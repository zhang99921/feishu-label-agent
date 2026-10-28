"""受固定表配置约束的库存读写；始终使用当前用户令牌，不回退到应用身份。"""
from decimal import Decimal, InvalidOperation
import re

from .business_tables import BusinessTableReader, BusinessDataUnavailable, linked_record_ids
from .existing_forms import REQUIRED_FIELDS
from finding_assistant.domain.inventory_posting import BOX_TYPES, DETAIL_TYPES, LEDGER_TYPES, PostingStopped
from finding_assistant.domain.scan_submission import field_text
from finding_assistant.infrastructure.performance import timed


def canonical(value, kind, row_table=None):
    if kind == 18:
        return list(linked_record_ids(value, row_table))
    if kind in (1, 3, 1005):
        return field_text(value)
    if value is None:
        return None
    if kind == 2:
        if isinstance(value, bool) or len(str(value)) > 200:
            raise PostingStopped('NUMBER_UNCONFIRMED')
        try:
            number = Decimal(str(value))
        except InvalidOperation:
            raise PostingStopped('NUMBER_UNCONFIRMED') from None
        if not number.is_finite():
            raise PostingStopped('NUMBER_UNCONFIRMED')
        return format(number.normalize(), 'f')
    if kind == 5:
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise PostingStopped('DATE_UNCONFIRMED')
        try:
            number = Decimal(str(value))
            if not number.is_finite() or number != number.to_integral_value():
                raise ValueError
            return int(number)
        except (InvalidOperation, ValueError):
            raise PostingStopped('DATE_UNCONFIRMED') from None
    raise PostingStopped('FIELD_TYPE_UNSUPPORTED')


def same_fields(actual, expected, types, row_table=None):
    return all(canonical(actual.get(name), types[name], row_table) == canonical(value, types[name], row_table)
               for name, value in expected.items())


class InventoryAccess:
    SCAN_TYPES = {**REQUIRED_FIELDS, '流水号': 1005, '位置码': 1}
    REQUIREMENTS = {'BOX': BOX_TYPES, 'DETAIL': DETAIL_TYPES, 'LEDGER': LEDGER_TYPES,
                    'STATUS': {'处理状态': 3, '处理说明': 1}}
    WRITABLE = {'BOX': {'状态', '行', '位置码', '入库时间'}, 'DETAIL': {'状态', '当前套数'},
                'LEDGER': set(LEDGER_TYPES), 'STATUS': {'处理状态', '处理说明'}}

    def __init__(self, access, config):
        self.access, self.config = access, config
        self.reader = BusinessTableReader(access, config)
        self.tables = {'BOX': config.box_table_id, 'DETAIL': config.details_table_id,
                       'LEDGER': config.transaction_table_id, 'STATUS': access.config.scan_table_id}

    def _path(self, role):
        if role not in self.tables or not self.tables[role]:
            raise PostingStopped('POSTING_TABLE_NOT_CONFIGURED')
        return self.reader._path(self.tables[role])

    @staticmethod
    def _id(value):
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9]+', value):
            raise ValueError('INVALID_RECORD_ID')
        return value

    def source(self, identity, record_id):
        self.reader._complete_scope(identity)
        self.reader._schema(identity, self.tables['STATUS'], self.SCAN_TYPES)
        return self._get(identity, 'STATUS', record_id)

    @timed('readback')
    def _get(self, identity, role, record_id):
        record_id = self._id(record_id)
        if role == 'BOX':
            # 单条GET的关联字段实测只有text_arr展示值，没有record_id，不能据此校验真实位置。
            # batch_get按内部ID读取机器可用的关联值，不按展示行码猜关联，更不把未知结构当空位。
            data = self.access._request('POST', self._path(role) + '/records/batch_get', identity.access_token,
                {'record_ids': [record_id], 'user_id_type': 'open_id', 'automatic_fields': True}).get('data')
            if (not isinstance(data, dict) or not isinstance(data.get('records'), list)
                    or len(data['records']) != 1 or data.get('absent_record_ids', []) != []
                    or data.get('forbidden_record_ids', []) != []):
                raise BusinessDataUnavailable('POSTING_RECORD_UNCONFIRMED')
            record = data['records'][0]
        else:
            data = self.access._request('GET', self._path(role) + '/records/' + record_id,
                                        identity.access_token, params={'user_id_type': 'open_id'}).get('data')
            record = data.get('record') if isinstance(data, dict) else None
        if not isinstance(record, dict) or record.get('record_id') != record_id or not isinstance(record.get('fields'), dict):
            raise BusinessDataUnavailable('POSTING_RECORD_UNCONFIRMED')
        return record

    def get(self, identity, step, remote_id=None):
        return self._get(identity, step['kind'], remote_id or step['record_id'])

    def _batch_records(self, identity, table, record_ids):
        """按真实ID分批读取；缺失、越权、重复或夹带其他记录均不接受。"""
        ids = list(dict.fromkeys(self._id(rid) for rid in record_ids))
        records = {}
        for offset in range(0, len(ids), 100):
            chunk = ids[offset:offset + 100]
            data = self.access._request('POST', self.reader._path(table) + '/records/batch_get',
                identity.access_token, {'record_ids': chunk, 'user_id_type': 'open_id',
                                        'automatic_fields': True}).get('data')
            if (not isinstance(data, dict) or not isinstance(data.get('records'), list)
                    or data.get('absent_record_ids', []) != [] or data.get('forbidden_record_ids', []) != []):
                raise BusinessDataUnavailable('POSTING_RECORD_UNCONFIRMED')
            page = {}
            for record in data['records']:
                if (not isinstance(record, dict) or not isinstance(record.get('record_id'), str)
                        or record['record_id'] not in chunk or record['record_id'] in page
                        or not isinstance(record.get('fields'), dict)):
                    raise BusinessDataUnavailable('POSTING_RECORD_UNCONFIRMED')
                page[record['record_id']] = record
            if set(page) != set(chunk):
                raise BusinessDataUnavailable('POSTING_RECORD_UNCONFIRMED')
            records.update(page)
        return records

    @timed('readback')
    def get_many(self, identity, role, record_ids):
        if role not in ('BOX', 'DETAIL'):
            raise ValueError('BATCH_READ_ROLE_DENIED')
        self.reader._complete_scope(identity)
        self._path(role)
        return self._batch_records(identity, self.tables[role], record_ids)

    @timed('related_read')
    def snapshot(self, identity, box_codes, action):
        self.reader._complete_scope(identity)
        if action == 'OUT' and not self.tables['DETAIL']:
            raise PostingStopped('DETAIL_TABLE_REQUIRED')
        boxes = self.reader._search(identity, self.tables['BOX'], BOX_TYPES, '箱号', box_codes)
        self.reader._schema(identity, self.config.row_table_id, self.reader.ROW_FIELDS)
        rows = self.reader._records(identity, self.config.row_table_id, {'field_names': list(self.reader.ROW_FIELDS)})
        details = self.reader._search(identity, self.tables['DETAIL'], DETAIL_TYPES, '箱号', box_codes) if action == 'OUT' else ()

        def normalized(records, types):
            return [{'record_id': rid, 'fields': {name: canonical(fields.get(name), kind, self.config.row_table_id)
                                                 for name, kind in types.items()}} for rid, fields in records]
        return {'boxes': normalized(boxes, BOX_TYPES), 'rows': normalized(rows, self.reader.ROW_FIELDS),
                'details': normalized(details, DETAIL_TYPES)}

    def validate_feedback(self, identity):
        self.reader._complete_scope(identity)
        schema = self.reader._schema(identity, self.tables['STATUS'], self.REQUIREMENTS['STATUS'])
        options = (schema['处理状态'].get('property') or {}).get('options')
        if not isinstance(options, list) or '异常' not in {option.get('name') for option in options}:
            raise PostingStopped('FEEDBACK_OPTION_NOT_CONFIGURED')

    def validate_plan(self, identity, plan):
        self.reader._complete_scope(identity)
        if plan['tables'] != self.tables:
            raise PostingStopped('POSTING_CONFIGURATION_CHANGED')
        schemas = {}
        for step in plan['steps']:
            role = step['kind']
            if (role not in self.REQUIREMENTS or step['table_id'] != self.tables[role]
                    or not set(step['fields']) <= self.WRITABLE[role] or step['types'] != self.REQUIREMENTS[role]):
                raise PostingStopped('POSTING_PLAN_INVALID')
            if role not in schemas:
                schemas[role] = self.reader._schema(identity, self.tables[role], self.REQUIREMENTS[role])
            # 不通过创建记录暗中补单选选项；配置问题在箱表改变之前发现。
            for name, value in step['fields'].items():
                if step['types'][name] == 3:
                    options = (schemas[role][name].get('property') or {}).get('options')
                    if not isinstance(options, list) or value not in {o.get('name') for o in options}:
                        raise PostingStopped('POSTING_OPTION_NOT_CONFIGURED')

    @timed('readback')
    def verify_rows(self, identity, plan):
        # 行码或仓映射在计划冻结后变化时，不向旧业务含义的位置继续写入。
        self.reader._schema(identity, self.config.row_table_id, self.reader.ROW_FIELDS)
        # 只回读冻结计划涉及的行记录，不再下载整张行表。每次调用仍重新读取。
        records = {rid: record['fields'] for rid, record in
                   self._batch_records(identity, self.config.row_table_id, plan['row_guards']).items()}
        for rid, expected in plan['row_guards'].items():
            if rid not in records or not same_fields(records[rid], expected, self.reader.ROW_FIELDS):
                raise PostingStopped('ROW_MAPPING_CHANGED')

    @timed('readback')
    def ledger(self, identity, step):
        rows = self.reader._search(identity, self.tables['LEDGER'], LEDGER_TYPES, '事务号',
                                   (step['fields']['事务号'],))
        return [{'record_id': rid, 'fields': fields} for rid, fields in rows]

    @timed('readback')
    def ledgers(self, identity, steps):
        """同一核账阶段合并精确事务号查询；仍保留重复事务供调用方拒绝。"""
        numbers = tuple(dict.fromkeys(step['fields']['事务号'] for step in steps))
        grouped = {number: [] for number in numbers}
        for offset in range(0, len(numbers), 36):
            rows = self.reader._search(identity, self.tables['LEDGER'], LEDGER_TYPES, '事务号',
                                       numbers[offset:offset + 36])
            for rid, fields in rows:
                number = field_text(fields.get('事务号'))
                grouped[number].append({'record_id': rid, 'fields': fields})
        return grouped

    @timed('inventory_write')
    def write(self, identity, step):
        role = step['kind']
        if step['table_id'] != self.tables.get(role) or not set(step['fields']) <= self.WRITABLE.get(role, set()):
            raise PostingStopped('POSTING_TARGET_DENIED')
        params = {'user_id_type': 'open_id', 'ignore_consistency_check': 'false'}
        path = self._path(role) + '/records'
        if role == 'LEDGER':
            params['client_token'] = step['step_id']
            data = self.access._request('POST', path, identity.access_token, {'fields': step['fields']}, params)
        else:
            data = self.access._request('PUT', path + '/' + self._id(step['record_id']), identity.access_token,
                                         {'fields': step['fields']}, params)
        record = data.get('data', {}).get('record')
        if not isinstance(record, dict) or not isinstance(record.get('record_id'), str) or not record['record_id']:
            raise BusinessDataUnavailable('POSTING_WRITE_UNCONFIRMED')
        if role != 'LEDGER' and record['record_id'] != step['record_id']:
            raise BusinessDataUnavailable('POSTING_RECORD_ID_MISMATCH')
        return record['record_id']

    def verify(self, record, expected, types):
        return same_fields(record['fields'], expected, types, self.config.row_table_id)


    @timed('inventory_write')
    def write_many(self, identity, steps):
        """一次只写一个表/角色，按ID或事务号匹配回执，不相信返回顺序。"""
        if not 1 <= len(steps) <= 36 or len({s['kind'] for s in steps}) != 1:
            raise PostingStopped('BATCH_WRITE_SCOPE_INVALID')
        role=steps[0]['kind']
        if role not in ('BOX','DETAIL','LEDGER'):raise PostingStopped('BATCH_WRITE_SCOPE_INVALID')
        for step in steps:
            if step['table_id']!=self.tables[role] or not set(step['fields'])<=self.WRITABLE[role]:
                raise PostingStopped('POSTING_TARGET_DENIED')
        body={'records':[{'fields':s['fields'],**({} if role=='LEDGER' else {'record_id':self._id(s['record_id'])})} for s in steps]}
        params={'user_id_type':'open_id','ignore_consistency_check':'false','client_token':steps[0]['step_id']}
        endpoint='batch_create' if role=='LEDGER' else 'batch_update'
        data=self.access._request('POST',self._path(role)+'/records/'+endpoint,identity.access_token,body,params).get('data')
        if not isinstance(data,dict) or not isinstance(data.get('records'),list) or len(data['records'])!=len(steps):
            raise BusinessDataUnavailable('BATCH_WRITE_UNCONFIRMED')
        ids=set();matched={}
        for record in data['records']:
            rid=record.get('record_id') if isinstance(record,dict) else None
            if not isinstance(rid,str) or not rid or rid in ids:raise BusinessDataUnavailable('BATCH_RECEIPT_UNCONFIRMED')
            self._id(rid);ids.add(rid)
            key=field_text(record.get('fields',{}).get('事务号')) if role=='LEDGER' else rid
            if key in matched:raise BusinessDataUnavailable('BATCH_RECEIPT_UNCONFIRMED')
            matched[key]=rid
        expected={s['fields']['事务号'] if role=='LEDGER' else s['record_id'] for s in steps}
        if set(matched)!=expected:raise BusinessDataUnavailable('BATCH_RECEIPT_UNCONFIRMED')
        return {s['ordinal']:matched[s['fields']['事务号'] if role=='LEDGER' else s['record_id']] for s in steps}
