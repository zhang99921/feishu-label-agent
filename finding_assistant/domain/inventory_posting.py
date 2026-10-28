"""把已核实快照转换为不可变的逐箱执行计划；不在本模块发送HTTP或修改数据库。"""
from decimal import Decimal, InvalidOperation
import uuid


class PostingStopped(Exception):
    def __init__(self, code, box_code=None):
        super().__init__(code)
        self.code = code
        self.box_code = box_code


BOX_TYPES = {'箱号': 1, '状态': 3, '行': 18, '位置码': 1, '本箱套数': 2,
             '内容版本': 2, '入库时间': 5, '箱型': 3}
DETAIL_TYPES = {'箱号': 1, '状态': 3, '当前套数': 2, '版本': 1}
LEDGER_TYPES = {'事务号': 1, '类型': 3, '箱号/行': 1, '行': 1, '数量(套)': 2,
                '变更前': 1, '变更后': 1, '单据引用': 1, '时间': 5}
FINAL_STATUS = {'IN': '已入账', 'OUT': '已出账', 'MOVE': '已转仓'}


def positive_quantity(value):
    if isinstance(value, bool) or value is None or len(str(value)) > 200:
        raise PostingStopped('QUANTITY_UNCONFIRMED')
    try:
        amount = Decimal(str(value))
    except InvalidOperation:
        raise PostingStopped('QUANTITY_UNCONFIRMED') from None
    if not amount.is_finite() or amount <= 0:
        # 不把缺值转成0；零、负数的业务分支仍留待用户决定。
        raise PostingStopped('QUANTITY_REVIEW_REQUIRED')
    number = int(amount) if amount == amount.to_integral_value() else float(amount)
    if Decimal(str(number)) != amount:
        raise PostingStopped('QUANTITY_PRECISION_REVIEW')
    return number


def document_references(display_number, record_id, box_codes):
    """k按完整去重扫描序列编号，单箱不带后缀；不把人读编号当内部幂等键。"""
    codes = tuple(dict.fromkeys(box_codes))
    prefix = display_number or 'PH-' + record_id
    return {code: prefix if len(codes) == 1 else f'{prefix}-{i}' for i, code in enumerate(codes, 1)}


def build_posting_plan(submission, display_number, snapshot, tables, reservation, sources, stamp):
    if submission.errors or submission.action not in FINAL_STATUS:
        raise PostingStopped('SOURCE_INPUT_INVALID')
    by_code = {}
    for box in snapshot['boxes']:
        by_code.setdefault(box['fields']['箱号'], []).append(box)
    rows = {row['record_id']: row['fields'] for row in snapshot['rows']}
    if len(rows) != len(snapshot['rows']):
        raise PostingStopped('ROW_ARCHIVE_AMBIGUOUS')
    references = document_references(display_number, submission.source_record_id, submission.boxes)
    steps, transactions, skipped, row_guards = [], [], [], {}

    def add(kind, record_id, before, fields, types, box_id=None, step_id=None):
        steps.append({'ordinal': len(steps) + 1, 'step_id': step_id or str(uuid.uuid4()), 'kind': kind,
                      'table_id': tables[kind], 'record_id': record_id, 'box_record_id': box_id,
                      'before': before, 'fields': fields, 'after': {**before, **fields}, 'types': types})

    for code in submission.boxes:
        matches = by_code.get(code, [])
        if len(matches) != 1:
            raise PostingStopped('BOX_ARCHIVE_NOT_UNIQUE', code)
        box = matches[0]
        rid, before = box['record_id'], dict(box['fields'])
        status, links, suffix = before['状态'], before['行'], before['位置码']
        if len(links) > 1 or links and links[0] not in rows:
            raise PostingStopped('BOX_ROW_UNCONFIRMED', code)
        row_id = links[0] if links else None
        row = rows.get(row_id, {})
        if row_id:
            row_guards[row_id] = row
        old_code, old_warehouse = row.get('行码', ''), row.get('仓', '')
        if submission.action == 'OUT' and status == '已出库':
            if links or suffix:
                raise PostingStopped('OUTBOUND_POSITION_CONFLICT', code)
            skipped.append({'record_id': rid, 'fields': before})
            continue
        quantity = positive_quantity(before['本箱套数'])
        target_code, target_suffix = '', ''
        if submission.action in ('IN', 'MOVE'):
            if reservation is None:
                raise PostingStopped('POSITION_RESERVATION_REQUIRED')
            target_id, target_code = reservation['target_row_record_id'], reservation['target_row_code']
            target_suffix = reservation['position_code']
            if (target_id not in rows or rows[target_id]['行码'] != target_code
                    or rows[target_id]['仓'] != reservation['target_warehouse']):
                raise PostingStopped('TARGET_ROW_CHANGED', code)
            row_guards[target_id] = rows[target_id]
            if submission.location != target_code or submission.position_code != target_suffix:
                raise PostingStopped('FLOW_POSITION_MISMATCH')
        if submission.action == 'IN':
            if status in ('在库', '在托'):
                # 入库入口的旧式转行仍须有已跟踪来源，不借此接管历史位置。
                expected = next((source for source in reservation['sources'] if source['box_record_id'] == rid), None)
                if (not expected or row_id == target_id
                        or expected['row_record_id'] != row_id or expected['position_code'] != suffix
                        or expected['status'] != status):
                    raise PostingStopped('INBOUND_TRANSFER_SOURCE_CHANGED', code)
                fields = {'状态': '在库', '行': [target_id], '位置码': target_suffix}
                event_type = '转行'
            else:
                if status != '待入库' or links or suffix or reservation['source_reservation_id'] or reservation['sources']:
                    raise PostingStopped('INBOUND_STATE_REVIEW_REQUIRED', code)
                fields = {'状态': '在库', '行': [target_id], '位置码': target_suffix,
                          '入库时间': before['入库时间'] if before['入库时间'] is not None else stamp}
                event_type = '入库'
            after_text = f'在库 {target_code}{target_suffix}'
        elif submission.action == 'MOVE':
            expected = next((source for source in reservation['sources'] if source['box_record_id'] == rid), None)
            if (status not in ('在库', '在托') or not expected or expected['row_record_id'] != row_id
                    or expected['position_code'] != suffix or expected['status'] != status):
                raise PostingStopped('TRANSFER_SOURCE_CHANGED', code)
            fields = {'行': [target_id], '位置码': target_suffix}
            event_type = '转仓' if old_warehouse != rows[target_id]['仓'] else '转行'
            after_text = f'{status} {target_code}{target_suffix}'
        else:
            if status not in ('在库', '在托', '待入库'):
                raise PostingStopped('OUTBOUND_STATE_REVIEW_REQUIRED', code)
            if status == '待入库' and (links or suffix):
                raise PostingStopped('OUTBOUND_POSITION_CONFLICT', code)
            if status in ('在库', '在托') and (not row_id or (suffix and rid not in sources)):
                raise PostingStopped('HISTORICAL_POSITION_NOT_TAKEN_OVER')
            fields = {'状态': '已出库', '行': [], '位置码': ''}
            event_type, after_text = '出库', '已出库'
        add('BOX', rid, before, fields, BOX_TYPES, rid)
        transaction_id = str(uuid.uuid4())
        number = 'T-' + uuid.UUID(transaction_id).hex
        before_text = f'{status} {old_code}{suffix}'.strip()
        if submission.action == 'OUT' and status == '待入库':
            before_text += '（未经入库直接出库）'
        ledger = {'事务号': number, '类型': event_type, '箱号/行': code,
                  '行': old_code if submission.action == 'OUT' else target_code, '数量(套)': quantity,
                  '变更前': before_text, '变更后': after_text, '单据引用': references[code], '时间': stamp}
        add('LEDGER', None, {}, ledger, LEDGER_TYPES, rid, transaction_id)
        if submission.action == 'OUT':
            if not tables.get('DETAIL'):
                raise PostingStopped('DETAIL_TABLE_REQUIRED')
            for detail in snapshot['details']:
                if detail['fields']['箱号'] == code:
                    add('DETAIL', detail['record_id'], detail['fields'],
                        {'状态': '已拣空', '当前套数': 0}, DETAIL_TYPES, rid)
        transactions.append({'transaction_id': transaction_id, 'box_record_id': rid, 'box_code': code,
            'document_reference': references[code], 'transaction_no': number, 'quantity': quantity,
            'before': before, 'after': {**before, **fields},
            'source_position_id': (sources.get(rid, {}).get('reservation_id') if submission.action == 'OUT'
                                   else next((source.get('reservation_id', str(reservation['source_reservation_id']) if reservation['source_reservation_id'] else None)
                                              for source in reservation['sources'] if source['box_record_id'] == rid), None) if reservation else None),
            'target_position_id': str(reservation['reservation_id']) if reservation else None})
    note = f'已完成{len(transactions)}箱，忽略已出库{len(skipped)}箱。'
    add('STATUS', submission.source_record_id, {'处理状态': '待处理'},
        {'处理状态': FINAL_STATUS[submission.action], '处理说明': note}, {'处理状态': 3, '处理说明': 1})
    source_groups = {}
    for source in (reservation['sources'] if reservation else []):
        if source.get('reservation_id'):
            source_groups[source['reservation_id']] = {key: source[key] for key in ('reservation_id','member_ids','row_record_id','position_code')}
    version = 3 if len(transactions) > 1 else 2
    if version == 3:
        # 新计划按同类步骤分阶段；旧冻结计划不改序、不重写。
        steps = [step for role in ('BOX','LEDGER','DETAIL','STATUS') for step in steps if step['kind']==role]
        for ordinal, step in enumerate(steps, 1):step['ordinal']=ordinal
    return {'version': version, 'source_key': submission.source_key, 'source_record_id': submission.source_record_id,
            'fingerprint': submission.fingerprint, 'action': submission.action, 'tables': tables,
            'steps': steps, 'transactions': transactions, 'skipped': skipped,
            'row_guards': row_guards,
            'position_reservation_id': str(reservation['reservation_id']) if reservation else None,
            'outbound_sources': sources, 'source_groups': list(source_groups.values()), 'stamp': stamp}
