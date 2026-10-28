"""现有箱表、行表和事务账的只读适配，不创建表、不修改库存。

使用 records/search 的 field_names 和精确过滤读取相关记录，完整处理分页。
https://open.feishu.cn/document/docs/bitable-v1/app-table-record/search
"""
from dataclasses import dataclass
from copy import deepcopy
import re

from finding_assistant.domain.inbound_rules import BoxRecord, LocationRecord
from finding_assistant.domain.scan_submission import field_text
from finding_assistant.adapters.feishu.existing_forms import REQUIRED_FIELDS
from finding_assistant.security.errors import AuthorizationUnavailable
from finding_assistant.security.errors import UpstreamThrottled
from finding_assistant.infrastructure.performance import timed
from finding_assistant.infrastructure.request_scope import current_scope


class BusinessDataUnavailable(AuthorizationUnavailable):
    """业务数据没有完整核实；不得解释为业务校验不通过。"""


@dataclass(frozen=True)
class BusinessTableConfig:
    box_table_id: str
    row_table_id: str
    transaction_table_id: str = ''
    details_table_id: str = ''

    def __post_init__(self):
        for value in (self.box_table_id, self.row_table_id):
            if not isinstance(value,str) or not re.fullmatch(r'[A-Za-z0-9]+',value):
                raise ValueError('BOX_AND_ROW_TABLE_IDS_REQUIRED')
        if any(value and not re.fullmatch(r'[A-Za-z0-9]+',value)
               for value in (self.transaction_table_id,self.details_table_id)):
            raise ValueError('INVALID_TRANSACTION_TABLE_ID')
        ids=[v for v in (self.box_table_id,self.row_table_id,self.transaction_table_id,self.details_table_id) if v]
        if len(ids)!=len(set(ids)):
            raise ValueError('BUSINESS_TABLE_TARGETS_MUST_DIFFER')

    @classmethod
    def from_env(cls, values):
        ids=[values.get(k,'').strip() for k in ('FEISHU_BOX_TABLE_ID','FEISHU_ROW_TABLE_ID','FEISHU_TRANSACTION_TABLE_ID',
                                              'FEISHU_BOX_DETAILS_TABLE_ID')]
        return cls(*ids) if any(ids) else None


@dataclass(frozen=True)
class TransactionRecord:
    record_id: str
    document_reference: str
    box_code: str
    event_type: str
    location_code: str
    before: str
    after: str


def linked_record_ids(value,expected_table_id=None):
    """空关联允许省略；兼容已知API形状，未知结构不能当作空位置。"""
    # records/search 已实测：空关联返回{}；仅接受完全为空的对象，
    # 其他未知对象仍须拒绝，避免把未核实的位置误判为空。
    if value is None or isinstance(value, dict) and not value:
        return ()
    if isinstance(value,dict) and 'link_record_ids' in value:
        if value.get('table_id') and value['table_id']!=expected_table_id:
            raise BusinessDataUnavailable('BOX_LOCATION_TARGET_MISMATCH')
        value=value['link_record_ids']
    if not isinstance(value,list):
        raise BusinessDataUnavailable('BOX_LOCATION_FORMAT_UNCONFIRMED')
    result=[]
    for item in value:
        if isinstance(item,dict):
            if item.get('table_id') and item['table_id']!=expected_table_id:
                raise BusinessDataUnavailable('BOX_LOCATION_TARGET_MISMATCH')
            ids=item['record_ids'] if 'record_ids' in item else [item.get('record_id')]
        else:ids=[item]
        if not isinstance(ids,list):
            raise BusinessDataUnavailable('BOX_LOCATION_FORMAT_UNCONFIRMED')
        for rid in ids:
            if not isinstance(rid,str) or not re.fullmatch(r'[A-Za-z0-9]+',rid):
                raise BusinessDataUnavailable('BOX_LOCATION_FORMAT_UNCONFIRMED')
            result.append(rid)
    if len(result)>1:
        raise BusinessDataUnavailable('BOX_LOCATION_NOT_SINGLE')
    return tuple(result)


class BusinessTableReader:
    BOX_FIELDS={'箱号':1,'状态':3,'行':18}
    ROW_FIELDS={'行码':1,'仓':3}
    TRANSACTION_FIELDS={'单据引用':1,'箱号/行':1,'类型':3,'行':1,'变更前':1,'变更后':1}

    def __init__(self, access, config):
        self.access,self.config=access,config
        if access.config.scan_table_id in (config.box_table_id,config.row_table_id,config.transaction_table_id,config.details_table_id):
            raise ValueError('BUSINESS_TABLE_CANNOT_BE_SCAN_TABLE')

    def _path(self,table):
        return f'/bitable/v1/apps/{self.access.config.app_token}/tables/{table}'

    def _read(self,identity,method,path,body=None,params=None):
        # 只允许字段读取和检索接口；POST search 属于只读查询。
        if not (method=='GET' and path.endswith('/fields') or method=='POST' and path.endswith('/records/search')):
            raise ValueError('READ_ONLY_BUSINESS_ADAPTER')
        try:
            return self.access._request(method,path,identity.access_token,body,params).get('data')
        except UpstreamThrottled:
            raise
        except AuthorizationUnavailable:
            raise BusinessDataUnavailable('BUSINESS_READ_UNCONFIRMED') from None

    @staticmethod
    def _complete_scope(identity):
        # 编辑权限可能受行级筛选限制，成功返回空数组并不能证明档案不存在。
        # 在后台读取身份尚未敲定前，不借用应用权限扩大员工可见范围。
        if identity.permission!='full_access':
            raise BusinessDataUnavailable('FULL_BUSINESS_READ_SCOPE_UNCONFIRMED')

    @timed('schema_check')
    def _schema(self,identity,table,required):
        scope = current_scope()
        if scope is None:
            return self._validated_schema(identity, table, required)
        key = ('business_schema', self.access, identity.access_token, table)
        with scope.lock:
            if key in scope.values:
                schema = deepcopy(scope.values[key])
                self._validate_schema(schema, required)
                return schema
            schema = self._validated_schema(identity, table, required)
            scope.values[key] = deepcopy(schema)
            return schema

    def _validated_schema(self,identity,table,required):
        fields=[];cursor=None;seen=set()
        for _ in range(100):
            params={'page_size':100}
            if cursor:params['page_token']=cursor
            data=self._read(identity,'GET',self._path(table)+'/fields',params=params)
            if not isinstance(data,dict) or not isinstance(data.get('items'),list) or type(data.get('has_more')) is not bool:
                raise BusinessDataUnavailable('BUSINESS_SCHEMA_UNCONFIRMED')
            fields.extend(data['items'])
            if not data['has_more']:break
            cursor=data.get('page_token')
            if not isinstance(cursor,str) or not cursor or cursor in seen:
                raise BusinessDataUnavailable('BUSINESS_SCHEMA_PAGINATION_UNCONFIRMED')
            seen.add(cursor)
        else:raise BusinessDataUnavailable('BUSINESS_SCHEMA_PAGE_LIMIT')
        by_name={}
        for f in fields:
            if not isinstance(f,dict) or not isinstance(f.get('field_name'),str) or f['field_name'] in by_name:
                raise BusinessDataUnavailable('BUSINESS_SCHEMA_AMBIGUOUS')
            by_name[f['field_name']]=f
        self._validate_schema(by_name, required)
        return by_name

    def _validate_schema(self,by_name,required):
        if any(type(by_name.get(name,{}).get('type')) is not int or by_name[name]['type']!=kind for name,kind in required.items()):
            raise BusinessDataUnavailable('BUSINESS_SCHEMA_MISMATCH')
        if '行' in required and required['行']==18:
            target=(by_name['行'].get('property') or {}).get('table_id')
            if target!=self.config.row_table_id:
                raise BusinessDataUnavailable('BOX_ROW_LINK_TARGET_MISMATCH')

    def _search(self,identity,table,fields,match_field,values):
        self._complete_scope(identity)
        self._schema(identity,table,fields)
        if not isinstance(values,(list,tuple)) or not values or len(values)>36 or any(not isinstance(v,str) or not v.strip() or len(v)>200 for v in values):
            raise ValueError('INVALID_BUSINESS_LOOKUP_VALUES')
        values=tuple(dict.fromkeys(v.strip() for v in values))
        body={'field_names':list(fields),'filter':{'conjunction':'or','conditions':[
            {'field_name':match_field,'operator':'is','value':[v]} for v in values]}}
        return self._records(identity, table, body, match_field, values)

    def _records(self, identity, table, body, match_field=None, values=()):
        """分页必须完整；未带过滤的检索用于核实转仓来源和全部位置占用。"""
        records={};cursor=None;seen=set()
        for _ in range(1000):
            params={'page_size':100,'user_id_type':'open_id'}
            if cursor:params['page_token']=cursor
            data=self._read(identity,'POST',self._path(table)+'/records/search',body,params)
            if not isinstance(data,dict) or not isinstance(data.get('items'),list) or type(data.get('has_more')) is not bool:
                raise BusinessDataUnavailable('BUSINESS_LOOKUP_INCOMPLETE')
            for record in data['items']:
                if not isinstance(record,dict) or not isinstance(record.get('record_id'),str) or not record['record_id'] or not isinstance(record.get('fields'),dict):
                    raise BusinessDataUnavailable('BUSINESS_RECORD_UNCONFIRMED')
                rid=record['record_id']
                if match_field is not None:
                    try:matched=field_text(record['fields'].get(match_field))
                    except ValueError:raise BusinessDataUnavailable('BUSINESS_MATCH_FIELD_UNCONFIRMED') from None
                    if matched not in values:
                        raise BusinessDataUnavailable('BUSINESS_FILTER_RESULT_MISMATCH')
                if rid in records and records[rid]!=record['fields']:
                    raise BusinessDataUnavailable('BUSINESS_RECORD_CHANGED_DURING_READ')
                records[rid]=record['fields']
            if not data['has_more']:
                return tuple(records.items())
            cursor=data.get('page_token')
            if not isinstance(cursor,str) or not cursor or cursor in seen:
                raise BusinessDataUnavailable('BUSINESS_LOOKUP_PAGINATION_UNCONFIRMED')
            seen.add(cursor)
        raise BusinessDataUnavailable('BUSINESS_LOOKUP_PAGE_LIMIT')

    @staticmethod
    def _text(fields,name):
        try:return field_text(fields.get(name))
        except ValueError:raise BusinessDataUnavailable('BUSINESS_FIELD_FORMAT_UNCONFIRMED') from None

    def boxes(self,identity,box_codes):
        rows=self._search(identity,self.config.box_table_id,self.BOX_FIELDS,'箱号',box_codes)
        return tuple(BoxRecord(rid,self._text(f,'箱号'),self._text(f,'状态'),linked_record_ids(f.get('行'),self.config.row_table_id)) for rid,f in rows)

    def locations(self,identity,location_codes):
        rows=self._search(identity,self.config.row_table_id,self.ROW_FIELDS,'行码',location_codes)
        return tuple(LocationRecord(rid,self._text(f,'行码'),self._text(f,'仓')) for rid,f in rows)

    @timed('related_read')
    def transfer_snapshot(self, identity):
        # 无完整读取范围时不能将“用户看不到的箱子”误判为空位置。
        self._complete_scope(identity)
        self._schema(identity, self.config.box_table_id, self.BOX_FIELDS)
        self._schema(identity, self.config.row_table_id, self.ROW_FIELDS)
        boxes = self._records(identity, self.config.box_table_id, {'field_names': list(self.BOX_FIELDS)})
        rows = self._records(identity, self.config.row_table_id, {'field_names': list(self.ROW_FIELDS)})
        return (tuple(BoxRecord(rid, self._text(f, '箱号'), self._text(f, '状态'),
                                linked_record_ids(f.get('行'), self.config.row_table_id)) for rid, f in boxes),
                tuple(LocationRecord(rid, self._text(f, '行码'), self._text(f, '仓')) for rid, f in rows))

    @timed('related_read')
    def position_snapshot(self, identity):
        """新分配必须能看到位置字段及全部占用，不能静默退回只看行码的旧模型。"""
        self._complete_scope(identity)
        required = {**self.BOX_FIELDS, '位置码': 1}
        self._schema(identity, self.config.box_table_id, required)
        self._schema(identity, self.config.row_table_id, self.ROW_FIELDS)
        # 本次写入还要求扫码流水表已有文本位置码字段；仅校验，绝不自动改表。
        self._schema(identity, self.access.config.scan_table_id, {**REQUIRED_FIELDS, '位置码': 1})
        boxes = self._records(identity, self.config.box_table_id, {'field_names': list(required)})
        rows = self._records(identity, self.config.row_table_id, {'field_names': list(self.ROW_FIELDS)})
        return (
            tuple(BoxRecord(rid, self._text(f, '箱号'), self._text(f, '状态'),
                            linked_record_ids(f.get('行'), self.config.row_table_id),
                            self._text(f, '位置码')) for rid, f in boxes),
            tuple(LocationRecord(rid, self._text(f, '行码'), self._text(f, '仓')) for rid, f in rows),
        )

    def transactions(self,identity,document_references):
        if not self.config.transaction_table_id:
            raise BusinessDataUnavailable('TRANSACTION_TABLE_NOT_CONFIGURED')
        rows=self._search(identity,self.config.transaction_table_id,self.TRANSACTION_FIELDS,'单据引用',document_references)
        return tuple(TransactionRecord(rid,*(self._text(f,n) for n in self.TRANSACTION_FIELDS)) for rid,f in rows)
