"""版本化业务备份与真正的SQL箱检索；只供已授权运维人员使用。"""
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
import hashlib
import json
import uuid

from psycopg.types.json import Jsonb

from .postgres_tasks import PostgresTasks

BOX_INDEX_VERSION = 2


def text(value):
    if value is None:return None
    if isinstance(value,str):return value.strip() or None
    if isinstance(value,list) and all(isinstance(x,dict) and isinstance(x.get('text'),str) for x in value):
        return ''.join(x['text'] for x in value).strip() or None
    return None


def link_ids(value):
    if value is None or value=={}:return []
    if not isinstance(value,list):raise ValueError('BACKUP_LINK_SHAPE')
    result=[]
    for v in value:
        if isinstance(v,str):result.append(v)
        elif isinstance(v,dict) and isinstance(v.get('record_ids'),list):result.extend(v['record_ids'])
        elif isinstance(v,dict) and not v.get('record_ids') and v.get('type')=='text' and not v.get('text_arr'):continue
        else:raise ValueError('BACKUP_LINK_SHAPE')
    if any(not isinstance(v,str) for v in result):raise ValueError('BACKUP_LINK_SHAPE')
    return result


def catalog_checksum(catalog):
    # API分页顺序变化不应生成内容相同的新版本；字段顺序保留为源表结构的一部分。
    normalized = [{**table, 'records': sorted(table['records'], key=lambda r: r['record_id'])}
                  for table in sorted(catalog, key=lambda t: t['table_id'])]
    return hashlib.sha256(json.dumps(normalized, ensure_ascii=False, sort_keys=True,
                                    separators=(',', ':')).encode()).hexdigest()


def quantity_value(amount):
    """数字索引保留十进制精度；拒绝布尔值、无限值和非数字形状。"""
    if amount is None:return None
    if isinstance(amount,bool) or not isinstance(amount,(str,int,float)) or len(str(amount))>200:
        raise ValueError('BACKUP_QUANTITY_INVALID')
    try:
        value=Decimal(str(amount))
    except InvalidOperation:
        raise ValueError('BACKUP_QUANTITY_INVALID') from None
    if not value.is_finite():raise ValueError('BACKUP_QUANTITY_INVALID')
    return value


class BusinessBackups:
    def __init__(self,dsn):self.tasks=PostgresTasks(dsn)

    @contextmanager
    def query_connection(self):
        with self.tasks.connect() as db:
            db.execute('SET TRANSACTION READ ONLY')
            db.execute("SET LOCAL statement_timeout='10s'")
            yield db

    def capture(self,reader,table_ids=None,metadata=None):
        """先留意图；只在所有表/记录/索引同事务落库后公开为完整版本。"""
        self.tasks.ready()
        # 已配置的Base在首次鉴权解析Wiki之前可能为空，先解析且不读取业务数据。
        reader.source.login()
        base=reader.base_token
        if not isinstance(base,str) or not base:raise ValueError('BACKUP_BASE_REQUIRED')
        key=uuid.uuid4()
        with self.tasks.connect() as db:
            db.execute('''INSERT INTO finding_assistant.business_backups(backup_id,base_token,state,metadata)
                VALUES(%s,%s,'RUNNING',%s)''',(key,base,Jsonb(metadata or {})))
        try:
            catalog=reader.catalog(table_ids)
            if reader.base_token!=base:raise ValueError('BACKUP_BASE_CHANGED')
            self._finish(key,catalog)
        except Exception as error:
            with self.tasks.connect() as db:
                db.execute("UPDATE finding_assistant.business_backups SET state='FAILED',failure_code=%s,finished_at=clock_timestamp() WHERE backup_id=%s AND state='RUNNING'",
                           (type(error).__name__,key))
            raise
        return self.status(base,backup_id=str(key))

    def _finish(self,key,catalog):
        if not isinstance(catalog,list) or not catalog:raise ValueError('EMPTY_BACKUP_CATALOG')
        row_data={};box_tables=[];seen_tables=set();record_count=0
        checksum=catalog_checksum(catalog)
        with self.tasks.connect() as db:
            run=db.execute("SELECT state FROM finding_assistant.business_backups WHERE backup_id=%s FOR UPDATE",(key,)).fetchone()
            if not run or run['state']!='RUNNING':raise ValueError('BACKUP_NOT_RUNNING')
            for table in catalog:
                tid=table['table_id'];schema=table['fields']
                if not isinstance(tid,str) or tid in seen_tables:raise ValueError('BACKUP_TABLE_DUPLICATE')
                seen_tables.add(tid)
                names=[f['field_name'] for f in schema]
                if len(names)!=len(set(names)):raise ValueError('BACKUP_FIELD_AMBIGUOUS')
                db.execute('''INSERT INTO finding_assistant.business_backup_tables VALUES(%s,%s,%s,%s)''',
                    (key,tid,table['table_name'],Jsonb(schema)))
                seen_records=set()
                for r in table['records']:
                    rid=r['record_id'];fields=r['fields']
                    if not isinstance(rid,str) or rid in seen_records or not isinstance(fields,dict):
                        raise ValueError('BACKUP_RECORD_AMBIGUOUS')
                    seen_records.add(rid)
                    db.execute('INSERT INTO finding_assistant.business_backup_records(backup_id,table_id,record_id,fields) VALUES(%s,%s,%s,%s)',
                        (key,tid,rid,Jsonb(fields)));record_count+=1
                    if '行码' in names and '仓' in names:
                        row_data[(tid,rid)]=(text(fields.get('行码')),text(fields.get('仓')))
                if '箱号' in names and '状态' in names and '行' in names and '本箱套数' in names:
                    box_tables.append(table)
            for table in box_tables:
                target=next((f.get('property',{}).get('table_id') for f in table['fields'] if f['field_name']=='行'),None)
                for r in table['records']:
                    f=r['fields'];links=link_ids(f.get('行'))
                    if len(links)>1:raise ValueError('BACKUP_BOX_MULTIPLE_LOCATIONS')
                    if links and (target,links[0]) not in row_data:
                        # 箱子的当前位置不能靠猜测；备份箱表时须一并选择其关联行表。
                        raise ValueError('BACKUP_ROW_SOURCE_MISSING')
                    row,warehouse=row_data.get((target,links[0]),(None,None)) if links else (None,None)
                    quantity=quantity_value(f.get('本箱套数'))
                    db.execute('''INSERT INTO finding_assistant.business_box_index
                        (backup_id,table_id,record_id,box_code,fnsku,sku,po_number,state,row_code,position_code,warehouse,quantity,
                         row_table_id,row_record_id)
                        VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''',
                        (key,table['table_id'],r['record_id'],text(f.get('箱号')),text(f.get('标上FNSKU')),
                         text(f.get('SKU')),text(f.get('PO单号')),text(f.get('状态')),row,text(f.get('位置码')),warehouse,quantity,
                         target if links else None,links[0] if links else None))
            db.execute('''UPDATE finding_assistant.business_backups SET state='SUCCEEDED',finished_at=clock_timestamp(),
                table_count=%s,record_count=%s,content_sha256=%s WHERE backup_id=%s''',
                (len(catalog),record_count,checksum,key))

    @staticmethod
    def latest(db,base):
        return db.execute('''SELECT backup_id,base_token,started_at,finished_at,table_count,record_count,state
            FROM finding_assistant.business_backups WHERE base_token=%s AND state='SUCCEEDED'
            ORDER BY started_at DESC,backup_id DESC LIMIT 1''',(base,)).fetchone()

    def status(self,base,backup_id=None):
        with self.query_connection() as db:
            if backup_id:
                row=db.execute('''SELECT backup_id,base_token,started_at,finished_at,state,table_count,record_count,failure_code
                    FROM finding_assistant.business_backups WHERE base_token=%s AND backup_id=%s''',(base,uuid.UUID(backup_id))).fetchone()
            else:row=self.latest(db,base)
        return {'found':row is not None,'backup':row,'read_only':True,'business_primary':'feishu'}

    def boxes(self,base,*,box_code=None,fnsku=None,sku=None,po=None,row_code=None,position_code=None,state=None,limit=20,
              offset=0, snapshot_id=None, table_id=None):
        if type(limit) is not int or not 1<=limit<=100:raise ValueError('BACKUP_QUERY_LIMIT')
        if type(offset) is not int or not 0<=offset<=1000000:raise ValueError('BACKUP_QUERY_OFFSET')
        pairs=[('box_code',box_code),('fnsku',fnsku),('sku',sku),('po_number',po),('row_code',row_code),
               ('position_code',position_code),('state',state)]
        clauses=['backup_id=%s'];params=[]
        if table_id is not None:
            clauses.append('table_id=%s');params.append(table_id)
        for column,value in pairs:
            if value is not None:
                if not isinstance(value,str) or not value.strip() or len(value)>200:raise ValueError('BACKUP_QUERY_FILTER')
                clauses.append(column+'=%s');params.append(value)
        with self.query_connection() as db:
            snapshot=(db.execute('''SELECT backup_id,base_token,started_at,finished_at,table_count,record_count,state
                FROM finding_assistant.business_backups WHERE base_token=%s AND backup_id=%s AND state='SUCCEEDED' ''',
                (base,snapshot_id)).fetchone() if snapshot_id else self.latest(db,base))
            if not snapshot:return {'items':[],'has_more':False,'backup':None,'read_only':True,'source':'postgresql'}
            # SQL片段和列名固定，所有外部筛选值均参数化；不调用飞书或在Python过滤整表。
            query='''SELECT table_id,record_id,box_code,fnsku,sku,po_number,state,row_code,position_code,warehouse,quantity
                FROM finding_assistant.business_box_index WHERE '''+' AND '.join(clauses)+' ORDER BY box_code,table_id,record_id LIMIT %s OFFSET %s'
            rows=db.execute(query,[snapshot['backup_id'],*params,limit+1,offset]).fetchall()
        return {'items':rows[:limit],'has_more':len(rows)>limit,'limit':limit,'backup':snapshot,
                'next_offset':offset+limit if len(rows)>limit else None,
                'read_only':True,'source':'postgresql','business_primary':'feishu'}
