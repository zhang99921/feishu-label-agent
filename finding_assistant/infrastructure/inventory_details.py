"""固定SQL副本内的单箱及关联业务信息；按表独立执行行列可见性。"""
import re
import uuid

from finding_assistant.application.workflow import Conflict
from finding_assistant.security.errors import AccessDenied
from finding_assistant.security.sql_visibility import Clause, TRUE, FALSE, combine, schema_fields, table_visibility, VisibilityUnavailable
from .business_sync import ReplicaUnavailable


class InventoryDetails:
    SECTIONS = frozenset({'all','box','details','flows','ledger'})

    def __init__(self, replica, tables):
        self.replica, self.tables = replica, dict(tables)
        if set(self.tables)-{'box','details','flows','ledger'}:
            raise ValueError('INVALID_DETAIL_TABLE_ROLE')
        ids=[tid for tid in self.tables.values() if tid]
        if len(ids)!=len(set(ids)):raise ValueError('DETAIL_TABLE_TARGETS_MUST_DIFFER')
        if not self.tables.get('box') or self.tables['box'] not in replica.config.table_ids:
            raise ValueError('DETAIL_BOX_TABLE_REQUIRED')

    @staticmethod
    def projection(schema, policy, table):
        if policy is None:
            return Clause('box_data.fields'), TRUE, TRUE
        visibility = table_visibility(policy['roles'], table, schema)
        if not any(g.fields for g in visibility.grants):
            return Clause("'{}'::jsonb"),FALSE,FALSE
        allowed = visibility.rows('box_data')
        masks = [combine('AND', (Clause('kv.key=%s',(name,)),visibility.field(name,'box_data')))
                 for name,field in schema_fields(schema).items() if field['type'] not in (17,18,21)]
        mask = combine('OR',masks)
        return (Clause("(SELECT COALESCE(jsonb_object_agg(kv.key,kv.value),'{}'::jsonb) FROM jsonb_each(box_data.fields) kv WHERE "+mask.sql+')',mask.params),
                allowed,visibility.field('箱号','box_data'))

    def read(self, record_id, *, policy=None, section='all', limit=20, offset=0, backup_id=None):
        if not isinstance(record_id,str) or not re.fullmatch(r'[A-Za-z0-9]{1,200}',record_id):
            raise ValueError('INVALID_BOX_RECORD_ID')
        if section not in self.SECTIONS or type(limit) is not int or not 1<=limit<=100 or type(offset) is not int or not 0<=offset<=1000000:
            raise ValueError('INVALID_DETAIL_PAGINATION')
        if backup_id is not None:
            try:backup_id=str(uuid.UUID(backup_id))
            except (ValueError,TypeError,AttributeError):raise ValueError('INVALID_DETAIL_BACKUP') from None
        status=self.replica.status()
        if not status['ready'] or status['stale']:
            raise ReplicaUnavailable('SQL_REPLICA_NOT_FRESH')
        snapshot=status['sync']['active_backup_id']
        if backup_id is not None and backup_id!=str(snapshot):
            raise Conflict('query snapshot changed; restart detail pagination')
        configured={tid for tid in self.tables.values() if tid and tid in self.replica.config.table_ids}
        with self.replica.backups.query_connection() as db:
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            schemas={r['table_id']:r['field_schema'] for r in db.execute('''SELECT table_id,field_schema
                FROM finding_assistant.business_backup_tables WHERE backup_id=%s AND table_id=ANY(%s)''',
                (snapshot,list(configured))).fetchall()}
            if self.tables['box'] not in schemas:raise ReplicaUnavailable('BOX_SCHEMA_NOT_AVAILABLE')
            projection,allowed,key_visible=self.projection(schemas[self.tables['box']],policy,self.tables['box'])
            query='SELECT box_data.record_id,'+projection.sql+' fields,'+key_visible.sql+''' key_visible,
                finding_assistant.query_scalar_text(box_data.fields->'箱号') relation_key
                FROM finding_assistant.business_backup_records box_data
                WHERE backup_id=%s AND table_id=%s AND record_id=%s AND '''+allowed.sql
            box_params=projection.params+key_visible.params+(snapshot,self.tables['box'],record_id)+allowed.params
            if len(box_params)>20000:raise VisibilityUnavailable('DETAIL_POLICY_TOO_COMPLEX')
            row=db.execute(query,box_params).fetchone()
            if row is None:return {'found':False,'read_only':True,'source':'postgresql','backup_id':str(snapshot)}
            result={'found':True,'record_id':record_id,'box_fields':row['fields'],'sections':{},
                    'read_only':True,'source':'postgresql','backup_id':str(snapshot),
                    'data_age_seconds':status['data_age_seconds'],'stale':False,'business_primary':'feishu'}
            result['linked_fields_withheld']=policy is not None
            result['attachments_withheld']=policy is not None
            if section=='box':return result
            unique = False
            if row['key_visible'] and row['relation_key']:
                matches=db.execute('''SELECT record_id FROM finding_assistant.business_backup_records
                    WHERE backup_id=%s AND table_id=%s AND finding_assistant.query_scalar_text(fields->'箱号')=%s LIMIT 2''',
                    (snapshot,self.tables['box'],row['relation_key'])).fetchall()
                unique=len(matches)==1
            roles=('details','flows','ledger') if section=='all' else (section,)
            for role in roles:
                table=self.tables.get(role)
                if not table or table not in schemas:
                    result['sections'][role]={'available':False,'reason':'TABLE_NOT_IN_SNAPSHOT'};continue
                if not row['key_visible'] or not row['relation_key']:
                    result['sections'][role]={'available':False,'reason':'RELATION_KEY_NOT_VISIBLE'};continue
                if not unique:
                    result['sections'][role]={'available':False,'reason':'RELATION_KEY_UNCONFIRMED'};continue
                projected,restricted,_=self.projection(schemas[table],policy,table)
                if policy is not None:
                    visibility=table_visibility(policy['roles'],table,schemas[table])
                    if not any(g.fields for g in visibility.grants):
                        result['sections'][role]={'available':False,'reason':'TABLE_ACCESS_DENIED'};continue
                names=[f'箱号{i}' for i in range(1,37)] if role=='flows' else ['箱号/行' if role=='ledger' else '箱号']
                matches=combine('OR',[combine('AND',(
                    visibility.field(name,'box_data') if policy is not None else TRUE,
                    Clause('finding_assistant.query_scalar_text(box_data.fields->%s)=%s',
                          (name,row['relation_key'])))) for name in names])
                where=combine('AND',(Clause('backup_id=%s AND table_id=%s',(snapshot,table)),restricted,matches))
                params=projected.params+where.params+(limit+1,offset)
                if len(params)>20000:raise VisibilityUnavailable('DETAIL_POLICY_TOO_COMPLEX')
                records=db.execute('SELECT box_data.record_id,'+projected.sql+''' fields
                    FROM finding_assistant.business_backup_records box_data WHERE '''+where.sql+
                    ' ORDER BY box_data.record_id LIMIT %s OFFSET %s',params).fetchall()
                result['sections'][role]={'available':True,'table_id':table,'items':records[:limit],
                    'has_more':len(records)>limit,'next_offset':offset+limit if len(records)>limit else None,'limit':limit}
            return result
