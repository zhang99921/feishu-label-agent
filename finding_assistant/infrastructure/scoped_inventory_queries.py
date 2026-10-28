"""在完整SQL副本内按当前原生权限筛选行、遮蔽字段；不读取飞书业务数据。"""
from psycopg.types.json import Jsonb

from finding_assistant.security.errors import AccessDenied
from finding_assistant.security.sql_visibility import Clause, VisibilityUnavailable, combine, table_visibility
from finding_assistant.security.query_scope import scope_token,require_scope,verify_policy


# 返回列与原始字段的固定映射；不接受客户端提供SQL字段名。
BOX_FIELDS = {'box_code': '箱号', 'fnsku': '标上FNSKU', 'sku': 'SKU', 'po_number': 'PO单号',
              'state': '状态', 'position_code': '位置码', 'quantity': '本箱套数'}
FILTERS = {'box_code', 'fnsku', 'sku', 'po', 'row_code', 'position_code', 'state'}


class ScopedInventoryQueries:
    def __init__(self, replica, app_id, box_table_id, row_table_id):
        if not app_id or box_table_id not in replica.config.table_ids or row_table_id not in replica.config.table_ids:
            raise ValueError('SQL_VISIBILITY_TABLE_SCOPE_REQUIRED')
        self.replica, self.app_id = replica, app_id
        self.box_table, self.row_table = box_table_id, row_table_id

    @staticmethod
    def public_status(status):
        sync = status['sync']
        # 不向普通账号返回全库记录数、表清单、其他账号或完整权限配置。
        return {'ready': status['ready'], 'source': 'postgresql', 'business_primary': 'feishu',
                'backup_id': sync['active_backup_id'], 'data_age_seconds': status['data_age_seconds'],
                'stale': status['stale'], 'source_read_started_at': sync['source_read_started_at'],
                'last_checked_at': sync['last_checked_at'], 'visibility': 'native_row_and_field_rules',
                'permission_check': 'fresh_native_metadata', 'read_only': True}

    def boxes(self, identity, directory, **filters):
        expected_scope=filters.pop('visibility_token',None)
        if set(filters) - FILTERS - {'limit', 'offset'}:
            raise ValueError('INVALID_SQL_QUERY_FILTER')
        limit, offset = filters.pop('limit', 20), filters.pop('offset', 0)
        if type(limit) is not int or not 1 <= limit <= 100 or type(offset) is not int or not 0 <= offset <= 1000000:
            raise ValueError('INVALID_SQL_QUERY_PAGINATION')
        if any(v is not None and (not isinstance(v, str) or not v.strip() or len(v) > 200) for v in filters.values()):
            raise ValueError('INVALID_SQL_QUERY_FILTER')
        status = self.replica.status()
        if not status['ready'] or status['stale']:
            raise VisibilityUnavailable('SQL_VISIBILITY_REPLICA_NOT_FRESH')
        snapshot = status['sync']['active_backup_id']
        with self.replica.backups.query_connection() as db:
            rows = db.execute('''SELECT table_id,field_schema FROM finding_assistant.business_backup_tables
                WHERE backup_id=%s AND table_id=ANY(%s)''', (snapshot, [self.box_table, self.row_table])).fetchall()
        schemas = {r['table_id']: r['field_schema'] for r in rows}
        if set(schemas) != {self.box_table, self.row_table}:
            raise VisibilityUnavailable('SQL_VISIBILITY_SCHEMA_MISSING')
        # 只读取权限元数据。失败不使用上次存下的授权，更不借用应用权限返回全表。
        policy = directory.read(identity)
        token=scope_token(identity,self.app_id,self.replica.base,self.box_table,snapshot,policy)
        require_scope(expected_scope,token,offset)
        box = table_visibility(policy['roles'], self.box_table, schemas[self.box_table])
        row = table_visibility(policy['roles'], self.row_table, schemas[self.row_table])
        if not box.grants or not any(g.fields for g in box.grants):
            raise AccessDenied('native table or field access denied')
        expressions, masks = {}, {}
        for column, field in BOX_FIELDS.items():
            expressions[column] = Clause('idx.' + column)
            masks[column] = box.field(field, 'box_data')
        for column, field in (('row_code', '行码'), ('warehouse', '仓')):
            expressions[column] = Clause('finding_assistant.query_scalar_text(row_data.fields -> %s)', (field,))
            masks[column] = combine('AND', (Clause('row_data.record_id IS NOT NULL'),
                box.field('行', 'box_data'), row.field(field, 'row_data')))
        select = [Clause('idx.table_id'), Clause('idx.record_id')]
        for column, expression in expressions.items():
            mask = masks[column]
            select.append(Clause(f'CASE WHEN {mask.sql} THEN {expression.sql} END AS {column}', mask.params + expression.params))
            select.append(Clause(f'{mask.sql} AS {column}_visible', mask.params))
        where = [Clause('idx.backup_id=%s AND idx.table_id=%s', (snapshot, self.box_table)), box.rows('box_data')]
        for name, value in filters.items():
            if value is None:
                continue
            column = 'po_number' if name == 'po' else name
            expression = expressions[column]
            where.extend((masks[column], Clause(expression.sql + '=%s', expression.params + (value,))))
        restriction = combine('AND', where)
        query = 'SELECT ' + ','.join(c.sql for c in select) + '''
            FROM finding_assistant.business_box_index idx
            JOIN finding_assistant.business_backup_records box_data ON box_data.backup_id=idx.backup_id
                AND box_data.table_id=idx.table_id AND box_data.record_id=idx.record_id
            LEFT JOIN finding_assistant.business_backup_records row_data ON row_data.backup_id=idx.backup_id
                AND row_data.table_id=idx.row_table_id AND row_data.record_id=idx.row_record_id AND row_data.table_id=%s
            WHERE ''' + restriction.sql + ' ORDER BY idx.record_id LIMIT %s OFFSET %s'
        params = tuple(p for clause in select for p in clause.params) + (self.row_table,) + restriction.params + (limit + 1, offset)
        if len(params) > 20000:
            raise VisibilityUnavailable('SQL_VISIBILITY_POLICY_TOO_COMPLEX')
        with self.replica.backups.query_connection() as db:
            rows = db.execute(query, params).fetchall()
        items = []
        for record in rows[:limit]:
            item = {'table_id': record['table_id'], 'record_id': record['record_id']}
            for column in expressions:
                if record[column + '_visible']:
                    item[column] = record[column]
            items.append(item)
        verify_policy(directory,identity,policy)
        # 只保存受控权限依据，供运维追溯；此表不作为下一次请求的放行缓存。
        with self.replica.backups.tasks.connect() as db:
            db.execute('''INSERT INTO finding_assistant.query_access_snapshots
                (app_id,tenant_key,open_id,base_token,table_id,source_backup_id,policy_hash,policy)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(app_id,tenant_key,open_id,base_token,table_id) DO UPDATE SET
                source_backup_id=excluded.source_backup_id,policy_hash=excluded.policy_hash,
                policy=excluded.policy,checked_at=clock_timestamp()''',
                (self.app_id, identity.tenant_key, identity.open_id, self.replica.base, self.box_table,
                 snapshot, policy['policy_hash'], Jsonb(policy['roles'])))
        return {'items': items, 'has_more': len(rows) > limit, 'limit': limit,'visibility_token':token,
                'next_offset': offset + limit if len(rows) > limit else None, 'source': 'postgresql',
                'business_primary': 'feishu', 'read_only': True, 'replica': self.public_status(status)}
