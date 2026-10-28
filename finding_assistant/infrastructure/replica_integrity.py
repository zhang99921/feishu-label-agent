"""只读巡检已发布SQL副本的表范围、记录计数及箱索引覆盖，不自动修复数据。"""
from .business_backups import link_ids, quantity_value, text
from .streaming_backups import CONTENT_DIGEST_VERSION, PAGE_SIZE, content_checksum


def _check_index_values(db, key, tables):
    """逐页重算预期索引；仅返回差异计数，不输出箱号、隐藏字段或原数据。"""
    schemas = {t['table_id']: {f['field_name']: f for f in t['field_schema']} for t in tables}
    checked = mismatched = invalid = 0
    for tid, schema in schemas.items():
        if not {'箱号', '状态', '行', '本箱套数'} <= schema.keys():
            continue
        target = schema['行'].get('property', {}).get('table_id')
        row_source = {'行码', '仓'} <= schemas.get(target, {}).keys()
        with db.cursor(name='replica_index_verify') as cursor:
            cursor.execute('''SELECT r.record_id,r.fields,i.record_id AS indexed_record_id,
                i.box_code,i.fnsku,i.sku,i.po_number,i.state,i.row_code,i.position_code,i.warehouse,
                i.quantity,i.row_table_id,i.row_record_id
                FROM finding_assistant.business_backup_records r LEFT JOIN finding_assistant.business_box_index i
                ON i.backup_id=r.backup_id AND i.table_id=r.table_id AND i.record_id=r.record_id
                WHERE r.backup_id=%s AND r.table_id=%s ORDER BY r.record_id''', (key, tid))
            while batch := cursor.fetchmany(PAGE_SIZE):
                parsed = []
                for r in batch:
                    checked += 1
                    try:
                        if not isinstance(r['fields'], dict):raise ValueError('INVALID_FIELDS')
                        ids = link_ids(r['fields'].get('行'))
                        if len(ids) > 1 or (ids and not row_source):raise ValueError('INVALID_LOCATION')
                        amount = quantity_value(r['fields'].get('本箱套数'))
                        parsed.append((r, ids, amount))
                    except ValueError:
                        invalid += 1
                ids = list({links[0] for _, links, _ in parsed if links})
                rows = db.execute('''SELECT record_id,fields FROM finding_assistant.business_backup_records
                    WHERE backup_id=%s AND table_id=%s AND record_id=ANY(%s)''',
                    (key, target, ids)).fetchall() if ids else []
                locations = {r['record_id']: r['fields'] for r in rows}
                for r, links, amount in parsed:
                    if links and (links[0] not in locations or not isinstance(locations[links[0]], dict)):
                        invalid += 1
                        continue
                    f = r['fields']; row = locations[links[0]] if links else {}
                    expected = {'box_code': text(f.get('箱号')), 'fnsku': text(f.get('标上FNSKU')),
                        'sku': text(f.get('SKU')), 'po_number': text(f.get('PO单号')), 'state': text(f.get('状态')),
                        'row_code': text(row.get('行码')), 'position_code': text(f.get('位置码')),
                        'warehouse': text(row.get('仓')), 'quantity': amount,
                        'row_table_id': target if links else None, 'row_record_id': links[0] if links else None}
                    if r['indexed_record_id'] is None or any(r[name] != value for name, value in expected.items()):
                        mismatched += 1
    return {'checked_records': checked, 'mismatched_records': mismatched, 'invalid_source_records': invalid}


def check_replica(replica, *, verify_content=False):
    if type(verify_content) is not bool:raise ValueError('INVALID_REPLICA_CHECK_MODE')
    deep_issues = []
    content = {'requested': verify_content, 'digest_verified': False, 'index_values_verified': False}
    with replica.backups.query_connection() as db:
        # 固定一个数据库快照及活动版本；同步发布不能让本次巡检混入两个版本。
        db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
        active = db.execute('''SELECT s.scope_hash,b.backup_id,b.state,b.table_count,b.record_count,b.metadata,b.content_sha256
            FROM finding_assistant.business_sync_sources s JOIN finding_assistant.business_backups b
            ON b.backup_id=s.active_backup_id AND b.base_token=s.base_token WHERE s.base_token=%s''',
            (replica.base,)).fetchone()
        if not active or active['state'] != 'SUCCEEDED' or active['scope_hash'] != replica.scope_hash:
            return {'healthy': False, 'issues': ['COMPLETE_REPLICA_NOT_READY'], 'read_only': True,
                    'feishu_checked': False, 'repairs_executed': False}
        key = active['backup_id']
        tables = db.execute('''SELECT t.table_id,t.field_schema,count(r.record_id) AS records
            FROM finding_assistant.business_backup_tables t LEFT JOIN finding_assistant.business_backup_records r
            ON r.backup_id=t.backup_id AND r.table_id=t.table_id WHERE t.backup_id=%s
            GROUP BY t.table_id,t.field_schema ORDER BY t.table_id''', (key,)).fetchall()
        indexes = db.execute('''SELECT table_id,count(*) AS records FROM finding_assistant.business_box_index
            WHERE backup_id=%s GROUP BY table_id ORDER BY table_id''', (key,)).fetchall()
        if verify_content:
            if active['metadata'].get('content_digest_version') != CONTENT_DIGEST_VERSION:
                deep_issues.append('REPLICA_DIGEST_VERSION_UNSUPPORTED')
            elif content_checksum(db, key) != active['content_sha256']:
                deep_issues.append('REPLICA_CONTENT_DIGEST_MISMATCH')
            else:
                content['digest_verified'] = True
            content.update(_check_index_values(db, key, tables))
            if content['invalid_source_records']:
                deep_issues.append('REPLICA_INDEX_SOURCE_INVALID')
            if content['mismatched_records']:
                deep_issues.append('REPLICA_INDEX_VALUES_MISMATCH')
            content['index_values_verified'] = not (content['invalid_source_records'] or content['mismatched_records'])
    issues = deep_issues
    if {t['table_id'] for t in tables} != set(replica.config.table_ids):
        issues.append('REPLICA_TABLE_SCOPE_MISMATCH')
    if len(tables) != active['table_count']:
        issues.append('REPLICA_TABLE_COUNT_MISMATCH')
    if sum(t['records'] for t in tables) != active['record_count']:
        issues.append('REPLICA_RECORD_COUNT_MISMATCH')
    box_tables = {t['table_id']: t['records'] for t in tables
                  if {'箱号', '状态', '行', '本箱套数'} <= {f['field_name'] for f in t['field_schema']}}
    actual = {r['table_id']: r['records'] for r in indexes}
    if any(actual.get(tid, 0) != count for tid, count in box_tables.items()) or set(actual) - box_tables.keys():
        issues.append('REPLICA_BOX_INDEX_COVERAGE_MISMATCH')
    return {'healthy': not issues, 'issues': issues, 'backup_id': str(key),
            'table_count': len(tables), 'record_count': sum(t['records'] for t in tables),
            'box_index_records': sum(actual.values()), 'read_only': True, 'feishu_checked': False,
            'repairs_executed': False, 'content': content,
            'checks': ['configured_table_scope', 'header_counts', 'box_index_coverage'] +
                      (['content_digest', 'box_index_values'] if verify_content else [])}
