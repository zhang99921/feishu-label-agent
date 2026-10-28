"""分页暂存完整副本；内存随单页增长，发布前的数据始终不可用于日常检索。"""
import hashlib
import json
import uuid

from psycopg.types.json import Jsonb

from .business_backups import BOX_INDEX_VERSION, link_ids, quantity_value, text

CAPTURE_METHOD = 'query_sync_stream'
CONTENT_DIGEST_VERSION = 2
PAGE_SIZE = 100


def content_checksum(db, key):
    """沿用摘要版本2；调用方提供连接，巡检可与活动版本检查共享只读快照。"""
    digest = hashlib.sha256()

    def frame(value):
        data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        digest.update(len(data).to_bytes(8, 'big'))
        digest.update(data)

    tables = db.execute('''SELECT table_id,table_name,field_schema FROM finding_assistant.business_backup_tables
        WHERE backup_id=%s ORDER BY table_id''', (key,)).fetchall()
    for table in tables:
        frame(['table', table['table_id'], table['table_name'], table['field_schema']])
        with db.cursor(name='backup_digest') as cursor:
            cursor.execute('''SELECT record_id,fields FROM finding_assistant.business_backup_records
                WHERE backup_id=%s AND table_id=%s ORDER BY record_id''', (key, table['table_id']))
            while batch := cursor.fetchmany(PAGE_SIZE):
                for row in batch:
                    frame(['record', row['record_id'], row['fields']])
    return digest.hexdigest()


class StreamingBackups:
    def __init__(self, backups):
        self.tasks = backups.tasks

    def begin(self, base, scope_hash, started):
        key = uuid.uuid4()
        metadata = {'capture_method': CAPTURE_METHOD, 'scope_hash': scope_hash,
                    'box_index_version': BOX_INDEX_VERSION, 'content_digest_version': CONTENT_DIGEST_VERSION,
                    'source_versions_version': 1}
        with self.tasks.connect() as db:
            db.execute('''INSERT INTO finding_assistant.business_backups
                (backup_id,base_token,state,metadata,started_at) VALUES(%s,%s,'RUNNING',%s,%s)''',
                (key, base, Jsonb(metadata), started))
        return key

    @staticmethod
    def _running(db, key):
        row = db.execute('''SELECT state,metadata FROM finding_assistant.business_backups
            WHERE backup_id=%s FOR UPDATE''', (key,)).fetchone()
        if not row or row['state'] != 'RUNNING' or row['metadata'].get('capture_method') != CAPTURE_METHOD:
            raise ValueError('STREAM_BACKUP_NOT_RUNNING')

    def stage(self, key, events, expected_ids):
        """每页独立提交；PK负责跨页去重，不维护全表record_id集合。"""
        seen, completed, current = set(), set(), None
        stats = {'table_count': 0, 'record_count': 0, 'record_pages': 0, 'max_page_records': 0}
        for event in events:
            tid, kind = event.get('table_id'), event.get('event')
            if tid not in expected_ids:
                raise ValueError('STREAM_CATALOG_SCOPE_MISMATCH')
            if kind == 'table':
                if current is not None or tid in seen:
                    raise ValueError('STREAM_TABLE_SEQUENCE_INVALID')
                schema = event['fields']
                if not isinstance(schema, list) or any(not isinstance(f, dict) or
                        not isinstance(f.get('field_name'), str) or not f['field_name'] for f in schema):
                    raise ValueError('BACKUP_FIELD_INVALID')
                names = [f['field_name'] for f in schema]
                if len(names) != len(set(names)):
                    raise ValueError('BACKUP_FIELD_AMBIGUOUS')
                if not isinstance(event.get('table_name'), str):
                    raise ValueError('BACKUP_TABLE_NAME_INVALID')
                with self.tasks.connect() as db:
                    self._running(db, key)
                    db.execute('INSERT INTO finding_assistant.business_backup_tables VALUES(%s,%s,%s,%s)',
                               (key, tid, event['table_name'], Jsonb(schema)))
                current = tid
                seen.add(tid)
            elif kind == 'records' and current == tid:
                records = event['records']
                if not isinstance(records, list) or len(records) > PAGE_SIZE:
                    raise ValueError('STREAM_PAGE_SIZE_INVALID')
                for record in records:
                    if (not isinstance(record, dict) or not isinstance(record.get('record_id'), str)
                            or not record['record_id'] or not isinstance(record.get('fields'), dict)):
                        raise ValueError('BACKUP_RECORD_AMBIGUOUS')
                    modified = record.get('last_modified_time')
                    if modified is not None and (type(modified) is not int or not 0 <= modified <= 9223372036854775807):
                        raise ValueError('BACKUP_MODIFIED_TIME_INVALID')
                with self.tasks.connect() as db:
                    self._running(db, key)
                    with db.cursor() as cursor:
                        cursor.executemany('''INSERT INTO finding_assistant.business_backup_records
                            (backup_id,table_id,record_id,fields,source_modified_time) VALUES(%s,%s,%s,%s,%s)''',
                            ((key, tid, r['record_id'], Jsonb(r['fields']), r.get('last_modified_time')) for r in records))
                stats['record_pages'] += 1
                stats['record_count'] += len(records)
                stats['max_page_records'] = max(stats['max_page_records'], len(records))
            elif kind == 'end_table' and current == tid:
                completed.add(tid)
                current = None
            else:
                raise ValueError('STREAM_EVENT_SEQUENCE_INVALID')
        if current is not None or completed != set(expected_ids):
            raise ValueError('STREAM_CATALOG_INCOMPLETE')
        stats['table_count'] = len(completed)
        return stats

    def checksum(self, key):
        """排序由SQL完成，服务端游标逐批哈希；分页顺序不影响内容摘要。"""
        with self.tasks.connect() as db:
            return content_checksum(db, key)

    def finish(self, key, checksum, stats):
        """只保留一页箱数据和该页关联行；索引校验失败不公开任何新数据。"""
        with self.tasks.connect() as db:
            self._running(db, key)
            tables = db.execute('''SELECT table_id,field_schema FROM finding_assistant.business_backup_tables
                WHERE backup_id=%s''', (key,)).fetchall()
            schemas = {t['table_id']: {f['field_name']: f for f in t['field_schema']} for t in tables}
            for tid, fields in schemas.items():
                if not {'箱号', '状态', '行', '本箱套数'} <= fields.keys():
                    continue
                target = fields['行'].get('property', {}).get('table_id')
                row_source = {'行码', '仓'} <= schemas.get(target, {}).keys()
                with db.cursor(name='backup_box_index') as cursor:
                    cursor.execute('''SELECT record_id,fields FROM finding_assistant.business_backup_records
                        WHERE backup_id=%s AND table_id=%s ORDER BY record_id''', (key, tid))
                    while batch := cursor.fetchmany(PAGE_SIZE):
                        linked = [(r, link_ids(r['fields'].get('行'))) for r in batch]
                        if any(len(ids) > 1 for _, ids in linked):
                            raise ValueError('BACKUP_BOX_MULTIPLE_LOCATIONS')
                        ids = list({ids[0] for _, ids in linked if ids})
                        if ids and not row_source:
                            raise ValueError('BACKUP_ROW_SOURCE_MISSING')
                        rows = (db.execute('''SELECT record_id,fields FROM finding_assistant.business_backup_records
                            WHERE backup_id=%s AND table_id=%s AND record_id=ANY(%s)''',
                            (key, target, ids)).fetchall() if ids else [])
                        row_map = {r['record_id']: r['fields'] for r in rows}
                        if len(row_map) != len(ids):
                            raise ValueError('BACKUP_ROW_SOURCE_MISSING')
                        values = []
                        for r, ids in linked:
                            f = r['fields']
                            row = row_map[ids[0]] if ids else {}
                            values.append((key, tid, r['record_id'], text(f.get('箱号')), text(f.get('标上FNSKU')),
                                text(f.get('SKU')), text(f.get('PO单号')), text(f.get('状态')), text(row.get('行码')),
                                text(f.get('位置码')), text(row.get('仓')), quantity_value(f.get('本箱套数')),
                                target if ids else None, ids[0] if ids else None))
                        with db.cursor() as writer:
                            writer.executemany('''INSERT INTO finding_assistant.business_box_index
                                (backup_id,table_id,record_id,box_code,fnsku,sku,po_number,state,row_code,position_code,
                                 warehouse,quantity,row_table_id,row_record_id)
                                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)''', values)
            db.execute('''UPDATE finding_assistant.business_backups SET state='SUCCEEDED',finished_at=clock_timestamp(),
                table_count=%s,record_count=%s,content_sha256=%s,metadata=metadata||%s WHERE backup_id=%s''',
                (stats['table_count'], stats['record_count'], checksum, Jsonb({'stream_stats': stats}), key))

    def discard(self, key, base, failure_code=None):
        """只清理本实现自己创建且从未发布的暂存；已完成版本、人工归档均不在范围内。"""
        with self.tasks.connect() as db:
            row = db.execute('''SELECT state,metadata FROM finding_assistant.business_backups
                WHERE backup_id=%s AND base_token=%s FOR UPDATE''', (key, base)).fetchone()
            if not row or row['state'] != 'RUNNING' or row['metadata'].get('capture_method') != CAPTURE_METHOD:
                return False
            referenced = db.execute('''SELECT EXISTS(SELECT 1 FROM finding_assistant.business_sync_sources
                WHERE active_backup_id=%s) OR EXISTS(SELECT 1 FROM finding_assistant.query_access_snapshots
                WHERE source_backup_id=%s) AS protected''', (key, key)).fetchone()['protected']
            if referenced:
                raise ValueError('STREAM_STAGING_REFERENCED')
            for table in ('business_box_index', 'business_backup_records', 'business_backup_tables'):
                db.execute('DELETE FROM finding_assistant.' + table + ' WHERE backup_id=%s', (key,))
            if failure_code:
                db.execute('''UPDATE finding_assistant.business_backups SET state='FAILED',failure_code=%s,
                    finished_at=clock_timestamp() WHERE backup_id=%s''', (failure_code, key))
            else:
                db.execute('DELETE FROM finding_assistant.business_backups WHERE backup_id=%s', (key,))
        return True

    def recover_abandoned(self, base):
        """调用方须持有Base同步锁；中断暂存留失败头，不影响旧完整版本及其他导入。"""
        with self.tasks.connect() as db:
            keys = db.execute('''SELECT backup_id FROM finding_assistant.business_backups
                WHERE base_token=%s AND state='RUNNING' AND metadata->>'capture_method'=%s
                ORDER BY started_at LIMIT 20''', (base, CAPTURE_METHOD)).fetchall()
        return sum(self.discard(r['backup_id'], base, 'SYNC_INTERRUPTED') for r in keys)
