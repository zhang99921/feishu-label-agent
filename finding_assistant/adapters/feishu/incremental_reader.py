"""轮询记录清单，复用未变的纯数据记录；依赖/附件/未知类型保守整表读取。"""
import hashlib
import json
import re

from .existing_forms import SourceUnavailable

SAFE_TYPES = frozenset({1, 2, 3, 4, 5, 7, 13, 15, 1005})


class IncrementalFallback(Exception):
    """不能确认增量清单，整轮放弃暂存并改用全量读取。"""


class IncrementalReader:
    def __init__(self, reader, backups, previous_id=None):
        self.reader, self.backups, self.previous_id = reader, backups, previous_id
        self.metrics = {'incremental_tables': 0, 'full_tables': 0, 'reused_records': 0,
                        'changed_records_fetched': 0, 'manifest_pages': 0}

    def _stamp(self, record, primary):
        rid, modified = record.get('record_id'), record.get('last_modified_time')
        if (not isinstance(rid, str) or not re.fullmatch(r'[A-Za-z0-9]+', rid)
                or type(modified) is not int or not 0 <= modified <= 9223372036854775807
                or not isinstance(record.get('fields'), dict) or set(record['fields']) - {primary}):
            raise IncrementalFallback('INCREMENTAL_MANIFEST_UNCONFIRMED')
        return rid, modified

    def _manifest(self, path, primary):
        params = {'automatic_fields': 'true', 'field_names': json.dumps([primary], ensure_ascii=False)}
        for page in self.reader._page_batches(path, params):
            self.metrics['manifest_pages'] += 1
            for record in page:self._stamp(record, primary)
            yield page

    @staticmethod
    def _digest(digest, record):
        value = [record['record_id'], record['last_modified_time'], record['fields']]
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        digest.update(len(encoded).to_bytes(8, 'big'));digest.update(encoded)

    def stream_catalog(self, table_ids):
        root, catalog, ids = self.reader._table_catalog(table_ids)
        for tid in ids:
            schema = self.reader._pages(root+'/'+tid+'/fields')
            old_schema = None
            if self.previous_id:
                with self.backups.query_connection() as db:
                    old_schema = db.execute('''SELECT field_schema FROM finding_assistant.business_backup_tables
                        WHERE backup_id=%s AND table_id=%s''', (self.previous_id, tid)).fetchone()
            primary = [f['field_name'] for f in schema if f.get('is_primary') is True]
            eligible = bool(old_schema and old_schema['field_schema'] == schema and len(primary) == 1
                            and all(f.get('type') in SAFE_TYPES for f in schema))
            path = root+'/'+tid+'/records'
            yield {'event': 'table', 'table_id': tid, 'table_name': catalog[tid]['name'], 'fields': schema}
            if not eligible:
                self.metrics['full_tables'] += 1
                for page in self.reader._page_batches(path, {'automatic_fields': 'true'}):
                    yield {'event': 'records', 'table_id': tid, 'records': page}
            else:
                self.metrics['incremental_tables'] += 1
                first, second = hashlib.sha256(), hashlib.sha256()
                for page in self._manifest(path, primary[0]):
                    record_ids = [r['record_id'] for r in page]
                    with self.backups.query_connection() as db:
                        cached = db.execute('''SELECT record_id,fields,source_modified_time
                            FROM finding_assistant.business_backup_records WHERE backup_id=%s AND table_id=%s
                            AND record_id=ANY(%s)''', (self.previous_id, tid, record_ids)).fetchall()
                    by_id = {r['record_id']: r for r in cached}
                    records = []
                    for observed in page:
                        self._digest(first, observed)
                        rid, modified = self._stamp(observed, primary[0])
                        prior = by_id.get(rid)
                        if (prior and prior['source_modified_time'] == modified
                                and prior['fields'].get(primary[0]) == observed['fields'].get(primary[0])):
                            records.append({'record_id': rid, 'fields': prior['fields'], 'last_modified_time': modified})
                            self.metrics['reused_records'] += 1
                        else:
                            self.metrics['changed_records_fetched'] += 1
                            if self.metrics['changed_records_fetched'] > 100:
                                raise IncrementalFallback('INCREMENTAL_CHANGE_BUDGET_EXCEEDED')
                            data = self.reader.source._request('GET', path+'/'+rid,
                                params={'automatic_fields': 'true', 'user_id_type': 'open_id'}).get('data')
                            record = data.get('record') if isinstance(data, dict) else None
                            if (not isinstance(record, dict) or record.get('record_id') != rid
                                    or type(record.get('last_modified_time')) is not int
                                    or record['last_modified_time'] != modified or not isinstance(record.get('fields'), dict)):
                                raise IncrementalFallback('INCREMENTAL_RECORD_CHANGED_DURING_READ')
                            records.append(record)
                    # 仅当前页的缓存及变更正文留在内存；遗漏的旧ID不会写入新版本，实现删除同步。
                    yield {'event': 'records', 'table_id': tid, 'records': records}
                for page in self._manifest(path, primary[0]):
                    for record in page:self._digest(second, record)
                if first.digest() != second.digest():
                    # 即使只是分页顺序改变，也保守回退；不推断未确认的删除。
                    raise IncrementalFallback('INCREMENTAL_MANIFEST_CHANGED')
            if schema != self.reader._pages(root+'/'+tid+'/fields'):
                raise IncrementalFallback('INCREMENTAL_SCHEMA_CHANGED')
            yield {'event': 'end_table', 'table_id': tid}
