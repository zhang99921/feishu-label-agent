"""飞书主存的只读同步与原子发布；历史备份和日常查询版本分别管理。"""
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import re
import time
import uuid

from psycopg.types.json import Jsonb

from .business_backups import BOX_INDEX_VERSION, BusinessBackups, catalog_checksum
from .environment import env_bool
from .streaming_backups import CONTENT_DIGEST_VERSION, StreamingBackups
from .streaming_backups import content_checksum
from ..adapters.feishu.incremental_reader import IncrementalReader, IncrementalFallback
from ..adapters.feishu.existing_forms import SourceUnavailable


class ReplicaUnavailable(Exception):
    """还没有可查询的完整副本；不得回退为在线全表读取。"""


@dataclass(frozen=True)
class SyncConfig:
    table_ids: tuple[str, ...]
    interval: int = 60
    stale_seconds: int = 300
    incremental: bool = False
    full_seconds: int = 3600

    @classmethod
    def from_values(cls, values):
        raw = values.get('FEISHU_SYNC_TABLE_IDS', '')
        ids = raw.split(',') if isinstance(raw, str) and raw.strip() else []
        ids = tuple(sorted(x.strip() for x in ids))
        if not ids or len(ids) != len(set(ids)) or any(not re.fullmatch(r'[A-Za-z0-9]+', x) for x in ids):
            raise ValueError('EXPLICIT_SYNC_TABLE_IDS_REQUIRED')
        try:
            interval = int(values.get('FEISHU_SYNC_SECONDS', '60'))
            stale = int(values.get('FINDING_ASSISTANT_SQL_STALE_SECONDS', '300'))
            if not 10 <= interval <= 86400 or not interval <= stale <= 604800:
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError('INVALID_SYNC_INTERVAL_OR_FRESHNESS') from None
        incremental = env_bool(values, 'FINDING_ASSISTANT_ENABLE_INCREMENTAL_SYNC')
        try:
            full = int(values.get('FEISHU_SYNC_FULL_SECONDS', '3600'))
            if not 60 <= full <= 604800:raise ValueError
        except (ValueError, TypeError):
            raise ValueError('INVALID_FULL_SYNC_INTERVAL') from None
        return cls(ids, interval, stale, incremental, full)


def query_enabled(values):
    return env_bool(values, 'FINDING_ASSISTANT_ENABLE_SQL_QUERY')


class BusinessSync:
    def __init__(self, dsn, base_token, config):
        if not isinstance(base_token, str) or not re.fullmatch(r'[A-Za-z0-9_]+', base_token):
            raise ValueError('SYNC_BASE_REQUIRED')
        self.backups = BusinessBackups(dsn)
        self.base = base_token
        self.config = config
        self.scope_hash = hashlib.sha256(json.dumps(sorted(config.table_ids)).encode()).hexdigest()
        # 按Base互斥，避免不同表清单的两个worker抢着发布日常查询版本。
        self.lock_key = int.from_bytes(hashlib.sha256(('business-sync:' + base_token).encode()).digest()[:8],
                                       'big', signed=True)

    def sync_once(self, reader):
        """完整读完才发布；远端失败、进程中断或结构异常均保留上次完整版本。"""
        self.backups.tasks.ready()
        with self.backups.tasks.connect() as guard:
            guard.autocommit = True
            locked = guard.execute('SELECT pg_try_advisory_lock(%s) AS locked', (self.lock_key,)).fetchone()['locked']
            if not locked:
                return {'outcome': 'BUSY', 'feishu_written': False}
            key = None
            stream = None
            metrics = {}
            timer = time.monotonic()
            started = guard.execute('SELECT clock_timestamp() AS t').fetchone()['t']
            guard.execute('''INSERT INTO finding_assistant.business_sync_sources
                (base_token,table_ids,scope_hash,state,started_at) VALUES(%s,%s,%s,'SYNCING',%s)
                ON CONFLICT(base_token) DO UPDATE SET state='SYNCING',started_at=excluded.started_at,
                failure_code=NULL''', (self.base, Jsonb(list(self.config.table_ids)), self.scope_hash, started))
            try:
                reader.source.login()
                if reader.base_token != self.base:
                    raise ValueError('SYNC_BASE_MISMATCH')
                previous = guard.execute('''SELECT s.active_backup_id,b.content_sha256,b.metadata,s.scope_hash,
                    s.last_full_read_started_at FROM finding_assistant.business_sync_sources s
                    LEFT JOIN finding_assistant.business_backups b ON b.backup_id=s.active_backup_id
                    AND b.state='SUCCEEDED' AND b.base_token=s.base_token WHERE s.base_token=%s''', (self.base,)).fetchone()
                full_read = True
                cache_invalid = False
                # 实际HTTP读取器走逐页暂存；旧手工导入适配器仍支持原完整目录协议。
                if callable(getattr(reader, 'stream_catalog', None)):
                    stream = StreamingBackups(self.backups)
                    recovered = stream.recover_abandoned(self.base)
                    key = stream.begin(self.base, self.scope_hash, started)
                    selected = reader
                    fallback = False
                    if self.config.incremental:
                        full_read = not (previous['active_backup_id'] and previous['scope_hash'] == self.scope_hash
                            and previous['metadata'] and previous['metadata'].get('incremental_baseline') is True
                            and previous['last_full_read_started_at']
                            and (started - previous['last_full_read_started_at']).total_seconds() < self.config.full_seconds)
                        if not full_read:
                            # 不把已损坏的本地原始数据当作可信缓存；核验不通过时改用源全读。
                            with self.backups.query_connection() as db:
                                cache_invalid = content_checksum(db, previous['active_backup_id']) != previous['content_sha256']
                                full_read = cache_invalid
                        selected = IncrementalReader(reader, self.backups, None if full_read else previous['active_backup_id'])
                    try:
                        stats = stream.stage(key, selected.stream_catalog(list(self.config.table_ids)), self.config.table_ids)
                    except (IncrementalFallback, SourceUnavailable):
                        if not self.config.incremental or full_read:raise
                        stream.discard(key, self.base, 'INCREMENTAL_FALLBACK')
                        key = stream.begin(self.base, self.scope_hash, started)
                        selected = IncrementalReader(reader, self.backups)
                        full_read = fallback = True
                        stats = stream.stage(key, selected.stream_catalog(list(self.config.table_ids)), self.config.table_ids)
                    checksum = stream.checksum(key)
                    metrics = {**stats, 'interrupted_stages_recovered': recovered, 'streaming': True,
                               'sync_mode': 'full' if full_read else 'incremental', 'incremental_fallback': fallback,
                               'cache_verification_failed': cache_invalid,
                               **(selected.metrics if self.config.incremental else {})}
                else:
                    catalog = reader.catalog(list(self.config.table_ids))
                    if sorted(t['table_id'] for t in catalog) != list(self.config.table_ids):
                        raise ValueError('SYNC_CATALOG_SCOPE_MISMATCH')
                    checksum = catalog_checksum(catalog)
                if reader.base_token != self.base:
                    raise ValueError('SYNC_BASE_MISMATCH')
                changed = not (not cache_invalid and previous['active_backup_id'] and previous['scope_hash'] == self.scope_hash
                               and previous['content_sha256'] == checksum
                               and previous['metadata'].get('box_index_version') == BOX_INDEX_VERSION
                               and (not stream or previous['metadata'].get('content_digest_version') == CONTENT_DIGEST_VERSION)
                               and (not self.config.incremental or previous['metadata'].get('incremental_baseline') is True))
                if changed:
                    if stream:
                        guard.execute('''UPDATE finding_assistant.business_backups SET metadata=metadata||%s
                            WHERE backup_id=%s AND state='RUNNING' ''',
                            (Jsonb({'incremental_baseline': self.config.incremental, 'sync_mode': metrics['sync_mode']}), key))
                        stream.finish(key, checksum, stats)
                    else:
                        key = uuid.uuid4()
                        guard.execute('''INSERT INTO finding_assistant.business_backups
                            (backup_id,base_token,state,metadata,started_at) VALUES(%s,%s,'RUNNING',%s,%s)''',
                            (key, self.base, Jsonb({'capture_method': 'query_sync', 'scope_hash': self.scope_hash,
                                                   'box_index_version': BOX_INDEX_VERSION}), started))
                        self.backups._finish(key, catalog)
                else:
                    if stream:
                        if self.config.incremental:
                            with self.backups.tasks.connect() as db:
                                # 原始字段和摘要未变，仅刷新系统更新时间，避免同值编辑反复回读。
                                db.execute('''UPDATE finding_assistant.business_backup_records old
                                    SET source_modified_time=fresh.source_modified_time
                                    FROM finding_assistant.business_backup_records fresh
                                    WHERE old.backup_id=%s AND fresh.backup_id=%s
                                    AND old.table_id=fresh.table_id AND old.record_id=fresh.record_id
                                    AND old.source_modified_time IS DISTINCT FROM fresh.source_modified_time''',
                                    (previous['active_backup_id'], key))
                        stream.discard(key, self.base)
                    key = previous['active_backup_id']
                # 使用持有会话锁的同一连接提交发布；连接丢失后不能另连冒充仍持有锁。
                guard.execute('''UPDATE finding_assistant.business_sync_sources SET table_ids=%s,scope_hash=%s,
                    active_backup_id=%s,state='SUCCEEDED',last_finished_at=clock_timestamp(),
                    last_checked_at=clock_timestamp(),source_read_started_at=%s,
                    last_full_read_started_at=CASE WHEN %s THEN %s ELSE last_full_read_started_at END,
                    last_changed_at=CASE WHEN %s THEN clock_timestamp() ELSE last_changed_at END,
                    failure_code=NULL,failure_count=0 WHERE base_token=%s''',
                    (Jsonb(list(self.config.table_ids)), self.scope_hash, key, started, full_read, started, changed, self.base))
                return {'outcome': 'UPDATED' if changed else 'UNCHANGED', 'backup_id': str(key),
                        'metrics': {**metrics, 'duration_seconds': round(time.monotonic() - timer, 3)},
                        'feishu_written': False, **self.status()}
            except BaseException as error:
                if stream and key:
                    # 清理失败不得覆盖最初故障；残留RUNNING暂存在下轮持锁后回收。
                    try:
                        stream.discard(key, self.base, type(error).__name__)
                    except Exception:
                        pass
                # 不存异常原文，其中可能包含URL、凭据或业务原数据。
                with self.backups.tasks.connect() as db:
                    db.execute('''UPDATE finding_assistant.business_sync_sources SET state='FAILED',
                        last_finished_at=clock_timestamp(),failure_code=%s,failure_count=failure_count+1
                        WHERE base_token=%s AND started_at=%s''',
                        (type(error).__name__, self.base, started))
                    if key and not stream:
                        db.execute('''UPDATE finding_assistant.business_backups SET state='FAILED',
                            failure_code=%s,finished_at=clock_timestamp() WHERE backup_id=%s AND state='RUNNING' ''',
                            (type(error).__name__, key))
                raise
            # 关闭guard连接释放会话锁，崩溃后由PostgreSQL自动释放，无须清理业务状态。

    def status(self):
        with self.backups.query_connection() as db:
            row = db.execute('''SELECT s.*,b.table_count,b.record_count
                FROM finding_assistant.business_sync_sources s LEFT JOIN finding_assistant.business_backups b
                ON b.backup_id=s.active_backup_id AND b.base_token=s.base_token AND b.state='SUCCEEDED'
                WHERE s.base_token=%s''', (self.base,)).fetchone()
        ready = bool(row and row['active_backup_id'] and row['record_count'] is not None
                     and row['scope_hash'] == self.scope_hash)
        checked = row.get('source_read_started_at') if ready else None
        age = max(0, (datetime.now(timezone.utc) - checked).total_seconds()) if checked else None
        return {'ready': ready, 'source': 'postgresql', 'business_primary': 'feishu',
                'sync': row, 'data_age_seconds': round(age, 3) if age is not None else None,
                'stale': age is None or age > self.config.stale_seconds,
                'stale_after_seconds': self.config.stale_seconds, 'read_only': True}

    def boxes(self, **filters):
        status = self.status()
        if not status['ready']:
            raise ReplicaUnavailable('SQL_REPLICA_NOT_READY')
        result = self.backups.boxes(self.base, snapshot_id=status['sync']['active_backup_id'], **filters)
        return {**result, 'replica': status}

    def records(self, table_id, *, limit=20, after_id=None):
        """运维读取任意已配置表；每页返回版本ID，版本变化时调用方应重置分页。"""
        if table_id not in self.config.table_ids or type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError('INVALID_REPLICA_TABLE_OR_LIMIT')
        if after_id is not None and (not isinstance(after_id, str) or not re.fullmatch(r'[A-Za-z0-9]+', after_id)):
            raise ValueError('INVALID_REPLICA_CURSOR')
        status = self.status()
        if not status['ready']:
            raise ReplicaUnavailable('SQL_REPLICA_NOT_READY')
        with self.backups.query_connection() as db:
            rows = db.execute('''SELECT record_id,fields FROM finding_assistant.business_backup_records
                WHERE backup_id=%s AND table_id=%s AND record_id>%s ORDER BY record_id LIMIT %s''',
                (status['sync']['active_backup_id'], table_id, after_id or '', limit + 1)).fetchall()
        return {'items': rows[:limit], 'has_more': len(rows) > limit,
                'next_after_id': rows[limit - 1]['record_id'] if len(rows) > limit else None, 'replica': status}
