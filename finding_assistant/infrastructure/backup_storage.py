"""副本存储统计与保留策略预览。所有连接只读，本模块不执行历史版本删除。"""
import re


class BackupStorage:
    def __init__(self, backups, base):
        if not isinstance(base, str) or not re.fullmatch(r'[A-Za-z0-9_]+', base):
            raise ValueError('BACKUP_STORAGE_BASE_REQUIRED')
        self.backups, self.base = backups, base

    def status(self):
        with self.backups.query_connection() as db:
            versions = db.execute('''SELECT state,count(*) AS versions,sum(record_count) AS completed_records,
                min(started_at) AS oldest_started_at,max(started_at) AS newest_started_at
                FROM finding_assistant.business_backups WHERE base_token=%s GROUP BY state ORDER BY state''',
                (self.base,)).fetchall()
            data = db.execute('''SELECT count(*) AS stored_records,coalesce(sum(pg_column_size(r)),0) AS logical_record_bytes
                FROM finding_assistant.business_backup_records r JOIN finding_assistant.business_backups b
                ON b.backup_id=r.backup_id WHERE b.base_token=%s''', (self.base,)).fetchone()
            # 物理表占用包含所有Base、索引及空闲页，不能冒充本Base的精确磁盘占用。
            relations = db.execute('''SELECT c.relname AS relation,pg_total_relation_size(c.oid) AS physical_bytes
                FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                WHERE n.nspname='finding_assistant' AND c.relname IN
                ('business_backups','business_backup_tables','business_backup_records','business_box_index')
                ORDER BY c.relname''').fetchall()
        return {'versions': versions, 'base_data': data, 'relations_all_bases': relations,
                'read_only': True, 'deletion_executed': False, 'retention_policy_configured': False}

    def preview(self, scope_hash, *, keep_days, keep_latest, limit=50, offset=0):
        """只预览过期日常副本；保留策略由调用者显式提供，不写为默认自动清理配置。"""
        if (not isinstance(scope_hash, str) or not re.fullmatch(r'[a-f0-9]{64}', scope_hash)
                or type(keep_days) is not int or not 1 <= keep_days <= 36500
                or type(keep_latest) is not int or not 1 <= keep_latest <= 100000
                or type(limit) is not int or not 1 <= limit <= 100
                or type(offset) is not int or not 0 <= offset <= 1000000):
            raise ValueError('BACKUP_RETENTION_PREVIEW_ARGUMENTS_INVALID')
        cte = '''WITH routine AS (
            SELECT b.*,row_number() OVER(ORDER BY started_at DESC,backup_id DESC) AS recency
            FROM finding_assistant.business_backups b WHERE base_token=%s AND state='SUCCEEDED'
            AND metadata->>'capture_method' IN ('query_sync','query_sync_stream') AND metadata->>'scope_hash'=%s
        ), candidates AS (
            SELECT backup_id,started_at,finished_at,table_count,record_count FROM routine b
            WHERE started_at < current_timestamp-(%s * interval '1 day') AND recency>%s
            AND coalesce(metadata->>'protected','false') NOT IN ('true','1','yes')
            AND coalesce(metadata->>'pinned','false') NOT IN ('true','1','yes')
            AND coalesce(metadata->>'retain','false') NOT IN ('true','1','yes')
            AND coalesce(metadata->>'retention','')<>'keep'
            AND NOT EXISTS(SELECT 1 FROM finding_assistant.business_sync_sources s WHERE s.active_backup_id=b.backup_id)
            AND NOT EXISTS(SELECT 1 FROM finding_assistant.query_access_snapshots q WHERE q.source_backup_id=b.backup_id)
        ) '''
        params = (self.base, scope_hash, keep_days, keep_latest)
        with self.backups.query_connection() as db:
            # 两次统计读取同一个数据库快照，避免同步发布恰好发生于预览分页之间。
            db.execute('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ')
            summary = db.execute(cte + '''SELECT count(*) AS candidate_versions,
                coalesce(sum(record_count),0) AS candidate_records FROM candidates''', params).fetchone()
            rows = db.execute(cte + '''SELECT * FROM candidates ORDER BY started_at,backup_id LIMIT %s OFFSET %s''',
                              (*params, limit + 1, offset)).fetchall()
        return {**summary, 'items': rows[:limit], 'has_more': len(rows) > limit,
                'next_offset': offset + limit if len(rows) > limit else None,
                'policy_preview': {'keep_days': keep_days, 'keep_latest': keep_latest, 'scope_hash': scope_hash},
                'protected': ['active_query_version', 'permission_snapshot_reference', 'manual_archive',
                              'explicit_pin', 'other_scope_or_base', 'unfinished_or_failed', 'latest_versions'],
                'read_only': True, 'deletion_executed': False}
