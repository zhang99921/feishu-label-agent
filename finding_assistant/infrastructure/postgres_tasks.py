"""PostgreSQL 内部任务登记：持久幂等、输入漂移隔离及逐箱任务，非库存主库。"""
from importlib.resources import files
import hashlib

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

MIGRATIONS = ('001_scan_tasks.sql', '002_identity_operations.sql', '003_location_reservations.sql', '004_session_refresh.sql', '005_business_backups.sql', '006_position_reservations.sql', '007_inventory_execution.sql', '008_business_sync.sql', '009_query_visibility.sql', '010_incremental_sync.sql', '011_validation_feedback.sql', '012_partial_row_compatibility.sql', '013_warehouse_tasks.sql')


def migration_source(name):
    sql = files('finding_assistant.infrastructure.sql').joinpath(name).read_text(encoding='utf-8')
    return sql, hashlib.sha256(sql.encode()).hexdigest()


class PostgresTasks:
    def __init__(self, dsn):
        if not isinstance(dsn, str) or not dsn:
            raise ValueError("DATABASE_URL_REQUIRED")
        # DSN 可能含密码，不提供 repr，也不写入日志或异常文案。
        self._dsn = dsn

    def connect(self):
        return psycopg.connect(self._dsn, connect_timeout=5, row_factory=dict_row)

    def ready(self):
        """只读检查全部迁移和校验和；不在后台自动补建或修正数据库。"""
        with self.connect() as connection:
            rows = connection.execute('SELECT version, checksum FROM finding_assistant.schema_migrations').fetchall()
        installed = {row['version']: row['checksum'] for row in rows}
        for name in MIGRATIONS:
            if name not in installed:
                raise ValueError('DATABASE_MIGRATION_REQUIRED')
            if installed[name] != migration_source(name)[1]:
                raise ValueError('MIGRATION_CHECKSUM_MISMATCH')

    def initialize(self):
        """显式运行迁移；启动/轮询不会悄悄建立或更改表结构。"""
        with self.connect() as connection:
            # 防止两个初始化进程同时建表；使用与任务执行无关的事务级迁移锁。
            connection.execute("SELECT pg_advisory_xact_lock(714021001)")
            connection.execute('CREATE SCHEMA IF NOT EXISTS finding_assistant')
            connection.execute('''CREATE TABLE IF NOT EXISTS finding_assistant.schema_migrations (
                version text PRIMARY KEY, checksum char(64) NOT NULL,
                applied_at timestamptz NOT NULL DEFAULT now())''')
            for name in MIGRATIONS:
                sql, checksum = migration_source(name)
                existing = connection.execute('SELECT checksum FROM finding_assistant.schema_migrations WHERE version=%s',(name,)).fetchone()
                if existing:
                    if existing['checksum'] != checksum:
                        raise ValueError('MIGRATION_CHECKSUM_MISMATCH')
                    continue
                connection.execute(sql)
                connection.execute('INSERT INTO finding_assistant.schema_migrations(version,checksum) VALUES (%s,%s)',(name,checksum))

    def enqueue(self, submission):
        """唯一键与行锁协调不同进程；连接上下文成功提交、异常回滚。"""
        state = "BLOCKED" if submission.errors else "QUEUED"
        with self.connect() as connection:
            inserted = connection.execute("""
                INSERT INTO finding_assistant.scan_jobs
                    (source_key, source_record_id, fingerprint, action, state, payload)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (source_key) DO NOTHING RETURNING source_key
            """, (submission.source_key, submission.source_record_id, submission.fingerprint,
                  submission.action, state, Jsonb(submission.payload()))).fetchone()
            if inserted:
                for position, box in enumerate(submission.boxes, 1):
                    connection.execute("""
                        INSERT INTO finding_assistant.scan_items (source_key, position, box_code)
                        VALUES (%s, %s, %s)
                    """, (submission.source_key, position, box))
                connection.execute("""
                    INSERT INTO finding_assistant.scan_job_events (source_key, event_code)
                    VALUES (%s, %s)
                """, (submission.source_key, state))
                return state.lower()
            current = connection.execute("""
                SELECT fingerprint, state FROM finding_assistant.scan_jobs
                WHERE source_key = %s FOR UPDATE
            """, (submission.source_key,)).fetchone()
            if current["fingerprint"] == submission.fingerprint:
                return "duplicate"
            # 原始任务与逐箱输入保持不变；源行被编辑后只隔离，不自动替换或再次过账。
            if current["state"] != "RECONCILE":
                connection.execute("""
                    UPDATE finding_assistant.scan_jobs
                    SET state = 'RECONCILE', updated_at = now() WHERE source_key = %s
                """, (submission.source_key,))
                connection.execute("""
                    INSERT INTO finding_assistant.scan_job_events (source_key, event_code)
                    VALUES (%s, 'SOURCE_CHANGED')
                """, (submission.source_key,))
            return "reconcile"

    def counts(self):
        with self.connect() as connection:
            return {row["state"]: row["count"] for row in connection.execute(
                "SELECT state, count(*) AS count FROM finding_assistant.scan_jobs GROUP BY state"
            )}
