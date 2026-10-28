-- 查询使用显式发布的完整副本，手工备份不能覆盖这个指针。
CREATE TABLE finding_assistant.business_sync_sources (
    base_token text PRIMARY KEY,
    table_ids jsonb NOT NULL CHECK (jsonb_typeof(table_ids) = 'array'),
    scope_hash char(64) NOT NULL,
    active_backup_id uuid REFERENCES finding_assistant.business_backups(backup_id),
    state text NOT NULL CHECK (state IN ('SYNCING', 'SUCCEEDED', 'FAILED')),
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    last_finished_at timestamptz,
    last_checked_at timestamptz,
    source_read_started_at timestamptz,
    last_changed_at timestamptz,
    failure_code text,
    failure_count integer NOT NULL DEFAULT 0 CHECK (failure_count >= 0)
);
