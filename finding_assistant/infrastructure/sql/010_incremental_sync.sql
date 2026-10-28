-- 技术更新时间独立于飞书业务字段；旧版本保持NULL，首次启用增量时重建基线。
ALTER TABLE finding_assistant.business_backup_records
    ADD COLUMN source_modified_time bigint CHECK(source_modified_time >= 0);
ALTER TABLE finding_assistant.business_sync_sources
    ADD COLUMN last_full_read_started_at timestamptz;
