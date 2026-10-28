-- 飞书业务记录的版本化备份和SQL检索副本；不切换业务主存，不更新飞书。
CREATE TABLE finding_assistant.business_backups (
    backup_id uuid PRIMARY KEY, base_token text NOT NULL,
    state text NOT NULL CHECK(state IN ('RUNNING','SUCCEEDED','FAILED')),
    metadata jsonb NOT NULL DEFAULT '{}', failure_code text,
    started_at timestamptz NOT NULL DEFAULT clock_timestamp(), finished_at timestamptz,
    table_count integer NOT NULL DEFAULT 0, record_count integer NOT NULL DEFAULT 0,
    content_sha256 char(64)
);
CREATE INDEX business_backups_latest ON finding_assistant.business_backups(base_token,started_at DESC)
    WHERE state='SUCCEEDED';
CREATE TABLE finding_assistant.business_backup_tables (
    backup_id uuid NOT NULL REFERENCES finding_assistant.business_backups(backup_id),
    table_id text NOT NULL, table_name text NOT NULL, field_schema jsonb NOT NULL,
    PRIMARY KEY(backup_id,table_id)
);
CREATE TABLE finding_assistant.business_backup_records (
    backup_id uuid NOT NULL, table_id text NOT NULL, record_id text NOT NULL, fields jsonb NOT NULL,
    PRIMARY KEY(backup_id,table_id,record_id),
    FOREIGN KEY(backup_id,table_id) REFERENCES finding_assistant.business_backup_tables(backup_id,table_id)
);
CREATE INDEX business_backup_records_json ON finding_assistant.business_backup_records USING gin(fields);
CREATE TABLE finding_assistant.business_box_index (
    backup_id uuid NOT NULL, table_id text NOT NULL, record_id text NOT NULL,
    box_code text, fnsku text, sku text, po_number text, state text,
    row_code text, position_code text, warehouse text, quantity numeric,
    PRIMARY KEY(backup_id,table_id,record_id),
    FOREIGN KEY(backup_id,table_id,record_id)
        REFERENCES finding_assistant.business_backup_records(backup_id,table_id,record_id)
);
CREATE INDEX business_box_code ON finding_assistant.business_box_index(backup_id,box_code);
CREATE INDEX business_box_fnsku ON finding_assistant.business_box_index(backup_id,fnsku);
CREATE INDEX business_box_sku ON finding_assistant.business_box_index(backup_id,sku);
CREATE INDEX business_box_po ON finding_assistant.business_box_index(backup_id,po_number);
CREATE INDEX business_box_location ON finding_assistant.business_box_index(backup_id,row_code,position_code);
