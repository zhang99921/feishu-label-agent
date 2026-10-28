-- 已有历史版本保留；新同步版本记录真实关联ID，权限判断不按显示行码猜关联。
ALTER TABLE finding_assistant.business_box_index
    ADD COLUMN row_table_id text,
    ADD COLUMN row_record_id text,
    ADD CONSTRAINT business_box_row_source_fk
        FOREIGN KEY (backup_id,row_table_id,row_record_id)
        REFERENCES finding_assistant.business_backup_records(backup_id,table_id,record_id);

CREATE TABLE finding_assistant.query_access_snapshots (
    app_id text NOT NULL,
    tenant_key text NOT NULL,
    open_id text NOT NULL,
    base_token text NOT NULL,
    table_id text NOT NULL,
    source_backup_id uuid NOT NULL REFERENCES finding_assistant.business_backups(backup_id),
    policy_hash char(64) NOT NULL,
    policy jsonb NOT NULL,
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY(app_id,tenant_key,open_id,base_token,table_id)
);

-- 字段目标值均由参数传递。仅解释已确认的标量形状，其他类型不成为授权条件。
CREATE FUNCTION finding_assistant.query_scalar_text(value jsonb) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE jsonb_typeof(value)
        WHEN 'string' THEN value #>> '{}'
        WHEN 'number' THEN value #>> '{}'
        WHEN 'array' THEN CASE WHEN jsonb_array_length(value)>0 AND NOT EXISTS (
            SELECT 1 FROM jsonb_array_elements(value) item
            WHERE jsonb_typeof(item)<>'object' OR jsonb_typeof(item->'text') IS DISTINCT FROM 'string'
        ) THEN (SELECT string_agg(item->>'text','' ORDER BY position)
                FROM jsonb_array_elements(value) WITH ORDINALITY AS elements(item,position)) END
    END
$$;

CREATE FUNCTION finding_assistant.query_scalar_number(value jsonb) RETURNS numeric
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE WHEN length(v)<=200 AND
        v ~ '^[+-]?([0-9]+([.][0-9]*)?|[.][0-9]+)([eE][+-]?[0-9]{1,3})?$'
        THEN v::numeric END
    FROM (SELECT finding_assistant.query_scalar_text(value) AS v) source
$$;
