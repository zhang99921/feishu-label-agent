-- 后端行码预占，不改变飞书字段，不代表库存已经完成转仓。
CREATE TABLE IF NOT EXISTS finding_assistant.location_reservations (
    app_id text NOT NULL, base_token text NOT NULL, table_id text NOT NULL, request_key uuid NOT NULL,
    row_table_id text NOT NULL, tenant_key text NOT NULL, open_id text NOT NULL,
    input_fingerprint char(64) NOT NULL, source_location_code text NOT NULL,
    target_row_record_id text NOT NULL, target_location_code text NOT NULL, target_warehouse text NOT NULL,
    payload jsonb NOT NULL,
    state text NOT NULL CHECK(state IN ('RESERVED','RECORDED','UNKNOWN','COOLING','RELEASED')),
    cooldown_until timestamptz, flow_record_id text,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(app_id,base_token,table_id,request_key),
    CHECK(state <> 'COOLING' OR cooldown_until IS NOT NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS location_reservations_active_row
    ON finding_assistant.location_reservations(base_token,row_table_id,target_row_record_id)
    WHERE state <> 'RELEASED';
CREATE UNIQUE INDEX IF NOT EXISTS location_reservations_active_code
    ON finding_assistant.location_reservations(base_token,row_table_id,target_location_code)
    WHERE state <> 'RELEASED';
