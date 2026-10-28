-- 仅后端记录前置拒绝及异常回写意图，不在飞书新增表或字段。
CREATE TABLE finding_assistant.inventory_rejections (
    source_key text PRIMARY KEY,
    rejection_id uuid NOT NULL UNIQUE,
    app_id text NOT NULL, base_token text NOT NULL, scan_table_id text NOT NULL, source_record_id text NOT NULL,
    tenant_key text NOT NULL, open_id text NOT NULL,
    action text NOT NULL CHECK(action IN ('IN','OUT','MOVE')),
    fingerprint char(64) NOT NULL, reason_code text NOT NULL, box_code text,
    before_note text NOT NULL, note text NOT NULL,
    state text NOT NULL CHECK(state IN ('PENDING','RUNNING','CONFIRMED','UNKNOWN','REJECTED')),
    remote_record_id text, position_released boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CHECK(remote_record_id IS NULL OR remote_record_id=source_record_id)
);
CREATE INDEX inventory_rejections_scope_state ON finding_assistant.inventory_rejections(app_id,base_token,state,updated_at);
