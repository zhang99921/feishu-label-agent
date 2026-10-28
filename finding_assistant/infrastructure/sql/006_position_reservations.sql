-- 新模型单独建表，保留003中的整行预占及旧请求结果，不为历史箱虚构位置码。
CREATE TABLE finding_assistant.position_reservations (
    reservation_id uuid PRIMARY KEY, batch_id uuid NOT NULL,
    app_id text NOT NULL, base_token text NOT NULL, table_id text NOT NULL, request_key uuid NOT NULL,
    box_table_id text NOT NULL, row_table_id text NOT NULL, tenant_key text NOT NULL, open_id text NOT NULL,
    action text NOT NULL CHECK(action IN ('IN','MOVE')), input_fingerprint char(64) NOT NULL,
    target_row_record_id text NOT NULL, target_row_code text NOT NULL,
    position_no numeric NOT NULL CHECK(position_no>=1 AND position_no=trunc(position_no)),
    position_code text NOT NULL, target_warehouse text NOT NULL,
    sources jsonb NOT NULL, payload jsonb NOT NULL,
    source_reservation_id uuid,
    state text NOT NULL CHECK(state IN ('RESERVED','RECORDED','UNKNOWN','OCCUPIED','COOLING','RELEASED')),
    flow_record_id text, cooldown_until timestamptz, posting_evidence text, departure_evidence text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE(app_id,base_token,table_id,request_key),
    UNIQUE(reservation_id,base_token,row_table_id,box_table_id),
    UNIQUE(reservation_id,base_token,box_table_id),
    FOREIGN KEY(source_reservation_id,base_token,row_table_id,box_table_id)
        REFERENCES finding_assistant.position_reservations(reservation_id,base_token,row_table_id,box_table_id),
    CHECK(position_code='-' || lpad(position_no::text,GREATEST(2,length(position_no::text)),'0')),
    CHECK(state<>'COOLING' OR cooldown_until IS NOT NULL),
    CHECK(action<>'MOVE' OR source_reservation_id IS NOT NULL)
);
CREATE UNIQUE INDEX position_reservations_active_id
    ON finding_assistant.position_reservations(base_token,row_table_id,target_row_record_id,position_no)
    WHERE state<>'RELEASED';
CREATE UNIQUE INDEX position_reservations_active_code
    ON finding_assistant.position_reservations(base_token,row_table_id,target_row_code,position_no)
    WHERE state<>'RELEASED';
CREATE INDEX position_reservations_batch ON finding_assistant.position_reservations(base_token,batch_id,created_at);

CREATE TABLE finding_assistant.position_box_claims (
    reservation_id uuid NOT NULL,
    base_token text NOT NULL, box_table_id text NOT NULL, box_record_id text NOT NULL, box_code text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    PRIMARY KEY(reservation_id,box_record_id),
    FOREIGN KEY(reservation_id,base_token,box_table_id)
        REFERENCES finding_assistant.position_reservations(reservation_id,base_token,box_table_id)
);
CREATE UNIQUE INDEX position_box_claims_active ON finding_assistant.position_box_claims(base_token,box_table_id,box_record_id)
    WHERE active;
