-- 实际库存执行的持久步骤及逐箱事务；旧接收任务状态保持兼容。
CREATE TABLE finding_assistant.inventory_executions (
    source_key text PRIMARY KEY REFERENCES finding_assistant.scan_jobs(source_key),
    execution_id uuid NOT NULL UNIQUE,
    app_id text NOT NULL, base_token text NOT NULL, scan_table_id text NOT NULL, source_record_id text NOT NULL,
    tenant_key text NOT NULL, open_id text NOT NULL, action text NOT NULL CHECK(action IN ('IN','OUT','MOVE')),
    fingerprint char(64) NOT NULL, plan jsonb NOT NULL,
    state text NOT NULL CHECK(state IN ('PREPARED','RUNNING','RECONCILE','SUCCEEDED')),
    owner_id uuid, position_confirmed boolean NOT NULL DEFAULT false, failure_code text,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE finding_assistant.inventory_steps (
    source_key text NOT NULL REFERENCES finding_assistant.inventory_executions(source_key),
    ordinal integer NOT NULL CHECK(ordinal>=1), step_id uuid NOT NULL UNIQUE,
    kind text NOT NULL CHECK(kind IN ('BOX','DETAIL','LEDGER','STATUS')),
    box_record_id text, specification jsonb NOT NULL,
    state text NOT NULL CHECK(state IN ('PENDING','RUNNING','UNKNOWN','REJECTED','CONFIRMED')),
    remote_record_id text, failure_code text, confirmed_at timestamptz,
    PRIMARY KEY(source_key,ordinal)
);
CREATE TABLE finding_assistant.inventory_transactions (
    transaction_id uuid PRIMARY KEY, source_key text NOT NULL REFERENCES finding_assistant.inventory_executions(source_key),
    base_token text NOT NULL, box_table_id text NOT NULL, box_record_id text NOT NULL, box_code text NOT NULL,
    action text NOT NULL CHECK(action IN ('IN','OUT','MOVE')), document_reference text NOT NULL,
    transaction_no text NOT NULL UNIQUE, quantity numeric NOT NULL CHECK(quantity>0),
    before_values jsonb NOT NULL, after_values jsonb NOT NULL,
    source_position_id uuid REFERENCES finding_assistant.position_reservations(reservation_id),
    target_position_id uuid REFERENCES finding_assistant.position_reservations(reservation_id),
    state text NOT NULL CHECK(state IN ('PLANNED','POSTED')), active boolean NOT NULL DEFAULT true,
    remote_record_id text, posted_at timestamptz,
    UNIQUE(source_key,box_record_id,action)
);
CREATE UNIQUE INDEX inventory_transactions_active_box
    ON finding_assistant.inventory_transactions(base_token,box_table_id,box_record_id) WHERE active;
CREATE INDEX inventory_executions_state ON finding_assistant.inventory_executions(state,created_at);
