-- 仅新增后端辅助表，不新建库存副本，不触碰飞书表结构。
CREATE SCHEMA IF NOT EXISTS finding_assistant;

CREATE TABLE IF NOT EXISTS finding_assistant.scan_jobs (
    source_key text PRIMARY KEY,
    source_record_id text NOT NULL,
    fingerprint char(64) NOT NULL,
    action text NOT NULL,
    state text NOT NULL CHECK (state IN ('QUEUED', 'BLOCKED', 'RECONCILE')),
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS finding_assistant.scan_items (
    source_key text NOT NULL REFERENCES finding_assistant.scan_jobs(source_key),
    position smallint NOT NULL CHECK (position BETWEEN 1 AND 36),
    box_code text NOT NULL CHECK (length(box_code) > 0),
    PRIMARY KEY (source_key, position),
    UNIQUE (source_key, box_code)
);

CREATE TABLE IF NOT EXISTS finding_assistant.scan_job_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    source_key text NOT NULL REFERENCES finding_assistant.scan_jobs(source_key),
    event_code text NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS scan_jobs_state_created
    ON finding_assistant.scan_jobs (state, created_at);
