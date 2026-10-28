-- 先受理后执行：只保存加密会话凭证；不是新的库存主账。
CREATE TABLE finding_assistant.warehouse_tasks (
 task_id uuid PRIMARY KEY, app_id text NOT NULL, base_token text NOT NULL,
 request_key uuid NOT NULL, tenant_key text NOT NULL, open_id text NOT NULL,
 action text NOT NULL CHECK(action IN ('IN','OUT','MOVE')),
 fingerprint char(64) NOT NULL, payload jsonb NOT NULL, session_cipher bytea,
 state text NOT NULL CHECK(state IN ('QUEUED','RUNNING','AUTH_REQUIRED','REVIEW','SUCCEEDED')),
 record_id text, result jsonb, failure_code text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(app_id,base_token,request_key)
);
CREATE INDEX warehouse_tasks_pending ON finding_assistant.warehouse_tasks(app_id,base_token,state,created_at);
