-- 后端身份与运维数据；不复制飞书库存，不维护第二套角色成员关系。
CREATE TABLE IF NOT EXISTS finding_assistant.app_users (
    app_id text NOT NULL, tenant_key text NOT NULL, open_id text NOT NULL,
    first_login_at timestamptz NOT NULL DEFAULT now(), last_login_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (app_id, tenant_key, open_id)
);
CREATE TABLE IF NOT EXISTS finding_assistant.oauth_challenges (
    app_id text NOT NULL, state_hash char(64) NOT NULL, binding_hash char(64) NOT NULL,
    verifier_cipher bytea NOT NULL, expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(app_id,state_hash)
);
CREATE INDEX IF NOT EXISTS oauth_challenges_expiry ON finding_assistant.oauth_challenges(expires_at);
CREATE TABLE IF NOT EXISTS finding_assistant.user_sessions (
    app_id text NOT NULL, session_hash char(64) NOT NULL,
    tenant_key text NOT NULL, open_id text NOT NULL, access_token_cipher bytea NOT NULL,
    expires_at timestamptz NOT NULL, revoked_at timestamptz, created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(app_id,session_hash),
    FOREIGN KEY(app_id,tenant_key,open_id) REFERENCES finding_assistant.app_users(app_id,tenant_key,open_id)
);
CREATE INDEX IF NOT EXISTS user_sessions_expiry ON finding_assistant.user_sessions(expires_at);
CREATE INDEX IF NOT EXISTS user_sessions_actor ON finding_assistant.user_sessions(app_id,tenant_key,open_id);
CREATE TABLE IF NOT EXISTS finding_assistant.write_requests (
    app_id text NOT NULL, base_token text NOT NULL, table_id text NOT NULL, request_key uuid NOT NULL,
    tenant_key text NOT NULL, open_id text NOT NULL, action text NOT NULL CHECK(action IN ('IN','OUT','MOVE')),
    fingerprint char(64) NOT NULL, payload jsonb NOT NULL,
    state text NOT NULL CHECK(state IN ('PENDING','RUNNING','SUCCEEDED','FAILED','UNKNOWN')),
    response jsonb, record_id text, failure_code text,
    created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY(app_id,base_token,table_id,request_key)
);
CREATE INDEX IF NOT EXISTS write_requests_state_time ON finding_assistant.write_requests(state,updated_at);
CREATE INDEX IF NOT EXISTS write_requests_actor_time ON finding_assistant.write_requests(app_id,tenant_key,open_id,created_at);
CREATE TABLE IF NOT EXISTS finding_assistant.audit_events (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    app_id text NOT NULL, tenant_key text, open_id text, event_type text NOT NULL,
    outcome text NOT NULL, action text, permission text, request_key uuid,
    recorded_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS audit_events_time ON finding_assistant.audit_events(recorded_at);
CREATE INDEX IF NOT EXISTS audit_events_actor_time ON finding_assistant.audit_events(app_id,tenant_key,open_id,recorded_at);
