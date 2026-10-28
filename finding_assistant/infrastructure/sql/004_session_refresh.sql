-- 会话绝对期限与飞书令牌期限分开；既有会话不自动延长，需重新授权取得刷新凭据。
ALTER TABLE finding_assistant.user_sessions
    ADD COLUMN IF NOT EXISTS access_token_expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS refresh_token_cipher bytea,
    ADD COLUMN IF NOT EXISTS refresh_token_expires_at timestamptz,
    ADD COLUMN IF NOT EXISTS token_scopes text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS refresh_state text NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN IF NOT EXISTS refresh_attempt_id uuid,
    ADD COLUMN IF NOT EXISTS refresh_started_at timestamptz;
UPDATE finding_assistant.user_sessions SET access_token_expires_at=expires_at
    WHERE access_token_expires_at IS NULL;
ALTER TABLE finding_assistant.user_sessions
    ADD CONSTRAINT user_sessions_refresh_state_check
        CHECK(refresh_state IN ('ACTIVE','REFRESHING','UNKNOWN')),
    ADD CONSTRAINT user_sessions_refresh_claim_check
        CHECK(refresh_state <> 'REFRESHING' OR (refresh_attempt_id IS NOT NULL AND refresh_started_at IS NOT NULL));
