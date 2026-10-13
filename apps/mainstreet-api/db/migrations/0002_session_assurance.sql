-- MainStreet server-side session assurance hardening.
-- Authentication providers own password/MFA factors. MainStreet stores only
-- opaque session hashes and normalized assurance metadata needed for policy.

BEGIN;

ALTER TABLE mainstreet_app_sessions
    ADD COLUMN IF NOT EXISTS session_secret_hash text,
    ADD COLUMN IF NOT EXISTS auth_assurance text NOT NULL DEFAULT 'aal1'
        CHECK (auth_assurance IN ('aal1', 'aal2', 'aal3')),
    ADD COLUMN IF NOT EXISTS authenticated_at timestamptz,
    ADD COLUMN IF NOT EXISTS mfa_satisfied boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS last_seen_at timestamptz,
    ADD COLUMN IF NOT EXISTS idle_expires_at timestamptz;

ALTER TABLE mainstreet_app_sessions
    ADD CONSTRAINT mainstreet_session_secret_hash_format
        CHECK (session_secret_hash IS NULL OR session_secret_hash ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT mainstreet_session_assurance_consistent
        CHECK (auth_assurance = 'aal1' OR mfa_satisfied = true),
    ADD CONSTRAINT mainstreet_session_authenticated_at_bounds
        CHECK (authenticated_at IS NULL OR authenticated_at >= issued_at),
    ADD CONSTRAINT mainstreet_session_last_seen_bounds
        CHECK (last_seen_at IS NULL OR last_seen_at >= issued_at),
    ADD CONSTRAINT mainstreet_session_idle_expiry_bounds
        CHECK (idle_expires_at IS NULL OR idle_expires_at > issued_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_mainstreet_session_secret_hash
    ON mainstreet_app_sessions(session_secret_hash)
    WHERE session_secret_hash IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_mainstreet_session_active_lookup
    ON mainstreet_app_sessions(user_id, expires_at, idle_expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS mainstreet_auth_events (
    id uuid PRIMARY KEY,
    tenant_id uuid REFERENCES mainstreet_tenants(id),
    user_id uuid NOT NULL REFERENCES mainstreet_users(id),
    session_id uuid REFERENCES mainstreet_app_sessions(id),
    event_type text NOT NULL,
    auth_provider text NOT NULL,
    auth_assurance text
        CHECK (auth_assurance IS NULL OR auth_assurance IN ('aal1', 'aal2', 'aal3')),
    mfa_satisfied boolean,
    request_id text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    CHECK (char_length(event_type) BETWEEN 2 AND 128),
    CHECK (char_length(auth_provider) BETWEEN 2 AND 128),
    CHECK (char_length(request_id) BETWEEN 2 AND 128)
);

CREATE INDEX IF NOT EXISTS idx_mainstreet_auth_events_user_time
    ON mainstreet_auth_events(user_id, occurred_at DESC);

ALTER TABLE mainstreet_auth_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE mainstreet_auth_events FORCE ROW LEVEL SECURITY;

CREATE POLICY mainstreet_auth_events_tenant_user
ON mainstreet_auth_events
USING (
    (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('mainstreet.tenant_id', true), '')::uuid)
    AND user_id = NULLIF(current_setting('mainstreet.user_id', true), '')::uuid
)
WITH CHECK (
    (tenant_id IS NULL OR tenant_id = NULLIF(current_setting('mainstreet.tenant_id', true), '')::uuid)
    AND user_id = NULLIF(current_setting('mainstreet.user_id', true), '')::uuid
);

COMMIT;
