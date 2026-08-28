-- MainStreet customer identity + tenancy foundation.
-- PostgreSQL 15+ compatible. Application code must SET LOCAL
-- mainstreet.tenant_id and mainstreet.user_id inside each transaction after
-- authentication + membership resolution.

BEGIN;

CREATE TABLE IF NOT EXISTS mainstreet_tenants (
    id uuid PRIMARY KEY,
    slug text NOT NULL UNIQUE,
    display_name text NOT NULL,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'closed')),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (char_length(slug) BETWEEN 2 AND 80),
    CHECK (char_length(display_name) BETWEEN 1 AND 160)
);

CREATE TABLE IF NOT EXISTS mainstreet_users (
    id uuid PRIMARY KEY,
    auth_provider text NOT NULL,
    auth_subject text NOT NULL,
    email text,
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (auth_provider, auth_subject),
    CHECK (char_length(auth_provider) BETWEEN 2 AND 128),
    CHECK (char_length(auth_subject) BETWEEN 2 AND 512)
);

CREATE TABLE IF NOT EXISTS mainstreet_memberships (
    tenant_id uuid NOT NULL REFERENCES mainstreet_tenants(id),
    user_id uuid NOT NULL REFERENCES mainstreet_users(id),
    role text NOT NULL CHECK (role IN ('owner', 'admin', 'staff', 'viewer')),
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS mainstreet_app_sessions (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    user_id uuid NOT NULL,
    auth_provider text NOT NULL,
    auth_session_subject text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, user_id)
        REFERENCES mainstreet_memberships(tenant_id, user_id),
    CHECK (expires_at > issued_at),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);

CREATE TABLE IF NOT EXISTS mainstreet_audit_events (
    id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES mainstreet_tenants(id),
    actor_user_id uuid REFERENCES mainstreet_users(id),
    request_id text NOT NULL,
    event_type text NOT NULL,
    target_type text,
    target_id text,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    CHECK (char_length(request_id) BETWEEN 2 AND 128),
    CHECK (char_length(event_type) BETWEEN 2 AND 128)
);

CREATE INDEX IF NOT EXISTS idx_mainstreet_memberships_user
    ON mainstreet_memberships(user_id, status);
CREATE INDEX IF NOT EXISTS idx_mainstreet_sessions_tenant_user
    ON mainstreet_app_sessions(tenant_id, user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_mainstreet_audit_tenant_time
    ON mainstreet_audit_events(tenant_id, occurred_at DESC);

-- Defense in depth. The application still MUST include tenant_id explicitly in
-- every customer data query. These policies are not a substitute for correct
-- repository scoping.
ALTER TABLE mainstreet_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE mainstreet_tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE mainstreet_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE mainstreet_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE mainstreet_app_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mainstreet_app_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE mainstreet_audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE mainstreet_audit_events FORCE ROW LEVEL SECURITY;

CREATE POLICY mainstreet_tenant_self
ON mainstreet_tenants
USING (
    id = NULLIF(current_setting('mainstreet.tenant_id', true), '')::uuid
)
WITH CHECK (
    id = NULLIF(current_setting('mainstreet.tenant_id', true), '')::uuid
);

CREATE POLICY mainstreet_membership_tenant
ON mainstreet_memberships
USING (
    tenant_id = NULLIF(current_setting('mainstreet.tenant_id', true), '')::uuid
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('mainstreet.tenant_id', true), '')::uuid
);

CREATE POLICY mainstreet_session_tenant_user
ON mainstreet_app_sessions
USING (
    tenant_id = NULLIF(current_setting('mainstreet.tenant_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('mainstreet.user_id', true), '')::uuid
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('mainstreet.tenant_id', true), '')::uuid
    AND user_id = NULLIF(current_setting('mainstreet.user_id', true), '')::uuid
);

CREATE POLICY mainstreet_audit_tenant
ON mainstreet_audit_events
USING (
    tenant_id = NULLIF(current_setting('mainstreet.tenant_id', true), '')::uuid
)
WITH CHECK (
    tenant_id = NULLIF(current_setting('mainstreet.tenant_id', true), '')::uuid
);

COMMIT;
