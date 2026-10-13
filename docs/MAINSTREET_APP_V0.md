# MainStreet App v0

## Status

This branch starts the customer-facing MainStreet product shell without weakening the existing ClaimSieve/MainStreet execution boundary.

It is intentionally stacked on the governed note/OCR work so the eventual phone capture flow can reuse that evidence path.

## Current request path

```text
browser / installed PWA
        |
        | same-origin secure session
        v
authentication adapter
        |
        v
validated user identity
        |
        +--> GET /v1/businesses
        |       server-side memberships for this user only
        |
        v
selected business
        |
        | selection is NOT authority
        v
active membership resolution
        |
        v
tenant request context
        |
        v
MainStreet customer application service
        |
        +--> read-only business / dashboard surfaces
        |
        +--> proposal-only assistant request
                    |
                    v
            existing MainStreet / ClaimSieve boundary
```

## Implemented in this increment

### Identity and tenancy

- provider-neutral authentication assertion contract
- expiry and future-issuance checks
- active membership requirement
- owner, admin, staff, and viewer roles
- explicit permission checks
- context-bound tenant identity
- ordinary repository APIs do not expose caller-selected cross-tenant lookup
- cross-tenant access tests

### PostgreSQL foundation

`apps/mainstreet-api/db/migrations/0001_identity_tenancy.sql` defines:

- tenants
- users
- memberships
- application sessions
- audit events
- foreign-key membership/session binding
- forced PostgreSQL row-level security for customer-scoped tables
- tenant/user transaction-context policies as defense in depth

Application queries must still bind tenant identity explicitly. Row-level security is not treated as a substitute for correct application scoping.

### Customer API core

Current contract routes:

- `GET /healthz`
- `GET /v1/businesses`
- `GET /v1/session`
- `GET /v1/today`
- `POST /v1/assistant/requests`

`/v1/businesses` is the only pre-tenant customer route. It validates that every membership returned by the adapter belongs to the authenticated identity and rejects duplicate tenant records.

All tenant routes require a selected business plus an active membership resolved server-side. The browser-provided tenant identifier is only a selector.

Assistant requests are explicitly returned with `executionAuthority: false` and the next boundary `mainstreet-proposal-only`.

### Responsive / phone shell

`apps/mainstreet-web` provides the first responsive installable web shell with:

- sign-in handoff
- business picker
- Today
- Ask MainStreet
- Inbox placeholder
- Tasks placeholder
- Notes placeholder
- Approvals placeholder
- Activity placeholder
- mobile safe-area layout
- PWA manifest and service worker

The browser does not collect passwords and does not handle bearer or refresh tokens. Production authentication is expected to use a same-origin server session backed by Secure, HttpOnly cookies.

The PWA service worker caches only static shell assets. Authentication routes and `/v1/` API requests are deliberately excluded from service-worker caching.

## Tests added

The API suite discriminates:

- expired/future authentication assertions
- inactive memberships
- identity/membership mismatch
- role permission failures
- cross-tenant resource access
- cross-tenant dashboard leakage
- attempted tenant-id mutation
- caller-selected unauthorized businesses
- pre-tenant membership leakage from another user
- duplicate membership adapter output
- proposal-only assistant behavior
- PostgreSQL row-level-security contract presence

The web suite discriminates:

- no password collection in the shell
- no browser bearer-token handling
- no local-storage token pattern
- membership discovery before tenant selection
- proposal-only assistant response handling
- no API/auth caching in the service worker
- standalone PWA manifest
- phone navigation surface presence

These suites are now included in the normal Reference CI and Full Assurance script.

## Not production-ready yet

This branch does **not** claim the following are implemented:

- production authentication provider and callback/session adapter
- cryptographically protected production browser session implementation
- live PostgreSQL connection pool or executed production migration
- backup/restore testing
- production deployment/runtime adapter
- public marketing website
- business onboarding wizard
- invite/team-management endpoints
- real Inbox/Tasks/Approvals/Activity persistence
- note image upload/object storage endpoint
- push notifications
- native iOS/Android packaging
- billing
- production observability and incident response
- end-to-end penetration/cross-tenant testing against a deployed environment

## Next build slice

1. choose and integrate a production OpenID Connect authentication provider behind `/auth/login`, `/auth/callback`, and `/auth/logout`
2. implement the server-side Secure/HttpOnly session adapter
3. connect the repository contract to PostgreSQL and execute the migration in an isolated environment
4. add tenant/business onboarding and owner invitation flow
5. connect Notes to immutable object storage plus the existing governed OCR/note-memory boundary
6. deploy a private beta environment and run end-to-end cross-tenant/adversarial tests
