# MainStreet Authentication + Database v1

## Purpose

This increment continues the customer-facing MainStreet app with the deliberately boring production foundation: server-side sessions, authentication assurance metadata, step-up authentication rules, and PostgreSQL session persistence.

It is stacked on `feat/mainstreet-app-v0`. It does not modify the ClaimSieve permit authority, executor, observer, or proposal-only MainStreet boundary.

## Security model

MainStreet does not implement password verification or MFA factor cryptography itself. A production OpenID Connect identity provider remains responsible for primary authentication, passkeys/authenticator-app enrollment, factor recovery, and the signed authentication assertion.

MainStreet consumes a normalized provider assertion and records only the minimum state needed to enforce its own session and authorization policy.

### Browser session

The browser receives one opaque random session secret in a host-only Secure, HttpOnly, SameSite cookie. Only a SHA-256 digest of that opaque session secret is intended to be stored server-side.

The browser must never receive provider access tokens, refresh tokens, service credentials, or executor credentials.

### Authentication assurance

Normalized assurance levels are `aal1`, `aal2`, and `aal3`. MainStreet never infers stronger assurance merely from a method label. `aal2` or stronger requires an explicit MFA-satisfied assertion from the authentication provider.

Sensitive operations can require a fresh step-up assertion. The initial library defaults to a ten-minute freshness window and requires at least `aal2` for step-up protected actions.

This is separate from ClaimSieve authorization. A recently MFA-authenticated owner still does not obtain authority to bypass proposal, policy, permit, execution, or observation controls.

## Database changes

`0002_session_assurance.sql` adds:

- hashed opaque session secret storage
- authentication assurance level
- authentication timestamp
- explicit MFA-satisfied state
- last-seen and idle-expiry state
- active-session indexes
- append-oriented authentication security events

No password hashes, TOTP seeds, passkey private keys, recovery codes, provider refresh tokens, or service credentials are stored by this migration.

## Executable tests

`session-security.test.js` discriminates:

- random opaque session generation
- hash-only session verification
- constant-time digest comparison
- Secure/HttpOnly/__Host cookie requirements
- rejection of non-host cookie names
- bounded cookie lifetime
- explicit MFA requirement for `aal2+`
- weak-assurance rejection for step-up
- stale step-up rejection

## Still not production ready

This increment does not yet establish:

- a selected production OpenID Connect provider
- callback signature/token verification
- a live PostgreSQL connection pool
- executed migrations against staging/production PostgreSQL
- session rotation on privilege changes
- CSRF enforcement on state-changing web routes
- recovery and account-lockout flows
- organization-level MFA policy configuration
- backup/restore validation
- deployed cross-tenant penetration testing

Those are the next boring production slices.
