# MainStreet Customer App Rules

1. Browser code must never collect, persist, log, or expose authentication passwords, provider access tokens, refresh tokens, or service credentials.
2. Production browser authentication uses a same-origin server session with Secure, HttpOnly cookies. Authentication providers sit behind an adapter boundary.
3. A caller-selected business or tenant identifier is never authority. Every selection must resolve to an active server-side membership for the authenticated user.
4. Ordinary customer repositories are tenant-scoped by resolved request context and must not expose caller-selected cross-tenant lookup or global listing methods.
5. PostgreSQL row-level security is defense in depth, not a replacement for explicit tenant predicates and request-context binding.
6. MainStreet customer surfaces remain proposal-only for consequential actions. A web or mobile screen must not bypass the ClaimSieve authorization and execution boundary.
7. Service workers and browser caches must never cache authenticated API responses or authentication routes.
8. Support/admin cross-tenant capabilities require a distinct audited boundary and must not be added to ordinary customer routes.
9. Every tenancy, authentication, permission, and execution-authority claim requires a discriminating executable test.
10. Do not call the customer application production-ready until the exact release head has executed its repository CI, production authentication, PostgreSQL migration, backup/restore, and cross-tenant adversarial tests.
