# Founder OS Known Limitations

- A restricted GitHub issue adapter is implemented, locally tested, and exercised by one explicitly authorized live canary. One canary does not establish general provider correctness.
- The temporary fine-grained tokens used for the canary were revoked. No durable GitHub App installation, webhook, or production secret broker is configured.
- The provider simulator has stronger idempotency and fencing behavior than GitHub issue creation provides. The live adapter therefore sends only once and never automatically retries an ambiguous response.
- Correlation-marker read-back is bounded by the configured observation-page limit and can be delayed by provider visibility. Absence remains `OUTCOME_UNKNOWN`.
- Separate read and write tokens are enforced in code, but ordinary process environment variables are not production-grade secret isolation.
- The live observer used a distinct read-only token but ran within the same local operator boundary, so it is not infrastructurally independent.
- The local Founder OS allowlist is a product guard, not a substitute for signed repository-registry evidence.
- Fixture Ed25519 keys are deterministic and unsafe outside tests.
- SQLite provides local durable behavior, not distributed consensus.
- MainStreet has a proposal builder, not a complete visual workspace.
- The original Founder OS v0.1 HMAC authority remains only as a preserved input archive and is not active code.
