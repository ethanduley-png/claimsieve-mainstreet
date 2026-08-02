# Patched Architecture — v0.34.0

## Demonstrated correction

The v0.32 observer accepted a correctly signed executor rejection as terminal failure when no independent provider record existed. v0.33 removes executor receipts from terminal-outcome authority.

## Current executable Python path

* Campaign successor and permit persistence are atomic in the local SQLite reference.
* Reservation is durable and one-use.
* Revocation, suspension, freeze, expiry, ownership, and exact binding are checked before dispatch.
* Executor commands and receipts are separately signed.
* Executor receipts remain audit evidence only.
* Observer receipts are signed by a distinct observer key.
* Provider-only evidence determines outcome.
* No provider record maps to `OUTCOME_UNKNOWN`.
* Rejected-with-effect and accepted-without-effect map to `OUTCOME_UNKNOWN` plus containment.
* Exact observed effect maps to success.
* Different observed effect maps to divergence plus containment.
* Confirmed provider rejection without effect maps to failure.
* No outcome automatically authorizes a new logical attempt.
* Same-dispatch transport replay is separately guarded by provider-contract conditions.
* The optional GitHub adapter restricts egress to `api.github.com`, exact allowlisted repositories, issue creation, and read-only issue reconciliation.
* GitHub writer and observer tokens are distinct, and a failed observation preflight blocks the write.

## Deliberately unresolved

* Rust observer receipt v1 versus Python/schema v2.
* Executed live-provider behavior.
* Webhook and read-back independence.
* Multi-node consensus.
* Independent-host observer.
* Hardware-backed or workload-identity key custody.
* Signed reproducible build provenance.
