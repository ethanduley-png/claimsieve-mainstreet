# v0.32 Roadmap

## Release gate 1: native parity

1. Install the pinned Rust toolchain.
2. Compile the complete workspace.
3. Repair all formatting and Clippy failures without weakening checks.
4. Add Rust conformance vectors for campaign CAS, reservation, fencing, dispatch, and terminal outcomes.
5. Compile Rocq and archive every `Print Assumptions` result.
6. Add Python, Rust, and Rocq-derived differential fixtures.

## Release gate 2: production state backend

Select one backend through evidence, not preference.

Candidate evaluation must include:

* linearizable compare-and-swap;
* durable monotonic revision or fencing token;
* transactional campaign successor plus permit record;
* atomic reservation;
* revocation and freeze propagation;
* crash and restart behavior;
* backup and restore;
* three- and five-node partition tests;
* stale leader rejection;
* rolling upgrade and schema migration;
* audit export and independent verification.

The reference names etcd and PostgreSQL only as research candidates. Neither is selected in v0.32.

## Release gate 3: credential broker and connector isolation

* only the broker owns provider credentials;
* exact provider, account, endpoint, and request digest are bound;
* dispatch ticket is consumed once;
* egress is limited to the exact provider destination;
* redirects and DNS changes are observed;
* stale fencing token is rejected downstream;
* unknown outcome halts new authorization for the affected resource.

## Release gate 4: independent observation

Move observation to a distinct identity, process, host, and where possible provider account or read-only API. Test executor compromise and observer compromise separately.

## Release gate 5: MainStreet tax-notice pilot

Build a no-send customer flow using synthetic and redacted documents:

* notice intake;
* deadline and amount extraction;
* evidence review;
* plain-language uncertainty;
* exact approval screen;
* submission packet generation;
* simulator-only execution;
* acknowledgment versus resolution tracking;
* human takeover.

Live filing remains disabled until the state backend, identity plane, connector isolation, and provider reconciliation contract pass their gates.
