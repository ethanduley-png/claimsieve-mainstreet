# Operations Guide

This guide describes a future controlled integration. The current release uses fixtures and simulations and must not be used for live consequential execution.

## Before start

* Verify ZIP checksum and internal manifest.
* Pin trust roots out of band.
* Separate permit, executor, observer, containment, and witness identities.
* Confirm deny-by-default network policy and exact provider routes.
* Confirm durable campaign, reservation, revocation, and ledger health.
* Confirm observer credentials are read-only and independent of executor credentials.
* Confirm provider-contract version, account, endpoint, idempotency semantics, and retention assumptions.
* Keep all live connectors disabled until explicitly authorized.

## Monitoring

Monitor campaign conflicts, reservation conflicts, stale fencing, revocation propagation, unknown outcomes, provider evidence contradictions, executor/observer disagreement, role-key collision, ledger gaps, direct side-effect attempts, and provider-contract changes.

## Unknown outcomes

1. Freeze automatic workflow progression.
2. Preserve reservation, request digest, key, endpoint, account, and receipts.
3. Query independent provider state.
4. Wait for verified asynchronous evidence where applicable.
5. Permit same-dispatch transport replay only when the exact contract guard passes.
6. Never create a new logical action automatically.
7. Escalate unresolved uncertainty in plain language.

## Release verification

Run `VERIFY_MANIFEST=1 ./scripts/test_all.sh` from a fresh extraction. Refuse deployment if required native or provider gates are absent for the intended risk level.
