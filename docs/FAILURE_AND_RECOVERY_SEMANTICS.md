# Failure and Recovery Semantics — v0.33.0

## Before dispatch commit

A committed freeze, revocation, expiry, ownership loss, or binding mismatch blocks dispatch. The reservation may be marked rejected or returned for controlled recovery.

## After dispatch commit

The remote effect cannot be rolled back by changing local state. A timeout, disconnect, crash, or ambiguous response enters `OUTCOME_UNKNOWN` unless independent evidence already establishes a terminal result.

## Recovery choices

1. Independently query provider state.
2. Wait for a verified asynchronous event.
3. Escalate to a human with uncertainty visible.
4. Perform a contract-bounded same-dispatch transport replay.
5. Create a new logical action only through the full authorization lifecycle.

## Prohibited recovery behavior

* Treating timeout as failure.
* Treating a signed executor rejection as failure.
* Replaying with changed parameters or endpoint.
* Reusing an idempotency key outside the guaranteed window.
* Creating a new key without new logical authority.
* Automatically compensating.
* Rewriting a terminal outcome.

## Compensation

Compensation is a new consequential action. It requires current evidence, exact scope, policy evaluation, approval where required, campaign advancement, and a new permit.
