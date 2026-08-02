# Recovery Guide — v0.33.0

## Trigger conditions

* campaign fork or reservation inconsistency;
* role-key compromise;
* provider evidence contradiction;
* executor/observer disagreement;
* unknown external outcome;
* stale fence or revocation;
* ledger or manifest failure;
* provider-contract change;
* direct side-effect attempt from an untrusted runtime.

## Immediate actions

1. Freeze affected campaign and executor scope.
2. Revoke unused permits.
3. Preserve all proposal, evidence, decision, reservation, dispatch, executor, provider, observer, ledger, and build artifacts.
4. Mark in-flight actions unknown unless independent evidence supports a terminal result.
5. Disable automatic compensation and new logical attempts.
6. Rotate compromised identities and update trust roots out of band.

## Reconciliation

* Match provider records to exact reservation, account, endpoint, request digest, and idempotency key.
* Treat executor receipts as audit evidence, not outcome authority.
* Record contradictions without coercing a terminal answer.
* Use contract-bounded transport replay only for the same dispatch.

## Reopening

Reopening requires a separate recovery authorization, current policy and evidence, updated keys where necessary, and limited scope. Old permits are not reactivated.

## Compensation

Compensation is a new consequential action and requires a full new authorization lifecycle.
