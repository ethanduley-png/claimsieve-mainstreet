# Architecture — v0.33.0 Independent Outcome Boundary

## Authority and evidence path

```text
MainStreet / OpenClaw / model                  untrusted proposal side
                  |
                  v
Restricted canonical proposal + evidence snapshot
                  |
                  v
ClaimSieve policy kernel
                  |
                  v
Independent permit authority
                  |
       atomic campaign successor + permit commit
                  v
Durable local state boundary
 campaign | permit | reservation | revocation | fence | outcome
                  |
          signed executor command
                  v
Restricted executor                           attempt authority only
                  |
      exact request + provider idempotency key
                  v
External provider
                  |
   independent read-back / event evidence
                  v
Independent observer                          terminal outcome authority
                  |
      signed observer receipt + containment
                  v
Durable outcome + execution ledger
```

## Trust boundaries

### Proposal boundary

MainStreet and OpenClaw can formulate a candidate action. They do not own provider credentials, permit keys, executor keys, observer keys, or direct transports in this release.

### Permit boundary

The permit authority reconstructs the decision from the exact proposal, policy, evidence, campaign state, and sequence. A caller-supplied `ALLOW` is not authority.

### Execution boundary

The executor can consume one exact reservation and attempt one exact provider request. Its receipt establishes what the executor key signed, not what occurred externally.

### Observation boundary

The observer uses independently readable provider evidence. It does not need the executor verification key to assign terminal outcome. Missing or contradictory evidence remains unknown.

### Durable-state boundary

The executed reference uses a single SQLite database for local atomicity and crash recovery. It does not claim multi-machine consensus.

## Local linearization points

1. Campaign successor and permit persistence commit in one SQLite write transaction.
2. Reservation is a unique insert keyed by permit identifier.
3. `DISPATCH_COMMIT_POINT` is the final local revocation, freeze, ownership, and expiry check before a request may leave.
4. Terminal outcome is committed only from an authenticated observer receipt based on independent provider evidence.

## Unknown-outcome paths

### New logical action

Never automatic. It requires new proposal identity, current evidence, decision reconstruction, campaign successor, and permit.

### Same-dispatch transport replay

Potentially allowed only under a provider-specific idempotency contract and exact replay guard. It must preserve reservation, key, request, endpoint, account, active authority, retention, and bounded replay count. It does not create a new logical action.

## Failure domains

* Executor compromise cannot alone declare terminal outcome after the v0.33 TCB reduction.
* Observer compromise remains dangerous within observer authority.
* Provider compromise or false provider state can mislead reconciliation.
* Database compromise can rewrite local state and journal together.
* Same-host executor and observer do not provide independent infrastructure failure domains.
* Provider-contract drift can invalidate replay assumptions.
