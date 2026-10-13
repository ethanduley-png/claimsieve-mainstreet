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

## Experimental bounded operational state

The vNext proposal-side experiment adds a compact working-state layer **upstream** of the existing ClaimSieve intake:

```text
procedure + bounded operational state + latest observation
                         |
                         v
               untrusted model / worker
                    |             |
                    |             +--> proposed consequential action --> existing ClaimSieve path
                    v
             digest-bound state patch
                    |
                    v
        deterministic bounded-state gate
```

This working state is not part of the permit, evidence, execution, observation, or durable campaign authority. It cannot occupy reserved authority roots, and a successful state transition grants no permission to execute. The detailed design, limitations, and paper citation are in `docs/BOUNDED_OPERATIONAL_STATE.md`.

## Trust boundaries

### Proposal boundary

MainStreet and OpenClaw can formulate a candidate action. They do not own provider credentials, permit keys, executor keys, observer keys, or direct transports in this release.

Bounded operational state, when used, remains inside this untrusted proposal boundary. Its revision and digest protect working-state consistency; they do not establish truth or authority.

### Permit boundary

The permit authority reconstructs the decision from the exact proposal, policy, evidence, campaign state, and sequence. A caller-supplied `ALLOW` is not authority.

### Execution boundary

The executor can consume one exact reservation and attempt one exact provider request. Its receipt establishes what the executor key signed, not what occurred externally.

### Observation boundary

The observer uses independently readable provider evidence. It does not need the executor verification key to assign terminal outcome. Missing or contradictory evidence remains unknown.

### Durable-state boundary

The executed reference uses a single SQLite database for local atomicity and crash recovery. It does not claim multi-machine consensus.

The durable state boundary is intentionally separate from bounded operational state. Durable campaign state remains authoritative; proposal-side working state is disposable and reconstructable from retained evidence where possible.

## Local linearization points

1. Campaign successor and permit persistence commit in one SQLite write transaction.
2. Reservation is a unique insert keyed by permit identifier.
3. `DISPATCH_COMMIT_POINT` is the final local revocation, freeze, ownership, and expiry check before a request may leave.
4. Terminal outcome is committed only from an authenticated observer receipt based on independent provider evidence.

The experimental operational-state compare-and-swap is a proposal-side consistency point only and is not added to this list of execution-authority linearization points.

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
* Bounded working state can omit or misrepresent relevant facts; therefore evidence capture and authority reconstruction must remain independent of the worker's state projection.
