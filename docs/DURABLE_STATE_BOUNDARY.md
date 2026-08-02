# Durable State Boundary

## Decision

The v0.33 reference retains the v0.32 single-database mechanism and uses a single SQLite database as the authoritative state machine for campaign succession and execution reservation.

This is deliberately narrower than a distributed consensus service. It gives a reproducible enforcement boundary that survives process restart and coordinates competing local processes. It does not claim availability or linearizability across independent machines during a network partition.

## Authoritative records

The database owns:

* canonical campaign state and digest;
* campaign sequence and revision;
* committed permit digest;
* revocation and freeze epoch;
* one-use reservation;
* request digest and idempotency key;
* resource-scoped fencing token;
* dispatch state;
* provider response record;
* durable unknown outcome;
* independent reconciliation result;
* a hash-chained operational journal.

The database does not replace the four ClaimSieve ledgers. The ledgers remain the attributable proposal, evidence, decision, and execution records. The state journal records operational state transitions needed for recovery and concurrency analysis.

## Transaction boundaries

### Campaign and permit

The authority constructs and signs a permit, then commits the exact predecessor-to-successor campaign transition and the permit record in one write transaction. The permit is returned only after commit.

A stale predecessor, equal sequence, duplicate permit identifier, or state digest mismatch fails closed.

### Reservation

Reservation is a unique insert keyed by permit identifier. The transaction also checks:

* current campaign state;
* revocation;
* global freeze;
* permit digest;
* action digest;
* campaign-state binding.

The reservation allocates a monotonic fencing token and binds an idempotency key to the exact request digest.

### Dispatch commit point

The transition from `EXECUTING` to `DISPATCHING` is the local authorization linearization point.

Revocation or freeze committed before this transaction prevents dispatch. Revocation committed after this point cannot be described as retroactive prevention because the request may already be in flight. The correct state is investigation and reconciliation.

## Fencing

The provider simulator stores the highest accepted fencing token for each resource key. A request carrying a token less than or equal to the recorded token is rejected unless it is an exact idempotent replay of an already recorded request.

Fencing is not a substitute for consensus. A stale executor that reaches a provider before the newer executor may still act. The state service must prevent stale dispatch authorization, and the provider must reject old work after a newer fence is observed.

## Durability profile

The reference configures:

```text
journal_mode = WAL
synchronous = FULL
foreign_keys = ON
busy_timeout = 30000 ms
write transaction = BEGIN IMMEDIATE
```

The implementation assumes the operating system and storage stack honor SQLite durability requests. Power-loss, filesystem corruption, disk-controller behavior, and replicated storage semantics were not tested.

## Recovery rule

Recovery never infers success from an executor log alone.

* `RESERVED`: no dispatch commit point was crossed; the same reservation may be resumed after current containment checks.
* `EXECUTING`: executor claimed work but did not cross dispatch; resume requires current containment checks.
* `DISPATCHING`: the request may have left the process; query independent provider state. A same-key transport replay is allowed only if the contract-bounded replay guard passes.
* `OUTCOME_UNKNOWN`: preserve and investigate. Do not automatically create a new logical action. A same-dispatch transport replay is a separate, strictly guarded operation.
* terminal reconciliation: immutable unless a separately governed correction protocol is created.
