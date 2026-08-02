# ADR-004: Durable single-database state boundary

**Status:** Accepted for v0.32 reference

## Context

v0.31 serialized campaign and reservation state only within one Python process. A crash or second process could lose or fork the operational history around a side effect.

## Decision

Use SQLite as an executable single-database reference for campaign succession, atomic permit registration, one-use reservation, containment epoch, fencing tokens, dispatch state, unknown outcome, and reconciliation.

Use `BEGIN IMMEDIATE`, WAL, full synchronous mode, unique constraints, canonical digests, and a hash-chained journal. Add multi-process races and deterministic crash injection.

Add a separate deterministic quorum safety model for partition reasoning, while explicitly declining to claim a production consensus implementation.

## Consequences

### Positive

* State survives process restart.
* Competing local processes serialize through one authoritative database.
* A permit cannot be returned before its campaign successor and permit record are committed.
* Reservation loss and replay become testable.
* Revocation ordering is explicit.
* Unknown outcomes survive restart.

### Negative

* One database is a single availability and failure domain.
* Filesystem and SQLite durability remain trusted assumptions.
* No real network partition or multi-node failover is exercised.
* Remote side effects cannot be atomic with the local dispatch transaction.

## Next decision

Select and implement one production replicated backend only after its conformance suite proves the same transition semantics. Candidate mechanisms include an etcd transaction API or a PostgreSQL serializable design with explicit fencing and failover tests. No candidate is accepted by this ADR.
