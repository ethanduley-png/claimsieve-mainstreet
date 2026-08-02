# v0.32 Research Findings

## Established facts from primary sources

1. SQLite documents that `BEGIN IMMEDIATE` starts a write transaction immediately and can fail when another write transaction is active. This supports a single-writer reference boundary across local connections and processes. Source: <https://sqlite.org/lang_transaction.html>
2. etcd documents linearizable reads and writes as operations that reflect cluster consensus, and notes that linearizable operations require the Raft consensus path. Source: <https://etcd.io/docs/v3.7/learning/api_guarantees/>
3. The Raft project describes consensus as multiple servers agreeing on final values while a majority remains available. Source: <https://raft.github.io/>
4. Stripe documents idempotency keys, storage of the first result, replay of the original result, and parameter comparison to reject reuse with different request parameters. Source: <https://docs.stripe.com/api/idempotent_requests>
5. etcd documentation describes revision numbers as useful fencing tokens. Source: <https://etcd.io/docs/v3.6/learning/why/>

## Design interpretations

* A local SQLite transaction is suitable as an executable oracle for state-transition semantics and multi-process races, but it is not evidence of multi-node consensus.
* A permit identifier can serve as a provider idempotency key only when it is bound to the exact request digest and the provider preserves the key long enough for reconciliation.
* Fencing tokens reduce stale-worker risk only when the downstream system enforces them.
* The last local revocation check must be named explicitly. After a request is dispatched, revocation changes future authority but does not prove that the current request was prevented.
* Provider response and provider state are separate evidence classes. A timeout may conceal either no effect or a completed effect.

## Assumptions in the executable reference

* SQLite and the local filesystem honor committed transactions and `fsync` semantics.
* All processes use the same database file and do not bypass it.
* The provider simulator is the only path to the simulated external effect.
* Provider query results accurately represent provider state.
* Logical sequences are supplied correctly and are not wall-clock timestamps.
* Fixture keys are test-only and do not establish real workload identity.

## Unverified hypotheses

* A production etcd or PostgreSQL implementation can preserve these exact state transitions without semantic drift.
* A credential broker can make the dispatch commit point sufficiently close to network transmission to make revocation behavior operationally understandable.
* Real providers expose durable idempotency and read-back semantics adequate for independent reconciliation.
* Small-business users will understand the difference between submitted, acknowledged, observed, and resolved without approval fatigue.
