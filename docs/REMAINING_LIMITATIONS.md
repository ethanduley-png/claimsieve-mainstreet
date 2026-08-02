# Remaining Limitations — v0.34.0

## 1. Rust observer receipt divergence

Rust emits an observer receipt v1 shape while Python and the schema use v2. Portable verifier and canonicalization parity are not established.

## 2. Live provider evidence is one narrow canary

The Stripe model remains contract-derived. The restricted GitHub adapter has one explicitly authorized live issue-create and delayed read-back result, but no live network fault injection, webhook exercise, or representative production workload. The temporary canary credentials were revoked.

## 3. Provider contract adherence is an assumption

A provider defect, incident, undocumented behavior, account-specific behavior, or contract change can invalidate the model.

## 4. Provider evidence can still be wrong

An independently queried record may be stale, incomplete, misbound to an account, or semantically misleading. Independent does not mean infallible.

## 5. Observer independence is logical, not infrastructural

The simulation uses distinct keys and a read-only interface but still runs on the same host and administrative environment.

## 6. SQLite is not distributed consensus

The local durable boundary does not establish behavior under multi-node partitions, stale leaders, cross-region failover, or administrator compromise.

## 7. Remote side effects cannot share one atomic transaction with local state

Dispatch and remote effect remain separated by a failure boundary. Reconciliation is required after the commit point.

## 8. Human approval remains fallible

The system can bind an approval but cannot prove comprehension, voluntariness, competence, or legal sufficiency.

## 9. Signatures do not prove truth

Signed policy, evidence, executor, provider, observer, or witness records can still contain false semantic claims.

## 10. Supply-chain provenance is incomplete

A resolved Rust lockfile is now included, but signed build provenance, a transparency-log entry, and an independently reproduced binary are not.

## 11. MainStreet product maturity remains limited

The proposal boundary exists, but the complete owner-facing tax-notice workspace, privacy controls, professional escalation, and real customer usability evidence remain unfinished.

## 12. GitHub lacks native ClaimSieve idempotency

The issue adapter uses one-shot dispatch plus a hidden correlation marker and bounded read-back. A delayed or removed marker can leave the outcome unknown, and unknown never authorizes an automatic retry.
