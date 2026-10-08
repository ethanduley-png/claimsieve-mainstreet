# Ledger Ablation Experiment

Status: experimental. This branch does **not** change normative invariant I-040.

## Question

Does ClaimSieve need four independent cryptographic chains to preserve the security properties currently attributed to proposal, evidence, decision, and execution separation, or can a single multi-signer witnessed chain plus content-addressed artifacts preserve the same relevant guarantees with lower hot-path cost and less complexity?

The experiment is intentionally adversarial. A unified log only wins if it preserves the important guarantees. Lower latency alone is insufficient.

## Architectures under test

### A. Current four-ledger design

Four hash chains with distinct writers:

- proposal
- evidence
- decision
- execution

The current reference implementation stores the full payload in each ledger record, hashes the payload, signs the complete record subject, and hashes the resulting signed record.

### B. Unified multi-signer commitment log

One global hash chain. Every record retains:

- explicit record type
- explicit writer role
- a role-specific signing key
- a per-record signature
- a payload digest
- optional inline payload
- previous-record hash
- global sequence number

Large evidence may remain in immutable content-addressed storage while the audit chain carries the exact digest.

This log is audit evidence only. It is not a permit, reservation, credential, or execution authority.

### C. Minimal deterministic permit boundary

A negative/latency control containing only the commitments required to authorize one exact action:

- proposal/action digest
- evidence root
- policy digest
- validity interval
- nonce
- one-use constraint
- authority signature
- durable consumption state outside the microbenchmark

This case tests which security properties actually require a ledger rather than a permit boundary.

## Required attack matrix

The unified design must detect or prevent all applicable attacks below before I-040 can be reconsidered:

| Attack | Four ledgers | Unified chain requirement |
| --- | --- | --- |
| proposal payload mutation | detect | detect |
| evidence substitution | detect | detect |
| evidence commitment mutation | detect | detect |
| decision deletion | detect | detect |
| record reordering | detect | detect |
| proposal writer forges decision | reject | reject |
| evidence writer forges execution | reject | reject |
| unknown record type | fail closed | fail closed |
| chain truncation after witnessed head | detect | detect |
| unrelated artifact substitution | reject | reject |
| post-approval action mutation | reject at permit boundary | reject at permit boundary |
| authorization replay | reject at durable state boundary | reject at durable state boundary |
| stale/revoked authority | reject at durable state boundary | reject at durable state boundary |
| unknown provider outcome | remain unknown | remain unknown |

## Security properties that are not provided by chain count

The experiment treats the following as independent mechanisms and does not credit either log design for them unless they are actually enforced by the corresponding boundary:

- exact action binding
- fresh evidence requirements
- deterministic policy evaluation
- human approval binding
- one-use reservation
- revocation dominance
- provider idempotency semantics
- independent outcome observation
- credential isolation
- external trust root

A receipt-only system therefore remains an invalid substitute for ClaimSieve authority semantics even if it is faster.

## Performance measurements

`python/experiments/ledger_ablation.py` reports median, p95, and p99 local cryptographic/canonicalization time plus serialized audit bytes for 1 KiB, 8 KiB, and 64 KiB evidence payloads.

The benchmark excludes database fsync, network latency, provider latency, independent observation, production contention, and multi-host coordination. Results are microbenchmarks, not production service-level claims.

## Acceptance criteria

Do not replace I-040 unless all of the following are true:

1. The unified design passes the mutation, deletion, reordering, cross-role forgery, unknown-type, and commitment-substitution tests.
2. Permit/reservation/revocation behavior remains unchanged and independently tested.
3. Independent outcome authority remains unchanged.
4. A witnessed head or equivalent external checkpoint detects suffix truncation.
5. Content-addressed evidence can be retrieved and byte-for-byte matched to the committed digest for audit replay.
6. Concurrency testing shows the single chain does not introduce unacceptable writer contention or availability coupling.
7. Crash recovery preserves sequence and no-successor ambiguity.
8. The measured benefit is material enough to justify migration complexity.

## Expected interpretation

A likely outcome is not "four concepts are unnecessary." Proposal, evidence, decision, and execution remain distinct semantic and authority domains. The question is whether those domains require four physical hash chains, or whether role-separated signatures and exact commitments on a shared chain are sufficient for audit integrity while execution safety remains in the permit and durable-state boundaries.
