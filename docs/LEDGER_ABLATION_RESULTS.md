# Ledger Ablation Results

Date: 2026-09-09
Branch: `experiment/unified-audit-log`
Status: preliminary local microbenchmark, not a production performance claim.

## Attack checks

The experimental unified multi-signer log passed the first mutation and writer-separation probes:

- valid chain verifies
- proposal payload mutation detected
- evidence commitment mutation detected
- record deletion detected
- record reordering detected
- proposal writer forging a decision detected

These checks establish only audit-chain integrity for the tested cases. They do not replace ClaimSieve permit, reservation, revocation, approval, provider reconciliation, or independent outcome authority.

## Methodology correction

The first benchmark compared the current four-ledger path with inline evidence against a unified log carrying only an evidence commitment. That comparison mixed two independent variables: **chain count** and **artifact representation**.

A corrected control was added: **four ledgers with the same content-addressed evidence commitment strategy**. This isolates the cost of four physical chains from the cost of carrying large evidence artifacts inline.

That correction materially changes the interpretation.

## Corrected local benchmark

The benchmark uses the same algorithmic shape as the current Python reference path: restricted canonical JSON, SHA-256 commitments, Ed25519 signatures, the existing four-ledger append structure, and the experimental unified commitment log. It excludes database fsync, network/provider latency, observer latency, cross-host coordination, content-store writes/reads, and production contention.

200 iterations per corrected case were run in the local test environment.

| Evidence payload | Architecture | Median | p95 | p99 | Serialized audit bytes |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 KiB | minimal permit control | 0.266 ms | 0.441 ms | 0.532 ms | 460 |
| 1 KiB | four ledgers inline | 0.712 ms | 0.876 ms | 0.985 ms | 3,677 |
| 1 KiB | four ledgers commitment | 0.667 ms | 0.754 ms | 0.929 ms | 2,663 |
| 1 KiB | unified commitment log | 0.661 ms | 0.733 ms | 0.893 ms | 2,664 |
| 8 KiB | minimal permit control | 0.284 ms | 0.329 ms | 0.575 ms | 460 |
| 8 KiB | four ledgers inline | 0.868 ms | 0.975 ms | 1.141 ms | 10,845 |
| 8 KiB | four ledgers commitment | 0.698 ms | 0.796 ms | 0.951 ms | 2,663 |
| 8 KiB | unified commitment log | 0.689 ms | 0.808 ms | 0.944 ms | 2,664 |
| 64 KiB | minimal permit control | 0.524 ms | 0.557 ms | 0.671 ms | 460 |
| 64 KiB | four ledgers inline | 2.153 ms | 2.482 ms | 2.676 ms | 68,189 |
| 64 KiB | four ledgers commitment | 0.933 ms | 1.050 ms | 1.248 ms | 2,663 |
| 64 KiB | unified commitment log | 0.917 ms | 1.000 ms | 1.079 ms | 2,664 |

## Preliminary interpretation

The corrected experiment does **not** support the claim that four physical hash chains themselves create massive cryptographic overhead. Once both designs carry the same compact evidence commitment, their local costs are nearly identical. At 64 KiB the four-ledger commitment case measured about 0.933 ms median versus about 0.917 ms for the unified chain, with essentially identical serialized audit size.

The performance problem is therefore much more specifically **large inline artifact handling**, not the number four. The current inline four-ledger case still scales with evidence size because the evidence artifact is repeatedly canonicalized and incorporated into signed/hash-chained structures. Replacing large inline artifacts with exact content commitments removes most of that growth while preserving four semantic chains.

The result also does **not** support a receipt-only architecture. Exact authority still depends on proposal/action commitments, evidence commitments, policy state, validity, one-use semantics, and durable reservation/revocation checks.

The remaining argument for or against four physical chains is now architectural rather than a simple cryptographic-latency argument: writer independence, storage/failure-domain separation, retention policy, concurrent append contention, operational complexity, crash recovery, and external witnessing.

## Decision

Keep I-040 normative for now. The most promising optimization is **content-addressed evidence with compact ledger commitments while retaining the four semantic chains**. Continue testing the unified design only as an ablation control until the full acceptance criteria in `docs/LEDGER_ABLATION_EXPERIMENT.md` are satisfied or it fails one of them.
