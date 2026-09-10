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

## Local benchmark

The benchmark uses the same algorithmic shape as the current Python reference path: restricted canonical JSON, SHA-256 commitments, Ed25519 signatures, the existing four-ledger append structure, and the experimental unified commitment log. It excludes database fsync, network/provider latency, observer latency, cross-host coordination, and production contention.

120 iterations per case were run in the local test environment.

| Evidence payload | Architecture | Median | p95 | p99 | Serialized audit bytes |
| ---: | --- | ---: | ---: | ---: | ---: |
| 1 KiB | minimal permit control | 0.257 ms | 0.298 ms | 0.392 ms | 460 |
| 1 KiB | four ledgers inline | 0.710 ms | 0.808 ms | 0.988 ms | 3,641 |
| 1 KiB | unified commitment log | 0.680 ms | 0.724 ms | 0.856 ms | 2,628 |
| 8 KiB | minimal permit control | 0.285 ms | 0.318 ms | 0.386 ms | 460 |
| 8 KiB | four ledgers inline | 0.867 ms | 0.971 ms | 1.160 ms | 10,809 |
| 8 KiB | unified commitment log | 0.739 ms | 0.818 ms | 1.009 ms | 2,628 |
| 64 KiB | minimal permit control | 0.525 ms | 0.619 ms | 0.800 ms | 460 |
| 64 KiB | four ledgers inline | 2.137 ms | 2.383 ms | 2.491 ms | 68,153 |
| 64 KiB | unified commitment log | 1.217 ms | 1.535 ms | 1.979 ms | 2,628 |

## Preliminary interpretation

The first result does **not** support a receipt-only architecture. Exact authority still depends on proposal/action commitments, evidence commitments, policy state, validity, one-use semantics, and durable reservation/revocation checks.

The result does support a narrower criticism: carrying full evidence artifacts inside every hot-path ledger record produces avoidable work and audit-volume growth. At 64 KiB, the experimental commitment log reduced median local audit-path cryptographic/canonicalization time from about 2.14 ms to 1.22 ms and reduced serialized audit material from about 68 KiB to about 2.6 KiB. The content itself must still exist in immutable/retrievable storage; those storage costs are not included here.

The experiment has not yet established that one physical chain can replace four chains. The remaining decisive tests are external witnessed-head truncation detection, exact artifact replay from content-addressed storage, concurrent writer contention, crash recovery, writer availability coupling, and preservation of existing durable execution tests.

## Decision

Keep I-040 normative for now. Continue the ablation branch until the full acceptance criteria in `docs/LEDGER_ABLATION_EXPERIMENT.md` are satisfied or the unified design fails one of them.
