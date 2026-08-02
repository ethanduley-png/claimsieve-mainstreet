# Codex Handoff — v0.34 Founder Operations Boundary

## Mission

Continue from the merged v0.34 release. Preserve v0.33 assurance mechanisms unless a discriminating test demonstrates a flaw. Do not reintroduce the Founder OS v0.1 HMAC authority or any parallel execution path.

## Required first output

Before editing, report:

1. repository root, branch, and commit if Git metadata exists;
2. `VERSION` and authoritative source inputs;
3. toolchains available;
4. exact commands used to reproduce all gates;
5. any failing gate;
6. the single invariant selected for the next change.

## Completed engineering target

The GitHub adapter contract harness and guarded live REST path are implemented. Local tests cover marker binding, exact read-back, mutation, duplicates, ambiguous transport, read-back preflight, repository allowlisting, and the full Founder OS composition.

One explicitly authorized live canary was executed on 2026-08-02. It created `ethanduley-png/claimsieve-mainstreet#1` exactly once. The immediate bounded observation was unknown; the later read-only `observe` command matched the exact permitted action digest and classified it `CONFIRMED_SUCCESS`. Both temporary fine-grained tokens were revoked after reconciliation. Redacted details are in `evidence/GITHUB_LIVE_CANARY_REPORT.json`.

Required properties:

- client-generated correlation marker bound into the approved payload;
- independent readback by repository and marker;
- no automatic retry after a timeout;
- duplicate detection;
- explicit `OUTCOME_UNKNOWN` when readback is incomplete;
- exact repository binding;
- deterministic simulator and conformance vectors;
- no live call without explicit credentials and authorization.

GitHub App installation identity binding remains a production target; the current reference accepts separate fine-grained tokens scoped outside the process.

## Second target

Native compilation is complete locally: Rust format, warning-denied Clippy, 28 tests, v0.34 bundle verification, and all four Rocq compilation/assumption gates pass. The remaining target is to make Rust consume the complete Founder OS and provider-outcome vector sets and to resolve or explicitly preserve the observer receipt v1/v2 divergence.

## Reporting standard

For every claim use one of:

- implemented and tested;
- implemented but not executed;
- designed but not implemented;
- formally modeled;
- formally proved by an executed compiler gate;
- outside the proof boundary;
- blocked by environment limitations.
