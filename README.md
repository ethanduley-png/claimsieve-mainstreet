# MainStreet AI + ClaimSieve v0.34.0 — Founder Operations Boundary

This release merges the Founder OS v0.1 product concept into the v0.33 Independent Outcome Boundary without retaining its weaker parallel permit system.

## Product sentence

MainStreet helps the founders observe work and prepare exact proposals. ClaimSieve independently verifies policy, evidence, approval, campaign state, and action bindings. A restricted adapter may execute one valid permit. Independent observation determines whether the external effect is confirmed, failed, divergent, or unknown.

## First Founder OS vertical slice

The first governed company action is intentionally narrow:

> Propose creation of one GitHub issue in one approved repository.

The deterministic simulator remains the default. An opt-in, GitHub.com-only issue adapter is also implemented with separate writer/observer credentials, exact repository allowlisting, correlation-marker read-back, and no automatic retry. On 2026-08-02, an explicitly authorized canary created [issue #1](https://github.com/ethanduley-png/claimsieve-mainstreet/issues/1) in the dedicated private repository. The immediate bounded read returned `OUTCOME_UNKNOWN`; a later read-only reconciliation found the exact permitted action digest and returned `CONFIRMED_SUCCESS` without retrying the write. The temporary canary tokens were then revoked.

## What changed from v0.33

- Added a proposal-only Founder OS builder to MainStreet.
- Added a deterministic Python Founder OS reference workflow.
- Added signed work-item and repository-registry evidence.
- Added exact founder approval and existing v0.33 permit issuance.
- Added durable reservation, fencing, execution, independent observation, and four-ledger recording for the GitHub issue workflow.
- Added Founder OS product, threat, migration, acceptance, and limitation documents.
- Added Python, Node, and adversarial tests.
- Added the restricted live GitHub issue adapter and guarded command-line entry point.
- Preserved both source archives with checksums under `provenance/inputs/`.

## Deliberately removed from the active path

The Founder OS v0.1 HMAC authority, in-memory replay set, direct adapter outcome classification, and single JSONL ledger were not promoted into the merged runtime. They remain only in the preserved input archive.

## Run all available gates

```bash
./scripts/test_all.sh
```

## Focused Founder OS demo

```bash
PYTHONPATH=python python3 python/founder_os_demo.py
```

On Windows, `..\run-claimsieve.cmd` runs the demo and `..\run-claimsieve.cmd test` runs the Python, JavaScript, Rust, and Rocq gates with the installed local toolchains.

See `docs/GITHUB_INTEGRATION.md` for the read-only access check, non-sending plan, credential boundary, and deliberately gated live-create command.

The Rust portable verifier requires the independently supplied trust root:

```bash
cd rust
cargo run -p claimsieve-cli -- verify ../vectors/valid_evidence_bundle.json ../trust/fixture-trust-root.json
```

## Read first

1. `START_HERE.md`
2. `docs/FOUNDER_OS_MERGE_REPORT.md`
3. `docs/FOUNDER_OS_ARCHITECTURE.md`
4. `docs/CONCRETE_INVARIANT_VIOLATION.md`
5. `docs/SEMANTIC_DIVERGENCE_REPORT.md`
6. `docs/FOUNDER_OS_KNOWN_LIMITATIONS.md`
7. `CODEX_HANDOFF.md`

## Claim boundary

Implemented and executed here: Python reference behavior, MainStreet proposal-only JavaScript, deterministic provider simulation, restricted GitHub adapter tests, one explicitly authorized live GitHub canary, read-only reconciliation, four ledgers, attack tests, packaging, and fresh extraction.

Not established here: production credential isolation, distributed consensus, infrastructurally independent observation, complete Rust provider-outcome parity, or end-to-end Founder OS correctness. The live observer used a distinct read-only token but ran from the same local operator boundary. The native status report records the Rust gates and accepted Rocq proofs that were executed locally.
