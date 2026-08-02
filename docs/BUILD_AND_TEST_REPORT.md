# Build and Test Report — v0.34.0

## Environment

- Python 3.14.6
- Node.js 24.14.0
- npm 10.9.2
- Rust: project-pinned 1.90.0 GNU (rustup user default 1.97.1)
- Rocq Platform 2025.08 / Rocq Prover 9.0.1
- Networked provider execution: one explicitly authorized canary executed; continuing writes remain disabled without fresh credentials and exact repository confirmation

## Merge inputs

See `provenance/INPUTS.sha256`.

The v0.33 archive was used as the active baseline. The Founder OS v0.1 archive was inspected and retained as provenance. Its weaker HMAC authority was not imported into active code.

## Commands executed

```bash
./scripts/test_all.sh
```

The script executed:

- Python unit and state-machine tests
- Restricted GitHub adapter and independent read-back tests
- Evidence bundle generation and verification
- Durable execution vector generation
- MainStreet Node tests
- JavaScript syntax checks
- Founder OS deterministic demo
- Founder OS adversarial suite
- Source and schema gate
- v0.33 invariant trace probe
- Stripe contract model gate
- Semantic divergence gate
- Inherited red-team suite
- Durable-state red-team suite
- Native toolchain detection

## Results

- Python: **170 passed**
- Node: **23 passed**
- Founder OS adversarial scenarios: **8 of 8 blocked or detected**
- Founder OS tested bypasses surviving: **0**
- Inherited red team: **0 tested bypasses**, with documented infrastructure limitations
- Durable red team: **0 tested bypasses**, with documented infrastructure limitations
- Rust: **28 tests passed**, formatting and warning-denied Clippy passed
- Rust v0.34 portable verifier: **PASS** against the external fixture trust root
- Rocq: **4 files compiled**, with audited theorems closed under the global context
- Source and schema gate: **PASS**
- Four Founder OS ledger chains: **PASS**
- Available executable gates: **PASS**

## Native status

Rust and Rocq were installed and executed locally on 2026-08-02. The exact commands and claim boundary are recorded in `docs/NATIVE_COMPILATION_REPORT.md` and `evidence/NATIVE_COMPILATION_ATTEMPT.txt`. Native success does not resolve the remaining Rust observer-receipt v1 versus Python/schema v2 divergence.

## Provider status

The Founder OS defaults to a deterministic local provider simulator. A GitHub.com-only issue adapter is implemented and tested through a deterministic HTTP seam, including distinct tokens, exact repository restrictions, one-shot POST behavior, marker read-back, mutation detection, duplicate detection, and read-path preflight.

On 2026-08-02, an explicitly authorized canary created `ethanduley-png/claimsieve-mainstreet#1` exactly once. The immediate bounded read returned `OUTCOME_UNKNOWN`; later read-only reconciliation matched the exact permitted action digest and returned `CONFIRMED_SUCCESS` without retrying the write. Both temporary fine-grained tokens were revoked. This single canary is evidence only for the recorded action and does not establish production credential isolation or infrastructure-independent observation.
