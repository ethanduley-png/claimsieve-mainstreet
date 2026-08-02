# Claims and Evidence Matrix

## Evidence hierarchy

1. Raw discriminating trace
2. Executed test output
3. Fresh-extraction reproduction
4. Native compiler or proof-assistant output
5. Static source inspection
6. Design document

Higher-numbered items cannot substitute for missing lower-numbered evidence when the claim requires execution.

## Major claims

### Unknown remains unknown

* Invariant: `security/INVARIANTS.md`
* Original counterexample: `evidence/V032_INVARIANT_VIOLATION_TRACE.json`
* Patch: `python/claimsieve_ref/durable_state.py`
* Regression: `python/tests/test_durable_state.py`
* Adversarial trace: `evidence/DURABLE_RED_TEAM_REPORT.json`
* Rocq statement: `rocq/DurableState.v`
* Native proof status: compiled and assumption-audited with Rocq 9.0.1

### Executor is not outcome authority

* TCB decision: `docs/SMALLEST_TCB_REMOVAL.md`
* Python implementation: `IndependentObserver`
* Rust source candidate: `IndependentObserver`
* Structural gate: `scripts/source_gate.py`
* Remaining protocol divergence: `docs/SEMANTIC_DIVERGENCE_REPORT.md`

### Transport replay is not a new logical action

* Provider contract snapshot: `research/stripe_idempotency_contract.json`
* Executable model: `python/claimsieve_ref/provider_contracts.py`
* Gate: `scripts/provider_contract_gate.py`
* Python tests: `python/tests/test_provider_contracts.py`
* Rust source guard: `transport_replay_allowed`
* Rocq model: `transport_replay_allowed`
* Live provider status: not tested

### Native assurance

* Rust source exists: yes
* Rust compiler evidence: yes; format, warning-denied Clippy, 28 tests, and v0.34 bundle verification pass
* Rocq source exists: yes
* Rocq compiler and assumption evidence: yes; four files compile and audited theorems are closed under the global context
* Explicit attempt: `evidence/NATIVE_COMPILATION_ATTEMPT.txt`

### Restricted GitHub issue integration

* Implementation: `python/claimsieve_ref/github_provider.py`
* Guarded command: `python/github_integration.py`
* Exact-action and adversarial tests: `python/tests/test_github_provider.py`
* Operator instructions: `docs/GITHUB_INTEGRATION.md`
* Redacted live evidence: `evidence/GITHUB_LIVE_CANARY_REPORT.json`
* Deterministic HTTP-boundary status: implemented and tested
* Live GitHub status: one explicitly authorized issue created exactly once; delayed read-only reconciliation confirmed the exact permitted action digest without a write retry
* Credential status: both temporary canary tokens revoked after reconciliation

## Prohibited inference

Do not infer that a property is implemented in Rust because it is proved in Rocq, or proved in Rocq because a similarly named Python test passes. Each bridge requires separate refinement or differential evidence.
