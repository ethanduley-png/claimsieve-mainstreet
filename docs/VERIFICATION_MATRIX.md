# Engineering Verification Matrix

This map intentionally distinguishes available code or tests from demonstrated end-to-end deployment assurance. Recheck evidence on the exact proposed commit.

| Control | Invariant | Implementation entry | Executable evidence or check | Remaining limitation |
| --- | --- | --- | --- | --- |
| Exact authorization and separation | I-001, I-002, I-006 | `python/claimsieve_ref/kernel.py`, `rust/crates/kernel/src/lib.rs` | `python/tests/test_kernel.py`, `python/tests/test_runtime.py`, Rust workflow | Production role isolation unverified |
| Approval/evidence binding | I-020, I-021, I-022, I-023 | `python/claimsieve_ref/verifier.py` | `python/tests/test_runtime.py`, `scripts/source_gate.py` | Human comprehension cannot be proved |
| One-use reservation and durable state | I-003, I-017, I-030 | `python/claimsieve_ref/durable_state.py`, `rust/crates/durable-state/src/lib.rs` | `python/tests/test_durable_state.py`, `scripts/run_durable_red_team.py` | Multi-node linearizability not established |
| Uncertain outcome quarantine | I-032, I-032A, I-033B, I-033C | `python/claimsieve_ref/provider_contracts.py`, `python/claimsieve_ref/github_provider.py` | `python/tests/test_provider_contracts.py`, `python/tests/test_github_provider.py`, provider gate | Real provider faults and contract drift |
| No direct agent effects | I-007 | `mainstreet/src/index.js`, `python/mainstreet_runtimes/agent_reach_plane.py` | `scripts/source_gate.py`, `mainstreet/test/proposal-bridge.test.js` | Static checks alone cannot prove containment |
| Tamper evidence | I-040, I-041, I-042 | `python/claimsieve_ref/ledger.py`, `python/claimsieve_ref/verifier.py` | `python/tests/test_ledger.py`, `python/verify_bundle.py` | Independent witness deployment absent |
| Proof model | I-002, I-030, I-032 | `rocq/Claimsieve.v`, `rocq/DurableState.v` | `.github/workflows/rocq.yml` | No complete Rust-to-Rocq refinement |
| Workflow integrity | Secure development | `scripts/engineering_policy_gate.py` | `python/tests/test_engineering_policy_gate.py`, engineering policy workflow | Structural guard only; branch protection required |
| Locked Rust resolution | Supply chain | `rust/Cargo.lock` | Rust workflow's `cargo ... --locked` | No signed binary provenance |
| Production incident recovery | Operational resilience | `docs/RECOVERY_GUIDE.md` | Explicit deployment exercise needed | No production drill evidence |

## Evidence states

- **PASS**: a check actually executed successfully against the indicated revision and configuration.
- **FAIL**: it executed and rejected or produced a failed assertion.
- **NOT RUN**: the check did not execute, including when a runner was unavailable, the toolchain was absent, or only source inspection occurred.
- **NOT PROVED**: a model proof may be valid without proving a matching runtime implementation or environment.

A merge decision must record all relevant states and cannot substitute descriptive documentation for a required execution result.
