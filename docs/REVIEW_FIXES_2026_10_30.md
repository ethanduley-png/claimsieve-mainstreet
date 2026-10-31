# Review fixes and native validation â€” 2026-10-30

Published implementation revision: `2411009e953e29b47acc0242fdf6c7262b1fba19`.

Tests executed on local revision `f7251b004b854f7746bb29aaec59452375b2ee9f`. GitHub publication has the identical Git tree `a16fd4069bc20ff12a1199ac935de4a0e84b367e` (verified through the GitHub API); commit metadata differs because publication used the connected integration.
Review baseline: `fa858f56a9d459d7dcb4b1651dd77f8d93ce1157`.
The subsequent evidence/documentation commit does not change executable source.

## Fixes and invariant mapping

- **I-002 / I-023:** recovery snapshots the supplied proposal and verifies its authority action digest against the durable reservation before changing state or claiming dispatch. Negative tests mutate body, tenant, principal, campaign and objective; valid recovery still executes.
- **I-033 / I-033A / I-033B:** observation verifies the same durable binding before querying or recording finality. A substituted proposal cannot disguise a divergent provider effect as success; reconciliation with the original proposal still records divergence and containment.
- OCR inputs are written into a private temporary directory and closed before engine access. The directory remains alive during lazy result iteration and is cleaned on exit. Existing fake-engine tests reopen and verify the source bytes, provenance and cleanup on Windows.
- GitHub challenge connections close on initialization, issuance, consumption and replay rejection. The new lifecycle test retains connection references and proves all four connections are closed, independently of garbage collection.
- Context test-reference validation rejects POSIX, Windows, UNC, drive-relative and parent-traversal paths consistently across hosts.
- Rocq fixes repair existing missing imports, a missing parenthesis, conjunction construction, explicit theorem arguments and Boolean simplification. No theorem statements are weakened and no axioms or admissions are introduced.
- Both local test runners now compile every `.v` entry in `_RocqProject`; the project includes ExecutionAssurance and its assumption checks. Windows Rust commands use `--locked`.

## Executed validation

All results below are for implementation revision `f7251b004b854f7746bb29aaec59452375b2ee9f` on Windows. Sanitized logs include the revision; local filesystem prefixes and non-actionable memory-address warnings are omitted.

| Check | Result | Evidence |
| --- | --- | --- |
| Python unittest discovery | PASS: 511 tests, 15 skipped | `evidence/review-2026-10-30/reference-tests.txt` |
| JavaScript bridge/API/web tests | PASS: 88 tests | same reference log |
| Source, engineering-policy and context-contract gates | PASS | same reference log |
| Rust 1.90 formatting, locked offline Clippy, workspace tests | PASS: 48 tests | `evidence/review-2026-10-30/rust.txt` |
| Python/Rust outcome and observer-wire conformance | PASS: 11 outcome and 12 wire vectors | same Rust log |
| Rocq 9.0.1 compilation | PASS: all 18 files | `evidence/review-2026-10-30/rocq.txt` |
| Rocq assumption reports | PASS: 119 reports closed under the global context | same Rocq log |
| PowerShell/Bash runner syntax | PASS | locally parsed with PowerShell Parser / `bash -n` |
| CI's Rocq 9.2 container | NOT RUN locally | remote CI must execute before merge |
| Live provider writes / production isolation | NOT RUN | offline tests only |

The original unauthorized dispatch and false-success reproduction is preserved in `evidence/review-2026-10-30/before-boundary-trace.txt`. The new negative tests failed against the baseline; their original failure output is preserved in `before-regressions.txt`.

## Limits and merge boundary

These are repository fixes, not a new packaged release. Existing release manifests and archived fresh-extraction claims are not regenerated or relabeled. Before a new release, regenerate the manifest and run fresh-extraction validation.

Local passing checks do not establish production credential isolation, observer-host independence, complete Python/Rust equivalence, or that the executable implementation satisfies every Rocq theorem. Python discovery still skips 15 environment/optional cases and emits ResourceWarnings from other pre-existing database lifecycles; those are not claimed fixed here. The complete aggregate test runner was not executed end-to-end; the listed lanes and syntax checks were executed explicitly.

Independent review and actually executed required CI remain necessary before merging this security-critical change. No automatic merge is requested.
