# Detailed Test Report — v0.33.0

## Executed gates

| Gate | Result |
|---|---|
| Python unit and adversarial tests | 140 passed |
| MainStreet Node tests | 18 passed |
| Source and schema gate | Passed |
| Portable bundle verification | Passed |
| v0.32 violating trace | Reproduced from preserved probe |
| v0.33 patched trace | `OUTCOME_UNKNOWN`, violation blocked |
| Outcome semantics vectors | 8 of 8 passed |
| Stripe contract-derived scenarios | 6 of 6 passed |
| Inherited red-team suite | 52 blocked or detected, 0 bypasses, 6 limitations |
| Durable-state red-team suite | 25 blocked or detected, 0 bypasses, 4 limitations |
| Rust native gates | Not available |
| Rocq native gates | Not available |

## Discriminating tests added

### False signed executor rejection

Would fail if a signed executor status could still establish terminal failure without independent provider evidence.

### Contradictory provider record

Would fail if an accepted-without-effect or rejected-with-effect record were coerced into success or failure rather than remaining unknown.

### Exact same-dispatch replay

Would fail if the provider model created a second effect for the same key and request inside the modeled retention window.

### Retention expiry

Would fail if ClaimSieve allowed replay at or beyond the conservative retention boundary. The bypass branch intentionally shows the model creating a second effect.

### Mutation and revocation guards

Would fail if changed reservation, key, request, endpoint, account, authority, provider guarantee, or replay budget still authorized replay.

## Evidence files

* `evidence/PYTHON_TEST_OUTPUT.txt`
* `evidence/NODE_TEST_OUTPUT.txt`
* `evidence/SOURCE_GATE.txt`
* `evidence/V032_INVARIANT_VIOLATION_TRACE.json`
* `evidence/V033_PATCHED_TRACE.json`
* `evidence/PROVIDER_CONTRACT_TEST_REPORT.json`
* `evidence/SEMANTIC_DIVERGENCE_REPORT.json`
* `evidence/RED_TEAM_REPORT.json`
* `evidence/DURABLE_RED_TEAM_REPORT.json`
* `evidence/NATIVE_TOOLCHAIN_STATUS.json`
* `evidence/NATIVE_COMPILATION_ATTEMPT.txt`

## Interpretation rule

A test count is not a security claim. It is evidence that specific paths behaved as expected under specific fixtures. Infrastructure limitations, common-mode implementation assumptions, and untested live-provider behavior remain material.
