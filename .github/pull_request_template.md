## Purpose and change scope

What changed, why, and which components or authority boundaries are affected?

## Requirements and threats

- Invariant IDs (from `security/INVARIANTS.md`) or business acceptance requirements:
- Threat scenario and expected rejection:
- Are tenant, destination, approval, evidence or provider boundaries affected?
- Does the change add a dependency, credential, external action or egress capability?

## Verification evidence

Record the **exact commit SHA** and PASS / FAIL / NOT RUN for each applicable lane.

| Gate | Status | Revision, log or trace |
| --- | --- | --- |
| Engineering policy and mutation tests | NOT RUN | |
| Python and Node reference tests | NOT RUN | |
| Source, provider and adversarial gates | NOT RUN | |
| Rust format, Clippy and tests | NOT RUN | |
| Rocq compilation and assumption check | NOT RUN | |
| Live / fault-injection tests if relevant | NOT RUN | |

## Security and release review

- [ ] Negative tests demonstrate rejection of unauthorized or modified actions.
- [ ] No reduction in security checks, independent authority or key separation.
- [ ] Unknown external outcomes remain unknown; no automatic effect replay.
- [ ] Changes preserve no-credential and no-direct-execution boundaries in Main Street.
- [ ] Documents, limitations and release evidence updated as applicable.
- [ ] Any exception has a named owner, expiry, rationale and compensating control.
- [ ] Required checks executed successfully; independent review complete before merge.
