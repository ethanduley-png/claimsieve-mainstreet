# 01_propose — produce a bounded proposal

## Purpose
Create a proposal artifact only. This stage has no authority to authorize or execute consequential actions.

## Inputs
- Working: user or upstream task input
- Reference: `schemas/proposal.schema.json`
- Reference: applicable file under `policies/`
- Reference: `security/INVARIANTS.md`

## Authority
- May: construct and serialize a proposal.
- Must not: issue permits, call providers, claim execution success, alter trust roots, approvals, or policy.

## Invariants
1. Consequential actions remain proposal-only.
2. Repository/destination, action, parameters, expected effect, policy, evidence, approval, and campaign identifiers are explicit before adjudication.
3. Unknown or missing consequential fields fail closed into non-executable proposal state.

## Outputs
- Proposal conforming to `schemas/proposal.schema.json`.

## Evidence produced
- Canonical proposal representation/hash where supported by runtime.

## Tests
- `python/tests/test_kernel.py`
- `python/tests/test_runtime.py`
- `mainstreet/test/proposal-bridge.test.js`

## Human gate
For actions requiring human approval, a human must review the exact action scope and parameters before any permit can become valid.