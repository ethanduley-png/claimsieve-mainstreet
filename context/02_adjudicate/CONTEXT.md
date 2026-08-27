# 02_adjudicate — independently check proposal claims

## Purpose
Evaluate a proposal against policy, evidence, trust, freshness, and security invariants. Adjudication decides eligibility; it does not execute.

## Inputs
- Working: exact proposal artifact from stage 01
- Reference: applicable `policies/` document
- Reference: `schemas/evidence-bundle.schema.json`
- Reference: trust material under `trust/`
- Reference: `security/INVARIANTS.md`

## Authority
- May: allow, deny, or require human review according to policy.
- Must not: mutate proposal bindings to make a request pass, call provider execution APIs, or manufacture evidence.

## Invariants
1. Policy and evidence are independently checked against the exact proposal.
2. Missing, stale, conflicting, or unverifiable material fails closed.
3. A model/provider that proposed an action cannot make its own assertion sufficient evidence for authorization.

## Outputs
- Adjudication decision and reasons.
- Evidence references required by authorization.

## Evidence produced
- Decision trace binding proposal, policy, evidence, and decision.

## Tests
- `python/tests/test_kernel.py`
- `python/tests/test_runtime.py`
- `scripts/semantic_divergence_gate.py`
- `scripts/run_red_team.py`

## Human gate
If policy requires review, adjudication can only mark the action as awaiting an independent human decision; it cannot synthesize approval.