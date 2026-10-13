# 06_audit — reconstruct and challenge the action chain

## Purpose
Independently determine whether proposal, adjudication, authorization, execution, and observation satisfied the declared contracts and preserved evidence.

## Inputs
- Working: proposal, adjudication trace, permit, execution trace, observation record
- Reference: `CLAIMS_MATRIX.md`
- Reference: `LIMITATIONS.md`
- Reference: `TEST_REPORT.md`
- Reference: `security/INVARIANTS.md`
- Reference: release manifest/evidence artifacts

## Authority
- May: verify, flag, or reject assurance claims.
- Must not: rewrite historical artifacts, manufacture missing evidence, or convert source inspection into claims of compilation/proof acceptance.

## Invariants
1. Every security claim has a discriminating test and preserved trace.
2. Release claims distinguish source inspection from executed tests, Rust compilation, and Rocq proof acceptance.
3. Missing evidence is reported as a limitation, not inferred away.
4. Trace linkage preserves exact material action bindings across stages.

## Outputs
- Audit findings, violated invariant(s), evidence references, residual limitations.

## Evidence produced
- Reproducible audit report and release evidence references.

## Tests
- Full `.github/workflows/reference-tests.yml` gate set.
- Fresh extraction/bundle verification where required by release process.

## Human gate
Release acceptance is a human decision informed by the evidence. Audit output cannot silently promote an unverified claim into a verified one.