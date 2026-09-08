# Strix adversarial baseline

This integration treats Strix as an untrusted adversary around ClaimSieve, not as part of the trusted computing base.

## CI behavior

The workflow at `.github/workflows/strix-adversarial.yml` has two independent jobs.

1. **Deterministic boundary baseline** runs the existing ClaimSieve adversarial/runtime unit tests and the executable red-team harness. This requires no external model credentials.
2. **Strix autonomous adversary** runs a pinned Strix CLI (`strix-agent==1.6.2`) in headless quick-scan mode when both `STRIX_LLM` and `LLM_API_KEY` are available as GitHub Actions secrets. Its first deployment is deliberately nonblocking.

Strix exit codes are preserved in uploaded evidence. A vulnerability result is therefore not discarded merely because the baseline job is nonblocking.

## Trust model

Strix receives no production credentials by design. The attack instructions explicitly limit it to the checked-out worktree and local simulated/reference systems. Its reports are evidence candidates, not trusted facts. Findings must be independently reproduced before becoming merge-blocking controls.

The intended progression is:

`observe -> reproduce -> classify -> add deterministic regression -> remediate -> rerun -> promote high-confidence regression to merge-blocking gate`

## Promotion rule

Do not make raw Strix output itself a hard merge gate. Promote a finding only after a deterministic reproducer demonstrates a security-relevant invariant failure. The deterministic regression then becomes the durable gate; Strix remains a discovery layer.

## Initial ClaimSieve attack surface

The scan instructions emphasize exact action/destination/parameter binding, human approval freshness and identity, permit replay and races, policy/evidence substitution, durable campaign-state forks, cryptographic role separation, containment/revocation races, ambiguous outcomes, DeepAgents adapter bypasses, ambient credentials/egress, ledger tampering, parser/canonicalization disagreement, Python/Rust/Rocq conformance, and fail-open exception paths.

## Evidence

GitHub Actions uploads:

- `claimsieve-deterministic-adversarial-baseline`
- `claimsieve-strix-adversarial-baseline`

The Strix artifact records whether credentials were available. When a scan executes, console output, the actual Strix exit code, and any generated `strix_runs/` artifacts are retained.
