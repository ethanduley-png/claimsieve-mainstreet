# Security Policy

## Reporting vulnerabilities

Please do not disclose exploitable security issues or credentials in public issues or pull requests. Prefer the repository's **Private vulnerability reporting** feature under GitHub Security if enabled. If it is not enabled, contact the repository maintainers through an agreed private channel. Do not send production tokens or customer information in a report.

Include the affected version or commit, the trust boundary, minimal reproduction steps, expected versus observed result and the potential impact. Avoid testing against real customer systems without explicit permission.

## Security scope

ClaimSieve is being developed as a security control for independently authorized consequential actions. The repository includes reference implementations, models and demonstrations; their presence is **not** a claim of complete deployment security, standards certification or production readiness.

See `security/THREAT_MODEL.md`, `security/INVARIANTS.md`, `docs/VERIFICATION_MATRIX.md`, and `docs/REMAINING_LIMITATIONS.md`.

The team will triage reports based on exploitability, affected trust boundary, blast radius and available reproductions. Fixes should include a regression that fails before the fix and passes after it.
