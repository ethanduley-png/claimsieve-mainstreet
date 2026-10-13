# Engineering Standards Baseline

Status: adopted engineering guidance and partial automated enforcement; **not** certification or full standards conformance.

## Sources and use

| Reference | Application in this repository | Evidence expected |
| --- | --- | --- |
| [NIST SSDF SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final) | Defined secure-development roles, code review, change control, vulnerability remediation | PR review and security test trace |
| [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) | Explicit authentication, authorization, session, data and API requirements for future production interfaces | Requirement-specific negative tests |
| [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/) | Agent output untrusted, bounded tool permissions, external execution approval | Agent bypass and mutation tests |
| [ISO/IEC 25010:2023](https://www.iso.org/standard/78176.html) | Reliability, security, maintainability, interoperability and performance quality attributes | Measured properties and documented limits |
| [OpenSSF Security Baseline](https://baseline.openssf.org/) | Access control, reviewed changes, dependency and workflow hardening | GitHub repository settings and CI |
| [SLSA](https://slsa.dev/) | Reproducible build inputs, traceable releases, provenance integrity | Signed provenance and independently checked subjects (not yet complete) |

These references are guidance, not a claim that every published control has been implemented.

## Security requirements for any new consequential action

1. Define the actor, tenant, action, destination, exact parameters, policy identity and expiry.
2. Bind any approval to the identical canonical representation presented to the reviewer.
3. Deny dispatch without a valid independently issued permit and durable one-use reservation.
4. Enforce tenant isolation at data access and the executor, not only in prompts or user interfaces.
5. Keep verifier and executor authority separate. Do not let an agent, adapter, or observer self-authorize.
6. Treat malformed, missing, contradictory, stale and unverifiable evidence as non-authorizing.
7. Preserve an explicit `OUTCOME_UNKNOWN` state and never silently retry a possibly dispatched effect.
8. Emit traceable evidence without leaking credentials, sensitive payloads, or fabricated outcome certainty.

## Definition of done

- Design includes a threat model and traceable invariant or business acceptance requirement.
- Tests cover success, rejection, boundary mutations, replay and relevant failure recovery.
- Changed workflow rules pass `python scripts/engineering_policy_gate.py` and its mutation tests.
- Python, JavaScript, Rust, and Rocq lanes execute as applicable; a skipped/unavailable lane is `NOT RUN`.
- Review describes exact commit, failing or missing checks, deviations, and limitations.
- Release requires actual CI evidence and repository-side branch protection; adding workflow files alone does **not** enforce merge restrictions.

## Supply chain and operational gaps to close

- The repository currently references third-party GitHub Actions by mutable tags. Migrate to reviewed full commit SHA pins with a recorded update process.
- Lock Python production and test dependencies with hashes or a reviewed constraints strategy; current test ranges do not establish a reproducible installation.
- Add software composition analysis, secret scanning, dependency update governance, build provenance signing and a security disclosure contact.
- Require status checks and at least one independent approval on the default branch via GitHub rulesets or branch protection.
- Establish deployment-level workload identity, egress confinement, tenant isolation, hardware-backed key custody, recovery and live fault-injection evidence.
- Do not claim production readiness or formal correspondence from isolated Python tests or Rocq source proofs.

See `docs/VERIFICATION_MATRIX.md` and `security/REVIEW_CHECKLIST.md`.
