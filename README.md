# ClaimSieve + MainStreet AI

**Authority before action. Evidence after execution.**

AI agents are useful because they can propose work. They should not be trusted to authorize their own actions, execute with unrestricted credentials, or certify their own success.

**ClaimSieve** is an independent authority and execution-assurance boundary for AI-proposed actions. **MainStreet AI** is the small-business product layer that prepares workflows and proposals without owning the security-critical authority.

> **The rule:** An agent can propose an action. ClaimSieve decides whether that *exact* action is authorized. A restricted executor may attempt it once under the applicable permit. Independent observation determines what can actually be said about the outcome.

**Current repository release:** `v0.34.0 — Founder Operations Boundary` (see [VERSION](VERSION) and [START_HERE.md](START_HERE.md))  
**Maturity:** Research and reference implementation with executable tests, formal models, and one narrowly scoped live GitHub canary. **Not a production-ready autonomous business assistant.**

## Why this exists

A plausible model response is not permission. A tool-call success message is not proof of an external result. A network timeout is not proof that an action failed.

ClaimSieve separates these questions:

1. **Proposal:** What action is being requested, by whom, and with what exact destination and parameters?
2. **Authority:** Is there current, independently verifiable policy, evidence, approval, and state allowing it?
3. **Execution:** Did a restricted component receive the matching, valid, one-use authority for that action?
4. **Outcome:** Can an independent observer confirm what happened, or must the result remain unknown?
5. **Audit:** Can the decision, attempted effect, and observed result be reconstructed from preserved evidence?

The goal is *bounded authority and accountable execution*, not a promise that an AI model will never make mistakes.

## Architecture

```text
User / MainStreet / OpenClaw / other agent
           (untrusted proposal side)
                     |
                     v
       Canonical proposal + evidence
                     |
                     v
       ClaimSieve policy verification
                     |
             exact approval
                     |
                     v
     Independent one-use permit authority
                     |
             durable reservation
                     |
                     v
          Restricted executor
                     |
                external effect
                     |
                     v
          Independent observer
                     |
       confirmed / failed / divergent
              / still unknown
                     |
                     v
       Durable state + audit ledgers
```

**No single agent or provider should both propose and independently certify its own authority and outcome.** MainStreet and optional agent runtimes remain outside the permit-signing and execution boundary. The design is provider-neutral at the authority boundary; this release does **not** claim every provider integration is complete.

Read [Architecture](docs/ARCHITECTURE.md), [Security Assumptions](docs/SECURITY_ASSUMPTIONS.md), and the [Product Map](docs/PRODUCT_MAP.md).

## What is implemented today

| Area | Evidence-backed status |
| --- | --- |
| MainStreet proposal-only JavaScript bridge | Implemented and tested; deliberately excludes provider credentials and direct execution |
| ClaimSieve policy, signed evidence, exact bindings, and permit path | Implemented in the Python reference and exercised by tests |
| Durable campaign, permit, reservation, revocation, and outcome state | Local SQLite reference implementation and adversarial tests; **not distributed consensus** |
| Four-ledger proposal / authorization / execution / observation evidence | Reference workflow and verification tests |
| Founder OS GitHub issue workflow | Proposal builder, exact repository binding, guarded live adapter, deterministic simulation, and read-only reconciliation |
| GitHub live experiment | **One** explicitly authorized issue creation on August 2, 2026; initially unknown, later reconciled to confirmed success without resending |
| Rust and Rocq | Source, tests, and local native compilation/proof-assistant evidence for specified components; **not an end-to-end production proof** |
| OpenClaw, Deep Agents, and Agent Reach | Proposal/adapter or untrusted-observation integration seams and tests; **not a verified production deployment** |
| Full MainStreet customer-facing product | **Not yet implemented** as a complete deployed business application |

The live experiment is documented in [GitHub Integration](docs/GITHUB_INTEGRATION.md) and [canary evidence](evidence/GITHUB_LIVE_CANARY_REPORT.json). Its temporary credentials were revoked. It is a narrow integration check, not evidence of general production safety.

For claim-by-claim detail, see the [Status Matrix](docs/STATUS_MATRIX.md), [Claims and Evidence Matrix](docs/CLAIMS_AND_EVIDENCE_MATRIX.md), and [Remaining Limitations](docs/REMAINING_LIMITATIONS.md).

## Quick start (local reference implementation)

**Prerequisites**

- Python 3.11 or newer and pip
- Node.js 22 or newer
- Bash and standard Unix tools (Windows users can use WSL)
- Rust toolchain for Rust gates; Rocq/Coq for formal compilation gates

The full test script reports unavailable native toolchains rather than treating unexecuted Rust or Rocq checks as passing. It also writes test transcripts to `evidence/`; use a disposable working copy when preserving a clean checkout matters.

```bash
git clone https://github.com/ethanduley-png/claimsieve-mainstreet.git
cd claimsieve-mainstreet
python3 -m pip install -r python/requirements-test.txt
./scripts/test_all.sh
```

For a focused, offline Founder OS demonstration:

```bash
PYTHONPATH=python python3 python/founder_os_demo.py
```

To test the MainStreet proposal-side JavaScript module separately:

```bash
cd mainstreet
npm test
npm run check
```

Rust verification is available from `rust/`, including `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, and `cargo test --workspace --all-features`. The project contains Rocq sources and build instructions under [rocq/](rocq/). Local native results and their exact scope are documented in [Native Compilation Report](docs/NATIVE_COMPILATION_REPORT.md).

**Trust-root warning:** The bundled fixture keys and example trust root are for demonstration and tests. They are not production authority.

## First governed action: create one GitHub issue

The v0.34 Founder OS slice deliberately starts small: **prepare and, only when explicitly authorized, create one issue in one approved repository**.

The workflow includes signed work-item and repository evidence, exact human approval, an action-bound permit, a durable one-use reservation, a restricted GitHub writer, separate read-only observation credentials, and outcome reconciliation.

By default, use the deterministic simulator. The live integration requires dedicated credentials, repository allowlisting, and an explicit enable switch plus execute confirmation. **Never automatically retry an ambiguous GitHub issue creation.** A timeout may leave the effect committed but not yet visible; the correct result is `OUTCOME_UNKNOWN` until suitable observation resolves it.

See [GitHub Integration](docs/GITHUB_INTEGRATION.md) for non-sending `check` and `plan` commands, opt-in live execution, reconciliation, and security requirements.

## MainStreet and untrusted agent runtimes

MainStreet is the proposed owner-facing layer for communications, tasks, documents, scheduling, workflow preparation, approvals, and recovery. Its role is to provide a useful small-business experience **without bypassing ClaimSieve**.

- **OpenClaw and Deep Agents** are replaceable proposal-side runtimes, not independent permit authorities.
- **Agent Reach** is treated as an untrusted internet observation surface. Even a read query can leak tenant information, so exact outbound requests require authorization before egress.
- Internet responses are **untrusted observations**, not permission, verified evidence, or instructions for the executor.
- The executor, observer, and signing identities are meant to have distinct authority and credentials. The repository includes reference boundaries, not proof that a deployed infrastructure enforces every separation.

See [MainStreet boundary](mainstreet/README.md), [Agent Reach integration](docs/AGENT_REACH_OPENCLAW_INTEGRATION.md), [Deep Agents adapter](docs/DEEPAGENTS_RUNTIME_ADAPTER.md), and [deployment reference](deploy/README.md).

## What this project does not claim

This is important to the trust model:

- **No general production safety certification.** One controlled GitHub canary is not a representative production test.
- **No full Rust/Python semantic parity.** Known observer receipt/schema divergence remains documented.
- **No blanket end-to-end formal verification.** Rocq results prove specified modeled statements under their assumptions; implementation refinement, cryptography, parsing, key custody, and deployment need independent evidence.
- **No distributed high availability.** SQLite provides local atomicity, not multi-node consensus or independent failure domains.
- **No guaranteed provider truth or native GitHub idempotency.** Read-back can be stale or incomplete; conflicting or absent results remain unknown.
- **No complete MainStreet user interface or multi-tenant hosted service** in this release.

See [Remaining Limitations](docs/REMAINING_LIMITATIONS.md) and [Roadmap](docs/ROADMAP.md) before representing any part of the project as deployment-ready.

## Start reading

- [START_HERE.md](START_HERE.md) — current release identity and first demonstration
- [Architecture](docs/ARCHITECTURE.md) — authority and outcome boundaries
- [Founder OS Architecture](docs/FOUNDER_OS_ARCHITECTURE.md) — bounded GitHub workflow
- [Status Matrix](docs/STATUS_MATRIX.md) — what is implemented versus unproven
- [Claims and Evidence Matrix](docs/CLAIMS_AND_EVIDENCE_MATRIX.md) — traces, tests, and proof scope
- [Remaining Limitations](docs/REMAINING_LIMITATIONS.md) — unresolved safety and deployment obligations
- [CODEX_HANDOFF.md](CODEX_HANDOFF.md) — development handoff and next steps

**Release policy:** `VERSION` and [Authoritative Version Map](AUTHORITATIVE_VERSION_MAP.md) identify the active baseline. Experiments in open pull requests are not part of the released main branch unless merged.

## License

Licensed under the **Apache License, Version 2.0** ([LICENSE](LICENSE)). You may use, modify, and distribute the covered code under its terms, including its notice and attribution requirements. Apache 2.0 includes an express patent license from contributors for applicable patent claims. See [NOTICE](NOTICE) for project attribution; third-party materials retain their applicable licenses.

---

*Trust in an uncertain world means admitting uncertainty, constraining authority, and keeping evidence available for independent review.*