# ClaimSieve Context Router

Purpose: route an agent to the smallest trustworthy context needed for a task. This file is documentation and routing only. It is not an authorization boundary and never substitutes for ClaimSieve policy, evidence, permit, executor, observer, or ledger checks.

## Routing

| Task | Read |
|---|---|
| Propose a consequential action | `context/01_propose/CONTEXT.md` |
| Adjudicate claims and policy | `context/02_adjudicate/CONTEXT.md` |
| Issue or validate authority | `context/03_authorize/CONTEXT.md` |
| Execute an authorized action | `context/04_execute/CONTEXT.md` |
| Observe provider outcome | `context/05_observe/CONTEXT.md` |
| Audit evidence and traces | `context/06_audit/CONTEXT.md` |
| Global security invariants | `security/INVARIANTS.md` |
| Threat model | `security/THREAT_MODEL.md` |
| Architecture | `docs/ARCHITECTURE.md` |
| Durable state semantics | `docs/DURABLE_STATE_BOUNDARY.md` |

## Separation of powers

Context routing is not authority. A proposer cannot authorize itself. An authorizer cannot manufacture execution evidence. An executor cannot determine provider outcome. An observer cannot retroactively change a permit. Each stage emits an artifact that the next authority independently checks.

## Walk rule

A cold agent must be able to reach the correct stage contract from this file in one read, then identify exact inputs, authority, invariants, outputs, evidence, tests, and the human gate from that contract.
