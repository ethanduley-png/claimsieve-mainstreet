# Open Execution Assurance Profile v1

Status: **candidate**

This document extracts provider-neutral execution-assurance invariants from the existing ClaimSieve v0.34 reference implementation. It is deliberately narrower than the complete MainStreet / Founder OS product and broader than any one provider adapter.

The profile is intended to answer one question:

> What must be true before an AI-proposed consequential action is allowed to become an external state change, and how must its outcome be represented afterward?

This is a behavioral conformance profile. It is not a claim of production safety, legal compliance, formal proof of the full system, or novelty.

## Core model

```text
untrusted proposer
      |
      v
exact proposal + evidence snapshot
      |
      v
deterministic policy decision
      |
      v
independent permit authority
      |
      v
one-use exact-action permit
      |
      v
durable reservation / execution boundary
      |
      v
external provider
      |
      v
independent read-back
      |
      v
outcome reconciliation + evidence chains
```

The governing principle is:

> **Proposal is not authority.**

A model, agent, workflow, user interface, or orchestrator may prepare a proposed action. None of those artifacts alone authorize the external effect.

## Normative invariants

The keywords **MUST**, **MUST NOT**, **SHOULD**, and **SHOULD NOT** are normative for this candidate profile.

### OEA-001 — Proposal is not authority

A proposal and an `ALLOW` decision MUST NOT be sufficient to execute a consequential action. The execution boundary MUST require cryptographically verifiable authority bound to the evaluated proposal and decision.

### OEA-002 — Exact action binding

Execution authority MUST bind the exact action, destination, and parameters. A mutation after authorization MUST be rejected before dispatch.

An implementation MUST NOT treat authorization for an action class such as `send_message`, `refund`, or `create_issue` as authority for arbitrary recipients, amounts, repositories, payloads, or other parameters.

### OEA-003 — One-use logical authority

A permit for one consequential logical action MUST be consumable at most once. Concurrent or later attempts to consume the same permit as a new logical action MUST fail closed.

A provider-specific transport replay is outside this invariant only when it is demonstrably the same already-authorized dispatch and is governed by a separate idempotency contract.

### OEA-004 — Unknown is a first-class outcome

Ambiguous transport, missing read-back, contradictory evidence, or incomplete provider state MUST NOT be converted to success or failure without sufficient independent evidence.

The system MUST preserve `OUTCOME_UNKNOWN` until later evidence supports a stronger classification.

### OEA-005 — Independent outcome authority

An executor receipt establishes what the executor attempted or reported. It MUST NOT be terminal authority over the real external effect.

Terminal reconciliation MUST be based on independently readable provider evidence or an explicitly documented equivalent observation boundary.

### OEA-006 — Divergence triggers containment

If independently observed external state differs from the authorized action, the system MUST classify the effect as `DIVERGENT_EFFECT` rather than success.

The reference profile requires containment of the affected campaign after a divergent effect or internally contradictory provider evidence.

### OEA-007 — No automatic new logical retry

No outcome, including `CONFIRMED_FAILURE` or `OUTCOME_UNKNOWN`, MUST automatically grant authority for a new logical attempt.

A new logical action requires fresh authority under current policy, evidence, campaign state, and approval requirements.

### OEA-008 — Separate evidence chains

The reference profile keeps proposal, evidence, decision, and execution records separately identifiable and independently chain-verifiable.

Combining storage backends is not forbidden, but an implementation claiming this profile MUST preserve the ability to distinguish and verify these authority domains.

## Candidate conformance gate

The machine-readable profile is:

```text
vectors/execution_assurance_profile_v1.json
```

The reference behavioral gate is:

```text
PYTHONPATH=python python -m unittest python.tests.test_execution_assurance_profile -v
```

The normal repository gate also discovers this suite:

```text
PYTHONPATH=python python -m unittest discover -s python/tests -v
```

The tests exercise the existing v0.34 durable Founder OS slice as a concrete adapter. Passing those tests demonstrates the listed reference behaviors for the tested simulator scenarios. It does **not** establish that every provider integration or production deployment satisfies the profile.

## Existing implementation mapping

The current v0.34 code already contains the main building blocks needed for this profile:

- deterministic proposal and evidence evaluation;
- exact action, destination, parameter, policy, evidence, approval, and campaign-state permit bindings;
- a one-use durable reservation boundary;
- a restricted executor;
- a separately keyed observer;
- explicit `OUTCOME_UNKNOWN` semantics;
- divergent-effect containment;
- four signed ledger chains;
- external trust-root verification in the portable verifier;
- Rust and Rocq assurance work with documented proof boundaries.

This profile therefore formalizes an existing architectural direction rather than introducing a parallel authority path.

## Known non-conformance and out-of-scope boundaries

The candidate profile does not erase existing limitations. In particular:

- the Rust runtime still emits observer receipt v1 rather than the complete Python/schema v2 receipt;
- observer independence is logical in the reference deployment, not an independent infrastructure failure domain;
- the SQLite durable boundary is not distributed consensus;
- provider records can be incomplete, stale, false, or semantically misleading;
- human approval binding does not prove comprehension or legal sufficiency;
- hardware-backed key isolation and independently reproduced builds are not established;
- live-provider evidence remains intentionally narrow.

These limitations must remain visible in claims about conformance.

## Provider neutrality

A conforming implementation is not required to use a particular model, cloud, agent framework, or provider. The proposer can be OpenAI, Google, Microsoft, Anthropic, a local model, a deterministic workflow, or a human-operated system.

The assurance boundary evaluates **authority over the exact external state transition**, not the brand or intelligence of the proposer.

That is the interoperability target for a future standalone ClaimSieve open-source project.
