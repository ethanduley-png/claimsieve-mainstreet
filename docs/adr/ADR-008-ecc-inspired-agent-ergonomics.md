# ADR-008: ECC-inspired agent ergonomics remain outside the authority boundary

Status: Accepted

## Context

Main Street needs a usable agent operating model: reusable skills, specialized agent roles, durable rules, memory, evaluation, and harness adapters. ECC demonstrates a practical way to package those concerns without relying on one monolithic prompt.

Main Street already has a stronger security constraint: proposal runtimes remain non-authoritative and ClaimSieve is the independent authority and execution boundary. Agent ergonomics must not weaken that separation.

The existing small-business registry already classifies business capabilities by domain, risk, consequence, ClaimSieve requirement, human review, keywords, suggested inputs, and expected output. The existing Deep Agents adapter already treats the model runtime as untrusted and intercepts consequential tool calls before provider execution. The ergonomics layer should reuse those assets rather than create a parallel authority model.

## Decision

Use ECC as a reference implementation for agent ergonomics, not as an authority implementation.

Main Street may adopt clean-room patterns for:

- declarative skills
- specialized agent profiles
- durable non-authoritative rules
- cross-harness adapters
- unreviewed memory/context
- evaluation-driven development
- observation-to-workflow learning

Consequential Main Street skills must declare or derive all of the following properties:

- execution mode is `proposal_only`
- adjudicator is `claimsieve`
- direct execution is false

Informational skills remain `informational_only` and also have no provider execution capability.

Agent profiles may read context, select skills, prepare plans or proposals, validate non-authoritative acknowledgements, and record unreviewed observations. They may not acquire provider credentials, permit authority, provider execution, or authority to declare terminal external outcomes.

The JavaScript ergonomics layer may prepare an exact proposal for the existing `ProposalOnlyBridge`. When a stronger product-specific proposal builder already exists, the ergonomic skill must delegate to that builder rather than reimplement weaker validation. The first GitHub issue skill therefore delegates to `FounderOSProposalBuilder`, preserving its exact repository validation and derived correlation marker.

The Python ergonomics catalog is generated one-to-one from the existing `small_business_agent.registry` capability set. It provides a harness-neutral skill and agent vocabulary for planning and discovery; it does not replace the planner, ClaimSieve intake, runtime tool classification, policy evaluation, or execution path.

Memory created by the ergonomics layer starts as `trust: unreviewed`. Main Street exposes no memory-to-policy promotion capability. Any future promotion mechanism must be separately specified and independently governed.

Harness adapters such as OpenClaw, Deep Agents, Agent Reach, and future proposal runtimes are treated as untrusted capability and reasoning planes. They may select skills, gather context, and prepare proposals. They do not become part of the ClaimSieve trusted computing base merely because they use Main Street manifests.

## Consequences

Main Street gets ECC-style usability and portability without conflating workflow guidance with authority.

A compromised or hallucinating agent can still prepare a malicious proposal, but that proposal remains non-authoritative and must cross the existing ClaimSieve boundary before any consequential effect is possible.

Skill discovery metadata is not proof that a runtime tool implementation is benign. Existing runtime adapters must continue to fail closed on unclassified tools and must not infer provider permissions from ergonomic skill names.

The initial implementation lives in `mainstreet/src/ergonomics.js`, `mainstreet/ergonomics/`, and `python/mainstreet_ergonomics/`. The OpenClaw entry point exposes the non-authoritative catalog while continuing to forbid provider-secret environment prefixes. The implementation intentionally contains no provider SDK, credential store, permit issuer, direct execution function, or outcome authority.

## Non-goals

This ADR does not make ECC, OpenClaw, Deep Agents, Agent Reach, a model provider, a skill, an agent profile, a planner, or a memory store authoritative. It does not replace ClaimSieve policy evaluation, evidence checking, authorization, execution binding, outcome authority, or ledgers.
