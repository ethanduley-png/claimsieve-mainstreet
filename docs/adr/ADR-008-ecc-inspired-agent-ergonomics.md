# ADR-008: ECC-inspired agent ergonomics remain outside the authority boundary

Status: Accepted

## Context

Main Street needs a usable agent operating model: reusable skills, specialized agent roles, durable rules, memory, evaluation, and harness adapters. ECC demonstrates a practical way to package those concerns without relying on one monolithic prompt.

Main Street already has a stronger security constraint: the Main Street runtime is proposal-only and ClaimSieve is the independent authority and execution boundary. Agent ergonomics must not weaken that separation.

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

Every Main Street skill and agent manifest must declare:

- `mode: proposal_only`
- `adjudicator: claimsieve`
- `direct_execution: false`

The ergonomics layer may prepare an exact proposal for the existing `ProposalOnlyBridge`. It may not issue approval, sign or reserve permits, access provider credentials, execute provider actions, or confirm execution outcomes.

Memory created by the ergonomics layer starts as `trust: unreviewed`. Main Street exposes no memory-to-policy promotion capability. Any future promotion mechanism must be separately specified and independently governed.

Harness adapters such as OpenClaw or Agent Reach are treated as untrusted capability and reasoning planes. They may select skills, gather context, and prepare proposals. They do not become part of the ClaimSieve trusted computing base merely because they use Main Street manifests.

## Consequences

Main Street gets ECC-style usability and portability without conflating workflow guidance with authority.

A compromised or hallucinating agent can still prepare a malicious proposal, but that proposal remains non-authoritative and must cross the existing ClaimSieve boundary before any consequential effect is possible.

The initial implementation lives in `mainstreet/src/ergonomics.js` and `mainstreet/ergonomics/`. It intentionally contains no provider SDK, credential store, network transport, shell execution, filesystem write, permit issuer, or execution function.

## Non-goals

This ADR does not make ECC, OpenClaw, Agent Reach, a model provider, a skill, an agent profile, or a memory store authoritative. It does not replace ClaimSieve policy evaluation, evidence checking, authorization, execution binding, outcome authority, or ledgers.
