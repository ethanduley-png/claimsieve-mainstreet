# ADR 008: Agent Reach is an explicitly untrusted capability plane

Status: accepted for implementation

## Context

Agent Reach is an installer, health checker, and routing guide for internet-facing upstream tools. Its own code states that reading and searching normally happens by calling those upstream tools directly rather than through Agent Reach itself. That is useful for MainStreet, but exposing those tools directly to the planning agent would collapse the separation between observation, authority, and execution.

Internet content is also adversarial by default. A web page, post, repository, video transcript, or search result can contain instructions aimed at the model. Those instructions are data from an external principal. They are not MainStreet policy, human approval, ClaimSieve authority, or an execution permit.

## Decision

MainStreet places Agent Reach below ClaimSieve as an explicitly untrusted observation plane.

```text
User / owner intent
        |
        v
OpenClaw planner
        |
        | narrow read request only
        v
MainStreet untrusted observation bridge
        |
        | isolated transport
        v
Agent Reach observer sidecar
        |
        | exact allowlisted read recipe
        v
Internet / upstream read tools
        |
        | untrusted bytes
        v
Tainted observation envelope
        |
        v
OpenClaw planner
        |
        | may cite observation as provenance input
        v
MainStreet proposal-only bridge
        |
        v
ClaimSieve policy + evidence + approval verification
        |
        | permit only if all gates pass
        v
Restricted executor
```

The invariant is:

> Agent Reach output can supply observations, but it can never supply authority.

Every Agent Reach result is wrapped as `mainstreet.untrusted_observation.v1` with `authority = NONE`, `executable = false`, `instructions_are_data = true`, required taint labels, and `claim_sieve_disposition = OBSERVATION_ONLY`.

The OpenClaw-facing JavaScript module has no network client, shell, provider credential, permit signer, or executor. It only prepares an allowlisted request and validates the returned envelope. The separate Python observer owns the narrow upstream process invocation. It uses `shell=False`, prebuilt argument vectors, bounded output, exact parameter shapes, and no caller supplied executable, environment, flags, or output path.

## Initial capability set

The first slice intentionally supports only a small read surface: Agent Reach status, web page reading through the Agent Reach documented Jina path, public GitHub repository search, Exa search, V2EX hot topics, and Bilibili search. Login-backed social channels are disabled in the policy file until their credential and browser isolation can be proven independently.

Mutation verbs, arbitrary commands, provider configuration, login automation, cookie extraction, write credentials, approvals, permit operations, and execution are out of scope for this plane.

## Security consequences

Prompt injection is not parsed as policy. It remains inside `content` and carries `NO_AUTHORITY` plus `REQUIRES_INDEPENDENT_VERIFICATION`.

A compromised or malicious upstream tool still cannot legitimately mint ClaimSieve authority. Deployment must additionally deny the observer access to ClaimSieve signing material, permit storage, executor credentials, writer credentials, and internal execution endpoints.

URL validation blocks obvious loopback, private address, embedded credential, and non-HTTP targets before launch. Network policy remains the authoritative defense against DNS rebinding and unexpected egress.

Hashes bind the capability request and exact returned content to an observation identifier. They provide integrity binding, not truth. A raw Agent Reach observation is not `claimsieve.evidence.v1`, cannot satisfy `required_evidence`, and is never marked `verified`. When a policy needs an internet-derived fact, a separate trusted evidence verifier must inspect the observation, derive the bounded claim, and sign that claim under an evidence key already authorized by ClaimSieve policy.

## Replaceability

Agent Reach remains replaceable. ClaimSieve consumes policy-qualified signed evidence and proposals, not Agent Reach-specific authority semantics. A future browser, search system, or connector can implement the same untrusted observation contract without changing the authority boundary.
