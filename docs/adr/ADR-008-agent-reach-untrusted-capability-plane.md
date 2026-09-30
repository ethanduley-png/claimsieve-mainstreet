# ADR 008: Agent Reach is a permit-gated, explicitly untrusted capability plane

Status: accepted for implementation

## Context

Agent Reach is an installer, health checker, and routing guide for internet-facing upstream tools. Its own code states that reading and searching normally happens by calling those upstream tools directly rather than through Agent Reach itself. That is useful for MainStreet, but exposing those tools directly to the planning agent would collapse the separation between observation, authority, and execution.

Internet content is adversarial by default. A web page, post, repository, video transcript, or search result can contain instructions aimed at the model. Those instructions are data from an external principal. They are not MainStreet policy, human approval, ClaimSieve authority, or an execution permit.

A second risk is outbound disclosure. A supposedly read-only search can still leak customer data, credentials, or tenant context through its query or URL. Therefore “read-only” is not the same as “safe to execute without authority.”

## Decision

MainStreet places Agent Reach below ClaimSieve as an explicitly untrusted, permit-gated observation plane.

```text
User / owner intent
        |
        v
OpenClaw planner
        |
        | narrow read request
        v
MainStreet observation bridge
        |
        | exact ClaimSieve action binding
        v
Proposal-only bridge
        |
        v
ClaimSieve policy + evidence + approval verification
        |
        | signed one-use permit
        v
Agent Reach read executor
        |
        | exact permit-bound read recipe
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
        | may cite provenance, never authority
        v
Any later consequential action goes through ClaimSieve again
```

The core invariants are:

> No Agent Reach network call occurs without an exact signed ClaimSieve permit.

> Agent Reach output can supply observations, but it can never supply authority.

Every capability request is mapped to a ClaimSieve `fetch_artifact` action with effect class `network_boundary`, destination trust domain `agent-reach-untrusted`, exact channel and operation binding, and parameters containing the request identifier, observation sequence, and exact arguments. The proposal must carry risk tag `UNTRUSTED_NETWORK_EGRESS` so policy can explicitly govern this boundary.

The read executor verifies the ClaimSieve authority signature, exact proposal/action/destination/parameter binding, validity window, containment state, and `max_uses = 1`. It atomically consumes the permit before any outbound call. A timeout or empty result does not restore the permit because disclosure may already have happened.

Every successful result is wrapped as `mainstreet.untrusted_observation.v1` with its ClaimSieve `permit_id`, `authority = NONE`, `executable = false`, `instructions_are_data = true`, required taint labels, and `claim_sieve_disposition = OBSERVATION_ONLY`.

The OpenClaw-facing JavaScript module has no network client, shell, provider credential, permit signer, or executor. It only prepares an allowlisted request, produces the exact ClaimSieve action binding, and validates the returned envelope. The separate Python read executor owns the narrow upstream process invocation. It uses `shell=False`, prebuilt argument vectors, bounded output, exact parameter shapes, a dedicated observer home, and no caller supplied executable, environment, flags, or output path.

## Initial capability set

The first slice intentionally supports only a small read surface: Agent Reach status, web page reading through the Agent Reach documented Jina path, public GitHub repository search, Exa search, V2EX hot topics, and Bilibili search. Login-backed social channels are disabled until their credential and browser isolation can be proven independently.

Mutation verbs, arbitrary commands, provider configuration, login automation, cookie extraction, write credentials, approvals, permit signing, and arbitrary execution are out of scope for this plane.

## Security consequences

Prompt injection is not parsed as policy. It remains inside `content` and carries `NO_AUTHORITY` plus `REQUIRES_INDEPENDENT_VERIFICATION`.

The query or URL itself is permit-bound before any DNS lookup or upstream request. Obvious loopback, private address, embedded credential, and non-HTTP targets are rejected syntactically before authorization. DNS resolution occurs only after permit authorization and rejects non-global answers. Deployment network policy remains the authoritative defense against DNS rebinding and unexpected internal egress.

A compromised or malicious upstream tool still cannot legitimately mint ClaimSieve authority. Deployment must additionally deny the observer access to ClaimSieve signing material, planner browser profiles, permit-signing services, executor credentials, writer credentials, and internal execution endpoints.

Hashes bind the permit, capability request, and exact returned content to an observation identifier. They provide integrity binding, not truth. A raw Agent Reach observation is not `claimsieve.evidence.v1`, cannot satisfy `required_evidence`, and is never marked `verified`. When a policy needs an internet-derived fact, a separate trusted evidence verifier must inspect the observation, derive the bounded claim, and sign that claim under an evidence key already authorized by ClaimSieve policy.

## Replaceability

Agent Reach remains replaceable. ClaimSieve authorizes a provider-neutral effect shape and consumes policy-qualified signed evidence and proposals, not Agent Reach-specific claims of authority. A future browser, search system, or connector can implement the same permit-gated untrusted observation contract without changing the authority boundary.
