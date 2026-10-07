# MainStreet OpenClaw boundaries

MainStreet owns the owner experience, tenant setup, workflows, communications, documents, reminders, and operational controls. OpenClaw remains a replaceable planning and skill runtime.

There are two deliberately separate OpenClaw-facing seams in this directory:

* `src/index.js` is the proposal-only bridge. It has one authority: prepare a bounded proposal for ClaimSieve intake and validate a non-authoritative acknowledgement. It deliberately contains no provider software development kit, provider credentials, permit signer, reservation client, shell, generic network client, browser automation, or direct execution method.
* `src/agent-reach-untrusted.js` is the Agent Reach observation bridge. It prepares only an exact allowlisted read request, maps that request to the exact ClaimSieve `network_boundary` action that must be authorized, and validates the returned permit-bound tainted observation. It does not execute Agent Reach itself and it cannot convert internet content into approval, policy, evidence, a permit, or execution authority.

The read flow is deliberately ordered as:

```text
OpenClaw -> capability request -> ClaimSieve proposal -> signed one-use permit
         -> isolated Agent Reach read executor -> internet -> tainted observation
```

There is no supported direct OpenClaw-to-Agent-Reach network path. This matters because even a read-only search query can disclose tenant data.

The Agent Reach read executor belongs in a separate container or pod. It verifies the trusted ClaimSieve authority signature, exact request/action/parameter bindings, validity, containment state, and one-use semantics before outbound network activity. Its output is always `OBSERVATION_ONLY`, `authority = NONE`, and `executable = false`. External instructions remain data even when they contain prompt injection or claim to be authorized.

See `docs/AGENT_REACH_OPENCLAW_INTEGRATION.md` and `docs/adr/ADR-008-agent-reach-untrusted-capability-plane.md` for the process split and threat boundary.

The OpenClaw descriptors are integration seams and have not been loaded into a live pinned OpenClaw runtime in this repository environment. Production acceptance still requires the exact upstream packages, isolated runtimes, hashes of installed skills and dependencies, and egress tests proving each process can reach only its allowed destinations.

Run:

```bash
npm test
npm run check
```
