# MainStreet OpenClaw boundaries

MainStreet owns the owner experience, tenant setup, workflows, communications, documents, reminders, and operational controls. OpenClaw remains a replaceable planning and skill runtime.

There are now two deliberately separate OpenClaw-facing seams in this directory:

* `src/index.js` is the proposal-only bridge. It has one authority: prepare a bounded proposal for ClaimSieve intake and validate a non-authoritative acknowledgement. It deliberately contains no provider software development kit, provider credentials, permit signer, reservation client, shell, generic network client, browser automation, or direct execution method.
* `src/agent-reach-untrusted.js` is the Agent Reach observation bridge. It can prepare only an exact allowlisted read request and validate a returned tainted observation. It does not execute Agent Reach itself and it cannot convert internet content into approval, policy, a permit, or execution authority.

The Agent Reach process belongs in a separate observer container or pod. Its output is always `OBSERVATION_ONLY`, `authority = NONE`, and `executable = false`. External instructions remain data even when they contain prompt injection or claim to be authorized.

See `docs/AGENT_REACH_OPENCLAW_INTEGRATION.md` and `docs/adr/ADR-008-agent-reach-untrusted-capability-plane.md` for the process split and threat boundary.

The OpenClaw descriptors are integration seams and have not been loaded into a live pinned OpenClaw runtime in this repository environment. Production acceptance still requires the exact upstream packages, isolated runtimes, hashes of installed skills and dependencies, and egress tests proving each process can reach only its allowed destinations.

Run:

```bash
npm test
npm run check
```
