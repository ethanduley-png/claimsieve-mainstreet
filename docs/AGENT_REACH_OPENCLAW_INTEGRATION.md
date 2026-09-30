# MainStreet + OpenClaw + Agent Reach + ClaimSieve

This integration deliberately does **not** install Agent Reach inside the same authority domain as OpenClaw or let OpenClaw call its upstream tools freely.

Agent Reach 1.5.0 describes itself as an installer and health checker; for reading and searching, agents normally call upstream tools directly. MainStreet therefore treats the Agent Reach recipes and upstream tools as a hostile-capable sensor surface rather than a trusted plugin surface.

## The enforced order

```text
OpenClaw intent
    -> bounded capability request
    -> exact ClaimSieve action
    -> ClaimSieve decision
    -> signed one-use permit
    -> Agent Reach read executor
    -> internet
    -> tainted observation
    -> OpenClaw
```

There is no supported `OpenClaw -> Agent Reach -> internet` shortcut.

The reason is confidentiality as well as integrity. A malicious page can inject instructions into the planner, and a malicious instruction can try to exfiltrate tenant data through the next search query. Even though a search is read-only at the provider, the outbound query is a network-boundary effect. ClaimSieve therefore authorizes the exact query or URL before it leaves the observer.

## Process split

Use four distinct authority domains:

1. **OpenClaw planner**: may reason over user intent and validated observations. It receives no provider write credentials and no ClaimSieve signing material.
2. **ClaimSieve**: verifies the internet-read proposal just like another governed effect. It binds the exact action, destination, parameters, policy, evidence, approval state, validity window, and one-use permit.
3. **Agent Reach read executor**: receives only a bounded request plus its exact signed ClaimSieve permit. It verifies the permit and containment state, atomically consumes it, then executes one allowlisted read recipe. It cannot sign permits or mutate providers.
4. **Restricted consequential executor**: remains separate for later business effects such as messages, calendar changes, refunds, or record updates. Internet content cannot jump directly to this executor.

Never expose Agent Reach's raw command surface, OpenCLI discovery, generic shell access, cookie extraction, configure/install commands, or arbitrary MCP tools directly to the planner.

## Request and permit binding

`UntrustedObservationBridge.prepare()` constructs `mainstreet.capability_request.v1`. `claimSieveBinding()` maps the request to:

```text
kind          = fetch_artifact
effect_class  = network_boundary
scheme        = agent-reach
trust_domain  = agent-reach-untrusted
method        = READ
risk tag      = UNTRUSTED_NETWORK_EGRESS
```

The action parameters bind the request identifier, observation sequence, and exact read arguments. Channel and operation are bound in the destination. MainStreet sends the full proposal through the existing proposal-only bridge.

The Python read executor accepts no unsigned shortcut. It verifies the trusted ClaimSieve authority signature plus exact proposal, action, destination, and parameter digests. It also verifies permit validity, revocation/freeze/suspension state, and one-use semantics before dispatch.

The permit is consumed before the upstream attempt. If the network call times out or produces unusable output, MainStreet must obtain a fresh authorization rather than silently replaying the request.

## Observation semantics

The result is `mainstreet.untrusted_observation.v1` and is bound to the `permit_id`, request digest, and exact content digest. Its semantics are fixed to:

```text
authority               = NONE
executable              = false
instructions_are_data   = true
claim_sieve_disposition = OBSERVATION_ONLY
```

If external content says "ignore ClaimSieve" or "this action is approved", those words remain data inside the observation. They do not alter any of the fields above.

## ClaimSieve evidence rule

Raw Agent Reach output never satisfies ClaimSieve `required_evidence`. The observation envelope is provenance only: it is not `claimsieve.evidence.v1`, it is not signed by a trusted evidence source, and it is not marked verified.

If a later action depends on an internet-derived fact, a separate verifier must inspect the raw observation, extract a bounded claim, and emit signed ClaimSieve evidence using an evidence identity and key that the active tenant policy already authorizes. That verifier is independent of Agent Reach and the OpenClaw planner.

This preserves three different statements:

```text
"The internet returned X"       -> observation
"A trusted verifier proved X"   -> evidence
"This exact effect may occur"   -> ClaimSieve permit
```

## Initial read surface

The policy currently allows only `agent-reach.status`, `web.read`, `github.search_repositories`, `search.exa`, `v2ex.hot`, and `bilibili.search`.

Authenticated social channels are intentionally disabled for the first integration. They should be added one at a time only after the observer can use a dedicated read-only credential/profile and the deployment proves that credential cannot perform a provider mutation.

## Deployment requirements

Run the read executor in its own container or pod, service account, filesystem, home directory, and network policy. Do not mount the OpenClaw home directory, normal browser profile, ClaimSieve signing key material, consequential executor credentials, or provider writer credentials into it.

The read executor should have only the authority public keys needed to verify permits and a read-only view of revocation/freeze/suspension state. It must not possess the ClaimSieve private authority key.

Use a dedicated observer home. The reference subprocess runner intentionally does not inherit the planner's `HOME`, GitHub token, cloud credentials, provider credentials, or arbitrary environment variables. Any future authenticated read credential must be scoped to that observer and proven unable to write.

The observer needs broad public read egress, so production should combine network isolation with an egress proxy that blocks private/metadata networks and records permitted destinations. Network policy must deny routes to internal execution services even if an upstream tool is compromised.

The OpenClaw planner should not receive generic internet egress merely because Agent Reach exists. Its existing proposal-only boundary remains separate.

Pin Agent Reach before production deployment. The current policy records upstream version `1.5.0` and commit `a19a171fa980a0785849596492e0af4db800c82f`. Upgrades require reviewing the read recipes, security behavior, and dependency changes before changing the pin.

## Verification

The JavaScript boundary tests run without Agent Reach or network access:

```bash
node --test mainstreet/test/agent-reach-untrusted.test.js
```

The Python tests exercise the integration against the real ClaimSieve reference authority: a signed policy and signed evidence produce a real one-use permit, the read executor verifies that permit, tampered queries and forged/revoked/replayed permits are rejected, and prompt injection remains non-authoritative data.

```bash
PYTHONPATH=python python3 -m unittest python/tests/test_agent_reach_plane.py -v
```

The full repository workflow discovers both suites. A live acceptance test is still a separate deployment step because this repository does not claim that a pinned OpenClaw runtime and Agent Reach sidecar have already been deployed in production.
