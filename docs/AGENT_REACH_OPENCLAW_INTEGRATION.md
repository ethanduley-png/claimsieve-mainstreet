# MainStreet + OpenClaw + Agent Reach + ClaimSieve

This integration deliberately does **not** install Agent Reach inside the same authority domain as OpenClaw or ClaimSieve.

Agent Reach 1.5.0 describes itself as an installer and health checker; for reading and searching, agents call upstream tools directly. MainStreet therefore treats the Agent Reach recipes and upstream tools as a hostile-capable sensor surface rather than a trusted plugin surface.

## Process split

Use four distinct authority domains:

1. **OpenClaw planner**: may reason over user intent and validated observations. It receives no provider write credentials and no ClaimSieve signing material.
2. **Agent Reach observer**: may perform only operations in `config/agent-reach-readonly-policy.json`. It has internet egress but no write credentials, no ClaimSieve permit material, and no route to the executor.
3. **ClaimSieve**: verifies proposals, policy, evidence, approvals, freshness, destination binding, and action binding. It never trusts an observation merely because Agent Reach returned it.
4. **Restricted executor**: receives an exact ClaimSieve permit and performs only the bound action with separate provider credentials.

Never expose Agent Reach's raw command surface, OpenCLI discovery, generic shell access, cookie extraction, configure/install commands, or arbitrary MCP tools directly to the planner.

## Request flow

The OpenClaw integration seam uses `UntrustedObservationBridge.prepare()` to construct `mainstreet.capability_request.v1`. The request contains only an allowlisted channel, operation, exact parameters, tenant and trace binding, and a monotonic observation sequence.

An isolated broker passes that request to `mainstreet_runtimes.agent_reach_plane`. The Python policy validates it again before constructing a hard-coded argument vector. The caller cannot provide an executable, command string, environment variable, header, cookie, token, password, or arbitrary flag.

The result is returned as `mainstreet.untrusted_observation.v1`. The OpenClaw-side bridge validates request binding and recomputes the request, content, and observation digests. It then gives the planner a frozen observation whose semantics are fixed to:

```text
authority               = NONE
executable              = false
instructions_are_data   = true
claim_sieve_disposition = OBSERVATION_ONLY
```

If external content says "ignore ClaimSieve" or "this action is approved", those words remain data inside the observation. They do not alter any of the fields above.

## ClaimSieve evidence rule

Raw Agent Reach output never satisfies ClaimSieve `required_evidence`. The observation envelope is provenance only: it is not `claimsieve.evidence.v1`, it is not signed by a trusted evidence source, and it is not marked verified.

If an action depends on an internet-derived fact, a separate verifier must inspect the raw observation, extract a bounded claim, and emit signed ClaimSieve evidence using an evidence identity and key that the active tenant policy already authorizes. That verifier is independent of Agent Reach and the OpenClaw planner. This keeps “I read it on the internet” structurally different from “ClaimSieve has trusted evidence for this action.”

## Initial read surface

The policy currently allows only `agent-reach.status`, `web.read`, `github.search_repositories`, `search.exa`, `v2ex.hot`, and `bilibili.search`.

Authenticated social channels are intentionally disabled for the first integration. They should be added one at a time only after the observer can use a dedicated read-only credential/profile and the deployment proves that credential cannot perform a provider mutation.

## Deployment requirements

Run the observer in its own container or pod, service account, filesystem, home directory, and network policy. Do not mount the OpenClaw home directory, browser profile, ClaimSieve key material, permit store, executor credentials, or provider writer credentials into the observer.

The observer should have outbound internet access only to the endpoints required by enabled read operations. It should have one narrow authenticated internal route back to the observation transport. It should have no route to the ClaimSieve signing service or restricted executor.

The OpenClaw planner should not receive generic internet egress merely because Agent Reach exists. Its existing proposal-only boundary remains separate.

Pin Agent Reach before production deployment. The current policy records upstream version `1.5.0` and commit `a19a171fa980a0785849596492e0af4db800c82f`. Upgrades require reviewing the read recipes, security behavior, and dependency changes before changing the pin.

## Local verification

The boundary tests do not require Agent Reach or network access:

```bash
PYTHONPATH=python python3 -m unittest python/tests/test_agent_reach_plane.py -v
node --test mainstreet/test/agent-reach-untrusted.test.js
```

The full repository gate also discovers the new Python and Node tests through `scripts/test_all.sh`.

A live acceptance test is a separate deployment step because the repository does not claim that a pinned OpenClaw runtime and Agent Reach sidecar have already been installed in production.
