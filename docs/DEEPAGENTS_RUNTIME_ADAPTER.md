# Deep Agents Runtime Adapter — Experimental Branch

## Status

Experimental integration on `feat/deepagents-runtime-adapter`.

Target upstream package: `deepagents==0.7.9`.

The branch implements a reference proposal-to-permit composition, a guarded Deep Agents runtime configuration, and runtime identity binding through the Founder OS reference authority path. It does not claim production key isolation, live provider execution, durable runtime-intake recovery, cryptographic attestation of arbitrary caller-supplied Python middleware or benign tool implementations, or a completed Deep Agents versus OpenClaw benchmark.

## Security objective

Deep Agents is treated as an untrusted proposal runtime. It must not own:

- provider credentials;
- ClaimSieve permit-signing keys;
- executor keys;
- observer keys;
- authority to declare terminal external outcomes.

Consequential calls are intercepted before the underlying Deep Agents tool handler runs. The middleware converts the call into a canonical intent and routes it toward ClaimSieve instead of executing the provider tool.

The middleware response explicitly records:

```json
{
  "routed_to_claimsieve": true,
  "external_action_executed": false
}
```

A successful middleware return means routing succeeded. It does not mean the external action succeeded.

## Current reference path

```text
Deep Agents model
      |
      v
Deep Agents tool call
      |
      v
ClaimSieveDeepAgentsMiddleware
      |
      +---- classified benign tool -----------> normal Deep Agents handler
      |
      +---- classified consequential tool
                |
                v
        DeepAgentsProposalAdapter
                |
                v
      canonical consequential intent
                |
                v
       DeepAgentsFounderIntake
                |
                v
 existing Founder OS / ClaimSieve authority
                |
                v
       one-use permit pending
                |
          separate explicit step
                |
                v
       restricted executor
                |
                v
      independent observer
```

The intake call stops after permit issuance. Provider execution requires a separate explicit call to the existing executor path.

## Runtime identity binding now implemented

The Founder OS reference path now supports an exact runtime profile containing:

- runtime name;
- runtime version;
- runtime principal;
- runtime manifest digest;
- skills manifest digest;
- network profile digest.

For Deep Agents, that binding is carried into the proposal, matched against the proposal principal, matched against signed deployment evidence and the signed governance epoch, constrained by the policy principal allowlist, and preserved through permit issuance. The executor rechecks the exact approved proposal through the existing permit digest bindings, so post-approval runtime identity mutation is rejected.

The legacy OpenClaw reference path remains backward compatible when no explicit runtime profile is supplied.

This is reference-path runtime identity assurance. It is not a claim that the Python process, runtime package, deployment host, or arbitrary extension code is independently attested in production.

## Fail-closed runtime configuration

`create_claimsieve_deep_agent` is the guarded construction path for this experiment.

It currently enforces:

1. The main agent receives `ClaimSieveDeepAgentsMiddleware`.
2. Every raw subagent receives its own ClaimSieve middleware instance.
3. An explicit guarded `general-purpose` subagent is supplied so Deep Agents cannot auto-create its normal general-purpose subagent without the ClaimSieve middleware.
4. Compiled subagents are rejected because their internal graph is supplied as-is.
5. Remote async subagents are rejected because their enforcement boundary is outside this process.
6. Caller middleware cannot replace or shadow the ClaimSieve middleware name.
7. The backend is fixed to Deep Agents `StateBackend` rather than a caller-selected shell-capable sandbox backend.
8. Every caller-supplied tool must have a stable name and be classified as either consequential or explicitly benign.
9. A tool cannot be classified as both benign and consequential.
10. Unclassified tools fail closed.

The guarded factory is still a reference composition boundary. The Python composition root that constructs the adapter, supplies extra middleware, and marks tools benign is trusted configuration in this branch. Name-based benign classification does not prove a Python tool implementation is side-effect free, and arbitrary extension code is not cryptographically attested here. Production deployment must either remove those extension points from the untrusted surface or bind them to an independently verified runtime/tool manifest.

Deep Agents upstream documents that `StateBackend` has no process to execute into and no `execute` method. This is why the experimental governed factory fixes that backend rather than accepting a caller-selected shell backend.

## Upstream subagent finding

A top-level custom middleware entry is not sufficient by itself.

Deep Agents builds raw subagent middleware from each subagent specification. Its default general-purpose subagent only inherits caller middleware that replaces an existing default middleware slot by name. A newly named `ClaimSieveDeepAgentsMiddleware` therefore does not automatically propagate to that default subagent.

The governed factory closes this tested path by supplying an explicit guarded general-purpose subagent and adding the gate to every accepted raw subagent.

## Initial consequential tool set

- `create_github_issue`
- `send_email`
- `issue_refund`
- `update_crm_record`

The set is configurable and exact. This is not the entire production policy model; it is the initial reference set for runtime integration testing.

## Reference ClaimSieve intake

`DeepAgentsFounderIntake` accepts only:

- schema `mainstreet.consequential_tool_intent.v1`;
- runtime `deepagents`;
- pinned runtime version `0.7.9` through the bound Founder OS runtime profile;
- tool `create_github_issue`;
- exact arguments `repository`, `title`, and `body`;
- exact context fields `trace_id`, `campaign_id`, `session_id`, `work_item_id`, and `requested_at_seq`.

It rejects duplicate Deep Agents tool-call identities within the current intake process and rejects unexpected fields before they enter the authority path. It then uses the existing `FounderOSReferenceWorkflow.prepare_issue()` path to reach the existing ClaimSieve authority. The receipt is `PERMIT_ISSUED_EXECUTION_PENDING` and explicitly states `external_action_executed: false`.

The pending-permit and seen-tool-call registries in this adapter are in memory. Durable one-use permit enforcement remains in the existing ClaimSieve durable execution path, but process-restart recovery of the adapter's pending-intake registry is not implemented here. This intake is a reference composition, not a production service boundary.

## Tests

`python/tests/test_deepagents_adapter.py`

- canonicalizes consequential calls;
- deep-copies arguments before routing;
- rejects non-consequential calls at the adapter boundary;
- rejects missing tool-call identity;
- rejects invalid runtime sequence values;
- verifies custom consequential tool sets are exact.

`python/tests/test_deepagents_middleware.py`

- verifies the upstream `middleware` extension point exists;
- proves a consequential tool call does not reach the underlying handler;
- proves a benign tool still reaches the underlying handler;
- verifies the returned message does not claim external execution.

`python/tests/test_deepagents_claimsieve_intake.py`

- proves intent can reach the existing authority and stop with execution pending;
- proves provider execution requires a separate explicit step;
- proves Deep Agents policy, proposal, deployment evidence, and permit use the Deep Agents principal;
- rejects runtime substitution and wrong pinned runtime version;
- rejects post-approval runtime identity mutation at execution;
- rejects unexpected arguments;
- rejects duplicate tool-call identity within one intake process;
- rejects unknown permits and double execution start.

`python/tests/test_runtime_identity_kernel.py`

- allows a valid Deep Agents runtime identity and signed deployment binding;
- rejects a valid OpenClaw deployment certificate used with a Deep Agents proposal;
- rejects runtime-principal mismatch;
- preserves the legacy OpenClaw reference path.

`python/tests/test_deepagents_runtime.py`

- proves the explicit general-purpose subagent is guarded;
- proves raw subagents receive the ClaimSieve gate;
- rejects compiled and remote async subagents;
- rejects middleware shadowing by the ClaimSieve middleware name;
- rejects unclassified tools on main-agent and subagent paths;
- accepts explicitly configured benign tools and consequential tools;
- rejects contradictory benign/consequential classification;
- rejects caller-selected backends.

The Deep Agents-specific CI workflow installs the pinned upstream dependency. The base reference suite keeps Deep Agents optional so the existing ClaimSieve test environment does not gain an unnecessary runtime dependency.

## Remaining engineering before production use

1. Make runtime-intake replay identity and pending-permit recovery durable across process restarts.
2. Move adapter construction, middleware admission, and benign-tool admission behind a trusted composition root or independently verified manifest rather than treating names alone as semantic proof.
3. Bind the exact runtime package/build and approved tool implementations to deployment provenance suitable for the production environment.
4. Exercise direct-network, arbitrary-extension-code, credential-discovery, and host-boundary attacks in the deployed topology.
5. Run the same governed tasks through OpenClaw and Deep Agents and compare capability, latency, token use, failure recovery, deterministic trace quality, attack resistance, and runtime-specific code ownership.

## Attack matrix

Covered or partially covered in the branch:

- argument substitution after approval;
- destination substitution through existing permit bindings;
- stale approval reuse through existing authority checks;
- permit replay through existing durable execution checks;
- duplicate runtime tool-call identity within one intake process;
- compiled-subagent bypass;
- remote-subagent bypass;
- unclassified-tool injection by name;
- middleware name shadowing;
- caller-selected shell backend;
- unknown provider outcome;
- provider timeout after commit;
- observer contradiction through the existing execution path;
- runtime identity substitution;
- runtime version substitution;
- post-approval runtime identity mutation.

Still requiring stronger production-topology evidence:

- process-restart replay of runtime tool-call identity;
- malicious implementation hidden behind an approved benign tool name;
- arbitrary caller middleware with side effects;
- malicious or substituted adapter route callable;
- direct provider or generic network side effects from extension code;
- runtime package/build substitution outside the reference manifest model;
- credential discovery and host escape in the deployed runtime;
- independent host/process isolation of execution and observation.

## Architectural decision rule

MainStreet should depend on a runtime adapter interface, not on Deep Agents or OpenClaw directly.

```text
MainStreet product layer
        |
Runtime adapter interface
   /             \
Deep Agents     OpenClaw
   \             /
      ClaimSieve
          |
 restricted executor
          |
 independent observer
```

A proposal runtime may be replaced without changing the single ClaimSieve authority or execution model. That replaceability claim applies only when the replacement runtime is bound to an equivalent verified runtime profile and the execution boundary remains outside the proposal runtime.
