# OpenWorker Runtime Adapter

## Status

Experimental reference integration. OpenWorker remains an untrusted proposal runtime and is not a ClaimSieve authority, executor, observer, or trust root.

Pinned upstream reference commit:

`86c57f0692a5a318e55d1b9e0188d798b9fc5690`

OpenWorker currently reports package version `0.0.0`, so compatibility is bound to the exact upstream Git commit. The dedicated OpenWorker CI gate installs that Git revision directly and verifies its PEP 610 `direct_url.json` commit provenance before native integration tests run.

## Stable boundary

MainStreet owns a small normalized boundary:

```json
{
  "schema_version": "mainstreet.openworker_tool_call.v1",
  "id": "opaque-call-id",
  "name": "create_github_issue",
  "arguments": {
    "repository": "owner/repository",
    "title": "title",
    "body": "body"
  }
}
```

The adapter accepts only the exact four fields above, classifies an explicitly configured consequential-tool set, defensively copies arguments, and emits the existing `mainstreet.consequential_tool_intent.v1` envelope with `runtime = openworker`.

The OpenWorker intake validates the exact intent shape and routes the request into the existing Founder OS to ClaimSieve authority path.

## Native OpenWorker bridge

At the pinned commit, OpenWorker represents a model-requested invocation as `coworker.providers.base.ToolCall(id, name, arguments)`. Its `TurnEngine` authorizes those calls and ultimately dispatches them through `_execute_sync`, which normally invokes `ToolRegistry.execute(name, arguments)`.

`python/mainstreet_runtimes/openworker_native_bridge.py` creates a pinned guarded `TurnEngine` subclass outside the ClaimSieve authority kernel. It verifies the installed Git provenance and the exact native `ToolCall` and `_execute_sync` API seam before initialization.

For an explicitly mapped consequential call, the guarded execution seam:

1. receives the real OpenWorker `ToolCall`;
2. defensively translates it into `mainstreet.openworker_tool_call.v1`;
3. routes it through the existing OpenWorker proposal adapter and ClaimSieve intake;
4. returns the ClaimSieve route receipt to OpenWorker; and
5. never calls the native registry function for that consequential action.

A successful native route therefore stops at `PERMIT_ISSUED_EXECUTION_PENDING`. Provider execution still requires the existing separate ClaimSieve execution step.

The guard also fails closed for any unmapped tool that OpenWorker's base risk model treats as consequential, and for all native tools categorized as `connector` or `mcp`. MainStreet deliberately ignores user-local OpenWorker risk downgrades when deciding whether native execution may fall through. An OpenWorker permission preference may affect its own user experience; it cannot downgrade the MainStreet execution boundary.

Pure local, unmapped, non-consequential tools retain normal OpenWorker registry execution.

## Authority invariants

1. OpenWorker cannot issue a ClaimSieve permit.
2. OpenWorker cannot execute a mapped consequential provider action through the guarded runtime.
3. A successful route stops at `PERMIT_ISSUED_EXECUTION_PENDING`.
4. Execution requires a separate explicit `execute_pending` call.
5. The runtime principal is exactly `spiffe://mainstreet.local/{tenant}/agent/openworker`.
6. Runtime identity and the pinned upstream commit are bound into policy, proposal, permit, and signed deployment evidence through the existing Founder OS runtime profile.
7. Runtime identity mutation after permit issuance invalidates execution.
8. Unknown boundary and intent fields fail closed rather than being ignored.
9. Duplicate tool-call identities fail closed, including concurrent same-process admission.
10. Replaying the same OpenWorker call after an OpenWorker approval cannot create a second ClaimSieve admission.
11. Unknown consequential connector, plug-in, and MCP tool names cannot fall through to native execution merely because they were not mapped yet.
12. Existing restricted executor and independent observer semantics remain unchanged.

## Adversarial coverage

The native CI tests exercise:

- exact Git commit provenance and API-seam drift detection;
- a real OpenWorker `ToolCall` passing through the guarded `TurnEngine`;
- direct connector interception before the registered native provider function executes;
- OpenWorker human approval without provider execution or ClaimSieve authority substitution;
- approval replay using the same OpenWorker tool-call identity;
- field substitution after capture/admission;
- a real OpenWorker MCP wrapper created by `coworker.mcp.tools.build_callables`, proving its remote async callable is not reached when mapped to a governed consequential action;
- unmapped MCP execution with OpenWorker-side approval disabled, which still fails closed at the MainStreet guard;
- unmapped connector and third-party approval-required plug-in aliases, which fail closed rather than reaching `ToolRegistry.execute`;
- benign unmapped local-tool fallthrough, proving the guard does not indiscriminately disable the runtime; and
- runtime drift, which prevents the guarded engine from being created.

## Deliberate non-goals and remaining boundaries

This increment does not start the full OpenWorker desktop/server product, grant OpenWorker unrestricted provider credentials, replace its permission engine, import its approval decisions as ClaimSieve evidence, or treat OpenWorker audit records as ClaimSieve authority.

The native bridge currently relies on a pinned OpenWorker internal execution seam. This is intentional and guarded by exact provenance plus API fingerprint tests, but it remains an integration maintenance boundary rather than a stable upstream public API.

Restart-durable adapter replay state remains future work. The intake's seen-tool-call and pending-permit registries are process-local even though lower-level ClaimSieve execution durability is stronger.

Deployed-process isolation, operating-system sandboxing, connector credential topology, network policy, live OpenWorker server IPC, package-signature/SBOM policy, and compromise of the OpenWorker host itself are not established by these reference tests. MCP tests prove that a governed tool invocation cannot reach its wrapped remote callable through this composition; they do not prove that an independently reachable MCP process or network credential is impossible in a production host topology.

## Why a normalized boundary

OpenWorker is an actively changing upstream project. Its native bridge is allowed to change with the pinned runtime, but ClaimSieve continues to receive the same small, closed proposal envelope. This keeps upstream runtime churn outside the ClaimSieve authority semantics.

## Tests and CI

- `python/tests/test_openworker_adapter.py`
- `python/tests/test_openworker_claimsieve_intake.py`
- `python/tests/test_openworker_native_runtime.py`
- `python/tests/test_openworker_native_fail_closed.py`
- `.github/workflows/openworker-adapter.yml`

The ordinary Reference workflow does not install OpenWorker; native tests are skipped there. The dedicated OpenWorker Adapter workflow installs the exact pinned Git commit, verifies its provenance and API seam, then runs all `test_openworker_*.py` tests. The normal Rust, Rocq, Deep Agents, Reference, and Full Assurance workflows remain independent regression gates.
