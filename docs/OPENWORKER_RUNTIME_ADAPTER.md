# OpenWorker Runtime Adapter

## Status

Experimental reference integration. OpenWorker remains an untrusted proposal runtime and is not a ClaimSieve authority, executor, observer, or trust root.

Pinned upstream reference commit:

`86c57f0692a5a318e55d1b9e0188d798b9fc5690`

OpenWorker currently reports package version `0.0.0`, so this integration pins an upstream commit rather than treating that package version as a stable compatibility identifier.

## Boundary

The first integration deliberately does not patch or import OpenWorker internal tool-call classes. MainStreet owns a small normalized boundary:

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

The adapter accepts only the exact four fields above, classifies only an explicitly configured consequential-tool set, defensively copies arguments, and emits the existing `mainstreet.consequential_tool_intent.v1` envelope with `runtime = openworker`.

The OpenWorker intake then validates the exact intent shape and routes the request into the existing Founder OS to ClaimSieve authority path.

## Authority invariants

1. OpenWorker cannot issue a ClaimSieve permit.
2. OpenWorker cannot execute a consequential provider action through this adapter.
3. A successful route stops at `PERMIT_ISSUED_EXECUTION_PENDING`.
4. Execution requires a separate explicit `execute_pending` call.
5. The runtime principal is exactly `spiffe://mainstreet.local/{tenant}/agent/openworker`.
6. Runtime identity and the pinned upstream commit are bound into policy, proposal, permit, and signed deployment evidence through the existing Founder OS runtime profile.
7. Runtime identity mutation after permit issuance invalidates execution.
8. Unknown boundary and intent fields fail closed rather than being ignored.
9. Duplicate tool-call identities fail closed, including concurrent same-process admission.
10. Existing restricted executor and independent observer semantics remain unchanged.

## Deliberate non-goals

This increment does not claim direct compatibility with every OpenWorker internal API. It does not install OpenWorker as a dependency, start its server, grant it provider credentials, replace its permission engine, import its approval decisions, or treat OpenWorker audit records as ClaimSieve evidence.

It also does not solve restart-durable adapter replay state, deployed host isolation, connector credential topology, network sandboxing, upstream package provenance, or direct OpenWorker-to-MainStreet IPC. Those require separate design and adversarial testing.

## Why a normalized boundary

OpenWorker is an actively changing upstream project. Importing private internal classes directly into the ClaimSieve trust boundary would couple authorization semantics to upstream refactors. The normalized boundary gives us a stable choke point where OpenWorker integration code can change while ClaimSieve continues to receive the same small, closed proposal envelope.

A future native bridge should translate OpenWorker's then-current tool invocation object into this boundary outside the ClaimSieve authority process and should be pinned and tested against an exact upstream commit.

## Tests

- `python/tests/test_openworker_adapter.py`
- `python/tests/test_openworker_claimsieve_intake.py`

The tests cover proposal-only routing, closed schemas, defensive copying, runtime substitution, exact runtime pinning, permit/execution separation, signed runtime identity binding, duplicate and concurrent duplicate admission, field smuggling, and post-permit runtime mutation.
