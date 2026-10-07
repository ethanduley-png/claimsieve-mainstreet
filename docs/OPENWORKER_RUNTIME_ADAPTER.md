# OpenWorker Runtime Adapter

## Status

Production-oriented integration under active validation. OpenWorker remains an untrusted proposal runtime. It is not a ClaimSieve authority, permit issuer, provider executor, observer, or trust root.

Pinned upstream identities:

- OpenWorker: `86c57f0692a5a318e55d1b9e0188d798b9fc5690`
- aisuite: `1b4bbf303ec21968230b1ec869a144d054e9b3c4`
- Python: `3.11.16`

The complete Python dependency graph is frozen in `python/requirements-openworker.lock.txt`. The OpenWorker gate requires an exact `pip freeze` match, `pip check`, and PEP 610 Git provenance for both VCS packages.

## Consequential-action boundary

At the pinned commit, OpenWorker represents model-requested calls as `coworker.providers.base.ToolCall` and primary engines are constructed through `coworker.agent.build_engine`.

MainStreet binds that primary constructor to a guarded `TurnEngine` after verifying the pinned upstream API seam. The native GitHub connector name `github_create_issue` maps to ClaimSieve's canonical `create_github_issue` intent.

A governed call follows this path:

1. OpenWorker produces a native `ToolCall`.
2. The guard converts it to the closed `mainstreet.openworker_tool_call.v1` boundary.
3. The adapter emits `mainstreet.consequential_tool_intent.v1` with `runtime = openworker`.
4. ClaimSieve evaluates the request and may issue a permit.
5. The OpenWorker path stops at `PERMIT_ISSUED_EXECUTION_PENDING`.
6. Provider execution remains a separate ClaimSieve-controlled step.

Mapped consequential calls never execute through the native OpenWorker registry. Unmapped connector and MCP tools, and tools OpenWorker's base risk model classifies as consequential, fail closed. User-local OpenWorker risk downgrades cannot weaken this boundary.

OpenWorker's separate `explore` child engine is not rebound at this pin because its registry is limited to read/search/git tooling and it runs under `Mode.PLAN`. Any upstream change to that assumption must be reviewed before moving the pin.

## Restart and replay durability

The intake boundary uses a transactional SQLite journal with WAL and `synchronous=FULL`.

Tool-call identity is durably reserved before permit preparation. Pending prepared actions are integrity-bound before storage. Execution is durably reserved before entering the provider boundary. If the process crashes after execution reservation, automatic retry remains blocked because the external result may be indeterminate.

Tests cover replay after restart, pending permit recovery, crash-after-reservation, persisted-action tampering, concurrent duplicate admission, and multiple intake instances sharing the same durable replay boundary.

Production session context is also durable. Real OpenWorker session identities receive distinct ClaimSieve contexts and a monotonic sequence allocator survives restart.

## Production server composition

The supported server entrypoint is:

`python -m mainstreet_runtimes.openworker_production_server`

Do not deploy the upstream `openworker-server` entrypoint directly.

Before upstream `SessionManager` is instantiated, production boot:

- verifies the exact OpenWorker Git pin;
- replaces its imported file/environment-backed `SecretStore` constructor with `NoCredentialSecretStore`;
- injects `MainStreetOpenWorkerModelGatewayProvider` instead of a vendor `ProviderRouter`;
- creates durable per-session ClaimSieve context;
- installs the guarded primary engine constructor; and
- requires a valid OpenWorker API token before FastAPI app construction.

The API token is read from `/var/run/mainstreet/mtls/openworker.token`, exposed to upstream only while `create_app` snapshots it, and then removed from the process environment before uvicorn starts. Calling `build_production_app` without a valid token also fails closed.

`NoCredentialSecretStore` reports no credential profiles, exposes no secret path, and refuses credential resolution, persistence, or deletion. OpenWorker therefore does not own provider or connector credentials in this topology.

## Model boundary

OpenWorker model traffic uses `MainStreetOpenWorkerModelGatewayProvider`, a native OpenWorker `ProviderClient` implementation.

Its only endpoint is:

`https://model-gateway.mainstreet-system.svc.cluster.local:8443/v1/runtime/openworker/completions`

The client requires TLS 1.3 mutual authentication and hostname validation. It rejects alternate endpoints, redirects, fallback, provider/API-key/header routing settings, malformed JSON, duplicate tool-call identities, invalid usage values, and non-closed response shapes.

Until the model gateway exposes a separately authenticated capability contract, the adapter advertises only the required tool capability. Vision, native PDF ingestion, parallel tool calls, and streaming remain disabled.

## ClaimSieve IPC

Consequential intents use a separate fixed TLS 1.3 mutual-authentication endpoint:

`https://claimsieve-intake.mainstreet-system.svc.cluster.local:8443/v1/runtime/openworker/intents`

The client and server enforce fixed endpoint identity, bounded closed JSON, duplicate-key rejection, no redirects/fallback, and maximum request/receipt sizes. The server derives the OpenWorker SPIFFE identity from the verified client certificate URI SAN; caller identity is never trusted from the request body or an HTTP identity header.

## Kubernetes isolation contract

`deploy/openworker/kubernetes.json` is a release template, not a directly deployable release artifact. Its image placeholder is explicitly rejected by production validation.

The template requires:

- UID, GID, and fsGroup `65532`;
- non-root execution;
- read-only root filesystem;
- all Linux capabilities dropped;
- `RuntimeDefault` seccomp;
- no service-account token;
- no host network, PID, IPC, or host-path mounts;
- an exact MainStreet production command, arguments, environment allowlist, mounts, and health probes;
- default-deny ingress and egress;
- application egress only to ClaimSieve intake and the model gateway over TCP 8443;
- constrained DNS egress; and
- exactly one read-only workload-identity Secret.

The workload identity Secret uses mode `0440` for the fixed fsGroup and exposes exactly four named files: `ca.crt`, `tls.crt`, `tls.key`, and `openworker.token`. Extra Secret keys are not mounted.

The reference manifest deliberately has no application ingress allow rule. External exposure must be added only after the owning MainStreet control-plane/gateway identity is defined and reviewed.

## Image and release provenance

The production image is built from `deploy/openworker/Dockerfile`.

The workflow first resolves `python:3.11.16-slim` to an immutable digest. Git and build tooling exist only in a throwaway wheel-builder stage. The final runtime installs the frozen wheel set without network package resolution, copies MainStreet code, runs as `65532:65532`, and contains no Git binary.

OCI labels bind the repository commit, OpenWorker commit, and aisuite commit.

The release image repository is fixed to:

`ghcr.io/ethanduley-png/claimsieve-openworker`

The deployment renderer and release record bind that exact repository plus the produced image digest. A digest from another repository cannot satisfy release verification.

The PR image gate builds the real image and verifies user identity, provenance labels, absence of Git, importability of the production entrypoint, and a Trivy gate for known fixable HIGH/CRITICAL operating-system and Python-library vulnerabilities.

The manual production release workflow repeats source tests and provenance verification, pushes the image, requires its content digest, emits BuildKit SBOM and maximum provenance, repeats the vulnerability gate, renders the digest-pinned Kubernetes release, verifies the closed release record, publishes GitHub build provenance attestation, and archives release evidence with checksums.

## Authority invariants

1. OpenWorker cannot issue a ClaimSieve permit.
2. OpenWorker cannot execute a governed consequential provider action through its native registry.
3. A successful proposal route stops before provider execution.
4. Execution remains a separate explicit ClaimSieve-controlled operation.
5. Replay state and pending permits survive process restart.
6. Crash after execution reservation does not permit automatic retry.
7. Runtime identity and version are bound into ClaimSieve evidence.
8. Runtime identity mutation after permit issuance invalidates execution.
9. Unknown fields, duplicate identities, and unsupported runtime versions fail closed.
10. OpenWorker has no vendor/provider/connector credential authority in the supported production server.
11. Production model and ClaimSieve egress use separate fixed mTLS endpoints.
12. Existing ClaimSieve executor, observer, Rust semantics, Rocq proof bodies, and trust roots remain unchanged.

## Validation

The dedicated OpenWorker workflow runs all `python/tests/test_openworker_*.py` tests and builds/scans the actual production image. Reference, Deep Agents, Rust, Rocq, and Full Assurance workflows remain independent regression gates.

An earlier hardening head passed the native OpenWorker suite and exact dependency/provenance checks. The current production-oriented head contains additional server, credential, IPC, deployment, image, vulnerability, and release hardening and must pass again before merge.

At the time of this update GitHub Actions jobs are failing before runner allocation (`steps: null`), so the current head is not yet CI-validated. Keep PR #9 in draft until the exact head receives runners and all required matrices are green.

## Remaining deployment responsibilities

This adapter does not implement the separate production certificate issuer/rotation system, the deployed ClaimSieve intake service, or the model gateway's vendor credential store. Those are independent trusted services and must be deployed and reviewed separately.

The adapter also does not claim resistance to compromise of the entire Kubernetes node or cluster control plane. Its purpose is to keep an untrusted or compromised OpenWorker runtime from becoming its own consequential-action authority within the defined deployment boundary.
