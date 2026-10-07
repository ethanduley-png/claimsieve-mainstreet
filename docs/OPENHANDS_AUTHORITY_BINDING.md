# OpenHands Authority Binding Increment

## Scope

This increment binds one pinned OpenHands capability to the existing ClaimSieve v0.33 authority path. It does not make OpenHands trusted and it does not give OpenHands provider credentials.

The selected path is intentionally narrow:

- runtime: `openhands`
- pinned upstream revision: `ea7a85c27628a6abad4d5738527e5044b34b91ff`
- OpenHands action discriminator: `MCPToolAction`
- tool name: `create_github_issue`
- exact arguments: `repository`, `title`, `body`

All other OpenHands capabilities remain outside this authority intake.

## Intent v2

The OpenHands proposal adapter emits `mainstreet.consequential_tool_intent.v2`.

The v2 envelope carries:

- expected runtime name;
- expected pinned runtime revision;
- exact OpenHands action discriminator;
- tool-call identity;
- tool name;
- deep-copied arguments;
- trace, campaign, session, work-item, and sequence correlation context.

OpenHands reasoning, `security_risk`, critic data, and other model-generated metadata are not authority inputs. The OpenHands intake rejects unexpected top-level fields rather than silently ignoring them.

The runtime name and revision inside this proposal envelope are binding inputs, not authentication. A proposal-controlled field cannot prove which workload sent the request. The separate transport identity model is documented in `OPENHANDS_TRANSPORT_IDENTITY.md`.

## Runtime principal and profile binding

`OpenHandsFounderIntake` requires a `FounderOSReferenceWorkflow` whose configured runtime profile is exactly:

`spiffe://mainstreet.local/tenant-founder/agent/openhands`

with the pinned OpenHands revision above.

The intake independently reconstructs the expected reference profile and requires the full binding to match, including:

- runtime name;
- runtime version;
- principal;
- runtime profile digest;
- skills profile digest;
- network profile digest.

The prepared proposal must carry that same runtime identity. The issued permit must carry the same principal. The signed deployment certificate must identify the same configured runtime name, revision, principal, and reference-profile digest.

This closes substitution inside the reference composition: a proposal cannot be admitted through this path after changing the runtime identity, runtime revision, or reviewed capability.

It does **not** prove that the bytes of a live OpenHands process match the pinned revision. The current `runtime_manifest_digest` is a canonical digest of ClaimSieve reference runtime metadata, not a complete binary, container-image, filesystem, or measured-boot hash. Deployment-level artifact identity remains a separate requirement.

## Out-of-band authenticated route model

`AuthenticatedRuntimeBinding` and `OpenHandsAuthenticatedRoute` model the additional property the live deployment needs: caller identity supplied independently of the OpenHands proposal payload.

The route is constructed only when the authenticated binding exactly matches the independently configured ClaimSieve runtime profile. Principal or manifest substitution in that out-of-band binding is rejected before proposal admission.

This is a reference model, not an implementation of mutual Transport Layer Security, SPIFFE workload identity, or measured attestation. Production must populate the equivalent binding from infrastructure the OpenHands process cannot forge.

## Exact effect binding

For the selected GitHub issue capability, the existing ClaimSieve authority path continues to bind the approved effect to exact digests for:

- proposal;
- action;
- destination;
- parameters.

The executor therefore rejects post-approval mutation of the repository destination, issue title/body parameters, or runtime identity.

## Replay and execution separation

A successful intake returns `PERMIT_ISSUED_EXECUTION_PENDING` and `external_action_executed: false`.

Provider execution requires a separate explicit `execute_pending` call. The proposal adapter also rejects route receipts unless the ClaimSieve callback explicitly states `external_action_executed: false`.

Tool-call identities are tracked under a same-process lock so duplicate or concurrent duplicate admissions are rejected. This state is not restart-durable and is not presented as a production replay solution.

## Adversarial baseline

`scripts/run_openhands_boundary_red_team.py` exercises the following tested bypass classes:

1. execution occurring during proposal routing;
2. runtime revision substitution;
3. action-capability substitution;
4. tool-name substitution;
5. authority-metadata injection;
6. unexpected argument injection;
7. tool-call replay;
8. post-permit destination mutation;
9. post-permit parameter mutation;
10. post-permit runtime-identity mutation;
11. unknown pending permit execution;
12. execution-positive route receipts;
13. an unpinned OpenHands runtime profile backing the intake;
14. authenticated-principal substitution;
15. authenticated reference-manifest substitution.

The harness records unexpected exception classes as failed test cases instead of aborting before writing evidence. It writes a JSON report and exits nonzero if any tested bypass survives or fails in an unexpected way.

## CI promotion strategy

`.github/workflows/openhands-authority.yml` separates two lanes:

- `authority-tests` is intended to be blocking once GitHub Actions is executing normally;
- `adversarial-baseline` is initially nonblocking and preserves its JSON report as an artifact.

A failure class should only move from observation to a merge-blocking gate after it is stable, discriminating, reproducible, and its false-positive behavior is understood.

## What this does not prove

This increment is still a local reference composition. It does not prove:

- that a deployed OpenHands process is cryptographically or attestationally the pinned upstream revision;
- that a deployed OpenHands process has no ambient cloud, GitHub, shell, or model-provider credentials;
- that process isolation, network egress confinement, or secret custody is correctly deployed;
- that every OpenHands capability has a ClaimSieve policy mapping;
- that replay protection survives process restart;
- that a live OpenHands agent cannot exploit a deployment mechanism outside the mediated adapter;
- that the full execution boundary is green.

The next deployment-level increment should run a pinned OpenHands workload in an isolated environment with independently established workload/artifact identity, no executor credentials, egress constrained to ClaimSieve intake and approved read channels, a restricted executor holding consequential provider credentials, and an independent observer.
