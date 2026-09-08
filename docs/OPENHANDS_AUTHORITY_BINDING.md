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

The OpenHands proposal adapter now emits `mainstreet.consequential_tool_intent.v2`.

The v2 envelope binds:

- runtime name;
- exact pinned runtime revision;
- exact OpenHands action discriminator;
- tool-call identity;
- tool name;
- deep-copied arguments;
- trace, campaign, session, work-item, and sequence correlation context.

OpenHands reasoning, `security_risk`, critic data, and other model-generated metadata are not authority inputs. The OpenHands intake rejects unexpected top-level fields rather than silently ignoring them.

## Runtime principal and manifest binding

`OpenHandsFounderIntake` requires a `FounderOSReferenceWorkflow` whose runtime profile is exactly:

`spiffe://mainstreet.local/tenant-founder/agent/openhands`

with the pinned OpenHands revision above.

The intake independently reconstructs the expected runtime profile and requires the full binding to match, including:

- runtime name;
- runtime version;
- principal;
- runtime manifest digest;
- skills manifest digest;
- network profile digest.

The prepared proposal must carry that same runtime identity. The issued permit must carry the same principal. The signed deployment certificate must identify the same runtime name, revision, principal, and manifest digest.

This means an OpenHands proposal cannot be admitted through this reference path after substituting a different runtime identity, runtime revision, or reviewed capability.

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
13. an unpinned OpenHands runtime profile backing the intake.

The harness writes a JSON evidence report and exits nonzero if any tested bypass survives.

## CI promotion strategy

`.github/workflows/openhands-authority.yml` separates two lanes:

- `authority-tests` is intended to be blocking once GitHub Actions is executing normally;
- `adversarial-baseline` is initially nonblocking and preserves its JSON report as an artifact.

A failure class should only move from observation to a merge-blocking gate after it is stable, discriminating, reproducible, and its false-positive behavior is understood.

## What this does not prove

This increment is still a local reference composition. It does not prove:

- that a deployed OpenHands process has no ambient cloud, GitHub, shell, or model-provider credentials;
- that process isolation, network egress confinement, or secret custody is correctly deployed;
- that every OpenHands capability has a ClaimSieve policy mapping;
- that replay protection survives process restart;
- that a live OpenHands agent cannot exploit a deployment mechanism outside the mediated adapter;
- that the full execution boundary is green.

The next deployment-level increment should run a pinned OpenHands process in an isolated environment with no executor credentials, allow egress only to the ClaimSieve intake, and attempt the same adversarial cases against a restricted executor and independent observer.
