# OpenHands Runtime Adapter Baseline

## Status

This document describes the first ClaimSieve/OpenHands compatibility increment. It is intentionally narrow: OpenHands remains an untrusted proposal runtime and ClaimSieve remains the independent authority boundary.

The baseline is pinned to upstream repository `OpenHands/OpenHands` commit `ea7a85c27628a6abad4d5738527e5044b34b91ff` for the structural contract probe. The adapter itself consumes a mapping shaped like the OpenHands `ActionEvent` contract rather than importing OpenHands as a trusted dependency.

## Boundary

OpenHands may propose an action. The adapter may canonicalize a reviewed consequential action into `mainstreet.consequential_tool_intent.v1`. The adapter may then pass that proposal to a ClaimSieve intake function.

The adapter does not:

- execute OpenHands tools or shell commands;
- issue or sign ClaimSieve permits;
- own provider credentials, executor keys, or observer keys;
- treat OpenHands `security_risk`, critic output, thought text, or model reasoning as authorization;
- retry provider execution;
- declare an external action successful or failed.

The route-result envelope therefore sets `external_action_executed` to `false` at the adapter boundary.

## Reviewed action classification

The first baseline treats the following action kinds as consequential and therefore proposal-only:

- `ExecuteBashAction`
- `TerminalAction`
- `MCPToolAction`
- `TaskAction`
- `LaunchChildConversationAction`
- `BrowserNavigateAction`
- `BrowserClickAction`
- `BrowserTypeAction`

File editing is command-sensitive. `FileEditorAction`, `StrReplaceEditorAction`, and `PlanningFileEditorAction` are consequential for mutation commands and non-consequential for `view`.

A small set of observation/read-oriented action kinds is explicitly classified as non-consequential. Any action kind that has not been reviewed fails closed. This includes both future OpenHands additions and currently known kinds that have not yet been assigned a ClaimSieve side-effect class.

Failing closed is deliberate: an upstream feature addition must not silently acquire authority merely because OpenHands can represent or execute it.

## Fields deliberately excluded from authority

OpenHands `ActionEvent` includes information such as thought/reasoning content, a model-generated security-risk label, and optional critic output. Those fields are not copied into the ClaimSieve consequential intent.

The ClaimSieve proposal envelope is restricted to:

- runtime identity (`openhands`);
- tool-call identity;
- tool name;
- canonical action arguments;
- caller-supplied correlation context.

Correlation context is not a permit or approval.

## Adversarial tests in this increment

`python/tests/test_openhands_adapter.py` discriminates at least these failure modes:

1. MCP actions are routed without executing an external action.
2. OpenHands thought/reasoning and risk labels do not become ClaimSieve authority inputs.
3. A `LOW` upstream risk label cannot authorize execution.
4. Mutable source arguments are copied before routing to prevent post-canonicalization mutation.
5. File reads and file writes are separated.
6. Shell execution is always treated as consequential.
7. Unknown or unreviewed action kinds fail closed.
8. Malformed MCP payloads and missing tool-call identities are rejected.
9. Invalid runtime sequence metadata is rejected.

## Nonblocking upstream drift lane

`.github/workflows/openhands-adapter.yml` contains two jobs.

`adapter-tests` is an ordinary test lane for ClaimSieve's own adapter code.

`upstream-contract` checks the pinned OpenHands source contract and preserves a JSON artifact. It is deliberately `continue-on-error: true` during this first baseline phase. A drift failure is evidence to investigate, not yet a merge blocker.

The contract probe validates the presence of the `ActionEvent` fields required by the adapter, the reviewed action kinds, and the file-editor command contract. It does not prove OpenHands runtime safety and does not test a live OpenHands deployment.

## Promotion path

The next increment should not make OpenHands trusted. It should add an OpenHands-specific ClaimSieve intake principal that binds runtime identity and exact action semantics to the existing v0.33 authority path, followed by a live adversarial harness.

The intended maturity sequence is:

1. structural compatibility baseline;
2. proposal-only adapter tests;
3. runtime-principal and manifest binding;
4. exact destination and parameter binding for selected consequential actions;
5. replay and freshness tests;
6. live OpenHands adversarial scenarios with no ambient executor credentials;
7. preserved evidence and baseline metrics;
8. only then promote stable, high-confidence failures from nonblocking observation to merge-blocking ClaimSieve gates.

A green compatibility probe alone is not evidence that the full execution boundary is green.
