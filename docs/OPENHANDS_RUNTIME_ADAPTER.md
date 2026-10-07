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

The route-result envelope therefore sets `external_action_executed` to `false` at the adapter boundary. The callback used as `route_intent` must also return an explicit proposal-only receipt with `external_action_executed: false`; missing, ambiguous, or execution-positive receipts are rejected. This catches accidental composition with an execution-capable route, but it does not replace process separation or prove that a dishonest callback had no side effect.

## Reviewed action classification

This baseline deliberately treats capability access, not only external writes, as potentially consequential. A read can disclose credentials, customer data, source code, browser state, or other protected information to an untrusted runtime or model provider. A final user-visible response can also disclose protected data or make an operational claim. ClaimSieve therefore does not assume that "read only" or "final response" means "safe."

The reviewed consequential set includes:

- shell and terminal execution;
- MCP tool invocation;
- file viewing, search, and mutation;
- browser navigation, interaction, state/content access, and tab operations;
- skill invocation;
- subagent/task launch;
- model-profile switching;
- Canvas UI capability actions;
- child-conversation launch;
- user-visible `FinishAction` output.

The adapter recognizes both the legacy OpenHands action names and the generated SDK client action discriminators currently used for Canvas UI and child-conversation launch: `ClientAction_canvas_ui_control` and `ClientAction_launch_child_conversation`.

Only the explicitly internal `ThinkAction` and `TaskTrackerAction` are currently classified as non-consequential. Any other action kind fails closed.

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
4. A route callback cannot return an ambiguous or execution-positive receipt and still be accepted as proposal-only.
5. Mutable source arguments are copied before routing to prevent post-canonicalization mutation.
6. File reads are treated as consequential because confidentiality loss is an effect.
7. File writes and shell execution are consequential.
8. Model-profile switching and sensitive file discovery are consequential.
9. User-visible final output is consequential.
10. Current generated client-action discriminators are classified as consequential.
11. Explicitly internal thought operations stay outside the consequential route.
12. Unknown action kinds fail closed.
13. Malformed MCP payloads, missing tool-call identities, and invalid runtime sequence metadata are rejected.

## Nonblocking upstream drift lane

`.github/workflows/openhands-adapter.yml` contains two jobs.

`adapter-tests` is an ordinary test lane for ClaimSieve's own adapter code.

`upstream-contract` checks the pinned OpenHands source contract and preserves a JSON artifact. It is deliberately `continue-on-error: true` during this first baseline phase. A drift failure is evidence to investigate, not yet a merge blocker.

The contract probe validates the `ActionEvent` fields required by the adapter, every currently reviewed capability interface, the explicitly internal action kinds, the file-editor command contract, and the generated Canvas UI and child-conversation discriminator definitions. It does not prove OpenHands runtime safety and does not test a live OpenHands deployment.

## Promotion path

The next increment should not make OpenHands trusted. It should add an OpenHands-specific ClaimSieve intake principal that binds runtime identity and exact action semantics to the existing v0.33 authority path, followed by a live adversarial harness.

The intended maturity sequence is:

1. structural compatibility baseline;
2. proposal-only adapter tests;
3. runtime-principal and manifest binding;
4. exact capability, destination, data-access, outbound-content, and parameter binding for selected consequential actions;
5. replay and freshness tests;
6. live OpenHands adversarial scenarios with no ambient executor credentials;
7. preserved evidence and baseline metrics;
8. only then promote stable, high-confidence failures from nonblocking observation to merge-blocking ClaimSieve gates.

A green compatibility probe alone is not evidence that the full execution boundary is green.
