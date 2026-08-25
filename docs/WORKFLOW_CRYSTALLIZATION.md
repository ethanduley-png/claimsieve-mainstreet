# MainStreet Workflow Crystallization v1

Status: candidate implementation

## Goal

MainStreet should use model reasoning for work that is genuinely ambiguous, novel, or judgment-heavy. When the same bounded workflow repeats with stable inputs, stable action shape, stable policy, and confirmed outcomes, the system should be able to replace that repeated agent reasoning with deterministic code.

The deterministic workflow is not a new authority path.

It can only build a proposal. Consequential actions still require the normal ClaimSieve adjudication, permit, restricted executor, independent observation, and evidence path.

## Lifecycle

```text
agent performs bounded work
        |
        v
signed/traceable action history
        |
        v
eligible trace filter
        |
        v
pattern/binding discovery
        |
        v
workflow candidate
        |
        +----> historical replay
        |
        +----> generated deterministic proposal code
        |
        v
shadow comparison
        |
        v
promotion gate
        |
        v
human/operator deployment decision
        |
        v
deterministic proposal builder
        |
        v
ClaimSieve
        |
        v
restricted executor + independent observer
```

## v1 eligibility

A trace may contribute to automatic crystallization only when:

1. ClaimSieve allowed the action.
2. Independent reconciliation ended in `CONFIRMED_SUCCESS`.
3. The trace is not financial, legal/compliance, employment, health/safety, credential/security, or irreversible/high-impact work.
4. Every trace in the learning set represents the same capability and risk class.
5. Every trace was evaluated under the same policy digest.
6. The proposed action has the same structural shape.
7. Every field that varies across actions can be deterministically bound to an input fact.

Denied actions, review-only actions, unknown outcomes, confirmed failures, and divergent effects cannot become positive training authority.

Unknown risk-class strings also fail closed. A misspelled or unrecognized risk class cannot silently fall into the lower-risk automatic crystallization path.

## Binding rule

Crystallization does not copy one historical action and generalize from it.

For every leaf field in the action:

- if that field is demonstrably equal to a named runtime input fact across the learning set, it becomes a dynamic binding;
- otherwise, if it is constant across the learning set, it becomes a constant;
- otherwise the candidate fails closed.

Input-to-action relationships are preferred over constants. This prevents a value that happened to be constant during learning, such as a message body, from being accidentally frozen when it actually comes from runtime input.

## Candidate identity

The candidate identifier is a SHA-256 binding over the candidate's material contract: capability, risk class, required policy digest, field bindings, required facts, support count, learning-dataset digest, ClaimSieve requirement, and autonomous-deployment prohibition.

Candidate validation recomputes this identity. A caller cannot alter a binding, policy, or authority field while retaining the original candidate identifier.

## Generated code

`render_python_module` emits a pure proposal-building module. The generated code:

- performs no network calls;
- imports no provider SDK;
- accesses no credentials;
- checks the required policy digest;
- checks required runtime facts;
- deterministically constructs the action;
- returns `requires_claimsieve=True`;
- returns `autonomous_execution_allowed=False`.

This is the first code-generation boundary. It intentionally replaces agent reasoning, not ClaimSieve authority or the restricted executor.

## Shadow gate

A candidate can be considered promotable only after shadow evaluation.

The v1 gate requires:

- enough shadow cases;
- no safety violations;
- no action divergences;
- agreement at or above the configured threshold;
- ClaimSieve still required;
- autonomous deployment still forbidden.

A changed policy is a safety violation, not a normal mismatch.

## High-risk boundary

v1 refuses automatic crystallization for:

- financial actions;
- legal/compliance submissions;
- employment decisions;
- health/safety actions;
- credential/security changes;
- irreversible high-impact actions.

This does not mean deterministic implementations can never exist for those domains. It means they require a separately designed and reviewed assurance profile rather than inheriting trust from repeated agent behavior.

## Tests

`python/tests/test_workflow_crystallization.py` covers:

- stable repeated workflows;
- dynamic input-to-action binding;
- fields that vary without a deterministic source;
- denied, unknown, failed, and divergent traces;
- high-risk exclusions, including health/safety;
- unknown risk-class rejection;
- candidate identity tamper detection;
- policy drift;
- runtime policy mismatch;
- missing runtime facts;
- exact shadow agreement;
- shadow divergence;
- shadow policy change;
- generated deterministic Python equivalence and proposal-only behavior.

The normal repository Python discovery gate executes this test module automatically.

## Next hardening steps

1. Bind candidates to signed trace/evidence bundles rather than in-memory trace objects.
2. Add schema files for the candidate, shadow report, and promotion decision.
3. Add temporal and numeric predicates so the candidate can express rules such as elapsed time, amount bounds, consent state, and business-hour windows.
4. Add negative examples and counterfactual replay so a workflow proves when it must *not* fire.
5. Add explicit human approval receipts for production promotion.
6. Store deployed workflow source hashes and bind them into ClaimSieve deployment/governance evidence.
7. Add rollback, drift detection, and automatic return-to-agent behavior when the deterministic workflow encounters out-of-domain inputs.
8. Measure token, latency, energy, carbon, and water savings produced by crystallized workflows.

## Claim discipline

This implementation demonstrates deterministic candidate synthesis and shadow gating for the covered in-memory trace model.

It does not establish that arbitrary agent workflows can be safely compiled, that generated source code is secure in all environments, or that production deployment can occur without additional signing, provenance, sandboxing, and operational controls.
