# MainStreet Workflow Crystallization v1

Status: candidate implementation + signed-evidence assurance hardening

## Goal

MainStreet should use model reasoning for work that is genuinely ambiguous, novel, or judgment-heavy. When the same bounded workflow repeats with stable inputs, stable action shape, stable policy, and confirmed outcomes, the system should be able to replace that repeated agent reasoning with deterministic code.

The deterministic workflow is not a new authority path.

It can only build a proposal. Consequential actions still require the normal ClaimSieve adjudication, permit, restricted executor, independent observation, and evidence path.

## Lifecycle

```text
agent performs bounded work
        |
        v
authenticated execution traces
        |
        v
positive + negative evidence filter
        |
        v
pattern/binding + safe-guard discovery
        |
        v
workflow candidate + hardened profile
        |
        +----> historical/shadow replay
        |
        +----> generated deterministic proposal code
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
        +----> drift / envelope mismatch ----> agent fallback
        |
        v
ClaimSieve
        |
        v
restricted executor + independent observer
```

## v1 eligibility

A positive trace may contribute to automatic crystallization only when:

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

This replaces repeated agent reasoning, not ClaimSieve authority or the restricted executor.

## Shadow gate

A candidate can be considered promotable only after shadow evaluation.

The v1 gate requires enough shadow cases, no safety violations, no action divergences, agreement at or above the configured threshold, ClaimSieve still required, and autonomous deployment still forbidden.

A changed policy is a safety violation, not a normal mismatch.

## High-risk boundary

v1 refuses automatic crystallization for financial actions, legal/compliance submissions, employment decisions, health/safety actions, credential/security changes, and irreversible high-impact actions.

This does not mean deterministic implementations can never exist for those domains. It means they require a separately designed and reviewed assurance profile rather than inheriting trust from repeated agent behavior.

## Signed-evidence assurance hardening

`python/mainstreet_crystallization/assurance.py` adds the next layer:

- `SignedAgentTrace` seals trace payloads with the existing domain-separated Ed25519 ClaimSieve primitive;
- signer public keys must be explicitly allowlisted;
- signed datasets, positive evidence, and negative evidence receive canonical SHA-256 digests;
- hardened learning requires negative/counterfactual examples as well as confirmed successes;
- safe-input guards are inferred only when positive examples are stable and negative examples demonstrate the boundary;
- any negative example that the learned guards cannot explain causes hardened crystallization to fail closed;
- the hardened workflow identity binds the candidate, guards, evidence digests, signer IDs, support counts, ClaimSieve requirement, and autonomous-execution prohibition;
- policy drift, guard mismatch, missing runtime facts, or a tripped monitor returns `AGENT_FALLBACK` with no deterministic proposal;
- in-envelope denial/review, unknown/divergent outcomes, invalid signed evidence, capability/risk/policy drift, or excessive confirmed failures/action divergence trip the runtime monitor;
- once tripped, the deterministic route does not automatically recover.

Outside-envelope cases are expected to use the agent path and do not poison the deterministic behavioral monitor.

See `docs/WORKFLOW_CRYSTALLIZATION_ASSURANCE.md` for the complete assurance semantics and limitation statement.

## Tests

The crystallization implementation now has two focused suites:

- `python/tests/test_workflow_crystallization.py`: 13 baseline synthesis, identity, shadow, high-risk, and generated-code tests.
- `python/tests/test_workflow_crystallization_assurance.py`: 14 signed-evidence, counterfactual, guard, tamper, drift, and fallback tests.

The normal repository Python discovery gate executes both automatically.

## Remaining hardening steps

1. Add schema files for candidates, hardened profiles, shadow reports, and promotion decisions.
2. Add richer temporal and numeric predicates for elapsed time, amount bounds, consent freshness, and business-hour windows.
3. Split trace authentication into separate cryptographic attestations for the ClaimSieve adjudication record and the independently observed terminal outcome.
4. Add explicit signed human approval receipts for production promotion.
5. Store deployed workflow source hashes and bind them into ClaimSieve deployment/governance evidence.
6. Add durable rollback and lifecycle state for tripped workflows.
7. Measure token, latency, energy, carbon, and water savings produced by crystallized workflows.

## Claim discipline

This implementation demonstrates deterministic candidate synthesis, authenticated evidence intake, counterfactual guard learning, shadow gating, and deterministic-to-agent fallback for the covered trace model.

It does not establish that arbitrary agent workflows can be safely compiled, that generated source code is secure in all environments, or that production deployment can occur without additional role-separated signing, provenance, sandboxing, lifecycle controls, and operational review.
