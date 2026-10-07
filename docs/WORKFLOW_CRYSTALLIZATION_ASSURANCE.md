# Workflow Crystallization Assurance

## Purpose

This increment hardens MainStreet workflow crystallization so deterministic workflow candidates are learned from authenticated execution evidence, constrained by negative examples, and automatically abandoned when runtime conditions leave the learned envelope.

The deterministic path remains proposal-only. ClaimSieve remains the authority for consequential actions.

## Evidence intake

Raw `AgentTrace` objects are not learning authority for the hardened path.

`SignedAgentTrace` seals the complete trace payload with the repository's existing domain-separated Ed25519 primitive and ClaimSieve canonical JSON profile. Verification requires an allowlisted public key. Tampering with the input facts, proposed action, ClaimSieve verdict, terminal outcome, policy digest, or evidence root invalidates the signature.

Signed datasets are additionally bound into the hardened workflow identity through canonical SHA-256 digests.

## Positive and negative evidence

A hardened workflow requires both:

1. positive traces that were allowed by ClaimSieve and independently reconciled as `CONFIRMED_SUCCESS`; and
2. negative or counterfactual traces that were denied, sent to review, failed, remained unknown, diverged, or were not executed.

The learner looks for input facts that are constant across successful examples and that differ in negative examples. Those facts become explicit safe-input guards.

For example, if successful lead-intro traces all contain `sms_consent=true` and a denied counterexample contains `sms_consent=false`, the crystallized deterministic path is only eligible while `sms_consent=true` remains true.

If a negative example cannot be excluded by any learned guard, hardened crystallization fails closed with an unresolved-negative error. The system does not invent a hidden reason for the denial.

## Runtime routing

The runtime has two routes:

- `DETERMINISTIC_PROPOSAL`: the hardened profile, policy digest, required facts, learned guards, and drift monitor all match. A proposal is built deterministically and still requires ClaimSieve.
- `AGENT_FALLBACK`: policy drift, a guard mismatch, a missing runtime fact, or a tripped drift monitor causes the deterministic path to produce no proposal. Novel reasoning returns to the agent path, where consequential actions still require ClaimSieve.

The fallback is not autonomous execution permission.

## Drift detection

Only in-envelope executions are scored by the behavioral monitor. Expected outside-envelope cases are routed to the agent and do not poison the deterministic monitor.

The monitor trips when:

- an in-envelope action is denied or moved to review under the bound policy;
- an outcome becomes unknown or divergent;
- authenticated execution evidence is invalid;
- capability, risk class, or policy identity drifts; or
- ordinary confirmed failures/action divergences exceed the configured rolling-window threshold.

Once tripped, the monitor does not auto-recover. The deterministic route remains disabled until an external lifecycle action replaces or resets the deployment state.

## Identity binding

`HardenedWorkflow.profile_id` binds:

- the deterministic candidate ID;
- learned guards;
- the signed dataset digest;
- positive and negative trace digests;
- trusted signer IDs;
- positive and negative support counts;
- the mandatory ClaimSieve requirement; and
- the prohibition on autonomous execution.

Material tampering therefore invalidates the profile identity.

## Current limitation

This increment verifies a sealed trace against an allowlisted Ed25519 signer. It does not yet require two independent cryptographic attestations for the ClaimSieve verdict and the independently observed terminal outcome.

The next hardening step should split those attestations so one authority signs the adjudication record and a different observer signs the post-execution outcome, with promotion requiring both identities and both signatures. That will align the learning evidence more tightly with ClaimSieve's separation-of-powers model.

## Tests

The assurance suite covers signature tampering, untrusted signers, unresolved negative examples, profile identity tampering, safe-input guard learning, policy drift, guard escape, missing runtime facts, outside-envelope routing, in-envelope denial, rolling behavioral drift, invalid signed execution evidence, and deterministic-to-agent fallback.
