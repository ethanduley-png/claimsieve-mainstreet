# 05_observe — determine external outcome independently

## Purpose
Establish what the provider actually did without allowing the executor or proposer to self-certify success.

## Inputs
- Working: dispatch/provider request identifiers and exact expected effect
- Reference: independent observer interface
- Reference: durable state semantics
- Reference: `security/INVARIANTS.md`

## Authority
- May: classify externally observed outcome using independent evidence.
- Must not: issue permits, mutate action scope, or treat timeout/transport ambiguity as success or failure without evidence.

## Invariants
1. Execution and observation are separate authorities/interfaces.
2. Unknown remains unknown until evidence resolves it.
3. Observed effect must match the permit's expected effect and destination/parameters.
4. Conflicting observations remain explicit and auditable.

## Outputs
- Observed-success, observed-failure, observed-mismatch, or unresolved/unknown.

## Evidence produced
- Provider-side or independent observation record linked to the execution trace.

## Tests
- `scripts/provider_contract_gate.py`
- `scripts/semantic_divergence_gate.py`
- `scripts/run_durable_red_team.py`

## Human gate
Material mismatches or unresolved consequential outcomes escalate for human handling rather than triggering autonomous corrective execution.