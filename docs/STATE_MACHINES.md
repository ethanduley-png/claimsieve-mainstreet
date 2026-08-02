# State Machines and Testable Invariants — v0.33.0

These are normative design descriptions. Executed Python coverage is identified by tests. Rust and Rocq correspondence remains incomplete.

## Proposal

```text
DRAFT -> CANONICAL -> RECORDED -> EVIDENCE_PENDING -> READY_FOR_DECISION
      -> CANONICALIZATION_REJECTED
```

Mutation after canonicalization creates a new proposal identity.

## Evidence

```text
OBSERVED -> SOURCE_SIGNED -> ROLE_VERIFIED -> FRESH -> SNAPSHOT_BOUND
                                               -> EXPIRED | REVOKED | SUPERSEDED
```

Evidence omission, duplication, source substitution, or snapshot mutation invalidates the bound root.

## Decision

```text
PENDING -> EVALUATED -> DENY | REQUIRE_HUMAN | QUARANTINE
                         | SUSPEND_CAMPAIGN | ALLOW_CANDIDATE
```

`ALLOW_CANDIDATE` is not authority.

## Campaign

```text
ACTIVE -> SUSPENDED -> RECOVERY_REVIEW -> ACTIVE_WITH_NEW_AUTHORITY | CLOSED
```

Each committed action advances from exactly one predecessor with a strictly greater logical sequence.

## Permit

```text
NOT_ISSUED -> ISSUED -> RESERVED -> DISPATCHING -> CONSUMED
                   -> REVOKED | EXPIRED
```

Revocation and freeze dominate prior validity before dispatch.

## Execution

```text
PRECHECK -> RESERVED -> FINAL_RECHECK -> DISPATCH_COMMIT_POINT
                                      -> PROVIDER_RESPONSE
                                      -> CONNECTION_LOST
                                      -> LOCAL_CRASH
```

A dispatch commit does not imply remote success.

## Outcome

```text
NO_PROVIDER_RECORD -----------------------------> OUTCOME_UNKNOWN
PROVIDER_REJECTED + NO EFFECT ------------------> CONFIRMED_FAILURE
EXACT EFFECT ------------------------------------> CONFIRMED_SUCCESS
DIFFERENT EFFECT --------------------------------> DIVERGENT_EFFECT
CONTRADICTORY PROVIDER STATUS/EFFECT ------------> OUTCOME_UNKNOWN + CONTAINMENT
```

Executor claims do not choose these branches.

## Recovery and replay

```text
OUTCOME_UNKNOWN -> INDEPENDENT_READ_BACK
                -> WAIT_FOR_EVENT
                -> HUMAN_REVIEW
                -> SAME_DISPATCH_TRANSPORT_REPLAY [strict contract guard]
                -> NEW_LOGICAL_ACTION [never automatic; full new authority]
```

Transport replay is a continuation of the original dispatch and must preserve every bound field. A new logical action requires new authorization.

## Terminal immutability

A confirmed success, confirmed failure, or divergent effect cannot be rewritten into a different terminal outcome. New contradictory evidence creates an incident or new reconciliation record; it does not silently rewrite history.

## Testable invariants

1. Duplicate JSON keys, floats, unsafe integers, non-normalized strings, and excessive structures are rejected.
2. Proposal does not imply permission.
3. Policy and evidence roles are externally pinned.
4. Only one campaign successor commits from a predecessor in the executed local reference.
5. Only one reservation exists per permit.
6. Exact action, destination, parameters, purpose, evidence, policy, approval, campaign, sequence, and expiry remain bound.
7. Revocation and freeze are checked before dispatch.
8. Executor cannot sign observer outcome.
9. Executor receipt cannot establish terminal outcome.
10. No provider record remains unknown.
11. Contradictory provider evidence remains unknown and contained.
12. No outcome automatically authorizes a new logical action.
13. Same-dispatch replay requires exact provider-contract and authority guards.
14. Replay outside retention is denied.
15. Terminal outcomes are immutable.
16. Every status claim identifies whether it is executed, source-only, modeled, proved, or blocked.
