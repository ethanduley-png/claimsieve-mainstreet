# ADR-005: Independent Outcome Authority

**Status:** Accepted for the v0.33 reference

## Context

The executor is inside the threat model. A valid executor signature cannot establish that its claim about an external effect is true. v0.32 nevertheless allowed a signed executor rejection to become terminal failure when no provider record existed.

## Decision

Executor receipts are removed from the terminal-outcome trust path. Terminal classification is based on independently readable provider evidence. Executor receipts remain audit and conflict evidence.

No provider record produces `OUTCOME_UNKNOWN`. Contradictory provider evidence also produces `OUTCOME_UNKNOWN` and containment.

## Consequences

Positive:

* smaller trusted computing base;
* executor compromise cannot alone declare success or failure;
* signature validity is separated from semantic authority;
* unknown outcomes remain explicit.

Negative:

* outcome resolution can take longer;
* provider read access becomes a critical dependency;
* observation freshness and account binding require stronger controls;
* some providers may not expose sufficient independent read-back.

## Rejected alternatives

* Trust the executor if its receipt is signed.
* Add another verifier for the same executor receipt.
* Treat missing provider evidence as failure.
* Automatically retry after a signed failure.
