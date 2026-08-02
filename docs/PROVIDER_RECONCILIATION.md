# Provider Reconciliation — v0.33.0

## Evidence hierarchy

Terminal classification is based on independently obtained provider evidence, not the executor's attempt narrative.

Possible evidence sources include:

* provider read-back using read-only credentials;
* verified webhook or event-delivery records;
* external resource state;
* independent network or process observation;
* human-confirmed provider state where policy permits.

No single source is assumed infallible.

## Classification table

| Provider response | Observed effect | Classification |
|---|---|---|
| none | none | `OUTCOME_UNKNOWN` |
| rejected | none | `CONFIRMED_FAILURE` |
| accepted | exact | `CONFIRMED_SUCCESS` |
| timeout/unknown | exact | `CONFIRMED_SUCCESS` |
| any | different | `DIVERGENT_EFFECT` |
| rejected | present | `OUTCOME_UNKNOWN` + conflict |
| accepted | absent | `OUTCOME_UNKNOWN` + conflict |

## Executor receipt role

The executor receipt is retained for audit and disagreement detection. It cannot establish terminal outcome. A valid executor signature proves only that the executor key signed the stated receipt.

## Contract-bounded transport replay

A network error may permit exact replay under a provider idempotency contract. This is not a general retry policy.

The guard requires:

* same reservation;
* same idempotency key;
* same canonical request;
* same endpoint and account;
* active authority;
* documented provider guarantee;
* unexpired retention window;
* bounded replay count.

A cached 500 remains indeterminate. A new idempotency key is a new logical attempt and requires new authority.

## Conflicts

Contradictory provider evidence must not be coerced into a terminal answer. The reference records the conflict, suspends the campaign, and preserves `OUTCOME_UNKNOWN`.
