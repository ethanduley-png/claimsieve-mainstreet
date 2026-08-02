# Stripe Provider Contract Test

## Test objective

Test the unknown-outcome boundary against a real published provider contract without creating external effects or pretending that a deterministic simulator is a live integration.

## Contract used

The source snapshot is `research/stripe_idempotency_contract.json`. It maps clauses from Stripe's official API v1 idempotency, low-level error handling, and webhook documentation to executable scenarios.

The modeled provider contract includes:

* first-result replay for the same idempotency key, including saved 500 responses;
* rejection of same-key parameter changes;
* no saved result before endpoint execution begins;
* safe exact replay after network uncertainty;
* possible key pruning after at least 24 hours;
* 500 responses remaining semantically indeterminate;
* later provider read-back or asynchronous events potentially revealing effects.

## ClaimSieve refinement

The release distinguishes a **transport replay** from a **new logical action**.

A transport replay is permitted only when all of the following remain true:

* the original outcome is unknown;
* reservation identity is unchanged;
* idempotency key is unchanged;
* canonical request digest is unchanged;
* endpoint is unchanged;
* provider account is unchanged;
* authority remains active;
* the provider contract supports the exact replay;
* elapsed time is inside the conservative retention window;
* the bounded replay budget is not exhausted.

The decision does not consume or issue a new permit and must not change the logical action identity.

## Executed scenarios

| Scenario | Expected discrimination |
|---|---|
| Connection drop after commit | Exact replay returns the original result and effect count remains one |
| Parameter mutation | ClaimSieve denies and provider model rejects |
| Validation failure | Result is not cached; corrected execution can proceed under separately valid authority |
| Retention expiry | ClaimSieve denies; bypass demonstrates duplicate risk |
| Cached 500 with side effect | Replay returns the same 500; terminal outcome remains indeterminate |
| Revocation and binding mutations | Every changed authority or identity field denies replay |

The raw report is `evidence/PROVIDER_CONTRACT_TEST_REPORT.json`.

## What this test establishes

Implemented and executed:

* the ClaimSieve guard logic is compatible with the cited provider contract model;
* the model demonstrates why a same-dispatch replay can be safer than creating a new attempt;
* the retention and mutation boundaries are discriminating;
* a 500 is not converted into success or failure.

## What this test does not establish

* No Stripe credential was used.
* No live API request or external object was created.
* No network fault was injected against Stripe.
* No webhook endpoint was registered.
* No webhook signature, duplication, ordering, delay, or account-context behavior was tested.
* The provider may behave differently during defects, incidents, undocumented changes, or contract violations.

A credentialed test-mode experiment remains a separate, explicitly authorized future gate.
