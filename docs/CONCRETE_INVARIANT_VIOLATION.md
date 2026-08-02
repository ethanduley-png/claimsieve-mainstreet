# Concrete Invariant Violation

## Invariants

**I-032:** An outcome that cannot be independently established remains `OUTCOME_UNKNOWN`.

**Independent observation:** The component that attempted an action must not be authoritative for the action's terminal outcome.

**I-033A:** A valid signature proves key use and message integrity, not semantic truth.

## Reproduced v0.32 trace

The preserved probe is `evidence/V032_INVARIANT_VIOLATION_PROBE.py`. It reconstructs the v0.32 code path and performs these steps:

1. Issue a valid exact-action permit.
2. Create a durable reservation and dispatch ticket.
3. Do not create an independent provider record.
4. Use the legitimate executor key to sign a semantically false `rejected` receipt.
5. Persist the executor claim.
6. Ask the observer to reconcile.

Observed trace:

```json
{
  "executor_claim": "rejected (valid signature, false semantics)",
  "final_outcome": "CONFIRMED_FAILURE",
  "invariant": "I-032 Unknown is not failure; observation must be independent",
  "observer_reconciliation": "CONFIRMED_FAILURE",
  "provider_record": null,
  "violation": true
}
```

## Why the test is discriminating

The test would produce a different result if the observer were truly independent. With no provider record, the only supported result is `OUTCOME_UNKNOWN`. The v0.32 result changed solely because the executor supplied a signed rejection.

The attack does not forge a key, mutate a hash, or bypass signature validation. It uses a legitimate executor key under the stated threat model, which explicitly permits executor compromise.

## Impact

A false `CONFIRMED_FAILURE` can:

* cause a user or recovery worker to issue a new logical action;
* conceal an effect that actually happened but is not yet observable;
* erase the distinction between failed transport and failed external action;
* produce duplicate payments, messages, filings, deployments, or record changes;
* create a misleading audit history with valid signatures.

## Patched result

The v0.33 probe repeats the same compromised-executor trace. The observer ignores the executor narrative for terminal classification:

```json
{
  "executor_claim": "rejected (valid signature, false semantics)",
  "final_outcome": "OUTCOME_UNKNOWN",
  "observer_reconciliation": "OUTCOME_UNKNOWN",
  "patch_result": "BLOCKED",
  "provider_record": null,
  "violation": false
}
```

The regression is enforced by executed Python tests and the durable red-team scenario `FORGED_EXECUTOR_RECEIPT`.
