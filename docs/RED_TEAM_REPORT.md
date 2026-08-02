# Red-Team Report — v0.33.0

## Inherited suite

* Total scenarios: 58
* Blocked or detected: 52
* Tested bypasses: 0
* Infrastructure limitations: 6

## Durable and independent-outcome suite

* Total scenarios: 29
* Blocked or detected: 25
* Tested bypasses: 0
* Infrastructure limitations: 4

## v0.33 corrections to adversarial expectations

### Conflicting provider receipt

Contradictory provider evidence is no longer expected to resolve to success merely because an effect exists. The expected result is `OUTCOME_UNKNOWN`, explicit conflict, and containment.

### Forged local executor narrative

The observer is not expected to reject the forged executor receipt as part of terminal classification. The stronger property is that the receipt has no authority over terminal outcome. Independent provider evidence controls the result.

## Strongest remaining attack classes

1. Provider read credentials or account selection compromised.
2. Observer and executor sharing one infrastructure failure domain.
3. Multi-node state split-brain around a remote effect.
4. Provider-contract drift or violation.
5. Rust wire-format divergence.
6. Formal constructor misclassification.
7. Supply-chain substitution before native compilation.

## Machine-readable evidence

* `evidence/RED_TEAM_REPORT.json`
* `evidence/DURABLE_RED_TEAM_REPORT.json`
