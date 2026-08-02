# Semantic Divergence Report

## Method

The release compares semantics rather than counting matching names. The gate asks whether each representation assigns the same authority and outcome to identical traces.

Executed comparisons:

* eight canonical provider-evidence vectors through Python;
* one Stripe contract-derived connection-drop replay trace;
* structural checks of Rust authority ownership and retry behavior;
* structural checks of Rocq theorem statements and guards;
* schema comparison for observer receipts.

The machine-readable output is `evidence/SEMANTIC_DIVERGENCE_REPORT.json`.

## Resolved divergences

### DIV-001: executor rejection without provider record

* v0.32 Python: `CONFIRMED_FAILURE`
* v0.33 Python, Rust source, Rocq model: `OUTCOME_UNKNOWN`

### DIV-002: observer signing key ownership

* v0.32 Rust source: executor owned observer signing material
* v0.33 Rust source: separate `IndependentObserver`

### DIV-003: automatic retry after terminal failure

* prior Rust source: confirmed failure could enable retry
* v0.33 Python, Rust source, and Rocq model: no outcome automatically authorizes a new logical attempt

### DIV-004: contradictory provider evidence

* v0.33 rule: contradiction remains `OUTCOME_UNKNOWN` and triggers containment

### DIV-005: Rust native status

The Rust workspace now formats, compiles under warning-denied Clippy, passes 28 tests, and verifies the generated v0.34 bundle against an external trust root.

### DIV-006: Rocq native status

All four Rocq files compile with Rocq 9.0.1. `Check.v` and `CheckDurableState.v` report every audited theorem closed under the global context.

## Remaining divergences

### REM-DIV-001: observer receipt wire shape

Rust still emits `claimsieve.observer_receipt.v1` with fewer fields. Executed Python and `schemas/observer-receipt-v2.schema.json` bind:

* reservation identifier;
* permit identifier;
* campaign identifier;
* provider-record digest;
* observed action digest;
* conflict flag;
* observation sequence;
* observer key.

Impact: Rust cannot claim portable wire-format or verifier parity.

### REM-DIV-002: Rocq abstraction boundary

Rocq models provider observation as constructors such as `NoProviderRecord` and `ProviderAcceptedExact`. It does not model how a record is parsed, authenticated, selected, queried, or bound to an account and reservation.

Impact: the theorem can be true while the implementation supplies the wrong constructor.

## Review rule

Do not remove a divergence from this report because prose was aligned. Remove it only after a discriminating cross-implementation test or accepted proof result demonstrates the relevant property.
