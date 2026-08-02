# Rust Implementation Report — v0.33.0

## Status

Compiled and executed locally on 2026-08-02 with the project-pinned Rust 1.90.0 GNU toolchain. Formatting, warning-denied Clippy, 28 tests, documentation tests, the Python-generated kernel conformance vector, and v0.34 portable bundle verification all pass.

## Relevant source changes

`rust/crates/runtime/src/lib.rs` now contains:

* an `ObservationSource` read-only interface;
* a separately keyed `IndependentObserver`;
* an executor that emits no observer receipt;
* provider-only outcome classification;
* contradictory evidence mapping to `OutcomeUnknown` with containment;
* no automatic logical retry from any outcome;
* a narrow same-dispatch transport replay guard;
* tests written for the new semantics.

The source gate verifies structurally that the `Executor` does not contain `observer_signing_key` and that the former confirmed-failure retry pattern is absent.

The native pass also aligned the Rust protocol and verifier with v0.34 digest-bearing fields: signed evidence identity/signature, type-scoped evidence key policy, predecessor campaign-state commitment, signed-policy permit binding, successor campaign-state binding, the v2 bundle envelope, external trust roots, and release witnesses.

## Known divergence

The Rust protocol still defines and emits `claimsieve.observer_receipt.v1`. The executed Python durable boundary and JSON schema use observer receipt v2.

This is a substantive divergence, not a naming issue. The v1 Rust receipt does not bind the full v2 field set, including reservation, campaign, provider-record digest, and conflict indicator.

## Remaining evidence work

* Run all eight provider-outcome vectors through Rust, not only the included kernel and verifier conformance cases.
* Upgrade emitted observer receipts to the v2 schema and test their full bindings.
* Expand canonical-byte and signature-domain differential fixtures beyond the valid v0.34 bundle.
* Reproduce the build independently and attach signed build provenance.
