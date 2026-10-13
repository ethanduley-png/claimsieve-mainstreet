# Rust ↔ Rocq-derived OCaml refinement conformance v1

## Purpose

This increment checks one narrow semantic correspondence between a Rust candidate and a function mechanically extracted from the audited Rocq model.

The function under comparison is `reconcile_from_independent_provider`.

## Shared input domain

The fixture `vectors/reconciliation_refinement_v1.tsv` contains the complete finite product of:

- four executor claims
- five independent provider observations

This gives 20 cases.

The executor claim is intentionally non-authoritative. The provider observation alone determines the reconciled outcome.

## Comparison path

1. The existing Rocq definition is compiled.
2. Rocq extraction emits `RefinementCore.ml` from `reconcile_from_independent_provider`.
3. The OCaml conformance runner evaluates all 20 shared fixture cases.
4. An example-only Rust candidate in the existing durable-state crate evaluates the same cases while using the production Rust `Outcome` representation.
5. Both runners emit canonical `case_id<TAB>outcome` lines.
6. Continuous integration requires exactly 20 output lines from each runner and performs a byte-for-byte `diff`.

Any semantic disagreement fails the refinement conformance gate.

## What a green gate establishes

A green gate establishes behavioral agreement over the complete finite input domain of this one reconciliation classifier between:

- the audited Rocq definition as mechanically extracted to OCaml; and
- the isolated Rust refinement candidate used by the conformance runner.

It also establishes that executor self-report cannot change the classifier result within this tested finite model.

## What it does not establish

This is not yet a proof that the production Rust runtime refines the Rocq model.

The Rust classifier in this increment is example-only and is not yet wired into the authoritative execution path. The gate does not prove parsing, observer authentication, cryptography, durable storage, networking, provider behavior, concurrency, deployment behavior, or the correctness of the OCaml compiler/runtime.

The next refinement increment should replace the example-only Rust classifier with the actual production classification boundary, preserving the same fixture and extracted reference behavior.
