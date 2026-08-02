# Release Inventory — v0.33.0 Independent Outcome Boundary

## Executable components

* Python ClaimSieve reference kernel, durable-state boundary, provider-contract model, verifier, generators, and tests
* MainStreet JavaScript proposal boundary and tests
* source, schema, provider-contract, semantic-divergence, red-team, and packaging gates

## Source-only native components

* Rust workspace with seven crates
* Rocq model and assumption-printing files

## Protocol and evidence artifacts

* strict JSON schemas
* trust-root fixture
* portable evidence bundle
* durable execution vector
* eight-case outcome semantics vector
* provider contract snapshot
* four authority ledgers in the reference bundle
* durable operational journal in the local state reference

## Preserved adversarial evidence

* v0.32 invariant-violation probe and trace
* v0.33 patched probe and trace
* inherited red-team report
* durable-state red-team report
* provider-contract report
* semantic-divergence report

## Build and release

* deterministic ZIP packager
* SHA-256 manifest
* fresh-extraction test harness
* native compilation attempt script
* GitHub workflows for Python/Node, Rust, Rocq, and release evidence

## Missing execution dependencies

* Rust toolchain
* Rocq/Coq toolchain
* container runtime
* connected GitHub repository for remote workflow execution
* live provider credentials and explicit effect authorization
