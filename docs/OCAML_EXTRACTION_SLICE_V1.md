# OCaml Extraction Slice v1

## Goal

Establish the first mechanically checked Rocq-to-OCaml executable slice without changing ClaimSieve runtime authority.

## Selected semantic function

`reconcile_from_independent_provider` from `rocq/DurableState.v`.

This function is deliberately narrow and security relevant. An executor claim is not able to establish terminal truth. The independent provider observation determines whether the modeled result is confirmed success, confirmed failure, divergent effect, or unknown.

## Mechanical check

`rocq/ExtractRefinement.v` loads Rocq's extraction framework, imports the audited durable-state model, selects OCaml as the extraction target, and runs:

`Extraction TestCompile reconcile_from_independent_provider.`

Rocq's `TestCompile` command extracts the selected definition and its dependencies to temporary OCaml source and invokes the OCaml compiler used by the Rocq installation. The dedicated Rocq CI workflow compiles `ExtractRefinement.v`, so a failed extraction or OCaml type-check fails the gate.

## What this establishes

If the gate passes, the repository has direct evidence that the selected machine-checked Rocq decision function can be turned into OCaml accepted by the pinned proof toolchain.

## What this does not establish

This increment does not claim:

- that the Rust runtime refines the Rocq model;
- that extracted OCaml is part of production authority;
- that parsing, cryptography, storage, transport, clocks, provider correctness, or deployment isolation are proved;
- that the complete ClaimSieve state machine has been extracted;
- that Rust and extracted OCaml are behaviorally equivalent on all inputs.

Those are later refinement increments. The next intended step, after this slice is green, is to define a shared finite conformance vector for this decision function and execute the same cases against Rust and the extracted OCaml result.
