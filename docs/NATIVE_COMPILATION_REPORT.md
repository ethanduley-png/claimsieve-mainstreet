# Native Compilation Report

## Requested gates

Rust:

```bash
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

Rocq:

```bash
rocq compile -Q . ClaimSieve Claimsieve.v
rocq compile -Q . ClaimSieve DurableState.v
rocq compile -Q . ClaimSieve Check.v
rocq compile -Q . ClaimSieve CheckDurableState.v
```

Equivalent `coqc` commands are supported when the legacy executable is present.

## Actual environment

The native gates were executed locally on 2026-08-02 with:

* project-pinned Rust 1.90.0 through `rust-toolchain.toml`;
* rustup 1.29.0 (the user default toolchain is Rust 1.97.1);
* the Rust GNU target plus MinGW binutils from MSYS2;
* Rocq Platform 2025.08, Rocq Prover 9.0.1.

The exact successful attempt is recorded in `evidence/NATIVE_COMPILATION_ATTEMPT.txt`.

## Status

| Gate | Status |
|---|---|
| Rust parse/type check | Pass |
| Rust format | Pass |
| Rust Clippy with warnings denied | Pass |
| Rust unit and conformance tests | Pass (28 tests) |
| Rust documentation tests | Pass |
| Rust v0.34 bundle CLI verification | Pass |
| Rocq compilation | Pass (4 files) |
| Rocq `Print Assumptions` audit | Pass; all reported closed under the global context |
| Static Rust boundary scan | Pass |
| Static Rocq escape scan | Pass |

## Included external execution paths

* `.github/workflows/rust.yml`
* `.github/workflows/rocq.yml`
* `scripts/compile_native.sh`
* `scripts/test_rocq_docker.sh`

These remain reproducible external execution paths. The local results above are direct execution evidence; workflow presence alone is not.
