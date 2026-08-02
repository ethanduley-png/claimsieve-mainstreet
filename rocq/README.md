# Rocq formal kernel

Target: Rocq Prover 9.2.

This directory contains a deliberately bounded authorization and lifecycle model. It models selected facts about:

- fail-closed policy and evidence premises;
- campaign suspension and cumulative limits;
- one-use and revoked permits;
- exact action, destination, and decision binding;
- external trust-root premises;
- role-key separation as an abstract predicate;
- compare-and-swap campaign succession;
- strict sequence advancement;
- the rule that no outcome independently authorizes an automatic retry.

It does **not** prove parser correctness, cryptographic security, storage linearizability, operating-system isolation, network behavior, identity issuance, external-system behavior, or correspondence with the Python or Rust implementations. Those remain outside the proof boundary and require separate evidence.

Compile with Rocq 9.2:

```bash
rocq compile -Q . ClaimSieve Claimsieve.v
rocq compile -Q . ClaimSieve Check.v
```

`Check.v` prints assumptions for every named theorem. The source gate rejects `Admitted`, `admit`, `Axiom`, `Parameter`, and `Abort`. In the current build environment Rocq is unavailable, so these files are **formally modeled but not compiled or accepted by Rocq in this release run**.
