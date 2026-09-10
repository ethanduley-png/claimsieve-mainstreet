# Authority Compression: Formal to Production Conformance

## Status

The Rocq authority-compression model is a target invariant, not yet a complete refinement proof of the Rust executor.

The current Rust runtime enforces the same core safety concerns, but its `Executor::verify_permit` still receives full policy, full evidence, the decision object, and campaign state, then reruns the deterministic kernel before dispatch. That design is conservative, but it keeps full evidence on the latency-critical execution path and therefore does not yet satisfy the fast-path separation theorem.

A separate shadow-only Rust candidate now lives in `rust/crates/compact-admission`. Its `verify_shadow_compact_preflight` interface deliberately accepts no full `Policy`, `Evidence`, or `Decision` object. It verifies the authenticated permit against exact proposal material plus bounded current authority facts. It is not wired to a connector and must not be treated as execution authority.

## Refinement direction

The safe migration is staged:

1. Keep the current Rust full-revalidation path as the reference implementation.
2. Run `claimsieve-compact-admission` as a shadow preflight beside the reference path.
3. Feed the shadow path trusted bounded current facts: effective policy commitments, current principal/campaign status, containment state, logical sequence, and permit-consumption state.
4. Run both paths over the same valid and adversarial corpus and require decision equivalence.
5. Treat every disagreement as fail closed and preserve the full reference-path evidence.
6. Replace the shadow consumption snapshot with the same or stronger linearizable one-use reservation primitive before any compact path can dispatch.
7. Only after equivalence testing, atomic reservation, independent assurance, Rust compilation, and Rocq compilation are green may the compact path become eligible for latency-critical execution.

## Formal guard mapping

The machine-readable map is `vectors/authority_compression_conformance_v1.json`.

The main correspondences are:

- formal certificate authority -> trusted authority-signed permit issued only after an exact `ALLOW` kernel result
- formal revocation -> containment permit revocation and campaign/global containment state
- formal consumption -> `max_uses = 1` plus atomic reservation and replay rejection
- formal action binding -> proposal/action/destination/parameter digest checks
- formal policy binding -> policy and signed-policy commitments plus current effective-policy status
- formal identity binding -> tenant, campaign, and principal tuple plus current principal status
- formal freshness -> `valid_from_seq` and `expires_at_seq`
- formal evidence linkage -> signed `evidence_root` commitment
- formal reconstruction linkage -> signed `decision_digest` plus preserved evidence/decision records

## Compact shadow interface

The shadow candidate carries only bounded current authority facts alongside the signed permit and exact proposal material. Current facts presently include:

- current logical sequence
- currently effective policy digest
- currently effective signed-policy-envelope digest
- current campaign identifier
- policy active state
- principal active state
- campaign active state
- global freeze state
- campaign suspension state
- permit revocation state
- permit-consumption snapshot

This is intentionally closer to the Rocq fast-path model than the current reference executor. The static conformance test rejects future changes that add full `Policy`, `Evidence`, or `Decision` inputs to the shadow verifier or reintroduce `evaluate(...)` or evidence-root reconstruction inside the compact body.

## Important distinction

The evidence commitment is not supposed to require rereading the entire evidence archive at execution. It is an integrity-protected pointer to the historical basis of authority. Current reference Rust still recomputes that root from full evidence. That is the principal conformance gap this work exposes.

Likewise, the target compact path must not silently accept stale policy authority. Replacing full-policy reevaluation requires small trusted current-state facts such as the currently effective policy and signed-policy digests plus an active/revoked status. The executor must not infer present authority solely from an old signed permit.

The current shadow candidate contains a `permit_consumed` snapshot only to compare semantics. A snapshot cannot prevent a race between two executors. Production dispatch must retain a linearizable reservation/consume operation at the commit point. Until that exists, the shadow candidate is structurally incapable of replacing the reference executor.

## Security posture during migration

Do not delete the full reference path first. The authority signer already reruns the deterministic kernel before signing a permit, and the executor independently reruns it today. Removing executor reevaluation changes the fault model: a compromised or defective authority signer would become more powerful.

Before switching paths, ClaimSieve should preserve equivalent defense through independent verification, threshold authorization, a separately trusted attestation, or another explicit mechanism. The target architecture should reduce evidence-path latency without silently collapsing separation of powers.

The desired end state is therefore not "trust the permit blindly." It is:

> Verify compact, independently authenticated authority facts on the execution path; preserve and independently reconstruct the complete evidence off that path.

## Merge criterion

This PR should not be represented as full production conformance until:

- Rocq modules compile with no admitted or axiomatized proof source;
- the compact candidate compiles cleanly under workspace formatting, lint, and tests;
- the compact candidate and full reference path agree on a broad adversarial corpus;
- policy revocation/currentness is represented compactly and derived from a trusted source;
- principal currentness is represented compactly and derived from a trusted source;
- replay reservation remains atomic and one use;
- action, destination, parameter, tenant, campaign, and principal mutations are blocked;
- evidence and decision commitments remain cryptographically bound to the authenticated permit;
- independent assurance preserves the intended separation-of-powers fault model;
- the promoted executor can operate without receiving the full evidence archive.

Track the production refactor in GitHub Issue #24.
