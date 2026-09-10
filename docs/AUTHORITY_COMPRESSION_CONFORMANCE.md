# Authority Compression: Formal to Production Conformance

## Status

The Rocq authority-compression model is a target invariant, not yet a complete refinement proof of the Rust executor.

The current Rust runtime enforces the same core safety concerns, but its `Executor::verify_permit` still receives full policy, full evidence, the decision object, and campaign state, then reruns the deterministic kernel before dispatch. That design is conservative, but it keeps full evidence on the latency-critical execution path and therefore does not yet satisfy the fast-path separation theorem.

## Refinement direction

The safe migration is staged:

1. Keep the current Rust full-revalidation path as the reference implementation.
2. Define an authenticated compact admission path that accepts only the signed permit, exact proposal/action material required for dispatch, current policy identity/status commitments, current containment state, logical sequence, and atomic one-use reservation state.
3. Run both paths in shadow mode over the same corpus and require decision equivalence.
4. Treat every disagreement as fail closed and preserve the full reference-path evidence.
5. Only after equivalence testing and Rocq compilation are green may the compact path become eligible for latency-critical execution.

## Formal guard mapping

The machine-readable map is `vectors/authority_compression_conformance_v1.json`.

The main correspondences are:

- formal certificate authority -> trusted authority-signed permit issued only after an exact `ALLOW` kernel result
- formal revocation -> containment permit revocation and campaign/global containment state
- formal consumption -> `max_uses = 1` plus atomic reservation and replay rejection
- formal action binding -> proposal/action/destination/parameter digest checks
- formal policy binding -> policy and signed-policy commitments
- formal identity binding -> tenant, campaign, and principal tuple
- formal freshness -> `valid_from_seq` and `expires_at_seq`
- formal evidence linkage -> signed `evidence_root` commitment
- formal reconstruction linkage -> signed `decision_digest` plus preserved evidence/decision records

## Important distinction

The evidence commitment is not supposed to require rereading the entire evidence archive at execution. It is an integrity-protected pointer to the historical basis of authority. Current Rust still recomputes that root from full evidence. That is the principal conformance gap this work exposes.

Likewise, the target compact path should not silently accept stale policy authority. Replacing full-policy reevaluation requires a small trusted current-state fact such as the currently effective policy digest/version plus revocation status. The executor must not infer current authority solely from an old signed permit.

## Security posture during migration

Do not delete the full reference path first. The authority signer already reruns the deterministic kernel before signing a permit, and the executor independently reruns it today. Removing executor reevaluation changes the fault model: a compromised or defective authority signer would become more powerful. Before switching paths, ClaimSieve should preserve equivalent defense through independent verification, threshold authorization, or another separately trusted attestation mechanism.

The desired end state is therefore not "trust the permit blindly." It is:

> Verify compact, independently authenticated authority facts on the execution path; preserve and independently reconstruct the complete evidence off that path.

## Merge criterion

This PR should not be represented as full production conformance until:

- Rocq modules compile with no admitted or axiomatized proof source;
- the compact candidate and full reference path agree on a broad adversarial corpus;
- policy revocation/currentness is represented compactly;
- replay reservation remains atomic and one use;
- action, destination, parameter, tenant, campaign, and principal mutations are blocked;
- evidence and decision commitments remain cryptographically bound to the authenticated permit;
- the executor can operate without receiving the full evidence archive.
