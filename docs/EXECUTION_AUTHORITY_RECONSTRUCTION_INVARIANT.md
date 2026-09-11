# Execution Authority and Reconstruction Invariant

## Core statement

ClaimSieve should be able to make one narrow system claim precisely:

> An action may execute only if valid authority existed beforehand, that authority is bound to the exact action being executed, and preserved evidence can later reconstruct why the authority existed.

The formal target is:

`Executed(x) -> PriorAuthority(x) /\ ExactBinding(x) /\ Reconstructable(x)`.

The current vertical slice refines that into two layers so the proof does not overclaim what the storage system or cryptography guarantees.

## Hot-path safety

The first theorem is independent of audit-store reconstruction:

`stored_execution_allowed entry candidate current = true`

implies

`cert_authorized (stored_certificate entry) = true`

and exact equality between the certificate and candidate for the modeled authority-relevant action, policy, and identity digests.

In Rocq this is:

`execution_implies_prior_exact_authority`.

This is the safety portion of the invariant. If an authority-relevant action field changes after authorization, the existing compact certificate no longer authorizes the mutated candidate.

The module also proves explicit fail-closed mutation results for action, policy, and identity binding.

## Reconstruction layer

The historical archive is deliberately outside the latency-critical execution predicate.

A persisted authority entry contains:

- an authority identifier
- the compact authority certificate
- the historical authority archive

The archive is valid reconstruction material only when its authority-relevant commitments still agree with the compact certificate:

- action digest
- policy digest
- identity digest
- evidence digest
- historical authorization result

This relation is `certificate_archive_binding`.

The system-level theorem is:

`execution_authority_reconstruction_invariant`.

Given:

1. the authority identifier resolves to the persisted entry,
2. the certificate remains bound to the preserved archive, and
3. the compact/current-state execution predicate accepts,

then:

- reconstruction from the store returns historical `Allow`,
- the candidate is exactly bound to the action, policy, and identity commitments in the certificate, and
- the evidence commitment in the certificate still matches the preserved archive.

This makes the durability and archive-integrity premise explicit instead of pretending the formal kernel can prove a database, filesystem, or object store will never lose or corrupt data.

## Important separation

The hot path does not inspect the full historical archive.

This is intentional.

An archive mutation can therefore leave the compact execution predicate unchanged while invalidating the later reconstruction lineage. The Python model contains this exact test. That is not a contradiction. It demonstrates why execution safety and durable audit reconstruction are separate assurance obligations.

The intended architecture is:

```text
historical policy + proposal + evidence + decision
                    |
                    v
        authenticated compact authority
                    |
          +---------+---------+
          |                   |
          v                   v
current authority state   preserved archive
          |                   |
          v                   v
     execution gate       reconstruction
```

## Formal properties in this increment

The Rocq module `rocq/ExecutionAuthorityReconstruction.v` establishes:

- compact execution implies the certificate records prior authority
- successful stored execution implies prior authority and exact action/policy/identity binding
- successful execution plus durable valid lineage implies reconstruction returns historical authority
- missing authority records are not reconstructable
- evidence-archive mutation breaks the lineage relation
- action mutation blocks stored execution
- policy mutation blocks stored execution
- identity mutation blocks stored execution

`rocq/CheckExecutionAuthorityReconstruction.v` prints the theorem assumptions so continuous integration can expose any accidental axiom or admitted-proof dependency.

## Executable model

`python/tests/test_execution_authority_reconstruction_model.py` mirrors the formal split.

The model tests:

- a valid execution is prior-authorized, exactly bound, and reconstructable
- a missing archive is not reconstructable
- authority-relevant mutations fail closed
- archive evidence mutation breaks reconstruction lineage without changing the hot-path predicate
- a certificate claiming authorization cannot form valid lineage with an archive that reconstructs to denial
- an exhaustive finite state space contains no counterexample to the modeled invariant

The exhaustive test evaluates 16,384 combinations of authorization, candidate binding, archive binding, and current-state conditions.

## Rust mapping

The Rust layer should not pull full evidence back into the latency-critical path merely to satisfy the reconstruction theorem.

Instead, the compact admission result already carries the authority-relevant commitments needed to locate and verify audit material later, including the permit identifier, trace identifier, action digest, policy digest, evidence root, and decision digest.

The Rust increment adds an explicit reconstruction handle and a persisted authority index verifier outside the execution decision itself. That verifier detects mutation of any indexed authority commitment before audit reconstruction proceeds.

This remains shadow/reference work. It is not permission to bypass the existing production executor or its atomic one-use reservation.

## Proof boundary

This increment does not claim to prove:

- Ed25519 or any other cryptographic primitive
- collision resistance of production hashes
- canonical serialization correctness
- key custody
- correctness or freshness of trusted current-state services
- durable storage implementation
- clock correctness
- uniqueness of authority identifiers in a production database
- full Rust refinement of the Rocq semantics
- deployment-level complete mediation

Those remain separate assurance obligations.

The narrow claim is conditional and testable:

> If the authenticated compact authority is valid, current authority state is trustworthy, the persisted archive remains available and commitment-consistent, and the implementation refines the modeled predicates, then an accepted execution has prior exact authority and its historical authority can be reconstructed without traversing the full evidence archive on the latency-critical path.
