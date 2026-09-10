# Authority Compression Invariant

## Design statement

Persist the minimum immutable authority-relevant facts required to establish historical execution authority. Preserve the complete evidence needed to reconstruct that authority outside the latency-critical path. At execution time, combine the authenticated compact certificate with the minimum trusted current-state facts required to establish that the authority remains executable.

Short form:

> Compress authority, not evidence. Keep mutable authority live.

## Three-way split

Let `R` be the preserved historical authority archive, `C = Γ(R)` the immutable compact certificate, and `U_t` trusted current authority state at execution time.

Historical reconstruction evaluates:

`Reconstruct(R)`.

Immutable compact verification evaluates:

`Verify(C, x, t)`.

Present executability evaluates:

`ExecuteNow(C, x, t, U_t)`.

The central safety direction is:

`ExecuteNow(Γ(R), x, t, U_t) = true -> Reconstruct(R) = true`.

Current invalidity is allowed to turn execution off without rewriting history:

`Reconstruct(R) = true` and `Revoked(U_t) = true` imply `ExecuteNow(Γ(R), x, t, U_t) = false`.

That distinction is deliberate:

- `Reconstruct(R)` answers **was this authorized then?**
- `ExecuteNow(...)` answers **may this execute now?**

## Immutable certificate state

The Rocq `authority_certificate` now carries only immutable or issuance-bound facts:

- action digest
- policy digest
- identity digest
- evidence archive digest
- historical authority result
- validity interval

Revocation and consumption are deliberately **not** certificate fields. They can change after issuance and therefore belong to trusted current state. This matches the production architecture more closely: the real permit is immutable, revocation is held by containment state, and one-use consumption is enforced by reservation state.

The evidence archive digest has a distinct role from runtime decision guards. It binds the authenticated compact certificate back to preserved evidence for reconstruction and audit, but the compact verifier does not traverse that evidence.

## Trusted current state

`rocq/AuthorityCompressionCurrentState.v` adds the mutable facts needed to decide present executability:

- currently effective policy digest
- currently effective identity digest
- policy active state
- identity active state
- campaign active state
- global execution freeze
- campaign suspension
- permit revocation
- permit consumption

The module proves that each blocking current condition dominates execution while historical authority remains independently reconstructible. In particular:

- current revocation blocks execution
- current consumption blocks execution
- policy or identity deactivation blocks execution
- policy or identity replacement blocks execution
- campaign inactivity or suspension blocks execution
- global freeze blocks execution
- current execution implies historical authority
- revocation and global freeze do not rewrite historical authority

## Pointwise minimality

Minimality is split across immutable and mutable state instead of mixing them into one record.

`rocq/AuthorityCompressionNecessity.v` gives omission witnesses for every immutable compact-verifier guard:

- historical authority
- action binding
- policy binding
- identity binding
- not-before freshness
- expiry

`rocq/AuthorityCompressionCurrentStateNecessity.v` gives omission witnesses for every modeled live current-state guard:

- current policy digest
- current identity digest
- policy active state
- identity active state
- campaign active state
- global freeze
- campaign suspension
- current revocation
- current consumption

These are **pointwise necessity** results. They show that removing an individual guard admits at least one unsafe state represented by the model. They do not claim globally minimal bit encoding or uniqueness of representation.

The evidence digest remains outside both guard-minimality sets. It is an authenticated reconstruction commitment, not a predicate that should require reading full evidence at execution.

## Authenticated certificate boundary

`rocq/AuthorityCompressionAuthenticity.v` models:

`external signature/trust verification -> authenticated certificate -> compact verification`.

It proves that unauthenticated certificates fail closed, authenticated execution implies compact execution, and authenticity is independently necessary.

The production permit path already carries an authority key identifier and Ed25519 signature. The formal model abstracts the Boolean result of that external cryptographic verification. It does not prove Ed25519, trust-root correctness, key custody, or canonical serialization.

## Executable model tests

`python/tests/test_authority_compression_model.py` mirrors the immutable certificate verifier. Its finite domain exhaustively evaluates 3,456 states. The full verifier accepts 80 states. Omitting historical authority, action, policy, or identity creates 80 additional unsafe accepts per guard; omitting either validity-bound guard creates 64.

`python/tests/test_authority_compression_shadow_vectors.py` separately models present executability. It contains named reference-versus-shadow vectors and an exhaustive 512-combination current-state sweep. With historical authority and immutable bindings held valid, only one of those 512 current-state combinations remains executable: every required live condition is current and nonblocking.

This separation prevents the test model from falsely treating mutable revocation or consumption as facts frozen inside an immutable permit.

## Formal-to-production conformance

The current Rust reference executor still receives full policy, evidence, decision, and campaign state and reruns the deterministic kernel. That is conservative but keeps full evidence on the execution path.

The shadow-only `claimsieve-compact-admission` crate models the target interface without full `Policy`, `Evidence`, or `Decision` arguments. It is not an execution authority and cannot be promoted until its current-state inputs have trusted provenance, one-use reservation is atomic, reference-versus-shadow equivalence is demonstrated broadly, and both Rust and Rocq toolchains compile successfully.

See `docs/AUTHORITY_COMPRESSION_CONFORMANCE.md` and GitHub Issue #24.

## Proof boundary

The formal work intentionally does not prove cryptographic collision resistance, canonical serialization, certificate signature implementation, trusted-state service correctness, durable storage, clock correctness, key custody, or that abstract numeric digests equal production cryptographic digests.

The resulting system claim is conditional but precise:

> If the compact certificate is authentically derived from the preserved archive, if trusted current-state facts are correct and fresh, and if the execution implementation refines the modeled predicates, then present execution implies reconstructible historical authority without requiring traversal of the full evidence archive on the latency-critical path.
