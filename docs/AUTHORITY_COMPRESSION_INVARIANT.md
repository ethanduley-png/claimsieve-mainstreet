# Authority Compression Invariant

## Design statement

Persist the minimum authority-relevant facts required to establish execution authority before execution. Preserve the complete evidence needed to reconstruct that authority outside the latency-critical path. Cryptographically bind the compact execution certificate to the preserved evidence.

Short form:

> Compress authority, not evidence.

## Formal split

Let `R` denote the preserved authority archive and let `C = Γ(R)` denote the compact certificate projected from it.

The execution path evaluates only:

`Verify(C, x, t)`

while historical reconstruction evaluates:

`Reconstruct(R)`.

The central safety requirement is:

`Verify(Γ(R), x, t) = true  ->  Reconstruct(R) = true`.

In the current Rocq model, `Reconstruct(R)` is the result of replaying the preserved ClaimSieve `decide` inputs. Therefore the stronger proved bridge is:

`Verify(Γ(R), x, t) = true  ->  decide(policy(R), proposal(R), campaign(R)) = Allow`.

## Compact authority state

The compact certificate carries:

- action digest
- policy digest
- identity digest
- evidence archive digest
- historical authority result
- revocation state
- consumption state
- validity interval

The full archived adjudication inputs and arbitrary evidence payload are not parameters of the latency-critical verifier.

The evidence archive digest has a distinct role from the runtime guards. It binds the compact certificate back to the preserved evidence for reconstruction and audit, but `verify_compact` does not compare the evidence digest against the execution candidate. In production, integrity of that linkage therefore depends on the signed or otherwise integrity-protected certificate representation. The Rocq model makes this separation explicit rather than claiming that every carried field is a runtime predicate.

## Proven properties

`rocq/AuthorityCompression.v` proves:

- compression preserves the reconstructed authority result
- compression binds action, policy, identity, and evidence archive digests
- compact verification is sound with respect to reconstructed authority
- compact execution implies the original ClaimSieve adjudication result was `Allow`
- unauthorized, revoked, consumed, expired, and not-yet-valid certificates fail closed
- action, policy, and identity mutations invalidate the certificate
- archives with the same authority-relevant projection produce the same fast-path result regardless of archived payload detail
- every accepted compressed certificate has reconstructible authority under the preserved archive

`rocq/AuthorityCompressionNecessity.v` strengthens the minimality claim. It proves pointwise necessity for every runtime guard currently used by `verify_compact`: historical authority, revocation, consumption, action binding, policy binding, identity binding, not-before freshness, and expiry. For each guard, the file supplies a concrete witness where omitting only that guard changes an unsafe execution from reject to accept.

That result is deliberately called **pointwise necessity**, not global information-theoretic minimality. It establishes that no current runtime predicate can simply be deleted while preserving the modeled safety behavior. It does not prove that the certificate representation uses the fewest possible bits or that no mathematically equivalent encoding exists.

The same module also proves that the evidence archive digest is not itself a runtime guard: changing only that field leaves `verify_compact` unchanged. This clarifies that the digest belongs to the reconstructibility and audit binding layer rather than the execution predicate layer.

## Authenticated certificate boundary

`rocq/AuthorityCompressionAuthenticity.v` models the system boundary that exists outside the compact semantics kernel:

`external signature and trust verification -> authenticated envelope -> verify_compact`.

The outer model carries the Boolean result of certificate authenticity verification and proves:

- an unauthenticated envelope always fails closed
- authenticated execution implies the underlying compact verifier accepted
- authenticated execution of a compressed archive implies the original ClaimSieve `decide` result was `Allow`
- the authenticity gate is independently necessary because a semantically valid raw certificate can pass `verify_compact` while the same certificate is rejected when its authenticity result is false
- once authenticity is established, the wrapper is transparent to the compact verifier

This abstraction matches the production permit architecture, where permits carry an authority key identifier and Ed25519 signature and verification is performed against externally supplied trusted authority keys before permit bindings are accepted. The formal module does not prove Ed25519, external trust-root correctness, canonicalization, or key custody; it proves the control-flow consequence of the external verifier's Boolean result.

`rocq/CheckAuthorityCompression.v`, `rocq/CheckAuthorityCompressionNecessity.v`, and `rocq/CheckAuthorityCompressionAuthenticity.v` print assumptions for each theorem. CI rejects `Admitted`, `admit`, `Axiom`, and `Parameter` in Rocq proof sources.

## Executable model tests

`python/tests/test_authority_compression_model.py` mirrors the compact verifier independently of Rocq. It exhaustively evaluates 13,824 small-domain verifier states, checks reconstruction and payload separation, verifies every guard can independently block, constructs one omission witness for each runtime guard, measures the exhaustive omission matrix, confirms that changing only the evidence archive digest does not change the fast-path result, and verifies that certificate authenticity acts as an outer fail-closed gate.

The local executable model currently passes 8 tests. In the exhaustive finite domain, the full verifier accepts 80 states. Removing authority, revocation, consumption, action, policy, or identity introduces 80 unsafe accepts each; removing either validity-window guard introduces 64.

## Proof boundary

The Rocq model intentionally does not claim to prove cryptographic collision resistance, canonical serialization, certificate signature verification, storage durability, clock correctness, key custody, or that numeric digests correspond to production cryptographic digests. Those remain implementation and assurance obligations outside this formal kernel.

This means the mathematical statement is a conditional system invariant: once production components correctly establish the archive digests, authenticate and protect the compact certificate, and preserve the archive, the execution boundary can operate on the compact certificate without traversing the full evidence record while retaining reconstructible authority.
