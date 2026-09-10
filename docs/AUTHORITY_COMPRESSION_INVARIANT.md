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

The compact certificate carries only execution-relevant state:

- action digest
- policy digest
- identity digest
- evidence archive digest
- historical authority result
- revocation state
- consumption state
- validity interval

The full archived adjudication inputs and arbitrary evidence payload are not parameters of the latency-critical verifier.

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

`rocq/CheckAuthorityCompression.v` prints assumptions for each theorem. CI rejects `Admitted`, `admit`, `Axiom`, and `Parameter` in Rocq proof sources.

## Proof boundary

The Rocq model intentionally does not claim to prove cryptographic collision resistance, canonical serialization, storage durability, clock correctness, or that numeric digests correspond to production cryptographic digests. Those remain implementation and assurance obligations outside this formal kernel.

This means the mathematical statement is a conditional system invariant: once production components correctly establish the archive digests and preserve the archive, the execution boundary can operate on the compact certificate without traversing the full evidence record while retaining reconstructible authority.
