# ClaimSieve × in-toto interoperability note

## Scope

This note describes a narrow evidence-export bridge. It does not make in-toto part of ClaimSieve's permit-issuance path, does not replace native ClaimSieve signatures, and does not authorize execution from an arbitrary attestation.

## Current external facts

As reviewed on 2026-08-27:

- The in-toto Attestation Framework documentation identifies v1.2 as the latest v1 specification while retaining `_type: https://in-toto.io/Statement/v1`.
- Statement v1 binds one or more immutable subjects to a typed predicate.
- The envelope specification recommends DSSE and requires authentication semantics separate from the Statement payload.
- in-toto issue #554, opened 2026-05-19, proposes `agent-decision/v0.1` for AI-agent policy decisions. The issue remains open and the predicate is not treated here as an adopted standard.

## Existing repository state

`provenance/in-toto.layout.json` is a legacy release/build template. It has empty key sets and empty step public-key lists, and its own readme identifies it as a template. `provenance/README.md` separately states that the in-toto, SLSA, and CycloneDX files are templates/source inventories and are not signed attestations.

The runtime authority chain is separate:

1. native proposal and evidence
2. policy decision
3. signed ClaimSieve permit
4. durable reservation / fencing / containment checks
5. executor receipt
6. independent observer receipt
7. reconciliation and ledgers

## Runtime mapping

| Native ClaimSieve record | Experimental in-toto predicate | Subjects | Important semantics preserved |
| --- | --- | --- | --- |
| `claimsieve.permit.v1` | `authorization-permit/v0.1` | native permit digest + authorized action digest | proposal, destination, parameters, policy, signed policy, predecessor/current state, evidence root, decision, approval, validity, nonce, max uses |
| `claimsieve.executor_receipt.v2` | `execution-attempt/v0.1` | native executor-receipt digest + attempted action digest | request digest, idempotency key, fencing token, containment epoch, provider status/id, attempt sequence |
| `claimsieve.observer_receipt.v2` | `outcome-observation/v0.1` | native observer-receipt digest + observed action digest when known | provider-record digest, observed action, reconciliation, conflict flag, observation sequence |

Each predicate also carries the digest, key identifier, and signature of the native source record under `native_record`. That native signature is evidence about the ClaimSieve source object; it is not an in-toto envelope signature. The exporter does not verify the embedded native signature and marks `signature_verification: NOT_PERFORMED`; native signature verification remains a separate ClaimSieve verifier responsibility.

## Conformance increment

The branch now includes:

- closed JSON Schemas for all three experimental predicates;
- a deterministic vector at `vectors/in_toto_interop_v1.json` containing native source records plus expected Statement exports;
- Python tests that regenerate the committed vector exactly and validate every predicate schema;
- a strict interoperability verifier that rejects unknown predicate versions and subject/signature-shape confusion;
- Rust tests that consume the same committed vector and check version, source-record subject, action-subject, and selected boundary semantics.

Rust remains a test consumer only in this increment. No Rust runtime path accepts an in-toto Statement as authority.

## Why we do not emit the proposed agent-decision predicate yet

The open proposal records an agent identifier, principal, policy evaluations, tool calls and argument hashes, optional evaluation results/trace context, and a wall-clock decision timestamp. The native `claimsieve.decision.v1` object instead binds proposal, approval, policy, evidence root, predecessor/current campaign state, verdict, reasons, and a logical decision sequence.

Those schemas overlap but are not equivalent. In particular, ClaimSieve's native decision does not necessarily contain the proposed RFC's agent identifier, tool-call array, or wall-clock timestamp. An adapter that fills those fields from guesses or unrelated data would produce false provenance.

If compatibility is later added, it should be a separately tested mapping from an enriched runtime context that actually contains all required fields.

## Deliberate non-goals in this increment

- No DSSE signing or verification.
- No Sigstore integration.
- No native-signature verification inside the exporter.
- No inbound attestation-to-permit conversion.
- No change to ClaimSieve trust roots.
- No change to Rust or Rocq authority semantics.
- No claim of registered ClaimSieve predicate URIs.
- No claim that the open `agent-decision/v0.1` RFC is standardized.
- No claim that an exported Statement proves execution merely because an authorization Statement exists.

## Security review questions

1. Is the native record digest always computed over exactly the semantic object that native signature verification expects?
2. Should exported Statements include only the native record as subject and move action digests into references, or is the current multi-subject model preferable for policy engines?
3. Should future DSSE signing use the same identity as native ClaimSieve signing, or a separate attestation identity to preserve separation of powers?
4. How should key rotation and revocation be represented without allowing a historical Statement to become executable authority?
5. How should logical sequence time coexist with RFC 3339 wall-clock fields when interoperability requires both?
6. Can an external verifier distinguish `OUTCOME_UNKNOWN` from absence of an observer record without consulting the ClaimSieve ledger?
7. Should future Rust verification independently recompute ClaimSieve canonical source-record digests, or consume only already-verified native records from the native verifier boundary?

## Next engineering increment

After independent review of this bridge:

1. add negative Rust mutation vectors for downgrade and subject substitution;
2. decide whether Rust should independently implement source-record canonical digest verification or stay downstream of native verification;
3. design DSSE signing and verification with explicit trust-root and signer-separation rules;
4. model key rotation and revocation;
5. re-run the full adversarial suite against replay, mix-and-match, stale attestation, downgrade, and trust-root substitution attacks;
6. re-review in-toto issue #554 before any compatibility claim.

## References

- https://github.com/in-toto/attestation/blob/main/spec/README.md
- https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
- https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md
- https://github.com/in-toto/attestation/issues/554
