# ADR-008: in-toto is an interoperability layer, not ClaimSieve runtime authority

Status: Proposed

## Context

ClaimSieve already uses native signed records for policy decisions, permits, execution receipts, observer receipts, durable reservation state, and four-ledger evidence. The repository also contains `provenance/in-toto.layout.json`, but that file is a release/build layout template rather than a runtime authorization mechanism.

The current in-toto Attestation Framework uses Statement v1 to bind typed predicates to immutable subjects and recommends an authenticated envelope such as DSSE. In May 2026, in-toto issue #554 proposed an `agent-decision/v0.1` predicate for AI-agent policy decisions. That proposal is open and is not an adopted in-toto standard.

ClaimSieve's runtime semantics are materially richer than the proposed `agent-decision` shape. A native permit binds the exact proposal, action, destination, parameters, policy, signed policy, predecessor/current campaign state, evidence root, decision, approval, validity window, nonce, authority identity, and single-use constraint. Execution and independently observed outcome are separate records.

## Decision

1. Native ClaimSieve records remain the only source of runtime authority.
2. in-toto is used only as an interoperability and evidence-export layer in this increment.
3. Export occurs only after a native ClaimSieve record exists. Export functions are pure and have no execution capability.
4. Exported objects are in-toto Statement v1 payloads only. They are not DSSE envelopes and MUST NOT be described as in-toto-authenticated attestations until a separate envelope/signature implementation is added and verified.
5. Native ClaimSieve signatures are carried inside the predicate as properties of the source record and are explicitly labeled `claimsieve-native`. The exporter does not verify them and marks `signature_verification: NOT_PERFORMED`. They do not authenticate the in-toto Statement itself.
6. Each export includes a subject for the immutable native record digest. When an action digest is available, a second subject binds the Statement to that action digest.
7. Experimental ClaimSieve predicate URIs use the repository's existing `claimsieve.example` namespace. They are not registered in the in-toto predicate registry.
8. No inbound path from an arbitrary in-toto Statement to ClaimSieve permit issuance or execution is authorized by this ADR.
9. The open `agent-decision/v0.1` proposal is treated as research input only. ClaimSieve will not fabricate missing `agent_id`, tool-call, wall-clock, or policy-evaluation fields merely to claim compatibility.
10. The existing release/build in-toto layout remains separate from runtime attestation interoperability.
11. Cross-language conformance requirements are defined separately in ADR-009; satisfying them does not promote in-toto Statements into authority artifacts.

## Exported predicate types

- `https://claimsieve.example/attestation/authorization-permit/v0.1`
- `https://claimsieve.example/attestation/execution-attempt/v0.1`
- `https://claimsieve.example/attestation/outcome-observation/v0.1`

## Security properties preserved

The permit export preserves destination and parameter binding, evidence and approval commitments, policy and signed-policy commitments, predecessor/current campaign state, validity bounds, nonce, and single-use metadata.

The execution export preserves request binding, idempotency key, fencing token, containment epoch, provider status, provider identifier, and attempt sequence.

The observation export preserves independent reconciliation state, provider-record digest, observed action digest when known, receipt-conflict state, and observation sequence. `OUTCOME_UNKNOWN` remains representable without inventing an observed action.

## Threats and mitigations

### Semantic truncation

Risk: an external consumer sees an allow/deny-style record and assumes it captures the full ClaimSieve authority chain.

Mitigation: export native record digests plus ClaimSieve-specific predicates; do not collapse permits into the proposed `agent-decision` predicate.

### Signature confusion

Risk: a consumer mistakes the embedded native signature for an in-toto envelope signature or assumes the exporter verified the native signature.

Mitigation: payload-only export; explicit `signature_format: claimsieve-native`; explicit `signature_verification: NOT_PERFORMED`; no `payload`, `payloadType`, or `signatures` fields.

### Subject substitution

Risk: an exporter binds the predicate to a malformed or attacker-selected digest.

Mitigation: fail closed unless every exported security-relevant digest matches `sha256:<64 lowercase hex>`; the interoperability verifier also checks that native/action subjects match predicate commitments.

### Replay or stale authority

Risk: portable evidence is misused as executable authority.

Mitigation: exported Statements are non-authoritative; ClaimSieve's native permit verification, durable reservation, sequence validity, fencing, containment epoch, and single-use rules remain mandatory.

### Upstream RFC drift

Risk: ClaimSieve accidentally treats an evolving proposal as a stable standard.

Mitigation: no dependency on issue #554 schema in the runtime path; compatibility is reviewed separately before any future adapter is added.

## Consequences

This creates a narrow standards bridge without changing the trusted computing base for authorization or execution. It also gives future DSSE/Sigstore work a clean boundary: authenticate exported Statements only after the semantics and signer trust model are independently reviewed.

## Review gates before promotion

- Maintain closed JSON Schemas for the three experimental predicates.
- Maintain deterministic cross-language conformance vectors under ADR-009.
- Run the full Python, Rust, Rocq, Node, and adversarial gates after integration.
- Add DSSE only with a distinct signing/verifying design and explicit trust-root handling.
- Re-review the current status of in-toto issue #554 before claiming compatibility.
- Obtain independent security review of the semantic mapping before using exported attestations in production policy decisions.

## References

- https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md
- https://github.com/in-toto/attestation/blob/main/spec/v1/envelope.md
- https://github.com/in-toto/attestation/issues/554
