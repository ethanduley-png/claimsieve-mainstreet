# ADR-009: Cross-language in-toto interoperability is conformance-tested, not authoritative

Status: Proposed

## Context

ADR-008 established in-toto as an evidence-export boundary rather than ClaimSieve runtime authority. The next risk is semantic drift between implementations: Python could export one Statement shape while Rust or another consumer interprets a subtly different shape.

Cryptographic signing does not repair semantic disagreement. A signed but differently interpreted object is still unsafe.

## Decision

1. The repository commits one deterministic interoperability vector at `vectors/in_toto_interop_v1.json`.
2. The vector contains both native ClaimSieve source records and their expected Statement v1 exports.
3. Python tests must regenerate the committed Statements exactly from the native records.
4. Every exported predicate must validate against a closed JSON Schema.
5. The strict Python interoperability verifier must reject unknown predicate versions, unknown Statement fields, malformed subjects, subject substitution, unsupported signature metadata, and fabricated observed-action subjects.
6. Rust consumes the committed vector only as a conformance test in this increment. Rust does not gain authority to issue, accept, or execute from in-toto Statements.
7. Rust tests assert Statement and predicate versions, source-record subject binding, action-subject binding, and preservation of selected authorization/execution/observation boundaries.
8. DSSE, Sigstore, and native-signature verification remain out of scope for this increment.

## Security consequence

The interoperability surface now has an executable specification shared by Python and Rust. A future implementation change that alters the exported semantic object must deliberately update the vector and pass both language suites.

This does not make the vector an authorization artifact. Native ClaimSieve verification, durable state, permit single-use enforcement, fencing, containment, executor restrictions, and independent observation remain mandatory.

## Review gate

Before any in-toto Statement can influence a production policy decision:

- add authenticated envelope verification with a separate trust model;
- verify native ClaimSieve signatures before relying on embedded source-record claims;
- add key-rotation and revocation semantics;
- adversarially test downgrade, replay, mix-and-match, and trust-root substitution;
- obtain independent security review of the mapping and signer separation.
