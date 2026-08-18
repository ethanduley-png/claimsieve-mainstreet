# Observer Receipt v2 Validation Contract

Status: candidate interoperability evidence

ClaimSieve treats the observer receipt as independent evidence about the external effect. The executor may report what it attempted, but executor evidence does not determine the terminal reconciliation class.

The authoritative wire contract is `schemas/observer-receipt-v2.schema.json`. The shared signed interoperability fixture is `vectors/valid_evidence_bundle_observer_v2.json`.

The validation path intentionally uses multiple boundaries:

1. The durable Python observer emits and verifies the v2 receipt semantics.
2. The portable Python verifier rejects unknown fields, invalid signatures, broken reservation/campaign/permit bindings, and invalid provider-record/outcome combinations.
3. The Rust protocol and runtime use the same v2 field shape and `observer-receipt-v2` signing domain.
4. The Rust portable verifier consumes the Python-generated shared v2 evidence bundle rather than a Rust-only self-generated fixture.
5. The durable red-team gate executes the shared v2 contract check: it requires exactly one v2 receipt, an exact match to the authoritative schema fields, and zero portable-verifier errors. The validated run reports 29 scenarios, 26 blocked or detected, 0 bypasses, and 3 infrastructure limitations.
6. The strict Rust workflow independently runs formatting, Clippy with warnings denied, and workspace tests that include the shared vector.

The durable containment boundary consumes this authenticated observation path. An independently classified divergent effect is a containment event; executor disagreement alone is not.

This is evidence of tested cross-language receipt-contract parity for the covered fixture and adversarial cases. It is not a claim that provider behavior, cryptography, transport, database durability, or observer infrastructure independence has been formally proven.
