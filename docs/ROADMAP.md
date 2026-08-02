# Recommended Roadmap After v0.34.0

## Gate 1 — Native truth

Status: completed locally on 2026-08-02; independent clean-extraction reproduction and signed provenance remain future work.

1. Compile unchanged Rust and Rocq sources.
2. Preserve every failure.
3. Generate a resolved Rust lockfile.
4. Run Rust format, Clippy, and tests.
5. Compile Rocq files and preserve `Print Assumptions` output.
6. Repackage only after clean extraction reproduces the native gates.

Success criterion achieved locally: native evidence exists, the Rust lockfile is resolved, and source inspection no longer substitutes for compilation.

## Gate 2 — Semantic differential harness

1. Make Python and Rust consume `vectors/outcome_semantics_vectors.json`.
2. Emit normalized classification and receipt artifacts.
3. Validate both against the same schemas.
4. Compare canonical bytes, domain-separated signatures, unknown-state behavior, replay guards, and containment decisions.
5. Preserve disagreements before patching.

Success criterion: no unexplained cross-language divergence for the defined vector set.

## Gate 3 — Rocq refinement boundary

1. Map every theorem precondition to an executable guard.
2. Identify implementation inputs that decide which abstract constructor is used.
3. Add negative fixtures for misclassification of provider evidence.
4. Keep parsing, crypto, persistence, and deployment outside the proof claim unless separately modeled.

Success criterion: formal claims identify their refinement obligations rather than implying end-to-end proof.

## Gate 4 — Authorized live provider experiment

Use a dedicated Stripe test account and harmless object type. Inject a controlled connection interruption, preserve one idempotency key, perform exact replay, independently retrieve the object, validate webhook signatures, test duplicate and reordered events, and clean up.

Success criterion: a complete provider trace distinguishes transport response, provider state, webhook evidence, and terminal reconciliation without creating a second logical action.

## Gate 5 — Independent observer failure domain

Move observation to separate credentials, process, host, and administrative policy. Add read-only provider scopes and conflict handling between read-back and webhook evidence.

Success criterion: executor-host compromise cannot control or suppress every observation channel.

## Gate 6 — Distributed durable state

Select exactly one linearizable backend. Test leader loss, minority partition, stale clients, fencing, revocation races, crash recovery, backup restore, and operator error.

Success criterion: one campaign successor and one dispatch reservation survive real multi-node failure.

## Gate 7 — MainStreet product proof

Build the no-send tax-notice workspace and test it with consented users. Measure whether they can understand uncertainty, prepare evidence-linked packets, obtain professional escalation, and distinguish draft, submission, acknowledgment, and resolution.

Success criterion: product usefulness advances alongside the kernel.
