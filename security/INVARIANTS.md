# Normative Invariants

Identifiers are stable and referenced by tests, reason codes, and formal lemmas.

## Authority and execution

* **I-001 Proposal is not permission.** No proposal is executable without a valid authority permit.
* **I-002 Exact action binding.** Any change to destination, method, parameters, effect class, tenant, principal, campaign, evidence root, authorizing decision, approval, or policy invalidates the permit.
* **I-002A Independent adjudication at issuance.** A caller-supplied `ALLOW` has no authority. The permit signer re-runs the deterministic kernel over the exact proposal, policy, evidence, prior campaign state, and sequence and requires exact decision equality.
* **I-002B Nonce-separated permit identity.** Reissuing the same eligible inputs with a fresh nonce produces a different permit identifier; permit identity is never proposal ID alone.
* **I-003 One use.** A permit can produce at most one successful reservation.
* **I-004 Revocation dominance.** A revoked permit or suspended campaign cannot execute even if previously approved.
* **I-005 Bounded validity.** Permit sequence validity is checked at reservation and immediately before execution.
* **I-006 No self-authorization.** The proposal writer cannot be the authority signer or executor signer for the same action. Critical-role separation compares public-key material, not merely caller-controlled key identifiers.
* **I-007 No direct MainStreet effects.** MainStreet and OpenClaw have no live connector capability.
* **I-008 External trust root.** A portable bundle cannot establish the organizational keys used to trust that same bundle.

## Campaign and trajectory

* **I-010 Durable campaign limits.** New sessions, models, workers, or sandboxes do not reset campaign state.
* **I-011 Parent lineage.** Every child action and session links to the durable campaign and its parent.
* **I-012 Purpose preservation.** The declared subgoal and expected effect must be allowed by the root objective policy.
* **I-013 New boundary authorization.** Crossing a trust domain requires explicit policy and, where configured, fresh human approval.
* **I-014 Credential quarantine.** Discovered credentials cannot be used by the discovering campaign without a separate incident-response workflow.
* **I-015 Observer tampering trips containment.** Attempts to disable observation, policy, or containment suspend the campaign.
* **I-016 Immediate circuit breaker.** The action that exceeds a campaign limit causes suspension in the same committed transition, not on a later request.
* **I-017 Single campaign successor.** At most one candidate transition may commit from a durable predecessor; permit issuance follows the successful commit.

## Evidence and approval

* **I-020 Evidence completeness.** Required evidence types and source identities must be present.
* **I-020A Exact evidence snapshot.** Proposal evidence references are unique and equal the complete set of evidence-item digests; omission, addition, duplication, or substitution fails closed.
* **I-020B Trusted evidence issuer.** Each required evidence type must come from a policy-allowed authenticated source identity and match the exact action subject and destination where applicable.
* **I-021 Evidence freshness.** Evidence sequence and policy version must satisfy the action-specific window.
* **I-021A Decision snapshot binding.** Permit issuance must use the exact evidence root and logical sequence evaluated by the authorizing decision.
* **I-022 Independent approval signature.** Human approval is an Ed25519-signed artifact from an approved, separately controlled key and binds the exact proposal digest, display digest, approver identity, and validity sequence.
* **I-023 No post-approval mutation.** Any material change requires a new approval.
* **I-024 Explicit uncertainty.** Missing, contradictory, or unverified evidence cannot be silently converted to certainty.

## Execution and reconciliation

* **I-030 Reservation before side effect.** Executor invocation occurs only after a successful atomic reservation.
* **I-031 Provider idempotency binding.** Where supported, provider idempotency key derives from the permit identifier.
* **I-032 Unknown is not failure.** An ambiguous outcome is `OUTCOME_UNKNOWN`, not safely retryable failure.
* **I-032A New logical retry requires new authority.** No outcome class independently authorizes a new logical action attempt. A changed request, destination, account, endpoint, reservation, or idempotency key requires a new proposal and permit.
* **I-032B Same-dispatch transport replay is not new authority.** A byte-identical resend of an already authorized dispatch is permitted only while outcome remains unknown, current authority remains active, reservation, key, request digest, endpoint, and provider account are unchanged, the provider contract guarantees idempotent replay, the retention window is still guaranteed, and a bounded replay budget remains.
* **I-033 Divergence quarantine.** Observed effect differing from permitted effect suspends retries and triggers containment.
* **I-033A Receipt semantic integrity.** Executor and observer receipts bind trace, permit, reservation, action, provider status, reconciliation class, and observed effect; signatures alone are insufficient.
* **I-033B Independent outcome authority.** Executor receipts are audit evidence only. Terminal success or failure requires evidence obtained through a separately controlled read path; absence of independent provider evidence remains `OUTCOME_UNKNOWN` regardless of an executor signature.
* **I-033C Contradictory provider evidence remains unknown.** A provider record that simultaneously indicates rejection and an effect, or acceptance without any independently readable effect, cannot establish success or failure. The case remains unknown and triggers containment for evidence conflict.
* **I-034 Compensation is separately authorized.** A compensating action is a new proposal, not implicit rollback authority.

## Audit and supply chain

* **I-040 Separate ledgers.** Proposal, evidence, decision, and execution records have distinct writers and chains.
* **I-041 Append-only verification.** Record deletion, reordering, substitution, or previous-hash mutation is detectable.
* **I-042 Cross-ledger trace integrity.** A complete execution has linked proposal, evidence, decision, reservation, attempt, and observation records.
* **I-042A Exact artifact inclusion.** A valid chain containing an unrelated artifact does not satisfy the bundle. Each exported artifact must appear byte-for-byte canonically in its designated ledger with its exact payload digest.
* **I-043 Signed release provenance.** Production artifacts require source revision, builder identity, materials, subject digest, generated SBOM, and signature. This release does not satisfy that production condition.
* **I-045 Witness binding.** Exported manifest and ledger heads require a trusted witness signature independent of bundle-supplied trust.
* **I-044 Fail closed on unknown schema or algorithm.** Unsupported versions and cryptographic algorithms are rejected.
