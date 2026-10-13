From Stdlib Require Import Bool.
From ClaimSieve Require Import AuthorityCompression AuthorityCompressionNecessity.

(** Authentication wrapper for compact authority certificates.

    The production ClaimSieve permit path verifies an authority signature against
    an external trust root before permit bindings are accepted. This module
    models only the Boolean result of that cryptographic/trust-root verification.
    It does not attempt to prove Ed25519 or trust-root implementation correctness.

    The split is intentional:

      external cryptographic verifier -> authenticated envelope -> verify_compact

    [verify_compact] remains the small deterministic semantics kernel. *)

Record authenticated_authority_envelope : Type := {
  envelope_certificate : authority_certificate;
  envelope_authentic : bool
}.

Definition verify_authenticated_compact
  (envelope : authenticated_authority_envelope)
  (candidate : execution_candidate) : bool :=
  envelope_authentic envelope &&
  verify_compact (envelope_certificate envelope) candidate.

Theorem unauthenticated_envelope_fails_closed :
  forall envelope candidate,
    envelope_authentic envelope = false ->
    verify_authenticated_compact envelope candidate = false.
Proof.
  intros envelope candidate Hauth.
  unfold verify_authenticated_compact.
  rewrite Hauth.
  reflexivity.
Qed.

Theorem authenticated_execution_implies_compact_execution :
  forall envelope candidate,
    verify_authenticated_compact envelope candidate = true ->
    verify_compact (envelope_certificate envelope) candidate = true.
Proof.
  intros envelope candidate Hverify.
  unfold verify_authenticated_compact in Hverify.
  apply Bool.andb_true_iff in Hverify.
  destruct Hverify as [_ Hcompact].
  exact Hcompact.
Qed.

Theorem authenticated_compressed_execution_implies_original_decision_allow :
  forall archive candidate valid_from expires_at,
    verify_authenticated_compact
      {| envelope_certificate :=
           compress_authority archive valid_from expires_at;
         envelope_authentic := true |}
      candidate = true ->
    decide
      (archive_policy archive)
      (archive_proposal archive)
      (archive_campaign archive) = Allow.
Proof.
  intros archive candidate valid_from expires_at Hverify.
  apply execution_implies_original_decision_allow.
  unfold verify_authenticated_compact in Hverify.
  simpl in Hverify.
  exact Hverify.
Qed.

(** A raw certificate can satisfy the semantic verifier even when no trusted
    authority signature has established its provenance. The outer authenticity
    gate is therefore independently necessary at the system boundary. *)
Definition unauthenticated_semantically_valid_envelope :
  authenticated_authority_envelope :=
  {| envelope_certificate := necessity_base_certificate;
     envelope_authentic := false |}.

Theorem authenticity_gate_is_necessary :
  verify_compact necessity_base_certificate necessity_good_candidate = true /\
  verify_authenticated_compact
    unauthenticated_semantically_valid_envelope
    necessity_good_candidate = false.
Proof.
  reflexivity.
Qed.

(** Once authenticity has been established, the outer wrapper is semantically
    transparent to the compact verifier. *)
Theorem authentic_wrapper_is_transparent :
  forall certificate candidate,
    verify_authenticated_compact
      {| envelope_certificate := certificate;
         envelope_authentic := true |}
      candidate =
    verify_compact certificate candidate.
Proof.
  intros certificate candidate.
  reflexivity.
Qed.
