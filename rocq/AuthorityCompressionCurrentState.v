From Stdlib Require Import Bool Arith.
From ClaimSieve Require Import AuthorityCompression AuthorityCompressionAuthenticity.

(** Historical authority and current executability are intentionally distinct.

    A signed permit proves that authority existed at issuance. It cannot, by
    itself, prove that authority remains current after issuance. Revocation,
    policy replacement, identity disablement, campaign suspension, and global
    freeze therefore arrive from a separately trusted current-state boundary.

    This module leaves the original compact certificate model intact and adds
    current state as a dominating execution predicate. In particular, an old
    certificate whose embedded [cert_revoked] bit is false can still be rejected
    by a later current revocation. *)

Record current_authority_state : Type := {
  current_policy_digest : nat;
  current_identity_digest : nat;
  current_policy_active : bool;
  current_identity_active : bool;
  current_campaign_active : bool;
  current_execution_frozen : bool;
  current_campaign_suspended : bool;
  current_permit_revoked : bool;
  current_permit_consumed : bool
}.

Definition current_state_allows
  (certificate : authority_certificate)
  (current : current_authority_state) : bool :=
  Nat.eqb (cert_policy_digest certificate) (current_policy_digest current) &&
  (Nat.eqb (cert_identity_digest certificate) (current_identity_digest current) &&
  (current_policy_active current &&
  (current_identity_active current &&
  (current_campaign_active current &&
  (negb (current_execution_frozen current) &&
  (negb (current_campaign_suspended current) &&
  (negb (current_permit_revoked current) &&
   negb (current_permit_consumed current)))))))).

Definition executable_now
  (envelope : authenticated_authority_envelope)
  (candidate : execution_candidate)
  (current : current_authority_state) : bool :=
  verify_authenticated_compact envelope candidate &&
  current_state_allows (envelope_certificate envelope) current.

Theorem current_state_is_additional_authority_boundary :
  forall envelope candidate current,
    executable_now envelope candidate current = true ->
    verify_authenticated_compact envelope candidate = true.
Proof.
  intros envelope candidate current Hexecute.
  unfold executable_now in Hexecute.
  apply Bool.andb_true_iff in Hexecute.
  destruct Hexecute as [Hauthenticated _].
  exact Hauthenticated.
Qed.

Theorem current_revocation_blocks_execution :
  forall envelope candidate current,
    current_permit_revoked current = true ->
    executable_now envelope candidate current = false.
Proof.
  intros envelope candidate current Hrevoked.
  unfold executable_now, current_state_allows.
  rewrite Hrevoked.
  repeat rewrite Bool.andb_false_r.
  destruct (verify_authenticated_compact envelope candidate); reflexivity.
Qed.

Theorem current_consumption_blocks_execution :
  forall envelope candidate current,
    current_permit_consumed current = true ->
    executable_now envelope candidate current = false.
Proof.
  intros envelope candidate current Hconsumed.
  unfold executable_now, current_state_allows.
  rewrite Hconsumed.
  repeat rewrite Bool.andb_false_r.
  destruct (verify_authenticated_compact envelope candidate); reflexivity.
Qed.

Theorem current_policy_inactive_blocks_execution :
  forall envelope candidate current,
    current_policy_active current = false ->
    executable_now envelope candidate current = false.
Proof.
  intros envelope candidate current Hinactive.
  unfold executable_now, current_state_allows.
  rewrite Hinactive.
  repeat rewrite Bool.andb_false_r.
  destruct (verify_authenticated_compact envelope candidate); reflexivity.
Qed.

Theorem current_identity_inactive_blocks_execution :
  forall envelope candidate current,
    current_identity_active current = false ->
    executable_now envelope candidate current = false.
Proof.
  intros envelope candidate current Hinactive.
  unfold executable_now, current_state_allows.
  rewrite Hinactive.
  repeat rewrite Bool.andb_false_r.
  destruct (verify_authenticated_compact envelope candidate); reflexivity.
Qed.

Theorem current_campaign_inactive_blocks_execution :
  forall envelope candidate current,
    current_campaign_active current = false ->
    executable_now envelope candidate current = false.
Proof.
  intros envelope candidate current Hinactive.
  unfold executable_now, current_state_allows.
  rewrite Hinactive.
  repeat rewrite Bool.andb_false_r.
  destruct (verify_authenticated_compact envelope candidate); reflexivity.
Qed.

Theorem current_global_freeze_blocks_execution :
  forall envelope candidate current,
    current_execution_frozen current = true ->
    executable_now envelope candidate current = false.
Proof.
  intros envelope candidate current Hfrozen.
  unfold executable_now, current_state_allows.
  rewrite Hfrozen.
  repeat rewrite Bool.andb_false_r.
  destruct (verify_authenticated_compact envelope candidate); reflexivity.
Qed.

Theorem current_campaign_suspension_blocks_execution :
  forall envelope candidate current,
    current_campaign_suspended current = true ->
    executable_now envelope candidate current = false.
Proof.
  intros envelope candidate current Hsuspended.
  unfold executable_now, current_state_allows.
  rewrite Hsuspended.
  repeat rewrite Bool.andb_false_r.
  destruct (verify_authenticated_compact envelope candidate); reflexivity.
Qed.

Theorem current_policy_replacement_blocks_execution :
  forall envelope candidate current,
    cert_policy_digest (envelope_certificate envelope) <>
      current_policy_digest current ->
    executable_now envelope candidate current = false.
Proof.
  intros envelope candidate current Hneq.
  unfold executable_now, current_state_allows.
  apply Nat.eqb_neq in Hneq.
  rewrite Hneq.
  destruct (verify_authenticated_compact envelope candidate); reflexivity.
Qed.

Theorem current_identity_replacement_blocks_execution :
  forall envelope candidate current,
    cert_identity_digest (envelope_certificate envelope) <>
      current_identity_digest current ->
    executable_now envelope candidate current = false.
Proof.
  intros envelope candidate current Hneq.
  unfold executable_now, current_state_allows.
  apply Nat.eqb_neq in Hneq.
  rewrite Hneq.
  destruct (verify_authenticated_compact envelope candidate); reflexivity.
Qed.

(** Current invalidity never rewrites the historical adjudication. The archive
    remains the source of the question "was this authorized then?" while current
    state answers "may this execute now?". *)
Theorem revocation_does_not_rewrite_historical_authority :
  forall archive candidate valid_from expires_at current,
    reconstruct_authority archive = true ->
    current_permit_revoked current = true ->
    reconstruct_authority archive = true /\
    executable_now
      {| envelope_certificate :=
           compress_authority archive valid_from expires_at;
         envelope_authentic := true |}
      candidate
      current = false.
Proof.
  intros archive candidate valid_from expires_at current Hhistorical Hrevoked.
  split.
  - exact Hhistorical.
  - apply current_revocation_blocks_execution.
    exact Hrevoked.
Qed.

Theorem global_freeze_does_not_rewrite_historical_authority :
  forall archive candidate valid_from expires_at current,
    reconstruct_authority archive = true ->
    current_execution_frozen current = true ->
    reconstruct_authority archive = true /\
    executable_now
      {| envelope_certificate :=
           compress_authority archive valid_from expires_at;
         envelope_authentic := true |}
      candidate
      current = false.
Proof.
  intros archive candidate valid_from expires_at current Hhistorical Hfrozen.
  split.
  - exact Hhistorical.
  - apply current_global_freeze_blocks_execution.
    exact Hfrozen.
Qed.

Theorem current_execution_implies_historical_authority :
  forall archive candidate valid_from expires_at current,
    executable_now
      {| envelope_certificate :=
           compress_authority archive valid_from expires_at;
         envelope_authentic := true |}
      candidate
      current = true ->
    reconstruct_authority archive = true.
Proof.
  intros archive candidate valid_from expires_at current Hexecute.
  apply current_state_is_additional_authority_boundary in Hexecute.
  apply authenticated_execution_implies_compact_execution in Hexecute.
  exact
    (certificate_soundness
      archive candidate valid_from expires_at Hexecute).
Qed.
