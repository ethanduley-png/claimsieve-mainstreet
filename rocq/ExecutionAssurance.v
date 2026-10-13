From Stdlib Require Import Bool.
From ClaimSieve Require Import DurableState.

(** Refinement connecting the independent-outcome model to the dispatch guard.
    The base DurableState model proves when provider observations require
    containment. This file proves that a contained campaign cannot remain
    dispatchable, including an action that had already reached Executing before
    the divergent or conflicting observation was recorded. *)

Definition governed_dispatchable
  (frozen revoked campaign_active : bool)
  (phase : reservation_phase) : bool :=
  campaign_active && dispatchable frozen revoked phase.

Theorem suspended_campaign_blocks_dispatch :
  forall frozen revoked phase,
    governed_dispatchable frozen revoked false phase = false.
Proof.
  intros frozen revoked phase.
  unfold governed_dispatchable.
  reflexivity.
Qed.

Theorem contained_observation_blocks_dispatch :
  forall frozen revoked was_active observation phase,
    observation_requires_containment observation = true ->
    governed_dispatchable
      frozen
      revoked
      (campaign_active_after_observation was_active observation)
      phase = false.
Proof.
  intros frozen revoked was_active observation phase Hcontain.
  unfold governed_dispatchable.
  rewrite (contained_observation_cannot_leave_campaign_active
    was_active observation Hcontain).
  reflexivity.
Qed.

Theorem divergent_observation_blocks_preexisting_executing_dispatch :
  forall frozen revoked was_active,
    governed_dispatchable
      frozen
      revoked
      (campaign_active_after_observation was_active ProviderAcceptedDivergent)
      Executing = false.
Proof.
  intros frozen revoked was_active.
  apply contained_observation_blocks_dispatch.
  reflexivity.
Qed.

Theorem conflicting_observation_blocks_preexisting_executing_dispatch :
  forall frozen revoked was_active,
    governed_dispatchable
      frozen
      revoked
      (campaign_active_after_observation was_active ProviderConflicting)
      Executing = false.
Proof.
  intros frozen revoked was_active.
  apply contained_observation_blocks_dispatch.
  reflexivity.
Qed.

Theorem exact_success_preserves_campaign_activity :
  forall was_active,
    campaign_active_after_observation was_active ProviderAcceptedExact = was_active.
Proof.
  apply exact_success_does_not_force_containment.
Qed.
