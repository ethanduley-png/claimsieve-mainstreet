From Stdlib Require Import Bool Arith Lia.

(** Narrow model for the v0.33 independent outcome boundary. Storage engines,
    consensus implementations, cryptography, clocks, networks, and provider
    behavior remain outside this proof boundary. *)

Inductive reservation_phase : Type :=
| Reserved
| Executing
| Dispatching
| Reconciled.

Definition dispatchable
  (frozen revoked : bool)
  (phase : reservation_phase) : bool :=
  negb frozen && negb revoked &&
  match phase with
  | Executing => true
  | _ => false
  end.

Theorem freeze_before_dispatch_blocks :
  forall revoked phase,
    dispatchable true revoked phase = false.
Proof.
  intros revoked phase.
  unfold dispatchable.
  reflexivity.
Qed.

Theorem revocation_before_dispatch_blocks :
  forall frozen phase,
    dispatchable frozen true phase = false.
Proof.
  intros frozen phase.
  unfold dispatchable.
  destruct frozen; reflexivity.
Qed.

Definition strict_successor (current next : nat) : bool :=
  Nat.ltb current next.

Theorem equal_sequence_not_successor :
  forall n, strict_successor n n = false.
Proof.
  intro n.
  unfold strict_successor.
  apply Nat.ltb_irrefl.
Qed.

Theorem lower_sequence_not_successor :
  forall current next,
    next <= current ->
    strict_successor current next = false.
Proof.
  intros current next Hle.
  unfold strict_successor.
  apply Nat.ltb_ge.
  exact Hle.
Qed.

Definition provider_accepts_fence (highest candidate : nat) : bool :=
  Nat.ltb highest candidate.

Theorem stale_fence_rejected :
  forall highest candidate,
    candidate <= highest ->
    provider_accepts_fence highest candidate = false.
Proof.
  intros highest candidate Hle.
  unfold provider_accepts_fence.
  apply Nat.ltb_ge.
  exact Hle.
Qed.

Theorem larger_fence_accepted :
  forall highest candidate,
    highest < candidate ->
    provider_accepts_fence highest candidate = true.
Proof.
  intros highest candidate Hlt.
  unfold provider_accepts_fence.
  apply Nat.ltb_lt.
  exact Hlt.
Qed.

Inductive outcome : Type :=
| ConfirmedSuccess
| ConfirmedFailure
| DivergentEffect
| OutcomeUnknown.

Definition outcome_eqb (left right : outcome) : bool :=
  match left, right with
  | ConfirmedSuccess, ConfirmedSuccess => true
  | ConfirmedFailure, ConfirmedFailure => true
  | DivergentEffect, DivergentEffect => true
  | OutcomeUnknown, OutcomeUnknown => true
  | _, _ => false
  end.

Definition terminal (value : outcome) : bool :=
  match value with
  | OutcomeUnknown => false
  | _ => true
  end.

Definition rewrite_allowed (old new : outcome) : bool :=
  if terminal old then outcome_eqb old new else true.

Theorem confirmed_success_cannot_be_rewritten_as_failure :
  rewrite_allowed ConfirmedSuccess ConfirmedFailure = false.
Proof.
  reflexivity.
Qed.

Theorem confirmed_failure_cannot_be_rewritten_as_success :
  rewrite_allowed ConfirmedFailure ConfirmedSuccess = false.
Proof.
  reflexivity.
Qed.

Theorem unknown_may_be_resolved :
  forall next, rewrite_allowed OutcomeUnknown next = true.
Proof.
  intro next.
  reflexivity.
Qed.

Definition automatic_retry_allowed (_ : outcome) : bool := false.

Theorem no_outcome_authorizes_automatic_retry :
  forall value, automatic_retry_allowed value = false.
Proof.
  intro value.
  reflexivity.
Qed.

Record reservation_identity : Type := {
  permit_number : nat;
  action_number : nat;
  request_number : nat
}.

Definition same_reservation
  (left right : reservation_identity) : bool :=
  Nat.eqb (permit_number left) (permit_number right) &&
  Nat.eqb (action_number left) (action_number right) &&
  Nat.eqb (request_number left) (request_number right).

Theorem request_mutation_changes_reservation_identity :
  forall left right,
    request_number left <> request_number right ->
    same_reservation left right = false.
Proof.
  intros left right Hneq.
  unfold same_reservation.
  apply Nat.eqb_neq in Hneq.
  rewrite Hneq.
  destruct (Nat.eqb (permit_number left) (permit_number right));
  destruct (Nat.eqb (action_number left) (action_number right));
  reflexivity.
Qed.

(** The executable boundary authenticates executor commands and observer
    receipts outside this model. These booleans state the transition guards
    that the cryptographic layer must establish. *)
Definition executor_command_allowed (authenticated : bool) : bool := authenticated.

Theorem unauthenticated_executor_command_blocked :
  executor_command_allowed false = false.
Proof.
  reflexivity.
Qed.

Definition observer_outcome_allowed (authenticated : bool) : bool := authenticated.

Theorem unauthenticated_observer_outcome_blocked :
  observer_outcome_allowed false = false.
Proof.
  reflexivity.
Qed.

Definition permit_valid_at
  (valid_from expires current : nat) : bool :=
  Nat.leb valid_from current && Nat.leb current expires.

Theorem permit_after_expiry_invalid :
  forall valid_from expires current,
    expires < current ->
    permit_valid_at valid_from expires current = false.
Proof.
  intros valid_from expires current Hlate.
  unfold permit_valid_at.
  assert (Hfalse : Nat.leb current expires = false).
  { apply Nat.leb_gt. exact Hlate. }
  rewrite Hfalse.
  destruct (Nat.leb valid_from current); reflexivity.
Qed.

Theorem permit_before_start_invalid :
  forall valid_from expires current,
    current < valid_from ->
    permit_valid_at valid_from expires current = false.
Proof.
  intros valid_from expires current Hearly.
  unfold permit_valid_at.
  assert (Hfalse : Nat.leb valid_from current = false).
  { apply Nat.leb_gt. exact Hearly. }
  rewrite Hfalse.
  reflexivity.
Qed.

(** v0.33 independent outcome boundary. Executor statements are deliberately
    not an input capable of establishing a terminal outcome. *)
Inductive executor_claim : Type :=
| ExecutorAccepted
| ExecutorRejected
| ExecutorTimeout
| NoExecutorClaim.

Inductive provider_observation : Type :=
| NoProviderRecord
| ProviderRejected
| ProviderAcceptedExact
| ProviderAcceptedDivergent
| ProviderConflicting.

Definition reconcile_from_independent_provider
  (_ : executor_claim)
  (observation : provider_observation) : outcome :=
  match observation with
  | NoProviderRecord => OutcomeUnknown
  | ProviderRejected => ConfirmedFailure
  | ProviderAcceptedExact => ConfirmedSuccess
  | ProviderAcceptedDivergent => DivergentEffect
  | ProviderConflicting => OutcomeUnknown
  end.

Theorem no_provider_record_is_unknown_regardless_of_executor_claim :
  forall claim,
    reconcile_from_independent_provider claim NoProviderRecord = OutcomeUnknown.
Proof.
  intro claim.
  destruct claim; reflexivity.
Qed.

Theorem signed_executor_rejection_does_not_confirm_failure :
  reconcile_from_independent_provider ExecutorRejected NoProviderRecord = OutcomeUnknown.
Proof.
  reflexivity.
Qed.

Theorem conflicting_provider_evidence_remains_unknown :
  forall claim,
    reconcile_from_independent_provider claim ProviderConflicting = OutcomeUnknown.
Proof.
  intro claim.
  destruct claim; reflexivity.
Qed.

(** Reconciliation and containment are separate decisions. Provider conflict
    remains OutcomeUnknown but still requires containment, while an independently
    observed divergent effect both reconciles as DivergentEffect and requires
    containment. This prevents a terminal classification from silently leaving
    authority active. *)
Definition observation_requires_containment
  (observation : provider_observation) : bool :=
  match observation with
  | ProviderAcceptedDivergent => true
  | ProviderConflicting => true
  | _ => false
  end.

Definition campaign_active_after_observation
  (was_active : bool)
  (observation : provider_observation) : bool :=
  was_active && negb (observation_requires_containment observation).

Theorem divergent_provider_observation_requires_containment :
  observation_requires_containment ProviderAcceptedDivergent = true.
Proof.
  reflexivity.
Qed.

Theorem conflicting_provider_observation_requires_containment :
  observation_requires_containment ProviderConflicting = true.
Proof.
  reflexivity.
Qed.

Theorem contained_observation_cannot_leave_campaign_active :
  forall was_active observation,
    observation_requires_containment observation = true ->
    campaign_active_after_observation was_active observation = false.
Proof.
  intros was_active observation Hcontain.
  unfold campaign_active_after_observation.
  rewrite Hcontain.
  destruct was_active; reflexivity.
Qed.

Theorem divergent_effect_cannot_leave_campaign_active :
  forall claim was_active,
    reconcile_from_independent_provider claim ProviderAcceptedDivergent = DivergentEffect /\
    campaign_active_after_observation was_active ProviderAcceptedDivergent = false.
Proof.
  intros claim was_active.
  split.
  - destruct claim; reflexivity.
  - destruct was_active; reflexivity.
Qed.

Theorem conflicting_evidence_is_unknown_and_contained :
  forall claim was_active,
    reconcile_from_independent_provider claim ProviderConflicting = OutcomeUnknown /\
    campaign_active_after_observation was_active ProviderConflicting = false.
Proof.
  intros claim was_active.
  split.
  - destruct claim; reflexivity.
  - destruct was_active; reflexivity.
Qed.

Theorem exact_success_does_not_force_containment :
  forall was_active,
    campaign_active_after_observation was_active ProviderAcceptedExact = was_active.
Proof.
  intro was_active.
  destruct was_active; reflexivity.
Qed.

(** A transport replay is not a new logical action. It is permitted only for
    the same reservation, key, request, endpoint, and account, while authority
    remains active, the provider contract guarantees idempotency, the retention
    window remains active, and the replay budget is not exhausted. *)
Record replay_context : Type := {
  replay_outcome_unknown : bool;
  replay_same_reservation : bool;
  replay_same_key : bool;
  replay_same_request : bool;
  replay_same_endpoint : bool;
  replay_same_account : bool;
  replay_authority_active : bool;
  replay_provider_guarantee : bool;
  replay_elapsed : nat;
  replay_retention : nat;
  replay_count : nat;
  replay_limit : nat
}.

Definition transport_replay_allowed (context : replay_context) : bool :=
  replay_outcome_unknown context &&
  replay_same_reservation context &&
  replay_same_key context &&
  replay_same_request context &&
  replay_same_endpoint context &&
  replay_same_account context &&
  replay_authority_active context &&
  replay_provider_guarantee context &&
  Nat.ltb (replay_elapsed context) (replay_retention context) &&
  Nat.ltb (replay_count context) (replay_limit context).

Theorem revoked_authority_blocks_transport_replay :
  forall context,
    replay_authority_active context = false ->
    transport_replay_allowed context = false.
Proof.
  intros context Hrevoked.
  unfold transport_replay_allowed.
  rewrite Hrevoked.
  repeat rewrite Bool.andb_false_r.
  reflexivity.
Qed.

Theorem changed_request_blocks_transport_replay :
  forall context,
    replay_same_request context = false ->
    transport_replay_allowed context = false.
Proof.
  intros context Hchanged.
  unfold transport_replay_allowed.
  rewrite Hchanged.
  repeat rewrite Bool.andb_false_r.
  reflexivity.
Qed.

Theorem expired_retention_blocks_transport_replay :
  forall context,
    replay_retention context <= replay_elapsed context ->
    transport_replay_allowed context = false.
Proof.
  intros context Hexpired.
  unfold transport_replay_allowed.
  assert (Hfalse : Nat.ltb (replay_elapsed context) (replay_retention context) = false).
  { apply Nat.ltb_ge. exact Hexpired. }
  rewrite Hfalse.
  repeat rewrite Bool.andb_false_r.
  reflexivity.
Qed.
