From Stdlib Require Import Bool Arith Lia List.
Import ListNotations.

(** A deliberately small formal core. It models authorization and lifecycle
    facts only. Parsing, cryptography, operating-system isolation, connectors,
    and correspondence with the Rust implementation remain trusted assumptions. *)

Inductive verdict : Type :=
| Allow
| Deny
| RequireHuman
| Quarantine
| SuspendCampaign.

Record policy : Type := {
  policy_allows_action : bool;
  policy_requires_human : bool
}.

Record proposal : Type := {
  evidence_complete : bool;
  evidence_fresh : bool;
  objective_aligned : bool;
  destination_allowed : bool;
  identity_valid : bool;
  approval_valid : bool;
  severe_risk : bool;
  credential_event : bool
}.

Record campaign : Type := {
  campaign_active : bool;
  action_count : nat;
  action_limit : nat
}.

Definition over_budget (c : campaign) : bool :=
  Nat.leb (action_limit c) (action_count c).

Definition decide (pol : policy) (p : proposal) (c : campaign) : verdict :=
  if negb (campaign_active c) then SuspendCampaign else
  if severe_risk p || credential_event p then SuspendCampaign else
  if over_budget c then SuspendCampaign else
  if negb (identity_valid p) then Deny else
  if negb (objective_aligned p) then Deny else
  if negb (destination_allowed p) then Deny else
  if negb (evidence_complete p && evidence_fresh p) then Deny else
  if negb (policy_allows_action pol) then Deny else
  if policy_requires_human pol && negb (approval_valid p)
    then RequireHuman
    else Allow.

Definition executable (v : verdict) : Prop := v = Allow.

Theorem suspended_campaign_not_executable :
  forall pol p c,
    campaign_active c = false ->
    ~ executable (decide pol p c).
Proof.
  intros pol p c Hactive Hexe.
  unfold executable, decide in Hexe.
  rewrite Hactive in Hexe.
  discriminate.
Qed.

Theorem missing_evidence_fails_closed :
  forall pol p c,
    campaign_active c = true ->
    evidence_complete p = false ->
    ~ executable (decide pol p c).
Proof.
  intros pol p c Hactive Hevidence Hexe.
  unfold executable, decide in Hexe.
  rewrite Hactive in Hexe.
  destruct (severe_risk p || credential_event p); try discriminate.
  destruct (over_budget c); try discriminate.
  destruct (identity_valid p); try discriminate.
  destruct (objective_aligned p); try discriminate.
  destruct (destination_allowed p); try discriminate.
  rewrite Hevidence in Hexe.
  discriminate.
Qed.

Theorem stale_evidence_fails_closed :
  forall pol p c,
    campaign_active c = true ->
    evidence_fresh p = false ->
    ~ executable (decide pol p c).
Proof.
  intros pol p c Hactive Hfresh Hexe.
  unfold executable, decide in Hexe.
  rewrite Hactive in Hexe.
  destruct (severe_risk p || credential_event p); try discriminate.
  destruct (over_budget c); try discriminate.
  destruct (identity_valid p); try discriminate.
  destruct (objective_aligned p); try discriminate.
  destruct (destination_allowed p); try discriminate.
  rewrite Hfresh in Hexe.
  rewrite Bool.andb_false_r in Hexe.
  discriminate.
Qed.

Theorem objective_substitution_fails_closed :
  forall pol p c,
    campaign_active c = true ->
    objective_aligned p = false ->
    ~ executable (decide pol p c).
Proof.
  intros pol p c Hactive Haligned Hexe.
  unfold executable, decide in Hexe.
  rewrite Hactive in Hexe.
  destruct (severe_risk p || credential_event p); try discriminate.
  destruct (over_budget c); try discriminate.
  destruct (identity_valid p); try discriminate.
  rewrite Haligned in Hexe.
  discriminate.
Qed.

Theorem invalid_required_approval_not_executable :
  forall pol p c,
    campaign_active c = true ->
    policy_requires_human pol = true ->
    approval_valid p = false ->
    ~ executable (decide pol p c).
Proof.
  intros pol p c Hactive Hrequired Happroval Hexe.
  unfold executable, decide in Hexe.
  rewrite Hactive in Hexe.
  destruct (severe_risk p || credential_event p); try discriminate.
  destruct (over_budget c); try discriminate.
  destruct (identity_valid p); try discriminate.
  destruct (objective_aligned p); try discriminate.
  destruct (destination_allowed p); try discriminate.
  destruct (evidence_complete p && evidence_fresh p); try discriminate.
  destruct (policy_allows_action pol); try discriminate.
  rewrite Hrequired, Happroval in Hexe.
  simpl in Hexe.
  discriminate.
Qed.

Theorem credential_event_suspends :
  forall pol p c,
    campaign_active c = true ->
    credential_event p = true ->
    decide pol p c = SuspendCampaign.
Proof.
  intros pol p c Hactive Hcredential.
  unfold decide.
  rewrite Hactive.
  destruct (severe_risk p).
  - reflexivity.
  - simpl. rewrite Hcredential. reflexivity.
Qed.

Theorem budget_survives_process_reset :
  forall c1 c2,
    action_count c1 = action_count c2 ->
    action_limit c1 = action_limit c2 ->
    campaign_active c1 = campaign_active c2 ->
    over_budget c1 = over_budget c2.
Proof.
  intros c1 c2 Hcount Hlimit Hactive.
  unfold over_budget.
  rewrite Hcount, Hlimit.
  reflexivity.
Qed.

Record permit : Type := {
  permit_action_digest : nat;
  permit_destination_digest : nat;
  permit_decision_digest : nat;
  permit_revoked : bool;
  permit_consumed : bool;
  permit_valid_from : nat;
  permit_expires_at : nat
}.

Record execution_request : Type := {
  request_action_digest : nat;
  request_destination_digest : nat;
  request_decision_digest : nat;
  request_sequence : nat
}.

Definition permit_valid (cap : permit) (req : execution_request) : bool :=
  negb (permit_revoked cap) &&
  negb (permit_consumed cap) &&
  Nat.eqb (permit_action_digest cap) (request_action_digest req) &&
  Nat.eqb (permit_destination_digest cap) (request_destination_digest req) &&
  Nat.eqb (permit_decision_digest cap) (request_decision_digest req) &&
  Nat.leb (permit_valid_from cap) (request_sequence req) &&
  Nat.leb (request_sequence req) (permit_expires_at cap).

Theorem revocation_dominates :
  forall cap req,
    permit_revoked cap = true ->
    permit_valid cap req = false.
Proof.
  intros cap req Hrevoked.
  unfold permit_valid.
  rewrite Hrevoked.
  reflexivity.
Qed.

Theorem consumed_permit_cannot_execute :
  forall cap req,
    permit_consumed cap = true ->
    permit_valid cap req = false.
Proof.
  intros cap req Hconsumed.
  unfold permit_valid.
  rewrite Hconsumed.
  destruct (permit_revoked cap); reflexivity.
Qed.

Theorem destination_mutation_invalidates :
  forall cap req,
    permit_destination_digest cap <> request_destination_digest req ->
    permit_valid cap req = false.
Proof.
  intros cap req Hneq.
  unfold permit_valid.
  apply Nat.eqb_neq in Hneq.
  rewrite Hneq.
  repeat rewrite andb_false_r.
  reflexivity.
Qed.

Theorem action_mutation_invalidates :
  forall cap req,
    permit_action_digest cap <> request_action_digest req ->
    permit_valid cap req = false.
Proof.
  intros cap req Hneq.
  unfold permit_valid.
  apply Nat.eqb_neq in Hneq.
  rewrite Hneq.
  repeat rewrite andb_false_r.
  reflexivity.
Qed.

Theorem decision_artifact_mutation_invalidates :
  forall cap req,
    permit_decision_digest cap <> request_decision_digest req ->
    permit_valid cap req = false.
Proof.
  intros cap req Hneq.
  unfold permit_valid.
  apply Nat.eqb_neq in Hneq.
  rewrite Hneq.
  repeat rewrite andb_false_r.
  reflexivity.
Qed.

Inductive outcome : Type :=
| ConfirmedSuccess
| ConfirmedFailure
| OutcomeUnknown
| DivergentEffect.

(** Automatic retry is never authorized by an outcome alone. A confirmed
    failure may justify a new proposal, but that proposal must traverse the
    complete authorization lifecycle and receive a new one-use permit. *)
Definition retry_allowed (_ : outcome) : bool := false.

Theorem unknown_outcome_never_retries :
  retry_allowed OutcomeUnknown = false.
Proof. reflexivity. Qed.

Theorem divergence_never_retries :
  retry_allowed DivergentEffect = false.
Proof. reflexivity. Qed.

Theorem confirmed_failure_requires_new_authorization :
  retry_allowed ConfirmedFailure = false.
Proof. reflexivity. Qed.

Theorem no_outcome_authorizes_automatic_retry :
  forall o, retry_allowed o = false.
Proof. intros o; destruct o; reflexivity. Qed.

(** External trust roots and role separation are modeled as explicit inputs.
    This does not prove cryptography. It proves that the abstract authorization
    predicate fails closed whenever any required trust premise is false. *)
Record trust_context : Type := {
  policy_root_trusted : bool;
  evidence_root_trusted : bool;
  authority_root_trusted : bool;
  witness_valid : bool;
  role_keys_distinct : bool
}.

Definition trust_ready (t : trust_context) : bool :=
  policy_root_trusted t &&
  evidence_root_trusted t &&
  authority_root_trusted t &&
  witness_valid t &&
  role_keys_distinct t.

Definition execution_authorized
  (t : trust_context) (v : verdict) (cap : permit) (req : execution_request) : bool :=
  trust_ready t &&
  match v with
  | Allow => permit_valid cap req
  | _ => false
  end.

Theorem untrusted_policy_root_fails_closed :
  forall t v cap req,
    policy_root_trusted t = false ->
    execution_authorized t v cap req = false.
Proof.
  intros t v cap req H.
  unfold execution_authorized, trust_ready.
  rewrite H.
  reflexivity.
Qed.

Theorem untrusted_evidence_root_fails_closed :
  forall t v cap req,
    evidence_root_trusted t = false ->
    execution_authorized t v cap req = false.
Proof.
  intros t v cap req H.
  unfold execution_authorized, trust_ready.
  destruct (policy_root_trusted t); simpl; try reflexivity.
  rewrite H. reflexivity.
Qed.

Theorem invalid_witness_fails_closed :
  forall t v cap req,
    witness_valid t = false ->
    execution_authorized t v cap req = false.
Proof.
  intros t v cap req H.
  unfold execution_authorized, trust_ready.
  destruct (policy_root_trusted t); simpl; try reflexivity.
  destruct (evidence_root_trusted t); simpl; try reflexivity.
  destruct (authority_root_trusted t); simpl; try reflexivity.
  rewrite H. reflexivity.
Qed.

Theorem collapsed_roles_fail_closed :
  forall t v cap req,
    role_keys_distinct t = false ->
    execution_authorized t v cap req = false.
Proof.
  intros t v cap req H.
  unfold execution_authorized, trust_ready.
  destruct (policy_root_trusted t); simpl; try reflexivity.
  destruct (evidence_root_trusted t); simpl; try reflexivity.
  destruct (authority_root_trusted t); simpl; try reflexivity.
  destruct (witness_valid t); simpl; try reflexivity.
  rewrite H. reflexivity.
Qed.

Theorem non_allow_verdict_never_executes :
  forall t v cap req,
    v <> Allow ->
    execution_authorized t v cap req = false.
Proof.
  intros t v cap req H.
  unfold execution_authorized.
  destruct (trust_ready t); simpl.
  - destruct v; try reflexivity; contradiction.
  - reflexivity.
Qed.

(** Campaign-state updates use a compare-and-swap abstraction. The expected
    predecessor must equal the durable current sequence. Once one successor has
    advanced the durable sequence, another candidate derived from the old
    predecessor is rejected. *)
Inductive commit_result : Type :=
| CommitAccepted
| CommitRejected.

Definition cas_commit (expected current : nat) : commit_result :=
  if Nat.eqb expected current then CommitAccepted else CommitRejected.

Theorem matching_predecessor_can_commit :
  forall current, cas_commit current current = CommitAccepted.
Proof.
  intro current.
  unfold cas_commit.
  rewrite Nat.eqb_refl.
  reflexivity.
Qed.

Theorem stale_predecessor_is_rejected :
  forall expected current,
    expected <> current ->
    cas_commit expected current = CommitRejected.
Proof.
  intros expected current Hneq.
  unfold cas_commit.
  apply Nat.eqb_neq in Hneq.
  rewrite Hneq.
  reflexivity.
Qed.

Theorem second_same_predecessor_is_rejected_after_advance :
  forall prior successor,
    prior < successor ->
    cas_commit prior successor = CommitRejected.
Proof.
  intros prior successor Hlt.
  apply stale_predecessor_is_rejected.
  lia.
Qed.

Definition strict_successor (prior successor : nat) : bool :=
  Nat.ltb prior successor.

Theorem same_sequence_is_not_a_successor :
  forall sequence,
    strict_successor sequence sequence = false.
Proof.
  intro sequence.
  unfold strict_successor.
  apply Nat.ltb_irrefl.
Qed.

Theorem lower_or_equal_sequence_is_not_a_successor :
  forall prior successor,
    successor <= prior ->
    strict_successor prior successor = false.
Proof.
  intros prior successor Hle.
  unfold strict_successor.
  apply Nat.ltb_ge.
  exact Hle.
Qed.
