From Stdlib Require Import Bool Arith.
From ClaimSieve Require Import
  AuthorityCompressionNecessity
  AuthorityCompressionAuthenticity
  AuthorityCompressionCurrentState.

(** Pointwise necessity of trusted mutable current-state guards.

    These are deliberately separate from immutable certificate necessity. The
    signed certificate answers what was authorized. Current state answers
    whether that historical authority remains executable now. *)

Inductive current_guard : Type :=
| CurrentPolicyDigestGuard
| CurrentIdentityDigestGuard
| PolicyActiveGuard
| IdentityActiveGuard
| CampaignActiveGuard
| GlobalFreezeGuard
| CampaignSuspensionGuard
| CurrentRevocationGuard
| CurrentConsumptionGuard.

Definition same_current_guard (left right : current_guard) : bool :=
  match left, right with
  | CurrentPolicyDigestGuard, CurrentPolicyDigestGuard => true
  | CurrentIdentityDigestGuard, CurrentIdentityDigestGuard => true
  | PolicyActiveGuard, PolicyActiveGuard => true
  | IdentityActiveGuard, IdentityActiveGuard => true
  | CampaignActiveGuard, CampaignActiveGuard => true
  | GlobalFreezeGuard, GlobalFreezeGuard => true
  | CampaignSuspensionGuard, CampaignSuspensionGuard => true
  | CurrentRevocationGuard, CurrentRevocationGuard => true
  | CurrentConsumptionGuard, CurrentConsumptionGuard => true
  | _, _ => false
  end.

Definition current_check_unless_omitted
  (omitted current : current_guard)
  (check : bool) : bool :=
  if same_current_guard omitted current then true else check.

Definition current_state_allows_without
  (omitted : current_guard)
  (certificate : authority_certificate)
  (current : current_authority_state) : bool :=
  current_check_unless_omitted omitted CurrentPolicyDigestGuard
    (Nat.eqb (cert_policy_digest certificate) (current_policy_digest current)) &&
  (current_check_unless_omitted omitted CurrentIdentityDigestGuard
    (Nat.eqb (cert_identity_digest certificate) (current_identity_digest current)) &&
  (current_check_unless_omitted omitted PolicyActiveGuard
    (current_policy_active current) &&
  (current_check_unless_omitted omitted IdentityActiveGuard
    (current_identity_active current) &&
  (current_check_unless_omitted omitted CampaignActiveGuard
    (current_campaign_active current) &&
  (current_check_unless_omitted omitted GlobalFreezeGuard
    (negb (current_execution_frozen current)) &&
  (current_check_unless_omitted omitted CampaignSuspensionGuard
    (negb (current_campaign_suspended current)) &&
  (current_check_unless_omitted omitted CurrentRevocationGuard
    (negb (current_permit_revoked current)) &&
   current_check_unless_omitted omitted CurrentConsumptionGuard
    (negb (current_permit_consumed current)))))))).

Definition executable_now_without_current_guard
  (omitted : current_guard)
  (envelope : authenticated_authority_envelope)
  (candidate : execution_candidate)
  (current : current_authority_state) : bool :=
  verify_authenticated_compact envelope candidate &&
  current_state_allows_without omitted (envelope_certificate envelope) current.

Definition current_necessity_envelope : authenticated_authority_envelope :=
  {| envelope_certificate := necessity_base_certificate;
     envelope_authentic := true |}.

Definition current_necessity_base : current_authority_state :=
  {| current_policy_digest := 2;
     current_identity_digest := 3;
     current_policy_active := true;
     current_identity_active := true;
     current_campaign_active := true;
     current_execution_frozen := false;
     current_campaign_suspended := false;
     current_permit_revoked := false;
     current_permit_consumed := false |}.

Definition current_wrong_policy : current_authority_state :=
  {| current_policy_digest := 9;
     current_identity_digest := 3;
     current_policy_active := true;
     current_identity_active := true;
     current_campaign_active := true;
     current_execution_frozen := false;
     current_campaign_suspended := false;
     current_permit_revoked := false;
     current_permit_consumed := false |}.

Definition current_wrong_identity : current_authority_state :=
  {| current_policy_digest := 2;
     current_identity_digest := 9;
     current_policy_active := true;
     current_identity_active := true;
     current_campaign_active := true;
     current_execution_frozen := false;
     current_campaign_suspended := false;
     current_permit_revoked := false;
     current_permit_consumed := false |}.

Definition current_policy_inactive : current_authority_state :=
  {| current_policy_digest := 2;
     current_identity_digest := 3;
     current_policy_active := false;
     current_identity_active := true;
     current_campaign_active := true;
     current_execution_frozen := false;
     current_campaign_suspended := false;
     current_permit_revoked := false;
     current_permit_consumed := false |}.

Definition current_identity_inactive : current_authority_state :=
  {| current_policy_digest := 2;
     current_identity_digest := 3;
     current_policy_active := true;
     current_identity_active := false;
     current_campaign_active := true;
     current_execution_frozen := false;
     current_campaign_suspended := false;
     current_permit_revoked := false;
     current_permit_consumed := false |}.

Definition current_campaign_inactive : current_authority_state :=
  {| current_policy_digest := 2;
     current_identity_digest := 3;
     current_policy_active := true;
     current_identity_active := true;
     current_campaign_active := false;
     current_execution_frozen := false;
     current_campaign_suspended := false;
     current_permit_revoked := false;
     current_permit_consumed := false |}.

Definition current_frozen : current_authority_state :=
  {| current_policy_digest := 2;
     current_identity_digest := 3;
     current_policy_active := true;
     current_identity_active := true;
     current_campaign_active := true;
     current_execution_frozen := true;
     current_campaign_suspended := false;
     current_permit_revoked := false;
     current_permit_consumed := false |}.

Definition current_suspended : current_authority_state :=
  {| current_policy_digest := 2;
     current_identity_digest := 3;
     current_policy_active := true;
     current_identity_active := true;
     current_campaign_active := true;
     current_execution_frozen := false;
     current_campaign_suspended := true;
     current_permit_revoked := false;
     current_permit_consumed := false |}.

Definition current_revoked : current_authority_state :=
  {| current_policy_digest := 2;
     current_identity_digest := 3;
     current_policy_active := true;
     current_identity_active := true;
     current_campaign_active := true;
     current_execution_frozen := false;
     current_campaign_suspended := false;
     current_permit_revoked := true;
     current_permit_consumed := false |}.

Definition current_consumed : current_authority_state :=
  {| current_policy_digest := 2;
     current_identity_digest := 3;
     current_policy_active := true;
     current_identity_active := true;
     current_campaign_active := true;
     current_execution_frozen := false;
     current_campaign_suspended := false;
     current_permit_revoked := false;
     current_permit_consumed := true |}.

Theorem current_policy_digest_guard_is_necessary :
  executable_now_without_current_guard
    CurrentPolicyDigestGuard current_necessity_envelope necessity_good_candidate
    current_wrong_policy = true /\
  executable_now current_necessity_envelope necessity_good_candidate
    current_wrong_policy = false.
Proof. reflexivity. Qed.

Theorem current_identity_digest_guard_is_necessary :
  executable_now_without_current_guard
    CurrentIdentityDigestGuard current_necessity_envelope necessity_good_candidate
    current_wrong_identity = true /\
  executable_now current_necessity_envelope necessity_good_candidate
    current_wrong_identity = false.
Proof. reflexivity. Qed.

Theorem policy_active_guard_is_necessary :
  executable_now_without_current_guard
    PolicyActiveGuard current_necessity_envelope necessity_good_candidate
    current_policy_inactive = true /\
  executable_now current_necessity_envelope necessity_good_candidate
    current_policy_inactive = false.
Proof. reflexivity. Qed.

Theorem identity_active_guard_is_necessary :
  executable_now_without_current_guard
    IdentityActiveGuard current_necessity_envelope necessity_good_candidate
    current_identity_inactive = true /\
  executable_now current_necessity_envelope necessity_good_candidate
    current_identity_inactive = false.
Proof. reflexivity. Qed.

Theorem campaign_active_guard_is_necessary :
  executable_now_without_current_guard
    CampaignActiveGuard current_necessity_envelope necessity_good_candidate
    current_campaign_inactive = true /\
  executable_now current_necessity_envelope necessity_good_candidate
    current_campaign_inactive = false.
Proof. reflexivity. Qed.

Theorem global_freeze_guard_is_necessary :
  executable_now_without_current_guard
    GlobalFreezeGuard current_necessity_envelope necessity_good_candidate
    current_frozen = true /\
  executable_now current_necessity_envelope necessity_good_candidate
    current_frozen = false.
Proof. reflexivity. Qed.

Theorem campaign_suspension_guard_is_necessary :
  executable_now_without_current_guard
    CampaignSuspensionGuard current_necessity_envelope necessity_good_candidate
    current_suspended = true /\
  executable_now current_necessity_envelope necessity_good_candidate
    current_suspended = false.
Proof. reflexivity. Qed.

Theorem current_revocation_guard_is_necessary :
  executable_now_without_current_guard
    CurrentRevocationGuard current_necessity_envelope necessity_good_candidate
    current_revoked = true /\
  executable_now current_necessity_envelope necessity_good_candidate
    current_revoked = false.
Proof. reflexivity. Qed.

Theorem current_consumption_guard_is_necessary :
  executable_now_without_current_guard
    CurrentConsumptionGuard current_necessity_envelope necessity_good_candidate
    current_consumed = true /\
  executable_now current_necessity_envelope necessity_good_candidate
    current_consumed = false.
Proof. reflexivity. Qed.

Theorem current_runtime_guard_set_is_pointwise_necessary :
  (executable_now_without_current_guard
    CurrentPolicyDigestGuard current_necessity_envelope necessity_good_candidate
    current_wrong_policy = true /\
   executable_now current_necessity_envelope necessity_good_candidate
    current_wrong_policy = false) /\
  (executable_now_without_current_guard
    CurrentIdentityDigestGuard current_necessity_envelope necessity_good_candidate
    current_wrong_identity = true /\
   executable_now current_necessity_envelope necessity_good_candidate
    current_wrong_identity = false) /\
  (executable_now_without_current_guard
    PolicyActiveGuard current_necessity_envelope necessity_good_candidate
    current_policy_inactive = true /\
   executable_now current_necessity_envelope necessity_good_candidate
    current_policy_inactive = false) /\
  (executable_now_without_current_guard
    IdentityActiveGuard current_necessity_envelope necessity_good_candidate
    current_identity_inactive = true /\
   executable_now current_necessity_envelope necessity_good_candidate
    current_identity_inactive = false) /\
  (executable_now_without_current_guard
    CampaignActiveGuard current_necessity_envelope necessity_good_candidate
    current_campaign_inactive = true /\
   executable_now current_necessity_envelope necessity_good_candidate
    current_campaign_inactive = false) /\
  (executable_now_without_current_guard
    GlobalFreezeGuard current_necessity_envelope necessity_good_candidate
    current_frozen = true /\
   executable_now current_necessity_envelope necessity_good_candidate
    current_frozen = false) /\
  (executable_now_without_current_guard
    CampaignSuspensionGuard current_necessity_envelope necessity_good_candidate
    current_suspended = true /\
   executable_now current_necessity_envelope necessity_good_candidate
    current_suspended = false) /\
  (executable_now_without_current_guard
    CurrentRevocationGuard current_necessity_envelope necessity_good_candidate
    current_revoked = true /\
   executable_now current_necessity_envelope necessity_good_candidate
    current_revoked = false) /\
  (executable_now_without_current_guard
    CurrentConsumptionGuard current_necessity_envelope necessity_good_candidate
    current_consumed = true /\
   executable_now current_necessity_envelope necessity_good_candidate
    current_consumed = false).
Proof.
  repeat split; reflexivity.
Qed.
