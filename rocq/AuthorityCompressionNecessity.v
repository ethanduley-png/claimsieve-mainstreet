From Stdlib Require Import Bool Arith.
From ClaimSieve Require Import AuthorityCompression.

(** Pointwise necessity of the immutable compact-certificate guard set.

    Mutable facts such as revocation and consumption are intentionally excluded
    from this module. Their necessity belongs to trusted current state, not to
    the immutable certificate.

    For each guard used by [verify_compact], we construct a concrete state where
    omitting only that guard changes an unsafe request from reject to accept. *)

Inductive runtime_guard : Type :=
| AuthorityGuard
| ActionGuard
| PolicyGuard
| IdentityGuard
| NotBeforeGuard
| ExpiryGuard.

Definition same_runtime_guard (left right : runtime_guard) : bool :=
  match left, right with
  | AuthorityGuard, AuthorityGuard => true
  | ActionGuard, ActionGuard => true
  | PolicyGuard, PolicyGuard => true
  | IdentityGuard, IdentityGuard => true
  | NotBeforeGuard, NotBeforeGuard => true
  | ExpiryGuard, ExpiryGuard => true
  | _, _ => false
  end.

Definition apply_unless_omitted
  (omitted current : runtime_guard)
  (check : bool) : bool :=
  if same_runtime_guard omitted current then true else check.

Definition verify_without
  (omitted : runtime_guard)
  (certificate : authority_certificate)
  (candidate : execution_candidate) : bool :=
  apply_unless_omitted omitted AuthorityGuard
    (cert_authorized certificate) &&
  (apply_unless_omitted omitted ActionGuard
    (Nat.eqb (cert_action_digest certificate) (exec_action_digest candidate)) &&
  (apply_unless_omitted omitted PolicyGuard
    (Nat.eqb (cert_policy_digest certificate) (exec_policy_digest candidate)) &&
  (apply_unless_omitted omitted IdentityGuard
    (Nat.eqb (cert_identity_digest certificate) (exec_identity_digest candidate)) &&
  (apply_unless_omitted omitted NotBeforeGuard
    (Nat.leb (cert_valid_from certificate) (exec_sequence candidate)) &&
   apply_unless_omitted omitted ExpiryGuard
    (Nat.leb (exec_sequence candidate) (cert_expires_at certificate)))))).

Definition necessity_base_certificate : authority_certificate :=
  {| cert_action_digest := 1;
     cert_policy_digest := 2;
     cert_identity_digest := 3;
     cert_evidence_digest := 4;
     cert_authorized := true;
     cert_valid_from := 10;
     cert_expires_at := 20 |}.

Definition necessity_good_candidate : execution_candidate :=
  {| exec_action_digest := 1;
     exec_policy_digest := 2;
     exec_identity_digest := 3;
     exec_sequence := 15 |}.

Definition necessity_unauthorized_certificate : authority_certificate :=
  {| cert_action_digest := 1;
     cert_policy_digest := 2;
     cert_identity_digest := 3;
     cert_evidence_digest := 4;
     cert_authorized := false;
     cert_valid_from := 10;
     cert_expires_at := 20 |}.

Definition necessity_wrong_action_candidate : execution_candidate :=
  {| exec_action_digest := 9;
     exec_policy_digest := 2;
     exec_identity_digest := 3;
     exec_sequence := 15 |}.

Definition necessity_wrong_policy_candidate : execution_candidate :=
  {| exec_action_digest := 1;
     exec_policy_digest := 9;
     exec_identity_digest := 3;
     exec_sequence := 15 |}.

Definition necessity_wrong_identity_candidate : execution_candidate :=
  {| exec_action_digest := 1;
     exec_policy_digest := 2;
     exec_identity_digest := 9;
     exec_sequence := 15 |}.

Definition necessity_early_candidate : execution_candidate :=
  {| exec_action_digest := 1;
     exec_policy_digest := 2;
     exec_identity_digest := 3;
     exec_sequence := 9 |}.

Definition necessity_expired_candidate : execution_candidate :=
  {| exec_action_digest := 1;
     exec_policy_digest := 2;
     exec_identity_digest := 3;
     exec_sequence := 21 |}.

Theorem authority_guard_is_necessary :
  verify_without
    AuthorityGuard
    necessity_unauthorized_certificate
    necessity_good_candidate = true /\
  verify_compact
    necessity_unauthorized_certificate
    necessity_good_candidate = false.
Proof. reflexivity. Qed.

Theorem action_guard_is_necessary :
  verify_without
    ActionGuard
    necessity_base_certificate
    necessity_wrong_action_candidate = true /\
  verify_compact
    necessity_base_certificate
    necessity_wrong_action_candidate = false.
Proof. reflexivity. Qed.

Theorem policy_guard_is_necessary :
  verify_without
    PolicyGuard
    necessity_base_certificate
    necessity_wrong_policy_candidate = true /\
  verify_compact
    necessity_base_certificate
    necessity_wrong_policy_candidate = false.
Proof. reflexivity. Qed.

Theorem identity_guard_is_necessary :
  verify_without
    IdentityGuard
    necessity_base_certificate
    necessity_wrong_identity_candidate = true /\
  verify_compact
    necessity_base_certificate
    necessity_wrong_identity_candidate = false.
Proof. reflexivity. Qed.

Theorem not_before_guard_is_necessary :
  verify_without
    NotBeforeGuard
    necessity_base_certificate
    necessity_early_candidate = true /\
  verify_compact
    necessity_base_certificate
    necessity_early_candidate = false.
Proof. reflexivity. Qed.

Theorem expiry_guard_is_necessary :
  verify_without
    ExpiryGuard
    necessity_base_certificate
    necessity_expired_candidate = true /\
  verify_compact
    necessity_base_certificate
    necessity_expired_candidate = false.
Proof. reflexivity. Qed.

(** The evidence digest is retained for archive linkage and reconstruction. It
    is deliberately not consulted by [verify_compact]. *)
Definition with_evidence_digest
  (certificate : authority_certificate)
  (new_evidence_digest : nat) : authority_certificate :=
  {| cert_action_digest := cert_action_digest certificate;
     cert_policy_digest := cert_policy_digest certificate;
     cert_identity_digest := cert_identity_digest certificate;
     cert_evidence_digest := new_evidence_digest;
     cert_authorized := cert_authorized certificate;
     cert_valid_from := cert_valid_from certificate;
     cert_expires_at := cert_expires_at certificate |}.

Theorem evidence_digest_is_not_runtime_guard :
  forall certificate candidate new_evidence_digest,
    verify_compact
      (with_evidence_digest certificate new_evidence_digest)
      candidate =
    verify_compact certificate candidate.
Proof.
  intros certificate candidate new_evidence_digest.
  reflexivity.
Qed.

Theorem compact_runtime_guard_set_is_pointwise_necessary :
  (verify_without
    AuthorityGuard
    necessity_unauthorized_certificate
    necessity_good_candidate = true /\
   verify_compact
    necessity_unauthorized_certificate
    necessity_good_candidate = false) /\
  (verify_without
    ActionGuard
    necessity_base_certificate
    necessity_wrong_action_candidate = true /\
   verify_compact
    necessity_base_certificate
    necessity_wrong_action_candidate = false) /\
  (verify_without
    PolicyGuard
    necessity_base_certificate
    necessity_wrong_policy_candidate = true /\
   verify_compact
    necessity_base_certificate
    necessity_wrong_policy_candidate = false) /\
  (verify_without
    IdentityGuard
    necessity_base_certificate
    necessity_wrong_identity_candidate = true /\
   verify_compact
    necessity_base_certificate
    necessity_wrong_identity_candidate = false) /\
  (verify_without
    NotBeforeGuard
    necessity_base_certificate
    necessity_early_candidate = true /\
   verify_compact
    necessity_base_certificate
    necessity_early_candidate = false) /\
  (verify_without
    ExpiryGuard
    necessity_base_certificate
    necessity_expired_candidate = true /\
   verify_compact
    necessity_base_certificate
    necessity_expired_candidate = false).
Proof.
  repeat split; reflexivity.
Qed.
