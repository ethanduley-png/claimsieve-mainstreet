From Stdlib Require Import Bool Arith List.
From ClaimSieve Require Import Claimsieve.
Import ListNotations.

(** Authority compression model.

    Design rule:
      persist only immutable authority facts required by the execution boundary;
      preserve the complete evidence archive outside the latency-critical path;
      bind the compact certificate back to that archive.

    Mutable execution facts such as revocation and consumption are deliberately
    NOT fields of the immutable authority certificate. They belong to trusted
    current state and are modeled in [AuthorityCompressionCurrentState].

    Cryptographic collision resistance, canonical serialization, storage
    durability, clocks, and correspondence between numeric digests and real
    cryptographic digests remain outside this proof boundary. *)

Definition verdict_allows (v : verdict) : bool :=
  match v with
  | Allow => true
  | _ => false
  end.

Record authority_archive : Type := {
  archive_policy : policy;
  archive_proposal : proposal;
  archive_campaign : campaign;
  archive_action_digest : nat;
  archive_policy_digest : nat;
  archive_identity_digest : nat;
  archive_evidence_digest : nat;
  archive_payload : list nat
}.

(** Reconstruct the historical authority judgment from the preserved full
    adjudication inputs. *)
Definition reconstruct_authority (archive : authority_archive) : bool :=
  verdict_allows
    (decide
      (archive_policy archive)
      (archive_proposal archive)
      (archive_campaign archive)).

(** Immutable compact authority certificate.

    The certificate contains historical authority and immutable commitments.
    Revocation, consumption, current policy status, identity status, campaign
    status, and global freeze are intentionally excluded because those facts may
    change after issuance. *)
Record authority_certificate : Type := {
  cert_action_digest : nat;
  cert_policy_digest : nat;
  cert_identity_digest : nat;
  cert_evidence_digest : nat;
  cert_authorized : bool;
  cert_valid_from : nat;
  cert_expires_at : nat
}.

Record execution_candidate : Type := {
  exec_action_digest : nat;
  exec_policy_digest : nat;
  exec_identity_digest : nat;
  exec_sequence : nat
}.

(** Compression projects the full archive onto immutable authority facts needed
    by the compact verifier. The evidence payload itself is intentionally absent. *)
Definition compress_authority
  (archive : authority_archive)
  (valid_from expires_at : nat) : authority_certificate :=
  {| cert_action_digest := archive_action_digest archive;
     cert_policy_digest := archive_policy_digest archive;
     cert_identity_digest := archive_identity_digest archive;
     cert_evidence_digest := archive_evidence_digest archive;
     cert_authorized := reconstruct_authority archive;
     cert_valid_from := valid_from;
     cert_expires_at := expires_at |}.

(** Immutable compact verification.

    This answers whether the authenticated historical certificate is internally
    sufficient and bound to the candidate. It does NOT answer whether mutable
    current authority still permits execution; [executable_now] adds that layer. *)
Definition verify_compact
  (certificate : authority_certificate)
  (candidate : execution_candidate) : bool :=
  cert_authorized certificate &&
  (Nat.eqb (cert_action_digest certificate) (exec_action_digest candidate) &&
  (Nat.eqb (cert_policy_digest certificate) (exec_policy_digest candidate) &&
  (Nat.eqb (cert_identity_digest certificate) (exec_identity_digest candidate) &&
  (Nat.leb (cert_valid_from certificate) (exec_sequence candidate) &&
   Nat.leb (exec_sequence candidate) (cert_expires_at certificate))))).

Theorem compression_reconstruction_equivalence :
  forall archive valid_from expires_at,
    cert_authorized (compress_authority archive valid_from expires_at) =
    reconstruct_authority archive.
Proof.
  intros archive valid_from expires_at.
  reflexivity.
Qed.

Theorem compression_binds_evidence_archive :
  forall archive valid_from expires_at,
    cert_evidence_digest (compress_authority archive valid_from expires_at) =
    archive_evidence_digest archive.
Proof.
  intros archive valid_from expires_at.
  reflexivity.
Qed.

Theorem compression_binds_action :
  forall archive valid_from expires_at,
    cert_action_digest (compress_authority archive valid_from expires_at) =
    archive_action_digest archive.
Proof.
  intros archive valid_from expires_at.
  reflexivity.
Qed.

Theorem compression_binds_policy :
  forall archive valid_from expires_at,
    cert_policy_digest (compress_authority archive valid_from expires_at) =
    archive_policy_digest archive.
Proof.
  intros archive valid_from expires_at.
  reflexivity.
Qed.

Theorem compression_binds_identity :
  forall archive valid_from expires_at,
    cert_identity_digest (compress_authority archive valid_from expires_at) =
    archive_identity_digest archive.
Proof.
  intros archive valid_from expires_at.
  reflexivity.
Qed.

(** Core historical soundness: compact acceptance of a certificate derived from
    an archive implies reconstruction of that archive returns allow. *)
Theorem certificate_soundness :
  forall archive candidate valid_from expires_at,
    verify_compact
      (compress_authority archive valid_from expires_at)
      candidate = true ->
    reconstruct_authority archive = true.
Proof.
  intros archive candidate valid_from expires_at Hverify.
  unfold verify_compact in Hverify.
  cbn [compress_authority] in Hverify.
  apply Bool.andb_true_iff in Hverify.
  destruct Hverify as [Hauthority _].
  exact Hauthority.
Qed.

Theorem execution_implies_original_decision_allow :
  forall archive candidate valid_from expires_at,
    verify_compact
      (compress_authority archive valid_from expires_at)
      candidate = true ->
    decide
      (archive_policy archive)
      (archive_proposal archive)
      (archive_campaign archive) = Allow.
Proof.
  intros archive candidate valid_from expires_at Hverify.
  pose proof
    (certificate_soundness archive candidate valid_from expires_at Hverify)
    as Hauthority.
  unfold reconstruct_authority, verdict_allows in Hauthority.
  destruct
    (decide
      (archive_policy archive)
      (archive_proposal archive)
      (archive_campaign archive)) eqn:Hdecision;
    simpl in Hauthority;
    try discriminate;
    exact Hdecision.
Qed.

Theorem unauthorized_certificate_fails_closed :
  forall certificate candidate,
    cert_authorized certificate = false ->
    verify_compact certificate candidate = false.
Proof.
  intros certificate candidate Hunauthorized.
  unfold verify_compact.
  rewrite Hunauthorized.
  reflexivity.
Qed.

Theorem action_binding_of_compact_verifier :
  forall certificate candidate,
    verify_compact certificate candidate = true ->
    cert_action_digest certificate = exec_action_digest candidate.
Proof.
  intros certificate candidate Hverify.
  unfold verify_compact in Hverify.
  destruct (cert_authorized certificate); simpl in Hverify; try discriminate.
  destruct
    (Nat.eqb
      (cert_action_digest certificate)
      (exec_action_digest candidate)) eqn:Hequal;
    simpl in Hverify;
    try discriminate.
  apply Nat.eqb_eq in Hequal.
  exact Hequal.
Qed.

Theorem policy_binding_of_compact_verifier :
  forall certificate candidate,
    verify_compact certificate candidate = true ->
    cert_policy_digest certificate = exec_policy_digest candidate.
Proof.
  intros certificate candidate Hverify.
  unfold verify_compact in Hverify.
  destruct (cert_authorized certificate); simpl in Hverify; try discriminate.
  destruct
    (Nat.eqb
      (cert_action_digest certificate)
      (exec_action_digest candidate));
    simpl in Hverify;
    try discriminate.
  destruct
    (Nat.eqb
      (cert_policy_digest certificate)
      (exec_policy_digest candidate)) eqn:Hequal;
    simpl in Hverify;
    try discriminate.
  apply Nat.eqb_eq in Hequal.
  exact Hequal.
Qed.

Theorem identity_binding_of_compact_verifier :
  forall certificate candidate,
    verify_compact certificate candidate = true ->
    cert_identity_digest certificate = exec_identity_digest candidate.
Proof.
  intros certificate candidate Hverify.
  unfold verify_compact in Hverify.
  destruct (cert_authorized certificate); simpl in Hverify; try discriminate.
  destruct
    (Nat.eqb
      (cert_action_digest certificate)
      (exec_action_digest candidate));
    simpl in Hverify;
    try discriminate.
  destruct
    (Nat.eqb
      (cert_policy_digest certificate)
      (exec_policy_digest candidate));
    simpl in Hverify;
    try discriminate.
  destruct
    (Nat.eqb
      (cert_identity_digest certificate)
      (exec_identity_digest candidate)) eqn:Hequal;
    simpl in Hverify;
    try discriminate.
  apply Nat.eqb_eq in Hequal.
  exact Hequal.
Qed.

Theorem action_mutation_invalidates_compact_certificate :
  forall certificate candidate,
    cert_action_digest certificate <> exec_action_digest candidate ->
    verify_compact certificate candidate = false.
Proof.
  intros certificate candidate Hneq.
  unfold verify_compact.
  apply Nat.eqb_neq in Hneq.
  rewrite Hneq.
  repeat rewrite Bool.andb_false_r.
  reflexivity.
Qed.

Theorem policy_mutation_invalidates_compact_certificate :
  forall certificate candidate,
    cert_policy_digest certificate <> exec_policy_digest candidate ->
    verify_compact certificate candidate = false.
Proof.
  intros certificate candidate Hneq.
  unfold verify_compact.
  apply Nat.eqb_neq in Hneq.
  rewrite Hneq.
  repeat rewrite Bool.andb_false_r.
  reflexivity.
Qed.

Theorem identity_mutation_invalidates_compact_certificate :
  forall certificate candidate,
    cert_identity_digest certificate <> exec_identity_digest candidate ->
    verify_compact certificate candidate = false.
Proof.
  intros certificate candidate Hneq.
  unfold verify_compact.
  apply Nat.eqb_neq in Hneq.
  rewrite Hneq.
  repeat rewrite Bool.andb_false_r.
  reflexivity.
Qed.

Theorem expired_compact_certificate_invalid :
  forall certificate candidate,
    cert_expires_at certificate < exec_sequence candidate ->
    verify_compact certificate candidate = false.
Proof.
  intros certificate candidate Hexpired.
  unfold verify_compact.
  assert
    (Hlate :
      Nat.leb
        (exec_sequence candidate)
        (cert_expires_at certificate) = false).
  { apply Nat.leb_gt. exact Hexpired. }
  rewrite Hlate.
  repeat rewrite Bool.andb_false_r.
  reflexivity.
Qed.

Theorem not_yet_valid_compact_certificate_invalid :
  forall certificate candidate,
    exec_sequence candidate < cert_valid_from certificate ->
    verify_compact certificate candidate = false.
Proof.
  intros certificate candidate Hearly.
  unfold verify_compact.
  assert
    (Hearlyb :
      Nat.leb
        (cert_valid_from certificate)
        (exec_sequence candidate) = false).
  { apply Nat.leb_gt. exact Hearly. }
  rewrite Hearlyb.
  repeat rewrite Bool.andb_false_r.
  reflexivity.
Qed.

(** Two archives may differ in arbitrarily large payload detail. Once their
    authority-relevant projection is equal, the compact result is equal. *)
Definition same_execution_projection
  (left right : authority_archive) : Prop :=
  archive_action_digest left = archive_action_digest right /\
  archive_policy_digest left = archive_policy_digest right /\
  archive_identity_digest left = archive_identity_digest right /\
  archive_evidence_digest left = archive_evidence_digest right /\
  reconstruct_authority left = reconstruct_authority right.

Theorem archived_payload_outside_fast_path :
  forall left right valid_from expires_at candidate,
    same_execution_projection left right ->
    verify_compact
      (compress_authority left valid_from expires_at)
      candidate =
    verify_compact
      (compress_authority right valid_from expires_at)
      candidate.
Proof.
  intros left right valid_from expires_at candidate Hprojection.
  destruct Hprojection as [Haction [Hpolicy [Hidentity [Hevidence Hauthority]]]].
  unfold verify_compact.
  cbn [compress_authority].
  rewrite Haction, Hpolicy, Hidentity, Hevidence, Hauthority.
  reflexivity.
Qed.

Theorem execution_implies_reconstructible_authority :
  forall archive candidate valid_from expires_at,
    verify_compact
      (compress_authority archive valid_from expires_at)
      candidate = true ->
    reconstruct_authority archive = true.
Proof.
  intros archive candidate valid_from expires_at Hverify.
  exact
    (certificate_soundness
      archive candidate valid_from expires_at Hverify).
Qed.
