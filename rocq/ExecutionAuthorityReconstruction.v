From Stdlib Require Import Bool Arith List.
From ClaimSieve Require Import
  AuthorityCompression
  AuthorityCompressionAuthenticity
  AuthorityCompressionCurrentState.
Import ListNotations.

(** Execution authority and reconstruction invariant.

    This module composes the existing compact-authority and current-state models
    into one system-level statement:

      execution -> prior authority + exact binding + reconstructable lineage

    The hot execution predicate does not traverse the archived evidence payload.
    Reconstruction is conditional on a durable persisted authority entry whose
    certificate remains bound to the preserved historical archive.

    Cryptographic collision resistance, canonical serialization, durable-storage
    correctness, trusted-state correctness, clocks, and key custody remain outside
    this proof boundary. *)

Record persisted_authority : Type := {
  stored_authority_id : nat;
  stored_certificate : authority_certificate;
  stored_archive : authority_archive
}.

Definition authority_store : Type := list persisted_authority.

Fixpoint lookup_authority
  (authority_id : nat)
  (store : authority_store) : option persisted_authority :=
  match store with
  | [] => None
  | entry :: rest =>
      if Nat.eqb authority_id (stored_authority_id entry)
      then Some entry
      else lookup_authority authority_id rest
  end.

Definition stored_envelope
  (entry : persisted_authority) : authenticated_authority_envelope :=
  {| envelope_certificate := stored_certificate entry;
     envelope_authentic := true |}.

(** The execution path consumes the compact certificate and live current state.
    It deliberately does not consume [stored_archive]. *)
Definition stored_execution_allowed
  (entry : persisted_authority)
  (candidate : execution_candidate)
  (current : current_authority_state) : bool :=
  executable_now (stored_envelope entry) candidate current.

(** A persisted archive is valid reconstruction material only when the immutable
    certificate commitments still match the archive from which authority can be
    recomputed. *)
Definition certificate_archive_binding
  (certificate : authority_certificate)
  (archive : authority_archive) : Prop :=
  cert_action_digest certificate = archive_action_digest archive /\
  cert_policy_digest certificate = archive_policy_digest archive /\
  cert_identity_digest certificate = archive_identity_digest archive /\
  cert_evidence_digest certificate = archive_evidence_digest archive /\
  cert_authorized certificate = reconstruct_authority archive.

Definition stored_lineage_valid
  (entry : persisted_authority) : Prop :=
  certificate_archive_binding
    (stored_certificate entry)
    (stored_archive entry).

Definition exact_authority_binding
  (entry : persisted_authority)
  (candidate : execution_candidate) : Prop :=
  cert_action_digest (stored_certificate entry) = exec_action_digest candidate /\
  cert_policy_digest (stored_certificate entry) = exec_policy_digest candidate /\
  cert_identity_digest (stored_certificate entry) = exec_identity_digest candidate.

Definition evidence_lineage_preserved
  (entry : persisted_authority) : Prop :=
  cert_evidence_digest (stored_certificate entry) =
    archive_evidence_digest (stored_archive entry).

Definition reconstruct_from_store
  (store : authority_store)
  (authority_id : nat) : option bool :=
  match lookup_authority authority_id store with
  | Some entry => Some (reconstruct_authority (stored_archive entry))
  | None => None
  end.

Theorem compact_execution_implies_certificate_authorized :
  forall certificate candidate,
    verify_compact certificate candidate = true ->
    cert_authorized certificate = true.
Proof.
  intros certificate candidate Hverify.
  unfold verify_compact in Hverify.
  apply Bool.andb_true_iff in Hverify.
  destruct Hverify as [Hauthorized _].
  exact Hauthorized.
Qed.

Theorem stored_execution_implies_compact_execution :
  forall entry candidate current,
    stored_execution_allowed entry candidate current = true ->
    verify_compact (stored_certificate entry) candidate = true.
Proof.
  intros entry candidate current Hexecute.
  unfold stored_execution_allowed in Hexecute.
  pose proof
    (current_state_is_additional_authority_boundary
      (stored_envelope entry)
      candidate
      current
      Hexecute)
    as Hauthenticated.
  apply authenticated_execution_implies_compact_execution in Hauthenticated.
  unfold stored_envelope in Hauthenticated.
  simpl in Hauthenticated.
  exact Hauthenticated.
Qed.

(** Hot-path safety: successful execution already establishes prior authority and
    exact candidate binding, before any audit reconstruction is attempted. *)
Theorem execution_implies_prior_exact_authority :
  forall entry candidate current,
    stored_execution_allowed entry candidate current = true ->
    cert_authorized (stored_certificate entry) = true /\
    exact_authority_binding entry candidate.
Proof.
  intros entry candidate current Hexecute.
  pose proof
    (stored_execution_implies_compact_execution
      entry candidate current Hexecute)
    as Hcompact.
  split.
  - exact
      (compact_execution_implies_certificate_authorized
        (stored_certificate entry)
        candidate
        Hcompact).
  - unfold exact_authority_binding.
    pose proof Hcompact as Haction.
    pose proof Hcompact as Hpolicy.
    pose proof Hcompact as Hidentity.
    apply action_binding_of_compact_verifier in Haction.
    apply policy_binding_of_compact_verifier in Hpolicy.
    apply identity_binding_of_compact_verifier in Hidentity.
    repeat split; assumption.
Qed.

(** System-level invariant.

    If a durable authority store can retrieve the exact persisted entry, and the
    persisted certificate remains bound to its historical archive, then every
    accepted execution has reconstructible historical authority, exact action /
    policy / identity binding, and a preserved evidence commitment.

    This is intentionally conditional on durable lineage availability and
    integrity. The theorem does not pretend to prove the storage substrate. *)
Theorem execution_authority_reconstruction_invariant :
  forall store authority_id entry candidate current,
    lookup_authority authority_id store = Some entry ->
    stored_lineage_valid entry ->
    stored_execution_allowed entry candidate current = true ->
    reconstruct_from_store store authority_id = Some true /\
    exact_authority_binding entry candidate /\
    evidence_lineage_preserved entry.
Proof.
  intros store authority_id entry candidate current Hlookup Hlineage Hexecute.
  unfold stored_lineage_valid, certificate_archive_binding in Hlineage.
  destruct Hlineage as
    [Harchive_action
      [Harchive_policy
        [Harchive_identity
          [Harchive_evidence Harchive_authority]]]].

  pose proof
    (execution_implies_prior_exact_authority
      entry candidate current Hexecute)
    as Hprior_exact.
  destruct Hprior_exact as [Hauthorized Hexact].

  assert
    (Hreconstruct : reconstruct_authority (stored_archive entry) = true).
  {
    rewrite <- Harchive_authority.
    exact Hauthorized.
  }

  split.
  - unfold reconstruct_from_store.
    rewrite Hlookup.
    rewrite Hreconstruct.
    reflexivity.
  - split.
    + exact Hexact.
    + unfold evidence_lineage_preserved.
      exact Harchive_evidence.
Qed.

Theorem missing_authority_is_not_reconstructable :
  forall store authority_id,
    lookup_authority authority_id store = None ->
    reconstruct_from_store store authority_id = None.
Proof.
  intros store authority_id Hmissing.
  unfold reconstruct_from_store.
  rewrite Hmissing.
  reflexivity.
Qed.

Theorem evidence_archive_mutation_breaks_lineage :
  forall certificate archive,
    cert_evidence_digest certificate <>
      archive_evidence_digest archive ->
    ~ certificate_archive_binding certificate archive.
Proof.
  intros certificate archive Hneq Hbinding.
  unfold certificate_archive_binding in Hbinding.
  destruct Hbinding as
    [_ [_ [_ [Hevidence _]]]].
  exact (Hneq Hevidence).
Qed.

Theorem action_mutation_blocks_stored_execution :
  forall entry candidate current,
    cert_action_digest (stored_certificate entry) <>
      exec_action_digest candidate ->
    stored_execution_allowed entry candidate current = false.
Proof.
  intros entry candidate current Hneq.
  unfold stored_execution_allowed, stored_envelope, executable_now,
    verify_authenticated_compact.
  simpl.
  rewrite
    (action_mutation_invalidates_compact_certificate
      (stored_certificate entry)
      candidate
      Hneq).
  reflexivity.
Qed.

Theorem policy_mutation_blocks_stored_execution :
  forall entry candidate current,
    cert_policy_digest (stored_certificate entry) <>
      exec_policy_digest candidate ->
    stored_execution_allowed entry candidate current = false.
Proof.
  intros entry candidate current Hneq.
  unfold stored_execution_allowed, stored_envelope, executable_now,
    verify_authenticated_compact.
  simpl.
  rewrite
    (policy_mutation_invalidates_compact_certificate
      (stored_certificate entry)
      candidate
      Hneq).
  reflexivity.
Qed.

Theorem identity_mutation_blocks_stored_execution :
  forall entry candidate current,
    cert_identity_digest (stored_certificate entry) <>
      exec_identity_digest candidate ->
    stored_execution_allowed entry candidate current = false.
Proof.
  intros entry candidate current Hneq.
  unfold stored_execution_allowed, stored_envelope, executable_now,
    verify_authenticated_compact.
  simpl.
  rewrite
    (identity_mutation_invalidates_compact_certificate
      (stored_certificate entry)
      candidate
      Hneq).
  reflexivity.
Qed.
