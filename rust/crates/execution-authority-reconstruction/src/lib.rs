#![forbid(unsafe_code)]

//! Audit-side authority reconstruction linkage for ClaimSieve.
//!
//! This crate deliberately does not authorize execution and does not load the
//! full historical evidence archive on the execution path. It converts an
//! already accepted shadow compact admission into a small reconstruction handle
//! and verifies that a persisted authority index carries the same commitments.
//! Full archive retrieval and evidence verification remain downstream audit work.

use claimsieve_compact_admission::ShadowCompactAdmission;
use thiserror::Error;

/// Immutable handle emitted from a compact admission for later reconstruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorityReconstructionHandle {
    /// Permit identifier used to locate the authority record.
    pub permit_id: String,
    /// Cross-ledger trace identifier.
    pub trace_id: String,
    /// Commitment to the exact action admitted for execution.
    pub action_digest: String,
    /// Commitment to the effective policy.
    pub policy_digest: String,
    /// Commitment to the signed policy envelope.
    pub signed_policy_digest: String,
    /// Commitment to the preserved evidence archive.
    pub evidence_root: String,
    /// Commitment to the exact authorizing decision.
    pub decision_digest: String,
    /// First logical sequence at which the authority is usable.
    pub valid_from_seq: u64,
    /// Last logical sequence at which the authority is usable.
    pub expires_at_seq: u64,
}

impl From<&ShadowCompactAdmission> for AuthorityReconstructionHandle {
    fn from(admission: &ShadowCompactAdmission) -> Self {
        Self {
            permit_id: admission.permit_id.clone(),
            trace_id: admission.trace_id.clone(),
            action_digest: admission.action_digest.clone(),
            policy_digest: admission.policy_digest.clone(),
            signed_policy_digest: admission.signed_policy_digest.clone(),
            evidence_root: admission.evidence_root.clone(),
            decision_digest: admission.decision_digest.clone(),
            valid_from_seq: admission.valid_from_seq,
            expires_at_seq: admission.expires_at_seq,
        }
    }
}

/// Compact index entry stored alongside or in front of the full authority archive.
///
/// A successful match says only that the persisted index is commitment-consistent
/// with the compact admission. It does not by itself prove that the full evidence
/// payload exists, that the payload hashes to `evidence_root`, or that the storage
/// system is durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedAuthorityIndex {
    /// Persisted permit identifier.
    pub permit_id: String,
    /// Persisted cross-ledger trace identifier.
    pub trace_id: String,
    /// Persisted exact-action commitment.
    pub action_digest: String,
    /// Persisted effective-policy commitment.
    pub policy_digest: String,
    /// Persisted signed-policy commitment.
    pub signed_policy_digest: String,
    /// Persisted evidence-archive root.
    pub evidence_root: String,
    /// Persisted authorizing-decision commitment.
    pub decision_digest: String,
    /// Persisted lower validity bound.
    pub valid_from_seq: u64,
    /// Persisted upper validity bound.
    pub expires_at_seq: u64,
}

impl From<&AuthorityReconstructionHandle> for PersistedAuthorityIndex {
    fn from(handle: &AuthorityReconstructionHandle) -> Self {
        Self {
            permit_id: handle.permit_id.clone(),
            trace_id: handle.trace_id.clone(),
            action_digest: handle.action_digest.clone(),
            policy_digest: handle.policy_digest.clone(),
            signed_policy_digest: handle.signed_policy_digest.clone(),
            evidence_root: handle.evidence_root.clone(),
            decision_digest: handle.decision_digest.clone(),
            valid_from_seq: handle.valid_from_seq,
            expires_at_seq: handle.expires_at_seq,
        }
    }
}

/// Fail-closed mismatch while linking an admission to persisted audit material.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum ReconstructionIndexError {
    /// One authority-relevant persisted field disagrees with the admission handle.
    #[error("reconstruction index mismatch: {0}")]
    Mismatch(&'static str),
}

fn require_equal<T: PartialEq>(
    name: &'static str,
    expected: &T,
    actual: &T,
) -> Result<(), ReconstructionIndexError> {
    if expected == actual {
        Ok(())
    } else {
        Err(ReconstructionIndexError::Mismatch(name))
    }
}

/// Verify that a persisted authority index is exactly bound to an admission.
///
/// This is an audit-side linkage check. It intentionally performs no provider
/// dispatch and does not make an execution authorization decision.
pub fn verify_reconstruction_index(
    handle: &AuthorityReconstructionHandle,
    index: &PersistedAuthorityIndex,
) -> Result<(), ReconstructionIndexError> {
    require_equal("permit_id", &handle.permit_id, &index.permit_id)?;
    require_equal("trace_id", &handle.trace_id, &index.trace_id)?;
    require_equal("action_digest", &handle.action_digest, &index.action_digest)?;
    require_equal("policy_digest", &handle.policy_digest, &index.policy_digest)?;
    require_equal(
        "signed_policy_digest",
        &handle.signed_policy_digest,
        &index.signed_policy_digest,
    )?;
    require_equal("evidence_root", &handle.evidence_root, &index.evidence_root)?;
    require_equal(
        "decision_digest",
        &handle.decision_digest,
        &index.decision_digest,
    )?;
    require_equal("valid_from_seq", &handle.valid_from_seq, &index.valid_from_seq)?;
    require_equal("expires_at_seq", &handle.expires_at_seq, &index.expires_at_seq)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        AuthorityReconstructionHandle, PersistedAuthorityIndex, ReconstructionIndexError,
        verify_reconstruction_index,
    };
    use claimsieve_compact_admission::ShadowCompactAdmission;

    fn sample_admission() -> ShadowCompactAdmission {
        ShadowCompactAdmission {
            permit_id: "permit:1".to_owned(),
            trace_id: "trace:1".to_owned(),
            action_digest: "sha256:action".to_owned(),
            policy_digest: "sha256:policy".to_owned(),
            signed_policy_digest: "sha256:signed-policy".to_owned(),
            evidence_root: "sha256:evidence".to_owned(),
            decision_digest: "sha256:decision".to_owned(),
            valid_from_seq: 10,
            expires_at_seq: 15,
        }
    }

    fn sample_handle() -> AuthorityReconstructionHandle {
        AuthorityReconstructionHandle::from(&sample_admission())
    }

    #[test]
    fn matching_index_is_reconstructable_linkage() {
        let handle = sample_handle();
        let index = PersistedAuthorityIndex::from(&handle);
        assert_eq!(verify_reconstruction_index(&handle, &index), Ok(()));
    }

    #[test]
    fn action_mutation_breaks_reconstruction_linkage() {
        let handle = sample_handle();
        let mut index = PersistedAuthorityIndex::from(&handle);
        index.action_digest = "sha256:mutated-action".to_owned();
        assert_eq!(
            verify_reconstruction_index(&handle, &index),
            Err(ReconstructionIndexError::Mismatch("action_digest"))
        );
    }

    #[test]
    fn evidence_mutation_breaks_reconstruction_linkage() {
        let handle = sample_handle();
        let mut index = PersistedAuthorityIndex::from(&handle);
        index.evidence_root = "sha256:mutated-evidence".to_owned();
        assert_eq!(
            verify_reconstruction_index(&handle, &index),
            Err(ReconstructionIndexError::Mismatch("evidence_root"))
        );
    }

    #[test]
    fn decision_mutation_breaks_reconstruction_linkage() {
        let handle = sample_handle();
        let mut index = PersistedAuthorityIndex::from(&handle);
        index.decision_digest = "sha256:mutated-decision".to_owned();
        assert_eq!(
            verify_reconstruction_index(&handle, &index),
            Err(ReconstructionIndexError::Mismatch("decision_digest"))
        );
    }

    #[test]
    fn policy_mutation_breaks_reconstruction_linkage() {
        let handle = sample_handle();
        let mut index = PersistedAuthorityIndex::from(&handle);
        index.policy_digest = "sha256:mutated-policy".to_owned();
        assert_eq!(
            verify_reconstruction_index(&handle, &index),
            Err(ReconstructionIndexError::Mismatch("policy_digest"))
        );
    }

    #[test]
    fn trace_mutation_breaks_reconstruction_linkage() {
        let handle = sample_handle();
        let mut index = PersistedAuthorityIndex::from(&handle);
        index.trace_id = "trace:other".to_owned();
        assert_eq!(
            verify_reconstruction_index(&handle, &index),
            Err(ReconstructionIndexError::Mismatch("trace_id"))
        );
    }

    #[test]
    fn validity_mutation_breaks_reconstruction_linkage() {
        let handle = sample_handle();
        let mut index = PersistedAuthorityIndex::from(&handle);
        index.expires_at_seq += 1;
        assert_eq!(
            verify_reconstruction_index(&handle, &index),
            Err(ReconstructionIndexError::Mismatch("expires_at_seq"))
        );
    }
}
