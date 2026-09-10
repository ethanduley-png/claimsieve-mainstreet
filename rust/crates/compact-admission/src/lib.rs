#![forbid(unsafe_code)]

//! Shadow-only compact authority admission candidate.
//!
//! This crate is deliberately not an execution authority. It models the target
//! compact fast path without accepting full `Policy`, `Evidence`, or `Decision`
//! objects. The existing runtime remains the reference execution path until
//! shadow equivalence, atomic one-use reservation, and formal compilation are
//! all green.

use claimsieve_protocol::{
    Permit, Proposal, action_digest, approval_digest, destination_digest, parameter_digest,
    proposal_digest,
};
use claimsieve_runtime::verify_permit_signature;
use ed25519_dalek::VerifyingKey;
use std::collections::BTreeMap;
use thiserror::Error;

/// Bounded current authority facts supplied by separately trusted state services.
///
/// These fields are intentionally small. A production compact executor must
/// derive them from trusted policy, identity, containment, and reservation
/// services rather than from the agent or proposal payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CurrentAuthorityFacts {
    /// Current logical sequence.
    pub sequence: u64,
    /// Digest of the policy that is currently effective for execution.
    pub effective_policy_digest: String,
    /// Digest of the signed policy envelope currently effective for execution.
    pub effective_signed_policy_digest: String,
    /// Campaign whose authority state is being checked.
    pub campaign_id: String,
    /// Whether the effective policy remains active.
    pub policy_active: bool,
    /// Whether the proposal principal remains active.
    pub principal_active: bool,
    /// Whether the campaign remains active.
    pub campaign_active: bool,
    /// Global execution freeze state.
    pub execution_frozen: bool,
    /// Campaign suspension state.
    pub campaign_suspended: bool,
    /// Permit revocation state.
    pub permit_revoked: bool,
    /// Snapshot indication that the permit is already consumed.
    ///
    /// This field is adequate only for shadow comparison. Production dispatch
    /// still requires an atomic reservation operation at the commit point.
    pub permit_consumed: bool,
}

/// Compact result retained only for shadow equivalence and audit comparison.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowCompactAdmission {
    /// Permit identifier.
    pub permit_id: String,
    /// Cross-ledger trace identifier.
    pub trace_id: String,
    /// Exact action digest.
    pub action_digest: String,
    /// Effective policy digest.
    pub policy_digest: String,
    /// Effective signed-policy envelope digest.
    pub signed_policy_digest: String,
    /// Commitment to the preserved evidence archive.
    pub evidence_root: String,
    /// Commitment to the exact authorizing decision.
    pub decision_digest: String,
    /// First valid logical sequence.
    pub valid_from_seq: u64,
    /// Last valid logical sequence.
    pub expires_at_seq: u64,
}

/// Fail-closed rejection reasons for the shadow compact path.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CompactAdmissionError {
    /// Unsupported protocol object.
    #[error("unsupported schema: {0}")]
    UnsupportedSchema(&'static str),
    /// Permit authority key is not in the trusted active key set.
    #[error("unknown or inactive authority key")]
    UnknownAuthorityKey,
    /// Permit signature did not verify under the trusted authority key.
    #[error("permit signature invalid")]
    InvalidSignature,
    /// Current policy is not active.
    #[error("current policy authority is inactive")]
    PolicyInactive,
    /// Current principal identity is not active.
    #[error("current principal authority is inactive")]
    PrincipalInactive,
    /// Execution is globally frozen.
    #[error("execution globally frozen")]
    ExecutionFrozen,
    /// Permit was revoked.
    #[error("permit revoked")]
    PermitRevoked,
    /// Campaign is suspended or otherwise inactive.
    #[error("campaign authority inactive")]
    CampaignInactive,
    /// Permit has already been consumed according to the shadow snapshot.
    #[error("permit already consumed")]
    PermitConsumed,
    /// Permit sequence window does not contain the current sequence.
    #[error("permit outside validity sequence")]
    OutsideValidity,
    /// Permit is not one-use.
    #[error("permit must be one use")]
    NotOneUse,
    /// A compact execution binding did not match.
    #[error("compact binding mismatch: {0}")]
    Binding(&'static str),
    /// Canonical digest construction failed.
    #[error("protocol digest failure: {0}")]
    Protocol(String),
}

fn protocol_error(error: impl std::fmt::Display) -> CompactAdmissionError {
    CompactAdmissionError::Protocol(error.to_string())
}

fn check_binding(
    name: &'static str,
    actual: &str,
    expected: &str,
) -> Result<(), CompactAdmissionError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CompactAdmissionError::Binding(name))
    }
}

/// Evaluate the compact target semantics in shadow mode.
///
/// The function signature intentionally contains no full `Policy`, `Evidence`,
/// or `Decision` argument. Historical evidence and decision material are bound
/// through the authority-signed permit commitments instead of being traversed
/// here.
///
/// This function must not directly authorize a provider call. The production
/// path still requires atomic one-use reservation and successful shadow
/// equivalence against the reference executor before promotion.
pub fn verify_shadow_compact_preflight(
    permit: &Permit,
    proposal: &Proposal,
    current: &CurrentAuthorityFacts,
    authority_keys: &BTreeMap<String, VerifyingKey>,
) -> Result<ShadowCompactAdmission, CompactAdmissionError> {
    if permit.schema_version != "claimsieve.permit.v1" {
        return Err(CompactAdmissionError::UnsupportedSchema("permit"));
    }
    if proposal.schema_version != "claimsieve.proposal.v1" {
        return Err(CompactAdmissionError::UnsupportedSchema("proposal"));
    }

    let authority_key = authority_keys
        .get(&permit.authority_key_id)
        .ok_or(CompactAdmissionError::UnknownAuthorityKey)?;
    verify_permit_signature(permit, authority_key)
        .map_err(|_| CompactAdmissionError::InvalidSignature)?;

    if !current.policy_active {
        return Err(CompactAdmissionError::PolicyInactive);
    }
    if !current.principal_active {
        return Err(CompactAdmissionError::PrincipalInactive);
    }
    if current.execution_frozen {
        return Err(CompactAdmissionError::ExecutionFrozen);
    }
    if current.permit_revoked {
        return Err(CompactAdmissionError::PermitRevoked);
    }
    if !current.campaign_active || current.campaign_suspended {
        return Err(CompactAdmissionError::CampaignInactive);
    }
    if current.permit_consumed {
        return Err(CompactAdmissionError::PermitConsumed);
    }
    if current.sequence < permit.valid_from_seq || current.sequence > permit.expires_at_seq {
        return Err(CompactAdmissionError::OutsideValidity);
    }
    if permit.max_uses != 1 {
        return Err(CompactAdmissionError::NotOneUse);
    }

    check_binding("trace_id", &permit.trace_id, &proposal.trace_id)?;
    check_binding("tenant_id", &permit.tenant_id, &proposal.tenant_id)?;
    check_binding("campaign_id", &permit.campaign_id, &proposal.campaign_id)?;
    check_binding("current_campaign_id", &permit.campaign_id, &current.campaign_id)?;
    check_binding("principal", &permit.principal, &proposal.principal)?;
    check_binding(
        "policy_digest",
        &permit.policy_digest,
        &current.effective_policy_digest,
    )?;
    check_binding(
        "signed_policy_digest",
        &permit.signed_policy_digest,
        &current.effective_signed_policy_digest,
    )?;

    let expected_proposal_digest = proposal_digest(proposal).map_err(protocol_error)?;
    check_binding(
        "proposal_digest",
        &permit.proposal_digest,
        &expected_proposal_digest,
    )?;
    let expected_action_digest = action_digest(proposal).map_err(protocol_error)?;
    check_binding(
        "action_digest",
        &permit.action_digest,
        &expected_action_digest,
    )?;
    let expected_destination_digest = destination_digest(proposal).map_err(protocol_error)?;
    check_binding(
        "destination_digest",
        &permit.destination_digest,
        &expected_destination_digest,
    )?;
    let expected_parameter_digest = parameter_digest(proposal).map_err(protocol_error)?;
    check_binding(
        "parameter_digest",
        &permit.parameter_digest,
        &expected_parameter_digest,
    )?;
    let expected_approval_digest = approval_digest(proposal).map_err(protocol_error)?;
    if permit.approval_digest != expected_approval_digest {
        return Err(CompactAdmissionError::Binding("approval_digest"));
    }

    Ok(ShadowCompactAdmission {
        permit_id: permit.permit_id.clone(),
        trace_id: permit.trace_id.clone(),
        action_digest: permit.action_digest.clone(),
        policy_digest: permit.policy_digest.clone(),
        signed_policy_digest: permit.signed_policy_digest.clone(),
        evidence_root: permit.evidence_root.clone(),
        decision_digest: permit.decision_digest.clone(),
        valid_from_seq: permit.valid_from_seq,
        expires_at_seq: permit.expires_at_seq,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        CompactAdmissionError, CurrentAuthorityFacts, verify_shadow_compact_preflight,
    };
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    use claimsieve_protocol::{
        Action, Destination, Objective, Permit, Proposal, action_digest, approval_digest,
        canonical_bytes, destination_digest, parameter_digest, proposal_digest,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde::Serialize;
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Serialize)]
    struct UnsignedPermitForTest<'a> {
        schema_version: &'a str,
        permit_id: &'a str,
        trace_id: &'a str,
        tenant_id: &'a str,
        campaign_id: &'a str,
        principal: &'a str,
        proposal_digest: &'a str,
        action_digest: &'a str,
        destination_digest: &'a str,
        parameter_digest: &'a str,
        policy_digest: &'a str,
        signed_policy_digest: &'a str,
        evidence_root: &'a str,
        decision_digest: &'a str,
        approval_digest: &'a Option<String>,
        prior_campaign_state_digest: &'a str,
        campaign_state_digest: &'a str,
        valid_from_seq: u64,
        expires_at_seq: u64,
        max_uses: u8,
        nonce: &'a str,
        authority_key_id: &'a str,
    }

    fn sample_proposal() -> Proposal {
        Proposal {
            schema_version: "claimsieve.proposal.v1".to_owned(),
            proposal_id: "proposal:compact-shadow".to_owned(),
            trace_id: "trace:compact-shadow".to_owned(),
            tenant_id: "tenant:test".to_owned(),
            campaign_id: "campaign:test".to_owned(),
            session_id: "session:test".to_owned(),
            parent_action_id: None,
            principal: "spiffe://claimsieve.test/agent".to_owned(),
            objective: Objective {
                root: "send approved message".to_owned(),
                subgoal: "notify".to_owned(),
                expected_effect: "one message sent".to_owned(),
                constraints: Vec::new(),
            },
            action: Action {
                kind: "send_message".to_owned(),
                effect_class: "communication".to_owned(),
                destination: Destination {
                    scheme: "sms".to_owned(),
                    authority: "+15555550100".to_owned(),
                    resource: "primary".to_owned(),
                    trust_domain: "test".to_owned(),
                },
                method: "SEND".to_owned(),
                parameters: BTreeMap::new(),
                reversibility: "reversible".to_owned(),
            },
            evidence_refs: Vec::new(),
            approval: None,
            requested_at_seq: 9,
            risk_tags: Vec::new(),
        }
    }

    fn sign_test_permit(
        permit: &Permit,
        signing_key: &SigningKey,
    ) -> Result<String, String> {
        let unsigned = UnsignedPermitForTest {
            schema_version: &permit.schema_version,
            permit_id: &permit.permit_id,
            trace_id: &permit.trace_id,
            tenant_id: &permit.tenant_id,
            campaign_id: &permit.campaign_id,
            principal: &permit.principal,
            proposal_digest: &permit.proposal_digest,
            action_digest: &permit.action_digest,
            destination_digest: &permit.destination_digest,
            parameter_digest: &permit.parameter_digest,
            policy_digest: &permit.policy_digest,
            signed_policy_digest: &permit.signed_policy_digest,
            evidence_root: &permit.evidence_root,
            decision_digest: &permit.decision_digest,
            approval_digest: &permit.approval_digest,
            prior_campaign_state_digest: &permit.prior_campaign_state_digest,
            campaign_state_digest: &permit.campaign_state_digest,
            valid_from_seq: permit.valid_from_seq,
            expires_at_seq: permit.expires_at_seq,
            max_uses: permit.max_uses,
            nonce: &permit.nonce,
            authority_key_id: &permit.authority_key_id,
        };
        let encoded = canonical_bytes(&unsigned).map_err(|error| error.to_string())?;
        let mut message = b"CLAIMSIEVE\0permit-v1\0".to_vec();
        message.extend_from_slice(&encoded);
        let signature = signing_key.sign(&message);
        Ok(format!(
            "ed25519:{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ))
    }

    fn sample_signed_permit() -> Result<(Permit, Proposal, SigningKey), String> {
        let proposal = sample_proposal();
        let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
        let mut permit = Permit {
            schema_version: "claimsieve.permit.v1".to_owned(),
            permit_id: "permit:compact-shadow".to_owned(),
            trace_id: proposal.trace_id.clone(),
            tenant_id: proposal.tenant_id.clone(),
            campaign_id: proposal.campaign_id.clone(),
            principal: proposal.principal.clone(),
            proposal_digest: proposal_digest(&proposal).map_err(|error| error.to_string())?,
            action_digest: action_digest(&proposal).map_err(|error| error.to_string())?,
            destination_digest: destination_digest(&proposal).map_err(|error| error.to_string())?,
            parameter_digest: parameter_digest(&proposal).map_err(|error| error.to_string())?,
            policy_digest: format!("sha256:{}", "1".repeat(64)),
            signed_policy_digest: format!("sha256:{}", "2".repeat(64)),
            evidence_root: format!("sha256:{}", "3".repeat(64)),
            decision_digest: format!("sha256:{}", "4".repeat(64)),
            approval_digest: approval_digest(&proposal).map_err(|error| error.to_string())?,
            prior_campaign_state_digest: format!("sha256:{}", "5".repeat(64)),
            campaign_state_digest: format!("sha256:{}", "6".repeat(64)),
            valid_from_seq: 10,
            expires_at_seq: 15,
            max_uses: 1,
            nonce: "0123456789abcdef0123456789abcdef".to_owned(),
            authority_key_id: "authority:test".to_owned(),
            signature: String::new(),
        };
        permit.signature = sign_test_permit(&permit, &signing_key)?;
        Ok((permit, proposal, signing_key))
    }

    fn current(permit: &Permit) -> CurrentAuthorityFacts {
        CurrentAuthorityFacts {
            sequence: 12,
            effective_policy_digest: permit.policy_digest.clone(),
            effective_signed_policy_digest: permit.signed_policy_digest.clone(),
            campaign_id: permit.campaign_id.clone(),
            policy_active: true,
            principal_active: true,
            campaign_active: true,
            execution_frozen: false,
            campaign_suspended: false,
            permit_revoked: false,
            permit_consumed: false,
        }
    }

    #[test]
    fn valid_shadow_compact_preflight_accepts_without_full_evidence() -> Result<(), String> {
        let (permit, proposal, signing_key) = sample_signed_permit()?;
        let mut keys = BTreeMap::new();
        keys.insert(permit.authority_key_id.clone(), signing_key.verifying_key());
        let admission = verify_shadow_compact_preflight(
            &permit,
            &proposal,
            &current(&permit),
            &keys,
        )
        .map_err(|error| error.to_string())?;
        assert_eq!(admission.action_digest, permit.action_digest);
        assert_eq!(admission.evidence_root, permit.evidence_root);
        Ok(())
    }

    #[test]
    fn shadow_compact_preflight_fails_closed_on_current_state() -> Result<(), String> {
        let (permit, proposal, signing_key) = sample_signed_permit()?;
        let mut keys = BTreeMap::new();
        keys.insert(permit.authority_key_id.clone(), signing_key.verifying_key());

        let mut revoked = current(&permit);
        revoked.permit_revoked = true;
        assert_eq!(
            verify_shadow_compact_preflight(&permit, &proposal, &revoked, &keys),
            Err(CompactAdmissionError::PermitRevoked)
        );

        let mut consumed = current(&permit);
        consumed.permit_consumed = true;
        assert_eq!(
            verify_shadow_compact_preflight(&permit, &proposal, &consumed, &keys),
            Err(CompactAdmissionError::PermitConsumed)
        );

        let mut expired = current(&permit);
        expired.sequence = 16;
        assert_eq!(
            verify_shadow_compact_preflight(&permit, &proposal, &expired, &keys),
            Err(CompactAdmissionError::OutsideValidity)
        );
        Ok(())
    }

    #[test]
    fn shadow_compact_preflight_rejects_mutated_action() -> Result<(), String> {
        let (permit, mut proposal, signing_key) = sample_signed_permit()?;
        let mut keys = BTreeMap::new();
        keys.insert(permit.authority_key_id.clone(), signing_key.verifying_key());
        proposal.action.destination.authority = "+15555550999".to_owned();
        let result = verify_shadow_compact_preflight(
            &permit,
            &proposal,
            &current(&permit),
            &keys,
        );
        assert!(matches!(
            result,
            Err(CompactAdmissionError::Binding("proposal_digest"))
                | Err(CompactAdmissionError::Binding("action_digest"))
                | Err(CompactAdmissionError::Binding("destination_digest"))
        ));
        Ok(())
    }

    #[test]
    fn shadow_compact_preflight_rejects_bad_signature() -> Result<(), String> {
        let (mut permit, proposal, signing_key) = sample_signed_permit()?;
        let mut keys = BTreeMap::new();
        keys.insert(permit.authority_key_id.clone(), signing_key.verifying_key());
        permit.signature = "ed25519:AA".to_owned();
        assert_eq!(
            verify_shadow_compact_preflight(&permit, &proposal, &current(&permit), &keys),
            Err(CompactAdmissionError::InvalidSignature)
        );
        Ok(())
    }

    #[test]
    fn current_policy_digest_is_a_compact_runtime_guard() -> Result<(), String> {
        let (permit, proposal, signing_key) = sample_signed_permit()?;
        let mut keys = BTreeMap::new();
        keys.insert(permit.authority_key_id.clone(), signing_key.verifying_key());
        let mut facts = current(&permit);
        facts.effective_policy_digest = format!("sha256:{}", "9".repeat(64));
        assert_eq!(
            verify_shadow_compact_preflight(&permit, &proposal, &facts, &keys),
            Err(CompactAdmissionError::Binding("policy_digest"))
        );
        Ok(())
    }

    #[test]
    fn test_module_imports_remain_used() {
        let set: BTreeSet<String> = BTreeSet::new();
        assert!(set.is_empty());
    }
}
