#![forbid(unsafe_code)]

//! Portable protocol types and restricted canonical JSON for ClaimSieve.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// Largest integer accepted by the cross-language canonicalization profile.
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
/// Maximum nested array or object depth.
pub const MAX_DEPTH: usize = 64;
/// Maximum nodes in one canonical JSON value.
pub const MAX_NODES: usize = 100_000;
/// Maximum Unicode scalar values in one string.
pub const MAX_STRING_LENGTH: usize = 1_048_576;
/// Maximum direct children in one array or object.
pub const MAX_CONTAINER_ITEMS: usize = 100_000;

/// Errors produced by protocol canonicalization and validation.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// Serialization failed.
    #[error("serialization failed: {0}")]
    Serialization(String),
    /// Floating-point numbers are forbidden by the protocol profile.
    #[error("floating-point value forbidden at {0}")]
    FloatForbidden(String),
    /// Integer cannot be represented exactly by every supported runtime.
    #[error("integer outside the safe canonical range at {0}")]
    IntegerOutOfRange(String),
    /// A string is not normalized to Unicode NFC.
    #[error("string is not NFC-normalized at {0}")]
    StringNotNormalized(String),
    /// A string contains a control character.
    #[error("control character forbidden at {0}")]
    ControlCharacter(String),
    /// A canonical value exceeds a structural resource bound.
    #[error("canonical JSON resource limit exceeded at {0}")]
    ResourceLimit(String),
    /// A required version is unsupported.
    #[error("unsupported schema version: {0}")]
    UnsupportedSchema(String),
}

/// Human-authorized objective and declared subgoal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Objective {
    /// Root human objective.
    pub root: String,
    /// Policy-named subgoal.
    pub subgoal: String,
    /// Expected externally observable effect.
    pub expected_effect: String,
    /// Explicit constraints that must remain true.
    pub constraints: Vec<String>,
}

/// Exact external destination.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    /// Destination scheme, such as sms or https.
    pub scheme: String,
    /// Exact provider authority or recipient.
    pub authority: String,
    /// Provider-specific resource identifier.
    pub resource: String,
    /// Named trust domain.
    pub trust_domain: String,
}

/// Proposed exact action.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Action {
    /// Policy action kind.
    pub kind: String,
    /// Effect class.
    pub effect_class: String,
    /// Exact destination.
    pub destination: Destination,
    /// Method or verb.
    pub method: String,
    /// Structured parameters. Floats are rejected during canonicalization.
    pub parameters: BTreeMap<String, Value>,
    /// Reversibility classification.
    pub reversibility: String,
}

/// Human approval bound to the exact proposal display.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    /// Approval protocol version.
    pub schema_version: String,
    /// Approval identifier.
    pub approval_id: String,
    /// Authenticated approver workload identity.
    pub approver: String,
    /// Digest of the proposal with approval removed.
    pub proposal_digest: String,
    /// Digest of the exact human display.
    pub display_digest: String,
    /// Logical approval sequence.
    pub approved_at_seq: u64,
    /// Logical expiry sequence.
    pub expires_at_seq: u64,
    /// Independent human-approval verification key identifier.
    pub approver_key_id: String,
    /// Ed25519 signature over this approval with the signature field omitted.
    pub signature: String,
}

/// Agent proposal. A proposal is never permission by itself.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Proposal {
    /// Protocol version.
    pub schema_version: String,
    /// Proposal identifier.
    pub proposal_id: String,
    /// Cross-ledger trace identifier.
    pub trace_id: String,
    /// Tenant identifier.
    pub tenant_id: String,
    /// Durable campaign identifier.
    pub campaign_id: String,
    /// Ephemeral session identifier.
    pub session_id: String,
    /// Parent action identifier, if any.
    pub parent_action_id: Option<String>,
    /// Workload identity of the proposal writer.
    pub principal: String,
    /// Objective chain.
    pub objective: Objective,
    /// Exact action.
    pub action: Action,
    /// Digests of evidence records.
    pub evidence_refs: Vec<String>,
    /// Optional human approval.
    pub approval: Option<Approval>,
    /// Logical request sequence.
    pub requested_at_seq: u64,
    /// Declared and observed risk tags.
    pub risk_tags: Vec<String>,
}

/// Evidence record supplied to the deterministic kernel.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Protocol version.
    pub schema_version: String,
    /// Policy evidence type.
    #[serde(rename = "type")]
    pub evidence_type: String,
    /// Workload identity of the source.
    pub source: String,
    /// Evidence subject.
    pub subject: String,
    /// Logical observation sequence.
    pub observed_at_seq: u64,
    /// Whether source verification succeeded.
    pub verified: bool,
    /// Structured content.
    pub content: BTreeMap<String, Value>,
    /// Type-scoped evidence issuer verification-key identifier.
    pub issuer_key_id: String,
    /// Domain-separated Ed25519 signature over the unsigned evidence body.
    pub signature: String,
}

/// Campaign budget limits.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CampaignLimits {
    /// Maximum proposals in the campaign.
    pub max_actions: u64,
    /// Maximum denied actions before suspension.
    pub max_denials: u64,
    /// Maximum distinct destinations.
    pub max_new_destinations: u64,
    /// Maximum distinct sessions.
    pub max_sessions: u64,
    /// Maximum new trust-domain crossings.
    pub max_boundary_crossings: u64,
    /// Maximum encoded fragments before suspension.
    pub max_encoded_fragments: u64,
}

/// Deterministic tenant policy.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Protocol version.
    pub schema_version: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Monotonic policy version.
    pub version: u64,
    /// Tenant identifier.
    pub tenant_id: String,
    /// Workload identities authorized to submit proposals.
    pub allowed_principals: Vec<String>,
    /// Allowed action kinds.
    pub allowed_action_kinds: Vec<String>,
    /// Allowed effect classes.
    pub allowed_effect_classes: Vec<String>,
    /// Allowed trust domains.
    pub allowed_trust_domains: Vec<String>,
    /// Allowed policy-named subgoals.
    pub allowed_subgoals: Vec<String>,
    /// Action kinds or effect classes requiring human approval.
    pub approval_required_for: Vec<String>,
    /// Human-approval key identifiers authorized by this policy.
    pub allowed_approver_key_ids: Vec<String>,
    /// Human identities authorized to approve actions.
    pub allowed_approver_identities: Vec<String>,
    /// Required evidence types.
    pub required_evidence: Vec<String>,
    /// Trusted source identities for each evidence type.
    pub trusted_evidence_sources: BTreeMap<String, Vec<String>>,
    /// Trusted evidence signer key identifiers for each evidence type.
    pub trusted_evidence_key_ids: BTreeMap<String, Vec<String>>,
    /// Maximum logical evidence age.
    pub freshness_window: u64,
    /// Durable campaign limits.
    pub campaign_limits: CampaignLimits,
    /// Risk tags that deny the action.
    pub deny_risk_tags: Vec<String>,
    /// Risk tags that suspend the campaign.
    pub suspend_risk_tags: Vec<String>,
}

/// Kernel verdict.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Verdict {
    /// All gates passed.
    Allow,
    /// Proposal is denied.
    Deny,
    /// Fresh human approval is required.
    RequireHuman,
    /// Action and evidence are quarantined.
    Quarantine,
    /// The durable campaign is suspended.
    SuspendCampaign,
}

/// Signed-kernel decision body.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    /// Protocol version.
    pub schema_version: String,
    /// Decision identifier.
    pub decision_id: String,
    /// Cross-ledger trace identifier.
    pub trace_id: String,
    /// Digest of the proposal approval subject.
    pub proposal_digest: String,
    /// Digest of the exact human-approval artifact, when present.
    pub approval_digest: Option<String>,
    /// Digest of the exact policy.
    pub policy_digest: String,
    /// Digest of the evidence snapshot evaluated by the kernel.
    pub evidence_root: String,
    /// Digest of the exact predecessor campaign state.
    pub prior_campaign_state_digest: String,
    /// Digest of resulting campaign state.
    pub campaign_state_digest: String,
    /// Verdict.
    pub verdict: Verdict,
    /// Stable reason codes.
    pub reason_codes: Vec<String>,
    /// Logical decision sequence.
    pub decided_at_seq: u64,
}

/// One-use exact-action permit.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Permit {
    /// Protocol version.
    pub schema_version: String,
    /// Permit identifier.
    pub permit_id: String,
    /// Cross-ledger trace identifier.
    pub trace_id: String,
    /// Tenant identifier.
    pub tenant_id: String,
    /// Campaign identifier.
    pub campaign_id: String,
    /// Proposal principal.
    pub principal: String,
    /// Proposal digest.
    pub proposal_digest: String,
    /// Exact action digest.
    pub action_digest: String,
    /// Exact destination digest.
    pub destination_digest: String,
    /// Exact parameter digest.
    pub parameter_digest: String,
    /// Exact policy digest.
    pub policy_digest: String,
    /// Digest of the signed policy envelope.
    pub signed_policy_digest: String,
    /// Evidence root.
    pub evidence_root: String,
    /// Digest of the exact decision that authorized issuance.
    pub decision_digest: String,
    /// Approval digest when approval exists.
    pub approval_digest: Option<String>,
    /// Digest of the predecessor campaign state authorized for transition.
    pub prior_campaign_state_digest: String,
    /// Digest of the resulting campaign state.
    pub campaign_state_digest: String,
    /// First valid logical sequence.
    pub valid_from_seq: u64,
    /// Last valid logical sequence.
    pub expires_at_seq: u64,
    /// Must equal one.
    pub max_uses: u8,
    /// Unique nonce.
    pub nonce: String,
    /// Authority verification-key identifier.
    pub authority_key_id: String,
    /// Domain-separated Ed25519 signature.
    pub signature: String,
}

/// Reservation record created before execution.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    /// Protocol version.
    pub schema_version: String,
    /// Permit identifier.
    pub permit_id: String,
    /// Bound action digest.
    pub action_digest: String,
    /// Logical reservation sequence.
    pub reserved_at_seq: u64,
    /// Reservation identifier.
    pub reservation_id: String,
}

/// Executor receipt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutorReceipt {
    /// Protocol version.
    pub schema_version: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Permit identifier.
    pub permit_id: String,
    /// Reservation identifier.
    pub reservation_id: String,
    /// Exact action digest.
    pub action_digest: String,
    /// Provider status.
    pub provider_status: String,
    /// Provider operation identifier.
    pub provider_id: Option<String>,
    /// Logical attempt sequence.
    pub attempted_at_seq: u64,
    /// Executor key identifier.
    pub executor_key_id: String,
    /// Signature.
    pub signature: String,
}

/// Observer reconciliation state.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reconciliation {
    /// Exact effect was observed.
    ConfirmedSuccess,
    /// Provider rejection was confirmed.
    ConfirmedFailure,
    /// Outcome cannot be determined.
    OutcomeUnknown,
    /// Observed effect differs from authorized effect.
    DivergentEffect,
}

/// Observer receipt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ObserverReceipt {
    /// Protocol version.
    pub schema_version: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Permit identifier.
    pub permit_id: String,
    /// Digest of observed action, when observable.
    pub observed_action_digest: Option<String>,
    /// Reconciliation result.
    pub reconciliation: Reconciliation,
    /// Logical observation sequence.
    pub observed_at_seq: u64,
    /// Observer key identifier.
    pub observer_key_id: String,
    /// Signature.
    pub signature: String,
}

fn validate_string(value: &str, path: &str) -> Result<(), ProtocolError> {
    if value.chars().count() > MAX_STRING_LENGTH {
        return Err(ProtocolError::ResourceLimit(path.to_owned()));
    }
    if !value.nfc().eq(value.chars()) {
        return Err(ProtocolError::StringNotNormalized(path.to_owned()));
    }
    if value.chars().any(char::is_control) {
        return Err(ProtocolError::ControlCharacter(path.to_owned()));
    }
    Ok(())
}

fn validate_value(
    value: &Value,
    path: &str,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ProtocolError> {
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_NODES || depth > MAX_DEPTH {
        return Err(ProtocolError::ResourceLimit(path.to_owned()));
    }
    match value {
        Value::Null | Value::Bool(_) => Ok(()),
        Value::String(text) => validate_string(text, path),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                if value.unsigned_abs() <= MAX_SAFE_INTEGER {
                    Ok(())
                } else {
                    Err(ProtocolError::IntegerOutOfRange(path.to_owned()))
                }
            } else if let Some(value) = number.as_u64() {
                if value <= MAX_SAFE_INTEGER {
                    Ok(())
                } else {
                    Err(ProtocolError::IntegerOutOfRange(path.to_owned()))
                }
            } else {
                Err(ProtocolError::FloatForbidden(path.to_owned()))
            }
        }
        Value::Array(items) => {
            if items.len() > MAX_CONTAINER_ITEMS {
                return Err(ProtocolError::ResourceLimit(path.to_owned()));
            }
            for (index, item) in items.iter().enumerate() {
                validate_value(item, &format!("{path}[{index}]"), depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            if map.len() > MAX_CONTAINER_ITEMS {
                return Err(ProtocolError::ResourceLimit(path.to_owned()));
            }
            for (key, item) in map {
                validate_string(key, &format!("{path}.<key>"))?;
                validate_value(item, &format!("{path}.{key}"), depth + 1, nodes)?;
            }
            Ok(())
        }
    }
}

/// Return canonical JSON bytes under the restricted ClaimSieve profile.
pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let json = serde_json::to_value(value)
        .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
    let mut nodes = 0;
    validate_value(&json, "$", 0, &mut nodes)?;
    serde_jcs::to_vec(&json).map_err(|error| ProtocolError::Serialization(error.to_string()))
}

/// Return a `sha256:` digest of canonical JSON.
pub fn digest<T: Serialize>(value: &T) -> Result<String, ProtocolError> {
    let bytes = canonical_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

/// Produce the proposal subject approved by a human.
pub fn proposal_for_approval(proposal: &Proposal) -> Proposal {
    let mut subject = proposal.clone();
    subject.approval = None;
    subject
}

/// Digest the proposal subject approved by a human.
pub fn proposal_digest(proposal: &Proposal) -> Result<String, ProtocolError> {
    digest(&proposal_for_approval(proposal))
}

/// Digest the exact human display fields.
pub fn display_digest(proposal: &Proposal) -> Result<String, ProtocolError> {
    #[derive(Serialize)]
    struct Display<'a> {
        tenant_id: &'a str,
        campaign_id: &'a str,
        objective: &'a Objective,
        action: &'a Action,
        risk_tags: &'a [String],
    }
    digest(&Display {
        tenant_id: &proposal.tenant_id,
        campaign_id: &proposal.campaign_id,
        objective: &proposal.objective,
        action: &proposal.action,
        risk_tags: &proposal.risk_tags,
    })
}

/// Digest the exact action and authority context.
pub fn action_digest(proposal: &Proposal) -> Result<String, ProtocolError> {
    #[derive(Serialize)]
    struct ActionSubject<'a> {
        tenant_id: &'a str,
        campaign_id: &'a str,
        principal: &'a str,
        objective: &'a Objective,
        action: &'a Action,
    }
    digest(&ActionSubject {
        tenant_id: &proposal.tenant_id,
        campaign_id: &proposal.campaign_id,
        principal: &proposal.principal,
        objective: &proposal.objective,
        action: &proposal.action,
    })
}

/// Digest the exact destination.
pub fn destination_digest(proposal: &Proposal) -> Result<String, ProtocolError> {
    digest(&proposal.action.destination)
}

/// Digest the exact parameter map.
pub fn parameter_digest(proposal: &Proposal) -> Result<String, ProtocolError> {
    digest(&proposal.action.parameters)
}

/// Produce the independently signed human-approval subject.
pub fn approval_signing_subject(approval: &Approval) -> Result<Value, ProtocolError> {
    let mut value = serde_json::to_value(approval)
        .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        ProtocolError::Serialization("approval did not serialize as an object".to_owned())
    })?;
    object.remove("signature");
    Ok(value)
}

/// Digest approval when present.
pub fn approval_digest(proposal: &Proposal) -> Result<Option<String>, ProtocolError> {
    proposal.approval.as_ref().map(digest).transpose()
}

/// Compute a deterministic sorted evidence root.
pub fn evidence_root(evidence: &[Evidence]) -> Result<String, ProtocolError> {
    #[derive(Serialize)]
    struct Root {
        algorithm: &'static str,
        leaves: Vec<String>,
    }
    let mut leaves = evidence.iter().map(digest).collect::<Result<Vec<_>, _>>()?;
    leaves.sort();
    digest(&Root {
        algorithm: "claimsieve.sorted-digest-root.v1",
        leaves,
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_SAFE_INTEGER, canonical_bytes, digest};
    use serde_json::json;

    #[test]
    fn canonical_key_order_is_stable() {
        let left = json!({"b": 2, "a": 1});
        let right = json!({"a": 1, "b": 2});
        assert_eq!(digest(&left).ok(), digest(&right).ok());
    }

    #[test]
    fn floating_point_is_rejected() {
        let value = json!({"bad": 1.25});
        assert!(canonical_bytes(&value).is_err());
    }

    #[test]
    fn unsafe_integer_is_rejected() {
        let value = json!({"bad": MAX_SAFE_INTEGER + 1});
        assert!(canonical_bytes(&value).is_err());
    }

    #[test]
    fn safe_integer_boundary_is_accepted() {
        let value = json!({"good": MAX_SAFE_INTEGER});
        assert!(canonical_bytes(&value).is_ok());
    }

    #[test]
    fn non_nfc_string_is_rejected() {
        let value = json!({"bad": "e\u{301}"});
        assert!(canonical_bytes(&value).is_err());
    }

    #[test]
    fn control_character_is_rejected() {
        let value = json!({"bad": "line\nfeed"});
        assert!(canonical_bytes(&value).is_err());
    }
}
