#![forbid(unsafe_code)]

//! Exact-action permit issuance, reservation, containment, execution, and reconciliation.

pub mod hardening;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use claimsieve_kernel::{CampaignState, evaluate};
use claimsieve_protocol::{
    Action, Decision, Evidence, ExecutorReceipt, MAX_SAFE_INTEGER, ObserverReceipt, Permit, Policy,
    Proposal, ProtocolError, Reconciliation, Reservation, Verdict, action_digest, approval_digest,
    approval_signing_subject, canonical_bytes, destination_digest, digest, display_digest,
    evidence_root, parameter_digest, proposal_digest,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;
use uuid::Uuid;

/// Runtime errors. Every error is fail closed.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// Protocol failure.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Authorization or binding failure.
    #[error("authorization failed: {0}")]
    Authorization(String),
    /// Cryptographic verification failure.
    #[error("signature verification failed: {0}")]
    Signature(String),
    /// Permit was already reserved.
    #[error("permit replay or concurrent duplicate")]
    Replay,
    /// Connector failed before a classified provider result existed.
    #[error("connector failure: {0}")]
    Connector(String),
}

fn signing_message<T: Serialize>(domain: &str, value: &T) -> Result<Vec<u8>, RuntimeError> {
    let mut message = b"CLAIMSIEVE\0".to_vec();
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(&canonical_bytes(value)?);
    Ok(message)
}

fn sign(key: &SigningKey, domain: &str, value: &impl Serialize) -> Result<String, RuntimeError> {
    let signature = key.sign(&signing_message(domain, value)?);
    Ok(format!(
        "ed25519:{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn verify_signature(
    key: &VerifyingKey,
    domain: &str,
    value: &impl Serialize,
    encoded: &str,
) -> Result<(), RuntimeError> {
    let Some(raw) = encoded.strip_prefix("ed25519:") else {
        return Err(RuntimeError::Signature("unsupported encoding".to_owned()));
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|error| RuntimeError::Signature(error.to_string()))?;
    let signature = Signature::from_slice(&bytes)
        .map_err(|error| RuntimeError::Signature(error.to_string()))?;
    key.verify(&signing_message(domain, value)?, &signature)
        .map_err(|error| RuntimeError::Signature(error.to_string()))
}

/// Unsigned exact-action permit body.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnsignedPermit {
    /// Schema version.
    pub schema_version: String,
    /// Permit identifier.
    pub permit_id: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Tenant identifier.
    pub tenant_id: String,
    /// Campaign identifier.
    pub campaign_id: String,
    /// Proposal principal.
    pub principal: String,
    /// Proposal digest.
    pub proposal_digest: String,
    /// Action digest.
    pub action_digest: String,
    /// Destination digest.
    pub destination_digest: String,
    /// Parameter digest.
    pub parameter_digest: String,
    /// Policy digest.
    pub policy_digest: String,
    /// Signed policy envelope digest.
    pub signed_policy_digest: String,
    /// Evidence root.
    pub evidence_root: String,
    /// Digest of the exact authorizing decision.
    pub decision_digest: String,
    /// Approval digest.
    pub approval_digest: Option<String>,
    /// Predecessor campaign-state digest.
    pub prior_campaign_state_digest: String,
    /// Resulting campaign-state digest.
    pub campaign_state_digest: String,
    /// First valid sequence.
    pub valid_from_seq: u64,
    /// Last valid sequence.
    pub expires_at_seq: u64,
    /// Must equal one.
    pub max_uses: u8,
    /// Nonce.
    pub nonce: String,
    /// Authority key identifier.
    pub authority_key_id: String,
}

impl From<&Permit> for UnsignedPermit {
    fn from(permit: &Permit) -> Self {
        Self {
            schema_version: permit.schema_version.clone(),
            permit_id: permit.permit_id.clone(),
            trace_id: permit.trace_id.clone(),
            tenant_id: permit.tenant_id.clone(),
            campaign_id: permit.campaign_id.clone(),
            principal: permit.principal.clone(),
            proposal_digest: permit.proposal_digest.clone(),
            action_digest: permit.action_digest.clone(),
            destination_digest: permit.destination_digest.clone(),
            parameter_digest: permit.parameter_digest.clone(),
            policy_digest: permit.policy_digest.clone(),
            signed_policy_digest: permit.signed_policy_digest.clone(),
            evidence_root: permit.evidence_root.clone(),
            decision_digest: permit.decision_digest.clone(),
            approval_digest: permit.approval_digest.clone(),
            prior_campaign_state_digest: permit.prior_campaign_state_digest.clone(),
            campaign_state_digest: permit.campaign_state_digest.clone(),
            valid_from_seq: permit.valid_from_seq,
            expires_at_seq: permit.expires_at_seq,
            max_uses: permit.max_uses,
            nonce: permit.nonce.clone(),
            authority_key_id: permit.authority_key_id.clone(),
        }
    }
}

#[derive(Serialize)]
struct PermitIdentity<'a> {
    tenant_id: &'a str,
    campaign_id: &'a str,
    proposal_id: &'a str,
    sequence: u64,
    nonce: &'a str,
}

/// Independent authority signer.
pub struct Authority {
    key_id: String,
    signing_key: SigningKey,
    approval_keys: BTreeMap<String, VerifyingKey>,
}

impl Authority {
    /// Construct an authority role with an explicit human-approval trust store.
    #[must_use]
    pub fn new(
        key_id: impl Into<String>,
        signing_key: SigningKey,
        approval_keys: BTreeMap<String, VerifyingKey>,
    ) -> Self {
        Self {
            key_id: key_id.into(),
            signing_key,
            approval_keys,
        }
    }

    /// Return the public verification key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    fn verify_human_approval(
        &self,
        proposal: &Proposal,
        policy: &Policy,
        sequence: u64,
    ) -> Result<(), RuntimeError> {
        let required = policy
            .approval_required_for
            .iter()
            .any(|item| item == &proposal.action.kind || item == &proposal.action.effect_class)
            || matches!(
                proposal.action.reversibility.as_str(),
                "irreversible" | "unknown"
            );
        let Some(approval) = proposal.approval.as_ref() else {
            return if required {
                Err(RuntimeError::Authorization(
                    "required human approval is missing".to_owned(),
                ))
            } else {
                Ok(())
            };
        };
        if approval.schema_version != "claimsieve.approval.v1" {
            return Err(RuntimeError::Authorization(
                "unsupported human approval schema".to_owned(),
            ));
        }
        if !approval.approver.starts_with("spiffe://") {
            return Err(RuntimeError::Authorization(
                "human approval identity is not an authenticated SPIFFE identity".to_owned(),
            ));
        }
        if !policy
            .allowed_approver_identities
            .iter()
            .any(|identity| identity == &approval.approver)
        {
            return Err(RuntimeError::Authorization(
                "human approval identity is not allowed by policy".to_owned(),
            ));
        }
        if approval.proposal_digest != proposal_digest(proposal)? {
            return Err(RuntimeError::Authorization(
                "human approval proposal binding mismatch".to_owned(),
            ));
        }
        if approval.display_digest != display_digest(proposal)? {
            return Err(RuntimeError::Authorization(
                "human approval display binding mismatch".to_owned(),
            ));
        }
        if approval.approved_at_seq > sequence
            || approval.expires_at_seq < sequence
            || approval.expires_at_seq < approval.approved_at_seq
        {
            return Err(RuntimeError::Authorization(
                "human approval is stale or not yet valid".to_owned(),
            ));
        }
        if !policy
            .allowed_approver_key_ids
            .iter()
            .any(|key_id| key_id == &approval.approver_key_id)
        {
            return Err(RuntimeError::Authorization(
                "human approval key is not allowed by policy".to_owned(),
            ));
        }
        if approval.approver_key_id == self.key_id {
            return Err(RuntimeError::Authorization(
                "authority and human approval key roles must be distinct".to_owned(),
            ));
        }
        let key = self
            .approval_keys
            .get(&approval.approver_key_id)
            .ok_or_else(|| RuntimeError::Authorization("unknown human approval key".to_owned()))?;
        if key.as_bytes() == self.signing_key.verifying_key().as_bytes() {
            return Err(RuntimeError::Authorization(
                "authority and human approval key material must be distinct".to_owned(),
            ));
        }
        let subject = approval_signing_subject(approval)?;
        verify_signature(key, "approval-v1", &subject, &approval.signature)
            .map_err(|_| RuntimeError::Authorization("human approval signature invalid".to_owned()))
    }

    /// Issue a one-use permit after an exact `ALLOW` decision.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        &self,
        proposal: &Proposal,
        policy: &Policy,
        signed_policy_digest: &str,
        evidence: &[Evidence],
        decision: &Decision,
        prior_state: &CampaignState,
        sequence: u64,
        ttl_sequences: u64,
    ) -> Result<Permit, RuntimeError> {
        if decision.schema_version != "claimsieve.decision.v1" {
            return Err(RuntimeError::Authorization(
                "unsupported decision schema".to_owned(),
            ));
        }
        if decision.verdict != Verdict::Allow {
            return Err(RuntimeError::Authorization(
                "only an ALLOW decision can produce a permit".to_owned(),
            ));
        }
        if proposal.tenant_id != policy.tenant_id {
            return Err(RuntimeError::Authorization(
                "proposal tenant does not match policy tenant".to_owned(),
            ));
        }
        if !policy
            .allowed_principals
            .iter()
            .any(|principal| principal == &proposal.principal)
        {
            return Err(RuntimeError::Authorization(
                "proposal principal is not allowed by policy".to_owned(),
            ));
        }
        if prior_state.campaign_id != proposal.campaign_id || prior_state.status != "ACTIVE" {
            return Err(RuntimeError::Authorization(
                "campaign state is not active for proposal".to_owned(),
            ));
        }
        if !(1..=5).contains(&ttl_sequences) {
            return Err(RuntimeError::Authorization(
                "permit TTL must be between one and five logical sequences".to_owned(),
            ));
        }
        let expires_at_seq = sequence.checked_add(ttl_sequences).ok_or_else(|| {
            RuntimeError::Authorization("permit expiry sequence overflow".to_owned())
        })?;
        if sequence > MAX_SAFE_INTEGER || expires_at_seq > MAX_SAFE_INTEGER {
            return Err(RuntimeError::Authorization(
                "permit sequence exceeds the safe canonical range".to_owned(),
            ));
        }
        self.verify_human_approval(proposal, policy, sequence)?;

        // A caller-supplied ALLOW document has no authority by itself. Re-run
        // the deterministic kernel over the exact inputs and prior campaign
        // state, then require exact equality before any permit can be signed.
        let reevaluated =
            evaluate(proposal, policy, evidence, prior_state, sequence).map_err(|error| {
                RuntimeError::Authorization(format!("kernel reevaluation failed: {error}"))
            })?;
        if reevaluated.decision != *decision {
            return Err(RuntimeError::Authorization(
                "decision does not match independent kernel reevaluation".to_owned(),
            ));
        }

        if decision.trace_id != proposal.trace_id {
            return Err(RuntimeError::Authorization(
                "decision trace binding mismatch".to_owned(),
            ));
        }
        if decision.proposal_digest != proposal_digest(proposal)? {
            return Err(RuntimeError::Authorization(
                "decision proposal binding mismatch".to_owned(),
            ));
        }
        if decision.approval_digest != approval_digest(proposal)? {
            return Err(RuntimeError::Authorization(
                "decision human-approval binding mismatch".to_owned(),
            ));
        }
        if decision.policy_digest != digest(policy)? {
            return Err(RuntimeError::Authorization(
                "decision policy binding mismatch".to_owned(),
            ));
        }
        if decision.evidence_root != evidence_root(evidence)? {
            return Err(RuntimeError::Authorization(
                "decision evidence binding mismatch".to_owned(),
            ));
        }
        if decision.campaign_state_digest != digest(&reevaluated.next_state)? {
            return Err(RuntimeError::Authorization(
                "decision campaign-state binding mismatch".to_owned(),
            ));
        }
        if decision.prior_campaign_state_digest != digest(prior_state)? {
            return Err(RuntimeError::Authorization(
                "decision predecessor campaign-state binding mismatch".to_owned(),
            ));
        }
        if decision.decided_at_seq != sequence {
            return Err(RuntimeError::Authorization(
                "decision sequence does not match permit issuance".to_owned(),
            ));
        }
        let nonce = Uuid::new_v4().simple().to_string();
        let permit_identity_digest = digest(&PermitIdentity {
            tenant_id: &proposal.tenant_id,
            campaign_id: &proposal.campaign_id,
            proposal_id: &proposal.proposal_id,
            sequence,
            nonce: &nonce,
        })?;
        let unsigned = UnsignedPermit {
            schema_version: "claimsieve.permit.v1".to_owned(),
            permit_id: format!(
                "permit:{}",
                permit_identity_digest.trim_start_matches("sha256:")
            ),
            trace_id: proposal.trace_id.clone(),
            tenant_id: proposal.tenant_id.clone(),
            campaign_id: proposal.campaign_id.clone(),
            principal: proposal.principal.clone(),
            proposal_digest: proposal_digest(proposal)?,
            action_digest: action_digest(proposal)?,
            destination_digest: destination_digest(proposal)?,
            parameter_digest: parameter_digest(proposal)?,
            policy_digest: digest(policy)?,
            signed_policy_digest: signed_policy_digest.to_owned(),
            evidence_root: evidence_root(evidence)?,
            decision_digest: digest(decision)?,
            approval_digest: approval_digest(proposal)?,
            prior_campaign_state_digest: decision.prior_campaign_state_digest.clone(),
            campaign_state_digest: decision.campaign_state_digest.clone(),
            valid_from_seq: sequence,
            expires_at_seq,
            max_uses: 1,
            nonce,
            authority_key_id: self.key_id.clone(),
        };
        let signature = sign(&self.signing_key, "permit-v1", &unsigned)?;
        Ok(Permit {
            schema_version: unsigned.schema_version,
            permit_id: unsigned.permit_id,
            trace_id: unsigned.trace_id,
            tenant_id: unsigned.tenant_id,
            campaign_id: unsigned.campaign_id,
            principal: unsigned.principal,
            proposal_digest: unsigned.proposal_digest,
            action_digest: unsigned.action_digest,
            destination_digest: unsigned.destination_digest,
            parameter_digest: unsigned.parameter_digest,
            policy_digest: unsigned.policy_digest,
            signed_policy_digest: unsigned.signed_policy_digest,
            evidence_root: unsigned.evidence_root,
            decision_digest: unsigned.decision_digest,
            approval_digest: unsigned.approval_digest,
            prior_campaign_state_digest: unsigned.prior_campaign_state_digest,
            campaign_state_digest: unsigned.campaign_state_digest,
            valid_from_seq: unsigned.valid_from_seq,
            expires_at_seq: unsigned.expires_at_seq,
            max_uses: unsigned.max_uses,
            nonce: unsigned.nonce,
            authority_key_id: unsigned.authority_key_id,
            signature,
        })
    }
}

/// Atomic reservation interface. Production implementations must provide
/// linearizable compare-and-set semantics across all executor replicas.
pub trait ReservationBackend: Send + Sync {
    /// Reserve a permit once. `Ok(None)` means it was already reserved.
    fn reserve(
        &self,
        permit_id: &str,
        action_digest: &str,
        sequence: u64,
    ) -> Result<Option<Reservation>, RuntimeError>;
}

/// In-memory reservation backend for conformance tests.
#[derive(Default)]
pub struct InMemoryReservationStore {
    reservations: Mutex<BTreeMap<String, Reservation>>,
}

impl InMemoryReservationStore {
    /// Number of unique reservations.
    #[must_use]
    pub fn len(&self) -> usize {
        self.reservations.lock().len()
    }

    /// Whether the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ReservationBackend for InMemoryReservationStore {
    fn reserve(
        &self,
        permit_id: &str,
        action_digest_value: &str,
        sequence: u64,
    ) -> Result<Option<Reservation>, RuntimeError> {
        let mut guard = self.reservations.lock();
        if guard.contains_key(permit_id) {
            return Ok(None);
        }
        let reservation = Reservation {
            schema_version: "claimsieve.reservation.v1".to_owned(),
            permit_id: permit_id.to_owned(),
            action_digest: action_digest_value.to_owned(),
            reserved_at_seq: sequence,
            reservation_id: format!("reservation:{permit_id}"),
        };
        guard.insert(permit_id.to_owned(), reservation.clone());
        Ok(Some(reservation))
    }
}

/// Signed containment operation receipt.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ContainmentReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Operation name.
    pub operation: String,
    /// Optional campaign identifier.
    pub campaign_id: Option<String>,
    /// Optional permit identifier.
    pub permit_id: Option<String>,
    /// Reason.
    pub reason: String,
    /// Logical sequence.
    pub sequence: u64,
    /// Controller key identifier.
    pub controller_key_id: String,
    /// Signature.
    pub signature: String,
}

#[derive(Serialize)]
struct UnsignedContainmentReceipt<'a> {
    schema_version: &'static str,
    operation: &'a str,
    campaign_id: &'a Option<String>,
    permit_id: &'a Option<String>,
    reason: &'a str,
    sequence: u64,
    controller_key_id: &'a str,
}

#[derive(Default)]
struct ContainmentState {
    suspended_campaigns: BTreeMap<String, String>,
    revoked_permits: BTreeMap<String, String>,
    frozen: bool,
}

/// Independent containment controller below the agent runtime.
pub struct ContainmentController {
    key_id: String,
    signing_key: SigningKey,
    state: Mutex<ContainmentState>,
}

impl ContainmentController {
    /// Construct a containment role.
    #[must_use]
    pub fn new(key_id: impl Into<String>, signing_key: SigningKey) -> Self {
        Self {
            key_id: key_id.into(),
            signing_key,
            state: Mutex::new(ContainmentState::default()),
        }
    }

    /// Return the controller key identifier.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// Return the controller verification key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Return whether execution is globally frozen.
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        self.state.lock().frozen
    }

    /// Return whether a campaign is suspended.
    #[must_use]
    pub fn is_suspended(&self, campaign_id: &str) -> bool {
        self.state
            .lock()
            .suspended_campaigns
            .contains_key(campaign_id)
    }

    /// Return whether a permit is revoked.
    #[must_use]
    pub fn is_revoked(&self, permit_id: &str) -> bool {
        self.state.lock().revoked_permits.contains_key(permit_id)
    }

    fn receipt(
        &self,
        operation: &str,
        campaign_id: Option<String>,
        permit_id: Option<String>,
        reason: &str,
        sequence: u64,
    ) -> Result<ContainmentReceipt, RuntimeError> {
        let unsigned = UnsignedContainmentReceipt {
            schema_version: "claimsieve.containment_receipt.v1",
            operation,
            campaign_id: &campaign_id,
            permit_id: &permit_id,
            reason,
            sequence,
            controller_key_id: &self.key_id,
        };
        let signature = sign(&self.signing_key, "containment-v1", &unsigned)?;
        Ok(ContainmentReceipt {
            schema_version: "claimsieve.containment_receipt.v1".to_owned(),
            operation: operation.to_owned(),
            campaign_id,
            permit_id,
            reason: reason.to_owned(),
            sequence,
            controller_key_id: self.key_id.clone(),
            signature,
        })
    }

    /// Suspend a campaign and sign the operation.
    pub fn suspend(
        &self,
        campaign_id: &str,
        reason: &str,
        sequence: u64,
    ) -> Result<ContainmentReceipt, RuntimeError> {
        self.state
            .lock()
            .suspended_campaigns
            .insert(campaign_id.to_owned(), reason.to_owned());
        self.receipt(
            "SUSPEND_CAMPAIGN",
            Some(campaign_id.to_owned()),
            None,
            reason,
            sequence,
        )
    }

    /// Revoke a permit and sign the operation.
    pub fn revoke(
        &self,
        permit_id: &str,
        reason: &str,
        sequence: u64,
    ) -> Result<ContainmentReceipt, RuntimeError> {
        self.state
            .lock()
            .revoked_permits
            .insert(permit_id.to_owned(), reason.to_owned());
        self.receipt(
            "REVOKE_PERMIT",
            None,
            Some(permit_id.to_owned()),
            reason,
            sequence,
        )
    }

    /// Freeze all execution and sign the operation.
    pub fn freeze(&self, reason: &str, sequence: u64) -> Result<ContainmentReceipt, RuntimeError> {
        self.state.lock().frozen = true;
        self.receipt("FREEZE_EXECUTION", None, None, reason, sequence)
    }
}

/// Provider response made available by a provider adapter.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectorResponse {
    /// `accepted`, `rejected`, or `timeout_unknown`.
    pub status: String,
    /// Provider operation identifier when available.
    pub provider_id: Option<String>,
    /// Independently readable action state when available.
    pub observed_action: Option<Action>,
}

/// Narrow execution connector. It receives only an exact action and idempotency key.
pub trait Connector: Send + Sync {
    /// Perform the exact action.
    fn invoke(
        &self,
        action: &Action,
        idempotency_key: &str,
    ) -> Result<ConnectorResponse, RuntimeError>;
}

/// Read-only provider observation interface owned by the observer role.
pub trait ObservationSource: Send + Sync {
    /// Query independently readable provider state for an existing idempotency key.
    fn query(&self, idempotency_key: &str) -> Result<Option<ConnectorResponse>, RuntimeError>;
}

/// Deterministic connector and read-back source used by conformance tests.
pub struct SimulatedConnector {
    mode: String,
    calls: Mutex<Vec<(Action, String)>>,
    records: Mutex<BTreeMap<String, ConnectorResponse>>,
}

impl SimulatedConnector {
    /// Construct a connector mode: success, failure, ambiguous, or divergent.
    #[must_use]
    pub fn new(mode: impl Into<String>) -> Self {
        Self {
            mode: mode.into(),
            calls: Mutex::new(Vec::new()),
            records: Mutex::new(BTreeMap::new()),
        }
    }

    /// Number of provider invocations.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.lock().len()
    }
}

impl Connector for SimulatedConnector {
    fn invoke(
        &self,
        action: &Action,
        idempotency_key: &str,
    ) -> Result<ConnectorResponse, RuntimeError> {
        self.calls
            .lock()
            .push((action.clone(), idempotency_key.to_owned()));
        let response = match self.mode.as_str() {
            "success" => ConnectorResponse {
                status: "accepted".to_owned(),
                provider_id: Some(format!("provider:{idempotency_key}")),
                observed_action: Some(action.clone()),
            },
            "failure" => ConnectorResponse {
                status: "rejected".to_owned(),
                provider_id: None,
                observed_action: None,
            },
            "ambiguous" => ConnectorResponse {
                status: "timeout_unknown".to_owned(),
                provider_id: None,
                observed_action: None,
            },
            "divergent" => {
                let mut observed = action.clone();
                observed.destination.authority = "unexpected-target".to_owned();
                ConnectorResponse {
                    status: "accepted".to_owned(),
                    provider_id: Some(format!("provider:{idempotency_key}")),
                    observed_action: Some(observed),
                }
            }
            other => {
                return Err(RuntimeError::Connector(format!(
                    "unsupported simulated mode: {other}"
                )));
            }
        };
        // An ambiguous transport result intentionally creates no independently
        // readable provider record. All other modes are queryable by the
        // observer without trusting the executor receipt.
        if response.status != "timeout_unknown" {
            self.records
                .lock()
                .insert(idempotency_key.to_owned(), response.clone());
        }
        Ok(response)
    }
}

impl ObservationSource for SimulatedConnector {
    fn query(&self, idempotency_key: &str) -> Result<Option<ConnectorResponse>, RuntimeError> {
        Ok(self.records.lock().get(idempotency_key).cloned())
    }
}

#[derive(Serialize)]
struct UnsignedExecutorReceipt<'a> {
    schema_version: &'static str,
    trace_id: &'a str,
    permit_id: &'a str,
    reservation_id: &'a str,
    action_digest: &'a str,
    provider_status: &'a str,
    provider_id: &'a Option<String>,
    attempted_at_seq: u64,
    executor_key_id: &'a str,
}

#[derive(Serialize)]
struct UnsignedObserverReceipt<'a> {
    schema_version: &'static str,
    reservation_id: &'a str,
    permit_id: &'a str,
    campaign_id: &'a str,
    provider_record_digest: &'a Option<String>,
    observed_action_digest: &'a Option<String>,
    reconciliation: Reconciliation,
    receipt_conflict: bool,
    observed_at_seq: u64,
    observer_key_id: &'a str,
}

/// Result of dispatch by the restricted executor. It contains no observer claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchResult {
    /// Atomic permit reservation.
    pub reservation: Reservation,
    /// Executor attempt receipt.
    pub executor_receipt: ExecutorReceipt,
    /// Automatic retry is never authorized by dispatch output.
    pub automatic_retry_allowed: bool,
}

/// Result created by the separately keyed observer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObservationResult {
    /// Independent observer receipt.
    pub observer_receipt: ObserverReceipt,
    /// Containment receipt when divergence or provider-evidence conflict trips suspension.
    pub containment_receipt: Option<ContainmentReceipt>,
    /// Reconciliation result.
    pub reconciliation: Reconciliation,
    /// Whether the independently read provider record contradicted itself.
    pub provider_evidence_conflict: bool,
    /// No outcome independently authorizes a new logical attempt.
    pub automatic_retry_allowed: bool,
}

/// Classify only independently read provider evidence.
///
/// A provider record that both reports rejection and exposes an effect, or
/// reports acceptance without an independently readable effect, is
/// contradictory. Contradictory evidence remains unknown and triggers
/// containment rather than being coerced into success or failure.
#[must_use]
pub fn classify_provider_observation(
    status: &str,
    observed_action_digest: Option<&str>,
    intended_action_digest: &str,
) -> (Reconciliation, bool) {
    let conflict = (status == "rejected" && observed_action_digest.is_some())
        || (status == "accepted" && observed_action_digest.is_none());
    if conflict {
        return (Reconciliation::OutcomeUnknown, true);
    }
    match observed_action_digest {
        Some(observed) if observed == intended_action_digest => {
            (Reconciliation::ConfirmedSuccess, false)
        }
        Some(_) => (Reconciliation::DivergentEffect, false),
        None if status == "rejected" => (Reconciliation::ConfirmedFailure, false),
        None => (Reconciliation::OutcomeUnknown, false),
    }
}

/// Conservative lower bound for the modeled provider idempotency retention window.
pub const STRIPE_MINIMUM_SAFE_RETENTION_SECONDS: u64 = 24 * 60 * 60;

/// Exact same-dispatch transport replay context.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportReplayContext {
    /// Original dispatch is still outcome-unknown.
    pub outcome_unknown: bool,
    /// Reservation identity is unchanged.
    pub same_reservation: bool,
    /// Provider idempotency key is unchanged.
    pub same_idempotency_key: bool,
    /// Canonical request digest is unchanged.
    pub same_request_digest: bool,
    /// Provider endpoint is unchanged.
    pub same_endpoint: bool,
    /// Provider account is unchanged.
    pub same_account: bool,
    /// Permit/campaign/executor authority remains active.
    pub authority_active: bool,
    /// Provider contract guarantees idempotent POST replay.
    pub provider_supports_idempotent_post: bool,
    /// Elapsed seconds since the initial request.
    pub elapsed_seconds: u64,
    /// Number of prior transport replays.
    pub replay_count: u32,
    /// Maximum allowed transport replays for this dispatch.
    pub replay_limit: u32,
}

/// Permit a transport replay only when it is the same already-authorized dispatch.
///
/// Returning `true` never authorizes a new logical action or a fresh permit use.
#[must_use]
pub const fn transport_replay_allowed(context: TransportReplayContext) -> bool {
    context.outcome_unknown
        && context.same_reservation
        && context.same_idempotency_key
        && context.same_request_digest
        && context.same_endpoint
        && context.same_account
        && context.authority_active
        && context.provider_supports_idempotent_post
        && context.elapsed_seconds < STRIPE_MINIMUM_SAFE_RETENTION_SECONDS
        && context.replay_count < context.replay_limit
}

/// No outcome independently authorizes an automatic new logical attempt.
#[must_use]
pub const fn automatic_retry_allowed(_outcome: Reconciliation) -> bool {
    false
}

/// Restricted executor. It cannot possess or use the observer signing key.
pub struct Executor<'a, R: ReservationBackend, C: Connector> {
    authority_keys: BTreeMap<String, VerifyingKey>,
    executor_key_id: String,
    executor_signing_key: SigningKey,
    reservations: &'a R,
    containment: &'a ContainmentController,
    connector: &'a C,
}

impl<'a, R: ReservationBackend, C: Connector> Executor<'a, R, C> {
    /// Construct an executor and enforce distinct authority, executor, and containment keys.
    pub fn new(
        authority_keys: BTreeMap<String, VerifyingKey>,
        executor_key_id: impl Into<String>,
        executor_signing_key: SigningKey,
        reservations: &'a R,
        containment: &'a ContainmentController,
        connector: &'a C,
    ) -> Result<Self, RuntimeError> {
        let executor_key_id = executor_key_id.into();
        let authority_ids: BTreeSet<&str> = authority_keys.keys().map(String::as_str).collect();
        if executor_key_id == containment.key_id()
            || authority_ids.contains(executor_key_id.as_str())
            || authority_ids.contains(containment.key_id())
        {
            return Err(RuntimeError::Authorization(
                "authority, executor, and containment key roles must be distinct".to_owned(),
            ));
        }
        let executor_verifying_key = executor_signing_key.verifying_key();
        let containment_verifying_key = containment.verifying_key();
        if executor_verifying_key.as_bytes() == containment_verifying_key.as_bytes()
            || authority_keys.values().any(|key| {
                key.as_bytes() == executor_verifying_key.as_bytes()
                    || key.as_bytes() == containment_verifying_key.as_bytes()
            })
        {
            return Err(RuntimeError::Authorization(
                "authority, executor, and containment key material must be distinct".to_owned(),
            ));
        }
        Ok(Self {
            authority_keys,
            executor_key_id,
            executor_signing_key,
            reservations,
            containment,
            connector,
        })
    }

    fn verify_containment(
        &self,
        permit: &Permit,
        state: &CampaignState,
    ) -> Result<(), RuntimeError> {
        if self.containment.is_frozen() {
            return Err(RuntimeError::Authorization(
                "execution globally frozen".to_owned(),
            ));
        }
        if self.containment.is_revoked(&permit.permit_id) {
            return Err(RuntimeError::Authorization("permit revoked".to_owned()));
        }
        if self.containment.is_suspended(&permit.campaign_id) || state.status != "ACTIVE" {
            return Err(RuntimeError::Authorization("campaign suspended".to_owned()));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_permit(
        &self,
        permit: &Permit,
        proposal: &Proposal,
        policy: &Policy,
        signed_policy_digest: &str,
        evidence: &[Evidence],
        decision: &Decision,
        state: &CampaignState,
        sequence: u64,
    ) -> Result<(), RuntimeError> {
        let reevaluated =
            evaluate(proposal, policy, evidence, state, sequence).map_err(|error| {
                RuntimeError::Authorization(format!("kernel reevaluation failed: {error}"))
            })?;
        if permit.schema_version != "claimsieve.permit.v1" {
            return Err(RuntimeError::Authorization(
                "unsupported permit schema".to_owned(),
            ));
        }
        let unsigned = UnsignedPermit::from(permit);
        let authority = self
            .authority_keys
            .get(&permit.authority_key_id)
            .ok_or_else(|| RuntimeError::Authorization("unknown authority key".to_owned()))?;
        verify_signature(authority, "permit-v1", &unsigned, &permit.signature)?;
        self.verify_containment(permit, state)?;
        if sequence < permit.valid_from_seq || sequence > permit.expires_at_seq {
            return Err(RuntimeError::Authorization(
                "permit outside validity sequence".to_owned(),
            ));
        }
        if decision.schema_version != "claimsieve.decision.v1" {
            return Err(RuntimeError::Authorization(
                "unsupported decision schema".to_owned(),
            ));
        }
        if decision.verdict != Verdict::Allow {
            return Err(RuntimeError::Authorization(
                "decision is not executable".to_owned(),
            ));
        }
        if decision.trace_id != proposal.trace_id {
            return Err(RuntimeError::Authorization(
                "decision trace binding mismatch".to_owned(),
            ));
        }
        if decision.proposal_digest != proposal_digest(proposal)? {
            return Err(RuntimeError::Authorization(
                "decision proposal binding mismatch".to_owned(),
            ));
        }
        if decision.approval_digest != approval_digest(proposal)? {
            return Err(RuntimeError::Authorization(
                "decision human-approval binding mismatch".to_owned(),
            ));
        }
        if decision.policy_digest != digest(policy)? {
            return Err(RuntimeError::Authorization(
                "decision policy binding mismatch".to_owned(),
            ));
        }
        if decision.evidence_root != evidence_root(evidence)? {
            return Err(RuntimeError::Authorization(
                "decision evidence binding mismatch".to_owned(),
            ));
        }
        if decision.campaign_state_digest != digest(&reevaluated.next_state)? {
            return Err(RuntimeError::Authorization(
                "decision campaign-state binding mismatch".to_owned(),
            ));
        }
        if decision.decided_at_seq != permit.valid_from_seq {
            return Err(RuntimeError::Authorization(
                "decision sequence binding mismatch".to_owned(),
            ));
        }
        if permit.decision_digest != digest(decision)? {
            return Err(RuntimeError::Authorization(
                "permit binding mismatch: decision_digest".to_owned(),
            ));
        }
        if permit.signed_policy_digest != signed_policy_digest {
            return Err(RuntimeError::Authorization(
                "permit binding mismatch: signed_policy_digest".to_owned(),
            ));
        }
        if permit.prior_campaign_state_digest != decision.prior_campaign_state_digest {
            return Err(RuntimeError::Authorization(
                "permit binding mismatch: prior_campaign_state_digest".to_owned(),
            ));
        }
        if permit.campaign_state_digest != decision.campaign_state_digest {
            return Err(RuntimeError::Authorization(
                "permit binding mismatch: campaign_state_digest".to_owned(),
            ));
        }
        let bindings = [
            (
                "tenant_id",
                permit.tenant_id.clone(),
                proposal.tenant_id.clone(),
            ),
            (
                "campaign_id",
                permit.campaign_id.clone(),
                proposal.campaign_id.clone(),
            ),
            (
                "principal",
                permit.principal.clone(),
                proposal.principal.clone(),
            ),
            (
                "proposal_digest",
                permit.proposal_digest.clone(),
                proposal_digest(proposal)?,
            ),
            (
                "action_digest",
                permit.action_digest.clone(),
                action_digest(proposal)?,
            ),
            (
                "destination_digest",
                permit.destination_digest.clone(),
                destination_digest(proposal)?,
            ),
            (
                "parameter_digest",
                permit.parameter_digest.clone(),
                parameter_digest(proposal)?,
            ),
            (
                "policy_digest",
                permit.policy_digest.clone(),
                digest(policy)?,
            ),
            (
                "evidence_root",
                permit.evidence_root.clone(),
                evidence_root(evidence)?,
            ),
        ];
        for (name, actual, expected) in bindings {
            if actual != expected {
                return Err(RuntimeError::Authorization(format!(
                    "permit binding mismatch: {name}"
                )));
            }
        }
        if permit.approval_digest != approval_digest(proposal)? {
            return Err(RuntimeError::Authorization(
                "permit binding mismatch: approval_digest".to_owned(),
            ));
        }
        if permit.max_uses != 1 {
            return Err(RuntimeError::Authorization(
                "permit must be one use".to_owned(),
            ));
        }
        Ok(())
    }

    /// Execute one exact permitted action and return only executor evidence.
    #[allow(clippy::too_many_arguments)]
    pub fn execute(
        &self,
        permit: &Permit,
        proposal: &Proposal,
        policy: &Policy,
        signed_policy_digest: &str,
        evidence: &[Evidence],
        decision: &Decision,
        state: &CampaignState,
        sequence: u64,
    ) -> Result<DispatchResult, RuntimeError> {
        self.verify_permit(
            permit,
            proposal,
            policy,
            signed_policy_digest,
            evidence,
            decision,
            state,
            sequence,
        )?;
        let reservation = self
            .reservations
            .reserve(&permit.permit_id, &permit.action_digest, sequence)?
            .ok_or(RuntimeError::Replay)?;
        self.verify_containment(permit, state)?;
        let provider = self.connector.invoke(&proposal.action, &permit.permit_id)?;
        let unsigned_executor = UnsignedExecutorReceipt {
            schema_version: "claimsieve.executor_receipt.v1",
            trace_id: &proposal.trace_id,
            permit_id: &permit.permit_id,
            reservation_id: &reservation.reservation_id,
            action_digest: &permit.action_digest,
            provider_status: &provider.status,
            provider_id: &provider.provider_id,
            attempted_at_seq: sequence,
            executor_key_id: &self.executor_key_id,
        };
        let executor_signature = sign(
            &self.executor_signing_key,
            "executor-receipt-v1",
            &unsigned_executor,
        )?;
        let executor_receipt = ExecutorReceipt {
            schema_version: "claimsieve.executor_receipt.v1".to_owned(),
            trace_id: proposal.trace_id.clone(),
            permit_id: permit.permit_id.clone(),
            reservation_id: reservation.reservation_id.clone(),
            action_digest: permit.action_digest.clone(),
            provider_status: provider.status,
            provider_id: provider.provider_id,
            attempted_at_seq: sequence,
            executor_key_id: self.executor_key_id.clone(),
            signature: executor_signature,
        };
        Ok(DispatchResult {
            reservation,
            executor_receipt,
            automatic_retry_allowed: false,
        })
    }
}

/// Separately keyed observer. It cannot invoke the action connector.
pub struct IndependentObserver<'a, O: ObservationSource> {
    observer_key_id: String,
    observer_signing_key: SigningKey,
    containment: &'a ContainmentController,
    source: &'a O,
}

impl<'a, O: ObservationSource> IndependentObserver<'a, O> {
    /// Construct an observer with a key distinct from containment.
    pub fn new(
        observer_key_id: impl Into<String>,
        observer_signing_key: SigningKey,
        containment: &'a ContainmentController,
        source: &'a O,
    ) -> Result<Self, RuntimeError> {
        let observer_key_id = observer_key_id.into();
        if observer_key_id == containment.key_id()
            || observer_signing_key.verifying_key().as_bytes()
                == containment.verifying_key().as_bytes()
        {
            return Err(RuntimeError::Authorization(
                "observer and containment key roles must be distinct".to_owned(),
            ));
        }
        Ok(Self {
            observer_key_id,
            observer_signing_key,
            containment,
            source,
        })
    }

    /// Reconcile from independently readable provider state only.
    pub fn reconcile(
        &self,
        permit: &Permit,
        proposal: &Proposal,
        reservation: &Reservation,
        sequence: u64,
    ) -> Result<ObservationResult, RuntimeError> {
        self.reconcile_with_executor_receipt(permit, proposal, reservation, None, sequence)
    }

    /// Reconcile from independent provider state while optionally comparing executor audit evidence.
    ///
    /// The executor receipt never controls the outcome classification. When supplied, it is used only
    /// to surface a receipt conflict after the independently read provider record has been classified.
    pub fn reconcile_with_executor_receipt(
        &self,
        permit: &Permit,
        proposal: &Proposal,
        reservation: &Reservation,
        executor_receipt: Option<&ExecutorReceipt>,
        sequence: u64,
    ) -> Result<ObservationResult, RuntimeError> {
        if reservation.permit_id != permit.permit_id
            || reservation.action_digest != permit.action_digest
        {
            return Err(RuntimeError::Authorization(
                "observer reservation binding mismatch".to_owned(),
            ));
        }
        if permit.campaign_id != proposal.campaign_id {
            return Err(RuntimeError::Authorization(
                "observer campaign binding mismatch".to_owned(),
            ));
        }
        let intended_action_digest = digest(&proposal.action)?;
        if permit.action_digest != intended_action_digest {
            return Err(RuntimeError::Authorization(
                "observer action binding mismatch".to_owned(),
            ));
        }
        if let Some(receipt) = executor_receipt
            && (receipt.permit_id != permit.permit_id
                || receipt.reservation_id != reservation.reservation_id)
        {
            return Err(RuntimeError::Authorization(
                "observer executor-receipt binding mismatch".to_owned(),
            ));
        }
        let provider = self.source.query(&permit.permit_id)?;
        let (
            provider_record_digest,
            observed_action_digest,
            reconciliation,
            provider_evidence_conflict,
            provider_status,
        ) = match provider {
            None => (None, None, Reconciliation::OutcomeUnknown, false, None),
            Some(record) => {
                let provider_record_digest = Some(digest(&record)?);
                let observed = record.observed_action.as_ref().map(digest).transpose()?;
                let (outcome, conflict) = classify_provider_observation(
                    record.status.as_str(),
                    observed.as_deref(),
                    &intended_action_digest,
                );
                (
                    provider_record_digest,
                    observed,
                    outcome,
                    conflict,
                    Some(record.status),
                )
            }
        };
        let receipt_conflict = provider_evidence_conflict
            || matches!(
                (executor_receipt, provider_status.as_deref()),
                (Some(receipt), Some(status)) if receipt.provider_status.as_str() != status
            );
        let unsigned_observer = UnsignedObserverReceipt {
            schema_version: "claimsieve.observer_receipt.v2",
            reservation_id: &reservation.reservation_id,
            permit_id: &permit.permit_id,
            campaign_id: &permit.campaign_id,
            provider_record_digest: &provider_record_digest,
            observed_action_digest: &observed_action_digest,
            reconciliation,
            receipt_conflict,
            observed_at_seq: sequence,
            observer_key_id: &self.observer_key_id,
        };
        let signature = sign(
            &self.observer_signing_key,
            "observer-receipt-v2",
            &unsigned_observer,
        )?;
        let observer_receipt = ObserverReceipt {
            schema_version: "claimsieve.observer_receipt.v2".to_owned(),
            reservation_id: reservation.reservation_id.clone(),
            permit_id: permit.permit_id.clone(),
            campaign_id: permit.campaign_id.clone(),
            provider_record_digest,
            observed_action_digest,
            reconciliation,
            receipt_conflict,
            observed_at_seq: sequence,
            observer_key_id: self.observer_key_id.clone(),
            signature,
        };
        let containment_receipt = if provider_evidence_conflict {
            Some(self.containment.suspend(
                &proposal.campaign_id,
                "PROVIDER_EVIDENCE_CONFLICT",
                sequence,
            )?)
        } else if reconciliation == Reconciliation::DivergentEffect {
            Some(
                self.containment
                    .suspend(&proposal.campaign_id, "DIVERGENT_EFFECT", sequence)?,
            )
        } else {
            None
        };
        Ok(ObservationResult {
            observer_receipt,
            containment_receipt,
            reconciliation,
            provider_evidence_conflict,
            automatic_retry_allowed: automatic_retry_allowed(reconciliation),
        })
    }
}

/// Verify a permit signature independently.
pub fn verify_permit_signature(
    permit: &Permit,
    authority_key: &VerifyingKey,
) -> Result<(), RuntimeError> {
    verify_signature(
        authority_key,
        "permit-v1",
        &UnsignedPermit::from(permit),
        &permit.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        Connector, ContainmentController, InMemoryReservationStore, IndependentObserver,
        ReservationBackend, RuntimeError, SimulatedConnector, TransportReplayContext,
        automatic_retry_allowed, classify_provider_observation, transport_replay_allowed,
    };
    use claimsieve_protocol::{
        Action, Destination, ExecutorReceipt, Objective, Permit, Proposal, Reconciliation,
        Reservation, digest,
    };
    use ed25519_dalek::SigningKey;
    use std::collections::BTreeMap;

    #[test]
    fn reservation_is_one_use() {
        let store = InMemoryReservationStore::default();
        let first = store.reserve("permit", "action", 1);
        let second = store.reserve("permit", "action", 1);
        assert!(matches!(first, Ok(Some(_))));
        assert!(matches!(second, Ok(None)));
    }

    #[test]
    fn no_outcome_authorizes_automatic_retry() {
        for outcome in [
            Reconciliation::ConfirmedSuccess,
            Reconciliation::ConfirmedFailure,
            Reconciliation::OutcomeUnknown,
            Reconciliation::DivergentEffect,
        ] {
            assert!(!automatic_retry_allowed(outcome));
        }
    }

    #[test]
    fn exact_same_dispatch_transport_replay_is_narrowly_allowed() {
        let context = TransportReplayContext {
            outcome_unknown: true,
            same_reservation: true,
            same_idempotency_key: true,
            same_request_digest: true,
            same_endpoint: true,
            same_account: true,
            authority_active: true,
            provider_supports_idempotent_post: true,
            elapsed_seconds: 10,
            replay_count: 0,
            replay_limit: 2,
        };
        assert!(transport_replay_allowed(context));
        assert!(!transport_replay_allowed(TransportReplayContext {
            authority_active: false,
            ..context
        }));
        assert!(!transport_replay_allowed(TransportReplayContext {
            same_request_digest: false,
            ..context
        }));
    }

    fn observer_fixture() -> Result<(Proposal, Permit, Reservation), RuntimeError> {
        let action = Action {
            kind: "send_message".to_owned(),
            effect_class: "external_message".to_owned(),
            destination: Destination {
                scheme: "sms".to_owned(),
                authority: "+15550000000".to_owned(),
                resource: "lead".to_owned(),
                trust_domain: "crm".to_owned(),
            },
            method: "POST".to_owned(),
            parameters: BTreeMap::new(),
            reversibility: "reversible".to_owned(),
        };
        let action_digest = digest(&action)?;
        let proposal = Proposal {
            schema_version: "claimsieve.proposal.v1".to_owned(),
            proposal_id: "proposal:test".to_owned(),
            trace_id: "trace:test".to_owned(),
            tenant_id: "tenant:test".to_owned(),
            campaign_id: "campaign:test".to_owned(),
            session_id: "session:test".to_owned(),
            parent_action_id: None,
            principal: "spiffe://claimsieve.test/agent".to_owned(),
            objective: Objective {
                root: "test".to_owned(),
                subgoal: "test".to_owned(),
                expected_effect: "message sent".to_owned(),
                constraints: Vec::new(),
            },
            action,
            evidence_refs: Vec::new(),
            approval: None,
            requested_at_seq: 1,
            risk_tags: Vec::new(),
        };
        let permit = Permit {
            schema_version: "claimsieve.permit.v1".to_owned(),
            permit_id: "permit:test".to_owned(),
            trace_id: proposal.trace_id.clone(),
            tenant_id: proposal.tenant_id.clone(),
            campaign_id: proposal.campaign_id.clone(),
            principal: proposal.principal.clone(),
            proposal_digest: "sha256:proposal".to_owned(),
            action_digest: action_digest.clone(),
            destination_digest: "sha256:destination".to_owned(),
            parameter_digest: "sha256:parameters".to_owned(),
            policy_digest: "sha256:policy".to_owned(),
            signed_policy_digest: "sha256:signed-policy".to_owned(),
            evidence_root: "sha256:evidence".to_owned(),
            decision_digest: "sha256:decision".to_owned(),
            approval_digest: None,
            prior_campaign_state_digest: "sha256:prior".to_owned(),
            campaign_state_digest: "sha256:state".to_owned(),
            valid_from_seq: 1,
            expires_at_seq: 5,
            max_uses: 1,
            nonce: "nonce".to_owned(),
            authority_key_id: "authority".to_owned(),
            signature: "fixture".to_owned(),
        };
        let reservation = Reservation {
            schema_version: "claimsieve.reservation.v1".to_owned(),
            permit_id: permit.permit_id.clone(),
            action_digest,
            reserved_at_seq: 2,
            reservation_id: "reservation:test".to_owned(),
        };
        Ok((proposal, permit, reservation))
    }

    #[test]
    fn observer_v2_uses_independent_provider_state_and_flags_executor_conflict()
    -> Result<(), RuntimeError> {
        let (proposal, permit, reservation) = observer_fixture()?;
        let connector = SimulatedConnector::new("success");
        connector.invoke(&proposal.action, &permit.permit_id)?;
        let containment =
            ContainmentController::new("containment", SigningKey::from_bytes(&[3_u8; 32]));
        let observer = IndependentObserver::new(
            "observer",
            SigningKey::from_bytes(&[4_u8; 32]),
            &containment,
            &connector,
        )?;
        let executor_receipt = ExecutorReceipt {
            schema_version: "claimsieve.executor_receipt.v1".to_owned(),
            trace_id: proposal.trace_id.clone(),
            permit_id: permit.permit_id.clone(),
            reservation_id: reservation.reservation_id.clone(),
            action_digest: permit.action_digest.clone(),
            provider_status: "rejected".to_owned(),
            provider_id: None,
            attempted_at_seq: 2,
            executor_key_id: "executor".to_owned(),
            signature: "fixture".to_owned(),
        };
        let result = observer.reconcile_with_executor_receipt(
            &permit,
            &proposal,
            &reservation,
            Some(&executor_receipt),
            3,
        )?;
        assert_eq!(result.reconciliation, Reconciliation::ConfirmedSuccess);
        assert!(result.observer_receipt.receipt_conflict);
        assert_eq!(
            result.observer_receipt.schema_version,
            "claimsieve.observer_receipt.v2"
        );
        assert_eq!(
            result.observer_receipt.reservation_id,
            reservation.reservation_id
        );
        assert_eq!(result.observer_receipt.campaign_id, permit.campaign_id);
        assert!(result.observer_receipt.provider_record_digest.is_some());
        assert!(result.containment_receipt.is_none());
        Ok(())
    }

    #[test]
    fn observer_rejects_proposal_action_not_bound_by_permit() -> Result<(), RuntimeError> {
        let (mut proposal, permit, reservation) = observer_fixture()?;
        proposal.action.destination.authority = "+15551111111".to_owned();
        let connector = SimulatedConnector::new("ambiguous");
        let containment =
            ContainmentController::new("containment", SigningKey::from_bytes(&[5_u8; 32]));
        let observer = IndependentObserver::new(
            "observer",
            SigningKey::from_bytes(&[6_u8; 32]),
            &containment,
            &connector,
        )?;
        let result = observer.reconcile(&permit, &proposal, &reservation, 3);
        assert!(matches!(
            result,
            Err(RuntimeError::Authorization(message)) if message == "observer action binding mismatch"
        ));
        Ok(())
    }

    #[test]
    fn signed_or_reported_rejection_with_observed_effect_is_not_failure() {
        let (outcome, conflict) =
            classify_provider_observation("rejected", Some("sha256:effect"), "sha256:effect");
        assert_eq!(outcome, Reconciliation::OutcomeUnknown);
        assert!(conflict);
    }

    #[test]
    fn timeout_with_independent_exact_effect_resolves_success() {
        let (outcome, conflict) = classify_provider_observation(
            "timeout_unknown",
            Some("sha256:effect"),
            "sha256:effect",
        );
        assert_eq!(outcome, Reconciliation::ConfirmedSuccess);
        assert!(!conflict);
    }
}
