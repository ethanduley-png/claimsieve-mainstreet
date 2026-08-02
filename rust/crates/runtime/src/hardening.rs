#![forbid(unsafe_code)]

//! v0.31 trust-root and single-successor contracts.
//!
//! These types encode the production seams introduced by the executable
//! Python reference. They are source-level candidates until Cargo compilation
//! and cross-language conformance are run in an environment with Rust 1.90.

use claimsieve_kernel::CampaignState;
use claimsieve_protocol::{Evidence, Policy};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Policy artifact signed by a role pinned outside the evidence bundle.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicyEnvelope {
    /// Envelope schema.
    pub schema_version: String,
    /// Exact policy body.
    pub policy: Policy,
    /// External trust-root key identifier.
    pub signer_key_id: String,
    /// Domain-separated signature.
    pub signature: String,
}

/// Evidence artifact signed by the evidence issuer.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidenceEnvelope {
    /// Exact evidence body.
    pub evidence: Evidence,
    /// Role-scoped issuer key identifier.
    pub issuer_key_id: String,
    /// Domain-separated signature.
    pub signature: String,
}

/// Out-of-band trust root. A bundle must never establish its own authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalTrustRoot {
    /// Trust-root schema.
    pub schema_version: String,
    /// Operator-pinned root identifier.
    pub root_id: String,
    /// Public keys by identifier.
    pub keys: BTreeMap<String, String>,
    /// Allowed key identifiers by security role.
    pub roles: BTreeMap<String, Vec<String>>,
}

/// Witness statement over the exact release/bundle manifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WitnessStatement {
    /// Witness schema.
    pub schema_version: String,
    /// Exact manifest digest.
    pub manifest_digest: String,
    /// Release identity.
    pub release_id: String,
    /// Witness key identifier.
    pub witness_key_id: String,
    /// Domain-separated signature.
    pub signature: String,
}

/// Atomic campaign-state interface.
///
/// Production implementations must be durable and linearizable across all
/// permit-authority replicas. The method accepts exactly one successor for a
/// predecessor digest and strict logical sequence.
pub trait CampaignStateBackend: Send + Sync {
    /// Read current durable state.
    fn read(&self, campaign_id: &str) -> Result<CampaignState, String>;

    /// Commit one strict successor. `Ok(false)` means a sibling or stale writer
    /// already changed the predecessor.
    fn compare_and_swap_successor(
        &self,
        campaign_id: &str,
        expected_predecessor_digest: &str,
        expected_last_sequence: u64,
        successor: &CampaignState,
    ) -> Result<bool, String>;
}

/// Read-only containment surface available to an executor.
pub trait ContainmentReadView: Send + Sync {
    /// Whether all execution is frozen.
    fn frozen(&self) -> Result<bool, String>;
    /// Whether a campaign is suspended.
    fn campaign_suspended(&self, campaign_id: &str) -> Result<bool, String>;
    /// Whether a permit is revoked.
    fn permit_revoked(&self, permit_id: &str) -> Result<bool, String>;
}

/// Independent external-state reader available to an observer, not executor.
pub trait IndependentObservationBackend: Send + Sync {
    /// Return canonical externally observed action bytes, or `None` when the
    /// outcome remains unknown.
    fn observe_action(&self, idempotency_key: &str) -> Result<Option<Vec<u8>>, String>;
}
