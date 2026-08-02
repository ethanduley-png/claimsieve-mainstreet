#![forbid(unsafe_code)]

//! Deterministic fail-closed authorization and trajectory kernel.

use claimsieve_protocol::{
    Decision, Evidence, Policy, Proposal, ProtocolError, Verdict, approval_digest, digest,
    display_digest, evidence_root, proposal_digest,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Kernel evaluation error. Errors are not authorization.
#[derive(Debug, Error)]
pub enum KernelError {
    /// Protocol canonicalization failed.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

/// Durable campaign state, stored outside any agent process.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CampaignState {
    /// Durable campaign identifier.
    pub campaign_id: String,
    /// `ACTIVE` or `SUSPENDED`.
    pub status: String,
    /// Total proposals seen.
    pub total_actions: u64,
    /// Denied proposals.
    pub denials: u64,
    /// Quarantined proposals.
    pub quarantines: u64,
    /// Distinct sessions.
    pub sessions: BTreeSet<String>,
    /// Distinct destination authorities.
    pub destinations: BTreeSet<String>,
    /// Distinct trust domains.
    pub trust_domains: BTreeSet<String>,
    /// Count of new trust-domain crossings.
    pub boundary_crossings: u64,
    /// Count of encoded fragments.
    pub encoded_fragments: u64,
    /// Credential discovery or use events.
    pub credential_events: u64,
    /// Last accepted logical sequence.
    pub last_sequence: u64,
    /// Stable suspension reason.
    pub suspension_reason: Option<String>,
}

impl CampaignState {
    /// Construct an active, empty campaign.
    #[must_use]
    pub fn new(campaign_id: impl Into<String>) -> Self {
        Self {
            campaign_id: campaign_id.into(),
            status: "ACTIVE".to_owned(),
            total_actions: 0,
            denials: 0,
            quarantines: 0,
            sessions: BTreeSet::new(),
            destinations: BTreeSet::new(),
            trust_domains: BTreeSet::new(),
            boundary_crossings: 0,
            encoded_fragments: 0,
            credential_events: 0,
            last_sequence: 0,
            suspension_reason: None,
        }
    }
}

/// Kernel result and the next durable campaign state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evaluation {
    /// Portable decision document.
    pub decision: Decision,
    /// State to commit atomically with the decision.
    pub next_state: CampaignState,
}

fn contains(values: &[String], candidate: &str) -> bool {
    values.iter().any(|value| value == candidate)
}

fn tag_set(proposal: &Proposal) -> BTreeSet<&str> {
    proposal.risk_tags.iter().map(String::as_str).collect()
}

#[allow(clippy::too_many_arguments)]
fn finish_evaluation(
    proposal: &Proposal,
    policy: &Policy,
    prior_state: &CampaignState,
    mut state: CampaignState,
    sequence: u64,
    evidence: &[Evidence],
    verdict: Verdict,
    mut reason_codes: Vec<String>,
) -> Result<Evaluation, KernelError> {
    let mut verdict = verdict;
    match verdict {
        Verdict::Deny => {
            state.denials = state.denials.saturating_add(1);
            if state.denials > policy.campaign_limits.max_denials {
                verdict = Verdict::SuspendCampaign;
                reason_codes.push("CAMPAIGN_DENIAL_BUDGET_EXCEEDED".to_owned());
                state.status = "SUSPENDED".to_owned();
                state.suspension_reason = Some("CAMPAIGN_DENIAL_BUDGET_EXCEEDED".to_owned());
            }
        }
        Verdict::Quarantine => state.quarantines = state.quarantines.saturating_add(1),
        Verdict::SuspendCampaign => {
            state.status = "SUSPENDED".to_owned();
            state.suspension_reason = reason_codes.first().cloned();
        }
        Verdict::Allow | Verdict::RequireHuman => {}
    }
    state.last_sequence = state.last_sequence.max(sequence);
    reason_codes.sort();
    reason_codes.dedup();
    if reason_codes.is_empty() {
        reason_codes.push("INTERNAL_FAIL_CLOSED".to_owned());
    }
    let decision = Decision {
        schema_version: "claimsieve.decision.v1".to_owned(),
        decision_id: format!("decision:{}:{sequence}", proposal.proposal_id),
        trace_id: proposal.trace_id.clone(),
        proposal_digest: proposal_digest(proposal)?,
        approval_digest: approval_digest(proposal)?,
        policy_digest: digest(policy)?,
        evidence_root: evidence_root(evidence)?,
        prior_campaign_state_digest: digest(prior_state)?,
        campaign_state_digest: digest(&state)?,
        verdict,
        reason_codes,
        decided_at_seq: sequence,
    };
    Ok(Evaluation {
        decision,
        next_state: state,
    })
}

/// Evaluate a proposal under policy and accumulated campaign state.
///
/// Any parser, canonicalization, or internal error must be treated as denial by
/// the caller. This function never grants authority; it only returns a verdict.
pub fn evaluate(
    proposal: &Proposal,
    policy: &Policy,
    evidence: &[Evidence],
    state: &CampaignState,
    sequence: u64,
) -> Result<Evaluation, KernelError> {
    let mut next = state.clone();
    let finish = |proposal: &Proposal,
                  policy: &Policy,
                  next_state: CampaignState,
                  decision_sequence: u64,
                  evaluated_evidence: &[Evidence],
                  verdict: Verdict,
                  reason_codes: Vec<String>| {
        finish_evaluation(
            proposal,
            policy,
            state,
            next_state,
            decision_sequence,
            evaluated_evidence,
            verdict,
            reason_codes,
        )
    };

    if proposal.schema_version != "claimsieve.proposal.v1" {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::Deny,
            vec!["UNSUPPORTED_PROPOSAL_SCHEMA".to_owned()],
        );
    }
    if policy.schema_version != "claimsieve.policy.v1" {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::Deny,
            vec!["UNSUPPORTED_POLICY_SCHEMA".to_owned()],
        );
    }
    if sequence <= next.last_sequence {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::Deny,
            vec!["NON_SUCCESSOR_SEQUENCE".to_owned()],
        );
    }
    if next.status != "ACTIVE" {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::SuspendCampaign,
            vec!["CAMPAIGN_NOT_ACTIVE".to_owned()],
        );
    }
    if proposal.campaign_id != next.campaign_id {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::Deny,
            vec!["CAMPAIGN_ID_MISMATCH".to_owned()],
        );
    }
    if proposal.tenant_id != policy.tenant_id {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::Deny,
            vec!["TENANT_MISMATCH".to_owned()],
        );
    }
    if !proposal.principal.starts_with("spiffe://") {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::Deny,
            vec!["INVALID_WORKLOAD_IDENTITY".to_owned()],
        );
    }
    if !contains(&policy.allowed_principals, &proposal.principal) {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::Deny,
            vec!["PRINCIPAL_NOT_ALLOWED".to_owned()],
        );
    }

    next.total_actions = next.total_actions.saturating_add(1);
    next.sessions.insert(proposal.session_id.clone());
    let tags = tag_set(proposal);

    const ALWAYS_SUSPEND: [&str; 10] = [
        "DIRECT_EXECUTION_ATTEMPT",
        "CREDENTIAL_USE",
        "CLOUD_METADATA_ACCESS",
        "OBSERVER_TAMPER",
        "POLICY_TAMPER",
        "CONTAINMENT_TAMPER",
        "PRIVILEGE_ESCALATION",
        "UNRESTRICTED_NESTED_AGENT",
        "COVERT_RELAY",
        "PRODUCTION_LATERAL_MOVE",
    ];
    let mut severe = BTreeSet::new();
    for tag in &tags {
        if ALWAYS_SUSPEND.contains(tag) || contains(&policy.suspend_risk_tags, tag) {
            severe.insert(*tag);
        }
    }
    if !severe.is_empty() {
        if severe.contains("CREDENTIAL_USE") {
            next.credential_events = next.credential_events.saturating_add(1);
        }
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::SuspendCampaign,
            severe
                .into_iter()
                .map(|tag| format!("TRAJECTORY_{tag}"))
                .collect(),
        );
    }

    if tags.contains("CREDENTIAL_DISCOVERED") {
        next.credential_events = next.credential_events.saturating_add(1);
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::Quarantine,
            vec!["CREDENTIAL_DISCOVERY_QUARANTINE".to_owned()],
        );
    }

    const ALWAYS_DENY: [&str; 5] = [
        "UNDECLARED_REDIRECT",
        "PURPOSE_MISMATCH",
        "EXECUTABLE_UPLOAD",
        "PACKAGE_PROXY_TUNNEL",
        "POST_APPROVAL_MUTATION",
    ];
    let mut denied_tags = BTreeSet::new();
    for tag in &tags {
        if ALWAYS_DENY.contains(tag) || contains(&policy.deny_risk_tags, tag) {
            denied_tags.insert(*tag);
        }
    }
    if !denied_tags.is_empty() {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::Deny,
            denied_tags
                .into_iter()
                .map(|tag| format!("RISK_{tag}"))
                .collect(),
        );
    }

    if tags.contains("ENCODED_FRAGMENT") {
        next.encoded_fragments = next.encoded_fragments.saturating_add(1);
    }
    if next
        .destinations
        .insert(proposal.action.destination.authority.clone())
    {
        // The set length is the authoritative distinct-destination count.
    }
    if next
        .trust_domains
        .insert(proposal.action.destination.trust_domain.clone())
    {
        next.boundary_crossings = next.boundary_crossings.saturating_add(1);
    }

    let limits = &policy.campaign_limits;
    let mut budget_failures = Vec::new();
    if next.total_actions > limits.max_actions {
        budget_failures.push("CAMPAIGN_ACTION_BUDGET_EXCEEDED".to_owned());
    }
    if u64::try_from(next.sessions.len()).unwrap_or(u64::MAX) > limits.max_sessions {
        budget_failures.push("CAMPAIGN_SESSION_BUDGET_EXCEEDED".to_owned());
    }
    if u64::try_from(next.destinations.len()).unwrap_or(u64::MAX) > limits.max_new_destinations {
        budget_failures.push("CAMPAIGN_DESTINATION_BUDGET_EXCEEDED".to_owned());
    }
    if next.boundary_crossings > limits.max_boundary_crossings {
        budget_failures.push("CAMPAIGN_BOUNDARY_BUDGET_EXCEEDED".to_owned());
    }
    if next.encoded_fragments > limits.max_encoded_fragments {
        budget_failures.push("ENCODED_FRAGMENT_CHAIN_DETECTED".to_owned());
    }
    if next.denials > limits.max_denials {
        budget_failures.push("CAMPAIGN_DENIAL_BUDGET_EXCEEDED".to_owned());
    }
    if !budget_failures.is_empty() {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::SuspendCampaign,
            budget_failures,
        );
    }

    let mut policy_failures = Vec::new();
    if !contains(&policy.allowed_action_kinds, &proposal.action.kind) {
        policy_failures.push("ACTION_KIND_NOT_ALLOWED".to_owned());
    }
    if !contains(
        &policy.allowed_effect_classes,
        &proposal.action.effect_class,
    ) {
        policy_failures.push("EFFECT_CLASS_NOT_ALLOWED".to_owned());
    }
    if !contains(
        &policy.allowed_trust_domains,
        &proposal.action.destination.trust_domain,
    ) {
        policy_failures.push("TRUST_DOMAIN_NOT_ALLOWED".to_owned());
    }
    if !contains(&policy.allowed_subgoals, &proposal.objective.subgoal) {
        policy_failures.push("SUBGOAL_NOT_ALLOWED".to_owned());
    }
    if proposal.objective.root.is_empty() || proposal.objective.expected_effect.is_empty() {
        policy_failures.push("PURPOSE_CHAIN_INCOMPLETE".to_owned());
    }
    if proposal.action.reversibility == "unknown" {
        policy_failures.push("REVERSIBILITY_UNKNOWN".to_owned());
    }
    if !policy_failures.is_empty() {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::Deny,
            policy_failures,
        );
    }

    let mut by_type: BTreeMap<&str, Vec<&Evidence>> = BTreeMap::new();
    let mut evidence_failures = Vec::new();
    for item in evidence.iter().filter(|item| item.verified) {
        let trusted = policy
            .trusted_evidence_sources
            .get(&item.evidence_type)
            .is_some_and(|sources| contains(sources, &item.source));
        if trusted {
            by_type
                .entry(item.evidence_type.as_str())
                .or_default()
                .push(item);
        } else if contains(&policy.required_evidence, &item.evidence_type) {
            evidence_failures.push(format!("UNTRUSTED_EVIDENCE_SOURCE_{}", item.evidence_type));
        }
    }
    for required in &policy.required_evidence {
        let Some(candidates) = by_type.get(required.as_str()) else {
            evidence_failures.push(format!("MISSING_EVIDENCE_{required}"));
            continue;
        };
        let fresh = candidates.iter().any(|item| {
            sequence >= item.observed_at_seq
                && sequence.saturating_sub(item.observed_at_seq) <= policy.freshness_window
        });
        if !fresh {
            evidence_failures.push(format!("STALE_EVIDENCE_{required}"));
        }
    }

    let destination_authorized = by_type
        .get("destination_registry")
        .is_some_and(|candidates| {
            candidates.iter().any(|item| {
                item.content
                    .get("authority")
                    .and_then(serde_json::Value::as_str)
                    == Some(proposal.action.destination.authority.as_str())
                    && item
                        .content
                        .get("trust_domain")
                        .and_then(serde_json::Value::as_str)
                        == Some(proposal.action.destination.trust_domain.as_str())
            })
        });
    if !destination_authorized {
        evidence_failures.push("DESTINATION_EVIDENCE_MISMATCH".to_owned());
    }
    if proposal.action.kind == "send_message" {
        let contact_authorized =
            by_type
                .get("customer_contact_authority")
                .is_some_and(|candidates| {
                    candidates.iter().any(|item| {
                        item.subject == proposal.action.destination.resource
                            && item
                                .content
                                .get("phone")
                                .and_then(serde_json::Value::as_str)
                                == Some(proposal.action.destination.authority.as_str())
                            && item
                                .content
                                .get("consent")
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|value| !value.is_empty())
                    })
                });
        if !contact_authorized {
            evidence_failures.push("CONTACT_AUTHORITY_EVIDENCE_MISMATCH".to_owned());
        }
    }

    let mut active_deployments = Vec::new();
    if let Some(candidates) = by_type.get("deployment_certificate") {
        for item in candidates {
            let status = item
                .content
                .get("status")
                .and_then(serde_json::Value::as_str);
            if status != Some("ACTIVE") {
                evidence_failures.push("DEPLOYMENT_CERTIFICATE_NOT_ACTIVE".to_owned());
                continue;
            }
            let valid_from = item
                .content
                .get("valid_from_seq")
                .and_then(serde_json::Value::as_u64);
            let expires_at = item
                .content
                .get("expires_at_seq")
                .and_then(serde_json::Value::as_u64);
            if !matches!(
                (valid_from, expires_at),
                (Some(start), Some(end)) if start <= sequence && sequence <= end
            ) {
                evidence_failures.push("DEPLOYMENT_CERTIFICATE_OUTSIDE_VALIDITY".to_owned());
                continue;
            }
            let runtime_manifest = item
                .content
                .get("runtime_manifest_digest")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default();
            if !runtime_manifest.starts_with("sha256:") {
                evidence_failures.push("DEPLOYMENT_RUNTIME_MANIFEST_INVALID".to_owned());
                continue;
            }
            active_deployments.push(*item);
        }
    }

    let mut active_epochs = Vec::new();
    if let Some(candidates) = by_type.get("governance_epoch") {
        for item in candidates {
            let status = item
                .content
                .get("status")
                .and_then(serde_json::Value::as_str);
            if status != Some("ACTIVE") {
                evidence_failures.push("GOVERNANCE_EPOCH_NOT_ACTIVE".to_owned());
                continue;
            }
            let epoch_policy_version = item
                .content
                .get("policy_version")
                .and_then(serde_json::Value::as_u64);
            if epoch_policy_version != Some(policy.version) {
                evidence_failures.push("GOVERNANCE_EPOCH_POLICY_MISMATCH".to_owned());
                continue;
            }
            active_epochs.push(*item);
        }
    }
    if active_deployments.len() != 1 {
        evidence_failures.push("ACTIVE_DEPLOYMENT_CERTIFICATE_COUNT_INVALID".to_owned());
    }
    if active_epochs.len() != 1 {
        evidence_failures.push("ACTIVE_GOVERNANCE_EPOCH_COUNT_INVALID".to_owned());
    }
    if active_deployments.len() == 1
        && active_epochs.len() == 1
        && let (Some(deployment), Some(epoch)) = (active_deployments.first(), active_epochs.first())
    {
        let expected_deployment = digest(*deployment)?;
        let epoch_deployment = epoch
            .content
            .get("deployment_certificate_digest")
            .and_then(serde_json::Value::as_str);
        if epoch_deployment != Some(expected_deployment.as_str()) {
            evidence_failures.push("GOVERNANCE_EPOCH_DEPLOYMENT_MISMATCH".to_owned());
        }
        let deployment_runtime = deployment
            .content
            .get("runtime_manifest_digest")
            .and_then(serde_json::Value::as_str);
        let epoch_runtime = epoch
            .content
            .get("runtime_manifest_digest")
            .and_then(serde_json::Value::as_str);
        if epoch_runtime != deployment_runtime {
            evidence_failures.push("GOVERNANCE_EPOCH_RUNTIME_MISMATCH".to_owned());
        }
    }

    let available = evidence
        .iter()
        .map(digest)
        .collect::<Result<BTreeSet<_>, _>>()?;
    let referenced = proposal
        .evidence_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if referenced.len() != proposal.evidence_refs.len()
        || available.len() != evidence.len()
        || referenced != available
    {
        evidence_failures.push("EVIDENCE_REFERENCE_MISMATCH".to_owned());
    }
    if !evidence_failures.is_empty() {
        return finish(
            proposal,
            policy,
            next,
            sequence,
            evidence,
            Verdict::Deny,
            evidence_failures,
        );
    }

    let approval_required = contains(&policy.approval_required_for, &proposal.action.kind)
        || contains(&policy.approval_required_for, &proposal.action.effect_class)
        || matches!(
            proposal.action.reversibility.as_str(),
            "irreversible" | "unknown"
        );
    if approval_required {
        let Some(approval) = &proposal.approval else {
            return finish(
                proposal,
                policy,
                next,
                sequence,
                evidence,
                Verdict::RequireHuman,
                vec!["HUMAN_APPROVAL_REQUIRED".to_owned()],
            );
        };
        let mut approval_failures = Vec::new();
        if !policy
            .allowed_approver_key_ids
            .iter()
            .any(|key_id| key_id == &approval.approver_key_id)
        {
            approval_failures.push("APPROVER_KEY_NOT_ALLOWED".to_owned());
        }
        if approval.proposal_digest != proposal_digest(proposal)? {
            approval_failures.push("APPROVAL_PROPOSAL_DIGEST_MISMATCH".to_owned());
        }
        if approval.display_digest != display_digest(proposal)? {
            approval_failures.push("APPROVAL_DISPLAY_DIGEST_MISMATCH".to_owned());
        }
        if !approval.approver.starts_with("spiffe://") {
            approval_failures.push("INVALID_APPROVER_IDENTITY".to_owned());
        }
        if !contains(&policy.allowed_approver_identities, &approval.approver) {
            approval_failures.push("APPROVER_IDENTITY_NOT_ALLOWED".to_owned());
        }
        if sequence < approval.approved_at_seq || sequence > approval.expires_at_seq {
            approval_failures.push("APPROVAL_EXPIRED_OR_NOT_YET_VALID".to_owned());
        }
        if !approval_failures.is_empty() {
            return finish(
                proposal,
                policy,
                next,
                sequence,
                evidence,
                Verdict::Deny,
                approval_failures,
            );
        }
    }

    finish(
        proposal,
        policy,
        next,
        sequence,
        evidence,
        Verdict::Allow,
        vec!["ALL_GATES_PASSED".to_owned()],
    )
}

#[cfg(test)]
mod tests {
    use super::CampaignState;

    #[test]
    fn new_campaign_is_active() {
        let state = CampaignState::new("campaign");
        assert_eq!(state.status, "ACTIVE");
        assert_eq!(state.total_actions, 0);
    }
}
