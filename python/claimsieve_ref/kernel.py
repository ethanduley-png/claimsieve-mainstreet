from __future__ import annotations

import copy
from dataclasses import asdict, dataclass, field
from typing import Any

from .canonical import MAX_SAFE_INTEGER, digest
from .model import approval_digest, display_digest, evidence_root, proposal_digest


@dataclass
class CampaignState:
    campaign_id: str
    status: str = "ACTIVE"
    total_actions: int = 0
    denials: int = 0
    quarantines: int = 0
    sessions: set[str] = field(default_factory=set)
    destinations: set[str] = field(default_factory=set)
    trust_domains: set[str] = field(default_factory=set)
    boundary_crossings: int = 0
    encoded_fragments: int = 0
    credential_events: int = 0
    last_sequence: int = 0
    suspension_reason: str | None = None

    def as_canonical(self) -> dict[str, Any]:
        raw = asdict(self)
        for key in ("sessions", "destinations", "trust_domains"):
            raw[key] = sorted(raw[key])
        return raw

    def clone(self) -> "CampaignState":
        return copy.deepcopy(self)


@dataclass(frozen=True)
class Decision:
    document: dict[str, Any]
    next_state: CampaignState


SUSPEND_TAGS_ALWAYS = {
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
}

DENY_TAGS_ALWAYS = {
    "UNDECLARED_REDIRECT",
    "PURPOSE_MISMATCH",
    "EXECUTABLE_UPLOAD",
    "PACKAGE_PROXY_TUNNEL",
    "POST_APPROVAL_MUTATION",
}


def _finish(
    proposal: dict[str, Any],
    policy: dict[str, Any],
    state: CampaignState,
    seq: int,
    evidence_root_value: str,
    verdict: str,
    reasons: list[str],
) -> Decision:
    if verdict == "DENY":
        state.denials += 1
        max_denials = policy.get("campaign_limits", {}).get("max_denials")
        if isinstance(max_denials, int) and state.denials > max_denials:
            verdict = "SUSPEND_CAMPAIGN"
            reasons = [*reasons, "CAMPAIGN_DENIAL_BUDGET_EXCEEDED"]
            state.status = "SUSPENDED"
            state.suspension_reason = "CAMPAIGN_DENIAL_BUDGET_EXCEEDED"
    elif verdict == "QUARANTINE":
        state.quarantines += 1
    elif verdict == "SUSPEND_CAMPAIGN":
        state.status = "SUSPENDED"
        state.suspension_reason = reasons[0]
    state.last_sequence = max(state.last_sequence, seq)
    body = {
        "schema_version": "claimsieve.decision.v1",
        "decision_id": f"decision:{proposal.get('proposal_id', 'unknown')}:{seq}",
        "trace_id": proposal.get("trace_id", "unknown"),
        "proposal_digest": proposal_digest(proposal) if proposal.get("schema_version") == "claimsieve.proposal.v1" else digest(proposal),
        "approval_digest": approval_digest(proposal),
        "policy_digest": digest(policy),
        "evidence_root": evidence_root_value,
        "prior_campaign_state_digest": getattr(state, "_prior_state_digest", None),
        "campaign_state_digest": digest(state.as_canonical()),
        "verdict": verdict,
        "reason_codes": sorted(set(reasons)) or ["INTERNAL_FAIL_CLOSED"],
        "decided_at_seq": seq,
    }
    return Decision(body, state)


def evaluate(
    proposal: dict[str, Any],
    policy: dict[str, Any],
    evidence: list[dict[str, Any]],
    state: CampaignState,
    seq: int,
) -> Decision:
    """Deterministic fail-closed policy and trajectory evaluation."""
    next_state = state.clone()
    # Carry the exact predecessor commitment outside the canonical state.
    # The permit authority uses it for an atomic compare-and-swap transition.
    setattr(next_state, "_prior_state_digest", digest(state.as_canonical()))
    reasons: list[str] = []
    evidence_root_value = evidence_root(evidence)

    if (
        isinstance(seq, bool)
        or not isinstance(seq, int)
        or seq < 0
        or seq > MAX_SAFE_INTEGER
    ):
        safe_sequence = state.last_sequence if isinstance(state.last_sequence, int) and state.last_sequence >= 0 else 0
        return _finish(
            proposal, policy, next_state, safe_sequence, evidence_root_value,
            "DENY", ["INVALID_DECISION_SEQUENCE"],
        )

    if proposal.get("schema_version") != "claimsieve.proposal.v1":
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "DENY", ["UNSUPPORTED_PROPOSAL_SCHEMA"])
    if policy.get("schema_version") != "claimsieve.policy.v1":
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "DENY", ["UNSUPPORTED_POLICY_SCHEMA"])
    if seq <= next_state.last_sequence:
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "DENY", ["NON_SUCCESSOR_SEQUENCE"])
    if next_state.status != "ACTIVE":
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "SUSPEND_CAMPAIGN", ["CAMPAIGN_NOT_ACTIVE"])
    if proposal.get("campaign_id") != next_state.campaign_id:
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "DENY", ["CAMPAIGN_ID_MISMATCH"])
    if proposal.get("tenant_id") != policy.get("tenant_id"):
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "DENY", ["TENANT_MISMATCH"])
    principal = proposal.get("principal")
    if not isinstance(principal, str) or not principal.startswith("spiffe://"):
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "DENY", ["INVALID_WORKLOAD_IDENTITY"])
    allowed_principals = policy.get("allowed_principals")
    if not isinstance(allowed_principals, list) or principal not in allowed_principals:
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "DENY", ["PRINCIPAL_NOT_ALLOWED"])

    action = proposal.get("action")
    objective = proposal.get("objective")
    session_id = proposal.get("session_id")
    risk_tags = proposal.get("risk_tags")
    if (
        not isinstance(action, dict)
        or not isinstance(objective, dict)
        or not isinstance(action.get("destination"), dict)
        or not isinstance(session_id, str)
        or not session_id
        or not isinstance(risk_tags, list)
        or not all(isinstance(tag, str) for tag in risk_tags)
    ):
        return _finish(
            proposal, policy, next_state, seq, evidence_root_value,
            "DENY", ["PROPOSAL_STRUCTURE_INVALID"],
        )

    list_policy_fields = (
        "allowed_action_kinds",
        "allowed_effect_classes",
        "allowed_trust_domains",
        "allowed_subgoals",
        "approval_required_for",
        "deny_risk_tags",
        "suspend_risk_tags",
    )
    if any(
        not isinstance(policy.get(field_name), list)
        or not all(isinstance(item, str) for item in policy[field_name])
        for field_name in list_policy_fields
    ):
        return _finish(
            proposal, policy, next_state, seq, evidence_root_value,
            "DENY", ["POLICY_LIST_FIELD_INVALID"],
        )

    limits = policy.get("campaign_limits")
    required_limits = (
        "max_actions",
        "max_denials",
        "max_new_destinations",
        "max_sessions",
        "max_boundary_crossings",
        "max_encoded_fragments",
    )
    if (
        not isinstance(limits, dict)
        or any(
            isinstance(limits.get(limit_name), bool)
            or not isinstance(limits.get(limit_name), int)
            or not 0 <= limits[limit_name] <= MAX_SAFE_INTEGER
            for limit_name in required_limits
        )
    ):
        return _finish(
            proposal, policy, next_state, seq, evidence_root_value,
            "DENY", ["CAMPAIGN_LIMIT_POLICY_INVALID"],
        )

    next_state.total_actions += 1
    next_state.sessions.add(session_id)

    destination = action["destination"]
    tags = set(risk_tags)

    # High-severity trajectory events dominate ordinary policy.
    severe = tags & (SUSPEND_TAGS_ALWAYS | set(policy.get("suspend_risk_tags", [])))
    if severe:
        if "CREDENTIAL_USE" in severe:
            next_state.credential_events += 1
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "SUSPEND_CAMPAIGN", [f"TRAJECTORY_{tag}" for tag in sorted(severe)])

    if "CREDENTIAL_DISCOVERED" in tags:
        next_state.credential_events += 1
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "QUARANTINE", ["CREDENTIAL_DISCOVERY_QUARANTINE"])

    denied_tags = tags & (DENY_TAGS_ALWAYS | set(policy.get("deny_risk_tags", [])))
    if denied_tags:
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "DENY", [f"RISK_{tag}" for tag in sorted(denied_tags)])

    if "ENCODED_FRAGMENT" in tags:
        next_state.encoded_fragments += 1

    authority = str(destination.get("authority", ""))
    trust_domain = str(destination.get("trust_domain", ""))
    if authority and authority not in next_state.destinations:
        next_state.destinations.add(authority)
    if trust_domain and trust_domain not in next_state.trust_domains:
        next_state.trust_domains.add(trust_domain)
        next_state.boundary_crossings += 1

    # Campaign-level budgets survive process and session changes.
    budget_failures: list[str] = []
    if next_state.total_actions > limits["max_actions"]:
        budget_failures.append("CAMPAIGN_ACTION_BUDGET_EXCEEDED")
    if len(next_state.sessions) > limits["max_sessions"]:
        budget_failures.append("CAMPAIGN_SESSION_BUDGET_EXCEEDED")
    if len(next_state.destinations) > limits["max_new_destinations"]:
        budget_failures.append("CAMPAIGN_DESTINATION_BUDGET_EXCEEDED")
    if next_state.boundary_crossings > limits["max_boundary_crossings"]:
        budget_failures.append("CAMPAIGN_BOUNDARY_BUDGET_EXCEEDED")
    if next_state.encoded_fragments > limits["max_encoded_fragments"]:
        budget_failures.append("ENCODED_FRAGMENT_CHAIN_DETECTED")
    if next_state.denials > limits["max_denials"]:
        budget_failures.append("CAMPAIGN_DENIAL_BUDGET_EXCEEDED")
    if budget_failures:
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "SUSPEND_CAMPAIGN", budget_failures)

    if action.get("kind") not in policy["allowed_action_kinds"]:
        reasons.append("ACTION_KIND_NOT_ALLOWED")
    if action.get("effect_class") not in policy["allowed_effect_classes"]:
        reasons.append("EFFECT_CLASS_NOT_ALLOWED")
    if trust_domain not in policy["allowed_trust_domains"]:
        reasons.append("TRUST_DOMAIN_NOT_ALLOWED")
    if objective.get("subgoal") not in policy["allowed_subgoals"]:
        reasons.append("SUBGOAL_NOT_ALLOWED")
    if not objective.get("root") or not objective.get("expected_effect"):
        reasons.append("PURPOSE_CHAIN_INCOMPLETE")
    if action.get("reversibility") == "unknown":
        reasons.append("REVERSIBILITY_UNKNOWN")
    if reasons:
        return _finish(proposal, policy, next_state, seq, evidence_root_value, "DENY", reasons)

    evidence_by_type: dict[str, list[dict[str, Any]]] = {}
    evidence_failures: list[str] = []
    trusted_sources = policy.get("trusted_evidence_sources")
    if not isinstance(trusted_sources, dict):
        return _finish(
            proposal, policy, next_state, seq, evidence_root_value, "DENY",
            ["TRUSTED_EVIDENCE_SOURCE_POLICY_MISSING"],
        )
    required_evidence = policy.get("required_evidence")
    if not isinstance(required_evidence, list) or not all(isinstance(item, str) for item in required_evidence):
        return _finish(
            proposal, policy, next_state, seq, evidence_root_value, "DENY",
            ["REQUIRED_EVIDENCE_POLICY_INVALID"],
        )
    for item in evidence:
        if not isinstance(item, dict) or item.get("verified") is not True or not isinstance(item.get("type"), str):
            continue
        evidence_type = item["type"]
        allowed_sources = trusted_sources.get(evidence_type, [])
        source = item.get("source")
        if not isinstance(allowed_sources, list) or source not in allowed_sources:
            if evidence_type in required_evidence:
                evidence_failures.append(f"UNTRUSTED_EVIDENCE_SOURCE_{evidence_type}")
            continue
        evidence_by_type.setdefault(evidence_type, []).append(item)

    freshness_window = policy.get("freshness_window")
    if isinstance(freshness_window, bool) or not isinstance(freshness_window, int) or freshness_window < 0:
        return _finish(
            proposal, policy, next_state, seq, evidence_root_value, "DENY",
            ["FRESHNESS_WINDOW_POLICY_INVALID"],
        )
    for required in required_evidence:
        candidates = evidence_by_type.get(required, [])
        if not candidates:
            evidence_failures.append(f"MISSING_EVIDENCE_{required}")
            continue
        fresh = False
        for item in candidates:
            observed = item.get("observed_at_seq")
            if isinstance(observed, bool) or not isinstance(observed, int):
                continue
            if 0 <= seq - observed <= freshness_window:
                fresh = True
                break
        if not fresh:
            evidence_failures.append(f"STALE_EVIDENCE_{required}")

    # The evidence snapshot must authorize the exact recipient and destination,
    # not merely contain records with the right type names.
    destination_candidates = evidence_by_type.get("destination_registry", [])
    if not any(
        isinstance(item.get("content"), dict)
        and item["content"].get("authority") == destination.get("authority")
        and item["content"].get("trust_domain") == destination.get("trust_domain")
        for item in destination_candidates
    ):
        evidence_failures.append("DESTINATION_EVIDENCE_MISMATCH")
    if action.get("kind") == "send_message":
        contact_candidates = evidence_by_type.get("customer_contact_authority", [])
        if not any(
            item.get("subject") == destination.get("resource")
            and isinstance(item.get("content"), dict)
            and item["content"].get("phone") == destination.get("authority")
            and isinstance(item["content"].get("consent"), str)
            and bool(item["content"].get("consent"))
            for item in contact_candidates
        ):
            evidence_failures.append("CONTACT_AUTHORITY_EVIDENCE_MISMATCH")

    deployment_candidates = evidence_by_type.get("deployment_certificate", [])
    epoch_candidates = evidence_by_type.get("governance_epoch", [])
    active_deployments = []
    for item in deployment_candidates:
        content = item.get("content", {})
        if not isinstance(content, dict):
            evidence_failures.append("DEPLOYMENT_CERTIFICATE_CONTENT_INVALID")
            continue
        if content.get("status") != "ACTIVE":
            evidence_failures.append("DEPLOYMENT_CERTIFICATE_NOT_ACTIVE")
            continue
        valid_from = content.get("valid_from_seq")
        expires_at = content.get("expires_at_seq")
        if (
            isinstance(valid_from, bool)
            or isinstance(expires_at, bool)
            or not isinstance(valid_from, int)
            or not isinstance(expires_at, int)
            or not (valid_from <= seq <= expires_at)
        ):
            evidence_failures.append("DEPLOYMENT_CERTIFICATE_OUTSIDE_VALIDITY")
            continue
        if not str(content.get("runtime_manifest_digest", "")).startswith("sha256:"):
            evidence_failures.append("DEPLOYMENT_RUNTIME_MANIFEST_INVALID")
            continue
        active_deployments.append(item)
    active_epochs = []
    for item in epoch_candidates:
        content = item.get("content", {})
        if not isinstance(content, dict) or content.get("status") != "ACTIVE":
            evidence_failures.append("GOVERNANCE_EPOCH_NOT_ACTIVE")
            continue
        if content.get("policy_version") != policy.get("version"):
            evidence_failures.append("GOVERNANCE_EPOCH_POLICY_MISMATCH")
            continue
        active_epochs.append(item)
    if len(active_deployments) != 1:
        evidence_failures.append("ACTIVE_DEPLOYMENT_CERTIFICATE_COUNT_INVALID")
    if len(active_epochs) != 1:
        evidence_failures.append("ACTIVE_GOVERNANCE_EPOCH_COUNT_INVALID")
    if len(active_deployments) == 1 and len(active_epochs) == 1:
        deployment = active_deployments[0]
        epoch = active_epochs[0]
        if epoch["content"].get("deployment_certificate_digest") != digest(deployment):
            evidence_failures.append("GOVERNANCE_EPOCH_DEPLOYMENT_MISMATCH")
        if epoch["content"].get("runtime_manifest_digest") != deployment["content"].get("runtime_manifest_digest"):
            evidence_failures.append("GOVERNANCE_EPOCH_RUNTIME_MISMATCH")

    referenced_raw = proposal.get("evidence_refs")
    available_list = [digest(item) for item in evidence]
    available = set(available_list)
    valid_reference_set = (
        isinstance(referenced_raw, list)
        and all(isinstance(reference, str) for reference in referenced_raw)
        and len(referenced_raw) == len(set(referenced_raw))
        and len(available_list) == len(available)
        and set(referenced_raw) == available
    )
    if not valid_reference_set:
        evidence_failures.append("EVIDENCE_REFERENCE_MISMATCH")
    if evidence_failures:
        return _finish(
            proposal, policy, next_state, seq, evidence_root_value, "DENY", evidence_failures
        )

    approval_required = (
        action.get("kind") in policy.get("approval_required_for", [])
        or action.get("effect_class") in policy.get("approval_required_for", [])
        or action.get("reversibility") in {"irreversible", "unknown"}
    )
    if approval_required:
        approval = proposal.get("approval")
        if not isinstance(approval, dict):
            return _finish(proposal, policy, next_state, seq, evidence_root_value, "REQUIRE_HUMAN", ["HUMAN_APPROVAL_REQUIRED"])
        approval_reasons: list[str] = []
        if approval.get("proposal_digest") != proposal_digest(proposal):
            approval_reasons.append("APPROVAL_PROPOSAL_DIGEST_MISMATCH")
        if approval.get("display_digest") != display_digest(proposal):
            approval_reasons.append("APPROVAL_DISPLAY_DIGEST_MISMATCH")
        approver_identity = approval.get("approver")
        if not isinstance(approver_identity, str) or not approver_identity.startswith("spiffe://"):
            approval_reasons.append("INVALID_APPROVER_IDENTITY")
        allowed_identities = policy.get("allowed_approver_identities", [])
        if not isinstance(allowed_identities, list) or approver_identity not in allowed_identities:
            approval_reasons.append("APPROVER_IDENTITY_NOT_ALLOWED")
        allowed_approvers = policy.get("allowed_approver_key_ids", [])
        if not isinstance(allowed_approvers, list) or approval.get("approver_key_id") not in allowed_approvers:
            approval_reasons.append("APPROVER_KEY_NOT_ALLOWED")
        approved_at = approval.get("approved_at_seq")
        expires_at = approval.get("expires_at_seq")
        if (
            isinstance(approved_at, bool)
            or isinstance(expires_at, bool)
            or not isinstance(approved_at, int)
            or not isinstance(expires_at, int)
        ):
            approval_reasons.append("APPROVAL_SEQUENCE_INVALID")
        elif not (approved_at <= seq <= expires_at) or expires_at < approved_at:
            approval_reasons.append("APPROVAL_EXPIRED_OR_NOT_YET_VALID")
        if approval_reasons:
            return _finish(proposal, policy, next_state, seq, evidence_root_value, "DENY", approval_reasons)

    return _finish(proposal, policy, next_state, seq, evidence_root_value, "ALLOW", ["ALL_GATES_PASSED"])
