from __future__ import annotations

import copy
from typing import Any

from .canonical import digest
from .crypto import KeyPair
from .model import approval_signing_subject, display_digest, proposal_digest
from .trust import sign_evidence, sign_policy


_KEY_NAMES = [
    "proposal", "evidence", "decision", "execution", "authority", "approver",
    "executor", "observer", "containment", "witness", "policy_authority",
    "crm_evidence", "registry_evidence", "deployment_evidence", "epoch_evidence",
]


def keypairs() -> dict[str, KeyPair]:
    return {
        name: KeyPair.from_seed(f"{name}-key-v1", bytes([index + 1]) * 32)
        for index, name in enumerate(_KEY_NAMES)
    }


def policy(**overrides: Any) -> dict[str, Any]:
    keys = keypairs()
    value: dict[str, Any] = {
        "schema_version": "claimsieve.policy.v1",
        "policy_id": "mainstreet-demo-policy",
        "version": 2,
        "tenant_id": "tenant-demo",
        "allowed_principals": ["spiffe://mainstreet.local/tenant-demo/agent/openclaw"],
        "allowed_action_kinds": ["send_message", "create_calendar_event", "fetch_artifact"],
        "allowed_effect_classes": ["read", "external_write", "network_boundary"],
        "allowed_trust_domains": ["tenant-demo", "sms-provider", "calendar-provider", "artifact-registry"],
        "allowed_subgoals": ["respond_to_lead", "schedule_appointment", "retrieve_pinned_dependency"],
        "approval_required_for": ["external_write", "network_boundary", "create_calendar_event"],
        "allowed_approver_key_ids": [keys["approver"].key_id],
        "allowed_approver_identities": ["spiffe://mainstreet.local/tenant-demo/human/owner"],
        "required_evidence": [
            "customer_contact_authority", "destination_registry",
            "deployment_certificate", "governance_epoch",
        ],
        "trusted_evidence_sources": {
            "customer_contact_authority": ["spiffe://mainstreet.local/tenant-demo/crm-reader"],
            "destination_registry": ["spiffe://claimsieve.local/registry"],
            "deployment_certificate": ["spiffe://claimsieve.local/deployment-certifier"],
            "governance_epoch": ["spiffe://claimsieve.local/epoch-authority"],
        },
        "trusted_evidence_key_ids": {
            "customer_contact_authority": [keys["crm_evidence"].key_id],
            "destination_registry": [keys["registry_evidence"].key_id],
            "deployment_certificate": [keys["deployment_evidence"].key_id],
            "governance_epoch": [keys["epoch_evidence"].key_id],
        },
        "freshness_window": 10,
        "campaign_limits": {
            "max_actions": 20,
            "max_denials": 3,
            "max_new_destinations": 4,
            "max_sessions": 3,
            "max_boundary_crossings": 4,
            "max_encoded_fragments": 1,
        },
        "deny_risk_tags": ["UNDECLARED_REDIRECT", "EXECUTABLE_UPLOAD", "PACKAGE_PROXY_TUNNEL"],
        "suspend_risk_tags": [
            "DIRECT_EXECUTION_ATTEMPT", "CREDENTIAL_USE", "CLOUD_METADATA_ACCESS",
            "OBSERVER_TAMPER", "UNRESTRICTED_NESTED_AGENT",
        ],
    }
    value.update(copy.deepcopy(overrides))
    return value


def signed_policy(**overrides: Any) -> dict[str, Any]:
    keys = keypairs()
    return sign_policy(policy(**overrides), keys["policy_authority"])


def evidence(seq: int = 10) -> list[dict[str, Any]]:
    keys = keypairs()
    runtime_manifest_digest = digest({
        "openclaw_build": "pinned-required",
        "bridge_version": "0.33.0",
        "skills": ["mainstreet-claimsieve-proposal"],
        "direct_execution": False,
    })
    contact = sign_evidence({
        "schema_version": "claimsieve.evidence.v1",
        "type": "customer_contact_authority",
        "source": "spiffe://mainstreet.local/tenant-demo/crm-reader",
        "subject": "lead-123",
        "observed_at_seq": seq,
        "verified": True,
        "content": {"phone": "+15551234567", "consent": "lead-form"},
    }, keys["crm_evidence"])
    registry = sign_evidence({
        "schema_version": "claimsieve.evidence.v1",
        "type": "destination_registry",
        "source": "spiffe://claimsieve.local/registry",
        "subject": "sms-provider",
        "observed_at_seq": seq,
        "verified": True,
        "content": {"authority": "+15551234567", "trust_domain": "sms-provider"},
    }, keys["registry_evidence"])
    deployment = sign_evidence({
        "schema_version": "claimsieve.evidence.v1",
        "type": "deployment_certificate",
        "source": "spiffe://claimsieve.local/deployment-certifier",
        "subject": "mainstreet-tenant-demo-deployment",
        "observed_at_seq": seq,
        "verified": True,
        "content": {
            "status": "ACTIVE",
            "valid_from_seq": 0,
            "expires_at_seq": 100,
            "runtime_manifest_digest": runtime_manifest_digest,
            "skills_manifest_digest": digest(["mainstreet-claimsieve-proposal"]),
            "network_profile_digest": digest({"egress": ["claimsieve-intake"]}),
        },
    }, keys["deployment_evidence"])
    epoch = sign_evidence({
        "schema_version": "claimsieve.evidence.v1",
        "type": "governance_epoch",
        "source": "spiffe://claimsieve.local/epoch-authority",
        "subject": "tenant-demo-epoch-2",
        "observed_at_seq": seq,
        "verified": True,
        "content": {
            "status": "ACTIVE",
            "policy_version": 2,
            "deployment_certificate_digest": digest(deployment),
            "runtime_manifest_digest": runtime_manifest_digest,
        },
    }, keys["epoch_evidence"])
    return [contact, registry, deployment, epoch]


def proposal(
    evidence_items: list[dict[str, Any]],
    seq: int = 10,
    approve: bool = True,
    **overrides: Any,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema_version": "claimsieve.proposal.v1",
        "proposal_id": "proposal-001",
        "trace_id": "trace-001",
        "tenant_id": "tenant-demo",
        "campaign_id": "campaign-001",
        "session_id": "session-001",
        "parent_action_id": None,
        "principal": "spiffe://mainstreet.local/tenant-demo/agent/openclaw",
        "objective": {
            "root": "Help the gym respond to a lead using only approved business channels.",
            "subgoal": "respond_to_lead",
            "expected_effect": "One consented SMS is sent to the lead.",
            "constraints": ["No medical claims", "No unapproved destination", "No direct provider access"],
        },
        "action": {
            "kind": "send_message",
            "effect_class": "external_write",
            "destination": {
                "scheme": "sms",
                "authority": "+15551234567",
                "resource": "lead-123",
                "trust_domain": "sms-provider",
            },
            "method": "SEND",
            "parameters": {"body": "Hi! Would you like to schedule an intro session?"},
            "reversibility": "compensable",
        },
        "evidence_refs": [digest(item) for item in evidence_items],
        "approval": None,
        "requested_at_seq": seq,
        "risk_tags": [],
    }
    for key, item in overrides.items():
        value[key] = copy.deepcopy(item)
    if approve:
        approver = keypairs()["approver"]
        unsigned = {
            "schema_version": "claimsieve.approval.v1",
            "approval_id": f"approval-{value['proposal_id']}",
            "approver": "spiffe://mainstreet.local/tenant-demo/human/owner",
            "proposal_digest": proposal_digest(value),
            "display_digest": display_digest(value),
            "approved_at_seq": seq,
            "expires_at_seq": seq + 5,
            "approver_key_id": approver.key_id,
        }
        value["approval"] = {
            **unsigned,
            "signature": approver.sign("approval-v1", approval_signing_subject(unsigned)),
        }
    return value


def trust_root() -> dict[str, Any]:
    keys = keypairs()
    return {
        "schema_version": "claimsieve.trust_root.v1",
        "root_id": "claimsieve-fixture-trust-root-v1",
        "keys": {name_key.key_id: name_key.public.encode() for name_key in keys.values()},
        "roles": {
            "policy_signers": [keys["policy_authority"].key_id],
            "authority_signers": [keys["authority"].key_id],
            "approval_signers": [keys["approver"].key_id],
            "executor_signers": [keys["executor"].key_id],
            "observer_signers": [keys["observer"].key_id],
            "containment_signers": [keys["containment"].key_id],
            "witness_signers": [keys["witness"].key_id],
            "evidence_signers": [
                keys["crm_evidence"].key_id,
                keys["registry_evidence"].key_id,
                keys["deployment_evidence"].key_id,
                keys["epoch_evidence"].key_id,
            ],
            "proposal_ledger_writers": [keys["proposal"].key_id],
            "evidence_ledger_writers": [keys["evidence"].key_id],
            "decision_ledger_writers": [keys["decision"].key_id],
            "execution_ledger_writers": [keys["execution"].key_id],
        },
    }
