#!/usr/bin/env python3
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Any

from claimsieve_ref.canonical import digest
from claimsieve_ref.durable_state import (
    DurableCampaignStateStore,
    DurableExecutor,
    DurableProviderSimulator,
    DurableStateService,
    IndependentObserver,
)
from claimsieve_ref.fixtures import keypairs
from claimsieve_ref.kernel import evaluate
from claimsieve_ref.model import approval_signing_subject, display_digest, proposal_digest
from claimsieve_ref.runtime import Authority
from claimsieve_ref.trust import sign_evidence, sign_policy


def _tax_policy() -> dict[str, Any]:
    keys = keypairs()
    return {
        "schema_version": "claimsieve.policy.v1",
        "policy_id": "mainstreet-tax-notice-simulator-policy",
        "version": 1,
        "tenant_id": "tenant-synthetic-tax-pilot",
        "allowed_principals": [
            "spiffe://mainstreet.local/tenant-synthetic-tax-pilot/agent/openclaw"
        ],
        "allowed_action_kinds": ["submit_tax_response_simulated"],
        "allowed_effect_classes": ["external_write"],
        "allowed_trust_domains": ["tax-portal-simulator"],
        "allowed_subgoals": ["respond_to_tax_notice"],
        "approval_required_for": ["external_write", "submit_tax_response_simulated"],
        "allowed_approver_key_ids": [keys["approver"].key_id],
        "allowed_approver_identities": [
            "spiffe://mainstreet.local/tenant-synthetic-tax-pilot/human/taxpayer"
        ],
        "required_evidence": [
            "tax_notice",
            "taxpayer_attestation",
            "destination_registry",
            "deployment_certificate",
            "governance_epoch",
        ],
        "trusted_evidence_sources": {
            "tax_notice": ["spiffe://mainstreet.local/tenant-synthetic-tax-pilot/document-reader"],
            "taxpayer_attestation": ["spiffe://mainstreet.local/tenant-synthetic-tax-pilot/human-attestation"],
            "destination_registry": ["spiffe://claimsieve.local/registry"],
            "deployment_certificate": ["spiffe://claimsieve.local/deployment-certifier"],
            "governance_epoch": ["spiffe://claimsieve.local/epoch-authority"],
        },
        "trusted_evidence_key_ids": {
            "tax_notice": [keys["crm_evidence"].key_id],
            "taxpayer_attestation": [keys["crm_evidence"].key_id],
            "destination_registry": [keys["registry_evidence"].key_id],
            "deployment_certificate": [keys["deployment_evidence"].key_id],
            "governance_epoch": [keys["epoch_evidence"].key_id],
        },
        "freshness_window": 5,
        "campaign_limits": {
            "max_actions": 5,
            "max_denials": 2,
            "max_new_destinations": 1,
            "max_sessions": 2,
            "max_boundary_crossings": 1,
            "max_encoded_fragments": 0,
        },
        "deny_risk_tags": ["POST_APPROVAL_MUTATION", "PURPOSE_MISMATCH"],
        "suspend_risk_tags": ["DIRECT_EXECUTION_ATTEMPT", "CREDENTIAL_USE"],
    }


def _tax_evidence(seq: int = 10) -> list[dict[str, Any]]:
    keys = keypairs()
    runtime_manifest = digest(
        {
            "product": "mainstreet-tax-notice-pilot",
            "version": "0.33.0",
            "live_portal_access": False,
        }
    )
    notice = sign_evidence(
        {
            "schema_version": "claimsieve.evidence.v1",
            "type": "tax_notice",
            "source": "spiffe://mainstreet.local/tenant-synthetic-tax-pilot/document-reader",
            "subject": "synthetic-notice-001",
            "observed_at_seq": seq,
            "verified": True,
            "content": {
                "authority": "Synthetic State Revenue Agency",
                "notice_type": "Proposed Assessment",
                "tax_period": "2023",
                "response_deadline": "2026-08-21",
                "document_digest": digest({"synthetic": "notice-001"}),
            },
        },
        keys["crm_evidence"],
    )
    attestation = sign_evidence(
        {
            "schema_version": "claimsieve.evidence.v1",
            "type": "taxpayer_attestation",
            "source": "spiffe://mainstreet.local/tenant-synthetic-tax-pilot/human-attestation",
            "subject": "synthetic-taxpayer",
            "observed_at_seq": seq,
            "verified": True,
            "content": {
                "statement": "The attached response is accurate to the best of my knowledge.",
                "scope": "synthetic-notice-001",
            },
        },
        keys["crm_evidence"],
    )
    registry = sign_evidence(
        {
            "schema_version": "claimsieve.evidence.v1",
            "type": "destination_registry",
            "source": "spiffe://claimsieve.local/registry",
            "subject": "tax-portal-simulator",
            "observed_at_seq": seq,
            "verified": True,
            "content": {
                "authority": "simulator.tax.local",
                "trust_domain": "tax-portal-simulator",
            },
        },
        keys["registry_evidence"],
    )
    deployment = sign_evidence(
        {
            "schema_version": "claimsieve.evidence.v1",
            "type": "deployment_certificate",
            "source": "spiffe://claimsieve.local/deployment-certifier",
            "subject": "mainstreet-tax-notice-pilot",
            "observed_at_seq": seq,
            "verified": True,
            "content": {
                "status": "ACTIVE",
                "valid_from_seq": 0,
                "expires_at_seq": 100,
                "runtime_manifest_digest": runtime_manifest,
                "skills_manifest_digest": digest(["tax-notice-case-manager"]),
                "network_profile_digest": digest({"egress": ["tax-portal-simulator"]}),
            },
        },
        keys["deployment_evidence"],
    )
    epoch = sign_evidence(
        {
            "schema_version": "claimsieve.evidence.v1",
            "type": "governance_epoch",
            "source": "spiffe://claimsieve.local/epoch-authority",
            "subject": "synthetic-tax-epoch-1",
            "observed_at_seq": seq,
            "verified": True,
            "content": {
                "status": "ACTIVE",
                "policy_version": 1,
                "deployment_certificate_digest": digest(deployment),
                "runtime_manifest_digest": runtime_manifest,
            },
        },
        keys["epoch_evidence"],
    )
    return [notice, attestation, registry, deployment, epoch]


def _tax_proposal(evidence_items: list[dict[str, Any]], seq: int = 10) -> dict[str, Any]:
    keys = keypairs()
    value: dict[str, Any] = {
        "schema_version": "claimsieve.proposal.v1",
        "proposal_id": "tax-proposal-001",
        "trace_id": "tax-trace-001",
        "tenant_id": "tenant-synthetic-tax-pilot",
        "campaign_id": "tax-campaign-001",
        "session_id": "tax-session-001",
        "parent_action_id": None,
        "principal": "spiffe://mainstreet.local/tenant-synthetic-tax-pilot/agent/openclaw",
        "objective": {
            "root": "Respond accurately to a synthetic tax notice before the deadline.",
            "subgoal": "respond_to_tax_notice",
            "expected_effect": "One exact response packet is accepted by the tax portal simulator.",
            "constraints": [
                "No live government portal access",
                "No payment",
                "No signature substitution",
                "No automatic retry after an unknown outcome",
            ],
        },
        "action": {
            "kind": "submit_tax_response_simulated",
            "effect_class": "external_write",
            "destination": {
                "scheme": "https-simulator",
                "authority": "simulator.tax.local",
                "resource": "synthetic-notice-001",
                "trust_domain": "tax-portal-simulator",
            },
            "method": "SUBMIT",
            "parameters": {
                "packet_digest": digest({"synthetic": "response-packet-001"}),
                "tax_period": "2023",
                "notice_id": "synthetic-notice-001",
            },
            "reversibility": "compensable",
        },
        "evidence_refs": [digest(item) for item in evidence_items],
        "approval": None,
        "requested_at_seq": seq,
        "risk_tags": [],
    }
    unsigned = {
        "schema_version": "claimsieve.approval.v1",
        "approval_id": "approval-tax-proposal-001",
        "approver": "spiffe://mainstreet.local/tenant-synthetic-tax-pilot/human/taxpayer",
        "proposal_digest": proposal_digest(value),
        "display_digest": display_digest(value),
        "approved_at_seq": seq,
        "expires_at_seq": seq + 3,
        "approver_key_id": keys["approver"].key_id,
    }
    value["approval"] = {
        **unsigned,
        "signature": keys["approver"].sign("approval-v1", approval_signing_subject(unsigned)),
    }
    return value


def run_demo(mode: str = "success") -> dict[str, Any]:
    keys = keypairs()
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        state = DurableStateService(
            root / "state.sqlite3",
            executor_keys={keys["executor"].key_id: keys["executor"].public},
            observer_keys={keys["observer"].key_id: keys["observer"].public},
        )
        provider = DurableProviderSimulator(root / "tax-portal-simulator.sqlite3", mode)
        pol = _tax_policy()
        signed = sign_policy(pol, keys["policy_authority"])
        ev = _tax_evidence(10)
        prop = _tax_proposal(ev, 10)
        prior = state.read_campaign(prop["campaign_id"]).state
        decision = evaluate(prop, pol, ev, prior, 10)
        authority = Authority(
            keys["authority"],
            {keys["approver"].key_id: keys["approver"].public},
            {keys["policy_authority"].key_id: keys["policy_authority"].public},
            {
                keys["crm_evidence"].key_id: keys["crm_evidence"].public,
                keys["registry_evidence"].key_id: keys["registry_evidence"].public,
                keys["deployment_evidence"].key_id: keys["deployment_evidence"].public,
                keys["epoch_evidence"].key_id: keys["epoch_evidence"].public,
            },
            DurableCampaignStateStore(state),
        )
        permit = authority.issue(prop, signed, ev, decision.document, 10, nonce="99" * 24)
        executor = DurableExecutor(
            state,
            provider,
            {keys["authority"].key_id: keys["authority"].public},
            keys["executor"],
        )
        execution = executor.execute(permit, prop, signed, ev, decision.document, 11)
        observer = IndependentObserver(
            state,
            provider,
            keys["observer"],
        )
        observation = observer.reconcile(execution["reservation"]["reservation_id"], prop, 12)
        return {
            "release": "0.33.0",
            "live_portal_access": False,
            "decision": decision.document["verdict"],
            "reservation_status": state.get_reservation(execution["reservation"]["reservation_id"])["status"],
            "reconciliation": observation["reconciliation"],
            "automatic_retry_allowed": execution["automatic_retry_allowed"],
            "journal_verified": state.verify_journal(),
        }


if __name__ == "__main__":
    print(json.dumps(run_demo(), indent=2, sort_keys=True))
