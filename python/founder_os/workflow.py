from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from claimsieve_ref.canonical import digest
from claimsieve_ref.crypto import KeyPair
from claimsieve_ref.durable_state import (
    DurableProvider,
    DurableCampaignStateStore,
    DurableExecutor,
    DurableProviderSimulator,
    DurableStateService,
    IndependentObserver,
)
from claimsieve_ref.fixtures import keypairs as baseline_keypairs
from claimsieve_ref.kernel import evaluate
from claimsieve_ref.ledger import Ledger
from claimsieve_ref.model import (
    approval_signing_subject,
    display_digest,
    proposal_digest,
)
from claimsieve_ref.runtime import Authority, PermitError
from claimsieve_ref.trust import sign_evidence, sign_policy

_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")


class FounderOSInputError(ValueError):
    pass


@dataclass(frozen=True)
class GitHubIssueRequest:
    proposal_id: str
    trace_id: str
    campaign_id: str
    session_id: str
    work_item_id: str
    repository: str
    title: str
    body: str
    requested_at_seq: int

    def validate(self) -> None:
        bounded = {
            "proposal_id": (self.proposal_id, 128),
            "trace_id": (self.trace_id, 128),
            "campaign_id": (self.campaign_id, 128),
            "session_id": (self.session_id, 128),
            "work_item_id": (self.work_item_id, 256),
            "title": (self.title, 180),
            "body": (self.body, 20_000),
        }
        for name, (value, maximum) in bounded.items():
            if not isinstance(value, str) or not value or len(value) > maximum:
                raise FounderOSInputError(f"{name} must be a non-empty string of at most {maximum} characters")
        if not _REPOSITORY_RE.fullmatch(self.repository):
            raise FounderOSInputError("repository must be an exact owner/name identifier")
        if isinstance(self.requested_at_seq, bool) or not isinstance(self.requested_at_seq, int) or self.requested_at_seq < 0:
            raise FounderOSInputError("requested_at_seq must be a non-negative integer")


@dataclass(frozen=True)
class PreparedFounderAction:
    request: GitHubIssueRequest
    evidence: list[dict[str, Any]]
    policy: dict[str, Any]
    signed_policy: dict[str, Any]
    proposal: dict[str, Any]
    decision: dict[str, Any]
    permit: dict[str, Any]


@dataclass(frozen=True)
class FounderActionResult:
    prepared: PreparedFounderAction
    execution: dict[str, Any]
    observation: dict[str, Any]
    ledgers: dict[str, list[dict[str, Any]]]



def founder_fixture_keys() -> dict[str, KeyPair]:
    """Deterministic fixture keys for tests only; never production key material."""
    keys = baseline_keypairs()
    keys["founder_work_evidence"] = KeyPair.from_seed(
        "founder_work_evidence-key-v1", bytes([31]) * 32
    )
    keys["github_registry_evidence"] = KeyPair.from_seed(
        "github_registry_evidence-key-v1", bytes([32]) * 32
    )
    return keys



def founder_policy(keys: dict[str, KeyPair], tenant_id: str = "tenant-founder") -> dict[str, Any]:
    return {
        "schema_version": "claimsieve.policy.v1",
        "policy_id": "mainstreet-founder-os-github-issue",
        "version": 1,
        "tenant_id": tenant_id,
        "allowed_principals": [f"spiffe://mainstreet.local/{tenant_id}/agent/openclaw"],
        "allowed_action_kinds": ["run_connector"],
        "allowed_effect_classes": ["external_write"],
        "allowed_trust_domains": ["github.com"],
        "allowed_subgoals": ["create_project_issue"],
        "approval_required_for": ["run_connector", "external_write"],
        "allowed_approver_key_ids": [keys["approver"].key_id],
        "allowed_approver_identities": [f"spiffe://mainstreet.local/{tenant_id}/human/founder"],
        "required_evidence": [
            "work_item_authority",
            "destination_registry",
            "deployment_certificate",
            "governance_epoch",
        ],
        "trusted_evidence_sources": {
            "work_item_authority": [f"spiffe://mainstreet.local/{tenant_id}/founder-work-log"],
            "destination_registry": ["spiffe://claimsieve.local/github-repository-registry"],
            "deployment_certificate": ["spiffe://claimsieve.local/deployment-certifier"],
            "governance_epoch": ["spiffe://claimsieve.local/epoch-authority"],
        },
        "trusted_evidence_key_ids": {
            "work_item_authority": [keys["founder_work_evidence"].key_id],
            "destination_registry": [keys["github_registry_evidence"].key_id],
            "deployment_certificate": [keys["deployment_evidence"].key_id],
            "governance_epoch": [keys["epoch_evidence"].key_id],
        },
        "freshness_window": 10,
        "campaign_limits": {
            "max_actions": 20,
            "max_denials": 3,
            "max_new_destinations": 3,
            "max_sessions": 3,
            "max_boundary_crossings": 2,
            "max_encoded_fragments": 0,
        },
        "deny_risk_tags": [
            "UNDECLARED_REDIRECT",
            "EXECUTABLE_UPLOAD",
            "PACKAGE_PROXY_TUNNEL",
            "PURPOSE_MISMATCH",
        ],
        "suspend_risk_tags": [
            "DIRECT_EXECUTION_ATTEMPT",
            "CREDENTIAL_USE",
            "CLOUD_METADATA_ACCESS",
            "OBSERVER_TAMPER",
            "UNRESTRICTED_NESTED_AGENT",
        ],
    }



def _runtime_manifest_digest(tenant_id: str) -> str:
    return digest(
        {
            "mainstreet_bridge_version": "0.34.0",
            "openclaw": "proposal-only; pinned build required",
            "tenant_id": tenant_id,
            "skills": ["founder-os-github-issue-proposal"],
            "direct_provider_execution": False,
        }
    )



def founder_evidence(
    request: GitHubIssueRequest,
    keys: dict[str, KeyPair],
    tenant_id: str = "tenant-founder",
) -> list[dict[str, Any]]:
    request.validate()
    seq = request.requested_at_seq
    runtime_digest = _runtime_manifest_digest(tenant_id)
    requested_effect = {
        "repository": request.repository,
        "title": request.title,
        "body": request.body,
        "work_item_id": request.work_item_id,
    }
    work_item = sign_evidence(
        {
            "schema_version": "claimsieve.evidence.v1",
            "type": "work_item_authority",
            "source": f"spiffe://mainstreet.local/{tenant_id}/founder-work-log",
            "subject": request.work_item_id,
            "observed_at_seq": seq,
            "verified": True,
            "content": {
                "status": "OPEN",
                "requested_effect_digest": digest(requested_effect),
                "purpose": "Create one reviewable project issue",
            },
        },
        keys["founder_work_evidence"],
    )
    registry = sign_evidence(
        {
            "schema_version": "claimsieve.evidence.v1",
            "type": "destination_registry",
            "source": "spiffe://claimsieve.local/github-repository-registry",
            "subject": request.repository,
            "observed_at_seq": seq,
            "verified": True,
            "content": {
                "authority": request.repository,
                "trust_domain": "github.com",
                "allowed_operation": "issues:create",
                "credential_owner": "restricted-github-adapter",
            },
        },
        keys["github_registry_evidence"],
    )
    deployment = sign_evidence(
        {
            "schema_version": "claimsieve.evidence.v1",
            "type": "deployment_certificate",
            "source": "spiffe://claimsieve.local/deployment-certifier",
            "subject": f"mainstreet-{tenant_id}-founder-os",
            "observed_at_seq": seq,
            "verified": True,
            "content": {
                "status": "ACTIVE",
                "valid_from_seq": max(0, seq - 1),
                "expires_at_seq": seq + 100,
                "runtime_manifest_digest": runtime_digest,
                "skills_manifest_digest": digest(["founder-os-github-issue-proposal"]),
                "network_profile_digest": digest({"egress": ["claimsieve-intake"]}),
            },
        },
        keys["deployment_evidence"],
    )
    epoch = sign_evidence(
        {
            "schema_version": "claimsieve.evidence.v1",
            "type": "governance_epoch",
            "source": "spiffe://claimsieve.local/epoch-authority",
            "subject": f"{tenant_id}-founder-os-epoch-1",
            "observed_at_seq": seq,
            "verified": True,
            "content": {
                "status": "ACTIVE",
                "policy_version": 1,
                "deployment_certificate_digest": digest(deployment),
                "runtime_manifest_digest": runtime_digest,
            },
        },
        keys["epoch_evidence"],
    )
    return [work_item, registry, deployment, epoch]



def founder_proposal(
    request: GitHubIssueRequest,
    evidence_items: Iterable[dict[str, Any]],
    keys: dict[str, KeyPair],
    tenant_id: str = "tenant-founder",
    approve: bool = True,
) -> dict[str, Any]:
    request.validate()
    evidence_list = list(evidence_items)
    seq = request.requested_at_seq
    correlation_marker = f"claimsieve:{request.proposal_id}"
    value: dict[str, Any] = {
        "schema_version": "claimsieve.proposal.v1",
        "proposal_id": request.proposal_id,
        "trace_id": request.trace_id,
        "tenant_id": tenant_id,
        "campaign_id": request.campaign_id,
        "session_id": request.session_id,
        "parent_action_id": None,
        "principal": f"spiffe://mainstreet.local/{tenant_id}/agent/openclaw",
        "objective": {
            "root": "Operate the ClaimSieve and MainStreet company through reviewable governed work.",
            "subgoal": "create_project_issue",
            "expected_effect": "Exactly one GitHub issue is created in the approved repository.",
            "constraints": [
                "No direct GitHub credential access from MainStreet or OpenClaw",
                "No repository substitution",
                "No payload mutation after approval",
                "Ambiguous outcomes remain unknown until independent reconciliation",
            ],
        },
        "action": {
            "kind": "run_connector",
            "effect_class": "external_write",
            "destination": {
                "scheme": "github",
                "authority": request.repository,
                "resource": "issues",
                "trust_domain": "github.com",
            },
            "method": "CREATE",
            "parameters": {
                "title": request.title,
                "body": request.body,
                "correlation_marker": correlation_marker,
                "work_item_id": request.work_item_id,
            },
            "reversibility": "compensable",
        },
        "evidence_refs": [digest(item) for item in evidence_list],
        "approval": None,
        "requested_at_seq": seq,
        "risk_tags": [],
    }
    if approve:
        approver = keys["approver"]
        unsigned = {
            "schema_version": "claimsieve.approval.v1",
            "approval_id": f"approval-{request.proposal_id}",
            "approver": f"spiffe://mainstreet.local/{tenant_id}/human/founder",
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


class FounderOSReferenceWorkflow:
    """Reference composition over the v0.33 authority and durable outcome boundary.

    This class intentionally owns no alternate permit issuer. It uses the baseline
    Authority, DurableStateService, DurableExecutor, and IndependentObserver.
    The provider is a deterministic local simulator, not a live GitHub adapter.
    """

    def __init__(
        self,
        workspace: str | Path,
        allowed_repositories: Iterable[str],
        provider_mode: str = "success",
        tenant_id: str = "tenant-founder",
        provider: DurableProvider | None = None,
    ) -> None:
        self.workspace = Path(workspace)
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.allowed_repositories = frozenset(allowed_repositories)
        if not self.allowed_repositories or any(not _REPOSITORY_RE.fullmatch(repo) for repo in self.allowed_repositories):
            raise FounderOSInputError("at least one valid owner/name repository is required")
        self.tenant_id = tenant_id
        self._keys = founder_fixture_keys()
        self._state = DurableStateService(
            self.workspace / "founder-state.sqlite3",
            executor_keys={self._keys["executor"].key_id: self._keys["executor"].public},
            observer_keys={self._keys["observer"].key_id: self._keys["observer"].public},
        )
        self._provider = provider or DurableProviderSimulator(
            self.workspace / "github-provider-simulator.sqlite3", provider_mode
        )
        self._authority = Authority(
            self._keys["authority"],
            {self._keys["approver"].key_id: self._keys["approver"].public},
            {self._keys["policy_authority"].key_id: self._keys["policy_authority"].public},
            {
                self._keys[name].key_id: self._keys[name].public
                for name in (
                    "founder_work_evidence",
                    "github_registry_evidence",
                    "deployment_evidence",
                    "epoch_evidence",
                )
            },
            DurableCampaignStateStore(self._state),
        )
        self._executor = DurableExecutor(
            self._state,
            self._provider,
            {self._keys["authority"].key_id: self._keys["authority"].public},
            self._keys["executor"],
        )
        self._observer = IndependentObserver(self._state, self._provider, self._keys["observer"])
        self._ledgers = {
            "proposal": Ledger("proposal", self._keys["proposal"]),
            "evidence": Ledger("evidence", self._keys["evidence"]),
            "decision": Ledger("decision", self._keys["decision"]),
            "execution": Ledger("execution", self._keys["execution"]),
        }

    def prepare_issue(self, request: GitHubIssueRequest, nonce: str = "44" * 24) -> PreparedFounderAction:
        request.validate()
        if request.repository not in self.allowed_repositories:
            raise FounderOSInputError("repository is not in the Founder OS allowlist")
        policy = founder_policy(self._keys, self.tenant_id)
        signed = sign_policy(policy, self._keys["policy_authority"])
        evidence_items = founder_evidence(request, self._keys, self.tenant_id)
        proposal = founder_proposal(request, evidence_items, self._keys, self.tenant_id, approve=True)
        prior = self._state.read_campaign(request.campaign_id).state
        decision = evaluate(proposal, policy, evidence_items, prior, request.requested_at_seq)
        if decision.document.get("verdict") != "ALLOW":
            raise PermitError("Founder OS proposal was not allowed: " + ",".join(decision.document.get("reason_codes", [])))
        permit = self._authority.issue(
            proposal,
            signed,
            evidence_items,
            decision.document,
            request.requested_at_seq,
            nonce=nonce,
        )
        trace_id = request.trace_id
        self._ledgers["proposal"].append(trace_id, "FOUNDER_OS_PROPOSAL_SUBMITTED", proposal)
        for item in evidence_items:
            self._ledgers["evidence"].append(trace_id, "FOUNDER_OS_EVIDENCE_RECORDED", item)
        self._ledgers["decision"].append(trace_id, "FOUNDER_OS_SIGNED_POLICY_RECORDED", signed)
        self._ledgers["decision"].append(trace_id, "FOUNDER_OS_DECISION_RECORDED", decision.document)
        self._ledgers["decision"].append(trace_id, "FOUNDER_OS_PERMIT_ISSUED", permit)
        return PreparedFounderAction(
            request=request,
            evidence=copy.deepcopy(evidence_items),
            policy=copy.deepcopy(policy),
            signed_policy=copy.deepcopy(signed),
            proposal=copy.deepcopy(proposal),
            decision=copy.deepcopy(decision.document),
            permit=copy.deepcopy(permit),
        )

    def execute_issue(
        self,
        prepared: PreparedFounderAction,
        execute_seq: int,
        observe_seq: int,
        failpoint: str | None = None,
    ) -> FounderActionResult:
        execution = self._executor.execute(
            prepared.permit,
            prepared.proposal,
            prepared.signed_policy,
            prepared.evidence,
            prepared.decision,
            execute_seq,
            failpoint=failpoint,
        )
        if execution.get("automatic_retry_allowed") is not False:
            raise RuntimeError("Founder OS requires automatic_retry_allowed to remain false")
        reservation = execution["reservation"]
        observation = self._observer.reconcile(
            str(reservation["reservation_id"]), prepared.proposal, observe_seq
        )
        trace_id = prepared.request.trace_id
        self._ledgers["execution"].append(trace_id, "FOUNDER_OS_RESERVATION", reservation)
        self._ledgers["execution"].append(trace_id, "FOUNDER_OS_EXECUTOR_RECEIPT", execution["executor_receipt"])
        self._ledgers["execution"].append(trace_id, "FOUNDER_OS_OBSERVER_RECEIPT", observation)
        return FounderActionResult(
            prepared=prepared,
            execution=copy.deepcopy(execution),
            observation=copy.deepcopy(observation),
            ledgers=self.ledger_records(),
        )

    def ledger_records(self) -> dict[str, list[dict[str, Any]]]:
        return {name: copy.deepcopy(ledger.records) for name, ledger in self._ledgers.items()}

    def verify_ledgers(self) -> dict[str, list[str]]:
        writer_keys = {
            self._keys[name].key_id: self._keys[name].public
            for name in ("proposal", "evidence", "decision", "execution")
        }
        return {
            name: Ledger.verify(ledger.records, writer_keys, name)
            for name, ledger in self._ledgers.items()
        }
