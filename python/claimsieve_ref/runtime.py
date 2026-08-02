from __future__ import annotations

import copy
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping

from .canonical import digest
from .crypto import KeyPair, PublicKey
from .kernel import CampaignState, evaluate
from .model import (
    action_digest,
    approval_digest,
    approval_signing_subject,
    destination_digest,
    display_digest,
    evidence_root,
    parameter_digest,
    proposal_digest,
)
from .trust import TrustError, verify_signed_evidence, verify_signed_policy


class PermitError(ValueError):
    pass


@dataclass
class CampaignStateStore:
    """Atomic in-process reference store for a single durable successor per state.

    The Python object is a conformance oracle, not a distributed production store.
    The API deliberately exposes compare-and-swap semantics that a production
    linearizable database or replicated state machine must preserve.
    """

    _states: dict[str, CampaignState] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def read(self, campaign_id: str) -> CampaignState:
        with self._lock:
            state = self._states.setdefault(campaign_id, CampaignState(campaign_id))
            return state.clone()

    def compare_and_swap(
        self,
        campaign_id: str,
        expected_digest: str,
        expected_last_sequence: int,
        successor: CampaignState,
    ) -> bool:
        with self._lock:
            current = self._states.setdefault(campaign_id, CampaignState(campaign_id))
            if digest(current.as_canonical()) != expected_digest:
                return False
            if current.last_sequence != expected_last_sequence:
                return False
            if successor.campaign_id != campaign_id:
                return False
            if successor.last_sequence <= current.last_sequence:
                return False
            stored = successor.clone()
            if hasattr(stored, "_prior_state_digest"):
                delattr(stored, "_prior_state_digest")
            self._states[campaign_id] = stored
            return True

    def replace_for_recovery(self, state: CampaignState) -> None:
        """Explicit recovery hook; callers must govern access outside this oracle."""
        with self._lock:
            self._states[state.campaign_id] = state.clone()


@dataclass
class Authority:
    key: KeyPair
    approval_keys: Mapping[str, PublicKey]
    policy_keys: Mapping[str, PublicKey]
    evidence_keys: Mapping[str, PublicKey]
    campaign_states: CampaignStateStore

    def _verify_human_approval(
        self, proposal: dict[str, Any], policy: dict[str, Any], seq: int
    ) -> None:
        action = proposal.get("action", {})
        required = (
            action.get("kind") in policy.get("approval_required_for", [])
            or action.get("effect_class") in policy.get("approval_required_for", [])
            or action.get("reversibility") in {"irreversible", "unknown"}
        )
        approval = proposal.get("approval")
        if approval is None:
            if required:
                raise PermitError("required human approval is missing")
            return
        if not isinstance(approval, dict):
            raise PermitError("human approval must be an object")
        if approval.get("schema_version") != "claimsieve.approval.v1":
            raise PermitError("unsupported human approval schema")
        approver_identity = approval.get("approver")
        if not isinstance(approver_identity, str) or not approver_identity.startswith("spiffe://"):
            raise PermitError("human approval identity is not an authenticated SPIFFE identity")
        allowed_identities = policy.get("allowed_approver_identities", [])
        if not isinstance(allowed_identities, list) or approver_identity not in allowed_identities:
            raise PermitError("human approval identity is not allowed by policy")
        if approval.get("proposal_digest") != proposal_digest(proposal):
            raise PermitError("human approval proposal binding mismatch")
        if approval.get("display_digest") != display_digest(proposal):
            raise PermitError("human approval display binding mismatch")
        approved_at = approval.get("approved_at_seq")
        expires_at = approval.get("expires_at_seq")
        if (
            isinstance(approved_at, bool)
            or isinstance(expires_at, bool)
            or not isinstance(approved_at, int)
            or not isinstance(expires_at, int)
            or approved_at > seq
            or expires_at < seq
            or expires_at < approved_at
        ):
            raise PermitError("human approval is stale or not yet valid")
        key_id = approval.get("approver_key_id")
        allowed_key_ids = policy.get("allowed_approver_key_ids", [])
        if not isinstance(allowed_key_ids, list) or key_id not in allowed_key_ids:
            raise PermitError("human approval key is not allowed by policy")
        if key_id == self.key.key_id:
            raise PermitError("authority and human approval key roles must be distinct")
        key = self.approval_keys.get(key_id)
        if key is None or key_id != key.key_id:
            raise PermitError("unknown human approval key")
        if key.raw == self.key.public.raw:
            raise PermitError("authority and human approval key material must be distinct")
        if not key.verify(
            "approval-v1", approval_signing_subject(approval), str(approval.get("signature", ""))
        ):
            raise PermitError("human approval signature invalid")

    def issue(
        self,
        proposal: dict[str, Any],
        signed_policy: dict[str, Any],
        evidence: list[dict[str, Any]],
        decision: dict[str, Any],
        seq: int,
        ttl_sequences: int = 5,
        nonce: str | None = None,
    ) -> dict[str, Any]:
        try:
            policy = verify_signed_policy(signed_policy, self.policy_keys)
            verify_signed_evidence(evidence, self.evidence_keys, policy)
        except TrustError as exc:
            raise PermitError(str(exc)) from exc

        if decision.get("schema_version") != "claimsieve.decision.v1":
            raise PermitError("unsupported decision schema")
        if decision.get("verdict") != "ALLOW":
            raise PermitError("only an ALLOW decision can produce a permit")
        if proposal.get("tenant_id") != policy.get("tenant_id"):
            raise PermitError("proposal tenant does not match policy tenant")
        if isinstance(ttl_sequences, bool) or not isinstance(ttl_sequences, int) or not (1 <= ttl_sequences <= 5):
            raise PermitError("permit TTL must be between one and five logical sequences")

        current = self.campaign_states.read(str(proposal.get("campaign_id", "")))
        prior_digest = digest(current.as_canonical())
        if decision.get("prior_campaign_state_digest") != prior_digest:
            raise PermitError("decision predecessor does not match durable campaign state")
        if seq <= current.last_sequence:
            raise PermitError("decision sequence is not a strict successor")

        self._verify_human_approval(proposal, policy, seq)
        reevaluated = evaluate(proposal, policy, evidence, current, seq)
        if reevaluated.document != decision:
            raise PermitError("decision does not match independent kernel reevaluation")
        if decision.get("proposal_digest") != proposal_digest(proposal):
            raise PermitError("decision is not bound to proposal")
        if decision.get("approval_digest") != approval_digest(proposal):
            raise PermitError("decision is not bound to human approval")
        if decision.get("policy_digest") != digest(policy):
            raise PermitError("decision is not bound to policy")
        if decision.get("evidence_root") != evidence_root(evidence):
            raise PermitError("decision is not bound to evidence")
        if decision.get("campaign_state_digest") != digest(reevaluated.next_state.as_canonical()):
            raise PermitError("decision is not bound to reevaluated campaign state")
        if decision.get("decided_at_seq") != seq:
            raise PermitError("decision sequence does not match permit issuance")

        nonce_value = nonce or secrets.token_hex(24)
        permit_identity_digest = digest({
            "tenant_id": proposal["tenant_id"],
            "campaign_id": proposal["campaign_id"],
            "proposal_id": proposal["proposal_id"],
            "sequence": seq,
            "nonce": nonce_value,
        })
        unsigned = {
            "schema_version": "claimsieve.permit.v1",
            "permit_id": "permit:" + permit_identity_digest.removeprefix("sha256:"),
            "trace_id": proposal["trace_id"],
            "tenant_id": proposal["tenant_id"],
            "campaign_id": proposal["campaign_id"],
            "principal": proposal["principal"],
            "proposal_digest": proposal_digest(proposal),
            "action_digest": action_digest(proposal),
            "destination_digest": destination_digest(proposal),
            "parameter_digest": parameter_digest(proposal),
            "policy_digest": digest(policy),
            "signed_policy_digest": digest(signed_policy),
            "evidence_root": evidence_root(evidence),
            "decision_digest": digest(decision),
            "approval_digest": approval_digest(proposal),
            "prior_campaign_state_digest": prior_digest,
            "campaign_state_digest": digest(reevaluated.next_state.as_canonical()),
            "valid_from_seq": seq,
            "expires_at_seq": seq + ttl_sequences,
            "max_uses": 1,
            "nonce": nonce_value,
            "authority_key_id": self.key.key_id,
        }
        permit = {**unsigned, "signature": self.key.sign("permit-v1", unsigned)}
        atomic_commit = getattr(self.campaign_states, "commit_successor_with_permit", None)
        if atomic_commit is not None:
            committed = atomic_commit(
                current.campaign_id,
                prior_digest,
                current.last_sequence,
                reevaluated.next_state,
                permit,
            )
        else:
            committed = self.campaign_states.compare_and_swap(
                current.campaign_id,
                prior_digest,
                current.last_sequence,
                reevaluated.next_state,
            )
        if not committed:
            raise PermitError("campaign state fork or concurrent successor")
        return permit


@dataclass
class ReservationStore:
    _reserved: dict[str, dict[str, Any]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def reserve(self, permit_id: str, action_digest_value: str, seq: int) -> dict[str, Any] | None:
        with self._lock:
            if permit_id in self._reserved:
                return None
            reservation = {
                "schema_version": "claimsieve.reservation.v1",
                "permit_id": permit_id,
                "action_digest": action_digest_value,
                "reserved_at_seq": seq,
                "reservation_id": f"reservation:{permit_id}",
            }
            self._reserved[permit_id] = reservation
            return copy.deepcopy(reservation)

    def count(self) -> int:
        with self._lock:
            return len(self._reserved)


@dataclass
class ContainmentState:
    suspended_campaigns: dict[str, str] = field(default_factory=dict)
    revoked_permits: dict[str, str] = field(default_factory=dict)
    frozen: bool = False
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False, compare=False)


@dataclass(frozen=True)
class ContainmentView:
    state: ContainmentState

    def is_frozen(self) -> bool:
        with self.state.lock:
            return self.state.frozen

    def is_suspended(self, campaign_id: str) -> bool:
        with self.state.lock:
            return campaign_id in self.state.suspended_campaigns

    def is_revoked(self, permit_id: str) -> bool:
        with self.state.lock:
            return permit_id in self.state.revoked_permits


@dataclass
class ContainmentController:
    key: KeyPair
    state: ContainmentState = field(default_factory=ContainmentState)

    def view(self) -> ContainmentView:
        return ContainmentView(self.state)

    @property
    def suspended_campaigns(self) -> dict[str, str]:
        return self.state.suspended_campaigns

    def suspend(self, campaign_id: str, reason: str, seq: int) -> dict[str, Any]:
        with self.state.lock:
            self.state.suspended_campaigns[campaign_id] = reason
        unsigned = {
            "schema_version": "claimsieve.containment_receipt.v1",
            "operation": "SUSPEND_CAMPAIGN",
            "campaign_id": campaign_id,
            "reason": reason,
            "sequence": seq,
            "controller_key_id": self.key.key_id,
        }
        return {**unsigned, "signature": self.key.sign("containment-v1", unsigned)}

    def revoke(self, permit_id: str, reason: str, seq: int) -> dict[str, Any]:
        with self.state.lock:
            self.state.revoked_permits[permit_id] = reason
        unsigned = {
            "schema_version": "claimsieve.containment_receipt.v1",
            "operation": "REVOKE_PERMIT",
            "permit_id": permit_id,
            "reason": reason,
            "sequence": seq,
            "controller_key_id": self.key.key_id,
        }
        return {**unsigned, "signature": self.key.sign("containment-v1", unsigned)}

    def freeze(self, reason: str, seq: int) -> dict[str, Any]:
        with self.state.lock:
            self.state.frozen = True
        unsigned = {
            "schema_version": "claimsieve.containment_receipt.v1",
            "operation": "FREEZE_EXECUTION",
            "reason": reason,
            "sequence": seq,
            "controller_key_id": self.key.key_id,
        }
        return {**unsigned, "signature": self.key.sign("containment-v1", unsigned)}

    def apply_observation(
        self,
        receipt: dict[str, Any],
        observer_keys: Mapping[str, PublicKey],
        seq: int,
    ) -> dict[str, Any] | None:
        unsigned = {key: value for key, value in receipt.items() if key != "signature"}
        key = observer_keys.get(receipt.get("observer_key_id"))
        if key is None or not key.verify(
            "observer-receipt-v1", unsigned, str(receipt.get("signature", ""))
        ):
            raise PermitError("observer receipt signature invalid")
        if receipt.get("reconciliation") == "DIVERGENT_EFFECT":
            return self.suspend(str(receipt.get("campaign_id")), "DIVERGENT_EFFECT", seq)
        return None


@dataclass
class SimulatedExternalSystem:
    mode: str = "success"
    records: dict[str, dict[str, Any]] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, repr=False)

    def apply(self, action: dict[str, Any], idempotency_key: str) -> dict[str, Any]:
        with self._lock:
            if self.mode == "success":
                self.records[idempotency_key] = copy.deepcopy(action)
                return {"status": "accepted", "provider_id": f"provider:{idempotency_key}"}
            if self.mode == "failure":
                return {"status": "rejected", "provider_id": None}
            if self.mode == "ambiguous":
                return {"status": "timeout_unknown", "provider_id": None}
            if self.mode == "ambiguous_applied":
                self.records[idempotency_key] = copy.deepcopy(action)
                return {"status": "timeout_unknown", "provider_id": None}
            if self.mode == "divergent":
                changed = copy.deepcopy(action)
                changed["destination"]["authority"] = "unexpected-target"
                self.records[idempotency_key] = changed
                return {"status": "accepted", "provider_id": f"provider:{idempotency_key}"}
            raise ValueError("unsupported simulated external-system mode")

    def observe(self, idempotency_key: str) -> dict[str, Any] | None:
        with self._lock:
            return copy.deepcopy(self.records.get(idempotency_key))


@dataclass
class SimulatedConnector:
    system: SimulatedExternalSystem
    calls: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def with_mode(cls, mode: str = "success") -> "SimulatedConnector":
        return cls(SimulatedExternalSystem(mode))

    def invoke(self, action: dict[str, Any], idempotency_key: str) -> dict[str, Any]:
        self.calls.append({"action": copy.deepcopy(action), "idempotency_key": idempotency_key})
        return self.system.apply(action, idempotency_key)


@dataclass
class Executor:
    authority_keys: Mapping[str, PublicKey]
    executor_key: KeyPair
    reservations: ReservationStore
    containment: ContainmentView
    connector: SimulatedConnector

    def __post_init__(self) -> None:
        if self.executor_key.key_id in self.authority_keys:
            raise PermitError("authority and executor key roles must be distinct")
        for key_id, key in self.authority_keys.items():
            if key_id != key.key_id:
                raise PermitError("authority key identifier does not match public key")
            if key.raw == self.executor_key.public.raw:
                raise PermitError("authority and executor key material must be distinct")

    def _verify_containment(self, permit: dict[str, Any], state: CampaignState) -> None:
        if self.containment.is_frozen():
            raise PermitError("execution globally frozen")
        if self.containment.is_revoked(str(permit["permit_id"])):
            raise PermitError("permit revoked")
        if self.containment.is_suspended(str(permit["campaign_id"])) or state.status != "ACTIVE":
            raise PermitError("campaign suspended")

    def _verify_permit(
        self,
        permit: dict[str, Any],
        proposal: dict[str, Any],
        signed_policy: dict[str, Any],
        evidence: list[dict[str, Any]],
        decision: dict[str, Any],
        state: CampaignState,
        seq: int,
    ) -> None:
        policy = signed_policy.get("policy")
        if not isinstance(policy, dict):
            raise PermitError("signed policy artifact malformed")
        if permit.get("schema_version") != "claimsieve.permit.v1":
            raise PermitError("unsupported permit schema")
        unsigned = {key: value for key, value in permit.items() if key != "signature"}
        authority = self.authority_keys.get(permit.get("authority_key_id"))
        if authority is None or not authority.verify(
            "permit-v1", unsigned, str(permit.get("signature", ""))
        ):
            raise PermitError("permit signature invalid")
        self._verify_containment(permit, state)
        if not (permit["valid_from_seq"] <= seq <= permit["expires_at_seq"]):
            raise PermitError("permit outside validity sequence")
        if decision.get("verdict") != "ALLOW":
            raise PermitError("decision is not executable")
        expected = {
            "trace_id": proposal["trace_id"],
            "tenant_id": proposal["tenant_id"],
            "campaign_id": proposal["campaign_id"],
            "principal": proposal["principal"],
            "proposal_digest": proposal_digest(proposal),
            "action_digest": action_digest(proposal),
            "destination_digest": destination_digest(proposal),
            "parameter_digest": parameter_digest(proposal),
            "policy_digest": digest(policy),
            "signed_policy_digest": digest(signed_policy),
            "evidence_root": evidence_root(evidence),
            "decision_digest": digest(decision),
            "approval_digest": approval_digest(proposal),
            "prior_campaign_state_digest": decision.get("prior_campaign_state_digest"),
            "campaign_state_digest": digest(state.as_canonical()),
            "valid_from_seq": decision.get("decided_at_seq"),
            "max_uses": 1,
        }
        for field_name, expected_value in expected.items():
            if permit.get(field_name) != expected_value:
                raise PermitError(f"permit binding mismatch: {field_name}")

    def execute(
        self,
        permit: dict[str, Any],
        proposal: dict[str, Any],
        signed_policy: dict[str, Any],
        evidence: list[dict[str, Any]],
        decision: dict[str, Any],
        state: CampaignState,
        seq: int,
    ) -> dict[str, Any]:
        self._verify_permit(permit, proposal, signed_policy, evidence, decision, state, seq)
        reservation = self.reservations.reserve(str(permit["permit_id"]), str(permit["action_digest"]), seq)
        if reservation is None:
            raise PermitError("permit replay or concurrent duplicate")
        self._verify_containment(permit, state)
        provider = self.connector.invoke(proposal["action"], str(permit["permit_id"]))
        unsigned = {
            "schema_version": "claimsieve.executor_receipt.v1",
            "trace_id": proposal["trace_id"],
            "campaign_id": proposal["campaign_id"],
            "permit_id": permit["permit_id"],
            "reservation_id": reservation["reservation_id"],
            "action_digest": action_digest(proposal),
            "provider_status": provider["status"],
            "provider_id": provider["provider_id"],
            "attempted_at_seq": seq,
            "executor_key_id": self.executor_key.key_id,
        }
        receipt = {**unsigned, "signature": self.executor_key.sign("executor-receipt-v1", unsigned)}
        return {
            "reservation": reservation,
            "executor_receipt": receipt,
            "automatic_retry_allowed": False,
        }


@dataclass
class Observer:
    observer_key: KeyPair
    executor_keys: Mapping[str, PublicKey]
    system: SimulatedExternalSystem

    def __post_init__(self) -> None:
        if self.observer_key.key_id in self.executor_keys:
            raise PermitError("executor and observer key roles must be distinct")
        if any(key.raw == self.observer_key.public.raw for key in self.executor_keys.values()):
            raise PermitError("executor and observer key material must be distinct")

    def observe(
        self,
        permit: dict[str, Any],
        proposal: dict[str, Any],
        executor_receipt: dict[str, Any],
        seq: int,
    ) -> dict[str, Any]:
        unsigned_executor = {
            key: value for key, value in executor_receipt.items() if key != "signature"
        }
        executor_key = self.executor_keys.get(executor_receipt.get("executor_key_id"))
        if executor_key is None or not executor_key.verify(
            "executor-receipt-v1",
            unsigned_executor,
            str(executor_receipt.get("signature", "")),
        ):
            raise PermitError("executor receipt signature invalid")
        if executor_receipt.get("permit_id") != permit.get("permit_id"):
            raise PermitError("executor receipt permit mismatch")
        observed = self.system.observe(str(permit["permit_id"]))
        provider_status = executor_receipt.get("provider_status")
        if observed is None and provider_status == "rejected":
            reconciliation = "CONFIRMED_FAILURE"
        elif observed is None:
            reconciliation = "OUTCOME_UNKNOWN"
        elif digest(observed) != digest(proposal["action"]):
            reconciliation = "DIVERGENT_EFFECT"
        else:
            reconciliation = "CONFIRMED_SUCCESS"
        unsigned = {
            "schema_version": "claimsieve.observer_receipt.v1",
            "trace_id": proposal["trace_id"],
            "campaign_id": proposal["campaign_id"],
            "permit_id": permit["permit_id"],
            "executor_receipt_digest": digest(executor_receipt),
            "observed_action_digest": digest(observed) if observed is not None else None,
            "reconciliation": reconciliation,
            "observed_at_seq": seq,
            "observer_key_id": self.observer_key.key_id,
        }
        return {**unsigned, "signature": self.observer_key.sign("observer-receipt-v1", unsigned)}
