from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Mapping

from founder_os import FounderActionResult, FounderOSReferenceWorkflow, GitHubIssueRequest, PreparedFounderAction


class ClaimSieveIntakeError(ValueError):
    """Raised when a proposal-runtime intent cannot enter the ClaimSieve path."""


@dataclass
class _PendingAction:
    prepared: PreparedFounderAction
    execution_started: bool = False


class DeepAgentsFounderIntake:
    """Reference intake from Deep Agents intent to the existing Founder OS authority.

    This is a composition test boundary, not a production deployment topology.
    It uses the existing FounderOSReferenceWorkflow to prove that a runtime intent
    can reach the one active ClaimSieve permit authority without executing the
    provider inside the Deep Agents middleware call.

    Replay/pending state is process-local. The lock below closes same-process
    concurrent admission races; restart-durable intake identity remains an
    explicit non-production limitation.
    """

    INTENT_SCHEMA = "mainstreet.consequential_tool_intent.v1"
    SUPPORTED_RUNTIME = "deepagents"
    SUPPORTED_RUNTIME_VERSION = "0.7.9"
    SUPPORTED_TOOL = "create_github_issue"
    REQUIRED_ARGUMENTS = frozenset({"repository", "title", "body"})
    REQUIRED_CONTEXT = frozenset(
        {"trace_id", "campaign_id", "session_id", "work_item_id", "requested_at_seq"}
    )

    def __init__(self, workflow: FounderOSReferenceWorkflow) -> None:
        profile = getattr(workflow, "runtime_profile", None)
        if profile is None or profile.runtime_name != self.SUPPORTED_RUNTIME:
            raise ClaimSieveIntakeError(
                "Deep Agents intake requires a Founder OS workflow bound to the deepagents principal"
            )
        try:
            profile.validate()
        except ValueError as exc:
            raise ClaimSieveIntakeError("Deep Agents runtime profile is invalid") from exc
        if profile.runtime_version != self.SUPPORTED_RUNTIME_VERSION:
            raise ClaimSieveIntakeError(
                "Deep Agents intake runtime version does not match the pinned adapter version"
            )
        self._workflow = workflow
        self._runtime_profile = profile
        self._pending: dict[str, _PendingAction] = {}
        self._seen_tool_calls: set[str] = set()
        self._lock = threading.RLock()

    @staticmethod
    def _exact_mapping(value: Any, name: str) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise ClaimSieveIntakeError(f"{name} must be a mapping")
        return value

    @staticmethod
    def _nonempty_string(value: Any, name: str, maximum: int) -> str:
        if not isinstance(value, str) or not value or len(value) > maximum:
            raise ClaimSieveIntakeError(
                f"{name} must be a non-empty string of at most {maximum} characters"
            )
        return value

    def _request_from_intent(self, intent: Mapping[str, Any]) -> GitHubIssueRequest:
        if intent.get("schema_version") != self.INTENT_SCHEMA:
            raise ClaimSieveIntakeError("unsupported runtime intent schema")
        if intent.get("runtime") != self.SUPPORTED_RUNTIME:
            raise ClaimSieveIntakeError("runtime identity mismatch")
        if intent.get("tool_name") != self.SUPPORTED_TOOL:
            raise ClaimSieveIntakeError("unsupported consequential tool")

        tool_call_id = self._nonempty_string(intent.get("tool_call_id"), "tool_call_id", 110)
        if tool_call_id in self._seen_tool_calls:
            raise ClaimSieveIntakeError("duplicate Deep Agents tool call identity")

        arguments = self._exact_mapping(intent.get("arguments"), "arguments")
        if frozenset(arguments) != self.REQUIRED_ARGUMENTS:
            raise ClaimSieveIntakeError("GitHub issue arguments must be exactly repository, title, and body")

        context = self._exact_mapping(intent.get("context"), "context")
        if frozenset(context) != self.REQUIRED_CONTEXT:
            raise ClaimSieveIntakeError("runtime context fields do not match the required schema")

        requested_at_seq = context.get("requested_at_seq")
        if isinstance(requested_at_seq, bool) or not isinstance(requested_at_seq, int) or requested_at_seq < 0:
            raise ClaimSieveIntakeError("requested_at_seq must be a non-negative integer")

        return GitHubIssueRequest(
            proposal_id=f"deepagents-{tool_call_id}",
            trace_id=self._nonempty_string(context.get("trace_id"), "trace_id", 128),
            campaign_id=self._nonempty_string(context.get("campaign_id"), "campaign_id", 128),
            session_id=self._nonempty_string(context.get("session_id"), "session_id", 128),
            work_item_id=self._nonempty_string(context.get("work_item_id"), "work_item_id", 256),
            repository=self._nonempty_string(arguments.get("repository"), "repository", 201),
            title=self._nonempty_string(arguments.get("title"), "title", 180),
            body=self._nonempty_string(arguments.get("body"), "body", 20_000),
            requested_at_seq=requested_at_seq,
        )

    def route_intent(self, intent: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            request = self._request_from_intent(intent)
            prepared = self._workflow.prepare_issue(request)
            if prepared.proposal.get("principal") != self._runtime_profile.principal:
                raise ClaimSieveIntakeError("prepared proposal principal is not bound to Deep Agents")
            if prepared.permit.get("principal") != self._runtime_profile.principal:
                raise ClaimSieveIntakeError("issued permit principal is not bound to Deep Agents")
            runtime_identity = prepared.proposal.get("runtime_identity")
            if runtime_identity != self._runtime_profile.binding():
                raise ClaimSieveIntakeError("prepared proposal runtime identity binding mismatch")

            permit_id = str(prepared.permit["permit_id"])
            if permit_id in self._pending:
                raise ClaimSieveIntakeError("duplicate permit identity")
            self._seen_tool_calls.add(str(intent["tool_call_id"]))
            self._pending[permit_id] = _PendingAction(prepared=prepared)
            return {
                "schema_version": "mainstreet.claimsieve_intake_receipt.v1",
                "status": "PERMIT_ISSUED_EXECUTION_PENDING",
                "permit_id": permit_id,
                "proposal_id": request.proposal_id,
                "runtime_name": self._runtime_profile.runtime_name,
                "runtime_version": self._runtime_profile.runtime_version,
                "runtime_principal": self._runtime_profile.principal,
                "runtime_manifest_digest": self._runtime_profile.runtime_manifest_digest,
                "proposal_digest": prepared.permit["proposal_digest"],
                "action_digest": prepared.permit["action_digest"],
                "destination_digest": prepared.permit["destination_digest"],
                "parameter_digest": prepared.permit["parameter_digest"],
                "expires_at_seq": prepared.permit["expires_at_seq"],
                "external_action_executed": False,
            }

    def execute_pending(self, permit_id: str, execute_seq: int, observe_seq: int) -> FounderActionResult:
        with self._lock:
            pending = self._pending.get(permit_id)
            if pending is None:
                raise ClaimSieveIntakeError("unknown pending permit")
            if pending.execution_started:
                raise ClaimSieveIntakeError("pending permit execution already started")
            pending.execution_started = True
        return self._workflow.execute_issue(pending.prepared, execute_seq, observe_seq)

    def pending_permits(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._pending))
