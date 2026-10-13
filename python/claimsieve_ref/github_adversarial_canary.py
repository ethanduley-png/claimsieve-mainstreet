"""Offline GitHub adversarial canary; never trusts agent/tool transcripts for finality.

Caller supplies a previously VERIFIED action and dispatch ticket. This is not a
permit issuer or substitute for ClaimSieve's production dispatch boundary.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .canonical import digest
from .durable_state import DispatchTicket
from .github_provider import GitHubIssueProvider, GitHubProviderError


class CanaryConfigurationError(ValueError):
    """No trusted action or read-only observation boundary."""


@dataclass(frozen=True)
class CanaryFinding:
    outcome: str
    reason: str
    expected_action_digest: str
    observed_action_digest: str | None = None
    provider_id: str | None = None
    executor_claim_conflict: bool = False
    automatic_retry_allowed: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class GitHubAdversarialCanary:
    """Check an attempted action, then reconcile via GitHub read-only evidence.

    Call allow_attempt only within the trusted dispatch boundary. observe() is
    side-effect-free and ignores the agent's alleged execution result.
    """

    def __init__(
        self,
        *,
        approved_action: Mapping[str, Any],
        approved_action_digest: str,
        ticket: DispatchTicket,
        observer: GitHubIssueProvider,
    ) -> None:
        if not isinstance(approved_action, Mapping):
            raise CanaryConfigurationError("approved action is missing")
        try:
            expected = digest(dict(approved_action))
        except (TypeError, ValueError) as exc:
            raise CanaryConfigurationError("approved action is invalid") from exc
        if expected != approved_action_digest:
            raise CanaryConfigurationError("approval action digest mismatch")
        if not isinstance(ticket, DispatchTicket) or not ticket.idempotency_key:
            raise CanaryConfigurationError("trusted dispatch ticket is required")
        if not isinstance(observer, GitHubIssueProvider) or observer._write_token is not None:
            raise CanaryConfigurationError("observer must be a read-only GitHub provider")
        destination = approved_action.get("destination")
        repository = destination.get("authority") if isinstance(destination, dict) else None
        if not isinstance(repository, str) or observer.allowed_repositories != frozenset({repository}):
            raise CanaryConfigurationError("observer repository scope must match approved destination")
        self._action_digest = expected
        self._ticket = ticket
        self._observer = observer

    def allow_attempt(self, attempted_action: Mapping[str, Any]) -> bool:
        """Fail closed on mutation; caller MUST dispatch only when True."""
        try:
            return isinstance(attempted_action, Mapping) and digest(dict(attempted_action)) == self._action_digest
        except (TypeError, ValueError):
            return False

    def observe(self, *, executor_claim: str | None = None) -> CanaryFinding:
        """Only independently read GitHub state may establish positive finality."""
        try:
            record = self._observer.query(self._ticket.idempotency_key)
        except GitHubProviderError:
            record = None
        observed_digest = None
        provider_id = None
        outcome, reason = "OUTCOME_UNKNOWN", "no_complete_independent_provider_evidence"
        if isinstance(record, dict):
            effect = record.get("effect")
            if isinstance(effect, dict):
                try:
                    observed_digest = digest(effect)
                except (TypeError, ValueError):
                    pass
            response = record.get("response")
            matching_binding = (
                record.get("idempotency_key") == self._ticket.idempotency_key
                and record.get("request_digest") == self._ticket.request_digest
                and record.get("action_digest") == self._ticket.action_digest
                and record.get("resource_key") == self._ticket.resource_key
                and type(record.get("fencing_token")) is int
                and record["fencing_token"] == self._ticket.fencing_token
            )
            provider_id = record.get("provider_id")
            verified_positive = (
                matching_binding
                and record.get("status") == "accepted"
                and isinstance(response, dict)
                and response.get("status") == "accepted"
                and isinstance(provider_id, str)
                and bool(provider_id)
                and response.get("provider_id") == provider_id
                and observed_digest is not None
            )
            if verified_positive and observed_digest != self._action_digest:
                outcome, reason = "DIVERGENT_EFFECT", "readback_effect_differs_from_approval"
            elif verified_positive:
                outcome, reason = "CONFIRMED_SUCCESS", "readback_matches_exact_approval_and_ticket"
            else:
                provider_id = None
                reason = "provider_evidence_conflict_or_incomplete_binding"
        conflict = executor_claim is not None and executor_claim != outcome
        return CanaryFinding(
            outcome=outcome,
            reason=reason,
            expected_action_digest=self._action_digest,
            observed_action_digest=observed_digest,
            provider_id=provider_id,
            executor_claim_conflict=conflict,
        )
