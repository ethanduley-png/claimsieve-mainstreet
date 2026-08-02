from __future__ import annotations

"""Provider-contract models for unknown-outcome testing.

These models are not provider SDKs and perform no network calls. They encode
specific, cited provider guarantees as executable conformance fixtures so the
ClaimSieve boundary can be tested against a real published contract without
using credentials or causing external effects.
"""

from dataclasses import dataclass
from typing import Any, Literal


STRIPE_CONTRACT_ID = "stripe-api-v1-idempotency-2026-08-01"
STRIPE_MINIMUM_SAFE_RETENTION_SECONDS = 24 * 60 * 60


class ProviderContractError(ValueError):
    """The requested replay violates the modeled provider contract."""


@dataclass(frozen=True)
class ReplayContext:
    """Inputs required to authorize one transport replay of the same dispatch."""

    outcome_unknown: bool
    same_reservation: bool
    same_idempotency_key: bool
    same_request_digest: bool
    same_endpoint: bool
    same_account: bool
    authority_active: bool
    provider_supports_idempotent_post: bool
    elapsed_seconds: int
    replay_count: int
    replay_limit: int = 2


@dataclass(frozen=True)
class ReplayDecision:
    allowed: bool
    reason: str
    creates_new_logical_attempt: bool = False


def authorize_stripe_transport_replay(context: ReplayContext) -> ReplayDecision:
    """Authorize only a byte-identical continuation of an existing dispatch.

    This never authorizes a new logical action. It permits the same POST to be
    resent with the same idempotency key only while the documented Stripe
    retention guarantee is conservatively treated as active and current
    ClaimSieve authority has not been revoked or frozen.
    """

    checks = (
        (context.outcome_unknown, "outcome is not unknown"),
        (context.same_reservation, "reservation changed"),
        (context.same_idempotency_key, "idempotency key changed"),
        (context.same_request_digest, "request digest changed"),
        (context.same_endpoint, "endpoint changed"),
        (context.same_account, "provider account changed"),
        (context.authority_active, "authority is revoked, suspended, or frozen"),
        (
            context.provider_supports_idempotent_post,
            "provider contract does not guarantee idempotent POST replay",
        ),
        (context.elapsed_seconds >= 0, "negative elapsed time"),
        (
            context.elapsed_seconds < STRIPE_MINIMUM_SAFE_RETENTION_SECONDS,
            "idempotency retention window is no longer guaranteed",
        ),
        (context.replay_count < context.replay_limit, "transport replay budget exhausted"),
    )
    for passed, reason in checks:
        if not passed:
            return ReplayDecision(False, reason)
    return ReplayDecision(True, "exact same-dispatch transport replay permitted")


@dataclass(frozen=True)
class ContractResponse:
    transport: Literal["response", "network_error"]
    status_code: int | None
    body: dict[str, Any] | None
    idempotent_replay: bool
    effect_count: int


@dataclass
class _StoredResult:
    endpoint: str
    request_digest: str
    saved_at_seconds: int
    status_code: int
    body: dict[str, Any]


class StripeIdempotencyContractModel:
    """Deterministic model of Stripe's documented POST idempotency semantics.

    Modeled facts:
    * the first result is cached after endpoint execution begins, including 500;
    * exact same-key/same-parameter replays return that result;
    * same-key parameter or endpoint mutation is rejected;
    * validation/pre-execution failures are not cached;
    * keys may be pruned after at least 24 hours, after which reuse can execute
      a new request.
    """

    def __init__(self) -> None:
        self._stored: dict[str, _StoredResult] = {}
        self.effect_count = 0

    def _existing(
        self, idempotency_key: str, endpoint: str, request_digest: str, now_seconds: int
    ) -> _StoredResult | None:
        stored = self._stored.get(idempotency_key)
        if stored is None:
            return None
        age = now_seconds - stored.saved_at_seconds
        if age < 0:
            raise ProviderContractError("provider time moved backwards")
        if age >= STRIPE_MINIMUM_SAFE_RETENTION_SECONDS:
            del self._stored[idempotency_key]
            return None
        if stored.endpoint != endpoint or stored.request_digest != request_digest:
            raise ProviderContractError("idempotency key reused with different endpoint or parameters")
        return stored

    def post(
        self,
        *,
        idempotency_key: str,
        endpoint: str,
        request_digest: str,
        now_seconds: int,
        scenario: Literal[
            "success",
            "commit_then_connection_drop",
            "server_500_with_effect",
            "validation_error",
        ] = "success",
    ) -> ContractResponse:
        if not idempotency_key or len(idempotency_key) > 255:
            raise ProviderContractError("invalid idempotency key")
        existing = self._existing(idempotency_key, endpoint, request_digest, now_seconds)
        if existing is not None:
            return ContractResponse(
                transport="response",
                status_code=existing.status_code,
                body=dict(existing.body),
                idempotent_replay=True,
                effect_count=self.effect_count,
            )

        if scenario == "validation_error":
            return ContractResponse(
                transport="response",
                status_code=400,
                body={"error": "invalid_request"},
                idempotent_replay=False,
                effect_count=self.effect_count,
            )

        self.effect_count += 1
        object_id = f"obj_{self.effect_count}"
        if scenario == "server_500_with_effect":
            status_code = 500
            body = {"error": "api_error", "possible_object_id": object_id}
        else:
            status_code = 200
            body = {"id": object_id, "status": "created"}
        self._stored[idempotency_key] = _StoredResult(
            endpoint=endpoint,
            request_digest=request_digest,
            saved_at_seconds=now_seconds,
            status_code=status_code,
            body=dict(body),
        )
        if scenario == "commit_then_connection_drop":
            return ContractResponse(
                transport="network_error",
                status_code=None,
                body=None,
                idempotent_replay=False,
                effect_count=self.effect_count,
            )
        return ContractResponse(
            transport="response",
            status_code=status_code,
            body=body,
            idempotent_replay=False,
            effect_count=self.effect_count,
        )
