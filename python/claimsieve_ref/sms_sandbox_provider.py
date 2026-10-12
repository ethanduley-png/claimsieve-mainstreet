"""No-send SMS adapter exercising the existing durable ClaimSieve provider boundary.

This module has no network or SMS dependency. It is NOT a provider integration,
independent observer host, or permission issuer. It uses the durable simulator
to make the second action surface exercise real reservation and recovery rules.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable

from .durable_state import DispatchTicket, DurableProviderSimulator, DurableStateError

_E164 = re.compile(r"^\+[1-9][0-9]{7,14}$")
_ACTION_FIELDS = frozenset({"kind", "effect_class", "destination", "method", "parameters", "reversibility"})
_DEST_FIELDS = frozenset({"scheme", "authority", "resource", "trust_domain"})
_PARAM_FIELDS = frozenset({"body"})


class SMSBoundaryError(DurableStateError):
    """A request tried to leave the narrow no-send messaging boundary."""


class SandboxSMSProvider:
    """Durable reference adapter, explicitly incapable of network egress."""

    def __init__(
        self,
        path: str | Path,
        *,
        allowed_recipients: Iterable[str],
        allowed_resources: Iterable[str],
    ) -> None:
        recipients = frozenset(allowed_recipients)
        if not recipients or any(not isinstance(item, str) or not _E164.fullmatch(item) for item in recipients):
            raise SMSBoundaryError("explicit E.164 recipient allowlist required")
        resources = frozenset(allowed_resources)
        if not resources or any(type(value) is not str or not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", value) for value in resources):
            raise SMSBoundaryError("explicit bounded lead resource allowlist required")
        self._recipients = recipients
        self._resources = resources
        # Durable test backend, NOT a transport or external SMS provider.
        self._simulator = DurableProviderSimulator(path, mode="success")

    def _validate(self, action: dict[str, Any]) -> None:
        if type(action) is not dict or set(action) != _ACTION_FIELDS:
            raise SMSBoundaryError("unexpected SMS action structure")
        dest = action["destination"]
        params = action["parameters"]
        if type(dest) is not dict or set(dest) != _DEST_FIELDS:
            raise SMSBoundaryError("invalid SMS destination structure")
        if type(params) is not dict or set(params) != _PARAM_FIELDS:
            raise SMSBoundaryError("unexpected SMS parameter structure")
        if (
            action["kind"] != "send_message"
            or action["effect_class"] != "external_write"
            or action["method"] != "SEND"
            or action["reversibility"] != "irreversible"
            or dest["scheme"] != "sms"
            or dest["resource"] not in self._resources
            or dest["trust_domain"] != "sms-provider"
        ):
            raise SMSBoundaryError("action not permitted by SMS sandbox contract")
        if type(dest["authority"]) is not str or dest["authority"] not in self._recipients:
            raise SMSBoundaryError("recipient not allowlisted")
        body = params["body"]
        if (
            type(body) is not str or not (1 <= len(body) <= 1000)
            or any(ord(c) < 32 and c not in "\n" for c in body)
            or "\x7f" in body
        ):
            raise SMSBoundaryError("invalid SMS message body")

    def invoke(self, action: dict[str, Any], ticket: DispatchTicket) -> dict[str, Any]:
        self._validate(action)
        if not isinstance(ticket, DispatchTicket) or not ticket.idempotency_key:
            raise SMSBoundaryError("verified dispatch ticket required")
        # An existing key must NEVER silently replay a modified message.
        existing = self._simulator.query(ticket.idempotency_key)
        if existing is not None and existing.get("effect") != action:
            raise SMSBoundaryError("idempotency key rebound to different SMS payload")
        return self._simulator.invoke(action, ticket)

    def query(self, idempotency_key: str) -> dict[str, Any] | None:
        # Read-only observation of separate simulated provider state.
        return self._simulator.query(idempotency_key)
