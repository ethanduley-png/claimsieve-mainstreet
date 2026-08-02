"""Deliberately faulty implementations used to verify test discrimination."""
from __future__ import annotations

from typing import Any


def permit_matches_ignoring_destination(permit: dict[str, Any], proposal: dict[str, Any]) -> bool:
    """FAULT: treats permit ID as sufficient and ignores exact action binding."""
    return permit.get("campaign_id") == proposal.get("campaign_id")


class ReplayableReservationStore:
    """FAULT: every reservation succeeds."""

    def reserve(self, permit_id: str, action_digest: str, seq: int) -> dict[str, Any]:
        return {"permit_id": permit_id, "action_digest": action_digest, "reserved_at_seq": seq}


def reset_campaign_on_new_session(state: dict[str, Any], session_id: str) -> dict[str, Any]:
    """FAULT: resets counters when the process/session changes."""
    if session_id not in state.get("sessions", []):
        return {"campaign_id": state["campaign_id"], "total_actions": 0, "sessions": [session_id]}
    return state


def unknown_means_retryable(provider_status: str) -> bool:
    """FAULT: retries an ambiguous operation."""
    return provider_status in {"rejected", "timeout_unknown"}
