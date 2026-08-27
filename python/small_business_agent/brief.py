from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .brain import BusinessSignal, BusinessSnapshot


@dataclass(frozen=True)
class BriefItem:
    signal_id: str
    title: str
    priority: int
    bucket: str
    why_now: str
    founder_needed: bool


@dataclass(frozen=True)
class FounderBrief:
    as_of: date
    needs_founder: tuple[BriefItem, ...]
    agent_can_handle: tuple[BriefItem, ...]
    watch: tuple[BriefItem, ...]
    data_warnings: tuple[str, ...]

    @property
    def total_attention_items(self) -> int:
        return len(self.needs_founder) + len(self.agent_can_handle)


def _bucket(signal: BusinessSignal) -> str:
    founder_kinds = {
        "money_movement",
        "refund",
        "pricing_commitment",
        "legal_deadline",
        "employment_decision",
        "credential_change",
        "safety_incident",
    }
    agent_kinds = {
        "lead_followup",
        "customer_followup",
        "draft_response",
        "task_overdue",
        "document_missing",
        "inventory_attention",
        "calendar_conflict",
    }
    if signal.kind in founder_kinds or signal.severity >= 4:
        return "founder"
    if signal.kind in agent_kinds or signal.severity >= 3:
        return "agent"
    return "watch"


def _why_now(signal: BusinessSignal, today: date) -> str:
    if signal.due_date is not None:
        days = (signal.due_date - today).days
        if days < 0:
            return f"overdue by {abs(days)} day(s)"
        if days == 0:
            return "due today"
        return f"due in {days} day(s)"
    if signal.amount is not None:
        return f"${signal.amount:,.2f} at stake"
    return f"severity {signal.severity}/5"


def build_founder_brief(snapshot: BusinessSnapshot) -> FounderBrief:
    snapshot.validate()
    founder: list[BriefItem] = []
    agent: list[BriefItem] = []
    watch: list[BriefItem] = []

    for signal in sorted(snapshot.signals, key=lambda s: (-s.severity, s.due_date or date.max, s.signal_id)):
        bucket = _bucket(signal)
        item = BriefItem(
            signal_id=signal.signal_id,
            title=signal.title,
            priority=signal.severity,
            bucket=bucket,
            why_now=_why_now(signal, snapshot.as_of),
            founder_needed=bucket == "founder",
        )
        if bucket == "founder":
            founder.append(item)
        elif bucket == "agent":
            agent.append(item)
        else:
            watch.append(item)

    warnings = tuple(f"stale source: {source}" for source in sorted(set(snapshot.stale_sources)))
    return FounderBrief(snapshot.as_of, tuple(founder), tuple(agent), tuple(watch), warnings)
