from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import date
from typing import Any, Iterable


@dataclass(frozen=True)
class BusinessSignal:
    signal_id: str
    kind: str
    title: str
    severity: int
    source: str
    due_date: date | None = None
    amount: float | None = None
    customer_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.signal_id or not self.kind or not self.title or not self.source:
            raise ValueError("signal identity, kind, title, and source are required")
        if isinstance(self.severity, bool) or not isinstance(self.severity, int) or not 0 <= self.severity <= 5:
            raise ValueError("severity must be an integer from 0 to 5")
        if self.amount is not None:
            if isinstance(self.amount, bool) or not isinstance(self.amount, (int, float)) or not math.isfinite(float(self.amount)):
                raise ValueError("amount must be a finite number")
            if self.amount < 0:
                raise ValueError("amount cannot be negative")


@dataclass(frozen=True)
class BusinessProfile:
    tenant_id: str
    legal_name: str
    display_name: str
    business_type: str
    timezone: str
    locations: tuple[str, ...] = ()
    owner_ids: tuple[str, ...] = ()

    def validate(self) -> None:
        for name, value in {
            "tenant_id": self.tenant_id,
            "legal_name": self.legal_name,
            "display_name": self.display_name,
            "business_type": self.business_type,
            "timezone": self.timezone,
        }.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be non-empty")


@dataclass(frozen=True)
class BusinessSnapshot:
    profile: BusinessProfile
    as_of: date
    signals: tuple[BusinessSignal, ...] = ()
    metrics: dict[str, float] = field(default_factory=dict)
    open_work: tuple[str, ...] = ()
    stale_sources: tuple[str, ...] = ()

    def validate(self) -> None:
        self.profile.validate()
        if not isinstance(self.as_of, date):
            raise ValueError("as_of must be a date")
        for name, value in self.metrics.items():
            if not isinstance(name, str) or not name.strip():
                raise ValueError("metric names must be non-empty")
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise ValueError(f"metric {name} must be a finite number")
        seen: set[str] = set()
        for signal in self.signals:
            signal.validate()
            if signal.signal_id in seen:
                raise ValueError("duplicate signal_id")
            seen.add(signal.signal_id)

    def by_kind(self, kind: str) -> tuple[BusinessSignal, ...]:
        return tuple(s for s in self.signals if s.kind == kind)

    def high_attention(self, threshold: int = 3) -> tuple[BusinessSignal, ...]:
        return tuple(sorted((s for s in self.signals if s.severity >= threshold), key=lambda s: (-s.severity, s.due_date or date.max, s.signal_id)))


def merge_signals(*groups: Iterable[BusinessSignal]) -> tuple[BusinessSignal, ...]:
    by_id: dict[str, BusinessSignal] = {}
    for group in groups:
        for signal in group:
            signal.validate()
            existing = by_id.get(signal.signal_id)
            if existing is not None and existing != signal:
                raise ValueError(f"conflicting signal_id: {signal.signal_id}")
            by_id[signal.signal_id] = signal
    return tuple(sorted(by_id.values(), key=lambda s: s.signal_id))
