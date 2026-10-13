from __future__ import annotations

from dataclasses import dataclass

from .model import ActionRisk, BusinessDomain, Intent
from .planner import plan_intent


@dataclass(frozen=True)
class InboxMessage:
    message_id: str
    channel: str
    sender: str
    subject: str
    body: str

    def validate(self) -> None:
        if not self.message_id or not self.channel or not self.sender:
            raise ValueError("message_id, channel, and sender are required")
        if not (self.subject.strip() or self.body.strip()):
            raise ValueError("message must contain subject or body")


@dataclass(frozen=True)
class InboxTriage:
    message_id: str
    domains: tuple[BusinessDomain, ...]
    risks: tuple[ActionRisk, ...]
    requires_claimsieve: bool
    requires_human_approval: bool
    summary: str


def triage_message(message: InboxMessage, tenant_id: str, principal_id: str) -> InboxTriage:
    message.validate()
    text = " ".join(part for part in (message.subject.strip(), message.body.strip()) if part)
    plan = plan_intent(Intent(text=text, tenant_id=tenant_id, principal_id=principal_id, context={"channel": message.channel, "sender": message.sender}))
    risks = tuple(dict.fromkeys(item.risk for item in plan.items))
    requires_human = any(item.requires_human_approval for item in plan.items)
    summary = text if len(text) <= 240 else text[:237].rstrip() + "..."
    return InboxTriage(
        message_id=message.message_id,
        domains=plan.domains,
        risks=risks,
        requires_claimsieve=plan.requires_claimsieve,
        requires_human_approval=requires_human,
        summary=summary,
    )
