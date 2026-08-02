from __future__ import annotations

import copy
from typing import Any, Iterable

from .canonical import digest


def proposal_for_approval(proposal: dict[str, Any]) -> dict[str, Any]:
    subject = copy.deepcopy(proposal)
    subject["approval"] = None
    return subject


def proposal_digest(proposal: dict[str, Any]) -> str:
    return digest(proposal_for_approval(proposal))


def display_digest(proposal: dict[str, Any]) -> str:
    return digest(
        {
            "tenant_id": proposal["tenant_id"],
            "campaign_id": proposal["campaign_id"],
            "objective": proposal["objective"],
            "action": proposal["action"],
            "risk_tags": proposal["risk_tags"],
        }
    )


def action_digest(proposal: dict[str, Any]) -> str:
    return digest(
        {
            "tenant_id": proposal["tenant_id"],
            "campaign_id": proposal["campaign_id"],
            "principal": proposal["principal"],
            "objective": proposal["objective"],
            "action": proposal["action"],
        }
    )


def destination_digest(proposal: dict[str, Any]) -> str:
    return digest(proposal["action"]["destination"])


def parameter_digest(proposal: dict[str, Any]) -> str:
    return digest(proposal["action"]["parameters"])


def approval_signing_subject(approval: dict[str, Any]) -> dict[str, Any]:
    subject = copy.deepcopy(approval)
    subject.pop("signature", None)
    return subject


def approval_digest(proposal: dict[str, Any]) -> str | None:
    approval = proposal.get("approval")
    return digest(approval) if approval is not None else None


def evidence_root(evidence: Iterable[dict[str, Any]]) -> str:
    leaves = sorted(digest(item) for item in evidence)
    return digest({"algorithm": "claimsieve.sorted-digest-root.v1", "leaves": leaves})
