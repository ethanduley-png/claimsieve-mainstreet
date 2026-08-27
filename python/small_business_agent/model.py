from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class BusinessDomain(str, Enum):
    EXECUTIVE = "executive"
    COMMUNICATIONS = "communications"
    SALES_CRM = "sales_crm"
    CUSTOMER_SERVICE = "customer_service"
    MARKETING = "marketing"
    SCHEDULING = "scheduling"
    FINANCE_ADMIN = "finance_admin"
    PURCHASING = "purchasing"
    PEOPLE = "people"
    COMPLIANCE = "compliance"
    KNOWLEDGE = "knowledge"
    PROJECTS = "projects"
    ANALYTICS = "analytics"
    INVENTORY_OPERATIONS = "inventory_operations"
    IT_SECURITY = "it_security"
    WEB_COMMERCE = "web_commerce"
    STRATEGY = "strategy"
    FOUNDER_PERSONAL = "founder_personal"


class ActionRisk(str, Enum):
    INFORMATIONAL = "informational"
    INTERNAL_REVERSIBLE = "internal_reversible"
    EXTERNAL_COMMUNICATION = "external_communication"
    COMMERCIAL_COMMITMENT = "commercial_commitment"
    FINANCIAL = "financial"
    LEGAL_COMPLIANCE = "legal_compliance"
    EMPLOYMENT = "employment"
    HEALTH_SAFETY = "health_safety"
    CREDENTIAL_SECURITY = "credential_security"
    IRREVERSIBLE_HIGH_IMPACT = "irreversible_high_impact"


@dataclass(frozen=True)
class Intent:
    text: str
    tenant_id: str
    principal_id: str
    context: dict[str, Any] = field(default_factory=dict)

    def validate(self) -> None:
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("intent text must be non-empty")
        if not isinstance(self.tenant_id, str) or not self.tenant_id.strip():
            raise ValueError("tenant_id must be non-empty")
        if not isinstance(self.principal_id, str) or not self.principal_id.strip():
            raise ValueError("principal_id must be non-empty")


@dataclass(frozen=True)
class ProposedWorkItem:
    capability_id: str
    domain: BusinessDomain
    risk: ActionRisk
    description: str
    consequential: bool
    requires_claimsieve: bool
    requires_human_approval: bool
    suggested_inputs: tuple[str, ...] = ()
    expected_output: str = ""


@dataclass(frozen=True)
class WorkPlan:
    intent: Intent
    domains: tuple[BusinessDomain, ...]
    items: tuple[ProposedWorkItem, ...]
    assumptions: tuple[str, ...] = ()
    missing_context: tuple[str, ...] = ()

    @property
    def consequential_items(self) -> tuple[ProposedWorkItem, ...]:
        return tuple(item for item in self.items if item.consequential)

    @property
    def requires_claimsieve(self) -> bool:
        return any(item.requires_claimsieve for item in self.items)
