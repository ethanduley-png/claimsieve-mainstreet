from __future__ import annotations

from dataclasses import dataclass

from .model import ActionRisk, BusinessDomain


@dataclass(frozen=True)
class Capability:
    capability_id: str
    domain: BusinessDomain
    description: str
    risk: ActionRisk
    consequential: bool
    requires_claimsieve: bool
    requires_human_approval: bool
    keywords: tuple[str, ...]
    suggested_inputs: tuple[str, ...]
    expected_output: str


def _cap(
    capability_id: str,
    domain: BusinessDomain,
    description: str,
    risk: ActionRisk,
    *,
    consequential: bool = False,
    claimsieve: bool = False,
    human: bool = False,
    keywords: tuple[str, ...] = (),
    inputs: tuple[str, ...] = (),
    output: str = "",
) -> Capability:
    if consequential and not claimsieve:
        raise ValueError(f"consequential capability {capability_id} must require ClaimSieve")
    return Capability(
        capability_id=capability_id,
        domain=domain,
        description=description,
        risk=risk,
        consequential=consequential,
        requires_claimsieve=claimsieve,
        requires_human_approval=human,
        keywords=keywords,
        suggested_inputs=inputs,
        expected_output=output,
    )


CAPABILITIES: tuple[Capability, ...] = (
    _cap("founder_daily_brief", BusinessDomain.EXECUTIVE, "Build a prioritized founder brief from current business state.", ActionRisk.INFORMATIONAL, keywords=("today", "attention", "brief", "priority", "priorities"), inputs=("calendar", "inbox", "tasks", "metrics", "open risks"), output="prioritized founder brief"),
    _cap("decision_brief", BusinessDomain.EXECUTIVE, "Structure a business decision with options, evidence, tradeoffs, and open questions.", ActionRisk.INFORMATIONAL, keywords=("decide", "decision", "options", "tradeoff"), inputs=("decision context", "business constraints"), output="decision brief"),
    _cap("inbox_triage", BusinessDomain.COMMUNICATIONS, "Classify and prioritize business communications.", ActionRisk.INFORMATIONAL, keywords=("inbox", "email", "messages", "triage"), inputs=("messages"), output="triaged communication queue"),
    _cap("draft_external_message", BusinessDomain.COMMUNICATIONS, "Draft an external customer, vendor, or partner message.", ActionRisk.EXTERNAL_COMMUNICATION, keywords=("draft", "reply", "respond", "email", "text", "message"), inputs=("thread", "business policy", "recipient context"), output="draft message"),
    _cap("send_external_message", BusinessDomain.COMMUNICATIONS, "Send an externally visible business communication.", ActionRisk.EXTERNAL_COMMUNICATION, consequential=True, claimsieve=True, keywords=("send", "follow up", "reach out", "notify"), inputs=("approved message", "recipient", "channel"), output="provider execution receipt"),
    _cap("lead_pipeline_review", BusinessDomain.SALES_CRM, "Review leads, stale opportunities, next actions, and conversion blockers.", ActionRisk.INFORMATIONAL, keywords=("lead", "leads", "pipeline", "crm", "prospect", "conversion"), inputs=("lead records", "activity history"), output="ranked sales worklist"),
    _cap("create_sales_followup_campaign", BusinessDomain.SALES_CRM, "Prepare a bounded follow-up campaign for eligible leads.", ActionRisk.EXTERNAL_COMMUNICATION, consequential=True, claimsieve=True, human=True, keywords=("follow up", "campaign", "leads", "prospects"), inputs=("eligible leads", "message policy", "campaign limits"), output="governed campaign proposal"),
    _cap("customer_issue_triage", BusinessDomain.CUSTOMER_SERVICE, "Classify customer issues and route sensitive cases for review.", ActionRisk.INFORMATIONAL, keywords=("customer", "complaint", "problem", "support", "refund", "cancel"), inputs=("customer message", "account context", "policy"), output="support disposition"),
    _cap("issue_refund", BusinessDomain.CUSTOMER_SERVICE, "Issue or approve a customer refund.", ActionRisk.FINANCIAL, consequential=True, claimsieve=True, human=True, keywords=("refund", "money back", "credit customer"), inputs=("customer account", "refund policy", "amount", "approval"), output="refund execution receipt"),
    _cap("cancel_customer_service", BusinessDomain.CUSTOMER_SERVICE, "Cancel or materially change a customer membership, subscription, or service entitlement.", ActionRisk.COMMERCIAL_COMMITMENT, consequential=True, claimsieve=True, human=True, keywords=("cancel membership", "cancel subscription", "close membership", "terminate membership", "cancel service"), inputs=("customer account", "cancellation policy", "effective date", "approval"), output="cancellation execution receipt"),
    _cap("health_safety_escalation", BusinessDomain.CUSTOMER_SERVICE, "Escalate health, medical, injury, pregnancy, surgery, medication, pain, or recovery-related customer requests before advice or consequential response.", ActionRisk.HEALTH_SAFETY, consequential=True, claimsieve=True, human=True, keywords=("pain", "injury", "pregnant", "pregnancy", "surgery", "medication", "medical", "recovery", "chest pain"), inputs=("customer message", "applicable safety policy", "human reviewer"), output="human-reviewed safety disposition"),
    _cap("marketing_plan", BusinessDomain.MARKETING, "Build a campaign or content plan tied to business goals.", ActionRisk.INFORMATIONAL, keywords=("marketing", "campaign", "social", "content", "promotion", "ads"), inputs=("goals", "audience", "offers", "performance history"), output="marketing plan"),
    _cap("publish_marketing_content", BusinessDomain.MARKETING, "Publish customer-facing marketing content.", ActionRisk.EXTERNAL_COMMUNICATION, consequential=True, claimsieve=True, keywords=("publish", "post", "social", "website"), inputs=("approved content", "destination", "brand policy"), output="publication receipt"),
    _cap("schedule_review", BusinessDomain.SCHEDULING, "Review calendar, tasks, conflicts, and workload.", ActionRisk.INFORMATIONAL, keywords=("calendar", "schedule", "appointment", "meeting", "reminder", "tasks"), inputs=("calendar", "tasks"), output="schedule plan"),
    _cap("create_external_appointment", BusinessDomain.SCHEDULING, "Create or modify an appointment involving an external party.", ActionRisk.EXTERNAL_COMMUNICATION, consequential=True, claimsieve=True, keywords=("book", "schedule", "reschedule", "appointment", "meeting"), inputs=("attendees", "time", "calendar policy"), output="calendar execution receipt"),
    _cap("cash_awareness_brief", BusinessDomain.FINANCE_ADMIN, "Summarize cash position, receivables, payables, and anomalies without moving money.", ActionRisk.INFORMATIONAL, keywords=("cash", "revenue", "expense", "budget", "invoice", "financial", "money"), inputs=("financial summaries", "receivables", "payables"), output="cash awareness brief"),
    _cap("prepare_invoice", BusinessDomain.FINANCE_ADMIN, "Prepare an invoice for review.", ActionRisk.COMMERCIAL_COMMITMENT, keywords=("invoice", "bill customer"), inputs=("customer", "pricing", "work performed"), output="invoice draft"),
    _cap("send_invoice", BusinessDomain.FINANCE_ADMIN, "Send a binding invoice to a customer.", ActionRisk.COMMERCIAL_COMMITMENT, consequential=True, claimsieve=True, keywords=("send invoice", "issue invoice"), inputs=("approved invoice", "customer", "amount"), output="invoice provider receipt"),
    _cap("move_money", BusinessDomain.FINANCE_ADMIN, "Initiate a payment, transfer, payroll, tax payment, wire, or other movement of funds.", ActionRisk.FINANCIAL, consequential=True, claimsieve=True, human=True, keywords=("pay", "payment", "transfer", "wire", "payroll", "tax payment", "bank"), inputs=("amount", "source", "destination", "purpose", "approval"), output="financial execution receipt"),
    _cap("compare_vendor_quotes", BusinessDomain.PURCHASING, "Compare vendor quotes and recommend an option.", ActionRisk.INFORMATIONAL, keywords=("vendor", "quote", "supplier", "purchase", "buy"), inputs=("quotes", "requirements", "budget"), output="vendor comparison"),
    _cap("place_purchase", BusinessDomain.PURCHASING, "Place an order or make a commercial purchase commitment.", ActionRisk.COMMERCIAL_COMMITMENT, consequential=True, claimsieve=True, human=True, keywords=("order", "purchase", "buy", "reorder"), inputs=("approved vendor", "items", "price", "destination"), output="purchase receipt"),
    _cap("hiring_pipeline", BusinessDomain.PEOPLE, "Coordinate candidates, interviews, and hiring workflow.", ActionRisk.INFORMATIONAL, keywords=("hire", "hiring", "candidate", "interview", "employee", "staff"), inputs=("role", "candidates", "availability"), output="hiring worklist"),
    _cap("employment_decision", BusinessDomain.PEOPLE, "Make or communicate a hiring, termination, compensation, discipline, or similar employment decision.", ActionRisk.EMPLOYMENT, consequential=True, claimsieve=True, human=True, keywords=("terminate", "fire", "salary", "raise", "discipline", "offer job", "hire"), inputs=("employee/candidate record", "policy", "decision", "approval"), output="governed employment proposal"),
    _cap("compliance_deadline_review", BusinessDomain.COMPLIANCE, "Track licenses, insurance, tax, filing, and renewal deadlines.", ActionRisk.INFORMATIONAL, keywords=("license", "renewal", "insurance", "compliance", "filing", "deadline", "tax"), inputs=("compliance calendar", "business profile"), output="compliance deadline list"),
    _cap("submit_regulatory_filing", BusinessDomain.COMPLIANCE, "Submit a tax, regulatory, licensing, or legal filing or attestation.", ActionRisk.LEGAL_COMPLIANCE, consequential=True, claimsieve=True, human=True, keywords=("file", "submit", "attest", "tax return", "license application"), inputs=("filing", "evidence", "authorized signer"), output="filing receipt"),
    _cap("business_knowledge_answer", BusinessDomain.KNOWLEDGE, "Answer a question from authoritative business records and identify the source.", ActionRisk.INFORMATIONAL, keywords=("policy", "procedure", "document", "where", "what is", "knowledge"), inputs=("business knowledge base",), output="grounded answer"),
    _cap("project_review", BusinessDomain.PROJECTS, "Review milestones, blockers, dependencies, and owners.", ActionRisk.INFORMATIONAL, keywords=("project", "milestone", "blocker", "roadmap", "initiative"), inputs=("project state",), output="project status brief"),
    _cap("metric_analysis", BusinessDomain.ANALYTICS, "Analyze business performance and explain changes.", ActionRisk.INFORMATIONAL, keywords=("why", "metric", "conversion", "churn", "utilization", "trend", "analytics"), inputs=("business metrics",), output="analysis with drivers and uncertainty"),
    _cap("inventory_review", BusinessDomain.INVENTORY_OPERATIONS, "Review inventory, stockouts, maintenance, and operational exceptions.", ActionRisk.INFORMATIONAL, keywords=("inventory", "stock", "maintenance", "equipment", "facility"), inputs=("inventory", "assets", "maintenance schedule"), output="operations exception list"),
    _cap("security_access_review", BusinessDomain.IT_SECURITY, "Review business accounts, access, software, and security exceptions.", ActionRisk.INFORMATIONAL, keywords=("security", "access", "account", "password", "credential", "software"), inputs=("system inventory", "access records"), output="security review"),
    _cap("change_access_or_credentials", BusinessDomain.IT_SECURITY, "Grant/revoke access, rotate credentials, or modify authentication/security controls.", ActionRisk.CREDENTIAL_SECURITY, consequential=True, claimsieve=True, human=True, keywords=("grant access", "revoke", "rotate", "password", "credential", "admin"), inputs=("identity", "system", "requested privilege", "approval"), output="security change receipt"),
    _cap("destructive_data_change", BusinessDomain.IT_SECURITY, "Delete, purge, or irreversibly destroy business records or system data.", ActionRisk.IRREVERSIBLE_HIGH_IMPACT, consequential=True, claimsieve=True, human=True, keywords=("delete records", "delete customer", "erase records", "purge", "destroy data"), inputs=("target records", "retention policy", "scope", "approval"), output="destructive-change execution receipt"),
    _cap("web_store_review", BusinessDomain.WEB_COMMERCE, "Review website, listings, catalog, ecommerce, and reputation state.", ActionRisk.INFORMATIONAL, keywords=("website", "store", "ecommerce", "listing", "reviews", "catalog"), inputs=("web/store state",), output="web commerce worklist"),
    _cap("change_price_or_catalog", BusinessDomain.WEB_COMMERCE, "Change a public price, product, service, catalog entry, or offer.", ActionRisk.COMMERCIAL_COMMITMENT, consequential=True, claimsieve=True, human=True, keywords=("change price", "pricing", "catalog", "offer", "product"), inputs=("approved price/catalog change", "destination"), output="commerce change receipt"),
    _cap("strategy_analysis", BusinessDomain.STRATEGY, "Analyze pricing, market, competition, expansion, or new services.", ActionRisk.INFORMATIONAL, keywords=("strategy", "competitor", "market", "expand", "new service", "pricing"), inputs=("business goals", "market evidence", "financial model"), output="strategy brief"),
    _cap("founder_meeting_prep", BusinessDomain.FOUNDER_PERSONAL, "Prepare the founder for meetings, relationships, travel, and business-linked personal obligations.", ActionRisk.INFORMATIONAL, keywords=("prepare me", "meeting prep", "travel", "remember", "relationship"), inputs=("calendar", "contacts", "notes"), output="founder prep brief"),
)


BY_ID = {cap.capability_id: cap for cap in CAPABILITIES}

if len(BY_ID) != len(CAPABILITIES):
    raise RuntimeError("capability ids must be unique")

for _capability in CAPABILITIES:
    if _capability.consequential and not _capability.requires_claimsieve:
        raise RuntimeError(f"{_capability.capability_id}: consequential actions must require ClaimSieve")
