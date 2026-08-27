from __future__ import annotations

import re

from .model import BusinessDomain, Intent, ProposedWorkItem, WorkPlan
from .registry import BY_ID, CAPABILITIES, Capability

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_POLITE_PREFIXES = (
    "please ",
    "can you ",
    "could you ",
    "would you ",
    "i want you to ",
    "go ahead and ",
)
_DRAFT_PREFIXES = ("draft ", "write ", "prepare ", "compose ")


def _normalized(text: str) -> str:
    return " ".join(_TOKEN_RE.findall(text.lower()))


def _score(capability: Capability, normalized: str) -> int:
    score = 0
    haystack = f" {normalized} "
    for keyword in capability.keywords:
        k = _normalized(keyword)
        if k and f" {k} " in haystack:
            # Longer, more specific phrases beat generic single words.
            score += 4 + len(k.split())
    return score


def _command_text(normalized: str) -> str:
    command = normalized
    changed = True
    while changed:
        changed = False
        for prefix in _POLITE_PREFIXES:
            if command.startswith(prefix):
                command = command[len(prefix) :]
                changed = True
                break
    return command


def _imperative_overrides(normalized: str) -> tuple[Capability, ...]:
    """Conservatively identify language that plausibly requests an external side effect.

    Keyword scoring is useful for routing topics, but it must not downgrade an imperative
    action into a harmless draft merely because both share words such as "email". These
    overrides only create governed proposals; they never execute or authorize anything.
    """
    command = _command_text(normalized)
    forced: list[Capability] = []

    if not command.startswith(_DRAFT_PREFIXES):
        external_verbs = (
            "email ",
            "text ",
            "message ",
            "notify ",
            "contact ",
            "reach out ",
            "follow up ",
            "reply ",
            "respond ",
        )
        if command.startswith(external_verbs):
            forced.append(BY_ID["send_external_message"])

    cancellation_terms = ("membership", "subscription", "service", "customer account")
    if (
        command.startswith(("cancel ", "terminate ", "close "))
        and any(term in command for term in cancellation_terms)
    ):
        forced.append(BY_ID["cancel_customer_service"])

    if command.startswith(("delete ", "erase ", "purge ", "destroy ")):
        forced.append(BY_ID["destructive_data_change"])

    if command.startswith("wire "):
        forced.append(BY_ID["move_money"])

    # Preserve order while de-duplicating.
    return tuple(dict.fromkeys(forced))


def _to_item(capability: Capability) -> ProposedWorkItem:
    return ProposedWorkItem(
        capability_id=capability.capability_id,
        domain=capability.domain,
        risk=capability.risk,
        description=capability.description,
        consequential=capability.consequential,
        requires_claimsieve=capability.requires_claimsieve,
        requires_human_approval=capability.requires_human_approval,
        suggested_inputs=capability.suggested_inputs,
        expected_output=capability.expected_output,
    )


def plan_intent(intent: Intent, *, max_items: int = 8) -> WorkPlan:
    """Route founder language into bounded work proposals without executing anything.

    This is intentionally deterministic. An LLM can propose richer candidate tasks later,
    but those tasks should be normalized through the same capability/risk registry before
    any consequential action can enter the ClaimSieve authority path.
    """
    intent.validate()
    if isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 1:
        raise ValueError("max_items must be a positive integer")

    normalized = _normalized(intent.text)
    founder = BY_ID["founder_daily_brief"]

    triage_only_phrases = (
        "where to start",
        "no idea where to start",
        "dont know where to start",
        "do not know where to start",
    )
    if any(phrase in normalized for phrase in triage_only_phrases):
        selected = [founder]
    else:
        forced = list(_imperative_overrides(normalized))
        forced_ids = {cap.capability_id for cap in forced}
        forced_domains = {cap.domain for cap in forced}

        scored: list[tuple[int, Capability]] = []
        for capability in CAPABILITIES:
            if capability.capability_id in forced_ids:
                continue
            score = _score(capability, normalized)
            if score:
                scored.append((score, capability))

        scored.sort(key=lambda pair: (-pair[0], pair[1].capability_id))
        best_per_domain: dict[BusinessDomain, tuple[int, Capability]] = {}
        for score, capability in scored:
            if capability.domain in forced_domains:
                continue
            best_per_domain.setdefault(capability.domain, (score, capability))

        selected = forced + [pair[1] for pair in best_per_domain.values()]
        selected_ids = {cap.capability_id for cap in selected}
        for _, capability in scored:
            if len(selected) >= max_items:
                break
            if capability.domain in forced_domains:
                continue
            if capability.capability_id not in selected_ids:
                selected.append(capability)
                selected_ids.add(capability.capability_id)

        if not selected:
            selected = [founder]

        broad_phrases = (
            "everything",
            "run my business",
            "help me everywhere",
            "what needs my attention",
            "what should i do",
            "handle the business",
        )
        if any(phrase in normalized for phrase in broad_phrases):
            selected_ids = {cap.capability_id for cap in selected}
            if founder.capability_id not in selected_ids:
                selected.insert(0, founder)

    selected = selected[:max_items]

    domains: list[BusinessDomain] = []
    for capability in selected:
        if capability.domain not in domains:
            domains.append(capability.domain)

    missing: list[str] = []
    available = set(intent.context)
    needed = {item for capability in selected for item in capability.suggested_inputs}
    for requirement in sorted(needed):
        key = requirement.lower().replace(" ", "_").replace("/", "_")
        if key not in available:
            missing.append(requirement)

    assumptions = (
        "The agent is proposal-only for consequential actions.",
        "Missing authority or evidence does not imply permission.",
        "Execution outcome is established by an executor/observer path, not by the planner.",
    )

    return WorkPlan(
        intent=intent,
        domains=tuple(domains),
        items=tuple(_to_item(capability) for capability in selected),
        assumptions=assumptions,
        missing_context=tuple(missing),
    )
