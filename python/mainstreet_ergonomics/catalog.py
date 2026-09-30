from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from small_business_agent.model import WorkPlan
from small_business_agent.registry import BY_ID, CAPABILITIES, Capability


AGENT_OPERATIONS = (
    "read_context",
    "select_skill",
    "prepare_work_plan",
    "prepare_claimsieve_intent",
    "record_unreviewed_observation",
)


@dataclass(frozen=True)
class SkillDescriptor:
    """Harness-neutral ergonomic view of one Main Street business capability.

    This is discovery/routing metadata only. It does not contain a provider
    client, credential, permit issuer, executor, or authority decision.
    """

    schema_version: str
    skill_id: str
    capability_id: str
    domain: str
    description: str
    risk: str
    triggers: tuple[str, ...]
    required_inputs: tuple[str, ...]
    expected_output: str
    consequential: bool
    requires_claimsieve: bool
    requires_human_approval: bool
    execution_mode: str
    adjudicator: str | None
    direct_execution: bool

    def validate(self) -> None:
        if self.schema_version != "mainstreet.skill_descriptor.v1":
            raise ValueError("unsupported Main Street skill descriptor schema")
        if not self.skill_id.startswith("mainstreet."):
            raise ValueError("skill_id must be namespaced under mainstreet")
        if self.capability_id not in BY_ID:
            raise ValueError("skill references unknown capability")
        if self.direct_execution:
            raise ValueError("ergonomic skill descriptors cannot grant direct execution")
        if self.consequential:
            if not self.requires_claimsieve:
                raise ValueError("consequential skills must require ClaimSieve")
            if self.execution_mode != "proposal_only":
                raise ValueError("consequential skills must remain proposal-only")
            if self.adjudicator != "claimsieve":
                raise ValueError("consequential skills must name ClaimSieve as adjudicator")
        else:
            if self.execution_mode != "informational_only":
                raise ValueError("non-consequential skills must remain informational-only")
            if self.adjudicator is not None:
                raise ValueError("informational-only skills do not acquire an adjudicator")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class AgentProfile:
    """Non-authoritative role profile shared across proposal runtimes."""

    schema_version: str
    agent_id: str
    title: str
    purpose: str
    operations: tuple[str, ...]
    skill_ids: tuple[str, ...]
    provider_credentials: bool
    permit_authority: bool
    provider_execution: bool
    outcome_authority: bool

    def validate(self) -> None:
        if self.schema_version != "mainstreet.agent_profile.v1":
            raise ValueError("unsupported Main Street agent profile schema")
        if not self.agent_id.startswith("mainstreet."):
            raise ValueError("agent_id must be namespaced under mainstreet")
        if self.operations != AGENT_OPERATIONS:
            raise ValueError("agent operations must match the non-authoritative allowlist")
        if len(set(self.skill_ids)) != len(self.skill_ids):
            raise ValueError("agent profile contains duplicate skills")
        known = {skill.skill_id for skill in MAINSTREET_SKILLS}
        if any(skill_id not in known for skill_id in self.skill_ids):
            raise ValueError("agent profile references unknown skill")
        if any(
            (
                self.provider_credentials,
                self.permit_authority,
                self.provider_execution,
                self.outcome_authority,
            )
        ):
            raise ValueError("agent profile cannot acquire authority or execution capability")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


def _descriptor(capability: Capability) -> SkillDescriptor:
    consequential = capability.consequential
    skill = SkillDescriptor(
        schema_version="mainstreet.skill_descriptor.v1",
        skill_id=f"mainstreet.{capability.capability_id}",
        capability_id=capability.capability_id,
        domain=capability.domain.value,
        description=capability.description,
        risk=capability.risk.value,
        triggers=tuple(capability.keywords),
        required_inputs=tuple(capability.suggested_inputs),
        expected_output=capability.expected_output,
        consequential=consequential,
        requires_claimsieve=capability.requires_claimsieve,
        requires_human_approval=capability.requires_human_approval,
        execution_mode="proposal_only" if consequential else "informational_only",
        adjudicator="claimsieve" if consequential else None,
        direct_execution=False,
    )
    skill.validate()
    return skill


MAINSTREET_SKILLS: tuple[SkillDescriptor, ...] = tuple(_descriptor(capability) for capability in CAPABILITIES)
_SKILLS_BY_CAPABILITY = {skill.capability_id: skill for skill in MAINSTREET_SKILLS}

if len(_SKILLS_BY_CAPABILITY) != len(MAINSTREET_SKILLS):
    raise RuntimeError("ergonomic skill ids must map one-to-one to capabilities")


MAINSTREET_AGENT_PROFILE = AgentProfile(
    schema_version="mainstreet.agent_profile.v1",
    agent_id="mainstreet.small_business_operator",
    title="Main Street Small Business Operator",
    purpose=(
        "Select bounded business skills, gather context, prepare work plans, and route "
        "consequential intent toward ClaimSieve without gaining provider authority."
    ),
    operations=AGENT_OPERATIONS,
    skill_ids=tuple(skill.skill_id for skill in MAINSTREET_SKILLS),
    provider_credentials=False,
    permit_authority=False,
    provider_execution=False,
    outcome_authority=False,
)
MAINSTREET_AGENT_PROFILE.validate()


def skill_for_capability(capability_id: str) -> SkillDescriptor:
    try:
        return _SKILLS_BY_CAPABILITY[capability_id]
    except KeyError as exc:
        raise KeyError(f"unknown Main Street capability: {capability_id}") from exc


def skills_for_work_plan(plan: WorkPlan) -> tuple[SkillDescriptor, ...]:
    """Project the deterministic planner's work items into ergonomic skill descriptors."""

    return tuple(skill_for_capability(item.capability_id) for item in plan.items)


def catalog_snapshot() -> dict[str, Any]:
    """Return a serializable, non-authoritative catalog for runtime adapters."""

    return {
        "schema_version": "mainstreet.ergonomics_catalog.v1",
        "authority": "non_authoritative",
        "agent": MAINSTREET_AGENT_PROFILE.to_dict(),
        "skills": [skill.to_dict() for skill in MAINSTREET_SKILLS],
    }
