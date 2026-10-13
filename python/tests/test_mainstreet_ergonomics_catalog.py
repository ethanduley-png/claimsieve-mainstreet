from __future__ import annotations

import json

from mainstreet_ergonomics import (
    AGENT_OPERATIONS,
    MAINSTREET_AGENT_PROFILE,
    MAINSTREET_SKILLS,
    catalog_snapshot,
    skill_for_capability,
    skills_for_work_plan,
)
from small_business_agent.model import Intent
from small_business_agent.planner import plan_intent
from small_business_agent.registry import CAPABILITIES


def test_catalog_is_one_to_one_with_business_capability_registry() -> None:
    assert len(MAINSTREET_SKILLS) == len(CAPABILITIES)
    assert {skill.capability_id for skill in MAINSTREET_SKILLS} == {
        capability.capability_id for capability in CAPABILITIES
    }
    assert len({skill.skill_id for skill in MAINSTREET_SKILLS}) == len(MAINSTREET_SKILLS)


def test_consequential_skills_are_proposal_only_and_claimsieve_gated() -> None:
    consequential = [skill for skill in MAINSTREET_SKILLS if skill.consequential]
    assert consequential
    for skill in consequential:
        assert skill.requires_claimsieve is True
        assert skill.execution_mode == "proposal_only"
        assert skill.adjudicator == "claimsieve"
        assert skill.direct_execution is False


def test_informational_skills_do_not_gain_execution_or_authority() -> None:
    informational = [skill for skill in MAINSTREET_SKILLS if not skill.consequential]
    assert informational
    for skill in informational:
        assert skill.execution_mode == "informational_only"
        assert skill.adjudicator is None
        assert skill.direct_execution is False


def test_agent_profile_has_no_credentials_permits_execution_or_outcome_authority() -> None:
    assert MAINSTREET_AGENT_PROFILE.operations == AGENT_OPERATIONS
    assert MAINSTREET_AGENT_PROFILE.provider_credentials is False
    assert MAINSTREET_AGENT_PROFILE.permit_authority is False
    assert MAINSTREET_AGENT_PROFILE.provider_execution is False
    assert MAINSTREET_AGENT_PROFILE.outcome_authority is False
    assert not any("execute" in operation for operation in MAINSTREET_AGENT_PROFILE.operations)


def test_existing_planner_projects_into_same_skill_catalog() -> None:
    plan = plan_intent(
        Intent(
            text="send a follow up email to this lead",
            tenant_id="tenant-demo",
            principal_id="operator-demo",
            context={},
        )
    )
    skills = skills_for_work_plan(plan)
    assert skills
    assert tuple(skill.capability_id for skill in skills) == tuple(
        item.capability_id for item in plan.items
    )
    assert any(skill.capability_id == "send_external_message" for skill in skills)
    assert skill_for_capability("send_external_message").adjudicator == "claimsieve"


def test_catalog_snapshot_is_serializable_and_explicitly_non_authoritative() -> None:
    snapshot = catalog_snapshot()
    assert snapshot["authority"] == "non_authoritative"
    encoded = json.dumps(snapshot, sort_keys=True)
    assert "provider_credentials" in encoded
    assert "proposal_only" in encoded
    assert "claimsieve" in encoded
