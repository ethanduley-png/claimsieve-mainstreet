#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import tempfile
from pathlib import Path

from claimsieve_ref.durable_state import DurableStateError
from founder_os import FounderOSInputError, FounderOSReferenceWorkflow, GitHubIssueRequest


def request(repository: str = "example/claimsieve-mainstreet") -> GitHubIssueRequest:
    return GitHubIssueRequest(
        proposal_id="founder-proposal-rt",
        trace_id="founder-trace-rt",
        campaign_id="founder-campaign-rt",
        session_id="founder-session-rt",
        work_item_id="work-item-rt",
        repository=repository,
        title="Adversarial Founder OS review",
        body="Test exact binding and unknown outcome handling.",
        requested_at_seq=10,
    )


def record(name: str, expected: str, blocked: bool, actual: str) -> dict[str, object]:
    return {"name": name, "expected": expected, "blocked_or_detected": blocked, "actual": actual}


def main() -> None:
    results: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)

        workflow = FounderOSReferenceWorkflow(root / "base", {"example/claimsieve-mainstreet"})
        prepared = workflow.prepare_issue(request())

        try:
            changed = copy.deepcopy(prepared.proposal)
            changed["action"]["destination"]["authority"] = "attacker/other"
            workflow._executor.execute(prepared.permit, changed, prepared.signed_policy, prepared.evidence, prepared.decision, 11)
            results.append(record("repository_substitution", "blocked", False, "executed"))
        except DurableStateError as exc:
            results.append(record("repository_substitution", "blocked", True, str(exc)))

        try:
            changed = copy.deepcopy(prepared.proposal)
            changed["action"]["parameters"]["title"] = "mutated"
            workflow._executor.execute(prepared.permit, changed, prepared.signed_policy, prepared.evidence, prepared.decision, 11)
            results.append(record("payload_mutation", "blocked", False, "executed"))
        except DurableStateError as exc:
            results.append(record("payload_mutation", "blocked", True, str(exc)))

        try:
            FounderOSReferenceWorkflow(root / "allowlist", {"example/claimsieve-mainstreet"}).prepare_issue(request("attacker/other"))
            results.append(record("unapproved_repository", "blocked", False, "prepared"))
        except FounderOSInputError as exc:
            results.append(record("unapproved_repository", "blocked", True, str(exc)))

        replay = FounderOSReferenceWorkflow(root / "replay", {"example/claimsieve-mainstreet"})
        replay_prepared = replay.prepare_issue(request())
        replay.execute_issue(replay_prepared, 11, 12)
        try:
            replay.execute_issue(replay_prepared, 13, 14)
            results.append(record("permit_replay", "blocked", False, "executed twice"))
        except DurableStateError as exc:
            results.append(record("permit_replay", "blocked", True, str(exc)))

        before = FounderOSReferenceWorkflow(root / "before", {"example/claimsieve-mainstreet"}, "timeout_before_commit")
        before_result = before.execute_issue(before.prepare_issue(request()), 11, 12)
        results.append(record(
            "timeout_before_commit",
            "OUTCOME_UNKNOWN",
            before_result.observation["reconciliation"] == "OUTCOME_UNKNOWN",
            before_result.observation["reconciliation"],
        ))

        after = FounderOSReferenceWorkflow(root / "after", {"example/claimsieve-mainstreet"}, "timeout_after_commit")
        after_result = after.execute_issue(after.prepare_issue(request()), 11, 12)
        results.append(record(
            "timeout_after_commit",
            "CONFIRMED_SUCCESS by independent readback",
            after_result.observation["reconciliation"] == "CONFIRMED_SUCCESS",
            after_result.observation["reconciliation"],
        ))

        results.append(record(
            "automatic_retry_after_unknown",
            "false",
            before_result.execution["automatic_retry_allowed"] is False,
            str(before_result.execution["automatic_retry_allowed"]).lower(),
        ))

        ledger_errors = after.verify_ledgers()
        results.append(record(
            "four_ledger_integrity",
            "all chains verify",
            all(not value for value in ledger_errors.values()),
            json.dumps(ledger_errors, sort_keys=True),
        ))

    report = {
        "schema_version": "claimsieve.founder_os_red_team.v1",
        "total": len(results),
        "blocked_or_detected": sum(bool(item["blocked_or_detected"]) for item in results),
        "surviving_tested_bypasses": [item["name"] for item in results if not item["blocked_or_detected"]],
        "results": results,
        "limitations": [
            "This red-team run uses the deterministic local provider and does not make a live GitHub API call.",
            "Complete mediation still depends on deployment and credential isolation.",
            "Fixture keys are deterministic test material and are not production credentials.",
        ],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["surviving_tested_bypasses"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
