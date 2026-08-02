#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from claimsieve_ref.canonical import digest, loads_strict
from claimsieve_ref.durable_state import classify_provider_evidence
from claimsieve_ref.github_provider import GitHubIssueProvider, GitHubProviderError
from founder_os import FounderOSReferenceWorkflow, GitHubIssueRequest


def _load_request(path: Path) -> GitHubIssueRequest:
    try:
        value = loads_strict(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit(f"request file is invalid: {exc}") from exc
    if not isinstance(value, dict):
        raise SystemExit("request file must contain one JSON object")
    expected = set(GitHubIssueRequest.__dataclass_fields__)
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise SystemExit(f"request fields do not match; missing={missing}, extra={extra}")
    try:
        request = GitHubIssueRequest(**value)
        request.validate()
        return request
    except (TypeError, ValueError) as exc:
        raise SystemExit(f"request fields are invalid: {exc}") from exc


def _token(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"required secret environment variable is not set: {name}")
    return value


def _provider(repository: str, *, writable: bool) -> GitHubIssueProvider:
    return GitHubIssueProvider(
        {repository},
        read_token=_token("CLAIMSIEVE_GITHUB_READ_TOKEN"),
        write_token=_token("CLAIMSIEVE_GITHUB_WRITE_TOKEN") if writable else None,
    )


def _print(value: dict[str, Any]) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def check(repository: str) -> int:
    provider = _provider(repository, writable=False)
    _print({"status": "READY", **provider.check_repository(repository)})
    return 0


def observation_summary(
    record: dict[str, Any] | None,
    expected_action_digest: str,
) -> dict[str, Any]:
    effect = record.get("effect") if isinstance(record, dict) else None
    response = record.get("response") if isinstance(record, dict) else None
    response_status = response.get("status") if isinstance(response, dict) else None
    observed_action_digest = digest(effect) if isinstance(effect, dict) else None
    reconciliation, provider_evidence_conflict = classify_provider_evidence(
        response_status,
        observed_action_digest,
        expected_action_digest,
    )
    return {
        "status": "OBSERVED",
        "provider_id": record.get("provider_id") if isinstance(record, dict) else None,
        "provider_status": response_status,
        "observed_action_digest": observed_action_digest,
        "expected_action_digest": expected_action_digest,
        "independent_outcome": reconciliation,
        "provider_evidence_conflict": provider_evidence_conflict,
        "automatic_retry_allowed": False,
    }


def observe(repository: str, idempotency_key: str, expected_action_digest: str) -> int:
    provider = _provider(repository, writable=False)
    _print(observation_summary(provider.query(idempotency_key), expected_action_digest))
    return 0


def plan(request_path: Path) -> int:
    request = _load_request(request_path)
    with tempfile.TemporaryDirectory(prefix="claimsieve-github-plan-") as temp:
        workflow = FounderOSReferenceWorkflow(
            temp,
            allowed_repositories={request.repository},
        )
        prepared = workflow.prepare_issue(request)
    _print(
        {
            "status": "PLANNED_NO_EXTERNAL_EFFECT",
            "repository": request.repository,
            "proposal_id": request.proposal_id,
            "proposal_digest": digest(prepared.proposal),
            "action_digest": digest(prepared.proposal["action"]),
            "permit_id": prepared.permit["permit_id"],
            "automatic_retry_allowed": False,
        }
    )
    return 0


def execute(
    request_path: Path,
    workspace: Path,
    confirm_repository: str,
    execute_live_write: bool,
) -> int:
    request = _load_request(request_path)
    if not execute_live_write:
        raise SystemExit("live execution requires --execute-live-write")
    if os.environ.get("CLAIMSIEVE_ENABLE_LIVE_GITHUB_WRITE") != "1":
        raise SystemExit("live execution requires CLAIMSIEVE_ENABLE_LIVE_GITHUB_WRITE=1")
    if confirm_repository != request.repository:
        raise SystemExit("--confirm-repository must exactly match the request repository")
    provider = _provider(request.repository, writable=True)
    repository = provider.check_repository(request.repository)
    if repository.get("archived") is True:
        raise SystemExit("live execution is blocked because the repository is archived")
    workflow = FounderOSReferenceWorkflow(
        workspace,
        allowed_repositories={request.repository},
        provider=provider,
    )
    prepared = workflow.prepare_issue(request)
    result = workflow.execute_issue(
        prepared,
        execute_seq=request.requested_at_seq + 1,
        observe_seq=request.requested_at_seq + 2,
    )
    _print(
        {
            "status": "EXECUTED",
            "repository": request.repository,
            "proposal_id": request.proposal_id,
            "permit_id": prepared.permit["permit_id"],
            "provider_status": result.execution["executor_receipt"]["provider_status"],
            "provider_id": result.execution["executor_receipt"].get("provider_id"),
            "independent_outcome": result.observation["reconciliation"],
            "automatic_retry_allowed": result.execution["automatic_retry_allowed"],
            "ledger_errors": workflow.verify_ledgers(),
        }
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Restricted ClaimSieve GitHub issue integration"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    check_parser = subparsers.add_parser("check", help="verify read access and repository identity")
    check_parser.add_argument("repository", help="exact owner/name repository")

    observe_parser = subparsers.add_parser(
        "observe", help="perform read-only marker reconciliation after an unknown outcome"
    )
    observe_parser.add_argument("repository", help="exact owner/name repository")
    observe_parser.add_argument("idempotency_key", help="permit/idempotency key to locate")
    observe_parser.add_argument("--expected-action-digest", required=True)

    plan_parser = subparsers.add_parser("plan", help="prepare and authorize without a GitHub request")
    plan_parser.add_argument("request", type=Path)

    execute_parser = subparsers.add_parser("execute", help="create one governed GitHub issue")
    execute_parser.add_argument("request", type=Path)
    execute_parser.add_argument("--workspace", type=Path, required=True)
    execute_parser.add_argument("--confirm-repository", required=True)
    execute_parser.add_argument("--execute-live-write", action="store_true")

    args = parser.parse_args()
    try:
        if args.command == "check":
            return check(args.repository)
        if args.command == "observe":
            return observe(
                args.repository,
                args.idempotency_key,
                args.expected_action_digest,
            )
        if args.command == "plan":
            return plan(args.request)
        return execute(
            args.request,
            args.workspace,
            args.confirm_repository,
            args.execute_live_write,
        )
    except GitHubProviderError as exc:
        raise SystemExit(f"GitHub integration failed: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
