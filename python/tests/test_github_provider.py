from __future__ import annotations

import copy
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from typing import Any

from claimsieve_ref.canonical import digest
from claimsieve_ref.durable_state import DispatchTicket
from claimsieve_ref.github_provider import (
    GitHubHttpResponse,
    GitHubIssueProvider,
    GitHubProviderError,
    GitHubTransportError,
    UrllibGitHubTransport,
)
from founder_os import FounderOSReferenceWorkflow, GitHubIssueRequest
from github_integration import observation_summary


class FakeGitHubTransport:
    def __init__(self, repository: str = "example/claimsieve-mainstreet") -> None:
        self.repository = repository
        self.issues: list[dict[str, Any]] = []
        self.requests: list[tuple[str, str, str, dict[str, Any] | None]] = []
        self.post_status = 201
        self.get_issues_status = 200
        self.raise_on_post = False
        self.duplicate_on_read = False

    def request(
        self,
        method: str,
        path: str,
        token: str,
        json_body: dict[str, Any] | None = None,
    ) -> GitHubHttpResponse:
        self.requests.append((method, path, token, copy.deepcopy(json_body)))
        root = f"/repos/{self.repository}"
        if method == "GET" and path == root:
            return GitHubHttpResponse(
                200,
                {},
                {
                    "id": 123,
                    "full_name": self.repository,
                    "private": True,
                    "archived": False,
                    "has_issues": True,
                    "visibility": "private",
                    "permissions": {"pull": True, "push": False},
                },
            )
        if method == "GET" and path.startswith(root + "/issues?"):
            parsed = urllib.parse.urlsplit(path)
            query = urllib.parse.parse_qs(parsed.query)
            page = int(query.get("page", ["1"])[0])
            per_page = int(query.get("per_page", ["30"])[0])
            issues = list(reversed(copy.deepcopy(self.issues)))
            if self.duplicate_on_read and issues:
                duplicate = copy.deepcopy(issues[0])
                duplicate["number"] = 999
                duplicate["html_url"] = f"https://github.com/{self.repository}/issues/999"
                issues.insert(0, duplicate)
            start = (page - 1) * per_page
            end = start + per_page
            page_issues = issues[start:end]
            return GitHubHttpResponse(
                self.get_issues_status,
                {},
                page_issues if self.get_issues_status == 200 else {"message": "denied"},
            )
        if method == "POST" and path == root + "/issues":
            if self.raise_on_post:
                raise GitHubTransportError("simulated ambiguous transport")
            if self.post_status != 201:
                return GitHubHttpResponse(self.post_status, {}, {"message": "simulated"})
            assert json_body is not None
            number = len(self.issues) + 1
            issue = {
                "number": number,
                "title": json_body["title"],
                "body": json_body["body"],
                "html_url": f"https://github.com/{self.repository}/issues/{number}",
            }
            self.issues.append(issue)
            return GitHubHttpResponse(201, {}, copy.deepcopy(issue))
        raise AssertionError(f"unexpected fake GitHub request: {method} {path}")


class GitHubIssueProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repository = "example/claimsieve-mainstreet"
        self.transport = FakeGitHubTransport(self.repository)
        self.provider = GitHubIssueProvider(
            {self.repository},
            read_token="read-token-fixture",
            write_token="write-token-fixture",
            transport=self.transport,
        )
        self.action = {
            "kind": "run_connector",
            "effect_class": "external_write",
            "destination": {
                "scheme": "github",
                "authority": self.repository,
                "resource": "issues",
                "trust_domain": "github.com",
            },
            "method": "CREATE",
            "parameters": {
                "title": "Review GitHub integration",
                "body": "Verify exact read-back.",
                "correlation_marker": "claimsieve:proposal-001",
                "work_item_id": "work-item-001",
            },
            "reversibility": "compensable",
        }
        self.ticket = DispatchTicket(
            reservation_id="reservation:permit-001",
            permit_id="permit-001",
            campaign_id="campaign-001",
            action_digest=digest(self.action),
            request_digest="sha256:" + "11" * 32,
            resource_key="sha256:" + "22" * 32,
            idempotency_key="permit-001",
            fencing_token=7,
            containment_epoch=0,
        )

    def test_create_and_independent_read_back_reconstruct_exact_action(self) -> None:
        response = self.provider.invoke(self.action, self.ticket)
        record = self.provider.query(self.ticket.idempotency_key)
        self.assertEqual(response["status"], "accepted")
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record["request_digest"], self.ticket.request_digest)
        self.assertEqual(digest(record["effect"]), digest(self.action))
        post = next(request for request in self.transport.requests if request[0] == "POST")
        self.assertEqual(post[1], f"/repos/{self.repository}/issues")
        self.assertIn("<!-- claimsieve-v1:", post[3]["body"])
        self.assertNotIn("read-token-fixture", post[3]["body"])
        self.assertNotIn("write-token-fixture", post[3]["body"])

    def test_issue_edit_is_observed_as_action_divergence(self) -> None:
        self.provider.invoke(self.action, self.ticket)
        self.transport.issues[0]["title"] = "Edited outside ClaimSieve"
        record = self.provider.query(self.ticket.idempotency_key)
        assert record is not None
        self.assertNotEqual(digest(record["effect"]), digest(self.action))

    def test_duplicate_marker_is_reported_as_conflicting_provider_evidence(self) -> None:
        self.provider.invoke(self.action, self.ticket)
        duplicate = copy.deepcopy(self.transport.issues[0])
        duplicate["number"] = 2
        duplicate["html_url"] = f"https://github.com/{self.repository}/issues/2"
        self.transport.issues.append(duplicate)
        record = self.provider.query(self.ticket.idempotency_key)
        assert record is not None
        self.assertEqual(record["status"], "conflict")
        self.assertEqual(record["response"]["status"], "rejected")

    def _post_count(self) -> int:
        return sum(1 for method, _, _, _ in self.transport.requests if method == "POST")

    def test_marker_survives_trailing_whitespace_edit(self) -> None:
        self.provider.invoke(self.action, self.ticket)
        self.transport.issues[0]["body"] += "\n"
        record = self.provider.query(self.ticket.idempotency_key)
        assert record is not None
        self.assertEqual(record["status"], "accepted")
        self.assertEqual(digest(record["effect"]), digest(self.action))

    def test_marker_survives_crlf_line_ending_edit(self) -> None:
        self.provider.invoke(self.action, self.ticket)
        body = self.transport.issues[0]["body"]
        self.transport.issues[0]["body"] = body.replace("\n\n<!--", "\r\n\r\n<!--") + "\r\n"
        record = self.provider.query(self.ticket.idempotency_key)
        assert record is not None
        self.assertEqual(record["status"], "accepted")
        self.assertEqual(digest(record["effect"]), digest(self.action))

    def test_mangled_marker_is_conflict_and_blocks_second_write(self) -> None:
        self.provider.invoke(self.action, self.ticket)
        self.assertEqual(self._post_count(), 1)
        self.transport.issues[0]["body"] += " appended after the marker"
        record = self.provider.query(self.ticket.idempotency_key)
        assert record is not None
        self.assertEqual(record["status"], "conflict")
        with self.assertRaises(GitHubProviderError):
            self.provider.invoke(self.action, self.ticket)
        self.assertEqual(self._post_count(), 1)

    def test_exhausted_observation_window_blocks_write_and_is_unknown_on_read(self) -> None:
        provider = GitHubIssueProvider(
            {self.repository},
            read_token="read-token-fixture",
            write_token="write-token-fixture",
            transport=self.transport,
            max_observation_pages=2,
        )
        self.transport.issues = [
            {
                "number": number,
                "title": f"unrelated {number}",
                "body": "no marker here",
                "html_url": f"https://github.com/{self.repository}/issues/{number}",
            }
            for number in range(1, 201)
        ]
        with self.assertRaisesRegex(GitHubProviderError, "window exhausted"):
            provider.invoke(self.action, self.ticket)
        self.assertEqual(self._post_count(), 0)
        self.assertIsNone(provider.query(self.ticket.idempotency_key))

    def test_exhausted_window_with_visible_match_does_not_confirm_uniqueness(self) -> None:
        self.provider.invoke(self.action, self.ticket)
        self.assertEqual(self._post_count(), 1)
        self.transport.issues.extend(
            {
                "number": number,
                "title": f"unrelated {number}",
                "body": "no marker here",
                "html_url": f"https://github.com/{self.repository}/issues/{number}",
            }
            for number in range(2, 201)
        )
        provider = GitHubIssueProvider(
            {self.repository},
            read_token="read-token-fixture",
            write_token="write-token-fixture",
            transport=self.transport,
            max_observation_pages=2,
        )
        self.assertIsNone(provider.query(self.ticket.idempotency_key))
        with self.assertRaisesRegex(GitHubProviderError, "uniqueness"):
            provider.invoke(self.action, self.ticket)
        self.assertEqual(self._post_count(), 1)

    def test_ambiguous_post_is_not_retried(self) -> None:
        self.transport.raise_on_post = True
        response = self.provider.invoke(self.action, self.ticket)
        post_count = sum(1 for method, _, _, _ in self.transport.requests if method == "POST")
        self.assertEqual(response["status"], "timeout_unknown")
        self.assertEqual(post_count, 1)

    def test_write_is_blocked_when_read_back_preflight_fails(self) -> None:
        self.transport.get_issues_status = 403
        with self.assertRaisesRegex(GitHubProviderError, "preflight"):
            self.provider.invoke(self.action, self.ticket)
        post_count = sum(1 for method, _, _, _ in self.transport.requests if method == "POST")
        self.assertEqual(post_count, 0)

    def test_server_error_is_unknown_not_confirmed_failure(self) -> None:
        self.transport.post_status = 503
        response = self.provider.invoke(self.action, self.ticket)
        self.assertEqual(response["status"], "timeout_unknown")

    def test_validation_error_is_confirmed_rejection(self) -> None:
        self.transport.post_status = 422
        response = self.provider.invoke(self.action, self.ticket)
        self.assertEqual(response["status"], "rejected")

    def test_repository_allowlist_blocks_request_before_transport(self) -> None:
        changed = copy.deepcopy(self.action)
        changed["destination"]["authority"] = "attacker/other"
        with self.assertRaisesRegex(GitHubProviderError, "allowlisted"):
            self.provider.invoke(changed, self.ticket)
        self.assertEqual(self.transport.requests, [])

    def test_reserved_marker_in_user_body_is_rejected(self) -> None:
        changed = copy.deepcopy(self.action)
        changed["parameters"]["body"] = "spoof <!-- claimsieve-v1:"
        with self.assertRaisesRegex(GitHubProviderError, "reserved"):
            self.provider.invoke(changed, self.ticket)

    def test_read_and_write_tokens_are_separate(self) -> None:
        with self.assertRaisesRegex(GitHubProviderError, "distinct"):
            GitHubIssueProvider(
                {self.repository},
                read_token="same-token",
                write_token="same-token",
                transport=self.transport,
            )

    def test_transport_rejects_non_github_api_hosts(self) -> None:
        with self.assertRaisesRegex(GitHubProviderError, "exactly"):
            UrllibGitHubTransport("https://attacker.example")

    def test_generic_connector_action_is_rejected(self) -> None:
        changed = copy.deepcopy(self.action)
        changed["method"] = "DELETE"
        with self.assertRaisesRegex(GitHubProviderError, "method"):
            self.provider.invoke(changed, self.ticket)

    def test_repository_access_check_returns_only_bounded_metadata(self) -> None:
        result = self.provider.check_repository(self.repository)
        self.assertEqual(result["repository"], self.repository)
        self.assertTrue(result["has_issues"])
        self.assertNotIn("token", result)

    def test_full_founder_workflow_uses_live_provider_boundary(self) -> None:
        request = GitHubIssueRequest(
            proposal_id="founder-proposal-live-001",
            trace_id="founder-trace-live-001",
            campaign_id="founder-campaign-live-001",
            session_id="founder-session-live-001",
            work_item_id="work-item-live-001",
            repository=self.repository,
            title="Review live GitHub boundary",
            body="Verify the exact issue after creation.",
            requested_at_seq=10,
        )
        with tempfile.TemporaryDirectory() as temp:
            workflow = FounderOSReferenceWorkflow(
                Path(temp),
                {self.repository},
                provider=self.provider,
            )
            prepared = workflow.prepare_issue(request)
            result = workflow.execute_issue(prepared, 11, 12)
            self.assertEqual(result.observation["reconciliation"], "CONFIRMED_SUCCESS")
            self.assertFalse(result.execution["automatic_retry_allowed"])
            self.assertTrue(all(not errors for errors in workflow.verify_ledgers().values()))

    def test_full_workflow_duplicate_read_back_remains_unknown(self) -> None:
        request = GitHubIssueRequest(
            proposal_id="founder-proposal-duplicate-001",
            trace_id="founder-trace-duplicate-001",
            campaign_id="founder-campaign-duplicate-001",
            session_id="founder-session-duplicate-001",
            work_item_id="work-item-duplicate-001",
            repository=self.repository,
            title="Detect duplicate GitHub issue markers",
            body="Duplicate provider evidence must remain unknown.",
            requested_at_seq=10,
        )
        with tempfile.TemporaryDirectory() as temp:
            workflow = FounderOSReferenceWorkflow(
                Path(temp),
                {self.repository},
                provider=self.provider,
            )
            prepared = workflow.prepare_issue(request)
            self.transport.duplicate_on_read = True
            result = workflow.execute_issue(prepared, 11, 12)
            self.assertEqual(result.observation["reconciliation"], "OUTCOME_UNKNOWN")
            self.assertTrue(result.observation["receipt_conflict"])
            self.assertFalse(result.execution["automatic_retry_allowed"])

    def test_read_only_observation_summary_confirms_exact_effect(self) -> None:
        self.provider.invoke(self.action, self.ticket)
        record = self.provider.query(self.ticket.idempotency_key)
        result = observation_summary(record, digest(self.action))
        self.assertEqual(result["independent_outcome"], "CONFIRMED_SUCCESS")
        self.assertFalse(result["automatic_retry_allowed"])

    def test_read_only_observation_summary_preserves_absence_as_unknown(self) -> None:
        result = observation_summary(None, digest(self.action))
        self.assertEqual(result["independent_outcome"], "OUTCOME_UNKNOWN")
        self.assertFalse(result["provider_evidence_conflict"])


if __name__ == "__main__":
    unittest.main()
