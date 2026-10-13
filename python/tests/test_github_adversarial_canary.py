"""Reproducible offline adversarial cases; fake GitHub transport, no live effects."""
from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from claimsieve_ref.canonical import digest
from claimsieve_ref.durable_state import DispatchTicket, DurableStateError
from claimsieve_ref.github_adversarial_canary import (
    CanaryConfigurationError,
    GitHubAdversarialCanary,
)
from claimsieve_ref.github_provider import GitHubIssueProvider
from test_github_provider import FakeGitHubTransport
from founder_os import FounderOSReferenceWorkflow, GitHubIssueRequest


class GitHubAdversarialCanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = "example/claimsieve-mainstreet"
        self.transport = FakeGitHubTransport(self.repo)
        self.writer = GitHubIssueProvider(
            {self.repo}, read_token="preflight-token", write_token="writer-token",
            transport=self.transport,
        )
        self.observer = GitHubIssueProvider(
            {self.repo}, read_token="independent-observer-token",
            transport=self.transport,
        )
        self.action = {
            "kind": "run_connector", "effect_class": "external_write",
            "destination": {"scheme": "github", "authority": self.repo,
                            "resource": "issues", "trust_domain": "github.com"},
            "method": "CREATE",
            "parameters": {"title": "Approved action A", "body": "Exact authorized action.",
                           "correlation_marker": "proposal-A", "work_item_id": "work-A"},
            "reversibility": "compensable",
        }
        self.ticket = DispatchTicket(
            reservation_id="reservation:permit-A", permit_id="permit-A",
            campaign_id="campaign-A", action_digest="sha256:" + "a1" * 32,
            request_digest="sha256:" + "b2" * 32,
            resource_key="sha256:" + "c3" * 32,
            idempotency_key="permit-A", fencing_token=9, containment_epoch=0,
        )
        self.canary = GitHubAdversarialCanary(
            approved_action=self.action, approved_action_digest=digest(self.action),
            ticket=self.ticket, observer=self.observer,
        )

    def dispatch(self) -> dict:
        self.assertTrue(self.canary.allow_attempt(self.action))
        return self.writer.invoke(self.action, self.ticket)

    def test_01_exact_action_success_requires_readback(self) -> None:
        self.assertEqual(self.dispatch()["status"], "accepted")
        finding = self.canary.observe(executor_claim="CONFIRMED_SUCCESS")
        self.assertEqual(finding.outcome, "CONFIRMED_SUCCESS")
        self.assertFalse(finding.executor_claim_conflict)
        self.assertFalse(finding.automatic_retry_allowed)
        self.assertEqual(self.transport.requests[-1][2], "independent-observer-token")

    def test_02_title_mutation_blocked_before_write(self) -> None:
        action_b = copy.deepcopy(self.action)
        action_b["parameters"]["title"] = "Unauthorized action B"
        self.assertFalse(self.canary.allow_attempt(action_b))
        self.assertEqual(self.transport.requests, [])

    def test_03_destination_swap_blocked_before_write(self) -> None:
        action_b = copy.deepcopy(self.action)
        action_b["destination"]["authority"] = "attacker/other"
        self.assertFalse(self.canary.allow_attempt(action_b))
        self.assertEqual(self.transport.requests, [])

    def test_04_approval_digest_mutation_rejected(self) -> None:
        with self.assertRaises(CanaryConfigurationError):
            GitHubAdversarialCanary(
                approved_action=self.action, approved_action_digest="sha256:" + "00" * 32,
                ticket=self.ticket, observer=self.observer,
            )

    def test_05_fabricated_success_transcript_cannot_confirm_missing_effect(self) -> None:
        finding = self.canary.observe(executor_claim="CONFIRMED_SUCCESS")
        self.assertEqual(finding.outcome, "OUTCOME_UNKNOWN")
        self.assertTrue(finding.executor_claim_conflict)
        self.assertIsNone(finding.provider_id)

    def test_06_fabricated_rejection_cannot_override_real_effect(self) -> None:
        self.dispatch()
        finding = self.canary.observe(executor_claim="CONFIRMED_FAILURE")
        self.assertEqual(finding.outcome, "CONFIRMED_SUCCESS")
        self.assertTrue(finding.executor_claim_conflict)

    def test_07_observer_denied_is_unknown(self) -> None:
        self.dispatch()
        self.transport.get_issues_status = 403
        self.assertEqual(self.canary.observe(executor_claim="CONFIRMED_SUCCESS").outcome, "OUTCOME_UNKNOWN")

    def test_08_ambiguous_post_does_not_get_retried_or_confirmed(self) -> None:
        self.transport.raise_on_post = True
        self.assertEqual(self.dispatch()["status"], "timeout_unknown")
        self.assertEqual(self.canary.observe(executor_claim="CONFIRMED_SUCCESS").outcome, "OUTCOME_UNKNOWN")
        self.assertEqual(sum(r[0] == "POST" for r in self.transport.requests), 1)

    def test_09_provider_title_mutation_detected(self) -> None:
        self.dispatch()
        self.transport.issues[0]["title"] = "Altered in GitHub"
        self.assertEqual(self.canary.observe().outcome, "DIVERGENT_EFFECT")

    def test_10_duplicate_marker_cannot_confirm(self) -> None:
        self.dispatch()
        issue = copy.deepcopy(self.transport.issues[0])
        issue["number"] = 2
        issue["html_url"] = f"https://github.com/{self.repo}/issues/2"
        self.transport.issues.append(issue)
        self.assertEqual(self.canary.observe(executor_claim="CONFIRMED_SUCCESS").outcome, "OUTCOME_UNKNOWN")

    def test_11_malformed_marker_cannot_confirm(self) -> None:
        self.dispatch()
        self.transport.issues[0]["body"] += "ATTACK"
        self.assertEqual(self.canary.observe().outcome, "OUTCOME_UNKNOWN")

    def test_12_ticket_binding_mismatch_cannot_confirm(self) -> None:
        self.dispatch()
        wrong_ticket = DispatchTicket(**{**self.ticket.__dict__, "request_digest": "sha256:" + "ff" * 32})
        canary = GitHubAdversarialCanary(
            approved_action=self.action, approved_action_digest=digest(self.action),
            ticket=wrong_ticket, observer=self.observer,
        )
        self.assertEqual(canary.observe().outcome, "OUTCOME_UNKNOWN")

    def test_13_observer_must_not_have_writer_credentials(self) -> None:
        with self.assertRaises(CanaryConfigurationError):
            GitHubAdversarialCanary(
                approved_action=self.action, approved_action_digest=digest(self.action),
                ticket=self.ticket, observer=self.writer,
            )

    def test_14_same_ticket_repeat_does_not_duplicate_write(self) -> None:
        self.dispatch()
        self.assertTrue(self.writer.invoke(self.action, self.ticket)["idempotent_replay"])
        self.assertEqual(sum(r[0] == "POST" for r in self.transport.requests), 1)

    def test_15_mismatched_action_digest_marker_cannot_confirm(self) -> None:
        self.dispatch()
        issue = self.transport.issues[0]
        wrong_ticket = DispatchTicket(**{**self.ticket.__dict__, "action_digest": "sha256:" + "ff" * 32})
        canary = GitHubAdversarialCanary(
            approved_action=self.action, approved_action_digest=digest(self.action),
            ticket=wrong_ticket, observer=self.observer,
        )
        self.assertIn("claimsieve-v1", issue["body"])
        self.assertEqual(canary.observe().outcome, "OUTCOME_UNKNOWN")

    def test_16_exhausted_observation_window_is_unknown(self) -> None:
        self.dispatch()
        self.transport.issues.extend({
            "number": n, "title": f"unrelated {n}", "body": "no marker",
            "html_url": f"https://github.com/{self.repo}/issues/{n}",
        } for n in range(2, 102))
        short_reader = GitHubIssueProvider(
            {self.repo}, read_token="independent-observer-token",
            transport=self.transport, max_observation_pages=1,
        )
        canary = GitHubAdversarialCanary(
            approved_action=self.action, approved_action_digest=digest(self.action),
            ticket=self.ticket, observer=short_reader,
        )
        self.assertEqual(canary.observe().outcome, "OUTCOME_UNKNOWN")


    def test_17_durable_executor_rejects_mutated_title_without_post(self) -> None:
        request = GitHubIssueRequest(
            proposal_id="founder-proposal-canary-017",
            trace_id="founder-trace-canary-017",
            campaign_id="founder-campaign-canary-017",
            session_id="founder-session-canary-017",
            work_item_id="work-canary-017",
            repository=self.repo,
            title="Authorized",
            body="Exact authorized request",
            requested_at_seq=10,
        )
        with tempfile.TemporaryDirectory() as root:
            workflow = FounderOSReferenceWorkflow(
                Path(root), allowed_repositories={self.repo}, provider=self.writer
            )
            prepared = workflow.prepare_issue(request)
            mutated = copy.deepcopy(prepared.proposal)
            mutated["action"]["parameters"]["title"] = "Action B"
            with self.assertRaisesRegex(DurableStateError, "binding mismatch"):
                workflow._executor.execute(
                    prepared.permit, mutated, prepared.signed_policy,
                    prepared.evidence, prepared.decision, 11,
                )
        self.assertEqual(sum(x[0] == "POST" for x in self.transport.requests), 0)

    def test_18_durable_executor_rejects_destination_swap_without_post(self) -> None:
        request = GitHubIssueRequest(
            proposal_id="founder-proposal-canary-018",
            trace_id="founder-trace-canary-018",
            campaign_id="founder-campaign-canary-018",
            session_id="founder-session-canary-018",
            work_item_id="work-canary-018",
            repository=self.repo,
            title="Authorized",
            body="Exact authorized request",
            requested_at_seq=10,
        )
        with tempfile.TemporaryDirectory() as root:
            workflow = FounderOSReferenceWorkflow(
                Path(root), allowed_repositories={self.repo}, provider=self.writer
            )
            prepared = workflow.prepare_issue(request)
            mutated = copy.deepcopy(prepared.proposal)
            mutated["action"]["destination"]["authority"] = "attacker/other"
            with self.assertRaisesRegex(DurableStateError, "binding mismatch"):
                workflow._executor.execute(
                    prepared.permit, mutated, prepared.signed_policy,
                    prepared.evidence, prepared.decision, 11,
                )
        self.assertEqual(sum(x[0] == "POST" for x in self.transport.requests), 0)



if __name__ == "__main__":
    unittest.main()
