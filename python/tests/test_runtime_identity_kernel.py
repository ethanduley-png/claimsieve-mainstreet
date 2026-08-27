from __future__ import annotations

import unittest

from claimsieve_ref.kernel import CampaignState, evaluate
from founder_os import (
    FounderOSInputError,
    FounderRuntimeProfile,
    GitHubIssueRequest,
    founder_evidence,
    founder_fixture_keys,
    founder_policy,
    founder_proposal,
    founder_runtime_profile,
)


class RuntimeIdentityKernelTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tenant_id = "tenant-founder"
        self.keys = founder_fixture_keys()
        self.request = GitHubIssueRequest(
            proposal_id="proposal-runtime-kernel-001",
            trace_id="trace-runtime-kernel-001",
            campaign_id="campaign-runtime-kernel-001",
            session_id="session-runtime-kernel-001",
            work_item_id="work-runtime-kernel-001",
            repository="example/claimsieve-mainstreet",
            title="Verify runtime certificate binding",
            body="A valid certificate for one proposal runtime must not authorize another runtime.",
            requested_at_seq=40,
        )
        self.deepagents = founder_runtime_profile(
            self.tenant_id,
            runtime_name="deepagents",
            runtime_version="0.7.9",
        )

    def evaluate_with(self, proposal: dict, policy: dict, evidence: list[dict]):
        return evaluate(
            proposal,
            policy,
            evidence,
            CampaignState(self.request.campaign_id),
            self.request.requested_at_seq,
        )

    def test_deepagents_runtime_identity_and_deployment_certificate_allow(self) -> None:
        evidence = founder_evidence(
            self.request,
            self.keys,
            self.tenant_id,
            self.deepagents,
        )
        policy = founder_policy(
            self.keys,
            self.tenant_id,
            self.deepagents,
        )
        proposal = founder_proposal(
            self.request,
            evidence,
            self.keys,
            self.tenant_id,
            approve=True,
            runtime_profile=self.deepagents,
        )
        decision = self.evaluate_with(proposal, policy, evidence)
        self.assertEqual(decision.document["verdict"], "ALLOW")
        self.assertEqual(decision.document["reason_codes"], ["ALL_GATES_PASSED"])

    def test_valid_openclaw_certificate_cannot_authorize_deepagents_proposal(self) -> None:
        openclaw_evidence = founder_evidence(
            self.request,
            self.keys,
            self.tenant_id,
        )
        deepagents_policy = founder_policy(
            self.keys,
            self.tenant_id,
            self.deepagents,
        )
        deepagents_proposal = founder_proposal(
            self.request,
            openclaw_evidence,
            self.keys,
            self.tenant_id,
            approve=True,
            runtime_profile=self.deepagents,
        )

        decision = self.evaluate_with(
            deepagents_proposal,
            deepagents_policy,
            openclaw_evidence,
        )

        self.assertEqual(decision.document["verdict"], "DENY")
        self.assertIn(
            "RUNTIME_DEPLOYMENT_BINDING_MISMATCH",
            decision.document["reason_codes"],
        )
        self.assertIn(
            "RUNTIME_EPOCH_BINDING_MISMATCH",
            decision.document["reason_codes"],
        )

    def test_runtime_identity_principal_mismatch_fails_closed(self) -> None:
        evidence = founder_evidence(
            self.request,
            self.keys,
            self.tenant_id,
            self.deepagents,
        )
        policy = founder_policy(
            self.keys,
            self.tenant_id,
            self.deepagents,
        )
        proposal = founder_proposal(
            self.request,
            evidence,
            self.keys,
            self.tenant_id,
            approve=False,
            runtime_profile=self.deepagents,
        )
        proposal["runtime_identity"]["principal"] = (
            "spiffe://mainstreet.local/tenant-founder/agent/openclaw"
        )

        decision = self.evaluate_with(proposal, policy, evidence)

        self.assertEqual(decision.document["verdict"], "DENY")
        self.assertIn(
            "RUNTIME_PRINCIPAL_BINDING_MISMATCH",
            decision.document["reason_codes"],
        )

    def test_runtime_profile_rejects_runtime_name_principal_confusion(self) -> None:
        confused = FounderRuntimeProfile(
            tenant_id=self.deepagents.tenant_id,
            runtime_name="deepagents",
            runtime_version=self.deepagents.runtime_version,
            principal="spiffe://mainstreet.local/tenant-founder/agent/openclaw",
            runtime_manifest_digest=self.deepagents.runtime_manifest_digest,
            skills_manifest_digest=self.deepagents.skills_manifest_digest,
            network_profile_digest=self.deepagents.network_profile_digest,
        )
        with self.assertRaisesRegex(
            FounderOSInputError, "principal must exactly bind tenant_id and runtime_name"
        ):
            founder_policy(self.keys, self.tenant_id, confused)

    def test_runtime_profile_rejects_malformed_manifest_digest(self) -> None:
        malformed = FounderRuntimeProfile(
            tenant_id=self.deepagents.tenant_id,
            runtime_name=self.deepagents.runtime_name,
            runtime_version=self.deepagents.runtime_version,
            principal=self.deepagents.principal,
            runtime_manifest_digest="sha256:not-a-digest",
            skills_manifest_digest=self.deepagents.skills_manifest_digest,
            network_profile_digest=self.deepagents.network_profile_digest,
        )
        with self.assertRaisesRegex(
            FounderOSInputError, "runtime_manifest_digest must be an exact sha256 digest"
        ):
            founder_evidence(
                self.request,
                self.keys,
                self.tenant_id,
                malformed,
            )

    def test_legacy_openclaw_proposal_remains_backward_compatible(self) -> None:
        evidence = founder_evidence(self.request, self.keys, self.tenant_id)
        policy = founder_policy(self.keys, self.tenant_id)
        proposal = founder_proposal(
            self.request,
            evidence,
            self.keys,
            self.tenant_id,
            approve=True,
        )

        self.assertEqual(
            proposal["principal"],
            "spiffe://mainstreet.local/tenant-founder/agent/openclaw",
        )
        self.assertNotIn("runtime_identity", proposal)
        deployment = next(
            item for item in evidence if item.get("type") == "deployment_certificate"
        )
        self.assertEqual(
            deployment["subject"],
            "mainstreet-tenant-founder-founder-os",
        )
        self.assertNotIn("runtime_name", deployment["content"])

        decision = self.evaluate_with(proposal, policy, evidence)
        self.assertEqual(decision.document["verdict"], "ALLOW")


if __name__ == "__main__":
    unittest.main()
