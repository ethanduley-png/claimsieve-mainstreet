from __future__ import annotations

import unittest

from claimsieve_ref.crypto import KeyPair
from mainstreet_crystallization.assurance import (
    AgentTrace,
    CrystallizationError,
    DriftMonitor,
    HardenedWorkflow,
    SignedAgentTrace,
    learn_hardened_workflow,
    observe_signed_execution,
    route_work,
    sign_trace,
    verify_signed_trace,
)


POLICY = "sha256:policy-v1"
SIGNER = KeyPair.from_seed("observer-key-1", b"\x11" * 32)
TRUST = {SIGNER.key_id: SIGNER.public}


def trace(
    index: int,
    *,
    status: str = "NEW",
    consent: bool = True,
    verdict: str = "ALLOW",
    outcome: str = "CONFIRMED_SUCCESS",
    policy: str = POLICY,
    body: str | None = None,
) -> AgentTrace:
    phone = f"+1555000{index:04d}"
    body = body or f"Hi lead {index}, want to schedule?"
    return AgentTrace(
        trace_id=f"trace-{index}",
        capability_id="send_lead_intro",
        risk_class="external_communication",
        input_facts={
            "lead_phone": phone,
            "message_body": body,
            "lead_status": status,
            "sms_consent": consent,
        },
        proposed_action={
            "kind": "send_message",
            "destination": {
                "scheme": "sms",
                "authority": phone,
                "trust_domain": "sms-provider",
            },
            "parameters": {"body": body},
            "effect_class": "external_write",
        },
        claimsieve_verdict=verdict,
        terminal_outcome=outcome,
        policy_digest=policy,
        evidence_root=f"sha256:evidence-{index}",
    )


def build_profile() -> HardenedWorkflow:
    positives = [sign_trace(trace(i), SIGNER) for i in range(1, 7)]
    negatives = [
        sign_trace(
            trace(50, consent=False, verdict="DENY", outcome="NOT_EXECUTED"),
            SIGNER,
        ),
        sign_trace(
            trace(
                51,
                status="EXISTING_MEMBER",
                verdict="REVIEW",
                outcome="NOT_EXECUTED",
            ),
            SIGNER,
        ),
    ]
    return learn_hardened_workflow(
        positives + negatives,
        TRUST,
        minimum_support=5,
        minimum_negative_examples=2,
    )


class WorkflowCrystallizationAssuranceTests(unittest.TestCase):
    def test_signed_trace_verifies(self) -> None:
        envelope = sign_trace(trace(1), SIGNER)
        self.assertEqual(verify_signed_trace(envelope, TRUST).trace_id, "trace-1")

    def test_tampered_trace_rejected(self) -> None:
        envelope = sign_trace(trace(1), SIGNER)
        tampered_trace = AgentTrace(
            **{
                **envelope.trace.__dict__,
                "evidence_root": "sha256:evil",
            }
        )
        tampered = SignedAgentTrace(
            envelope.schema_version,
            envelope.signer_key_id,
            tampered_trace,
            envelope.signature,
        )
        with self.assertRaisesRegex(CrystallizationError, "signature verification failed"):
            verify_signed_trace(tampered, TRUST)

    def test_untrusted_signer_rejected(self) -> None:
        other = KeyPair.from_seed("other", b"\x22" * 32)
        with self.assertRaisesRegex(CrystallizationError, "untrusted signer"):
            verify_signed_trace(sign_trace(trace(1), other), TRUST)

    def test_hardened_profile_learns_explicit_safe_input_guards(self) -> None:
        profile = build_profile()
        self.assertEqual(
            {guard.fact_name: guard.expected_value for guard in profile.guards},
            {"lead_status": "NEW", "sms_consent": True},
        )
        self.assertTrue(profile.requires_claimsieve)
        self.assertFalse(profile.autonomous_execution_allowed)
        profile.validate()

    def test_unresolved_negative_example_fails_closed(self) -> None:
        positives = [sign_trace(trace(i), SIGNER) for i in range(1, 7)]
        consent_denial = sign_trace(
            trace(60, consent=False, verdict="DENY", outcome="NOT_EXECUTED"),
            SIGNER,
        )
        unexplained_denial = sign_trace(
            trace(61, verdict="DENY", outcome="NOT_EXECUTED"),
            SIGNER,
        )
        with self.assertRaisesRegex(CrystallizationError, "unresolved negative"):
            learn_hardened_workflow(
                positives + [consent_denial, unexplained_denial],
                TRUST,
                minimum_support=5,
            )

    def test_profile_identity_detects_material_tampering(self) -> None:
        profile = build_profile()
        tampered = HardenedWorkflow(
            **{
                **profile.__dict__,
                "negative_count": profile.negative_count + 1,
            }
        )
        with self.assertRaisesRegex(CrystallizationError, "identity mismatch"):
            tampered.validate()

    def test_within_envelope_routes_deterministic_proposal_only(self) -> None:
        profile = build_profile()
        inputs = {
            "lead_phone": "+15559990000",
            "message_body": "hello",
            "lead_status": "NEW",
            "sms_consent": True,
        }
        decision = route_work(profile, inputs, policy_digest=POLICY)
        self.assertEqual(decision.mode, "DETERMINISTIC_PROPOSAL")
        self.assertEqual(decision.proposal["destination"]["authority"], "+15559990000")
        self.assertTrue(decision.requires_claimsieve)
        self.assertFalse(decision.autonomous_execution_allowed)

    def test_guard_mismatch_routes_to_agent_fallback(self) -> None:
        profile = build_profile()
        inputs = {
            "lead_phone": "+15559990000",
            "message_body": "hello",
            "lead_status": "NEW",
            "sms_consent": False,
        }
        decision = route_work(profile, inputs, policy_digest=POLICY)
        self.assertEqual(decision.mode, "AGENT_FALLBACK")
        self.assertIsNone(decision.proposal)
        self.assertEqual(decision.reason, "guard_mismatch:sms_consent")

    def test_policy_drift_routes_to_agent_fallback(self) -> None:
        profile = build_profile()
        inputs = {
            "lead_phone": "+1",
            "message_body": "x",
            "lead_status": "NEW",
            "sms_consent": True,
        }
        decision = route_work(profile, inputs, policy_digest="sha256:policy-v2")
        self.assertEqual(decision.mode, "AGENT_FALLBACK")
        self.assertEqual(decision.reason, "policy_drift")
        self.assertIsNone(decision.proposal)

    def test_missing_dynamic_fact_routes_to_agent_fallback(self) -> None:
        profile = build_profile()
        inputs = {
            "message_body": "x",
            "lead_status": "NEW",
            "sms_consent": True,
        }
        decision = route_work(profile, inputs, policy_digest=POLICY)
        self.assertEqual(decision.mode, "AGENT_FALLBACK")
        self.assertEqual(decision.reason, "runtime_fact_mismatch")

    def test_outside_envelope_observation_does_not_poison_monitor(self) -> None:
        profile = build_profile()
        monitor = DriftMonitor(window_size=3, max_divergences=0)
        envelope = sign_trace(
            trace(70, consent=False, verdict="DENY", outcome="NOT_EXECUTED"),
            SIGNER,
        )
        observation = observe_signed_execution(profile, envelope, TRUST, monitor)
        self.assertFalse(observation.eligible_for_monitor)
        self.assertFalse(monitor.tripped)
        self.assertEqual(monitor.observation_count, 0)

    def test_denied_in_envelope_execution_trips_monitor_immediately(self) -> None:
        profile = build_profile()
        monitor = DriftMonitor(window_size=5, max_divergences=1)
        envelope = sign_trace(
            trace(71, verdict="DENY", outcome="NOT_EXECUTED"),
            SIGNER,
        )
        observation = observe_signed_execution(profile, envelope, TRUST, monitor)
        self.assertTrue(observation.safety_violation)
        self.assertTrue(monitor.tripped)

        inputs = {
            "lead_phone": "+1",
            "message_body": "x",
            "lead_status": "NEW",
            "sms_consent": True,
        }
        decision = route_work(
            profile,
            inputs,
            policy_digest=POLICY,
            monitor=monitor,
        )
        self.assertEqual(decision.mode, "AGENT_FALLBACK")
        self.assertIsNone(decision.proposal)

    def test_behavioral_drift_trips_after_threshold(self) -> None:
        profile = build_profile()
        monitor = DriftMonitor(window_size=4, max_divergences=1)
        for index in (80, 81):
            observe_signed_execution(
                profile,
                sign_trace(trace(index), SIGNER),
                TRUST,
                monitor,
            )
        for index in (82, 83):
            observe_signed_execution(
                profile,
                sign_trace(trace(index, outcome="CONFIRMED_FAILURE"), SIGNER),
                TRUST,
                monitor,
            )

        self.assertTrue(monitor.tripped)
        self.assertEqual(monitor.divergence_count, 2)
        inputs = {
            "lead_phone": "+1",
            "message_body": "x",
            "lead_status": "NEW",
            "sms_consent": True,
        }
        decision = route_work(
            profile,
            inputs,
            policy_digest=POLICY,
            monitor=monitor,
        )
        self.assertEqual(decision.mode, "AGENT_FALLBACK")
        self.assertTrue(decision.reason.startswith("runtime_drift:"))

    def test_invalid_signed_execution_evidence_trips_monitor(self) -> None:
        profile = build_profile()
        monitor = DriftMonitor(window_size=3, max_divergences=0)
        envelope = sign_trace(trace(90), SIGNER)
        tampered_trace = AgentTrace(
            **{
                **envelope.trace.__dict__,
                "evidence_root": "sha256:tampered",
            }
        )
        tampered = SignedAgentTrace(
            envelope.schema_version,
            envelope.signer_key_id,
            tampered_trace,
            envelope.signature,
        )
        with self.assertRaises(CrystallizationError):
            observe_signed_execution(profile, tampered, TRUST, monitor)
        self.assertTrue(monitor.tripped)
        self.assertEqual(monitor.tripped_reason, "invalid_signed_execution_evidence")


if __name__ == "__main__":
    unittest.main()
