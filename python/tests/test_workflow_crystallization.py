from __future__ import annotations

import copy
import unittest

from mainstreet_crystallization import (
    AgentTrace,
    CrystallizationError,
    WorkflowCandidate,
    compile_action,
    learn_candidate,
    promotion_gate,
    render_python_module,
    shadow_compare,
)


POLICY = "sha256:policy-v1"


def trace(index: int, *, phone: str | None = None, body: str | None = None, risk: str = "external_communication", verdict: str = "ALLOW", outcome: str = "CONFIRMED_SUCCESS", policy: str = POLICY) -> AgentTrace:
    phone = phone or f"+1555000{index:04d}"
    body = body or "Hi! Would you like to schedule an intro session?"
    return AgentTrace(
        trace_id=f"trace-{index}",
        capability_id="send_lead_intro",
        risk_class=risk,
        input_facts={
            "lead_phone": phone,
            "message_body": body,
            "lead_status": "NEW",
            "sms_consent": True,
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


def trace_with_fact_key(index: int, key: str) -> AgentTrace:
    """Trace whose destination source uses a caller-chosen fact key."""
    base = trace(index)
    phone = base.input_facts["lead_phone"]
    facts = {k: v for k, v in base.input_facts.items() if k != "lead_phone"}
    facts[key] = phone
    return AgentTrace(
        trace_id=base.trace_id,
        capability_id=base.capability_id,
        risk_class=base.risk_class,
        input_facts=facts,
        proposed_action=base.proposed_action,
        claimsieve_verdict=base.claimsieve_verdict,
        terminal_outcome=base.terminal_outcome,
        policy_digest=base.policy_digest,
        evidence_root=base.evidence_root,
    )


class WorkflowCrystallizationTests(unittest.TestCase):
    def test_stable_repeated_agent_work_crystallizes(self) -> None:
        history = [trace(i) for i in range(1, 7)]
        candidate = learn_candidate(history, minimum_support=5)
        self.assertEqual(candidate.capability_id, "send_lead_intro")
        self.assertTrue(candidate.requires_claimsieve)
        self.assertFalse(candidate.autonomous_deployment_allowed)
        self.assertIn("lead_phone", candidate.required_facts)
        self.assertIn("message_body", candidate.required_facts)

        next_action = compile_action(
            candidate,
            {
                "lead_phone": "+15559990000",
                "message_body": "Welcome. Want to tour tomorrow?",
            },
            policy_digest=POLICY,
        )
        self.assertEqual(next_action["destination"]["authority"], "+15559990000")
        self.assertEqual(next_action["parameters"]["body"], "Welcome. Want to tour tomorrow?")
        self.assertEqual(next_action["kind"], "send_message")

    def test_variable_action_field_without_input_binding_fails_closed(self) -> None:
        history = [trace(i) for i in range(1, 6)]
        broken = []
        for i, item in enumerate(history):
            action = copy.deepcopy(item.proposed_action)
            action["parameters"]["campaign_nonce"] = f"n-{i}"
            broken.append(
                AgentTrace(
                    **{
                        **item.__dict__,
                        "proposed_action": action,
                    }
                )
            )
        with self.assertRaisesRegex(CrystallizationError, "varies without"):
            learn_candidate(broken, minimum_support=5)

    def test_denied_unknown_or_divergent_traces_are_not_training_authority(self) -> None:
        for verdict, outcome in (
            ("DENY", "NOT_EXECUTED"),
            ("ALLOW", "OUTCOME_UNKNOWN"),
            ("ALLOW", "DIVERGENT_EFFECT"),
            ("ALLOW", "CONFIRMED_FAILURE"),
        ):
            history = [trace(i) for i in range(1, 5)]
            history.append(trace(10, verdict=verdict, outcome=outcome))
            with self.subTest(verdict=verdict, outcome=outcome):
                with self.assertRaisesRegex(CrystallizationError, "learning set contains"):
                    learn_candidate(history, minimum_support=5)

    def test_high_risk_workflows_do_not_auto_crystallize(self) -> None:
        for risk in (
            "financial",
            "legal_compliance",
            "employment",
            "health_safety",
            "credential_security",
            "irreversible_high_impact",
        ):
            with self.subTest(risk=risk):
                with self.assertRaisesRegex(CrystallizationError, "high-risk"):
                    learn_candidate([trace(i, risk=risk) for i in range(1, 6)])

    def test_unknown_risk_class_fails_closed(self) -> None:
        history = [trace(i, risk="financal") for i in range(1, 6)]
        with self.assertRaisesRegex(CrystallizationError, "unknown risk class"):
            learn_candidate(history)

    def test_candidate_identity_binds_policy_and_bindings(self) -> None:
        candidate = learn_candidate([trace(i) for i in range(1, 6)])
        tampered = WorkflowCandidate(
            **{
                **candidate.__dict__,
                "required_policy_digest": "sha256:attacker-policy",
            }
        )
        with self.assertRaisesRegex(CrystallizationError, "candidate identity mismatch"):
            tampered.validate()

    def test_policy_drift_fails_closed(self) -> None:
        history = [trace(i) for i in range(1, 5)]
        history.append(trace(5, policy="sha256:policy-v2"))
        with self.assertRaisesRegex(CrystallizationError, "policy drift"):
            learn_candidate(history, minimum_support=5)

    def test_compiled_workflow_cannot_run_under_different_policy(self) -> None:
        candidate = learn_candidate([trace(i) for i in range(1, 6)])
        with self.assertRaisesRegex(CrystallizationError, "policy digest mismatch"):
            compile_action(
                candidate,
                {"lead_phone": "+15551112222", "message_body": "hello"},
                policy_digest="sha256:policy-v2",
            )

    def test_shadow_exact_match_can_pass_promotion_gate(self) -> None:
        candidate = learn_candidate([trace(i) for i in range(1, 7)])
        shadow = shadow_compare(candidate, [trace(i) for i in range(100, 125)])
        decision = promotion_gate(candidate, shadow, minimum_shadow_cases=20)
        self.assertEqual(shadow.exact_matches, 25)
        self.assertEqual(shadow.divergences, ())
        self.assertEqual(shadow.safety_violations, ())
        self.assertTrue(decision.promotable)
        self.assertEqual(decision.reasons, ())

    def test_shadow_divergence_blocks_promotion(self) -> None:
        candidate = learn_candidate([trace(i) for i in range(1, 7)])
        shadow_cases = [trace(i) for i in range(100, 124)]
        changed = trace(124)
        changed_action = copy.deepcopy(changed.proposed_action)
        changed_action["kind"] = "send_email"
        shadow_cases.append(AgentTrace(**{**changed.__dict__, "proposed_action": changed_action}))
        shadow = shadow_compare(candidate, shadow_cases)
        decision = promotion_gate(candidate, shadow, minimum_shadow_cases=20)
        self.assertIn("trace-124", shadow.divergences)
        self.assertFalse(decision.promotable)
        self.assertIn("shadow divergences present", decision.reasons)

    def test_shadow_policy_change_is_a_safety_violation(self) -> None:
        candidate = learn_candidate([trace(i) for i in range(1, 7)])
        shadow_cases = [trace(i) for i in range(100, 124)]
        shadow_cases.append(trace(124, policy="sha256:policy-v2"))
        shadow = shadow_compare(candidate, shadow_cases)
        decision = promotion_gate(candidate, shadow, minimum_shadow_cases=20)
        self.assertTrue(any("policy drift" in item for item in shadow.safety_violations))
        self.assertFalse(decision.promotable)

    def test_hostile_fact_names_cannot_inject_generated_code(self) -> None:
        hostile_keys = [
            "x')\n    print('INJECTED')\n    if 0:\n        raise ValueError('",
            "x'); print('INJECTED'); ('",
            "x\ny",
            "has space",
            "quote'name",
            "",
            "a" * 129,
        ]
        for key in hostile_keys:
            with self.subTest(key=key):
                history = [trace_with_fact_key(i, key) for i in range(1, 7)]
                with self.assertRaises(CrystallizationError):
                    candidate = learn_candidate(history, minimum_support=5)
                    render_python_module(candidate)

    def test_benign_unusual_fact_names_render_to_expected_ast(self) -> None:
        import ast

        history = [trace_with_fact_key(i, "lead.phone-number_2") for i in range(1, 7)]
        candidate = learn_candidate(history, minimum_support=5)
        source = render_python_module(candidate)
        tree = ast.parse(source)
        builder = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "build_proposal")
        calls = []
        for node in ast.walk(builder):
            if isinstance(node, ast.Call):
                self.assertIsInstance(node.func, ast.Name)
                calls.append(node.func.id)
        self.assertEqual(set(calls), {"ValueError", "_set_path"})
        self.assertNotIn("print", calls)
        self.assertNotIn("__import__", calls)
        self.assertNotIn("exec", calls)

    def test_function_name_must_not_be_a_keyword(self) -> None:
        candidate = learn_candidate([trace(i) for i in range(1, 7)], minimum_support=5)
        for name in ("class", "def", "import", "not an identifier"):
            with self.subTest(name=name):
                with self.assertRaises(CrystallizationError):
                    render_python_module(candidate, function_name=name)

    def test_codegen_rejects_string_subclasses_before_repr(self) -> None:
        class HostileStr(str):
            def __repr__(self) -> str:
                raise AssertionError("custom repr must never reach code generation")

        candidate = learn_candidate(
            [trace(i, policy=HostileStr(POLICY)) for i in range(1, 7)],
            minimum_support=5,
        )
        with self.assertRaisesRegex(CrystallizationError, "exact built-in"):
            render_python_module(candidate)

    def test_generated_python_is_proposal_only_and_equivalent(self) -> None:
        candidate = learn_candidate([trace(i) for i in range(1, 6)])
        source = render_python_module(candidate)
        self.assertNotIn("requests", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("socket", source)
        namespace: dict[str, object] = {}
        exec(source, namespace)
        generated = namespace["build_proposal"](
            {
                "lead_phone": "+15553334444",
                "message_body": "Can we schedule your tour?",
            },
            POLICY,
        )
        expected = compile_action(
            candidate,
            {
                "lead_phone": "+15553334444",
                "message_body": "Can we schedule your tour?",
            },
            policy_digest=POLICY,
        )
        self.assertEqual(generated["proposal"], expected)
        self.assertTrue(generated["requires_claimsieve"])
        self.assertFalse(generated["autonomous_execution_allowed"])

    def test_missing_runtime_fact_fails_closed(self) -> None:
        candidate = learn_candidate([trace(i) for i in range(1, 6)])
        with self.assertRaisesRegex(CrystallizationError, "missing required fact"):
            compile_action(
                candidate,
                {"lead_phone": "+15551112222"},
                policy_digest=POLICY,
            )


if __name__ == "__main__":
    unittest.main()
