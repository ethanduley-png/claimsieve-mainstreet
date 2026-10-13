from __future__ import annotations

import unittest

from mainstreet_runtimes import ClaimSieveRuntimeContext, DeepAgentsProposalAdapter

try:
    from mainstreet_runtimes.deepagents_middleware import ClaimSieveDeepAgentsMiddleware
    from mainstreet_runtimes.deepagents_runtime import (
        DeepAgentsRuntimeSafetyError,
        create_claimsieve_deep_agent,
        prepare_governed_subagents,
    )

    DEEPAGENTS_AVAILABLE = True
except ImportError:
    ClaimSieveDeepAgentsMiddleware = None
    DeepAgentsRuntimeSafetyError = None
    create_claimsieve_deep_agent = None
    prepare_governed_subagents = None
    DEEPAGENTS_AVAILABLE = False


@unittest.skipUnless(DEEPAGENTS_AVAILABLE, "deepagents optional dependency is not installed")
class GovernedDeepAgentsRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        context = ClaimSieveRuntimeContext(
            trace_id="trace-runtime-001",
            campaign_id="campaign-runtime-001",
            session_id="session-runtime-001",
            work_item_id="work-runtime-001",
            requested_at_seq=50,
        )
        self.adapter = DeepAgentsProposalAdapter(
            context,
            lambda intent: {"status": "PERMIT_PENDING"},
        )

    @staticmethod
    def middleware_names(spec: dict) -> list[str]:
        return [getattr(item, "name", type(item).__name__) for item in spec["middleware"]]

    def test_explicit_general_purpose_subagent_is_always_claimsieve_guarded(self) -> None:
        prepared = prepare_governed_subagents(
            tools=[],
            adapter=self.adapter,
            subagents=None,
        )
        general = prepared[0]
        self.assertEqual(general["name"], "general-purpose")
        self.assertIn(ClaimSieveDeepAgentsMiddleware.name, self.middleware_names(general))

    def test_raw_subagent_receives_claimsieve_middleware(self) -> None:
        prepared = prepare_governed_subagents(
            tools=[],
            adapter=self.adapter,
            subagents=[
                {
                    "name": "sales",
                    "description": "Draft and propose sales actions.",
                    "system_prompt": "Stay on the proposal side.",
                    "tools": [],
                }
            ],
        )
        sales = next(item for item in prepared if item["name"] == "sales")
        self.assertIn(ClaimSieveDeepAgentsMiddleware.name, self.middleware_names(sales))
        self.assertEqual(
            sum(
                name == ClaimSieveDeepAgentsMiddleware.name
                for name in self.middleware_names(sales)
            ),
            1,
        )

    def test_compiled_subagent_is_rejected(self) -> None:
        with self.assertRaisesRegex(DeepAgentsRuntimeSafetyError, "compiled subagents"):
            prepare_governed_subagents(
                tools=[],
                adapter=self.adapter,
                subagents=[
                    {
                        "name": "compiled",
                        "description": "opaque runnable",
                        "runnable": object(),
                    }
                ],
            )

    def test_remote_async_subagent_is_rejected(self) -> None:
        with self.assertRaisesRegex(DeepAgentsRuntimeSafetyError, "remote async subagents"):
            prepare_governed_subagents(
                tools=[],
                adapter=self.adapter,
                subagents=[
                    {
                        "name": "remote",
                        "description": "remote graph",
                        "graph_id": "graph-001",
                    }
                ],
            )

    def test_claimsieve_middleware_shadowing_is_rejected(self) -> None:
        class FakeGate:
            name = "ClaimSieveDeepAgentsMiddleware"

        with self.assertRaisesRegex(DeepAgentsRuntimeSafetyError, "replace or shadow"):
            prepare_governed_subagents(
                tools=[],
                adapter=self.adapter,
                subagents=[
                    {
                        "name": "sales",
                        "description": "attempt shadow",
                        "system_prompt": "test",
                        "tools": [],
                        "middleware": [FakeGate()],
                    }
                ],
            )

    def test_unclassified_main_tool_is_denied(self) -> None:
        def mystery_write() -> str:
            return "should never be admitted without classification"

        with self.assertRaisesRegex(DeepAgentsRuntimeSafetyError, "unclassified"):
            prepare_governed_subagents(
                tools=[mystery_write],
                adapter=self.adapter,
            )

    def test_explicit_benign_main_tool_is_allowed(self) -> None:
        def lookup_customer() -> str:
            return "read-only fixture"

        prepared = prepare_governed_subagents(
            tools=[lookup_customer],
            adapter=self.adapter,
            allowed_benign_tool_names={"lookup_customer"},
        )
        general = prepared[0]
        self.assertEqual(general["tools"][0].__name__, "lookup_customer")

    def test_consequential_main_tool_is_allowed_but_not_benign(self) -> None:
        def issue_refund() -> str:
            return "provider path must be intercepted"

        prepared = prepare_governed_subagents(
            tools=[issue_refund],
            adapter=self.adapter,
        )
        general = prepared[0]
        self.assertEqual(general["tools"][0].__name__, "issue_refund")

        with self.assertRaisesRegex(DeepAgentsRuntimeSafetyError, "both benign and consequential"):
            prepare_governed_subagents(
                tools=[issue_refund],
                adapter=self.adapter,
                allowed_benign_tool_names={"issue_refund"},
            )

    def test_unclassified_subagent_tool_is_denied(self) -> None:
        def hidden_provider_write() -> str:
            return "must not enter a subagent"

        with self.assertRaisesRegex(DeepAgentsRuntimeSafetyError, "unclassified"):
            prepare_governed_subagents(
                tools=[],
                adapter=self.adapter,
                subagents=[
                    {
                        "name": "sales",
                        "description": "attempt hidden tool",
                        "system_prompt": "test",
                        "tools": [hidden_provider_write],
                    }
                ],
            )

    def test_governed_factory_rejects_caller_backend(self) -> None:
        with self.assertRaisesRegex(DeepAgentsRuntimeSafetyError, "StateBackend"):
            create_claimsieve_deep_agent(
                model="openai:gpt-5.5",
                adapter=self.adapter,
                tools=[],
                backend=object(),
            )


if __name__ == "__main__":
    unittest.main()
