from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

COWORKER_AVAILABLE = importlib.util.find_spec("coworker") is not None


@unittest.skipUnless(COWORKER_AVAILABLE, "pinned OpenWorker is installed only in its CI gate")
class OpenWorkerBootstrapTests(unittest.TestCase):
    def test_real_upstream_build_engine_constructs_guard_and_blocks_connector(self) -> None:
        from coworker.agent import build_engine
        import coworker.agent as agent_module
        import coworker.engine as engine_module
        from coworker.agents import code_agent
        from coworker.permissions import Mode
        from coworker.providers.base import AssistantTurn, ModelCapabilities, ProviderClient, ToolCall

        from mainstreet_runtimes import ClaimSieveRuntimeContext, OpenWorkerProposalAdapter
        from mainstreet_runtimes.openworker_bootstrap import (
            install_production_turn_engine_guard,
            verify_production_turn_engine_guard_installed,
        )

        class Provider(ProviderClient):
            def complete(self, *, model, messages, tools=None, **settings):
                return AssistantTurn(text="unused")

            def capabilities(self, model):
                return ModelCapabilities()

        routed = []
        executed = []
        context = ClaimSieveRuntimeContext(
            trace_id="trace-bootstrap",
            campaign_id="campaign-bootstrap",
            session_id="session-bootstrap",
            work_item_id="work-bootstrap",
            requested_at_seq=1,
        )
        adapter = OpenWorkerProposalAdapter(
            context,
            lambda intent: routed.append(intent) or {"status": "test-only"},
            consequential_tools={"create_github_issue"},
        )

        def connector(repository: str, title: str, body: str):
            executed.append((repository, title, body))
            return {"provider_executed": True}

        connector.__name__ = "native_create_issue"
        connector.__coworker_schema__ = {
            "type": "function",
            "function": {
                "name": "native_create_issue",
                "description": "test connector",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repository": {"type": "string"},
                        "title": {"type": "string"},
                        "body": {"type": "string"},
                    },
                    "required": ["repository", "title", "body"],
                },
            },
        }
        connector.__aisuite_metadata__ = SimpleNamespace(
            category="connector", risk_level="medium", requires_approval=True
        )

        native = engine_module.TurnEngine
        self.addCleanup(setattr, agent_module, "TurnEngine", native)
        Guarded = install_production_turn_engine_guard(
            adapter, native_tool_map={"native_create_issue": "create_github_issue"}
        )
        verify_production_turn_engine_guard_installed()

        with tempfile.TemporaryDirectory() as temp:
            engine = build_engine(
                agent=code_agent(),
                workspace=Path(temp),
                provider=Provider(),
                model="test-model",
                mode=Mode.BYPASS_APPROVALS,
                extra_tools=[connector],
            )
            self.assertIsInstance(engine, Guarded)
            result, status = engine._execute_sync(
                ToolCall(
                    id="bootstrap-call-1",
                    name="native_create_issue",
                    arguments={
                        "repository": "example/repo",
                        "title": "Guard actual build path",
                        "body": "The native connector must not execute.",
                    },
                )
            )
        self.assertEqual(status, "ok")
        self.assertEqual(executed, [])
        self.assertEqual(len(routed), 1)
        self.assertEqual(routed[0]["tool_name"], "create_github_issue")

    def test_second_or_ambiguous_guard_binding_is_rejected(self) -> None:
        import coworker.agent as agent_module
        import coworker.engine as engine_module
        from mainstreet_runtimes import ClaimSieveRuntimeContext, OpenWorkerProposalAdapter
        from mainstreet_runtimes.openworker_bootstrap import (
            OpenWorkerBootstrapError,
            install_production_turn_engine_guard,
        )

        adapter = OpenWorkerProposalAdapter(
            ClaimSieveRuntimeContext(
                trace_id="trace-bootstrap-2",
                campaign_id="campaign-bootstrap-2",
                session_id="session-bootstrap-2",
                work_item_id="work-bootstrap-2",
                requested_at_seq=1,
            ),
            lambda intent: {},
            consequential_tools={"create_github_issue"},
        )
        native = engine_module.TurnEngine
        self.addCleanup(setattr, agent_module, "TurnEngine", native)
        install_production_turn_engine_guard(adapter)
        with self.assertRaisesRegex(OpenWorkerBootstrapError, "already modified"):
            install_production_turn_engine_guard(adapter)


if __name__ == "__main__":
    unittest.main()
