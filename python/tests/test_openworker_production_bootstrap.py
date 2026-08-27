from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

COWORKER_AVAILABLE = importlib.util.find_spec("coworker") is not None


@unittest.skipUnless(COWORKER_AVAILABLE, "pinned OpenWorker is installed only in its CI gate")
class OpenWorkerProductionBootstrapTests(unittest.TestCase):
    def test_real_build_engine_uses_per_session_durable_context_and_mtls_client_type(self) -> None:
        import coworker.agent as agent_module
        import coworker.engine as engine_module
        from coworker.agent import build_engine
        from coworker.agents import code_agent
        from coworker.permissions import Mode
        from coworker.providers.base import AssistantTurn, ModelCapabilities, ProviderClient, ToolCall

        from mainstreet_runtimes.openworker_bootstrap import (
            install_production_runtime_guard,
            verify_production_turn_engine_guard_installed,
        )
        from mainstreet_runtimes.openworker_context import OpenWorkerProductionContextStore
        from mainstreet_runtimes.openworker_ipc import OpenWorkerClaimSieveHTTPSClient

        class Provider(ProviderClient):
            def complete(self, *, model, messages, tools=None, **settings):
                return AssistantTurn(text="unused")

            def capabilities(self, model):
                return ModelCapabilities()

        executed = []
        routed = []

        def connector(repository: str, title: str, body: str):
            executed.append(True)
            return {"provider_executed": True}

        connector.__name__ = "native_create_issue"
        connector.__coworker_schema__ = {
            "type": "function",
            "function": {
                "name": "native_create_issue",
                "description": "test connector",
                "parameters": {"type": "object", "properties": {}},
            },
        }
        connector.__aisuite_metadata__ = SimpleNamespace(
            category="connector", risk_level="medium", requires_approval=True
        )

        client = OpenWorkerClaimSieveHTTPSClient.__new__(OpenWorkerClaimSieveHTTPSClient)
        client.route_intent = lambda intent: routed.append(intent) or {
            "schema_version": "mainstreet.claimsieve_intake_receipt.v1",
            "status": "PERMIT_ISSUED_EXECUTION_PENDING",
        }

        native = engine_module.TurnEngine
        self.addCleanup(setattr, agent_module, "TurnEngine", native)
        with tempfile.TemporaryDirectory() as temp:
            context_store = OpenWorkerProductionContextStore(Path(temp) / "context.sqlite3")
            Guarded = install_production_runtime_guard(
                client,
                context_store,
                consequential_tools={"create_github_issue"},
                native_tool_map={"native_create_issue": "create_github_issue"},
            )
            verify_production_turn_engine_guard_installed()
            engine = build_engine(
                agent=code_agent(),
                workspace=Path(temp),
                provider=Provider(),
                model="test-model",
                mode=Mode.BYPASS_APPROVALS,
                extra_tools=[connector],
                session_id="real-openworker-session-123",
            )
            self.assertIsInstance(engine, Guarded)
            result, status = engine._execute_sync(
                ToolCall(
                    id="real-call-1",
                    name="native_create_issue",
                    arguments={
                        "repository": "example/repo",
                        "title": "Real session context",
                        "body": "Guarded before provider execution.",
                    },
                )
            )
            self.assertEqual(status, "ok")
            self.assertEqual(executed, [])
            self.assertEqual(len(routed), 1)
            context = routed[0]["context"]
            self.assertEqual(context["session_id"], "real-openworker-session-123")
            self.assertEqual(context["requested_at_seq"], 1)

            engine2 = build_engine(
                agent=code_agent(),
                workspace=Path(temp),
                provider=Provider(),
                model="test-model",
                mode=Mode.BYPASS_APPROVALS,
                extra_tools=[connector],
                session_id="real-openworker-session-456",
            )
            _, status2 = engine2._execute_sync(
                ToolCall(
                    id="real-call-2",
                    name="native_create_issue",
                    arguments={
                        "repository": "example/repo",
                        "title": "Second session",
                        "body": "Separate session, durable sequence.",
                    },
                )
            )
            self.assertEqual(status2, "ok")
            self.assertEqual(routed[1]["context"]["session_id"], "real-openworker-session-456")
            self.assertEqual(routed[1]["context"]["requested_at_seq"], 2)


if __name__ == "__main__":
    unittest.main()
