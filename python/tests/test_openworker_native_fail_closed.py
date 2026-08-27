from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

COWORKER_AVAILABLE = importlib.util.find_spec("coworker") is not None

if COWORKER_AVAILABLE:
    from coworker.permissions import Mode, PermissionEngine
    from coworker.providers.base import AssistantTurn, ModelCapabilities, ProviderClient, ToolCall
    from coworker.tools.registry import ToolRegistry

    from founder_os import FounderOSReferenceWorkflow
    from mainstreet_runtimes import ClaimSieveRuntimeContext, OpenWorkerProposalAdapter
    from mainstreet_runtimes.openworker_claimsieve_intake import OpenWorkerFounderIntake
    from mainstreet_runtimes.openworker_native_bridge import (
        PINNED_OPENWORKER_COMMIT,
        guarded_turn_engine_class,
    )


@unittest.skipUnless(COWORKER_AVAILABLE, "pinned OpenWorker is installed only in its CI gate")
class OpenWorkerNativeFailClosedTests(unittest.TestCase):
    class _Provider(ProviderClient):
        def complete(self, *, model, messages, tools=None, **settings):
            return AssistantTurn(text="unused")

        def capabilities(self, model):
            return ModelCapabilities()

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        workflow = FounderOSReferenceWorkflow(
            self.root,
            allowed_repositories={"example/claimsieve-mainstreet"},
            provider_mode="success",
            runtime_name="openworker",
            runtime_version=PINNED_OPENWORKER_COMMIT,
        )
        intake = OpenWorkerFounderIntake(workflow)
        adapter = OpenWorkerProposalAdapter(
            ClaimSieveRuntimeContext(
                trace_id="trace-fail-closed",
                campaign_id="campaign-fail-closed",
                session_id="session-fail-closed",
                work_item_id="work-fail-closed",
                requested_at_seq=90,
            ),
            intake.route_intent,
            consequential_tools={"create_github_issue"},
        )
        self.registry = ToolRegistry()
        Engine = guarded_turn_engine_class()
        self.engine = Engine(
            provider=self._Provider(),
            registry=self.registry,
            permissions=PermissionEngine(self.root, mode=Mode.BYPASS_APPROVALS),
            model="test-model",
            claimsieve_adapter=adapter,
        )
        self.native_calls = []

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def _schema(name: str) -> dict:
        return {
            "type": "function",
            "function": {
                "name": name,
                "description": "external test tool",
                "parameters": {"type": "object", "properties": {}},
            },
        }

    def _register_external(self, name: str, category: str, requires_approval: bool) -> None:
        def external_tool():
            self.native_calls.append(name)
            return {"native_executed": True}

        external_tool.__name__ = name
        external_tool.__coworker_schema__ = self._schema(name)
        self.registry.register(
            external_tool,
            metadata=SimpleNamespace(
                category=category,
                risk_level="low",
                requires_approval=requires_approval,
            ),
        )

    def test_unmapped_connector_cannot_bypass_claimsieve_by_using_new_tool_name(self) -> None:
        self._register_external("unmapped_connector_write", "connector", False)
        result, status = self.engine._execute_sync(
            ToolCall(id="connector-bypass-1", name="unmapped_connector_write", arguments={})
        )
        self.assertEqual(status, "error")
        self.assertIn("unmapped consequential OpenWorker tool", result["error"])
        self.assertEqual(self.native_calls, [])

    def test_unmapped_mcp_tool_cannot_bypass_claimsieve_when_openworker_approval_is_disabled(self) -> None:
        self._register_external("mcp__unknown__external_write", "mcp", False)
        result, status = self.engine._execute_sync(
            ToolCall(id="mcp-bypass-1", name="mcp__unknown__external_write", arguments={})
        )
        self.assertEqual(status, "error")
        self.assertIn("unmapped consequential OpenWorker tool", result["error"])
        self.assertEqual(self.native_calls, [])

    def test_unmapped_requires_approval_plugin_cannot_fall_through_even_outside_known_categories(self) -> None:
        self._register_external("third_party_side_effect", "plugin", True)
        result, status = self.engine._execute_sync(
            ToolCall(id="plugin-bypass-1", name="third_party_side_effect", arguments={})
        )
        self.assertEqual(status, "error")
        self.assertIn("unmapped consequential OpenWorker tool", result["error"])
        self.assertEqual(self.native_calls, [])


if __name__ == "__main__":
    unittest.main()
