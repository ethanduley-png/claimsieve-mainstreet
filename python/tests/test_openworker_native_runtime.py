from __future__ import annotations

import asyncio
import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

COWORKER_AVAILABLE = importlib.util.find_spec("coworker") is not None

if COWORKER_AVAILABLE:
    from coworker.engine import ApprovalOutcome
    from coworker.mcp.config import MCPServerDef
    from coworker.mcp.tools import build_callables, tool_name
    from coworker.permissions import Mode, PermissionEngine
    from coworker.providers.base import AssistantTurn, ModelCapabilities, ProviderClient, ToolCall
    from coworker.tools.registry import ToolRegistry

    from founder_os import FounderOSReferenceWorkflow
    from mainstreet_runtimes import ClaimSieveRuntimeContext, OpenWorkerProposalAdapter
    from mainstreet_runtimes.openworker_claimsieve_intake import OpenWorkerFounderIntake
    from mainstreet_runtimes.openworker_native_bridge import (
        PINNED_OPENWORKER_COMMIT,
        OpenWorkerNativeBridgeError,
        guarded_turn_engine_class,
        translate_native_tool_call,
        verify_pinned_openworker_runtime,
    )


@unittest.skipUnless(COWORKER_AVAILABLE, "pinned OpenWorker is installed only in its CI gate")
class OpenWorkerNativeRuntimeTests(unittest.IsolatedAsyncioTestCase):
    class _Provider(ProviderClient):
        def complete(self, *, model, messages, tools=None, **settings):
            return AssistantTurn(text="unused")

        def capabilities(self, model):
            return ModelCapabilities()

    async def asyncSetUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repository = "example/claimsieve-mainstreet"
        self.workflow = FounderOSReferenceWorkflow(
            self.root,
            allowed_repositories={self.repository},
            provider_mode="success",
            runtime_name="openworker",
            runtime_version=PINNED_OPENWORKER_COMMIT,
        )
        self.intake = OpenWorkerFounderIntake(self.workflow)
        self.context = ClaimSieveRuntimeContext(
            trace_id="trace-openworker-native-001",
            campaign_id="campaign-openworker-native-001",
            session_id="session-openworker-native-001",
            work_item_id="work-openworker-native-001",
            requested_at_seq=80,
        )
        self.adapter = OpenWorkerProposalAdapter(
            self.context,
            self.intake.route_intent,
            consequential_tools={"create_github_issue"},
        )
        self.registry = ToolRegistry()
        self.direct_connector_calls = 0

        def create_github_issue(repository: str, title: str, body: str):
            self.direct_connector_calls += 1
            return {"provider_executed": True}

        create_github_issue.__coworker_schema__ = {
            "type": "function",
            "function": {
                "name": "create_github_issue",
                "description": "test external write",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repository": {"type": "string"},
                        "title": {"type": "string"},
                        "body": {"type": "string"},
                    },
                    "required": ["repository", "title", "body"],
                    "additionalProperties": False,
                },
            },
        }
        self.registry.register(
            create_github_issue,
            metadata=SimpleNamespace(
                category="connector",
                risk_level="medium",
                requires_approval=True,
            ),
        )

    async def asyncTearDown(self) -> None:
        self.temp.cleanup()

    def native_call(self, *, call_id: str = "ow-native-001", title: str = "Native bridge"):
        return ToolCall(
            id=call_id,
            name="create_github_issue",
            arguments={
                "repository": self.repository,
                "title": title,
                "body": "A real OpenWorker ToolCall must stop before provider execution.",
            },
        )

    def make_engine(self, *, mode=Mode.BYPASS_APPROVALS, approver=None, tool_map=None):
        Engine = guarded_turn_engine_class()
        return Engine(
            provider=self._Provider(),
            registry=self.registry,
            permissions=PermissionEngine(self.root, mode=mode),
            model="test-model",
            approver=approver,
            claimsieve_adapter=self.adapter,
            native_tool_map=tool_map,
        )

    def test_installed_openworker_is_exact_pinned_git_commit(self) -> None:
        self.assertEqual(verify_pinned_openworker_runtime(), PINNED_OPENWORKER_COMMIT)

    def test_real_toolcall_translation_is_defensive_and_closed(self) -> None:
        call = self.native_call()
        boundary = translate_native_tool_call(call)
        self.assertEqual(boundary["schema_version"], "mainstreet.openworker_tool_call.v1")
        self.assertEqual(boundary["id"], call.id)
        self.assertEqual(boundary["name"], call.name)
        call.arguments["title"] = "mutated after capture"
        self.assertEqual(boundary["arguments"]["title"], "Native bridge")
        self.assertEqual(
            frozenset(boundary),
            frozenset({"schema_version", "id", "name", "arguments"}),
        )

    async def test_real_openworker_turn_intercepts_before_direct_connector_execution(self) -> None:
        engine = self.make_engine()
        events = [event async for event in engine._handle_tool_calls([self.native_call()])]
        self.assertTrue(events)
        self.assertEqual(self.direct_connector_calls, 0)
        self.assertEqual(len(self.workflow.ledger_records()["execution"]), 0)
        permit_ids = self.intake.pending_permits()
        self.assertEqual(len(permit_ids), 1)
        tool_results = [m for m in engine.messages if m.get("role") == "tool"]
        self.assertEqual(len(tool_results), 1)
        self.assertIn("PERMIT_ISSUED_EXECUTION_PENDING", str(tool_results[0]))

    async def test_openworker_human_approval_does_not_become_execution_authority(self) -> None:
        approvals = []

        async def approve_once(request):
            approvals.append((request.tool_call_id, request.tool_name))
            return ApprovalOutcome.ONCE

        engine = self.make_engine(mode=Mode.INTERACTIVE, approver=approve_once)
        events = [event async for event in engine._handle_tool_calls([self.native_call()])]
        self.assertTrue(events)
        self.assertEqual(approvals, [("ow-native-001", "create_github_issue")])
        self.assertEqual(self.direct_connector_calls, 0)
        self.assertEqual(len(self.workflow.ledger_records()["execution"]), 0)
        self.assertEqual(len(self.intake.pending_permits()), 1)

    def test_approval_replay_of_same_openworker_call_cannot_reenter_intake(self) -> None:
        engine = self.make_engine()
        first_result, first_status = engine._execute_sync(self.native_call())
        self.assertEqual(first_status, "ok")
        self.assertTrue(first_result["routed_to_claimsieve"])
        second_result, second_status = engine._execute_sync(self.native_call())
        self.assertEqual(second_status, "error")
        self.assertIn("duplicate OpenWorker tool call identity", second_result["error"])
        self.assertEqual(self.direct_connector_calls, 0)
        self.assertEqual(len(self.intake.pending_permits()), 1)

    def test_field_substitution_after_first_admission_fails_closed(self) -> None:
        engine = self.make_engine()
        first = self.native_call()
        _, status = engine._execute_sync(first)
        self.assertEqual(status, "ok")
        substituted = self.native_call(title="substituted title")
        result, status = engine._execute_sync(substituted)
        self.assertEqual(status, "error")
        self.assertIn("duplicate OpenWorker tool call identity", result["error"])
        self.assertEqual(self.direct_connector_calls, 0)

    async def test_mcp_tool_is_mapped_and_intercepted_before_remote_call(self) -> None:
        remote_calls = []

        async def call_async(remote, kwargs):
            remote_calls.append((remote, kwargs))
            return {"remote_executed": True}

        mcp_tool = SimpleNamespace(
            name="create_issue",
            description="create an issue over MCP",
            inputSchema={
                "type": "object",
                "properties": {
                    "repository": {"type": "string"},
                    "title": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["repository", "title", "body"],
            },
        )
        server = MCPServerDef(name="github", transport="http", requires_approval=False)
        native_name = tool_name(server.name, mcp_tool.name)
        callables = build_callables(
            server,
            [mcp_tool],
            call_async,
            asyncio.get_running_loop(),
            timeout=1,
        )
        self.assertEqual(len(callables), 1)
        self.registry.register(callables[0])
        engine = self.make_engine(
            tool_map={native_name: "create_github_issue"},
        )
        call = ToolCall(
            id="ow-mcp-001",
            name=native_name,
            arguments={
                "repository": self.repository,
                "title": "MCP must stop at ClaimSieve",
                "body": "The wrapped MCP remote callable must never run here.",
            },
        )
        events = [event async for event in engine._handle_tool_calls([call])]
        self.assertTrue(events)
        self.assertEqual(remote_calls, [])
        self.assertEqual(len(self.workflow.ledger_records()["execution"]), 0)
        self.assertEqual(len(self.intake.pending_permits()), 1)

    def test_benign_unmapped_tool_retains_native_registry_execution(self) -> None:
        benign_calls = []

        def local_lookup(value: str):
            benign_calls.append(value)
            return {"value": value}

        local_lookup.__coworker_schema__ = {
            "type": "function",
            "function": {
                "name": "local_lookup",
                "description": "benign local lookup",
                "parameters": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "required": ["value"],
                },
            },
        }
        self.registry.register(local_lookup)
        engine = self.make_engine()
        result, status = engine._execute_sync(
            ToolCall(id="benign-1", name="local_lookup", arguments={"value": "ok"})
        )
        self.assertEqual(status, "ok")
        self.assertEqual(result, {"value": "ok"})
        self.assertEqual(benign_calls, ["ok"])

    def test_runtime_drift_fails_before_guarded_engine_is_created(self) -> None:
        with patch(
            "mainstreet_runtimes.openworker_native_bridge.installed_openworker_commit",
            return_value="0" * 40,
        ):
            with self.assertRaisesRegex(OpenWorkerNativeBridgeError, "runtime drift"):
                verify_pinned_openworker_runtime()


if __name__ == "__main__":
    unittest.main()
