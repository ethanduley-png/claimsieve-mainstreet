from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

COWORKER_AVAILABLE = importlib.util.find_spec("coworker") is not None


class OpenWorkerProductionTokenTests(unittest.TestCase):
    def test_token_file_is_required_and_bounded(self) -> None:
        from mainstreet_runtimes.openworker_production_server import (
            OpenWorkerProductionServerError,
            _load_api_token,
        )

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            missing = root / "missing"
            with self.assertRaisesRegex(OpenWorkerProductionServerError, "required OpenWorker API token"):
                _load_api_token(missing)

            short = root / "short"
            short.write_text("too-short", encoding="utf-8")
            with self.assertRaisesRegex(OpenWorkerProductionServerError, "32-512"):
                _load_api_token(short)

            good = root / "good"
            good.write_text("a" * 64 + "\n", encoding="utf-8")
            self.assertEqual(_load_api_token(good), "a" * 64)


@unittest.skipUnless(COWORKER_AVAILABLE, "pinned OpenWorker is installed only in its CI gate")
class OpenWorkerProductionServerTests(unittest.TestCase):
    class _TLS:
        minimum_version = None
        check_hostname = None
        verify_mode = None

        def load_cert_chain(self, certfile, keyfile):
            self.certfile = certfile
            self.keyfile = keyfile

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.identity = self.root / "identity"
        self.identity.mkdir()
        for name in ("ca.crt", "tls.crt", "tls.key"):
            (self.identity / name).write_text("fixture", encoding="utf-8")

        import coworker.agent as agent_module
        import coworker.engine as engine_module
        import coworker.server.manager as manager_module

        self.agent_module = agent_module
        self.manager_module = manager_module
        self.native_turn_engine = engine_module.TurnEngine
        self.native_secret_store = manager_module.SecretStore
        self.addCleanup(setattr, agent_module, "TurnEngine", self.native_turn_engine)
        self.addCleanup(setattr, manager_module, "SecretStore", self.native_secret_store)
        self.old_api_token = os.environ.get("COWORKER_API_TOKEN")

    def tearDown(self) -> None:
        if self.old_api_token is None:
            os.environ.pop("COWORKER_API_TOKEN", None)
        else:
            os.environ["COWORKER_API_TOKEN"] = self.old_api_token
        self.temp.cleanup()

    def test_direct_factory_cannot_create_tokenless_production_app(self) -> None:
        from mainstreet_runtimes.openworker_production_server import (
            OpenWorkerProductionServerError,
            build_production_app,
        )

        os.environ.pop("COWORKER_API_TOKEN", None)
        with self.assertRaisesRegex(OpenWorkerProductionServerError, "COWORKER_API_TOKEN"):
            build_production_app(state_dir=self.state, mtls_dir=self.identity)

    def test_app_uses_gateway_no_credentials_and_guarded_engine_constructor(self) -> None:
        from mainstreet_runtimes.openworker_model_gateway import (
            MainStreetOpenWorkerModelGatewayProvider,
        )
        from mainstreet_runtimes.openworker_no_credentials import NoCredentialSecretStore
        from mainstreet_runtimes.openworker_production_server import build_production_app

        os.environ["COWORKER_API_TOKEN"] = "t" * 64
        with patch(
            "mainstreet_runtimes.openworker_ipc.ssl.create_default_context",
            return_value=self._TLS(),
        ), patch(
            "mainstreet_runtimes.openworker_model_gateway.ssl.create_default_context",
            return_value=self._TLS(),
        ):
            app = build_production_app(state_dir=self.state, mtls_dir=self.identity)

        manager = app.state.manager
        self.assertTrue(app.state.mainstreet_production_runtime)
        self.assertTrue(app.state.mainstreet_no_credentials)
        self.assertTrue(app.state.mainstreet_claimsieve_guard)
        self.assertIsInstance(manager.secrets, NoCredentialSecretStore)
        self.assertIsInstance(manager.provider, MainStreetOpenWorkerModelGatewayProvider)
        self.assertTrue(
            getattr(self.agent_module.TurnEngine, "__claimsieve_production_guard__", False)
        )
        self.assertIs(self.manager_module.SecretStore, NoCredentialSecretStore)

    def test_default_native_map_routes_github_create_issue_name(self) -> None:
        from coworker.providers.base import ToolCall
        from types import SimpleNamespace

        from mainstreet_runtimes.openworker_ipc import OpenWorkerClaimSieveHTTPSClient
        from mainstreet_runtimes.openworker_production_server import build_production_app

        routed = []
        os.environ["COWORKER_API_TOKEN"] = "t" * 64

        with patch(
            "mainstreet_runtimes.openworker_ipc.ssl.create_default_context",
            return_value=self._TLS(),
        ), patch(
            "mainstreet_runtimes.openworker_model_gateway.ssl.create_default_context",
            return_value=self._TLS(),
        ), patch.object(
            OpenWorkerClaimSieveHTTPSClient,
            "route_intent",
            autospec=True,
            side_effect=lambda _self, intent: routed.append(intent)
            or {
                "schema_version": "mainstreet.claimsieve_intake_receipt.v1",
                "status": "PERMIT_ISSUED_EXECUTION_PENDING",
            },
        ):
            app = build_production_app(state_dir=self.state, mtls_dir=self.identity)

            engine_class = self.agent_module.TurnEngine
            executed = []

            def github_create_issue(repository: str, title: str, body: str):
                executed.append(True)
                return {"executed": True}

            github_create_issue.__name__ = "github_create_issue"
            github_create_issue.__coworker_schema__ = {
                "type": "function",
                "function": {
                    "name": "github_create_issue",
                    "description": "fixture",
                    "parameters": {"type": "object", "properties": {}},
                },
            }
            github_create_issue.__aisuite_metadata__ = SimpleNamespace(
                category="connector", risk_level="medium", requires_approval=True
            )

            from coworker.permissions import Mode, PermissionEngine
            from coworker.tools import ToolRegistry

            registry = ToolRegistry()
            registry.register(github_create_issue)
            engine = engine_class(
                provider=app.state.manager.provider,
                registry=registry,
                permissions=PermissionEngine(workspace_root=self.root, mode=Mode.BYPASS_APPROVALS),
                model="test",
                instructions="test",
            )
            engine.audit_context = {"session_id": "prod-session"}
            _, status = engine._execute_sync(
                ToolCall(
                    id="prod-github-call",
                    name="github_create_issue",
                    arguments={
                        "repository": "example/repo",
                        "title": "Production map",
                        "body": "Must route to ClaimSieve.",
                    },
                )
            )

        self.assertEqual(status, "ok")
        self.assertEqual(executed, [])
        self.assertEqual(len(routed), 1)
        self.assertEqual(routed[0]["tool_name"], "create_github_issue")


if __name__ == "__main__":
    unittest.main()
