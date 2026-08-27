from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from founder_os import FounderOSReferenceWorkflow
from mainstreet_runtimes import ClaimSieveRuntimeContext, OpenWorkerProposalAdapter
from mainstreet_runtimes.openworker_claimsieve_intake import OpenWorkerFounderIntake
from mainstreet_runtimes.openworker_ipc import (
    CLAIMSIEVE_INTAKE_HOST,
    CLAIMSIEVE_INTAKE_PATH,
    CLAIMSIEVE_INTAKE_PORT,
    OpenWorkerClaimSieveHTTPSClient,
    OpenWorkerIPCError,
    OpenWorkerIntakeService,
)

OPENWORKER_COMMIT = "86c57f0692a5a318e55d1b9e0188d798b9fc5690"


class _FakeTLSContext:
    minimum_version = None
    check_hostname = None
    verify_mode = None

    def load_cert_chain(self, certfile, keyfile):
        self.certfile = certfile
        self.keyfile = keyfile


class _FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, amount: int) -> bytes:
        return self._body[:amount]


class _FakeConnection:
    response = _FakeResponse(500, b"")
    last_request = None

    def __init__(self, host, port, timeout, context) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.context = context

    def request(self, method, path, body=None, headers=None):
        type(self).last_request = (method, path, body, headers)

    def getresponse(self):
        return type(self).response

    def close(self):
        pass


class OpenWorkerIPCTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repository = "example/claimsieve-mainstreet"
        self.workflow = FounderOSReferenceWorkflow(
            self.root,
            allowed_repositories={self.repository},
            provider_mode="success",
            runtime_name="openworker",
            runtime_version=OPENWORKER_COMMIT,
        )
        self.intake = OpenWorkerFounderIntake(self.workflow)
        self.context = ClaimSieveRuntimeContext(
            trace_id="trace-openworker-ipc",
            campaign_id="campaign-openworker-ipc",
            session_id="session-openworker-ipc",
            work_item_id="work-openworker-ipc",
            requested_at_seq=70,
        )
        self.adapter = OpenWorkerProposalAdapter(
            self.context,
            lambda intent: intent,
            consequential_tools={"create_github_issue"},
        )
        self.principal = "spiffe://mainstreet.local/tenant-founder/agent/openworker"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def intent(self) -> dict:
        return self.adapter.build_intent(
            {
                "schema_version": "mainstreet.openworker_tool_call.v1",
                "id": "ow-ipc-001",
                "name": "create_github_issue",
                "arguments": {
                    "repository": self.repository,
                    "title": "Authenticated IPC",
                    "body": "Consequential actions cross only the ClaimSieve mTLS boundary.",
                },
            }
        ).to_dict()

    def test_service_accepts_authenticated_runtime_and_stops_before_execution(self) -> None:
        service = OpenWorkerIntakeService(self.intake)
        raw = json.dumps(self.intent(), separators=(",", ":")).encode()
        receipt = json.loads(service.handle(raw, self.principal))
        self.assertEqual(receipt["status"], "PERMIT_ISSUED_EXECUTION_PENDING")
        self.assertFalse(receipt["external_action_executed"])
        self.assertEqual(len(self.workflow.ledger_records()["execution"]), 0)

    def test_service_rejects_wrong_authenticated_principal_before_state_change(self) -> None:
        service = OpenWorkerIntakeService(self.intake)
        raw = json.dumps(self.intent()).encode()
        with self.assertRaisesRegex(OpenWorkerIPCError, "principal mismatch"):
            service.handle(raw, "spiffe://mainstreet.local/tenant-founder/agent/attacker")
        self.assertEqual(self.intake.pending_permits(), ())

    def test_service_rejects_duplicate_json_keys(self) -> None:
        service = OpenWorkerIntakeService(self.intake)
        raw = b'{"runtime":"openworker","runtime":"attacker"}'
        with self.assertRaisesRegex(OpenWorkerIPCError, "duplicate JSON key"):
            service.handle(raw, self.principal)

    def client(self) -> OpenWorkerClaimSieveHTTPSClient:
        ca = self.root / "ca.pem"
        cert = self.root / "client.pem"
        key = self.root / "client.key"
        for path in (ca, cert, key):
            path.write_text("fixture", encoding="utf-8")
        with patch("mainstreet_runtimes.openworker_ipc.ssl.create_default_context", return_value=_FakeTLSContext()):
            return OpenWorkerClaimSieveHTTPSClient(
                endpoint=f"https://{CLAIMSIEVE_INTAKE_HOST}:{CLAIMSIEVE_INTAKE_PORT}{CLAIMSIEVE_INTAKE_PATH}",
                ca_file=ca,
                client_cert_file=cert,
                client_key_file=key,
            )

    def test_client_rejects_endpoint_substitution(self) -> None:
        material = self.root / "x"
        material.write_text("x")
        with self.assertRaisesRegex(OpenWorkerIPCError, "fixed production"):
            OpenWorkerClaimSieveHTTPSClient(
                endpoint="https://github.com:8443/v1/runtime/openworker/intents",
                ca_file=material,
                client_cert_file=material,
                client_key_file=material,
            )

    def test_client_rejects_redirect_without_following_it(self) -> None:
        client = self.client()
        _FakeConnection.response = _FakeResponse(302, b"")
        with patch("mainstreet_runtimes.openworker_ipc.http.client.HTTPSConnection", _FakeConnection):
            with self.assertRaisesRegex(OpenWorkerIPCError, "redirects and fallback are forbidden"):
                client.route_intent(self.intent())

    def test_client_accepts_only_closed_pending_receipt(self) -> None:
        client = self.client()
        service = OpenWorkerIntakeService(self.intake)
        receipt = service.handle(json.dumps(self.intent()).encode(), self.principal)
        _FakeConnection.response = _FakeResponse(200, receipt)
        with patch("mainstreet_runtimes.openworker_ipc.http.client.HTTPSConnection", _FakeConnection):
            result = client.route_intent(self.intent())
        self.assertEqual(result["status"], "PERMIT_ISSUED_EXECUTION_PENDING")
        self.assertFalse(result["external_action_executed"])
        method, path, _, _ = _FakeConnection.last_request
        self.assertEqual((method, path), ("POST", CLAIMSIEVE_INTAKE_PATH))

    def test_client_rejects_receipt_field_smuggling(self) -> None:
        client = self.client()
        service = OpenWorkerIntakeService(self.intake)
        receipt = json.loads(service.handle(json.dumps(self.intent()).encode(), self.principal))
        receipt["provider_token"] = "smuggled"
        _FakeConnection.response = _FakeResponse(200, json.dumps(receipt).encode())
        with patch("mainstreet_runtimes.openworker_ipc.http.client.HTTPSConnection", _FakeConnection):
            with self.assertRaisesRegex(OpenWorkerIPCError, "closed schema"):
                client.route_intent(self.intent())


if __name__ == "__main__":
    unittest.main()
