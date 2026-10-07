from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mainstreet_runtimes import ClaimSieveRuntimeContext
from mainstreet_runtimes.openworker_ipc import (
    CLAIMSIEVE_INTAKE_PATH,
    OpenWorkerIPCError,
    build_production_openworker_adapter,
)


class _TLS:
    minimum_version = None
    check_hostname = None
    verify_mode = None

    def load_cert_chain(self, certfile, keyfile):
        pass


class _Response:
    status = 200

    def read(self, amount):
        return json.dumps(
            {
                "schema_version": "mainstreet.claimsieve_intake_receipt.v1",
                "status": "PERMIT_ISSUED_EXECUTION_PENDING",
                "permit_id": "permit-1",
                "proposal_id": "proposal-1",
                "runtime_name": "openworker",
                "runtime_version": "86c57f0692a5a318e55d1b9e0188d798b9fc5690",
                "runtime_principal": "spiffe://mainstreet.local/tenant-founder/agent/openworker",
                "runtime_manifest_digest": "sha256:" + "1" * 64,
                "proposal_digest": "sha256:" + "2" * 64,
                "action_digest": "sha256:" + "3" * 64,
                "destination_digest": "sha256:" + "4" * 64,
                "parameter_digest": "sha256:" + "5" * 64,
                "expires_at_seq": 10,
                "external_action_executed": False,
            }
        ).encode()


class _Connection:
    request_seen = None

    def __init__(self, host, port, timeout, context):
        pass

    def request(self, method, path, body=None, headers=None):
        type(self).request_seen = (method, path, body, headers)

    def getresponse(self):
        return _Response()

    def close(self):
        pass


class OpenWorkerProductionFactoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name in ("ca.crt", "tls.crt", "tls.key"):
            (self.root / name).write_text("fixture", encoding="utf-8")
        self.context = ClaimSieveRuntimeContext(
            trace_id="trace-prod-factory",
            campaign_id="campaign-prod-factory",
            session_id="session-prod-factory",
            work_item_id="work-prod-factory",
            requested_at_seq=5,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_factory_routes_only_through_fixed_https_client(self) -> None:
        with patch("mainstreet_runtimes.openworker_ipc.ssl.create_default_context", return_value=_TLS()):
            adapter = build_production_openworker_adapter(
                self.context,
                ca_file=self.root / "ca.crt",
                client_cert_file=self.root / "tls.crt",
                client_key_file=self.root / "tls.key",
                consequential_tools={"create_github_issue"},
            )
        with patch("mainstreet_runtimes.openworker_ipc.http.client.HTTPSConnection", _Connection):
            routed = adapter.route_tool_call(
                {
                    "schema_version": "mainstreet.openworker_tool_call.v1",
                    "id": "prod-call-1",
                    "name": "create_github_issue",
                    "arguments": {
                        "repository": "example/repo",
                        "title": "Production path",
                        "body": "Must use mTLS ClaimSieve intake.",
                    },
                }
            )
        self.assertTrue(routed["routed_to_claimsieve"])
        self.assertFalse(routed["external_action_executed"])
        self.assertEqual(_Connection.request_seen[0:2], ("POST", CLAIMSIEVE_INTAKE_PATH))

    def test_factory_fails_closed_when_identity_material_is_missing(self) -> None:
        with self.assertRaisesRegex(OpenWorkerIPCError, "mTLS material is missing"):
            build_production_openworker_adapter(
                self.context,
                ca_file=self.root / "missing-ca",
                client_cert_file=self.root / "missing-cert",
                client_key_file=self.root / "missing-key",
                consequential_tools={"create_github_issue"},
            )


if __name__ == "__main__":
    unittest.main()
