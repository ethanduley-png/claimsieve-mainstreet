from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mainstreet_runtimes.openworker_mtls_server import (
    OpenWorkerMTLSServerError,
    build_server_ssl_context,
    serve_openworker_intake_mtls,
    spiffe_id_from_peer_certificate,
)


class _Context:
    minimum_version = None
    verify_mode = None

    def load_verify_locations(self, cafile):
        self.cafile = cafile

    def load_cert_chain(self, certfile, keyfile):
        self.certfile = certfile
        self.keyfile = keyfile


class OpenWorkerMTLSServerTests(unittest.TestCase):
    def test_exactly_one_spiffe_uri_san_is_required(self) -> None:
        principal = "spiffe://mainstreet.local/tenant-founder/agent/openworker"
        self.assertEqual(
            spiffe_id_from_peer_certificate(
                {"subjectAltName": (("DNS", "openworker"), ("URI", principal))}
            ),
            principal,
        )
        with self.assertRaisesRegex(OpenWorkerMTLSServerError, "exactly one"):
            spiffe_id_from_peer_certificate(
                {"subjectAltName": (("URI", principal), ("URI", "spiffe://attacker/runtime"))}
            )
        with self.assertRaisesRegex(OpenWorkerMTLSServerError, "exactly one"):
            spiffe_id_from_peer_certificate({"subjectAltName": (("DNS", "openworker"),)})

    def test_server_context_requires_tls13_and_client_certificates(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("ca.crt", "server.crt", "server.key"):
                (root / name).write_text("fixture", encoding="utf-8")
            context = _Context()
            with patch(
                "mainstreet_runtimes.openworker_mtls_server.ssl.create_default_context",
                return_value=context,
            ):
                result = build_server_ssl_context(
                    ca_file=root / "ca.crt",
                    server_cert_file=root / "server.crt",
                    server_key_file=root / "server.key",
                )
            self.assertIs(result, context)
            self.assertIsNotNone(context.minimum_version)
            self.assertIsNotNone(context.verify_mode)
            self.assertEqual(context.cafile, str(root / "ca.crt"))

    def test_server_refuses_alternate_bind_port(self) -> None:
        with self.assertRaisesRegex(OpenWorkerMTLSServerError, "port must be 8443"):
            serve_openworker_intake_mtls(
                object(),
                bind_host="0.0.0.0",
                port=443,
                ca_file="missing",
                server_cert_file="missing",
                server_key_file="missing",
            )

    def test_server_refuses_loopback_or_arbitrary_bind_identity(self) -> None:
        with self.assertRaisesRegex(OpenWorkerMTLSServerError, "pod network interface"):
            serve_openworker_intake_mtls(
                object(),
                bind_host="127.0.0.1",
                port=8443,
                ca_file="missing",
                server_cert_file="missing",
                server_key_file="missing",
            )


if __name__ == "__main__":
    unittest.main()
