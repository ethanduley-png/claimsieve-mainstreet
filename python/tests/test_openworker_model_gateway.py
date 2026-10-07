from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

COWORKER_AVAILABLE = importlib.util.find_spec("coworker") is not None

BASE_RESPONSE = {
    "schema_version": "mainstreet.openworker_model_response.v1",
    "text": "ok",
    "tool_calls": [
        {"id": "call-1", "name": "create_github_issue", "arguments": {"repository": "example/repo"}}
    ],
    "finish_reason": "tool_calls",
    "reasoning": None,
    "extras": {},
    "usage": {"input": 10, "output": 3, "cache_read": 0, "cache_write": 0},
}


@unittest.skipUnless(COWORKER_AVAILABLE, "pinned OpenWorker is installed only in its CI gate")
class OpenWorkerModelGatewayTests(unittest.TestCase):
    class _TLS:
        minimum_version = None
        check_hostname = None
        verify_mode = None

        def load_cert_chain(self, certfile, keyfile):
            self.certfile = certfile
            self.keyfile = keyfile

    class _Response:
        status = 200
        payload = BASE_RESPONSE

        def read(self, amount):
            return json.dumps(type(self).payload).encode()[:amount]

    class _Connection:
        response = None
        request_seen = None

        def __init__(self, host, port, timeout, context):
            self.host = host
            self.port = port

        def request(self, method, path, body=None, headers=None):
            type(self).request_seen = (method, path, body, headers)

        def getresponse(self):
            return type(self).response

        def close(self):
            pass

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name in ("ca.crt", "tls.crt", "tls.key"):
            (self.root / name).write_text("fixture", encoding="utf-8")
        self._Response.status = 200
        self._Response.payload = json.loads(json.dumps(BASE_RESPONSE))
        self._Connection.response = None
        self._Connection.request_seen = None

    def tearDown(self) -> None:
        self.temp.cleanup()

    def provider(self):
        from mainstreet_runtimes.openworker_model_gateway import MainStreetOpenWorkerModelGatewayProvider
        with patch(
            "mainstreet_runtimes.openworker_model_gateway.ssl.create_default_context",
            return_value=self._TLS(),
        ):
            return MainStreetOpenWorkerModelGatewayProvider(
                ca_file=self.root / "ca.crt",
                client_cert_file=self.root / "tls.crt",
                client_key_file=self.root / "tls.key",
            )

    def test_provider_is_native_openworker_providerclient(self) -> None:
        from coworker.providers.base import ProviderClient
        self.assertIsInstance(self.provider(), ProviderClient)

    def test_fixed_gateway_normalizes_turn_without_vendor_credentials(self) -> None:
        from mainstreet_runtimes.openworker_model_gateway import MODEL_GATEWAY_PATH
        self._Connection.response = self._Response()
        provider = self.provider()
        with patch("mainstreet_runtimes.openworker_model_gateway.http.client.HTTPSConnection", self._Connection):
            turn = provider.complete(
                model="openai:gpt-test",
                messages=[{"role": "user", "content": "test"}],
                tools=[],
                temperature=0,
            )
        self.assertEqual(turn.text, "ok")
        self.assertEqual(turn.tool_calls[0].name, "create_github_issue")
        self.assertEqual(turn.usage.input, 10)
        method, path, body, _ = self._Connection.request_seen
        self.assertEqual((method, path), ("POST", MODEL_GATEWAY_PATH))
        request = json.loads(body)
        self.assertEqual(request["settings"], {"temperature": 0})
        self.assertNotIn("api_key", body.decode())

    def test_provider_routing_and_credentials_cannot_be_smuggled_in_settings(self) -> None:
        from mainstreet_runtimes.openworker_model_gateway import OpenWorkerModelGatewayError
        provider = self.provider()
        for key in ("api_key", "base_url", "authorization", "provider", "headers"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(OpenWorkerModelGatewayError, "forbidden"):
                    provider.complete(model="test", messages=[], **{key: "attacker-controlled"})

    def test_duplicate_tool_call_identity_from_gateway_fails_closed(self) -> None:
        from mainstreet_runtimes.openworker_model_gateway import OpenWorkerModelGatewayError
        self._Response.payload["tool_calls"] = [
            {"id": "dup", "name": "a", "arguments": {}},
            {"id": "dup", "name": "b", "arguments": {}},
        ]
        self._Connection.response = self._Response()
        provider = self.provider()
        with patch("mainstreet_runtimes.openworker_model_gateway.http.client.HTTPSConnection", self._Connection):
            with self.assertRaisesRegex(OpenWorkerModelGatewayError, "duplicated"):
                provider.complete(model="test", messages=[])

    def test_redirect_or_endpoint_substitution_has_no_fallback(self) -> None:
        from mainstreet_runtimes.openworker_model_gateway import (
            MainStreetOpenWorkerModelGatewayProvider,
            OpenWorkerModelGatewayError,
        )
        with self.assertRaisesRegex(OpenWorkerModelGatewayError, "fixed production"):
            MainStreetOpenWorkerModelGatewayProvider(
                endpoint="https://api.openai.com:8443/v1/runtime/openworker/completions",
                ca_file=self.root / "ca.crt",
                client_cert_file=self.root / "tls.crt",
                client_key_file=self.root / "tls.key",
            )
        response = self._Response()
        response.status = 302
        self._Connection.response = response
        provider = self.provider()
        with patch("mainstreet_runtimes.openworker_model_gateway.http.client.HTTPSConnection", self._Connection):
            with self.assertRaisesRegex(OpenWorkerModelGatewayError, "fallback are forbidden"):
                provider.complete(model="test", messages=[])


if __name__ == "__main__":
    unittest.main()
