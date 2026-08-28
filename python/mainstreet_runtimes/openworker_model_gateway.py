from __future__ import annotations

import http.client
import json
import ssl
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

try:
    from coworker.providers.base import ProviderClient as _ProviderClientBase
except ImportError:
    class _ProviderClientBase:  # type: ignore[no-redef]
        pass

MODEL_GATEWAY_HOST = "model-gateway.mainstreet-system.svc.cluster.local"
MODEL_GATEWAY_PORT = 8443
MODEL_GATEWAY_PATH = "/v1/runtime/openworker/completions"
MODEL_GATEWAY_ENDPOINT = f"https://{MODEL_GATEWAY_HOST}:{MODEL_GATEWAY_PORT}{MODEL_GATEWAY_PATH}"
MAX_REQUEST_BYTES = 8 * 1024 * 1024
MAX_RESPONSE_BYTES = 8 * 1024 * 1024


class OpenWorkerModelGatewayError(RuntimeError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise OpenWorkerModelGatewayError(f"duplicate model-gateway JSON key: {key}")
        out[key] = value
    return out


def _decode(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise OpenWorkerModelGatewayError("model-gateway response exceeds size limit")
    try:
        payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OpenWorkerModelGatewayError("model-gateway response is malformed") from exc
    if not isinstance(payload, dict):
        raise OpenWorkerModelGatewayError("model-gateway response must be an object")
    return payload


class MainStreetOpenWorkerModelGatewayProvider(_ProviderClientBase):
    """Native OpenWorker ProviderClient with no external-provider credentials."""

    RESPONSE_FIELDS = frozenset(
        {"schema_version", "text", "tool_calls", "finish_reason", "reasoning", "extras", "usage"}
    )
    TOOL_CALL_FIELDS = frozenset({"id", "name", "arguments"})
    USAGE_FIELDS = frozenset({"input", "output", "cache_read", "cache_write"})

    def __init__(
        self,
        *,
        endpoint: str = MODEL_GATEWAY_ENDPOINT,
        ca_file: str | Path,
        client_cert_file: str | Path,
        client_key_file: str | Path,
        timeout_seconds: float = 30.0,
    ) -> None:
        parts = urlsplit(endpoint)
        if (
            parts.scheme != "https"
            or parts.hostname != MODEL_GATEWAY_HOST
            or parts.port != MODEL_GATEWAY_PORT
            or parts.path != MODEL_GATEWAY_PATH
            or parts.query
            or parts.fragment
            or parts.username is not None
            or parts.password is not None
        ):
            raise OpenWorkerModelGatewayError(
                "OpenWorker model gateway must use the fixed production mTLS endpoint"
            )
        if (
            not isinstance(timeout_seconds, (int, float))
            or isinstance(timeout_seconds, bool)
            or timeout_seconds <= 0
            or timeout_seconds > 60
        ):
            raise OpenWorkerModelGatewayError("model-gateway timeout must be in (0, 60] seconds")
        files = [Path(ca_file), Path(client_cert_file), Path(client_key_file)]
        if any(not path.is_file() for path in files):
            raise OpenWorkerModelGatewayError("model-gateway mTLS material is missing")
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(files[0]))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=str(files[1]), keyfile=str(files[2]))
        self._context = context
        self._timeout = float(timeout_seconds)

    @staticmethod
    def _safe_settings(settings: Mapping[str, Any]) -> dict[str, Any]:
        forbidden = {
            "api_key", "token", "authorization", "base_url", "endpoint", "headers",
            "organization", "project", "credentials", "provider",
        }
        for key in settings:
            if str(key).lower() in forbidden:
                raise OpenWorkerModelGatewayError(
                    f"provider-routing or credential setting is forbidden: {key}"
                )
        try:
            encoded = json.dumps(dict(settings), allow_nan=False)
            decoded = json.loads(encoded)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise OpenWorkerModelGatewayError("model settings must be finite JSON data") from exc
        if not isinstance(decoded, dict):
            raise OpenWorkerModelGatewayError("model settings must be an object")
        return decoded

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise OpenWorkerModelGatewayError("model-gateway request must be finite JSON data") from exc
        if len(raw) > MAX_REQUEST_BYTES:
            raise OpenWorkerModelGatewayError("model-gateway request exceeds size limit")
        conn = http.client.HTTPSConnection(
            MODEL_GATEWAY_HOST,
            MODEL_GATEWAY_PORT,
            timeout=self._timeout,
            context=self._context,
        )
        try:
            conn.request(
                "POST",
                MODEL_GATEWAY_PATH,
                body=raw,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Content-Length": str(len(raw)),
                },
            )
            response = conn.getresponse()
            if response.status != 200:
                raise OpenWorkerModelGatewayError(
                    f"model gateway returned HTTP {response.status}; redirects and fallback are forbidden"
                )
            body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise OpenWorkerModelGatewayError("model-gateway response exceeds size limit")
            return _decode(body)
        except (OSError, http.client.HTTPException) as exc:
            raise OpenWorkerModelGatewayError("model-gateway transport failed closed") from exc
        finally:
            conn.close()

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        **settings: Any,
    ):
        from coworker.providers.base import AssistantTurn, TokenUsage, ToolCall

        if not isinstance(model, str) or not model or len(model) > 200:
            raise OpenWorkerModelGatewayError("model identifier is invalid")
        if not isinstance(messages, list):
            raise OpenWorkerModelGatewayError("messages must be a list")
        if tools is not None and not isinstance(tools, list):
            raise OpenWorkerModelGatewayError("tools must be a list or null")
        payload = {
            "schema_version": "mainstreet.openworker_model_request.v1",
            "model": model,
            "messages": messages,
            "tools": tools or [],
            "settings": self._safe_settings(settings),
        }
        response = self._request(payload)
        if frozenset(response) != self.RESPONSE_FIELDS:
            raise OpenWorkerModelGatewayError("model-gateway response fields do not match the closed schema")
        if response.get("schema_version") != "mainstreet.openworker_model_response.v1":
            raise OpenWorkerModelGatewayError("unsupported model-gateway response schema")

        raw_calls = response.get("tool_calls")
        if not isinstance(raw_calls, list):
            raise OpenWorkerModelGatewayError("model-gateway tool_calls must be a list")
        calls: list[ToolCall] = []
        seen_ids: set[str] = set()
        for raw_call in raw_calls:
            if not isinstance(raw_call, dict) or frozenset(raw_call) != self.TOOL_CALL_FIELDS:
                raise OpenWorkerModelGatewayError("model-gateway tool call fields are invalid")
            call_id = raw_call.get("id")
            name = raw_call.get("name")
            arguments = raw_call.get("arguments")
            if not isinstance(call_id, str) or not call_id or call_id in seen_ids:
                raise OpenWorkerModelGatewayError("model-gateway tool call identity is invalid or duplicated")
            if not isinstance(name, str) or not name:
                raise OpenWorkerModelGatewayError("model-gateway tool name is invalid")
            if not isinstance(arguments, dict):
                raise OpenWorkerModelGatewayError("model-gateway tool arguments must be an object")
            seen_ids.add(call_id)
            calls.append(ToolCall(id=call_id, name=name, arguments=arguments))

        usage_raw = response.get("usage")
        usage = None
        if usage_raw is not None:
            if not isinstance(usage_raw, dict) or frozenset(usage_raw) != self.USAGE_FIELDS:
                raise OpenWorkerModelGatewayError("model-gateway usage fields are invalid")
            values: list[int] = []
            for key in ("input", "output", "cache_read", "cache_write"):
                value = usage_raw.get(key)
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise OpenWorkerModelGatewayError("model-gateway usage values must be non-negative integers")
                values.append(value)
            usage = TokenUsage(*values)

        text = response.get("text")
        reasoning = response.get("reasoning")
        finish_reason = response.get("finish_reason")
        extras = response.get("extras")
        if text is not None and not isinstance(text, str):
            raise OpenWorkerModelGatewayError("model-gateway text must be string or null")
        if reasoning is not None and not isinstance(reasoning, str):
            raise OpenWorkerModelGatewayError("model-gateway reasoning must be string or null")
        if finish_reason is not None and not isinstance(finish_reason, str):
            raise OpenWorkerModelGatewayError("model-gateway finish_reason must be string or null")
        if not isinstance(extras, dict):
            raise OpenWorkerModelGatewayError("model-gateway extras must be an object")
        return AssistantTurn(
            text=text,
            tool_calls=calls,
            finish_reason=finish_reason,
            reasoning=reasoning,
            extras=extras,
            usage=usage,
        )

    def capabilities(self, model: str):
        from coworker.providers.base import ModelCapabilities

        if not isinstance(model, str) or not model:
            raise OpenWorkerModelGatewayError("model identifier is invalid")
        # Until the gateway exposes a separately authenticated capability contract, do not
        # advertise optional modalities. Tool use is the only capability this integration
        # requires and independently gates at the ClaimSieve execution boundary.
        return ModelCapabilities(
            tools=True,
            vision=False,
            pdf=False,
            parallel_tool_calls=False,
            streaming=False,
        )
