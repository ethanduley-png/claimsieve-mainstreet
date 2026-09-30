"""MainStreet's explicitly untrusted Agent Reach capability plane.

Agent Reach is useful for discovery and read access, but its upstream tools are
not an authority source. This module deliberately exposes a tiny, audited set
of read-only operations and turns every result into a tainted observation.

The important boundary is semantic as well as technical:

    observation != instruction != approval != permit != execution authority

The planner may cite an observation when constructing a ClaimSieve proposal,
but only ClaimSieve may decide whether the evidence and policy are sufficient
for an action, and only the restricted executor may perform an authorized
external effect.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import subprocess
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit, urlunsplit


REQUEST_SCHEMA = "mainstreet.capability_request.v1"
OBSERVATION_SCHEMA = "mainstreet.untrusted_observation.v1"
MAX_OUTPUT_BYTES = 262_144
MAX_QUERY_CHARS = 4_096
MAX_URL_CHARS = 8_192
MAX_LIMIT = 20


class CapabilityPolicyError(ValueError):
    """Raised before any upstream capability is invoked."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class CapabilityExecutionError(RuntimeError):
    """Raised when an allowed upstream capability fails safely."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class CapabilityRequest:
    request_id: str
    trace_id: str
    tenant_id: str
    channel: str
    operation: str
    parameters: Mapping[str, Any]
    observed_at_seq: int


@dataclass(frozen=True)
class ObservationEnvelope:
    schema_version: str
    observation_id: str
    request_id: str
    trace_id: str
    tenant_id: str
    plane: str
    channel: str
    operation: str
    observed_at_seq: int
    request_digest: str
    content_digest: str
    content: str
    taint_labels: tuple[str, ...]
    authority: str
    executable: bool
    instructions_are_data: bool
    claim_sieve_disposition: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "request_id": self.request_id,
            "trace_id": self.trace_id,
            "tenant_id": self.tenant_id,
            "plane": self.plane,
            "channel": self.channel,
            "operation": self.operation,
            "observed_at_seq": self.observed_at_seq,
            "request_digest": self.request_digest,
            "content_digest": self.content_digest,
            "content": self.content,
            "taint_labels": list(self.taint_labels),
            "authority": self.authority,
            "executable": self.executable,
            "instructions_are_data": self.instructions_are_data,
            "claim_sieve_disposition": self.claim_sieve_disposition,
        }


class CapabilityRunner(Protocol):
    def run(self, request: CapabilityRequest) -> str:
        """Execute one already validated capability request."""


_ALLOWED_PARAMETER_KEYS: dict[tuple[str, str], frozenset[str]] = {
    ("agent-reach", "status"): frozenset(),
    ("web", "read"): frozenset({"url"}),
    ("github", "search_repositories"): frozenset({"query", "limit"}),
    ("search", "exa"): frozenset({"query", "limit"}),
    ("v2ex", "hot"): frozenset(),
    ("bilibili", "search"): frozenset({"query", "limit"}),
}

_MUTATION_WORDS = frozenset(
    {
        "post",
        "create",
        "send",
        "write",
        "update",
        "delete",
        "remove",
        "upload",
        "comment",
        "reply",
        "like",
        "follow",
        "unfollow",
        "merge",
        "close",
        "reopen",
        "install",
        "configure",
        "login",
        "logout",
        "purchase",
        "pay",
        "execute",
        "run_command",
    }
)

_FORBIDDEN_PARAMETER_WORDS = frozenset(
    {
        "cookie",
        "cookies",
        "token",
        "secret",
        "password",
        "credential",
        "credentials",
        "authorization",
        "api_key",
        "apikey",
        "command",
        "argv",
        "environment",
        "env",
        "headers",
    }
)

_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,512}$")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _require_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise CapabilityPolicyError("INVALID_ID", f"{field} is not a bounded protocol identifier")
    return value


def _require_nfc_string(value: Any, field: str, max_chars: int) -> str:
    if not isinstance(value, str) or not value or len(value) > max_chars:
        raise CapabilityPolicyError("INVALID_STRING", f"{field} must be a non-empty bounded string")
    if value != unicodedata.normalize("NFC", value):
        raise CapabilityPolicyError("NON_NFC_STRING", f"{field} must be NFC-normalized")
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        raise CapabilityPolicyError("CONTROL_CHARACTER", f"{field} contains a control character")
    return value


def _require_limit(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > MAX_LIMIT:
        raise CapabilityPolicyError("INVALID_LIMIT", f"limit must be an integer from 1 to {MAX_LIMIT}")
    return value


def _validate_public_url(raw: Any) -> str:
    url = _require_nfc_string(raw, "parameters.url", MAX_URL_CHARS)
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"}:
        raise CapabilityPolicyError("URL_SCHEME_DENIED", "only http and https URLs are permitted")
    if not parts.hostname or parts.username or parts.password:
        raise CapabilityPolicyError("URL_AUTHORITY_DENIED", "URL must have a host and no embedded credentials")
    if parts.port not in {None, 80, 443}:
        raise CapabilityPolicyError("URL_PORT_DENIED", "only ports 80 and 443 are permitted")

    hostname = parts.hostname.rstrip(".").lower()
    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
        raise CapabilityPolicyError("PRIVATE_TARGET_DENIED", "local network targets are not permitted")

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise CapabilityPolicyError("PRIVATE_TARGET_DENIED", "non-global IP targets are not permitted")

    # DNS rebinding must still be constrained by deployment egress policy. This
    # lightweight resolver check blocks the common case before process launch.
    try:
        answers = socket.getaddrinfo(hostname, parts.port or (443 if parts.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise CapabilityPolicyError("DNS_RESOLUTION_FAILED", "target host could not be resolved") from exc
    for answer in answers:
        resolved = ipaddress.ip_address(answer[4][0])
        if not resolved.is_global:
            raise CapabilityPolicyError("PRIVATE_TARGET_DENIED", "target resolves to a non-global address")

    clean_netloc = hostname if parts.port is None else f"{hostname}:{parts.port}"
    return urlunsplit((parts.scheme, clean_netloc, parts.path or "/", parts.query, ""))


def _reject_secret_like_parameters(value: Any, path: str = "parameters") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CapabilityPolicyError("INVALID_PARAMETER_KEY", f"{path} contains a non-string key")
            normalized = key.lower().replace("-", "_")
            if normalized in _FORBIDDEN_PARAMETER_WORDS or any(word in normalized for word in ("password", "secret", "credential")):
                raise CapabilityPolicyError("CREDENTIAL_MATERIAL_DENIED", f"{path}.{key} is forbidden")
            _reject_secret_like_parameters(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_like_parameters(child, f"{path}[{index}]")


def parse_request(raw: Mapping[str, Any]) -> CapabilityRequest:
    if not isinstance(raw, Mapping):
        raise CapabilityPolicyError("INVALID_REQUEST", "request must be an object")
    expected = {
        "schema_version",
        "request_id",
        "trace_id",
        "tenant_id",
        "channel",
        "operation",
        "parameters",
        "observed_at_seq",
    }
    unknown = set(raw) - expected
    missing = expected - set(raw)
    if unknown:
        raise CapabilityPolicyError("UNKNOWN_FIELD", f"unknown request fields: {sorted(unknown)}")
    if missing:
        raise CapabilityPolicyError("MISSING_FIELD", f"missing request fields: {sorted(missing)}")
    if raw["schema_version"] != REQUEST_SCHEMA:
        raise CapabilityPolicyError("UNSUPPORTED_SCHEMA", "unsupported capability request schema")

    channel = _require_nfc_string(raw["channel"], "channel", 128).lower()
    operation = _require_nfc_string(raw["operation"], "operation", 128).lower()
    tokens = {token for token in re.split(r"[^a-z0-9]+", operation) if token}
    if tokens & _MUTATION_WORDS:
        raise CapabilityPolicyError("MUTATION_DENIED", "mutation-like operations are forbidden in the observation plane")
    if (channel, operation) not in _ALLOWED_PARAMETER_KEYS:
        raise CapabilityPolicyError("CAPABILITY_DENIED", f"{channel}.{operation} is not allowlisted")

    parameters = raw["parameters"]
    if not isinstance(parameters, Mapping):
        raise CapabilityPolicyError("INVALID_PARAMETERS", "parameters must be an object")
    allowed_keys = _ALLOWED_PARAMETER_KEYS[(channel, operation)]
    if set(parameters) != allowed_keys:
        raise CapabilityPolicyError(
            "PARAMETER_SHAPE_MISMATCH",
            f"{channel}.{operation} requires exactly {sorted(allowed_keys)}",
        )
    _reject_secret_like_parameters(parameters)

    normalized: dict[str, Any] = {}
    if "query" in parameters:
        normalized["query"] = _require_nfc_string(parameters["query"], "parameters.query", MAX_QUERY_CHARS)
    if "limit" in parameters:
        normalized["limit"] = _require_limit(parameters["limit"])
    if "url" in parameters:
        normalized["url"] = _validate_public_url(parameters["url"])

    seq = raw["observed_at_seq"]
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0 or seq > 9_007_199_254_740_991:
        raise CapabilityPolicyError("INVALID_SEQUENCE", "observed_at_seq must be a non-negative safe integer")

    return CapabilityRequest(
        request_id=_require_id(raw["request_id"], "request_id"),
        trace_id=_require_id(raw["trace_id"], "trace_id"),
        tenant_id=_require_id(raw["tenant_id"], "tenant_id"),
        channel=channel,
        operation=operation,
        parameters=normalized,
        observed_at_seq=seq,
    )


class AgentReachSubprocessRunner:
    """Execute only the explicit read recipes published by Agent Reach.

    No caller supplied executable, flags, environment variables, shell syntax,
    output path, or working directory is accepted. Any credentials needed for a
    future authenticated read channel belong only in this isolated process and
    must never be emitted in an observation envelope.
    """

    def __init__(self, *, timeout_seconds: int = 20, max_output_bytes: int = MAX_OUTPUT_BYTES):
        if timeout_seconds < 1 or timeout_seconds > 120:
            raise ValueError("timeout_seconds out of range")
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def _argv(self, request: CapabilityRequest) -> list[str]:
        key = (request.channel, request.operation)
        if key == ("agent-reach", "status"):
            return ["agent-reach", "doctor", "--json"]
        if key == ("web", "read"):
            target = request.parameters["url"]
            return [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--max-time",
                str(self.timeout_seconds),
                f"https://r.jina.ai/{target}",
            ]
        if key == ("github", "search_repositories"):
            return [
                "gh",
                "search",
                "repos",
                request.parameters["query"],
                "--sort",
                "stars",
                "--limit",
                str(request.parameters["limit"]),
                "--json",
                "fullName,description,stargazersCount,url",
            ]
        if key == ("search", "exa"):
            return [
                "mcporter",
                "call",
                "exa.web_search_exa",
                f"query={request.parameters['query']}",
                f"numResults={request.parameters['limit']}",
            ]
        if key == ("v2ex", "hot"):
            return [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                str(self.timeout_seconds),
                "https://www.v2ex.com/api/topics/hot.json",
                "-H",
                "User-Agent: mainstreet-agent-reach-observer/1",
            ]
        if key == ("bilibili", "search"):
            return [
                "bili",
                "search",
                request.parameters["query"],
                "--type",
                "video",
                "-n",
                str(request.parameters["limit"]),
            ]
        raise CapabilityPolicyError("CAPABILITY_DENIED", "request reached a non-allowlisted runner path")

    def run(self, request: CapabilityRequest) -> str:
        argv = self._argv(request)
        env = {
            key: value
            for key, value in os.environ.items()
            if key in {"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "XDG_CONFIG_HOME", "XDG_CACHE_HOME"}
        }
        try:
            completed = subprocess.run(
                argv,
                check=False,
                capture_output=True,
                text=False,
                shell=False,
                timeout=self.timeout_seconds + 2,
                env=env,
            )
        except FileNotFoundError as exc:
            raise CapabilityExecutionError("UPSTREAM_NOT_INSTALLED", f"required read tool is not installed: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise CapabilityExecutionError("UPSTREAM_TIMEOUT", "read capability timed out") from exc

        if completed.returncode != 0:
            # Do not relay stderr because upstream tools may include sensitive
            # operational context. A coarse error is sufficient for the agent.
            raise CapabilityExecutionError("UPSTREAM_FAILED", f"read capability failed with exit code {completed.returncode}")
        if len(completed.stdout) > self.max_output_bytes:
            raise CapabilityExecutionError("OUTPUT_TOO_LARGE", "upstream output exceeded the observation budget")
        try:
            return completed.stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CapabilityExecutionError("NON_UTF8_OUTPUT", "upstream output was not UTF-8 text") from exc


def observe(raw_request: Mapping[str, Any], runner: CapabilityRunner) -> ObservationEnvelope:
    """Validate, execute one read operation, and taint the resulting content."""

    request = parse_request(raw_request)
    content = runner.run(request)
    if not isinstance(content, str):
        raise CapabilityExecutionError("INVALID_RUNNER_OUTPUT", "runner must return text")
    if not content:
        raise CapabilityExecutionError("EMPTY_OUTPUT", "runner returned no observation content")
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise CapabilityExecutionError("OUTPUT_TOO_LARGE", "runner output exceeded the observation budget")

    request_material = {
        "schema_version": REQUEST_SCHEMA,
        "request_id": request.request_id,
        "trace_id": request.trace_id,
        "tenant_id": request.tenant_id,
        "channel": request.channel,
        "operation": request.operation,
        "parameters": dict(request.parameters),
        "observed_at_seq": request.observed_at_seq,
    }
    request_digest = _sha256(_canonical_json(request_material))
    content_digest = _sha256(encoded)
    observation_material = {
        "request_digest": request_digest,
        "content_digest": content_digest,
        "plane": "agent-reach-untrusted",
        "channel": request.channel,
        "operation": request.operation,
        "observed_at_seq": request.observed_at_seq,
    }
    observation_id = _sha256(_canonical_json(observation_material))

    return ObservationEnvelope(
        schema_version=OBSERVATION_SCHEMA,
        observation_id=observation_id,
        request_id=request.request_id,
        trace_id=request.trace_id,
        tenant_id=request.tenant_id,
        plane="agent-reach-untrusted",
        channel=request.channel,
        operation=request.operation,
        observed_at_seq=request.observed_at_seq,
        request_digest=request_digest,
        content_digest=content_digest,
        content=content,
        taint_labels=("UNTRUSTED_EXTERNAL_CONTENT", "NO_AUTHORITY", "REQUIRES_INDEPENDENT_VERIFICATION"),
        authority="NONE",
        executable=False,
        instructions_are_data=True,
        claim_sieve_disposition="OBSERVATION_ONLY",
    )
