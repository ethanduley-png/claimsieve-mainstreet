"""Permit-gated, explicitly untrusted Agent Reach capability plane for MainStreet.

Agent Reach is useful for discovery and read access, but neither Agent Reach nor
internet content is an authority source. Every outbound capability request must
first be represented as a ClaimSieve proposal and authorized by a signed,
one-use ClaimSieve permit. Only then may this module invoke a tiny, audited set
of read-only upstream tools.

The boundary is intentionally strict:

    request -> ClaimSieve proposal -> signed permit -> read -> tainted observation

and never:

    internet content -> instruction/approval/authority

A successful read produces observation data only. It does not satisfy trusted
ClaimSieve evidence by itself and can never authorize a subsequent effect.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import sqlite3
import subprocess
import threading
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit, urlunsplit

from claimsieve_ref.model import (
    action_digest,
    destination_digest,
    parameter_digest,
    proposal_digest,
)


REQUEST_SCHEMA = "mainstreet.capability_request.v1"
OBSERVATION_SCHEMA = "mainstreet.untrusted_observation.v1"
AGENT_REACH_TRUST_DOMAIN = "agent-reach-untrusted"
REQUIRED_RISK_TAG = "UNTRUSTED_NETWORK_EGRESS"
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
    """Raised when an authorized upstream capability fails safely."""

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
class ReadAuthorization:
    permit_id: str
    proposal_digest: str
    action_digest: str
    authorized_at_seq: int


@dataclass(frozen=True)
class ObservationEnvelope:
    schema_version: str
    observation_id: str
    permit_id: str
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
            "permit_id": self.permit_id,
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
        """Execute one already permit-authorized capability request."""


class AuthorityPublicKey(Protocol):
    key_id: str

    def verify(self, domain: str, payload: Any, signature: str) -> bool:
        """Verify a ClaimSieve authority signature."""


class ContainmentView(Protocol):
    def is_frozen(self) -> bool: ...
    def is_suspended(self, campaign_id: str) -> bool: ...
    def is_revoked(self, permit_id: str) -> bool: ...


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
        "post", "create", "send", "write", "update", "delete", "remove", "upload",
        "comment", "reply", "like", "follow", "unfollow", "merge", "close", "reopen",
        "install", "configure", "login", "logout", "purchase", "pay", "execute",
        "run_command",
    }
)

_FORBIDDEN_PARAMETER_WORDS = frozenset(
    {
        "cookie", "cookies", "token", "secret", "password", "credential", "credentials",
        "authorization", "api_key", "apikey", "command", "argv", "environment", "env",
        "headers",
    }
)

_ID_RE = re.compile(r"^[A-Za-z0-9._:/-]{1,512}$")


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha256(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _require_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise CapabilityPolicyError("INVALID_ID", f"{field_name} is not a bounded protocol identifier")
    return value


def _require_nfc_string(value: Any, field_name: str, max_chars: int) -> str:
    if not isinstance(value, str) or not value or len(value) > max_chars:
        raise CapabilityPolicyError("INVALID_STRING", f"{field_name} must be a non-empty bounded string")
    if value != unicodedata.normalize("NFC", value):
        raise CapabilityPolicyError("NON_NFC_STRING", f"{field_name} must be NFC-normalized")
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        raise CapabilityPolicyError("CONTROL_CHARACTER", f"{field_name} contains a control character")
    return value


def _require_query(value: Any) -> str:
    query = _require_nfc_string(value, "parameters.query", MAX_QUERY_CHARS)
    if query.lstrip().startswith("-"):
        raise CapabilityPolicyError("ARGUMENT_INJECTION_DENIED", "query may not begin with an option marker")
    return query


def _require_limit(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1 or value > MAX_LIMIT:
        raise CapabilityPolicyError("INVALID_LIMIT", f"limit must be an integer from 1 to {MAX_LIMIT}")
    return value


def _validate_public_url_syntax(raw: Any) -> str:
    """Reject obvious private targets without doing network I/O pre-permit."""

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
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None and not literal.is_global:
        raise CapabilityPolicyError("PRIVATE_TARGET_DENIED", "non-global IP targets are not permitted")

    clean_netloc = hostname if parts.port is None else f"{hostname}:{parts.port}"
    return urlunsplit((parts.scheme, clean_netloc, parts.path or "/", parts.query, ""))


def _assert_public_resolution(url: str) -> None:
    """Resolve only after ClaimSieve authorization and reject private answers."""

    parts = urlsplit(url)
    hostname = parts.hostname
    if hostname is None:
        raise CapabilityExecutionError("INVALID_TARGET", "authorized URL is missing a host")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        answers = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise CapabilityExecutionError("DNS_RESOLUTION_FAILED", "target host could not be resolved") from exc
    for answer in answers:
        resolved = ipaddress.ip_address(answer[4][0])
        if not resolved.is_global:
            raise CapabilityExecutionError("PRIVATE_TARGET_DENIED", "target resolves to a non-global address")


def _reject_secret_like_parameters(value: Any, path: str = "parameters") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CapabilityPolicyError("INVALID_PARAMETER_KEY", f"{path} contains a non-string key")
            normalized = key.lower().replace("-", "_")
            if normalized in _FORBIDDEN_PARAMETER_WORDS or any(
                word in normalized for word in ("password", "secret", "credential")
            ):
                raise CapabilityPolicyError("CREDENTIAL_MATERIAL_DENIED", f"{path}.{key} is forbidden")
            _reject_secret_like_parameters(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_secret_like_parameters(child, f"{path}[{index}]")


def parse_request(raw: Mapping[str, Any]) -> CapabilityRequest:
    if not isinstance(raw, Mapping):
        raise CapabilityPolicyError("INVALID_REQUEST", "request must be an object")
    expected = {
        "schema_version", "request_id", "trace_id", "tenant_id", "channel", "operation",
        "parameters", "observed_at_seq",
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
        normalized["query"] = _require_query(parameters["query"])
    if "limit" in parameters:
        normalized["limit"] = _require_limit(parameters["limit"])
    if "url" in parameters:
        normalized["url"] = _validate_public_url_syntax(parameters["url"])

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


def claimsieve_action_for_request(request: CapabilityRequest) -> dict[str, Any]:
    """Map an internet read to the exact effect ClaimSieve must authorize.

    The network request is modeled as a network-boundary effect, not as a free
    local read, because query/URL material itself can disclose tenant data.
    """

    return {
        "kind": "fetch_artifact",
        "effect_class": "network_boundary",
        "destination": {
            "scheme": "agent-reach",
            "authority": request.channel,
            "resource": request.operation,
            "trust_domain": AGENT_REACH_TRUST_DOMAIN,
        },
        "method": "READ",
        "parameters": {
            "request_id": request.request_id,
            "observed_at_seq": request.observed_at_seq,
            "arguments": dict(request.parameters),
        },
        "reversibility": "reversible",
    }


class PermitUseStore:
    """SQLite-backed one-use reservation for Agent Reach read permits.

    The default file survives process restart. Tests may explicitly use
    ':memory:' when restart durability is not under test.
    """

    def __init__(
        self,
        path: str = "/var/lib/mainstreet-agent-reach/permit-uses.sqlite3",
    ) -> None:
        if not isinstance(path, str) or not path:
            raise ValueError("permit-use store path must be non-empty")
        self.path = path
        if path != ":memory:":
            db_path = Path(path)
            if not db_path.is_absolute():
                raise ValueError("permit-use store path must be absolute")
            db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(
            path,
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        self._connection.execute("PRAGMA busy_timeout = 30000")
        if path != ":memory:":
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.execute(
            "CREATE TABLE IF NOT EXISTS used_permits (permit_id TEXT PRIMARY KEY)"
        )

    def reserve(self, permit_id: str) -> bool:
        with self._lock:
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                self._connection.execute(
                    "INSERT INTO used_permits(permit_id) VALUES(?)",
                    (permit_id,),
                )
                self._connection.execute("COMMIT")
                return True
            except sqlite3.IntegrityError:
                self._connection.execute("ROLLBACK")
                return False
            except BaseException:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def close(self) -> None:
        with self._lock:
            self._connection.close()


@dataclass
class ClaimSieveReadPermitGate:
    """Verify a signed ClaimSieve permit before any outbound Agent Reach call.

    Policy/evidence/approval semantics were checked by the ClaimSieve authority
    before it signed the permit. This executor-side gate trusts only configured
    ClaimSieve authority public keys, then independently verifies the permit's
    exact request/action/destination/parameter binding, validity, containment,
    and one-use reservation before dispatch.
    """

    authority_keys: Mapping[str, AuthorityPublicKey]
    containment: ContainmentView
    permit_uses: PermitUseStore

    def _check_containment(self, permit: Mapping[str, Any], campaign_id: str) -> None:
        permit_id = str(permit.get("permit_id", ""))
        if self.containment.is_frozen():
            raise CapabilityPolicyError("EXECUTION_FROZEN", "observation execution is globally frozen")
        if self.containment.is_revoked(permit_id):
            raise CapabilityPolicyError("PERMIT_REVOKED", "ClaimSieve permit was revoked")
        if self.containment.is_suspended(campaign_id):
            raise CapabilityPolicyError("CAMPAIGN_SUSPENDED", "campaign is suspended")

    def authorize(
        self,
        request: CapabilityRequest,
        proposal: Mapping[str, Any],
        permit: Mapping[str, Any],
        seq: int,
    ) -> ReadAuthorization:
        if not isinstance(proposal, Mapping) or proposal.get("schema_version") != "claimsieve.proposal.v1":
            raise CapabilityPolicyError("INVALID_PROPOSAL", "a ClaimSieve proposal is required")
        if not isinstance(permit, Mapping) or permit.get("schema_version") != "claimsieve.permit.v1":
            raise CapabilityPolicyError("INVALID_PERMIT", "a ClaimSieve permit is required")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
            raise CapabilityPolicyError("INVALID_SEQUENCE", "authorization sequence is invalid")

        if proposal.get("trace_id") != request.trace_id or proposal.get("tenant_id") != request.tenant_id:
            raise CapabilityPolicyError("REQUEST_PROPOSAL_BINDING_MISMATCH", "request is not bound to the proposal")
        if proposal.get("action") != claimsieve_action_for_request(request):
            raise CapabilityPolicyError("REQUEST_ACTION_BINDING_MISMATCH", "proposal action does not exactly match the read request")
        risk_tags = proposal.get("risk_tags")
        if not isinstance(risk_tags, list) or REQUIRED_RISK_TAG not in risk_tags:
            raise CapabilityPolicyError("RISK_TAG_MISSING", f"proposal must include {REQUIRED_RISK_TAG}")

        unsigned = {key: value for key, value in permit.items() if key != "signature"}
        authority = self.authority_keys.get(str(permit.get("authority_key_id", "")))
        if authority is None or authority.key_id != permit.get("authority_key_id") or not authority.verify(
            "permit-v1", unsigned, str(permit.get("signature", ""))
        ):
            raise CapabilityPolicyError("PERMIT_SIGNATURE_INVALID", "ClaimSieve permit signature is invalid")

        campaign_id = proposal.get("campaign_id")
        if not isinstance(campaign_id, str) or not campaign_id:
            raise CapabilityPolicyError("INVALID_PROPOSAL", "proposal campaign_id is invalid")
        self._check_containment(permit, campaign_id)

        valid_from = permit.get("valid_from_seq")
        expires_at = permit.get("expires_at_seq")
        if (
            isinstance(valid_from, bool) or isinstance(expires_at, bool)
            or not isinstance(valid_from, int) or not isinstance(expires_at, int)
            or not (valid_from <= seq <= expires_at)
        ):
            raise CapabilityPolicyError("PERMIT_EXPIRED", "ClaimSieve permit is outside its validity window")
        if permit.get("max_uses") != 1:
            raise CapabilityPolicyError("PERMIT_USE_LIMIT_INVALID", "read permits must be one-use")

        expected_bindings = {
            "trace_id": proposal.get("trace_id"),
            "tenant_id": proposal.get("tenant_id"),
            "campaign_id": campaign_id,
            "principal": proposal.get("principal"),
            "proposal_digest": proposal_digest(dict(proposal)),
            "action_digest": action_digest(dict(proposal)),
            "destination_digest": destination_digest(dict(proposal)),
            "parameter_digest": parameter_digest(dict(proposal)),
        }
        for field_name, expected_value in expected_bindings.items():
            if permit.get(field_name) != expected_value:
                raise CapabilityPolicyError("PERMIT_BINDING_MISMATCH", f"permit binding mismatch: {field_name}")

        permit_id = permit.get("permit_id")
        if not isinstance(permit_id, str) or not permit_id:
            raise CapabilityPolicyError("INVALID_PERMIT", "permit_id is missing")
        if not self.permit_uses.reserve(permit_id):
            raise CapabilityPolicyError("PERMIT_REPLAY", "ClaimSieve read permit has already been used")

        # Re-check after the atomic reservation to close the common
        # revocation-between-check-and-dispatch window.
        self._check_containment(permit, campaign_id)

        return ReadAuthorization(
            permit_id=permit_id,
            proposal_digest=expected_bindings["proposal_digest"],
            action_digest=expected_bindings["action_digest"],
            authorized_at_seq=seq,
        )


class AgentReachSubprocessRunner:
    """Execute only the explicit read recipes published by Agent Reach.

    No caller supplied executable, flags, environment variables, shell syntax,
    output path, or working directory is accepted. The process uses a dedicated
    observer home rather than the planner's home, preventing ambient browser,
    GitHub writer, or provider credentials from being inherited by accident.
    """

    def __init__(
        self,
        *,
        observer_home: str = "/var/lib/mainstreet-agent-reach",
        timeout_seconds: int = 20,
        max_output_bytes: int = MAX_OUTPUT_BYTES,
    ):
        if timeout_seconds < 1 or timeout_seconds > 120:
            raise ValueError("timeout_seconds out of range")
        home = Path(observer_home)
        if not home.is_absolute():
            raise ValueError("observer_home must be absolute")
        self.observer_home = str(home)
        self.timeout_seconds = timeout_seconds
        self.max_output_bytes = max_output_bytes

    def _argv(self, request: CapabilityRequest) -> list[str]:
        key = (request.channel, request.operation)
        if key == ("agent-reach", "status"):
            return ["agent-reach", "doctor", "--json"]
        if key == ("web", "read"):
            target = request.parameters["url"]
            _assert_public_resolution(target)
            return [
                "curl", "--fail", "--silent", "--show-error", "--max-time",
                str(self.timeout_seconds), f"https://r.jina.ai/{target}",
            ]
        if key == ("github", "search_repositories"):
            return [
                "gh", "search", "repos", request.parameters["query"], "--sort", "stars",
                "--limit", str(request.parameters["limit"]), "--json",
                "fullName,description,stargazersCount,url",
            ]
        if key == ("search", "exa"):
            return [
                "mcporter", "call", "exa.web_search_exa",
                f"query={request.parameters['query']}",
                f"numResults={request.parameters['limit']}",
            ]
        if key == ("v2ex", "hot"):
            return [
                "curl", "--fail", "--silent", "--show-error", "--max-time",
                str(self.timeout_seconds), "https://www.v2ex.com/api/topics/hot.json",
                "-H", "User-Agent: mainstreet-agent-reach-observer/1",
            ]
        if key == ("bilibili", "search"):
            return [
                "bili", "search", request.parameters["query"], "--type", "video",
                "-n", str(request.parameters["limit"]),
            ]
        raise CapabilityPolicyError("CAPABILITY_DENIED", "request reached a non-allowlisted runner path")

    def run(self, request: CapabilityRequest) -> str:
        argv = self._argv(request)
        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": self.observer_home,
            "XDG_CONFIG_HOME": f"{self.observer_home}/.config",
            "XDG_CACHE_HOME": f"{self.observer_home}/.cache",
            "LANG": os.environ.get("LANG", "C.UTF-8"),
            "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
            "TMPDIR": os.environ.get("TMPDIR", "/tmp"),
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
                cwd=self.observer_home,
            )
        except FileNotFoundError as exc:
            raise CapabilityExecutionError("UPSTREAM_NOT_INSTALLED", f"required read tool is not installed: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise CapabilityExecutionError("UPSTREAM_TIMEOUT", "read capability timed out") from exc

        if completed.returncode != 0:
            # Never relay stderr: upstream tools can include credential or local
            # configuration details in diagnostics.
            raise CapabilityExecutionError("UPSTREAM_FAILED", f"read capability failed with exit code {completed.returncode}")
        if len(completed.stdout) > self.max_output_bytes:
            raise CapabilityExecutionError("OUTPUT_TOO_LARGE", "upstream output exceeded the observation budget")
        try:
            return completed.stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CapabilityExecutionError("NON_UTF8_OUTPUT", "upstream output was not UTF-8 text") from exc


def observe(
    raw_request: Mapping[str, Any],
    runner: CapabilityRunner,
    *,
    gate: ClaimSieveReadPermitGate,
    proposal: Mapping[str, Any],
    permit: Mapping[str, Any],
    seq: int,
) -> ObservationEnvelope:
    """Permit-gate one read and wrap its result as permanently tainted data."""

    request = parse_request(raw_request)
    authorization = gate.authorize(request, proposal, permit, seq)
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
        "permit_id": authorization.permit_id,
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
        permit_id=authorization.permit_id,
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
