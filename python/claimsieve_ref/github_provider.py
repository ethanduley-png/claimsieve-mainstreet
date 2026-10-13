from __future__ import annotations

import base64
import hashlib
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .canonical import canonical_bytes, loads_strict
from .durable_state import DispatchTicket, DurableStateError

DEFAULT_API_BASE_URL = "https://api.github.com"
DEFAULT_API_VERSION = "2026-03-10"
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$")
_MARKER_PREFIX = "<!-- claimsieve-v1:"
# GitHub's web editor can rewrite line endings to CRLF and append trailing
# whitespace. Those edits must not hide an existing marker from observation.
_MARKER_RE = re.compile(
    r"(?:\r?\n){2}<!-- claimsieve-v1:([0-9a-f]{64}):([A-Za-z0-9_-]+) -->\s*\Z"
)


class GitHubProviderError(DurableStateError):
    """Fail-closed GitHub adapter error that never includes credentials."""


class GitHubTransportError(GitHubProviderError):
    """The transport outcome is not trustworthy enough to classify as failure."""


@dataclass(frozen=True)
class GitHubHttpResponse:
    status: int
    headers: Mapping[str, str]
    body: Any


class GitHubTransport(Protocol):
    def request(
        self,
        method: str,
        path: str,
        token: str,
        json_body: dict[str, Any] | None = None,
    ) -> GitHubHttpResponse: ...


class _RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class UrllibGitHubTransport:
    """Small GitHub.com-only REST transport with bounded responses and no retries."""

    def __init__(
        self,
        api_base_url: str = DEFAULT_API_BASE_URL,
        api_version: str = DEFAULT_API_VERSION,
        timeout_seconds: int = 20,
    ) -> None:
        parsed = urllib.parse.urlsplit(api_base_url)
        if (
            parsed.scheme != "https"
            or parsed.hostname != "api.github.com"
            or parsed.port is not None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise GitHubProviderError("GitHub API base URL must be exactly https://api.github.com")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", api_version):
            raise GitHubProviderError("GitHub API version must use YYYY-MM-DD")
        if isinstance(timeout_seconds, bool) or not 1 <= timeout_seconds <= 120:
            raise GitHubProviderError("GitHub timeout must be between 1 and 120 seconds")
        self.api_base_url = DEFAULT_API_BASE_URL
        self.api_version = api_version
        self.timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(_RejectRedirects())

    def request(
        self,
        method: str,
        path: str,
        token: str,
        json_body: dict[str, Any] | None = None,
    ) -> GitHubHttpResponse:
        if method not in {"GET", "POST"}:
            raise GitHubProviderError("GitHub transport method is not allowlisted")
        if not path.startswith("/") or path.startswith("//"):
            raise GitHubProviderError("GitHub API path is invalid")
        _validate_token(token)
        data = None
        if json_body is not None:
            data = json.dumps(
                json_body,
                ensure_ascii=False,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8")
        request = urllib.request.Request(
            self.api_base_url + path,
            data=data,
            method=method,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "ClaimSieve-FounderOS/0.34",
                "X-GitHub-Api-Version": self.api_version,
            },
        )
        try:
            with self._opener.open(request, timeout=self.timeout_seconds) as response:
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw) > _MAX_RESPONSE_BYTES:
                    raise GitHubTransportError("GitHub response exceeded the size limit")
                return GitHubHttpResponse(
                    status=int(response.status),
                    headers={key.lower(): value for key, value in response.headers.items()},
                    body=_decode_json(raw),
                )
        except urllib.error.HTTPError as exc:
            raw = exc.read(_MAX_RESPONSE_BYTES + 1)
            if len(raw) > _MAX_RESPONSE_BYTES:
                raise GitHubTransportError("GitHub error response exceeded the size limit") from exc
            return GitHubHttpResponse(
                status=int(exc.code),
                headers={key.lower(): value for key, value in exc.headers.items()},
                body=_decode_json(raw),
            )
        except (urllib.error.URLError, TimeoutError, socket.timeout, OSError) as exc:
            raise GitHubTransportError(
                f"GitHub transport outcome unknown ({type(exc).__name__})"
            ) from exc


def _decode_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubTransportError("GitHub returned malformed JSON") from exc


def _validate_token(token: str) -> None:
    if not isinstance(token, str) or not token or len(token) > 2048:
        raise GitHubProviderError("GitHub token is missing or malformed")
    if any(character.isspace() or ord(character) < 0x20 for character in token):
        raise GitHubProviderError("GitHub token is missing or malformed")


def _validate_repository(repository: str) -> None:
    if not isinstance(repository, str) or not _REPOSITORY_RE.fullmatch(repository):
        raise GitHubProviderError("repository must be an exact owner/name identifier")


def _repository_path(repository: str) -> str:
    owner, name = repository.split("/", 1)
    return "/repos/" + urllib.parse.quote(owner, safe="") + "/" + urllib.parse.quote(name, safe="")


def _marker_fingerprint(idempotency_key: str) -> str:
    return hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()


def _encode_marker(metadata: dict[str, Any]) -> str:
    encoded = base64.urlsafe_b64encode(canonical_bytes(metadata)).decode("ascii").rstrip("=")
    return f"{_MARKER_PREFIX}{_marker_fingerprint(str(metadata['idempotency_key']))}:{encoded} -->"


def _decode_marker(body: str, idempotency_key: str) -> tuple[str, dict[str, Any]] | None:
    match = _MARKER_RE.search(body)
    if match is None or match.group(1) != _marker_fingerprint(idempotency_key):
        return None
    encoded = match.group(2)
    try:
        padded = encoded + "=" * (-len(encoded) % 4)
        metadata = loads_strict(base64.urlsafe_b64decode(padded).decode("utf-8"))
    except Exception as exc:
        raise GitHubProviderError("matching GitHub issue contains an invalid ClaimSieve marker") from exc
    if not isinstance(metadata, dict) or metadata.get("idempotency_key") != idempotency_key:
        raise GitHubProviderError("matching GitHub issue contains a mismatched ClaimSieve marker")
    return body[: match.start()], metadata


class GitHubIssueProvider:
    """Restricted GitHub issue writer plus independently credentialed read-back.

    GitHub issue creation has no ClaimSieve-compatible idempotency primitive.
    This adapter therefore performs exactly one POST, never retries a transport-
    ambiguous write, and relies on a hidden correlation marker for read-back.
    """

    def __init__(
        self,
        allowed_repositories: set[str] | frozenset[str],
        read_token: str,
        write_token: str | None = None,
        *,
        transport: GitHubTransport | None = None,
        max_observation_pages: int = 10,
        require_distinct_tokens: bool = True,
    ) -> None:
        repositories = frozenset(allowed_repositories)
        if not repositories:
            raise GitHubProviderError("at least one GitHub repository must be allowlisted")
        for repository in repositories:
            _validate_repository(repository)
        _validate_token(read_token)
        if write_token is not None:
            _validate_token(write_token)
            if require_distinct_tokens and write_token == read_token:
                raise GitHubProviderError("GitHub read and write tokens must be distinct")
        if isinstance(max_observation_pages, bool) or not 1 <= max_observation_pages <= 100:
            raise GitHubProviderError("max_observation_pages must be between 1 and 100")
        self.allowed_repositories = repositories
        self._read_token = read_token
        self._write_token = write_token
        self._transport = transport or UrllibGitHubTransport()
        self._max_observation_pages = max_observation_pages

    def check_repository(self, repository: str) -> dict[str, Any]:
        self._require_allowed_repository(repository)
        response = self._transport.request(
            "GET", _repository_path(repository), self._read_token
        )
        if response.status != 200 or not isinstance(response.body, dict):
            raise GitHubProviderError(
                f"GitHub repository access check failed with HTTP {response.status}"
            )
        full_name = response.body.get("full_name")
        if not isinstance(full_name, str) or full_name.casefold() != repository.casefold():
            raise GitHubProviderError("GitHub repository response identity mismatch")
        if response.body.get("has_issues") is not True:
            raise GitHubProviderError("GitHub Issues is disabled for the repository")
        return {
            "repository": full_name,
            "repository_id": response.body.get("id"),
            "private": response.body.get("private"),
            "archived": response.body.get("archived"),
            "has_issues": True,
            "visibility": response.body.get("visibility"),
            "permissions": response.body.get("permissions"),
            "api_version": DEFAULT_API_VERSION,
        }

    def invoke(self, action: dict[str, Any], ticket: DispatchTicket) -> dict[str, Any]:
        repository, title, body = self._validate_action(action)
        if self._write_token is None:
            raise GitHubProviderError("GitHub write token is not configured")

        existing = self._query(ticket.idempotency_key, strict=True)
        if existing is not None:
            if existing.get("request_digest") != ticket.request_digest:
                raise GitHubProviderError("GitHub marker request digest mismatch")
            response = existing.get("response")
            if isinstance(response, dict) and response.get("status") == "accepted":
                return {
                    "status": "accepted",
                    "provider_id": existing.get("provider_id"),
                    "idempotent_replay": True,
                }
            return {"status": "timeout_unknown", "provider_id": None}

        parameters = action["parameters"]
        metadata = {
            "schema_version": "claimsieve.github_marker.v1",
            "idempotency_key": ticket.idempotency_key,
            "request_digest": ticket.request_digest,
            "resource_key": ticket.resource_key,
            "fencing_token": ticket.fencing_token,
            "action_digest": ticket.action_digest,
            "correlation_marker": parameters["correlation_marker"],
            "work_item_id": parameters["work_item_id"],
        }
        payload = {"title": title, "body": body + "\n\n" + _encode_marker(metadata)}
        try:
            response = self._transport.request(
                "POST",
                _repository_path(repository) + "/issues",
                self._write_token,
                payload,
            )
        except GitHubTransportError:
            return {"status": "timeout_unknown", "provider_id": None}
        if response.status == 201 and isinstance(response.body, dict):
            provider_id = self._validated_issue_url(repository, response.body)
            return {"status": "accepted", "provider_id": provider_id}
        if response.status in {401, 403, 404, 410, 422}:
            return {
                "status": "rejected",
                "provider_id": None,
                "http_status": response.status,
            }
        return {
            "status": "timeout_unknown",
            "provider_id": None,
            "http_status": response.status,
        }

    def query(self, idempotency_key: str) -> dict[str, Any] | None:
        return self._query(idempotency_key, strict=False)

    def _query(self, idempotency_key: str, *, strict: bool) -> dict[str, Any] | None:
        fingerprint = _marker_fingerprint(idempotency_key)
        matches: list[dict[str, Any]] = []
        malformed_match = False
        window_exhausted = False
        for repository in sorted(self.allowed_repositories):
            for page in range(1, self._max_observation_pages + 1):
                query = urllib.parse.urlencode(
                    {
                        "state": "all",
                        "per_page": 100,
                        "page": page,
                        "sort": "created",
                        "direction": "desc",
                    }
                )
                try:
                    response = self._transport.request(
                        "GET",
                        _repository_path(repository) + "/issues?" + query,
                        self._read_token,
                    )
                except GitHubTransportError as exc:
                    if strict:
                        raise GitHubProviderError(
                            "GitHub observation preflight transport failed"
                        ) from exc
                    return None
                if response.status != 200 or not isinstance(response.body, list):
                    if strict:
                        raise GitHubProviderError(
                            f"GitHub observation preflight failed with HTTP {response.status}"
                        )
                    return None
                for issue in response.body:
                    if not isinstance(issue, dict) or "pull_request" in issue:
                        continue
                    issue_body = issue.get("body")
                    if not isinstance(issue_body, str) or f"{_MARKER_PREFIX}{fingerprint}:" not in issue_body:
                        continue
                    try:
                        decoded = _decode_marker(issue_body, idempotency_key)
                    except GitHubProviderError:
                        malformed_match = True
                        continue
                    if decoded is None:
                        # The fingerprint is present but the marker is not in its
                        # exact trailing position. Treating that as "no match"
                        # would let a duplicate write pass the preflight.
                        malformed_match = True
                        continue
                    base_body, metadata = decoded
                    try:
                        matches.append(
                            self._provider_record(repository, issue, base_body, metadata)
                        )
                    except GitHubProviderError:
                        malformed_match = True
                if len(response.body) < 100:
                    break
            else:
                # Every page in the window was full; older issues were not read.
                window_exhausted = True
        if malformed_match or len(matches) > 1:
            effect = matches[0]["effect"] if matches else {"invalid_github_marker": True}
            return {
                "idempotency_key": idempotency_key,
                "request_digest": matches[0].get("request_digest") if matches else None,
                "resource_key": matches[0].get("resource_key") if matches else None,
                "fencing_token": matches[0].get("fencing_token") if matches else 0,
                "status": "conflict",
                "provider_id": None,
                "effect": effect,
                "response": {
                    "status": "rejected",
                    "provider_id": None,
                    "reason": "duplicate_or_invalid_claimsieve_marker",
                },
            }
        if window_exhausted:
            # A bounded scan can establish neither absence nor uniqueness when
            # every page in the observation window was full. Even one visible
            # valid marker is insufficient because an older duplicate or
            # malformed marker may exist beyond the scanned window.
            if strict:
                raise GitHubProviderError(
                    "GitHub observation window exhausted before uniqueness could be established"
                )
            return None
        return matches[0] if matches else None

    def _provider_record(
        self,
        repository: str,
        issue: dict[str, Any],
        body: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        required_strings = (
            "idempotency_key",
            "request_digest",
            "resource_key",
            "action_digest",
            "correlation_marker",
            "work_item_id",
        )
        if any(not isinstance(metadata.get(field), str) for field in required_strings):
            raise GitHubProviderError("GitHub marker field is malformed")
        fencing_token = metadata.get("fencing_token")
        if isinstance(fencing_token, bool) or not isinstance(fencing_token, int) or fencing_token < 0:
            raise GitHubProviderError("GitHub marker fencing token is malformed")
        title = issue.get("title")
        if not isinstance(title, str):
            raise GitHubProviderError("GitHub issue title is malformed")
        provider_id = self._validated_issue_url(repository, issue)
        effect = {
            "kind": "run_connector",
            "effect_class": "external_write",
            "destination": {
                "scheme": "github",
                "authority": repository,
                "resource": "issues",
                "trust_domain": "github.com",
            },
            "method": "CREATE",
            "parameters": {
                "title": title,
                "body": body,
                "correlation_marker": metadata["correlation_marker"],
                "work_item_id": metadata["work_item_id"],
            },
            "reversibility": "compensable",
        }
        return {
            "idempotency_key": metadata["idempotency_key"],
            "request_digest": metadata["request_digest"],
            "resource_key": metadata["resource_key"],
            "fencing_token": fencing_token,
            "status": "accepted",
            "provider_id": provider_id,
            "effect": effect,
            "response": {"status": "accepted", "provider_id": provider_id},
        }

    def _validate_action(self, action: dict[str, Any]) -> tuple[str, str, str]:
        if not isinstance(action, dict):
            raise GitHubProviderError("GitHub action is malformed")
        destination = action.get("destination")
        parameters = action.get("parameters")
        if not isinstance(destination, dict) or not isinstance(parameters, dict):
            raise GitHubProviderError("GitHub action boundary is malformed")
        expected = {
            "kind": "run_connector",
            "effect_class": "external_write",
            "method": "CREATE",
            "reversibility": "compensable",
        }
        for field, value in expected.items():
            if action.get(field) != value:
                raise GitHubProviderError(f"GitHub action field is not allowlisted: {field}")
        repository = destination.get("authority")
        self._require_allowed_repository(repository)
        if destination != {
            "scheme": "github",
            "authority": repository,
            "resource": "issues",
            "trust_domain": "github.com",
        }:
            raise GitHubProviderError("GitHub destination is not the exact issue endpoint")
        title = parameters.get("title")
        body = parameters.get("body")
        if not isinstance(title, str) or not title or len(title) > 180:
            raise GitHubProviderError("GitHub issue title is malformed")
        if not isinstance(body, str) or not body or len(body) > 20_000:
            raise GitHubProviderError("GitHub issue body is malformed")
        if _MARKER_PREFIX in body:
            raise GitHubProviderError("GitHub issue body contains a reserved ClaimSieve marker")
        for field in ("correlation_marker", "work_item_id"):
            if not isinstance(parameters.get(field), str) or not parameters[field]:
                raise GitHubProviderError(f"GitHub action parameter is malformed: {field}")
        if set(parameters) != {"title", "body", "correlation_marker", "work_item_id"}:
            raise GitHubProviderError("GitHub action parameters are not exactly allowlisted")
        return repository, title, body

    def _require_allowed_repository(self, repository: Any) -> None:
        if not isinstance(repository, str):
            raise GitHubProviderError("GitHub repository is malformed")
        _validate_repository(repository)
        if repository not in self.allowed_repositories:
            raise GitHubProviderError("GitHub repository is not allowlisted")

    @staticmethod
    def _validated_issue_url(repository: str, issue: dict[str, Any]) -> str:
        number = issue.get("number")
        html_url = issue.get("html_url")
        if isinstance(number, bool) or not isinstance(number, int) or number <= 0:
            raise GitHubProviderError("GitHub issue response number is malformed")
        expected = f"https://github.com/{repository}/issues/{number}"
        if html_url != expected:
            raise GitHubProviderError("GitHub issue response URL is outside the allowlist")
        return expected
