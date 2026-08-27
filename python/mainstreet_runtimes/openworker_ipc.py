from __future__ import annotations

import http.client
import json
import ssl
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit

from .openworker_claimsieve_intake import OpenWorkerFounderIntake, OpenWorkerIntakeError

CLAIMSIEVE_INTAKE_HOST = "claimsieve-intake.mainstreet-system.svc.cluster.local"
CLAIMSIEVE_INTAKE_PORT = 8443
CLAIMSIEVE_INTAKE_PATH = "/v1/runtime/openworker/intents"
MAX_INTENT_BYTES = 64 * 1024
MAX_RECEIPT_BYTES = 128 * 1024

_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "permit_id",
        "proposal_id",
        "runtime_name",
        "runtime_version",
        "runtime_principal",
        "runtime_manifest_digest",
        "proposal_digest",
        "action_digest",
        "destination_digest",
        "parameter_digest",
        "expires_at_seq",
        "external_action_executed",
    }
)


class OpenWorkerIPCError(RuntimeError):
    pass


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise OpenWorkerIPCError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _decode_closed_json(raw: bytes, maximum: int) -> dict[str, Any]:
    if len(raw) > maximum:
        raise OpenWorkerIPCError("IPC JSON payload exceeds size limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OpenWorkerIPCError("IPC JSON payload is malformed") from exc
    if not isinstance(value, dict):
        raise OpenWorkerIPCError("IPC JSON payload must be an object")
    return value


class OpenWorkerIntakeService:
    """Framework-neutral ClaimSieve intake handler behind authenticated TLS termination.

    The TLS/server layer must provide the authenticated SPIFFE identity from the client
    certificate; this handler never accepts caller identity from the JSON body or an
    untrusted HTTP header.
    """

    def __init__(self, intake: OpenWorkerFounderIntake) -> None:
        self._intake = intake
        self._expected_principal = intake._runtime_profile.principal  # bounded internal composition

    def handle(self, raw_body: bytes, authenticated_principal: str) -> bytes:
        if authenticated_principal != self._expected_principal:
            raise OpenWorkerIPCError("authenticated OpenWorker principal mismatch")
        intent = _decode_closed_json(raw_body, MAX_INTENT_BYTES)
        try:
            receipt = self._intake.route_intent(intent)
        except OpenWorkerIntakeError:
            raise
        encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(encoded) > MAX_RECEIPT_BYTES:
            raise OpenWorkerIPCError("ClaimSieve intake receipt exceeds size limit")
        return encoded


class OpenWorkerClaimSieveHTTPSClient:
    """mTLS client for the only production OpenWorker consequential-action egress path."""

    def __init__(
        self,
        *,
        endpoint: str,
        ca_file: str | Path,
        client_cert_file: str | Path,
        client_key_file: str | Path,
        timeout_seconds: float = 5.0,
    ) -> None:
        parts = urlsplit(endpoint)
        if (
            parts.scheme != "https"
            or parts.hostname != CLAIMSIEVE_INTAKE_HOST
            or parts.port != CLAIMSIEVE_INTAKE_PORT
            or parts.path != CLAIMSIEVE_INTAKE_PATH
            or parts.query
            or parts.fragment
            or parts.username is not None
            or parts.password is not None
        ):
            raise OpenWorkerIPCError("ClaimSieve intake endpoint must match the fixed production mTLS endpoint")
        if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) or timeout_seconds <= 0 or timeout_seconds > 30:
            raise OpenWorkerIPCError("ClaimSieve intake timeout must be in (0, 30] seconds")
        files = [Path(ca_file), Path(client_cert_file), Path(client_key_file)]
        if any(not path.is_file() for path in files):
            raise OpenWorkerIPCError("ClaimSieve mTLS material is missing")

        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(files[0]))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile=str(files[1]), keyfile=str(files[2]))
        self._context = context
        self._timeout = float(timeout_seconds)

    @staticmethod
    def _validate_receipt(receipt: Mapping[str, Any]) -> dict[str, Any]:
        if frozenset(receipt) != _RECEIPT_FIELDS:
            raise OpenWorkerIPCError("ClaimSieve intake receipt fields do not match the closed schema")
        if receipt.get("schema_version") != "mainstreet.claimsieve_intake_receipt.v1":
            raise OpenWorkerIPCError("unsupported ClaimSieve intake receipt schema")
        if receipt.get("status") != "PERMIT_ISSUED_EXECUTION_PENDING":
            raise OpenWorkerIPCError("unexpected ClaimSieve intake status")
        if receipt.get("runtime_name") != "openworker":
            raise OpenWorkerIPCError("ClaimSieve receipt runtime mismatch")
        if receipt.get("external_action_executed") is not False:
            raise OpenWorkerIPCError("ClaimSieve receipt cannot report execution on proposal intake")
        return dict(receipt)

    def route_intent(self, intent: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(intent, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if len(body) > MAX_INTENT_BYTES:
            raise OpenWorkerIPCError("OpenWorker intent exceeds IPC size limit")
        conn = http.client.HTTPSConnection(
            CLAIMSIEVE_INTAKE_HOST,
            CLAIMSIEVE_INTAKE_PORT,
            timeout=self._timeout,
            context=self._context,
        )
        try:
            conn.request(
                "POST",
                CLAIMSIEVE_INTAKE_PATH,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
            response = conn.getresponse()
            if response.status != 200:
                raise OpenWorkerIPCError(f"ClaimSieve intake returned HTTP {response.status}; redirects and fallback are forbidden")
            raw = response.read(MAX_RECEIPT_BYTES + 1)
            if len(raw) > MAX_RECEIPT_BYTES:
                raise OpenWorkerIPCError("ClaimSieve intake receipt exceeds size limit")
            return self._validate_receipt(_decode_closed_json(raw, MAX_RECEIPT_BYTES))
        except (OSError, http.client.HTTPException) as exc:
            raise OpenWorkerIPCError("ClaimSieve intake transport failed closed") from exc
        finally:
            conn.close()
