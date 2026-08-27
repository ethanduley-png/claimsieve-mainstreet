from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Mapping

from .canonical import digest

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PERMIT_PREDICATE_TYPE = "https://claimsieve.example/attestation/authorization-permit/v0.1"
EXECUTION_PREDICATE_TYPE = "https://claimsieve.example/attestation/execution-attempt/v0.1"
OBSERVATION_PREDICATE_TYPE = "https://claimsieve.example/attestation/outcome-observation/v0.1"
_SHA256 = re.compile(r"^sha256:([0-9a-f]{64})$")


class InTotoExportError(ValueError):
    """Raised when a native ClaimSieve record cannot be exported losslessly enough."""


def _require(record: Mapping[str, Any], field: str) -> Any:
    if field not in record:
        raise InTotoExportError(f"missing required field: {field}")
    return record[field]


def _sha256_hex(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise InTotoExportError(f"{field} must be a sha256 digest string")
    match = _SHA256.fullmatch(value)
    if match is None:
        raise InTotoExportError(f"{field} must match sha256:<64 lowercase hex>")
    return match.group(1)


def _subject(name: str, digest_value: str) -> dict[str, Any]:
    return {"name": name, "digest": {"sha256": _sha256_hex(digest_value, name)}}


def _statement(
    subjects: list[dict[str, Any]],
    predicate_type: str,
    predicate: Mapping[str, Any],
) -> dict[str, Any]:
    if not subjects:
        raise InTotoExportError("at least one subject is required")
    return {
        "_type": STATEMENT_TYPE,
        "subject": deepcopy(subjects),
        "predicateType": predicate_type,
        "predicate": deepcopy(dict(predicate)),
    }


def _native_record(
    record: Mapping[str, Any],
    key_id_field: str,
    signature_field: str = "signature",
) -> dict[str, Any]:
    key_id = _require(record, key_id_field)
    signature = _require(record, signature_field)
    if not isinstance(key_id, str) or not key_id:
        raise InTotoExportError(f"{key_id_field} must be a non-empty string")
    if not isinstance(signature, str) or not signature:
        raise InTotoExportError(f"{signature_field} must be a non-empty string")
    return {
        "schema_version": _require(record, "schema_version"),
        "digest": digest(dict(record)),
        "key_id": key_id,
        "signature": signature,
        "signature_format": "claimsieve-native",
    }


def permit_statement(permit: Mapping[str, Any]) -> dict[str, Any]:
    """Export a native ClaimSieve permit as an in-toto Statement v1 payload.

    This does not create a DSSE envelope and does not grant or verify authority.
    The native permit remains the authoritative authorization object.
    """
    if _require(permit, "schema_version") != "claimsieve.permit.v1":
        raise InTotoExportError("unsupported permit schema_version")

    permit_digest = digest(dict(permit))
    action_digest = _require(permit, "action_digest")
    subjects = [
        _subject(f"claimsieve-permit:{_require(permit, 'permit_id')}", permit_digest),
        _subject("claimsieve-authorized-action", action_digest),
    ]
    fields = (
        "permit_id",
        "trace_id",
        "tenant_id",
        "campaign_id",
        "principal",
        "proposal_digest",
        "action_digest",
        "destination_digest",
        "parameter_digest",
        "policy_digest",
        "signed_policy_digest",
        "prior_campaign_state_digest",
        "campaign_state_digest",
        "evidence_root",
        "decision_digest",
        "approval_digest",
        "valid_from_seq",
        "expires_at_seq",
        "max_uses",
        "nonce",
    )
    predicate = {field: deepcopy(_require(permit, field)) for field in fields}
    predicate["native_record"] = _native_record(permit, "authority_key_id")
    return _statement(subjects, PERMIT_PREDICATE_TYPE, predicate)


def executor_receipt_statement(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Export an executor receipt without changing execution semantics."""
    if _require(receipt, "schema_version") != "claimsieve.executor_receipt.v2":
        raise InTotoExportError("unsupported executor receipt schema_version")

    receipt_digest = digest(dict(receipt))
    action_digest = _require(receipt, "action_digest")
    subjects = [
        _subject(
            f"claimsieve-executor-receipt:{_require(receipt, 'reservation_id')}",
            receipt_digest,
        ),
        _subject("claimsieve-attempted-action", action_digest),
    ]
    fields = (
        "trace_id",
        "campaign_id",
        "permit_id",
        "reservation_id",
        "action_digest",
        "request_digest",
        "idempotency_key",
        "fencing_token",
        "containment_epoch",
        "provider_status",
        "provider_id",
        "attempted_at_seq",
    )
    predicate = {field: deepcopy(_require(receipt, field)) for field in fields}
    predicate["native_record"] = _native_record(receipt, "executor_key_id")
    return _statement(subjects, EXECUTION_PREDICATE_TYPE, predicate)


def observer_receipt_statement(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Export an independent observer receipt, including unknown outcomes."""
    if _require(receipt, "schema_version") != "claimsieve.observer_receipt.v2":
        raise InTotoExportError("unsupported observer receipt schema_version")

    receipt_digest = digest(dict(receipt))
    subjects = [
        _subject(
            f"claimsieve-observer-receipt:{_require(receipt, 'reservation_id')}",
            receipt_digest,
        )
    ]
    observed_action_digest = _require(receipt, "observed_action_digest")
    if observed_action_digest is not None:
        subjects.append(_subject("claimsieve-observed-action", observed_action_digest))

    fields = (
        "reservation_id",
        "permit_id",
        "campaign_id",
        "provider_record_digest",
        "observed_action_digest",
        "reconciliation",
        "receipt_conflict",
        "observed_at_seq",
    )
    predicate = {field: deepcopy(_require(receipt, field)) for field in fields}
    predicate["native_record"] = _native_record(receipt, "observer_key_id")
    return _statement(subjects, OBSERVATION_PREDICATE_TYPE, predicate)
