from __future__ import annotations

import re
from copy import deepcopy
from typing import Any, Mapping

from .canonical import MAX_SAFE_INTEGER, digest

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PERMIT_PREDICATE_TYPE = "https://claimsieve.example/attestation/authorization-permit/v0.1"
EXECUTION_PREDICATE_TYPE = "https://claimsieve.example/attestation/execution-attempt/v0.1"
OBSERVATION_PREDICATE_TYPE = "https://claimsieve.example/attestation/outcome-observation/v0.1"
SUPPORTED_PREDICATE_TYPES = frozenset(
    {
        PERMIT_PREDICATE_TYPE,
        EXECUTION_PREDICATE_TYPE,
        OBSERVATION_PREDICATE_TYPE,
    }
)
_SHA256 = re.compile(r"^sha256:([0-9a-f]{64})$")
_NONCE = re.compile(r"^[a-f0-9]{32,128}$")
_PROVIDER_STATUSES = frozenset({"accepted", "rejected", "timeout_unknown", "stale_fence"})
_RECONCILIATIONS = frozenset(
    {"CONFIRMED_SUCCESS", "CONFIRMED_FAILURE", "DIVERGENT_EFFECT", "OUTCOME_UNKNOWN"}
)

_PERMIT_FIELDS = (
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
_EXECUTION_FIELDS = (
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
_OBSERVATION_FIELDS = (
    "reservation_id",
    "permit_id",
    "campaign_id",
    "provider_record_digest",
    "observed_action_digest",
    "reconciliation",
    "receipt_conflict",
    "observed_at_seq",
)


class InTotoExportError(ValueError):
    """Raised when a native ClaimSieve record cannot be exported losslessly enough."""


class InTotoVerificationError(ValueError):
    """Raised when a ClaimSieve in-toto Statement is structurally unsupported or inconsistent."""


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


def _validate_optional_digest(value: Any, field: str) -> None:
    if value is None:
        return
    _sha256_hex(value, field)


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
        "signature_verification": "NOT_PERFORMED",
    }


def permit_statement(permit: Mapping[str, Any]) -> dict[str, Any]:
    """Export a native ClaimSieve permit as an in-toto Statement v1 payload.

    This does not create a DSSE envelope and does not grant or verify authority.
    The native permit remains the authoritative authorization object.
    """
    if _require(permit, "schema_version") != "claimsieve.permit.v1":
        raise InTotoExportError("unsupported permit schema_version")

    digest_fields = (
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
    )
    for field in digest_fields:
        _sha256_hex(_require(permit, field), field)
    _validate_optional_digest(_require(permit, "approval_digest"), "approval_digest")

    permit_digest = digest(dict(permit))
    action_digest = _require(permit, "action_digest")
    subjects = [
        _subject(f"claimsieve-permit:{_require(permit, 'permit_id')}", permit_digest),
        _subject("claimsieve-authorized-action", action_digest),
    ]
    predicate = {field: deepcopy(_require(permit, field)) for field in _PERMIT_FIELDS}
    predicate["native_record"] = _native_record(permit, "authority_key_id")
    return _statement(subjects, PERMIT_PREDICATE_TYPE, predicate)


def executor_receipt_statement(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Export an executor receipt without changing execution semantics."""
    if _require(receipt, "schema_version") != "claimsieve.executor_receipt.v2":
        raise InTotoExportError("unsupported executor receipt schema_version")

    for field in ("action_digest", "request_digest"):
        _sha256_hex(_require(receipt, field), field)

    receipt_digest = digest(dict(receipt))
    action_digest = _require(receipt, "action_digest")
    subjects = [
        _subject(
            f"claimsieve-executor-receipt:{_require(receipt, 'reservation_id')}",
            receipt_digest,
        ),
        _subject("claimsieve-attempted-action", action_digest),
    ]
    predicate = {field: deepcopy(_require(receipt, field)) for field in _EXECUTION_FIELDS}
    predicate["native_record"] = _native_record(receipt, "executor_key_id")
    return _statement(subjects, EXECUTION_PREDICATE_TYPE, predicate)


def observer_receipt_statement(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Export an independent observer receipt, including unknown outcomes."""
    if _require(receipt, "schema_version") != "claimsieve.observer_receipt.v2":
        raise InTotoExportError("unsupported observer receipt schema_version")

    _validate_optional_digest(_require(receipt, "provider_record_digest"), "provider_record_digest")
    _validate_optional_digest(_require(receipt, "observed_action_digest"), "observed_action_digest")

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

    predicate = {field: deepcopy(_require(receipt, field)) for field in _OBSERVATION_FIELDS}
    predicate["native_record"] = _native_record(receipt, "observer_key_id")
    return _statement(subjects, OBSERVATION_PREDICATE_TYPE, predicate)


def _verification_error_from_export(callable_: Any, *args: Any) -> Any:
    try:
        return callable_(*args)
    except InTotoExportError as exc:
        raise InTotoVerificationError(str(exc)) from exc


def _require_nonempty_string(predicate: Mapping[str, Any], field: str) -> str:
    value = predicate.get(field)
    if not isinstance(value, str) or not value:
        raise InTotoVerificationError(f"{field} must be a non-empty string")
    return value


def _require_sequence(predicate: Mapping[str, Any], field: str, minimum: int = 0) -> int:
    value = predicate.get(field)
    if isinstance(value, bool) or not isinstance(value, int):
        raise InTotoVerificationError(f"{field} must be an integer")
    if value < minimum or value > MAX_SAFE_INTEGER:
        raise InTotoVerificationError(f"{field} outside accepted range")
    return value


def _require_exact_fields(predicate: Mapping[str, Any], fields: tuple[str, ...]) -> None:
    expected = set(fields) | {"native_record"}
    if set(predicate) != expected:
        raise InTotoVerificationError("unexpected predicate fields")


def _verify_permit_predicate(predicate: Mapping[str, Any]) -> None:
    _require_exact_fields(predicate, _PERMIT_FIELDS)
    for field in ("permit_id", "trace_id", "tenant_id", "campaign_id"):
        _require_nonempty_string(predicate, field)
    principal = _require_nonempty_string(predicate, "principal")
    if not principal.startswith("spiffe://"):
        raise InTotoVerificationError("principal must use spiffe:// identity")
    for field in (
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
    ):
        _verification_error_from_export(_sha256_hex, predicate.get(field), field)
    _verification_error_from_export(
        _validate_optional_digest, predicate.get("approval_digest"), "approval_digest"
    )
    valid_from = _require_sequence(predicate, "valid_from_seq")
    expires_at = _require_sequence(predicate, "expires_at_seq")
    if expires_at < valid_from:
        raise InTotoVerificationError("permit expiry precedes validity start")
    if predicate.get("max_uses") != 1 or isinstance(predicate.get("max_uses"), bool):
        raise InTotoVerificationError("max_uses must be exactly 1")
    nonce = predicate.get("nonce")
    if not isinstance(nonce, str) or _NONCE.fullmatch(nonce) is None:
        raise InTotoVerificationError("invalid permit nonce")


def _verify_execution_predicate(predicate: Mapping[str, Any]) -> None:
    _require_exact_fields(predicate, _EXECUTION_FIELDS)
    for field in ("trace_id", "campaign_id", "permit_id", "reservation_id", "idempotency_key"):
        _require_nonempty_string(predicate, field)
    for field in ("action_digest", "request_digest"):
        _verification_error_from_export(_sha256_hex, predicate.get(field), field)
    _require_sequence(predicate, "fencing_token", minimum=1)
    _require_sequence(predicate, "containment_epoch")
    _require_sequence(predicate, "attempted_at_seq")
    if predicate.get("provider_status") not in _PROVIDER_STATUSES:
        raise InTotoVerificationError("unsupported provider_status")
    provider_id = predicate.get("provider_id")
    if provider_id is not None and (not isinstance(provider_id, str) or not provider_id):
        raise InTotoVerificationError("provider_id must be null or non-empty string")


def _verify_observation_predicate(predicate: Mapping[str, Any]) -> None:
    _require_exact_fields(predicate, _OBSERVATION_FIELDS)
    for field in ("reservation_id", "permit_id", "campaign_id"):
        _require_nonempty_string(predicate, field)
    _verification_error_from_export(
        _validate_optional_digest, predicate.get("provider_record_digest"), "provider_record_digest"
    )
    _verification_error_from_export(
        _validate_optional_digest, predicate.get("observed_action_digest"), "observed_action_digest"
    )
    if predicate.get("reconciliation") not in _RECONCILIATIONS:
        raise InTotoVerificationError("unsupported reconciliation")
    if not isinstance(predicate.get("receipt_conflict"), bool):
        raise InTotoVerificationError("receipt_conflict must be boolean")
    _require_sequence(predicate, "observed_at_seq")


def verify_exported_statement(statement: Mapping[str, Any]) -> None:
    """Fail closed on unsupported or internally inconsistent exported Statements.

    This verifies only the ClaimSieve interoperability profile. It does not verify
    DSSE, Sigstore, or the embedded native ClaimSieve signature, and therefore
    does not establish runtime authority.
    """
    if not isinstance(statement, Mapping):
        raise InTotoVerificationError("statement must be an object")
    if set(statement) != {"_type", "subject", "predicateType", "predicate"}:
        raise InTotoVerificationError("unexpected Statement fields")
    if statement.get("_type") != STATEMENT_TYPE:
        raise InTotoVerificationError("unsupported Statement type")

    predicate_type = statement.get("predicateType")
    if predicate_type not in SUPPORTED_PREDICATE_TYPES:
        raise InTotoVerificationError("unsupported predicate type")
    subjects = statement.get("subject")
    predicate = statement.get("predicate")
    if not isinstance(subjects, list) or not subjects:
        raise InTotoVerificationError("Statement requires subjects")
    if not isinstance(predicate, Mapping):
        raise InTotoVerificationError("predicate must be an object")

    if predicate_type == PERMIT_PREDICATE_TYPE:
        _verify_permit_predicate(predicate)
    elif predicate_type == EXECUTION_PREDICATE_TYPE:
        _verify_execution_predicate(predicate)
    else:
        _verify_observation_predicate(predicate)

    for subject in subjects:
        if not isinstance(subject, Mapping) or set(subject) != {"name", "digest"}:
            raise InTotoVerificationError("invalid subject shape")
        if not isinstance(subject.get("name"), str) or not subject["name"]:
            raise InTotoVerificationError("invalid subject name")
        digests = subject.get("digest")
        if not isinstance(digests, Mapping) or set(digests) != {"sha256"}:
            raise InTotoVerificationError("only sha256 subject digests are accepted")
        value = digests.get("sha256")
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise InTotoVerificationError("invalid subject sha256")

    native = predicate.get("native_record")
    if not isinstance(native, Mapping):
        raise InTotoVerificationError("native_record is required")
    expected_native_fields = {
        "schema_version",
        "digest",
        "key_id",
        "signature",
        "signature_format",
        "signature_verification",
    }
    if set(native) != expected_native_fields:
        raise InTotoVerificationError("unexpected native_record fields")
    if not isinstance(native.get("key_id"), str) or not native.get("key_id"):
        raise InTotoVerificationError("native key_id must be a non-empty string")
    if not isinstance(native.get("signature"), str) or not native.get("signature"):
        raise InTotoVerificationError("native signature must be a non-empty string")
    if native.get("signature_format") != "claimsieve-native":
        raise InTotoVerificationError("unsupported native signature format")
    if native.get("signature_verification") != "NOT_PERFORMED":
        raise InTotoVerificationError("exporter must not claim native signature verification")
    native_hex = _verification_error_from_export(_sha256_hex, native.get("digest"), "native_record.digest")

    first_digest = subjects[0]["digest"]["sha256"]
    if first_digest != native_hex:
        raise InTotoVerificationError("native record subject digest mismatch")

    expected_schema = {
        PERMIT_PREDICATE_TYPE: "claimsieve.permit.v1",
        EXECUTION_PREDICATE_TYPE: "claimsieve.executor_receipt.v2",
        OBSERVATION_PREDICATE_TYPE: "claimsieve.observer_receipt.v2",
    }[predicate_type]
    if native.get("schema_version") != expected_schema:
        raise InTotoVerificationError("predicate/native schema mismatch")

    if predicate_type == PERMIT_PREDICATE_TYPE:
        action_hex = _verification_error_from_export(_sha256_hex, predicate.get("action_digest"), "action_digest")
        if len(subjects) != 2 or subjects[1].get("name") != "claimsieve-authorized-action":
            raise InTotoVerificationError("permit Statement requires authorized-action subject")
        if subjects[1]["digest"]["sha256"] != action_hex:
            raise InTotoVerificationError("authorized action subject mismatch")
    elif predicate_type == EXECUTION_PREDICATE_TYPE:
        action_hex = _verification_error_from_export(_sha256_hex, predicate.get("action_digest"), "action_digest")
        if len(subjects) != 2 or subjects[1].get("name") != "claimsieve-attempted-action":
            raise InTotoVerificationError("execution Statement requires attempted-action subject")
        if subjects[1]["digest"]["sha256"] != action_hex:
            raise InTotoVerificationError("attempted action subject mismatch")
    else:
        observed = predicate.get("observed_action_digest")
        if observed is None:
            if len(subjects) != 1:
                raise InTotoVerificationError("unknown outcome must not invent observed-action subject")
        else:
            observed_hex = _verification_error_from_export(
                _sha256_hex, observed, "observed_action_digest"
            )
            if len(subjects) != 2 or subjects[1].get("name") != "claimsieve-observed-action":
                raise InTotoVerificationError("observation Statement requires observed-action subject")
            if subjects[1]["digest"]["sha256"] != observed_hex:
                raise InTotoVerificationError("observed action subject mismatch")
