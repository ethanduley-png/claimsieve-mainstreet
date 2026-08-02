from __future__ import annotations

import copy
from typing import Any, Mapping

from .crypto import KeyPair, PublicKey


class TrustError(ValueError):
    """Raised when authority-bearing material is not rooted in trusted keys."""


def _without_signature(value: Mapping[str, Any]) -> dict[str, Any]:
    subject = copy.deepcopy(dict(value))
    subject.pop("signature", None)
    return subject


def policy_signing_subject(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return _without_signature(envelope)


def evidence_signing_subject(evidence: Mapping[str, Any]) -> dict[str, Any]:
    return _without_signature(evidence)


def witness_signing_subject(statement: Mapping[str, Any]) -> dict[str, Any]:
    return _without_signature(statement)


def sign_policy(policy: dict[str, Any], signer: KeyPair) -> dict[str, Any]:
    unsigned = {
        "schema_version": "claimsieve.signed_policy.v1",
        "policy": copy.deepcopy(policy),
        "signer_key_id": signer.key_id,
    }
    return {**unsigned, "signature": signer.sign("signed-policy-v1", unsigned)}


def sign_evidence(item: dict[str, Any], signer: KeyPair) -> dict[str, Any]:
    unsigned = copy.deepcopy(item)
    unsigned["issuer_key_id"] = signer.key_id
    unsigned.pop("signature", None)
    return {**unsigned, "signature": signer.sign("evidence-v1", unsigned)}


def sign_witness(manifest_digest: str, release_id: str, signer: KeyPair) -> dict[str, Any]:
    unsigned = {
        "schema_version": "claimsieve.witness_statement.v1",
        "manifest_digest": manifest_digest,
        "release_id": release_id,
        "witness_key_id": signer.key_id,
    }
    return {**unsigned, "signature": signer.sign("witness-v1", unsigned)}


def public_keys_from_trust_root(trust_root: Mapping[str, Any]) -> dict[str, PublicKey]:
    if trust_root.get("schema_version") != "claimsieve.trust_root.v1":
        raise TrustError("unsupported trust root schema")
    encoded = trust_root.get("keys")
    if not isinstance(encoded, dict) or not encoded:
        raise TrustError("trust root has no keys")
    result: dict[str, PublicKey] = {}
    for key_id, value in encoded.items():
        if not isinstance(key_id, str) or not isinstance(value, str):
            raise TrustError("trust root key registry is malformed")
        key = PublicKey.decode(key_id, value)
        if key.key_id != key_id:
            raise TrustError("trust root key identifier mismatch")
        result[key_id] = key
    if len({key.raw for key in result.values()}) != len(result):
        raise TrustError("trust root reuses key material across key identifiers")
    return result


def role_key_ids(trust_root: Mapping[str, Any], role: str) -> list[str]:
    roles = trust_root.get("roles")
    if not isinstance(roles, dict):
        raise TrustError("trust root role registry is missing")
    values = roles.get(role)
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise TrustError(f"trust root role {role} is malformed")
    return values


def verify_signed_policy(
    envelope: Mapping[str, Any],
    trusted_policy_keys: Mapping[str, PublicKey],
) -> dict[str, Any]:
    if envelope.get("schema_version") != "claimsieve.signed_policy.v1":
        raise TrustError("unsupported signed policy schema")
    signer_key_id = envelope.get("signer_key_id")
    policy = envelope.get("policy")
    if not isinstance(signer_key_id, str) or not isinstance(policy, dict):
        raise TrustError("signed policy envelope is malformed")
    key = trusted_policy_keys.get(signer_key_id)
    if key is None:
        raise TrustError("policy signer is not trusted")
    if not key.verify(
        "signed-policy-v1",
        policy_signing_subject(envelope),
        str(envelope.get("signature", "")),
    ):
        raise TrustError("signed policy signature invalid")
    return copy.deepcopy(policy)


def verify_signed_evidence(
    items: list[dict[str, Any]],
    trusted_evidence_keys: Mapping[str, PublicKey],
    policy: Mapping[str, Any],
) -> None:
    expected_key_ids = policy.get("trusted_evidence_key_ids")
    if not isinstance(expected_key_ids, dict):
        raise TrustError("policy trusted evidence key registry is missing")
    for item in items:
        if not isinstance(item, dict) or item.get("schema_version") != "claimsieve.evidence.v1":
            raise TrustError("unsupported evidence schema")
        evidence_type = item.get("type")
        issuer_key_id = item.get("issuer_key_id")
        if not isinstance(evidence_type, str) or not isinstance(issuer_key_id, str):
            raise TrustError("signed evidence identity is malformed")
        allowed = expected_key_ids.get(evidence_type)
        if not isinstance(allowed, list) or issuer_key_id not in allowed:
            raise TrustError(f"evidence signer is not trusted for {evidence_type}")
        key = trusted_evidence_keys.get(issuer_key_id)
        if key is None:
            raise TrustError(f"evidence key is unavailable for {evidence_type}")
        if not key.verify(
            "evidence-v1",
            evidence_signing_subject(item),
            str(item.get("signature", "")),
        ):
            raise TrustError(f"evidence signature invalid for {evidence_type}")


def trusted_key_subset(
    trust_root: Mapping[str, Any], role: str
) -> dict[str, PublicKey]:
    keys = public_keys_from_trust_root(trust_root)
    ids = role_key_ids(trust_root, role)
    missing = [key_id for key_id in ids if key_id not in keys]
    if missing:
        raise TrustError(f"trust root role {role} references missing keys")
    return {key_id: keys[key_id] for key_id in ids}
