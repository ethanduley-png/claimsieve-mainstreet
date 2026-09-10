from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Mapping

from .canonical import digest
from .crypto import KeyPair, PublicKey
from .ledger import GENESIS_HASH


@dataclass
class UnifiedAuditLog:
    """Experimental single-chain audit log with role-constrained writers.

    This is intentionally not execution authority. It is an ablation target for
    I-040 (four separate ledgers): records from proposal, evidence, decision,
    and execution writers share one hash chain while retaining distinct keys,
    explicit writer roles, payload commitments, and per-record signatures.
    """

    log_id: str = "claimsieve-unified-audit"
    records: list[dict[str, Any]] = field(default_factory=list)

    def append(
        self,
        *,
        trace_id: str,
        record_type: str,
        writer_role: str,
        writer: KeyPair,
        payload: dict[str, Any] | None = None,
        payload_digest: str | None = None,
    ) -> dict[str, Any]:
        if (payload is None) == (payload_digest is None):
            raise ValueError("exactly one of payload or payload_digest is required")

        committed_digest = digest(payload) if payload is not None else payload_digest
        if not isinstance(committed_digest, str) or not committed_digest.startswith("sha256:"):
            raise ValueError("payload_digest must be a sha256 commitment")

        sequence = len(self.records)
        unsigned: dict[str, Any] = {
            "schema_version": "claimsieve.unified_audit_record.v1",
            "log_id": self.log_id,
            "sequence": sequence,
            "trace_id": trace_id,
            "record_type": record_type,
            "writer_role": writer_role,
            "writer_key_id": writer.key_id,
            "previous_hash": self.records[-1]["record_hash"] if self.records else GENESIS_HASH,
            "payload_digest": committed_digest,
        }
        if payload is not None:
            unsigned["payload"] = copy.deepcopy(payload)

        signature = writer.sign("unified-audit-record-v1", unsigned)
        complete = {**unsigned, "signature": signature}
        complete["record_hash"] = digest(complete)
        self.records.append(complete)
        return copy.deepcopy(complete)

    @staticmethod
    def verify(
        records: list[dict[str, Any]],
        *,
        keys: Mapping[str, PublicKey],
        role_keys: Mapping[str, set[str]],
        record_roles: Mapping[str, str],
        expected_log_id: str = "claimsieve-unified-audit",
    ) -> list[str]:
        errors: list[str] = []
        previous = GENESIS_HASH

        for index, record in enumerate(records):
            if record.get("schema_version") != "claimsieve.unified_audit_record.v1":
                errors.append(f"record {index}: unsupported schema")
                continue
            if record.get("log_id") != expected_log_id:
                errors.append(f"record {index}: log id mismatch")
            if record.get("sequence") != index:
                errors.append(f"record {index}: sequence mismatch")
            if record.get("previous_hash") != previous:
                errors.append(f"record {index}: previous hash mismatch")

            record_type = record.get("record_type")
            expected_role = record_roles.get(record_type)
            actual_role = record.get("writer_role")
            if expected_role is None:
                errors.append(f"record {index}: unknown record type")
            elif actual_role != expected_role:
                errors.append(f"record {index}: writer role mismatch")

            key_id = record.get("writer_key_id")
            allowed = role_keys.get(str(actual_role), set())
            if key_id not in allowed:
                errors.append(f"record {index}: writer key not allowed for role")

            payload = record.get("payload")
            if payload is not None:
                try:
                    if record.get("payload_digest") != digest(payload):
                        errors.append(f"record {index}: payload digest mismatch")
                except Exception:
                    errors.append(f"record {index}: payload cannot be canonicalized")
            elif not isinstance(record.get("payload_digest"), str):
                errors.append(f"record {index}: payload commitment missing")

            unsigned = {k: v for k, v in record.items() if k not in {"signature", "record_hash"}}
            key = keys.get(key_id)
            if key is None or not key.verify(
                "unified-audit-record-v1", unsigned, str(record.get("signature", ""))
            ):
                errors.append(f"record {index}: signature invalid")

            complete_without_hash = {k: v for k, v in record.items() if k != "record_hash"}
            try:
                calculated = digest(complete_without_hash)
            except Exception:
                calculated = None
            if record.get("record_hash") != calculated:
                errors.append(f"record {index}: record hash mismatch")

            previous = str(record.get("record_hash", ""))

        return errors


def default_record_roles() -> dict[str, str]:
    return {
        "PROPOSAL_SUBMITTED": "proposal",
        "EVIDENCE_RECORDED": "evidence",
        "SIGNED_POLICY_RECORDED": "decision",
        "DECISION_RECORDED": "decision",
        "PERMIT_ISSUED": "decision",
        "PERMIT_RESERVED": "execution",
        "EXECUTOR_RECEIPT": "execution",
        "OBSERVER_RECEIPT": "execution",
        "CONTAINMENT_RECEIPT": "execution",
    }
