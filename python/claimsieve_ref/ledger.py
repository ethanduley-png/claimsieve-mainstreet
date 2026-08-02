from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Mapping

from .canonical import digest
from .crypto import KeyPair, PublicKey

GENESIS_HASH = "sha256:" + "0" * 64


@dataclass
class Ledger:
    ledger_id: str
    writer: KeyPair
    records: list[dict[str, Any]] = field(default_factory=list)

    def append(self, trace_id: str, record_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        sequence = len(self.records)
        unsigned = {
            "schema_version": "claimsieve.ledger_record.v1",
            "ledger_id": self.ledger_id,
            "sequence": sequence,
            "trace_id": trace_id,
            "record_type": record_type,
            "previous_hash": self.records[-1]["record_hash"] if self.records else GENESIS_HASH,
            "payload": copy.deepcopy(payload),
            "payload_hash": digest(payload),
            "writer_key_id": self.writer.key_id,
        }
        signature = self.writer.sign("ledger-record-v1", unsigned)
        complete = {**unsigned, "signature": signature}
        complete["record_hash"] = digest(complete)
        self.records.append(complete)
        return copy.deepcopy(complete)

    @staticmethod
    def verify(records: list[dict[str, Any]], keys: Mapping[str, PublicKey], expected_ledger_id: str) -> list[str]:
        errors: list[str] = []
        previous = GENESIS_HASH
        for index, record in enumerate(records):
            if record.get("schema_version") != "claimsieve.ledger_record.v1":
                errors.append(f"record {index}: unsupported schema")
                continue
            if record.get("ledger_id") != expected_ledger_id:
                errors.append(f"record {index}: ledger id mismatch")
            if record.get("sequence") != index:
                errors.append(f"record {index}: sequence mismatch")
            if record.get("previous_hash") != previous:
                errors.append(f"record {index}: previous hash mismatch")
            if record.get("payload_hash") != digest(record.get("payload")):
                errors.append(f"record {index}: payload hash mismatch")
            unsigned = {k: v for k, v in record.items() if k not in {"signature", "record_hash"}}
            key_id = record.get("writer_key_id")
            key = keys.get(key_id)
            if key is None or not key.verify("ledger-record-v1", unsigned, record.get("signature", "")):
                errors.append(f"record {index}: signature invalid")
            complete_without_hash = {k: v for k, v in record.items() if k != "record_hash"}
            calculated = digest(complete_without_hash)
            if record.get("record_hash") != calculated:
                errors.append(f"record {index}: record hash mismatch")
            previous = record.get("record_hash", "")
        return errors
