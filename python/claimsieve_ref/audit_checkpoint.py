"""Externally pinned, independently signed SQLite journal checkpoints.

An export and its local hash chain are not proof against administrator rollback.
The verifier MUST receive a checkpoint digest and auditor public key through an
independent channel; a checkpoint stored alongside the database is insufficient.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence

from .canonical import digest
from .crypto import KeyPair, PublicKey

GENESIS = "GENESIS"
VERSION = "claimsieve.audit_checkpoint.v1"
DOMAIN = "audit-checkpoint-v1"
FIELDS = frozenset({
    "schema_version", "event_count", "head_hash",
    "previous_checkpoint_digest", "auditor_key_id", "signature",
})


class AuditCheckpointError(ValueError):
    """Fail closed on broken chain, bad signature, or missing external pin."""


def journal_head(events: Sequence[Mapping[str, Any]]) -> tuple[int, str]:
    """Verify local journal sequence AND every hash before checkpointing."""
    previous = GENESIS
    for sequence, event in enumerate(events, start=1):
        if not isinstance(event, Mapping) or set(event) != {
            "event_sequence", "event_type", "object_id", "payload",
            "previous_hash", "event_hash",
        }:
            raise AuditCheckpointError("journal event has invalid fields")
        if type(event["event_sequence"]) is not int or event["event_sequence"] != sequence:
            raise AuditCheckpointError("journal event sequence gap or duplicate")
        if event["previous_hash"] != previous:
            raise AuditCheckpointError("journal predecessor mismatch")
        try:
            subject = {k: v for k, v in event.items() if k != "event_hash"}
            if digest(subject) != event["event_hash"]:
                raise AuditCheckpointError("journal event hash mismatch")
        except (ValueError, TypeError) as exc:
            raise AuditCheckpointError("journal event invalid") from exc
        previous = event["event_hash"]
    return len(events), previous


def issue_checkpoint(
    events: Sequence[Mapping[str, Any]],
    auditor: KeyPair,
    previous: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Sign a checked snapshot with a dedicated OFF-HOST auditor identity.

    The caller is responsible for protecting the auditor private key and
    publishing the resulting checkpoint digest to an independent append-only
    location. This function performs no network or key management.
    """
    count, head = journal_head(events)
    prior_digest = None
    if previous is not None:
        if previous.get("schema_version") != VERSION:
            raise AuditCheckpointError("unsupported previous checkpoint")
        old_count = previous.get("event_count")
        if type(old_count) is not int or old_count >= count:
            raise AuditCheckpointError("checkpoint must advance")
        if old_count > 0 and events[old_count - 1]["event_hash"] != previous.get("head_hash"):
            raise AuditCheckpointError("checkpoint history diverged")
        if old_count == 0 and previous.get("head_hash") != GENESIS:
            raise AuditCheckpointError("invalid prior genesis")
        prior_digest = digest(dict(previous))
    unsigned = {
        "schema_version": VERSION,
        "event_count": count,
        "head_hash": head,
        "previous_checkpoint_digest": prior_digest,
        "auditor_key_id": auditor.key_id,
    }
    return {**unsigned, "signature": auditor.sign(DOMAIN, unsigned)}


def verify_checkpoint(
    events: Sequence[Mapping[str, Any]],
    checkpoint: Mapping[str, Any],
    auditor_public: PublicKey,
    *,
    externally_pinned_digest: str,
    previous: Mapping[str, Any] | None = None,
) -> bool:
    """Require out-of-band digest and key; detect forgery, truncation and rollback.

    Raises AuditCheckpointError instead of returning an ambiguous success.
    """
    if not externally_pinned_digest or not isinstance(externally_pinned_digest, str):
        raise AuditCheckpointError("independent checkpoint pin required")
    if not isinstance(checkpoint, Mapping) or set(checkpoint) != FIELDS:
        raise AuditCheckpointError("invalid checkpoint fields")
    if checkpoint["schema_version"] != VERSION or checkpoint["auditor_key_id"] != auditor_public.key_id:
        raise AuditCheckpointError("checkpoint schema or auditor identity mismatch")
    if digest(dict(checkpoint)) != externally_pinned_digest:
        raise AuditCheckpointError("checkpoint does not match external pin")
    count, head = journal_head(events)
    if checkpoint["event_count"] != count or checkpoint["head_hash"] != head:
        raise AuditCheckpointError("journal differs from pinned checkpoint")
    if previous is None:
        if checkpoint["previous_checkpoint_digest"] is not None:
            raise AuditCheckpointError("missing independently verified predecessor")
    elif checkpoint["previous_checkpoint_digest"] != digest(dict(previous)):
        raise AuditCheckpointError("previous checkpoint mismatch")
    unsigned = {k: v for k, v in checkpoint.items() if k != "signature"}
    if not auditor_public.verify(DOMAIN, unsigned, str(checkpoint["signature"])):
        raise AuditCheckpointError("auditor signature invalid")
    return True
