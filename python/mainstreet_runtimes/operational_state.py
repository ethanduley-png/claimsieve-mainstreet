from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from claimsieve_ref.canonical import canonical_bytes, digest, loads_strict


class OperationalStateError(ValueError):
    """Fail-closed error for the untrusted bounded working-state boundary."""


class StaleOperationalStateError(OperationalStateError):
    """Raised when a patch was prepared from a different state revision."""


class ProtectedOperationalStateError(OperationalStateError):
    """Raised when working state attempts to occupy an authority namespace."""


class OperationalStateBoundsError(OperationalStateError):
    """Raised when working state exceeds a configured constant budget."""


# Operational state is intentionally not an authority store. These root names
# are reserved so a worker cannot accidentally create objects that look like
# ClaimSieve authority, durable-state, evidence-ledger, or execution records.
# Summaries such as `evidence_summary` remain possible, but they stay untrusted.
PROTECTED_ROOT_KEYS = frozenset(
    {
        "approval",
        "approvals",
        "authorization",
        "authorizations",
        "campaign_state",
        "claimsieve_authority",
        "decision_ledger",
        "durable_state",
        "evidence",
        "evidence_ledger",
        "execution",
        "execution_ledger",
        "execution_receipt",
        "ledger",
        "ledgers",
        "permit",
        "permits",
        "proposal_ledger",
        "receipt",
        "receipts",
        "revocation",
        "revocations",
        "trust_root",
    }
)


@dataclass(frozen=True)
class OperationalStateBounds:
    """Constant limits that make bounded-state claims mechanically testable."""

    max_encoded_bytes: int = 32_768
    max_top_level_keys: int = 64
    max_patch_bytes: int = 8_192
    max_deletions_per_patch: int = 64

    def __post_init__(self) -> None:
        for name, value in (
            ("max_encoded_bytes", self.max_encoded_bytes),
            ("max_top_level_keys", self.max_top_level_keys),
            ("max_patch_bytes", self.max_patch_bytes),
            ("max_deletions_per_patch", self.max_deletions_per_patch),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise OperationalStateBoundsError(f"{name} must be a positive integer")


DEFAULT_OPERATIONAL_STATE_BOUNDS = OperationalStateBounds()


def _canonical_text(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")


def _canonical_object(text: str, *, field: str) -> dict[str, Any]:
    try:
        value = loads_strict(text)
    except (TypeError, ValueError) as exc:
        raise OperationalStateError(f"{field} is not valid ClaimSieve canonical JSON") from exc
    if not isinstance(value, dict):
        raise OperationalStateError(f"{field} must encode a JSON object")
    if _canonical_text(value) != text:
        raise OperationalStateError(f"{field} must use canonical JSON encoding")
    return value


def _validate_root_keys(payload: Mapping[str, Any]) -> None:
    protected = sorted(PROTECTED_ROOT_KEYS.intersection(payload))
    if protected:
        raise ProtectedOperationalStateError(
            "operational state may not occupy ClaimSieve authority roots: "
            + ",".join(protected)
        )
    internal = sorted(key for key in payload if key.startswith("_claimsieve"))
    if internal:
        raise ProtectedOperationalStateError(
            "operational state may not create reserved _claimsieve roots: "
            + ",".join(internal)
        )


def _validate_payload_bounds(
    payload: Mapping[str, Any],
    encoded: bytes,
    bounds: OperationalStateBounds,
) -> None:
    if len(payload) > bounds.max_top_level_keys:
        raise OperationalStateBoundsError(
            f"operational state has {len(payload)} top-level keys; "
            f"limit is {bounds.max_top_level_keys}"
        )
    if len(encoded) > bounds.max_encoded_bytes:
        raise OperationalStateBoundsError(
            f"operational state encodes to {len(encoded)} bytes; "
            f"limit is {bounds.max_encoded_bytes}"
        )


def _normalize_deletions(
    deletions: Sequence[str],
    *,
    bounds: OperationalStateBounds,
) -> tuple[str, ...]:
    if isinstance(deletions, (str, bytes)) or not isinstance(deletions, Sequence):
        raise OperationalStateError("patch deletions must be a sequence of root names")
    deletion_items = tuple(deletions)
    if any(not isinstance(key, str) or not key for key in deletion_items):
        raise OperationalStateError("patch deletion keys must be non-empty strings")
    if len(set(deletion_items)) != len(deletion_items):
        raise OperationalStateError("patch deletions must be unique")
    if len(deletion_items) > bounds.max_deletions_per_patch:
        raise OperationalStateBoundsError(
            f"operational patch deletes {len(deletion_items)} roots; "
            f"limit is {bounds.max_deletions_per_patch}"
        )
    deletion_tuple = tuple(sorted(deletion_items))
    _validate_root_keys({key: None for key in deletion_tuple})
    return deletion_tuple


@dataclass(frozen=True)
class OperationalState:
    """Versioned, canonical, bounded working state for an untrusted agent.

    This object is deliberately separate from ClaimSieve durable campaign state.
    Its digest detects stale/concurrent writes; it is not an authorization token.
    """

    version: int
    payload_json: str
    state_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 0:
            raise OperationalStateError("operational state version must be a non-negative integer")
        payload = _canonical_object(self.payload_json, field="payload_json")
        _validate_root_keys(payload)
        expected = digest(
            {
                "schema_version": "claimsieve.operational_state.v1",
                "version": self.version,
                "payload": payload,
            }
        )
        if self.state_digest != expected:
            raise OperationalStateError("operational state digest mismatch")

    @classmethod
    def from_payload(
        cls,
        payload: Mapping[str, Any],
        *,
        version: int = 0,
        bounds: OperationalStateBounds = DEFAULT_OPERATIONAL_STATE_BOUNDS,
    ) -> "OperationalState":
        if not isinstance(payload, Mapping):
            raise OperationalStateError("operational state payload must be a mapping")
        materialized = dict(payload)
        _validate_root_keys(materialized)
        encoded = canonical_bytes(materialized)
        _validate_payload_bounds(materialized, encoded, bounds)
        state_digest = digest(
            {
                "schema_version": "claimsieve.operational_state.v1",
                "version": version,
                "payload": materialized,
            }
        )
        return cls(
            version=version,
            payload_json=encoded.decode("utf-8"),
            state_digest=state_digest,
        )

    @property
    def payload(self) -> dict[str, Any]:
        # Strict parsing returns a fresh object, so callers cannot mutate the
        # state in place and silently invalidate its digest.
        return _canonical_object(self.payload_json, field="payload_json")


@dataclass(frozen=True)
class OperationalStatePatch:
    """Compare-and-swap patch proposed by an untrusted worker."""

    base_version: int
    base_state_digest: str
    actor: str
    changes_json: str
    deletions: tuple[str, ...]
    patch_digest: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.base_version, int)
            or isinstance(self.base_version, bool)
            or self.base_version < 0
        ):
            raise OperationalStateError("patch base_version must be a non-negative integer")
        if not isinstance(self.base_state_digest, str) or not self.base_state_digest:
            raise OperationalStateError("patch requires a base state digest")
        if not isinstance(self.actor, str) or not self.actor:
            raise OperationalStateError("patch actor must be a non-empty string")
        changes = _canonical_object(self.changes_json, field="changes_json")
        _validate_root_keys(changes)
        if any(not isinstance(key, str) or not key for key in self.deletions):
            raise OperationalStateError("patch deletion keys must be non-empty strings")
        if len(set(self.deletions)) != len(self.deletions):
            raise OperationalStateError("patch deletions must be unique")
        if tuple(sorted(self.deletions)) != self.deletions:
            raise OperationalStateError("patch deletions must be sorted")
        _validate_root_keys({key: None for key in self.deletions})
        overlap = set(changes).intersection(self.deletions)
        if overlap:
            raise OperationalStateError(
                "patch cannot both change and delete the same root: " + ",".join(sorted(overlap))
            )
        expected = digest(
            {
                "schema_version": "claimsieve.operational_state_patch.v1",
                "base_version": self.base_version,
                "base_state_digest": self.base_state_digest,
                "actor": self.actor,
                "changes": changes,
                "deletions": list(self.deletions),
            }
        )
        if self.patch_digest != expected:
            raise OperationalStateError("operational state patch digest mismatch")

    @classmethod
    def from_changes(
        cls,
        state: OperationalState,
        *,
        actor: str,
        changes: Mapping[str, Any] | None = None,
        deletions: Sequence[str] = (),
        bounds: OperationalStateBounds = DEFAULT_OPERATIONAL_STATE_BOUNDS,
    ) -> "OperationalStatePatch":
        if changes is not None and not isinstance(changes, Mapping):
            raise OperationalStateError("patch changes must be a mapping")
        materialized = dict(changes or {})
        _validate_root_keys(materialized)
        encoded_changes = canonical_bytes(materialized)
        if len(encoded_changes) > bounds.max_patch_bytes:
            raise OperationalStateBoundsError(
                f"operational patch encodes to {len(encoded_changes)} bytes; "
                f"limit is {bounds.max_patch_bytes}"
            )

        deletion_tuple = _normalize_deletions(deletions, bounds=bounds)
        overlap = set(materialized).intersection(deletion_tuple)
        if overlap:
            raise OperationalStateError(
                "patch cannot both change and delete the same root: " + ",".join(sorted(overlap))
            )

        patch_body = {
            "schema_version": "claimsieve.operational_state_patch.v1",
            "base_version": state.version,
            "base_state_digest": state.state_digest,
            "actor": actor,
            "changes": materialized,
            "deletions": list(deletion_tuple),
        }
        return cls(
            base_version=state.version,
            base_state_digest=state.state_digest,
            actor=actor,
            changes_json=encoded_changes.decode("utf-8"),
            deletions=deletion_tuple,
            patch_digest=digest(patch_body),
        )

    @property
    def changes(self) -> dict[str, Any]:
        return _canonical_object(self.changes_json, field="changes_json")


@dataclass(frozen=True)
class OperationalStateTransition:
    """Non-authoritative transition receipt suitable for later ledger binding."""

    actor: str
    before_version: int
    before_digest: str
    patch_digest: str
    after_version: int
    after_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "claimsieve.operational_state_transition.v1",
            "actor": self.actor,
            "before_version": self.before_version,
            "before_digest": self.before_digest,
            "patch_digest": self.patch_digest,
            "after_version": self.after_version,
            "after_digest": self.after_digest,
        }


def apply_operational_state_patch(
    state: OperationalState,
    patch: OperationalStatePatch,
    *,
    bounds: OperationalStateBounds = DEFAULT_OPERATIONAL_STATE_BOUNDS,
) -> tuple[OperationalState, OperationalStateTransition]:
    """Apply a top-level CAS patch and enforce the post-merge state budget.

    The function never writes ClaimSieve authority or evidence stores. The actor
    label is provenance metadata only and grants no permission.
    """

    if patch.base_version != state.version:
        raise StaleOperationalStateError(
            f"stale operational state version: patch={patch.base_version} current={state.version}"
        )
    if patch.base_state_digest != state.state_digest:
        raise StaleOperationalStateError("stale operational state digest")

    candidate = state.payload
    changes = patch.changes
    _validate_root_keys(changes)
    _validate_root_keys({key: None for key in patch.deletions})

    for key in patch.deletions:
        candidate.pop(key, None)
    for key, value in changes.items():
        candidate[key] = value

    _validate_root_keys(candidate)
    encoded = canonical_bytes(candidate)
    _validate_payload_bounds(candidate, encoded, bounds)

    successor = OperationalState.from_payload(
        candidate,
        version=state.version + 1,
        bounds=bounds,
    )
    transition = OperationalStateTransition(
        actor=patch.actor,
        before_version=state.version,
        before_digest=state.state_digest,
        patch_digest=patch.patch_digest,
        after_version=successor.version,
        after_digest=successor.state_digest,
    )
    return successor, transition
