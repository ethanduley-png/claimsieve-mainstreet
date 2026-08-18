from __future__ import annotations

import copy
import json
import os
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Protocol

from .canonical import canonical_bytes, digest, loads_strict
from .crypto import KeyPair, PublicKey
from .kernel import CampaignState
from .model import (
    action_digest,
    approval_digest,
    destination_digest,
    evidence_root,
    parameter_digest,
    proposal_digest,
)
from .runtime import PermitError


class DurableStateError(PermitError):
    """Fail-closed error raised by the durable state boundary."""


class InjectedCrash(RuntimeError):
    """Deterministic crash injection used only by the test harness."""


@dataclass(frozen=True)
class CampaignSnapshot:
    state: CampaignState
    state_digest: str
    revision: int
    fencing_token: int


@dataclass(frozen=True)
class DispatchTicket:
    reservation_id: str
    permit_id: str
    campaign_id: str
    action_digest: str
    request_digest: str
    resource_key: str
    idempotency_key: str
    fencing_token: int
    containment_epoch: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "claimsieve.dispatch_ticket.v1",
            "reservation_id": self.reservation_id,
            "permit_id": self.permit_id,
            "campaign_id": self.campaign_id,
            "action_digest": self.action_digest,
            "request_digest": self.request_digest,
            "resource_key": self.resource_key,
            "idempotency_key": self.idempotency_key,
            "fencing_token": self.fencing_token,
            "containment_epoch": self.containment_epoch,
        }


def _state_from_dict(raw: dict[str, Any]) -> CampaignState:
    return CampaignState(
        campaign_id=str(raw["campaign_id"]),
        status=str(raw.get("status", "ACTIVE")),
        total_actions=int(raw.get("total_actions", 0)),
        denials=int(raw.get("denials", 0)),
        quarantines=int(raw.get("quarantines", 0)),
        sessions=set(raw.get("sessions", [])),
        destinations=set(raw.get("destinations", [])),
        trust_domains=set(raw.get("trust_domains", [])),
        boundary_crossings=int(raw.get("boundary_crossings", 0)),
        encoded_fragments=int(raw.get("encoded_fragments", 0)),
        credential_events=int(raw.get("credential_events", 0)),
        last_sequence=int(raw.get("last_sequence", 0)),
        suspension_reason=raw.get("suspension_reason"),
    )


def _json(value: Any) -> str:
    return canonical_bytes(value).decode("utf-8")


def _parse_json(value: str) -> Any:
    return loads_strict(value)


class DurableStateService:
    """SQLite-backed single-writer reference state machine.

    Guarantees in this implementation:
    * committed writes survive process restart when the filesystem honors fsync;
    * write transactions are serialized by SQLite `BEGIN IMMEDIATE`;
    * campaign predecessor-to-successor transitions are compare-and-swap;
    * permit reservation is unique and crash durable;
    * fencing tokens are monotonically increasing;
    * revocation and freeze are checked at the dispatch commit point;
    * in-flight ambiguity remains durable until independent reconciliation.

    This is a single-database reference boundary. It is not a multi-node
    consensus implementation and must not be described as one.
    """

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        executor_keys: Mapping[str, PublicKey] | None = None,
        observer_keys: Mapping[str, PublicKey] | None = None,
    ) -> None:
        self.path = str(path)
        self.executor_keys = dict(executor_keys or {})
        self.observer_keys = dict(observer_keys or {})
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._local = threading.local()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=30.0,
            isolation_level=None,
            check_same_thread=False,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA wal_autocheckpoint = 100")
        return connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.execute("COMMIT")
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO metadata(key, value) VALUES
                    ('next_fencing_token', 1),
                    ('next_event_sequence', 1);

                CREATE TABLE IF NOT EXISTS containment (
                    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                    frozen INTEGER NOT NULL CHECK(frozen IN (0, 1)),
                    freeze_reason TEXT,
                    epoch INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO containment(singleton, frozen, freeze_reason, epoch)
                    VALUES(1, 0, NULL, 0);

                CREATE TABLE IF NOT EXISTS campaigns (
                    campaign_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    state_digest TEXT NOT NULL,
                    last_sequence INTEGER NOT NULL,
                    revision INTEGER NOT NULL,
                    fencing_token INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    suspension_reason TEXT
                );

                CREATE TABLE IF NOT EXISTS permits (
                    permit_id TEXT PRIMARY KEY,
                    campaign_id TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    permit_digest TEXT NOT NULL,
                    campaign_state_digest TEXT NOT NULL,
                    issued_sequence INTEGER NOT NULL,
                    expires_sequence INTEGER NOT NULL,
                    FOREIGN KEY(campaign_id) REFERENCES campaigns(campaign_id)
                );

                CREATE TABLE IF NOT EXISTS revocations (
                    permit_id TEXT PRIMARY KEY,
                    reason TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    containment_epoch INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reservations (
                    reservation_id TEXT PRIMARY KEY,
                    permit_id TEXT NOT NULL UNIQUE,
                    campaign_id TEXT NOT NULL,
                    action_digest TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    resource_key TEXT NOT NULL,
                    idempotency_key TEXT NOT NULL UNIQUE,
                    reserved_sequence INTEGER NOT NULL,
                    fencing_token INTEGER NOT NULL UNIQUE,
                    containment_epoch INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    executor_id TEXT,
                    provider_status TEXT,
                    provider_receipt_json TEXT,
                    outcome TEXT,
                    observation_digest TEXT,
                    updated_sequence INTEGER NOT NULL,
                    FOREIGN KEY(permit_id) REFERENCES permits(permit_id),
                    FOREIGN KEY(campaign_id) REFERENCES campaigns(campaign_id)
                );

                CREATE TABLE IF NOT EXISTS journal (
                    event_sequence INTEGER PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    previous_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL UNIQUE
                );
                """
            )
        finally:
            connection.close()

    @staticmethod
    def _next_counter(connection: sqlite3.Connection, key: str) -> int:
        row = connection.execute("SELECT value FROM metadata WHERE key = ?", (key,)).fetchone()
        if row is None:
            raise DurableStateError(f"metadata counter missing: {key}")
        value = int(row["value"])
        connection.execute("UPDATE metadata SET value = ? WHERE key = ?", (value + 1, key))
        return value

    def _append_event(
        self,
        connection: sqlite3.Connection,
        event_type: str,
        object_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        event_sequence = self._next_counter(connection, "next_event_sequence")
        previous = connection.execute(
            "SELECT event_hash FROM journal ORDER BY event_sequence DESC LIMIT 1"
        ).fetchone()
        previous_hash = str(previous["event_hash"]) if previous else "GENESIS"
        subject = {
            "event_sequence": event_sequence,
            "event_type": event_type,
            "object_id": object_id,
            "payload": payload,
            "previous_hash": previous_hash,
        }
        event_hash = digest(subject)
        connection.execute(
            "INSERT INTO journal(event_sequence, event_type, object_id, payload_json, previous_hash, event_hash) "
            "VALUES(?, ?, ?, ?, ?, ?)",
            (event_sequence, event_type, object_id, _json(payload), previous_hash, event_hash),
        )
        return {**subject, "event_hash": event_hash}

    def _ensure_campaign(self, connection: sqlite3.Connection, campaign_id: str) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,)
        ).fetchone()
        if row is not None:
            return row
        state = CampaignState(campaign_id)
        raw = state.as_canonical()
        fence = self._next_counter(connection, "next_fencing_token")
        connection.execute(
            "INSERT INTO campaigns(campaign_id, state_json, state_digest, last_sequence, revision, "
            "fencing_token, status, suspension_reason) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (campaign_id, _json(raw), digest(raw), 0, 0, fence, "ACTIVE", None),
        )
        self._append_event(
            connection,
            "CAMPAIGN_INITIALIZED",
            campaign_id,
            {"campaign_id": campaign_id, "state_digest": digest(raw), "fencing_token": fence},
        )
        row = connection.execute(
            "SELECT * FROM campaigns WHERE campaign_id = ?", (campaign_id,)
        ).fetchone()
        if row is None:
            raise DurableStateError("campaign initialization failed")
        return row

    def read_campaign(self, campaign_id: str) -> CampaignSnapshot:
        with self._transaction() as connection:
            row = self._ensure_campaign(connection, campaign_id)
            state = _state_from_dict(_parse_json(str(row["state_json"])))
            return CampaignSnapshot(
                state=state,
                state_digest=str(row["state_digest"]),
                revision=int(row["revision"]),
                fencing_token=int(row["fencing_token"]),
            )

    def commit_campaign_successor(
        self,
        campaign_id: str,
        expected_digest: str,
        expected_last_sequence: int,
        successor: CampaignState,
        permit: dict[str, Any] | None = None,
    ) -> bool:
        with self._transaction() as connection:
            current = self._ensure_campaign(connection, campaign_id)
            if str(current["state_digest"]) != expected_digest:
                return False
            if int(current["last_sequence"]) != expected_last_sequence:
                return False
            if successor.campaign_id != campaign_id:
                return False
            if successor.last_sequence <= expected_last_sequence:
                return False

            successor_copy = successor.clone()
            if hasattr(successor_copy, "_prior_state_digest"):
                delattr(successor_copy, "_prior_state_digest")
            raw = successor_copy.as_canonical()
            successor_digest = digest(raw)
            fence = self._next_counter(connection, "next_fencing_token")
            revision = int(current["revision"]) + 1

            if permit is not None:
                if permit.get("campaign_id") != campaign_id:
                    raise DurableStateError("permit campaign mismatch")
                if permit.get("campaign_state_digest") != successor_digest:
                    raise DurableStateError("permit successor-state binding mismatch")
                connection.execute(
                    "INSERT INTO permits(permit_id, campaign_id, action_digest, permit_digest, "
                    "campaign_state_digest, issued_sequence, expires_sequence) VALUES(?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(permit["permit_id"]),
                        campaign_id,
                        str(permit["action_digest"]),
                        digest(permit),
                        successor_digest,
                        int(permit["valid_from_seq"]),
                        int(permit["expires_at_seq"]),
                    ),
                )

            connection.execute(
                "UPDATE campaigns SET state_json = ?, state_digest = ?, last_sequence = ?, revision = ?, "
                "fencing_token = ?, status = ?, suspension_reason = ? WHERE campaign_id = ?",
                (
                    _json(raw),
                    successor_digest,
                    successor_copy.last_sequence,
                    revision,
                    fence,
                    successor_copy.status,
                    successor_copy.suspension_reason,
                    campaign_id,
                ),
            )
            self._append_event(
                connection,
                "CAMPAIGN_SUCCESSOR_COMMITTED",
                campaign_id,
                {
                    "prior_state_digest": expected_digest,
                    "successor_state_digest": successor_digest,
                    "last_sequence": successor_copy.last_sequence,
                    "revision": revision,
                    "fencing_token": fence,
                    "permit_id": permit.get("permit_id") if permit else None,
                },
            )
            return True

    def register_permit_for_existing_state(self, permit: dict[str, Any]) -> None:
        """Migration helper for permits issued by an older in-memory authority.

        New issuance should use atomic campaign commit plus permit storage.
        """
        with self._transaction() as connection:
            campaign_id = str(permit["campaign_id"])
            current = self._ensure_campaign(connection, campaign_id)
            if str(current["state_digest"]) != str(permit["campaign_state_digest"]):
                raise DurableStateError("permit does not bind current durable campaign state")
            connection.execute(
                "INSERT INTO permits(permit_id, campaign_id, action_digest, permit_digest, "
                "campaign_state_digest, issued_sequence, expires_sequence) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (
                    str(permit["permit_id"]),
                    campaign_id,
                    str(permit["action_digest"]),
                    digest(permit),
                    str(permit["campaign_state_digest"]),
                    int(permit["valid_from_seq"]),
                    int(permit["expires_at_seq"]),
                ),
            )
            self._append_event(
                connection,
                "PERMIT_REGISTERED_MIGRATION",
                str(permit["permit_id"]),
                {"permit_digest": digest(permit), "campaign_id": campaign_id},
            )

    def containment_status(self) -> dict[str, Any]:
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM containment WHERE singleton = 1").fetchone()
            if row is None:
                raise DurableStateError("containment state missing")
            return {
                "frozen": bool(row["frozen"]),
                "freeze_reason": row["freeze_reason"],
                "epoch": int(row["epoch"]),
            }
        finally:
            connection.close()

    def _contain_campaign_in_transaction(
        self,
        connection: sqlite3.Connection,
        campaign_id: str,
        reason: str,
        seq: int,
    ) -> dict[str, Any]:
        """Suspend one campaign exactly once inside the caller's transaction.

        The first containment advances the global containment epoch and campaign
        fencing token. Replaying the same or another containment signal against
        an already-suspended campaign is idempotent: it does not allocate a new
        fence, advance the epoch, or append a duplicate suspension event.
        """

        current = self._ensure_campaign(connection, campaign_id)
        containment = connection.execute(
            "SELECT epoch FROM containment WHERE singleton = 1"
        ).fetchone()
        if containment is None:
            raise DurableStateError("containment state missing")
        current_epoch = int(containment["epoch"])
        if str(current["status"]) == "SUSPENDED":
            return {
                "event_type": "CAMPAIGN_ALREADY_SUSPENDED",
                "object_id": campaign_id,
                "payload": {
                    "reason": current["suspension_reason"],
                    "sequence": seq,
                    "fencing_token": int(current["fencing_token"]),
                    "containment_epoch": current_epoch,
                },
            }

        epoch = current_epoch + 1
        connection.execute(
            "UPDATE containment SET epoch = ? WHERE singleton = 1",
            (epoch,),
        )
        state = _state_from_dict(_parse_json(str(current["state_json"])))
        state.status = "SUSPENDED"
        state.suspension_reason = reason
        raw = state.as_canonical()
        fence = self._next_counter(connection, "next_fencing_token")
        connection.execute(
            "UPDATE campaigns SET state_json = ?, state_digest = ?, status = 'SUSPENDED', "
            "suspension_reason = ?, fencing_token = ? WHERE campaign_id = ?",
            (_json(raw), digest(raw), reason, fence, campaign_id),
        )
        return self._append_event(
            connection,
            "CAMPAIGN_SUSPENDED",
            campaign_id,
            {
                "reason": reason,
                "sequence": seq,
                "fencing_token": fence,
                "containment_epoch": epoch,
            },
        )

    def suspend_campaign(self, campaign_id: str, reason: str, seq: int) -> dict[str, Any]:
        with self._transaction() as connection:
            return self._contain_campaign_in_transaction(
                connection, campaign_id, reason, seq
            )

    def revoke_permit(self, permit_id: str, reason: str, seq: int) -> dict[str, Any]:
        with self._transaction() as connection:
            containment = connection.execute(
                "SELECT epoch FROM containment WHERE singleton = 1"
            ).fetchone()
            if containment is None:
                raise DurableStateError("containment state missing")
            epoch = int(containment["epoch"]) + 1
            connection.execute("UPDATE containment SET epoch = ? WHERE singleton = 1", (epoch,))
            connection.execute(
                "INSERT INTO revocations(permit_id, reason, sequence, containment_epoch) VALUES(?, ?, ?, ?) "
                "ON CONFLICT(permit_id) DO UPDATE SET reason = excluded.reason, sequence = excluded.sequence, "
                "containment_epoch = excluded.containment_epoch",
                (permit_id, reason, seq, epoch),
            )
            reservation = connection.execute(
                "SELECT status FROM reservations WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            in_flight = reservation is not None and str(reservation["status"]) in {
                "DISPATCHING",
                "PROVIDER_ACKNOWLEDGED",
                "OUTCOME_UNKNOWN",
            }
            event = self._append_event(
                connection,
                "PERMIT_REVOKED",
                permit_id,
                {
                    "reason": reason,
                    "sequence": seq,
                    "containment_epoch": epoch,
                    "in_flight_at_revocation": in_flight,
                },
            )
            return event

    def freeze(self, reason: str, seq: int) -> dict[str, Any]:
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT epoch FROM containment WHERE singleton = 1"
            ).fetchone()
            if row is None:
                raise DurableStateError("containment state missing")
            epoch = int(row["epoch"]) + 1
            connection.execute(
                "UPDATE containment SET frozen = 1, freeze_reason = ?, epoch = ? WHERE singleton = 1",
                (reason, epoch),
            )
            return self._append_event(
                connection,
                "EXECUTION_FROZEN",
                "global",
                {"reason": reason, "sequence": seq, "containment_epoch": epoch},
            )

    def unfreeze_for_test(self, seq: int) -> None:
        """Test-only recovery hook; production requires separate recovery authority."""
        with self._transaction() as connection:
            row = connection.execute("SELECT epoch FROM containment WHERE singleton = 1").fetchone()
            if row is None:
                raise DurableStateError("containment state missing")
            epoch = int(row["epoch"]) + 1
            connection.execute(
                "UPDATE containment SET frozen = 0, freeze_reason = NULL, epoch = ? WHERE singleton = 1",
                (epoch,),
            )
            self._append_event(
                connection,
                "EXECUTION_UNFROZEN_TEST_ONLY",
                "global",
                {"sequence": seq, "containment_epoch": epoch},
            )

    @staticmethod
    def _verify_role_artifact(
        artifact: dict[str, Any],
        *,
        domain: str,
        key_field: str,
        trusted_keys: Mapping[str, PublicKey],
        role_name: str,
    ) -> dict[str, Any]:
        if not isinstance(artifact, dict):
            raise DurableStateError(f"{role_name} artifact malformed")
        key_id = artifact.get(key_field)
        if not isinstance(key_id, str) or key_id not in trusted_keys:
            raise DurableStateError(f"trusted {role_name} key not configured")
        signature = artifact.get("signature")
        unsigned = {key: value for key, value in artifact.items() if key != "signature"}
        if not isinstance(signature, str) or not trusted_keys[key_id].verify(
            domain, unsigned, signature
        ):
            raise DurableStateError(f"{role_name} signature invalid")
        return unsigned

    def _verify_executor_command(
        self,
        command: dict[str, Any] | None,
        *,
        expected_command: str,
        reservation_id: str,
        executor_id: str | None,
        seq: int,
    ) -> dict[str, Any]:
        if command is None:
            raise DurableStateError("signed executor command required")
        unsigned = self._verify_role_artifact(
            command,
            domain="executor-command-v1",
            key_field="executor_key_id",
            trusted_keys=self.executor_keys,
            role_name="executor command",
        )
        expected = {
            "schema_version": "claimsieve.executor_command.v1",
            "command": expected_command,
            "reservation_id": reservation_id,
            "sequence": seq,
        }
        for field, value in expected.items():
            if unsigned.get(field) != value:
                raise DurableStateError(f"executor command mismatch: {field}")
        if executor_id is not None and unsigned.get("executor_id") != executor_id:
            raise DurableStateError("executor command mismatch: executor_id")
        if not isinstance(unsigned.get("executor_id"), str) or not unsigned["executor_id"]:
            raise DurableStateError("executor command executor_id missing")
        return unsigned

    def _check_containment(
        self,
        connection: sqlite3.Connection,
        permit_id: str,
        campaign_id: str,
    ) -> int:
        containment = connection.execute(
            "SELECT frozen, epoch FROM containment WHERE singleton = 1"
        ).fetchone()
        if containment is None:
            raise DurableStateError("containment state missing")
        if bool(containment["frozen"]):
            raise DurableStateError("execution globally frozen")
        revoked = connection.execute(
            "SELECT 1 FROM revocations WHERE permit_id = ?", (permit_id,)
        ).fetchone()
        if revoked is not None:
            raise DurableStateError("permit revoked")
        campaign = self._ensure_campaign(connection, campaign_id)
        if str(campaign["status"]) != "ACTIVE":
            raise DurableStateError("campaign suspended")
        return int(containment["epoch"])

    def reserve(
        self,
        permit: dict[str, Any],
        proposal: dict[str, Any],
        seq: int,
    ) -> dict[str, Any] | None:
        permit_id = str(permit["permit_id"])
        campaign_id = str(permit["campaign_id"])
        action_digest_value = action_digest(proposal)
        request_digest = digest(
            {
                "permit_id": permit_id,
                "action_digest": action_digest_value,
                "destination_digest": destination_digest(proposal),
                "parameter_digest": parameter_digest(proposal),
            }
        )
        resource_key = digest(
            {
                "tenant_id": proposal["tenant_id"],
                "destination": proposal["action"]["destination"],
                "subject": proposal["action"]["destination"].get("resource"),
            }
        )
        with self._transaction() as connection:
            stored_permit = connection.execute(
                "SELECT * FROM permits WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            if stored_permit is None:
                raise DurableStateError("permit is not committed in durable authority state")
            if str(stored_permit["permit_digest"]) != digest(permit):
                raise DurableStateError("durable permit digest mismatch")
            if str(stored_permit["action_digest"]) != action_digest_value:
                raise DurableStateError("durable permit action binding mismatch")
            if not (
                int(stored_permit["issued_sequence"])
                <= seq
                <= int(stored_permit["expires_sequence"])
            ):
                raise DurableStateError("permit outside durable validity sequence")
            current = self._ensure_campaign(connection, campaign_id)
            epoch = self._check_containment(connection, permit_id, campaign_id)
            if str(current["state_digest"]) != str(permit["campaign_state_digest"]):
                raise DurableStateError("permit campaign state is stale")
            existing = connection.execute(
                "SELECT * FROM reservations WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            if existing is not None:
                return None
            fence = self._next_counter(connection, "next_fencing_token")
            reservation_id = "reservation:" + permit_id
            connection.execute(
                "INSERT INTO reservations(reservation_id, permit_id, campaign_id, action_digest, request_digest, "
                "resource_key, idempotency_key, reserved_sequence, fencing_token, containment_epoch, status, "
                "updated_sequence) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'RESERVED', ?)",
                (
                    reservation_id,
                    permit_id,
                    campaign_id,
                    action_digest_value,
                    request_digest,
                    resource_key,
                    permit_id,
                    seq,
                    fence,
                    epoch,
                    seq,
                ),
            )
            self._append_event(
                connection,
                "EXECUTION_RESERVED",
                reservation_id,
                {
                    "permit_id": permit_id,
                    "campaign_id": campaign_id,
                    "action_digest": action_digest_value,
                    "request_digest": request_digest,
                    "resource_key": resource_key,
                    "fencing_token": fence,
                    "containment_epoch": epoch,
                    "sequence": seq,
                },
            )
            return self._reservation_row(connection, reservation_id)

    def begin_execution(
        self,
        reservation_id: str,
        executor_id: str,
        seq: int,
        executor_command: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._verify_executor_command(
            executor_command,
            expected_command="BEGIN_EXECUTION",
            reservation_id=reservation_id,
            executor_id=executor_id,
            seq=seq,
        )
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM reservations WHERE reservation_id = ?", (reservation_id,)
            ).fetchone()
            if row is None:
                raise DurableStateError("reservation not found")
            if str(row["status"]) != "RESERVED":
                raise DurableStateError("reservation is not claimable")
            self._check_containment(connection, str(row["permit_id"]), str(row["campaign_id"]))
            connection.execute(
                "UPDATE reservations SET status = 'EXECUTING', executor_id = ?, updated_sequence = ? "
                "WHERE reservation_id = ?",
                (executor_id, seq, reservation_id),
            )
            self._append_event(
                connection,
                "EXECUTION_CLAIMED",
                reservation_id,
                {"executor_id": executor_id, "sequence": seq},
            )
            return self._reservation_row(connection, reservation_id)

    def claim_dispatch(
        self,
        reservation_id: str,
        seq: int,
        executor_command: dict[str, Any] | None = None,
    ) -> DispatchTicket:
        """Linearization point for local authorization to dispatch.

        Revocation and freeze dominate before this transaction commits. After it
        commits, the external request may already be in flight; later revocation
        cannot be represented as retroactive prevention and the outcome must be
        independently reconciled.
        """
        command = self._verify_executor_command(
            executor_command,
            expected_command="CLAIM_DISPATCH",
            reservation_id=reservation_id,
            executor_id=None,
            seq=seq,
        )
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT r.*, p.issued_sequence, p.expires_sequence FROM reservations r "
                "JOIN permits p ON p.permit_id = r.permit_id WHERE r.reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            if row is None:
                raise DurableStateError("reservation not found")
            if str(row["status"]) != "EXECUTING":
                raise DurableStateError("reservation is not ready for dispatch")
            if row["executor_id"] != command["executor_id"]:
                raise DurableStateError("dispatch executor does not own reservation")
            if not (int(row["issued_sequence"]) <= seq <= int(row["expires_sequence"])):
                raise DurableStateError("permit expired before dispatch commit")
            epoch = self._check_containment(
                connection, str(row["permit_id"]), str(row["campaign_id"])
            )
            connection.execute(
                "UPDATE reservations SET status = 'DISPATCHING', containment_epoch = ?, "
                "updated_sequence = ? WHERE reservation_id = ?",
                (epoch, seq, reservation_id),
            )
            ticket = DispatchTicket(
                reservation_id=reservation_id,
                permit_id=str(row["permit_id"]),
                campaign_id=str(row["campaign_id"]),
                action_digest=str(row["action_digest"]),
                request_digest=str(row["request_digest"]),
                resource_key=str(row["resource_key"]),
                idempotency_key=str(row["idempotency_key"]),
                fencing_token=int(row["fencing_token"]),
                containment_epoch=epoch,
            )
            self._append_event(
                connection,
                "DISPATCH_COMMIT_POINT",
                reservation_id,
                {**ticket.as_dict(), "sequence": seq},
            )
            return ticket

    def persist_provider_attempt(
        self,
        reservation_id: str,
        provider_result: dict[str, Any],
        executor_receipt: dict[str, Any],
        seq: int,
    ) -> dict[str, Any]:
        unsigned_receipt = self._verify_role_artifact(
            executor_receipt,
            domain="executor-receipt-v2",
            key_field="executor_key_id",
            trusted_keys=self.executor_keys,
            role_name="executor receipt",
        )
        status = str(provider_result.get("status"))
        if unsigned_receipt.get("provider_status") != status:
            raise DurableStateError("executor receipt provider status mismatch")
        if unsigned_receipt.get("provider_id") != provider_result.get("provider_id"):
            raise DurableStateError("executor receipt provider id mismatch")
        if unsigned_receipt.get("attempted_at_seq") != seq:
            raise DurableStateError("executor receipt sequence mismatch")
        if status == "accepted":
            next_status = "PROVIDER_ACKNOWLEDGED"
            outcome = None
        elif status == "rejected":
            next_status = "PROVIDER_REJECTED"
            outcome = None
        elif status == "stale_fence":
            next_status = "BLOCKED_STALE_FENCE"
            outcome = None
        else:
            next_status = "OUTCOME_UNKNOWN"
            outcome = "OUTCOME_UNKNOWN"
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM reservations WHERE reservation_id = ?", (reservation_id,)
            ).fetchone()
            if row is None:
                raise DurableStateError("reservation not found")
            if str(row["status"]) not in {"DISPATCHING", "OUTCOME_UNKNOWN"}:
                raise DurableStateError("provider result cannot be recorded from current state")
            receipt_bindings = {
                "reservation_id": reservation_id,
                "permit_id": row["permit_id"],
                "campaign_id": row["campaign_id"],
                "action_digest": row["action_digest"],
                "request_digest": row["request_digest"],
                "idempotency_key": row["idempotency_key"],
                "fencing_token": row["fencing_token"],
                "containment_epoch": row["containment_epoch"],
            }
            for field, value in receipt_bindings.items():
                if unsigned_receipt.get(field) != value:
                    raise DurableStateError(f"executor receipt binding mismatch: {field}")
            connection.execute(
                "UPDATE reservations SET status = ?, provider_status = ?, provider_receipt_json = ?, "
                "outcome = ?, updated_sequence = ? WHERE reservation_id = ?",
                (
                    next_status,
                    status,
                    _json(executor_receipt),
                    outcome,
                    seq,
                    reservation_id,
                ),
            )
            self._append_event(
                connection,
                "PROVIDER_ATTEMPT_RECORDED",
                reservation_id,
                {
                    "provider_status": status,
                    "reservation_status": next_status,
                    "outcome": outcome,
                    "executor_receipt_digest": digest(executor_receipt),
                    "sequence": seq,
                },
            )
            return self._reservation_row(connection, reservation_id)

    def record_observation(
        self,
        reservation_id: str,
        observation: dict[str, Any],
        seq: int,
        *,
        containment_reason: str | None = None,
    ) -> dict[str, Any]:
        """Record independent reconciliation and required containment atomically.

        Divergent effects always require containment. The trusted independent
        observer may additionally identify internally contradictory provider
        evidence and request `PROVIDER_EVIDENCE_CONFLICT` containment. Merely
        setting `receipt_conflict` is not enough because that flag can also mean
        the untrusted executor disagreed with otherwise coherent provider state.
        """

        unsigned_observation = self._verify_role_artifact(
            observation,
            domain="observer-receipt-v2",
            key_field="observer_key_id",
            trusted_keys=self.observer_keys,
            role_name="observer receipt",
        )
        reconciliation = str(observation.get("reconciliation"))
        allowed = {
            "CONFIRMED_SUCCESS",
            "CONFIRMED_FAILURE",
            "DIVERGENT_EFFECT",
            "OUTCOME_UNKNOWN",
        }
        if reconciliation not in allowed:
            raise DurableStateError("invalid reconciliation state")
        if containment_reason not in {None, "PROVIDER_EVIDENCE_CONFLICT"}:
            raise DurableStateError("invalid observation containment reason")
        if containment_reason == "PROVIDER_EVIDENCE_CONFLICT" and not (
            reconciliation == "OUTCOME_UNKNOWN"
            and unsigned_observation.get("receipt_conflict") is True
        ):
            raise DurableStateError("provider-evidence containment binding mismatch")

        effective_containment_reason = (
            "DIVERGENT_EFFECT"
            if reconciliation == "DIVERGENT_EFFECT"
            else containment_reason
        )
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT * FROM reservations WHERE reservation_id = ?", (reservation_id,)
            ).fetchone()
            if row is None:
                raise DurableStateError("reservation not found")
            observation_bindings = {
                "schema_version": "claimsieve.observer_receipt.v2",
                "reservation_id": reservation_id,
                "permit_id": row["permit_id"],
                "campaign_id": row["campaign_id"],
                "observed_at_seq": seq,
            }
            for field, value in observation_bindings.items():
                if unsigned_observation.get(field) != value:
                    raise DurableStateError(f"observer receipt binding mismatch: {field}")
            current_outcome = row["outcome"]
            if current_outcome in {"CONFIRMED_SUCCESS", "CONFIRMED_FAILURE", "DIVERGENT_EFFECT"}:
                if current_outcome != reconciliation:
                    raise DurableStateError("terminal outcome cannot be rewritten")
                if effective_containment_reason is not None:
                    self._contain_campaign_in_transaction(
                        connection,
                        str(row["campaign_id"]),
                        effective_containment_reason,
                        seq,
                    )
                return self._reservation_row(connection, reservation_id)

            next_status = "RECONCILED" if reconciliation != "OUTCOME_UNKNOWN" else "OUTCOME_UNKNOWN"
            connection.execute(
                "UPDATE reservations SET status = ?, outcome = ?, observation_digest = ?, "
                "updated_sequence = ? WHERE reservation_id = ?",
                (next_status, reconciliation, digest(observation), seq, reservation_id),
            )
            self._append_event(
                connection,
                "OUTCOME_RECONCILED",
                reservation_id,
                {
                    "reconciliation": reconciliation,
                    "observation_digest": digest(observation),
                    "sequence": seq,
                },
            )
            if effective_containment_reason is not None:
                self._contain_campaign_in_transaction(
                    connection,
                    str(row["campaign_id"]),
                    effective_containment_reason,
                    seq,
                )
            return self._reservation_row(connection, reservation_id)

    def _reservation_row(
        self, connection: sqlite3.Connection, reservation_id: str
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM reservations WHERE reservation_id = ?", (reservation_id,)
        ).fetchone()
        if row is None:
            raise DurableStateError("reservation not found")
        result = {key: row[key] for key in row.keys()}
        if result.get("provider_receipt_json"):
            result["provider_receipt"] = _parse_json(str(result.pop("provider_receipt_json")))
        else:
            result.pop("provider_receipt_json", None)
        return result

    def get_reservation(self, reservation_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            return self._reservation_row(connection, reservation_id)
        finally:
            connection.close()

    def recovery_queue(self) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT reservation_id FROM reservations WHERE status IN "
                "('RESERVED', 'EXECUTING', 'DISPATCHING', 'PROVIDER_ACKNOWLEDGED', 'OUTCOME_UNKNOWN') "
                "ORDER BY fencing_token"
            ).fetchall()
            return [self._reservation_row(connection, str(row["reservation_id"])) for row in rows]
        finally:
            connection.close()

    def journal(self) -> list[dict[str, Any]]:
        connection = self._connect()
        try:
            rows = connection.execute("SELECT * FROM journal ORDER BY event_sequence").fetchall()
            return [
                {
                    "event_sequence": int(row["event_sequence"]),
                    "event_type": str(row["event_type"]),
                    "object_id": str(row["object_id"]),
                    "payload": _parse_json(str(row["payload_json"])),
                    "previous_hash": str(row["previous_hash"]),
                    "event_hash": str(row["event_hash"]),
                }
                for row in rows
            ]
        finally:
            connection.close()

    def verify_journal(self) -> bool:
        previous = "GENESIS"
        for event in self.journal():
            if event["previous_hash"] != previous:
                return False
            subject = {key: value for key, value in event.items() if key != "event_hash"}
            if digest(subject) != event["event_hash"]:
                return False
            previous = event["event_hash"]
        return True


@dataclass
class DurableCampaignStateStore:
    service: DurableStateService

    def read(self, campaign_id: str) -> CampaignState:
        return self.service.read_campaign(campaign_id).state.clone()

    def compare_and_swap(
        self,
        campaign_id: str,
        expected_digest: str,
        expected_last_sequence: int,
        successor: CampaignState,
    ) -> bool:
        return self.service.commit_campaign_successor(
            campaign_id,
            expected_digest,
            expected_last_sequence,
            successor,
        )

    def commit_successor_with_permit(
        self,
        campaign_id: str,
        expected_digest: str,
        expected_last_sequence: int,
        successor: CampaignState,
        permit: dict[str, Any],
    ) -> bool:
        return self.service.commit_campaign_successor(
            campaign_id,
            expected_digest,
            expected_last_sequence,
            successor,
            permit,
        )

    def replace_for_recovery(self, state: CampaignState) -> None:
        raise DurableStateError("recovery replacement requires a separate recovery protocol")


class DurableProvider(Protocol):
    """Provider boundary shared by the simulator and restricted live adapters."""

    def invoke(self, action: dict[str, Any], ticket: DispatchTicket) -> dict[str, Any]: ...

    def query(self, idempotency_key: str) -> dict[str, Any] | None: ...


class DurableProviderSimulator:
    """Independent SQLite provider simulator with idempotency and fencing."""

    def __init__(self, path: str | os.PathLike[str], mode: str = "success") -> None:
        self.path = str(path)
        self.mode = mode
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS resource_fences (
                    resource_key TEXT PRIMARY KEY,
                    highest_fence INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS requests (
                    idempotency_key TEXT PRIMARY KEY,
                    request_digest TEXT NOT NULL,
                    resource_key TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    provider_id TEXT,
                    effect_json TEXT,
                    response_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS attempts (
                    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    idempotency_key TEXT NOT NULL,
                    request_digest TEXT NOT NULL,
                    fencing_token INTEGER NOT NULL,
                    result TEXT NOT NULL
                );
                """
            )
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path, timeout=30.0, isolation_level=None, check_same_thread=False
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 30000")
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def invoke(self, action: dict[str, Any], ticket: DispatchTicket) -> dict[str, Any]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT * FROM requests WHERE idempotency_key = ?", (ticket.idempotency_key,)
            ).fetchone()
            if existing is not None:
                if str(existing["request_digest"]) != ticket.request_digest:
                    raise DurableStateError("idempotency key reused with different request")
                response = _parse_json(str(existing["response_json"]))
                connection.execute(
                    "INSERT INTO attempts(idempotency_key, request_digest, fencing_token, result) "
                    "VALUES(?, ?, ?, 'IDEMPOTENT_REPLAY')",
                    (ticket.idempotency_key, ticket.request_digest, ticket.fencing_token),
                )
                connection.execute("COMMIT")
                return {**response, "idempotent_replay": True}

            fence = connection.execute(
                "SELECT highest_fence FROM resource_fences WHERE resource_key = ?",
                (ticket.resource_key,),
            ).fetchone()
            if fence is not None and ticket.fencing_token <= int(fence["highest_fence"]):
                response = {
                    "status": "stale_fence",
                    "provider_id": None,
                    "fencing_token": ticket.fencing_token,
                }
                connection.execute(
                    "INSERT INTO attempts(idempotency_key, request_digest, fencing_token, result) "
                    "VALUES(?, ?, ?, 'STALE_FENCE')",
                    (ticket.idempotency_key, ticket.request_digest, ticket.fencing_token),
                )
                connection.execute("COMMIT")
                return response

            if self.mode == "timeout_before_commit":
                connection.execute(
                    "INSERT INTO attempts(idempotency_key, request_digest, fencing_token, result) "
                    "VALUES(?, ?, ?, 'TIMEOUT_BEFORE_COMMIT')",
                    (ticket.idempotency_key, ticket.request_digest, ticket.fencing_token),
                )
                connection.execute("COMMIT")
                return {"status": "timeout_unknown", "provider_id": None}

            provider_id = "provider:" + ticket.idempotency_key
            effect: dict[str, Any] | None = copy.deepcopy(action)
            if self.mode == "divergent":
                effect = copy.deepcopy(action)
                effect["destination"]["authority"] = "unexpected-target"
            if self.mode == "reject":
                effect = None
                response = {"status": "rejected", "provider_id": None}
            elif self.mode == "conflicting_receipt":
                response = {"status": "rejected", "provider_id": None}
            elif self.mode == "timeout_after_commit":
                response = {"status": "timeout_unknown", "provider_id": None}
            else:
                response = {"status": "accepted", "provider_id": provider_id}

            connection.execute(
                "INSERT INTO resource_fences(resource_key, highest_fence) VALUES(?, ?) "
                "ON CONFLICT(resource_key) DO UPDATE SET highest_fence = excluded.highest_fence "
                "WHERE excluded.highest_fence > resource_fences.highest_fence",
                (ticket.resource_key, ticket.fencing_token),
            )
            connection.execute(
                "INSERT INTO requests(idempotency_key, request_digest, resource_key, fencing_token, status, "
                "provider_id, effect_json, response_json) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    ticket.idempotency_key,
                    ticket.request_digest,
                    ticket.resource_key,
                    ticket.fencing_token,
                    str(response["status"]),
                    provider_id if effect is not None else None,
                    _json(effect) if effect is not None else None,
                    _json(response),
                ),
            )
            connection.execute(
                "INSERT INTO attempts(idempotency_key, request_digest, fencing_token, result) "
                "VALUES(?, ?, ?, ?)",
                (ticket.idempotency_key, ticket.request_digest, ticket.fencing_token, str(response["status"])),
            )
            connection.execute("COMMIT")
            return response
        except BaseException:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            connection.close()

    def query(self, idempotency_key: str) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM requests WHERE idempotency_key = ?", (idempotency_key,)
            ).fetchone()
            if row is None:
                return None
            return {
                "idempotency_key": str(row["idempotency_key"]),
                "request_digest": str(row["request_digest"]),
                "resource_key": str(row["resource_key"]),
                "fencing_token": int(row["fencing_token"]),
                "status": str(row["status"]),
                "provider_id": row["provider_id"],
                "effect": _parse_json(str(row["effect_json"])) if row["effect_json"] else None,
                "response": _parse_json(str(row["response_json"])),
            }
        finally:
            connection.close()

    def highest_fence(self, resource_key: str) -> int | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT highest_fence FROM resource_fences WHERE resource_key = ?", (resource_key,)
            ).fetchone()
            return int(row["highest_fence"]) if row else None
        finally:
            connection.close()


@dataclass
class DurableExecutor:
    state: DurableStateService
    provider: DurableProvider
    authority_keys: Mapping[str, PublicKey]
    executor_key: KeyPair
    executor_id: str = "spiffe://claimsieve.local/executor/reference"

    def _signed_command(
        self, command: str, reservation_id: str, seq: int
    ) -> dict[str, Any]:
        unsigned = {
            "schema_version": "claimsieve.executor_command.v1",
            "command": command,
            "reservation_id": reservation_id,
            "executor_id": self.executor_id,
            "sequence": seq,
            "executor_key_id": self.executor_key.key_id,
        }
        return {
            **unsigned,
            "signature": self.executor_key.sign("executor-command-v1", unsigned),
        }

    def claim_reservation_for_dispatch(
        self, reservation_id: str, seq: int
    ) -> DispatchTicket:
        self.state.begin_execution(
            reservation_id,
            self.executor_id,
            seq,
            self._signed_command("BEGIN_EXECUTION", reservation_id, seq),
        )
        return self.state.claim_dispatch(
            reservation_id,
            seq,
            self._signed_command("CLAIM_DISPATCH", reservation_id, seq),
        )

    def _verify(
        self,
        permit: dict[str, Any],
        proposal: dict[str, Any],
        signed_policy: dict[str, Any],
        evidence: list[dict[str, Any]],
        decision: dict[str, Any],
        seq: int,
    ) -> None:
        policy = signed_policy.get("policy")
        if not isinstance(policy, dict):
            raise DurableStateError("signed policy artifact malformed")
        if permit.get("schema_version") != "claimsieve.permit.v1":
            raise DurableStateError("unsupported permit schema")
        unsigned = {key: value for key, value in permit.items() if key != "signature"}
        authority = self.authority_keys.get(permit.get("authority_key_id"))
        if authority is None or not authority.verify(
            "permit-v1", unsigned, str(permit.get("signature", ""))
        ):
            raise DurableStateError("permit signature invalid")
        snapshot = self.state.read_campaign(str(permit["campaign_id"]))
        if snapshot.state.status != "ACTIVE":
            raise DurableStateError("campaign suspended")
        containment = self.state.containment_status()
        if containment["frozen"]:
            raise DurableStateError("execution globally frozen")
        if not (int(permit["valid_from_seq"]) <= seq <= int(permit["expires_at_seq"])):
            raise DurableStateError("permit outside validity sequence")
        expected = {
            "trace_id": proposal["trace_id"],
            "tenant_id": proposal["tenant_id"],
            "campaign_id": proposal["campaign_id"],
            "principal": proposal["principal"],
            "proposal_digest": proposal_digest(proposal),
            "action_digest": action_digest(proposal),
            "destination_digest": destination_digest(proposal),
            "parameter_digest": parameter_digest(proposal),
            "policy_digest": digest(policy),
            "signed_policy_digest": digest(signed_policy),
            "evidence_root": evidence_root(evidence),
            "decision_digest": digest(decision),
            "approval_digest": approval_digest(proposal),
            "campaign_state_digest": snapshot.state_digest,
            "valid_from_seq": decision.get("decided_at_seq"),
            "max_uses": 1,
        }
        for field_name, expected_value in expected.items():
            if permit.get(field_name) != expected_value:
                raise DurableStateError(f"permit binding mismatch: {field_name}")

    def execute(
        self,
        permit: dict[str, Any],
        proposal: dict[str, Any],
        signed_policy: dict[str, Any],
        evidence: list[dict[str, Any]],
        decision: dict[str, Any],
        seq: int,
        failpoint: str | None = None,
        before_dispatch: Callable[[], None] | None = None,
    ) -> dict[str, Any]:
        self._verify(permit, proposal, signed_policy, evidence, decision, seq)
        reservation = self.state.reserve(permit, proposal, seq)
        if reservation is None:
            raise DurableStateError("permit replay or concurrent duplicate")
        if failpoint == "after_reservation":
            raise InjectedCrash(failpoint)

        reservation_id = str(reservation["reservation_id"])
        reservation = self.state.begin_execution(
            reservation_id,
            self.executor_id,
            seq,
            self._signed_command("BEGIN_EXECUTION", reservation_id, seq),
        )
        if failpoint == "after_begin":
            raise InjectedCrash(failpoint)
        if before_dispatch is not None:
            before_dispatch()
        ticket = self.state.claim_dispatch(
            reservation_id,
            seq,
            self._signed_command("CLAIM_DISPATCH", reservation_id, seq),
        )
        if failpoint == "after_dispatch_commit":
            raise InjectedCrash(failpoint)

        provider_result = self.provider.invoke(proposal["action"], ticket)
        if failpoint == "after_provider":
            raise InjectedCrash(failpoint)
        unsigned = {
            "schema_version": "claimsieve.executor_receipt.v2",
            "trace_id": proposal["trace_id"],
            "campaign_id": proposal["campaign_id"],
            "permit_id": permit["permit_id"],
            "reservation_id": ticket.reservation_id,
            "action_digest": action_digest(proposal),
            "request_digest": ticket.request_digest,
            "idempotency_key": ticket.idempotency_key,
            "fencing_token": ticket.fencing_token,
            "containment_epoch": ticket.containment_epoch,
            "provider_status": provider_result["status"],
            "provider_id": provider_result.get("provider_id"),
            "attempted_at_seq": seq,
            "executor_key_id": self.executor_key.key_id,
        }
        receipt = {**unsigned, "signature": self.executor_key.sign("executor-receipt-v2", unsigned)}
        persisted = self.state.persist_provider_attempt(
            ticket.reservation_id, provider_result, receipt, seq
        )
        if failpoint == "after_provider_persist":
            raise InjectedCrash(failpoint)
        return {
            "reservation": persisted,
            "executor_receipt": receipt,
            "automatic_retry_allowed": False,
        }

    def resume_reserved(
        self,
        reservation_id: str,
        proposal: dict[str, Any],
        seq: int,
        failpoint: str | None = None,
    ) -> dict[str, Any]:
        row = self.state.get_reservation(reservation_id)
        if row["status"] == "RESERVED":
            self.state.begin_execution(
                reservation_id,
                self.executor_id,
                seq,
                self._signed_command("BEGIN_EXECUTION", reservation_id, seq),
            )
        elif row["status"] != "EXECUTING":
            raise DurableStateError("reservation cannot be resumed")
        ticket = self.state.claim_dispatch(
            reservation_id,
            seq,
            self._signed_command("CLAIM_DISPATCH", reservation_id, seq),
        )
        provider_result = self.provider.invoke(proposal["action"], ticket)
        if failpoint == "after_provider":
            raise InjectedCrash(failpoint)
        unsigned = {
            "schema_version": "claimsieve.executor_receipt.v2",
            "trace_id": proposal["trace_id"],
            "campaign_id": proposal["campaign_id"],
            "permit_id": ticket.permit_id,
            "reservation_id": reservation_id,
            "action_digest": ticket.action_digest,
            "request_digest": ticket.request_digest,
            "idempotency_key": ticket.idempotency_key,
            "fencing_token": ticket.fencing_token,
            "containment_epoch": ticket.containment_epoch,
            "provider_status": provider_result["status"],
            "provider_id": provider_result.get("provider_id"),
            "attempted_at_seq": seq,
            "executor_key_id": self.executor_key.key_id,
        }
        receipt = {**unsigned, "signature": self.executor_key.sign("executor-receipt-v2", unsigned)}
        persisted = self.state.persist_provider_attempt(reservation_id, provider_result, receipt, seq)
        return {"reservation": persisted, "executor_receipt": receipt, "automatic_retry_allowed": False}


def classify_provider_evidence(
    response_status: str | None,
    observed_action_digest: str | None,
    intended_action_digest: str,
) -> tuple[str, bool]:
    """Classify only independently read provider evidence.

    Returns ``(reconciliation, provider_evidence_conflict)``. A transport
    timeout can be resolved by later exact read-back. Contradictory provider
    evidence remains unknown rather than being coerced into success or failure.
    """

    conflict = (
        (response_status == "rejected" and observed_action_digest is not None)
        or (response_status == "accepted" and observed_action_digest is None)
    )
    if conflict:
        return "OUTCOME_UNKNOWN", True
    if observed_action_digest is not None:
        if observed_action_digest == intended_action_digest:
            return "CONFIRMED_SUCCESS", False
        return "DIVERGENT_EFFECT", False
    if response_status == "rejected":
        return "CONFIRMED_FAILURE", False
    return "OUTCOME_UNKNOWN", False


@dataclass
class IndependentObserver:
    state: DurableStateService
    provider: DurableProvider
    observer_key: KeyPair

    def reconcile(
        self,
        reservation_id: str,
        proposal: dict[str, Any],
        seq: int,
    ) -> dict[str, Any]:
        """Reconcile from independently readable provider state.

        Executor receipts remain audit evidence in the durable state store, but
        they are deliberately outside this observer's trust path. A correctly
        signed executor statement proves only which executor key produced the
        statement; it cannot turn absence of provider evidence into a confirmed
        success or failure.
        """
        reservation = self.state.get_reservation(reservation_id)
        provider_record = self.provider.query(str(reservation["idempotency_key"]))
        provider_status = reservation.get("provider_status")
        provider_evidence_conflict = False
        if provider_record is None:
            reconciliation = "OUTCOME_UNKNOWN"
            observed_action_digest = None
            receipt_conflict = False
        else:
            effect = provider_record.get("effect")
            response = provider_record.get("response")
            response_status = response.get("status") if isinstance(response, dict) else None
            observed_action_digest = digest(effect) if effect is not None else None
            # A provider record that says both "rejected" and "effect exists", or
            # "accepted" without any independently readable effect, is internally
            # contradictory. It cannot establish success or failure.
            reconciliation, provider_evidence_conflict = classify_provider_evidence(
                response_status,
                observed_action_digest,
                digest(proposal["action"]),
            )
            # Executor/provider disagreement remains visible as audit evidence,
            # but it never controls the terminal outcome classification.
            receipt_conflict = (
                provider_evidence_conflict
                or provider_status not in {None, response_status}
            )
        unsigned = {
            "schema_version": "claimsieve.observer_receipt.v2",
            "reservation_id": reservation_id,
            "permit_id": reservation["permit_id"],
            "campaign_id": reservation["campaign_id"],
            "provider_record_digest": digest(provider_record) if provider_record is not None else None,
            "observed_action_digest": observed_action_digest,
            "reconciliation": reconciliation,
            "receipt_conflict": receipt_conflict,
            "observed_at_seq": seq,
            "observer_key_id": self.observer_key.key_id,
        }
        observation = {
            **unsigned,
            "signature": self.observer_key.sign("observer-receipt-v2", unsigned),
        }
        containment_reason = (
            "PROVIDER_EVIDENCE_CONFLICT"
            if provider_evidence_conflict
            else None
        )
        self.state.record_observation(
            reservation_id,
            observation,
            seq,
            containment_reason=containment_reason,
        )
        return observation


@dataclass
class SimulatedConsensusNode:
    node_id: str
    term: int = 0
    commit_index: int = 0
    last_fence: int = 0
    active: bool = True


class QuorumStateMachineSimulator:
    """Deterministic safety model for partition and stale-leader tests.

    It is not a Raft implementation. It models only the invariants needed by
    this release: quorum-only commits, monotonically increasing terms and
    fencing tokens, and rejection of stale leaders after a majority advances.
    """

    def __init__(self, node_ids: tuple[str, ...] = ("n1", "n2", "n3")) -> None:
        if len(node_ids) < 3 or len(node_ids) % 2 == 0:
            raise ValueError("simulator requires an odd cluster of at least three nodes")
        self.nodes = {node_id: SimulatedConsensusNode(node_id) for node_id in node_ids}
        self.reachability = {
            left: {right for right in node_ids if right != left} for left in node_ids
        }
        self.leader_id: str | None = None
        self.global_term = 0
        self.global_commit_index = 0
        self.global_fence = 0
        self.trace: list[dict[str, Any]] = []

    @property
    def quorum(self) -> int:
        return len(self.nodes) // 2 + 1

    def partition(self, groups: list[set[str]]) -> None:
        all_nodes = set().union(*groups)
        if all_nodes != set(self.nodes):
            raise ValueError("partition groups must cover all nodes exactly")
        self.reachability = {node_id: set() for node_id in self.nodes}
        for group in groups:
            for node_id in group:
                self.reachability[node_id] = set(group) - {node_id}
        self.trace.append({"event": "PARTITION", "groups": [sorted(group) for group in groups]})

    def heal(self) -> None:
        node_ids = tuple(self.nodes)
        self.reachability = {
            left: {right for right in node_ids if right != left} for left in node_ids
        }
        for node in self.nodes.values():
            node.term = max(node.term, self.global_term)
            node.commit_index = self.global_commit_index
            node.last_fence = self.global_fence
        self.trace.append({"event": "HEAL", "commit_index": self.global_commit_index})

    def visible_active(self, node_id: str) -> set[str]:
        if not self.nodes[node_id].active:
            return set()
        return {node_id} | {
            peer
            for peer in self.reachability[node_id]
            if self.nodes[peer].active and node_id in self.reachability[peer]
        }

    def elect(self, node_id: str) -> bool:
        visible = self.visible_active(node_id)
        node = self.nodes[node_id]
        if len(visible) < self.quorum:
            self.trace.append({"event": "ELECTION_REJECTED", "node": node_id, "visible": sorted(visible)})
            return False
        max_commit = max(self.nodes[peer].commit_index for peer in visible)
        if node.commit_index < max_commit:
            self.trace.append({"event": "ELECTION_REJECTED_STALE_LOG", "node": node_id})
            return False
        self.global_term += 1
        node.term = self.global_term
        self.leader_id = node_id
        self.trace.append({"event": "LEADER_ELECTED", "node": node_id, "term": self.global_term})
        return True

    def commit(self, command_id: str) -> int | None:
        if self.leader_id is None:
            return None
        visible = self.visible_active(self.leader_id)
        leader = self.nodes[self.leader_id]
        if len(visible) < self.quorum or leader.term != self.global_term:
            self.trace.append(
                {"event": "COMMIT_REJECTED_NO_QUORUM", "leader": self.leader_id, "command": command_id}
            )
            return None
        self.global_commit_index += 1
        self.global_fence += 1
        for node_id in visible:
            node = self.nodes[node_id]
            node.term = self.global_term
            node.commit_index = self.global_commit_index
            node.last_fence = self.global_fence
        self.trace.append(
            {
                "event": "COMMIT",
                "leader": self.leader_id,
                "command": command_id,
                "term": self.global_term,
                "commit_index": self.global_commit_index,
                "fencing_token": self.global_fence,
                "replicas": sorted(visible),
            }
        )
        return self.global_fence

    def crash(self, node_id: str) -> None:
        self.nodes[node_id].active = False
        if self.leader_id == node_id:
            self.leader_id = None
        self.trace.append({"event": "CRASH", "node": node_id})

    def restart(self, node_id: str) -> None:
        self.nodes[node_id].active = True
        self.trace.append({"event": "RESTART", "node": node_id})
