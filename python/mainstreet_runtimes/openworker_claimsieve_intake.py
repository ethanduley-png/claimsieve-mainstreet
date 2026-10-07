from __future__ import annotations

import copy
import json
import sqlite3
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from claimsieve_ref.canonical import digest
from founder_os import FounderActionResult, FounderOSReferenceWorkflow, GitHubIssueRequest, PreparedFounderAction


class OpenWorkerIntakeError(ValueError):
    """Raised when an OpenWorker proposal cannot enter the ClaimSieve path."""


@dataclass(frozen=True)
class _StoredPendingAction:
    tool_call_id: str
    state: str
    permit_id: str | None
    prepared: PreparedFounderAction | None


class _DurableOpenWorkerIntakeStore:
    """Transactional replay and pending-action journal for the native OpenWorker boundary.

    A tool-call identity is reserved before ClaimSieve permit preparation starts. A crash at
    any later point therefore cannot make the same OpenWorker call look new after restart.
    Execution is similarly reserved durably before the provider boundary is entered; a crash
    after reservation is treated as indeterminate and automatic retry stays blocked.
    """

    SCHEMA_VERSION = 1
    ADMITTING = "ADMITTING"
    PENDING = "PENDING"
    EXECUTION_RESERVED = "EXECUTION_RESERVED"
    COMPLETE = "COMPLETE"
    FAILED_CLOSED = "FAILED_CLOSED"

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS openworker_intake (
                    tool_call_id TEXT PRIMARY KEY,
                    intent_digest TEXT NOT NULL,
                    state TEXT NOT NULL,
                    permit_id TEXT UNIQUE,
                    prepared_json TEXT,
                    prepared_digest TEXT,
                    failure_reason TEXT,
                    schema_version INTEGER NOT NULL
                )
                """
            )

    @staticmethod
    def _prepared_document(prepared: PreparedFounderAction) -> dict[str, Any]:
        return {
            "request": asdict(prepared.request),
            "evidence": copy.deepcopy(prepared.evidence),
            "policy": copy.deepcopy(prepared.policy),
            "signed_policy": copy.deepcopy(prepared.signed_policy),
            "proposal": copy.deepcopy(prepared.proposal),
            "decision": copy.deepcopy(prepared.decision),
            "permit": copy.deepcopy(prepared.permit),
        }

    @classmethod
    def _serialize_prepared(cls, prepared: PreparedFounderAction) -> tuple[str, str]:
        document = cls._prepared_document(prepared)
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return encoded, digest(document)

    @classmethod
    def _deserialize_prepared(cls, encoded: str, expected_digest: str) -> PreparedFounderAction:
        try:
            document = json.loads(encoded)
        except json.JSONDecodeError as exc:
            raise OpenWorkerIntakeError("durable OpenWorker pending action is malformed") from exc
        if not isinstance(document, dict) or digest(document) != expected_digest:
            raise OpenWorkerIntakeError("durable OpenWorker pending action failed integrity verification")
        request_document = document.get("request")
        if not isinstance(request_document, dict):
            raise OpenWorkerIntakeError("durable OpenWorker request is malformed")
        try:
            request = GitHubIssueRequest(**request_document)
            request.validate()
        except (TypeError, ValueError) as exc:
            raise OpenWorkerIntakeError("durable OpenWorker request failed validation") from exc
        required = {"evidence", "policy", "signed_policy", "proposal", "decision", "permit"}
        if not required.issubset(document):
            raise OpenWorkerIntakeError("durable OpenWorker prepared action is incomplete")
        return PreparedFounderAction(
            request=request,
            evidence=copy.deepcopy(document["evidence"]),
            policy=copy.deepcopy(document["policy"]),
            signed_policy=copy.deepcopy(document["signed_policy"]),
            proposal=copy.deepcopy(document["proposal"]),
            decision=copy.deepcopy(document["decision"]),
            permit=copy.deepcopy(document["permit"]),
        )

    def reserve_admission(self, tool_call_id: str, intent_digest: str) -> None:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT state FROM openworker_intake WHERE tool_call_id = ?",
                (tool_call_id,),
            ).fetchone()
            if existing is not None:
                raise OpenWorkerIntakeError("duplicate OpenWorker tool call identity")
            conn.execute(
                """
                INSERT INTO openworker_intake
                    (tool_call_id, intent_digest, state, schema_version)
                VALUES (?, ?, ?, ?)
                """,
                (tool_call_id, intent_digest, self.ADMITTING, self.SCHEMA_VERSION),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def fail_closed(self, tool_call_id: str, reason: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE openworker_intake
                SET state = ?, failure_reason = ?
                WHERE tool_call_id = ? AND state = ?
                """,
                (self.FAILED_CLOSED, reason[:1000], tool_call_id, self.ADMITTING),
            )

    def finalize_pending(self, tool_call_id: str, prepared: PreparedFounderAction) -> None:
        permit_id = str(prepared.permit["permit_id"])
        encoded, prepared_digest = self._serialize_prepared(prepared)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT state FROM openworker_intake WHERE tool_call_id = ?",
                (tool_call_id,),
            ).fetchone()
            if row is None or row["state"] != self.ADMITTING:
                raise OpenWorkerIntakeError("OpenWorker admission reservation is not active")
            conn.execute(
                """
                UPDATE openworker_intake
                SET state = ?, permit_id = ?, prepared_json = ?, prepared_digest = ?
                WHERE tool_call_id = ?
                """,
                (self.PENDING, permit_id, encoded, prepared_digest, tool_call_id),
            )
            conn.commit()
        except sqlite3.IntegrityError as exc:
            conn.rollback()
            raise OpenWorkerIntakeError("duplicate permit identity") from exc
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def reserve_execution(self, permit_id: str) -> PreparedFounderAction:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT tool_call_id, state, prepared_json, prepared_digest, schema_version
                FROM openworker_intake WHERE permit_id = ?
                """,
                (permit_id,),
            ).fetchone()
            if row is None:
                raise OpenWorkerIntakeError("unknown pending permit")
            if row["schema_version"] != self.SCHEMA_VERSION:
                raise OpenWorkerIntakeError("unsupported durable OpenWorker intake schema")
            if row["state"] != self.PENDING:
                if row["state"] == self.EXECUTION_RESERVED:
                    raise OpenWorkerIntakeError(
                        "pending permit execution already reserved; outcome may be indeterminate"
                    )
                raise OpenWorkerIntakeError("pending permit is not executable")
            encoded = row["prepared_json"]
            expected_digest = row["prepared_digest"]
            if not isinstance(encoded, str) or not isinstance(expected_digest, str):
                raise OpenWorkerIntakeError("durable OpenWorker pending action is incomplete")
            prepared = self._deserialize_prepared(encoded, expected_digest)
            conn.execute(
                "UPDATE openworker_intake SET state = ? WHERE permit_id = ? AND state = ?",
                (self.EXECUTION_RESERVED, permit_id, self.PENDING),
            )
            conn.commit()
            return prepared
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def mark_complete(self, permit_id: str) -> None:
        with self._connect() as conn:
            changed = conn.execute(
                "UPDATE openworker_intake SET state = ? WHERE permit_id = ? AND state = ?",
                (self.COMPLETE, permit_id, self.EXECUTION_RESERVED),
            ).rowcount
            if changed != 1:
                raise OpenWorkerIntakeError("durable OpenWorker execution state changed unexpectedly")

    def pending_permits(self) -> tuple[str, ...]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT permit_id FROM openworker_intake WHERE state = ? ORDER BY permit_id",
                (self.PENDING,),
            ).fetchall()
        return tuple(str(row["permit_id"]) for row in rows)

    def state_for_tool_call(self, tool_call_id: str) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT state FROM openworker_intake WHERE tool_call_id = ?",
                (tool_call_id,),
            ).fetchone()
        return None if row is None else str(row["state"])


class OpenWorkerFounderIntake:
    """Durable OpenWorker intake into the existing Founder OS authority path.

    OpenWorker remains proposal-side only. Tool-call replay identity and pending execution
    state are persisted transactionally so process restart does not create a fresh authority
    opportunity. Provider execution remains a separate explicit step.
    """

    INTENT_SCHEMA = "mainstreet.consequential_tool_intent.v1"
    SUPPORTED_RUNTIME = "openworker"
    SUPPORTED_RUNTIME_VERSION = "86c57f0692a5a318e55d1b9e0188d798b9fc5690"
    SUPPORTED_TOOL = "create_github_issue"
    REQUIRED_ARGUMENTS = frozenset({"repository", "title", "body"})
    REQUIRED_CONTEXT = frozenset(
        {"trace_id", "campaign_id", "session_id", "work_item_id", "requested_at_seq"}
    )

    def __init__(self, workflow: FounderOSReferenceWorkflow) -> None:
        profile = getattr(workflow, "runtime_profile", None)
        if profile is None or profile.runtime_name != self.SUPPORTED_RUNTIME:
            raise OpenWorkerIntakeError(
                "OpenWorker intake requires a Founder OS workflow bound to the openworker principal"
            )
        try:
            profile.validate()
        except ValueError as exc:
            raise OpenWorkerIntakeError("OpenWorker runtime profile is invalid") from exc
        if profile.runtime_version != self.SUPPORTED_RUNTIME_VERSION:
            raise OpenWorkerIntakeError(
                "OpenWorker intake runtime version does not match the pinned upstream commit"
            )
        workspace = getattr(workflow, "workspace", None)
        if not isinstance(workspace, Path):
            raise OpenWorkerIntakeError("OpenWorker intake requires a durable Founder OS workspace")
        self._workflow = workflow
        self._runtime_profile = profile
        self._store = _DurableOpenWorkerIntakeStore(workspace / "openworker-intake.sqlite3")
        self._lock = threading.RLock()

    @staticmethod
    def _exact_mapping(value: Any, name: str) -> Mapping[str, Any]:
        if not isinstance(value, Mapping):
            raise OpenWorkerIntakeError(f"{name} must be a mapping")
        return value

    @staticmethod
    def _nonempty_string(value: Any, name: str, maximum: int) -> str:
        if not isinstance(value, str) or not value or len(value) > maximum:
            raise OpenWorkerIntakeError(
                f"{name} must be a non-empty string of at most {maximum} characters"
            )
        return value

    def _request_from_intent(self, intent: Mapping[str, Any]) -> GitHubIssueRequest:
        if frozenset(intent) != frozenset(
            {"schema_version", "runtime", "tool_call_id", "tool_name", "arguments", "context"}
        ):
            raise OpenWorkerIntakeError("runtime intent fields do not match the required schema")
        if intent.get("schema_version") != self.INTENT_SCHEMA:
            raise OpenWorkerIntakeError("unsupported runtime intent schema")
        if intent.get("runtime") != self.SUPPORTED_RUNTIME:
            raise OpenWorkerIntakeError("runtime identity mismatch")
        if intent.get("tool_name") != self.SUPPORTED_TOOL:
            raise OpenWorkerIntakeError("unsupported consequential tool")

        tool_call_id = self._nonempty_string(intent.get("tool_call_id"), "tool_call_id", 110)
        arguments = self._exact_mapping(intent.get("arguments"), "arguments")
        if frozenset(arguments) != self.REQUIRED_ARGUMENTS:
            raise OpenWorkerIntakeError(
                "GitHub issue arguments must be exactly repository, title, and body"
            )

        context = self._exact_mapping(intent.get("context"), "context")
        if frozenset(context) != self.REQUIRED_CONTEXT:
            raise OpenWorkerIntakeError("runtime context fields do not match the required schema")

        requested_at_seq = context.get("requested_at_seq")
        if (
            isinstance(requested_at_seq, bool)
            or not isinstance(requested_at_seq, int)
            or requested_at_seq < 0
        ):
            raise OpenWorkerIntakeError("requested_at_seq must be a non-negative integer")

        return GitHubIssueRequest(
            proposal_id=f"openworker-{tool_call_id}",
            trace_id=self._nonempty_string(context.get("trace_id"), "trace_id", 128),
            campaign_id=self._nonempty_string(context.get("campaign_id"), "campaign_id", 128),
            session_id=self._nonempty_string(context.get("session_id"), "session_id", 128),
            work_item_id=self._nonempty_string(context.get("work_item_id"), "work_item_id", 256),
            repository=self._nonempty_string(arguments.get("repository"), "repository", 201),
            title=self._nonempty_string(arguments.get("title"), "title", 180),
            body=self._nonempty_string(arguments.get("body"), "body", 20_000),
            requested_at_seq=requested_at_seq,
        )

    def route_intent(self, intent: dict[str, Any]) -> dict[str, Any]:
        request = self._request_from_intent(intent)
        tool_call_id = str(intent["tool_call_id"])
        try:
            intent_digest = digest(intent)
        except ValueError as exc:
            raise OpenWorkerIntakeError("runtime intent is not canonically digestible") from exc

        # The local lock keeps same-process behavior deterministic; the SQLite reservation is
        # the actual cross-process/restart replay boundary.
        with self._lock:
            self._store.reserve_admission(tool_call_id, intent_digest)

        try:
            prepared = self._workflow.prepare_issue(request)
            if prepared.proposal.get("principal") != self._runtime_profile.principal:
                raise OpenWorkerIntakeError("prepared proposal principal is not bound to OpenWorker")
            if prepared.permit.get("principal") != self._runtime_profile.principal:
                raise OpenWorkerIntakeError("issued permit principal is not bound to OpenWorker")
            if prepared.proposal.get("runtime_identity") != self._runtime_profile.binding():
                raise OpenWorkerIntakeError("prepared proposal runtime identity binding mismatch")
            self._store.finalize_pending(tool_call_id, prepared)
        except Exception as exc:
            self._store.fail_closed(tool_call_id, f"{type(exc).__name__}: {exc}")
            raise

        permit_id = str(prepared.permit["permit_id"])
        return {
            "schema_version": "mainstreet.claimsieve_intake_receipt.v1",
            "status": "PERMIT_ISSUED_EXECUTION_PENDING",
            "permit_id": permit_id,
            "proposal_id": request.proposal_id,
            "runtime_name": self._runtime_profile.runtime_name,
            "runtime_version": self._runtime_profile.runtime_version,
            "runtime_principal": self._runtime_profile.principal,
            "runtime_manifest_digest": self._runtime_profile.runtime_manifest_digest,
            "proposal_digest": prepared.permit["proposal_digest"],
            "action_digest": prepared.permit["action_digest"],
            "destination_digest": prepared.permit["destination_digest"],
            "parameter_digest": prepared.permit["parameter_digest"],
            "expires_at_seq": prepared.permit["expires_at_seq"],
            "external_action_executed": False,
        }

    def execute_pending(self, permit_id: str, execute_seq: int, observe_seq: int) -> FounderActionResult:
        prepared = self._store.reserve_execution(permit_id)
        result = self._workflow.execute_issue(prepared, execute_seq, observe_seq)
        self._store.mark_complete(permit_id)
        return result

    def pending_permits(self) -> tuple[str, ...]:
        return self._store.pending_permits()

    def durable_state_for_tool_call(self, tool_call_id: str) -> str | None:
        """Expose bounded state for tests/operations without exposing stored action payloads."""
        return self._store.state_for_tool_call(tool_call_id)
