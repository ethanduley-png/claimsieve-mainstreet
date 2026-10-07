from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path
from typing import Any, Mapping

from .deepagents_adapter import ClaimSieveRuntimeContext


class OpenWorkerContextError(RuntimeError):
    pass


class OpenWorkerProductionContextStore:
    """Durably allocate ClaimSieve context for each consequential OpenWorker tool call."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sequence (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    last_seq INTEGER NOT NULL CHECK (last_seq >= 0)
                )
                """
            )
            conn.execute(
                "INSERT OR IGNORE INTO sequence(singleton, last_seq) VALUES (1, 0)"
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0, isolation_level=None)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    def _next_seq(self) -> int:
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT last_seq FROM sequence WHERE singleton = 1"
            ).fetchone()
            if row is None or not isinstance(row[0], int) or row[0] < 0:
                raise OpenWorkerContextError("OpenWorker context sequence state is invalid")
            value = row[0] + 1
            conn.execute(
                "UPDATE sequence SET last_seq = ? WHERE singleton = 1", (value,)
            )
            conn.commit()
            return value
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    @staticmethod
    def _hash(prefix: str, value: str) -> str:
        return f"{prefix}-{hashlib.sha256(value.encode('utf-8')).hexdigest()[:32]}"

    def context_for_engine_call(
        self,
        engine: Any,
        tool_call: Mapping[str, Any],
    ) -> ClaimSieveRuntimeContext:
        audit = getattr(engine, "audit_context", None)
        if not isinstance(audit, Mapping):
            raise OpenWorkerContextError(
                "OpenWorker engine lacks bound audit context at consequential execution"
            )
        session_id = audit.get("session_id")
        tool_call_id = tool_call.get("id")
        if not isinstance(session_id, str) or not session_id or len(session_id) > 128:
            raise OpenWorkerContextError("OpenWorker engine session identity is invalid")
        if not isinstance(tool_call_id, str) or not tool_call_id or len(tool_call_id) > 110:
            raise OpenWorkerContextError("OpenWorker tool call identity is invalid")
        context = ClaimSieveRuntimeContext(
            trace_id=self._hash("ow-trace", f"{session_id}:{tool_call_id}"),
            campaign_id=self._hash("ow-campaign", session_id),
            session_id=session_id,
            work_item_id=f"openworker-tool-{tool_call_id}",
            requested_at_seq=self._next_seq(),
        )
        context.validate()
        return context
