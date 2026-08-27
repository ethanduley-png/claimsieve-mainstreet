from __future__ import annotations

import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

from mainstreet_runtimes.openworker_context import (
    OpenWorkerContextError,
    OpenWorkerProductionContextStore,
)


class OpenWorkerProductionContextTests(unittest.TestCase):
    def test_context_binds_real_engine_session_and_increments_durably(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "context.sqlite3"
            first = OpenWorkerProductionContextStore(path)
            engine = SimpleNamespace(audit_context={"session_id": "session-real-1"})
            a = first.context_for_engine_call(engine, {"id": "tool-1"})
            self.assertEqual(a.session_id, "session-real-1")
            self.assertEqual(a.requested_at_seq, 1)

            restarted = OpenWorkerProductionContextStore(path)
            b = restarted.context_for_engine_call(engine, {"id": "tool-2"})
            self.assertEqual(b.requested_at_seq, 2)
            self.assertEqual(a.campaign_id, b.campaign_id)
            self.assertNotEqual(a.trace_id, b.trace_id)

    def test_missing_engine_session_fails_closed_without_allocating_context(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = OpenWorkerProductionContextStore(Path(temp) / "context.sqlite3")
            with self.assertRaisesRegex(OpenWorkerContextError, "session identity"):
                store.context_for_engine_call(SimpleNamespace(audit_context={}), {"id": "tool-1"})
            valid = store.context_for_engine_call(
                SimpleNamespace(audit_context={"session_id": "session-ok"}), {"id": "tool-2"}
            )
            self.assertEqual(valid.requested_at_seq, 1)

    def test_concurrent_allocations_are_unique_and_monotonic(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = OpenWorkerProductionContextStore(Path(temp) / "context.sqlite3")
            engine = SimpleNamespace(audit_context={"session_id": "session-concurrent"})
            values: list[int] = []
            errors: list[BaseException] = []
            barrier = threading.Barrier(8)

            def allocate(index: int) -> None:
                try:
                    barrier.wait(timeout=5)
                    values.append(
                        store.context_for_engine_call(engine, {"id": f"tool-{index}"}).requested_at_seq
                    )
                except BaseException as exc:
                    errors.append(exc)

            threads = [threading.Thread(target=allocate, args=(i,)) for i in range(8)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(timeout=5)
            self.assertEqual(errors, [])
            self.assertEqual(sorted(values), list(range(1, 9)))


if __name__ == "__main__":
    unittest.main()
