from __future__ import annotations

import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from founder_os import FounderOSReferenceWorkflow
from mainstreet_runtimes import ClaimSieveRuntimeContext, OpenWorkerProposalAdapter
from mainstreet_runtimes.openworker_claimsieve_intake import (
    OpenWorkerFounderIntake,
    OpenWorkerIntakeError,
)


OPENWORKER_COMMIT = "86c57f0692a5a318e55d1b9e0188d798b9fc5690"


class OpenWorkerIntakeDurabilityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repository = "example/claimsieve-mainstreet"
        self.context = ClaimSieveRuntimeContext(
            trace_id="trace-openworker-durable",
            campaign_id="campaign-openworker-durable",
            session_id="session-openworker-durable",
            work_item_id="work-openworker-durable",
            requested_at_seq=60,
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def workflow(self) -> FounderOSReferenceWorkflow:
        return FounderOSReferenceWorkflow(
            self.root,
            allowed_repositories={self.repository},
            provider_mode="success",
            runtime_name="openworker",
            runtime_version=OPENWORKER_COMMIT,
        )

    def adapter(self, intake: OpenWorkerFounderIntake) -> OpenWorkerProposalAdapter:
        return OpenWorkerProposalAdapter(
            self.context,
            intake.route_intent,
            consequential_tools={"create_github_issue"},
        )

    def tool_call(self) -> dict:
        return {
            "schema_version": "mainstreet.openworker_tool_call.v1",
            "id": "ow-durable-001",
            "name": "create_github_issue",
            "arguments": {
                "repository": self.repository,
                "title": "Durable OpenWorker boundary",
                "body": "Replay identity and pending execution must survive process restart.",
            },
        }

    def test_seen_tool_call_and_pending_permit_survive_restart(self) -> None:
        first = OpenWorkerFounderIntake(self.workflow())
        routed = self.adapter(first).route_tool_call(self.tool_call())
        permit_id = routed["claimsieve"]["permit_id"]
        self.assertEqual(first.pending_permits(), (permit_id,))

        restarted = OpenWorkerFounderIntake(self.workflow())
        self.assertEqual(restarted.pending_permits(), (permit_id,))
        self.assertEqual(restarted.durable_state_for_tool_call("ow-durable-001"), "PENDING")
        with self.assertRaisesRegex(OpenWorkerIntakeError, "duplicate OpenWorker tool call identity"):
            self.adapter(restarted).route_tool_call(self.tool_call())

    def test_pending_action_can_execute_after_restart_without_reissuing_permit(self) -> None:
        first = OpenWorkerFounderIntake(self.workflow())
        routed = self.adapter(first).route_tool_call(self.tool_call())
        permit_id = routed["claimsieve"]["permit_id"]

        restarted = OpenWorkerFounderIntake(self.workflow())
        result = restarted.execute_pending(permit_id, 61, 62)
        self.assertEqual(result.observation["reconciliation"], "CONFIRMED_SUCCESS")
        self.assertEqual(restarted.pending_permits(), ())
        self.assertEqual(restarted.durable_state_for_tool_call("ow-durable-001"), "COMPLETE")

    def test_execution_reservation_survives_crash_and_blocks_automatic_retry(self) -> None:
        workflow = self.workflow()
        first = OpenWorkerFounderIntake(workflow)
        routed = self.adapter(first).route_tool_call(self.tool_call())
        permit_id = routed["claimsieve"]["permit_id"]

        def crash_after_reservation(*args, **kwargs):
            raise RuntimeError("synthetic crash at provider boundary")

        workflow.execute_issue = crash_after_reservation  # type: ignore[method-assign]
        with self.assertRaisesRegex(RuntimeError, "synthetic crash"):
            first.execute_pending(permit_id, 61, 62)
        self.assertEqual(
            first.durable_state_for_tool_call("ow-durable-001"),
            "EXECUTION_RESERVED",
        )

        restarted = OpenWorkerFounderIntake(self.workflow())
        with self.assertRaisesRegex(OpenWorkerIntakeError, "outcome may be indeterminate"):
            restarted.execute_pending(permit_id, 63, 64)

    def test_tampered_persisted_prepared_action_fails_integrity_before_execution(self) -> None:
        first = OpenWorkerFounderIntake(self.workflow())
        routed = self.adapter(first).route_tool_call(self.tool_call())
        permit_id = routed["claimsieve"]["permit_id"]

        db = self.root / "openworker-intake.sqlite3"
        with sqlite3.connect(db) as conn:
            row = conn.execute(
                "SELECT prepared_json FROM openworker_intake WHERE permit_id = ?", (permit_id,)
            ).fetchone()
            self.assertIsNotNone(row)
            conn.execute(
                "UPDATE openworker_intake SET prepared_json = ? WHERE permit_id = ?",
                (str(row[0]).replace("Durable OpenWorker boundary", "tampered title"), permit_id),
            )

        restarted = OpenWorkerFounderIntake(self.workflow())
        with self.assertRaisesRegex(OpenWorkerIntakeError, "integrity verification"):
            restarted.execute_pending(permit_id, 61, 62)
        self.assertEqual(restarted.durable_state_for_tool_call("ow-durable-001"), "PENDING")

    def test_two_intake_instances_share_one_cross_process_style_replay_boundary(self) -> None:
        intake_a = OpenWorkerFounderIntake(self.workflow())
        intake_b = OpenWorkerFounderIntake(self.workflow())
        intent = self.adapter(intake_a).build_intent(self.tool_call()).to_dict()
        outcomes: list[str] = []
        errors: list[BaseException] = []
        barrier = threading.Barrier(2)

        def route(intake: OpenWorkerFounderIntake) -> None:
            try:
                barrier.wait(timeout=5)
                intake.route_intent(dict(intent))
                outcomes.append("admitted")
            except BaseException as exc:
                errors.append(exc)

        a = threading.Thread(target=route, args=(intake_a,))
        b = threading.Thread(target=route, args=(intake_b,))
        a.start()
        b.start()
        a.join(timeout=5)
        b.join(timeout=5)
        self.assertEqual(outcomes, ["admitted"])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], OpenWorkerIntakeError)
        self.assertIn("duplicate OpenWorker tool call identity", str(errors[0]))


if __name__ == "__main__":
    unittest.main()
