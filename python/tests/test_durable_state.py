from __future__ import annotations

import copy
import multiprocessing as mp
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any

from claimsieve_ref.canonical import digest
from claimsieve_ref.durable_state import (
    DispatchTicket,
    DurableCampaignStateStore,
    DurableExecutor,
    DurableProviderSimulator,
    DurableStateError,
    DurableStateService,
    classify_provider_evidence,
    IndependentObserver,
    InjectedCrash,
    QuorumStateMachineSimulator,
)
from claimsieve_ref.fixtures import evidence, keypairs, policy, proposal, signed_policy
from claimsieve_ref.kernel import CampaignState, evaluate
from claimsieve_ref.model import action_digest
from claimsieve_ref.runtime import Authority, PermitError


def _authority(service: DurableStateService) -> Authority:
    keys = keypairs()
    return Authority(
        keys["authority"],
        {keys["approver"].key_id: keys["approver"].public},
        {keys["policy_authority"].key_id: keys["policy_authority"].public},
        {
            keys["crm_evidence"].key_id: keys["crm_evidence"].public,
            keys["registry_evidence"].key_id: keys["registry_evidence"].public,
            keys["deployment_evidence"].key_id: keys["deployment_evidence"].public,
            keys["epoch_evidence"].key_id: keys["epoch_evidence"].public,
        },
        DurableCampaignStateStore(service),
    )


def _issue(service: DurableStateService, seq: int = 10, nonce: str = "11" * 24) -> tuple[Any, ...]:
    ev = evidence(seq)
    prop = proposal(ev, seq)
    pol = policy()
    signed = signed_policy()
    current = service.read_campaign(prop["campaign_id"]).state
    decision = evaluate(prop, pol, ev, current, seq)
    permit = _authority(service).issue(prop, signed, ev, decision.document, seq, nonce=nonce)
    return ev, prop, pol, signed, decision, permit


def _reserve_worker(db_path: str, permit: dict[str, Any], prop: dict[str, Any], queue: Any) -> None:
    service = DurableStateService(db_path)
    try:
        result = service.reserve(permit, prop, 11)
        queue.put(result is not None)
    except BaseException as exc:  # pragma: no cover - failure trace is returned
        queue.put(type(exc).__name__ + ":" + str(exc))


def _issue_worker(db_path: str, queue: Any) -> None:
    service = DurableStateService(db_path)
    try:
        _issue(service, 10, "22" * 24)
        queue.put("WIN")
    except PermitError as exc:
        queue.put("LOSE:" + str(exc))
    except BaseException as exc:  # pragma: no cover
        queue.put("ERROR:" + type(exc).__name__ + ":" + str(exc))


class DurableStateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.state_path = root / "state.sqlite3"
        self.provider_path = root / "provider.sqlite3"
        self.keys = keypairs()
        self.state = DurableStateService(
            self.state_path,
            executor_keys={self.keys["executor"].key_id: self.keys["executor"].public},
            observer_keys={self.keys["observer"].key_id: self.keys["observer"].public},
        )
        self.ev, self.prop, self.pol, self.signed, self.decision, self.permit = _issue(self.state)
        keys = self.keys
        self.provider = DurableProviderSimulator(self.provider_path, "success")
        self.executor = DurableExecutor(
            self.state,
            self.provider,
            {keys["authority"].key_id: keys["authority"].public},
            keys["executor"],
        )
        self.observer = IndependentObserver(
            self.state,
            self.provider,
            keys["observer"],
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_campaign_and_permit_survive_reopen(self) -> None:
        reopened = DurableStateService(self.state_path)
        snapshot = reopened.read_campaign("campaign-001")
        self.assertEqual(snapshot.state.last_sequence, 10)
        reservation = reopened.reserve(self.permit, self.prop, 11)
        self.assertIsNotNone(reservation)

    def test_journal_chain_verifies(self) -> None:
        self.assertTrue(self.state.verify_journal())
        self.state.reserve(self.permit, self.prop, 11)
        self.assertTrue(self.state.verify_journal())

    def test_journal_tamper_is_detected(self) -> None:
        connection = sqlite3.connect(self.state_path)
        try:
            connection.execute(
                "UPDATE journal SET payload_json = ? WHERE event_sequence = 1",
                ('{"tampered":true}',),
            )
            connection.commit()
        finally:
            connection.close()
        self.assertFalse(self.state.verify_journal())

    def test_duplicate_reservation_is_rejected(self) -> None:
        first = self.state.reserve(self.permit, self.prop, 11)
        second = self.state.reserve(self.permit, self.prop, 11)
        self.assertIsNotNone(first)
        self.assertIsNone(second)

    def test_cross_process_reservation_has_one_winner(self) -> None:
        ctx = mp.get_context("spawn")
        queue = ctx.Queue()
        processes = [
            ctx.Process(
                target=_reserve_worker,
                args=(str(self.state_path), self.permit, self.prop, queue),
            )
            for _ in range(24)
        ]
        for process in processes:
            process.start()
        for process in processes:
            process.join(20)
            self.assertEqual(process.exitcode, 0)
        results = [queue.get(timeout=5) for _ in processes]
        self.assertEqual(results.count(True), 1, results)
        self.assertEqual(results.count(False), 23, results)

    def test_cross_process_campaign_successor_has_one_winner(self) -> None:
        # Use a fresh database without the permit issued in setUp.
        fresh = Path(self.temp.name) / "campaign-race.sqlite3"
        DurableStateService(fresh).read_campaign("campaign-001")
        ctx = mp.get_context("spawn")
        queue = ctx.Queue()
        processes = [ctx.Process(target=_issue_worker, args=(str(fresh), queue)) for _ in range(16)]
        for process in processes:
            process.start()
        for process in processes:
            process.join(20)
            self.assertEqual(process.exitcode, 0)
        results = [queue.get(timeout=5) for _ in processes]
        self.assertEqual(results.count("WIN"), 1, results)
        self.assertEqual(sum(item.startswith("LOSE:") for item in results), 15, results)

    def test_execution_and_independent_observation(self) -> None:
        result = self.executor.execute(
            self.permit, self.prop, self.signed, self.ev, self.decision.document, 11
        )
        observation = self.observer.reconcile(
            result["reservation"]["reservation_id"], self.prop, 12
        )
        self.assertEqual(observation["reconciliation"], "CONFIRMED_SUCCESS")
        stored = self.state.get_reservation(result["reservation"]["reservation_id"])
        self.assertEqual(stored["outcome"], "CONFIRMED_SUCCESS")
        self.assertFalse(result["automatic_retry_allowed"])

    def test_crash_after_reservation_is_recoverable_without_new_reservation(self) -> None:
        with self.assertRaises(InjectedCrash):
            self.executor.execute(
                self.permit,
                self.prop,
                self.signed,
                self.ev,
                self.decision.document,
                11,
                failpoint="after_reservation",
            )
        queue = self.state.recovery_queue()
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["status"], "RESERVED")
        resumed = self.executor.resume_reserved(queue[0]["reservation_id"], self.prop, 12)
        self.assertEqual(resumed["reservation"]["status"], "PROVIDER_ACKNOWLEDGED")
        self.assertEqual(self.observer.reconcile(queue[0]["reservation_id"], self.prop, 13)["reconciliation"], "CONFIRMED_SUCCESS")

    def test_crash_after_provider_commit_reconciles_without_retry(self) -> None:
        provider = DurableProviderSimulator(self.provider_path, "success")
        executor = DurableExecutor(
            self.state,
            provider,
            self.executor.authority_keys,
            self.executor.executor_key,
        )
        with self.assertRaises(InjectedCrash):
            executor.execute(
                self.permit,
                self.prop,
                self.signed,
                self.ev,
                self.decision.document,
                11,
                failpoint="after_provider",
            )
        row = self.state.recovery_queue()[0]
        self.assertEqual(row["status"], "DISPATCHING")
        observer = IndependentObserver(
            self.state, provider, self.observer.observer_key
        )
        observation = observer.reconcile(row["reservation_id"], self.prop, 12)
        self.assertEqual(observation["reconciliation"], "CONFIRMED_SUCCESS")

    def test_timeout_after_commit_is_resolved_by_provider_query(self) -> None:
        provider = DurableProviderSimulator(self.provider_path, "timeout_after_commit")
        executor = DurableExecutor(
            self.state, provider, self.executor.authority_keys, self.executor.executor_key
        )
        result = executor.execute(
            self.permit, self.prop, self.signed, self.ev, self.decision.document, 11
        )
        self.assertEqual(result["reservation"]["status"], "OUTCOME_UNKNOWN")
        observer = IndependentObserver(
            self.state, provider, self.observer.observer_key
        )
        observation = observer.reconcile(result["reservation"]["reservation_id"], self.prop, 12)
        self.assertEqual(observation["reconciliation"], "CONFIRMED_SUCCESS")

    def test_timeout_before_commit_remains_unknown(self) -> None:
        provider = DurableProviderSimulator(self.provider_path, "timeout_before_commit")
        executor = DurableExecutor(
            self.state, provider, self.executor.authority_keys, self.executor.executor_key
        )
        result = executor.execute(
            self.permit, self.prop, self.signed, self.ev, self.decision.document, 11
        )
        observer = IndependentObserver(
            self.state, provider, self.observer.observer_key
        )
        observation = observer.reconcile(result["reservation"]["reservation_id"], self.prop, 12)
        self.assertEqual(observation["reconciliation"], "OUTCOME_UNKNOWN")
        self.assertEqual(self.state.get_reservation(result["reservation"]["reservation_id"])["status"], "OUTCOME_UNKNOWN")

    def test_conflicting_provider_receipt_is_detected(self) -> None:
        provider = DurableProviderSimulator(self.provider_path, "conflicting_receipt")
        executor = DurableExecutor(
            self.state, provider, self.executor.authority_keys, self.executor.executor_key
        )
        result = executor.execute(
            self.permit, self.prop, self.signed, self.ev, self.decision.document, 11
        )
        observer = IndependentObserver(
            self.state, provider, self.observer.observer_key
        )
        observation = observer.reconcile(result["reservation"]["reservation_id"], self.prop, 12)
        self.assertEqual(observation["reconciliation"], "OUTCOME_UNKNOWN")
        self.assertTrue(observation["receipt_conflict"])
        self.assertEqual(
            self.state.read_campaign(self.prop["campaign_id"]).state.status,
            "SUSPENDED",
        )

    def test_divergent_effect_is_detected(self) -> None:
        provider = DurableProviderSimulator(self.provider_path, "divergent")
        executor = DurableExecutor(
            self.state, provider, self.executor.authority_keys, self.executor.executor_key
        )
        result = executor.execute(
            self.permit, self.prop, self.signed, self.ev, self.decision.document, 11
        )
        observer = IndependentObserver(
            self.state, provider, self.observer.observer_key
        )
        observation = observer.reconcile(result["reservation"]["reservation_id"], self.prop, 12)
        self.assertEqual(observation["reconciliation"], "DIVERGENT_EFFECT")

    def test_revocation_before_dispatch_commit_blocks(self) -> None:
        def revoke() -> None:
            self.state.revoke_permit(self.permit["permit_id"], "operator stop", 11)

        with self.assertRaisesRegex(DurableStateError, "revoked"):
            self.executor.execute(
                self.permit,
                self.prop,
                self.signed,
                self.ev,
                self.decision.document,
                11,
                before_dispatch=revoke,
            )
        self.assertIsNone(self.provider.query(self.permit["permit_id"]))

    def test_revocation_after_dispatch_commit_is_in_flight_not_retroactive(self) -> None:
        reservation = self.state.reserve(self.permit, self.prop, 11)
        assert reservation is not None
        ticket = self.executor.claim_reservation_for_dispatch(
            reservation["reservation_id"], 11
        )
        event = self.state.revoke_permit(self.permit["permit_id"], "late revocation", 11)
        self.assertTrue(event["payload"]["in_flight_at_revocation"])
        response = self.provider.invoke(self.prop["action"], ticket)
        self.assertEqual(response["status"], "accepted")
        # The late revocation cannot be misreported as prevention; reconciliation is required.
        observation = self.observer.reconcile(reservation["reservation_id"], self.prop, 12)
        self.assertEqual(observation["reconciliation"], "CONFIRMED_SUCCESS")

    def test_freeze_before_dispatch_commit_blocks(self) -> None:
        def freeze() -> None:
            self.state.freeze("incident", 11)

        with self.assertRaisesRegex(DurableStateError, "frozen"):
            self.executor.execute(
                self.permit,
                self.prop,
                self.signed,
                self.ev,
                self.decision.document,
                11,
                before_dispatch=freeze,
            )

    def test_suspension_survives_restart(self) -> None:
        self.state.suspend_campaign("campaign-001", "risk budget", 11)
        reopened = DurableStateService(self.state_path)
        self.assertEqual(reopened.read_campaign("campaign-001").state.status, "SUSPENDED")
        with self.assertRaisesRegex(DurableStateError, "suspended"):
            reopened.reserve(self.permit, self.prop, 12)

    def test_terminal_outcome_cannot_be_rewritten(self) -> None:
        result = self.executor.execute(
            self.permit, self.prop, self.signed, self.ev, self.decision.document, 11
        )
        reservation_id = result["reservation"]["reservation_id"]
        self.observer.reconcile(reservation_id, self.prop, 12)
        unsigned = {
            "schema_version": "claimsieve.observer_receipt.v2",
            "reservation_id": reservation_id,
            "permit_id": self.permit["permit_id"],
            "campaign_id": self.permit["campaign_id"],
            "provider_record_digest": None,
            "observed_action_digest": None,
            "reconciliation": "CONFIRMED_FAILURE",
            "receipt_conflict": False,
            "observed_at_seq": 13,
            "observer_key_id": self.keys["observer"].key_id,
        }
        conflicting = {
            **unsigned,
            "signature": self.keys["observer"].sign("observer-receipt-v2", unsigned),
        }
        with self.assertRaisesRegex(DurableStateError, "cannot be rewritten"):
            self.state.record_observation(reservation_id, conflicting, 13)

    def test_unsigned_executor_command_is_rejected(self) -> None:
        reservation = self.state.reserve(self.permit, self.prop, 11)
        assert reservation is not None
        with self.assertRaisesRegex(DurableStateError, "signed executor command required"):
            self.state.begin_execution(reservation["reservation_id"], "attacker", 11)

    def test_forged_provider_attempt_receipt_is_rejected_by_state(self) -> None:
        reservation = self.state.reserve(self.permit, self.prop, 11)
        assert reservation is not None
        ticket = self.executor.claim_reservation_for_dispatch(
            reservation["reservation_id"], 11
        )
        forged = {
            "schema_version": "claimsieve.executor_receipt.v2",
            "trace_id": self.prop["trace_id"],
            "campaign_id": self.prop["campaign_id"],
            "permit_id": self.permit["permit_id"],
            "reservation_id": ticket.reservation_id,
            "action_digest": ticket.action_digest,
            "request_digest": ticket.request_digest,
            "idempotency_key": ticket.idempotency_key,
            "fencing_token": ticket.fencing_token,
            "containment_epoch": ticket.containment_epoch,
            "provider_status": "accepted",
            "provider_id": "provider:forged",
            "attempted_at_seq": 11,
            "executor_key_id": self.keys["executor"].key_id,
            "signature": "ed25519:forged",
        }
        with self.assertRaisesRegex(DurableStateError, "signature invalid"):
            self.state.persist_provider_attempt(
                ticket.reservation_id,
                {"status": "accepted", "provider_id": "provider:forged"},
                forged,
                11,
            )

    def test_unsigned_observer_outcome_is_rejected(self) -> None:
        result = self.executor.execute(
            self.permit, self.prop, self.signed, self.ev, self.decision.document, 11
        )
        reservation_id = result["reservation"]["reservation_id"]
        with self.assertRaisesRegex(DurableStateError, "trusted observer receipt key"):
            self.state.record_observation(
                reservation_id,
                {
                    "schema_version": "claimsieve.observer_receipt.v2",
                    "reservation_id": reservation_id,
                    "reconciliation": "CONFIRMED_SUCCESS",
                },
                12,
            )

    def test_expired_permit_cannot_be_reserved(self) -> None:
        with self.assertRaisesRegex(DurableStateError, "outside durable validity"):
            self.state.reserve(
                self.permit, self.prop, int(self.permit["expires_at_seq"]) + 1
            )

    def test_permit_expiring_after_reservation_cannot_dispatch(self) -> None:
        reserve_seq = int(self.permit["expires_at_seq"])
        reservation = self.state.reserve(self.permit, self.prop, reserve_seq)
        assert reservation is not None
        reservation_id = reservation["reservation_id"]
        self.state.begin_execution(
            reservation_id,
            self.executor.executor_id,
            reserve_seq,
            self.executor._signed_command("BEGIN_EXECUTION", reservation_id, reserve_seq),
        )
        dispatch_seq = reserve_seq + 1
        with self.assertRaisesRegex(DurableStateError, "expired before dispatch"):
            self.state.claim_dispatch(
                reservation_id,
                dispatch_seq,
                self.executor._signed_command("CLAIM_DISPATCH", reservation_id, dispatch_seq),
            )

    def test_provider_idempotent_replay_returns_original_result(self) -> None:
        reservation = self.state.reserve(self.permit, self.prop, 11)
        assert reservation is not None
        ticket = self.executor.claim_reservation_for_dispatch(
            reservation["reservation_id"], 11
        )
        first = self.provider.invoke(self.prop["action"], ticket)
        second = self.provider.invoke(self.prop["action"], ticket)
        self.assertEqual(first["status"], second["status"])
        self.assertTrue(second["idempotent_replay"])

    def test_idempotency_key_parameter_reuse_is_rejected(self) -> None:
        reservation = self.state.reserve(self.permit, self.prop, 11)
        assert reservation is not None
        ticket = self.executor.claim_reservation_for_dispatch(
            reservation["reservation_id"], 11
        )
        self.provider.invoke(self.prop["action"], ticket)
        changed = DispatchTicket(
            reservation_id=ticket.reservation_id,
            permit_id=ticket.permit_id,
            campaign_id=ticket.campaign_id,
            action_digest=ticket.action_digest,
            request_digest=digest({"different": True}),
            resource_key=ticket.resource_key,
            idempotency_key=ticket.idempotency_key,
            fencing_token=ticket.fencing_token + 1,
            containment_epoch=ticket.containment_epoch,
        )
        with self.assertRaisesRegex(DurableStateError, "different request"):
            self.provider.invoke(self.prop["action"], changed)

    def test_stale_fencing_token_is_rejected(self) -> None:
        resource_key = digest({"resource": "same"})
        newer = DispatchTicket(
            "r2", "p2", "c", "a2", "q2", resource_key, "id2", 20, 0
        )
        older = DispatchTicket(
            "r1", "p1", "c", "a1", "q1", resource_key, "id1", 10, 0
        )
        self.assertEqual(self.provider.invoke(self.prop["action"], newer)["status"], "accepted")
        self.assertEqual(self.provider.invoke(self.prop["action"], older)["status"], "stale_fence")


    def test_observer_does_not_trust_executor_receipt_for_outcome(self) -> None:
        result = self.executor.execute(
            self.permit, self.prop, self.signed, self.ev, self.decision.document, 11
        )
        reservation_id = result["reservation"]["reservation_id"]
        connection = sqlite3.connect(self.state_path)
        try:
            row = connection.execute(
                "SELECT provider_receipt_json FROM reservations WHERE reservation_id = ?",
                (reservation_id,),
            ).fetchone()
            assert row is not None
            import json
            receipt = json.loads(row[0])
            receipt["provider_status"] = "rejected"
            connection.execute(
                "UPDATE reservations SET provider_receipt_json = ? WHERE reservation_id = ?",
                (json.dumps(receipt, separators=(",", ":"), sort_keys=True), reservation_id),
            )
            connection.commit()
        finally:
            connection.close()
        observation = self.observer.reconcile(reservation_id, self.prop, 12)
        self.assertEqual(observation["reconciliation"], "CONFIRMED_SUCCESS")

    def test_signed_false_executor_failure_without_provider_record_stays_unknown(self) -> None:
        reservation = self.state.reserve(self.permit, self.prop, 11)
        assert reservation is not None
        ticket = self.executor.claim_reservation_for_dispatch(
            reservation["reservation_id"], 11
        )
        provider_result = {"status": "rejected", "provider_id": None}
        unsigned = {
            "schema_version": "claimsieve.executor_receipt.v2",
            "trace_id": self.prop["trace_id"],
            "campaign_id": self.prop["campaign_id"],
            "permit_id": self.permit["permit_id"],
            "reservation_id": ticket.reservation_id,
            "action_digest": action_digest(self.prop),
            "request_digest": ticket.request_digest,
            "idempotency_key": ticket.idempotency_key,
            "fencing_token": ticket.fencing_token,
            "containment_epoch": ticket.containment_epoch,
            "provider_status": "rejected",
            "provider_id": None,
            "attempted_at_seq": 11,
            "executor_key_id": self.keys["executor"].key_id,
        }
        receipt = {
            **unsigned,
            "signature": self.keys["executor"].sign("executor-receipt-v2", unsigned),
        }
        self.state.persist_provider_attempt(
            ticket.reservation_id, provider_result, receipt, 11
        )
        self.assertIsNone(self.provider.query(ticket.idempotency_key))
        observation = self.observer.reconcile(ticket.reservation_id, self.prop, 12)
        self.assertEqual(observation["reconciliation"], "OUTCOME_UNKNOWN")
        final = self.state.get_reservation(ticket.reservation_id)
        self.assertEqual(final["outcome"], "OUTCOME_UNKNOWN")

    def test_revocation_survives_restart(self) -> None:
        self.state.revoke_permit(self.permit["permit_id"], "operator stop", 11)
        reopened = DurableStateService(self.state_path)
        with self.assertRaisesRegex(DurableStateError, "revoked"):
            reopened.reserve(self.permit, self.prop, 12)

    def test_freeze_survives_restart(self) -> None:
        self.state.freeze("incident", 11)
        reopened = DurableStateService(self.state_path)
        self.assertTrue(reopened.containment_status()["frozen"])
        with self.assertRaisesRegex(DurableStateError, "frozen"):
            reopened.reserve(self.permit, self.prop, 12)

    def test_crash_after_dispatch_before_provider_stays_unknown(self) -> None:
        with self.assertRaises(InjectedCrash):
            self.executor.execute(
                self.permit,
                self.prop,
                self.signed,
                self.ev,
                self.decision.document,
                11,
                failpoint="after_dispatch_commit",
            )
        row = self.state.recovery_queue()[0]
        self.assertEqual(row["status"], "DISPATCHING")
        observation = self.observer.reconcile(row["reservation_id"], self.prop, 12)
        self.assertEqual(observation["reconciliation"], "OUTCOME_UNKNOWN")

    def test_fencing_tokens_are_monotonic(self) -> None:
        first = self.state.reserve(self.permit, self.prop, 11)
        assert first is not None
        # Issue another campaign with a separate ID and destination.
        ev = evidence(20)
        prop = proposal(ev, 20, campaign_id="campaign-002", proposal_id="proposal-002", trace_id="trace-002")
        current = self.state.read_campaign("campaign-002").state
        dec = evaluate(prop, self.pol, ev, current, 20)
        second_permit = _authority(self.state).issue(
            prop, self.signed, ev, dec.document, 20, nonce="33" * 24
        )
        second = self.state.reserve(second_permit, prop, 21)
        assert second is not None
        self.assertGreater(second["fencing_token"], first["fencing_token"])


class OutcomeSemanticsTest(unittest.TestCase):
    def test_provider_evidence_classification_vectors(self) -> None:
        exact = "sha256:exact"
        vectors = [
            (None, None, "OUTCOME_UNKNOWN", False),
            ("rejected", None, "CONFIRMED_FAILURE", False),
            ("accepted", exact, "CONFIRMED_SUCCESS", False),
            ("timeout_unknown", exact, "CONFIRMED_SUCCESS", False),
            ("accepted", "sha256:other", "DIVERGENT_EFFECT", False),
            ("rejected", exact, "OUTCOME_UNKNOWN", True),
            ("accepted", None, "OUTCOME_UNKNOWN", True),
            ("timeout_unknown", None, "OUTCOME_UNKNOWN", False),
        ]
        for status, observed, expected, conflict in vectors:
            with self.subTest(status=status, observed=observed):
                self.assertEqual(
                    classify_provider_evidence(status, observed, exact),
                    (expected, conflict),
                )


class QuorumSimulationTest(unittest.TestCase):
    def test_minority_partition_cannot_commit(self) -> None:
        cluster = QuorumStateMachineSimulator()
        self.assertTrue(cluster.elect("n1"))
        self.assertIsNotNone(cluster.commit("initial"))
        cluster.partition([{"n1"}, {"n2", "n3"}])
        self.assertIsNone(cluster.commit("minority-write"))

    def test_majority_failover_advances_term_and_fence(self) -> None:
        cluster = QuorumStateMachineSimulator()
        self.assertTrue(cluster.elect("n1"))
        first = cluster.commit("first")
        cluster.partition([{"n1"}, {"n2", "n3"}])
        self.assertTrue(cluster.elect("n2"))
        second = cluster.commit("second")
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        assert first is not None and second is not None
        self.assertGreater(second, first)
        cluster.heal()
        self.assertEqual(cluster.nodes["n1"].commit_index, 2)

    def test_stale_log_node_cannot_win_election(self) -> None:
        cluster = QuorumStateMachineSimulator()
        self.assertTrue(cluster.elect("n1"))
        cluster.partition([{"n1", "n2"}, {"n3"}])
        self.assertIsNotNone(cluster.commit("majority-commit"))
        cluster.heal()
        # Make n3 stale again and show that it cannot win against a visible newer node.
        cluster.nodes["n3"].commit_index = 0
        self.assertFalse(cluster.elect("n3"))

    def test_crashed_leader_requires_new_quorum_election(self) -> None:
        cluster = QuorumStateMachineSimulator()
        self.assertTrue(cluster.elect("n1"))
        cluster.crash("n1")
        self.assertIsNone(cluster.commit("no-leader"))
        self.assertTrue(cluster.elect("n2"))
        self.assertIsNotNone(cluster.commit("after-failover"))


if __name__ == "__main__":
    unittest.main()
