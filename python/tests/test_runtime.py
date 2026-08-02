from __future__ import annotations

import copy
import threading
import unittest

from claimsieve_ref.canonical import digest
from claimsieve_ref.crypto import KeyPair, PublicKey
from claimsieve_ref.fixtures import evidence, keypairs, policy, proposal, signed_policy
from claimsieve_ref.kernel import CampaignState, evaluate
from claimsieve_ref.model import approval_signing_subject
from claimsieve_ref.runtime import (
    Authority,
    CampaignStateStore,
    ContainmentController,
    Executor,
    Observer,
    PermitError,
    ReservationStore,
    SimulatedConnector,
    SimulatedExternalSystem,
)
from claimsieve_ref.trust import sign_evidence, sign_policy


class RuntimeFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.keys = keypairs()
        self.ev = evidence(10)
        self.signed_pol = signed_policy()
        self.pol = self.signed_pol["policy"]
        self.prop = proposal(self.ev, 10, approve=True)
        self.states = CampaignStateStore()
        self.prior = self.states.read("campaign-001")
        self.decision = evaluate(self.prop, self.pol, self.ev, self.prior, 10)
        self.authority = self.make_authority(self.states)

    def make_authority(self, states: CampaignStateStore) -> Authority:
        return Authority(
            self.keys["authority"],
            {self.keys["approver"].key_id: self.keys["approver"].public},
            {self.keys["policy_authority"].key_id: self.keys["policy_authority"].public},
            {
                self.keys[name].key_id: self.keys[name].public
                for name in ("crm_evidence", "registry_evidence", "deployment_evidence", "epoch_evidence")
            },
            states,
        )

    def issue(self, nonce: str = "11" * 24) -> dict:
        return self.authority.issue(
            self.prop, self.signed_pol, self.ev, self.decision.document, 10, nonce=nonce
        )

    def execution_components(self, mode: str = "success"):
        system = SimulatedExternalSystem(mode)
        containment = ContainmentController(self.keys["containment"])
        executor = Executor(
            {self.keys["authority"].key_id: self.keys["authority"].public},
            self.keys["executor"],
            ReservationStore(),
            containment.view(),
            SimulatedConnector(system),
        )
        observer = Observer(
            self.keys["observer"],
            {self.keys["executor"].key_id: self.keys["executor"].public},
            system,
        )
        return system, containment, executor, observer

    def test_successful_exact_execution(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        _, containment, executor, observer = self.execution_components()
        execution = executor.execute(
            permit, self.prop, self.signed_pol, self.ev, self.decision.document, state, 11
        )
        observation = observer.observe(permit, self.prop, execution["executor_receipt"], 12)
        self.assertEqual(observation["reconciliation"], "CONFIRMED_SUCCESS")
        self.assertFalse(execution["automatic_retry_allowed"])
        self.assertIsNone(containment.apply_observation(
            observation, {self.keys["observer"].key_id: self.keys["observer"].public}, 12
        ))

    def test_unsigned_policy_is_rejected(self) -> None:
        with self.assertRaisesRegex(PermitError, "signed policy"):
            self.authority.issue(self.prop, self.pol, self.ev, self.decision.document, 10)

    def test_policy_signed_by_untrusted_key_is_rejected(self) -> None:
        rogue = KeyPair.from_seed("rogue-policy", b"R" * 32)
        changed = copy.deepcopy(self.pol)
        changed["allowed_action_kinds"].append("delete_record")
        envelope = sign_policy(changed, rogue)
        result = evaluate(self.prop, changed, self.ev, self.prior, 10)
        with self.assertRaisesRegex(PermitError, "policy signer is not trusted"):
            self.authority.issue(self.prop, envelope, self.ev, result.document, 10)

    def test_policy_substitution_with_old_signature_is_rejected(self) -> None:
        changed = copy.deepcopy(self.signed_pol)
        changed["policy"]["version"] = 999
        with self.assertRaisesRegex(PermitError, "signature invalid"):
            self.authority.issue(self.prop, changed, self.ev, self.decision.document, 10)

    def test_unsigned_evidence_is_rejected(self) -> None:
        changed = copy.deepcopy(self.ev)
        changed[0].pop("signature")
        changed_prop = proposal(changed, 10, approve=True)
        result = evaluate(changed_prop, self.pol, changed, self.prior, 10)
        with self.assertRaisesRegex(PermitError, "evidence signature invalid"):
            self.authority.issue(changed_prop, self.signed_pol, changed, result.document, 10)

    def test_evidence_signed_by_wrong_role_is_rejected(self) -> None:
        changed = copy.deepcopy(self.ev)
        unsigned = {k: v for k, v in changed[0].items() if k not in {"signature", "issuer_key_id"}}
        changed[0] = sign_evidence(unsigned, self.keys["registry_evidence"])
        changed_prop = proposal(changed, 10, approve=True)
        result = evaluate(changed_prop, self.pol, changed, self.prior, 10)
        with self.assertRaisesRegex(PermitError, "not trusted for customer_contact_authority"):
            self.authority.issue(changed_prop, self.signed_pol, changed, result.document, 10)

    def test_strict_sequence_reuse_is_denied(self) -> None:
        state = CampaignState("campaign-001", last_sequence=10)
        result = evaluate(self.prop, self.pol, self.ev, state, 10)
        self.assertEqual(result.document["verdict"], "DENY")
        self.assertIn("NON_SUCCESSOR_SEQUENCE", result.document["reason_codes"])

    def test_campaign_fork_has_exactly_one_successor(self) -> None:
        winners = []
        barrier = threading.Barrier(2)

        prop_a = copy.deepcopy(self.prop)
        prop_b = copy.deepcopy(self.prop)
        prop_b["proposal_id"] = "proposal-fork-b"
        prop_b["trace_id"] = "trace-fork-b"
        prop_b["approval"] = None
        prop_b = proposal(self.ev, 10, approve=True, proposal_id="proposal-fork-b", trace_id="trace-fork-b")
        decision_a = evaluate(prop_a, self.pol, self.ev, self.prior, 10)
        decision_b = evaluate(prop_b, self.pol, self.ev, self.prior, 10)

        def worker(prop, decision, nonce):
            barrier.wait()
            try:
                permit = self.authority.issue(prop, self.signed_pol, self.ev, decision.document, 10, nonce=nonce)
                winners.append(permit["permit_id"])
            except PermitError:
                pass

        threads = [
            threading.Thread(target=worker, args=(prop_a, decision_a, "aa" * 24)),
            threading.Thread(target=worker, args=(prop_b, decision_b, "bb" * 24)),
        ]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(len(winners), 1)
        self.assertEqual(self.states.read("campaign-001").total_actions, 1)

    def test_durable_state_prevents_action_budget_reset(self) -> None:
        tight = signed_policy(campaign_limits={**policy()["campaign_limits"], "max_actions": 1})
        pol = tight["policy"]
        first = evaluate(self.prop, pol, self.ev, self.prior, 10)
        authority = self.make_authority(self.states)
        authority.issue(self.prop, tight, self.ev, first.document, 10, nonce="01" * 24)
        second_prop = proposal(
            self.ev, 11, approve=True, proposal_id="proposal-2", trace_id="trace-2", session_id="session-2"
        )
        current = self.states.read("campaign-001")
        second = evaluate(second_prop, pol, self.ev, current, 11)
        self.assertEqual(second.document["verdict"], "SUSPEND_CAMPAIGN")
        with self.assertRaisesRegex(PermitError, "only an ALLOW"):
            authority.issue(second_prop, tight, self.ev, second.document, 11)

    def test_fabricated_allow_is_rejected(self) -> None:
        denied_prop = proposal(self.ev, 10, approve=True, risk_tags=["PURPOSE_MISMATCH"])
        denied = evaluate(denied_prop, self.pol, self.ev, self.prior, 10)
        forged = copy.deepcopy(denied.document)
        forged["verdict"] = "ALLOW"
        with self.assertRaisesRegex(PermitError, "independent kernel"):
            self.authority.issue(denied_prop, self.signed_pol, self.ev, forged, 10)

    def test_stale_human_approval_rejected(self) -> None:
        changed = copy.deepcopy(self.prop)
        changed["approval"]["expires_at_seq"] = 9
        changed["approval"]["signature"] = self.keys["approver"].sign(
            "approval-v1", approval_signing_subject(changed["approval"])
        )
        with self.assertRaisesRegex(PermitError, "stale"):
            self.authority.issue(changed, self.signed_pol, self.ev, self.decision.document, 10)

    def test_permit_replay_is_blocked(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        _, _, executor, _ = self.execution_components()
        executor.execute(permit, self.prop, self.signed_pol, self.ev, self.decision.document, state, 11)
        with self.assertRaisesRegex(PermitError, "replay"):
            executor.execute(permit, self.prop, self.signed_pol, self.ev, self.decision.document, state, 11)

    def test_concurrent_permit_replay_has_one_winner(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        _, _, executor, _ = self.execution_components()
        winners = 0
        lock = threading.Lock()
        def worker():
            nonlocal winners
            try:
                executor.execute(permit, self.prop, self.signed_pol, self.ev, self.decision.document, state, 11)
                with lock: winners += 1
            except PermitError:
                pass
        threads = [threading.Thread(target=worker) for _ in range(64)]
        for thread in threads: thread.start()
        for thread in threads: thread.join()
        self.assertEqual(winners, 1)

    def test_revoked_permit_blocked(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        _, containment, executor, _ = self.execution_components()
        containment.revoke(permit["permit_id"], "operator", 11)
        with self.assertRaisesRegex(PermitError, "revoked"):
            executor.execute(permit, self.prop, self.signed_pol, self.ev, self.decision.document, state, 11)

    def test_revocation_after_reservation_blocks_dispatch(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        system = SimulatedExternalSystem("success")
        containment = ContainmentController(self.keys["containment"])
        class RevokingStore(ReservationStore):
            def reserve(inner, permit_id, action_digest_value, seq):
                value = super(RevokingStore, inner).reserve(permit_id, action_digest_value, seq)
                containment.revoke(permit_id, "race", seq)
                return value
        connector = SimulatedConnector(system)
        executor = Executor(
            {self.keys["authority"].key_id: self.keys["authority"].public},
            self.keys["executor"], RevokingStore(), containment.view(), connector,
        )
        with self.assertRaisesRegex(PermitError, "revoked"):
            executor.execute(permit, self.prop, self.signed_pol, self.ev, self.decision.document, state, 11)
        self.assertEqual(connector.calls, [])

    def test_executor_cannot_sign_observer_receipt(self) -> None:
        _, _, executor, _ = self.execution_components()
        self.assertFalse(hasattr(executor, "observer_key"))
        self.assertFalse(hasattr(executor.containment, "key"))

    def test_observer_rejects_forged_executor_receipt(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        _, _, executor, observer = self.execution_components()
        execution = executor.execute(permit, self.prop, self.signed_pol, self.ev, self.decision.document, state, 11)
        execution["executor_receipt"]["provider_status"] = "rejected"
        with self.assertRaisesRegex(PermitError, "signature invalid"):
            observer.observe(permit, self.prop, execution["executor_receipt"], 12)

    def test_unknown_outcome_never_allows_automatic_retry(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        _, _, executor, observer = self.execution_components("ambiguous")
        execution = executor.execute(permit, self.prop, self.signed_pol, self.ev, self.decision.document, state, 11)
        observation = observer.observe(permit, self.prop, execution["executor_receipt"], 12)
        self.assertEqual(observation["reconciliation"], "OUTCOME_UNKNOWN")
        self.assertFalse(execution["automatic_retry_allowed"])

    def test_confirmed_failure_still_requires_new_authorization(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        _, _, executor, observer = self.execution_components("failure")
        execution = executor.execute(permit, self.prop, self.signed_pol, self.ev, self.decision.document, state, 11)
        observation = observer.observe(permit, self.prop, execution["executor_receipt"], 12)
        self.assertEqual(observation["reconciliation"], "CONFIRMED_FAILURE")
        self.assertFalse(execution["automatic_retry_allowed"])

    def test_divergent_effect_is_independently_observed_and_suspends(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        _, containment, executor, observer = self.execution_components("divergent")
        execution = executor.execute(permit, self.prop, self.signed_pol, self.ev, self.decision.document, state, 11)
        observation = observer.observe(permit, self.prop, execution["executor_receipt"], 12)
        self.assertEqual(observation["reconciliation"], "DIVERGENT_EFFECT")
        receipt = containment.apply_observation(
            observation, {self.keys["observer"].key_id: self.keys["observer"].public}, 12
        )
        self.assertIsNotNone(receipt)
        self.assertIn("campaign-001", containment.suspended_campaigns)

    def test_destination_mutation_after_permit_is_blocked(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        _, _, executor, _ = self.execution_components()
        changed = copy.deepcopy(self.prop)
        changed["action"]["destination"]["authority"] = "+15550000000"
        with self.assertRaisesRegex(PermitError, "proposal_digest|action_digest|destination_digest"):
            executor.execute(permit, changed, self.signed_pol, self.ev, self.decision.document, state, 11)

    def test_policy_mutation_after_permit_is_blocked(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        _, _, executor, _ = self.execution_components()
        changed = copy.deepcopy(self.signed_pol)
        changed["policy"]["version"] = 99
        with self.assertRaisesRegex(PermitError, "policy_digest|signed_policy_digest"):
            executor.execute(permit, self.prop, changed, self.ev, self.decision.document, state, 11)

    def test_campaign_state_mutation_after_permit_is_blocked(self) -> None:
        permit = self.issue()
        state = self.states.read("campaign-001")
        state.total_actions += 1
        _, _, executor, _ = self.execution_components()
        with self.assertRaisesRegex(PermitError, "campaign_state_digest"):
            executor.execute(permit, self.prop, self.signed_pol, self.ev, self.decision.document, state, 11)

    def test_key_material_alias_is_rejected(self) -> None:
        alias = PublicKey("authority-alias", self.keys["executor"].public.raw)
        with self.assertRaisesRegex(PermitError, "material"):
            Executor(
                {alias.key_id: alias}, self.keys["executor"], ReservationStore(),
                ContainmentController(self.keys["containment"]).view(),
                SimulatedConnector.with_mode("success"),
            )

    def test_permit_identity_includes_nonce(self) -> None:
        first = self.issue("11" * 24)
        # Reconstruct same inputs in a separate isolated campaign store.
        states = CampaignStateStore()
        authority = self.make_authority(states)
        prior = states.read("campaign-001")
        decision = evaluate(self.prop, self.pol, self.ev, prior, 10)
        second = authority.issue(self.prop, self.signed_pol, self.ev, decision.document, 10, nonce="22" * 24)
        self.assertNotEqual(first["permit_id"], second["permit_id"])


if __name__ == "__main__":
    unittest.main()
