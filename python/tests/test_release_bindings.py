"""Negative release regressions: recovery must not replace reserved authority."""
import copy
import unittest
import test_durable_state as fixtures
from claimsieve_ref.durable_state import DurableStateError

class ReleaseBindingTests(unittest.TestCase):
    setUp = fixtures.DurableStateTest.setUp
    tearDown = fixtures.DurableStateTest.tearDown

    def test_recovery_rejects_replacement_before_dispatch(self):
        row = self.state.reserve(self.permit, self.prop, 11)
        altered = copy.deepcopy(self.prop)
        altered['action']['parameters']['injected'] = 'replacement'
        with self.assertRaises(DurableStateError):
            self.executor.resume_reserved(row['reservation_id'], altered, 11)
        self.assertEqual(self.state.get_reservation(row['reservation_id'])['status'], 'RESERVED')
        self.assertIsNone(self.provider.query(row['idempotency_key']))

    def test_recovery_rejects_principal_substitution(self):
        row = self.state.reserve(self.permit, self.prop, 11)
        altered = copy.deepcopy(self.prop)
        altered['principal'] = 'attacker'
        with self.assertRaises(DurableStateError):
            self.executor.resume_reserved(row['reservation_id'], altered, 11)
        self.assertEqual(self.state.get_reservation(row['reservation_id'])['status'], 'RESERVED')

    def test_observer_rejects_replacement(self):
        result = self.executor.execute(self.permit, self.prop, self.signed, self.ev, self.decision.document, 11)
        altered = copy.deepcopy(self.prop)
        altered['action']['parameters']['injected'] = 'replacement'
        with self.assertRaises(DurableStateError):
            self.observer.reconcile(result['reservation']['reservation_id'], altered, 12)

    def test_reservation_rejects_principal_substitution(self):
        altered = copy.deepcopy(self.prop)
        altered['principal'] = 'attacker'
        with self.assertRaises(DurableStateError):
            self.state.reserve(self.permit, altered, 11)

    def test_observer_rejects_wrong_request_correlation(self):
        result = self.executor.execute(self.permit, self.prop, self.signed, self.ev, self.decision.document, 11)
        original = self.provider.query
        def substituted(key):
            record = original(key)
            record['request_digest'] = 'sha256:' + '0' * 64
            return record
        self.provider.query = substituted
        observed = self.observer.reconcile(result['reservation']['reservation_id'], self.prop, 12)
        self.assertEqual(observed['reconciliation'], 'OUTCOME_UNKNOWN')
        self.assertTrue(observed['receipt_conflict'])

    def test_production_rejects_fixture_composition(self):
        from unittest.mock import patch
        from founder_os import FounderOSReferenceWorkflow
        with patch.dict('os.environ', {'CLAIMSIEVE_MODE': 'production'}):
            with self.assertRaises(ValueError):
                FounderOSReferenceWorkflow(self.temp.name, {'example/repo'})

    def test_recovery_rejects_approval_and_trace_substitution(self):
        row = self.state.reserve(self.permit, self.prop, 11)
        for field, value in [('approval', None), ('trace_id', 'replacement')]:
            with self.subTest(field=field):
                altered = copy.deepcopy(self.prop)
                altered[field] = value
                with self.assertRaises(DurableStateError):
                    self.executor.resume_reserved(row['reservation_id'], altered, 11)
                self.assertEqual(self.state.get_reservation(row['reservation_id'])['status'], 'RESERVED')

    def test_snapshot_survives_reopen_and_backup(self):
        import sqlite3
        from pathlib import Path
        from claimsieve_ref.durable_state import DurableStateService
        row = self.state.reserve(self.permit, self.prop, 11)
        backup = Path(self.temp.name) / 'backup.sqlite3'
        with sqlite3.connect(self.state_path) as source, sqlite3.connect(backup) as target:
            source.backup(target)
        restored = DurableStateService(backup)
        self.assertEqual(restored.reserved_proposal(row['reservation_id'], self.prop), self.prop)
        self.assertIsNone(restored.reserve(self.permit, self.prop, 11))
        self.assertTrue(restored.verify_journal())

    def test_snapshot_cannot_be_updated(self):
        import sqlite3
        self.state.reserve(self.permit, self.prop, 11)
        with sqlite3.connect(self.state_path) as connection:
            with self.assertRaises(sqlite3.IntegrityError):
                connection.execute("UPDATE reservation_proposals SET proposal_json = '{}'")

    def test_legacy_reservation_cannot_acquire_snapshot_from_caller(self):
        import sqlite3
        from claimsieve_ref.durable_state import DurableStateService
        row = self.state.reserve(self.permit, self.prop, 11)
        with sqlite3.connect(self.state_path) as connection:
            connection.execute('DROP TABLE reservation_proposals')
            connection.execute('PRAGMA user_version = 0')
        reopened = DurableStateService(self.state_path)
        self.assertEqual(reopened.get_reservation(row['reservation_id'])['status'], 'RESERVED')
        with self.assertRaises(DurableStateError):
            reopened.reserved_proposal(row['reservation_id'], self.prop)

    def test_future_schema_rejected(self):
        import sqlite3
        from claimsieve_ref.durable_state import DurableStateService
        with sqlite3.connect(self.state_path) as connection:
            connection.execute('PRAGMA user_version = 999')
        with self.assertRaises(DurableStateError):
            DurableStateService(self.state_path)

    def test_stale_observer_sequence_rejected(self):
        result = self.executor.execute(self.permit, self.prop, self.signed, self.ev, self.decision.document, 11)
        with self.assertRaises(DurableStateError):
            self.observer.reconcile(result['reservation']['reservation_id'], self.prop, 10)

    def test_durable_success_requires_exact_observed_effect(self):
        from claimsieve_ref.canonical import digest
        result = self.executor.execute(self.permit, self.prop, self.signed, self.ev, self.decision.document, 11)
        rid = result['reservation']['reservation_id']
        unsigned = dict(schema_version='claimsieve.observer_receipt.v2', reservation_id=rid,
            permit_id=self.permit['permit_id'], campaign_id=self.permit['campaign_id'],
            provider_record_digest=digest({}), observed_action_digest=digest({'wrong': 'effect'}),
            reconciliation='CONFIRMED_SUCCESS', receipt_conflict=False, observed_at_seq=12,
            observer_key_id=self.keys['observer'].key_id)
        receipt = {**unsigned, 'signature': self.keys['observer'].sign('observer-receipt-v2', unsigned)}
        with self.assertRaises(DurableStateError):
            self.state.record_observation(rid, receipt, 12)

    def test_caller_mutation_after_reservation_cannot_change_dispatched_payload(self):
        expected = copy.deepcopy(self.prop['action'])
        def mutate():
            self.prop['action']['parameters']['injected'] = 'after verification'
        result = self.executor.execute(self.permit, self.prop, self.signed, self.ev,
            self.decision.document, 11, before_dispatch=mutate)
        record = self.provider.query(result['reservation']['idempotency_key'])
        self.assertEqual(record['effect'], expected)
