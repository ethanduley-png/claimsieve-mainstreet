import copy
import unittest

from claimsieve_ref.canonical import digest
from claimsieve_ref.intoto import (
    EXECUTION_PREDICATE_TYPE,
    OBSERVATION_PREDICATE_TYPE,
    PERMIT_PREDICATE_TYPE,
    STATEMENT_TYPE,
    InTotoExportError,
    executor_receipt_statement,
    observer_receipt_statement,
    permit_statement,
)

D = "sha256:" + "a" * 64
D2 = "sha256:" + "b" * 64


def permit():
    return {
        "schema_version": "claimsieve.permit.v1",
        "permit_id": "p1",
        "trace_id": "t1",
        "tenant_id": "tenant",
        "campaign_id": "c1",
        "principal": "spiffe://example/principal",
        "proposal_digest": D,
        "action_digest": D2,
        "destination_digest": D,
        "parameter_digest": D2,
        "policy_digest": D,
        "signed_policy_digest": D2,
        "prior_campaign_state_digest": D,
        "campaign_state_digest": D2,
        "evidence_root": D,
        "decision_digest": D2,
        "approval_digest": None,
        "valid_from_seq": 10,
        "expires_at_seq": 20,
        "max_uses": 1,
        "nonce": "ab" * 16,
        "authority_key_id": "authority-1",
        "signature": "ed25519:abc",
    }


def executor_receipt():
    return {
        "schema_version": "claimsieve.executor_receipt.v2",
        "trace_id": "t1",
        "campaign_id": "c1",
        "permit_id": "p1",
        "reservation_id": "r1",
        "action_digest": D2,
        "request_digest": D,
        "idempotency_key": "idem-1",
        "fencing_token": 3,
        "containment_epoch": 1,
        "provider_status": "accepted",
        "provider_id": "provider-1",
        "attempted_at_seq": 12,
        "executor_key_id": "executor-1",
        "signature": "ed25519:def",
    }


def observer_receipt(observed=D2):
    return {
        "schema_version": "claimsieve.observer_receipt.v2",
        "reservation_id": "r1",
        "permit_id": "p1",
        "campaign_id": "c1",
        "provider_record_digest": D,
        "observed_action_digest": observed,
        "reconciliation": "CONFIRMED_SUCCESS",
        "receipt_conflict": False,
        "observed_at_seq": 13,
        "observer_key_id": "observer-1",
        "signature": "ed25519:ghi",
    }


class InTotoExportTests(unittest.TestCase):
    def test_permit_statement_preserves_native_authority_bindings(self):
        native = permit()
        statement = permit_statement(native)
        self.assertEqual(statement["_type"], STATEMENT_TYPE)
        self.assertEqual(statement["predicateType"], PERMIT_PREDICATE_TYPE)
        self.assertEqual(statement["subject"][1]["digest"]["sha256"], "b" * 64)
        self.assertEqual(statement["predicate"]["destination_digest"], D)
        self.assertEqual(statement["predicate"]["parameter_digest"], D2)
        self.assertEqual(statement["predicate"]["native_record"]["digest"], digest(native))
        self.assertEqual(
            statement["predicate"]["native_record"]["signature_format"],
            "claimsieve-native",
        )

    def test_statement_is_payload_only_not_a_dsse_envelope(self):
        statement = permit_statement(permit())
        self.assertNotIn("payload", statement)
        self.assertNotIn("payloadType", statement)
        self.assertNotIn("signatures", statement)

    def test_export_does_not_mutate_native_record(self):
        native = permit()
        before = copy.deepcopy(native)
        permit_statement(native)
        self.assertEqual(native, before)

    def test_executor_statement_keeps_fencing_and_idempotency(self):
        statement = executor_receipt_statement(executor_receipt())
        self.assertEqual(statement["predicateType"], EXECUTION_PREDICATE_TYPE)
        self.assertEqual(statement["predicate"]["fencing_token"], 3)
        self.assertEqual(statement["predicate"]["idempotency_key"], "idem-1")
        self.assertEqual(statement["predicate"]["containment_epoch"], 1)

    def test_observer_unknown_action_still_has_native_receipt_subject(self):
        native = observer_receipt(None)
        native["provider_record_digest"] = None
        native["reconciliation"] = "OUTCOME_UNKNOWN"
        statement = observer_receipt_statement(native)
        self.assertEqual(statement["predicateType"], OBSERVATION_PREDICATE_TYPE)
        self.assertEqual(len(statement["subject"]), 1)
        self.assertEqual(statement["predicate"]["observed_action_digest"], None)

    def test_invalid_digest_fails_closed(self):
        native = permit()
        native["action_digest"] = "sha256:NOTHEX"
        with self.assertRaises(InTotoExportError):
            permit_statement(native)

    def test_missing_native_signature_fails_closed(self):
        native = permit()
        del native["signature"]
        with self.assertRaises(InTotoExportError):
            permit_statement(native)


if __name__ == "__main__":
    unittest.main()
