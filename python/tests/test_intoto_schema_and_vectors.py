import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from claimsieve_ref.intoto import (
    EXECUTION_PREDICATE_TYPE,
    OBSERVATION_PREDICATE_TYPE,
    PERMIT_PREDICATE_TYPE,
    InTotoVerificationError,
    executor_receipt_statement,
    observer_receipt_statement,
    permit_statement,
    verify_exported_statement,
)

ROOT = Path(__file__).resolve().parents[2]
VECTOR = ROOT / "vectors" / "in_toto_interop_v1.json"
SCHEMAS = {
    PERMIT_PREDICATE_TYPE: ROOT / "schemas" / "in-toto-authorization-permit-v0.1.schema.json",
    EXECUTION_PREDICATE_TYPE: ROOT / "schemas" / "in-toto-execution-attempt-v0.1.schema.json",
    OBSERVATION_PREDICATE_TYPE: ROOT / "schemas" / "in-toto-outcome-observation-v0.1.schema.json",
}


class InTotoSchemaAndVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.vector = json.loads(VECTOR.read_text(encoding="utf-8"))
        cls.schemas = {
            predicate_type: json.loads(path.read_text(encoding="utf-8"))
            for predicate_type, path in SCHEMAS.items()
        }
        for schema in cls.schemas.values():
            Draft202012Validator.check_schema(schema)

    def test_native_records_generate_exact_committed_vector(self):
        native = self.vector["native"]
        generated = {
            "permit": permit_statement(native["permit"]),
            "execution": executor_receipt_statement(native["executor_receipt"]),
            "observation": observer_receipt_statement(native["observer_receipt"]),
        }
        self.assertEqual(generated, self.vector["statements"])

    def test_every_vector_predicate_validates_against_closed_schema(self):
        for statement in self.vector["statements"].values():
            predicate_type = statement["predicateType"]
            Draft202012Validator(self.schemas[predicate_type]).validate(statement["predicate"])
            verify_exported_statement(statement)

    def test_unknown_predicate_version_fails_closed(self):
        statement = copy.deepcopy(self.vector["statements"]["permit"])
        statement["predicateType"] = "https://claimsieve.example/attestation/authorization-permit/v0.2"
        with self.assertRaises(InTotoVerificationError):
            verify_exported_statement(statement)

    def test_unknown_predicate_field_fails_closed(self):
        statement = copy.deepcopy(self.vector["statements"]["permit"])
        statement["predicate"]["authority_override"] = True
        with self.assertRaises(InTotoVerificationError):
            verify_exported_statement(statement)

    def test_non_subject_binding_digest_fails_closed_in_verifier(self):
        statement = copy.deepcopy(self.vector["statements"]["permit"])
        statement["predicate"]["destination_digest"] = "sha256:NOTHEX"
        with self.assertRaises(InTotoVerificationError):
            verify_exported_statement(statement)

    def test_invalid_provider_status_fails_closed(self):
        statement = copy.deepcopy(self.vector["statements"]["execution"])
        statement["predicate"]["provider_status"] = "success"
        with self.assertRaises(InTotoVerificationError):
            verify_exported_statement(statement)

    def test_subject_substitution_fails_closed(self):
        statement = copy.deepcopy(self.vector["statements"]["permit"])
        statement["subject"][1]["digest"]["sha256"] = "c" * 64
        with self.assertRaises(InTotoVerificationError):
            verify_exported_statement(statement)

    def test_native_record_subject_substitution_fails_closed(self):
        statement = copy.deepcopy(self.vector["statements"]["execution"])
        statement["subject"][0]["digest"]["sha256"] = "c" * 64
        with self.assertRaises(InTotoVerificationError):
            verify_exported_statement(statement)

    def test_signature_verification_confusion_fails_closed(self):
        statement = copy.deepcopy(self.vector["statements"]["observation"])
        statement["predicate"]["native_record"]["signature_verification"] = "VERIFIED"
        with self.assertRaises(InTotoVerificationError):
            verify_exported_statement(statement)

    def test_dsse_like_extra_fields_fail_closed(self):
        statement = copy.deepcopy(self.vector["statements"]["permit"])
        statement["signatures"] = []
        with self.assertRaises(InTotoVerificationError):
            verify_exported_statement(statement)

    def test_unknown_outcome_has_no_fabricated_action_subject(self):
        native = copy.deepcopy(self.vector["native"]["observer_receipt"])
        native["provider_record_digest"] = None
        native["observed_action_digest"] = None
        native["reconciliation"] = "OUTCOME_UNKNOWN"
        statement = observer_receipt_statement(native)
        self.assertEqual(len(statement["subject"]), 1)
        verify_exported_statement(statement)
        Draft202012Validator(self.schemas[OBSERVATION_PREDICATE_TYPE]).validate(statement["predicate"])


if __name__ == "__main__":
    unittest.main()
