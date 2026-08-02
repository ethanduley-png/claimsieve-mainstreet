from __future__ import annotations

import copy
import json
import unittest

from claimsieve_ref.canonical import CanonicalizationError, digest
from claimsieve_ref.crypto import KeyPair
from claimsieve_ref.fixtures import trust_root
from claimsieve_ref.ledger import Ledger
from claimsieve_ref.verifier import verify_bundle, verify_json
from generate_bundle import build_bundle


class BundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bundle = build_bundle()
        self.root = trust_root()

    def verify(self, bundle=None, root=None):
        return verify_bundle(bundle or self.bundle, root or self.root)

    def test_valid_bundle_verifies_against_external_root(self) -> None:
        self.assertEqual(self.verify(), [])

    def test_external_trust_root_is_mandatory(self) -> None:
        self.assertEqual(verify_bundle(self.bundle), ["external trust root is required"])

    def test_attacker_self_asserted_keys_do_not_verify(self) -> None:
        rogue = KeyPair.from_seed("rogue-witness", b"R" * 32)
        changed = copy.deepcopy(self.bundle)
        statement = changed["witness_statement"]
        statement["witness_key_id"] = rogue.key_id
        unsigned = {k: v for k, v in statement.items() if k != "signature"}
        statement["signature"] = rogue.sign("witness-v1", unsigned)
        changed["embedded_keys"] = {rogue.key_id: rogue.public.encode()}
        errors = self.verify(changed)
        self.assertTrue(any("witness" in error for error in errors))

    def test_wrong_external_root_rejects_valid_bundle(self) -> None:
        changed_root = copy.deepcopy(self.root)
        changed_root["roles"]["witness_signers"] = [changed_root["roles"]["executor_signers"][0]]
        errors = self.verify(root=changed_root)
        self.assertTrue(any("witness" in error for error in errors))

    def test_policy_tampering_is_detected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["signed_policy"]["policy"]["version"] = 999
        errors = self.verify(changed)
        self.assertIn("signed policy signature invalid", errors)

    def test_evidence_tampering_is_detected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["evidence"][0]["content"]["consent"] = "forged"
        errors = self.verify(changed)
        self.assertTrue(any("evidence signature invalid" in error for error in errors))

    def test_evidence_reference_omission_is_detected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["proposal"]["evidence_refs"].pop()
        errors = self.verify(changed)
        self.assertIn("proposal evidence references do not exactly match the snapshot", errors)

    def test_tampered_approval_is_detected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["proposal"]["approval"]["expires_at_seq"] += 1
        errors = self.verify(changed)
        self.assertTrue(any("approval" in error for error in errors))

    def test_tampered_permit_is_detected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["permit"]["destination_digest"] = "sha256:" + "0" * 64
        errors = self.verify(changed)
        self.assertTrue(any("permit" in error for error in errors))

    def test_campaign_state_substitution_is_detected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["campaign_state"]["total_actions"] += 1
        errors = self.verify(changed)
        self.assertTrue(any("campaign-state" in error for error in errors))

    def test_ledger_payload_tampering_is_detected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["ledgers"]["execution"][0]["payload"]["reserved_at_seq"] += 1
        errors = self.verify(changed)
        self.assertTrue(any("execution ledger" in error for error in errors))

    def test_ledger_writer_outside_trust_root_is_rejected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["ledgers"]["proposal"][0]["writer_key_id"] = "attacker"
        errors = self.verify(changed)
        self.assertTrue(any("outside external trust root" in error for error in errors))

    def test_duplicate_reservation_is_detected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["ledgers"]["execution"].append(copy.deepcopy(changed["ledgers"]["execution"][0]))
        errors = self.verify(changed)
        self.assertTrue(any("duplicate permit reservation" in error for error in errors))

    def test_manifest_heads_mismatch_is_detected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["manifest"]["ledger_heads"]["execution"] = "sha256:" + "0" * 64
        errors = self.verify(changed)
        self.assertIn("manifest ledger heads mismatch", errors)

    def test_manifest_counts_mismatch_is_detected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["manifest"]["record_counts"]["execution"] += 1
        errors = self.verify(changed)
        self.assertIn("manifest record counts mismatch", errors)

    def test_witness_manifest_binding_is_detected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["manifest"]["record_counts"]["proposal"] += 1
        # Even if the internal manifest digest is recomputed, the external witness is stale.
        unsigned = {k: v for k, v in changed["manifest"].items() if k != "bundle_digest"}
        changed["manifest"]["bundle_digest"] = digest(unsigned)
        errors = self.verify(changed)
        self.assertIn("witness statement manifest binding mismatch", errors)

    def test_observer_receipt_must_bind_executor_receipt(self) -> None:
        changed = copy.deepcopy(self.bundle)
        observer = next(r for r in changed["receipts"] if r["schema_version"] == "claimsieve.observer_receipt.v1")
        observer["executor_receipt_digest"] = "sha256:" + "0" * 64
        errors = self.verify(changed)
        self.assertTrue(any("observer" in error for error in errors))

    def test_success_receipt_with_wrong_effect_is_rejected(self) -> None:
        changed = copy.deepcopy(self.bundle)
        observer = next(r for r in changed["receipts"] if r["schema_version"] == "claimsieve.observer_receipt.v1")
        observer["observed_action_digest"] = "sha256:" + "1" * 64
        errors = self.verify(changed)
        self.assertIn("successful observation does not match authorized action", errors)

    def test_duplicate_json_key_rejected_before_verification(self) -> None:
        text = '{"schema_version":"claimsieve.evidence_bundle.v2","schema_version":"other"}'
        with self.assertRaises(CanonicalizationError):
            verify_json(text, self.root)

    def test_float_rejected_before_verification(self) -> None:
        with self.assertRaises(CanonicalizationError):
            verify_json('{"schema_version":"claimsieve.evidence_bundle.v2","x":1.5}', self.root)

    def test_role_key_material_alias_in_root_is_rejected(self) -> None:
        changed_root = copy.deepcopy(self.root)
        authority_id = changed_root["roles"]["authority_signers"][0]
        executor_id = changed_root["roles"]["executor_signers"][0]
        changed_root["keys"][executor_id] = changed_root["keys"][authority_id]
        errors = self.verify(root=changed_root)
        self.assertIn("trust root reuses key material across key identifiers", errors)

    def test_unrelated_proposal_cannot_satisfy_ledger_inclusion(self) -> None:
        changed = copy.deepcopy(self.bundle)
        changed["ledgers"]["proposal"][0]["payload"]["proposal_id"] = "unrelated"
        errors = self.verify(changed)
        self.assertTrue(any("proposal is not recorded" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
