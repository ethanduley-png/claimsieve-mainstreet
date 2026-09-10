from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
MAP_PATH = ROOT / "vectors" / "authority_compression_conformance_v1.json"


class AuthorityCompressionConformanceMapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mapping = json.loads(MAP_PATH.read_text(encoding="utf-8"))

    def test_sources_and_schema_exist(self) -> None:
        self.assertEqual(
            self.mapping["schema_version"],
            "claimsieve.authority_compression_conformance.v1",
        )
        for key in (
            "formal_source",
            "necessity_source",
            "authenticity_source",
            "production_source",
            "shadow_candidate_source",
            "permit_schema",
        ):
            self.assertTrue((ROOT / self.mapping[key]).is_file(), key)

    def test_every_guard_has_formal_reference_and_shadow_anchor(self) -> None:
        formal_paths = [
            ROOT / self.mapping["formal_source"],
            ROOT / self.mapping["necessity_source"],
            ROOT / self.mapping["authenticity_source"],
        ]
        formal_text = "\n".join(path.read_text(encoding="utf-8") for path in formal_paths)
        production_text = (ROOT / self.mapping["production_source"]).read_text(encoding="utf-8")
        shadow_text = (ROOT / self.mapping["shadow_candidate_source"]).read_text(encoding="utf-8")

        names: set[str] = set()
        for guard in self.mapping["guards"]:
            name = guard["name"]
            self.assertNotIn(name, names)
            names.add(name)
            self.assertTrue(guard["formal_tokens"], name)
            self.assertTrue(guard["production_tokens"], name)
            self.assertTrue(guard["shadow_tokens"], name)
            for token in guard["formal_tokens"]:
                self.assertIn(token, formal_text, f"formal guard drift: {name}: {token}")
            for token in guard["production_tokens"]:
                self.assertIn(token, production_text, f"reference guard drift: {name}: {token}")
            for token in guard["shadow_tokens"]:
                self.assertIn(token, shadow_text, f"shadow guard drift: {name}: {token}")

        self.assertEqual(
            names,
            {
                "authenticity",
                "historical_authority",
                "revocation",
                "consumption",
                "action_binding",
                "policy_binding",
                "identity_binding",
                "not_before",
                "expiry",
            },
        )

    def test_audit_link_anchors_exist(self) -> None:
        formal_paths = [
            ROOT / self.mapping["formal_source"],
            ROOT / self.mapping["necessity_source"],
        ]
        formal_text = "\n".join(path.read_text(encoding="utf-8") for path in formal_paths)
        production_text = (ROOT / self.mapping["production_source"]).read_text(encoding="utf-8")
        shadow_text = (ROOT / self.mapping["shadow_candidate_source"]).read_text(encoding="utf-8")
        for link in self.mapping["audit_links"]:
            for token in link["formal_tokens"]:
                self.assertIn(token, formal_text, f"formal audit-link drift: {link['name']}: {token}")
            for token in link["production_tokens"]:
                self.assertIn(token, production_text, f"reference audit-link drift: {link['name']}: {token}")
            for token in link["shadow_tokens"]:
                self.assertIn(token, shadow_text, f"shadow audit-link drift: {link['name']}: {token}")

    def test_reference_fast_path_gaps_remain_explicit_until_resolved(self) -> None:
        production_text = (ROOT / self.mapping["production_source"]).read_text(encoding="utf-8")
        gaps = {gap["id"]: gap for gap in self.mapping["known_gaps"]}
        expected = {
            "FULL_EVIDENCE_ON_REFERENCE_EXECUTION_PATH",
            "FULL_POLICY_AND_DECISION_ON_REFERENCE_EXECUTION_PATH",
            "SHADOW_CONSUMPTION_IS_NOT_ATOMIC",
            "SHADOW_PATH_NOT_YET_EQUIVALENCE_TESTED_AGAINST_REFERENCE",
        }
        self.assertEqual(set(gaps), expected)
        for gap_id in (
            "FULL_EVIDENCE_ON_REFERENCE_EXECUTION_PATH",
            "FULL_POLICY_AND_DECISION_ON_REFERENCE_EXECUTION_PATH",
        ):
            gap = gaps[gap_id]
            self.assertEqual(gap["status"], "open")
            for token in gap["production_tokens"]:
                self.assertIn(token, production_text, f"known reference gap changed without map update: {gap_id}: {token}")

    def test_shadow_gaps_remain_explicit_until_resolved(self) -> None:
        shadow_text = (ROOT / self.mapping["shadow_candidate_source"]).read_text(encoding="utf-8")
        gaps = {gap["id"]: gap for gap in self.mapping["known_gaps"]}
        for gap_id in (
            "SHADOW_CONSUMPTION_IS_NOT_ATOMIC",
            "SHADOW_PATH_NOT_YET_EQUIVALENCE_TESTED_AGAINST_REFERENCE",
        ):
            gap = gaps[gap_id]
            self.assertEqual(gap["status"], "open")
            for token in gap["shadow_tokens"]:
                self.assertIn(token, shadow_text, f"known shadow gap changed without map update: {gap_id}: {token}")

    def test_shadow_interface_excludes_full_authority_inputs(self) -> None:
        shadow_text = (ROOT / self.mapping["shadow_candidate_source"]).read_text(encoding="utf-8")
        start = shadow_text.index("pub fn verify_shadow_compact_preflight(")
        signature_end = shadow_text.index(") -> Result<ShadowCompactAdmission", start)
        signature = shadow_text[start:signature_end]
        body_end = shadow_text.index("\n}\n\n#[cfg(test)]", signature_end)
        body = shadow_text[signature_end:body_end]

        for forbidden in ("Policy", "Evidence", "Decision"):
            self.assertNotIn(forbidden, signature)
        self.assertNotIn("evaluate(", body)
        self.assertNotIn("evidence_root(", body)
        self.assertIn("verify_permit_signature(permit, authority_key)", body)
        self.assertIn("current.effective_policy_digest", body)
        self.assertIn("current.permit_revoked", body)
        self.assertIn("current.permit_consumed", body)

    def test_permit_schema_carries_reconstruction_commitments(self) -> None:
        permit_schema = json.loads((ROOT / self.mapping["permit_schema"]).read_text(encoding="utf-8"))
        required = set(permit_schema["required"])
        self.assertTrue(
            {
                "action_digest",
                "destination_digest",
                "parameter_digest",
                "policy_digest",
                "signed_policy_digest",
                "evidence_root",
                "decision_digest",
                "approval_digest",
                "valid_from_seq",
                "expires_at_seq",
                "max_uses",
                "nonce",
                "authority_key_id",
                "signature",
            }.issubset(required)
        )


if __name__ == "__main__":
    unittest.main()
