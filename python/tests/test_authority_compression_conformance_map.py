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
            "permit_schema",
        ):
            self.assertTrue((ROOT / self.mapping[key]).is_file(), key)

    def test_every_guard_has_formal_and_production_anchor(self) -> None:
        formal_paths = [
            ROOT / self.mapping["formal_source"],
            ROOT / self.mapping["necessity_source"],
            ROOT / self.mapping["authenticity_source"],
        ]
        formal_text = "\n".join(path.read_text(encoding="utf-8") for path in formal_paths)
        production_text = (ROOT / self.mapping["production_source"]).read_text(encoding="utf-8")

        names: set[str] = set()
        for guard in self.mapping["guards"]:
            name = guard["name"]
            self.assertNotIn(name, names)
            names.add(name)
            self.assertTrue(guard["formal_tokens"], name)
            self.assertTrue(guard["production_tokens"], name)
            for token in guard["formal_tokens"]:
                self.assertIn(token, formal_text, f"formal guard drift: {name}: {token}")
            for token in guard["production_tokens"]:
                self.assertIn(token, production_text, f"production guard drift: {name}: {token}")

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
        for link in self.mapping["audit_links"]:
            for token in link["formal_tokens"]:
                self.assertIn(token, formal_text, f"formal audit-link drift: {link['name']}: {token}")
            for token in link["production_tokens"]:
                self.assertIn(token, production_text, f"production audit-link drift: {link['name']}: {token}")

    def test_known_fast_path_gaps_remain_explicit_until_resolved(self) -> None:
        production_text = (ROOT / self.mapping["production_source"]).read_text(encoding="utf-8")
        gaps = {gap["id"]: gap for gap in self.mapping["known_gaps"]}
        self.assertEqual(
            set(gaps),
            {"FULL_EVIDENCE_ON_EXECUTION_PATH", "FULL_POLICY_AND_DECISION_ON_EXECUTION_PATH"},
        )
        for gap in gaps.values():
            self.assertEqual(gap["status"], "open")
            for token in gap["production_tokens"]:
                self.assertIn(token, production_text, f"known gap changed without map update: {gap['id']}: {token}")

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
