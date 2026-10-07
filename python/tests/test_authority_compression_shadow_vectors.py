from __future__ import annotations

from itertools import product
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
VECTOR_PATH = ROOT / "vectors" / "authority_compression_shadow_cases_v1.json"


def historical_authority(state: dict[str, object]) -> bool:
    return bool(state["authorized"])


def reference_executable(state: dict[str, object]) -> bool:
    return all(
        (
            bool(state["authenticated"]),
            historical_authority(state),
            not bool(state["revoked"]),
            not bool(state["consumed"]),
            state["certificate_action"] == state["candidate_action"],
            state["certificate_policy"] == state["candidate_policy"],
            state["certificate_identity"] == state["candidate_identity"],
            int(state["valid_from"]) <= int(state["sequence"]),
            int(state["sequence"]) <= int(state["expires_at"]),
            bool(state["policy_active"]),
            bool(state["principal_active"]),
            bool(state["campaign_active"]),
            not bool(state["execution_frozen"]),
            not bool(state["campaign_suspended"]),
        )
    )


def compact_shadow_executable(state: dict[str, object]) -> bool:
    if not bool(state["authenticated"]):
        return False
    if not bool(state["authorized"]):
        return False
    if not bool(state["policy_active"]):
        return False
    if not bool(state["principal_active"]):
        return False
    if bool(state["execution_frozen"]):
        return False
    if bool(state["revoked"]):
        return False
    if not bool(state["campaign_active"]) or bool(state["campaign_suspended"]):
        return False
    if bool(state["consumed"]):
        return False
    if int(state["sequence"]) < int(state["valid_from"]):
        return False
    if int(state["sequence"]) > int(state["expires_at"]):
        return False
    if state["certificate_action"] != state["candidate_action"]:
        return False
    if state["certificate_policy"] != state["candidate_policy"]:
        return False
    if state["certificate_identity"] != state["candidate_identity"]:
        return False
    return True


class AuthorityCompressionShadowVectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))

    def resolved_cases(self):
        base = self.vectors["base"]
        for case in self.vectors["cases"]:
            state = dict(base)
            state.update(case["changes"])
            yield case, state

    def test_vector_schema_and_unique_ids(self) -> None:
        self.assertEqual(
            self.vectors["schema_version"],
            "claimsieve.authority_compression_shadow_cases.v1",
        )
        ids = [case["id"] for case in self.vectors["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 18)

    def test_reference_and_compact_shadow_agree_on_every_vector(self) -> None:
        for case, state in self.resolved_cases():
            with self.subTest(case=case["id"]):
                reference = reference_executable(state)
                shadow = compact_shadow_executable(state)
                expected = bool(case["expected"])
                self.assertEqual(reference, shadow)
                self.assertEqual(reference, expected)

    def test_current_invalidity_does_not_rewrite_historical_authority(self) -> None:
        checked = 0
        for case, state in self.resolved_cases():
            if "expected_historical_authority" not in case:
                continue
            with self.subTest(case=case["id"]):
                self.assertEqual(
                    historical_authority(state),
                    bool(case["expected_historical_authority"]),
                )
                self.assertFalse(reference_executable(state))
                self.assertFalse(compact_shadow_executable(state))
                checked += 1
        self.assertEqual(checked, 3)

    def test_single_guard_mutations_fail_closed(self) -> None:
        rejection_cases = {
            "unauthenticated",
            "historically_unauthorized",
            "revoked",
            "consumed",
            "action_mutated",
            "policy_mutated",
            "identity_mutated",
            "not_yet_valid",
            "expired",
            "policy_inactive",
            "principal_inactive",
            "campaign_inactive",
            "execution_frozen",
            "campaign_suspended",
        }
        found = {
            case["id"]
            for case in self.vectors["cases"]
            if case["id"] in rejection_cases and not bool(case["expected"])
        }
        self.assertEqual(found, rejection_cases)

    def test_exhaustive_current_state_dominance(self) -> None:
        base = dict(self.vectors["base"])
        base["authenticated"] = True
        base["authorized"] = True
        base["certificate_action"] = base["candidate_action"] = 1
        base["certificate_policy"] = base["candidate_policy"] = 2
        base["certificate_identity"] = base["candidate_identity"] = 3
        base["valid_from"] = 10
        base["sequence"] = 15
        base["expires_at"] = 20

        checked = 0
        accepted = 0
        for (
            policy_active,
            principal_active,
            campaign_active,
            execution_frozen,
            campaign_suspended,
            revoked,
            consumed,
            policy_matches,
            identity_matches,
        ) in product((False, True), repeat=9):
            state = dict(base)
            state.update(
                {
                    "policy_active": policy_active,
                    "principal_active": principal_active,
                    "campaign_active": campaign_active,
                    "execution_frozen": execution_frozen,
                    "campaign_suspended": campaign_suspended,
                    "revoked": revoked,
                    "consumed": consumed,
                    "candidate_policy": 2 if policy_matches else 9,
                    "candidate_identity": 3 if identity_matches else 9,
                }
            )
            expected = all(
                (
                    policy_active,
                    principal_active,
                    campaign_active,
                    not execution_frozen,
                    not campaign_suspended,
                    not revoked,
                    not consumed,
                    policy_matches,
                    identity_matches,
                )
            )
            self.assertEqual(reference_executable(state), expected)
            self.assertEqual(compact_shadow_executable(state), expected)
            self.assertTrue(historical_authority(state))
            checked += 1
            accepted += int(expected)

        self.assertEqual(checked, 512)
        self.assertEqual(accepted, 1)


if __name__ == "__main__":
    unittest.main()
