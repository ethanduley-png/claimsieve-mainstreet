from __future__ import annotations

import unittest

from claimsieve_ref.canonical import canonical_bytes, digest
from mainstreet_runtimes.operational_state import (
    OperationalState,
    OperationalStateBounds,
    OperationalStateBoundsError,
    OperationalStateError,
    OperationalStatePatch,
    ProtectedOperationalStateError,
    StaleOperationalStateError,
    apply_operational_state_patch,
)


class BoundedOperationalStateTests(unittest.TestCase):
    def test_patch_is_versioned_and_digest_bound(self) -> None:
        state = OperationalState.from_payload({"goal": "qualify lead", "status": "researching"})
        patch = OperationalStatePatch.from_changes(
            state,
            actor="worker:sales",
            changes={"status": "ready", "next_step": "prepare proposal"},
        )
        successor, transition = apply_operational_state_patch(state, patch)
        self.assertEqual(1, successor.version)
        self.assertEqual("ready", successor.payload["status"])
        self.assertEqual(state.state_digest, transition.before_digest)
        self.assertEqual(successor.state_digest, transition.after_digest)
        self.assertEqual(patch.patch_digest, transition.patch_digest)

    def test_deterministic_encoding_and_digest(self) -> None:
        state_a = OperationalState.from_payload({"b": 2, "a": 1})
        state_b = OperationalState.from_payload({"a": 1, "b": 2})
        self.assertEqual(state_a.payload_json, state_b.payload_json)
        self.assertEqual(state_a.state_digest, state_b.state_digest)

    def test_stale_revision_is_rejected(self) -> None:
        state = OperationalState.from_payload({"step": 0})
        stale = OperationalStatePatch.from_changes(state, actor="worker:a", changes={"step": 1})
        current_patch = OperationalStatePatch.from_changes(state, actor="worker:b", changes={"step": 2})
        current, _ = apply_operational_state_patch(state, current_patch)
        with self.assertRaises(StaleOperationalStateError):
            apply_operational_state_patch(current, stale)

    def test_same_revision_wrong_digest_is_rejected(self) -> None:
        state_a = OperationalState.from_payload({"source": "a"})
        state_b = OperationalState.from_payload({"source": "b"})
        patch = OperationalStatePatch.from_changes(state_a, actor="worker:a", changes={"done": True})
        with self.assertRaises(StaleOperationalStateError):
            apply_operational_state_patch(state_b, patch)

    def test_reserved_roots_are_rejected(self) -> None:
        for key in ("permit", "approvals", "evidence", "execution_receipt", "durable_state"):
            with self.subTest(key=key):
                with self.assertRaises(ProtectedOperationalStateError):
                    OperationalState.from_payload({key: {"value": "untrusted"}})

    def test_manual_state_constructor_cannot_bypass_reserved_roots(self) -> None:
        payload = {"permit": {"value": "untrusted"}}
        payload_json = canonical_bytes(payload).decode("utf-8")
        state_digest = digest(
            {
                "schema_version": "claimsieve.operational_state.v1",
                "version": 0,
                "payload": payload,
            }
        )
        with self.assertRaises(ProtectedOperationalStateError):
            OperationalState(version=0, payload_json=payload_json, state_digest=state_digest)

    def test_non_authoritative_summaries_remain_possible(self) -> None:
        state = OperationalState.from_payload(
            {"evidence_summary": {"known": 2, "unknown": 1}, "approval_summary": "review required"}
        )
        self.assertEqual(2, state.payload["evidence_summary"]["known"])

    def test_post_merge_byte_budget_is_enforced(self) -> None:
        bounds = OperationalStateBounds(
            max_encoded_bytes=80,
            max_top_level_keys=8,
            max_patch_bytes=256,
            max_deletions_per_patch=8,
        )
        state = OperationalState.from_payload({"goal": "x"}, bounds=bounds)
        patch = OperationalStatePatch.from_changes(
            state, actor="worker:a", changes={"notes": "n" * 100}, bounds=bounds
        )
        with self.assertRaises(OperationalStateBoundsError):
            apply_operational_state_patch(state, patch, bounds=bounds)

    def test_key_budget_is_enforced(self) -> None:
        bounds = OperationalStateBounds(
            max_encoded_bytes=1024,
            max_top_level_keys=2,
            max_patch_bytes=512,
            max_deletions_per_patch=8,
        )
        state = OperationalState.from_payload({"a": 1, "b": 2}, bounds=bounds)
        patch = OperationalStatePatch.from_changes(state, actor="worker:a", changes={"c": 3}, bounds=bounds)
        with self.assertRaises(OperationalStateBoundsError):
            apply_operational_state_patch(state, patch, bounds=bounds)

    def test_deletion_supports_explicit_compaction(self) -> None:
        state = OperationalState.from_payload({"goal": "x", "temporary": "discard", "status": "working"})
        patch = OperationalStatePatch.from_changes(
            state,
            actor="worker:a",
            changes={"status": "done"},
            deletions=("temporary",),
        )
        successor, _ = apply_operational_state_patch(state, patch)
        self.assertNotIn("temporary", successor.payload)
        self.assertEqual("done", successor.payload["status"])

    def test_string_deletions_are_rejected_as_malformed_input(self) -> None:
        state = OperationalState.from_payload({"temporary": "discard"})
        with self.assertRaisesRegex(OperationalStateError, "sequence of root names"):
            OperationalStatePatch.from_changes(
                state,
                actor="worker:a",
                deletions="temporary",
            )

    def test_non_string_deletion_is_rejected_cleanly(self) -> None:
        state = OperationalState.from_payload({"temporary": "discard"})
        with self.assertRaisesRegex(OperationalStateError, "non-empty strings"):
            OperationalStatePatch.from_changes(
                state,
                actor="worker:a",
                deletions=(1,),
            )

    def test_protected_root_cannot_be_deleted_as_authority_side_effect(self) -> None:
        state = OperationalState.from_payload({"status": "working"})
        with self.assertRaises(ProtectedOperationalStateError):
            OperationalStatePatch.from_changes(
                state,
                actor="worker:a",
                deletions=("permit",),
            )

    def test_change_delete_overlap_is_rejected(self) -> None:
        state = OperationalState.from_payload({"status": "working"})
        with self.assertRaises(OperationalStateError):
            OperationalStatePatch.from_changes(
                state,
                actor="worker:a",
                changes={"status": "done"},
                deletions=("status",),
            )

    def test_input_mutation_does_not_mutate_state(self) -> None:
        source = {"plan": {"steps": ["a"]}}
        state = OperationalState.from_payload(source)
        source["plan"]["steps"].append("b")
        extracted = state.payload
        extracted["plan"]["steps"].append("c")
        self.assertEqual(["a"], state.payload["plan"]["steps"])

    def test_forged_digest_is_rejected(self) -> None:
        good = OperationalState.from_payload({"goal": "x"})
        with self.assertRaises(OperationalStateError):
            OperationalState(
                version=good.version,
                payload_json=good.payload_json,
                state_digest="sha256:" + "0" * 64,
            )


if __name__ == "__main__":
    unittest.main()
