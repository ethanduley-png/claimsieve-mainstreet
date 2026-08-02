from __future__ import annotations

import unittest

from claimsieve_ref.provider_contracts import (
    ProviderContractError,
    ReplayContext,
    STRIPE_MINIMUM_SAFE_RETENTION_SECONDS,
    StripeIdempotencyContractModel,
    authorize_stripe_transport_replay,
)


class StripeProviderContractTests(unittest.TestCase):
    def context(self, **changes: object) -> ReplayContext:
        values = {
            "outcome_unknown": True,
            "same_reservation": True,
            "same_idempotency_key": True,
            "same_request_digest": True,
            "same_endpoint": True,
            "same_account": True,
            "authority_active": True,
            "provider_supports_idempotent_post": True,
            "elapsed_seconds": 10,
            "replay_count": 0,
        }
        values.update(changes)
        return ReplayContext(**values)  # type: ignore[arg-type]

    def test_connection_drop_exact_replay_returns_original_without_duplicate(self) -> None:
        provider = StripeIdempotencyContractModel()
        first = provider.post(
            idempotency_key="key-1",
            endpoint="/v1/customers",
            request_digest="sha256:request-a",
            now_seconds=100,
            scenario="commit_then_connection_drop",
        )
        self.assertEqual(first.transport, "network_error")
        self.assertEqual(first.effect_count, 1)
        decision = authorize_stripe_transport_replay(self.context())
        self.assertTrue(decision.allowed)
        self.assertFalse(decision.creates_new_logical_attempt)
        second = provider.post(
            idempotency_key="key-1",
            endpoint="/v1/customers",
            request_digest="sha256:request-a",
            now_seconds=110,
        )
        self.assertTrue(second.idempotent_replay)
        self.assertEqual(second.body, {"id": "obj_1", "status": "created"})
        self.assertEqual(second.effect_count, 1)

    def test_same_key_parameter_mutation_is_denied_by_claimsieve_and_provider(self) -> None:
        provider = StripeIdempotencyContractModel()
        provider.post(
            idempotency_key="key-2",
            endpoint="/v1/customers",
            request_digest="sha256:request-a",
            now_seconds=100,
        )
        self.assertFalse(
            authorize_stripe_transport_replay(
                self.context(same_request_digest=False)
            ).allowed
        )
        with self.assertRaisesRegex(ProviderContractError, "different endpoint or parameters"):
            provider.post(
                idempotency_key="key-2",
                endpoint="/v1/customers",
                request_digest="sha256:request-b",
                now_seconds=110,
            )

    def test_replay_after_retention_is_denied_and_can_duplicate_if_bypassed(self) -> None:
        provider = StripeIdempotencyContractModel()
        first = provider.post(
            idempotency_key="key-3",
            endpoint="/v1/customers",
            request_digest="sha256:request-a",
            now_seconds=0,
        )
        self.assertEqual(first.effect_count, 1)
        decision = authorize_stripe_transport_replay(
            self.context(elapsed_seconds=STRIPE_MINIMUM_SAFE_RETENTION_SECONDS)
        )
        self.assertFalse(decision.allowed)
        bypassed = provider.post(
            idempotency_key="key-3",
            endpoint="/v1/customers",
            request_digest="sha256:request-a",
            now_seconds=STRIPE_MINIMUM_SAFE_RETENTION_SECONDS,
        )
        self.assertFalse(bypassed.idempotent_replay)
        self.assertEqual(bypassed.effect_count, 2)

    def test_revocation_blocks_transport_replay(self) -> None:
        decision = authorize_stripe_transport_replay(
            self.context(authority_active=False)
        )
        self.assertFalse(decision.allowed)
        self.assertIn("revoked", decision.reason)

    def test_server_500_is_cached_but_remains_semantically_indeterminate(self) -> None:
        provider = StripeIdempotencyContractModel()
        first = provider.post(
            idempotency_key="key-4",
            endpoint="/v1/customers",
            request_digest="sha256:request-a",
            now_seconds=100,
            scenario="server_500_with_effect",
        )
        self.assertEqual(first.status_code, 500)
        self.assertEqual(first.effect_count, 1)
        replay = provider.post(
            idempotency_key="key-4",
            endpoint="/v1/customers",
            request_digest="sha256:request-a",
            now_seconds=110,
        )
        self.assertEqual(replay.status_code, 500)
        self.assertTrue(replay.idempotent_replay)
        self.assertEqual(replay.effect_count, 1)
        # A repeated 500 is not independent proof of success or failure.
        self.assertIn("possible_object_id", replay.body or {})

    def test_pre_execution_validation_error_is_not_cached(self) -> None:
        provider = StripeIdempotencyContractModel()
        rejected = provider.post(
            idempotency_key="key-5",
            endpoint="/v1/customers",
            request_digest="sha256:bad",
            now_seconds=100,
            scenario="validation_error",
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(rejected.effect_count, 0)
        later = provider.post(
            idempotency_key="key-5",
            endpoint="/v1/customers",
            request_digest="sha256:bad",
            now_seconds=110,
            scenario="success",
        )
        self.assertFalse(later.idempotent_replay)
        self.assertEqual(later.effect_count, 1)


if __name__ == "__main__":
    unittest.main()
