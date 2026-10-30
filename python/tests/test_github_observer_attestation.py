"""Signed observer boundary tests against deterministic GitHub provider transport."""
from __future__ import annotations

import copy
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from claimsieve_ref.canonical import digest
from claimsieve_ref.crypto import KeyPair
from claimsieve_ref.durable_state import DispatchTicket
from claimsieve_ref.github_observer_attestation import (
    DOMAIN,
    GitHubObserverAttestationError,
    GitHubVerifierChallengeStore,
    issue_github_observer_attestation,
    verify_github_observer_attestation,
)
from claimsieve_ref.github_provider import GitHubIssueProvider
from github_observer_cli import _load_private_seed
from test_github_provider import FakeGitHubTransport


class SignedGitHubObserverTests(unittest.TestCase):
    NOW = 2_000_000_000

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = "example/claimsieve-mainstreet"
        self.transport = FakeGitHubTransport(self.repo)
        self.writer = GitHubIssueProvider(
            {self.repo}, read_token="writer-preflight-read",
            write_token="executor-write", transport=self.transport,
        )
        self.observer = GitHubIssueProvider(
            {self.repo}, read_token="separate-observer-read",
            transport=self.transport,
        )
        self.observer_key = KeyPair.from_seed("observer-independent", bytes([41]) * 32)
        self.attacker_key = KeyPair.from_seed("executor-or-agent", bytes([43]) * 32)
        self.action = {
            "kind": "run_connector", "effect_class": "external_write",
            "destination": {"scheme": "github", "authority": self.repo,
                            "resource": "issues", "trust_domain": "github.com"},
            "method": "CREATE",
            "parameters": {"title": "Action A", "body": "Exact approved change",
                           "correlation_marker": "proposal-A", "work_item_id": "work-A"},
            "reversibility": "compensable",
        }
        self.action_digest = digest(self.action)
        self.ticket = DispatchTicket(
            reservation_id="reservation:permit-observer",
            permit_id="permit-observer",
            campaign_id="campaign-observer",
            action_digest="sha256:" + "11" * 32,
            request_digest="sha256:" + "22" * 32,
            resource_key="sha256:" + "33" * 32,
            idempotency_key="permit-observer", fencing_token=14, containment_epoch=0,
        )
        self.store = GitHubVerifierChallengeStore(Path(self.tmp.name) / "nonce.sqlite")

    def test_connections_close_on_success_and_replay_rejection(self) -> None:
        connections = []
        original_connect = GitHubVerifierChallengeStore._connect

        def track(store):
            connection = original_connect(store)
            connections.append(connection)
            return connection

        with patch.object(GitHubVerifierChallengeStore, "_connect", track):
            store = GitHubVerifierChallengeStore(Path(self.tmp.name) / "lifecycle.sqlite")
            challenge = store.issue(ticket=self.ticket, approved_action_digest=self.action_digest,
                                    now_unix=self.NOW)
            args = dict(challenge=challenge, ticket=self.ticket,
                        approved_action_digest=self.action_digest, now_unix=self.NOW)
            store.consume(**args)
            with self.assertRaises(GitHubObserverAttestationError):
                store.consume(**args)
        self.assertEqual(len(connections), 4)
        for connection in connections:
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute("SELECT 1")

    def prepare(self, *, write: bool = True, observed_at: int | None = None, ttl: int = 60) -> tuple[str, dict]:
        if write:
            self.assertEqual(self.writer.invoke(self.action, self.ticket)["status"], "accepted")
        challenge = self.store.issue(
            ticket=self.ticket, approved_action_digest=self.action_digest,
            now_unix=self.NOW, ttl_seconds=ttl,
        )
        signed = issue_github_observer_attestation(
            approved_action=self.action, approved_action_digest=self.action_digest,
            ticket=self.ticket, challenge=challenge, observer=self.observer,
            observer_key=self.observer_key,
            observed_at_unix=self.NOW if observed_at is None else observed_at,
        )
        return challenge, signed

    def verify(self, challenge: str, signed: dict, **changes):
        args = dict(
            approved_action=self.action, approved_action_digest=self.action_digest,
            ticket=self.ticket, challenge=challenge,
            observer_public_key=self.observer_key.public,
            challenge_store=self.store, now_unix=self.NOW + 1,
        )
        args.update(changes)
        return verify_github_observer_attestation(signed, **args)

    def resign(self, receipt: dict) -> dict:
        receipt = copy.deepcopy(receipt)
        unsigned = {k: v for k, v in receipt.items() if k != "signature"}
        receipt["signature"] = self.observer_key.sign(DOMAIN, unsigned)
        return receipt

    def test_01_signed_exact_external_readback_is_confirmed(self) -> None:
        challenge, signed = self.prepare()
        result = self.verify(challenge, signed)
        self.assertEqual(result["outcome"], "CONFIRMED_SUCCESS")
        self.assertEqual(result["observed_action_digest"], self.action_digest)
        self.assertEqual(self.transport.requests[-1][2], "separate-observer-read")

    def test_02_missing_provider_state_is_signed_unknown(self) -> None:
        challenge, signed = self.prepare(write=False)
        result = self.verify(challenge, signed)
        self.assertEqual(result["outcome"], "OUTCOME_UNKNOWN")
        self.assertIsNone(result["provider_id"])

    def test_03_agent_spoofed_success_is_signature_invalid(self) -> None:
        challenge, signed = self.prepare(write=False)
        signed["result"]["outcome"] = "CONFIRMED_SUCCESS"
        with self.assertRaisesRegex(GitHubObserverAttestationError, "signature"):
            self.verify(challenge, signed)

    def test_04_executor_key_cannot_impersonate_observer(self) -> None:
        challenge, signed = self.prepare()
        unsigned = {k: v for k, v in signed.items() if k != "signature"}
        signed["signature"] = self.attacker_key.sign(DOMAIN, unsigned)
        with self.assertRaisesRegex(GitHubObserverAttestationError, "signature"):
            self.verify(challenge, signed)

    def test_05_changed_challenge_detected(self) -> None:
        _, signed = self.prepare()
        other = self.store.issue(
            ticket=self.ticket, approved_action_digest=self.action_digest,
            now_unix=self.NOW,
        )
        with self.assertRaisesRegex(GitHubObserverAttestationError, "bind"):
            self.verify(other, signed)

    def test_06_exact_receipt_replay_rejected_after_first_use(self) -> None:
        challenge, signed = self.prepare()
        self.assertEqual(self.verify(challenge, signed)["outcome"], "CONFIRMED_SUCCESS")
        with self.assertRaisesRegex(GitHubObserverAttestationError, "replayed"):
            self.verify(challenge, signed)

    def test_07_stale_observation_rejected(self) -> None:
        challenge, signed = self.prepare(observed_at=self.NOW - 90)
        with self.assertRaisesRegex(GitHubObserverAttestationError, "stale"):
            self.verify(challenge, signed)

    def test_08_future_dated_observation_rejected(self) -> None:
        challenge, signed = self.prepare(observed_at=self.NOW + 30)
        with self.assertRaisesRegex(GitHubObserverAttestationError, "future"):
            self.verify(challenge, signed)

    def test_09_wrong_trusted_ticket_detected(self) -> None:
        challenge, signed = self.prepare()
        wrong = DispatchTicket(**{**self.ticket.__dict__, "fencing_token": 99})
        with self.assertRaisesRegex(GitHubObserverAttestationError, "bind"):
            self.verify(challenge, signed, ticket=wrong)

    def test_10_wrong_approved_action_detected(self) -> None:
        challenge, signed = self.prepare()
        wrong = copy.deepcopy(self.action)
        wrong["parameters"]["title"] = "Action B"
        with self.assertRaisesRegex(GitHubObserverAttestationError, "action digest"):
            self.verify(challenge, signed, approved_action=wrong)

    def test_11_unknown_extra_field_rejected(self) -> None:
        challenge, signed = self.prepare()
        signed["agent_claims_success"] = True
        with self.assertRaisesRegex(GitHubObserverAttestationError, "fields"):
            self.verify(challenge, signed)

    def test_12_duplicate_external_marker_stays_unknown(self) -> None:
        self.writer.invoke(self.action, self.ticket)
        issue = copy.deepcopy(self.transport.issues[0])
        issue["number"] = 2
        issue["html_url"] = f"https://github.com/{self.repo}/issues/2"
        self.transport.issues.append(issue)
        challenge, signed = self.prepare(write=False)
        self.assertEqual(self.verify(challenge, signed)["outcome"], "OUTCOME_UNKNOWN")

    def test_13_provider_mutation_yields_divergence(self) -> None:
        self.writer.invoke(self.action, self.ticket)
        self.transport.issues[0]["title"] = "Mutated by adversary"
        challenge, signed = self.prepare(write=False)
        self.assertEqual(self.verify(challenge, signed)["outcome"], "DIVERGENT_EFFECT")

    def test_14_same_key_can_sign_invalid_positive_but_semantics_reject(self) -> None:
        challenge, signed = self.prepare(write=False)
        signed["result"]["outcome"] = "CONFIRMED_SUCCESS"
        signed["result"]["reason"] = "readback_matches_exact_approval_and_ticket"
        signed = self.resign(signed)
        with self.assertRaisesRegex(GitHubObserverAttestationError, "success lacks"):
            self.verify(challenge, signed)

    def test_15_unsigned_observer_identity_is_not_accepted(self) -> None:
        challenge, signed = self.prepare()
        signed["observer_key_id"] = "fake-observer"
        with self.assertRaisesRegex(GitHubObserverAttestationError, "bind"):
            self.verify(challenge, signed)

    def test_16_expired_registered_challenge_rejected(self) -> None:
        challenge, signed = self.prepare(ttl=1)
        with self.assertRaisesRegex(GitHubObserverAttestationError, "expired"):
            self.verify(challenge, signed, now_unix=self.NOW + 3)

    def test_17_attestation_with_write_credential_cannot_be_issued(self) -> None:
        self.writer.invoke(self.action, self.ticket)
        challenge = self.store.issue(
            ticket=self.ticket, approved_action_digest=self.action_digest,
            now_unix=self.NOW,
        )
        with self.assertRaises(ValueError):
            issue_github_observer_attestation(
                approved_action=self.action, approved_action_digest=self.action_digest,
                ticket=self.ticket, challenge=challenge, observer=self.writer,
                observer_key=self.observer_key, observed_at_unix=self.NOW,
            )

    def test_18_concurrent_receipt_replay_has_one_winner(self) -> None:
        challenge, signed = self.prepare()
        def one(_: int) -> bool:
            try:
                self.verify(challenge, signed)
                return True
            except GitHubObserverAttestationError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            accepted = list(pool.map(one, range(2)))
        self.assertEqual(accepted.count(True), 1)

    def test_19_wrong_observer_public_key_detected(self) -> None:
        challenge, signed = self.prepare()
        with self.assertRaises(GitHubObserverAttestationError):
            self.verify(challenge, signed, observer_public_key=self.attacker_key.public)

    def test_20_mutated_result_signed_with_correct_key_still_rejected(self) -> None:
        challenge, signed = self.prepare()
        signed["result"]["outcome"] = ["CONFIRMED_SUCCESS"]
        signed = self.resign(signed)
        with self.assertRaises(GitHubObserverAttestationError):
            self.verify(challenge, signed)

    def test_21_wrong_provider_url_even_when_signed_rejected(self) -> None:
        challenge, signed = self.prepare()
        signed["result"]["provider_id"] = "https://attacker.example/issues/1"
        signed = self.resign(signed)
        with self.assertRaisesRegex(GitHubObserverAttestationError, "success lacks"):
            self.verify(challenge, signed)

    def test_22_observer_seed_file_requires_private_permissions(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX key custody only")
        path = Path(self.tmp.name) / "seed"
        path.write_bytes(bytes([44]) * 32)
        path.chmod(0o644)
        with self.assertRaisesRegex(GitHubObserverAttestationError, "0600"):
            _load_private_seed(path)
        path.chmod(0o600)
        self.assertEqual(_load_private_seed(path), bytes([44]) * 32)

    def test_23_observer_seed_symlink_refused(self) -> None:
        if os.name != "posix":
            self.skipTest("POSIX key custody only")
        path = Path(self.tmp.name) / "seed"
        path.write_bytes(bytes([45]) * 32)
        path.chmod(0o600)
        symlink = Path(self.tmp.name) / "seed-link"
        symlink.symlink_to(path)
        with self.assertRaisesRegex(GitHubObserverAttestationError, "symlink"):
            _load_private_seed(symlink)


if __name__ == "__main__":
    unittest.main()
