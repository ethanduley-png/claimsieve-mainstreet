"""Challenge-bound, Ed25519-signed GitHub observer evidence.

Verifier trusts an externally pinned observer public key and locally trusted
approval / dispatch ticket. A signature authenticates an observer statement; it
does NOT certify host independence, GitHub-origin signatures, or chronology.
"""
from __future__ import annotations

import re
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any, Mapping

from .canonical import digest
from .crypto import KeyPair, PublicKey
from .durable_state import DispatchTicket
from .github_adversarial_canary import GitHubAdversarialCanary
from .github_provider import GitHubIssueProvider

SCHEMA = "claimsieve.github_observer_attestation.v1"
DOMAIN = "github-observer-attestation-v1"
_FIELDS = frozenset({
    "schema_version", "challenge", "observed_at_unix", "repository",
    "ticket_digest", "approved_action_digest", "result",
    "observer_key_id", "signature",
})
_RESULT_FIELDS = frozenset({
    "outcome", "reason", "expected_action_digest", "observed_action_digest",
    "provider_id", "executor_claim_conflict", "automatic_retry_allowed",
})
_CHALLENGE_RE = re.compile(r"^[0-9a-f]{64}$")
_REASONS = {
    "CONFIRMED_SUCCESS": {"readback_matches_exact_approval_and_ticket"},
    "DIVERGENT_EFFECT": {"readback_effect_differs_from_approval"},
    "OUTCOME_UNKNOWN": {
        "no_complete_independent_provider_evidence",
        "provider_evidence_conflict_or_incomplete_binding",
    },
}


class GitHubObserverAttestationError(ValueError):
    """Untrusted, malformed, replayed, stale or mismatched observer receipt."""



class GitHubVerifierChallengeStore:
    """Durably issue and atomically consume fresh challenges in trusted verifier.

    This reference single-host SQLite store needs off-host anti-rollback in
    production: a privileged local administrator can restore an old snapshot.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS challenges ("
                "challenge TEXT PRIMARY KEY, ticket_digest TEXT NOT NULL,"
                "action_digest TEXT NOT NULL, issued_at INTEGER NOT NULL,"
                "expires_at INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0"
                " CHECK(consumed IN (0, 1)))"
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("PRAGMA busy_timeout = 15000")
        return connection

    def issue(
        self,
        *,
        ticket: DispatchTicket,
        approved_action_digest: str,
        now_unix: int | None = None,
        ttl_seconds: int = 60,
    ) -> str:
        now = int(time.time()) if now_unix is None else now_unix
        if not isinstance(ticket, DispatchTicket) or type(now) is not int or now < 1:
            raise GitHubObserverAttestationError("trusted ticket and clock required")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 3600:
            raise GitHubObserverAttestationError("invalid challenge lifetime")
        if not isinstance(approved_action_digest, str) or re.fullmatch(
            r"sha256:[0-9a-f]{64}", approved_action_digest
        ) is None:
            raise GitHubObserverAttestationError("trusted action digest malformed")
        challenge = new_observation_challenge()
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO challenges(challenge, ticket_digest, action_digest,"
                " issued_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                (challenge, digest(ticket.as_dict()), approved_action_digest, now, now + ttl_seconds),
            )
        return challenge

    def consume(
        self,
        *,
        challenge: str,
        ticket: DispatchTicket,
        approved_action_digest: str,
        now_unix: int,
    ) -> None:
        _challenge(challenge)
        if type(now_unix) is not int or now_unix < 1:
            raise GitHubObserverAttestationError("invalid verifier time")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                affected = connection.execute(
                    "UPDATE challenges SET consumed = 1 WHERE challenge = ? "
                    "AND ticket_digest = ? AND action_digest = ? AND consumed = 0 "
                    "AND expires_at >= ? AND issued_at <= ?",
                    (challenge, digest(ticket.as_dict()), approved_action_digest,
                     now_unix, now_unix + 5),
                ).rowcount
                if affected != 1:
                    raise GitHubObserverAttestationError(
                        "challenge absent, expired, replayed or incorrectly bound"
                    )
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

def new_observation_challenge() -> str:
    """Mint the challenge only in the trusted verifier, never the agent."""
    return secrets.token_hex(32)


def _repository(approved_action: Mapping[str, Any]) -> str:
    destination = approved_action.get("destination")
    repository = destination.get("authority") if isinstance(destination, dict) else None
    if not isinstance(repository, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}", repository
    ):
        raise GitHubObserverAttestationError("approved GitHub repository missing")
    return repository


def _challenge(value: Any) -> None:
    if not isinstance(value, str) or _CHALLENGE_RE.fullmatch(value) is None:
        raise GitHubObserverAttestationError("invalid verifier challenge")


def issue_github_observer_attestation(
    *,
    approved_action: Mapping[str, Any],
    approved_action_digest: str,
    ticket: DispatchTicket,
    challenge: str,
    observer: GitHubIssueProvider,
    observer_key: KeyPair,
    observed_at_unix: int | None = None,
) -> dict[str, Any]:
    """Sign only what a read-only GitHub observer actually reconciled.

    The calling process must hold a separate read-only GitHub identity and
    independent signing key. Neither may be accessible to agent or executor.
    """
    _challenge(challenge)
    if not isinstance(observer_key, KeyPair) or not observer_key.key_id:
        raise GitHubObserverAttestationError("dedicated observer signing key required")
    if not isinstance(ticket, DispatchTicket):
        raise GitHubObserverAttestationError("trusted dispatch ticket required")
    # The canary checks exact action digest and observer's lack of write token.
    canary = GitHubAdversarialCanary(
        approved_action=approved_action,
        approved_action_digest=approved_action_digest,
        ticket=ticket,
        observer=observer,
    )
    observation = canary.observe().as_dict()
    timestamp = int(time.time()) if observed_at_unix is None else observed_at_unix
    if type(timestamp) is not int or timestamp < 1:
        raise GitHubObserverAttestationError("invalid observation time")
    unsigned = {
        "schema_version": SCHEMA,
        "challenge": challenge,
        "observed_at_unix": timestamp,
        "repository": _repository(approved_action),
        "ticket_digest": digest(ticket.as_dict()),
        "approved_action_digest": approved_action_digest,
        "result": observation,
        "observer_key_id": observer_key.key_id,
    }
    return {**unsigned, "signature": observer_key.sign(DOMAIN, unsigned)}


def verify_github_observer_attestation(
    attestation: Mapping[str, Any],
    *,
    approved_action: Mapping[str, Any],
    approved_action_digest: str,
    ticket: DispatchTicket,
    challenge: str,
    observer_public_key: PublicKey,
    challenge_store: GitHubVerifierChallengeStore,
    now_unix: int | None = None,
    max_age_seconds: int = 60,
    max_future_skew_seconds: int = 5,
) -> dict[str, Any]:
    """Verify a receipt against out-of-band trust roots and exact trusted ticket.

    The caller MUST ensure challenge is fresh, verifier-generated, and
    single-use. A valid signature is NOT a replacement for the trusted issuer.
    """
    _challenge(challenge)
    if not isinstance(attestation, Mapping) or set(attestation) != _FIELDS:
        raise GitHubObserverAttestationError("observer receipt fields invalid")
    if (not isinstance(ticket, DispatchTicket) or not isinstance(observer_public_key, PublicKey)
            or not isinstance(challenge_store, GitHubVerifierChallengeStore)):
        raise GitHubObserverAttestationError("trusted ticket, pinned key and challenge store required")
    if type(max_age_seconds) is not int or not 1 <= max_age_seconds <= 3600:
        raise GitHubObserverAttestationError("invalid maximum observation age")
    if type(max_future_skew_seconds) is not int or not 0 <= max_future_skew_seconds <= 60:
        raise GitHubObserverAttestationError("invalid future skew")
    now = int(time.time()) if now_unix is None else now_unix
    observed = attestation["observed_at_unix"]
    if type(now) is not int or type(observed) is not int or observed < 1:
        raise GitHubObserverAttestationError("invalid observation clock")
    if observed > now + max_future_skew_seconds or now - observed > max_age_seconds:
        raise GitHubObserverAttestationError("stale or future-dated observation")
    expected_digest = digest(dict(approved_action))
    if approved_action_digest != expected_digest:
        raise GitHubObserverAttestationError("local approved action digest invalid")
    if (
        attestation["schema_version"] != SCHEMA
        or attestation["challenge"] != challenge
        or attestation["repository"] != _repository(approved_action)
        or attestation["ticket_digest"] != digest(ticket.as_dict())
        or attestation["approved_action_digest"] != expected_digest
        or attestation["observer_key_id"] != observer_public_key.key_id
    ):
        raise GitHubObserverAttestationError("observer receipt does not bind trusted request")
    unsigned = {k: v for k, v in attestation.items() if k != "signature"}
    signature = attestation["signature"]
    if not isinstance(signature, str) or not observer_public_key.verify(DOMAIN, unsigned, signature):
        raise GitHubObserverAttestationError("observer signature invalid")
    result = attestation["result"]
    if not isinstance(result, dict) or set(result) != _RESULT_FIELDS:
        raise GitHubObserverAttestationError("observation result shape invalid")
    outcome = result.get("outcome")
    if (not isinstance(outcome, str) or outcome not in _REASONS
            or not isinstance(result.get("reason"), str)
            or result["reason"] not in _REASONS[outcome]):
        raise GitHubObserverAttestationError("observation status invalid")
    if (
        result.get("expected_action_digest") != expected_digest
        or result.get("automatic_retry_allowed") is not False
        or result.get("executor_claim_conflict") is not False
    ):
        raise GitHubObserverAttestationError("observer result has invalid bindings")
    observed_digest, provider_id = result.get("observed_action_digest"), result.get("provider_id")
    if observed_digest is not None and (
        not isinstance(observed_digest, str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", observed_digest) is None
    ):
        raise GitHubObserverAttestationError("observed digest malformed")
    repo = _repository(approved_action)
    expected_url_re = r"https://github[.]com/" + re.escape(repo) + r"/issues/[1-9][0-9]*"
    if outcome == "CONFIRMED_SUCCESS":
        if observed_digest != expected_digest or not isinstance(provider_id, str) or re.fullmatch(expected_url_re, provider_id) is None:
            raise GitHubObserverAttestationError("success lacks exact provider readback")
    elif outcome == "DIVERGENT_EFFECT":
        if observed_digest is None or observed_digest == expected_digest or not isinstance(provider_id, str) or re.fullmatch(expected_url_re, provider_id) is None:
            raise GitHubObserverAttestationError("divergence lacks independent effect")
    elif provider_id is not None:
        raise GitHubObserverAttestationError("unknown result must not assert confirmed provider identity")
    # Replay consumption is a durable atomic write: two verifier workers cannot
    # both accept the same signed receipt/challenge, even concurrently.
    challenge_store.consume(
        challenge=challenge, ticket=ticket, approved_action_digest=expected_digest,
        now_unix=now,
    )
    return dict(result)
