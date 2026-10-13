#!/usr/bin/env python3
"""Read-only GitHub observer entrypoint for a separately administered process.

This CLI never dispatches an effect and never accepts GitHub write credentials.
Run it only on a host/container that the agent and executor cannot administer.
"""
from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

from claimsieve_ref.canonical import loads_strict
from claimsieve_ref.crypto import KeyPair
from claimsieve_ref.durable_state import DispatchTicket
from claimsieve_ref.github_observer_attestation import (
    GitHubObserverAttestationError,
    issue_github_observer_attestation,
)
from claimsieve_ref.github_provider import GitHubIssueProvider, GitHubProviderError

_REQUEST_FIELDS = frozenset({"approved_action", "approved_action_digest", "ticket", "challenge"})
_TICKET_FIELDS = frozenset(DispatchTicket.__dataclass_fields__)


def _load_private_seed(path: Path) -> bytes:
    """Do not follow links, read keys with shared permissions, or print them."""
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise GitHubObserverAttestationError("observer key must be a regular non-symlink file")
    if os.name != "posix" or metadata.st_mode & 0o077:
        raise GitHubObserverAttestationError("observer key requires POSIX 0600/private mode")
    if metadata.st_uid != os.geteuid():
        raise GitHubObserverAttestationError("observer key must be owned by the running identity")
    # O_NOFOLLOW also prevents a symlink swap between lstat and open.
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise GitHubObserverAttestationError("observer key changed during open")
        if opened.st_mode & 0o077:
            raise GitHubObserverAttestationError("observer key file permissions are unsafe")
        seed = os.read(descriptor, 33)
    finally:
        os.close(descriptor)
    if len(seed) != 32:
        raise GitHubObserverAttestationError("observer Ed25519 seed must be exactly 32 bytes")
    return seed


def _load_request(path: Path) -> tuple[dict, str, DispatchTicket, str]:
    raw = loads_strict(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict) or set(raw) != _REQUEST_FIELDS:
        raise GitHubObserverAttestationError("observer request fields invalid")
    if not isinstance(raw["approved_action"], dict) or not isinstance(raw["ticket"], dict):
        raise GitHubObserverAttestationError("observer request action/ticket invalid")
    if set(raw["ticket"]) != _TICKET_FIELDS:
        raise GitHubObserverAttestationError("trusted dispatch ticket fields invalid")
    try:
        ticket = DispatchTicket(**raw["ticket"])
    except TypeError as exc:
        raise GitHubObserverAttestationError("trusted dispatch ticket malformed") from exc
    return raw["approved_action"], raw["approved_action_digest"], ticket, raw["challenge"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Independently sign read-only GitHub observation")
    parser.add_argument("--repository", required=True, help="exact allowlisted owner/name")
    parser.add_argument("--request", required=True, type=Path, help="verifier challenge and trusted dispatch ticket JSON")
    parser.add_argument("--observer-key-id", required=True)
    parser.add_argument("--key-seed-file", required=True, type=Path, help="private Ed25519 32-byte seed (0600)")
    args = parser.parse_args()
    try:
        if any(os.environ.get(name) for name in (
            "CLAIMSIEVE_GITHUB_WRITE_TOKEN", "GITHUB_TOKEN", "GH_TOKEN",
        )):
            raise GitHubObserverAttestationError("observer process must not carry GitHub write/ambient credentials")
        token = os.environ.get("CLAIMSIEVE_GITHUB_READ_TOKEN")
        if not token:
            raise GitHubObserverAttestationError("dedicated read-only GitHub token missing")
        action, action_digest, ticket, challenge = _load_request(args.request)
        observer_key = KeyPair.from_seed(args.observer_key_id, _load_private_seed(args.key_seed_file))
        provider = GitHubIssueProvider({args.repository}, read_token=token)
        receipt = issue_github_observer_attestation(
            approved_action=action, approved_action_digest=action_digest,
            ticket=ticket, challenge=challenge, observer=provider,
            observer_key=observer_key,
        )
    except (GitHubObserverAttestationError, GitHubProviderError, ValueError, TypeError, OSError) as exc:
        # No exception values, file contents, or tokens are ever printed.
        print(f"observer refused: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
