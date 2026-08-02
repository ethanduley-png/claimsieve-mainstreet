from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * ((4 - len(text) % 4) % 4))


def signing_message(domain: str, value: Any) -> bytes:
    if not domain or "\x00" in domain:
        raise ValueError("invalid signature domain")
    return b"CLAIMSIEVE\x00" + domain.encode("ascii") + b"\x00" + canonical_bytes(value)


@dataclass(frozen=True)
class PublicKey:
    key_id: str
    raw: bytes

    def encode(self) -> str:
        return "ed25519-pub:" + _b64u(self.raw)

    @classmethod
    def decode(cls, key_id: str, encoded: str) -> "PublicKey":
        prefix = "ed25519-pub:"
        if not encoded.startswith(prefix):
            raise ValueError("unsupported public key encoding")
        raw = _unb64u(encoded[len(prefix):])
        if len(raw) != 32:
            raise ValueError("invalid Ed25519 public key length")
        return cls(key_id=key_id, raw=raw)

    def verify(self, domain: str, value: Any, signature: str) -> bool:
        prefix = "ed25519:"
        if not signature.startswith(prefix):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(self.raw).verify(
                _unb64u(signature[len(prefix):]),
                signing_message(domain, value),
            )
            return True
        except (InvalidSignature, ValueError):
            return False


@dataclass
class KeyPair:
    key_id: str
    private: Ed25519PrivateKey

    @classmethod
    def from_seed(cls, key_id: str, seed: bytes) -> "KeyPair":
        if len(seed) != 32:
            raise ValueError("Ed25519 seed must be 32 bytes")
        return cls(key_id=key_id, private=Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public(self) -> PublicKey:
        raw = self.private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return PublicKey(self.key_id, raw)

    def sign(self, domain: str, value: Any) -> str:
        return "ed25519:" + _b64u(self.private.sign(signing_message(domain, value)))
