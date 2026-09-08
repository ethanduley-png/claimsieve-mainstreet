from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

from founder_os import FounderOSReferenceWorkflow

from .claimsieve_intake import OpenHandsFounderIntake

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class OpenHandsTransportError(ValueError):
    """Raised when out-of-band runtime identity does not match the authority profile."""


@dataclass(frozen=True)
class AuthenticatedRuntimeBinding:
    """Runtime identity supplied by a trusted transport/attestation layer.

    This object is deliberately separate from the OpenHands proposal payload.
    A production implementation would populate it from authenticated workload
    identity and deployment attestation, not from model- or agent-controlled
    event fields.
    """

    runtime_name: str
    runtime_version: str
    principal: str
    runtime_manifest_digest: str
    skills_manifest_digest: str
    network_profile_digest: str

    def validate(self) -> None:
        for name in ("runtime_name", "runtime_version", "principal"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 512:
                raise OpenHandsTransportError(
                    f"authenticated {name} must be a non-empty bounded string"
                )
        for name in (
            "runtime_manifest_digest",
            "skills_manifest_digest",
            "network_profile_digest",
        ):
            value = getattr(self, name)
            if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
                raise OpenHandsTransportError(
                    f"authenticated {name} must be an exact sha256 digest"
                )

    def binding(self) -> dict[str, str]:
        self.validate()
        return {
            "runtime_name": self.runtime_name,
            "runtime_version": self.runtime_version,
            "principal": self.principal,
            "runtime_manifest_digest": self.runtime_manifest_digest,
            "skills_manifest_digest": self.skills_manifest_digest,
            "network_profile_digest": self.network_profile_digest,
        }

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "AuthenticatedRuntimeBinding":
        required = {
            "runtime_name",
            "runtime_version",
            "principal",
            "runtime_manifest_digest",
            "skills_manifest_digest",
            "network_profile_digest",
        }
        if not isinstance(value, Mapping) or set(value) != required:
            raise OpenHandsTransportError(
                "authenticated runtime binding fields do not match the required schema"
            )
        binding = cls(**{name: value[name] for name in required})
        binding.validate()
        return binding


class OpenHandsAuthenticatedRoute:
    """Reference route with runtime identity bound outside the OpenHands intent.

    This class models the boundary that a production mTLS/workload-identity or
    attested service hop must provide. The proposal adapter receives only the
    bound ``route_intent`` callback; it cannot alter the authenticated identity
    captured when this object is constructed.

    This remains a local reference composition and is not itself a network
    authentication implementation.
    """

    def __init__(
        self,
        intake: OpenHandsFounderIntake,
        workflow: FounderOSReferenceWorkflow,
        authenticated_binding: AuthenticatedRuntimeBinding,
    ) -> None:
        if not isinstance(intake, OpenHandsFounderIntake):
            raise OpenHandsTransportError(
                "authenticated OpenHands route requires OpenHandsFounderIntake"
            )
        profile = getattr(workflow, "runtime_profile", None)
        if profile is None:
            raise OpenHandsTransportError("Founder OS workflow has no runtime profile")
        authenticated_binding.validate()
        expected = profile.binding()
        if authenticated_binding.binding() != expected:
            raise OpenHandsTransportError(
                "authenticated runtime binding does not match the ClaimSieve runtime profile"
            )
        if expected.get("runtime_name") != "openhands":
            raise OpenHandsTransportError(
                "authenticated route requires the openhands runtime profile"
            )
        self._intake = intake
        self._authenticated_binding = authenticated_binding

    @property
    def authenticated_binding(self) -> dict[str, str]:
        return self._authenticated_binding.binding()

    def route_intent(self, intent: dict[str, Any]) -> dict[str, Any]:
        return self._intake.route_intent(intent)
