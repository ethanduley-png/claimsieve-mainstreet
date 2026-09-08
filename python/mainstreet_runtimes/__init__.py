"""Proposal-runtime adapters for MainStreet.

Runtime adapters remain on the untrusted proposal side of the ClaimSieve boundary.
They must not own provider credentials, permit-signing keys, executor keys, or
observer keys.
"""

from .claimsieve_intake import ClaimSieveIntakeError, DeepAgentsFounderIntake
from .deepagents_adapter import (
    ClaimSieveRuntimeContext,
    ConsequentialToolIntent,
    DeepAgentsAdapterError,
    DeepAgentsProposalAdapter,
)
from .openhands_adapter import (
    OpenHandsAdapterError,
    OpenHandsConsequentialIntent,
    OpenHandsProposalAdapter,
    OpenHandsRuntimeContext,
)

__all__ = [
    "ClaimSieveIntakeError",
    "ClaimSieveRuntimeContext",
    "ConsequentialToolIntent",
    "DeepAgentsAdapterError",
    "DeepAgentsFounderIntake",
    "DeepAgentsProposalAdapter",
    "OpenHandsAdapterError",
    "OpenHandsConsequentialIntent",
    "OpenHandsProposalAdapter",
    "OpenHandsRuntimeContext",
]
