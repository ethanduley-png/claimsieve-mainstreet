"""Proposal-runtime adapters for MainStreet.

Runtime adapters remain on the untrusted proposal side of the ClaimSieve boundary.
They must not own provider credentials, permit-signing keys, executor keys, or
observer keys.
"""

from .claimsieve_intake import (
    ClaimSieveIntakeError,
    DeepAgentsFounderIntake,
    OpenHandsFounderIntake,
)
from .deepagents_adapter import (
    ClaimSieveRuntimeContext,
    ConsequentialToolIntent,
    DeepAgentsAdapterError,
    DeepAgentsProposalAdapter,
)
from .openhands_adapter import (
    PINNED_OPENHANDS_COMMIT,
    OpenHandsAdapterError,
    OpenHandsConsequentialIntent,
    OpenHandsProposalAdapter,
    OpenHandsRuntimeContext,
)
from .openhands_transport import (
    AuthenticatedRuntimeBinding,
    OpenHandsAuthenticatedRoute,
    OpenHandsTransportError,
)

__all__ = [
    "AuthenticatedRuntimeBinding",
    "ClaimSieveIntakeError",
    "ClaimSieveRuntimeContext",
    "ConsequentialToolIntent",
    "DeepAgentsAdapterError",
    "DeepAgentsFounderIntake",
    "DeepAgentsProposalAdapter",
    "OpenHandsAdapterError",
    "OpenHandsAuthenticatedRoute",
    "OpenHandsConsequentialIntent",
    "OpenHandsFounderIntake",
    "OpenHandsProposalAdapter",
    "OpenHandsRuntimeContext",
    "OpenHandsTransportError",
    "PINNED_OPENHANDS_COMMIT",
]
