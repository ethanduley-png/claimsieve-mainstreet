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
from .operational_state import (
    DEFAULT_OPERATIONAL_STATE_BOUNDS,
    OperationalState,
    OperationalStateBounds,
    OperationalStateBoundsError,
    OperationalStateError,
    OperationalStatePatch,
    OperationalStateTransition,
    ProtectedOperationalStateError,
    StaleOperationalStateError,
    apply_operational_state_patch,
)

__all__ = [
    "ClaimSieveIntakeError",
    "ClaimSieveRuntimeContext",
    "ConsequentialToolIntent",
    "DeepAgentsAdapterError",
    "DeepAgentsFounderIntake",
    "DeepAgentsProposalAdapter",
    "DEFAULT_OPERATIONAL_STATE_BOUNDS",
    "OpenHandsAdapterError",
    "OpenHandsConsequentialIntent",
    "OpenHandsProposalAdapter",
    "OpenHandsRuntimeContext",
    "AuthenticatedRuntimeBinding",
    "OpenHandsAuthenticatedRoute",
    "OpenHandsFounderIntake",
    "OpenHandsTransportError",
    "PINNED_OPENHANDS_COMMIT",
    "OperationalState",
    "OperationalStateBounds",
    "OperationalStateBoundsError",
    "OperationalStateError",
    "OperationalStatePatch",
    "OperationalStateTransition",
    "ProtectedOperationalStateError",
    "StaleOperationalStateError",
    "apply_operational_state_patch",
]
