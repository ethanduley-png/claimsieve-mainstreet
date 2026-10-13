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
