"""Executable conformance oracle for ClaimSieve v0.33 independent-outcome hardening."""

from .canonical import canonical_bytes, digest
from .kernel import CampaignState, evaluate
from .runtime import (
    Authority,
    CampaignStateStore,
    ContainmentController,
    ContainmentView,
    Executor,
    Observer,
    ReservationStore,
)
from .ledger import Ledger
from .durable_state import (
    DurableStateService, DurableCampaignStateStore, DurableProvider, DurableProviderSimulator,
    DurableExecutor, IndependentObserver, QuorumStateMachineSimulator,
    DurableStateError, InjectedCrash, DispatchTicket,
)
from .verifier import verify_bundle
from .github_provider import GitHubIssueProvider, GitHubProviderError

__all__ = [
    "canonical_bytes", "digest", "CampaignState", "evaluate", "Authority",
    "CampaignStateStore", "ContainmentController", "ContainmentView", "Executor",
    "Observer", "ReservationStore", "Ledger", "verify_bundle",
    "DurableStateService", "DurableCampaignStateStore", "DurableProvider", "DurableProviderSimulator",
    "DurableExecutor", "IndependentObserver", "QuorumStateMachineSimulator",
    "DurableStateError", "InjectedCrash", "DispatchTicket",
    "GitHubIssueProvider", "GitHubProviderError",
]
