#![forbid(unsafe_code)]
//! Composition tests for the public production reconciliation boundary.

use claimsieve_durable_state::{
    DurableState, DurableStateError, ExecutorReport, Outcome, ProviderObservation,
    ReservationPhase,
};

fn reserve(state: &mut DurableState, permit_id: &str) {
    state
        .reserve(
            permit_id,
            "campaign",
            "action",
            "request",
            "resource",
            1,
            10,
            2,
        )
        .expect("fixture reservation must succeed");
}

#[test]
fn unauthenticated_observation_is_rejected_without_mutation() {
    let mut state = DurableState::new();
    reserve(&mut state, "p1");
    let before = state.clone();

    let result = state.reconcile_observation(
        "p1",
        ExecutorReport::ExecutorAccepted,
        ProviderObservation::ProviderConflicting,
        false,
    );

    assert_eq!(
        result,
        Err(DurableStateError::ObserverAuthenticationRequired)
    );
    assert_eq!(state, before);
}

#[test]
fn unknown_observation_may_later_resolve() {
    let mut state = DurableState::new();
    reserve(&mut state, "p1");

    assert_eq!(
        state.reconcile_observation(
            "p1",
            ExecutorReport::ExecutorAccepted,
            ProviderObservation::NoProviderRecord,
            true,
        ),
        Ok(Outcome::Unknown)
    );
    assert_eq!(
        state.reservations["p1"].phase,
        ReservationPhase::OutcomeUnknown
    );

    assert_eq!(
        state.reconcile_observation(
            "p1",
            ExecutorReport::ExecutorRejected,
            ProviderObservation::ProviderAcceptedExact,
            true,
        ),
        Ok(Outcome::ConfirmedSuccess)
    );
    assert_eq!(
        state.reservations["p1"].outcome,
        Some(Outcome::ConfirmedSuccess)
    );
    assert_eq!(
        state.reservations["p1"].phase,
        ReservationPhase::Reconciled
    );
}

#[test]
fn terminal_outcome_cannot_be_rewritten_through_public_boundary() {
    let mut state = DurableState::new();
    reserve(&mut state, "p1");
    assert_eq!(
        state.reconcile_observation(
            "p1",
            ExecutorReport::ExecutorTimeout,
            ProviderObservation::ProviderAcceptedExact,
            true,
        ),
        Ok(Outcome::ConfirmedSuccess)
    );
    let terminal = state.clone();

    assert_eq!(
        state.reconcile_observation(
            "p1",
            ExecutorReport::ExecutorAccepted,
            ProviderObservation::ProviderRejected,
            true,
        ),
        Err(DurableStateError::TerminalOutcomeRewrite)
    );
    assert_eq!(state, terminal);
}

#[test]
fn divergent_observation_contains_campaign_and_blocks_existing_dispatch() {
    let mut state = DurableState::new();
    reserve(&mut state, "p1");
    reserve(&mut state, "p2");
    state
        .begin_execution("p2", "executor-2", true)
        .expect("fixture execution must begin");

    assert_eq!(
        state.reconcile_observation(
            "p1",
            ExecutorReport::ExecutorRejected,
            ProviderObservation::ProviderAcceptedDivergent,
            true,
        ),
        Ok(Outcome::DivergentEffect)
    );
    assert!(state.campaigns["campaign"].suspended);
    assert_eq!(state.containment_epoch, 1);
    assert_eq!(
        state.claim_dispatch("p2", "executor-2", true, 3),
        Err(DurableStateError::CampaignSuspended)
    );
}

#[test]
fn conflicting_evidence_is_unknown_and_contained() {
    let mut state = DurableState::new();
    reserve(&mut state, "p1");

    assert_eq!(
        state.reconcile_observation(
            "p1",
            ExecutorReport::NoExecutorClaim,
            ProviderObservation::ProviderConflicting,
            true,
        ),
        Ok(Outcome::Unknown)
    );
    assert_eq!(
        state.reservations["p1"].phase,
        ReservationPhase::OutcomeUnknown
    );
    assert!(state.campaigns["campaign"].suspended);
    assert_eq!(state.containment_epoch, 1);
    assert_eq!(
        state.reserve(
            "p2",
            "campaign",
            "action-2",
            "request-2",
            "resource",
            1,
            10,
            3,
        ),
        Err(DurableStateError::CampaignSuspended)
    );
}

#[test]
fn exact_success_does_not_force_containment() {
    let mut state = DurableState::new();
    reserve(&mut state, "p1");

    assert_eq!(
        state.reconcile_observation(
            "p1",
            ExecutorReport::ExecutorRejected,
            ProviderObservation::ProviderAcceptedExact,
            true,
        ),
        Ok(Outcome::ConfirmedSuccess)
    );
    assert!(!state.campaigns["campaign"].suspended);
    assert_eq!(state.containment_epoch, 0);
}
