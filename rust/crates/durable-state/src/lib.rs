#![forbid(unsafe_code)]
//! Pure state-transition candidate retained for the v0.33 independent outcome boundary.
//!
//! This crate deliberately does not claim storage, cryptography, or consensus.
//! A production backend must implement the [`LinearizableStateStore`] trait
//! with durable single-copy semantics and authenticate executor and observer
//! commands before invoking these transitions.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

/// Durable execution phases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReservationPhase {
    /// Permit has been atomically reserved.
    Reserved,
    /// An authenticated executor owns the reservation.
    Executing,
    /// The local dispatch commit point has been crossed.
    Dispatching,
    /// Provider acknowledged the request; independent observation is pending.
    ProviderAcknowledged,
    /// Provider rejected the request; independent observation is pending.
    ProviderRejected,
    /// Provider response was ambiguous.
    OutcomeUnknown,
    /// Independent observation produced a terminal result.
    Reconciled,
}

/// Independently reconciled outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Outcome {
    /// External effect matches the authorized action.
    ConfirmedSuccess,
    /// Independent evidence shows the effect did not occur.
    ConfirmedFailure,
    /// An effect occurred but differs from the authorized action.
    DivergentEffect,
    /// Evidence remains insufficient to decide.
    Unknown,
}

/// One durable campaign record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CampaignRecord {
    /// Stable campaign identifier.
    pub campaign_id: String,
    /// Digest of the canonical campaign state.
    pub state_digest: String,
    /// Strictly increasing logical sequence.
    pub last_sequence: u64,
    /// Strictly increasing committed revision.
    pub revision: u64,
    /// Campaign suspension flag.
    pub suspended: bool,
}

/// One durable reservation record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReservationRecord {
    /// Stable reservation identifier.
    pub reservation_id: String,
    /// One-use permit identifier.
    pub permit_id: String,
    /// Campaign identifier.
    pub campaign_id: String,
    /// Exact action digest.
    pub action_digest: String,
    /// Exact provider request digest.
    pub request_digest: String,
    /// Resource-scoped fencing domain.
    pub resource_key: String,
    /// Provider idempotency key.
    pub idempotency_key: String,
    /// First sequence at which the permit is valid.
    pub valid_from_sequence: u64,
    /// Last sequence at which the permit is valid.
    pub expires_sequence: u64,
    /// Authenticated executor that owns the reservation, if claimed.
    pub executor_id: Option<String>,
    /// Monotonic fencing token.
    pub fencing_token: u64,
    /// Containment epoch observed at the dispatch point.
    pub containment_epoch: u64,
    /// Current durable phase.
    pub phase: ReservationPhase,
    /// Independently reconciled outcome, if any.
    pub outcome: Option<Outcome>,
}

/// In-memory transition model used for conformance fixtures.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableState {
    /// Campaigns by identifier.
    pub campaigns: BTreeMap<String, CampaignRecord>,
    /// Reservations by permit identifier.
    pub reservations: BTreeMap<String, ReservationRecord>,
    /// Revoked permit identifiers.
    pub revoked_permits: BTreeSet<String>,
    /// Global execution freeze.
    pub frozen: bool,
    /// Monotonic containment epoch.
    pub containment_epoch: u64,
    /// Next fencing token to allocate.
    pub next_fencing_token: u64,
}

/// Fail-closed transition error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DurableStateError {
    /// Campaign predecessor did not match the committed state.
    #[error("stale campaign predecessor")]
    StaleCampaignPredecessor,
    /// Campaign sequence was not a strict successor.
    #[error("campaign sequence is not a strict successor")]
    NonSuccessorSequence,
    /// Campaign is suspended.
    #[error("campaign suspended")]
    CampaignSuspended,
    /// Permit has been revoked.
    #[error("permit revoked")]
    PermitRevoked,
    /// Permit is outside its exact logical validity interval.
    #[error("permit outside validity sequence")]
    PermitOutsideValidity,
    /// Execution is globally frozen.
    #[error("execution frozen")]
    ExecutionFrozen,
    /// Permit already has a reservation.
    #[error("permit already reserved")]
    PermitAlreadyReserved,
    /// Reservation was not found.
    #[error("reservation not found")]
    ReservationNotFound,
    /// Executor command was not independently authenticated.
    #[error("executor authentication required")]
    ExecutorAuthenticationRequired,
    /// A different executor owns this reservation.
    #[error("executor ownership mismatch")]
    ExecutorOwnershipMismatch,
    /// Observer receipt was not independently authenticated.
    #[error("observer authentication required")]
    ObserverAuthenticationRequired,
    /// Transition is not valid from the current phase.
    #[error("invalid reservation transition")]
    InvalidReservationTransition,
    /// Terminal outcome cannot be rewritten.
    #[error("terminal outcome cannot be rewritten")]
    TerminalOutcomeRewrite,
    /// Fencing counter exhausted.
    #[error("fencing counter exhausted")]
    FencingCounterExhausted,
}

impl DurableState {
    /// Construct a state with the first legal fencing token set to one.
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_fencing_token: 1,
            ..Self::default()
        }
    }

    fn allocate_fence(&mut self) -> Result<u64, DurableStateError> {
        let token = self.next_fencing_token;
        self.next_fencing_token = self
            .next_fencing_token
            .checked_add(1)
            .ok_or(DurableStateError::FencingCounterExhausted)?;
        Ok(token)
    }

    fn valid_at(valid_from: u64, expires: u64, sequence: u64) -> bool {
        valid_from <= sequence && sequence <= expires
    }

    fn contain_campaign(&mut self, campaign_id: &str) {
        let already_suspended = self
            .campaigns
            .get(campaign_id)
            .is_some_and(|campaign| campaign.suspended);
        if !already_suspended {
            self.containment_epoch = self.containment_epoch.saturating_add(1);
        }
        let campaign = self
            .campaigns
            .entry(campaign_id.to_owned())
            .or_insert_with(|| CampaignRecord {
                campaign_id: campaign_id.to_owned(),
                state_digest: "GENESIS".to_owned(),
                last_sequence: 0,
                revision: 0,
                suspended: false,
            });
        campaign.suspended = true;
    }

    /// Commit exactly one campaign successor.
    pub fn commit_campaign_successor(
        &mut self,
        campaign_id: &str,
        expected_digest: &str,
        expected_sequence: u64,
        successor_digest: &str,
        successor_sequence: u64,
    ) -> Result<u64, DurableStateError> {
        let existing = self
            .campaigns
            .entry(campaign_id.to_owned())
            .or_insert_with(|| CampaignRecord {
                campaign_id: campaign_id.to_owned(),
                state_digest: "GENESIS".to_owned(),
                last_sequence: 0,
                revision: 0,
                suspended: false,
            });
        if existing.state_digest != expected_digest || existing.last_sequence != expected_sequence {
            return Err(DurableStateError::StaleCampaignPredecessor);
        }
        if successor_sequence <= existing.last_sequence {
            return Err(DurableStateError::NonSuccessorSequence);
        }
        if existing.suspended {
            return Err(DurableStateError::CampaignSuspended);
        }
        existing.state_digest = successor_digest.to_owned();
        existing.last_sequence = successor_sequence;
        existing.revision = existing.revision.saturating_add(1);
        Ok(existing.revision)
    }

    /// Atomically create one reservation and allocate its fencing token.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve(
        &mut self,
        permit_id: &str,
        campaign_id: &str,
        action_digest: &str,
        request_digest: &str,
        resource_key: &str,
        valid_from_sequence: u64,
        expires_sequence: u64,
        current_sequence: u64,
    ) -> Result<ReservationRecord, DurableStateError> {
        if self.frozen {
            return Err(DurableStateError::ExecutionFrozen);
        }
        if self.revoked_permits.contains(permit_id) {
            return Err(DurableStateError::PermitRevoked);
        }
        if !Self::valid_at(valid_from_sequence, expires_sequence, current_sequence) {
            return Err(DurableStateError::PermitOutsideValidity);
        }
        if self
            .campaigns
            .get(campaign_id)
            .is_some_and(|campaign| campaign.suspended)
        {
            return Err(DurableStateError::CampaignSuspended);
        }
        if self.reservations.contains_key(permit_id) {
            return Err(DurableStateError::PermitAlreadyReserved);
        }
        let fencing_token = self.allocate_fence()?;
        let record = ReservationRecord {
            reservation_id: format!("reservation:{permit_id}"),
            permit_id: permit_id.to_owned(),
            campaign_id: campaign_id.to_owned(),
            action_digest: action_digest.to_owned(),
            request_digest: request_digest.to_owned(),
            resource_key: resource_key.to_owned(),
            idempotency_key: permit_id.to_owned(),
            valid_from_sequence,
            expires_sequence,
            executor_id: None,
            fencing_token,
            containment_epoch: self.containment_epoch,
            phase: ReservationPhase::Reserved,
            outcome: None,
        };
        self.reservations
            .insert(permit_id.to_owned(), record.clone());
        Ok(record)
    }

    /// Move a reservation to authenticated executor-owned state.
    pub fn begin_execution(
        &mut self,
        permit_id: &str,
        executor_id: &str,
        executor_authenticated: bool,
    ) -> Result<(), DurableStateError> {
        if !executor_authenticated {
            return Err(DurableStateError::ExecutorAuthenticationRequired);
        }
        self.check_containment(permit_id)?;
        let record = self
            .reservations
            .get_mut(permit_id)
            .ok_or(DurableStateError::ReservationNotFound)?;
        if record.phase != ReservationPhase::Reserved {
            return Err(DurableStateError::InvalidReservationTransition);
        }
        record.executor_id = Some(executor_id.to_owned());
        record.phase = ReservationPhase::Executing;
        Ok(())
    }

    /// Cross the local dispatch commit point after rechecking identity and expiry.
    pub fn claim_dispatch(
        &mut self,
        permit_id: &str,
        executor_id: &str,
        executor_authenticated: bool,
        current_sequence: u64,
    ) -> Result<u64, DurableStateError> {
        if !executor_authenticated {
            return Err(DurableStateError::ExecutorAuthenticationRequired);
        }
        self.check_containment(permit_id)?;
        let record = self
            .reservations
            .get_mut(permit_id)
            .ok_or(DurableStateError::ReservationNotFound)?;
        if record.phase != ReservationPhase::Executing {
            return Err(DurableStateError::InvalidReservationTransition);
        }
        if record.executor_id.as_deref() != Some(executor_id) {
            return Err(DurableStateError::ExecutorOwnershipMismatch);
        }
        if !Self::valid_at(
            record.valid_from_sequence,
            record.expires_sequence,
            current_sequence,
        ) {
            return Err(DurableStateError::PermitOutsideValidity);
        }
        record.phase = ReservationPhase::Dispatching;
        record.containment_epoch = self.containment_epoch;
        Ok(record.fencing_token)
    }

    /// Revoke a permit and advance the containment epoch.
    pub fn revoke(&mut self, permit_id: &str) {
        self.containment_epoch = self.containment_epoch.saturating_add(1);
        self.revoked_permits.insert(permit_id.to_owned());
    }

    /// Freeze all future dispatch commit points.
    pub fn freeze(&mut self) {
        self.containment_epoch = self.containment_epoch.saturating_add(1);
        self.frozen = true;
    }

    /// Record an authenticated independently reconciled outcome.
    ///
    /// A divergent independently observed effect is a containment event: the
    /// affected campaign is suspended before this transition returns. Replaying
    /// the same terminal divergence is idempotent and does not advance the
    /// containment epoch again.
    pub fn reconcile(
        &mut self,
        permit_id: &str,
        outcome: Outcome,
        observer_authenticated: bool,
    ) -> Result<(), DurableStateError> {
        if !observer_authenticated {
            return Err(DurableStateError::ObserverAuthenticationRequired);
        }
        let record = self
            .reservations
            .get_mut(permit_id)
            .ok_or(DurableStateError::ReservationNotFound)?;
        let campaign_id = record.campaign_id.clone();
        if let Some(existing) = &record.outcome {
            if existing != &outcome {
                return Err(DurableStateError::TerminalOutcomeRewrite);
            }
            let should_contain = existing == &Outcome::DivergentEffect;
            if should_contain {
                self.contain_campaign(&campaign_id);
            }
            return Ok(());
        }
        let should_contain = outcome == Outcome::DivergentEffect;
        record.outcome = Some(outcome);
        record.phase = ReservationPhase::Reconciled;
        if should_contain {
            self.contain_campaign(&campaign_id);
        }
        Ok(())
    }

    fn check_containment(&self, permit_id: &str) -> Result<(), DurableStateError> {
        if self.frozen {
            return Err(DurableStateError::ExecutionFrozen);
        }
        if self.revoked_permits.contains(permit_id) {
            return Err(DurableStateError::PermitRevoked);
        }
        if let Some(reservation) = self.reservations.get(permit_id)
            && self
                .campaigns
                .get(&reservation.campaign_id)
                .is_some_and(|campaign| campaign.suspended)
        {
            return Err(DurableStateError::CampaignSuspended);
        }
        Ok(())
    }
}

/// Storage contract required from a production state service.
pub trait LinearizableStateStore {
    /// Execute one state transition as a durable linearizable operation.
    fn transact<T, F>(&self, operation: F) -> Result<T, DurableStateError>
    where
        F: FnOnce(&mut DurableState) -> Result<T, DurableStateError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reserve(state: &mut DurableState) -> Result<ReservationRecord, DurableStateError> {
        state.reserve("p", "c", "a", "r", "resource", 1, 10, 2)
    }

    #[test]
    fn second_reservation_is_rejected() {
        let mut state = DurableState::new();
        assert!(reserve(&mut state).is_ok());
        let second = reserve(&mut state);
        assert_eq!(second, Err(DurableStateError::PermitAlreadyReserved));
    }

    #[test]
    fn expired_permit_is_rejected_at_reservation() {
        let mut state = DurableState::new();
        let result = state.reserve("p", "c", "a", "r", "resource", 1, 10, 11);
        assert_eq!(result, Err(DurableStateError::PermitOutsideValidity));
    }

    #[test]
    fn unauthenticated_executor_is_rejected() {
        let mut state = DurableState::new();
        assert!(reserve(&mut state).is_ok());
        assert_eq!(
            state.begin_execution("p", "executor", false),
            Err(DurableStateError::ExecutorAuthenticationRequired)
        );
    }

    #[test]
    fn revocation_blocks_dispatch_before_commit_point() {
        let mut state = DurableState::new();
        assert!(reserve(&mut state).is_ok());
        assert!(state.begin_execution("p", "executor", true).is_ok());
        state.revoke("p");
        assert_eq!(
            state.claim_dispatch("p", "executor", true, 3),
            Err(DurableStateError::PermitRevoked)
        );
    }

    #[test]
    fn expiry_is_rechecked_at_dispatch() {
        let mut state = DurableState::new();
        assert!(reserve(&mut state).is_ok());
        assert!(state.begin_execution("p", "executor", true).is_ok());
        assert_eq!(
            state.claim_dispatch("p", "executor", true, 11),
            Err(DurableStateError::PermitOutsideValidity)
        );
    }

    #[test]
    fn unauthenticated_observer_is_rejected() {
        let mut state = DurableState::new();
        assert!(reserve(&mut state).is_ok());
        assert_eq!(
            state.reconcile("p", Outcome::ConfirmedSuccess, false),
            Err(DurableStateError::ObserverAuthenticationRequired)
        );
    }

    #[test]
    fn terminal_outcome_is_immutable() {
        let mut state = DurableState::new();
        assert!(reserve(&mut state).is_ok());
        assert!(
            state
                .reconcile("p", Outcome::ConfirmedSuccess, true)
                .is_ok()
        );
        assert_eq!(
            state.reconcile("p", Outcome::ConfirmedFailure, true),
            Err(DurableStateError::TerminalOutcomeRewrite)
        );
    }

    #[test]
    fn divergent_effect_suspends_campaign_and_blocks_new_reservation() {
        let mut state = DurableState::new();
        assert!(reserve(&mut state).is_ok());
        assert!(state.reconcile("p", Outcome::DivergentEffect, true).is_ok());
        assert!(
            state
                .campaigns
                .get("c")
                .is_some_and(|campaign| campaign.suspended)
        );
        assert_eq!(state.containment_epoch, 1);
        assert_eq!(
            state.reserve("p2", "c", "a2", "r2", "resource", 1, 10, 3),
            Err(DurableStateError::CampaignSuspended)
        );
    }

    #[test]
    fn divergent_effect_blocks_preexisting_executing_reservation() {
        let mut state = DurableState::new();
        assert!(reserve(&mut state).is_ok());
        assert!(
            state
                .reserve("p2", "c", "a2", "r2", "resource", 1, 10, 2)
                .is_ok()
        );
        assert!(state.begin_execution("p2", "executor-2", true).is_ok());
        assert!(state.reconcile("p", Outcome::DivergentEffect, true).is_ok());
        assert_eq!(
            state.claim_dispatch("p2", "executor-2", true, 3),
            Err(DurableStateError::CampaignSuspended)
        );
    }

    #[test]
    fn repeated_divergence_is_idempotent_for_containment_epoch() {
        let mut state = DurableState::new();
        assert!(reserve(&mut state).is_ok());
        assert!(state.reconcile("p", Outcome::DivergentEffect, true).is_ok());
        let contained_epoch = state.containment_epoch;
        assert!(state.reconcile("p", Outcome::DivergentEffect, true).is_ok());
        assert_eq!(state.containment_epoch, contained_epoch);
    }

    #[test]
    fn non_divergent_outcome_does_not_suspend_campaign() {
        let mut state = DurableState::new();
        assert!(reserve(&mut state).is_ok());
        assert!(
            state
                .reconcile("p", Outcome::ConfirmedFailure, true)
                .is_ok()
        );
        assert!(
            !state
                .campaigns
                .get("c")
                .is_some_and(|campaign| campaign.suspended)
        );
        assert_eq!(state.containment_epoch, 0);
    }
}
