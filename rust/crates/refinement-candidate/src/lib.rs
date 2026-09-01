#![forbid(unsafe_code)]
//! Narrow Rust candidate used only for cross-language refinement conformance.
//!
//! This crate is deliberately not wired into the production authority path.
//! It mirrors one audited Rocq decision function so continuous integration can
//! compare the Rust result with mechanically extracted OCaml behavior.

pub use claimsieve_durable_state::Outcome;

/// Executor self-report supplied to the reconciliation classifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutorClaim {
    /// Executor reports that the provider accepted the request.
    ExecutorAccepted,
    /// Executor reports that the provider rejected the request.
    ExecutorRejected,
    /// Executor reports that the provider response timed out.
    ExecutorTimeout,
    /// No executor claim is available.
    NoExecutorClaim,
}

/// Independent provider observation used to classify the external outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderObservation {
    /// No independent provider record exists.
    NoProviderRecord,
    /// Independent provider evidence establishes rejection.
    ProviderRejected,
    /// Independent provider evidence shows the exact authorized effect.
    ProviderAcceptedExact,
    /// Independent provider evidence shows a divergent effect.
    ProviderAcceptedDivergent,
    /// Independent provider evidence conflicts and cannot establish truth.
    ProviderConflicting,
}

/// Classify an outcome from independent provider evidence.
///
/// The executor claim is intentionally non-authoritative. This function is a
/// Rust refinement candidate for the Rocq function of the same name; it is not
/// yet the production reconciliation entry point.
#[must_use]
pub const fn reconcile_from_independent_provider(
    _claim: ExecutorClaim,
    observation: ProviderObservation,
) -> Outcome {
    match observation {
        ProviderObservation::NoProviderRecord | ProviderObservation::ProviderConflicting => {
            Outcome::Unknown
        }
        ProviderObservation::ProviderRejected => Outcome::ConfirmedFailure,
        ProviderObservation::ProviderAcceptedExact => Outcome::ConfirmedSuccess,
        ProviderObservation::ProviderAcceptedDivergent => Outcome::DivergentEffect,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_claim_never_changes_provider_derived_outcome() {
        let claims = [
            ExecutorClaim::ExecutorAccepted,
            ExecutorClaim::ExecutorRejected,
            ExecutorClaim::ExecutorTimeout,
            ExecutorClaim::NoExecutorClaim,
        ];
        let observations = [
            (ProviderObservation::NoProviderRecord, Outcome::Unknown),
            (
                ProviderObservation::ProviderRejected,
                Outcome::ConfirmedFailure,
            ),
            (
                ProviderObservation::ProviderAcceptedExact,
                Outcome::ConfirmedSuccess,
            ),
            (
                ProviderObservation::ProviderAcceptedDivergent,
                Outcome::DivergentEffect,
            ),
            (ProviderObservation::ProviderConflicting, Outcome::Unknown),
        ];

        for claim in claims {
            for (observation, expected) in &observations {
                assert_eq!(
                    reconcile_from_independent_provider(claim, *observation),
                    expected.clone()
                );
            }
        }
    }
}
