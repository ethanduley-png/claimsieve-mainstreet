use claimsieve_refinement_candidate::{
    ExecutorClaim, Outcome, ProviderObservation, reconcile_from_independent_provider,
};
use std::{env, fs, io};

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn parse_claim(value: &str) -> Option<ExecutorClaim> {
    match value {
        "ExecutorAccepted" => Some(ExecutorClaim::ExecutorAccepted),
        "ExecutorRejected" => Some(ExecutorClaim::ExecutorRejected),
        "ExecutorTimeout" => Some(ExecutorClaim::ExecutorTimeout),
        "NoExecutorClaim" => Some(ExecutorClaim::NoExecutorClaim),
        _ => None,
    }
}

fn parse_observation(value: &str) -> Option<ProviderObservation> {
    match value {
        "NoProviderRecord" => Some(ProviderObservation::NoProviderRecord),
        "ProviderRejected" => Some(ProviderObservation::ProviderRejected),
        "ProviderAcceptedExact" => Some(ProviderObservation::ProviderAcceptedExact),
        "ProviderAcceptedDivergent" => Some(ProviderObservation::ProviderAcceptedDivergent),
        "ProviderConflicting" => Some(ProviderObservation::ProviderConflicting),
        _ => None,
    }
}

fn outcome_name(value: &Outcome) -> &'static str {
    match value {
        Outcome::ConfirmedSuccess => "ConfirmedSuccess",
        Outcome::ConfirmedFailure => "ConfirmedFailure",
        Outcome::DivergentEffect => "DivergentEffect",
        Outcome::Unknown => "OutcomeUnknown",
    }
}

fn main() -> io::Result<()> {
    let fixture_path = env::args_os().nth(1).ok_or_else(|| {
        invalid_input("usage: refinement_conformance <reconciliation-fixture.tsv>")
    })?;
    let fixture = fs::read_to_string(fixture_path)?;

    for (line_index, line) in fixture.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let fields: Vec<_> = line.split('\t').collect();
        let [case_id, claim_name, observation_name] = fields.as_slice() else {
            return Err(invalid_data(format!(
                "line {} must contain case_id, executor_claim, provider_observation",
                line_index + 1
            )));
        };

        let claim = parse_claim(claim_name).ok_or_else(|| {
            invalid_data(format!(
                "line {} has unknown executor claim {claim_name}",
                line_index + 1
            ))
        })?;
        let observation = parse_observation(observation_name).ok_or_else(|| {
            invalid_data(format!(
                "line {} has unknown provider observation {observation_name}",
                line_index + 1
            ))
        })?;
        let outcome = reconcile_from_independent_provider(claim, observation);
        println!("{case_id}\t{}", outcome_name(&outcome));
    }

    Ok(())
}
