#![forbid(unsafe_code)]

//! Command-line verifier and cross-language outcome conformance runner.

use claimsieve_protocol::Reconciliation;
use claimsieve_runtime::classify_provider_observation;
use claimsieve_verifier::verify_json;
use serde_json::{Value, json};
use std::{env, fs, process::ExitCode};

fn usage() {
    eprintln!("usage: claimsieve verify <evidence-bundle.json> <trust-root.json>");
    eprintln!("       claimsieve outcome-vectors <vectors/outcome_semantics_vectors.json>");
}

fn run_vectors(path: &str) -> Result<String, String> {
    let input = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let doc: Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    if doc.get("schema_version").and_then(Value::as_str)
        != Some("claimsieve.outcome_semantics_vectors.v1")
    {
        return Err("unexpected conformance vector version".to_owned());
    }
    let intended = doc
        .get("intended_action_digest")
        .and_then(Value::as_str)
        .ok_or("missing intended action digest")?;
    let cases = doc
        .get("vectors")
        .and_then(Value::as_array)
        .ok_or("missing outcome vectors")?;
    let mut outputs = Vec::new();
    for case in cases {
        let id = case
            .get("id")
            .and_then(Value::as_str)
            .ok_or("missing vector id")?;
        let status = case.get("response_status").and_then(Value::as_str);
        let observed = case.get("observed_action_digest").and_then(Value::as_str);
        let (actual, conflict) =
            classify_provider_observation(status.unwrap_or(""), observed, intended);
        outputs.push(json!({
            "id": id,
            "actual_reconciliation": actual,
            "actual_conflict": conflict
        }));
    }
    serde_json::to_string_pretty(&outputs).map_err(|e| e.to_string())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() == 3 && args[1] == "outcome-vectors" {
        return match run_vectors(&args[2]) {
            Ok(result) => {
                println!("{result}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("native outcome vectors failed: {error}");
                ExitCode::from(2)
            }
        };
    }
    if args.len() != 4 || args[1] != "verify" {
        usage();
        return ExitCode::from(2);
    }
    let input = match fs::read_to_string(&args[2]) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed to read {}: {error}", args[2]);
            return ExitCode::from(2);
        }
    };
    let trust_root = match fs::read_to_string(&args[3]) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("failed to read {}: {error}", args[3]);
            return ExitCode::from(2);
        }
    };
    match verify_json(&input, &trust_root) {
        Ok(report) => {
            match serde_json::to_string_pretty(&report) {
                Ok(json) => println!("{json}"),
                Err(error) => {
                    eprintln!("failed to encode verification report: {error}");
                    return ExitCode::from(2);
                }
            }
            if report.valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(error) => {
            eprintln!("verification failed: {error}");
            ExitCode::from(2)
        }
    }
}
