#![forbid(unsafe_code)]

//! Command-line verifier for ClaimSieve evidence bundles.

use claimsieve_verifier::verify_json;
use std::{env, fs, process::ExitCode};

fn usage() {
    eprintln!("usage: claimsieve verify <evidence-bundle.json> <trust-root.json>");
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
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
