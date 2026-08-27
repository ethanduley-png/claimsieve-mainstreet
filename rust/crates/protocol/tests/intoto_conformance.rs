#![forbid(unsafe_code)]

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn vector_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vectors/in_toto_interop_v1.json")
}

fn load_vector() -> Value {
    let text = match fs::read_to_string(vector_path()) {
        Ok(value) => value,
        Err(error) => panic!("read in-toto conformance vector: {error}"),
    };
    match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => panic!("parse in-toto conformance vector: {error}"),
    }
}

fn assert_lower_sha256_hex(value: &str) {
    assert_eq!(value.len(), 64);
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    );
}

#[test]
fn in_toto_vector_has_only_supported_statement_and_predicate_versions() {
    let vector = load_vector();
    assert_eq!(vector["schema_version"], "claimsieve.intoto.conformance.v1");

    let statements = match vector["statements"].as_object() {
        Some(value) => value,
        None => panic!("statements must be an object"),
    };
    let expected = [
        (
            "permit",
            "https://claimsieve.example/attestation/authorization-permit/v0.1",
        ),
        (
            "execution",
            "https://claimsieve.example/attestation/execution-attempt/v0.1",
        ),
        (
            "observation",
            "https://claimsieve.example/attestation/outcome-observation/v0.1",
        ),
    ];

    for (name, predicate_type) in expected {
        let statement = &statements[name];
        assert_eq!(statement["_type"], "https://in-toto.io/Statement/v1");
        assert_eq!(statement["predicateType"], predicate_type);
        assert!(statement.get("payload").is_none());
        assert!(statement.get("payloadType").is_none());
        assert!(statement.get("signatures").is_none());

        let native = &statement["predicate"]["native_record"];
        assert_eq!(native["signature_format"], "claimsieve-native");
        assert_eq!(native["signature_verification"], "NOT_PERFORMED");

        let native_digest = match native["digest"].as_str() {
            Some(value) => value,
            None => panic!("native digest must be a string"),
        };
        let native_digest = match native_digest.strip_prefix("sha256:") {
            Some(value) => value,
            None => panic!("native digest must use sha256 prefix"),
        };
        assert_lower_sha256_hex(native_digest);
        assert_eq!(statement["subject"][0]["digest"]["sha256"], native_digest);
    }
}

#[test]
fn in_toto_action_subjects_match_predicate_bindings() {
    let vector = load_vector();
    let statements = &vector["statements"];

    for name in ["permit", "execution"] {
        let statement = &statements[name];
        let action = match statement["predicate"]["action_digest"].as_str() {
            Some(value) => value,
            None => panic!("action digest must be a string"),
        };
        let action = match action.strip_prefix("sha256:") {
            Some(value) => value,
            None => panic!("action digest must use sha256 prefix"),
        };
        assert_lower_sha256_hex(action);
        assert_eq!(statement["subject"][1]["digest"]["sha256"], action);
    }

    let observation = &statements["observation"];
    let observed = match observation["predicate"]["observed_action_digest"].as_str() {
        Some(value) => value,
        None => panic!("observed action digest must be a string"),
    };
    let observed = match observed.strip_prefix("sha256:") {
        Some(value) => value,
        None => panic!("observed action digest must use sha256 prefix"),
    };
    assert_lower_sha256_hex(observed);
    assert_eq!(observation["subject"][1]["digest"]["sha256"], observed);
}

#[test]
fn in_toto_vector_preserves_authorization_execution_and_observation_boundaries() {
    let vector = load_vector();
    let statements = &vector["statements"];

    assert_eq!(statements["permit"]["predicate"]["max_uses"], 1);
    assert_eq!(
        statements["permit"]["predicate"]["destination_digest"],
        vector["native"]["permit"]["destination_digest"]
    );
    assert_eq!(
        statements["execution"]["predicate"]["fencing_token"],
        vector["native"]["executor_receipt"]["fencing_token"]
    );
    assert_eq!(
        statements["execution"]["predicate"]["idempotency_key"],
        vector["native"]["executor_receipt"]["idempotency_key"]
    );
    assert_eq!(
        statements["observation"]["predicate"]["reconciliation"],
        vector["native"]["observer_receipt"]["reconciliation"]
    );
}
