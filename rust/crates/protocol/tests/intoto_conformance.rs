//! Cross-language conformance checks for ClaimSieve in-toto interoperability vectors.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use std::error::Error;
    use std::fs;
    use std::io;
    use std::path::PathBuf;

    fn vector_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../vectors/in_toto_interop_v1.json")
    }

    fn invalid(message: &str) -> Box<dyn Error> {
        io::Error::other(message).into()
    }

    fn load_vector() -> Result<Value, Box<dyn Error>> {
        let text = fs::read_to_string(vector_path())?;
        Ok(serde_json::from_str(&text)?)
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
    fn in_toto_vector_has_only_supported_statement_and_predicate_versions()
    -> Result<(), Box<dyn Error>> {
        let vector = load_vector()?;
        assert_eq!(vector["schema_version"], "claimsieve.intoto.conformance.v1");

        let statements = vector["statements"]
            .as_object()
            .ok_or_else(|| invalid("statements must be an object"))?;
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

            let native_digest = native["digest"]
                .as_str()
                .ok_or_else(|| invalid("native digest must be a string"))?;
            let native_digest = native_digest
                .strip_prefix("sha256:")
                .ok_or_else(|| invalid("native digest must use sha256 prefix"))?;
            assert_lower_sha256_hex(native_digest);
            assert_eq!(statement["subject"][0]["digest"]["sha256"], native_digest);
        }
        Ok(())
    }

    #[test]
    fn in_toto_action_subjects_match_predicate_bindings() -> Result<(), Box<dyn Error>> {
        let vector = load_vector()?;
        let statements = &vector["statements"];

        for name in ["permit", "execution"] {
            let statement = &statements[name];
            let action = statement["predicate"]["action_digest"]
                .as_str()
                .ok_or_else(|| invalid("action digest must be a string"))?;
            let action = action
                .strip_prefix("sha256:")
                .ok_or_else(|| invalid("action digest must use sha256 prefix"))?;
            assert_lower_sha256_hex(action);
            assert_eq!(statement["subject"][1]["digest"]["sha256"], action);
        }

        let observation = &statements["observation"];
        let observed = observation["predicate"]["observed_action_digest"]
            .as_str()
            .ok_or_else(|| invalid("observed action digest must be a string"))?;
        let observed = observed
            .strip_prefix("sha256:")
            .ok_or_else(|| invalid("observed action digest must use sha256 prefix"))?;
        assert_lower_sha256_hex(observed);
        assert_eq!(observation["subject"][1]["digest"]["sha256"], observed);
        Ok(())
    }

    #[test]
    fn in_toto_vector_preserves_authorization_execution_and_observation_boundaries()
    -> Result<(), Box<dyn Error>> {
        let vector = load_vector()?;
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
        Ok(())
    }
}
