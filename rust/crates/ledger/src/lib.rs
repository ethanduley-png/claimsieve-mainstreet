#![forbid(unsafe_code)]

//! Signed append-only hash chains for the four ClaimSieve ledgers.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use claimsieve_protocol::{ProtocolError, canonical_bytes, digest};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

/// Genesis previous hash.
pub const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Ledger errors.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// Protocol failure.
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Verification failure.
    #[error("ledger verification failed: {0}")]
    Verification(String),
}

/// Unsigned portion of a ledger record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UnsignedLedgerRecord {
    /// Schema version.
    pub schema_version: String,
    /// One of proposal, evidence, decision, execution.
    pub ledger_id: String,
    /// Zero-based record sequence.
    pub sequence: u64,
    /// Cross-ledger trace identifier.
    pub trace_id: String,
    /// Stable record type.
    pub record_type: String,
    /// Previous signed record hash.
    pub previous_hash: String,
    /// Record payload.
    pub payload: Value,
    /// Canonical payload digest.
    pub payload_hash: String,
    /// Writer verification-key identifier.
    pub writer_key_id: String,
}

/// Complete signed ledger record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LedgerRecord {
    /// Unsigned body fields flattened into the record.
    #[serde(flatten)]
    pub unsigned: UnsignedLedgerRecord,
    /// Domain-separated Ed25519 signature.
    pub signature: String,
    /// Digest over the unsigned body and signature.
    pub record_hash: String,
}

#[derive(Serialize)]
struct RecordHashSubject<'a> {
    #[serde(flatten)]
    unsigned: &'a UnsignedLedgerRecord,
    signature: &'a str,
}

fn signing_message<T: Serialize>(domain: &str, value: &T) -> Result<Vec<u8>, LedgerError> {
    let mut message = b"CLAIMSIEVE\0".to_vec();
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(&canonical_bytes(value)?);
    Ok(message)
}

fn sign(key: &SigningKey, domain: &str, value: &impl Serialize) -> Result<String, LedgerError> {
    let signature = key.sign(&signing_message(domain, value)?);
    Ok(format!(
        "ed25519:{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    ))
}

fn verify_signature(
    key: &VerifyingKey,
    domain: &str,
    value: &impl Serialize,
    encoded: &str,
) -> Result<(), LedgerError> {
    let Some(raw) = encoded.strip_prefix("ed25519:") else {
        return Err(LedgerError::Verification(
            "unsupported signature encoding".to_owned(),
        ));
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|error| LedgerError::Verification(error.to_string()))?;
    let signature = Signature::from_slice(&bytes)
        .map_err(|error| LedgerError::Verification(error.to_string()))?;
    key.verify(&signing_message(domain, value)?, &signature)
        .map_err(|error| LedgerError::Verification(error.to_string()))
}

/// In-memory ledger used by the reference service and tests.
#[derive(Clone)]
pub struct Ledger {
    ledger_id: String,
    writer_key_id: String,
    signing_key: SigningKey,
    records: Vec<LedgerRecord>,
}

impl Ledger {
    /// Construct an empty ledger.
    #[must_use]
    pub fn new(
        ledger_id: impl Into<String>,
        writer_key_id: impl Into<String>,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            ledger_id: ledger_id.into(),
            writer_key_id: writer_key_id.into(),
            signing_key,
            records: Vec::new(),
        }
    }

    /// Append and sign a record.
    pub fn append<T: Serialize>(
        &mut self,
        trace_id: impl Into<String>,
        record_type: impl Into<String>,
        payload: &T,
    ) -> Result<LedgerRecord, LedgerError> {
        let payload_value = serde_json::to_value(payload)
            .map_err(|error| ProtocolError::Serialization(error.to_string()))?;
        let unsigned = UnsignedLedgerRecord {
            schema_version: "claimsieve.ledger_record.v1".to_owned(),
            ledger_id: self.ledger_id.clone(),
            sequence: u64::try_from(self.records.len())
                .map_err(|_| LedgerError::Verification("ledger sequence overflow".to_owned()))?,
            trace_id: trace_id.into(),
            record_type: record_type.into(),
            previous_hash: self.records.last().map_or_else(
                || GENESIS_HASH.to_owned(),
                |record| record.record_hash.clone(),
            ),
            payload_hash: digest(&payload_value)?,
            payload: payload_value,
            writer_key_id: self.writer_key_id.clone(),
        };
        let signature = sign(&self.signing_key, "ledger-record-v1", &unsigned)?;
        let record_hash = digest(&RecordHashSubject {
            unsigned: &unsigned,
            signature: &signature,
        })?;
        let record = LedgerRecord {
            unsigned,
            signature,
            record_hash,
        };
        self.records.push(record.clone());
        Ok(record)
    }

    /// Borrow all records.
    #[must_use]
    pub fn records(&self) -> &[LedgerRecord] {
        &self.records
    }
}

/// Verify a complete ledger chain and all signatures.
pub fn verify_chain(
    records: &[LedgerRecord],
    expected_ledger_id: &str,
    public_keys: &BTreeMap<String, VerifyingKey>,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();
    let mut previous = GENESIS_HASH.to_owned();
    for (index, record) in records.iter().enumerate() {
        let expected_sequence = u64::try_from(index).unwrap_or(u64::MAX);
        if record.unsigned.schema_version != "claimsieve.ledger_record.v1" {
            errors.push(format!("record {index}: unsupported schema"));
        }
        if record.unsigned.ledger_id != expected_ledger_id {
            errors.push(format!("record {index}: ledger id mismatch"));
        }
        if record.unsigned.sequence != expected_sequence {
            errors.push(format!("record {index}: sequence mismatch"));
        }
        if record.unsigned.previous_hash != previous {
            errors.push(format!("record {index}: previous hash mismatch"));
        }
        match digest(&record.unsigned.payload) {
            Ok(value) if value == record.unsigned.payload_hash => {}
            Ok(_) => errors.push(format!("record {index}: payload hash mismatch")),
            Err(error) => errors.push(format!("record {index}: payload canonicalization: {error}")),
        }
        match public_keys.get(&record.unsigned.writer_key_id) {
            Some(key) => {
                if let Err(error) =
                    verify_signature(key, "ledger-record-v1", &record.unsigned, &record.signature)
                {
                    errors.push(format!("record {index}: signature invalid: {error}"));
                }
            }
            None => errors.push(format!("record {index}: unknown writer key")),
        }
        match digest(&RecordHashSubject {
            unsigned: &record.unsigned,
            signature: &record.signature,
        }) {
            Ok(value) if value == record.record_hash => {}
            Ok(_) => errors.push(format!("record {index}: record hash mismatch")),
            Err(error) => errors.push(format!(
                "record {index}: record hash canonicalization: {error}"
            )),
        }
        previous.clone_from(&record.record_hash);
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::{Ledger, verify_chain};
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use std::collections::BTreeMap;

    #[test]
    fn valid_chain_verifies() {
        let key = SigningKey::from_bytes(&[7_u8; 32]);
        let verifying = key.verifying_key();
        let mut ledger = Ledger::new("proposal", "proposal-key", key);
        assert!(
            ledger
                .append("trace", "PROPOSAL", &json!({"id": 1}))
                .is_ok()
        );
        let keys = BTreeMap::from([("proposal-key".to_owned(), verifying)]);
        assert!(verify_chain(ledger.records(), "proposal", &keys).is_ok());
    }
}
