#![forbid(unsafe_code)]

//! Offline verification for portable ClaimSieve evidence bundles.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use claimsieve_ledger::{LedgerRecord, verify_chain};
use claimsieve_protocol::{
    Decision, Evidence, MAX_SAFE_INTEGER, ObserverReceipt, Permit, Policy, Proposal, action_digest,
    approval_digest, approval_signing_subject, canonical_bytes, destination_digest, digest,
    display_digest, evidence_root, parameter_digest, proposal_digest,
};
use claimsieve_runtime::verify_permit_signature;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use thiserror::Error;

/// Errors that prevent the verifier itself from processing a bundle.
#[derive(Debug, Error)]
pub enum VerifierError {
    /// JSON parsing failed.
    #[error("bundle JSON parsing failed: {0}")]
    Json(String),
}

/// Portable evidence-bundle manifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BundleManifest {
    /// Manifest schema version.
    pub schema_version: String,
    /// Release identifier.
    pub release_id: String,
    /// Trace identifier.
    pub trace_id: String,
    /// Canonicalization profile.
    pub canonical_profile: String,
    /// Hash algorithm.
    pub hash_algorithm: String,
    /// Signature algorithm.
    pub signature_algorithm: String,
    /// Identifier of the independently supplied trust root.
    pub trust_root_id: String,
    /// Expected ledger heads.
    pub ledger_heads: BTreeMap<String, Option<String>>,
    /// Expected ledger record counts.
    pub record_counts: BTreeMap<String, u64>,
    /// Digest of the manifest with this field omitted.
    pub bundle_digest: String,
}

/// Signed policy envelope carried by a v2 evidence bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPolicy {
    /// Envelope schema version.
    pub schema_version: String,
    /// Exact policy authorized by the signer.
    pub policy: Policy,
    /// Policy-authority verification-key identifier.
    pub signer_key_id: String,
    /// Domain-separated Ed25519 signature.
    pub signature: String,
}

/// Independently supplied role-scoped trust root.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustRoot {
    /// Trust-root schema version.
    pub schema_version: String,
    /// Stable trust-root identifier.
    pub root_id: String,
    /// Verification keys by identifier.
    pub keys: BTreeMap<String, String>,
    /// Allowed key identifiers by security role.
    pub roles: BTreeMap<String, Vec<String>>,
}

/// Release witness statement binding the complete manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessStatement {
    /// Witness statement schema version.
    pub schema_version: String,
    /// Digest of the complete bundle manifest.
    pub manifest_digest: String,
    /// Release identifier covered by the witness.
    pub release_id: String,
    /// Witness verification-key identifier.
    pub witness_key_id: String,
    /// Domain-separated Ed25519 signature.
    pub signature: String,
}

/// Complete portable evidence bundle.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceBundle {
    /// Schema version.
    pub schema_version: String,
    /// Cross-ledger trace identifier.
    pub trace_id: String,
    /// Proposal.
    pub proposal: Proposal,
    /// Signed policy envelope.
    pub signed_policy: SignedPolicy,
    /// Evidence records.
    pub evidence: Vec<Evidence>,
    /// Kernel decision.
    pub decision: Decision,
    /// Exact post-decision campaign state committed by the decision.
    pub campaign_state: Value,
    /// Optional one-use permit.
    pub permit: Option<Permit>,
    /// Four separate signed ledgers.
    pub ledgers: BTreeMap<String, Vec<LedgerRecord>>,
    /// Signed executor, observer, and containment receipts.
    pub receipts: Vec<Value>,
    /// Portable manifest.
    pub manifest: BundleManifest,
    /// Independent release witness statement.
    pub witness_statement: WitnessStatement,
}

/// Verification result. An empty error list means the bundle verified.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerificationReport {
    /// Whether all checks passed.
    pub valid: bool,
    /// Stable human-readable failures.
    pub errors: Vec<String>,
}

fn decode_public_key(encoded: &str) -> Result<VerifyingKey, String> {
    let raw = encoded
        .strip_prefix("ed25519-pub:")
        .ok_or_else(|| "unsupported public-key encoding".to_owned())?;
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|error| format!("invalid public-key base64: {error}"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "public key must be 32 bytes".to_owned())?;
    VerifyingKey::from_bytes(&array).map_err(|error| format!("invalid public key: {error}"))
}

fn decode_signature(encoded: &str) -> Result<Signature, String> {
    let raw = encoded
        .strip_prefix("ed25519:")
        .ok_or_else(|| "unsupported signature encoding".to_owned())?;
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|error| format!("invalid signature base64: {error}"))?;
    Signature::from_slice(&bytes).map_err(|error| format!("invalid signature: {error}"))
}

fn signing_message(domain: &str, value: &Value) -> Result<Vec<u8>, String> {
    let mut message = b"CLAIMSIEVE\0".to_vec();
    message.extend_from_slice(domain.as_bytes());
    message.push(0);
    message.extend_from_slice(&canonical_bytes(value).map_err(|error| error.to_string())?);
    Ok(message)
}

fn verify_value_signature(
    key: &VerifyingKey,
    domain: &str,
    unsigned: &Value,
    encoded: &str,
) -> Result<(), String> {
    let signature = decode_signature(encoded)?;
    let message = signing_message(domain, unsigned)?;
    key.verify(&message, &signature)
        .map_err(|error| format!("signature mismatch: {error}"))
}

fn public_keys(trust_root: &TrustRoot) -> (BTreeMap<String, VerifyingKey>, Vec<String>) {
    let mut keys = BTreeMap::new();
    let mut errors = Vec::new();
    for (key_id, encoded) in &trust_root.keys {
        match decode_public_key(encoded) {
            Ok(key) => {
                keys.insert(key_id.clone(), key);
            }
            Err(error) => errors.push(format!("public key {key_id}: {error}")),
        }
    }
    let unique_material = keys
        .values()
        .map(|key| *key.as_bytes())
        .collect::<BTreeSet<_>>();
    if unique_material.len() != keys.len() {
        errors.push("trust root reuses key material across key identifiers".to_owned());
    }
    for (role, key_ids) in &trust_root.roles {
        for key_id in key_ids {
            if !keys.contains_key(key_id) {
                errors.push(format!(
                    "trust-root role {role} references missing key {key_id}"
                ));
            }
        }
    }
    (keys, errors)
}

fn role_allows(trust_root: &TrustRoot, role: &str, key_id: &str) -> bool {
    trust_root
        .roles
        .get(role)
        .is_some_and(|key_ids| key_ids.iter().any(|candidate| candidate == key_id))
}

#[allow(clippy::too_many_arguments)]
fn verify_role_signature<T: Serialize>(
    artifact: &T,
    key_id: &str,
    signature: &str,
    role: &str,
    domain: &str,
    label: &str,
    trust_root: &TrustRoot,
    keys: &BTreeMap<String, VerifyingKey>,
) -> Vec<String> {
    if !role_allows(trust_root, role, key_id) {
        return vec![format!("{label} key is not trusted for role {role}")];
    }
    let Some(key) = keys.get(key_id) else {
        return vec![format!("{label} key is unavailable")];
    };
    let mut unsigned = match serde_json::to_value(artifact) {
        Ok(value) => value,
        Err(error) => return vec![format!("{label} serialization failed: {error}")],
    };
    let Some(object) = unsigned.as_object_mut() else {
        return vec![format!("{label} is not a JSON object")];
    };
    object.remove("signature");
    match verify_value_signature(key, domain, &unsigned, signature) {
        Ok(()) => Vec::new(),
        Err(error) => vec![format!("{label} signature invalid: {error}")],
    }
}

fn same_key_material(
    keys: &BTreeMap<String, VerifyingKey>,
    left: Option<&str>,
    right: Option<&str>,
) -> bool {
    match (
        left.and_then(|id| keys.get(id)),
        right.and_then(|id| keys.get(id)),
    ) {
        (Some(left_key), Some(right_key)) => left_key.as_bytes() == right_key.as_bytes(),
        _ => false,
    }
}

fn artifact_recorded<T: Serialize>(
    bundle: &EvidenceBundle,
    ledger_id: &str,
    record_type: &str,
    artifact: &T,
) -> Result<bool, String> {
    let artifact_value = serde_json::to_value(artifact)
        .map_err(|error| format!("artifact serialization failed: {error}"))?;
    let artifact_digest = digest(&artifact_value).map_err(|error| error.to_string())?;
    Ok(bundle
        .ledgers
        .get(ledger_id)
        .into_iter()
        .flatten()
        .any(|record| {
            record.unsigned.record_type == record_type
                && record.unsigned.payload_hash == artifact_digest
                && record.unsigned.payload == artifact_value
        }))
}

fn verify_receipt(
    receipt: &Value,
    keys: &BTreeMap<String, VerifyingKey>,
    trust_root: &TrustRoot,
    trace_id: &str,
    permit_id: Option<&str>,
) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(object) = receipt.as_object() else {
        return vec!["receipt must be a JSON object".to_owned()];
    };
    let schema = object
        .get("schema_version")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let (key_field, role, domain, requires_trace_binding, requires_permit_binding) = match schema {
        "claimsieve.executor_receipt.v1" => (
            "executor_key_id",
            "executor_signers",
            "executor-receipt-v1",
            true,
            true,
        ),
        "claimsieve.observer_receipt.v1" => (
            "observer_key_id",
            "observer_signers",
            "observer-receipt-v1",
            true,
            true,
        ),
        "claimsieve.observer_receipt.v2" => (
            "observer_key_id",
            "observer_signers",
            "observer-receipt-v2",
            false,
            true,
        ),
        "claimsieve.containment_receipt.v1" => (
            "controller_key_id",
            "containment_signers",
            "containment-v1",
            false,
            false,
        ),
        _ => return vec![format!("unsupported receipt schema: {schema}")],
    };
    if schema == "claimsieve.observer_receipt.v2"
        && serde_json::from_value::<ObserverReceipt>(receipt.clone()).is_err()
    {
        errors.push("observer receipt v2 fields do not exactly match schema".to_owned());
    }
    let Some(key_id) = object.get(key_field).and_then(Value::as_str) else {
        return vec![format!("receipt missing {key_field}")];
    };
    if !role_allows(trust_root, role, key_id) {
        errors.push(format!("receipt key is not trusted for role {role}"));
    }
    let Some(encoded_signature) = object.get("signature").and_then(Value::as_str) else {
        return vec!["receipt missing signature".to_owned()];
    };
    let mut unsigned_object = object.clone();
    unsigned_object.remove("signature");
    match keys.get(key_id) {
        Some(key) => {
            if let Err(error) = verify_value_signature(
                key,
                domain,
                &Value::Object(unsigned_object),
                encoded_signature,
            ) {
                errors.push(format!("invalid {schema} signature: {error}"));
            }
        }
        None => errors.push(format!("unknown receipt key: {key_id}")),
    }
    if requires_trace_binding && object.get("trace_id").and_then(Value::as_str) != Some(trace_id) {
        errors.push("receipt trace mismatch".to_owned());
    }
    if requires_permit_binding {
        match permit_id {
            Some(expected) if object.get("permit_id").and_then(Value::as_str) == Some(expected) => {
            }
            _ => errors.push("receipt permit mismatch".to_owned()),
        }
    }
    errors
}

fn verify_manifest(bundle: &EvidenceBundle) -> Vec<String> {
    let mut errors = Vec::new();
    if bundle.manifest.schema_version != "claimsieve.bundle_manifest.v2" {
        errors.push("unsupported bundle manifest schema".to_owned());
    }
    if bundle.manifest.trace_id != bundle.trace_id {
        errors.push("manifest trace mismatch".to_owned());
    }
    if bundle.manifest.canonical_profile != "claimsieve.restricted-json.v1" {
        errors.push("unsupported canonical profile".to_owned());
    }
    if bundle.manifest.hash_algorithm != "sha256" {
        errors.push("unsupported hash algorithm".to_owned());
    }
    if bundle.manifest.signature_algorithm != "ed25519" {
        errors.push("unsupported signature algorithm".to_owned());
    }
    let mut manifest_value = match serde_json::to_value(&bundle.manifest) {
        Ok(value) => value,
        Err(error) => {
            errors.push(format!("manifest serialization failed: {error}"));
            return errors;
        }
    };
    if let Some(object) = manifest_value.as_object_mut() {
        object.remove("bundle_digest");
    }
    match digest(&manifest_value) {
        Ok(expected) if expected == bundle.manifest.bundle_digest => {}
        Ok(_) => errors.push("manifest digest mismatch".to_owned()),
        Err(error) => errors.push(format!("manifest digest failed: {error}")),
    }
    for ledger_id in ["proposal", "evidence", "decision", "execution"] {
        let records = bundle
            .ledgers
            .get(ledger_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let expected_head = records.last().map(|record| record.record_hash.clone());
        if bundle.manifest.ledger_heads.get(ledger_id) != Some(&expected_head) {
            errors.push(format!("manifest ledger head mismatch: {ledger_id}"));
        }
        let count = u64::try_from(records.len()).unwrap_or(u64::MAX);
        if bundle.manifest.record_counts.get(ledger_id) != Some(&count) {
            errors.push(format!("manifest record count mismatch: {ledger_id}"));
        }
    }
    errors
}

struct StrictJsonValue(Value);

impl<'de> Deserialize<'de> for StrictJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJsonValue;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate keys or floating-point numbers")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue(Value::Null))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue(Value::Null))
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value.unsigned_abs() > MAX_SAFE_INTEGER {
                    return Err(E::custom("integer outside the safe canonical range"));
                }
                Ok(StrictJsonValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value > MAX_SAFE_INTEGER {
                    return Err(E::custom("integer outside the safe canonical range"));
                }
                Ok(StrictJsonValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, _value: f64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Err(E::custom("floating-point JSON values are forbidden"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(StrictJsonValue(Value::String(value)))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(StrictJsonValue(value)) =
                    sequence.next_element::<StrictJsonValue>()?
                {
                    values.push(value);
                }
                Ok(StrictJsonValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut object = serde_json::Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if object.contains_key(&key) {
                        return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
                    }
                    let StrictJsonValue(value) = map.next_value::<StrictJsonValue>()?;
                    object.insert(key, value);
                }
                Ok(StrictJsonValue(Value::Object(object)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn parse_strict(input: &str) -> Result<Value, VerifierError> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let StrictJsonValue(value) = StrictJsonValue::deserialize(&mut deserializer)
        .map_err(|error| VerifierError::Json(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| VerifierError::Json(error.to_string()))?;
    Ok(value)
}

/// Parse with duplicate-key and float rejection, then verify against an external trust root.
pub fn verify_json(
    input: &str,
    trust_root_input: &str,
) -> Result<VerificationReport, VerifierError> {
    let value = parse_strict(input)?;
    let bundle: EvidenceBundle =
        serde_json::from_value(value).map_err(|error| VerifierError::Json(error.to_string()))?;
    let trust_root: TrustRoot = serde_json::from_value(parse_strict(trust_root_input)?)
        .map_err(|error| VerifierError::Json(error.to_string()))?;
    Ok(verify_bundle(&bundle, &trust_root))
}

/// Verify a decoded evidence bundle without relying on internal databases.
#[must_use]
pub fn verify_bundle(bundle: &EvidenceBundle, trust_root: &TrustRoot) -> VerificationReport {
    let mut errors = Vec::new();
    if bundle.schema_version != "claimsieve.evidence_bundle.v2" {
        errors.push("unsupported evidence bundle schema".to_owned());
    }
    if trust_root.schema_version != "claimsieve.trust_root.v1" {
        errors.push("unsupported trust root schema".to_owned());
    }
    if bundle.manifest.trust_root_id != trust_root.root_id {
        errors.push("manifest trust-root binding mismatch".to_owned());
    }
    if bundle.trace_id != bundle.proposal.trace_id {
        errors.push("bundle trace does not match proposal".to_owned());
    }
    if bundle.decision.trace_id != bundle.proposal.trace_id {
        errors.push("decision trace does not match proposal".to_owned());
    }
    if bundle.proposal.tenant_id != bundle.signed_policy.policy.tenant_id {
        errors.push("proposal tenant does not match policy".to_owned());
    }
    if !bundle
        .signed_policy
        .policy
        .allowed_principals
        .iter()
        .any(|principal| principal == &bundle.proposal.principal)
    {
        errors.push("proposal principal is not allowed by policy".to_owned());
    }
    match digest(&bundle.campaign_state) {
        Ok(value) if value == bundle.decision.campaign_state_digest => {}
        Ok(_) => errors.push("decision campaign-state digest mismatch".to_owned()),
        Err(error) => errors.push(format!("campaign-state digest failed: {error}")),
    }
    if bundle
        .campaign_state
        .get("campaign_id")
        .and_then(Value::as_str)
        != Some(bundle.proposal.campaign_id.as_str())
    {
        errors.push("campaign state identifier mismatch".to_owned());
    }
    if bundle.permit.is_some()
        && bundle.campaign_state.get("status").and_then(Value::as_str) != Some("ACTIVE")
    {
        errors.push("permit issued for non-active campaign state".to_owned());
    }
    match proposal_digest(&bundle.proposal) {
        Ok(value) if value == bundle.decision.proposal_digest => {}
        Ok(_) => errors.push("decision proposal digest mismatch".to_owned()),
        Err(error) => errors.push(format!("proposal digest failed: {error}")),
    }
    match approval_digest(&bundle.proposal) {
        Ok(value) if value == bundle.decision.approval_digest => {}
        Ok(_) => errors.push("decision human approval digest mismatch".to_owned()),
        Err(error) => errors.push(format!("decision approval digest failed: {error}")),
    }
    match digest(&bundle.signed_policy.policy) {
        Ok(value) if value == bundle.decision.policy_digest => {}
        Ok(_) => errors.push("decision policy digest mismatch".to_owned()),
        Err(error) => errors.push(format!("policy digest failed: {error}")),
    }
    match evidence_root(&bundle.evidence) {
        Ok(value) if value == bundle.decision.evidence_root => {}
        Ok(_) => errors.push("decision evidence root mismatch".to_owned()),
        Err(error) => errors.push(format!("decision evidence root failed: {error}")),
    }
    if !bundle
        .decision
        .prior_campaign_state_digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        })
    {
        errors.push("decision predecessor campaign-state commitment missing".to_owned());
    }

    let evidence_digests = bundle
        .evidence
        .iter()
        .map(digest)
        .collect::<Result<Vec<_>, _>>();
    match evidence_digests {
        Ok(digests) => {
            let available = digests.iter().cloned().collect::<BTreeSet<_>>();
            let referenced = bundle
                .proposal
                .evidence_refs
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>();
            if available.len() != digests.len()
                || referenced.len() != bundle.proposal.evidence_refs.len()
                || available != referenced
            {
                errors.push(
                    "proposal evidence references do not exactly match the snapshot".to_owned(),
                );
            }
        }
        Err(error) => errors.push(format!("evidence digest failed: {error}")),
    }

    let (keys, key_errors) = public_keys(trust_root);
    errors.extend(key_errors);

    if bundle.signed_policy.schema_version != "claimsieve.signed_policy.v1" {
        errors.push("unsupported signed policy schema".to_owned());
    }
    errors.extend(verify_role_signature(
        &bundle.signed_policy,
        &bundle.signed_policy.signer_key_id,
        &bundle.signed_policy.signature,
        "policy_signers",
        "signed-policy-v1",
        "signed policy",
        trust_root,
        &keys,
    ));
    for item in &bundle.evidence {
        if item.schema_version != "claimsieve.evidence.v1" {
            errors.push("unsupported evidence schema".to_owned());
        }
        let signer_allowed_for_type = bundle
            .signed_policy
            .policy
            .trusted_evidence_key_ids
            .get(&item.evidence_type)
            .is_some_and(|key_ids| key_ids.iter().any(|key_id| key_id == &item.issuer_key_id));
        if !signer_allowed_for_type {
            errors.push(format!(
                "evidence signer is not trusted for {}",
                item.evidence_type
            ));
        }
        errors.extend(verify_role_signature(
            item,
            &item.issuer_key_id,
            &item.signature,
            "evidence_signers",
            "evidence-v1",
            "evidence",
            trust_root,
            &keys,
        ));
    }

    if let Some(approval) = &bundle.proposal.approval {
        if approval.schema_version != "claimsieve.approval.v1" {
            errors.push("unsupported human approval schema".to_owned());
        }
        if !approval.approver.starts_with("spiffe://") {
            errors.push("human approval identity invalid".to_owned());
        }
        if !bundle
            .signed_policy
            .policy
            .allowed_approver_identities
            .iter()
            .any(|identity| identity == &approval.approver)
        {
            errors.push("human approval identity not allowed by policy".to_owned());
        }
        match proposal_digest(&bundle.proposal) {
            Ok(expected) if expected == approval.proposal_digest => {}
            Ok(_) => errors.push("human approval proposal digest mismatch".to_owned()),
            Err(error) => errors.push(format!("human approval proposal digest failed: {error}")),
        }
        match display_digest(&bundle.proposal) {
            Ok(expected) if expected == approval.display_digest => {}
            Ok(_) => errors.push("human approval display digest mismatch".to_owned()),
            Err(error) => errors.push(format!("human approval display digest failed: {error}")),
        }
        if approval.approved_at_seq > bundle.decision.decided_at_seq
            || approval.expires_at_seq < bundle.decision.decided_at_seq
            || approval.expires_at_seq < approval.approved_at_seq
        {
            errors.push("human approval sequence invalid".to_owned());
        }
        if !bundle
            .signed_policy
            .policy
            .allowed_approver_key_ids
            .iter()
            .any(|key_id| key_id == &approval.approver_key_id)
        {
            errors.push("human approval key not allowed by policy".to_owned());
        }
        if !role_allows(trust_root, "approval_signers", &approval.approver_key_id) {
            errors.push("human approval key is not trusted for its role".to_owned());
        }
        match (
            keys.get(&approval.approver_key_id),
            approval_signing_subject(approval),
        ) {
            (Some(key), Ok(subject)) => {
                if verify_value_signature(key, "approval-v1", &subject, &approval.signature)
                    .is_err()
                {
                    errors.push("human approval signature invalid".to_owned());
                }
            }
            (None, _) => errors.push("human approval key missing".to_owned()),
            (_, Err(error)) => errors.push(format!("human approval subject failed: {error}")),
        }
    }

    if let Some(permit) = &bundle.permit {
        if !role_allows(trust_root, "authority_signers", &permit.authority_key_id) {
            errors.push("permit authority key is not trusted for its role".to_owned());
        }
        match keys.get(&permit.authority_key_id) {
            Some(key) => {
                if let Err(error) = verify_permit_signature(permit, key) {
                    errors.push(format!("permit signature invalid: {error}"));
                }
            }
            None => errors.push("permit authority key missing".to_owned()),
        }
        let bindings = [
            (
                "trace_id",
                permit.trace_id.clone(),
                bundle.proposal.trace_id.clone(),
            ),
            (
                "tenant_id",
                permit.tenant_id.clone(),
                bundle.proposal.tenant_id.clone(),
            ),
            (
                "campaign_id",
                permit.campaign_id.clone(),
                bundle.proposal.campaign_id.clone(),
            ),
            (
                "principal",
                permit.principal.clone(),
                bundle.proposal.principal.clone(),
            ),
        ];
        for (name, actual, expected) in bindings {
            if actual != expected {
                errors.push(format!("permit binding mismatch: {name}"));
            }
        }
        let derived = [
            (
                "proposal_digest",
                proposal_digest(&bundle.proposal),
                &permit.proposal_digest,
            ),
            (
                "action_digest",
                action_digest(&bundle.proposal),
                &permit.action_digest,
            ),
            (
                "destination_digest",
                destination_digest(&bundle.proposal),
                &permit.destination_digest,
            ),
            (
                "parameter_digest",
                parameter_digest(&bundle.proposal),
                &permit.parameter_digest,
            ),
            (
                "policy_digest",
                digest(&bundle.signed_policy.policy),
                &permit.policy_digest,
            ),
            (
                "evidence_root",
                evidence_root(&bundle.evidence),
                &permit.evidence_root,
            ),
            (
                "decision_digest",
                digest(&bundle.decision),
                &permit.decision_digest,
            ),
        ];
        for (name, result, actual) in derived {
            match result {
                Ok(expected) if expected == *actual => {}
                Ok(_) => errors.push(format!("permit binding mismatch: {name}")),
                Err(error) => errors.push(format!("permit {name} derivation failed: {error}")),
            }
        }
        match approval_digest(&bundle.proposal) {
            Ok(value) if value == permit.approval_digest => {}
            Ok(_) => errors.push("permit binding mismatch: approval_digest".to_owned()),
            Err(error) => errors.push(format!("approval digest failed: {error}")),
        }
        match digest(&bundle.signed_policy) {
            Ok(value) if value == permit.signed_policy_digest => {}
            Ok(_) => errors.push("permit binding mismatch: signed_policy_digest".to_owned()),
            Err(error) => errors.push(format!("signed policy digest failed: {error}")),
        }
        if permit.prior_campaign_state_digest != bundle.decision.prior_campaign_state_digest {
            errors.push("permit binding mismatch: prior_campaign_state_digest".to_owned());
        }
        if permit.campaign_state_digest != bundle.decision.campaign_state_digest {
            errors.push("permit binding mismatch: campaign_state_digest".to_owned());
        }
        if permit.max_uses != 1 {
            errors.push("permit max_uses must equal one".to_owned());
        }
        if permit.valid_from_seq != bundle.decision.decided_at_seq {
            errors.push("permit binding mismatch: valid_from_seq".to_owned());
        }
        match permit.expires_at_seq.checked_sub(permit.valid_from_seq) {
            Some(duration) if (1..=5).contains(&duration) => {}
            _ => errors.push("permit validity window invalid".to_owned()),
        }
    }

    let expected_ledgers = ["proposal", "evidence", "decision", "execution"]
        .into_iter()
        .collect::<BTreeSet<_>>();
    let actual_ledgers = bundle
        .ledgers
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_ledgers != expected_ledgers {
        errors.push("bundle must contain exactly four named ledgers".to_owned());
    }
    for (ledger_id, writer_role) in [
        ("proposal", "proposal_ledger_writers"),
        ("evidence", "evidence_ledger_writers"),
        ("decision", "decision_ledger_writers"),
        ("execution", "execution_ledger_writers"),
    ] {
        let records = bundle
            .ledgers
            .get(ledger_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        if let Err(chain_errors) = verify_chain(records, ledger_id, &keys) {
            errors.extend(
                chain_errors
                    .into_iter()
                    .map(|error| format!("{ledger_id} ledger: {error}")),
            );
        }
        for record in records {
            if !role_allows(trust_root, writer_role, &record.unsigned.writer_key_id) {
                errors.push(format!(
                    "{ledger_id} ledger writer is outside external trust root"
                ));
            }
        }
        if !records
            .iter()
            .any(|record| record.unsigned.trace_id == bundle.trace_id)
        {
            errors.push(format!("missing trace in {ledger_id} ledger"));
        }
    }

    for (ledger_id, record_type, label, recorded) in [
        (
            "proposal",
            "PROPOSAL_SUBMITTED",
            "proposal",
            artifact_recorded(bundle, "proposal", "PROPOSAL_SUBMITTED", &bundle.proposal),
        ),
        (
            "decision",
            "DECISION_RECORDED",
            "decision",
            artifact_recorded(bundle, "decision", "DECISION_RECORDED", &bundle.decision),
        ),
    ] {
        match recorded {
            Ok(true) => {}
            Ok(false) => errors.push(format!(
                "{label} is not recorded in the {ledger_id} ledger as {record_type}"
            )),
            Err(error) => errors.push(format!("{label} ledger binding failed: {error}")),
        }
    }
    match artifact_recorded(
        bundle,
        "decision",
        "SIGNED_POLICY_RECORDED",
        &bundle.signed_policy,
    ) {
        Ok(true) => {}
        Ok(false) => errors.push("signed policy is not recorded in the decision ledger".to_owned()),
        Err(error) => errors.push(format!("signed policy ledger binding failed: {error}")),
    }
    for item in &bundle.evidence {
        match artifact_recorded(bundle, "evidence", "EVIDENCE_RECORDED", item) {
            Ok(true) => {}
            Ok(false) => {
                errors.push("evidence item is not recorded in the evidence ledger".to_owned())
            }
            Err(error) => errors.push(format!("evidence ledger binding failed: {error}")),
        }
    }
    if let Some(permit) = &bundle.permit {
        match artifact_recorded(bundle, "decision", "PERMIT_ISSUED", permit) {
            Ok(true) => {}
            Ok(false) => errors.push("permit is not recorded in the decision ledger".to_owned()),
            Err(error) => errors.push(format!("permit ledger binding failed: {error}")),
        }
    }

    let mut reserved = BTreeSet::new();
    let mut matching_reservations: Vec<&Value> = Vec::new();
    if let Some(execution) = bundle.ledgers.get("execution") {
        for record in execution {
            if record.unsigned.record_type == "PERMIT_RESERVED"
                && let Some(reserved_permit_id) = record
                    .unsigned
                    .payload
                    .get("permit_id")
                    .and_then(Value::as_str)
            {
                if !reserved.insert(reserved_permit_id.to_owned()) {
                    errors.push(format!(
                        "duplicate permit reservation: {reserved_permit_id}"
                    ));
                }
                if bundle
                    .permit
                    .as_ref()
                    .is_some_and(|permit| permit.permit_id == reserved_permit_id)
                {
                    matching_reservations.push(&record.unsigned.payload);
                }
            }
        }
    }

    let permit_id = bundle
        .permit
        .as_ref()
        .map(|permit| permit.permit_id.as_str());
    for receipt in &bundle.receipts {
        errors.extend(verify_receipt(
            receipt,
            &keys,
            trust_root,
            &bundle.trace_id,
            permit_id,
        ));
        let record_type = match receipt.get("schema_version").and_then(Value::as_str) {
            Some("claimsieve.executor_receipt.v1") => Some("EXECUTOR_RECEIPT"),
            Some("claimsieve.observer_receipt.v1") | Some("claimsieve.observer_receipt.v2") => {
                Some("OBSERVER_RECEIPT")
            }
            Some("claimsieve.containment_receipt.v1") => Some("CONTAINMENT_RECEIPT"),
            _ => None,
        };
        if let Some(record_type) = record_type {
            match artifact_recorded(bundle, "execution", record_type, receipt) {
                Ok(true) => {}
                Ok(false) => {
                    errors.push("signed receipt is not recorded in the execution ledger".to_owned())
                }
                Err(error) => errors.push(format!("receipt ledger binding failed: {error}")),
            }
        }
    }

    if let Some(permit) = &bundle.permit {
        if !bundle.receipts.is_empty() && matching_reservations.len() != 1 {
            errors.push("executed permit must have exactly one reservation".to_owned());
        }
        if let Some(reservation) = matching_reservations.first()
            && reservation.get("action_digest").and_then(Value::as_str)
                != Some(permit.action_digest.as_str())
        {
            errors.push("reservation action digest mismatch".to_owned());
        }

        let executor_receipts = bundle
            .receipts
            .iter()
            .filter(|receipt| {
                receipt.get("schema_version").and_then(Value::as_str)
                    == Some("claimsieve.executor_receipt.v1")
            })
            .collect::<Vec<_>>();
        let observer_receipts = bundle
            .receipts
            .iter()
            .filter(|receipt| {
                receipt
                    .get("schema_version")
                    .and_then(Value::as_str)
                    .is_some_and(|schema| {
                        matches!(
                            schema,
                            "claimsieve.observer_receipt.v1" | "claimsieve.observer_receipt.v2"
                        )
                    })
            })
            .collect::<Vec<_>>();
        if !bundle.receipts.is_empty()
            && (executor_receipts.len() != 1 || observer_receipts.len() != 1)
        {
            errors
                .push("executed permit requires one executor and one observer receipt".to_owned());
        }
        if let Some(executor_receipt) = executor_receipts.first() {
            if executor_receipt
                .get("action_digest")
                .and_then(Value::as_str)
                != Some(permit.action_digest.as_str())
            {
                errors.push("executor receipt action digest mismatch".to_owned());
            }
            if let Some(reservation) = matching_reservations.first()
                && executor_receipt
                    .get("reservation_id")
                    .and_then(Value::as_str)
                    != reservation.get("reservation_id").and_then(Value::as_str)
            {
                errors.push("executor receipt reservation mismatch".to_owned());
            }
        }
        if let Some(observer_receipt) = observer_receipts.first() {
            let schema = observer_receipt
                .get("schema_version")
                .and_then(Value::as_str);
            let reconciliation = observer_receipt
                .get("reconciliation")
                .and_then(Value::as_str);
            let observed = observer_receipt
                .get("observed_action_digest")
                .and_then(Value::as_str);
            if schema == Some("claimsieve.observer_receipt.v2") {
                if observer_receipt.get("permit_id").and_then(Value::as_str)
                    != Some(permit.permit_id.as_str())
                {
                    errors.push("observer receipt permit mismatch".to_owned());
                }
                if observer_receipt.get("campaign_id").and_then(Value::as_str)
                    != Some(permit.campaign_id.as_str())
                {
                    errors.push("observer receipt campaign mismatch".to_owned());
                }
                if let Some(reservation) = matching_reservations.first() {
                    if observer_receipt
                        .get("reservation_id")
                        .and_then(Value::as_str)
                        != reservation.get("reservation_id").and_then(Value::as_str)
                    {
                        errors.push("observer receipt reservation mismatch".to_owned());
                    }
                } else {
                    errors.push("observer receipt reservation mismatch".to_owned());
                }
                let provider_record_digest = observer_receipt
                    .get("provider_record_digest")
                    .and_then(Value::as_str);
                let receipt_conflict = observer_receipt
                    .get("receipt_conflict")
                    .and_then(Value::as_bool);
                if provider_record_digest.is_none() {
                    if reconciliation != Some("OUTCOME_UNKNOWN") {
                        errors.push(
                            "observer receipt without provider record must remain OUTCOME_UNKNOWN"
                                .to_owned(),
                        );
                    }
                    if observed.is_some() {
                        errors.push(
                            "observer receipt without provider record cannot contain observed action"
                                .to_owned(),
                        );
                    }
                    if receipt_conflict != Some(false) {
                        errors.push(
                            "observer receipt without provider record cannot claim conflict"
                                .to_owned(),
                        );
                    }
                }
                if matches!(
                    reconciliation,
                    Some("CONFIRMED_SUCCESS" | "CONFIRMED_FAILURE" | "DIVERGENT_EFFECT")
                ) && provider_record_digest.is_none()
                {
                    errors.push(
                        "confirmed observer outcome requires provider record digest".to_owned(),
                    );
                }
                if receipt_conflict == Some(true) && provider_record_digest.is_none() {
                    errors.push(
                        "observer receipt conflict requires provider record digest".to_owned(),
                    );
                }
            }
            match digest(&bundle.proposal.action) {
                Ok(exact_action_digest) => match reconciliation {
                    Some("CONFIRMED_SUCCESS") if observed != Some(exact_action_digest.as_str()) => {
                        errors.push(
                            "successful observation does not match authorized action".to_owned(),
                        );
                    }
                    Some("DIVERGENT_EFFECT")
                        if observed.is_none() || observed == Some(exact_action_digest.as_str()) =>
                    {
                        errors.push(
                            "divergent observation lacks a divergent action digest".to_owned(),
                        );
                    }
                    Some("CONFIRMED_FAILURE") if observed.is_some() => {
                        errors.push(
                            "failed observation unexpectedly contains an action digest".to_owned(),
                        );
                    }
                    Some("OUTCOME_UNKNOWN") if observed.is_some() => {
                        let conflict = observer_receipt
                            .get("receipt_conflict")
                            .and_then(Value::as_bool);
                        if schema != Some("claimsieve.observer_receipt.v2")
                            || conflict != Some(true)
                        {
                            errors.push(
                                "unknown observation contains an action digest without conflict evidence"
                                    .to_owned(),
                            );
                        }
                    }
                    Some(
                        "CONFIRMED_SUCCESS" | "CONFIRMED_FAILURE" | "DIVERGENT_EFFECT"
                        | "OUTCOME_UNKNOWN",
                    ) => {}
                    _ => errors.push("observer receipt reconciliation is invalid".to_owned()),
                },
                Err(error) => errors.push(format!("authorized action digest failed: {error}")),
            }
        }
        if let (Some(executor_receipt), Some(observer_receipt)) =
            (executor_receipts.first(), observer_receipts.first())
            && observer_receipt
                .get("schema_version")
                .and_then(Value::as_str)
                == Some("claimsieve.observer_receipt.v1")
        {
            match digest(*executor_receipt) {
                Ok(expected)
                    if observer_receipt
                        .get("executor_receipt_digest")
                        .and_then(Value::as_str)
                        == Some(expected.as_str()) => {}
                Ok(_) => {
                    errors.push("observer receipt is not bound to executor receipt".to_owned())
                }
                Err(error) => errors.push(format!("executor receipt digest failed: {error}")),
            }
            let status = executor_receipt
                .get("provider_status")
                .and_then(Value::as_str);
            let reconciliation = observer_receipt
                .get("reconciliation")
                .and_then(Value::as_str);
            let compatible = matches!(
                (status, reconciliation),
                (Some("accepted"), Some("CONFIRMED_SUCCESS"))
                    | (Some("accepted"), Some("DIVERGENT_EFFECT"))
                    | (Some("accepted"), Some("OUTCOME_UNKNOWN"))
                    | (Some("rejected"), Some("CONFIRMED_FAILURE"))
                    | (Some("timeout_unknown"), Some("OUTCOME_UNKNOWN"))
            );
            if !compatible {
                errors.push("provider status and observer reconciliation disagree".to_owned());
            }
        }
    }

    let mut roles = BTreeMap::<String, String>::new();
    for ledger_id in ["proposal", "evidence", "decision", "execution"] {
        let writer_ids = bundle
            .ledgers
            .get(ledger_id)
            .into_iter()
            .flatten()
            .map(|record| record.unsigned.writer_key_id.clone())
            .collect::<BTreeSet<_>>();
        if writer_ids.len() == 1 {
            if let Some(writer_id) = writer_ids.into_iter().next() {
                roles.insert(format!("ledger:{ledger_id}"), writer_id);
            }
        } else {
            errors.push(format!(
                "{ledger_id} ledger must use exactly one writer security role"
            ));
        }
    }
    if let Some(approval) = &bundle.proposal.approval {
        roles.insert(
            "human-approval".to_owned(),
            approval.approver_key_id.clone(),
        );
    }
    if let Some(permit) = &bundle.permit {
        roles.insert(
            "permit-authority".to_owned(),
            permit.authority_key_id.clone(),
        );
    }
    for receipt in &bundle.receipts {
        for (field, role) in [
            ("executor_key_id", "executor"),
            ("observer_key_id", "observer"),
            ("controller_key_id", "containment"),
        ] {
            if let Some(key_id) = receipt.get(field).and_then(Value::as_str) {
                roles.insert(role.to_owned(), key_id.to_owned());
            }
        }
    }
    let role_items = roles.iter().collect::<Vec<(&String, &String)>>();
    for (index, &(left_role, left_id)) in role_items.iter().enumerate() {
        if !keys.contains_key(left_id.as_str()) {
            errors.push(format!(
                "missing key for security role {left_role}: {left_id}"
            ));
        }
        for &(right_role, right_id) in role_items.iter().skip(index + 1) {
            if same_key_material(&keys, Some(left_id.as_str()), Some(right_id.as_str())) {
                errors.push(format!(
                    "security role key material reused: {left_role} and {right_role}"
                ));
            }
        }
    }

    errors.extend(verify_manifest(bundle));
    if bundle.witness_statement.schema_version != "claimsieve.witness_statement.v1" {
        errors.push("unsupported witness statement schema".to_owned());
    }
    if bundle.witness_statement.release_id != bundle.manifest.release_id {
        errors.push("witness statement release binding mismatch".to_owned());
    }
    match digest(&bundle.manifest) {
        Ok(expected) if expected == bundle.witness_statement.manifest_digest => {}
        Ok(_) => errors.push("witness statement manifest binding mismatch".to_owned()),
        Err(error) => errors.push(format!("manifest witness digest failed: {error}")),
    }
    errors.extend(verify_role_signature(
        &bundle.witness_statement,
        &bundle.witness_statement.witness_key_id,
        &bundle.witness_statement.signature,
        "witness_signers",
        "witness-v1",
        "witness statement",
        trust_root,
        &keys,
    ));
    errors.sort();
    errors.dedup();
    VerificationReport {
        valid: errors.is_empty(),
        errors,
    }
}

#[cfg(test)]
mod tests {
    use super::verify_json;

    const TRUST_ROOT: &str = include_str!("../../../../trust/fixture-trust-root.json");

    #[test]
    fn python_generated_vector_verifies() {
        let input = include_str!("../../../../vectors/valid_evidence_bundle.json");
        let result = verify_json(input, TRUST_ROOT);
        assert!(result.is_ok());
        if let Ok(report) = result {
            assert!(report.valid, "{:?}", report.errors);
        }
    }

    #[test]
    fn python_generated_observer_v2_vector_verifies() {
        let input = include_str!("../../../../vectors/valid_evidence_bundle_observer_v2.json");
        let result = verify_json(input, TRUST_ROOT);
        assert!(result.is_ok());
        if let Ok(report) = result {
            assert!(report.valid, "{:?}", report.errors);
        }
    }

    #[test]
    fn tampered_vector_is_rejected() {
        let input = include_str!("../../../../vectors/valid_evidence_bundle.json");
        let tampered = input.replace("Would you like", "You must");
        let result = verify_json(&tampered, TRUST_ROOT);
        assert!(result.is_ok());
        if let Ok(report) = result {
            assert!(!report.valid);
        }
    }

    #[test]
    fn forged_human_approval_is_rejected() {
        let input = include_str!("../../../../vectors/valid_evidence_bundle.json");
        let tampered = input.replace(
            "spiffe://mainstreet.local/tenant-demo/human/owner",
            "spiffe://attacker.invalid/forged",
        );
        let result = verify_json(&tampered, TRUST_ROOT);
        assert!(result.is_ok());
        if let Ok(report) = result {
            assert!(!report.valid);
            assert!(
                report
                    .errors
                    .iter()
                    .any(|error| error.contains("human approval"))
            );
        }
    }

    #[test]
    fn duplicate_json_keys_are_rejected() {
        let input = r#"{"schema_version":"claimsieve.evidence_bundle.v1","schema_version":"evil"}"#;
        assert!(verify_json(input, TRUST_ROOT).is_err());
    }

    #[test]
    fn floating_point_json_is_rejected() {
        let input = r#"{"schema_version":"claimsieve.evidence_bundle.v1","value":1.25}"#;
        assert!(verify_json(input, TRUST_ROOT).is_err());
    }

    #[test]
    fn unsafe_integer_json_is_rejected() {
        let input =
            r#"{"schema_version":"claimsieve.evidence_bundle.v1","value":9007199254740992}"#;
        assert!(verify_json(input, TRUST_ROOT).is_err());
    }
}
