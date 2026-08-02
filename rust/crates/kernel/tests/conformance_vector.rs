#![forbid(unsafe_code)]

//! Conformance check against the generated Python evidence-bundle vector.

use claimsieve_kernel::{CampaignState, evaluate};
use claimsieve_protocol::{Decision, Evidence, Policy, Proposal};
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorSubset {
    proposal: Proposal,
    signed_policy: SignedPolicySubset,
    evidence: Vec<Evidence>,
    decision: Decision,
}

#[derive(Deserialize)]
struct SignedPolicySubset {
    policy: Policy,
}

fn load_vector() -> Result<VectorSubset, serde_json::Error> {
    serde_json::from_str(include_str!(
        "../../../../vectors/valid_evidence_bundle.json"
    ))
}

#[test]
fn rust_kernel_matches_python_vector() {
    let result = load_vector();
    assert!(result.is_ok());
    if let Ok(vector) = result {
        let state = CampaignState::new("campaign-001");
        let evaluated = evaluate(
            &vector.proposal,
            &vector.signed_policy.policy,
            &vector.evidence,
            &state,
            10,
        );
        assert!(evaluated.is_ok());
        if let Ok(value) = evaluated {
            assert_eq!(value.decision, vector.decision);
        }
    }
}

#[test]
fn revoked_deployment_fails_closed() {
    let result = load_vector();
    assert!(result.is_ok());
    if let Ok(mut vector) = result {
        if let Some(deployment) = vector
            .evidence
            .iter_mut()
            .find(|item| item.evidence_type == "deployment_certificate")
        {
            deployment
                .content
                .insert("status".to_owned(), serde_json::json!("REVOKED"));
        }
        let state = CampaignState::new("campaign-001");
        let evaluated = evaluate(
            &vector.proposal,
            &vector.signed_policy.policy,
            &vector.evidence,
            &state,
            10,
        );
        assert!(evaluated.is_ok());
        if let Ok(value) = evaluated {
            assert_ne!(value.decision.verdict, claimsieve_protocol::Verdict::Allow);
            assert!(
                value
                    .decision
                    .reason_codes
                    .iter()
                    .any(|reason| reason == "DEPLOYMENT_CERTIFICATE_NOT_ACTIVE")
            );
        }
    }
}
