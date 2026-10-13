import { ProposalBoundaryError, ProposalOnlyBridge } from "./index.js";

const E164 = /^\+[1-9][0-9]{7,14}$/;

function bounded(value, name, max) {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new ProposalBoundaryError("INVALID_SMS_DRAFT", `${name} must be a non-empty bounded string`);
  }
  return value;
}

/** Proposal-only MainStreet SMS workflow: no provider token, SDK, transport or permit authority. */
export class SMSProposalBuilder {
  #bridge;
  #tenantId;
  constructor({ bridge, tenantId }) {
    if (!(bridge instanceof ProposalOnlyBridge)) {
      throw new ProposalBoundaryError("INVALID_BRIDGE", "SMS requires the proposal-only bridge");
    }
    this.#bridge = bridge;
    this.#tenantId = bounded(tenantId, "tenantId", 128);
    Object.freeze(this);
  }

  prepareSMS({ proposalId, traceId, campaignId, sessionId, recipient,
    resourceId, body, evidenceRefs, requestedAtSeq }) {
    if (typeof recipient !== "string" || !E164.test(recipient)) {
      throw new ProposalBoundaryError("INVALID_SMS_RECIPIENT", "exact E.164 recipient required");
    }
    const message = bounded(body, "body", 1000);
    const resource = bounded(resourceId, "resourceId", 128);
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(resource)) {
      throw new ProposalBoundaryError("INVALID_SMS_RESOURCE", "invalid lead resource");
    }
    return this.#bridge.prepare({
      proposal_id: bounded(proposalId, "proposalId", 128),
      trace_id: bounded(traceId, "traceId", 128),
      tenant_id: this.#tenantId,
      campaign_id: bounded(campaignId, "campaignId", 128),
      session_id: bounded(sessionId, "sessionId", 128),
      parent_action_id: null,
      objective: {
        root: "Respond to an existing customer request under explicit owner oversight.",
        subgoal: "respond_to_lead",
        expected_effect: "Exactly one bounded SMS message is proposed for the approved recipient.",
        constraints: [
          "No network execution from MainStreet",
          "Recipient and text cannot change after approval",
          "Fresh human approval required before external send",
          "Unknown outcomes never authorize automatic resending"
        ]
      },
      action: {
        kind: "send_message",
        effect_class: "external_write",
        destination: {
          scheme: "sms", authority: recipient,
          resource, trust_domain: "sms-provider"
        },
        method: "SEND",
        parameters: { body: message },
        reversibility: "irreversible"
      },
      evidence_refs: evidenceRefs,
      requested_at_seq: requestedAtSeq,
      risk_tags: []
    });
  }
}

export const smsCapabilityManifest = Object.freeze({
  schema_version: "mainstreet.sms_proposal_capability_manifest.v1",
  role: "sms_proposal_only",
  allowed: ["prepare_sms_proposal"],
  forbidden: ["sms_send", "sms_provider_credentials", "network_egress",
    "permit_signing", "reservation", "outcome_confirmation"]
});
