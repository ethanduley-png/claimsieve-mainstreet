import { ProposalBoundaryError, ProposalOnlyBridge } from "./index.js";

const REPOSITORY = /^[A-Za-z0-9_.-]{1,100}\/[A-Za-z0-9_.-]{1,100}$/;

function requireText(value, name, maximum) {
  if (typeof value !== "string" || value.length === 0 || value.length > maximum) {
    throw new ProposalBoundaryError("INVALID_FOUNDER_INPUT", `${name} must be a non-empty bounded string`);
  }
  return value;
}

/**
 * Product-specific proposal builder. It has no GitHub SDK, credentials,
 * transport, permit issuer, or execution function. Its output is passed through
 * the existing proposal-only bridge and remains non-authoritative.
 */
export class FounderOSProposalBuilder {
  #bridge;
  #tenantId;

  constructor({ bridge, tenantId }) {
    if (!(bridge instanceof ProposalOnlyBridge)) {
      throw new ProposalBoundaryError("INVALID_BRIDGE", "Founder OS requires the baseline ProposalOnlyBridge");
    }
    this.#bridge = bridge;
    this.#tenantId = requireText(tenantId, "tenantId", 128);
    Object.freeze(this);
  }

  prepareGitHubIssue({
    proposalId,
    traceId,
    campaignId,
    sessionId,
    workItemId,
    repository,
    title,
    body,
    evidenceRefs,
    requestedAtSeq
  }) {
    requireText(repository, "repository", 201);
    if (!REPOSITORY.test(repository)) {
      throw new ProposalBoundaryError("INVALID_REPOSITORY", "repository must be an exact owner/name identifier");
    }
    const safeTitle = requireText(title, "title", 180);
    const safeBody = requireText(body, "body", 20_000);
    const safeWorkItem = requireText(workItemId, "workItemId", 256);

    return this.#bridge.prepare({
      proposal_id: requireText(proposalId, "proposalId", 128),
      trace_id: requireText(traceId, "traceId", 128),
      tenant_id: this.#tenantId,
      campaign_id: requireText(campaignId, "campaignId", 128),
      session_id: requireText(sessionId, "sessionId", 128),
      parent_action_id: null,
      objective: {
        root: "Operate the ClaimSieve and MainStreet company through reviewable governed work.",
        subgoal: "create_project_issue",
        expected_effect: "Exactly one GitHub issue is proposed for the approved repository.",
        constraints: [
          "No direct GitHub credential access",
          "No repository substitution",
          "No payload mutation after approval",
          "Ambiguous outcomes remain unknown"
        ]
      },
      action: {
        kind: "run_connector",
        effect_class: "external_write",
        destination: {
          scheme: "github",
          authority: repository,
          resource: "issues",
          trust_domain: "github.com"
        },
        method: "CREATE",
        parameters: {
          title: safeTitle,
          body: safeBody,
          correlation_marker: `claimsieve:${proposalId}`,
          work_item_id: safeWorkItem
        },
        reversibility: "compensable"
      },
      evidence_refs: evidenceRefs,
      requested_at_seq: requestedAtSeq,
      risk_tags: []
    });
  }
}

export const founderOSCapabilityManifest = Object.freeze({
  schema_version: "mainstreet.founder_os_capability_manifest.v1",
  role: "founder_os_proposal_builder",
  allowed: ["prepare_github_issue_proposal"],
  forbidden: [
    "github_credentials",
    "github_api_execution",
    "permit_signing",
    "permit_reservation",
    "outcome_confirmation",
    "generic_network_egress"
  ]
});
