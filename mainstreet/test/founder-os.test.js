import assert from "node:assert/strict";
import test from "node:test";
import { ProposalOnlyBridge } from "../src/index.js";
import { FounderOSProposalBuilder, founderOSCapabilityManifest } from "../src/founder-os.js";

const tenantId = "tenant-founder";
const bridge = new ProposalOnlyBridge({
  identity: {
    tenant_id: tenantId,
    principal: "spiffe://mainstreet.local/tenant-founder/agent/openclaw"
  }
});

function request() {
  return {
    proposalId: "founder-proposal-001",
    traceId: "founder-trace-001",
    campaignId: "founder-campaign-001",
    sessionId: "founder-session-001",
    workItemId: "work-item-001",
    repository: "example/claimsieve-mainstreet",
    title: "Review Founder OS integration",
    body: "Inspect exact action binding.",
    evidenceRefs: ["sha256:" + "a".repeat(64)],
    requestedAtSeq: 10
  };
}

test("Founder OS reuses the proposal-only boundary", () => {
  const builder = new FounderOSProposalBuilder({ bridge, tenantId });
  const proposal = builder.prepareGitHubIssue(request());
  assert.equal(proposal.action.kind, "run_connector");
  assert.equal(proposal.action.destination.authority, "example/claimsieve-mainstreet");
  assert.equal(proposal.approval, null);
  assert.ok(Object.isFrozen(proposal));
  assert.equal(typeof builder.execute, "undefined");
  assert.equal(typeof builder.issuePermit, "undefined");
});

test("Founder OS rejects a non owner/name repository", () => {
  const builder = new FounderOSProposalBuilder({ bridge, tenantId });
  assert.throws(
    () => builder.prepareGitHubIssue({ ...request(), repository: "https://github.com/example/repo" }),
    /owner\/name/
  );
});

test("Founder OS rejects empty issue content", () => {
  const builder = new FounderOSProposalBuilder({ bridge, tenantId });
  assert.throws(() => builder.prepareGitHubIssue({ ...request(), title: "" }), /bounded string/);
  assert.throws(() => builder.prepareGitHubIssue({ ...request(), body: "" }), /bounded string/);
});

test("Founder OS cannot inject approval or authority fields", () => {
  const builder = new FounderOSProposalBuilder({ bridge, tenantId });
  const proposal = builder.prepareGitHubIssue(request());
  assert.equal(proposal.principal, "spiffe://mainstreet.local/tenant-founder/agent/openclaw");
  assert.equal(proposal.approval, null);
  assert.equal(Object.hasOwn(proposal, "permit"), false);
  assert.equal(Object.hasOwn(proposal, "verdict"), false);
});

test("Founder OS manifest exposes no execution capability", () => {
  assert.deepEqual(founderOSCapabilityManifest.allowed, ["prepare_github_issue_proposal"]);
  assert.ok(founderOSCapabilityManifest.forbidden.includes("github_api_execution"));
  assert.ok(founderOSCapabilityManifest.forbidden.includes("outcome_confirmation"));
});
