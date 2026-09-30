import assert from "node:assert/strict";
import test from "node:test";
import { ProposalOnlyBridge } from "../src/index.js";
import {
  ErgonomicsBoundaryError,
  ProposalSkill,
  createUnreviewedMemory,
  ergonomicsCapabilityManifest,
  normalizeAgentManifest,
  normalizeSkillManifest
} from "../src/ergonomics.js";
import { founderGitHubIssueSkill } from "../ergonomics/skills/founder-github-issue.js";
import { founderOperatorAgent } from "../ergonomics/agents/founder-operator.js";

const identity = {
  tenant_id: "tenant-demo",
  principal: "spiffe://mainstreet.local/tenant-demo/agent/openclaw"
};

function bridge() {
  return new ProposalOnlyBridge({ identity });
}

function prepareInput() {
  return {
    proposalId: "proposal-ergonomics-1",
    traceId: "trace-ergonomics-1",
    tenantId: "tenant-demo",
    campaignId: "campaign-1",
    sessionId: "session-1",
    bindings: { repository: "ethanduley-png/claimsieve-mainstreet" },
    parameters: {
      title: "Implement governed skill catalog",
      body: "Track the first ECC-inspired Main Street ergonomics slice.",
      correlation_marker: "claimsieve:proposal-ergonomics-1",
      work_item_id: "work-1"
    },
    evidenceRefs: ["sha256:evidence"],
    requestedAtSeq: 42,
    riskTags: []
  };
}

test("normalizes an ECC-inspired skill but preserves ClaimSieve authority", () => {
  const manifest = normalizeSkillManifest(founderGitHubIssueSkill);
  assert.equal(manifest.authority.mode, "proposal_only");
  assert.equal(manifest.authority.adjudicator, "claimsieve");
  assert.equal(manifest.authority.direct_execution, false);
  assert.ok(Object.isFrozen(manifest));
});

test("skill prepares a proposal and exposes no execution method", () => {
  const skill = new ProposalSkill({ bridge: bridge(), manifest: founderGitHubIssueSkill });
  const proposal = skill.prepare(prepareInput());
  assert.equal(proposal.action.destination.authority, "ethanduley-png/claimsieve-mainstreet");
  assert.equal(proposal.action.destination.resource, "issues");
  assert.equal(proposal.action.method, "CREATE");
  assert.equal(proposal.approval, null);
  assert.equal(typeof skill.execute, "undefined");
});

test("skill rejects undeclared parameters", () => {
  const skill = new ProposalSkill({ bridge: bridge(), manifest: founderGitHubIssueSkill });
  const input = prepareInput();
  input.parameters.execute_now = true;
  assert.throws(() => skill.prepare(input), (error) =>
    error instanceof ErgonomicsBoundaryError && error.code === "UNDECLARED_ERGONOMIC_INPUT");
});

test("skill rejects undeclared destination bindings", () => {
  const skill = new ProposalSkill({ bridge: bridge(), manifest: founderGitHubIssueSkill });
  const input = prepareInput();
  input.bindings.owner_token = "secret";
  assert.throws(() => skill.prepare(input), (error) =>
    error instanceof ErgonomicsBoundaryError && error.code === "UNDECLARED_ERGONOMIC_INPUT");
});

test("skill rejects direct execution authority", () => {
  const unsafe = structuredClone(founderGitHubIssueSkill);
  unsafe.authority.direct_execution = true;
  assert.throws(() => normalizeSkillManifest(unsafe), (error) =>
    error instanceof ErgonomicsBoundaryError && error.code === "AUTHORITY_ESCALATION");
});

test("agent roles are ergonomics only and cannot acquire execute capability", () => {
  const agent = normalizeAgentManifest(founderOperatorAgent);
  assert.equal(agent.authority.adjudicator, "claimsieve");
  const unsafe = structuredClone(founderOperatorAgent);
  unsafe.capabilities.push("execute_provider_action");
  assert.throws(() => normalizeAgentManifest(unsafe), (error) =>
    error instanceof ErgonomicsBoundaryError && error.code === "AGENT_CAPABILITY_ESCALATION");
});

test("new memory is context with unreviewed trust, never policy", () => {
  const memory = createUnreviewedMemory({
    id: "lead.followup.preference",
    created_at_seq: 77,
    source: "conversation-observation",
    scope: "tenant-demo",
    content: "The customer asked to be contacted in the afternoon.",
    evidence_refs: ["sha256:conversation"]
  });
  assert.equal(memory.trust, "unreviewed");
  assert.equal(memory.status, "active");
  assert.equal(Object.hasOwn(memory, "policy"), false);
  assert.equal(Object.hasOwn(memory, "approval"), false);
});

test("ergonomics capability manifest explicitly forbids authority and execution", () => {
  assert.ok(ergonomicsCapabilityManifest.allowed.includes("prepare_claimsieve_proposal"));
  assert.ok(ergonomicsCapabilityManifest.forbidden.includes("provider_execution"));
  assert.ok(ergonomicsCapabilityManifest.forbidden.includes("permit_signing"));
  assert.ok(ergonomicsCapabilityManifest.forbidden.includes("memory_to_policy_promotion"));
});
