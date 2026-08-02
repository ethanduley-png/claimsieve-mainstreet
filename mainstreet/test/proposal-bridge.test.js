import assert from "node:assert/strict";
import test from "node:test";
import { ProposalBoundaryError, ProposalOnlyBridge, capabilityManifest } from "../src/index.js";

const identity = {
  tenant_id: "tenant-demo",
  principal: "spiffe://mainstreet.local/tenant-demo/agent/openclaw"
};

function draft() {
  return {
    proposal_id: "proposal-1",
    trace_id: "trace-1",
    tenant_id: "tenant-demo",
    campaign_id: "campaign-1",
    session_id: "session-1",
    parent_action_id: null,
    objective: {
      root: "Respond to a consented business lead.",
      subgoal: "respond_to_lead",
      expected_effect: "One message is proposed for the registered lead.",
      constraints: ["No medical claims", "No direct execution"]
    },
    action: {
      kind: "send_message",
      effect_class: "external_write",
      destination: {
        scheme: "sms",
        authority: "+15551234567",
        resource: "lead-123",
        trust_domain: "sms-provider"
      },
      method: "SEND",
      parameters: { body: "Would you like to schedule an intro session?" },
      reversibility: "compensable"
    },
    evidence_refs: ["sha256:abc"],
    requested_at_seq: 10,
    risk_tags: []
  };
}

function bridge() {
  return new ProposalOnlyBridge({ identity });
}

test("prepares a frozen proposal without any transport", () => {
  const candidate = bridge().prepare(draft());
  assert.equal(candidate.principal, identity.principal);
  assert.equal(candidate.approval, null);
  assert.ok(Object.isFrozen(candidate));
  assert.ok(Object.isFrozen(candidate.action.destination));
  assert.equal(typeof bridge().propose, "undefined");
});

test("validates only a non-authoritative acknowledgement", () => {
  const b = bridge();
  const proposal = b.prepare(draft());
  const ack = b.validateAcknowledgement(proposal, {
    schema_version: "claimsieve.intake_ack.v1",
    proposal_id: proposal.proposal_id,
    trace_id: proposal.trace_id,
    intake_status: "RECORDED"
  });
  assert.equal(ack.intake_status, "RECORDED");
  assert.ok(Object.isFrozen(ack));
});

test("rejects acknowledgement authority claims", () => {
  const b = bridge();
  const proposal = b.prepare(draft());
  assert.throws(() => b.validateAcknowledgement(proposal, {
    schema_version: "claimsieve.intake_ack.v1",
    proposal_id: proposal.proposal_id,
    trace_id: proposal.trace_id,
    intake_status: "RECORDED",
    verdict: "ALLOW"
  }), (error) => error instanceof ProposalBoundaryError && error.code === "UNKNOWN_FIELD");
});

test("rejects caller supplied authority fields", () => {
  const candidate = { ...draft(), principal: "spiffe://attacker" };
  assert.throws(() => bridge().prepare(candidate), /not allowed/);
});

test("rejects cross-tenant proposals", () => {
  const candidate = { ...draft(), tenant_id: "other" };
  assert.throws(() => bridge().prepare(candidate), /authenticated tenant/);
});

test("rejects floating point authority data", () => {
  const candidate = draft();
  candidate.action.parameters = { confidence: 0.99 };
  assert.throws(() => bridge().prepare(candidate), /safe integer/);
});

test("rejects unsafe integers", () => {
  const candidate = draft();
  candidate.action.parameters.count = 9_007_199_254_740_992;
  assert.throws(() => bridge().prepare(candidate), /safe integer/);
});

test("rejects non-NFC strings", () => {
  const candidate = draft();
  candidate.action.parameters.body = "Cafe\u0301";
  assert.throws(() => bridge().prepare(candidate), /NFC/);
});

test("rejects sparse arrays", () => {
  const candidate = draft();
  candidate.risk_tags = new Array(2);
  candidate.risk_tags[1] = "PURPOSE_MISMATCH";
  assert.throws(() => bridge().prepare(candidate), /holes/);
});

test("rejects accessor properties without invoking them", () => {
  const candidate = draft();
  let invoked = false;
  Object.defineProperty(candidate.action.parameters, "secret", {
    enumerable: true,
    get() { invoked = true; return "value"; }
  });
  assert.throws(() => bridge().prepare(candidate), /data property/);
  assert.equal(invoked, false);
});

test("rejects duplicate evidence references", () => {
  const candidate = draft();
  candidate.evidence_refs = ["sha256:abc", "sha256:abc"];
  assert.throws(() => bridge().prepare(candidate), /duplicates/);
});

test("rejects cyclic graphs", () => {
  const candidate = draft();
  candidate.action.parameters.self = candidate.action.parameters;
  assert.throws(() => bridge().prepare(candidate), (error) => error.code === "CYCLIC_VALUE");
});

test("rejects shared object references", () => {
  const candidate = draft();
  const shared = { value: "same" };
  candidate.action.parameters = { left: shared, right: shared };
  assert.throws(() => bridge().prepare(candidate), (error) => error.code === "SHARED_REFERENCE");
});

test("rejects __proto__ as an own property", () => {
  const candidate = draft();
  Object.defineProperty(candidate.action.parameters, "__proto__", {
    value: { polluted: true }, enumerable: true, configurable: true, writable: true
  });
  assert.throws(() => bridge().prepare(candidate), (error) => error.code === "DANGEROUS_PROPERTY");
});

test("rejects constructor and prototype keys at any depth", () => {
  for (const key of ["constructor", "prototype"]) {
    const candidate = draft();
    candidate.action.parameters = { nested: { [key]: "bad" } };
    assert.throws(() => bridge().prepare(candidate), (error) => error.code === "DANGEROUS_PROPERTY");
  }
});

test("rejects unpaired Unicode surrogates", () => {
  const candidate = draft();
  candidate.action.parameters.body = "bad\uD800";
  assert.throws(() => bridge().prepare(candidate), /unpaired surrogate/);
});

test("acknowledgement must bind proposal and trace", () => {
  const b = bridge();
  const proposal = b.prepare(draft());
  assert.throws(() => b.validateAcknowledgement(proposal, {
    schema_version: "claimsieve.intake_ack.v1",
    proposal_id: "other",
    trace_id: proposal.trace_id,
    intake_status: "RECORDED"
  }), /not bound/);
});

test("capability manifest contains no transport or execution capability", () => {
  assert.ok(capabilityManifest.allowed.includes("prepare_canonicalizable_proposal"));
  assert.ok(capabilityManifest.forbidden.includes("provider_execution"));
  assert.ok(capabilityManifest.forbidden.includes("generic_network_egress"));
  assert.match(capabilityManifest.production_runtime.egress, /none/);
});
