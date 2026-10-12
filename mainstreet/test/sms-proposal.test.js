import assert from "node:assert/strict";
import test from "node:test";
import { ProposalOnlyBridge } from "../src/index.js";
import { SMSProposalBuilder, smsCapabilityManifest } from "../src/sms-proposal.js";

const bridge = new ProposalOnlyBridge({
  identity: { tenant_id: "tenant-1", principal: "spiffe://mainstreet.local/tenant-1/agent" }
});
const builder = new SMSProposalBuilder({ bridge, tenantId: "tenant-1" });
const draft = () => ({
  proposalId: "sms-1", traceId: "trace-1", campaignId: "campaign-1",
  sessionId: "session-1", recipient: "+15551234567", resourceId: "lead-123", body: "Are you available tomorrow?",
  evidenceRefs: ["sha256:" + "a".repeat(64)], requestedAtSeq: 10
});

test("SMS only prepares a bound, frozen proposal", () => {
  const proposal = builder.prepareSMS(draft());
  assert.equal(proposal.action.destination.authority, "+15551234567");
  assert.equal(proposal.action.parameters.body, "Are you available tomorrow?");
  assert.equal(proposal.action.kind, "send_message");
  assert.equal(proposal.action.destination.resource, "lead-123");
  assert.equal(proposal.action.destination.trust_domain, "sms-provider");
  assert.equal(proposal.approval, null);
  assert.ok(Object.isFrozen(proposal));
  assert.equal(typeof builder.execute, "undefined");
  assert.equal(typeof builder.send, "undefined");
});

test("SMS rejects bad recipients and empty bodies", () => {
  assert.throws(() => builder.prepareSMS({ ...draft(), recipient: "5551234567" }), /E.164/);
  assert.throws(() => builder.prepareSMS({ ...draft(), body: "" }), /bounded/);
  assert.throws(() => builder.prepareSMS({ ...draft(), resourceId: "lead / other" }), /lead resource/);
});

test("SMS capability does not carry execution authority", () => {
  assert.deepEqual(smsCapabilityManifest.allowed, ["prepare_sms_proposal"]);
  assert.ok(smsCapabilityManifest.forbidden.includes("sms_send"));
  assert.ok(smsCapabilityManifest.forbidden.includes("permit_signing"));
});
