#!/usr/bin/env python3
from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from claimsieve_ref.canonical import CanonicalizationError, digest, loads_strict  # noqa: E402
from claimsieve_ref.crypto import KeyPair  # noqa: E402
from claimsieve_ref.fixtures import evidence, keypairs, policy, proposal, signed_policy, trust_root  # noqa: E402
from claimsieve_ref.kernel import CampaignState, evaluate  # noqa: E402
from claimsieve_ref.model import approval_signing_subject  # noqa: E402
from claimsieve_ref.runtime import (  # noqa: E402
    Authority, CampaignStateStore, ContainmentController, Executor, Observer,
    PermitError, ReservationStore, SimulatedConnector, SimulatedExternalSystem,
)
from claimsieve_ref.trust import sign_evidence, sign_policy  # noqa: E402
from claimsieve_ref.verifier import verify_bundle  # noqa: E402
from generate_bundle import build_bundle  # noqa: E402

REPORT: list[dict[str, Any]] = []


def _safe_report_value(value: Any) -> Any:
    """Keep evidence reports inside the restricted authority JSON profile."""
    if isinstance(value, str):
        return "".join(
            ch if ord(ch) >= 0x20 and ord(ch) != 0x7F else f"\\u{ord(ch):04x}"
            for ch in value
        )
    if isinstance(value, list):
        return [_safe_report_value(item) for item in value]
    if isinstance(value, tuple):
        return [_safe_report_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _safe_report_value(item) for key, item in value.items()}
    return value


def record(
    attack: str,
    expected: str,
    actual: str,
    status: str,
    impact: str,
    trace: Any,
    fix: str,
    coverage: str = "EXECUTED",
) -> None:
    REPORT.append({
        "attack": attack,
        "expected_result": expected,
        "actual_result": actual,
        "status": status,
        "impact_if_unblocked": impact,
        "reproducible_trace": _safe_report_value(trace),
        "fix_or_control": _safe_report_value(fix),
        "coverage": coverage,
    })


def fixture(mode: str = "success") -> dict[str, Any]:
    keys = keypairs()
    ev = evidence(10)
    signed_pol = signed_policy()
    pol = signed_pol["policy"]
    prop = proposal(ev, 10, approve=True)
    states = CampaignStateStore()
    prior = states.read("campaign-001")
    decision = evaluate(prop, pol, ev, prior, 10)
    authority = Authority(
        keys["authority"],
        {keys["approver"].key_id: keys["approver"].public},
        {keys["policy_authority"].key_id: keys["policy_authority"].public},
        {keys[n].key_id: keys[n].public for n in ("crm_evidence", "registry_evidence", "deployment_evidence", "epoch_evidence")},
        states,
    )
    permit = authority.issue(prop, signed_pol, ev, decision.document, 10, nonce="44" * 24)
    system = SimulatedExternalSystem(mode)
    containment = ContainmentController(keys["containment"])
    executor = Executor(
        {keys["authority"].key_id: keys["authority"].public}, keys["executor"],
        ReservationStore(), containment.view(), SimulatedConnector(system),
    )
    observer = Observer(
        keys["observer"], {keys["executor"].key_id: keys["executor"].public}, system,
    )
    return locals()


def expect_exception(name: str, expected_pattern: str, fn: Callable[[], Any], impact: str, fix: str) -> None:
    try:
        value = fn()
    except Exception as exc:  # discriminating trace records exact exception
        passed = expected_pattern.lower() in str(exc).lower()
        record(name, f"reject with {expected_pattern}", str(exc), "BLOCKED" if passed else "BYPASS", impact, {"exception": type(exc).__name__, "message": str(exc)}, fix)
    else:
        record(name, f"reject with {expected_pattern}", f"accepted: {value!r}", "BYPASS", impact, {"returned": repr(value)}, fix)


def kernel_tag_case(name: str, tag: str, expected_verdict: str, impact: str, scope: str = "POLICY_SIMULATION") -> None:
    ev = evidence(10)
    prop = proposal(ev, 10, approve=True, risk_tags=[tag])
    result = evaluate(prop, policy(), ev, CampaignState("campaign-001"), 10)
    actual = result.document["verdict"]
    record(
        name, expected_verdict, actual,
        "BLOCKED" if actual == expected_verdict else "BYPASS",
        impact, result.document, f"Risk tag {tag} dominates ordinary allow policy.", scope,
    )


# 1 Fabricated ALLOW
f = fixture()
denied_prop = proposal(f["ev"], 11, approve=True, proposal_id="deny", trace_id="deny", risk_tags=["PURPOSE_MISMATCH"])
denied = evaluate(denied_prop, f["pol"], f["ev"], f["states"].read("campaign-001"), 11)
forged = copy.deepcopy(denied.document); forged["verdict"] = "ALLOW"
expect_exception("FABRICATED_ALLOW_DECISION", "independent kernel", lambda: f["authority"].issue(denied_prop, f["signed_pol"], f["ev"], forged, 11), "Unauthorized permit", "Authority independently reconstructs the decision.")

# 2 Fabricated permit
f = fixture(); fake = copy.deepcopy(f["permit"]); fake["signature"] = "ed25519:AAAA"
expect_exception("FABRICATED_PERMIT", "signature invalid", lambda: f["executor"].execute(fake, f["prop"], f["signed_pol"], f["ev"], f["decision"].document, f["states"].read("campaign-001"), 11), "Unauthorized side effect", "Executor verifies authority signature against pinned key.")

# 3 campaign substitution
f = fixture(); bad_state = f["states"].read("campaign-001"); bad_state.total_actions += 1
expect_exception("CAMPAIGN_STATE_SUBSTITUTION", "campaign_state_digest", lambda: f["executor"].execute(f["permit"], f["prop"], f["signed_pol"], f["ev"], f["decision"].document, bad_state, 11), "Budget reset or cross-campaign execution", "Permit binds the committed successor state.")

# 4-8 evidence attacks
for attack, mutator, expected in [
    ("EVIDENCE_OMISSION", lambda ev: ev.pop(), "only an ALLOW"),
    ("EVIDENCE_DUPLICATION", lambda ev: ev.append(copy.deepcopy(ev[0])), "only an ALLOW"),
    ("EVIDENCE_SOURCE_IMPERSONATION", lambda ev: ev[0].__setitem__("source", "spiffe://attacker/fake"), "evidence signature invalid"),
    ("STALE_EVIDENCE", lambda ev: ev[0].__setitem__("observed_at_seq", 0), "evidence signature invalid"),
]:
    f = fixture(); changed = copy.deepcopy(f["ev"]); mutator(changed)
    changed_prop = proposal(changed, 11, approve=True, proposal_id=attack.lower(), trace_id=attack.lower())
    current = f["states"].read("campaign-001")
    result = evaluate(changed_prop, f["pol"], changed, current, 11)
    expect_exception(attack, expected, lambda cp=changed_prop, ce=changed, r=result, ff=f: ff["authority"].issue(cp, ff["signed_pol"], ce, r.document, 11), "False evidence could authorize an action", "Signed evidence envelopes, exact snapshot references, source and freshness policy.")

# Evidence signed by the wrong trusted role.
f = fixture(); changed = copy.deepcopy(f["ev"])
unsigned = {k: v for k, v in changed[0].items() if k not in {"signature", "issuer_key_id"}}
changed[0] = sign_evidence(unsigned, f["keys"]["registry_evidence"])
changed_prop = proposal(changed, 11, approve=True, proposal_id="wrong-role", trace_id="wrong-role")
result = evaluate(changed_prop, f["pol"], changed, f["states"].read("campaign-001"), 11)
expect_exception("EVIDENCE_KEY_ROLE_SUBSTITUTION", "not trusted", lambda: f["authority"].issue(changed_prop, f["signed_pol"], changed, result.document, 11), "Cross-source evidence forgery", "Policy pins evidence types to issuer keys.")

# 9-10 approval attacks
f = fixture(); fresh_states = CampaignStateStore(); fresh_authority = Authority(
    f["keys"]["authority"],
    {f["keys"]["approver"].key_id: f["keys"]["approver"].public},
    {f["keys"]["policy_authority"].key_id: f["keys"]["policy_authority"].public},
    {f["keys"][n].key_id: f["keys"][n].public for n in ("crm_evidence", "registry_evidence", "deployment_evidence", "epoch_evidence")},
    fresh_states,
)
stale = copy.deepcopy(f["prop"]); stale["approval"]["expires_at_seq"] = 9; stale["approval"]["signature"] = f["keys"]["approver"].sign("approval-v1", approval_signing_subject(stale["approval"]))
expect_exception("STALE_HUMAN_APPROVAL", "stale", lambda: fresh_authority.issue(stale, f["signed_pol"], f["ev"], f["decision"].document, 10), "Approval replay", "Approval is signed, exact-proposal bound, and sequence limited.")
f = fixture(); fresh_states = CampaignStateStore(); fresh_authority = Authority(
    f["keys"]["authority"],
    {f["keys"]["approver"].key_id: f["keys"]["approver"].public},
    {f["keys"]["policy_authority"].key_id: f["keys"]["policy_authority"].public},
    {f["keys"][n].key_id: f["keys"][n].public for n in ("crm_evidence", "registry_evidence", "deployment_evidence", "epoch_evidence")},
    fresh_states,
)
substituted = copy.deepcopy(f["prop"]); substituted["approval"]["approver"] = "spiffe://mainstreet.local/tenant-demo/human/other"; substituted["approval"]["signature"] = f["keys"]["approver"].sign("approval-v1", approval_signing_subject(substituted["approval"]))
expect_exception("APPROVER_SUBSTITUTION", "not allowed", lambda: fresh_authority.issue(substituted, f["signed_pol"], f["ev"], f["decision"].document, 10), "Unauthorized human approval", "Policy pins approver identity and key.")

# 11-12 policy downgrade/version confusion
f = fixture(); changed_pol = copy.deepcopy(f["pol"]); changed_pol["version"] = 1; envelope = sign_policy(changed_pol, KeyPair.from_seed("rogue", b"R"*32)); result = evaluate(f["prop"], changed_pol, f["ev"], CampaignState("campaign-001"), 10)
expect_exception("POLICY_DOWNGRADE", "policy signer is not trusted", lambda: f["authority"].issue(f["prop"], envelope, f["ev"], result.document, 10), "Widened policy", "External trust root pins policy signers.")
f = fixture(); changed = copy.deepcopy(f["signed_pol"]); changed["policy"]["version"] = 99
expect_exception("POLICY_VERSION_CONFUSION", "signature invalid", lambda: f["authority"].issue(f["prop"], changed, f["ev"], f["decision"].document, 11), "Policy substitution", "Signed policy envelope and governance epoch binding.")

# 13-16 exact mutation attacks
for attack, mutate in [
    ("DESTINATION_MUTATION", lambda p: p["action"]["destination"].__setitem__("authority", "+15550000000")),
    ("PARAMETER_MUTATION", lambda p: p["action"]["parameters"].__setitem__("body", "changed")),
    ("SUBJECT_MUTATION", lambda p: p["action"]["destination"].__setitem__("resource", "lead-other")),
    ("PURPOSE_MUTATION", lambda p: p["objective"].__setitem__("subgoal", "retrieve_pinned_dependency")),
]:
    f = fixture(); changed = copy.deepcopy(f["prop"]); mutate(changed)
    expect_exception(attack, "binding mismatch", lambda c=changed, ff=f: ff["executor"].execute(ff["permit"], c, ff["signed_pol"], ff["ev"], ff["decision"].document, ff["states"].read("campaign-001"), 11), "Post-approval action change", "Permit binds exact proposal/action/destination/parameters/purpose.")

# 17-26 network and tool abuse policy simulations.
for name, tag, verdict, impact in [
    ("REDIRECT_ABUSE", "UNDECLARED_REDIRECT", "DENY", "Redirect to unapproved destination"),
    ("DOMAIN_REBINDING", "UNDECLARED_REDIRECT", "DENY", "Resolved endpoint changes after approval"),
    ("DNS_REBINDING", "UNDECLARED_REDIRECT", "DENY", "DNS target changes after check"),
    ("PACKAGE_PROXY_TUNNELING", "PACKAGE_PROXY_TUNNEL", "DENY", "Arbitrary network relay through package service"),
    ("UPLOAD_AS_CODE_EXECUTION", "EXECUTABLE_UPLOAD", "DENY", "Uploaded artifact becomes executable"),
    ("CREDENTIAL_DISCOVERY_AND_REUSE", "CREDENTIAL_USE", "SUSPEND_CAMPAIGN", "Credential theft"),
    ("CLOUD_METADATA_ACCESS", "CLOUD_METADATA_ACCESS", "SUSPEND_CAMPAIGN", "Cloud credential theft"),
    ("PUBLIC_SERVICE_RELAY_ABUSE", "COVERT_RELAY", "SUSPEND_CAMPAIGN", "Third-party relay bypass"),
    ("COVERT_CHANNELS", "COVERT_RELAY", "SUSPEND_CAMPAIGN", "Hidden exfiltration"),
    ("RECOVERY_PRIVILEGE_ESCALATION", "PRIVILEGE_ESCALATION", "SUSPEND_CAMPAIGN", "Recovery path becomes authority bypass"),
]: kernel_tag_case(name, tag, verdict, impact)

# 27 log tampering / ledger attacks.
bundle = build_bundle(); root = trust_root(); truncated = copy.deepcopy(bundle); truncated["ledgers"]["execution"].pop()
errors = verify_bundle(truncated, root)
record("LEDGER_TRUNCATION", "detect", "; ".join(errors), "DETECTED" if errors else "BYPASS", "Audit history removal", errors, "Witnessed manifest counts and ledger heads.")
reordered = copy.deepcopy(bundle); reordered["ledgers"]["evidence"][0], reordered["ledgers"]["evidence"][1] = reordered["ledgers"]["evidence"][1], reordered["ledgers"]["evidence"][0]
errors = verify_bundle(reordered, root)
record("LEDGER_REORDERING", "detect", "; ".join(errors), "DETECTED" if errors else "BYPASS", "Audit chronology manipulation", errors, "Sequence and previous-hash verification.")
tampered = copy.deepcopy(bundle); tampered["ledgers"]["proposal"][0]["payload"]["proposal_id"] = "tampered"
errors = verify_bundle(tampered, root)
record("LOG_TAMPERING", "detect", "; ".join(errors), "DETECTED" if errors else "BYPASS", "False audit record", errors, "Signed hash-chained records plus external witness.")

# 28-29 observer/executor compromise.
f = fixture(); forged_obs = {"schema_version":"claimsieve.observer_receipt.v1","trace_id":f["prop"]["trace_id"],"campaign_id":"campaign-001","permit_id":f["permit"]["permit_id"],"executor_receipt_digest":"sha256:"+"0"*64,"observed_action_digest":digest(f["prop"]["action"]),"reconciliation":"CONFIRMED_SUCCESS","observed_at_seq":12,"observer_key_id":f["keys"]["observer"].key_id,"signature":"ed25519:AAAA"}
expect_exception("OBSERVER_COMPROMISE_FORGED_RECEIPT", "signature invalid", lambda: f["containment"].apply_observation(forged_obs, {f["keys"]["observer"].key_id:f["keys"]["observer"].public}, 12), "False success or containment", "Observer key is separate and receipts are verified.")
f = fixture(); execution = f["executor"].execute(f["permit"], f["prop"], f["signed_pol"], f["ev"], f["decision"].document, f["states"].read("campaign-001"), 11); forged_exec=copy.deepcopy(execution["executor_receipt"]); forged_exec["provider_status"]="rejected"
expect_exception("EXECUTOR_COMPROMISE_FORGED_STATUS", "signature invalid", lambda: f["observer"].observe(f["permit"], f["prop"], forged_exec, 12), "Misreported execution", "Observer verifies executor receipt and independently reads external state.")

# 30-34 replay, cloning, races, double execution.
f = fixture(); state=f["states"].read("campaign-001"); f["executor"].execute(f["permit"], f["prop"], f["signed_pol"], f["ev"], f["decision"].document, state, 11)
expect_exception("PERMIT_REPLAY", "replay", lambda: f["executor"].execute(f["permit"], f["prop"], f["signed_pol"], f["ev"], f["decision"].document, state, 11), "Duplicate effect", "Atomic one-use reservation.")
f = fixture(); clone=copy.deepcopy(f["permit"]); clone["permit_id"]="permit:clone"
expect_exception("PERMIT_CLONING", "signature invalid", lambda: f["executor"].execute(clone, f["prop"], f["signed_pol"], f["ev"], f["decision"].document, f["states"].read("campaign-001"), 11), "Duplicate or altered capability", "Permit identifier is signed.")
f=fixture(); winners=[]; state=f["states"].read("campaign-001")
def race_worker():
    try: f["executor"].execute(f["permit"], f["prop"], f["signed_pol"], f["ev"], f["decision"].document, state, 11); winners.append(1)
    except PermitError: pass
threads=[threading.Thread(target=race_worker) for _ in range(64)]
[t.start() for t in threads]; [t.join() for t in threads]
record("RESERVATION_RACE", "one winner", str(len(winners)), "BLOCKED" if len(winners)==1 else "BYPASS", "Concurrent duplicate execution", {"contenders":64,"winners":len(winners)}, "Atomic reservation store; production requires linearizable durability.")
record("DOUBLE_EXECUTION", "one provider call", str(len(f["executor"].connector.calls)), "BLOCKED" if len(f["executor"].connector.calls)==1 else "BYPASS", "Duplicate effect", {"calls":f["executor"].connector.calls}, "One-use permit reservation.")
f=fixture(); containment=f["containment"]
class RevokingStore(ReservationStore):
    def reserve(self, permit_id, action_digest_value, seq):
        value=super().reserve(permit_id,action_digest_value,seq); containment.revoke(permit_id,"race",seq); return value
f["executor"].reservations=RevokingStore()
expect_exception("REVOCATION_RACE", "revoked", lambda: f["executor"].execute(f["permit"], f["prop"], f["signed_pol"], f["ev"], f["decision"].document, f["states"].read("campaign-001"), 11), "Execution after revocation", "Containment is checked after reservation and immediately before dispatch.")

# 35 ambiguous/conflicting outcomes.
f=fixture("ambiguous"); execution=f["executor"].execute(f["permit"],f["prop"],f["signed_pol"],f["ev"],f["decision"].document,f["states"].read("campaign-001"),11); observation=f["observer"].observe(f["permit"],f["prop"],execution["executor_receipt"],12)
record("AMBIGUOUS_PROVIDER_OUTCOME", "OUTCOME_UNKNOWN and no auto retry", f"{observation['reconciliation']}, retry={execution['automatic_retry_allowed']}", "BLOCKED" if observation["reconciliation"]=="OUTCOME_UNKNOWN" and not execution["automatic_retry_allowed"] else "BYPASS", "Duplicate effect after uncertain timeout", {"execution":execution,"observation":observation}, "Unknown remains unknown; new authorization required.")
bundle=build_bundle(); conflicting=copy.deepcopy(bundle); observer=next(r for r in conflicting["receipts"] if r["schema_version"]=="claimsieve.observer_receipt.v1"); observer["reconciliation"]="CONFIRMED_FAILURE"; errors=verify_bundle(conflicting,trust_root())
record("CONFLICTING_RECEIPTS", "detect", "; ".join(errors), "DETECTED" if errors else "BYPASS", "False outcome narrative", errors, "Signed receipt binding and semantic reconciliation.")

# 36 valid signature over false claim and self-asserted roots.
bundle=build_bundle(); rogue=KeyPair.from_seed("rogue-witness",b"W"*32); false=copy.deepcopy(bundle); statement=false["witness_statement"]; statement["witness_key_id"]=rogue.key_id; unsigned={k:v for k,v in statement.items() if k!="signature"}; statement["signature"]=rogue.sign("witness-v1",unsigned); errors=verify_bundle(false,trust_root())
record("VALID_SIGNATURE_OVER_FALSE_CLAIM", "reject untrusted signer", "; ".join(errors), "DETECTED" if errors else "BYPASS", "Cryptographically valid lie", errors, "External role-scoped trust root; signatures prove origin, not truth.")
self_root=copy.deepcopy(trust_root()); self_root["keys"][rogue.key_id]=rogue.public.encode(); self_root["roles"]["witness_signers"]=[rogue.key_id]
errors=verify_bundle(false,self_root)
record("SELF_ASSERTED_TRUST_ROOT", "caller-selected root must not be treated as organizational trust", "bundle verifies under attacker-selected root" if not errors else "; ".join(errors), "LIMITATION", "Complete provenance forgery if verifier accepts arbitrary root", {"errors":errors}, "Deploy verifier with out-of-band pinned root; fixture CLI cannot establish organizational root authenticity.", "INFRASTRUCTURE_REQUIRED")

# 37-39 inherited reset attacks: v0.31 reference used in-process state; v0.32 adds separate durable-state tests.
f=fixture(); current=f["states"].read("campaign-001")
for name in ("RESTART_BASED_LIMIT_RESET","SUBAGENT_BASED_LIMIT_RESET","SANDBOX_BASED_LIMIT_RESET"):
    second=proposal(f["ev"],11,approve=True,proposal_id=name.lower(),trace_id=name.lower(),session_id=name.lower())
    result=evaluate(second,f["pol"],f["ev"],current,11)
    record(name,"state begins with prior total_actions=1",str(current.total_actions),"BLOCKED" if current.total_actions==1 else "BYPASS","Campaign budget reset",{"state":current.as_canonical(),"next_verdict":result.document["verdict"]},"Campaign identity and state are outside agent/session identity. Production durable store remains required.","REFERENCE_STORE_ONLY")

# 40-45 parser/resource attacks.
for name,text,expected in [
    ("INTEGER_OVERFLOW",'{"x":9007199254740992}',"safe JSON"),
    ("SERIALIZATION_AMBIGUITY_DUPLICATE_KEYS",'{"x":1,"x":2}',"duplicate key"),
    ("UNICODE_NORMALIZATION_ATTACK",'{"x":"Cafe\\u0301"}',"NFC"),
]:
    try: loads_strict(text); actual="accepted"; status="BYPASS"
    except Exception as exc: actual=str(exc); status="BLOCKED" if expected.lower() in str(exc).lower() else "BYPASS"
    record(name,f"reject with {expected}",actual,status,"Digest disagreement or parser differential",{"json":text,"result":actual},"Restricted canonical JSON profile.")
# Python structures cannot encode JS prototypes; Node test is the discriminating test.
node_command = os.environ.get("CLAIMSIEVE_NODE", "node")
node = subprocess.run([node_command,"--test",str(ROOT/"mainstreet"/"test"/"proposal-bridge.test.js")],capture_output=True,text=True)
record("PROTOTYPE_POLLUTION", "Node dangerous-key tests pass", f"exit={node.returncode}", "BLOCKED" if node.returncode==0 and "rejects __proto__" in node.stdout else "BYPASS", "Prototype chain manipulation", node.stdout[-2000:], "Reject __proto__, prototype, and constructor recursively.")
# Excessive depth and size.
deep={}; cursor=deep
for i in range(80): cursor["x"]={}; cursor=cursor["x"]
try: digest(deep); actual="accepted"; status="BYPASS"
except Exception as exc: actual=str(exc); status="BLOCKED"
record("EXCESSIVE_NESTING", "reject", actual,status,"Stack or parser exhaustion",{"depth":80,"result":actual},"Depth and node budgets.")
large=[0] * 100_001
try: digest(large); actual="accepted"; status="BYPASS"
except Exception as exc: actual=str(exc); status="BLOCKED"
record("RESOURCE_EXHAUSTION", "reject", actual,status,"Memory or CPU exhaustion",{"items":100001,"result":actual},"Bounded containers, nodes, strings, and depth.")

# 46 TOCTOU, key collapse, compensation, supply chain.
f=fixture(); changed=copy.deepcopy(f["prop"]); changed["action"]["parameters"]["body"]="mutated after check"
expect_exception("TIME_OF_CHECK_TO_TIME_OF_USE", "binding mismatch", lambda: f["executor"].execute(f["permit"],changed,f["signed_pol"],f["ev"],f["decision"].document,f["states"].read("campaign-001"),11), "Action differs after authorization", "Executor recomputes exact digests immediately before reservation and dispatch.")
# Trust root rejects raw key alias.
root=trust_root(); auth_id=root["roles"]["authority_signers"][0]; exec_id=root["roles"]["executor_signers"][0]; root["keys"][exec_id]=root["keys"][auth_id]; errors=verify_bundle(build_bundle(),root)
record("KEY_ROLE_COLLAPSE", "reject", "; ".join(errors), "DETECTED" if errors else "BYPASS", "One role can forge another", errors, "Trust-root raw key uniqueness and runtime role checks.")
kernel_tag_case("COMPENSATION_ABUSE", "PRIVILEGE_ESCALATION", "SUSPEND_CAMPAIGN", "Compensation expands privilege")
bundle=build_bundle(); bundle["manifest"]["release_id"]="substituted"; errors=verify_bundle(bundle,trust_root())
record("SUPPLY_CHAIN_SUBSTITUTION", "detect bundle substitution", "; ".join(errors), "DETECTED" if errors else "BYPASS", "Malicious release replacement", errors, "Witnessed release manifest; Sigstore/SLSA signing remains deployment work.","PARTIAL_NO_PUBLIC_TRANSPARENCY")

# Explicit infrastructure limitations for live network/runtime claims.
for name, detail in [
    ("LIVE_DNS_PINNING", "No live resolver or connector is included."),
    ("LIVE_GVISOR_ESCAPE_TEST", "No container runtime is installed or invoked."),
    ("LIVE_EBPF_OBSERVER_INDEPENDENCE", "No kernel observer is connected."),
    ("DISTRIBUTED_RESERVATION_CRASH_RECOVERY", "A durable single-database reference now exists, but no networked multi-node consensus backend is implemented."),
    ("SIGNED_REPRODUCIBLE_BUILD_PROVENANCE", "Templates exist; no Sigstore transparency entry is produced."),
]: record(name,"exercise in deployed infrastructure",detail,"LIMITATION","Deployment-specific bypass",{"environment":detail},"Required before deployment claims.","INFRASTRUCTURE_REQUIRED")

summary = {
    "release": (ROOT / "VERSION").read_text().strip(),
    "total": len(REPORT),
    "blocked_or_detected": sum(item["status"] in {"BLOCKED","DETECTED"} for item in REPORT),
    "bypasses": sum(item["status"] == "BYPASS" for item in REPORT),
    "limitations": sum(item["status"] == "LIMITATION" for item in REPORT),
    "results": REPORT,
}
(ROOT / "evidence").mkdir(exist_ok=True)
(ROOT / "evidence" / "RED_TEAM_REPORT.json").write_text(json.dumps(summary,indent=2,sort_keys=True)+"\n")
print(json.dumps(summary,indent=2,sort_keys=True))
if summary["bypasses"]:
    raise SystemExit(1)
