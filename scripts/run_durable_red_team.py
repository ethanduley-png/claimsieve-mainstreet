#!/usr/bin/env python3
from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))

from claimsieve_ref.canonical import digest  # noqa: E402
from claimsieve_ref.durable_state import (  # noqa: E402
    DispatchTicket,
    DurableCampaignStateStore,
    DurableExecutor,
    DurableProviderSimulator,
    DurableStateError,
    DurableStateService,
    IndependentObserver,
    InjectedCrash,
    QuorumStateMachineSimulator,
)
from claimsieve_ref.fixtures import evidence, keypairs, policy, proposal, signed_policy  # noqa: E402
from claimsieve_ref.kernel import evaluate  # noqa: E402
from claimsieve_ref.runtime import Authority  # noqa: E402
from claimsieve_ref.verifier import verify_bundle  # noqa: E402

REPORT: list[dict[str, Any]] = []


def record(
    attack: str,
    expected: str,
    actual: str,
    status: str,
    impact: str,
    trace: Any,
    control: str,
    coverage: str = "EXECUTED",
) -> None:
    REPORT.append(
        {
            "attack": attack,
            "expected_result": expected,
            "actual_result": actual,
            "status": status,
            "impact_if_unblocked": impact,
            "reproducible_trace": trace,
            "control": control,
            "coverage": coverage,
        }
    )


def expect_error(
    attack: str,
    phrase: str,
    call: Callable[[], Any],
    impact: str,
    control: str,
) -> None:
    try:
        value = call()
    except Exception as exc:
        passed = phrase.lower() in str(exc).lower()
        record(
            attack,
            f"reject with {phrase}",
            str(exc),
            "BLOCKED" if passed else "BYPASS",
            impact,
            {"exception": type(exc).__name__, "message": str(exc)},
            control,
        )
    else:
        record(
            attack,
            f"reject with {phrase}",
            f"accepted: {value!r}",
            "BYPASS",
            impact,
            {"returned": repr(value)},
            control,
        )


def fixture(mode: str = "success") -> dict[str, Any]:
    temp = tempfile.TemporaryDirectory()
    root = Path(temp.name)
    keys = keypairs()
    state = DurableStateService(
        root / "state.sqlite3",
        executor_keys={keys["executor"].key_id: keys["executor"].public},
        observer_keys={keys["observer"].key_id: keys["observer"].public},
    )
    provider = DurableProviderSimulator(root / "provider.sqlite3", mode)
    ev = evidence(10)
    prop = proposal(ev, 10)
    signed = signed_policy()
    pol = policy()
    prior = state.read_campaign(prop["campaign_id"]).state
    decision = evaluate(prop, pol, ev, prior, 10)
    authority = Authority(
        keys["authority"],
        {keys["approver"].key_id: keys["approver"].public},
        {keys["policy_authority"].key_id: keys["policy_authority"].public},
        {
            keys[name].key_id: keys[name].public
            for name in (
                "crm_evidence",
                "registry_evidence",
                "deployment_evidence",
                "epoch_evidence",
            )
        },
        DurableCampaignStateStore(state),
    )
    permit = authority.issue(prop, signed, ev, decision.document, 10, nonce="77" * 24)
    executor = DurableExecutor(
        state,
        provider,
        {keys["authority"].key_id: keys["authority"].public},
        keys["executor"],
    )
    observer = IndependentObserver(
        state,
        provider,
        keys["observer"],
    )
    return locals()


# 1. Durable restart and exact permit registration.
f = fixture()
reopened = DurableStateService(f["state"].path)
snapshot = reopened.read_campaign("campaign-001")
reservation = reopened.reserve(f["permit"], f["prop"], 11)
record(
    "PROCESS_RESTART_STATE_RESET",
    "campaign sequence and permit survive restart",
    f"sequence={snapshot.state.last_sequence}, reserved={reservation is not None}",
    "BLOCKED" if snapshot.state.last_sequence == 10 and reservation is not None else "BYPASS",
    "Restart resets campaign limits or loses authorization state",
    {"campaign": snapshot.state.as_canonical(), "reservation": reservation},
    "SQLite FULL-synchronous transaction commits campaign successor and permit before return.",
)
f["temp"].cleanup()

# 2. Duplicate reservation.
f = fixture()
first = f["state"].reserve(f["permit"], f["prop"], 11)
second = f["state"].reserve(f["permit"], f["prop"], 11)
record(
    "DUPLICATE_RESERVATION",
    "exactly one reservation",
    f"first={first is not None}, second={second is not None}",
    "BLOCKED" if first is not None and second is None else "BYPASS",
    "Double execution",
    {"first": first, "second": second},
    "Unique permit and idempotency constraints inside a serialized write transaction.",
)
f["temp"].cleanup()

# 3. Crash after reservation.
f = fixture()
try:
    f["executor"].execute(
        f["permit"], f["prop"], f["signed"], f["ev"], f["decision"].document, 11,
        failpoint="after_reservation",
    )
except InjectedCrash as exc:
    queue = DurableStateService(f["state"].path).recovery_queue()
    passed = len(queue) == 1 and queue[0]["status"] == "RESERVED"
    record(
        "CRASH_AFTER_RESERVATION",
        "durable RESERVED recovery item",
        queue[0]["status"] if queue else "missing",
        "BLOCKED" if passed else "BYPASS",
        "Lost reservation permits replay or stranded authority",
        {"crash": str(exc), "recovery_queue": queue},
        "Reservation commits before the executor can dispatch.",
    )
f["temp"].cleanup()

# 4. Crash after remote commit but before local receipt.
f = fixture("success")
try:
    f["executor"].execute(
        f["permit"], f["prop"], f["signed"], f["ev"], f["decision"].document, 11,
        failpoint="after_provider",
    )
except InjectedCrash as exc:
    row = f["state"].recovery_queue()[0]
    observation = f["observer"].reconcile(row["reservation_id"], f["prop"], 12)
    record(
        "CRASH_AFTER_PROVIDER_COMMIT",
        "independent provider query confirms effect without retry",
        observation["reconciliation"],
        "BLOCKED" if observation["reconciliation"] == "CONFIRMED_SUCCESS" else "BYPASS",
        "Duplicate side effect after crash",
        {"crash": str(exc), "reservation": row, "observation": observation},
        "Provider idempotency record plus independent reconciliation.",
    )
f["temp"].cleanup()

# 5. Timeout before provider commit remains unknown.
f = fixture("timeout_before_commit")
result = f["executor"].execute(
    f["permit"], f["prop"], f["signed"], f["ev"], f["decision"].document, 11
)
observation = f["observer"].reconcile(result["reservation"]["reservation_id"], f["prop"], 12)
record(
    "TIMEOUT_BEFORE_COMMIT",
    "OUTCOME_UNKNOWN and no automatic retry",
    f"{observation['reconciliation']}, retry={result['automatic_retry_allowed']}",
    "BLOCKED" if observation["reconciliation"] == "OUTCOME_UNKNOWN" and not result["automatic_retry_allowed"] else "BYPASS",
    "Unknown remote state treated as safe failure",
    {"execution": result, "observation": observation},
    "Unknown is durable and only independent evidence may resolve it.",
)
f["temp"].cleanup()

# 6. Timeout after provider commit resolves to success.
f = fixture("timeout_after_commit")
result = f["executor"].execute(
    f["permit"], f["prop"], f["signed"], f["ev"], f["decision"].document, 11
)
observation = f["observer"].reconcile(result["reservation"]["reservation_id"], f["prop"], 12)
record(
    "TIMEOUT_AFTER_COMMIT",
    "independent query confirms success",
    observation["reconciliation"],
    "BLOCKED" if observation["reconciliation"] == "CONFIRMED_SUCCESS" else "BYPASS",
    "Duplicate retry after committed effect",
    {"execution": result, "observation": observation},
    "Same idempotency key plus provider read API.",
)
f["temp"].cleanup()

# 7. Revocation before dispatch.
f = fixture()
def revoke_before() -> None:
    f["state"].revoke_permit(f["permit"]["permit_id"], "operator stop", 11)
expect_error(
    "REVOCATION_BEFORE_DISPATCH",
    "revoked",
    lambda: f["executor"].execute(
        f["permit"], f["prop"], f["signed"], f["ev"], f["decision"].document, 11,
        before_dispatch=revoke_before,
    ),
    "Execution after revocation",
    "Revocation is checked inside the dispatch commit transaction.",
)
f["temp"].cleanup()

# 8. Revocation after dispatch is not misrepresented as prevention.
f = fixture()
reservation = f["state"].reserve(f["permit"], f["prop"], 11)
assert reservation is not None
ticket = f["executor"].claim_reservation_for_dispatch(
    reservation["reservation_id"], 11
)
event = f["state"].revoke_permit(f["permit"]["permit_id"], "late stop", 11)
response = f["provider"].invoke(f["prop"]["action"], ticket)
observation = f["observer"].reconcile(reservation["reservation_id"], f["prop"], 12)
passed = event["payload"]["in_flight_at_revocation"] and observation["reconciliation"] == "CONFIRMED_SUCCESS"
record(
    "REVOCATION_AFTER_DISPATCH",
    "mark in flight and reconcile; do not claim retroactive prevention",
    f"in_flight={event['payload']['in_flight_at_revocation']}, {observation['reconciliation']}",
    "DETECTED" if passed else "BYPASS",
    "False assurance that a dispatched request was stopped",
    {"revocation": event, "provider": response, "observation": observation},
    "Explicit dispatch linearization point and in-flight revocation trace.",
)
f["temp"].cleanup()

# 9. Global freeze before dispatch.
f = fixture()
def freeze_before() -> None:
    f["state"].freeze("incident", 11)
expect_error(
    "FREEZE_BEFORE_DISPATCH",
    "frozen",
    lambda: f["executor"].execute(
        f["permit"], f["prop"], f["signed"], f["ev"], f["decision"].document, 11,
        before_dispatch=freeze_before,
    ),
    "Execution after containment freeze",
    "Global freeze is checked at the dispatch commit point.",
)
f["temp"].cleanup()

# 10. Stale fencing token.
f = fixture()
resource = digest({"resource": "same"})
newer = DispatchTicket("r2", "p2", "c", "a2", "q2", resource, "id2", 20, 0)
older = DispatchTicket("r1", "p1", "c", "a1", "q1", resource, "id1", 10, 0)
new_result = f["provider"].invoke(f["prop"]["action"], newer)
old_result = f["provider"].invoke(f["prop"]["action"], older)
record(
    "STALE_EXECUTOR_FENCE",
    "reject lower fencing token after newer token",
    old_result["status"],
    "BLOCKED" if new_result["status"] == "accepted" and old_result["status"] == "stale_fence" else "BYPASS",
    "Old leader executes after failover",
    {"newer": new_result, "older": old_result},
    "Resource-scoped monotonically increasing fencing token.",
)
f["temp"].cleanup()

# 11. Idempotency replay and mutation.
f = fixture()
reservation = f["state"].reserve(f["permit"], f["prop"], 11)
assert reservation is not None
ticket = f["executor"].claim_reservation_for_dispatch(
    reservation["reservation_id"], 11
)
first = f["provider"].invoke(f["prop"]["action"], ticket)
second = f["provider"].invoke(f["prop"]["action"], ticket)
record(
    "IDEMPOTENT_REPLAY",
    "same key and request returns original result",
    f"{second['status']}, replay={second.get('idempotent_replay')}",
    "BLOCKED" if second.get("idempotent_replay") else "BYPASS",
    "Duplicate provider object",
    {"first": first, "second": second},
    "Provider stores the first result by idempotency key.",
)
mutated = DispatchTicket(
    ticket.reservation_id, ticket.permit_id, ticket.campaign_id, ticket.action_digest,
    digest({"different": True}), ticket.resource_key, ticket.idempotency_key,
    ticket.fencing_token + 1, ticket.containment_epoch,
)
expect_error(
    "IDEMPOTENCY_PARAMETER_MUTATION",
    "different request",
    lambda: f["provider"].invoke(f["prop"]["action"], mutated),
    "Idempotency key hides a different action",
    "Idempotency key is bound to request digest.",
)
f["temp"].cleanup()

# 12. Conflicting provider receipt.
f = fixture("conflicting_receipt")
result = f["executor"].execute(
    f["permit"], f["prop"], f["signed"], f["ev"], f["decision"].document, 11
)
observation = f["observer"].reconcile(result["reservation"]["reservation_id"], f["prop"], 12)
record(
    "CONFLICTING_PROVIDER_RECEIPT",
    "contradictory provider evidence remains OUTCOME_UNKNOWN, conflict is explicit, and the campaign is contained",
    f"{observation['reconciliation']}, conflict={observation['receipt_conflict']}",
    "DETECTED" if observation["reconciliation"] == "OUTCOME_UNKNOWN" and observation["receipt_conflict"] else "BYPASS",
    "Contradictory evidence is collapsed into a false terminal outcome",
    observation,
    "Independent provider contradiction is preserved as uncertainty and triggers containment.",
)
f["temp"].cleanup()

# 13. Forged executor receipt stored locally.
f = fixture()
result = f["executor"].execute(
    f["permit"], f["prop"], f["signed"], f["ev"], f["decision"].document, 11
)
reservation_id = result["reservation"]["reservation_id"]
connection = sqlite3.connect(f["state"].path)
row = connection.execute(
    "SELECT provider_receipt_json FROM reservations WHERE reservation_id = ?",
    (reservation_id,),
).fetchone()
assert row is not None
forged_receipt = json.loads(row[0])
forged_receipt["provider_status"] = "rejected"
connection.execute(
    "UPDATE reservations SET provider_receipt_json = ? WHERE reservation_id = ?",
    (json.dumps(forged_receipt, separators=(",", ":"), sort_keys=True), reservation_id),
)
connection.commit()
connection.close()
forged_observation = f["observer"].reconcile(reservation_id, f["prop"], 12)
record(
    "FORGED_EXECUTOR_RECEIPT",
    "forged local executor narrative has no authority over terminal classification",
    forged_observation["reconciliation"],
    "BLOCKED" if forged_observation["reconciliation"] == "CONFIRMED_SUCCESS" else "BYPASS",
    "Observer lets a forged executor narrative override independent provider evidence",
    forged_observation,
    "Executor receipts are retained for audit and conflict evidence but removed from the observer's terminal-outcome trust path.",
)
f["temp"].cleanup()

# 14. Divergent effect.
f = fixture("divergent")
result = f["executor"].execute(
    f["permit"], f["prop"], f["signed"], f["ev"], f["decision"].document, 11
)
observation = f["observer"].reconcile(result["reservation"]["reservation_id"], f["prop"], 12)
record(
    "DIVERGENT_EXTERNAL_EFFECT",
    "DIVERGENT_EFFECT",
    observation["reconciliation"],
    "DETECTED" if observation["reconciliation"] == "DIVERGENT_EFFECT" else "BYPASS",
    "Provider changes destination or parameters",
    observation,
    "Independent effect digest comparison.",
)
f["temp"].cleanup()

# 15. Terminal outcome rewrite.
f = fixture()
result = f["executor"].execute(
    f["permit"], f["prop"], f["signed"], f["ev"], f["decision"].document, 11
)
reservation_id = result["reservation"]["reservation_id"]
f["observer"].reconcile(reservation_id, f["prop"], 12)
unsigned_conflict = {
    "schema_version": "claimsieve.observer_receipt.v2",
    "reservation_id": reservation_id,
    "permit_id": f["permit"]["permit_id"],
    "campaign_id": f["permit"]["campaign_id"],
    "provider_record_digest": None,
    "observed_action_digest": None,
    "reconciliation": "CONFIRMED_FAILURE",
    "receipt_conflict": False,
    "observed_at_seq": 13,
    "observer_key_id": f["keys"]["observer"].key_id,
}
conflicting_observation = {
    **unsigned_conflict,
    "signature": f["keys"]["observer"].sign(
        "observer-receipt-v2", unsigned_conflict
    ),
}
expect_error(
    "TERMINAL_OUTCOME_REWRITE",
    "cannot be rewritten",
    lambda: f["state"].record_observation(
        reservation_id, conflicting_observation, 13
    ),
    "Audit history changes a known outcome",
    "Terminal reconciliation is immutable and observer authenticated.",
)
f["temp"].cleanup()

# 16. Journal tampering.
f = fixture()
connection = sqlite3.connect(f["state"].path)
connection.execute("UPDATE journal SET payload_json = ? WHERE event_sequence = 1", ('{"tampered":true}',))
connection.commit()
connection.close()
record(
    "STATE_JOURNAL_TAMPERING",
    "detect hash-chain break",
    str(f["state"].verify_journal()),
    "DETECTED" if not f["state"].verify_journal() else "BYPASS",
    "Operational history rewritten",
    {"verified": f["state"].verify_journal()},
    "Canonical hash chain over durable state events.",
)
f["temp"].cleanup()

# 17. Unsigned executor command cannot claim a reservation.
f = fixture()
reservation = f["state"].reserve(f["permit"], f["prop"], 11)
assert reservation is not None
expect_error(
    "UNAUTHENTICATED_EXECUTOR_COMMAND",
    "signed executor command required",
    lambda: f["state"].begin_execution(
        reservation["reservation_id"], "spiffe://attacker/executor", 11
    ),
    "A caller with database API access claims the executor role",
    "State transitions require a command signed by a configured executor key.",
)
f["temp"].cleanup()

# 18. Expired permit cannot be reserved.
f = fixture()
expect_error(
    "EXPIRED_PERMIT_RESERVATION",
    "outside durable validity",
    lambda: f["state"].reserve(
        f["permit"], f["prop"], int(f["permit"]["expires_at_seq"]) + 1
    ),
    "Expired capability creates a fresh execution reservation",
    "Durable permit validity is rechecked inside the reservation transaction.",
)
f["temp"].cleanup()

# 19. Permit that expires after reservation cannot cross dispatch commit.
f = fixture()
reserve_seq = int(f["permit"]["expires_at_seq"])
reservation = f["state"].reserve(f["permit"], f["prop"], reserve_seq)
assert reservation is not None
reservation_id = reservation["reservation_id"]
f["state"].begin_execution(
    reservation_id,
    f["executor"].executor_id,
    reserve_seq,
    f["executor"]._signed_command("BEGIN_EXECUTION", reservation_id, reserve_seq),
)
dispatch_seq = reserve_seq + 1
expect_error(
    "PERMIT_EXPIRY_BEFORE_DISPATCH",
    "expired before dispatch",
    lambda: f["state"].claim_dispatch(
        reservation_id,
        dispatch_seq,
        f["executor"]._signed_command(
            "CLAIM_DISPATCH", reservation_id, dispatch_seq
        ),
    ),
    "A reservation extends authority beyond permit expiration",
    "Validity is checked again at the dispatch commit point.",
)
f["temp"].cleanup()

# 20. Forged executor receipt cannot update provider-attempt state.
f = fixture()
reservation = f["state"].reserve(f["permit"], f["prop"], 11)
assert reservation is not None
ticket = f["executor"].claim_reservation_for_dispatch(
    reservation["reservation_id"], 11
)
forged_attempt_receipt = {
    "schema_version": "claimsieve.executor_receipt.v2",
    "trace_id": f["prop"]["trace_id"],
    "campaign_id": f["prop"]["campaign_id"],
    "permit_id": f["permit"]["permit_id"],
    "reservation_id": ticket.reservation_id,
    "action_digest": ticket.action_digest,
    "request_digest": ticket.request_digest,
    "idempotency_key": ticket.idempotency_key,
    "fencing_token": ticket.fencing_token,
    "containment_epoch": ticket.containment_epoch,
    "provider_status": "accepted",
    "provider_id": "provider:forged",
    "attempted_at_seq": 11,
    "executor_key_id": f["keys"]["executor"].key_id,
    "signature": "ed25519:forged",
}
expect_error(
    "FORGED_PROVIDER_ATTEMPT_RECEIPT",
    "signature invalid",
    lambda: f["state"].persist_provider_attempt(
        ticket.reservation_id,
        {"status": "accepted", "provider_id": "provider:forged"},
        forged_attempt_receipt,
        11,
    ),
    "A caller writes provider-attempt state without executor authority",
    "Provider-attempt persistence verifies the configured executor key and exact bindings.",
)
f["temp"].cleanup()

# 21. Unsigned observer outcome cannot become authoritative state.
f = fixture()
result = f["executor"].execute(
    f["permit"], f["prop"], f["signed"], f["ev"], f["decision"].document, 11
)
reservation_id = result["reservation"]["reservation_id"]
expect_error(
    "UNAUTHENTICATED_OBSERVER_OUTCOME",
    "trusted observer receipt key",
    lambda: f["state"].record_observation(
        reservation_id,
        {
            "schema_version": "claimsieve.observer_receipt.v2",
            "reservation_id": reservation_id,
            "reconciliation": "CONFIRMED_SUCCESS",
        },
        12,
    ),
    "An arbitrary caller marks an unknown effect as successful",
    "Outcome transitions require a receipt signed by a configured observer key.",
)
f["temp"].cleanup()

# 22-25 deterministic quorum model.
cluster = QuorumStateMachineSimulator()
cluster.elect("n1")
first_fence = cluster.commit("initial")
cluster.partition([{"n1"}, {"n2", "n3"}])
minority = cluster.commit("minority")
record(
    "MINORITY_PARTITION_WRITE",
    "reject without quorum",
    str(minority),
    "BLOCKED" if minority is None else "BYPASS",
    "Split-brain campaign successor",
    cluster.trace,
    "Quorum-only commit model.",
    "DETERMINISTIC_MODEL",
)
new_election = cluster.elect("n2")
second_fence = cluster.commit("majority")
record(
    "MAJORITY_FAILOVER",
    "new term commits with larger fence",
    f"elected={new_election}, first={first_fence}, second={second_fence}",
    "BLOCKED" if new_election and first_fence is not None and second_fence is not None and second_fence > first_fence else "BYPASS",
    "Failover reuses stale authority",
    cluster.trace,
    "Monotonic term, commit index, and fence in the model.",
    "DETERMINISTIC_MODEL",
)
cluster.heal()
cluster.nodes["n3"].commit_index = 0
stale_election = cluster.elect("n3")
record(
    "STALE_LOG_ELECTION",
    "reject stale candidate",
    str(stale_election),
    "BLOCKED" if not stale_election else "BYPASS",
    "Old state becomes leader",
    cluster.trace,
    "Candidate log freshness requirement in model.",
    "DETERMINISTIC_MODEL",
)

# 26. Shared observer receipt v2 wire contract.
v2_bundle = json.loads(
    (ROOT / "vectors" / "valid_evidence_bundle_observer_v2.json").read_text(encoding="utf-8")
)
v2_schema = json.loads(
    (ROOT / "schemas" / "observer-receipt-v2.schema.json").read_text(encoding="utf-8")
)
trust_root = json.loads(
    (ROOT / "trust" / "fixture-trust-root.json").read_text(encoding="utf-8")
)
v2_receipts = [
    item
    for item in v2_bundle.get("receipts", [])
    if isinstance(item, dict)
    and item.get("schema_version") == "claimsieve.observer_receipt.v2"
]
v2_receipt = v2_receipts[0] if len(v2_receipts) == 1 else None
v2_required = set(v2_schema.get("required", []))
v2_fields = set(v2_receipt) if isinstance(v2_receipt, dict) else set()
v2_errors = verify_bundle(v2_bundle, trust_root)
v2_contract_ok = (
    isinstance(v2_receipt, dict)
    and v2_fields == v2_required
    and v2_schema.get("additionalProperties") is False
    and v2_schema.get("properties", {})
    .get("schema_version", {})
    .get("const") == "claimsieve.observer_receipt.v2"
    and not v2_errors
)
record(
    "OBSERVER_RECEIPT_V2_WIRE_DIVERGENCE",
    "shared v2 vector exactly matches the authoritative schema and portable verifier semantics",
    (
        f"receipts={len(v2_receipts)}, exact_fields={v2_fields == v2_required}, "
        f"verifier_errors={v2_errors}"
    ),
    "BLOCKED" if v2_contract_ok else "BYPASS",
    "Cross-implementation receipt consumers can disagree",
    {
        "schema_required": sorted(v2_required),
        "receipt_fields": sorted(v2_fields),
        "verifier_errors": v2_errors,
    },
    "Authoritative v2 schema plus one shared signed vector; the strict Rust workflow consumes the same vector.",
)

# Honest limitations.
for name, detail, expected, impact, control in [
    (
        "MULTI_NODE_CONSENSUS_IMPLEMENTATION",
        "No networked Raft or equivalent production consensus service is implemented; partition behavior is a deterministic safety model.",
        "validate in deployed infrastructure",
        "Infrastructure-specific failure remains untested",
        "Required before live consequential execution.",
    ),
    (
        "REMOTE_PROVIDER_ATOMICITY",
        "The dispatch commit point and remote side effect cannot be one atomic transaction; post-dispatch revocation requires reconciliation.",
        "validate in deployed infrastructure",
        "Infrastructure-specific failure remains untested",
        "Required before live consequential execution.",
    ),
    (
        "INDEPENDENT_HOST_OBSERVER",
        "Provider and observer use a separate SQLite database but run on the same test host and process family.",
        "validate in deployed infrastructure",
        "Infrastructure-specific failure remains untested",
        "Required before live consequential execution.",
    ),
]:
    record(
        name,
        expected,
        detail,
        "LIMITATION",
        impact,
        {"detail": detail},
        control,
        "INFRASTRUCTURE_REQUIRED",
    )

summary = {
    "release": (ROOT / "VERSION").read_text().strip(),
    "total": len(REPORT),
    "blocked_or_detected": sum(item["status"] in {"BLOCKED", "DETECTED"} for item in REPORT),
    "bypasses": sum(item["status"] == "BYPASS" for item in REPORT),
    "limitations": sum(item["status"] == "LIMITATION" for item in REPORT),
    "results": REPORT,
}
(ROOT / "evidence").mkdir(exist_ok=True)
(ROOT / "evidence" / "DURABLE_RED_TEAM_REPORT.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print(json.dumps(summary, indent=2, sort_keys=True))
if summary["bypasses"]:
    raise SystemExit(1)
