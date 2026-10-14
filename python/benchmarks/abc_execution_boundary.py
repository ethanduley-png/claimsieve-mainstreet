from __future__ import annotations

import copy
import json
import math
import os
import statistics
import time
from pathlib import Path
from typing import Any, Callable

from claimsieve_ref.canonical import canonical_bytes, digest
from claimsieve_ref.fixtures import evidence, keypairs, proposal, signed_policy
from claimsieve_ref.kernel import evaluate
from claimsieve_ref.model import (
    action_digest,
    approval_digest,
    approval_signing_subject,
    destination_digest,
    evidence_root,
    parameter_digest,
    proposal_digest,
)
from claimsieve_ref.runtime import (
    Authority,
    CampaignStateStore,
    ContainmentController,
    Executor,
    PermitError,
    ReservationStore,
    SimulatedConnector,
    SimulatedExternalSystem,
)

HOT_N = int(os.environ.get("CLAIMSIEVE_ABC_HOT_N", "1200"))
WARMUP_N = int(os.environ.get("CLAIMSIEVE_ABC_WARMUP_N", "120"))
ISSUE_N = int(os.environ.get("CLAIMSIEVE_ABC_ISSUE_N", "120"))


def percentile_ns(samples: list[int], fraction: float) -> int:
    ordered = sorted(samples)
    if not ordered:
        return 0
    index = max(0, min(len(ordered) - 1, math.ceil(fraction * len(ordered)) - 1))
    return ordered[index]


def latency_summary(samples: list[int], elapsed_ns: int, cpu_ns: int) -> dict[str, Any]:
    return {
        "samples": len(samples),
        "p50_us": round(percentile_ns(samples, 0.50) / 1_000, 3),
        "p95_us": round(percentile_ns(samples, 0.95) / 1_000, 3),
        "p99_us": round(percentile_ns(samples, 0.99) / 1_000, 3),
        "mean_us": round(statistics.fmean(samples) / 1_000, 3),
        "ops_per_second": round(len(samples) / (elapsed_ns / 1_000_000_000), 1),
        "cpu_us_per_op": round((cpu_ns / max(1, len(samples))) / 1_000, 3),
    }


def make_authority(keys: dict[str, Any], states: CampaignStateStore) -> Authority:
    return Authority(
        keys["authority"],
        {keys["approver"].key_id: keys["approver"].public},
        {keys["policy_authority"].key_id: keys["policy_authority"].public},
        {
            keys[name].key_id: keys[name].public
            for name in ("crm_evidence", "registry_evidence", "deployment_evidence", "epoch_evidence")
        },
        states,
    )


def make_fixture(campaign_id: str = "campaign-abc") -> dict[str, Any]:
    keys = keypairs()
    ev = evidence(10)
    signed_pol = signed_policy()
    pol = signed_pol["policy"]
    prop = proposal(
        ev,
        10,
        approve=True,
        campaign_id=campaign_id,
        proposal_id=f"proposal-{campaign_id}",
        trace_id=f"trace-{campaign_id}",
        session_id=f"session-{campaign_id}",
    )
    states = CampaignStateStore()
    prior = states.read(campaign_id)
    decision = evaluate(prop, pol, ev, prior, 10)
    authority = make_authority(keys, states)
    permit = authority.issue(prop, signed_pol, ev, decision.document, 10, nonce="11" * 24)
    state = states.read(campaign_id)
    return {
        "keys": keys,
        "evidence": ev,
        "signed_policy": signed_pol,
        "policy": pol,
        "proposal": prop,
        "states": states,
        "decision": decision.document,
        "authority": authority,
        "permit": permit,
        "state": state,
    }


def command_from_proposal(prop: dict[str, Any]) -> dict[str, Any]:
    # This is exactly the subject hashed by model.action_digest().
    return {
        "tenant_id": prop["tenant_id"],
        "campaign_id": prop["campaign_id"],
        "principal": prop["principal"],
        "objective": copy.deepcopy(prop["objective"]),
        "action": copy.deepcopy(prop["action"]),
    }


def resign_permit(permit: dict[str, Any], authority_key: Any, serial: int) -> dict[str, Any]:
    changed = copy.deepcopy(permit)
    changed["permit_id"] = "permit:" + digest(
        {"base": permit["permit_id"], "serial": serial}
    ).removeprefix("sha256:")
    changed["nonce"] = f"{serial:048x}"[-48:]
    unsigned = {key: value for key, value in changed.items() if key != "signature"}
    changed["signature"] = authority_key.sign("permit-v1", unsigned)
    return changed


def make_attestations(permit: dict[str, Any], keys: dict[str, Any]) -> dict[str, Any]:
    proposal_subject = {
        "proposal_digest": permit["proposal_digest"],
        "action_digest": permit["action_digest"],
        "destination_digest": permit["destination_digest"],
        "parameter_digest": permit["parameter_digest"],
    }
    evidence_subject = {
        "evidence_root": permit["evidence_root"],
    }
    decision_subject = {
        "decision_digest": permit["decision_digest"],
        "proposal_digest": permit["proposal_digest"],
        "policy_digest": permit["policy_digest"],
        "signed_policy_digest": permit["signed_policy_digest"],
        "evidence_root": permit["evidence_root"],
        "approval_digest": permit["approval_digest"],
        "campaign_state_digest": permit["campaign_state_digest"],
        "verdict": "ALLOW",
    }
    return {
        "proposal": {
            "subject": proposal_subject,
            "key_id": keys["proposal"].key_id,
            "signature": keys["proposal"].sign("proposal-commitment-v1", proposal_subject),
        },
        "evidence": {
            "subject": evidence_subject,
            "key_id": keys["evidence"].key_id,
            "signature": keys["evidence"].sign("evidence-commitment-v1", evidence_subject),
        },
        "decision": {
            "subject": decision_subject,
            "key_id": keys["decision"].key_id,
            "signature": keys["decision"].sign("decision-commitment-v1", decision_subject),
        },
    }


def verify_attestation(attestation: dict[str, Any], public: Any, domain: str) -> None:
    if attestation.get("key_id") != public.key_id:
        raise PermitError("commitment signer mismatch")
    if not public.verify(domain, attestation["subject"], str(attestation.get("signature", ""))):
        raise PermitError("commitment signature invalid")


def make_boundary_components(keys: dict[str, Any]):
    system = SimulatedExternalSystem("success")
    containment = ContainmentController(keys["containment"])
    reservations = ReservationStore()
    connector = SimulatedConnector(system)
    return system, containment, reservations, connector


def _verify_common_compact(
    permit: dict[str, Any],
    command: dict[str, Any],
    state: Any,
    seq: int,
    keys: dict[str, Any],
    containment: Any,
) -> None:
    if permit.get("schema_version") != "claimsieve.permit.v1":
        raise PermitError("unsupported permit schema")
    unsigned = {key: value for key, value in permit.items() if key != "signature"}
    if permit.get("authority_key_id") != keys["authority"].key_id or not keys["authority"].public.verify(
        "permit-v1", unsigned, str(permit.get("signature", ""))
    ):
        raise PermitError("permit signature invalid")
    if containment.is_frozen() or containment.is_revoked(str(permit["permit_id"])):
        raise PermitError("execution contained")
    if containment.is_suspended(str(permit["campaign_id"])) or state.status != "ACTIVE":
        raise PermitError("campaign suspended")
    if not (permit["valid_from_seq"] <= seq <= permit["expires_at_seq"]):
        raise PermitError("permit outside validity sequence")
    if permit.get("max_uses") != 1:
        raise PermitError("permit use count invalid")
    if permit.get("tenant_id") != command["tenant_id"]:
        raise PermitError("tenant binding mismatch")
    if permit.get("campaign_id") != command["campaign_id"]:
        raise PermitError("campaign binding mismatch")
    if permit.get("principal") != command["principal"]:
        raise PermitError("principal binding mismatch")
    if permit.get("action_digest") != digest(command):
        raise PermitError("action binding mismatch")
    if permit.get("destination_digest") != digest(command["action"]["destination"]):
        raise PermitError("destination binding mismatch")
    if permit.get("parameter_digest") != digest(command["action"]["parameters"]):
        raise PermitError("parameter binding mismatch")
    if permit.get("campaign_state_digest") != digest(state.as_canonical()):
        raise PermitError("campaign state binding mismatch")


def compact_execute_a(
    permit: dict[str, Any],
    command: dict[str, Any],
    state: Any,
    seq: int,
    keys: dict[str, Any],
    reservations: ReservationStore,
    containment: Any,
    connector: SimulatedConnector,
) -> dict[str, Any]:
    """A: strongest single-envelope reference.

    The upstream authority is the current strict ClaimSieve issuer, but at the
    hot boundary only its signed envelope plus the minimal command is used.
    There are no independent proposal/evidence/decision commitment signatures.
    """
    _verify_common_compact(permit, command, state, seq, keys, containment)
    reservation = reservations.reserve(str(permit["permit_id"]), str(permit["action_digest"]), seq)
    if reservation is None:
        raise PermitError("permit replay or concurrent duplicate")
    if containment.is_frozen() or containment.is_revoked(str(permit["permit_id"])):
        raise PermitError("execution contained")
    provider = connector.invoke(command["action"], str(permit["permit_id"]))
    unsigned_receipt = {
        "schema_version": "claimsieve.executor_receipt.v1",
        "campaign_id": command["campaign_id"],
        "permit_id": permit["permit_id"],
        "reservation_id": reservation["reservation_id"],
        "action_digest": digest(command),
        "provider_status": provider["status"],
        "provider_id": provider["provider_id"],
        "attempted_at_seq": seq,
        "executor_key_id": keys["executor"].key_id,
    }
    return {
        **unsigned_receipt,
        "signature": keys["executor"].sign("executor-receipt-v1", unsigned_receipt),
    }


def compact_execute_c(
    permit: dict[str, Any],
    attestations: dict[str, Any],
    command: dict[str, Any],
    state: Any,
    seq: int,
    keys: dict[str, Any],
    reservations: ReservationStore,
    containment: Any,
    connector: SimulatedConnector,
) -> dict[str, Any]:
    """C: compact hot path with independently signed off-path commitments."""
    _verify_common_compact(permit, command, state, seq, keys, containment)

    verify_attestation(attestations["proposal"], keys["proposal"].public, "proposal-commitment-v1")
    verify_attestation(attestations["evidence"], keys["evidence"].public, "evidence-commitment-v1")
    verify_attestation(attestations["decision"], keys["decision"].public, "decision-commitment-v1")

    proposal_subject = attestations["proposal"]["subject"]
    evidence_subject = attestations["evidence"]["subject"]
    decision_subject = attestations["decision"]["subject"]
    for field_name in ("proposal_digest", "action_digest", "destination_digest", "parameter_digest"):
        if proposal_subject.get(field_name) != permit.get(field_name):
            raise PermitError(f"proposal commitment mismatch: {field_name}")
    if evidence_subject.get("evidence_root") != permit.get("evidence_root"):
        raise PermitError("evidence commitment mismatch")
    if decision_subject.get("verdict") != "ALLOW":
        raise PermitError("decision commitment is not ALLOW")
    for field_name in (
        "decision_digest", "proposal_digest", "policy_digest", "signed_policy_digest",
        "evidence_root", "approval_digest", "campaign_state_digest",
    ):
        if decision_subject.get(field_name) != permit.get(field_name):
            raise PermitError(f"decision commitment mismatch: {field_name}")

    reservation = reservations.reserve(str(permit["permit_id"]), str(permit["action_digest"]), seq)
    if reservation is None:
        raise PermitError("permit replay or concurrent duplicate")
    if containment.is_frozen() or containment.is_revoked(str(permit["permit_id"])):
        raise PermitError("execution contained")
    provider = connector.invoke(command["action"], str(permit["permit_id"]))
    unsigned_receipt = {
        "schema_version": "claimsieve.executor_receipt.v1",
        "campaign_id": command["campaign_id"],
        "permit_id": permit["permit_id"],
        "reservation_id": reservation["reservation_id"],
        "action_digest": digest(command),
        "provider_status": provider["status"],
        "provider_id": provider["provider_id"],
        "attempted_at_seq": seq,
        "executor_key_id": keys["executor"].key_id,
    }
    return {
        **unsigned_receipt,
        "signature": keys["executor"].sign("executor-receipt-v1", unsigned_receipt),
    }


def benchmark_hot_path(fx: dict[str, Any]) -> dict[str, Any]:
    keys = fx["keys"]
    prop = fx["proposal"]
    command = command_from_proposal(prop)
    assert digest(command) == action_digest(prop)
    base_permit = fx["permit"]
    attestations = make_attestations(base_permit, keys)

    # Sign unique permit identities outside the timed region so signature creation
    # by the issuer is not accidentally charged to execution latency.
    permits = [
        resign_permit(base_permit, keys["authority"], serial)
        for serial in range(HOT_N + WARMUP_N)
    ]

    results: dict[str, Any] = {}

    for architecture in ("A", "B", "C"):
        _, containment_controller, reservations, connector = make_boundary_components(keys)
        containment = containment_controller.view()
        if architecture == "B":
            executor = Executor(
                {keys["authority"].key_id: keys["authority"].public},
                keys["executor"],
                reservations,
                containment,
                connector,
            )

        def invoke(permit: dict[str, Any]) -> Any:
            if architecture == "A":
                return compact_execute_a(
                    permit, command, fx["state"], 11, keys, reservations, containment, connector
                )
            if architecture == "B":
                return executor.execute(
                    permit,
                    prop,
                    fx["signed_policy"],
                    fx["evidence"],
                    fx["decision"],
                    fx["state"],
                    11,
                )
            return compact_execute_c(
                permit, attestations, command, fx["state"], 11,
                keys, reservations, containment, connector,
            )

        for permit in permits[:WARMUP_N]:
            invoke(permit)

        samples: list[int] = []
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        for permit in permits[WARMUP_N:]:
            start = time.perf_counter_ns()
            invoke(permit)
            samples.append(time.perf_counter_ns() - start)
        cpu_elapsed = time.process_time_ns() - cpu_start
        wall_elapsed = time.perf_counter_ns() - wall_start
        results[architecture] = latency_summary(samples, wall_elapsed, cpu_elapsed)

    payload_b = {
        "permit": base_permit,
        "proposal": prop,
        "signed_policy": fx["signed_policy"],
        "evidence": fx["evidence"],
        "decision": fx["decision"],
        "state": fx["state"].as_canonical(),
    }
    payload_a = {
        "permit": base_permit,
        "command": command,
        "state_digest": digest(fx["state"].as_canonical()),
    }
    payload_c = {
        "permit": base_permit,
        "attestations": attestations,
        "command": command,
        "state_digest": digest(fx["state"].as_canonical()),
    }
    payload_bytes = {
        "A": len(canonical_bytes(payload_a)),
        "B": len(canonical_bytes(payload_b)),
        "C": len(canonical_bytes(payload_c)),
    }
    return {"latency": results, "boundary_payload_bytes": payload_bytes}


def benchmark_issuance() -> dict[str, Any]:
    keys = keypairs()
    ev = evidence(10)
    signed_pol = signed_policy()
    pol = signed_pol["policy"]
    results: dict[str, Any] = {}

    # A and B intentionally share the exact strict issuer. A differs only in what
    # reaches the hot execution path. C adds three independent commitment signs.
    for architecture in ("A", "B", "C"):
        states = CampaignStateStore()
        authority = make_authority(keys, states)
        samples: list[int] = []
        wall_start = time.perf_counter_ns()
        cpu_start = time.process_time_ns()
        for index in range(ISSUE_N):
            campaign_id = f"issue-{architecture}-{index}"
            prop = proposal(
                ev,
                10,
                approve=True,
                campaign_id=campaign_id,
                proposal_id=f"proposal-{campaign_id}",
                trace_id=f"trace-{campaign_id}",
                session_id=f"session-{campaign_id}",
            )
            prior = states.read(campaign_id)
            decision = evaluate(prop, pol, ev, prior, 10)
            start = time.perf_counter_ns()
            permit = authority.issue(
                prop, signed_pol, ev, decision.document, 10, nonce=f"{index + 1:048x}"[-48:]
            )
            if architecture == "C":
                make_attestations(permit, keys)
            samples.append(time.perf_counter_ns() - start)
        cpu_elapsed = time.process_time_ns() - cpu_start
        wall_elapsed = time.perf_counter_ns() - wall_start
        # CPU/wall throughput includes fixture proposal+decision preparation while
        # per-call latency samples isolate the authorization/commit operation.
        summary = latency_summary(samples, wall_elapsed, cpu_elapsed)
        summary["note"] = "per-call latency excludes proposal construction and first-pass kernel evaluation"
        results[architecture] = summary
    return results


def blocked(fn: Callable[[], Any]) -> bool:
    try:
        fn()
        return False
    except (PermitError, ValueError, KeyError, TypeError):
        return True


def baseline_attack_matrix() -> dict[str, dict[str, bool]]:
    matrix: dict[str, dict[str, bool]] = {"A": {}, "B": {}, "C": {}}

    def issue_for_architecture(architecture: str, fixture: dict[str, Any], prop: dict[str, Any], signed_pol: dict[str, Any], ev: list[dict[str, Any]], decision: dict[str, Any], seq: int = 10):
        # The single-receipt A is deliberately given the strongest fair model:
        # the same strict issuer as B/C. This avoids winning by weakening A.
        permit = fixture["authority"].issue(prop, signed_pol, ev, decision, seq, nonce="22" * 24)
        if architecture == "C":
            return permit, make_attestations(permit, fixture["keys"])
        return permit, None

    # Issuance-side trust/control failures: strict issuer should reject all three.
    for architecture in matrix:
        # Invalid evidence signature.
        fx = make_fixture(f"attack-evidence-base-{architecture}")
        # Use a fresh state because make_fixture already consumed its campaign successor.
        keys = fx["keys"]
        ev = copy.deepcopy(fx["evidence"])
        ev[0]["content"]["phone"] = "+15550000000"
        campaign = f"attack-evidence-{architecture}"
        prop = proposal(ev, 10, approve=True, campaign_id=campaign, proposal_id=f"p-{campaign}", trace_id=f"t-{campaign}")
        states = CampaignStateStore()
        authority = make_authority(keys, states)
        prior = states.read(campaign)
        decision = evaluate(prop, fx["policy"], ev, prior, 10).document
        matrix[architecture]["tampered_evidence"] = blocked(
            lambda: authority.issue(prop, fx["signed_policy"], ev, decision, 10, nonce="31" * 24)
        )

        # Stale, but correctly re-signed, human approval.
        ev2 = evidence(10)
        campaign2 = f"attack-stale-{architecture}"
        prop2 = proposal(ev2, 10, approve=True, campaign_id=campaign2, proposal_id=f"p-{campaign2}", trace_id=f"t-{campaign2}")
        prop2["approval"]["expires_at_seq"] = 9
        prop2["approval"]["signature"] = keys["approver"].sign(
            "approval-v1", approval_signing_subject(prop2["approval"])
        )
        states2 = CampaignStateStore()
        authority2 = make_authority(keys, states2)
        prior2 = states2.read(campaign2)
        decision2 = evaluate(prop2, fx["policy"], ev2, prior2, 10).document
        matrix[architecture]["stale_approval"] = blocked(
            lambda: authority2.issue(prop2, fx["signed_policy"], ev2, decision2, 10, nonce="32" * 24)
        )

        # Fabricated ALLOW from a decision the independent kernel did not produce.
        ev3 = evidence(10)
        campaign3 = f"attack-forged-{architecture}"
        prop3 = proposal(
            ev3, 10, approve=True, campaign_id=campaign3,
            proposal_id=f"p-{campaign3}", trace_id=f"t-{campaign3}",
            risk_tags=["PURPOSE_MISMATCH"],
        )
        states3 = CampaignStateStore()
        authority3 = make_authority(keys, states3)
        prior3 = states3.read(campaign3)
        denied = evaluate(prop3, fx["policy"], ev3, prior3, 10).document
        forged = copy.deepcopy(denied)
        forged["verdict"] = "ALLOW"
        matrix[architecture]["fabricated_allow"] = blocked(
            lambda: authority3.issue(prop3, fx["signed_policy"], ev3, forged, 10, nonce="33" * 24)
        )

        # Unsigned policy.
        ev4 = evidence(10)
        campaign4 = f"attack-policy-{architecture}"
        prop4 = proposal(ev4, 10, approve=True, campaign_id=campaign4, proposal_id=f"p-{campaign4}", trace_id=f"t-{campaign4}")
        states4 = CampaignStateStore()
        authority4 = make_authority(keys, states4)
        prior4 = states4.read(campaign4)
        decision4 = evaluate(prop4, fx["policy"], ev4, prior4, 10).document
        matrix[architecture]["unsigned_policy"] = blocked(
            lambda: authority4.issue(prop4, fx["policy"], ev4, decision4, 10, nonce="34" * 24)
        )

        # Two successors from the same predecessor.
        ev5 = evidence(10)
        campaign5 = f"attack-fork-{architecture}"
        states5 = CampaignStateStore()
        authority5 = make_authority(keys, states5)
        prior5 = states5.read(campaign5)
        pa = proposal(ev5, 10, approve=True, campaign_id=campaign5, proposal_id=f"pa-{campaign5}", trace_id=f"ta-{campaign5}")
        pb = proposal(ev5, 10, approve=True, campaign_id=campaign5, proposal_id=f"pb-{campaign5}", trace_id=f"tb-{campaign5}")
        da = evaluate(pa, fx["policy"], ev5, prior5, 10).document
        db = evaluate(pb, fx["policy"], ev5, prior5, 10).document
        authority5.issue(pa, fx["signed_policy"], ev5, da, 10, nonce="35" * 24)
        matrix[architecture]["campaign_fork"] = blocked(
            lambda: authority5.issue(pb, fx["signed_policy"], ev5, db, 10, nonce="36" * 24)
        )

        # Execution-side mutations and replay/expiry.
        fx_exec = make_fixture(f"attack-exec-{architecture}")
        command = command_from_proposal(fx_exec["proposal"])
        attestations = make_attestations(fx_exec["permit"], fx_exec["keys"])

        def run_arch(permit: dict[str, Any], cmd: dict[str, Any], seq: int, reservations: ReservationStore, containment: Any, connector: SimulatedConnector):
            if architecture == "A":
                return compact_execute_a(permit, cmd, fx_exec["state"], seq, fx_exec["keys"], reservations, containment, connector)
            if architecture == "B":
                executor = Executor(
                    {fx_exec["keys"]["authority"].key_id: fx_exec["keys"]["authority"].public},
                    fx_exec["keys"]["executor"], reservations, containment, connector,
                )
                # Reconstruct a full proposal from the original, applying command changes.
                full_prop = copy.deepcopy(fx_exec["proposal"])
                full_prop["objective"] = copy.deepcopy(cmd["objective"])
                full_prop["action"] = copy.deepcopy(cmd["action"])
                return executor.execute(
                    permit, full_prop, fx_exec["signed_policy"], fx_exec["evidence"],
                    fx_exec["decision"], fx_exec["state"], seq,
                )
            return compact_execute_c(
                permit, attestations, cmd, fx_exec["state"], seq, fx_exec["keys"],
                reservations, containment, connector,
            )

        mutated_dest = copy.deepcopy(command)
        mutated_dest["action"]["destination"]["authority"] = "+15559999999"
        _, cont_ctl, res, conn = make_boundary_components(fx_exec["keys"])
        matrix[architecture]["destination_mutation"] = blocked(
            lambda: run_arch(fx_exec["permit"], mutated_dest, 11, res, cont_ctl.view(), conn)
        )

        mutated_param = copy.deepcopy(command)
        mutated_param["action"]["parameters"]["body"] = "MUTATED"
        _, cont_ctl, res, conn = make_boundary_components(fx_exec["keys"])
        matrix[architecture]["parameter_mutation"] = blocked(
            lambda: run_arch(fx_exec["permit"], mutated_param, 11, res, cont_ctl.view(), conn)
        )

        _, cont_ctl, res, conn = make_boundary_components(fx_exec["keys"])
        run_arch(fx_exec["permit"], command, 11, res, cont_ctl.view(), conn)
        matrix[architecture]["replay"] = blocked(
            lambda: run_arch(fx_exec["permit"], command, 11, res, cont_ctl.view(), conn)
        )

        _, cont_ctl, res, conn = make_boundary_components(fx_exec["keys"])
        matrix[architecture]["expired_permit"] = blocked(
            lambda: run_arch(fx_exec["permit"], command, fx_exec["permit"]["expires_at_seq"] + 1, res, cont_ctl.view(), conn)
        )

    return matrix


def trust_fault_probes(fx: dict[str, Any]) -> dict[str, Any]:
    """Probe the architectural difference, not ordinary input validation.

    We explicitly model compromise/bug of the authority signing key. This is not
    a normal attacker capability. A and B have one authority signature at the
    executor. C additionally requires independently keyed commitments.
    """
    keys = fx["keys"]
    command = command_from_proposal(fx["proposal"])
    attestations = make_attestations(fx["permit"], keys)

    tampered_evidence = copy.deepcopy(fx["evidence"])
    tampered_evidence[0]["content"]["phone"] = "+15550000000"  # invalidates original evidence signature
    forged_permit = copy.deepcopy(fx["permit"])
    forged_permit["evidence_root"] = evidence_root(tampered_evidence)
    unsigned = {key: value for key, value in forged_permit.items() if key != "signature"}
    forged_permit["signature"] = keys["authority"].sign("permit-v1", unsigned)

    outcomes: dict[str, Any] = {}

    # A: no independent evidence/decision attestation at the boundary.
    _, cont_ctl, res, conn = make_boundary_components(keys)
    outcomes["A_authority_key_plus_tampered_evidence_accepted"] = not blocked(
        lambda: compact_execute_a(
            forged_permit, command, fx["state"], 11, keys, res, cont_ctl.view(), conn
        )
    )

    # B: if the compromised authority can also supply matching full artifacts,
    # current Executor does not re-verify evidence signatures; it checks hashes.
    _, cont_ctl, res, conn = make_boundary_components(keys)
    executor = Executor(
        {keys["authority"].key_id: keys["authority"].public},
        keys["executor"], res, cont_ctl.view(), conn,
    )
    outcomes["B_authority_key_plus_tampered_evidence_accepted"] = not blocked(
        lambda: executor.execute(
            forged_permit,
            fx["proposal"],
            fx["signed_policy"],
            tampered_evidence,
            fx["decision"],
            fx["state"],
            11,
        )
    )

    # C: honest evidence and decision commitment keys still pin the original root.
    _, cont_ctl, res, conn = make_boundary_components(keys)
    outcomes["C_authority_key_plus_tampered_evidence_accepted"] = not blocked(
        lambda: compact_execute_c(
            forged_permit, attestations, command, fx["state"], 11,
            keys, res, cont_ctl.view(), conn,
        )
    )

    # Hot-path availability: remove full policy/evidence/decision artifacts.
    _, cont_ctl, res, conn = make_boundary_components(keys)
    a_permit = resign_permit(fx["permit"], keys["authority"], 900001)
    outcomes["A_executes_without_full_artifacts"] = not blocked(
        lambda: compact_execute_a(a_permit, command, fx["state"], 11, keys, res, cont_ctl.view(), conn)
    )

    _, cont_ctl, res, conn = make_boundary_components(keys)
    b_permit = resign_permit(fx["permit"], keys["authority"], 900002)
    executor2 = Executor(
        {keys["authority"].key_id: keys["authority"].public},
        keys["executor"], res, cont_ctl.view(), conn,
    )
    outcomes["B_executes_without_full_artifacts"] = not blocked(
        lambda: executor2.execute(
            b_permit, fx["proposal"], {}, [], {}, fx["state"], 11
        )
    )

    _, cont_ctl, res, conn = make_boundary_components(keys)
    c_permit = resign_permit(fx["permit"], keys["authority"], 900003)
    outcomes["C_executes_without_full_artifacts"] = not blocked(
        lambda: compact_execute_c(
            c_permit, attestations, command, fx["state"], 11,
            keys, res, cont_ctl.view(), conn,
        )
    )

    return outcomes


def main() -> None:
    fixture = make_fixture("campaign-abc-benchmark")
    hot = benchmark_hot_path(fixture)
    issuance = benchmark_issuance()
    attacks = baseline_attack_matrix()
    trust_faults = trust_fault_probes(fixture)

    attack_scores = {
        architecture: {
            "blocked": sum(1 for blocked_value in vectors.values() if blocked_value),
            "total": len(vectors),
        }
        for architecture, vectors in attacks.items()
    }

    report = {
        "schema_version": "claimsieve.abc_boundary_benchmark.v1",
        "architectures": {
            "A": "strict ClaimSieve issuer -> one authority-signed envelope + minimal command at execution",
            "B": "current ClaimSieve v0.34 Executor -> permit + proposal + signed policy + evidence + decision + state at execution",
            "C": "strict ClaimSieve issuer -> authority permit + independent proposal/evidence/decision commitment signatures + minimal command",
        },
        "parameters": {
            "hot_samples": HOT_N,
            "warmup_samples": WARMUP_N,
            "issuance_samples": ISSUE_N,
        },
        "hot_path": hot,
        "issuance": issuance,
        "baseline_attack_matrix": attacks,
        "baseline_attack_scores": attack_scores,
        "trust_fault_probes": trust_faults,
        "measurement_limits": {
            "scope": "single-process Python reference microbenchmark using simulated provider; no network/database ledger I/O",
            "energy": "not directly measured; cpu_us_per_op is reported only as a compute-time proxy",
            "carbon": "not measured; runner power source and carbon intensity are unavailable",
            "water": "not measured; datacenter water data are unavailable",
            "production_sla": "GitHub-hosted runner timing is comparative evidence, not a production latency guarantee",
            "A_model": "A is a strong reference model derived from the public discussion, not an implementation supplied by Johnny Watson/Liora AI",
        },
    }

    out_path = Path("evidence/ABC_BOUNDARY_BENCHMARK.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("=== ClaimSieve A/B/C execution-boundary benchmark ===")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"\nWrote {out_path}")


if __name__ == "__main__":
    main()
