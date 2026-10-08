from __future__ import annotations

import copy
import json
import math
import os
import statistics
import time
from pathlib import Path
from typing import Any

from claimsieve_ref.canonical import canonical_bytes, digest
from claimsieve_ref.model import evidence_root
from claimsieve_ref.runtime import Executor, PermitError, ReservationStore

from benchmarks.abc_execution_boundary import (
    command_from_proposal,
    make_boundary_components,
    make_fixture,
    resign_permit,
    compact_execute_a,
)

HOT_N = int(os.environ.get("CLAIMSIEVE_ABC_HOT_N", "1500"))
WARMUP_N = int(os.environ.get("CLAIMSIEVE_ABC_WARMUP_N", "150"))
REPEATS = int(os.environ.get("CLAIMSIEVE_ABC_REPEATS", "5"))


def pct(samples: list[int], q: float) -> float:
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, math.ceil(q * len(ordered)) - 1))
    return ordered[index] / 1_000


def summarize(samples: list[int], wall_ns: int, cpu_ns: int) -> dict[str, float]:
    return {
        "p50_us": round(pct(samples, 0.50), 3),
        "p95_us": round(pct(samples, 0.95), 3),
        "p99_us": round(pct(samples, 0.99), 3),
        "mean_us": round(statistics.fmean(samples) / 1_000, 3),
        "ops_per_second": round(len(samples) / (wall_ns / 1_000_000_000), 1),
        "cpu_us_per_op": round(cpu_ns / len(samples) / 1_000, 3),
    }


def witness_attestation(permit: dict[str, Any], keys: dict[str, Any]) -> dict[str, Any]:
    subject = {
        field: permit[field]
        for field in (
            "proposal_digest",
            "action_digest",
            "destination_digest",
            "parameter_digest",
            "policy_digest",
            "signed_policy_digest",
            "evidence_root",
            "decision_digest",
            "approval_digest",
            "campaign_state_digest",
        )
    }
    subject["verdict"] = "ALLOW"
    return {
        "schema_version": "claimsieve.verification_attestation.v1",
        "subject": subject,
        "witness_key_id": keys["witness"].key_id,
        "signature": keys["witness"].sign("verification-attestation-v1", subject),
    }


def verify_witness(permit: dict[str, Any], attestation: dict[str, Any], keys: dict[str, Any]) -> None:
    if attestation.get("witness_key_id") != keys["witness"].key_id:
        raise PermitError("verification witness key mismatch")
    subject = attestation.get("subject")
    if not isinstance(subject, dict) or not keys["witness"].public.verify(
        "verification-attestation-v1", subject, str(attestation.get("signature", ""))
    ):
        raise PermitError("verification witness signature invalid")
    if subject.get("verdict") != "ALLOW":
        raise PermitError("verification witness did not attest ALLOW")
    for field in (
        "proposal_digest",
        "action_digest",
        "destination_digest",
        "parameter_digest",
        "policy_digest",
        "signed_policy_digest",
        "evidence_root",
        "decision_digest",
        "approval_digest",
        "campaign_state_digest",
    ):
        if subject.get(field) != permit.get(field):
            raise PermitError(f"verification witness commitment mismatch: {field}")


def compact_execute_c(
    permit: dict[str, Any],
    attestation: dict[str, Any],
    command: dict[str, Any],
    state: Any,
    seq: int,
    keys: dict[str, Any],
    reservations: ReservationStore,
    containment: Any,
    connector: Any,
) -> Any:
    # Reuse A's compact authority/capability checks and execution semantics, but
    # independently pin the upstream commitments before the reservation/dispatch.
    # We verify the witness before calling A, so an authority-only forgery fails.
    verify_witness(permit, attestation, keys)
    return compact_execute_a(
        permit, command, state, seq, keys, reservations, containment, connector
    )


def run_once(fx: dict[str, Any], repeat: int) -> dict[str, Any]:
    keys = fx["keys"]
    command = command_from_proposal(fx["proposal"])
    attestation = witness_attestation(fx["permit"], keys)
    permits = [
        resign_permit(fx["permit"], keys["authority"], repeat * 100_000 + index)
        for index in range(HOT_N + WARMUP_N)
    ]
    out: dict[str, Any] = {}

    for architecture in ("A", "B", "C"):
        _, containment_controller, reservations, connector = make_boundary_components(keys)
        containment = containment_controller.view()
        executor = None
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
                assert executor is not None
                return executor.execute(
                    permit,
                    fx["proposal"],
                    fx["signed_policy"],
                    fx["evidence"],
                    fx["decision"],
                    fx["state"],
                    11,
                )
            return compact_execute_c(
                permit, attestation, command, fx["state"], 11,
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
        cpu_ns = time.process_time_ns() - cpu_start
        wall_ns = time.perf_counter_ns() - wall_start
        out[architecture] = summarize(samples, wall_ns, cpu_ns)

    return out


def median_runs(runs: list[dict[str, Any]]) -> dict[str, Any]:
    fields = ("p50_us", "p95_us", "p99_us", "mean_us", "ops_per_second", "cpu_us_per_op")
    return {
        architecture: {
            field: round(statistics.median(run[architecture][field] for run in runs), 3)
            for field in fields
        }
        for architecture in ("A", "B", "C")
    }


def trust_fault_probe(fx: dict[str, Any]) -> dict[str, bool]:
    keys = fx["keys"]
    command = command_from_proposal(fx["proposal"])
    attestation = witness_attestation(fx["permit"], keys)

    tampered_evidence = copy.deepcopy(fx["evidence"])
    tampered_evidence[0]["content"]["phone"] = "+15550000000"
    forged = copy.deepcopy(fx["permit"])
    forged["evidence_root"] = evidence_root(tampered_evidence)
    unsigned = {key: value for key, value in forged.items() if key != "signature"}
    forged["signature"] = keys["authority"].sign("permit-v1", unsigned)

    def accepted(fn) -> bool:
        try:
            fn()
            return True
        except (PermitError, ValueError, KeyError, TypeError):
            return False

    _, ctl, res, conn = make_boundary_components(keys)
    a_accepts = accepted(
        lambda: compact_execute_a(forged, command, fx["state"], 11, keys, res, ctl.view(), conn)
    )

    _, ctl, res, conn = make_boundary_components(keys)
    executor = Executor(
        {keys["authority"].key_id: keys["authority"].public},
        keys["executor"], res, ctl.view(), conn,
    )
    b_accepts = accepted(
        lambda: executor.execute(
            forged, fx["proposal"], fx["signed_policy"], tampered_evidence,
            fx["decision"], fx["state"], 11,
        )
    )

    _, ctl, res, conn = make_boundary_components(keys)
    c_accepts = accepted(
        lambda: compact_execute_c(
            forged, attestation, command, fx["state"], 11,
            keys, res, ctl.view(), conn,
        )
    )

    return {
        "modeled_authority_key_compromise_A_accepts_tampered_evidence_commitment": a_accepts,
        "modeled_authority_key_compromise_B_accepts_matching_tampered_full_artifact": b_accepts,
        "modeled_authority_key_compromise_C_accepts_with_honest_witness": c_accepts,
    }


def payload_sizes(fx: dict[str, Any]) -> dict[str, int]:
    command = command_from_proposal(fx["proposal"])
    attestation = witness_attestation(fx["permit"], fx["keys"])
    return {
        "A": len(canonical_bytes({
            "permit": fx["permit"],
            "command": command,
            "state_digest": digest(fx["state"].as_canonical()),
        })),
        "B": len(canonical_bytes({
            "permit": fx["permit"],
            "proposal": fx["proposal"],
            "signed_policy": fx["signed_policy"],
            "evidence": fx["evidence"],
            "decision": fx["decision"],
            "state": fx["state"].as_canonical(),
        })),
        "C": len(canonical_bytes({
            "permit": fx["permit"],
            "verification_attestation": attestation,
            "command": command,
            "state_digest": digest(fx["state"].as_canonical()),
        })),
    }


def main() -> None:
    fx = make_fixture("campaign-abc-v2")
    runs = [run_once(fx, repeat) for repeat in range(REPEATS)]
    report = {
        "schema_version": "claimsieve.abc_boundary_benchmark.v2",
        "architectures": {
            "A": "strict current ClaimSieve issuer; one authority-signed compact permit at execution; no independent execution-time witness",
            "B": "current ClaimSieve v0.34 Executor with full proposal, signed policy, evidence, decision and state on the hot path",
            "C": "strict issuer; compact permit plus one independently keyed witness attestation over proposal/evidence/policy/decision/state commitments",
        },
        "parameters": {"hot_samples_per_repeat": HOT_N, "warmup": WARMUP_N, "repeats": REPEATS},
        "median_of_repeats": median_runs(runs),
        "all_runs": runs,
        "boundary_payload_bytes": payload_sizes(fx),
        "trust_fault_probe": trust_fault_probe(fx),
        "limits": {
            "scope": "single-process Python reference microbenchmark with simulated provider; no network or database ledger I/O",
            "A_is_reference": "A is a strong reference architecture inferred from the public discussion, not Liora AI code",
            "energy": "not directly measured; CPU time per operation is only a compute-time proxy",
            "carbon": "not measured",
            "water": "not measured",
            "sla": "runner timing is comparative evidence, not a production SLA",
        },
    }
    path = Path("evidence/ABC_BOUNDARY_BENCHMARK_V2.json")
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
