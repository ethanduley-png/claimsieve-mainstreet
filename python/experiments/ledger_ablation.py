from __future__ import annotations

import argparse
import json
import statistics
import time
from typing import Callable

from claimsieve_ref.canonical import canonical_bytes, digest
from claimsieve_ref.fixtures import keypairs
from claimsieve_ref.ledger import Ledger
from claimsieve_ref.unified_audit import UnifiedAuditLog


def _percentile(values: list[int], percentile: float) -> int:
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * percentile))
    return ordered[index]


def _measure(fn: Callable[[], int], iterations: int) -> dict[str, float | int]:
    samples: list[int] = []
    serialized_bytes: list[int] = []
    for _ in range(iterations):
        start = time.perf_counter_ns()
        serialized_bytes.append(fn())
        samples.append(time.perf_counter_ns() - start)
    return {
        "median_ms": statistics.median(samples) / 1_000_000,
        "p95_ms": _percentile(samples, 0.95) / 1_000_000,
        "p99_ms": _percentile(samples, 0.99) / 1_000_000,
        "median_serialized_bytes": int(statistics.median(serialized_bytes)),
    }


def _payload(size_bytes: int) -> dict[str, object]:
    return {
        "schema_version": "claimsieve.ablation.evidence.v1",
        "subject": "lead-123",
        "sequence": 10,
        "verified": True,
        "blob": "x" * size_bytes,
    }


def _minimal_permit_case(size_bytes: int) -> int:
    keys = keypairs()
    evidence = _payload(size_bytes)
    proposal = {
        "trace_id": "trace-ablation",
        "action": "send_message",
        "destination": "sms:+15551234567",
        "parameters": {"body": "hello"},
    }
    subject = {
        "proposal_digest": digest(proposal),
        "evidence_root": digest(evidence),
        "policy_digest": digest({"policy_id": "p1", "version": 1}),
        "valid_from_seq": 10,
        "expires_at_seq": 12,
        "nonce": "n1",
        "max_uses": 1,
    }
    signature = keys["authority"].sign("permit-ablation-v1", subject)
    return len(canonical_bytes({"subject": subject, "signature": signature}))


def _four_ledger_case(size_bytes: int) -> int:
    keys = keypairs()
    evidence = _payload(size_bytes)
    proposal = {"proposal_id": "p1", "destination": "sms:+15551234567"}
    decision = {"decision": "ALLOW", "evidence_root": digest(evidence)}
    execution = {"status": "submitted", "provider_id": "provider-1"}

    proposal_ledger = Ledger("proposal", keys["proposal"])
    evidence_ledger = Ledger("evidence", keys["evidence"])
    decision_ledger = Ledger("decision", keys["decision"])
    execution_ledger = Ledger("execution", keys["execution"])

    proposal_ledger.append("trace-ablation", "PROPOSAL_SUBMITTED", proposal)
    evidence_ledger.append("trace-ablation", "EVIDENCE_RECORDED", evidence)
    decision_ledger.append("trace-ablation", "DECISION_RECORDED", decision)
    execution_ledger.append("trace-ablation", "EXECUTOR_RECEIPT", execution)

    bundle = {
        "proposal": proposal_ledger.records,
        "evidence": evidence_ledger.records,
        "decision": decision_ledger.records,
        "execution": execution_ledger.records,
    }
    return len(canonical_bytes(bundle))


def _unified_commitment_case(size_bytes: int) -> int:
    keys = keypairs()
    evidence = _payload(size_bytes)
    proposal = {"proposal_id": "p1", "destination": "sms:+15551234567"}
    decision = {"decision": "ALLOW", "evidence_root": digest(evidence)}
    execution = {"status": "submitted", "provider_id": "provider-1"}

    log = UnifiedAuditLog()
    log.append(
        trace_id="trace-ablation",
        record_type="PROPOSAL_SUBMITTED",
        writer_role="proposal",
        writer=keys["proposal"],
        payload=proposal,
    )
    log.append(
        trace_id="trace-ablation",
        record_type="EVIDENCE_RECORDED",
        writer_role="evidence",
        writer=keys["evidence"],
        payload_digest=digest(evidence),
    )
    log.append(
        trace_id="trace-ablation",
        record_type="DECISION_RECORDED",
        writer_role="decision",
        writer=keys["decision"],
        payload=decision,
    )
    log.append(
        trace_id="trace-ablation",
        record_type="EXECUTOR_RECEIPT",
        writer_role="execution",
        writer=keys["execution"],
        payload=execution,
    )
    return len(canonical_bytes(log.records))


def run(iterations: int) -> dict[str, object]:
    result: dict[str, object] = {
        "schema_version": "claimsieve.ledger_ablation.v1",
        "iterations": iterations,
        "warning": (
            "Local microbenchmark only. Excludes database, network, provider, "
            "observer, fsync, and production concurrency costs."
        ),
        "cases": {},
    }
    cases = result["cases"]
    assert isinstance(cases, dict)

    for size in (1024, 8192, 65536):
        cases[str(size)] = {
            "minimal_permit": _measure(lambda: _minimal_permit_case(size), iterations),
            "four_ledgers_inline": _measure(lambda: _four_ledger_case(size), iterations),
            "unified_commitment_log": _measure(lambda: _unified_commitment_case(size), iterations),
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--output", type=str, default="")
    args = parser.parse_args()
    if args.iterations < 10:
        raise SystemExit("iterations must be >= 10")

    result = run(args.iterations)
    text = json.dumps(result, indent=2, sort_keys=True)
    print(text)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text + "\n")


if __name__ == "__main__":
    main()
