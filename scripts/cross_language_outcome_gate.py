#!/usr/bin/env python3
"""Mandatory native-vs-Python outcome semantics equivalence gate.

Unlike source-string tests, this runs both classifiers against the exact same
vectors and fails on a single mismatch or on an unavailable native toolchain.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "python"))
from claimsieve_ref.durable_state import classify_provider_evidence  # noqa: E402


def main() -> int:
    path = ROOT / "vectors" / "outcome_semantics_vectors.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    intended = doc["intended_action_digest"]
    expected = []
    for case in doc["vectors"]:
        actual, conflict = classify_provider_evidence(
            case["response_status"], case["observed_action_digest"], intended
        )
        if (actual, conflict) != (case["expected_reconciliation"], case["expected_conflict"]):
            raise AssertionError("Python vector failed: " + case["id"])
        expected.append({
            "id": case["id"],
            "actual_reconciliation": actual,
            "actual_conflict": conflict,
        })
    run = subprocess.run([
        "cargo", "run", "--quiet", "--locked",
        "--manifest-path", str(ROOT / "rust" / "Cargo.toml"),
        "-p", "claimsieve-cli", "--",
        "outcome-vectors", str(path),
    ], cwd=ROOT, capture_output=True, text=True, check=True, timeout=180)
    rust = json.loads(run.stdout)
    if rust != expected:
        raise AssertionError(
            "Cross-language semantic divergence:\nPython " + repr(expected)
            + "\nRust " + repr(rust)
        )
    from jsonschema import Draft202012Validator

    schema_path = ROOT / "schemas" / "observer-receipt-v2.schema.json"
    observer_schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(observer_schema)
    validator = Draft202012Validator(observer_schema)
    observer_path = ROOT / "vectors" / "observer_receipt_wire_v2.json"
    observer_vectors = json.loads(observer_path.read_text(encoding="utf-8"))["vectors"]
    expected_wire = []
    for case in observer_vectors:
        accepted = validator.is_valid(case["receipt"])
        if accepted != case["expected_accept"]:
            raise AssertionError("Python observer wire validation mismatch: " + case["id"])
        expected_wire.append({"id": case["id"], "accepted": accepted})
    native = subprocess.run([
        "cargo", "run", "--quiet", "--locked",
        "--manifest-path", str(ROOT / "rust" / "Cargo.toml"),
        "-p", "claimsieve-cli", "--",
        "observer-vectors", str(observer_path),
    ], cwd=ROOT, capture_output=True, text=True, check=True, timeout=180)
    actual_wire = json.loads(native.stdout)
    if actual_wire != expected_wire:
        raise AssertionError(
            "Observer-v2 wire acceptance diverged:\\nPython " + repr(expected_wire)
            + "\\nRust " + repr(actual_wire)
        )
    print(f"OBSERVER_RECEIPT_V2_WIRE_CONFORMANCE: PASS ({len(expected_wire)} executed vectors)")
    print(f"CROSS_LANGUAGE_OUTCOME_CONFORMANCE: PASS ({len(expected)} executed vectors)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.SubprocessError, ValueError, AssertionError) as exc:
        print("CROSS_LANGUAGE_OUTCOME_CONFORMANCE: FAIL", str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
