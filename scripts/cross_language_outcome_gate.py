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
    print(f"CROSS_LANGUAGE_OUTCOME_CONFORMANCE: PASS ({len(expected)} executed vectors)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.SubprocessError, ValueError, AssertionError) as exc:
        print("CROSS_LANGUAGE_OUTCOME_CONFORMANCE: FAIL", str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
