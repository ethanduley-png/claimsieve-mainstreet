#!/usr/bin/env python3
"""Run the GitHub attack matrix offline and emit machine-readable evidence."""
from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    suite = unittest.defaultTestLoader.discover(
        "python/tests", pattern="test_github_adversarial_canary.py"
    )
    result = unittest.TextTestRunner(verbosity=2, stream=sys.stderr).run(suite)
    report = {
        "schema_version": "claimsieve.github_adversarial_evaluation.v1",
        "evaluation": "offline_deterministic_fake_github_transport",
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "passing": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        "passed": result.wasSuccessful() and result.testsRun >= 16,
        "live_provider_independence_proven": False,
        "live_github_write_attempts": 0,
    }
    serialized = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized, encoding="utf-8")
    print(serialized, end="")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
