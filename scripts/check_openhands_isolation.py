#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from mainstreet_runtimes.openhands_isolation import (
    OpenHandsIsolationError,
    load_isolation_contract,
    validate_isolation_contract,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate the static isolated OpenHands deployment contract. "
            "This checks manifests only and is not proof of live cluster enforcement."
        )
    )
    parser.add_argument(
        "--root",
        default="deploy/openhands",
        help="directory containing the OpenHands isolation JSON manifests",
    )
    parser.add_argument(
        "--output",
        default="openhands-isolation-contract.json",
        help="JSON evidence report path",
    )
    args = parser.parse_args()

    try:
        documents = load_isolation_contract(args.root)
        report = validate_isolation_contract(documents)
    except OpenHandsIsolationError as exc:
        report = {
            "schema_version": "claimsieve.openhands_isolation_contract.v1",
            "status": "FAIL",
            "deployment_ready": False,
            "image_identity": "UNKNOWN",
            "error": str(exc),
            "checks": [],
            "limitations": [
                "Validation could not complete because the static isolation contract was malformed."
            ],
        }

    Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
