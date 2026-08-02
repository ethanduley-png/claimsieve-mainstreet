from __future__ import annotations

import argparse
import json
from pathlib import Path

from claimsieve_ref.verifier import verify_bundle


def main() -> None:
    parser = argparse.ArgumentParser(description="Verify a ClaimSieve bundle against an external trust root")
    parser.add_argument("bundle")
    parser.add_argument("trust_root")
    args = parser.parse_args()
    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    trust_root = json.loads(Path(args.trust_root).read_text(encoding="utf-8"))
    errors = verify_bundle(bundle, trust_root)
    if errors:
        for error in errors:
            print(f"FAIL: {error}")
        raise SystemExit(1)
    print("PASS: bundle verified against external trust root")


if __name__ == "__main__":
    main()
