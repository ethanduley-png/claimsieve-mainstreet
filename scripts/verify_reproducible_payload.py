#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT.parent / f"{ROOT.name}-payload.zip"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def member_digests(path: Path) -> dict[str, str]:
    with zipfile.ZipFile(path) as archive:
        return {
            info.filename: hashlib.sha256(archive.read(info.filename)).hexdigest()
            for info in archive.infolist()
            if not info.is_dir()
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    output = args.output.resolve()

    with tempfile.TemporaryDirectory(prefix="claimsieve-repro-") as tmp:
        tmp_path = Path(tmp)
        first = tmp_path / "payload-a.zip"
        second = tmp_path / "payload-b.zip"
        for candidate in (first, second):
            subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "package_release.py"), "--output", str(candidate)],
                cwd=ROOT,
                check=True,
            )
        first_hash = sha256(first)
        second_hash = sha256(second)
        if first_hash != second_hash:
            first_members = member_digests(first)
            second_members = member_digests(second)
            names = sorted(set(first_members) | set(second_members))
            changed = [
                name
                for name in names
                if first_members.get(name) != second_members.get(name)
            ]
            print("REPRODUCIBLE PAYLOAD: FAIL", file=sys.stderr)
            print(f"first sha256:  {first_hash}", file=sys.stderr)
            print(f"second sha256: {second_hash}", file=sys.stderr)
            for name in changed[:50]:
                print(f"different member: {name}", file=sys.stderr)
            return 1

        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(first, output)
        output_hash = sha256(output)
        output.with_suffix(output.suffix + ".sha256").write_text(
            f"{output_hash}  {output.name}\n", encoding="utf-8"
        )

    print("REPRODUCIBLE PAYLOAD: PASS")
    print(f"SHA-256: {output_hash}")
    print(f"Archive: {output}")
    print("Independent serializations compared: 2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
