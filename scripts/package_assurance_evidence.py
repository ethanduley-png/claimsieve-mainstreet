#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
DEFAULT_OUTPUT = ROOT.parent / f"{ROOT.name}-assurance-evidence.zip"
FIXED_ZIP_TIME = (2026, 8, 1, 4, 0, 0)
EXCLUDED_PARTS = {"__pycache__", ".pytest_cache", "release"}
EXCLUDED_SUFFIXES = {".pyc"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def evidence_files() -> list[Path]:
    result: list[Path] = []
    if not EVIDENCE.is_dir():
        return result
    for path in EVIDENCE.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(EVIDENCE)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.suffix in EXCLUDED_SUFFIXES:
            continue
        result.append(path)
    return sorted(result, key=lambda p: p.relative_to(EVIDENCE).as_posix())


def git_head() -> str | None:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def github_event() -> dict[str, object]:
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if not event_path:
        return {}
    try:
        value = json.loads(Path(event_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def source_identity() -> dict[str, str | None]:
    event = github_event()
    pull_request = event.get("pull_request")
    head_sha = None
    base_sha = None
    if isinstance(pull_request, dict):
        head = pull_request.get("head")
        base = pull_request.get("base")
        if isinstance(head, dict) and isinstance(head.get("sha"), str):
            head_sha = head["sha"]
        if isinstance(base, dict) and isinstance(base.get("sha"), str):
            base_sha = base["sha"]
    return {
        "tested_tree_commit": os.environ.get("GITHUB_SHA") or git_head(),
        "pull_request_head_sha": head_sha,
        "pull_request_base_sha": base_sha,
    }


def archive_entry(name: str, *, executable: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = ((0o755 if executable else 0o644) & 0xFFFF) << 16
    return info


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--payload", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    payload = args.payload.resolve()
    output = args.output.resolve()
    if not payload.is_file():
        raise SystemExit(f"payload not found: {payload}")

    payload_digest = sha256_file(payload)
    selected = evidence_files()
    reference = {
        "schema_version": "claimsieve.assurance-payload-reference.v2",
        "payload": {"name": payload.name, "sha256": payload_digest},
        "source": source_identity(),
        "workflow": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "workflow": os.environ.get("GITHUB_WORKFLOW"),
        },
        "generated_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "signature": {"status": "not_configured"},
    }
    reference_bytes = (json.dumps(reference, indent=2, sort_keys=True) + "\n").encode("utf-8")

    manifest_lines = []
    for path in selected:
        manifest_lines.append(
            f"{sha256_file(path)}  {path.relative_to(EVIDENCE).as_posix()}"
        )
    manifest_lines.append(f"{sha256_bytes(reference_bytes)}  PAYLOAD_REFERENCE.json")
    manifest = ("\n".join(sorted(manifest_lines)) + "\n").encode("utf-8")

    archive_root = f"{ROOT.name}-assurance-evidence"
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in selected:
            relative = path.relative_to(EVIDENCE).as_posix()
            executable = bool(path.stat().st_mode & stat.S_IXUSR)
            archive.writestr(
                archive_entry(f"{archive_root}/{relative}", executable=executable),
                path.read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )
        archive.writestr(
            archive_entry(f"{archive_root}/PAYLOAD_REFERENCE.json"),
            reference_bytes,
            compress_type=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        )
        archive.writestr(
            archive_entry(f"{archive_root}/MANIFEST.sha256"),
            manifest,
            compress_type=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        )

    evidence_digest = sha256_file(output)
    output.with_suffix(output.suffix + ".sha256").write_text(
        f"{evidence_digest}  {output.name}\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "kind": "run-specific-assurance-evidence",
                "profile": "claimsieve.assurance-evidence.v1",
                "zip": str(output),
                "sha256": evidence_digest,
                "payload_sha256": payload_digest,
                "evidence_files": len(selected),
                "signature_status": "not_configured",
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
