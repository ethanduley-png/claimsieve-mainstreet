#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT.parent / f"{ROOT.name}.zip"
EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".claimsieve-github",
    "node_modules",
    ".git",
    "target",
}
EXCLUDED_TOP_LEVEL = {"evidence", "release"}
EXCLUDED_NAMES = {"MANIFEST.sha256"}
EXCLUDED_SUFFIXES = {".aux", ".glob", ".vo", ".vok", ".vos", ".pyc"}
FIXED_ZIP_TIME = (2026, 8, 1, 4, 0, 0)


def files() -> list[Path]:
    result: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if relative.parts and relative.parts[0] in EXCLUDED_TOP_LEVEL:
            continue
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.name in EXCLUDED_NAMES or path.name == ".lia.cache":
            continue
        if path.suffix in EXCLUDED_SUFFIXES:
            continue
        result.append(path)
    return sorted(result, key=lambda p: p.relative_to(ROOT).as_posix())


def manifest_bytes(selected: list[Path]) -> bytes:
    lines = []
    for path in selected:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(ROOT).as_posix()}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def archive_entry(name: str, data: bytes, *, executable: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = ((0o755 if executable else 0o644) & 0xFFFF) << 16
    return info


def build(output: Path) -> tuple[str, int]:
    selected = files()
    manifest = manifest_bytes(selected)
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in selected:
            relative = Path(ROOT.name) / path.relative_to(ROOT)
            executable = bool(path.stat().st_mode & stat.S_IXUSR)
            archive.writestr(
                archive_entry(relative.as_posix(), path.read_bytes(), executable=executable),
                path.read_bytes(),
                compress_type=zipfile.ZIP_DEFLATED,
                compresslevel=9,
            )
        manifest_name = (Path(ROOT.name) / "MANIFEST.sha256").as_posix()
        archive.writestr(
            archive_entry(manifest_name, manifest),
            manifest,
            compress_type=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        )
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(
        f"{digest}  {output.name}\n", encoding="utf-8"
    )
    return digest, len(selected) + 1


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    digest, count = build(args.output)
    print(
        json.dumps(
            {
                "kind": "deterministic-release-payload",
                "profile": "claimsieve.release-payload.v1",
                "zip": str(args.output.resolve()),
                "sha256": digest,
                "files": count,
                "evidence_in_payload": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
