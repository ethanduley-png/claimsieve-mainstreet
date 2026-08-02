#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import stat
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT.parent / f"{ROOT.name}.zip"
EXCLUDED_PARTS = {
    "__pycache__",
    ".pytest_cache",
    ".claimsieve-github",
    "node_modules",
    ".git",
    "target",
}
EXCLUDED_NAMES = {OUTPUT.name, "MANIFEST.sha256"}
EXCLUDED_SUFFIXES = {".aux", ".glob", ".vo", ".vok", ".vos"}


def files() -> list[Path]:
    result = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in EXCLUDED_PARTS for part in path.parts):
            continue
        if (
            path.name in EXCLUDED_NAMES
            or path.name == ".lia.cache"
            or path.suffix == ".pyc"
            or path.suffix in EXCLUDED_SUFFIXES
        ):
            continue
        result.append(path)
    return sorted(result, key=lambda p: p.relative_to(ROOT).as_posix())


manifest_lines = []
for path in files():
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_lines.append(f"{digest}  {path.relative_to(ROOT).as_posix()}")
(ROOT / "MANIFEST.sha256").write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")

with zipfile.ZipFile(OUTPUT, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for path in files() + [ROOT / "MANIFEST.sha256"]:
        relative = Path(ROOT.name) / path.relative_to(ROOT)
        info = zipfile.ZipInfo(relative.as_posix(), date_time=(2026, 8, 1, 4, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        mode = path.stat().st_mode
        executable = bool(mode & stat.S_IXUSR)
        info.external_attr = ((0o755 if executable else 0o644) & 0xFFFF) << 16
        archive.writestr(info, path.read_bytes())

zip_digest = hashlib.sha256(OUTPUT.read_bytes()).hexdigest()
sha_path = OUTPUT.with_suffix(OUTPUT.suffix + ".sha256")
sha_path.write_text(f"{zip_digest}  {OUTPUT.name}\n", encoding="utf-8")
print(json.dumps({"zip": str(OUTPUT), "sha256": zip_digest, "files": len(files()) + 1}, indent=2))
