#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath


def validate_member(info: zipfile.ZipInfo) -> None:
    name = info.filename
    path = PurePosixPath(name)
    if not name or name.endswith("/"):
        return
    if path.is_absolute() or ".." in path.parts or "" in path.parts:
        raise ValueError(f"unsafe archive path: {name}")
    mode = (info.external_attr >> 16) & 0xFFFF
    if stat.S_ISLNK(mode):
        raise ValueError(f"symlink entry forbidden: {name}")
    if info.flag_bits & 0x1:
        raise ValueError(f"encrypted entry forbidden: {name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--run-tests", action="store_true")
    args = parser.parse_args()
    archive = args.archive.resolve()
    if not archive.is_file():
        raise SystemExit(f"archive not found: {archive}")

    with zipfile.ZipFile(archive) as zf:
        names = [info.filename for info in zf.infolist()]
        if len(names) != len(set(names)):
            raise SystemExit("duplicate archive entry")
        for info in zf.infolist():
            validate_member(info)
        roots = {PurePosixPath(name).parts[0] for name in names if name and not name.endswith("/")}
        if len(roots) != 1:
            raise SystemExit(f"expected one archive root, found: {sorted(roots)}")
        root_name = next(iter(roots))
        with tempfile.TemporaryDirectory(prefix="claimsieve-release-") as tmp:
            target = Path(tmp)
            zf.extractall(target)
            root = target / root_name
            manifest = root / "MANIFEST.sha256"
            if not manifest.is_file():
                raise SystemExit("MANIFEST.sha256 missing")
            for line in manifest.read_text(encoding="utf-8").splitlines():
                expected, relative = line.split("  ", 1)
                path = root / relative
                if not path.is_file():
                    raise SystemExit(f"manifest file missing: {relative}")
                actual = hashlib.sha256(path.read_bytes()).hexdigest()
                if actual != expected:
                    raise SystemExit(f"manifest mismatch: {relative}")
            if args.run_tests:
                env = dict(os.environ)
                env["VERIFY_MANIFEST"] = "1"
                if os.name == "nt":
                    configured_python = env.get("CLAIMSIEVE_PYTHON")
                    sibling_venv_python = (
                        archive.parent
                        / ".venv-claimsieve-v034"
                        / "Scripts"
                        / "python.exe"
                    )
                    if configured_python and Path(configured_python).is_file():
                        test_python = Path(configured_python)
                    elif sibling_venv_python.is_file():
                        test_python = sibling_venv_python
                    else:
                        test_python = Path(sys.executable)
                    env["CLAIMSIEVE_PYTHON"] = str(test_python)
                    env["CLAIMSIEVE_NODE"] = str(
                        Path.home()
                        / ".cache"
                        / "codex-runtimes"
                        / "codex-primary-runtime"
                        / "dependencies"
                        / "node"
                        / "bin"
                        / "node.exe"
                    )
                    env["CLAIMSIEVE_CARGO"] = str(
                        Path.home() / ".cargo" / "bin" / "cargo.exe"
                    )
                    env["CLAIMSIEVE_ROCQ"] = str(
                        Path.home()
                        / "Rocq-Platform9.0.2025.08"
                        / "bin"
                        / "rocq.exe"
                    )
                    completed = subprocess.run(
                        [
                            "powershell",
                            "-NoProfile",
                            "-ExecutionPolicy",
                            "Bypass",
                            "-File",
                            "scripts/test_all.ps1",
                        ],
                        cwd=root,
                        env=env,
                        capture_output=True,
                        text=True,
                    )
                    if completed.returncode != 0:
                        sys.stdout.write(completed.stdout)
                        sys.stderr.write(completed.stderr)
                        raise SystemExit(
                            f"archive test suite failed with exit code {completed.returncode}"
                        )
                    print("ALL AVAILABLE EXECUTABLE GATES PASSED")
                else:
                    bash = shutil.which("bash")
                    if bash is None:
                        raise SystemExit("bash is required to execute archive tests")
                    completed = subprocess.run(
                        [bash, "scripts/test_all.sh"],
                        cwd=root,
                        env=env,
                        capture_output=True,
                        text=True,
                    )
                    if completed.returncode != 0:
                        sys.stdout.write(completed.stdout)
                        sys.stderr.write(completed.stderr)
                        raise SystemExit(
                            f"archive test suite failed with exit code {completed.returncode}"
                        )
                    print("ALL AVAILABLE EXECUTABLE GATES PASSED")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    print(f"ARCHIVE VALIDATION: PASS")
    print(f"Archive: {archive}")
    print(f"SHA-256: {digest}")
    print(f"Single root: {root_name}")
    print(f"Tests executed: {'YES' if args.run_tests else 'NO'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
