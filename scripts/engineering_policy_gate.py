#!/usr/bin/env python3
"""Fail closed on changes that bypass the repository's executable assurance lanes.

This is a structural policy check, not a YAML interpreter or a substitute for
execution, branch protection, dependency audits, or security review.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_COMMANDS = {
    "reference-tests.yml": (
        "python -m unittest discover -s python/tests -v",
        "node --test mainstreet/test/*.test.js",
        "python scripts/source_gate.py",
        "python scripts/context_contract_gate.py",
        "python scripts/engineering_policy_gate.py",
        "python scripts/provider_contract_gate.py",
        "python scripts/semantic_divergence_gate.py",
        "python scripts/run_red_team.py",
        "python scripts/run_durable_red_team.py",
    ),
    "rust.yml": (
        "cargo fmt --check",
        "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
        "cargo test --locked --workspace --all-features",
    ),
    "rocq.yml": (
        "rocq compile -Q . ClaimSieve Claimsieve.v",
        "rocq compile -Q . ClaimSieve DurableState.v",
        "Reject admitted or axiomatized proof source",
        "Admitted|admit|Axiom|Parameter",
    ),
    "engineering-policy.yml": (
        "python -m unittest discover -s python/tests -p 'test_engineering_policy_gate.py' -v",
        "python scripts/engineering_policy_gate.py",
    ),
}

PROTECTED_LANES = frozenset(REQUIRED_COMMANDS)
FORBIDDEN_EVENTS = re.compile(r"^\s*(?:pull_request_target|workflow_run)\s*:", re.MULTILINE)
PERMISSIONS_LINE = re.compile(r"^(?P<indent>\s*)permissions:\s*(?P<value>.*?)\s*$")
PERMISSION_ITEM = re.compile(r"^\s+([a-z-]+):\s*([a-z-]+)\s*(?:#.*)?$")


def active_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def check_workflow(path: str, text: str) -> list[str]:
    """Validate conservative properties of YAML files with explicit permission maps."""
    errors: list[str] = []
    lines = active_lines(text)
    source = "\n".join(lines)
    if FORBIDDEN_EVENTS.search(source):
        errors.append(f"{path}: untrusted privileged workflow trigger")

    root_permissions = False
    for index, line in enumerate(lines):
        match = PERMISSIONS_LINE.match(line)
        if not match:
            if re.match(r"^permissions:\s*(?:read-all|write-all|\{.*\})\s*$", line):
                errors.append(f"{path}: broad or opaque workflow permissions")
            continue
        indent = len(match.group("indent"))
        if match.group("value"):
            errors.append(f"{path}: permissions must use an explicit read-only map")
            continue
        items: dict[str, str] = {}
        for next_line in lines[index + 1 :]:
            next_indent = len(next_line) - len(next_line.lstrip())
            if next_indent <= indent:
                break
            permission = PERMISSION_ITEM.match(next_line)
            if permission and next_indent == indent + 2:
                items[permission.group(1)] = permission.group(2)
        for name, access in items.items():
            if access not in {"read", "none"}:
                errors.append(f"{path}: {name} permission cannot be {access}")
        if indent == 0:
            root_permissions = True
            if items.get("contents") != "read":
                errors.append(f"{path}: root permissions must include contents: read")
    if not root_permissions:
        errors.append(f"{path}: missing explicit root permissions")
    if path in PROTECTED_LANES and re.search(r"^\s*continue-on-error:\s*true\b", source, re.MULTILINE):
        errors.append(f"{path}: protected assurance lane cannot ignore failures")
    return errors


def check_required_commands(path: str, text: str) -> list[str]:
    """Guard against accidental removal of critical command invocations.

    Checks for active text only. A malicious workflow can still evade this
    structural check; branch protection and human review remain essential.
    """
    active = "\n".join(active_lines(text))
    return [f"{path}: missing required command: {command}"
            for command in REQUIRED_COMMANDS.get(path, ()) if command not in active]


def validate_repository(root: Path = ROOT) -> list[str]:
    folder = root / ".github" / "workflows"
    problems: list[str] = []
    if not folder.is_dir():
        return ["missing .github/workflows"]
    workflow_paths = sorted([*folder.glob("*.yml"), *folder.glob("*.yaml")])
    if not workflow_paths:
        return ["no GitHub Actions workflow files"]
    for path in workflow_paths:
        content = path.read_text(encoding="utf-8")
        problems.extend(check_workflow(path.name, content))
        problems.extend(check_required_commands(path.name, content))
    for required in REQUIRED_COMMANDS:
        if not (folder / required).is_file():
            problems.append(f"missing required assurance workflow: {required}")
    return problems


def main() -> int:
    problems = validate_repository()
    if problems:
        print("ENGINEERING POLICY GATE: FAIL")
        for problem in problems:
            print(f"- {problem}")
        return 1
    print("ENGINEERING POLICY GATE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
