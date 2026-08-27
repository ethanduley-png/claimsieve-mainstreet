from __future__ import annotations

import glob
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STAGES = [
    "context/01_propose/CONTEXT.md",
    "context/02_adjudicate/CONTEXT.md",
    "context/03_authorize/CONTEXT.md",
    "context/04_execute/CONTEXT.md",
    "context/05_observe/CONTEXT.md",
    "context/06_audit/CONTEXT.md",
]
REQUIRED = [
    "## Purpose",
    "## Inputs",
    "## Authority",
    "## Invariants",
    "## Outputs",
    "## Evidence produced",
    "## Tests",
    "## Human gate",
]
CODE_REFERENCE = re.compile(r"`([^`]+)`")


def _tests_section(text: str) -> str:
    marker = "## Tests"
    if marker not in text:
        return ""
    section = text.split(marker, 1)[1]
    return section.split("\n## ", 1)[0]


def validate_test_references(text: str, rel: str, root: Path = ROOT) -> list[str]:
    section = _tests_section(text)
    references = CODE_REFERENCE.findall(section)
    failures: list[str] = []

    if not references:
        return [f"{rel}: ## Tests contains no repository references"]

    for reference in references:
        candidate = Path(reference)
        if candidate.is_absolute() or ".." in candidate.parts:
            failures.append(f"{rel}: unsafe test reference {reference}")
            continue

        if glob.has_magic(reference):
            matches = [path for path in root.glob(reference) if path.is_file()]
            if not matches:
                failures.append(f"{rel}: test glob matches no files: {reference}")
            continue

        target = root / candidate
        if not target.is_file():
            failures.append(f"{rel}: missing test reference {reference}")

    return failures


def main() -> int:
    failures: list[str] = []
    router = ROOT / "CONTEXT.md"
    if not router.exists():
        failures.append("missing root CONTEXT.md")
    else:
        router_text = router.read_text(encoding="utf-8")
        for rel in STAGES:
            if rel not in router_text:
                failures.append(f"router does not reference {rel}")

    for rel in STAGES:
        path = ROOT / rel
        if not path.exists():
            failures.append(f"missing {rel}")
            continue
        text = path.read_text(encoding="utf-8")
        for heading in REQUIRED:
            if heading not in text:
                failures.append(f"{rel}: missing {heading}")
        failures.extend(validate_test_references(text, rel))

    if failures:
        print("CONTEXT CONTRACT GATE: FAIL")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("CONTEXT CONTRACT GATE: PASS")
    print(f"validated {len(STAGES)} stage contracts, test references, and root routing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
