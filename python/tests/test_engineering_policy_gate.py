"""Mutation-oriented tests for workflow downgrade detection."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "engineering_policy_gate.py"
SPEC = importlib.util.spec_from_file_location("engineering_policy_gate", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)

SAFE = """name: Test
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo valid
"""


class EngineeringPolicyGateTests(unittest.TestCase):
    def test_read_only_workflow_passes(self) -> None:
        self.assertEqual([], GATE.check_workflow("other.yml", SAFE))

    def test_unsafe_privileged_trigger_fails(self) -> None:
        self.assertIn("untrusted privileged workflow trigger", " ".join(
            GATE.check_workflow("other.yml", SAFE.replace("pull_request:", "pull_request_target:"))
        ))

    def test_missing_permission_map_fails(self) -> None:
        text = SAFE.replace("permissions:\n  contents: read\n", "")
        self.assertIn("missing explicit root permissions", " ".join(GATE.check_workflow("other.yml", text)))

    def test_broad_write_and_nested_write_fail(self) -> None:
        self.assertTrue(GATE.check_workflow("other.yml", SAFE.replace("contents: read", "contents: write")))
        extra = SAFE.replace("    runs-on:", "    permissions:\n      checks: write\n    runs-on:")
        self.assertIn("checks permission cannot be write", " ".join(GATE.check_workflow("other.yml", extra)))
        self.assertTrue(GATE.check_workflow("other.yml", SAFE.replace("permissions:\n  contents: read", "permissions: write-all")))

    def test_security_command_removed_is_rejected(self) -> None:
        commands = "\n".join(GATE.REQUIRED_COMMANDS["reference-tests.yml"])
        self.assertFalse(GATE.check_required_commands("reference-tests.yml", commands))
        broken = commands.replace("python scripts/source_gate.py", "echo skipped")
        self.assertTrue(any("source_gate.py" in item for item in GATE.check_required_commands("reference-tests.yml", broken)))

    def test_protected_lane_cannot_suppress_failure(self) -> None:
        self.assertTrue(GATE.check_workflow("rust.yml", SAFE + "      - run: false\n        continue-on-error: true\n"))

    def test_missing_workflow_detected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / ".github" / "workflows"
            folder.mkdir(parents=True)
            (folder / "other.yml").write_text(SAFE, encoding="utf-8")
            self.assertTrue(any("missing required assurance workflow" in item for item in GATE.validate_repository(Path(tmp))))

    def test_real_repository_conforms(self) -> None:
        self.assertEqual([], GATE.validate_repository(SCRIPT.parents[1]))


if __name__ == "__main__":
    unittest.main()
