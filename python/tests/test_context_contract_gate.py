import importlib.util
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "context_contract_gate.py"
SPEC = importlib.util.spec_from_file_location("context_contract_gate", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load context_contract_gate.py")
GATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GATE)


class ContextContractReferenceTests(unittest.TestCase):
    @staticmethod
    def _text(*references: str) -> str:
        rows = "\n".join(f"- `{reference}`" for reference in references)
        return f"# Contract\n\n## Tests\n{rows}\n\n## Human gate\nReview.\n"

    def test_existing_literal_reference_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "python" / "tests" / "test_ok.py"
            target.parent.mkdir(parents=True)
            target.write_text("# fixture\n", encoding="utf-8")
            failures = GATE.validate_test_references(
                self._text("python/tests/test_ok.py"), "context/test.md", root
            )
            self.assertEqual([], failures)

    def test_missing_literal_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            failures = GATE.validate_test_references(
                self._text("python/tests/test_missing.py"),
                "context/test.md",
                Path(tmp),
            )
            self.assertEqual(
                ["context/test.md: missing test reference python/tests/test_missing.py"],
                failures,
            )

    def test_glob_requires_at_least_one_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            failures = GATE.validate_test_references(
                self._text("mainstreet/test/*.test.js"), "context/test.md", root
            )
            self.assertEqual(
                [
                    "context/test.md: test glob matches no files: "
                    "mainstreet/test/*.test.js"
                ],
                failures,
            )

            target = root / "mainstreet" / "test" / "proposal.test.js"
            target.parent.mkdir(parents=True)
            target.write_text("// fixture\n", encoding="utf-8")
            self.assertEqual(
                [],
                GATE.validate_test_references(
                    self._text("mainstreet/test/*.test.js"), "context/test.md", root
                ),
            )

    def test_parent_traversal_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            failures = GATE.validate_test_references(
                self._text("../outside.test"), "context/test.md", Path(tmp)
            )
            self.assertEqual(
                ["context/test.md: unsafe test reference ../outside.test"], failures
            )

    def test_absolute_reference_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            failures = GATE.validate_test_references(
                self._text("/tmp/outside.test"), "context/test.md", Path(tmp)
            )
            self.assertEqual(
                ["context/test.md: unsafe test reference /tmp/outside.test"], failures
            )

    def test_tests_section_requires_repository_reference(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            failures = GATE.validate_test_references(
                "# Contract\n\n## Tests\n- manual review\n\n## Human gate\nReview.\n",
                "context/test.md",
                Path(tmp),
            )
            self.assertEqual(
                ["context/test.md: ## Tests contains no repository references"], failures
            )


if __name__ == "__main__":
    unittest.main()
