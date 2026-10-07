from __future__ import annotations

import unittest

from mainstreet_runtimes.openworker_no_credentials import (
    NoCredentialSecretStore,
    OpenWorkerCredentialIsolationError,
)


class NoCredentialSecretStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.store = NoCredentialSecretStore()

    def test_reads_expose_no_profiles_or_secret_path(self) -> None:
        self.assertIsNone(self.store.get("github"))
        self.assertEqual(self.store.status(), [])
        self.assertIsNone(self.store.path)

    def test_explicit_resolution_cannot_expand_environment_or_dotenv_references(self) -> None:
        with self.assertRaisesRegex(OpenWorkerCredentialIsolationError, "resolution is disabled"):
            self.store.resolve({"token": "${GITHUB_TOKEN}"})

    def test_persistence_and_deletion_are_disabled(self) -> None:
        with self.assertRaisesRegex(OpenWorkerCredentialIsolationError, "may not persist"):
            self.store.put("github", {"token": "secret"})
        with self.assertRaisesRegex(OpenWorkerCredentialIsolationError, "may not mutate"):
            self.store.delete("github")

    def test_non_string_profile_name_fails_closed(self) -> None:
        with self.assertRaisesRegex(OpenWorkerCredentialIsolationError, "profile name"):
            self.store.get(123)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
