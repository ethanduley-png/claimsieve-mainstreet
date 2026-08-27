from __future__ import annotations

import copy
import unittest
from pathlib import Path

from mainstreet_runtimes.openworker_release import (
    OpenWorkerReleaseError,
    build_openworker_release,
    verify_openworker_release,
)

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "python" / "requirements-openworker.lock.txt"
TEMPLATE = ROOT / "deploy" / "openworker" / "kubernetes.json"
REPO_COMMIT = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64


class OpenWorkerReleaseTests(unittest.TestCase):
    def release(self) -> dict:
        return build_openworker_release(
            repository_commit=REPO_COMMIT,
            image_digest=IMAGE_DIGEST,
            dependency_lock_path=LOCK,
            deployment_template_path=TEMPLATE,
        )

    def test_release_binds_source_dependencies_image_and_deployment(self) -> None:
        record = self.release()
        self.assertEqual(record["repository_commit"], REPO_COMMIT)
        self.assertEqual(record["container_image_digest"], IMAGE_DIGEST)
        self.assertTrue(record["dependency_lock_digest"].startswith("sha256:"))
        self.assertTrue(record["rendered_deployment_digest"].startswith("sha256:"))
        self.assertTrue(record["release_digest"].startswith("sha256:"))
        verify_openworker_release(
            record,
            dependency_lock_path=LOCK,
            deployment_template_path=TEMPLATE,
        )

    def test_placeholder_or_short_image_digest_cannot_form_release(self) -> None:
        for bad in (
            "sha256:REPLACE_WITH_RELEASE_IMAGE_DIGEST",
            "sha256:1234",
            "latest",
        ):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(OpenWorkerReleaseError, "container image digest"):
                    build_openworker_release(
                        repository_commit=REPO_COMMIT,
                        image_digest=bad,
                        dependency_lock_path=LOCK,
                        deployment_template_path=TEMPLATE,
                    )

    def test_release_field_smuggling_is_rejected(self) -> None:
        record = self.release()
        record["approval_override"] = True
        with self.assertRaisesRegex(OpenWorkerReleaseError, "closed schema"):
            verify_openworker_release(record, dependency_lock_path=LOCK, deployment_template_path=TEMPLATE)

    def test_rendered_deployment_tampering_is_rejected(self) -> None:
        record = self.release()
        tampered = copy.deepcopy(record)
        deployment = next(item for item in tampered["rendered_deployment"]["items"] if item["kind"] == "Deployment")
        deployment["spec"]["template"]["spec"]["hostNetwork"] = True
        with self.assertRaisesRegex(OpenWorkerReleaseError, "rendered deployment digest"):
            verify_openworker_release(tampered, dependency_lock_path=LOCK, deployment_template_path=TEMPLATE)

    def test_dependency_lock_change_invalidates_release(self) -> None:
        record = self.release()
        record["dependency_lock_digest"] = "sha256:" + "0" * 64
        with self.assertRaisesRegex(OpenWorkerReleaseError, "dependency lock digest mismatch"):
            verify_openworker_release(record, dependency_lock_path=LOCK, deployment_template_path=TEMPLATE)


if __name__ == "__main__":
    unittest.main()
