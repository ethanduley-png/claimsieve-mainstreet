from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from mainstreet_runtimes.openworker_deployment_policy import (
    OpenWorkerDeploymentPolicyError,
    validate_openworker_production_manifest,
    validate_openworker_production_manifest_file,
)


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "deploy" / "openworker" / "kubernetes.json"


class OpenWorkerDeploymentPolicyTests(unittest.TestCase):
    def manifest(self) -> dict:
        return json.loads(MANIFEST.read_text(encoding="utf-8"))

    @staticmethod
    def deployment(manifest: dict) -> dict:
        return next(item for item in manifest["items"] if item["kind"] == "Deployment")

    @staticmethod
    def allow_policy(manifest: dict) -> dict:
        return next(
            item
            for item in manifest["items"]
            if item["kind"] == "NetworkPolicy"
            and item["metadata"]["name"] == "openworker-allow-governed-egress"
        )

    def test_reference_production_manifest_passes(self) -> None:
        validate_openworker_production_manifest_file(MANIFEST)

    def test_provider_credential_environment_is_rejected(self) -> None:
        manifest = self.manifest()
        container = self.deployment(manifest)["spec"]["template"]["spec"]["containers"][0]
        container["env"].append({"name": "GITHUB_TOKEN", "value": "should-never-be-here"})
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "credential environment"):
            validate_openworker_production_manifest(manifest)

    def test_openai_provider_key_is_rejected_even_if_model_gateway_exists(self) -> None:
        manifest = self.manifest()
        container = self.deployment(manifest)["spec"]["template"]["spec"]["containers"][0]
        container["env"].append({"name": "OPENAI_API_KEY", "value": "bypass-gateway"})
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "credential environment"):
            validate_openworker_production_manifest(manifest)

    def test_privilege_escalation_is_rejected(self) -> None:
        manifest = self.manifest()
        security = self.deployment(manifest)["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        security["allowPrivilegeEscalation"] = True
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "privilege escalation"):
            validate_openworker_production_manifest(manifest)

    def test_writable_root_filesystem_is_rejected(self) -> None:
        manifest = self.manifest()
        security = self.deployment(manifest)["spec"]["template"]["spec"]["containers"][0]["securityContext"]
        security["readOnlyRootFilesystem"] = False
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "read-only"):
            validate_openworker_production_manifest(manifest)

    def test_service_account_token_mount_is_rejected(self) -> None:
        manifest = self.manifest()
        pod = self.deployment(manifest)["spec"]["template"]["spec"]
        pod["automountServiceAccountToken"] = True
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "service-account token"):
            validate_openworker_production_manifest(manifest)

    def test_host_network_is_rejected(self) -> None:
        manifest = self.manifest()
        self.deployment(manifest)["spec"]["template"]["spec"]["hostNetwork"] = True
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "host network"):
            validate_openworker_production_manifest(manifest)

    def test_host_path_mount_is_rejected(self) -> None:
        manifest = self.manifest()
        self.deployment(manifest)["spec"]["template"]["spec"]["volumes"].append(
            {"name": "docker", "hostPath": {"path": "/var/run/docker.sock"}}
        )
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "host paths"):
            validate_openworker_production_manifest(manifest)

    def test_secret_volume_is_rejected(self) -> None:
        manifest = self.manifest()
        self.deployment(manifest)["spec"]["template"]["spec"]["volumes"].append(
            {"name": "github-creds", "secret": {"secretName": "github"}}
        )
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "Secret volumes"):
            validate_openworker_production_manifest(manifest)

    def test_direct_internet_egress_rule_is_rejected(self) -> None:
        manifest = self.manifest()
        policy = self.allow_policy(manifest)
        policy["spec"]["egress"].append(
            {"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "ports": [{"protocol": "TCP", "port": 443}]}
        )
        with self.assertRaises(OpenWorkerDeploymentPolicyError):
            validate_openworker_production_manifest(manifest)

    def test_direct_github_connector_egress_alias_is_rejected(self) -> None:
        manifest = self.manifest()
        policy = self.allow_policy(manifest)
        policy["spec"]["egress"][0]["to"][0]["podSelector"]["matchLabels"]["app"] = "github-connector"
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "unapproved OpenWorker egress"):
            validate_openworker_production_manifest(manifest)

    def test_runtime_commit_drift_is_rejected(self) -> None:
        manifest = self.manifest()
        container = self.deployment(manifest)["spec"]["template"]["spec"]["containers"][0]
        commit = next(entry for entry in container["env"] if entry["name"] == "OPENWORKER_RUNTIME_COMMIT")
        commit["value"] = "0" * 40
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "pinned commit"):
            validate_openworker_production_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
