from __future__ import annotations

import json
import unittest
from pathlib import Path

from mainstreet_runtimes.openworker_deployment_policy import (
    OpenWorkerDeploymentPolicyError,
    render_openworker_production_manifest,
    validate_openworker_deployment_template_file,
    validate_openworker_production_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "deploy" / "openworker" / "kubernetes.json"
RELEASE_DIGEST = "sha256:" + "1" * 64


class OpenWorkerDeploymentPolicyTests(unittest.TestCase):
    def manifest(self) -> dict:
        return json.loads(MANIFEST.read_text(encoding="utf-8"))

    def production_manifest(self) -> dict:
        return render_openworker_production_manifest(self.manifest(), RELEASE_DIGEST)

    @staticmethod
    def deployment(manifest: dict) -> dict:
        return next(item for item in manifest["items"] if item["kind"] == "Deployment")

    @staticmethod
    def allow_policy(manifest: dict) -> dict:
        return next(item for item in manifest["items"] if item["kind"] == "NetworkPolicy" and item["metadata"]["name"] == "openworker-allow-governed-egress")

    def container(self, manifest: dict) -> dict:
        return self.deployment(manifest)["spec"]["template"]["spec"]["containers"][0]

    def test_checked_in_template_passes_template_validation(self) -> None:
        validate_openworker_deployment_template_file(MANIFEST)

    def test_checked_in_placeholder_is_not_a_production_release(self) -> None:
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "64-hex"):
            validate_openworker_production_manifest(self.manifest())

    def test_release_renderer_requires_exact_image_digest_and_produces_valid_release(self) -> None:
        release = self.production_manifest()
        self.assertEqual(self.container(release)["image"], f"mainstreet/openworker@{RELEASE_DIGEST}")
        validate_openworker_production_manifest(release)
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "exactly 64"):
            render_openworker_production_manifest(self.manifest(), "sha256:1234")

    def test_upstream_or_shell_entrypoint_cannot_replace_restricted_bootstrap(self) -> None:
        for command in (["openworker-server"], ["sh", "-c", "openworker-server"]):
            with self.subTest(command=command):
                manifest = self.production_manifest()
                self.container(manifest)["command"] = command
                with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "MainStreet production bootstrap"):
                    validate_openworker_production_manifest(manifest)

    def test_provider_credential_environment_is_rejected(self) -> None:
        manifest = self.production_manifest()
        self.container(manifest)["env"].append({"name": "GITHUB_TOKEN", "value": "should-never-be-here"})
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "credential environment"):
            validate_openworker_production_manifest(manifest)

    def test_openworker_api_token_cannot_be_in_environment(self) -> None:
        manifest = self.production_manifest()
        self.container(manifest)["env"].append({"name": "COWORKER_API_TOKEN", "value": "secret-in-env"})
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "credential environment"):
            validate_openworker_production_manifest(manifest)

    def test_openai_provider_key_is_rejected_even_if_model_gateway_exists(self) -> None:
        manifest = self.production_manifest()
        self.container(manifest)["env"].append({"name": "OPENAI_API_KEY", "value": "bypass-gateway"})
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "credential environment"):
            validate_openworker_production_manifest(manifest)

    def test_environment_smuggling_is_rejected_even_when_not_named_secret(self) -> None:
        manifest = self.production_manifest()
        self.container(manifest)["env"].append({"name": "ATTACKER_CONTROLLED_MODE", "value": "1"})
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "fixed non-secret allowlist"):
            validate_openworker_production_manifest(manifest)

    def test_privilege_escalation_is_rejected(self) -> None:
        manifest = self.production_manifest()
        self.container(manifest)["securityContext"]["allowPrivilegeEscalation"] = True
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "privilege escalation"):
            validate_openworker_production_manifest(manifest)

    def test_writable_root_filesystem_is_rejected(self) -> None:
        manifest = self.production_manifest()
        self.container(manifest)["securityContext"]["readOnlyRootFilesystem"] = False
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "read-only"):
            validate_openworker_production_manifest(manifest)

    def test_service_account_token_mount_is_rejected(self) -> None:
        manifest = self.production_manifest()
        self.deployment(manifest)["spec"]["template"]["spec"]["automountServiceAccountToken"] = True
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "service-account token"):
            validate_openworker_production_manifest(manifest)

    def test_host_network_is_rejected(self) -> None:
        manifest = self.production_manifest()
        self.deployment(manifest)["spec"]["template"]["spec"]["hostNetwork"] = True
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "host network"):
            validate_openworker_production_manifest(manifest)

    def test_host_path_mount_is_rejected(self) -> None:
        manifest = self.production_manifest()
        self.deployment(manifest)["spec"]["template"]["spec"]["volumes"].append({"name": "docker", "hostPath": {"path": "/var/run/docker.sock"}})
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "host paths"):
            validate_openworker_production_manifest(manifest)

    def test_arbitrary_secret_volume_is_rejected_but_workload_identity_secret_is_allowed(self) -> None:
        manifest = self.production_manifest()
        volumes = self.deployment(manifest)["spec"]["template"]["spec"]["volumes"]
        self.assertTrue(any(v.get("name") == "claimsieve-mtls" for v in volumes))
        volumes.append({"name": "github-creds", "secret": {"secretName": "github"}})
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "only the ClaimSieve workload-identity"):
            validate_openworker_production_manifest(manifest)

    def test_identity_mount_must_be_read_only_and_exact(self) -> None:
        manifest = self.production_manifest()
        mounts = self.container(manifest)["volumeMounts"]
        next(m for m in mounts if m["name"] == "claimsieve-mtls")["readOnly"] = False
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "fixed production set"):
            validate_openworker_production_manifest(manifest)

    def test_identity_secret_permissions_cannot_be_broadened(self) -> None:
        manifest = self.production_manifest()
        volumes = self.deployment(manifest)["spec"]["template"]["spec"]["volumes"]
        next(v for v in volumes if v["name"] == "claimsieve-mtls")["secret"]["defaultMode"] = 420
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "0440"):
            validate_openworker_production_manifest(manifest)

    def test_health_probe_cannot_be_redirected_to_unrelated_endpoint(self) -> None:
        manifest = self.production_manifest()
        self.container(manifest)["readinessProbe"]["httpGet"]["path"] = "/"
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "fixed health endpoint"):
            validate_openworker_production_manifest(manifest)

    def test_direct_internet_egress_rule_is_rejected(self) -> None:
        manifest = self.production_manifest()
        self.allow_policy(manifest)["spec"]["egress"].append({"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "ports": [{"protocol": "TCP", "port": 443}]})
        with self.assertRaises(OpenWorkerDeploymentPolicyError):
            validate_openworker_production_manifest(manifest)

    def test_direct_github_connector_egress_alias_is_rejected(self) -> None:
        manifest = self.production_manifest()
        self.allow_policy(manifest)["spec"]["egress"][0]["to"][0]["podSelector"]["matchLabels"]["app"] = "github-connector"
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "unapproved OpenWorker egress"):
            validate_openworker_production_manifest(manifest)

    def test_runtime_commit_drift_is_rejected(self) -> None:
        manifest = self.production_manifest()
        next(entry for entry in self.container(manifest)["env"] if entry["name"] == "OPENWORKER_RUNTIME_COMMIT")["value"] = "0" * 40
        with self.assertRaisesRegex(OpenWorkerDeploymentPolicyError, "fixed non-secret allowlist"):
            validate_openworker_production_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
