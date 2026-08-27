from __future__ import annotations

import json
from pathlib import Path
from typing import Any

PINNED_OPENWORKER_COMMIT = "86c57f0692a5a318e55d1b9e0188d798b9fc5690"
_ALLOWED_EGRESS_APPS = frozenset({"claimsieve-intake", "model-gateway"})
_FORBIDDEN_ENV_MARKERS = (
    "AWS_",
    "AZURE_",
    "GCP_",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "STRIPE_",
    "DATABASE_URL",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
)


class OpenWorkerDeploymentPolicyError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise OpenWorkerDeploymentPolicyError(message)


def _items(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    _require(manifest.get("kind") == "List", "OpenWorker deployment manifest must be a Kubernetes List")
    items = manifest.get("items")
    _require(isinstance(items, list), "OpenWorker deployment manifest items must be a list")
    _require(all(isinstance(item, dict) for item in items), "OpenWorker deployment items must be objects")
    return items


def validate_openworker_production_manifest(manifest: dict[str, Any]) -> None:
    """Fail closed if the reference deployment loses its process/credential/network isolation."""

    items = _items(manifest)
    deployments = [item for item in items if item.get("kind") == "Deployment"]
    _require(len(deployments) == 1, "exactly one OpenWorker Deployment is required")
    deployment = deployments[0]
    _require(deployment.get("metadata", {}).get("namespace") == "mainstreet-runtime", "OpenWorker must run in the runtime namespace")

    pod = deployment.get("spec", {}).get("template", {}).get("spec", {})
    _require(isinstance(pod, dict), "OpenWorker pod spec is missing")
    _require(pod.get("automountServiceAccountToken") is False, "OpenWorker service-account token must not be mounted")
    _require(pod.get("hostNetwork") is False, "OpenWorker may not use the host network")
    _require(pod.get("hostPID") is False, "OpenWorker may not use the host PID namespace")
    _require(pod.get("hostIPC") is False, "OpenWorker may not use the host IPC namespace")

    pod_security = pod.get("securityContext", {})
    _require(pod_security.get("runAsNonRoot") is True, "OpenWorker pod must run as non-root")
    _require(pod_security.get("seccompProfile", {}).get("type") == "RuntimeDefault", "OpenWorker pod must use RuntimeDefault seccomp")

    containers = pod.get("containers")
    _require(isinstance(containers, list) and len(containers) == 1, "OpenWorker pod must contain exactly one runtime container")
    container = containers[0]
    security = container.get("securityContext", {})
    _require(security.get("allowPrivilegeEscalation") is False, "OpenWorker privilege escalation must be disabled")
    _require(security.get("readOnlyRootFilesystem") is True, "OpenWorker root filesystem must be read-only")
    _require(security.get("runAsNonRoot") is True, "OpenWorker container must run as non-root")
    _require(security.get("seccompProfile", {}).get("type") == "RuntimeDefault", "OpenWorker container must use RuntimeDefault seccomp")
    dropped = security.get("capabilities", {}).get("drop")
    _require(dropped == ["ALL"], "OpenWorker must drop all Linux capabilities")

    image = container.get("image")
    _require(isinstance(image, str) and "@sha256:" in image, "OpenWorker image must be digest-pinned")
    _require(":" not in image.split("@", 1)[0].rsplit("/", 1)[-1], "OpenWorker image may not rely on a mutable tag")

    env = container.get("env", [])
    _require(isinstance(env, list), "OpenWorker env must be a list")
    env_names = {entry.get("name") for entry in env if isinstance(entry, dict)}
    for name in env_names:
        if not isinstance(name, str):
            continue
        _require(
            not any(name == marker or name.startswith(marker) for marker in _FORBIDDEN_ENV_MARKERS),
            f"provider or infrastructure credential environment is forbidden in OpenWorker: {name}",
        )
    commit_entry = next((entry for entry in env if entry.get("name") == "OPENWORKER_RUNTIME_COMMIT"), None)
    _require(commit_entry is not None and commit_entry.get("value") == PINNED_OPENWORKER_COMMIT, "OpenWorker runtime commit env must match the pinned commit")

    volumes = pod.get("volumes", [])
    _require(isinstance(volumes, list), "OpenWorker volumes must be a list")
    for volume in volumes:
        _require("hostPath" not in volume, "OpenWorker may not mount host paths")
        _require("secret" not in volume, "OpenWorker may not receive Kubernetes Secret volumes")
        _require("projected" not in volume, "OpenWorker may not receive projected credential volumes")

    policies = [item for item in items if item.get("kind") == "NetworkPolicy"]
    deny = [p for p in policies if p.get("metadata", {}).get("name") == "openworker-default-deny"]
    _require(len(deny) == 1, "OpenWorker requires one default-deny NetworkPolicy")
    _require(set(deny[0].get("spec", {}).get("policyTypes", [])) == {"Ingress", "Egress"}, "default-deny policy must cover ingress and egress")
    _require("egress" not in deny[0].get("spec", {}), "default-deny policy may not contain egress exceptions")

    allow = [p for p in policies if p.get("metadata", {}).get("name") == "openworker-allow-governed-egress"]
    _require(len(allow) == 1, "OpenWorker requires one governed-egress NetworkPolicy")
    egress = allow[0].get("spec", {}).get("egress")
    _require(isinstance(egress, list) and egress, "governed-egress policy must enumerate destinations")
    seen_apps: set[str] = set()
    dns_seen = False
    for rule in egress:
        destinations = rule.get("to")
        _require(isinstance(destinations, list) and len(destinations) == 1, "each OpenWorker egress rule must have exactly one destination selector")
        destination = destinations[0]
        namespace = destination.get("namespaceSelector", {}).get("matchLabels", {}).get("kubernetes.io/metadata.name")
        app = destination.get("podSelector", {}).get("matchLabels", {}).get("app")
        dns_app = destination.get("podSelector", {}).get("matchLabels", {}).get("k8s-app")
        if namespace == "kube-system" and dns_app == "kube-dns":
            dns_seen = True
            ports = {(p.get("protocol"), p.get("port")) for p in rule.get("ports", [])}
            _require(ports == {("UDP", 53), ("TCP", 53)}, "DNS egress must be limited to TCP/UDP 53")
            continue
        _require(namespace == "mainstreet-system", "OpenWorker application egress must remain inside mainstreet-system")
        _require(app in _ALLOWED_EGRESS_APPS, f"unapproved OpenWorker egress target: {app}")
        ports = rule.get("ports", [])
        _require(ports == [{"protocol": "TCP", "port": 8443}], "OpenWorker application egress must use TCP 8443")
        seen_apps.add(app)
    _require(seen_apps == _ALLOWED_EGRESS_APPS, "OpenWorker must have only ClaimSieve intake and model-gateway application egress")
    _require(dns_seen, "OpenWorker requires constrained cluster DNS egress")


def validate_openworker_production_manifest_file(path: str | Path) -> None:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OpenWorkerDeploymentPolicyError("OpenWorker deployment manifest is unreadable") from exc
    if not isinstance(payload, dict):
        raise OpenWorkerDeploymentPolicyError("OpenWorker deployment manifest must be an object")
    validate_openworker_production_manifest(payload)
