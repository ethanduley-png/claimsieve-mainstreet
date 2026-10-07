from __future__ import annotations

import copy
import json
import re
from pathlib import Path
from typing import Any

PINNED_OPENWORKER_COMMIT = "86c57f0692a5a318e55d1b9e0188d798b9fc5690"
IMAGE_REPOSITORY = "ghcr.io/ethanduley-png/claimsieve-openworker"
IMAGE_PLACEHOLDER = f"{IMAGE_REPOSITORY}@sha256:REPLACE_WITH_RELEASE_IMAGE_DIGEST"
_IMAGE_RE = re.compile(r"^ghcr\.io/ethanduley-png/claimsieve-openworker@sha256:[0-9a-f]{64}$")
_ALLOWED_EGRESS_APPS = frozenset({"claimsieve-intake", "model-gateway"})
_REQUIRED_COMMAND = ["python", "-m", "mainstreet_runtimes.openworker_production_server"]
_REQUIRED_ARGS = ["--host", "0.0.0.0", "--port", "8080"]
_REQUIRED_SECRET_ITEMS = [
    {"key": "ca.crt", "path": "ca.crt"},
    {"key": "tls.crt", "path": "tls.crt"},
    {"key": "tls.key", "path": "tls.key"},
    {"key": "openworker.token", "path": "openworker.token"},
]
_FORBIDDEN_ENV_MARKERS = (
    "AWS_", "AZURE_", "GCP_", "GOOGLE_APPLICATION_CREDENTIALS",
    "GITHUB_TOKEN", "GH_TOKEN", "STRIPE_", "DATABASE_URL", "COWORKER_API_TOKEN",
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY",
)
_REQUIRED_ENV = {
    "PYTHONPATH": "/opt/mainstreet/python",
    "COWORKER_STATE_DIR": "/var/lib/mainstreet/openworker",
    "MAINSTREET_CLAIMSIEVE_ENDPOINT": "https://claimsieve-intake.mainstreet-system.svc.cluster.local:8443/v1/runtime/openworker/intents",
    "MAINSTREET_MODEL_GATEWAY_ENDPOINT": "https://model-gateway.mainstreet-system.svc.cluster.local:8443/v1/runtime/openworker/completions",
    "MAINSTREET_MTLS_CA_FILE": "/var/run/mainstreet/mtls/ca.crt",
    "MAINSTREET_MTLS_CERT_FILE": "/var/run/mainstreet/mtls/tls.crt",
    "MAINSTREET_MTLS_KEY_FILE": "/var/run/mainstreet/mtls/tls.key",
    "OPENWORKER_RUNTIME_COMMIT": PINNED_OPENWORKER_COMMIT,
}


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


def _validate_probe(container: dict[str, Any], name: str, period: int, failures: int) -> None:
    probe = container.get(name)
    _require(isinstance(probe, dict), f"OpenWorker {name} is required")
    _require(
        probe.get("httpGet") == {"path": "/v1/health", "port": 8080, "scheme": "HTTP"},
        f"OpenWorker {name} must target the fixed health endpoint",
    )
    _require(probe.get("periodSeconds") == period, f"OpenWorker {name} period is fixed")
    _require(probe.get("failureThreshold") == failures, f"OpenWorker {name} failure threshold is fixed")
    _require(probe.get("timeoutSeconds") == 1, f"OpenWorker {name} timeout is fixed")


def _validate(manifest: dict[str, Any], *, allow_image_placeholder: bool) -> None:
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
    _require(pod_security.get("runAsUser") == 65532, "OpenWorker pod user is fixed")
    _require(pod_security.get("runAsGroup") == 65532, "OpenWorker pod group is fixed")
    _require(pod_security.get("fsGroup") == 65532, "OpenWorker fsGroup is fixed")
    _require(pod_security.get("seccompProfile", {}).get("type") == "RuntimeDefault", "OpenWorker pod must use RuntimeDefault seccomp")

    containers = pod.get("containers")
    _require(isinstance(containers, list) and len(containers) == 1, "OpenWorker pod must contain exactly one runtime container")
    container = containers[0]
    _require(container.get("command") == _REQUIRED_COMMAND, "OpenWorker must launch the MainStreet production bootstrap")
    _require(container.get("args") == _REQUIRED_ARGS, "OpenWorker production bootstrap arguments are fixed")
    security = container.get("securityContext", {})
    _require(security.get("allowPrivilegeEscalation") is False, "OpenWorker privilege escalation must be disabled")
    _require(security.get("readOnlyRootFilesystem") is True, "OpenWorker root filesystem must be read-only")
    _require(security.get("runAsNonRoot") is True, "OpenWorker container must run as non-root")
    _require(security.get("seccompProfile", {}).get("type") == "RuntimeDefault", "OpenWorker container must use RuntimeDefault seccomp")
    _require(security.get("capabilities", {}).get("drop") == ["ALL"], "OpenWorker must drop all Linux capabilities")

    image = container.get("image")
    if allow_image_placeholder:
        _require(image == IMAGE_PLACEHOLDER or (isinstance(image, str) and _IMAGE_RE.fullmatch(image) is not None), "OpenWorker template image must be the release placeholder or an exact sha256 image")
    else:
        _require(isinstance(image, str) and _IMAGE_RE.fullmatch(image) is not None, "OpenWorker production release image must contain the exact GHCR repository and a 64-hex sha256 digest")

    env = container.get("env", [])
    _require(isinstance(env, list), "OpenWorker env must be a list")
    env_map = {entry.get("name"): entry.get("value") for entry in env if isinstance(entry, dict)}
    _require(len(env_map) == len(env), "OpenWorker env entries must have unique names")
    for name in env_map:
        if isinstance(name, str):
            _require(not any(name == marker or name.startswith(marker) for marker in _FORBIDDEN_ENV_MARKERS), f"provider or infrastructure credential environment is forbidden in OpenWorker: {name}")
    _require(env_map == _REQUIRED_ENV, "OpenWorker production environment must match the fixed non-secret allowlist")

    mounts = container.get("volumeMounts", [])
    _require(
        mounts == [
            {"name": "runtime-tmp", "mountPath": "/tmp"},
            {"name": "runtime-state", "mountPath": "/var/lib/mainstreet/openworker"},
            {"name": "claimsieve-mtls", "mountPath": "/var/run/mainstreet/mtls", "readOnly": True},
        ],
        "OpenWorker volume mounts must match the fixed production set",
    )
    _validate_probe(container, "startupProbe", 2, 30)
    _validate_probe(container, "readinessProbe", 5, 3)
    _validate_probe(container, "livenessProbe", 10, 3)

    volumes = pod.get("volumes", [])
    _require(isinstance(volumes, list), "OpenWorker volumes must be a list")
    mtls_volumes = []
    for volume in volumes:
        _require("hostPath" not in volume, "OpenWorker may not mount host paths")
        _require("projected" not in volume, "OpenWorker may not receive projected credential volumes")
        if "secret" in volume:
            _require(volume.get("name") == "claimsieve-mtls", "OpenWorker may receive only the ClaimSieve workload-identity Secret")
            secret = volume.get("secret", {})
            _require(secret.get("secretName") == "openworker-claimsieve-mtls", "OpenWorker workload-identity Secret name is fixed")
            _require(secret.get("defaultMode") == 288, "OpenWorker workload identity files must be mode 0440 for the fixed fsGroup")
            _require(secret.get("items") == _REQUIRED_SECRET_ITEMS, "OpenWorker workload-identity Secret may expose only CA, client certificate, client key, and API token")
            mtls_volumes.append(volume)
    _require(len(mtls_volumes) == 1, "OpenWorker requires exactly one workload-identity Secret")

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
        _require(rule.get("ports", []) == [{"protocol": "TCP", "port": 8443}], "OpenWorker application egress must use TCP 8443")
        seen_apps.add(app)
    _require(seen_apps == _ALLOWED_EGRESS_APPS, "OpenWorker must have only ClaimSieve intake and model-gateway application egress")
    _require(dns_seen, "OpenWorker requires constrained cluster DNS egress")


def validate_openworker_deployment_template(manifest: dict[str, Any]) -> None:
    _validate(manifest, allow_image_placeholder=True)


def validate_openworker_production_manifest(manifest: dict[str, Any]) -> None:
    _validate(manifest, allow_image_placeholder=False)


def render_openworker_production_manifest(template: dict[str, Any], image_digest: str) -> dict[str, Any]:
    _require(re.fullmatch(r"sha256:[0-9a-f]{64}", image_digest) is not None, "release image digest must be sha256 followed by exactly 64 lowercase hex characters")
    rendered = copy.deepcopy(template)
    deployment = next(item for item in _items(rendered) if item.get("kind") == "Deployment")
    deployment["spec"]["template"]["spec"]["containers"][0]["image"] = f"{IMAGE_REPOSITORY}@{image_digest}"
    validate_openworker_production_manifest(rendered)
    return rendered


def _load(path: str | Path) -> dict[str, Any]:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OpenWorkerDeploymentPolicyError("OpenWorker deployment manifest is unreadable") from exc
    if not isinstance(payload, dict):
        raise OpenWorkerDeploymentPolicyError("OpenWorker deployment manifest must be an object")
    return payload


def validate_openworker_deployment_template_file(path: str | Path) -> None:
    validate_openworker_deployment_template(_load(path))


def validate_openworker_production_manifest_file(path: str | Path) -> None:
    validate_openworker_production_manifest(_load(path))
