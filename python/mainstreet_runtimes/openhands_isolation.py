from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping


OPENHANDS_NAMESPACE = "claimsieve-openhands"
OPENHANDS_APP = "claimsieve-openhands-adversary"
OPENHANDS_SERVICE_ACCOUNT = "claimsieve-openhands-proposer"
CLAIMSIEVE_NAMESPACE = "claimsieve-system"
CLAIMSIEVE_INTAKE_APP = "claimsieve-intake"
CLAIMSIEVE_INTAKE_PORT = 8443
IMAGE_PLACEHOLDER = "REPLACE_WITH_PINNED_OPENHANDS_IMAGE_DIGEST"
_IMAGE_DIGEST_RE = re.compile(r"^.+@sha256:[0-9a-f]{64}$")
_SECRET_NAME_RE = re.compile(
    r"(?:secret|token|password|credential|api[_-]?key|private[_-]?key)",
    re.IGNORECASE,
)


class OpenHandsIsolationError(ValueError):
    """Raised when the isolated OpenHands deployment contract is malformed."""


def _check(name: str, passed: bool, detail: str) -> dict[str, Any]:
    return {"name": name, "status": "PASS" if passed else "FAIL", "detail": detail}


def _mapping(value: Any, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OpenHandsIsolationError(f"{name} must be a mapping")
    return value


def _list(value: Any, name: str) -> list[Any]:
    if not isinstance(value, list):
        raise OpenHandsIsolationError(f"{name} must be a list")
    return value


def load_isolation_contract(root: str | Path) -> dict[str, Any]:
    """Load every JSON document in the isolated OpenHands deployment directory."""

    base = Path(root)
    if not base.is_dir():
        raise OpenHandsIsolationError(f"isolation contract directory not found: {base}")
    documents: dict[str, Any] = {}
    for path in sorted(base.glob("*.json")):
        try:
            documents[path.name] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OpenHandsIsolationError(f"cannot load {path.name}: {exc}") from exc
    required = {
        "namespace.json",
        "service-account.json",
        "offline-adversary-deployment.json",
        "network-policies.json",
    }
    missing = sorted(required - set(documents))
    if missing:
        raise OpenHandsIsolationError(
            "missing required isolation contract files: " + ", ".join(missing)
        )
    return documents


def _network_policy_items(document: Any) -> list[Mapping[str, Any]]:
    root = _mapping(document, "network policy document")
    if root.get("kind") != "List":
        raise OpenHandsIsolationError("network-policies.json must be a Kubernetes List")
    items = _list(root.get("items"), "network policy items")
    result: list[Mapping[str, Any]] = []
    for index, item in enumerate(items):
        mapped = _mapping(item, f"network policy item {index}")
        if mapped.get("kind") != "NetworkPolicy":
            raise OpenHandsIsolationError(
                "network-policies.json may contain only NetworkPolicy resources"
            )
        result.append(mapped)
    return result


def _policy_by_name(items: list[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for item in items:
        metadata = _mapping(item.get("metadata"), "NetworkPolicy metadata")
        name = metadata.get("name")
        if not isinstance(name, str) or not name:
            raise OpenHandsIsolationError("NetworkPolicy name must be non-empty")
        if name in result:
            raise OpenHandsIsolationError(f"duplicate NetworkPolicy name: {name}")
        result[name] = item
    return result


def _container_security_checks(container: Mapping[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    security = _mapping(container.get("securityContext"), "container securityContext")
    checks.append(
        _check(
            "container is not privileged",
            security.get("privileged") is False,
            "privileged must be explicitly false",
        )
    )
    checks.append(
        _check(
            "privilege escalation disabled",
            security.get("allowPrivilegeEscalation") is False,
            "allowPrivilegeEscalation must be false",
        )
    )
    checks.append(
        _check(
            "root filesystem is read only",
            security.get("readOnlyRootFilesystem") is True,
            "readOnlyRootFilesystem must be true",
        )
    )
    checks.append(
        _check(
            "container runs as non-root",
            security.get("runAsNonRoot") is True,
            "runAsNonRoot must be true",
        )
    )
    capabilities = _mapping(security.get("capabilities"), "container capabilities")
    drops = capabilities.get("drop")
    checks.append(
        _check(
            "all Linux capabilities dropped",
            isinstance(drops, list) and drops == ["ALL"],
            "capabilities.drop must be exactly [ALL]",
        )
    )
    seccomp = _mapping(security.get("seccompProfile"), "container seccompProfile")
    checks.append(
        _check(
            "runtime default seccomp enabled",
            seccomp.get("type") == "RuntimeDefault",
            "container seccompProfile.type must be RuntimeDefault",
        )
    )
    return checks


def _credential_checks(container: Mapping[str, Any]) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    checks.append(
        _check(
            "no envFrom credential injection",
            "envFrom" not in container,
            "envFrom is forbidden in the untrusted OpenHands workload",
        )
    )
    env = container.get("env", [])
    env_list = env if isinstance(env, list) else []
    forbidden: list[str] = []
    secret_refs: list[str] = []
    for entry in env_list:
        if not isinstance(entry, Mapping):
            forbidden.append("<malformed-env-entry>")
            continue
        name = entry.get("name")
        if isinstance(name, str) and _SECRET_NAME_RE.search(name):
            forbidden.append(name)
        value_from = entry.get("valueFrom")
        if isinstance(value_from, Mapping) and (
            "secretKeyRef" in value_from or "serviceAccountToken" in value_from
        ):
            secret_refs.append(str(name))
    checks.append(
        _check(
            "no credential-shaped environment variables",
            not forbidden,
            "forbidden environment names: " + ", ".join(forbidden)
            if forbidden
            else "no credential-shaped environment variable names",
        )
    )
    checks.append(
        _check(
            "no secret or service-account-token env references",
            not secret_refs,
            "credential references: " + ", ".join(secret_refs)
            if secret_refs
            else "no secretKeyRef or serviceAccountToken environment sources",
        )
    )
    return checks


def validate_isolation_contract(documents: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the static zero-ambient-executor-credential reference profile.

    Passing this function is evidence about the checked manifests only. It is not
    proof of the behavior of a deployed cluster, container image, CNI plugin, or
    runtime workload.
    """

    checks: list[dict[str, Any]] = []

    namespace = _mapping(documents.get("namespace.json"), "namespace document")
    ns_meta = _mapping(namespace.get("metadata"), "namespace metadata")
    ns_labels = _mapping(ns_meta.get("labels"), "namespace labels")
    checks.append(
        _check(
            "dedicated OpenHands namespace",
            namespace.get("kind") == "Namespace"
            and ns_meta.get("name") == OPENHANDS_NAMESPACE,
            f"namespace must be {OPENHANDS_NAMESPACE}",
        )
    )
    checks.append(
        _check(
            "restricted Pod Security admission",
            ns_labels.get("pod-security.kubernetes.io/enforce") == "restricted"
            and ns_labels.get("pod-security.kubernetes.io/audit") == "restricted"
            and ns_labels.get("pod-security.kubernetes.io/warn") == "restricted",
            "enforce, audit, and warn must all use the restricted profile",
        )
    )

    service_account = _mapping(
        documents.get("service-account.json"), "service account document"
    )
    sa_meta = _mapping(service_account.get("metadata"), "service account metadata")
    checks.append(
        _check(
            "dedicated proposer service account",
            service_account.get("kind") == "ServiceAccount"
            and sa_meta.get("name") == OPENHANDS_SERVICE_ACCOUNT
            and sa_meta.get("namespace") == OPENHANDS_NAMESPACE,
            "service account identity and namespace must be exact",
        )
    )
    checks.append(
        _check(
            "service account token automount disabled",
            service_account.get("automountServiceAccountToken") is False,
            "automountServiceAccountToken must be false on the ServiceAccount",
        )
    )

    deployment = _mapping(
        documents.get("offline-adversary-deployment.json"), "deployment document"
    )
    dep_meta = _mapping(deployment.get("metadata"), "deployment metadata")
    dep_spec = _mapping(deployment.get("spec"), "deployment spec")
    template = _mapping(dep_spec.get("template"), "pod template")
    pod_spec = _mapping(template.get("spec"), "pod spec")
    containers = _list(pod_spec.get("containers"), "pod containers")
    checks.append(
        _check(
            "single untrusted OpenHands container",
            deployment.get("kind") == "Deployment"
            and dep_meta.get("namespace") == OPENHANDS_NAMESPACE
            and len(containers) == 1
            and isinstance(containers[0], Mapping)
            and containers[0].get("name") == "openhands",
            "reference deployment must contain exactly one OpenHands container",
        )
    )
    container = _mapping(containers[0], "OpenHands container") if containers else {}

    checks.append(
        _check(
            "gVisor runtime class required",
            pod_spec.get("runtimeClassName") == "gvisor",
            "runtimeClassName must be gvisor",
        )
    )
    checks.append(
        _check(
            "pod service account token automount disabled",
            pod_spec.get("automountServiceAccountToken") is False,
            "automountServiceAccountToken must be false on the pod",
        )
    )
    checks.append(
        _check(
            "pod uses dedicated proposer service account",
            pod_spec.get("serviceAccountName") == OPENHANDS_SERVICE_ACCOUNT,
            f"serviceAccountName must be {OPENHANDS_SERVICE_ACCOUNT}",
        )
    )
    checks.append(
        _check(
            "service-link environment injection disabled",
            pod_spec.get("enableServiceLinks") is False,
            "enableServiceLinks must be false",
        )
    )
    checks.append(
        _check(
            "host namespaces disabled",
            pod_spec.get("hostNetwork") is False
            and pod_spec.get("hostPID") is False
            and pod_spec.get("hostIPC") is False,
            "hostNetwork, hostPID, and hostIPC must all be false",
        )
    )
    pod_security = _mapping(pod_spec.get("securityContext"), "pod securityContext")
    pod_seccomp = _mapping(pod_security.get("seccompProfile"), "pod seccompProfile")
    checks.append(
        _check(
            "pod-level non-root and seccomp restrictions",
            pod_security.get("runAsNonRoot") is True
            and pod_seccomp.get("type") == "RuntimeDefault",
            "pod securityContext must require non-root and RuntimeDefault seccomp",
        )
    )
    checks.extend(_container_security_checks(container))
    checks.extend(_credential_checks(container))

    volumes = pod_spec.get("volumes", [])
    volume_list = volumes if isinstance(volumes, list) else []
    forbidden_volume_types: list[str] = []
    for volume in volume_list:
        if not isinstance(volume, Mapping):
            forbidden_volume_types.append("malformed")
            continue
        allowed_keys = {"name", "emptyDir"}
        extra = set(volume) - allowed_keys
        if "emptyDir" not in volume or extra:
            forbidden_volume_types.append(
                str(volume.get("name", "unnamed")) + ":" + ",".join(sorted(extra))
            )
    checks.append(
        _check(
            "volumes are ephemeral only",
            bool(volume_list) and not forbidden_volume_types,
            "only emptyDir volumes are allowed"
            if not forbidden_volume_types
            else "forbidden volume definitions: " + ", ".join(forbidden_volume_types),
        )
    )

    image = container.get("image") if isinstance(container, Mapping) else None
    image_is_placeholder = image == IMAGE_PLACEHOLDER
    image_is_pinned = isinstance(image, str) and bool(_IMAGE_DIGEST_RE.fullmatch(image))
    checks.append(
        _check(
            "image reference is immutable or explicitly unbound template",
            image_is_placeholder or image_is_pinned,
            "image must be the documented placeholder or an @sha256 immutable reference",
        )
    )

    policies = _network_policy_items(documents.get("network-policies.json"))
    by_name = _policy_by_name(policies)
    expected_policy_names = {
        "deny-all-openhands",
        "openhands-to-claimsieve-intake-only",
        "claimsieve-intake-from-isolated-openhands",
    }
    checks.append(
        _check(
            "network policy set is exact",
            set(by_name) == expected_policy_names,
            "no additional policy may expand OpenHands ingress or egress in this contract",
        )
    )

    deny = by_name.get("deny-all-openhands", {})
    deny_meta = _mapping(deny.get("metadata", {}), "deny-all metadata")
    deny_spec = _mapping(deny.get("spec", {}), "deny-all spec")
    deny_selector = _mapping(deny_spec.get("podSelector", {}), "deny-all podSelector")
    checks.append(
        _check(
            "OpenHands default deny ingress and egress",
            deny_meta.get("namespace") == OPENHANDS_NAMESPACE
            and deny_selector.get("matchLabels")
            == {"app.kubernetes.io/name": OPENHANDS_APP}
            and set(deny_spec.get("policyTypes", [])) == {"Ingress", "Egress"}
            and deny_spec.get("ingress") == []
            and deny_spec.get("egress") == [],
            "selected OpenHands pods must have explicit empty ingress and egress rules",
        )
    )

    allow = by_name.get("openhands-to-claimsieve-intake-only", {})
    allow_meta = _mapping(allow.get("metadata", {}), "allow-egress metadata")
    allow_spec = _mapping(allow.get("spec", {}), "allow-egress spec")
    expected_egress = [
        {
            "to": [
                {
                    "namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": CLAIMSIEVE_NAMESPACE
                        }
                    },
                    "podSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": CLAIMSIEVE_INTAKE_APP
                        }
                    },
                }
            ],
            "ports": [{"protocol": "TCP", "port": CLAIMSIEVE_INTAKE_PORT}],
        }
    ]
    checks.append(
        _check(
            "OpenHands egress is ClaimSieve intake only",
            allow_meta.get("namespace") == OPENHANDS_NAMESPACE
            and allow_spec.get("podSelector", {}).get("matchLabels")
            == {"app.kubernetes.io/name": OPENHANDS_APP}
            and allow_spec.get("policyTypes") == ["Egress"]
            and allow_spec.get("egress") == expected_egress,
            f"only {CLAIMSIEVE_NAMESPACE}/{CLAIMSIEVE_INTAKE_APP}:8443 TCP may be allowed",
        )
    )

    intake = by_name.get("claimsieve-intake-from-isolated-openhands", {})
    intake_meta = _mapping(intake.get("metadata", {}), "intake-ingress metadata")
    intake_spec = _mapping(intake.get("spec", {}), "intake-ingress spec")
    expected_ingress = [
        {
            "from": [
                {
                    "namespaceSelector": {
                        "matchLabels": {
                            "kubernetes.io/metadata.name": OPENHANDS_NAMESPACE
                        }
                    },
                    "podSelector": {
                        "matchLabels": {"app.kubernetes.io/name": OPENHANDS_APP}
                    },
                }
            ],
            "ports": [{"protocol": "TCP", "port": CLAIMSIEVE_INTAKE_PORT}],
        }
    ]
    checks.append(
        _check(
            "ClaimSieve intake ingress admits isolated OpenHands only on 8443",
            intake_meta.get("namespace") == CLAIMSIEVE_NAMESPACE
            and intake_spec.get("podSelector", {}).get("matchLabels")
            == {"app.kubernetes.io/name": CLAIMSIEVE_INTAKE_APP}
            and intake_spec.get("policyTypes") == ["Ingress"]
            and intake_spec.get("ingress") == expected_ingress,
            "ingress rule must exactly bind OpenHands namespace/app and TCP 8443",
        )
    )

    forbidden_kinds = {"Secret", "RoleBinding", "ClusterRoleBinding"}
    present_forbidden: list[str] = []
    for filename, document in documents.items():
        if not isinstance(document, Mapping):
            continue
        if document.get("kind") in forbidden_kinds:
            present_forbidden.append(f"{filename}:{document.get('kind')}")
        if document.get("kind") == "List":
            for item in document.get("items", []):
                if isinstance(item, Mapping) and item.get("kind") in forbidden_kinds:
                    present_forbidden.append(f"{filename}:{item.get('kind')}")
    checks.append(
        _check(
            "contract contains no Secret or RBAC binding",
            not present_forbidden,
            "forbidden resources: " + ", ".join(present_forbidden)
            if present_forbidden
            else "no Secret, RoleBinding, or ClusterRoleBinding resources",
        )
    )

    security_pass = all(check["status"] == "PASS" for check in checks)
    return {
        "schema_version": "claimsieve.openhands_isolation_contract.v1",
        "status": "PASS" if security_pass else "FAIL",
        "deployment_ready": bool(security_pass and image_is_pinned),
        "image_identity": "PINNED" if image_is_pinned else "UNBOUND_TEMPLATE",
        "checks": checks,
        "limitations": [
            "Static manifest validation does not prove the cluster enforces NetworkPolicy, Pod Security, gVisor, or seccomp as configured.",
            "The reference workload is offline adversarial mode and intentionally has no model-provider or Internet egress.",
            "The image placeholder must be replaced with a verified immutable image digest before deployment_ready can become true.",
            "No claim is made here about the isolation or credential custody of the ClaimSieve intake, restricted executor, or independent observer pods.",
        ],
    }
