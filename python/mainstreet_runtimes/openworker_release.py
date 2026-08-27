from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from claimsieve_ref.canonical import digest
from .openworker_deployment_policy import (
    PINNED_OPENWORKER_COMMIT,
    render_openworker_production_manifest,
)

PINNED_AISUITE_COMMIT = "1b4bbf303ec21968230b1ec869a144d054e9b3c4"
PYTHON_RUNTIME = "3.11.16"
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class OpenWorkerReleaseError(ValueError):
    pass


def _sha256_file(path: Path) -> str:
    if not path.is_file():
        raise OpenWorkerReleaseError(f"release input is missing: {path}")
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise OpenWorkerReleaseError(f"release JSON input is invalid: {path}") from exc
    if not isinstance(payload, dict):
        raise OpenWorkerReleaseError(f"release JSON input must be an object: {path}")
    return payload


def build_openworker_release(
    *,
    repository_commit: str,
    image_digest: str,
    dependency_lock_path: str | Path,
    deployment_template_path: str | Path,
) -> dict[str, Any]:
    """Build a closed provenance record and rendered manifest for a production image.

    This does not sign or publish an image. It ensures the release inputs are exact and
    cryptographically bound before a signer/registry workflow is allowed to proceed.
    """

    if _SHA40.fullmatch(repository_commit) is None:
        raise OpenWorkerReleaseError("repository commit must be exactly 40 lowercase hex characters")
    if _IMAGE_DIGEST.fullmatch(image_digest) is None:
        raise OpenWorkerReleaseError("container image digest must be sha256 plus exactly 64 lowercase hex characters")

    lock_path = Path(dependency_lock_path)
    template_path = Path(deployment_template_path)
    lock_digest = _sha256_file(lock_path)
    template_digest = _sha256_file(template_path)
    template = _load_json(template_path)
    rendered = render_openworker_production_manifest(template, image_digest)
    rendered_digest = digest(rendered)

    record = {
        "schema_version": "mainstreet.openworker_release.v1",
        "repository_commit": repository_commit,
        "openworker_commit": PINNED_OPENWORKER_COMMIT,
        "aisuite_commit": PINNED_AISUITE_COMMIT,
        "python_runtime": PYTHON_RUNTIME,
        "dependency_lock_digest": lock_digest,
        "deployment_template_digest": template_digest,
        "container_image_digest": image_digest,
        "rendered_deployment_digest": rendered_digest,
        "rendered_deployment": rendered,
    }
    record["release_digest"] = digest(record)
    return record


def verify_openworker_release(
    record: dict[str, Any],
    *,
    dependency_lock_path: str | Path,
    deployment_template_path: str | Path,
) -> None:
    required = {
        "schema_version", "repository_commit", "openworker_commit", "aisuite_commit",
        "python_runtime", "dependency_lock_digest", "deployment_template_digest",
        "container_image_digest", "rendered_deployment_digest", "rendered_deployment",
        "release_digest",
    }
    if set(record) != required:
        raise OpenWorkerReleaseError("OpenWorker release fields do not match the closed schema")
    if record["schema_version"] != "mainstreet.openworker_release.v1":
        raise OpenWorkerReleaseError("unsupported OpenWorker release schema")
    if record["openworker_commit"] != PINNED_OPENWORKER_COMMIT:
        raise OpenWorkerReleaseError("OpenWorker release commit drift")
    if record["aisuite_commit"] != PINNED_AISUITE_COMMIT:
        raise OpenWorkerReleaseError("aisuite release commit drift")
    if record["python_runtime"] != PYTHON_RUNTIME:
        raise OpenWorkerReleaseError("Python runtime drift")
    if _SHA40.fullmatch(record["repository_commit"]) is None:
        raise OpenWorkerReleaseError("repository release commit is malformed")
    if _IMAGE_DIGEST.fullmatch(record["container_image_digest"]) is None:
        raise OpenWorkerReleaseError("container image digest is malformed")
    if record["dependency_lock_digest"] != _sha256_file(Path(dependency_lock_path)):
        raise OpenWorkerReleaseError("dependency lock digest mismatch")
    if record["deployment_template_digest"] != _sha256_file(Path(deployment_template_path)):
        raise OpenWorkerReleaseError("deployment template digest mismatch")
    if record["rendered_deployment_digest"] != digest(record["rendered_deployment"]):
        raise OpenWorkerReleaseError("rendered deployment digest mismatch")
    unsigned = dict(record)
    supplied_release_digest = unsigned.pop("release_digest")
    if supplied_release_digest != digest(unsigned):
        raise OpenWorkerReleaseError("OpenWorker release record integrity mismatch")
