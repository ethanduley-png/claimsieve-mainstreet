from __future__ import annotations

from typing import Any


class OpenWorkerCredentialIsolationError(RuntimeError):
    pass


class NoCredentialSecretStore:
    """Production OpenWorker secret-store capability with no credential authority.

    OpenWorker receives this object instead of its file/env-backed SecretStore. Reads always
    report absence, status is empty, and every mutation/explicit resolution attempt fails.
    Provider credentials belong to the MainStreet model gateway; connector credentials
    belong behind ClaimSieve-controlled execution services.
    """

    path = None

    def get(self, profile: str) -> None:
        if not isinstance(profile, str):
            raise OpenWorkerCredentialIsolationError("credential profile name is invalid")
        return None

    def status(self) -> list[dict[str, Any]]:
        return []

    def resolve(self, value: Any) -> Any:
        # Returning caller data here would allow `${ENV_VAR}` expansion semantics to creep
        # back in through upstream helpers. Production code must not use OpenWorker to
        # resolve credential material at all.
        raise OpenWorkerCredentialIsolationError(
            "OpenWorker credential resolution is disabled in MainStreet production"
        )

    def put(self, profile: str, data: dict[str, Any]) -> None:
        raise OpenWorkerCredentialIsolationError(
            "OpenWorker may not persist credentials in MainStreet production"
        )

    def delete(self, profile: str) -> bool:
        raise OpenWorkerCredentialIsolationError(
            "OpenWorker may not mutate credentials in MainStreet production"
        )
