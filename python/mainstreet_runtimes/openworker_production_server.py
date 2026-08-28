from __future__ import annotations

import argparse
import os
from pathlib import Path

from .openworker_bootstrap import (
    install_production_runtime_guard,
    verify_production_turn_engine_guard_installed,
)
from .openworker_context import OpenWorkerProductionContextStore
from .openworker_ipc import (
    CLAIMSIEVE_INTAKE_HOST,
    CLAIMSIEVE_INTAKE_PATH,
    CLAIMSIEVE_INTAKE_PORT,
    OpenWorkerClaimSieveHTTPSClient,
)
from .openworker_model_gateway import MainStreetOpenWorkerModelGatewayProvider
from .openworker_native_bridge import verify_pinned_openworker_runtime
from .openworker_no_credentials import NoCredentialSecretStore

DEFAULT_STATE_DIR = Path("/var/lib/mainstreet/openworker")
DEFAULT_MTLS_DIR = Path("/var/run/mainstreet/mtls")
DEFAULT_HOST = "0.0.0.0"
DEFAULT_PORT = 8080


class OpenWorkerProductionServerError(RuntimeError):
    pass


def _require_file(path: Path, label: str) -> Path:
    if not path.is_file():
        raise OpenWorkerProductionServerError(f"required {label} is missing: {path}")
    return path


def build_production_app(
    *,
    state_dir: str | Path = DEFAULT_STATE_DIR,
    mtls_dir: str | Path = DEFAULT_MTLS_DIR,
    model: str = "mainstreet:default",
    native_tool_map: dict[str, str] | None = None,
    consequential_tools: set[str] | frozenset[str] | None = None,
):
    """Construct the only supported production OpenWorker server composition.

    Invariants established before SessionManager exists:
    - exact pinned upstream runtime verified;
    - OpenWorker's file/env SecretStore constructor replaced with deny-all capability;
    - model access injected through MainStreet's fixed mTLS gateway ProviderClient;
    - primary TurnEngine constructor guarded so consequential tools route to ClaimSieve;
    - per-session ClaimSieve context allocated durably from the runtime state volume.

    This function intentionally does not accept arbitrary provider, credential-store, route,
    or endpoint objects. Production callers cannot substitute those trust-boundary pieces.
    """

    verify_pinned_openworker_runtime()

    root = Path(state_dir)
    identity = Path(mtls_dir)
    ca_file = _require_file(identity / "ca.crt", "mTLS CA")
    cert_file = _require_file(identity / "tls.crt", "mTLS client certificate")
    key_file = _require_file(identity / "tls.key", "mTLS client key")
    root.mkdir(parents=True, exist_ok=True)

    # Import only after verifying the pinned package. SessionManager captures SecretStore
    # from this module global when instantiated, so replace that constructor before creating
    # the manager. Every downstream connector/MCP consumer receives the same deny-all object.
    import coworker.server.manager as manager_module
    from coworker.permissions import Mode
    from coworker.server.app import create_app

    native_secret_store = manager_module.SecretStore
    if native_secret_store is NoCredentialSecretStore:
        raise OpenWorkerProductionServerError(
            "OpenWorker credential constructor was already modified; refusing ambiguous bootstrap"
        )
    manager_module.SecretStore = NoCredentialSecretStore

    try:
        claimsieve_client = OpenWorkerClaimSieveHTTPSClient(
            endpoint=(
                f"https://{CLAIMSIEVE_INTAKE_HOST}:{CLAIMSIEVE_INTAKE_PORT}"
                f"{CLAIMSIEVE_INTAKE_PATH}"
            ),
            ca_file=ca_file,
            client_cert_file=cert_file,
            client_key_file=key_file,
        )
        provider = MainStreetOpenWorkerModelGatewayProvider(
            ca_file=ca_file,
            client_cert_file=cert_file,
            client_key_file=key_file,
        )
        context_store = OpenWorkerProductionContextStore(root / "claimsieve-context.sqlite3")
        install_production_runtime_guard(
            claimsieve_client,
            context_store,
            consequential_tools=consequential_tools,
            native_tool_map=native_tool_map,
        )
        verify_production_turn_engine_guard_installed()

        manager = manager_module.SessionManager(
            workspace=None,
            data_dir=root,
            model=model,
            # Never allow the upstream bypass/auto-approval modes on production boot.
            mode=Mode.INTERACTIVE,
            provider=provider,
        )
        if not isinstance(manager.secrets, NoCredentialSecretStore):
            raise OpenWorkerProductionServerError(
                "OpenWorker production manager acquired credential authority"
            )
        if manager.provider is not provider:
            raise OpenWorkerProductionServerError(
                "OpenWorker production manager did not retain the MainStreet model gateway"
            )
        app = create_app(manager)
        app.state.mainstreet_production_runtime = True
        app.state.mainstreet_no_credentials = True
        return app
    except BaseException:
        # A failed bootstrap must not leave a partially modified process available for reuse.
        manager_module.SecretStore = native_secret_store
        raise


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="mainstreet-openworker")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--state-dir", default=str(DEFAULT_STATE_DIR))
    parser.add_argument("--mtls-dir", default=str(DEFAULT_MTLS_DIR))
    parser.add_argument("--model", default=os.environ.get("MAINSTREET_MODEL", "mainstreet:default"))
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        raise OpenWorkerProductionServerError("server port must be in [1, 65535]")

    # A machine-local OpenWorker token is still required even when Kubernetes NetworkPolicy
    # limits ingress. Fail closed rather than letting upstream's tokenless compatibility path
    # become the production default.
    api_token = os.environ.get("COWORKER_API_TOKEN", "")
    if len(api_token) < 32:
        raise OpenWorkerProductionServerError(
            "COWORKER_API_TOKEN must be configured with at least 32 characters"
        )

    app = build_production_app(
        state_dir=args.state_dir,
        mtls_dir=args.mtls_dir,
        model=args.model,
    )
    import uvicorn

    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        proxy_headers=False,
        server_header=False,
        access_log=False,
    )


if __name__ == "__main__":
    main()
