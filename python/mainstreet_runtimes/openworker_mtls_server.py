from __future__ import annotations

import http.server
import ssl
from pathlib import Path
from typing import Any

from .openworker_ipc import CLAIMSIEVE_INTAKE_PATH, MAX_INTENT_BYTES, OpenWorkerIPCError, OpenWorkerIntakeService


class OpenWorkerMTLSServerError(RuntimeError):
    pass


def spiffe_id_from_peer_certificate(certificate: dict[str, Any]) -> str:
    """Extract exactly one SPIFFE URI SAN from a verified TLS peer certificate."""
    sans = certificate.get("subjectAltName")
    if not isinstance(sans, (list, tuple)):
        raise OpenWorkerMTLSServerError("verified client certificate has no subjectAltName")
    spiffe_ids = [
        value
        for kind, value in sans
        if kind == "URI" and isinstance(value, str) and value.startswith("spiffe://")
    ]
    if len(spiffe_ids) != 1:
        raise OpenWorkerMTLSServerError("client certificate must contain exactly one SPIFFE URI SAN")
    return spiffe_ids[0]


def build_server_ssl_context(
    *,
    ca_file: str | Path,
    server_cert_file: str | Path,
    server_key_file: str | Path,
) -> ssl.SSLContext:
    files = [Path(ca_file), Path(server_cert_file), Path(server_key_file)]
    if any(not path.is_file() for path in files):
        raise OpenWorkerMTLSServerError("ClaimSieve server TLS material is missing")
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile=str(files[0]))
    context.load_cert_chain(certfile=str(files[1]), keyfile=str(files[2]))
    return context


def make_handler(service: OpenWorkerIntakeService) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "ClaimSieveOpenWorkerIntake/1"
        sys_version = ""

        def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
            if self.path != CLAIMSIEVE_INTAKE_PATH:
                self.send_error(404)
                return
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                self.send_error(415)
                return
            raw_length = self.headers.get("Content-Length")
            try:
                length = int(raw_length) if raw_length is not None else -1
            except ValueError:
                length = -1
            if length < 0 or length > MAX_INTENT_BYTES:
                self.send_error(413)
                return
            try:
                certificate = self.connection.getpeercert()
                principal = spiffe_id_from_peer_certificate(certificate)
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise OpenWorkerMTLSServerError("truncated OpenWorker request body")
                response = service.handle(raw, principal)
            except (OpenWorkerIPCError, OpenWorkerMTLSServerError, ValueError):
                self.send_error(403)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(response)

        def do_GET(self) -> None:  # noqa: N802
            self.send_error(405)

        def log_message(self, format: str, *args: Any) -> None:
            # Production logging belongs to the host's structured audit sink; do not emit
            # request bodies, certificate details, or tool parameters through BaseHTTPServer.
            return

    return Handler


def serve_openworker_intake_mtls(
    service: OpenWorkerIntakeService,
    *,
    bind_host: str,
    port: int,
    ca_file: str | Path,
    server_cert_file: str | Path,
    server_key_file: str | Path,
) -> None:
    if bind_host not in {"0.0.0.0", "::"}:
        raise OpenWorkerMTLSServerError("ClaimSieve intake must bind only to the pod network interface")
    if port != 8443:
        raise OpenWorkerMTLSServerError("ClaimSieve intake port must be 8443")
    context = build_server_ssl_context(
        ca_file=ca_file,
        server_cert_file=server_cert_file,
        server_key_file=server_key_file,
    )
    server = http.server.ThreadingHTTPServer((bind_host, port), make_handler(service))
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever(poll_interval=0.5)
