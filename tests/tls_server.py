"""A tiny local HTTPS server for tests. It sends only the leaf certificate, like many KVM web servers."""

from __future__ import annotations

import contextlib
import re
import ssl
import tempfile
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_FIRST_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----\s*", re.DOTALL)


class OkHandler(BaseHTTPRequestHandler):
    """Answers every GET with 200 ``ok``. HTTP/1.0, so each connection carries one request."""

    timeout = 10  # backstop so a stuck client can't hang the server's shutdown

    def do_GET(self) -> None:
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        pass


class _TLSServer(ThreadingHTTPServer):
    daemon_threads = False  # so server_close() joins the handler threads
    block_on_close = True

    def __init__(self, address: tuple[str, int], handler: type[BaseHTTPRequestHandler], context: ssl.SSLContext):
        self._tls_context = context
        super().__init__(address, handler)

    def get_request(self):  # type: ignore[override]
        sock, addr = super().get_request()
        # Handshake lazily in the handler thread, so a client that aborts the handshake
        # (as the pinned-mode tests do) can't block or kill the accept loop.
        return self._tls_context.wrap_socket(sock, server_side=True, do_handshake_on_connect=False), addr

    def handle_error(self, request, client_address) -> None:
        pass  # clients that reject our certificate abort the handshake; that is expected in tests


@contextlib.contextmanager
def serve_https(
    cert_pem: bytes,
    key_pem: bytes,
    *,
    handler: type[BaseHTTPRequestHandler] | None = None,
    port: int = 0,
) -> Iterator[tuple[str, int]]:
    """Serve HTTPS on 127.0.0.1 with the given leaf certificate; yields ``(host, port)``."""
    match = _FIRST_CERT.search(cert_pem)
    if match is None:
        raise ValueError("cert_pem holds no certificate")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as tmp:
        leaf_file = Path(tmp, "leaf.pem")
        key_file = Path(tmp, "key.pem")
        leaf_file.write_bytes(match.group(0))  # only the leaf, never an intermediate
        key_file.write_bytes(key_pem)
        context.load_cert_chain(leaf_file, key_file)

    server = _TLSServer(("127.0.0.1", port), handler or OkHandler, context)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield "127.0.0.1", server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
