"""HTTP transport: bounded bodies, bounded threads, JSON-only errors.

Deliberately quiet: no access log, no auth log, no request-body log. The only
stderr output is a single sanitized line for an unexpected internal error.
"""

from __future__ import annotations

import json
import os
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping
from urllib.parse import urlsplit

from .errors import ApiError
from .validation import CONTENT_LENGTH_RE

MAX_PATH_LENGTH = 512

_NOT_FOUND_DETAILS = {
    400: "bad request",
    404: "not found",
    405: "method not allowed",
    411: "length required",
    413: "request body too large",
    414: "uri too long",
    431: "request headers too large",
    501: "method not implemented",
    505: "http version not supported",
}


class RelayHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 64

    def __init__(self, address: tuple[str, int], app: Any) -> None:
        self.app = app
        # Bound concurrent handler threads so slow or hostile clients cannot
        # spawn unbounded threads. Extra connections are dropped immediately.
        self._slots = threading.BoundedSemaphore(app.cfg.max_threads)
        super().__init__(address, RelayRequestHandler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.close()
            except OSError:
                pass
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Never dump a traceback (or the client address) to stderr."""

        if (os.environ.get("VEIL_DEBUG") or "").strip() == "1":
            super().handle_error(request, client_address)
        else:
            print("veil-relay: connection handler failed", file=sys.stderr)


class RelayRequestHandler(BaseHTTPRequestHandler):
    server_version = "veil-relay"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 20.0

    # -- lifecycle -----------------------------------------------------------

    def setup(self) -> None:
        self.timeout = float(self.server.app.cfg.request_timeout)  # type: ignore[attr-defined]
        self._head_only = False
        super().setup()

    # -- silence -------------------------------------------------------------

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    def log_error(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    # -- methods -------------------------------------------------------------

    def do_GET(self) -> None:
        self._handle("GET")

    def do_HEAD(self) -> None:
        self._handle("HEAD")

    def do_POST(self) -> None:
        self._handle("POST")

    def do_PUT(self) -> None:
        self._handle("PUT")

    def do_PATCH(self) -> None:
        self._handle("PATCH")

    def do_DELETE(self) -> None:
        self._handle("DELETE")

    def _handle(self, method: str) -> None:
        self._head_only = method == "HEAD"
        self._body_read = method not in ("POST", "PUT", "PATCH")
        client_ip = self.client_address[0] if self.client_address else "unknown"
        try:
            self.server.app.precheck(method, self.path, client_ip)  # type: ignore[attr-defined]
            body: bytes | None = None
            if method in ("POST", "PUT", "PATCH"):
                body = self._read_body()
                self._body_read = True
            else:
                self._discard_body()
            status, payload, headers = self.server.app.dispatch(  # type: ignore[attr-defined]
                method, self.path, self.headers, body, client_ip
            )
            self._send_json(status, payload, headers)
        except ApiError as err:
            if not self._body_read:
                # The unread body would desynchronize a keep-alive connection.
                self.close_connection = True
            try:
                self._send_json(err.status, {"detail": err.detail}, err.headers)
            except OSError:
                self.close_connection = True
        except OSError:
            self.close_connection = True
        except Exception:  # pragma: no cover - defensive
            if (os.environ.get("VEIL_DEBUG") or "").strip() == "1":
                traceback.print_exc()
            else:
                print(
                    "veil-relay: internal error while serving a request", file=sys.stderr
                )
            try:
                self._send_json(500, {"detail": "internal error"})
            except OSError:
                self.close_connection = True

    # -- request body --------------------------------------------------------

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding") is not None:
            self.close_connection = True
            raise ApiError(400, "chunked bodies are not supported")

        values = self.headers.get_all("Content-Length") or []
        if len(values) != 1:
            self.close_connection = True
            raise ApiError(400, "exactly one content-length header is required")

        raw = values[0].strip()
        if not CONTENT_LENGTH_RE.fullmatch(raw):
            self.close_connection = True
            raise ApiError(400, "invalid content-length")

        length = int(raw, 10)
        if length == 0:
            # An empty body is a malformed payload, not a malformed request:
            # let routing/validation decide the status (e.g. 405 vs 400).
            return b""
        if length > self.server.app.cfg.max_body_bytes:  # type: ignore[attr-defined]
            # Do not read the body: refuse, then close so the socket cannot
            # desynchronize.
            self.close_connection = True
            raise ApiError(413, "request body too large")

        data = self.rfile.read(length)
        if data is None or len(data) != length:
            self.close_connection = True
            raise ApiError(400, "incomplete request body")
        return data

    def _discard_body(self) -> None:
        # A GET with a body is unusual; close instead of trying to resynchronize.
        if self.headers.get("Content-Length") is not None:
            self.close_connection = True

    # -- responses -----------------------------------------------------------

    def _send_json(
        self,
        status: int,
        payload: Mapping[str, Any],
        extra_headers: Mapping[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode(
            "utf-8"
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(str(name), str(value))
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self._head_only:
            return
        try:
            self.wfile.write(body)
        except OSError:
            self.close_connection = True

    def send_error(
        self,
        code: int,
        message: str | None = None,
        explain: str | None = None,
    ) -> None:
        """JSON errors even for transport-level failures (no HTML, no tracebacks)."""

        self.close_connection = True
        detail = _NOT_FOUND_DETAILS.get(code, "request failed")
        try:
            self._send_json(code, {"detail": detail})
        except OSError:
            pass


def normalize_path(raw_path: str) -> str:
    """Split off query/fragment, reject oversized or malformed paths."""

    if not isinstance(raw_path, str) or len(raw_path) > MAX_PATH_LENGTH:
        raise ApiError(400, "invalid request path")
    try:
        path = urlsplit(raw_path).path
    except ValueError:
        raise ApiError(400, "invalid request path") from None
    if not path.startswith("/"):
        raise ApiError(400, "invalid request path")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    return path
