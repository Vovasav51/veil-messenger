"""Shared fixtures for the Veil relay test-suite.

Everything here uses real HTTP against a real ``ThreadingHTTPServer`` bound to an
ephemeral loopback port, plus a real on-disk SQLite database in a temp dir.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Mapping

SERVER_DIR = Path(__file__).resolve().parent.parent
if str(SERVER_DIR) not in sys.path:  # allow `python3 -m unittest` from anywhere
    sys.path.insert(0, str(SERVER_DIR))

from veil_relay.app import App  # noqa: E402
from veil_relay.config import from_env  # noqa: E402
from veil_relay.db import Database  # noqa: E402
from veil_relay.httpd import RelayHTTPServer  # noqa: E402

LOOPBACK = "127.0.0.1"
KYBER_BYTES = 1568


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def signal_key(label: str, index: int) -> str:
    """A deterministic, well-shaped 33-byte serialized Signal public key."""

    seed = f"{label}:{index}".encode("utf-8")
    return b64(b"\x05" + hashlib.sha256(seed).digest())


def signature(label: str, index: int) -> str:
    seed = f"sig:{label}:{index}".encode("utf-8")
    return b64(hashlib.shake_256(seed).digest(64))


def kyber_key(label: str, index: int) -> str:
    seed = f"kyber:{label}:{index}".encode("utf-8")
    return b64(hashlib.shake_256(seed).digest(KYBER_BYTES))


def make_bundle(
    *,
    label: str = "alice",
    one_time: int = 3,
    start_id: int = 1,
    registration_id: int = 1001,
    signed_id: int = 11,
    kyber_id: int = 21,
) -> dict[str, Any]:
    return {
        "registration_id": registration_id,
        "device_id": 1,
        "identity_key": signal_key(label, 0),
        "signed_prekey": {
            "id": signed_id,
            "public_key": signal_key(label, 1),
            "signature": signature(label, 1),
        },
        "kyber_prekey": {
            "id": kyber_id,
            "public_key": kyber_key(label, 1),
            "signature": signature(label, 2),
        },
        "one_time_prekeys": [
            {"id": start_id + i, "public_key": signal_key(label, 1000 + start_id + i)}
            for i in range(one_time)
        ],
    }


def new_uuid() -> str:
    return str(uuid.uuid4())


def make_handle() -> str:
    return "u_" + uuid.uuid4().hex[:10]


class Relay:
    """A live relay server + database on an ephemeral loopback port."""

    def __init__(self, env: Mapping[str, str] | None = None) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="veil-relay-test-")
        base = {
            "VEIL_HOST": LOOPBACK,
            "VEIL_PORT": "0",
            "VEIL_DB": os.path.join(self.tmpdir, "relay.sqlite3"),
            "VEIL_TTL_SECONDS": "3600",
            "VEIL_PURGE_INTERVAL": "0",
            "VEIL_PURGE_THREAD_INTERVAL": "3600",
            "VEIL_HOME": self.tmpdir,
        }
        base.update(env or {})
        self.env = base
        self.cfg = from_env(base)
        self.db = Database(self.cfg.db_path)
        self.app = App(self.cfg, self.db)
        self.httpd = RelayHTTPServer((LOOPBACK, 0), self.app)
        self.port = int(self.httpd.server_address[1])
        self.app.start()
        self._thread = threading.Thread(
            target=self.httpd.serve_forever,
            kwargs={"poll_interval": 0.02},
            name="veil-test-server",
            daemon=True,
        )
        self._thread.start()

    # -- teardown ------------------------------------------------------------

    def close(self) -> None:
        try:
            self.httpd.shutdown()
            self.httpd.server_close()
        finally:
            self.app.stop()
            shutil.rmtree(self.tmpdir, ignore_errors=True)

    # -- HTTP ----------------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        raw_body: bytes | None = None,
        token: str | None = None,
        headers: Mapping[str, str] | None = None,
        timeout: float = 15.0,
    ) -> tuple[int, Any, dict[str, str]]:
        connection = http.client.HTTPConnection(LOOPBACK, self.port, timeout=timeout)
        try:
            request_headers: dict[str, str] = {}
            data: bytes | None
            if raw_body is not None:
                data = raw_body
                request_headers["Content-Type"] = "application/json"
            elif body is not None:
                data = json.dumps(body).encode("utf-8")
                request_headers["Content-Type"] = "application/json"
            else:
                data = None
            if token is not None:
                request_headers["Authorization"] = "Bearer " + token
            if headers:
                request_headers.update(headers)
            connection.request(method, path, body=data, headers=request_headers)
            response = connection.getresponse()
            raw = response.read()
            parsed = json.loads(raw) if raw else None
            return response.status, parsed, {
                key.lower(): value for key, value in response.getheaders()
            }
        finally:
            connection.close()

    def raw_exchange(self, payload: bytes, *, timeout: float = 10.0) -> bytes:
        """Send raw bytes, half-close, and read everything the server returns."""

        with socket.create_connection((LOOPBACK, self.port), timeout=timeout) as sock:
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        return b"".join(chunks)

    # -- accounts ------------------------------------------------------------

    def register(
        self,
        *,
        handle: str | None = None,
        bundle: Mapping[str, Any] | None = None,
        uid: str | None = None,
        invite_code: str | None = None,
        label: str | None = None,
    ) -> tuple[int, Any, str, dict[str, Any]]:
        account_uid = uid or new_uuid()
        account_handle = make_handle() if handle is None else handle
        account_bundle = dict(bundle or make_bundle(label=label or account_handle))
        body: dict[str, Any] = {
            "uid": account_uid,
            "handle": account_handle,
            "device_id": 1,
            "bundle": account_bundle,
        }
        if invite_code is not None:
            body["invite_code"] = invite_code
        status, payload, _ = self.request("POST", "/v1/register", body)
        return status, payload, account_uid, account_bundle

    def account(
        self,
        *,
        bundle: Mapping[str, Any] | None = None,
        handle: str | None = None,
        invite_code: str | None = None,
    ) -> dict[str, Any]:
        status, payload, uid, account_bundle = self.register(
            handle=handle, bundle=bundle, invite_code=invite_code
        )
        if status != 201:
            raise AssertionError(f"registration failed: {status} {payload}")
        return {
            "uid": payload["uid"],
            "handle": payload["handle"],
            "token": payload["token"],
            "bundle": account_bundle,
            "raw_uid": uid,
        }

    # -- database inspection -------------------------------------------------

    def sql(self, query: str, params: tuple[Any, ...] = ()) -> list[Any]:
        with self.db.connection() as connection:
            return connection.execute(query, params).fetchall()

    def scalar(self, query: str, params: tuple[Any, ...] = ()) -> Any:
        rows = self.sql(query, params)
        return rows[0][0] if rows else None

    def db_bytes(self) -> bytes:
        chunks: list[bytes] = []
        for suffix in ("", "-wal", "-shm"):
            path = self.db.path + suffix
            if os.path.exists(path):
                with open(path, "rb") as handle:
                    chunks.append(handle.read())
        return b"".join(chunks)


def parse_http_response(raw: bytes) -> tuple[int, dict[str, str], bytes]:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or len(lines[0].split()) < 2:
        raise AssertionError(f"not an HTTP response: {raw!r}")
    status = int(lines[0].split()[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers[name.decode("latin-1").strip().lower()] = value.strip().decode("latin-1")
    return status, headers, body


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((LOOPBACK, 0))
        return int(sock.getsockname()[1])


def wait_for_health(port: int, *, timeout: float = 20.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            connection = http.client.HTTPConnection(LOOPBACK, port, timeout=1.0)
            try:
                connection.request("GET", "/health")
                response = connection.getresponse()
                raw = response.read()
                if response.status == 200:
                    return json.loads(raw)
            finally:
                connection.close()
        except OSError as exc:  # not listening yet
            last_error = exc
        time.sleep(0.05)
    raise AssertionError(f"relay did not become healthy: {last_error}")
