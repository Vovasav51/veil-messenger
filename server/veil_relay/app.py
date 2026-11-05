"""Routing, authentication, quotas and TTL maintenance."""

from __future__ import annotations

import hmac
import re
import threading
import time
from typing import Any, Mapping
from urllib.parse import unquote

from . import SERVER_VERSION, service
from .config import Config, RateLimit
from .db import Database
from .errors import ApiError
from .httpd import normalize_path
from .ratelimit import RateLimiter
from .validation import (
    normalize_handle,
    normalize_uuid,
    parse_json_object,
    validate_ack,
    validate_outgoing_message,
    validate_public_bundle,
    validate_registration,
)

# 32 random bytes, base64url without padding.
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")

DIRECTORY_PREFIX = "/v1/directory/"
PREKEYS_PREFIX = "/v1/prekeys/"


class App:
    """Stateful application core, shared by all request threads."""

    def __init__(self, cfg: Config, db: Database, *, limiter: RateLimiter | None = None):
        self.cfg = cfg
        self.db = db
        self.limiter = limiter or RateLimiter()
        self._purge_lock = threading.Lock()
        self._last_purge = 0.0
        self._stop = threading.Event()
        self._purge_thread: threading.Thread | None = None

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Purge once at startup, then keep purging while the server is idle."""

        self.purge_now()
        self._purge_thread = threading.Thread(
            target=self._purge_loop, name="veil-relay-purge", daemon=True
        )
        self._purge_thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._purge_thread
        if thread is not None:
            thread.join(timeout=3.0)
            self._purge_thread = None

    def _purge_loop(self) -> None:
        # A real timer, independent of traffic: the 30-day TTL must hold even if
        # nobody sends a request.
        while not self._stop.wait(self.cfg.purge_thread_interval):
            try:
                self.purge_now()
            except Exception:  # pragma: no cover - keep the janitor alive
                pass

    def purge_now(self) -> int:
        deleted = service.purge_expired(self.db)
        self._last_purge = time.monotonic()
        return deleted

    def purge_if_due(self) -> None:
        if time.monotonic() - self._last_purge < self.cfg.purge_interval:
            return
        if not self._purge_lock.acquire(blocking=False):
            return
        try:
            if time.monotonic() - self._last_purge >= self.cfg.purge_interval:
                self.purge_now()
        except Exception:  # pragma: no cover - a request must not fail on cleanup
            pass
        finally:
            self._purge_lock.release()

    # -- rate limits ---------------------------------------------------------

    def _limit(self, scope: str, key: str, limit: RateLimit) -> None:
        retry_after = self.limiter.hit(scope, key, limit)
        if retry_after:
            raise ApiError(
                429,
                "rate limit exceeded",
                headers={"Retry-After": str(int(retry_after))},
            )

    # -- request pipeline ----------------------------------------------------

    def precheck(self, method: str, raw_path: str, client_ip: str) -> None:
        """Cheap checks that should happen before a request body is read."""

        self.purge_if_due()
        self._limit("ip", client_ip, self.cfg.rl_global)
        path = normalize_path(raw_path)
        if method == "POST" and path == "/v1/register":
            self._limit("register", client_ip, self.cfg.rl_register)

    def dispatch(
        self,
        method: str,
        raw_path: str,
        headers: Mapping[str, str],
        body: bytes | None,
        client_ip: str,
    ) -> tuple[int, dict[str, Any], dict[str, str]]:
        path = normalize_path(raw_path)

        if path == "/health":
            self._require_method(method, "GET")
            return 200, {"status": "ok", "version": SERVER_VERSION}, {}

        if path == "/v1/register":
            self._require_method(method, "POST")
            payload = parse_json_object(body if body is not None else b"")
            self._check_invite(payload.get("invite_code"))
            data = validate_registration(
                payload, max_otk=self.cfg.max_otk_per_bundle
            )
            result = service.register(
                self.db,
                uid=data["uid"],
                handle=data["handle"],
                device_id=data["device_id"],
                bundle=data["bundle"],
            )
            return 201, result, {}

        if path.startswith(DIRECTORY_PREFIX):
            self._require_method(method, "GET")
            account = self._authenticate(headers)
            self._limit("directory", account["uid"], self.cfg.rl_directory)
            handle = normalize_handle(self._path_segment(path, DIRECTORY_PREFIX))
            return 200, service.directory_entry(self.db, handle), {}

        if path.startswith(PREKEYS_PREFIX):
            self._require_method(method, "GET")
            account = self._authenticate(headers)
            self._limit("prekeys-get", account["uid"], self.cfg.rl_prekeys_get)
            target = normalize_uuid(self._path_segment(path, PREKEYS_PREFIX), field="uid")
            return 200, service.fetch_bundle_and_consume(self.db, target), {}

        if path == "/v1/prekeys":
            self._require_method(method, "PUT")
            account = self._authenticate(headers)
            self._limit("prekeys-put", account["uid"], self.cfg.rl_prekeys_put)
            payload = parse_json_object(body if body is not None else b"")
            bundle = validate_public_bundle(
                payload, max_otk=self.cfg.max_otk_per_bundle
            )
            service.replace_prekeys(self.cfg, self.db, account["uid"], bundle)
            return 200, {"ok": True}, {}

        if path == "/v1/messages/ack":
            self._require_method(method, "POST")
            account = self._authenticate(headers)
            self._limit("messages-ack", account["uid"], self.cfg.rl_messages_ack)
            payload = parse_json_object(body if body is not None else b"")
            ids = validate_ack(payload, max_ids=self.cfg.max_ack_ids)
            service.ack_messages(self.db, account["uid"], ids)
            return 200, {"ok": True}, {}

        if path == "/v1/messages":
            if method == "GET":
                account = self._authenticate(headers)
                self._limit("messages-pull", account["uid"], self.cfg.rl_messages_pull)
                return 200, service.fetch_messages(self.cfg, self.db, account["uid"]), {}
            if method == "POST":
                account = self._authenticate(headers)
                self._limit("messages-send", account["uid"], self.cfg.rl_messages_send)
                payload = parse_json_object(body if body is not None else b"")
                message = validate_outgoing_message(
                    payload, max_ciphertext_bytes=self.cfg.max_ciphertext_bytes
                )
                result = service.send_message(
                    self.cfg, self.db, sender_uid=account["uid"], message=message
                )
                return 202, result, {}
            raise ApiError(405, "method not allowed", headers={"Allow": "GET, POST"})

        raise ApiError(404, "not found")

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _require_method(actual: str, expected: str) -> None:
        if actual != expected:
            raise ApiError(
                405, "method not allowed", headers={"Allow": expected}
            )

    @staticmethod
    def _path_segment(path: str, prefix: str) -> str:
        rest = path[len(prefix) :]
        if not rest or "/" in rest:
            raise ApiError(404, "not found")
        try:
            return unquote(rest, errors="strict")
        except UnicodeDecodeError:
            raise ApiError(400, "invalid request path") from None

    def _authenticate(self, headers: Mapping[str, str]) -> dict[str, Any]:
        raw = headers.get("Authorization")
        if raw is None:
            raise ApiError(401, "missing bearer token")
        parts = raw.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise ApiError(401, "invalid authorization header")
        token = parts[1]
        if not TOKEN_RE.fullmatch(token):
            raise ApiError(401, "invalid bearer token")
        return service.authenticate(self.db, token)

    def _check_invite(self, supplied: Any) -> None:
        expected = self.cfg.invite_code
        if expected is None:
            return
        if not isinstance(supplied, str):
            raise ApiError(401, "invalid invite code")
        given = supplied.strip().encode("utf-8")
        wanted = expected.encode("utf-8")
        if not hmac.compare_digest(given, wanted):
            raise ApiError(401, "invalid invite code")
