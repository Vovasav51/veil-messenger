"""Runtime configuration for the Veil relay, read from the environment.

The relay binds loopback only unless an operator explicitly opts out with
``VEIL_ALLOW_NON_LOOPBACK=1``. This task authorizes no public deployment, so the
default is deliberately the safe one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping

LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})
DEFAULT_TTL_DAYS = 30
DEFAULT_TTL_SECONDS = DEFAULT_TTL_DAYS * 24 * 60 * 60

# Hard ceilings: these keep a hostile client from asking the server to hold
# unbounded state or allocate unbounded memory, regardless of env overrides.
_MAX_BODY_CEILING = 4 * 1024 * 1024
_MAX_CIPHERTEXT_CEILING = 1024 * 1024
_MAX_OTK_PER_BUNDLE_CEILING = 500
_MAX_STORED_PREKEYS_CEILING = 5000
_MAX_MAILBOX_CEILING = 10000
_MAX_PULL_CEILING = 500
_MAX_ACK_CEILING = 500


@dataclass(frozen=True)
class RateLimit:
    """Token-bucket parameters: ``burst`` capacity, refilled at ``per_minute``."""

    per_minute: int
    burst: int


@dataclass(frozen=True)
class Config:
    host: str
    port: int
    db_path: str
    ttl_seconds: int
    invite_code: str | None
    max_body_bytes: int
    max_ciphertext_bytes: int
    max_otk_per_bundle: int
    max_stored_prekeys: int
    max_mailbox: int
    max_pull: int
    max_ack_ids: int
    max_threads: int
    request_timeout: float
    purge_interval: float
    purge_thread_interval: float
    rl_global: RateLimit
    rl_register: RateLimit
    rl_directory: RateLimit
    rl_prekeys_get: RateLimit
    rl_prekeys_put: RateLimit
    rl_messages_send: RateLimit
    rl_messages_pull: RateLimit
    rl_messages_ack: RateLimit

    @property
    def ttl_days(self) -> float:
        return self.ttl_seconds / 86400.0


def _env_int(
    env: Mapping[str, str],
    name: str,
    default: int,
    *,
    low: int,
    high: int,
) -> int:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    text = raw.strip()
    if not text.isascii() or not text.lstrip("+-").isdigit():
        raise ValueError(f"{name} must be an integer")
    value = int(text, 10)
    if not (low <= value <= high):
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


def _env_float(
    env: Mapping[str, str],
    name: str,
    default: float,
    *,
    low: float,
    high: float,
) -> float:
    raw = env.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw.strip())
    except ValueError as exc:  # pragma: no cover - defensive
        raise ValueError(f"{name} must be a number") from exc
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError(f"{name} must be a finite number")
    if not (low <= value <= high):
        raise ValueError(f"{name} must be between {low} and {high}")
    return value


def _env_rate(
    env: Mapping[str, str],
    name: str,
    default: RateLimit,
) -> RateLimit:
    per_minute = _env_int(
        env, f"VEIL_RL_{name}_PER_MIN", default.per_minute, low=1, high=100000
    )
    burst = _env_int(env, f"VEIL_RL_{name}_BURST", default.burst, low=1, high=100000)
    return RateLimit(per_minute=per_minute, burst=burst)


def _env_bool(env: Mapping[str, str], name: str) -> bool:
    return (env.get(name) or "").strip().lower() in {"1", "true", "yes", "on"}


def _default_db_path(env: Mapping[str, str]) -> str:
    """A private per-user data path, never a world-readable cwd file."""

    home = (env.get("HOME") or os.path.expanduser("~")).strip() or os.path.expanduser("~")
    xdg = (env.get("XDG_DATA_HOME") or "").strip()
    base = xdg if xdg else os.path.join(home, ".local", "share")
    return os.path.join(base, "veil-relay", "relay.sqlite3")


def from_env(env: Mapping[str, str] | None = None) -> Config:
    """Build a validated config from ``env`` (defaults to ``os.environ``)."""

    source: Mapping[str, str] = os.environ if env is None else env

    host = (source.get("VEIL_HOST") or "127.0.0.1").strip()
    if not host or len(host) > 255 or any(ch.isspace() for ch in host):
        raise ValueError("VEIL_HOST is not a valid host name or address")
    if host not in LOOPBACK_HOSTS and not _env_bool(source, "VEIL_ALLOW_NON_LOOPBACK"):
        raise ValueError(
            "refusing to bind a non-loopback address; the relay is a development "
            "component and must stay behind a local reverse proxy "
            "(set VEIL_ALLOW_NON_LOOPBACK=1 only if you understand this)"
        )

    port = _env_int(source, "VEIL_PORT", 8787, low=0, high=65535)

    db_path = (source.get("VEIL_DB") or _default_db_path(source)).strip()
    if not db_path or len(db_path) > 4096:
        raise ValueError("VEIL_DB must be a filesystem path")

    # VEIL_TTL_SECONDS exists so tests can exercise expiry quickly; it wins over
    # VEIL_TTL_DAYS when set.
    if (source.get("VEIL_TTL_SECONDS") or "").strip():
        ttl_seconds = _env_int(
            source, "VEIL_TTL_SECONDS", DEFAULT_TTL_SECONDS, low=1, high=20 * 365 * 86400
        )
    else:
        ttl_days = _env_int(
            source, "VEIL_TTL_DAYS", DEFAULT_TTL_DAYS, low=1, high=3650
        )
        ttl_seconds = ttl_days * 86400

    invite_code = (source.get("VEIL_INVITE_CODE") or "").strip() or None
    if invite_code is not None and len(invite_code) > 256:
        raise ValueError("VEIL_INVITE_CODE must be at most 256 characters")

    max_body = _env_int(
        source, "VEIL_MAX_BODY_BYTES", 262144, low=1024, high=_MAX_BODY_CEILING
    )
    max_ciphertext = _env_int(
        source,
        "VEIL_MAX_CIPHERTEXT_BYTES",
        65536,
        low=64,
        high=min(_MAX_CIPHERTEXT_CEILING, max_body),
    )
    max_otk = _env_int(
        source,
        "VEIL_MAX_OTK_PER_BUNDLE",
        200,
        low=1,
        high=_MAX_OTK_PER_BUNDLE_CEILING,
    )
    max_stored = _env_int(
        source,
        "VEIL_MAX_STORED_PREKEYS",
        400,
        low=max_otk,
        high=_MAX_STORED_PREKEYS_CEILING,
    )
    max_mailbox = _env_int(
        source, "VEIL_MAX_MAILBOX", 1000, low=1, high=_MAX_MAILBOX_CEILING
    )
    max_pull = _env_int(source, "VEIL_MAX_PULL", 100, low=1, high=_MAX_PULL_CEILING)
    max_ack = _env_int(source, "VEIL_MAX_ACK_IDS", 100, low=1, high=_MAX_ACK_CEILING)
    max_threads = _env_int(source, "VEIL_MAX_THREADS", 64, low=4, high=512)

    request_timeout = _env_float(
        source, "VEIL_REQUEST_TIMEOUT", 20.0, low=1.0, high=300.0
    )
    purge_interval = _env_float(
        source, "VEIL_PURGE_INTERVAL", 5.0, low=0.0, high=3600.0
    )
    purge_thread_interval = _env_float(
        source, "VEIL_PURGE_THREAD_INTERVAL", 60.0, low=1.0, high=86400.0
    )

    return Config(
        host=host,
        port=port,
        db_path=db_path,
        ttl_seconds=ttl_seconds,
        invite_code=invite_code,
        max_body_bytes=max_body,
        max_ciphertext_bytes=max_ciphertext,
        max_otk_per_bundle=max_otk,
        max_stored_prekeys=max_stored,
        max_mailbox=max_mailbox,
        max_pull=max_pull,
        max_ack_ids=max_ack,
        max_threads=max_threads,
        request_timeout=request_timeout,
        purge_interval=purge_interval,
        purge_thread_interval=purge_thread_interval,
        rl_global=_env_rate(source, "GLOBAL", RateLimit(1200, 300)),
        rl_register=_env_rate(source, "REGISTER", RateLimit(30, 30)),
        rl_directory=_env_rate(source, "DIRECTORY", RateLimit(120, 60)),
        rl_prekeys_get=_env_rate(source, "PREKEYS_GET", RateLimit(90, 45)),
        rl_prekeys_put=_env_rate(source, "PREKEYS_PUT", RateLimit(30, 15)),
        rl_messages_send=_env_rate(source, "MESSAGES_SEND", RateLimit(120, 60)),
        rl_messages_pull=_env_rate(source, "MESSAGES_PULL", RateLimit(120, 60)),
        rl_messages_ack=_env_rate(source, "MESSAGES_ACK", RateLimit(120, 60)),
    )
