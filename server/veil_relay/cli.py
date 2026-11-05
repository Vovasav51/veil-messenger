"""Command line entry point: ``python3 -m veil_relay`` or the packaged .pyz."""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
from typing import Sequence

from . import __version__
from .app import App
from .config import Config, from_env
from .db import Database
from .httpd import RelayHTTPServer


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="veil-relay",
        description=(
            "Veil relay: loopback development server that stores opaque Signal "
            "ciphertexts and public key bundles. No plaintext, no crypto."
        ),
    )
    parser.add_argument(
        "--host",
        default=None,
        help="bind address (default: 127.0.0.1; non-loopback needs VEIL_ALLOW_NON_LOOPBACK=1)",
    )
    parser.add_argument(
        "--port", type=int, default=None, help="bind port (default: 8787, 0 = ephemeral)"
    )
    parser.add_argument(
        "--db",
        default=None,
        help="SQLite path (default: $XDG_DATA_HOME/veil-relay/relay.sqlite3)",
    )
    parser.add_argument(
        "--ttl-days", type=int, default=None, help="message TTL in days (default: 30)"
    )
    parser.add_argument(
        "--invite-code",
        default=None,
        help="require this invite code at registration (overrides VEIL_INVITE_CODE)",
    )
    parser.add_argument(
        "--check", action="store_true", help="validate configuration and exit"
    )
    parser.add_argument("--version", action="version", version=f"veil-relay {__version__}")
    return parser


def _config_from_args(args: argparse.Namespace) -> Config:
    env = dict(os.environ)
    if args.host is not None:
        env["VEIL_HOST"] = args.host
    if args.port is not None:
        env["VEIL_PORT"] = str(args.port)
    if args.db is not None:
        env["VEIL_DB"] = args.db
    if args.ttl_days is not None:
        env.pop("VEIL_TTL_SECONDS", None)
        env["VEIL_TTL_DAYS"] = str(args.ttl_days)
    if args.invite_code is not None:
        env["VEIL_INVITE_CODE"] = args.invite_code
    return from_env(env)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        cfg = _config_from_args(args)
    except ValueError as exc:
        print(f"veil-relay: {exc}", file=sys.stderr)
        return 2

    print(
        "veil-relay {}: db={} ttl={}d invite={} max_body={} max_threads={}".format(
            __version__,
            cfg.db_path,
            int(cfg.ttl_days) if cfg.ttl_days == int(cfg.ttl_days) else cfg.ttl_days,
            "required" if cfg.invite_code else "open",
            cfg.max_body_bytes,
            cfg.max_threads,
        ),
        flush=True,
    )

    if args.check:
        try:
            Database(cfg.db_path)
        except (OSError, RuntimeError) as exc:
            print(f"veil-relay: cannot open database: {exc}", file=sys.stderr)
            return 1
        print("veil-relay: configuration ok", flush=True)
        return 0

    try:
        db = Database(cfg.db_path)
    except (OSError, RuntimeError) as exc:
        print(f"veil-relay: cannot open database: {exc}", file=sys.stderr)
        return 1

    app = App(cfg, db)
    try:
        httpd = RelayHTTPServer((cfg.host, cfg.port), app)
    except OSError as exc:
        print(f"veil-relay: cannot bind {cfg.host}:{cfg.port}: {exc}", file=sys.stderr)
        return 1

    app.start()
    address, port = httpd.server_address[:2]
    print(
        f"veil-relay {__version__}: listening on http://{address}:{port} "
        "(loopback development only; terminate HTTPS in a local reverse proxy)",
        flush=True,
    )

    stop = threading.Event()

    def _request_stop(signum: int, frame: object) -> None:  # noqa: ARG001
        stop.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, _request_stop)
        except (ValueError, OSError):  # pragma: no cover - non-main thread
            pass

    httpd.timeout = 0.2
    try:
        while not stop.is_set():
            httpd.handle_request()
    finally:
        httpd.server_close()
        app.stop()
        print("veil-relay: stopped", flush=True)
    return 0
