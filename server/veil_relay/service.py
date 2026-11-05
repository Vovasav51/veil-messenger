"""Relay business logic.

The relay is an opaque store: it never parses or verifies Signal ciphertexts or
signatures, and it never stores message plaintext. All invariants that matter
(uniqueness, one-time prekey consumption, idempotency, ACK ownership) are
enforced inside single SQLite write transactions.
"""

from __future__ import annotations

import base64
import hashlib
import sqlite3
import time
from typing import Any

from .config import Config
from .db import Database
from .errors import ApiError


def now_ts() -> int:
    return int(time.time())


def new_token() -> str:
    import secrets

    return base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


# --- accounts ----------------------------------------------------------------


def register(
    db: Database,
    *,
    uid: str,
    handle: str,
    device_id: int,
    bundle: dict[str, Any],
) -> dict[str, Any]:
    token = new_token()
    token_hash = hash_token(token)
    created_at = now_ts()

    def _run(conn: sqlite3.Connection) -> None:
        existing = conn.execute(
            "SELECT uid, handle FROM accounts WHERE uid = ? OR handle = ?",
            (uid, handle),
        ).fetchone()
        if existing is not None:
            if existing["uid"] == uid:
                raise ApiError(409, "uid is already registered")
            raise ApiError(409, "handle is already taken")
        try:
            conn.execute(
                """
                INSERT INTO accounts (
                    uid, handle, device_id, token_hash, registration_id,
                    identity_key, signed_prekey_id, signed_prekey_public,
                    signed_prekey_sig, kyber_prekey_id, kyber_prekey_public,
                    kyber_prekey_sig, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    uid,
                    handle,
                    device_id,
                    token_hash,
                    bundle["registration_id"],
                    bundle["identity_key"],
                    bundle["signed_prekey"]["id"],
                    bundle["signed_prekey"]["public_key"],
                    bundle["signed_prekey"]["signature"],
                    bundle["kyber_prekey"]["id"],
                    bundle["kyber_prekey"]["public_key"],
                    bundle["kyber_prekey"]["signature"],
                    created_at,
                ),
            )
        except sqlite3.IntegrityError:
            raise ApiError(409, "account already exists") from None
        for key in bundle["one_time_prekeys"]:
            conn.execute(
                """
                INSERT INTO one_time_prekeys (uid, key_id, public_key, created_at, consumed_at)
                VALUES (?, ?, ?, ?, NULL)
                """,
                (uid, key["id"], key["public_key"], created_at),
            )

    db.transaction(_run)
    return {"uid": uid, "handle": handle, "token": token}


def authenticate(db: Database, token: str) -> dict[str, Any]:
    token_hash = hash_token(token)

    def _run(conn: sqlite3.Connection) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT uid, handle FROM accounts WHERE token_hash = ?", (token_hash,)
        ).fetchone()

    row = db.read(_run)
    if row is None:
        raise ApiError(401, "invalid bearer token")
    return {"uid": row["uid"], "handle": row["handle"]}


def directory_entry(db: Database, handle: str) -> dict[str, Any]:
    def _run(conn: sqlite3.Connection) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT uid, handle, device_id, identity_key FROM accounts WHERE handle = ?",
            (handle,),
        ).fetchone()

    row = db.read(_run)
    if row is None:
        raise ApiError(404, "unknown handle")
    return {
        "uid": row["uid"],
        "handle": row["handle"],
        "device_id": row["device_id"],
        "identity_key": row["identity_key"],
    }


# --- prekeys -----------------------------------------------------------------


def _bundle_from_account(account: sqlite3.Row) -> dict[str, Any]:
    return {
        "registration_id": account["registration_id"],
        "device_id": account["device_id"],
        "identity_key": account["identity_key"],
        "signed_prekey": {
            "id": account["signed_prekey_id"],
            "public_key": account["signed_prekey_public"],
            "signature": account["signed_prekey_sig"],
        },
        "kyber_prekey": {
            "id": account["kyber_prekey_id"],
            "public_key": account["kyber_prekey_public"],
            "signature": account["kyber_prekey_sig"],
        },
        "one_time_prekeys": [],
    }


def fetch_bundle_and_consume(db: Database, target_uid: str) -> dict[str, Any]:
    """Return the target's public bundle and atomically consume one prekey."""

    consumed_at = now_ts()

    def _run(conn: sqlite3.Connection) -> dict[str, Any]:
        account = conn.execute(
            "SELECT * FROM accounts WHERE uid = ?", (target_uid,)
        ).fetchone()
        if account is None:
            raise ApiError(404, "unknown uid")

        prekey = conn.execute(
            """
            SELECT key_id, public_key
            FROM one_time_prekeys
            WHERE uid = ? AND consumed_at IS NULL
            ORDER BY key_id ASC
            LIMIT 1
            """,
            (target_uid,),
        ).fetchone()

        bundle = _bundle_from_account(account)
        if prekey is not None:
            cursor = conn.execute(
                """
                UPDATE one_time_prekeys SET consumed_at = ?
                WHERE uid = ? AND key_id = ? AND consumed_at IS NULL
                """,
                (consumed_at, target_uid, prekey["key_id"]),
            )
            if cursor.rowcount != 1:
                # Impossible under BEGIN IMMEDIATE; fail loudly rather than
                # hand out a key twice.
                raise RuntimeError("prekey consumption lost a race")
            bundle["one_time_prekeys"].append(
                {"id": prekey["key_id"], "public_key": prekey["public_key"]}
            )
        return bundle

    return db.transaction(_run)


def replace_prekeys(cfg: Config, db: Database, uid: str, bundle: dict[str, Any]) -> None:
    created_at = now_ts()

    def _run(conn: sqlite3.Connection) -> None:
        account = conn.execute(
            "SELECT * FROM accounts WHERE uid = ?", (uid,)
        ).fetchone()
        if account is None:
            raise ApiError(404, "unknown account")

        if bundle["registration_id"] != account["registration_id"]:
            raise ApiError(409, "registration_id cannot change")
        if bundle["identity_key"] != account["identity_key"]:
            raise ApiError(409, "identity_key cannot change")
        signed = bundle["signed_prekey"]
        if (
            signed["id"] != account["signed_prekey_id"]
            or signed["public_key"] != account["signed_prekey_public"]
            or signed["signature"] != account["signed_prekey_sig"]
        ):
            raise ApiError(409, "signed_prekey cannot change")
        kyber = bundle["kyber_prekey"]
        if (
            kyber["id"] != account["kyber_prekey_id"]
            or kyber["public_key"] != account["kyber_prekey_public"]
            or kyber["signature"] != account["kyber_prekey_sig"]
        ):
            raise ApiError(409, "kyber_prekey cannot change")

        stored = int(
            conn.execute(
                "SELECT COUNT(*) FROM one_time_prekeys WHERE uid = ?", (uid,)
            ).fetchone()[0]
        )
        for key in bundle["one_time_prekeys"]:
            row = conn.execute(
                "SELECT public_key, consumed_at FROM one_time_prekeys WHERE uid = ? AND key_id = ?",
                (uid, key["id"]),
            ).fetchone()
            if row is not None:
                if row["consumed_at"] is not None:
                    raise ApiError(409, "one_time_prekey was already consumed")
                if row["public_key"] != key["public_key"]:
                    raise ApiError(409, "one_time_prekey public key mismatch")
                continue  # idempotent re-upload of an unconsumed key
            if stored >= cfg.max_stored_prekeys:
                raise ApiError(429, "prekey quota exceeded")
            conn.execute(
                """
                INSERT INTO one_time_prekeys (uid, key_id, public_key, created_at, consumed_at)
                VALUES (?, ?, ?, ?, NULL)
                """,
                (uid, key["id"], key["public_key"], created_at),
            )
            stored += 1

    db.transaction(_run)


# --- messages ----------------------------------------------------------------


def send_message(
    cfg: Config,
    db: Database,
    *,
    sender_uid: str,
    message: dict[str, Any],
) -> dict[str, Any]:
    created_at = now_ts()
    expires_at = created_at + cfg.ttl_seconds

    def _run(conn: sqlite3.Connection) -> dict[str, Any]:
        recipient = conn.execute(
            "SELECT uid FROM accounts WHERE uid = ?", (message["recipient_uid"],)
        ).fetchone()
        if recipient is None:
            raise ApiError(404, "unknown recipient")

        digest = hashlib.sha256(message["ciphertext"].encode("ascii")).digest()

        own = conn.execute(
            """
            SELECT recipient_uid, message_type, ciphertext_sha256
            FROM messages
            WHERE sender_uid = ? AND msg_id = ?
            """,
            (sender_uid, message["id"]),
        ).fetchone()
        if own is not None:
            # Idempotent retry: same sender + id + recipient + type + payload.
            # The payload itself is purged on ACK, but the SHA-256 fingerprint
            # survives in the tombstone, so a mismatched retry is still caught.
            if (
                own["recipient_uid"] != message["recipient_uid"]
                or own["message_type"] != message["message_type"]
                or (
                    own["ciphertext_sha256"] is not None
                    and bytes(own["ciphertext_sha256"]) != digest
                )
            ):
                raise ApiError(409, "message id conflict")
            return {"id": message["id"], "accepted": True}

        # Message ids are unique per recipient mailbox (v3). Another sender may
        # already have used this id for this recipient; refuse with the same
        # generic conflict so nothing about that envelope is revealed.
        taken = conn.execute(
            "SELECT 1 FROM messages WHERE recipient_uid = ? AND msg_id = ?",
            (message["recipient_uid"], message["id"]),
        ).fetchone()
        if taken is not None:
            raise ApiError(409, "message id conflict")

        pending = int(
            conn.execute(
                """
                SELECT COUNT(*) FROM messages
                WHERE recipient_uid = ? AND ciphertext IS NOT NULL
                """,
                (message["recipient_uid"],),
            ).fetchone()[0]
        )
        if pending >= cfg.max_mailbox:
            raise ApiError(429, "recipient mailbox is full")

        try:
            conn.execute(
                """
                INSERT INTO messages (
                    sender_uid, msg_id, recipient_uid, message_type,
                    ciphertext, ciphertext_sha256, created_at, expires_at, acked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    sender_uid,
                    message["id"],
                    message["recipient_uid"],
                    message["message_type"],
                    message["ciphertext"],
                    digest,
                    created_at,
                    expires_at,
                ),
            )
        except sqlite3.IntegrityError:
            # Concurrent insert of the same (recipient, id) or (sender, id).
            raise ApiError(409, "message id conflict") from None
        return {"id": message["id"], "accepted": True}

    return db.transaction(_run)


def fetch_messages(cfg: Config, db: Database, uid: str) -> dict[str, Any]:
    def _run(conn: sqlite3.Connection) -> list[sqlite3.Row]:
        return conn.execute(
            """
            SELECT msg_id, sender_uid, recipient_uid, message_type,
                   ciphertext, created_at
            FROM messages
            WHERE recipient_uid = ? AND ciphertext IS NOT NULL
            ORDER BY created_at ASC, rowid ASC
            LIMIT ?
            """,
            (uid, cfg.max_pull),
        ).fetchall()

    rows = db.read(_run)
    return {
        "messages": [
            {
                "id": row["msg_id"],
                "sender_uid": row["sender_uid"],
                "sender_device_id": 1,
                "recipient_uid": row["recipient_uid"],
                "recipient_device_id": 1,
                "message_type": row["message_type"],
                "ciphertext": row["ciphertext"],
                "created_at": row["created_at"],
            }
            for row in rows
        ]
    }


def ack_messages(db: Database, uid: str, ids: list[str]) -> None:
    acked_at = now_ts()

    def _run(conn: sqlite3.Connection) -> None:
        for message_id in ids:
            # Scoped to the caller's own inbox: an id from somebody else's
            # mailbox matches nothing and is silently ignored, which also avoids
            # leaking whether that envelope exists.
            conn.execute(
                """
                UPDATE messages SET ciphertext = NULL, acked_at = COALESCE(acked_at, ?)
                WHERE recipient_uid = ? AND msg_id = ? AND ciphertext IS NOT NULL
                """,
                (acked_at, uid, message_id),
            )

    db.transaction(_run)


# --- maintenance -------------------------------------------------------------


def purge_expired(db: Database, *, now: int | None = None) -> int:
    """Delete expired message rows (payloads and tombstones).

    Consumed one-time prekey tombstones are intentionally **never** purged: a
    prekey id that was handed out once must never be accepted again. The
    per-account row cap (``VEIL_MAX_STORED_PREKEYS``) is therefore also the
    lifetime key budget for an account; see the server README.
    """

    current = now_ts() if now is None else int(now)

    def _run(conn: sqlite3.Connection) -> int:
        deleted = conn.execute(
            "DELETE FROM messages WHERE expires_at <= ?", (current,)
        ).rowcount
        return int(deleted or 0)

    return db.transaction(_run)
