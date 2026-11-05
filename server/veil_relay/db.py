"""SQLite persistence with explicit, retrying write transactions.

Design notes
------------
* WAL mode + ``synchronous=FULL``: a committed ACK / message / tombstone
  survives a crash, which is what the "durable dedup tombstone" requirement
  needs.
* One short-lived connection per operation: no connection is ever handed to a
  request thread that later dies, so nothing leaks.
* Write transactions use ``BEGIN IMMEDIATE`` so concurrent one-time-prekey
  consumption serializes instead of racing, and SQLITE_BUSY is retried with
  bounded exponential backoff.
* The database file is created with mode 0600 inside a 0700 directory. SQLite
  copies the database file's mode onto its WAL/SHM files, so those stay private
  too.
"""

from __future__ import annotations

import errno
import os
import sqlite3
import stat
import sys
import time
from contextlib import contextmanager
from typing import Callable, Iterator, TypeVar

T = TypeVar("T")

SCHEMA_VERSION = 3

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS accounts (
    uid                  TEXT PRIMARY KEY,
    handle               TEXT NOT NULL UNIQUE,
    device_id            INTEGER NOT NULL,
    token_hash           BLOB NOT NULL UNIQUE,
    registration_id      INTEGER NOT NULL,
    identity_key         TEXT NOT NULL,
    signed_prekey_id     INTEGER NOT NULL,
    signed_prekey_public TEXT NOT NULL,
    signed_prekey_sig    TEXT NOT NULL,
    kyber_prekey_id      INTEGER NOT NULL,
    kyber_prekey_public  TEXT NOT NULL,
    kyber_prekey_sig     TEXT NOT NULL,
    created_at           INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS one_time_prekeys (
    uid         TEXT NOT NULL REFERENCES accounts(uid) ON DELETE CASCADE,
    key_id      INTEGER NOT NULL,
    public_key  TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    consumed_at INTEGER,
    PRIMARY KEY (uid, key_id)
);

CREATE INDEX IF NOT EXISTS one_time_prekeys_available
    ON one_time_prekeys(uid, consumed_at, key_id);

CREATE TABLE IF NOT EXISTS messages (
    sender_uid    TEXT NOT NULL,
    msg_id        TEXT NOT NULL,
    recipient_uid TEXT NOT NULL REFERENCES accounts(uid) ON DELETE CASCADE,
    message_type  INTEGER NOT NULL,
    ciphertext    TEXT,
    ciphertext_sha256 BLOB,
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    acked_at      INTEGER,
    PRIMARY KEY (sender_uid, msg_id)
);

CREATE INDEX IF NOT EXISTS messages_inbox
    ON messages(recipient_uid, created_at, msg_id);

CREATE INDEX IF NOT EXISTS messages_expiry
    ON messages(expires_at);
"""

# Applied separately so that an upgrade from an older database can fail closed
# with a clear error instead of exploding halfway through the table script.
UNIQUE_INBOX_INDEX_SQL = (
    "CREATE UNIQUE INDEX IF NOT EXISTS messages_recipient_msg "
    "ON messages(recipient_uid, msg_id)"
)


def _stderr_warning(message: str) -> None:
    print(f"veil-relay: warning: {message}", file=sys.stderr)


class Database:
    """Thin, thread-safe wrapper around a private SQLite file.

    The database file itself is always ``0600`` and must not be a symlink. The
    *parent* directory is only chmod'ed when this process created it: an
    existing directory (a home directory, a shared data dir) is never modified.
    """

    def __init__(
        self,
        path: str,
        *,
        retries: int = 8,
        warn: Callable[[str], None] | None = None,
    ) -> None:
        self.path = os.path.abspath(path)
        self._retries = max(1, int(retries))
        self._warn = warn if warn is not None else _stderr_warning
        self._prepare_path()
        self._init_schema()

    # -- setup ---------------------------------------------------------------

    def _prepare_path(self) -> None:
        parent = os.path.dirname(self.path) or "."
        parent_existed = os.path.isdir(parent)
        if not parent_existed:
            if os.path.exists(parent) or os.path.islink(parent):
                raise RuntimeError(f"database parent is not a directory: {parent}")
            # Dedicated directory: we created it, so 0700 is ours to set.
            os.makedirs(parent, mode=0o700, exist_ok=True)
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
        else:
            # Never touch permissions on a directory we did not create.
            try:
                parent_mode = stat.S_IMODE(os.stat(parent).st_mode)
            except OSError:
                parent_mode = None
            if parent_mode is not None and parent_mode & 0o077:
                self._warn(
                    f"database directory {parent} is accessible by other users "
                    f"(mode {parent_mode:04o}); the database file itself is 0600 "
                    "-- prefer a dedicated 0700 directory"
                )

        if os.path.islink(self.path):
            raise RuntimeError(
                "database path must not be a symlink; point --db at a real file "
                "inside a private directory"
            )

        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            if exc.errno in (errno.ELOOP, errno.EMLINK):
                raise RuntimeError(
                    "database path must not be a symlink"
                ) from None
            raise
        try:
            # fchmod on the descriptor we opened, never on a path we did not
            # verify, so a swapped symlink cannot make us chmod something else.
            os.fchmod(fd, 0o600)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise RuntimeError("database path must be a regular file")
        finally:
            os.close(fd)

    def _connect(self) -> sqlite3.Connection:
        if os.path.islink(self.path):
            raise RuntimeError("database path must not be a symlink")
        conn = sqlite3.connect(
            self.path,
            timeout=30.0,
            isolation_level=None,  # explicit BEGIN/COMMIT only
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA busy_timeout=30000")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA synchronous=FULL")
            conn.execute("PRAGMA trusted_schema=OFF")
        except sqlite3.Error:
            conn.close()
            raise
        return conn

    def _init_schema(self) -> None:
        conn = self._connect()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(SCHEMA_SQL)
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])

            if version == 0:
                pass  # fresh database, tables just created
            elif version == 1:
                # Pre-release upgrade: add the dedup fingerprint column. Rows
                # written by v1 keep a NULL hash and accept any retry payload.
                columns = {
                    row["name"]
                    for row in conn.execute("PRAGMA table_info(messages)").fetchall()
                }
                if "ciphertext_sha256" not in columns:
                    conn.execute(
                        "ALTER TABLE messages ADD COLUMN ciphertext_sha256 BLOB"
                    )
            elif version not in (2, 3):
                raise RuntimeError(
                    f"unsupported database schema version {version}; "
                    f"this build expects {SCHEMA_VERSION}"
                )

            # v3: a message id is unique inside one recipient mailbox, so an
            # ACK-by-id batch can never address two envelopes. Fail closed
            # rather than delete legacy rows if an old database collides.
            try:
                conn.execute(UNIQUE_INBOX_INDEX_SQL)
            except sqlite3.IntegrityError:
                raise RuntimeError(
                    "existing database contains duplicate (recipient_uid, msg_id) "
                    "messages; refusing to start because a unique inbox-id index "
                    "cannot be created (fail closed)"
                ) from None

            if version != SCHEMA_VERSION:
                conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        finally:
            conn.close()

    # -- access --------------------------------------------------------------

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a fresh connection; always closed, open transactions rolled back."""

        conn = self._connect()
        try:
            yield conn
        finally:
            try:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            conn.close()

    def read(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        with self.connection() as conn:
            return fn(conn)

    def transaction(self, fn: Callable[[sqlite3.Connection], T]) -> T:
        """Run ``fn`` inside ``BEGIN IMMEDIATE`` ... ``COMMIT``.

        ``fn`` may raise :class:`ApiError`; the transaction is rolled back and the
        error propagates untouched. Busy/locked failures are retried a bounded
        number of times.
        """

        delay = 0.005
        last_error: sqlite3.OperationalError | None = None
        for attempt in range(self._retries):
            with self.connection() as conn:
                try:
                    conn.execute("BEGIN IMMEDIATE")
                except sqlite3.OperationalError as exc:
                    last_error = exc
                else:
                    try:
                        result = fn(conn)
                    except BaseException:
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                        raise
                    try:
                        conn.execute("COMMIT")
                    except sqlite3.OperationalError as exc:
                        try:
                            conn.execute("ROLLBACK")
                        except sqlite3.Error:
                            pass
                        last_error = exc
                    else:
                        return result
            if attempt + 1 < self._retries:
                message = str(last_error).lower()
                if "locked" not in message and "busy" not in message:
                    raise last_error  # type: ignore[misc]
                time.sleep(delay)
                delay = min(delay * 2, 0.2)
        assert last_error is not None
        raise last_error
