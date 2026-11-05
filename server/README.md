# Veil relay (server)

Minimal, zero-dependency ciphertext relay for the Veil iOS MVP. It implements the
JSON API from [`../SPEC.md`](../SPEC.md) and nothing else: no accounts beyond a
UID/handle, no phone or email, no contacts, no plaintext, no protocol crypto.

> **Status:** unaudited development MVP. Binds `127.0.0.1` by default and refuses
> a non-loopback address unless `VEIL_ALLOW_NON_LOOPBACK=1` is set explicitly.
> No public deployment is authorized by this project. Do not run load tests
> against anything but your own loopback process.

## What the relay does and does not hold

| Stored | Not stored |
| --- | --- |
| UID, handle, device id (always 1) | passwords, phone, email, contacts |
| SHA-256 of the bearer token | the bearer token itself |
| Signal **public** bundle (identity, signed prekey, kyber prekey, one-time prekeys) | private keys |
| opaque base64 ciphertext + routing metadata | message plaintext |
| SHA-256 fingerprint of each ciphertext (dedup tombstone) | decrypted or decryptable content |

The relay never verifies Signal signatures and never parses ciphertext. All
cryptography lives in the iOS client, which pins the upstream
`LibSignalClient`. The relay is an opaque, trusted-for-availability store.

## Requirements

* Linux (tested on Ubuntu with **Python 3.14.4**; code targets 3.11+).
* Standard library only. There is no `requirements.txt` because nothing is
  installed: `sqlite3`, `http.server`, `ssl`-free plain HTTP, `json`, `hashlib`.
* Reverse proxy for TLS (Caddy recommended) — the relay speaks plain HTTP and
  must stay on loopback behind that proxy.

## Run

Module form (from this `server/` directory):

```bash
python3 -m veil_relay --host 127.0.0.1 --port 8787 --db /path/private/relay.sqlite3
```

Single-file executable (no dependencies, build once from the repo root):

```bash
python3 server/build_zipapp.py      # writes ./dist/veil-relay.pyz (repo root)
python3 dist/veil-relay.pyz --host 127.0.0.1 --port 8787 --db /path/private/relay.sqlite3
```

`build_zipapp.py` always defaults to the repository-root `dist/veil-relay.pyz`,
regardless of the directory it is invoked from; `--output PATH` overrides it.

Health check:

```bash
curl -s http://127.0.0.1:8787/health
# {"status":"ok","version":"0.1.0"}
```

CLI flags: `--host`, `--port` (`0` = ephemeral), `--db`, `--ttl-days`,
`--invite-code`, `--check` (validate config + open the DB, then exit),
`--version`.

Defaults: host `127.0.0.1`, port `8787`, TTL 30 days, DB
`$XDG_DATA_HOME/veil-relay/relay.sqlite3` (or
`~/.local/share/veil-relay/relay.sqlite3`).

Database path rules:

* The SQLite file (and its `-wal`/`-shm` siblings) is always `0600`.
* A **newly created** parent directory is `0700`.
* An **existing** directory is never chmod'ed — pointing `--db` at a shared or
  home directory leaves its mode untouched. If that directory is group/world
  accessible the relay prints a one-time advisory warning and keeps the file at
  `0600`; prefer a dedicated `0700` directory.
* A symlinked database path is rejected (`O_NOFOLLOW` + `fchmod` on the opened
  descriptor), so the relay can never chmod an unrelated file.

Startup prints one line with the bind address, the DB path and the TTL. Nothing
per-request is ever printed: there are no access, body, or auth logs. The only
stderr line possible is a sanitized `veil-relay: internal error ...` without
request data. `VEIL_DEBUG=1` is a local-only escape hatch that enables tracebacks
on stderr; never set it where stderr is collected.

## Configuration (environment)

`--host`, `--port`, `--db`, `--ttl-days`, `--invite-code` override the matching
variables. All values are validated at startup; invalid values exit with code 2.

| Variable | Default | Meaning |
| --- | --- | --- |
| `VEIL_HOST` | `127.0.0.1` | bind address (non-loopback needs `VEIL_ALLOW_NON_LOOPBACK=1`) |
| `VEIL_ALLOW_NON_LOOPBACK` | unset | explicit opt-out of the loopback guard |
| `VEIL_PORT` | `8787` | bind port, `0` = ephemeral |
| `VEIL_DB` | private XDG path | SQLite file path |
| `VEIL_TTL_DAYS` | `30` | ciphertext + tombstone TTL |
| `VEIL_TTL_SECONDS` | unset | test override, wins over `VEIL_TTL_DAYS` |
| `VEIL_INVITE_CODE` | unset | when set, registration requires `invite_code` |
| `VEIL_MAX_BODY_BYTES` | `262144` | maximum request body (also caps all fields) |
| `VEIL_MAX_CIPHERTEXT_BYTES` | `65536` | maximum decoded ciphertext |
| `VEIL_MAX_OTK_PER_BUNDLE` | `200` | one-time prekeys accepted per bundle |
| `VEIL_MAX_STORED_PREKEYS` | `400` | rows per account (available + consumed tombstones) |
| `VEIL_MAX_MAILBOX` | `1000` | pending (un-ACKed) messages per recipient |
| `VEIL_MAX_PULL` | `100` | messages returned by one `GET /v1/messages` |
| `VEIL_MAX_ACK_IDS` | `100` | ids accepted by one ACK batch |
| `VEIL_MAX_THREADS` | `64` | concurrent handler threads (extra connections are dropped) |
| `VEIL_REQUEST_TIMEOUT` | `20` | socket timeout per read/write, seconds |
| `VEIL_PURGE_INTERVAL` | `5` | minimum seconds between per-request purges |
| `VEIL_PURGE_THREAD_INTERVAL` | `60` | idle purge timer, seconds |
| `VEIL_RL_<NAME>_PER_MIN` / `_BURST` | see below | token-bucket rate limits |

Rate-limit buckets (per process, in memory):

| Name | Scope | Default per minute / burst |
| --- | --- | --- |
| `GLOBAL` | client IP | 1200 / 300 |
| `REGISTER` | client IP | 30 / 30 |
| `DIRECTORY` | caller UID | 120 / 60 |
| `PREKEYS_GET` | caller UID | 90 / 45 |
| `PREKEYS_PUT` | caller UID | 30 / 15 |
| `MESSAGES_SEND` | caller UID | 120 / 60 |
| `MESSAGES_PULL` | caller UID | 120 / 60 |
| `MESSAGES_ACK` | caller UID | 120 / 60 |

## API v1

All JSON, `snake_case`. Every endpoint except `GET /health` and
`POST /v1/register` requires `Authorization: Bearer <token>`. Errors are always
`{"detail": "<safe string>"}` with status `400`, `401`, `404`, `405`, `409`,
`413`, `429`, or a generic `500`.

`uid` and message `id` are client-generated canonical UUIDs (any version,
lower-cased by the server; nil UUID rejected). `device_id` is always `1`.
Handles are normalised to lower-case ASCII `[a-z0-9_]{3,24}`, with an optional
leading `@` stripped.

### `GET /health`

`200 {"status":"ok","version":"0.1.0"}`.

### `POST /v1/register`

```json
{
  "uid": "0192f0c4-...",
  "handle": "@Alice_01",
  "device_id": 1,
  "bundle": { "...": "PublicBundle" },
  "invite_code": "optional, only when VEIL_INVITE_CODE is configured"
}
```

`201 {"uid","handle","token"}`. The token is 32 random bytes, base64url, 43
characters; only its SHA-256 is stored. UID and handle are unique (`409`).
Invalid handles/UUIDs/bundles are `400`; a wrong or missing invite code is `401`.
Registration is rate-limited per client IP. **The API extension `invite_code` is
only meaningful when the server has `VEIL_INVITE_CODE` set**; otherwise it is
ignored and registration is open.

A client that loses the registration response cannot recover the token: there is
no account recovery in v0.1. Register again with a fresh UID/handle.

### `GET /v1/directory/{handle}`

`200 {"uid","handle","device_id":1,"identity_key":"<base64>"}`. Exact lookup,
authenticated, rate-limited per caller. Unknown handle `404`, malformed handle
`400`.

### `GET /v1/prekeys/{uid}`

Returns the target `PublicBundle` with **at most one** `one_time_prekeys` entry.
One available prekey is consumed atomically (`BEGIN IMMEDIATE`) as part of the
same transaction, so concurrent fetches never receive the same key. When the
pool is empty the bundle is still returned with `"one_time_prekeys": []`.
Unknown UID `404`.

The relay serves one prekey per session and never reuses one. Note that a
prekey is consumed even by a self-fetch; that follows the contract and is
rate-limited per caller.

### `PUT /v1/prekeys`

Body is a bare `PublicBundle` for the authenticated account:
`200 {"ok":true}`.

* `registration_id`, `identity_key`, `signed_prekey`, `kyber_prekey` are
  immutable in v0.1: any difference is `409` (no silent rotation).
* One-time prekeys are merged by id. Re-uploading an existing **unconsumed** id
  with the same public key is idempotent; a different public key `409`; an id
  that was already consumed `409` (replay protection).
* Exceeding `VEIL_MAX_STORED_PREKEYS` is `429`.

### `POST /v1/messages`

```json
{
  "id": "UUID",
  "recipient_uid": "UUID",
  "recipient_device_id": 1,
  "message_type": 2,
  "ciphertext": "<base64>"
}
```

`202 {"id","accepted":true}`. Only Signal message types `2` (CIPHERTEXT) and `3`
(PREKEY_BUNDLE) are accepted. `sender_uid` is always derived from the bearer
token; any `sender_uid`/`sender_device_id` supplied in the body is ignored.

Idempotency is sender-scoped: `(sender_uid, id)` is unique, so retrying the
identical message is a `202` no-op. Reusing the id with a different recipient,
type, or ciphertext is `409` — including after the recipient ACKed it, because
the tombstone keeps a SHA-256 fingerprint of the purged ciphertext.

Message ids are also unique **per recipient mailbox** (`(recipient_uid, id)`
unique index, schema v3). If a different sender already used that id for the
same recipient, the relay answers `409 {"detail":"message id conflict"}` with
no further detail, so an ACK-by-id batch can never address two envelopes.
Using the same id for different recipients is fine. Unknown recipient `404`;
mailbox full `429`; oversized ciphertext `413`.

### `GET /v1/messages`

`200 {"messages":[{id,sender_uid,sender_device_id:1,recipient_uid,recipient_device_id:1,message_type,ciphertext,created_at}]}`

Oldest first, at most `VEIL_MAX_PULL` (100) entries. Pull does not delete
anything; the client ACKs after durable commit.

### `POST /v1/messages/ack`

`{"ids":["UUID", ...]}` (at most 100, duplicates collapsed) →
`200 {"ok":true}`.

Only the caller's own inbox is touched: an id that belongs to somebody else's
mailbox (or does not exist) is silently ignored. This avoids leaking envelope
existence and is idempotent. ACK purges the ciphertext and keeps a tombstone
(no payload, SHA-256 fingerprint, `acked_at`) until TTL, so a sender retry still
gets `202`.

### `PublicBundle` validation

| Field | Rule |
| --- | --- |
| `registration_id` | integer `1..16380` (bool/float/string rejected) |
| `device_id` | integer `1` |
| `identity_key` | base64, exactly 33 bytes, first byte `0x05` |
| `signed_prekey.id` / `kyber_prekey.id` | integer `1..4294967295` |
| `signed_prekey.public_key` | base64, exactly 33 bytes, first byte `0x05` |
| `signed_prekey.signature` | base64, exactly 64 bytes (XEd25519) |
| `kyber_prekey.public_key` | base64, 1568 bytes (Kyber-1024, as serialized by current libsignal); 1569 tolerated for a leading type byte |
| `kyber_prekey.signature` | base64, exactly 64 bytes |
| `one_time_prekeys[].id` | integer `1..4294967295`, unique within the bundle |
| `one_time_prekeys[].public_key` | base64, exactly 33 bytes, first byte `0x05` |
| `one_time_prekeys` | array, at most 200 entries, may be empty |

Base64 must be canonical standard base64 (`A-Za-z0-9+/`, correct `=`, no
whitespace, no URL-safe alphabet, no stray trailing bits). These are serialized
*sizes* only — the relay does not verify signatures, and it does not pin a
libsignal version. The iOS client pins
[`LibSignalClient`](https://github.com/signalapp/libsignal); if the pinned
version serializes Kyber keys differently, adjust
`KYBER_PUBLIC_KEY_LEN`/`KYBER_PUBLIC_KEY_MAX` in
`veil_relay/validation.py` and document it. Do not invent protocol crypto in the
relay to "fix" a mismatch.

## TTL, purge and durability

* Every message gets `expires_at = created_at + TTL` (default 30 days).
* Expiry is enforced by a **real timer**, not only by traffic:
  * a full purge at startup, before the socket starts serving;
  * a daemon purge thread every `VEIL_PURGE_THREAD_INTERVAL` (60 s) while idle;
  * a throttled purge (`VEIL_PURGE_INTERVAL`, 5 s) at the start of every request.
* `purge_expired` deletes message rows past TTL (live payloads *and* dedup
  tombstones).
* Consumed one-time prekey tombstones are **never** purged: a prekey id that was
  handed out once must never be accepted again. The consequence is documented
  and intentional: `VEIL_MAX_STORED_PREKEYS` (400) counts available *and*
  consumed rows, so it is also the lifetime one-time-prekey budget of an
  account.
* SQLite runs in WAL with `synchronous=FULL`; message insert, prekey consumption,
  ACK and purge are explicit `BEGIN IMMEDIATE` transactions with bounded
  retry/backoff on `SQLITE_BUSY`. Connections are per operation, never shared
  across request threads.
* Schema version is tracked in `PRAGMA user_version` (currently `3`). A `v1`
  development database gains the fingerprint column on open; a `v2` database
  gains the unique `(recipient_uid, msg_id)` index. If a legacy database already
  contains duplicate inbox ids the upgrade **fails closed** with a clear error
  and deletes nothing.

## Operational notes

* **Loopback only.** Bind `127.0.0.1` and terminate TLS in a local Caddy. The
  guard exists because a public relay would be an abuse vector and this task
  authorizes no deployment.
* **Slow clients.** Each socket has a read/write timeout
  (`VEIL_REQUEST_TIMEOUT`, 20 s) and concurrent handler threads are capped
  (`VEIL_MAX_THREADS`, 64); excess connections are closed. The reverse proxy
  should also set `read_header_timeout`, `read_body_timeout` (or Caddy
  equivalents) and a small body limit — defense in depth, since a drip-feeding
  client can hold one slot for up to the timeout.
* **Rate limits are per process and in memory.** They reset on restart and do
  not coordinate across replicas; one loopback process is the supported shape.
* **No request logging.** Do not add middleware that logs bodies, tokens, paths
  with handles, or client IPs. If you need uptime metrics, count status codes
  only.
* **Backups** of the SQLite file contain ciphertext and public keys, not
  plaintext. Keep the file `0600` and treat it as sensitive metadata (who talks
  to whom, when).
* The relay necessarily learns sender UID, recipient UID, IP and timing. There
  is **no sealed-sender property** and none is claimed.

## Tests

Stdlib `unittest`, real HTTP over an ephemeral loopback port, real on-disk
SQLite per test:

```bash
cd server
python3 -m unittest discover -s tests -t . -v
```

Coverage includes: health/auth, strict registration and bundle validation,
handle/UUID normalisation, duplicate registration conflicts, directory lookup
and its rate limit, prekey depletion, re-upload of consumed ids (never reusable,
even after TTL), immutable bundle fields, concurrent one-time fetch (no reuse),
message send/pull with server-inferred sender, idempotent retries and mismatched
duplicates, retry after ACK, cross-sender inbox-id collisions (serial and
concurrent), ACK ownership and idempotency, mailbox cap, TTL purge on request /
at startup / by the idle timer, no plaintext persisted, body-limit and
Content-Length attacks, registration/lookup/send rate limits, invite codes,
private DB permissions, existing-directory mode preservation, symlinked DB
rejection, v2→v3 migration and fail-closed duplicate detection, and building +
running the root `dist/veil-relay.pyz` artifact.

`dist/veil-relay.pyz` (repo root) is a build output and is git-ignored; run
`python3 server/build_zipapp.py` to recreate it.

## Layout

```
server/
  veil_relay/
    __init__.py      version constants
    __main__.py      python3 -m veil_relay
    cli.py           argparse, signals, bind/announce
    config.py        env parsing + loopback guard + limits
    validation.py    strict JSON/base64/UUID/Signal-key validation
    db.py            SQLite schema, transactions, retries, permissions
    service.py       accounts, prekeys (atomic), messages, tombstone dedup, purge
    ratelimit.py     in-memory token buckets
    httpd.py         ThreadingHTTPServer, bounded bodies/threads, JSON errors
    app.py           routing, auth, quotas, purge scheduling
  tests/             integration + artifact tests (stdlib unittest)
  build_zipapp.py    creates <repo>/dist/veil-relay.pyz
```
