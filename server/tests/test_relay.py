"""End-to-end tests: real HTTP, real SQLite, ephemeral loopback port.

Run from ``server/``:

    python3 -m unittest discover -s tests -t . -v
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor

from tests.support import (
    Relay,
    b64,
    kyber_key,
    make_bundle,
    make_handle,
    new_uuid,
    parse_http_response,
    signal_key,
    signature,
)

TOKEN_LENGTH = 43
UNKNOWN_UUID = "6f1c9d2e-3b4a-4c5d-8e9f-0123456789ab"


class RelayTestCase(unittest.TestCase):
    ENV: dict[str, str] = {}

    def setUp(self) -> None:
        self.relay = Relay(self.ENV)
        self.addCleanup(self.relay.close)

    # -- helpers -------------------------------------------------------------

    def account(self, **kwargs):
        return self.relay.account(**kwargs)

    def send(
        self,
        sender: dict,
        recipient: dict,
        *,
        message_id: str | None = None,
        message_type: int = 2,
        ciphertext: str | None = None,
        extra: dict | None = None,
        token: str | None = None,
    ):
        message_id = message_id or new_uuid()
        ciphertext = ciphertext if ciphertext is not None else b64(os.urandom(96))
        body = {
            "id": message_id,
            "recipient_uid": recipient["uid"],
            "recipient_device_id": 1,
            "message_type": message_type,
            "ciphertext": ciphertext,
        }
        if extra:
            body.update(extra)
        status, payload, headers = self.relay.request(
            "POST", "/v1/messages", body, token=token or sender["token"]
        )
        return status, payload, message_id, ciphertext

    def pull(self, account: dict):
        status, payload, _ = self.relay.request(
            "GET", "/v1/messages", token=account["token"]
        )
        self.assertEqual(status, 200, payload)
        return payload["messages"]

    def ack(self, account: dict, ids: list[str]):
        return self.relay.request(
            "POST", "/v1/messages/ack", {"ids": ids}, token=account["token"]
        )


class HealthTests(RelayTestCase):
    def test_health_is_public_and_minimal(self) -> None:
        status, payload, headers = self.relay.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(payload, {"status": "ok", "version": "0.1.0"})
        self.assertIn("application/json", headers["content-type"])
        self.assertNotIn("python", headers.get("server", "").lower())


class RegistrationTests(RelayTestCase):
    def test_register_returns_account_and_stores_only_token_hash(self) -> None:
        status, payload, uid, bundle = self.relay.register(label="alice")
        self.assertEqual(status, 201, payload)
        self.assertEqual(payload["uid"], uid)
        self.assertEqual(set(payload), {"uid", "handle", "token"})
        token = payload["token"]
        self.assertEqual(len(token), TOKEN_LENGTH)
        self.assertRegex(token, r"^[A-Za-z0-9_-]{43}$")

        stored = self.relay.scalar(
            "SELECT token_hash FROM accounts WHERE uid = ?", (uid,)
        )
        self.assertEqual(stored, hashlib.sha256(token.encode()).digest())
        self.assertNotIn(token.encode(), self.relay.db_bytes())
        self.assertEqual(
            self.relay.scalar(
                "SELECT identity_key FROM accounts WHERE uid = ?", (uid,)
            ),
            bundle["identity_key"],
        )

    def test_register_normalizes_handle(self) -> None:
        status, payload, _, _ = self.relay.register(handle="@Alice_01")
        self.assertEqual(status, 201, payload)
        self.assertEqual(payload["handle"], "alice_01")

        status, payload, _ = self.relay.request(
            "GET", "/v1/directory/ALICE_01", token=payload["token"]
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["handle"], "alice_01")

    def test_register_rejects_bad_handles(self) -> None:
        for handle in ["ab", "a" * 25, "bad handle", "with-dash", "ümlaut", "", "!!!"]:
            with self.subTest(handle=handle):
                status, payload, _, _ = self.relay.register(handle=handle)
                self.assertEqual(status, 400, payload)
                self.assertIn("handle", payload["detail"])

    def test_register_rejects_bad_uuids(self) -> None:
        for uid in ["not-a-uuid", "00000000-0000-0000-0000-000000000000", "1234"]:
            with self.subTest(uid=uid):
                status, payload, _, _ = self.relay.register(uid=uid)
                self.assertEqual(status, 400, payload)
                self.assertIn("uid", payload["detail"])

    def test_register_rejects_invalid_bundles(self) -> None:
        def broken(mutator):
            bundle = copy.deepcopy(make_bundle(label="bad"))
            mutator(bundle)
            return bundle

        cases = {
            "identity too short": broken(
                lambda b: b.__setitem__("identity_key", b64(b"\x05" + b"\x00" * 31))
            ),
            "identity wrong type byte": broken(
                lambda b: b.__setitem__("identity_key", b64(b"\x04" + b"\x11" * 32))
            ),
            "identity bad base64": broken(
                lambda b: b.__setitem__("identity_key", "!!!!")
            ),
            "signed public too short": broken(
                lambda b: b["signed_prekey"].__setitem__("public_key", b64(b"\x05" * 32))
            ),
            "signed signature short": broken(
                lambda b: b["signed_prekey"].__setitem__("signature", b64(b"\x00" * 63))
            ),
            "kyber too short": broken(
                lambda b: b["kyber_prekey"].__setitem__("public_key", b64(b"\x00" * 100))
            ),
            "kyber too large": broken(
                lambda b: b["kyber_prekey"].__setitem__("public_key", b64(b"\x00" * 4096))
            ),
            "registration id zero": broken(
                lambda b: b.__setitem__("registration_id", 0)
            ),
            "registration id high": broken(
                lambda b: b.__setitem__("registration_id", 16381)
            ),
            "registration id bool": broken(
                lambda b: b.__setitem__("registration_id", True)
            ),
            "registration id string": broken(
                lambda b: b.__setitem__("registration_id", "1001")
            ),
            "device id two": broken(lambda b: b.__setitem__("device_id", 2)),
            "device id bool": broken(lambda b: b.__setitem__("device_id", True)),
            "duplicate otk ids": broken(
                lambda b: b["one_time_prekeys"].append(
                    {
                        "id": b["one_time_prekeys"][0]["id"],
                        "public_key": signal_key("bad", 7),
                    }
                )
            ),
            "otk bad key length": broken(
                lambda b: b["one_time_prekeys"][0].__setitem__(
                    "public_key", b64(b"\x05" * 32)
                )
            ),
            "missing signed prekey": broken(lambda b: b.pop("signed_prekey")),
            "missing kyber prekey": broken(lambda b: b.pop("kyber_prekey")),
        }
        for name, bundle in cases.items():
            with self.subTest(case=name):
                status, payload, _, _ = self.relay.register(bundle=bundle)
                self.assertEqual(status, 400, (name, payload))
                self.assertIsInstance(payload.get("detail"), str)

        status, payload, _ = self.relay.request(
            "POST",
            "/v1/register",
            {"uid": new_uuid(), "handle": make_handle(), "device_id": 1, "bundle": ["nope"]},
        )
        self.assertEqual(status, 400, payload)

    def test_register_rejects_too_many_one_time_prekeys(self) -> None:
        bundle = make_bundle(label="many", one_time=201)
        status, payload, _, _ = self.relay.register(bundle=bundle)
        self.assertEqual(status, 400, payload)
        self.assertIn("one_time_prekeys", payload["detail"])

    def test_register_conflicts(self) -> None:
        first = self.account()

        status, payload, _, _ = self.relay.register(
            uid=first["uid"], handle=make_handle()
        )
        self.assertEqual(status, 409, payload)
        self.assertIn("uid", payload["detail"])

        status, payload, _, _ = self.relay.register(handle=first["handle"])
        self.assertEqual(status, 409, payload)
        self.assertIn("handle", payload["detail"])

    def test_registration_body_limits(self) -> None:
        # Missing Content-Length.
        response = self.relay.raw_exchange(
            b"POST /v1/register HTTP/1.1\r\nHost: veil\r\nConnection: close\r\n\r\n{}"
        )
        status, _, body = parse_http_response(response)
        self.assertEqual(status, 400)
        self.assertIn("content-length", json.loads(body)["detail"])

        # Invalid Content-Length.
        response = self.relay.raw_exchange(
            b"POST /v1/register HTTP/1.1\r\nHost: veil\r\nContent-Length: abc\r\n\r\n"
        )
        status, _, body = parse_http_response(response)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(body)["detail"], "invalid content-length")

        # Duplicate Content-Length headers.
        response = self.relay.raw_exchange(
            b"POST /v1/register HTTP/1.1\r\nHost: veil\r\nContent-Length: 2\r\n"
            b"Content-Length: 2\r\n\r\n{}"
        )
        status, _, body = parse_http_response(response)
        self.assertEqual(status, 400)
        self.assertIn("content-length", json.loads(body)["detail"])

        # Chunked bodies are not accepted.
        response = self.relay.raw_exchange(
            b"POST /v1/register HTTP/1.1\r\nHost: veil\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        status, _, body = parse_http_response(response)
        self.assertEqual(status, 400)
        self.assertIn("chunked", json.loads(body)["detail"])

        # Declared body larger than the cap is refused without reading it.
        oversized = int(self.relay.cfg.max_body_bytes) + 1
        response = self.relay.raw_exchange(
            (
                f"POST /v1/register HTTP/1.1\r\nHost: veil\r\n"
                f"Content-Length: {oversized}\r\n\r\n{{}}"
            ).encode()
        )
        status, headers, body = parse_http_response(response)
        self.assertEqual(status, 413)
        self.assertEqual(json.loads(body)["detail"], "request body too large")
        self.assertEqual(headers.get("connection"), "close")

        # Truncated body.
        response = self.relay.raw_exchange(
            b"POST /v1/register HTTP/1.1\r\nHost: veil\r\nContent-Length: 100\r\n\r\n{}"
        )
        status, _, body = parse_http_response(response)
        self.assertEqual(status, 400)
        self.assertIn("incomplete", json.loads(body)["detail"])

    def test_invalid_json_bodies(self) -> None:
        for raw in [
            b"",
            b"not json",
            b"[]",
            b"{}",
            b'{"uid": "a", "uid": "b"}',
            b"NaN",
            b'{"uid": "\xff"}',
        ]:
            with self.subTest(raw=raw[:20]):
                status, payload, _ = self.relay.request(
                    "POST", "/v1/register", raw_body=raw
                )
                self.assertEqual(status, 400, payload)
                self.assertIsInstance(payload["detail"], str)
                self.assertNotIn("Traceback", payload["detail"])


class AuthAndDirectoryTests(RelayTestCase):
    def test_auth_required(self) -> None:
        account = self.account()
        cases = [
            ("GET", "/v1/messages", None, "missing bearer token"),
            ("GET", "/v1/messages", "short", "invalid bearer token"),
            ("GET", "/v1/messages", "A" * 43, "invalid bearer token"),
            ("GET", f"/v1/prekeys/{account['uid']}", "B" * 42 + "!", "invalid bearer token"),
            ("GET", "/v1/directory/someone", "C" * 43, "invalid bearer token"),
        ]
        for method, path, token, expected in cases:
            with self.subTest(path=path, token=token):
                status, payload, _ = self.relay.request(method, path, token=token)
                self.assertEqual(status, 401, payload)
                self.assertEqual(payload["detail"], expected)

        status, payload, _ = self.relay.request(
            "GET", "/v1/messages", headers={"Authorization": "Basic abcdef"}
        )
        self.assertEqual(status, 401, payload)
        self.assertEqual(payload["detail"], "invalid authorization header")

        status, payload, _ = self.relay.request(
            "GET", "/v1/messages", token=account["token"]
        )
        self.assertEqual(status, 200, payload)

    def test_directory_lookup(self) -> None:
        target = self.account(handle="alice_01")
        caller = self.account()
        status, payload, _ = self.relay.request(
            "GET", "/v1/directory/alice_01", token=caller["token"]
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(
            payload,
            {
                "uid": target["uid"],
                "handle": "alice_01",
                "device_id": 1,
                "identity_key": target["bundle"]["identity_key"],
            },
        )

        status, payload, _ = self.relay.request(
            "GET", "/v1/directory/nobody_here", token=caller["token"]
        )
        self.assertEqual(status, 404, payload)

        status, payload, _ = self.relay.request(
            "GET", "/v1/directory/bad-handle!", token=caller["token"]
        )
        self.assertEqual(status, 400, payload)

        status, payload, _ = self.relay.request(
            "GET", "/v1/directory/a/b", token=caller["token"]
        )
        self.assertEqual(status, 404, payload)


class DirectoryRateLimitTests(RelayTestCase):
    ENV = {
        "VEIL_RL_DIRECTORY_PER_MIN": "1",
        "VEIL_RL_DIRECTORY_BURST": "1",
    }

    def test_directory_is_rate_limited(self) -> None:
        self.account(handle="rate_limited")
        caller = self.account()
        first = self.relay.request(
            "GET", "/v1/directory/rate_limited", token=caller["token"]
        )
        second = self.relay.request(
            "GET", "/v1/directory/rate_limited", token=caller["token"]
        )
        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 429)
        self.assertGreaterEqual(int(second[2]["retry-after"]), 1)
        self.assertEqual(second[1], {"detail": "rate limit exceeded"})


class PrekeyTests(RelayTestCase):
    def test_fetch_consumes_one_key_at_a_time(self) -> None:
        bundle = make_bundle(label="bob", one_time=3, start_id=1)
        bob = self.account(bundle=bundle)
        caller = self.account()

        seen: list[int] = []
        for expected_id in (1, 2, 3):
            status, payload, _ = self.relay.request(
                "GET", f"/v1/prekeys/{bob['uid']}", token=caller["token"]
            )
            self.assertEqual(status, 200, payload)
            self.assertEqual(payload["registration_id"], bundle["registration_id"])
            self.assertEqual(payload["identity_key"], bundle["identity_key"])
            self.assertEqual(payload["signed_prekey"], bundle["signed_prekey"])
            self.assertEqual(payload["kyber_prekey"], bundle["kyber_prekey"])
            self.assertEqual(len(payload["one_time_prekeys"]), 1)
            key_id = payload["one_time_prekeys"][0]["id"]
            self.assertEqual(key_id, expected_id)
            seen.append(key_id)

        # Depleted: bundle still returned, one_time_prekeys empty.
        status, payload, _ = self.relay.request(
            "GET", f"/v1/prekeys/{bob['uid']}", token=caller["token"]
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["one_time_prekeys"], [])
        self.assertEqual(len(seen), 3)
        self.assertEqual(
            self.relay.scalar(
                "SELECT COUNT(*) FROM one_time_prekeys "
                "WHERE uid = ? AND consumed_at IS NOT NULL",
                (bob["uid"],),
            ),
            3,
        )

    def test_fetch_unknown_or_invalid_uid(self) -> None:
        caller = self.account()
        status, payload, _ = self.relay.request(
            "GET", f"/v1/prekeys/{UNKNOWN_UUID}", token=caller["token"]
        )
        self.assertEqual(status, 404, payload)
        status, payload, _ = self.relay.request(
            "GET", "/v1/prekeys/not-a-uuid", token=caller["token"]
        )
        self.assertEqual(status, 400, payload)

    def test_concurrent_fetch_never_reuses_a_prekey(self) -> None:
        bundle = make_bundle(label="carol", one_time=10, start_id=1)
        carol = self.account(bundle=bundle)
        caller = self.account()

        def fetch(_: int):
            status, payload, _ = self.relay.request(
                "GET", f"/v1/prekeys/{carol['uid']}", token=caller["token"]
            )
            return status, payload

        with ThreadPoolExecutor(max_workers=10) as pool:
            results = list(pool.map(fetch, range(10)))

        ids: list[int] = []
        for status, payload in results:
            self.assertEqual(status, 200, payload)
            self.assertEqual(len(payload["one_time_prekeys"]), 1, payload)
            ids.append(payload["one_time_prekeys"][0]["id"])

        self.assertEqual(sorted(ids), list(range(1, 11)))
        self.assertEqual(len(set(ids)), 10)
        self.assertEqual(
            self.relay.scalar(
                "SELECT COUNT(*) FROM one_time_prekeys "
                "WHERE uid = ? AND consumed_at IS NOT NULL",
                (carol["uid"],),
            ),
            10,
        )

    def test_refill_merges_and_rejects_consumed_or_changed_keys(self) -> None:
        original = make_bundle(label="dave", one_time=3, start_id=1)
        dave = self.account(bundle=original)

        status, payload, _ = self.relay.request(
            "GET", f"/v1/prekeys/{dave['uid']}", token=dave["token"]
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["one_time_prekeys"][0]["id"], 1)

        # Re-upload of a consumed id must be refused (replay protection).
        consumed = make_bundle(label="dave", one_time=1, start_id=1)
        status, payload, _ = self.relay.request(
            "PUT", "/v1/prekeys", consumed, token=dave["token"]
        )
        self.assertEqual(status, 409, payload)
        self.assertIn("consumed", payload["detail"])

        # Merge: 2 and 3 already exist unconsumed (idempotent), 4 is new.
        refill = make_bundle(label="dave", one_time=3, start_id=2)
        status, payload, _ = self.relay.request(
            "PUT", "/v1/prekeys", refill, token=dave["token"]
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload, {"ok": True})
        status, payload, _ = self.relay.request(
            "PUT", "/v1/prekeys", refill, token=dave["token"]
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(
            self.relay.scalar(
                "SELECT COUNT(*) FROM one_time_prekeys WHERE uid = ?", (dave["uid"],)
            ),
            4,
        )

        # Identity / registration id / signed / kyber changes are rejected.
        mutations = []

        changed_identity = copy.deepcopy(refill)
        changed_identity["identity_key"] = signal_key("eve", 0)
        mutations.append(("identity_key", changed_identity))

        changed_registration = copy.deepcopy(refill)
        changed_registration["registration_id"] = 4242
        mutations.append(("registration_id", changed_registration))

        changed_signed = copy.deepcopy(refill)
        changed_signed["signed_prekey"]["signature"] = signature("eve", 5)
        mutations.append(("signed_prekey", changed_signed))

        changed_kyber = copy.deepcopy(refill)
        changed_kyber["kyber_prekey"]["public_key"] = kyber_key("eve", 5)
        mutations.append(("kyber_prekey", changed_kyber))

        for field, mutated in mutations:
            with self.subTest(field=field):
                status, payload, _ = self.relay.request(
                    "PUT", "/v1/prekeys", mutated, token=dave["token"]
                )
                self.assertEqual(status, 409, payload)
                self.assertIn(field, payload["detail"])

        status, payload, _ = self.relay.request("PUT", "/v1/prekeys", refill)
        self.assertEqual(status, 401, payload)


class PrekeyQuotaTests(RelayTestCase):
    ENV = {
        "VEIL_MAX_OTK_PER_BUNDLE": "5",
        "VEIL_MAX_STORED_PREKEYS": "5",
    }

    def test_prekey_quota(self) -> None:
        bundle = make_bundle(label="quota", one_time=5, start_id=1)
        account = self.account(bundle=bundle)
        extra = make_bundle(label="quota", one_time=1, start_id=100)
        status, payload, _ = self.relay.request(
            "PUT", "/v1/prekeys", extra, token=account["token"]
        )
        self.assertEqual(status, 429, payload)
        self.assertIn("quota", payload["detail"])


class MessageTests(RelayTestCase):
    def test_send_and_pull_with_inferred_sender(self) -> None:
        alice = self.account()
        bob = self.account()

        status, payload, message_id, ciphertext = self.send(
            alice,
            bob,
            message_type=3,
            extra={"sender_uid": bob["uid"], "sender_device_id": 9, "text": "hello"},
        )
        self.assertEqual(status, 202, payload)
        self.assertEqual(payload, {"id": message_id, "accepted": True})

        inbox = self.pull(bob)
        self.assertEqual(len(inbox), 1)
        message = inbox[0]
        self.assertEqual(
            set(message),
            {
                "id",
                "sender_uid",
                "sender_device_id",
                "recipient_uid",
                "recipient_device_id",
                "message_type",
                "ciphertext",
                "created_at",
            },
        )
        self.assertEqual(message["id"], message_id)
        # Sender comes from the bearer token, never from the body.
        self.assertEqual(message["sender_uid"], alice["uid"])
        self.assertEqual(message["sender_device_id"], 1)
        self.assertEqual(message["recipient_uid"], bob["uid"])
        self.assertEqual(message["recipient_device_id"], 1)
        self.assertEqual(message["message_type"], 3)
        self.assertEqual(message["ciphertext"], ciphertext)
        self.assertIsInstance(message["created_at"], int)

        self.assertEqual(self.pull(alice), [])

    def test_message_validation(self) -> None:
        alice = self.account()
        bob = self.account()

        base = {
            "id": new_uuid(),
            "recipient_uid": bob["uid"],
            "recipient_device_id": 1,
            "message_type": 2,
            "ciphertext": b64(b"payload"),
        }

        def send_variant(**changes):
            body = dict(base)
            body.update(changes)
            return self.relay.request(
                "POST", "/v1/messages", body, token=alice["token"]
            )

        for message_type in (0, 1, 4, 255):
            with self.subTest(message_type=message_type):
                status, payload, _ = send_variant(message_type=message_type)
                self.assertEqual(status, 400, payload)

        status, payload, _ = send_variant(recipient_uid=UNKNOWN_UUID)
        self.assertEqual(status, 404, payload)

        status, payload, _ = send_variant(id="not-a-uuid")
        self.assertEqual(status, 400, payload)

        status, payload, _ = send_variant(recipient_device_id=2)
        self.assertEqual(status, 400, payload)

        for ciphertext in ("!!!!", "", "AAA", "AB==", "a" * 5):
            with self.subTest(ciphertext=ciphertext[:12]):
                status, payload, _ = send_variant(ciphertext=ciphertext)
                self.assertEqual(status, 400, payload)

        status, payload, _ = send_variant(ciphertext=b64(os.urandom(70000)))
        self.assertEqual(status, 413, payload)

        status, payload, _ = self.relay.request(
            "POST", "/v1/messages", {"id": new_uuid()}, token=alice["token"]
        )
        self.assertEqual(status, 400, payload)
        self.assertIn("recipient_uid", payload["detail"])

        # Boundary: the maximum ciphertext size is accepted.
        status, payload, _, _ = self.send(
            alice,
            bob,
            ciphertext=b64(os.urandom(self.relay.cfg.max_ciphertext_bytes)),
        )
        self.assertEqual(status, 202, payload)

    def test_idempotent_retry_and_mismatch(self) -> None:
        alice = self.account()
        bob = self.account()
        carol = self.account()

        status, payload, message_id, ciphertext = self.send(alice, bob)
        self.assertEqual(status, 202)

        status, payload, _, _ = self.send(
            alice, bob, message_id=message_id, ciphertext=ciphertext
        )
        self.assertEqual(status, 202, payload)
        self.assertEqual(
            self.relay.scalar(
                "SELECT COUNT(*) FROM messages WHERE sender_uid = ? AND msg_id = ?",
                (alice["uid"], message_id),
            ),
            1,
        )

        status, payload, _, _ = self.send(
            alice, bob, message_id=message_id, ciphertext=b64(b"different")
        )
        self.assertEqual(status, 409, payload)

        status, payload, _, _ = self.send(alice, carol, message_id=message_id)
        self.assertEqual(status, 409, payload)

        status, payload, _, _ = self.send(
            alice, bob, message_id=message_id, message_type=3
        )
        self.assertEqual(status, 409, payload)

    def test_ack_purges_ciphertext_but_retry_succeeds(self) -> None:
        alice = self.account()
        bob = self.account()

        status, _, message_id, ciphertext = self.send(alice, bob)
        self.assertEqual(status, 202)

        status, payload, _ = self.ack(bob, [message_id])
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload, {"ok": True})
        self.assertEqual(self.pull(bob), [])

        rows = self.relay.sql(
            "SELECT ciphertext, acked_at FROM messages WHERE msg_id = ?", (message_id,)
        )
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["ciphertext"])
        self.assertIsNotNone(rows[0]["acked_at"])

        # Retry after ACK is accepted (durable tombstone) and does not reappear.
        status, payload, _, _ = self.send(
            alice, bob, message_id=message_id, ciphertext=ciphertext
        )
        self.assertEqual(status, 202, payload)
        self.assertEqual(self.pull(bob), [])

        # A mismatched retry is still rejected: the tombstone keeps a SHA-256
        # fingerprint of the purged ciphertext.
        status, payload, _, _ = self.send(
            alice, bob, message_id=message_id, ciphertext=b64(b"other payload")
        )
        self.assertEqual(status, 409, payload)

        # Acknowledgement is idempotent.
        status, payload, _ = self.ack(bob, [message_id])
        self.assertEqual(status, 200, payload)

    def test_ack_only_touches_own_inbox(self) -> None:
        alice = self.account()
        bob = self.account()
        carol = self.account()

        _, _, bob_message_id, _ = self.send(alice, bob)
        _, _, carol_message_id, _ = self.send(alice, carol)

        status, payload, _ = self.ack(bob, [carol_message_id, UNKNOWN_UUID])
        self.assertEqual(status, 200, payload)

        self.assertEqual(len(self.pull(carol)), 1)
        self.assertEqual(len(self.pull(bob)), 1)

        rows = self.relay.sql(
            "SELECT ciphertext FROM messages WHERE msg_id = ?", (carol_message_id,)
        )
        self.assertIsNotNone(rows[0]["ciphertext"])

        status, payload, _ = self.ack(carol, [bob_message_id])
        self.assertEqual(status, 200, payload)
        self.assertEqual(len(self.pull(bob)), 1)

    def test_message_id_is_unique_per_recipient_mailbox(self) -> None:
        alice = self.account()
        carol = self.account()
        bob = self.account()
        dave = self.account()

        shared_id = new_uuid()
        status, payload, _, _ = self.send(alice, bob, message_id=shared_id)
        self.assertEqual(status, 202, payload)

        # A different sender reusing the id in the same mailbox is a conflict,
        # reported with the same generic detail (no envelope data leaked).
        status, payload, _, _ = self.send(carol, bob, message_id=shared_id)
        self.assertEqual(status, 409, payload)
        self.assertEqual(payload, {"detail": "message id conflict"})

        # The mailbox still holds exactly one envelope, owned by alice.
        inbox = self.pull(bob)
        self.assertEqual(len(inbox), 1)
        self.assertEqual(inbox[0]["sender_uid"], alice["uid"])

        # ACK never removes two envelopes for one id: carol can ACK that id but
        # only alice's inbox-owned row is affected (and it is bob's inbox).
        status, payload, _ = self.ack(bob, [shared_id])
        self.assertEqual(status, 200, payload)
        self.assertEqual(self.pull(bob), [])

        # The tombstone still reserves the id for that mailbox.
        status, payload, _, _ = self.send(carol, bob, message_id=shared_id)
        self.assertEqual(status, 409, payload)

        # Same id in a different mailbox is independent.
        status, payload, _, _ = self.send(carol, dave, message_id=shared_id)
        self.assertEqual(status, 202, payload)
        status, payload, _, _ = self.send(alice, dave, message_id=shared_id)
        self.assertEqual(status, 409, payload)
        self.assertEqual(self.pull(dave)[0]["sender_uid"], carol["uid"])

        # A sender still cannot reuse its own id for another recipient.
        status, payload, _, _ = self.send(alice, dave, message_id=new_uuid())
        self.assertEqual(status, 202, payload)

    def test_message_id_collision_is_atomic_under_concurrency(self) -> None:
        bob = self.account()
        senders = [self.account() for _ in range(6)]
        shared_id = new_uuid()
        bodies = [
            {
                "id": shared_id,
                "recipient_uid": bob["uid"],
                "recipient_device_id": 1,
                "message_type": 2,
                "ciphertext": b64(os.urandom(32)),
            }
            for _ in senders
        ]

        def send_one(pair):
            sender, body = pair
            return self.relay.request(
                "POST", "/v1/messages", body, token=sender["token"]
            )[0]

        with ThreadPoolExecutor(max_workers=len(senders)) as pool:
            statuses = list(pool.map(send_one, zip(senders, bodies)))

        self.assertEqual(statuses.count(202), 1, statuses)
        self.assertEqual(statuses.count(409), len(senders) - 1, statuses)
        self.assertEqual(len(self.pull(bob)), 1)

    def test_ack_validation(self) -> None:
        bob = self.account()
        for body in [{"ids": "nope"}, {"ids": [1]}, {"ids": ["not-a-uuid"]}]:
            with self.subTest(body=str(body)[:40]):
                status, payload, _ = self.relay.request(
                    "POST", "/v1/messages/ack", body, token=bob["token"]
                )
                self.assertEqual(status, 400, payload)

        # Unknown but well-formed ids are silently ignored (no existence leak).
        status, payload, _ = self.ack(bob, [UNKNOWN_UUID, UNKNOWN_UUID])
        self.assertEqual(status, 200, payload)

        # An empty batch is a no-op.
        status, payload, _ = self.ack(bob, [])
        self.assertEqual(status, 200, payload)

    def test_messages_are_not_stored_in_plaintext(self) -> None:
        alice = self.account()
        bob = self.account()
        marker = "PLAINTEXT-MARKER-9f8e7d"
        plaintext = b"the quick brown fox " + marker.encode()
        status, payload, message_id, ciphertext = self.send(
            alice,
            bob,
            ciphertext=b64(plaintext),
            extra={"text": marker, "plaintext": marker},
        )
        self.assertEqual(status, 202, payload)

        inbox = self.pull(bob)
        self.assertNotIn("text", inbox[0])
        self.assertNotIn("plaintext", inbox[0])
        self.assertEqual(inbox[0]["ciphertext"], ciphertext)

        # The extra plaintext field is ignored, and the raw plaintext is never
        # persisted (only the base64 ciphertext is).
        self.assertNotIn(marker.encode(), self.relay.db_bytes())
        self.assertNotIn(b"quick brown fox", self.relay.db_bytes())

    def test_concurrent_sends_from_many_senders(self) -> None:
        bob = self.account()
        senders = [self.account() for _ in range(12)]
        bodies = [
            {
                "id": new_uuid(),
                "recipient_uid": bob["uid"],
                "recipient_device_id": 1,
                "message_type": 2,
                "ciphertext": b64(os.urandom(48)),
            }
            for _ in senders
        ]

        def send_one(pair):
            sender, body = pair
            return self.relay.request(
                "POST", "/v1/messages", body, token=sender["token"]
            )[0]

        with ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(send_one, zip(senders, bodies)))

        self.assertEqual(statuses, [202] * len(bodies))
        inbox = self.pull(bob)
        self.assertEqual(len(inbox), len(bodies))
        self.assertEqual({m["id"] for m in inbox}, {b["id"] for b in bodies})


class MessageLimitTests(RelayTestCase):
    ENV = {
        "VEIL_MAX_PULL": "2",
        "VEIL_MAX_ACK_IDS": "2",
        "VEIL_MAX_MAILBOX": "3",
    }

    def test_pull_is_oldest_first_and_bounded(self) -> None:
        alice = self.account()
        bob = self.account()
        ids = []
        for _ in range(3):
            status, _, message_id, _ = self.send(alice, bob)
            self.assertEqual(status, 202)
            ids.append(message_id)

        status, payload, _ = self.relay.request(
            "GET", "/v1/messages", token=bob["token"]
        )
        self.assertEqual(status, 200)
        self.assertEqual([m["id"] for m in payload["messages"]], ids[:2])

    def test_pull_and_ack_bounds(self) -> None:
        alice = self.account()
        bob = self.account()
        ids = [self.send(alice, bob)[2] for _ in range(3)]
        self.assertEqual(len(self.pull(bob)), 2)

        status, payload, _ = self.ack(bob, ids)
        self.assertEqual(status, 400, payload)
        self.assertIn("ids", payload["detail"])

        status, payload, _ = self.ack(bob, ids[:2])
        self.assertEqual(status, 200, payload)


class MailboxCapTests(RelayTestCase):
    ENV = {"VEIL_MAX_MAILBOX": "2"}

    def test_mailbox_cap(self) -> None:
        alice = self.account()
        bob = self.account()
        self.assertEqual(self.send(alice, bob)[0], 202)
        self.assertEqual(self.send(alice, bob)[0], 202)
        status, payload, _, _ = self.send(alice, bob)
        self.assertEqual(status, 429, payload)
        self.assertIn("mailbox", payload["detail"])

        inbox = self.pull(bob)
        status, payload, _ = self.ack(bob, [inbox[0]["id"]])
        self.assertEqual(status, 200, payload)
        # The ACK freed a slot.
        self.assertEqual(self.send(alice, bob)[0], 202)


class RateLimitTests(RelayTestCase):
    ENV = {
        "VEIL_RL_REGISTER_PER_MIN": "1",
        "VEIL_RL_REGISTER_BURST": "2",
        "VEIL_RL_MESSAGES_SEND_PER_MIN": "1",
        "VEIL_RL_MESSAGES_SEND_BURST": "2",
    }

    def test_registration_rate_limit(self) -> None:
        self.assertEqual(self.relay.register()[0], 201)
        self.assertEqual(self.relay.register()[0], 201)
        status, payload, headers = self.relay.request(
            "POST",
            "/v1/register",
            {
                "uid": new_uuid(),
                "handle": make_handle(),
                "device_id": 1,
                "bundle": make_bundle(label="limited"),
            },
        )
        self.assertEqual(status, 429, payload)
        self.assertEqual(payload["detail"], "rate limit exceeded")
        self.assertGreaterEqual(int(headers["retry-after"]), 1)

    def test_send_is_rate_limited(self) -> None:
        alice = self.account()
        bob = self.account()
        self.assertEqual(self.send(alice, bob)[0], 202)
        self.assertEqual(self.send(alice, bob)[0], 202)
        body = {
            "id": new_uuid(),
            "recipient_uid": bob["uid"],
            "recipient_device_id": 1,
            "message_type": 2,
            "ciphertext": b64(os.urandom(32)),
        }
        status, payload, headers = self.relay.request(
            "POST", "/v1/messages", body, token=alice["token"]
        )
        self.assertEqual(status, 429, payload)
        self.assertGreaterEqual(int(headers["retry-after"]), 1)


class InviteTests(RelayTestCase):
    ENV = {"VEIL_INVITE_CODE": "let-me-in"}

    def test_invite_code_required_when_configured(self) -> None:
        status, payload, _, _ = self.relay.register()
        self.assertEqual(status, 401, payload)
        self.assertEqual(payload["detail"], "invalid invite code")

        status, payload, _, _ = self.relay.register(invite_code="wrong")
        self.assertEqual(status, 401, payload)

        status, payload, _, _ = self.relay.register(invite_code="ünïcode")
        self.assertEqual(status, 401, payload)

        status, payload, _, _ = self.relay.register(invite_code="let-me-in")
        self.assertEqual(status, 201, payload)

        # Public health stays reachable without an invite.
        self.assertEqual(self.relay.request("GET", "/health")[0], 200)


class ExpiryTests(RelayTestCase):
    def test_request_purge_removes_expired_payload_and_tombstone(self) -> None:
        alice = self.account()
        bob = self.account()

        _, _, live_id, _ = self.send(alice, bob)
        _, _, acked_id, _ = self.send(alice, bob)
        status, _, _ = self.ack(bob, [acked_id])
        self.assertEqual(status, 200)

        self.assertEqual(self.pull(bob)[0]["id"], live_id)

        past = int(time.time()) - 1
        self.relay.sql("UPDATE messages SET expires_at = ?", (past,))
        # Any request (even /health) triggers the throttled purge.
        self.assertEqual(self.relay.request("GET", "/health")[0], 200)

        self.assertEqual(self.relay.scalar("SELECT COUNT(*) FROM messages"), 0)
        self.assertEqual(self.pull(bob), [])

    def test_startup_purge_runs_without_traffic(self) -> None:
        alice = self.account()
        bob = self.account()
        _, _, message_id, _ = self.send(alice, bob)
        past = int(time.time()) - 1
        self.relay.sql("UPDATE messages SET expires_at = ?", (past,))

        # A fresh App on the same database purges during start(), before any
        # request is served.
        from veil_relay.app import App
        from veil_relay.db import Database

        fresh_db = Database(self.relay.cfg.db_path)
        fresh_app = App(self.relay.cfg, fresh_db)
        try:
            fresh_app.start()
            self.assertEqual(
                self.relay.scalar(
                    "SELECT COUNT(*) FROM messages WHERE msg_id = ?", (message_id,)
                ),
                0,
            )
        finally:
            fresh_app.stop()

    def test_consumed_prekeys_are_never_purged_or_reused(self) -> None:
        caller = self.account()
        bob = self.account(bundle=make_bundle(label="bob", one_time=1, start_id=1))
        status, payload, _ = self.relay.request(
            "GET", f"/v1/prekeys/{bob['uid']}", token=caller["token"]
        )
        self.assertEqual(status, 200)
        self.assertEqual(payload["one_time_prekeys"][0]["id"], 1)

        # Age the consumption past the TTL and run a purge.
        self.relay.sql(
            "UPDATE one_time_prekeys SET consumed_at = ? WHERE uid = ?",
            (int(time.time()) - self.relay.cfg.ttl_seconds - 1, bob["uid"]),
        )
        self.assertEqual(self.relay.request("GET", "/health")[0], 200)
        self.assertEqual(self.relay.app.purge_now(), 0)

        # The tombstone survives, so the id can never be handed out or uploaded
        # again (no prekey reuse, ever).
        self.assertEqual(
            self.relay.scalar(
                "SELECT COUNT(*) FROM one_time_prekeys WHERE uid = ?", (bob["uid"],)
            ),
            1,
        )
        status, payload, _ = self.relay.request(
            "PUT",
            "/v1/prekeys",
            make_bundle(label="bob", one_time=1, start_id=1),
            token=bob["token"],
        )
        self.assertEqual(status, 409, payload)
        self.assertIn("consumed", payload["detail"])


class IdlePurgeTests(RelayTestCase):
    ENV = {"VEIL_PURGE_THREAD_INTERVAL": "1"}

    def test_timer_purges_without_requests(self) -> None:
        alice = self.account()
        bob = self.account()
        _, _, message_id, _ = self.send(alice, bob)
        self.relay.sql(
            "UPDATE messages SET expires_at = ? WHERE msg_id = ?",
            (int(time.time()) - 1, message_id),
        )

        deadline = time.monotonic() + 6.0
        remaining = 1
        while time.monotonic() < deadline:
            remaining = self.relay.scalar(
                "SELECT COUNT(*) FROM messages WHERE msg_id = ?", (message_id,)
            )
            if remaining == 0:
                break
            time.sleep(0.1)
        self.assertEqual(remaining, 0, "idle purge timer did not fire")


class ErrorContractTests(RelayTestCase):
    def test_unknown_routes_and_methods(self) -> None:
        account = self.account()

        status, payload, _ = self.relay.request(
            "GET", "/v1/nope", token=account["token"]
        )
        self.assertEqual(status, 404, payload)
        self.assertEqual(payload, {"detail": "not found"})

        status, payload, headers = self.relay.request(
            "GET", "/v1/messages/ack", token=account["token"]
        )
        self.assertEqual(status, 405, payload)
        self.assertEqual(headers["allow"], "POST")

        status, payload, headers = self.relay.request(
            "DELETE", "/v1/messages", token=account["token"]
        )
        self.assertEqual(status, 405, payload)
        self.assertIn("GET", headers["allow"])

        status, payload, headers = self.relay.request("POST", "/health")
        self.assertEqual(status, 405, payload)
        self.assertEqual(headers["allow"], "GET")

        # Unknown HTTP verb reaches BaseHTTPRequestHandler's error path, JSON.
        response = self.relay.raw_exchange(
            b"BREW /health HTTP/1.1\r\nHost: veil\r\n\r\n"
        )
        status, _, body = parse_http_response(response)
        self.assertIn(status, (405, 501))
        self.assertIsInstance(json.loads(body)["detail"], str)

        # No traceback text ever reaches the client.
        self.assertNotIn("Traceback", json.dumps(payload))
        self.assertNotIn(b"Traceback", body)

    def test_response_headers_are_safe(self) -> None:
        account = self.account()
        status, payload, headers = self.relay.request(
            "GET", "/v1/messages", token=account["token"]
        )
        self.assertEqual(status, 200, payload)
        self.assertEqual(headers.get("cache-control"), "no-store")
        self.assertEqual(headers.get("x-content-type-options"), "nosniff")


class ConfigTests(unittest.TestCase):
    def test_loopback_is_the_default_and_required(self) -> None:
        from veil_relay.config import from_env

        cfg = from_env({"HOME": "/tmp"})
        self.assertEqual(cfg.host, "127.0.0.1")
        self.assertEqual(cfg.port, 8787)
        self.assertEqual(cfg.ttl_seconds, 30 * 86400)
        self.assertIn("veil-relay", cfg.db_path)

        with self.assertRaises(ValueError):
            from_env({"VEIL_HOST": "0.0.0.0", "HOME": "/tmp"})
        with self.assertRaises(ValueError):
            from_env({"VEIL_HOST": "192.168.1.10", "HOME": "/tmp"})

        allowed = from_env(
            {
                "VEIL_HOST": "0.0.0.0",
                "VEIL_ALLOW_NON_LOOPBACK": "1",
                "HOME": "/tmp",
            }
        )
        self.assertEqual(allowed.host, "0.0.0.0")

    def test_invalid_values_are_rejected(self) -> None:
        from veil_relay.config import from_env

        for env in [
            {"VEIL_PORT": "70000"},
            {"VEIL_PORT": "abc"},
            {"VEIL_TTL_DAYS": "0"},
            {"VEIL_MAX_BODY_BYTES": "10"},
            {"VEIL_RL_REGISTER_BURST": "0"},
            {"VEIL_INVITE_CODE": "x" * 300},
            {"VEIL_MAX_THREADS": "1"},
        ]:
            with self.subTest(env=env):
                with self.assertRaises(ValueError):
                    from_env({**env, "HOME": "/tmp"})


class StoragePrivacyTests(RelayTestCase):
    def test_database_permissions_are_private(self) -> None:
        path = self.relay.db.path
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(path)).st_mode & 0o777, 0o700)

    def test_database_is_sqlite_and_has_no_plaintext_columns(self) -> None:
        with open(self.relay.db.path, "rb") as handle:
            self.assertEqual(handle.read(16), b"SQLite format 3\x00")
        columns = {
            row["name"] for row in self.relay.sql("PRAGMA table_info(messages)")
        }
        self.assertEqual(
            columns,
            {
                "sender_uid",
                "msg_id",
                "recipient_uid",
                "message_type",
                "ciphertext",
                "ciphertext_sha256",
                "created_at",
                "expires_at",
                "acked_at",
            },
        )
        indexes = {
            row["name"]: int(row["unique"])
            for row in self.relay.sql("PRAGMA index_list(messages)")
        }
        self.assertIn("messages_recipient_msg", indexes)
        self.assertEqual(indexes["messages_recipient_msg"], 1)


V2_SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    uid TEXT PRIMARY KEY,
    handle TEXT,
    device_id INTEGER,
    token_hash BLOB,
    registration_id INTEGER,
    identity_key TEXT,
    signed_prekey_id INTEGER,
    signed_prekey_public TEXT,
    signed_prekey_sig TEXT,
    kyber_prekey_id INTEGER,
    kyber_prekey_public TEXT,
    kyber_prekey_sig TEXT,
    created_at INTEGER
);
CREATE TABLE IF NOT EXISTS one_time_prekeys (
    uid TEXT,
    key_id INTEGER,
    public_key TEXT,
    created_at INTEGER,
    consumed_at INTEGER,
    PRIMARY KEY (uid, key_id)
);
CREATE TABLE IF NOT EXISTS messages (
    sender_uid TEXT,
    msg_id TEXT,
    recipient_uid TEXT,
    message_type INTEGER,
    ciphertext TEXT,
    ciphertext_sha256 BLOB,
    created_at INTEGER,
    expires_at INTEGER,
    acked_at INTEGER,
    PRIMARY KEY (sender_uid, msg_id)
);
PRAGMA user_version=2;
"""


class DatabasePathTests(unittest.TestCase):
    """The DB file is private, but pre-existing directories are never touched."""

    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="veil-db-path-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_existing_shared_parent_keeps_its_mode(self) -> None:
        from veil_relay.db import Database

        shared = os.path.join(self.root, "shared")
        os.mkdir(shared, 0o700)
        os.chmod(shared, 0o755)
        warnings: list[str] = []

        db = Database(os.path.join(shared, "relay.sqlite3"), warn=warnings.append)

        self.assertEqual(stat.S_IMODE(os.stat(shared).st_mode), 0o755)
        self.assertEqual(stat.S_IMODE(os.stat(db.path).st_mode), 0o600)
        self.assertEqual(len(warnings), 1)
        self.assertIn("accessible by other users", warnings[0])
        with db.connection() as connection:
            self.assertEqual(connection.execute("SELECT 1").fetchone()[0], 1)

    def test_existing_private_parent_is_quiet(self) -> None:
        from veil_relay.db import Database

        private = os.path.join(self.root, "private")
        os.mkdir(private, 0o700)
        warnings: list[str] = []
        db = Database(os.path.join(private, "relay.sqlite3"), warn=warnings.append)
        self.assertEqual(stat.S_IMODE(os.stat(private).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(db.path).st_mode), 0o600)
        self.assertEqual(warnings, [])

    def test_new_parents_are_created_0700(self) -> None:
        from veil_relay.db import Database

        target = os.path.join(self.root, "fresh", "nested", "relay.sqlite3")
        warnings: list[str] = []
        db = Database(target, warn=warnings.append)
        self.assertEqual(
            stat.S_IMODE(os.stat(os.path.dirname(db.path)).st_mode), 0o700
        )
        self.assertEqual(stat.S_IMODE(os.stat(db.path).st_mode), 0o600)
        self.assertEqual(warnings, [])

    def test_symlinked_parent_is_allowed_and_untouched(self) -> None:
        from veil_relay.db import Database

        real_dir = os.path.join(self.root, "real-data")
        os.mkdir(real_dir, 0o700)
        link_dir = os.path.join(self.root, "linked-data")
        os.symlink(real_dir, link_dir)

        db = Database(os.path.join(link_dir, "relay.sqlite3"), warn=lambda _: None)
        self.assertEqual(stat.S_IMODE(os.stat(real_dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(db.path).st_mode), 0o600)

    def test_symlinked_database_file_is_rejected_untouched(self) -> None:
        from veil_relay.db import Database

        real = os.path.join(self.root, "unrelated.sqlite3")
        with open(real, "wb") as handle:
            handle.write(b"unrelated file")
        os.chmod(real, 0o644)
        link = os.path.join(self.root, "relay.sqlite3")
        os.symlink(real, link)

        with self.assertRaises(RuntimeError) as caught:
            Database(link, warn=lambda _: None)
        self.assertIn("symlink", str(caught.exception))
        # The chmod must never have followed the link to the unrelated file.
        self.assertEqual(stat.S_IMODE(os.stat(real).st_mode), 0o644)
        self.assertTrue(os.path.islink(link))


class SchemaMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="veil-db-migrate-")
        self.addCleanup(shutil.rmtree, self.root, True)

    def _legacy_v2(self, rows: list[tuple]) -> str:
        path = os.path.join(self.root, "legacy.sqlite3")
        connection = sqlite3.connect(path)
        connection.isolation_level = None
        connection.executescript(V2_SCHEMA)
        connection.executemany(
            """
            INSERT INTO messages (
                sender_uid, msg_id, recipient_uid, message_type, ciphertext,
                ciphertext_sha256, created_at, expires_at, acked_at
            ) VALUES (?, ?, ?, ?, ?, NULL, 0, 0, NULL)
            """,
            rows,
        )
        connection.close()
        return path

    def test_v2_database_upgrades_to_v3(self) -> None:
        from veil_relay.db import Database

        path = self._legacy_v2([("sender-a", "msg-1", "recipient-a", 2, "CT")])
        db = Database(path, warn=lambda _: None)
        with db.connection() as connection:
            self.assertEqual(
                int(connection.execute("PRAGMA user_version").fetchone()[0]), 3
            )
            indexes = {
                row["name"]
                for row in connection.execute("PRAGMA index_list(messages)")
            }
            self.assertIn("messages_recipient_msg", indexes)

    def test_v2_database_with_duplicate_inbox_ids_fails_closed(self) -> None:
        from veil_relay.db import Database

        path = self._legacy_v2(
            [
                ("sender-a", "msg-1", "recipient-a", 2, "CT1"),
                ("sender-b", "msg-1", "recipient-a", 2, "CT2"),
            ]
        )
        with self.assertRaises(RuntimeError) as caught:
            Database(path, warn=lambda _: None)
        self.assertIn("duplicate", str(caught.exception))

        # Fail closed means fail without deleting anything.
        connection = sqlite3.connect(path)
        try:
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM messages").fetchone()[0], 2
            )
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
