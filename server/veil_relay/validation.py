"""Strict, allocation-bounded validation of relay request payloads.

Everything here is defensive: JSON must be an object, integers must be real
integers, base64 must be canonical, UUIDs canonical, and Signal public key
material must have the exact serialized sizes libsignal produces. The relay
never inspects or validates *signatures* cryptographically -- it stores opaque
public key material -- but it refuses shapes that no real Signal client emits.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Mapping

from .errors import ApiError

# --- Signal key material sizes (serialized, as produced by libsignal) ---------
#
# A serialized Signal identity key / signed prekey public key is a 33-byte
# ``0x05 || curve25519(32)`` DjbEC public key.
SIGNAL_PUBLIC_KEY_LEN = 33
SIGNAL_PUBLIC_KEY_TYPE = 0x05
# XEd25519 signatures are 64 bytes.
SIGNAL_SIGNATURE_LEN = 64
#
# Kyber-1024 public keys are 1568 bytes in current libsignal (PQXDH). A 1569
# byte form is tolerated for a leading type byte so that a minor serialization
# change does not brick clients; both are still bounded and plausible.
KYBER_PUBLIC_KEY_LEN = 1568
KYBER_PUBLIC_KEY_MAX = 1569

REGISTRATION_ID_MIN = 1
REGISTRATION_ID_MAX = 16380
DEVICE_ID = 1
PREKEY_ID_MIN = 1
PREKEY_ID_MAX = 0xFFFFFFFF
# Signal message types accepted by the relay: CIPHERTEXT (2) and
# PREKEY_BUNDLE (3). Key-exchange/placeholder types are not relayed.
MESSAGE_TYPES = frozenset({2, 3})

HANDLE_RE = re.compile(r"[a-z0-9_]{3,24}")
UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
NIL_UUID = "00000000-0000-0000-0000-000000000000"
_B64_RE = re.compile(r"[A-Za-z0-9+/]*={0,2}")
CONTENT_LENGTH_RE = re.compile(r"[0-9]{1,12}")

MAX_HANDLE_RAW_LEN = 25  # optional '@' plus 24 characters
MAX_UUID_LEN = 36
MAX_JSON_TEXT_BYTES = 4 * 1024 * 1024


# --- primitive readers -------------------------------------------------------


def require_object(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ApiError(400, f"{field} must be a JSON object")
    return value


def require_list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise ApiError(400, f"{field} must be a JSON array")
    return value


def require_str(
    obj: Mapping[str, Any],
    key: str,
    *,
    field: str | None = None,
    min_len: int = 1,
    max_len: int,
) -> str:
    name = field or key
    if key not in obj:
        raise ApiError(400, f"{name} is required")
    value = obj[key]
    if not isinstance(value, str):
        raise ApiError(400, f"{name} must be a string")
    if len(value) < min_len or len(value) > max_len:
        raise ApiError(400, f"{name} has an invalid length")
    return value


def require_int(
    obj: Mapping[str, Any],
    key: str,
    *,
    field: str | None = None,
    low: int,
    high: int,
) -> int:
    name = field or key
    if key not in obj:
        raise ApiError(400, f"{name} is required")
    value = obj[key]
    # ``bool`` is an ``int`` subclass: reject it explicitly.
    if type(value) is not int:
        raise ApiError(400, f"{name} must be an integer")
    if not (low <= value <= high):
        raise ApiError(400, f"{name} is out of range")
    return value


def require_optional_str(
    obj: Mapping[str, Any],
    key: str,
    *,
    field: str | None = None,
    max_len: int,
) -> str | None:
    if key not in obj or obj[key] is None:
        return None
    return require_str(obj, key, field=field, min_len=1, max_len=max_len)


# --- identifiers -------------------------------------------------------------


def normalize_uuid(value: Any, *, field: str = "uid") -> str:
    if not isinstance(value, str):
        raise ApiError(400, f"{field} must be a UUID string")
    if len(value) != MAX_UUID_LEN or not UUID_RE.fullmatch(value):
        raise ApiError(400, f"{field} must be a UUID")
    normalized = value.lower()
    if normalized == NIL_UUID:
        raise ApiError(400, f"{field} must not be the nil UUID")
    return normalized


def normalize_handle(value: Any) -> str:
    if not isinstance(value, str):
        raise ApiError(400, "handle must be a string")
    raw = value
    if len(raw) > MAX_HANDLE_RAW_LEN or len(raw) < 3:
        raise ApiError(400, "handle must be 3-24 characters")
    if raw.startswith("@"):
        raw = raw[1:]
    normalized = raw.lower()
    if not HANDLE_RE.fullmatch(normalized):
        raise ApiError(400, "handle must match [a-z0-9_]{3,24}")
    return normalized


# --- base64 ------------------------------------------------------------------


def max_encoded_length(max_bytes: int) -> int:
    return 4 * ((max_bytes + 2) // 3)


def decode_base64(
    value: Any,
    *,
    field: str,
    min_bytes: int,
    max_bytes: int,
    oversize_status: int = 400,
) -> bytes:
    if not isinstance(value, str):
        raise ApiError(400, f"{field} must be a base64 string")
    encoded_limit = max_encoded_length(max_bytes)
    if len(value) > encoded_limit:
        raise ApiError(oversize_status, f"{field} is too large")
    if not value or len(value) % 4 != 0:
        raise ApiError(400, f"{field} must be canonical base64")
    if not _B64_RE.fullmatch(value):
        raise ApiError(400, f"{field} must be canonical base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise ApiError(400, f"{field} must be canonical base64") from None
    if not (min_bytes <= len(raw) <= max_bytes):
        raise ApiError(400, f"{field} has an invalid length")
    # Reject non-zero trailing bits / non-canonical padding.
    if base64.b64encode(raw).decode("ascii") != value:
        raise ApiError(400, f"{field} must be canonical base64")
    return raw


def _decode_key(
    value: Any,
    *,
    field: str,
    min_bytes: int,
    max_bytes: int,
) -> str:
    raw = decode_base64(value, field=field, min_bytes=min_bytes, max_bytes=max_bytes)
    return base64.b64encode(raw).decode("ascii")


def _validate_signal_public_key(value: Any, *, field: str) -> str:
    raw = decode_base64(
        value,
        field=field,
        min_bytes=SIGNAL_PUBLIC_KEY_LEN,
        max_bytes=SIGNAL_PUBLIC_KEY_LEN,
    )
    if raw[0] != SIGNAL_PUBLIC_KEY_TYPE:
        raise ApiError(400, f"{field} is not a serialized Signal public key")
    return base64.b64encode(raw).decode("ascii")


def _validate_signature(value: Any, *, field: str) -> str:
    return _decode_key(
        value,
        field=field,
        min_bytes=SIGNAL_SIGNATURE_LEN,
        max_bytes=SIGNAL_SIGNATURE_LEN,
    )


def _validate_kyber_public_key(value: Any, *, field: str) -> str:
    return _decode_key(
        value,
        field=field,
        min_bytes=KYBER_PUBLIC_KEY_LEN,
        max_bytes=KYBER_PUBLIC_KEY_MAX,
    )


# --- JSON body ---------------------------------------------------------------


def _reject_constant(token: str) -> Any:
    raise ValueError(f"unsupported JSON constant: {token}")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ApiError(400, "duplicate JSON key")
        result[key] = value
    return result


def parse_json_object(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_JSON_TEXT_BYTES:
        raise ApiError(413, "request body too large")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ApiError(400, "request body must be UTF-8") from None
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
    except ApiError:
        raise
    except (ValueError, RecursionError):
        raise ApiError(400, "request body must be valid JSON") from None
    if not isinstance(parsed, dict):
        raise ApiError(400, "request body must be a JSON object")
    return parsed


# --- PublicBundle ------------------------------------------------------------


def validate_public_bundle(value: Any, *, max_otk: int) -> dict[str, Any]:
    bundle = require_object(value, "bundle")

    registration_id = require_int(
        bundle,
        "registration_id",
        low=REGISTRATION_ID_MIN,
        high=REGISTRATION_ID_MAX,
    )
    device_id = require_int(bundle, "device_id", low=DEVICE_ID, high=DEVICE_ID)

    identity_key = _validate_signal_public_key(
        bundle.get("identity_key"), field="identity_key"
    )

    signed_raw = require_object(bundle.get("signed_prekey"), "signed_prekey")
    signed_prekey = {
        "id": require_int(
            signed_raw, "id", field="signed_prekey.id", low=PREKEY_ID_MIN, high=PREKEY_ID_MAX
        ),
        "public_key": _validate_signal_public_key(
            signed_raw.get("public_key"), field="signed_prekey.public_key"
        ),
        "signature": _validate_signature(
            signed_raw.get("signature"), field="signed_prekey.signature"
        ),
    }

    kyber_raw = require_object(bundle.get("kyber_prekey"), "kyber_prekey")
    kyber_prekey = {
        "id": require_int(
            kyber_raw, "id", field="kyber_prekey.id", low=PREKEY_ID_MIN, high=PREKEY_ID_MAX
        ),
        "public_key": _validate_kyber_public_key(
            kyber_raw.get("public_key"), field="kyber_prekey.public_key"
        ),
        "signature": _validate_signature(
            kyber_raw.get("signature"), field="kyber_prekey.signature"
        ),
    }

    one_time_raw = bundle.get("one_time_prekeys", [])
    one_time_list = require_list(one_time_raw, "one_time_prekeys")
    if len(one_time_list) > max_otk:
        raise ApiError(400, f"one_time_prekeys is limited to {max_otk} entries")

    one_time_prekeys: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for index, item in enumerate(one_time_list):
        entry = require_object(item, f"one_time_prekeys[{index}]")
        key_id = require_int(
            entry,
            "id",
            field=f"one_time_prekeys[{index}].id",
            low=PREKEY_ID_MIN,
            high=PREKEY_ID_MAX,
        )
        if key_id in seen_ids:
            raise ApiError(400, "one_time_prekeys contains duplicate ids")
        seen_ids.add(key_id)
        one_time_prekeys.append(
            {
                "id": key_id,
                "public_key": _validate_signal_public_key(
                    entry.get("public_key"),
                    field=f"one_time_prekeys[{index}].public_key",
                ),
            }
        )

    return {
        "registration_id": registration_id,
        "device_id": device_id,
        "identity_key": identity_key,
        "signed_prekey": signed_prekey,
        "kyber_prekey": kyber_prekey,
        "one_time_prekeys": one_time_prekeys,
    }


# --- request bodies ----------------------------------------------------------


def validate_registration(body: Mapping[str, Any], *, max_otk: int) -> dict[str, Any]:
    uid = normalize_uuid(body.get("uid"), field="uid")
    handle = normalize_handle(body.get("handle"))
    device_id = require_int(body, "device_id", low=DEVICE_ID, high=DEVICE_ID)
    bundle = validate_public_bundle(body.get("bundle"), max_otk=max_otk)
    invite_code = require_optional_str(body, "invite_code", max_len=256)
    return {
        "uid": uid,
        "handle": handle,
        "device_id": device_id,
        "bundle": bundle,
        "invite_code": invite_code,
    }


def validate_outgoing_message(
    body: Mapping[str, Any], *, max_ciphertext_bytes: int
) -> dict[str, Any]:
    message_id = normalize_uuid(body.get("id"), field="id")
    recipient_uid = normalize_uuid(body.get("recipient_uid"), field="recipient_uid")
    recipient_device_id = require_int(
        body, "recipient_device_id", low=DEVICE_ID, high=DEVICE_ID
    )
    message_type = require_int(
        body, "message_type", low=min(MESSAGE_TYPES), high=max(MESSAGE_TYPES)
    )
    if message_type not in MESSAGE_TYPES:
        raise ApiError(400, "message_type must be 2 or 3")
    ciphertext = decode_base64(
        body.get("ciphertext"),
        field="ciphertext",
        min_bytes=1,
        max_bytes=max_ciphertext_bytes,
        oversize_status=413,
    )
    return {
        "id": message_id,
        "recipient_uid": recipient_uid,
        "recipient_device_id": recipient_device_id,
        "message_type": message_type,
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def validate_ack(body: Mapping[str, Any], *, max_ids: int) -> list[str]:
    raw_ids = require_list(body.get("ids"), "ids")
    if len(raw_ids) > max_ids:
        raise ApiError(400, f"ids is limited to {max_ids} entries")
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(raw_ids):
        message_id = normalize_uuid(item, field=f"ids[{index}]")
        if message_id in seen:
            continue
        seen.add(message_id)
        result.append(message_id)
    return result
