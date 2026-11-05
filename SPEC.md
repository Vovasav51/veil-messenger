# Veil MVP integration contract

Native iOS 17+ SwiftUI and Android 8+ Java, one device per account, 1:1 text only. Use real pinned upstream libsignal; do not implement a substitute protocol. This is an unaudited development MVP, not production. No phone/email, contacts upload, analytics, groups, attachments, account recovery, push, or multi-device in v0.1. UI may use native system style (not a web page).

Cross-platform safety number: libsignal numeric fingerprint, iterations 5200, version 2, identifiers = lowercase UID UTF-8 bytes, respective identity public keys. Compare full 60-digit display text; whitespace is presentation only. Protocol types per upstream Rust `CiphertextMessageType`: Whisper=2, PreKey=3 (NOT 1), SenderKey=7 and Plaintext=8; relay permits only 2 and 3.

## Server JSON API v1

All endpoints except `/health` and registration require `Authorization: Bearer <token>`. HTTPS required by release client. Server binds loopback by default. API uses snake_case JSON. UID is client-generated UUID (prefer UUIDv7). device_id is 1.

- `GET /health` -> `{"status":"ok","version":"0.1.0"}`.
- `POST /v1/register` body `{uid, handle, device_id:1, bundle: PublicBundle}` -> 201 `{uid, handle, token}`. Handle normalized lower-case ASCII `[a-z0-9_]{3,24}`, optional leading @ stripped. Token server-generated 32 random bytes; DB stores hash only. UID unique, handle unique. No private key uploaded. Registration quota/rate limited; closed beta invite env if configured.
- `GET /v1/directory/{handle}` -> `{uid,handle,device_id:1,identity_key:<base64>}`. Exact lookup, authenticated and rate-limited.
- `GET /v1/prekeys/{uid}` -> `PublicBundle`. Atomically consumes one available one-time prekey. Others remain; no key reuse by server.
- `PUT /v1/prekeys` body `PublicBundle` -> `{"ok":true}`. Own account only. Refills prekeys; identity, registration_id and signed/kyber keys cannot silently change in MVP. Merge unique one-time IDs; reject reupload of consumed IDs.
- `POST /v1/messages` body `{id:<UUID>,recipient_uid,recipient_device_id:1,message_type:<integer>,ciphertext:<base64>}` -> 202 `{id,accepted:true}`. Server derives sender_uid from auth, never trusts caller sender. Accept only Signal message types 2/3. Sender+message id idempotency; mismatched duplicate rejected. Bounded ciphertext, per-user mailbox cap, TTL (default 30 days), batch max 100. Return same success for retry even after recipient ACK (tombstone without payload until TTL).
- `GET /v1/messages` -> `{"messages":[{id,sender_uid,sender_device_id:1,recipient_uid,recipient_device_id:1,message_type,ciphertext,created_at:<unix seconds>}...]}`. Pull, no automatic delete; oldest first.
- `POST /v1/messages/ack` body `{"ids":[<UUID>...]}` -> `{"ok":true}`. ACK only own inbox; purge ciphertext after client durable commit.

`PublicBundle` keys: `registration_id` UInt32 in 1...16380, `device_id:1`, `identity_key` base64 serialized Signal identity public key, `signed_prekey:{id:UInt32,public_key:base64,signature:base64}`, `kyber_prekey:{id:UInt32,public_key:base64,signature:base64}`, `one_time_prekeys:[{id:UInt32,public_key:base64}]`. Directory prekey GET returns same fields but at most one one_time_prekeys element. LibSignal version may use PQXDH; document exact pinned version honestly.

Errors `{detail:<safe string>}` with proper 400/401/404/409/413/429 status, never tracebacks or secrets. No request-body/auth/access logs. Relay learns sender/recipient/IP/timing; **no sealed sender claim**. SQLite at private path, not plaintext message history. HTTPS via reverse proxy Caddy; no public deployment is authorized by this task.

## Swift shared types (Models.swift, owned by crypto/storage agent)

All Codable + value types unless stated. JSONEncoder/Decoder default keys; use explicit CodingKeys for snake_case. Foundation Date internal local only.

`PublicPreKey { id: UInt32, publicKey: String }`
`PublicSignedPreKey { id: UInt32, publicKey: String, signature: String }`
`PublicBundle { registrationId: UInt32, deviceId: UInt32, identityKey: String, signedPrekey: PublicSignedPreKey, kyberPrekey: PublicSignedPreKey, oneTimePrekeys: [PublicPreKey] }`
`Account { uid: String, handle: String, token: String, serverURL: String }`
`Contact: Identifiable { uid: String, handle: String, identityKey: String, verified: Bool; var id:String { uid } }`
`ChatMessage: Identifiable { id:String, peerUID:String, text:String, outgoing:Bool, createdAt:Date, status:String }` status `queued`/`sent`/`received`.
`Envelope: Codable, Identifiable { id:String, senderUID:String, senderDeviceId:UInt32, recipientUID:String, recipientDeviceId:UInt32, messageType:UInt8, ciphertext:String, createdAt:Double }`
`OutgoingEnvelope: Codable, Identifiable { id:String, recipientUID:String, recipientDeviceId:UInt32, messageType:UInt8, ciphertext:String }`

`VaultState: Codable { account:Account?, contacts:[Contact], messages:[ChatMessage], outbox:[OutgoingEnvelope], processedEnvelopeIDs:[String], crypto:CryptoState }`, default initializer empty.
`@MainActor final class EncryptedVault` has `var state:VaultState`, `init() throws`, `func save() throws`, `func transaction<T>(_ body: () throws -> T) throws -> T` rollback full state on mutation/save failure. AES-GCM encrypted atomic Application Support file, random key in Keychain ThisDeviceOnly, no backups, FileProtection.complete; never silently wipe corrupt state. No plaintext file fallback. Crypto agent can revise transaction API if it documents exact contract promptly.
`@MainActor final class SignalService` `init(vault:EncryptedVault)`, `func publicBundle() throws -> PublicBundle`, `func encrypt(text:String, to contact:Contact, bundle:PublicBundle?, localUID:String) throws -> (UInt8, String)`, `func decrypt(_ envelope:Envelope, localUID:String) throws -> String`, `func fingerprint(for contact:Contact, localUID:String) throws -> String`. Signal stores backed by `vault.state.crypto`; persist ratchets+outbox atomically using vault.transaction in coordinator. Reject changed identity and directory/bundle mismatches. Initial peer identities TOFU, explicit out-of-band fingerprint comparison. UTF-8 max 4096 bytes. UUID function `makeUUIDv7() -> String` if practical.

## Swift UI/network/coordinator (owned by iOS UI agent)

`VeilApp.swift`, `AppModel.swift`, `RelayClient.swift`, `Views/*.swift`. @MainActor AppModel ObservableObject owns vault, SignalService and publishes state/errors. Bootstrap with throwing vault load (failure screen, no reset). Onboard server URL + @handle; generate local identity before registration, preserve pending uid to allow retry (do not claim account recovery). Add contact exact lookup and show fingerprint, verify checkbox explicit. Send creates encrypted outbox and local message in same transaction, then flush HTTP; retry reuses ciphertext/id, never encrypts again. Receive durable transaction: dedup ID, decrypt, save chat+ratchet+processed ID, then ACK only committed IDs; no ACK on decrypt/storage failure. Do not trust envelope sender metadata as cryptographic verification; Signal identity pins. Poll only while foreground; cancellations respected, no overlaps; backoff, clear status. No network plaintext fallback, HTTPS release, debug-only localhost http allowed via explicit ATS local networking. No in-app logging. Read/compose/chat list/settings and privacy overlay when background. Secure first-party URLSession ephemeral, no URLCache. No plaintext sensitive UserDefaults. Display actual experimental status and limitations in settings.
