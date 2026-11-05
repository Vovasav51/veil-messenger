# Veil iOS — UI / network / coordinator notes

Owner: iOS UI agent. Files in this layer:

- `ios/Veil/VeilApp.swift` — `@main`, root switch (fatal screen / onboarding / tabs), scene-phase → polling, privacy overlay.
- `ios/Veil/AppModel.swift` — `@MainActor ObservableObject`, vault + `SignalService` + relay coordination, single write path, registration, contacts, send/receive, polling/backoff, Keychain pending-registration record.
- `ios/Veil/RelayClient.swift` — relay JSON API v1 client, URL validation, ephemeral `URLSession`, redirect refusal, error mapping.
- `ios/Veil/Views/SupportViews.swift` — brand mark, banner, sync badge, privacy overlay, fatal boot screen, formatters.
- `ios/Veil/Views/OnboardingView.swift` — HTTPS server URL + handle, pending-registration state, uncertain-result copy.
- `ios/Veil/Views/ChatsListView.swift` — chat list + contacts, pull-to-refresh, compose entry point.
- `ios/Veil/Views/ChatView.swift` — 1:1 conversation, byte limit, per-message status, unknown-sender read-only state.
- `ios/Veil/Views/ComposeView.swift` — exact handle lookup, fingerprint display, explicit verify toggle.
- `ios/Veil/Views/ContactDetailView.swift` — pinned-key fingerprint + verification toggle.
- `ios/Veil/Views/SettingsView.swift` — account, own fingerprint, sync diagnostics, honest limitations.
- `ios/VeilTests/RelayClientTests.swift` — XCTest for URL/cleartext policy (`RelayClient.validateServerURL`, `isLoopbackHost`) and handle normalization.

No shared `Models.swift` / crypto / storage / project files were created or modified.

## Shared API exactly as used (verified against the landed files)

`Models.swift`, `Storage/EncryptedVault.swift` and `Crypto/*` (including `SignalService.swift`) were present when this layer was finished; the calls below were checked against them. `SignalService` implements exactly this surface:

```swift
@MainActor final class SignalService {
    init(vault: EncryptedVault)                       // non-throwing, sets vault.cryptoMirror
    func publicBundle() throws -> PublicBundle        // provisions identity on first call
    func encrypt(text: String, to contact: Contact,
                 bundle: PublicBundle?, localUID: String) throws -> (UInt8, String)
    func decrypt(_ envelope: Envelope, localUID: String) throws -> String
    func fingerprint(for contact: Contact, localUID: String) throws -> String
}
```

Value types are built with **memberwise initializers** in the SPEC/Models field order:

- `Account(uid:handle:token:serverURL:)`
- `Contact(uid:handle:identityKey:verified:)`
- `ChatMessage(id:peerUID:text:outgoing:createdAt:status:)`
- `OutgoingEnvelope(id:recipientUID:recipientDeviceId:messageType:ciphertext:)`
- `VaultState()` (Models provides the defaulted init)
- `Envelope` / `PublicBundle` are decoded directly with their own Codable keys (`sender_uid`, `identity_key`, `registration_id`, `one_time_prekeys`, …), which Models already defines as snake_case. The client never re-maps them.
- Message/uid ids come from the shared `makeUUIDv7()`.

Transaction contract actually implemented by `EncryptedVault` and relied on here:

1. `transaction` snapshots `state` + the crypto mirror and restores both on any error; the write happens once at commit.
2. `save()` inside a transaction is a documented no-op that defers to the commit — the coordinator still calls it inside the body so the intent is explicit and nothing depends on ordering.
3. The coordinator passes the `EncryptedVault` itself into its `write` closure (not an `inout VaultState`), so a `SignalService` call can never overlap exclusive access to `vault.state`. `SignalService` must keep using its `CryptoStateMirroring` state, not `vault.state`.
4. `SignalService` must not open its own `vault.transaction` (nested transactions are blocked with a precondition here).
5. `encrypt(bundle:)`: non-nil bundle only when the session is being created; the coordinator passes one only when there is no local history for that peer, i.e. the first message. Later messages use `bundle: nil`.
6. If `encrypt` throws `VeilCryptoError.missingBundle` / `.sessionNotFound` on a message sent with `bundle: nil`, the coordinator fetches a fresh verified bundle and retries once. Identity/pin errors are rethrown unchanged.
7. `decrypt` enforces the identity pin through `SignalProtocolStore` (already landed: `saveIdentity` throws on a changed key, `isTrustedIdentity` is TOFU). Envelope `sender_uid` is only a routing label.
8. `fingerprint` output is a display string; the UI does not reformat it.

## Behaviour implemented

**Contacts.** Compose performs a directory lookup only (exact handle, `device_id == 1`, non-empty identity key) and shows the fingerprint derived from that directory identity; it does **not** fetch prekeys, so previewing a contact consumes nothing. The prekey bundle is fetched and cross-checked against directory + pin only at the first send. Adding a contact whose uid already exists is refused if the freshly verified identity key differs from the stored pin (the pin and the verified flag are never silently upgraded); an empty TOFU placeholder may be filled once.

**Network hardening.** Responses are streamed with `URLSession.bytes(for:delegate:)` and capped at 12 MiB (error bodies at 64 KiB, truncated rather than failing so the status code wins); `expectedContentLength` is checked before reading and the body read is cancelled with the task. Redirects are refused, so a `30x` can never replay the `Authorization` header to another origin.


**Registration.** Handle is normalized (strip `@`, lower-case ASCII, `[a-z0-9_]{3,24}`) and the server URL is validated (HTTPS only; `http` accepted only for an exact loopback host in DEBUG — `127.0.0.0/8` strict dotted-quad, `localhost`, `::1`; lookalikes such as `127.attacker.com` are rejected even in Debug). Before the first network call the coordinator writes a non-secret `PendingRegistration {uid, handle, serverURL}` to the Keychain (`app.veil.pending-registration`, `AfterFirstUnlockThisDeviceOnly`, non-synchronizable) and materialises the local identity via `signal.publicBundle()` inside a transaction. A retry reuses the same uid and the same local identity. The 201 body is treated as untrusted: `uid` must equal the uid we sent, `handle` must equal the normalized handle, and the token must be 16–512 characters with no whitespace/control characters; anything else is refused and **not** persisted. On an uncertain result (transport error) the UI explicitly says the outcome is unknown and that retrying keeps the uid; on `409` it distinguishes a uid conflict (offers a *new uid with the same local identity*, no account recovery claim) from a taken handle. Nothing is written to `UserDefaults`; no secrets are written to disk by this layer.

**Send.** Plaintext is validated (non-empty, ≤ 4096 UTF-8 bytes). For a peer with no prior traffic, the directory entry and the prekey bundle are both fetched and must agree on uid / device_id / identity_key and match the pinned `Contact.identityKey`. Encryption, the `OutgoingEnvelope` and the local `ChatMessage(status: "queued")` are committed in one transaction, then the exact stored ciphertext is POSTed. The 202 body must contain `accepted == true` **and** echo our envelope `id`; otherwise the outbox entry stays put and nothing is marked sent. HTTP retry loops re-send that same `id` + ciphertext; they never re-encrypt or re-ratchet. `status: "sent"` + outbox removal are persisted only after that validated acceptance. Permanent rejections (4xx except 401/408/429) are surfaced and kept out of the retry loop but stay in the outbox record.

**Receive.** Only envelopes whose `recipient_uid`/`recipient_device_id` match this account are considered. Per envelope: one transaction that decrypts, appends the chat message and records the id in `processedEnvelopeIDs`; then a single `POST /v1/messages/ack` with committed ids only. Ids already in `processedEnvelopeIDs` (e.g. ACK lost last time) are ACKed again without decrypting. Decrypt/storage failures are never ACKed; after 5 failed attempts the envelope is skipped (still not ACKed) and the user is warned. Duplicate prevention lives entirely in the durable `processedEnvelopeIDs` set.

**Foreground polling.** A single `Task` per activation with a generation counter, cancelled on `scenePhase != .active`; no overlapping cycles (`isSyncing`/`isFlushing` guards); 3 s cadence on success, exponential backoff 3→40 s on failure, hard stop with a visible error on 401. Pull-to-refresh and Settings reuse the same cycle.

## Build-owner tasks (not touched here)

- `ios/project.yml` (XcodeGen), `ios/Veil/Info.plist`, `ios/Veil/Info-Debug.plist` and `docs/IOS_BUILD.md` already exist and were left untouched. `Info-Debug.plist` already carries `NSAppTransportSecurity → NSAllowsLocalNetworking = true`, which matches the only supported insecure case: `http://127.0.0.1|localhost` in a DEBUG build. Release `Info.plist` has no ATS exception — keep it that way; do **not** add `NSAllowsArbitraryLoads`.
- `Security.framework` is required by this layer (`PendingRegistrationStore`, Keychain). It is linked by default for iOS app targets.
- No background modes, no push/notification entitlements, no keychain sharing groups, no URL cache.
- If the project enables `SWIFT_STRICT_CONCURRENCY = complete`, the crypto layer's types must be `Sendable` (`Models.swift` already is); this layer is entirely `@MainActor` except `RelayClient` (`@unchecked Sendable`, immutable stored state, ephemeral `URLSession`).
- `SignalService` now exists (`Crypto/SignalService.swift`) and matches the contract used here (`missingBundle` when `bundle == nil` and no session, `messageType` 2/3, provisioning inside `publicBundle()`).

## Known limitations / caveats

- libsignal version and PQXDH availability are pinned by the crypto agent; the UI only states "LibSignalClient 1:1" and never claims an audit or production readiness.
- A first message to a contact consumes one one-time prekey from the server; compose performs only the directory lookup, so previewing or cancelling never consumes a prekey.
- A 2xx send response that contradicts the request (`accepted != true` or a different `id`) is treated as a transient failure: the ciphertext stays queued and is retried unchanged. A relay that is permanently broken this way will therefore keep one bounded outbox entry per message the user wrote; nothing is lost or marked sent.
- `ios/VeilTests/RelayClientTests.swift` was written but **not executed** — there is no Xcode/iOS SDK on this Linux host. It has no network dependency and should run in the first `bash scripts/ios-build.sh test` on macOS.
- Fingerprints are shown grouped as 12×5 digits when the service returns the canonical 60-digit safety number (Signal convention); any other format is displayed verbatim.
- There is no UI path to `SignalService.resetPeerTrust` (safety-number-changed flow). A contact whose pinned key legitimately changes stays blocked with a clear error; re-pinning requires an explicit product decision, and no silent re-pin exists anywhere.
- If `encrypt` throws `missingBundle`/`sessionNotFound` for the *first* message to a peer, the coordinator fetches a fresh bundle and retries once with a new message id (the failed attempt was rolled back). Other crypto errors surface as-is. Retries of already-queued messages always reuse the stored ciphertext, and only the exact id/ciphertext pair is ever re-POSTed.
- Messages from senders who are not in the contact list are shown read-only with an explicit warning; no `Contact` is fabricated from envelope metadata.
- `409` classification on registration is a heuristic on the server's `detail` text (`"uid"` vs anything else).
- Polling only runs while the app is active; there is no push, no background refresh, no recovery, no groups, no attachments, no multi-device.
- Relay metadata (who talks to whom, when, size, IP) is not hidden; no sealed-sender claim anywhere in the UI.

## Manual test checklist

1. First launch with an unreachable relay → error banner, pending registration stays, second attempt reuses the same uid (`GET /v1/...` logs on the server side show one uid).
2. Register two accounts on two devices; add each other; compare fingerprints; send while offline (bubble shows clock) then restore network → one POST, one message on the peer, status flips to sent.
3. Kill the app between encrypt and flush → relaunch → the queued ciphertext is sent unchanged (same message id at the server).
4. Duplicate delivery / lost ACK: server re-delivers the same id → no duplicate bubble, id is ACKed, no second decrypt.
5. Tamper with a ciphertext byte → no ACK, warning banner, envelope stays until TTL; other messages in the same batch still commit and ACK.
6. Background the app → privacy overlay, polling stops; foreground → polling resumes, no overlapping cycles after rapid app-switch.
7. Directory identity ≠ bundle identity (server test double) → contact cannot be added and first-time encryption is refused.
