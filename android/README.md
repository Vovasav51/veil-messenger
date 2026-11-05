# Veil Android client

Native Android (Java 17, minSdk 26, compileSdk/targetSdk 35, AGP 8.7.3, Gradle 8.9)
messenger for the Veil relay API in [`../SPEC.md`](../SPEC.md). No WebView, no
Compose, no JavaScript, no custom cryptography.

## Pinned crypto

| Component | Version | Source |
| --- | --- | --- |
| `org.signal:libsignal-android` | **0.106.0** | `https://build-artifacts.signal.org/libraries/maven/` |
| `org.signal:libsignal-client` | **0.106.0** | transitive / test JVM (same build) |

0.106.0 is the official Signal build used by Signal-Android itself
(`settings.gradle.kts` adds `SignalBuildArtifacts`,
`https://build-artifacts.signal.org/libraries/maven/`). Maven Central only
carries the Java/Android artifacts up to 0.86.5; the Signal repository is
therefore listed **first**, restricted with `includeGroup "org.signal"` so no
other dependency can be resolved from it.

The published POM depends on Kotlin stdlib 2.2.20. The 0.106 binding requires a
**local address** for session operations:
`new SessionBuilder(store, remoteAddress, localAddress)` and
`new SessionCipher(store, localAddress, remoteAddress)`; the client passes
`(localUid, 1)` and `(peerUid, 1)` accordingly. The AAR supplies the Android
JNI libraries (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`); the Java/Kotlin API
classes come from `libsignal-client`, exactly as the published POM declares.
Protocol features in use: X3DH/PQXDH with **Kyber-1024**, double ratchet,
`CiphertextMessage` types **2** (whisper) and **3** (prekey). No substitute
protocol, no stub, no mock.

The desktop native libraries bundled inside `libsignal-client`
(`libsignal_jni_amd64.so`, `*.dylib`, `*.dll`) are excluded from the APK in
`app/build.gradle`; `libsignal_jni_testing.so` is also excluded so the production
library is always the one loaded.

## Public keys and fingerprint (iOS interop)

`PublicBundle` serialization matches the relay validator byte for byte:

- `identity_key`, `signed_prekey.public_key`, one-time prekeys: 33 bytes,
  `0x05 || curve25519` (`ECPublicKey.serialize()`).
- `signed_prekey.signature`, `kyber_prekey.signature`: 64-byte XEd25519 over the
  corresponding public key bytes (`IdentityKeyPair.privateKey.calculateSignature`).
- `kyber_prekey.public_key`: `KEMPublicKey.serialize()` emits **1569** bytes
  (`0x08` KEM type tag + 1568-byte Kyber-1024 key). The relay accepts 1568..1569;
  the 1569-byte form is forwarded to libsignal unchanged, and a bare 1568-byte
  key is also accepted on input.

Verification fingerprint (must match iOS exactly):

```text
version      = 2
iterations   = 5200
localId      = lowercase(uid) as UTF-8 bytes
remoteId     = lowercase(uid) as UTF-8 bytes
fingerprint  = libsignal NumericFingerprintGenerator
                 .createFor(2, localId, localIdentityKey, remoteId, remoteIdentityKey)
display      = getDisplayableFingerprint().getDisplayText()   // exactly 60 digits
```

The UI groups the digits into 12 blocks of five; comparison is on the digits.

## Interop with the iOS client (libsignal Swift v0.106.0)

Both clients pin the **same upstream version, 0.106.0**, so the bindings,
protocol implementation and serialization are identical:

- `SignalMessage` / `PreKeySignalMessage` (message types 2/3), X3DH/PQXDH with
  Kyber-1024, XEd25519 signed prekeys and 33-byte DjbEC identity keys are
  produced by the same build on both platforms (SPQR/PQ ratchet included).
- Bundle key encodings match the relay validator: 33-byte EC keys, 64-byte
  signatures, 1569-byte serialized Kyber key (a bare 1568-byte key is accepted
  and tagged before use).
- A bundle with **no one-time prekey** (signed prekey + Kyber only, e.g. when the
  iOS side has exhausted its 100 OTKs and does not auto-refill) is supported:
  `PreKeyBundle` is built with `NULL_PRE_KEY_ID`, matching Signal's fallback.
  Covered by `signedAndKyberOnlyBundleWithoutOneTimePrekeyWorks`.
- Fingerprint inputs are identical on both platforms (version 2, 5200
  iterations, lower-case UID bytes, sorted-pair numeric fingerprint).

## Security model (what is enforced in code)

- **One worker thread** (`AppCore`) owns vault, network and crypto. UI only reads
  immutable snapshots and receives callbacks on the main thread; no network or
  libsignal call ever runs on the main thread.
- **Encrypted vault**: `state.veil` is AES-256-GCM with AAD
  `io.veil.messenger/vault/v1`, key alias `io.veil.messenger.vault.aes.v1` in
  Android Keystore (non-exportable, randomized IV). The file is written to a
  temp file, `fsync`ed and atomically replaced.
- **Atomic transactions**: every mutation runs on a deep copy of `VaultState`.
  ratchet records, outbox entry, chat row and processed-envelope id are committed
  in one JSON document or not at all. Save failure ⇒ full rollback (tested).
- **No wipe on corruption**: a decrypt/parse failure raises a fatal screen; the
  file is never deleted or replaced with empty state (tested).
- **Outbox**: ciphertext and message id are frozen when encryption commits.
  Retries re-POST exactly those bytes (`SendQueue`), never re-encrypt.
- **Receive**: durable dedup *before* ACK (`processedEnvelopeIds`), decrypt and
  commit first, then ACK the committed ids only. Failed decryption or storage ⇒
  transaction rollback, no ACK, so the relay redelivers (tested). Ciphertext is
  bounded to the relay's **64 KiB**; plaintext to **4096 UTF-8 bytes**.
- **Identity pinning**: the directory key is written into the crypto store when a
  contact is saved (`SignalEngine.pinIdentity`), i.e. **before any inbound
  message**. A prekey envelope carries the sender identity key, so the receive
  path compares it with the pin *before* any ratchet work; a changed key produces
  `IDENTITY_CHANGED` and is never silently trusted. Unknown peers are pinned by
  libsignal on their first successfully decrypted message (TOFU), and the first
  inbound test asserts that pin. Removing a contact is the only explicit way to
  accept a new key.
- **Registration**: identity, prekeys and the pending UID are persisted before
  the HTTP request. An uncertain result keeps the same UID and key material; a
  409 on retry is reported honestly (there is no account recovery).
- **Transport**: HTTPS only; HTTP is accepted solely for `127.0.0.1`,
  `localhost` and the emulator alias `10.0.2.2` in debug builds (code + network
  security config). Redirects are never followed, so the bearer token cannot be
  replayed to another origin. Request ≤ 512 KiB, response ≤ 12 MiB, connect 10 s,
  read 20 s. No logging of requests, tokens, ciphertext or keys.
  Integration review raised the bounded response cap to **12 MiB** to cover a
  legal 100-envelope mailbox at the relay's 64-KiB ciphertext bound. Registration
  UID/handle/token and send acknowledgement ID are validated before local commit.
- **Platform**: `allowBackup=false`, `dataExtractionRules` exclude every domain,
  `FLAG_SECURE` on all activities, opaque privacy shield in `onPause`.
  Automatic EmojiCompat downloadable-font initialization is disabled; system
  emoji fonts remain available without a font-provider request.

Additional integration checks: an unrecorded envelope ID is never ACKed merely
because libsignal reports a ratchet duplicate; only durable dedup authorizes that
shortcut. A real HTTP integration test starts the Python relay on loopback and
exercises the Android Java transport with actual Signal JNI encryption, offline
queue, reply, retries before/after ACK and no plaintext in relay SQLite/WAL.

## Layout

```
app/src/main/java/io/veil/messenger/
  core/            models, vault (AES-GCM), RelayClient, AppCore, SendQueue, InboxProcessor
    model/         wire + stored value types (Account, Contact, ChatMessage, Envelope, PublicBundle)
  crypto/          CryptoState, VaultSignalStore (libsignal store), SignalEngine, CryptoException
  ui/              activities, ListView adapters (system widgets only)
app/src/test/java/         JVM tests (real libsignal Linux JNI + vault transaction tests)
```

## Build and test (Linux)

```bash
# JDK 21 and Android SDK 35 + build-tools 35.0.0 are provided by the repo scripts.
source ~/.cache/veil-build/env.sh
gradle -p android --no-daemon assembleDebug        # APK
gradle -p android --no-daemon testDebugUnitTest    # unit + crypto tests
```

or `scripts/android-build.sh debug|test` from the repository root.

The debug APK is ~119 MB: libsignal's `libsignal_jni.so` for all four ABIs is
kept (any device or emulator works) but compressed inside the APK with
`jniLibs.useLegacyPackaging = true`; the system extracts it into app-private
storage at install time. Desktop `.so`/`.dylib`/`.dll` files and
`libsignal_jni_testing.so` are excluded from packaging.

The unit-test JVM is pointed at `app/build/jni-tmp` for `java.io.tmpdir`, so
libsignal's JNI loader can extract and `System.load` its Linux `.so` on hosts
where `/tmp` is `noexec`.

## Honest limitations (v0.1)

- One device per account (`device_id = 1`); no multi-device, no linking.
- Text only (≤ 4096 UTF-8 bytes); no attachments, groups, reactions, calls.
- No push: messages arrive while the app is in the foreground (3 s poll with
  exponential backoff, no overlapping requests). No background service.
- No account recovery, no backup, no export. Losing the device loses the account.
- The relay learns sender/recipient UIDs, timing, sizes and IP addresses; there
  is no sealed sender.
- Beta rate limits and mailbox caps apply; the client surfaces 429 honestly.
- Unaudited development MVP. Not for sensitive data.
- A message from a not-yet-added UID is kept with an explicit "unknown contact"
  placeholder (handle filled in when the contact is added by exact lookup);
  directory lookup is by handle only.
