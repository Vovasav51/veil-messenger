# Veil — LibSignalClient integration (Swift)

Owner: crypto/storage agent. This file documents the **exact pinned upstream
dependency**, how to wire it into CocoaPods, the contract of the files in
`ios/Veil/Crypto`, `ios/Veil/Storage` and `ios/Veil/Models.swift`, and the honest
limitations of the MVP.

---

## 1. Pinned upstream release

| Item | Value |
| --- | --- |
| Project | [`signalapp/libsignal`](https://github.com/signalapp/libsignal) |
| **Pinned release** | **`v0.106.0`** |
| Git commit | `fc90b90fa2b9c37822fa47ba0e0dcdf387a0c071` |
| Commit date | 2026‑10‑23 |
| CocoaPods podspec | `LibSignalClient.podspec` (repo root, present up to `v0.106.0`) |
| Prebuilt Rust FFI | `https://build-artifacts.signal.org/libraries/libsignal-client-ios-build-v0.106.0.tar.gz` |
| SHA‑256 (official asset) | `ddfa5ac6fd6e0da9ebe4eb23890af048140aec1a3e916d3eccadc1036627152f` |
| Archive size | 180 765 521 bytes |
| Archive contents | `target/{aarch64-apple-ios,aarch64-apple-ios-sim,x86_64-apple-ios}/release/libsignal_ffi.a` |
| License | **AGPL‑3.0‑only** |

Why `v0.106.0` and not `v0.106.1`/`main`: **`v0.106.1` removed
`LibSignalClient.podspec` and `bin/fetch_archive.py`.** `RELEASE_NOTES.md` for
`v0.106.1` says:

> Swift: LibSignalClient is now distributed using Swift Package Manager instead
> of CocoaPods.

So `v0.106.0` is the **last release that supports CocoaPods**, and it already
contains the mandatory-PQXDH API (`PreKeyBundle` with `kyberPrekeyId`,
`kyberPrekey`, `kyberPrekeySignature`, `signalDecryptPreKey(... kyberPreKeyStore: ...)`),
matching the upstream test vectors referenced in the task
(`swift/Tests/LibSignalClientTests/SessionTests.swift`, which builds every bundle
with kyber material and decrypts with `signalDecryptPreKey`).

The checksum above was verified by downloading the archive and comparing with the
official release asset
`.../releases/download/v0.106.0/libsignal-client-ios-build-v0.106.0.tar.gz.sha256`.
It **must** be supplied, otherwise `bin/fetch_archive.py` aborts (it asserts the
digest even when the env var is empty).

### Podspec facts that matter

* `s.version = '0.106.0'` → archive name `libsignal-client-ios-build-v0.106.0.tar.gz`
  (`LIBSIGNAL_FFI_PREBUILD_ARCHIVE`).
* `s.platform = :ios, '15.0'` (app targets iOS 17 — fine).
* `s.swift_version = '5'`.
* `s.source_files = ['swift/Sources/**/*.swift', 'swift/Sources/**/*.m']`,
  plus a `SignalFfi` system-library module map in
  `swift/Sources/SignalFfi` (header search path is set by the pod).
* Two script phases: download the archive into
  `~/Library/Caches/org.signal.libsignal/`, then untar into
  `$(PROJECT_TEMP_DIR)/libsignal_ffi` and link
  `target/$(CARGO_BUILD_TARGET)/release/libsignal_ffi.a` via `OTHER_LDFLAGS`.
* No `prepare_command`; no Rust toolchain needed on the build machine.

---

## 2. CocoaPods wiring (Podfile — owned by the build agent)

The podspec is **not published to the CocoaPods trunk** (`trunk.cocoapods.org`
returns "No pod found"), so it must be referenced by git. `use_frameworks!` is
required (Swift pod with a static Rust library inside).

```ruby
platform :ios, '17.0'
use_frameworks!

# LibSignalClient v0.106.0 — last release with a CocoaPods podspec.
# The podspec requires this checksum or `pod install` fails during the build.
ENV['LIBSIGNAL_FFI_PREBUILD_CHECKSUM'] =
  'ddfa5ac6fd6e0da9ebe4eb23890af048140aec1a3e916d3eccadc1036627152f'

target 'Veil' do
  pod 'LibSignalClient',
      :git => 'https://github.com/signalapp/libsignal.git',
      :commit => 'fc90b90fa2b9c37822fa47ba0e0dcdf387a0c071'
      # `:tag => 'v0.106.0'` is equivalent and more readable; `:commit` is
      # immutable. Either way the podspec inside the checkout declares 0.106.0,
      # which is what selects the prebuilt archive.

  target 'VeilTests' do
    inherit! :search_paths
  end
end

post_install do |installer|
  installer.pods_project.targets.each do |target|
    target.build_configurations.each do |config|
      config.build_settings['IPHONEOS_DEPLOYMENT_TARGET'] = '17.0'
      # LibSignalClient does not support explicitly built modules (see
      # swift/README.md in the upstream repo). Disabling it is the documented
      # alternative to adding a non-recursive header search path to
      # $(PODS_ROOT)/LibSignalClient/swift/Sources/SignalFfi.
      config.build_settings['SWIFT_ENABLE_EXPLICIT_MODULES'] = 'NO'
    end
  end
end
```

Notes for CI (`.github/workflows/ios.yml` already installs `cocoapods`):

* The first `pod install` needs ~180 MB of network; the archive is cached in
  `~/Library/Caches/org.signal.libsignal`, so later builds are offline-safe.
* Commit `ios/Podfile.lock`. It records the exact commit + checksum.
* The compile step also needs `SWIFT_ENABLE_EXPLICIT_MODULES = NO` on the app
  target if Xcode 16+ turns explicit modules on globally; the `post_install`
  above covers the Pods project, add the same build setting to the `Veil` target
  in `project.yml` if the linker cannot find `LibSignalClient`.

### Version alignment with Android

The wire protocol is versioned, but the two clients must agree on:

1. Both clients should pin **0.106.0**. Java/Android artifacts are published at
   the official `https://build-artifacts.signal.org/libraries/maven/` repository,
   not only Maven Central (whose older metadata stops at 0.86.5). Both sides send
   `kyber_prekey` in the bundle and accept `PreKeySignalMessage` type 3. Matching
   key shapes alone is not proof of cross-version interoperability.
2. `registration_id ∈ 1…16380`, `device_id = 1`, message types **2 (whisper)**
   and **3 (prekey)** — unchanged upstream constants.
3. The **safety number parameters** in §5 — this is the only value that is not
   negotiated on the wire and silently produces different digits if it differs.
4. Kyber public keys serialize to 1568 bytes (1569 tolerated by the relay).

Actual iOS ↔ Android device interoperability has not been tested on this Linux
host. Updating either pin requires protocol/store/API regression tests and a
real two-platform check; do not assume all releases are interchangeable.

---

## 3. Files and contract

```
ios/Veil/Models.swift                     shared value types (SPEC contract)
ios/Veil/Crypto/CryptoState.swift         serialized protocol state (all value records)
ios/Veil/Crypto/SignalProtocolStore.swift libsignal store protocols over CryptoState
ios/Veil/Crypto/SignalService.swift       encrypt/decrypt/bundle/fingerprint
ios/Veil/Crypto/VeilCryptoError.swift     user-readable errors + libsignal error mapping
ios/Veil/Storage/EncryptedVault.swift     AES-GCM vault, atomic writes, transactions
ios/Veil/Storage/FileVaultStore.swift     Application Support file, complete protection
ios/Veil/Storage/KeychainVaultKeyStore.swift 256-bit key, ThisDeviceOnly, non-syncable
ios/VeilTests/…                           XCTest suites (see §7)
```

### `VaultState.crypto`

`CryptoState` stores libsignal's own `serialize()` outputs, never a custom
format:

| Field | libsignal record |
| --- | --- |
| `identityKeyPair` | `IdentityKeyPair.serialize()` |
| `registrationId` | `localRegistrationId` |
| `sessions[].record` | `SessionRecord.serialize()` (Double Ratchet + post‑PQXDH state) |
| `identities[].identityKey` | `IdentityKey.serialize()` (trust pin, public only) |
| `preKeys[].record` | `PreKeyRecord.serialize()` |
| `signedPreKeys[].record` | `SignedPreKeyRecord.serialize()` |
| `kyberPreKeys[].record` | `KyberPreKeyRecord.serialize()` |
| `kyberBaseKeys[]` | seen `(kyber prekey id, signed prekey id, base key)` triples |
| `next*Id` | monotonic prekey id allocators (never reused) |

Address keys are `"<uid>.<deviceId>"` (device is always 1, uids are UUIDs, so the
key is unambiguous).

### Working-state vs vault (important)

The landed coordinator (`AppModel.write`) now passes the vault itself:

```swift
vault.transaction {
    let value = try body(vault)   // mutates vault.state inside the transaction
    try vault.save()              // deferred to the commit
    return value
}
```

`SignalService` still never touches `vault.state` for two reasons: the earlier
`inout`-based coordinator shape would have been an overlapping-access trap, and
keeping the service's state separate is what makes rollback exact (one snapshot
restores both the plain state and the ratchet). Therefore:

* `SignalService` owns the live `CryptoState` (`crypto`), registered with the
  vault as `cryptoMirror` in `init`.
* `EncryptedVault` copies the mirror into `state.crypto` at **commit** time and
  restores both on **rollback**.
* Consequence: `vault.state.crypto` is authoritative *between* transactions. Do
  not assign `vault.state.crypto` directly while a service is attached.

`SignalService` methods must be called inside `vault.transaction` (the coordinator
already does this) so ratchet changes are committed atomically with the outbox /
chat message and rolled back on failure. `publicBundle()` may provision missing
prekeys in memory; wrap it in a transaction too. `SignalService` must not open a
transaction itself — the coordinator blocks nesting.

`provisionIfNeeded(oneTimePreKeyCount:)` is available for an explicit refill
(`nil` uses the default of 100); nothing in the UI calls it yet, see §6.

### `save()` semantics

* Outside a transaction: writes immediately (atomically, AES‑GCM sealed).
* Inside a transaction: the write is **deferred to commit**. This makes
  `try vault.save()` inside the body cheap and means a body that throws after
  `save()` leaves the file untouched (previously it would have persisted a
  half-finished change set). The error from a failed commit still propagates out
  of `transaction`, so callers keep a single error path.

`transaction` snapshots the entire `VaultState` (value semantics, including
`crypto`) and restores it on any throw, including a failed commit.

### Storage guarantees

* File: `Application Support/Veil/vault.bin`, protected temporary encrypted file,
  file synchronization then POSIX atomic rename; directory and file excluded
  from backup. Directory protection/backup exclusion failure prevents opening.
  Post-rename directory fsync is best-effort; power-loss durability on a real
  device has not been fault-tested. The commit path never throws after rename,
  avoiding a rollback of memory after the new ratchet is already on disk.
* Payload: `"VEILVLT1" || 0x01 || AES.GCM(combined)`, header used as AAD, so a
  truncated/replaced/foreign blob fails authentication.
* Key: 256-bit `SymmetricKey` in Keychain,
  `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `kSecAttrSynchronizable=false`.
  No export feature or plaintext key file; not derived from a password, no
  plaintext fallback. This is a generic-password Keychain key read into app RAM,
  not a non-exportable Secure Enclave AES key.
* A missing key with an existing file, a wrong key, or a corrupt blob throws
  (`vaultKeyLost` / `vaultCorrupted`); the vault never resets, never deletes, and
  never re-creates an identity.

---

## 4. Protocol behaviour

* `ensureIdentity()` creates the identity **once**. If the identity exists but is
  unparseable — or only half of `{identityKeyPair, registrationId}` is present —
  it throws `corruptedState` and **never regenerates**. This is the "profile
  identity must not silently regenerate when the vault is corrupted" rule.
* `publicBundle()` returns `registration_id`, `device_id`, `identity_key`,
  `signed_prekey`, `kyber_prekey` and up to 100 one-time prekeys. Identity,
  registration id and the signed/kyber prekey are stable across calls.
* `encrypt`:
  * rejects > 4096 **UTF‑8 bytes**;
  * requires a bundle only when no session exists, so an existing ratchet is
    never reset by re-processing a bundle;
  * rejects a bundle whose `identity_key` differs from `Contact.identityKey`
    (byte comparison base64-decoded, not string comparison);
  * after `processPreKeyBundle`, re-checks that the stored pin still equals the
    contact pin.
* `decrypt`:
  * validates recipient uid, both device ids, message type ∈ {2, 3}, base64;
  * for type 3, compares the prekey message's carried identity key with the
    pinned identity **before** handing it to libsignal;
  * relies on libsignal's own `isTrustedIdentity` for type 2 (session-bound);
  * commits the ratchet only on full success (failed/tampered attempts leave the
    store untouched, so the message can be retried).
* Identity policy: first sighting is TOFU; once pinned, a different key is
  rejected (`identityMismatch` / `untrustedIdentity`), and `saveIdentity` throws
  instead of overwriting a pin. `resetPeerTrust(uid:)` exists as an explicit,
  user-confirmed escape hatch; **it is not wired into the UI in v0.1**.
* Integration review fix: `pinContact(_:)` commits the added contact identity
  into the protocol store before any session. `AppModel.addContact` calls it in
  the same transaction as the contact; receive repeats the check for existing
  contacts before decrypt. This prevents first-inbound TOFU from bypassing a
  contact already verified in the UI. Both inbound ciphertext and plaintext
  sizes are bounded (64 KiB / 4096 UTF-8 bytes).

---

## 5. Cross-platform safety number (must match Android exactly)

Swift (this repo):

```swift
NumericFingerprintGenerator(iterations: 5200).create(
    version: 2,
    localIdentifier: Data(localUID.lowercased().utf8),
    localKey: <local identity public key>,
    remoteIdentifier: Data(contactUID.lowercased().utf8),
    remoteKey: <remote identity public key>)
```

Java/Android counterpart (libsignal Java):

```java
new NumericFingerprintGenerator(5200)
    .createFor(2,
               localUid.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8),
               localIdentityKey,
               remoteUid.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8),
               remoteIdentityKey)
    .getDisplayableFingerprint()
    .getDisplayText();
```

Rules:

* `iterations = 5200`, `version = 2`.
* Identifiers are the **lower-case** uid strings encoded as UTF‑8 bytes — the raw
  uid, no `@`, no `:`/device suffix, no UUID binary form.
* Keys are the serialized identity public keys (`0x05 || 32 bytes`), which is what
  `IdentityKey.serialize()` and the Java `IdentityKey` both produce.
* `fingerprint(for:localUID:)` returns the **60 digits with no separators**. The UI
  adds grouping (e.g. `12345 67890 …`); the service must not, otherwise the two
  platforms compare different strings.
* The value is symmetric (libsignal sorts the two 30-digit halves), so both
  parties compute the same 60 digits. The `version` parameter only affects the
  scannable protobuf encoding, not the digits — but keep it at 2 anyway so a
  future QR flow stays compatible.

---

## 6. Limitations (honest)

1. **AGPL‑3.0‑only.** LibSignalClient is AGPL‑licensed. Distributing a Veil build
   that links it triggers AGPL source-availability obligations. This is a
   licensing decision for the project owner, not something the code can fix.
2. **No mobile-side audit.** Protocol code is upstream Signal's, but the store
   glue, identity pinning and storage are unaudited, and no test in this repo has
   been executed on a device (development happened on Linux; see
   `docs/IOS_BUILD.md`).
3. **No signed-prekey rotation.** One signed prekey and one kyber prekey are
   created and kept for the lifetime of the vault.
4. **No multi-device, groups, attachments, sealed sender.** `device_id` is fixed
   at 1; anything else is rejected.
5. **TOFU for first contact.** A first message from an unknown sender is accepted
   and pinned; the UI must prompt for out-of-band fingerprint comparison. A peer
   who reinstalls cannot be re-trusted without an explicit
   `resetPeerTrust(uid:)` (not wired to the UI).
5a. **No prekey refill flow.** The relay stores the 100 one-time prekeys uploaded
   at registration. `RelayClient.uploadPrekeys` exists but is never called, so
   after ~100 new sessions the server returns bundles with an empty
   `one_time_prekeys` array. That still works (PQXDH with signed + kyber prekey,
   covered by a test), but it loses one-time-prekey forward secrecy for new
   sessions. Wiring a refill is a coordinator change, not a crypto change.
6. **4096-byte limit** is on UTF‑8 bytes, no padding.
7. **One `SignalService` per vault.** Two services over one vault would each hold
   a separate `CryptoState` copy.
8. `kyberBaseKeys` and `identities` grow monotonically (bounded by peer count /
   uses; acceptable for v0.1).
9. **Relay-visible metadata.** No sealed sender: the relay sees sender, recipient,
   IP and timing.
10. **Locked-device launch fails closed.** The Keychain item is
    `WhenUnlockedThisDeviceOnly` (as required), so opening the vault while the
    device is locked fails with `keyUnavailable` and the app shows its bootstrap
    failure screen. No data is lost and the next unlocked launch works. This is
    only reachable if the app is ever started without an unlocked device (no
    background modes or push exist in v0.1).

---

## 7. Tests

`ios/VeilTests` (XCTest, run by `scripts/ios-build.sh test` on a simulator):

`ProtocolRoundTripTests`
* full round trip, prekey → whisper, both directions;
* ratchet survives a simulated relaunch (vault file + Keychain key reload);
* out-of-order delivery via skipped message keys (3, 1, 2);
* tampered ciphertext rejected, state unchanged, original still decrypts;
* replayed whisper rejected as `duplicateMessage`;
* 4096-byte limit, including multi-byte UTF‑8;
* bundle identity ≠ contact pin rejected, no session created;
* spoofed sender (valid prekey message from Eve labelled as Bob) rejected and the
  Bob pin preserved;
* wrong recipient / device / message type / base64 rejected;
* bundle without one-time prekey still establishes PQXDH;
* safety number symmetric, 60 digits, case-insensitive uids, differs per identity;
* fingerprint rejects a contact pin that conflicts with the stored identity;
* coordinator-style `inout vault.state` + `save()` transaction commits outbox and
  ratchet and yields a decryptable ciphertext.

`VaultStorageTests`
* state round trip through the sealed file;
* no plaintext (message text, `identity_key_pair`, JSON keys) in the blob;
* rollback on thrown body (no write);
* rollback of the **protocol state** when the disk write fails, then the same
  message still encrypts and decrypts;
* `save()` outside a transaction persists immediately, is a no-op when unchanged;
* corrupted / truncated / foreign / wrong-key blobs throw and keep the file;
* missing Keychain key is fatal and never regenerated;
* unreadable or partial identity is not regenerated;
* snake_case wire encoding and UUIDv7 shape.

They cannot run on Linux: `LibSignalClient` links a Rust static library built only
for Apple platforms.

### What was verified on the Linux host

* Every file in `Models.swift`, `Crypto/` and `Storage/` parses with the Swift
  6.1.3 toolchain (`swiftc -parse`).
* `Models.swift`, `Crypto/*` and `VeilTests/*` **typecheck** in Swift 5 mode
  against a stub module built from the exact `v0.106.0` public signatures
  (`ProtocolAddress`, `IdentityKeyPair`, `PreKeyBundle`, `signalDecryptPreKey`,
  `NumericFingerprintGenerator`, store protocols, …), so label/arity drift in the
  libsignal calls would fail there.
* `Storage/EncryptedVault.swift` + `FileVaultStore.swift` typecheck against
  CryptoKit/iOS-Foundation shims, and the **real vault state machine** was
  executed on Linux with an identity-transform CryptoKit stub: 24 checks covering
  commit, reopen, snapshot rollback (state and crypto mirror), write-failure
  rollback, save idempotence, corrupt-blob rejection and missing-key handling.
* Confidentiality, real AES-GCM, Keychain and libsignal itself are **not**
  verified by any of the above; they need the macOS/simulator run.
