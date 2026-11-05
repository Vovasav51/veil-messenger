import Foundation
import LibSignalClient

/// Genuine libsignal (LibSignalClient) Double Ratchet + PQXDH service for the
/// 1:1 text MVP.
///
/// The service owns the working `CryptoState`; `EncryptedVault` copies it in on
/// commit and restores it on rollback. That keeps the coordinator's
/// `inout VaultState` access free of overlapping accesses, and means a failed
/// encrypt/decrypt never leaves a half-advanced ratchet in memory or on disk.
///
/// Nothing here re-implements cryptography: session setup, ratchets, skipped
/// message keys, MACs and PQXDH KEM are all libsignal's.
@MainActor
final class SignalService: CryptoStateMirroring {

    static let maxMessageBytes = 4096
    static let defaultOneTimePreKeyCount = 100
    static let maxOneTimePreKeysPerBundle = 100
    static let deviceId: UInt32 = 1
    /// Must match the Android client exactly.
    static let fingerprintIterations = 5200
    static let fingerprintVersion = 2
    static let maxRegistrationId: UInt32 = 16380

    private let vault: EncryptedVault
    private let storeContext = VeilStoreContext()
    private var crypto: CryptoState

    init(vault: EncryptedVault) {
        self.vault = vault
        self.crypto = vault.state.crypto
        vault.cryptoMirror = self
    }

    // MARK: - CryptoStateMirroring

    var mirroredCryptoState: CryptoState {
        crypto
    }

    func restoreMirroredCryptoState(_ state: CryptoState) {
        crypto = state
    }

    // MARK: - Provisioning

    var hasIdentity: Bool {
        crypto.hasIdentity
    }

    /// Creates the profile identity once, before registration.
    ///
    /// Existing state is only validated: a missing, partial or unparseable
    /// identity throws instead of being replaced. Losing an identity silently
    /// would break every existing safety number.
    func ensureIdentity() throws {
        if crypto.hasIdentity {
            _ = try requireIdentityKeyPair()
            _ = try requireRegistrationId()
            return
        }

        guard !crypto.hasPartialIdentity else {
            throw VeilCryptoError.corruptedState("ідентичність неповна: є лише частина ключів")
        }

        let identity = IdentityKeyPair.generate()
        let serialized = identity.serialize()
        guard !serialized.isEmpty else {
            throw VeilCryptoError.provisioningFailed("порожній ключ ідентичності")
        }

        var generator = SystemRandomNumberGenerator()
        let registrationId = UInt32.random(in: 1...Self.maxRegistrationId, using: &generator)

        crypto.identityKeyPair = serialized
        crypto.registrationId = registrationId
    }

    /// Ensures identity, signed prekey, kyber prekey and a pool of one-time
    /// prekeys exist. Safe to call repeatedly; only adds what is missing.
    func provisionIfNeeded(oneTimePreKeyCount: Int? = nil) throws {
        let targetPreKeyCount = oneTimePreKeyCount ?? Self.defaultOneTimePreKeyCount
        try ensureIdentity()
        let identity = try requireIdentityKeyPair()

        if crypto.signedPreKeys.isEmpty {
            try addSignedPreKey(identity: identity)
        }
        if crypto.kyberPreKeys.isEmpty {
            try addKyberPreKey(identity: identity)
        }

        let missing = max(0, targetPreKeyCount - crypto.preKeys.count)
        if missing > 0 {
            try addOneTimePreKeys(count: missing)
        }
    }

    // MARK: - Public bundle

    /// Current uploadable bundle.
    ///
    /// May provision missing prekeys in memory; call it inside
    /// `vault.transaction` so the refill is committed atomically with whatever
    /// else the caller is doing. Identity, registration id and the signed/kyber
    /// prekey ids stay stable across calls, as the relay requires.
    func publicBundle() throws -> PublicBundle {
        try provisionIfNeeded()

        let identity = try requireIdentityKeyPair()
        let registrationId = try requireRegistrationId()

        guard let signedEntry = crypto.signedPreKeys.max(by: { $0.id < $1.id }) else {
            throw VeilCryptoError.notProvisioned
        }
        guard let kyberEntry = crypto.kyberPreKeys.max(by: { $0.id < $1.id }) else {
            throw VeilCryptoError.notProvisioned
        }

        let signedRecord = try signedPreKeyRecord(from: signedEntry.record)
        let kyberRecord = try kyberPreKeyRecord(from: kyberEntry.record)

        var oneTimePrekeys: [PublicPreKey] = []
        for entry in crypto.preKeys.sorted(by: { $0.id < $1.id }).prefix(Self.maxOneTimePreKeysPerBundle) {
            do {
                let record = try PreKeyRecord(bytes: entry.record)
                oneTimePrekeys.append(
                    PublicPreKey(
                        id: entry.id,
                        publicKey: try record.publicKey().serialize().base64EncodedString()
                    )
                )
            } catch {
                throw VeilCryptoError.corruptedState("one-time prekey \(entry.id) не читається")
            }
        }

        return PublicBundle(
            registrationId: registrationId,
            deviceId: Self.deviceId,
            identityKey: identity.identityKey.serialize().base64EncodedString(),
            signedPrekey: PublicSignedPreKey(
                id: signedRecord.id,
                publicKey: try signedRecord.publicKey().serialize().base64EncodedString(),
                signature: signedRecord.signature.base64EncodedString()
            ),
            kyberPrekey: PublicSignedPreKey(
                id: kyberRecord.id,
                publicKey: try kyberRecord.publicKey().serialize().base64EncodedString(),
                signature: kyberRecord.signature.base64EncodedString()
            ),
            oneTimePrekeys: oneTimePrekeys
        )
    }

    // MARK: - Encrypt

    /// Pin a user-added directory identity before any session or inbound TOFU.
    /// Must be committed in the same vault transaction as the contact itself.
    func pinContact(_ contact: Contact) throws {
        let bytes = try base64Data(contact.identityKey, field: "contact.identity_key")
        guard bytes.count == 33, bytes.first == 0x05 else {
            throw VeilCryptoError.invalidBundleField("contact.identity_key")
        }
        let identity = try IdentityKey(bytes: bytes)
        let peerAddress = try address(for: contact.uid.lowercased())
        let stores = SignalProtocolStore(state: crypto)
        _ = try stores.saveIdentity(identity, for: peerAddress, context: storeContext)
        crypto = stores.snapshot
    }

    /// Encrypts `text` for `contact`.
    ///
    /// - `bundle` is required only when no session exists yet. It is never
    ///   re-processed while a session is alive, so the ratchet is not reset.
    /// - A pinned contact identity must match the bundle byte-for-byte; a
    ///   replaced identity is rejected instead of being silently re-pinned.
    func encrypt(
        text: String,
        to contact: Contact,
        bundle: PublicBundle?,
        localUID: String
    ) throws -> (UInt8, String) {
        let plaintext = Data(text.utf8)
        guard plaintext.count <= Self.maxMessageBytes else {
            throw VeilCryptoError.messageTooLarge(plaintext.count)
        }
        guard !localUID.isEmpty else {
            throw VeilCryptoError.invalidEnvelope("порожній локальний uid")
        }
        let localUIDNormalized = localUID.lowercased()
        let peerUID = contact.uid.lowercased()
        guard !peerUID.isEmpty, peerUID != localUIDNormalized else {
            throw VeilCryptoError.invalidEnvelope("одержувач збігається з локальним uid")
        }

        _ = try requireIdentityKeyPair()

        let stores = SignalProtocolStore(state: crypto)
        let localAddress = try address(for: localUIDNormalized)
        let peerAddress = try address(for: peerUID)

        let contactPin: Data?
        if contact.identityKey.isEmpty {
            contactPin = nil
        } else {
            contactPin = try base64Data(contact.identityKey, field: "contact.identity_key")
        }

        if let contactPin {
            try verifyStoredPin(contactPin, for: peerAddress, stores: stores, what: "контакт")
        }

        let existingSession = try loadSession(for: peerAddress, stores: stores)

        if let bundle {
            try validateBundle(bundle, contactPin: contactPin)
            if existingSession == nil {
                let preKeyBundle = try makePreKeyBundle(bundle)
                do {
                    try processPreKeyBundle(
                        preKeyBundle,
                        for: peerAddress,
                        ourAddress: localAddress,
                        sessionStore: stores,
                        identityStore: stores,
                        context: storeContext
                    )
                } catch {
                    throw VeilCryptoError.map(error)
                }
            }
            // The bundle must not have silently re-pinned a different identity.
            if let contactPin {
                try verifyStoredPin(contactPin, for: peerAddress, stores: stores, what: "бандл передключів")
            }
        } else if existingSession == nil {
            throw VeilCryptoError.missingBundle
        }

        let message: CiphertextMessage
        do {
            message = try signalEncrypt(
                message: plaintext,
                for: peerAddress,
                localAddress: localAddress,
                sessionStore: stores,
                identityStore: stores,
                context: storeContext
            )
        } catch {
            throw VeilCryptoError.map(error)
        }

        let messageType = message.messageType.rawValue
        guard messageType == 2 || messageType == 3 else {
            // Upstream constants: Whisper = 2, PreKey = 3. The relay only accepts
            // these two, so anything else is a programming error, not a wire case.
            throw VeilCryptoError.unsupportedMessageType(messageType)
        }

        crypto = stores.snapshot
        return (messageType, message.serialize().base64EncodedString())
    }

    // MARK: - Decrypt

    /// Decrypts one envelope. The ratchet, prekey store and identity pins are
    /// only committed when decryption fully succeeds.
    func decrypt(_ envelope: Envelope, localUID: String) throws -> String {
        guard envelope.messageType == 2 || envelope.messageType == 3 else {
            throw VeilCryptoError.unsupportedMessageType(envelope.messageType)
        }
        guard !localUID.isEmpty else {
            throw VeilCryptoError.invalidEnvelope("порожній локальний uid")
        }
        let localUIDNormalized = localUID.lowercased()
        guard envelope.recipientUID.lowercased() == localUIDNormalized else {
            throw VeilCryptoError.invalidEnvelope("конверт адресований іншому отримувачу")
        }
        guard envelope.recipientDeviceId == Self.deviceId, envelope.senderDeviceId == Self.deviceId else {
            throw VeilCryptoError.invalidEnvelope("непідтримуваний device_id")
        }
        guard !envelope.senderUID.isEmpty,
              envelope.senderUID.lowercased() != localUIDNormalized
        else {
            throw VeilCryptoError.invalidEnvelope("некоректний відправник")
        }
        guard let ciphertext = Data(base64Encoded: envelope.ciphertext), !ciphertext.isEmpty else {
            throw VeilCryptoError.invalidCiphertext
        }
        guard ciphertext.count <= 64 * 1024 else {
            throw VeilCryptoError.invalidCiphertext
        }

        _ = try requireIdentityKeyPair()

        let stores = SignalProtocolStore(state: crypto)
        let localAddress = try address(for: localUIDNormalized)
        let senderAddress = try address(for: envelope.senderUID.lowercased())

        // Trust pin check happens against the protocol store, never against the
        // envelope's claimed sender fields.
        let senderPin = stores.snapshot.identityRecord(for: SignalAddressing.key(senderAddress))

        let plaintext: Data
        do {
            switch envelope.messageType {
            case 3:
                let preKeyMessage = try PreKeySignalMessage(bytes: ciphertext)
                if let senderPin {
                    let carriedIdentity = preKeyMessage.identityKey.serialize()
                    guard carriedIdentity == senderPin else {
                        throw VeilCryptoError.identityMismatch("prekey-повідомлення підписане іншим ключем, ніж збережений ключ відправника")
                    }
                }
                plaintext = try signalDecryptPreKey(
                    message: preKeyMessage,
                    from: senderAddress,
                    localAddress: localAddress,
                    sessionStore: stores,
                    identityStore: stores,
                    preKeyStore: stores,
                    signedPreKeyStore: stores,
                    kyberPreKeyStore: stores,
                    context: storeContext
                )
            default:
                let message = try SignalMessage(bytes: ciphertext)
                plaintext = try signalDecrypt(
                    message: message,
                    from: senderAddress,
                    to: localAddress,
                    sessionStore: stores,
                    identityStore: stores,
                    context: storeContext
                )
            }
        } catch let error as VeilCryptoError {
            throw error
        } catch {
            throw VeilCryptoError.map(error)
        }

        // libsignal pinned the sender identity during decryption (TOFU or an
        // exact match). If it now differs from an existing pin, refuse and do
        // not commit anything.
        if let senderPin,
           let stored = stores.snapshot.identityRecord(for: SignalAddressing.key(senderAddress)),
           stored != senderPin {
            throw VeilCryptoError.identityMismatch("ключ відправника змінився під час розшифрування")
        }

        guard plaintext.count <= Self.maxMessageBytes else {
            throw VeilCryptoError.messageTooLarge(plaintext.count)
        }
        guard let text = String(data: plaintext, encoding: .utf8) else {
            throw VeilCryptoError.notUTF8Plaintext
        }

        crypto = stores.snapshot
        return text
    }

    // MARK: - Fingerprint

    /// Safety number, exactly as libsignal computes it and as the Android client
    /// must compute it:
    ///
    ///     NumericFingerprintGenerator(5200).create(
    ///         version: 2,
    ///         localIdentifier: localUID.lowercased().utf8,
    ///         localKey: local identity public key,
    ///         remoteIdentifier: contact.uid.lowercased().utf8,
    ///         remoteKey: contact identity public key)
    ///
    /// Returns the 60-digit displayable fingerprint without separators; the UI
    /// groups the digits. The digits are symmetric: both sides compute the same
    /// string, and the version only affects the scannable protobuf encoding.
    func fingerprint(for contact: Contact, localUID: String) throws -> String {
        let identity = try requireIdentityKeyPair()
        guard !localUID.isEmpty, !contact.uid.isEmpty else {
            throw VeilCryptoError.invalidEnvelope("порожній uid для відбитка")
        }

        let contactPin: Data?
        if contact.identityKey.isEmpty {
            contactPin = nil
        } else {
            contactPin = try base64Data(contact.identityKey, field: "contact.identity_key")
        }

        let storedPin = crypto.identityRecord(
            for: SignalAddressing.key(name: contact.uid.lowercased(), deviceId: Self.deviceId)
        )

        if let contactPin, let storedPin, contactPin != storedPin {
            throw VeilCryptoError.identityMismatch("пін контакту не збігається зі збереженим ключем співрозмовника")
        }
        guard let remoteIdentityData = contactPin ?? storedPin else {
            throw VeilCryptoError.identityMissing
        }

        let remoteKey: PublicKey
        do {
            remoteKey = try PublicKey(remoteIdentityData)
        } catch {
            throw VeilCryptoError.corruptedState("ключ ідентичності контакту не читається")
        }

        let generator = NumericFingerprintGenerator(iterations: Self.fingerprintIterations)
        let fingerprint: Fingerprint
        do {
            fingerprint = try generator.create(
                version: Self.fingerprintVersion,
                localIdentifier: Data(localUID.lowercased().utf8),
                localKey: identity.publicKey,
                remoteIdentifier: Data(contact.uid.lowercased().utf8),
                remoteKey: remoteKey
            )
        } catch {
            throw VeilCryptoError.provisioningFailed("відбиток не обчислюється")
        }

        return Self.digitsOnly(fingerprint.displayable.formatted)
    }

    // MARK: - Explicit trust reset

    /// Forgets the session and the pinned identity for a peer.
    ///
    /// Deliberately explicit: the MVP has no silent re-pin path. A UI that calls
    /// this must first show the fingerprint change and ask the user, exactly like
    /// a "safety number changed" prompt.
    func resetPeerTrust(uid: String) throws {
        let peerAddress = try address(for: uid.lowercased())
        let stores = SignalProtocolStore(state: crypto)
        stores.removeSession(for: peerAddress)
        stores.removeIdentity(for: peerAddress)
        crypto = stores.snapshot
    }

    // MARK: - Bundle validation

    private func validateBundle(_ bundle: PublicBundle, contactPin: Data?) throws {
        guard bundle.deviceId == Self.deviceId else {
            throw VeilCryptoError.invalidBundleField("device_id")
        }
        guard (1...Self.maxRegistrationId).contains(bundle.registrationId) else {
            throw VeilCryptoError.invalidBundleField("registration_id")
        }

        let bundleIdentity = try base64Data(bundle.identityKey, field: "identity_key")
        guard bundleIdentity.count == 33, bundleIdentity.first == 0x05 else {
            throw VeilCryptoError.invalidBundleField("identity_key")
        }
        if let contactPin, bundleIdentity != contactPin {
            throw VeilCryptoError.identityMismatch("бандл передключів містить інший ключ ідентичності, ніж у контакті")
        }

        guard !bundle.signedPrekey.publicKey.isEmpty, !bundle.kyberPrekey.publicKey.isEmpty else {
            throw VeilCryptoError.invalidBundleField("порожній підписаний передключ")
        }
        _ = try publicKey(bundle.signedPrekey.publicKey, field: "signed_prekey.public_key")
        _ = try kemPublicKey(bundle.kyberPrekey.publicKey, field: "kyber_prekey.public_key")
        _ = try base64Data(bundle.signedPrekey.signature, field: "signed_prekey.signature")
        _ = try base64Data(bundle.kyberPrekey.signature, field: "kyber_prekey.signature")

        guard bundle.oneTimePrekeys.count <= Self.maxOneTimePreKeysPerBundle else {
            throw VeilCryptoError.invalidBundleField("one_time_prekeys (забагато)")
        }
        var seen = Set<UInt32>()
        for prekey in bundle.oneTimePrekeys {
            guard seen.insert(prekey.id).inserted else {
                throw VeilCryptoError.invalidBundleField("one_time_prekeys (повтор id)")
            }
            _ = try publicKey(prekey.publicKey, field: "one_time_prekeys.public_key")
        }
    }

    private func makePreKeyBundle(_ bundle: PublicBundle) throws -> PreKeyBundle {
        let identityKey: IdentityKey
        do {
            identityKey = try IdentityKey(bytes: base64Data(bundle.identityKey, field: "identity_key"))
        } catch {
            throw VeilCryptoError.invalidBundleField("identity_key")
        }

        let signedPublic = try publicKey(bundle.signedPrekey.publicKey, field: "signed_prekey.public_key")
        let signedSignature = try base64Data(bundle.signedPrekey.signature, field: "signed_prekey.signature")
        let kyberPublic = try kemPublicKey(bundle.kyberPrekey.publicKey, field: "kyber_prekey.public_key")
        let kyberSignature = try base64Data(bundle.kyberPrekey.signature, field: "kyber_prekey.signature")

        do {
            if let oneTime = bundle.oneTimePrekeys.first {
                let prekey = try publicKey(oneTime.publicKey, field: "one_time_prekeys.public_key")
                return try PreKeyBundle(
                    registrationId: bundle.registrationId,
                    deviceId: bundle.deviceId,
                    prekeyId: oneTime.id,
                    prekey: prekey,
                    signedPrekeyId: bundle.signedPrekey.id,
                    signedPrekey: signedPublic,
                    signedPrekeySignature: signedSignature,
                    identity: identityKey,
                    kyberPrekeyId: bundle.kyberPrekey.id,
                    kyberPrekey: kyberPublic,
                    kyberPrekeySignature: kyberSignature
                )
            }

            // No one-time prekey available (server exhausted the pool): PQXDH
            // still works with the signed + kyber prekey only.
            return try PreKeyBundle(
                registrationId: bundle.registrationId,
                deviceId: bundle.deviceId,
                signedPrekeyId: bundle.signedPrekey.id,
                signedPrekey: signedPublic,
                signedPrekeySignature: signedSignature,
                identity: identityKey,
                kyberPrekeyId: bundle.kyberPrekey.id,
                kyberPrekey: kyberPublic,
                kyberPrekeySignature: kyberSignature
            )
        } catch let error as VeilCryptoError {
            throw error
        } catch {
            throw VeilCryptoError.invalidBundleField("PreKeyBundle відхилено libsignal")
        }
    }

    // MARK: - Prekey generation

    private func addSignedPreKey(identity: IdentityKeyPair) throws {
        let id = try Self.allocate(&crypto.nextSignedPreKeyId)
        let privateKey = PrivateKey.generate()
        let signature = identity.privateKey.generateSignature(message: privateKey.publicKey.serialize())
        do {
            let record = try SignedPreKeyRecord(
                id: id,
                timestamp: Self.nowMilliseconds(),
                privateKey: privateKey,
                signature: signature
            )
            crypto.setSignedPreKeyRecord(record.serialize(), id: id)
        } catch {
            throw VeilCryptoError.provisioningFailed("signed prekey")
        }
    }

    private func addKyberPreKey(identity: IdentityKeyPair) throws {
        let id = try Self.allocate(&crypto.nextKyberPreKeyId)
        let keyPair = KEMKeyPair.generate()
        let publicKey = keyPair.publicKey.serialize()
        let signature = identity.privateKey.generateSignature(message: publicKey)
        do {
            let record = try KyberPreKeyRecord(
                id: id,
                timestamp: Self.nowMilliseconds(),
                keyPair: keyPair,
                signature: signature
            )
            crypto.setKyberPreKeyRecord(record.serialize(), id: id)
        } catch {
            throw VeilCryptoError.provisioningFailed("kyber prekey")
        }
    }

    private func addOneTimePreKeys(count: Int) throws {
        guard count > 0 else { return }
        for _ in 0..<count {
            let id = try Self.allocate(&crypto.nextPreKeyId)
            do {
                let record = try PreKeyRecord(id: id, privateKey: PrivateKey.generate())
                crypto.setPreKeyRecord(record.serialize(), id: id)
            } catch {
                throw VeilCryptoError.provisioningFailed("one-time prekey")
            }
        }
    }

    // MARK: - Small helpers

    private func requireIdentityKeyPair() throws -> IdentityKeyPair {
        guard let serialized = crypto.identityKeyPair else {
            throw VeilCryptoError.identityMissing
        }
        do {
            return try IdentityKeyPair(bytes: serialized)
        } catch {
            throw VeilCryptoError.corruptedState("ключ ідентичності не читається")
        }
    }

    private func requireRegistrationId() throws -> UInt32 {
        guard let registrationId = crypto.registrationId else {
            throw VeilCryptoError.corruptedState("registration_id відсутній")
        }
        guard (1...Self.maxRegistrationId).contains(registrationId) else {
            throw VeilCryptoError.corruptedState("registration_id поза діапазоном")
        }
        return registrationId
    }

    private func signedPreKeyRecord(from data: Data) throws -> SignedPreKeyRecord {
        do {
            return try SignedPreKeyRecord(bytes: data)
        } catch {
            throw VeilCryptoError.corruptedState("signed prekey не читається")
        }
    }

    private func kyberPreKeyRecord(from data: Data) throws -> KyberPreKeyRecord {
        do {
            return try KyberPreKeyRecord(bytes: data)
        } catch {
            throw VeilCryptoError.corruptedState("kyber prekey не читається")
        }
    }

    private func address(for uid: String) throws -> ProtocolAddress {
        guard !uid.isEmpty else {
            throw VeilCryptoError.invalidEnvelope("порожній uid")
        }
        do {
            return try ProtocolAddress(name: uid, deviceId: Self.deviceId)
        } catch {
            throw VeilCryptoError.invalidEnvelope("некоректна адреса протоколу")
        }
    }

    private func loadSession(for address: ProtocolAddress, stores: SignalProtocolStore) throws -> SessionRecord? {
        do {
            return try stores.loadSession(for: address, context: storeContext)
        } catch let error as VeilCryptoError {
            throw error
        } catch {
            throw VeilCryptoError.map(error)
        }
    }

    private func verifyStoredPin(
        _ pin: Data,
        for address: ProtocolAddress,
        stores: SignalProtocolStore,
        what: String
    ) throws {
        guard let stored = try stores.identity(for: address, context: storeContext) else {
            return // nothing pinned yet: TOFU will happen on first use
        }
        guard stored.serialize() == pin else {
            throw VeilCryptoError.identityMismatch("\(what): збережений ключ співрозмовника інший")
        }
    }

    private func base64Data(_ value: String, field: String) throws -> Data {
        guard !value.isEmpty, let data = Data(base64Encoded: value) else {
            throw VeilCryptoError.invalidBundleField(field)
        }
        return data
    }

    private func publicKey(_ value: String, field: String) throws -> PublicKey {
        do {
            return try PublicKey(base64Data(value, field: field))
        } catch let error as VeilCryptoError {
            throw error
        } catch {
            throw VeilCryptoError.invalidBundleField(field)
        }
    }

    private func kemPublicKey(_ value: String, field: String) throws -> KEMPublicKey {
        do {
            return try KEMPublicKey(base64Data(value, field: field))
        } catch let error as VeilCryptoError {
            throw error
        } catch {
            throw VeilCryptoError.invalidBundleField(field)
        }
    }

    private static func allocate(_ next: inout UInt32) throws -> UInt32 {
        guard next != 0 else {
            throw VeilCryptoError.corruptedState("лічильник prekey id зіпсований")
        }
        guard next < UInt32.max else {
            throw VeilCryptoError.idSpaceExhausted
        }
        let id = next
        next = id + 1
        return id
    }

    private static func nowMilliseconds() -> UInt64 {
        UInt64(max(0, Date().timeIntervalSince1970) * 1000)
    }

    private static func digitsOnly(_ value: String) -> String {
        String(value.unicodeScalars.filter { CharacterSet.decimalDigits.contains($0) }.map { Character($0) })
    }
}
