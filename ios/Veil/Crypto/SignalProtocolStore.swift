import Foundation
import LibSignalClient

/// Marker context for the single local store instance. LibSignalClient passes
/// it back to every store callback so one object can be used as the context of
/// another; Veil has exactly one store per operation, so it is a plain token.
struct VeilStoreContext: StoreContext, Sendable {
    init() {}
}

/// Address key used in `CryptoState`. Names are uids (UUID strings) and the
/// device id is always 1, so `"<uid>.1"` is unambiguous.
enum SignalAddressing {
    static func key(name: String, deviceId: UInt32) -> String {
        "\(name).\(deviceId)"
    }

    static func key(_ address: ProtocolAddress) -> String {
        key(name: address.name, deviceId: address.deviceId)
    }
}

/// LibSignalClient protocol stores backed by a `CryptoState` value.
///
/// One instance is created per cryptographic operation from
/// `vault.state.crypto`; after a successful operation the caller writes
/// `snapshot` back into the vault. If the operation throws, the snapshot is
/// dropped, so a failed decrypt can never leave a half-advanced ratchet in
/// memory or on disk.
///
/// Deliberate policy choices (MVP, documented in CRYPTO_INTEGRATION.md):
/// - First sighting of a peer identity is TOFU (libsignal's default).
/// - Once an identity is pinned, a different one is refused: `saveIdentity`
///   never overwrites a pin, it throws. The UI has no silent re-pin path.
/// - A missing or unreadable identity key pair throws; it is never regenerated
///   implicitly.
final class SignalProtocolStore: IdentityKeyStore, PreKeyStore, SignedPreKeyStore, KyberPreKeyStore, SessionStore {

    private var state: CryptoState

    init(state: CryptoState) {
        self.state = state
    }

    /// Mutable view for the owning operation; only read after success.
    var snapshot: CryptoState {
        state
    }

    // MARK: - IdentityKeyStore

    func identityKeyPair(context: StoreContext) throws -> IdentityKeyPair {
        guard let serialized = state.identityKeyPair else {
            throw VeilCryptoError.identityMissing
        }
        do {
            return try IdentityKeyPair(bytes: serialized)
        } catch {
            throw VeilCryptoError.corruptedState("ключ ідентичності не читається")
        }
    }

    func localRegistrationId(context: StoreContext) throws -> UInt32 {
        guard let registrationId = state.registrationId else {
            throw VeilCryptoError.corruptedState("registration_id відсутній")
        }
        guard (1...16380).contains(registrationId) else {
            throw VeilCryptoError.corruptedState("registration_id поза діапазоном")
        }
        return registrationId
    }

    func saveIdentity(
        _ identity: IdentityKey,
        for address: ProtocolAddress,
        context: StoreContext
    ) throws -> IdentityChange {
        let key = SignalAddressing.key(address)
        let incoming = identity.serialize()

        guard let existing = state.identityRecord(for: key) else {
            state.setIdentityRecord(incoming, for: key)
            return .newOrUnchanged
        }

        guard existing == incoming else {
            // Never silently replace a pinned key: the caller has to go through
            // an explicit user-visible decision.
            throw VeilCryptoError.identityMismatch("збережений ключ співрозмовника відрізняється")
        }
        return .newOrUnchanged
    }

    func isTrustedIdentity(
        _ identity: IdentityKey,
        for address: ProtocolAddress,
        direction: Direction,
        context: StoreContext
    ) throws -> Bool {
        let key = SignalAddressing.key(address)
        guard let existing = state.identityRecord(for: key) else {
            return true // TOFU: first sighting
        }
        return existing == identity.serialize()
    }

    func identity(for address: ProtocolAddress, context: StoreContext) throws -> IdentityKey? {
        guard let serialized = state.identityRecord(for: SignalAddressing.key(address)) else {
            return nil
        }
        do {
            return try IdentityKey(bytes: serialized)
        } catch {
            throw VeilCryptoError.corruptedState("збережений ключ співрозмовника не читається")
        }
    }

    // MARK: - PreKeyStore

    func loadPreKey(id: UInt32, context: StoreContext) throws -> PreKeyRecord {
        guard let serialized = state.preKeyRecord(id: id) else {
            throw SignalError.invalidKeyIdentifier("немає one-time prekey з таким id")
        }
        do {
            return try PreKeyRecord(bytes: serialized)
        } catch {
            throw VeilCryptoError.corruptedState("one-time prekey не читається")
        }
    }

    func storePreKey(_ record: PreKeyRecord, id: UInt32, context: StoreContext) throws {
        state.setPreKeyRecord(record.serialize(), id: id)
    }

    func removePreKey(id: UInt32, context: StoreContext) throws {
        state.removePreKeyRecord(id: id)
    }

    // MARK: - SignedPreKeyStore

    func loadSignedPreKey(id: UInt32, context: StoreContext) throws -> SignedPreKeyRecord {
        guard let serialized = state.signedPreKeyRecord(id: id) else {
            throw SignalError.invalidKeyIdentifier("немає signed prekey з таким id")
        }
        do {
            return try SignedPreKeyRecord(bytes: serialized)
        } catch {
            throw VeilCryptoError.corruptedState("signed prekey не читається")
        }
    }

    func storeSignedPreKey(_ record: SignedPreKeyRecord, id: UInt32, context: StoreContext) throws {
        state.setSignedPreKeyRecord(record.serialize(), id: id)
    }

    // MARK: - KyberPreKeyStore

    func loadKyberPreKey(id: UInt32, context: StoreContext) throws -> KyberPreKeyRecord {
        guard let serialized = state.kyberPreKeyRecord(id: id) else {
            throw SignalError.invalidKeyIdentifier("немає kyber prekey з таким id")
        }
        do {
            return try KyberPreKeyRecord(bytes: serialized)
        } catch {
            throw VeilCryptoError.corruptedState("kyber prekey не читається")
        }
    }

    func storeKyberPreKey(_ record: KyberPreKeyRecord, id: UInt32, context: StoreContext) throws {
        state.setKyberPreKeyRecord(record.serialize(), id: id)
    }

    func markKyberPreKeyUsed(
        id: UInt32,
        signedPreKeyId: UInt32,
        baseKey: PublicKey,
        context: StoreContext
    ) throws {
        let serializedBaseKey = baseKey.serialize()
        let reused = state.kyberBaseKeys.contains {
            $0.kyberPreKeyId == id && $0.signedPreKeyId == signedPreKeyId && $0.baseKey == serializedBaseKey
        }
        guard !reused else {
            // Same shape as InMemorySignalProtocolStore: a repeated base key for
            // the same kyber prekey is a replay, not a new session.
            throw SignalError.invalidMessage("повторне використання base key")
        }
        state.kyberBaseKeys.append(
            CryptoState.KyberBaseKeyEntry(
                kyberPreKeyId: id,
                signedPreKeyId: signedPreKeyId,
                baseKey: serializedBaseKey
            )
        )
    }

    // MARK: - SessionStore

    func loadSession(for address: ProtocolAddress, context: StoreContext) throws -> SessionRecord? {
        guard let serialized = state.sessionRecord(for: SignalAddressing.key(address)) else {
            return nil
        }
        do {
            return try SessionRecord(bytes: serialized)
        } catch {
            throw VeilCryptoError.corruptedState("запис сесії не читається")
        }
    }

    func loadExistingSessions(
        for addresses: [ProtocolAddress],
        context: StoreContext
    ) throws -> [SessionRecord] {
        try addresses.map { address in
            guard let record = try loadSession(for: address, context: context) else {
                throw SignalError.sessionNotFound("немає сесії для \(address.debugDescription)")
            }
            return record
        }
    }

    func storeSession(_ record: SessionRecord, for address: ProtocolAddress, context: StoreContext) throws {
        state.setSessionRecord(record.serialize(), for: SignalAddressing.key(address))
    }

    // MARK: - Extensions used by the service (not part of libsignal protocols)

    func removeSession(for address: ProtocolAddress) {
        state.removeSessionRecord(for: SignalAddressing.key(address))
    }

    func removeIdentity(for address: ProtocolAddress) {
        state.identities.removeAll { $0.address == SignalAddressing.key(address) }
    }
}
