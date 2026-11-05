import Foundation

// MARK: - CryptoState
//
// Serialized, value-typed mirror of everything LibSignalClient keeps for us:
// the identity key pair, registration id, peer identity pins, sessions
// (Double Ratchet / PQXDH session records), prekeys, signed prekeys and kyber
// prekeys. Each record is stored as the exact `serialize()` output of the
// corresponding LibSignalClient record, so it can be handed back to
// `SessionRecord(bytes:)`, `PreKeyRecord(bytes:)`, etc. without any custom
// serialization format.
//
// Nothing here is encrypted in memory; confidentiality comes from
// `EncryptedVault` sealing the whole `VaultState` (which contains this value)
// with AES-GCM before it touches disk.

struct CryptoState: Codable, Equatable {
    struct SessionEntry: Codable, Equatable {
        /// `"<protocol address name>.<device id>"`, e.g. `"<uuid>.1"`.
        var address: String
        var record: Data
    }

    struct IdentityEntry: Codable, Equatable {
        var address: String
        /// Serialized `IdentityKey` (public key only; never a private key).
        var identityKey: Data
    }

    struct PreKeyEntry: Codable, Equatable {
        var id: UInt32
        var record: Data
    }

    struct SignedPreKeyEntry: Codable, Equatable {
        var id: UInt32
        var record: Data
    }

    struct KyberPreKeyEntry: Codable, Equatable {
        var id: UInt32
        var record: Data
    }

    /// Kyber base keys already seen for a (kyber prekey id, signed prekey id)
    /// pair. libsignal rejects a reused base key; persisting this keeps that
    /// protection across app launches.
    struct KyberBaseKeyEntry: Codable, Equatable {
        var kyberPreKeyId: UInt32
        var signedPreKeyId: UInt32
        var baseKey: Data
    }

    /// Both are nil until the profile identity is provisioned. They are set
    /// together; one set without the other means corrupted state, never a
    /// reason to mint a new identity.
    var registrationId: UInt32? = nil
    var identityKeyPair: Data? = nil

    var sessions: [SessionEntry] = []
    var identities: [IdentityEntry] = []
    var preKeys: [PreKeyEntry] = []
    var signedPreKeys: [SignedPreKeyEntry] = []
    var kyberPreKeys: [KyberPreKeyEntry] = []
    var kyberBaseKeys: [KyberBaseKeyEntry] = []

    /// Monotonic id allocators. Prekey ids are never reused so the relay can
    /// reject re-uploads of consumed ids.
    var nextPreKeyId: UInt32 = 1
    var nextSignedPreKeyId: UInt32 = 1
    var nextKyberPreKeyId: UInt32 = 1
}

// MARK: - Lookup / mutation helpers

extension CryptoState {

    var hasIdentity: Bool {
        identityKeyPair != nil && registrationId != nil
    }

    /// Exactly one of the two identity fields is present: corrupted state.
    var hasPartialIdentity: Bool {
        (identityKeyPair == nil) != (registrationId == nil)
    }

    func identityRecord(for address: String) -> Data? {
        identities.first { $0.address == address }?.identityKey
    }

    mutating func setIdentityRecord(_ record: Data, for address: String) {
        if let index = identities.firstIndex(where: { $0.address == address }) {
            identities[index].identityKey = record
        } else {
            identities.append(IdentityEntry(address: address, identityKey: record))
        }
    }

    func sessionRecord(for address: String) -> Data? {
        sessions.first { $0.address == address }?.record
    }

    mutating func setSessionRecord(_ record: Data, for address: String) {
        if let index = sessions.firstIndex(where: { $0.address == address }) {
            sessions[index].record = record
        } else {
            sessions.append(SessionEntry(address: address, record: record))
        }
    }

    mutating func removeSessionRecord(for address: String) {
        sessions.removeAll { $0.address == address }
    }

    func preKeyRecord(id: UInt32) -> Data? {
        preKeys.first { $0.id == id }?.record
    }

    mutating func setPreKeyRecord(_ record: Data, id: UInt32) {
        if let index = preKeys.firstIndex(where: { $0.id == id }) {
            preKeys[index].record = record
        } else {
            preKeys.append(PreKeyEntry(id: id, record: record))
        }
    }

    mutating func removePreKeyRecord(id: UInt32) {
        preKeys.removeAll { $0.id == id }
    }

    func signedPreKeyRecord(id: UInt32) -> Data? {
        signedPreKeys.first { $0.id == id }?.record
    }

    mutating func setSignedPreKeyRecord(_ record: Data, id: UInt32) {
        if let index = signedPreKeys.firstIndex(where: { $0.id == id }) {
            signedPreKeys[index].record = record
        } else {
            signedPreKeys.append(SignedPreKeyEntry(id: id, record: record))
        }
    }

    func kyberPreKeyRecord(id: UInt32) -> Data? {
        kyberPreKeys.first { $0.id == id }?.record
    }

    mutating func setKyberPreKeyRecord(_ record: Data, id: UInt32) {
        if let index = kyberPreKeys.firstIndex(where: { $0.id == id }) {
            kyberPreKeys[index].record = record
        } else {
            kyberPreKeys.append(KyberPreKeyEntry(id: id, record: record))
        }
    }

    /// Drops private prekey material whose public half is already published
    /// and consumed. Used by tests/rotation helpers; normal decryption relies
    /// on libsignal calling `removePreKey`, which the store forwards here.
    mutating func removePublishedOneTimePreKey(id: UInt32) {
        preKeys.removeAll { $0.id == id }
    }
}
