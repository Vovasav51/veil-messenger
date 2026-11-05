import Foundation

// MARK: - Shared value types
//
// Owned by the crypto/storage agent; see SPEC.md "Swift shared types".
// Everything here is a Codable value type. Wire types use explicit snake_case
// CodingKeys so that JSONEncoder/JSONDecoder default key strategies stay in
// place (and so a server-side field rename is a compile-time-visible diff).
//
// No type in this file may carry plaintext secrets that are not already
// protected by the encrypted vault; `Account.token` is only ever persisted
// inside `VaultState`.

// MARK: Public prekey material

struct PublicPreKey: Codable, Equatable, Sendable {
    var id: UInt32
    var publicKey: String

    enum CodingKeys: String, CodingKey {
        case id
        case publicKey = "public_key"
    }
}

struct PublicSignedPreKey: Codable, Equatable, Sendable {
    var id: UInt32
    var publicKey: String
    var signature: String

    enum CodingKeys: String, CodingKey {
        case id
        case signature
        case publicKey = "public_key"
    }
}

/// Wire representation of a Signal prekey bundle (PQXDH / kyber variant).
///
/// The kyber fields are mandatory: LibSignalClient >= 0.4x refuses to build a
/// PQXDH session without them, so a bundle missing `kyber_prekey` is rejected
/// instead of silently falling back to classic X3DH.
struct PublicBundle: Codable, Equatable, Sendable {
    var registrationId: UInt32
    var deviceId: UInt32
    var identityKey: String
    var signedPrekey: PublicSignedPreKey
    var kyberPrekey: PublicSignedPreKey
    var oneTimePrekeys: [PublicPreKey]

    enum CodingKeys: String, CodingKey {
        case registrationId = "registration_id"
        case deviceId = "device_id"
        case identityKey = "identity_key"
        case signedPrekey = "signed_prekey"
        case kyberPrekey = "kyber_prekey"
        case oneTimePrekeys = "one_time_prekeys"
    }
}

// MARK: Local state

struct Account: Codable, Equatable, Sendable {
    var uid: String
    var handle: String
    var token: String
    var serverURL: String

    enum CodingKeys: String, CodingKey {
        case uid
        case handle
        case token
        case serverURL = "server_url"
    }
}

struct Contact: Codable, Equatable, Identifiable, Sendable {
    var uid: String
    var handle: String
    /// Base64 of the serialized Signal identity public key (`IdentityKey.serialize()`).
    /// This is the trust pin: it is compared byte-for-byte against the directory,
    /// the fetched bundle and the pinned store entry. An empty string means
    /// "not pinned yet" (first-use TOFU) and is only produced by tests/tools.
    var identityKey: String
    var verified: Bool

    var id: String { uid }

    enum CodingKeys: String, CodingKey {
        case uid
        case handle
        case verified
        case identityKey = "identity_key"
    }
}

struct ChatMessage: Codable, Equatable, Identifiable, Sendable {
    var id: String
    var peerUID: String
    var text: String
    var outgoing: Bool
    var createdAt: Date
    /// One of `queued`, `sent`, `received`.
    var status: String

    enum CodingKeys: String, CodingKey {
        case id
        case text
        case outgoing
        case status
        case peerUID = "peer_uid"
        case createdAt = "created_at"
    }
}

struct Envelope: Codable, Equatable, Identifiable, Sendable {
    var id: String
    var senderUID: String
    var senderDeviceId: UInt32
    var recipientUID: String
    var recipientDeviceId: UInt32
    var messageType: UInt8
    var ciphertext: String
    var createdAt: Double

    enum CodingKeys: String, CodingKey {
        case id
        case ciphertext
        case senderUID = "sender_uid"
        case senderDeviceId = "sender_device_id"
        case recipientUID = "recipient_uid"
        case recipientDeviceId = "recipient_device_id"
        case messageType = "message_type"
        case createdAt = "created_at"
    }
}

struct OutgoingEnvelope: Codable, Equatable, Identifiable, Sendable {
    var id: String
    var recipientUID: String
    var recipientDeviceId: UInt32
    var messageType: UInt8
    var ciphertext: String

    enum CodingKeys: String, CodingKey {
        case id
        case ciphertext
        case recipientUID = "recipient_uid"
        case recipientDeviceId = "recipient_device_id"
        case messageType = "message_type"
    }
}

/// Root persisted state. Stored only as an AES-GCM sealed blob; see
/// `EncryptedVault`. Every field is a value type so a snapshot is a deep copy.
struct VaultState: Codable, Equatable {
    var account: Account?
    var contacts: [Contact]
    var messages: [ChatMessage]
    var outbox: [OutgoingEnvelope]
    var processedEnvelopeIDs: [String]
    /// Everything LibSignalClient needs, serialized as value records.
    var crypto: CryptoState

    init(
        account: Account? = nil,
        contacts: [Contact] = [],
        messages: [ChatMessage] = [],
        outbox: [OutgoingEnvelope] = [],
        processedEnvelopeIDs: [String] = [],
        crypto: CryptoState = CryptoState()
    ) {
        self.account = account
        self.contacts = contacts
        self.messages = messages
        self.outbox = outbox
        self.processedEnvelopeIDs = processedEnvelopeIDs
        self.crypto = crypto
    }
}

// MARK: - UUID v7

/// Time-ordered UUID (RFC 9562 version 7) as a lower-case string.
///
/// Only used for message/uid identifiers; it is not a security primitive.
func makeUUIDv7() -> String {
    var bytes = [UInt8](repeating: 0, count: 16)
    var rng = SystemRandomNumberGenerator()
    for index in 0..<bytes.count {
        bytes[index] = UInt8.random(in: UInt8.min...UInt8.max, using: &rng)
    }

    let milliseconds = UInt64(Date().timeIntervalSince1970 * 1000) & 0x0000_FFFF_FFFF_FFFF
    for index in 0..<6 {
        bytes[index] = UInt8(truncatingIfNeeded: milliseconds >> (8 * UInt64(5 - index)))
    }
    bytes[6] = (bytes[6] & 0x0F) | 0x70
    bytes[8] = (bytes[8] & 0x3F) | 0x80

    let hex = bytes.map { String(format: "%02x", $0) }.joined()
    let groups = [
        String(hex.prefix(8)),
        String(hex.dropFirst(8).prefix(4)),
        String(hex.dropFirst(12).prefix(4)),
        String(hex.dropFirst(16).prefix(4)),
        String(hex.dropFirst(20).prefix(12))
    ]
    return groups.joined(separator: "-")
}
