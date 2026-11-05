import CryptoKit
import Foundation
import XCTest

@testable import Veil

// MARK: - Deterministic, side-effect free storage doubles

/// In-memory replacement for the Application Support file. `failWrites` is used
/// to prove that a failed commit rolls the whole state (including ratchets)
/// back instead of leaving memory ahead of disk.
final class MemoryVaultFileStore: VaultFileStoring {
    private(set) var data: Data?
    private(set) var writeCount = 0
    var failWrites = false

    init(data: Data? = nil) {
        self.data = data
    }

    func readEncryptedData() throws -> Data? {
        data
    }

    func writeEncryptedData(_ data: Data) throws {
        writeCount += 1
        if failWrites {
            throw VeilStorageError.writeFailed("simulated disk failure")
        }
        self.data = data
    }

    func overwrite(_ data: Data?) {
        self.data = data
    }
}

final class MemoryVaultKeyStore: VaultKeyProviding {
    var key: SymmetricKey?
    var failCreation = false

    init(key: SymmetricKey? = nil) {
        self.key = key
    }

    func loadKey() throws -> SymmetricKey? {
        key
    }

    func createKey() throws -> SymmetricKey {
        if failCreation {
            throw VeilStorageError.keyCreationFailed("simulated keychain failure")
        }
        let generated = SymmetricKey(size: .bits256)
        key = generated
        return generated
    }
}

// MARK: - Test failure

enum TestFailure: Error, Equatable {
    case boom
}

// MARK: - Peer harness

/// One simulated installation: its own sealed vault file, its own Keychain key
/// and its own `SignalService`.
@MainActor
final class TestPeer {
    let uid: String
    let handle: String
    let fileStore: MemoryVaultFileStore
    let keyStore: MemoryVaultKeyStore
    private(set) var vault: EncryptedVault
    private(set) var service: SignalService
    private(set) var identityKey: String

    init(uid: String = makeUUIDv7(), handle: String) throws {
        let fileStore = MemoryVaultFileStore()
        let keyStore = MemoryVaultKeyStore()
        let vault = try EncryptedVault(fileStore: fileStore, keyStore: keyStore)
        let service = SignalService(vault: vault)
        let bundle = try vault.transaction { try service.publicBundle() }

        self.uid = uid
        self.handle = handle
        self.fileStore = fileStore
        self.keyStore = keyStore
        self.vault = vault
        self.service = service
        self.identityKey = bundle.identityKey
    }

    /// Simulates an app relaunch: new vault object + new service over the same
    /// sealed file and the same Keychain key.
    func relaunch() throws {
        let vault = try EncryptedVault(fileStore: fileStore, keyStore: keyStore)
        self.vault = vault
        self.service = SignalService(vault: vault)
    }

    func currentBundle() throws -> PublicBundle {
        try vault.transaction { try service.publicBundle() }
    }

    func contact(for peer: TestPeer) -> Contact {
        Contact(uid: peer.uid, handle: peer.handle, identityKey: peer.identityKey, verified: false)
    }

    func contact(uid: String, handle: String, identityKey: String) -> Contact {
        Contact(uid: uid, handle: handle, identityKey: identityKey, verified: false)
    }

    func sessionExists(with peer: TestPeer) -> Bool {
        vault.state.crypto.sessionRecord(
            for: SignalAddressing.key(name: peer.uid.lowercased(), deviceId: SignalService.deviceId)
        ) != nil
    }
}

// MARK: - Message helpers

@MainActor
func encryptMessage(
    from sender: TestPeer,
    to recipient: TestPeer,
    text: String,
    bundle: PublicBundle?
) throws -> Envelope {
    let contact = sender.contact(for: recipient)
    let (messageType, ciphertext) = try sender.vault.transaction {
        try sender.service.encrypt(text: text, to: contact, bundle: bundle, localUID: sender.uid)
    }
    return Envelope(
        id: makeUUIDv7(),
        senderUID: sender.uid,
        senderDeviceId: SignalService.deviceId,
        recipientUID: recipient.uid,
        recipientDeviceId: SignalService.deviceId,
        messageType: messageType,
        ciphertext: ciphertext,
        createdAt: Date().timeIntervalSince1970
    )
}

@MainActor
func decryptMessage(_ envelope: Envelope, on peer: TestPeer) throws -> String {
    try peer.vault.transaction {
        try peer.service.decrypt(envelope, localUID: peer.uid)
    }
}

/// Reproduces the coordinator's exact access pattern: an `inout` view of
/// `vault.state` held across the service call, plus an explicit `save()` inside
/// the transaction. If the service ever touched `vault.state` directly this
/// would trip Swift's exclusivity enforcement.
@MainActor
func coordinatorStyleWrite<T>(
    _ vault: EncryptedVault,
    _ body: (inout VaultState) throws -> T
) throws -> T {
    try vault.transaction { () throws -> T in
        let value = try body(&vault.state)
        try vault.save()
        return value
    }
}

/// Flips one byte in the middle of a base64 envelope payload.
func tamperedCiphertext(_ base64: String) -> String {
    guard var bytes = Data(base64Encoded: base64), bytes.count > 8 else { return base64 }
    let index = bytes.startIndex + bytes.count / 2
    bytes[index] ^= 0x01
    return bytes.base64EncodedString()
}
