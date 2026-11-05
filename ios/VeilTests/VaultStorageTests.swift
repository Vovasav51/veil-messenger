import CryptoKit
import Foundation
import XCTest

@testable import Veil

/// Vault confidentiality, atomicity and corruption behaviour.
final class VaultStorageTests: XCTestCase {

    // MARK: - Round trip

    @MainActor
    func testStateRoundTripsThroughSealedFile() async throws {
        let file = MemoryVaultFileStore()
        let keys = MemoryVaultKeyStore()
        let vault = try EncryptedVault(fileStore: file, keyStore: keys)

        let message = ChatMessage(
            id: makeUUIDv7(),
            peerUID: makeUUIDv7(),
            text: "секретний текст",
            outgoing: true,
            createdAt: Date(timeIntervalSince1970: 1_700_000_000),
            status: "queued"
        )
        try vault.transaction {
            vault.state.account = Account(
                uid: makeUUIDv7(),
                handle: "alice",
                token: "token-123",
                serverURL: "https://relay.example/"
            )
            vault.state.messages.append(message)
            vault.state.processedEnvelopeIDs.append("env-1")
        }

        XCTAssertNotNil(file.data)
        let keyAfterFirstSave = keys.key?.withUnsafeBytes { Data($0) }
        XCTAssertNotNil(keyAfterFirstSave)

        let reopened = try EncryptedVault(fileStore: file, keyStore: keys)
        XCTAssertEqual(reopened.state, vault.state)
        XCTAssertEqual(reopened.state.messages.first?.text, "секретний текст")
        XCTAssertEqual(reopened.state.account?.token, "token-123")
        XCTAssertEqual(
            keys.key?.withUnsafeBytes { Data($0) },
            keyAfterFirstSave,
            "ключ не має змінюватися під час повторного відкриття"
        )
    }

    // MARK: - No plaintext at rest

    @MainActor
    func testVaultFileContainsNoPlaintext() async throws {
        let file = MemoryVaultFileStore()
        let keys = MemoryVaultKeyStore()
        let vault = try EncryptedVault(fileStore: file, keyStore: keys)
        let service = SignalService(vault: vault)

        _ = try vault.transaction { try service.publicBundle() }

        let marker = "PLAINTEXT-MARKER-9f3a"
        try vault.transaction {
            vault.state.messages.append(
                ChatMessage(
                    id: makeUUIDv7(),
                    peerUID: makeUUIDv7(),
                    text: marker,
                    outgoing: false,
                    createdAt: Date(),
                    status: "received"
                )
            )
        }

        let blob = try XCTUnwrap(file.data)
        XCTAssertNil(blob.range(of: Data(marker.utf8)), "plaintext не має бути у файлі")
        XCTAssertNil(blob.range(of: Data("identity_key_pair".utf8)))
        XCTAssertNil(blob.range(of: Data("\"messages\"".utf8)))

        // Sealed with the expected magic + version, not a JSON document.
        var expectedHeader = Data("VEILVLT1".utf8)
        expectedHeader.append(1)
        XCTAssertEqual(blob.prefix(expectedHeader.count), expectedHeader)
        XCTAssertGreaterThan(blob.count, expectedHeader.count + 28)
    }

    // MARK: - Transactions

    @MainActor
    func testTransactionRollsBackOnThrownError() async throws {
        let file = MemoryVaultFileStore()
        let keys = MemoryVaultKeyStore()
        let vault = try EncryptedVault(fileStore: file, keyStore: keys)

        try vault.transaction {
            vault.state.contacts.append(Contact(uid: "u1", handle: "alice", identityKey: "", verified: false))
        }
        let before = vault.state
        let writesBefore = file.writeCount

        XCTAssertThrowsError(
            try vault.transaction {
                vault.state.contacts.append(Contact(uid: "u2", handle: "bob", identityKey: "", verified: false))
                vault.state.messages.append(
                    ChatMessage(id: "m1", peerUID: "u2", text: "x", outgoing: true, createdAt: Date(), status: "queued")
                )
                throw TestFailure.boom
            }
        ) { error in
            XCTAssertEqual(error as? TestFailure, .boom)
        }

        XCTAssertEqual(vault.state, before)
        XCTAssertEqual(file.writeCount, writesBefore, "невдала транзакція не має писати файл")
    }

    @MainActor
    func testTransactionRollsBackProtocolStateOnWriteFailure() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")
        let bundle = try bob.currentBundle()
        let bobContact = alice.contact(for: bob)

        // Establish a session and persist it.
        _ = try encryptMessage(from: alice, to: bob, text: "перше", bundle: bundle)
        let cryptoBefore = alice.vault.state.crypto
        XCTAssertTrue(alice.sessionExists(with: bob))

        alice.fileStore.failWrites = true
        XCTAssertThrowsError(
            try alice.vault.transaction {
                _ = try alice.service.encrypt(text: "друге", to: bobContact, bundle: nil, localUID: alice.uid)
            }
        ) { error in
            XCTAssertEqual(error as? VeilStorageError, .writeFailed("simulated disk failure"))
        }
        XCTAssertEqual(alice.vault.state.crypto, cryptoBefore, "ratchet мусить відкотитися разом зі станом")

        // With the disk healthy again the same message still encrypts and Bob can
        // read it: the rolled-back ratchet was not half-advanced.
        alice.fileStore.failWrites = false
        let envelope = try encryptMessage(from: alice, to: bob, text: "друге", bundle: nil)
        XCTAssertEqual(try decryptMessage(envelope, on: bob), "друге")
    }

    @MainActor
    func testSaveOutsideTransactionPersistsImmediately() async throws {
        let file = MemoryVaultFileStore()
        let keys = MemoryVaultKeyStore()
        let vault = try EncryptedVault(fileStore: file, keyStore: keys)
        XCTAssertNil(file.data)

        vault.state.processedEnvelopeIDs.append("env-1")
        XCTAssertTrue(vault.hasUnsavedChanges)
        try vault.save()
        XCTAssertFalse(vault.hasUnsavedChanges)
        XCTAssertNotNil(file.data)

        let reopened = try EncryptedVault(fileStore: file, keyStore: keys)
        XCTAssertEqual(reopened.state.processedEnvelopeIDs, ["env-1"])

        // Saving an unchanged state does not rewrite the file.
        let writes = file.writeCount
        try vault.save()
        XCTAssertEqual(file.writeCount, writes)
    }

    // MARK: - Corruption is never silently reset

    @MainActor
    func testCorruptedBlobThrowsAndKeepsFile() async throws {
        let file = MemoryVaultFileStore()
        let keys = MemoryVaultKeyStore()
        let vault = try EncryptedVault(fileStore: file, keyStore: keys)

        try vault.transaction {
            vault.state.processedEnvelopeIDs.append("env-1")
        }
        var blob = try XCTUnwrap(file.data)
        blob[blob.count / 2] ^= 0xFF
        file.overwrite(blob)

        XCTAssertThrowsError(try EncryptedVault(fileStore: file, keyStore: keys)) { error in
            guard case VeilStorageError.vaultCorrupted = error else {
                return XCTFail("очікували vaultCorrupted, отримали \(error)")
            }
        }
        XCTAssertEqual(file.data, blob, "пошкоджений файл не має перезаписуватися чи видалятися")
    }

    @MainActor
    func testTruncatedAndForeignBlobsAreRejected() async throws {
        let keys = MemoryVaultKeyStore()
        _ = try keys.createKey()

        let truncated = MemoryVaultFileStore(data: Data("VEILVLT1".utf8))
        XCTAssertThrowsError(try EncryptedVault(fileStore: truncated, keyStore: keys))

        let foreign = MemoryVaultFileStore(data: Data("{\"messages\":[]}".utf8))
        XCTAssertThrowsError(try EncryptedVault(fileStore: foreign, keyStore: keys))
    }

    @MainActor
    func testWrongKeyIsRejected() async throws {
        let file = MemoryVaultFileStore()
        let keys = MemoryVaultKeyStore()
        let vault = try EncryptedVault(fileStore: file, keyStore: keys)
        try vault.transaction {
            vault.state.processedEnvelopeIDs.append("env-1")
        }

        let otherKeys = MemoryVaultKeyStore()
        _ = try otherKeys.createKey()

        XCTAssertThrowsError(try EncryptedVault(fileStore: file, keyStore: otherKeys)) { error in
            guard case VeilStorageError.vaultCorrupted = error else {
                return XCTFail("очікували vaultCorrupted, отримали \(error)")
            }
        }
    }

    @MainActor
    func testMissingKeyIsFatalAndNeverRegenerated() async throws {
        let file = MemoryVaultFileStore()
        let keys = MemoryVaultKeyStore()
        let vault = try EncryptedVault(fileStore: file, keyStore: keys)
        let service = SignalService(vault: vault)
        _ = try vault.transaction { try service.publicBundle() }

        XCTAssertNotNil(keys.key)
        keys.key = nil

        XCTAssertThrowsError(try EncryptedVault(fileStore: file, keyStore: keys)) { error in
            XCTAssertEqual(error as? VeilStorageError, .vaultKeyLost)
        }
        XCTAssertNil(keys.key, "ключ не має створюватися замість втраченого")
    }

    // MARK: - Identity is never regenerated from corrupted crypto state

    @MainActor
    func testUnreadableIdentityIsNotReplaced() async throws {
        let file = MemoryVaultFileStore()
        let keys = MemoryVaultKeyStore()
        let vault = try EncryptedVault(fileStore: file, keyStore: keys)
        let service = SignalService(vault: vault)

        _ = try vault.transaction { try service.publicBundle() }
        let originalIdentity = try XCTUnwrap(vault.state.crypto.identityKeyPair)
        XCTAssertFalse(originalIdentity.isEmpty)

        // Simulate state that authenticates (valid GCM) but whose identity bytes
        // are garbage — exactly what a bug or a partial restore could produce.
        var corrupted = service.mirroredCryptoState
        let garbage = Data([0x01, 0x02, 0x03])
        corrupted.identityKeyPair = garbage
        service.restoreMirroredCryptoState(corrupted)
        try vault.save()

        let reopened = try EncryptedVault(fileStore: file, keyStore: keys)
        let reopenedService = SignalService(vault: reopened)
        XCTAssertEqual(reopened.state.crypto.identityKeyPair, garbage)

        XCTAssertThrowsError(try reopened.transaction { try reopenedService.publicBundle() }) { error in
            guard case VeilCryptoError.corruptedState = error else {
                return XCTFail("очікували corruptedState, отримали \(error)")
            }
        }
        XCTAssertEqual(reopened.state.crypto.identityKeyPair, garbage, "ідентичність не має перегенеровуватися")
    }

    @MainActor
    func testPartialIdentityIsRejectedWithoutRegeneration() async throws {
        let file = MemoryVaultFileStore()
        let keys = MemoryVaultKeyStore()
        let vault = try EncryptedVault(fileStore: file, keyStore: keys)
        let service = SignalService(vault: vault)

        _ = try vault.transaction { try service.publicBundle() }

        var partial = service.mirroredCryptoState
        partial.registrationId = nil
        let identityBefore = partial.identityKeyPair
        service.restoreMirroredCryptoState(partial)
        try vault.save()

        let reopened = try EncryptedVault(fileStore: file, keyStore: keys)
        let reopenedService = SignalService(vault: reopened)

        XCTAssertThrowsError(try reopened.transaction { try reopenedService.publicBundle() }) { error in
            guard case VeilCryptoError.corruptedState = error else {
                return XCTFail("очікували corruptedState, отримали \(error)")
            }
        }
        XCTAssertEqual(reopened.state.crypto.identityKeyPair, identityBefore)
        XCTAssertNil(reopened.state.crypto.registrationId)
    }

    // MARK: - Model contract

    func testWireModelsUseSnakeCase() throws {
        let bundle = PublicBundle(
            registrationId: 42,
            deviceId: 1,
            identityKey: "aWRlbnRpdHk=",
            signedPrekey: PublicSignedPreKey(id: 1, publicKey: "c2lnbmVk", signature: "c2ln"),
            kyberPrekey: PublicSignedPreKey(id: 2, publicKey: "a3liZXI=", signature: "c2ln"),
            oneTimePrekeys: [PublicPreKey(id: 3, publicKey: "b3Rw")]
        )
        let json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(bundle)) as? [String: Any]
        let jsonKeys = Set((json ?? [:]).keys)
        XCTAssertEqual(jsonKeys, Set([
            "registration_id", "device_id", "identity_key",
            "signed_prekey", "kyber_prekey", "one_time_prekeys"
        ]))

        let signed = try XCTUnwrap(json?["signed_prekey"] as? [String: Any])
        XCTAssertEqual(Set(signed.keys), ["id", "public_key", "signature"])

        let decoded = try JSONDecoder().decode(
            PublicBundle.self,
            from: Data("""
            {"registration_id":42,"device_id":1,"identity_key":"aWRlbnRpdHk=",
             "signed_prekey":{"id":1,"public_key":"c2lnbmVk","signature":"c2ln"},
             "kyber_prekey":{"id":2,"public_key":"a3liZXI=","signature":"c2ln"},
             "one_time_prekeys":[{"id":3,"public_key":"b3Rw"}]}
            """.utf8)
        )
        XCTAssertEqual(decoded, bundle)

        let envelope = Envelope(
            id: "e1",
            senderUID: "s",
            senderDeviceId: 1,
            recipientUID: "r",
            recipientDeviceId: 1,
            messageType: 3,
            ciphertext: "abc",
            createdAt: 1_700_000_000
        )
        let envelopeJSON = try JSONSerialization.jsonObject(with: JSONEncoder().encode(envelope)) as? [String: Any]
        let envelopeKeys = Set((envelopeJSON ?? [:]).keys)
        XCTAssertEqual(envelopeKeys, Set([
            "id", "sender_uid", "sender_device_id", "recipient_uid",
            "recipient_device_id", "message_type", "ciphertext", "created_at"
        ]))
    }

    func testUUIDv7Shape() {
        let uuid = makeUUIDv7()
        let parts = uuid.split(separator: "-")
        XCTAssertEqual(uuid.count, 36)
        XCTAssertEqual(parts.count, 5)
        XCTAssertEqual(parts.map(\.count), [8, 4, 4, 4, 12])
        XCTAssertEqual(String(parts[2].prefix(1)), "7", "версія UUID мусить бути 7")
        XCTAssertEqual(uuid, uuid.lowercased())
    }

    func testVaultStateStartsEmptyAndUnprovisioned() {
        let state = VaultState()
        XCTAssertNil(state.account)
        XCTAssertTrue(state.contacts.isEmpty)
        XCTAssertTrue(state.messages.isEmpty)
        XCTAssertTrue(state.outbox.isEmpty)
        XCTAssertTrue(state.processedEnvelopeIDs.isEmpty)
        XCTAssertFalse(state.crypto.hasIdentity)
        XCTAssertFalse(state.crypto.hasPartialIdentity)
        XCTAssertNil(state.crypto.identityKeyPair)
        XCTAssertNil(state.crypto.registrationId)
    }
}
