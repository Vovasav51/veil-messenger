import Foundation
import XCTest

@testable import Veil

/// End-to-end protocol behaviour against the real LibSignalClient pod.
///
/// These tests exercise Double Ratchet + PQXDH, not a stand-in cipher. They run
/// on the iOS simulator only (libsignal links a Rust static library), so they
/// cannot be executed on Linux; they are still real XCTest cases with real
/// assertions.
final class ProtocolRoundTripTests: XCTestCase {

    // MARK: - Basic round trip + persisted ratchet

    @MainActor
    func testRoundTripPersistsRatchetAcrossRelaunch() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")
        let bobBundle = try bob.currentBundle()

        let first = try encryptMessage(from: alice, to: bob, text: "привіт, Бобе", bundle: bobBundle)
        XCTAssertEqual(first.messageType, 3, "перше повідомлення мусить бути prekey (PQXDH)")
        XCTAssertEqual(try decryptMessage(first, on: bob), "привіт, Бобе")
        XCTAssertTrue(alice.sessionExists(with: bob))
        XCTAssertTrue(bob.sessionExists(with: alice))

        let reply = try encryptMessage(from: bob, to: alice, text: "і тобі", bundle: nil)
        XCTAssertEqual(reply.messageType, 2, "відповідь у наявній сесії мусить бути whisper")
        XCTAssertEqual(try decryptMessage(reply, on: alice), "і тобі")

        // Both apps are killed and relaunched: only the sealed vault survives.
        try alice.relaunch()
        try bob.relaunch()

        let afterRestart = try encryptMessage(from: alice, to: bob, text: "після перезапуску", bundle: nil)
        XCTAssertEqual(afterRestart.messageType, 2)
        XCTAssertEqual(try decryptMessage(afterRestart, on: bob), "після перезапуску")

        let afterRestartReply = try encryptMessage(from: bob, to: alice, text: "також", bundle: nil)
        XCTAssertEqual(try decryptMessage(afterRestartReply, on: alice), "також")

        // The reloaded identity is the same key, not a regenerated one.
        XCTAssertEqual(bob.identityKey, try bob.currentBundle().identityKey)
    }

    // MARK: - Out of order delivery

    @MainActor
    func testOutOfOrderDeliveryUsesSkippedMessageKeys() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")

        let handshake = try encryptMessage(from: alice, to: bob, text: "0", bundle: try bob.currentBundle())
        XCTAssertEqual(try decryptMessage(handshake, on: bob), "0")

        let first = try encryptMessage(from: alice, to: bob, text: "1", bundle: nil)
        let second = try encryptMessage(from: alice, to: bob, text: "2", bundle: nil)
        let third = try encryptMessage(from: alice, to: bob, text: "3", bundle: nil)

        XCTAssertEqual(try decryptMessage(third, on: bob), "3")
        XCTAssertEqual(try decryptMessage(first, on: bob), "1")
        XCTAssertEqual(try decryptMessage(second, on: bob), "2")
    }

    // MARK: - Tamper / replay

    @MainActor
    func testTamperedCiphertextIsRejectedWithoutAdvancingRatchet() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")

        let envelope = try encryptMessage(from: alice, to: bob, text: "цілісність", bundle: try bob.currentBundle())
        var tampered = envelope
        tampered.ciphertext = tamperedCiphertext(envelope.ciphertext)
        XCTAssertNotEqual(tampered.ciphertext, envelope.ciphertext)

        let before = bob.vault.state.crypto
        XCTAssertThrowsError(try decryptMessage(tampered, on: bob)) { error in
            guard error is VeilCryptoError else {
                return XCTFail("очікували VeilCryptoError, отримали \(error)")
            }
        }
        XCTAssertEqual(bob.vault.state.crypto, before, "невдала спроба не має змінювати стан протоколу")

        // The untouched message must still decrypt: the failed attempt left no
        // half-consumed prekey or ratchet behind.
        XCTAssertEqual(try decryptMessage(envelope, on: bob), "цілісність")
    }

    @MainActor
    func testReplayedWhisperMessageIsRejected() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")

        _ = try decryptMessage(
            try encryptMessage(from: alice, to: bob, text: "старт", bundle: try bob.currentBundle()),
            on: bob
        )

        let message = try encryptMessage(from: alice, to: bob, text: "один раз", bundle: nil)
        XCTAssertEqual(try decryptMessage(message, on: bob), "один раз")

        let before = bob.vault.state.crypto
        XCTAssertThrowsError(try decryptMessage(message, on: bob)) { error in
            XCTAssertEqual(error as? VeilCryptoError, .duplicateMessage)
        }
        XCTAssertEqual(bob.vault.state.crypto, before)
    }

    // MARK: - Message size limit

    @MainActor
    func testMessageSizeIsLimitedTo4096UTF8Bytes() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")
        let bobBundle = try bob.currentBundle()

        XCTAssertThrowsError(
            try encryptMessage(from: alice, to: bob, text: String(repeating: "a", count: 4097), bundle: bobBundle)
        ) { error in
            guard case VeilCryptoError.messageTooLarge(let bytes) = error else {
                return XCTFail("очікували messageTooLarge, отримали \(error)")
            }
            XCTAssertEqual(bytes, 4097)
        }

        // Multi-byte text: the limit is bytes, not characters.
        XCTAssertThrowsError(
            try encryptMessage(from: alice, to: bob, text: String(repeating: "ї", count: 2049), bundle: bobBundle)
        ) { error in
            guard case VeilCryptoError.messageTooLarge(let bytes) = error else {
                return XCTFail("очікували messageTooLarge, отримали \(error)")
            }
            XCTAssertEqual(bytes, 4098)
        }

        let exact = String(repeating: "b", count: 4096)
        let envelope = try encryptMessage(from: alice, to: bob, text: exact, bundle: bobBundle)
        XCTAssertEqual(try decryptMessage(envelope, on: bob).utf8.count, 4096)
    }

    // MARK: - Identity pinning

    @MainActor
    func testBundleIdentityMustMatchContactPin() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")
        let mallory = try TestPeer(handle: "mallory")

        let bobContact = alice.contact(for: bob)
        let malloryBundle = try mallory.currentBundle()
        XCTAssertNotEqual(malloryBundle.identityKey, bobContact.identityKey)

        let before = alice.vault.state.crypto
        XCTAssertThrowsError(
            try alice.vault.transaction {
                try alice.service.encrypt(text: "підміна", to: bobContact, bundle: malloryBundle, localUID: alice.uid)
            }
        ) { error in
            guard case VeilCryptoError.identityMismatch = error else {
                return XCTFail("очікували identityMismatch, отримали \(error)")
            }
        }
        XCTAssertEqual(alice.vault.state.crypto, before)
        XCTAssertFalse(alice.sessionExists(with: bob), "підмінений бандл не має створювати сесію")
    }

    /// Envelope metadata is not authentication: a prekey message produced by a
    /// different identity but labelled with a known peer's uid must be refused
    /// and must not replace the pin.
    @MainActor
    func testSpoofedSenderIdentityIsRejectedAndPinPreserved() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")
        let eve = try TestPeer(handle: "eve")

        // Establishes a session and pins Bob's identity on Alice's side.
        _ = try encryptMessage(from: alice, to: bob, text: "привіт", bundle: try bob.currentBundle())

        let bobAddressKey = SignalAddressing.key(name: bob.uid.lowercased(), deviceId: SignalService.deviceId)
        let bobPin = alice.vault.state.crypto.identityRecord(for: bobAddressKey)
        XCTAssertNotNil(bobPin)

        // Eve encrypts a perfectly valid prekey message to Alice, then we relabel
        // it as if it came from Bob.
        let aliceBundle = try alice.currentBundle()
        let aliceContact = eve.contact(uid: alice.uid, handle: alice.handle, identityKey: aliceBundle.identityKey)
        let (messageType, ciphertext) = try eve.vault.transaction {
            try eve.service.encrypt(text: "я Боб", to: aliceContact, bundle: aliceBundle, localUID: eve.uid)
        }
        XCTAssertEqual(messageType, 3)

        let spoofed = Envelope(
            id: makeUUIDv7(),
            senderUID: bob.uid,
            senderDeviceId: SignalService.deviceId,
            recipientUID: alice.uid,
            recipientDeviceId: SignalService.deviceId,
            messageType: messageType,
            ciphertext: ciphertext,
            createdAt: Date().timeIntervalSince1970
        )

        let before = alice.vault.state.crypto
        XCTAssertThrowsError(try decryptMessage(spoofed, on: alice)) { error in
            guard case VeilCryptoError.identityMismatch = error else {
                return XCTFail("очікували identityMismatch, отримали \(error)")
            }
        }
        XCTAssertEqual(alice.vault.state.crypto, before)
        XCTAssertEqual(alice.vault.state.crypto.identityRecord(for: bobAddressKey), bobPin)
    }

    // MARK: - Envelope validation

    @MainActor
    func testContactPinsIdentityBeforeAnySession() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")
        let eve = try TestPeer(handle: "eve")
        let contact = alice.contact(for: bob)

        try alice.vault.transaction { try alice.service.pinContact(contact) }
        XCTAssertFalse(alice.sessionExists(with: bob))
        let key = SignalAddressing.key(name: bob.uid.lowercased(), deviceId: 1)
        XCTAssertEqual(alice.vault.state.crypto.identityRecord(for: key), Data(base64Encoded: bob.identityKey))

        let wrong = Contact(uid: bob.uid, handle: bob.handle, identityKey: eve.identityKey, verified: true)
        let before = alice.vault.state.crypto
        XCTAssertThrowsError(try alice.vault.transaction { try alice.service.pinContact(wrong) })
        XCTAssertEqual(alice.vault.state.crypto, before)

        // Simulate a malicious relay/client presenting Eve's key under Bob's
        // address; address binding alone must not be our contact-key policy.
        let bundle = try alice.currentBundle()
        let (type, ciphertext) = try eve.vault.transaction {
            try eve.service.encrypt(text: "not Bob", to: eve.contact(for: alice), bundle: bundle, localUID: bob.uid)
        }
        let spoofed = Envelope(id: makeUUIDv7(), senderUID: bob.uid, senderDeviceId: 1,
                               recipientUID: alice.uid, recipientDeviceId: 1,
                               messageType: type, ciphertext: ciphertext, createdAt: Date().timeIntervalSince1970)
        XCTAssertThrowsError(try decryptMessage(spoofed, on: alice))
        XCTAssertEqual(alice.vault.state.crypto, before)
    }

    @MainActor
    func testEnvelopeForAnotherRecipientIsRejected() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")
        let mallory = try TestPeer(handle: "mallory")

        let envelope = try encryptMessage(from: alice, to: bob, text: "не тобі", bundle: try bob.currentBundle())

        var wrongRecipient = envelope
        wrongRecipient.recipientUID = mallory.uid
        XCTAssertThrowsError(try decryptMessage(wrongRecipient, on: bob)) { error in
            guard case VeilCryptoError.invalidEnvelope = error else {
                return XCTFail("очікували invalidEnvelope, отримали \(error)")
            }
        }

        var wrongDevice = envelope
        wrongDevice.recipientDeviceId = 2
        XCTAssertThrowsError(try decryptMessage(wrongDevice, on: bob))

        var wrongType = envelope
        wrongType.messageType = 1
        XCTAssertThrowsError(try decryptMessage(wrongType, on: bob)) { error in
            XCTAssertEqual(error as? VeilCryptoError, .unsupportedMessageType(1))
        }

        var badBase64 = envelope
        badBase64.ciphertext = "not base64!!"
        XCTAssertThrowsError(try decryptMessage(badBase64, on: bob)) { error in
            XCTAssertEqual(error as? VeilCryptoError, .invalidCiphertext)
        }

        // Nothing above consumed the prekey; the real envelope still works.
        XCTAssertEqual(try decryptMessage(envelope, on: bob), "не тобі")
    }

    // MARK: - Bundle without one-time prekey

    @MainActor
    func testBundleWithoutOneTimePreKeyStillEstablishesPQXDH() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")

        var bundle = try bob.currentBundle()
        XCTAssertFalse(bundle.oneTimePrekeys.isEmpty)
        bundle.oneTimePrekeys = []

        let envelope = try encryptMessage(from: alice, to: bob, text: "без OTP", bundle: bundle)
        XCTAssertEqual(envelope.messageType, 3)
        XCTAssertEqual(try decryptMessage(envelope, on: bob), "без OTP")
    }

    // MARK: - Fingerprint

    @MainActor
    func testFingerprintIsSymmetricAndMatchesSignalFormat() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")

        let aliceView = try alice.service.fingerprint(for: alice.contact(for: bob), localUID: alice.uid)
        let bobView = try bob.service.fingerprint(for: bob.contact(for: alice), localUID: bob.uid)

        XCTAssertEqual(aliceView, bobView, "відбиток мусить бути однаковим з обох боків")
        XCTAssertEqual(aliceView.count, 60, "libsignal displayable fingerprint — 60 цифр")
        XCTAssertTrue(aliceView.allSatisfy { $0.isNumber })
        XCTAssertFalse(aliceView.contains(" "), "UI додає пробіли, сервіс повертає лише цифри")

        // Identifier casing must not matter (Android uses lower-case uid bytes).
        let upperCase = try alice.service.fingerprint(
            for: Contact(uid: bob.uid.uppercased(), handle: bob.handle, identityKey: bob.identityKey, verified: false),
            localUID: alice.uid.uppercased()
        )
        XCTAssertEqual(aliceView, upperCase)

        // A different identity must produce a different fingerprint.
        let eve = try TestPeer(handle: "eve")
        let eveView = try alice.service.fingerprint(for: alice.contact(for: eve), localUID: alice.uid)
        XCTAssertNotEqual(aliceView, eveView)
    }

    @MainActor
    func testFingerprintRejectsContactPinThatConflictsWithStore() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")

        _ = try encryptMessage(from: alice, to: bob, text: "pin", bundle: try bob.currentBundle())

        let eve = try TestPeer(handle: "eve")
        // Contact claims Bob's uid but carries Eve's key while the store already
        // pinned Bob's key.
        let conflicting = Contact(uid: bob.uid, handle: bob.handle, identityKey: eve.identityKey, verified: false)
        XCTAssertThrowsError(try alice.service.fingerprint(for: conflicting, localUID: alice.uid)) { error in
            guard case VeilCryptoError.identityMismatch = error else {
                return XCTFail("очікували identityMismatch, отримали \(error)")
            }
        }
    }

    // MARK: - Coordinator access pattern / transactional commit

    @MainActor
    func testCoordinatorStyleTransactionCommitsOutboxAndRatchet() async throws {
        let alice = try TestPeer(handle: "alice")
        let bob = try TestPeer(handle: "bob")
        let bobBundle = try bob.currentBundle()
        let bobContact = alice.contact(for: bob)

        try coordinatorStyleWrite(alice.vault) { state in
            let (messageType, ciphertext) = try alice.service.encrypt(
                text: "через координатор",
                to: bobContact,
                bundle: bobBundle,
                localUID: alice.uid
            )
            state.outbox.append(
                OutgoingEnvelope(
                    id: makeUUIDv7(),
                    recipientUID: bob.uid,
                    recipientDeviceId: SignalService.deviceId,
                    messageType: messageType,
                    ciphertext: ciphertext
                )
            )
            state.messages.append(
                ChatMessage(
                    id: makeUUIDv7(),
                    peerUID: bob.uid,
                    text: "через координатор",
                    outgoing: true,
                    createdAt: Date(),
                    status: "queued"
                )
            )
        }

        XCTAssertEqual(alice.vault.state.outbox.count, 1)
        XCTAssertEqual(alice.vault.state.messages.count, 1)
        XCTAssertTrue(alice.sessionExists(with: bob))
        XCTAssertNotNil(alice.fileStore.data, "коміт мусить записати файл сховища")

        // The persisted outbox ciphertext decrypts for Bob.
        let stored = try XCTUnwrap(alice.vault.state.outbox.first)
        let envelope = Envelope(
            id: stored.id,
            senderUID: alice.uid,
            senderDeviceId: SignalService.deviceId,
            recipientUID: bob.uid,
            recipientDeviceId: SignalService.deviceId,
            messageType: stored.messageType,
            ciphertext: stored.ciphertext,
            createdAt: Date().timeIntervalSince1970
        )
        XCTAssertEqual(try decryptMessage(envelope, on: bob), "через координатор")
    }
}
