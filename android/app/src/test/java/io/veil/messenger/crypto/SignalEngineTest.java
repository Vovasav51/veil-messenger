package io.veil.messenger.crypto;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.json.JSONObject;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import io.veil.messenger.core.Codec;
import io.veil.messenger.core.InboxProcessor;
import io.veil.messenger.core.SendQueue;
import io.veil.messenger.core.VaultState;
import io.veil.messenger.core.model.Account;
import io.veil.messenger.core.model.Contact;
import io.veil.messenger.core.model.Envelope;
import io.veil.messenger.core.model.OutgoingEnvelope;
import io.veil.messenger.core.model.PublicBundle;

/**
 * End-to-end crypto tests against the real libsignal implementation.
 *
 * <p>These run on a plain JVM: Gradle resolves {@code org.signal:libsignal-client}
 * (the same pinned build as the Android AAR) and the artifact's Linux x86_64
 * JNI library is loaded from the jar. No emulator, no Android Keystore, no
 * fakes: every operation below goes through the official Signal Protocol.
 */
public class SignalEngineTest {

    private static final String ALICE_UID = "0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a01";
    private static final String BOB_UID = "0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a02";
    private static final String EVE_UID = "0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a03";

    private CryptoState alice;
    private CryptoState bob;
    private PublicBundle aliceBundle;
    private PublicBundle bobBundle;

    @Before
    public void setUp() throws Exception {
        alice = new CryptoState();
        bob = new CryptoState();
        SignalEngine.ensureIdentity(alice, SignalEngine.INITIAL_ONE_TIME_PREKEYS);
        SignalEngine.ensureIdentity(bob, SignalEngine.INITIAL_ONE_TIME_PREKEYS);
        aliceBundle = SignalEngine.buildBundle(alice, false);
        bobBundle = SignalEngine.buildBundle(bob, false);
    }

    @Test
    public void identitiesAndBundlesHaveContractShapes() throws Exception {
        assertTrue(alice.hasIdentity());
        assertEquals(1, aliceBundle.deviceId);
        assertTrue(aliceBundle.registrationId >= 1 && aliceBundle.registrationId <= 16380);
        assertEquals(33, Codec.unb64(aliceBundle.identityKey, 33).length);
        assertEquals(33, Codec.unb64(aliceBundle.signedPreKey.publicKey, 33).length);
        assertEquals(64, Codec.unb64(aliceBundle.signedPreKey.signature, 64).length);
        // libsignal serializes KEM public keys with a leading 0x08 type tag.
        assertEquals(PublicBundle.KYBER_PUBLIC_KEY_SERIALIZED_LEN,
                Codec.unb64(aliceBundle.kyberPreKey.publicKey,
                        PublicBundle.KYBER_PUBLIC_KEY_SERIALIZED_LEN).length);
        assertEquals(64, Codec.unb64(aliceBundle.kyberPreKey.signature, 64).length);
        assertEquals(SignalEngine.INITIAL_ONE_TIME_PREKEYS,
                aliceBundle.oneTimePreKeys.size());
        assertNotEquals(aliceBundle.identityKey, bobBundle.identityKey);

        // Bundle must survive the exact wire encoding the relay validates.
        JSONObject wire = aliceBundle.toWireJson();
        PublicBundle reparsed = PublicBundle.fromWire(wire);
        assertEquals(aliceBundle.identityKey, reparsed.identityKey);
        assertEquals(aliceBundle.kyberPreKey.publicKey, reparsed.kyberPreKey.publicKey);
    }

    @Test
    public void roundTripBothDirections() throws Exception {
        SignalEngine.Encrypted first = SignalEngine.encrypt(
                alice, ALICE_UID, BOB_UID, bobBundle.identityKey, bobBundle, Codec.utf8("привіт, Бобе"));
        assertEquals(3, first.messageType); // prekey message establishes the session

        byte[] plaintext = SignalEngine.decrypt(bob, BOB_UID, envelope("m1", ALICE_UID, BOB_UID, first));
        assertEquals("привіт, Бобе", Codec.fromUtf8(plaintext));

        SignalEngine.Encrypted reply = SignalEngine.encrypt(
                bob, BOB_UID, ALICE_UID, aliceBundle.identityKey, null, Codec.utf8("чував, Алісо"));
        assertEquals(2, reply.messageType); // established session uses whisper messages
        assertEquals("чував, Алісо",
                Codec.fromUtf8(SignalEngine.decrypt(alice, ALICE_UID,
                        envelope("m2", BOB_UID, ALICE_UID, reply))));

        assertTrue(SignalEngine.hasSession(alice, BOB_UID));
        assertTrue(SignalEngine.hasSession(bob, ALICE_UID));
    }

    @Test
    public void relabelledRatchetReplayIsNotAckedWithoutDurableEnvelopeId() throws Exception {
        VaultState receiver = VaultState.empty();
        receiver.crypto = bob;
        receiver.account = new Account(BOB_UID, "bob", "test-token", "https://relay.test/");
        SignalEngine.Encrypted first = SignalEngine.encrypt(alice, ALICE_UID, BOB_UID,
                bobBundle.identityKey, bobBundle, Codec.utf8("first"));
        InboxProcessor.process(receiver, envelope("original", ALICE_UID, BOB_UID, first), BOB_UID);
        SignalEngine.Encrypted second = SignalEngine.encrypt(alice, ALICE_UID, BOB_UID,
                bobBundle.identityKey, null, Codec.utf8("second"));
        InboxProcessor.process(receiver, envelope("saved", ALICE_UID, BOB_UID, second), BOB_UID);
        try {
            InboxProcessor.process(receiver, envelope("not-saved", ALICE_UID, BOB_UID, second), BOB_UID);
            fail("Ratchet duplicate alone is not authorization to ACK an uncommitted id");
        } catch (CryptoException expected) {
            assertEquals(CryptoException.Kind.DUPLICATE, expected.kind);
        }
        assertFalse(receiver.isProcessed("not-saved"));
        assertEquals(2, receiver.messages.size());
    }

    @Test
    public void outOfOrderDeliveryUsesSkippedMessageKeys() throws Exception {
        SignalEngine.Encrypted first = SignalEngine.encrypt(
                alice, ALICE_UID, BOB_UID, bobBundle.identityKey, bobBundle, Codec.utf8("1"));
        assertEquals("1", Codec.fromUtf8(SignalEngine.decrypt(bob, BOB_UID,
                envelope("m1", ALICE_UID, BOB_UID, first))));

        List<SignalEngine.Encrypted> later = new ArrayList<>();
        for (int i = 2; i <= 4; i++) {
            later.add(SignalEngine.encrypt(
                    alice, ALICE_UID, BOB_UID, bobBundle.identityKey, null, Codec.utf8("msg" + i)));
        }

        // Deliver 4, then 2, then 3.
        assertEquals("msg4", Codec.fromUtf8(SignalEngine.decrypt(bob, BOB_UID,
                envelope("m4", ALICE_UID, BOB_UID, later.get(2)))));
        assertEquals("msg2", Codec.fromUtf8(SignalEngine.decrypt(bob, BOB_UID,
                envelope("m2", ALICE_UID, BOB_UID, later.get(0)))));
        assertEquals("msg3", Codec.fromUtf8(SignalEngine.decrypt(bob, BOB_UID,
                envelope("m3", ALICE_UID, BOB_UID, later.get(1)))));
    }

    @Test
    public void tamperedCiphertextIsRejected() throws Exception {
        SignalEngine.Encrypted encrypted = SignalEngine.encrypt(
                alice, ALICE_UID, BOB_UID, bobBundle.identityKey, bobBundle, Codec.utf8("секрет"));
        byte[] raw = Codec.unb64(encrypted.ciphertext);
        // Flip one bit in the middle of the authenticated body.
        raw[raw.length / 2] ^= 0x40;
        Envelope tampered = new Envelope("m1", ALICE_UID, 1, BOB_UID, 1,
                encrypted.messageType, Codec.b64(raw), 1700000000L);
        try {
            SignalEngine.decrypt(bob, BOB_UID, tampered);
            fail("tampered ciphertext must not decrypt");
        } catch (CryptoException e) {
            assertEquals(CryptoException.Kind.MALFORMED, e.kind);
        }
    }

    @Test
    public void stateSurvivesJsonReload() throws Exception {
        SignalEngine.Encrypted first = SignalEngine.encrypt(
                alice, ALICE_UID, BOB_UID, bobBundle.identityKey, bobBundle, Codec.utf8("до перезапуску"));
        SignalEngine.decrypt(bob, BOB_UID, envelope("m1", ALICE_UID, BOB_UID, first));

        CryptoState aliceReloaded = reload(alice);
        CryptoState bobReloaded = reload(bob);

        SignalEngine.Encrypted second = SignalEngine.encrypt(
                aliceReloaded, ALICE_UID, BOB_UID, bobBundle.identityKey, null,
                Codec.utf8("після"));
        assertEquals("після", Codec.fromUtf8(SignalEngine.decrypt(bobReloaded, BOB_UID,
                envelope("m2", ALICE_UID, BOB_UID, second))));

        SignalEngine.Encrypted reply = SignalEngine.encrypt(
                bobReloaded, BOB_UID, ALICE_UID, aliceBundle.identityKey, null,
                Codec.utf8("теж після"));
        assertEquals("теж після", Codec.fromUtf8(SignalEngine.decrypt(aliceReloaded, ALICE_UID,
                envelope("m3", BOB_UID, ALICE_UID, reply))));

        // Reloaded state must keep the pinned peer identity, not just sessions.
        assertEquals(bobBundle.identityKey, aliceReloaded.identities.get(BOB_UID));
        assertEquals(aliceBundle.identityKey, bobReloaded.identities.get(ALICE_UID));
    }

    @Test
    public void changedIdentityKeyIsRejected() throws Exception {
        SignalEngine.Encrypted first = SignalEngine.encrypt(
                alice, ALICE_UID, BOB_UID, bobBundle.identityKey, bobBundle, Codec.utf8("справжня Аліса"));
        SignalEngine.decrypt(bob, BOB_UID, envelope("m1", ALICE_UID, BOB_UID, first));

        // An impostor with the same UID but a fresh identity tries to start a
        // session. Bob's unused prekey 1 was consumed by the first message, so
        // the fresh bundle starts at the next available id.
        PublicBundle refreshedBobBundle = SignalEngine.buildBundle(bob, false);
        CryptoState impostor = new CryptoState();
        SignalEngine.ensureIdentity(impostor, SignalEngine.INITIAL_ONE_TIME_PREKEYS);
        SignalEngine.Encrypted forged = SignalEngine.encrypt(
                impostor, ALICE_UID, BOB_UID, refreshedBobBundle.identityKey, refreshedBobBundle,
                Codec.utf8("підміна"));

        try {
            SignalEngine.decrypt(bob, BOB_UID, envelope("m2", ALICE_UID, BOB_UID, forged));
            fail("a changed identity key must be rejected");
        } catch (CryptoException e) {
            assertEquals(CryptoException.Kind.IDENTITY_CHANGED, e.kind);
        }
        // The original pin is intact, so the real Alice still works.
        assertEquals(aliceBundle.identityKey, bob.identities.get(ALICE_UID));
        SignalEngine.Encrypted real = SignalEngine.encrypt(
                alice, ALICE_UID, BOB_UID, bobBundle.identityKey, null, Codec.utf8("справжня знову"));
        assertEquals("справжня знову", Codec.fromUtf8(SignalEngine.decrypt(bob, BOB_UID,
                envelope("m3", ALICE_UID, BOB_UID, real))));
    }

    @Test
    public void signedAndKyberOnlyBundleWithoutOneTimePrekeyWorks() throws Exception {
        // iOS may run out of one-time prekeys and publish signed+Kyber only;
        // the send path must still establish a PQXDH session.
        PublicBundle noOtk = new PublicBundle(
                bobBundle.registrationId, 1, bobBundle.identityKey,
                bobBundle.signedPreKey, bobBundle.kyberPreKey,
                java.util.Collections.emptyList());
        SignalEngine.Encrypted encrypted = SignalEngine.encrypt(
                alice, ALICE_UID, BOB_UID, noOtk.identityKey, noOtk, Codec.utf8("без OTK"));
        assertEquals("без OTK", Codec.fromUtf8(SignalEngine.decrypt(bob, BOB_UID,
                envelope("m1", ALICE_UID, BOB_UID, encrypted))));
    }

    @Test
    public void bare1568ByteKyberKeyIsAccepted() throws Exception {
        // The relay allows the 1568-byte raw Kyber key as well as libsignal's
        // 1569-byte serialized form; both must interoperate.
        byte[] serialized = Codec.unb64(bobBundle.kyberPreKey.publicKey,
                PublicBundle.KYBER_PUBLIC_KEY_SERIALIZED_LEN);
        byte[] bare = new byte[serialized.length - 1];
        System.arraycopy(serialized, 1, bare, 0, bare.length);
        PublicBundle bareBundle = new PublicBundle(
                bobBundle.registrationId, 1, bobBundle.identityKey,
                bobBundle.signedPreKey,
                new PublicBundle.PublicSignedPreKey(
                        bobBundle.kyberPreKey.id, Codec.b64(bare),
                        bobBundle.kyberPreKey.signature),
                bobBundle.oneTimePreKeys);
        SignalEngine.Encrypted encrypted = SignalEngine.encrypt(
                alice, ALICE_UID, BOB_UID, bareBundle.identityKey, bareBundle, Codec.utf8("1568"));
        assertEquals("1568", Codec.fromUtf8(SignalEngine.decrypt(bob, BOB_UID,
                envelope("m1", ALICE_UID, BOB_UID, encrypted))));
    }

    @Test
    public void bundleFromAnotherIdentityIsRejected() throws Exception {
        CryptoState eve = new CryptoState();
        SignalEngine.ensureIdentity(eve, 5);
        PublicBundle eveBundle = SignalEngine.buildBundle(eve, false);
        try {
            SignalEngine.encrypt(alice, ALICE_UID, BOB_UID, bobBundle.identityKey, eveBundle,
                    Codec.utf8("невірний бандл"));
            fail("directory/bundle identity mismatch must be rejected");
        } catch (CryptoException e) {
            assertEquals(CryptoException.Kind.IDENTITY_CHANGED, e.kind);
        }
    }

    @Test
    public void retryReusesTheSameCiphertextAndId() throws Exception {
        VaultState state = new VaultState();
        state.account = new Account(ALICE_UID, "alice", "token", "https://relay.test/");
        state.crypto = alice;
        state.upsertContact(new Contact(BOB_UID, "bob", bobBundle.identityKey, true));

        OutgoingEnvelope queued = SendQueue.enqueue(state, BOB_UID, "черга", bobBundle);
        String originalId = queued.id;
        String originalCiphertext = queued.ciphertext;

        // Simulate a network failure: the outbox is untouched and no new
        // encryption happens. A retry picks up exactly the stored bytes.
        assertEquals(1, state.outbox.size());
        assertEquals(1, state.messages.size());
        OutgoingEnvelope retry = state.findOutbox(originalId);
        assertNotNull(retry);
        assertEquals(originalCiphertext, retry.ciphertext);
        assertEquals(originalId, retry.id);

        // Those stored bytes are exactly what the peer accepts, once.
        assertEquals("черга", Codec.fromUtf8(SignalEngine.decrypt(bob, BOB_UID,
                envelope(originalId, ALICE_UID, BOB_UID,
                        new SignalEngine.Encrypted(retry.messageType, retry.ciphertext)))));

        SendQueue.markSent(state, originalId);
        assertTrue(state.outbox.isEmpty());
        assertEquals("sent", state.findMessage(originalId).status);
    }

    @Test
    public void duplicateCiphertextIsRejectedByTheRatchet() throws Exception {
        SignalEngine.Encrypted first = SignalEngine.encrypt(
                alice, ALICE_UID, BOB_UID, bobBundle.identityKey, bobBundle, Codec.utf8("один раз"));
        Envelope envelope = envelope("m1", ALICE_UID, BOB_UID, first);
        assertEquals("один раз", Codec.fromUtf8(SignalEngine.decrypt(bob, BOB_UID, envelope)));
        try {
            SignalEngine.decrypt(bob, BOB_UID, envelope);
            fail("replayed ciphertext must be rejected");
        } catch (CryptoException e) {
            assertEquals(CryptoException.Kind.DUPLICATE, e.kind);
        }
    }

    @Test
    public void inboxDedupAcksBeforeCryptoAndNeverAcksFailures() throws Exception {
        VaultState state = new VaultState();
        state.account = new Account(BOB_UID, "bob", "token", "https://relay.test/");
        state.crypto = bob;
        state.upsertContact(new Contact(ALICE_UID, "alice", aliceBundle.identityKey, true));

        SignalEngine.Encrypted first = SignalEngine.encrypt(
                alice, ALICE_UID, BOB_UID, bobBundle.identityKey, bobBundle, Codec.utf8("вхідне"));
        Envelope envelope = envelope("m1", ALICE_UID, BOB_UID, first);

        InboxProcessor.Result accepted = InboxProcessor.process(state, envelope, BOB_UID);
        assertTrue(accepted.acknowledge);
        assertFalse(accepted.duplicate);
        assertEquals(1, state.messages.size());
        assertTrue(state.isProcessed("m1"));

        int messageCount = state.messages.size();
        InboxProcessor.Result replay = InboxProcessor.process(state, envelope, BOB_UID);
        assertTrue(replay.acknowledge);
        assertTrue(replay.duplicate);
        assertEquals(messageCount, state.messages.size());

        // Complete the handshake in both directions so the next message is a
        // plain whisper message whose whole body is MAC-protected.
        SignalEngine.Encrypted reply = SignalEngine.encrypt(
                bob, BOB_UID, ALICE_UID, aliceBundle.identityKey, null, Codec.utf8("відповідь"));
        SignalEngine.decrypt(alice, ALICE_UID, envelope("m1r", BOB_UID, ALICE_UID, reply));

        SignalEngine.Encrypted next = SignalEngine.encrypt(
                alice, ALICE_UID, BOB_UID, bobBundle.identityKey, null, Codec.utf8("наступне"));
        assertEquals(2, next.messageType);
        byte[] raw = Codec.unb64(next.ciphertext);
        raw[raw.length / 2] ^= 0x40;
        Envelope broken = new Envelope("m2", ALICE_UID, 1, BOB_UID, 1,
                next.messageType, Codec.b64(raw), 1700000000L);

        VaultState failing = state.copy();
        try {
            InboxProcessor.process(failing, broken, BOB_UID);
            fail("tampered ciphertext must not be accepted");
        } catch (CryptoException e) {
            assertEquals(CryptoException.Kind.MALFORMED, e.kind);
        }
        assertFalse("failed decryption must not be acknowledged",
                failing.isProcessed("m2"));
        assertEquals(messageCount, failing.messages.size());

        // Envelope for somebody else is rejected without ACK.
        Envelope foreign = new Envelope("m3", ALICE_UID, 1, EVE_UID, 1,
                first.messageType, first.ciphertext, 1700000000L);
        try {
            InboxProcessor.process(state, foreign, BOB_UID);
            fail("foreign envelope must be refused");
        } catch (InboxProcessor.Failure expected) {
            assertFalse(state.isProcessed("m3"));
        }
    }

    @Test
    public void textLimitIsEnforcedInBytes() throws Exception {
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < 4096; i++) {
            builder.append('ї'); // 2 bytes in UTF-8
        }
        VaultState state = new VaultState();
        state.account = new Account(ALICE_UID, "alice", "token", "https://relay.test/");
        state.crypto = alice;
        state.upsertContact(new Contact(BOB_UID, "bob", bobBundle.identityKey, true));
        try {
            SendQueue.enqueue(state, BOB_UID, builder.toString(), bobBundle);
            fail("over-limit text must be rejected before encryption");
        } catch (CryptoException e) {
            assertEquals(CryptoException.Kind.TEXT_TOO_LONG, e.kind);
        }
        assertTrue(state.outbox.isEmpty());
        assertTrue(state.messages.isEmpty());
    }

    @Test
    public void fingerprintIsSymmetricAndSixtyDigits() throws Exception {
        String fromAlice = SignalEngine.fingerprint(
                alice, ALICE_UID, BOB_UID, bobBundle.identityKey);
        String fromBob = SignalEngine.fingerprint(
                bob, BOB_UID, ALICE_UID, aliceBundle.identityKey);
        assertEquals(fromAlice, fromBob);
        assertEquals(60, fromAlice.length());
        assertTrue(fromAlice.matches("[0-9]{60}"));
        assertEquals(60, SignalEngine.fingerprint(
                alice, ALICE_UID, EVE_UID, bobBundle.identityKey).length());
    }

    @Test
    public void directoryPinIsEnforcedBeforeFirstInbound() throws Exception {
        VaultState state = new VaultState();
        state.account = new Account(BOB_UID, "bob", "token", "https://relay.test/");
        state.crypto = bob;
        state.upsertContact(new Contact(ALICE_UID, "alice",
                aliceBundle.identityKey, false));
        // What saveContact does when a contact is added from the directory.
        SignalEngine.pinIdentity(bob, ALICE_UID, aliceBundle.identityKey);

        // An impostor with the same UID and a fresh identity sends a prekey
        // message. Bob's unused prekey 1 is still available, so failure can
        // only come from the identity check.
        PublicBundle bobFresh = SignalEngine.buildBundle(bob, false);
        CryptoState impostor = new CryptoState();
        SignalEngine.ensureIdentity(impostor, SignalEngine.INITIAL_ONE_TIME_PREKEYS);
        SignalEngine.Encrypted forged = SignalEngine.encrypt(impostor, ALICE_UID, BOB_UID,
                bobFresh.identityKey, bobFresh, Codec.utf8("підміна до першого вхідного"));
        Envelope forgedEnvelope = envelope("m1", ALICE_UID, BOB_UID, forged);

        try {
            InboxProcessor.process(state, forgedEnvelope, BOB_UID);
            fail("a prekey message with a changed identity must be rejected");
        } catch (CryptoException e) {
            assertEquals(CryptoException.Kind.IDENTITY_CHANGED, e.kind);
        }
        assertFalse(state.isProcessed("m1"));
        assertTrue(state.messages.isEmpty());
        assertEquals(aliceBundle.identityKey, bob.identities.get(ALICE_UID));
    }

    @Test
    public void firstInboundFromUnknownPeerPinsIdentity() throws Exception {
        VaultState state = new VaultState();
        state.account = new Account(BOB_UID, "bob", "token", "https://relay.test/");
        state.crypto = bob;

        SignalEngine.Encrypted first = SignalEngine.encrypt(alice, ALICE_UID, BOB_UID,
                bobBundle.identityKey, bobBundle, Codec.utf8("перше вхідне"));
        InboxProcessor.Result result = InboxProcessor.process(state,
                envelope("m1", ALICE_UID, BOB_UID, first), BOB_UID);

        assertTrue(result.acknowledge);
        assertEquals(aliceBundle.identityKey, bob.identities.get(ALICE_UID));
        assertNotNull(state.findContact(ALICE_UID));
        assertEquals(1, state.messages.size());

        // The pin now blocks a different identity for the same UID.
        PublicBundle bobFresh = SignalEngine.buildBundle(bob, false);
        CryptoState impostor = new CryptoState();
        SignalEngine.ensureIdentity(impostor, 5);
        SignalEngine.Encrypted forged = SignalEngine.encrypt(impostor, ALICE_UID, BOB_UID,
                bobFresh.identityKey, bobFresh, Codec.utf8("інший ключ"));
        try {
            InboxProcessor.process(state, envelope("m2", ALICE_UID, BOB_UID, forged), BOB_UID);
            fail("pinned identity must reject the second key");
        } catch (CryptoException e) {
            assertEquals(CryptoException.Kind.IDENTITY_CHANGED, e.kind);
        }
    }

    @Test
    public void oversizedOrTamperedCiphertextBoundsAreEnforced() throws Exception {
        assertEquals(64 * 1024, Codec.MAX_CIPHERTEXT_BYTES);
        byte[] oversized = new byte[Codec.MAX_CIPHERTEXT_BYTES + 1];
        org.json.JSONObject wire = new org.json.JSONObject();
        wire.put("id", "0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a10");
        wire.put("sender_uid", ALICE_UID);
        wire.put("sender_device_id", 1);
        wire.put("recipient_uid", BOB_UID);
        wire.put("recipient_device_id", 1);
        wire.put("message_type", 2);
        wire.put("ciphertext", Codec.b64(oversized));
        wire.put("created_at", 1700000000L);
        try {
            Envelope.fromWire(wire);
            fail("ciphertext over the 64 KiB relay bound must be rejected");
        } catch (Codec.CodecException expected) {
            // ok
        }
    }

    private static CryptoState reload(CryptoState state) throws Exception {
        return CryptoState.fromJson(new JSONObject(state.toJson().toString()));
    }

    private static Envelope envelope(String id, String from, String to,
                                     SignalEngine.Encrypted encrypted) {
        return new Envelope(id, from, 1, to, 1, encrypted.messageType,
                encrypted.ciphertext, 1700000000L);
    }
}
