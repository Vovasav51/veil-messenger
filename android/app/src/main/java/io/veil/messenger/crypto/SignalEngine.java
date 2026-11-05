package io.veil.messenger.crypto;

import io.veil.messenger.core.Codec;
import io.veil.messenger.core.model.Envelope;
import io.veil.messenger.core.model.PublicBundle;
import org.signal.libsignal.protocol.DuplicateMessageException;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.NoSessionException;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.UntrustedIdentityException;
import org.signal.libsignal.protocol.ecc.ECKeyPair;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.fingerprint.Fingerprint;
import org.signal.libsignal.protocol.fingerprint.NumericFingerprintGenerator;
import org.signal.libsignal.protocol.kem.KEMKeyPair;
import org.signal.libsignal.protocol.kem.KEMKeyType;
import org.signal.libsignal.protocol.kem.KEMPublicKey;
import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.message.PreKeySignalMessage;
import org.signal.libsignal.protocol.message.SignalMessage;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyBundle;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.util.KeyHelper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Thin, deterministic wrapper around the official libsignal client.
 *
 * <p>This class is intentionally Android-free: it operates on {@link CryptoState}
 * and plain model objects, so the same code path is exercised by JVM unit tests
 * with the Linux JNI build of libsignal.
 *
 * <p>Nothing here attempts to reimplement the Signal Protocol. Key generation,
 * X3DH/PQXDH, double ratchet, MAC verification and fingerprinting all come from
 * {@code org.signal:libsignal-*}.
 */
public final class SignalEngine {

    public static final int DEVICE_ID = 1;
    public static final int MAX_TEXT_BYTES = 4096;
    public static final int INITIAL_ONE_TIME_PREKEYS = 100;
    public static final int PREKEY_LOW_WATER = 20;
    public static final int PREKEY_REFILL = 80;

    /** Signal numeric fingerprint parameters, agreed with the iOS client. */
    public static final int FINGERPRINT_VERSION = 2;
    public static final int FINGERPRINT_ITERATIONS = 5200;

    private SignalEngine() {
    }

    // --- local identity and bundles -----------------------------------------

    /**
     * Creates the local identity, signed prekey, Kyber prekey and one-time
     * prekeys if they do not exist yet. Idempotent.
     */
    public static void ensureIdentity(CryptoState state, int oneTimePreKeyCount)
            throws CryptoException {
        if (state.hasIdentity()) {
            return;
        }
        try {
            IdentityKeyPair pair = IdentityKeyPair.generate();
            state.identityKeyPair = Codec.b64(pair.serialize());
            state.registrationId = KeyHelper.generateRegistrationId(false);
            if (state.registrationId < 1 || state.registrationId > 16380) {
                throw new CryptoException(CryptoException.Kind.INTERNAL,
                        "generated registration id is out of range");
            }

            long now = System.currentTimeMillis();
            ECKeyPair signedKeyPair = ECKeyPair.generate();
            byte[] signedSignature = pair.getPrivateKey()
                    .calculateSignature(signedKeyPair.getPublicKey().serialize());
            SignedPreKeyRecord signedRecord = new SignedPreKeyRecord(
                    1, now, signedKeyPair, signedSignature);
            state.signedPreKey = new CryptoState.SignedPreKeyState(
                    1, now, Codec.b64(signedRecord.serialize()));
            state.nextKyberPreKeyId = 2;

            KEMKeyPair kyberKeyPair = KEMKeyPair.generate(KEMKeyType.KYBER_1024);
            byte[] kyberSignature = pair.getPrivateKey()
                    .calculateSignature(kyberKeyPair.getPublicKey().serialize());
            KyberPreKeyRecord kyberRecord = new KyberPreKeyRecord(
                    1, now, kyberKeyPair, kyberSignature);
            state.kyberPreKey = new CryptoState.KyberPreKeyState(
                    1, now, Codec.b64(kyberRecord.serialize()));

            state.nextPreKeyId = 1;
            addOneTimePreKeys(state, Math.max(0, oneTimePreKeyCount));
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException(CryptoException.Kind.INTERNAL,
                    "failed to generate identity material", e);
        }
    }

    /** Generates additional one-time prekeys, advancing the id counter. */
    public static void addOneTimePreKeys(CryptoState state, int count) throws CryptoException {
        if (count <= 0) {
            return;
        }
        try {
            for (int i = 0; i < count; i++) {
                int id = state.nextPreKeyId++;
                PreKeyRecord record = new PreKeyRecord(id, ECKeyPair.generate());
                state.oneTimePreKeys.add(new CryptoState.PreKeyState(
                        id, Codec.b64(record.serialize())));
            }
        } catch (Exception e) {
            throw new CryptoException(CryptoException.Kind.INTERNAL,
                    "failed to generate one-time prekeys", e);
        }
    }

    /**
     * Builds the public bundle from local state.
     *
     * @param onlyNotYetUploaded when true, only prekeys whose ids were never
     *                           uploaded are included (needed by PUT /v1/prekeys,
     *                           which rejects re-uploaded consumed ids).
     */
    public static PublicBundle buildBundle(CryptoState state, boolean onlyNotYetUploaded)
            throws CryptoException {
        if (!state.hasIdentity() || state.signedPreKey == null || state.kyberPreKey == null) {
            throw new CryptoException(CryptoException.Kind.NO_IDENTITY,
                    "local identity is not initialised");
        }
        try {
            IdentityKeyPair pair = new IdentityKeyPair(Codec.unb64(state.identityKeyPair, 512));
            SignedPreKeyRecord signed = new SignedPreKeyRecord(
                    Codec.unb64(state.signedPreKey.record, 4096));
            KyberPreKeyRecord kyber = new KyberPreKeyRecord(
                    Codec.unb64(state.kyberPreKey.record, 8192));

            List<PublicBundle.PublicPreKey> otks = new ArrayList<>();
            for (CryptoState.PreKeyState stored : state.oneTimePreKeys) {
                if (onlyNotYetUploaded && stored.id <= state.lastUploadedPreKeyId) {
                    continue;
                }
                PreKeyRecord record = new PreKeyRecord(Codec.unb64(stored.record, 4096));
                otks.add(new PublicBundle.PublicPreKey(stored.id,
                        Codec.b64(record.getKeyPair().getPublicKey().serialize())));
            }

            return new PublicBundle(
                    state.registrationId,
                    DEVICE_ID,
                    Codec.b64(pair.getPublicKey().serialize()),
                    new PublicBundle.PublicSignedPreKey(
                            signed.getId(),
                            Codec.b64(signed.getKeyPair().getPublicKey().serialize()),
                            Codec.b64(signed.getSignature())),
                    new PublicBundle.PublicSignedPreKey(
                            kyber.getId(),
                            Codec.b64(kyber.getKeyPair().getPublicKey().serialize()),
                            Codec.b64(kyber.getSignature())),
                    otks);
        } catch (Exception e) {
            throw new CryptoException(CryptoException.Kind.INTERNAL,
                    "failed to build public bundle", e);
        }
    }

    public static PreKeyBundle toPreKeyBundle(PublicBundle bundle) throws CryptoException {
        try {
            PublicBundle.PublicPreKey otk =
                    bundle.oneTimePreKeys.isEmpty() ? null : bundle.oneTimePreKeys.get(0);
            return new PreKeyBundle(
                    bundle.registrationId,
                    bundle.deviceId,
                    otk == null ? PreKeyBundle.NULL_PRE_KEY_ID : otk.id,
                    otk == null ? null : new ECPublicKey(Codec.unb64(otk.publicKey, 33)),
                    bundle.signedPreKey.id,
                    new ECPublicKey(Codec.unb64(bundle.signedPreKey.publicKey, 33)),
                    Codec.unb64(bundle.signedPreKey.signature, 64),
                    new IdentityKey(Codec.unb64(bundle.identityKey, 33)),
                    bundle.kyberPreKey.id,
                    new KEMPublicKey(normalizeKyberKey(bundle.kyberPreKey.publicKey)),
                    Codec.unb64(bundle.kyberPreKey.signature, 64));
        } catch (Exception e) {
            throw new CryptoException(CryptoException.Kind.MALFORMED,
                    "peer prekey bundle is not valid", e);
        }
    }

    // --- session operations --------------------------------------------------

    public static boolean hasSession(CryptoState state, String peerUid) {
        return state.sessions.containsKey(peerUid);
    }

    /**
     * Encrypts one message. The session is created from {@code bundle} when no
     * session exists yet; the caller must have already compared the bundle
     * identity with the directory entry and the pinned key.
     */
    public static Encrypted encrypt(CryptoState state, String localUid, String peerUid,
                                    String peerIdentityB64, PublicBundle bundle,
                                    byte[] plaintext) throws CryptoException {
        if (plaintext.length == 0) {
            throw new CryptoException(CryptoException.Kind.MALFORMED, "empty plaintext");
        }
        if (plaintext.length > MAX_TEXT_BYTES) {
            throw new CryptoException(CryptoException.Kind.TEXT_TOO_LONG,
                    "plaintext exceeds " + MAX_TEXT_BYTES + " bytes");
        }
        String identity = requireIdentity(peerIdentityB64);
        String pinned = state.identities.get(peerUid);
        if (pinned != null && !pinned.equals(identity)) {
            throw new CryptoException(CryptoException.Kind.IDENTITY_CHANGED,
                    "pinned identity differs from the directory identity");
        }
        if (bundle != null && !bundle.identityKey.equals(identity)) {
            throw new CryptoException(CryptoException.Kind.IDENTITY_CHANGED,
                    "prekey bundle identity differs from the directory identity");
        }

        try {
            VaultSignalStore store = new VaultSignalStore(state);
            SignalProtocolAddress local = address(localUid);
            SignalProtocolAddress remote = address(peerUid);
            if (!store.containsSession(remote)) {
                if (bundle == null) {
                    throw new CryptoException(CryptoException.Kind.NO_SESSION,
                            "no session and no prekey bundle");
                }
                new org.signal.libsignal.protocol.SessionBuilder(store, remote, local)
                        .process(toPreKeyBundle(bundle));
            }
            CiphertextMessage message = new org.signal.libsignal.protocol.SessionCipher(
                    store, local, remote).encrypt(plaintext);
            return new Encrypted(message.getType(), Codec.b64(message.serialize()));
        } catch (CryptoException e) {
            throw e;
        } catch (UntrustedIdentityException e) {
            throw new CryptoException(CryptoException.Kind.IDENTITY_CHANGED,
                    "peer identity is not trusted", e);
        } catch (InvalidKeyException | NoSessionException e) {
            throw new CryptoException(CryptoException.Kind.NO_SESSION,
                    "cannot establish session", e);
        } catch (Exception e) {
            if (isMalformedFailure(e)) {
                throw new CryptoException(CryptoException.Kind.MALFORMED,
                        "peer bundle was rejected", e);
            }
            throw new CryptoException(CryptoException.Kind.INTERNAL, "encryption failed", e);
        }
    }

    /**
     * Decrypts one envelope. The caller is responsible for dedup before calling
     * this, and for persisting the returned plaintext only on success.
     */
    public static byte[] decrypt(CryptoState state, String localUid, Envelope envelope)
            throws CryptoException {
        if (envelope.messageType != CiphertextMessage.WHISPER_TYPE
                && envelope.messageType != CiphertextMessage.PREKEY_TYPE) {
            throw new CryptoException(CryptoException.Kind.MALFORMED,
                    "unsupported message type");
        }
        final byte[] ciphertext;
        try {
            ciphertext = Codec.unb64(envelope.ciphertext, Codec.MAX_CIPHERTEXT_BYTES);
        } catch (Codec.CodecException e) {
            throw new CryptoException(CryptoException.Kind.MALFORMED, "ciphertext is malformed", e);
        }

        VaultSignalStore store = new VaultSignalStore(state);
        SignalProtocolAddress local = address(localUid);
        SignalProtocolAddress remote = address(envelope.senderUid);
        org.signal.libsignal.protocol.SessionCipher cipher =
                new org.signal.libsignal.protocol.SessionCipher(store, local, remote);
        try {
            if (envelope.messageType == CiphertextMessage.PREKEY_TYPE) {
                PreKeySignalMessage message = new PreKeySignalMessage(ciphertext);
                byte[] plaintext = cipher.decrypt(message);
                Optional<Integer> preKeyId = message.getPreKeyId();
                if (preKeyId.isPresent()) {
                    store.removePreKey(preKeyId.get());
                }
                return plaintext;
            }
            return cipher.decrypt(new SignalMessage(ciphertext));
        } catch (DuplicateMessageException e) {
            throw new CryptoException(CryptoException.Kind.DUPLICATE,
                    "message was already processed by the ratchet", e);
        } catch (UntrustedIdentityException e) {
            throw new CryptoException(CryptoException.Kind.IDENTITY_CHANGED,
                    "peer identity is not trusted", e);
        } catch (NoSessionException e) {
            throw new CryptoException(CryptoException.Kind.NO_SESSION,
                    "no session for sender", e);
        } catch (InvalidKeyIdException e) {
            throw new CryptoException(CryptoException.Kind.MALFORMED,
                    "referenced prekey is unknown", e);
        } catch (InvalidMessageException | InvalidKeyException | InvalidVersionException
                 | LegacyMessageException e) {
            throw new CryptoException(CryptoException.Kind.MALFORMED,
                    "ciphertext failed verification", e);
        } catch (Exception e) {
            if (isMalformedFailure(e)) {
                // A few protocol failures (e.g. InvalidMacException) are not
                // declared on the Java bridge but can still surface here.
                throw new CryptoException(CryptoException.Kind.MALFORMED,
                        "ciphertext failed verification", e);
            }
            throw new CryptoException(CryptoException.Kind.INTERNAL, "decryption failed", e);
        }
    }

    // --- fingerprints --------------------------------------------------------

    /**
     * Signal numeric fingerprint (version 2, 5200 iterations) over the
     * lower-case UID strings and both identity public keys.
     *
     * <p>Both peers compute the same 60 digits: local/remote roles only change
     * which side is hashed first, which the generator accounts for by hashing
     * the pair in a canonical order. The iOS client uses identical inputs.
     */
    public static String fingerprint(CryptoState state, String localUid, String peerUid,
                                     String peerIdentityB64) throws CryptoException {
        if (!state.hasIdentity()) {
            throw new CryptoException(CryptoException.Kind.NO_IDENTITY,
                    "local identity is not initialised");
        }
        try {
            IdentityKeyPair pair = new IdentityKeyPair(Codec.unb64(state.identityKeyPair, 512));
            IdentityKey local = pair.getPublicKey();
            IdentityKey remote = new IdentityKey(
                    Codec.unb64(requireIdentity(peerIdentityB64), 33));
            byte[] localId = localUid.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);
            byte[] remoteId = peerUid.toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8);
            Fingerprint fingerprint = new NumericFingerprintGenerator(FINGERPRINT_ITERATIONS)
                    .createFor(FINGERPRINT_VERSION, localId, local, remoteId, remote);
            return fingerprint.getDisplayableFingerprint().getDisplayText();
        } catch (CryptoException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException(CryptoException.Kind.INTERNAL,
                    "failed to compute fingerprint", e);
        }
    }

    /**
     * Pins a peer identity that was verified through the relay directory (or
     * the app's own contact list). A different existing pin is never replaced.
     */
    public static void pinIdentity(CryptoState state, String uid, String identityB64)
            throws CryptoException {
        String identity = requireIdentity(identityB64);
        String existing = state.identities.get(uid);
        if (existing != null && !existing.equals(identity)) {
            throw new CryptoException(CryptoException.Kind.IDENTITY_CHANGED,
                    "peer identity differs from the pinned key");
        }
        state.identities.put(uid, identity);
    }

    /**
     * Checks a peer identity against the existing pin without creating one.
     * Used on the receive path before any ratchet work is done.
     */
    public static void verifyPeerIdentity(CryptoState state, String uid, String identityB64)
            throws CryptoException {
        String identity = requireIdentity(identityB64);
        String existing = state.identities.get(uid);
        if (existing != null && !existing.equals(identity)) {
            throw new CryptoException(CryptoException.Kind.IDENTITY_CHANGED,
                    "peer identity differs from the pinned key");
        }
    }

    /** Local identity public key, base64 (33-byte serialized form). */
    public static String localIdentityKey(CryptoState state) throws CryptoException {
        if (!state.hasIdentity()) {
            throw new CryptoException(CryptoException.Kind.NO_IDENTITY,
                    "local identity is not initialised");
        }
        try {
            IdentityKeyPair pair = new IdentityKeyPair(Codec.unb64(state.identityKeyPair, 512));
            return Codec.b64(pair.getPublicKey().serialize());
        } catch (Exception e) {
            throw new CryptoException(CryptoException.Kind.INTERNAL,
                    "failed to read local identity", e);
        }
    }

    private static String requireIdentity(String value) throws CryptoException {
        try {
            byte[] raw = Codec.unb64(value, 33);
            if (raw.length != 33 || raw[0] != 0x05) {
                throw new CryptoException(CryptoException.Kind.MALFORMED,
                        "identity key is not a serialized Signal public key");
            }
            return Codec.b64(raw);
        } catch (Codec.CodecException e) {
            throw new CryptoException(CryptoException.Kind.MALFORMED, "identity key is malformed", e);
        }
    }

    /**
     * libsignal serializes Kyber public keys with a leading 0x08 type tag
     * (1569 bytes). The relay also permits the bare 1568-byte key, so prepend
     * the tag if a peer sends the raw form.
     */
    private static byte[] normalizeKyberKey(String base64) throws Exception {
        byte[] raw = Codec.unb64(base64, PublicBundle.KYBER_PUBLIC_KEY_SERIALIZED_LEN);
        if (raw.length == PublicBundle.KYBER_PUBLIC_KEY_LEN) {
            byte[] tagged = new byte[raw.length + 1];
            tagged[0] = 0x08;
            System.arraycopy(raw, 0, tagged, 1, raw.length);
            return tagged;
        }
        return raw;
    }

    private static boolean isMalformedFailure(Throwable error) {
        String name = error.getClass().getSimpleName();
        return "InvalidMacException".equals(name)
                || "InvalidMessageException".equals(name)
                || "InvalidKeyException".equals(name)
                || "InvalidKeyIdException".equals(name)
                || "InvalidVersionException".equals(name)
                || "LegacyMessageException".equals(name)
                || "InvalidRegistrationIdException".equals(name)
                || "ReusedBaseKeyException".equals(name);
    }

    private static SignalProtocolAddress address(String uid) {
        return new SignalProtocolAddress(uid, DEVICE_ID);
    }

    /** Result of one encryption: libsignal message type (2 or 3) and ciphertext. */
    public static final class Encrypted {
        public final int messageType;
        public final String ciphertext;

        public Encrypted(int messageType, String ciphertext) {
            this.messageType = messageType;
            this.ciphertext = ciphertext;
        }
    }
}
