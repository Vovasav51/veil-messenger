package io.veil.messenger.crypto;

import io.veil.messenger.core.Codec;
import org.signal.libsignal.protocol.IdentityKey;
import org.signal.libsignal.protocol.IdentityKeyPair;
import org.signal.libsignal.protocol.InvalidKeyIdException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.NoSessionException;
import org.signal.libsignal.protocol.ReusedBaseKeyException;
import org.signal.libsignal.protocol.SignalProtocolAddress;
import org.signal.libsignal.protocol.ecc.ECPublicKey;
import org.signal.libsignal.protocol.groups.state.SenderKeyRecord;
import org.signal.libsignal.protocol.groups.state.SenderKeyStore;
import org.signal.libsignal.protocol.state.IdentityKeyStore;
import org.signal.libsignal.protocol.state.KyberPreKeyRecord;
import org.signal.libsignal.protocol.state.KyberPreKeyStore;
import org.signal.libsignal.protocol.state.PreKeyRecord;
import org.signal.libsignal.protocol.state.PreKeyStore;
import org.signal.libsignal.protocol.state.SessionRecord;
import org.signal.libsignal.protocol.state.SessionStore;
import org.signal.libsignal.protocol.state.SignalProtocolStore;
import org.signal.libsignal.protocol.state.SignedPreKeyRecord;
import org.signal.libsignal.protocol.state.SignedPreKeyStore;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * libsignal store backed by the app's {@link CryptoState}.
 *
 * <p>Every mutation happens on the in-memory state; the surrounding vault
 * transaction decides whether it is ever persisted. Identity pins are never
 * overwritten: a changed peer key is reported as {@code REPLACED_EXISTING} and
 * {@link #isTrustedIdentity} keeps rejecting it, which makes libsignal throw
 * {@code UntrustedIdentityException}.
 *
 * <p>Only device id 1 exists (one device per account), so sessions are keyed by
 * peer UID alone.
 */
public final class VaultSignalStore implements SignalProtocolStore {

    private final CryptoState state;
    private final Map<String, SenderKeyRecord> senderKeys = new HashMap<>();

    private IdentityKeyPair cachedIdentity;
    private String cachedIdentityRaw;

    public VaultSignalStore(CryptoState state) {
        this.state = state;
    }

    // --- identity ------------------------------------------------------------

    @Override
    public IdentityKeyPair getIdentityKeyPair() {
        String raw = state.identityKeyPair;
        if (raw == null) {
            throw new IllegalStateException("identity key pair is missing");
        }
        if (cachedIdentity == null || !raw.equals(cachedIdentityRaw)) {
            try {
                cachedIdentity = new IdentityKeyPair(Codec.unb64(raw, 512));
                cachedIdentityRaw = raw;
            } catch (Exception e) {
                throw new IllegalStateException("identity key pair is corrupt", e);
            }
        }
        return cachedIdentity;
    }

    @Override
    public int getLocalRegistrationId() {
        return state.registrationId;
    }

    @Override
    public IdentityChange saveIdentity(SignalProtocolAddress address, IdentityKey identityKey) {
        String uid = address.getName();
        String existing = state.identities.get(uid);
        String raw = Codec.b64(identityKey.serialize());
        if (existing == null) {
            state.identities.put(uid, raw);
            return IdentityChange.NEW_OR_UNCHANGED;
        }
        if (existing.equals(raw)) {
            return IdentityChange.NEW_OR_UNCHANGED;
        }
        // Deliberately do not replace the pin: a changed key must be rejected
        // rather than silently trusted.
        return IdentityChange.REPLACED_EXISTING;
    }

    @Override
    public boolean isTrustedIdentity(SignalProtocolAddress address, IdentityKey identityKey,
                                     Direction direction) {
        String existing = state.identities.get(address.getName());
        if (existing == null) {
            return true; // TOFU: first seen key is pinned by saveIdentity
        }
        return existing.equals(Codec.b64(identityKey.serialize()));
    }

    @Override
    public IdentityKey getIdentity(SignalProtocolAddress address) {
        String raw = state.identities.get(address.getName());
        if (raw == null) {
            return null;
        }
        try {
            return new IdentityKey(Codec.unb64(raw, 64));
        } catch (Exception e) {
            throw new IllegalStateException("pinned identity is corrupt", e);
        }
    }

    // --- sessions ------------------------------------------------------------

    @Override
    public SessionRecord loadSession(SignalProtocolAddress address) {
        String raw = state.sessions.get(address.getName());
        if (raw == null) {
            return null;
        }
        try {
            return new SessionRecord(Codec.unb64(raw, 64 * 1024));
        } catch (InvalidMessageException | Codec.CodecException e) {
            throw new IllegalStateException("session record is corrupt", e);
        }
    }

    @Override
    public List<SessionRecord> loadExistingSessions(List<SignalProtocolAddress> addresses)
            throws NoSessionException {
        List<SessionRecord> records = new ArrayList<>(addresses.size());
        for (SignalProtocolAddress address : addresses) {
            SessionRecord record = loadSession(address);
            if (record == null) {
                throw new NoSessionException(address, "no session for " + address);
            }
            records.add(record);
        }
        return records;
    }

    @Override
    public List<Integer> getSubDeviceSessions(String name) {
        return Collections.emptyList();
    }

    @Override
    public void storeSession(SignalProtocolAddress address, SessionRecord record) {
        state.sessions.put(address.getName(), Codec.b64(record.serialize()));
    }

    @Override
    public boolean containsSession(SignalProtocolAddress address) {
        return state.sessions.containsKey(address.getName());
    }

    @Override
    public void deleteSession(SignalProtocolAddress address) {
        state.sessions.remove(address.getName());
    }

    @Override
    public void deleteAllSessions(String name) {
        state.sessions.remove(name);
    }

    // --- one-time prekeys ----------------------------------------------------

    @Override
    public PreKeyRecord loadPreKey(int preKeyId) throws InvalidKeyIdException {
        for (CryptoState.PreKeyState key : state.oneTimePreKeys) {
            if (key.id == preKeyId) {
                try {
                    return new PreKeyRecord(Codec.unb64(key.record, 4096));
                } catch (InvalidMessageException | Codec.CodecException e) {
                    throw new InvalidKeyIdException("prekey record is corrupt");
                }
            }
        }
        throw new InvalidKeyIdException("no prekey with id " + preKeyId);
    }

    @Override
    public void storePreKey(int preKeyId, PreKeyRecord record) {
        for (int i = 0; i < state.oneTimePreKeys.size(); i++) {
            if (state.oneTimePreKeys.get(i).id == preKeyId) {
                state.oneTimePreKeys.set(i, new CryptoState.PreKeyState(preKeyId,
                        Codec.b64(record.serialize())));
                return;
            }
        }
        state.oneTimePreKeys.add(new CryptoState.PreKeyState(preKeyId,
                Codec.b64(record.serialize())));
    }

    @Override
    public boolean containsPreKey(int preKeyId) {
        for (CryptoState.PreKeyState key : state.oneTimePreKeys) {
            if (key.id == preKeyId) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void removePreKey(int preKeyId) {
        for (int i = 0; i < state.oneTimePreKeys.size(); i++) {
            if (state.oneTimePreKeys.get(i).id == preKeyId) {
                state.oneTimePreKeys.remove(i);
                return;
            }
        }
    }

    // --- signed prekey -------------------------------------------------------

    @Override
    public SignedPreKeyRecord loadSignedPreKey(int signedPreKeyId) throws InvalidKeyIdException {
        CryptoState.SignedPreKeyState stored = state.signedPreKey;
        if (stored == null || stored.id != signedPreKeyId) {
            throw new InvalidKeyIdException("no signed prekey with id " + signedPreKeyId);
        }
        try {
            return new SignedPreKeyRecord(Codec.unb64(stored.record, 4096));
        } catch (InvalidMessageException | Codec.CodecException e) {
            throw new InvalidKeyIdException("signed prekey record is corrupt");
        }
    }

    @Override
    public List<SignedPreKeyRecord> loadSignedPreKeys() {
        if (state.signedPreKey == null) {
            return Collections.emptyList();
        }
        try {
            return Collections.singletonList(
                    new SignedPreKeyRecord(Codec.unb64(state.signedPreKey.record, 4096)));
        } catch (InvalidMessageException | Codec.CodecException e) {
            throw new IllegalStateException("signed prekey record is corrupt", e);
        }
    }

    @Override
    public void storeSignedPreKey(int signedPreKeyId, SignedPreKeyRecord record) {
        long createdAt = state.signedPreKey == null ? 0L : state.signedPreKey.createdAtMs;
        state.signedPreKey = new CryptoState.SignedPreKeyState(
                signedPreKeyId, createdAt, Codec.b64(record.serialize()));
    }

    @Override
    public boolean containsSignedPreKey(int signedPreKeyId) {
        return state.signedPreKey != null && state.signedPreKey.id == signedPreKeyId;
    }

    @Override
    public void removeSignedPreKey(int signedPreKeyId) {
        if (state.signedPreKey != null && state.signedPreKey.id == signedPreKeyId) {
            state.signedPreKey = null;
        }
    }

    // --- Kyber prekey --------------------------------------------------------

    @Override
    public KyberPreKeyRecord loadKyberPreKey(int kyberPreKeyId) throws InvalidKeyIdException {
        CryptoState.KyberPreKeyState stored = state.kyberPreKey;
        if (stored == null || stored.id != kyberPreKeyId) {
            throw new InvalidKeyIdException("no kyber prekey with id " + kyberPreKeyId);
        }
        try {
            return new KyberPreKeyRecord(Codec.unb64(stored.record, 8192));
        } catch (InvalidMessageException | Codec.CodecException e) {
            throw new InvalidKeyIdException("kyber prekey record is corrupt");
        }
    }

    @Override
    public List<KyberPreKeyRecord> loadKyberPreKeys() {
        if (state.kyberPreKey == null) {
            return Collections.emptyList();
        }
        try {
            return Collections.singletonList(
                    new KyberPreKeyRecord(Codec.unb64(state.kyberPreKey.record, 8192)));
        } catch (InvalidMessageException | Codec.CodecException e) {
            throw new IllegalStateException("kyber prekey record is corrupt", e);
        }
    }

    @Override
    public void storeKyberPreKey(int kyberPreKeyId, KyberPreKeyRecord record) {
        long createdAt = state.kyberPreKey == null ? 0L : state.kyberPreKey.createdAtMs;
        state.kyberPreKey = new CryptoState.KyberPreKeyState(
                kyberPreKeyId, createdAt, Codec.b64(record.serialize()));
    }

    @Override
    public boolean containsKyberPreKey(int kyberPreKeyId) {
        return state.kyberPreKey != null && state.kyberPreKey.id == kyberPreKeyId;
    }

    @Override
    public void markKyberPreKeyUsed(int kyberPreKeyId, int signedPreKeyId, ECPublicKey baseKey)
            throws ReusedBaseKeyException {
        String signature = kyberPreKeyId + "|" + signedPreKeyId + "|"
                + Codec.b64(baseKey.serialize());
        if (state.usedKyberBaseKeys.contains(signature)) {
            throw new ReusedBaseKeyException("kyber base key was already used");
        }
        state.markKyberBaseKeyUsed(signature);
    }

    // --- sender keys (unused for 1:1, required by the interface) ------------

    @Override
    public void storeSenderKey(SignalProtocolAddress sender, UUID distributionId,
                               SenderKeyRecord record) {
        senderKeys.put(sender.getName() + "|" + sender.getDeviceId() + "|" + distributionId,
                record);
    }

    @Override
    public SenderKeyRecord loadSenderKey(SignalProtocolAddress sender, UUID distributionId) {
        SenderKeyRecord record = senderKeys.get(
                sender.getName() + "|" + sender.getDeviceId() + "|" + distributionId);
        if (record == null) {
            return null;
        }
        try {
            return new SenderKeyRecord(record.serialize());
        } catch (InvalidMessageException e) {
            throw new IllegalStateException("sender key record is corrupt", e);
        }
    }
}
