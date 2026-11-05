package io.veil.messenger.core;

import io.veil.messenger.core.model.ChatMessage;
import io.veil.messenger.core.model.Contact;
import io.veil.messenger.core.model.OutgoingEnvelope;
import io.veil.messenger.core.model.PublicBundle;
import io.veil.messenger.crypto.CryptoException;
import io.veil.messenger.crypto.SignalEngine;

/**
 * Pure send-path logic: encrypt and enqueue in one step.
 *
 * <p>Callers run this inside a vault transaction so the ratchet advance, the
 * local chat row and the outbox entry commit together. If the save fails, the
 * whole mutation is discarded and the session is not advanced.
 *
 * <p>Retries never call this again: they re-send the stored outbox ciphertext.
 */
public final class SendQueue {

    private SendQueue() {
    }

    /**
     * @param bundle peer prekey bundle to establish a session, or {@code null}
     *               when a session already exists
     */
    public static OutgoingEnvelope enqueue(VaultState state, String peerUid, String text,
                                           PublicBundle bundle) throws CryptoException {
        Contact contact = state.findContact(peerUid);
        if (contact == null) {
            throw new CryptoException(CryptoException.Kind.NO_SESSION,
                    "peer is not a known contact");
        }
        if (state.account == null) {
            throw new CryptoException(CryptoException.Kind.NO_IDENTITY,
                    "local account is missing");
        }
        byte[] plaintext = Codec.utf8(text);
        if (plaintext.length == 0) {
            throw new CryptoException(CryptoException.Kind.MALFORMED, "empty message");
        }
        if (plaintext.length > SignalEngine.MAX_TEXT_BYTES) {
            throw new CryptoException(CryptoException.Kind.TEXT_TOO_LONG,
                    "message exceeds " + SignalEngine.MAX_TEXT_BYTES + " bytes");
        }

        SignalEngine.Encrypted encrypted = SignalEngine.encrypt(
                state.crypto, state.account.uid, peerUid, contact.identityKey, bundle, plaintext);

        String id = Uuid7.create();
        long now = System.currentTimeMillis();
        state.messages.add(new ChatMessage(
                id, peerUid, text, true, now, ChatMessage.STATUS_QUEUED));
        OutgoingEnvelope envelope = new OutgoingEnvelope(
                id, peerUid, SignalEngine.DEVICE_ID,
                encrypted.messageType, encrypted.ciphertext);
        state.outbox.add(envelope);
        return envelope;
    }

    /**
     * Marks a queued message as sent. Called only after the relay accepted the
     * exact stored ciphertext.
     */
    public static void markSent(VaultState state, String messageId) {
        state.removeOutbox(messageId);
        state.setMessageStatus(messageId, ChatMessage.STATUS_SENT);
    }

    /** Records a permanent rejection (4xx other than 401/408/429) and drops the entry. */
    public static void markPermanentlyRejected(VaultState state, String messageId, String reason) {
        state.removeOutbox(messageId);
        state.recordSendFailure(messageId, reason);
    }
}
