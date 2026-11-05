package io.veil.messenger.core;

import io.veil.messenger.core.model.ChatMessage;
import io.veil.messenger.core.model.Contact;
import io.veil.messenger.core.model.Envelope;
import io.veil.messenger.crypto.CryptoException;
import io.veil.messenger.crypto.SignalEngine;
import org.signal.libsignal.protocol.InvalidKeyException;
import org.signal.libsignal.protocol.InvalidMessageException;
import org.signal.libsignal.protocol.InvalidVersionException;
import org.signal.libsignal.protocol.LegacyMessageException;
import org.signal.libsignal.protocol.message.CiphertextMessage;
import org.signal.libsignal.protocol.message.PreKeySignalMessage;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Pure receive-path logic: durable dedup, decryption and local commit.
 *
 * <p>The relay ACK is sent by the caller only after this returns
 * {@link Result#acknowledge} and the surrounding vault transaction has been
 * persisted. A failed decryption or storage step therefore never ACKs, and the
 * relay redelivers the envelope instead of destroying it.
 */
public final class InboxProcessor {

    private InboxProcessor() {
    }

    public static Result process(VaultState state, Envelope envelope, String localUid)
            throws CryptoException, Failure {
        if (state.isProcessed(envelope.id)) {
            // Dedup happened before any crypto: the ciphertext was already
            // committed and ACKed or is about to be ACKed.
            return Result.acknowledgedDuplicate(null);
        }
        if (!localUid.equals(envelope.recipientUid)) {
            throw new Failure("envelope is addressed to another account");
        }

        // A prekey message carries the sender's identity key. Compare it with
        // the directory pin *before* any ratchet work, so a changed key is
        // rejected even if libsignal would otherwise touch session state.
        if (envelope.messageType == CiphertextMessage.PREKEY_TYPE) {
            final byte[] raw;
            try {
                raw = Codec.unb64(envelope.ciphertext, Codec.MAX_CIPHERTEXT_BYTES);
                PreKeySignalMessage message = new PreKeySignalMessage(raw);
                SignalEngine.verifyPeerIdentity(state.crypto, envelope.senderUid,
                        Codec.b64(message.getIdentityKey().serialize()));
            } catch (Codec.CodecException | InvalidMessageException | InvalidKeyException
                     | InvalidVersionException | LegacyMessageException e) {
                throw new CryptoException(CryptoException.Kind.MALFORMED,
                        "prekey envelope is malformed", e);
            }
        }

        final byte[] plaintext;
        try {
            plaintext = SignalEngine.decrypt(state.crypto, localUid, envelope);
        } catch (CryptoException e) {
            // A duplicate ratchet error is not proof that this envelope id and
            // its chat row were committed. The vault saves them atomically, so
            // only the explicit durable-id check above authorizes a retry ACK.
            // Throwing (instead of returning a failure) makes the caller's
            // vault transaction roll back any partial ratchet mutation.
            throw e;
        }

        if (plaintext.length > SignalEngine.MAX_TEXT_BYTES) {
            throw new Failure("plaintext exceeds the 4096-byte contract limit");
        }
        final String text;
        try {
            text = decodeStrictUtf8(plaintext);
        } catch (CharacterCodingException e) {
            throw new Failure("plaintext is not valid UTF-8");
        }

        Contact contact = state.findContact(envelope.senderUid);
        if (contact == null) {
            // First contact from an unknown peer: libsignal pinned the identity
            // during decryption. Keep an explicit placeholder rather than
            // discarding a valid message; the handle can be filled in later by
            // adding the contact through exact directory lookup.
            String identity = state.crypto.identities.get(envelope.senderUid);
            if (identity == null) {
                throw new Failure("sender identity was not recorded");
            }
            contact = new Contact(envelope.senderUid, "", identity, false);
            state.upsertContact(contact);
        }

        long createdAt = envelope.createdAt > 0
                ? envelope.createdAt * 1000L
                : System.currentTimeMillis();
        ChatMessage message = new ChatMessage(
                envelope.id, envelope.senderUid, text, false, createdAt,
                ChatMessage.STATUS_RECEIVED);
        state.messages.add(message);
        state.markProcessed(envelope.id);
        return Result.success(message);
    }

    /** Human-readable reason for a rejected envelope (already user-facing). */
    public static String describe(CryptoException e) {
        switch (e.kind) {
            case IDENTITY_CHANGED:
                return "ключ співрозмовника змінився — повідомлення відхилено";
            case NO_SESSION:
                return "немає сесії для відправника";
            case MALFORMED:
                return "шифротекст не пройшов перевірку";
            case NO_IDENTITY:
                return "локальний ідентифікатор відсутній";
            default:
                return "криптографічна помилка";
        }
    }

    static String decodeStrictUtf8(byte[] raw) throws CharacterCodingException {
        CharBuffer chars = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(raw));
        return chars.toString();
    }

    /** Outcome of one envelope. */
    public static final class Result {
        public final boolean acknowledge;
        public final boolean duplicate;
        public final ChatMessage message;

        private Result(boolean acknowledge, boolean duplicate, ChatMessage message) {
            this.acknowledge = acknowledge;
            this.duplicate = duplicate;
            this.message = message;
        }

        static Result success(ChatMessage message) {
            return new Result(true, false, message);
        }

        static Result acknowledgedDuplicate(ChatMessage message) {
            return new Result(true, true, message);
        }
    }

    /** Non-cryptographic rejection (wrong recipient, size, encoding). */
    public static final class Failure extends Exception {
        public Failure(String message) {
            super(message);
        }
    }
}
