package io.veil.messenger.crypto;

/** Typed crypto failure, so callers never have to parse exception text. */
public final class CryptoException extends Exception {

    public enum Kind {
        /** Peer identity key differs from the pinned one (or directory != bundle). */
        IDENTITY_CHANGED,
        /** The ratchet has already seen this message; safe to ACK. */
        DUPLICATE,
        /** No session yet and no prekey bundle was supplied. */
        NO_SESSION,
        /** Ciphertext is malformed, tampered with, or of an unsupported version. */
        MALFORMED,
        /** Local identity/ratchet state is missing. */
        NO_IDENTITY,
        /** Plaintext exceeds the 4096-byte UTF-8 contract limit. */
        TEXT_TOO_LONG,
        /** Anything that indicates a local bug rather than remote data. */
        INTERNAL
    }

    public final Kind kind;

    public CryptoException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public CryptoException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }
}
