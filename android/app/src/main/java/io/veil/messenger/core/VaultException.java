package io.veil.messenger.core;

/** Storage failure. The original cause is preserved for mapping. */
public final class VaultException extends Exception {

    public enum Kind {
        /** The file exists but cannot be decrypted or parsed. Never auto-wiped. */
        CORRUPT,
        /** Read/write failure. */
        IO,
        /** The mutation itself threw; the in-memory state was rolled back. */
        MUTATION,
        /** Serialized state would exceed the supported size. */
        TOO_LARGE
    }

    public final Kind kind;

    public VaultException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public VaultException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }
}
