package io.veil.messenger.core;

/** URL validation failure with a user-presentable reason. */
public final class UrlException extends Exception {

    public enum Kind {
        EMPTY,
        INVALID,
        INSECURE
    }

    public final Kind kind;

    public UrlException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }
}
