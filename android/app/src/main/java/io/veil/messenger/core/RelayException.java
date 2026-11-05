package io.veil.messenger.core;

/** Transport/protocol failure from the relay, with a stable classification. */
public final class RelayException extends Exception {

    public enum Kind {
        /** Connection failed; the request may or may not have been applied. */
        NETWORK,
        /** Read/connect timeout; outcome is unknown. */
        TIMEOUT,
        /** 401/403. Polling must stop; no account recovery exists. */
        UNAUTHORIZED,
        /** 429 with optional Retry-After detail. */
        RATE_LIMITED,
        /** Any other non-2xx response. */
        SERVER,
        /** Body was not the JSON we expect. */
        DECODING,
        /** 2xx with an empty body. */
        EMPTY,
        /** A 3xx: refused so the bearer token can never be replayed elsewhere. */
        REDIRECT,
        /** Response exceeded the client bound. */
        TOO_LARGE,
        /** Client is missing a token or a valid base URL. */
        CONFIG
    }

    public final Kind kind;
    public final int status;
    public final String detail;

    public RelayException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
        this.status = 0;
        this.detail = "";
    }

    public RelayException(Kind kind, int status, String detail) {
        super(kind + (status > 0 ? " " + status : "") + (detail.isEmpty() ? "" : ": " + detail));
        this.kind = kind;
        this.status = status;
        this.detail = detail;
    }

    /** Rejections that will not succeed on retry (do not keep the outbox spinning). */
    public boolean isPermanentRejection() {
        return kind == Kind.SERVER && status >= 400 && status < 500
                && status != 401 && status != 408 && status != 429;
    }

    /** The request may have reached the relay. */
    public boolean isUncertain() {
        return kind == Kind.NETWORK || kind == Kind.TIMEOUT;
    }

    public boolean isAuthFailure() {
        return kind == Kind.UNAUTHORIZED;
    }
}
