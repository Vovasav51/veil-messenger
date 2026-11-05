package io.veil.messenger.core;

import java.util.Locale;

/** Server-side handle normalization: optional leading '@', lower-case ASCII. */
public final class HandleRules {

    private HandleRules() {
    }

    /**
     * @throws IllegalArgumentException when the handle is not
     *         {@code ^[a-z0-9_]{3,24}$} after normalization
     */
    public static String normalize(String raw) {
        if (raw == null) {
            throw new IllegalArgumentException("handle is required");
        }
        String value = raw.trim();
        if (value.startsWith("@")) {
            value = value.substring(1);
        }
        value = value.toLowerCase(Locale.ROOT);
        if (value.length() < 3 || value.length() > 24) {
            throw new IllegalArgumentException("handle length must be 3..24");
        }
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            boolean ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
            if (!ok) {
                throw new IllegalArgumentException("handle has an invalid character");
            }
        }
        return value;
    }
}
