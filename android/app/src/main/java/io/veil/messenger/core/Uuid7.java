package io.veil.messenger.core;

import java.security.SecureRandom;
import java.util.Locale;
import java.util.UUID;

/**
 * RFC 9562 UUID version 7 (time-ordered) generator.
 *
 * <p>The relay requires client-generated UUIDs. Version 7 keeps message ids
 * roughly sortable by creation time, which makes the outbox deterministic and
 * avoids leaking a device-specific random prefix.
 */
public final class Uuid7 {

    private static final SecureRandom RANDOM = new SecureRandom();

    private Uuid7() {
    }

    public static String create() {
        long millis = System.currentTimeMillis() & 0x0000FFFFFFFFFFFFL;
        long randA = RANDOM.nextInt(1 << 12);
        long msb = (millis << 16) | 0x7000L | randA;
        long lsb = (RANDOM.nextLong() & 0x3FFFFFFFFFFFFFFFL) | 0x8000000000000000L;
        return fromBits(msb, lsb);
    }

    static String fromBits(long msb, long lsb) {
        return String.format(Locale.ROOT,
                "%08x-%04x-%04x-%04x-%012x",
                (msb >>> 32) & 0xFFFFFFFFL,
                (msb >>> 16) & 0xFFFFL,
                msb & 0xFFFFL,
                (lsb >>> 48) & 0xFFFFL,
                lsb & 0x0000FFFFFFFFFFFFL);
    }

    /** Strict canonical (lower-case) UUID check, matching the relay validator. */
    public static boolean isCanonical(String value) {
        if (value == null || value.length() != 36) {
            return false;
        }
        for (int i = 0; i < 36; i++) {
            char c = value.charAt(i);
            if (i == 8 || i == 13 || i == 18 || i == 23) {
                if (c != '-') {
                    return false;
                }
            } else if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) {
                return false;
            }
        }
        return !"00000000-0000-0000-0000-000000000000".equals(value);
    }

    /**
     * Normalizes a server-supplied UUID. The relay lower-cases ids already; we
     * still refuse anything that is not a plain UUID so a hostile relay cannot
     * inject a long string into UI or storage.
     */
    public static String normalize(String value) {
        if (value == null) {
            return null;
        }
        String lower = value.toLowerCase(Locale.ROOT);
        return isCanonical(lower) ? lower : null;
    }

    /** Convenience wrapper used by models/tests. */
    static UUID parse(String value) {
        return UUID.fromString(value);
    }
}
