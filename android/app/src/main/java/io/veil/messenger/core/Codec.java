package io.veil.messenger.core;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Strict, allocation-bounded codec helpers.
 *
 * <p>Base64 uses {@link java.util.Base64} (available on API 26+) instead of
 * {@code android.util.Base64} so that serialization logic stays testable on a
 * plain JVM. Decoding is canonical: the re-encoded bytes must equal the input,
 * which rejects non-zero padding bits and stray whitespace.
 */
public final class Codec {

    /** Relay contract bound for one ciphertext (receive path). */
    public static final int MAX_CIPHERTEXT_BYTES = 64 * 1024;
    public static final int MAX_BUNDLE_KEY_BYTES = 2 * 1024;
    public static final int MAX_IDENTITY_BYTES = 33;
    public static final int MAX_SIGNATURE_BYTES = 64;
    public static final int MAX_KYBER_BYTES = 1569;

    private Codec() {
    }

    public static String b64(byte[] raw) {
        return Base64.getEncoder().encodeToString(raw);
    }

    public static byte[] unb64(String value) throws CodecException {
        return unb64(value, MAX_CIPHERTEXT_BYTES);
    }

    public static byte[] unb64(String value, int maxBytes) throws CodecException {
        if (value == null) {
            throw new CodecException("missing base64 value");
        }
        if (value.isEmpty() || value.length() > 4 * ((maxBytes + 2) / 3)) {
            throw new CodecException("base64 value has invalid length");
        }
        if (value.length() % 4 != 0) {
            throw new CodecException("base64 value is not canonical");
        }
        final byte[] raw;
        try {
            raw = Base64.getDecoder().decode(value);
        } catch (IllegalArgumentException e) {
            throw new CodecException("base64 value is malformed");
        }
        if (raw.length > maxBytes) {
            throw new CodecException("base64 value is too large");
        }
        if (!Base64.getEncoder().encodeToString(raw).equals(value)) {
            throw new CodecException("base64 value is not canonical");
        }
        return raw;
    }

    public static byte[] utf8(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }

    public static String fromUtf8(byte[] value) {
        return new String(value, StandardCharsets.UTF_8);
    }

    /** Runtime failure for malformed local or remote data. */
    public static final class CodecException extends Exception {
        public CodecException(String message) {
            super(message);
        }
    }
}
