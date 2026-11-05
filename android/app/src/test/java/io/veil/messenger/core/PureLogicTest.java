package io.veil.messenger.core;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

import java.net.URL;
import java.util.HashSet;
import java.util.Set;

/** Pure-JVM tests for URL policy, ids, handles and strict base64. */
public class PureLogicTest {

    @Test
    public void urlNormalizationKeepsProxyPrefix() throws Exception {
        URL url = UrlPolicy.parse("relay.example.org/veil", false);
        assertEquals("https", url.getProtocol());
        assertEquals("relay.example.org", url.getHost());
        assertEquals("/veil/", url.getPath());
        assertEquals("https://relay.example.org/veil/", url.toString());

        URL bare = UrlPolicy.parse("  https://relay.example.org  ", false);
        assertEquals("/", bare.getPath());
    }

    @Test
    public void cleartextIsAllowedOnlyForLoopbackInDebug() throws Exception {
        assertEquals("http://127.0.0.1:8080/",
                UrlPolicy.parse("http://127.0.0.1:8080", true).toString());
        assertEquals("http://10.0.2.2:8000/",
                UrlPolicy.parse("http://10.0.2.2:8000", true).toString());
        assertEquals("http://localhost:9000/",
                UrlPolicy.parse("http://localhost:9000/", true).toString());

        for (String value : new String[]{
                "http://127.0.0.1:8080/", "http://10.0.2.2:8000/"}) {
            try {
                UrlPolicy.parse(value, false);
                fail("cleartext must be refused in release builds: " + value);
            } catch (UrlException e) {
                assertEquals(UrlException.Kind.INSECURE, e.kind);
            }
        }
        try {
            UrlPolicy.parse("http://192.168.1.10:8080/", true);
            fail("LAN cleartext must be refused even in debug builds");
        } catch (UrlException e) {
            assertEquals(UrlException.Kind.INSECURE, e.kind);
        }
    }

    @Test
    public void unsafeUrlShapesAreRefused() {
        String[] bad = new String[]{
                "",
                "ftp://relay.example.org/",
                "https://user:pass@relay.example.org/",
                "https://relay.example.org/?x=1",
                "https://relay.example.org/#frag",
                "https://relay.example.org/a/../b",
                "https://",
        };
        for (String value : bad) {
            try {
                UrlPolicy.parse(value, false);
                fail("must be refused: " + value);
            } catch (UrlException expected) {
                // ok
            }
        }
    }

    @Test
    public void uuidV7ShapeAndUniqueness() {
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < 500; i++) {
            String id = Uuid7.create();
            assertTrue(Uuid7.isCanonical(id));
            assertEquals('7', id.charAt(14));
            assertTrue("variant bits", "89ab".indexOf(id.charAt(19)) >= 0);
            assertTrue(seen.add(id));
        }
        assertFalse(Uuid7.isCanonical("00000000-0000-0000-0000-000000000000"));
        assertFalse(Uuid7.isCanonical("0192F4B3-1C2D-7A10-9D21-0F6C3B1E4A01"));
        assertEquals("0192f4b3-1c2d-7a10-9d21-0f6c3b1e4a01",
                Uuid7.normalize("0192F4B3-1C2D-7A10-9D21-0F6C3B1E4A01"));
        assertEquals(null, Uuid7.normalize("not-a-uuid"));
    }

    @Test
    public void handleNormalizationMatchesRelayRules() {
        assertEquals("olena_k", HandleRules.normalize("@Olena_K"));
        assertEquals("abc", HandleRules.normalize(" abc "));
        for (String bad : new String[]{"ab", "", "@", "olena-k", "олена", "abcdefghijklmnopqrstuvwxy"}) {
            try {
                HandleRules.normalize(bad);
                fail("must be refused: " + bad);
            } catch (IllegalArgumentException expected) {
                // ok
            }
        }
    }

    @Test
    public void base64IsCanonicalAndBounded() throws Exception {
        byte[] raw = new byte[]{0x05, 0x01, (byte) 0xFF};
        String encoded = Codec.b64(raw);
        assertEquals(encoded, Codec.b64(Codec.unb64(encoded)));

        for (String bad : new String[]{"", "AAA", "AA=A", "A A A", "____", "AB=="}) {
            try {
                Codec.unb64(bad, 16);
                fail("must be refused: " + bad);
            } catch (Codec.CodecException expected) {
                // ok
            }
        }
        try {
            Codec.unb64(Codec.b64(new byte[64]), 32);
            fail("oversized value must be refused");
        } catch (Codec.CodecException expected) {
            // ok
        }
    }

    @Test
    public void messageStatusConstantsMatchContract() {
        assertEquals("queued", io.veil.messenger.core.model.ChatMessage.STATUS_QUEUED);
        assertEquals("sent", io.veil.messenger.core.model.ChatMessage.STATUS_SENT);
        assertEquals("received", io.veil.messenger.core.model.ChatMessage.STATUS_RECEIVED);
        assertNotNull(io.veil.messenger.core.model.ChatMessage.STATUS_QUEUED);
    }
}
