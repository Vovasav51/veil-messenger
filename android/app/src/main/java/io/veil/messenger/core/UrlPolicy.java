package io.veil.messenger.core;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.Locale;

/**
 * Server URL policy, identical in spirit to the iOS client:
 * HTTPS only, no credentials, no query/fragment, trailing slash so reverse
 * proxy prefixes survive, and cleartext permitted only for loopback/emulator
 * hosts in debug builds.
 */
public final class UrlPolicy {

    public static final int MAX_URL_LENGTH = 2048;
    private static final java.util.regex.Pattern SCHEME_PREFIX =
            java.util.regex.Pattern.compile("^[A-Za-z][A-Za-z0-9+.\\-]*://");

    private UrlPolicy() {
    }

    public static URL parse(String raw, boolean allowLoopbackHttp) throws UrlException {
        String text = raw == null ? "" : raw.trim();
        if (text.isEmpty()) {
            throw new UrlException(UrlException.Kind.EMPTY, "empty server URL");
        }
        if (text.length() > MAX_URL_LENGTH) {
            throw new UrlException(UrlException.Kind.INVALID, "server URL is too long");
        }
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (Character.isISOControl(c) || Character.isWhitespace(c)) {
                throw new UrlException(UrlException.Kind.INVALID,
                        "server URL contains whitespace or control characters");
            }
        }

        String lower = text.toLowerCase(Locale.ROOT);
        if (!lower.startsWith("https://") && !lower.startsWith("http://")) {
            // Only an absent scheme may be completed to https. Anything that
            // already looks like scheme://... (ftp://, file://, javascript://)
            // is rejected instead of being turned into a weird https host.
            if (SCHEME_PREFIX.matcher(text).find()) {
                throw new UrlException(UrlException.Kind.INSECURE,
                        "unsupported URL scheme");
            }
            text = "https://" + text;
        }

        final URI uri;
        try {
            uri = new URI(text);
        } catch (URISyntaxException e) {
            throw new UrlException(UrlException.Kind.INVALID, "server URL cannot be parsed");
        }

        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        if (uri.getRawUserInfo() != null) {
            throw new UrlException(UrlException.Kind.INVALID,
                    "credentials are not allowed in a server URL");
        }
        if (uri.getRawQuery() != null || uri.getRawFragment() != null) {
            throw new UrlException(UrlException.Kind.INVALID,
                    "query and fragment are not allowed in a server URL");
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new UrlException(UrlException.Kind.INVALID, "server URL has no host");
        }

        if ("http".equals(scheme)) {
            if (!allowLoopbackHttp || !isLoopback(host)) {
                throw new UrlException(UrlException.Kind.INSECURE,
                        "http is allowed only for loopback hosts in debug builds");
            }
        } else if (!"https".equals(scheme)) {
            throw new UrlException(UrlException.Kind.INSECURE, "unsupported URL scheme");
        }

        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        if (path.contains("..")) {
            throw new UrlException(UrlException.Kind.INVALID, "server URL path is not allowed");
        }
        if (!path.endsWith("/")) {
            path = path + "/";
        }

        try {
            URI normalized = new URI(scheme, null, host, uri.getPort(), path, null, null);
            return normalized.toURL();
        } catch (URISyntaxException | MalformedURLException e) {
            throw new UrlException(UrlException.Kind.INVALID, "server URL cannot be normalized");
        }
    }

    /**
     * Loopback plus the Android emulator host alias only. A LAN address is
     * deliberately not considered local: cleartext must not leak onto a shared
     * network even in debug builds.
     */
    public static boolean isLoopback(String host) {
        String normalized = host.toLowerCase(Locale.ROOT);
        if (normalized.startsWith("[") && normalized.endsWith("]")) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        return "localhost".equals(normalized)
                || "::1".equals(normalized)
                || "127.0.0.1".equals(normalized)
                || "10.0.2.2".equals(normalized);
    }
}
