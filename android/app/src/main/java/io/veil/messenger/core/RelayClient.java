package io.veil.messenger.core;

import io.veil.messenger.core.model.Envelope;
import io.veil.messenger.core.model.OutgoingEnvelope;
import io.veil.messenger.core.model.PublicBundle;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * First-party client for the Veil relay JSON API v1.
 *
 * <p>Hardening rules:
 * <ul>
 *   <li>Never follows redirects (a 30x could replay the bearer token to
 *       another origin).</li>
 *   <li>Ephemeral connection, no caches, no cookies.</li>
 *   <li>Bounded request and response bodies, fixed timeouts.</li>
 *   <li>No request/response logging, ever.</li>
 * </ul>
 */
public final class RelayClient {

    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS = 20_000;
    private static final int MAX_RESPONSE_BYTES = 12 * 1024 * 1024;
    private static final int MAX_REQUEST_BYTES = 512 * 1024;
    private static final int MAX_MESSAGES_PER_PULL = 100;

    private final URL baseUrl;
    private final String token;

    public RelayClient(URL baseUrl, String token) {
        this.baseUrl = baseUrl;
        this.token = token;
    }

    public URL baseUrl() {
        return baseUrl;
    }

    // --- endpoints -----------------------------------------------------------

    public Health health() throws RelayException {
        JSONObject response = call("GET", "health", null, false);
        try {
            String status = response.getString("status");
            String version = response.getString("version");
            return new Health(status, version);
        } catch (JSONException e) {
            throw new RelayException(RelayException.Kind.DECODING, "health response is invalid", e);
        }
    }

    public RegisterResponse register(String uid, String handle, PublicBundle bundle)
            throws RelayException {
        JSONObject body = new JSONObject();
        try {
            body.put("uid", uid);
            body.put("handle", handle);
            body.put("device_id", 1);
            body.put("bundle", bundle.toWireJson());
        } catch (JSONException e) {
            throw new RelayException(RelayException.Kind.CONFIG, "cannot encode registration", e);
        }
        JSONObject response = call("POST", "v1/register", body, false);
        try {
            String uidValue = Uuid7.normalize(response.getString("uid"));
            String handleValue = HandleRules.normalize(response.getString("handle"));
            String tokenValue = response.getString("token");
            if (uidValue == null || !uidValue.equals(uid)
                    || !handleValue.equals(HandleRules.normalize(handle))
                    || tokenValue.length() < 16 || tokenValue.length() > 512) {
                throw new JSONException("registration response has invalid fields");
            }
            for (int i = 0; i < tokenValue.length(); i++) {
                if (Character.isWhitespace(tokenValue.charAt(i))
                        || Character.isISOControl(tokenValue.charAt(i))) {
                    throw new JSONException("registration token contains invalid characters");
                }
            }
            return new RegisterResponse(uidValue, handleValue, tokenValue);
        } catch (JSONException | IllegalArgumentException e) {
            throw new RelayException(RelayException.Kind.DECODING,
                    "registration response is invalid", e);
        }
    }

    public DirectoryEntry directory(String handle) throws RelayException {
        JSONObject response = call("GET", "v1/directory/" + encodePath(handle), null, true);
        try {
            String uid = Uuid7.normalize(response.getString("uid"));
            String normalizedHandle = HandleRules.normalize(response.getString("handle"));
            int deviceId = response.getInt("device_id");
            String identityKey = PublicBundle.requireSignalKey(
                    response.getString("identity_key"), "identity_key");
            if (uid == null || deviceId != 1) {
                throw new JSONException("directory entry has invalid fields");
            }
            return new DirectoryEntry(uid, normalizedHandle, deviceId, identityKey);
        } catch (JSONException | Codec.CodecException | IllegalArgumentException e) {
            throw new RelayException(RelayException.Kind.DECODING,
                    "directory response is invalid", e);
        }
    }

    public PublicBundle prekeys(String uid) throws RelayException {
        JSONObject response = call("GET", "v1/prekeys/" + encodePath(uid), null, true);
        try {
            return PublicBundle.fromWire(response);
        } catch (JSONException | Codec.CodecException e) {
            throw new RelayException(RelayException.Kind.DECODING, "prekey response is invalid", e);
        }
    }

    public void uploadPrekeys(PublicBundle bundle) throws RelayException {
        JSONObject body;
        try {
            body = bundle.toWireJson();
        } catch (JSONException e) {
            throw new RelayException(RelayException.Kind.CONFIG, "cannot encode prekeys", e);
        }
        JSONObject response = call("PUT", "v1/prekeys", body, true);
        requireOk(response);
    }

    public void send(OutgoingEnvelope envelope) throws RelayException {
        JSONObject body = new JSONObject();
        try {
            body.put("id", envelope.id);
            body.put("recipient_uid", envelope.recipientUid);
            body.put("recipient_device_id", envelope.recipientDeviceId);
            body.put("message_type", envelope.messageType);
            body.put("ciphertext", envelope.ciphertext);
        } catch (JSONException e) {
            throw new RelayException(RelayException.Kind.CONFIG, "cannot encode message", e);
        }
        JSONObject response = call("POST", "v1/messages", body, true);
        try {
            if (!response.getBoolean("accepted") || !envelope.id.equals(response.getString("id"))) {
                throw new RelayException(RelayException.Kind.SERVER, 202, "message not accepted");
            }
        } catch (JSONException e) {
            throw new RelayException(RelayException.Kind.DECODING, "send response is invalid", e);
        }
    }

    public List<Envelope> fetchMessages() throws RelayException {
        JSONObject response = call("GET", "v1/messages", null, true);
        JSONArray array;
        try {
            array = response.getJSONArray("messages");
        } catch (JSONException e) {
            throw new RelayException(RelayException.Kind.DECODING, "messages response is invalid", e);
        }
        List<Envelope> envelopes = new ArrayList<>();
        int count = Math.min(array.length(), MAX_MESSAGES_PER_PULL);
        for (int i = 0; i < count; i++) {
            try {
                envelopes.add(Envelope.fromWire(array.getJSONObject(i)));
            } catch (JSONException | Codec.CodecException e) {
                throw new RelayException(RelayException.Kind.DECODING,
                        "envelope is invalid", e);
            }
        }
        return envelopes;
    }

    public void acknowledge(List<String> ids) throws RelayException {
        if (ids.isEmpty()) {
            return;
        }
        JSONObject body = new JSONObject();
        try {
            body.put("ids", new JSONArray(ids));
        } catch (JSONException e) {
            throw new RelayException(RelayException.Kind.CONFIG, "cannot encode ack", e);
        }
        requireOk(call("POST", "v1/messages/ack", body, true));
    }

    // --- transport -----------------------------------------------------------

    private JSONObject call(String method, String path, JSONObject body, boolean authorized)
            throws RelayException {
        if (baseUrl == null) {
            throw new RelayException(RelayException.Kind.CONFIG, "relay URL is not configured", null);
        }
        if (authorized && (token == null || token.isEmpty())) {
            throw new RelayException(RelayException.Kind.CONFIG, "relay token is missing", null);
        }

        final byte[] payload;
        try {
            payload = body == null ? null
                    : body.toString().getBytes(StandardCharsets.UTF_8);
        } catch (RuntimeException e) {
            throw new RelayException(RelayException.Kind.CONFIG, "cannot encode request", e);
        }
        if (payload != null && payload.length > MAX_REQUEST_BYTES) {
            throw new RelayException(RelayException.Kind.CONFIG, "request body is too large", null);
        }

        HttpURLConnection connection = null;
        try {
            URL url = new URL(baseUrl, path);
            if (!sameOrigin(url)) {
                throw new RelayException(RelayException.Kind.CONFIG,
                        "request would leave the configured origin", null);
            }
            connection = (HttpURLConnection) url.openConnection();
            connection.setInstanceFollowRedirects(false);
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            connection.setUseCaches(false);
            connection.setRequestMethod(method);
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Accept-Encoding", "identity");
            connection.setRequestProperty("User-Agent", "Veil-Android/0.1");
            if (authorized) {
                connection.setRequestProperty("Authorization", "Bearer " + token);
            }
            if (payload != null) {
                connection.setDoOutput(true);
                connection.setFixedLengthStreamingMode(payload.length);
                connection.setRequestProperty("Content-Type", "application/json");
                try (OutputStream out = connection.getOutputStream()) {
                    out.write(payload);
                    out.flush();
                }
            }

            int status = connection.getResponseCode();
            if (status >= 300 && status < 400) {
                throw new RelayException(RelayException.Kind.REDIRECT, status,
                        "redirects are not followed");
            }
            long declaredLength = connection.getContentLengthLong();
            if (declaredLength > MAX_RESPONSE_BYTES) {
                throw new RelayException(RelayException.Kind.TOO_LARGE, status,
                        "response is too large");
            }
            InputStream stream = status >= 400
                    ? connection.getErrorStream()
                    : connection.getInputStream();
            byte[] responseBody = stream == null ? new byte[0] : readBounded(stream);

            if (status == 401 || status == 403) {
                throw new RelayException(RelayException.Kind.UNAUTHORIZED, status, "");
            }
            if (status == 429) {
                String retryAfter = connection.getHeaderField("Retry-After");
                throw new RelayException(RelayException.Kind.RATE_LIMITED, status,
                        retryAfter == null ? "" : retryAfter);
            }
            if (status < 200 || status >= 300) {
                throw new RelayException(RelayException.Kind.SERVER, status,
                        detailOf(responseBody));
            }
            if (responseBody.length == 0) {
                throw new RelayException(RelayException.Kind.EMPTY, status, "");
            }
            try {
                return new JSONObject(Codec.fromUtf8(responseBody));
            } catch (JSONException e) {
                throw new RelayException(RelayException.Kind.DECODING,
                        "response is not JSON", e);
            }
        } catch (java.net.SocketTimeoutException e) {
            throw new RelayException(RelayException.Kind.TIMEOUT, "request timed out", e);
        } catch (java.net.MalformedURLException e) {
            throw new RelayException(RelayException.Kind.CONFIG, "relay URL is invalid", e);
        } catch (java.io.IOException e) {
            throw new RelayException(RelayException.Kind.NETWORK, "network failure", e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private boolean sameOrigin(URL url) {
        if (!baseUrl.getProtocol().equalsIgnoreCase(url.getProtocol())) {
            return false;
        }
        if (!baseUrl.getHost().equalsIgnoreCase(url.getHost())) {
            return false;
        }
        return effectivePort(baseUrl) == effectivePort(url);
    }

    private static int effectivePort(URL url) {
        if (url.getPort() != -1) {
            return url.getPort();
        }
        return "https".equalsIgnoreCase(url.getProtocol()) ? 443 : 80;
    }

    private static byte[] readBounded(InputStream stream) throws IOException, RelayException {
        try (InputStream in = stream) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int total = 0;
            int read;
            while ((read = in.read(buffer)) != -1) {
                total += read;
                if (total > MAX_RESPONSE_BYTES) {
                    throw new RelayException(RelayException.Kind.TOO_LARGE, 0,
                            "response is too large");
                }
                out.write(buffer, 0, read);
            }
            return out.toByteArray();
        }
    }

    private static String detailOf(byte[] body) {
        if (body == null || body.length == 0) {
            return "";
        }
        try {
            JSONObject json = new JSONObject(Codec.fromUtf8(body));
            String detail = json.optString("detail", "");
            detail = detail.replace('\n', ' ').replace('\r', ' ').trim();
            if (detail.length() > 180) {
                detail = detail.substring(0, 180);
            }
            return detail;
        } catch (JSONException e) {
            return "";
        }
    }

    private static String encodePath(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8").replace("+", "%20");
        } catch (java.io.UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void requireOk(JSONObject response) throws RelayException {
        try {
            if (!response.getBoolean("ok")) {
                throw new RelayException(RelayException.Kind.SERVER, 200, "server did not confirm");
            }
        } catch (JSONException e) {
            throw new RelayException(RelayException.Kind.DECODING, "ack response is invalid", e);
        }
    }

    // --- wire types ----------------------------------------------------------

    public static final class Health {
        public final String status;
        public final String version;

        Health(String status, String version) {
            this.status = status;
            this.version = version;
        }
    }

    public static final class RegisterResponse {
        public final String uid;
        public final String handle;
        public final String token;

        RegisterResponse(String uid, String handle, String token) {
            this.uid = uid;
            this.handle = handle;
            this.token = token;
        }
    }

    public static final class DirectoryEntry {
        public final String uid;
        public final String handle;
        public final int deviceId;
        public final String identityKey;

        DirectoryEntry(String uid, String handle, int deviceId, String identityKey) {
            this.uid = uid;
            this.handle = handle;
            this.deviceId = deviceId;
            this.identityKey = identityKey;
        }
    }
}
