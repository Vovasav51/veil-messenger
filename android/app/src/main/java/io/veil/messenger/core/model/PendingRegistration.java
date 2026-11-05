package io.veil.messenger.core.model;

import io.veil.messenger.core.Uuid7;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * Registration that has been persisted locally before the network request.
 * If the result is uncertain the same UID and the same keys must be reused;
 * a fresh UID would create a second, unusable identity.
 */
public final class PendingRegistration {

    public final String uid;
    public final String handle;
    public final String serverUrl;
    public final long createdAtMs;

    public PendingRegistration(String uid, String handle, String serverUrl, long createdAtMs) {
        this.uid = uid;
        this.handle = handle;
        this.serverUrl = serverUrl;
        this.createdAtMs = createdAtMs;
    }

    public PendingRegistration withHandle(String value) {
        return new PendingRegistration(uid, value, serverUrl, createdAtMs);
    }

    public PendingRegistration withServerUrl(String value) {
        return new PendingRegistration(uid, handle, value, createdAtMs);
    }

    public JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("uid", uid);
        o.put("handle", handle);
        o.put("serverUrl", serverUrl);
        o.put("createdAtMs", createdAtMs);
        return o;
    }

    public static PendingRegistration fromJson(JSONObject o) throws JSONException {
        String uid = Uuid7.normalize(o.getString("uid"));
        if (uid == null) {
            throw new JSONException("pending registration has invalid uid");
        }
        return new PendingRegistration(
                uid,
                o.getString("handle"),
                o.getString("serverUrl"),
                o.optLong("createdAtMs", 0L));
    }
}
