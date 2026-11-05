package io.veil.messenger.core.model;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Verified/known peer. {@code identityKey} is the pinned base64 Signal identity
 * public key learned from the relay directory; it is never silently replaced.
 */
public final class Contact {

    public final String uid;
    public final String handle;
    public final String identityKey;
    public final boolean verified;

    public Contact(String uid, String handle, String identityKey, boolean verified) {
        this.uid = uid;
        this.handle = handle;
        this.identityKey = identityKey;
        this.verified = verified;
    }

    public Contact withVerified(boolean value) {
        return new Contact(uid, handle, identityKey, value);
    }

    public JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("uid", uid);
        o.put("handle", handle);
        o.put("identityKey", identityKey);
        o.put("verified", verified);
        return o;
    }

    public static Contact fromJson(JSONObject o) throws JSONException {
        return new Contact(
                o.getString("uid"),
                o.getString("handle"),
                o.getString("identityKey"),
                o.optBoolean("verified", false));
    }
}
