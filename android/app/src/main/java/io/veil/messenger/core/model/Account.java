package io.veil.messenger.core.model;

import org.json.JSONException;
import org.json.JSONObject;

/** Local account. The relay token never leaves the encrypted vault. */
public final class Account {

    public final String uid;
    public final String handle;
    public final String token;
    public final String serverUrl;

    public Account(String uid, String handle, String token, String serverUrl) {
        this.uid = uid;
        this.handle = handle;
        this.token = token;
        this.serverUrl = serverUrl;
    }

    public JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("uid", uid);
        o.put("handle", handle);
        o.put("token", token);
        o.put("serverUrl", serverUrl);
        return o;
    }

    public static Account fromJson(JSONObject o) throws JSONException {
        return new Account(
                o.getString("uid"),
                o.getString("handle"),
                o.getString("token"),
                o.getString("serverUrl"));
    }
}
