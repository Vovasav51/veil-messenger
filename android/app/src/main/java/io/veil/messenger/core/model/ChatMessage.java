package io.veil.messenger.core.model;

import org.json.JSONException;
import org.json.JSONObject;

/** One 1:1 text message as stored locally (plaintext, vault-encrypted at rest). */
public final class ChatMessage {

    public static final String STATUS_QUEUED = "queued";
    public static final String STATUS_SENT = "sent";
    public static final String STATUS_RECEIVED = "received";

    public final String id;
    public final String peerUid;
    public final String text;
    public final boolean outgoing;
    public final long createdAtMs;
    public final String status;

    public ChatMessage(String id, String peerUid, String text, boolean outgoing,
                       long createdAtMs, String status) {
        this.id = id;
        this.peerUid = peerUid;
        this.text = text;
        this.outgoing = outgoing;
        this.createdAtMs = createdAtMs;
        this.status = status;
    }

    public ChatMessage withStatus(String value) {
        return new ChatMessage(id, peerUid, text, outgoing, createdAtMs, value);
    }

    public JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("id", id);
        o.put("peerUid", peerUid);
        o.put("text", text);
        o.put("outgoing", outgoing);
        o.put("createdAtMs", createdAtMs);
        o.put("status", status);
        return o;
    }

    public static ChatMessage fromJson(JSONObject o) throws JSONException {
        return new ChatMessage(
                o.getString("id"),
                o.getString("peerUid"),
                o.getString("text"),
                o.getBoolean("outgoing"),
                o.getLong("createdAtMs"),
                o.getString("status"));
    }
}
