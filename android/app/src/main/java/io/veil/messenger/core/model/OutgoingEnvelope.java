package io.veil.messenger.core.model;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Queued ciphertext. The id and ciphertext are frozen at encryption time:
 * retries re-send exactly these bytes and never re-encrypt (re-encryption would
 * advance the ratchet and lose the message on the peer side).
 */
public final class OutgoingEnvelope {

    public final String id;
    public final String recipientUid;
    public final int recipientDeviceId;
    public final int messageType;
    public final String ciphertext;

    public OutgoingEnvelope(String id, String recipientUid, int recipientDeviceId,
                            int messageType, String ciphertext) {
        this.id = id;
        this.recipientUid = recipientUid;
        this.recipientDeviceId = recipientDeviceId;
        this.messageType = messageType;
        this.ciphertext = ciphertext;
    }

    public JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("id", id);
        o.put("recipientUid", recipientUid);
        o.put("recipientDeviceId", recipientDeviceId);
        o.put("messageType", messageType);
        o.put("ciphertext", ciphertext);
        return o;
    }

    public static OutgoingEnvelope fromJson(JSONObject o) throws JSONException {
        return new OutgoingEnvelope(
                o.getString("id"),
                o.getString("recipientUid"),
                o.getInt("recipientDeviceId"),
                o.getInt("messageType"),
                o.getString("ciphertext"));
    }
}
