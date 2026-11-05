package io.veil.messenger.core.model;

import io.veil.messenger.core.Codec;
import io.veil.messenger.core.Uuid7;
import org.json.JSONException;
import org.json.JSONObject;

/** Inbound envelope as returned by the relay (wire shape). */
public final class Envelope {

    public final String id;
    public final String senderUid;
    public final int senderDeviceId;
    public final String recipientUid;
    public final int recipientDeviceId;
    public final int messageType;
    public final String ciphertext;
    public final long createdAt;

    public Envelope(String id, String senderUid, int senderDeviceId, String recipientUid,
                    int recipientDeviceId, int messageType, String ciphertext, long createdAt) {
        this.id = id;
        this.senderUid = senderUid;
        this.senderDeviceId = senderDeviceId;
        this.recipientUid = recipientUid;
        this.recipientDeviceId = recipientDeviceId;
        this.messageType = messageType;
        this.ciphertext = ciphertext;
        this.createdAt = createdAt;
    }

    public static Envelope fromWire(JSONObject o) throws JSONException, Codec.CodecException {
        String id = Uuid7.normalize(o.getString("id"));
        String sender = Uuid7.normalize(o.getString("sender_uid"));
        String recipient = Uuid7.normalize(o.getString("recipient_uid"));
        if (id == null || sender == null || recipient == null) {
            throw new Codec.CodecException("envelope has non-canonical ids");
        }
        int messageType = o.getInt("message_type");
        if (messageType != 2 && messageType != 3) {
            throw new Codec.CodecException("envelope has unsupported message type");
        }
        int senderDevice = o.getInt("sender_device_id");
        int recipientDevice = o.getInt("recipient_device_id");
        if (senderDevice != 1 || recipientDevice != 1) {
            throw new Codec.CodecException("envelope has unsupported device id");
        }
        String ciphertext = o.getString("ciphertext");
        Codec.unb64(ciphertext, Codec.MAX_CIPHERTEXT_BYTES);
        long createdAt = o.optLong("created_at", 0L);
        return new Envelope(id, sender, senderDevice, recipient, recipientDevice,
                messageType, ciphertext, createdAt);
    }

    public JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("id", id);
        o.put("senderUid", senderUid);
        o.put("senderDeviceId", senderDeviceId);
        o.put("recipientUid", recipientUid);
        o.put("recipientDeviceId", recipientDeviceId);
        o.put("messageType", messageType);
        o.put("ciphertext", ciphertext);
        o.put("createdAt", createdAt);
        return o;
    }

    public static Envelope fromJson(JSONObject o) throws JSONException {
        return new Envelope(
                o.getString("id"),
                o.getString("senderUid"),
                o.getInt("senderDeviceId"),
                o.getString("recipientUid"),
                o.getInt("recipientDeviceId"),
                o.getInt("messageType"),
                o.getString("ciphertext"),
                o.optLong("createdAt", 0L));
    }
}
