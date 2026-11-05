package io.veil.messenger.crypto;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * All ratchet/identity state that must survive a process restart.
 *
 * <p>This class is deliberately free of Android APIs and of libsignal calls: it
 * is a plain JSON-backed record holder. libsignal records are stored as their
 * opaque serialized bytes (base64) exactly as the library produced them, so no
 * ratchet detail is ever reinterpreted by this app.
 */
public final class CryptoState {

    /** Bounded cache of Kyber base keys already used with our last-resort prekey. */
    private static final int MAX_USED_KYBER_KEYS = 256;

    public int registrationId;
    public String identityKeyPair;
    public SignedPreKeyState signedPreKey;
    public KyberPreKeyState kyberPreKey;
    public final List<PreKeyState> oneTimePreKeys = new ArrayList<>();
    public int nextPreKeyId = 1;
    public int nextKyberPreKeyId = 1;
    public int lastUploadedPreKeyId;
    public final Map<String, String> sessions = new LinkedHashMap<>();
    public final Map<String, String> identities = new LinkedHashMap<>();
    public final List<String> usedKyberBaseKeys = new ArrayList<>();

    public boolean hasIdentity() {
        return identityKeyPair != null && !identityKeyPair.isEmpty()
                && registrationId >= 1 && signedPreKey != null && kyberPreKey != null;
    }

    public void markKyberBaseKeyUsed(String key) {
        if (usedKyberBaseKeys.contains(key)) {
            return;
        }
        usedKyberBaseKeys.add(key);
        while (usedKyberBaseKeys.size() > MAX_USED_KYBER_KEYS) {
            usedKyberBaseKeys.remove(0);
        }
    }

    public JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("registrationId", registrationId);
        o.put("identityKeyPair", identityKeyPair);
        if (signedPreKey != null) {
            o.put("signedPreKey", signedPreKey.toJson());
        }
        if (kyberPreKey != null) {
            o.put("kyberPreKey", kyberPreKey.toJson());
        }
        JSONArray otks = new JSONArray();
        for (PreKeyState key : oneTimePreKeys) {
            otks.put(key.toJson());
        }
        o.put("oneTimePreKeys", otks);
        o.put("nextPreKeyId", nextPreKeyId);
        o.put("nextKyberPreKeyId", nextKyberPreKeyId);
        o.put("lastUploadedPreKeyId", lastUploadedPreKeyId);
        o.put("sessions", new JSONObject(sessions));
        o.put("identities", new JSONObject(identities));
        o.put("usedKyberBaseKeys", new JSONArray(usedKyberBaseKeys));
        return o;
    }

    public static CryptoState fromJson(JSONObject o) throws JSONException {
        CryptoState state = new CryptoState();
        state.registrationId = o.optInt("registrationId", 0);
        state.identityKeyPair = o.optString("identityKeyPair", null);
        if (o.has("signedPreKey") && !o.isNull("signedPreKey")) {
            state.signedPreKey = SignedPreKeyState.fromJson(o.getJSONObject("signedPreKey"));
        }
        if (o.has("kyberPreKey") && !o.isNull("kyberPreKey")) {
            state.kyberPreKey = KyberPreKeyState.fromJson(o.getJSONObject("kyberPreKey"));
        }
        JSONArray otks = o.optJSONArray("oneTimePreKeys");
        if (otks != null) {
            for (int i = 0; i < otks.length(); i++) {
                state.oneTimePreKeys.add(PreKeyState.fromJson(otks.getJSONObject(i)));
            }
        }
        state.nextPreKeyId = o.optInt("nextPreKeyId", 1);
        state.nextKyberPreKeyId = o.optInt("nextKyberPreKeyId", 1);
        state.lastUploadedPreKeyId = o.optInt("lastUploadedPreKeyId", 0);
        JSONObject sessions = o.optJSONObject("sessions");
        if (sessions != null) {
            for (java.util.Iterator<String> it = sessions.keys(); it.hasNext(); ) {
                String key = it.next();
                state.sessions.put(key, sessions.getString(key));
            }
        }
        JSONObject identities = o.optJSONObject("identities");
        if (identities != null) {
            for (java.util.Iterator<String> it = identities.keys(); it.hasNext(); ) {
                String key = it.next();
                state.identities.put(key, identities.getString(key));
            }
        }
        JSONArray used = o.optJSONArray("usedKyberBaseKeys");
        if (used != null) {
            for (int i = 0; i < used.length(); i++) {
                state.usedKyberBaseKeys.add(used.getString(i));
            }
        }
        return state;
    }

    /** Stored signed prekey record plus its creation time. */
    public static final class SignedPreKeyState {
        public final int id;
        public final long createdAtMs;
        public final String record;

        public SignedPreKeyState(int id, long createdAtMs, String record) {
            this.id = id;
            this.createdAtMs = createdAtMs;
            this.record = record;
        }

        JSONObject toJson() throws JSONException {
            JSONObject o = new JSONObject();
            o.put("id", id);
            o.put("createdAtMs", createdAtMs);
            o.put("record", record);
            return o;
        }

        static SignedPreKeyState fromJson(JSONObject o) throws JSONException {
            return new SignedPreKeyState(
                    o.getInt("id"), o.optLong("createdAtMs", 0L), o.getString("record"));
        }
    }

    /** Stored Kyber prekey record plus its creation time. */
    public static final class KyberPreKeyState {
        public final int id;
        public final long createdAtMs;
        public final String record;

        public KyberPreKeyState(int id, long createdAtMs, String record) {
            this.id = id;
            this.createdAtMs = createdAtMs;
            this.record = record;
        }

        JSONObject toJson() throws JSONException {
            JSONObject o = new JSONObject();
            o.put("id", id);
            o.put("createdAtMs", createdAtMs);
            o.put("record", record);
            return o;
        }

        static KyberPreKeyState fromJson(JSONObject o) throws JSONException {
            return new KyberPreKeyState(
                    o.getInt("id"), o.optLong("createdAtMs", 0L), o.getString("record"));
        }
    }

    /** Stored one-time prekey record. */
    public static final class PreKeyState {
        public final int id;
        public final String record;

        public PreKeyState(int id, String record) {
            this.id = id;
            this.record = record;
        }

        JSONObject toJson() throws JSONException {
            JSONObject o = new JSONObject();
            o.put("id", id);
            o.put("record", record);
            return o;
        }

        static PreKeyState fromJson(JSONObject o) throws JSONException {
            return new PreKeyState(o.getInt("id"), o.getString("record"));
        }
    }
}
