package io.veil.messenger.core.model;

import io.veil.messenger.core.Codec;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Wire-compatible {@code PublicBundle} from the Veil integration contract.
 * Key material is validated for exact serialized Signal sizes.
 */
public final class PublicBundle {

    public static final int SIGNAL_PUBLIC_KEY_LEN = 33;
    public static final int SIGNATURE_LEN = 64;
    /** Raw Kyber-1024 key material. */
    public static final int KYBER_PUBLIC_KEY_LEN = 1568;
    /**
     * Serialized key as libsignal actually emits it: 0x08 (KEM type) followed
     * by the 1568-byte Kyber-1024 key. The relay accepts 1568..1569, and the
     * 1569-byte form must be forwarded to libsignal unchanged.
     */
    public static final int KYBER_PUBLIC_KEY_SERIALIZED_LEN = 1569;
    public static final int OTK_MAX = 200;

    public final int registrationId;
    public final int deviceId;
    public final String identityKey;
    public final PublicSignedPreKey signedPreKey;
    public final PublicSignedPreKey kyberPreKey;
    public final List<PublicPreKey> oneTimePreKeys;

    public PublicBundle(int registrationId, int deviceId, String identityKey,
                        PublicSignedPreKey signedPreKey, PublicSignedPreKey kyberPreKey,
                        List<PublicPreKey> oneTimePreKeys) {
        this.registrationId = registrationId;
        this.deviceId = deviceId;
        this.identityKey = identityKey;
        this.signedPreKey = signedPreKey;
        this.kyberPreKey = kyberPreKey;
        this.oneTimePreKeys = Collections.unmodifiableList(new ArrayList<>(oneTimePreKeys));
    }

    public JSONObject toWireJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("registration_id", registrationId);
        o.put("device_id", deviceId);
        o.put("identity_key", identityKey);
        o.put("signed_prekey", signedPreKey.toWireJson());
        o.put("kyber_prekey", kyberPreKey.toWireJson());
        JSONArray array = new JSONArray();
        for (PublicPreKey key : oneTimePreKeys) {
            array.put(key.toWireJson());
        }
        o.put("one_time_prekeys", array);
        return o;
    }

    public static PublicBundle fromWire(JSONObject o) throws JSONException, Codec.CodecException {
        int registrationId = o.getInt("registration_id");
        if (registrationId < 1 || registrationId > 16380) {
            throw new Codec.CodecException("bundle registration_id out of range");
        }
        int deviceId = o.getInt("device_id");
        if (deviceId != 1) {
            throw new Codec.CodecException("bundle device_id must be 1");
        }
        String identity = requireSignalKey(o.getString("identity_key"), "identity_key");
        PublicSignedPreKey signed = PublicSignedPreKey.fromWire(o.getJSONObject("signed_prekey"), false);
        PublicSignedPreKey kyber = PublicSignedPreKey.fromWire(o.getJSONObject("kyber_prekey"), true);

        JSONArray array = o.optJSONArray("one_time_prekeys");
        List<PublicPreKey> otks = new ArrayList<>();
        int count = array == null ? 0 : array.length();
        if (count > OTK_MAX) {
            throw new Codec.CodecException("bundle has too many one-time prekeys");
        }
        for (int i = 0; i < count; i++) {
            otks.add(PublicPreKey.fromWire(array.getJSONObject(i)));
        }
        return new PublicBundle(registrationId, deviceId, identity, signed, kyber, otks);
    }

    public static String requireSignalKey(String value, String field) throws Codec.CodecException {
        byte[] raw = Codec.unb64(value, SIGNAL_PUBLIC_KEY_LEN);
        if (raw.length != SIGNAL_PUBLIC_KEY_LEN || raw[0] != 0x05) {
            throw new Codec.CodecException(field + " is not a serialized Signal public key");
        }
        return Codec.b64(raw);
    }

    public static String requireSignature(String value, String field) throws Codec.CodecException {
        byte[] raw = Codec.unb64(value, SIGNATURE_LEN);
        if (raw.length != SIGNATURE_LEN) {
            throw new Codec.CodecException(field + " has an invalid signature length");
        }
        return Codec.b64(raw);
    }

    /**
     * Validates a Kyber-1024 public key exactly as the relay bounds it
     * (1568 or 1569 bytes) and preserves the bytes: libsignal expects its own
     * 1569-byte serialized form (type tag 0x08 + 1568-byte key).
     */
    public static String requireKyberKey(String value, String field)
            throws Codec.CodecException {
        byte[] raw = Codec.unb64(value, KYBER_PUBLIC_KEY_SERIALIZED_LEN);
        if (raw.length != KYBER_PUBLIC_KEY_LEN
                && raw.length != KYBER_PUBLIC_KEY_SERIALIZED_LEN) {
            throw new Codec.CodecException(field + " has an invalid Kyber public key length");
        }
        if (raw.length == KYBER_PUBLIC_KEY_SERIALIZED_LEN && raw[0] != 0x08) {
            throw new Codec.CodecException(field + " has an invalid KEM type byte");
        }
        return Codec.b64(raw);
    }

    /** Immutable public one-time prekey. */
    public static final class PublicPreKey {
        public final int id;
        public final String publicKey;

        public PublicPreKey(int id, String publicKey) {
            this.id = id;
            this.publicKey = publicKey;
        }

        JSONObject toWireJson() throws JSONException {
            JSONObject o = new JSONObject();
            o.put("id", id);
            o.put("public_key", publicKey);
            return o;
        }

        static PublicPreKey fromWire(JSONObject o) throws JSONException, Codec.CodecException {
            return new PublicPreKey(o.getInt("id"),
                    requireSignalKey(o.getString("public_key"), "one_time_prekeys.public_key"));
        }
    }

    /** Signed prekey (both the X25519 and the Kyber variant use this shape). */
    public static final class PublicSignedPreKey {
        public final int id;
        public final String publicKey;
        public final String signature;

        public PublicSignedPreKey(int id, String publicKey, String signature) {
            this.id = id;
            this.publicKey = publicKey;
            this.signature = signature;
        }

        JSONObject toWireJson() throws JSONException {
            JSONObject o = new JSONObject();
            o.put("id", id);
            o.put("public_key", publicKey);
            o.put("signature", signature);
            return o;
        }

        static PublicSignedPreKey fromWire(JSONObject o, boolean kyber)
                throws JSONException, Codec.CodecException {
            String key = kyber
                    ? requireKyberKey(o.getString("public_key"), "kyber_prekey.public_key")
                    : requireSignalKey(o.getString("public_key"), "signed_prekey.public_key");
            String sig = requireSignature(o.getString("signature"),
                    kyber ? "kyber_prekey.signature" : "signed_prekey.signature");
            return new PublicSignedPreKey(o.getInt("id"), key, sig);
        }
    }
}
