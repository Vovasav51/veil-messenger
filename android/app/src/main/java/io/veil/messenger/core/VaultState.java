package io.veil.messenger.core;

import io.veil.messenger.core.model.Account;
import io.veil.messenger.core.model.ChatMessage;
import io.veil.messenger.core.model.Contact;
import io.veil.messenger.core.model.OutgoingEnvelope;
import io.veil.messenger.core.model.PendingRegistration;
import io.veil.messenger.crypto.CryptoState;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The complete durable client state, serialized as one JSON document inside the
 * AES-GCM vault. Nothing here is secret by itself; the file it lives in is.
 */
public final class VaultState {

    /** Bounded dedup ring. The relay TTL is 30 days; 5000 ids is plenty. */
    public static final int MAX_PROCESSED_IDS = 5000;
    public static final int MAX_SEND_FAILURES = 200;

    public Account account;
    public PendingRegistration pending;
    public final List<Contact> contacts = new ArrayList<>();
    public final List<ChatMessage> messages = new ArrayList<>();
    public final List<OutgoingEnvelope> outbox = new ArrayList<>();
    public final List<String> processedEnvelopeIds = new ArrayList<>();
    /** Message id -> human-readable permanent rejection reason. */
    public final Map<String, String> sendFailures = new LinkedHashMap<>();
    public CryptoState crypto = new CryptoState();

    public static VaultState empty() {
        return new VaultState();
    }

    // --- lookups -------------------------------------------------------------

    public Contact findContact(String uid) {
        for (Contact contact : contacts) {
            if (contact.uid.equals(uid)) {
                return contact;
            }
        }
        return null;
    }

    public Contact findContactByHandle(String handle) {
        for (Contact contact : contacts) {
            if (contact.handle.equals(handle)) {
                return contact;
            }
        }
        return null;
    }

    public void upsertContact(Contact contact) {
        for (int i = 0; i < contacts.size(); i++) {
            if (contacts.get(i).uid.equals(contact.uid)) {
                contacts.set(i, contact);
                return;
            }
        }
        contacts.add(contact);
    }

    public boolean removeContact(String uid) {
        for (int i = 0; i < contacts.size(); i++) {
            if (contacts.get(i).uid.equals(uid)) {
                contacts.remove(i);
                return true;
            }
        }
        return false;
    }

    public List<ChatMessage> messagesFor(String peerUid) {
        List<ChatMessage> result = new ArrayList<>();
        for (ChatMessage message : messages) {
            if (message.peerUid.equals(peerUid)) {
                result.add(message);
            }
        }
        return result;
    }

    public ChatMessage findMessage(String id) {
        for (ChatMessage message : messages) {
            if (message.id.equals(id)) {
                return message;
            }
        }
        return null;
    }

    public ChatMessage lastMessageFor(String peerUid) {
        ChatMessage last = null;
        for (ChatMessage message : messages) {
            if (message.peerUid.equals(peerUid)) {
                last = message;
            }
        }
        return last;
    }

    public void setMessageStatus(String id, String status) {
        for (int i = 0; i < messages.size(); i++) {
            if (messages.get(i).id.equals(id)) {
                messages.set(i, messages.get(i).withStatus(status));
                return;
            }
        }
    }

    // --- outbox --------------------------------------------------------------

    public OutgoingEnvelope findOutbox(String id) {
        for (OutgoingEnvelope envelope : outbox) {
            if (envelope.id.equals(id)) {
                return envelope;
            }
        }
        return null;
    }

    public boolean removeOutbox(String id) {
        for (int i = 0; i < outbox.size(); i++) {
            if (outbox.get(i).id.equals(id)) {
                outbox.remove(i);
                return true;
            }
        }
        return false;
    }

    public void recordSendFailure(String id, String reason) {
        sendFailures.put(id, reason);
        while (sendFailures.size() > MAX_SEND_FAILURES) {
            Iterator<String> it = sendFailures.keySet().iterator();
            it.next();
            it.remove();
        }
    }

    // --- dedup ---------------------------------------------------------------

    public boolean isProcessed(String envelopeId) {
        return processedEnvelopeIds.contains(envelopeId);
    }

    public void markProcessed(String envelopeId) {
        if (processedEnvelopeIds.contains(envelopeId)) {
            return;
        }
        processedEnvelopeIds.add(envelopeId);
        while (processedEnvelopeIds.size() > MAX_PROCESSED_IDS) {
            processedEnvelopeIds.remove(0);
        }
    }

    // --- serialization -------------------------------------------------------

    public JSONObject toJson() throws JSONException {
        JSONObject o = new JSONObject();
        o.put("version", 1);
        if (account != null) {
            o.put("account", account.toJson());
        }
        if (pending != null) {
            o.put("pending", pending.toJson());
        }
        JSONArray contactArray = new JSONArray();
        for (Contact contact : contacts) {
            contactArray.put(contact.toJson());
        }
        o.put("contacts", contactArray);
        JSONArray messageArray = new JSONArray();
        for (ChatMessage message : messages) {
            messageArray.put(message.toJson());
        }
        o.put("messages", messageArray);
        JSONArray outboxArray = new JSONArray();
        for (OutgoingEnvelope envelope : outbox) {
            outboxArray.put(envelope.toJson());
        }
        o.put("outbox", outboxArray);
        o.put("processed", new JSONArray(processedEnvelopeIds));
        o.put("sendFailures", new JSONObject(sendFailures));
        o.put("crypto", crypto.toJson());
        return o;
    }

    public static VaultState fromJson(JSONObject o) throws JSONException {
        VaultState state = new VaultState();
        if (o.has("account") && !o.isNull("account")) {
            state.account = Account.fromJson(o.getJSONObject("account"));
        }
        if (o.has("pending") && !o.isNull("pending")) {
            state.pending = PendingRegistration.fromJson(o.getJSONObject("pending"));
        }
        JSONArray contacts = o.optJSONArray("contacts");
        if (contacts != null) {
            for (int i = 0; i < contacts.length(); i++) {
                state.contacts.add(Contact.fromJson(contacts.getJSONObject(i)));
            }
        }
        JSONArray messages = o.optJSONArray("messages");
        if (messages != null) {
            for (int i = 0; i < messages.length(); i++) {
                state.messages.add(ChatMessage.fromJson(messages.getJSONObject(i)));
            }
        }
        JSONArray outbox = o.optJSONArray("outbox");
        if (outbox != null) {
            for (int i = 0; i < outbox.length(); i++) {
                state.outbox.add(OutgoingEnvelope.fromJson(outbox.getJSONObject(i)));
            }
        }
        JSONArray processed = o.optJSONArray("processed");
        if (processed != null) {
            for (int i = 0; i < processed.length(); i++) {
                state.processedEnvelopeIds.add(processed.getString(i));
            }
            while (state.processedEnvelopeIds.size() > MAX_PROCESSED_IDS) {
                state.processedEnvelopeIds.remove(0);
            }
        }
        JSONObject failures = o.optJSONObject("sendFailures");
        if (failures != null) {
            for (Iterator<String> it = failures.keys(); it.hasNext(); ) {
                String key = it.next();
                state.sendFailures.put(key, failures.getString(key));
            }
        }
        JSONObject crypto = o.optJSONObject("crypto");
        if (crypto != null) {
            state.crypto = CryptoState.fromJson(crypto);
        }
        return state;
    }

    /**
     * Deep copy used for transactional mutation. A copy that fails to serialize
     * is a bug in the model, not a storage failure.
     */
    public VaultState copy() {
        try {
            return fromJson(new JSONObject(toJson().toString()));
        } catch (JSONException e) {
            throw new IllegalStateException("vault state is not serializable", e);
        }
    }
}
