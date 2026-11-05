package io.veil.messenger.ui;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

import io.veil.messenger.core.model.ChatMessage;
import io.veil.messenger.core.model.Contact;

/** Small presentation helpers. No I/O, no logging. */
final class Formatting {

    private Formatting() {
    }

    /** Groups the 60 fingerprint digits into 12 blocks of five. */
    static String fingerprint(String digits) {
        if (digits == null) {
            return "";
        }
        StringBuilder builder = new StringBuilder(digits.length() + 12);
        for (int i = 0; i < digits.length(); i++) {
            if (i > 0 && i % 5 == 0) {
                builder.append(' ');
            }
            builder.append(digits.charAt(i));
        }
        return builder.toString();
    }

    static String displayName(Contact contact) {
        if (contact == null) {
            return "";
        }
        if (contact.handle == null || contact.handle.isEmpty()) {
            return "Невідомий · " + shortUid(contact.uid);
        }
        return "@" + contact.handle;
    }

    static String shortUid(String uid) {
        if (uid == null) {
            return "";
        }
        return uid.length() > 8 ? uid.substring(0, 8) : uid;
    }

    static String time(long epochMs) {
        Calendar now = Calendar.getInstance();
        Calendar then = Calendar.getInstance();
        then.setTimeInMillis(epochMs);
        boolean sameDay = now.get(Calendar.YEAR) == then.get(Calendar.YEAR)
                && now.get(Calendar.DAY_OF_YEAR) == then.get(Calendar.DAY_OF_YEAR);
        String pattern = sameDay ? "HH:mm" : "dd.MM";
        return new SimpleDateFormat(pattern, Locale.getDefault()).format(new Date(epochMs));
    }

    static String messageStatus(ChatMessage message) {
        if (message == null || !message.outgoing) {
            return "";
        }
        switch (message.status) {
            case ChatMessage.STATUS_SENT:
                return "надіслано";
            case ChatMessage.STATUS_RECEIVED:
                return "отримано";
            default:
                return "у черзі";
        }
    }

    static String snippet(ChatMessage message) {
        if (message == null) {
            return "";
        }
        String prefix = message.outgoing ? "Ви: " : "";
        String text = message.text.replace('\n', ' ');
        if (text.length() > 120) {
            text = text.substring(0, 120) + "…";
        }
        return prefix + text;
    }
}
