package io.veil.messenger.ui;

import android.view.Gravity;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.LinearLayout;
import android.widget.TextView;

import com.google.android.material.color.MaterialColors;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import io.veil.messenger.R;
import io.veil.messenger.core.model.ChatMessage;

/**
 * Chat bubbles. Incoming text is plain text (never HTML/markdown). Incoming and
 * outgoing bubbles differ in shape, background and text colour, both resolved
 * from the theme so the dark variant stays readable.
 */
final class MessageAdapter extends BaseAdapter {

    private final LayoutInflater inflater;
    private final List<ChatMessage> messages = new ArrayList<>();
    private Map<String, String> failures = new LinkedHashMap<>();

    MessageAdapter(LayoutInflater inflater) {
        this.inflater = inflater;
    }

    void setData(List<ChatMessage> newMessages, Map<String, String> newFailures) {
        messages.clear();
        messages.addAll(newMessages);
        failures = newFailures;
        notifyDataSetChanged();
    }

    int size() {
        return messages.size();
    }

    @Override
    public int getCount() {
        return messages.size();
    }

    @Override
    public ChatMessage getItem(int position) {
        return messages.get(position);
    }

    @Override
    public long getItemId(int position) {
        return messages.get(position).id.hashCode();
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View view = convertView;
        if (view == null) {
            view = inflater.inflate(R.layout.item_message, parent, false);
            view.setTag(new Holder(view));
        }
        Holder holder = (Holder) view.getTag();
        ChatMessage message = getItem(position);
        holder.body.setText(message.text);
        holder.bubble.setBackgroundResource(message.outgoing
                ? R.drawable.bg_bubble_out : R.drawable.bg_bubble_in);
        int bubbleText = message.outgoing
                ? R.attr.veilBubbleOutText
                : R.attr.veilBubbleInText;
        holder.body.setTextColor(MaterialColors.getColor(holder.body, bubbleText));
        ((LinearLayout) view).setGravity(message.outgoing ? Gravity.END : Gravity.START);

        String meta = Formatting.time(message.createdAtMs);
        String failure = failures.get(message.id);
        if (failure != null) {
            meta = meta + " · " + failure;
            holder.meta.setTextColor(MaterialColors.getColor(holder.meta,
                    com.google.android.material.R.attr.colorError));
        } else {
            String status = Formatting.messageStatus(message);
            if (!status.isEmpty()) {
                meta = meta + " · " + status;
            }
            holder.meta.setTextColor(MaterialColors.getColor(holder.meta,
                    com.google.android.material.R.attr.colorOnSurfaceVariant));
        }
        holder.meta.setText(meta);
        return view;
    }

    private static final class Holder {
        final View bubble;
        final TextView body;
        final TextView meta;

        Holder(View view) {
            bubble = view.findViewById(R.id.bubble);
            body = view.findViewById(R.id.body);
            meta = view.findViewById(R.id.meta);
        }
    }
}
