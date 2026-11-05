package io.veil.messenger.ui;

import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

import io.veil.messenger.R;
import io.veil.messenger.core.VaultState;
import io.veil.messenger.core.model.ChatMessage;
import io.veil.messenger.core.model.Contact;

/** 1:1 conversation list: contact handle, last message preview and time. */
final class ConversationAdapter extends BaseAdapter {

    private final LayoutInflater inflater;
    private final List<Contact> contacts = new ArrayList<>();
    private VaultState state = VaultState.empty();

    ConversationAdapter(LayoutInflater inflater) {
        this.inflater = inflater;
    }

    void setData(List<Contact> newContacts, VaultState newState) {
        contacts.clear();
        contacts.addAll(newContacts);
        state = newState;
        notifyDataSetChanged();
    }

    @Override
    public int getCount() {
        return contacts.size();
    }

    @Override
    public Contact getItem(int position) {
        return contacts.get(position);
    }

    @Override
    public long getItemId(int position) {
        return contacts.get(position).uid.hashCode();
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
        View view = convertView;
        if (view == null) {
            view = inflater.inflate(R.layout.item_conversation, parent, false);
            view.setTag(new Holder(view));
        }
        Holder holder = (Holder) view.getTag();
        Contact contact = getItem(position);
        ChatMessage last = state.lastMessageFor(contact.uid);
        holder.name.setText(Formatting.displayName(contact));
        holder.snippet.setText(last == null
                ? holder.snippet.getContext().getString(R.string.main_no_messages)
                : Formatting.snippet(last));
        holder.time.setText(last == null ? "" : Formatting.time(last.createdAtMs));
        return view;
    }

    private static final class Holder {
        final TextView name;
        final TextView snippet;
        final TextView time;

        Holder(View view) {
            name = view.findViewById(R.id.name);
            snippet = view.findViewById(R.id.snippet);
            time = view.findViewById(R.id.time);
        }
    }
}
