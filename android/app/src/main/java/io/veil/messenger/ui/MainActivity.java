package io.veil.messenger.ui;

import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.ListView;

import androidx.annotation.Nullable;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.google.android.material.snackbar.Snackbar;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import io.veil.messenger.R;
import io.veil.messenger.core.AppCore;
import io.veil.messenger.core.VaultState;
import io.veil.messenger.core.model.ChatMessage;
import io.veil.messenger.core.model.Contact;

/** Conversation list: one row per known contact, newest activity first. */
public final class MainActivity extends BaseActivity implements AppCore.Listener {

    private ListView list;
    private View empty;
    private ConversationAdapter adapter;
    private final List<Contact> conversations = new ArrayList<>();

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        Insets.top(toolbar);

        list = findViewById(R.id.list);
        empty = findViewById(R.id.empty);
        Insets.bottom(findViewById(R.id.content));
        adapter = new ConversationAdapter(getLayoutInflater());
        list.setAdapter(adapter);

        list.setOnItemClickListener((parent, view, position, id) -> {
            Contact contact = adapter.getItem(position);
            Intent intent = new Intent(this, ChatActivity.class);
            intent.putExtra(ChatActivity.EXTRA_UID, contact.uid);
            startActivity(intent);
        });
        list.setOnItemLongClickListener((parent, view, position, id) -> {
            Contact contact = adapter.getItem(position);
            Intent intent = new Intent(this, ContactActivity.class);
            intent.putExtra(ContactActivity.EXTRA_UID, contact.uid);
            startActivity(intent);
            return true;
        });

        FloatingActionButton add = findViewById(R.id.addButton);
        View.OnClickListener addContact =
                view -> startActivity(new Intent(this, ContactActivity.class));
        add.setOnClickListener(addContact);
        findViewById(R.id.emptyAddButton).setOnClickListener(addContact);
    }

    @Override
    protected void onStart() {
        super.onStart();
        core().addListener(this);
        core().setForeground(true);
        render();
    }

    @Override
    protected void onStop() {
        core().removeListener(this);
        core().setForeground(false);
        super.onStop();
    }

    @Override
    public void onReady() {
        render();
    }

    @Override
    public void onStateChanged() {
        render();
    }

    @Override
    public void onFatal(String message) {
        showFatal();
    }

    @Override
    public void onNotice(String message) {
        Snackbar.make(list, message, Snackbar.LENGTH_LONG)
                .setAnchorView(findViewById(R.id.addButton))
                .show();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_refresh) {
            core().refreshNow();
            return true;
        }
        if (id == R.id.action_settings) {
            startActivity(new Intent(this, SettingsActivity.class));
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private void render() {
        if (core().isFatal()) {
            showFatal();
            return;
        }
        if (!core().isReady()) {
            return;
        }
        VaultState state = core().state();
        if (state.account == null) {
            startActivity(new Intent(this, OnboardingActivity.class));
            finish();
            return;
        }

        List<Contact> sorted = new ArrayList<>(state.contacts);
        Collections.sort(sorted, new Comparator<Contact>() {
            @Override
            public int compare(Contact left, Contact right) {
                long leftTime = lastTime(state, left.uid);
                long rightTime = lastTime(state, right.uid);
                if (leftTime != rightTime) {
                    return rightTime > leftTime ? 1 : -1;
                }
                return Formatting.displayName(left)
                        .compareToIgnoreCase(Formatting.displayName(right));
            }
        });
        conversations.clear();
        conversations.addAll(sorted);
        adapter.setData(conversations, state);
        empty.setVisibility(conversations.isEmpty() ? View.VISIBLE : View.GONE);
    }

    private static long lastTime(VaultState state, String uid) {
        ChatMessage last = state.lastMessageFor(uid);
        return last == null ? 0L : last.createdAtMs;
    }
}
