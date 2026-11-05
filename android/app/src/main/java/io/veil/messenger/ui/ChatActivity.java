package io.veil.messenger.ui;

import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.EditText;
import android.widget.ListView;

import androidx.annotation.Nullable;

import com.google.android.material.appbar.MaterialToolbar;
import com.google.android.material.button.MaterialButton;

import java.util.ArrayList;
import java.util.List;

import io.veil.messenger.R;
import io.veil.messenger.core.AppCore;
import io.veil.messenger.core.VaultState;
import io.veil.messenger.core.model.ChatMessage;
import io.veil.messenger.core.model.Contact;

/** 1:1 chat. Sends go through the single core worker; UI never touches crypto. */
public final class ChatActivity extends BaseActivity implements AppCore.Listener {

    public static final String EXTRA_UID = "io.veil.messenger.extra.UID";

    private String uid;
    private MaterialToolbar toolbar;
    private ListView list;
    private View empty;
    private EditText input;
    private MaterialButton sendButton;
    private MessageAdapter adapter;
    private int lastCount = -1;
    private boolean sending;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_chat);

        uid = getIntent().getStringExtra(EXTRA_UID);
        if (uid == null) {
            finish();
            return;
        }

        toolbar = findViewById(R.id.toolbar);
        setSupportActionBar(toolbar);
        toolbar.setNavigationOnClickListener(view -> finish());
        Insets.top(toolbar);

        list = findViewById(R.id.list);
        empty = findViewById(R.id.empty);
        input = findViewById(R.id.input);
        sendButton = findViewById(R.id.sendButton);
        adapter = new MessageAdapter(getLayoutInflater());
        list.setAdapter(adapter);

        // Keeps the composer above the keyboard and above the navigation bar.
        Insets.bottomFollowsKeyboard(findViewById(R.id.composer));

        sendButton.setOnClickListener(view -> send());
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
        showNotice(message);
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_chat, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.action_verify) {
            Intent intent = new Intent(this, ContactActivity.class);
            intent.putExtra(ContactActivity.EXTRA_UID, uid);
            startActivity(intent);
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
        Contact contact = state.findContact(uid);
        if (contact == null) {
            finish();
            return;
        }
        toolbar.setTitle(Formatting.displayName(contact));
        toolbar.setSubtitle(contact.verified
                ? getString(R.string.chat_verified)
                : getString(R.string.chat_unverified));
        toolbar.setSubtitleTextColor(contact.verified
                ? themeValue(R.attr.veilStatusOk)
                : themeValue(R.attr.veilStatusPending));

        List<ChatMessage> messages = new ArrayList<>(state.messagesFor(uid));
        adapter.setData(messages, state.sendFailures);
        sendButton.setEnabled(!sending);
        empty.setVisibility(adapter.getCount() == 0 ? View.VISIBLE : View.GONE);
        if (adapter.getCount() != lastCount) {
            lastCount = adapter.getCount();
            if (lastCount > 0) {
                list.setSelection(lastCount - 1);
            }
        }
    }

    private void send() {
        if (sending) {
            return;
        }
        String text = input.getText() == null ? "" : input.getText().toString();
        if (text.trim().isEmpty()) {
            return;
        }
        sending = true;
        render();
        core().sendText(uid, text, new AppCore.Op() {
            @Override
            public void onSuccess() {
                sending = false;
                input.setText("");
                render();
            }

            @Override
            public void onFailure(String message) {
                sending = false;
                render();
                showNotice(message);
            }
        });
    }
}
