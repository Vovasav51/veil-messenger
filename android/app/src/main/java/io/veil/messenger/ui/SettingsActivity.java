package io.veil.messenger.ui;

import android.os.Bundle;
import android.widget.TextView;

import androidx.annotation.Nullable;

import com.google.android.material.appbar.MaterialToolbar;

import io.veil.messenger.BuildConfig;
import io.veil.messenger.R;
import io.veil.messenger.core.AppCore;
import io.veil.messenger.core.VaultState;

/** Honest account/security summary and the exact limitations of this build. */
public final class SettingsActivity extends BaseActivity implements AppCore.Listener {

    private TextView accountHandle;
    private TextView accountUid;
    private TextView accountServer;
    private TextView statusValue;
    private TextView versionValue;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        MaterialToolbar toolbar = findViewById(R.id.toolbar);
        toolbar.setNavigationOnClickListener(view -> finish());

        accountHandle = findViewById(R.id.accountHandle);
        accountUid = findViewById(R.id.accountUid);
        accountServer = findViewById(R.id.accountServer);
        statusValue = findViewById(R.id.statusValue);
        versionValue = findViewById(R.id.versionValue);
        versionValue.setText(getString(R.string.settings_build_legal, BuildConfig.VERSION_NAME));
        versionValue.setOnClickListener(view -> showLicense());
        render();
    }

    @Override
    protected void onStart() {
        super.onStart();
        core().addListener(this);
        render();
    }

    @Override
    protected void onStop() {
        core().removeListener(this);
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

    private void render() {
        VaultState state = core().state();
        if (state.account != null) {
            accountHandle.setText(getString(R.string.settings_handle_at, state.account.handle));
            accountUid.setText(state.account.uid);
            accountServer.setText(state.account.serverUrl);
            statusValue.setText(R.string.settings_status_ready);
        } else {
            accountHandle.setText("—");
            accountUid.setText("—");
            accountServer.setText(state.pending == null ? "—" : state.pending.serverUrl);
            statusValue.setText(state.pending == null
                    ? "—" : getString(R.string.settings_status_pending));
        }
    }

    private void showLicense() {
        try (java.io.InputStream input = getAssets().open("AGPL-3.0.txt")) {
            java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();
            byte[] bytes = new byte[4096];
            int length;
            while ((length = input.read(bytes)) != -1) buffer.write(bytes, 0, length);
            TextView text = new TextView(this);
            text.setPadding(24, 12, 24, 12);
            text.setText(new String(buffer.toByteArray(), java.nio.charset.StandardCharsets.UTF_8));
            text.setTextIsSelectable(true);
            android.widget.ScrollView scroll = new android.widget.ScrollView(this);
            scroll.addView(text);
            new com.google.android.material.dialog.MaterialAlertDialogBuilder(this)
                    .setTitle("AGPL-3.0")
                    .setView(scroll)
                    .setPositiveButton(android.R.string.ok, null)
                    .show();
        } catch (java.io.IOException error) {
            showNotice(getString(R.string.settings_license_fallback));
        }
    }
}
