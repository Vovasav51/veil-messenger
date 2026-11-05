package io.veil.messenger.ui;

import android.content.Intent;
import android.os.Bundle;
import android.view.View;
import android.widget.ProgressBar;

import androidx.annotation.Nullable;

import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;

import io.veil.messenger.R;
import io.veil.messenger.core.AppCore;
import io.veil.messenger.core.VaultState;
import io.veil.messenger.core.model.PendingRegistration;

/**
 * Onboarding: relay URL and handle. The local identity and the pending UID are
 * persisted before the registration request, so an uncertain result can be
 * retried with the same identity instead of generating a new one.
 */
public final class OnboardingActivity extends BaseActivity implements AppCore.Listener {

    private TextInputEditText serverInput;
    private TextInputEditText handleInput;
    private MaterialButton createButton;
    private ProgressBar progress;
    private View pendingCard;
    private boolean prefilled;

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_onboarding);

        serverInput = findViewById(R.id.serverInput);
        handleInput = findViewById(R.id.handleInput);
        createButton = findViewById(R.id.createButton);
        progress = findViewById(R.id.progress);
        pendingCard = findViewById(R.id.pendingCard);

        createButton.setOnClickListener(view -> submit());
        core().start(this);
    }

    @Override
    protected void onStart() {
        super.onStart();
        core().addListener(this);
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
        if (core().isFatal()) {
            showFatal();
            return;
        }
        VaultState state = core().state();
        if (state.account != null) {
            openMain();
            return;
        }
        if (!prefilled && core().isReady()) {
            PendingRegistration pending = state.pending;
            if (pending != null) {
                serverInput.setText(pending.serverUrl);
                handleInput.setText(pending.handle);
                pendingCard.setVisibility(View.VISIBLE);
                createButton.setText(R.string.onboarding_retry);
            }
            prefilled = true;
        }
    }

    private void submit() {
        String server = serverInput.getText() == null
                ? "" : serverInput.getText().toString();
        String handle = handleInput.getText() == null
                ? "" : handleInput.getText().toString();
        setBusy(true);
        setStatusText(R.id.statusText, null);
        core().register(server, handle, new AppCore.Op() {
            @Override
            public void onSuccess() {
                setBusy(false);
                openMain();
            }

            @Override
            public void onFailure(String message) {
                setBusy(false);
                setStatusText(R.id.statusText, message);
            }
        });
    }

    private void setBusy(boolean busy) {
        createButton.setEnabled(!busy);
        serverInput.setEnabled(!busy);
        handleInput.setEnabled(!busy);
        progress.setVisibility(busy ? View.VISIBLE : View.GONE);
    }

    private void openMain() {
        if (isFinishing()) {
            return;
        }
        startActivity(new Intent(this, MainActivity.class));
        finish();
    }
}
