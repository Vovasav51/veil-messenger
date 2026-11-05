package io.veil.messenger.ui;

import android.os.Bundle;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.TextView;

import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import io.veil.messenger.R;
import io.veil.messenger.VeilApp;
import io.veil.messenger.core.AppCore;

/**
 * Shared activity behaviour: FLAG_SECURE on every window, a privacy shield when
 * the activity is backgrounded (so the recents thumbnail is never live content),
 * and one fatal-storage dialog that never offers to wipe data.
 */
public abstract class BaseActivity extends AppCompatActivity {

    private View privacyShield;
    private boolean fatalDialogShown;

    protected AppCore core() {
        return ((VeilApp) getApplication()).core();
    }

    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        super.onCreate(savedInstanceState);
        core().ensureStarted();
    }

    @Override
    protected void onResume() {
        super.onResume();
        removePrivacyShield();
        if (core().isFatal()) {
            showFatal();
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (!isFinishing()) {
            showPrivacyShield();
        }
    }

    private void showPrivacyShield() {
        ViewGroup root = findViewById(android.R.id.content);
        if (root == null || privacyShield != null) {
            return;
        }
        TextView shield = new TextView(this);
        shield.setText(R.string.privacy_overlay);
        shield.setTextSize(24f);
        shield.setLetterSpacing(0.35f);
        shield.setGravity(android.view.Gravity.CENTER);
        shield.setTextColor(getColor(R.color.veil_text_muted));
        shield.setBackgroundColor(getColor(R.color.veil_bg));
        shield.setClickable(true);
        shield.setFocusable(true);
        root.addView(shield, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        privacyShield = shield;
    }

    private void removePrivacyShield() {
        if (privacyShield == null) {
            return;
        }
        ViewGroup parent = (ViewGroup) privacyShield.getParent();
        if (parent != null) {
            parent.removeView(privacyShield);
        }
        privacyShield = null;
    }

    protected void showFatal() {
        if (fatalDialogShown || isFinishing()) {
            return;
        }
        fatalDialogShown = true;
        new AlertDialog.Builder(this)
                .setTitle(R.string.fatal_title)
                .setMessage(core().fatalMessage().isEmpty()
                        ? getString(R.string.fatal_body) : core().fatalMessage())
                .setCancelable(false)
                .setPositiveButton(R.string.fatal_exit, (dialog, which) -> finishAffinity())
                .show();
    }

    protected void showNotice(String message) {
        android.widget.Toast.makeText(this, message, android.widget.Toast.LENGTH_LONG).show();
    }

    protected void setStatusText(int viewId, String message) {
        TextView view = findViewById(viewId);
        if (view == null) {
            return;
        }
        if (message == null || message.isEmpty()) {
            view.setVisibility(View.GONE);
            view.setText("");
        } else {
            view.setText(message);
            view.setVisibility(View.VISIBLE);
        }
    }
}
