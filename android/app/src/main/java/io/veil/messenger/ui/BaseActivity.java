package io.veil.messenger.ui;

import android.os.Bundle;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.annotation.AttrRes;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.view.WindowCompat;

import io.veil.messenger.R;
import io.veil.messenger.VeilApp;
import io.veil.messenger.core.AppCore;

/**
 * Shared activity behaviour: FLAG_SECURE on every window, a privacy shield when
 * the activity is backgrounded (so the recents thumbnail is never live content),
 * and one fatal-storage dialog that never offers to wipe data.
 *
 * <p>Every screen draws edge-to-edge (targetSdk 35 enforces it), so the content
 * root must never assume it starts below the status bar; each activity applies
 * {@link Insets} to its own app bar and bottom container.</p>
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
        // Draw behind the system bars on every supported release, not only on
        // API 35 where it is mandatory. Insets are then applied by each screen.
        WindowCompat.setDecorFitsSystemWindows(getWindow(), false);
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

    /** Resolves a theme attribute (colour, dimension) to a concrete value. */
    protected int themeValue(@AttrRes int attr) {
        TypedValue value = new TypedValue();
        if (!getTheme().resolveAttribute(attr, value, true)) {
            return 0;
        }
        if (value.resourceId != 0) {
            return getResources().getColor(value.resourceId, getTheme());
        }
        return value.data;
    }

    private void showPrivacyShield() {
        ViewGroup root = findViewById(android.R.id.content);
        if (root == null || privacyShield != null) {
            return;
        }
        int muted = themeValue(com.google.android.material.R.attr.colorOnSurfaceVariant);

        LinearLayout shield = new LinearLayout(this);
        shield.setOrientation(LinearLayout.VERTICAL);
        shield.setGravity(Gravity.CENTER_HORIZONTAL);
        shield.setBackgroundColor(ContextCompat.getColor(this, R.color.veil_shield));
        shield.setClickable(true);
        shield.setFocusable(true);

        ImageView mark = new ImageView(this);
        mark.setImageResource(R.drawable.ic_veil_mark);
        mark.setImageTintList(android.content.res.ColorStateList.valueOf(muted));
        mark.setContentDescription(null);
        LinearLayout.LayoutParams markParams =
                new LinearLayout.LayoutParams(dp(40), dp(40));
        shield.addView(mark, markParams);

        TextView wordmark = new TextView(this);
        wordmark.setText(R.string.privacy_overlay);
        wordmark.setTextSize(20f);
        wordmark.setLetterSpacing(0.3f);
        wordmark.setTextColor(muted);
        LinearLayout.LayoutParams textParams = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        textParams.topMargin = dp(16);
        shield.addView(wordmark, textParams);

        root.addView(shield, new ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        privacyShield = shield;
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
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
