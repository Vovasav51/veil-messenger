package io.veil.messenger.ui;

import android.view.View;

import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

/**
 * Converts the window insets into extra padding.
 *
 * <p>targetSdk 35 makes every window edge-to-edge: the app draws behind the
 * status bar and behind the navigation bar / gesture handle, on API 35 and -
 * because {@link BaseActivity} disables decor fitting on every version - on
 * older releases too. No view can rely on the decor view being inset any more,
 * so the top inset is added to the app bar and the bottom inset to whatever
 * sits at the bottom of the screen. The chat composer additionally follows the
 * keyboard so the text field is never hidden by the IME.</p>
 *
 * <p>Insets are added to the padding the view already declares, so spacing
 * defined in XML keeps working. Insets are never consumed: nothing below these
 * views needs them, and consuming them would be wrong for scroll containers
 * that also report them to their children.</p>
 */
final class Insets {

    private Insets() {
    }

    /** Status bar (and display cutout) as top padding. */
    static void top(View view) {
        pad(view, true, false, false);
    }

    /** Navigation bar / gesture area as bottom padding. */
    static void bottom(View view) {
        pad(view, false, true, false);
    }

    /** Status bar on top, navigation bar at the bottom. */
    static void topAndBottom(View view) {
        pad(view, true, true, false);
    }

    /**
     * Bottom padding that grows to the keyboard height while the IME is open
     * and falls back to the navigation-bar height otherwise. Used by the chat
     * composer so the message field stays above the keyboard.
     */
    static void bottomFollowsKeyboard(View view) {
        pad(view, false, false, true);
    }

    private static void pad(View view, boolean top, boolean bottom, boolean keyboard) {
        final int left = view.getPaddingLeft();
        final int initialTop = view.getPaddingTop();
        final int right = view.getPaddingRight();
        final int initialBottom = view.getPaddingBottom();

        ViewCompat.setOnApplyWindowInsetsListener(view, (target, windowInsets) -> {
            androidx.core.graphics.Insets bars = windowInsets.getInsets(
                    WindowInsetsCompat.Type.systemBars()
                            | WindowInsetsCompat.Type.displayCutout());
            int topInset = top ? bars.top : 0;
            int bottomInset;
            if (bottom) {
                bottomInset = bars.bottom;
            } else if (keyboard) {
                // On API 30+ the keyboard is reported separately and the window
                // is no longer resized, so the bar has to move by itself. Below
                // API 30 ime() is 0 and the legacy adjustResize path resizes the
                // window instead, hence no double offset.
                androidx.core.graphics.Insets ime =
                        windowInsets.getInsets(WindowInsetsCompat.Type.ime());
                bottomInset = Math.max(bars.bottom, ime.bottom);
            } else {
                bottomInset = 0;
            }
            target.setPadding(left, initialTop + topInset, right, initialBottom + bottomInset);
            return windowInsets;
        });
        ViewCompat.requestApplyInsets(view);
    }
}
