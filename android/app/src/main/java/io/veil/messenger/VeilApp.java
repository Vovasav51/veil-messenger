package io.veil.messenger;

import android.app.Application;

import io.veil.messenger.core.AppCore;

/** Process-wide holder for the single-threaded core. */
public final class VeilApp extends Application {

    private AppCore core;

    @Override
    public void onCreate() {
        super.onCreate();
        core = new AppCore(this);
    }

    public AppCore core() {
        return core;
    }
}
