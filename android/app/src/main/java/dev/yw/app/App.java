package dev.yw.app;

import android.app.Application;
import android.content.Context;

/**
 * The application (spec/15 §3.2-§3.3; 2026-11-24 A2-3). Before anything else it replaces the default
 * uncaught-exception handler, then loads libyw.so in the main process only (§18 1): JNI_OnLoad first makes the
 * process non-dumpable (prctl), then registers the native methods. A failed load is fatal and never caught (§3.2):
 * the app does not go on without the wallet library.
 */
public final class App extends Application {
    private static volatile boolean loaded;

    @Override
    protected void attachBaseContext(Context base) {
        Thread.setDefaultUncaughtExceptionHandler(new UncaughtGuard());
        super.attachBaseContext(base);
        if (ProcessRule.isMainProcess(Application.getProcessName(), getPackageName())) {
            System.loadLibrary("yw");
            loaded = true;
        }
    }

    /** Whether this process loaded libyw.so (and so registered the native methods). */
    static boolean loaded() {
        return loaded;
    }
}
