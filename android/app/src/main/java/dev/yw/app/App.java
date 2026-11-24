package dev.yw.app;

import android.app.Application;
import android.content.Context;

/**
 * The application (spec/15 §3.2-§3.3; 2026-11-24 A2-3). Before anything else it replaces the default
 * uncaught-exception handler, then loads libyw.so in the main process only (§18 1): JNI_OnLoad first makes the
 * process non-dumpable (prctl), then registers the native methods. A failed load is fatal and never caught (§3.2):
 * the app does not go on without the wallet library.
 *
 * <p>2026-11-25 A2-4b: in onCreate the main process starts the I/O thread ({@link IoLoop}, the Keystore device key
 * and the memory facts that Rust requests, §3.2) and then sends the start input with the no-backup folder (§5.1),
 * where Rust keeps the data folder v3 and its log file.
 *
 * <p>2026-11-25 A2-5: then the device facts (DeviceFacts, spec/15 §1.1, §8.2), so that Rust logs the protection tier
 * once at start; the main Activity sends them again on every onStart.
 *
 * <p>2026-11-25 A2-6: the screen state keeps the application context (the clipboard of a copy) before the I/O thread
 * starts handing it frames; the start input makes Rust post the first screen model.
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

    @Override
    public void onCreate() {
        super.onCreate();
        if (loaded) {
            Screen.init(this);
            IoLoop.start(this);
            byte[] start = Wire.start(getNoBackupFilesDir().getAbsolutePath());
            if (start != null) {
                Native.call(start);
            }
            Native.call(DeviceFacts.input(this));
        }
    }

    /** Whether this process loaded libyw.so (and so registered the native methods). */
    static boolean loaded() {
        return loaded;
    }
}
