package dev.yw.app;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import java.util.HashMap;
import java.util.Map;

/**
 * The screen's process state on the main thread (spec/15 §3.2; 2026-11-25 A2-6): the model Rust handed out last, the
 * Activity that draws it, the one-shot timers Rust asked for and the copies. The I/O thread hands each UI frame here
 * ({@link #post}); everything else runs on the main thread. Rust never calls Java: what Rust wants done arrives as a
 * frame, and Java's answers go back as inputs through {@link Native#call}.
 *
 * <p>2026-11-25 A2-7: and the secret windows (spec/15 §9.1): {@code s_open} starts a {@link SecretActivity} for a
 * secret session from the Activity in front (or, with none in front, as soon as one starts), {@code s_close} closes
 * the window of that session (and one still starting for it closes itself at once), {@code s_model} goes to the
 * secret window that draws now, which draws it only when it is its own.
 *
 * <p>2026-11-25 A2-7 review: the secret windows are kept in {@link SecretWindows}, every live one: {@code s_close}
 * closes every window of its session, {@code s_close_win} one window, {@code s_keep} (Rust's resync) every window not
 * named, a model goes to the window it names, and a session whose window exists or is starting is not started again.
 * The lifetime events go by the app's started-Activity count (spec/15 §5.4): {@code life front} when the first Activity
 * starts, {@code life back} when the last one stops; a secret window covering the main one is not the background.
 * Before, Screen kept only the last secret window made, and MainActivity sent the events on its own onStart/onStop.
 */
final class Screen {
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final Map<String, Runnable> TIMERS = new HashMap<>();
    /** The secret windows and the started count (2026-11-25 A2-7 review). */
    private static final SecretWindows<SecretActivity> WINDOWS = new SecretWindows<>();
    private static Context app;
    private static Object model;
    private static MainActivity shown;
    /** The started Activity that can start a secret window (main or secret), or null (2026-11-25 A2-7). */
    private static Activity top;

    private Screen() {}

    /** Keeps the application context (the clipboard). */
    static void init(Context context) {
        app = context.getApplicationContext();
    }

    /** A frame from {@link Native#next} (any thread): a UI frame goes to the main thread, anything else is dropped. */
    static void post(byte[] bytes) {
        Object frame = UiWire.frame(bytes);
        if (frame != null) {
            MAIN.post(() -> apply(frame));
        }
    }

    /** Sends one input to Rust (main thread). */
    static void send(byte[] input) {
        if (input != null && App.loaded()) {
            Native.call(input);
        }
    }

    /**
     * An Activity of the app started (2026-11-25 A2-7): a secret window waiting for one is started from it. The first
     * started Activity sends {@code life front} (2026-11-25 A2-7 review, spec/15 §5.4).
     */
    static void started(Activity activity) {
        top = activity;
        if (WINDOWS.started()) {
            send(UiWire.life("front"));
        }
        long serial = WINDOWS.takePending();
        if (serial >= 0) {
            launch(serial);
        }
    }

    /**
     * An Activity of the app stopped; when none is started any more the app is in the background: {@code life back}
     * (2026-11-25 A2-7 review: a secret window covering the main Activity is not; before, MainActivity's onStop sent it).
     */
    static void stopped(Activity activity) {
        if (top == activity) {
            top = null;
        }
        if (WINDOWS.stopped()) {
            send(UiWire.life("back"));
        }
    }

    /** A secret window was made. */
    static void secretCreated(SecretActivity activity) {
        WINDOWS.created(activity);
    }

    /** A secret window is destroyed. */
    static void secretDestroyed(SecretActivity activity) {
        WINDOWS.destroyed(activity);
    }

    /** Whether Rust closed the session {@code serial} already (a window starting for it closes itself). */
    static boolean wasClosed(long serial) {
        return WINDOWS.wasClosed(serial);
    }

    /** Starts the secret window of {@code serial}, unless one of it exists or is starting (2026-11-25 A2-7 review). */
    private static void launch(long serial) {
        if (WINDOWS.launch(serial, top != null)) {
            top.startActivity(new Intent(top, SecretActivity.class).putExtra(SecretActivity.EXTRA_SERIAL, serial));
        }
    }

    /** The Activity in front draws from now on; it gets the last model at once. */
    static void attach(MainActivity activity) {
        shown = activity;
        if (model != null) {
            activity.drawModel(model);
        }
    }

    /** The Activity stopped drawing. */
    static void detach(MainActivity activity) {
        if (shown == activity) {
            shown = null;
        }
    }

    private static void apply(Object frame) {
        String kind = Json.string(frame, "t");
        switch (kind) {
            case "model":
                model = frame;
                if (shown != null) {
                    shown.drawModel(frame);
                }
                break;
            case "field":
            case "reveal":
            case "top":
                if (shown != null) {
                    shown.applyFrame(frame);
                }
                break;
            case "timer":
                startTimer(Json.string(frame, "id"), Json.number(frame, "ms", -1));
                break;
            case "stop_timer":
                stopTimer(Json.string(frame, "id"));
                break;
            case "copy":
                copy(Json.number(frame, "id", -1), Json.string(frame, "text"));
                break;
            case "s_open":
                launch(Json.number(frame, "serial", -1));
                break;
            case "s_close":
                WINDOWS.close(Json.number(frame, "serial", -1));
                break;
            case "s_close_win":
                WINDOWS.closeWin(Json.number(frame, "serial", -1), Json.number(frame, "win", -1));
                break;
            case "s_keep":
                WINDOWS.keep(SecretWire.kept(frame));
                break;
            case "s_model": {
                SecretActivity window =
                        WINDOWS.find(Json.number(frame, "serial", -1), Json.number(frame, "win", -1));
                if (window != null) {
                    window.applyModel(frame);
                }
                break;
            }
            default:
                break;
        }
    }

    private static void startTimer(String id, long ms) {
        if (id == null || ms < 0) {
            return;
        }
        stopTimer(id);
        Runnable fire = () -> {
            TIMERS.remove(id);
            send(UiWire.timer(id));
        };
        TIMERS.put(id, fire);
        MAIN.postDelayed(fire, ms);
    }

    private static void stopTimer(String id) {
        Runnable fire = id == null ? null : TIMERS.remove(id);
        if (fire != null) {
            MAIN.removeCallbacks(fire);
        }
    }

    /** Non-secret text only (an address, a hash: Rust's CopyText); the label is empty (Java holds no text). */
    private static void copy(long id, String text) {
        if (id < 0 || text == null) {
            return;
        }
        boolean ok = false;
        try {
            ClipboardManager clipboard = app == null ? null : app.getSystemService(ClipboardManager.class);
            if (clipboard != null) {
                clipboard.setPrimaryClip(ClipData.newPlainText("", text));
                ok = true;
            }
        } catch (RuntimeException refused) {
            ok = false;
        }
        send(UiWire.copied(id, ok));
    }
}
