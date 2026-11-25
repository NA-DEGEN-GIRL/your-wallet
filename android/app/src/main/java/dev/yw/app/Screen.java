package dev.yw.app;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.os.Handler;
import android.os.Looper;
import java.util.ArrayDeque;
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
 */
final class Screen {
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final Map<String, Runnable> TIMERS = new HashMap<>();
    /** The last sessions Rust closed (2026-11-25 A2-7). */
    private static final ArrayDeque<Long> CLOSED = new ArrayDeque<>();
    private static final int CLOSED_MAX = 32;
    private static Context app;
    private static Object model;
    private static MainActivity shown;
    /** The started Activity that can start a secret window (main or secret), or null (2026-11-25 A2-7). */
    private static Activity top;
    /** A secret window asked while no Activity was started (-1: none). */
    private static long pendingOpen = -1;
    /** The secret window that draws now. */
    private static SecretActivity secret;

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

    /** An Activity of the app started (2026-11-25 A2-7): a secret window waiting for one is started from it. */
    static void started(Activity activity) {
        top = activity;
        if (pendingOpen >= 0) {
            long serial = pendingOpen;
            pendingOpen = -1;
            launch(serial);
        }
    }

    /** An Activity of the app stopped. */
    static void stopped(Activity activity) {
        if (top == activity) {
            top = null;
        }
    }

    /** A secret window was made; it draws the secret models from now on. */
    static void secretCreated(SecretActivity activity) {
        secret = activity;
    }

    /** A secret window is destroyed. */
    static void secretDestroyed(SecretActivity activity) {
        if (secret == activity) {
            secret = null;
        }
    }

    /** Whether Rust closed the session {@code serial} already (a window starting for it closes itself). */
    static boolean wasClosed(long serial) {
        return CLOSED.contains(serial);
    }

    private static void launch(long serial) {
        if (serial < 0) {
            return;
        }
        if (top == null) {
            pendingOpen = serial;
            return;
        }
        top.startActivity(new Intent(top, SecretActivity.class).putExtra(SecretActivity.EXTRA_SERIAL, serial));
    }

    private static void closeSecret(long serial) {
        if (serial < 0) {
            return;
        }
        CLOSED.addLast(serial);
        while (CLOSED.size() > CLOSED_MAX) {
            CLOSED.removeFirst();
        }
        if (pendingOpen == serial) {
            pendingOpen = -1;
        }
        if (secret != null && secret.serial() == serial) {
            secret.closeFromRust();
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
                closeSecret(Json.number(frame, "serial", -1));
                break;
            case "s_model":
                if (secret != null) {
                    secret.applyModel(frame);
                }
                break;
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
