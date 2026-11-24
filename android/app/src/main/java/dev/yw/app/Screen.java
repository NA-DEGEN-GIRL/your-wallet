package dev.yw.app;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import java.util.HashMap;
import java.util.Map;

/**
 * The screen's process state on the main thread (spec/15 §3.2; 2026-11-25 A2-6): the model Rust handed out last, the
 * Activity that draws it, the one-shot timers Rust asked for and the copies. The I/O thread hands each UI frame here
 * ({@link #post}); everything else runs on the main thread. Rust never calls Java: what Rust wants done arrives as a
 * frame, and Java's answers go back as inputs through {@link Native#call}.
 */
final class Screen {
    private static final Handler MAIN = new Handler(Looper.getMainLooper());
    private static final Map<String, Runnable> TIMERS = new HashMap<>();
    private static Context app;
    private static Object model;
    private static MainActivity shown;

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
