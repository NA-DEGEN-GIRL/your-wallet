package dev.yw.app;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * The secret windows of the process and the app's started Activities (spec/15 §9.1, §5.4; 2026-11-25 A2-7 review):
 * the bookkeeping {@link Screen} does on the main thread, kept free of android.* so that the JVM runner tests it.
 *
 * <ul>
 *   <li>Every live secret window (Activity instance), not only the last one made: {@code s_close} closes every window of
 *       its session, {@code s_close_win} that one window only (a ready Rust did not take: late, a repeated or older
 *       instance id), {@code s_keep} every window the list does not name (Rust's resync after the UI queue dropped
 *       frames: a lost {@code s_close} still closes its window), and a model goes to the one window it names.
 *   <li>A session asked again ({@code s_open} after a resync) whose window exists or is starting is not started again
 *       (before, a second Activity of the same session could start, and the first one lost every later frame).
 *   <li>The started count of §5.4: the app is in the background only when none of its Activities is started; a secret
 *       window covering the main one is not the app leaving ({@link #started}, {@link #stopped}).
 * </ul>
 *
 * <p>Before this review, Screen kept one secret window, the last one made, and set it to null when that one was
 * destroyed; MainActivity sent {@code life back} on its own onStop.
 */
final class SecretWindows<W extends SecretWindows.Win> {
    /** A secret window as the registry sees it. */
    interface Win {
        /** The session it was opened for. */
        long serial();

        /** Its instance id (counted up, never reused). */
        int win();

        /** Closes it, wiped, because Rust said so (sends nothing back). */
        void closeFromRust();
    }

    /** How many closed sessions are kept (a window still starting for one closes itself). */
    static final int CLOSED_MAX = 32;

    private final List<W> live = new ArrayList<>();
    private final Set<Long> starting = new HashSet<>();
    private final ArrayDeque<Long> closed = new ArrayDeque<>();
    private long pending = -1;
    private int started;

    /**
     * Whether {@code serial} is to be started now: not when it is negative, closed already, or when a window of it is
     * live or starting. With no started Activity to start it from ({@code canStart} false) it waits as the pending one.
     */
    boolean launch(long serial, boolean canStart) {
        if (serial < 0 || closed.contains(serial) || starting.contains(serial) || liveOf(serial)) {
            return false;
        }
        if (!canStart) {
            pending = serial;
            return false;
        }
        if (pending == serial) {
            pending = -1;
        }
        starting.add(serial);
        return true;
    }

    /** The session waiting for a started Activity to start it from (-1: none); it is taken. */
    long takePending() {
        long serial = pending;
        pending = -1;
        return serial;
    }

    /** A secret window was made. */
    void created(W window) {
        starting.remove(window.serial());
        live.add(window);
    }

    /** A secret window is destroyed. */
    void destroyed(W window) {
        live.remove(window);
    }

    /** Whether Rust closed session {@code serial} already. */
    boolean wasClosed(long serial) {
        return closed.contains(serial);
    }

    /** {@code s_close}: every window of the session closes, and one still starting for it closes itself. */
    void close(long serial) {
        if (serial < 0) {
            return;
        }
        markClosed(serial);
        for (W window : new ArrayList<>(live)) {
            if (window.serial() == serial) {
                window.closeFromRust();
            }
        }
    }

    /** {@code s_close_win}: that one window only; the session goes on. */
    void closeWin(long serial, long win) {
        for (W window : new ArrayList<>(live)) {
            if (window.serial() == serial && window.win() == win) {
                window.closeFromRust();
            }
        }
    }

    /**
     * {@code s_keep}: every window not named closes. Each entry is {serial, win}; win 0 keeps every window of that
     * session (an asked one whose instance Rust does not know yet). A session not named at all is closed (as by
     * s_close); another window of a named session (a duplicate) closes alone.
     */
    void keep(List<long[]> kept) {
        for (W window : new ArrayList<>(live)) {
            if (!named(kept, window.serial(), window.win())) {
                if (!named(kept, window.serial(), 0)) {
                    markClosed(window.serial());
                }
                window.closeFromRust();
            }
        }
        for (Long serial : new ArrayList<>(starting)) {
            if (!named(kept, serial, 0)) {
                markClosed(serial);
            }
        }
        if (pending >= 0 && !named(kept, pending, 0)) {
            markClosed(pending);
        }
    }

    /** The live window {@code win} of session {@code serial}, or null. */
    W find(long serial, long win) {
        for (W window : live) {
            if (window.serial() == serial && window.win() == win) {
                return window;
            }
        }
        return null;
    }

    /** The live windows (tests). */
    int liveCount() {
        return live.size();
    }

    /** An Activity of the app started; true when it is the first one (the app came to the front). */
    boolean started() {
        started++;
        return started == 1;
    }

    /** An Activity of the app stopped; true when none is started any more (the app went to the background). */
    boolean stopped() {
        if (started == 0) {
            return false;
        }
        started--;
        return started == 0;
    }

    private boolean liveOf(long serial) {
        for (W window : live) {
            if (window.serial() == serial) {
                return true;
            }
        }
        return false;
    }

    private void markClosed(long serial) {
        starting.remove(serial);
        if (pending == serial) {
            pending = -1;
        }
        if (!closed.contains(serial)) {
            closed.addLast(serial);
            while (closed.size() > CLOSED_MAX) {
                closed.removeFirst();
            }
        }
    }

    private static boolean named(List<long[]> kept, long serial, long win) {
        for (long[] entry : kept) {
            if (entry.length == 2 && entry[0] == serial && (entry[1] == 0 || win == 0 || entry[1] == win)) {
                return true;
            }
        }
        return false;
    }
}
