package dev.yw.app;

import java.util.IdentityHashMap;
import java.util.Map;

/**
 * The buttons of a secret window that a finger is on (spec/15 §9.1; 2026-11-26 A2 final review): what each touch sends
 * ({@code down}, {@code up}, {@code out}) and which part of the window may be rebuilt. Android cancels a touch whose view
 * is removed, so while a finger is on a button, the part that holds the button is kept: neither the body (W05's checkbox,
 * every field's hold-to-reveal) nor the button row (W08's hold) is rebuilt until every finger on its buttons is up, left
 * or cancelled. Rust decides everything else; this class only reports the edges.
 *
 * <p>The 2026-11-25 A2 device run kept only the button row (SecretActivity.pressed): the body was rebuilt by the very
 * model that answers a button's {@code down}, so the checkbox never toggled under a finger that stayed on it for longer
 * than a tap, and a reveal ended at once.
 *
 * <p>A button is named by its object (the View; any object in the JVM tests). A finger is on it while it stays inside the
 * rectangle the button had on the screen when it went down (a relayout under the finger, such as a box that takes another
 * line, is not the finger leaving). Platform-neutral: tested by the JVM runner (JvmTests.heldButtons).
 */
final class HeldButtons {
    /** The redrawn body: the checkbox and the reveals. */
    static final int BODY = 0;

    /** The button row under it. */
    static final int ROW = 1;

    static final String DOWN = "down";
    static final String UP = "up";
    static final String OUT = "out";

    private static final class Hold {
        final int place;
        final float left;
        final float top;
        final float right;
        final float bottom;

        Hold(int place, float left, float top, float width, float height) {
            this.place = place;
            this.left = left;
            this.top = top;
            this.right = left + width;
            this.bottom = top + height;
        }

        boolean holds(float x, float y) {
            return x >= left && x <= right && y >= top && y <= bottom;
        }
    }

    private final Map<Object, Hold> held = new IdentityHashMap<>();

    /**
     * A finger went down on {@code button} of {@code place}, whose rectangle on the screen starts at (left, top): the
     * edge to send, or null for a disabled button (it is not held, and no later edge of that touch is sent).
     */
    String down(Object button, int place, boolean enabled, float left, float top, float width, float height) {
        if (!enabled) {
            return null;
        }
        held.put(button, new Hold(place, left, top, width, height));
        return DOWN;
    }

    /** The finger on {@code button} moved to (x, y) on the screen: {@code out} once when it left, else null. */
    String moved(Object button, float x, float y) {
        Hold hold = held.get(button);
        if (hold == null || hold.holds(x, y)) {
            return null;
        }
        held.remove(button);
        return OUT;
    }

    /** The finger on {@code button} went up at (x, y): {@code up} on it, else {@code out}; null when it is not held. */
    String up(Object button, float x, float y) {
        Hold hold = held.remove(button);
        if (hold == null) {
            return null;
        }
        return hold.holds(x, y) ? UP : OUT;
    }

    /** The touch on {@code button} was cancelled: {@code out}, or null when it is not held (any more). */
    String cancelled(Object button) {
        return held.remove(button) == null ? null : OUT;
    }

    /** Whether {@code place} may be rebuilt from a model now: no finger is on a button of it. */
    boolean rebuilds(int place) {
        for (Hold hold : held.values()) {
            if (hold.place == place) {
                return false;
            }
        }
        return true;
    }

    /** No finger is on any button (the window is hidden). */
    void clear() {
        held.clear();
    }
}
