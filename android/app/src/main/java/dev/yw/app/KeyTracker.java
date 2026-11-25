package dev.yw.app;

import java.util.ArrayList;
import java.util.List;

/**
 * The app keyboard's fingers (spec/15 §9.2; 2026-11-26 A2 final review): which key each finger went down on, by pointer
 * id, so that typing with two thumbs loses no key. A key is typed when its own finger goes up on it, or, when another
 * finger goes down first, right then (rollover: the keys come out in the order they went down). A finger that goes up
 * somewhere else types nothing. Before, the keyboard followed only the first finger: a key pressed while another was
 * still down was dropped, and the last finger up could type for the wrong key.
 *
 * <p>It keeps only the codes of keys under a finger now (the layout's, {@link KeyLayout}); nothing typed is kept.
 * Platform-neutral: tested by the JVM runner (JvmTests.keyTracker).
 */
final class KeyTracker {
    /** No key. */
    static final int NONE = Integer.MIN_VALUE;

    /** {pointer id, row, column, code}, in the order the fingers went down. */
    private final List<int[]> down = new ArrayList<>();

    /** Another finger goes down: the codes of the keys still under a finger, in order; they are typed now, once. */
    int[] rollover() {
        int[] codes = new int[down.size()];
        for (int at = 0; at < codes.length; at++) {
            codes[at] = down.get(at)[3];
        }
        down.clear();
        return codes;
    }

    /** Finger {@code id} went down on the key {@code code} at (row, col). */
    void down(int id, int row, int col, int code) {
        forget(id);
        down.add(new int[] {id, row, col, code});
    }

    /** Finger {@code id} went up over the key at (row, col) (-1, -1: none): the code to type, or {@link #NONE}. */
    int up(int id, int row, int col) {
        int[] key = forget(id);
        return key != null && key[1] == row && key[2] == col ? key[3] : NONE;
    }

    /** No finger is down (cancelled, or another keyboard). */
    void clear() {
        down.clear();
    }

    /** Whether a finger is on the key at (row, col). */
    boolean isDown(int row, int col) {
        for (int[] key : down) {
            if (key[1] == row && key[2] == col) {
                return true;
            }
        }
        return false;
    }

    private int[] forget(int id) {
        for (int at = 0; at < down.size(); at++) {
            if (down.get(at)[0] == id) {
                return down.remove(at);
            }
        }
        return null;
    }
}
