package dev.yw.app;

import java.nio.charset.StandardCharsets;

/**
 * The secret windows' half of the wire (spec/15 §3.2, §9.1-§9.2; 2026-11-25 A2-7): the inputs a secret window sends
 * through {@link Native#call}, the field token of {@link Native#secretKey} and the frame kinds. None carries a secret:
 * a typed unit goes through secretKey, a shown text comes through secretFill. Rust (yw-android secret_wire,
 * secret_keys) decodes the same bytes; its tests and JvmTests.secretInputs pin them.
 *
 * <ul>
 *   <li>{@code s_ready}: the window of a secret session is attached and read back its FLAG_SECURE ({@code secure}),
 *       with the device facts read for this open (the debugging band, §8.2);
 *   <li>{@code s_btn}: a button, a field's reveal or a field box: {@code down}, {@code up} (released on it) or
 *       {@code out} (the finger left it or the touch was cancelled);
 *   <li>{@code s_focus}, {@code s_back}, {@code s_gone} (the Activity is destroyed).
 * </ul>
 *
 * <p>Frames (yw-android secret_wire): {@code s_open}, {@code s_close} (every window of a session), {@code s_model},
 * and since the 2026-11-25 A2-7 review {@code s_close_win} (one window: a ready Rust did not take) and {@code s_keep}
 * (Rust's resync: every window not named closes, {@link #kept}).
 *
 * <p>Platform-neutral: tested by the JVM runner.
 */
final class SecretWire {
    /** Bits of a field token below the window id (yw-android secret_keys::TARGET_BITS). */
    static final int TARGET_BITS = 8;

    /** The largest window id (yw-android secret_keys::WIN_MAX). */
    static final int WIN_MAX = (1 << 23) - 1;

    /** The token target that picks W05's completion (yw-android secret_keys::TARGET_PICK). */
    static final int TARGET_PICK = 0x40;

    /** The most completions a window shows (yw-engine secret::form::WORD_CANDIDATES_MAX). */
    static final int CANDIDATES_MAX = 4;

    private SecretWire() {}

    /** The field token of {@code target} (a field index, or TARGET_PICK) in window {@code win}; -1 when out of range. */
    static int field(int win, int target) {
        if (win <= 0 || win > WIN_MAX || target < 0 || target > 0xff) {
            return -1;
        }
        return win << TARGET_BITS | target;
    }

    /** {@code {"t":"s_ready","serial":S,"win":W,"secure":B,<facts members>}}; facts as Wire.factsMembers. */
    static byte[] ready(long serial, int win, boolean secure, String factsMembers) {
        return utf8("{\"t\":\"s_ready\",\"serial\":" + serial + ",\"win\":" + win + ",\"secure\":" + secure + ","
                + factsMembers + "}");
    }

    /** {@code {"t":"s_btn","win":W,"b":"…","i":N,"e":"down"|"up"|"out"}}. */
    static byte[] button(int win, String word, int index, String edge) {
        return utf8("{\"t\":\"s_btn\",\"win\":" + win + ",\"b\":" + Json.quote(word) + ",\"i\":" + Math.max(0, index)
                + ",\"e\":" + Json.quote(edge) + "}");
    }

    /** {@code {"t":"s_focus","win":W,"on":B}}. */
    static byte[] focus(int win, boolean on) {
        return utf8("{\"t\":\"s_focus\",\"win\":" + win + ",\"on\":" + on + "}");
    }

    /** {@code {"t":"s_back","win":W}}. */
    static byte[] back(int win) {
        return utf8("{\"t\":\"s_back\",\"win\":" + win + "}");
    }

    /** {@code {"t":"s_gone","serial":S,"win":W}}. */
    static byte[] gone(long serial, int win) {
        return utf8("{\"t\":\"s_gone\",\"serial\":" + serial + ",\"win\":" + win + "}");
    }

    /**
     * The windows a frame {@code {"t":"s_keep","wins":[{"serial":S,"win":W},…]}} keeps (2026-11-25 A2-7 review), each
     * {serial, win} with win 0 for every window of that session; an entry that does not read keeps nothing (the
     * windows it might have named close: fail closed).
     */
    static java.util.List<long[]> kept(Object frame) {
        java.util.List<long[]> kept = new java.util.ArrayList<>();
        for (Object entry : Json.list(frame, "wins")) {
            long serial = Json.number(entry, "serial", -1);
            long win = Json.number(entry, "win", -1);
            if (serial >= 0 && win >= 0 && win <= WIN_MAX) {
                kept.add(new long[] {serial, win});
            }
        }
        return kept;
    }

    /**
     * The label of the button {@code word} in the model {@code frame}'s {@code buttons}, or null when it has none
     * (2026-11-25 A2 device run: a held button keeps its view and takes only its new label, spec/15 §9.1).
     */
    static String buttonLabel(Object frame, String word) {
        for (Object button : Json.list(frame, "buttons")) {
            if (word != null && word.equals(Json.string(button, "b"))) {
                return Json.string(button, "label");
            }
        }
        return null;
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
