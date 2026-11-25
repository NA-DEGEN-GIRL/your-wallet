package dev.yw.app;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * The screen half of the wire (spec/15 §3.2, §18 8; 2026-11-25 A2-6): the UI frames Rust hands out through
 * {@link Native#next} and the inputs Java sends back through {@link Native#call}. Rust decides what each input means:
 * a press names only the revision of the model it was drawn from and the control's slot, never what the control does
 * (Rust drops a press of another revision and resolves the slot to the press it drew). Java holds no fixed text: every
 * word it draws comes in a frame.
 *
 * <p>Frames ({@code 0x02} then yw-json): the model {@code {"t":"model","rev":R,"items":[…]}} (yw-engine
 * wire::model), {@code field} (with {@code seen}, 2026-11-25 A2-6 review: {@link #fieldApplies}), {@code reveal},
 * {@code top}, {@code timer}, {@code stop_timer} and {@code copy} (yw-android ui_host). Inputs: {@code press}, {@code edit}, {@code rendered}, {@code life}, {@code tick},
 * {@code timer} and {@code copied} (yw-engine wire::decode_input).
 *
 * <p>Platform-neutral: tested by the JVM runner; Rust's tests pin the same bytes.
 */
final class UiWire {
    /** The first byte of a UI frame (yw-android io_request::FRAME_UI). */
    static final int FRAME_UI = 0x02;

    /** The main timer's period (yw-engine screen::MAIN_TIMER_MS). */
    static final long TICK_MS = 250;

    /** The longest input Rust reads (yw-engine wire::INPUT_MAX). */
    static final int INPUT_MAX = 16_384;

    private UiWire() {}

    /** The frame of a {@code next} answer that is a UI frame, parsed; null for any other or an unreadable one. */
    static Object frame(byte[] bytes) {
        if (bytes == null || bytes.length < 2 || (bytes[0] & 0xff) != FRAME_UI) {
            return null;
        }
        Object frame = Json.parse(Arrays.copyOfRange(bytes, 1, bytes.length));
        return Json.string(frame, "t") == null ? null : frame;
    }

    /**
     * Whether a field frame applies to the model drawn now ({@code rev}) whose slot has had {@code sent} edits sent since
     * it was drawn: the frame must be of that model and Rust must have taken exactly those edits ({@code seen}); with
     * more sent since, the edit already shows a newer text than the frame's, which Rust takes after it (2026-11-25 A2-6
     * review).
     */
    static boolean fieldApplies(Object frame, long rev, long sent) {
        return Json.number(frame, "rev", -2) == rev && Json.number(frame, "seen", -1) == sent;
    }

    /** {@code {"t":"press","rev":R,"slot":S}}. */
    static byte[] press(long rev, long slot) {
        return utf8("{\"t\":\"press\",\"rev\":" + rev + ",\"slot\":" + slot + "}");
    }

    /** {@code {"t":"edit","rev":R,"slot":S,"text":"…"}}; null when it would be longer than Rust reads. */
    static byte[] edit(long rev, long slot, String text) {
        byte[] input = utf8("{\"t\":\"edit\",\"rev\":" + rev + ",\"slot\":" + slot + ",\"text\":" + Json.quote(text) + "}");
        return input.length <= INPUT_MAX ? input : null;
    }

    /**
     * {@code {"t":"rendered","rev":R,"focus":S,"of":P}}: model R is drawn; the plain edit that had the focus before was
     * slot S of model P. A negative focus or revision is none ({@code "focus":null,"of":null}).
     */
    static byte[] rendered(long rev, long focus, long of) {
        String named = focus < 0 || of < 0 ? "null,\"of\":null" : focus + ",\"of\":" + of;
        return utf8("{\"t\":\"rendered\",\"rev\":" + rev + ",\"focus\":" + named + "}");
    }

    /** {@code {"t":"life","e":"front"|"back"|"screen_off"}}. */
    static byte[] life(String event) {
        return utf8("{\"t\":\"life\",\"e\":" + Json.quote(event) + "}");
    }

    /** {@code {"t":"tick"}}. */
    static byte[] tick() {
        return utf8("{\"t\":\"tick\"}");
    }

    /** {@code {"t":"timer","id":"…"}}. */
    static byte[] timer(String id) {
        return utf8("{\"t\":\"timer\",\"id\":" + Json.quote(id) + "}");
    }

    /** {@code {"t":"copied","id":N,"ok":B}}. */
    static byte[] copied(long id, boolean ok) {
        return utf8("{\"t\":\"copied\",\"id\":" + id + ",\"ok\":" + ok + "}");
    }

    /** The QR modules of a {@code qr} item: row-major, most significant bit first; null when they do not fit. */
    static boolean[] qrModules(long size, String bits) {
        if (size <= 0 || size > 177 || bits == null || bits.length() != (size * size + 7) / 8 * 2) {
            return null;
        }
        for (int index = 0; index < bits.length(); index++) {
            if (Character.digit(bits.charAt(index), 16) < 0) {
                return null;
            }
        }
        int count = (int) (size * size);
        boolean[] dark = new boolean[count];
        for (int index = 0; index < count; index++) {
            int digit = Character.digit(bits.charAt(index / 4), 16);
            if (digit < 0) {
                return null;
            }
            dark[index] = ((digit >> (3 - index % 4)) & 1) == 1;
        }
        return dark;
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
