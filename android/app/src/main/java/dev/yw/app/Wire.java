package dev.yw.app;

import java.nio.charset.StandardCharsets;

/**
 * The two inputs Java sends through {@link Native#call} before the wire format of A2-6 exists (spec/15 §3.2,
 * 2026-11-24 A2-3). Rust matches them byte for byte (yw-android interim; its unit tests pin the same bytes):
 *
 * <ul>
 *   <li>{@link #statusRequest()}: the answer is one status line (the library version and ABI, printable ASCII, no
 *       words to translate), which MainActivity shows so that a device smoke sees a Rust answer drawn;
 *   <li>{@link #javaUncaught()}: the fixed event of the uncaught-exception handler (§3.3); Rust wipes every slot and
 *       ends the process with _exit, so the call does not return.
 * </ul>
 *
 * <p>Platform-neutral: tested by the JVM runner (§18 42 N15).
 */
final class Wire {
    /** The longest status line Java accepts. */
    static final int STATUS_MAX = 64;

    private Wire() {}

    /** A fresh copy each time, so no caller can change what another one sends. */
    static byte[] statusRequest() {
        return "{\"t\":\"status\"}".getBytes(StandardCharsets.US_ASCII);
    }

    /** A fresh copy each time. */
    static byte[] javaUncaught() {
        return "{\"t\":\"java_uncaught\"}".getBytes(StandardCharsets.US_ASCII);
    }

    /** The status line in Rust's answer, or null unless it is 1 to STATUS_MAX printable ASCII bytes. */
    static String statusLine(byte[] answer) {
        if (answer == null || answer.length == 0 || answer.length > STATUS_MAX) {
            return null;
        }
        for (byte unit : answer) {
            if (unit < 0x20 || unit > 0x7e) {
                return null;
            }
        }
        return new String(answer, StandardCharsets.US_ASCII);
    }
}
