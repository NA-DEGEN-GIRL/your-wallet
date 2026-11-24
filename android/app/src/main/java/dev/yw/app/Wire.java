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
 * <p>2026-11-25 A2-4b: and the start input ({@link #start(String)}), the data folder's parent.
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

    /** The longest start input (yw-android interim::START_MAX). */
    static final int START_MAX = 1024;

    /**
     * The start input {"t":"start","dir":"<dir>"} (2026-11-25 A2-4b): dir is Context.getNoBackupFilesDir(), under
     * which Rust keeps the data folder v3 (§5.1). Null unless dir is an absolute path of printable ASCII without a
     * space, quote or backslash and without "." or ".." components, and the input fits START_MAX (the same rules as
     * yw-android interim::start_dir); then Java does not start the wallet (fail closed).
     */
    static byte[] start(String dir) {
        if (dir == null || !dir.startsWith("/")) {
            return null;
        }
        for (int at = 0; at < dir.length(); at++) {
            char unit = dir.charAt(at);
            if (unit < 0x21 || unit > 0x7e || unit == '"' || unit == '\\') {
                return null;
            }
        }
        for (String part : dir.split("/", -1)) {
            if (part.equals(".") || part.equals("..")) {
                return null;
            }
        }
        byte[] input = ("{\"t\":\"start\",\"dir\":\"" + dir + "\"}").getBytes(StandardCharsets.US_ASCII);
        return input.length <= START_MAX ? input : null;
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
