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
 * <p>2026-11-25 A2-5: and the facts input ({@link #facts}), whose answer is the main screen's warning bands
 * ({@link #bands}); the uncaught-exception event now also leaves one log line (Rust's app.java_uncaught).
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

    /** The largest sdk value Rust accepts (yw-android interim::SDK_MAX). */
    static final int SDK_MAX = 1000;

    /** The longest bands answer Java accepts (yw-android interim::BANDS_MAX). */
    static final int BANDS_MAX = 1024;

    /**
     * The facts input {"t":"facts","sdk":N,"patch":"YYYY-MM-DD","adb":B,"adbw":B} (2026-11-25 A2-5, spec/15 §1.1,
     * §8.2): the API level, the security patch date and whether USB or wireless debugging is on. A patch that is not
     * exactly four digits, '-', two digits, '-', two digits is sent as "" (Rust reads an unknown patch as old, so the
     * weak-protection band shows); an sdk outside 0..SDK_MAX is sent as 0 (the lowest tier). The same rules as
     * yw-android interim::facts.
     */
    static byte[] facts(int sdk, String patch, boolean adb, boolean adbWifi) {
        return ("{\"t\":\"facts\"," + factsMembers(sdk, patch, adb, adbWifi) + "}").getBytes(StandardCharsets.US_ASCII);
    }

    /**
     * The four facts members {@code "sdk":N,"patch":"…","adb":B,"adbw":B} by the rules of {@link #facts}
     * (2026-11-25 A2-7: also the secret window's ready input, SecretWire.ready, which carries the facts read for that
     * open, spec/15 §8.2).
     */
    static String factsMembers(int sdk, String patch, boolean adb, boolean adbWifi) {
        int level = sdk < 0 || sdk > SDK_MAX ? 0 : sdk;
        String date = isDate(patch) ? patch : "";
        return "\"sdk\":" + level + ",\"patch\":\"" + date + "\",\"adb\":" + adb + ",\"adbw\":" + adbWifi;
    }

    /**
     * Whether a Settings.Global switch reads as on, from its raw string (2026-11-25 A2-5 review, spec/15 §8.2): an
     * integer other than 0 is on and 0 is off; anything else (an empty or non-integer value) is on, and so is a missing
     * one (null) unless absentMeansOff (adb_wifi_enabled before API 30, which has no such setting). Before, the value
     * was read with Settings.Global.getInt(…, 0), which reads a missing or malformed value as off.
     */
    static boolean settingOn(String raw, boolean absentMeansOff) {
        if (raw == null) {
            return !absentMeansOff;
        }
        try {
            return Integer.parseInt(raw) != 0;
        } catch (NumberFormatException malformed) {
            return true;
        }
    }

    private static boolean isDate(String text) {
        if (text == null || text.length() != 10) {
            return false;
        }
        for (int at = 0; at < 10; at++) {
            char unit = text.charAt(at);
            boolean dash = at == 4 || at == 7;
            if (dash ? unit != '-' : unit < '0' || unit > '9') {
                return false;
            }
        }
        return true;
    }

    /**
     * The band texts of Rust's answer to the facts input, top first (2026-11-25 A2-5): strict UTF-8, at most BANDS_MAX
     * bytes, lines split at '\n', no other control character and no empty line. Anything else is not drawn as text
     * Rust wrote: an empty array for an empty answer, null for a bad one (the caller then draws no band text, only an
     * empty band in the warning colours, 2026-11-25 A2-5 review).
     */
    static String[] bands(byte[] answer) {
        if (answer == null || answer.length > BANDS_MAX) {
            return null;
        }
        if (answer.length == 0) {
            return new String[0];
        }
        String text;
        try {
            text = StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
                    .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
                    .decode(java.nio.ByteBuffer.wrap(answer))
                    .toString();
        } catch (java.nio.charset.CharacterCodingException bad) {
            return null;
        }
        String[] lines = text.split("\n", -1);
        for (String line : lines) {
            if (line.isEmpty()) {
                return null;
            }
            for (int at = 0; at < line.length(); at++) {
                char unit = line.charAt(at);
                if (unit < 0x20 || unit == 0x7f) {
                    return null;
                }
            }
        }
        return lines;
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
