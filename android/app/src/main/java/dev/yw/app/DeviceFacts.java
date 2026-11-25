package dev.yw.app;

import android.content.Context;
import android.os.Build;
import android.provider.Settings;

/**
 * The device facts behind the protection tier and the warning bands (spec/15 §1.1, §8.2; 2026-11-25 A2-5): the API
 * level, the security patch date and whether USB or wireless debugging is on. Java only reads them; Rust decides the
 * tier and the bands (yw-engine protection) and answers the bands' texts. adb_enabled and adb_wifi_enabled change
 * while the app runs, so the facts are read and sent again each time a screen that shows bands comes up.
 *
 * <p>A setting that cannot be read counts as on: the debugging band then shows (fail toward the warning).
 * adb_wifi_enabled exists from API 30; on API 29 a missing one reads as off.
 *
 * <p>2026-11-25 A2-5 review: the raw string is read (Settings.Global.getString) and judged by Wire.settingOn, so a
 * missing value, a non-integer one and a failed provider (null) all read as on. Before, getInt(…, 0) read all three as
 * off, and the catch below was nearly dead.
 */
final class DeviceFacts {
    /** The first API level with adb_wifi_enabled (Android 11). */
    private static final int ADB_WIFI_SINCE = 30;

    private DeviceFacts() {}

    /** The facts input for Native.call (Wire.facts). */
    static byte[] input(Context context) {
        int sdk = Build.VERSION.SDK_INT;
        return Wire.facts(
                sdk,
                Build.VERSION.SECURITY_PATCH,
                setting(context, Settings.Global.ADB_ENABLED, false),
                setting(context, "adb_wifi_enabled", sdk < ADB_WIFI_SINCE));
    }

    /**
     * The facts members read now, for a secret window's ready input (2026-11-25 A2-7, spec/15 §8.2: each secret
     * window reads them again when it opens, so a stale value never hides the debugging band).
     */
    static String members(Context context) {
        int sdk = Build.VERSION.SDK_INT;
        return Wire.factsMembers(
                sdk,
                Build.VERSION.SECURITY_PATCH,
                setting(context, Settings.Global.ADB_ENABLED, false),
                setting(context, "adb_wifi_enabled", sdk < ADB_WIFI_SINCE));
    }

    private static boolean setting(Context context, String name, boolean absentMeansOff) {
        try {
            return Wire.settingOn(Settings.Global.getString(context.getContentResolver(), name), absentMeansOff);
        } catch (RuntimeException unreadable) {
            return true;
        }
    }
}
