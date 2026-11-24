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
 * adb_wifi_enabled exists from API 30; on API 29 it reads as its default, off.
 */
final class DeviceFacts {
    private DeviceFacts() {}

    /** The facts input for Native.call (Wire.facts). */
    static byte[] input(Context context) {
        return Wire.facts(
                Build.VERSION.SDK_INT,
                Build.VERSION.SECURITY_PATCH,
                setting(context, Settings.Global.ADB_ENABLED),
                setting(context, "adb_wifi_enabled"));
    }

    private static boolean setting(Context context, String name) {
        try {
            return Settings.Global.getInt(context.getContentResolver(), name, 0) != 0;
        } catch (RuntimeException unreadable) {
            return true;
        }
    }
}
