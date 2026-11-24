package dev.yw.app;

import android.content.res.ColorStateList;
import android.widget.Button;

/**
 * The colours of the screen model's tones, button styles and badge marks on Android (2026-11-25 A2-6). Colours and
 * symbols only: the words come from Rust (spec/15 §3.3, spec/14).
 */
final class Tones {
    private Tones() {}

    /** The text colour of a band or tag of {@code tone}. */
    static int ink(String tone) {
        if (tone == null) {
            return 0xff1f2328;
        }
        switch (tone) {
            case "danger":
            case "high_risk":
            case "blocked":
                return 0xff82071e;
            case "warn":
                return 0xff7d4e00;
            case "success":
                return 0xff1a7f37;
            case "btc_mainnet":
                return 0xff7d4e00;
            case "testnet":
            case "btc_testnet4":
                return 0xff6639ba;
            default:
                return 0xff0550ae;
        }
    }

    /** The background of a band or tag of {@code tone}. */
    static int background(String tone) {
        if (tone == null) {
            return 0xffddf4ff;
        }
        switch (tone) {
            case "danger":
            case "high_risk":
            case "blocked":
                return 0xffffebe9;
            case "warn":
            case "btc_mainnet":
                return 0xfffff8c5;
            case "success":
                return 0xffdafbe1;
            case "testnet":
            case "btc_testnet4":
                return 0xfffbefff;
            default:
                return 0xffddf4ff;
        }
    }

    /** A button of {@code style} (null: secondary). */
    static void styleButton(Button button, String style) {
        int background;
        int text;
        if ("primary".equals(style) || "tab_on".equals(style) || "entry_on".equals(style)) {
            background = 0xff1f6feb;
            text = 0xffffffff;
        } else if ("danger".equals(style)) {
            background = 0xffcf222e;
            text = 0xffffffff;
        } else {
            background = 0xffeaeef2;
            text = 0xff1f2328;
        }
        button.setBackgroundTintList(ColorStateList.valueOf(background));
        button.setTextColor(text);
    }

    /** The symbol of a badge mark (no letters: the letter mark carries its own). */
    static String markGlyph(String mark) {
        if (mark == null) {
            return "";
        }
        switch (mark) {
            case "diamond":
                return "◆";
            case "hexagon":
                return "⬢";
            case "ring":
                return "○";
            case "hollow_diamond":
                return "◇";
            case "bars":
                return "≡";
            case "bitcoin":
                return "₿";
            default:
                return "";
        }
    }
}
