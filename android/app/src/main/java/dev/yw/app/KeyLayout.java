package dev.yw.app;

/**
 * The app keyboard's fixed layout (spec/15 §9.2; 2026-11-25 A2-7): every secret field is typed here, never through
 * the system keyboard. The layout is fixed (not shuffled), and every key sends exactly one UTF-16 unit through
 * {@link Native#secretKey}, which Rust (yw-android secret_keys) hands to the engine's form: 0x08 Backspace, 0x0D
 * Enter, 0x20-0x7E a character. The layer keys only change the layer here; they send nothing.
 *
 * <p>Modes (the window model's {@code keys}): {@code text} (passwords, passphrases, keys: four layers that together
 * hold every printable ASCII character), {@code words} (W05: a-z and space), {@code letters} (W10: a-z), {@code none}.
 *
 * <p>Labels are the characters themselves or symbols (no word to translate, spec/15 §3.3). Platform-neutral: the
 * JVM runner checks the layout (JvmTests.keyLayout).
 */
final class KeyLayout {
    /** Shift: lower ↔ upper letters; in the symbol layers, the second symbol layer and back. */
    static final int SHIFT = -1;

    /** To the symbol layer. */
    static final int SYMBOLS = -2;

    /** Back to the letters. */
    static final int LETTERS = -3;

    static final int BACKSPACE = 0x08;
    static final int ENTER = 0x0D;
    static final int SPACE = 0x20;

    /** The layers of the text mode. */
    static final int LOWER = 0;
    static final int UPPER = 1;
    static final int SYMBOL = 2;
    static final int MORE = 3;

    private KeyLayout() {}

    private static int[] chars(String text) {
        int[] codes = new int[text.length()];
        for (int at = 0; at < text.length(); at++) {
            codes[at] = text.charAt(at);
        }
        return codes;
    }

    private static int[] with(int first, String middle, int last) {
        int[] inner = chars(middle);
        int[] codes = new int[inner.length + 2];
        codes[0] = first;
        System.arraycopy(inner, 0, codes, 1, inner.length);
        codes[codes.length - 1] = last;
        return codes;
    }

    /** The rows of {@code mode} in {@code layer} (a fresh array), top first; an empty array for none. */
    static int[][] rows(String mode, int layer) {
        if ("words".equals(mode)) {
            return new int[][] {
                chars("qwertyuiop"), chars("asdfghjkl"), with(SPACE, "zxcvbnm", BACKSPACE), new int[] {ENTER}
            };
        }
        if ("letters".equals(mode)) {
            return new int[][] {chars("qwertyuiop"), chars("asdfghjkl"), with(BACKSPACE, "zxcvbnm", ENTER)};
        }
        if (!"text".equals(mode)) {
            return new int[0][];
        }
        switch (layer) {
            case UPPER:
                return new int[][] {
                    chars("QWERTYUIOP"),
                    chars("ASDFGHJKL"),
                    with(SHIFT, "ZXCVBNM", BACKSPACE),
                    new int[] {SYMBOLS, SPACE, ENTER}
                };
            case SYMBOL:
                return new int[][] {
                    chars("1234567890"),
                    chars("@#$%&-+()/"),
                    with(SHIFT, "*\"':;!?", BACKSPACE),
                    new int[] {LETTERS, ',', SPACE, '.', ENTER}
                };
            case MORE:
                return new int[][] {
                    chars("1234567890"),
                    chars("[]{}<>^_="),
                    with(SHIFT, "\\|~`", BACKSPACE),
                    new int[] {LETTERS, ',', SPACE, '.', ENTER}
                };
            default:
                return new int[][] {
                    chars("qwertyuiop"),
                    chars("asdfghjkl"),
                    with(SHIFT, "zxcvbnm", BACKSPACE),
                    new int[] {SYMBOLS, SPACE, ENTER}
                };
        }
    }

    /** The layer after pressing {@code code} in {@code layer} (a character key keeps the layer). */
    static int next(int layer, int code) {
        switch (code) {
            case SHIFT:
                if (layer == LOWER) {
                    return UPPER;
                }
                if (layer == UPPER) {
                    return LOWER;
                }
                return layer == SYMBOL ? MORE : SYMBOL;
            case SYMBOLS:
                return SYMBOL;
            case LETTERS:
                return LOWER;
            default:
                return layer;
        }
    }

    /** Whether {@code code} is sent to Rust (a unit), not a layer key. */
    static boolean sends(int code) {
        return code >= 0;
    }

    /** The label drawn on a key: the character, or a symbol for the special keys. */
    static String label(int code, int layer) {
        switch (code) {
            case SHIFT:
                return layer == SYMBOL ? "#+=" : layer == MORE ? "123" : "⇧";
            case SYMBOLS:
                return "123";
            case LETTERS:
                return "abc";
            case BACKSPACE:
                return "⌫";
            case ENTER:
                return "⏎";
            case SPACE:
                return "␣";
            default:
                return String.valueOf((char) code);
        }
    }

    /** How many key widths a key takes (space is wide). */
    static int span(int code) {
        return code == SPACE ? 4 : 1;
    }
}
