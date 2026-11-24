package dev.yw.app;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A strict JSON reader for the UI frames Rust writes (spec/15 §3.2; 2026-11-25 A2-6). No library: the app has no
 * runtime dependency (§4.2) and android.jar's org.json does not run in the JVM tests (§18 42 N15). It reads RFC 8259
 * JSON from strict UTF-8 with a depth bound, objects with unique keys, and integer numbers only (the frames carry no
 * other kind); anything else is null, so a frame Java cannot read is not drawn.
 *
 * <p>Values: {@code Map<String, Object>} (insertion order), {@code List<Object>}, {@code String}, {@code Long},
 * {@code Boolean} and {@link #NULL}.
 *
 * <p>Platform-neutral: tested by the JVM runner.
 */
final class Json {
    /** JSON null (a map cannot hold Java null as a value here). */
    static final Object NULL = new Object();

    /** The deepest nesting read. */
    static final int MAX_DEPTH = 32;

    private final String text;
    private int at;

    private Json(String text) {
        this.text = text;
    }

    /** The value of {@code bytes}, or null when they are not exactly one strict JSON value. */
    static Object parse(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        String text;
        try {
            text = StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes))
                    .toString();
        } catch (CharacterCodingException bad) {
            return null;
        }
        Json reader = new Json(text);
        try {
            reader.space();
            Object value = reader.value(0);
            reader.space();
            return reader.at == text.length() ? value : null;
        } catch (IllegalArgumentException bad) {
            return null;
        }
    }

    private static IllegalArgumentException bad() {
        return new IllegalArgumentException("json");
    }

    private void space() {
        while (at < text.length()) {
            char unit = text.charAt(at);
            if (unit != ' ' && unit != '\t' && unit != '\n' && unit != '\r') {
                return;
            }
            at++;
        }
    }

    private char peek() {
        if (at >= text.length()) {
            throw bad();
        }
        return text.charAt(at);
    }

    private void expect(String word) {
        if (!text.startsWith(word, at)) {
            throw bad();
        }
        at += word.length();
    }

    private Object value(int depth) {
        char unit = peek();
        switch (unit) {
            case '{':
                return object(depth + 1);
            case '[':
                return array(depth + 1);
            case '"':
                return string();
            case 't':
                expect("true");
                return Boolean.TRUE;
            case 'f':
                expect("false");
                return Boolean.FALSE;
            case 'n':
                expect("null");
                return NULL;
            default:
                return number();
        }
    }

    private Map<String, Object> object(int depth) {
        if (depth > MAX_DEPTH) {
            throw bad();
        }
        at++;
        Map<String, Object> members = new LinkedHashMap<>();
        space();
        if (peek() == '}') {
            at++;
            return Collections.unmodifiableMap(members);
        }
        while (true) {
            space();
            if (peek() != '"') {
                throw bad();
            }
            String key = string();
            space();
            expect(":");
            space();
            Object value = value(depth);
            if (members.put(key, value) != null) {
                throw bad();
            }
            space();
            char next = peek();
            at++;
            if (next == '}') {
                return Collections.unmodifiableMap(members);
            }
            if (next != ',') {
                throw bad();
            }
        }
    }

    private List<Object> array(int depth) {
        if (depth > MAX_DEPTH) {
            throw bad();
        }
        at++;
        List<Object> items = new ArrayList<>();
        space();
        if (peek() == ']') {
            at++;
            return Collections.unmodifiableList(items);
        }
        while (true) {
            space();
            items.add(value(depth));
            space();
            char next = peek();
            at++;
            if (next == ']') {
                return Collections.unmodifiableList(items);
            }
            if (next != ',') {
                throw bad();
            }
        }
    }

    private String string() {
        at++;
        StringBuilder out = new StringBuilder();
        while (true) {
            char unit = peek();
            at++;
            if (unit == '"') {
                return out.toString();
            }
            if (unit < 0x20) {
                throw bad();
            }
            if (unit != '\\') {
                out.append(unit);
                continue;
            }
            char escape = peek();
            at++;
            switch (escape) {
                case '"':
                case '\\':
                case '/':
                    out.append(escape);
                    break;
                case 'b':
                    out.append('\b');
                    break;
                case 'f':
                    out.append('\f');
                    break;
                case 'n':
                    out.append('\n');
                    break;
                case 'r':
                    out.append('\r');
                    break;
                case 't':
                    out.append('\t');
                    break;
                case 'u':
                    if (at + 4 > text.length()) {
                        throw bad();
                    }
                    int code = 0;
                    for (int digit = 0; digit < 4; digit++) {
                        int value = Character.digit(text.charAt(at + digit), 16);
                        if (value < 0) {
                            throw bad();
                        }
                        code = code * 16 + value;
                    }
                    at += 4;
                    out.append((char) code);
                    break;
                default:
                    throw bad();
            }
        }
    }

    private Long number() {
        int start = at;
        if (peek() == '-') {
            at++;
        }
        char first = peek();
        if (first < '0' || first > '9') {
            throw bad();
        }
        at++;
        if (first != '0') {
            while (at < text.length() && text.charAt(at) >= '0' && text.charAt(at) <= '9') {
                at++;
            }
        }
        if (at < text.length() && (text.charAt(at) == '.' || text.charAt(at) == 'e' || text.charAt(at) == 'E')) {
            throw bad();
        }
        try {
            return Long.parseLong(text.substring(start, at));
        } catch (NumberFormatException tooLarge) {
            throw bad();
        }
    }

    /** The member {@code key} of {@code value} when it is a map, else null. */
    static Object get(Object value, String key) {
        if (value instanceof Map) {
            return ((Map<?, ?>) value).get(key);
        }
        return null;
    }

    /** The string member {@code key}, or null. */
    static String string(Object value, String key) {
        Object member = get(value, key);
        return member instanceof String ? (String) member : null;
    }

    /** The integer member {@code key}, or {@code fallback}. */
    static long number(Object value, String key, long fallback) {
        Object member = get(value, key);
        return member instanceof Long ? (Long) member : fallback;
    }

    /** The boolean member {@code key}, or null (absent or JSON null). */
    static Boolean bool(Object value, String key) {
        Object member = get(value, key);
        return member instanceof Boolean ? (Boolean) member : null;
    }

    /** The array member {@code key}, or an empty list. */
    static List<?> list(Object value, String key) {
        Object member = get(value, key);
        return member instanceof List ? (List<?>) member : Collections.emptyList();
    }

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    /** A JSON string literal of {@code text} (the escapes Rust's yw-json reads). */
    static String quote(String text) {
        StringBuilder out = new StringBuilder(text.length() + 2);
        out.append('"');
        for (int index = 0; index < text.length(); index++) {
            char unit = text.charAt(index);
            if (unit == '"' || unit == '\\') {
                out.append('\\').append(unit);
            } else if (unit < 0x20) {
                out.append("\\u00").append(HEX[unit >> 4]).append(HEX[unit & 0xf]);
            } else {
                out.append(unit);
            }
        }
        return out.append('"').toString();
    }
}
