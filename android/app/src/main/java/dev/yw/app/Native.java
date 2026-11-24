package dev.yw.app;

/**
 * The five native methods of libyw.so (spec/15 §3.2). JNI_OnLoad registers them on this class by name with
 * RegisterNatives; there is no Java_* symbol. Rust never calls Java: everything it has for Java comes back from these
 * calls (next for effects, the screen model and platform I/O requests; ioComplete carries the answers).
 *
 * <p>2026-11-24 A2-3: call knows only the two interim inputs of {@link Wire}; the other four are stubs that answer
 * nothing until A2-6 (the wire format) and A2-7 (the secret windows).
 */
final class Native {
    private Native() {}

    /** An input for the engine; its answer, or null. */
    static native byte[] call(byte[] input);

    /** The next effect, screen model or platform I/O request, waiting up to timeoutMs; null if none. */
    static native byte[] next(long timeoutMs);

    /** The result of a platform I/O request. */
    static native void ioComplete(long id, int status, byte[] body);

    /** One key of the app keyboard on a secret field (spec/15 §9.2). */
    static native void secretKey(int field, int codeUnit);

    /** Writes the secret text of a display handle into out; the number of chars written, 0 for an unknown handle. */
    static native int secretFill(long handle, char[] out);
}
