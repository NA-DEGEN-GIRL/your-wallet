package dev.yw.app;

/**
 * Whether the main screen may be seen (spec/15 §5.4 "그리기 전에 먼저 경과를 검사"; 2026-11-25 A2-8): from the moment the
 * app goes to the background ({@code life back}) the main screen's content is hidden, and it is shown again only when
 * Rust's {@code {"t":"shown","n":N}} names the {@code front} Java sent last: Rust handles {@code front} by checking the
 * time away first, locking when it is due, then drawing, so everything drawn before that frame is already the checked
 * state. A {@code shown} of an older {@code front} (a resync's) does not show it. Free of android.* so that the JVM
 * runner tests it.
 */
final class FrontGate {
    private long fronts;
    private boolean hidden;
    /** Between a back and the next front: no shown counts (one of an earlier front, a resync's). */
    private boolean away;

    /** The app went to the background: hidden until the {@code shown} of the next {@code front}. */
    void back() {
        hidden = true;
        away = true;
    }

    /** The first Activity started again: the number of this {@code front} (Rust counts the same ones). */
    long front() {
        fronts++;
        away = false;
        return fronts;
    }

    /** Rust's {@code shown} of {@code front} number {@code n}: whether the screen may be seen now. */
    boolean shown(long n) {
        if (!away && n == fronts) {
            hidden = false;
        }
        return !hidden;
    }

    /** Whether the screen is hidden now. */
    boolean hidden() {
        return hidden;
    }
}
