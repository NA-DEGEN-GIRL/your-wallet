package dev.yw.app;

import android.app.Activity;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * The main Activity (spec/15 §3.1). 2026-11-24 A2-3: it shows the one status line Rust answers (Wire), as the device
 * smoke of the skeleton; the screen model and its renderer replace it in A2-6. Java holds no fixed text (§3.3).
 *
 * <p>2026-11-25 A2-5: above the status line, the warning bands that cannot be closed (spec/15 §1.1, §17): on every
 * onStart the device facts are sent again (debugging can be switched while the app is in the background) and the
 * bands Rust answers are drawn, top first. Their texts come from Rust's catalogues; Java has only their colours.
 *
 * <p>2026-11-25 A2-6: below the bands, the screen Rust builds (spec/15 §11.3): each model frame is drawn by
 * {@link ScreenView} and answered with the rendered input; a press or a typed text goes back as an input naming the
 * model's revision and the control's slot (spec/15 §18 8). While the Activity is in front it sends the main timer's
 * tick every {@link UiWire#TICK_MS} (and, until the 2026-11-25 A2-7 review, the lifetime events front and back). The
 * status line is gone (the model replaces it).
 *
 * <p>2026-11-25 A2-7: a secret window (SecretActivity) is started from here (Screen.started); while it covers this
 * Activity, it sends the main timer's tick itself.
 *
 * <p>2026-11-25 A2-7 review: the lifetime events front and back are no longer this Activity's: {@link Screen} sends
 * them by the app's started-Activity count (spec/15 §5.4), so a secret window covering this one is not the app going to
 * the background (before, this onStop sent {@code life back} and each onStart {@code life front}).
 */
public final class MainActivity extends Activity {
    private final Handler main = new Handler(Looper.getMainLooper());
    private final Runnable tick = this::tick;
    private LinearLayout bands;
    private ScrollView scroll;
    private ScreenView screen;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        int padding = dp(16);
        // 2026-11-25 A2-6: from API 35 a target-36 app is drawn edge to edge, and the platform action bar and the status
        // bar covered the warning bands (seen on the API 35 emulator; the API 29 test device draws below them). The
        // bar goes (its only text is the app label; every screen has its own title) and the root keeps clear of the
        // system bars, so the bands are always the first thing in sight.
        if (getActionBar() != null) {
            getActionBar().hide();
        }
        // 2026-11-25 A2-8 (spec/15 §9.1 "API 33+ 모든 Activity", §5.4): no recents screenshot of the main screen either,
        // so the screen from before the app left is not shown in recents or while it returns (API 33+; below, the
        // platform keeps one, a residual).
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            setRecentsScreenshotEnabled(false);
        }
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setFitsSystemWindows(true);
        bands = new LinearLayout(this);
        bands.setOrientation(LinearLayout.VERTICAL);
        root.addView(bands);
        scroll = new ScrollView(this);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(padding, padding, padding, padding);
        scroll.addView(content);
        root.addView(scroll, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        screen = new ScreenView(this, content, new ScreenView.Sink() {
            @Override
            public void press(long rev, long slot) {
                Screen.send(UiWire.press(rev, slot));
            }

            @Override
            public boolean edit(long rev, long slot, String text) {
                byte[] input = UiWire.edit(rev, slot, text);
                Screen.send(input);
                return input != null;
            }
        });
        setContentView(root);
    }

    @Override
    protected void onStart() {
        super.onStart();
        drawBands(App.loaded() ? Wire.bands(Native.call(DeviceFacts.input(this))) : null);
        Screen.started(this);
        Screen.attach(this);
        main.postDelayed(tick, UiWire.TICK_MS);
    }

    @Override
    protected void onStop() {
        main.removeCallbacks(tick);
        Screen.detach(this);
        Screen.stopped(this);
        super.onStop();
    }

    private void tick() {
        Screen.send(UiWire.tick());
        main.postDelayed(tick, UiWire.TICK_MS);
    }

    /** Draws a model frame and answers it (the focused plain edit of the screen shown before). */
    void drawModel(Object model) {
        long before = screen.rev();
        long focus = screen.draw(model);
        Screen.send(UiWire.rendered(screen.rev(), focus, before));
    }

    /**
     * Shows or hides the screen's content (2026-11-25 A2-8, spec/15 §5.4, {@link FrontGate}): hidden from the moment the
     * app goes to the background until Rust has checked the time away on the way back; the warning bands stay.
     */
    void setScreenShown(boolean on) {
        scroll.setVisibility(on ? android.view.View.VISIBLE : android.view.View.INVISIBLE);
    }

    /** A field, reveal or top frame. */
    void applyFrame(Object frame) {
        screen.apply(frame, scroll);
    }

    private void drawBands(String[] texts) {
        bands.removeAllViews();
        int padding = dp(12);
        if (texts == null) {
            // No answer Java can draw (2026-11-25 A2-5 review): the screen is never shown as if there were no warning.
            // Java holds no text, so an empty band in the warning colours stands for the missing ones; before, no band
            // was drawn at all, not even the test-build band.
            TextView band = new TextView(this);
            band.setBackgroundColor(getColor(R.color.band_background));
            band.setMinHeight(dp(48));
            band.setPadding(padding, padding, padding, padding);
            bands.addView(band);
            return;
        }
        for (String text : texts) {
            TextView band = new TextView(this);
            band.setText(text);
            band.setTextColor(getColor(R.color.band_text));
            band.setBackgroundColor(getColor(R.color.band_background));
            band.setPadding(padding, padding, padding, padding);
            bands.addView(band);
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
