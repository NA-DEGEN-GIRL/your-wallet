package dev.yw.app;

import android.app.Activity;
import android.os.Bundle;
import android.widget.LinearLayout;
import android.widget.TextView;

/**
 * The main Activity (spec/15 §3.1). 2026-11-24 A2-3: it shows the one status line Rust answers (Wire), as the device
 * smoke of the skeleton; the screen model and its renderer replace it in A2-6. Java holds no fixed text (§3.3).
 *
 * <p>2026-11-25 A2-5: above the status line, the warning bands that cannot be closed (spec/15 §1.1, §17): on every
 * onStart the device facts are sent again (debugging can be switched while the app is in the background) and the
 * bands Rust answers are drawn, top first. Their texts come from Rust's catalogues; Java has only their colours.
 */
public final class MainActivity extends Activity {
    private LinearLayout bands;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String status = App.loaded() ? Wire.statusLine(Native.call(Wire.statusRequest())) : null;
        int padding = dp(16);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        bands = new LinearLayout(this);
        bands.setOrientation(LinearLayout.VERTICAL);
        root.addView(bands);
        TextView line = new TextView(this);
        line.setText(status == null ? "" : status);
        line.setPadding(padding, padding, padding, padding);
        root.addView(line);
        setContentView(root);
    }

    @Override
    protected void onStart() {
        super.onStart();
        String[] texts = App.loaded() ? Wire.bands(Native.call(DeviceFacts.input(this))) : null;
        bands.removeAllViews();
        if (texts == null) {
            return;
        }
        int padding = dp(12);
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
