package dev.yw.app;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

/**
 * The main Activity (spec/15 §3.1). 2026-11-24 A2-3: it shows the one status line Rust answers (Wire), as the device
 * smoke of the skeleton; the screen model and its renderer replace it in A2-6. Java holds no fixed text (§3.3).
 */
public final class MainActivity extends Activity {
    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        String status = App.loaded() ? Wire.statusLine(Native.call(Wire.statusRequest())) : null;
        TextView line = new TextView(this);
        line.setText(status == null ? "" : status);
        int padding = Math.round(16 * getResources().getDisplayMetrics().density);
        line.setPadding(padding, padding, padding, padding);
        setContentView(line);
    }
}
