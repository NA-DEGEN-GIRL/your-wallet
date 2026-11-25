package dev.yw.app;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.view.HapticFeedbackConstants;
import android.view.MotionEvent;
import android.view.SoundEffectConstants;
import android.view.View;
import android.view.ViewStructure;

/**
 * The app keyboard (spec/15 §9.2; 2026-11-25 A2-7): the fixed layout of {@link KeyLayout}, drawn and hit-tested here
 * with no key preview, no popup and no window of its own. A key released where it was pressed sends its one unit to
 * the sink (which calls {@link Native#secretKey}); a layer key only changes the layer. Nothing typed is kept here.
 * Sound and vibration follow the system settings (the view's own feedback calls, which the platform gates).
 */
final class KeyPad extends View {
    /** Where a key's unit goes. */
    interface Sink {
        void key(int unit);
    }

    private static final int KEY = 0xffeaeef2;
    private static final int KEY_DOWN = 0xffd0d7de;
    private static final int SPECIAL = 0xffd8dee4;
    private static final int LABEL = 0xff1f2328;
    private static final int OFF = 0xff8c959f;

    private final Sink sink;
    private final Paint keyPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint labelPaint = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final float density;
    private String mode = "none";
    private int layer = KeyLayout.LOWER;
    private boolean enabled;
    private int[][] rows = new int[0][];
    private int downRow = -1;
    private int downCol = -1;

    KeyPad(Context context, Sink sink) {
        super(context);
        this.sink = sink;
        density = context.getResources().getDisplayMetrics().density;
        labelPaint.setTextSize(20 * density);
        labelPaint.setTextAlign(Paint.Align.CENTER);
        setSaveEnabled(false);
        setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        setSoundEffectsEnabled(true);
        setHapticFeedbackEnabled(true);
    }

    /** The window model's keyboard and whether its input is on. */
    void set(String keys, boolean enabled) {
        String next = keys == null ? "none" : keys;
        if (!next.equals(mode)) {
            mode = next;
            layer = KeyLayout.LOWER;
        }
        this.enabled = enabled;
        rows = KeyLayout.rows(mode, layer);
        setVisibility(rows.length == 0 ? View.GONE : View.VISIBLE);
        requestLayout();
        invalidate();
    }

    private float keyHeight() {
        return 52 * density;
    }

    @Override
    protected void onMeasure(int widthSpec, int heightSpec) {
        int width = MeasureSpec.getSize(widthSpec);
        setMeasuredDimension(width, Math.round(rows.length * keyHeight() + 8 * density));
    }

    private static int rowSpan(int[] row) {
        int span = 0;
        for (int code : row) {
            span += KeyLayout.span(code);
        }
        return span;
    }

    /** The bounds of key {@code col} of row {@code row}. */
    private RectF bounds(int row, int col) {
        int[] keys = rows[row];
        float unit = getWidth() / (float) Math.max(10, rowSpan(keys));
        float x = (getWidth() - unit * rowSpan(keys)) / 2;
        for (int at = 0; at < col; at++) {
            x += unit * KeyLayout.span(keys[at]);
        }
        float top = 4 * density + row * keyHeight();
        float gap = 3 * density;
        return new RectF(x + gap, top + gap, x + unit * KeyLayout.span(keys[col]) - gap, top + keyHeight() - gap);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        for (int row = 0; row < rows.length; row++) {
            for (int col = 0; col < rows[row].length; col++) {
                int code = rows[row][col];
                RectF key = bounds(row, col);
                boolean down = row == downRow && col == downCol;
                keyPaint.setColor(down ? KEY_DOWN : KeyLayout.sends(code) && code > 0x20 ? KEY : SPECIAL);
                canvas.drawRoundRect(key, 6 * density, 6 * density, keyPaint);
                labelPaint.setColor(enabled || !KeyLayout.sends(code) ? LABEL : OFF);
                float y = key.centerY() - (labelPaint.ascent() + labelPaint.descent()) / 2;
                canvas.drawText(KeyLayout.label(code, layer), key.centerX(), y, labelPaint);
            }
        }
    }

    /** The key under (x, y) as {row, col}, or null. */
    private int[] keyAt(float x, float y) {
        for (int row = 0; row < rows.length; row++) {
            for (int col = 0; col < rows[row].length; col++) {
                if (bounds(row, col).contains(x, y)) {
                    return new int[] {row, col};
                }
            }
        }
        return null;
    }

    @Override
    public boolean onTouchEvent(MotionEvent event) {
        int[] key = keyAt(event.getX(), event.getY());
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                downRow = key == null ? -1 : key[0];
                downCol = key == null ? -1 : key[1];
                invalidate();
                return true;
            case MotionEvent.ACTION_UP:
                if (key != null && key[0] == downRow && key[1] == downCol) {
                    press(rows[downRow][downCol]);
                }
                downRow = -1;
                downCol = -1;
                invalidate();
                return true;
            case MotionEvent.ACTION_CANCEL:
                downRow = -1;
                downCol = -1;
                invalidate();
                return true;
            default:
                return true;
        }
    }

    private void press(int code) {
        performHapticFeedback(HapticFeedbackConstants.KEYBOARD_TAP);
        playSoundEffect(SoundEffectConstants.CLICK);
        if (!KeyLayout.sends(code)) {
            layer = KeyLayout.next(layer, code);
            rows = KeyLayout.rows(mode, layer);
            invalidate();
            return;
        }
        if (enabled) {
            sink.key(code);
        }
    }

    // The keys are not secret, but the keyboard gives no structure to autofill or content capture either.
    @Override
    public void onProvideStructure(ViewStructure structure) {}

    @Override
    public void onProvideAutofillStructure(ViewStructure structure, int flags) {}

    @Override
    public void onProvideContentCaptureStructure(ViewStructure structure, int flags) {}
}
