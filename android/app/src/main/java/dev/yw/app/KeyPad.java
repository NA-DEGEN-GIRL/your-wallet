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
 *
 * <p>2026-11-26 A2 final review: every finger is followed by its pointer id ({@link KeyTracker}; before, only the first
 * one, so two-thumb typing lost keys), and the rows get lower when the window is low ({@link #room},
 * {@link KeyLayout#keyHeight}), so that the warning bands above the content always stay.
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
    private final KeyTracker fingers = new KeyTracker();
    /** The height the window has for the content and this keyboard together (bands and completions taken off). */
    private int room = Integer.MAX_VALUE;
    private float keyHeight;

    KeyPad(Context context, Sink sink) {
        super(context);
        this.sink = sink;
        density = context.getResources().getDisplayMetrics().density;
        keyHeight = KeyLayout.KEY_DP * density;
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
            fingers.clear();
        }
        this.enabled = enabled;
        rows = KeyLayout.rows(mode, layer);
        setVisibility(rows.length == 0 ? View.GONE : View.VISIBLE);
        requestLayout();
        invalidate();
    }

    /** The height for the content and this keyboard (the window's root says it before it measures its children). */
    void room(int px) {
        if (px != room) {
            room = px;
            forceLayout();
        }
    }

    @Override
    protected void onMeasure(int widthSpec, int heightSpec) {
        int width = MeasureSpec.getSize(widthSpec);
        keyHeight = KeyLayout.keyHeight(room, rows.length, density);
        labelPaint.setTextSize(Math.min(20 * density, keyHeight * 0.5f));
        float pad = KeyLayout.PAD_DP * density;
        setMeasuredDimension(width, rows.length == 0 ? 0 : Math.round(rows.length * keyHeight + pad));
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
        float top = KeyLayout.PAD_DP * density / 2 + row * keyHeight;
        float gap = 3 * density;
        return new RectF(x + gap, top + gap, x + unit * KeyLayout.span(keys[col]) - gap, top + keyHeight - gap);
    }

    @Override
    protected void onDraw(Canvas canvas) {
        for (int row = 0; row < rows.length; row++) {
            for (int col = 0; col < rows[row].length; col++) {
                int code = rows[row][col];
                RectF key = bounds(row, col);
                boolean down = fingers.isDown(row, col);
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
        int index = event.getActionIndex();
        int id = event.getPointerId(index);
        switch (event.getActionMasked()) {
            case MotionEvent.ACTION_DOWN:
                fingers.clear();
                touchDown(id, event.getX(index), event.getY(index));
                return true;
            case MotionEvent.ACTION_POINTER_DOWN:
                // The keys still under another finger are typed first; a layer key among them changes the keys hit now.
                for (int code : fingers.rollover()) {
                    press(code);
                }
                touchDown(id, event.getX(index), event.getY(index));
                return true;
            case MotionEvent.ACTION_POINTER_UP:
            case MotionEvent.ACTION_UP:
                int[] key = keyAt(event.getX(index), event.getY(index));
                int code = fingers.up(id, key == null ? -1 : key[0], key == null ? -1 : key[1]);
                if (code != KeyTracker.NONE) {
                    press(code);
                }
                invalidate();
                return true;
            case MotionEvent.ACTION_CANCEL:
                fingers.clear();
                invalidate();
                return true;
            default:
                return true;
        }
    }

    private void touchDown(int id, float x, float y) {
        int[] key = keyAt(x, y);
        if (key != null) {
            fingers.down(id, key[0], key[1], rows[key[0]][key[1]]);
        }
        invalidate();
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
