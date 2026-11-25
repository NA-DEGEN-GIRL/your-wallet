package dev.yw.app;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.RectF;
import android.graphics.Typeface;
import android.util.TypedValue;
import android.view.View;
import android.view.ViewStructure;
import android.view.accessibility.AccessibilityNodeInfo;
import java.util.Arrays;

/**
 * One secret text of a secret window (spec/15 §3.1, §9.1; 2026-11-25 A2-7): a field's content, the shown recovery
 * words or key, or one of W05's completions. It holds the text only in its own {@code char[]}, which Rust fills
 * through {@link Native#secretFill} with the handle the window model gave (never a String, never in the model, never
 * in an EditText, a title, a content description or an accessibility or autofill node), draws it with
 * {@code Canvas.drawText(char[], …)} and fills it with zeros whenever it is filled again, hidden or detached. The
 * Activity reads its FLAG_SECURE back right before every fill (SecretActivity.fillAll).
 *
 * <p>A grid box (W08) draws the words numbered in two columns; any other box wraps its text at spaces (and inside a
 * run longer than the line).
 */
final class SecretBox extends View {
    private static final int INK = 0xff1f2328;
    private static final int MUTED = 0xff59636e;
    private static final int FRAME = 0xffd0d7de;
    private static final int ACTIVE = 0xff0969da;
    private static final int CARD = 0xfff6f8fa;

    private final long handle;
    private final char[] buffer;
    private final boolean grid;
    private final boolean framed;
    private final Paint ink = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint mark = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint box = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final float pad;
    private final float lineHeight;
    private int count;
    private boolean active;
    /** Line (or grid cell) starts and lengths, in pairs. */
    private int[] spans = new int[0];
    private int spanCount;

    SecretBox(Context context, long handle, int capacity, boolean grid, boolean framed, float textSp) {
        super(context);
        this.handle = handle;
        this.buffer = new char[Math.max(0, capacity)];
        this.grid = grid;
        this.framed = framed;
        float size = TypedValue.applyDimension(
                TypedValue.COMPLEX_UNIT_SP, textSp, context.getResources().getDisplayMetrics());
        ink.setTypeface(Typeface.MONOSPACE);
        ink.setTextSize(size);
        ink.setColor(INK);
        mark.setTypeface(Typeface.MONOSPACE);
        mark.setTextSize(size * 0.8f);
        mark.setColor(MUTED);
        pad = 8 * context.getResources().getDisplayMetrics().density;
        lineHeight = ink.getFontSpacing() * 1.25f;
        setSaveEnabled(false);
        setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
    }

    /** Fills the box from Rust (the caller read FLAG_SECURE back right before); how many units it now holds. */
    int fill() {
        Arrays.fill(buffer, '\0');
        int written = buffer.length == 0 ? 0 : Native.secretFill(handle, buffer);
        count = Math.max(0, Math.min(buffer.length, written));
        requestLayout();
        invalidate();
        return count;
    }

    /** Fills the buffer with zeros (hidden, closed, refilled). */
    void wipe() {
        Arrays.fill(buffer, '\0');
        count = 0;
        spanCount = 0;
        invalidate();
    }

    /** How many units it holds. */
    int count() {
        return count;
    }

    /** The active field's frame. */
    void setActive(boolean active) {
        this.active = active;
        invalidate();
    }

    @Override
    protected void onMeasure(int widthSpec, int heightSpec) {
        int width = MeasureSpec.getSize(widthSpec);
        layoutText(Math.max(1f, width - 2 * pad));
        int rows = grid ? (spanCount + 1) / 2 : spanCount;
        int height = Math.round(Math.max(1, rows) * lineHeight + 2 * pad);
        setMeasuredDimension(width, height);
    }

    private void addSpan(int start, int length) {
        if (spans.length < (spanCount + 1) * 2) {
            spans = Arrays.copyOf(spans, Math.max(8, spans.length * 2));
        }
        spans[spanCount * 2] = start;
        spans[spanCount * 2 + 1] = length;
        spanCount++;
    }

    /** Splits the text into lines (or grid words) that fit {@code width}. */
    private void layoutText(float width) {
        spanCount = 0;
        if (grid) {
            int start = 0;
            for (int at = 0; at <= count; at++) {
                if (at == count || buffer[at] == ' ') {
                    if (at > start) {
                        addSpan(start, at - start);
                    }
                    start = at + 1;
                }
            }
            return;
        }
        int start = 0;
        while (start < count) {
            int end = start;
            int lastSpace = -1;
            while (end < count) {
                if (end > start && ink.measureText(buffer, start, end + 1 - start) > width) {
                    break;
                }
                if (buffer[end] == ' ') {
                    lastSpace = end;
                }
                end++;
            }
            if (end < count && lastSpace >= start) {
                end = lastSpace + 1;
            }
            addSpan(start, end - start);
            start = end;
        }
    }

    @Override
    protected void onDraw(Canvas canvas) {
        if (framed) {
            box.setStyle(Paint.Style.FILL);
            box.setColor(CARD);
            RectF frame = new RectF(1, 1, getWidth() - 1, getHeight() - 1);
            canvas.drawRoundRect(frame, pad / 2, pad / 2, box);
            box.setStyle(Paint.Style.STROKE);
            box.setStrokeWidth(active ? 4 : 2);
            box.setColor(active ? ACTIVE : FRAME);
            canvas.drawRoundRect(frame, pad / 2, pad / 2, box);
        }
        float baseline = pad - ink.ascent();
        if (grid) {
            float column = (getWidth() - 2 * pad) / 2;
            float number = mark.measureText("00. ");
            for (int at = 0; at < spanCount; at++) {
                float x = pad + (at % 2) * column;
                float y = baseline + (at / 2) * lineHeight;
                canvas.drawText((at + 1) + ".", x, y, mark);
                canvas.drawText(buffer, spans[at * 2], spans[at * 2 + 1], x + number, y, ink);
            }
            return;
        }
        for (int at = 0; at < spanCount; at++) {
            canvas.drawText(buffer, spans[at * 2], spans[at * 2 + 1], pad, baseline + at * lineHeight, ink);
        }
    }

    @Override
    protected void onDetachedFromWindow() {
        wipe();
        super.onDetachedFromWindow();
    }

    // No structure, autofill, content capture or accessibility text of a secret (spec/15 §9.1).
    @Override
    public void onProvideStructure(ViewStructure structure) {}

    @Override
    public void onProvideVirtualStructure(ViewStructure structure) {}

    @Override
    public void onProvideAutofillStructure(ViewStructure structure, int flags) {}

    @Override
    public void onProvideAutofillVirtualStructure(ViewStructure structure, int flags) {}

    @Override
    public void onProvideContentCaptureStructure(ViewStructure structure, int flags) {}

    @Override
    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo info) {
        super.onInitializeAccessibilityNodeInfo(info);
        info.setText(null);
        info.setContentDescription(null);
    }
}
