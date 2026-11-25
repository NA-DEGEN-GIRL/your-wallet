package dev.yw.app;

import android.app.Activity;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.style.StyleSpan;
import android.graphics.Typeface;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.List;

/**
 * A secret window (W01-W12, spec/15 §9.1-§9.2, §8.4; 2026-11-25 A2-7): its own Activity, not exported, excluded from
 * the recent apps, with an affinity of its own, never recreated on a configuration change (it handles them).
 *
 * <p><b>The two-phase open</b> (§9.1, §18 42 N23). Rust asks for the window with {@code s_open}; this Activity sets
 * FLAG_SECURE before any content, turns off the recents screenshot (API 33+), and once its window is attached reads
 * the flag back and answers {@code s_ready} with its serial, its own instance id (counted up, never reused) and what
 * it read; with the flag off it closes at once. Only then does Rust make the form, or (W08/W09) move the secret into
 * it, and send the window model {@code s_model}. A model of another serial or instance is not drawn.
 *
 * <p><b>Secrets</b> are drawn only by {@link SecretBox}es filled through {@link Native#secretFill} with the model's
 * handles; FLAG_SECURE is read back right before every fill, and when it is off nothing is filled and the window
 * closes (fail closed). The boxes are wiped when the window is hidden, refilled, closed or destroyed. Keys come only
 * from the app keyboard ({@link KeyPad}, through {@link Native#secretKey}); no system input method is ever shown (no
 * text editor exists here, and the window keeps the soft input hidden). No Dialog, Toast or PopupWindow.
 *
 * <p>The root view is excluded from autofill, content capture (API 30+), marked accessibility-data-sensitive (API 34+)
 * and content-sensitive (API 35+). Every text drawn comes from the model (Rust's catalogues, spec/15 §3.3).
 *
 * <p>2026-11-26 A2 final review (spec/15 §1.1, §9.1): the window is, from the top, the warning bands (outside the scroll
 * view, always in sight, drawn from each model), the scrolled content, W05's completions and the app keyboard, whose rows
 * get lower before the bands would give way ({@link Root}). Before, the bands were the first thing in the scrolled body
 * and scrolled away. And no button a finger is on is ever rebuilt ({@link HeldButtons}).
 */
public final class SecretActivity extends Activity implements SecretWindows.Win {
    /** The intent extra: the secret session's serial. */
    static final String EXTRA_SERIAL = "dev.yw.app.serial";

    private static final int INK = 0xff1f2328;
    private static final int MUTED = 0xff59636e;
    private static final int OK = 0xff1a7f37;
    private static final int BAD = 0xffcf222e;

    /** The last instance id handed out in this process (never reused). */
    private static int lastWin;

    private final Handler main = new Handler(Looper.getMainLooper());
    private final Runnable tick = this::tick;
    /** The boxes of the body (kept with it) and, apart, those of the completions. */
    private final List<SecretBox> boxes = new ArrayList<>();
    private final List<SecretBox> candidateBoxes = new ArrayList<>();
    /** The field boxes of the drawn body by field index (empty while the content is masked). */
    private final List<SecretBox> fieldBoxes = new ArrayList<>();
    private long serial = -1;
    private int win;
    private boolean readySent;
    private boolean closedByRust;
    /** The warning bands (spec/15 §1.1, §8.2), above and outside the scroll view, and the texts drawn now. */
    private LinearLayout bands;
    private List<String> bandTexts = new ArrayList<>();
    private LinearLayout content;
    /**
     * 2026-11-25 A2 device run (spec/15 §9.1): {@code content} holds {@code body} and then {@code buttons}, the button
     * row. 2026-11-26 A2 final review: each of the two is rebuilt from a model only while no finger is on one of its own
     * buttons ({@link HeldButtons}); a kept body still refills its boxes (a held reveal shows the field that way) and a
     * kept row still takes the model's labels (W08's hold counts down in its label). The latest model is drawn when the
     * finger is gone. Before the device run every model removed every view, and until this review the body's buttons
     * (W05's checkbox, the reveals) were still removed under the finger: Android cancelled the touch.
     */
    private LinearLayout body;
    private LinearLayout buttons;
    private final HeldButtons held = new HeldButtons();
    private LinearLayout candidates;
    private KeyPad keypad;
    private Object model;
    private int active;
    private float density;

    @Override
    protected void onCreate(Bundle state) {
        // Before any content (spec/15 §9.1); read back once attached and before every fill.
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);
        super.onCreate(null);
        if (Build.VERSION.SDK_INT >= 33) {
            setRecentsScreenshotEnabled(false);
            // From API 33 (and always for target 36 on API 36) Back comes through the dispatcher, not onBackPressed.
            getOnBackInvokedDispatcher()
                    .registerOnBackInvokedCallback(
                            android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT,
                            () -> Screen.send(SecretWire.back(win)));
        }
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);
        if (getActionBar() != null) {
            getActionBar().hide();
        }
        density = getResources().getDisplayMetrics().density;
        serial = getIntent().getLongExtra(EXTRA_SERIAL, -1);
        win = ++lastWin;
        Screen.secretCreated(this);
        Root root = new Root(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setFitsSystemWindows(true);
        root.setBackgroundColor(0xffffffff);
        root.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        if (Build.VERSION.SDK_INT >= 30) {
            root.setImportantForContentCapture(View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS);
        }
        if (Build.VERSION.SDK_INT >= 34) {
            root.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES);
        }
        if (Build.VERSION.SDK_INT >= 35) {
            root.setContentSensitivity(View.CONTENT_SENSITIVITY_SENSITIVE);
        }
        bands = new LinearLayout(this);
        bands.setOrientation(LinearLayout.VERTICAL);
        root.addView(bands);
        ScrollView scroll = new ScrollView(this);
        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int padding = dp(16);
        content.setPadding(padding, padding, padding, padding);
        body = new LinearLayout(this);
        body.setOrientation(LinearLayout.VERTICAL);
        content.addView(body);
        buttons = new LinearLayout(this);
        buttons.setOrientation(LinearLayout.HORIZONTAL);
        buttons.setGravity(Gravity.END);
        content.addView(buttons, spaced());
        scroll.addView(content);
        root.addView(scroll, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));
        candidates = new LinearLayout(this);
        candidates.setOrientation(LinearLayout.HORIZONTAL);
        root.addView(candidates);
        keypad = new KeyPad(this, this::key);
        keypad.set("none", false);
        root.addView(keypad);
        setContentView(root);
        if (serial < 0 || Screen.wasClosed(serial)) {
            closedByRust = true;
            finish();
        }
    }

    /**
     * Whether this window's FLAG_SECURE is set, read back now from the window's LayoutParams (the attributes the window
     * was added with and is updated from). 2026-11-25 A2-7 review: this proves that nothing in the app cleared the flag;
     * it cannot see whether the window manager or an OEM build honours it (the residual of spec/15 §9.1, checked on the
     * device with dumpsys and screencap, spec/09 §2.6).
     */
    private boolean secure() {
        return (getWindow().getAttributes().flags & WindowManager.LayoutParams.FLAG_SECURE) != 0;
    }

    @Override
    public void onAttachedToWindow() {
        super.onAttachedToWindow();
        if (readySent || closedByRust) {
            return;
        }
        readySent = true;
        boolean secure = secure();
        Screen.send(SecretWire.ready(serial, win, secure, DeviceFacts.members(this)));
        if (!secure) {
            closedByRust = true;
            finish();
        }
    }

    @Override
    protected void onStart() {
        super.onStart();
        Screen.started(this);
        main.postDelayed(tick, UiWire.TICK_MS);
        if (model != null) {
            draw(model);
        }
    }

    @Override
    protected void onStop() {
        main.removeCallbacks(tick);
        held.clear();
        wipeAll();
        Screen.stopped(this);
        super.onStop();
    }

    /** The main timer runs while a secret window covers the main one (its hold, time-outs, countdown). */
    private void tick() {
        Screen.send(UiWire.tick());
        main.postDelayed(tick, UiWire.TICK_MS);
    }

    @Override
    public void onWindowFocusChanged(boolean hasFocus) {
        super.onWindowFocusChanged(hasFocus);
        if (readySent && !closedByRust) {
            Screen.send(SecretWire.focus(win, hasFocus));
        }
    }

    @Override
    public void onBackPressed() {
        // Rust decides (Esc: wipe and cancel; nothing while a submitted job runs).
        Screen.send(SecretWire.back(win));
    }

    @Override
    public void onConfigurationChanged(android.content.res.Configuration config) {
        super.onConfigurationChanged(config);
        // The bands too: drawn again although their texts are the same (a new font scale).
        bands.removeAllViews();
        if (model != null) {
            draw(model);
        }
    }

    @Override
    protected void onDestroy() {
        wipeAll();
        Screen.secretDestroyed(this);
        if (!closedByRust && serial >= 0) {
            Screen.send(SecretWire.gone(serial, win));
        }
        super.onDestroy();
    }

    /** The serial this window was opened for. */
    @Override
    public long serial() {
        return serial;
    }

    /** This window's instance id. */
    @Override
    public int win() {
        return win;
    }

    /** Rust closed the window ({@code s_close}, {@code s_close_win} or a resync's {@code s_keep}). */
    @Override
    public void closeFromRust() {
        closedByRust = true;
        wipeAll();
        finish();
    }

    /** A window model ({@code s_model}): drawn only when it is this window's. */
    void applyModel(Object frame) {
        if (Json.number(frame, "serial", -1) != serial || Json.number(frame, "win", -1) != win || closedByRust) {
            return;
        }
        model = frame;
        draw(frame);
    }

    private void wipeAll() {
        for (SecretBox box : boxes) {
            box.wipe();
        }
        for (SecretBox box : candidateBoxes) {
            box.wipe();
        }
    }

    /** Fills every box, after reading FLAG_SECURE back; with the flag off nothing is filled and the window closes. */
    private boolean fillAll() {
        if (!secure()) {
            wipeAll();
            finish();
            return false;
        }
        for (SecretBox box : boxes) {
            box.fill();
        }
        for (SecretBox box : candidateBoxes) {
            box.fill();
        }
        return true;
    }

    private void key(int unit) {
        Native.secretKey(SecretWire.field(win, active), unit);
    }

    private void draw(Object frame) {
        wipeAll();
        drawBands(frame);
        String masked = Json.string(frame, "masked");
        if (held.rebuilds(HeldButtons.BODY)) {
            drawBody(frame, masked);
        } else {
            keepBody(frame);
        }
        drawButtons(frame);
        candidates.removeAllViews();
        candidateBoxes.clear();
        boolean input = Boolean.TRUE.equals(Json.bool(frame, "input"));
        if (masked == null && input) {
            for (Object candidate : Json.list(frame, "cands")) {
                addCandidate(candidate);
            }
        }
        keypad.set(Json.string(frame, "keys"), input && masked == null);
        if (fillAll()) {
            // A completion that fills nothing is not shown (the model never says how many there are).
            for (SecretBox box : candidateBoxes) {
                box.setVisibility(box.count() > 0 ? View.VISIBLE : View.GONE);
            }
        }
    }

    /**
     * The warning bands of {@code frame}, top first; the views are rebuilt only when a text changed. An entry that is no
     * text still draws an empty band (the window is never shown as if it had no warning, as on the main screen).
     */
    private void drawBands(Object frame) {
        List<String> texts = new ArrayList<>();
        for (Object band : Json.list(frame, "bands")) {
            texts.add(band instanceof String ? (String) band : "");
        }
        if (texts.equals(bandTexts) && bands.getChildCount() == texts.size()) {
            return;
        }
        bandTexts = texts;
        bands.removeAllViews();
        for (String value : texts) {
            TextView view = text(value, 14, false, getColor(R.color.band_text));
            view.setBackgroundColor(getColor(R.color.band_background));
            view.setPadding(dp(12), dp(8), dp(12), dp(8));
            LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
            params.setMargins(0, 0, 0, dp(2));
            bands.addView(view, params);
        }
    }

    /** The body while a finger is on one of its buttons: its views stay; only the active field follows the model. */
    private void keepBody(Object frame) {
        int index = 0;
        for (Object field : Json.list(frame, "fields")) {
            boolean isActive = Boolean.TRUE.equals(Json.bool(field, "active"));
            if (isActive) {
                active = index;
            }
            if (index < fieldBoxes.size()) {
                fieldBoxes.get(index).setActive(isActive);
            }
            index++;
        }
    }

    private void drawBody(Object frame, String masked) {
        boxes.clear();
        fieldBoxes.clear();
        body.removeAllViews();
        Object step = Json.get(frame, "step");
        if (step instanceof java.util.Map) {
            body.addView(text(Json.string(step, "head"), 13, false, MUTED), spaced());
            SpannableStringBuilder labels = new SpannableStringBuilder();
            long current = Json.number(step, "current", 0);
            int number = 0;
            for (Object label : Json.list(step, "labels")) {
                number++;
                if (labels.length() > 0) {
                    labels.append("  ");
                }
                int start = labels.length();
                labels.append(String.valueOf(number)).append(" ").append(String.valueOf(label));
                if (number == current) {
                    labels.setSpan(new StyleSpan(Typeface.BOLD), start, labels.length(), Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                }
            }
            TextView view = new TextView(this);
            view.setText(labels);
            view.setTextColor(INK);
            body.addView(view, spaced());
        }
        body.addView(text(Json.string(frame, "title"), 20, true, INK), spaced());
        for (Object paragraph : Json.list(frame, "intro")) {
            if (paragraph instanceof String) {
                body.addView(text((String) paragraph, 15, false, INK), spaced());
            }
        }
        if (masked != null) {
            body.addView(text(masked, 15, false, MUTED), spaced());
        }
        int index = 0;
        active = 0;
        for (Object field : Json.list(frame, "fields")) {
            addField(field, index, masked == null);
            index++;
        }
        String words = Json.string(frame, "words");
        if (words != null) {
            body.addView(text(words, 13, false, MUTED), spaced());
        }
        for (Object check : Json.list(frame, "checks")) {
            body.addView(toned(check), spaced());
        }
        Object checkbox = Json.get(frame, "checkbox");
        if (checkbox instanceof java.util.Map) {
            boolean on = Boolean.TRUE.equals(Json.bool(checkbox, "on"));
            Button box = button((on ? "☑ " : "☐ ") + Json.string(checkbox, "label"), "checkbox", 0, HeldButtons.BODY,
                    Boolean.TRUE.equals(Json.bool(checkbox, "enabled")));
            body.addView(box, spaced());
        }
        String note = Json.string(frame, "note");
        if (note != null) {
            body.addView(text(note, 14, false, MUTED), spaced());
        }
        Object shown = Json.get(frame, "shown");
        if (shown instanceof java.util.Map && masked == null) {
            SecretBox box = new SecretBox(this, Json.number(shown, "h", 0), (int) Json.number(shown, "cap", 0),
                    Boolean.TRUE.equals(Json.bool(shown, "grid")), true, 18);
            boxes.add(box);
            body.addView(box, spaced());
        }
        Object address = Json.get(frame, "address");
        if (address instanceof java.util.Map) {
            body.addView(text(Json.string(address, "label"), 14, true, INK), spaced());
            TextView line = text(Json.string(address, "text"), 14, false, INK);
            line.setTypeface(Typeface.MONOSPACE);
            body.addView(line, spaced());
        }
        String passphrase = Json.string(frame, "pp_note");
        if (passphrase != null) {
            body.addView(text(passphrase, 14, false, BAD), spaced());
        }
        for (Object line : Json.list(frame, "status")) {
            body.addView(toned(line), spaced());
        }
        for (Object line : Json.list(frame, "msgs")) {
            body.addView(toned(line), spaced());
        }
    }

    /**
     * The button row of {@code frame}. While a finger is on one of its buttons the row is kept and its buttons only take
     * the model's labels (W08's hold counts down in its label).
     */
    private void drawButtons(Object frame) {
        if (!held.rebuilds(HeldButtons.ROW)) {
            for (int at = 0; at < buttons.getChildCount(); at++) {
                Button button = (Button) buttons.getChildAt(at);
                String label = SecretWire.buttonLabel(frame, (String) button.getTag());
                if (label != null) {
                    button.setText(label);
                }
            }
            return;
        }
        buttons.removeAllViews();
        for (Object item : Json.list(frame, "buttons")) {
            String word = Json.string(item, "b");
            if (word != null) {
                buttons.addView(button(Json.string(item, "label"), word, 0, HeldButtons.ROW,
                        Boolean.TRUE.equals(Json.bool(item, "on"))));
            }
        }
    }

    private void addField(Object field, int index, boolean visible) {
        LinearLayout head = new LinearLayout(this);
        head.setOrientation(LinearLayout.HORIZONTAL);
        TextView label = text(Json.string(field, "label"), 15, true, INK);
        head.addView(label, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        String right = Json.string(field, "right");
        if (right != null && !right.isEmpty()) {
            head.addView(text(right, 13, false, Boolean.TRUE.equals(Json.bool(field, "bad")) ? BAD : MUTED));
        }
        body.addView(head, spaced());
        if (!visible) {
            return;
        }
        boolean isActive = Boolean.TRUE.equals(Json.bool(field, "active"));
        if (isActive) {
            active = index;
        }
        SecretBox box = new SecretBox(this, Json.number(field, "h", 0), (int) Json.number(field, "cap", 0), false, true,
                16);
        box.setActive(isActive);
        box.setOnTouchListener((view, event) -> {
            if (event.getActionMasked() == MotionEvent.ACTION_DOWN) {
                Screen.send(SecretWire.button(win, "field", index, "down"));
            }
            return true;
        });
        boxes.add(box);
        fieldBoxes.add(box);
        body.addView(box, spaced());
        Object reveal = Json.get(field, "reveal");
        if (reveal instanceof java.util.Map) {
            body.addView(button(Json.string(reveal, "label"), "reveal", index, HeldButtons.BODY,
                    Boolean.TRUE.equals(Json.bool(reveal, "on"))));
        }
    }

    private void addCandidate(Object candidate) {
        int index = candidates.getChildCount();
        SecretBox box = new SecretBox(this, Json.number(candidate, "h", 0), (int) Json.number(candidate, "cap", 0),
                false, true, 16);
        box.setOnTouchListener((view, event) -> {
            if (event.getActionMasked() == MotionEvent.ACTION_UP) {
                Native.secretKey(SecretWire.field(win, SecretWire.TARGET_PICK), index);
            }
            return true;
        });
        candidateBoxes.add(box);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        params.setMargins(dp(4), dp(4), dp(4), dp(4));
        candidates.addView(box, params);
    }

    /**
     * A button of the model in {@code place} of the window: a press, a release on it and a finger that leaves it are each
     * sent (Rust decides; a held button such as W08's acknowledgement or a reveal needs them all). {@link HeldButtons}
     * says which, and keeps the place from being rebuilt until the finger is gone; then the latest model is drawn.
     */
    private Button button(String label, String word, int index, int place, boolean enabled) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setEnabled(enabled);
        button.setTag(word);
        button.setOnTouchListener((view, event) -> {
            float x = event.getRawX();
            float y = event.getRawY();
            String edge;
            switch (event.getActionMasked()) {
                case MotionEvent.ACTION_DOWN:
                    edge = held.down(view, place, view.isEnabled(), x - event.getX(), y - event.getY(), view.getWidth(),
                            view.getHeight());
                    break;
                case MotionEvent.ACTION_MOVE:
                    edge = held.moved(view, x, y);
                    break;
                case MotionEvent.ACTION_UP:
                    edge = held.up(view, x, y);
                    break;
                case MotionEvent.ACTION_CANCEL:
                    edge = held.cancelled(view);
                    break;
                default:
                    edge = null;
                    break;
            }
            if (edge == null) {
                return true;
            }
            boolean down = HeldButtons.DOWN.equals(edge);
            view.setPressed(down);
            Screen.send(SecretWire.button(win, word, index, edge));
            if (!down && model != null && !closedByRust) {
                draw(model);
            }
            return true;
        });
        return button;
    }

    private TextView toned(Object line) {
        String tone = Json.string(line, "tone");
        int color = "ok".equals(tone) ? OK : "bad".equals(tone) ? BAD : MUTED;
        return text(Json.string(line, "text"), 14, false, color);
    }

    private TextView text(String value, int sp, boolean bold, int color) {
        TextView view = new TextView(this);
        view.setText(value == null ? "" : value);
        view.setTextSize(sp);
        view.setTextColor(color);
        if (bold) {
            view.setTypeface(Typeface.DEFAULT_BOLD);
        }
        return view;
    }

    private LinearLayout.LayoutParams spaced() {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT);
        params.setMargins(0, dp(4), 0, dp(4));
        return params;
    }

    private int dp(int value) {
        return Math.round(value * density);
    }

    /**
     * The window's root: the bands and the completions keep their height, the keyboard takes lower rows when little is
     * left ({@link KeyLayout#keyHeight}), and the scrolled content has the rest. A LinearLayout alone would measure the
     * keyboard against the whole height and, in a low window, lay it out below the screen's end.
     */
    private final class Root extends LinearLayout {
        Root(android.content.Context context) {
            super(context);
        }

        @Override
        protected void onMeasure(int widthSpec, int heightSpec) {
            int width = MeasureSpec.getSize(widthSpec) - getPaddingLeft() - getPaddingRight();
            int height = MeasureSpec.getSize(heightSpec) - getPaddingTop() - getPaddingBottom();
            int fixed = 0;
            for (View view : new View[] {bands, candidates}) {
                view.measure(MeasureSpec.makeMeasureSpec(Math.max(0, width), MeasureSpec.EXACTLY),
                        MeasureSpec.makeMeasureSpec(0, MeasureSpec.UNSPECIFIED));
                fixed += view.getMeasuredHeight();
            }
            keypad.room(Math.max(0, height - fixed));
            super.onMeasure(widthSpec, heightSpec);
        }
    }
}
