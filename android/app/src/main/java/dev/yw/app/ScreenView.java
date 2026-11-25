package dev.yw.app;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.text.Editable;
import android.text.InputFilter;
import android.text.InputType;
import android.text.SpannableStringBuilder;
import android.text.Spanned;
import android.text.TextWatcher;
import android.text.style.StyleSpan;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.Space;
import android.widget.TextView;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Draws one screen model (yw-engine wire::model, spec/15 §11.3; 2026-11-25 A2-6) as Android Views in a narrow, vertical
 * layout. Rust decides everything a screen says and does; this class only lays it out: every text comes from the
 * model, a control knows only its slot, and a press or a typed text goes back as an input naming the model's revision
 * and that slot (UiWire). Item kinds are drawn plainly; the colours follow the item's tone or style.
 *
 * <p>A credential edit ({@code "c":"cred"}) is drawn as an empty box that takes no input: credentials are typed only
 * on the app keyboard of the secret windows (spec/15 §9.2, A3/A7), never through the system keyboard. Plain edits use
 * the system keyboard with suggestions, personalised learning and autofill off (2026-11-25 A2-6 review: the learning
 * flag added; it is a request to the keyboard, not a guarantee, spec/15 §9.2).
 *
 * <p>What a plain edit shows is Rust's (2026-11-25 A2-6 review; yw-engine wire module doc): a model is drawn with its
 * own texts and nothing typed is kept here; Rust answers the rendered input with a field frame for every edit whose
 * text differs (the Windows keep rule, decided by the engine) and a reveal for the edit that keeps the focus. A field
 * frame names how many edits of its slot Rust had taken since the render ({@code seen}); when more were sent since,
 * the frame is older than what the edit shows and is not applied (Rust takes those edits after it). Before the
 * review this class kept the focused edit's typed text by a rule of its own (same slot, limit and model text), which
 * could differ from the engine's form state that a press reads. A check box or radio shows its drawn state until the
 * next model: a click sends the press and puts the box back.
 */
final class ScreenView {
    /** What a drawn control sends. */
    interface Sink {
        void press(long rev, long slot);

        /** Sends a typed text; false when it could not be sent (too long for Rust to read). */
        boolean edit(long rev, long slot, String text);
    }

    private static final int INK = 0xff1f2328;
    private static final int MUTED = 0xff59636e;
    private static final int LINK = 0xff0969da;
    private static final int CARD = 0xfff6f8fa;
    private static final int RULE = 0xffd0d7de;

    private final Context context;
    private final LinearLayout root;
    private final Sink sink;
    private final float density;
    private long rev = -1;
    /** Each drawn plain edit by slot. */
    private final Map<Long, EditText> edits = new HashMap<>();
    /** The edits sent per slot since the model was drawn (a field frame's {@code seen} is compared with it). */
    private final Map<Long, Long> sent = new HashMap<>();
    private final Map<Long, View> controls = new HashMap<>();
    private boolean writing;

    ScreenView(Context context, LinearLayout root, Sink sink) {
        this.context = context;
        this.root = root;
        this.sink = sink;
        this.density = context.getResources().getDisplayMetrics().density;
    }

    /** The revision drawn (-1: none). */
    long rev() {
        return rev;
    }

    /**
     * Draws {@code model} in place of the screen drawn before, each edit with the model's text, and returns the slot of
     * the plain edit that had the focus before (-1: none), which the rendered answer names. Rust answers with the texts
     * and the focus (class doc).
     */
    long draw(Object model) {
        long focus = -1;
        for (Map.Entry<Long, EditText> entry : edits.entrySet()) {
            if (entry.getValue().hasFocus()) {
                focus = entry.getKey();
            }
        }
        rev = Json.number(model, "rev", -1);
        edits.clear();
        sent.clear();
        controls.clear();
        root.removeAllViews();
        Deque<LinearLayout> cards = new ArrayDeque<>();
        cards.push(root);
        for (Object item : Json.list(model, "items")) {
            String kind = Json.string(item, "k");
            if ("card".equals(kind)) {
                LinearLayout card = column();
                GradientDrawable shape = new GradientDrawable();
                shape.setColor(CARD);
                shape.setStroke(dp(1), RULE);
                shape.setCornerRadius(dp(8));
                card.setBackground(shape);
                card.setPadding(dp(12), dp(8), dp(12), dp(8));
                String title = Json.string(item, "title");
                if (title != null) {
                    card.addView(text(title, 17, true, INK));
                }
                cards.peek().addView(card, spaced());
                cards.push(card);
            } else if ("end".equals(kind)) {
                if (cards.size() > 1) {
                    cards.pop();
                }
            } else {
                View view = item(item);
                if (view != null) {
                    cards.peek().addView(view, spaced());
                }
            }
        }
        return focus;
    }

    /** A field, reveal or top frame of the model drawn now; one of another revision is dropped. */
    void apply(Object frame, android.widget.ScrollView scroll) {
        String kind = Json.string(frame, "t");
        if ("top".equals(kind)) {
            scroll.scrollTo(0, 0);
            return;
        }
        if (Json.number(frame, "rev", -2) != rev) {
            return;
        }
        long slot = Json.number(frame, "slot", -1);
        if ("field".equals(kind)) {
            EditText edit = edits.get(slot);
            String text = Json.string(frame, "text");
            if (edit != null && text != null && UiWire.fieldApplies(frame, rev, sent.getOrDefault(slot, 0L))) {
                write(edit, text);
            }
        } else if ("reveal".equals(kind)) {
            View view = controls.get(slot);
            if (view != null) {
                view.requestFocus();
                if (view instanceof EditText) {
                    ((EditText) view).setSelection(((EditText) view).length());
                }
                scroll.requestChildFocus(view, view);
            }
        }
    }

    private void write(EditText view, String text) {
        writing = true;
        try {
            view.setText(text);
            if (view.hasFocus()) {
                view.setSelection(view.length());
            }
        } finally {
            writing = false;
        }
    }

    private int dp(int value) {
        return Math.round(value * density);
    }

    private LinearLayout column() {
        LinearLayout column = new LinearLayout(context);
        column.setOrientation(LinearLayout.VERTICAL);
        return column;
    }

    private LinearLayout.LayoutParams spaced() {
        LinearLayout.LayoutParams params =
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = dp(4);
        return params;
    }

    private TextView text(String value, int sp, boolean bold, int color) {
        TextView view = new TextView(context);
        view.setText(value == null ? "" : value);
        view.setTextSize(sp);
        view.setTextColor(color);
        if (bold) {
            view.setTypeface(Typeface.DEFAULT_BOLD);
        }
        return view;
    }

    private View item(Object item) {
        String kind = Json.string(item, "k");
        if (kind == null) {
            return null;
        }
        switch (kind) {
            case "title":
                return text(Json.string(item, "text"), 22, true, INK);
            case "text":
                return text(Json.string(item, "text"), 15, false, INK);
            case "muted":
                return text(Json.string(item, "text"), 14, false, MUTED);
            case "help":
                return text(Json.string(item, "text"), 13, false, MUTED);
            case "subtitle":
                return text(Json.string(item, "text"), 17, true, INK);
            case "display":
                return text(Json.string(item, "text"), 28, true, INK);
            case "display_muted":
                return text(Json.string(item, "text"), 28, true, MUTED);
            case "mono": {
                TextView view = text(Json.string(item, "text"), 14, false, INK);
                view.setTypeface(Typeface.MONOSPACE);
                return view;
            }
            case "copy": {
                LinearLayout line = column();
                View value = control(Json.get(item, "value"));
                if (value != null) {
                    line.addView(value);
                }
                line.addView(row(Json.list(item, "actions")));
                return line;
            }
            case "list": {
                LinearLayout line = new LinearLayout(context);
                line.setOrientation(LinearLayout.HORIZONTAL);
                line.addView(text(Json.string(item, "title") + "  ", 15, true, INK));
                line.addView(text(Json.string(item, "value") + "  ", 15, true, INK));
                line.addView(text(Json.string(item, "note"), 13, false, MUTED));
                if (Boolean.TRUE.equals(Json.bool(item, "dim"))) {
                    line.setAlpha(0.5f);
                }
                return line;
            }
            case "pill": {
                TextView view = text(Json.string(item, "text"), 12, true, Tones.ink(Json.string(item, "tone")));
                view.setBackground(rounded(Tones.background(Json.string(item, "tone"))));
                view.setPadding(dp(8), dp(2), dp(8), dp(2));
                LinearLayout wrap = new LinearLayout(context);
                wrap.addView(view);
                return wrap;
            }
            case "menu":
                return stack(Json.list(item, "ctls"));
            case "field": {
                LinearLayout field = column();
                field.addView(text(Json.string(item, "label"), 13, false, MUTED));
                field.addView(text(Json.string(item, "value"), 15, false, INK));
                return field;
            }
            case "banner": {
                String tone = Json.string(item, "tone");
                String tag = Json.string(item, "tag");
                TextView view = text((tag == null ? "" : tag + " · ") + Json.string(item, "text"), 14, false,
                        Tones.ink(tone));
                view.setBackground(rounded(Tones.background(tone)));
                view.setPadding(dp(12), dp(8), dp(12), dp(8));
                return view;
            }
            case "gap": {
                Space space = new Space(context);
                space.setMinimumHeight(dp((int) Math.min(200, Json.number(item, "dip", 0))));
                return space;
            }
            case "row":
                return stack(Json.list(item, "ctls"));
            case "lrow": {
                LinearLayout field = column();
                field.addView(text(Json.string(item, "label"), 13, false, MUTED));
                field.addView(stack(Json.list(item, "ctls")));
                return field;
            }
            case "rule": {
                View rule = new View(context);
                rule.setBackgroundColor(RULE);
                rule.setMinimumHeight(dp(1));
                return rule;
            }
            case "qr":
                return qr(Json.number(item, "size", 0), Json.string(item, "bits"));
            case "steps": {
                LinearLayout steps = column();
                long current = Json.number(item, "current", 0);
                long number = 1;
                for (Object label : Json.list(item, "labels")) {
                    boolean reached = number <= current;
                    steps.addView(text((reached ? "● " : "○ ") + label, 13, number == current, reached ? INK : MUTED));
                    number++;
                }
                return steps;
            }
            case "bar": {
                LinearLayout bar = column();
                bar.addView(text(Json.string(item, "title"), 17, true, INK));
                bar.addView(row(Json.list(item, "ctls")));
                return bar;
            }
            case "badged": {
                LinearLayout line = new LinearLayout(context);
                line.setOrientation(LinearLayout.HORIZONTAL);
                line.setGravity(Gravity.CENTER_VERTICAL);
                line.addView(badge(Json.get(item, "badge")));
                View inner = item(Json.get(item, "item"));
                if (inner != null) {
                    line.addView(inner);
                }
                return line;
            }
            case "hold": {
                TextView view = text(Json.string(item, "label"), 15, false, MUTED);
                view.setEnabled(false);
                return view;
            }
            default:
                return null;
        }
    }

    private GradientDrawable rounded(int color) {
        GradientDrawable shape = new GradientDrawable();
        shape.setColor(color);
        shape.setCornerRadius(dp(6));
        return shape;
    }

    /** Controls one under the other (a narrow screen). */
    private LinearLayout stack(List<?> ctls) {
        LinearLayout stack = column();
        for (Object ctl : ctls) {
            View view = control(ctl);
            if (view != null) {
                stack.addView(view, spaced());
            }
        }
        return stack;
    }

    /** Small controls side by side, scrolled when they do not fit. */
    private View row(List<?> ctls) {
        LinearLayout line = new LinearLayout(context);
        line.setOrientation(LinearLayout.HORIZONTAL);
        for (Object ctl : ctls) {
            View view = control(ctl);
            if (view != null) {
                line.addView(view);
            }
        }
        HorizontalScrollView scroll = new HorizontalScrollView(context);
        scroll.addView(line);
        return scroll;
    }

    private TextView badge(Object badge) {
        String mark = Json.string(badge, "mark");
        String face;
        if ("letter".equals(mark)) {
            String letter = Json.string(badge, "ch");
            face = letter == null ? "" : letter;
        } else {
            face = Tones.markGlyph(mark);
        }
        TextView view = text(face, 12, true, (int) (0xff000000L | Json.number(badge, "ink", 0xffffff)));
        GradientDrawable disc = new GradientDrawable();
        disc.setShape(GradientDrawable.OVAL);
        disc.setColor((int) (0xff000000L | Json.number(badge, "color", 0x888888)));
        view.setBackground(disc);
        view.setGravity(Gravity.CENTER);
        view.setMinWidth(dp(22));
        view.setMinHeight(dp(22));
        if (Boolean.TRUE.equals(Json.bool(badge, "testnet"))) {
            view.setAlpha(0.6f);
        }
        return view;
    }

    private CharSequence faceText(Object ctl) {
        Object face = Json.get(ctl, "face");
        String label = Json.string(ctl, "text");
        String kind = Json.string(face, "f");
        if (kind == null) {
            return label == null ? "" : label;
        }
        switch (kind) {
            case "glyph":
                return Json.string(face, "glyph");
            case "entry": {
                String glyph = Json.string(face, "glyph");
                return label + (glyph == null ? "" : "  " + glyph);
            }
            case "value":
            case "copied": {
                SpannableStringBuilder out = new SpannableStringBuilder();
                for (Object line : Json.list(face, "lines")) {
                    if (out.length() > 0) {
                        out.append('\n');
                    }
                    if (line instanceof List) {
                        for (Object span : (List<?>) line) {
                            if (span instanceof List && ((List<?>) span).size() == 2) {
                                Object piece = ((List<?>) span).get(0);
                                int start = out.length();
                                out.append(piece instanceof String ? (String) piece : "");
                                if (Boolean.TRUE.equals(((List<?>) span).get(1))) {
                                    out.setSpan(new StyleSpan(Typeface.BOLD), start, out.length(),
                                            Spanned.SPAN_EXCLUSIVE_EXCLUSIVE);
                                }
                            }
                        }
                    }
                }
                if ("copied".equals(kind)) {
                    out.append(" ✓\n").append(Json.string(face, "note"));
                } else {
                    out.append(" ⧉");
                }
                return out;
            }
            default:
                return label == null ? "" : label;
        }
    }

    private View control(Object ctl) {
        long slot = Json.number(ctl, "s", -1);
        String kind = Json.string(ctl, "c");
        if (slot < 0 || kind == null) {
            return null;
        }
        boolean on = Boolean.TRUE.equals(Json.bool(ctl, "on"));
        long drawnRev = rev;
        View view;
        switch (kind) {
            case "button": {
                String style = Json.string(ctl, "style");
                TextView button;
                if ("link".equals(style)) {
                    button = text("", 15, false, LINK);
                    button.setPadding(dp(4), dp(8), dp(4), dp(8));
                } else {
                    Button plain = new Button(context);
                    plain.setAllCaps(false);
                    Tones.styleButton(plain, style);
                    button = plain;
                }
                CharSequence face = faceText(ctl);
                String tip = Json.string(ctl, "tip");
                button.setText(face);
                if (tip != null) {
                    button.setContentDescription(tip);
                    button.setTooltipText(tip);
                } else if (Json.get(Json.get(ctl, "face"), "f") != null) {
                    button.setContentDescription(Json.string(ctl, "text"));
                }
                if (Boolean.TRUE.equals(Json.bool(ctl, "compact"))) {
                    button.setTextSize(13);
                }
                Object badge = Json.get(ctl, "badge");
                if (badge instanceof Map) {
                    LinearLayout line = new LinearLayout(context);
                    line.setOrientation(LinearLayout.HORIZONTAL);
                    line.setGravity(Gravity.CENTER_VERTICAL);
                    line.addView(badge(badge));
                    line.addView(button);
                    button.setOnClickListener(clicked -> sink.press(drawnRev, slot));
                    button.setEnabled(on);
                    controls.put(slot, button);
                    return line;
                }
                button.setOnClickListener(clicked -> sink.press(drawnRev, slot));
                view = button;
                break;
            }
            case "check": {
                CheckBox box = new CheckBox(context);
                boolean drawn = Boolean.TRUE.equals(Json.bool(ctl, "checked"));
                box.setText(Json.string(ctl, "text"));
                box.setChecked(drawn);
                // The click turned the box over; it shows the drawn state until Rust's next model (class doc).
                box.setOnClickListener(clicked -> {
                    box.setChecked(drawn);
                    sink.press(drawnRev, slot);
                });
                view = box;
                break;
            }
            case "radio": {
                RadioButton radio = new RadioButton(context);
                boolean drawn = Boolean.TRUE.equals(Json.bool(ctl, "checked"));
                radio.setText(Json.string(ctl, "text"));
                radio.setChecked(drawn);
                radio.setOnClickListener(clicked -> {
                    radio.setChecked(drawn);
                    sink.press(drawnRev, slot);
                });
                view = radio;
                break;
            }
            case "edit": {
                EditText edit = new EditText(context);
                String modelText = Json.string(ctl, "text");
                long limit = Json.number(ctl, "limit", 0);
                int type = InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS;
                if (Boolean.TRUE.equals(Json.bool(ctl, "password"))) {
                    type |= InputType.TYPE_TEXT_VARIATION_PASSWORD;
                }
                edit.setInputType(type);
                edit.setImeOptions(EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING);
                edit.setSingleLine(true);
                edit.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
                if (limit > 0) {
                    edit.setFilters(new InputFilter[] {new InputFilter.LengthFilter((int) Math.min(limit, 4096))});
                }
                write(edit, modelText == null ? "" : modelText);
                if (Boolean.TRUE.equals(Json.bool(ctl, "readonly"))) {
                    edit.setKeyListener(null);
                    edit.setFocusable(false);
                } else {
                    edit.addTextChangedListener(new TextWatcher() {
                        @Override
                        public void beforeTextChanged(CharSequence text, int start, int count, int after) {}

                        @Override
                        public void onTextChanged(CharSequence text, int start, int before, int count) {}

                        @Override
                        public void afterTextChanged(Editable text) {
                            if (!writing && drawnRev == rev && sink.edit(drawnRev, slot, text.toString())) {
                                sent.put(slot, sent.getOrDefault(slot, 0L) + 1);
                            }
                        }
                    });
                }
                edits.put(slot, edit);
                view = edit;
                break;
            }
            case "cred": {
                // Never the system keyboard (class doc): an empty box until the app keyboard exists.
                TextView box = new TextView(context);
                GradientDrawable shape = new GradientDrawable();
                shape.setStroke(dp(1), RULE);
                shape.setCornerRadius(dp(4));
                box.setBackground(shape);
                box.setMinHeight(dp(40));
                box.setFocusable(false);
                box.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
                view = box;
                on = false;
                break;
            }
            default:
                return null;
        }
        view.setEnabled(on);
        controls.put(slot, view);
        return view;
    }

    private View qr(long size, String bits) {
        boolean[] dark = UiWire.qrModules(size, bits);
        if (dark == null) {
            return null;
        }
        int modules = (int) size;
        View view = new View(context) {
            private final Paint ink = new Paint();

            @Override
            protected void onDraw(Canvas canvas) {
                canvas.drawColor(Color.WHITE);
                ink.setColor(Color.BLACK);
                float cell = (float) Math.min(getWidth(), getHeight()) / (modules + 8);
                for (int y = 0; y < modules; y++) {
                    for (int x = 0; x < modules; x++) {
                        if (dark[y * modules + x]) {
                            float left = (x + 4) * cell;
                            float top = (y + 4) * cell;
                            canvas.drawRect(left, top, left + cell, top + cell, ink);
                        }
                    }
                }
            }
        };
        int side = dp(240);
        LinearLayout wrap = new LinearLayout(context);
        wrap.setGravity(Gravity.CENTER_HORIZONTAL);
        wrap.addView(view, new LinearLayout.LayoutParams(side, side));
        return wrap;
    }
}
