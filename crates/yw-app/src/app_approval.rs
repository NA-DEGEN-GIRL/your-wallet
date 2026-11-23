//! The approval window A01 (spec/04 §3): `YourWalletV3Approval` (top-level, topmost, no owner)
//! with fixed header, simulation band and bottom bar, and a `YourWalletV3Panel` child for the
//! scrolling content. Input maps to `ApprovalInteraction` events (spec/04 §3.4 table), the gate is
//! re-armed on every event and 50 ms tick, and the EVM flow continues with `ApprovalStore::issue`
//! at first Ready display, re-simulation at click after 60 s (spec/03 §6.6), `consume` and
//! `SignEvm` on the key worker.
//!
//! The native window code follows `archive/spec-v2.4:crates/approval-ui/src/native.rs:40-1090`
//! (fixed 820×710 DIP client, minimum 520×460, click-through guard, 50 ms timer, explicit
//! approve/reject controls) on yw-win instead of `windows`, with the app's single message loop
//! and owner-drawn content instead of a read-only EDIT.

use std::collections::HashMap;

use yw_core::lang::Lang;
use yw_engine::approval::flow::{ApprovalEffect, ApprovalSignal, OpenOutcome, ShownId};
use yw_engine::cmd::Cmd;
use yw_win::ui::{
    Color, DrawFlags, Handler, Msg, PaintDc, Rect, Reply, Window, WindowKind, WindowSpec,
    create_window,
};

use crate::app::App;
use crate::ui::approval_input::{
    APPROVAL_TIMER_ID, BarHits, Facts, Focus, Mapped, Pressed, ScrollGoal, Step, Surface,
    TrustedSignals, map_msg, panel_click, panel_hit, tab_order, tab_target, wheel_delta,
    window_input,
};
use crate::ui::theme::{self, FontRole, Fonts, wide};
#[cfg(test)]
use yw_engine::approval::QueueOutcome;
#[cfg(test)]
use yw_engine::approval::interaction::InteractionEvent;
use yw_engine::approval::interaction::{
    APPROVAL_TICK_MS, HIGH_RISK_HOLD_MS, PrepareStage, PrepareState,
};
use yw_engine::approval::layout as text_layout;
use yw_engine::approval::text;
use yw_engine::approval::view::{ApprovalView, Block, Tone, escape_spans};
use yw_engine::badge::{BADGE_DIP, BADGE_GAP_DIP};
use yw_engine::errors::ErrorCode;
use yw_engine::explain::panel::{BODY_LINES, PANEL_TITLE, PanelLine, RETRY_LABEL, body_lines};
use yw_engine::wallet::app_approval::is_badge;
use yw_engine::wallet::approval_flow::{ApprovalFlow, ApprovalPaint};

/// Approval window class.
pub const APPROVAL_CLASS: &str = "YourWalletV3Approval";
/// Scrolling panel class.
pub const PANEL_CLASS: &str = "YourWalletV3Panel";
/// Extra window height (DIP) when the AI panel is reserved (spec/06 §6: ten body lines plus the
/// title row), so the core content area keeps the size it has without the panel.
const AI_PANEL_EXTRA_DIP: i32 = 240;
/// The AI explanation panel of one window (spec/06 §6, spec/04 §3.8): reserved when the window
/// opens, painted by the window (title, `다시 요청`) and by its own child (`body`, ten lines,
/// scrolled inside). Never focused and never an input of the gate. 2026-11-19 (S4 B4b): this is
/// the shell half, the body child and its scroll; the panel state, serial, host, model and kind
/// are the flow's `approval_flow::AiFlow` (before, one `AiUi` held both).
struct AiBody {
    body: Window,
    scroll: i32,
}

#[derive(Clone, Debug)]
struct Line {
    x: i32,
    y: i32,
    text: String,
    font: FontRole,
    color: Color,
    height: i32,
    /// The line ended at an LF of the value (an escaped `[U+000A]` right before it is the
    /// visible mark of that very line break).
    lf: bool,
}

#[derive(Clone, Debug, Default)]
struct PanelLayout {
    width: i32,
    lines: Vec<Line>,
    /// Rounded shapes (cards, warning boxes, tags, check boxes): rect, fill, outline, corner
    /// radius in pixels.
    rounds: Vec<(Rect, Color, Color, i32)>,
    /// Centered bold labels on shapes (status tags, check marks).
    tags: Vec<(Rect, String, Color)>,
    fills: Vec<(Rect, Color)>,
    frames: Vec<(Rect, Color)>,
    height: i32,
    ack: Option<Rect>,
    raw: Option<Rect>,
    accounts: Vec<(usize, Rect)>,
    /// The revision of the flow's view this layout was drawn from (2026-11-19, S4 B6, critique
    /// A-13): a connect toggle hit-tested here carries it.
    view_rev: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct Bottom {
    /// The whole bottom bar (status line and buttons): what a tick repaints.
    bar: Rect,
    approve: Rect,
    reject: Rect,
    retry: Option<Rect>,
    panel: Rect,
    ai_retry: Option<Rect>,
    ai_body: Rect,
}

/// What the bottom bar shows. The 50 ms tick repaints only the bar, and only when this changes
/// (the hold progress, the countdown second, the armed look), so the rest of the window is never
/// redrawn by the timer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct BarState {
    /// `남은 시간 m:ss · 대기 n건 · 상태 문구` (and the hold's seconds).
    status: String,
    /// The `남은 시간 m:ss` prefix of `status` is drawn in the caution color (30 s or less).
    urgent: Option<usize>,
    /// The user's next step, drawn on its own (bold, next to or above the buttons).
    step: Option<&'static str>,
    label: &'static str,
    armed: bool,
    /// Milliseconds held so far while a high-risk hold is under way.
    held_ms: Option<u64>,
    focus: Option<Focus>,
}

/// T-SIM-CHANGED (spec/04 §7): the fact, and what to do when no next step says it.
/// The status message on the status line: while a next step is shown, a message that also
/// says what to do (T-SIM-CHANGED, T-SIM-RESIM-FAILED, spec/04 §7) keeps only its fact (the step
/// says the rest, once).
fn status_fact(lang: Lang, message: &str, step_shown: bool) -> &str {
    if !step_shown {
        return message;
    }
    [text::SIM_CHANGED, text::SIM_RESIM_FAILED]
        .into_iter()
        .map(|fact| fact.get(lang))
        .find(|fact| message.starts_with(fact))
        .unwrap_or(message)
}

/// The bottom bar's texts (2026-11-19, S4 B3: what it shows apart from the text assembly — the
/// countdown facts, the hold progress, the next step (was `next_step` here), the button label and
/// its armed look — comes from `yw_engine::approval::flow::bar_facts`, moved from here unchanged).
/// (2026-11-19, S4 B4b: it reads the flow through the read model `ApprovalPaint` and the shell's
/// focus; was the whole `ApprovalUi`.)
fn bar_state(paint: &ApprovalPaint<'_>, focus: Focus, waiting: usize, now: u64) -> BarState {
    let lang = paint.lang;
    let facts = paint.bar(now);
    let held_ms = facts.held_ms;
    let step = facts.step.map(|step| step.get(lang));
    let mut status = String::new();
    let mut urgent = None;
    let part = |status: &mut String, text: &str| {
        if !status.is_empty() {
            status.push_str(" · ");
        }
        status.push_str(text);
    };
    if facts.countdown {
        status.push_str(&text::REMAINING.fill(lang, [&remaining_text(facts.remaining_ms)]));
        // The last 30 s are drawn in the caution color.
        urgent = facts.urgent.then_some(status.len());
    }
    if waiting > 0 {
        part(
            &mut status,
            &text::WAITING.fill(lang, [&waiting.to_string()]),
        );
    }
    if let Some(message) = paint.status {
        part(&mut status, status_fact(lang, message, step.is_some()));
    }
    if let Some(done) = held_ms {
        part(
            &mut status,
            &text::HELD.fill(
                lang,
                [
                    &(done / 1_000).to_string(),
                    &((done % 1_000) / 100).to_string(),
                ],
            ),
        );
    }
    BarState {
        status,
        urgent,
        step,
        label: facts.label.get(lang),
        armed: facts.armed,
        held_ms,
        focus: matches!(focus, Focus::Approve | Focus::Reject).then_some(focus),
    }
}

/// The open approval window's shell state (2026-11-19, S4 B4b, spec/15 §11.4 S4): the window,
/// its scrolling panel, the AI body and its scroll, the focus, the panel scroll, the pressed
/// button, the panel layout, the bottom bar's rectangles and last painted state, and the glyph
/// widths. It holds no gate: the flow state is `App.evm.approval` (`ApprovalFlow`), and the window
/// paints from its read model `ApprovalPaint`. Shown exactly while the flow is (`open_approval`
/// sets both, `close_approval_window` takes both). Before B4b, one `EvmUi.window: ApprovalUi` held
/// this state and the flow (B4a) or every field (before B4a). 2026-11-19 (S4 B5): made by the
/// `Effect::Approval(Open)` executor arm (`open_approval_window`) after the flow, which
/// `open_approval` makes first, and taken by the `Close` arm (`close_approval_shell`) right after
/// `close_approval_window` took the flow; `shown` is the flow's window id.
pub struct ApprovalWin {
    /// The flow's window id (S4 B5): an effect for another id leaves this window alone.
    shown: ShownId,
    window: Window,
    panel: Window,
    focus: Focus,
    scroll: i32,
    pressed: Option<Pressed>,
    layout: Option<PanelLayout>,
    bottom: Bottom,
    /// The bottom bar as last painted.
    bar: BarState,
    widths: HashMap<(FontRole, char), i32>,
    /// The AI body child, when the window reserved the AI panel (exactly when the flow has an
    /// `AiFlow`).
    ai: Option<AiBody>,
}

impl core::fmt::Debug for ApprovalWin {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ApprovalWin")
    }
}

impl ApprovalWin {
    /// The wide layout applies: the client area is at least 80 × 8 DIP wide (2026-11-19, S4 B5:
    /// the measure `rebuild_view_with` read itself before; now reported to the flow).
    fn is_wide(&self) -> bool {
        self.window.client_rect().w >= self.window.px(80 * 8)
    }
}

/// The window a `Forward` serves and the approval window it belongs to: the `ShownId` captured
/// when `open_approval_window` made it (2026-11-19, S4 B6, critique A-12). Its inputs carry that
/// id, never the id of the window shown when they arrive, so the flow drops an input of a window
/// that is no longer the shown one. Before B6 the target named the kind of window only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Approval(ShownId),
    Panel(ShownId),
    AiBody(ShownId),
}

impl Target {
    /// The kind of window.
    const fn surface(self) -> Surface {
        match self {
            Self::Approval(_) => Surface::Approval,
            Self::Panel(_) => Surface::Panel,
            Self::AiBody(_) => Surface::AiBody,
        }
    }

    /// The approval window it belongs to.
    const fn shown(self) -> ShownId {
        match self {
            Self::Approval(shown) | Self::Panel(shown) | Self::AiBody(shown) => shown,
        }
    }

    /// The window kind a dropped re-entrant message was meant for (S4 A5 trace).
    #[cfg(test)]
    const fn label(self) -> &'static str {
        match self {
            Self::Approval(_) => "approval",
            Self::Panel(_) => "panel",
            Self::AiBody(_) => "ai-body",
        }
    }
}

/// The window that got a message and the approval window it belongs to (2026-11-19, S4 B6,
/// critique A-12): what `Forward` hands to `on_surface_msg`. It derefs to the window, so the steps
/// that act on the window that got the message use it as before.
struct Received<'a> {
    window: &'a Window,
    shown: ShownId,
}

impl core::ops::Deref for Received<'_> {
    type Target = Window;

    fn deref(&self) -> &Window {
        self.window
    }
}

struct Forward {
    app: std::rc::Weak<std::cell::RefCell<App>>,
    target: Target,
}

impl Handler for Forward {
    fn on(&mut self, window: &Window, msg: &Msg) -> Reply {
        let Some(app) = self.app.upgrade() else {
            return Reply::Default;
        };
        let Ok(mut app) = app.try_borrow_mut() else {
            // 2026-11-18 (S4 A5, critique A-8): the cfg(test) trace records every message this
            // branch drops (or defers), so the re-entrancy golden `s4_flow/reentry.txt` pins it.
            #[cfg(test)]
            flow_support::log_input(flow_support::Logged::Dropped {
                target: self.target.label(),
                msg: *msg,
            });
            // A paint requested from inside another handler: owed, not dropped unpainted.
            if matches!(msg, Msg::Paint) {
                window.defer_paint();
                return Reply::Handled(0);
            }
            return Reply::Default;
        };
        // 2026-11-20 (S4 P10b, critique A-14): every entry drained before it returned.
        app.assert_outbox_empty();
        // 2026-11-19 (S4 B6, A-12): with the id the window was made for (before, the three
        // `on_*_msg` entries, whose inputs went to the window shown at the time).
        let received = Received {
            window,
            shown: self.target.shown(),
        };
        // 2026-11-20 (S4 P10b): `surface_entry` is `on_surface_msg`, then the drain.
        app.surface_entry(self.target.surface(), &received, msg)
    }
}

fn char_width(
    dc: &mut PaintDc<'_>,
    fonts: &Fonts,
    cache: &mut HashMap<(FontRole, char), i32>,
    role: FontRole,
    character: char,
) -> i32 {
    if let Some(width) = cache.get(&(role, character)) {
        return *width;
    }
    dc.select_font(fonts.get(role));
    let mut units = [0_u16; 2];
    let encoded = character.encode_utf16(&mut units);
    let width = dc.measure(encoded, i32::MAX).1;
    cache.insert((role, character), width);
    width
}

fn line_height(dc: &mut PaintDc<'_>, fonts: &Fonts, role: FontRole) -> i32 {
    dc.select_font(fonts.get(role));
    // WRAP, not LINE: DT_VCENTER with DT_CALCRECT on a zero-height rectangle halves the height.
    dc.measure_wrapped(&wide("가Ay"), 10_000, DrawFlags::WRAP)
        .max(1)
}

struct Builder<'a, 'd> {
    lang: Lang,
    dc: &'a mut PaintDc<'d>,
    fonts: &'a Fonts,
    cache: &'a mut HashMap<(FontRole, char), i32>,
    layout: PanelLayout,
    y: i32,
    margin: i32,
    dpi: u32,
    /// Content box: the window margin, or a card's padded inside.
    x: i32,
    w: i32,
    /// Open card: top and fill.
    card: Option<(i32, Color, Color)>,
    last_gap: i32,
}

impl Builder<'_, '_> {
    fn px(&self, dip: i32) -> i32 {
        yw_win::ui::scale(dip, self.dpi)
    }

    fn outer_w(&self) -> i32 {
        self.layout
            .width
            .saturating_sub(self.margin.saturating_mul(2))
            .max(40)
    }

    fn text(&mut self, text: &str, role: FontRole, color: Color, x: i32, width: i32) {
        // An address line (whole or in the display model's 4-character groups) is laid out
        // whole; `draw_line` emphasizes its ends (2026-11-12, spec/04 §3.3).
        let whole = (role == FontRole::Mono)
            .then(|| crate::ui::theme::whole_address(text))
            .flatten();
        let text = whole.as_ref().map_or(text, |(address, _)| address.as_str());
        let height = line_height(self.dc, self.fonts, role);
        for character in text.chars() {
            let _ = char_width(self.dc, self.fonts, self.cache, role, character);
        }
        let cache = &*self.cache;
        let lines = text_layout::layout(text, width, &|character| {
            cache.get(&(role, character)).copied().unwrap_or(0)
        });
        for line in lines {
            let slice = text.get(line.start..line.end).unwrap_or("");
            self.layout.lines.push(Line {
                x,
                y: self.y,
                text: slice.to_owned(),
                font: role,
                color,
                height,
                lf: line.brk == text_layout::Break::Newline,
            });
            self.y = self.y.saturating_add(height);
        }
        self.last_gap = 0;
    }

    fn gap(&mut self, dip: i32) {
        let gap = self.px(dip);
        self.y = self.y.saturating_add(gap);
        self.last_gap = gap;
    }

    /// Opens a card (closing any open one); its shape is sized when it closes.
    fn open_card(&mut self, fill: Color, border: Color) {
        self.close_card();
        self.card = Some((self.y, fill, border));
        let pad = self.px(14);
        self.x = self.margin.saturating_add(pad);
        self.w = self.outer_w().saturating_sub(pad.saturating_mul(2)).max(40);
        self.y = self.y.saturating_add(pad);
        self.last_gap = 0;
    }

    fn close_card(&mut self) {
        let Some((top, fill, border)) = self.card.take() else {
            return;
        };
        let pad = self.px(14);
        self.y = self.y.saturating_sub(self.last_gap).saturating_add(pad);
        let radius = self.px(theme::RADIUS_CARD);
        self.layout.rounds.insert(
            0,
            (
                Rect::new(self.margin, top, self.outer_w(), self.y.saturating_sub(top)),
                fill,
                border,
                radius,
            ),
        );
        self.x = self.margin;
        self.w = self.outer_w();
        self.gap(10);
    }

    fn boxed(&mut self, text: &str, tone: Tone) {
        let pad = self.px(10);
        let (fill, color, tag) = match tone {
            Tone::Danger => (
                theme::DANGER_BG,
                theme::DANGER_TEXT,
                Some((
                    text::LEVEL_HIGH.get(self.lang),
                    theme::DANGER_ACCENT,
                    theme::CARD,
                )),
            ),
            Tone::Blocked => (
                theme::BLOCKED_BG,
                theme::BLOCKED_TEXT,
                Some((
                    text::LEVEL_BLOCKED.get(self.lang),
                    theme::CARD,
                    theme::BLOCKED_BG,
                )),
            ),
            Tone::Warn => (
                theme::WARN_BG,
                theme::WARN_TEXT,
                Some((
                    text::LEVEL_CAUTION.get(self.lang),
                    theme::WARN_ACCENT,
                    theme::CARD,
                )),
            ),
            Tone::Plain => (
                theme::INFO_BG,
                theme::INFO_TEXT,
                Some((
                    text::LEVEL_INFO.get(self.lang),
                    theme::INFO_ACCENT,
                    theme::CARD,
                )),
            ),
        };
        let top = self.y;
        let tag_h = self.px(22);
        let tag_w = tag.map_or(0, |(label, _, _)| {
            self.dc.select_font(&self.fonts.body_bold);
            self.dc
                .measure(&wide(label), i32::MAX)
                .1
                .saturating_add(self.px(16))
                .max(self.px(44))
        });
        let text_x = self
            .x
            .saturating_add(pad)
            .saturating_add(tag_w)
            .saturating_add(self.px(10));
        let text_w = self
            .w
            .saturating_sub(pad.saturating_mul(2))
            .saturating_sub(tag_w)
            .saturating_sub(self.px(10));
        self.y = self.y.saturating_add(pad);
        let text_top = self.y;
        self.text(text, FontRole::Body, color, text_x, text_w);
        self.y = self
            .y
            .max(text_top.saturating_add(tag_h))
            .saturating_add(pad);
        let radius = self.px(theme::RADIUS_CONTROL);
        self.layout.rounds.push((
            Rect::new(self.x, top, self.w, self.y.saturating_sub(top)),
            fill,
            fill,
            radius,
        ));
        if let Some((label, tag_fill, tag_text)) = tag {
            let tag_rect = Rect::new(self.x.saturating_add(pad), text_top, tag_w, tag_h);
            self.layout
                .rounds
                .push((tag_rect, tag_fill, tag_fill, tag_h / 2));
            self.layout
                .tags
                .push((tag_rect, label.to_owned(), tag_text));
        }
        self.gap(8);
    }
}

#[expect(clippy::too_many_lines, reason = "one arm per content block kind")]
fn build_layout(
    dc: &mut PaintDc<'_>,
    fonts: &Fonts,
    cache: &mut HashMap<(FontRole, char), i32>,
    view: &ApprovalView,
    width: i32,
    dpi: u32,
    ack_checked: bool,
) -> PanelLayout {
    let margin = yw_win::ui::scale(16, dpi);
    let mut builder = Builder {
        lang: view.lang,
        dc,
        fonts,
        cache,
        layout: PanelLayout {
            width,
            ..PanelLayout::default()
        },
        y: margin,
        margin,
        dpi,
        x: margin,
        w: width.saturating_sub(margin.saturating_mul(2)).max(40),
        card: None,
        last_gap: 0,
    };
    for block in &view.blocks {
        match block {
            Block::Summary {
                sentence,
                address,
                notes,
                title,
                remark,
            } => {
                builder.open_card(theme::INFO_BG, theme::INFO_ACCENT);
                let (x, w) = (builder.x, builder.w);
                let summary = text::SUMMARY.get(builder.lang);
                builder.text(summary, FontRole::Caption, theme::INFO_TEXT, x, w);
                builder.gap(2);
                builder.text(sentence, FontRole::ApprovalTitle, theme::TEXT, x, w);
                if let Some(address) = address {
                    builder.gap(6);
                    builder.text(address, FontRole::Mono, theme::TEXT, x, w);
                    if !notes.is_empty() {
                        builder.text(notes, FontRole::Caption, theme::INFO_TEXT, x, w);
                    }
                }
                builder.gap(6);
                builder.text(title, FontRole::Caption, theme::MUTED, x, w);
                if let Some(remark) = remark {
                    builder.gap(4);
                    builder.text(remark, FontRole::Caption, theme::MUTED, x, w);
                }
                builder.close_card();
            }
            Block::Subheading(text) => {
                let (x, w) = (builder.x, builder.w);
                if builder.last_gap == 0 {
                    builder.gap(4);
                }
                builder.text(text, FontRole::BodyBold, theme::INFO_TEXT, x, w);
                builder.gap(4);
            }
            Block::Title(text) => {
                let (x, w) = (builder.x, builder.w);
                builder.text(text, FontRole::ApprovalTitle, theme::TEXT, x, w);
                builder.gap(10);
            }
            Block::Warning { text, tone } => builder.boxed(text, *tone),
            Block::Ack => {
                let size = builder.px(18);
                let top = builder.y;
                let (x, w) = (builder.x, builder.w);
                let rect = Rect::new(x, top, size, size);
                let corner = builder.px(3);
                builder.layout.rounds.push((
                    rect,
                    if ack_checked {
                        theme::FOCUS
                    } else {
                        theme::CARD
                    },
                    if ack_checked {
                        theme::FOCUS
                    } else {
                        theme::TEXT
                    },
                    corner,
                ));
                if ack_checked {
                    builder
                        .layout
                        .tags
                        .push((rect, "✓".to_owned(), theme::PRIMARY_TEXT));
                }
                builder.text(
                    text::ACK.get(builder.lang),
                    FontRole::BodyBold,
                    theme::TEXT,
                    x.saturating_add(size).saturating_add(builder.px(8)),
                    w.saturating_sub(size),
                );
                builder.layout.ack = Some(Rect::new(
                    x,
                    top,
                    w,
                    builder.y.saturating_sub(top).max(size),
                ));
                builder.gap(10);
            }
            Block::Section(title) => {
                builder.open_card(theme::CARD, theme::CARD_BORDER);
                let (x, w) = (builder.x, builder.w);
                builder.text(title, FontRole::Subtitle, theme::TEXT, x, w);
                builder.gap(8);
            }
            Block::Field { label, value, mono } => {
                let (x, w) = (builder.x, builder.w);
                builder.text(label, FontRole::Caption, theme::MUTED, x, w);
                let role = if *mono {
                    if label.starts_with("calldata") {
                        FontRole::MonoSmall
                    } else {
                        FontRole::Mono
                    }
                } else {
                    FontRole::Body
                };
                builder.gap(2);
                let has_address = value.split('\n').any(|line| {
                    crate::ui::theme::address_with_notes(line).is_some()
                        || (!*mono && crate::ui::theme::whole_address(line).is_some())
                });
                if has_address {
                    // Addresses on their own lines of a text field (the SPL mint and token
                    // accounts of `0x0502`) are drawn like address fields, and an address with
                    // its notes (`0x… [일반 계정(EOA)]`) is drawn whole with the notes on the
                    // next line (spec/04 §3.3, 2026-11-14).
                    for line in value.split('\n') {
                        if let Some((address, notes)) = crate::ui::theme::address_with_notes(line) {
                            builder.text(address, FontRole::Mono, theme::TEXT, x, w);
                            builder.text(notes, FontRole::Body, theme::TEXT, x, w);
                            continue;
                        }
                        let line_role = if crate::ui::theme::whole_address(line).is_some() {
                            FontRole::Mono
                        } else {
                            role
                        };
                        builder.text(line, line_role, theme::TEXT, x, w);
                    }
                } else {
                    builder.text(value, role, theme::TEXT, x, w);
                }
                builder.gap(10);
            }
            Block::Muted(text) => {
                let (x, w) = (builder.x, builder.w);
                builder.text(text, FontRole::Body, theme::MUTED, x, w);
                builder.gap(6);
            }
            Block::RawToggle { open } => {
                builder.close_card();
                let top = builder.y;
                let (x, w) = (builder.x, builder.w);
                let toggle = if *open {
                    text::DETAILS_OPEN
                } else {
                    text::DETAILS_CLOSED
                };
                builder.text(
                    toggle.get(builder.lang),
                    FontRole::BodyBold,
                    theme::FOCUS,
                    x,
                    w,
                );
                builder.layout.raw = Some(Rect::new(x, top, w, builder.y.saturating_sub(top)));
                builder.gap(8);
                if *open {
                    builder.open_card(theme::CARD, theme::CARD_BORDER);
                }
            }
            Block::Notice(text) => {
                builder.gap(20);
                let (x, w) = (builder.x, builder.w);
                builder.text(text, FontRole::BodyBold, theme::FOCUS, x, w);
            }
            Block::Account {
                index,
                label,
                address,
                checked,
            } => {
                let size = builder.px(18);
                let top = builder.y;
                let (x0, w0) = (builder.x, builder.w);
                let rect = Rect::new(x0, top, size, size);
                let corner = builder.px(3);
                builder.layout.rounds.push((
                    rect,
                    if *checked { theme::FOCUS } else { theme::CARD },
                    if *checked { theme::FOCUS } else { theme::TEXT },
                    corner,
                ));
                if *checked {
                    builder
                        .layout
                        .tags
                        .push((rect, "✓".to_owned(), theme::PRIMARY_TEXT));
                }
                let x = x0.saturating_add(size).saturating_add(builder.px(8));
                let width = w0.saturating_sub(size).saturating_sub(builder.px(8));
                // The name (with why it cannot sign), then its source and path muted.
                let mut lines = label.split('\n');
                builder.text(
                    lines.next().unwrap_or(""),
                    FontRole::BodyBold,
                    theme::TEXT,
                    x,
                    width,
                );
                for detail in lines {
                    builder.text(detail, FontRole::Caption, theme::MUTED, x, width);
                }
                let shown = yw_core::evm::address::parse_address(address)
                    .map_or_else(|_| address.clone(), yw_core::evm::Address::to_checksum);
                builder.text(&shown, FontRole::Mono, theme::TEXT, x, width);
                builder.layout.accounts.push((
                    *index,
                    Rect::new(x0, top, w0, builder.y.saturating_sub(top).max(size)),
                ));
                builder.gap(8);
            }
        }
    }
    builder.close_card();
    builder.layout.height = builder.y.saturating_add(margin);
    builder.layout
}

fn draw_line(
    dc: &mut PaintDc<'_>,
    fonts: &Fonts,
    line: &Line,
    offset_y: i32,
    widths: &HashMap<(FontRole, char), i32>,
) {
    if line.font == FontRole::Mono
        && let Some(spans) = crate::ui::theme::address_spans(&line.text)
    {
        let rect = Rect::new(
            line.x,
            line.y.saturating_sub(offset_y),
            i32::MAX / 4,
            line.height,
        );
        if crate::ui::theme::paint_spans(dc, fonts, &spans, rect, line.color, theme::FOCUS) {
            return;
        }
    }
    dc.select_font(fonts.get(line.font));
    let spans = escape_spans(&line.text);
    let mut x = line.x;
    let mut cursor = 0_usize;
    let draw = |dc: &mut PaintDc<'_>, segment: &str, color: Color, x: &mut i32| {
        if segment.is_empty() {
            return;
        }
        let width: i32 = segment
            .chars()
            .map(|character| widths.get(&(line.font, character)).copied().unwrap_or(0))
            .sum();
        dc.set_text_color(color);
        dc.draw_text(
            &wide(segment),
            Rect::new(
                *x,
                line.y.saturating_sub(offset_y),
                width.saturating_add(4),
                line.height,
            ),
            DrawFlags::LINE,
        );
        *x = x.saturating_add(width);
    };
    for (start, end) in spans {
        draw(
            dc,
            line.text.get(cursor..start).unwrap_or(""),
            line.color,
            &mut x,
        );
        // An escaped LF right before the real line break only marks that break: muted, so the
        // marks of other characters keep their warning color (2026-11-10).
        let marker = line.text.get(start..end).unwrap_or("");
        let color = if line.lf && end == line.text.len() && marker == "[U+000A]" {
            theme::MUTED
        } else {
            theme::ESCAPE_TEXT
        };
        draw(dc, marker, color, &mut x);
        cursor = end;
    }
    draw(
        dc,
        line.text.get(cursor..).unwrap_or(""),
        line.color,
        &mut x,
    );
}

#[cfg(test)]
thread_local! {
    /// Render harness only (`smoke`): treat A01 as the foreground window, since a test process
    /// usually may not take the foreground.
    pub(crate) static TEST_FORCE_FOREGROUND: core::cell::Cell<bool> =
        const { core::cell::Cell::new(false) };
    /// The surfaces `approval_repaint_ai` invalidated, in order (`"ai-body"`, `"a01"`), while a
    /// test records them (`Some`); `None`: not recording (2026-11-22, S4 W14ab review).
    pub(crate) static TEST_AI_REPAINTS: core::cell::RefCell<Option<Vec<&'static str>>> =
        const { core::cell::RefCell::new(None) };
}

/// Records one invalidation of `approval_repaint_ai` while a test records them.
#[cfg(test)]
fn trace_ai_repaint(surface: &'static str) {
    TEST_AI_REPAINTS.with(|log| {
        if let Some(log) = log.borrow_mut().as_mut() {
            log.push(surface);
        }
    });
}

// The Win32 side effects of A01 (spec/04 §3.4) go through the small functions below, each a
// plain call in release builds. 2026-11-18 (S4 A3, spec/15 §11.4 S4): under `cfg(test)` every
// call is traced with its program point (`flow_support`); a hidden test host skips the calls that
// could show or activate a window. 2026-11-19 (S4 B2): the trusted-signal reads that were here
// (`window_is_foreground`, `raw_foreground`, `key_down`, `enter_in_message`, `injected_input`)
// are `ui::approval_input::TrustedSignals::sample*`, their only readers (source check S2), with
// the same scripted oracle under `cfg(test)`.

fn show_window(window: &Window) {
    #[cfg(test)]
    if flow_support::effect(flow_support::Fx::Show) {
        return;
    }
    window.show();
}

fn center_window(window: &Window, anchor: Option<&Window>) {
    #[cfg(test)]
    if flow_support::effect(flow_support::Fx::CenterOn) {
        return;
    }
    window.center_on(anchor);
}

/// `SetForegroundWindow` on A01 or (`of == "main"`) the main window.
#[cfg_attr(
    not(test),
    expect(unused_variables, reason = "`of` labels the cfg(test) trace only")
)]
fn request_foreground(window: &Window, of: &'static str) -> bool {
    #[cfg(test)]
    if let Some(done) = flow_support::foreground_request(of) {
        return done;
    }
    window.set_foreground()
}

fn flash_window(window: &Window) {
    #[cfg(test)]
    if flow_support::effect(flow_support::Fx::Flash) {
        return;
    }
    window.flash();
}

fn focus_window(window: &Window) {
    #[cfg(test)]
    if flow_support::effect(flow_support::Fx::SetFocus) {
        return;
    }
    window.set_focus();
}

fn capture_mouse(window: &Window) {
    #[cfg(test)]
    if flow_support::effect(flow_support::Fx::SetCapture) {
        return;
    }
    window.set_capture();
}

fn release_mouse(window: &Window) {
    #[cfg(test)]
    if flow_support::effect(flow_support::Fx::ReleaseCapture) {
        return;
    }
    window.release_capture();
}

fn remaining_text(ms: u64) -> String {
    let seconds = ms / 1_000;
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

/// One header badge pill as painted.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Pill {
    text: String,
    rect: Rect,
    fill: Color,
    border: Color,
    color: Color,
}

/// The colors of a header badge: the mainnet badge (EVM and Solana mainnets, `HyperCore`
/// mainnet) is filled with `DANGER_ACCENT` and lettered white like the 고위험 tag, so a
/// real-asset window stands out at least as much as a testnet one; every other badge keeps the
/// white pill.
fn badge_colors(badge: &str) -> (Color, Color, Color) {
    if is_badge(badge, text::BADGE_MAINNET) {
        (theme::DANGER_ACCENT, theme::DANGER_ACCENT, theme::CARD)
    } else {
        (theme::CARD, theme::CARD_BORDER, theme::TEXT)
    }
}

/// Header badge pitch (DIP): a 24 DIP pill and its gap.
const BADGE_ROW_DIP: i32 = 30;

/// Lays the header badges out from `(left, top)` in rows of `width` pixels: each pill is its
/// measured text plus 20 DIP (never wider than a row), 8 DIP apart, and a pill that does not fit
/// the rest of a row starts the next one — none is dropped. Returns the pills and the row count.
fn layout_badges(
    badges: &[String],
    left: i32,
    top: i32,
    width: i32,
    px: &dyn Fn(i32) -> i32,
    measure: &mut dyn FnMut(&str) -> i32,
) -> (Vec<Pill>, i32) {
    let mut pills = Vec::with_capacity(badges.len());
    let (mut x, mut row) = (left, 0_i32);
    for badge in badges {
        let w = measure(badge).saturating_add(px(20)).min(width.max(1));
        if x > left && x.saturating_add(w) > left.saturating_add(width) {
            row = row.saturating_add(1);
            x = left;
        }
        let (fill, border, color) = badge_colors(badge);
        pills.push(Pill {
            text: badge.clone(),
            rect: Rect::new(
                x,
                top.saturating_add(row.saturating_mul(px(BADGE_ROW_DIP))),
                w,
                px(24),
            ),
            fill,
            border,
            color,
        });
        x = x.saturating_add(w).saturating_add(px(8));
    }
    let rows = if pills.is_empty() {
        0
    } else {
        row.saturating_add(1)
    };
    (pills, rows)
}

/// The bottom bar's layout (spec/04 §3.2 하단, 2026-11-10). The status line (`남은 시간 m:ss ·
/// 대기 n건 · 상태 문구`) wraps at the full width; the next step is bold text to the left of the
/// buttons, two lines at most — or, where that space is narrower than 260 DIP (or would need a
/// third line), on its own row above the buttons; the buttons stay at the bottom right. The bar
/// grows with its lines and the content area shrinks by as much. Pure: measured character widths
/// in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct BarLayout {
    /// Bar height.
    height: i32,
    /// Status lines `(y, text)`, `y` from the bar top.
    status: Vec<(i32, String)>,
    /// Next-step lines `(y, text)`, `y` from the bar top.
    step: Vec<(i32, String)>,
    /// The next step's left edge and width.
    step_x: i32,
    step_w: i32,
    /// `승인` and `거부`, `y` from the bar top.
    approve: Rect,
    reject: Rect,
}

/// What [`bar_layout`] measures with.
struct BarMetrics<'a> {
    px: &'a dyn Fn(i32) -> i32,
    status_line: i32,
    step_line: i32,
    status_char: &'a dyn Fn(char) -> i32,
    step_char: &'a dyn Fn(char) -> i32,
}

fn wrap_lines(text: &str, width: i32, char_width: &dyn Fn(char) -> i32) -> Vec<String> {
    text_layout::layout(text, width.max(1), char_width)
        .into_iter()
        .map(|line| text.get(line.start..line.end).unwrap_or("").to_owned())
        .collect()
}

fn bar_layout(
    client_w: i32,
    status: &str,
    step: Option<&str>,
    metrics: &BarMetrics<'_>,
) -> BarLayout {
    let px = metrics.px;
    let margin = px(16);
    let gap = px(12);
    let button_h = px(40);
    let width = client_w
        .saturating_sub(margin.saturating_mul(2))
        .max(px(100));
    let mut layout = BarLayout::default();
    let mut y = px(10);
    if !status.is_empty() {
        for line in wrap_lines(status, width, metrics.status_char) {
            layout.status.push((y, line));
            y = y.saturating_add(metrics.status_line);
        }
    }
    let approve_x = client_w.saturating_sub(margin).saturating_sub(px(220));
    let reject_x = approve_x.saturating_sub(gap).saturating_sub(px(140));
    let free = reject_x.saturating_sub(gap).saturating_sub(margin);
    let narrow = free < px(260);
    let mut beside: Vec<String> = Vec::new();
    let side = step
        .filter(|_| !narrow)
        .map(|step| wrap_lines(step, free, metrics.step_char))
        .filter(|lines| lines.len() <= 2);
    if let Some(lines) = side {
        beside = lines;
        layout.step_x = margin;
        layout.step_w = free;
    } else if step.is_some() || narrow {
        // Its own row above the buttons. A narrow window keeps two lines for it even without a
        // step, so the content does not jump when a step comes or goes (the arm delay, a hold).
        y = y.saturating_add(px(4));
        layout.step_x = margin;
        layout.step_w = width;
        let lines = step.map_or_else(Vec::new, |step| wrap_lines(step, width, metrics.step_char));
        let reserved = if narrow {
            lines.len().max(2)
        } else {
            lines.len()
        };
        for line in lines {
            layout.step.push((y, line));
            y = y.saturating_add(metrics.step_line);
        }
        let shown = layout.step.len();
        y = y.saturating_add(
            metrics
                .step_line
                .saturating_mul(i32::try_from(reserved.saturating_sub(shown)).unwrap_or(0)),
        );
    }
    let buttons_y = y.saturating_add(px(8));
    layout.height = buttons_y
        .saturating_add(button_h)
        .saturating_add(margin)
        .max(px(96));
    let buttons_y = layout
        .height
        .saturating_sub(margin)
        .saturating_sub(button_h);
    layout.approve = Rect::new(approve_x, buttons_y, px(220), button_h);
    layout.reject = Rect::new(reject_x, buttons_y, px(140), button_h);
    if !beside.is_empty() {
        let lines = i32::try_from(beside.len()).unwrap_or(2);
        let block = metrics.step_line.saturating_mul(lines);
        let mut top = buttons_y.saturating_add(button_h.saturating_sub(block) / 2);
        for line in beside {
            layout.step.push((top, line));
            top = top.saturating_add(metrics.step_line);
        }
    }
    layout
}

impl App {
    // ----- the approval window (shell) ----------------------------------------------------

    /// Applies one `Effect::Approval` (S4 B5), called by the executor `App::drain` in emission
    /// order when the entry that emitted it drains. Returns the open's answer, which the drain
    /// hands to the logic before it applies the next effect. (2026-11-20, S4 P10b: before, called
    /// by `App::emit` at once, which fed the answer back before `emit` returned.)
    pub(crate) fn apply_approval_effect(&mut self, effect: ApprovalEffect) -> Option<Cmd> {
        // 2026-11-20 (S4 B7): the headless approval host of the tests records the effect and
        // answers an open itself (no window); release builds have no such line.
        #[cfg(test)]
        if headless_host::installed() {
            return headless_host::record(
                effect,
                self.evm.approval.as_ref().map(ApprovalFlow::shown),
            );
        }
        match effect {
            ApprovalEffect::Open {
                shown,
                lang,
                ai_reserved,
                connect,
            } => {
                let (outcome, wide) = self.open_approval_window(shown, lang, ai_reserved, connect);
                Some(Cmd::ApprovalOpened {
                    shown,
                    outcome,
                    wide,
                })
            }
            ApprovalEffect::Close { shown } => {
                self.close_approval_shell(shown);
                None
            }
            ApprovalEffect::Rebuilt { shown, changed } => {
                self.approval_rebuilt(shown, changed);
                None
            }
            ApprovalEffect::RepaintBar { shown } => {
                self.approval_repaint_bar(shown);
                None
            }
            ApprovalEffect::Redraw { shown } => {
                self.approval_redraw(shown);
                None
            }
            ApprovalEffect::RepaintAi { shown, body_only } => {
                self.approval_repaint_ai(shown, body_only);
                None
            }
        }
    }

    /// `Effect::Approval(Open)`: A01 (topmost), its panel and, when reserved, the AI body, in this
    /// order; then centred on the main window, the 50 ms timer, shown, brought to the foreground
    /// or flashed, focus on `거부` (reject-first), and the width class measured. Any window that
    /// cannot be made drops the ones made before it (panel before A01, as before) and the open
    /// answers `Failed(E-APP-009)`. 2026-11-19 (S4 B5): this was the window part of
    /// `open_approval`, the same calls in the same order (the flow, made there before B5 between
    /// the AI body and the centring, is now made before the open is asked for). 2026-11-19 (S4 B5
    /// review, critique A-3): an open for a `shown` that is no longer the current flow's makes
    /// nothing and answers `Failed(E-APP-009)` (the answer is then dropped as stale). 2026-11-20
    /// (S4 P10b): this happens when the flow ended in the same entry before it drained (an open,
    /// then a lock: `open_then_lock_same_entry`, owner decision 2026-11-20); before, effects were
    /// applied at once, the open ran right after its flow was stored and this never happened.
    fn open_approval_window(
        &mut self,
        shown: ShownId,
        lang: Lang,
        ai_reserved: bool,
        connect: bool,
    ) -> (OpenOutcome, bool) {
        const FAILED: (OpenOutcome, bool) = (OpenOutcome::Failed(ErrorCode::App009), false);
        if self.evm.approval.as_ref().map(ApprovalFlow::shown) != Some(shown) {
            return FAILED;
        }
        // 2026-11-19 (S4 B6, A-12): each window's `Forward` keeps the id it was made for.
        let handler = Box::new(Forward {
            app: self.self_ref.clone(),
            target: Target::Approval(shown),
        });
        let title = if connect {
            text::TITLE_CONNECT
        } else {
            text::TITLE_APPROVAL
        }
        .get(lang);
        let extra = if ai_reserved { AI_PANEL_EXTRA_DIP } else { 0 };
        let spec = WindowSpec::new(APPROVAL_CLASS, WindowKind::Floating)
            .title(title)
            .size(820, 710 + extra)
            .min_size(520, 460 + extra)
            .topmost(true)
            .resizable(true);
        #[cfg(test)]
        if flow_support::fail_open() {
            return FAILED;
        }
        let Ok(window) = create_window(&spec, handler) else {
            return FAILED;
        };
        let panel_handler = Box::new(Forward {
            app: self.self_ref.clone(),
            target: Target::Panel(shown),
        });
        let panel_spec = WindowSpec::new(
            PANEL_CLASS,
            WindowKind::Child {
                parent: window.hwnd(),
            },
        )
        .visible(true);
        let Ok(panel) = create_window(&panel_spec, panel_handler) else {
            return FAILED;
        };
        let ai = if ai_reserved {
            let body_handler = Box::new(Forward {
                app: self.self_ref.clone(),
                target: Target::AiBody(shown),
            });
            let body_spec = WindowSpec::new(
                PANEL_CLASS,
                WindowKind::Child {
                    parent: window.hwnd(),
                },
            )
            .visible(true);
            let Ok(body) = create_window(&body_spec, body_handler) else {
                return FAILED;
            };
            Some(AiBody { body, scroll: 0 })
        } else {
            None
        };
        center_window(&window, self.main.as_ref());
        let _ = window.set_timer(APPROVAL_TIMER_ID, APPROVAL_TICK_MS);
        show_window(&window);
        if !request_foreground(&window, "approval") {
            flash_window(&window);
        }
        focus_window(&window);
        let win = ApprovalWin {
            shown,
            window,
            panel,
            focus: Focus::Reject,
            scroll: 0,
            pressed: None,
            layout: None,
            bottom: Bottom::default(),
            bar: BarState::default(),
            widths: HashMap::new(),
            ai,
        };
        let wide = win.is_wide();
        // 2026-11-19 (S4 B4b): the shell state is `App.approval_win` (the flow `EvmUi.approval`,
        // one `EvmUi.window` before).
        self.approval_win = Some(win);
        (
            OpenOutcome::Shown {
                capture_excluded: false,
            },
            wide,
        )
    }

    /// `Effect::Approval(Close)`: the AI body, the timer, the panel and the window go, then the
    /// main window is raised. Nothing for a window that is not open under `shown` (one never made,
    /// critique A-3). 2026-11-19 (S4 B5): the window part of `close_approval_window`, same order.
    fn close_approval_shell(&mut self, shown: ShownId) {
        let Some(mut win) = self.approval_win.take_if(|win| win.shown == shown) else {
            return;
        };
        drop(win.ai.take());
        win.window.kill_timer(APPROVAL_TIMER_ID);
        drop(win.panel);
        drop(win.window);
        if let Some(main) = self.main.as_ref()
            && main.is_alive()
        {
            let _ = request_foreground(main, "main");
        }
    }

    /// `Effect::Approval(Rebuilt)`: a changed view drops the layout and invalidates the window,
    /// the panel and the AI body (S4 B5: was inline in `rebuild_view_with`).
    fn approval_rebuilt(&mut self, shown: ShownId, changed: bool) {
        if !changed {
            return;
        }
        if let Some(win) = self.approval_win.as_mut().filter(|win| win.shown == shown) {
            win.layout = None;
            win.window.invalidate();
            win.panel.invalidate();
            if let Some(ai) = win.ai.as_ref() {
                ai.body.invalidate();
            }
        }
    }

    /// `Effect::Approval(RepaintBar)`: the whole window while the bar was never laid out, else the
    /// bar's rectangle when what it shows changed (S4 B5: was inline in `interaction()`).
    fn approval_repaint_bar(&mut self, shown: ShownId) {
        let waiting = self.evm.queue.len().saturating_sub(1);
        if let (Some(flow), Some(win)) = (self.evm.approval.as_ref(), self.approval_win.as_ref())
            && win.shown == shown
        {
            if win.bottom.bar.w <= 0 {
                win.window.invalidate();
            } else if bar_state(&flow.paint(), win.focus, waiting, self.clock.now_ms()) != win.bar {
                win.window.invalidate_rect(win.bottom.bar);
            }
        }
    }

    /// `Effect::Approval(Redraw)`: the acknowledgement checkbox changed; the layout is dropped and
    /// the panel, the window and the AI body (a High-risk request's AI panel waits for the
    /// checkbox, `held_for_ack`) are invalidated, in this order. Nothing for a window that is not
    /// open under `shown`. (2026-11-19, S4 B6: was inline in `toggle_ack`.)
    fn approval_redraw(&mut self, shown: ShownId) {
        if let Some(win) = self.approval_win.as_mut().filter(|win| win.shown == shown) {
            win.layout = None;
            win.panel.invalidate();
            win.window.invalidate();
            if let Some(ai) = win.ai.as_ref() {
                ai.body.invalidate();
            }
        }
    }

    /// `Effect::Approval(RepaintAi)`: the AI body (when the window has one), then, unless
    /// `body_only`, the window, are invalidated. Nothing for a window that is not open under
    /// `shown`. (2026-11-22, S4 W14a: was inline in `ai_after` — the AI body then A01 of the
    /// window open then — and in `ai_tick` — the AI body alone; both now emit it.)
    /// 2026-11-22 (S4 W14ab review): test builds record each invalidation in
    /// [`TEST_AI_REPAINTS`] (a hidden window gets no update region, so Win32 cannot show it);
    /// the winui test `input_tests::the_ai_repaint_reaches_only_its_window` reads it.
    fn approval_repaint_ai(&self, shown: ShownId, body_only: bool) {
        if let Some(win) = self.approval_win.as_ref().filter(|win| win.shown == shown) {
            if let Some(ai) = win.ai.as_ref() {
                ai.body.invalidate();
                #[cfg(test)]
                trace_ai_repaint("ai-body");
            }
            if !body_only {
                win.window.invalidate();
                #[cfg(test)]
                trace_ai_repaint("a01");
            }
        }
    }

    /// The flow (`EvmUi.approval`) and the window's shell state (`App.approval_win`) are set and
    /// taken together (2026-11-19, S4 B4 review). Test builds check it where they change and
    /// where a window event reaches the flow, so a flow left without its window (or a window
    /// without its flow) fails the tests: the recorders print both cases like a closed window.
    /// 2026-11-19 (S4 B5): checked at the end of the open's answer (was the end of
    /// `open_approval`), and kept here because the flow-only functions name no window.
    /// 2026-11-20 (S4 B7): under the headless approval host there is never a window
    /// (`headless_host`), so the check is that none was made.
    /// 2026-11-20 (S4 P10b): only while no effect is queued — with the outbox the flow's open or
    /// close is ahead of the window until the entry drains (the queued `Approval(Open)` or
    /// `Approval(Close)`). 2026-11-20 (S4 P10b review): so `App::drain` also checks it when the
    /// queue is empty; before, the checks after an open's answer and after a close (both right
    /// after an `emit`) were skipped and nothing checked the pairing after those transitions.
    /// 2026-11-22 (S4 W14a, preflight critic C5): the flow's fns `on_approval_opened` and
    /// `close_approval_window` no longer call it (wallet code names no shell fn, so W14c can
    /// make them `impl Wallet`); `App::drain` checks those transitions. 2026-11-22 (S4 W14b):
    /// nor does `on_approval_input`; the shell's senders of a window's input (`window_event`,
    /// `window_signal`) check it right before they send it, where that fn checked it first.
    #[cfg(test)]
    pub(crate) fn assert_flow_and_window_in_step(&self) {
        if headless_host::installed() {
            assert!(
                self.approval_win.is_none(),
                "the headless approval host made a window"
            );
            return;
        }
        if self.queued_effects() > 0 {
            return;
        }
        assert_eq!(
            self.evm.approval.is_some(),
            self.approval_win.is_some(),
            "the approval flow and its window are out of step"
        );
    }

    // ----- window messages ----------------------------------------------------------------

    /// An interaction event of the window `shown` (2026-11-19, S4 B6; the window half of the
    /// former `interaction()`): the gate's foreground sample of that A01, taken before the event,
    /// then the input as `Cmd::Approval` (`signal`: the event itself, or the close box, whose
    /// event is `RejectActivated`). Without an open window of that id there is no sample and the
    /// input goes with `foreground: false` (2026-11-20, S4 B6 review: this comment said the flow
    /// then drops it). The flow drops it when the id is not the shown flow's (the window ended,
    /// or none is open); a flow of that id without its window (the pairing test builds assert in
    /// `assert_flow_and_window_in_step`) gets the event with `false`, which never makes the gate
    /// foreground, where `interaction()` before B6 dropped the event without a window.
    /// `shown` is the id of the window that got the message (`Received`), never the window shown
    /// now.
    fn window_event(&mut self, shown: Option<ShownId>, signal: ApprovalSignal) {
        // A false → true edge (activation, also within this process) restarts the arm delay.
        // The gate's foreground sample, taken before the event (2026-11-19, S4 B2: through
        // `TrustedSignals`, was `window_is_foreground`; B2 review: a getter, the field is private).
        let sample = self
            .approval_win
            .as_ref()
            .filter(|win| Some(win.shown) == shown)
            .map(|win| {
                (
                    TrustedSignals::sample_foreground(&win.window).foreground(),
                    win.focus,
                )
            });
        #[cfg(test)]
        flow_support::log_input(flow_support::Logged::Event {
            event: match signal {
                ApprovalSignal::Event(event) => event,
                _ => InteractionEvent::RejectActivated,
            },
            foreground: sample.map(|(foreground, _)| foreground),
            focus: sample.map(|(_, focus)| focus),
        });
        if let Some(shown) = shown {
            let foreground = sample.is_some_and(|(foreground, _)| foreground);
            // Tests: the flow and its window are in step when a window's input reaches the flow
            // (2026-11-22, S4 W14b, critic C5: was the first step of `on_approval_input`, a flow
            // fn, which names no shell fn since W14b).
            #[cfg(test)]
            self.assert_flow_and_window_in_step();
            // 2026-11-20 (S4 P10b): through `dispatch`, which drains, so the message's next step
            // runs after this input's effects and their answers, as before.
            self.dispatch(Cmd::Approval(window_input(shown, foreground, signal)));
        }
    }

    /// An input of the window `shown` that is not an interaction event (2026-11-19, S4 B6):
    /// activation, a toggle, a retry, the width class. No foreground sample (`false`, not read).
    /// (2026-11-20, S4 P10b: through `dispatch`, as `window_event`.)
    fn window_signal(&mut self, shown: Option<ShownId>, signal: ApprovalSignal) {
        if let Some(shown) = shown {
            // Tests: as in `window_event` (2026-11-22, S4 W14b).
            #[cfg(test)]
            self.assert_flow_and_window_in_step();
            self.dispatch(Cmd::Approval(window_input(shown, false, signal)));
        }
    }

    /// The focus of the window `shown` when it is open (the tests' input log).
    #[cfg(test)]
    fn focus_of(&self, shown: Option<ShownId>) -> Option<Focus> {
        self.approval_win
            .as_ref()
            .filter(|win| Some(win.shown) == shown)
            .map(|win| win.focus)
    }

    /// Logs a toggle or retry step of the window `shown` with its focus (the tests' input log,
    /// A-19; 2026-11-19, S4 B6: logged by the step, was logged by `toggle_ack`, `toggle_raw`,
    /// `toggle_connect_account`, `retry_action` and `ai_retry`).
    #[cfg(test)]
    fn log_window_call(&self, shown: Option<ShownId>, call: flow_support::Call) {
        flow_support::log_input(flow_support::Logged::Call {
            call,
            focus: self.focus_of(shown),
        });
    }

    /// The id of the approval window opened last: the shown one, or (none open) one that has
    /// ended or `ShownId(0)`, which is never handed out. The tests' entries deliver to it as if
    /// it got the message (2026-11-19, S4 B6).
    #[cfg(test)]
    const fn last_opened(&self) -> ShownId {
        ShownId(self.wallet.evm.next_shown)
    }

    /// An interaction event of the window opened last (the tests' event entry; 2026-11-19, S4
    /// B6: what the window's `Event` step does; before, `interaction()` was the event entry).
    #[cfg(test)]
    fn interaction(&mut self, event: InteractionEvent) {
        self.window_event(Some(self.last_opened()), ApprovalSignal::Event(event));
    }

    /// The checkbox toggle of the window opened last (the tests' entry; the `ToggleAck` step).
    #[cfg(test)]
    fn toggle_ack(&mut self) {
        let shown = Some(self.last_opened());
        self.log_window_call(shown, flow_support::Call::ToggleAck);
        self.window_signal(shown, ApprovalSignal::ToggleAck);
    }

    fn scroll_by(&mut self, delta: i32) {
        #[cfg(test)]
        self.log_approval_call(flow_support::Call::Scroll(delta));
        if let Some(win) = self.approval_win.as_mut() {
            let page = win.panel.client_rect().h;
            let max = win
                .layout
                .as_ref()
                .map_or(0, |layout| layout.height.saturating_sub(page).max(0));
            win.scroll = win.scroll.saturating_add(delta).clamp(0, max);
            win.panel.set_vscroll(
                win.scroll,
                page,
                win.layout.as_ref().map_or(0, |l| l.height),
            );
            win.panel.invalidate();
        }
    }

    // 2026-11-19 (S4 B2, spec/15 §11.4 S4, spec/04 §3.4): the window procedures of A01, its panel
    // and its AI body only sample what a message reads on arrival (`TrustedSignals`), read the
    // window's facts, map the message with the pure `ui::approval_input::map_msg` and run its steps
    // in order (`run_steps`); a step that delivers an approving or holding event samples its
    // trusted signals right before it. Before, each arm read the signals through the A3 wrappers
    // and built its events inline. The reads, Win32 calls and events keep their order
    // (`s4_flow/input.txt`, `reentry.txt` byte-equal).

    /// A message to A01 of the window opened last (the tests' entry; 2026-11-19, S4 B6: `Forward`
    /// calls `on_surface_msg` with the id its window was made for).
    #[cfg(test)]
    pub(crate) fn on_approval_msg(&mut self, window: &Window, msg: &Msg) -> Reply {
        let received = Received {
            window,
            shown: self.last_opened(),
        };
        self.surface_entry(Surface::Approval, &received, msg)
    }

    /// One message of `surface`: sample, map, run. `window`: the window that got it and the
    /// approval window it belongs to (2026-11-19, S4 B6, A-12: was the window only).
    /// 2026-11-20 (S4 P10b): its callers (`Forward`, the tests' entries) drain after it, as an
    /// entry does (the steps that are not an input of the flow, e.g. the timer's tail, may emit
    /// too; each flow input drains in `dispatch`).
    fn on_surface_msg(&mut self, surface: Surface, window: &Received<'_>, msg: &Msg) -> Reply {
        let signals = TrustedSignals::sample_on_arrival(surface, msg, window);
        let facts = self.input_facts(window.shown, msg);
        let Mapped { steps, reply } = map_msg(surface, msg, facts, signals);
        self.run_steps(surface, Some(window), &steps)
            .unwrap_or(reply)
    }

    /// [`Self::on_surface_msg`], then the effects it emitted (2026-11-20, S4 P10b): the entry of
    /// `Forward` and of the tests' message entries.
    fn surface_entry(&mut self, surface: Surface, window: &Received<'_>, msg: &Msg) -> Reply {
        let reply = self.on_surface_msg(surface, window, msg);
        self.drain();
        reply
    }

    /// What A01 of the window `shown` is when a message arrives (`None`: that window is not open):
    /// its focus, its pressed button and, for a mouse message, the bottom-bar buttons that contain
    /// the point. (2026-11-19, S4 B6, A-12: of the window the message belongs to, was whatever
    /// window was shown; a message of a window that is not the shown one maps as with no window.)
    fn input_facts(&self, shown: ShownId, msg: &Msg) -> Option<Facts> {
        let win = self
            .approval_win
            .as_ref()
            .filter(|win| win.shown == shown)?;
        let hits = match *msg {
            Msg::MouseDown { x, y } | Msg::MouseUp { x, y } | Msg::MouseMove { x, y } => {
                let bottom = win.bottom;
                BarHits {
                    approve: bottom.approve.contains(x, y),
                    reject: bottom.reject.contains(x, y),
                    retry: bottom.retry.is_some_and(|rect| rect.contains(x, y)),
                    ai_retry: bottom.ai_retry.is_some_and(|rect| rect.contains(x, y)),
                }
            }
            _ => BarHits::default(),
        };
        Some(Facts {
            focus: win.focus,
            pressed: win.pressed,
            hits,
        })
    }

    /// Runs mapped steps in order; `Some(reply)` when a guard step ended the message. `window`:
    /// the window that got it and the approval window it belongs to (2026-11-19, S4 B6: every
    /// entry passes one; before, `on_approval_key`'s window-less keys passed `None`).
    fn run_steps(
        &mut self,
        surface: Surface,
        window: Option<&Received<'_>>,
        steps: &[Step],
    ) -> Option<Reply> {
        for step in steps {
            if let Some(reply) = self.run_step(surface, window, *step) {
                return Some(reply);
            }
        }
        None
    }

    #[expect(clippy::too_many_lines, reason = "one arm per mapped step")]
    fn run_step(
        &mut self,
        surface: Surface,
        window: Option<&Received<'_>>,
        step: Step,
    ) -> Option<Reply> {
        // The approval window the message belongs to (2026-11-19, S4 B6, critique A-12): every
        // input of this message carries its id, so the flow drops it once that window is no
        // longer the shown one.
        let shown = window.map(|received| received.shown);
        match step {
            Step::Event(event) => self.window_event(shown, ApprovalSignal::Event(event)),
            // The only delivery of an approving or holding event (source check S8; 2026-11-19,
            // S4 B2 review: `Trusted::deliver` samples and builds in one call, was
            // `TrustedSignals::sample_for` then a `pub` `Trusted::event`).
            Step::Sampled(trusted) => {
                let event = trusted.deliver(window.map(|received| received.window));
                self.window_event(shown, ApprovalSignal::Event(event));
            }
            Step::Activated => {
                #[cfg(test)]
                flow_support::log_input(flow_support::Logged::Activated {
                    focus: self.focus_of(shown),
                });
                self.window_signal(shown, ApprovalSignal::Activated);
            }
            // 2026-11-19 (S4 F1, L-1, owner decision O-4): the close box rejects only the
            // request this window showed. Before, `if self.evm.window.is_some()` also rejected
            // the next request, whose window `RejectActivated` had just opened. 2026-11-19 (S4
            // B6): `ApprovalSignal::Close`, the guard is the flow's id check
            // (`on_approval_input`; was the queue item shown before the event, here).
            Step::Close => self.window_event(shown, ApprovalSignal::Close),
            Step::ToggleAck => {
                #[cfg(test)]
                self.log_window_call(shown, flow_support::Call::ToggleAck);
                self.window_signal(shown, ApprovalSignal::ToggleAck);
            }
            Step::ToggleRaw => {
                #[cfg(test)]
                self.log_window_call(shown, flow_support::Call::ToggleRaw);
                self.window_signal(shown, ApprovalSignal::ToggleRaw);
            }
            Step::ToggleAccount { index, view_rev } => {
                #[cfg(test)]
                self.log_window_call(shown, flow_support::Call::ToggleAccount(index));
                // More rows than `u16` holds cannot be drawn; such an index toggles nothing.
                let index = u16::try_from(index).unwrap_or(u16::MAX);
                self.window_signal(shown, ApprovalSignal::ToggleAccount { index, view_rev });
            }
            Step::Retry => {
                #[cfg(test)]
                self.log_window_call(shown, flow_support::Call::Retry);
                self.window_signal(shown, ApprovalSignal::Retry);
            }
            Step::AiRetry => {
                #[cfg(test)]
                self.log_window_call(shown, flow_support::Call::AiRetry);
                self.window_signal(shown, ApprovalSignal::AiRetry);
            }
            Step::SameWindow(reply) => {
                // 2026-11-19 (S4 F1, L-1): a press that ended this request (past its deadline)
                // goes no further, like a press with no window. Before, the rest of the message
                // ran on the next request's window that the press had just opened. 2026-11-19
                // (S4 B6): the window that got the message by its id (was the queue item shown
                // when the message arrived).
                if shown.is_none_or(|shown| self.shown_now() != Some(shown)) {
                    return Some(reply);
                }
            }
            // 2026-11-20 (S4 B6 review): not an id check. A panel or AI-body message passes it
            // while any flow is shown, and the steps after it (`FocusApproval`, `PanelClick`,
            // `MoveFocus`, `AiExpand`) act on the shown window and flow, not on the window that
            // got the message. Windows cannot reach the difference (an ended window gets no
            // message while effects are applied at once); recorded in spec/15 §11.4 (B6 review)
            // for P10/S4d, which make a deferred schedule.
            Step::AnyWindow(reply) => {
                if self.evm.approval.is_none() {
                    return Some(reply);
                }
            }
            Step::FocusReceiver => {
                if let Some(window) = window {
                    focus_window(window);
                }
            }
            Step::FocusApproval => {
                if let Some(win) = self.approval_win.as_ref() {
                    focus_window(&win.window);
                }
            }
            Step::MoveFocus(focus) => {
                if let Some(win) = self.approval_win.as_mut() {
                    win.focus = focus;
                }
            }
            Step::Press(pressed) => {
                if let Some(win) = self.approval_win.as_mut() {
                    win.pressed = Some(pressed);
                }
            }
            Step::Unpress => {
                if let Some(win) = self.approval_win.as_mut() {
                    win.pressed = None;
                }
            }
            Step::Capture => {
                if let Some(window) = window {
                    capture_mouse(window);
                }
            }
            Step::Release => {
                if let Some(window) = window {
                    release_mouse(window);
                }
            }
            Step::Invalidate => {
                if let Some(window) = window {
                    window.invalidate();
                }
            }
            Step::InvalidateApproval => {
                if let Some(win) = self.approval_win.as_ref() {
                    win.window.invalidate();
                }
            }
            Step::Tab => {
                if let (Some(flow), Some(win)) = (
                    self.wallet.evm.approval.as_ref(),
                    self.approval_win.as_mut(),
                ) {
                    let view = flow.view();
                    let order = tab_order(view.blocks.contains(&Block::Ack), view.has_raw);
                    let backwards = TrustedSignals::sample_shift().shift_down();
                    win.focus = tab_target(&order, win.focus, backwards);
                    win.window.invalidate();
                    win.panel.invalidate();
                }
            }
            Step::KeyScroll(scroll) => {
                let metrics = self
                    .approval_win
                    .as_ref()
                    .map(|win| (win.panel.client_rect().h, win.panel.px(20)));
                if let Some((page, line)) = metrics {
                    self.scroll_by(scroll.delta(page, line));
                }
            }
            Step::Wheel(delta) => {
                if let Some(window) = window {
                    self.scroll_by(wheel_delta(delta, window.px(60)));
                }
            }
            Step::AiWheel(delta) => {
                if let Some(window) = window {
                    self.ai_scroll_by(window, wheel_delta(delta, window.px(40)));
                }
            }
            Step::PanelScroll(goal) => {
                let win = self.approval_win.as_ref()?;
                let page = win.panel.client_rect().h;
                let line = win.panel.px(20);
                let current = win.scroll;
                let track = if goal == ScrollGoal::Track {
                    win.panel.vscroll_track_pos()
                } else {
                    0
                };
                let target = goal.target(current, page, line, track);
                self.scroll_by(target.saturating_sub(current));
            }
            Step::AiScroll(goal) => {
                if let Some(window) = window {
                    let page = window.client_rect().h;
                    let line = window.px(20);
                    let current = self
                        .approval_win
                        .as_ref()
                        .and_then(|win| win.ai.as_ref())
                        .map_or(0, |ai| ai.scroll);
                    let track = if goal == ScrollGoal::Track {
                        window.vscroll_track_pos()
                    } else {
                        0
                    };
                    let target = goal.target(current, page, line, track);
                    self.ai_scroll_by(window, target.saturating_sub(current));
                }
            }
            Step::PanelClick { x, y } => {
                let win = self.approval_win.as_ref()?;
                let content_y = y.saturating_add(win.scroll);
                let layout = win.layout.clone().unwrap_or_default();
                let hit = panel_hit(&layout.accounts, layout.ack, layout.raw, x, content_y);
                // 2026-11-19 (S4 B6, A-13): an account row's toggle carries the revision of the
                // view the layout was drawn from.
                for step in panel_click(hit, layout.view_rev) {
                    if let Some(reply) = self.run_step(surface, window, step) {
                        return Some(reply);
                    }
                }
            }
            Step::AiExpand => {
                // 2026-11-19 (S4 B4b): the panel state is the flow's `AiFlow`, the body's scroll
                // the shell's `AiBody`. 2026-11-20 (S4 B6 review): it flips the shown flow's
                // panel directly, not through `Cmd::Approval` and its id check (see `AnyWindow`).
                // 2026-11-22 (S4c W15): the flip is the wallet's `toggle_ai_panel` (the flow's AI
                // state); before, this step wrote it through `DerefMut`. Same order: the flip,
                // then the shell's body scroll and repaint when it changed.
                if self.wallet.toggle_ai_panel()
                    && let Some(body) = self.approval_win.as_mut().and_then(|win| win.ai.as_mut())
                {
                    body.scroll = 0;
                    if let Some(window) = window {
                        window.invalidate();
                    }
                }
            }
            Step::Paint => {
                if let Some(window) = window {
                    match surface {
                        Surface::Approval => self.paint_approval(window),
                        Surface::Panel => self.paint_panel(window),
                        Surface::AiBody => self.paint_ai_body(window),
                    }
                }
            }
            Step::Relayout => {
                // 2026-11-19 (S4 B5): the width class goes to the flow here, where the rebuild
                // read it from the window before B5. 2026-11-19 (S4 B6): as
                // `ApprovalSignal::Resized` of the window that got the message, whose flow sets it
                // and rebuilds the view (was `set_wide` and `rebuild_view` here).
                let resized = self
                    .approval_win
                    .as_mut()
                    .filter(|win| Some(win.shown) == shown)
                    .map(|win| {
                        win.layout = None;
                        win.is_wide()
                    });
                if let Some(wide) = resized {
                    self.window_signal(shown, ApprovalSignal::Resized { wide });
                }
            }
            // 2026-11-20 (S4 B6 review): the timer's tail after its `Tick` runs on the flow shown
            // now, without the id check (plan §3.1 puts it inside the flow's `Event(Tick)`). A
            // `Tick` that ends the request (`Expire`) and opens the next one's window is followed
            // by this tail on the new flow, as before B6; moving it behind the id check would
            // change that order, so it stays here until P10/S4d (spec/15 §11.4, B6 review).
            // 2026-11-20 (S4 P10b): each of its two calls into the flow is drained before the
            // next step, as when `emit` applied each effect at once.
            // 2026-11-22 (S4c W15): the two calls are the wallet's own fns, named on the wallet
            // (non-test builds have no `DerefMut`).
            Step::TimerTail => {
                let now = self.clock.now_ms();
                self.wallet.ai_tick(now);
                self.drain();
                if let Some(flow) = self.evm.approval.as_ref()
                    && matches!(
                        flow.gate().prepare,
                        PrepareState::Preparing(PrepareStage::Simulating { .. })
                    )
                {
                    self.wallet.rebuild_view_with(false);
                }
                self.drain();
            }
        }
        None
    }
}

impl App {
    /// A message to the panel of the window opened last (the tests' entry; 2026-11-19, S4 B6).
    #[cfg(test)]
    pub(crate) fn on_panel_msg(&mut self, window: &Window, msg: &Msg) -> Reply {
        let received = Received {
            window,
            shown: self.last_opened(),
        };
        self.surface_entry(Surface::Panel, &received, msg)
    }

    // ----- painting -----------------------------------------------------------------------

    #[expect(clippy::too_many_lines, reason = "the fixed A01 areas in order")]
    fn paint_approval(&mut self, window: &Window) {
        let now = self.clock.now_ms();
        let dpi = window.dpi();
        let client = window.client_rect();
        let llm_busy = self
            .llm
            .as_ref()
            .is_none_or(yw_engine::explain::ExplainService::busy);
        let lang = self.approval_lang();
        // 2026-11-22 (S4c W15): the flow is borrowed shared (`&self.wallet.evm`) beside the
        // shell's fonts and window state; before, a `Self { wallet: Wallet { evm, .. }, .. }`
        // pattern bound it mutably (it was only read).
        let evm = &self.wallet.evm;
        let Self {
            fonts,
            approval_win,
            ..
        } = self;
        let Some(fonts) = fonts.for_dpi(dpi, lang) else {
            return;
        };
        // 2026-11-19 (S4 B4b): the flow is read through `ApprovalPaint`, the shell state is
        // `App.approval_win` (both were `EvmUi.window`).
        let (Some(flow), Some(win)) = (evm.approval.as_ref(), approval_win.as_mut()) else {
            return;
        };
        let paint = flow.paint();
        let Ok(mut dc) = window.begin_paint() else {
            return;
        };
        let px = |dip: i32| yw_win::ui::scale(dip, dpi);
        let margin = px(16);
        let width = client
            .w
            .saturating_sub(margin.saturating_mul(2))
            .max(px(100));
        dc.fill_rect(client, theme::BG);
        let mut y = margin;
        // Header: one row per field (muted label column, value), then the badges as pills. A
        // grouped Solana address line is Consolas with bold middle groups (spec/07 §12.3).
        let mut rows: Vec<(String, String, FontRole)> = Vec::new();
        for (label, value) in &paint.view.header {
            let mut first = true;
            for line in value.split('\n') {
                // An address on a line of its own is drawn whole with its ends emphasized
                // (spec/04 §3.3, 2026-11-12); an address with notes (`0x… [내 계정: 계정 1]`)
                // too, the notes on the next row (2026-11-14).
                let mut pieces: Vec<(String, FontRole)> = Vec::with_capacity(2);
                if let Some((address, notes)) = crate::ui::theme::address_with_notes(line) {
                    if let Some((address, _)) = crate::ui::theme::whole_address(address) {
                        pieces.push((address, FontRole::Mono));
                    }
                    pieces.push((notes.to_owned(), FontRole::Body));
                } else if let Some((address, _)) = crate::ui::theme::whole_address(line) {
                    pieces.push((address, FontRole::Mono));
                } else {
                    pieces.push((line.to_owned(), FontRole::Body));
                }
                for (text, role) in pieces {
                    rows.push((
                        if first { label.clone() } else { String::new() },
                        text,
                        role,
                    ));
                    first = false;
                }
            }
        }
        if rows.is_empty() {
            rows.push((
                yw_engine::approval::labels::ORIGIN
                    .get(paint.lang)
                    .to_owned(),
                yw_core::approval::APP_ORIGIN.get(paint.lang).to_owned(),
                FontRole::Body,
            ));
        }
        // The label column fits its widest label (2026-11-14: English labels such as
        // "Requested by" are wider than the Korean ones, which keep the 84 px column).
        dc.select_font(&fonts.body);
        let widest = rows
            .iter()
            .map(|(label, _, _)| dc.measure(&wide(label), i32::MAX).1)
            .max()
            .unwrap_or(0);
        let label_w = px(84).max(widest.saturating_add(px(10))).min(width / 3);
        let value_w = width.saturating_sub(label_w).max(px(60));
        let mut badges: Vec<String> = Vec::new();
        if let Some(banner) = paint.view.btc_banner
            && !rows
                .iter()
                .any(|(_, value, _)| value.contains(banner.text(paint.lang)))
        {
            badges.push(banner.text(paint.lang).to_owned());
        }
        badges.extend(paint.view.badges.iter().cloned());
        // The chain badge goes before the first `네트워크` value line (app chrome, spec/04 §3.2).
        let badge_size = px(BADGE_DIP);
        let badge_row = paint.view.chain.and_then(|badge| {
            rows.iter()
                .position(|(label, _, _)| {
                    label == yw_engine::approval::labels::NETWORK.get(paint.lang)
                })
                .map(|row| (row, badge))
        });
        let badge_indent = |row: usize| {
            badge_row
                .filter(|(at, _)| *at == row)
                .map_or(0, |_| badge_size.saturating_add(px(BADGE_GAP_DIP)))
        };
        let mut header_height = 0;
        for (row, (_, value, role)) in rows.iter().enumerate() {
            dc.select_font(fonts.get(*role));
            header_height += dc
                .measure_wrapped(
                    &wide(value),
                    value_w.saturating_sub(badge_indent(row)),
                    DrawFlags::WRAP,
                )
                .saturating_add(px(4));
        }
        // Every badge is laid out, in as many rows as it takes (2026-11-10: a badge that did not
        // fit the first row used to be dropped). Positions are relative to the badge area top.
        dc.select_font(&fonts.body_bold);
        let (pills, badge_rows) = layout_badges(&badges, margin, 0, width, &px, &mut |text| {
            dc.measure(&wide(text), i32::MAX).1
        });
        header_height += badge_rows.saturating_mul(px(BADGE_ROW_DIP));
        let mainnet = badges
            .iter()
            .any(|badge| is_badge(badge, text::BADGE_MAINNET));
        let (header_fill, header_text, header_muted) = match paint.view.btc_banner {
            Some(yw_engine::approval::view::BtcBanner::Mainnet) => (
                theme::BTC_MAINNET_BG,
                theme::BTC_MAINNET_TEXT,
                theme::BTC_MAINNET_TEXT,
            ),
            Some(yw_engine::approval::view::BtcBanner::Testnet4) => {
                (theme::BTC_TESTNET4_BG, theme::TEXT, theme::TEXT)
            }
            None if paint.view.testnet => (theme::TESTNET_BG, theme::TEXT, theme::MUTED),
            None => (theme::CARD, theme::TEXT, theme::MUTED),
        };
        let header_rect = Rect::new(
            0,
            0,
            client.w,
            header_height.saturating_add(margin.saturating_mul(2)),
        );
        dc.fill_rect(header_rect, header_fill);
        if mainnet {
            // A real-asset window: a red rule across the top of the header.
            dc.fill_rect(Rect::new(0, 0, client.w, px(4)), theme::DANGER_ACCENT);
        }
        dc.fill_rect(
            Rect::new(0, header_rect.bottom(), client.w, 1),
            theme::CARD_BORDER,
        );
        for (row, (label, value, role)) in rows.iter().enumerate() {
            let indent = badge_indent(row);
            let row_w = value_w.saturating_sub(indent);
            dc.select_font(fonts.get(*role));
            let height = dc.measure_wrapped(&wide(value), row_w, DrawFlags::WRAP);
            if !label.is_empty() {
                dc.select_font(&fonts.body);
                dc.set_text_color(header_muted);
                dc.draw_text(
                    &wide(label),
                    Rect::new(margin, y, label_w, height.max(px(18))),
                    DrawFlags::WRAP,
                );
            }
            if indent > 0
                && let Some((_, badge)) = badge_row
            {
                let line = line_height(&mut dc, fonts, *role);
                let top = y.saturating_add((line.saturating_sub(badge_size) / 2).max(0));
                let pixels = badge.render(badge_size);
                dc.draw_argb(
                    margin.saturating_add(label_w),
                    top,
                    badge_size,
                    badge_size,
                    &pixels,
                );
            }
            let rect = Rect::new(
                margin.saturating_add(label_w).saturating_add(indent),
                y,
                row_w,
                height,
            );
            dc.set_text_color(header_text);
            let emphasized = *role == FontRole::Mono
                && crate::ui::theme::address_spans(value).is_some_and(|spans| {
                    crate::ui::theme::paint_spans(
                        &mut dc,
                        fonts,
                        &spans,
                        rect,
                        header_text,
                        // White on the red Bitcoin mainnet header, `FOCUS` elsewhere.
                        if paint.view.btc_banner
                            == Some(yw_engine::approval::view::BtcBanner::Mainnet)
                        {
                            header_text
                        } else {
                            theme::FOCUS
                        },
                    )
                });
            if !emphasized {
                dc.select_font(fonts.get(*role));
                dc.draw_text(&wide(value), rect, DrawFlags::WRAP);
            }
            y = y.saturating_add(height).saturating_add(px(4));
        }
        if !pills.is_empty() {
            let top = y.saturating_add(px(4));
            dc.select_font(&fonts.body_bold);
            for pill in &pills {
                let rect = Rect::new(
                    pill.rect.x,
                    pill.rect.y.saturating_add(top),
                    pill.rect.w,
                    pill.rect.h,
                );
                dc.round_rect(rect, px(12), pill.fill, pill.border);
                dc.set_text_color(pill.color);
                dc.draw_text(&wide(&pill.text), rect, DrawFlags::CENTER);
            }
        }
        y = header_rect.bottom().saturating_add(px(10));
        // Simulation band.
        let mut retry = None;
        if let Some(band) = paint.view.band.clone() {
            let pad = px(12);
            // The tag fits its word (2026-11-14: "High risk" is wider than "고위험"; the Korean
            // tag keeps its 56 px).
            dc.select_font(&fonts.body_bold);
            let (_, level_w) = dc.measure(&wide(text::LEVEL_HIGH.get(paint.lang)), i32::MAX);
            let tag_w = px(56).max(level_w.saturating_add(px(16)));
            let inner = width
                .saturating_sub(pad.saturating_mul(2))
                .saturating_sub(tag_w)
                .saturating_sub(px(10));
            let text_x = margin
                .saturating_add(pad)
                .saturating_add(tag_w)
                .saturating_add(px(10));
            dc.select_font(&fonts.body_bold);
            let head_h = dc.measure_wrapped(&wide(&band.head), inner, DrawFlags::WRAP);
            dc.select_font(&fonts.body);
            let detail_h = if band.detail.is_empty() {
                0
            } else {
                dc.measure_wrapped(&wide(&band.detail), inner, DrawFlags::WRAP)
            };
            let button_h = if band.retry { px(34) } else { 0 };
            let height = head_h
                .saturating_add(detail_h)
                .saturating_add(button_h)
                .saturating_add(pad.saturating_mul(3))
                .min(client.h / 3);
            let rect = Rect::new(margin, y, width, height);
            dc.round_rect(
                rect,
                px(theme::RADIUS_CONTROL),
                theme::DANGER_BG,
                theme::DANGER_ACCENT,
            );
            let tag = Rect::new(margin + pad, y + pad, tag_w, px(22));
            dc.round_rect(tag, px(11), theme::DANGER_ACCENT, theme::DANGER_ACCENT);
            dc.select_font(&fonts.body_bold);
            dc.set_text_color(theme::CARD);
            dc.draw_text(
                &wide(text::LEVEL_HIGH.get(paint.lang)),
                tag,
                DrawFlags::CENTER,
            );
            dc.set_text_color(theme::DANGER_TEXT);
            dc.draw_text(
                &wide(&band.head),
                Rect::new(text_x, y + pad, inner, head_h),
                DrawFlags::WRAP,
            );
            dc.select_font(&fonts.body);
            dc.draw_text(
                &wide(&band.detail),
                Rect::new(text_x, y + pad + head_h, inner, detail_h),
                DrawFlags::WRAP,
            );
            if band.retry {
                let button = Rect::new(text_x, y + height - pad - px(30), px(180), px(30));
                dc.round_rect(
                    button,
                    px(theme::RADIUS_CONTROL),
                    theme::CARD,
                    theme::DANGER_ACCENT,
                );
                dc.set_text_color(theme::DANGER_TEXT);
                dc.draw_text(
                    &wide(text::RETRY_SIMULATION.get(paint.lang)),
                    button,
                    DrawFlags::CENTER,
                );
                retry = Some(button);
            }
            y = y.saturating_add(height).saturating_add(px(8));
        }
        // Bottom bar: the status line(s), the next step, the buttons (spec/04 §3.2 하단).
        let waiting = evm.queue.len().saturating_sub(1);
        let bar = bar_state(&paint, win.focus, waiting, now);
        for character in bar.status.chars() {
            let _ = char_width(&mut dc, fonts, &mut win.widths, FontRole::Body, character);
        }
        for character in bar.step.unwrap_or("").chars() {
            let _ = char_width(
                &mut dc,
                fonts,
                &mut win.widths,
                FontRole::BodyBold,
                character,
            );
        }
        let status_line = line_height(&mut dc, fonts, FontRole::Body);
        let step_line = line_height(&mut dc, fonts, FontRole::BodyBold);
        let bar_layout = {
            let widths = &win.widths;
            let status_char = |character| {
                widths
                    .get(&(FontRole::Body, character))
                    .copied()
                    .unwrap_or(0)
            };
            let step_char = |character| {
                widths
                    .get(&(FontRole::BodyBold, character))
                    .copied()
                    .unwrap_or(0)
            };
            bar_layout(
                client.w,
                &bar.status,
                bar.step,
                &BarMetrics {
                    px: &px,
                    status_line,
                    step_line,
                    status_char: &status_char,
                    step_char: &step_char,
                },
            )
        };
        let bottom_h = bar_layout.height.min(client.h);
        let bottom_top = client.h.saturating_sub(bottom_h);
        if win.bottom.bar.h > 0 && win.bottom.bar.h != bottom_h {
            // The bar grew or shrank (a wrapped status line, a step above the buttons): the
            // content area moves, so the whole window is painted again.
            window.invalidate();
        }
        dc.fill_rect(Rect::new(0, bottom_top, client.w, bottom_h), theme::CARD);
        dc.fill_rect(Rect::new(0, bottom_top, client.w, 1), theme::CARD_BORDER);
        dc.select_font(&fonts.body);
        for (index, (line_y, line)) in bar_layout.status.iter().enumerate() {
            let top = bottom_top.saturating_add(*line_y);
            // The remaining time of the last 30 s in the caution color (first line only).
            let (urgent, rest) = match bar.urgent {
                Some(end) if index == 0 => line
                    .get(..end)
                    .zip(line.get(end..))
                    .unwrap_or(("", line.as_str())),
                _ => ("", line.as_str()),
            };
            let urgent_w: i32 = urgent
                .chars()
                .map(|character| {
                    win.widths
                        .get(&(FontRole::Body, character))
                        .copied()
                        .unwrap_or(0)
                })
                .sum();
            if !urgent.is_empty() {
                dc.set_text_color(theme::WARN_TEXT);
                dc.draw_text(
                    &wide(urgent),
                    Rect::new(margin, top, urgent_w.saturating_add(px(4)), status_line),
                    DrawFlags::LINE,
                );
            }
            dc.set_text_color(theme::MUTED);
            dc.draw_text(
                &wide(rest),
                Rect::new(
                    margin.saturating_add(urgent_w),
                    top,
                    width.saturating_sub(urgent_w).saturating_add(px(4)),
                    status_line,
                ),
                DrawFlags::LINE,
            );
        }
        dc.select_font(&fonts.body_bold);
        dc.set_text_color(theme::TEXT);
        for (line_y, line) in &bar_layout.step {
            dc.draw_text(
                &wide(line),
                Rect::new(
                    bar_layout.step_x,
                    bottom_top.saturating_add(*line_y),
                    bar_layout.step_w.saturating_add(px(4)),
                    step_line,
                ),
                DrawFlags::LINE,
            );
        }
        let approve = Rect::new(
            bar_layout.approve.x,
            bottom_top.saturating_add(bar_layout.approve.y),
            bar_layout.approve.w,
            bar_layout.approve.h,
        );
        let reject = Rect::new(
            bar_layout.reject.x,
            bottom_top.saturating_add(bar_layout.reject.y),
            bar_layout.reject.w,
            bar_layout.reject.h,
        );
        let radius = px(theme::RADIUS_CONTROL);
        dc.round_rect(reject, radius, theme::CARD, theme::BUTTON_SECONDARY.border);
        dc.set_text_color(theme::TEXT);
        dc.draw_text(
            &wide(text::REJECT.get(paint.lang)),
            reject,
            DrawFlags::CENTER,
        );
        let armed = bar.armed;
        let label = bar.label;
        let (fill, text_color) = if armed {
            (theme::PRIMARY_BG, theme::PRIMARY_TEXT)
        } else {
            (theme::DISABLED_BG, theme::DISABLED_TEXT)
        };
        dc.round_rect(
            approve,
            radius,
            fill,
            if armed { fill } else { theme::CARD_BORDER },
        );
        if let Some(done) = bar.held_ms {
            let progress = i32::try_from(
                u64::try_from(approve.w.max(0)).unwrap_or(0) * done / HIGH_RISK_HOLD_MS,
            )
            .unwrap_or(0);
            dc.fill_rect(
                Rect::new(
                    approve.x,
                    approve.bottom().saturating_sub(px(5)),
                    progress,
                    px(5),
                ),
                theme::WARN_ACCENT,
            );
        }
        dc.set_text_color(text_color);
        dc.select_font(&fonts.body_bold);
        dc.draw_text(&wide(label), approve, DrawFlags::CENTER);
        match win.focus {
            Focus::Approve => dc.frame_rect(approve.inset(-px(3)), theme::FOCUS),
            Focus::Reject => dc.frame_rect(reject.inset(-px(3)), theme::FOCUS),
            _ => {}
        }
        // AI panel (spec/06 §6): fixed height right above the bottom bar, reserved from the start,
        // so a result never moves the buttons or the warnings.
        let (content_bottom, ai_retry, ai_body) = match paint.ai.zip(win.ai.as_ref()) {
            Some((ai, ai_child)) => {
                let line_h = line_height(&mut dc, fonts, FontRole::Body);
                let pad = px(10);
                let title_h = px(28);
                let body_h = line_h.saturating_mul(BODY_LINES);
                let height = pad
                    .saturating_add(title_h)
                    .saturating_add(px(6))
                    .saturating_add(body_h)
                    .saturating_add(pad);
                // Anchored to the bottom bar: the buttons are never covered, whatever the size.
                let top = bottom_top.saturating_sub(height);
                dc.fill_rect(Rect::new(0, top, client.w, height), theme::AI_PANEL_BG);
                dc.fill_rect(Rect::new(0, top, client.w, 1), theme::AI_PANEL_BORDER);
                dc.fill_rect(Rect::new(0, top, px(4), height), theme::AI_PANEL_BORDER);
                let button_w = px(110);
                dc.select_font(&fonts.body_bold);
                dc.set_text_color(theme::TEXT);
                dc.draw_text(
                    &wide(PANEL_TITLE.get(ai.panel.lang())),
                    Rect::new(
                        margin,
                        top.saturating_add(pad),
                        width.saturating_sub(button_w).saturating_sub(px(12)),
                        title_h,
                    ),
                    DrawFlags::LINE,
                );
                let retry_rect = ai.panel.retry_offered().then(|| {
                    Rect::new(
                        client.w.saturating_sub(margin).saturating_sub(button_w),
                        top.saturating_add(pad),
                        button_w,
                        title_h,
                    )
                });
                if let Some(rect) = retry_rect {
                    let style = theme::BUTTON_SECONDARY;
                    let (fill, border, text) = if llm_busy {
                        (
                            style.disabled_fill,
                            style.disabled_border,
                            style.disabled_text,
                        )
                    } else {
                        (style.fill, style.border, style.text)
                    };
                    dc.round_rect(rect, radius, fill, border);
                    dc.select_font(&fonts.body);
                    dc.set_text_color(text);
                    dc.draw_text(
                        &wide(RETRY_LABEL.get(ai.panel.lang())),
                        rect,
                        DrawFlags::CENTER,
                    );
                }
                let body = Rect::new(
                    margin,
                    top.saturating_add(pad)
                        .saturating_add(title_h)
                        .saturating_add(px(6)),
                    width,
                    body_h,
                );
                if body != win.bottom.ai_body {
                    ai_child.body.set_rect(body);
                    ai_child.body.invalidate();
                }
                (top, retry_rect.filter(|_| !llm_busy), body)
            }
            None => (bottom_top, None, Rect::default()),
        };
        let panel = Rect::new(0, y, client.w, content_bottom.saturating_sub(y).max(px(40)));
        if panel != win.bottom.panel {
            win.panel.set_rect(panel);
            win.layout = None;
            win.panel.invalidate();
        }
        let bar_rect = Rect::new(0, bottom_top, client.w, bottom_h);
        // A paint that did not cover the whole bar leaves part of it stale: the next tick
        // repaints it.
        let update = dc.update_rect();
        win.bar = if update.x <= bar_rect.x
            && update.y <= bar_rect.y
            && update.right() >= bar_rect.right()
            && update.bottom() >= bar_rect.bottom()
        {
            bar
        } else {
            BarState::default()
        };
        win.bottom = Bottom {
            bar: bar_rect,
            approve,
            reject,
            retry,
            panel,
            ai_retry,
            ai_body,
        };
    }

    /// Paints the AI panel body (spec/06 §6): plain text laid out by
    /// `yw_engine::approval::layout`, wrapped only; no links, formatting, click actions or copy.
    fn paint_ai_body(&mut self, window: &Window) {
        let now = self.clock.now_ms();
        let dpi = window.dpi();
        let client = window.client_rect();
        let lang = self.approval_lang();
        // 2026-11-22 (S4c W15): the AI panel's held flag is the wallet's to write
        // (`Wallet::hold_shown_ai_for_ack`), so the paint makes its early checks first — the
        // fonts, the flow and the window, the AI body — in the same order, then that call at the
        // same point, then the drawing with the flow borrowed shared. Before, one
        // `Self { wallet: Wallet { evm, .. }, .. }` pattern bound the flow mutably and the paint
        // called `ApprovalFlow::hold_ai_for_ack` on it there. The fonts are looked up twice; the
        // second lookup finds the first one's (`FontCache::for_dpi` makes them once per DPI).
        if self.fonts.for_dpi(dpi, lang).is_none()
            || self.evm.approval.is_none()
            || self
                .approval_win
                .as_ref()
                .is_none_or(|win| win.ai.is_none())
        {
            return;
        }
        // A High-risk request shows its warnings first: the AI text waits for the
        // acknowledgement checkbox (the panel keeps its reserved place). (2026-11-19, S4 B4b:
        // `ApprovalFlow::hold_ai_for_ack` sets it from the issued request and the gate, then the
        // body paints from `ApprovalPaint`; was `ai.panel.set_held(held_for_ack(..))` here.)
        if !self.wallet.hold_shown_ai_for_ack() {
            return;
        }
        let evm = &self.wallet.evm;
        let Self {
            fonts,
            approval_win,
            ..
        } = self;
        let Some(fonts) = fonts.for_dpi(dpi, lang) else {
            return;
        };
        let (Some(flow), Some(win)) = (evm.approval.as_ref(), approval_win.as_mut()) else {
            return;
        };
        let ApprovalWin {
            ai: ai_child,
            widths,
            ..
        } = win;
        let Some(ai_child) = ai_child.as_mut() else {
            return;
        };
        let paint = flow.paint();
        let Some(ai) = paint.ai else {
            return;
        };
        let Ok(mut dc) = window.begin_paint() else {
            return;
        };
        dc.fill_rect(client, theme::AI_PANEL_BG);
        let px = |dip: i32| yw_win::ui::scale(dip, dpi);
        let width = client.w.saturating_sub(px(4)).max(px(40));
        let mut rows: Vec<(i32, String, FontRole, Color, i32)> = Vec::new();
        let mut y = 0_i32;
        for line in body_lines(&ai.panel, now, &ai.host, &ai.model) {
            let (text, role, color) = match line {
                PanelLine::Text(text) | PanelLine::Action(text) | PanelLine::Bullet(text) => {
                    (text, FontRole::Body, theme::TEXT)
                }
                PanelLine::Heading(text) | PanelLine::Notice(text) => {
                    (text, FontRole::BodyBold, theme::TEXT)
                }
                PanelLine::Footer(text) => (text, FontRole::Caption, theme::MUTED),
                PanelLine::Gap => {
                    y = y.saturating_add(px(6));
                    continue;
                }
            };
            let height = line_height(&mut dc, fonts, role);
            for character in text.chars() {
                let _ = char_width(&mut dc, fonts, widths, role, character);
            }
            let cache = &*widths;
            let pieces = text_layout::layout(&text, width, &|character| {
                cache.get(&(role, character)).copied().unwrap_or(0)
            });
            for piece in pieces {
                rows.push((
                    y,
                    text.get(piece.start..piece.end).unwrap_or("").to_owned(),
                    role,
                    color,
                    height,
                ));
                y = y.saturating_add(height);
            }
        }
        let max = y.saturating_sub(client.h).max(0);
        ai_child.scroll = ai_child.scroll.clamp(0, max);
        window.set_vscroll(ai_child.scroll, client.h, y);
        for (top, text, role, color, height) in rows {
            let top = top.saturating_sub(ai_child.scroll);
            if top.saturating_add(height) < 0 || top > client.h {
                continue;
            }
            dc.select_font(fonts.get(role));
            dc.set_text_color(color);
            dc.draw_text(
                &wide(&text),
                Rect::new(0, top, width.saturating_add(px(4)), height),
                DrawFlags::LINE,
            );
        }
    }

    /// A message to the AI body of the window opened last (the tests' entry; 2026-11-19, S4 B6).
    #[cfg(test)]
    pub(crate) fn on_ai_body_msg(&mut self, window: &Window, msg: &Msg) -> Reply {
        let received = Received {
            window,
            shown: self.last_opened(),
        };
        self.surface_entry(Surface::AiBody, &received, msg)
    }

    fn ai_scroll_by(&mut self, window: &Window, delta: i32) {
        if let Some(ai) = self.approval_win.as_mut().and_then(|win| win.ai.as_mut()) {
            ai.scroll = ai.scroll.saturating_add(delta).max(0);
            window.invalidate();
        }
    }
}

impl App {
    #[expect(
        clippy::too_many_lines,
        reason = "the layout, then the panel's shapes, lines and focus in one pass"
    )]
    fn paint_panel(&mut self, window: &Window) {
        let dpi = window.dpi();
        let client = window.client_rect();
        let lang = self.approval_lang();
        // 2026-11-22 (S4c W15): the flow borrowed shared, as in `paint_approval`.
        let evm = &self.wallet.evm;
        let Self {
            fonts,
            approval_win,
            ..
        } = self;
        let Some(fonts) = fonts.for_dpi(dpi, lang) else {
            return;
        };
        let (Some(flow), Some(win)) = (evm.approval.as_ref(), approval_win.as_mut()) else {
            return;
        };
        let paint = flow.paint();
        let Ok(mut dc) = window.begin_paint() else {
            return;
        };
        dc.fill_rect(client, theme::BG);
        let width = client.w;
        if win
            .layout
            .as_ref()
            .is_none_or(|layout| layout.width != width)
        {
            let mut layout = build_layout(
                &mut dc,
                fonts,
                &mut win.widths,
                paint.view,
                width,
                dpi,
                paint.ack_checked,
            );
            // 2026-11-19 (S4 B6, A-13): the revision of the view it was drawn from.
            layout.view_rev = paint.view_rev;
            win.layout = Some(layout);
            let max = win
                .layout
                .as_ref()
                .map_or(0, |layout| layout.height.saturating_sub(client.h).max(0));
            win.scroll = win.scroll.min(max);
            window.set_vscroll(
                win.scroll,
                client.h,
                win.layout.as_ref().map_or(0, |layout| layout.height),
            );
        }
        let Some(layout) = win.layout.as_ref() else {
            return;
        };
        let offset = win.scroll;
        for (rect, fill, border, radius) in &layout.rounds {
            let shifted = Rect::new(rect.x, rect.y.saturating_sub(offset), rect.w, rect.h);
            if shifted.bottom() >= 0 && shifted.y <= client.h {
                dc.round_rect(shifted, *radius, *fill, *border);
            }
        }
        for (rect, color) in &layout.fills {
            let shifted = Rect::new(rect.x, rect.y.saturating_sub(offset), rect.w, rect.h);
            if shifted.bottom() >= 0 && shifted.y <= client.h {
                dc.fill_rect(shifted, *color);
            }
        }
        for (rect, color) in &layout.frames {
            dc.frame_rect(
                Rect::new(rect.x, rect.y.saturating_sub(offset), rect.w, rect.h),
                *color,
            );
        }
        dc.select_font(&fonts.body_bold);
        for (rect, text, color) in &layout.tags {
            dc.set_text_color(*color);
            dc.draw_text(
                &wide(text),
                Rect::new(rect.x, rect.y.saturating_sub(offset), rect.w, rect.h),
                DrawFlags::CENTER,
            );
        }
        for line in &layout.lines {
            let top = line.y.saturating_sub(offset);
            if top.saturating_add(line.height) < 0 || top > client.h {
                continue;
            }
            draw_line(&mut dc, fonts, line, offset, &win.widths);
        }
        let focus_rect = match win.focus {
            Focus::Ack => layout.ack,
            Focus::Raw => layout.raw,
            _ => None,
        };
        if let Some(rect) = focus_rect {
            dc.frame_rect(
                Rect::new(
                    rect.x - 2,
                    rect.y.saturating_sub(offset) - 2,
                    rect.w + 4,
                    rect.h + 4,
                ),
                theme::FOCUS,
            );
        }
        if win.focus == Focus::Scroll {
            dc.frame_rect(client.inset(1), theme::FOCUS);
        }
    }
}

#[cfg(test)]
#[path = "app_approval_smoke.rs"]
pub(crate) mod smoke;

/// S4 A3 (2026-11-18, spec/15 §11.4 S4): the test clock, the hidden approval host, the scripted
/// trusted-signal oracle with its call trace, and the App fixture of the approval flow tests.
#[cfg(test)]
#[path = "app_approval_flow_support.rs"]
pub(crate) mod flow_support;

/// S4 B7 (2026-11-20, spec/15 §11.4 S4): the headless approval host: `Effect::Approval`
/// recorded instead of applied, the open answered without a window (the headless half of the
/// flow and lifecycle scenarios, `flow_tests::lifecycle::headless`, gate test step).
#[cfg(test)]
#[path = "app_approval_headless_host.rs"]
pub(crate) mod headless_host;

/// S4 A4 (2026-11-18, spec/15 §11.4 S4): the App-level approval flow scenarios and their golden
/// `app/tests/s4_flow/flow.txt` (`#[ignore]`, gate step `winui`).
#[cfg(test)]
#[path = "app_approval_flow_tests.rs"]
mod flow_tests;

/// S4 A5 (2026-11-18, spec/15 §11.4 S4): the approval window's input mapping and re-entrancy
/// goldens `app/tests/s4_flow/{input,reentry}.txt` (`#[ignore]`, gate step `winui`) and the
/// source checks S1–S3 (gate test step).
#[cfg(test)]
#[path = "app_approval_input_tests.rs"]
mod input_tests;

/// Hooks for the screenshot tour (`ui::tour`, an `#[ignore]` test). Gated like the tour module
/// (`#[cfg(test)]` + `#[cfg(debug_assertions)]`), so `cargo test --release` has no dead code.
#[cfg(test)]
#[cfg(debug_assertions)]
impl App {
    /// The open approval window.
    pub(crate) fn tour_approval_window(&self) -> Option<&Window> {
        self.approval_win.as_ref().map(|win| &win.window)
    }

    /// Rejects the open approval (as `거부` would).
    pub(crate) fn tour_reject_approval(&mut self) {
        self.finish_approval(QueueOutcome::Rejected);
    }

    /// The open window's AI panel state (spec/06), if it has one.
    pub(crate) fn tour_ai_state(&self) -> Option<yw_engine::explain::AiPanelState> {
        // 2026-11-19 (S4 B4b): read through the flow's `ApprovalPaint`.
        self.evm
            .approval
            .as_ref()
            .and_then(|flow| flow.paint().ai.map(|ai| ai.panel.state().clone()))
    }
}

#[cfg(test)]
mod tests {
    use yw_core::evm::chain::{
        ARBITRUM_ONE, BASE_MAINNET, BSC_MAINNET, ETHEREUM_MAINNET, HYPEREVM_MAINNET,
        ROBINHOOD_MAINNET, SEPOLIA,
    };
    use yw_core::sol::SolCluster;

    use super::{BarMetrics, bar_layout, layout_badges};
    use yw_engine::wallet::app_approval::{network_badge, order_badges};

    const MAINNET_BADGE: &str = yw_engine::approval::text::BADGE_MAINNET.ko;
    const T_ACK_FIRST: &str = yw_engine::approval::text::ACK_FIRST.ko;
    const T_SIM_RESIM_FAILED: &str = yw_engine::approval::text::SIM_RESIM_FAILED.ko;
    use crate::ui::theme;

    /// Test widths: 13 px a Hangul (or other wide) character, 7 px an ASCII one (96 DPI).
    fn test_width(character: char) -> i32 {
        if character.is_ascii() { 7 } else { 13 }
    }

    /// spec/04 §3.2 (2026-11-10): six badges in a 520 DIP window are all placed, in the
    /// network-first order, and the mainnet pill is filled red with white letters.
    #[test]
    fn every_header_badge_is_placed_and_the_mainnet_pill_is_red() {
        let px = |dip: i32| dip;
        let mut badges = vec![
            "YubiKey로 서명 · #12345678 · 터치 1회".to_owned(),
            "WalletConnect 세션".to_owned(),
            "사용자 추가 체인 (chainId 10)".to_owned(),
            "로컬 개발 사이트(http)".to_owned(),
            "국제화 도메인(punycode)".to_owned(),
            MAINNET_BADGE.to_owned(),
        ];
        order_badges(&mut badges);
        assert_eq!(
            badges,
            [
                MAINNET_BADGE,
                "국제화 도메인(punycode)",
                "로컬 개발 사이트(http)",
                "WalletConnect 세션",
                "사용자 추가 체인 (chainId 10)",
                "YubiKey로 서명 · #12345678 · 터치 1회",
            ]
        );
        let width = 520 - 2 * 16;
        let (pills, rows) = layout_badges(&badges, 16, 0, width, &px, &mut |text| {
            text.chars().map(test_width).sum()
        });
        assert_eq!(pills.len(), 6, "no badge is dropped");
        assert!(rows >= 2, "{rows}");
        for pill in &pills {
            assert!(
                pill.rect.x >= 16 && pill.rect.right() <= 16 + width,
                "{pill:?}"
            );
            assert_eq!(pill.rect.y % 30, 0);
        }
        assert_eq!(
            (pills[0].fill, pills[0].color),
            (theme::DANGER_ACCENT, theme::CARD)
        );
        assert!(pills[1..].iter().all(|pill| pill.fill == theme::CARD));
    }

    /// spec/04 §3.2 하단 (2026-11-10): at 520 DIP with three waiting requests and a failed
    /// re-simulation the whole next step is shown (its own row above the buttons) and the status
    /// line is kept whole; at 820 DIP the step goes beside the buttons.
    #[test]
    fn the_whole_next_step_fits_a_narrow_bar() {
        let px = |dip: i32| dip;
        let status = format!("남은 시간 1:58 · 대기 3건 · {T_SIM_RESIM_FAILED}");
        let metrics = BarMetrics {
            px: &px,
            status_line: 19,
            step_line: 19,
            status_char: &test_width,
            step_char: &test_width,
        };
        let narrow = bar_layout(520, &status, Some(T_ACK_FIRST), &metrics);
        let joined = |lines: &[(i32, String)]| {
            lines
                .iter()
                .map(|(_, line)| line.as_str())
                .collect::<Vec<_>>()
                .join(" ")
        };
        assert_eq!(joined(&narrow.step), T_ACK_FIRST);
        assert_eq!(joined(&narrow.status), status);
        let status_bottom = narrow.status.last().map_or(0, |(y, _)| y + 19);
        for (y, line) in &narrow.step {
            assert!(line.chars().map(test_width).sum::<i32>() <= narrow.step_w);
            assert!(
                *y >= status_bottom && y + 19 <= narrow.approve.y,
                "{narrow:?}"
            );
        }
        assert_eq!(narrow.approve.bottom(), narrow.height - 16);
        assert_eq!(narrow.approve.right(), 520 - 16);
        // Without a step the narrow bar keeps the same height (no jump at arming).
        let armed = bar_layout(520, &status, None, &metrics);
        assert_eq!(armed.height, narrow.height);
        let wide = bar_layout(820, &status, Some(T_ACK_FIRST), &metrics);
        assert!(wide.step.len() <= 2 && wide.step_w >= 260, "{wide:?}");
        assert_eq!(joined(&wide.step), T_ACK_FIRST);
        assert!(wide.step.iter().all(|(y, _)| *y >= wide.approve.y - 2));
    }

    #[test]
    fn mainnets_get_the_real_asset_badge() {
        assert_eq!(MAINNET_BADGE, "메인넷 — 실제 자산");
        for chain in [
            ETHEREUM_MAINNET,
            HYPEREVM_MAINNET,
            ARBITRUM_ONE,
            BASE_MAINNET,
            BSC_MAINNET,
            ROBINHOOD_MAINNET,
        ] {
            assert_eq!(
                network_badge(yw_core::lang::Lang::Ko, Some(chain), None),
                Some((MAINNET_BADGE, false))
            );
        }
        assert_eq!(
            network_badge(yw_core::lang::Lang::Ko, None, Some(SolCluster::Mainnet)),
            Some((MAINNET_BADGE, false))
        );
        assert_eq!(
            network_badge(yw_core::lang::Lang::Ko, Some(SEPOLIA), None),
            Some(("테스트넷 — 실제 자산이 아닙니다", true))
        );
        assert!(
            network_badge(yw_core::lang::Lang::Ko, None, Some(SolCluster::Devnet))
                .is_some_and(|(_, test)| test)
        );
        // User chains have no testnet classification; Bitcoin has its own banner.
        assert_eq!(network_badge(yw_core::lang::Lang::Ko, Some(10), None), None);
        assert_eq!(network_badge(yw_core::lang::Lang::Ko, None, None), None);
    }
}
