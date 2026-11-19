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

use yw_core::approval::RiskLevel;
use yw_core::evm::chain::SEPOLIA;
use yw_core::evm::simulate::needs_resimulation;
use yw_core::lang::{Lang, Text};
use yw_engine::approval::QueueId;
use yw_engine::approval::flow::{
    ApprovalEffect, OpenOutcome, ShownId, StatusAction, connect_gate_count,
};
use yw_engine::cmd::Cmd;
use yw_engine::effect::Effect;
use yw_win::ui::{
    Color, DrawFlags, Handler, Msg, PaintDc, Rect, Reply, Window, WindowKind, WindowSpec,
    create_window,
};

use crate::app::App;
use crate::app_evm::{AppApproval, QueuedItem};
use crate::app_llm::log_request;
use crate::approval_flow::{AiFlow, ApprovalFlow, ApprovalPaint};
use crate::browser::{SiteKind, SiteRequest};
use crate::errors::ErrorCode;
use crate::events::{KeyJob, SignInfo};
use crate::explain::input::RequestKind;
use crate::explain::panel::{
    AiPanel, BODY_LINES, Dispatch, Ended, PANEL_TITLE, PanelLine, RETRY_LABEL, body_lines,
};
use crate::explain::{
    ExplainError, ExplainInput, ExplainSource, LlmDone, LlmJob, RequestStats, build_input,
};
use crate::flow::evm::Limits;
use crate::flow::evm::prepare::{
    PrepareJob, PrepareOutcome, PrepareResult, Prepared, ResimJob, ResimKind, ResimResult,
};
use crate::logging::{self, Field};
use crate::ui::approval::QueueOutcome;
use crate::ui::approval_input::{
    APPROVAL_TIMER_ID, BarHits, Facts, Focus, Mapped, Pressed, ScrollGoal, Step, Surface,
    TrustedSignals, map_msg, panel_click, panel_hit, tab_order, tab_target, wheel_delta,
};
use crate::ui::approval_text as text;
use crate::ui::approval_view::{ApprovalView, Block, Tone, escape_spans, view};
use crate::ui::badge::{BADGE_DIP, BADGE_GAP_DIP, Badge};
use crate::ui::interaction::{
    APPROVAL_TICK_MS, HIGH_RISK_HOLD_MS, InteractionEvent, PrepareStage, PrepareState, ReadyContent,
};
use crate::ui::text_layout;
use crate::ui::theme::{self, FontRole, Fonts, wide};
use crate::workers::rpc::RpcJob;

/// Approval window class.
pub const APPROVAL_CLASS: &str = "YourWalletV3Approval";
/// Scrolling panel class.
pub const PANEL_CLASS: &str = "YourWalletV3Panel";
/// Extra window height (DIP) when the AI panel is reserved (spec/06 §6: ten body lines plus the
/// title row), so the core content area keeps the size it has without the panel.
const AI_PANEL_EXTRA_DIP: i32 = 240;
const SKIP_BLOCKED: Text = text::AI_SKIP_BLOCKED;
const SKIP_FAILED: Text = text::AI_SKIP_FAILED;

/// Which approval window is shown (2026-11-19, S4 F1, L-1, spec/04 §3.6): none, or one showing
/// the queue item with this id (`None`: a window without its queue item, not expected between
/// messages).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShownWindow {
    NoWindow,
    Showing(Option<QueueId>),
}

/// The AI explanation panel of one window (spec/06 §6, spec/04 §3.8): reserved when the window
/// opens, painted by the window (title, `다시 요청`) and by its own child (`body`, ten lines,
/// scrolled inside). Never focused and never an input of the gate. 2026-11-19 (S4 B4b): this is
/// the shell half, the body child and its scroll; the panel state, serial, host, model and kind
/// are the flow's `approval_flow::AiFlow` (before, one `AiUi` held both).
struct AiBody {
    body: Window,
    scroll: i32,
}

/// What a Ready display means for the AI panel.
enum AiReady {
    Input(Result<ExplainInput, ExplainError>),
    Skip(&'static str),
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
}

/// Connect-window state (spec/05 §4.2, §4.9).
#[derive(Clone, Debug)]
pub struct ConnectState {
    /// Offered accounts `(choice, label, address text, group)` in list order. EVM accounts are
    /// checkboxes (1–16); Solana and Bitcoin choices are one radio group per purpose.
    pub accounts: Vec<crate::app_chain_sites::ConnectEntry>,
    /// Selection.
    pub selected: Vec<bool>,
    /// Origin chain name.
    pub chain_name: String,
    /// EVM: the origin chain shown (`chain_name`). Re-read from the dispatcher at every render
    /// and checked at approval, which stores exactly this chain (security review L4(c)).
    pub chain_id: u64,
    /// The request's chain family.
    pub family: yw_core::policy::Family,
    /// Number of radio groups (Solana 1, Bitcoin one per purpose; unused for EVM).
    pub groups: u8,
}

impl ConnectState {
    /// The gate's `connect_selected`: the checked count for EVM; for Solana/Bitcoin the count
    /// when every group has exactly one choice, else 0 (approve disabled). (2026-11-19, S4 B3:
    /// the rule is `yw_engine::approval::flow::connect_gate_count`, moved from here unchanged.)
    #[must_use]
    pub fn gate_count(&self) -> usize {
        connect_gate_count(
            &self.accounts,
            |(_, _, _, group)| *group,
            &self.selected,
            self.groups,
            self.family == yw_core::policy::Family::Evm,
        )
    }

    /// Toggles entry `index`: a checkbox for EVM, a radio button within its group otherwise.
    pub fn toggle(&mut self, index: usize) {
        if self.family == yw_core::policy::Family::Evm {
            if let Some(slot) = self.selected.get_mut(index) {
                *slot = !*slot;
            }
            return;
        }
        let Some(group) = self.accounts.get(index).map(|(_, _, _, group)| *group) else {
            return;
        };
        for (position, ((_, _, _, of), slot)) in self
            .accounts
            .iter()
            .zip(self.selected.iter_mut())
            .enumerate()
        {
            if *of == group {
                *slot = position == index;
            }
        }
    }
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

/// The AI explanation kind of a queued item (spec/06 §3.1): dApp transactions, `personal_sign`
/// and typed data; the window reserves its panel only while the LLM worker exists. 2026-11-19
/// (S4 B5): the match of `open_approval`, shared with the open's answer.
fn explain_kind(item: &QueuedItem) -> Option<RequestKind> {
    match item {
        QueuedItem::Site(site) => match &site.kind {
            SiteKind::Send(_) => Some(RequestKind::EvmTx),
            SiteKind::PersonalSign { .. } => Some(RequestKind::PersonalSign),
            SiteKind::TypedData { .. } => Some(RequestKind::TypedData),
            SiteKind::RequestAccounts
            | SiteKind::RequestPermissions
            | SiteKind::Revoke
            | SiteKind::SolConnect
            | SiteKind::BtcConnect(_)
            | SiteKind::SolSign { .. }
            | SiteKind::SolTx { .. }
            | SiteKind::BtcSign { .. } => None,
        },
        QueuedItem::App(_)
        | QueuedItem::Sol(_)
        | QueuedItem::Btc(_)
        | QueuedItem::Zec(_)
        | QueuedItem::HyperCore(_) => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Approval,
    Panel,
    AiBody,
}

#[cfg(test)]
impl Target {
    /// The window kind a dropped re-entrant message was meant for (S4 A5 trace).
    const fn label(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Panel => "panel",
            Self::AiBody => "ai-body",
        }
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
        match self.target {
            Target::Approval => app.on_approval_msg(window, msg),
            Target::Panel => app.on_panel_msg(window, msg),
            Target::AiBody => app.on_ai_body_msg(window, msg),
        }
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

/// The header network badge (spec/04 §3 header): built-in mainnets (Ethereum, `HyperEVM`,
/// Arbitrum One, Base, BNB Smart Chain, Robinhood Chain, Solana mainnet) say plainly that real assets move; Sepolia and Solana devnet are test
/// networks. User chains have no testnet classification and get neither; Bitcoin has its own
/// network banner. Returns the text and whether it is the testnet coloring.
fn network_badge(
    lang: Lang,
    evm_chain: Option<u64>,
    sol: Option<yw_core::sol::SolCluster>,
) -> Option<(&'static str, bool)> {
    use yw_core::evm::chain::is_builtin_mainnet;
    use yw_core::sol::SolCluster;
    match (evm_chain, sol) {
        (_, Some(SolCluster::Devnet)) => Some((text::BADGE_DEVNET.get(lang), true)),
        (_, Some(SolCluster::Mainnet)) => Some((text::BADGE_MAINNET.get(lang), false)),
        (Some(chain), None) if is_builtin_mainnet(chain) => {
            Some((text::BADGE_MAINNET.get(lang), false))
        }
        (Some(SEPOLIA), None) => Some((text::BADGE_TESTNET.get(lang), true)),
        _ => None,
    }
}

/// Whether `badge` is `text` in either language (the badge order and colors do not depend on
/// the window's language).
fn is_badge(badge: &str, text: Text) -> bool {
    Lang::ALL.iter().any(|lang| badge == text.get(*lang))
}

/// Whether `badge` starts with the fixed part of `text` (before any `{0}`) in either language.
fn badge_starts<const N: usize>(badge: &str, text: yw_core::lang::Tpl<N>) -> bool {
    Lang::ALL.iter().any(|lang| {
        let template = text.template(*lang);
        badge.starts_with(template.split('{').next().unwrap_or(template))
    })
}

/// Where a header badge goes (spec/04 §3.2, 2026-11-10): the network first (mainnet / testnet),
/// then the origin's risk (punycode, http), the compatibility mode and the `WalletConnect`
/// session, the user chain, and last the signer (`YubiKey`) and the Verify state. Signing,
/// connect and `WalletConnect` connect windows use the same order. The badges are app chrome
/// outside the digested display.
fn badge_rank(badge: &str) -> u8 {
    if [
        text::BADGE_MAINNET,
        text::BADGE_TESTNET,
        text::BADGE_DEVNET,
        text::BADGE_HC_TESTNET,
    ]
    .into_iter()
    .any(|text| is_badge(badge, text))
        || Lang::ALL.iter().any(|lang| {
            [
                yw_core::btc::BtcNetwork::Mainnet,
                yw_core::btc::BtcNetwork::Testnet4,
            ]
            .iter()
            .any(|network| badge == network.banner_in(*lang))
        })
    {
        0
    } else if badge_starts(badge, text::BADGE_PUNYCODE) {
        1
    } else if badge_starts(badge, text::BADGE_HTTP) {
        2
    } else if badge_starts(badge, text::BADGE_COMPAT) {
        3
    } else if is_badge(badge, text::BADGE_WALLETCONNECT) {
        4
    } else if badge_starts(badge, text::BADGE_CUSTOM_CHAIN) {
        5
    } else if badge_starts(badge, text::BADGE_YUBIKEY) {
        6
    } else if badge.starts_with("Verify ") {
        7
    } else {
        8
    }
}

/// Puts header badges in [`badge_rank`] order (stable within a rank).
fn order_badges(badges: &mut [String]) {
    badges.sort_by_key(|badge| badge_rank(badge));
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
    // ----- queue and window lifecycle -----------------------------------------------------

    /// Shows the next queued approval (unlocked only, spec/04 §3.7). Site items that need no
    /// window (connected `eth_requestAccounts`, revoke after unlock) or fail their checks are
    /// answered and skipped.
    pub fn show_next_approval(&mut self) {
        if self.evm.approval.is_some() || !matches!(self.mode, crate::app::AppMode::Unlocked { .. })
        {
            if self.mode == crate::app::AppMode::BackupPending {
                let finished = self.evm.queue.drain_waiting_matching(
                    |item| matches!(item, QueuedItem::Site(_)),
                    QueueOutcome::NotReady,
                );
                for (item, outcome) in finished {
                    self.approval_finished(&item.payload, outcome);
                }
            }
            self.refresh();
            return;
        }
        if self.sol_connect_waits_for_account() {
            // Moves again when the account arrives (`KeyOutcome::SolKeys`).
            self.refresh();
            return;
        }
        loop {
            let now = self.clock.now_ms();
            let mut finished = Vec::new();
            let shown = self.evm.queue.show_next(now, &mut finished);
            for (item, outcome) in finished {
                self.approval_finished(&item.payload, outcome);
            }
            if shown.is_none() {
                self.refresh();
                return;
            }
            let Some(item) = self.evm.queue.shown().map(|shown| shown.payload.clone()) else {
                return;
            };
            if let QueuedItem::Site(site) = &item
                && let Some(outcome) = self.site_preflight(site)
            {
                if let Some((done, outcome)) = self.evm.queue.finish_shown(outcome) {
                    self.approval_finished(&done.payload, outcome);
                }
                continue;
            }
            // 2026-11-19 (S4 B5): the open's answer (`on_approval_opened`) starts the
            // preparation or rejects the item with E-APP-009 (was here, on `open_approval`'s
            // result).
            self.open_approval(item);
            return;
        }
    }

    pub(crate) fn connect_state(&self, site: &SiteRequest) -> ConnectState {
        let family = site.kind.family();
        if family != yw_core::policy::Family::Evm {
            let (accounts, selected, chain_name) = self.chain_connect_choices(site);
            let groups = match &site.kind {
                SiteKind::BtcConnect(purposes) => u8::try_from(purposes.len()).unwrap_or(1),
                _ => 1,
            };
            return ConnectState {
                accounts,
                selected,
                chain_name,
                chain_id: site.chain_id,
                family,
                groups,
            };
        }
        let granted: Vec<yw_core::evm::address::Address> = self
            .browser_grants()
            .into_iter()
            .find(|grant| grant.origin == site.origin)
            .map(|grant| grant.accounts)
            .unwrap_or_default();
        let accounts = self.own_account_rows();
        // An account whose recovery phrase is not backed up can receive but not sign (spec/02
        // §8.6), nor can a YubiKey key on a card still at its factory PINs (spec/10 §9.3): its
        // row says so, and it is not the default of a new site while another is.
        let unconfirmed: Vec<Option<yw_core::vault::RecordId>> = accounts
            .iter()
            .map(|(address, ..)| self.evm_account_unconfirmed(address))
            .collect();
        let factory: Vec<Option<u32>> = accounts
            .iter()
            .map(|(address, ..)| self.evm_account_card_gate(address))
            .collect();
        let can_sign = |index: usize| {
            unconfirmed.get(index).is_some_and(Option::is_none)
                && factory.get(index).is_some_and(Option::is_none)
        };
        // A new site starts with the account chosen on the main screen (2026-11-08; account 0
        // before), so the user picks deliberately; the window is still approved explicitly.
        let current = self.selected_account().and_then(|(current, ..)| {
            accounts
                .iter()
                .position(|(address, ..)| *address == current)
        });
        let first = current
            .filter(|index| can_sign(*index))
            .or_else(|| (0..accounts.len()).find(|index| can_sign(*index)))
            .or(current)
            .unwrap_or(0);
        let selected = accounts
            .iter()
            .enumerate()
            .map(|(index, (address, ..))| {
                if granted.is_empty() {
                    index == first
                } else {
                    granted.contains(address)
                }
            })
            .collect();
        ConnectState {
            // Each row: the name (and why it cannot sign), a muted line with its source and
            // path, then the address — the Solana window's shape (2026-11-10).
            accounts: accounts
                .into_iter()
                .zip(unconfirmed.into_iter().zip(factory))
                .map(|((address, label, path), (phrase, serial))| {
                    (
                        crate::app_chain_sites::ConnectChoice::Evm(address),
                        format!(
                            "{label}{}{}\n{path}",
                            self.mn_connect_tag(phrase),
                            self.card_connect_tag(serial)
                        ),
                        address.to_checksum(),
                        0,
                    )
                })
                .collect(),
            selected,
            chain_name: self.evm_chain_label(self.connect_origin_chain(site)),
            chain_id: self.connect_origin_chain(site),
            family,
            groups: 1,
        }
    }

    /// The origin's chain now (spec/05 §4.3), or the request's without a dispatcher.
    fn connect_origin_chain(&self, site: &SiteRequest) -> u64 {
        self.browser.as_ref().map_or(site.chain_id, |browser| {
            browser.core.origin_chain(&site.origin)
        })
    }

    fn evm_chain_label(&self, chain_id: u64) -> String {
        self.settings
            .evm_chain_name_in(self.approval_lang(), chain_id)
            .unwrap_or_else(|| format!("chainId {chain_id}"))
    }

    /// Security review L4(c): an open EVM connect window shows the origin's chain of now (a
    /// window-less `wallet_switchEthereumChain` may have changed it). Returns whether it changed.
    fn refresh_connect_chain(&mut self) -> bool {
        let Some(site) =
            self.evm
                .approval
                .as_ref()
                .and_then(|flow| match (flow.item(), flow.connect()) {
                    (QueuedItem::Site(site), Some(connect))
                        if connect.family == yw_core::policy::Family::Evm =>
                    {
                        Some(site.clone())
                    }
                    _ => None,
                })
        else {
            return false;
        };
        let chain_id = self.connect_origin_chain(&site);
        let name = self.evm_chain_label(chain_id);
        self.evm
            .approval
            .as_mut()
            .is_some_and(|flow| flow.set_connect_chain(chain_id, name))
    }

    /// Opens the approval window for `item` (the wallet half; 2026-11-19, S4 B5, plan §3.1): the
    /// flow is made at `now` and becomes `EvmUi.approval`, then the window is asked for with
    /// `Effect::Approval(Open)`, which the executor applies at once (`open_approval_window`) and
    /// answers with `Cmd::ApprovalOpened` (`on_approval_opened`: the AI explanation, the first
    /// view, then `start_prepare`; a refused open rejects the item with E-APP-009). Before B5 this
    /// function made the window, its panel and AI body, then the flow, centred, showed and focused
    /// the window, and `show_next_approval` called `start_prepare` or rejected on its `Err`. The
    /// flow is pure: making it before the window changes no message, Win32 call or clock read
    /// (its only error, a clock past `u64::MAX - 120 000` ms, cannot happen; it would reject
    /// before a window was made instead of after the made windows were dropped unshown).
    fn open_approval(&mut self, item: QueuedItem) {
        let now = self.clock.now_ms();
        let connect = match &item {
            QueuedItem::Site(site) if site.kind.is_connect() => Some(self.connect_state(site)),
            _ => None,
        };
        let lang = self.settings.language;
        // spec/06 §3.1: dApp transactions, personal_sign and typed data, only while the worker
        // exists (feature effectively on). The panel's height is reserved now (§6).
        let ai_reserved = explain_kind(&item).is_some() && self.llm.is_some();
        let shown = self.evm.shown_id();
        let is_connect = connect.is_some();
        // 2026-11-19 (S4 B3): the deadline rule is `yw_engine::approval::flow::session_deadline`
        // (was inline here: the site deadline, else `now + MAX_LIFETIME_MS`, at least `now + 1`).
        // 2026-11-19 (S4 B4a): `ApprovalFlow::open` builds the gate and its session (was inline
        // here: the same gate, the same `now`).
        let Ok(flow) = ApprovalFlow::open(shown, lang, item, connect, now) else {
            self.approval_open_failed();
            return;
        };
        self.evm.approval = Some(flow);
        self.emit(Effect::Approval(ApprovalEffect::Open {
            shown,
            lang,
            ai_reserved,
            connect: is_connect,
        }));
    }

    /// The answer to `Effect::Approval(Open)` (S4 B5). Made: the AI explanation joins the flow
    /// when its body was made, the flow takes the window's width class, then the open's log, the
    /// first view and the preparation, in the order of the code before B5. Not made: the flow
    /// ends (its `Close` finds no window and does nothing, critique A-3) and the item is rejected
    /// with E-APP-009, as `show_next_approval` did on `open_approval`'s `Err`. An answer for a
    /// window that is not the flow's is dropped.
    pub(crate) fn on_approval_opened(&mut self, shown: ShownId, outcome: OpenOutcome, wide: bool) {
        if self.evm.approval.as_ref().map(ApprovalFlow::shown) != Some(shown) {
            return;
        }
        match outcome {
            OpenOutcome::Shown { .. } => {
                if let Some(flow) = self.evm.approval.as_mut() {
                    // 2026-11-19 (S4 B4b): the AI panel's state is the flow's `AiFlow`, its body
                    // child and scroll the shell's `AiBody`, made in the open in the same order.
                    if let (Some(kind), Some(service)) =
                        (explain_kind(flow.item()), self.llm.as_ref())
                    {
                        self.llm_ui.next_window = self.llm_ui.next_window.saturating_add(1);
                        flow.attach_ai(AiFlow {
                            panel: AiPanel::new(true, flow.lang()),
                            serial: self.llm_ui.next_window,
                            host: service.host().to_owned(),
                            model: service.model().to_owned(),
                            kind,
                        });
                    }
                    flow.set_wide(wide);
                }
                logging::info("app", "approval.open", &[]);
                self.rebuild_view();
                #[cfg(test)]
                self.assert_flow_and_window_in_step();
                self.start_prepare();
            }
            OpenOutcome::Refused(_) | OpenOutcome::Failed(_) => {
                if let Some(flow) = self.evm.approval.take() {
                    self.emit(Effect::Approval(ApprovalEffect::Close {
                        shown: flow.shown(),
                    }));
                }
                self.approval_open_failed();
            }
        }
    }

    /// The shown item could not get its window: rejected, E-APP-009 (`show_next_approval`'s
    /// open-failure branch before S4 B5).
    fn approval_open_failed(&mut self) {
        if let Some((item, outcome)) = self.evm.queue.finish_shown(QueueOutcome::Rejected) {
            self.approval_finished(&item.payload, outcome);
        }
        self.error_banner(ErrorCode::App009);
    }

    fn start_prepare(&mut self) {
        let job = self.evm.job();
        let Some(flow) = self.evm.approval.as_mut() else {
            return;
        };
        let item = flow.item().clone();
        flow.begin_prepare(job, self.clock.now_ms());
        match item {
            QueuedItem::App(app) => self.prepare_transaction(job, &app, None),
            QueuedItem::Site(site) => self.prepare_site(job, &site),
            QueuedItem::Sol(sol) => self.prepare_sol(job, &sol),
            QueuedItem::Btc(btc) => self.prepare_btc(&btc),
            QueuedItem::Zec(zec) => self.prepare_zec(&zec),
            QueuedItem::HyperCore(item) => self.prepare_hypercore(&item),
        }
        self.rebuild_view();
    }

    /// Steps 3–10 of spec/03 §3.7 on the RPC worker, for an app send or a dApp transaction.
    fn prepare_transaction(&mut self, job: u64, item: &AppApproval, site: Option<&SiteRequest>) {
        // The journal did not open and its choice was closed: one fixed reason, not the
        // `공간이 부족합니다` an absent journal's room would otherwise end with.
        if self.evm.journal.is_none() && self.sidecar.journal_closed {
            self.show_failure(
                ErrorCode::Vlt006,
                false,
                crate::app_sidecar::text::JOURNAL_CLOSED_SEND
                    .get(self.approval_lang())
                    .to_owned(),
            );
            return;
        }
        let records = self.evm.records().to_vec();
        let room = self
            .evm
            .journal
            .as_ref()
            .is_some_and(|journal| journal.room);
        let chain = match self.chain_job(item.chain_id) {
            Ok(chain) => chain,
            Err(code) => {
                let failure =
                    crate::flow::evm::prepare::PrepareFailure::no_endpoint(self.approval_lang());
                let message = failure.message(self.approval_lang());
                self.show_failure(code, false, message);
                return;
            }
        };
        let Ok(id) = Self::new_approval_id() else {
            self.show_failure(
                ErrorCode::Vlt005,
                false,
                ErrorCode::Vlt005.text_in(self.approval_lang()),
            );
            return;
        };
        let address_book = self.address_book_facts();
        let (origin, extra_warnings) = match site {
            Some(site) => (
                self.site_approval_origin(site),
                site_fee_warning(self.approval_lang(), site),
            ),
            None => (yw_core::approval::ApprovalOrigin::App, Vec::new()),
        };
        let lang = self.approval_lang();
        let sent = self.rpc(RpcJob::Prepare(Box::new(PrepareJob {
            job,
            lang,
            chain,
            id,
            origin,
            account: item.account,
            signer: item.signer,
            intent: item.intent.clone(),
            replace: item.replace.clone(),
            records,
            journal_room: room,
            address_book,
            own_accounts: self.own_accounts(),
            known: self.known_addresses(),
            extra_warnings,
            limits: Limits::PRODUCTION,
        })));
        if !sent {
            self.show_failure(
                ErrorCode::Rpc001,
                true,
                ErrorCode::Rpc001.text_in(self.approval_lang()),
            );
        }
    }

    /// The dApp items: connect window content, transaction preparation, message drafts.
    #[expect(clippy::too_many_lines, reason = "one arm per dApp request kind")]
    fn prepare_site(&mut self, job: u64, site: &SiteRequest) {
        let now = self.clock.now_ms();
        match &site.kind {
            SiteKind::RequestAccounts
            | SiteKind::RequestPermissions
            | SiteKind::SolConnect
            | SiteKind::BtcConnect(_) => {
                self.evm.queue.mark_ready(now);
                let deadline = self
                    .evm
                    .queue
                    .shown_deadline()
                    .unwrap_or(now.saturating_add(120_000));
                if let Some(flow) = self.evm.approval.as_mut() {
                    flow.connect_ready(deadline, now);
                }
            }
            SiteKind::Send(tx) => {
                let Some(signer) = self.account_source(&tx.from) else {
                    self.show_failure(
                        ErrorCode::App009,
                        false,
                        ErrorCode::App009.text_in(self.approval_lang()),
                    );
                    return;
                };
                let item = AppApproval {
                    chain_id: site.chain_id,
                    account: tx.from,
                    signer,
                    intent: crate::flow::evm::prepare::SendIntent {
                        to: tx.to,
                        value: tx.value,
                        data: tx.data.clone(),
                        access_list: tx.access_list.clone(),
                        dapp_gas: tx.gas,
                        dapp_nonce: tx.nonce,
                    },
                    replace: None,
                };
                self.prepare_transaction(job, &item, Some(site));
            }
            SiteKind::PersonalSign { .. } | SiteKind::TypedData { .. }
                if self.message_chain_failure(site.chain_id).is_some() =>
            {
                // L12: a chain known to answer for another chain blocks signatures too (E34).
                if let Some(failure) = self.message_chain_failure(site.chain_id) {
                    self.show_failure(failure.code, false, failure.message(self.approval_lang()));
                }
            }
            SiteKind::PersonalSign { account, message } => {
                let decoded = yw_core::evm::eip191::decode_personal_message(message.clone());
                let draft = self.message_chain(site.chain_id).and_then(|chain| {
                    let signer = self.account_source(account)?;
                    let id = Self::new_approval_id().ok()?;
                    yw_core::evm::display::build_personal_request(
                        self.approval_lang(),
                        id,
                        self.site_approval_origin(site),
                        signer,
                        *account,
                        yw_core::approval::ApprovalKind::EvmPersonalSign,
                        &chain,
                        &decoded,
                        self.clock.now_unix_ms(),
                    )
                    .ok()
                });
                match draft {
                    Some(draft) => {
                        self.show_ready_draft(draft, None);
                        self.ai_ready_message();
                    }
                    None => self.show_failure(
                        ErrorCode::App009,
                        false,
                        ErrorCode::App009.text_in(self.approval_lang()),
                    ),
                }
            }
            SiteKind::TypedData {
                account,
                source,
                value,
            } => {
                let l1_origin = Self::hl_l1_origin(site);
                let requester = l1_origin.as_deref().map_or(
                    yw_core::evm::eip712::HlL1Requester::Nobody,
                    yw_core::evm::eip712::HlL1Requester::Origin,
                );
                let Ok(typed) = yw_core::evm::eip712::validate_typed_data_v4_from(
                    source,
                    value,
                    site.chain_id,
                    requester,
                ) else {
                    self.respond(
                        &site.reply,
                        Err(yw_core::policy::ProviderError::InvalidParams),
                    );
                    self.finish_approval(QueueOutcome::Cancelled);
                    return;
                };
                let typed = Box::new(typed);
                if let Some(flow) = self.evm.approval.as_mut() {
                    flow.set_typed(typed.clone());
                }
                // Without the lookups (no endpoint, no worker) the spender counts as a failed
                // lookup (`Unknown`, T18, fail closed).
                let mut unlooked = yw_core::approval::ChainFacts {
                    address_book: self.address_book_facts(),
                    own_accounts: self.own_accounts(),
                    ..yw_core::approval::ChainFacts::default()
                };
                if let Some(info) = crate::flow::evm::chain_info(&self.settings, site.chain_id) {
                    crate::flow::evm::prepare::typed_spender_unknown_unless_classified(
                        &mut unlooked,
                        &info,
                        &typed,
                    );
                }
                if let Ok(chain) = self.chain_job(site.chain_id) {
                    let sent = self.rpc(RpcJob::TypedFacts {
                        job,
                        chain,
                        account: *account,
                        typed,
                        address_book: unlooked.address_book.clone(),
                        own_accounts: unlooked.own_accounts.clone(),
                    });
                    if !sent {
                        self.on_typed_facts(job, &unlooked, None);
                    }
                } else {
                    self.on_typed_facts(job, &unlooked, None);
                }
            }
            SiteKind::SolTx { .. } => self.prepare_sol_dapp(job, site),
            SiteKind::SolSign { .. } | SiteKind::BtcSign { .. } => {
                match self.chain_sign_draft(site) {
                    Some(draft) => self.show_ready_draft(draft, None),
                    None => self.show_failure(
                        ErrorCode::App009,
                        false,
                        ErrorCode::App009.text_in(self.approval_lang()),
                    ),
                }
            }
            SiteKind::Revoke => self.finish_approval(QueueOutcome::Cancelled),
        }
    }

    /// spec/03 §1.4 (security review L12): message signatures (`personal_sign`,
    /// `eth_signTypedData_v4`) on a chain whose last check found `RpcMismatch` are blocked with
    /// E34 like a send. No RPC is called for a message, so only a known mismatch blocks.
    pub(crate) fn message_chain_failure(
        &self,
        chain_id: u64,
    ) -> Option<crate::flow::evm::prepare::PrepareFailure> {
        let lang = self.approval_lang();
        self.evm
            .blocked(chain_id)
            .map(|kind| crate::flow::evm::prepare::PrepareFailure::chain_mismatch(lang, kind))
    }

    /// The language of the open approval window (the app language before it opens): every
    /// display, warning and failure of its request is built in it (spec/14 §2).
    pub(crate) fn approval_lang(&self) -> Lang {
        self.evm
            .approval
            .as_ref()
            .map_or(self.settings.language, ApprovalFlow::lang)
    }

    /// The chain of a message signature: the registered definition with the verified genesis
    /// when known (the approval binds the chain, spec/03 §11.1).
    fn message_chain(&self, chain_id: u64) -> Option<yw_core::evm::chain::ChainInfo> {
        let info = crate::flow::evm::chain_info(&self.settings, chain_id)?;
        Some(match self.evm.chain_checks.get(&chain_id) {
            Some(crate::flow::evm::ChainCheck::Verified { genesis, .. }) => {
                crate::flow::evm::with_genesis(&info, *genesis)
            }
            _ => info,
        })
    }

    /// Typed-data facts arrived: build the draft (spec/03 §8). `check` is the chain check the
    /// lookups were made under (`None` without lookups): a chain found to answer for another
    /// chain — now or before — blocks with E34 like a send (spec/03 §1.4, L12).
    pub fn on_typed_facts(
        &mut self,
        job: u64,
        facts: &yw_core::approval::ChainFacts,
        check: Option<crate::flow::evm::ChainCheck>,
    ) {
        let Some(flow) = self.evm.approval.as_ref() else {
            return;
        };
        if flow.job() != job {
            return;
        }
        let (QueuedItem::Site(site), Some(typed)) =
            (flow.item().clone(), flow.typed().cloned().map(Box::new))
        else {
            return;
        };
        let SiteKind::TypedData { account, .. } = &site.kind else {
            return;
        };
        let mismatch = match check {
            Some(crate::flow::evm::ChainCheck::Mismatch(kind)) => {
                Some(crate::flow::evm::prepare::PrepareFailure::chain_mismatch(
                    self.approval_lang(),
                    kind,
                ))
            }
            _ => self.message_chain_failure(site.chain_id),
        };
        if let Some(failure) = mismatch {
            self.show_failure(failure.code, false, failure.message(self.approval_lang()));
            return;
        }
        // A Hyperliquid transfer gets the S-HC recipient and spotMeta checks (spec/11 §7); a
        // verified book entry's row says so (`✓ 확인됨`).
        let mut facts = facts.clone();
        facts.hyperliquid = self.hl_site_facts(&typed, account);
        facts.known = self.known_addresses();
        let facts = &facts;
        let draft = self.message_chain(site.chain_id).and_then(|chain| {
            let signer = self.account_source(account)?;
            let id = Self::new_approval_id().ok()?;
            yw_core::evm::display::build_typed_request(
                self.approval_lang(),
                id,
                self.site_approval_origin(&site),
                signer,
                *account,
                yw_core::approval::ApprovalKind::EvmTypedData,
                &chain,
                &typed,
                facts,
                self.clock.now_unix_ms(),
            )
            .ok()
        });
        match draft {
            Some(draft) => {
                self.show_ready_draft(draft, None);
                self.ai_ready_typed(facts);
            }
            None => self.show_failure(
                ErrorCode::App009,
                false,
                ErrorCode::App009.text_in(self.approval_lang()),
            ),
        }
    }

    pub(crate) fn show_failure(&mut self, code: ErrorCode, retryable: bool, text: String) {
        if let Some(flow) = self.evm.approval.as_mut() {
            flow.fail(text, code, retryable, self.clock.now_ms());
        }
        self.ai_ready(AiReady::Skip(SKIP_FAILED.get(self.approval_lang())));
        self.rebuild_view();
    }

    /// Closes the window without queue bookkeeping; a still-pending issued approval is rejected
    /// (it can never be consumed without its window).
    pub fn close_approval_window(&mut self) {
        // 2026-11-18 (S4 A7, critique A-2): the secret characterization's lock order.
        #[cfg(test)]
        crate::app::secret_seam::log(crate::app::secret_seam::Op::ApprovalClose {
            shown: self.evm.approval.is_some(),
        });
        // 2026-11-19 (S4 B4b): the flow and the shell state are taken together; the steps keep
        // their order (reject, AI close and its log, AI body, timer, panel, window).
        // 2026-11-19 (S4 B5): the flow ends here (reject, AI close and its log) and emits
        // `Effect::Approval(Close)`, whose executor arm (`close_approval_shell`) then drops the AI
        // body, stops the timer, destroys the panel and the window and raises the main window, in
        // that order (were inline here).
        if let Some(mut flow) = self.evm.approval.take() {
            if let Some(request) = flow.issued() {
                self.evm.store.reject(request.id);
            }
            // spec/06 §3.2: a result arriving after the window closed is dropped.
            if let Some(mut ai) = flow.take_ai()
                && let Some(ended) = ai.panel.close(self.clock.now_ms())
            {
                log_request(&ai.host, ai.kind, &ended, None);
            }
            self.emit(Effect::Approval(ApprovalEffect::Close {
                shown: flow.shown(),
            }));
        }
        #[cfg(test)]
        self.assert_flow_and_window_in_step();
    }

    /// Which approval window is shown, by the queue id of its request (2026-11-19, S4 F1, L-1,
    /// spec/04 §3.6). The later steps of one window message apply only while this is unchanged:
    /// an earlier step of the same message may have ended the request and opened the next
    /// request's window (`finish_approval` → `show_next_approval`).
    fn shown_window(&self) -> ShownWindow {
        if self.evm.approval.is_some() {
            ShownWindow::Showing(self.evm.queue.shown().map(|item| item.id))
        } else {
            ShownWindow::NoWindow
        }
    }

    fn finish_approval(&mut self, outcome: QueueOutcome) {
        let id = self
            .evm
            .approval
            .as_ref()
            .and_then(|flow| flow.issued().map(|request| request.id));
        if let Some(id) = id
            && outcome != QueueOutcome::Approved
        {
            self.evm.store.reject(id);
        }
        self.close_approval_window();
        if let Some((item, outcome)) = self.evm.queue.finish_shown(outcome) {
            self.approval_finished(&item.payload, outcome);
        }
        self.show_next_approval();
    }

    // ----- pipeline events ----------------------------------------------------------------

    /// `eth_simulateV1` started.
    pub fn on_simulating(&mut self, job: u64, since_ms: u64) {
        if let Some(flow) = self.evm.approval.as_mut()
            && flow.job() == job
        {
            flow.simulating(since_ms, self.clock.now_ms());
            self.rebuild_view();
        }
    }

    /// Preparation finished: issue at first Ready display (spec/03 §11.5).
    pub fn on_prepared(&mut self, result: PrepareResult) {
        self.apply_transitions(result.transitions.clone());
        let matches = self
            .evm
            .approval
            .as_ref()
            .is_some_and(|flow| flow.job() == result.job);
        if !matches {
            return;
        }
        match result.outcome {
            PrepareOutcome::Failed(failure) => {
                logging::warn(
                    "app",
                    "prepare.failed",
                    &[("code", Field::Code(failure.code))],
                );
                let site = self
                    .evm
                    .approval
                    .as_ref()
                    .and_then(|flow| match flow.item() {
                        QueuedItem::Site(site) => Some(site.reply),
                        QueuedItem::App(_)
                        | QueuedItem::Sol(_)
                        | QueuedItem::Btc(_)
                        | QueuedItem::Zec(_)
                        | QueuedItem::HyperCore(_) => None,
                    });
                if failure.invalid_params
                    && let Some(reply) = site
                {
                    // spec/03 §3.2: the dApp nonce differs — -32602 naming the rule (spec/05 §5
                    // `InvalidTxParams`), no failure window.
                    self.respond(
                        &reply,
                        Err(yw_core::policy::ProviderError::InvalidTxParams(
                            yw_core::policy::TxRule::Nonce,
                        )),
                    );
                    self.finish_approval(QueueOutcome::Cancelled);
                    return;
                }
                let text = failure.message(self.approval_lang());
                self.show_failure(failure.code, failure.retryable, text);
            }
            PrepareOutcome::Ready(prepared) => {
                if prepared.native_emitter_mismatch {
                    logging::info("app", "native-emitter-mismatch", &[]);
                }
                let draft = prepared.draft.clone();
                self.show_ready_draft(draft, Some(prepared));
                self.ai_ready_tx();
            }
        }
    }

    /// Issues a draft at its first Ready display (spec/03 §11.5). Transactions keep their
    /// preparation (signing, journal, re-simulation); messages have none.
    pub(crate) fn show_ready_draft(
        &mut self,
        draft: yw_core::approval::ApprovalDraft,
        prepared: Option<Box<Prepared>>,
    ) {
        self.show_ready_draft_at(draft, prepared, self.clock.now_unix_ms());
    }

    /// [`Self::show_ready_draft`] with the wall-clock display time given (the SOL intent binds
    /// it as `created_at_ms`, spec/07 §13.1-3).
    pub(crate) fn show_ready_draft_at(
        &mut self,
        draft: yw_core::approval::ApprovalDraft,
        prepared: Option<Box<Prepared>>,
        now_unix: u64,
    ) {
        let now = self.clock.now_ms();
        let mut draft = draft;
        let site_origin = self
            .evm
            .approval
            .as_ref()
            .and_then(|flow| match flow.item() {
                QueuedItem::Site(site) => Some(site.origin.clone()),
                _ => None,
            });
        if !self.wc_decorate_draft(site_origin.as_ref(), &mut draft) {
            // spec/13 §7: a WalletConnect request is never shown without its label and warning.
            logging::warn("app", "E-UI-001", &[("wc", Field::Word("label"))]);
            self.error_banner(ErrorCode::Ui001);
            self.finish_approval(QueueOutcome::Rejected);
            return;
        }
        let Ok(request) = self.evm.store.issue(draft, now, now_unix) else {
            self.show_failure(
                ErrorCode::App009,
                false,
                ErrorCode::App009.text_in(self.approval_lang()),
            );
            return;
        };
        if crate::ui::approval::validate_for_display(&request.display).is_err() {
            logging::warn("app", "E-UI-001", &[]);
            self.error_banner(ErrorCode::Ui001);
            self.finish_approval(QueueOutcome::Rejected);
            return;
        }
        self.evm.queue.mark_ready(now);
        let deadline = self
            .evm
            .queue
            .shown_deadline()
            .unwrap_or(now.saturating_add(120_000));
        if let Some(flow) = self.evm.approval.as_mut() {
            flow.show_ready(request, prepared, deadline, now);
        }
        self.rebuild_view();
    }

    /// Re-simulation finished (spec/03 §6.6-3/4, spec/04 §3.4).
    pub fn on_resimulated(&mut self, result: ResimResult) {
        let Some(flow) = self.evm.approval.as_ref() else {
            return;
        };
        if flow.job() != result.job {
            return;
        }
        let click = flow.resim_click();
        let Some(old) = flow.issued().cloned() else {
            return;
        };
        // A chain mismatch found now blocks like at preparation (`Failed`, only `거부`); it never
        // becomes an approvable "no simulation" warning.
        if let Some(failure) = result.failure.filter(|_| result.kind == ResimKind::Failed) {
            logging::warn(
                "app",
                "resim.failed",
                &[("code", Field::Code(failure.code))],
            );
            if let Some(flow) = self.evm.approval.as_mut() {
                flow.resim_failed();
            }
            self.show_failure(failure.code, false, failure.message(self.approval_lang()));
            return;
        }
        let Some(prepared) = result.prepared else {
            if let Some(flow) = self.evm.approval.as_mut() {
                // Same content, but a new approval (checkbox, arm delay, fresh interaction).
                flow.resim_no_result(self.clock.now_ms());
            }
            self.rebuild_view();
            return;
        };
        // The re-simulated draft is built afresh: a WalletConnect request gets its label and
        // Verify warning again (spec/13 §7), or is not shown.
        let mut draft = prepared.draft.clone();
        let site_origin = self
            .evm
            .approval
            .as_ref()
            .and_then(|flow| match flow.item() {
                QueuedItem::Site(site) => Some(site.origin.clone()),
                _ => None,
            });
        if !self.wc_decorate_draft(site_origin.as_ref(), &mut draft) {
            logging::warn("app", "E-UI-001", &[("wc", Field::Word("label"))]);
            self.error_banner(ErrorCode::Ui001);
            self.finish_approval(QueueOutcome::Rejected);
            return;
        }
        // The worker compared its undecorated draft with the shown request, which carries the
        // `WalletConnect` label and Verify warning: the stable part is compared again on the
        // decorated draft (an extension request is unchanged by decoration).
        let kind = match result.kind {
            ResimKind::Same | ResimKind::Changed => {
                if crate::flow::evm::prepare::stable_equal(&old, &draft) {
                    ResimKind::Same
                } else {
                    ResimKind::Changed
                }
            }
            other => other,
        };
        let replaced = self.evm.store.replace(old.id, old.digest, draft);
        let Ok(request) = replaced else {
            self.show_failure(
                ErrorCode::App009,
                false,
                ErrorCode::App009.text_in(self.approval_lang()),
            );
            return;
        };
        let now = self.clock.now_ms();
        if let Some(flow) = self.evm.approval.as_mut() {
            // The documented exception (plan H1): `issued` is the replaced request from here on,
            // the session keeps the drawn content until `resim_shown` below.
            flow.resim_replaced(request.clone(), prepared);
        }
        if click && kind == ResimKind::Same {
            self.consume_and_sign();
            return;
        }
        if let Some(flow) = self.evm.approval.as_mut() {
            flow.resim_shown(kind, request, now);
        }
        // spec/06 §3.2: a re-simulation that changes the input bytes re-requests.
        self.ai_ready_tx();
        self.rebuild_view();
    }

    fn approved(&mut self) {
        let now = self.clock.now_ms();
        let connect =
            self.evm
                .approval
                .as_ref()
                .and_then(|flow| match (flow.item(), flow.connect()) {
                    (QueuedItem::Site(site), Some(connect)) => {
                        Some((site.clone(), connect.clone()))
                    }
                    _ => None,
                });
        if let Some((site, connect)) = connect {
            if connect.gate_count() == 0 {
                return;
            }
            let choices: Vec<crate::app_chain_sites::ConnectChoice> = connect
                .accounts
                .iter()
                .zip(&connect.selected)
                .filter(|(_, checked)| **checked)
                .map(|((choice, _, _, _), _)| choice.clone())
                .collect();
            if connect.family == yw_core::policy::Family::Evm {
                // L4(c): the chain changed since the window was drawn — show the new one and
                // wait for a new click (re-armed), never store a chain the user did not see.
                // (2026-11-19, S4 F2, owner decision O-5: the click that found the change left
                // the interaction `Approved`, so `거부`, Escape and the window's own expiry did
                // nothing and only the close box or the main timer ended the window (L-2). A fresh
                // interaction first, then the arm delay: the redrawn chain needs a new armed
                // click at least 1 s later, as after a re-simulation that asks again (C1).)
                if self.refresh_connect_chain() {
                    if let Some(flow) = self.evm.approval.as_mut() {
                        flow.chain_changed_at_approve(now);
                    }
                    self.rebuild_view();
                    return;
                }
                let accounts = choices
                    .iter()
                    .filter_map(|choice| match choice {
                        crate::app_chain_sites::ConnectChoice::Evm(address) => Some(*address),
                        _ => None,
                    })
                    .collect();
                self.connect_approved(&site, accounts, connect.chain_id);
            } else {
                self.chain_connect_approved(&site, &choices);
            }
            self.finish_approval(QueueOutcome::Approved);
            return;
        }
        let Some(flow) = self.evm.approval.as_mut() else {
            return;
        };
        // C1: one approval is acted on once — a submission in flight (re-simulation or consume)
        // ignores any further approval until its result replaces or resets the content.
        if flow.submitting() {
            return;
        }
        let Some(request) = flow.issued().cloned() else {
            return;
        };
        if flow.prepared().is_none() {
            flow.begin_submit();
            self.consume_and_sign();
            return;
        }
        flow.begin_submit();
        flow.checking();
        let received = flow
            .prepared()
            .map_or(0, |prepared| prepared.sim_received_ms);
        if needs_resimulation(&request.simulation, received, now) {
            self.start_resimulation(true);
        } else {
            self.consume_and_sign();
        }
    }

    fn start_resimulation(&mut self, click: bool) {
        let job = self.evm.job();
        let address_book = self.address_book_facts();
        let Some(flow) = self.evm.approval.as_mut() else {
            return;
        };
        let (Some(request), Some(prepared)) = (
            flow.issued().cloned(),
            flow.prepared().cloned().map(Box::new),
        ) else {
            return;
        };
        flow.resim_requested(job, click);
        let chain_id = flow.item().chain_id();
        let extra_warnings = match flow.item() {
            QueuedItem::Site(site) => site_fee_warning(flow.lang(), site),
            QueuedItem::App(_)
            | QueuedItem::Sol(_)
            | QueuedItem::Btc(_)
            | QueuedItem::Zec(_)
            | QueuedItem::HyperCore(_) => Vec::new(),
        };
        let chain = match self.chain_job(chain_id) {
            Ok(chain) => chain,
            Err(code) => {
                let failure =
                    crate::flow::evm::prepare::PrepareFailure::no_endpoint(self.approval_lang());
                self.show_failure(code, false, failure.message(self.approval_lang()));
                return;
            }
        };
        let sent = self.rpc(RpcJob::Resimulate(Box::new(ResimJob {
            job,
            chain,
            request,
            context: prepared.context,
            address_book,
            extra_warnings,
            limits: Limits::PRODUCTION,
        })));
        if let Some(flow) = self.evm.approval.as_mut() {
            if sent {
                // C1: the approval that asked for this re-simulation has been acted on; the
                // terminal `Approved` status must not dispatch it again on the next tick.
                flow.resim_sent(self.clock.now_ms());
            } else {
                flow.resim_not_sent(self.clock.now_ms());
            }
        }
        self.rebuild_view();
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one branch per approval kind, in the order of spec/03 §11.5"
    )]
    fn consume_and_sign(&mut self) {
        let now = self.clock.now_ms();
        let Some(flow) = self.evm.approval.as_ref() else {
            return;
        };
        // `issued` is the consume handle (2026-11-19, S4 B4a: was `ApprovalUi.request`).
        let Some(request) = flow.issued().cloned() else {
            return;
        };
        let prepared = flow.prepared().cloned().map(Box::new);
        let item = flow.item().clone();
        match self.evm.store.consume(request.id, request.digest, now) {
            Ok(approved) => {
                logging::info(
                    "app",
                    "approval.consumed",
                    &[("net", Field::Net(item.network()))],
                );
                // An EVM dApp request's answer and the grant it needs: the signature or hash goes
                // to the site only while its grant still names the signing account (spec/05
                // §4.5, 2026-11-13).
                let site_answer = match (&item, approved.account()) {
                    (QueuedItem::Site(site), yw_core::approval::AccountRef::Evm(account)) => {
                        Some((
                            site.reply,
                            crate::app_browser::SiteSigner {
                                origin: site.origin.clone(),
                                account,
                            },
                        ))
                    }
                    _ => None,
                };
                if let QueuedItem::Sol(sol) = &item
                    && request.kind == yw_core::approval::ApprovalKind::SolTransfer
                {
                    self.sol_consumed(approved, sol.cluster, now);
                    self.finish_approval(QueueOutcome::Approved);
                    return;
                }
                if let QueuedItem::HyperCore(hypercore) = &item
                    && request.kind == yw_core::approval::ApprovalKind::HyperCoreAction
                {
                    self.hc_consumed(approved, hypercore);
                    self.finish_approval(QueueOutcome::Approved);
                    return;
                }
                if let QueuedItem::Btc(btc) = &item
                    && request.kind.is_btc()
                {
                    self.btc_consumed(approved, btc);
                    self.finish_approval(QueueOutcome::Approved);
                    return;
                }
                if let QueuedItem::Zec(zec) = &item
                    && request.kind == yw_core::approval::ApprovalKind::ZecSend
                {
                    self.zec_consumed(approved, zec);
                    self.finish_approval(QueueOutcome::Approved);
                    return;
                }
                // A dApp Solana transaction request (spec/07 §20.8): its own waiter and signer.
                if request.kind == yw_core::approval::ApprovalKind::SolTransaction {
                    let QueuedItem::Site(site) = &item else {
                        self.show_failure(
                            ErrorCode::App009,
                            false,
                            ErrorCode::App009.text_in(self.approval_lang()),
                        );
                        return;
                    };
                    self.sol_dapp_consumed(approved, site);
                    self.finish_approval(QueueOutcome::Approved);
                    return;
                }
                if request.kind.is_chain_message() {
                    let waiter = match &item {
                        QueuedItem::Site(site) => Self::chain_waiter(site, approved.payload()),
                        _ => None,
                    };
                    let Some(waiter) = waiter else {
                        self.show_failure(
                            ErrorCode::App009,
                            false,
                            ErrorCode::App009.text_in(self.approval_lang()),
                        );
                        return;
                    };
                    let ticket = self.push_sign_waiter(waiter);
                    // A YubiKey account signs on the card after its PIN (spec/10 §10).
                    if let Err(approved) = self.card_begin(
                        approved,
                        crate::app_card::CardJobKind::ChainMessage,
                        Some(ticket),
                    ) {
                        self.key(KeyJob::SignChainMessage { ticket, approved });
                    }
                    self.finish_approval(QueueOutcome::Approved);
                    return;
                }
                match (prepared, request.kind) {
                    (
                        _,
                        kind @ (yw_core::approval::ApprovalKind::EvmPersonalSign
                        | yw_core::approval::ApprovalKind::EvmTypedData),
                    ) => {
                        let waiter = match (&item, site_answer) {
                            (QueuedItem::Site(_), Some((reply, signer))) => {
                                crate::app_browser::SignWaiter::Message(reply, signer)
                            }
                            (QueuedItem::Site(_), None) => {
                                self.show_failure(
                                    ErrorCode::App009,
                                    false,
                                    ErrorCode::App009.text_in(self.approval_lang()),
                                );
                                return;
                            }
                            _ => crate::app_browser::SignWaiter::App,
                        };
                        let ticket = self.push_sign_waiter(waiter);
                        let typed = kind == yw_core::approval::ApprovalKind::EvmTypedData;
                        // A YubiKey account signs on the card after its PIN (spec/10 §9.2).
                        if let Err(approved) = self.card_begin(
                            approved,
                            crate::app_card::CardJobKind::EvmMessage { typed },
                            Some(ticket),
                        ) {
                            self.key(KeyJob::SignMessage {
                                ticket,
                                approved,
                                typed,
                            });
                        }
                    }
                    (Some(prepared), _) => {
                        let (origin, waiter) = match &item {
                            QueuedItem::Site(site) => {
                                let Some((reply, signer)) = site_answer else {
                                    self.show_failure(
                                        ErrorCode::App009,
                                        false,
                                        ErrorCode::App009.text_in(self.approval_lang()),
                                    );
                                    return;
                                };
                                (
                                    self.site_origin_text(site),
                                    crate::app_browser::SignWaiter::Tx(reply, signer),
                                )
                            }
                            QueuedItem::App(_)
                            | QueuedItem::Sol(_)
                            | QueuedItem::Btc(_)
                            | QueuedItem::Zec(_)
                            | QueuedItem::HyperCore(_) => {
                                ("yw-app".to_owned(), crate::app_browser::SignWaiter::App)
                            }
                        };
                        let ticket = self.push_sign_waiter(waiter);
                        let info = SignInfo {
                            origin,
                            label: request.display.title.clone(),
                            role: prepared.context.role,
                            now_unix_ms: self.clock.now_unix_ms(),
                        };
                        // The S11 send: an app item that replaces nothing (speed-up and cancel
                        // come from the activity list).
                        let form = matches!(&item, QueuedItem::App(app) if app.replace.is_none());
                        self.dispatch_evm_sign(ticket, approved, info, form);
                    }
                    (None, _) => {
                        self.show_failure(
                            ErrorCode::App009,
                            false,
                            ErrorCode::App009.text_in(self.approval_lang()),
                        );
                        return;
                    }
                }
                self.finish_approval(QueueOutcome::Approved);
            }
            Err(_) => {
                self.show_failure(
                    ErrorCode::App009,
                    false,
                    ErrorCode::App009.text_in(self.approval_lang()),
                );
            }
        }
    }

    /// The signing job of a consumed EVM transaction approval: `SignEvm`, or — for a `YubiKey`
    /// account (`EvmKeySource::Hardware`) — the card step: the PIN window, then `SignEvmCard`
    /// (spec/10 §9.2). The job's send slot is noted by `ticket` (released when this job ends
    /// without a signature, spec/03 §3.6); `form` marks the S11 send.
    pub(crate) fn dispatch_evm_sign(
        &mut self,
        ticket: crate::events::SignTicket,
        approved: yw_core::approval::Approved,
        info: SignInfo,
        form: bool,
    ) {
        if let (
            yw_core::approval::ChainRef::Evm { chain_id, .. },
            yw_core::approval::AccountRef::Evm(account),
        ) = (approved.chain(), approved.account())
        {
            self.evm.signing.insert(
                ticket,
                crate::app_evm::SigningSlot {
                    chain_id,
                    account,
                    form,
                },
            );
        }
        if crate::yubikey::approval_role(&approved).is_none() {
            self.key(KeyJob::SignEvm {
                ticket,
                approved: Box::new(approved),
                info,
            });
            return;
        }
        let kind = crate::app_card::CardJobKind::EvmTx { info };
        if let Err(approved) = self.card_begin(approved, kind, Some(ticket)) {
            // Not reached (the role was checked); never signed in software by accident.
            drop(approved);
            self.browser_sign_cancelled(ticket);
            self.release_signing(ticket);
        }
    }

    /// Main-timer part: deadlines, re-arming, the simulation countdown.
    pub fn tick_approval(&mut self, now: u64) {
        self.card_tick(now);
        let finished = self.evm.queue.tick(now);
        let _ = self.evm.store.expire_due(now);
        let shown_gone = self.evm.queue.shown().is_none() && self.evm.approval.is_some();
        for (item, outcome) in finished {
            self.approval_finished(&item.payload, outcome);
        }
        if shown_gone {
            self.close_approval_window();
            self.show_next_approval();
        }
    }

    fn interaction(&mut self, event: InteractionEvent) {
        #[cfg(test)]
        self.assert_flow_and_window_in_step();
        let now = self.clock.now_ms();
        // 2026-11-19 (S4 B4b): the flow from `EvmUi.approval`, the window from `App.approval_win`.
        let (Some(flow), Some(win)) = (self.evm.approval.as_mut(), self.approval_win.as_ref())
        else {
            #[cfg(test)]
            flow_support::log_input(flow_support::Logged::Event {
                event,
                foreground: None,
                focus: None,
            });
            return;
        };
        // A false → true edge (activation, also within this process) restarts the arm delay.
        // The gate's foreground sample, taken before the event (2026-11-19, S4 B2: through
        // `TrustedSignals`, was `window_is_foreground`; B2 review: a getter, the field is private).
        let foreground = TrustedSignals::sample_foreground(&win.window).foreground();
        #[cfg(test)]
        flow_support::log_input(flow_support::Logged::Event {
            event,
            foreground: Some(foreground),
            focus: Some(win.focus),
        });
        // 2026-11-19 (S4 B4a): the foreground sample, the event, the early-release note and
        // `status_action` run in `ApprovalFlow::on_event`, in this order (were inline here).
        match flow.on_event(now, foreground, event) {
            StatusAction::Approve => self.approved(),
            StatusAction::Expire => self.finish_approval(QueueOutcome::Expired),
            StatusAction::Reject => {
                logging::info("app", "approval.rejected", &[]);
                self.finish_approval(QueueOutcome::Rejected);
            }
            StatusAction::Repaint => {
                // Only the bottom bar changes with interaction events and ticks: repaint just it,
                // and only when what it shows changed (no full-window redraw every 50 ms).
                // 2026-11-19 (S4 B5): `Effect::Approval(RepaintBar)`, applied at once by
                // `approval_repaint_bar` (the same code, was inline here).
                if let Some(shown) = self.evm.approval.as_ref().map(ApprovalFlow::shown) {
                    self.emit(Effect::Approval(ApprovalEffect::RepaintBar { shown }));
                }
            }
            StatusAction::Nothing => {}
        }
    }

    fn rebuild_view(&mut self) {
        self.rebuild_view_with(true);
    }

    /// Rebuilds the view; with `force == false` (the simulation countdown tick) nothing is
    /// invalidated when the rebuilt view is the one already shown.
    #[expect(
        clippy::too_many_lines,
        reason = "badges, connect view and signing view of every queue item kind"
    )]
    fn rebuild_view_with(&mut self, force: bool) {
        let now = self.clock.now_ms();
        self.refresh_connect_chain();
        let testnet_chain = self.evm.approval.as_ref().map(|flow| match flow.connect() {
            Some(connect) if connect.family == yw_core::policy::Family::Evm => connect.chain_id,
            _ => flow.item().chain_id(),
        });
        let Some(chain_id) = testnet_chain else {
            return;
        };
        let mut badges = Vec::new();
        let family = match self.evm.approval.as_ref().map(ApprovalFlow::item) {
            Some(QueuedItem::Site(site)) => site.kind.family(),
            _ => yw_core::policy::Family::Evm,
        };
        if family == yw_core::policy::Family::Evm
            && self
                .settings
                .evm_chains
                .iter()
                .any(|def| def.chain_id == chain_id)
        {
            badges.push(crate::ui::screens_evm::custom_chain_badge(
                self.evm
                    .approval
                    .as_ref()
                    .map_or(self.settings.language, ApprovalFlow::lang),
                chain_id,
            ));
        }
        let (evm_chain, sol_cluster) =
            match (self.evm.approval.as_ref().map(ApprovalFlow::item), family) {
                (Some(QueuedItem::Sol(item)), _) => (None, Some(item.cluster)),
                // A dApp transaction shows the cluster it is bound to, whatever is selected now.
                (Some(QueuedItem::Site(site)), yw_core::policy::Family::Solana) => match &site.kind
                {
                    SiteKind::SolTx { cluster, .. } => (None, Some(*cluster)),
                    _ => (None, Some(self.sol_cluster())),
                },
                (Some(QueuedItem::Site(_)), yw_core::policy::Family::Bitcoin)
                | (
                    Some(QueuedItem::Btc(_) | QueuedItem::Zec(_) | QueuedItem::HyperCore(_)) | None,
                    _,
                ) => (None, None),
                (Some(QueuedItem::App(_) | QueuedItem::Site(_)), _) => (Some(chain_id), None),
            };
        let site_btc_banner = (family == yw_core::policy::Family::Bitcoin)
            .then(|| crate::ui::approval_view::BtcBanner::of(self.btc_network_now()));
        let chain_badge = match (self.evm.approval.as_ref().map(ApprovalFlow::item), family) {
            (Some(QueuedItem::Btc(item)), _) => Some(Badge::bitcoin(item.network)),
            (Some(QueuedItem::Site(_)), yw_core::policy::Family::Bitcoin) => {
                Some(Badge::bitcoin(self.btc_network_now()))
            }
            _ => sol_cluster.map(Badge::solana).or_else(|| {
                evm_chain.map(|id| {
                    Badge::evm(
                        id,
                        &self.network_name(crate::network::NetworkId::Eip155(id)),
                    )
                })
            }),
        };
        let mut testnet = false;
        let lang = self
            .evm
            .approval
            .as_ref()
            .map_or(self.settings.language, ApprovalFlow::lang);
        if let Some((badge, test)) = network_badge(lang, evm_chain, sol_cluster) {
            testnet = test;
            badges.push(badge.to_owned());
        }
        // HyperCore (spec/11 §6): the same mainnet / testnet badges as the EVM chains.
        if let Some(QueuedItem::HyperCore(item)) =
            self.evm.approval.as_ref().map(ApprovalFlow::item)
        {
            if item.action.network == yw_core::hypercore::HcNetwork::Testnet {
                testnet = true;
                badges.push(text::BADGE_HC_TESTNET.get(lang).to_owned());
            } else {
                badges.push(text::BADGE_MAINNET.get(lang).to_owned());
            }
        }
        // spec/10 §10: a YubiKey signer adds the "YubiKey로 서명" badge (app chrome only: the
        // badges are not part of the request's digested display, spec/03 §11.3).
        let card_badge = self.evm.approval.as_ref().and_then(|flow| {
            let (role, touches) = match (flow.item(), &flow.gate().prepare) {
                (QueuedItem::Btc(item), _) => (
                    crate::yubikey::btc_plan_role(&item.plan)?,
                    item.plan.inputs().len(),
                ),
                (QueuedItem::Zec(item), _) => (
                    crate::yubikey::zec_plan_role(&item.plan)?,
                    item.plan.inputs.len(),
                ),
                // A sign-only Solana dApp request: one touch per transaction.
                (_, PrepareState::Ready(ReadyContent::Signing(request))) => (
                    crate::yubikey::role_of(&request.signer, &request.payload)?,
                    match &request.payload {
                        yw_core::approval::SigningPayload::SolTx(payload) => payload.items.len(),
                        _ => 1,
                    },
                ),
                _ => return None,
            };
            Some(crate::app_card::card_badge(
                lang,
                (&self.card.records, self.card_names()),
                role,
                touches,
            ))
        });
        badges.extend(card_badge);
        // WalletConnect sessions (spec/13 §7): the claimed origin, chains and Verify state.
        let wc_patch = self
            .evm
            .approval
            .as_ref()
            .and_then(|flow| match flow.item() {
                QueuedItem::Site(site) => self.wc_connect_patch(&site.origin),
                _ => None,
            });
        // 2026-11-19 (S4 B4b): the view is the flow's, the invalidations the window's.
        // 2026-11-19 (S4 B5): the width class is the flow's (`wide`, reported by the shell when
        // the window opened and at each A01 size or DPI change; was read here from the window),
        // and a rebuilt view is `Effect::Approval(Rebuilt)` (`approval_rebuilt`: layout dropped,
        // window, panel and AI body invalidated; was inline here). The flow and the window are
        // shown together, so the guard on the window is the guard on the flow.
        let Some(flow) = self.evm.approval.as_mut() else {
            return;
        };
        let shown = flow.shown();
        let wide_layout = flow.wide();
        if let QueuedItem::Site(site) = flow.item() {
            if crate::walletconnect::is_session_origin(&site.origin) {
                badges.insert(0, text::BADGE_WALLETCONNECT.get(lang).to_owned());
            }
            // spec/05 §2.12: after the http/punycode badges, connect and approval views alike.
            if let Some(mode) = site.compat_mode {
                badges.insert(0, crate::ui::approval_view::compat_mode_badge(lang, mode));
            }
            if let (Some(connect), PrepareState::Ready(ReadyContent::Connect(_))) =
                (flow.connect(), &flow.gate().prepare)
            {
                let accounts: Vec<(String, String)> = connect
                    .accounts
                    .iter()
                    .map(|(_, label, address, _)| (label.clone(), address.clone()))
                    .collect();
                let mut connect_view = crate::ui::approval_view::connect_view(
                    lang,
                    site.origin.as_str(),
                    site.origin.is_http(),
                    &accounts,
                    &connect.selected,
                    &connect.chain_name,
                    connect.family,
                );
                if let Some(patch) = &wc_patch {
                    patch.apply(&mut connect_view);
                }
                connect_view.badges.extend(badges);
                order_badges(&mut connect_view.badges);
                connect_view.testnet = testnet;
                connect_view.chain = chain_badge;
                flow.set_view(connect_view);
                // A connect window has no AI body (spec/06 §3.1), so `Rebuilt` invalidates the
                // window and the panel only, as before.
                self.emit(Effect::Approval(ApprovalEffect::Rebuilt {
                    shown,
                    changed: true,
                }));
                return;
            }
            let mut site_badges = Vec::new();
            if site.origin.is_http() {
                site_badges.push(text::BADGE_HTTP.get(lang).to_owned());
            }
            if site
                .origin
                .host()
                .split('.')
                .any(|label| label.starts_with("xn--"))
            {
                site_badges.push(text::BADGE_PUNYCODE.get(lang).to_owned());
            }
            site_badges.extend(badges);
            badges = site_badges;
        }
        let btc_banner = match flow.item() {
            QueuedItem::Btc(item) => Some(crate::ui::approval_view::BtcBanner::of(item.network)),
            QueuedItem::Site(_) => site_btc_banner,
            QueuedItem::App(_)
            | QueuedItem::Sol(_)
            | QueuedItem::Zec(_)
            | QueuedItem::HyperCore(_) => None,
        };
        match view(
            lang,
            &flow.gate().prepare,
            now,
            flow.raw_open(),
            wide_layout,
            badges,
            testnet,
            flow.failure(),
        ) {
            Ok(mut view) => {
                order_badges(&mut view.badges);
                view.btc_banner = btc_banner;
                view.chain = chain_badge;
                // W-ADDR-3 under the recipient (spec/04 §3.3, outside the digest).
                let note = match flow.item() {
                    QueuedItem::Btc(item) => item.look_alike.as_deref(),
                    QueuedItem::Zec(item) => item.look_alike.as_deref(),
                    QueuedItem::App(_)
                    | QueuedItem::Site(_)
                    | QueuedItem::Sol(_)
                    | QueuedItem::HyperCore(_) => None,
                };
                if let Some(note) = note {
                    crate::ui::approval_view::attach_address_note(&mut view, lang, note);
                }
                if !force && view == *flow.view() {
                    self.emit(Effect::Approval(ApprovalEffect::Rebuilt {
                        shown,
                        changed: false,
                    }));
                    return;
                }
                flow.set_view(view);
                // The risk level or the acknowledgement may have changed (held_for_ack): the AI
                // body is invalidated too.
                self.emit(Effect::Approval(ApprovalEffect::Rebuilt {
                    shown,
                    changed: true,
                }));
            }
            Err(code) => {
                logging::warn("app", "E-UI-001", &[]);
                self.error_banner(code);
                self.finish_approval(QueueOutcome::Rejected);
            }
        }
    }

    // ----- the approval window (shell) ----------------------------------------------------

    /// Applies one `Effect::Approval` (S4 B5; called by the executor `App::emit`, at once and in
    /// emission order). Returns the open's answer, which the executor feeds back at once.
    pub(crate) fn apply_approval_effect(&mut self, effect: ApprovalEffect) -> Option<Cmd> {
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
        }
    }

    /// `Effect::Approval(Open)`: A01 (topmost), its panel and, when reserved, the AI body, in this
    /// order; then centred on the main window, the 50 ms timer, shown, brought to the foreground
    /// or flashed, focus on `거부` (reject-first), and the width class measured. Any window that
    /// cannot be made drops the ones made before it (panel before A01, as before) and the open
    /// answers `Failed(E-APP-009)`. 2026-11-19 (S4 B5): this was the window part of
    /// `open_approval`, the same calls in the same order (the flow, made there before B5 between
    /// the AI body and the centring, is now made before the open is asked for).
    fn open_approval_window(
        &mut self,
        shown: ShownId,
        lang: Lang,
        ai_reserved: bool,
        connect: bool,
    ) -> (OpenOutcome, bool) {
        const FAILED: (OpenOutcome, bool) = (OpenOutcome::Failed(ErrorCode::App009), false);
        let handler = Box::new(Forward {
            app: self.self_ref.clone(),
            target: Target::Approval,
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
            target: Target::Panel,
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
                target: Target::AiBody,
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

    /// The flow (`EvmUi.approval`) and the window's shell state (`App.approval_win`) are set and
    /// taken together (2026-11-19, S4 B4 review). Test builds check it where they change and
    /// where a window event reaches the flow, so a flow left without its window (or a window
    /// without its flow) fails the tests: the recorders print both cases like a closed window.
    /// 2026-11-19 (S4 B5): checked at the end of the open's answer (was the end of
    /// `open_approval`), and kept here because the flow-only functions name no window.
    #[cfg(test)]
    fn assert_flow_and_window_in_step(&self) {
        assert_eq!(
            self.evm.approval.is_some(),
            self.approval_win.is_some(),
            "the approval flow and its window are out of step"
        );
    }

    // ----- window messages ----------------------------------------------------------------

    fn toggle_ack(&mut self) {
        #[cfg(test)]
        self.log_approval_call(flow_support::Call::ToggleAck);
        let now = self.clock.now_ms();
        if let (Some(flow), Some(win)) = (self.evm.approval.as_mut(), self.approval_win.as_mut())
            && flow.toggle_ack(now)
        {
            win.layout = None;
            win.panel.invalidate();
            win.window.invalidate();
            // A High-risk request's AI panel waits for this checkbox (held_for_ack).
            if let Some(ai) = win.ai.as_ref() {
                ai.body.invalidate();
            }
        }
    }

    fn toggle_connect_account(&mut self, index: usize) {
        #[cfg(test)]
        self.log_approval_call(flow_support::Call::ToggleAccount(index));
        let now = self.clock.now_ms();
        if let Some(flow) = self.evm.approval.as_mut() {
            flow.toggle_account(index, now);
        }
        self.rebuild_view();
    }

    fn toggle_raw(&mut self) {
        #[cfg(test)]
        self.log_approval_call(flow_support::Call::ToggleRaw);
        if let Some(flow) = self.evm.approval.as_mut() {
            flow.toggle_raw();
        }
        self.rebuild_view();
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

    pub(crate) fn on_approval_msg(&mut self, window: &Window, msg: &Msg) -> Reply {
        self.on_surface_msg(Surface::Approval, window, msg)
    }

    /// One message of `surface`: sample, map, run.
    fn on_surface_msg(&mut self, surface: Surface, window: &Window, msg: &Msg) -> Reply {
        let signals = TrustedSignals::sample_on_arrival(surface, msg, window);
        let facts = self.input_facts(msg);
        let Mapped { steps, reply } = map_msg(surface, msg, facts, signals);
        self.run_steps(surface, Some(window), &steps)
            .unwrap_or(reply)
    }

    /// What A01 is when a message arrives (`None`: no window): its focus, its pressed button
    /// and, for a mouse message, the bottom-bar buttons that contain the point.
    fn input_facts(&self, msg: &Msg) -> Option<Facts> {
        let win = self.approval_win.as_ref()?;
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
    /// the window that got it (`None` only for `on_approval_key`'s keys, whose steps need none).
    fn run_steps(
        &mut self,
        surface: Surface,
        window: Option<&Window>,
        steps: &[Step],
    ) -> Option<Reply> {
        // The window shown when the message arrived (S4 F1, L-1).
        let shown = self.shown_window();
        for step in steps {
            if let Some(reply) = self.run_step(surface, window, shown, *step) {
                return Some(reply);
            }
        }
        None
    }

    #[expect(clippy::too_many_lines, reason = "one arm per mapped step")]
    fn run_step(
        &mut self,
        surface: Surface,
        window: Option<&Window>,
        shown: ShownWindow,
        step: Step,
    ) -> Option<Reply> {
        match step {
            Step::Event(event) => self.interaction(event),
            // The only delivery of an approving or holding event (source check S8; 2026-11-19,
            // S4 B2 review: `Trusted::deliver` samples and builds in one call, was
            // `TrustedSignals::sample_for` then a `pub` `Trusted::event`).
            Step::Sampled(trusted) => self.interaction(trusted.deliver(window)),
            Step::Activated => {
                #[cfg(test)]
                flow_support::log_input(flow_support::Logged::Activated {
                    focus: self.approval_win.as_ref().map(|win| win.focus),
                });
                if let Some(flow) = self.evm.approval.as_mut() {
                    flow.activated(self.clock.now_ms());
                }
            }
            Step::Close => {
                // 2026-11-19 (S4 F1, L-1, owner decision O-4): the close box rejects only the
                // request this window showed. Before, `if self.evm.window.is_some()` also
                // rejected the next request, whose window `RejectActivated` had just opened.
                // A window whose `RejectActivated` changes nothing (L-2: already `Approved`)
                // still shows the same request, so the close box still ends it.
                let shown = self.shown_window();
                self.interaction(InteractionEvent::RejectActivated);
                if shown != ShownWindow::NoWindow && self.shown_window() == shown {
                    self.finish_approval(QueueOutcome::Rejected);
                }
            }
            Step::ToggleAck => self.toggle_ack(),
            Step::ToggleRaw => self.toggle_raw(),
            Step::ToggleAccount(index) => self.toggle_connect_account(index),
            Step::Retry => self.retry_action(),
            Step::AiRetry => self.ai_retry(),
            Step::SameWindow(reply) => {
                // 2026-11-19 (S4 F1, L-1): a press that ended this request (past its deadline)
                // goes no further, like a press with no window. Before, the rest of the message
                // ran on the next request's window that the press had just opened.
                if self.shown_window() != shown || self.evm.approval.is_none() {
                    return Some(reply);
                }
            }
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
                if let (Some(flow), Some(win)) =
                    (self.evm.approval.as_ref(), self.approval_win.as_mut())
                {
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
                for step in panel_click(hit) {
                    if let Some(reply) = self.run_step(surface, window, shown, step) {
                        return Some(reply);
                    }
                }
            }
            Step::AiExpand => {
                // 2026-11-19 (S4 B4b): the panel state is the flow's `AiFlow`, the body's scroll
                // the shell's `AiBody`.
                if let Some(ai) = self.evm.approval.as_mut().and_then(ApprovalFlow::ai_mut)
                    && ai.panel.toggle_expanded()
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
                if let Some(win) = self.approval_win.as_mut() {
                    win.layout = None;
                    // 2026-11-19 (S4 B5): the width class goes to the flow here, where the
                    // rebuild below read it from the window before B5 (B6: `Resized`).
                    let wide = win.is_wide();
                    if let Some(flow) = self.evm.approval.as_mut() {
                        flow.set_wide(wide);
                    }
                }
                self.rebuild_view();
            }
            Step::TimerTail => {
                self.ai_tick(self.clock.now_ms());
                if let Some(flow) = self.evm.approval.as_ref()
                    && matches!(
                        flow.gate().prepare,
                        PrepareState::Preparing(PrepareStage::Simulating { .. })
                    )
                {
                    self.rebuild_view_with(false);
                }
            }
        }
        None
    }

    fn retry_action(&mut self) {
        #[cfg(test)]
        self.log_approval_call(flow_support::Call::Retry);
        let failed_retryable = self.evm.approval.as_ref().is_some_and(|flow| {
            matches!(
                flow.gate().prepare,
                PrepareState::Failed {
                    retryable: true,
                    ..
                }
            )
        });
        if failed_retryable {
            self.start_prepare();
        } else {
            self.start_resimulation(false);
        }
    }

    /// An A01 `WM_KEYDOWN` without its window (the flow tests' key entry): the same map and steps
    /// as `on_approval_msg` (2026-11-19, S4 B2: production keys come through `map_msg`).
    #[cfg(test)]
    fn on_approval_key(&mut self, vk: u16, repeat: bool) {
        let steps = crate::ui::approval_input::map_key(
            vk,
            repeat,
            self.input_facts(&Msg::KeyDown { vk, repeat }),
        );
        let _ = self.run_steps(Surface::Approval, None, &steps);
    }

    pub(crate) fn on_panel_msg(&mut self, window: &Window, msg: &Msg) -> Reply {
        self.on_surface_msg(Surface::Panel, window, msg)
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
            .is_none_or(crate::explain::ExplainService::busy);
        let lang = self.approval_lang();
        let Self {
            evm,
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
                crate::ui::approval::labels::ORIGIN
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
                    label == crate::ui::approval::labels::NETWORK.get(paint.lang)
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
            Some(crate::ui::approval_view::BtcBanner::Mainnet) => (
                theme::BTC_MAINNET_BG,
                theme::BTC_MAINNET_TEXT,
                theme::BTC_MAINNET_TEXT,
            ),
            Some(crate::ui::approval_view::BtcBanner::Testnet4) => {
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
                            == Some(crate::ui::approval_view::BtcBanner::Mainnet)
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

    /// Paints the AI panel body (spec/06 §6): plain text laid out by `ui::text_layout`, wrapped
    /// only; no links, formatting, click actions or copy.
    fn paint_ai_body(&mut self, window: &Window) {
        let now = self.clock.now_ms();
        let dpi = window.dpi();
        let client = window.client_rect();
        let lang = self.approval_lang();
        let Self {
            evm,
            fonts,
            approval_win,
            ..
        } = self;
        let Some(fonts) = fonts.for_dpi(dpi, lang) else {
            return;
        };
        let (Some(flow), Some(win)) = (evm.approval.as_mut(), approval_win.as_mut()) else {
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
        // A High-risk request shows its warnings first: the AI text waits for the
        // acknowledgement checkbox (the panel keeps its reserved place). (2026-11-19, S4 B4b:
        // `ApprovalFlow::hold_ai_for_ack` sets it from the issued request and the gate, then the
        // body paints from `ApprovalPaint`; was `ai.panel.set_held(held_for_ack(..))` here.)
        if !flow.hold_ai_for_ack() {
            return;
        }
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

    pub(crate) fn on_ai_body_msg(&mut self, window: &Window, msg: &Msg) -> Reply {
        self.on_surface_msg(Surface::AiBody, window, msg)
    }

    fn ai_scroll_by(&mut self, window: &Window, delta: i32) {
        if let Some(ai) = self.approval_win.as_mut().and_then(|win| win.ai.as_mut()) {
            ai.scroll = ai.scroll.saturating_add(delta).max(0);
            window.invalidate();
        }
    }

    // ----- AI explanation (spec/06) -------------------------------------------------------

    fn llm_busy(&self) -> bool {
        self.llm
            .as_ref()
            .is_none_or(crate::explain::ExplainService::busy)
    }

    /// Logs an ended request and hands a new one to the worker.
    fn ai_after(
        &mut self,
        ended: Option<Ended>,
        dispatch: Option<Dispatch>,
        stats: Option<&RequestStats>,
    ) {
        let now = self.clock.now_ms();
        let Self {
            evm,
            llm,
            approval_win,
            ..
        } = self;
        let Some(ai) = evm.approval.as_mut().and_then(ApprovalFlow::ai_mut) else {
            return;
        };
        if let Some(ended) = ended {
            log_request(&ai.host, ai.kind, &ended, stats);
        }
        if let Some(dispatch) = dispatch {
            let generation = dispatch.generation;
            let job = LlmJob {
                window: ai.serial,
                generation,
                input: dispatch.input,
            };
            let sent = llm.as_ref().is_some_and(|service| service.submit(job));
            if !sent
                && let Some(ended) = ai
                    .panel
                    .on_result(now, generation, Err(ExplainError::Network))
            {
                log_request(&ai.host, ai.kind, &ended, None);
            }
        }
        if let Some(win) = approval_win.as_ref() {
            if let Some(ai_child) = win.ai.as_ref() {
                ai_child.body.invalidate();
            }
            win.window.invalidate();
        }
    }

    fn ai_ready(&mut self, ready: AiReady) {
        let now = self.clock.now_ms();
        let busy = self.llm_busy();
        let Some(ai) = self.evm.approval.as_mut().and_then(ApprovalFlow::ai_mut) else {
            return;
        };
        let (ended, dispatch) = match ready {
            AiReady::Input(Ok(input)) => ai.panel.set_input(now, input, busy),
            AiReady::Input(Err(error)) => (ai.panel.input_failed(now, error), None),
            AiReady::Skip(text) => (ai.panel.skip(now, text), None),
        };
        self.ai_after(ended, dispatch, None);
    }

    /// A dApp transaction reached Ready (first display or re-simulation): the input from the
    /// wallet's decoding and the simulation status (spec/06 §3.1, §4.3).
    fn ai_ready_tx(&mut self) {
        let ready = {
            let Some(flow) = self.evm.approval.as_ref() else {
                return;
            };
            if flow.ai().is_none() {
                return;
            }
            let (QueuedItem::Site(site), Some(prepared), Some(request)) =
                (flow.item(), flow.prepared(), flow.issued())
            else {
                return;
            };
            let yw_core::approval::AccountRef::Evm(user) = request.account else {
                return;
            };
            if request.display.risk == RiskLevel::Blocked {
                AiReady::Skip(SKIP_BLOCKED.get(self.approval_lang()))
            } else {
                crate::app_llm::transaction_input(
                    self.approval_lang(),
                    prepared,
                    &self.site_origin_text(site),
                    &user,
                )
                .map_or(
                    AiReady::Skip(SKIP_BLOCKED.get(self.approval_lang())),
                    AiReady::Input,
                )
            }
        };
        self.ai_ready(ready);
    }

    /// A `personal_sign` request reached Ready.
    fn ai_ready_message(&mut self) {
        let Some(flow) = self.evm.approval.as_ref() else {
            return;
        };
        // Only for the window whose draft was just shown (not a next window opened meanwhile).
        if flow.ai().is_none() || flow.issued().is_none() {
            return;
        }
        let QueuedItem::Site(site) = flow.item().clone() else {
            return;
        };
        let SiteKind::PersonalSign { account, message } = &site.kind else {
            return;
        };
        let blocked = flow
            .issued()
            .is_some_and(|request| request.display.risk == RiskLevel::Blocked);
        let ready = match self.message_chain(site.chain_id) {
            _ if blocked => AiReady::Skip(SKIP_BLOCKED.get(self.approval_lang())),
            Some(chain) => {
                let decoded = yw_core::evm::eip191::decode_personal_message(message.clone());
                AiReady::Input(build_input(
                    self.approval_lang(),
                    &ExplainSource::PersonalSign(&decoded),
                    &self.site_origin_text(&site),
                    account,
                    &chain,
                    &yw_core::approval::ChainFacts::default(),
                ))
            }
            None => AiReady::Skip(SKIP_FAILED.get(self.approval_lang())),
        };
        self.ai_ready(ready);
    }

    /// A typed-data request reached Ready (with the facts its display used).
    fn ai_ready_typed(&mut self, facts: &yw_core::approval::ChainFacts) {
        let Some(flow) = self.evm.approval.as_ref() else {
            return;
        };
        if flow.ai().is_none() || flow.issued().is_none() {
            return;
        }
        let (QueuedItem::Site(site), Some(typed)) =
            (flow.item().clone(), flow.typed().cloned().map(Box::new))
        else {
            return;
        };
        let SiteKind::TypedData { account, .. } = &site.kind else {
            return;
        };
        let blocked = flow
            .issued()
            .is_some_and(|request| request.display.risk == RiskLevel::Blocked);
        let ready = match self.message_chain(site.chain_id) {
            _ if blocked => AiReady::Skip(SKIP_BLOCKED.get(self.approval_lang())),
            Some(chain) => AiReady::Input(build_input(
                self.approval_lang(),
                &ExplainSource::TypedData(&typed),
                &self.site_origin_text(&site),
                account,
                &chain,
                facts,
            )),
            None => AiReady::Skip(SKIP_FAILED.get(self.approval_lang())),
        };
        self.ai_ready(ready);
    }

    /// The 50 ms tick: deadline and a request waiting for the worker (spec/06 §3.2).
    fn ai_tick(&mut self, now: u64) {
        let busy = self.llm_busy();
        let Some(ai) = self.evm.approval.as_mut().and_then(ApprovalFlow::ai_mut) else {
            return;
        };
        let requesting = matches!(
            ai.panel.state(),
            crate::explain::AiPanelState::Requesting { .. }
        );
        let (ended, dispatch) = ai.panel.tick(now, busy);
        if ended.is_some() || dispatch.is_some() {
            self.ai_after(ended, dispatch, None);
        } else if requesting
            && now % 1_000 < 50
            && let Some(ai_child) = self.approval_win.as_ref().and_then(|win| win.ai.as_ref())
        {
            ai_child.body.invalidate();
        }
    }

    /// `다시 요청` (mouse only).
    fn ai_retry(&mut self) {
        #[cfg(test)]
        self.log_approval_call(flow_support::Call::AiRetry);
        let now = self.clock.now_ms();
        let busy = self.llm_busy();
        let Some(ai) = self.evm.approval.as_mut().and_then(ApprovalFlow::ai_mut) else {
            return;
        };
        let dispatch = ai.panel.retry(now, busy);
        self.ai_after(None, dispatch, None);
    }

    /// A `yw-llm` result (spec/06 §3.2): applied only to the open window's current request.
    pub(crate) fn on_llm_done(&mut self, done: LlmDone) {
        let now = self.clock.now_ms();
        let Some(ai) = self
            .evm
            .approval
            .as_mut()
            .and_then(ApprovalFlow::ai_mut)
            .filter(|ai| ai.serial == done.window)
        else {
            return;
        };
        let ended = ai.panel.on_result(now, done.generation, done.result);
        self.ai_after(ended, None, Some(&done.stats));
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the layout, then the panel's shapes, lines and focus in one pass"
    )]
    fn paint_panel(&mut self, window: &Window) {
        let dpi = window.dpi();
        let client = window.client_rect();
        let lang = self.approval_lang();
        let Self {
            evm,
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
            let layout = build_layout(
                &mut dc,
                fonts,
                &mut win.widths,
                paint.view,
                width,
                dpi,
                paint.ack_checked,
            );
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

/// S4 A4 (2026-11-18, spec/15 §11.4 S4): the App-level approval flow scenarios and their golden
/// `app/tests/s4_flow/flow.txt` (`#[ignore]`, gate step `s4fl`).
#[cfg(test)]
#[path = "app_approval_flow_tests.rs"]
mod flow_tests;

/// S4 A5 (2026-11-18, spec/15 §11.4 S4): the approval window's input mapping and re-entrancy
/// goldens `app/tests/s4_flow/{input,reentry}.txt` (`#[ignore]`, gate step `s4fl`) and the
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
    pub(crate) fn tour_ai_state(&self) -> Option<crate::explain::AiPanelState> {
        // 2026-11-19 (S4 B4b): read through the flow's `ApprovalPaint`.
        self.evm
            .approval
            .as_ref()
            .and_then(|flow| flow.paint().ai.map(|ai| ai.panel.state().clone()))
    }
}

/// E31 for a dApp transaction that carried fee fields (spec/03 §3.4, values ignored).
fn site_fee_warning(lang: Lang, site: &SiteRequest) -> Vec<yw_core::approval::Warning> {
    match &site.kind {
        SiteKind::Send(tx) if tx.fee_fields => {
            vec![yw_core::evm::risk::warning(
                lang,
                yw_core::evm::risk::E31,
                None,
            )]
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use yw_core::evm::chain::{
        ARBITRUM_ONE, BASE_MAINNET, BSC_MAINNET, ETHEREUM_MAINNET, HYPEREVM_MAINNET,
        ROBINHOOD_MAINNET, SEPOLIA,
    };
    use yw_core::sol::SolCluster;

    use super::{BarMetrics, bar_layout, layout_badges, network_badge, order_badges};

    const MAINNET_BADGE: &str = crate::ui::approval_text::BADGE_MAINNET.ko;
    const T_ACK_FIRST: &str = crate::ui::approval_text::ACK_FIRST.ko;
    const T_SIM_RESIM_FAILED: &str = crate::ui::approval_text::SIM_RESIM_FAILED.ko;
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
