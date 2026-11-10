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

use core::fmt::Write as _;
use std::collections::HashMap;

use yw_core::approval::{ApprovalRequest, RiskLevel};
use yw_core::evm::chain::SEPOLIA;
use yw_core::evm::simulate::needs_resimulation;
use yw_win::input::is_down;
use yw_win::ui::{
    Color, DrawFlags, Handler, Msg, PaintDc, Rect, Reply, Window, WindowKind, WindowSpec,
    create_window,
};

use crate::app::App;
use crate::app_evm::{AppApproval, QueuedItem};
use crate::app_llm::log_request;
use crate::browser::{SiteKind, SiteRequest};
use crate::errors::ErrorCode;
use crate::events::{KeyJob, SignInfo};
use crate::explain::input::RequestKind;
use crate::explain::panel::{
    AiPanel, BODY_LINES, Dispatch, Ended, PANEL_TITLE, PanelLine, RETRY_LABEL, body_lines,
    held_for_ack,
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
use crate::ui::approval_view::{ApprovalView, Block, Tone, escape_spans, view};
use crate::ui::badge::{BADGE_DIP, BADGE_GAP_DIP, Badge};
use crate::ui::interaction::{
    APPROVAL_TICK_MS, ApprovalGate, ApprovalSession, HIGH_RISK_HOLD_MS, InteractionEvent,
    InteractionStatus, MAX_LIFETIME_MS, PrepareStage, PrepareState, ReadyContent, stray_press,
};
use crate::ui::text_layout;
use crate::ui::theme::{self, FontRole, Fonts, wide};
use crate::workers::rpc::RpcJob;

/// Approval window class.
pub const APPROVAL_CLASS: &str = "YourWalletV3Approval";
/// Scrolling panel class.
pub const PANEL_CLASS: &str = "YourWalletV3Panel";
const APPROVAL_TIMER_ID: usize = 7;
const MA_ACTIVATEANDEAT: isize = 2;
/// `SB_ENDSCROLL`: the scroll-bar button was released (every other `WM_VSCROLL` code comes from
/// a scroll-bar press or drag, which counts as a press for the press-gap rule).
const SB_ENDSCROLL: u16 = 8;
/// Extra window height (DIP) when the AI panel is reserved (spec/06 §6: ten body lines plus the
/// title row), so the core content area keeps the size it has without the panel.
const AI_PANEL_EXTRA_DIP: i32 = 240;
const SKIP_BLOCKED: &str = "승인할 수 없는 요청이라 AI 설명을 요청하지 않았습니다.";
const SKIP_FAILED: &str = "요청을 준비하지 못해 AI 설명을 요청하지 않았습니다.";
const VK_LBUTTON: u16 = 0x01;
const VK_TAB: u16 = 0x09;
const VK_RETURN: u16 = 0x0D;
const VK_SHIFT: u16 = 0x10;
const VK_ESCAPE: u16 = 0x1B;
const VK_SPACE: u16 = 0x20;
const VK_PRIOR: u16 = 0x21;
const VK_NEXT: u16 = 0x22;
const VK_END: u16 = 0x23;
const VK_HOME: u16 = 0x24;
const VK_UP: u16 = 0x26;
const VK_DOWN: u16 = 0x28;

/// Keyboard focus inside A01 (spec/04 §3.4 Tab order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    /// `거부` (initial).
    Reject,
    /// The acknowledgement checkbox.
    Ack,
    /// `승인`.
    Approve,
    /// `원본 데이터`.
    Raw,
    /// The scrolling area.
    Scroll,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pressed {
    Approve,
    Reject,
    Retry,
    AiRetry,
}

/// The AI explanation panel of one window (spec/06 §6, spec/04 §3.8): reserved when the window
/// opens, painted by the window (title, `다시 요청`) and by its own child (`body`, ten lines,
/// scrolled inside). Never focused and never an input of the gate.
struct AiUi {
    panel: AiPanel,
    serial: u64,
    body: Window,
    scroll: i32,
    host: String,
    model: String,
    kind: RequestKind,
}

impl core::fmt::Debug for AiUi {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AiUi")
            .field("state", self.panel.state())
            .finish_non_exhaustive()
    }
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
    /// when every group has exactly one choice, else 0 (approve disabled).
    #[must_use]
    pub fn gate_count(&self) -> usize {
        let count = self.selected.iter().filter(|checked| **checked).count();
        if self.family == yw_core::policy::Family::Evm {
            return count;
        }
        let complete = (0..self.groups).all(|group| {
            self.accounts
                .iter()
                .zip(&self.selected)
                .filter(|((_, _, _, of), checked)| *of == group && **checked)
                .count()
                == 1
        });
        if complete { count } else { 0 }
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
    status: String,
    label: &'static str,
    armed: bool,
    /// Milliseconds held so far while a high-risk hold is under way.
    held_ms: Option<u64>,
    focus: Option<Focus>,
}

/// The status-line note while the approve button waits for its 1 s arm delay (spec/04 §3.4-2).
pub const T_ARM_WAIT: &str = "잠시 뒤 버튼이 켜집니다 (실수 클릭을 막는 1초 대기)";
/// The same while another window is in front.
pub const T_ARM_WAIT_BACKGROUND: &str = "이 창을 클릭해 앞으로 가져오면 1초 뒤 버튼이 켜집니다";
/// The status line of a high-risk window whose acknowledgement box is unchecked (2026-11-08).
pub const T_ACK_FIRST: &str = "경고를 읽고 아래 '위 경고를 모두 확인했습니다'에 체크하세요";
/// The same once the high-risk window is armed.
pub const T_HOLD_NOW: &str = "'승인'을 2초 동안 누르고 있으세요";
/// The same after a hold was let go before 2 s (until the next press).
pub const T_HOLD_EARLY: &str = "2초가 되기 전에 놓았습니다 — 다시 2초 동안 누르세요";
/// The status line of a connect window with no account selected.
pub const T_CONNECT_PICK: &str = "연결할 계정을 하나 이상 고르세요";

/// The user's next step on the status line (display only; the gate is unchanged): what is still
/// to do, then why the button waits, then how to approve a high-risk request.
fn next_step(ui: &ApprovalUi, held: bool, now: u64) -> Option<&'static str> {
    let gate = &ui.session.gate;
    if ui.view.blocked || held || gate.submitting || now >= gate.deadline_ms {
        return None;
    }
    if ui.session.connect_empty() {
        return Some(T_CONNECT_PICK);
    }
    if ui.session.ack_missing() {
        return Some(T_ACK_FIRST);
    }
    if ui.early_release {
        return Some(T_HOLD_EARLY);
    }
    if ui.session.arm_waiting(now) {
        // Why the button is grey (review 2026-11-07 F7); the arm delay itself is unchanged.
        return Some(if gate.is_foreground {
            T_ARM_WAIT
        } else {
            T_ARM_WAIT_BACKGROUND
        });
    }
    (ui.view.high && ui.session.approve_ready(now)).then_some(T_HOLD_NOW)
}

fn bar_state(ui: &ApprovalUi, waiting: usize, now: u64) -> BarState {
    let gate = &ui.session.gate;
    let remaining = gate.deadline_ms.saturating_sub(now);
    let mut status = String::new();
    if matches!(gate.prepare, PrepareState::Ready(_)) {
        let _ = write!(status, "남은 시간 {}", remaining_text(remaining));
    }
    if waiting > 0 {
        let _ = write!(status, "   ·   대기 중인 다른 요청 {waiting}건");
    }
    if let Some(message) = &ui.status {
        status.push_str("   ·   ");
        status.push_str(message);
    }
    let held_ms = ui
        .session
        .interaction()
        .hold_remaining_ms(now)
        .map(|left| HIGH_RISK_HOLD_MS.saturating_sub(left));
    if let Some(done) = held_ms {
        let _ = write!(status, "   ·   {}.{}초", done / 1_000, (done % 1_000) / 100);
    }
    if let Some(step) = next_step(ui, held_ms.is_some(), now) {
        if !status.is_empty() {
            status.push_str("   ·   ");
        }
        status.push_str(step);
    }
    let simulating = matches!(
        gate.prepare,
        PrepareState::Preparing(PrepareStage::Simulating { .. })
    ) || (gate.submitting
        && ui
            .status
            .as_deref()
            .is_some_and(|s| s.starts_with("시뮬레이션")));
    let label = if ui.connect.is_some() {
        "연결"
    } else if ui.view.blocked {
        "승인할 수 없음"
    } else if simulating {
        "시뮬레이션 중…"
    } else if ui.view.high {
        "승인 (2초 길게 누르기)"
    } else {
        "승인"
    };
    BarState {
        status,
        label,
        armed: ui.session.approve_ready(now),
        held_ms,
        focus: matches!(ui.focus, Focus::Approve | Focus::Reject).then_some(ui.focus),
    }
}

/// The open approval window and its flow state.
pub struct ApprovalUi {
    window: Window,
    panel: Window,
    item: QueuedItem,
    connect: Option<ConnectState>,
    typed: Option<Box<yw_core::evm::eip712::DecodedTypedData>>,
    session: ApprovalSession,
    job: u64,
    prepared: Option<Box<Prepared>>,
    request: Option<ApprovalRequest>,
    failure: Option<String>,
    status: Option<String>,
    /// A high-risk hold was let go before 2 s (the status line says so until the next press).
    early_release: bool,
    focus: Focus,
    raw_open: bool,
    scroll: i32,
    pressed: Option<Pressed>,
    resim_click: bool,
    view: ApprovalView,
    layout: Option<PanelLayout>,
    bottom: Bottom,
    /// The bottom bar as last painted.
    bar: BarState,
    widths: HashMap<(FontRole, char), i32>,
    ai: Option<AiUi>,
}

impl ApprovalUi {
    /// The current preparation job id.
    pub(crate) const fn job(&self) -> u64 {
        self.job
    }
}

impl core::fmt::Debug for ApprovalUi {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ApprovalUi")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Approval,
    Panel,
    AiBody,
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

fn now_ms() -> u64 {
    yw_win::time::monotonic_ms()
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
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
                Some(("고위험", theme::DANGER_ACCENT, theme::CARD)),
            ),
            Tone::Blocked => (
                theme::BLOCKED_BG,
                theme::BLOCKED_TEXT,
                Some(("차단", theme::CARD, theme::BLOCKED_BG)),
            ),
            Tone::Warn => (
                theme::WARN_BG,
                theme::WARN_TEXT,
                Some(("주의", theme::WARN_ACCENT, theme::CARD)),
            ),
            Tone::Plain => (
                theme::INFO_BG,
                theme::INFO_TEXT,
                Some(("정보", theme::INFO_ACCENT, theme::CARD)),
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
            } => {
                builder.open_card(theme::INFO_BG, theme::INFO_ACCENT);
                let (x, w) = (builder.x, builder.w);
                builder.text("요약", FontRole::Caption, theme::INFO_TEXT, x, w);
                builder.gap(2);
                builder.text(sentence, FontRole::ApprovalTitle, theme::TEXT, x, w);
                if let Some(address) = address {
                    builder.gap(6);
                    let grouped = crate::ui::screens_btc::grouped(address);
                    let shown = if !address.contains(' ')
                        && crate::ui::theme::btc_address_segments(&grouped).is_some()
                    {
                        grouped
                    } else {
                        address.clone()
                    };
                    builder.text(&shown, FontRole::Mono, theme::TEXT, x, w);
                    if !notes.is_empty() {
                        builder.text(notes, FontRole::Caption, theme::INFO_TEXT, x, w);
                    }
                }
                builder.gap(6);
                builder.text(title, FontRole::Caption, theme::MUTED, x, w);
                builder.close_card();
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
                    "위 경고를 모두 확인했습니다",
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
                // A Bitcoin address (0x0601, no spaces in the value) is drawn in 4-character
                // groups with the first and last 6 characters bold (spec/04 §3.3, spec/08 §10).
                let grouped = crate::ui::screens_btc::grouped(value);
                let value = if *mono
                    && !value.contains(' ')
                    && crate::ui::theme::btc_address_segments(&grouped).is_some()
                {
                    &grouped
                } else {
                    value
                };
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
                let has_sol_address = !*mono
                    && value
                        .split('\n')
                        .any(|line| crate::ui::theme::sol_address_segments(line).is_some());
                if has_sol_address {
                    // Grouped Solana addresses on their own lines of a text field (the SPL mint
                    // and token accounts of `0x0502`) are drawn like address fields: Consolas
                    // with bold middle groups (spec/07 §12.3).
                    for line in value.split('\n') {
                        let line_role = if crate::ui::theme::sol_address_segments(line).is_some() {
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
                builder.text(
                    if *open {
                        "자세히 ▾  (나머지 항목·원본 데이터)"
                    } else {
                        "자세히 ▸  (나머지 항목·원본 데이터)"
                    },
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
                builder.text(label, FontRole::BodyBold, theme::TEXT, x, width);
                let shown = yw_core::evm::address::parse_address(address).map_or_else(
                    |_| address.clone(),
                    |parsed| yw_core::evm::display::format_address(&parsed),
                );
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
        && let Some(segments) = crate::ui::theme::address_segments(&line.text)
    {
        dc.set_text_color(line.color);
        let rect = Rect::new(
            line.x,
            line.y.saturating_sub(offset_y),
            i32::MAX / 4,
            line.height,
        );
        if crate::ui::theme::paint_sol_address(dc, fonts, &segments, rect) {
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
        draw(
            dc,
            line.text.get(start..end).unwrap_or(""),
            theme::ESCAPE_TEXT,
            &mut x,
        );
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

/// Whether A01 is the foreground window (the gate input, spec/04 §3.4).
fn window_is_foreground(window: &Window) -> bool {
    #[cfg(test)]
    if TEST_FORCE_FOREGROUND.with(core::cell::Cell::get) {
        return true;
    }
    window.is_foreground()
}

fn remaining_text(ms: u64) -> String {
    let seconds = ms / 1_000;
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

/// What the window does after an interaction event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusAction {
    /// Act on the approval (once).
    Approve,
    /// Expired (`Expired`).
    Expire,
    /// Rejected.
    Reject,
    /// Still pending: repaint.
    Repaint,
    /// An approval already acted on (C1): `Approved` is terminal and is returned again on every
    /// later tick, so only the transition into it may act.
    Nothing,
}

fn status_action(
    before: InteractionStatus,
    after: InteractionStatus,
    now_ms: u64,
    deadline_ms: u64,
) -> StatusAction {
    match after {
        InteractionStatus::Approved if before == InteractionStatus::Approved => {
            StatusAction::Nothing
        }
        InteractionStatus::Approved => StatusAction::Approve,
        InteractionStatus::Rejected if now_ms >= deadline_ms => StatusAction::Expire,
        InteractionStatus::Rejected => StatusAction::Reject,
        InteractionStatus::Pending => StatusAction::Repaint,
    }
}

/// The header network badge (spec/04 §3 header): built-in mainnets (Ethereum, `HyperEVM`,
/// Arbitrum One, Base, BNB Smart Chain, Robinhood Chain, Solana mainnet) say plainly that real assets move; Sepolia and Solana devnet are test
/// networks. User chains have no testnet classification and get neither; Bitcoin has its own
/// network banner. Returns the text and whether it is the testnet coloring.
fn network_badge(
    evm_chain: Option<u64>,
    sol: Option<yw_core::sol::SolCluster>,
) -> Option<(&'static str, bool)> {
    use yw_core::evm::chain::is_builtin_mainnet;
    use yw_core::sol::SolCluster;
    match (evm_chain, sol) {
        (_, Some(SolCluster::Devnet)) => {
            Some(("Solana devnet (테스트) — 실제 자산이 아닙니다", true))
        }
        (_, Some(SolCluster::Mainnet)) => Some((MAINNET_BADGE, false)),
        (Some(chain), None) if is_builtin_mainnet(chain) => Some((MAINNET_BADGE, false)),
        (Some(SEPOLIA), None) => Some(("테스트넷 — 실제 자산이 아닙니다", true)),
        _ => None,
    }
}

/// The mainnet header badge.
const MAINNET_BADGE: &str = "메인넷 — 실제 자산";

impl App {
    // ----- queue and window lifecycle -----------------------------------------------------

    /// Shows the next queued approval (unlocked only, spec/04 §3.7). Site items that need no
    /// window (connected `eth_requestAccounts`, revoke after unlock) or fail their checks are
    /// answered and skipped.
    pub fn show_next_approval(&mut self) {
        if self.evm.window.is_some() || !matches!(self.mode, crate::app::AppMode::Unlocked { .. }) {
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
            let now = now_ms();
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
            if self.open_approval(item).is_err() {
                if let Some((item, outcome)) = self.evm.queue.finish_shown(QueueOutcome::Rejected) {
                    self.approval_finished(&item.payload, outcome);
                }
                self.error_banner(ErrorCode::App009);
                return;
            }
            self.start_prepare();
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
        let accounts = self.own_accounts();
        // An account whose recovery phrase is not backed up can receive but not sign (spec/02
        // §8.6): its row says so, and it is not the default of a new site while another is.
        let unconfirmed: Vec<Option<yw_core::vault::RecordId>> = accounts
            .iter()
            .map(|(address, _)| self.evm_account_unconfirmed(address))
            .collect();
        // A new site starts with the account chosen on the main screen (2026-11-08; account 0
        // before), so the user picks deliberately; the window is still approved explicitly.
        let current = self
            .selected_account()
            .and_then(|(current, ..)| accounts.iter().position(|(address, _)| *address == current));
        let first = current
            .filter(|index| unconfirmed.get(*index).is_some_and(Option::is_none))
            .or_else(|| unconfirmed.iter().position(Option::is_none))
            .or(current)
            .unwrap_or(0);
        let selected = accounts
            .iter()
            .enumerate()
            .map(|(index, (address, _))| {
                if granted.is_empty() {
                    index == first
                } else {
                    granted.contains(address)
                }
            })
            .collect();
        ConnectState {
            accounts: accounts
                .into_iter()
                .zip(unconfirmed)
                .map(|((address, label), phrase)| {
                    (
                        crate::app_chain_sites::ConnectChoice::Evm(address),
                        format!("{label}{}", self.mn_connect_tag(phrase)),
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
            .evm_chain_name(chain_id)
            .unwrap_or_else(|| format!("chainId {chain_id}"))
    }

    /// Security review L4(c): an open EVM connect window shows the origin's chain of now (a
    /// window-less `wallet_switchEthereumChain` may have changed it). Returns whether it changed.
    fn refresh_connect_chain(&mut self) -> bool {
        let Some(site) = self
            .evm
            .window
            .as_ref()
            .and_then(|ui| match (&ui.item, &ui.connect) {
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
        let Some(connect) = self.evm.window.as_mut().and_then(|ui| ui.connect.as_mut()) else {
            return false;
        };
        if connect.chain_id == chain_id {
            return false;
        }
        connect.chain_id = chain_id;
        connect.chain_name = name;
        true
    }

    #[expect(
        clippy::too_many_lines,
        reason = "window, panel, AI body and session set up in order"
    )]
    fn open_approval(&mut self, item: QueuedItem) -> Result<(), ()> {
        let now = now_ms();
        let connect = match &item {
            QueuedItem::Site(site) if site.kind.is_connect() => Some(self.connect_state(site)),
            _ => None,
        };
        let handler = Box::new(Forward {
            app: self.self_ref.clone(),
            target: Target::Approval,
        });
        let title = if connect.is_some() {
            "Your Wallet — 사이트 연결"
        } else {
            "Your Wallet — 승인 요청"
        };
        // spec/06 §3.1: dApp transactions, personal_sign and typed data, only while the worker
        // exists (feature effectively on). The panel's height is reserved now (§6).
        let ai_kind = match &item {
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
                | SiteKind::BtcSign { .. } => None,
            },
            QueuedItem::App(_)
            | QueuedItem::Sol(_)
            | QueuedItem::Btc(_)
            | QueuedItem::Zec(_)
            | QueuedItem::HyperCore(_) => None,
        }
        .filter(|_| self.llm.is_some());
        let extra = if ai_kind.is_some() {
            AI_PANEL_EXTRA_DIP
        } else {
            0
        };
        let spec = WindowSpec::new(APPROVAL_CLASS, WindowKind::Floating)
            .title(title)
            .size(820, 710 + extra)
            .min_size(520, 460 + extra)
            .topmost(true)
            .resizable(true);
        let window = create_window(&spec, handler).map_err(|_| ())?;
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
        let panel = create_window(&panel_spec, panel_handler).map_err(|_| ())?;
        let ai = match (ai_kind, self.llm.as_ref()) {
            (Some(kind), Some(service)) => {
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
                let body = create_window(&body_spec, body_handler).map_err(|_| ())?;
                self.llm_ui.next_window = self.llm_ui.next_window.saturating_add(1);
                Some(AiUi {
                    panel: AiPanel::new(true),
                    serial: self.llm_ui.next_window,
                    body,
                    scroll: 0,
                    host: service.host().to_owned(),
                    model: service.model().to_owned(),
                    kind,
                })
            }
            _ => None,
        };
        let deadline_ms = match &item {
            QueuedItem::Site(site) => site.deadline_ms,
            QueuedItem::App(_)
            | QueuedItem::Sol(_)
            | QueuedItem::Btc(_)
            | QueuedItem::Zec(_)
            | QueuedItem::HyperCore(_) => now.saturating_add(MAX_LIFETIME_MS),
        };
        let gate = ApprovalGate {
            prepare: PrepareState::Preparing(PrepareStage::Building),
            ack_checked: false,
            connect_selected: 0,
            ready_at_ms: now,
            is_foreground: false,
            deadline_ms: deadline_ms.max(now.saturating_add(1)),
            submitting: false,
        };
        let session = ApprovalSession::new(gate, now).map_err(|_| ())?;
        window.center_on(self.main.as_ref());
        let _ = window.set_timer(APPROVAL_TIMER_ID, APPROVAL_TICK_MS);
        window.show();
        if !window.set_foreground() {
            window.flash();
        }
        window.set_focus();
        self.evm.window = Some(ApprovalUi {
            window,
            panel,
            item,
            connect,
            typed: None,
            session,
            job: 0,
            prepared: None,
            request: None,
            failure: None,
            status: None,
            early_release: false,
            focus: Focus::Reject,
            raw_open: false,
            scroll: 0,
            pressed: None,
            resim_click: false,
            view: ApprovalView::default(),
            layout: None,
            bottom: Bottom::default(),
            bar: BarState::default(),
            widths: HashMap::new(),
            ai,
        });
        logging::info("app", "approval.open", &[]);
        self.rebuild_view();
        Ok(())
    }

    fn start_prepare(&mut self) {
        let job = self.evm.job();
        let Some(ui) = self.evm.window.as_mut() else {
            return;
        };
        ui.job = job;
        ui.failure = None;
        let item = ui.item.clone();
        let _ = ui
            .session
            .replace_content(now_ms(), PrepareState::Preparing(PrepareStage::Building));
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
                crate::app_sidecar::T_JOURNAL_CLOSED_SEND.to_owned(),
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
                let failure = crate::flow::evm::prepare::PrepareFailure::no_endpoint();
                let text = failure.message();
                self.show_failure(code, false, text);
                return;
            }
        };
        let Ok(id) = Self::new_approval_id() else {
            self.show_failure(ErrorCode::Vlt005, false, ErrorCode::Vlt005.text());
            return;
        };
        let address_book = self.address_book_facts();
        let (origin, extra_warnings) = match site {
            Some(site) => (self.site_approval_origin(site), site_fee_warning(site)),
            None => (yw_core::approval::ApprovalOrigin::App, Vec::new()),
        };
        let sent = self.rpc(RpcJob::Prepare(Box::new(PrepareJob {
            job,
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
            self.show_failure(ErrorCode::Rpc001, true, ErrorCode::Rpc001.text());
        }
    }

    /// The dApp items: connect window content, transaction preparation, message drafts.
    #[expect(clippy::too_many_lines, reason = "one arm per dApp request kind")]
    fn prepare_site(&mut self, job: u64, site: &SiteRequest) {
        let now = now_ms();
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
                if let Some(ui) = self.evm.window.as_mut() {
                    let selected = ui.connect.as_ref().map_or(0, ConnectState::gate_count);
                    let accounts = ui.connect.as_ref().map_or(0, |c| c.accounts.len());
                    ui.session.gate.deadline_ms = deadline;
                    let _ = ui.session.replace_content(
                        now,
                        PrepareState::Ready(ReadyContent::Connect(
                            crate::ui::interaction::ConnectView { accounts },
                        )),
                    );
                    ui.session.gate.connect_selected = selected;
                }
            }
            SiteKind::Send(tx) => {
                let Some(signer) = self.account_source(&tx.from) else {
                    self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
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
                    self.show_failure(failure.code, false, failure.message());
                }
            }
            SiteKind::PersonalSign { account, message } => {
                let decoded = yw_core::evm::eip191::decode_personal_message(message.clone());
                let draft = self.message_chain(site.chain_id).and_then(|chain| {
                    let signer = self.account_source(account)?;
                    let id = Self::new_approval_id().ok()?;
                    yw_core::evm::display::build_personal_request(
                        id,
                        self.site_approval_origin(site),
                        signer,
                        *account,
                        yw_core::approval::ApprovalKind::EvmPersonalSign,
                        &chain,
                        &decoded,
                        now_unix_ms(),
                    )
                    .ok()
                });
                match draft {
                    Some(draft) => {
                        self.show_ready_draft(draft, None);
                        self.ai_ready_message();
                    }
                    None => self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text()),
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
                if let Some(ui) = self.evm.window.as_mut() {
                    ui.typed = Some(typed.clone());
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
            SiteKind::SolSign { .. } | SiteKind::BtcSign { .. } => {
                match self.chain_sign_draft(site) {
                    Some(draft) => self.show_ready_draft(draft, None),
                    None => self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text()),
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
        self.evm
            .blocked(chain_id)
            .map(crate::flow::evm::prepare::PrepareFailure::chain_mismatch)
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
        let Some(ui) = self.evm.window.as_ref() else {
            return;
        };
        if ui.job != job {
            return;
        }
        let (QueuedItem::Site(site), Some(typed)) = (ui.item.clone(), ui.typed.clone()) else {
            return;
        };
        let SiteKind::TypedData { account, .. } = &site.kind else {
            return;
        };
        let mismatch = match check {
            Some(crate::flow::evm::ChainCheck::Mismatch(kind)) => Some(
                crate::flow::evm::prepare::PrepareFailure::chain_mismatch(kind),
            ),
            _ => self.message_chain_failure(site.chain_id),
        };
        if let Some(failure) = mismatch {
            self.show_failure(failure.code, false, failure.message());
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
                id,
                self.site_approval_origin(&site),
                signer,
                *account,
                yw_core::approval::ApprovalKind::EvmTypedData,
                &chain,
                &typed,
                facts,
                now_unix_ms(),
            )
            .ok()
        });
        match draft {
            Some(draft) => {
                self.show_ready_draft(draft, None);
                self.ai_ready_typed(facts);
            }
            None => self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text()),
        }
    }

    pub(crate) fn show_failure(&mut self, code: ErrorCode, retryable: bool, text: String) {
        if let Some(ui) = self.evm.window.as_mut() {
            ui.failure = Some(text);
            let _ = ui
                .session
                .replace_content(now_ms(), PrepareState::Failed { code, retryable });
        }
        self.ai_ready(AiReady::Skip(SKIP_FAILED));
        self.rebuild_view();
    }

    /// Closes the window without queue bookkeeping; a still-pending issued approval is rejected
    /// (it can never be consumed without its window).
    pub fn close_approval_window(&mut self) {
        if let Some(mut ui) = self.evm.window.take() {
            if let Some(request) = ui.request.as_ref() {
                self.evm.store.reject(request.id);
            }
            // spec/06 §3.2: a result arriving after the window closed is dropped.
            if let Some(mut ai) = ui.ai.take() {
                if let Some(ended) = ai.panel.close(now_ms()) {
                    log_request(&ai.host, ai.kind, &ended, None);
                }
                drop(ai.body);
            }
            ui.window.kill_timer(APPROVAL_TIMER_ID);
            drop(ui.panel);
            drop(ui.window);
            if let Some(main) = self.main.as_ref()
                && main.is_alive()
            {
                let _ = main.set_foreground();
            }
        }
    }

    fn finish_approval(&mut self, outcome: QueueOutcome) {
        let id = self
            .evm
            .window
            .as_ref()
            .and_then(|ui| ui.request.as_ref().map(|request| request.id));
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
        if let Some(ui) = self.evm.window.as_mut()
            && ui.job == job
        {
            let _ = ui.session.replace_content(
                now_ms(),
                PrepareState::Preparing(PrepareStage::Simulating { since_ms }),
            );
            self.rebuild_view();
        }
    }

    /// Preparation finished: issue at first Ready display (spec/03 §11.5).
    pub fn on_prepared(&mut self, result: PrepareResult) {
        self.apply_transitions(result.transitions.clone());
        let matches = self
            .evm
            .window
            .as_ref()
            .is_some_and(|ui| ui.job == result.job);
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
                let site = self.evm.window.as_ref().and_then(|ui| match &ui.item {
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
                    // spec/03 §3.2: the dApp nonce differs — -32602, no failure window.
                    self.respond(&reply, Err(yw_core::policy::ProviderError::InvalidParams));
                    self.finish_approval(QueueOutcome::Cancelled);
                    return;
                }
                let text = failure.message();
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
    fn show_ready_draft(
        &mut self,
        draft: yw_core::approval::ApprovalDraft,
        prepared: Option<Box<Prepared>>,
    ) {
        self.show_ready_draft_at(draft, prepared, now_unix_ms());
    }

    /// [`Self::show_ready_draft`] with the wall-clock display time given (the SOL intent binds
    /// it as `created_at_ms`, spec/07 §13.1-3).
    pub(crate) fn show_ready_draft_at(
        &mut self,
        draft: yw_core::approval::ApprovalDraft,
        prepared: Option<Box<Prepared>>,
        now_unix: u64,
    ) {
        let now = now_ms();
        let mut draft = draft;
        let site_origin = self.evm.window.as_ref().and_then(|ui| match &ui.item {
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
            self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
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
        if let Some(ui) = self.evm.window.as_mut() {
            ui.raw_open = request.display.risk >= RiskLevel::High;
            ui.session.gate.deadline_ms = deadline;
            let _ = ui.session.replace_content(
                now,
                PrepareState::Ready(ReadyContent::Signing(Box::new(request.clone()))),
            );
            ui.request = Some(request);
            ui.prepared = prepared;
        }
        self.rebuild_view();
    }

    /// Re-simulation finished (spec/03 §6.6-3/4, spec/04 §3.4).
    pub fn on_resimulated(&mut self, result: ResimResult) {
        let Some(ui) = self.evm.window.as_ref() else {
            return;
        };
        if ui.job != result.job {
            return;
        }
        let click = ui.resim_click;
        let Some(old) = ui.request.clone() else {
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
            if let Some(ui) = self.evm.window.as_mut() {
                ui.status = None;
                ui.resim_click = false;
            }
            self.show_failure(failure.code, false, failure.message());
            return;
        }
        let Some(prepared) = result.prepared else {
            if let Some(ui) = self.evm.window.as_mut() {
                ui.status = Some(
                    "다시 실행한 시뮬레이션이 성공하지 못했습니다. 경고를 확인하고 다시 승인하세요."
                        .to_owned(),
                );
                ui.resim_click = false;
                // Same content, but a new approval (checkbox, arm delay, fresh interaction).
                let prepare = ui.session.gate.prepare.clone();
                let _ = ui.session.replace_content(now_ms(), prepare);
            }
            self.rebuild_view();
            return;
        };
        // The re-simulated draft is built afresh: a WalletConnect request gets its label and
        // Verify warning again (spec/13 §7), or is not shown.
        let mut draft = prepared.draft.clone();
        let site_origin = self.evm.window.as_ref().and_then(|ui| match &ui.item {
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
            self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
            return;
        };
        let now = now_ms();
        if let Some(ui) = self.evm.window.as_mut() {
            ui.request = Some(request.clone());
            ui.prepared = Some(prepared);
            ui.resim_click = false;
        }
        if click && kind == ResimKind::Same {
            self.consume_and_sign();
            return;
        }
        if let Some(ui) = self.evm.window.as_mut() {
            ui.status = match kind {
                ResimKind::Same => None,
                ResimKind::Changed | ResimKind::Blocked | ResimKind::Failed => {
                    Some("시뮬레이션 결과가 바뀌었습니다. 다시 확인하세요".to_owned())
                }
                ResimKind::NoResult => Some(
                    "다시 실행한 시뮬레이션이 성공하지 못했습니다. 경고를 확인하고 다시 승인하세요."
                        .to_owned(),
                ),
            };
            let _ = ui.session.replace_content(
                now,
                PrepareState::Ready(ReadyContent::Signing(Box::new(request))),
            );
        }
        // spec/06 §3.2: a re-simulation that changes the input bytes re-requests.
        self.ai_ready_tx();
        self.rebuild_view();
    }

    fn approved(&mut self) {
        let now = now_ms();
        let connect = self
            .evm
            .window
            .as_ref()
            .and_then(|ui| match (&ui.item, &ui.connect) {
                (QueuedItem::Site(site), Some(connect)) => Some((site.clone(), connect.clone())),
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
                if self.refresh_connect_chain() {
                    if let Some(ui) = self.evm.window.as_mut() {
                        ui.session.restart_arm_delay(now);
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
        let Some(ui) = self.evm.window.as_mut() else {
            return;
        };
        // C1: one approval is acted on once — a submission in flight (re-simulation or consume)
        // ignores any further approval until its result replaces or resets the content.
        if ui.session.gate.submitting {
            return;
        }
        let Some(request) = ui.request.clone() else {
            return;
        };
        if ui.prepared.is_none() {
            ui.session.gate.submitting = true;
            self.consume_and_sign();
            return;
        }
        ui.session.gate.submitting = true;
        ui.status = Some("확인 중…".to_owned());
        let received = ui
            .prepared
            .as_ref()
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
        let Some(ui) = self.evm.window.as_mut() else {
            return;
        };
        let (Some(request), Some(prepared)) = (ui.request.clone(), ui.prepared.clone()) else {
            return;
        };
        ui.job = job;
        ui.resim_click = click;
        ui.session.gate.submitting = true;
        ui.status = Some("시뮬레이션 중… (0/10초)".to_owned());
        let chain_id = ui.item.chain_id();
        let extra_warnings = match &ui.item {
            QueuedItem::Site(site) => site_fee_warning(site),
            QueuedItem::App(_)
            | QueuedItem::Sol(_)
            | QueuedItem::Btc(_)
            | QueuedItem::Zec(_)
            | QueuedItem::HyperCore(_) => Vec::new(),
        };
        let chain = match self.chain_job(chain_id) {
            Ok(chain) => chain,
            Err(code) => {
                let failure = crate::flow::evm::prepare::PrepareFailure::no_endpoint();
                self.show_failure(code, false, failure.message());
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
        if let Some(ui) = self.evm.window.as_mut() {
            if sent {
                // C1: the approval that asked for this re-simulation has been acted on; the
                // terminal `Approved` status must not dispatch it again on the next tick.
                let _ = ui.session.restart_interaction(now_ms());
            } else {
                ui.status = Some(ErrorCode::Rpc001.text());
                ui.resim_click = false;
                let prepare = ui.session.gate.prepare.clone();
                let _ = ui.session.replace_content(now_ms(), prepare);
            }
        }
        self.rebuild_view();
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one branch per approval kind, in the order of spec/03 §11.5"
    )]
    fn consume_and_sign(&mut self) {
        let now = now_ms();
        let Some(ui) = self.evm.window.as_ref() else {
            return;
        };
        let Some(request) = ui.request.clone() else {
            return;
        };
        let prepared = ui.prepared.clone();
        let item = ui.item.clone();
        match self.evm.store.consume(request.id, request.digest, now) {
            Ok(approved) => {
                logging::info(
                    "app",
                    "approval.consumed",
                    &[("net", Field::Net(item.network()))],
                );
                let reply = match &item {
                    QueuedItem::Site(site) => Some(site.reply),
                    QueuedItem::App(_)
                    | QueuedItem::Sol(_)
                    | QueuedItem::Btc(_)
                    | QueuedItem::Zec(_)
                    | QueuedItem::HyperCore(_) => None,
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
                if request.kind.is_chain_message() {
                    let waiter = match &item {
                        QueuedItem::Site(site) => Self::chain_waiter(site, approved.payload()),
                        _ => None,
                    };
                    let Some(waiter) = waiter else {
                        self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
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
                        let waiter = reply.map_or(
                            crate::app_browser::SignWaiter::App,
                            crate::app_browser::SignWaiter::Message,
                        );
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
                            QueuedItem::Site(site) => (
                                self.site_origin_text(site),
                                crate::app_browser::SignWaiter::Tx(site.reply),
                            ),
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
                            now_unix_ms: now_unix_ms(),
                        };
                        // The S11 send: an app item that replaces nothing (speed-up and cancel
                        // come from the activity list).
                        let form = matches!(&item, QueuedItem::App(app) if app.replace.is_none());
                        self.dispatch_evm_sign(ticket, approved, info, form);
                    }
                    (None, _) => {
                        self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
                        return;
                    }
                }
                self.finish_approval(QueueOutcome::Approved);
            }
            Err(_) => {
                self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
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
        let shown_gone = self.evm.queue.shown().is_none() && self.evm.window.is_some();
        for (item, outcome) in finished {
            self.approval_finished(&item.payload, outcome);
        }
        if shown_gone {
            self.close_approval_window();
            self.show_next_approval();
        }
    }

    fn interaction(&mut self, event: InteractionEvent) {
        let now = now_ms();
        let Some(ui) = self.evm.window.as_mut() else {
            return;
        };
        // A false → true edge (activation, also within this process) restarts the arm delay.
        ui.session
            .set_foreground(now, window_is_foreground(&ui.window));
        let before = ui.session.interaction().status();
        let holding = ui.session.interaction().hold_remaining_ms(now).is_some();
        let status = ui.session.event(now, event);
        if event.is_press() {
            ui.early_release = false;
        } else if holding
            && status == InteractionStatus::Pending
            && matches!(
                event,
                InteractionEvent::PointerReleased { .. } | InteractionEvent::SpaceReleased { .. }
            )
        {
            ui.early_release = true;
        }
        let deadline = ui.session.gate.deadline_ms;
        match status_action(before, status, now, deadline) {
            StatusAction::Approve => self.approved(),
            StatusAction::Expire => self.finish_approval(QueueOutcome::Expired),
            StatusAction::Reject => {
                logging::info("app", "approval.rejected", &[]);
                self.finish_approval(QueueOutcome::Rejected);
            }
            StatusAction::Repaint => {
                // Only the bottom bar changes with interaction events and ticks: repaint just it,
                // and only when what it shows changed (no full-window redraw every 50 ms).
                let waiting = self.evm.queue.len().saturating_sub(1);
                if let Some(ui) = self.evm.window.as_ref() {
                    if ui.bottom.bar.w <= 0 {
                        ui.window.invalidate();
                    } else if bar_state(ui, waiting, now_ms()) != ui.bar {
                        ui.window.invalidate_rect(ui.bottom.bar);
                    }
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
        let now = now_ms();
        self.refresh_connect_chain();
        let testnet_chain = self.evm.window.as_ref().map(|ui| match &ui.connect {
            Some(connect) if connect.family == yw_core::policy::Family::Evm => connect.chain_id,
            _ => ui.item.chain_id(),
        });
        let Some(chain_id) = testnet_chain else {
            return;
        };
        let mut badges = Vec::new();
        let family = match self.evm.window.as_ref().map(|ui| &ui.item) {
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
            badges.push(crate::ui::screens_evm::custom_chain_badge(chain_id));
        }
        let (evm_chain, sol_cluster) = match (self.evm.window.as_ref().map(|ui| &ui.item), family) {
            (Some(QueuedItem::Sol(item)), _) => (None, Some(item.cluster)),
            (Some(QueuedItem::Site(_)), yw_core::policy::Family::Solana) => {
                (None, Some(self.sol_cluster()))
            }
            (Some(QueuedItem::Site(_)), yw_core::policy::Family::Bitcoin)
            | (
                Some(QueuedItem::Btc(_) | QueuedItem::Zec(_) | QueuedItem::HyperCore(_)) | None,
                _,
            ) => (None, None),
            (Some(QueuedItem::App(_) | QueuedItem::Site(_)), _) => (Some(chain_id), None),
        };
        let site_btc_banner = (family == yw_core::policy::Family::Bitcoin)
            .then(|| crate::ui::approval_view::BtcBanner::of(self.btc_network_now()));
        let chain_badge = match (self.evm.window.as_ref().map(|ui| &ui.item), family) {
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
        if let Some((text, test)) = network_badge(evm_chain, sol_cluster) {
            testnet = test;
            badges.push(text.to_owned());
        }
        // HyperCore (spec/11 §6): the same mainnet / testnet badges as the EVM chains.
        if let Some(QueuedItem::HyperCore(item)) = self.evm.window.as_ref().map(|ui| &ui.item) {
            if item.action.network == yw_core::hypercore::HcNetwork::Testnet {
                testnet = true;
                badges.push("HyperCore 테스트넷 — 실제 자산이 아닙니다".to_owned());
            } else {
                badges.push(MAINNET_BADGE.to_owned());
            }
        }
        // spec/10 §10: a YubiKey signer adds the "YubiKey로 서명" badge (app chrome only: the
        // badges are not part of the request's digested display, spec/03 §11.3).
        let card_badge = self.evm.window.as_ref().and_then(|ui| {
            let (role, touches) = match (&ui.item, &ui.session.gate.prepare) {
                (QueuedItem::Btc(item), _) => (
                    crate::yubikey::btc_plan_role(&item.plan)?,
                    item.plan.inputs().len(),
                ),
                (QueuedItem::Zec(item), _) => (
                    crate::yubikey::zec_plan_role(&item.plan)?,
                    item.plan.inputs.len(),
                ),
                (_, PrepareState::Ready(ReadyContent::Signing(request))) => (
                    crate::yubikey::role_of(&request.signer, &request.payload)?,
                    1,
                ),
                _ => return None,
            };
            Some(crate::app_card::card_badge(
                &self.card.records,
                role,
                touches,
            ))
        });
        badges.extend(card_badge);
        // WalletConnect sessions (spec/13 §7): the claimed origin, chains and Verify state.
        let wc_patch = self.evm.window.as_ref().and_then(|ui| match &ui.item {
            QueuedItem::Site(site) => self.wc_connect_patch(&site.origin),
            _ => None,
        });
        let Some(ui) = self.evm.window.as_mut() else {
            return;
        };
        let wide_layout = ui.window.client_rect().w >= ui.window.px(80 * 8);
        if let QueuedItem::Site(site) = &ui.item {
            if crate::walletconnect::is_session_origin(&site.origin) {
                badges.insert(0, "WalletConnect 세션".to_owned());
            }
            // spec/05 §2.12: after the http/punycode badges, connect and approval views alike.
            if let Some(mode) = site.compat_mode {
                badges.insert(0, crate::ui::approval_view::compat_mode_badge(mode));
            }
            if let (Some(connect), PrepareState::Ready(ReadyContent::Connect(_))) =
                (&ui.connect, &ui.session.gate.prepare)
            {
                let accounts: Vec<(String, String)> = connect
                    .accounts
                    .iter()
                    .map(|(_, label, address, _)| (label.clone(), address.clone()))
                    .collect();
                let mut connect_view = crate::ui::approval_view::connect_view(
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
                connect_view.testnet = testnet;
                connect_view.chain = chain_badge;
                ui.view = connect_view;
                ui.layout = None;
                ui.window.invalidate();
                ui.panel.invalidate();
                return;
            }
            let mut site_badges = Vec::new();
            if site.origin.is_http() {
                site_badges.push("로컬 개발 사이트(http)".to_owned());
            }
            if site
                .origin
                .host()
                .split('.')
                .any(|label| label.starts_with("xn--"))
            {
                site_badges.push("국제화 도메인(punycode)".to_owned());
            }
            site_badges.extend(badges);
            badges = site_badges;
        }
        let btc_banner = match &ui.item {
            QueuedItem::Btc(item) => Some(crate::ui::approval_view::BtcBanner::of(item.network)),
            QueuedItem::Site(_) => site_btc_banner,
            QueuedItem::App(_)
            | QueuedItem::Sol(_)
            | QueuedItem::Zec(_)
            | QueuedItem::HyperCore(_) => None,
        };
        match view(
            &ui.session.gate.prepare,
            now,
            ui.raw_open,
            wide_layout,
            badges,
            testnet,
            ui.failure.as_deref(),
        ) {
            Ok(mut view) => {
                view.btc_banner = btc_banner;
                view.chain = chain_badge;
                // W-ADDR-3 under the recipient (spec/04 §3.3, outside the digest).
                let note = match &ui.item {
                    QueuedItem::Btc(item) => item.look_alike.as_deref(),
                    QueuedItem::Zec(item) => item.look_alike.as_deref(),
                    QueuedItem::App(_)
                    | QueuedItem::Site(_)
                    | QueuedItem::Sol(_)
                    | QueuedItem::HyperCore(_) => None,
                };
                if let Some(note) = note {
                    crate::ui::approval_view::attach_address_note(&mut view, note);
                }
                if !force && view == ui.view {
                    return;
                }
                ui.view = view;
                ui.layout = None;
                ui.window.invalidate();
                ui.panel.invalidate();
                // The risk level or the acknowledgement may have changed (held_for_ack).
                if let Some(ai) = ui.ai.as_ref() {
                    ai.body.invalidate();
                }
            }
            Err(code) => {
                logging::warn("app", "E-UI-001", &[]);
                self.error_banner(code);
                self.finish_approval(QueueOutcome::Rejected);
            }
        }
    }

    // ----- window messages ----------------------------------------------------------------

    fn focus_order(ui: &ApprovalUi) -> Vec<Focus> {
        let mut order = vec![Focus::Reject];
        if ui.view.blocks.contains(&Block::Ack) {
            order.push(Focus::Ack);
        }
        order.push(Focus::Approve);
        if ui.view.has_raw {
            order.push(Focus::Raw);
        }
        order.push(Focus::Scroll);
        order
    }

    fn toggle_ack(&mut self) {
        let now = now_ms();
        if let Some(ui) = self.evm.window.as_mut()
            && ui.view.blocks.contains(&Block::Ack)
        {
            let checked = !ui.session.gate.ack_checked;
            ui.session.set_ack(now, checked);
            ui.layout = None;
            ui.panel.invalidate();
            ui.window.invalidate();
            // A High-risk request's AI panel waits for this checkbox (held_for_ack).
            if let Some(ai) = ui.ai.as_ref() {
                ai.body.invalidate();
            }
        }
    }

    fn toggle_connect_account(&mut self, index: usize) {
        let now = now_ms();
        if let Some(ui) = self.evm.window.as_mut()
            && let Some(connect) = ui.connect.as_mut()
            && index < connect.selected.len()
        {
            connect.toggle(index);
            ui.session.gate.connect_selected = connect.gate_count();
            ui.session.set_ack(now, false);
        }
        self.rebuild_view();
    }

    fn toggle_raw(&mut self) {
        if let Some(ui) = self.evm.window.as_mut() {
            ui.raw_open = !ui.raw_open;
        }
        self.rebuild_view();
    }

    fn scroll_by(&mut self, delta: i32) {
        if let Some(ui) = self.evm.window.as_mut() {
            let page = ui.panel.client_rect().h;
            let max = ui
                .layout
                .as_ref()
                .map_or(0, |layout| layout.height.saturating_sub(page).max(0));
            ui.scroll = ui.scroll.saturating_add(delta).clamp(0, max);
            ui.panel
                .set_vscroll(ui.scroll, page, ui.layout.as_ref().map_or(0, |l| l.height));
            ui.panel.invalidate();
        }
    }

    #[expect(clippy::too_many_lines, reason = "one arm per spec/04 §3.4 input row")]
    pub(crate) fn on_approval_msg(&mut self, window: &Window, msg: &Msg) -> Reply {
        if let Some(event) = stray_press(msg) {
            // Right/middle/X button and non-client presses count too (spec/04 §3.4).
            self.interaction(event);
            return Reply::Default;
        }
        match msg {
            Msg::Paint => {
                self.paint_approval(window);
                Reply::Handled(0)
            }
            Msg::Size { .. } | Msg::DpiChanged { .. } => {
                if let Some(ui) = self.evm.window.as_mut() {
                    ui.layout = None;
                }
                self.rebuild_view();
                Reply::Default
            }
            Msg::MouseActivate => {
                if window.is_foreground() {
                    Reply::Default
                } else {
                    // The eaten activating click (any button) is a press while not armed.
                    self.interaction(InteractionEvent::OtherPress);
                    Reply::Handled(MA_ACTIVATEANDEAT)
                }
            }
            Msg::Timer(APPROVAL_TIMER_ID) => {
                self.interaction(InteractionEvent::Tick);
                self.ai_tick(now_ms());
                if let Some(ui) = self.evm.window.as_ref()
                    && matches!(
                        ui.session.gate.prepare,
                        PrepareState::Preparing(PrepareStage::Simulating { .. })
                    )
                {
                    self.rebuild_view_with(false);
                }
                Reply::Handled(0)
            }
            Msg::MouseDown { x, y } => {
                let on_approve = self
                    .evm
                    .window
                    .as_ref()
                    .is_some_and(|ui| ui.bottom.approve.contains(*x, *y));
                if !on_approve {
                    // Every press counts for the press-gap rule (spec/04 §3.4).
                    self.interaction(InteractionEvent::OtherPress);
                }
                let Some(ui) = self.evm.window.as_mut() else {
                    return Reply::Default;
                };
                window.set_focus();
                let bottom = ui.bottom;
                if bottom.approve.contains(*x, *y) {
                    ui.pressed = Some(Pressed::Approve);
                    ui.focus = Focus::Approve;
                    window.set_capture();
                    self.interaction(InteractionEvent::PointerPressed {
                        inside: true,
                        click_through: !window.is_foreground(),
                        physical_down: is_down(VK_LBUTTON),
                    });
                } else if bottom.reject.contains(*x, *y) {
                    ui.pressed = Some(Pressed::Reject);
                    ui.focus = Focus::Reject;
                    window.set_capture();
                } else if bottom.retry.is_some_and(|rect| rect.contains(*x, *y)) {
                    ui.pressed = Some(Pressed::Retry);
                    window.set_capture();
                } else if bottom.ai_retry.is_some_and(|rect| rect.contains(*x, *y)) {
                    // Mouse only: not a default button, not in the Tab order, not on Enter/Space.
                    ui.pressed = Some(Pressed::AiRetry);
                    window.set_capture();
                }
                window.invalidate();
                Reply::Handled(0)
            }
            Msg::MouseMove { x, y } => {
                let inside = self
                    .evm
                    .window
                    .as_ref()
                    .filter(|ui| ui.pressed == Some(Pressed::Approve))
                    .map(|ui| ui.bottom.approve.contains(*x, *y));
                if let Some(inside) = inside {
                    self.interaction(InteractionEvent::PointerMoved { inside });
                }
                Reply::Handled(0)
            }
            Msg::MouseUp { x, y } => {
                window.release_capture();
                let Some(ui) = self.evm.window.as_mut() else {
                    return Reply::Default;
                };
                let pressed = ui.pressed.take();
                let bottom = ui.bottom;
                match pressed {
                    Some(Pressed::Approve) => self.interaction(InteractionEvent::PointerReleased {
                        physical_down: is_down(VK_LBUTTON),
                    }),
                    Some(Pressed::Reject) if bottom.reject.contains(*x, *y) => {
                        self.interaction(InteractionEvent::RejectActivated);
                    }
                    Some(Pressed::Retry)
                        if bottom.retry.is_some_and(|rect| rect.contains(*x, *y)) =>
                    {
                        self.retry_action();
                    }
                    Some(Pressed::AiRetry)
                        if bottom.ai_retry.is_some_and(|rect| rect.contains(*x, *y)) =>
                    {
                        self.ai_retry();
                    }
                    _ => {}
                }
                window.invalidate();
                Reply::Handled(0)
            }
            Msg::KeyDown { vk, repeat } => {
                self.on_approval_key(*vk, *repeat);
                Reply::Handled(0)
            }
            Msg::KeyUp { vk } => {
                if *vk == VK_SPACE
                    && self
                        .evm
                        .window
                        .as_ref()
                        .is_some_and(|ui| ui.focus == Focus::Approve)
                {
                    self.interaction(InteractionEvent::SpaceReleased {
                        physical_down: is_down(VK_SPACE),
                    });
                }
                Reply::Handled(0)
            }
            Msg::Wheel(delta) => {
                let step = window.px(60);
                self.scroll_by(-(i32::from(*delta) / 120).saturating_mul(step));
                Reply::Handled(0)
            }
            Msg::KillFocus { to_foreign: true } => {
                self.interaction(InteractionEvent::FocusLost);
                Reply::Default
            }
            Msg::ActivateApp(false) => {
                self.interaction(InteractionEvent::ForegroundLost);
                Reply::Default
            }
            Msg::ActivateApp(true) => {
                if let Some(ui) = self.evm.window.as_mut() {
                    let now = now_ms();
                    ui.session.restart_arm_delay(now);
                    ui.session.set_foreground(now, true);
                }
                Reply::Default
            }
            Msg::CaptureChanged => {
                if self
                    .evm
                    .window
                    .as_ref()
                    .is_some_and(|ui| ui.pressed.is_some())
                {
                    if let Some(ui) = self.evm.window.as_mut() {
                        ui.pressed = None;
                    }
                    self.interaction(InteractionEvent::CaptureLost);
                }
                Reply::Default
            }
            Msg::CancelMode => {
                self.interaction(InteractionEvent::CancelMode);
                Reply::Default
            }
            Msg::Close => {
                self.interaction(InteractionEvent::RejectActivated);
                if self.evm.window.is_some() {
                    self.finish_approval(QueueOutcome::Rejected);
                }
                Reply::Handled(0)
            }
            _ => Reply::Default,
        }
    }

    fn retry_action(&mut self) {
        let failed_retryable = self.evm.window.as_ref().is_some_and(|ui| {
            matches!(
                ui.session.gate.prepare,
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

    fn on_approval_key(&mut self, vk: u16, repeat: bool) {
        // Every key press (auto-repeat included) counts for the press-gap rule; Enter and Space
        // on the approve button are presses of their own (`ApproveActivated`/`SpacePressed`).
        let approve_input = matches!(vk, VK_RETURN | VK_SPACE)
            && self
                .evm
                .window
                .as_ref()
                .is_some_and(|ui| ui.focus == Focus::Approve);
        if !approve_input {
            self.interaction(InteractionEvent::OtherPress);
        }
        let Some(ui) = self.evm.window.as_mut() else {
            return;
        };
        let focus = ui.focus;
        match vk {
            VK_TAB => {
                let order = Self::focus_order(ui);
                let position = order.iter().position(|item| *item == focus).unwrap_or(0);
                let len = order.len().max(1);
                let next = if is_down(VK_SHIFT) {
                    position.checked_sub(1).unwrap_or(len - 1)
                } else {
                    (position + 1) % len
                };
                ui.focus = order.get(next).copied().unwrap_or(Focus::Reject);
                ui.window.invalidate();
                ui.panel.invalidate();
            }
            VK_ESCAPE => self.interaction(InteractionEvent::RejectActivated),
            VK_RETURN => match focus {
                // L5: a posted/sent WM_KEYDOWN (not in the thread's key state) or an injected
                // one never approves, like Space and the pointer (`is_down`).
                Focus::Approve => self.interaction(InteractionEvent::ApproveActivated {
                    physical: yw_win::input::is_down_in_message(VK_RETURN)
                        && !yw_win::input::injected(),
                }),
                Focus::Reject => self.interaction(InteractionEvent::RejectActivated),
                Focus::Ack => self.toggle_ack(),
                Focus::Raw => self.toggle_raw(),
                Focus::Scroll => {}
            },
            VK_SPACE => match focus {
                Focus::Approve => self.interaction(InteractionEvent::SpacePressed {
                    repeat,
                    physical_down: is_down(VK_SPACE),
                }),
                Focus::Reject if !repeat => self.interaction(InteractionEvent::RejectActivated),
                Focus::Ack if !repeat => self.toggle_ack(),
                Focus::Raw if !repeat => self.toggle_raw(),
                _ => {}
            },
            VK_PRIOR | VK_NEXT | VK_UP | VK_DOWN | VK_HOME | VK_END if focus == Focus::Scroll => {
                let page = ui.panel.client_rect().h;
                let line = ui.panel.px(20);
                let delta = match vk {
                    VK_PRIOR => -page,
                    VK_NEXT => page,
                    VK_UP => -line,
                    VK_DOWN => line,
                    VK_HOME => i32::MIN / 2,
                    _ => i32::MAX / 2,
                };
                self.scroll_by(delta);
            }
            _ => {}
        }
    }

    pub(crate) fn on_panel_msg(&mut self, window: &Window, msg: &Msg) -> Reply {
        if let Some(event) = stray_press(msg) {
            // Right/middle/X button and non-client presses count too (spec/04 §3.4).
            self.interaction(event);
            return Reply::Default;
        }
        match msg {
            Msg::Paint => {
                self.paint_panel(window);
                Reply::Handled(0)
            }
            Msg::MouseDown { x, y } => {
                self.interaction(InteractionEvent::OtherPress);
                let Some(ui) = self.evm.window.as_mut() else {
                    return Reply::Default;
                };
                ui.window.set_focus();
                let content_y = y.saturating_add(ui.scroll);
                let layout = ui.layout.clone().unwrap_or_default();
                if let Some((index, _)) = layout
                    .accounts
                    .iter()
                    .find(|(_, rect)| rect.contains(*x, content_y))
                {
                    let index = *index;
                    self.toggle_connect_account(index);
                } else if layout.ack.is_some_and(|rect| rect.contains(*x, content_y)) {
                    ui.focus = Focus::Ack;
                    self.toggle_ack();
                } else if layout.raw.is_some_and(|rect| rect.contains(*x, content_y)) {
                    ui.focus = Focus::Raw;
                    self.toggle_raw();
                } else {
                    ui.focus = Focus::Scroll;
                    ui.window.invalidate();
                }
                Reply::Handled(0)
            }
            Msg::Wheel(delta) => {
                let step = window.px(60);
                self.scroll_by(-(i32::from(*delta) / 120).saturating_mul(step));
                Reply::Handled(0)
            }
            Msg::VScroll { code } => {
                if *code != SB_ENDSCROLL {
                    self.interaction(InteractionEvent::OtherPress);
                }
                let Some(ui) = self.evm.window.as_ref() else {
                    return Reply::Default;
                };
                let page = ui.panel.client_rect().h;
                let line = ui.panel.px(20);
                let current = ui.scroll;
                let target = match code {
                    0 => current.saturating_sub(line),
                    1 => current.saturating_add(line),
                    2 => current.saturating_sub(page),
                    3 => current.saturating_add(page),
                    4 | 5 => ui.panel.vscroll_track_pos(),
                    6 => 0,
                    7 => i32::MAX / 2,
                    _ => current,
                };
                self.scroll_by(target.saturating_sub(current));
                Reply::Handled(0)
            }
            _ => Reply::Default,
        }
    }

    // ----- painting -----------------------------------------------------------------------

    #[expect(clippy::too_many_lines, reason = "the fixed A01 areas in order")]
    fn paint_approval(&mut self, window: &Window) {
        let now = now_ms();
        let dpi = window.dpi();
        let client = window.client_rect();
        let llm_busy = self
            .llm
            .as_ref()
            .is_none_or(crate::explain::ExplainService::busy);
        let Self { evm, fonts, .. } = self;
        let Some(fonts) = fonts.for_dpi(dpi) else {
            return;
        };
        let Some(ui) = evm.window.as_mut() else {
            return;
        };
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
        let label_w = px(84);
        let value_w = width.saturating_sub(label_w).max(px(60));
        let mut rows: Vec<(String, String, FontRole)> = Vec::new();
        for (label, value) in &ui.view.header {
            for (index, line) in value.split('\n').enumerate() {
                let role = if index > 0 && crate::ui::theme::sol_address_segments(line).is_some() {
                    FontRole::Mono
                } else {
                    FontRole::Body
                };
                rows.push((
                    if index == 0 {
                        label.clone()
                    } else {
                        String::new()
                    },
                    line.to_owned(),
                    role,
                ));
            }
        }
        if rows.is_empty() {
            rows.push((
                "요청 출처".to_owned(),
                yw_core::approval::APP_ORIGIN_TEXT.to_owned(),
                FontRole::Body,
            ));
        }
        let mut badges: Vec<String> = Vec::new();
        if let Some(banner) = ui.view.btc_banner
            && !rows
                .iter()
                .any(|(_, value, _)| value.contains(banner.text()))
        {
            badges.push(banner.text().to_owned());
        }
        badges.extend(ui.view.badges.iter().cloned());
        // The chain badge goes before the first `네트워크` value line (app chrome, spec/04 §3.2).
        let badge_size = px(BADGE_DIP);
        let badge_row = ui.view.chain.and_then(|badge| {
            rows.iter()
                .position(|(label, _, _)| label == "네트워크")
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
        if !badges.is_empty() {
            header_height += px(30);
        }
        let (header_fill, header_text, header_muted) = match ui.view.btc_banner {
            Some(crate::ui::approval_view::BtcBanner::Mainnet) => (
                theme::BTC_MAINNET_BG,
                theme::BTC_MAINNET_TEXT,
                theme::BTC_MAINNET_TEXT,
            ),
            Some(crate::ui::approval_view::BtcBanner::Testnet4) => {
                (theme::BTC_TESTNET4_BG, theme::TEXT, theme::TEXT)
            }
            None if ui.view.testnet => (theme::TESTNET_BG, theme::TEXT, theme::MUTED),
            None => (theme::CARD, theme::TEXT, theme::MUTED),
        };
        let header_rect = Rect::new(
            0,
            0,
            client.w,
            header_height.saturating_add(margin.saturating_mul(2)),
        );
        dc.fill_rect(header_rect, header_fill);
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
                && crate::ui::theme::sol_address_segments(value).is_some_and(|segments| {
                    crate::ui::theme::paint_sol_address(&mut dc, fonts, &segments, rect)
                });
            if !emphasized {
                dc.select_font(fonts.get(*role));
                dc.draw_text(&wide(value), rect, DrawFlags::WRAP);
            }
            y = y.saturating_add(height).saturating_add(px(4));
        }
        if !badges.is_empty() {
            let mut x = margin;
            let top = y.saturating_add(px(4));
            dc.select_font(&fonts.body_bold);
            for badge in &badges {
                let text = wide(badge);
                let w = dc
                    .measure(&text, i32::MAX)
                    .1
                    .saturating_add(px(20))
                    .min(width);
                if x > margin && x.saturating_add(w) > margin.saturating_add(width) {
                    break;
                }
                let pill = Rect::new(x, top, w, px(24));
                dc.round_rect(pill, px(12), theme::CARD, theme::CARD_BORDER);
                dc.set_text_color(theme::TEXT);
                dc.draw_text(&text, pill, DrawFlags::CENTER);
                x = x.saturating_add(w).saturating_add(px(8));
            }
        }
        y = header_rect.bottom().saturating_add(px(10));
        // Simulation band.
        let mut retry = None;
        if let Some(band) = ui.view.band.clone() {
            let pad = px(12);
            let tag_w = px(56);
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
            dc.draw_text(&wide("고위험"), tag, DrawFlags::CENTER);
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
                dc.draw_text(&wide("시뮬레이션 다시 시도"), button, DrawFlags::CENTER);
                retry = Some(button);
            }
            y = y.saturating_add(height).saturating_add(px(8));
        }
        // Bottom bar.
        let bottom_h = px(96);
        let bottom_top = client.h.saturating_sub(bottom_h);
        dc.fill_rect(Rect::new(0, bottom_top, client.w, bottom_h), theme::CARD);
        dc.fill_rect(Rect::new(0, bottom_top, client.w, 1), theme::CARD_BORDER);
        let waiting = evm.queue.len().saturating_sub(1);
        let bar = bar_state(ui, waiting, now);
        dc.select_font(&fonts.body);
        dc.set_text_color(theme::MUTED);
        dc.draw_text(
            &wide(&bar.status),
            Rect::new(margin, bottom_top + px(10), width, px(22)),
            DrawFlags::LINE,
        );
        let button_w = px(220);
        let button_h = px(40);
        let buttons_y = client.h.saturating_sub(margin).saturating_sub(button_h);
        let approve = Rect::new(
            client.w.saturating_sub(margin).saturating_sub(button_w),
            buttons_y,
            button_w,
            button_h,
        );
        let reject = Rect::new(
            approve.x.saturating_sub(px(12)).saturating_sub(px(140)),
            buttons_y,
            px(140),
            button_h,
        );
        let radius = px(theme::RADIUS_CONTROL);
        dc.round_rect(reject, radius, theme::CARD, theme::BUTTON_SECONDARY.border);
        dc.set_text_color(theme::TEXT);
        dc.draw_text(&wide("거부"), reject, DrawFlags::CENTER);
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
        match ui.focus {
            Focus::Approve => dc.frame_rect(approve.inset(-px(3)), theme::FOCUS),
            Focus::Reject => dc.frame_rect(reject.inset(-px(3)), theme::FOCUS),
            _ => {}
        }
        // AI panel (spec/06 §6): fixed height right above the bottom bar, reserved from the start,
        // so a result never moves the buttons or the warnings.
        let (content_bottom, ai_retry, ai_body) = match ui.ai.as_ref() {
            Some(ai) => {
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
                    &wide(PANEL_TITLE),
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
                    dc.draw_text(&wide(RETRY_LABEL), rect, DrawFlags::CENTER);
                }
                let body = Rect::new(
                    margin,
                    top.saturating_add(pad)
                        .saturating_add(title_h)
                        .saturating_add(px(6)),
                    width,
                    body_h,
                );
                if body != ui.bottom.ai_body {
                    ai.body.set_rect(body);
                    ai.body.invalidate();
                }
                (top, retry_rect.filter(|_| !llm_busy), body)
            }
            None => (bottom_top, None, Rect::default()),
        };
        let panel = Rect::new(0, y, client.w, content_bottom.saturating_sub(y).max(px(40)));
        if panel != ui.bottom.panel {
            ui.panel.set_rect(panel);
            ui.layout = None;
            ui.panel.invalidate();
        }
        let bar_rect = Rect::new(0, bottom_top, client.w, bottom_h);
        // A paint that did not cover the whole bar leaves part of it stale: the next tick
        // repaints it.
        let update = dc.update_rect();
        ui.bar = if update.x <= bar_rect.x
            && update.y <= bar_rect.y
            && update.right() >= bar_rect.right()
            && update.bottom() >= bar_rect.bottom()
        {
            bar
        } else {
            BarState::default()
        };
        ui.bottom = Bottom {
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
        let now = now_ms();
        let dpi = window.dpi();
        let client = window.client_rect();
        let Self { evm, fonts, .. } = self;
        let Some(fonts) = fonts.for_dpi(dpi) else {
            return;
        };
        let Some(ui) = evm.window.as_mut() else {
            return;
        };
        let ApprovalUi {
            ai,
            widths,
            request,
            session,
            ..
        } = ui;
        let Some(ai) = ai.as_mut() else {
            return;
        };
        // A High-risk request shows its warnings first: the AI text waits for the
        // acknowledgement checkbox (the panel keeps its reserved place).
        ai.panel.set_held(held_for_ack(
            request.as_ref().map(|request| request.display.risk),
            session.gate.ack_checked,
        ));
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
        ai.scroll = ai.scroll.clamp(0, max);
        window.set_vscroll(ai.scroll, client.h, y);
        for (top, text, role, color, height) in rows {
            let top = top.saturating_sub(ai.scroll);
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
        if let Some(event) = stray_press(msg) {
            // Right/middle/X button and non-client presses count too (spec/04 §3.4).
            self.interaction(event);
            return Reply::Default;
        }
        match msg {
            Msg::Paint => {
                self.paint_ai_body(window);
                Reply::Handled(0)
            }
            Msg::MouseDown { .. } => {
                self.interaction(InteractionEvent::OtherPress);
                // The panel never takes keyboard focus (spec/04 §3.8). A click opens or folds
                // the body of an inconsistent explanation.
                if let Some(ui) = self.evm.window.as_mut() {
                    if let Some(ai) = ui.ai.as_mut()
                        && ai.panel.toggle_expanded()
                    {
                        ai.scroll = 0;
                        window.invalidate();
                    }
                    ui.window.set_focus();
                }
                Reply::Handled(0)
            }
            Msg::Wheel(delta) => {
                let step = window.px(40);
                self.ai_scroll_by(window, -(i32::from(*delta) / 120).saturating_mul(step));
                Reply::Handled(0)
            }
            Msg::VScroll { code } => {
                if *code != SB_ENDSCROLL {
                    self.interaction(InteractionEvent::OtherPress);
                }
                let page = window.client_rect().h;
                let line = window.px(20);
                let current = self
                    .evm
                    .window
                    .as_ref()
                    .and_then(|ui| ui.ai.as_ref())
                    .map_or(0, |ai| ai.scroll);
                let target = match code {
                    0 => current.saturating_sub(line),
                    1 => current.saturating_add(line),
                    2 => current.saturating_sub(page),
                    3 => current.saturating_add(page),
                    4 | 5 => window.vscroll_track_pos(),
                    6 => 0,
                    7 => i32::MAX / 2,
                    _ => current,
                };
                self.ai_scroll_by(window, target.saturating_sub(current));
                Reply::Handled(0)
            }
            _ => Reply::Default,
        }
    }

    fn ai_scroll_by(&mut self, window: &Window, delta: i32) {
        if let Some(ai) = self.evm.window.as_mut().and_then(|ui| ui.ai.as_mut()) {
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
        let now = now_ms();
        let Self { evm, llm, .. } = self;
        let Some(ui) = evm.window.as_mut() else {
            return;
        };
        let Some(ai) = ui.ai.as_mut() else {
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
        ai.body.invalidate();
        ui.window.invalidate();
    }

    fn ai_ready(&mut self, ready: AiReady) {
        let now = now_ms();
        let busy = self.llm_busy();
        let Some(ai) = self.evm.window.as_mut().and_then(|ui| ui.ai.as_mut()) else {
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
            let Some(ui) = self.evm.window.as_ref() else {
                return;
            };
            if ui.ai.is_none() {
                return;
            }
            let (QueuedItem::Site(site), Some(prepared), Some(request)) =
                (&ui.item, ui.prepared.as_ref(), ui.request.as_ref())
            else {
                return;
            };
            let yw_core::approval::AccountRef::Evm(user) = request.account else {
                return;
            };
            if request.display.risk == RiskLevel::Blocked {
                AiReady::Skip(SKIP_BLOCKED)
            } else {
                crate::app_llm::transaction_input(prepared, &self.site_origin_text(site), &user)
                    .map_or(AiReady::Skip(SKIP_BLOCKED), AiReady::Input)
            }
        };
        self.ai_ready(ready);
    }

    /// A `personal_sign` request reached Ready.
    fn ai_ready_message(&mut self) {
        let Some(ui) = self.evm.window.as_ref() else {
            return;
        };
        // Only for the window whose draft was just shown (not a next window opened meanwhile).
        if ui.ai.is_none() || ui.request.is_none() {
            return;
        }
        let QueuedItem::Site(site) = ui.item.clone() else {
            return;
        };
        let SiteKind::PersonalSign { account, message } = &site.kind else {
            return;
        };
        let blocked = ui
            .request
            .as_ref()
            .is_some_and(|request| request.display.risk == RiskLevel::Blocked);
        let ready = match self.message_chain(site.chain_id) {
            _ if blocked => AiReady::Skip(SKIP_BLOCKED),
            Some(chain) => {
                let decoded = yw_core::evm::eip191::decode_personal_message(message.clone());
                AiReady::Input(build_input(
                    &ExplainSource::PersonalSign(&decoded),
                    &self.site_origin_text(&site),
                    account,
                    &chain,
                    &yw_core::approval::ChainFacts::default(),
                ))
            }
            None => AiReady::Skip(SKIP_FAILED),
        };
        self.ai_ready(ready);
    }

    /// A typed-data request reached Ready (with the facts its display used).
    fn ai_ready_typed(&mut self, facts: &yw_core::approval::ChainFacts) {
        let Some(ui) = self.evm.window.as_ref() else {
            return;
        };
        if ui.ai.is_none() || ui.request.is_none() {
            return;
        }
        let (QueuedItem::Site(site), Some(typed)) = (ui.item.clone(), ui.typed.clone()) else {
            return;
        };
        let SiteKind::TypedData { account, .. } = &site.kind else {
            return;
        };
        let blocked = ui
            .request
            .as_ref()
            .is_some_and(|request| request.display.risk == RiskLevel::Blocked);
        let ready = match self.message_chain(site.chain_id) {
            _ if blocked => AiReady::Skip(SKIP_BLOCKED),
            Some(chain) => AiReady::Input(build_input(
                &ExplainSource::TypedData(&typed),
                &self.site_origin_text(&site),
                account,
                &chain,
                facts,
            )),
            None => AiReady::Skip(SKIP_FAILED),
        };
        self.ai_ready(ready);
    }

    /// The 50 ms tick: deadline and a request waiting for the worker (spec/06 §3.2).
    fn ai_tick(&mut self, now: u64) {
        let busy = self.llm_busy();
        let Some(ai) = self.evm.window.as_mut().and_then(|ui| ui.ai.as_mut()) else {
            return;
        };
        let requesting = matches!(
            ai.panel.state(),
            crate::explain::AiPanelState::Requesting { .. }
        );
        let (ended, dispatch) = ai.panel.tick(now, busy);
        if ended.is_some() || dispatch.is_some() {
            self.ai_after(ended, dispatch, None);
        } else if requesting && now % 1_000 < 50 {
            ai.body.invalidate();
        }
    }

    /// `다시 요청` (mouse only).
    fn ai_retry(&mut self) {
        let now = now_ms();
        let busy = self.llm_busy();
        let Some(ai) = self.evm.window.as_mut().and_then(|ui| ui.ai.as_mut()) else {
            return;
        };
        let dispatch = ai.panel.retry(now, busy);
        self.ai_after(None, dispatch, None);
    }

    /// A `yw-llm` result (spec/06 §3.2): applied only to the open window's current request.
    pub(crate) fn on_llm_done(&mut self, done: LlmDone) {
        let now = now_ms();
        let Some(ai) = self
            .evm
            .window
            .as_mut()
            .and_then(|ui| ui.ai.as_mut())
            .filter(|ai| ai.serial == done.window)
        else {
            return;
        };
        let ended = ai.panel.on_result(now, done.generation, done.result);
        self.ai_after(ended, None, Some(&done.stats));
    }

    fn paint_panel(&mut self, window: &Window) {
        let dpi = window.dpi();
        let client = window.client_rect();
        let Self { evm, fonts, .. } = self;
        let Some(fonts) = fonts.for_dpi(dpi) else {
            return;
        };
        let Some(ui) = evm.window.as_mut() else {
            return;
        };
        let Ok(mut dc) = window.begin_paint() else {
            return;
        };
        dc.fill_rect(client, theme::BG);
        let width = client.w;
        if ui
            .layout
            .as_ref()
            .is_none_or(|layout| layout.width != width)
        {
            let layout = build_layout(
                &mut dc,
                fonts,
                &mut ui.widths,
                &ui.view,
                width,
                dpi,
                ui.session.gate.ack_checked,
            );
            ui.layout = Some(layout);
            let max = ui
                .layout
                .as_ref()
                .map_or(0, |layout| layout.height.saturating_sub(client.h).max(0));
            ui.scroll = ui.scroll.min(max);
            window.set_vscroll(
                ui.scroll,
                client.h,
                ui.layout.as_ref().map_or(0, |layout| layout.height),
            );
        }
        let Some(layout) = ui.layout.as_ref() else {
            return;
        };
        let offset = ui.scroll;
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
            draw_line(&mut dc, fonts, line, offset, &ui.widths);
        }
        let focus_rect = match ui.focus {
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
        if ui.focus == Focus::Scroll {
            dc.frame_rect(client.inset(1), theme::FOCUS);
        }
    }
}

#[cfg(test)]
#[path = "app_approval_smoke.rs"]
pub(crate) mod smoke;

/// Hooks for the screenshot tour (`ui::tour`, an `#[ignore]` test). Gated like the tour module
/// (`#[cfg(test)]` + `#[cfg(debug_assertions)]`), so `cargo test --release` has no dead code.
#[cfg(test)]
#[cfg(debug_assertions)]
impl App {
    /// The open approval window.
    pub(crate) fn tour_approval_window(&self) -> Option<&Window> {
        self.evm.window.as_ref().map(|ui| &ui.window)
    }

    /// Rejects the open approval (as `거부` would).
    pub(crate) fn tour_reject_approval(&mut self) {
        self.finish_approval(QueueOutcome::Rejected);
    }

    /// The open window's AI panel state (spec/06), if it has one.
    pub(crate) fn tour_ai_state(&self) -> Option<crate::explain::AiPanelState> {
        self.evm
            .window
            .as_ref()
            .and_then(|ui| ui.ai.as_ref())
            .map(|ai| ai.panel.state().clone())
    }
}

/// E31 for a dApp transaction that carried fee fields (spec/03 §3.4, values ignored).
fn site_fee_warning(site: &SiteRequest) -> Vec<yw_core::approval::Warning> {
    match &site.kind {
        SiteKind::Send(tx) if tx.fee_fields => {
            vec![yw_core::evm::risk::warning(yw_core::evm::risk::E31, None)]
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

    use super::{MAINNET_BADGE, StatusAction, network_badge, status_action};
    use crate::ui::interaction::InteractionStatus;

    /// C1: `Approved` is terminal and comes back on every 50 ms tick; only the transition into
    /// it acts, so one click dispatches at most one re-simulation.
    #[test]
    fn only_the_transition_into_approved_acts() {
        use InteractionStatus::{Approved, Pending, Rejected};
        assert_eq!(
            status_action(Pending, Approved, 1, 10),
            StatusAction::Approve
        );
        for _tick in 0..100 {
            assert_eq!(
                status_action(Approved, Approved, 2, 10),
                StatusAction::Nothing
            );
        }
        assert_eq!(
            status_action(Pending, Pending, 3, 10),
            StatusAction::Repaint
        );
        assert_eq!(
            status_action(Pending, Rejected, 3, 10),
            StatusAction::Reject
        );
        assert_eq!(
            status_action(Pending, Rejected, 10, 10),
            StatusAction::Expire
        );
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
                network_badge(Some(chain), None),
                Some((MAINNET_BADGE, false))
            );
        }
        assert_eq!(
            network_badge(None, Some(SolCluster::Mainnet)),
            Some((MAINNET_BADGE, false))
        );
        assert_eq!(
            network_badge(Some(SEPOLIA), None),
            Some(("테스트넷 — 실제 자산이 아닙니다", true))
        );
        assert!(network_badge(None, Some(SolCluster::Devnet)).is_some_and(|(_, test)| test));
        // User chains have no testnet classification; Bitcoin has its own banner.
        assert_eq!(network_badge(Some(10), None), None);
        assert_eq!(network_badge(None, None), None);
    }
}
