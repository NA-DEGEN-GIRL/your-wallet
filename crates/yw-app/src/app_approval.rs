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
use crate::browser::{SiteKind, SiteRequest};
use crate::errors::ErrorCode;
use crate::events::{KeyJob, SignInfo};
use crate::flow::evm::Limits;
use crate::flow::evm::prepare::{
    PrepareJob, PrepareOutcome, PrepareResult, Prepared, ResimJob, ResimKind, ResimResult,
};
use crate::logging::{self, Field};
use crate::network::NetworkId;
use crate::ui::approval::QueueOutcome;
use crate::ui::approval_view::{ApprovalView, Block, Tone, escape_spans, view};
use crate::ui::interaction::{
    APPROVAL_TICK_MS, ApprovalGate, ApprovalSession, HIGH_RISK_HOLD_MS, InteractionEvent,
    InteractionStatus, MAX_LIFETIME_MS, PrepareStage, PrepareState, ReadyContent,
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
    fills: Vec<(Rect, Color)>,
    frames: Vec<(Rect, Color)>,
    height: i32,
    ack: Option<Rect>,
    raw: Option<Rect>,
    accounts: Vec<(usize, Rect)>,
}

/// Connect-window state (spec/05 §4.2).
#[derive(Clone, Debug)]
pub struct ConnectState {
    /// Offered accounts (address, label) in list order.
    pub accounts: Vec<(yw_core::evm::address::Address, String)>,
    /// Selection.
    pub selected: Vec<bool>,
    /// Origin chain name.
    pub chain_name: String,
}

#[derive(Clone, Copy, Debug, Default)]
struct Bottom {
    approve: Rect,
    reject: Rect,
    retry: Option<Rect>,
    panel: Rect,
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
    focus: Focus,
    raw_open: bool,
    scroll: i32,
    pressed: Option<Pressed>,
    resim_click: bool,
    view: ApprovalView,
    layout: Option<PanelLayout>,
    bottom: Bottom,
    widths: HashMap<(FontRole, char), i32>,
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
            return Reply::Default;
        };
        match self.target {
            Target::Approval => app.on_approval_msg(window, msg),
            Target::Panel => app.on_panel_msg(window, msg),
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
}

impl Builder<'_, '_> {
    fn px(&self, dip: i32) -> i32 {
        yw_win::ui::scale(dip, self.dpi)
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
    }

    fn gap(&mut self, dip: i32) {
        self.y = self.y.saturating_add(self.px(dip));
    }

    fn boxed(&mut self, text: &str, tone: Tone) {
        let pad = self.px(8);
        let width = self
            .layout
            .width
            .saturating_sub(self.margin.saturating_mul(2));
        let (fill, color) = match tone {
            Tone::Danger => (Some(theme::DANGER_BG), theme::DANGER_TEXT),
            Tone::Warn => (Some(theme::WARN_BG), theme::WARN_TEXT),
            Tone::Plain => (None, theme::TEXT),
        };
        let top = self.y;
        self.y = self.y.saturating_add(pad);
        self.text(
            text,
            FontRole::Body,
            color,
            self.margin.saturating_add(pad),
            width.saturating_sub(pad.saturating_mul(2)),
        );
        self.y = self.y.saturating_add(pad);
        if let Some(fill) = fill {
            self.layout.fills.push((
                Rect::new(self.margin, top, width, self.y.saturating_sub(top)),
                fill,
            ));
        }
        self.gap(6);
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
    };
    let inner = width.saturating_sub(margin.saturating_mul(2)).max(40);
    for block in &view.blocks {
        match block {
            Block::Title(text) => {
                builder.text(text, FontRole::ApprovalTitle, theme::TEXT, margin, inner);
                builder.gap(10);
            }
            Block::Warning { text, tone } => builder.boxed(text, *tone),
            Block::Ack => {
                let size = builder.px(16);
                let top = builder.y;
                let rect = Rect::new(margin, top, size, size);
                builder.layout.frames.push((rect, theme::TEXT));
                if ack_checked {
                    builder
                        .layout
                        .fills
                        .push((rect.inset(builder.px(3)), theme::FOCUS));
                }
                builder.text(
                    "위 경고를 모두 확인했습니다",
                    FontRole::BodyBold,
                    theme::TEXT,
                    margin.saturating_add(size).saturating_add(builder.px(8)),
                    inner.saturating_sub(size),
                );
                builder.layout.ack = Some(Rect::new(
                    margin,
                    top,
                    inner,
                    builder.y.saturating_sub(top).max(size),
                ));
                builder.gap(10);
            }
            Block::Section(title) => {
                builder.gap(6);
                builder.text(title, FontRole::BodyBold, theme::TEXT, margin, inner);
                let rule = Rect::new(margin, builder.y, inner, 1);
                builder.layout.fills.push((rule, theme::BORDER));
                builder.gap(6);
            }
            Block::Field { label, value, mono } => {
                builder.text(label, FontRole::Body, theme::MUTED, margin, inner);
                let role = if *mono {
                    if label.starts_with("calldata") {
                        FontRole::MonoSmall
                    } else {
                        FontRole::Mono
                    }
                } else {
                    FontRole::Body
                };
                builder.text(
                    value,
                    role,
                    theme::TEXT,
                    margin.saturating_add(builder.px(12)),
                    inner.saturating_sub(builder.px(12)),
                );
                builder.gap(8);
            }
            Block::Muted(text) => {
                builder.text(text, FontRole::Body, theme::MUTED, margin, inner);
                builder.gap(6);
            }
            Block::RawToggle { open } => {
                let top = builder.y;
                builder.text(
                    if *open {
                        "원본 데이터 ▾"
                    } else {
                        "원본 데이터 ▸"
                    },
                    FontRole::BodyBold,
                    theme::FOCUS,
                    margin,
                    inner,
                );
                builder.layout.raw =
                    Some(Rect::new(margin, top, inner, builder.y.saturating_sub(top)));
                builder.gap(6);
            }
            Block::Notice(text) => {
                builder.gap(20);
                builder.text(text, FontRole::BodyBold, theme::FOCUS, margin, inner);
            }
            Block::Account {
                index,
                label,
                address,
                checked,
            } => {
                let size = builder.px(16);
                let top = builder.y;
                let rect = Rect::new(margin, top, size, size);
                builder.layout.frames.push((rect, theme::TEXT));
                if *checked {
                    builder
                        .layout
                        .fills
                        .push((rect.inset(builder.px(3)), theme::FOCUS));
                }
                let x = margin.saturating_add(size).saturating_add(builder.px(8));
                let width = inner.saturating_sub(size).saturating_sub(builder.px(8));
                builder.text(label, FontRole::BodyBold, theme::TEXT, x, width);
                builder.text(address, FontRole::Mono, theme::TEXT, x, width);
                builder.layout.accounts.push((
                    *index,
                    Rect::new(margin, top, inner, builder.y.saturating_sub(top).max(size)),
                ));
                builder.gap(8);
            }
        }
    }
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

fn remaining_text(ms: u64) -> String {
    let seconds = ms / 1_000;
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

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

    fn connect_state(&self, site: &SiteRequest) -> ConnectState {
        let granted: Vec<yw_core::evm::address::Address> = self
            .browser_grants()
            .into_iter()
            .find(|grant| grant.origin == site.origin)
            .map(|grant| grant.accounts)
            .unwrap_or_default();
        let accounts = self.own_accounts();
        let selected = accounts
            .iter()
            .enumerate()
            .map(|(index, (address, _))| {
                if granted.is_empty() {
                    index == 0
                } else {
                    granted.contains(address)
                }
            })
            .collect();
        ConnectState {
            accounts,
            selected,
            chain_name: self
                .settings
                .evm_chain_name(site.chain_id)
                .unwrap_or_else(|| format!("chainId {}", site.chain_id)),
        }
    }

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
        let spec = WindowSpec::new(APPROVAL_CLASS, WindowKind::Floating)
            .title(title)
            .size(820, 710)
            .min_size(520, 460)
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
        let deadline_ms = match &item {
            QueuedItem::Site(site) => site.deadline_ms,
            QueuedItem::App(_) => now.saturating_add(MAX_LIFETIME_MS),
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
            focus: Focus::Reject,
            raw_open: false,
            scroll: 0,
            pressed: None,
            resim_click: false,
            view: ApprovalView::default(),
            layout: None,
            bottom: Bottom::default(),
            widths: HashMap::new(),
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
        }
        self.rebuild_view();
    }

    /// Steps 3–10 of spec/03 §3.7 on the RPC worker, for an app send or a dApp transaction.
    fn prepare_transaction(&mut self, job: u64, item: &AppApproval, site: Option<&SiteRequest>) {
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
            Some(site) => (
                yw_core::approval::ApprovalOrigin::Site(site.origin.clone()),
                site_fee_warning(site),
            ),
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
            SiteKind::RequestAccounts | SiteKind::RequestPermissions => {
                self.evm.queue.mark_ready(now);
                let deadline = self
                    .evm
                    .queue
                    .shown_deadline()
                    .unwrap_or(now.saturating_add(120_000));
                if let Some(ui) = self.evm.window.as_mut() {
                    let selected = ui.connect.as_ref().map_or(0, |connect| {
                        connect.selected.iter().filter(|checked| **checked).count()
                    });
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
            SiteKind::PersonalSign { account, message } => {
                let decoded = yw_core::evm::eip191::decode_personal_message(message.clone());
                let draft = self.message_chain(site.chain_id).and_then(|chain| {
                    let signer = self.account_source(account)?;
                    let id = Self::new_approval_id().ok()?;
                    yw_core::evm::display::build_personal_request(
                        id,
                        yw_core::approval::ApprovalOrigin::Site(site.origin.clone()),
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
                    Some(draft) => self.show_ready_draft(draft, None),
                    None => self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text()),
                }
            }
            SiteKind::TypedData {
                account,
                source,
                value,
            } => {
                let Ok(typed) =
                    yw_core::evm::eip712::validate_typed_data_v4(source, value, site.chain_id)
                else {
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
                if let Ok(chain) = self.chain_job(site.chain_id) {
                    let address_book = self.address_book_facts();
                    let sent = self.rpc(RpcJob::TypedFacts {
                        job,
                        chain,
                        account: *account,
                        typed,
                        address_book,
                    });
                    if !sent {
                        self.on_typed_facts(job, &yw_core::approval::ChainFacts::default());
                    }
                } else {
                    let facts = yw_core::approval::ChainFacts {
                        address_book: self.address_book_facts(),
                        ..yw_core::approval::ChainFacts::default()
                    };
                    self.on_typed_facts(job, &facts);
                }
            }
            SiteKind::Revoke => self.finish_approval(QueueOutcome::Cancelled),
        }
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

    /// Typed-data facts arrived: build the draft (spec/03 §8).
    pub fn on_typed_facts(&mut self, job: u64, facts: &yw_core::approval::ChainFacts) {
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
        let draft = self.message_chain(site.chain_id).and_then(|chain| {
            let signer = self.account_source(account)?;
            let id = Self::new_approval_id().ok()?;
            yw_core::evm::display::build_typed_request(
                id,
                yw_core::approval::ApprovalOrigin::Site(site.origin.clone()),
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
            Some(draft) => self.show_ready_draft(draft, None),
            None => self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text()),
        }
    }

    fn show_failure(&mut self, code: ErrorCode, retryable: bool, text: String) {
        if let Some(ui) = self.evm.window.as_mut() {
            ui.failure = Some(text);
            let _ = ui
                .session
                .replace_content(now_ms(), PrepareState::Failed { code, retryable });
        }
        self.rebuild_view();
    }

    /// Closes the window without queue bookkeeping; a still-pending issued approval is rejected
    /// (it can never be consumed without its window).
    pub fn close_approval_window(&mut self) {
        if let Some(ui) = self.evm.window.take() {
            if let Some(request) = ui.request.as_ref() {
                self.evm.store.reject(request.id);
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
                    QueuedItem::App(_) => None,
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
        let now = now_ms();
        let Ok(request) = self.evm.store.issue(draft, now, now_unix_ms()) else {
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
        let Some(prepared) = result.prepared else {
            if let Some(ui) = self.evm.window.as_mut() {
                ui.status = Some(
                    "다시 실행한 시뮬레이션이 성공하지 못했습니다. 경고를 확인하고 다시 승인하세요."
                        .to_owned(),
                );
                ui.session.gate.submitting = false;
            }
            self.rebuild_view();
            return;
        };
        let replaced = self
            .evm
            .store
            .replace(old.id, old.digest, prepared.draft.clone());
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
        if click && result.kind == ResimKind::Same {
            self.consume_and_sign();
            return;
        }
        if let Some(ui) = self.evm.window.as_mut() {
            ui.status = match result.kind {
                ResimKind::Same => None,
                ResimKind::Changed | ResimKind::Blocked => {
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
            let accounts: Vec<yw_core::evm::address::Address> = connect
                .accounts
                .iter()
                .zip(&connect.selected)
                .filter(|(_, checked)| **checked)
                .map(|((address, _), _)| *address)
                .collect();
            self.connect_approved(&site, accounts);
            self.finish_approval(QueueOutcome::Approved);
            return;
        }
        let Some(ui) = self.evm.window.as_mut() else {
            return;
        };
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
            QueuedItem::App(_) => Vec::new(),
        };
        let Ok(chain) = self.chain_job(chain_id) else {
            return;
        };
        let _ = self.rpc(RpcJob::Resimulate(Box::new(ResimJob {
            job,
            chain,
            request,
            context: prepared.context,
            address_book,
            extra_warnings,
            limits: Limits::PRODUCTION,
        })));
        self.rebuild_view();
    }

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
                    &[("net", Field::Net(NetworkId::Eip155(item.chain_id())))],
                );
                let reply = match &item {
                    QueuedItem::Site(site) => Some(site.reply),
                    QueuedItem::App(_) => None,
                };
                match (prepared, request.kind) {
                    (
                        _,
                        kind @ (yw_core::approval::ApprovalKind::EvmPersonalSign
                        | yw_core::approval::ApprovalKind::EvmTypedData),
                    ) => {
                        if let Some(reply) = reply {
                            self.push_sign_waiter(crate::app_browser::SignWaiter::Message(reply));
                        }
                        self.key(KeyJob::SignMessage {
                            approved: Box::new(approved),
                            typed: kind == yw_core::approval::ApprovalKind::EvmTypedData,
                        });
                    }
                    (Some(prepared), _) => {
                        let (origin, waiter) = match &item {
                            QueuedItem::Site(site) => (
                                site.origin.as_str().to_owned(),
                                crate::app_browser::SignWaiter::Tx(site.reply),
                            ),
                            QueuedItem::App(_) => {
                                ("yw-app".to_owned(), crate::app_browser::SignWaiter::App)
                            }
                        };
                        self.push_sign_waiter(waiter);
                        self.key(KeyJob::SignEvm {
                            approved: Box::new(approved),
                            info: SignInfo {
                                origin,
                                label: request.display.title.clone(),
                                role: prepared.context.role,
                                now_unix_ms: now_unix_ms(),
                            },
                        });
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

    /// Main-timer part: deadlines, re-arming, the simulation countdown.
    pub fn tick_approval(&mut self, now: u64) {
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
        ui.session.gate.is_foreground = ui.window.is_foreground();
        let status = ui.session.event(now, event);
        let deadline = ui.session.gate.deadline_ms;
        match status {
            InteractionStatus::Approved => self.approved(),
            InteractionStatus::Rejected if now >= deadline => {
                self.finish_approval(QueueOutcome::Expired);
            }
            InteractionStatus::Rejected => {
                logging::info("app", "approval.rejected", &[]);
                self.finish_approval(QueueOutcome::Rejected);
            }
            InteractionStatus::Pending => {
                if let Some(ui) = self.evm.window.as_ref() {
                    ui.window.invalidate();
                }
            }
        }
    }

    fn rebuild_view(&mut self) {
        let now = now_ms();
        let testnet_chain = self.evm.window.as_ref().map(|ui| ui.item.chain_id());
        let Some(chain_id) = testnet_chain else {
            return;
        };
        let mut badges = Vec::new();
        if self
            .settings
            .evm_chains
            .iter()
            .any(|def| def.chain_id == chain_id)
        {
            badges.push(crate::ui::screens_evm::custom_chain_badge(chain_id));
        }
        let testnet = chain_id == SEPOLIA;
        if testnet {
            badges.push("테스트넷 — 실제 자산이 아닙니다".to_owned());
        }
        let Some(ui) = self.evm.window.as_mut() else {
            return;
        };
        let wide_layout = ui.window.client_rect().w >= ui.window.px(80 * 8);
        if let QueuedItem::Site(site) = &ui.item {
            if let (Some(connect), PrepareState::Ready(ReadyContent::Connect(_))) =
                (&ui.connect, &ui.session.gate.prepare)
            {
                let accounts: Vec<(String, String)> = connect
                    .accounts
                    .iter()
                    .map(|(address, label)| (label.clone(), address.to_checksum()))
                    .collect();
                let mut connect_view = crate::ui::approval_view::connect_view(
                    site.origin.as_str(),
                    site.origin.is_http(),
                    &accounts,
                    &connect.selected,
                    &connect.chain_name,
                );
                connect_view.badges.extend(badges);
                connect_view.testnet = testnet;
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
        match view(
            &ui.session.gate.prepare,
            now,
            ui.raw_open,
            wide_layout,
            badges,
            testnet,
            ui.failure.as_deref(),
        ) {
            Ok(view) => {
                ui.view = view;
                ui.layout = None;
                ui.window.invalidate();
                ui.panel.invalidate();
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
        }
    }

    fn toggle_connect_account(&mut self, index: usize) {
        let now = now_ms();
        if let Some(ui) = self.evm.window.as_mut()
            && let Some(connect) = ui.connect.as_mut()
            && let Some(slot) = connect.selected.get_mut(index)
        {
            *slot = !*slot;
            let count = connect.selected.iter().filter(|checked| **checked).count();
            ui.session.gate.connect_selected = count;
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
                    Reply::Handled(MA_ACTIVATEANDEAT)
                }
            }
            Msg::Timer(APPROVAL_TIMER_ID) => {
                self.interaction(InteractionEvent::Tick);
                if let Some(ui) = self.evm.window.as_ref()
                    && matches!(
                        ui.session.gate.prepare,
                        PrepareState::Preparing(PrepareStage::Simulating { .. })
                    )
                {
                    self.rebuild_view();
                }
                Reply::Handled(0)
            }
            Msg::MouseDown { x, y } => {
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
                    ui.session.gate.is_foreground = true;
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
                Focus::Approve => self.interaction(InteractionEvent::ApproveActivated),
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
        match msg {
            Msg::Paint => {
                self.paint_panel(window);
                Reply::Handled(0)
            }
            Msg::MouseDown { x, y } => {
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
        // Header.
        let mut header_lines: Vec<(String, FontRole)> = ui
            .view
            .header
            .iter()
            .map(|(label, value)| (format!("{label}: {value}"), FontRole::Body))
            .collect();
        if header_lines.is_empty() {
            header_lines.push(("요청 출처: Your Wallet (이 앱)".to_owned(), FontRole::Body));
        }
        for badge in &ui.view.badges {
            header_lines.push((badge.clone(), FontRole::BodyBold));
        }
        let mut header_height = 0;
        for (text, role) in &header_lines {
            dc.select_font(fonts.get(*role));
            header_height += dc
                .measure_wrapped(&wide(text), width, DrawFlags::WRAP)
                .saturating_add(px(2));
        }
        if ui.view.testnet {
            dc.fill_rect(
                Rect::new(
                    0,
                    0,
                    client.w,
                    header_height.saturating_add(margin.saturating_mul(2)),
                ),
                theme::TESTNET_BG,
            );
        }
        for (text, role) in &header_lines {
            dc.select_font(fonts.get(*role));
            dc.set_text_color(theme::TEXT);
            let height = dc.measure_wrapped(&wide(text), width, DrawFlags::WRAP);
            dc.draw_text(
                &wide(text),
                Rect::new(margin, y, width, height),
                DrawFlags::WRAP,
            );
            y = y.saturating_add(height).saturating_add(px(2));
        }
        y = y.saturating_add(px(8));
        // Simulation band.
        let mut retry = None;
        if let Some(band) = ui.view.band.clone() {
            let pad = px(10);
            let inner = width.saturating_sub(pad.saturating_mul(2));
            dc.select_font(&fonts.body_bold);
            let head_h = dc.measure_wrapped(&wide(&band.head), inner, DrawFlags::WRAP);
            dc.select_font(&fonts.body);
            let detail_h = if band.detail.is_empty() {
                0
            } else {
                dc.measure_wrapped(&wide(&band.detail), inner, DrawFlags::WRAP)
            };
            let button_h = if band.retry { px(32) } else { 0 };
            let height = head_h
                .saturating_add(detail_h)
                .saturating_add(button_h)
                .saturating_add(pad.saturating_mul(3))
                .min(client.h / 3);
            let rect = Rect::new(margin, y, width, height);
            dc.fill_rect(rect, theme::DANGER_BG);
            dc.select_font(&fonts.body_bold);
            dc.set_text_color(theme::DANGER_TEXT);
            dc.draw_text(
                &wide(&band.head),
                Rect::new(margin + pad, y + pad, inner, head_h),
                DrawFlags::WRAP,
            );
            dc.select_font(&fonts.body);
            dc.draw_text(
                &wide(&band.detail),
                Rect::new(margin + pad, y + pad + head_h, inner, detail_h),
                DrawFlags::WRAP,
            );
            if band.retry {
                let button = Rect::new(margin + pad, y + height - pad - px(28), px(180), px(28));
                dc.fill_rect(button, theme::BG);
                dc.frame_rect(button, theme::DANGER_TEXT);
                dc.set_text_color(theme::DANGER_TEXT);
                dc.draw_text(&wide("시뮬레이션 다시 시도"), button, DrawFlags::CENTER);
                retry = Some(button);
            }
            y = y.saturating_add(height).saturating_add(px(8));
        }
        // Bottom bar.
        let bottom_h = px(96);
        let bottom_top = client.h.saturating_sub(bottom_h);
        dc.fill_rect(Rect::new(0, bottom_top, client.w, 1), theme::BORDER);
        let gate = &ui.session.gate;
        let remaining = gate.deadline_ms.saturating_sub(now);
        let mut status = String::new();
        if matches!(gate.prepare, PrepareState::Ready(_)) {
            let _ = write!(status, "남은 시간 {}", remaining_text(remaining));
        }
        let waiting = evm.queue.len().saturating_sub(1);
        if waiting > 0 {
            let _ = write!(status, "   ·   대기 중인 다른 요청 {waiting}건");
        }
        if let Some(message) = &ui.status {
            status.push_str("   ·   ");
            status.push_str(message);
        }
        let hold = ui.session.interaction().hold_remaining_ms(now);
        if let Some(left) = hold {
            let done = HIGH_RISK_HOLD_MS.saturating_sub(left);
            let _ = write!(status, "   ·   {}.{}초", done / 1_000, (done % 1_000) / 100);
        }
        dc.select_font(&fonts.body);
        dc.set_text_color(theme::MUTED);
        dc.draw_text(
            &wide(&status),
            Rect::new(margin, bottom_top + px(8), width, px(22)),
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
        dc.fill_rect(reject, theme::BG);
        dc.frame_rect(reject, theme::BORDER);
        dc.set_text_color(theme::TEXT);
        dc.draw_text(&wide("거부"), reject, DrawFlags::CENTER);
        let armed =
            ui.session.interaction().is_armed() && crate::ui::interaction::can_approve(gate, now);
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
        dc.fill_rect(
            approve,
            if armed {
                theme::PRIMARY_BG
            } else {
                theme::DISABLED_BG
            },
        );
        if let Some(left) = hold {
            let done = HIGH_RISK_HOLD_MS.saturating_sub(left);
            let progress = i32::try_from(
                u64::try_from(approve.w.max(0)).unwrap_or(0) * done / HIGH_RISK_HOLD_MS,
            )
            .unwrap_or(0);
            dc.fill_rect(
                Rect::new(approve.x, approve.y, progress, px(4)),
                theme::FOCUS,
            );
        }
        dc.set_text_color(if armed {
            theme::PRIMARY_TEXT
        } else {
            theme::MUTED
        });
        dc.draw_text(&wide(label), approve, DrawFlags::CENTER);
        match ui.focus {
            Focus::Approve => dc.frame_rect(approve.inset(-px(3)), theme::FOCUS),
            Focus::Reject => dc.frame_rect(reject.inset(-px(3)), theme::FOCUS),
            _ => {}
        }
        let panel = Rect::new(0, y, client.w, bottom_top.saturating_sub(y).max(px(40)));
        if panel != ui.bottom.panel {
            ui.panel.set_rect(panel);
            ui.layout = None;
            ui.panel.invalidate();
        }
        ui.bottom = Bottom {
            approve,
            reject,
            retry,
            panel,
        };
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
mod smoke;

/// E31 for a dApp transaction that carried fee fields (spec/03 §3.4, values ignored).
fn site_fee_warning(site: &SiteRequest) -> Vec<yw_core::approval::Warning> {
    match &site.kind {
        SiteKind::Send(tx) if tx.fee_fields => {
            vec![yw_core::evm::risk::warning(yw_core::evm::risk::E31, None)]
        }
        _ => Vec::new(),
    }
}
