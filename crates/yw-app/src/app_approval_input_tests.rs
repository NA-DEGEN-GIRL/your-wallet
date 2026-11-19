//! Approval window input mapping, re-entrancy and structure checks (2026-11-18, S4 A5;
//! spec/15 §11.4 S4, spec/04 §3.4, spec/01 §7.7, spec/09 §2.2): the goldens
//! `app/tests/s4_flow/input.txt` and `app/tests/s4_flow/reentry.txt`, recorded from today's code
//! before S4 moves a line of the approval window (owner decision O-2; reviewed at the F-A
//! checkpoint), and the source checks S1–S3 of the S4 plan (2026-11-19, S4 B2: S1 and S2
//! re-pointed to the input map `ui::approval_input`, and S8 added).
//!
//! **`input.txt`** (critique A-7): every arm of `on_approval_msg`, `on_approval_key` (through
//! `Msg::KeyDown`), `on_panel_msg` and `on_ai_body_msg`, delivered to a fresh window per row on
//! the A3 fixture (hidden windows, test clock, captured RPC channel and key queue), under the two
//! scripted trusted-signal oracles `fg-down` (A01 is the foreground window, raw and seamed; the
//! left button, Space and Shift are down; Enter is in the message's key state, not injected) and
//! `bg-up` (all of it false), plus an `injected` oracle for Enter and Space on `승인`. The window
//! got a `Tick` at +0 and the message comes at +1 500: armed under `fg-down` for the Standard,
//! connect and AI windows; the High window is not armed (its checkbox is unchecked), so a stray
//! press there restarts the delay (`ready=+1500` after an `OtherPress`, where the matching
//! Standard row keeps `ready=+0`). Button and panel rectangles are fixed values (`BOTTOM`,
//! `layout()`), not painted ones, and the real panel is moved to the fixed `BOTTOM.panel` size
//! (800 x 600 client pixels, so a page is 600 and the last scroll position 1 400). The panel
//! starts scrolled to `PANEL_SCROLL_START` with its scroll bar thumb at `PANEL_THUMB`, the AI
//! body at `AI_SCROLL_START` with the stand-in body window's thumb at `AI_THUMB`, so every page
//! key, every `WM_VSCROLL` code but `SB_ENDSCROLL` and the wheel move the view in a visible
//! direction (2026-11-18, A5 review: before, the panel had no size and no scroll position, so
//! the page keys and the page and thumb codes recorded `Scroll(0)`). No line depends on the
//! screen's DPI: a scroll is printed against its start, never in pixels. A line:
//! `<row> | <oracle> | reply <Reply of each message> | trace <the ordered input log of the
//! delivery: every oracle read with its program point and value, every A01 Win32 side effect
//! (`/skip` = the hidden host skipped it), every `interaction` event with its foreground sample
//! and focus, the `ActivateApp(true)` arm, every toggle/retry/scroll with the focus at the call
//! (scroll deltas as their sign, or `min`/`max`), every message the approval `Forward` dropped
//! because the App was borrowed> | after <the window afterwards: interaction status, gate
//! `ready` (relative to the clock origin) / foreground / checkbox, a hold in progress, the early
//! release mark, focus, pressed button, raw data open, connect selection, panel and AI body
//! scroll against the row's start (`0`, `start`, a named position: `start-page`, `start+page`,
//! `thumb`, `end`, else `<start` or `>start`; `-`: no AI body);
//! the store state of the issued request; the RPC and key jobs and dApp answers the delivery
//! caused>`.
//!
//! Branches inside the covered arms that `input.txt` does **not** pin (2026-11-18, A5 review):
//! the `ai.down` click on an inconsistent explanation (`toggle_expanded() == true`: it needs a
//! worker answer fed back, which these rows never do), and what `ai_tick` changes in the AI
//! panel's own state (`a01.timer.approval.ai-window` runs it on a live panel, but the panel state
//! is not printed). `a01.timer.approval.simulating` runs the `rebuild_view_with(false)` branch,
//! which has no traced effect of its own.
//!
//! **`reentry.txt`** (critique A-8): messages delivered through the real approval `Forward` with
//! the App **not** borrowed by the test, to the real A01 `HWND` (the test holds A01 and leaves an
//! inert hidden window in its place, so the Win32 calls of the arms act on A01 and A01's own
//! window procedure receives what they send). It pins: the messages sent while the window opens
//! and is prepared reach the `Forward` while the App is borrowed and are dropped; painting A01
//! moves its panel, and the panel's `WM_SIZE` is dropped the same way; on `MouseUp` the
//! `WM_CAPTURECHANGED` that `ReleaseCapture` sends to A01 is dropped (in the app the outer message
//! itself runs A01's handler, so yw-win's own running-handler guard drops it first; here the
//! `Forward`'s guard does) and a Standard click then approves exactly once; a capture taken by
//! another window while the button is held reaches the App (`CaptureLost`) and ends the press;
//! every message kind delivered to any of the three targets while the App is borrowed is dropped
//! (a paint is deferred) and leaves the App's state as it was. The dropped message's reply is
//! `Default`, and these scenarios call `Forward::on` directly, so what the window procedure then
//! does with it is **not** exercised: there `Reply::Default` goes to `DefWindowProc`, so a
//! re-entrant `WM_CLOSE` destroys A01 without `finish_approval` (the store item stays Pending and
//! the App still holds the dead window) and a re-entrant `WM_MOUSEACTIVATE` returns
//! `MA_ACTIVATE` (the activating click is not eaten). That is today's code (yw-win's own
//! running-handler guard answers the same way), a latent behaviour recorded for the owner at
//! F-A, not a harmless drop (2026-11-18, A5 review). Activation messages during a real (shown)
//! open are not produced here: the hidden host never shows, activates or focuses a window (A3);
//! the `while_borrowed` scenario pins the same drop for them only by direct calls. The order in
//! which `WM_ACTIVATEAPP`, `WM_MOUSEACTIVATE` and `WM_KILLFOCUS` reach A01 inside a shown open is
//! a gap left to the F-A review (the render harness shows a real window) and to B5's checks,
//! when the open becomes an effect. A line: `<scenario> <step> | reply <..> | trace <..> | after
//! <..>` (formats as above).
//!
//! Nothing here touches the network (the AI rows run the explanation worker on an in-process
//! transport that never opens a socket, the `tests/llm_mock.rs` pattern, and no answer is fed
//! back), a card reader, a process, the clipboard or the registry; files are written only below
//! each fixture's own temp folder (and by the `print_*` tests into `YW_S4_FLOW_OUT` when it is
//! set). Run (`#[ignore]`, gate step `s4fl`):
//! `cargo test -p yw-app --lib --locked --offline -- --ignored --test-threads=1 app_approval::input_tests`.
//! Regenerate for review (PowerShell): `$env:YW_S4_FLOW_OUT='<folder>'; cargo test -p yw-app
//! --lib --locked --offline -- --ignored --test-threads=1 app_approval::input_tests::print`.

use std::fmt::Write as _;
use std::rc::Rc;

use yw_core::approval::ApprovalId;
use yw_win::ui::{Handler, Msg, Rect, Reply, Window};

use super::flow_support::{self, Call, Fixture, HostMode, Logged, Outlet, Read, START_MS, Signals};
use super::flow_tests::{dapp, dapp_answers, personal_sign, request, spare_window};
use super::{APPROVAL_TIMER_ID, Bottom, Focus, Forward, PanelLayout, Pressed, Target};
use crate::explain::config::{ModelName, parse_endpoint};
use crate::explain::request::{HttpResponse, LlmTransport, TransportError};
use crate::explain::{ExplainService, LlmConfig, ResponseFormatMode};
use crate::ui::approval_input::{
    Surface, VK_DOWN, VK_END, VK_ESCAPE, VK_HOME, VK_NEXT, VK_PRIOR, VK_RETURN, VK_SPACE, VK_TAB,
    VK_UP,
};
use crate::ui::interaction::InteractionEvent;
use crate::workers::rpc::RpcJob;

/// The committed goldens.
const INPUT: &str = include_str!("app/tests/s4_flow/input.txt");
const REENTRY: &str = include_str!("app/tests/s4_flow/reentry.txt");

/// When the row's message comes (ms after the clock origin; the window's `Tick` was at +0).
const ARMED_AT: u64 = 1_500;
const VK_A: u16 = 0x41;
const TIMER_OTHER: usize = 99;

// ----- oracles ------------------------------------------------------------------------------

/// A01 is the foreground window (seamed and raw); left button, Space and Shift are down; Enter
/// is in the message's own key state and not injected.
const FG_DOWN: Signals = Signals {
    foreground: true,
    foreground_raw: true,
    lbutton_down: true,
    space_down: true,
    shift_down: true,
    enter_in_message: true,
    injected: false,
    set_foreground_ok: true,
};
/// Every read false.
const BG_UP: Signals = Signals {
    foreground: false,
    foreground_raw: false,
    lbutton_down: false,
    space_down: false,
    shift_down: false,
    enter_in_message: false,
    injected: false,
    set_foreground_ok: false,
};
/// `fg-down` with every key and button up (the release of a click).
const FG_UP: Signals = Signals {
    lbutton_down: false,
    space_down: false,
    shift_down: false,
    ..FG_DOWN
};
/// `fg-down`, but the message came from injected input (`SendInput`).
const INJECTED: Signals = Signals {
    injected: true,
    ..FG_DOWN
};

type Oracle = (&'static str, Signals);
const BOTH: &[Oracle] = &[("fg-down", FG_DOWN), ("bg-up", BG_UP)];
const ONLY_INJECTED: &[Oracle] = &[("injected", INJECTED)];

// ----- fixed geometry -----------------------------------------------------------------------

/// The bottom bar's rectangles of every row (A01 client pixels).
const BOTTOM: Bottom = Bottom {
    bar: Rect::new(0, 600, 800, 110),
    approve: Rect::new(600, 640, 120, 40),
    reject: Rect::new(460, 640, 120, 40),
    retry: Some(Rect::new(320, 640, 120, 40)),
    panel: Rect::new(0, 0, 800, 600),
    ai_retry: Some(Rect::new(180, 640, 120, 40)),
    ai_body: Rect::new(0, 0, 0, 0),
};
const AT_APPROVE: (i32, i32) = (660, 660);
const AT_REJECT: (i32, i32) = (520, 660);
const AT_RETRY: (i32, i32) = (380, 660);
const AT_AI_RETRY: (i32, i32) = (240, 660);
const AT_NOTHING: (i32, i32) = (50, 50);
const AT_ACCOUNT_0: (i32, i32) = (100, 115);
const AT_ACCOUNT_1: (i32, i32) = (100, 155);
const AT_ACK: (i32, i32) = (100, 215);
const AT_RAW: (i32, i32) = (100, 275);
const AT_PANEL_NOTHING: (i32, i32) = (100, 500);

/// Where the panel view starts in every row with the fixed geometry (content pixels; the last
/// position is `layout().height` 2 000 - the 600-pixel page = 1 400).
const PANEL_SCROLL_START: i32 = 700;
/// The panel content height of every row with the fixed geometry (`layout().height`).
const PANEL_CONTENT: i32 = 2_000;
/// The panel's scroll bar thumb at the start of a row (what `SB_THUMBPOSITION`/`SB_THUMBTRACK`
/// read): not the view's position, so a thumb code moves the view.
const PANEL_THUMB: i32 = 1_100;
/// Where the AI body view starts in every AI row (more than a page of the stand-in window, so a
/// page up stays above zero).
const AI_SCROLL_START: i32 = 2_000;
/// The stand-in AI body window's scroll bar thumb at the start of an AI body row.
const AI_THUMB: i32 = 3_000;

/// The panel layout of every row (panel content pixels): two account rows, the checkbox and the
/// raw-data switch, placed `PANEL_SCROLL_START` below the content top so that the `AT_*` panel
/// client points hit them through the start scroll (a click is mapped to content pixels).
fn layout() -> PanelLayout {
    let at = |y: i32| Rect::new(20, PANEL_SCROLL_START + y, 700, 30);
    PanelLayout {
        accounts: vec![(0, at(100)), (1, at(140))],
        ack: Some(at(200)),
        raw: Some(at(260)),
        height: PANEL_CONTENT,
        ..PanelLayout::default()
    }
}

const fn down((x, y): (i32, i32)) -> Msg {
    Msg::MouseDown { x, y }
}

const fn up((x, y): (i32, i32)) -> Msg {
    Msg::MouseUp { x, y }
}

const fn moved((x, y): (i32, i32)) -> Msg {
    Msg::MouseMove { x, y }
}

const fn key_down(vk: u16, repeat: bool) -> Msg {
    Msg::KeyDown { vk, repeat }
}

// ----- the explanation worker without a network ---------------------------------------------

/// An in-process transport (the `tests/llm_mock.rs` pattern): no socket, every request fails
/// as an OS error; its answer is never fed back to the App.
struct NoNetwork;

impl LlmTransport for NoNetwork {
    fn post(
        &self,
        _url: &yw_platform::http::EndpointUrl,
        _headers: &[(&str, &str)],
        _body: &[u8],
        _max_response: usize,
    ) -> Result<HttpResponse, TransportError> {
        Err(TransportError::Os(0))
    }
}

fn no_network_llm() -> ExplainService {
    let config = LlmConfig::new(
        parse_endpoint("https://llm.example.test/v1/chat/completions").unwrap(),
        ModelName::parse("mock-model").unwrap(),
        None,
        ResponseFormatMode::JsonSchema,
        0,
    );
    ExplainService::start_with(config, Box::new(NoNetwork), Box::new(|_| {})).unwrap()
}

// ----- windows ------------------------------------------------------------------------------

/// The window a row opens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// The S2 Sepolia app send (Standard).
    Std,
    /// The S3 app send (High: the checkbox block).
    High,
    /// An EVM connect (`eth_requestAccounts`) with two accounts.
    Connect,
    /// A site `personal_sign` with the explanation panel (AI body window).
    Ai,
    /// The S2 Sepolia app send while it is still simulating (its preparation not answered).
    Simulating,
}

/// One opened window and what the recorder needs of it.
struct Opened {
    fx: Fixture,
    outlet: Option<Outlet>,
    issued: Option<ApprovalId>,
    /// The fixed geometry and start positions are set (the `after` scrolls are printed against
    /// them; else against zero).
    fixed: bool,
}

/// Opens a fresh `kind` window on its own fixture, installs `oracle`, delivers the window's
/// `Tick` at +0 and moves the clock to +1 500; with `fixed`, the bottom bar and panel get the
/// fixed rectangles, the real panel the fixed size and scroll bar, and the views their start
/// positions. Everything captured on the way (jobs, answers, log) is discarded.
fn open(kind: Kind, oracle: Signals, tag: &str, fixed: bool) -> Opened {
    let fx = Fixture::new(tag, HostMode::Hidden);
    let outlet = match kind {
        Kind::Simulating => {
            fx.enqueue_sepolia_send();
            let _ = fx.rpc_jobs();
            let job = fx
                .app
                .borrow()
                .evm
                .approval
                .as_ref()
                .map_or(0, crate::approval_flow::ApprovalFlow::job);
            fx.app().on_simulating(job, START_MS);
            None
        }
        Kind::Std | Kind::High => {
            fx.enqueue_sepolia_send();
            let job = fx
                .rpc_jobs()
                .into_iter()
                .find_map(|job| match job {
                    RpcJob::Prepare(job) => Some(job),
                    _ => None,
                })
                .expect("a preparation job");
            fx.answer_prepare(&job, if kind == Kind::High { "S3" } else { "S2" });
            None
        }
        Kind::Connect => {
            let outlet = dapp(&fx, false, false);
            request(
                &fx,
                &outlet,
                1,
                "eth_requestAccounts",
                "[]",
                "permission",
                600_000,
            );
            Some(outlet)
        }
        Kind::Ai => {
            fx.app().llm = Some(no_network_llm());
            let outlet = dapp(&fx, false, true);
            personal_sign(&fx, &outlet, 1, 600_000);
            Some(outlet)
        }
    };
    flow_support::set_signals(Some(oracle));
    fx.app().interaction(InteractionEvent::Tick);
    fx.clock.set(START_MS + ARMED_AT);
    let issued = {
        let mut app = fx.app();
        // 2026-11-19 (S4 B6, A-13): the fixed layout stands for one drawn from the view shown.
        let view_rev = app
            .evm
            .approval
            .as_ref()
            .map_or(0, crate::approval_flow::ApprovalFlow::view_rev);
        let win = app.approval_win.as_mut().expect("the window is open");
        if fixed {
            let layout = PanelLayout {
                view_rev,
                ..layout()
            };
            win.panel.set_rect(BOTTOM.panel);
            win.panel
                .set_vscroll(PANEL_THUMB, BOTTOM.panel.h, layout.height);
            win.scroll = PANEL_SCROLL_START;
            win.bottom = BOTTOM;
            win.layout = Some(layout);
            if let Some(ai) = win.ai.as_mut() {
                ai.scroll = AI_SCROLL_START;
            }
        }
        app.evm
            .approval
            .as_ref()
            .and_then(|flow| flow.issued().map(|request| request.id))
    };
    let _ = fx.rpc_jobs();
    let _ = fx.key_jobs();
    if let Some(outlet) = outlet.as_ref() {
        let _ = outlet.answers();
    }
    let _ = flow_support::take_log();
    Opened {
        fx,
        outlet,
        issued,
        fixed,
    }
}

/// Delivers `msg` to `surface`'s arm of the window opened last with the App borrowed by the test
/// (as the window procedure would after `Forward` borrowed it). (2026-11-19, S4 B6: by surface;
/// `Target` now carries the window's `ShownId`.)
fn deliver(fx: &Fixture, surface: Surface, window: &Window, msg: &Msg) -> Reply {
    let mut app = fx.app();
    match surface {
        Surface::Approval => app.on_approval_msg(window, msg),
        Surface::Panel => app.on_panel_msg(window, msg),
        Surface::AiBody => app.on_ai_body_msg(window, msg),
    }
}

/// The real approval `Forward` of `target` (its kind and window id) on the fixture's App.
fn forward(fx: &Fixture, target: Target) -> Forward {
    Forward {
        app: Rc::downgrade(&fx.app),
        target,
    }
}

/// Takes the real A01 out of the App and leaves an inert hidden window in its place, so a
/// message delivered through `Forward` with A01 runs the arms on the real `HWND` while the App
/// is not borrowed (the arms' own window reads go through the oracle).
fn take_a01(fx: &Fixture) -> Window {
    let mut held = spare_window();
    if let Some(win) = fx.app().approval_win.as_mut() {
        std::mem::swap(&mut win.window, &mut held);
    }
    held
}

/// Puts A01 back while its window is still open (else dropping it destroys it).
fn put_back(fx: &Fixture, mut held: Window) {
    if let Some(win) = fx.app().approval_win.as_mut() {
        std::mem::swap(&mut win.window, &mut held);
    }
}

// ----- formatting ---------------------------------------------------------------------------

fn names<S: AsRef<str>>(items: impl Iterator<Item = S>) -> String {
    let joined = items
        .map(|item| item.as_ref().to_owned())
        .collect::<Vec<_>>()
        .join(",");
    if joined.is_empty() {
        "-".to_owned()
    } else {
        joined
    }
}

/// Monotonic `ms` relative to the clock origin.
fn rel(ms: u64) -> String {
    if ms >= u64::MAX / 2 {
        "max".to_owned()
    } else if ms >= START_MS {
        format!("+{}", ms - START_MS)
    } else {
        format!("-{}", START_MS - ms)
    }
}

fn bit(value: bool) -> u8 {
    u8::from(value)
}

fn focus_name(focus: Option<Focus>) -> String {
    focus.map_or_else(|| "-".to_owned(), |focus| format!("{focus:?}"))
}

/// A message's variant name (no coordinates, sizes or codes).
fn msg_name(msg: &Msg) -> String {
    let text = format!("{msg:?}");
    text.split([' ', '(', '{'])
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn read_name(read: Read) -> String {
    match read {
        Read::Foreground => "fg".to_owned(),
        Read::RawForeground(point) => format!("raw-fg@{point}"),
        Read::KeyDown(vk, point) => format!("key{vk:02x}@{point}"),
        Read::EnterInMessage => "enter-in-msg".to_owned(),
        Read::Injected => "injected".to_owned(),
    }
}

fn call_name(call: Call) -> String {
    match call {
        Call::Scroll(delta) if delta == i32::MIN / 2 => "Scroll(min)".to_owned(),
        Call::Scroll(delta) if delta == i32::MAX / 2 => "Scroll(max)".to_owned(),
        Call::Scroll(delta) => format!(
            "Scroll({})",
            match delta.signum() {
                -1 => "-",
                0 => "0",
                _ => "+",
            }
        ),
        other => format!("{other:?}"),
    }
}

/// The input log as one trace (format in the module doc).
fn trace(log: &[Logged]) -> String {
    let parts: Vec<String> = log
        .iter()
        .map(|entry| match *entry {
            Logged::Read { read, value } => format!("read {}={}", read_name(read), bit(value)),
            Logged::Effect { fx, performed } => {
                format!("fx {fx:?}{}", if performed { "" } else { "/skip" })
            }
            Logged::Event {
                event,
                foreground,
                focus,
            } => format!(
                "ev {event:?} fg={} focus={}",
                foreground.map_or_else(|| "-".to_owned(), |fg| bit(fg).to_string()),
                focus_name(focus)
            ),
            Logged::Activated { focus } => format!("activated focus={}", focus_name(focus)),
            Logged::Call { call, focus } => {
                format!("call {} focus={}", call_name(call), focus_name(focus))
            }
            Logged::Dropped { target, msg } => format!("drop {target}:{}", msg_name(&msg)),
        })
        .collect();
    if parts.is_empty() {
        "-".to_owned()
    } else {
        parts.join("; ")
    }
}

fn replies(replies: &[Reply]) -> String {
    names(replies.iter().map(|reply| format!("{reply:?}")))
}

/// A view position, never in pixels: `0`, `start`, one of the row's `named` positions, else
/// `<start` or `>start`.
fn against(scroll: i32, start: i32, named: &[(i32, &'static str)]) -> &'static str {
    if scroll == 0 {
        return "0";
    }
    if scroll == start {
        return "start";
    }
    if let Some((_, name)) = named.iter().find(|(at, _)| *at == scroll) {
        return name;
    }
    if scroll < start { "<start" } else { ">start" }
}

/// The panel positions a fixed row names: a page above and below the start, the thumb and the
/// last position (all DPI-independent; a line or wheel step is not).
const PANEL_NAMED: [(i32, &str); 4] = [
    (PANEL_SCROLL_START - BOTTOM.panel.h, "start-page"),
    (PANEL_SCROLL_START + BOTTOM.panel.h, "start+page"),
    (PANEL_THUMB, "thumb"),
    (PANEL_CONTENT - BOTTOM.panel.h, "end"),
];
/// The AI body positions a fixed row names (its page is the stand-in window's, not fixed).
const AI_NAMED: [(i32, &str); 2] = [(AI_THUMB, "thumb"), (i32::MAX / 2, "end")];

/// The window and what the delivery caused (format in the module doc).
fn after(opened: &Opened, issued: Option<ApprovalId>) -> String {
    let fx = &opened.fx;
    let outlet = opened.outlet.as_ref();
    let now = fx.clock.peek();
    let app = fx.app.borrow();
    let mut line = match (app.evm.approval.as_ref(), app.approval_win.as_ref()) {
        (Some(flow), Some(win)) => {
            let gate = flow.gate();
            format!(
                "win open status={:?} ready={} fg={} ack={} hold={} early={} focus={:?} \
                 pressed={} raw={} sel={} scroll={} ai-scroll={}",
                flow.session().interaction().status(),
                rel(gate.ready_at_ms),
                bit(gate.is_foreground),
                bit(gate.ack_checked),
                bit(flow
                    .session()
                    .interaction()
                    .hold_remaining_ms(now)
                    .is_some()),
                bit(flow.early_release()),
                win.focus,
                win.pressed
                    .map_or_else(|| "-".to_owned(), |pressed| format!("{pressed:?}")),
                bit(flow.raw_open()),
                flow.connect().map_or_else(
                    || "-".to_owned(),
                    |connect| connect
                        .selected
                        .iter()
                        .map(|checked| if *checked { '1' } else { '0' })
                        .collect()
                ),
                if opened.fixed {
                    against(win.scroll, PANEL_SCROLL_START, &PANEL_NAMED)
                } else {
                    against(win.scroll, 0, &[])
                },
                win.ai.as_ref().map_or("-", |ai| if opened.fixed {
                    against(ai.scroll, AI_SCROLL_START, &AI_NAMED)
                } else {
                    against(ai.scroll, 0, &[])
                }),
            )
        }
        _ => "win closed".to_owned(),
    };
    let store = issued
        .and_then(|id| app.evm.store.state(id))
        .map_or_else(|| "-".to_owned(), |state| format!("{state:?}"));
    drop(app);
    let rpc = names(fx.rpc_jobs().iter().map(RpcJob::name));
    let key = names(fx.key_jobs().iter().map(crate::events::KeyJob::name));
    let dapp = outlet.map_or_else(|| "-".to_owned(), dapp_answers);
    let _ = write!(
        line,
        " | store {store} | rpc {rpc} | key {key} | dapp {dapp}"
    );
    line
}

// ----- the input rows -----------------------------------------------------------------------

/// One row of `input.txt`: the messages delivered in order to one arm of a fresh window.
struct Row {
    name: String,
    kind: Kind,
    target: Surface,
    focus: Focus,
    pressed: Option<Pressed>,
    msgs: Vec<Msg>,
    oracles: &'static [Oracle],
}

impl Row {
    fn new(name: &str, kind: Kind, target: Surface, msgs: Vec<Msg>) -> Self {
        Self {
            name: name.to_owned(),
            kind,
            target,
            focus: Focus::Reject,
            pressed: None,
            msgs,
            oracles: BOTH,
        }
    }

    const fn focus(mut self, focus: Focus) -> Self {
        self.focus = focus;
        self
    }

    const fn pressed(mut self, pressed: Pressed) -> Self {
        self.pressed = Some(pressed);
        self
    }

    const fn oracles(mut self, oracles: &'static [Oracle]) -> Self {
        self.oracles = oracles;
        self
    }
}

/// The A01 rows (`on_approval_msg`), on the Standard send unless named.
fn a01_rows() -> Vec<Row> {
    let row = |name: &str, msgs: Vec<Msg>| Row::new(name, Kind::Std, Surface::Approval, msgs);
    vec![
        row("a01.stray.other-button", vec![Msg::OtherButtonDown]),
        row("a01.stray.non-client", vec![Msg::NonClientButtonDown]),
        row("a01.paint", vec![Msg::Paint]),
        row("a01.size", vec![Msg::Size { w: 800, h: 700 }]),
        row("a01.dpi-changed", vec![Msg::DpiChanged { dpi: 96 }]),
        row("a01.mouse-activate", vec![Msg::MouseActivate]),
        row("a01.timer.approval", vec![Msg::Timer(APPROVAL_TIMER_ID)]),
        Row::new(
            "a01.timer.approval.ai-window",
            Kind::Ai,
            Surface::Approval,
            vec![Msg::Timer(APPROVAL_TIMER_ID)],
        ),
        Row::new(
            "a01.timer.approval.simulating",
            Kind::Simulating,
            Surface::Approval,
            vec![Msg::Timer(APPROVAL_TIMER_ID)],
        ),
        row("a01.timer.other", vec![Msg::Timer(TIMER_OTHER)]),
        row("a01.down.approve", vec![down(AT_APPROVE)]),
        row("a01.down.reject", vec![down(AT_REJECT)]),
        row("a01.down.retry", vec![down(AT_RETRY)]),
        row("a01.down.ai-retry", vec![down(AT_AI_RETRY)]),
        row("a01.down.elsewhere", vec![down(AT_NOTHING)]),
        row("a01.click.approve", vec![down(AT_APPROVE), up(AT_APPROVE)]),
        row("a01.click.reject", vec![down(AT_REJECT), up(AT_REJECT)]),
        row("a01.move.pressed-inside", vec![moved(AT_APPROVE)]).pressed(Pressed::Approve),
        row("a01.move.pressed-outside", vec![moved(AT_NOTHING)]).pressed(Pressed::Approve),
        row("a01.move.unpressed", vec![moved(AT_APPROVE)]),
        row("a01.up.approve-inside", vec![up(AT_APPROVE)]).pressed(Pressed::Approve),
        row("a01.up.approve-outside", vec![up(AT_NOTHING)]).pressed(Pressed::Approve),
        row("a01.up.reject-inside", vec![up(AT_REJECT)]).pressed(Pressed::Reject),
        row("a01.up.reject-outside", vec![up(AT_NOTHING)]).pressed(Pressed::Reject),
        row("a01.up.retry-inside", vec![up(AT_RETRY)]).pressed(Pressed::Retry),
        row("a01.up.retry-outside", vec![up(AT_NOTHING)]).pressed(Pressed::Retry),
        row("a01.up.ai-retry-inside", vec![up(AT_AI_RETRY)]).pressed(Pressed::AiRetry),
        Row::new(
            "a01.up.ai-retry-inside.ai-window",
            Kind::Ai,
            Surface::Approval,
            vec![up(AT_AI_RETRY)],
        )
        .pressed(Pressed::AiRetry),
        row("a01.up.unpressed", vec![up(AT_APPROVE)]),
        row("a01.keyup.space.approve", vec![Msg::KeyUp { vk: VK_SPACE }]).focus(Focus::Approve),
        row("a01.keyup.space.reject", vec![Msg::KeyUp { vk: VK_SPACE }]),
        row(
            "a01.keyup.return.approve",
            vec![Msg::KeyUp { vk: VK_RETURN }],
        )
        .focus(Focus::Approve),
        row("a01.wheel.down", vec![Msg::Wheel(-120)]),
        row("a01.wheel.up", vec![Msg::Wheel(120)]),
        row(
            "a01.kill-focus.foreign",
            vec![Msg::KillFocus { to_foreign: true }],
        ),
        row(
            "a01.kill-focus.own",
            vec![Msg::KillFocus { to_foreign: false }],
        ),
        row("a01.activate-app.false", vec![Msg::ActivateApp(false)]),
        row("a01.activate-app.true", vec![Msg::ActivateApp(true)]),
        row("a01.capture-changed.pressed", vec![Msg::CaptureChanged]).pressed(Pressed::Approve),
        row("a01.capture-changed.unpressed", vec![Msg::CaptureChanged]),
        row("a01.cancel-mode", vec![Msg::CancelMode]),
        row("a01.close", vec![Msg::Close]),
        row("a01.other.char", vec![Msg::Char(0x41)]),
        row("a01.other.create", vec![Msg::Create]),
        row("a01.other.destroy", vec![Msg::Destroy]),
        row("a01.other.exit-size-move", vec![Msg::ExitSizeMove]),
        row("a01.other.command", vec![Msg::Command { id: 1, code: 0 }]),
        row("a01.other.vscroll", vec![Msg::VScroll { code: 1 }]),
    ]
}

/// The keyboard rows (`map_key` through `Msg::KeyDown`; 2026-11-19, S4 B6: `on_approval_key` is
/// gone): every key the arm names and one
/// it does not, × focus; Enter and Space also auto-repeated. The checkbox focus is on the High
/// send (the only one with the checkbox); the rest on the Standard send.
fn key_rows() -> Vec<Row> {
    const KEYS: [(&str, u16, bool); 11] = [
        ("tab", VK_TAB, false),
        ("escape", VK_ESCAPE, false),
        ("return", VK_RETURN, true),
        ("space", VK_SPACE, true),
        ("pageup", VK_PRIOR, false),
        ("pagedown", VK_NEXT, false),
        ("home", VK_HOME, false),
        ("end", VK_END, false),
        ("up", VK_UP, false),
        ("down", VK_DOWN, false),
        ("a", VK_A, false),
    ];
    const FOCI: [Focus; 5] = [
        Focus::Reject,
        Focus::Ack,
        Focus::Approve,
        Focus::Raw,
        Focus::Scroll,
    ];
    let mut rows = Vec::new();
    for (key, vk, repeats) in KEYS {
        for repeat in [false, true] {
            if repeat && !repeats {
                continue;
            }
            for focus in FOCI {
                let kind = if focus == Focus::Ack {
                    Kind::High
                } else {
                    Kind::Std
                };
                let focus_name = format!("{focus:?}").to_ascii_lowercase();
                rows.push(
                    Row::new(
                        &format!("key.{key}.{focus_name}.r{}", bit(repeat)),
                        kind,
                        Surface::Approval,
                        vec![key_down(vk, repeat)],
                    )
                    .focus(focus),
                );
            }
        }
    }
    for (key, vk) in [("return", VK_RETURN), ("space", VK_SPACE)] {
        rows.push(
            Row::new(
                &format!("key.{key}.approve.r0.injected"),
                Kind::Std,
                Surface::Approval,
                vec![key_down(vk, false)],
            )
            .focus(Focus::Approve)
            .oracles(ONLY_INJECTED),
        );
    }
    rows
}

/// Every `WM_VSCROLL` code the arms name (`SB_LINEUP` 0 … `SB_BOTTOM` 7) and `SB_ENDSCROLL` 8.
fn vscroll_rows(prefix: &str, kind: Kind, target: Surface) -> Vec<Row> {
    (0..=8_u16)
        .map(|code| {
            Row::new(
                &format!("{prefix}.vscroll.{code}"),
                kind,
                target,
                vec![Msg::VScroll { code }],
            )
        })
        .collect()
}

/// The panel rows (`on_panel_msg`).
fn panel_rows() -> Vec<Row> {
    let row = |name: &str, kind: Kind, msgs: Vec<Msg>| Row::new(name, kind, Surface::Panel, msgs);
    let mut rows = vec![
        row(
            "panel.stray.other-button",
            Kind::Std,
            vec![Msg::OtherButtonDown],
        ),
        row(
            "panel.stray.non-client",
            Kind::Std,
            vec![Msg::NonClientButtonDown],
        ),
        row("panel.paint", Kind::Std, vec![Msg::Paint]),
        row(
            "panel.down.account-0",
            Kind::Connect,
            vec![down(AT_ACCOUNT_0)],
        ),
        row(
            "panel.down.account-1",
            Kind::Connect,
            vec![down(AT_ACCOUNT_1)],
        ),
        row("panel.down.ack", Kind::High, vec![down(AT_ACK)]),
        row("panel.down.raw", Kind::Std, vec![down(AT_RAW)]),
        row(
            "panel.down.elsewhere",
            Kind::Std,
            vec![down(AT_PANEL_NOTHING)],
        ),
        row("panel.wheel.down", Kind::Std, vec![Msg::Wheel(-120)]),
        row("panel.wheel.up", Kind::Std, vec![Msg::Wheel(120)]),
    ];
    rows.extend(vscroll_rows("panel", Kind::Std, Surface::Panel));
    rows.extend([
        row("panel.other.mouse-up", Kind::Std, vec![up(AT_ACK)]),
        row(
            "panel.other.mouse-activate",
            Kind::Std,
            vec![Msg::MouseActivate],
        ),
        row(
            "panel.other.key-down",
            Kind::Std,
            vec![key_down(VK_RETURN, false)],
        ),
        row(
            "panel.other.capture-changed",
            Kind::Std,
            vec![Msg::CaptureChanged],
        ),
    ]);
    rows
}

/// The AI body rows (`on_ai_body_msg`, a site `personal_sign` with the explanation panel).
fn ai_rows() -> Vec<Row> {
    let row = |name: &str, msgs: Vec<Msg>| Row::new(name, Kind::Ai, Surface::AiBody, msgs);
    let mut rows = vec![
        row("ai.stray.other-button", vec![Msg::OtherButtonDown]),
        row("ai.stray.non-client", vec![Msg::NonClientButtonDown]),
        row("ai.paint", vec![Msg::Paint]),
        row("ai.down", vec![down(AT_NOTHING)]),
        row("ai.wheel.down", vec![Msg::Wheel(-120)]),
        row("ai.wheel.up", vec![Msg::Wheel(120)]),
    ];
    rows.extend(vscroll_rows("ai", Kind::Ai, Surface::AiBody));
    rows.extend([
        row("ai.other.mouse-up", vec![up(AT_NOTHING)]),
        row("ai.other.mouse-activate", vec![Msg::MouseActivate]),
        row("ai.other.key-down", vec![key_down(VK_RETURN, false)]),
    ]);
    rows
}

/// The groups of `input.txt`, in file order.
fn groups() -> [(&'static str, Vec<Row>); 4] {
    [
        ("a01", a01_rows()),
        ("key", key_rows()),
        ("panel", panel_rows()),
        ("ai", ai_rows()),
    ]
}

/// Runs one row under one oracle: a fresh window, the pre-state (focus, pressed button), the
/// messages, the line.
fn run_row(row: &Row, oracle: &Oracle, serial: usize) -> String {
    let opened = open(row.kind, oracle.1, &format!("input-{serial}"), true);
    let fx = &opened.fx;
    let spare = spare_window();
    if row.target == Surface::AiBody {
        // The stand-in AI body's scroll bar: what the thumb codes read.
        spare.set_vscroll(AI_THUMB, 100, 10_000);
    }
    if let Some(win) = fx.app().approval_win.as_mut() {
        win.focus = row.focus;
        win.pressed = row.pressed;
    }
    let replies_seen: Vec<Reply> = row
        .msgs
        .iter()
        .map(|msg| deliver(fx, row.target, &spare, msg))
        .collect();
    let log = flow_support::take_log();
    format!(
        "{} | {} | reply {} | trace {} | after {}",
        row.name,
        oracle.0,
        replies(&replies_seen),
        trace(&log),
        after(&opened, opened.issued)
    )
}

/// The lines of `group` (every row under each of its oracles).
fn group_lines(group: &str) -> Vec<String> {
    let (_, rows) = groups()
        .into_iter()
        .find(|(name, _)| *name == group)
        .expect("a group of the table");
    let mut lines = Vec::new();
    for row in &rows {
        for oracle in row.oracles {
            lines.push(run_row(row, oracle, lines.len()));
        }
    }
    lines
}

/// `(row, oracle)` of every line `input.txt` must hold, in order (no window).
fn expected_input_keys() -> Vec<(String, &'static str)> {
    let mut keys = Vec::new();
    for (_, rows) in groups() {
        for row in rows {
            for oracle in row.oracles {
                keys.push((row.name.clone(), oracle.0));
            }
        }
    }
    keys
}

// ----- the re-entrancy scenarios ------------------------------------------------------------

/// The lines of one re-entrancy scenario.
struct Rec<'a> {
    name: &'static str,
    opened: &'a Opened,
    /// The last request the window issued (its store state is printed).
    issued: Option<ApprovalId>,
    lines: Vec<String>,
}

impl<'a> Rec<'a> {
    const fn new(name: &'static str, opened: &'a Opened) -> Self {
        Self {
            name,
            opened,
            issued: opened.issued,
            lines: Vec::new(),
        }
    }

    fn line(&mut self, step: &str, replies_seen: &[Reply]) {
        let log = flow_support::take_log();
        if let Some(id) = self
            .opened
            .fx
            .app
            .borrow()
            .evm
            .approval
            .as_ref()
            .and_then(|flow| flow.issued().map(|request| request.id))
        {
            self.issued = Some(id);
        }
        let after = after(self.opened, self.issued);
        self.lines.push(format!(
            "{} {step} | reply {} | trace {} | after {after}",
            self.name,
            replies(replies_seen),
            trace(&log)
        ));
    }
}

/// The center of A01's `승인` button as last painted.
fn approve_center(fx: &Fixture) -> (i32, i32) {
    fx.app.borrow().approval_win.as_ref().map_or((0, 0), |win| {
        let rect = win.bottom.approve;
        (rect.x + rect.w / 2, rect.y + rect.h / 2)
    })
}

/// A-8: what reaches the `Forward` while the window opens and is prepared (the App borrowed by
/// `enqueue_app` and `on_prepared`) is dropped; nothing is shown, activated or focused.
fn reentry_open() -> Vec<String> {
    let opened = Opened {
        fx: Fixture::new("reentry-open", HostMode::Hidden),
        outlet: None,
        issued: None,
        fixed: false,
    };
    let fx = &opened.fx;
    flow_support::set_signals(Some(FG_DOWN));
    let _ = flow_support::take_log();
    let mut rec = Rec::new("reentry_open", &opened);
    fx.enqueue_sepolia_send();
    let jobs = fx.rpc_jobs();
    let sent = names(jobs.iter().map(RpcJob::name));
    let job = jobs
        .into_iter()
        .find_map(|job| match job {
            RpcJob::Prepare(job) => Some(job),
            _ => None,
        })
        .expect("a preparation job");
    rec.line("enqueue", &[]);
    rec.lines
        .push(format!("reentry_open enqueue-jobs | rpc {sent}"));
    fx.answer_prepare(&job, "S2");
    rec.line("prepare", &[]);
    rec.lines
}

/// A-8: a Standard click through the real `Forward` on the real A01: painting it moves the panel
/// (the panel's `WM_SIZE` is dropped: the App is borrowed by the paint); on `MouseUp` the
/// `WM_CAPTURECHANGED` that `ReleaseCapture` sends to A01 is dropped and the click approves
/// exactly once.
fn reentry_click() -> Vec<String> {
    let opened = open(Kind::Std, FG_DOWN, "reentry-click", false);
    let mut rec = Rec::new("reentry_click", &opened);
    let fx = &opened.fx;
    let a01 = take_a01(fx);
    let shown = fx.app.borrow().last_opened();
    let mut approval = forward(fx, Target::Approval(shown));
    let reply = approval.on(&a01, &Msg::Paint);
    rec.line("paint", &[reply]);
    let at = approve_center(fx);
    let reply = approval.on(&a01, &down(at));
    rec.line("down", &[reply]);
    flow_support::set_signals(Some(FG_UP));
    let reply = approval.on(&a01, &up(at));
    rec.line("up", &[reply]);
    // Inputs after the approval find no window.
    fx.clock.advance(1_100);
    flow_support::set_signals(Some(FG_DOWN));
    let first = approval.on(&a01, &down(at));
    flow_support::set_signals(Some(FG_UP));
    let second = approval.on(&a01, &up(at));
    rec.line("click-again", &[first, second]);
    put_back(fx, a01);
    rec.lines
}

/// A-8: another window takes the capture while `승인` is held: A01's `WM_CAPTURECHANGED` comes
/// through its own window procedure with the App free and ends the press (`CaptureLost`); the
/// release then sends nothing; two new clicks later (as today: the first is not taken, the
/// second approves).
fn reentry_capture_taken() -> Vec<String> {
    let opened = open(Kind::Std, FG_DOWN, "reentry-capture", false);
    let mut rec = Rec::new("reentry_capture_taken", &opened);
    let fx = &opened.fx;
    let a01 = take_a01(fx);
    let shown = fx.app.borrow().last_opened();
    let mut approval = forward(fx, Target::Approval(shown));
    let reply = approval.on(&a01, &Msg::Paint);
    rec.line("paint", &[reply]);
    let at = approve_center(fx);
    let reply = approval.on(&a01, &down(at));
    rec.line("down", &[reply]);
    let other = spare_window();
    other.set_capture();
    rec.line("capture-elsewhere", &[]);
    flow_support::set_signals(Some(FG_UP));
    let reply = approval.on(&a01, &up(at));
    rec.line("up", &[reply]);
    fx.clock.advance(1_200);
    flow_support::set_signals(Some(FG_DOWN));
    let first = approval.on(&a01, &down(at));
    flow_support::set_signals(Some(FG_UP));
    let second = approval.on(&a01, &up(at));
    rec.line("click-again", &[first, second]);
    fx.clock.advance(1_100);
    flow_support::set_signals(Some(FG_DOWN));
    let first = approval.on(&a01, &down(at));
    flow_support::set_signals(Some(FG_UP));
    let second = approval.on(&a01, &up(at));
    rec.line("click-third", &[first, second]);
    put_back(fx, a01);
    rec.lines
}

/// A-8: while the App is borrowed (as during an open, a paint or any handler), every message to
/// the approval window, its panel and its AI body is dropped (a paint is deferred) and the gate,
/// focus and window stay as they were. The `Default` replies are not passed on here; in the app
/// they reach `DefWindowProc` (module doc: a re-entrant `WM_CLOSE` destroys A01 without
/// `finish_approval`, a re-entrant `WM_MOUSEACTIVATE` is not eaten).
fn reentry_while_borrowed() -> Vec<String> {
    let opened = open(Kind::Std, FG_DOWN, "reentry-borrowed", true);
    let mut rec = Rec::new("reentry_while_borrowed", &opened);
    let fx = &opened.fx;
    let a01 = take_a01(fx);
    let other = spare_window();
    rec.line("before", &[]);
    let shown = fx.app.borrow().last_opened();
    let messages = [
        (Target::Approval(shown), Msg::ActivateApp(true)),
        (Target::Approval(shown), Msg::ActivateApp(false)),
        (Target::Approval(shown), Msg::MouseActivate),
        (Target::Approval(shown), Msg::KillFocus { to_foreign: true }),
        (Target::Approval(shown), down(AT_APPROVE)),
        (Target::Approval(shown), up(AT_APPROVE)),
        (Target::Approval(shown), key_down(VK_RETURN, false)),
        (Target::Approval(shown), key_down(VK_ESCAPE, false)),
        (Target::Approval(shown), Msg::Timer(APPROVAL_TIMER_ID)),
        (Target::Approval(shown), Msg::CaptureChanged),
        (Target::Approval(shown), Msg::Close),
        (Target::Panel(shown), down(AT_ACK)),
        (Target::Panel(shown), Msg::VScroll { code: 1 }),
        (Target::AiBody(shown), down(AT_NOTHING)),
        (Target::AiBody(shown), Msg::Wheel(120)),
        (Target::Panel(shown), Msg::Paint),
        (Target::Approval(shown), Msg::Paint),
    ];
    let mut seen = Vec::new();
    {
        let _borrowed = fx.app();
        for (target, msg) in &messages {
            let window = if *target == Target::Approval(shown) {
                &a01
            } else {
                &other
            };
            seen.push(forward(fx, *target).on(window, msg));
        }
    }
    rec.line("borrowed", &seen);
    put_back(fx, a01);
    rec.lines
}

type Scenario = fn() -> Vec<String>;

/// Every re-entrancy scenario, in golden order.
const REENTRY_SCENARIOS: [(&str, Scenario); 4] = [
    ("reentry_open", reentry_open),
    ("reentry_click", reentry_click),
    ("reentry_capture_taken", reentry_capture_taken),
    ("reentry_while_borrowed", reentry_while_borrowed),
];

// ----- comparing ----------------------------------------------------------------------------

/// The first line where `generated` and `committed` differ, as an assertion message.
fn first_difference(name: &str, generated: &[&str], committed: &[&str]) -> String {
    let at = generated
        .iter()
        .zip(committed)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| generated.len().min(committed.len()));
    format!(
        "{name}: line {} differs (generated {}, committed {}):\n  generated: {:?}\n  committed: \
         {:?}\nevery generated line:\n{}",
        at + 1,
        generated.len(),
        committed.len(),
        generated.get(at),
        committed.get(at),
        generated.join("\n")
    )
}

fn compare(name: &str, lines: &[String], committed: &[&str]) {
    let generated: Vec<&str> = lines.iter().map(String::as_str).collect();
    assert!(
        generated == committed,
        "{}",
        first_difference(name, &generated, committed)
    );
}

/// Runs the `input.txt` group `group` and compares it with its committed lines.
fn run_group(group: &str) {
    let prefix = format!("{group}.");
    let committed: Vec<&str> = INPUT
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .collect();
    compare(group, &group_lines(group), &committed);
}

/// Runs the re-entrancy scenario `name` and compares it with its committed lines.
fn run_reentry(name: &str) {
    let (_, scenario) = REENTRY_SCENARIOS
        .iter()
        .find(|(known, _)| *known == name)
        .expect("a scenario of the table");
    let prefix = format!("{name} ");
    let committed: Vec<&str> = REENTRY
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .collect();
    compare(name, &scenario(), &committed);
}

/// Writes `file` into `YW_S4_FLOW_OUT` (for review) and returns `true`, or returns `false`.
fn write_out(file: &str, lines: &[String]) -> bool {
    let Some(dir) = std::env::var_os("YW_S4_FLOW_OUT") else {
        return false;
    };
    let dir = std::path::PathBuf::from(dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut out = lines.join("\n");
    out.push('\n');
    std::fs::write(dir.join(file), out).unwrap();
    true
}

#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step s4fl)"]
fn golden_input_a01() {
    run_group("a01");
}

#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step s4fl)"]
fn golden_input_keys() {
    run_group("key");
}

#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step s4fl)"]
fn golden_input_panel() {
    run_group("panel");
}

#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step s4fl)"]
fn golden_input_ai_body() {
    run_group("ai");
}

#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step s4fl)"]
fn golden_reentry_open() {
    run_reentry("reentry_open");
}

#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step s4fl)"]
fn golden_reentry_click() {
    run_reentry("reentry_click");
}

#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step s4fl)"]
fn golden_reentry_capture_taken() {
    run_reentry("reentry_capture_taken");
}

#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step s4fl)"]
fn golden_reentry_while_borrowed() {
    run_reentry("reentry_while_borrowed");
}

/// Both goldens in full: writes `input.txt` and `reentry.txt` into `YW_S4_FLOW_OUT` when it is
/// set (for review), else compares each whole file (order and completeness).
#[test]
#[ignore = "creates hidden approval windows (S4 flow harness, gate step s4fl)"]
fn print() {
    let mut input = Vec::new();
    for (group, _) in groups() {
        input.extend(group_lines(group));
    }
    let mut reentry = Vec::new();
    for (_, scenario) in &REENTRY_SCENARIOS {
        reentry.extend(scenario());
    }
    let wrote_input = write_out("input.txt", &input);
    let wrote_reentry = write_out("reentry.txt", &reentry);
    if wrote_input && wrote_reentry {
        return;
    }
    compare("input.txt", &input, &INPUT.lines().collect::<Vec<_>>());
    compare(
        "reentry.txt",
        &reentry,
        &REENTRY.lines().collect::<Vec<_>>(),
    );
}

/// A golden line holds no address, URL, e-mail, local path or non-ASCII text.
fn assert_clean(line: &str) {
    for banned in ["0x", "://", "@", "\\", "Users"] {
        // `@` names a program point in a read (`raw-fg@mouse_down`); nothing else uses it.
        if banned == "@" {
            let points = line.matches('@').count();
            let reads = line.matches("@mouse_").count()
                + line.matches("@key_").count()
                + line.matches("@tab").count();
            assert_eq!(points, reads, "a stray @ in {line}");
            continue;
        }
        assert!(!line.contains(banned), "{banned:?} in {line}");
    }
    assert!(line.is_ascii(), "non-ASCII text in {line}");
}

/// `input.txt` holds exactly the table's rows under their oracles, in order, and
/// `reentry.txt` only the scenarios of its table, each one block in table order; neither holds
/// an address, URL, e-mail, local path or non-ASCII text (gate test step; no window).
#[test]
fn the_input_goldens_hold_only_known_rows() {
    let keys: Vec<(String, &str)> = INPUT
        .lines()
        .map(|line| {
            assert_clean(line);
            let mut parts = line.split(" | ");
            let row = parts.next().unwrap_or_default().to_owned();
            let oracle = parts.next().unwrap_or_default();
            let known = ["fg-down", "bg-up", "injected"]
                .into_iter()
                .find(|known| *known == oracle)
                .unwrap_or("?");
            (row, known)
        })
        .collect();
    assert_eq!(keys, expected_input_keys(), "every row, in table order");
    let mut order = Vec::new();
    for line in REENTRY.lines() {
        assert_clean(line);
        let name = line.split(' ').next().unwrap_or_default();
        assert!(
            REENTRY_SCENARIOS.iter().any(|(known, _)| *known == name),
            "unknown scenario: {line}"
        );
        if order.last() != Some(&name) {
            assert!(!order.contains(&name), "{name} is not one block");
            order.push(name);
        }
    }
    let table: Vec<&str> = REENTRY_SCENARIOS.iter().map(|(name, _)| *name).collect();
    assert_eq!(order, table, "every scenario, in table order");
}

// ----- source checks S1–S3 (plan §4.4; A-20: each asserts it found its targets) ------------

const APPROVAL_SOURCE: &str = include_str!("app_approval.rs");
const STRAY_SOURCE: &str = include_str!("ui/approval_input.rs");
const PANEL_SOURCE: &str = include_str!("../../yw-engine/src/explain/panel.rs");
const INTERACTION_SOURCE: &str = include_str!("../../yw-engine/src/approval/interaction.rs");

/// `app_approval.rs` without its `cfg(test)` child modules and test hooks (they follow the
/// smoke module's declaration at the end of the file) and without comment lines.
fn approval_production() -> String {
    let end = APPROVAL_SOURCE
        .find("#[cfg(test)]\n#[path = \"app_approval_smoke.rs\"]")
        .expect("the smoke module declaration");
    code_only(APPROVAL_SOURCE.get(..end).unwrap_or_default())
}

/// `source` without comment lines (`//`, `///`, `//!`).
fn code_only(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The text of the one item that starts with `head` (asserted to occur exactly once) up to its
/// closing brace at `indent` spaces.
fn item<'a>(source: &'a str, head: &str, indent: usize) -> &'a str {
    assert_eq!(source.matches(head).count(), 1, "exactly one {head:?}");
    let start = source.find(head).unwrap_or_default();
    let rest = source.get(start..).unwrap_or_default();
    let close = format!("\n{}}}\n", " ".repeat(indent));
    let end = rest
        .find(&close)
        .expect("the item's closing brace")
        .saturating_add(close.len());
    rest.get(..end).unwrap_or_default()
}

/// Whitespace runs folded to one space.
fn folded(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Asserts that `parts` occur in `text` in this order.
fn in_order(text: &str, parts: &[&str]) {
    let mut from = 0;
    for part in parts {
        let at = text.get(from..).and_then(|rest| rest.find(part));
        assert!(at.is_some(), "{part:?} after byte {from} in:\n{text}");
        from += at.unwrap_or_default() + part.len();
    }
}

/// S1 (spec/04 §3.6, AGENTS.md §6 window flags): A01 is opened `WS_EX_TOPMOST`, and its
/// activating click (A01 not the foreground window, raw read) is a press while not armed and is
/// eaten with `MA_ACTIVATEANDEAT` (2); the panel and the AI body have no activation arm of their
/// own (the click activates A01 through the parent). The behaviour is pinned by the
/// `a01.mouse-activate` rows of `input.txt`. 2026-11-19 (S4 B2, plan §4.4): re-pointed to the
/// input map — the `MouseActivate` row of `ui::approval_input::map_msg`, its raw foreground read
/// on arrival (`TrustedSignals::sample_on_arrival`, taken before the map) and the shell that
/// samples before it maps; before, the arm of `on_approval_msg` in `app_approval.rs`.
/// 2026-11-19 (S4 B5): A01 is made by the `Effect::Approval(Open)` executor arm
/// `open_approval_window` (was `open_approval`, which now makes the flow and emits the effect);
/// `open_approval` names no window spec.
#[test]
fn approval_window_is_topmost_and_eats_activating_clicks() {
    /// `ui/approval_input.rs` without comment lines and before its test module.
    fn map_code() -> String {
        let end = STRAY_SOURCE
            .find("#[cfg(test)]\n#[path = \"approval_input_tests.rs\"]")
            .expect("the table test module declaration");
        code_only(STRAY_SOURCE.get(..end).unwrap_or_default())
    }
    let code = approval_production();
    let open = folded(item(&code, "    fn open_approval_window(", 4));
    in_order(
        &open,
        &[
            "WindowSpec::new(APPROVAL_CLASS, WindowKind::Floating)",
            ".topmost(true)",
            "create_window(&spec, handler)",
        ],
    );
    assert_eq!(open.matches(".topmost(").count(), 1, "{open}");
    assert_eq!(
        code.matches(".topmost(").count(),
        1,
        "A01 is made in one place"
    );
    assert!(!item(&code, "    fn open_approval(", 4).contains("WindowSpec"));
    for moved in ["MA_ACTIVATEANDEAT", "MouseActivate"] {
        assert!(
            !code.contains(moved),
            "{moved} in app_approval.rs: the map's"
        );
    }
    let surface = folded(item(&code, "    fn on_surface_msg(", 4));
    in_order(
        &surface,
        &[
            "TrustedSignals::sample_on_arrival(surface, msg, window);",
            "map_msg(surface, msg, facts, signals);",
            "self.run_steps(surface, Some(window), &steps)",
            ".unwrap_or(reply)",
        ],
    );
    let map = map_code();
    assert!(map.contains("pub const MA_ACTIVATEANDEAT: isize = 2;"));
    assert_eq!(
        map.matches("MA_ACTIVATEANDEAT").count(),
        2,
        "definition and the map's row"
    );
    let arrival = folded(item(&map, "    pub fn sample_on_arrival(", 4));
    in_order(
        &arrival,
        &[
            "if surface == Surface::Approval && matches!(msg, Msg::MouseActivate) {",
            "foreground_raw: Self::sample_raw_foreground(window, \"mouse_activate\"),",
            "} else { Self::NONE }",
        ],
    );
    let a01 = item(&map, "fn map_approval(", 0);
    let activate = a01
        .find("Msg::MouseActivate => {")
        .and_then(|start| {
            let arm = a01.get(start..)?;
            arm.find("Msg::Timer(APPROVAL_TIMER_ID)")
                .and_then(|end| arm.get(..end))
        })
        .expect("the MouseActivate row");
    in_order(
        &folded(activate),
        &[
            "if signals.foreground_raw { mapped(Vec::new(), Reply::Default) } else {",
            "vec![Step::Event(InteractionEvent::OtherPress)],",
            "Reply::Handled(MA_ACTIVATEANDEAT),",
        ],
    );
    for head in ["fn map_panel(", "fn map_ai_body("] {
        assert!(!item(&map, head, 0).contains("MouseActivate"), "{head}");
    }
}

/// S2 (spec/04 §3.4, security review L5): Enter on `승인` approves only as `physical` = Enter
/// in the message's own key state **and** not injected, read while the message is handled, and
/// the trusted reads have one reader. 2026-11-19 (S4 B2, plan §4.4: the plan's
/// `trusted_signals_have_one_reader`, kept under this name because `frozen-helpers.txt` pins the
/// source checks by name): Enter on `승인` maps to the sampled `Trusted::ApproveEnter`, whose
/// event is built once (`Trusted::event`) from `enter_in_message && !injected`, the injection flag
/// read only for an Enter in the message; `is_foreground()`, `is_down(`, `is_down_in_message(`
/// and `injected()` occur in the approval shell only inside the `TrustedSignals::sample*` readers
/// of `ui/approval_input.rs` (none in `app_approval.rs`); the stray-press map names no approving
/// event. Before B2: the Enter arm of `on_approval_key` and the A3 wrappers in `app_approval.rs`.
/// 2026-11-19 (S4 B2 review): `Trusted::event` and `TrustedSignals::sample_for` are private and
/// called only by `Trusted::deliver` (sample, then build), the sample's fields are private, it
/// has no `Default`, and the shell reads the gate foreground through its getter.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one check per enforced part of the Enter rule and its readers"
)]
fn approve_enter_is_physical_and_not_injected() {
    /// `ui/approval_input.rs` without comment lines and before its test module.
    fn map_code() -> String {
        let end = STRAY_SOURCE
            .find("#[cfg(test)]\n#[path = \"approval_input_tests.rs\"]")
            .expect("the table test module declaration");
        code_only(STRAY_SOURCE.get(..end).unwrap_or_default())
    }
    const READS: [&str; 4] = [
        "is_foreground()",
        "is_down(",
        "is_down_in_message(",
        "injected()",
    ];
    let map = map_code();
    let key = folded(item(&map, "pub fn map_key(", 0));
    in_order(
        &key,
        &[
            "VK_RETURN | VK_SPACE => match focus {",
            "Focus::Approve if vk == VK_RETURN => Some(Step::Sampled(Trusted::ApproveEnter)),",
            "Focus::Reject if !repeat => Some(Step::Event(InteractionEvent::RejectActivated)),",
        ],
    );
    let event = folded(item(&map, "    const fn event(", 4));
    in_order(
        &event,
        &[
            "Self::ApproveEnter => InteractionEvent::ApproveActivated {",
            "physical: signals.enter_in_message && !signals.injected,",
        ],
    );
    assert_eq!(
        map.matches("InteractionEvent::ApproveActivated {").count(),
        1,
        "built only by Trusted::event"
    );
    let deliver = folded(item(&map, "    pub fn deliver(", 4));
    assert!(
        deliver.contains("self.event(TrustedSignals::sample_for(self, window))"),
        "{deliver}"
    );
    for private in [
        "pub const fn event(",
        "pub fn sample_for(",
        "impl Default for TrustedSignals",
    ] {
        assert!(!map.contains(private), "{private} in ui/approval_input.rs");
    }
    let head = "pub struct TrustedSignals {";
    let fields = item(&map, head, 0);
    assert_eq!(
        fields.matches("pub ").count(),
        1,
        "private fields:
{fields}"
    );
    let derive = map
        .get(..map.find(head).unwrap_or_default())
        .and_then(|before| before.rfind("#[derive(").and_then(|at| before.get(at..)))
        .expect("the derive of TrustedSignals");
    assert!(!derive.contains("Default"), "{derive}");
    assert_eq!(map.matches("self.event(").count(), 1, "only deliver builds");
    assert_eq!(
        map.matches("sample_for(").count(),
        2,
        "defined, called by deliver"
    );
    let sample = folded(item(&map, "    fn sample_for(", 4));
    in_order(
        &sample,
        &[
            "Trusted::ApproveEnter => {",
            "let enter_in_message = Self::sample_enter_in_message();",
            "injected: enter_in_message && Self::sample_injection(),",
        ],
    );
    let readers = [
        ("    fn sample_gate_foreground(", "window.is_foreground()"),
        ("    fn sample_raw_foreground(", "window.is_foreground()"),
        ("    fn sample_key(", "yw_win::input::is_down(vk)"),
        (
            "    fn sample_enter_in_message(",
            "yw_win::input::is_down_in_message(VK_RETURN)",
        ),
        ("    fn sample_injection(", "yw_win::input::injected()"),
    ];
    let signals = item(&map, "impl TrustedSignals {", 0);
    let mut rest = map.clone();
    for (head, read) in readers {
        let body = item(&map, head, 4);
        assert!(body.contains(read), "{head} reads {read}");
        assert!(signals.contains(body), "{head} is a TrustedSignals reader");
        rest = rest.replace(body, "");
    }
    for read in READS {
        assert!(
            !rest.contains(read),
            "{read} outside its TrustedSignals reader"
        );
    }
    let code = approval_production();
    assert!(
        !code.contains("yw_win::input"),
        "app_approval.rs reads no input"
    );
    for read in READS {
        assert!(!code.contains(read), "{read} in app_approval.rs");
    }
    assert!(code.contains("TrustedSignals::sample_foreground(&win.window).foreground()"));
    let stray = item(&map, "pub const fn stray_press(", 0);
    assert!(stray.contains("Some(InteractionEvent::OtherPress)"));
    for approving in ["ApproveActivated", "PointerPressed", "SpacePressed"] {
        assert!(!stray.contains(approving), "{approving} in stray_press");
    }
}

/// S8 (S4 B2, plan critique A-6, spec/04 §3.4): only the input map says "approve". In yw-app
/// production code (test files and inline `#[cfg(test)]` modules skipped, comment lines too),
/// `ApproveActivated`, `PointerPressed`, `PointerReleased`, `SpacePressed`, `SpaceReleased` and an
/// `ApprovalInput {` literal occur only in `ui/approval_input.rs`, where `Trusted::event` builds
/// the events from a sample (each as a whole identifier: yw-core's `HcApprovalInput` is another
/// type). Asserts that it scanned the crate (> 50 files) and found the map.
///
/// 2026-11-19 (S4 B2 review): the names above alone did not stop a forged approval: production
/// code could build `Trusted::ApproveEnter.event(TrustedSignals { enter_in_message: true, .. })`
/// without naming any of them (a review probe in `run_step` passed every check). Since then the
/// sample's fields and `Trusted::event` are private (S2 asserts it), so only `Trusted::deliver`
/// leaves the module with an event, and this check also pins where the way in is named: outside
/// `ui/approval_input.rs`, `Trusted::` and a `TrustedSignals {` literal occur nowhere, and
/// `Sampled(`, `.deliver(` and `.event(` once each, in `app_approval.rs`: the one
/// `Step::Sampled` arm of `run_step`, which delivers, and the session call of `interaction()`.
/// 2026-11-19 (S4 B4a): the session call moved with the gate into `ApprovalFlow::on_event`
/// (`approval_flow.rs`), which `interaction()` calls with the event it was handed: `.event(` is
/// now counted once in `approval_flow.rs` and none in `app_approval.rs`.
/// 2026-11-19 (S4 B6, critique A-6, A-12): the window's input is one `ApprovalInput`, built only
/// by `ui::approval_input::window_input` (the one `ApprovalInput {` literal) and sent as
/// `Cmd::Approval` only by the two senders of `app_approval.rs`: `window_event` (an interaction
/// event or the close box, with the foreground sample of the window the input belongs to, never
/// of the window shown now) and `window_signal` (no sample, `false`); `run_step` takes the id from
/// the window that got the message (`Received`, captured by `Forward` when the window was made);
/// `on_approval_input` drops an input of another window before anything else, and the flow half
/// of the former `interaction()` is `approval_event`.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the crate scan, then the names and the way to a sampled event"
)]
fn approving_input_is_built_only_by_the_mapper() {
    fn sources(root: &std::path::Path, dir: &std::path::Path, found: &mut Vec<(String, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if path.is_dir() {
                if name != "tests" {
                    sources(root, &path, found);
                }
            } else if std::path::Path::new(&name)
                .extension()
                .is_some_and(|extension| extension == "rs")
                && name != "tests.rs"
                && !name.ends_with("_tests.rs")
                && !relative.starts_with("ui/tour")
                && !matches!(
                    relative.as_str(),
                    "app_approval_flow_support.rs" | "app_approval_smoke.rs" | "app/secret_seam.rs"
                )
            {
                found.push((relative, std::fs::read_to_string(&path).unwrap()));
            }
        }
    }
    /// The text without its comment lines and its `#[cfg(test)]` `mod … {` blocks and
    /// `#[cfg(test)] #[path] mod …;` declarations (a top-level block ends at the first `}` line).
    fn production(text: &str) -> String {
        let mut kept = String::new();
        let mut lines = text.lines().peekable();
        while let Some(line) = lines.next() {
            if line == "#[cfg(test)]"
                && lines
                    .peek()
                    .is_some_and(|next| next.starts_with("mod ") && next.ends_with('{'))
            {
                for skipped in lines.by_ref() {
                    if skipped == "}" {
                        break;
                    }
                }
                continue;
            }
            if line.trim_start().starts_with("//") {
                continue;
            }
            kept.push_str(line);
            kept.push('\n');
        }
        kept
    }
    /// `name` occurs as a whole identifier (no identifier character right before it).
    fn names(code: &str, name: &str) -> bool {
        code.match_indices(name).any(|(at, _)| {
            !code[..at]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
    }
    const APPROVING: [&str; 6] = [
        "ApproveActivated",
        "PointerPressed",
        "PointerReleased",
        "SpacePressed",
        "SpaceReleased",
        "ApprovalInput {",
    ];
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found = Vec::new();
    sources(&root, &root, &mut found);
    assert!(found.len() > 50, "{}", found.len());
    let mut builders: Vec<(&str, &str)> = Vec::new();
    for (path, text) in &found {
        let code = production(text);
        for name in APPROVING {
            if names(&code, name) {
                builders.push((path.as_str(), name));
            }
        }
    }
    builders.sort_unstable();
    assert_eq!(
        builders,
        [
            ("ui/approval_input.rs", "ApprovalInput {"),
            ("ui/approval_input.rs", "ApproveActivated"),
            ("ui/approval_input.rs", "PointerPressed"),
            ("ui/approval_input.rs", "PointerReleased"),
            ("ui/approval_input.rs", "SpacePressed"),
            ("ui/approval_input.rs", "SpaceReleased"),
        ]
    );
    // The way to a sampled event (2026-11-19, S4 B2 review).
    let mut ways: Vec<(&str, &str, usize)> = Vec::new();
    for (path, text) in &found {
        let code = production(text);
        if path == "ui/approval_input.rs" {
            assert_eq!(
                code.matches(".deliver(").count(),
                0,
                "the map never delivers"
            );
            assert!(
                names(&code, "Trusted::"),
                "the map names its sampled events"
            );
            continue;
        }
        for name in ["Trusted::", "TrustedSignals {", "Sampled("] {
            let count = code
                .match_indices(name)
                .filter(|(at, _)| {
                    !code[..*at]
                        .chars()
                        .next_back()
                        .is_some_and(|c| c.is_alphanumeric() || c == '_')
                })
                .count();
            if count > 0 {
                ways.push((path.as_str(), name, count));
            }
        }
        for call in [".deliver(", ".event(", "window_input(", "Cmd::Approval("] {
            let count = code.matches(call).count();
            if count > 0 {
                ways.push((path.as_str(), call, count));
            }
        }
    }
    ways.sort_unstable();
    assert_eq!(
        ways,
        [
            ("app.rs", "Cmd::Approval(", 1),
            ("app_approval.rs", ".deliver(", 1),
            ("app_approval.rs", "Cmd::Approval(", 2),
            ("app_approval.rs", "Sampled(", 1),
            ("app_approval.rs", "window_input(", 2),
            ("approval_flow.rs", ".event(", 1),
        ]
    );
    let code = approval_production();
    let run_step = folded(item(&code, "    fn run_step(", 4));
    in_order(
        &run_step,
        &[
            "let shown = window.map(|received| received.shown);",
            "Step::Sampled(trusted) => { let event = trusted.deliver(window.map(|received| received.window)); self.window_event(shown, ApprovalSignal::Event(event)); }",
        ],
    );
    // The id is the window's that got the message (A-12): `run_step` and the two senders never
    // read the window shown now for it.
    let event = folded(item(&code, "    fn window_event(", 4));
    in_order(
        &event,
        &[
            ".filter(|win| Some(win.shown) == shown)",
            "TrustedSignals::sample_foreground(&win.window).foreground(),",
            "self.on_cmd(Cmd::Approval(window_input(shown, foreground, signal)));",
        ],
    );
    let signal = folded(item(&code, "    fn window_signal(", 4));
    assert!(
        signal.contains("self.on_cmd(Cmd::Approval(window_input(shown, false, signal)));"),
        "{signal}"
    );
    assert_eq!(
        run_step.matches("let shown =").count(),
        1,
        "one id per message"
    );
    assert!(!run_step.contains("last_opened"), "{run_step}");
    for body in [&event, &signal] {
        for banned in [
            "last_opened",
            "evm.approval",
            "ApprovalFlow::shown",
            "shown_now",
        ] {
            assert!(!body.contains(banned), "{banned} in {body}");
        }
    }
    in_order(
        &folded(item(&code, "impl Handler for Forward {", 0)),
        &[
            "shown: self.target.shown(),",
            "app.on_surface_msg(self.target.surface(), &received, msg)",
        ],
    );
    let opens = folded(item(&code, "    fn open_approval_window(", 4));
    in_order(
        &opens,
        &[
            "target: Target::Approval(shown),",
            "target: Target::Panel(shown),",
            "target: Target::AiBody(shown),",
        ],
    );
    in_order(
        &folded(item(&code, "    pub(crate) fn on_approval_input(", 4)),
        &[
            "let shown = input.shown;",
            "if self.shown_now() != Some(shown) { return; }",
            "match input.signal {",
        ],
    );
    assert!(
        item(&code, "    fn approval_event(", 4).contains("flow.on_event(now, foreground, event)"),
        "approval_event hands the event to the flow"
    );
    let flow = found
        .iter()
        .find(|(path, _)| path == "approval_flow.rs")
        .map(|(_, text)| code_only(text))
        .expect("approval_flow.rs");
    let on_event = item(&flow, "    pub(crate) fn on_event(", 4);
    assert!(
        on_event.contains("self.session.event(now, event)"),
        "the flow hands the event to the session"
    );
    // 2026-11-19 (S4 B4 review): the gate's foreground sample comes before the event, once (a
    // mutation that moved it after the event passed every golden; the behaviour is pinned by
    // `approval_flow::tests::the_foreground_sample_comes_before_the_event`).
    assert_eq!(on_event.matches("set_foreground(").count(), 1, "one sample");
    in_order(
        on_event,
        &[
            "self.session.set_foreground(now, foreground);",
            "self.session.event(now, event);",
        ],
    );
}

/// S3 (spec/04 §3.8, spec/06 D21, AP-5): the AI explanation never touches the gate: no `ai_*`
/// function of the window, `on_llm_done` or `llm_busy` names the session, the gate or the
/// interaction, `AiUi` holds none of them, the engine's AI panel names no gate type, and
/// `can_approve` takes the gate and the time only. 2026-11-19 (S4 B4a, plan §4.4 S3): extended to
/// the flow module `approval_flow.rs`, which holds the gate: it names no window (`yw_win`,
/// `Window`, `invalidate`, `create_window`, the timer, the Win32 foreground and flash calls), and
/// its only `set_foreground(` is the gate's own (`self.session.set_foreground(`). 2026-11-19 (S4
/// B4b): `AiUi` split into the flow's `AiFlow` (panel state, serial, host, model, kind) and the
/// shell's `AiBody` (body child, scroll): neither holds a gate type, `AiFlow` has no methods of its
/// own, and the flow's AI accessors (`ai`, `ai_mut`, `take_ai`) name no session or gate; the
/// shell state `ApprovalWin` holds no session, gate, flow or request. 2026-11-19 (S4 B4 review):
/// "no methods" is checked over every `impl` header of the crate that names `AiFlow` (only its
/// `Debug`, whose body names no gate either), not by the one spelling `impl AiFlow`.
/// 2026-11-19 (S4 B5): the flow's new AI accessor `attach_ai` names no session or gate either.
/// (2026-11-19, S4 B5 review: this said the AI explanation joins the flow "when the open's answer
/// says its body was made"; no answer says so. It is reserved once when the flow opens, the open
/// asks for the AI body iff one is reserved, and a made window's answer attaches the reservation.)
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the window's AI functions, then the flow module and the shell state"
)]
fn ai_never_touches_the_gate() {
    let code = approval_production();
    // Every `fn ai_*` of any visibility (2026-11-18, A5 review: the scan matched private
    // `    fn ai_` only, so a `pub(crate) fn ai_*` was skipped).
    let mut found = Vec::new();
    for line in code.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = [
            "fn ai_",
            "pub fn ai_",
            "pub(crate) fn ai_",
            "pub(super) fn ai_",
        ]
        .into_iter()
        .find_map(|prefix| trimmed.strip_prefix(prefix)) else {
            continue;
        };
        let name = rest.split('(').next().unwrap_or_default();
        let indent = line.len() - trimmed.len();
        let head_len = line.find('(').map_or(line.len(), |at| at + 1);
        let head = line.get(..head_len).unwrap_or_default();
        let body = item(&code, head, indent);
        for banned in ["session", "gate", "interaction(", "can_approve"] {
            assert!(!body.contains(banned), "{banned} in {head}");
        }
        found.push(format!("ai_{name}"));
    }
    assert_eq!(
        found,
        [
            "ai_scroll_by",
            "ai_after",
            "ai_ready",
            "ai_ready_tx",
            "ai_ready_message",
            "ai_ready_typed",
            "ai_tick",
            "ai_retry",
        ],
        "every ai_ function of the window (a new one is added here once checked)"
    );
    for head in [
        "    pub(crate) fn on_llm_done(",
        "    fn llm_busy(",
        "struct AiBody {",
    ] {
        let indent = if head.starts_with("struct") { 0 } else { 4 };
        let body = item(&code, head, indent);
        for banned in ["session", "gate", "interaction(", "can_approve"] {
            assert!(!body.contains(banned), "{banned} in {head}");
        }
    }
    let shell = item(&code, "pub struct ApprovalWin {", 0);
    for banned in ["Session", "Gate", "Flow", "ApprovalRequest", "Approved"] {
        assert!(!shell.contains(banned), "{banned} in ApprovalWin");
    }
    let panel = code_only(PANEL_SOURCE);
    assert!(panel.contains("pub struct AiPanel"), "the engine AI panel");
    for banned in [
        "ApprovalSession",
        "ApprovalGate",
        "InteractionEvent",
        "can_approve",
    ] {
        assert!(!panel.contains(banned), "{banned} in explain/panel.rs");
    }
    assert_eq!(
        INTERACTION_SOURCE
            .matches("pub fn can_approve(gate: &ApprovalGate, now_ms: u64) -> bool {")
            .count(),
        1
    );
    let flow = code_only(include_str!("approval_flow.rs"));
    assert!(
        flow.contains("pub struct ApprovalFlow {"),
        "the flow module"
    );
    for banned in [
        "yw_win",
        "Window",
        "invalidate",
        "create_window",
        "set_timer",
        "kill_timer",
        "request_foreground",
        "flash",
    ] {
        assert!(!flow.contains(banned), "{banned} in approval_flow.rs");
    }
    assert_eq!(
        flow.matches("set_foreground(").count(),
        flow.matches("self.session.set_foreground(").count(),
        "only the gate's foreground flag"
    );
    // `AiFlow` has no methods: the only `impl` naming it, in any yw-app source file, under any
    // path and for any trait, is its `Debug` (2026-11-19, S4 B4 review: the check was
    // `!contains("impl AiFlow")`, which missed `impl Trait for AiFlow` and
    // `impl crate::approval_flow::AiFlow`). An item header starts a line with `impl` and ends at
    // its first `{` or `;`.
    let ident = |c: char| c.is_alphanumeric() || c == '_';
    let mut files = Vec::new();
    let mut dirs = vec![std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    assert!(files.len() > 50, "{}", files.len());
    let mut ai_impls = Vec::new();
    for path in &files {
        let code = code_only(&std::fs::read_to_string(path).unwrap());
        let mut at = 0;
        for line in code.split_inclusive('\n') {
            let start = at;
            at += line.len();
            let trimmed = line.trim_start();
            if !(trimmed.starts_with("impl ") || trimmed.starts_with("impl<")) {
                continue;
            }
            let rest = code.get(start..).unwrap_or_default();
            let header = folded(
                rest.get(..rest.find(['{', ';']).unwrap_or(rest.len()))
                    .unwrap_or_default(),
            );
            let names_ai_flow = header.match_indices("AiFlow").any(|(i, _)| {
                !header
                    .get(..i)
                    .unwrap_or_default()
                    .chars()
                    .next_back()
                    .is_some_and(ident)
                    && !header
                        .get(i + 6..)
                        .unwrap_or_default()
                        .chars()
                        .next()
                        .is_some_and(ident)
            });
            if names_ai_flow {
                ai_impls.push(header);
            }
        }
    }
    assert_eq!(
        ai_impls,
        ["impl core::fmt::Debug for AiFlow"],
        "AiFlow has no methods"
    );
    for (head, indent) in [
        ("pub struct AiFlow {", 0),
        ("impl core::fmt::Debug for AiFlow {", 0),
        ("    pub(crate) const fn ai(", 4),
        ("    pub(crate) fn ai_mut(", 4),
        ("    pub(crate) fn take_ai(", 4),
        ("    pub(crate) fn attach_ai(", 4),
    ] {
        let body = item(&flow, head, indent);
        for banned in [
            "session",
            "gate",
            "Session",
            "Gate",
            "interaction",
            "can_approve",
        ] {
            assert!(!body.contains(banned), "{banned} in {head}");
        }
    }
    assert!(flow.contains("self.session.set_foreground("));
}

/// S6 (S4 B5, plan §4.4; spec/15 §11.4 S4): the approval flow names no window. The functions of
/// `app_approval.rs` from `show_next_approval` up to `interaction()` (queue, open, prepare,
/// results, close, finish, approve, re-simulation, consume, tick) and the view rebuild name no
/// window type, window field or Win32 window call as a whole identifier: the window is made,
/// closed, invalidated and repainted only through `Effect::Approval` (`apply_approval_effect`),
/// and the width class comes from the flow (`wide`). The open asks for the window after it made
/// the flow, the close emits `Close` after it ended the flow, and the executor feeds the open's
/// answer back at once. Asserts the functions it scanned (the plan's list must be among them).
/// 2026-11-19 (S4 B5 review, critique A-3): also that the shell's open makes nothing for a `shown`
/// that is not the current flow's, that an answer for such a `shown` closes the window it made,
/// and that the AI explanation is reserved once at the open (the answer attaches the reservation
/// and names neither `explain_kind` nor the endpoint). 2026-11-19 (S4 B6): the scanned range ends
/// at `rebuild_view` (was the event entry `interaction()`, whose flow half is now
/// `approval_event` and whose window half is `window_event`) and holds the input handler
/// `on_approval_input` and `approval_event`.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the scanned functions, the banned names, then the open and close order"
)]
fn the_approval_flow_names_no_window() {
    /// `name` occurs as a whole identifier (no identifier character on either side).
    fn ident(code: &str, name: &str) -> bool {
        let is_ident = |c: char| c.is_alphanumeric() || c == '_';
        code.match_indices(name).any(|(at, _)| {
            !code[..at].chars().next_back().is_some_and(is_ident)
                && !code[at + name.len()..].chars().next().is_some_and(is_ident)
        })
    }
    const BANNED: [&str; 19] = [
        "window",
        "win",
        "Window",
        "ApprovalWin",
        "approval_win",
        "panel_spec",
        "client_rect",
        "px",
        "invalidate",
        "invalidate_rect",
        "set_rect",
        "set_foreground",
        "request_foreground",
        "create_window",
        "center_window",
        "show_window",
        "flash_window",
        "focus_window",
        "kill_timer",
    ];
    let code = approval_production();
    let start = code
        .find("    pub fn show_next_approval(")
        .expect("show_next_approval");
    let end = code.find("    fn rebuild_view(").expect("rebuild_view");
    assert!(start < end);
    let range = code.get(start..end).unwrap_or_default();
    let mut heads: Vec<String> = Vec::new();
    for line in range.lines() {
        let trimmed = line.trim_start();
        if line.len() - trimmed.len() != 4 {
            continue;
        }
        if ["fn ", "pub fn ", "pub(crate) fn "]
            .iter()
            .any(|prefix| trimmed.starts_with(prefix))
        {
            let name_at = line.find("fn ").unwrap_or_default();
            let head_len = line
                .get(name_at..)
                .and_then(|rest| rest.find('('))
                .map_or(line.len(), |at| name_at + at + 1);
            heads.push(line.get(..head_len).unwrap_or_default().to_owned());
        }
    }
    heads.push("    fn rebuild_view(".to_owned());
    heads.push("    fn rebuild_view_with(".to_owned());
    let names: Vec<&str> = heads
        .iter()
        .map(|head| {
            head.trim_start()
                .trim_start_matches("pub(crate) ")
                .trim_start_matches("pub ")
                .trim_start_matches("fn ")
                .trim_end_matches('(')
        })
        .collect();
    for planned in [
        "show_next_approval",
        "open_approval",
        "on_approval_opened",
        "start_prepare",
        "show_failure",
        "close_approval_window",
        "finish_approval",
        "on_prepared",
        "on_resimulated",
        "approved",
        "start_resimulation",
        "consume_and_sign",
        "tick_approval",
        "on_approval_input",
        "approval_event",
        "rebuild_view_with",
    ] {
        assert!(names.contains(&planned), "{planned} not scanned: {names:?}");
    }
    assert!(names.len() > 20, "{names:?}");
    for head in &heads {
        let body = item(&code, head, 4);
        for banned in BANNED {
            assert!(!ident(body, banned), "{banned} in {head}");
        }
    }
    // The open makes the flow, then asks for the window; the answer ends a refused open.
    let open = folded(item(&code, "    fn open_approval(", 4));
    in_order(
        &open,
        &[
            "explain_kind(&item)",
            "ApprovalFlow::open(shown, lang, item, connect, ai_reserved, now)",
            "self.evm.approval = Some(flow);",
            "self.emit(Effect::Approval(ApprovalEffect::Open {",
            "ai_reserved: reserve_ai,",
        ],
    );
    let answer = folded(item(&code, "    pub(crate) fn on_approval_opened(", 4));
    // 2026-11-19 (S4 B5 review, critique A-3): a stale answer closes the window it made; the AI
    // explanation is the one reserved at the open, never worked out again from the endpoint.
    in_order(
        &answer,
        &[
            "!= Some(shown) { if matches!(outcome, OpenOutcome::Shown { .. }) { \
             self.emit(Effect::Approval(ApprovalEffect::Close { shown })); } return; }",
            "OpenOutcome::Shown { .. } => {",
            "if let Some(reserved) = flow.take_ai_reserved() {",
            "flow.attach_ai(AiFlow {",
            "self.rebuild_view();",
            "self.start_prepare();",
            "OpenOutcome::Refused(_) | OpenOutcome::Failed(_) => {",
            "self.evm.approval.take()",
            "ApprovalEffect::Close {",
            "self.approval_open_failed();",
        ],
    );
    for banned in ["explain_kind", "self.llm.", "service"] {
        assert!(!answer.contains(banned), "{banned} in on_approval_opened");
    }
    // The shell's open makes nothing for a `shown` that is not the current flow's (A-3).
    let shell_open = folded(item(&code, "    fn open_approval_window(", 4));
    in_order(
        &shell_open,
        &[
            "if self.evm.approval.as_ref().map(ApprovalFlow::shown) != Some(shown) { return FAILED; }",
            "create_window(&spec, handler)",
        ],
    );
    // The close ends the flow (reject, AI close), then the window goes.
    let close = folded(item(&code, "    pub fn close_approval_window(", 4));
    in_order(
        &close,
        &[
            "self.evm.approval.take()",
            "self.evm.store.reject(request.id);",
            "flow.take_ai()",
            "self.emit(Effect::Approval(ApprovalEffect::Close {",
        ],
    );
    // A `Close` for a window that is not open under its id does nothing (critique A-3).
    let shell = folded(item(&code, "    fn close_approval_shell(", 4));
    in_order(
        &shell,
        &[
            "self.approval_win.take_if(|win| win.shown == shown) else { return; };",
            "drop(win.ai.take());",
            "win.window.kill_timer(APPROVAL_TIMER_ID);",
            "drop(win.panel);",
            "drop(win.window);",
            "request_foreground(main, \"main\")",
        ],
    );
    // The executor applies an approval effect at once and feeds the open's answer back.
    let effects = code_only(include_str!("app_effects.rs"));
    assert!(
        folded(&effects).contains(
            "Effect::Approval(effect) => { if let Some(answer) = self.apply_approval_effect(effect) { self.on_cmd(answer); } }"
        ),
        "the executor arm"
    );
}
