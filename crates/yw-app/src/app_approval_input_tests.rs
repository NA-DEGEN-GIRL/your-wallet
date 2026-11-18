//! Approval window input mapping, re-entrancy and structure checks (2026-11-18, S4 A5;
//! spec/15 §11.4 S4, spec/04 §3.4, spec/01 §7.7, spec/09 §2.2): the goldens
//! `app/tests/s4_flow/input.txt` and `app/tests/s4_flow/reentry.txt`, recorded from today's code
//! before S4 moves a line of the approval window (owner decision O-2; reviewed at the F-A
//! checkpoint), and the source checks S1–S3 of the S4 plan.
//!
//! **`input.txt`** (critique A-7): every arm of `on_approval_msg`, `on_approval_key` (through
//! `Msg::KeyDown`), `on_panel_msg` and `on_ai_body_msg`, delivered to a fresh window per row on
//! the A3 fixture (hidden windows, test clock, captured RPC channel and key queue), under the two
//! scripted trusted-signal oracles `fg-down` (A01 is the foreground window, raw and seamed; the
//! left button, Space and Shift are down; Enter is in the message's key state, not injected) and
//! `bg-up` (all of it false), plus an `injected` oracle for Enter and Space on `승인`. The window
//! got a `Tick` at +0 and the message comes at +1 500 (armed under `fg-down`). Button and panel
//! rectangles are fixed values (`BOTTOM`, `layout()`), not painted ones, so no line depends on
//! the screen's DPI. A line:
//! `<row> | <oracle> | reply <Reply of each message> | trace <the ordered input log of the
//! delivery: every oracle read with its program point and value, every A01 Win32 side effect
//! (`/skip` = the hidden host skipped it), every `interaction` event with its foreground sample
//! and focus, the `ActivateApp(true)` arm, every toggle/retry/scroll with the focus at the call
//! (scroll deltas as their sign, or `min`/`max`), every message the approval `Forward` dropped
//! because the App was borrowed> | after <the window afterwards: interaction status, gate
//! `ready` (relative to the clock origin) / foreground / checkbox, a hold in progress, the early
//! release mark, focus, pressed button, raw data open, connect selection, panel and AI body
//! scroll at zero or not (`-`: no AI body);
//! the store state of the issued request; the RPC and key jobs and dApp answers the delivery
//! caused>`.
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
//! (a paint is deferred) and changes nothing. Activation messages during a real (shown) open are
//! not produced here: the hidden host never shows, activates or focuses a window (A3); the
//! `while_borrowed` scenario pins the same drop for them. A line: `<scenario> <step> | reply
//! <..> | trace <..> | after <..>` (formats as above).
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
use super::{
    APPROVAL_TIMER_ID, Bottom, Focus, Forward, PanelLayout, Pressed, Target, VK_DOWN, VK_END,
    VK_ESCAPE, VK_HOME, VK_NEXT, VK_PRIOR, VK_RETURN, VK_SPACE, VK_TAB, VK_UP,
};
use crate::explain::config::{ModelName, parse_endpoint};
use crate::explain::request::{HttpResponse, LlmTransport, TransportError};
use crate::explain::{ExplainService, LlmConfig, ResponseFormatMode};
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

/// The panel layout of every row (panel content pixels): two account rows, the checkbox and the
/// raw-data switch.
fn layout() -> PanelLayout {
    PanelLayout {
        accounts: vec![
            (0, Rect::new(20, 100, 700, 30)),
            (1, Rect::new(20, 140, 700, 30)),
        ],
        ack: Some(Rect::new(20, 200, 700, 30)),
        raw: Some(Rect::new(20, 260, 700, 30)),
        height: 2_000,
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
}

/// One opened window and what the recorder needs of it.
struct Opened {
    fx: Fixture,
    outlet: Option<Outlet>,
    issued: Option<ApprovalId>,
}

/// Opens a fresh `kind` window on its own fixture, installs `oracle`, delivers the window's
/// `Tick` at +0 and moves the clock to +1 500; with `fixed`, the bottom bar and panel get the
/// fixed rectangles. Everything captured on the way (jobs, answers, log) is discarded.
fn open(kind: Kind, oracle: Signals, tag: &str, fixed: bool) -> Opened {
    let fx = Fixture::new(tag, HostMode::Hidden);
    let outlet = match kind {
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
        let ui = app.evm.window.as_mut().expect("the window is open");
        if fixed {
            ui.bottom = BOTTOM;
            ui.layout = Some(layout());
        }
        ui.request.as_ref().map(|request| request.id)
    };
    let _ = fx.rpc_jobs();
    let _ = fx.key_jobs();
    if let Some(outlet) = outlet.as_ref() {
        let _ = outlet.answers();
    }
    let _ = flow_support::take_log();
    Opened { fx, outlet, issued }
}

/// Delivers `msg` to `target`'s arm with the App borrowed by the test (as the window procedure
/// would after `Forward` borrowed it).
fn deliver(fx: &Fixture, target: Target, window: &Window, msg: &Msg) -> Reply {
    let mut app = fx.app();
    match target {
        Target::Approval => app.on_approval_msg(window, msg),
        Target::Panel => app.on_panel_msg(window, msg),
        Target::AiBody => app.on_ai_body_msg(window, msg),
    }
}

/// The real approval `Forward` of `target` on the fixture's App.
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
    if let Some(ui) = fx.app().evm.window.as_mut() {
        std::mem::swap(&mut ui.window, &mut held);
    }
    held
}

/// Puts A01 back while its window is still open (else dropping it destroys it).
fn put_back(fx: &Fixture, mut held: Window) {
    if let Some(ui) = fx.app().evm.window.as_mut() {
        std::mem::swap(&mut ui.window, &mut held);
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

/// The window and what the delivery caused (format in the module doc).
fn after(fx: &Fixture, issued: Option<ApprovalId>, outlet: Option<&Outlet>) -> String {
    let now = fx.clock.peek();
    let app = fx.app.borrow();
    let mut line = match app.evm.window.as_ref() {
        None => "win closed".to_owned(),
        Some(ui) => {
            let gate = &ui.session.gate;
            format!(
                "win open status={:?} ready={} fg={} ack={} hold={} early={} focus={:?} \
                 pressed={} raw={} sel={} scroll={} ai-scroll={}",
                ui.session.interaction().status(),
                rel(gate.ready_at_ms),
                bit(gate.is_foreground),
                bit(gate.ack_checked),
                bit(ui.session.interaction().hold_remaining_ms(now).is_some()),
                bit(ui.early_release),
                ui.focus,
                ui.pressed
                    .map_or_else(|| "-".to_owned(), |pressed| format!("{pressed:?}")),
                bit(ui.raw_open),
                ui.connect.as_ref().map_or_else(
                    || "-".to_owned(),
                    |connect| connect
                        .selected
                        .iter()
                        .map(|checked| if *checked { '1' } else { '0' })
                        .collect()
                ),
                if ui.scroll == 0 { "0" } else { "+" },
                ui.ai
                    .as_ref()
                    .map_or("-", |ai| if ai.scroll == 0 { "0" } else { "+" }),
            )
        }
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
    target: Target,
    focus: Focus,
    pressed: Option<Pressed>,
    msgs: Vec<Msg>,
    oracles: &'static [Oracle],
}

impl Row {
    fn new(name: &str, kind: Kind, target: Target, msgs: Vec<Msg>) -> Self {
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
    let row = |name: &str, msgs: Vec<Msg>| Row::new(name, Kind::Std, Target::Approval, msgs);
    vec![
        row("a01.stray.other-button", vec![Msg::OtherButtonDown]),
        row("a01.stray.non-client", vec![Msg::NonClientButtonDown]),
        row("a01.paint", vec![Msg::Paint]),
        row("a01.size", vec![Msg::Size { w: 800, h: 700 }]),
        row("a01.dpi-changed", vec![Msg::DpiChanged { dpi: 96 }]),
        row("a01.mouse-activate", vec![Msg::MouseActivate]),
        row("a01.timer.approval", vec![Msg::Timer(APPROVAL_TIMER_ID)]),
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
            Target::Approval,
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
    ]
}

/// The keyboard rows (`on_approval_key` through `Msg::KeyDown`): every key the arm names and one
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
                        Target::Approval,
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
                Target::Approval,
                vec![key_down(vk, false)],
            )
            .focus(Focus::Approve)
            .oracles(ONLY_INJECTED),
        );
    }
    rows
}

/// Every `WM_VSCROLL` code the arms name (`SB_LINEUP` 0 … `SB_BOTTOM` 7) and `SB_ENDSCROLL` 8.
fn vscroll_rows(prefix: &str, kind: Kind, target: Target) -> Vec<Row> {
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
    let row = |name: &str, kind: Kind, msgs: Vec<Msg>| Row::new(name, kind, Target::Panel, msgs);
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
    rows.extend(vscroll_rows("panel", Kind::Std, Target::Panel));
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
    let row = |name: &str, msgs: Vec<Msg>| Row::new(name, Kind::Ai, Target::AiBody, msgs);
    let mut rows = vec![
        row("ai.stray.other-button", vec![Msg::OtherButtonDown]),
        row("ai.stray.non-client", vec![Msg::NonClientButtonDown]),
        row("ai.paint", vec![Msg::Paint]),
        row("ai.down", vec![down(AT_NOTHING)]),
        row("ai.wheel.down", vec![Msg::Wheel(-120)]),
        row("ai.wheel.up", vec![Msg::Wheel(120)]),
    ];
    rows.extend(vscroll_rows("ai", Kind::Ai, Target::AiBody));
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
    if let Some(ui) = fx.app().evm.window.as_mut() {
        ui.focus = row.focus;
        ui.pressed = row.pressed;
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
        after(fx, opened.issued, opened.outlet.as_ref())
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
            .window
            .as_ref()
            .and_then(|ui| ui.request.as_ref().map(|request| request.id))
        {
            self.issued = Some(id);
        }
        let after = after(&self.opened.fx, self.issued, self.opened.outlet.as_ref());
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
    fx.app.borrow().evm.window.as_ref().map_or((0, 0), |ui| {
        let rect = ui.bottom.approve;
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
    let mut approval = forward(fx, Target::Approval);
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
    let mut approval = forward(fx, Target::Approval);
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
/// focus and window stay as they were.
fn reentry_while_borrowed() -> Vec<String> {
    let opened = open(Kind::Std, FG_DOWN, "reentry-borrowed", true);
    let mut rec = Rec::new("reentry_while_borrowed", &opened);
    let fx = &opened.fx;
    let a01 = take_a01(fx);
    let other = spare_window();
    rec.line("before", &[]);
    let messages = [
        (Target::Approval, Msg::ActivateApp(true)),
        (Target::Approval, Msg::ActivateApp(false)),
        (Target::Approval, Msg::MouseActivate),
        (Target::Approval, Msg::KillFocus { to_foreign: true }),
        (Target::Approval, down(AT_APPROVE)),
        (Target::Approval, up(AT_APPROVE)),
        (Target::Approval, key_down(VK_RETURN, false)),
        (Target::Approval, key_down(VK_ESCAPE, false)),
        (Target::Approval, Msg::Timer(APPROVAL_TIMER_ID)),
        (Target::Approval, Msg::CaptureChanged),
        (Target::Approval, Msg::Close),
        (Target::Panel, down(AT_ACK)),
        (Target::Panel, Msg::VScroll { code: 1 }),
        (Target::AiBody, down(AT_NOTHING)),
        (Target::AiBody, Msg::Wheel(120)),
        (Target::Panel, Msg::Paint),
        (Target::Approval, Msg::Paint),
    ];
    let mut seen = Vec::new();
    {
        let _borrowed = fx.app();
        for (target, msg) in &messages {
            let window = if *target == Target::Approval {
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
/// `a01.mouse-activate` rows of `input.txt`.
#[test]
fn approval_window_is_topmost_and_eats_activating_clicks() {
    let code = approval_production();
    assert!(code.contains("const MA_ACTIVATEANDEAT: isize = 2;"));
    let open = folded(item(&code, "    fn open_approval(", 4));
    in_order(
        &open,
        &[
            "WindowSpec::new(APPROVAL_CLASS, WindowKind::Floating)",
            ".topmost(true)",
            "create_window(&spec, handler)",
        ],
    );
    assert_eq!(open.matches(".topmost(").count(), 1, "{open}");
    let on_msg = item(&code, "    pub(crate) fn on_approval_msg(", 4);
    let activate = on_msg
        .find("Msg::MouseActivate => {")
        .and_then(|start| {
            let arm = on_msg.get(start..)?;
            arm.find("Msg::Timer(APPROVAL_TIMER_ID)")
                .and_then(|end| arm.get(..end))
        })
        .expect("the MouseActivate arm");
    in_order(
        &folded(activate),
        &[
            "if raw_foreground(window, \"mouse_activate\") { Reply::Default } else {",
            "self.interaction(InteractionEvent::OtherPress);",
            "Reply::Handled(MA_ACTIVATEANDEAT)",
        ],
    );
    assert_eq!(
        code.matches("MA_ACTIVATEANDEAT").count(),
        2,
        "definition and arm"
    );
    for head in [
        "    pub(crate) fn on_panel_msg(",
        "    pub(crate) fn on_ai_body_msg(",
    ] {
        assert!(!item(&code, head, 4).contains("MouseActivate"), "{head}");
    }
}

/// S2 (spec/04 §3.4, security review L5): Enter on `승인` approves only as `physical` = Enter
/// in the message's own key state **and** not injected, read while the message is handled; the
/// trusted reads (`is_foreground`, `is_down`, `is_down_in_message`, `injected`) occur in
/// `app_approval.rs` only inside their A3 wrappers, `ApproveActivated` is built in one place,
/// and the stray-press map names no approving event. (B2 rewrites this into
/// `trusted_signals_have_one_reader`.)
#[test]
fn approve_enter_is_physical_and_not_injected() {
    let code = approval_production();
    let key = folded(item(&code, "    fn on_approval_key(", 4));
    in_order(
        &key,
        &[
            "VK_RETURN => match focus {",
            "Focus::Approve => self.interaction(InteractionEvent::ApproveActivated { physical: \
             enter_in_message() && !injected_input(), }),",
            "Focus::Reject if !repeat => self.interaction(InteractionEvent::RejectActivated),",
        ],
    );
    assert_eq!(
        code.matches("InteractionEvent::ApproveActivated {").count(),
        1,
        "built only by the Enter arm"
    );
    let wrappers = [
        ("fn window_is_foreground(", "window.is_foreground()"),
        ("fn raw_foreground(", "window.is_foreground()"),
        ("fn key_down(", "is_down(vk)"),
        (
            "fn enter_in_message(",
            "yw_win::input::is_down_in_message(VK_RETURN)",
        ),
        ("fn injected_input(", "yw_win::input::injected()"),
    ];
    let mut rest = code.clone();
    for (head, read) in wrappers {
        let body = item(&code, head, 0);
        assert!(body.contains(read), "{head} reads {read}");
        rest = rest.replace(body, "");
    }
    rest = rest.replace("use yw_win::input::is_down;", "");
    for read in [
        "is_foreground()",
        "is_down(",
        "is_down_in_message(",
        "injected()",
    ] {
        assert!(!rest.contains(read), "{read} outside its wrapper");
    }
    let stray = code_only(STRAY_SOURCE);
    assert!(stray.contains("Some(InteractionEvent::OtherPress)"));
    for approving in ["ApproveActivated", "PointerPressed", "SpacePressed"] {
        assert!(!stray.contains(approving), "{approving} in stray_press");
    }
}

/// S3 (spec/04 §3.8, spec/06 D21, AP-5): the AI explanation never touches the gate: no `ai_*`
/// function of the window, `on_llm_done` or `llm_busy` names the session, the gate or the
/// interaction, `AiUi` holds none of them, the engine's AI panel names no gate type, and
/// `can_approve` takes the gate and the time only.
#[test]
fn ai_never_touches_the_gate() {
    let code = approval_production();
    let mut found = 0;
    for (at, _) in code.match_indices("    fn ai_") {
        let head_end = code
            .get(at..)
            .and_then(|rest| rest.find('('))
            .map_or(at, |end| at + end + 1);
        let head = code.get(at..head_end).unwrap_or_default();
        let body = item(&code, head, 4);
        for banned in ["session", "gate", "interaction(", "can_approve"] {
            assert!(!body.contains(banned), "{banned} in {head}");
        }
        found += 1;
    }
    assert!(found >= 8, "every ai_ function: {found}");
    for head in [
        "    pub(crate) fn on_llm_done(",
        "    fn llm_busy(",
        "struct AiUi {",
    ] {
        let indent = if head.starts_with("struct") { 0 } else { 4 };
        let body = item(&code, head, indent);
        for banned in ["session", "gate", "interaction(", "can_approve"] {
            assert!(!body.contains(banned), "{banned} in {head}");
        }
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
}
