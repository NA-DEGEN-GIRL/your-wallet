//! The approval flow and lifecycle scenarios with the shell half absent (2026-11-20, S4 B7 as
//! amended by the owner-delegated decision of 2026-11-20; spec/15 §11.4 S4, spec/09 §2.1): the
//! golden `app/tests/s4_flow/headless.txt`, in the gate's test step (no `#[ignore]`, no window).
//!
//! Each scenario here is the windowed scenario of the same name (`flow_tests`, `s4_flow/flow.txt`;
//! `flow_tests::lifecycle`, `s4_flow/lifecycle.txt`) step for step, on the same A3 fixture (the
//! shared test clock, the scripted trusted-signal oracle, the RPC channel and key queue captured
//! and never run, the recorded dApp outlet), but with the headless approval host installed
//! (`app_approval::headless_host`): `Effect::Approval` is recorded instead of applied, the open is
//! answered by the host, and no approval window, panel or AI body exists (`approval_win` stays
//! `None`, asserted at every line). The window's inputs go to the flow the way its steps send
//! them: one `Cmd::Approval` of the window opened last (`window_input`), an interaction event with
//! the oracle's foreground sample (`flow_support::scripted`, the read `TrustedSignals` makes), a
//! key mapped by the production `ui::approval_input::map_key` with the focus this module keeps
//! (A01's focus is shell state: reset to `거부` when a window opens, moved by `MoveFocus` and Tab
//! as `run_step` moves it), an approving event built by `Trusted::deliver` from the oracle. The
//! main window's entries go through `App::test_on_main_windowless` (the arms of `on_main` that read
//! no window). (2026-11-23, S4d F22; the Solana/Bitcoin one since the F22 review) Four
//! grant-write tests outside the golden (the lock's and the shutdown's flush) run the captured key
//! queue on a key worker of their own (`DiskWorker`, a vault below the fixture's temp folder), so
//! the meta save is written, not only queued. Nothing here makes a window, touches the network, a
//! card reader, a process, the clipboard or the registry; files are written only below the
//! fixtures' own temp folders (and by `print_headless`, into `YW_S4_FLOW_OUT` when it is set).
//!
//! A line is the windowed line without its shell column (`focus=`) plus the approval effects the
//! flow emitted since the last line (`effects`: `open#<id>` / `open-connect#<id>`, `close#<id>`,
//! `rebuilt#<id>`, `same#<id>` (a rebuild that changed nothing), `bar#<id>`, `redraw#<id>`, and
//! since S4 W14a (2026-11-22) `ai#<id>`/`ai-body#<id>`, which no scenario here emits (none has an
//! explanation worker); a run of one effect is `x<count>`; `ShownId` serials of the fixture's App). A fact line is the windowed
//! fact without its shell part: the `windows=` counts are not there, and the facts that are only
//! the shell's (the close box's reply, mouse replies, window counts and Win32 calls) are not
//! recorded. `win open` is the shown flow (with windows: the flow and its window together).
//!
//! Each test checks its scenario twice: its lines equal its lines of `headless.txt`, and (the
//! cross-check) its lines without the `effects` column equal the windowed golden lines of that
//! scenario with their shell columns removed, parsed from `flow.txt` / `lifecycle.txt` (never a
//! second copy). The windowed scenarios that need the shell's own trace are in [`LEFT_OUT`] with
//! the reason; [`every_windowed_scenario_runs_headless_or_is_left_out`] keeps the two tables
//! complete. Regenerate for review (PowerShell): `$env:YW_S4_FLOW_OUT='<folder>'; cargo test -p
//! yw-app --lib --locked --offline -- --ignored --exact
//! app_approval::flow_tests::lifecycle::headless::print_headless`.

use std::fmt::Write as _;
use std::sync::Arc;

use yw_core::approval::ApprovalId;
use yw_core::evm::amount::U256;
use yw_engine::approval::flow::{ApprovalEffect, ApprovalSignal, ShownId};
use yw_engine::cmd::Cmd;
use yw_win::ui::Msg;

use super::super::super::flow_support::{self, Fixture, HostMode, Outlet, Read, START_MS, Signals};
use super::super::super::headless_host::{self, OpenAnswer};
use super::super::{
    ACCOUNT_A, ACCOUNT_B, ETHER_MAIL_SEPOLIA, PRESS, RELEASE, SOL_KEY, VK_A, answer_resim,
    approval_lang, btc_item, dapp, dapp_answers, enqueue_app_item, hypercore_item, item_name,
    key_name, names, origin, personal_sign, prep_name, rel, request, shown_digest, shown_request,
    signals, status_key, wc_personal_sign, zec_item,
};
use super::{
    LockAck, OTHER, QN_TOKEN, RpcJsonSeam, broadcast, cancel_request, card_fact, card_wallet,
    devnet, grant, install_events, journal_with, personal_sign_frame_only, personal_sign_from,
    shown_id, signed_evm, sol_preview, sol_public, sol_record, sol_transfer, sol_tx, waiter_fact,
    waiters, wc_waiting,
};
use crate::app_evm::QueuedItem;
use crate::events::{
    ChainMessageSigned, ChainSignature, EvmSigned, KeyJob, KeyOutcome, KeyResult, MessageSigned,
    RpcEvent, SignFailure, SignTicket, UiEvent,
};
use crate::flow::evm::prepare::{PrepareFailure, PrepareJob, ResimJob, ResimKind, ResimResult};
use crate::lock::LockReason;
use crate::shell_msg::{WM_YW_EVENTS, WM_YW_LOCK_SHORTCUT};
use crate::ui::approval_input::{
    BarHits, Facts, Focus, Step, TrustedSignals, VK_ESCAPE, VK_RETURN, VK_TAB, map_key, tab_order,
    tab_target, window_input,
};
use crate::ui::approval_view::Block;
use crate::ui::interaction::InteractionEvent;
use crate::workers::rpc::RpcJob;

/// The committed headless golden.
const GOLDEN: &str = include_str!("app/tests/s4_flow/headless.txt");
/// The windowed goldens the cross-check reads.
const FLOW_GOLDEN: &str = include_str!("app/tests/s4_flow/flow.txt");
const LIFECYCLE_GOLDEN: &str = include_str!("app/tests/s4_flow/lifecycle.txt");

// ----- fixture, recorder and driver -----------------------------------------------------------

/// The A3 fixture with the headless approval host installed (removed when it drops, after the
/// shown approval, if any, was closed).
struct Headless(Fixture);

impl std::ops::Deref for Headless {
    type Target = Fixture;

    fn deref(&self) -> &Fixture {
        &self.0
    }
}

impl Drop for Headless {
    fn drop(&mut self) {
        if let Ok(mut app) = self.0.app.try_borrow_mut() {
            app.close_approval_window();
        }
        headless_host::remove();
    }
}

/// The windowed `fixture(tag)` without windows: the oracle says A01 is the foreground window
/// and an Enter is in the message's key state; opens are answered `Shown`.
fn fixture(tag: &str) -> Headless {
    fixture_with(tag, OpenAnswer::Shown)
}

fn fixture_with(tag: &str, answer: OpenAnswer) -> Headless {
    // The host mode is never read: the headless host answers every open first.
    let fixture = Fixture::new(tag, HostMode::Hidden);
    flow_support::set_signals(Some(signals(true)));
    headless_host::install(answer);
    Headless(fixture)
}

/// The lines of one scenario, what was captured on the way, and the test-held A01 focus.
struct Run<'a> {
    name: &'static str,
    fx: &'a Fixture,
    outlet: Option<&'a Outlet>,
    lines: Vec<String>,
    issued: Option<ApprovalId>,
    rpc: Vec<RpcJob>,
    keys: Vec<KeyJob>,
    rpc_new: Vec<&'static str>,
    key_new: Vec<String>,
    /// A01's keyboard focus as the shell would hold it (only picks the key mapping; never
    /// recorded) and the window it belongs to.
    focus: Focus,
    focus_of: ShownId,
    /// A press on `거부` started (`Pressed::Reject` of the shell) on that window.
    pressed: Option<ShownId>,
}

impl<'a> Run<'a> {
    fn new(name: &'static str, fx: &'a Fixture, outlet: Option<&'a Outlet>) -> Self {
        Self {
            name,
            fx,
            outlet,
            lines: Vec::new(),
            issued: None,
            rpc: Vec::new(),
            keys: Vec::new(),
            rpc_new: Vec::new(),
            key_new: Vec::new(),
            focus: Focus::Reject,
            focus_of: ShownId(0),
            pressed: None,
        }
    }

    // ----- recorder ------------------------------------------------------------------------

    /// Moves the jobs sent since the last pull into the recorder.
    fn pull(&mut self) {
        for job in self.fx.rpc_jobs() {
            self.rpc_new.push(job.name());
            self.rpc.push(job);
        }
        for job in self.fx.key_jobs() {
            self.key_new.push(key_name(&job));
            self.keys.push(job);
        }
    }

    fn take_prepare(&mut self) -> Box<PrepareJob> {
        self.pull();
        let at = self
            .rpc
            .iter()
            .position(|job| matches!(job, RpcJob::Prepare(_)))
            .expect("a preparation job");
        match self.rpc.remove(at) {
            RpcJob::Prepare(job) => job,
            _ => unreachable!("matched above"),
        }
    }

    fn take_resim(&mut self) -> Box<ResimJob> {
        self.pull();
        let at = self
            .rpc
            .iter()
            .position(|job| matches!(job, RpcJob::Resimulate(_)))
            .expect("a re-simulation job");
        match self.rpc.remove(at) {
            RpcJob::Resimulate(job) => job,
            _ => unreachable!("matched above"),
        }
    }

    /// Records one line: the windowed recorder's line without `focus=`, plus `effects`.
    fn snap(&mut self, step: &str) {
        self.pull();
        let rpc = names(self.rpc_new.drain(..));
        let key = names(self.key_new.drain(..));
        let dapp = self.outlet.map_or_else(|| "-".to_owned(), dapp_answers);
        let effects = effect_names(&headless_host::take_effects());
        let app = self.fx.app.borrow();
        assert!(app.approval_win.is_none(), "no approval window headless");
        if let Some(id) = app
            .evm
            .approval
            .as_ref()
            .and_then(|flow| flow.issued().map(|request| request.id))
        {
            self.issued = Some(id);
        }
        let mut line = format!("{} {step} | t={}", self.name, rel(self.fx.clock.peek()));
        if let Some(flow) = app.evm.approval.as_ref() {
            let gate = flow.gate();
            let _ = write!(
                line,
                " | win open status={:?} prep={} risk={} | gate ready={} ack={} sel={} \
                 submitting={} fg={} deadline={} | status-text {}",
                flow.session().interaction().status(),
                prep_name(&gate.prepare),
                if flow.view().blocked {
                    "blocked"
                } else if flow.view().high {
                    "high"
                } else {
                    "std"
                },
                rel(gate.ready_at_ms),
                gate.ack_checked,
                flow.connect().map_or_else(
                    || "-".to_owned(),
                    |connect| connect
                        .selected
                        .iter()
                        .map(|checked| if *checked { '1' } else { '0' })
                        .collect()
                ),
                gate.submitting,
                gate.is_foreground,
                rel(gate.deadline_ms),
                status_key(flow),
            );
        } else {
            line.push_str(" | win closed");
        }
        let store = self
            .issued
            .and_then(|id| app.evm.store.state(id))
            .map_or_else(|| "-".to_owned(), |state| format!("{state:?}"));
        let shown = app
            .evm
            .queue
            .shown()
            .map_or("-", |shown| item_name(&shown.payload));
        let banners = names(
            app.banners
                .iter()
                .filter_map(|banner| banner.code.map(crate::errors::ErrorCode::code)),
        );
        let info = match app.evm.send.info.as_deref() {
            None => "-",
            Some(info)
                if info == crate::app_evm::text::APPROVAL_EXPIRED.get(app.settings.language) =>
            {
                "APPROVAL_EXPIRED"
            }
            Some(_) => "other",
        };
        let _ = write!(
            line,
            " | store {store} | queue len={} shown={shown} | rpc {rpc} | key {key} | dapp {dapp} \
             | banners {banners} | info {info} | card {} | effects {effects}",
            app.evm.queue.len(),
            if app.card.step.is_some() { "step" } else { "-" },
        );
        drop(app);
        self.lines.push(line);
    }

    /// A free-form fact line (`<scenario> <step> | <fact>`).
    fn fact(&mut self, step: &str, fact: &str) {
        self.lines.push(format!("{} {step} | {fact}", self.name));
    }

    // ----- the window's inputs ---------------------------------------------------------------

    fn at(&self, ms: u64) {
        self.fx.clock.set(START_MS + ms);
    }

    /// The window opened last (the windowed tests' entries deliver to it as if it got the
    /// message).
    fn window(&self) -> ShownId {
        self.fx.app.borrow().last_opened()
    }

    /// The shown flow's window.
    fn shown_now(&self) -> Option<ShownId> {
        self.fx
            .app
            .borrow()
            .evm
            .approval
            .as_ref()
            .map(crate::approval_flow::ApprovalFlow::shown)
    }

    /// A new window starts with the focus on `거부` (reject-first) and no pressed button.
    fn follow(&mut self, window: ShownId) {
        if self.focus_of != window {
            self.focus_of = window;
            self.focus = Focus::Reject;
            self.pressed = None;
        }
    }

    /// One `Cmd::Approval` of `window`.
    fn send(&self, window: ShownId, foreground: bool, signal: ApprovalSignal) {
        self.fx
            .app()
            .on_cmd(Cmd::Approval(window_input(window, foreground, signal)));
    }

    /// An interaction event (or the close box) of `window` with the gate's foreground sample,
    /// read from the oracle as `TrustedSignals::sample_foreground` reads it while that window is
    /// open (`false` without it, as `window_event` sends it).
    fn window_event(&self, window: ShownId, signal: ApprovalSignal) {
        let foreground = self.shown_now() == Some(window)
            && flow_support::scripted(Read::Foreground).unwrap_or(false);
        self.send(window, foreground, signal);
    }

    /// The windowed `ev`: an interaction event of the window opened last.
    fn ev(&mut self, event: InteractionEvent) {
        let window = self.window();
        self.follow(window);
        self.window_event(window, ApprovalSignal::Event(event));
    }

    fn click(&mut self) {
        self.ev(PRESS);
        self.ev(RELEASE);
    }

    /// The windowed `toggle_ack()` entry: the `ToggleAck` step (no sample).
    fn toggle_ack(&mut self) {
        let window = self.window();
        self.follow(window);
        self.send(window, false, ApprovalSignal::ToggleAck);
    }

    /// `WM_ACTIVATEAPP(TRUE)`: the `Activated` step (no sample).
    fn activate(&mut self) {
        let window = self.window();
        self.follow(window);
        self.send(window, false, ApprovalSignal::Activated);
    }

    /// The close box (`WM_CLOSE`): the `Close` step, with the sample.
    fn close_box(&mut self) {
        let window = self.window();
        self.follow(window);
        self.window_event(window, ApprovalSignal::Close);
    }

    /// The shell's focus moved by the test (the windowed `win.focus = …`), on an open window.
    fn set_focus(&mut self, focus: Focus) {
        let window = self.window();
        self.follow(window);
        if self.shown_now() == Some(window) {
            self.focus = focus;
        }
    }

    /// A key to the window opened last: the production `map_key` with the focus held here (the
    /// facts of A01 when that window is open, none otherwise), its steps run as `run_step` runs
    /// them for the flow.
    fn key(&mut self, vk: u16, repeat: bool) {
        let window = self.window();
        self.follow(window);
        let facts = (self.shown_now() == Some(window)).then_some(Facts {
            focus: self.focus,
            pressed: None,
            hits: BarHits::default(),
        });
        let steps = map_key(vk, repeat, facts);
        self.run_steps(window, &steps);
    }

    /// A left press and release on `거부` of the window opened last: the rows of A01's
    /// `WM_LBUTTONDOWN` (not on `승인`: `OtherPress`, then only while that window is shown, the
    /// focus to `거부` and the button pressed) and `WM_LBUTTONUP` (with `거부` pressed and the
    /// pointer on it: `RejectActivated`) of spec/04 §3.4 (`approval_press`, `approval_release`).
    fn mouse_reject(&mut self) {
        let window = self.window();
        self.follow(window);
        if self.shown_now() != Some(window) {
            self.window_event(window, ApprovalSignal::Event(InteractionEvent::OtherPress));
            return;
        }
        self.run_steps(
            window,
            &[
                Step::Event(InteractionEvent::OtherPress),
                Step::SameWindow(yw_win::ui::Reply::Default),
                Step::MoveFocus(Focus::Reject),
            ],
        );
        if self.shown_now() == Some(window) {
            self.pressed = Some(window);
        }
        if self.pressed.take() == Some(window) && self.shown_now() == Some(window) {
            self.run_steps(window, &[Step::Event(InteractionEvent::RejectActivated)]);
        }
    }

    /// The flow half of `App::run_step` for the steps a key can map to; the steps that only move
    /// pixels, capture or scroll send nothing to the flow.
    fn run_steps(&mut self, window: ShownId, steps: &[Step]) {
        for step in steps {
            match *step {
                Step::Event(event) => self.window_event(window, ApprovalSignal::Event(event)),
                Step::Sampled(trusted) => {
                    let event = trusted.deliver(None);
                    self.window_event(window, ApprovalSignal::Event(event));
                }
                Step::Activated => self.send(window, false, ApprovalSignal::Activated),
                Step::Close => self.window_event(window, ApprovalSignal::Close),
                Step::ToggleAck => self.send(window, false, ApprovalSignal::ToggleAck),
                Step::ToggleRaw => self.send(window, false, ApprovalSignal::ToggleRaw),
                Step::Retry => self.send(window, false, ApprovalSignal::Retry),
                Step::AiRetry => self.send(window, false, ApprovalSignal::AiRetry),
                Step::SameWindow(_) => {
                    if self.shown_now() != Some(window) {
                        return;
                    }
                }
                Step::AnyWindow(_) => {
                    if self.shown_now().is_none() {
                        return;
                    }
                }
                Step::MoveFocus(focus) => self.focus = focus,
                Step::Tab => {
                    let order = {
                        let app = self.fx.app.borrow();
                        app.evm.approval.as_ref().map(|flow| {
                            let view = flow.view();
                            tab_order(view.blocks.contains(&Block::Ack), view.has_raw)
                        })
                    };
                    if let Some(order) = order {
                        let backwards = TrustedSignals::sample_shift().shift_down();
                        self.focus = tab_target(&order, self.focus, backwards);
                    }
                }
                Step::FocusReceiver
                | Step::FocusApproval
                | Step::Press(_)
                | Step::Unpress
                | Step::Capture
                | Step::Release
                | Step::Invalidate
                | Step::InvalidateApproval
                | Step::KeyScroll(_)
                | Step::Wheel(_)
                | Step::AiWheel(_)
                | Step::PanelScroll(_)
                | Step::AiScroll(_)
                | Step::Paint => {}
                Step::ToggleAccount { .. }
                | Step::PanelClick { .. }
                | Step::AiExpand
                | Step::Relayout
                | Step::TimerTail => unreachable!("no key maps to {step:?}"),
            }
        }
    }

    // ----- shared scenario steps -----------------------------------------------------------

    /// The S2 Sepolia app send, prepared from the `eth_simulateV1` fixture `sim`.
    fn app_send(&mut self, sim: &str) {
        self.fx.enqueue_sepolia_send();
        self.snap("open");
        let job = self.take_prepare();
        self.fx.answer_prepare(&job, sim);
        self.snap("ready");
    }

    /// The windowed `approve_by_risk`, step for step.
    fn approve_by_risk(&mut self, t: u64) {
        self.at(t);
        self.ev(InteractionEvent::Tick);
        self.snap("tick");
        let high = self
            .fx
            .app
            .borrow()
            .evm
            .approval
            .as_ref()
            .is_some_and(|flow| flow.view().high);
        if !high {
            self.at(t + 1_000);
            self.click();
            self.snap("click");
            return;
        }
        self.toggle_ack();
        self.snap("ack");
        self.set_focus(Focus::Approve);
        self.at(t + 1_000);
        self.key(VK_RETURN, false);
        self.snap("enter-high");
        self.at(t + 2_100);
        self.ev(PRESS);
        self.at(t + 4_000);
        self.ev(InteractionEvent::Tick);
        self.snap("hold-1900");
        self.ev(RELEASE);
        self.snap("release-early");
        self.at(t + 5_100);
        self.ev(PRESS);
        self.at(t + 7_100);
        self.ev(InteractionEvent::Tick);
        self.snap("hold-2000");
        self.ev(RELEASE);
    }

    /// The lifecycle `armed`: a tick at `t`, then the clock at `t + 1 000`.
    fn armed(&mut self, t: u64) {
        self.at(t);
        self.ev(InteractionEvent::Tick);
        self.at(t + 1_000);
        self.ev(InteractionEvent::Tick);
    }

    // ----- the main window's entries (no window) -------------------------------------------

    fn main_msg(&self, msg: &Msg) {
        let _ = self.fx.app().test_on_main_windowless(msg);
    }

    fn main_tick(&self) {
        let _ = self.fx.app().test_main_timer_windowless();
    }

    fn lock_shortcut(&self) {
        self.main_msg(&Msg::App {
            msg: WM_YW_LOCK_SHORTCUT,
            wparam: 0,
        });
    }

    /// A worker result through the event drain (`WM_YW_EVENTS`).
    fn deliver(&self, event: UiEvent) {
        let queue = self.fx.app.borrow().events.clone().expect("an event queue");
        assert!(queue.push(event).is_ok());
        self.main_msg(&Msg::App {
            msg: WM_YW_EVENTS,
            wparam: 0,
        });
    }

    /// Key worker outcomes of the current lock epoch, in order, through one event drain.
    fn deliver_keys(&self, outcomes: Vec<KeyOutcome>) {
        let epoch = self.fx.app.borrow().lock_epoch;
        let queue = self.fx.app.borrow().events.clone().expect("an event queue");
        for outcome in outcomes {
            assert!(
                queue
                    .push(UiEvent::Key(Box::new(KeyResult { epoch, outcome })))
                    .is_ok()
            );
        }
        self.main_msg(&Msg::App {
            msg: WM_YW_EVENTS,
            wparam: 0,
        });
    }

    fn deliver_key(&self, outcome: KeyOutcome) {
        self.deliver_keys(vec![outcome]);
    }

    /// The ticket of the last signing job captured.
    fn last_ticket(&self) -> Option<SignTicket> {
        self.keys.iter().rev().find_map(|job| match job {
            KeyJob::SignEvm { ticket, .. }
            | KeyJob::SignMessage { ticket, .. }
            | KeyJob::SignEvmCard { ticket, .. }
            | KeyJob::SignMessageCard { ticket, .. }
            | KeyJob::SignChainMessage { ticket, .. }
            | KeyJob::SignChainMessageCard { ticket, .. }
            | KeyJob::SignSolDapp { ticket, .. } => Some(*ticket),
            _ => None,
        })
    }

    fn signed_digest(&self) -> Option<[u8; 32]> {
        self.keys.iter().find_map(|job| match job {
            KeyJob::SignEvm { approved, .. } => Some(approved.digest()),
            _ => None,
        })
    }
}

/// The recorded approval effects as names, a run of one effect counted (`x<n>`).
fn effect_names(effects: &[ApprovalEffect]) -> String {
    let named: Vec<String> = effects
        .iter()
        .map(|effect| match *effect {
            ApprovalEffect::Open {
                shown,
                connect: false,
                ..
            } => format!("open#{}", shown.0),
            ApprovalEffect::Open { shown, .. } => format!("open-connect#{}", shown.0),
            ApprovalEffect::Close { shown } => format!("close#{}", shown.0),
            ApprovalEffect::Rebuilt {
                shown,
                changed: true,
            } => format!("rebuilt#{}", shown.0),
            ApprovalEffect::Rebuilt { shown, .. } => format!("same#{}", shown.0),
            ApprovalEffect::RepaintBar { shown } => format!("bar#{}", shown.0),
            ApprovalEffect::Redraw { shown } => format!("redraw#{}", shown.0),
            // 2026-11-22 (S4 W14a): no scenario here has an AI panel (no explanation worker),
            // so no golden line names it.
            ApprovalEffect::RepaintAi {
                shown,
                body_only: false,
            } => format!("ai#{}", shown.0),
            ApprovalEffect::RepaintAi { shown, .. } => format!("ai-body#{}", shown.0),
        })
        .collect();
    let mut out: Vec<String> = Vec::new();
    let mut at = 0;
    while let Some(name) = named.get(at) {
        let run = named[at..].iter().take_while(|next| *next == name).count();
        out.push(if run > 1 {
            format!("{name}x{run}")
        } else {
            name.clone()
        });
        at += run;
    }
    names(out.iter())
}

/// The shown request's digest after `sign` (`same`/`new`/`none` against `old`).
fn digest_word(signed: Option<[u8; 32]>, old: [u8; 32]) -> &'static str {
    match signed {
        Some(digest) if digest == old => "same",
        Some(_) => "new",
        None => "none",
    }
}

// ----- flow scenarios (s4_flow/flow.txt) ------------------------------------------------------

fn reject_first() -> Vec<String> {
    let fx = fixture("reject-first");
    let mut h = Run::new("reject_first", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    h.snap("tick");
    h.at(1_500);
    h.key(VK_RETURN, false);
    h.snap("enter");
    let slots = fx.app.borrow().evm.slots.len();
    h.fact("slots", &format!("send slots held={slots}"));
    h.lines
}

fn repeat_enter_on_reject() -> Vec<String> {
    let fx = fixture("repeat-enter");
    let mut h = Run::new("repeat_enter_on_reject", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    h.snap("tick");
    h.at(500);
    h.key(VK_RETURN, true);
    h.snap("enter-repeat-unarmed");
    h.at(2_000);
    h.key(VK_RETURN, true);
    h.snap("enter-repeat-armed");
    h.at(2_100);
    h.key(VK_RETURN, false);
    h.snap("enter");
    h.lines
}

fn posted_enter_on_approve() -> Vec<String> {
    let fx = fixture("posted-enter");
    let mut h = Run::new("posted_enter_on_approve", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    h.at(100);
    h.key(VK_TAB, false);
    h.snap("tab");
    flow_support::set_signals(Some(signals(false)));
    h.at(1_200);
    h.key(VK_RETURN, false);
    h.snap("enter-posted");
    flow_support::set_signals(Some(signals(true)));
    h.at(1_700);
    h.key(VK_RETURN, false);
    h.snap("enter-too-soon");
    h.at(2_800);
    h.key(VK_RETURN, false);
    h.snap("enter-physical");
    h.lines
}

fn stray_key_unarmed() -> Vec<String> {
    let fx = fixture("stray-key");
    let mut h = Run::new("stray_key_unarmed", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    h.at(900);
    h.key(VK_A, false);
    h.snap("key-a");
    for (t, step) in [
        (1_500, "click-unarmed"),
        (1_900, "click-1900"),
        (3_000, "click-3000"),
    ] {
        h.at(t);
        h.click();
        h.snap(step);
    }
    h.lines
}

fn reactivation_restarts_the_delay() -> Vec<String> {
    let fx = fixture("reactivation");
    let mut h = Run::new("reactivation_restarts_the_delay", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    h.at(1_500);
    flow_support::set_signals(Some(Signals {
        foreground: false,
        ..signals(true)
    }));
    h.ev(InteractionEvent::Tick);
    h.snap("background");
    flow_support::set_signals(Some(signals(true)));
    h.at(1_600);
    h.ev(InteractionEvent::Tick);
    h.snap("foreground");
    h.at(2_000);
    h.click();
    h.snap("click-2000");
    h.at(3_500);
    h.activate();
    h.snap("activate-app");
    h.at(4_000);
    h.click();
    h.snap("click-4000");
    h.at(5_100);
    h.click();
    h.snap("click-5100");
    h.lines
}

fn c1_message_one_job() -> Vec<String> {
    let fx = fixture("c1-message");
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new("c1_message_one_job", &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    h.snap("ready");
    h.approve_by_risk(0);
    for step in 0..5 {
        h.at(1_100 + 1_100 * step);
        h.click();
        h.ev(InteractionEvent::Tick);
    }
    h.snap("after-5-clicks");
    let waiters = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map_or(0, |browser| browser.waiters.len());
    h.fact("waiters", &format!("sign waiters={waiters}"));
    h.lines
}

fn c1_stale_sim_one_resim() -> Vec<String> {
    let fx = fixture("c1-stale");
    let mut h = Run::new("c1_stale_sim_one_resim", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    h.at(61_000);
    h.click();
    h.snap("click-stale");
    for step in 0..3 {
        h.at(62_100 + 1_100 * step);
        h.click();
        h.ev(InteractionEvent::Tick);
    }
    h.snap("after-3-clicks");
    h.lines
}

fn resim_boundary(after_ms: u64, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let mut h = Run::new(name, &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    h.at(after_ms);
    h.click();
    h.snap("click");
    h.lines
}

fn resim_same_after_click() -> Vec<String> {
    let fx = fixture("resim-same");
    let mut h = Run::new("resim_same_after_click", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    let (id, old) = shown_digest(&fx).unwrap();
    h.at(61_000);
    h.click();
    h.snap("click-stale");
    let job = h.take_resim();
    h.at(61_500);
    answer_resim(&fx, &job, "S2");
    h.snap("resim-same");
    let signed = h.signed_digest();
    h.fact(
        "digest",
        &format!(
            "signed digest vs pre-resim digest={}",
            digest_word(signed, old)
        ),
    );
    let again = fx.app().evm.store.consume(id, old, START_MS + 61_600);
    h.fact(
        "old-digest",
        &format!(
            "consume with the pre-resim digest={:?}",
            again.map(|_| "approved")
        ),
    );
    h.lines
}

fn resim_changed_needs_a_new_click() -> Vec<String> {
    let fx = fixture("resim-changed");
    let mut h = Run::new("resim_changed_needs_a_new_click", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    let (_, old) = shown_digest(&fx).unwrap();
    h.at(61_000);
    h.click();
    h.snap("click-stale");
    let job = h.take_resim();
    h.at(61_500);
    answer_resim(&fx, &job, "S3");
    h.snap("resim-changed");
    let changed = shown_digest(&fx).map(|(_, digest)| digest != old);
    h.fact("digest", &format!("shown digest changed={changed:?}"));
    h.approve_by_risk(61_600);
    let signed = h.signed_digest();
    h.fact(
        "signed",
        &format!(
            "signed digest vs pre-resim digest={}",
            digest_word(signed, old)
        ),
    );
    h.lines
}

fn resim_changed_old_digest() -> Vec<String> {
    let fx = fixture("resim-old-digest");
    let mut h = Run::new("resim_changed_old_digest", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    let (id, old) = shown_digest(&fx).unwrap();
    h.at(61_000);
    h.click();
    h.snap("click-stale");
    let job = h.take_resim();
    h.at(61_500);
    answer_resim(&fx, &job, "S3");
    h.snap("resim-changed");
    let replaced = shown_digest(&fx).map(|(new_id, digest)| (new_id == id, digest != old));
    h.fact(
        "digest",
        &format!("shown (same id, digest changed)={replaced:?}"),
    );
    let again = fx.app().evm.store.consume(id, old, START_MS + 61_600);
    h.fact(
        "old-digest",
        &format!(
            "consume with the pre-resim digest={:?}",
            again.map(|_| "approved")
        ),
    );
    h.snap("after-old-digest");
    h.lines
}

fn resim_no_result_and_failed() -> Vec<String> {
    let fx = fixture("resim-noresult");
    let mut h = Run::new("resim_no_result_and_failed", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    h.at(61_000);
    h.click();
    h.snap("click-stale");
    let job = h.take_resim();
    h.at(61_500);
    fx.app().on_resimulated(ResimResult {
        job: job.job,
        kind: ResimKind::NoResult,
        prepared: None,
        failure: None,
    });
    h.snap("no-result");
    h.approve_by_risk(61_600);
    let job = h.take_resim();
    h.at(63_000);
    let lang = approval_lang(&fx);
    fx.app().on_resimulated(ResimResult {
        job: job.job,
        kind: ResimKind::Failed,
        prepared: None,
        failure: Some(PrepareFailure::no_endpoint(lang)),
    });
    h.snap("failed");
    h.at(64_100);
    h.click();
    h.snap("click-failed");
    h.lines
}

fn stale_resim_result_is_dropped() -> Vec<String> {
    let fx = fixture("resim-stale");
    let mut h = Run::new("stale_resim_result_is_dropped", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    h.at(61_000);
    h.click();
    h.snap("click-stale");
    let job = h.take_resim();
    h.at(61_500);
    fx.app().on_resimulated(ResimResult {
        job: job.job - 1,
        kind: ResimKind::NoResult,
        prepared: None,
        failure: None,
    });
    h.snap("other-job");
    answer_resim(&fx, &job, "S2");
    h.snap("own-job");
    h.lines
}

fn display_change_mid_hold() -> Vec<String> {
    let fx = fixture("mid-hold");
    let mut h = Run::new("display_change_mid_hold", &fx, None);
    h.app_send("S3");
    h.ev(InteractionEvent::Tick);
    h.toggle_ack();
    h.snap("ack");
    h.at(2_000);
    h.ev(PRESS);
    h.at(3_500);
    h.ev(InteractionEvent::Tick);
    h.snap("holding");
    let job = fx
        .app
        .borrow()
        .evm
        .approval
        .as_ref()
        .map_or(0, crate::approval_flow::ApprovalFlow::job);
    fx.app().on_simulating(job, START_MS + 3_500);
    h.snap("display-changed");
    h.at(4_000);
    h.ev(InteractionEvent::Tick);
    h.snap("old-hold-2000");
    h.ev(RELEASE);
    h.snap("release");
    h.lines
}

fn high_risk_evm() -> Vec<String> {
    let fx = fixture("high-evm");
    let mut h = Run::new("high_risk_evm", &fx, None);
    h.app_send("S3");
    h.approve_by_risk(0);
    h.lines
}

/// An app chain item (BTC, ZEC, `HyperCore`) shown at once, then approved by its risk.
fn chain_item(item: QueuedItem, fx: &Fixture, name: &'static str) -> Vec<String> {
    let mut h = Run::new(name, fx, None);
    enqueue_app_item(fx, item);
    h.snap("ready");
    h.approve_by_risk(0);
    h.lines
}

fn chain_btc() -> Vec<String> {
    let fx = fixture("chain-btc");
    chain_item(btc_item(), &fx, "chain_btc")
}

fn chain_zec() -> Vec<String> {
    let fx = fixture("chain-zec");
    chain_item(zec_item(), &fx, "chain_zec")
}

fn chain_hypercore(look_alike: bool, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let item = hypercore_item(&fx, look_alike);
    chain_item(item, &fx, name)
}

fn chain_sol_message() -> Vec<String> {
    let fx = fixture("chain-sol");
    let outlet = dapp(&fx, true, true);
    let mut h = Run::new("chain_sol_message", &fx, Some(&outlet));
    request(
        &fx,
        &outlet,
        1,
        "sol_signMessage",
        &format!(r#"[{{"publicKey":"{SOL_KEY}","message":"50726f7665206974"}}]"#),
        "signing",
        600_000,
    );
    h.snap("ready");
    h.approve_by_risk(0);
    h.lines
}

fn consume_site_messages() -> Vec<String> {
    let fx = fixture("site-messages");
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new("consume_site_messages", &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    h.snap("personal-ready");
    h.approve_by_risk(0);
    let typed = ETHER_MAIL_SEPOLIA.replace('"', "\\\"");
    h.at(10_000);
    request(
        &fx,
        &outlet,
        2,
        "eth_signTypedData_v4",
        &format!(r#"["{ACCOUNT_A}","{typed}"]"#),
        "signing",
        600_000,
    );
    h.snap("typed-open");
    h.pull();
    let facts = h.rpc.iter().find_map(|job| match job {
        RpcJob::TypedFacts {
            job,
            address_book,
            own_accounts,
            ..
        } => Some((*job, address_book.clone(), own_accounts.clone())),
        _ => None,
    });
    if let Some((job, address_book, own_accounts)) = facts {
        fx.app().on_typed_facts(
            job,
            &yw_core::approval::ChainFacts {
                address_book,
                own_accounts,
                ..yw_core::approval::ChainFacts::default()
            },
            None,
        );
    }
    h.snap("typed-ready");
    h.approve_by_risk(10_000);
    h.lines
}

/// An `eth_sendTransaction` of account A (the windowed site sends' request).
fn send_request(fx: &Fixture, outlet: &Outlet, n: u8) {
    request(
        fx,
        outlet,
        n,
        "eth_sendTransaction",
        &format!(
            r#"[{{"from":"{ACCOUNT_A}","to":"0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb","value":"0x2386f26fc10000"}}]"#
        ),
        "signing",
        600_000,
    );
}

fn site_send(sim: &'static str, approve: bool, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new(name, &fx, Some(&outlet));
    send_request(&fx, &outlet, 1);
    h.snap("open");
    h.pull();
    if !h.rpc.iter().any(|job| matches!(job, RpcJob::Prepare(_))) {
        return h.lines;
    }
    let job = h.take_prepare();
    fx.answer_prepare(&job, sim);
    h.snap("ready");
    if approve {
        h.approve_by_risk(0);
        let waiters = fx
            .app
            .borrow()
            .browser
            .as_ref()
            .map_or(0, |browser| browser.waiters.len());
        h.fact("waiters", &format!("sign waiters={waiters}"));
    } else {
        h.ev(InteractionEvent::Tick);
        h.at(1_000);
        h.key(VK_ESCAPE, false);
        h.snap("escape");
    }
    h.lines
}

fn consume_app009_branches() -> Vec<String> {
    let fx = fixture("app009");
    let mut h = Run::new("consume_app009_branches", &fx, None);
    h.app_send("S2");
    let lang = approval_lang(&fx);
    let draft = yw_core::sol::msgsign::build_sol_message_request(
        lang,
        &yw_core::sol::msgsign::SolMessageRequest {
            id: ApprovalId([7; 16]),
            origin: origin(),
            cluster: yw_core::sol::address::SolCluster::Devnet,
            source: yw_core::slip10::SolKeySource::Standard(
                yw_core::bip32::path::AccountIndex::ZERO,
            ),
            public: yw_core::codec::base58::base58_decode_32(SOL_KEY).unwrap(),
            label: "SOL 1".to_owned(),
            message: b"Prove it".to_vec(),
            sign_in: false,
        },
        fx.clock.unix_at(fx.clock.peek()),
    )
    .unwrap();
    fx.app().show_ready_draft(draft, None);
    h.snap("chain-message-on-app-item");
    h.approve_by_risk(0);
    let fx2 = fixture("app009-tx");
    let mut h2 = Run::new("consume_app009_branches", &fx2, None);
    fx2.enqueue_sepolia_send();
    let job = h2.take_prepare();
    fx2.answer_prepare(&job, "S2");
    let draft = fx2
        .app
        .borrow()
        .evm
        .approval
        .as_ref()
        .and_then(|flow| flow.prepared().map(|prepared| prepared.draft.clone()))
        .unwrap();
    let draft = yw_core::approval::ApprovalDraft {
        id: ApprovalId([8; 16]),
        ..draft
    };
    fx2.app().show_ready_draft(draft, None);
    h2.snap("tx-without-preparation");
    h2.approve_by_risk(0);
    let mut lines = h.lines;
    lines.append(&mut h2.lines);
    lines
}

fn blocked_is_never_consumed() -> Vec<String> {
    let fx = fixture("blocked");
    let mut h = Run::new("blocked_is_never_consumed", &fx, None);
    fx.enqueue_sepolia_send();
    h.snap("open");
    let mut job = h.take_prepare();
    job.chain.caps.max_total_fee = U256::from_u64(1_000);
    fx.answer_prepare(&job, "S2");
    h.snap("ready");
    h.ev(InteractionEvent::Tick);
    h.at(1_500);
    h.click();
    h.snap("click");
    h.set_focus(Focus::Approve);
    h.at(2_600);
    h.key(VK_RETURN, false);
    h.snap("enter");
    h.at(3_700);
    h.ev(PRESS);
    h.at(6_000);
    h.ev(InteractionEvent::Tick);
    h.ev(RELEASE);
    h.snap("hold");
    h.at(7_000);
    h.key(VK_ESCAPE, false);
    h.snap("escape");
    h.lines
}

fn expiry(main: bool, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let mut h = Run::new(name, &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    h.at(119_999);
    h.ev(InteractionEvent::Tick);
    fx.app().tick_approval(START_MS + 119_999);
    h.snap("tick-119999");
    h.at(120_000);
    if main {
        fx.app().tick_approval(START_MS + 120_000);
        h.snap("main-tick-120000");
        h.ev(InteractionEvent::Tick);
        h.snap("window-tick-after");
    } else {
        h.ev(InteractionEvent::Tick);
        h.snap("window-tick-120000");
        fx.app().tick_approval(START_MS + 120_000);
        h.snap("main-tick-after");
    }
    h.lines
}

fn l3_site_deadline(main: bool, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new(name, &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 30_000);
    h.snap("ready");
    h.ev(InteractionEvent::Tick);
    let deadline = fx
        .app
        .borrow()
        .evm
        .approval
        .as_ref()
        .map_or(0, |flow| flow.gate().deadline_ms);
    h.fact("deadline", &format!("gate deadline={}", rel(deadline)));
    fx.clock.set(deadline);
    if main {
        fx.app().tick_approval(deadline);
        h.snap("main-tick-at-deadline");
        h.ev(InteractionEvent::Tick);
        h.snap("window-tick-after");
    } else {
        h.ev(InteractionEvent::Tick);
        h.snap("window-tick-at-deadline");
        fx.app().tick_approval(deadline);
        h.snap("main-tick-after");
    }
    h.lines
}

fn ui001_and_wc_label() -> Vec<String> {
    let fx = fixture("ui001");
    let mut h = Run::new("ui001_and_wc_label", &fx, None);
    fx.enqueue_sepolia_send();
    let job = h.take_prepare();
    fx.answer_prepare(&job, "S2");
    let mut draft = fx
        .app
        .borrow()
        .evm
        .approval
        .as_ref()
        .and_then(|flow| flow.prepared().map(|prepared| prepared.draft.clone()))
        .unwrap();
    let mut unsafe_title = draft.clone();
    unsafe_title.id = ApprovalId([9; 16]);
    unsafe_title.display.title = "\u{202e}title".to_owned();
    fx.app().show_ready_draft(unsafe_title, None);
    h.snap("unsafe-title");
    let refused = fx.app.borrow().evm.store.state(ApprovalId([9; 16]));
    h.fact(
        "unsafe-title-id",
        &format!("store state of the draft={refused:?}"),
    );
    let fx3 = fixture("ui001-key");
    let mut h3 = Run::new("ui001_and_wc_label", &fx3, None);
    fx3.enqueue_sepolia_send();
    let job = h3.take_prepare();
    fx3.answer_prepare(&job, "S2");
    draft.id = ApprovalId([10; 16]);
    if let Some(mut field) = draft.display.fields.first().cloned() {
        field.key = yw_core::approval::FieldKey(0x7fff);
        draft.display.fields.push(field);
    }
    fx3.app().show_ready_draft(draft, None);
    h3.snap("unlabelled-field");
    let refused = fx3.app.borrow().evm.store.state(ApprovalId([10; 16]));
    h3.fact(
        "unlabelled-field-id",
        &format!("store state of the draft={refused:?}"),
    );
    h.lines.append(&mut h3.lines);
    let fx2 = fixture("wc-label");
    let outlet = dapp(&fx2, false, true);
    let wc_origin = crate::walletconnect::session_origin(&[9; 32]).unwrap();
    let (sender, frames) = std::sync::mpsc::channel();
    let core = fx2
        .app
        .borrow()
        .browser
        .as_ref()
        .map(|browser| Arc::clone(&browser.core))
        .unwrap();
    core.upsert_grant(
        yw_core::policy::ConnectedSite::new(
            wc_origin.clone(),
            vec![yw_core::evm::address::parse_address(ACCOUNT_A).unwrap()],
            yw_core::evm::chain::SEPOLIA,
            1,
        )
        .unwrap(),
    );
    let wc = Outlet {
        events: Arc::clone(&outlet.events),
        frames,
        conn: core.open_virtual_connection(Box::new(sender)),
    };
    let _ = wc.events.drain();
    let mut h2 = Run::new("ui001_and_wc_label", &fx2, Some(&wc));
    wc_personal_sign(&fx2, &core, &wc, wc_origin);
    h2.snap("wc-no-session");
    let mut lines = h.lines;
    lines.append(&mut h2.lines);
    lines
}

fn open_failure() -> Vec<String> {
    let fx = fixture_with("open-failure", OpenAnswer::Failed);
    let mut h = Run::new("open_failure", &fx, None);
    fx.enqueue_sepolia_send();
    h.snap("enqueue");
    let slots = fx.app.borrow().evm.slots.len();
    h.fact("slots", &format!("send slots held={slots}"));
    h.lines
}

fn issue_uses_one_instant() -> Vec<String> {
    let fx = fixture("one-instant");
    let mut h = Run::new("issue_uses_one_instant", &fx, None);
    fx.enqueue_sepolia_send();
    let job = h.take_prepare();
    fx.clock.set_step(7);
    fx.answer_prepare(&job, "S2");
    fx.clock.set_step(0);
    h.snap("ready");
    let app = fx.app.borrow();
    let flow = app.evm.approval.as_ref().unwrap();
    let request = flow.issued().unwrap();
    let queue_deadline = app.evm.queue.shown_deadline().unwrap_or(0);
    let received = flow
        .prepared()
        .map_or(0, |prepared| prepared.sim_received_ms);
    let fact = format!(
        "sim received={} session ready={} gate deadline={} queue deadline={} issued(unix-base)={} \
         expires-issued={}",
        rel(received),
        rel(flow.gate().ready_at_ms),
        rel(flow.gate().deadline_ms),
        rel(queue_deadline),
        rel(request.created_unix_ms - fx.clock.unix_at(0)),
        request.expires_unix_ms - request.created_unix_ms,
    );
    drop(app);
    h.fact("instants", &fact);
    h.lines
}

fn l1_close_with_a_second_request_queued() -> Vec<String> {
    let fx = fixture("l1");
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new("l1_close_with_a_second_request_queued", &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    personal_sign(&fx, &outlet, 2, 600_000);
    h.snap("two-queued");
    h.ev(InteractionEvent::Tick);
    h.at(1_500);
    h.close_box();
    h.snap("close-box");
    let shown = shown_request(&fx);
    h.fact("shown", &format!("shown request={shown}"));
    h.lines
}

/// The grants of the dispatcher as the L-2 scenarios record them.
fn grants(fx: &Fixture) -> String {
    fx.app.borrow().browser.as_ref().map_or_else(
        || "-".to_owned(),
        |browser| {
            let sites = browser.core.grants();
            let chains = names(sites.iter().map(|site| site.chain_id.to_string()));
            let accounts = names(sites.iter().map(|site| site.accounts.len().to_string()));
            format!("grants={} chain={chains} accounts={accounts}", sites.len())
        },
    )
}

fn l2_connect_chain_change(end: &'static str, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let outlet = dapp(&fx, false, false);
    let mut h = Run::new(name, &fx, Some(&outlet));
    request(
        &fx,
        &outlet,
        1,
        "eth_requestAccounts",
        "[]",
        "permission",
        600_000,
    );
    h.snap("connect-ready");
    h.ev(InteractionEvent::Tick);
    if let Some(browser) = fx.app.borrow().browser.as_ref() {
        browser
            .core
            .set_origin_chain(&origin(), yw_core::evm::chain::ETHEREUM_MAINNET);
    }
    h.at(1_500);
    h.click();
    h.snap("click-chain-changed");
    h.fact("grants", &grants(&fx));
    h.at(1_700);
    h.click();
    h.snap("click-too-soon");
    h.fact("grants", &grants(&fx));
    match end {
        "close-box" => {
            h.at(2_000);
            h.close_box();
            h.snap(end);
        }
        "main-tick" => {
            h.at(121_000);
            fx.app().tick_approval(START_MS + 121_000);
            h.snap(end);
        }
        "enter-on-reject" => {
            h.at(2_000);
            h.key(VK_RETURN, false);
            h.snap(end);
        }
        "mouse-reject" => {
            h.at(2_000);
            h.mouse_reject();
            h.snap(end);
        }
        "escape" => {
            h.at(2_000);
            h.key(VK_ESCAPE, false);
            h.snap(end);
        }
        "window-tick" => {
            h.at(121_000);
            h.ev(InteractionEvent::Tick);
            h.snap(end);
        }
        "approve" => {
            h.at(2_700);
            h.click();
            h.snap("click-armed");
            h.fact("grants", &grants(&fx));
        }
        _ => h.fact("error", &format!("unknown end {end}")),
    }
    h.lines
}

// ----- lifecycle scenarios (s4_flow/lifecycle.txt) ---------------------------------------------

fn lock_shortcut_while_shown() -> Vec<String> {
    let fx = fixture("lock-shortcut");
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new("lock_shortcut_while_shown", &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    personal_sign(&fx, &outlet, 2, 600_000);
    let wc = wc_waiting(&fx, &outlet);
    h.armed(0);
    h.snap("armed-2-waiting");
    h.lock_shortcut();
    h.snap("ctrl-l");
    h.fact(
        "walletconnect",
        &format!("walletconnect request: dapp {}", dapp_answers(&wc)),
    );
    let mode = format!("{:?}", fx.app.borrow().mode);
    h.fact("mode", &format!("mode={mode}"));
    h.at(2_000);
    h.click();
    h.snap("click-after-lock");
    h.lines
}

fn lock_with_resimulation_in_flight() -> Vec<String> {
    let fx = fixture("lock-resim");
    let mut h = Run::new("lock_with_resimulation_in_flight", &fx, None);
    h.app_send("S2");
    h.ev(InteractionEvent::Tick);
    h.at(61_000);
    h.click();
    h.snap("click-stale");
    let job = h.take_resim();
    h.lock_shortcut();
    h.snap("ctrl-l");
    h.at(61_500);
    answer_resim(&fx, &job, "S2");
    h.snap("resim-result-after-lock");
    h.lines
}

fn lock_by_message(msg: &Msg, name: &'static str) -> Vec<String> {
    let fx = fixture(name);
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new(name, &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    h.armed(0);
    h.snap("armed");
    {
        let _ack = LockAck::start(&fx);
        h.main_msg(msg);
    }
    h.snap("message");
    let app = fx.app.borrow();
    let fact = format!("mode={:?} screen={:?}", app.mode, app.screen);
    drop(app);
    h.fact("after", &fact);
    h.lines
}

fn lock_idle_after_the_window() -> Vec<String> {
    let fx = fixture("lock-idle");
    let outlet = dapp(&fx, false, true);
    let minutes = u64::from(fx.app.borrow().settings.auto_lock_minutes);
    let limit = minutes * 60_000;
    let mut h = Run::new("lock_idle_after_the_window", &fx, Some(&outlet));
    h.fact("limit", &format!("auto-lock minutes={minutes}"));
    personal_sign(&fx, &outlet, 1, 600_000);
    h.armed(0);
    h.main_tick();
    h.snap("tick-shown");
    for (t, step) in [
        (limit + 1_000, "tick-past-limit"),
        (limit + 2_000, "tick-after-close"),
        (2 * limit + 3_000, "tick-past-limit-again"),
    ] {
        h.at(t);
        h.main_tick();
        h.snap(step);
    }
    let mode = format!("{:?}", fx.app.borrow().mode);
    h.fact("mode", &format!("mode={mode}"));
    h.lines
}

fn open_then_lock_same_entry() -> Vec<String> {
    let fx = fixture("open-lock");
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new("open_then_lock_same_entry", &fx, Some(&outlet));
    let core = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map(|browser| Arc::clone(&browser.core))
        .unwrap();
    personal_sign_frame_only(&fx, &outlet, &core);
    {
        let mut app = fx.app();
        for event in outlet.events.drain() {
            if let UiEvent::Dapp(event) = event {
                app.on_dapp_event(event);
            }
        }
        app.lock(LockReason::Manual);
    }
    h.snap("open-and-lock");
    h.lines
}

/// `open_then_lock_same_entry` with a step its opener left for the answer to the open
/// (`AfterOpen::SetScreen`, as a confirmation overlay's next screen; 2026-11-20, S4 P10b review).
/// The lock in the same entry ends the flow, so the queued open is stale when the entry drains
/// and makes no window (critique A-3, owner decision 2026-11-20). 2026-11-21 (S4 F14, owner
/// decision, spec/04 §5.3, spec/15 §18 item 14): the lock drops the kept step and the wait for the
/// open's answer, so the step never runs; the stale open is still answered (`Failed`, dropped as
/// stale) and its window closed (`open#1,close#1`, as `open_then_lock_same_entry`). From the P10b
/// review until F14 this test was `a_step_kept_for_an_open_runs_after_a_lock_in_the_same_entry`
/// and pinned the other order: the lock kept the step, which ran with the stale answer, after the
/// lock (screen `Sites`). Before P10b the open was applied at once, so the step ran before the
/// lock. No production entry opens with a kept step and locks in the same call (the lock's callers
/// lock in their own entry, and every entry drains). Headless, no window.
#[test]
fn a_lock_drops_the_steps_kept_for_an_open_in_the_same_entry() {
    use yw_engine::effect::Effect;

    use crate::app::Screen;
    use crate::app_approval::AfterOpen;

    let fx = fixture("open-lock-kept");
    let outlet = dapp(&fx, false, true);
    let core = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map(|browser| Arc::clone(&browser.core))
        .unwrap();
    personal_sign_frame_only(&fx, &outlet, &core);
    let _ = headless_host::take_effects();
    {
        let mut app = fx.app();
        for event in outlet.events.drain() {
            if let UiEvent::Dapp(event) = event {
                app.on_dapp_event(event);
            }
        }
        assert!(app.evm.open_unanswered.is_some(), "the open is queued");
        app.after_pending_open(AfterOpen::SetScreen(Screen::Sites));
        assert_eq!(app.evm.after_open.len(), 1, "kept for the open's answer");
        app.lock(LockReason::Manual);
        assert_eq!(app.screen, Screen::Locked);
        assert!(app.evm.approval.is_none(), "the lock ended the flow");
        assert!(app.evm.after_open.is_empty(), "the lock dropped the step");
        assert_eq!(
            app.evm.open_unanswered, None,
            "no open waits after the lock"
        );
        assert!(
            app.outbox
                .iter()
                .any(|effect| matches!(effect, Effect::Approval(ApprovalEffect::Open { .. }))),
            "the stale open is still queued"
        );
    }
    assert_eq!(
        effect_names(&headless_host::take_effects()),
        "open#1,close#1",
        "the stale open was answered and its window closed"
    );
    assert_eq!(dapp_answers(&outlet), "4001 User rejected the request.");
    let app = fx.app.borrow();
    assert!(app.outbox.is_empty());
    assert_eq!(app.evm.open_unanswered, None);
    assert!(app.evm.after_open.is_empty());
    assert_eq!(app.screen, Screen::Locked, "the kept step did not run");
    assert!(app.approval_win.is_none(), "no window was made");
    assert!(app.evm.approval.is_none());
}

/// The `Suspend` shape of [`a_lock_drops_the_steps_kept_for_an_open_in_the_same_entry`]
/// (2026-11-21, S4 F14 review, spec/04 §5.3, spec/15 §18 item 14): a `Suspend` lock drains the
/// outbox inside `App::lock` before its wait for the key worker (`AwaitKeyLock`), so the stale
/// open queued earlier in the entry is applied and answered there, before the lock sets the mode
/// and the screen. The lock dropped the kept steps before that drain (`Wallet::lock_steps`, at the
/// `lock_epoch` bump; 2026-11-21, S4 W3a: before, `App::lock`), so none runs inside the lock
/// either. The kept `SetScreen` alone would not show it (the lock
/// sets `Locked` after the drain), so a `HiddenNote` is kept too: its banner stays after the lock
/// if it ran. A clear moved after the drain fails here (mutation probe of the F14 review, run and
/// reverted). No key worker runs, so the lock's wait times out (1.5 s). Headless, no window.
#[test]
fn a_suspend_lock_drops_the_steps_kept_for_an_open_before_its_drain() {
    use crate::app::Screen;
    use crate::app_approval::AfterOpen;

    let fx = fixture("open-lock-suspend");
    let outlet = dapp(&fx, false, true);
    let core = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map(|browser| Arc::clone(&browser.core))
        .unwrap();
    personal_sign_frame_only(&fx, &outlet, &core);
    let _ = headless_host::take_effects();
    let note = {
        let app = fx.app.borrow();
        crate::app_hidden::hidden_note(app.settings.language, "kept-step")
    };
    {
        let mut app = fx.app();
        for event in outlet.events.drain() {
            if let UiEvent::Dapp(event) = event {
                app.on_dapp_event(event);
            }
        }
        assert!(app.evm.open_unanswered.is_some(), "the open is queued");
        app.after_pending_open(AfterOpen::SetScreen(Screen::Sites));
        app.after_pending_open(AfterOpen::HiddenNote("kept-step".to_owned()));
        assert_eq!(app.evm.after_open.len(), 2, "kept for the open's answer");
        app.lock(LockReason::Suspend);
        // The lock's own drain applied the stale open and answered it, inside the lock.
        assert_eq!(
            effect_names(&headless_host::take_effects()),
            "open#1,close#1",
            "the stale open was answered in the lock and its window closed"
        );
        assert_eq!(app.screen, Screen::Locked);
        assert!(app.evm.approval.is_none(), "the lock ended the flow");
        assert!(app.evm.after_open.is_empty(), "the lock dropped the steps");
        assert_eq!(
            app.evm.open_unanswered, None,
            "no open waits after the lock"
        );
        assert!(
            !app.banners.iter().any(|banner| banner.text == note),
            "the kept steps did not run inside the lock"
        );
    }
    assert!(
        headless_host::take_effects().is_empty(),
        "the entry's drain had no approval effect left"
    );
    assert_eq!(dapp_answers(&outlet), "4001 User rejected the request.");
    let app = fx.app.borrow();
    assert!(app.outbox.is_empty());
    assert_eq!(app.evm.open_unanswered, None);
    assert!(app.evm.after_open.is_empty());
    assert_eq!(app.screen, Screen::Locked, "the kept steps did not run");
    assert!(
        !app.banners.iter().any(|banner| banner.text == note),
        "nor after it"
    );
    assert!(app.approval_win.is_none(), "no window was made");
    assert!(app.evm.approval.is_none());
}

/// The deferred-answer shape of [`a_lock_drops_the_steps_kept_for_an_open_in_the_same_entry`]
/// (2026-11-21, S4 F14, owner decision, spec/04 §5.3, spec/15 §18 item 14): the open and the step
/// kept for its answer are made in one entry whose effects the shell applies only later (here the
/// test takes them out of the outbox, as a shell that answers after the entry returned would hold
/// them: Android, the deferred schedule of S4d E2), a lock comes in a later entry, and the held
/// open is applied and answered after the lock. The lock dropped the kept step, so it does not
/// run then either: the screen stays `Locked`. The open is still answered (`Failed`: its flow
/// ended with the lock, the answer is dropped as stale) and makes no window; the lock's close came
/// first (`close#1,open#1`). Headless, no window.
#[test]
fn a_lock_drops_the_steps_kept_for_an_open_of_an_earlier_entry() {
    use yw_engine::effect::Effect;

    use crate::app::Screen;
    use crate::app_approval::AfterOpen;

    let fx = fixture("open-lock-deferred");
    let outlet = dapp(&fx, false, true);
    let core = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map(|browser| Arc::clone(&browser.core))
        .unwrap();
    personal_sign_frame_only(&fx, &outlet, &core);
    let _ = headless_host::take_effects();
    // Entry 1: the open is asked for and a step is kept for its answer; the shell holds the
    // entry's effects instead of applying them before it returns.
    let held: Vec<Effect> = {
        let mut app = fx.app();
        for event in outlet.events.drain() {
            if let UiEvent::Dapp(event) = event {
                app.on_dapp_event(event);
            }
        }
        let shown = app.evm.open_unanswered;
        assert!(shown.is_some(), "the open is queued");
        app.after_pending_open(AfterOpen::SetScreen(Screen::Sites));
        assert_eq!(app.evm.after_open.len(), 1, "kept for the open's answer");
        let held: Vec<Effect> = app.outbox.drain(..).collect();
        assert!(
            held.iter()
                .any(|effect| matches!(effect, Effect::Approval(ApprovalEffect::Open { .. }))),
            "the open is held"
        );
        held
    };
    {
        let app = fx.app.borrow();
        assert!(app.evm.open_unanswered.is_some(), "the open still waits");
        assert_eq!(app.evm.after_open.len(), 1, "and so does its step");
    }
    // Entry 2: a lock.
    {
        let mut app = fx.app();
        app.lock(LockReason::Manual);
        assert!(app.evm.after_open.is_empty(), "the lock dropped the step");
        assert_eq!(
            app.evm.open_unanswered, None,
            "no open waits after the lock"
        );
    }
    assert_eq!(fx.app.borrow().screen, Screen::Locked);
    assert_eq!(effect_names(&headless_host::take_effects()), "close#1");
    // Entry 3: the shell applies the held effects; the open is answered after the lock.
    {
        let mut app = fx.app();
        for effect in held {
            app.emit(effect);
        }
    }
    assert_eq!(
        effect_names(&headless_host::take_effects()),
        "open#1",
        "the held open was answered"
    );
    assert_eq!(dapp_answers(&outlet), "4001 User rejected the request.");
    let app = fx.app.borrow();
    assert!(app.outbox.is_empty());
    assert_eq!(app.evm.open_unanswered, None);
    assert!(app.evm.after_open.is_empty());
    assert_eq!(app.screen, Screen::Locked, "the kept step did not run");
    assert!(app.approval_win.is_none(), "no window was made");
    assert!(app.evm.approval.is_none());
}

/// The origins of the dispatcher's EVM grants, in its order.
fn granted_origins(fx: &Fixture) -> Vec<String> {
    let app = fx.app.borrow();
    app.browser.as_ref().map_or_else(Vec::new, |browser| {
        browser
            .core
            .grants()
            .iter()
            .map(|site| site.origin.as_str().to_owned())
            .collect()
    })
}

/// An unlock in one entry: the mode is `Unlocked` and the key worker's meta load answers with
/// `meta` (`KeyOutcome::Meta`, at the current epoch), as after the password.
fn unlock_with_meta(fx: &Fixture, meta: crate::meta::Meta) {
    use crate::app::AppMode;
    use crate::events::MetaLoaded;

    let mut app = fx.app();
    app.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    let epoch = app.lock_epoch;
    app.on_key_result(KeyResult {
        epoch,
        outcome: KeyOutcome::Meta(Ok(MetaLoaded {
            meta: Box::new(meta),
            mismatch: false,
            prefs_reset: false,
            has_mnemonic: true,
            zec_keys: Vec::new(),
            mnemonics: Vec::new(),
        })),
    });
}

/// The password of [`DiskWorker`]'s vault.
const DISK_PASSWORD: &str = "disk worker password";

/// 2026-11-23 (S4d F22, owner decision spec/15 §18 26 (가) "저장 후 잠금"): a key worker on its
/// own `abandon … about` vault in a folder below the fixture's temp folder (real files on
/// `store::WinKeyPlatform`, no card readers), unlocked, that runs the App's queued key jobs as
/// the worker thread does (`yw_engine::workers::key::step`, in queue order, until a `Shutdown`),
/// so a grant-write test ends with the meta save written to disk, not only queued.
struct DiskWorker {
    worker: yw_engine::workers::key::KeyWorker,
    signal: yw_engine::events::LockSignal,
}

impl DiskWorker {
    fn new(fx: &Fixture) -> Self {
        use yw_core::secret::Zeroizing;

        let dir = fx.dir().join("key-worker");
        std::fs::create_dir_all(&dir).unwrap();
        let mut worker = yw_engine::workers::key::KeyWorker::new(
            &dir,
            crate::store::WinKeyPlatform::deps_with_cards(Box::new(yw_engine::yubikey::NoReaders)),
        );
        // The public `abandon`×11 `about` test mnemonic, built at run time.
        let about = format!("{} about", ["abandon"; 11].join(" "));
        let bytes = |text: &str| Zeroizing::new(text.as_bytes().to_vec());
        worker.handle(KeyJob::Load);
        worker.handle(KeyJob::PreviewImport {
            password: Some(bytes(DISK_PASSWORD)),
            phrase: bytes(&about),
            passphrase: None,
        });
        assert!(matches!(
            worker.handle(KeyJob::CommitImport).first(),
            Some(KeyOutcome::Imported(Ok(())))
        ));
        Self {
            worker,
            signal: yw_engine::events::LockSignal::default(),
        }
    }

    /// Runs the jobs queued in the App's key queue; their outcomes as `name@epoch` (names only).
    fn run(&mut self, fx: &Fixture) -> Vec<String> {
        let queue = Arc::clone(&fx.app.borrow().key_queue);
        let results = std::cell::RefCell::new(Vec::new());
        while !queue.is_empty() {
            let Some(entry) = queue.pop() else {
                break;
            };
            let more = yw_engine::workers::key::step(
                &mut self.worker,
                &queue,
                entry,
                &|result: KeyResult| {
                    let name = match &result.outcome {
                        KeyOutcome::MetaSaved(Ok(())) => "MetaSaved".to_owned(),
                        KeyOutcome::MetaSaved(Err(_)) => "MetaSaveFailed".to_owned(),
                        KeyOutcome::Cancelled(name, _) => format!("Cancelled:{name}"),
                        KeyOutcome::LockDone => "LockDone".to_owned(),
                        KeyOutcome::Loaded { .. } | KeyOutcome::Status(_) => "Loaded".to_owned(),
                        _ => "other".to_owned(),
                    };
                    results
                        .borrow_mut()
                        .push(format!("{name}@{}", result.epoch));
                },
                &self.signal,
            );
            if !more {
                break;
            }
        }
        results.into_inner()
    }

    /// The meta document on disk: a meta load (after an unlock when the worker is locked).
    fn saved(&mut self) -> crate::meta::Meta {
        if let Some(KeyOutcome::Meta(Ok(loaded))) = self.worker.handle(KeyJob::LoadMeta).pop() {
            return *loaded.meta;
        }
        let _ = self.worker.handle(KeyJob::Unlock {
            password: yw_core::secret::Zeroizing::new(DISK_PASSWORD.as_bytes().to_vec()),
        });
        match self.worker.handle(KeyJob::LoadMeta).pop() {
            Some(KeyOutcome::Meta(Ok(loaded))) => *loaded.meta,
            _ => unreachable!("meta after the unlock"),
        }
    }
}

/// The App's queued key jobs as `name@epoch`, left queued (popped and pushed back in the same
/// order: `KeyQueue::push` puts a `Lock` at the front again, where it was).
fn queued(fx: &Fixture) -> Vec<String> {
    let queue = Arc::clone(&fx.app.borrow().key_queue);
    let mut entries = Vec::new();
    while !queue.is_empty() {
        let Some(entry) = queue.pop() else {
            break;
        };
        entries.push(entry);
    }
    let names = entries
        .iter()
        .map(|(epoch, job)| format!("{}@{epoch}", key_name(job)))
        .collect();
    for (epoch, job) in entries {
        queue.push(epoch, job);
    }
    names
}

/// The documents of the App's queued meta saves (`KeyJob::SaveMeta`) in queue order, left queued
/// as [`queued`] leaves them.
fn queued_saves(fx: &Fixture) -> Vec<crate::meta::Meta> {
    let queue = Arc::clone(&fx.app.borrow().key_queue);
    let mut entries = Vec::new();
    while !queue.is_empty() {
        let Some(entry) = queue.pop() else {
            break;
        };
        entries.push(entry);
    }
    let saves = entries
        .iter()
        .filter_map(|(_, job)| match job {
            KeyJob::SaveMeta { meta } => Some((**meta).clone()),
            _ => None,
        })
        .collect();
    for (epoch, job) in entries {
        queue.push(epoch, job);
    }
    saves
}

/// The EVM grant origins of a meta document.
fn saved_origins(meta: &crate::meta::Meta) -> Vec<String> {
    crate::browser::grants::sites_from_values(&meta.connected_sites)
        .iter()
        .map(|site| site.origin.as_str().to_owned())
        .collect()
}

/// 2026-11-21 (S4 F16, owner decision, spec/04 §5.3, spec/05 §4.5, spec/15 §18 item 16): a lock
/// keeps a dApp revoke. The deferred-answer shape of
/// [`a_lock_drops_the_steps_kept_for_an_open_of_an_earlier_entry`]: in entry 1 a request of
/// `app.example` asks for an approval open and, before its answer, the dispatcher reports the
/// revoke of `other.example` (`GrantChange::Revoked`), whose grant write
/// (`AfterOpen::WriteGrantsThenRefresh`) is kept for that answer; the shell holds the entry's
/// effects. Entry 2 locks: the lock writes the waiting revoke first (`flush_grant_writes`, before
/// F14 drops the kept step). Entry 3 applies the held effects (the stale open is answered). The
/// next unlock (`KeyOutcome::Meta` with the last meta document saved) leaves `other.example`
/// disconnected and `app.example` connected. Before F16 the lock dropped the write, the last
/// saved document still held `other.example`, and its grant came back at the unlock. No
/// production entry takes this path on Windows (every entry drains, so the answer comes in the
/// revoke's own entry); it is the shape of a shell that answers in a later entry (S4d E2).
/// (2026-11-23, S4d F22, spec/15 §18 26 (가)) The key queue now runs on a [`DiskWorker`]: the
/// lock's `KeyJob::Lock` (at the front) writes the waiting revoke's meta save first
/// (`MetaSaved` at the epoch before the lock, then `LockDone`), and the next unlock reads that
/// document back from disk. Before F22 the worker's `Lock` cancelled that save unless it had
/// taken it first, and the test only looked at the queued document.
/// Headless, no window; files only below the fixture's temp folder.
#[test]
#[expect(clippy::too_many_lines, reason = "one scenario in three entries")]
fn a_lock_keeps_a_revoke_whose_write_waits_for_an_open() {
    use yw_engine::effect::Effect;

    use crate::app::Screen;
    use crate::app_approval::AfterOpen;
    use crate::browser::{DappEvent, GrantChange};
    use yw_core::policy::BrowserOrigin;

    let fx = fixture("revoke-lock-deferred");
    let outlet = dapp(&fx, false, true);
    grant(&fx, OTHER, ACCOUNT_B);
    let mut disk = DiskWorker::new(&fx);
    // Both grants are in meta (the document a later unlock reads).
    fx.app().write_grants();
    let epoch = fx.app.borrow().lock_epoch;
    assert_eq!(disk.run(&fx), [format!("MetaSaved@{epoch}")]);
    assert_eq!(
        saved_origins(&disk.saved()).len(),
        2,
        "both sites are saved"
    );
    let core = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map(|browser| Arc::clone(&browser.core))
        .unwrap();
    personal_sign_frame_only(&fx, &outlet, &core);
    let _ = headless_host::take_effects();
    // Entry 1: the open is asked for; the revoke's write is kept for its answer; the shell holds
    // the entry's effects.
    let held: Vec<Effect> = {
        let mut app = fx.app();
        for event in outlet.events.drain() {
            if let UiEvent::Dapp(event) = event {
                app.on_dapp_event(event);
            }
        }
        assert!(app.evm.open_unanswered.is_some(), "the open is queued");
        let other = BrowserOrigin::parse(OTHER).unwrap();
        assert!(core.remove_grant(&other), "the dispatcher's revoke");
        app.on_dapp_event(DappEvent::GrantChanged {
            origin: other,
            change: GrantChange::Revoked,
        });
        assert!(
            app.evm
                .after_open
                .iter()
                .any(|(_, after)| matches!(after, AfterOpen::WriteGrantsThenRefresh)),
            "the revoke's write waits for the open's answer"
        );
        assert!(
            app.browser
                .as_ref()
                .is_some_and(|browser| browser.grant_write.revoke),
            "and is noted as waiting"
        );
        app.outbox.drain(..).collect()
    };
    assert!(
        !disk
            .run(&fx)
            .iter()
            .any(|name| name.starts_with("MetaSaved")),
        "nothing written yet"
    );
    assert_eq!(saved_origins(&disk.saved()).len(), 2, "nothing written yet");
    // Entry 2: a lock.
    {
        let mut app = fx.app();
        app.lock(LockReason::Manual);
        assert!(app.evm.after_open.is_empty(), "the lock dropped the step");
        assert!(
            app.browser
                .as_ref()
                .is_some_and(|browser| !browser.grant_write.revoke),
            "the lock wrote the revoke"
        );
    }
    assert_eq!(fx.app.borrow().screen, Screen::Locked);
    // The worker's `Lock` (at the front) writes the revoke's save first, then wipes; the
    // lock's `Load` follows.
    let lock_epoch = fx.app.borrow().lock_epoch;
    assert_eq!(lock_epoch, epoch + 1, "one lock");
    assert_eq!(
        queued(&fx),
        [
            format!("Lock@{lock_epoch}"),
            format!("SaveMeta@{epoch}"),
            format!("Load@{lock_epoch}")
        ]
    );
    assert_eq!(
        disk.run(&fx),
        [
            format!("MetaSaved@{epoch}"),
            format!("LockDone@{lock_epoch}"),
            format!("Loaded@{lock_epoch}")
        ],
        "the meta save is written before the lock"
    );
    let saved = disk.saved();
    assert_eq!(
        saved_origins(&saved),
        vec!["https://app.example".to_owned()],
        "the revoke is on disk"
    );
    // Entry 3: the shell applies the held effects; the stale open is answered after the lock.
    {
        let mut app = fx.app();
        for effect in held {
            app.emit(effect);
        }
    }
    assert_eq!(dapp_answers(&outlet), "4001 User rejected the request.");
    assert!(granted_origins(&fx).is_empty(), "locked: no grants");
    // The next unlock reads the last saved document.
    unlock_with_meta(&fx, saved);
    assert_eq!(
        granted_origins(&fx),
        vec!["https://app.example".to_owned()],
        "the revoked site stays disconnected after the unlock"
    );
    let app = fx.app.borrow();
    assert!(app.evm.after_open.is_empty());
    assert!(app.approval_win.is_none(), "no window was made");
}

/// Grants `origin` the Solana account (`sol`) or a Bitcoin payment address in the dispatcher.
fn chain_grant(
    core: &crate::browser::BrowserCore,
    origin: &yw_core::policy::BrowserOrigin,
    sol: bool,
) -> bool {
    use yw_core::btc::{BtcNetwork, BtcPubKey, ScriptType};
    use yw_core::policy::{BtcGrant, BtcGrantAddress, BtcPurpose, SolGrant};

    if sol {
        return core.upsert_sol_grant(SolGrant {
            origin: origin.clone(),
            public: yw_core::codec::base58::base58_decode_32(SOL_KEY).unwrap(),
            granted_at_unix_ms: 1,
        });
    }
    // BIP84 test vector address (public test mnemonic), as in the chain-sites tests.
    core.upsert_btc_grant(BtcGrant {
        origin: origin.clone(),
        network: BtcNetwork::Mainnet,
        addresses: vec![BtcGrantAddress {
            purpose: BtcPurpose::Payment,
            address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu".to_owned(),
            pubkey: BtcPubKey::Compressed([2; 33]),
            script_type: ScriptType::P2wpkh,
        }],
        granted_at_unix_ms: 1,
    })
}

/// How many Solana (`sol`) or Bitcoin sites the meta document holds.
fn saved_chain_sites(meta: &crate::meta::Meta, sol: bool) -> usize {
    if sol {
        meta.chain_sites.sol.len()
    } else {
        meta.chain_sites.btc.len()
    }
}

/// 2026-11-21 (S4 F16 review, spec/05 §4.5, spec/15 §18 item 16): the Solana and Bitcoin revokes
/// (`GrantChange::SolRevoked`, `GrantChange::BtcRevoked`, the dApp's `sol_disconnect` and
/// `btc_disconnect`) are noted as waiting writes too, and a lock before the open's answer writes
/// them. The deferred-answer shape of [`a_lock_keeps_a_revoke_whose_write_waits_for_an_open`],
/// one fixture per family, checked on the last saved meta document's `chain_sites.sol`/`btc`
/// (the review's mutation that noted `GrantChange::Revoked` only left the yw-app lib green).
/// (2026-11-23, S4d F22 review, spec/15 §18 26 (가)) The key queue runs on a [`DiskWorker`] too:
/// the queued revoke's document holds no site of that family, and the lock's `KeyJob::Lock`
/// writes it first (`MetaSaved` at the epoch before the lock, then `LockDone`). The document is
/// not read back from disk: the meta load prunes grants that name accounts the worker's wallet
/// does not hold (spec/05 §4.1), and the fixture's Solana key and Bitcoin address are not its
/// accounts. Before, this test only looked at the queued document.
/// Headless, no window; files only below each fixture's temp folder.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one scenario in three entries, per family"
)]
fn a_lock_keeps_a_solana_or_bitcoin_revoke_whose_write_waits_for_an_open() {
    use yw_core::policy::BrowserOrigin;
    use yw_engine::effect::Effect;

    use crate::app_approval::AfterOpen;
    use crate::browser::{DappEvent, GrantChange};

    for (tag, change) in [
        ("revoke-lock-deferred-sol", GrantChange::SolRevoked),
        ("revoke-lock-deferred-btc", GrantChange::BtcRevoked),
    ] {
        let sol = matches!(change, GrantChange::SolRevoked);
        let sites = |meta: &crate::meta::Meta| saved_chain_sites(meta, sol);
        let fx = fixture(tag);
        let outlet = dapp(&fx, false, true);
        let core = Arc::clone(&fx.app.borrow().browser.as_ref().unwrap().core);
        let other = BrowserOrigin::parse(OTHER).unwrap();
        assert!(chain_grant(&core, &other, sol), "{tag}: granted");
        let mut disk = DiskWorker::new(&fx);
        fx.app().write_grants();
        let epoch = fx.app.borrow().lock_epoch;
        assert_eq!(
            queued_saves(&fx).iter().map(sites).collect::<Vec<_>>(),
            [1],
            "{tag}: the site is saved"
        );
        assert_eq!(disk.run(&fx), [format!("MetaSaved@{epoch}")], "{tag}");
        personal_sign_frame_only(&fx, &outlet, &core);
        let _ = headless_host::take_effects();
        // Entry 1: the open is asked for; the revoke's write is kept for its answer.
        let held: Vec<Effect> = {
            let mut app = fx.app();
            for event in outlet.events.drain() {
                if let UiEvent::Dapp(event) = event {
                    app.on_dapp_event(event);
                }
            }
            assert!(
                app.evm.open_unanswered.is_some(),
                "{tag}: the open is queued"
            );
            let removed = if sol {
                core.remove_sol_grant(&other)
            } else {
                core.remove_btc_grant(&other)
            };
            assert!(removed, "{tag}: the dispatcher's revoke");
            app.on_dapp_event(DappEvent::GrantChanged {
                origin: other.clone(),
                change,
            });
            assert!(
                app.evm
                    .after_open
                    .iter()
                    .any(|(_, after)| matches!(after, AfterOpen::WriteGrantsThenRefresh)),
                "{tag}: the revoke's write waits for the open's answer"
            );
            assert!(
                app.browser
                    .as_ref()
                    .is_some_and(|browser| browser.grant_write.revoke),
                "{tag}: and is noted as waiting"
            );
            app.outbox.drain(..).collect()
        };
        assert!(queued_saves(&fx).is_empty(), "{tag}: nothing written yet");
        assert!(
            !disk
                .run(&fx)
                .iter()
                .any(|name| name.starts_with("MetaSaved")),
            "{tag}: nothing written yet"
        );
        // Entry 2: a lock writes the waiting revoke before it drops the kept step.
        {
            let mut app = fx.app();
            app.lock(LockReason::Manual);
            assert!(
                app.evm.after_open.is_empty(),
                "{tag}: the lock dropped the step"
            );
            assert!(
                app.browser
                    .as_ref()
                    .is_some_and(|browser| !browser.grant_write.revoke),
                "{tag}: the lock took the noted write"
            );
        }
        // The worker's `Lock` (at the front) writes the revoke's save first, then wipes; the
        // lock's `Load` follows.
        let lock_epoch = fx.app.borrow().lock_epoch;
        assert_eq!(lock_epoch, epoch + 1, "{tag}: one lock");
        assert_eq!(
            queued(&fx),
            [
                format!("Lock@{lock_epoch}"),
                format!("SaveMeta@{epoch}"),
                format!("Load@{lock_epoch}")
            ],
            "{tag}"
        );
        assert_eq!(
            queued_saves(&fx).iter().map(sites).collect::<Vec<_>>(),
            [0],
            "{tag}: the lock saved the revoke"
        );
        assert_eq!(
            disk.run(&fx),
            [
                format!("MetaSaved@{epoch}"),
                format!("LockDone@{lock_epoch}"),
                format!("Loaded@{lock_epoch}")
            ],
            "{tag}: the meta save is written before the lock"
        );
        // Entry 3: the shell applies the held effects; the stale open is answered.
        {
            let mut app = fx.app();
            for effect in held {
                app.emit(effect);
            }
        }
        assert_eq!(dapp_answers(&outlet), "4001 User rejected the request.");
        let app = fx.app.borrow();
        assert!(app.evm.after_open.is_empty());
        assert!(app.approval_win.is_none(), "{tag}: no window was made");
    }
}

/// The chain the meta document's EVM grant of `site` names, if it has one.
fn saved_chain(meta: &crate::meta::Meta, site: &str) -> Option<u64> {
    crate::browser::grants::sites_from_values(&meta.connected_sites)
        .iter()
        .find(|saved| saved.origin.as_str() == site)
        .map(|saved| saved.chain_id)
}

/// 2026-11-22 (S4d F21, owner decision, spec/04 §1.5, §5.3, spec/05 §4.5, spec/15 §18 21): the
/// shutdown writes a chain switch still coalesced inside `GRANT_WRITE_INTERVAL_MS` before it sets
/// `AppMode::ShuttingDown` (`Wallet::shutdown_begin` → `flush_grant_writes`, while meta is loaded).
/// A grant write was just made, so the dispatcher's switch of `app.example` to Ethereum is only
/// noted (`GrantWrite::dirty`); the shutdown then queues one meta save that holds the switch, at
/// the epoch before the lock. Before F21 the mode came first, the flush wrote nothing and the
/// switch was lost at exit. The queue is `[Lock, SaveMeta, Shutdown]`: the shutdown's
/// `KeyJob::Lock` went to the front, before that save. (2026-11-23, S4d F22, owner decision
/// spec/15 §18 26 (가) "저장 후 잠금") The queue then runs on a [`DiskWorker`]: the `Lock` writes
/// the save first (`MetaSaved` at the epoch before the lock, then `LockDone`), and the document on
/// disk holds the switch. From F21 until F22 the test pinned the race instead: the worker's
/// `Lock` would cancel that save (`KeyQueue::cancel_pending`) unless it had taken it first — the
/// lock's own flush was the same. Headless, no window; files only below the fixture's temp
/// folder.
#[test]
fn a_shutdown_writes_a_coalesced_chain_switch_first() {
    use yw_core::evm::address::parse_address;
    use yw_core::evm::chain::{ETHEREUM_MAINNET, SEPOLIA};
    use yw_core::policy::ConnectedSite;

    use crate::app::AppMode;
    use crate::browser::{DappEvent, GrantChange};

    let fx = fixture("shutdown-chain-switch");
    let _outlet = dapp(&fx, false, true);
    let mut disk = DiskWorker::new(&fx);
    // A grant write now: the switch below falls inside the coalescing interval.
    fx.app().write_grants();
    let before = fx.app.borrow().lock_epoch;
    assert_eq!(disk.run(&fx), [format!("MetaSaved@{before}")]);
    assert_eq!(
        saved_chain(&disk.saved(), "https://app.example"),
        Some(SEPOLIA),
        "the grant is saved on Sepolia"
    );
    let core = Arc::clone(&fx.app.borrow().browser.as_ref().unwrap().core);
    {
        let mut app = fx.app();
        assert!(matches!(app.mode, AppMode::Unlocked { .. }));
        // The dispatcher's chain switch (`wallet_switchEthereumChain`, answered from memory).
        core.upsert_grant(
            ConnectedSite::new(
                origin(),
                vec![parse_address(ACCOUNT_A).unwrap()],
                ETHEREUM_MAINNET,
                1,
            )
            .unwrap(),
        );
        app.on_dapp_event(DappEvent::GrantChanged {
            origin: origin(),
            change: GrantChange::Chain(ETHEREUM_MAINNET),
        });
        assert!(
            app.browser
                .as_ref()
                .is_some_and(|browser| browser.grant_write.dirty),
            "the switch waits for the interval"
        );
    }
    assert!(
        !disk
            .run(&fx)
            .iter()
            .any(|name| name.starts_with("MetaSaved")),
        "coalesced: nothing written yet"
    );
    {
        let _ack = LockAck::start(&fx);
        fx.app().shutdown();
    }
    let lock_epoch = {
        let app = fx.app.borrow();
        assert_eq!(app.mode, AppMode::ShuttingDown);
        assert!(
            app.browser
                .as_ref()
                .is_some_and(|browser| !browser.grant_write.pending()),
            "the shutdown took the waiting write"
        );
        app.lock_epoch
    };
    assert_eq!(lock_epoch, before + 1, "one lock");
    // The lock is first in the queue, then the shutdown's one meta save (queued before the
    // lock), then `Shutdown`.
    assert_eq!(
        queued(&fx),
        [
            format!("Lock@{lock_epoch}"),
            format!("SaveMeta@{before}"),
            format!("Shutdown@{lock_epoch}")
        ]
    );
    // The worker's `Lock` writes that save before its wipe; `Shutdown` ends the run.
    assert_eq!(
        disk.run(&fx),
        [
            format!("MetaSaved@{before}"),
            format!("LockDone@{lock_epoch}")
        ],
        "the meta save is written before the lock"
    );
    assert_eq!(
        saved_chain(&disk.saved(), "https://app.example"),
        Some(ETHEREUM_MAINNET),
        "the switch is on disk"
    );
}

/// 2026-11-22 (S4d F21, owner decision, spec/04 §1.5, §5.3, spec/05 §4.5, spec/15 §18 21): a
/// shutdown keeps a dApp revoke whose write waits for an approval open's answer. The shutdown
/// shape of [`a_lock_keeps_a_revoke_whose_write_waits_for_an_open`]: in entry 1 a request of
/// `app.example` asks for an approval open and, before its answer, the dispatcher reports the
/// revoke of `other.example`, whose grant write (`AfterOpen::WriteGrantsThenRefresh`) is kept for
/// that answer; the shell holds the entry's effects. Entry 2 shuts down: `shutdown_begin` writes
/// the waiting revoke before `AppMode::ShuttingDown`, so the last saved meta document holds
/// `app.example` only; the queued request is answered 4900 and the lock drops the kept step.
/// Entry 3 applies the held effects (the stale open makes no window). Before F21 the shutdown set
/// the mode first, its lock's flush wrote nothing and dropped the step, so no meta was saved and
/// the revoked grant came back at the next start. No production entry takes this path on Windows
/// (every entry drains, so the answer comes in the revoke's own entry); it is the shape of a
/// shell that answers in a later entry (S4d E2). (2026-11-23, S4d F22, owner decision spec/15
/// §18 26 (가) "저장 후 잠금") The key queue runs on a [`DiskWorker`]: the shutdown's
/// `KeyJob::Lock` writes the save first, and the document on disk lacks the revoked site. From
/// F21 until F22 the save's survival of that `Lock` was the open §18 26 and the test looked only
/// at the queued document. Headless, no window; files only below the fixture's temp folder.
#[test]
fn a_shutdown_keeps_a_revoke_whose_write_waits_for_an_open() {
    use yw_core::policy::BrowserOrigin;
    use yw_engine::effect::Effect;

    use crate::app::AppMode;
    use crate::app_approval::AfterOpen;
    use crate::browser::{DappEvent, GrantChange};

    let fx = fixture("revoke-shutdown-deferred");
    let outlet = dapp(&fx, false, true);
    grant(&fx, OTHER, ACCOUNT_B);
    let mut disk = DiskWorker::new(&fx);
    fx.app().write_grants();
    let before = fx.app.borrow().lock_epoch;
    assert_eq!(disk.run(&fx), [format!("MetaSaved@{before}")]);
    assert_eq!(
        saved_origins(&disk.saved()).len(),
        2,
        "both sites are saved"
    );
    let core = Arc::clone(&fx.app.borrow().browser.as_ref().unwrap().core);
    personal_sign_frame_only(&fx, &outlet, &core);
    let _ = headless_host::take_effects();
    // Entry 1: the open is asked for; the revoke's write is kept for its answer; the shell holds
    // the entry's effects.
    let held: Vec<Effect> = {
        let mut app = fx.app();
        for event in outlet.events.drain() {
            if let UiEvent::Dapp(event) = event {
                app.on_dapp_event(event);
            }
        }
        assert!(app.evm.open_unanswered.is_some(), "the open is queued");
        let other = BrowserOrigin::parse(OTHER).unwrap();
        assert!(core.remove_grant(&other), "the dispatcher's revoke");
        app.on_dapp_event(DappEvent::GrantChanged {
            origin: other,
            change: GrantChange::Revoked,
        });
        assert!(
            app.evm
                .after_open
                .iter()
                .any(|(_, after)| matches!(after, AfterOpen::WriteGrantsThenRefresh)),
            "the revoke's write waits for the open's answer"
        );
        assert!(
            app.browser
                .as_ref()
                .is_some_and(|browser| browser.grant_write.revoke),
            "and is noted as waiting"
        );
        app.outbox.drain(..).collect()
    };
    assert!(
        !disk
            .run(&fx)
            .iter()
            .any(|name| name.starts_with("MetaSaved")),
        "nothing written yet"
    );
    // Entry 2: the shutdown.
    {
        let _ack = LockAck::start(&fx);
        let mut app = fx.app();
        app.shutdown();
        assert_eq!(app.mode, AppMode::ShuttingDown);
        assert!(app.evm.after_open.is_empty(), "the lock dropped the step");
        assert!(
            app.browser
                .as_ref()
                .is_some_and(|browser| !browser.grant_write.revoke),
            "the shutdown wrote the revoke"
        );
    }
    let lock_epoch = fx.app.borrow().lock_epoch;
    assert_eq!(lock_epoch, before + 1, "one lock");
    // The worker's `Lock` (at the front) writes the shutdown's meta save before its wipe.
    assert_eq!(
        disk.run(&fx),
        [
            format!("MetaSaved@{before}"),
            format!("LockDone@{lock_epoch}")
        ],
        "the meta save is written before the lock"
    );
    assert_eq!(
        saved_origins(&disk.saved()),
        vec!["https://app.example".to_owned()],
        "the revoked site is not in the document on disk"
    );
    assert_eq!(dapp_answers(&outlet), "4900 Wallet connection closed.");
    // Entry 3: the shell applies the held effects; the stale open is answered after the shutdown.
    {
        let mut app = fx.app();
        for effect in held {
            app.emit(effect);
        }
    }
    let app = fx.app.borrow();
    assert!(app.evm.after_open.is_empty());
    assert!(app.approval_win.is_none(), "no window was made");
}

/// The store state of request `id` (shown before a revoke or cancel), without the windowed
/// fact's window count.
fn store_fact(fx: &Fixture, id: Option<ApprovalId>) -> String {
    let state = id
        .and_then(|id| fx.app.borrow().evm.store.state(id))
        .map_or_else(|| "-".to_owned(), |state| format!("{state:?}"));
    format!("store of the request shown before={state}")
}

/// Two sites, request 1 shown and armed, requests 2 and 3 waiting (the lifecycle `two_sites`).
fn two_sites(fx: &Fixture, h: &mut Run<'_>, outlet: &Outlet) {
    grant(fx, OTHER, ACCOUNT_B);
    personal_sign(fx, outlet, 1, 600_000);
    personal_sign_from(fx, outlet, 2, OTHER, 18, ACCOUNT_B);
    personal_sign(fx, outlet, 3, 600_000);
    h.armed(0);
    h.snap("shown-2-waiting");
}

/// A revoke of the shown request's site, account or chain while two requests wait.
fn revoke(name: &'static str, step: &str, act: fn(&mut crate::app::App)) -> Vec<String> {
    let fx = fixture(name);
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new(name, &fx, Some(&outlet));
    two_sites(&fx, &mut h, &outlet);
    let shown = shown_id(&fx);
    act(&mut fx.app());
    h.snap(step);
    h.fact("first", &store_fact(&fx, shown));
    h.lines
}

fn cancel_while_shown() -> Vec<String> {
    let fx = fixture("cancel");
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new("cancel_while_shown", &fx, Some(&outlet));
    two_sites(&fx, &mut h, &outlet);
    let first = shown_id(&fx);
    cancel_request(&fx, &outlet, 1, 10);
    h.snap("page-cancel");
    h.fact("first", &store_fact(&fx, first));
    let second = shown_id(&fx);
    let core = fx
        .app
        .borrow()
        .browser
        .as_ref()
        .map(|browser| Arc::clone(&browser.core))
        .unwrap();
    core.close_connection(outlet.conn);
    // The dispatcher cancels a closed connection's requests in its hash map's order, which
    // differs between runs (2026-11-20, S4 B7: found by this module's `effects` column; the
    // windowed line is the same for either order). The App gets them here in request order
    // (`requestId` bytes), so the effects are stable: request 2 (shown) ends, request 3 opens
    // and ends. This sort stands in for the dispatcher's order until the owner decides whether
    // `close_connection` should cancel in a stable order (2026-11-20, S4 B7 review: spec/15 §18
    // open question 10). In production, when the shown request is cancelled first, the next
    // queued request's approval window opens and is closed at once.
    let mut events: Vec<UiEvent> = outlet.events.drain();
    events.sort_by_key(|event| match event {
        UiEvent::Dapp(crate::browser::DappEvent::Cancel(key)) => (0, key.request.0),
        _ => (1, [0; 16]),
    });
    for event in events {
        if let UiEvent::Dapp(event) = event {
            fx.app().on_dapp_event(event);
        }
    }
    h.snap("connection-closed");
    h.fact("second", &store_fact(&fx, second));
    h.lines
}

fn grant_evm_message() -> Vec<String> {
    let fx = fixture("grant-message");
    let outlet = dapp(&fx, false, true);
    install_events(&fx, Some(&outlet));
    let mut h = Run::new("grant_evm_message", &fx, Some(&outlet));
    personal_sign(&fx, &outlet, 1, 600_000);
    h.approve_by_risk(0);
    h.snap("approved");
    let ticket = h.last_ticket();
    h.fact("signer", &waiter_fact(&fx, ticket, ACCOUNT_A));
    if let Some(ticket) = ticket {
        h.deliver_key(KeyOutcome::SignedMessage(MessageSigned {
            ticket,
            result: Ok([1; 65]),
        }));
    }
    h.snap("signed-grant-holds");
    h.at(10_000);
    personal_sign(&fx, &outlet, 2, 600_000);
    h.approve_by_risk(10_000);
    h.snap("approved-2");
    let ticket = h.last_ticket();
    fx.app().disconnect_site(&origin());
    h.snap("disconnected");
    if let Some(ticket) = ticket {
        h.deliver_key(KeyOutcome::SignedMessage(MessageSigned {
            ticket,
            result: Ok([1; 65]),
        }));
    }
    h.snap("signed-grant-gone");
    h.fact("waiters", &format!("sign waiters={}", waiters(&fx)));
    h.lines
}

/// The lifecycle `site_send`: request `n` prepared from `S2`.
fn prepared_send(fx: &Fixture, h: &mut Run<'_>, outlet: &Outlet, n: u8) {
    send_request(fx, outlet, n);
    let job = h.take_prepare();
    fx.answer_prepare(&job, "S2");
    h.snap("ready");
}

fn grant_evm_tx() -> Vec<String> {
    let fx = fixture("grant-tx");
    let outlet = dapp(&fx, false, true);
    install_events(&fx, Some(&outlet));
    let mut h = Run::new("grant_evm_tx", &fx, Some(&outlet));
    prepared_send(&fx, &mut h, &outlet, 1);
    h.approve_by_risk(0);
    h.snap("approved");
    let ticket = h.last_ticket();
    h.fact("signer", &waiter_fact(&fx, ticket, ACCOUNT_A));
    if let Some(ticket) = ticket {
        h.deliver_key(signed_evm(ticket, 0x11));
    }
    h.snap("signed");
    h.deliver(broadcast(&fx, 0x11));
    h.snap("broadcast-grant-holds");
    h.at(20_000);
    prepared_send(&fx, &mut h, &outlet, 2);
    h.approve_by_risk(20_000);
    if let Some(ticket) = h.last_ticket() {
        h.deliver_key(signed_evm(ticket, 0x22));
    }
    h.snap("signed-2");
    fx.app().disconnect_site(&origin());
    h.deliver(broadcast(&fx, 0x22));
    h.snap("broadcast-grant-gone");
    grant(&fx, "https://app.example", ACCOUNT_A);
    for (n, failure, step) in [
        (
            3_u8,
            SignFailure::JournalWrite(yw_core::error::VaultError::Storage(
                yw_core::error::StorageError::Io(5),
            )),
            "journal-write-failed",
        ),
        (4, SignFailure::JournalFull, "journal-full"),
    ] {
        h.at(20_000 * u64::from(n));
        prepared_send(&fx, &mut h, &outlet, n);
        h.approve_by_risk(20_000 * u64::from(n));
        if let Some(ticket) = h.last_ticket() {
            h.deliver_key(KeyOutcome::SignedEvm(EvmSigned {
                ticket,
                result: Err(failure),
            }));
        }
        h.snap(step);
    }
    h.fact("waiters", &format!("sign waiters={}", waiters(&fx)));
    h.lines
}

fn journal_evm_app_send() -> Vec<String> {
    let fx = fixture("journal-evm");
    install_events(&fx, None);
    let mut h = Run::new("journal_evm_app_send", &fx, None);
    for (round, result, step) in [
        (0_u64, None, "signed"),
        (
            1,
            Some(SignFailure::JournalWrite(
                yw_core::error::VaultError::Storage(yw_core::error::StorageError::Io(5)),
            )),
            "journal-write-failed",
        ),
        (2, Some(SignFailure::JournalFull), "journal-full"),
    ] {
        h.at(round * 20_000);
        h.app_send("S2");
        h.approve_by_risk(round * 20_000);
        if let Some(ticket) = h.last_ticket() {
            let outcome = match result {
                None => signed_evm(ticket, 0x33),
                Some(failure) => KeyOutcome::SignedEvm(EvmSigned {
                    ticket,
                    result: Err(failure),
                }),
            };
            h.deliver_key(outcome);
        }
        h.snap(step);
    }
    h.lines
}

fn grant_sol_message() -> Vec<String> {
    let fx = fixture("grant-sol");
    let outlet = dapp(&fx, true, true);
    install_events(&fx, Some(&outlet));
    let mut h = Run::new("grant_sol_message", &fx, Some(&outlet));
    let params = format!(r#"[{{"publicKey":"{SOL_KEY}","message":"50726f7665206974"}}]"#);
    let signed = |ticket| {
        KeyOutcome::SignedChainMessage(ChainMessageSigned {
            ticket,
            result: Ok(ChainSignature::Sol([2; 64])),
        })
    };
    request(
        &fx,
        &outlet,
        1,
        "sol_signMessage",
        &params,
        "signing",
        600_000,
    );
    h.approve_by_risk(0);
    h.snap("approved");
    if let Some(ticket) = h.last_ticket() {
        h.deliver_key(signed(ticket));
    }
    h.snap("signed-grant-holds");
    h.at(10_000);
    request(
        &fx,
        &outlet,
        2,
        "sol_signMessage",
        &params,
        "signing",
        600_000,
    );
    h.approve_by_risk(10_000);
    let ticket = h.last_ticket();
    fx.app()
        .disconnect_chain_site(&origin(), yw_core::policy::Family::Solana);
    h.snap("disconnected");
    if let Some(ticket) = ticket {
        h.deliver_key(signed(ticket));
    }
    h.snap("signed-grant-gone");
    h.lines
}

/// The lifecycle `sol_dapp_request`: request `n` (`method`) with its preview answered.
fn sol_dapp_request(fx: &Fixture, h: &mut Run<'_>, outlet: &Outlet, n: u8, method: &str) {
    request(
        fx,
        outlet,
        n,
        method,
        &format!(
            r#"[{{"publicKey":"{SOL_KEY}","transaction":"{}"}}]"#,
            yw_core::hex::encode(&sol_tx(n))
        ),
        "signing",
        600_000,
    );
    h.snap("open");
    let preview = h.rpc.iter().find_map(|job| match job {
        RpcJob::SolDappPreview(job) => Some(job.job),
        _ => None,
    });
    h.rpc.clear();
    if let Some(job) = preview {
        let item = yw_core::sol::dapp::SolTxItemFacts {
            tables: Ok((0, Vec::new())),
            pre: Vec::new(),
            post: None,
            sim: yw_core::sol::display::SimSummary::NoResult,
            sim_replaced_blockhash: false,
            rpc_fee: Some(5_000),
            blockhash_valid: Some(true),
        };
        h.deliver(UiEvent::Rpc(RpcEvent::SolDappPreviewed(Box::new((
            job,
            Ok(crate::sol::flow::DappPreview {
                items: vec![item],
                mints: Vec::new(),
                unread_mints: Vec::new(),
            }),
        )))));
    }
    h.snap("ready");
}

fn grant_sol_dapp_sign() -> Vec<String> {
    let fx = fixture("grant-sol-dapp");
    let outlet = dapp(&fx, true, true);
    devnet(&fx);
    install_events(&fx, Some(&outlet));
    let mut h = Run::new("grant_sol_dapp_sign", &fx, Some(&outlet));
    for (n, revoke) in [(1_u8, false), (2, true)] {
        let t = u64::from(n - 1) * 10_000;
        h.at(t);
        sol_dapp_request(&fx, &mut h, &outlet, n, "sol_signTransaction");
        h.approve_by_risk(t);
        let ticket = h.last_ticket();
        if revoke {
            fx.app()
                .disconnect_chain_site(&origin(), yw_core::policy::Family::Solana);
            h.snap("disconnected");
        }
        if let Some(ticket) = ticket {
            h.deliver_key(KeyOutcome::SignedChainMessage(ChainMessageSigned {
                ticket,
                result: Ok(ChainSignature::SolTxs(vec![sol_tx(n)])),
            }));
        }
        h.snap(if revoke {
            "signed-grant-gone"
        } else {
            "signed-grant-holds"
        });
    }
    h.lines
}

fn journal_sol_dapp_send() -> Vec<String> {
    use crate::events::{SolDappSigned, SolDappSignedSummary, SolSignFailure};
    let fx = fixture("journal-sol-dapp");
    let outlet = dapp(&fx, true, true);
    devnet(&fx);
    install_events(&fx, Some(&outlet));
    if let Some(browser) = fx.app().browser.as_mut() {
        browser.unlocked = true;
    }
    let mut h = Run::new("journal_sol_dapp_send", &fx, Some(&outlet));
    for (n, journaled, revoke) in [(1_u8, true, false), (2, false, false), (3, true, true)] {
        let t = u64::from(n - 1) * 10_000;
        h.at(t);
        sol_dapp_request(&fx, &mut h, &outlet, n, "sol_signAndSendTransaction");
        h.approve_by_risk(t);
        h.pull();
        let presign = h.rpc.iter().find_map(|job| match job {
            RpcJob::SolDappPreSign { job, .. } => Some(*job),
            _ => None,
        });
        h.rpc.clear();
        if let Some(job) = presign {
            h.deliver(UiEvent::Rpc(RpcEvent::SolDappPreSigned {
                job,
                result: Ok((
                    1_150,
                    yw_core::sol::dapp::PreSignCheck {
                        blockhash: [7; 32],
                        loaded: None,
                    },
                )),
            }));
        }
        h.snap("pre-sign-checked");
        let tx_id = [0x80 + n; 64];
        let record = sol_record(0x80 + n, Some(n));
        let result = if journaled {
            Ok(SolDappSignedSummary {
                cluster: yw_core::sol::SolCluster::Devnet,
                public: sol_public(),
                tx_id,
                own_signature: tx_id,
                tx: record.tx.clone(),
                signed_at_ms: fx.clock.unix_at(fx.clock.peek()),
                last_valid_block_height: 1_150,
                min_context_slot: None,
                reused: false,
            })
        } else {
            Err(SolSignFailure::JournalWrite(
                yw_core::error::VaultError::Storage(yw_core::error::StorageError::Io(5)),
            ))
        };
        if let Some(ticket) = h.last_ticket() {
            let mut outcomes = vec![KeyOutcome::SignedSolDapp(SolDappSigned { ticket, result })];
            if journaled {
                outcomes.push(journal_with(&fx, record));
            }
            h.deliver_keys(outcomes);
        }
        h.snap(if journaled {
            "signed"
        } else {
            "journal-write-failed"
        });
        if !journaled {
            continue;
        }
        if revoke {
            fx.app()
                .disconnect_chain_site(&origin(), yw_core::policy::Family::Solana);
            h.snap("disconnected");
        }
        h.deliver(UiEvent::Rpc(RpcEvent::SolTracked(Box::new(
            crate::sol::flow::TrackResult {
                signature: tx_id,
                state: yw_core::sol::broadcast::LoopState::default(),
                outcome: Ok(yw_core::sol::broadcast::Outcome::Pending { notice: false }),
                genesis_ok: Some(true),
                sends: 1,
                generation: 0,
            },
        ))));
        h.snap("first-round");
    }
    h.lines
}

fn journal_sol_app_send() -> Vec<String> {
    use crate::events::{SolSignFailure, SolSignedSummary};
    let fx = fixture("journal-sol");
    let _outlet = dapp(&fx, true, false);
    devnet(&fx);
    install_events(&fx, None);
    let mut h = Run::new("journal_sol_app_send", &fx, None);
    for (round, signature, journaled) in [(0_u64, 0x66_u8, true), (1, 0x77, false)] {
        h.at(round * 20_000);
        enqueue_app_item(&fx, sol_transfer());
        h.snap("open");
        let preview = h.rpc.iter().find_map(|job| match job {
            RpcJob::SolPreview(job) => Some(job.clone()),
            _ => None,
        });
        h.rpc.clear();
        if let Some(job) = preview {
            h.deliver(sol_preview(&job));
        }
        h.snap("ready");
        h.approve_by_risk(round * 20_000);
        h.pull();
        let presign = h.rpc.iter().find_map(|job| match job {
            RpcJob::SolPreSign { job, .. } => Some(*job),
            _ => None,
        });
        h.rpc.clear();
        if let Some(job) = presign {
            h.deliver(UiEvent::Rpc(RpcEvent::SolPreSigned {
                job,
                result: Ok(([9; 32], 1_000)),
            }));
        }
        h.snap("blockhash");
        let record = sol_record(signature, None);
        let outcomes = if journaled {
            vec![
                KeyOutcome::SignedSol(Ok(SolSignedSummary {
                    cluster: yw_core::sol::SolCluster::Devnet,
                    from: yw_core::sol::SolAddress::from_bytes(sol_public()),
                    signature: [signature; 64],
                    tx: record.tx.clone(),
                    signed_at_ms: fx.clock.unix_at(fx.clock.peek()),
                    last_valid_block_height: 1_000,
                })),
                journal_with(&fx, record),
            ]
        } else {
            vec![KeyOutcome::SignedSol(Err(SolSignFailure::JournalWrite(
                yw_core::error::VaultError::Storage(yw_core::error::StorageError::Io(5)),
            )))]
        };
        h.deliver_keys(outcomes);
        h.snap(if journaled {
            "signed"
        } else {
            "journal-write-failed"
        });
        h.main_tick();
        h.snap("next-main-tick");
    }
    h.lines
}

fn journal_zec() -> Vec<String> {
    use crate::workers::journal::zec::{ZecKeyOutcome, ZecSignedSummary};
    use yw_core::zec::ZecNetwork;
    let fx = fixture("journal-zec");
    install_events(&fx, None);
    {
        let mut app = fx.app();
        app.settings.zcash.network = ZecNetwork::Testnet;
        app.apikeys.set_rpc(
            crate::network::NetworkId::Zcash(ZecNetwork::Testnet),
            &yw_platform::http::HttpsUrl::parse("https://zec.example.test/").unwrap(),
        );
    }
    let mut h = Run::new("journal_zec", &fx, None);
    for (round, txid, committed) in [(0_u64, 0x44_u8, true), (1, 0x55, false)] {
        h.at(round * 20_000);
        enqueue_app_item(&fx, zec_item());
        h.snap("ready");
        h.approve_by_risk(round * 20_000);
        h.deliver_key(KeyOutcome::Zec(Box::new(ZecKeyOutcome::Signed(Ok(
            ZecSignedSummary {
                network: ZecNetwork::Testnet,
                raw: vec![0x05, 0x00],
                txid: [txid; 32],
            },
        )))));
        h.snap("signed");
        let outcome = if committed {
            ZecKeyOutcome::Journal {
                txid: [txid; 32],
                state: Some(yw_core::journal::zec::ZecTxState::Signed),
            }
        } else {
            ZecKeyOutcome::JournalFailed { txid: [txid; 32] }
        };
        h.deliver_key(KeyOutcome::Zec(Box::new(outcome)));
        h.snap(if committed {
            "disclose-committed"
        } else {
            "disclose-failed"
        });
    }
    h.lines
}

fn card_step_from_the_window() -> Vec<String> {
    let fx = fixture("card-step");
    let outlet = dapp(&fx, false, false);
    install_events(&fx, Some(&outlet));
    let dir = fx.dir().join("card");
    std::fs::create_dir_all(&dir).unwrap();
    let (wallet_dir, loaded) = card_wallet::meta(dir.clone());
    {
        let mut app = fx.app();
        app.meta = Some(*loaded.meta);
        app.card_after_meta();
        app.sync_browser();
    }
    let _ = std::fs::remove_dir_all(&wallet_dir);
    let _ = std::fs::remove_dir_all(&dir);
    grant(&fx, "https://app.example", ACCOUNT_B);
    let mut h = Run::new("card_step_from_the_window", &fx, Some(&outlet));
    let pin = || yw_core::secret::Zeroizing::new(b"135790".to_vec());
    personal_sign_from(&fx, &outlet, 1, "https://app.example", 17, ACCOUNT_B);
    h.approve_by_risk(0);
    h.snap("approved");
    h.fact("card", &card_fact(&fx));
    let ticket = fx
        .app
        .borrow()
        .card
        .step
        .as_ref()
        .and_then(|step| step.ticket);
    h.fact("signer", &waiter_fact(&fx, ticket, ACCOUNT_B));
    let id = fx.app.borrow().card_waiting_id();
    fx.app().disconnect_site(&origin());
    h.snap("disconnected-before-pin");
    h.fact("card", &card_fact(&fx));
    if let Some(id) = id {
        fx.app().card_submit(id, pin());
    }
    h.snap("pin-after-the-end");
    grant(&fx, "https://app.example", ACCOUNT_B);
    h.at(10_000);
    personal_sign_from(&fx, &outlet, 2, "https://app.example", 17, ACCOUNT_B);
    h.approve_by_risk(10_000);
    h.snap("approved-2");
    let id = fx.app.borrow().card_waiting_id();
    if let Some(id) = id {
        fx.app().card_submit(id, pin());
    }
    h.snap("pin");
    let ticket = h.last_ticket();
    fx.app().disconnect_site(&origin());
    h.snap("disconnected-past-pin");
    h.fact("card", &card_fact(&fx));
    if let Some(ticket) = ticket {
        h.deliver_key(KeyOutcome::SignedMessage(MessageSigned {
            ticket,
            result: Ok([1; 65]),
        }));
    }
    h.snap("signed-grant-gone");
    h.fact("card", &card_fact(&fx));
    h.lines
}

/// The five sites of the queue-limit scenarios, the first granted by `dapp`, the rest here.
fn five_sites(fx: &Fixture) -> [&'static str; 5] {
    let sites = [
        "https://app.example",
        "https://b.example",
        "https://c.example",
        "https://d.example",
        "https://e.example",
    ];
    for site in &sites[1..] {
        grant(fx, site, ACCOUNT_A);
    }
    sites
}

fn queue_limits() -> Vec<String> {
    let fx = fixture("queue-limits");
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new("queue_limits", &fx, Some(&outlet));
    let sites = five_sites(&fx);
    let mut n = 0_u8;
    let mut send = |fx: &Fixture, site: &str, tab: u8| {
        n += 1;
        personal_sign_from(fx, &outlet, n, site, tab, ACCOUNT_A);
    };
    for _ in 0..16 {
        send(&fx, sites[0], 17);
    }
    h.snap("16-of-one-site");
    send(&fx, sites[0], 17);
    h.snap("17th-of-one-site");
    for (index, site) in sites[1..4].iter().enumerate() {
        let tab = 18 + u8::try_from(index).unwrap();
        for _ in 0..16 {
            send(&fx, site, tab);
        }
    }
    h.snap("64-in-all");
    send(&fx, sites[4], 22);
    h.snap("65th-in-all");
    h.lines
}

fn queue_limit_at_the_app() -> Vec<String> {
    let fx = fixture("queue-limit-app");
    let outlet = dapp(&fx, false, true);
    let mut h = Run::new("queue_limit_at_the_app", &fx, Some(&outlet));
    let sites = five_sites(&fx);
    fx.enqueue_sepolia_send();
    h.snap("app-send-shown");
    let mut n = 0_u8;
    for (index, site) in sites[..4].iter().enumerate() {
        let tab = 17 + u8::try_from(index).unwrap();
        let count = if index == 3 { 15 } else { 16 };
        for _ in 0..count {
            n += 1;
            personal_sign_from(&fx, &outlet, n, site, tab, ACCOUNT_A);
        }
    }
    h.snap("63-site-requests");
    n += 1;
    personal_sign_from(&fx, &outlet, n, sites[4], 21, ACCOUNT_A);
    h.snap("64th-site-request");
    h.at(0);
    h.ev(InteractionEvent::Tick);
    h.at(1_500);
    h.key(VK_RETURN, false);
    h.snap("app-send-rejected");
    n += 1;
    personal_sign_from(&fx, &outlet, n, sites[4], 21, ACCOUNT_A);
    h.snap("64th-site-request-again");
    h.lines
}

fn rpc_import_on_temp_data() -> Vec<String> {
    use yw_engine::cmd::RpcImportPress;
    let fx = fixture("rpc-import");
    let file = fx.dir().join("rpc.json");
    let quicknode = format!("https://my-node.quiknode.pro/{QN_TOKEN}/");
    std::fs::write(
        &file,
        format!(
            concat!(
                r#"{{"eip155:1":"{quicknode}","solana:devnet":"https://sol.example.test/","#,
                r#""eip155:10":"http://plain.example.test/","unknown:1":"x"}}"#
            ),
            quicknode = quicknode
        ),
    )
    .unwrap();
    let _seam = RpcJsonSeam;
    crate::app_rpc_import::TEST_RPC_JSON.with(|path| *path.borrow_mut() = Some(file.clone()));
    let mut h = Run::new("rpc_import_on_temp_data", &fx, None);
    let key = |fx: &Fixture| -> &'static str {
        let app = fx.app.borrow();
        let lang = app.settings.language;
        let imported = crate::app_rpc_import::text::IMPORTED.fill(lang, ["1"]);
        match app.info.as_deref() {
            None => "-",
            Some(info) if info.starts_with(&imported) => "IMPORTED",
            Some(info) if info == crate::app_rpc_import::text::DELETED.get(lang) => "DELETED",
            Some(info) if info == crate::app_rpc_import::text::UNREADABLE.get(lang) => "UNREADABLE",
            Some(info) if info == crate::app_rpc_import::text::FORMAT.get(lang) => "FORMAT",
            Some(_) => "other",
        }
    };
    fx.app().on_rpc_import(RpcImportPress::Import);
    h.snap("import");
    let plan = fx.app.borrow().rpc_import.plan.as_ref().map_or_else(
        || "plan none".to_owned(),
        |plan| {
            format!(
                "plan entries={} rejected={} ignored={}",
                plan.entries.len(),
                plan.rejected.len(),
                plan.ignored
            )
        },
    );
    h.fact("plan", &plan);
    fx.app().on_rpc_import(RpcImportPress::Overwrite);
    h.snap("overwrite");
    let app = fx.app.borrow();
    let fact = format!(
        "info={} imported={} sealed file={} stored eth={} sol={} sepolia={} tests running={} waiting={} total={}",
        key(&fx),
        app.rpc_import.imported,
        fx.dir().join("apikeys.dpapi").exists(),
        app.apikeys
            .rpc_url(crate::network::NetworkId::Eip155(1))
            .is_some(),
        app.apikeys
            .rpc_url(crate::network::NetworkId::Solana(
                crate::network::SolCluster::Devnet
            ))
            .is_some(),
        app.apikeys
            .rpc_url(crate::network::NetworkId::Eip155(11_155_111))
            .is_some(),
        app.rpc_tests.running.is_some(),
        app.rpc_tests.waiting.len(),
        app.rpc_tests.total,
    );
    drop(app);
    h.fact("saved", &fact);
    fx.app().on_rpc_import(RpcImportPress::Delete);
    fx.app().on_rpc_import(RpcImportPress::DeleteConfirm);
    h.snap("delete");
    h.fact(
        "deleted",
        &format!("info={} file left={}", key(&fx), file.exists()),
    );
    h.lines
}

// ----- the scenario tables ---------------------------------------------------------------------

type Scenario = fn() -> Vec<String>;

/// Which windowed golden a scenario is cross-checked against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Windowed {
    Flow,
    Lifecycle,
}

impl Windowed {
    const fn golden(self) -> &'static str {
        match self {
            Self::Flow => FLOW_GOLDEN,
            Self::Lifecycle => LIFECYCLE_GOLDEN,
        }
    }
}

/// Every scenario run headless, in golden order (the windowed order, `flow.txt` first).
const SCENARIOS: [(&str, Scenario, Windowed); 67] = [
    ("reject_first", reject_first, Windowed::Flow),
    (
        "repeat_enter_on_reject",
        repeat_enter_on_reject,
        Windowed::Flow,
    ),
    (
        "posted_enter_on_approve",
        posted_enter_on_approve,
        Windowed::Flow,
    ),
    ("stray_key_unarmed", stray_key_unarmed, Windowed::Flow),
    (
        "reactivation_restarts_the_delay",
        reactivation_restarts_the_delay,
        Windowed::Flow,
    ),
    ("c1_message_one_job", c1_message_one_job, Windowed::Flow),
    (
        "c1_stale_sim_one_resim",
        c1_stale_sim_one_resim,
        Windowed::Flow,
    ),
    (
        "resim_fresh_59999",
        || resim_boundary(59_999, "resim_fresh_59999"),
        Windowed::Flow,
    ),
    (
        "resim_fresh_60000",
        || resim_boundary(60_000, "resim_fresh_60000"),
        Windowed::Flow,
    ),
    (
        "resim_stale_60001",
        || resim_boundary(60_001, "resim_stale_60001"),
        Windowed::Flow,
    ),
    (
        "resim_same_after_click",
        resim_same_after_click,
        Windowed::Flow,
    ),
    (
        "resim_changed_needs_a_new_click",
        resim_changed_needs_a_new_click,
        Windowed::Flow,
    ),
    (
        "resim_changed_old_digest",
        resim_changed_old_digest,
        Windowed::Flow,
    ),
    (
        "resim_no_result_and_failed",
        resim_no_result_and_failed,
        Windowed::Flow,
    ),
    (
        "stale_resim_result_is_dropped",
        stale_resim_result_is_dropped,
        Windowed::Flow,
    ),
    (
        "display_change_mid_hold",
        display_change_mid_hold,
        Windowed::Flow,
    ),
    ("high_risk_evm", high_risk_evm, Windowed::Flow),
    ("chain_btc", chain_btc, Windowed::Flow),
    ("chain_zec", chain_zec, Windowed::Flow),
    (
        "chain_hypercore",
        || chain_hypercore(false, "chain_hypercore"),
        Windowed::Flow,
    ),
    (
        "chain_hypercore_look_alike",
        || chain_hypercore(true, "chain_hypercore_look_alike"),
        Windowed::Flow,
    ),
    ("chain_sol_message", chain_sol_message, Windowed::Flow),
    (
        "consume_site_messages",
        consume_site_messages,
        Windowed::Flow,
    ),
    (
        "site_send_s3_approve",
        || site_send("S3", true, "site_send_s3_approve"),
        Windowed::Flow,
    ),
    (
        "site_send_s4_approve",
        || site_send("S4", true, "site_send_s4_approve"),
        Windowed::Flow,
    ),
    (
        "site_send_s3_reject",
        || site_send("S3", false, "site_send_s3_reject"),
        Windowed::Flow,
    ),
    (
        "consume_app009_branches",
        consume_app009_branches,
        Windowed::Flow,
    ),
    (
        "blocked_is_never_consumed",
        blocked_is_never_consumed,
        Windowed::Flow,
    ),
    (
        "expiry_window_tick",
        || expiry(false, "expiry_window_tick"),
        Windowed::Flow,
    ),
    (
        "expiry_main_tick",
        || expiry(true, "expiry_main_tick"),
        Windowed::Flow,
    ),
    (
        "l3_site_deadline_window_tick",
        || l3_site_deadline(false, "l3_site_deadline_window_tick"),
        Windowed::Flow,
    ),
    (
        "l3_site_deadline_main_tick",
        || l3_site_deadline(true, "l3_site_deadline_main_tick"),
        Windowed::Flow,
    ),
    ("ui001_and_wc_label", ui001_and_wc_label, Windowed::Flow),
    ("open_failure", open_failure, Windowed::Flow),
    (
        "issue_uses_one_instant",
        issue_uses_one_instant,
        Windowed::Flow,
    ),
    (
        "l1_close_with_a_second_request_queued",
        l1_close_with_a_second_request_queued,
        Windowed::Flow,
    ),
    (
        "l2_connect_chain_change_close_box",
        || l2_connect_chain_change("close-box", "l2_connect_chain_change_close_box"),
        Windowed::Flow,
    ),
    (
        "l2_connect_chain_change_main_tick",
        || l2_connect_chain_change("main-tick", "l2_connect_chain_change_main_tick"),
        Windowed::Flow,
    ),
    (
        "l2_connect_chain_change_enter_on_reject",
        || l2_connect_chain_change("enter-on-reject", "l2_connect_chain_change_enter_on_reject"),
        Windowed::Flow,
    ),
    (
        "l2_connect_chain_change_mouse_reject",
        || l2_connect_chain_change("mouse-reject", "l2_connect_chain_change_mouse_reject"),
        Windowed::Flow,
    ),
    (
        "l2_connect_chain_change_escape",
        || l2_connect_chain_change("escape", "l2_connect_chain_change_escape"),
        Windowed::Flow,
    ),
    (
        "l2_connect_chain_change_window_tick",
        || l2_connect_chain_change("window-tick", "l2_connect_chain_change_window_tick"),
        Windowed::Flow,
    ),
    (
        "l2_connect_chain_change_approve",
        || l2_connect_chain_change("approve", "l2_connect_chain_change_approve"),
        Windowed::Flow,
    ),
    (
        "lock_shortcut_while_shown",
        lock_shortcut_while_shown,
        Windowed::Lifecycle,
    ),
    (
        "lock_with_resimulation_in_flight",
        lock_with_resimulation_in_flight,
        Windowed::Lifecycle,
    ),
    (
        "lock_session_lock",
        || lock_by_message(&Msg::SessionLock, "lock_session_lock"),
        Windowed::Lifecycle,
    ),
    (
        "lock_session_disconnect",
        || lock_by_message(&Msg::SessionDisconnect, "lock_session_disconnect"),
        Windowed::Lifecycle,
    ),
    (
        "lock_suspend",
        || lock_by_message(&Msg::Suspend, "lock_suspend"),
        Windowed::Lifecycle,
    ),
    (
        "lock_end_session",
        || lock_by_message(&Msg::EndSession, "lock_end_session"),
        Windowed::Lifecycle,
    ),
    (
        "lock_idle_after_the_window",
        lock_idle_after_the_window,
        Windowed::Lifecycle,
    ),
    (
        "open_then_lock_same_entry",
        open_then_lock_same_entry,
        Windowed::Lifecycle,
    ),
    (
        "revoke_disconnect_while_shown",
        || {
            revoke("revoke_disconnect_while_shown", "disconnect", |app| {
                app.disconnect_site(&origin());
            })
        },
        Windowed::Lifecycle,
    ),
    (
        "revoke_account_removed_while_shown",
        || {
            revoke(
                "revoke_account_removed_while_shown",
                "account-removed",
                |app| {
                    app.account_removed_from_sites(
                        &yw_core::evm::address::parse_address(ACCOUNT_A).unwrap(),
                    );
                },
            )
        },
        Windowed::Lifecycle,
    ),
    (
        "revoke_chain_deleted_while_shown",
        || {
            revoke("revoke_chain_deleted_while_shown", "chain-deleted", |app| {
                app.chain_removed_from_sites(yw_core::evm::chain::SEPOLIA);
            })
        },
        Windowed::Lifecycle,
    ),
    (
        "cancel_while_shown",
        cancel_while_shown,
        Windowed::Lifecycle,
    ),
    ("grant_evm_message", grant_evm_message, Windowed::Lifecycle),
    ("grant_evm_tx", grant_evm_tx, Windowed::Lifecycle),
    (
        "journal_evm_app_send",
        journal_evm_app_send,
        Windowed::Lifecycle,
    ),
    ("grant_sol_message", grant_sol_message, Windowed::Lifecycle),
    (
        "grant_sol_dapp_sign",
        grant_sol_dapp_sign,
        Windowed::Lifecycle,
    ),
    (
        "journal_sol_dapp_send",
        journal_sol_dapp_send,
        Windowed::Lifecycle,
    ),
    (
        "journal_sol_app_send",
        journal_sol_app_send,
        Windowed::Lifecycle,
    ),
    ("journal_zec", journal_zec, Windowed::Lifecycle),
    (
        "card_step_from_the_window",
        card_step_from_the_window,
        Windowed::Lifecycle,
    ),
    ("queue_limits", queue_limits, Windowed::Lifecycle),
    (
        "queue_limit_at_the_app",
        queue_limit_at_the_app,
        Windowed::Lifecycle,
    ),
    (
        "rpc_import_on_temp_data",
        rpc_import_on_temp_data,
        Windowed::Lifecycle,
    ),
];

/// The windowed scenarios not run headless: each needs the shell's own trace (spec/09 §2.1).
/// They stay in gate step `winui` with their windowed goldens.
const LEFT_OUT: [(&str, &str); 9] = [
    (
        "l1_press_past_deadline_escape",
        "the steps of one A01 message after its OtherPress ended the request (the shell's \
         SameWindow guard), its reply, pressed button and Win32 side-effect trace",
    ),
    (
        "l1_press_past_deadline_enter",
        "the steps of one A01 message after its OtherPress ended the request (the shell's \
         SameWindow guard), its reply, pressed button and Win32 side-effect trace",
    ),
    (
        "l1_press_past_deadline_space",
        "the steps of one A01 message after its OtherPress ended the request (the shell's \
         SameWindow guard), its reply, pressed button and Win32 side-effect trace",
    ),
    (
        "l1_press_past_deadline_tab",
        "the steps of one A01 message after its OtherPress ended the request (the shell's \
         SameWindow guard), its reply, pressed button and Win32 side-effect trace",
    ),
    (
        "l1_press_past_deadline_mouse_reject",
        "the steps of one A01 message after its OtherPress ended the request (the shell's \
         SameWindow guard), its reply, pressed button and Win32 side-effect trace",
    ),
    (
        "connect_toggle_layout",
        "hit-tests the panel layout the shell paints and drops at a rebuild (A-13 on Windows)",
    ),
    (
        "stale_window_input_is_dropped",
        "messages through the ended window's own Forward (A-12: the id of the receiving HWND), \
         with their replies and trace",
    ),
    (
        "connect_toggle_stale_layout",
        "puts back a panel layout the shell drew from an older view and hit-tests it (A-13)",
    ),
    (
        "polling_while_hidden",
        "the main window's hidden state is a real window's (critique B-10; since S4 W3, \
         2026-11-21, the wallet's mirror follows that window through the shell's sync, and with \
         no window it is never hidden)",
    ),
];

// ----- the windowed lines without the shell -------------------------------------------------

/// Facts that are only the shell's (dropped from the windowed golden by the cross-check).
const SHELL_FACTS: [&str; 3] = ["close reply=", "down=", "approval windows="];

/// A windowed golden line without its shell part: a step line without `focus=`; a fact without
/// its `windows=` count (and the `approval` before it), or no line for a fact of the shell
/// alone. `None` for those.
fn without_shell(line: &str) -> Option<String> {
    let (head, rest) = line.split_once(" | ")?;
    if rest.starts_with("t=") {
        let columns: Vec<&str> = line
            .split(" | ")
            .filter(|column| !column.starts_with("focus="))
            .collect();
        return Some(columns.join(" | "));
    }
    if SHELL_FACTS.iter().any(|shell| rest.starts_with(shell)) {
        return None;
    }
    let mut words: Vec<&str> = rest.split(' ').collect();
    while let Some(at) = words.iter().position(|word| word.starts_with("windows=")) {
        words.remove(at);
        if at > 0 && words.get(at - 1) == Some(&"approval") {
            words.remove(at - 1);
        }
    }
    Some(format!("{head} | {}", words.join(" ")))
}

/// A headless line without its `effects` column.
fn without_effects(line: &str) -> &str {
    line.rfind(" | effects ").map_or(line, |at| &line[..at])
}

/// The lines of `name` in `golden` (in order).
fn lines_of(golden: &'static str, name: &str) -> Vec<&'static str> {
    let prefix = format!("{name} ");
    golden
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .collect()
}

/// The first line where `generated` and `committed` differ, as an assertion message.
fn first_difference(what: &str, generated: &[&str], committed: &[&str]) -> String {
    let at = generated
        .iter()
        .zip(committed)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| generated.len().min(committed.len()));
    format!(
        "{what}: line {} differs (generated {}, committed {}):\n  generated: {:?}\n  committed: \
         {:?}\nevery generated line:\n{}",
        at + 1,
        generated.len(),
        committed.len(),
        generated.get(at),
        committed.get(at),
        generated.join("\n")
    )
}

/// Runs scenario `name` headless once and checks it both ways: its lines against
/// `headless.txt`, and (the cross-check) its lines without `effects` against the windowed golden
/// lines of `name` without their shell part.
fn run(name: &str) {
    let (_, scenario, windowed) = SCENARIOS
        .iter()
        .find(|(known, ..)| *known == name)
        .expect("a scenario of the table");
    let lines = scenario();
    let generated: Vec<&str> = lines.iter().map(String::as_str).collect();
    let committed = lines_of(GOLDEN, name);
    assert!(
        generated == committed,
        "{}",
        first_difference(&format!("{name} (headless.txt)"), &generated, &committed)
    );
    let shell_free: Vec<&str> = generated.iter().map(|line| without_effects(line)).collect();
    let expected: Vec<String> = lines_of(windowed.golden(), name)
        .into_iter()
        .filter_map(without_shell)
        .collect();
    let expected: Vec<&str> = expected.iter().map(String::as_str).collect();
    assert!(!expected.is_empty(), "{name}: no windowed golden lines");
    assert!(
        shell_free == expected,
        "{}",
        first_difference(
            &format!("{name} (cross-check with the windowed golden)"),
            &shell_free,
            &expected
        )
    );
}

macro_rules! headless_tests {
    ($($test:ident => $name:literal),* $(,)?) => {
        $(
            #[test]
            fn $test() {
                run($name);
            }
        )*
    };
}

headless_tests! {
    headless_reject_first => "reject_first",
    headless_repeat_enter_on_reject => "repeat_enter_on_reject",
    headless_posted_enter_on_approve => "posted_enter_on_approve",
    headless_stray_key_unarmed => "stray_key_unarmed",
    headless_reactivation_restarts_the_delay => "reactivation_restarts_the_delay",
    headless_c1_message_one_job => "c1_message_one_job",
    headless_c1_stale_sim_one_resim => "c1_stale_sim_one_resim",
    headless_resim_fresh_59999 => "resim_fresh_59999",
    headless_resim_fresh_60000 => "resim_fresh_60000",
    headless_resim_stale_60001 => "resim_stale_60001",
    headless_resim_same_after_click => "resim_same_after_click",
    headless_resim_changed_needs_a_new_click => "resim_changed_needs_a_new_click",
    headless_resim_changed_old_digest => "resim_changed_old_digest",
    headless_resim_no_result_and_failed => "resim_no_result_and_failed",
    headless_stale_resim_result_is_dropped => "stale_resim_result_is_dropped",
    headless_display_change_mid_hold => "display_change_mid_hold",
    headless_high_risk_evm => "high_risk_evm",
    headless_chain_btc => "chain_btc",
    headless_chain_zec => "chain_zec",
    headless_chain_hypercore => "chain_hypercore",
    headless_chain_hypercore_look_alike => "chain_hypercore_look_alike",
    headless_chain_sol_message => "chain_sol_message",
    headless_consume_site_messages => "consume_site_messages",
    headless_site_send_s3_approve => "site_send_s3_approve",
    headless_site_send_s4_approve => "site_send_s4_approve",
    headless_site_send_s3_reject => "site_send_s3_reject",
    headless_consume_app009_branches => "consume_app009_branches",
    headless_blocked_is_never_consumed => "blocked_is_never_consumed",
    headless_expiry_window_tick => "expiry_window_tick",
    headless_expiry_main_tick => "expiry_main_tick",
    headless_l3_site_deadline_window_tick => "l3_site_deadline_window_tick",
    headless_l3_site_deadline_main_tick => "l3_site_deadline_main_tick",
    headless_ui001_and_wc_label => "ui001_and_wc_label",
    headless_open_failure => "open_failure",
    headless_issue_uses_one_instant => "issue_uses_one_instant",
    headless_l1_close_with_a_second_request_queued => "l1_close_with_a_second_request_queued",
    headless_l2_connect_chain_change_close_box => "l2_connect_chain_change_close_box",
    headless_l2_connect_chain_change_main_tick => "l2_connect_chain_change_main_tick",
    headless_l2_connect_chain_change_enter_on_reject => "l2_connect_chain_change_enter_on_reject",
    headless_l2_connect_chain_change_mouse_reject => "l2_connect_chain_change_mouse_reject",
    headless_l2_connect_chain_change_escape => "l2_connect_chain_change_escape",
    headless_l2_connect_chain_change_window_tick => "l2_connect_chain_change_window_tick",
    headless_l2_connect_chain_change_approve => "l2_connect_chain_change_approve",
    headless_lock_shortcut_while_shown => "lock_shortcut_while_shown",
    headless_lock_with_resimulation_in_flight => "lock_with_resimulation_in_flight",
    headless_lock_session_lock => "lock_session_lock",
    headless_lock_session_disconnect => "lock_session_disconnect",
    headless_lock_suspend => "lock_suspend",
    headless_lock_end_session => "lock_end_session",
    headless_lock_idle_after_the_window => "lock_idle_after_the_window",
    headless_open_then_lock_same_entry => "open_then_lock_same_entry",
    headless_revoke_disconnect_while_shown => "revoke_disconnect_while_shown",
    headless_revoke_account_removed_while_shown => "revoke_account_removed_while_shown",
    headless_revoke_chain_deleted_while_shown => "revoke_chain_deleted_while_shown",
    headless_cancel_while_shown => "cancel_while_shown",
    headless_grant_evm_message => "grant_evm_message",
    headless_grant_evm_tx => "grant_evm_tx",
    headless_journal_evm_app_send => "journal_evm_app_send",
    headless_grant_sol_message => "grant_sol_message",
    headless_grant_sol_dapp_sign => "grant_sol_dapp_sign",
    headless_journal_sol_dapp_send => "journal_sol_dapp_send",
    headless_journal_sol_app_send => "journal_sol_app_send",
    headless_journal_zec => "journal_zec",
    headless_card_step_from_the_window => "card_step_from_the_window",
    headless_queue_limits => "queue_limits",
    headless_queue_limit_at_the_app => "queue_limit_at_the_app",
    headless_rpc_import_on_temp_data => "rpc_import_on_temp_data",
}

/// Every scenario in table order, each on a thread of its own (as each test runs): writes
/// `headless.txt` into `YW_S4_FLOW_OUT` when it is set (for review), else compares the whole
/// golden file (order and completeness).
#[test]
#[ignore = "recording of s4_flow/headless.txt (S4 B7); the headless_* tests compare it in the gate"]
fn print_headless() {
    let mut out = String::new();
    for (_, scenario, _) in &SCENARIOS {
        let lines = std::thread::spawn(*scenario)
            .join()
            .expect("the scenario's thread");
        for line in lines {
            out.push_str(&line);
            out.push('\n');
        }
    }
    if let Some(dir) = std::env::var_os("YW_S4_FLOW_OUT") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("headless.txt"), &out).unwrap();
        return;
    }
    let generated: Vec<&str> = out.lines().collect();
    let committed: Vec<&str> = GOLDEN.lines().collect();
    assert!(
        generated == committed,
        "{}",
        first_difference("headless.txt", &generated, &committed)
    );
}

/// `headless.txt` names only scenarios of the table, each with lines, grouped in table order, and
/// holds no address, URL, e-mail, local path or non-ASCII text.
#[test]
fn the_headless_golden_names_only_known_scenarios() {
    let mut order = Vec::new();
    for line in GOLDEN.lines() {
        let name = line.split(' ').next().unwrap_or_default();
        assert!(
            SCENARIOS.iter().any(|(known, ..)| *known == name),
            "unknown scenario: {line}"
        );
        if order.last() != Some(&name) {
            assert!(!order.contains(&name), "{name} is not one block");
            order.push(name);
        }
        for banned in ["0x", "://", "@", "\\", "Users", ".example", "rpc.json"] {
            assert!(!line.contains(banned), "{banned:?} in {line}");
        }
        assert!(line.is_ascii(), "non-ASCII text in {line}");
    }
    let table: Vec<&str> = SCENARIOS.iter().map(|(name, ..)| *name).collect();
    assert_eq!(order, table, "every scenario, in table order");
}

/// Every scenario of the windowed goldens `flow.txt` and `lifecycle.txt` runs headless (against
/// its own golden) or is left out with a reason, never both; the left-out ones are real windowed
/// scenarios.
#[test]
fn every_windowed_scenario_runs_headless_or_is_left_out() {
    let mut windowed: Vec<(&str, Windowed)> = Vec::new();
    for (golden, which) in [
        (FLOW_GOLDEN, Windowed::Flow),
        (LIFECYCLE_GOLDEN, Windowed::Lifecycle),
    ] {
        for line in golden.lines() {
            let name = line.split(' ').next().unwrap_or_default();
            if !windowed.iter().any(|(known, _)| *known == name) {
                windowed.push((name, which));
            }
        }
    }
    assert_eq!(windowed.len(), SCENARIOS.len() + LEFT_OUT.len());
    for (name, which) in &windowed {
        let run = SCENARIOS
            .iter()
            .filter(|(known, _, golden)| known == name && golden == which)
            .count();
        let left = LEFT_OUT.iter().filter(|(known, _)| known == name).count();
        assert_eq!((run + left, left.min(run)), (1, 0), "{name}");
    }
    for (name, reason) in &LEFT_OUT {
        assert!(!reason.is_empty(), "{name}: no reason");
    }
    let headless: Vec<&str> = SCENARIOS.iter().map(|(name, ..)| *name).collect();
    let in_order: Vec<&str> = windowed
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| headless.contains(name))
        .collect();
    assert_eq!(headless, in_order, "the windowed order");
}

/// The cross-check drops only the shell's part of a windowed line: the `focus=` column, the
/// `windows=` counts and the facts of the shell alone; every other column stays.
#[test]
fn the_cross_check_drops_only_the_shell() {
    let step = "x tick | t=+0 | win open status=Pending prep=ready risk=std | gate ready=+0 \
                ack=false sel=- submitting=false fg=true deadline=+120000 | focus=Approve | \
                status-text - | store Pending | queue len=1 shown=app-send | rpc - | key - | \
                dapp - | banners - | info - | card -";
    assert_eq!(
        without_shell(step).as_deref(),
        Some(step.replace(" | focus=Approve", "").as_str())
    );
    let closed = "x enter | t=+1500 | win closed | store Rejected | queue len=0 shown=- | rpc - \
                  | key - | dapp - | banners - | info - | card -";
    assert_eq!(without_shell(closed).as_deref(), Some(closed));
    assert_eq!(
        without_shell("x after | mode=Locked screen=Locked windows=0").as_deref(),
        Some("x after | mode=Locked screen=Locked")
    );
    assert_eq!(
        without_shell("x first | store of the request shown before=Rejected approval windows=1")
            .as_deref(),
        Some("x first | store of the request shown before=Rejected")
    );
    for shell in [
        "x reply | close reply=Handled(0)",
        "x reply | down=Handled(0) up=Handled(0)",
        "x windows | approval windows=0",
        "x windows | approval windows=0 show calls=1 capture calls=0 release calls=0",
    ] {
        assert_eq!(without_shell(shell), None, "{shell}");
    }
    let fact = "x waiters | sign waiters=1";
    assert_eq!(without_shell(fact).as_deref(), Some(fact));
    assert_eq!(
        without_effects("x a | t=+0 | win closed | card - | effects close#1"),
        "x a | t=+0 | win closed | card -"
    );
    assert_eq!(without_effects(fact), fact);
}

/// `App::test_on_main_windowless` is the arms of `App::on_main` it stands for (source check;
/// `app.rs` read only, the `card_pcsc` precedent). 2026-11-20 (S4 B7 review): whole arms, not
/// snippets. Before, each snippet only had to appear somewhere in `on_main` and in the mirror, so
/// the check stayed green if `on_main` gained a call in its `Msg::App` arm before `match *msg` or
/// between the system check and the `match`, and the mirror's order was not checked. Now
/// `on_main`'s head up to `match msg {`, its `Msg::Timer(MAIN_TIMER_ID)` arm and its `Msg::App` arm
/// (each from the arm's start to the brace that closes it, comments dropped) are pinned whole, the
/// mirror is pinned whole, and the mirror's `Msg::App` arm is `on_main`'s with only the messages
/// that read the main window (`WM_YW_ACTIVATE` and the three foreground-guarded ones) left out. A
/// change to any of these parts of `on_main` fails here until the mirror is looked at again.
#[test]
fn the_windowless_main_entry_mirrors_on_main() {
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/app.rs"),
    )
    .unwrap();
    // The fn's text from its head to its closing brace, without `//` comments, each run of
    // whitespace one space.
    let body = |head: &str| -> String {
        assert_eq!(source.matches(head).count(), 1, "{head}");
        let start = source.find(head).expect(head);
        let rest = &source[start..];
        let end = rest.find("\n    }\n").expect("the end of the fn");
        rest[..end]
            .lines()
            .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
            .flat_map(str::split_whitespace)
            .collect::<Vec<_>>()
            .join(" ")
    };
    // 2026-11-20 (S4 P10b): both entries are a drain around their message arms
    // (`on_main_msg`, `windowless_msg`), which are compared as before.
    assert_eq!(
        body("    fn on_main(&mut self, window: &Window, msg: &Msg) -> Reply {"),
        "fn on_main(&mut self, window: &Window, msg: &Msg) -> Reply { \
         let reply = self.on_main_msg(window, msg); self.drain(); reply"
    );
    assert_eq!(
        body("    pub(crate) fn test_on_main_windowless(&mut self, msg: &Msg) -> Reply {"),
        "pub(crate) fn test_on_main_windowless(&mut self, msg: &Msg) -> Reply { \
         let reply = self.windowless_msg(msg); self.drain(); reply"
    );
    let on_main = body("    fn on_main_msg(&mut self, window: &Window, msg: &Msg) -> Reply {");
    let mirror = body("    fn windowless_msg(&mut self, msg: &Msg) -> Reply {");

    // 2026-11-21 (S4 W3, critique B-10): the wallet's main-window mirror is synced first (with
    // no window the windowless mirror never sends anything).
    let system = "self.sync_main_hidden(); if let Some(action) = system_action(msg) { \
                  return self.on_system(action); } match msg {";
    let timer = "Msg::Timer(MAIN_TIMER_ID) => { self.tick(); Reply::Handled(0) }";
    // 2026-11-22 (S4c W15): the activation is `Cmd::Activate` to the wallet, and the early reads
    // `Cmd::Tick` with `TickPart::ReadsDue` (before, `self.activate()` and `self.reads_due(now)`).
    let window_arms = [
        " WM_YW_ACTIVATE => self.wallet.on_cmd(Cmd::Activate),",
        " WM_YW_TAB_SHORTCUT if window.is_foreground() => self.tab_shortcut(*wparam),",
        " WM_YW_SHORTCUT if window.is_foreground() => self.shortcut(*wparam),",
        " WM_YW_NAV_KEY if window.is_foreground() => self.main_nav_key(window, *wparam),",
    ];
    // 2026-11-22 (S4c W14c-2): `reads_due` is `impl Wallet`, reached through `DerefMut`, which
    // gives a call no two-phase borrow, so the arm reads the time first (`let now`).
    let app_in_main = format!(
        "Msg::App {{ msg, wparam }} => {{ match *msg {{ WM_YW_EVENTS => self.drain_events(),{} \
         WM_YW_LOCK_SHORTCUT => self.lock_shortcut(),{} _ => {{}} }} \
         self.drain(); let now = self.clock.now_ms(); self.wallet.on_cmd(Cmd::Tick {{ now_ms: \
         now, part: TickPart::ReadsDue, }}); Reply::Handled(0) }}",
        window_arms[0],
        window_arms[1..].concat()
    );

    // on_main: the system messages first and nothing between them and the `match`; the two
    // arms whole; one catch-all, last.
    assert!(
        on_main.starts_with(&format!(
            "fn on_main_msg(&mut self, window: &Window, msg: &Msg) -> Reply {{ {system} "
        )),
        "on_main: {on_main}"
    );
    assert_eq!(
        match_arm(&on_main, "Msg::Timer(MAIN_TIMER_ID) =>").as_deref(),
        Some(timer)
    );
    assert_eq!(
        match_arm(&on_main, "Msg::App {").as_deref(),
        Some(app_in_main.as_str())
    );
    assert_eq!(on_main.matches("_ => Reply::Default,").count(), 1);
    assert!(
        on_main.ends_with(" _ => Reply::Default, }"),
        "on_main: {on_main}"
    );

    // The mirror, whole: the same head, the same timer arm, the `Msg::App` arm of `on_main`
    // without the window's messages, then nothing else.
    let mut app_in_mirror = app_in_main.replacen(
        "Msg::App { msg, wparam } =>",
        "Msg::App { msg, .. } if matches!(*msg, WM_YW_EVENTS | WM_YW_LOCK_SHORTCUT) =>",
        1,
    );
    for window_arm in window_arms {
        assert_eq!(app_in_mirror.matches(window_arm).count(), 1, "{window_arm}");
        app_in_mirror = app_in_mirror.replacen(window_arm, "", 1);
    }
    assert_eq!(
        match_arm(&mirror, "Msg::App {").as_deref(),
        Some(app_in_mirror.as_str())
    );
    assert_eq!(
        mirror,
        format!(
            "fn windowless_msg(&mut self, msg: &Msg) -> Reply {{ {system} \
             {timer} {app_in_mirror} _ => Reply::Default, }}"
        )
    );
}

/// The match arm of `text` that starts with `start` (it must be there exactly once): from `start`
/// to the brace that closes the arm's block.
fn match_arm(text: &str, start: &str) -> Option<String> {
    let mut found = text.match_indices(start);
    let (at, _) = found.next()?;
    if found.next().is_some() {
        return None;
    }
    let open = at + text[at..].find("=> {")? + "=> ".len();
    let mut depth = 0_usize;
    for (offset, c) in text[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(text[at..=open + offset].to_owned());
                }
            }
            _ => {}
        }
    }
    None
}

/// The headless host is installed only by the fixture of this module and leaves no window: a
/// scenario's App never had an approval window, and the host is gone when the fixture is.
#[test]
fn the_headless_host_makes_no_window() {
    {
        let fx = fixture("no-window");
        let mut h = Run::new("no_window", &fx, None);
        h.app_send("S2");
        assert!(headless_host::installed());
        assert!(fx.app.borrow().evm.approval.is_some());
        assert!(fx.app.borrow().approval_win.is_none());
        assert!(h.lines.iter().all(|line| line.contains(" | effects ")));
        assert!(h.lines[0].contains("| effects open#1"), "{}", h.lines[0]);
    }
    assert!(!headless_host::installed());
}
