//! Win32 input of the approval window (spec/04 §3.4): the window messages that count as presses
//! for [`ApprovalInteraction`](yw_engine::approval::interaction::ApprovalInteraction).
//! 2026-11-17 (spec/15 §11.4 S2): [`stray_press`] moved here from `ui::interaction`, which no
//! longer names a `yw_win` type; the interaction rules themselves are unchanged.
//!
//! 2026-11-19 (spec/15 §11.4 S4 B2): the approval window's trusted input is sampled into
//! [`TrustedSignals`] — only by its `sample*` functions, each read at the program point the window
//! procedure read it before — and every message of A01, its panel and its AI body is mapped to
//! its ordered [`Step`]s by the pure [`map_msg`] and [`map_key`] (one table row per arm, spec/04
//! §3.4 table; the table tests below mirror it row by row). The approving and holding events
//! (`ApproveActivated`, `PointerPressed`, `PointerReleased`, `SpacePressed`, `SpaceReleased`) are
//! built only here ([`Trusted::deliver`]), from a sample it takes itself right before the shell
//! delivers them; a press's focus and capture steps come before that sample (S4 critique A-7: the
//! pointer press samples the foreground and the button after `SetFocus` and `SetCapture`), and
//! `ReleaseCapture` comes before the release event (A-8). Before B2, `app_approval.rs` read the
//! signals through small wrappers and built the events inline in each arm; the reads, Win32 calls
//! and events keep their order (`app/tests/s4_flow/input.txt` and `reentry.txt` byte-equal).
//!
//! 2026-11-19 (S4 B2 review): a sample's fields and the sample-to-event step (`Trusted::event`)
//! are private, so no code outside this module can build a sample or an approving event from
//! made-up values (source check S8 also pins where `Trusted::` and `.deliver(` occur). Before,
//! the fields were `pub`, the type derived `Default` and `Trusted::event` was `pub`: any yw-app
//! code could have built `ApproveActivated { physical: true }` without naming a scanned
//! identifier.
//!
//! 2026-11-19 (S4 B6, plan §3.1, critique A-6, A-12, A-13): what a step hands to the approval flow
//! is one `yw_engine::approval::flow::ApprovalInput`, built only here ([`window_input`]: the
//! `ShownId` of the window that got the message, its foreground sample for an interaction event,
//! one signal) and sent as `Cmd::Approval`. A connect account row's step carries the revision of
//! the view its layout was drawn from ([`Step::ToggleAccount`]); the flow drops a toggle drawn
//! from an older view.

use yw_engine::approval::flow::{ApprovalInput, ApprovalSignal, ShownId};
use yw_win::ui::{Msg, Rect, Reply, Window};

use yw_engine::approval::interaction::InteractionEvent;

/// A01's 50 ms timer (the `Tick` input, spec/04 §3.4).
pub const APPROVAL_TIMER_ID: usize = 7;
/// The `WM_MOUSEACTIVATE` reply that activates A01 and discards the activating click (spec/04
/// §3.6, click-through guard).
pub const MA_ACTIVATEANDEAT: isize = 2;
/// `SB_ENDSCROLL`: the scroll-bar button was released (every other `WM_VSCROLL` code comes from
/// a scroll-bar press or drag, which counts as a press for the press-gap rule).
pub const SB_ENDSCROLL: u16 = 8;
// Virtual keys the approval window reads or maps.
pub const VK_LBUTTON: u16 = 0x01;
pub const VK_TAB: u16 = 0x09;
pub const VK_RETURN: u16 = 0x0D;
pub const VK_SHIFT: u16 = 0x10;
pub const VK_ESCAPE: u16 = 0x1B;
pub const VK_SPACE: u16 = 0x20;
pub const VK_PRIOR: u16 = 0x21;
pub const VK_NEXT: u16 = 0x22;
pub const VK_END: u16 = 0x23;
pub const VK_HOME: u16 = 0x24;
pub const VK_UP: u16 = 0x26;
pub const VK_DOWN: u16 = 0x28;

/// Keyboard focus inside A01 (spec/04 §3.4 Tab order). (2026-11-19, S4 B2: moved here from
/// `app_approval.rs` with the input map.)
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

/// The bottom-bar button a left press started on (until its release). (2026-11-19, S4 B2: moved
/// here from `app_approval.rs`.)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pressed {
    Approve,
    Reject,
    Retry,
    AiRetry,
}

/// The window a message came to: A01, its scrolling panel or its AI explanation body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Surface {
    Approval,
    Panel,
    AiBody,
}

/// The approval window's trusted input, read while its message is processed (spec/04 §3.4). The
/// `sample*` functions are the only readers of the foreground, the key state, the message's own
/// key state and the injection flag in the approval shell (source check S2); each sample reads
/// only what its step needs, so a field it does not read stays `false`. 2026-11-19 (S4 B2
/// review): the fields are private and there is no `Default`, so only the `sample*` functions
/// (and this module's table tests) make one; the shell reads the two values it needs through
/// [`TrustedSignals::foreground`] and [`TrustedSignals::shift_down`]. Before, the fields were
/// `pub` and the type derived `Default`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "one independent value per Win32 read"
)]
pub struct TrustedSignals {
    /// A01 is the foreground window: the gate's input, read before every interaction event (the
    /// render harness may force it under `cfg(test)`).
    foreground: bool,
    /// The raw foreground read (no harness force) of the activating click and the approve
    /// press's click-through check.
    foreground_raw: bool,
    /// `is_down(VK_LBUTTON)`.
    lbutton_down: bool,
    /// `is_down(VK_SPACE)`.
    space_down: bool,
    /// `is_down(VK_SHIFT)` (Tab direction only).
    shift_down: bool,
    /// Enter is down in the key state of the message being handled (`is_down_in_message`; a
    /// posted `WM_KEYDOWN` is not, security review L5).
    enter_in_message: bool,
    /// The message came from injected input (`SendInput`).
    injected: bool,
}

impl TrustedSignals {
    /// Nothing read.
    const NONE: Self = Self {
        foreground: false,
        foreground_raw: false,
        lbutton_down: false,
        space_down: false,
        shift_down: false,
        enter_in_message: false,
        injected: false,
    };

    /// A01 is the foreground window (the gate's sample, [`TrustedSignals::sample_foreground`]).
    #[must_use]
    pub const fn foreground(self) -> bool {
        self.foreground
    }

    /// Shift is down (Tab's direction, [`TrustedSignals::sample_shift`]).
    #[must_use]
    pub const fn shift_down(self) -> bool {
        self.shift_down
    }

    /// The gate's foreground sample, taken before every event (2026-11-19, S4 B6: by
    /// `App::window_event` for the window that got the message; was `interaction()`).
    #[must_use]
    pub fn sample_foreground(window: &Window) -> Self {
        Self {
            foreground: Self::sample_gate_foreground(window),
            ..Self::NONE
        }
    }

    /// What a message reads as soon as it arrives: only A01's `WM_MOUSEACTIVATE` reads (the raw
    /// foreground, before anything else of its arm).
    #[must_use]
    pub fn sample_on_arrival(surface: Surface, msg: &Msg, window: &Window) -> Self {
        if surface == Surface::Approval && matches!(msg, Msg::MouseActivate) {
            Self {
                foreground_raw: Self::sample_raw_foreground(window, "mouse_activate"),
                ..Self::NONE
            }
        } else {
            Self::NONE
        }
    }

    /// What `trusted` reads, right before its event is delivered (after the press's focus and
    /// capture steps). `window`: the window that got the message (the approve press reads its
    /// raw foreground; `None` only for keys, which never read it). Private: only
    /// [`Trusted::deliver`] samples for an event (2026-11-19, S4 B2 review).
    #[must_use]
    fn sample_for(trusted: Trusted, window: Option<&Window>) -> Self {
        match trusted {
            Trusted::PointerPressed => Self {
                foreground_raw: window
                    .is_some_and(|window| Self::sample_raw_foreground(window, "mouse_down")),
                lbutton_down: Self::sample_key(VK_LBUTTON, "mouse_down"),
                ..Self::NONE
            },
            Trusted::PointerReleased => Self {
                lbutton_down: Self::sample_key(VK_LBUTTON, "mouse_up"),
                ..Self::NONE
            },
            Trusted::SpacePressed { .. } => Self {
                space_down: Self::sample_key(VK_SPACE, "key_down"),
                ..Self::NONE
            },
            Trusted::SpaceReleased => Self {
                space_down: Self::sample_key(VK_SPACE, "key_up"),
                ..Self::NONE
            },
            Trusted::ApproveEnter => {
                // Short-circuit as before: the injection flag is read only for an Enter that is
                // in the message's key state.
                let enter_in_message = Self::sample_enter_in_message();
                Self {
                    enter_in_message,
                    injected: enter_in_message && Self::sample_injection(),
                    ..Self::NONE
                }
            }
        }
    }

    /// Tab's direction: Shift, read after the Tab press counted.
    #[must_use]
    pub fn sample_shift() -> Self {
        Self {
            shift_down: Self::sample_key(VK_SHIFT, "tab"),
            ..Self::NONE
        }
    }

    /// `window.is_foreground()`, or (`cfg(test)`) the scripted oracle, then the render harness's
    /// force.
    fn sample_gate_foreground(window: &Window) -> bool {
        #[cfg(test)]
        if let Some(value) = crate::app_approval::flow_support::scripted(
            crate::app_approval::flow_support::Read::Foreground,
        ) {
            return value;
        }
        #[cfg(test)]
        if crate::app_approval::TEST_FORCE_FOREGROUND.with(core::cell::Cell::get) {
            return true;
        }
        window.is_foreground()
    }

    /// `window.is_foreground()` without the render harness's force (`point` labels the
    /// `cfg(test)` trace).
    #[cfg_attr(
        not(test),
        expect(unused_variables, reason = "`point` labels the cfg(test) trace only")
    )]
    fn sample_raw_foreground(window: &Window, point: &'static str) -> bool {
        #[cfg(test)]
        if let Some(value) = crate::app_approval::flow_support::scripted(
            crate::app_approval::flow_support::Read::RawForeground(point),
        ) {
            return value;
        }
        window.is_foreground()
    }

    /// `is_down(vk)`: the key or button is down in the thread's key state.
    #[cfg_attr(
        not(test),
        expect(unused_variables, reason = "`point` labels the cfg(test) trace only")
    )]
    fn sample_key(vk: u16, point: &'static str) -> bool {
        #[cfg(test)]
        if let Some(value) = crate::app_approval::flow_support::scripted(
            crate::app_approval::flow_support::Read::KeyDown(vk, point),
        ) {
            return value;
        }
        yw_win::input::is_down(vk)
    }

    /// Enter is down in the state of the message being handled (L5: a posted `WM_KEYDOWN` is
    /// not).
    fn sample_enter_in_message() -> bool {
        #[cfg(test)]
        if let Some(value) = crate::app_approval::flow_support::scripted(
            crate::app_approval::flow_support::Read::EnterInMessage,
        ) {
            return value;
        }
        yw_win::input::is_down_in_message(VK_RETURN)
    }

    /// The message being handled came from injected input (`SendInput`).
    fn sample_injection() -> bool {
        #[cfg(test)]
        if let Some(value) = crate::app_approval::flow_support::scripted(
            crate::app_approval::flow_support::Read::Injected,
        ) {
            return value;
        }
        yw_win::input::injected()
    }
}

/// An event whose trusted fields come from a sample taken right before it is delivered: the
/// approving and holding events. They are built only by [`Trusted::deliver`] (source check S8:
/// in yw-app production code `Trusted::` and `TrustedSignals {` occur only in this file, and
/// `Step::Sampled` is run, and `.deliver(` called, only by the one `Step::Sampled` arm of
/// `App::run_step`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trusted {
    /// A left press on `승인`: click-through = A01 was not the foreground window (raw read),
    /// `physical_down` = the button is down.
    PointerPressed,
    /// The release of a press that started on `승인`.
    PointerReleased,
    /// Space with the focus on `승인` (`repeat`: lParam bit 30).
    SpacePressed { repeat: bool },
    /// Space released with the focus on `승인`.
    SpaceReleased,
    /// Enter with the focus on `승인`.
    ApproveEnter,
}

impl Trusted {
    /// Samples what this event reads, now (`TrustedSignals::sample_for`), and builds the event
    /// from that sample: the only way out of this module to an approving or holding event
    /// (2026-11-19, S4 B2 review: was `TrustedSignals::sample_for` + a `pub` `Trusted::event`,
    /// which took a sample built anywhere). `window`: the window that got the message.
    #[must_use]
    pub fn deliver(self, window: Option<&Window>) -> InteractionEvent {
        self.event(TrustedSignals::sample_for(self, window))
    }

    /// The event `signals` delivers (spec/04 §3.4 table). Private: the table tests call it with
    /// made-up samples; production calls it only through [`Trusted::deliver`].
    #[must_use]
    const fn event(self, signals: TrustedSignals) -> InteractionEvent {
        match self {
            Self::PointerPressed => InteractionEvent::PointerPressed {
                inside: true,
                click_through: !signals.foreground_raw,
                physical_down: signals.lbutton_down,
            },
            Self::PointerReleased => InteractionEvent::PointerReleased {
                physical_down: signals.lbutton_down,
            },
            Self::SpacePressed { repeat } => InteractionEvent::SpacePressed {
                repeat,
                physical_down: signals.space_down,
            },
            Self::SpaceReleased => InteractionEvent::SpaceReleased {
                physical_down: signals.space_down,
            },
            // L5: a posted/sent WM_KEYDOWN (not in the thread's key state) or an injected one
            // never approves, like Space and the pointer (`is_down`).
            Self::ApproveEnter => InteractionEvent::ApproveActivated {
                physical: signals.enter_in_message && !signals.injected,
            },
        }
    }
}

/// One input of the approval window `shown` (2026-11-19, S4 B6, critique A-6): the only place in
/// yw-app that builds an [`ApprovalInput`] (source check S8). `foreground` is that window's gate
/// sample ([`TrustedSignals::sample_foreground`]) for an interaction event (`Event`, `Close`),
/// `false` for the other signals, which take none. An approving event in `signal` comes only from
/// [`Trusted::deliver`].
#[must_use]
pub const fn window_input(
    shown: ShownId,
    foreground: bool,
    signal: ApprovalSignal,
) -> ApprovalInput {
    ApprovalInput {
        shown,
        foreground,
        signal,
    }
}

/// A page, line or end scroll of the panel by key (spec/04 §3.4: page keys and Home/End wherever
/// the focus is, the arrows on the scroll area only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyScroll {
    PageUp,
    PageDown,
    LineUp,
    LineDown,
    Top,
    Bottom,
}

impl KeyScroll {
    /// The scroll delta for a panel `page` and `line` high (pixels).
    #[must_use]
    pub const fn delta(self, page: i32, line: i32) -> i32 {
        match self {
            Self::PageUp => -page,
            Self::PageDown => page,
            Self::LineUp => -line,
            Self::LineDown => line,
            Self::Top => i32::MIN / 2,
            Self::Bottom => i32::MAX / 2,
        }
    }
}

/// Where a `WM_VSCROLL` code moves a view (`SB_*`; `SB_ENDSCROLL` and unknown codes stay).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrollGoal {
    LineUp,
    LineDown,
    PageUp,
    PageDown,
    /// `SB_THUMBPOSITION`/`SB_THUMBTRACK`: the scroll bar's track position.
    Track,
    Top,
    Bottom,
    Stay,
}

impl ScrollGoal {
    /// The goal of `WM_VSCROLL` code `code`.
    #[must_use]
    pub const fn of(code: u16) -> Self {
        match code {
            0 => Self::LineUp,
            1 => Self::LineDown,
            2 => Self::PageUp,
            3 => Self::PageDown,
            4 | 5 => Self::Track,
            6 => Self::Top,
            7 => Self::Bottom,
            _ => Self::Stay,
        }
    }

    /// The target position from `current` (`track`: the track position, read by the shell only
    /// for [`ScrollGoal::Track`]).
    #[must_use]
    pub const fn target(self, current: i32, page: i32, line: i32, track: i32) -> i32 {
        match self {
            Self::LineUp => current.saturating_sub(line),
            Self::LineDown => current.saturating_add(line),
            Self::PageUp => current.saturating_sub(page),
            Self::PageDown => current.saturating_add(page),
            Self::Track => track,
            Self::Top => 0,
            Self::Bottom => i32::MAX / 2,
            Self::Stay => current,
        }
    }
}

/// The scroll delta of a wheel `delta` (`WHEEL_DELTA` 120 per notch) at `step` pixels a notch.
#[must_use]
pub fn wheel_delta(delta: i16, step: i32) -> i32 {
    -(i32::from(delta) / 120).saturating_mul(step)
}

/// The Tab order of A01 (spec/04 §3.4): `거부` → the checkbox (if shown) → `승인` → `원본 데이터`
/// (if shown) → the scrolling area.
#[must_use]
pub fn tab_order(ack: bool, raw: bool) -> Vec<Focus> {
    let mut order = vec![Focus::Reject];
    if ack {
        order.push(Focus::Ack);
    }
    order.push(Focus::Approve);
    if raw {
        order.push(Focus::Raw);
    }
    order.push(Focus::Scroll);
    order
}

/// The focus after Tab (`backwards`: Shift+Tab) from `focus` along `order` (a focus not in the
/// order counts as the first).
#[must_use]
pub fn tab_target(order: &[Focus], focus: Focus, backwards: bool) -> Focus {
    let position = order.iter().position(|item| *item == focus).unwrap_or(0);
    let len = order.len().max(1);
    let next = if backwards {
        position.checked_sub(1).unwrap_or(len - 1)
    } else {
        (position + 1) % len
    };
    order.get(next).copied().unwrap_or(Focus::Reject)
}

/// What a left click on the panel content hit (content pixels).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PanelHit {
    /// A connect account row (its index in the offered list).
    Account(usize),
    /// The acknowledgement checkbox.
    Ack,
    /// The `원본 데이터` switch.
    Raw,
    /// Anything else.
    Nothing,
}

/// The first of the account rows, the checkbox and the raw-data switch that contains `(x, y)`.
#[must_use]
pub fn panel_hit(
    accounts: &[(usize, Rect)],
    ack: Option<Rect>,
    raw: Option<Rect>,
    x: i32,
    y: i32,
) -> PanelHit {
    if let Some((index, _)) = accounts.iter().find(|(_, rect)| rect.contains(x, y)) {
        PanelHit::Account(*index)
    } else if ack.is_some_and(|rect| rect.contains(x, y)) {
        PanelHit::Ack
    } else if raw.is_some_and(|rect| rect.contains(x, y)) {
        PanelHit::Raw
    } else {
        PanelHit::Nothing
    }
}

/// The steps of a panel click on `hit` (after its press counted and A01 took the focus).
/// `view_rev`: the revision of the view the hit layout was drawn from (2026-11-19, S4 B6, A-13).
#[must_use]
pub fn panel_click(hit: PanelHit, view_rev: u64) -> Vec<Step> {
    match hit {
        PanelHit::Account(index) => vec![Step::ToggleAccount { index, view_rev }],
        PanelHit::Ack => vec![Step::MoveFocus(Focus::Ack), Step::ToggleAck],
        PanelHit::Raw => vec![Step::MoveFocus(Focus::Raw), Step::ToggleRaw],
        PanelHit::Nothing => vec![Step::MoveFocus(Focus::Scroll), Step::InvalidateApproval],
    }
}

/// One step of a mapped message. The shell runs the steps in order, inside the `App` borrow of
/// the message; a guard step that fails ends the message with its reply. 2026-11-19 (S4 B6): the
/// steps that reach the approval flow (an event, activation, the close box, a toggle, a retry, a
/// size change) go as one `Cmd::Approval` input of the window that got the message
/// ([`window_input`]); the flow drops it when that window is not the shown one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// An event the message decides by itself (`ApprovalSignal::Event`, with the window's
    /// foreground sample).
    Event(InteractionEvent),
    /// Sample what `Trusted` reads now and deliver its event ([`Trusted::deliver`]; 2026-11-19,
    /// S4 B2 review: one call, was `TrustedSignals::sample_for` then `Trusted::event`).
    Sampled(Trusted),
    /// `WM_ACTIVATEAPP(TRUE)`: restart the arm delay unconditionally, then foreground `true` (not
    /// an interaction event; `ApprovalSignal::Activated`).
    Activated,
    /// The close box: `RejectActivated`, then finish `Rejected` only while the window that got
    /// it is still the shown one (S4 F1, L-1; 2026-11-19, S4 B6: `ApprovalSignal::Close`, the
    /// window's id checked by the flow, was the shown queue item).
    Close,
    ToggleAck,
    ToggleRaw,
    /// A connect account row: its index in the offered list and the revision of the view the
    /// layout was drawn from (2026-11-19, S4 B6, A-13: was the index only).
    ToggleAccount {
        index: usize,
        view_rev: u64,
    },
    Retry,
    AiRetry,
    /// Go on only while the window that got the message is the shown one (S4 F1, L-1;
    /// 2026-11-19, S4 B6: its `ShownId`, was the queue item shown when the message arrived);
    /// else end with this reply. 2026-11-24 (spec/15 §11.4 S5-10, S5 plan owner item O-12,
    /// spec/04 §3.4): also the guard of the panel's and the AI body's presses and scroll-bar
    /// messages; before, those went on while any approval window was open (`AnyWindow`, gone),
    /// and the steps after it acted on the window and flow shown then. (S5-10 review: so a panel
    /// or AI-body press that expires its own request no longer focuses, clicks or toggles the
    /// next request's window it opened; actions dropped only.)
    SameWindow(Reply),
    /// `SetFocus` on the window that got the message (A01).
    FocusReceiver,
    /// `SetFocus` on A01 (from the panel or the AI body).
    FocusApproval,
    /// A01's keyboard focus.
    MoveFocus(Focus),
    /// The bottom-bar button the press started on.
    Press(Pressed),
    /// Forget the pressed button.
    Unpress,
    /// `SetCapture` on the window that got the message.
    Capture,
    /// `ReleaseCapture`.
    Release,
    /// Invalidate the window that got the message.
    Invalidate,
    /// Invalidate A01.
    InvalidateApproval,
    /// Sample Shift ([`TrustedSignals::sample_shift`]), move the focus along the Tab order
    /// ([`tab_target`]) and repaint A01 and the panel.
    Tab,
    /// Scroll the panel by key ([`KeyScroll::delta`] of the panel's page and line).
    KeyScroll(KeyScroll),
    /// Scroll the panel by a wheel delta (60 DIP a notch of the receiving window).
    Wheel(i16),
    /// Scroll the AI body by a wheel delta (40 DIP a notch).
    AiWheel(i16),
    /// Scroll the panel to a `WM_VSCROLL` goal.
    PanelScroll(ScrollGoal),
    /// Scroll the AI body to a `WM_VSCROLL` goal.
    AiScroll(ScrollGoal),
    /// A click on the panel content at client `(x, y)`: hit-tested against the layout and scroll
    /// of the window shown at this step ([`panel_hit`], [`panel_click`]).
    PanelClick {
        x: i32,
        y: i32,
    },
    /// An AI body click opens or folds an inconsistent explanation (2026-11-24, S5-10: the
    /// flow's `ApprovalSignal::AiExpand` of the window that got the click; before, the shell
    /// flipped the shown flow's panel).
    AiExpand,
    /// Paint the window that got the message.
    Paint,
    /// A01's size or DPI changed: lay out and rebuild the view (2026-11-19, S4 B6: the width
    /// class goes to the flow as `ApprovalSignal::Resized`).
    Relayout,
    /// The rest of the 50 ms timer after its `Tick`: the AI panel tick, then the
    /// simulating-countdown rebuild (2026-11-24, S5-10: the flow's `ApprovalSignal::TimerTail`
    /// of the window that got the timer, run only after that window's own `Tick`; before, the
    /// shell called the two on the shown flow).
    TimerTail,
}

/// What A01 knows about a message when it arrives (`None` in [`map_msg`]: no window is open).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Facts {
    pub focus: Focus,
    pub pressed: Option<Pressed>,
    /// For a mouse message: which bottom-bar buttons contain its point.
    pub hits: BarHits,
}

/// The bottom-bar buttons that contain a point.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[expect(clippy::struct_excessive_bools, reason = "one rectangle test each")]
pub struct BarHits {
    pub approve: bool,
    pub reject: bool,
    pub retry: bool,
    pub ai_retry: bool,
}

/// One message mapped: its steps in order and the window procedure's reply (unless a guard step
/// ends it with its own).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapped {
    pub steps: Vec<Step>,
    pub reply: Reply,
}

/// The approval-window (and panel) messages that are presses with no approval meaning of their
/// own: a right, middle or X button press in the client area, and any button press on the
/// non-client area (title bar, caption buttons, frame, scroll bar). They count as
/// [`InteractionEvent::OtherPress`] (press-gap rule, arm-delay restart while not armed); the window
/// still lets the system handle the message (`Reply::Default`).
#[must_use]
pub const fn stray_press(msg: &Msg) -> Option<InteractionEvent> {
    match msg {
        Msg::OtherButtonDown | Msg::NonClientButtonDown => Some(InteractionEvent::OtherPress),
        _ => None,
    }
}

/// Maps one message of `surface` (spec/04 §3.4; one arm per row of the window procedure).
/// `facts`: A01's state when the message arrived (`None`: no window); `signals`: what
/// [`TrustedSignals::sample_on_arrival`] read.
#[must_use]
pub fn map_msg(
    surface: Surface,
    msg: &Msg,
    facts: Option<Facts>,
    signals: TrustedSignals,
) -> Mapped {
    if let Some(event) = stray_press(msg) {
        // Right/middle/X button and non-client presses count too, on every surface.
        return mapped(vec![Step::Event(event)], Reply::Default);
    }
    match surface {
        Surface::Approval => map_approval(msg, facts, signals),
        Surface::Panel => map_panel(msg),
        Surface::AiBody => map_ai_body(msg),
    }
}

const fn mapped(steps: Vec<Step>, reply: Reply) -> Mapped {
    Mapped { steps, reply }
}

fn map_approval(msg: &Msg, facts: Option<Facts>, signals: TrustedSignals) -> Mapped {
    match *msg {
        Msg::Paint => mapped(vec![Step::Paint], Reply::Handled(0)),
        Msg::Size { .. } | Msg::DpiChanged { .. } => mapped(vec![Step::Relayout], Reply::Default),
        Msg::MouseActivate => {
            if signals.foreground_raw {
                mapped(Vec::new(), Reply::Default)
            } else {
                // The eaten activating click (any button) is a press while not armed.
                mapped(
                    vec![Step::Event(InteractionEvent::OtherPress)],
                    Reply::Handled(MA_ACTIVATEANDEAT),
                )
            }
        }
        Msg::Timer(APPROVAL_TIMER_ID) => mapped(
            vec![Step::Event(InteractionEvent::Tick), Step::TimerTail],
            Reply::Handled(0),
        ),
        Msg::MouseDown { .. } => approval_press(facts),
        Msg::MouseMove { .. } => {
            let steps = match facts {
                Some(facts) if facts.pressed == Some(Pressed::Approve) => {
                    vec![Step::Event(InteractionEvent::PointerMoved {
                        inside: facts.hits.approve,
                    })]
                }
                _ => Vec::new(),
            };
            mapped(steps, Reply::Handled(0))
        }
        Msg::MouseUp { .. } => approval_release(facts),
        Msg::KeyDown { vk, repeat } => mapped(map_key(vk, repeat, facts), Reply::Handled(0)),
        Msg::KeyUp { vk } => {
            let steps =
                if vk == VK_SPACE && facts.is_some_and(|facts| facts.focus == Focus::Approve) {
                    vec![Step::Sampled(Trusted::SpaceReleased)]
                } else {
                    Vec::new()
                };
            mapped(steps, Reply::Handled(0))
        }
        Msg::Wheel(delta) => mapped(vec![Step::Wheel(delta)], Reply::Handled(0)),
        Msg::KillFocus { to_foreign: true } => mapped(
            vec![Step::Event(InteractionEvent::FocusLost)],
            Reply::Default,
        ),
        Msg::ActivateApp(false) => mapped(
            vec![Step::Event(InteractionEvent::ForegroundLost)],
            Reply::Default,
        ),
        Msg::ActivateApp(true) => mapped(vec![Step::Activated], Reply::Default),
        Msg::CaptureChanged => {
            let steps = if facts.is_some_and(|facts| facts.pressed.is_some()) {
                vec![Step::Unpress, Step::Event(InteractionEvent::CaptureLost)]
            } else {
                Vec::new()
            };
            mapped(steps, Reply::Default)
        }
        Msg::CancelMode => mapped(
            vec![Step::Event(InteractionEvent::CancelMode)],
            Reply::Default,
        ),
        Msg::Close => mapped(vec![Step::Close], Reply::Handled(0)),
        _ => mapped(Vec::new(), Reply::Default),
    }
}

/// A01 `WM_LBUTTONDOWN`: a press on `승인` is the pointer press (focus and capture first, then the
/// sample); every other press counts as `OtherPress` first and goes on only while its window is
/// still the shown one (S4 F1).
fn approval_press(facts: Option<Facts>) -> Mapped {
    let Some(facts) = facts else {
        return mapped(
            vec![Step::Event(InteractionEvent::OtherPress)],
            Reply::Default,
        );
    };
    let hits = facts.hits;
    let mut steps = Vec::new();
    if !hits.approve {
        // Every press counts for the press-gap rule (spec/04 §3.4).
        steps.push(Step::Event(InteractionEvent::OtherPress));
        steps.push(Step::SameWindow(Reply::Default));
    }
    steps.push(Step::FocusReceiver);
    if hits.approve {
        steps.extend([
            Step::Press(Pressed::Approve),
            Step::MoveFocus(Focus::Approve),
            Step::Capture,
            Step::Sampled(Trusted::PointerPressed),
        ]);
    } else if hits.reject {
        steps.extend([
            Step::Press(Pressed::Reject),
            Step::MoveFocus(Focus::Reject),
            Step::Capture,
        ]);
    } else if hits.retry {
        steps.extend([Step::Press(Pressed::Retry), Step::Capture]);
    } else if hits.ai_retry {
        // Mouse only: not a default button, not in the Tab order, not on Enter/Space.
        steps.extend([Step::Press(Pressed::AiRetry), Step::Capture]);
    }
    steps.push(Step::Invalidate);
    mapped(steps, Reply::Handled(0))
}

/// A01 `WM_LBUTTONUP`: release the capture first (its own `WM_CAPTURECHANGED` comes while the
/// App is borrowed and is dropped, `s4_flow/reentry.txt`), then end the press it started.
fn approval_release(facts: Option<Facts>) -> Mapped {
    let Some(facts) = facts else {
        return mapped(vec![Step::Release], Reply::Default);
    };
    let hits = facts.hits;
    let mut steps = vec![Step::Release, Step::Unpress];
    match facts.pressed {
        Some(Pressed::Approve) => steps.push(Step::Sampled(Trusted::PointerReleased)),
        Some(Pressed::Reject) if hits.reject => {
            steps.push(Step::Event(InteractionEvent::RejectActivated));
        }
        Some(Pressed::Retry) if hits.retry => steps.push(Step::Retry),
        Some(Pressed::AiRetry) if hits.ai_retry => steps.push(Step::AiRetry),
        _ => {}
    }
    steps.push(Step::Invalidate);
    mapped(steps, Reply::Handled(0))
}

/// Maps an A01 `WM_KEYDOWN` (`repeat`: lParam bit 30). Every key press (auto-repeat included)
/// counts for the press-gap rule; Enter and Space on `승인` are presses of their own. A press
/// that ended the shown request (past its deadline) goes no further (S4 F1).
#[must_use]
pub fn map_key(vk: u16, repeat: bool, facts: Option<Facts>) -> Vec<Step> {
    let approve_input = matches!(vk, VK_RETURN | VK_SPACE)
        && facts.is_some_and(|facts| facts.focus == Focus::Approve);
    let mut steps = Vec::new();
    if !approve_input {
        steps.push(Step::Event(InteractionEvent::OtherPress));
    }
    let Some(facts) = facts else {
        return steps;
    };
    if !approve_input {
        steps.push(Step::SameWindow(Reply::Handled(0)));
    }
    let focus = facts.focus;
    let step = match vk {
        VK_TAB => Some(Step::Tab),
        VK_ESCAPE => Some(Step::Event(InteractionEvent::RejectActivated)),
        // Not an auto-repeat on `거부`, the checkbox or `원본 데이터` (2026-11-12): the Enter or
        // Space that opened this window from a send form may still be held.
        VK_RETURN | VK_SPACE => match focus {
            Focus::Approve if vk == VK_RETURN => Some(Step::Sampled(Trusted::ApproveEnter)),
            Focus::Approve => Some(Step::Sampled(Trusted::SpacePressed { repeat })),
            Focus::Reject if !repeat => Some(Step::Event(InteractionEvent::RejectActivated)),
            Focus::Ack if !repeat => Some(Step::ToggleAck),
            Focus::Raw if !repeat => Some(Step::ToggleRaw),
            _ => None,
        },
        // Page keys and Home/End scroll wherever the focus is (2026-11-12: they did nothing
        // until Tab reached the scroll area, the fifth stop); the arrows there only. The focus
        // stays where it was.
        VK_PRIOR => Some(Step::KeyScroll(KeyScroll::PageUp)),
        VK_NEXT => Some(Step::KeyScroll(KeyScroll::PageDown)),
        VK_HOME => Some(Step::KeyScroll(KeyScroll::Top)),
        VK_END => Some(Step::KeyScroll(KeyScroll::Bottom)),
        VK_UP if focus == Focus::Scroll => Some(Step::KeyScroll(KeyScroll::LineUp)),
        VK_DOWN if focus == Focus::Scroll => Some(Step::KeyScroll(KeyScroll::LineDown)),
        _ => None,
    };
    steps.extend(step);
    steps
}

fn map_panel(msg: &Msg) -> Mapped {
    match *msg {
        Msg::Paint => mapped(vec![Step::Paint], Reply::Handled(0)),
        Msg::MouseDown { x, y } => mapped(
            vec![
                Step::Event(InteractionEvent::OtherPress),
                Step::SameWindow(Reply::Default),
                Step::FocusApproval,
                Step::PanelClick { x, y },
            ],
            Reply::Handled(0),
        ),
        Msg::Wheel(delta) => mapped(vec![Step::Wheel(delta)], Reply::Handled(0)),
        Msg::VScroll { code } => {
            let mut steps = Vec::new();
            if code != SB_ENDSCROLL {
                steps.push(Step::Event(InteractionEvent::OtherPress));
            }
            steps.push(Step::SameWindow(Reply::Default));
            steps.push(Step::PanelScroll(ScrollGoal::of(code)));
            mapped(steps, Reply::Handled(0))
        }
        _ => mapped(Vec::new(), Reply::Default),
    }
}

fn map_ai_body(msg: &Msg) -> Mapped {
    match *msg {
        Msg::Paint => mapped(vec![Step::Paint], Reply::Handled(0)),
        // The panel never takes keyboard focus (spec/04 §3.8). A click opens or folds the body
        // of an inconsistent explanation.
        Msg::MouseDown { .. } => mapped(
            vec![
                Step::Event(InteractionEvent::OtherPress),
                Step::SameWindow(Reply::Handled(0)),
                Step::AiExpand,
                Step::FocusApproval,
            ],
            Reply::Handled(0),
        ),
        Msg::Wheel(delta) => mapped(vec![Step::AiWheel(delta)], Reply::Handled(0)),
        Msg::VScroll { code } => {
            let mut steps = Vec::new();
            if code != SB_ENDSCROLL {
                steps.push(Step::Event(InteractionEvent::OtherPress));
            }
            steps.push(Step::AiScroll(ScrollGoal::of(code)));
            mapped(steps, Reply::Handled(0))
        }
        _ => mapped(Vec::new(), Reply::Default),
    }
}

#[cfg(test)]
#[path = "approval_input_tests.rs"]
mod tests;
