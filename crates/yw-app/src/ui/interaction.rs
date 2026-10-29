//! Approval interaction state machine and approval gate (spec/04 §3.4).
//!
//! `ApprovalInteraction` is ported from `archive/spec-v2.4:crates/approval-ui/src/lib.rs:140-475`
//! (tests `:580-1006` → `tests/approval_interaction.rs`, AP-1) with the spec/04 §3.4 changes:
//! (1) the spec/03 levels map to the two interaction levels (`Info`/`Caution` → `Standard`,
//! `High` → `High`, `Blocked` → no approval at all; any non-`Ok` simulation state → `High`);
//! the stream codec and the one-shot `PRESENTED` guard are gone; (2) an `armed` flag set from
//! [`can_approve`] on every event and tick; (3) `physical_down` is filled by the window from
//! `input::is_down` (a consistency check, not a security boundary); (4) rapid-click lure
//! defence: every pointer or key press received while not armed, and every window
//! (re)activation, restarts the 1 s arm delay ([`ApprovalSession`]), and an approving press must
//! start at least 1 s after the previous press anywhere in the window
//! ([`InteractionEvent::is_press`]).

use yw_core::approval::{ApprovalRequest, RiskLevel, SimNoneReason, SimVerdict, SimulationBinding};

use crate::errors::ErrorCode;

/// Delay after content is shown (or after a restart: a press while not armed, a window
/// activation) before approval can be armed; also the minimum gap between the previous press
/// anywhere in the window and an approving press.
pub const APPROVE_ARM_DELAY_MS: u64 = 1_000;
/// Continuous hold for high-risk approval (D16; archive `HIGH_RISK_HOLD_MILLISECONDS`).
pub const HIGH_RISK_HOLD_MS: u64 = 2_000;
/// Approval window timer.
pub const APPROVAL_TICK_MS: u32 = 50;
/// A queued item with less remaining time is not shown (`TimedOut`).
pub const MIN_REMAINING_TO_SHOW_MS: u64 = 5_000;
/// Simulation wait bound.
pub const SIM_WAIT_MAX_MS: u64 = 10_000;
/// Largest interaction lifetime (the 600 s site deadline, D23).
pub const MAX_LIFETIME_MS: u64 = 600_000;

/// The two interaction levels of the ported state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InteractionRisk {
    /// Click (press and release on the button) or Enter/Space.
    Standard,
    /// Checkbox (gated by [`can_approve`]) plus a continuous 2 s hold; Enter ignored.
    High,
}

/// Source currently sustaining a high-risk hold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoldSource {
    /// Primary pointer button over the approval control.
    Pointer,
    /// Physical Space key while the approval control owns focus.
    Space,
}

impl HoldSource {
    const fn bit(self) -> u8 {
        match self {
            Self::Pointer => 1,
            Self::Space => 2,
        }
    }
}

/// Trusted UI event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InteractionEvent {
    /// Timer update.
    Tick,
    /// Enter on the approve button.
    ApproveActivated,
    /// Reject, close, Escape.
    RejectActivated,
    /// Primary pointer pressed over the approve button.
    PointerPressed {
        /// Inside the button rectangle.
        inside: bool,
        /// The press also activated a previously inactive window.
        click_through: bool,
        /// Physically down per `GetAsyncKeyState`.
        physical_down: bool,
    },
    /// Captured pointer moved.
    PointerMoved {
        /// Still inside the button.
        inside: bool,
    },
    /// Primary pointer released.
    PointerReleased {
        /// Still physically down.
        physical_down: bool,
    },
    /// Space pressed with the approve button focused.
    SpacePressed {
        /// Auto-repeat (lParam bit 30).
        repeat: bool,
        /// Physically down.
        physical_down: bool,
    },
    /// Space released.
    SpaceReleased {
        /// Still physically down.
        physical_down: bool,
    },
    /// Focus moved to another window.
    FocusLost,
    /// The window stopped being foreground.
    ForegroundLost,
    /// Unexpected capture loss.
    CaptureLost,
    /// `WM_CANCELMODE`.
    CancelMode,
    /// Any other pointer or key press in the window (another button, the panel, a scroll bar, a
    /// non-approval key, auto-repeat included): never an approval input, but it counts as the
    /// previous press for the press-gap rule and, while not armed, restarts the arm delay.
    OtherPress,
}

impl InteractionEvent {
    /// Whether this event is a pointer or key press (auto-repeat included). An approving press
    /// (`ApproveActivated`, `PointerPressed`, `SpacePressed`) must start at least
    /// [`APPROVE_ARM_DELAY_MS`] after the previous press of any kind.
    #[must_use]
    pub const fn is_press(self) -> bool {
        matches!(
            self,
            Self::ApproveActivated
                | Self::PointerPressed { .. }
                | Self::SpacePressed { .. }
                | Self::OtherPress
        )
    }
}

/// Interaction status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InteractionStatus {
    /// No decision.
    Pending,
    /// Approval requirements were satisfied.
    Approved,
    /// Rejected, expired or time went backwards.
    Rejected,
}

/// Invalid interaction parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InteractionError;

/// The pure, deterministic approval interaction (times are monotonic milliseconds).
#[derive(Debug)]
pub struct ApprovalInteraction {
    risk: Option<InteractionRisk>,
    deadline_ms: u64,
    last_now_ms: u64,
    status: InteractionStatus,
    active_hold: Option<(HoldSource, u64)>,
    blocked_inputs: u8,
    armed: bool,
    /// The most recent press of any kind (see [`InteractionEvent::is_press`]).
    last_press_ms: Option<u64>,
}

impl ApprovalInteraction {
    /// A bounded interaction expiring `expires_after_ms` after `now_ms`. `risk = None` is the
    /// blocked level: nothing but reject is possible.
    ///
    /// # Errors
    ///
    /// Zero or overlong lifetime, or timestamp overflow.
    pub fn new(
        risk: impl Into<Option<InteractionRisk>>,
        expires_after_ms: u64,
        now_ms: u64,
    ) -> Result<Self, InteractionError> {
        if !(1..=MAX_LIFETIME_MS).contains(&expires_after_ms) {
            return Err(InteractionError);
        }
        let deadline_ms = now_ms
            .checked_add(expires_after_ms)
            .ok_or(InteractionError)?;
        Ok(Self {
            risk: risk.into(),
            deadline_ms,
            last_now_ms: now_ms,
            status: InteractionStatus::Pending,
            active_hold: None,
            blocked_inputs: 0,
            armed: true,
            last_press_ms: None,
        })
    }

    /// Arms or disarms approval input (spec/04 §3.4-2). Disarming clears an active hold and
    /// blocks its source until physically released.
    pub fn set_armed(&mut self, now_ms: u64, armed: bool) {
        if self.status != InteractionStatus::Pending {
            return;
        }
        if now_ms < self.last_now_ms {
            self.reject();
            return;
        }
        self.last_now_ms = now_ms;
        if !armed && let Some((source, _)) = self.active_hold {
            self.reset_source(source);
        }
        self.armed = armed;
    }

    /// Whether approval input is currently armed.
    #[must_use]
    pub const fn is_armed(&self) -> bool {
        self.armed
    }

    /// The most recent press of any kind seen by [`Self::apply`].
    #[must_use]
    pub const fn last_press_ms(&self) -> Option<u64> {
        self.last_press_ms
    }

    /// Whether a press starting at `now_ms` is far enough from the previous press anywhere in the
    /// window to be an approving press.
    #[must_use]
    pub fn press_spaced(&self, now_ms: u64) -> bool {
        self.last_press_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= APPROVE_ARM_DELAY_MS)
    }

    /// Applies one event.
    pub fn apply(&mut self, now_ms: u64, event: InteractionEvent) -> InteractionStatus {
        if self.status != InteractionStatus::Pending {
            return self.status;
        }
        if now_ms < self.last_now_ms {
            self.reject();
            return self.status;
        }
        self.last_now_ms = now_ms;
        if now_ms >= self.deadline_ms {
            self.reject();
            return self.status;
        }
        // Judged against the press before this one; then this press becomes the previous one.
        let spaced = !event.is_press() || self.press_spaced(now_ms);
        if event.is_press() {
            self.last_press_ms = Some(now_ms);
        }
        if self.resets_before_completion(event) {
            self.reset_for_event(event);
            return self.status;
        }
        if self.hold_completed(now_ms) {
            self.approve();
            return self.status;
        }
        match event {
            InteractionEvent::ApproveActivated => {
                if self.risk == Some(InteractionRisk::Standard) && self.armed && spaced {
                    self.approve();
                }
            }
            InteractionEvent::RejectActivated => self.reject(),
            InteractionEvent::PointerPressed {
                inside,
                click_through,
                physical_down: true,
            } => {
                if click_through || !inside {
                    self.block(HoldSource::Pointer);
                } else {
                    self.begin_hold(HoldSource::Pointer, now_ms, spaced);
                }
            }
            InteractionEvent::PointerReleased {
                physical_down: false,
            } => self.release_source(HoldSource::Pointer),
            InteractionEvent::SpacePressed {
                repeat: false,
                physical_down: true,
            } => self.begin_hold(HoldSource::Space, now_ms, spaced),
            InteractionEvent::SpaceReleased {
                physical_down: false,
            } => self.release_source(HoldSource::Space),
            InteractionEvent::Tick
            | InteractionEvent::PointerMoved { .. }
            | InteractionEvent::PointerPressed { .. }
            | InteractionEvent::PointerReleased { .. }
            | InteractionEvent::SpacePressed { .. }
            | InteractionEvent::SpaceReleased { .. }
            | InteractionEvent::FocusLost
            | InteractionEvent::ForegroundLost
            | InteractionEvent::CaptureLost
            | InteractionEvent::CancelMode
            | InteractionEvent::OtherPress => {}
        }
        self.status
    }

    /// Current status.
    #[must_use]
    pub const fn status(&self) -> InteractionStatus {
        self.status
    }

    /// Source sustaining a hold.
    #[must_use]
    pub const fn hold_source(&self) -> Option<HoldSource> {
        match self.active_hold {
            Some((source, _)) => Some(source),
            None => None,
        }
    }

    /// Whether `source` must be released before it can start again.
    #[must_use]
    pub const fn is_blocked(&self, source: HoldSource) -> bool {
        self.blocked_inputs & source.bit() != 0
    }

    /// Remaining hold time.
    #[must_use]
    pub fn hold_remaining_ms(&self, now_ms: u64) -> Option<u64> {
        self.active_hold
            .map(|(_, started)| HIGH_RISK_HOLD_MS.saturating_sub(now_ms.saturating_sub(started)))
    }

    /// Remaining lifetime.
    #[must_use]
    pub const fn lifetime_remaining_ms(&self, now_ms: u64) -> u64 {
        self.deadline_ms.saturating_sub(now_ms)
    }

    /// `spaced`: the press started at least [`APPROVE_ARM_DELAY_MS`] after the previous press.
    fn begin_hold(&mut self, source: HoldSource, now_ms: u64, spaced: bool) {
        if self.armed
            && spaced
            && self.risk.is_some()
            && self.active_hold.is_none()
            && !self.is_blocked(source)
        {
            self.active_hold = Some((source, now_ms));
        }
    }

    fn release_source(&mut self, source: HoldSource) {
        if self.risk == Some(InteractionRisk::Standard)
            && self.armed
            && self.hold_source() == Some(source)
        {
            self.approve();
            return;
        }
        self.clear_hold(source);
        self.unblock(source);
    }

    fn hold_completed(&self, now_ms: u64) -> bool {
        self.risk == Some(InteractionRisk::High)
            && self.armed
            && self
                .active_hold
                .is_some_and(|(_, started)| now_ms.saturating_sub(started) >= HIGH_RISK_HOLD_MS)
    }

    fn reset_for_event(&mut self, event: InteractionEvent) {
        match event {
            InteractionEvent::PointerMoved { inside: false } | InteractionEvent::CaptureLost => {
                self.reset_source(HoldSource::Pointer);
            }
            InteractionEvent::PointerPressed { .. } | InteractionEvent::PointerReleased { .. } => {
                self.reset_input_attempt(HoldSource::Pointer);
            }
            InteractionEvent::SpacePressed { .. } | InteractionEvent::SpaceReleased { .. } => {
                self.reset_input_attempt(HoldSource::Space);
            }
            InteractionEvent::FocusLost
            | InteractionEvent::ForegroundLost
            | InteractionEvent::CancelMode => {
                if let Some((source, _)) = self.active_hold {
                    self.reset_source(source);
                }
            }
            _ => {}
        }
    }

    fn reset_source(&mut self, source: HoldSource) {
        self.clear_hold(source);
        self.block(source);
    }

    fn reset_input_attempt(&mut self, attempted: HoldSource) {
        if let Some((active, _)) = self.active_hold {
            self.reset_source(active);
        }
        self.block(attempted);
    }

    fn clear_hold(&mut self, source: HoldSource) {
        if self.hold_source() == Some(source) {
            self.active_hold = None;
        }
    }

    const fn block(&mut self, source: HoldSource) {
        self.blocked_inputs |= source.bit();
    }

    const fn unblock(&mut self, source: HoldSource) {
        self.blocked_inputs &= !source.bit();
    }

    const fn approve(&mut self) {
        self.active_hold = None;
        self.status = InteractionStatus::Approved;
    }

    const fn reject(&mut self) {
        self.active_hold = None;
        self.status = InteractionStatus::Rejected;
    }

    fn resets_before_completion(&self, event: InteractionEvent) -> bool {
        match event {
            InteractionEvent::PointerMoved { inside: false }
            | InteractionEvent::FocusLost
            | InteractionEvent::ForegroundLost
            | InteractionEvent::CaptureLost
            | InteractionEvent::CancelMode => true,
            InteractionEvent::PointerPressed {
                inside,
                click_through,
                physical_down,
            } => !inside || click_through || !physical_down || self.hold_source().is_some(),
            InteractionEvent::PointerReleased { physical_down }
            | InteractionEvent::SpaceReleased { physical_down } => physical_down,
            InteractionEvent::SpacePressed {
                repeat,
                physical_down,
            } => {
                !physical_down
                    || (repeat && self.hold_source() != Some(HoldSource::Space))
                    || (!repeat && self.hold_source().is_some())
            }
            _ => false,
        }
    }
}

/// Simulation state of an EVM transaction approval (spec/04 §3.2.1, classification spec/03 §6.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SimState {
    /// Simulated and interpreted.
    Ok,
    /// `simulation = unsupported` (E36).
    Unsupported,
    /// No result (E01).
    NoResult,
    /// Reverted (E02).
    Reverted,
    /// Partially interpreted (E03/E04/E07–E09).
    Incomplete,
}

/// `Some` only for the three EVM transaction kinds that reached simulation.
#[must_use]
pub fn sim_state(request: &ApprovalRequest) -> Option<SimState> {
    if !request.kind.is_evm_transaction() {
        return None;
    }
    match request.simulation {
        SimulationBinding::NotApplicable
        | SimulationBinding::None {
            reason: SimNoneReason::Skipped,
        } => None,
        SimulationBinding::Simulated { verdict, .. } => Some(match verdict {
            SimVerdict::Ok => SimState::Ok,
            SimVerdict::Reverted => SimState::Reverted,
            SimVerdict::Incomplete => SimState::Incomplete,
        }),
        SimulationBinding::None {
            reason: SimNoneReason::Unsupported,
        } => Some(SimState::Unsupported),
        SimulationBinding::None { .. } => Some(SimState::NoResult),
    }
}

/// The interaction level of a request (spec/04 §3.4-1): `None` = blocked.
#[must_use]
pub fn interaction_risk(request: &ApprovalRequest) -> Option<InteractionRisk> {
    if request.display.risk == RiskLevel::Blocked {
        return None;
    }
    let unsuccessful = matches!(sim_state(request), Some(state) if state != SimState::Ok);
    Some(if request.display.risk == RiskLevel::High || unsuccessful {
        InteractionRisk::High
    } else {
        InteractionRisk::Standard
    })
}

/// D16: one checkbox when the level is high (also for inconsistent inputs, defence in depth).
#[must_use]
pub fn ack_needed(request: &ApprovalRequest) -> bool {
    request.display.ack_required
        || request.display.risk == RiskLevel::High
        || matches!(sim_state(request), Some(state) if state != SimState::Ok)
}

/// Preparation stage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrepareStage {
    /// Building the request.
    Building,
    /// `eth_simulateV1` in flight since this monotonic time.
    Simulating {
        /// Start.
        since_ms: u64,
    },
}

/// The connect window content (spec/05 §4.2; filled at M5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectView {
    /// Accounts offered.
    pub accounts: usize,
}

/// Ready content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReadyContent {
    /// A signing request.
    Signing(Box<ApprovalRequest>),
    /// A site connection.
    Connect(ConnectView),
}

/// Preparation state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PrepareState {
    /// Still preparing.
    Preparing(PrepareStage),
    /// Content shown.
    Ready(ReadyContent),
    /// The transaction could not be built.
    Failed {
        /// Error.
        code: ErrorCode,
        /// `다시 시도` offered.
        retryable: bool,
    },
}

/// The per-window gate (spec/04 §3.4). No AI explanation state is an input (AP-5, spec/06 E2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovalGate {
    /// Preparation state.
    pub prepare: PrepareState,
    /// The single acknowledgement checkbox (D16).
    pub ack_checked: bool,
    /// Accounts selected in a connect window.
    pub connect_selected: usize,
    /// Start of the current arm delay: when Ready content was (re)shown, or later when the delay
    /// was restarted (a press while not armed, a window activation; see [`ApprovalSession`]).
    pub ready_at_ms: u64,
    /// The window is foreground.
    pub is_foreground: bool,
    /// `min(site deadline, shown + 120 s)`.
    pub deadline_ms: u64,
    /// Approval submitted, waiting for consume/re-simulation.
    pub submitting: bool,
}

/// Whether approval input may be armed now.
#[must_use]
pub fn can_approve(gate: &ApprovalGate, now_ms: u64) -> bool {
    let (content_ok, ack_required) = match &gate.prepare {
        PrepareState::Ready(ReadyContent::Signing(request)) => (
            request.display.risk != RiskLevel::Blocked,
            ack_needed(request),
        ),
        PrepareState::Ready(ReadyContent::Connect(_)) => {
            ((1..=16).contains(&gate.connect_selected), false)
        }
        PrepareState::Preparing(_) | PrepareState::Failed { .. } => (false, false),
    };
    content_ok
        && (!ack_required || gate.ack_checked)
        && now_ms >= gate.ready_at_ms.saturating_add(APPROVE_ARM_DELAY_MS)
        && gate.is_foreground
        && now_ms < gate.deadline_ms
        && !gate.submitting
}

/// A gate plus its interaction: the unit the approval window drives (spec/04 §3.4 "매 이벤트와
/// 50 ms 타이머마다 `set_armed(now, can_approve(..))`").
#[derive(Debug)]
pub struct ApprovalSession {
    /// Gate.
    pub gate: ApprovalGate,
    interaction: ApprovalInteraction,
}

impl ApprovalSession {
    fn interaction_for(
        gate: &ApprovalGate,
        now_ms: u64,
    ) -> Result<ApprovalInteraction, InteractionError> {
        let risk = match &gate.prepare {
            PrepareState::Ready(ReadyContent::Signing(request)) => interaction_risk(request),
            PrepareState::Ready(ReadyContent::Connect(_)) => Some(InteractionRisk::Standard),
            PrepareState::Preparing(_) | PrepareState::Failed { .. } => None,
        };
        let lifetime = gate
            .deadline_ms
            .saturating_sub(now_ms)
            .clamp(1, MAX_LIFETIME_MS);
        ApprovalInteraction::new(risk, lifetime, now_ms)
    }

    /// Starts a session.
    ///
    /// # Errors
    ///
    /// [`InteractionError`] for an invalid deadline.
    pub fn new(gate: ApprovalGate, now_ms: u64) -> Result<Self, InteractionError> {
        let interaction = Self::interaction_for(&gate, now_ms)?;
        Ok(Self { gate, interaction })
    }

    /// Re-arms from the gate, then applies `event`. A press (any pointer or key press, see
    /// [`InteractionEvent::is_press`]) received while not armed first restarts the arm delay.
    pub fn event(&mut self, now_ms: u64, event: InteractionEvent) -> InteractionStatus {
        if event.is_press() && !can_approve(&self.gate, now_ms) {
            self.gate.ready_at_ms = self.gate.ready_at_ms.max(now_ms);
        }
        let armed = can_approve(&self.gate, now_ms);
        self.interaction.set_armed(now_ms, armed);
        self.interaction.apply(now_ms, event)
    }

    /// Restarts the 1 s arm delay at `now_ms` (window activation) and disarms at once.
    pub fn restart_arm_delay(&mut self, now_ms: u64) {
        self.gate.ready_at_ms = self.gate.ready_at_ms.max(now_ms);
        let armed = can_approve(&self.gate, now_ms);
        self.interaction.set_armed(now_ms, armed);
    }

    /// Records whether the window is foreground; a (re)activation (`false` → `true`) restarts
    /// the arm delay.
    pub fn set_foreground(&mut self, now_ms: u64, foreground: bool) {
        let activated = foreground && !self.gate.is_foreground;
        self.gate.is_foreground = foreground;
        if activated {
            self.restart_arm_delay(now_ms);
        }
    }

    /// Whether an approving press starting at `now_ms` would be accepted (the approve button's
    /// armed look): armed, the gate open, and at least 1 s since the previous press anywhere in
    /// the window, or a hold already under way.
    #[must_use]
    pub fn approve_ready(&self, now_ms: u64) -> bool {
        self.interaction.is_armed()
            && can_approve(&self.gate, now_ms)
            && (self.interaction.hold_source().is_some() || self.interaction.press_spaced(now_ms))
    }

    /// Toggles the acknowledgement checkbox.
    pub fn set_ack(&mut self, now_ms: u64, checked: bool) {
        self.gate.ack_checked = checked;
        let armed = can_approve(&self.gate, now_ms);
        self.interaction.set_armed(now_ms, armed);
    }

    /// Replaces the shown content (ready, re-simulation): clears any hold and the checkbox,
    /// restarts the arm delay and the interaction (same deadline).
    ///
    /// # Errors
    ///
    /// [`InteractionError`] when the deadline has passed.
    pub fn replace_content(
        &mut self,
        now_ms: u64,
        prepare: PrepareState,
    ) -> Result<(), InteractionError> {
        self.gate.prepare = prepare;
        self.gate.ack_checked = false;
        self.gate.ready_at_ms = now_ms;
        self.gate.submitting = false;
        self.renew_interaction(now_ms)
    }

    /// Starts a fresh interaction for the same content and gate (checkbox, arm delay and
    /// `submitting` unchanged): an `Approved` status is terminal for the state machine, so once
    /// it has been acted on (a re-simulation dispatched, spec/03 §6.6) the next approval must
    /// come from new input, never from the stale status on the following tick.
    ///
    /// # Errors
    ///
    /// [`InteractionError`] when the deadline has passed.
    pub fn restart_interaction(&mut self, now_ms: u64) -> Result<(), InteractionError> {
        self.renew_interaction(now_ms)
    }

    /// A fresh interaction that still remembers the last press: the press-gap rule spans
    /// content replacement and restarts.
    fn renew_interaction(&mut self, now_ms: u64) -> Result<(), InteractionError> {
        let last_press_ms = self.interaction.last_press_ms;
        self.interaction = Self::interaction_for(&self.gate, now_ms)?;
        self.interaction.last_press_ms = last_press_ms;
        Ok(())
    }

    /// The interaction (read-only).
    #[must_use]
    pub const fn interaction(&self) -> &ApprovalInteraction {
        &self.interaction
    }
}
