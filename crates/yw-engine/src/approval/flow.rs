//! Approval-flow decisions and the approval window ↔ flow protocol (spec/04 §3, spec/03 §11,
//! spec/15 §11.4 S4). Not the send flows of [`crate::flow`].
//!
//! 2026-11-19 (spec/15 §11.4 S4 B3): created. The pure decisions moved here unchanged from yw-app
//! `app_approval.rs`, which calls them at the same points: [`status_action`] (what one interaction
//! event did), [`session_deadline`] (the gate deadline `open_approval` computed),
//! [`connect_gate_count`] (the body of `ConnectState::gate_count`) and [`bar_facts`] (the part of
//! `bar_state` that is not text assembly, with `next_step` and the button label). The interaction
//! state machine ([`super::interaction`]), `can_approve`, the queue and the store are unchanged.
//! The window ↔ flow types [`ShownId`], [`ApprovalInput`], [`ApprovalSignal`], [`ApprovalEffect`]
//! and [`OpenOutcome`] are not used yet; S4 B4–B6 wire them. 2026-11-19 (S4 B5): the window's
//! operations are [`ApprovalEffect`]s inside `Effect::Approval` (applied at once by the Windows
//! executor then; 2026-11-20, S4 P10b: queued and applied when the shell entry drains, in
//! emission order, before it returns), the open is answered with `Cmd::ApprovalOpened` carrying its [`OpenOutcome`] and the
//! width class, and every flow carries its [`ShownId`]; [`ApprovalInput`] and [`ApprovalSignal`]
//! wait for B6. 2026-11-19 (S4 B6): the window sends its inputs as `Cmd::Approval`
//! ([`ApprovalInput`]): the [`ShownId`] of the window that got the message (captured when that
//! window was made), its foreground sample for an interaction event and one [`ApprovalSignal`];
//! the flow drops an input of a window that is not the shown one. [`ApprovalEffect::Redraw`] is
//! the acknowledgement checkbox's repaint.

use core::fmt;

use yw_core::lang::{Lang, Text};

use crate::approval::interaction::{
    ApprovalSession, HIGH_RISK_HOLD_MS, InteractionEvent, InteractionStatus, MAX_LIFETIME_MS,
    PrepareStage, PrepareState,
};
use crate::approval::text;
use crate::approval::view::ApprovalView;
use crate::errors::ErrorCode;

/// One opened approval window: a fresh serial at every open, never reused. The idle identity of
/// the shown approval stays its queue item id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShownId(pub u64);

/// What one approval window saw while one of its messages was processed. Built only by the
/// platform's input mapper from the window that received the message; never stored, posted or
/// queued past that message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ApprovalInput {
    /// The window that received the message (an input for another window is dropped).
    pub shown: ShownId,
    /// The window's foreground sample taken before the signal; applied to the session for
    /// [`ApprovalSignal::Event`] and the close box's `RejectActivated` ([`ApprovalSignal::Close`])
    /// only, the inputs that are interaction events (2026-11-19, S4 B6: `false`, never read, for
    /// the others, which take no sample).
    pub foreground: bool,
    /// What happened.
    pub signal: ApprovalSignal,
}

/// One input of the approval window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalSignal {
    /// An interaction event (the 50 ms window timer is `Event(Tick)`, then
    /// [`Self::TimerTail`]: the AI tick and the simulating-countdown rebuild).
    Event(InteractionEvent),
    /// The window was activated: restart the arm delay unconditionally, then mark it foreground.
    Activated,
    /// The close box: `Event(RejectActivated)`, then finish `Rejected` only if this window is
    /// still the shown one.
    Close,
    /// The acknowledgement box was toggled.
    ToggleAck,
    /// The raw-data fold was toggled.
    ToggleRaw,
    /// A connect account was toggled on the list as drawn at `view_rev`; a toggle drawn from an
    /// older list is dropped.
    ToggleAccount {
        /// The entry's position in the drawn list.
        index: u16,
        /// The revision of the drawn account list.
        view_rev: u64,
    },
    /// `시뮬레이션 다시 실행` was pressed.
    Retry,
    /// The AI panel's `다시 요청` was pressed.
    AiRetry,
    /// The window's width class changed; the view is rebuilt.
    Resized {
        /// The wide layout applies.
        wide: bool,
    },
    /// The AI body was clicked (`ai.down`, spec/06 §3.2): an inconsistent explanation opens or
    /// folds; when it did, [`ApprovalEffect::AiToggled`]. 2026-11-24 (spec/15 §11.4 S5-10, S5
    /// plan owner item O-12): before, the shell's `Step::AiExpand` flipped the shown flow's panel
    /// itself (the wallet's `toggle_ai_panel`), with no id check.
    AiExpand,
    /// The AI body is about to paint: its text is held while a High-risk request's
    /// acknowledgement checkbox is clear (`held_for_ack`, spec/06 §3.2; the AI panel's flag only,
    /// never the gate). 2026-11-24 (S5-10): before, the shell's paint called the wallet's
    /// `hold_shown_ai_for_ack` on the shown flow, with no id check.
    AiPaint,
    /// The rest of the window's 50 ms timer after its `Event(Tick)`: the AI tick, then the
    /// simulating-countdown rebuild. Taken only right after that window's own `Tick` passed the id
    /// check, and run on the flow shown then — the next request's when the `Tick` ended this one
    /// and opened the next (an expiry), as before. 2026-11-24 (S5-10): before, the shell's
    /// `Step::TimerTail` called the wallet's `ai_tick` and `rebuild_view_with` on the shown flow,
    /// with no id check (spec/15 §11.4 S4 B6 review).
    TimerTail,
}

/// What the approval flow asks the shell to do with the approval window (never coalesced).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalEffect {
    /// Create the window, its panel and (when reserved) the AI body: topmost, centred on the main
    /// window, 50 ms timer, shown, brought to the foreground or flashed, focus on `거부`.
    /// Answered with the open's outcome.
    Open {
        /// The new window.
        shown: ShownId,
        /// The window's language, fixed while it is shown.
        lang: Lang,
        /// Room for the AI explanation panel is reserved.
        ai_reserved: bool,
        /// A connect window (its title; 2026-11-19, S4 B5: added, the sketch had no title).
        connect: bool,
    },
    /// Stop the timer, destroy the windows and return the foreground to the main window. The
    /// flow sends it whenever it ends, also before its open was answered; for a window the shell
    /// never made (or already closed) it does nothing.
    Close {
        /// The window.
        shown: ShownId,
    },
    /// The view model was rebuilt: lay it out again and repaint when it changed.
    Rebuilt {
        /// The window.
        shown: ShownId,
        /// The view differs from the one drawn.
        changed: bool,
    },
    /// Only the bottom bar may have changed: repaint it when what it shows changed.
    RepaintBar {
        /// The window.
        shown: ShownId,
    },
    /// What the window draws changed without a new view (the acknowledgement checkbox): lay it
    /// out again and repaint the panel, the window and the AI body (2026-11-19, S4 B6).
    Redraw {
        /// The window.
        shown: ShownId,
    },
    /// The AI explanation's state changed: repaint the AI body and, unless `body_only`, the
    /// window (2026-11-22, S4 W14a: before, the AI flow invalidated them itself). `body_only` is
    /// the once-a-second redraw of a request's elapsed time; any other change of the AI panel
    /// (a request handed to the worker, its result, a skip, a retry) repaints both.
    RepaintAi {
        /// The window.
        shown: ShownId,
        /// Only the AI body (the elapsed time while a request waits).
        body_only: bool,
    },
    /// The AI panel's explanation opened or folded ([`ApprovalSignal::AiExpand`]): the AI body's
    /// scroll goes back to the top and the AI body is repainted (2026-11-24, spec/15 §11.4 S5-10:
    /// before, the shell's `Step::AiExpand` did both right after the flip).
    AiToggled {
        /// The window.
        shown: ShownId,
    },
}

/// The outcome of opening a window the logic asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenOutcome {
    /// The window exists and is shown.
    Shown {
        /// Its capture exclusion was verified (secret windows).
        capture_excluded: bool,
    },
    /// The platform refused the window (for example: capture exclusion unavailable).
    Refused(ErrorCode),
    /// The window could not be created.
    Failed(ErrorCode),
}

/// What the window does after an interaction event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusAction {
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

/// What one interaction event did, from the interaction status before and after it.
#[must_use]
pub fn status_action(
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

/// The gate deadline of an approval window opened at `now`: the site deadline of a dApp request
/// (`site_deadline`), `now + MAX_LIFETIME_MS` for the app's own requests, and never earlier than
/// `now + 1`.
#[must_use]
pub fn session_deadline(site_deadline: Option<u64>, now: u64) -> u64 {
    site_deadline
        .unwrap_or(now.saturating_add(MAX_LIFETIME_MS))
        .max(now.saturating_add(1))
}

/// The gate's `connect_selected` for a connect window (spec/05 §4.2, §4.9): the checked count
/// for EVM; for Solana and Bitcoin the count when each of the `groups` radio groups has exactly
/// one checked choice, else 0 (approve disabled). `entries` and `selected` pair up in list order;
/// `group_of` names an entry's radio group.
#[must_use]
pub fn connect_gate_count<E>(
    entries: &[E],
    group_of: fn(&E) -> u8,
    selected: &[bool],
    groups: u8,
    evm: bool,
) -> usize {
    let count = selected.iter().filter(|checked| **checked).count();
    if evm {
        return count;
    }
    let complete = (0..groups).all(|group| {
        entries
            .iter()
            .zip(selected)
            .filter(|(entry, checked)| group_of(entry) == group && **checked)
            .count()
            == 1
    });
    if complete { count } else { 0 }
}

/// The last part of the countdown, drawn in the caution colour (spec/04 §3.2 하단).
pub const URGENT_REMAINING_MS: u64 = 30_000;

/// What the bottom bar of the approval window reads from the shown approval.
#[derive(Clone, Copy)]
pub struct BarSource<'a> {
    /// The window's language.
    pub lang: Lang,
    /// The gate and its interaction.
    pub session: &'a ApprovalSession,
    /// The view drawn.
    pub view: &'a ApprovalView,
    /// A connect window.
    pub connect: bool,
    /// A high-risk hold was let go before 2 s (until the next press).
    pub early_release: bool,
    /// The status message.
    pub status: Option<&'a str>,
}

/// Names only: never the status text (D28).
impl fmt::Debug for BarSource<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BarSource")
            .field("lang", &self.lang)
            .field("connect", &self.connect)
            .field("early_release", &self.early_release)
            .field("status_len", &self.status.map(str::len))
            .finish_non_exhaustive()
    }
}

/// What the bottom bar shows apart from assembling its text (spec/04 §3.2 하단). Display only:
/// the gate is never read back from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BarFacts {
    /// Time left until the gate deadline.
    pub remaining_ms: u64,
    /// The content is ready: the countdown is shown.
    pub countdown: bool,
    /// [`URGENT_REMAINING_MS`] or less is left: the countdown is drawn in the caution colour.
    pub urgent: bool,
    /// Milliseconds held so far while a high-risk hold is under way.
    pub held_ms: Option<u64>,
    /// The user's next step.
    pub step: Option<Text>,
    /// The approve button's label.
    pub label: Text,
    /// The approve button is armed.
    pub armed: bool,
}

/// The bottom bar's facts at `now`.
#[must_use]
pub fn bar_facts(source: &BarSource<'_>, now: u64) -> BarFacts {
    let gate = &source.session.gate;
    let remaining_ms = gate.deadline_ms.saturating_sub(now);
    let held_ms = source
        .session
        .interaction()
        .hold_remaining_ms(now)
        .map(|left| HIGH_RISK_HOLD_MS.saturating_sub(left));
    let step = next_step(source, held_ms.is_some(), now);
    let simulating = matches!(
        gate.prepare,
        PrepareState::Preparing(PrepareStage::Simulating { .. })
    ) || (gate.submitting
        && source
            .status
            .is_some_and(|status| simulating_status(source.lang, status)));
    let label = if source.connect {
        text::CONNECT
    } else if source.view.blocked {
        text::CANNOT_APPROVE
    } else if simulating {
        text::SIMULATING_BUTTON
    } else if source.view.high {
        text::APPROVE_HOLD
    } else {
        text::APPROVE
    };
    BarFacts {
        remaining_ms,
        countdown: matches!(gate.prepare, PrepareState::Ready(_)),
        urgent: remaining_ms <= URGENT_REMAINING_MS,
        held_ms,
        step,
        label,
        armed: source.session.approve_ready(now),
    }
}

/// The user's next step on the status line (display only; the gate is unchanged): what is still
/// to do, then why the button waits (the 1 s arm delay, spec/04 §3.4-2), then how to approve a
/// high-risk request.
fn next_step(source: &BarSource<'_>, held: bool, now: u64) -> Option<Text> {
    let session = source.session;
    let gate = &session.gate;
    if source.view.blocked || held || gate.submitting || now >= gate.deadline_ms {
        return None;
    }
    let step = if session.connect_empty() {
        text::CONNECT_PICK
    } else if session.ack_missing() {
        text::ACK_FIRST
    } else if source.early_release {
        text::HOLD_EARLY
    } else if session.arm_waiting(now) {
        // Why the button is grey (review 2026-11-07 F7); the arm delay itself is unchanged.
        if gate.is_foreground {
            text::ARM_WAIT
        } else {
            text::ARM_WAIT_BACKGROUND
        }
    } else if source.view.high && session.approve_ready(now) {
        text::HOLD_NOW
    } else {
        return None;
    };
    Some(step)
}

/// Whether `event` lets go of a hold (pointer or Space release): a High-risk hold released before
/// 2 s marks the status line (`early_release`). 2026-11-22 (spec/15 §11.4 S4d E0a): was yw-app
/// `ui::approval_input::is_release`; the flow calls it, the window's map does not.
#[must_use]
pub const fn is_release(event: InteractionEvent) -> bool {
    matches!(
        event,
        InteractionEvent::PointerReleased { .. } | InteractionEvent::SpaceReleased { .. }
    )
}

/// Whether a status message says a simulation is under way or just changed the content.
fn simulating_status(lang: Lang, status: &str) -> bool {
    status.starts_with(text::SIMULATING_BUTTON.get(lang).trim_end_matches('…'))
        || status.starts_with(text::SIM_CHANGED.get(lang))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::interaction::{ApprovalGate, ConnectView, ReadyContent};

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
    fn the_session_deadline_is_the_site_deadline_or_the_longest_lifetime() {
        assert_eq!(session_deadline(Some(70_000), 10_000), 70_000);
        assert_eq!(session_deadline(None, 10_000), 10_000 + MAX_LIFETIME_MS);
        // Never at or before the open itself.
        assert_eq!(session_deadline(Some(5_000), 10_000), 10_001);
        assert_eq!(session_deadline(Some(10_000), 10_000), 10_001);
        assert_eq!(session_deadline(None, u64::MAX), u64::MAX);
    }

    #[test]
    fn connect_gate_count_needs_one_choice_per_group_off_evm() {
        let group = |entry: &u8| *entry;
        // EVM: the checked count, whatever the groups.
        assert_eq!(
            connect_gate_count(&[0, 0, 0], group, &[true, false, true], 0, true),
            2
        );
        // Bitcoin: two purposes, one choice each.
        let entries = [0_u8, 0, 1, 1];
        assert_eq!(
            connect_gate_count(&entries, group, &[true, false, false, true], 2, false),
            2
        );
        assert_eq!(
            connect_gate_count(&entries, group, &[true, false, false, false], 2, false),
            0
        );
        assert_eq!(
            connect_gate_count(&entries, group, &[true, true, false, true], 2, false),
            0
        );
        // Solana: one group.
        assert_eq!(
            connect_gate_count(&[0_u8, 0], group, &[false, true], 1, false),
            1
        );
        assert_eq!(
            connect_gate_count(&[0_u8, 0], group, &[false, false], 1, false),
            0
        );
    }

    fn connect_session(selected: usize, now: u64) -> ApprovalSession {
        let gate = ApprovalGate {
            prepare: PrepareState::Ready(ReadyContent::Connect(ConnectView { accounts: 2 })),
            ack_checked: false,
            connect_selected: selected,
            ready_at_ms: now,
            is_foreground: false,
            deadline_ms: now.saturating_add(120_000),
            submitting: false,
        };
        ApprovalSession::new(gate, now).unwrap()
    }

    #[test]
    fn bar_facts_name_the_next_step_and_the_label() {
        let view = ApprovalView::default();
        let empty = connect_session(0, 1_000);
        let source = BarSource {
            lang: Lang::En,
            session: &empty,
            view: &view,
            connect: true,
            early_release: false,
            status: None,
        };
        let facts = bar_facts(&source, 1_000);
        assert_eq!(facts.step, Some(text::CONNECT_PICK));
        assert_eq!(facts.label, text::CONNECT);
        assert!(facts.countdown && !facts.urgent && !facts.armed);
        assert_eq!((facts.remaining_ms, facts.held_ms), (120_000, None));

        let mut chosen = connect_session(1, 1_000);
        assert_eq!(
            bar_facts(
                &BarSource {
                    session: &chosen,
                    ..source
                },
                1_500
            )
            .step,
            Some(text::ARM_WAIT_BACKGROUND)
        );
        chosen.set_foreground(1_500, true);
        let facts = bar_facts(
            &BarSource {
                session: &chosen,
                ..source
            },
            1_600,
        );
        assert_eq!(facts.step, Some(text::ARM_WAIT));
        assert!(!facts.armed);
        // Armed by the tick after the delay: no step for a standard request.
        let _ = chosen.event(2_600, InteractionEvent::Tick);
        let source = BarSource {
            session: &chosen,
            ..source
        };
        let facts = bar_facts(&source, 2_600);
        assert_eq!(facts.step, None);
        assert!(facts.armed);
        // The last 30 s are urgent; past the deadline there is no step.
        let facts = bar_facts(&source, 1_000 + 120_000 - URGENT_REMAINING_MS);
        assert!(facts.urgent);
        assert_eq!(bar_facts(&source, 121_000).step, None);

        let blocked = ApprovalView {
            blocked: true,
            ..ApprovalView::default()
        };
        let preparing = ApprovalSession::new(
            ApprovalGate {
                prepare: PrepareState::Preparing(PrepareStage::Building),
                ..connect_session(0, 0).gate
            },
            0,
        )
        .unwrap();
        let source = BarSource {
            lang: Lang::Ko,
            session: &preparing,
            view: &blocked,
            connect: false,
            early_release: false,
            status: None,
        };
        let facts = bar_facts(&source, 0);
        assert_eq!((facts.label, facts.step), (text::CANNOT_APPROVE, None));
        assert!(!facts.countdown);
        let high = ApprovalView {
            high: true,
            ..ApprovalView::default()
        };
        let source = BarSource {
            view: &high,
            ..source
        };
        assert_eq!(bar_facts(&source, 0).label, text::APPROVE_HOLD);
        let source = BarSource {
            view: &view,
            ..source
        };
        assert_eq!(bar_facts(&source, 0).label, text::APPROVE);
    }

    /// The guards and order of `next_step` (S4 B3 review). The connect sessions below have a
    /// standard interaction; the `high` view makes the bar read as a high-risk request.
    #[test]
    fn bar_next_step_guards_and_order() {
        let view = ApprovalView::default();
        let high = ApprovalView {
            high: true,
            ..ApprovalView::default()
        };
        // An armed high-risk window names the hold; while a submit or re-simulation runs there
        // is no step, even where one would otherwise show (early release, no account picked).
        let mut armed = connect_session(1, 1_000);
        armed.set_foreground(1_000, true);
        let _ = armed.event(2_000, InteractionEvent::Tick);
        let source = BarSource {
            lang: Lang::En,
            session: &armed,
            view: &high,
            connect: false,
            early_release: false,
            status: None,
        };
        assert_eq!(bar_facts(&source, 2_000).step, Some(text::HOLD_NOW));
        armed.gate.submitting = true;
        let source = BarSource {
            lang: Lang::En,
            session: &armed,
            view: &high,
            connect: false,
            early_release: false,
            status: None,
        };
        assert_eq!(bar_facts(&source, 2_000).step, None);
        let early = BarSource {
            early_release: true,
            ..source
        };
        assert_eq!(bar_facts(&early, 2_000).step, None);
        let mut empty = connect_session(0, 1_000);
        empty.gate.submitting = true;
        let source = BarSource {
            session: &empty,
            connect: true,
            ..source
        };
        assert_eq!(bar_facts(&source, 2_000).step, None);

        // While a hold is under way there is no step (it would otherwise be HOLD_NOW).
        let mut holding = connect_session(1, 1_000);
        holding.set_foreground(1_000, true);
        let _ = holding.event(2_000, InteractionEvent::Tick);
        let _ = holding.event(
            2_100,
            InteractionEvent::PointerPressed {
                inside: true,
                click_through: false,
                physical_down: true,
            },
        );
        let source = BarSource {
            lang: Lang::En,
            session: &holding,
            view: &high,
            connect: false,
            early_release: false,
            status: None,
        };
        let facts = bar_facts(&source, 2_600);
        assert_eq!((facts.held_ms, facts.step), (Some(500), None));

        // An early release (no acknowledgement needed on a connect window) names the hold ahead
        // of the arm wait; picking an account still comes first.
        let mut waiting = connect_session(1, 1_000);
        waiting.set_foreground(1_000, true);
        let source = BarSource {
            lang: Lang::En,
            session: &waiting,
            view: &view,
            connect: true,
            early_release: false,
            status: None,
        };
        assert_eq!(bar_facts(&source, 1_500).step, Some(text::ARM_WAIT));
        let source = BarSource {
            early_release: true,
            ..source
        };
        assert_eq!(bar_facts(&source, 1_500).step, Some(text::HOLD_EARLY));
        let unpicked = connect_session(0, 1_000);
        let source = BarSource {
            session: &unpicked,
            ..source
        };
        assert_eq!(bar_facts(&source, 1_500).step, Some(text::CONNECT_PICK));
    }

    #[test]
    fn a_submitted_approval_shows_simulating_from_its_status() {
        let view = ApprovalView::default();
        let mut session = connect_session(1, 0);
        session.gate.submitting = true;
        let changed = text::SIM_CHANGED.get(Lang::Ko);
        let source = BarSource {
            lang: Lang::Ko,
            session: &session,
            view: &view,
            connect: false,
            early_release: false,
            status: Some(changed),
        };
        assert_eq!(bar_facts(&source, 0).label, text::SIMULATING_BUTTON);
        let source = BarSource {
            status: Some("other"),
            ..source
        };
        assert_eq!(bar_facts(&source, 0).label, text::APPROVE);
    }

    #[test]
    fn debug_prints_no_text() {
        let view = ApprovalView::default();
        let session = connect_session(0, 0);
        let source = BarSource {
            lang: Lang::En,
            session: &session,
            view: &view,
            connect: false,
            early_release: false,
            status: Some("secret-looking status"),
        };
        let shown = format!("{source:?}");
        assert!(!shown.contains("secret"), "{shown}");
        assert_eq!(
            shown,
            "BarSource { lang: En, connect: false, early_release: false, status_len: Some(21), .. }"
        );
        let input = ApprovalInput {
            shown: ShownId(3),
            foreground: true,
            signal: ApprovalSignal::ToggleAccount {
                index: 1,
                view_rev: 7,
            },
        };
        assert_eq!(
            format!("{input:?}"),
            "ApprovalInput { shown: ShownId(3), foreground: true, signal: ToggleAccount { index: 1, view_rev: 7 } }"
        );
        assert_eq!(
            format!(
                "{:?}",
                OpenOutcome::Shown {
                    capture_excluded: true
                }
            ),
            "Shown { capture_excluded: true }"
        );
        assert_eq!(
            format!("{:?}", ApprovalEffect::Redraw { shown: ShownId(5) }),
            "Redraw { shown: ShownId(5) }"
        );
    }
}
