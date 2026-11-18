//! AP-1…AP-5 (spec/04 §3.9).
//!
//! AP-1 ports the interaction tests of `archive/spec-v2.4:crates/approval-ui/src/lib.rs:580-1006`
//! with the risk mapping (`Standard`/`High`); the removed stream codec and plain-text renderer
//! tests are not ported. AP-2 covers the gate (`armed`, one checkbox, 2 s hold, arm delay,
//! content replacement), AP-3 the queue, AP-4 the display re-check and line layout, AP-5 the
//! absence of any AI input to `can_approve`.

use core::fmt::Write as _;

use yw_core::approval::{
    AccountRef, ApprovalDisplay, ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalRequest,
    ApprovalStore, ChainRef, DisplayField, FieldKey, RiskLevel, RuleId, SigningPayload,
    SimNoneReason, SimulationBinding, Warning,
};
use yw_core::bip32::path::AccountIndex;
use yw_core::evm::address::Address;
use yw_core::evm::chain::SEPOLIA_GENESIS;
use yw_core::vault::EvmKeySource;
use yw_engine::approval::interaction::{
    ApprovalGate, ApprovalInteraction, ApprovalSession, ConnectView, HIGH_RISK_HOLD_MS, HoldSource,
    InteractionEvent, InteractionRisk, InteractionStatus, PrepareStage, PrepareState, ReadyContent,
    ack_needed, can_approve,
};
use yw_engine::approval::layout::{layout, rejoin};
use yw_engine::approval::{
    ApprovalQueue, MAX_APPROVALS_GLOBAL, MAX_APPROVALS_PER_ORIGIN, QueueOutcome, QueueSource,
    validate_for_display,
};
use yw_engine::errors::ErrorCode;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const PRESS: InteractionEvent = InteractionEvent::PointerPressed {
    inside: true,
    click_through: false,
    physical_down: true,
};
const RELEASE: InteractionEvent = InteractionEvent::PointerReleased {
    physical_down: false,
};

fn interaction(risk: InteractionRisk, lifetime: u64, now: u64) -> ApprovalInteraction {
    ApprovalInteraction::new(risk, lifetime, now).unwrap_or_else(|_| unreachable!("valid lifetime"))
}

// ----- AP-1 (ported) ---------------------------------------------------------------------

#[test]
fn ap1_standard_requires_explicit_activation() {
    let mut i = interaction(InteractionRisk::Standard, 30_000, 100);
    assert_eq!(
        i.apply(20_000, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert_eq!(
        i.apply(
            20_001,
            InteractionEvent::ApproveActivated { physical: true }
        ),
        InteractionStatus::Approved
    );
}

/// Security review L5: a synthetic Enter (posted `WM_KEYDOWN`, injected input) never approves a
/// Standard request, and as a press it still pushes the next approving press 1 s out.
#[test]
fn ap1_synthetic_enter_never_approves() {
    let mut i = interaction(InteractionRisk::Standard, 30_000, 100);
    assert_eq!(
        i.apply(
            20_000,
            InteractionEvent::ApproveActivated { physical: false }
        ),
        InteractionStatus::Pending
    );
    assert!(InteractionEvent::ApproveActivated { physical: false }.is_press());
    assert_eq!(
        i.apply(
            20_500,
            InteractionEvent::ApproveActivated { physical: true }
        ),
        InteractionStatus::Pending,
        "within 1 s of the synthetic press"
    );
    assert_eq!(
        i.apply(
            21_600,
            InteractionEvent::ApproveActivated { physical: true }
        ),
        InteractionStatus::Approved
    );
}

#[test]
fn ap1_standard_pointer_release_requires_a_matching_press() {
    let mut i = interaction(InteractionRisk::Standard, 30_000, 0);
    assert_eq!(i.apply(10, RELEASE), InteractionStatus::Pending);
    i.apply(20, PRESS);
    assert_eq!(i.apply(21, RELEASE), InteractionStatus::Approved);
}

#[test]
fn ap1_inconsistent_physical_input_cannot_approve_standard() {
    let mut pointer = interaction(InteractionRisk::Standard, 30_000, 0);
    pointer.apply(
        10,
        InteractionEvent::PointerPressed {
            inside: true,
            click_through: false,
            physical_down: false,
        },
    );
    assert!(pointer.is_blocked(HoldSource::Pointer));
    assert_eq!(pointer.apply(11, RELEASE), InteractionStatus::Pending);

    let mut keyboard = interaction(InteractionRisk::Standard, 30_000, 0);
    keyboard.apply(
        20,
        InteractionEvent::SpacePressed {
            repeat: false,
            physical_down: true,
        },
    );
    assert_eq!(
        keyboard.apply(
            21,
            InteractionEvent::SpaceReleased {
                physical_down: true
            }
        ),
        InteractionStatus::Pending
    );
    assert!(keyboard.is_blocked(HoldSource::Space));
}

#[test]
fn ap1_high_risk_ignores_ordinary_activation() {
    let mut i = interaction(InteractionRisk::High, 30_000, 0);
    assert_eq!(
        i.apply(10, InteractionEvent::ApproveActivated { physical: true }),
        InteractionStatus::Pending
    );
}

#[test]
fn ap1_high_risk_requires_full_continuous_pointer_hold() {
    let mut i = interaction(InteractionRisk::High, 30_000, 0);
    i.apply(100, PRESS);
    assert_eq!(i.hold_source(), Some(HoldSource::Pointer));
    assert_eq!(
        i.apply(2_099, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert_eq!(
        i.apply(2_100, InteractionEvent::Tick),
        InteractionStatus::Approved
    );
}

#[test]
fn ap1_pointer_outside_and_focus_loss_reset_and_require_release() {
    let mut i = interaction(InteractionRisk::High, 30_000, 0);
    i.apply(100, PRESS);
    i.apply(1_500, InteractionEvent::PointerMoved { inside: false });
    assert!(i.is_blocked(HoldSource::Pointer));
    i.apply(1_600, PRESS);
    assert_eq!(i.hold_source(), None);
    i.apply(1_700, RELEASE);
    // ≥ 1 s after the refused press at 1 600 (press-gap rule).
    i.apply(2_600, PRESS);
    assert_eq!(i.hold_source(), Some(HoldSource::Pointer));
    i.apply(3_000, InteractionEvent::FocusLost);
    assert_eq!(i.hold_source(), None);
    assert!(i.is_blocked(HoldSource::Pointer));
}

#[test]
fn ap1_space_repeat_resets_hold_until_physical_release() {
    let mut i = interaction(InteractionRisk::High, 30_000, 0);
    let space = |repeat, physical_down| InteractionEvent::SpacePressed {
        repeat,
        physical_down,
    };
    i.apply(100, space(false, true));
    i.apply(500, space(true, false));
    assert_eq!(i.hold_source(), None);
    assert!(i.is_blocked(HoldSource::Space));
    i.apply(700, space(false, true));
    assert_eq!(i.hold_source(), None);
    i.apply(
        800,
        InteractionEvent::SpaceReleased {
            physical_down: false,
        },
    );
    // ≥ 1 s after the refused press at 700 (press-gap rule).
    i.apply(1_700, space(false, true));
    assert_eq!(i.hold_source(), Some(HoldSource::Space));
    assert_eq!(
        i.apply(3_700, InteractionEvent::Tick),
        InteractionStatus::Approved
    );
}

#[test]
fn ap1_physical_space_repeat_neither_shortens_nor_extends_hold() {
    let mut i = interaction(InteractionRisk::High, 30_000, 0);
    let space = |repeat| InteractionEvent::SpacePressed {
        repeat,
        physical_down: true,
    };
    i.apply(100, space(false));
    i.apply(700, space(true));
    i.apply(1_500, space(true));
    assert_eq!(i.hold_remaining_ms(2_099), Some(1));
    assert_eq!(
        i.apply(2_099, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert_eq!(
        i.apply(2_100, InteractionEvent::Tick),
        InteractionStatus::Approved
    );
}

#[test]
fn ap1_stray_space_repeat_is_blocked_until_keyup() {
    let mut i = interaction(InteractionRisk::High, 30_000, 0);
    i.apply(
        100,
        InteractionEvent::SpacePressed {
            repeat: true,
            physical_down: true,
        },
    );
    assert_eq!(i.hold_source(), None);
    assert!(i.is_blocked(HoldSource::Space));
    i.apply(
        200,
        InteractionEvent::SpaceReleased {
            physical_down: false,
        },
    );
    assert!(!i.is_blocked(HoldSource::Space));
}

#[test]
fn ap1_click_through_never_starts_a_hold() {
    let mut i = interaction(InteractionRisk::High, 30_000, 0);
    i.apply(
        100,
        InteractionEvent::PointerPressed {
            inside: true,
            click_through: true,
            physical_down: true,
        },
    );
    assert_eq!(i.hold_source(), None);
    assert!(i.is_blocked(HoldSource::Pointer));
    assert_eq!(
        i.apply(5_000, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
}

#[test]
fn ap1_expiry_and_backwards_time_reject_terminally() {
    let mut expired = interaction(InteractionRisk::High, 1_000, 500);
    expired.apply(
        1_499,
        InteractionEvent::SpacePressed {
            repeat: false,
            physical_down: true,
        },
    );
    assert_eq!(
        expired.apply(1_500, InteractionEvent::Tick),
        InteractionStatus::Rejected
    );
    let mut backwards = interaction(InteractionRisk::Standard, 30_000, 500);
    assert_eq!(
        backwards.apply(499, InteractionEvent::ApproveActivated { physical: true }),
        InteractionStatus::Rejected
    );
    assert!(ApprovalInteraction::new(InteractionRisk::High, 0, 0).is_err());
}

// ----- helpers -----------------------------------------------------------------------------

fn request(
    risk: RiskLevel,
    ack_required: bool,
    warnings: u8,
    kind: ApprovalKind,
    simulation: SimulationBinding,
) -> ApprovalRequest {
    ApprovalRequest {
        id: ApprovalId([7; 16]),
        origin: ApprovalOrigin::App,
        chain: ChainRef::Evm {
            chain_id: 11_155_111,
            genesis: SEPOLIA_GENESIS,
        },
        account: AccountRef::Evm(Address::from_bytes([0x11; 20])),
        signer: yw_core::approval::Signer::Evm(EvmKeySource::Derived(AccountIndex::ZERO)),
        kind,
        payload: SigningPayload::EvmPersonal(b"x".to_vec()),
        display: ApprovalDisplay {
            lang: yw_core::lang::Lang::Ko,
            title: "[Sepolia 테스트넷] 시험".to_owned(),
            fields: Vec::new(),
            warnings: (1..=warnings)
                .map(|number| Warning {
                    rule: RuleId::new(b'E', number),
                    level: risk,
                    text: "고위험 경고".to_owned(),
                })
                .collect(),
            risk,
            ack_required,
        },
        simulation,
        created_unix_ms: 0,
        expires_unix_ms: 120_000,
        digest: [0; 32],
    }
}

fn message(risk: RiskLevel, ack_required: bool, warnings: u8) -> ApprovalRequest {
    request(
        risk,
        ack_required,
        warnings,
        ApprovalKind::EvmPersonalSign,
        SimulationBinding::NotApplicable,
    )
}

fn session(request: ApprovalRequest, ready_at: u64) -> ApprovalSession {
    ApprovalSession::new(
        ApprovalGate {
            prepare: PrepareState::Ready(ReadyContent::Signing(Box::new(request))),
            ack_checked: false,
            connect_selected: 0,
            ready_at_ms: ready_at,
            is_foreground: true,
            deadline_ms: ready_at + 120_000,
            submitting: false,
        },
        ready_at,
    )
    .unwrap_or_else(|_| unreachable!("valid session"))
}

fn hold(session: &mut ApprovalSession, start: u64, duration: u64) -> InteractionStatus {
    session.event(start, PRESS);
    session.event(start + duration, InteractionEvent::Tick)
}

// ----- AP-2 -------------------------------------------------------------------------------

#[test]
fn ap2_unarmed_input_is_ignored() {
    let mut i = interaction(InteractionRisk::Standard, 30_000, 0);
    i.set_armed(0, false);
    assert_eq!(
        i.apply(10, InteractionEvent::ApproveActivated { physical: true }),
        InteractionStatus::Pending
    );
    i.apply(20, PRESS);
    assert_eq!(i.apply(21, RELEASE), InteractionStatus::Pending);
    let mut high = interaction(InteractionRisk::High, 30_000, 0);
    high.apply(10, PRESS);
    high.set_armed(500, false);
    assert_eq!(high.hold_source(), None);
    assert!(high.is_blocked(HoldSource::Pointer));
    assert_eq!(
        high.apply(3_000, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
}

#[test]
fn ap2_two_high_warnings_one_checkbox_and_two_second_hold() {
    let request = message(RiskLevel::High, true, 2);
    assert!(ack_needed(&request));
    let mut s = session(request.clone(), 0);
    assert_eq!(
        hold(&mut s, 2_000, HIGH_RISK_HOLD_MS),
        InteractionStatus::Pending
    );
    let mut s = session(request.clone(), 0);
    s.set_ack(1_500, true);
    assert_eq!(hold(&mut s, 2_000, 1_900), InteractionStatus::Pending);
    let mut s = session(request, 0);
    s.set_ack(1_500, true);
    assert_eq!(hold(&mut s, 2_000, 2_000), InteractionStatus::Approved);
}

#[test]
fn ap2_inconsistent_high_without_ack_flag_still_needs_the_checkbox() {
    let request = message(RiskLevel::High, false, 1);
    assert!(ack_needed(&request));
    let mut s = session(request.clone(), 0);
    assert_eq!(hold(&mut s, 2_000, 3_000), InteractionStatus::Pending);
    let mut s = session(request, 0);
    s.set_ack(1_000, true);
    assert_eq!(hold(&mut s, 2_000, 2_000), InteractionStatus::Approved);
}

#[test]
fn ap2_blocked_never_approves() {
    let mut s = session(message(RiskLevel::Blocked, false, 1), 0);
    s.set_ack(1_500, true);
    assert_eq!(
        s.event(2_000, InteractionEvent::ApproveActivated { physical: true }),
        InteractionStatus::Pending
    );
    assert_eq!(hold(&mut s, 3_000, 5_000), InteractionStatus::Pending);
    s.event(9_000, PRESS);
    assert_eq!(s.event(9_001, RELEASE), InteractionStatus::Pending);
    assert_eq!(
        s.event(9_002, InteractionEvent::RejectActivated),
        InteractionStatus::Rejected
    );
}

#[test]
fn ap2_arm_delay_ignores_a_click_at_999_ms() {
    let mut s = session(message(RiskLevel::Info, false, 0), 10_000);
    s.event(10_999, PRESS);
    assert_eq!(s.event(10_999, RELEASE), InteractionStatus::Pending);
    assert_eq!(
        s.event(
            10_999,
            InteractionEvent::ApproveActivated { physical: true }
        ),
        InteractionStatus::Pending
    );
    // The presses at 10 999 came while not armed: the delay restarted there, so 11 000 is
    // refused too (and restarts it again).
    s.event(11_000, PRESS);
    assert_eq!(s.event(11_001, RELEASE), InteractionStatus::Pending);
    assert_eq!(s.gate.ready_at_ms, 11_000);
    s.event(12_000, PRESS);
    assert_eq!(s.event(12_001, RELEASE), InteractionStatus::Approved);
}

#[test]
fn ap2_press_while_not_armed_restarts_the_arm_delay() {
    let mut s = session(message(RiskLevel::Info, false, 0), 10_000);
    // A press anywhere (not on the approve button) before the delay elapsed.
    s.event(10_500, InteractionEvent::OtherPress);
    assert_eq!(s.gate.ready_at_ms, 10_500);
    assert!(!can_approve(&s.gate, 11_499));
    assert!(can_approve(&s.gate, 11_500));
    // A key press (auto-repeat too) while not armed restarts it again.
    s.event(11_200, InteractionEvent::OtherPress);
    assert_eq!(s.gate.ready_at_ms, 11_200);
    assert!(!can_approve(&s.gate, 12_199));
    assert_eq!(
        s.event(12_199, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert!(!s.interaction().is_armed());
    assert!(!s.approve_ready(12_199));
    assert_eq!(
        s.event(12_200, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert!(s.interaction().is_armed());
    assert!(s.approve_ready(12_200));
    // A press while armed does not move the delay (the press-gap rule still applies to it).
    s.event(13_000, InteractionEvent::OtherPress);
    assert_eq!(s.gate.ready_at_ms, 11_200);
    s.event(14_000, PRESS);
    assert_eq!(s.event(14_001, RELEASE), InteractionStatus::Approved);
}

#[test]
fn ap2_unarmed_approve_presses_restart_the_delay_for_high_risk_too() {
    let request = message(RiskLevel::High, true, 1);
    let mut s = session(request, 0);
    // The checkbox is unchecked: not armed, so each press restarts the delay.
    s.event(3_000, InteractionEvent::OtherPress);
    s.set_ack(3_000, true);
    assert_eq!(s.gate.ready_at_ms, 3_000);
    assert_eq!(hold(&mut s, 3_500, 3_000), InteractionStatus::Pending);
    assert_eq!(s.gate.ready_at_ms, 3_500);
    s.event(6_600, RELEASE);
    assert_eq!(
        hold(&mut s, 7_000, HIGH_RISK_HOLD_MS),
        InteractionStatus::Approved
    );
}

#[test]
fn ap2_window_activation_restarts_the_arm_delay() {
    let mut s = session(message(RiskLevel::Info, false, 0), 0);
    assert_eq!(
        s.event(5_000, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert!(s.interaction().is_armed());
    // Losing the foreground, then regaining it, restarts the delay with no press at all.
    s.set_foreground(5_000, false);
    assert!(!can_approve(&s.gate, 5_050));
    s.set_foreground(5_100, true);
    assert_eq!(s.gate.ready_at_ms, 5_100);
    assert!(!s.interaction().is_armed(), "disarmed at once");
    // Staying foreground is not a new activation.
    s.set_foreground(5_200, true);
    assert_eq!(s.gate.ready_at_ms, 5_100);
    assert_eq!(
        s.event(6_099, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert!(!s.approve_ready(6_099));
    assert_eq!(
        s.event(6_100, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert!(s.approve_ready(6_100));
    s.event(6_100, PRESS);
    assert_eq!(s.event(6_101, RELEASE), InteractionStatus::Approved);

    // `WM_ACTIVATEAPP(TRUE)`: an explicit restart while foreground.
    let mut s = session(message(RiskLevel::Info, false, 0), 0);
    s.event(5_000, InteractionEvent::Tick);
    s.restart_arm_delay(5_000);
    assert!(!s.interaction().is_armed());
    assert_eq!(
        s.event(5_999, InteractionEvent::ApproveActivated { physical: true }),
        InteractionStatus::Pending
    );
    // That Enter came while not armed: the delay now runs from 5 999.
    assert_eq!(s.gate.ready_at_ms, 5_999);
    assert_eq!(
        s.event(6_999, InteractionEvent::ApproveActivated { physical: true }),
        InteractionStatus::Approved
    );
}

#[test]
fn ap2_approve_press_under_one_second_after_any_press_is_refused() {
    // Standard pointer: armed since 1 000; a press elsewhere at 5 000.
    let mut s = session(message(RiskLevel::Info, false, 0), 0);
    s.event(5_000, InteractionEvent::OtherPress);
    assert!(s.interaction().is_armed(), "armed earlier, still armed");
    assert!(!s.approve_ready(5_999));
    s.event(5_999, PRESS);
    assert_eq!(s.interaction().hold_source(), None);
    assert_eq!(s.event(6_000, RELEASE), InteractionStatus::Pending);
    // ≥ 1 s after the previous press (the refused one at 5 999) → accepted.
    assert!(s.approve_ready(6_999));
    s.event(6_999, PRESS);
    assert_eq!(s.event(7_000, RELEASE), InteractionStatus::Approved);

    // Enter.
    let mut s = session(message(RiskLevel::Info, false, 0), 0);
    s.event(5_000, InteractionEvent::OtherPress);
    assert_eq!(
        s.event(5_500, InteractionEvent::ApproveActivated { physical: true }),
        InteractionStatus::Pending
    );
    assert_eq!(
        s.event(6_499, InteractionEvent::ApproveActivated { physical: true }),
        InteractionStatus::Pending
    );
    assert_eq!(
        s.event(7_499, InteractionEvent::ApproveActivated { physical: true }),
        InteractionStatus::Approved
    );

    // High risk: neither a pointer nor a Space hold starts within 1 s of another press.
    let space = InteractionEvent::SpacePressed {
        repeat: false,
        physical_down: true,
    };
    let space_up = InteractionEvent::SpaceReleased {
        physical_down: false,
    };
    let mut s = session(message(RiskLevel::High, true, 1), 0);
    s.set_ack(1_000, true);
    s.event(5_000, InteractionEvent::OtherPress);
    assert_eq!(hold(&mut s, 5_900, 3_000), InteractionStatus::Pending);
    s.event(8_900, RELEASE);
    s.event(9_000, InteractionEvent::OtherPress);
    s.event(9_999, space);
    assert_eq!(s.interaction().hold_source(), None);
    s.event(10_000, space_up);
    s.event(11_000, space);
    assert_eq!(s.interaction().hold_source(), Some(HoldSource::Space));
    assert_eq!(
        s.event(13_000, InteractionEvent::Tick),
        InteractionStatus::Approved
    );
}

#[test]
fn ap2_rapid_click_lure_never_approves() {
    // A page lures the user into clicking fast; the clicks walk onto the approve button long
    // after the window armed. Every click is a press, so none of them can approve.
    let mut s = session(message(RiskLevel::Info, false, 0), 0);
    let mut now = 10_000;
    for _ in 0..10 {
        s.event(now, InteractionEvent::OtherPress);
        now += 150;
    }
    for _ in 0..10 {
        s.event(now, PRESS);
        assert_eq!(s.event(now + 50, RELEASE), InteractionStatus::Pending);
        now += 150;
    }
    // Auto-repeated Enter on the focused button never approves either.
    for _ in 0..40 {
        assert_eq!(
            s.event(now, InteractionEvent::ApproveActivated { physical: true }),
            InteractionStatus::Pending
        );
        now += 33;
    }
    // One deliberate press after a 1 s pause does.
    now += 1_000;
    s.event(now, PRESS);
    assert_eq!(s.event(now + 50, RELEASE), InteractionStatus::Approved);
}

#[test]
fn ap2_right_middle_x_and_non_client_clicks_restart_the_arm_delay() {
    // Every mouse button in the client area and any press on the title bar, caption buttons,
    // frame or scroll bar is a press (spec/04 §3.4): the window maps them to `OtherPress`
    // (2026-11-17: that Win32 mapping is tested in `tests/approval_input.rs`).
    let event = InteractionEvent::OtherPress;
    let mut s = session(message(RiskLevel::Info, false, 0), 10_000);
    s.event(10_600, event);
    assert_eq!(s.gate.ready_at_ms, 10_600, "stray press while not armed");
    assert!(!can_approve(&s.gate, 11_599));
    s.event(11_599, PRESS);
    assert_eq!(s.event(11_600, RELEASE), InteractionStatus::Pending);
    // Armed: a stray press still blocks an approving press for 1 s.
    let mut s = session(message(RiskLevel::Info, false, 0), 0);
    s.event(5_000, event);
    assert!(!s.approve_ready(5_999), "stray press gap");
    assert!(s.approve_ready(6_000));
}

#[test]
fn ap2_press_gap_spans_an_interaction_restart() {
    let mut s = session(message(RiskLevel::Info, false, 0), 0);
    s.event(1_000, PRESS);
    assert_eq!(s.event(1_001, RELEASE), InteractionStatus::Approved);
    s.restart_interaction(1_060)
        .unwrap_or_else(|_| unreachable!("deadline ahead"));
    assert_eq!(s.interaction().last_press_ms(), Some(1_000));
    s.event(1_500, PRESS);
    assert_eq!(s.event(1_501, RELEASE), InteractionStatus::Pending);
    s.event(2_500, PRESS);
    assert_eq!(s.event(2_501, RELEASE), InteractionStatus::Approved);
}

#[test]
fn ap2_press_classification() {
    assert!(InteractionEvent::OtherPress.is_press());
    assert!(InteractionEvent::ApproveActivated { physical: true }.is_press());
    assert!(PRESS.is_press());
    assert!(
        InteractionEvent::SpacePressed {
            repeat: true,
            physical_down: true
        }
        .is_press()
    );
    assert!(!RELEASE.is_press());
    assert!(!InteractionEvent::Tick.is_press());
    assert!(!InteractionEvent::PointerMoved { inside: true }.is_press());
    assert!(!InteractionEvent::RejectActivated.is_press());
    // An `OtherPress` alone never approves, even with a completed arm delay.
    let mut i = interaction(InteractionRisk::Standard, 30_000, 0);
    assert_eq!(
        i.apply(5_000, InteractionEvent::OtherPress),
        InteractionStatus::Pending
    );
    assert_eq!(i.last_press_ms(), Some(5_000));
    assert!(!i.press_spaced(5_999));
    assert!(i.press_spaced(6_000));
}

/// C1: `Approved` is terminal (every later tick returns it). After the window acts on it (a
/// re-simulation dispatched, `submitting` set) the interaction restarts: ticks stay pending and
/// nothing approves until `submitting` clears and new input arrives.
#[test]
fn ap2_restart_after_acting_on_an_approval() {
    let mut s = session(message(RiskLevel::Info, false, 0), 0);
    s.event(1_000, PRESS);
    assert_eq!(s.event(1_001, RELEASE), InteractionStatus::Approved);
    assert_eq!(
        s.event(1_050, InteractionEvent::Tick),
        InteractionStatus::Approved,
        "terminal: the window must act only on the transition"
    );
    s.gate.submitting = true;
    s.restart_interaction(1_060)
        .unwrap_or_else(|_| unreachable!("deadline ahead"));
    for tick in 0..100 {
        assert_eq!(
            s.event(1_100 + tick * 50, InteractionEvent::Tick),
            InteractionStatus::Pending
        );
    }
    s.event(7_000, PRESS);
    assert_eq!(
        s.event(7_001, RELEASE),
        InteractionStatus::Pending,
        "submitting disarms"
    );
    s.gate.submitting = false;
    s.event(8_000, PRESS);
    assert_eq!(s.event(8_001, RELEASE), InteractionStatus::Approved);
}

#[test]
fn ap2_replacement_during_hold_cancels_and_unchecks() {
    let request = message(RiskLevel::High, true, 1);
    let mut s = session(request.clone(), 0);
    s.set_ack(1_000, true);
    s.event(1_500, PRESS);
    assert_eq!(s.interaction().hold_source(), Some(HoldSource::Pointer));
    s.replace_content(
        2_500,
        PrepareState::Ready(ReadyContent::Signing(Box::new(request))),
    )
    .unwrap_or_else(|_| unreachable!("deadline ahead"));
    assert!(!s.gate.ack_checked);
    assert_eq!(s.gate.ready_at_ms, 2_500);
    assert_eq!(s.interaction().hold_source(), None);
    assert_eq!(
        s.event(4_000, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
}

#[test]
fn ap2_simulation_failure_maps_to_high_even_for_caution() {
    let failed = request(
        RiskLevel::Caution,
        false,
        0,
        ApprovalKind::EvmTransaction,
        SimulationBinding::None {
            reason: SimNoneReason::Timeout,
        },
    );
    assert!(ack_needed(&failed));
    let mut s = session(failed, 0);
    assert_eq!(
        s.event(2_000, InteractionEvent::ApproveActivated { physical: true }),
        InteractionStatus::Pending
    );
    s.set_ack(2_000, true);
    assert_eq!(hold(&mut s, 3_000, 2_000), InteractionStatus::Approved);
}

#[test]
fn ap2_preparing_and_failed_never_arm() {
    let mut gate = ApprovalGate {
        prepare: PrepareState::Preparing(PrepareStage::Simulating { since_ms: 0 }),
        ack_checked: true,
        connect_selected: 0,
        ready_at_ms: 0,
        is_foreground: true,
        deadline_ms: 120_000,
        submitting: false,
    };
    assert!(!can_approve(&gate, 5_000));
    gate.prepare = PrepareState::Failed {
        code: ErrorCode::Rpc001,
        retryable: true,
    };
    assert!(!can_approve(&gate, 5_000));
}

// ----- AP-3 -------------------------------------------------------------------------------

fn site(origin: &str, deadline: u64) -> QueueSource {
    QueueSource::Site {
        origin: origin.to_owned(),
        deadline_ms: deadline,
    }
}

#[test]
fn ap3_queue_limits() {
    let mut queue: ApprovalQueue<u32> = ApprovalQueue::default();
    for n in 0..u32::try_from(MAX_APPROVALS_PER_ORIGIN).unwrap_or(16) {
        assert!(queue.enqueue(site("https://a.example", 600_000), n).is_ok());
    }
    assert_eq!(
        queue.enqueue(site("https://a.example", 600_000), 99),
        Err(QueueOutcome::TooManyPending)
    );
    let mut origin = 0;
    while queue.len() < MAX_APPROVALS_GLOBAL {
        origin += 1;
        let _ = queue.enqueue(
            site(&format!("https://o{}.example", origin / 10), 600_000),
            1,
        );
    }
    assert_eq!(
        queue.enqueue(QueueSource::App, 1),
        Err(QueueOutcome::TooManyPending)
    );
}

#[test]
fn ap3_short_remaining_deadline_times_out_without_a_window() {
    let mut queue: ApprovalQueue<u32> = ApprovalQueue::default();
    let _ = queue.enqueue(site("https://a.example", 104_999), 1);
    let _ = queue.enqueue(site("https://b.example", 600_000), 2);
    let mut finished = Vec::new();
    let shown = queue.show_next(100_000, &mut finished);
    assert_eq!(finished.len(), 1);
    assert_eq!(finished[0].1, QueueOutcome::TimedOut);
    assert_eq!(queue.shown().map(|item| item.payload), Some(2));
    assert!(shown.is_some());
}

#[test]
fn ap3_expiry_counts_from_ready_not_from_preparing() {
    let mut queue: ApprovalQueue<u32> = ApprovalQueue::default();
    let _ = queue.enqueue(site("https://a.example", 600_000), 1);
    queue.show_next(0, &mut Vec::new());
    assert!(queue.tick(30_000).is_empty());
    queue.mark_ready(30_000);
    assert_eq!(queue.shown_deadline(), Some(150_000));
    assert!(queue.tick(149_999).is_empty());
    let finished = queue.tick(150_000);
    assert_eq!(finished[0].1, QueueOutcome::Expired);
}

#[test]
fn ap3_app_item_expiry_and_a_new_approval_id() -> TestResult {
    let mut queue: ApprovalQueue<u32> = ApprovalQueue::default();
    let _ = queue.enqueue(QueueSource::App, 1);
    queue.show_next(0, &mut Vec::new());
    queue.mark_ready(0);
    assert_eq!(queue.tick(120_000)[0].1, QueueOutcome::Expired);
    // Re-reviewing issues a new id; the expired id can no longer be consumed.
    let mut store = ApprovalStore::new();
    let draft = |id: u8| yw_core::approval::ApprovalDraft {
        id: ApprovalId([id; 16]),
        origin: ApprovalOrigin::App,
        chain: ChainRef::Evm {
            chain_id: 11_155_111,
            genesis: SEPOLIA_GENESIS,
        },
        account: AccountRef::Evm(Address::from_bytes([0x11; 20])),
        signer: yw_core::approval::Signer::Evm(EvmKeySource::Derived(AccountIndex::ZERO)),
        kind: ApprovalKind::EvmPersonalSign,
        payload: SigningPayload::EvmPersonal(b"\x19Ethereum Signed Message:\n1x".to_vec()),
        display: ApprovalDisplay::new(
            yw_core::lang::Lang::Ko,
            "[Sepolia 테스트넷] 시험".to_owned(),
            Vec::new(),
            Vec::new(),
        )
        .unwrap_or_else(|_| unreachable!("valid display")),
        simulation: SimulationBinding::NotApplicable,
    };
    let first = store.issue(draft(1), 0, 0)?;
    let second = store.issue(draft(2), 130_000, 130_000)?;
    assert_ne!(first.id, second.id);
    assert!(store.consume(first.id, first.digest, 130_000).is_err());
    Ok(())
}

#[test]
fn ap3_connect_selection_bounds() {
    let gate = |selected| ApprovalGate {
        prepare: PrepareState::Ready(ReadyContent::Connect(ConnectView { accounts: 20 })),
        ack_checked: false,
        connect_selected: selected,
        ready_at_ms: 0,
        is_foreground: true,
        deadline_ms: 120_000,
        submitting: false,
    };
    assert!(can_approve(&gate(16), 1_000));
    assert!(!can_approve(&gate(17), 1_000));
    assert!(!can_approve(&gate(0), 1_000));
}

#[test]
fn ap3_lock_rejects_shown_and_revoke_hits_waiting_items() {
    let mut queue: ApprovalQueue<u32> = ApprovalQueue::default();
    let _ = queue.enqueue(site("https://a.example", 600_000), 1);
    let _ = queue.enqueue(site("https://a.example", 600_000), 2);
    let _ = queue.enqueue(site("https://b.example", 600_000), 3);
    queue.show_next(0, &mut Vec::new());
    let locked = queue.lock();
    assert_eq!(locked.len(), 1);
    assert_eq!(locked[0].1, QueueOutcome::Rejected);
    assert_eq!(queue.len(), 2);
    let revoked = queue.revoke("https://a.example");
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].1, QueueOutcome::Revoked);
    assert_eq!(queue.len(), 1);
    assert_eq!(queue.shutdown()[0].1, QueueOutcome::Shutdown);
}

// ----- AP-4 -------------------------------------------------------------------------------

#[test]
fn ap4_unsafe_text_and_unknown_keys_are_rejected() {
    let mut display = message(RiskLevel::Info, false, 0).display;
    assert_eq!(validate_for_display(&display), Ok(()));
    display.title = "[Sepolia] \u{202E}evil".to_owned();
    assert_eq!(validate_for_display(&display), Err(ErrorCode::Ui001));
    let mut display = message(RiskLevel::Info, false, 0).display;
    display.fields.push(DisplayField {
        key: FieldKey(0x0999),
        sub_label: String::new(),
        value: "x".to_owned(),
        critical: true,
        volatile: false,
    });
    assert_eq!(validate_for_display(&display), Err(ErrorCode::Ui001));
    let mut display = message(RiskLevel::Info, false, 0).display;
    display.fields.push(DisplayField {
        key: FieldKey::CALLDATA,
        sub_label: String::new(),
        value: "a\u{200B}b".to_owned(),
        critical: false,
        volatile: false,
    });
    assert_eq!(validate_for_display(&display), Err(ErrorCode::Ui001));
}

#[test]
fn ap4_large_values_lay_out_and_rejoin_exactly() {
    let width = |character: char| if character.is_ascii() { 7 } else { 14 };
    let mut words = String::with_capacity(270_000);
    for n in 0..30_000 {
        assert!(write!(words, "w{n:07} ").is_ok());
    }
    assert_eq!(words.len(), 270_000);
    let lines = layout(&words, 600, &width);
    assert_eq!(rejoin(&words, &lines), words);
    let unbroken = "x".repeat(3_000);
    let lines = layout(&unbroken, 600, &width);
    assert!(lines.len() > 30);
    assert_eq!(rejoin(&unbroken, &lines), unbroken);
}

// ----- AP-5 -------------------------------------------------------------------------------

#[test]
fn ap5_can_approve_takes_no_ai_state() {
    // The gate and the clock are the only inputs (spec/06 E2): the signature is the check.
    let function: fn(&ApprovalGate, u64) -> bool = can_approve;
    let gate = ApprovalGate {
        prepare: PrepareState::Preparing(PrepareStage::Building),
        ack_checked: false,
        connect_selected: 0,
        ready_at_ms: 0,
        is_foreground: true,
        deadline_ms: 10,
        submitting: false,
    };
    assert!(!function(&gate, 5));
}

/// Review 2026-11-07 F7: the status line explains a grey approve button only while the window's
/// own timing holds it back; a missing acknowledgement or a blocked request is not "waiting".
#[test]
fn arm_waiting_is_only_the_window_timing() {
    let mut s = session(message(RiskLevel::Info, false, 0), 10_000);
    assert!(s.arm_waiting(10_500));
    s.event(11_000, InteractionEvent::Tick);
    assert!(s.approve_ready(11_000));
    assert!(!s.arm_waiting(11_000));
    s.set_foreground(11_100, false);
    assert!(s.arm_waiting(11_100));

    let mut high = session(message(RiskLevel::High, true, 1), 0);
    high.event(5_000, InteractionEvent::Tick);
    assert!(!high.arm_waiting(5_000), "the checkbox is the user's step");
    // Clicking the checkbox is a press: the arm delay restarts there.
    high.event(5_000, InteractionEvent::OtherPress);
    high.set_ack(5_000, true);
    assert!(high.arm_waiting(5_500));
    high.event(6_100, InteractionEvent::Tick);
    assert!(!high.arm_waiting(6_100));

    let blocked = session(message(RiskLevel::Blocked, false, 1), 0);
    assert!(!blocked.arm_waiting(5_000));
}

/// 2026-11-08: the status line names the user's step on a high-risk window — the unchecked
/// acknowledgement box — and nothing else changes the gate.
#[test]
fn ack_missing_is_the_users_step() {
    let mut high = session(message(RiskLevel::High, true, 1), 0);
    assert!(high.ack_missing());
    assert!(!high.connect_empty());
    high.set_ack(5_000, true);
    assert!(!high.ack_missing());
    assert!(!session(message(RiskLevel::Info, false, 0), 0).ack_missing());
    assert!(!session(message(RiskLevel::Blocked, false, 1), 0).ack_missing());
}

// ----- AP-7 (2026-11-18, spec/15 §11.4 S4 A1) ----------------------------------------------
//
// Edges the App-level approval flow relies on, pinned before S4 moves that flow into the
// engine: physical Enter on a High request, synthetic Enter streams, reject during a hold, the
// exact 120 s boundary, display changes and resets in the middle of a hold, re-activation,
// time going backwards, the queue's `TimedOut`/`Expired` split, lock while preparing, the
// per-origin limit, and the session sequences the App uses (`restart_interaction`,
// `submitting`, the deadline, `restart_arm_delay` after `Approved`).

use yw_engine::approval::interaction::{APPROVE_ARM_DELAY_MS, MAX_LIFETIME_MS, interaction_risk};

const SPACE: InteractionEvent = InteractionEvent::SpacePressed {
    repeat: false,
    physical_down: true,
};
const SPACE_UP: InteractionEvent = InteractionEvent::SpaceReleased {
    physical_down: false,
};
const ENTER: InteractionEvent = InteractionEvent::ApproveActivated { physical: true };

fn press_of(source: HoldSource) -> InteractionEvent {
    match source {
        HoldSource::Pointer => PRESS,
        HoldSource::Space => SPACE,
    }
}

fn release_of(source: HoldSource) -> InteractionEvent {
    match source {
        HoldSource::Pointer => RELEASE,
        HoldSource::Space => SPACE_UP,
    }
}

/// A High request with its checkbox ticked at `ack_at`, shown at 0.
fn high_checked(ack_at: u64) -> ApprovalSession {
    let mut s = session(message(RiskLevel::High, true, 1), 0);
    s.set_ack(ack_at, true);
    s
}

/// High + checked + armed: a physical Enter is still not an approval, it counts as a press
/// (a hold within 1 s of it never starts), and a hold started 1 s later approves after 2 s.
#[test]
fn ap7_physical_enter_never_approves_high_even_armed_and_checked() {
    let mut s = high_checked(500);
    assert_eq!(
        s.event(1_000, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert!(s.approve_ready(1_000));
    assert_eq!(s.event(1_000, ENTER), InteractionStatus::Pending);
    assert_eq!(s.interaction().last_press_ms(), Some(1_000));
    s.event(1_500, PRESS);
    assert_eq!(
        s.interaction().hold_source(),
        None,
        "within 1 s of the Enter"
    );
    assert_eq!(s.event(1_600, RELEASE), InteractionStatus::Pending);
    s.event(2_600, PRESS);
    assert_eq!(s.interaction().hold_source(), Some(HoldSource::Pointer));
    assert_eq!(
        s.event(4_599, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert_eq!(
        s.event(4_600, InteractionEvent::Tick),
        InteractionStatus::Approved
    );
}

/// Standard, armed: 50 synthetic Enters 1.1 s apart never approve; a physical Enter within 1 s
/// of the last of them does not either, one 1 s after it does.
#[test]
fn ap7_synthetic_enter_stream_never_approves_standard() {
    let mut s = session(message(RiskLevel::Info, false, 0), 0);
    let mut now = 1_100;
    for _ in 0..50 {
        assert_eq!(
            s.event(now, InteractionEvent::ApproveActivated { physical: false }),
            InteractionStatus::Pending
        );
        assert!(s.interaction().is_armed());
        now += 1_100;
    }
    let last = now - 1_100;
    assert_eq!(s.event(last + 999, ENTER), InteractionStatus::Pending);
    assert_eq!(
        s.event(last + 999 + 1_000, ENTER),
        InteractionStatus::Approved
    );
}

/// Reject in the middle of a hold is terminal: neither the completed hold time nor a release
/// approves afterwards.
#[test]
fn ap7_reject_during_a_hold_is_terminal() {
    for source in [HoldSource::Pointer, HoldSource::Space] {
        let mut s = high_checked(500);
        s.event(1_000, press_of(source));
        assert_eq!(s.interaction().hold_source(), Some(source));
        assert_eq!(
            s.event(2_000, InteractionEvent::RejectActivated),
            InteractionStatus::Rejected
        );
        assert_eq!(
            s.event(3_100, InteractionEvent::Tick),
            InteractionStatus::Rejected
        );
        assert_eq!(
            s.event(3_200, release_of(source)),
            InteractionStatus::Rejected
        );
        assert_eq!(s.interaction().hold_source(), None);
    }
}

/// `deadline = ready + 120 000`: 119 999 is still inside (click, Enter, completed hold),
/// 120 000 is outside (everything rejects).
#[test]
fn ap7_expiry_at_exactly_120_s_from_ready() {
    let shown = || session(message(RiskLevel::Info, false, 0), 0);
    let mut s = shown();
    assert_eq!(s.interaction().lifetime_remaining_ms(119_999), 1);
    assert_eq!(s.interaction().lifetime_remaining_ms(120_000), 0);
    s.event(118_000, PRESS);
    assert_eq!(s.event(119_999, RELEASE), InteractionStatus::Approved);
    let mut s = shown();
    s.event(118_000, PRESS);
    assert_eq!(s.event(120_000, RELEASE), InteractionStatus::Rejected);
    let mut s = shown();
    assert_eq!(s.event(119_999, ENTER), InteractionStatus::Approved);
    let mut s = shown();
    assert!(!s.approve_ready(120_000));
    assert_eq!(s.event(120_000, ENTER), InteractionStatus::Rejected);
    let mut s = high_checked(500);
    s.event(117_999, PRESS);
    assert_eq!(
        s.event(119_999, InteractionEvent::Tick),
        InteractionStatus::Approved
    );
    let mut s = high_checked(500);
    s.event(118_000, PRESS);
    assert_eq!(
        s.event(119_999, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert_eq!(
        s.event(120_000, InteractionEvent::Tick),
        InteractionStatus::Rejected
    );
}

/// A hold that would complete after the deadline never completes: the deadline tick rejects and
/// the state stays rejected.
#[test]
fn ap7_a_hold_spanning_the_deadline_never_completes() {
    let mut s = high_checked(500);
    s.event(118_500, PRESS);
    assert_eq!(s.interaction().hold_source(), Some(HoldSource::Pointer));
    assert_eq!(
        s.event(119_950, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert_eq!(
        s.event(120_000, InteractionEvent::Tick),
        InteractionStatus::Rejected
    );
    assert_eq!(
        s.event(120_500, InteractionEvent::Tick),
        InteractionStatus::Rejected
    );
    assert_eq!(s.event(120_600, RELEASE), InteractionStatus::Rejected);
}

/// Replacing the shown content in the middle of a hold (Ready again, back to simulating,
/// failed), from either source: the hold and the checkbox clear, `ready_at = now`,
/// `submitting` clears, the deadline and the previous press are kept; only a new hold on new
/// Ready content approves.
#[test]
fn ap7_display_change_mid_hold_resets_for_every_new_state() {
    let request = message(RiskLevel::High, true, 1);
    let states = [
        PrepareState::Ready(ReadyContent::Signing(Box::new(request))),
        PrepareState::Preparing(PrepareStage::Simulating { since_ms: 2_000 }),
        PrepareState::Failed {
            code: ErrorCode::Rpc001,
            retryable: true,
        },
    ];
    for source in [HoldSource::Pointer, HoldSource::Space] {
        for state in &states {
            let mut s = high_checked(500);
            s.event(1_500, press_of(source));
            assert_eq!(s.interaction().hold_source(), Some(source));
            s.gate.submitting = true;
            s.replace_content(2_000, state.clone())
                .unwrap_or_else(|_| unreachable!("deadline ahead"));
            assert!(!s.gate.ack_checked);
            assert_eq!(s.gate.ready_at_ms, 2_000);
            assert!(!s.gate.submitting);
            assert_eq!(s.interaction().hold_source(), None);
            assert_eq!(s.interaction().last_press_ms(), Some(1_500));
            assert_eq!(s.gate.deadline_ms, 120_000, "the deadline is kept");
            assert_eq!(
                s.event(3_600, InteractionEvent::Tick),
                InteractionStatus::Pending
            );
            s.event(3_700, release_of(source));
            s.set_ack(3_800, true);
            s.event(4_000, press_of(source));
            let ready = matches!(state, PrepareState::Ready(_));
            assert_eq!(s.interaction().hold_source().is_some(), ready);
            assert_eq!(
                s.event(6_000, InteractionEvent::Tick),
                if ready {
                    InteractionStatus::Approved
                } else {
                    InteractionStatus::Pending
                }
            );
        }
    }
}

/// Focus loss, foreground loss and `WM_CANCELMODE` clear a hold of either source and block that
/// source until it is physically released; capture loss clears and blocks the pointer only
/// (a Space hold goes on: recorded as the code behaves at `0909127`).
#[test]
fn ap7_focus_foreground_capture_cancel_reset_either_source() {
    for event in [
        InteractionEvent::FocusLost,
        InteractionEvent::ForegroundLost,
        InteractionEvent::CaptureLost,
        InteractionEvent::CancelMode,
    ] {
        for source in [HoldSource::Pointer, HoldSource::Space] {
            let mut s = high_checked(500);
            s.event(1_000, press_of(source));
            assert_eq!(s.interaction().hold_source(), Some(source));
            assert_eq!(s.event(1_500, event), InteractionStatus::Pending);
            if event == InteractionEvent::CaptureLost && source == HoldSource::Space {
                assert_eq!(s.interaction().hold_source(), Some(HoldSource::Space));
                assert!(s.interaction().is_blocked(HoldSource::Pointer));
                assert_eq!(
                    s.event(3_000, InteractionEvent::Tick),
                    InteractionStatus::Approved
                );
                continue;
            }
            assert_eq!(s.interaction().hold_source(), None, "{event:?} {source:?}");
            assert!(s.interaction().is_blocked(source));
            // Pressed again without a release: still blocked.
            s.event(2_600, press_of(source));
            assert_eq!(s.interaction().hold_source(), None);
            // Released, then pressed 1 s after the previous press: a new hold.
            s.event(2_700, release_of(source));
            assert!(!s.interaction().is_blocked(source));
            s.event(3_600, press_of(source));
            assert_eq!(s.interaction().hold_source(), Some(source));
            assert_eq!(
                s.event(5_599, InteractionEvent::Tick),
                InteractionStatus::Pending
            );
            assert_eq!(
                s.event(5_600, InteractionEvent::Tick),
                InteractionStatus::Approved
            );
        }
    }
}

/// Losing and regaining the foreground in the middle of a hold restarts the arm delay, clears the
/// hold and blocks its source; a new hold needs a release and the new delay.
#[test]
fn ap7_reactivation_mid_hold_cancels_it() {
    let mut s = high_checked(500);
    s.event(1_500, PRESS);
    assert_eq!(s.interaction().hold_source(), Some(HoldSource::Pointer));
    s.set_foreground(2_000, false);
    s.set_foreground(2_100, true);
    assert_eq!(s.gate.ready_at_ms, 2_100);
    assert!(!s.interaction().is_armed());
    assert_eq!(s.interaction().hold_source(), None);
    assert!(s.interaction().is_blocked(HoldSource::Pointer));
    assert_eq!(
        s.event(3_600, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    s.event(3_650, RELEASE);
    // `ready_at` 2 100 + 1 s = 3 100 and ≥ 1 s after the press at 1 500: a new hold.
    s.event(3_700, PRESS);
    assert_eq!(s.interaction().hold_source(), Some(HoldSource::Pointer));
    assert_eq!(
        s.event(5_700, InteractionEvent::Tick),
        InteractionStatus::Approved
    );

    // An explicit `restart_arm_delay` (WM_ACTIVATEAPP(TRUE)) while foreground does the same.
    let mut s = high_checked(500);
    s.event(1_500, PRESS);
    s.restart_arm_delay(2_000);
    assert_eq!(s.gate.ready_at_ms, 2_000);
    assert_eq!(s.interaction().hold_source(), None);
    assert!(s.interaction().is_blocked(HoldSource::Pointer));
    assert_eq!(
        s.event(4_000, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
}

/// Unchecking the box in the middle of a hold clears it; checking again needs a new hold.
#[test]
fn ap7_unchecking_the_box_mid_hold_cancels_it() {
    let mut s = high_checked(500);
    s.event(1_500, PRESS);
    assert_eq!(s.interaction().hold_source(), Some(HoldSource::Pointer));
    s.set_ack(2_000, false);
    assert_eq!(s.interaction().hold_source(), None);
    assert!(s.interaction().is_blocked(HoldSource::Pointer));
    s.set_ack(2_100, true);
    assert_eq!(
        s.event(4_000, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    s.event(4_100, RELEASE);
    s.event(5_100, PRESS);
    assert_eq!(s.interaction().hold_source(), Some(HoldSource::Pointer));
    assert_eq!(
        s.event(7_100, InteractionEvent::Tick),
        InteractionStatus::Approved
    );
}

/// Time going backwards rejects terminally, whichever session call sees it.
#[test]
fn ap7_session_time_going_backwards_rejects() {
    let shown = || session(message(RiskLevel::Info, false, 0), 1_000);
    let mut s = shown();
    assert_eq!(
        s.event(5_000, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    assert_eq!(
        s.event(4_999, InteractionEvent::Tick),
        InteractionStatus::Rejected
    );
    assert_eq!(s.event(9_000, ENTER), InteractionStatus::Rejected);
    let mut s = shown();
    s.event(5_000, InteractionEvent::Tick);
    s.restart_arm_delay(4_999);
    assert_eq!(s.interaction().status(), InteractionStatus::Rejected);
    let mut s = shown();
    s.event(5_000, InteractionEvent::Tick);
    s.set_ack(4_999, true);
    assert_eq!(s.interaction().status(), InteractionStatus::Rejected);
}

/// The queue half of the two timer paths (spec/04 §3.5): the shown item ends `TimedOut` when the
/// site deadline is the earlier (or equal) one and `Expired` when the display deadline is.
#[test]
fn ap7_site_deadline_shorter_than_display_is_timed_out_by_the_queue() {
    let shown = |site_deadline: u64, ready: u64| {
        let mut queue: ApprovalQueue<u32> = ApprovalQueue::default();
        let _ = queue.enqueue(site("https://a.example", site_deadline), 1);
        queue.show_next(0, &mut Vec::new());
        queue.mark_ready(ready);
        queue
    };
    let mut queue = shown(100_000, 10_000);
    assert_eq!(queue.shown_deadline(), Some(100_000));
    assert!(queue.tick(99_999).is_empty());
    assert_eq!(queue.tick(100_000)[0].1, QueueOutcome::TimedOut);
    let mut queue = shown(600_000, 0);
    assert_eq!(queue.shown_deadline(), Some(120_000));
    assert!(queue.tick(119_999).is_empty());
    assert_eq!(queue.tick(120_000)[0].1, QueueOutcome::Expired);
    let mut queue = shown(130_000, 10_000);
    assert_eq!(queue.shown_deadline(), Some(130_000));
    assert_eq!(
        queue.tick(130_000)[0].1,
        QueueOutcome::TimedOut,
        "equal: the site's"
    );
}

/// Locking while the shown item is still preparing ends it `Rejected`; waiting items stay and
/// their deadlines go on.
#[test]
fn ap7_lock_while_preparing_and_waiting_deadlines_continue() {
    let mut queue: ApprovalQueue<u32> = ApprovalQueue::default();
    let _ = queue.enqueue(site("https://a.example", 600_000), 1);
    let _ = queue.enqueue(site("https://b.example", 50_000), 2);
    let _ = queue.enqueue(QueueSource::App, 3);
    assert!(queue.show_next(0, &mut Vec::new()).is_some());
    assert_eq!(queue.shown().map(|item| item.payload), Some(3));
    assert_eq!(
        queue.shown_deadline(),
        None,
        "an app item has none before Ready"
    );
    let locked = queue.lock();
    assert_eq!(locked.len(), 1);
    assert_eq!(locked[0].1, QueueOutcome::Rejected);
    assert_eq!(locked[0].0.payload, 3);
    assert!(queue.shown().is_none());
    assert_eq!(queue.len(), 2);
    assert!(queue.tick(49_999).is_empty());
    let timed_out = queue.tick(50_000);
    assert_eq!(timed_out.len(), 1);
    assert_eq!(timed_out[0].0.payload, 2);
    assert_eq!(timed_out[0].1, QueueOutcome::TimedOut);
    assert_eq!(queue.len(), 1);
}

/// The per-origin limit of 16 counts the shown item.
#[test]
fn ap7_per_origin_limit_counts_the_shown_item() {
    let mut queue: ApprovalQueue<u32> = ApprovalQueue::default();
    assert!(queue.enqueue(site("https://a.example", 600_000), 0).is_ok());
    assert!(queue.show_next(0, &mut Vec::new()).is_some());
    for n in 1..16 {
        assert!(queue.enqueue(site("https://a.example", 600_000), n).is_ok());
    }
    assert_eq!(queue.len(), MAX_APPROVALS_PER_ORIGIN);
    assert_eq!(
        queue.enqueue(site("https://a.example", 600_000), 16),
        Err(QueueOutcome::TooManyPending)
    );
    assert!(
        queue
            .enqueue(site("https://b.example", 600_000), 17)
            .is_ok()
    );
    // The shown item gone: one more fits.
    assert!(queue.finish_shown(QueueOutcome::Approved).is_some());
    assert!(
        queue
            .enqueue(site("https://a.example", 600_000), 18)
            .is_ok()
    );
}

/// `restart_interaction` (the App's C1 step after acting on `Approved`) keeps the checkbox, the arm
/// delay start, `submitting`, the deadline and the previous press; it clears a hold.
#[test]
fn ap7_restart_interaction_keeps_ack_arm_and_submitting() {
    let mut s = high_checked(500);
    s.event(1_000, PRESS);
    assert_eq!(
        s.event(3_000, InteractionEvent::Tick),
        InteractionStatus::Approved
    );
    s.gate.submitting = true;
    let before = s.gate.clone();
    s.restart_interaction(3_050)
        .unwrap_or_else(|_| unreachable!("deadline ahead"));
    assert_eq!(s.gate, before);
    assert_eq!(s.interaction().status(), InteractionStatus::Pending);
    assert_eq!(s.interaction().hold_source(), None);
    assert_eq!(s.interaction().last_press_ms(), Some(1_000));
    assert_eq!(
        s.interaction().lifetime_remaining_ms(3_050),
        120_000 - 3_050
    );
    // `submitting` disarms at the next event.
    s.event(5_000, PRESS);
    assert!(!s.interaction().is_armed());
    assert_eq!(s.interaction().hold_source(), None);
    assert_eq!(
        s.event(8_000, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
}

/// `submitting` blocks every approving input of both levels until it clears.
#[test]
fn ap7_submitting_blocks_approve() {
    let mut s = session(message(RiskLevel::Info, false, 0), 0);
    s.gate.submitting = true;
    assert!(!can_approve(&s.gate, 5_000));
    assert!(!s.approve_ready(5_000));
    assert!(!s.arm_waiting(5_000), "not the window's own timing");
    assert_eq!(s.event(5_000, ENTER), InteractionStatus::Pending);
    s.event(6_000, PRESS);
    assert_eq!(s.event(6_001, RELEASE), InteractionStatus::Pending);
    let mut high = high_checked(500);
    high.gate.submitting = true;
    high.event(2_000, PRESS);
    assert_eq!(high.interaction().hold_source(), None);
    assert_eq!(
        high.event(5_000, InteractionEvent::Tick),
        InteractionStatus::Pending
    );
    s.gate.submitting = false;
    // The presses while `submitting` were unarmed presses: the delay restarted at 6 000.
    assert_eq!(s.gate.ready_at_ms, 6_000);
    assert_eq!(s.event(7_001, ENTER), InteractionStatus::Approved);
}

/// The deadline the App gives the gate is `min(site, Ready + 120 s)` from the queue
/// (`shown_deadline`), the site deadline alone while preparing; the interaction's own lifetime is
/// clamped to `1..=MAX_LIFETIME_MS` from the session start.
#[test]
fn ap7_deadline_is_min_of_site_and_display() {
    let mut queue: ApprovalQueue<u32> = ApprovalQueue::default();
    let _ = queue.enqueue(site("https://a.example", 600_000), 1);
    queue.show_next(0, &mut Vec::new());
    assert_eq!(queue.shown_deadline(), Some(600_000));
    queue.mark_ready(10_000);
    assert_eq!(queue.shown_deadline(), Some(130_000));
    queue.mark_ready(20_000);
    assert_eq!(
        queue.shown_deadline(),
        Some(130_000),
        "the first Ready counts"
    );
    let mut app: ApprovalQueue<u32> = ApprovalQueue::default();
    let _ = app.enqueue(QueueSource::App, 1);
    app.show_next(0, &mut Vec::new());
    app.mark_ready(5_000);
    assert_eq!(app.shown_deadline(), Some(125_000));

    let start = |deadline_ms| {
        ApprovalSession::new(
            ApprovalGate {
                prepare: PrepareState::Ready(ReadyContent::Signing(Box::new(message(
                    RiskLevel::Info,
                    false,
                    0,
                )))),
                ack_checked: false,
                connect_selected: 0,
                ready_at_ms: 0,
                is_foreground: true,
                deadline_ms,
                submitting: false,
            },
            0,
        )
        .unwrap_or_else(|_| unreachable!("valid session"))
    };
    let s = start(MAX_LIFETIME_MS + 100_000);
    assert_eq!(s.interaction().lifetime_remaining_ms(0), MAX_LIFETIME_MS);
    let mut s = start(MAX_LIFETIME_MS + 100_000);
    assert_eq!(
        s.event(MAX_LIFETIME_MS, InteractionEvent::Tick),
        InteractionStatus::Rejected,
        "the interaction's own clamp"
    );
    let mut s = start(0);
    assert_eq!(s.interaction().lifetime_remaining_ms(0), 1);
    assert!(!can_approve(&s.gate, 0));
    assert_eq!(
        s.event(1, InteractionEvent::Tick),
        InteractionStatus::Rejected
    );
}

/// L-2's engine half (spec/04 §3.4): once the status is `Approved`, `restart_arm_delay`, the
/// checkbox, the foreground and every event leave it `Approved` (a Reject does nothing) while the
/// gate's values (`ready_at`, the checkbox, the foreground) still move; only
/// `restart_interaction` brings a pending interaction back.
#[test]
fn ap7_restart_arm_delay_while_approved_does_nothing() {
    let mut s = session(message(RiskLevel::Info, false, 0), 0);
    s.event(1_000, PRESS);
    assert_eq!(s.event(1_001, RELEASE), InteractionStatus::Approved);
    s.restart_arm_delay(1_100);
    assert_eq!(s.gate.ready_at_ms, 1_100, "the gate moves");
    assert_eq!(s.interaction().status(), InteractionStatus::Approved);
    assert_eq!(
        s.event(1_200, InteractionEvent::RejectActivated),
        InteractionStatus::Approved
    );
    // 2026-11-18 (S4 A1 review): the gate's checkbox and foreground values move too.
    s.set_ack(1_300, true);
    assert!(s.gate.ack_checked);
    assert_eq!(s.interaction().status(), InteractionStatus::Approved);
    s.set_foreground(1_400, false);
    assert!(!s.gate.is_foreground);
    assert_eq!(s.gate.ready_at_ms, 1_100);
    s.set_foreground(1_500, true);
    assert!(s.gate.is_foreground);
    assert_eq!(
        s.gate.ready_at_ms, 1_500,
        "re-activation restarts the arm delay"
    );
    assert_eq!(s.interaction().status(), InteractionStatus::Approved);
    assert_eq!(
        s.event(200_000, InteractionEvent::Tick),
        InteractionStatus::Approved
    );
    s.restart_interaction(1_600)
        .unwrap_or_else(|_| unreachable!("deadline ahead"));
    assert_eq!(s.interaction().status(), InteractionStatus::Pending);
    assert_eq!(
        s.event(1_700, InteractionEvent::RejectActivated),
        InteractionStatus::Rejected
    );
}

// ----- AP-7 fuzz-lite (spec/09 §2.4) ---------------------------------------------------------

/// Iterations: `YW_FUZZ_RUNS` when set to a positive number (the short smoke run of
/// `scripts/check.ps1`), otherwise 1,000,000 (spec/09 §2.4).
#[expect(
    clippy::disallowed_methods,
    reason = "the iteration count of a test tool; yw-engine itself never reads the environment"
)]
fn fuzz_runs() -> u32 {
    std::env::var("YW_FUZZ_RUNS")
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|&runs| runs > 0)
        .unwrap_or(1_000_000)
}

/// xorshift64* (the seed is fixed in the test).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }

    fn flag(&mut self) -> bool {
        self.next() & 1 == 1
    }

    fn connect_count(&mut self) -> usize {
        match self.below(4) {
            0 => 0,
            1 => 1,
            2 => 16,
            _ => 17,
        }
    }
}

/// Content kinds of the fuzz: Info, High with the flag, High without it, Blocked, a Caution
/// transaction whose simulation failed, a connect window, preparing and failed.
fn fuzz_content(rng: &mut Rng) -> PrepareState {
    let signing = |request| PrepareState::Ready(ReadyContent::Signing(Box::new(request)));
    // 2026-11-18 (S4 A1 review): weighted towards High (four of eleven) so that the short
    // gate run reaches High approvals more than a few dozen times.
    match rng.below(11) {
        0 => signing(message(RiskLevel::Info, false, 0)),
        1 | 8 => signing(message(RiskLevel::High, true, 1)),
        2 | 9 => signing(message(RiskLevel::High, false, 2)),
        3 => signing(message(RiskLevel::Blocked, false, 1)),
        4 | 10 => signing(request(
            RiskLevel::Caution,
            false,
            0,
            ApprovalKind::EvmTransaction,
            SimulationBinding::None {
                reason: SimNoneReason::Timeout,
            },
        )),
        5 => PrepareState::Ready(ReadyContent::Connect(ConnectView { accounts: 20 })),
        6 => PrepareState::Preparing(PrepareStage::Simulating { since_ms: 0 }),
        _ => PrepareState::Failed {
            code: ErrorCode::Rpc001,
            retryable: true,
        },
    }
}

fn fuzz_event(rng: &mut Rng) -> InteractionEvent {
    match rng.below(14) {
        0..=2 => InteractionEvent::Tick,
        3 => InteractionEvent::ApproveActivated {
            physical: rng.flag(),
        },
        4 => InteractionEvent::RejectActivated,
        5 | 6 => InteractionEvent::PointerPressed {
            inside: rng.below(4) != 0,
            click_through: rng.below(4) == 0,
            physical_down: rng.below(4) != 0,
        },
        7 => InteractionEvent::PointerMoved {
            inside: rng.below(4) != 0,
        },
        8 => InteractionEvent::PointerReleased {
            physical_down: rng.below(4) == 0,
        },
        9 => InteractionEvent::SpacePressed {
            repeat: rng.below(4) == 0,
            physical_down: rng.below(4) != 0,
        },
        10 => InteractionEvent::SpaceReleased {
            physical_down: rng.below(4) == 0,
        },
        11 => match rng.below(4) {
            0 => InteractionEvent::FocusLost,
            1 => InteractionEvent::ForegroundLost,
            2 => InteractionEvent::CaptureLost,
            _ => InteractionEvent::CancelMode,
        },
        _ => InteractionEvent::OtherPress,
    }
}

/// What the gate needs for an approving input at `now` (spec/04 §3.4), written out again here
/// rather than calling `can_approve`: approvable content, the checkbox when required, the arm
/// delay, the foreground, the deadline and not `submitting`.
fn fuzz_gate_open(gate: &ApprovalGate, now: u64) -> bool {
    let content = match &gate.prepare {
        PrepareState::Ready(ReadyContent::Signing(request)) => {
            request.display.risk != RiskLevel::Blocked && (!ack_needed(request) || gate.ack_checked)
        }
        PrepareState::Ready(ReadyContent::Connect(_)) => (1..=16).contains(&gate.connect_selected),
        PrepareState::Preparing(_) | PrepareState::Failed { .. } => false,
    };
    content
        && now >= gate.ready_at_ms + APPROVE_ARM_DELAY_MS
        && gate.is_foreground
        && now < gate.deadline_ms
        && !gate.submitting
}

fn fuzz_risk(gate: &ApprovalGate) -> Option<InteractionRisk> {
    match &gate.prepare {
        PrepareState::Ready(ReadyContent::Signing(request)) => interaction_risk(request),
        PrepareState::Ready(ReadyContent::Connect(_)) => Some(InteractionRisk::Standard),
        PrepareState::Preparing(_) | PrepareState::Failed { .. } => None,
    }
}

/// What the fuzz remembers about the hold under way: when it started, the gate's `ready_at` then,
/// and whether a session operation that must cancel a hold (an arm-delay restart, a foreground
/// change, an acknowledgement change where one is required, a content replacement or an
/// interaction restart) has happened since.
#[derive(Default)]
struct FuzzHold {
    started: Option<(u64, u64)>,
    disturbed: bool,
}

/// Checks one session event: a hold starts only on an armed, spaced, physical press of an
/// approvable request; an event never leaves a terminal status (`Approved` stays, `Rejected`
/// stays); and `Approved` appears only with every one of its conditions (Standard: a spaced
/// physical Enter or the release of such a hold; High: a hold ≥ 2 s), where an approving hold
/// started ≥ 1 s after the gate's current `ready_at` and survived no cancelling operation.
/// Returns the level of the approval this event made, if it made one.
fn fuzz_check_event(
    s: &mut ApprovalSession,
    tracker: &mut FuzzHold,
    now: u64,
    event: InteractionEvent,
) -> Option<InteractionRisk> {
    let gate = s.gate.clone();
    let risk = fuzz_risk(&gate);
    let before = s.interaction().status();
    let hold = s.interaction().hold_source();
    let remaining = s.interaction().hold_remaining_ms(now);
    let spaced = s
        .interaction()
        .last_press_ms()
        .is_none_or(|last| now >= last + APPROVE_ARM_DELAY_MS);
    let after = s.event(now, event);
    if before != InteractionStatus::Pending {
        // 2026-11-18 (S4 A1 review): only `restart_interaction`/`replace_content` renew it.
        assert_eq!(after, before, "an event left a terminal status: {event:?}");
        return None;
    }
    if hold.is_none() && s.interaction().hold_source().is_some() {
        assert!(
            fuzz_gate_open(&gate, now),
            "hold without the gate: {event:?}"
        );
        assert!(spaced, "hold within 1 s of a press");
        assert!(risk.is_some(), "hold on blocked content");
        assert!(matches!(
            event,
            InteractionEvent::PointerPressed {
                inside: true,
                click_through: false,
                physical_down: true,
            } | InteractionEvent::SpacePressed {
                repeat: false,
                physical_down: true,
            }
        ));
        *tracker = FuzzHold {
            started: Some((now, gate.ready_at_ms)),
            disturbed: false,
        };
    }
    if after == InteractionStatus::Approved {
        assert!(
            fuzz_gate_open(&gate, now),
            "approved without the gate: {event:?}"
        );
        if hold.is_some() {
            let (started, ready_at) = tracker
                .started
                .unwrap_or_else(|| unreachable!("a hold the fuzz did not see start"));
            assert!(!tracker.disturbed, "a hold survived a cancelling operation");
            assert_eq!(ready_at, gate.ready_at_ms, "the gate moved under a hold");
            assert!(
                started >= gate.ready_at_ms + APPROVE_ARM_DELAY_MS,
                "a hold started before the arm delay"
            );
        }
        match risk {
            Some(InteractionRisk::Standard) => match event {
                InteractionEvent::ApproveActivated { physical: true } => assert!(spaced),
                InteractionEvent::PointerReleased {
                    physical_down: false,
                } => assert_eq!(hold, Some(HoldSource::Pointer)),
                InteractionEvent::SpaceReleased {
                    physical_down: false,
                } => assert_eq!(hold, Some(HoldSource::Space)),
                other => unreachable!("Standard approved by {other:?}"),
            },
            // Any event may be the one that sees the completed hold (a Tick, a key press):
            // what approves is the hold, never the event itself.
            Some(InteractionRisk::High) => {
                assert!(hold.is_some(), "High approved without a hold");
                assert_eq!(remaining, Some(0), "High approved before 2 s");
            }
            None => unreachable!("approved blocked, preparing or failed content"),
        }
        return risk;
    }
    None
}

/// Whether the shown content needs the acknowledgement box for approval.
fn fuzz_ack_required(gate: &ApprovalGate) -> bool {
    matches!(
        &gate.prepare,
        PrepareState::Ready(ReadyContent::Signing(request))
            if request.display.risk != RiskLevel::Blocked && ack_needed(request)
    )
}

/// The session-level operations the App performs besides events; none of them approves.
/// Marks `tracker` disturbed when the operation must cancel a hold under way (the raw
/// `submitting`/`connect_selected` writes are judged by the next event's re-arm instead).
fn fuzz_other_step(s: &mut ApprovalSession, tracker: &mut FuzzHold, rng: &mut Rng, now: u64) {
    let before = s.interaction().status();
    let cancels = match rng.below(7) {
        0 => {
            let foreground = rng.below(5) != 0;
            let changed = foreground != s.gate.is_foreground;
            s.set_foreground(now, foreground);
            changed
        }
        1 => {
            let checked = rng.flag();
            let changed = checked != s.gate.ack_checked && fuzz_ack_required(&s.gate);
            s.set_ack(now, checked);
            changed
        }
        2 => {
            s.restart_arm_delay(now);
            true
        }
        3 => {
            let content = fuzz_content(rng);
            let _ = s.replace_content(now, content);
            true
        }
        4 => {
            s.gate.submitting = rng.below(3) == 0;
            let _ = s.restart_interaction(now);
            true
        }
        5 => {
            s.gate.connect_selected = rng.connect_count();
            false
        }
        _ => {
            s.gate.submitting = rng.below(4) == 0;
            false
        }
    };
    tracker.disturbed |= cancels;
    // 2026-11-18 (S4 A1 review): from any status, not only `Pending`.
    assert!(
        before == InteractionStatus::Approved
            || s.interaction().status() != InteractionStatus::Approved,
        "only an event approves"
    );
}

/// AP-7 fuzz-lite: random sessions (Info, High with and without the flag, Blocked, a failed
/// simulation, connect with 0/1/16/17 accounts, preparing, failed) driven by random events,
/// foreground flips, checkbox toggles, arm-delay restarts, content replacements, interaction
/// restarts and `submitting`, with time mostly moving forward. Whenever the status turns
/// `Approved` (from any status), every condition of spec/04 §3.4 held at that moment and an
/// approving hold started ≥ 1 s after the gate's current `ready_at` with no cancelling session
/// operation since; a hold never starts without them; no event leaves `Approved` or
/// `Rejected`; nothing but an event approves. (2026-11-18, S4 A1 review: the last three checks
/// and the High weighting were added; the 20,000-run gate step reaches 162 High and 318
/// Standard approvals, was 30 and 496.)
#[test]
#[ignore = "fuzz-lite (spec/09 §2.4 fallback)"]
fn fuzz_lite_approval_never_without_its_conditions() {
    let mut rng = Rng(0x5eed_a9a7_0000_0001);
    // The invariant must not pass on nothing: both levels are approved somewhere in the run.
    let (mut standard, mut high) = (0_u64, 0_u64);
    for _ in 0..fuzz_runs() {
        let mut now = rng.below(5_000);
        let gate = ApprovalGate {
            prepare: fuzz_content(&mut rng),
            ack_checked: rng.flag(),
            connect_selected: rng.connect_count(),
            ready_at_ms: now,
            is_foreground: rng.below(4) != 0,
            deadline_ms: now + 120_000,
            submitting: false,
        };
        let mut s =
            ApprovalSession::new(gate, now).unwrap_or_else(|_| unreachable!("valid session"));
        let mut tracker = FuzzHold::default();
        // 2026-11-18 (S4 A1 review): half of the sessions are calm — fewer session
        // operations, and mostly `Tick` while a hold is under way — so that holds complete.
        let calm = rng.flag();
        for _ in 0..64 {
            now = match rng.below(64) {
                0 => now.saturating_sub(1 + rng.below(100)),
                1..=4 => now + 1_000 + rng.below(3_000),
                5 => now + 20_000 + rng.below(110_000),
                _ => now + rng.below(400),
            };
            if rng.below(if calm { 8 } else { 3 }) == 0 {
                fuzz_other_step(&mut s, &mut tracker, &mut rng, now);
            } else {
                let event = if calm && s.interaction().hold_source().is_some() && rng.below(8) != 0
                {
                    InteractionEvent::Tick
                } else {
                    fuzz_event(&mut rng)
                };
                match fuzz_check_event(&mut s, &mut tracker, now, event) {
                    Some(InteractionRisk::Standard) => standard += 1,
                    Some(InteractionRisk::High) => high += 1,
                    None => {}
                }
            }
        }
    }
    assert!(
        standard > 0 && high > 0,
        "approvals: {standard} standard, {high} high"
    );
}
