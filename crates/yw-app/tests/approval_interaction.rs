//! AP-1…AP-5 (spec/04 §3.9).
//!
//! AP-1 ports the interaction tests of `archive/spec-v2.4:crates/approval-ui/src/lib.rs:580-1006`
//! with the risk mapping (`Standard`/`High`); the removed stream codec and plain-text renderer
//! tests are not ported. AP-2 covers the gate (`armed`, one checkbox, 2 s hold, arm delay,
//! content replacement), AP-3 the queue, AP-4 the display re-check and line layout, AP-5 the
//! absence of any AI input to `can_approve`.

use core::fmt::Write as _;

use yw_app::errors::ErrorCode;
use yw_app::ui::approval::{
    ApprovalQueue, MAX_APPROVALS_GLOBAL, MAX_APPROVALS_PER_ORIGIN, QueueOutcome, QueueSource,
    validate_for_display,
};
use yw_app::ui::interaction::{
    ApprovalGate, ApprovalInteraction, ApprovalSession, ConnectView, HIGH_RISK_HOLD_MS, HoldSource,
    InteractionEvent, InteractionRisk, InteractionStatus, PrepareStage, PrepareState, ReadyContent,
    ack_needed, can_approve,
};
use yw_app::ui::text_layout::{layout, rejoin};
use yw_core::approval::{
    AccountRef, ApprovalDisplay, ApprovalId, ApprovalKind, ApprovalOrigin, ApprovalRequest,
    ApprovalStore, ChainRef, DisplayField, FieldKey, RiskLevel, RuleId, SigningPayload,
    SimNoneReason, SimulationBinding, Warning,
};
use yw_core::bip32::path::AccountIndex;
use yw_core::evm::address::Address;
use yw_core::evm::chain::SEPOLIA_GENESIS;
use yw_core::vault::EvmKeySource;

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
        i.apply(20_001, InteractionEvent::ApproveActivated),
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
        i.apply(10, InteractionEvent::ApproveActivated),
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
    i.apply(1_800, PRESS);
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
    i.apply(900, space(false, true));
    assert_eq!(i.hold_source(), Some(HoldSource::Space));
    assert_eq!(
        i.apply(2_900, InteractionEvent::Tick),
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
        backwards.apply(499, InteractionEvent::ApproveActivated),
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
        i.apply(10, InteractionEvent::ApproveActivated),
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
        s.event(2_000, InteractionEvent::ApproveActivated),
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
        s.event(10_999, InteractionEvent::ApproveActivated),
        InteractionStatus::Pending
    );
    s.event(11_000, PRESS);
    assert_eq!(s.event(11_001, RELEASE), InteractionStatus::Approved);
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
        s.event(2_000, InteractionEvent::ApproveActivated),
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
        display: ApprovalDisplay::new("[Sepolia 테스트넷] 시험".to_owned(), Vec::new(), Vec::new())
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
