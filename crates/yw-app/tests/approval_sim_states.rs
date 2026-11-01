//! AP-6 (spec/04 §3.9, D15/D16): the approval window for every simulation state, built from the
//! requests the `flow::evm` pipeline produces with a fake transport (no hand-made displays): one
//! band and one checkbox for `Unsupported`/`NoResult`/`Reverted`/`Incomplete`, the checkbox and
//! the 2 s hold, Enter ignored, `Ok` approving with a click, `Blocked` never approving, inputs
//! ignored while `Preparing(Simulating)`, E12 + `NoResult` with one checkbox, and the
//! re-simulation click that turns into `NoResult` (content replaced, checkbox cleared, not
//! consumed, then checkbox + 2 s approves without another re-simulation).

mod common;

use common::evm::{
    NEW, S2_UNIX_MS, TestResult, USER, address, fake, fixture, job, ready, send_intent, user_chain,
    world,
};
use common::{Answer, FakeClock};
use yw_app::errors::ErrorCode;
use yw_app::flow::evm::ChainCache;
use yw_app::flow::evm::prepare::{Prepared, prepare};
use yw_app::ui::approval_view::{ApprovalView, Block, view};
use yw_app::ui::interaction::{
    ApprovalGate, ApprovalSession, HIGH_RISK_HOLD_MS, InteractionEvent, InteractionStatus,
    PrepareStage, PrepareState, ReadyContent, SimState, ack_needed, can_approve, sim_state,
};
use yw_core::approval::{ApprovalRequest, ApprovalStore, RiskLevel, SimulationBinding};
use yw_core::evm::amount::U256;
use yw_core::evm::chain::{SEPOLIA_GENESIS, SimulationSupport, sepolia};
use yw_core::evm::risk::{E01, E12};
use yw_core::evm::simulate::needs_resimulation;

const PRESS: InteractionEvent = InteractionEvent::PointerPressed {
    inside: true,
    click_through: false,
    physical_down: true,
};
const RELEASE: InteractionEvent = InteractionEvent::PointerReleased {
    physical_down: false,
};
const READY_AT: u64 = 10_000;

/// Runs the preparation against a Sepolia-like fake with `simulate` as the `eth_simulateV1`
/// answer and issues the draft.
fn sepolia_request(simulate: Answer, data: Vec<u8>) -> TestResult<(Prepared, ApprovalRequest)> {
    let mut overrides = vec![("eth_simulateV1", simulate)];
    if !data.is_empty() {
        overrides.push(("eth_getCode", Answer::Result("\"0x6080\"".to_owned())));
    }
    let rpc = fake(world(11_155_111, SEPOLIA_GENESIS, overrides));
    let clock = FakeClock::at(S2_UNIX_MS);
    let mut intent = send_intent()?;
    if !data.is_empty() {
        intent.value = U256::ZERO;
        intent.data = data;
    }
    let job = job(sepolia(), address(USER)?, intent);
    let prepared = ready(
        prepare(
            &rpc.shared(),
            &mut ChainCache::default(),
            &job,
            &clock,
            &|_| {},
        )
        .outcome,
    )?;
    let request = ApprovalStore::new().issue(prepared.draft.clone(), 1, S2_UNIX_MS)?;
    Ok((prepared, request))
}

fn unsupported_request() -> TestResult<ApprovalRequest> {
    let genesis = [0x11; 32];
    let rpc = fake(world(84_532, genesis, Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    let job = job(
        user_chain(84_532, genesis, SimulationSupport::Unsupported),
        address(USER)?,
        send_intent()?,
    );
    let prepared = ready(
        prepare(
            &rpc.shared(),
            &mut ChainCache::default(),
            &job,
            &clock,
            &|_| {},
        )
        .outcome,
    )?;
    Ok(ApprovalStore::new().issue(prepared.draft, 1, S2_UNIX_MS)?)
}

fn signing(request: &ApprovalRequest) -> PrepareState {
    PrepareState::Ready(ReadyContent::Signing(Box::new(request.clone())))
}

fn session(prepare: PrepareState) -> TestResult<ApprovalSession> {
    Ok(ApprovalSession::new(
        ApprovalGate {
            prepare,
            ack_checked: false,
            connect_selected: 0,
            ready_at_ms: READY_AT,
            is_foreground: true,
            deadline_ms: READY_AT + 120_000,
            submitting: false,
        },
        READY_AT,
    )
    .map_err(|error| format!("{error:?}"))?)
}

fn hold(session: &mut ApprovalSession, start: u64, duration: u64) -> InteractionStatus {
    session.event(start, PRESS);
    session.event(start + duration, InteractionEvent::Tick)
}

fn acks(view: &ApprovalView) -> usize {
    view.blocks
        .iter()
        .filter(|block| matches!(block, Block::Ack))
        .count()
}

fn render(request: &ApprovalRequest) -> TestResult<ApprovalView> {
    Ok(view(&signing(request), 0, false, true, Vec::new(), true, None).map_err(ErrorCode::code)?)
}

/// The D16 sequence on a fresh session for each step.
fn assert_checkbox_and_hold(request: &ApprovalRequest) -> TestResult {
    let start = READY_AT + 1_500;
    // Enter is ignored for the high-risk interaction.
    let mut s = session(signing(request))?;
    s.set_ack(start, true);
    assert_eq!(
        s.event(start, InteractionEvent::ApproveActivated { physical: true }),
        InteractionStatus::Pending
    );
    // Unchecked + 2 s hold → pending.
    let mut s = session(signing(request))?;
    assert_eq!(
        hold(&mut s, start, HIGH_RISK_HOLD_MS + 1_000),
        InteractionStatus::Pending
    );
    // Checked + 1.9 s → pending; checked + 2.0 s → approved.
    let mut s = session(signing(request))?;
    s.set_ack(start, true);
    assert_eq!(hold(&mut s, start, 1_900), InteractionStatus::Pending);
    let mut s = session(signing(request))?;
    s.set_ack(start, true);
    assert_eq!(
        hold(&mut s, start, HIGH_RISK_HOLD_MS),
        InteractionStatus::Approved
    );
    Ok(())
}

#[test]
fn ap6_unsuccessful_states_show_one_band_and_one_checkbox() -> TestResult {
    let cases = [
        (
            sepolia_request(Answer::Envelope(fixture("S3")), Vec::new())?.1,
            SimState::Reverted,
            ErrorCode::Sim001,
        ),
        (
            sepolia_request(Answer::Envelope(fixture("S4")), Vec::new())?.1,
            SimState::NoResult,
            ErrorCode::Sim002,
        ),
        (
            unsupported_request()?,
            SimState::Unsupported,
            ErrorCode::Sim003,
        ),
        (
            sepolia_request(Answer::Envelope(fixture("S7")), Vec::new())?.1,
            SimState::Incomplete,
            ErrorCode::Sim004,
        ),
    ];
    for (request, state, code) in cases {
        assert_eq!(sim_state(&request), Some(state));
        assert_eq!(request.display.risk, RiskLevel::High, "{state:?}");
        assert!(request.display.ack_required);
        assert!(ack_needed(&request));
        let shown = render(&request)?;
        let band = shown.band.as_ref().ok_or("band")?;
        assert!(
            band.head.ends_with(&format!("({})", code.code())),
            "{}",
            band.head
        );
        assert_eq!(band.retry, state == SimState::NoResult);
        assert_eq!(acks(&shown), 1, "{state:?}");
        assert!(shown.high && !shown.blocked);
        // The band warning is not repeated in the scrolling area.
        let first = band.head.split(" (E-SIM").next().unwrap_or("");
        assert!(
            !shown.blocks.iter().any(
                |block| matches!(block, Block::Warning { text, .. } if text.starts_with(first))
            )
        );
        assert_checkbox_and_hold(&request)?;
    }
    Ok(())
}

#[test]
fn ap6_ok_with_information_approves_with_a_click() -> TestResult {
    let (_, request) = sepolia_request(Answer::Envelope(fixture("S2")), Vec::new())?;
    assert_eq!(sim_state(&request), Some(SimState::Ok));
    assert!(!ack_needed(&request));
    let shown = render(&request)?;
    assert_eq!(shown.band, None);
    assert_eq!(acks(&shown), 0);
    assert!(
        shown
            .blocks
            .iter()
            .any(|block| matches!(block, Block::Field { label, .. } if label.starts_with("보냄")))
    );
    let mut s = session(signing(&request))?;
    s.event(READY_AT + 1_000, PRESS);
    assert_eq!(
        s.event(READY_AT + 1_001, RELEASE),
        InteractionStatus::Approved
    );
    Ok(())
}

#[test]
fn ap6_blocked_never_approves_whatever_the_simulation() -> TestResult {
    let rpc = fake(world(11_155_111, SEPOLIA_GENESIS, Vec::new()));
    let clock = FakeClock::at(S2_UNIX_MS);
    let mut capped = job(sepolia(), address(USER)?, send_intent()?);
    capped.chain.caps.max_total_fee = U256::from_u64(1_000);
    let prepared = ready(
        prepare(
            &rpc.shared(),
            &mut ChainCache::default(),
            &capped,
            &clock,
            &|_| {},
        )
        .outcome,
    )?;
    let request = ApprovalStore::new().issue(prepared.draft, 1, S2_UNIX_MS)?;
    assert_eq!(request.display.risk, RiskLevel::Blocked);
    let shown = render(&request)?;
    assert!(shown.blocked);
    assert_eq!(acks(&shown), 0);
    let mut s = session(signing(&request))?;
    s.set_ack(READY_AT + 1_500, true);
    assert_eq!(
        s.event(
            READY_AT + 2_000,
            InteractionEvent::ApproveActivated { physical: true }
        ),
        InteractionStatus::Pending
    );
    assert_eq!(
        hold(&mut s, READY_AT + 3_000, 5_000),
        InteractionStatus::Pending
    );
    s.event(READY_AT + 9_000, PRESS);
    assert_eq!(
        s.event(READY_AT + 9_001, RELEASE),
        InteractionStatus::Pending
    );
    Ok(())
}

#[test]
fn ap6_inputs_are_ignored_while_simulating() -> TestResult {
    let simulating = PrepareState::Preparing(PrepareStage::Simulating { since_ms: READY_AT });
    let mut s = session(simulating.clone())?;
    s.set_ack(READY_AT + 1_500, true);
    assert!(!can_approve(&s.gate, READY_AT + 5_000));
    assert_eq!(
        s.event(
            READY_AT + 5_000,
            InteractionEvent::ApproveActivated { physical: true }
        ),
        InteractionStatus::Pending
    );
    s.event(READY_AT + 5_100, PRESS);
    assert_eq!(
        s.event(READY_AT + 5_101, RELEASE),
        InteractionStatus::Pending
    );
    assert_eq!(
        hold(&mut s, READY_AT + 6_000, 3_000),
        InteractionStatus::Pending
    );
    // The notice counts up to 10 s and stops there.
    let shown = view(
        &simulating,
        READY_AT + 12_000,
        false,
        true,
        Vec::new(),
        true,
        None,
    )
    .map_err(ErrorCode::code)?;
    assert_eq!(
        shown.blocks,
        vec![Block::Notice("시뮬레이션 중… (10/10초)".to_owned())]
    );
    // A failed preparation is blocked; its retry is never an E-SIM code.
    let failed = view(
        &PrepareState::Failed {
            code: ErrorCode::Rpc001,
            retryable: true,
        },
        0,
        false,
        true,
        Vec::new(),
        true,
        None,
    )
    .map_err(ErrorCode::code)?;
    assert!(failed.blocked && failed.band.is_none());
    Ok(())
}

#[test]
fn ap6_uninterpreted_call_with_no_result_has_one_checkbox() -> TestResult {
    let data = vec![0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 1];
    let (_, request) = sepolia_request(Answer::Envelope(fixture("S4")), data)?;
    let rules: Vec<_> = request
        .display
        .warnings
        .iter()
        .map(|warning| warning.rule)
        .collect();
    assert!(rules.contains(&E12) && rules.contains(&E01), "{rules:?}");
    let shown = render(&request)?;
    assert!(shown.band.is_some());
    assert_eq!(acks(&shown), 1);
    assert_checkbox_and_hold(&request)
}

#[test]
fn ap6_resimulation_failure_replaces_the_content_and_needs_a_new_approval() -> TestResult {
    // An `Ok` request shown for more than 60 s: the click asks for a re-simulation.
    let (prepared, request) = sepolia_request(Answer::Envelope(fixture("S2")), Vec::new())?;
    let mut store = ApprovalStore::new();
    let shown_request = store.issue(prepared.draft.clone(), READY_AT, S2_UNIX_MS)?;
    let click_at = READY_AT + 61_000;
    assert!(needs_resimulation(&request.simulation, READY_AT, click_at));
    let mut s = session(signing(&shown_request))?;
    s.event(click_at, PRESS);
    assert_eq!(s.event(click_at + 1, RELEASE), InteractionStatus::Approved);
    // The app now shows "시뮬레이션 중…" (submitting) and the re-run gives no result.
    s.gate.submitting = true;
    assert!(!can_approve(&s.gate, click_at + 10));
    let (no_result, _) = sepolia_request(Answer::Envelope(fixture("S4")), Vec::new())?;
    let replaced = store.replace(
        shown_request.id,
        shown_request.digest,
        no_result.draft.clone(),
    )?;
    let replace_at = click_at + 3_000;
    s.replace_content(replace_at, signing(&replaced))
        .map_err(|error| format!("{error:?}"))?;
    assert!(!s.gate.ack_checked);
    assert_eq!(s.gate.ready_at_ms, replace_at);
    assert!(!s.gate.submitting);
    assert!(matches!(
        replaced.simulation,
        SimulationBinding::None { .. }
    ));
    // Checkbox + 2 s → approved, and no further re-simulation for a `None` binding.
    s.set_ack(replace_at + 1_200, true);
    assert_eq!(
        hold(&mut s, replace_at + 1_500, HIGH_RISK_HOLD_MS),
        InteractionStatus::Approved
    );
    assert!(!needs_resimulation(
        &replaced.simulation,
        0,
        replace_at + 600_000
    ));
    // The earlier click consumed nothing: the replaced request is still pending.
    assert!(
        store
            .consume(replaced.id, replaced.digest, replace_at + 4_000)
            .is_ok()
    );
    let _ = NEW;
    Ok(())
}
