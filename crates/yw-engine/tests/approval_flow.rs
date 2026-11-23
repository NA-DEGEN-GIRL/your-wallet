//! The approval flow of `yw_engine::Wallet` under both reply schedules of
//! `testkit::RecordingShell` (2026-11-23, S4d E2; plan §3.7, D-25, the S4d preflight's corrected
//! row E2 and O-5; spec/15 §3.2, §11.4 S4): `Immediate` is the Windows schedule (the effects an
//! entry queued are applied before it returns, each answer back at once), `Deferred` the Android
//! one (applied after the entry returned, the answers after the batch, each an entry of its own).
//! The wallet alone, with the recording shell's model as its shell: no yw-app, no window, no
//! file, no network, no card reader, no clipboard. The frozen goldens are not compared here: the
//! yw-app headless runners reproduce them with the Windows shell's executor under both schedules
//! (`app_approval::flow_tests::lifecycle::headless`, `app::tests::s4_secret`); these are the
//! Wallet-only scenarios that need no shell map, for Android parity, and the model's own tests.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use yw_core::bip32::path::AccountIndex;
use yw_core::evm::address::parse_address;
use yw_core::hypercore::display::HcRecipient;
use yw_core::hypercore::{HcAction, HcNetwork, HcPayload};
use yw_core::vault::{EvmKeySource, FileKind};
use yw_engine::apikeys::ApiKeys;
use yw_engine::app_store::{AppStore, SealedRead};
use yw_engine::approval::QueueSource;
use yw_engine::approval::flow::{ApprovalEffect, OpenOutcome, ShownId};
use yw_engine::cmd::{Cmd, CopyMark, Press};
use yw_engine::effect::{Effect, Folder};
use yw_engine::errors::ErrorCode;
use yw_engine::form::EditField;
use yw_engine::services::Services;
use yw_engine::settings::Settings;
use yw_engine::testkit::{RecordingShell, Schedule};
use yw_engine::wallet::app_evm::QueuedItem;
use yw_engine::wallet::app_hypercore::HcApprovalItem;
use yw_engine::wallet::lock::LockReason;
use yw_engine::wallet::{AppMode, Screen, Wallet};

/// The public test vector's account 0 (EIP-55) and a second public test-vector account.
const ACCOUNT_A: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
const ACCOUNT_B: &str = "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0";

/// A manual test clock (monotonic ms; the wall clock a fixed base after it).
struct TestClock(AtomicU64);

impl yw_platform::clock::Clock for TestClock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    fn now_unix_ms(&self) -> u64 {
        1_800_000_000_000 + self.now_ms()
    }

    fn sleep_ms(&self, _ms: u64) {}
}

/// No files: nothing is read or kept.
struct NoFiles;

impl AppStore for NoFiles {
    fn write_settings(&self, _json: &[u8]) -> bool {
        true
    }

    fn read_sealed_keys(&self) -> SealedRead {
        SealedRead::NotFound
    }

    fn write_sealed_keys(&self, _plain: &[u8]) -> bool {
        true
    }

    fn vault_file_info(&self) -> Option<(u64, u64)> {
        None
    }

    fn prev_exists(&self, _kind: FileKind) -> bool {
        false
    }

    fn reset_candidates(&self, _include_settings: bool) -> Vec<String> {
        Vec::new()
    }
}

/// An unlocked wallet with no workers, on a manual clock at 1 000 000 ms.
fn wallet() -> Wallet {
    let clock = Arc::new(TestClock(AtomicU64::new(1_000_000)));
    let mut wallet = Wallet::new(
        Box::new(NoFiles),
        Services {
            llm: Arc::new(|_endpoint| None),
            walletconnect: None,
            ua_platform: "test",
        },
        true,
        Settings::default(),
        ApiKeys::default(),
        clock,
        1_000_000,
    );
    wallet.mode = AppMode::Unlocked {
        alt_passphrase: false,
    };
    wallet
}

/// A `HyperCore` USD transfer of the app (its draft is built without a worker).
#[expect(clippy::unwrap_used, reason = "test helper: the fixed addresses parse")]
fn hypercore_item(wallet: &Wallet) -> QueuedItem {
    let action = HcAction::new(
        HcNetwork::Testnet,
        wallet.clock.now_unix_ms(),
        HcPayload::UsdSend {
            destination: parse_address(ACCOUNT_B).unwrap(),
            amount: "1".to_owned(),
        },
    );
    QueuedItem::HyperCore(Box::new(HcApprovalItem {
        action,
        account: parse_address(ACCOUNT_A).unwrap(),
        signer: EvmKeySource::Derived(AccountIndex::ZERO),
        token: None,
        recipient: HcRecipient {
            notes: Vec::new(),
            look_alike: false,
            not_in_book: true,
        },
    }))
}

/// Queues the item and asks for its window (the send forms' way, without a worker).
#[expect(
    clippy::unwrap_used,
    reason = "test helper: an empty queue takes the item"
)]
fn ask(wallet: &mut Wallet) {
    let item = hypercore_item(wallet);
    wallet.evm.queue.enqueue(QueueSource::App, item).unwrap();
    wallet.show_next_approval();
}

/// The approval state a scenario ends in (names and counts only).
fn state(wallet: &Wallet) -> String {
    format!(
        "mode={:?} screen={:?} shown={:?} unanswered={:?} queue={} kept={}",
        wallet.mode,
        wallet.screen,
        wallet
            .evm
            .approval
            .as_ref()
            .map(yw_engine::wallet::approval_flow::ApprovalFlow::shown),
        wallet.evm.open_unanswered,
        wallet.evm.queue.len(),
        wallet.evm.after_open.len(),
    )
}

/// The lock's two wallet halves for a reason other than `Suspend` (the composition `App::lock`
/// drains between them for `Suspend` only).
fn lock(wallet: &mut Wallet) {
    let vault_present = wallet.lock_steps(LockReason::Manual);
    wallet.lock_after_wait(vault_present);
}

/// The model answers every kind of effect as the Windows shell's executor answers it in the
/// headless tests (the answers and the effects that have none).
#[test]
fn the_model_answers_every_effect_kind() {
    let mut wallet = wallet();
    let mut shell = RecordingShell::new(Schedule::Immediate);
    let mark = CopyMark {
        anchor: Press::Back,
        address: false,
        band: None,
    };
    let answers = [
        (Effect::Render, None),
        (
            Effect::SetField {
                field: EditField::BookLabel,
                text: "label".to_owned(),
            },
            Some("field-shown:BookLabel"),
        ),
        (
            Effect::ClearField {
                field: EditField::BookLabel,
            },
            Some("field-shown:BookLabel"),
        ),
        (
            Effect::CopyText {
                text: "text".to_owned(),
                mark,
            },
            Some("copy-done:true"),
        ),
        (Effect::OpenFolder(Folder::Data), None),
        (
            Effect::OpenFolder(Folder::Extension),
            Some("folder-missing"),
        ),
        (Effect::RaiseMain, None),
        (Effect::ScrollMemoryClear, None),
        (Effect::ReleaseHold, None),
        (Effect::AwaitKeyLock { before: 0, ms: 1 }, None),
        (
            Effect::Approval(ApprovalEffect::Close { shown: ShownId(9) }),
            None,
        ),
    ];
    for (effect, expected) in answers {
        let answer = shell.apply(&mut wallet, effect);
        assert_eq!(
            answer
                .as_ref()
                .map(yw_engine::testkit::answer_name)
                .as_deref(),
            expected
        );
    }
    // A field write's answer shows what was written, cut to the field's cap.
    let Some(Cmd::FieldShown { text, .. }) = shell.apply(
        &mut wallet,
        Effect::SetField {
            field: EditField::BookLabel,
            text: "label".to_owned(),
        },
    ) else {
        unreachable!("a field write is answered");
    };
    assert_eq!(text.as_deref().map(String::as_str), Some("label"));
    // An approval open for a window that is not the shown flow's makes nothing.
    let stale = shell.apply(
        &mut wallet,
        Effect::Approval(ApprovalEffect::Open {
            shown: ShownId(9),
            lang: yw_core::lang::Lang::Ko,
            connect: false,
            ai_reserved: false,
        }),
    );
    assert!(
        matches!(
            stale,
            Some(Cmd::ApprovalOpened {
                shown: ShownId(9),
                outcome: OpenOutcome::Failed(ErrorCode::App009),
                wide: false,
            })
        ),
        "{stale:?}"
    );
    // The log names effects and answers only.
    let log = shell.take_log();
    assert!(log.iter().any(|name| name == "copy:len=4"), "{log:?}");
    assert!(log.iter().all(|name| !name.contains("label")), "{log:?}");
}

/// One request shown and answered: under both schedules the window opens, its open is
/// answered `Shown` and the flow is shown; under `Immediate` the answer is back when the entry's
/// drain ends, under `Deferred` the open is still held then and answered only after the entry.
#[test]
fn an_open_is_answered_under_both_schedules() {
    let mut finals = Vec::new();
    for schedule in [Schedule::Immediate, Schedule::Deferred] {
        let mut wallet = wallet();
        let mut shell = RecordingShell::new(schedule);
        ask(&mut wallet);
        shell.drain(&mut wallet);
        match schedule {
            Schedule::Immediate => {
                assert_eq!(
                    wallet.evm.open_unanswered, None,
                    "answered inside the drain"
                );
                assert_eq!(shell.held(), 0);
            }
            Schedule::Deferred => {
                assert!(wallet.evm.open_unanswered.is_some(), "not answered yet");
                assert!(shell.held() > 0, "the open is held");
                assert!(
                    shell.take_log().is_empty(),
                    "nothing applied inside the entry"
                );
            }
        }
        shell.end_entry(&mut wallet);
        let log = shell.take_log();
        assert!(
            log.iter().any(|name| name.starts_with("=opened#1:Shown")),
            "{schedule:?}: {log:?}"
        );
        assert_eq!(shell.held(), 0);
        assert!(
            wallet.evm.approval.is_some(),
            "{schedule:?}: the flow is shown"
        );
        assert_eq!(wallet.evm.open_unanswered, None, "{schedule:?}: answered");
        finals.push(state(&wallet));
    }
    assert_eq!(finals[0], finals[1], "the same final state");
}

/// Critique A-3 under both schedules: an open and a lock in the same entry make no window — the
/// open is applied after the lock ended its flow, answered `Failed(E-APP-009)` and dropped as
/// stale; the lock's close follows. Same final state.
#[test]
fn an_open_then_a_lock_in_one_entry_makes_no_window() {
    let mut finals = Vec::new();
    for schedule in [Schedule::Immediate, Schedule::Deferred] {
        let mut wallet = wallet();
        let mut shell = RecordingShell::new(schedule);
        shell.entry(&mut wallet, |wallet| {
            ask(wallet);
            lock(wallet);
        });
        let log = shell.take_log();
        let approval: Vec<&str> = log
            .iter()
            .map(String::as_str)
            .filter(|name| name.contains("#1"))
            .collect();
        let expected: &[&str] = match schedule {
            // The answer at once, before the lock's close is applied.
            Schedule::Immediate => &["open#1", "=opened#1:Failed(App009)", "close#1"],
            // The batch (the open, the lock's close), then the answer.
            Schedule::Deferred => &["open#1", "close#1", "=opened#1:Failed(App009)"],
        };
        assert_eq!(approval, expected, "{schedule:?}");
        assert!(wallet.evm.approval.is_none());
        assert_eq!(wallet.screen, Screen::Locked);
        finals.push(state(&wallet));
    }
    assert_eq!(finals[0], finals[1], "the same final state");
}

/// Critique A-3 and spec/15 §18 14 (F14) with the answer later still: the shell has not run when
/// the lock reaches the wallet (`keep`), so the open is applied after the lock and answered
/// `Failed`; the step kept for its answer was dropped by the lock and never runs. The final state
/// is the immediate run's, where the window opened and the lock closed it.
#[test]
fn a_lock_before_the_shell_ran_drops_the_steps_kept_for_the_open() {
    use yw_engine::wallet::app_approval::AfterOpen;

    let mut immediate = wallet();
    let mut shell = RecordingShell::new(Schedule::Immediate);
    shell.entry(&mut immediate, |wallet| {
        ask(wallet);
        wallet.after_pending_open(AfterOpen::SetScreen(Screen::Sites));
    });
    shell.entry(&mut immediate, lock);

    let mut late = wallet();
    let mut shell = RecordingShell::new(Schedule::Deferred);
    shell.keep(true);
    shell.entry(&mut late, |wallet| {
        ask(wallet);
        wallet.after_pending_open(AfterOpen::SetScreen(Screen::Sites));
    });
    assert!(shell.held() > 0, "the shell has not run");
    assert_eq!(late.evm.after_open.len(), 1, "kept for the open's answer");
    shell.entry(&mut late, lock);
    assert!(late.evm.after_open.is_empty(), "the lock dropped the step");
    shell.release_model(&mut late);
    let log = shell.take_log();
    assert!(
        log.iter().any(|name| name == "=opened#1:Failed(App009)"),
        "the open is answered after the lock, stale: {log:?}"
    );
    assert_eq!(late.screen, Screen::Locked, "the kept step did not run");
    assert_eq!(state(&late), state(&immediate), "the same final state");
}

/// The `Suspend` lock (spec/04 §5.3, critique A-2): on Windows the composition drains between
/// the lock's halves, so `AwaitKeyLock` is applied before the mode, the screen and `KeyJob::Load`
/// change; the deferred schedule applies nothing inside the entry, so the wait comes after them
/// (an Android shell has no such wait). The lock's clip and approval steps keep their order
/// before the wait under both schedules (2026-11-23, S4d E2 review: asserted for `Immediate`
/// too — there the composition's mid-lock drain applies all three before the second half); the
/// final state is the same.
#[test]
fn the_suspend_wait_comes_after_the_lock_under_the_deferred_schedule() {
    let mut finals = Vec::new();
    for schedule in [Schedule::Immediate, Schedule::Deferred] {
        let mut wallet = wallet();
        let mut shell = RecordingShell::new(schedule);
        shell.entry(&mut wallet, ask);
        let _ = shell.take_log();
        let vault_present = wallet.lock_steps(LockReason::Suspend);
        shell.drain(&mut wallet);
        let mut log = shell.take_log();
        let waited_before_the_mode = log.iter().any(|name| name == "wait");
        assert_eq!(
            waited_before_the_mode,
            schedule == Schedule::Immediate,
            "{schedule:?}: the wait before the second half"
        );
        assert!(matches!(wallet.mode, AppMode::Unlocked { .. }));
        wallet.lock_after_wait(vault_present);
        shell.end_entry(&mut wallet);
        log.extend(shell.take_log());
        let order: Vec<&str> = log
            .iter()
            .map(String::as_str)
            .filter(|name| ["clear-clip", "close#1", "wait"].contains(name))
            .collect();
        assert_eq!(
            order,
            ["clear-clip", "close#1", "wait"],
            "{schedule:?}: {log:?}"
        );
        assert_eq!(wallet.mode, AppMode::Locked);
        finals.push(state(&wallet));
    }
    assert_eq!(finals[0], finals[1], "the same final state");
}

/// A lock in a later entry closes the shown window under both schedules (spec/04 §3.7): the
/// flow ends, the queue is empty, the window's close is applied. Nothing here approves.
/// 2026-11-23 (S4d E2 review): this app-source item has no answer that shows its outcome, so
/// "as `Rejected`" (AGENTS.md §6) is not observed here; it is pinned under both schedules by the
/// headless golden line `lock_shortcut_while_shown ctrl-l` (the dApp request answered 4001),
/// which `run_deferred` reproduces under the deferred schedule.
#[test]
fn a_lock_closes_the_shown_window_under_both_schedules() {
    let mut finals = Vec::new();
    for schedule in [Schedule::Immediate, Schedule::Deferred] {
        let mut wallet = wallet();
        let mut shell = RecordingShell::new(schedule);
        shell.entry(&mut wallet, ask);
        assert!(wallet.evm.approval.is_some(), "{schedule:?}: shown");
        let _ = shell.take_log();
        shell.entry(&mut wallet, lock);
        let log = shell.take_log();
        assert!(
            log.iter().any(|name| name == "close#1"),
            "{schedule:?}: {log:?}"
        );
        assert!(wallet.evm.approval.is_none(), "{schedule:?}");
        assert_eq!(wallet.evm.queue.len(), 0, "{schedule:?}");
        finals.push(state(&wallet));
    }
    assert_eq!(finals[0], finals[1], "the same final state");
}
