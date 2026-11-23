//! The secret sessions of `yw_engine::Wallet` under both reply schedules of
//! `testkit::RecordingShell` (2026-11-23, S4d E2; plan §3.6–§3.7, D-25, critique A-3, A-21, the
//! S4d preflight's corrected row E2 and O-5; spec/04 §4.5, spec/15 §3.2, §11.4 S4). The wallet
//! alone with the recording shell's model as its shell (a window made and its capture exclusion
//! verified while its serial is the open, unshown session; a display secret handed only to such a
//! window and wiped there at once): no yw-app, no window, no file, no network, no card reader, no
//! clipboard. The secrets are synthetic (`not a real word`, a made-up password). The frozen
//! `s4_secret` goldens are reproduced by the yw-app headless runner under both schedules
//! (`app::tests::s4_secret`); these are the Wallet-only scenarios, for Android parity.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use yw_core::secret::{SecretString, Zeroizing};
use yw_core::vault::FileKind;
use yw_engine::apikeys::ApiKeys;
use yw_engine::app_store::{AppStore, SealedRead};
use yw_engine::secret::{DisplaySecret, SecretKind, Submission};
use yw_engine::services::Services;
use yw_engine::settings::Settings;
use yw_engine::testkit::{RecordingShell, Schedule, WalletTestExt};
use yw_engine::wallet::lock::LockReason;
use yw_engine::wallet::secret_session::SecretAction;
use yw_engine::wallet::{AppMode, Purpose, Wallet};

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

/// A wallet with no workers in `mode`, on a manual clock at 1 000 000 ms.
fn wallet(mode: AppMode) -> Wallet {
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
        Arc::new(TestClock(AtomicU64::new(1_000_000))),
        1_000_000,
    );
    wallet.mode = mode;
    wallet
}

const UNLOCKED: AppMode = AppMode::Unlocked {
    alt_passphrase: false,
};

/// A synthetic display secret (never a real word or key).
#[expect(clippy::unwrap_used, reason = "test helper: 15 bytes fit the capacity")]
fn display() -> DisplaySecret {
    let mut text = SecretString::with_capacity(16);
    text.push_str("not a real word").unwrap();
    DisplaySecret {
        text,
        address: None,
        passphrase_note: false,
        copy_allowed: false,
    }
}

/// The open session as `(serial, shown)`.
fn session(wallet: &Wallet) -> Option<(u64, bool)> {
    wallet
        .secret_session()
        .map(|session| (session.serial(), session.shown()))
}

/// The key jobs queued, by name, taken out of the queue (`pop` waits on an empty queue, so it is
/// called only while one is queued).
fn key_jobs(wallet: &Wallet) -> Vec<&'static str> {
    let mut names = Vec::new();
    while !wallet.key_queue.is_empty() {
        let Some((_, job)) = wallet.key_queue.pop() else {
            break;
        };
        names.push(job.name());
    }
    names
}

/// The lock's two wallet halves (no `Suspend`: no drain between them).
fn lock(wallet: &mut Wallet) {
    let vault_present = wallet.lock_steps(LockReason::Manual);
    wallet.lock_after_wait(vault_present);
}

/// An input window (W02) opens and closes under both schedules: the session is shown once its
/// open is answered, the close ends it; same final state.
#[test]
fn an_input_window_opens_and_closes_under_both_schedules() {
    for schedule in [Schedule::Immediate, Schedule::Deferred] {
        let mut wallet = wallet(AppMode::Starting);
        let mut shell = RecordingShell::new(schedule);
        shell.entry(&mut wallet, |wallet| {
            wallet.open_input(SecretKind::Unlock, Purpose::Unlock, false);
        });
        let serial = session(&wallet).map(|(serial, _)| serial);
        assert_eq!(
            session(&wallet).map(|(_, shown)| shown),
            Some(true),
            "{schedule:?}"
        );
        shell.entry(&mut wallet, Wallet::close_secret);
        assert_eq!(session(&wallet), None, "{schedule:?}");
        let log = shell.take_log();
        let serial = serial.unwrap_or_default();
        let secret: Vec<&str> = log
            .iter()
            .map(String::as_str)
            .filter(|name| name.contains("secret-"))
            .collect();
        assert_eq!(
            secret,
            [
                format!("secret-open#{serial}"),
                format!("=secret-opened#{serial}:Shown {{ capture_excluded: true }}"),
                format!("secret-close#{serial}"),
            ],
            "{schedule:?}"
        );
    }
}

/// A display window (W08) gets its secret only once made and verified, under both schedules
/// (spec/04 §4.5 4, plan §7.2): the model's window takes it (`display-handed`) and wipes it; the
/// session is shown and holds no secret after.
#[test]
fn a_display_secret_moves_only_into_a_verified_window_under_both_schedules() {
    for schedule in [Schedule::Immediate, Schedule::Deferred] {
        let mut wallet = wallet(AppMode::Starting);
        let mut shell = RecordingShell::new(schedule);
        shell.entry(&mut wallet, |wallet| {
            wallet.open_display(
                SecretKind::ShowMnemonic { create: true },
                Purpose::ShowForBackup,
                display(),
            );
        });
        let (serial, shown) = session(&wallet).unwrap_or_default();
        assert!(shown, "{schedule:?}: shown");
        let log = shell.take_log();
        assert!(
            log.contains(&format!("display-handed#{serial}")),
            "{schedule:?}: {log:?}"
        );
        assert!(
            wallet.take_display_secret(serial).is_none(),
            "{schedule:?}: the secret left the session once"
        );
    }
}

/// Critique A-3 under both schedules: a display window asked for and a lock in the same entry
/// open nothing — the open is applied after the lock ended the session, refused (`E-SEC-001`),
/// and the secret is never handed out (the lock dropped it). Same final state.
#[test]
fn a_display_then_a_lock_in_one_entry_hands_out_nothing() {
    for schedule in [Schedule::Immediate, Schedule::Deferred] {
        let mut wallet = wallet(UNLOCKED);
        let mut shell = RecordingShell::new(schedule);
        shell.entry(&mut wallet, |wallet| {
            wallet.open_display(
                SecretKind::ShowMnemonic { create: false },
                Purpose::ShowRevealed,
                display(),
            );
            lock(wallet);
        });
        let log = shell.take_log();
        assert!(
            log.iter().all(|name| !name.starts_with("display-handed")),
            "{schedule:?}: {log:?}"
        );
        assert!(
            log.iter()
                .any(|name| name.starts_with("=secret-opened#") && name.contains("Sec001")),
            "{schedule:?}: refused {log:?}"
        );
        assert_eq!(session(&wallet), None, "{schedule:?}");
        assert_eq!(wallet.mode, AppMode::Locked, "{schedule:?}");
    }
}

/// The shell has not run when a lock reaches the wallet (`keep`): the input window's open is
/// applied after the lock, refused as stale, and makes nothing; the final state is the immediate
/// run's (the window opened, the lock closed it).
#[test]
fn an_input_open_answered_after_a_lock_makes_nothing() {
    let mut finals = Vec::new();
    for keep in [false, true] {
        let schedule = if keep {
            Schedule::Deferred
        } else {
            Schedule::Immediate
        };
        let mut wallet = wallet(UNLOCKED);
        let mut shell = RecordingShell::new(schedule);
        shell.keep(keep);
        shell.entry(&mut wallet, |wallet| {
            wallet.open_input(
                SecretKind::ConfirmPassword,
                Purpose::ConfirmPassword(yw_engine::wallet::PasswordAction::RevealMnemonic {
                    then_backup: false,
                }),
                false,
            );
        });
        shell.entry(&mut wallet, lock);
        shell.release_model(&mut wallet);
        let log = shell.take_log();
        if keep {
            assert!(
                log.iter()
                    .any(|name| name.starts_with("=secret-opened#") && name.contains("Sec001")),
                "{log:?}"
            );
        }
        assert_eq!(session(&wallet), None, "keep={keep}");
        finals.push(format!("{:?} {:?}", wallet.mode, wallet.screen));
    }
    assert_eq!(finals[0], finals[1], "the same final state");
}

/// Critique A-21 under both schedules: a submission that arrives for a session the lock ended is
/// dropped (its buffer wiped where it is dropped) and starts no key job.
#[test]
fn a_late_submission_is_dropped_under_both_schedules() {
    for schedule in [Schedule::Immediate, Schedule::Deferred] {
        let mut wallet = wallet(AppMode::Locked);
        let mut shell = RecordingShell::new(schedule);
        shell.entry(&mut wallet, |wallet| {
            wallet.open_input(SecretKind::Unlock, Purpose::Unlock, false);
        });
        let (serial, shown) = session(&wallet).unwrap_or_default();
        assert!(shown, "{schedule:?}");
        shell.entry(&mut wallet, lock);
        let _ = key_jobs(&wallet);
        shell.entry(&mut wallet, |wallet| {
            wallet.on_secret_action(
                serial,
                SecretAction::Submit(Submission {
                    values: vec![Zeroizing::new(b"made-up password".to_vec())],
                    checkbox: false,
                }),
            );
        });
        assert!(key_jobs(&wallet).is_empty(), "{schedule:?}: no key job");
        assert_eq!(session(&wallet), None, "{schedule:?}");
        // The control: the same submission for the open session starts the unlock.
        shell.entry(&mut wallet, |wallet| {
            wallet.open_input(SecretKind::Unlock, Purpose::Unlock, false);
        });
        let (open, _) = session(&wallet).unwrap_or_default();
        assert_ne!(open, serial, "{schedule:?}: a fresh serial");
        shell.entry(&mut wallet, |wallet| {
            wallet.on_secret_action(
                open,
                SecretAction::Submit(Submission {
                    values: vec![Zeroizing::new(b"made-up password".to_vec())],
                    checkbox: false,
                }),
            );
        });
        assert_eq!(
            key_jobs(&wallet),
            ["Unlock"],
            "{schedule:?}: the open session's"
        );
    }
}
