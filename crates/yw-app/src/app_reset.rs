//! Loading waits that end in a message instead of hanging (T-WAIT-STALLED), and S22
//! `지갑 초기화` (spec/04 §2.20).
//!
//! Waits: a `Processing` screen and a requested meta (`KeyJob::LoadMeta`) are timed. After
//! [`WAIT_TIMEOUT_MS`] the screen keeps waiting (a late result still lands) but shows what to do
//! next: `다시 불러오기`, `잠금`, the log folder, and as a last resort `지갑 초기화`. A session
//! screen that needs the account list while no meta was ever requested requests it (the 2026-11
//! `BackupPending` hang: S04 never loaded the meta, so S12 waited forever).
//!
//! Reset: reachable from S07, S09, S04, S01 with T-LEFTOVER and settings → 보안, without
//! unlocking. Typing [`RESET_PHRASE`] enables a 2 s hold area; completing the hold locks the app
//! (closing every secret and approval window, like `잠금`), then the key worker drops the vault
//! and moves the files (`store::reset`), and the app reloads into S01.

use yw_core::vault::FileKind;

use crate::app::{App, AppMode, Screen};
use crate::errors::ErrorCode;
use crate::events::KeyJob;
use crate::lock::LockReason;
use crate::logging::{self, Field};
use crate::store::reset::{ResetError, ResetReport};
use crate::ui::secret::{BACKUP_ACK_HOLD_MS, HoldGate};

/// A wait longer than this shows T-WAIT-STALLED.
pub const WAIT_TIMEOUT_MS: u64 = 30_000;
/// What the user types to enable the reset hold.
pub const RESET_PHRASE: &str = "초기화";

/// The timed waits (monotonic ms).
#[derive(Debug, Default)]
pub struct WaitWatch {
    /// The current `Processing` screen was entered.
    pub since: Option<u64>,
    /// A meta load was requested and has not answered.
    pub meta_since: Option<u64>,
    /// A wait passed [`WAIT_TIMEOUT_MS`] (shown on `Processing` and the account-loading lines).
    pub stalled: bool,
    /// The last meta load failed (not `SidecarCorrupt`, which has its own overlay): no meta is
    /// in memory, nothing writes the meta, the main timer does not ask again, and T-META-FAILED
    /// offers the next steps (`다시 불러오기`, `잠금`, the log folder). The next `request_meta`
    /// clears it; a meta is in memory again only after a load succeeds.
    pub meta_failed: Option<ErrorCode>,
}

impl WaitWatch {
    /// `set_screen` from `from` to `to`.
    pub fn screen_changed(&mut self, from: &Screen, to: &Screen, now: u64) {
        let was = matches!(from, Screen::Processing(_));
        let is = matches!(to, Screen::Processing(_));
        if is && !was {
            self.since = Some(now);
        } else if !is {
            self.since = None;
        }
        if from != to {
            self.stalled = false;
        }
    }

    /// Whether a wait is over the limit at `now` (`meta_missing`: no meta in memory).
    #[must_use]
    pub fn over(&self, now: u64, meta_missing: bool) -> bool {
        let over = |since: Option<u64>| {
            since.is_some_and(|since| now.saturating_sub(since) >= WAIT_TIMEOUT_MS)
        };
        over(self.since) || (meta_missing && over(self.meta_since))
    }
}

/// S22 state.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts of one screen"
)]
pub struct ResetUi {
    /// Where `취소` returns to (the screen the reset was opened from).
    pub back: Option<Screen>,
    /// The confirmation field holds [`RESET_PHRASE`].
    pub phrase_ok: bool,
    /// `설정과 API 키도 함께 옮기기`.
    pub include_settings: bool,
    /// The 2 s hold of the hold area.
    pub gate: HoldGate,
    /// The hold area being held.
    pub holding: Option<u16>,
    /// Hold progress 0–1000 (drawn).
    pub progress: u16,
    /// The key worker is moving the files.
    pub running: bool,
    /// Sends were in flight when the reset started (logged, shown after).
    pub warned_in_flight: bool,
    /// The files that would move (listed when S22 opens and when the check box changes).
    pub files: Vec<String>,
}

/// Whether the confirmation field's text is the phrase (surrounding spaces ignored).
#[must_use]
pub fn phrase_matches(text: &str) -> bool {
    text.trim() == RESET_PHRASE
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// T-RESET-DONE.
#[must_use]
pub fn reset_done_text(report: &ResetReport) -> String {
    match &report.folder {
        Some(folder) => format!(
            "지갑을 초기화했습니다. 지갑 파일 {}개를 지우지 않고 {} 폴더로 옮겼습니다. 그 지갑의 자산은 복구 단어(또는 원래 개인키)로 다시 가져올 수 있고, 옮긴 파일은 예전 비밀번호로 열립니다(되돌리는 방법: 복구 안내).",
            report.moved.len(),
            folder.display()
        ),
        None => "옮길 지갑 파일이 없었습니다. 처음 화면입니다.".to_owned(),
    }
}

/// The text of a failed reset.
#[must_use]
pub fn reset_failed_text(error: &ResetError) -> String {
    match error {
        ResetError::Folder(_) => "지갑 파일을 옮길 폴더를 만들지 못했습니다. 아무 파일도 옮기지 않았습니다. 앱을 다시 실행한 뒤 다시 시도하거나, 앱을 종료하고 데이터 폴더의 파일을 직접 옮기세요(복구 안내).".to_owned(),
        ResetError::Move { folder, moved, failed, .. } => format!(
            "{failed} 파일을 옮기지 못했습니다. 먼저 옮긴 {}개는 {} 폴더에 있습니다. 다른 프로그램이 파일을 쓰고 있지 않은지 확인하고 다시 시도하세요.",
            moved.len(),
            folder.display()
        ),
    }
}

impl App {
    /// Queues `KeyJob::LoadMeta` and starts its wait clock (a failed load's T-META-FAILED
    /// gives way to the loading line; no meta is in memory until the answer).
    pub(crate) fn request_meta(&mut self) {
        self.wait.meta_failed = None;
        self.key(KeyJob::LoadMeta);
        if self.wait.meta_since.is_none() {
            self.wait.meta_since = Some(yw_win::time::monotonic_ms());
        }
    }

    /// A screen of an open session that shows accounts.
    fn needs_accounts(&self) -> bool {
        matches!(self.mode, AppMode::BackupPending | AppMode::Unlocked { .. })
            && matches!(
                self.screen,
                Screen::Main
                    | Screen::BackupPending
                    | Screen::Receive
                    | Screen::SolReceive
                    | Screen::BtcReceive
            )
    }

    /// Main-timer part of the waits.
    pub(crate) fn wait_tick(&mut self, now: u64) {
        if self.meta.is_none()
            && self.wait.meta_since.is_none()
            && self.wait.meta_failed.is_none()
            && self.needs_accounts()
        {
            logging::warn("app", "wait.meta_requested", &[]);
            self.request_meta();
        }
        let stalled = self.wait.over(now, self.meta.is_none());
        if stalled != self.wait.stalled {
            self.wait.stalled = stalled;
            if stalled {
                logging::warn(
                    "app",
                    "wait.timeout",
                    &[("mode", Field::Word(self.mode.word()))],
                );
            }
            self.refresh();
        }
    }

    /// `다시 불러오기` of T-WAIT-STALLED.
    pub(crate) fn wait_retry(&mut self) {
        self.wait = WaitWatch::default();
        if matches!(self.mode, AppMode::BackupPending | AppMode::Unlocked { .. }) {
            self.request_meta();
        }
        if matches!(self.screen, Screen::Processing(_)) {
            self.wait.since = Some(yw_win::time::monotonic_ms());
        }
        self.refresh();
    }

    /// Sends that may still confirm (only known while unlocked): the EVM, Solana and Zcash
    /// journal records not yet final (Zcash of every network and account), Bitcoin's, and
    /// `HyperCore` actions posted without a final answer (`전송 중`, or no answer — Hyperliquid may
    /// still have processed them).
    #[must_use]
    pub fn sends_in_flight(&self) -> bool {
        use crate::app_hypercore::HcStatus;
        self.evm
            .records()
            .iter()
            .any(|record| !record.state.is_terminal())
            || self
                .sol_records()
                .iter()
                .any(|record| !record.state.is_terminal())
            || self.btc_ctx().any_in_flight()
            || self.evm.journal.as_ref().is_some_and(|journal| {
                journal
                    .zec_records
                    .iter()
                    .any(|record| !record.is_terminal())
            })
            || self
                .hypercore
                .activity
                .iter()
                .any(|row| matches!(row.status, HcStatus::Submitting | HcStatus::Unknown(_)))
    }

    /// `지갑 초기화…`: S22 over the current screen.
    pub(crate) fn open_reset(&mut self) {
        if matches!(self.mode, AppMode::Starting | AppMode::ShuttingDown) || self.reset.running {
            return;
        }
        let back = if self.screen == Screen::Reset {
            self.reset.back.take()
        } else {
            Some(self.screen.clone())
        };
        self.reset = ResetUi {
            back,
            ..ResetUi::default()
        };
        self.reset_list_files();
        logging::info("app", "reset.opened", &[]);
        self.set_screen(Screen::Reset);
    }

    /// `취소` on S22.
    pub(crate) fn cancel_reset(&mut self) {
        let back = self.reset.back.take();
        self.reset = ResetUi::default();
        let fallback = match self.mode {
            AppMode::NoVault => Screen::FirstRun,
            AppMode::BackupPending => Screen::BackupPending,
            AppMode::Unlocked { .. } => Screen::Main,
            AppMode::Corrupt { .. } | AppMode::MainMissing => Screen::Recovery,
            _ => Screen::Locked,
        };
        self.set_screen(back.unwrap_or(fallback));
    }

    /// The confirmation field changed.
    pub(crate) fn reset_phrase_changed(&mut self, text: &str) {
        let ok = phrase_matches(text);
        if ok != self.reset.phrase_ok {
            self.reset.phrase_ok = ok;
            self.reset.gate.cancel();
            self.reset.holding = None;
            self.refresh();
        }
    }

    /// The hold completed: lock, then move the files on the key worker.
    pub(crate) fn reset_execute(&mut self) {
        if !self.reset.phrase_ok || self.reset.running || self.screen != Screen::Reset {
            return;
        }
        let include_settings = self.reset.include_settings;
        let in_flight = self.sends_in_flight();
        logging::warn(
            "app",
            "reset.start",
            &[
                (
                    "settings",
                    Field::Word(if include_settings { "moved" } else { "kept" }),
                ),
                (
                    "in_flight",
                    Field::Word(if in_flight { "yes" } else { "no" }),
                ),
            ],
        );
        // The lock procedure first: secret and approval windows close, queued dApp items end,
        // buffers are wiped, queued key jobs are cancelled.
        self.lock(LockReason::Manual);
        // WalletConnect: the old wallet's sessions, relay key and connection end with it (the
        // worker is restarted for the next wallet at its first unlock; spec/13 §8).
        self.wc_shutdown();
        self.wc = crate::app_walletconnect::WcUi::default();
        self.reset = ResetUi {
            include_settings,
            running: true,
            warned_in_flight: in_flight,
            ..ResetUi::default()
        };
        self.set_screen(Screen::Processing("지갑 파일을 옮기는 중…"));
        self.key(KeyJob::ResetWallet {
            stamp: crate::store::reset::stamp(now_unix_ms()),
            include_settings,
        });
    }

    /// `KeyOutcome::WalletReset`.
    pub(crate) fn on_wallet_reset(&mut self, result: Result<ResetReport, ResetError>) {
        let in_flight = self.reset.warned_in_flight;
        self.reset = ResetUi::default();
        match result {
            Ok(report) => {
                logging::warn(
                    "app",
                    "reset.done",
                    &[(
                        "files",
                        Field::Num(u64::try_from(report.moved.len()).unwrap_or(0)),
                    )],
                );
                if report.settings_moved {
                    self.settings = crate::settings::Settings::default();
                    self.apikeys = crate::apikeys::ApiKeys::default();
                    logging::set_level(self.settings.log_level);
                }
                // The old wallet's snapshot and generation facts went with its meta.
                self.guard.verified = false;
                self.guard.pending = None;
                self.guard.rollback = None;
                self.guard.vault_file = None;
                self.forget_vault_state();
                let mut text = reset_done_text(&report);
                if in_flight {
                    text.push_str(" 보내던 거래는 블록체인에서 계속 처리됩니다. 결과는 블록 탐색기에서 확인하세요.");
                }
                self.info = Some(text);
            }
            Err(error) => {
                logging::warn("app", "reset.failed", &[]);
                self.banner(None, reset_failed_text(&error));
            }
        }
        // S01 (nothing left) or, after a partial move, whatever the files now say.
        self.set_screen(Screen::Processing("불러오는 중…"));
        self.key(KeyJob::Load);
    }

    /// `KeyOutcome::Loaded` while the reset runs: only the facts, the screen stays.
    pub(crate) fn reset_absorbs_load(&mut self, leftover: bool) -> bool {
        if self.reset.running {
            self.leftover = leftover;
            return true;
        }
        false
    }

    /// The hold area under the pointer was pressed.
    pub(crate) fn hold_down(&mut self, x: i32, y: i32, now: u64) {
        let hit = self
            .placed
            .holds
            .iter()
            .find(|(_, rect, enabled)| *enabled && rect.contains(x, y))
            .map(|(id, ..)| *id);
        if let Some(id) = hit {
            self.reset.holding = Some(id);
            self.reset.gate.begin(now);
            self.reset.progress = 0;
            if let Some(main) = self.main.as_ref() {
                main.set_capture();
            }
            self.refresh();
        }
    }

    /// Pointer moved: leaving the area cancels the hold.
    pub(crate) fn hold_move(&mut self, x: i32, y: i32) {
        let Some(id) = self.reset.holding else {
            return;
        };
        let inside = self
            .placed
            .holds
            .iter()
            .any(|(held, rect, _)| *held == id && rect.contains(x, y));
        if !inside {
            self.hold_cancel();
        }
    }

    /// Released (early) or capture lost.
    pub(crate) fn hold_cancel(&mut self) {
        if self.reset.holding.take().is_some() {
            self.reset.gate.cancel();
            self.reset.progress = 0;
            if let Some(main) = self.main.as_ref() {
                main.release_capture();
            }
            self.refresh();
        }
    }

    /// Main-timer part of the hold: progress, then the action after 2 s.
    pub(crate) fn reset_hold_tick(&mut self, now: u64) {
        let Some(id) = self.reset.holding else {
            return;
        };
        if self.screen != Screen::Reset {
            self.hold_cancel();
            return;
        }
        if self.reset.gate.complete(now) {
            self.hold_cancel();
            if id == crate::ui::screens_reset::ids::RESET_HOLD {
                self.reset_execute();
            }
            return;
        }
        let done = BACKUP_ACK_HOLD_MS.saturating_sub(self.reset.gate.remaining_ms(now));
        self.reset.progress =
            u16::try_from(done.saturating_mul(1_000) / BACKUP_ACK_HOLD_MS).unwrap_or(1_000);
        self.refresh();
    }

    /// Commands of S22 and T-WAIT-STALLED; `false` when `id` is not one of them.
    pub(crate) fn on_reset_command(&mut self, id: u16) -> bool {
        use crate::ui::screens_reset::ids;
        match id {
            ids::RESET_OPEN => self.open_reset(),
            ids::RESET_CANCEL => self.cancel_reset(),
            ids::RESET_SETTINGS_CHECK => {
                self.reset.include_settings = self
                    .controls
                    .checked(ids::RESET_SETTINGS_CHECK)
                    .unwrap_or(!self.reset.include_settings);
                self.reset_list_files();
                self.refresh();
            }
            ids::WAIT_RETRY => self.wait_retry(),
            _ => return false,
        }
        true
    }

    /// `EN_CHANGE` of the S22 field; `false` for other fields.
    pub(crate) fn on_reset_edit_change(&mut self, id: u16) -> bool {
        if id != crate::ui::screens_reset::ids::RESET_PHRASE {
            return false;
        }
        let text = self.controls.text(id, 32).unwrap_or_default();
        self.reset_phrase_changed(&text);
        true
    }

    fn reset_list_files(&mut self) {
        self.reset.files =
            crate::store::reset::candidates(&self.paths.data, self.reset.include_settings)
                .unwrap_or_default();
    }

    /// After a reset the old wallet's per-file facts no longer apply.
    fn forget_vault_state(&mut self) {
        self.payload_damaged = false;
        self.unlock_failed = false;
        self.quarantined = None;
        self.prev_on_disk = crate::store::prev_exists(&self.paths.data, FileKind::Vault);
        self.done_imported = false;
        // S08's banner of the old wallet (a YubiKey wallet or a key start that never pressed
        // `지갑 열기`) must not follow the next first-run path.
        self.done_yubikey = None;
        self.keys.done_start = false;
        self.mismatch_checked = false;
    }
}
