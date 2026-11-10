//! The E-VLT-006 choices for a wallet side file that does not open (spec/04 §2.5, spec/02 §6.3;
//! 2026-11-10 review of what the choices silently cost).
//!
//! - meta (`Confirm::SidecarCorrupt`): no default stands in for the file and nothing is saved over
//!   it while the choice is open or closed (`WaitWatch::meta_failed` = E-VLT-006; the key worker
//!   also refuses `SaveMeta` for a file it could not read). `이전 사본(.prev) 사용` is offered only
//!   when `.prev` exists, and the key worker opens and reads the copy before anything moves;
//!   `격리하고 새로 시작` lists what resets; `닫기` changes nothing (T-META-FAILED in its E-VLT-006
//!   form, whose `다시 불러오기` reads the file again and so brings the choice back).
//! - journal (`Confirm::JournalCorrupt`): T-JOURNAL-RESET says what starting over loses — a
//!   transaction sent before may still confirm without a record. `닫기` stops every send with one
//!   reason and `선택 다시 보기` (header band) until the choice is made or the session ends.
//! - A file that opens with the wallet's key but that this build cannot read
//!   (`VaultError::SidecarUnsupported`, a newer build's format) is not called damage: `닫기` and
//!   `잠금`, and the destructive choices only under `고급`.
//! - After a choice the notice names the files moved aside (never deleted, recovery guide), and the
//!   stale E-VLT-006 band goes.
//! - After a journal reset, meta `journal_reset_at` keeps the time: the Bitcoin send form asks for
//!   a check for [`RESET_WATCH_SECS`] (no expiry: the old transaction can confirm until its inputs
//!   are spent), Solana sends wait [`SOL_RESET_WAIT_SECS`] (blockhash expiry) and Zcash sends
//!   [`ZEC_RESET_WAIT_SECS`] (expiry height). EVM needs nothing: a pending transaction of the
//!   account blocks the next nonce (`plan_nonce`, `ExternalPending`).

use yw_core::error::VaultError;
use yw_core::vault::FileKind;

use crate::app::{App, AppMode, Confirm, Screen};
use crate::errors::ErrorCode;
use crate::events::{KeyJob, SidecarMoves, SidecarRefusal};
use crate::logging::{self, Field};
use crate::ui::main_window::{Ctl, Item, Tone};

/// Command ids (block 16,600–16,609 of `ui::command_ids`). The overlays' other buttons keep their
/// ids: meta `SIDECAR_PREV`/`SIDECAR_FRESH`, journal `CONFIRM_YES`/`CONFIRM_NO`, `LOCK`.
pub mod ids {
    /// The meta overlay's `닫기 (아무것도 바꾸지 않음)`.
    pub const SIDECAR_CLOSE: u16 = 16_600;
    /// `고급` of a newer-format overlay (the destructive choices).
    pub const ADVANCED: u16 = 16_601;
    /// `선택 다시 보기` of the closed journal's band.
    pub const JOURNAL_REOPEN: u16 = 16_602;
    /// The Bitcoin send form's check after a journal reset.
    pub const RESET_ACK: u16 = 16_603;
    /// Every fixed id.
    pub const FIXED: &[u16] = &[SIDECAR_CLOSE, ADVANCED, JOURNAL_REOPEN, RESET_ACK];
}

/// How long after a journal reset the Bitcoin send form asks for a check: the journal's own
/// window for a transaction that may still confirm (an abandoned one stays live this long).
pub const RESET_WATCH_SECS: u64 = yw_core::journal::btc::BTC_ABANDON_WINDOW_SECS;
/// How long Solana sends wait after a journal reset: a signed transfer is valid for at most 150
/// blocks after its blockhash (about a minute).
pub const SOL_RESET_WAIT_SECS: u64 = 180;
/// How long Zcash sends wait after a journal reset: a transaction expires 40 blocks of 75 s (120
/// of 25 s from NU7) after it was signed, about 50 minutes; two hours leave room for slow blocks.
pub const ZEC_RESET_WAIT_SECS: u64 = 2 * 3_600;

/// T-JOURNAL-RESET: what starting the journal over loses.
pub const T_JOURNAL_RESET: &str = "새로 시작하면: 보낸 뒤 아직 확정되지 않았거나 '포기'한 거래는 기록만 사라지고, 블록체인에서는 나중에 확정될 수 있습니다. 블록 탐색기에서 확인하기 전에 같은 송금을 다시 보내면 두 번 지불될 수 있습니다. 그 거래의 수수료 올리기·취소·폐기·재전송도 더는 할 수 없습니다. 읽을 수 없는 파일과 이전 사본은 지우지 않고 journal.ywj.corrupt-<시각>, journal.ywj.prev.corrupt-<시각>으로 옮겨 둡니다(복구 안내).";
/// The journal overlay of a file that does not open.
const T_JOURNAL_DAMAGED: &str = "거래 저널(journal.ywj: 보낸 뒤 아직 끝나지 않은 거래의 기록)을 열 수 없습니다. 파일이 손상되었거나 다른 지갑의 파일입니다. 저널을 열기 전에는 EVM·Solana·Bitcoin·Zcash 보내기를 멈춥니다.";
/// The journal overlay of a file this build cannot read.
const T_JOURNAL_NEWER: &str = "거래 저널(journal.ywj)은 이 지갑의 키로 열리지만 이 버전이 모르는 형식입니다. 대개 더 새로운 버전의 앱이 저장한 파일입니다(새 버전을 쓰다가 이 버전으로 되돌린 경우). 파일은 바꾸지 않았고 EVM·Solana·Bitcoin·Zcash 보내기를 멈췄습니다. 앱을 최신 버전으로 업데이트하세요.";
/// The band of a journal whose choice was closed (every screen of the session).
pub const T_JOURNAL_CLOSED: &str = "거래 저널을 열지 못해 EVM·Solana·Bitcoin·Zcash 보내기를 멈췄습니다(Bitcoin은 조회도). 앱을 업데이트했거나 파일을 직접 되돌렸다면 잠근 뒤 다시 잠금 해제하세요. 아니면 '선택 다시 보기'에서 고르세요.";
/// The approval window's failure while the journal's choice is closed.
pub const T_JOURNAL_CLOSED_SEND: &str = "보내지 않았습니다: 거래 저널을 열지 못해 보내기를 멈췄습니다. 지갑 화면 맨 위의 '선택 다시 보기'에서 고르세요.";
/// The meta overlay of a file that does not open.
const T_META_DAMAGED: &str = "meta 파일(meta.ywm: 계정 이름·주소록·사이트 연결·활동 기록 등)을 열 수 없습니다. 파일이 손상되었거나 다른 지갑의 파일입니다. 복구 단어·개인키와 자산은 이 파일에 없어 그대로입니다. 고를 때까지 이 파일에 아무것도 쓰지 않습니다.";
/// The meta overlay of a file this build cannot read.
const T_META_NEWER: &str = "meta 파일(meta.ywm)은 이 지갑의 키로 열리지만 이 버전이 모르는 형식입니다. 대개 더 새로운 버전의 앱이 저장한 파일입니다(새 버전을 쓰다가 이 버전으로 되돌린 경우). 파일은 그대로 두었고, 고를 때까지 아무것도 쓰지 않습니다. 앱을 최신 버전으로 업데이트하세요.";
/// The warning above the destructive choices of a newer-format file.
const T_NEWER_ADVANCED: &str = "되돌리거나 새로 시작하면 새 버전에서 만든 내용(계정·라벨·연결, 저널이면 진행 중 거래 기록)이 사라지고, 새 버전으로 돌아가도 돌아오지 않습니다. 앱을 업데이트할 수 없을 때만 고르세요.";
/// `이전 사본(.prev) 사용` of meta.
const T_META_PREV: &str = "이전 사본(.prev) 사용: 이전 사본을 먼저 열어 보고, 열리지 않으면 아무것도 바꾸지 않습니다. 마지막 저장 하나가 되돌아갑니다 — 예: 방금 끊은 사이트 연결, 숨긴 계정, 지운 주소록 항목이 다시 생길 수 있습니다. 지금 파일은 지우지 않고 meta.ywm.corrupt-<시각>으로 옮겨 둡니다.";
/// `격리하고 새로 시작` of meta: what resets, in plain words.
const T_META_FRESH: &str = "격리하고 새로 시작: 다음이 처음 상태가 됩니다 — 계정 이름과 숨김 표시, 추가한 EVM·Solana 계정('계정 추가'로 다시 만들 수 있음), 주소록과 즐겨찾기, 사이트 연결(Solana·Bitcoin 포함)과 WalletConnect 세션, 추가한 토큰과 토큰 숨김, 기본 계정 외 Bitcoin 계정(EVM 키·YubiKey 키 계정 포함)과 주소 방식, Bitcoin 동결 표시(동결한 UTXO가 다시 쓰일 수 있음), 활동 기록과 비슷한 주소 경고가 비교하는 이전 받는 주소, 설정 파일 보호 기록. 복구 단어·가져온 개인키·YubiKey 등록과 자산은 그대로입니다. 지금 파일과 이전 사본은 지우지 않고 meta.ywm.corrupt-<시각>, meta.ywm.prev.corrupt-<시각>으로 옮겨 둡니다.";
/// `닫기` of meta.
const T_META_CLOSE: &str = "닫기: 아무것도 바꾸지 않습니다. 계정 목록 없이 열리고 보내기는 멈춥니다. 앱을 업데이트했거나 파일을 직접 되돌렸다면 '다시 불러오기'로 다시 읽습니다.";
/// T-META-FAILED in its E-VLT-006 form: the meta choice was closed.
pub const T_META_CLOSED: &str = "meta 파일(meta.ywm)을 읽을 수 없어 아무것도 바꾸지 않았습니다. 계정 이름·주소록·연결한 사이트 없이 열려 있고 보내기는 멈춥니다. 고를 때까지 이 파일에 아무것도 쓰지 않습니다. 앱을 업데이트했거나 파일을 직접 되돌렸다면 '다시 불러오기'를 누르세요. 여전히 읽을 수 없으면 고르는 화면이 다시 열립니다.";

/// The overlay state (this session).
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts of two overlays"
)]
pub struct SidecarUi {
    /// The meta overlay is for a file this build cannot read, not a damaged one.
    pub meta_newer: bool,
    /// The journal overlay is for a file this build cannot read.
    pub journal_newer: bool,
    /// The journal did not open and its choice was closed: every send stops.
    pub journal_closed: bool,
    /// `고급` of a newer-format overlay is open.
    pub advanced: bool,
    /// Why the last choice changed nothing (shown in the overlay).
    pub refusal: Option<String>,
    /// The Bitcoin send form's check after a journal reset is ticked.
    pub reset_ack: bool,
}

/// A send form, for [`App::journal_hold`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendChain {
    /// S11 and EVM approvals.
    Evm,
    /// Solana.
    Sol,
    /// Bitcoin.
    Btc,
    /// Zcash.
    Zec,
}

/// Why the journal holds a send now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalHold {
    /// The journal did not open and its choice was closed.
    Closed,
    /// Solana or Zcash after a journal reset: a transaction the old journal tracked may confirm
    /// until about this time (Unix seconds).
    Wait(u64),
    /// Bitcoin after a journal reset: the check is not ticked.
    Check,
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// `YYYY-MM-DD HH:MM` in local time (spec/04 §2.6); UTC with a suffix if the conversion fails.
fn local_time(unix_secs: u64) -> String {
    let unix_ms = unix_secs.saturating_mul(1_000);
    let wall = yw_win::time::local_wall_ms(unix_ms);
    let text = crate::logging::format_utc(wall.unwrap_or(unix_ms));
    let short = text.get(..16).unwrap_or(&text).replace('T', " ");
    if wall.is_some() {
        short
    } else {
        format!("{short} UTC")
    }
}

const fn overlay_of(kind: FileKind) -> Confirm {
    match kind {
        FileKind::Journal => Confirm::JournalCorrupt,
        FileKind::Meta | FileKind::Vault => Confirm::SidecarCorrupt,
    }
}

/// What the overlay says when a choice changed nothing (or not everything).
#[must_use]
pub fn refusal_text(kind: FileKind, refusal: SidecarRefusal) -> String {
    let name = crate::store::file_name(kind);
    match refusal {
        SidecarRefusal::NoPrev => {
            format!("이전 사본({name}.prev)이 없습니다. 아무 파일도 바꾸지 않았습니다.")
        }
        SidecarRefusal::PrevUnreadable => format!(
            "이전 사본({name}.prev)도 열리지 않거나 이 버전이 읽을 수 없습니다. 아무 파일도 바꾸지 않았습니다. 다른 선택을 고르거나, 앱을 최신 버전으로 업데이트하세요."
        ),
        SidecarRefusal::Failed(code) => format!(
            "파일을 옮기거나 쓰지 못했습니다. 데이터 폴더의 {name} 파일들(.prev, .corrupt-…)은 지우지 않았습니다. 다른 프로그램이 파일을 쓰고 있지 않은지 확인하고 다시 고르세요. ({})",
            code.code()
        ),
    }
}

/// The notice after a choice: what happened, where the moved files are, what to check.
#[must_use]
pub fn resolved_text(kind: FileKind, use_prev: bool, moves: &SidecarMoves) -> String {
    let mut names = Vec::new();
    if let Some(name) = &moves.quarantined {
        names.push(format!("읽을 수 없던 파일은 {name}"));
    }
    if let Some(name) = &moves.prev {
        names.push(format!("이전 사본은 {name}"));
    }
    let where_to = if names.is_empty() {
        String::new()
    } else {
        format!(
            " {}(으)로 옮겨 두었습니다(지우지 않음, 되돌리는 방법은 복구 안내).",
            names.join(", ")
        )
    };
    match (kind, use_prev) {
        (FileKind::Meta, true) => format!(
            "meta를 이전 사본(.prev)으로 되돌렸습니다.{where_to} 마지막 저장 하나가 빠졌을 수 있습니다: 사이트·WalletConnect에서 끊었던 연결이 다시 생겼는지, 숨긴 계정·지운 주소록 항목이 돌아왔는지 확인하세요. '설정 파일이 앱 밖에서 바뀌었습니다' 띠가 보이면 되돌린 사본의 기록 때문일 수 있습니다 — 직접 바꾼 값이면 '파일 값 사용'을 누르세요."
        ),
        (FileKind::Meta | FileKind::Vault, _) => format!(
            "meta를 새로 시작했습니다.{where_to} 추가했던 계정은 '계정 추가'로 다시 만들고, 사이트는 dApp에서 다시 연결하세요. 비슷한 주소 경고가 비교할 이전 받는 주소 기록도 없으니 받는 주소를 처음부터 끝까지 확인하세요."
        ),
        (FileKind::Journal, _) => format!(
            "거래 저널을 새로 시작했습니다.{where_to} 그 전에 보낸 거래 중 확정되지 않았던 것은 기록 없이 블록체인에서 확정될 수 있습니다. 같은 송금을 다시 보내기 전에 블록 탐색기에서 보낸 주소의 거래를 확인하세요."
        ),
    }
}

impl App {
    /// `KeyOutcome::Meta` could not open or read `meta.ywm` (E-VLT-006).
    pub(crate) fn meta_unreadable(&mut self, error: VaultError) {
        logging::warn(
            "app",
            "meta.unreadable",
            &[(
                "kind",
                Field::Word(if matches!(error, VaultError::SidecarUnsupported(_)) {
                    "newer"
                } else {
                    "damaged"
                }),
            )],
        );
        self.wait.meta_since = None;
        // Like T-META-FAILED: nothing in memory stands in for the file and nothing is saved over
        // it until a load succeeds (a reload during a session may have held an older document).
        self.meta = None;
        self.wait.meta_failed = Some(ErrorCode::Vlt006);
        self.sidecar.meta_newer = matches!(error, VaultError::SidecarUnsupported(_));
        self.sidecar.advanced = false;
        self.set_screen(Screen::Confirm(Confirm::SidecarCorrupt));
    }

    /// `KeyOutcome::Journal` could not open or read `journal.ywj` (E-VLT-006).
    pub(crate) fn journal_unreadable(&mut self, error: VaultError) {
        let newer = matches!(error, VaultError::SidecarUnsupported(_));
        logging::warn(
            "app",
            "journal.unreadable",
            &[("kind", Field::Word(if newer { "newer" } else { "damaged" }))],
        );
        self.sidecar.journal_newer = newer;
        if self.sidecar.journal_closed {
            // Read again by a later meta reload: the choice was closed this session, and its
            // band with `선택 다시 보기` is still up; it does not pop up over what the user does.
            self.refresh();
            return;
        }
        self.sidecar.advanced = false;
        self.set_screen(Screen::Confirm(Confirm::JournalCorrupt));
    }

    /// `이전 사본(.prev) 사용` / `격리하고 새로 시작` of either overlay.
    pub(crate) fn choose_sidecar(&mut self, kind: FileKind, use_prev: bool) {
        self.sidecar.refusal = None;
        self.set_screen(Screen::Processing(if use_prev {
            "이전 사본을 확인하는 중…"
        } else {
            "파일을 옮기는 중…"
        }));
        self.key(KeyJob::ResolveSidecar { kind, use_prev });
    }

    /// `닫기` of the journal overlay: nothing changes; every send stops with one reason and
    /// `선택 다시 보기` until the choice is made or the session ends.
    pub(crate) fn journal_choice_closed(&mut self) {
        logging::info("app", "journal.choice_closed", &[]);
        self.sidecar.journal_closed = true;
        self.sidecar.advanced = false;
        self.sidecar.refusal = None;
        self.set_screen(Screen::Main);
    }

    /// `KeyOutcome::SidecarResolved`.
    pub(crate) fn on_sidecar_resolved(
        &mut self,
        kind: FileKind,
        use_prev: bool,
        result: Result<SidecarMoves, SidecarRefusal>,
    ) {
        let moves = match result {
            Ok(moves) => moves,
            Err(refusal) => {
                // Back to the same choice, saying why; a load would only find the same file (or,
                // after a half-done move, quietly start from a default).
                self.sidecar.refusal = Some(refusal_text(kind, refusal));
                self.set_screen(Screen::Confirm(overlay_of(kind)));
                return;
            }
        };
        // The stale E-VLT-006 bands go; a damaged entry the reload still finds raises its own.
        self.banners
            .retain(|banner| banner.code != Some(ErrorCode::Vlt006));
        self.sidecar.refusal = None;
        self.sidecar.advanced = false;
        let text = resolved_text(kind, use_prev, &moves);
        if kind == FileKind::Journal {
            self.sidecar.journal_closed = false;
            self.sidecar.journal_newer = false;
            if !use_prev {
                // Saved before the reload below reads the meta again.
                self.sidecar.reset_ack = false;
                if let Some(meta) = self.meta.as_mut() {
                    meta.security.journal_reset_at = now_unix();
                }
                self.save_meta();
            }
            self.notice(text, Tone::Warn);
        } else {
            self.sidecar.meta_newer = false;
            self.notice(text, Tone::Info);
        }
        self.evm.journal = None;
        self.request_meta();
        self.set_screen(Screen::Processing("불러오는 중…"));
    }

    /// Commands of the two overlays, the closed journal's band and the reset check; `false` when
    /// `id` is not one of them.
    pub(crate) fn on_sidecar_command(&mut self, id: u16) -> bool {
        match id {
            ids::SIDECAR_CLOSE => {
                logging::info("app", "meta.choice_closed", &[]);
                self.sidecar.advanced = false;
                self.sidecar.refusal = None;
                self.set_screen(if self.mode == AppMode::BackupPending {
                    Screen::BackupPending
                } else {
                    Screen::Main
                });
            }
            ids::ADVANCED => {
                self.sidecar.advanced = !self.sidecar.advanced;
                self.refresh();
            }
            ids::JOURNAL_REOPEN => {
                if self.sidecar.journal_closed {
                    self.sidecar.advanced = false;
                    self.set_screen(Screen::Confirm(Confirm::JournalCorrupt));
                }
            }
            ids::RESET_ACK => {
                self.sidecar.reset_ack = self
                    .controls
                    .checked(ids::RESET_ACK)
                    .unwrap_or(!self.sidecar.reset_ack);
                self.refresh();
            }
            _ => return false,
        }
        true
    }

    /// The last journal reset (Unix seconds) and how far into `window` `now` is, while inside it.
    /// A clock set back before the reset counts as its start.
    fn reset_elapsed(&self, window: u64, now: u64) -> Option<(u64, u64)> {
        let at = self.meta.as_ref()?.security.journal_reset_at;
        let elapsed = now.saturating_sub(at);
        (at != 0 && elapsed < window).then_some((at, elapsed))
    }

    /// Why a send of `chain` stops now because of the journal (`None`: it does not).
    #[must_use]
    pub(crate) fn journal_hold(&self, chain: SendChain) -> Option<JournalHold> {
        if self.sidecar.journal_closed {
            return Some(JournalHold::Closed);
        }
        let now = now_unix();
        let wait = |window: u64| {
            self.reset_elapsed(window, now).map(|(_, elapsed)| {
                JournalHold::Wait(now.saturating_add(window.saturating_sub(elapsed)))
            })
        };
        match chain {
            SendChain::Evm => None,
            SendChain::Sol => wait(SOL_RESET_WAIT_SECS),
            SendChain::Zec => wait(ZEC_RESET_WAIT_SECS),
            SendChain::Btc => (self.reset_elapsed(RESET_WATCH_SECS, now).is_some()
                && !self.sidecar.reset_ack)
                .then_some(JournalHold::Check),
        }
    }

    /// Above a send form's `검토`: why the journal holds it — closed (one line; the header band
    /// has the reason and `선택 다시 보기`), or the wait or the check after a journal reset.
    pub(crate) fn journal_send_items(&self, chain: SendChain, items: &mut Vec<Item>) {
        if self.sidecar.journal_closed {
            items.push(Item::Help(
                "보내기 멈춤: 거래 저널을 열지 못했습니다(맨 위 안내의 '선택 다시 보기')."
                    .to_owned(),
            ));
            return;
        }
        let name = match chain {
            SendChain::Evm => return,
            SendChain::Sol => "Solana",
            SendChain::Zec => "Zcash",
            SendChain::Btc => {
                if let Some((at, _)) = self.reset_elapsed(RESET_WATCH_SECS, now_unix()) {
                    items.push(Item::Banner(
                        format!(
                            "거래 저널을 {}에 새로 시작했습니다. 그 전에 보낸 Bitcoin 거래 중 확정되지 않았거나 '포기'한 것은 기록 없이 나중에 확정될 수 있고, 이 앱은 그 거래가 쓴 UTXO를 더는 피하지 않습니다. 잔액이 줄었는데 활동에 없으면 그 거래일 수 있습니다. 같은 송금을 다시 보내기 전에 블록 탐색기에서 보내는 주소의 거래를 확인하세요.",
                            local_time(at)
                        ),
                        Tone::HighRisk,
                    ));
                    items.push(Item::Row(vec![Ctl::check(
                        ids::RESET_ACK,
                        "블록 탐색기에서 이전 거래를 확인했습니다",
                        self.sidecar.reset_ack,
                    )]));
                }
                return;
            }
        };
        if let Some(JournalHold::Wait(until)) = self.journal_hold(chain) {
            items.push(Item::Banner(
                format!(
                    "{name} 보내기는 {}부터 됩니다. 거래 저널을 새로 시작하기 전에 보낸 거래가 아직 처리 중이면 그때까지 확정될 수 있어, 같은 송금이 두 번 나가지 않도록 기다립니다.",
                    local_time(until)
                ),
                Tone::Warn,
            ));
        }
    }

    /// The closed journal's band with `선택 다시 보기`, on every screen of the session.
    pub(crate) fn journal_closed_items(&self, items: &mut Vec<Item>) {
        if !self.sidecar.journal_closed
            || !matches!(self.mode, AppMode::Unlocked { .. })
            || self.screen == Screen::Confirm(Confirm::JournalCorrupt)
        {
            return;
        }
        items.push(Item::Banner(
            format!("{T_JOURNAL_CLOSED} ({})", ErrorCode::Vlt006.code()),
            Tone::Blocked,
        ));
        items.push(Item::Row(vec![Ctl::button(
            ids::JOURNAL_REOPEN,
            "선택 다시 보기",
        )]));
    }

    fn refusal_items(&self, items: &mut Vec<Item>) {
        if let Some(text) = &self.sidecar.refusal {
            items.push(Item::Banner(text.clone(), Tone::Danger));
        }
    }

    fn advanced_link(&self, items: &mut Vec<Item>) {
        items.push(Item::Row(vec![Ctl::link(
            ids::ADVANCED,
            if self.sidecar.advanced {
                "고급: 되돌리기·새로 시작 숨기기 ▾"
            } else {
                "고급: 그래도 되돌리거나 새로 시작하기 ▸"
            },
        )]));
    }

    /// The meta overlay (`Confirm::SidecarCorrupt`).
    pub(crate) fn meta_overlay(&self, items: &mut Vec<Item>) {
        use crate::ui::screens::ids as core;
        let prev = crate::store::prev_exists(&self.paths.data, FileKind::Meta);
        let newer = self.sidecar.meta_newer;
        items.push(Item::Title(
            if newer {
                "새 버전 앱이 저장한 meta 파일"
            } else {
                "meta 파일을 열 수 없음"
            }
            .to_owned(),
        ));
        items.push(Item::CardStart(None));
        items.push(Item::Text(
            if newer { T_META_NEWER } else { T_META_DAMAGED }.to_owned(),
        ));
        self.refusal_items(items);
        if newer {
            items.push(Item::Row(vec![
                Ctl::primary(ids::SIDECAR_CLOSE, "닫기 (아무것도 바꾸지 않음)"),
                Ctl::button(core::LOCK, "잠금"),
            ]));
            self.advanced_link(items);
            if !self.sidecar.advanced {
                items.push(Item::CardEnd);
                return;
            }
            items.push(Item::Banner(T_NEWER_ADVANCED.to_owned(), Tone::HighRisk));
        }
        if prev {
            items.push(Item::Help(T_META_PREV.to_owned()));
        }
        items.push(Item::Help(T_META_FRESH.to_owned()));
        let mut row = Vec::new();
        if prev {
            row.push(if newer {
                Ctl::button(core::SIDECAR_PREV, "이전 사본(.prev) 사용")
            } else {
                Ctl::primary(core::SIDECAR_PREV, "이전 사본(.prev) 사용")
            });
        }
        row.push(Ctl::danger(core::SIDECAR_FRESH, "격리하고 새로 시작"));
        if !newer {
            items.push(Item::Help(T_META_CLOSE.to_owned()));
            row.push(Ctl::button(
                ids::SIDECAR_CLOSE,
                "닫기 (아무것도 바꾸지 않음)",
            ));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
    }

    /// The journal overlay (`Confirm::JournalCorrupt`).
    pub(crate) fn journal_overlay(&self, items: &mut Vec<Item>) {
        use crate::ui::screens::ids as core;
        let newer = self.sidecar.journal_newer;
        items.push(Item::Title(
            if newer {
                "새 버전 앱이 저장한 거래 저널"
            } else {
                "거래 저널을 열 수 없음"
            }
            .to_owned(),
        ));
        items.push(Item::CardStart(None));
        items.push(Item::Text(
            if newer {
                T_JOURNAL_NEWER
            } else {
                T_JOURNAL_DAMAGED
            }
            .to_owned(),
        ));
        self.refusal_items(items);
        if newer {
            items.push(Item::Row(vec![
                Ctl::primary(core::CONFIRM_NO, "닫기 (보내기 멈춤)"),
                Ctl::button(core::LOCK, "잠금"),
            ]));
            self.advanced_link(items);
            if self.sidecar.advanced {
                items.push(Item::Banner(T_NEWER_ADVANCED.to_owned(), Tone::HighRisk));
                items.push(Item::Banner(T_JOURNAL_RESET.to_owned(), Tone::HighRisk));
                items.push(Item::Row(vec![Ctl::danger(
                    core::CONFIRM_YES,
                    "격리하고 새로 시작",
                )]));
            }
        } else {
            items.push(Item::Banner(T_JOURNAL_RESET.to_owned(), Tone::HighRisk));
            items.push(Item::Row(vec![
                Ctl::danger(core::CONFIRM_YES, "격리하고 새로 시작"),
                Ctl::button(core::CONFIRM_NO, "닫기 (보내기 멈춤)"),
            ]));
        }
        items.push(Item::CardEnd);
    }
}
