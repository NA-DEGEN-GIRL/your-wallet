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
use yw_core::lang::{Lang, Text};
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

/// The overlay texts (spec/04 §2.5, T-JOURNAL-RESET, T-JOURNAL-CLOSED, T-META-CLOSED).
pub mod text {
    yw_core::texts! {
        /// T-JOURNAL-RESET: what starting the journal over loses.
        JOURNAL_RESET = "새로 시작하면: 보낸 뒤 아직 확정되지 않았거나 '포기'한 거래는 기록만 사라지고, 블록체인에서는 나중에 확정될 수 있습니다. 블록 탐색기에서 확인하기 전에 같은 송금을 다시 보내면 두 번 지불될 수 있습니다. 그 거래의 수수료 올리기·취소·폐기·재전송도 더는 할 수 없습니다. 읽을 수 없는 파일과 이전 사본은 지우지 않고 journal.ywj.corrupt-<시각>, journal.ywj.prev.corrupt-<시각>으로 옮겨 둡니다(복구 안내)."
            / "If you start over: transactions sent but not yet final, or 'abandoned', lose only their record and can still confirm on the blockchain later. Sending the same transfer again before checking a block explorer can pay twice. Raising the fee, cancelling, discarding or resending those transactions is no longer possible. The unreadable file and the previous copy are not deleted but moved to journal.ywj.corrupt-<time> and journal.ywj.prev.corrupt-<time> (recovery guide).";
        /// The journal overlay of a file that does not open.
        JOURNAL_DAMAGED = "거래 저널(journal.ywj: 보낸 뒤 아직 끝나지 않은 거래의 기록)을 열 수 없습니다. 파일이 손상되었거나 다른 지갑의 파일입니다. 저널을 열기 전에는 EVM·Solana·Bitcoin·Zcash 보내기를 멈춥니다."
            / "The transaction journal (journal.ywj: the record of sent transactions that are not finished yet) cannot be opened. The file is damaged or belongs to another wallet. EVM, Solana, Bitcoin and Zcash sends stop until the journal opens.";
        /// The journal overlay of a file this build cannot read.
        JOURNAL_NEWER = "거래 저널(journal.ywj)은 이 지갑의 키로 열리지만 이 버전이 모르는 형식입니다. 대개 더 새로운 버전의 앱이 저장한 파일입니다(새 버전을 쓰다가 이 버전으로 되돌린 경우). 파일은 바꾸지 않았고 EVM·Solana·Bitcoin·Zcash 보내기를 멈췄습니다. 앱을 최신 버전으로 업데이트하세요."
            / "The transaction journal (journal.ywj) opens with this wallet's key, but this version does not know its format. Usually a newer version of the app saved it (you used a newer version and went back to this one). The file was not changed, and EVM, Solana, Bitcoin and Zcash sends are stopped. Update the app to the latest version.";
        /// T-JOURNAL-CLOSED: the band of a journal whose choice was closed (every screen).
        JOURNAL_CLOSED = "거래 저널을 열지 못해 EVM·Solana·Bitcoin·Zcash 보내기를 멈췄습니다(Bitcoin은 조회도). 앱을 업데이트했거나 파일을 직접 되돌렸다면 잠근 뒤 다시 잠금 해제하세요. 아니면 '선택 다시 보기'에서 고르세요."
            / "The transaction journal did not open, so EVM, Solana, Bitcoin and Zcash sends are stopped (Bitcoin lookups too). If you updated the app or restored the file yourself, lock and unlock again. Otherwise choose under 'Show choices again'.";
        /// The approval window's failure while the journal's choice is closed.
        JOURNAL_CLOSED_SEND = "보내지 않았습니다: 거래 저널을 열지 못해 보내기를 멈췄습니다. 지갑 화면 맨 위의 '선택 다시 보기'에서 고르세요."
            / "Not sent: the transaction journal did not open, so sends are stopped. Choose under 'Show choices again' at the top of the wallet screen.";
        /// The meta overlay of a file that does not open.
        META_DAMAGED = "meta 파일(meta.ywm: 계정 이름·주소록·사이트 연결·활동 기록 등)을 열 수 없습니다. 파일이 손상되었거나 다른 지갑의 파일입니다. 복구 단어·개인키와 자산은 이 파일에 없어 그대로입니다. 고를 때까지 이 파일에 아무것도 쓰지 않습니다."
            / "The meta file (meta.ywm: account names, address book, site connections, activity and more) cannot be opened. The file is damaged or belongs to another wallet. Your recovery words, private keys and assets are not in this file and are unchanged. Nothing is written to this file until you choose.";
        /// The meta overlay of a file this build cannot read.
        META_NEWER = "meta 파일(meta.ywm)은 이 지갑의 키로 열리지만 이 버전이 모르는 형식입니다. 대개 더 새로운 버전의 앱이 저장한 파일입니다(새 버전을 쓰다가 이 버전으로 되돌린 경우). 파일은 그대로 두었고, 고를 때까지 아무것도 쓰지 않습니다. 앱을 최신 버전으로 업데이트하세요."
            / "The meta file (meta.ywm) opens with this wallet's key, but this version does not know its format. Usually a newer version of the app saved it (you used a newer version and went back to this one). The file was left as is, and nothing is written until you choose. Update the app to the latest version.";
        /// The warning above the destructive choices of a newer-format file.
        NEWER_ADVANCED = "되돌리거나 새로 시작하면 새 버전에서 만든 내용(계정·라벨·연결, 저널이면 진행 중 거래 기록)이 사라지고, 새 버전으로 돌아가도 돌아오지 않습니다. 앱을 업데이트할 수 없을 때만 고르세요."
            / "Restoring or starting over removes what the newer version created (accounts, labels, connections; for the journal, records of transactions in progress), and it does not come back when you return to the newer version. Choose this only if you cannot update the app.";
        /// `이전 사본(.prev) 사용` of meta.
        META_PREV = "이전 사본(.prev) 사용: 이전 사본을 먼저 열어 보고, 열리지 않으면 아무것도 바꾸지 않습니다. 마지막 저장 하나가 되돌아갑니다 — 예: 방금 끊은 사이트 연결, 숨긴 계정, 지운 주소록 항목이 다시 생길 수 있습니다. 지금 파일은 지우지 않고 meta.ywm.corrupt-<시각>으로 옮겨 둡니다."
            / "Use previous copy (.prev): the previous copy is opened first, and if it does not open nothing changes. The last save is undone — for example, a site connection you just removed, an account you hid or an address book entry you deleted may come back. The current file is not deleted but moved to meta.ywm.corrupt-<time>.";
        /// `격리하고 새로 시작` of meta: what resets, in plain words.
        META_FRESH = "격리하고 새로 시작: 다음이 처음 상태가 됩니다 — 계정 이름과 숨김 표시, 추가한 EVM·Solana 계정('계정 추가'로 다시 만들 수 있음), 주소록과 즐겨찾기, 사이트 연결(Solana·Bitcoin 포함)과 WalletConnect 세션, 추가한 토큰과 토큰 숨김, 기본 계정 외 Bitcoin 계정(EVM 키·YubiKey 키 계정 포함)과 주소 방식, Bitcoin 동결 표시(동결한 UTXO가 다시 쓰일 수 있음), 활동 기록과 비슷한 주소 경고가 비교하는 이전 받는 주소, 설정 파일 보호 기록. 복구 단어·가져온 개인키·YubiKey 등록과 자산은 그대로입니다. 지금 파일과 이전 사본은 지우지 않고 meta.ywm.corrupt-<시각>, meta.ywm.prev.corrupt-<시각>으로 옮겨 둡니다."
            / "Quarantine and start over: these go back to their initial state — account names and hidden marks, added EVM and Solana accounts (you can recreate them with 'Add account'), the address book and favorites, site connections (including Solana and Bitcoin) and WalletConnect sessions, added tokens and hidden tokens, Bitcoin accounts other than the default one (including EVM-key and YubiKey-key accounts) and their address types, Bitcoin freeze marks (frozen UTXOs may be spent again), activity and the earlier recipients the similar-address warning compares against, and the settings-file protection record. Recovery words, imported private keys, YubiKey enrolment and assets stay. The current file and the previous copy are not deleted but moved to meta.ywm.corrupt-<time> and meta.ywm.prev.corrupt-<time>.";
        /// `닫기` of meta.
        META_CLOSE = "닫기: 아무것도 바꾸지 않습니다. 계정 목록 없이 열리고 보내기는 멈춥니다. 앱을 업데이트했거나 파일을 직접 되돌렸다면 '다시 불러오기'로 다시 읽습니다."
            / "Close: nothing changes. The wallet opens without the account list and sends stop. If you updated the app or restored the file yourself, 'Reload' reads it again.";
        /// T-META-CLOSED: T-META-FAILED in its E-VLT-006 form (the meta choice was closed).
        META_CLOSED = "meta 파일(meta.ywm)을 읽을 수 없어 아무것도 바꾸지 않았습니다. 계정 이름·주소록·연결한 사이트 없이 열려 있고 보내기는 멈춥니다. 고를 때까지 이 파일에 아무것도 쓰지 않습니다. 앱을 업데이트했거나 파일을 직접 되돌렸다면 '다시 불러오기'를 누르세요. 여전히 읽을 수 없으면 고르는 화면이 다시 열립니다."
            / "The meta file (meta.ywm) could not be read, so nothing was changed. The wallet is open without account names, the address book or connected sites, and sends stop. Nothing is written to this file until you choose. If you updated the app or restored the file yourself, press 'Reload'. If it still cannot be read, the choice screen opens again.";
        REFUSAL_NO_PREV(1) = "이전 사본({0}.prev)이 없습니다. 아무 파일도 바꾸지 않았습니다."
            / "There is no previous copy ({0}.prev). No file was changed.";
        REFUSAL_PREV_UNREADABLE(1) = "이전 사본({0}.prev)도 열리지 않거나 이 버전이 읽을 수 없습니다. 아무 파일도 바꾸지 않았습니다. 다른 선택을 고르거나, 앱을 최신 버전으로 업데이트하세요."
            / "The previous copy ({0}.prev) does not open either, or this version cannot read it. No file was changed. Choose another option, or update the app to the latest version.";
        REFUSAL_FAILED(2) = "파일을 옮기거나 쓰지 못했습니다. 데이터 폴더의 {0} 파일들(.prev, .corrupt-…)은 지우지 않았습니다. 다른 프로그램이 파일을 쓰고 있지 않은지 확인하고 다시 고르세요. ({1})"
            / "The files could not be moved or written. The {0} files in the data folder (.prev, .corrupt-…) were not deleted. Check that no other program is using the files, then choose again. ({1})";
        MOVED_QUARANTINED(1) = "읽을 수 없던 파일은 {0}" / "the unreadable file to {0}";
        MOVED_PREV(1) = "이전 사본은 {0}" / "the previous copy to {0}";
        MOVED_WHERE(1) = " {0}(으)로 옮겨 두었습니다(지우지 않음, 되돌리는 방법은 복구 안내)."
            / " Moved {0} (not deleted; the recovery guide explains how to undo it).";
        RESOLVED_META_PREV(1) = "meta를 이전 사본(.prev)으로 되돌렸습니다.{0} 마지막 저장 하나가 빠졌을 수 있습니다: 사이트·WalletConnect에서 끊었던 연결이 다시 생겼는지, 숨긴 계정·지운 주소록 항목이 돌아왔는지 확인하세요. '설정 파일이 앱 밖에서 바뀌었습니다' 띠가 보이면 되돌린 사본의 기록 때문일 수 있습니다 — 직접 바꾼 값이면 '파일 값 사용'을 누르세요."
            / "The meta file was restored from the previous copy (.prev).{0} The last save may be missing: check whether connections you removed in Sites or WalletConnect came back, and whether hidden accounts or deleted address book entries returned. If the 'The settings file was changed outside the app' band appears, it may come from the restored copy's record — if you changed the value yourself, press 'Use file value'.";
        RESOLVED_META_FRESH(1) = "meta를 새로 시작했습니다.{0} 추가했던 계정은 '계정 추가'로 다시 만들고, 사이트는 dApp에서 다시 연결하세요. 비슷한 주소 경고가 비교할 이전 받는 주소 기록도 없으니 받는 주소를 처음부터 끝까지 확인하세요."
            / "The meta file was started over.{0} Recreate added accounts with 'Add account' and reconnect sites from the dApp. The similar-address warning has no earlier recipients to compare against either, so check each recipient address from start to end.";
        RESOLVED_JOURNAL(1) = "거래 저널을 새로 시작했습니다.{0} 그 전에 보낸 거래 중 확정되지 않았던 것은 기록 없이 블록체인에서 확정될 수 있습니다. 같은 송금을 다시 보내기 전에 블록 탐색기에서 보낸 주소의 거래를 확인하세요."
            / "The transaction journal was started over.{0} Transactions sent before that which were not final may confirm on the blockchain without a record. Before sending the same transfer again, check the sending address's transactions in a block explorer.";
        CHECKING_PREV = "이전 사본을 확인하는 중…" / "Checking the previous copy…";
        MOVING_FILES = "파일을 옮기는 중…" / "Moving files…";
        LOADING = "불러오는 중…" / "Loading…";
        SEND_STOPPED = "보내기 멈춤: 거래 저널을 열지 못했습니다(맨 위 안내의 '선택 다시 보기')."
            / "Sending stopped: the transaction journal did not open ('Show choices again' in the notice at the top).";
        BTC_RESET(1) = "거래 저널을 {0}에 새로 시작했습니다. 그 전에 보낸 Bitcoin 거래 중 확정되지 않았거나 '포기'한 것은 기록 없이 나중에 확정될 수 있고, 이 앱은 그 거래가 쓴 UTXO를 더는 피하지 않습니다. 잔액이 줄었는데 활동에 없으면 그 거래일 수 있습니다. 같은 송금을 다시 보내기 전에 블록 탐색기에서 보내는 주소의 거래를 확인하세요."
            / "The transaction journal was started over at {0}. Bitcoin transactions sent before that which were not final or were 'abandoned' may confirm later without a record, and this app no longer avoids the UTXOs they spent. If your balance went down and nothing in Activity explains it, it may be one of them. Before sending the same transfer again, check the sending address's transactions in a block explorer.";
        BTC_RESET_ACK = "블록 탐색기에서 이전 거래를 확인했습니다"
            / "I checked earlier transactions in a block explorer";
        RESET_WAIT(2) = "{0} 보내기는 {1}부터 됩니다. 거래 저널을 새로 시작하기 전에 보낸 거래가 아직 처리 중이면 그때까지 확정될 수 있어, 같은 송금이 두 번 나가지 않도록 기다립니다."
            / "{0} sends are possible from {1}. A transaction sent before the journal was started over may still confirm until then, so the wallet waits to keep the same transfer from going out twice.";
        SHOW_CHOICES = "선택 다시 보기" / "Show choices again";
        ADVANCED_HIDE = "고급: 되돌리기·새로 시작 숨기기 ▾" / "Advanced: hide restore and start over ▾";
        ADVANCED_SHOW = "고급: 그래도 되돌리거나 새로 시작하기 ▸" / "Advanced: restore or start over anyway ▸";
        META_NEWER_TITLE = "새 버전 앱이 저장한 meta 파일" / "Meta file saved by a newer app version";
        META_DAMAGED_TITLE = "meta 파일을 열 수 없음" / "The meta file cannot be opened";
        CLOSE_UNCHANGED = "닫기 (아무것도 바꾸지 않음)" / "Close (change nothing)";
        LOCK = "잠금" / "Lock";
        USE_PREV = "이전 사본(.prev) 사용" / "Use previous copy (.prev)";
        QUARANTINE = "격리하고 새로 시작" / "Quarantine and start over";
        JOURNAL_NEWER_TITLE = "새 버전 앱이 저장한 거래 저널" / "Transaction journal saved by a newer app version";
        JOURNAL_DAMAGED_TITLE = "거래 저널을 열 수 없음" / "The transaction journal cannot be opened";
        CLOSE_SENDS_STOP = "닫기 (보내기 멈춤)" / "Close (sends stop)";
    }
}

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
pub fn refusal_text(lang: Lang, kind: FileKind, refusal: SidecarRefusal) -> String {
    let name = crate::store::file_name(kind);
    match refusal {
        SidecarRefusal::NoPrev => text::REFUSAL_NO_PREV.fill(lang, [name]),
        SidecarRefusal::PrevUnreadable => text::REFUSAL_PREV_UNREADABLE.fill(lang, [name]),
        SidecarRefusal::Failed(code) => text::REFUSAL_FAILED.fill(lang, [name, code.code()]),
    }
}

/// The notice after a choice: what happened, where the moved files are, what to check.
#[must_use]
pub fn resolved_text(lang: Lang, kind: FileKind, use_prev: bool, moves: &SidecarMoves) -> String {
    let mut names = Vec::new();
    if let Some(name) = &moves.quarantined {
        names.push(text::MOVED_QUARANTINED.fill(lang, [name]));
    }
    if let Some(name) = &moves.prev {
        names.push(text::MOVED_PREV.fill(lang, [name]));
    }
    let where_to = if names.is_empty() {
        String::new()
    } else {
        text::MOVED_WHERE.fill(lang, [&names.join(", ")])
    };
    match (kind, use_prev) {
        (FileKind::Meta, true) => text::RESOLVED_META_PREV.fill(lang, [&where_to]),
        (FileKind::Meta | FileKind::Vault, _) => text::RESOLVED_META_FRESH.fill(lang, [&where_to]),
        (FileKind::Journal, _) => text::RESOLVED_JOURNAL.fill(lang, [&where_to]),
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
        let lang = self.settings.language;
        self.set_screen(Screen::Processing(if use_prev {
            text::CHECKING_PREV.get(lang)
        } else {
            text::MOVING_FILES.get(lang)
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
                self.sidecar.refusal = Some(refusal_text(self.settings.language, kind, refusal));
                self.set_screen(Screen::Confirm(overlay_of(kind)));
                return;
            }
        };
        // The stale E-VLT-006 bands go; a damaged entry the reload still finds raises its own.
        self.banners
            .retain(|banner| banner.code != Some(ErrorCode::Vlt006));
        self.sidecar.refusal = None;
        self.sidecar.advanced = false;
        let lang = self.settings.language;
        let notice = resolved_text(lang, kind, use_prev, &moves);
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
            self.notice(notice, Tone::Warn);
        } else {
            self.sidecar.meta_newer = false;
            self.notice(notice, Tone::Info);
        }
        self.evm.journal = None;
        self.request_meta();
        self.set_screen(Screen::Processing(text::LOADING.get(lang)));
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
        let lang = self.settings.language;
        if self.sidecar.journal_closed {
            items.push(Item::Help(text::SEND_STOPPED.get(lang).to_owned()));
            return;
        }
        let name = match chain {
            SendChain::Evm => return,
            SendChain::Sol => "Solana",
            SendChain::Zec => "Zcash",
            SendChain::Btc => {
                if let Some((at, _)) = self.reset_elapsed(RESET_WATCH_SECS, now_unix()) {
                    items.push(Item::Banner(
                        text::BTC_RESET.fill(lang, [&local_time(at)]),
                        Tone::HighRisk,
                    ));
                    items.push(Item::Row(vec![Ctl::check(
                        ids::RESET_ACK,
                        text::BTC_RESET_ACK.get(lang),
                        self.sidecar.reset_ack,
                    )]));
                }
                return;
            }
        };
        if let Some(JournalHold::Wait(until)) = self.journal_hold(chain) {
            items.push(Item::Banner(
                text::RESET_WAIT.fill(lang, [name, &local_time(until)]),
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
        let lang = self.settings.language;
        items.push(Item::Banner(
            format!(
                "{} ({})",
                text::JOURNAL_CLOSED.get(lang),
                ErrorCode::Vlt006.code()
            ),
            Tone::Blocked,
        ));
        items.push(Item::Row(vec![Ctl::button(
            ids::JOURNAL_REOPEN,
            text::SHOW_CHOICES.get(lang),
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
                text::ADVANCED_HIDE
            } else {
                text::ADVANCED_SHOW
            }
            .get(self.settings.language),
        )]));
    }

    /// The meta overlay (`Confirm::SidecarCorrupt`).
    pub(crate) fn meta_overlay(&self, items: &mut Vec<Item>) {
        use crate::ui::screens::ids as core;
        let prev = crate::store::prev_exists(&self.paths.data, FileKind::Meta);
        let newer = self.sidecar.meta_newer;
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        items.push(Item::Title(t(if newer {
            text::META_NEWER_TITLE
        } else {
            text::META_DAMAGED_TITLE
        })));
        items.push(Item::CardStart(None));
        items.push(Item::Text(t(if newer {
            text::META_NEWER
        } else {
            text::META_DAMAGED
        })));
        self.refusal_items(items);
        if newer {
            items.push(Item::Row(vec![
                Ctl::primary(ids::SIDECAR_CLOSE, text::CLOSE_UNCHANGED.get(lang)),
                Ctl::button(core::LOCK, text::LOCK.get(lang)),
            ]));
            self.advanced_link(items);
            if !self.sidecar.advanced {
                items.push(Item::CardEnd);
                return;
            }
            items.push(Item::Banner(t(text::NEWER_ADVANCED), Tone::HighRisk));
        }
        if prev {
            items.push(Item::Help(t(text::META_PREV)));
        }
        items.push(Item::Help(t(text::META_FRESH)));
        let mut row = Vec::new();
        if prev {
            row.push(if newer {
                Ctl::button(core::SIDECAR_PREV, text::USE_PREV.get(lang))
            } else {
                Ctl::primary(core::SIDECAR_PREV, text::USE_PREV.get(lang))
            });
        }
        row.push(Ctl::danger(core::SIDECAR_FRESH, text::QUARANTINE.get(lang)));
        if !newer {
            items.push(Item::Help(t(text::META_CLOSE)));
            row.push(Ctl::button(
                ids::SIDECAR_CLOSE,
                text::CLOSE_UNCHANGED.get(lang),
            ));
        }
        items.push(Item::Row(row));
        items.push(Item::CardEnd);
    }

    /// The journal overlay (`Confirm::JournalCorrupt`).
    pub(crate) fn journal_overlay(&self, items: &mut Vec<Item>) {
        use crate::ui::screens::ids as core;
        let newer = self.sidecar.journal_newer;
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        items.push(Item::Title(t(if newer {
            text::JOURNAL_NEWER_TITLE
        } else {
            text::JOURNAL_DAMAGED_TITLE
        })));
        items.push(Item::CardStart(None));
        items.push(Item::Text(t(if newer {
            text::JOURNAL_NEWER
        } else {
            text::JOURNAL_DAMAGED
        })));
        self.refusal_items(items);
        if newer {
            items.push(Item::Row(vec![
                Ctl::primary(core::CONFIRM_NO, text::CLOSE_SENDS_STOP.get(lang)),
                Ctl::button(core::LOCK, text::LOCK.get(lang)),
            ]));
            self.advanced_link(items);
            if self.sidecar.advanced {
                items.push(Item::Banner(t(text::NEWER_ADVANCED), Tone::HighRisk));
                items.push(Item::Banner(t(text::JOURNAL_RESET), Tone::HighRisk));
                items.push(Item::Row(vec![Ctl::danger(
                    core::CONFIRM_YES,
                    text::QUARANTINE.get(lang),
                )]));
            }
        } else {
            items.push(Item::Banner(t(text::JOURNAL_RESET), Tone::HighRisk));
            items.push(Item::Row(vec![
                Ctl::danger(core::CONFIRM_YES, text::QUARANTINE.get(lang)),
                Ctl::button(core::CONFIRM_NO, text::CLOSE_SENDS_STOP.get(lang)),
            ]));
        }
        items.push(Item::CardEnd);
    }
}
