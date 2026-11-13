//! Secret input and display windows W01–W10 (spec/04 §4, D11).
//!
//! The windows are custom-drawn (no OS EDIT control holds a secret); input arrives only as
//! `WM_CHAR` units into [`SecretField`] buffers; painting uses short-lived zeroizing UTF-16
//! copies. Ported from `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs`
//! (`HoldGate` 78-107, confirmation state 180-249, painting 342-470, field activation
//! 1559-1571, focus-loss handling 1572-1583) as an app-loop window instead of a one-shot helper:
//! focus loss masks the content (spec/04 §4.9) instead of cancelling.
//!
//! [`SecretForm`] is window-independent: `app` forwards decoded messages and acts on the returned
//! [`FormAction`].

use yw_core::bip39::{is_word, is_word_prefix};
use yw_core::keyimport::ImportChain;
use yw_core::password::VaultPassword;
use yw_core::secret::{SecretString, Zeroizing};
use yw_win::ui::{DrawFlags, PaintDc, Rect, scale};

use crate::errors::ErrorCode;
use crate::ui::secure_field::{
    Charset, PushResult, RejectReason, SecretField, finalize_private_key, has_edge_space,
    mnemonic_words, normalize_paste,
};
use crate::ui::theme::{self, Fonts, wide};

/// Inactivity (input windows) or display (W08/W09) lifetime.
pub const SECRET_WINDOW_TIMEOUT_MS: u64 = 300_000;
/// W08 `다 적었습니다` hold (archive `ACKNOWLEDGEMENT_HOLD_MS`).
pub const BACKUP_ACK_HOLD_MS: u64 = 2_000;
/// E-INP-008 visibility.
pub const INPUT_ERROR_MS: u64 = 3_000;
/// Input disabled after a wrong password (spec/02 §7.4).
pub const UNLOCK_FAIL_DISABLE_MS: u64 = 1_000;
/// Clipboard read bound.
pub const PASTE_MAX_UTF16_UNITS: usize = 4_096;
/// Window timer id and period.
pub const SECRET_TIMER_ID: usize = 1;
/// Timer period (hold progress, timeouts).
pub const SECRET_TIMER_MS: u32 = 50;
/// Mnemonic entry buffer (24 × 8 + 23 + 1).
pub const MNEMONIC_TEXT_MAX: usize = 216;
/// T-IMPORTED-KEY (W07, spec/04 §2.16): imported keys are not covered by the recovery words.
pub const T_IMPORTED_KEY_BACKUP: &str = "주의: 가져온 개인키는 이 지갑의 복구 단어(24단어)로 복구되지 않습니다. 이 PC나 지갑 파일을 잃으면 이 계정은 원래 개인키로만 되살릴 수 있으니, 원래 개인키를 따로 안전하게 보관하세요.";
/// T-KEY-ONLY (W07 of a wallet without recovery words, spec/04 §2.16).
pub const T_KEY_ONLY_BACKUP: &str = "주의: 이 지갑에는 복구 단어가 없습니다. 이 계정의 백업은 지금 입력하는 원래 개인키뿐입니다. 이 PC나 지갑 파일을 잃으면 원래 개인키로만 되살릴 수 있으니, 원래 개인키를 종이 등 안전한 곳에 따로 보관하세요.";
/// W11 (spec/10 §9.2): the card step after approval, after its three steps
/// ([`card_pin_steps`]).
pub const T_CARD_PIN: &str = "PIN은 이 서명 한 번에만 쓰고 바로 지웁니다.";

/// W11's steps (2026-11-10): which card to connect, the PIN, the touch — and the bounds.
#[must_use]
pub fn card_pin_steps(serial: u32) -> String {
    let card = if serial == 0 {
        "YubiKey".to_owned()
    } else {
        format!("YubiKey #{serial}")
    };
    format!(
        "1. {card} 연결 → 2. PIN 입력 후 확인 → 3. 깜박이면 15초 안에 터치 (승인 뒤 120초 안에)"
    )
}
/// W12 admin PIN (spec/10 §7.3).
pub const T_CARD_ADMIN_PIN: &str = "YubiKey를 하나만 연결하고 OpenPGP 관리자 PIN(PW3, 8–127자, 공장 기본값 12345678)을 입력하세요. 키를 가져오는 동안 한 번만 쓰고 바로 지웁니다.";
/// W12 management key (spec/10 §7.3).
pub const T_CARD_MANAGEMENT_KEY: &str = "YubiKey의 PIV 관리 키를 16진수 48자리로 입력하세요(ykman이 보여주는 형식). 이 지갑은 관리 키를 저장하지 않으며, 이번 작업에만 쓰고 바로 지웁니다.";
/// W12 of the optional ownership check of "`YubiKey` 연결하기" (spec/10 §7.6).
pub const T_CARD_USER_PIN: &str = "선택 사항입니다: 이 YubiKey의 PIN을 한 번 확인해 카드가 내 것인지 봅니다(VERIFY 한 번 — 서명·터치·쓰기 없음). 틀리면 남은 시도가 하나 줄어듭니다. 공장 기본 PIN(123456)은 보내지 않습니다. 확인하지 않아도 연결할 수 있고, 서명할 때는 언제나 PIN과 터치가 필요합니다.";
/// W12 PIV PIN (spec/10 §7.3, §9.3).
pub const T_CARD_PIV_PIN: &str = "YubiKey를 하나만 연결하고 PIV PIN(6–8자, 공장 기본값 123456)을 입력하세요. PIN으로 보호된 PIV 관리 키를 꺼내는 데 한 번만 쓰고 바로 지웁니다.";
/// W12 "PIN 하나로 통일" (spec/10 §9.3).
pub const T_CARD_SET_PINS: &str = "YubiKey를 하나만 연결하세요. 새 8자 PIN 하나를 OpenPGP PIN·OpenPGP 관리자 PIN·PIV PIN·PIV PUK에 똑같이 넣고, PIV 관리 키는 자동으로 새로 만들어 PIN으로 보호합니다. 현재 값이 공장 기본값이면 '현재 PIN'을 비워 두고, 전에 하나로 통일했다면 그 8자를 넣으세요. 공장 기본값(12345678)은 새 PIN으로 쓸 수 없습니다. 중간에 실패하면 거기서 멈추고 바뀐 것만 알려 드립니다.";
/// The unified W12's warning (2026-11-10): one current value is sent to all four secrets.
pub const T_CARD_SET_PINS_SAME: &str = "지금 네 값이 모두 같을 때만(공장값이거나 전에 통일한 값) 쓰세요. 다르면 “하나씩 따로”를 쓰세요. 틀린 현재 값은 그 PIN의 남은 시도를 1회 줄입니다.";
/// W12: a new PIN / PUK / admin PIN that is a factory value (spec/10 §9.3).
pub const T_CARD_NEW_FACTORY: &str = "공장 기본값(123456·12345678)은 새 PIN으로 쓸 수 없습니다 — YubiKey를 가진 사람이 그 값으로 바로 서명할 수 있습니다. 다른 값을 고르세요.";
/// W07 help of a Solana key (spec/04 §2.18).
pub const T_SOL_KEY_INPUT: &str = "Phantom·Solflare의 '개인키 내보내기'로 받은 base58 문자열(64바이트 keypair) 또는 solana-keygen JSON 파일의 내용([숫자 64개])을 붙여넣으세요. 주소(32바이트)는 개인키가 아닙니다.";
/// W07 help of a Zcash key (spec/12 §2.3).
pub const T_ZEC_KEY_INPUT: &str = "Zcash 개인키를 붙여넣으세요: 압축 WIF(K·L로 시작하면 mainnet, c로 시작하면 testnet — Zcash 탭의 네트워크와 같아야 함) 또는 16진수 64자리(지금 Zcash 탭의 네트워크로 씀). 일반(transparent) 주소 하나로 씁니다.";
/// W07 help of a Bitcoin key (spec/04 §2.18).
pub const T_BTC_KEY_INPUT: &str = "WIF 형식 개인키(5·K·L로 시작하면 mainnet, 9·c로 시작하면 testnet4)를 붙여넣으세요. 주소 형식은 앞 화면에서 고른 것으로 만듭니다.";
const VK_TAB: u16 = 0x09;
const VK_ESCAPE: u16 = 0x1B;
const VK_INSERT: u16 = 0x2D;
const VK_PROCESSKEY: u16 = 0xE5;

/// The ten secret windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretKind {
    /// W01 비밀번호 설정 (create/import).
    SetPassword,
    /// W02 잠금 해제.
    Unlock,
    /// W03 비밀번호 확인 (reveal, remove raw key, recover).
    ConfirmPassword,
    /// W04 비밀번호 변경.
    ChangePassword,
    /// W05 니모닉 입력.
    Mnemonic,
    /// W06 passphrase (`confirm` = import with a second field).
    Passphrase {
        /// Two fields.
        confirm: bool,
    },
    /// W07 개인키 가져오기 (`no_words`: the wallet has no recovery words — key-only wallet or
    /// "개인키로 시작하기").
    PrivateKey {
        /// Chain of the key (character set, length, help).
        chain: ImportChain,
        /// The T-IMPORTED-KEY variant without recovery words.
        no_words: bool,
    },
    /// W08 니모닉 표시 (`create` = first display with the 2 s acknowledgement).
    ShowMnemonic {
        /// Creation flow.
        create: bool,
    },
    /// W09 개인키 표시.
    ShowKey,
    /// W10 백업 확인 (positions 1-based).
    Backup {
        /// Word positions.
        positions: [u8; 4],
    },
    /// W11 `YubiKey` PIN (spec/10 §9.1): one masked ASCII field of `min..=max` characters
    /// (`OpenPGP` PW1 6–127, PIV 6–8), for one card operation; `touches` > 1 adds the
    /// "`YubiKey` 터치 N회가 필요합니다" line (one touch per Bitcoin or Zcash input, or per
    /// transaction of a Solana dApp request when `per_tx`).
    CardPin {
        /// Shortest PIN.
        min: u8,
        /// Longest PIN.
        max: u8,
        /// Card signatures (touches) the operation needs.
        touches: u8,
        /// One touch per transaction ("거래마다", a Solana dApp request), not per input.
        per_tx: bool,
        /// The card to connect (the first holding the key; 0 when unknown).
        serial: u32,
    },
    /// W12 `YubiKey` credentials of the enrolment wizard and the defaults change (spec/10 §7,
    /// §9.1, §9.3): the `OpenPGP` admin PIN, a PIV management key (48 hex digits), or a PIN /
    /// PUK change (current, new, new again). Same rules as W11: capture exclusion preferred,
    /// owner-drawn masked fields, no copy, ASCII, wiped after the one card operation.
    CardSecret(CardSecretKind),
}

/// What a W12 window asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardSecretKind {
    /// `OpenPGP` admin PIN (PW3, 8–127).
    AdminPin,
    /// The current PIV management key (48 hex digits, AES-192 / 3DES).
    ManagementKey,
    /// A PIN or PUK change: current, new, new again.
    ChangePin(crate::yubikey::PinTarget),
    /// The current PIV PIN (6–8): a PIN-protected management key at enrolment, or
    /// "PIV 관리 키 자동 보호".
    PivPin,
    /// "PIN 하나로 통일" (spec/10 §9.3): the one current value (empty = factory values, else 8
    /// characters), the new value (exactly 8) twice.
    SetPins,
    /// The optional ownership check of "`YubiKey` 연결하기" (spec/10 §7.6): the user PIN of
    /// `OpenPGP` (6–127) or, with `piv`, of PIV (6–8), verified once (no signature).
    UserPin {
        /// The PIV PIN instead of the `OpenPGP` PIN.
        piv: bool,
    },
}

impl CardSecretKind {
    /// Title.
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::AdminPin => "YubiKey 관리자 PIN",
            Self::ManagementKey => "YubiKey PIV 관리 키",
            Self::ChangePin(target) => target.change_title(),
            Self::PivPin => "YubiKey PIV PIN",
            Self::SetPins => "YubiKey PIN 하나로 통일",
            Self::UserPin { .. } => "YubiKey PIN 확인 (선택)",
        }
    }
}

impl SecretKind {
    /// `W01`…`W10` (logs).
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::SetPassword => "W01",
            Self::Unlock => "W02",
            Self::ConfirmPassword => "W03",
            Self::ChangePassword => "W04",
            Self::Mnemonic => "W05",
            Self::Passphrase { .. } => "W06",
            Self::PrivateKey { .. } => "W07",
            Self::ShowMnemonic { .. } => "W08",
            Self::ShowKey => "W09",
            Self::Backup { .. } => "W10",
            Self::CardPin { .. } => "W11",
            Self::CardSecret(_) => "W12",
        }
    }

    /// Display windows (W08, W09) use `CaptureExclusion::Required`.
    #[must_use]
    pub const fn is_display(self) -> bool {
        matches!(self, Self::ShowMnemonic { .. } | Self::ShowKey)
    }

    /// Display windows that end with the 2 s `다 적었습니다` hold instead of `닫기` (W08 of a new
    /// wallet): closing them is a cancel.
    #[must_use]
    pub const fn needs_hold(self) -> bool {
        matches!(self, Self::ShowMnemonic { create: true })
    }

    /// Plain-text windows mask their content on focus loss (W05, W07–W10).
    #[must_use]
    pub const fn plaintext(self) -> bool {
        matches!(
            self,
            Self::Mnemonic
                | Self::PrivateKey { .. }
                | Self::ShowMnemonic { .. }
                | Self::ShowKey
                | Self::Backup { .. }
        )
    }

    /// Paste allowed (W01–W07, W11, W12).
    #[must_use]
    pub const fn paste_allowed(self) -> bool {
        !matches!(
            self,
            Self::ShowMnemonic { .. } | Self::ShowKey | Self::Backup { .. }
        )
    }

    /// Window title (never secret).
    #[must_use]
    pub const fn title(self) -> &'static str {
        match self {
            Self::SetPassword => "비밀번호 정하기",
            Self::Unlock => "잠금 해제",
            Self::ConfirmPassword => "비밀번호 확인",
            Self::ChangePassword => "비밀번호 변경",
            Self::Mnemonic => "복구 단어 입력",
            Self::Passphrase { .. } => "passphrase 입력",
            Self::PrivateKey { .. } => "개인키 가져오기",
            Self::ShowMnemonic { .. } => "복구 단어 (니모닉)",
            Self::ShowKey => "개인키 보기",
            Self::Backup { .. } => "백업 확인",
            Self::CardPin { .. } => "YubiKey PIN",
            Self::CardSecret(what) => what.title(),
        }
    }

    /// Client size in DIP (spec/04 §1.7: 640×480, W08/W09 820×680).
    #[must_use]
    pub const fn size(self) -> (i32, i32) {
        match self {
            Self::ShowMnemonic { .. } | Self::ShowKey => (820, 680),
            Self::Mnemonic => (720, 600),
            // W07 also carries the T-IMPORTED-KEY backup warning.
            Self::Backup { .. }
            | Self::ChangePassword
            | Self::PrivateKey { .. }
            | Self::CardSecret(CardSecretKind::ChangePin(_) | CardSecretKind::SetPins) => {
                (640, 560)
            }
            _ => (640, 480),
        }
    }
}

/// What the app does after `create_window` for a secret window (spec/04 §4.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureDecision {
    /// Attach the secret state and show; `warning` = T-CAPTURE-WARN banner, `보기` disabled.
    Show {
        /// Exclusion not in effect.
        warning: bool,
    },
    /// Do not show the secret; wipe it and report E-SEC-001 on the main window.
    Refuse(ErrorCode),
}

/// Maps the creation result (`Ok(excluded)` or `Err` = `CaptureExclusionFailed`) to the app
/// decision. A `Required` (display) window can only come back excluded or as an error.
#[must_use]
pub const fn capture_decision(kind: SecretKind, created: Result<bool, ()>) -> CaptureDecision {
    match (kind.is_display(), created) {
        (_, Err(())) | (true, Ok(false)) => CaptureDecision::Refuse(ErrorCode::Sec001),
        (_, Ok(true)) => CaptureDecision::Show { warning: false },
        (false, Ok(false)) => CaptureDecision::Show { warning: true },
    }
}

/// The 2 s hold of W08's acknowledgement (archive `HoldGate`, pointer only).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HoldGate {
    started: Option<u64>,
}

impl HoldGate {
    /// Starts a hold (ignored while one is active).
    pub const fn begin(&mut self, now_ms: u64) {
        if self.started.is_none() {
            self.started = Some(now_ms);
        }
    }

    /// Cancels the hold (pointer left, released early, focus lost).
    pub const fn cancel(&mut self) {
        self.started = None;
    }

    /// Whether a hold is in progress.
    #[must_use]
    pub const fn active(self) -> bool {
        self.started.is_some()
    }

    /// Whether one continuous hold lasted 2 s.
    #[must_use]
    pub const fn complete(self, now_ms: u64) -> bool {
        match self.started {
            Some(started) => now_ms.saturating_sub(started) >= BACKUP_ACK_HOLD_MS,
            None => false,
        }
    }

    /// Milliseconds still needed.
    #[must_use]
    pub const fn remaining_ms(self, now_ms: u64) -> u64 {
        match self.started {
            Some(started) => BACKUP_ACK_HOLD_MS.saturating_sub(now_ms.saturating_sub(started)),
            None => BACKUP_ACK_HOLD_MS,
        }
    }
}

/// Values handed to the app on submit (moved out of the fields).
pub struct Submission {
    /// Field values in order.
    pub values: Vec<Zeroizing<Vec<u8>>>,
    /// Checkbox state (W05 passphrase).
    pub checkbox: bool,
}

impl core::fmt::Debug for Submission {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "Submission({} values, [REDACTED])",
            self.values.len()
        )
    }
}

/// What the app must do after an event.
#[derive(Debug)]
pub enum FormAction {
    /// Nothing visible changed.
    None,
    /// Repaint.
    Redraw,
    /// Primary button or Enter on the last field with valid input.
    Submit(Submission),
    /// Cancel / Esc / 나중에 (buffers already wiped).
    Cancel,
    /// Ctrl+V / Shift+Insert: read the clipboard and call [`SecretForm::apply_paste`].
    Paste,
    /// Ctrl+C or `복사` in W08/W09.
    Copy,
    /// W08 acknowledgement completed.
    HoldComplete,
    /// Close a display window (`닫기`).
    Close,
    /// Timed out (buffers wiped).
    TimedOut,
}

/// The secret shown by W08/W09.
pub struct DisplaySecret {
    /// Words joined by single spaces (W08) or 64 hex (W09).
    pub text: SecretString,
    /// EIP-55 account-0 address (W08).
    pub address: Option<String>,
    /// The wallet uses a BIP39 passphrase (W08 reveal note).
    pub passphrase_note: bool,
    /// `allowSecretCopy`.
    pub copy_allowed: bool,
}

impl core::fmt::Debug for DisplaySecret {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("DisplaySecret([REDACTED])")
    }
}

struct Slot {
    label: String,
    field: SecretField,
    min: usize,
    masked: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Button {
    Primary,
    Cancel,
    ClearAll,
    Copy,
    Reveal(usize),
    Checkbox,
}

#[derive(Debug, Default)]
struct Layout {
    fields: Vec<Rect>,
    buttons: Vec<(Button, Rect)>,
}

/// The state of one secret window.
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent flags of one window"
)]
pub struct SecretForm {
    kind: SecretKind,
    slots: Vec<Slot>,
    active: usize,
    checkbox: Option<(&'static str, bool)>,
    display: Option<DisplaySecret>,
    error: Option<String>,
    transient: Option<(String, u64)>,
    info: Option<String>,
    disabled_until: u64,
    busy: bool,
    revealing: Option<usize>,
    masked: bool,
    capture_excluded: bool,
    started_ms: u64,
    last_activity_ms: u64,
    hold: HoldGate,
    pressed: Option<Button>,
    layout: Layout,
    note: Option<String>,
    step: Option<SecretStep>,
    /// Extra non-secret lines under the intro (W11: the cards holding the key, the PIN tries).
    details: Vec<String>,
    /// W08 `create`: what the countdown line adds (where the words are seen again, or that
    /// they are wiped).
    timeout_note: Option<&'static str>,
    /// W08 `create`: the countdown seconds last drawn (a tick repaints when they change).
    countdown_secs: u64,
    /// W10: `확인`/Enter was pressed with a word not in the list — every field counts as left
    /// (red) until the next edit.
    backup_left: bool,
}

/// The flow a secret window belongs to and its step (the main window's step indicator, spec/04
/// §2.3–§2.4): the flow title, the step labels (three; five for the new `YubiKey` wallet) and
/// the current step (1-based).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecretStep {
    /// 새 지갑 만들기 / 기존 지갑 가져오기.
    pub flow: &'static str,
    /// The step labels.
    pub labels: &'static [&'static str],
    /// Current step, 1-based.
    pub current: usize,
}

/// W10's verdict on one typed word (2026-11-10, the public BIP39 list as W05 uses it): nothing,
/// a list word (grey), or a word that is not in the list (red; the field was left or no list word
/// starts with it). It says nothing about the paper: only the vault compares the four words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordMark {
    /// Empty, or still a beginning of some list word while typed.
    None,
    /// `목록에 있음`.
    Listed,
    /// `목록에 없는 단어`.
    Unlisted,
}

impl core::fmt::Debug for SecretForm {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "SecretForm({}, [REDACTED])", self.kind.id())
    }
}

fn slot(label: &str, charset: Charset, min: usize, max: usize, masked: bool) -> Option<Slot> {
    Some(Slot {
        label: label.to_owned(),
        field: SecretField::new(charset, max).ok()?,
        min,
        masked,
    })
}

#[expect(clippy::too_many_lines, reason = "one arm per window kind")]
fn slots_for(kind: SecretKind) -> Vec<Slot> {
    let slots = match kind {
        SecretKind::SetPassword => vec![
            slot("비밀번호", Charset::Printable, 12, 128, true),
            slot("비밀번호 확인", Charset::Printable, 12, 128, true),
        ],
        SecretKind::Unlock | SecretKind::ConfirmPassword => {
            vec![slot("비밀번호", Charset::Printable, 1, 128, true)]
        }
        SecretKind::ChangePassword => vec![
            slot("현재 비밀번호", Charset::Printable, 1, 128, true),
            slot("새 비밀번호", Charset::Printable, 12, 128, true),
            slot("새 비밀번호 확인", Charset::Printable, 12, 128, true),
        ],
        SecretKind::Mnemonic => vec![slot(
            "복구 단어",
            Charset::MnemonicText,
            1,
            MNEMONIC_TEXT_MAX,
            false,
        )],
        SecretKind::Passphrase { confirm: true } => vec![
            slot("passphrase", Charset::Printable, 1, 256, true),
            slot("passphrase 확인", Charset::Printable, 1, 256, true),
        ],
        SecretKind::Passphrase { confirm: false } => {
            vec![slot("passphrase", Charset::Printable, 1, 256, true)]
        }
        SecretKind::PrivateKey {
            chain: ImportChain::Evm,
            ..
        } => vec![slot(
            "개인키 (16진수 64자리)",
            Charset::PrivateKeyHex,
            64,
            66,
            false,
        )],
        SecretKind::PrivateKey {
            chain: ImportChain::Sol,
            ..
        } => vec![slot(
            "Solana 개인키 (base58 keypair 또는 JSON 배열)",
            Charset::KeyText,
            1,
            yw_core::keyimport::SOL_KEY_TEXT_MAX,
            false,
        )],
        SecretKind::PrivateKey {
            chain: ImportChain::Btc,
            ..
        } => vec![slot("Bitcoin 개인키 (WIF)", Charset::Base58, 51, 52, false)],
        SecretKind::PrivateKey {
            chain: ImportChain::Zec,
            ..
        } => vec![slot(
            "Zcash 개인키 (압축 WIF 또는 16진수 64자리)",
            Charset::KeyText,
            52,
            66,
            false,
        )],
        SecretKind::CardPin { min, max, .. } => vec![slot(
            "YubiKey PIN",
            Charset::Printable,
            usize::from(min),
            usize::from(max),
            true,
        )],
        SecretKind::CardSecret(CardSecretKind::AdminPin) => {
            vec![slot("OpenPGP 관리자 PIN", Charset::Printable, 8, 127, true)]
        }
        SecretKind::CardSecret(CardSecretKind::ManagementKey) => vec![slot(
            "PIV 관리 키 (16진수 48자리)",
            Charset::PrivateKeyHex,
            48,
            48,
            true,
        )],
        SecretKind::CardSecret(CardSecretKind::ChangePin(target)) => {
            let (min, max) = target.bounds();
            let (min, max) = (usize::from(min), usize::from(max));
            let name = target.name();
            vec![
                slot(&format!("현재 {name}"), Charset::Printable, min, max, true),
                slot(&format!("새 {name}"), Charset::Printable, min, max, true),
                slot(
                    &format!("새 {name} 확인"),
                    Charset::Printable,
                    min,
                    max,
                    true,
                ),
            ]
        }
        SecretKind::CardSecret(CardSecretKind::PivPin | CardSecretKind::UserPin { piv: true }) => {
            vec![slot("PIV PIN", Charset::Printable, 6, 8, true)]
        }
        SecretKind::CardSecret(CardSecretKind::UserPin { piv: false }) => {
            vec![slot("OpenPGP PIN", Charset::Printable, 6, 127, true)]
        }
        SecretKind::CardSecret(CardSecretKind::SetPins) => vec![
            slot(
                "현재 PIN (공장 기본값이면 비워 두기)",
                Charset::Printable,
                0,
                8,
                true,
            ),
            slot("새 PIN (8자)", Charset::Printable, 8, 8, true),
            slot("새 PIN 확인", Charset::Printable, 8, 8, true),
        ],
        SecretKind::Backup { positions } => positions
            .iter()
            .map(|position| {
                slot(
                    &format!("{position}번째 단어"),
                    Charset::BackupWord,
                    1,
                    8,
                    false,
                )
            })
            .collect(),
        SecretKind::ShowMnemonic { .. } | SecretKind::ShowKey => Vec::new(),
    };
    slots.into_iter().flatten().collect()
}

fn intro(kind: SecretKind, words: usize, address: bool) -> Vec<String> {
    let rule = "비밀번호는 영문·숫자·기호(ASCII) 12–128자입니다. 단어 4개 이상을 이은 긴 문장을 권장합니다. 잊으면 복구 단어(니모닉)로만 복구할 수 있습니다.";
    match kind {
        SecretKind::SetPassword => vec![rule.to_owned()],
        // Review L1 (2026-11-13: the DEK rotates, spec/02 §4.4): later contents are out of reach
        // of older copies, but those copies keep the old password and what they held (and a
        // weak old password can be cracked offline later).
        SecretKind::ChangePassword => vec![
            rule.to_owned(),
            "비밀번호를 바꾸면 암호화 키도 새로 만들어, 바꾼 뒤의 내용은 예전 사본으로 열 수 없습니다. 바꾸기 전에 만든 지갑 파일 사본(백업한 vault.ywv 등)은 예전 비밀번호로 계속 열리고 그때의 내용이 드러납니다(예전 비밀번호가 약했다면 나중에 오프라인으로 풀릴 수 있습니다)."
                .to_owned(),
        ],
        SecretKind::Unlock => vec!["지갑을 열려면 비밀번호를 입력하세요.".to_owned()],
        SecretKind::ConfirmPassword => {
            vec!["계속하려면 비밀번호를 다시 입력하세요.".to_owned()]
        }
        SecretKind::Mnemonic => vec![
            "다른 지갑에서 쓰던 영어 복구 단어(BIP39 니모닉) 12·15·18·21·24개를 순서대로 입력하세요. 공백 또는 Tab으로 다음 칸으로 넘어갑니다. 목록에 없는 단어는 빨간색으로 표시합니다.".to_owned(),
        ],
        SecretKind::Passphrase { confirm: true } => vec![
            "이전 지갑에서 쓰던 BIP39 passphrase를 두 번 입력하세요. ASCII만 지원합니다.".to_owned(),
        ],
        SecretKind::Passphrase { confirm: false } => {
            vec!["이 지갑의 BIP39 passphrase를 입력하세요.".to_owned()]
        }
        SecretKind::PrivateKey { chain, no_words } => vec![
            match chain {
                ImportChain::Evm => {
                    "가져올 EVM 개인키(16진수 64자리, 0x 선택)를 입력하세요.".to_owned()
                }
                ImportChain::Sol => T_SOL_KEY_INPUT.to_owned(),
                ImportChain::Btc => T_BTC_KEY_INPUT.to_owned(),
                ImportChain::Zec => T_ZEC_KEY_INPUT.to_owned(),
            },
            if no_words {
                T_KEY_ONLY_BACKUP.to_owned()
            } else {
                T_IMPORTED_KEY_BACKUP.to_owned()
            },
        ],
        // Without a known first address (an added phrase whose meta has none) only the words.
        SecretKind::ShowMnemonic { .. } => vec![format!(
            "아래 {words}단어{}를 순서대로 종이에 적으세요. 이 단어들이 지갑의 유일한 백업이며, 아는 사람은 누구든 자산을 옮길 수 있습니다. 이 창은 화면 캡처에서 제외됩니다.",
            if address { "와 첫 주소" } else { "" }
        )],
        SecretKind::ShowKey => vec![
            "개인키입니다. 다른 사람에게 보여주거나 사진·클라우드에 남기지 마세요. 이 창은 화면 캡처에서 제외됩니다.".to_owned(),
        ],
        SecretKind::Backup { positions } => vec![format!(
            "적은 종이를 보고 {}, {}, {}, {}번째 단어를 입력하세요.",
            positions[0], positions[1], positions[2], positions[3]
        )],
        SecretKind::CardSecret(CardSecretKind::AdminPin) => vec![T_CARD_ADMIN_PIN.to_owned()],
        SecretKind::CardSecret(CardSecretKind::ManagementKey) => {
            vec![T_CARD_MANAGEMENT_KEY.to_owned()]
        }
        SecretKind::CardSecret(CardSecretKind::ChangePin(target)) => vec![format!(
            "YubiKey를 하나만 연결하고 현재 {name}과(와) 새 {name}을(를) 입력하세요. {rule} 이 지갑은 PIN을 저장하지 않으니 새 {name}을(를) 따로 기억해 두세요.",
            name = target.name(),
            rule = target.rule()
        )],
        SecretKind::CardSecret(CardSecretKind::PivPin) => vec![T_CARD_PIV_PIN.to_owned()],
        SecretKind::CardSecret(CardSecretKind::SetPins) => vec![
            T_CARD_SET_PINS.to_owned(),
            T_CARD_SET_PINS_SAME.to_owned(),
        ],
        SecretKind::CardSecret(CardSecretKind::UserPin { .. }) => {
            vec![T_CARD_USER_PIN.to_owned()]
        }
        SecretKind::CardPin {
            touches,
            per_tx,
            serial,
            ..
        } => {
            let mut lines = vec![format!("{}. {T_CARD_PIN}", card_pin_steps(serial))];
            if touches > 1 {
                let (unit, topic) = if per_tx {
                    ("거래", "거래는")
                } else {
                    ("입력", "입력은")
                };
                lines.push(format!(
                    "YubiKey 터치 {touches}회가 필요합니다 ({unit}마다 한 번, 15초 유지 정책이면 첫 터치 뒤 15초 안의 {topic} 터치 없이 서명됩니다)."
                ));
            }
            lines
        }
    }
}

/// The two parts of W01/W04's status line for [`SecretForm::password_checks`]. A failed
/// condition names what is wrong, not the rule with a ✗ before it ("✗ 두 칸이 같음" read as
/// "being the same is wrong", 2026-11-12). The fields take only 0x20–0x7E and at most 128
/// characters, so the rule fails only by being short.
const fn password_status(
    rule: Option<bool>,
    same: Option<bool>,
) -> [(&'static str, yw_win::ui::Color); 2] {
    [
        match rule {
            Some(true) => ("✓ 12–128자", theme::SUCCESS_TEXT),
            Some(false) => ("✗ 12자 이상 필요", theme::DANGER_TEXT),
            None => ("· 12–128자", theme::MUTED),
        },
        match same {
            Some(true) => ("✓ 두 칸이 같음", theme::SUCCESS_TEXT),
            Some(false) => ("✗ 두 칸이 다름", theme::DANGER_TEXT),
            None => ("· 확인 칸에 한 번 더 입력", theme::MUTED),
        },
    ]
}

/// `true` when `count` is a valid BIP39 length.
#[must_use]
pub const fn valid_word_count(count: usize) -> bool {
    matches!(count, 12 | 15 | 18 | 21 | 24)
}

/// Draws the flow name, `n/{steps}단계` and the step dots of a secret window; returns the new y.
fn paint_steps(
    dc: &mut PaintDc<'_>,
    fonts: &Fonts,
    step: SecretStep,
    margin: i32,
    y: i32,
    width: i32,
    px: &dyn Fn(i32) -> i32,
) -> i32 {
    dc.select_font(&fonts.caption);
    dc.set_text_color(theme::MUTED);
    dc.draw_text(
        &wide(&format!(
            "{} · {}/{}단계",
            step.flow,
            step.current,
            step.labels.len()
        )),
        Rect::new(margin, y, width, px(18)),
        DrawFlags::LINE,
    );
    let top = y.saturating_add(px(22));
    let dot = px(20);
    let count = i32::try_from(step.labels.len()).unwrap_or(1).max(1);
    let column = width / count;
    // Five labels share the width: the caption font keeps each on its line.
    let small = step.labels.len() > 3;
    for (index, label) in step.labels.iter().enumerate() {
        let number = index.saturating_add(1);
        let x = margin.saturating_add(column.saturating_mul(i32::try_from(index).unwrap_or(0)));
        let reached = number <= step.current;
        dc.ellipse(
            Rect::new(x, top, dot, dot),
            if reached {
                theme::PRIMARY_BG
            } else {
                theme::CARD
            },
            if reached {
                theme::PRIMARY_BG
            } else {
                theme::BORDER
            },
        );
        dc.select_font(&fonts.caption);
        dc.set_text_color(if reached {
            theme::PRIMARY_TEXT
        } else {
            theme::MUTED
        });
        let mark = if number < step.current {
            "✓".to_owned()
        } else {
            number.to_string()
        };
        dc.draw_text(&wide(&mark), Rect::new(x, top, dot, dot), DrawFlags::CENTER);
        dc.select_font(if small {
            &fonts.caption
        } else if number == step.current {
            &fonts.body_bold
        } else {
            &fonts.body
        });
        dc.set_text_color(if reached { theme::TEXT } else { theme::MUTED });
        dc.draw_text(
            &wide(label),
            Rect::new(
                x.saturating_add(dot).saturating_add(px(8)),
                top,
                column.saturating_sub(dot).saturating_sub(px(12)),
                dot,
            ),
            DrawFlags::LINE,
        );
    }
    top.saturating_add(dot).saturating_add(px(14))
}

impl SecretForm {
    /// An input window (W01–W07, W10).
    #[must_use]
    pub fn new(kind: SecretKind, now_ms: u64, capture_excluded: bool) -> Self {
        Self {
            kind,
            slots: slots_for(kind),
            active: 0,
            checkbox: matches!(kind, SecretKind::Mnemonic).then_some(("BIP39 passphrase 사용", false)),
            display: None,
            error: None,
            transient: None,
            info: None,
            disabled_until: 0,
            busy: false,
            revealing: None,
            masked: false,
            capture_excluded,
            started_ms: now_ms,
            last_activity_ms: now_ms,
            hold: HoldGate::default(),
            pressed: None,
            layout: Layout::default(),
            step: None,
            details: Vec::new(),
            timeout_note: None,
            countdown_secs: 0,
            backup_left: false,
            note: matches!(kind, SecretKind::Mnemonic).then(|| {
                "이전 지갑에서 BIP39 passphrase(25번째 단어)를 썼을 때만 켜세요. ASCII만 지원합니다.".to_owned()
            }),
        }
    }

    /// A display window (W08/W09). Capture exclusion is required, so it is always excluded.
    #[must_use]
    pub fn display(kind: SecretKind, now_ms: u64, secret: DisplaySecret) -> Self {
        let mut form = Self::new(kind, now_ms, true);
        form.display = Some(secret);
        form
    }

    /// Shows the flow's step indicator above the title.
    pub const fn set_step(&mut self, step: Option<SecretStep>) {
        self.step = step;
    }

    /// W08 `create`: the note after the countdown (where the words can be seen again, or that
    /// they are wiped when the window closes).
    pub const fn set_timeout_note(&mut self, note: Option<&'static str>) {
        self.timeout_note = note;
    }

    /// W10: the list verdict of field `index` ([`WordMark`]).
    #[must_use]
    pub fn word_mark(&self, index: usize) -> WordMark {
        let Some(slot) = self.slots.get(index) else {
            return WordMark::None;
        };
        let Ok(word) = core::str::from_utf8(slot.field.as_bytes()) else {
            return WordMark::Unlisted;
        };
        if word.is_empty() {
            return WordMark::None;
        }
        if is_word(word) {
            return WordMark::Listed;
        }
        let left = self.backup_left || index != self.active;
        if left || !is_word_prefix(word) {
            WordMark::Unlisted
        } else {
            WordMark::None
        }
    }

    /// W10: the first field whose word is not in the list (its 1-based word position).
    fn unlisted_position(&self) -> Option<u8> {
        let SecretKind::Backup { positions } = self.kind else {
            return None;
        };
        (0..self.slots.len())
            .find(|index| self.word_mark(*index) == WordMark::Unlisted)
            .and_then(|index| positions.get(index).copied())
    }

    /// W01/W04 (2026-11-10): whether the new password meets the rule (`VaultPassword::new`, the
    /// same check as the vault's) and whether the two new fields are equal — each `None` (grey)
    /// while its field is empty. Never the value or its characters.
    fn password_checks(&self) -> Option<(Option<bool>, Option<bool>)> {
        let (new, again) = match self.kind {
            SecretKind::SetPassword => (0, 1),
            SecretKind::ChangePassword => (1, 2),
            _ => return None,
        };
        let first = self.slots.get(new)?;
        let second = self.slots.get(again)?;
        let rule =
            (!first.field.is_empty()).then(|| VaultPassword::new(&first.field.copy()).is_ok());
        let same =
            (!second.field.is_empty()).then(|| first.field.as_bytes() == second.field.as_bytes());
        Some((rule, same))
    }

    /// The lines between the content and the messages (2026-11-10): W01/W04's two password
    /// conditions, W10's word that is not in the list, W08's countdown on a first display.
    /// Returns the new y.
    #[expect(clippy::too_many_arguments, reason = "plain layout helpers")]
    fn paint_status(
        &self,
        dc: &mut PaintDc<'_>,
        fonts: &Fonts,
        margin: i32,
        mut y: i32,
        width: i32,
        px: impl Fn(i32) -> i32,
        now_ms: u64,
    ) -> i32 {
        dc.select_font(&fonts.body);
        if let Some((rule, same)) = self.password_checks() {
            let [(rule, rule_color), (same, same_color)] = password_status(rule, same);
            let mut x = margin;
            for (text, color) in [
                (rule, rule_color),
                (" · ", theme::MUTED),
                (same, same_color),
            ] {
                let units = wide(text);
                let (_, text_w) = dc.measure(&units, i32::MAX);
                dc.set_text_color(color);
                dc.draw_text(
                    &units,
                    Rect::new(x, y, text_w.saturating_add(px(2)), px(22)),
                    DrawFlags::LINE,
                );
                x = x.saturating_add(text_w);
            }
            y = y.saturating_add(px(26));
        }
        let mut lines: Vec<(String, yw_win::ui::Color)> = Vec::new();
        if let Some(position) = self.unlisted_position() {
            lines.push((
                format!(
                    "{position}번째 칸의 단어가 BIP39 단어 목록에 없습니다. 오타인지, 종이의 철자를 다시 보세요."
                ),
                theme::DANGER_TEXT,
            ));
        }
        if self.kind.needs_hold() && self.display.is_some() {
            let left = SECRET_WINDOW_TIMEOUT_MS
                .saturating_sub(now_ms.saturating_sub(self.started_ms))
                .div_ceil(1_000);
            let mut text = format!("{}:{:02} 남음 — 지나면 창이 닫힙니다", left / 60, left % 60);
            if let Some(note) = self.timeout_note {
                text.push(' ');
                text.push_str(note);
            }
            lines.push((text, theme::MUTED));
        }
        for (text, color) in lines {
            let units = wide(&text);
            dc.set_text_color(color);
            let height = dc.measure_wrapped(&units, width, DrawFlags::WRAP);
            dc.draw_text(&units, Rect::new(margin, y, width, height), DrawFlags::WRAP);
            y = y.saturating_add(height).saturating_add(px(4));
        }
        y
    }

    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.kind
    }

    /// Whether capture exclusion is in effect (`false` shows T-CAPTURE-WARN and disables `보기`).
    #[must_use]
    pub const fn capture_excluded(&self) -> bool {
        self.capture_excluded
    }

    /// Wipes every buffer and the displayed secret.
    pub fn wipe(&mut self) {
        for slot in &mut self.slots {
            slot.field.clear();
        }
        self.display = None;
        self.revealing = None;
        self.hold.cancel();
    }

    /// Shows an error line (fixed text).
    pub fn set_error(&mut self, message: Option<String>) {
        self.error = message;
    }

    /// Extra non-secret lines under the intro (W11 card serials and PIN tries).
    pub fn set_details(&mut self, lines: Vec<String>) {
        self.details = lines;
    }

    /// Shows an information line (T-PASTE-CLEARED, T-COPIED…).
    pub fn set_info(&mut self, message: Option<String>) {
        self.info = message;
    }

    /// Worker in progress: input and buttons disabled, status `확인 중…`.
    pub const fn set_busy(&mut self, busy: bool) {
        self.busy = busy;
    }

    /// Whether a worker result is awaited.
    #[must_use]
    pub const fn busy(&self) -> bool {
        self.busy
    }

    /// Wrong password (E-VLT-001): clear the fields and disable input for 1 s.
    pub fn fail_password(&mut self, now_ms: u64) {
        for slot in &mut self.slots {
            slot.field.clear();
        }
        self.active = 0;
        self.busy = false;
        self.disabled_until = now_ms.saturating_add(UNLOCK_FAIL_DISABLE_MS);
        self.error = Some(ErrorCode::Vlt001.text());
    }

    /// A new backup challenge (T-BACKUP-FAIL): new positions, empty fields.
    pub fn reset_backup(&mut self, positions: [u8; 4], message: Option<String>) {
        self.kind = SecretKind::Backup { positions };
        self.slots = slots_for(self.kind);
        self.active = 0;
        self.busy = false;
        self.backup_left = false;
        self.error = message;
    }

    fn input_enabled(&self, now_ms: u64) -> bool {
        !self.busy && now_ms >= self.disabled_until && self.display.is_none()
    }

    fn mnemonic_status(&self) -> (usize, Option<usize>, bool) {
        let Some(slot) = self.slots.first() else {
            return (0, None, false);
        };
        let words = mnemonic_words(&slot.field);
        let trailing_space = slot.field.as_bytes().last() == Some(&b' ');
        let completed = if trailing_space {
            words.len()
        } else {
            words.len().saturating_sub(1)
        };
        let first_unknown = words
            .iter()
            .take(completed)
            .position(|word| !core::str::from_utf8(word).is_ok_and(is_word));
        let all_known = words
            .iter()
            .all(|word| core::str::from_utf8(word).is_ok_and(is_word));
        (words.len(), first_unknown, all_known)
    }

    /// Whether the primary button is enabled.
    #[must_use]
    pub fn can_submit(&self, now_ms: u64) -> bool {
        if self.display.is_some() {
            return true;
        }
        if !self.input_enabled(now_ms) {
            return false;
        }
        if self.kind == SecretKind::Mnemonic {
            let (count, _, all_known) = self.mnemonic_status();
            return valid_word_count(count) && all_known && count <= 24;
        }
        // W01/W04: both conditions shown above the buttons (2026-11-10).
        if let Some((rule, same)) = self.password_checks()
            && !(rule == Some(true) && same == Some(true))
        {
            return false;
        }
        // W10: a word not in the list is a typo (or a misspelt paper), never sent (2026-11-10).
        if self.unlisted_position().is_some() {
            return false;
        }
        self.slots
            .iter()
            .all(|slot| slot.field.len() >= slot.min.min(1))
    }

    #[expect(clippy::too_many_lines, reason = "one arm per window kind")]
    fn validate(&self) -> Result<(), String> {
        let equal = |a: usize, b: usize| {
            self.slots.get(a).map(|slot| slot.field.as_bytes())
                == self.slots.get(b).map(|slot| slot.field.as_bytes())
        };
        // A new card secret that is a published factory value (spec/10 §9.3).
        let factory = |index: usize| {
            self.slots
                .get(index)
                .is_some_and(|slot| yw_core::yubikey::is_factory_secret(slot.field.as_bytes()))
        };
        let password_ok = |index: usize| {
            self.slots
                .get(index)
                .is_some_and(|slot| VaultPassword::new(&slot.field.copy()).is_ok())
        };
        match self.kind {
            SecretKind::SetPassword => {
                if !password_ok(0) {
                    return Err(ErrorCode::Inp001.text());
                }
                if !equal(0, 1) {
                    return Err(ErrorCode::Inp002.text());
                }
            }
            SecretKind::ChangePassword => {
                if !password_ok(1) {
                    return Err(ErrorCode::Inp001.text());
                }
                if !equal(1, 2) {
                    return Err(ErrorCode::Inp002.text());
                }
            }
            SecretKind::Passphrase { confirm: true } if !equal(0, 1) => {
                return Err(ErrorCode::Inp002.text());
            }
            SecretKind::PrivateKey {
                chain: ImportChain::Evm,
                ..
            } => {
                if let Some(slot) = self.slots.first() {
                    finalize_private_key(&slot.field).map_err(ErrorCode::text)?;
                }
            }
            SecretKind::PrivateKey {
                chain: ImportChain::Btc,
                ..
            } if self.slots.iter().any(|slot| slot.field.len() < slot.min) => {
                return Err(ErrorCode::Inp023.text());
            }
            SecretKind::Backup { .. }
                if self.slots.iter().any(|slot| slot.field.len() < slot.min) =>
            {
                return Err(ErrorCode::Inp013.text());
            }
            SecretKind::CardPin { min, max, .. }
                if self.slots.iter().any(|slot| {
                    !(usize::from(min)..=usize::from(max)).contains(&slot.field.len())
                }) =>
            {
                return Err(format!("PIN은 영문·숫자·기호(ASCII) {min}–{max}자입니다."));
            }
            SecretKind::CardSecret(CardSecretKind::AdminPin)
                if self
                    .slots
                    .iter()
                    .any(|slot| !(8..=127).contains(&slot.field.len())) =>
            {
                return Err("관리자 PIN은 영문·숫자·기호(ASCII) 8–127자입니다.".to_owned());
            }
            SecretKind::CardSecret(CardSecretKind::ManagementKey)
                if self.slots.iter().any(|slot| {
                    slot.field.len() != 48
                        || !slot.field.as_bytes().iter().all(u8::is_ascii_hexdigit)
                }) =>
            {
                return Err("관리 키는 16진수(0–9, a–f) 48자리입니다.".to_owned());
            }
            SecretKind::CardSecret(
                CardSecretKind::PivPin | CardSecretKind::UserPin { piv: true },
            ) if self
                .slots
                .iter()
                .any(|slot| !(6..=8).contains(&slot.field.len())) =>
            {
                return Err("PIV PIN은 영문·숫자·기호(ASCII) 6–8자입니다.".to_owned());
            }
            SecretKind::CardSecret(CardSecretKind::UserPin { piv: false })
                if self
                    .slots
                    .iter()
                    .any(|slot| !(6..=127).contains(&slot.field.len())) =>
            {
                return Err("OpenPGP PIN은 영문·숫자·기호(ASCII) 6–127자입니다.".to_owned());
            }
            SecretKind::CardSecret(CardSecretKind::SetPins) => {
                let current = self.slots.first().map_or(0, |slot| slot.field.len());
                if current != 0 && current != 8 {
                    return Err(
                        "현재 PIN은 비워 두거나(공장 기본값) 전에 통일한 8자를 넣으세요."
                            .to_owned(),
                    );
                }
                if self.slots.iter().skip(1).any(|slot| slot.field.len() != 8) {
                    return Err("새 PIN은 영문·숫자·기호(ASCII) 정확히 8자입니다.".to_owned());
                }
                if !equal(1, 2) {
                    return Err("새 PIN 두 칸이 서로 다릅니다.".to_owned());
                }
                if equal(0, 1) {
                    return Err("새 PIN이 현재 값과 같습니다.".to_owned());
                }
                if factory(1) {
                    return Err(T_CARD_NEW_FACTORY.to_owned());
                }
            }
            SecretKind::CardSecret(CardSecretKind::ChangePin(target)) => {
                let (min, max) = target.bounds();
                let range = usize::from(min)..=usize::from(max);
                if self
                    .slots
                    .iter()
                    .any(|slot| !range.contains(&slot.field.len()))
                {
                    return Err(format!("{}: {}", target.name(), target.rule()));
                }
                if !equal(1, 2) {
                    return Err(format!("새 {} 두 칸이 서로 다릅니다.", target.name()));
                }
                if equal(0, 1) {
                    return Err(format!("새 {}이(가) 현재 값과 같습니다.", target.name()));
                }
                if factory(1) {
                    return Err(T_CARD_NEW_FACTORY.to_owned());
                }
            }
            _ => {}
        }
        if self
            .slots
            .iter()
            .any(|slot| slot.field.len() < slot.min.min(1))
        {
            return Err(match self.kind {
                SecretKind::Passphrase { .. } => ErrorCode::Inp019.text(),
                _ => ErrorCode::Inp001.text(),
            });
        }
        Ok(())
    }

    fn submit(&mut self, now_ms: u64) -> FormAction {
        if self.display.is_some() {
            return if self.kind.needs_hold() {
                FormAction::None
            } else {
                FormAction::Close
            };
        }
        if !self.can_submit(now_ms) {
            if self.kind == SecretKind::Mnemonic {
                let (count, unknown, _) = self.mnemonic_status();
                self.error = Some(match unknown {
                    Some(position) => {
                        ErrorCode::Inp004.render(&position.saturating_add(1).to_string())
                    }
                    None if !valid_word_count(count) => ErrorCode::Inp003.text(),
                    None => ErrorCode::Inp005.text(),
                });
                return FormAction::Redraw;
            }
            if !self.input_enabled(now_ms) {
                return FormAction::None;
            }
            if matches!(
                self.kind,
                SecretKind::SetPassword | SecretKind::ChangePassword
            ) && let Err(message) = self.validate()
            {
                // Enter with a rule not met: the reason (E-INP-001/002), as before.
                self.error = Some(message);
                return FormAction::Redraw;
            }
            if matches!(self.kind, SecretKind::Backup { .. })
                && self.slots.iter().any(|slot| {
                    !slot.field.is_empty()
                        && !core::str::from_utf8(slot.field.as_bytes()).is_ok_and(is_word)
                })
            {
                // Every field counts as left: the status line names the word.
                self.backup_left = true;
                return FormAction::Redraw;
            }
            return FormAction::None;
        }
        if let Err(message) = self.validate() {
            self.error = Some(message);
            return FormAction::Redraw;
        }
        let mut values = Vec::with_capacity(self.slots.len());
        for slot in &mut self.slots {
            let mut value = slot.field.copy();
            if self.kind == SecretKind::Mnemonic && value.last() == Some(&b' ') {
                value.pop();
            }
            if matches!(
                self.kind,
                SecretKind::PrivateKey {
                    chain: ImportChain::Evm,
                    ..
                }
            ) {
                value = finalize_private_key(&slot.field).unwrap_or_default();
            }
            if matches!(
                self.kind,
                SecretKind::PrivateKey {
                    chain: ImportChain::Sol,
                    ..
                }
            ) && value.last() == Some(&b' ')
            {
                value.pop();
            }
            values.push(value);
            slot.field.clear();
        }
        self.error = None;
        FormAction::Submit(Submission {
            values,
            checkbox: self.checkbox.is_some_and(|(_, checked)| checked),
        })
    }

    fn cancel(&mut self) -> FormAction {
        self.wipe();
        FormAction::Cancel
    }

    fn touch(&mut self, now_ms: u64) {
        self.last_activity_ms = now_ms;
    }

    fn non_ascii(&mut self, now_ms: u64) -> FormAction {
        self.transient = Some((
            ErrorCode::Inp008.text(),
            now_ms.saturating_add(INPUT_ERROR_MS),
        ));
        FormAction::Redraw
    }

    /// `WM_CHAR`.
    pub fn on_char(&mut self, unit: u16, now_ms: u64) -> FormAction {
        self.touch(now_ms);
        if unit >= 0x80 {
            return self.non_ascii(now_ms);
        }
        if !self.input_enabled(now_ms) {
            return FormAction::None;
        }
        match unit {
            0x08 => {
                if let Some(slot) = self.slots.get_mut(self.active)
                    && slot.field.backspace()
                {
                    self.error = None;
                    self.backup_left = false;
                    return FormAction::Redraw;
                }
                FormAction::None
            }
            0x0D => {
                if self.active.saturating_add(1) < self.slots.len() {
                    self.active = self.active.saturating_add(1);
                    FormAction::Redraw
                } else {
                    self.submit(now_ms)
                }
            }
            0x20..=0x7E => {
                let Some(slot) = self.slots.get_mut(self.active) else {
                    return FormAction::None;
                };
                match slot.field.push_unit(unit) {
                    PushResult::Accepted => {
                        self.error = None;
                        self.backup_left = false;
                        FormAction::Redraw
                    }
                    PushResult::Rejected(RejectReason::NonAscii) => self.non_ascii(now_ms),
                    PushResult::Full | PushResult::Rejected(_) => FormAction::None,
                }
            }
            _ => FormAction::None,
        }
    }

    /// `WM_KEYDOWN` (modifier state from `input::is_down`).
    pub fn on_key(
        &mut self,
        vk: u16,
        ctrl: bool,
        shift: bool,
        alt: bool,
        now_ms: u64,
    ) -> FormAction {
        self.touch(now_ms);
        if vk == VK_PROCESSKEY {
            return self.non_ascii(now_ms);
        }
        if vk == VK_ESCAPE {
            // A submitted value's job (reveal, removal, `.prev` recovery, unlock) is running
            // and cannot be called back: Esc would only look like a cancel. The window closes
            // with the result (1–2 s).
            return if self.busy {
                FormAction::None
            } else {
                self.cancel()
            };
        }
        if alt {
            return FormAction::None;
        }
        if (ctrl && vk == u16::from(b'V')) || (shift && vk == VK_INSERT) {
            return if self.kind.paste_allowed() && self.input_enabled(now_ms) {
                FormAction::Paste
            } else {
                FormAction::None
            };
        }
        if ctrl && vk == u16::from(b'C') {
            return if self.kind.is_display() {
                FormAction::Copy
            } else {
                FormAction::None
            };
        }
        if vk == VK_TAB && !ctrl {
            if self.kind == SecretKind::Mnemonic {
                return self.on_char(0x20, now_ms);
            }
            let count = self.slots.len();
            if count > 0 {
                self.active = if shift {
                    self.active
                        .checked_sub(1)
                        .unwrap_or(count.saturating_sub(1))
                } else {
                    self.active.saturating_add(1) % count
                };
                return FormAction::Redraw;
            }
        }
        FormAction::None
    }

    fn hit(&self, x: i32, y: i32) -> Option<Button> {
        self.layout
            .buttons
            .iter()
            .find(|(_, rect)| rect.contains(x, y))
            .map(|(button, _)| *button)
    }

    fn button_enabled(&self, button: Button, now_ms: u64) -> bool {
        match button {
            Button::Primary => self.can_submit(now_ms) || self.display.is_some(),
            Button::Copy => self
                .display
                .as_ref()
                .is_some_and(|display| display.copy_allowed),
            Button::Reveal(_) => self.capture_excluded && self.input_enabled(now_ms),
            Button::ClearAll | Button::Checkbox => self.input_enabled(now_ms),
            // Not while a submitted job runs (see `on_key`'s Esc).
            Button::Cancel => !self.busy,
        }
    }

    /// `WM_LBUTTONDOWN`; returns the action and whether to capture the mouse.
    pub fn on_mouse_down(&mut self, x: i32, y: i32, now_ms: u64) -> (FormAction, bool) {
        self.touch(now_ms);
        self.masked = false;
        if let Some(index) = self
            .layout
            .fields
            .iter()
            .position(|rect| rect.contains(x, y))
        {
            self.active = index;
            return (FormAction::Redraw, false);
        }
        let Some(button) = self.hit(x, y) else {
            return (FormAction::Redraw, false);
        };
        if !self.button_enabled(button, now_ms) {
            return (FormAction::None, false);
        }
        self.pressed = Some(button);
        match button {
            Button::Primary if self.kind.needs_hold() => {
                self.hold.begin(now_ms);
                (FormAction::Redraw, true)
            }
            Button::Reveal(index) => {
                self.revealing = Some(index);
                (FormAction::Redraw, true)
            }
            _ => (FormAction::Redraw, true),
        }
    }

    /// `WM_MOUSEMOVE` while captured.
    pub fn on_mouse_move(&mut self, x: i32, y: i32) -> FormAction {
        let Some(pressed) = self.pressed else {
            return FormAction::None;
        };
        let inside = self
            .layout
            .buttons
            .iter()
            .any(|(button, rect)| *button == pressed && rect.contains(x, y));
        if !inside && (self.hold.active() || self.revealing.is_some()) {
            self.hold.cancel();
            self.revealing = None;
            return FormAction::Redraw;
        }
        FormAction::None
    }

    /// `WM_LBUTTONUP`.
    pub fn on_mouse_up(&mut self, x: i32, y: i32, now_ms: u64) -> FormAction {
        self.touch(now_ms);
        let pressed = self.pressed.take();
        self.revealing = None;
        if self.hold.active() {
            self.hold.cancel();
            return FormAction::Redraw;
        }
        let Some(pressed) = pressed else {
            return FormAction::None;
        };
        if self.hit(x, y) != Some(pressed) || !self.button_enabled(pressed, now_ms) {
            return FormAction::Redraw;
        }
        match pressed {
            Button::Primary => self.submit(now_ms),
            Button::Cancel => {
                if self.display.is_some() && !self.kind.needs_hold() {
                    self.wipe();
                    FormAction::Close
                } else {
                    self.cancel()
                }
            }
            Button::ClearAll => {
                for slot in &mut self.slots {
                    slot.field.clear();
                }
                self.active = 0;
                self.error = None;
                FormAction::Redraw
            }
            Button::Copy => FormAction::Copy,
            Button::Checkbox => {
                if let Some((_, checked)) = self.checkbox.as_mut() {
                    *checked = !*checked;
                }
                FormAction::Redraw
            }
            Button::Reveal(_) => FormAction::Redraw,
        }
    }

    /// Capture lost / cancel mode / focus lost: cancel holds and reveals.
    pub fn on_capture_lost(&mut self) -> FormAction {
        self.pressed = None;
        if self.hold.active() || self.revealing.is_some() {
            self.hold.cancel();
            self.revealing = None;
            return FormAction::Redraw;
        }
        FormAction::None
    }

    /// `WM_ACTIVATEAPP(0)` or focus to another window: mask plaintext windows, stop reveals.
    pub fn on_deactivate(&mut self) -> FormAction {
        self.hold.cancel();
        self.revealing = None;
        self.pressed = None;
        if self.kind.plaintext() {
            self.masked = true;
        }
        FormAction::Redraw
    }

    /// Re-activated: show the content again.
    pub const fn on_activate(&mut self) {
        self.masked = false;
    }

    /// Whether `보기` may reveal masked fields (never without capture exclusion).
    #[must_use]
    pub fn reveal_enabled(&self, now_ms: u64) -> bool {
        self.button_enabled(Button::Reveal(0), now_ms)
    }

    /// Whether the content is masked (T-MASKED).
    #[must_use]
    pub const fn masked(&self) -> bool {
        self.masked
    }

    /// Timer: hold completion, transient error expiry, window timeout.
    pub fn on_tick(&mut self, now_ms: u64) -> FormAction {
        if self.hold.complete(now_ms) {
            self.hold.cancel();
            self.pressed = None;
            return FormAction::HoldComplete;
        }
        let reference = if self.display.is_some() {
            self.started_ms
        } else {
            self.last_activity_ms
        };
        if now_ms.saturating_sub(reference) >= SECRET_WINDOW_TIMEOUT_MS {
            self.wipe();
            return FormAction::TimedOut;
        }
        let mut redraw = self.hold.active();
        // W08 `create`: its countdown changes every second.
        if self.kind.needs_hold() && self.display.is_some() {
            let secs = SECRET_WINDOW_TIMEOUT_MS
                .saturating_sub(now_ms.saturating_sub(self.started_ms))
                .div_ceil(1_000);
            if secs != self.countdown_secs {
                self.countdown_secs = secs;
                redraw = true;
            }
        }
        if self
            .transient
            .as_ref()
            .is_some_and(|(_, until)| now_ms >= *until)
        {
            self.transient = None;
            redraw = true;
        }
        if self.disabled_until != 0 && now_ms >= self.disabled_until {
            self.disabled_until = 0;
            redraw = true;
        }
        if redraw {
            FormAction::Redraw
        } else {
            FormAction::None
        }
    }

    /// Applies normalized clipboard text to the active field (all-or-nothing, E-INP-018).
    /// Returns `true` when a password/passphrase value (`Printable`, pasted exactly) starts or
    /// ends with a space, so the caller shows T-PASTE-EDGE-SPACE (spec/04 §4.7-3).
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Inp018`].
    pub fn apply_paste(&mut self, units: &[u16]) -> Result<bool, ErrorCode> {
        let slot = self.slots.get_mut(self.active).ok_or(ErrorCode::Inp018)?;
        let charset = slot.field.charset();
        let normalized = normalize_paste(units, charset, slot.field.limit())?;
        if !slot.field.replace_with(&normalized) {
            return Err(ErrorCode::Inp018);
        }
        self.error = None;
        Ok(charset == Charset::Printable && has_edge_space(&normalized))
    }

    /// The text to copy (W08: words joined by one space; W09: 64 hex) as UTF-16.
    #[must_use]
    pub fn copy_units(&self) -> Option<Zeroizing<Vec<u16>>> {
        let display = self.display.as_ref()?;
        let mut units = Zeroizing::new(Vec::with_capacity(display.text.expose().len()));
        units.extend(display.text.expose().encode_utf16());
        Some(units)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one linear paint pass for every window kind"
    )]
    fn layout_and_paint(
        &mut self,
        dc: &mut PaintDc<'_>,
        client: Rect,
        fonts: &Fonts,
        dpi: u32,
        now_ms: u64,
    ) {
        let px = |dip: i32| scale(dip, dpi);
        let margin = px(theme::SPACE_XL);
        let width = client
            .w
            .saturating_sub(margin.saturating_mul(2))
            .max(px(100));
        let mut y = px(theme::SPACE_L);
        let mut layout = Layout::default();
        dc.fill_rect(client, theme::BG);

        if !self.capture_excluded {
            let text = wide(
                "화면 캡처 제외가 적용되지 않았습니다. 화면 공유·녹화 중이면 입력하지 마세요.",
            );
            dc.select_font(&fonts.body_bold);
            let height = dc.measure_wrapped(&text, width.saturating_sub(px(20)), DrawFlags::WRAP);
            let banner = Rect::new(margin, y, width, height.saturating_add(px(20)));
            dc.round_rect(
                banner,
                px(theme::RADIUS_CONTROL),
                theme::DANGER_BG,
                theme::DANGER_ACCENT,
            );
            dc.set_text_color(theme::DANGER_TEXT);
            dc.draw_text(&text, banner.inset(px(10)), DrawFlags::WRAP);
            y = banner.bottom().saturating_add(px(12));
        }

        if let Some(step) = self.step {
            y = paint_steps(dc, fonts, step, margin, y, width, &px);
        }

        dc.select_font(&fonts.title);
        dc.set_text_color(theme::TEXT);
        let title = wide(self.kind.title());
        let title_h = dc.measure_wrapped(&title, width, DrawFlags::WRAP);
        dc.draw_text(
            &title,
            Rect::new(margin, y, width, title_h),
            DrawFlags::WRAP,
        );
        y = y.saturating_add(title_h).saturating_add(px(6));

        let words = self
            .display
            .as_ref()
            .map_or(24, |display| display.text.expose().split(' ').count());
        dc.select_font(&fonts.body);
        dc.set_text_color(theme::MUTED);
        let address = self
            .display
            .as_ref()
            .is_some_and(|display| display.address.is_some());
        for paragraph in intro(self.kind, words, address).iter().chain(&self.details) {
            let text = wide(paragraph);
            let height = dc.measure_wrapped(&text, width, DrawFlags::WRAP);
            dc.draw_text(&text, Rect::new(margin, y, width, height), DrawFlags::WRAP);
            y = y.saturating_add(height).saturating_add(px(8));
        }

        let buttons_h = px(36);
        let buttons_y = client
            .h
            .saturating_sub(px(theme::SPACE_L))
            .saturating_sub(buttons_h);
        // The content card between the header and the buttons.
        let card = Rect::new(
            margin,
            y.saturating_add(px(4)),
            width,
            buttons_y
                .saturating_sub(px(theme::SPACE_M))
                .saturating_sub(y.saturating_add(px(4)))
                .max(px(40)),
        );
        dc.round_rect(
            card,
            px(theme::RADIUS_CARD),
            theme::CARD,
            theme::CARD_BORDER,
        );
        let content_top = card.y;
        let inner_x = card.x.saturating_add(px(theme::SPACE_L));
        let inner_w = card.w.saturating_sub(px(theme::SPACE_L).saturating_mul(2));
        y = card.y.saturating_add(px(theme::SPACE_L));

        if let Some(display) = &self.display {
            y = self.paint_display(dc, display, fonts, inner_x, y, inner_w, px);
        } else if self.kind == SecretKind::Mnemonic {
            y = self.paint_mnemonic_grid(dc, fonts, inner_x, y, inner_w, px, &mut layout);
        } else {
            y = self.paint_fields(dc, fonts, inner_x, y, inner_w, px, &mut layout, now_ms);
        }

        if let Some((label, checked)) = self.checkbox {
            let box_rect = Rect::new(inner_x, y, px(18), px(18));
            dc.round_rect(
                box_rect,
                px(3),
                if checked { theme::FOCUS } else { theme::CARD },
                if checked { theme::FOCUS } else { theme::BORDER },
            );
            if checked {
                dc.select_font(&fonts.body_bold);
                dc.set_text_color(theme::PRIMARY_TEXT);
                dc.draw_text(&wide("✓"), box_rect, DrawFlags::CENTER);
            }
            dc.select_font(&fonts.body);
            dc.set_text_color(theme::TEXT);
            let label_rect = Rect::new(
                inner_x.saturating_add(px(26)),
                y.saturating_sub(px(2)),
                inner_w,
                px(22),
            );
            dc.draw_text(&wide(label), label_rect, DrawFlags::LINE);
            layout
                .buttons
                .push((Button::Checkbox, Rect::new(inner_x, y, inner_w / 2, px(20))));
            y = y.saturating_add(px(26));
            if checked && let Some(note) = &self.note {
                dc.set_text_color(theme::MUTED);
                dc.select_font(&fonts.caption);
                let text = wide(note);
                let height = dc.measure_wrapped(&text, inner_w, DrawFlags::WRAP);
                dc.draw_text(
                    &text,
                    Rect::new(inner_x, y, inner_w, height),
                    DrawFlags::WRAP,
                );
                y = y.saturating_add(height).saturating_add(px(6));
            }
        }

        y = self.paint_status(dc, fonts, inner_x, y, inner_w, px, now_ms);
        dc.select_font(&fonts.body);
        for (message, color) in [
            (self.error.as_deref(), theme::DANGER_TEXT),
            (
                self.transient.as_ref().map(|(text, _)| text.as_str()),
                theme::DANGER_TEXT,
            ),
            (self.info.as_deref(), theme::MUTED),
            (self.busy.then_some("확인 중…"), theme::MUTED),
        ] {
            if let Some(message) = message {
                let text = wide(message);
                dc.set_text_color(color);
                let height = dc.measure_wrapped(&text, inner_w, DrawFlags::WRAP);
                dc.draw_text(
                    &text,
                    Rect::new(inner_x, y, inner_w, height),
                    DrawFlags::WRAP,
                );
                y = y.saturating_add(height).saturating_add(px(4));
            }
        }

        self.paint_buttons(
            dc,
            fonts,
            client,
            margin,
            buttons_y,
            buttons_h,
            px,
            &mut layout,
            now_ms,
        );

        if self.masked {
            dc.round_rect(
                card,
                px(theme::RADIUS_CARD),
                theme::CARD,
                theme::CARD_BORDER,
            );
            dc.set_text_color(theme::MUTED);
            dc.select_font(&fonts.body);
            dc.draw_text(
                &wide("창이 비활성화되어 내용을 가렸습니다. 창을 클릭하면 다시 표시합니다."),
                card.inset(margin),
                DrawFlags::WRAP_CENTER,
            );
            layout.fields.clear();
            let _ = content_top;
        }
        self.layout = layout;
    }

    #[expect(clippy::too_many_arguments, reason = "plain layout helpers")]
    fn paint_display(
        &self,
        dc: &mut PaintDc<'_>,
        display: &DisplaySecret,
        fonts: &Fonts,
        margin: i32,
        mut y: i32,
        width: i32,
        px: impl Fn(i32) -> i32,
    ) -> i32 {
        dc.set_text_color(theme::TEXT);
        if matches!(self.kind, SecretKind::ShowKey) {
            dc.select_font(&fonts.mono_large);
            let text = display.text.expose();
            // A Solana keypair (up to 88 characters, no spaces) does not fit one line: paint it
            // in lines of 44 (the copied text is unchanged).
            let mut units = Zeroizing::new(Vec::with_capacity(text.len().saturating_add(2)));
            for (index, unit) in text.encode_utf16().enumerate() {
                if text.len() > 64 && index > 0 && index % 44 == 0 {
                    units.push(0x000A);
                }
                units.push(unit);
            }
            let box_rect = Rect::new(margin, y, width, px(80));
            dc.round_rect(box_rect, px(6), theme::BG, theme::CARD_BORDER);
            dc.draw_text(&units, box_rect.inset(px(12)), DrawFlags::WRAP);
            return box_rect.bottom().saturating_add(px(12));
        }
        let words: Vec<&str> = display.text.expose().split(' ').collect();
        let rows = words.len().div_ceil(3).max(1);
        let cell_h = px(32);
        let col_w = width / 3;
        let grid_h = cell_h.saturating_mul(i32::try_from(rows).unwrap_or(8));
        dc.round_rect(
            Rect::new(margin, y, width, grid_h.saturating_add(px(12))),
            px(6),
            theme::BG,
            theme::CARD_BORDER,
        );
        for (index, word) in words.iter().enumerate() {
            let column = index / rows;
            let row = index % rows;
            let cell = Rect::new(
                margin
                    .saturating_add(px(14))
                    .saturating_add(col_w.saturating_mul(i32::try_from(column).unwrap_or(0))),
                y.saturating_add(px(6))
                    .saturating_add(cell_h.saturating_mul(i32::try_from(row).unwrap_or(0))),
                col_w.saturating_sub(px(14)),
                cell_h,
            );
            dc.select_font(&fonts.mono);
            dc.set_text_color(theme::MUTED);
            let number = wide(&format!("{:>2}.", index.saturating_add(1)));
            dc.draw_text(
                &number,
                Rect::new(cell.x, cell.y, px(34), cell.h),
                DrawFlags::LINE,
            );
            dc.select_font(&fonts.mono_large);
            dc.set_text_color(theme::TEXT);
            let mut units = Zeroizing::new(Vec::with_capacity(16));
            units.extend(word.encode_utf16());
            dc.draw_text(
                &units,
                Rect::new(
                    cell.x.saturating_add(px(36)),
                    cell.y,
                    cell.w.saturating_sub(px(36)),
                    cell.h,
                ),
                DrawFlags::LINE,
            );
        }
        y = y.saturating_add(grid_h).saturating_add(px(24));
        if let Some(address) = &display.address {
            dc.select_font(&fonts.body_bold);
            dc.set_text_color(theme::TEXT);
            dc.draw_text(
                &wide("첫 주소 (계정 1) — 함께 적어 두면 복구할 때 맞는지 확인할 수 있습니다"),
                Rect::new(margin, y, width, px(22)),
                DrawFlags::LINE,
            );
            y = y.saturating_add(px(26));
            // Whole, its ends emphasized like every address (2026-11-12, spec/04 §3.3).
            let shown = yw_core::evm::address::parse_address(address)
                .map_or_else(|_| address.clone(), yw_core::evm::Address::to_checksum);
            let rect = Rect::new(margin, y, width, px(26));
            let spans = crate::ui::theme::own_address_spans(
                &shown,
                crate::ui::theme::AddressKind::Evm,
                false,
            );
            if !crate::ui::theme::paint_spans(dc, fonts, &spans, rect, theme::TEXT, theme::FOCUS) {
                dc.select_font(&fonts.mono_large);
                dc.draw_text(&wide(&shown), rect, DrawFlags::LINE);
            }
            y = y.saturating_add(px(34));
        }
        if display.passphrase_note {
            dc.select_font(&fonts.body);
            dc.set_text_color(theme::WARN_TEXT);
            let text = wide(
                "이 지갑은 passphrase를 사용합니다. passphrase는 저장되지 않으므로 따로 보관해야 합니다.",
            );
            let height = dc.measure_wrapped(&text, width, DrawFlags::WRAP);
            dc.draw_text(&text, Rect::new(margin, y, width, height), DrawFlags::WRAP);
            y = y.saturating_add(height).saturating_add(px(6));
        }
        y
    }

    #[expect(clippy::too_many_arguments, reason = "plain layout helpers")]
    fn paint_mnemonic_grid(
        &self,
        dc: &mut PaintDc<'_>,
        fonts: &Fonts,
        margin: i32,
        y: i32,
        width: i32,
        px: impl Fn(i32) -> i32,
        layout: &mut Layout,
    ) -> i32 {
        let Some(slot) = self.slots.first() else {
            return y;
        };
        let words = mnemonic_words(&slot.field);
        let trailing_space = slot.field.as_bytes().last() == Some(&b' ');
        let typing = if trailing_space || words.is_empty() {
            words.len()
        } else {
            words.len().saturating_sub(1)
        };
        let rows = 8_usize;
        let cell_h = px(30);
        let col_w = width / 3;
        let grid = Rect::new(
            margin,
            y,
            width,
            cell_h.saturating_mul(8).saturating_add(px(12)),
        );
        dc.round_rect(grid, px(6), theme::CARD, theme::FOCUS);
        layout.fields.push(grid);
        dc.select_font(&fonts.mono);
        for index in 0..24_usize {
            let column = index / rows;
            let row = index % rows;
            let cell = Rect::new(
                margin
                    .saturating_add(px(10))
                    .saturating_add(col_w.saturating_mul(i32::try_from(column).unwrap_or(0))),
                y.saturating_add(px(6))
                    .saturating_add(cell_h.saturating_mul(i32::try_from(row).unwrap_or(0))),
                col_w.saturating_sub(px(16)),
                cell_h.saturating_sub(px(4)),
            );
            if index == typing && index < 24 {
                dc.round_rect(cell, px(4), theme::INFO_BG, theme::FOCUS);
            }
            let word = words.get(index).copied().unwrap_or(&[]);
            let unknown = index < typing && !core::str::from_utf8(word).is_ok_and(is_word);
            dc.set_text_color(if unknown {
                theme::DANGER_TEXT
            } else {
                theme::TEXT
            });
            let mut units = Zeroizing::new(Vec::with_capacity(16));
            units.extend(format!("{:>2}. ", index.saturating_add(1)).encode_utf16());
            units.extend(word.iter().map(|byte| u16::from(*byte)));
            dc.draw_text(&units, cell.inset(px(2)), DrawFlags::LINE);
        }
        let mut y = grid.bottom().saturating_add(px(6));
        dc.select_font(&fonts.body);
        dc.set_text_color(theme::MUTED);
        let (count, _, _) = self.mnemonic_status();
        dc.draw_text(
            &wide(&format!(
                "{count}단어 입력 · {}/{}",
                slot.field.len(),
                slot.field.limit()
            )),
            Rect::new(margin, y, width, px(20)),
            DrawFlags::LINE,
        );
        y = y.saturating_add(px(26));
        y
    }

    #[expect(clippy::too_many_arguments, reason = "plain layout helpers")]
    fn paint_fields(
        &self,
        dc: &mut PaintDc<'_>,
        fonts: &Fonts,
        margin: i32,
        mut y: i32,
        width: i32,
        px: impl Fn(i32) -> i32,
        layout: &mut Layout,
        now_ms: u64,
    ) -> i32 {
        let enabled = self.input_enabled(now_ms);
        for (index, slot) in self.slots.iter().enumerate() {
            dc.select_font(&fonts.body_bold);
            dc.set_text_color(theme::TEXT);
            dc.draw_text(
                &wide(&slot.label),
                Rect::new(margin, y, width, px(22)),
                DrawFlags::LINE,
            );
            dc.select_font(&fonts.caption);
            // W10: the list verdict instead of the length (2026-11-10); other fields their length.
            let (right, color) = if matches!(self.kind, SecretKind::Backup { .. }) {
                match self.word_mark(index) {
                    WordMark::None => (String::new(), theme::MUTED),
                    WordMark::Listed => ("목록에 있음".to_owned(), theme::MUTED),
                    WordMark::Unlisted => ("목록에 없는 단어".to_owned(), theme::DANGER_TEXT),
                }
            } else {
                (
                    format!("{}/{}", slot.field.len(), slot.field.limit()),
                    theme::MUTED,
                )
            };
            dc.set_text_color(color);
            dc.draw_text(
                &wide(&right),
                Rect::new(margin, y, width, px(22)),
                DrawFlags::RIGHT,
            );
            y = y.saturating_add(px(24));
            let reveal_w = if slot.masked { px(64) } else { 0 };
            let box_w = width
                .saturating_sub(reveal_w)
                .saturating_sub(if slot.masked { px(8) } else { 0 });
            let box_rect = Rect::new(margin, y, box_w, px(36));
            let focused = index == self.active;
            dc.round_rect(
                box_rect,
                px(4),
                if enabled {
                    theme::CARD
                } else {
                    theme::DISABLED_BG
                },
                if focused { theme::FOCUS } else { theme::BORDER },
            );
            if focused {
                dc.round_rect(box_rect.inset(1), px(3), theme::CARD, theme::FOCUS);
            }
            let show_plain = !slot.masked || self.revealing == Some(index);
            let units = slot.field.render_utf16(!show_plain);
            dc.select_font(if slot.masked && !show_plain {
                &fonts.body
            } else {
                &fonts.mono
            });
            dc.set_text_color(theme::TEXT);
            dc.draw_text(&units, box_rect.inset(px(9)), DrawFlags::LINE);
            layout.fields.push(box_rect);
            if slot.masked {
                let reveal = Rect::new(box_rect.right().saturating_add(px(8)), y, reveal_w, px(36));
                let reveal_enabled = self.capture_excluded && enabled;
                dc.round_rect(
                    reveal,
                    px(theme::RADIUS_CONTROL),
                    if reveal_enabled {
                        theme::CARD
                    } else {
                        theme::DISABLED_BG
                    },
                    if reveal_enabled {
                        theme::BORDER
                    } else {
                        theme::CARD_BORDER
                    },
                );
                dc.select_font(&fonts.body);
                dc.set_text_color(if reveal_enabled {
                    theme::TEXT
                } else {
                    theme::DISABLED_TEXT
                });
                dc.draw_text(&wide("보기"), reveal, DrawFlags::CENTER);
                layout.buttons.push((Button::Reveal(index), reveal));
            }
            y = y.saturating_add(px(48));
        }
        y
    }

    #[expect(clippy::too_many_arguments, reason = "plain layout helpers")]
    fn paint_buttons(
        &self,
        dc: &mut PaintDc<'_>,
        fonts: &Fonts,
        client: Rect,
        margin: i32,
        y: i32,
        height: i32,
        px: impl Fn(i32) -> i32,
        layout: &mut Layout,
        now_ms: u64,
    ) {
        let primary_label = match self.kind {
            SecretKind::ShowMnemonic { create: true } => {
                if self.hold.active() {
                    format!(
                        "다 적었습니다 ({:.1}초)",
                        f64::from(u32::try_from(self.hold.remaining_ms(now_ms)).unwrap_or(0))
                            / 1_000.0
                    )
                } else {
                    "다 적었습니다 (2초 길게 누르기)".to_owned()
                }
            }
            SecretKind::ShowMnemonic { create: false } | SecretKind::ShowKey => "닫기".to_owned(),
            SecretKind::Unlock => "잠금 해제".to_owned(),
            SecretKind::ChangePassword => "변경".to_owned(),
            SecretKind::Mnemonic | SecretKind::SetPassword => "다음".to_owned(),
            SecretKind::PrivateKey { .. } => "가져오기".to_owned(),
            _ => "확인".to_owned(),
        };
        let mut right: Vec<(Button, String)> = vec![(Button::Primary, primary_label)];
        if self.display.is_none() {
            right.insert(
                0,
                (
                    Button::Cancel,
                    if self.kind == SecretKind::Unlock {
                        "나중에"
                    } else {
                        "취소"
                    }
                    .to_owned(),
                ),
            );
        }
        let mut left: Vec<(Button, String)> = Vec::new();
        if self.display.is_none() {
            left.push((Button::ClearAll, "모두 지우기".to_owned()));
        } else if self
            .display
            .as_ref()
            .is_some_and(|display| display.copy_allowed)
        {
            left.push((Button::Copy, "복사".to_owned()));
        }
        dc.select_font(&fonts.body);
        let mut x = client.w.saturating_sub(margin);
        for (button, label) in right.iter().rev() {
            let text = wide(label);
            let (_, text_w) = dc.measure(&text, i32::MAX);
            let w = text_w.saturating_add(px(36)).max(px(96));
            x = x.saturating_sub(w);
            let rect = Rect::new(x, y, w, height);
            self.paint_button(
                dc,
                rect,
                &text,
                *button,
                now_ms,
                px(4),
                px(theme::RADIUS_CONTROL),
            );
            layout.buttons.push((*button, rect));
            x = x.saturating_sub(px(8));
        }
        let mut x = margin;
        for (button, label) in &left {
            let text = wide(label);
            let (_, text_w) = dc.measure(&text, i32::MAX);
            let w = text_w.saturating_add(px(36)).max(px(96));
            let rect = Rect::new(x, y, w, height);
            self.paint_button(
                dc,
                rect,
                &text,
                *button,
                now_ms,
                px(4),
                px(theme::RADIUS_CONTROL),
            );
            layout.buttons.push((*button, rect));
            x = x.saturating_add(w).saturating_add(px(8));
        }
    }

    #[expect(clippy::too_many_arguments, reason = "plain paint helper")]
    fn paint_button(
        &self,
        dc: &mut PaintDc<'_>,
        rect: Rect,
        text: &[u16],
        button: Button,
        now_ms: u64,
        bar: i32,
        radius: i32,
    ) {
        let enabled = self.button_enabled(button, now_ms);
        let primary = button == Button::Primary;
        let (fill, border) = match (enabled, primary) {
            (false, true) => (
                theme::BUTTON_PRIMARY.disabled_fill,
                theme::BUTTON_PRIMARY.disabled_border,
            ),
            (false, false) => (theme::DISABLED_BG, theme::CARD_BORDER),
            (true, true) => (theme::PRIMARY_BG, theme::PRIMARY_BG),
            (true, false) => (theme::CARD, theme::BUTTON_SECONDARY.border),
        };
        dc.round_rect(rect, radius, fill, border);
        if primary && self.hold.active() {
            let done = BACKUP_ACK_HOLD_MS.saturating_sub(self.hold.remaining_ms(now_ms));
            let filled = i64::from(rect.w).saturating_mul(i64::try_from(done).unwrap_or(0)) / 2_000;
            let bar_rect = Rect::new(
                rect.x,
                rect.bottom().saturating_sub(bar),
                i32::try_from(filled).unwrap_or(0),
                bar,
            );
            dc.fill_rect(bar_rect, theme::WARN_ACCENT);
        }
        dc.set_text_color(match (enabled, primary) {
            (false, true) => theme::CARD,
            (false, false) => theme::DISABLED_TEXT,
            (true, true) => theme::PRIMARY_TEXT,
            (true, false) => theme::TEXT,
        });
        dc.draw_text(text, rect, DrawFlags::CENTER);
    }

    /// Paints the window and caches the layout used for hit-testing.
    pub fn paint(
        &mut self,
        dc: &mut PaintDc<'_>,
        client: Rect,
        fonts: &Fonts,
        dpi: u32,
        now_ms: u64,
    ) {
        self.layout_and_paint(dc, client, fonts, dpi, now_ms);
    }
}

#[cfg(test)]
mod tests;
