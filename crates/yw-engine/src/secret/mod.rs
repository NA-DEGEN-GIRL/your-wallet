//! The secret windows W01–W12 as the wallet logic sees them (spec/04 §4, D11; spec/15 §11.4 S4):
//! the window kinds, the flow step a window belongs to, what the logic asks the shell to do with
//! a secret window ([`SecretEffect`]) and the windows' fixed texts ([`text`]). Never a secret: the
//! input buffers and a displayed secret stay in the shell's window form (Windows: yw-app
//! `ui::secret::SecretForm`), and a submission reaches the logic in-process, never as a `Cmd`.
//!
//! 2026-11-20 (spec/15 §11.4 S4 P7a1, critique B-7): created. [`SecretKind`], [`CardSecretKind`]
//! and [`SecretStep`] moved from yw-app `ui::secret` unchanged except that the window size in DIP
//! stayed with the window (yw-app `ui::secret::window_size`); the catalogue [`text`] moved from
//! yw-app `ui::secret_text` (wording unchanged). [`SecretEffect`] is new: an input window's open
//! (answered with `Cmd::SecretOpened`, whose `OpenOutcome` is the approval window's
//! `approval::flow::OpenOutcome`) and a secret window's close. The purpose of a window (yw-app
//! `app::Purpose`) and the session that holds it (yw-app `secret_session::SecretSession`) stay in
//! yw-app until the wallet state moves (S4d); the display windows' open and the form operations
//! become effects in S4 P7b.
//!
//! 2026-11-20 (spec/15 §11.4 S4 P7b): [`SecretEffect::OpenDisplay`] (W08/W09; the secret is not
//! in it — the shell gets it from the wallet's session only after it verified the new window's
//! capture exclusion), [`SecretEffect::Form`] with [`SecretFormOp`] (what the handlers wrote into
//! the open window's form themselves before, yw-app `App::with_form`) and
//! [`SecretEffect::ClearClip`] (the lock's and the exit's clear of a pending secret copy, at the
//! lock's step 4, spec/04 §5.3).
//!
//! 2026-11-22 (spec/15 §11.4 S4d E0a): [`HoldGate`] with [`BACKUP_ACK_HOLD_MS`] (W08's and S22's
//! 2 s hold), [`DisplaySecret`] (the W08/W09 secret's container; it holds a secret, so it is never
//! in an effect, and its `Debug` prints `[REDACTED]`) and [`backup_retry_text`] (T-BACKUP-FAIL)
//! moved from yw-app `ui::secret` and `ui::screens` unchanged, so the wallet code names no shell
//! module for them. The window's form (`SecretForm`) and the submission stay in yw-app.

use core::fmt;

use yw_core::keyimport::ImportChain;
use yw_core::lang::Lang;
use yw_core::secret::SecretString;

use crate::yubikey::PinTarget;

pub mod text;

/// A PIN target's W12 title (`PinTarget::change_title` in `lang`).
const fn target_title(target: PinTarget, lang: Lang) -> &'static str {
    match target {
        PinTarget::OpenPgpUser => text::TITLE_CHANGE_OPENPGP_PIN.get(lang),
        PinTarget::OpenPgpAdmin => text::TITLE_CHANGE_ADMIN_PIN.get(lang),
        PinTarget::PivPin => text::TITLE_CHANGE_PIV_PIN.get(lang),
        PinTarget::PivPuk => text::TITLE_CHANGE_PIV_PUK.get(lang),
    }
}

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
    ChangePin(PinTarget),
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
    pub const fn title(self, lang: Lang) -> &'static str {
        match self {
            Self::AdminPin => text::TITLE_ADMIN_PIN.get(lang),
            Self::ManagementKey => text::TITLE_MANAGEMENT_KEY.get(lang),
            Self::ChangePin(target) => target_title(target, lang),
            Self::PivPin => "YubiKey PIV PIN",
            Self::SetPins => text::TITLE_SET_PINS.get(lang),
            Self::UserPin { .. } => text::TITLE_USER_PIN.get(lang),
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
    pub const fn title(self, lang: Lang) -> &'static str {
        match self {
            Self::SetPassword => text::TITLE_SET_PASSWORD.get(lang),
            Self::Unlock => text::UNLOCK.get(lang),
            Self::ConfirmPassword => text::TITLE_CONFIRM_PASSWORD.get(lang),
            Self::ChangePassword => text::TITLE_CHANGE_PASSWORD.get(lang),
            Self::Mnemonic => text::TITLE_MNEMONIC.get(lang),
            Self::Passphrase { .. } => text::TITLE_PASSPHRASE.get(lang),
            Self::PrivateKey { .. } => text::TITLE_PRIVATE_KEY.get(lang),
            Self::ShowMnemonic { .. } => text::TITLE_SHOW_MNEMONIC.get(lang),
            Self::ShowKey => text::TITLE_SHOW_KEY.get(lang),
            Self::Backup { .. } => text::TITLE_BACKUP.get(lang),
            Self::CardPin { .. } => "YubiKey PIN",
            Self::CardSecret(what) => what.title(lang),
        }
    }
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

/// What the logic asks the shell to do with a secret window (2026-11-20, S4 P7a1; inside
/// `Effect::Secret`). Ids, kinds, flags and fixed non-secret texts only, never secret text: a
/// window's buffers are filled by the person typing into the shell's form, a displayed secret
/// moves from the wallet's session into a verified window (never through an effect), and nothing
/// in here is a value. 2026-11-20 (S4 P7b): no longer `Copy` ([`SecretFormOp`] carries texts).
#[derive(Clone, PartialEq, Eq)]
pub enum SecretEffect {
    /// Open the input window of secret session `serial` (W01–W07, W10–W12; one window at a time:
    /// the logic closed the previous one first). The shell creates it, checks its capture
    /// exclusion (spec/04 §4.5: `Preferred` — not excluded opens with T-CAPTURE-WARN and `보기`
    /// off), shows it and focuses it, and answers with `Cmd::SecretOpened { serial, outcome }`:
    /// `Shown { capture_excluded }`, `Refused(E-SEC-001)` (the platform refused the window) or
    /// `Failed(E-APP-009)` (it could not be created). A `serial` that is no longer the logic's
    /// open session makes nothing (answered `Refused`, which the logic ignores).
    OpenInput {
        /// The secret session the window is for (a fresh serial per open, never reused).
        serial: u64,
        /// Which window.
        kind: SecretKind,
        /// The flow step the window shows (`None`: none).
        step: Option<SecretStep>,
        /// Above every window (W11 and the dApp's W02).
        topmost: bool,
        /// The language the window draws its texts in (the app language when asked).
        lang: Lang,
    },
    /// Close the window of secret session `serial` and wipe its buffers (spec/04 §4.9); nothing
    /// when that window is not open (a stale serial, a window never made). Not answered.
    Close {
        /// The secret session whose window closes.
        serial: u64,
    },
    /// Open the display window of secret session `serial` (W08/W09, 2026-11-20 S4 P7b; one
    /// window at a time: the logic closed the previous one first). The shell creates it, checks
    /// its capture exclusion (spec/04 §4.5: `Required`) and only then takes the secret from the
    /// session (Windows: `Wallet::take_display_secret`), fills the form and shows it; on any other
    /// result it keeps no window and the session's secret is wiped. Answered with
    /// `Cmd::SecretOpened { serial, outcome }`: `Shown { capture_excluded: true }`,
    /// `Refused(E-SEC-001)` (not excluded, or refused by the platform) or `Failed(E-APP-009)`. A
    /// `serial` that is no longer the logic's open, unshown session makes nothing (answered
    /// `Refused`, which the logic ignores).
    OpenDisplay {
        /// The secret session the window is for.
        serial: u64,
        /// W08 or W09.
        kind: SecretKind,
        /// The flow step the window shows (`None`: none).
        step: Option<SecretStep>,
        /// W08's note after its countdown (a fixed catalogue text; `None`: none). 2026-11-20 (P7b
        /// review, spec/15 §11.4 S4): the logic picks the text, where plan §3.6 sketched a flag
        /// the shell resolves; like `step`'s texts (also in `OpenInput`) it becomes a catalogue
        /// key before an `Effect` has to round-trip through the yw-json codec or the Android
        /// shell (S4d E2).
        timeout_note: Option<&'static str>,
        /// The language the window draws its texts in.
        lang: Lang,
    },
    /// Change the form of the window of secret session `serial` and repaint it (2026-11-20, S4
    /// P7b; was `App::with_form` in the handlers); nothing when that window is not open. Not
    /// answered.
    Form {
        /// The secret session whose window changes.
        serial: u64,
        /// What changes.
        op: SecretFormOp,
    },
    /// Clear a pending secret copy now (2026-11-20, S4 P7b: the lock's step 4, spec/04 §5.3,
    /// §4.8; `App::lock` called `App::clear_secret_clip`/`clear_secret_clip_at_exit` itself
    /// before). The clipboard and the pending copy are the shell's; nothing when none is pending.
    /// Not answered.
    ClearClip {
        /// The app is shutting down: a busy clipboard is retried for a short while now, since no
        /// later tick comes (else the main tick keeps retrying).
        at_exit: bool,
    },
}

/// One change to an open secret window's form (2026-11-20, S4 P7b; inside
/// [`SecretEffect::Form`]): what the handlers did to the form directly before (yw-app
/// `App::with_form`). The texts are fixed catalogue texts, error texts and non-secret card lines
/// (the `YubiKey`'s name and serial, PIN tries), never a secret; `Debug` prints names and lengths
/// only.
#[derive(Clone, PartialEq, Eq)]
pub enum SecretFormOp {
    /// A worker result is awaited (`true`: input and buttons disabled, `확인 중…`) or arrived.
    Busy(bool),
    /// The error line (`None`: none).
    Error(Option<String>),
    /// The non-secret lines under the intro (W11/W12: the card, its PIN tries).
    Details(Vec<String>),
    /// W11: the card its first step names (`None`: none).
    Card(Option<String>),
    /// The information line (`None`: none).
    Info(Option<String>),
    /// A wrong password (E-VLT-001): the fields cleared and input disabled for 1 s from `now_ms`
    /// (the logic's clock, read where the handler read it before).
    FailPassword {
        /// When the password was refused.
        now_ms: u64,
    },
    /// W10: a new backup challenge (new positions, empty fields, `message` as the error line).
    ResetBackup {
        /// The new word positions (1-based).
        positions: [u8; 4],
        /// The line saying why (`None`: none).
        message: Option<String>,
    },
}

/// Names and lengths only (D28): never the text of an error, a card line or an info line, nor
/// the backup positions.
impl fmt::Debug for SecretFormOp {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let len = |text: &Option<String>| text.as_ref().map(String::len);
        match self {
            Self::Busy(busy) => formatter.debug_tuple("Busy").field(busy).finish(),
            Self::Error(text) => formatter
                .debug_struct("Error")
                .field("len", &len(text))
                .finish(),
            Self::Details(lines) => formatter
                .debug_struct("Details")
                .field("lines", &lines.len())
                .finish(),
            Self::Card(text) => formatter
                .debug_struct("Card")
                .field("len", &len(text))
                .finish(),
            Self::Info(text) => formatter
                .debug_struct("Info")
                .field("len", &len(text))
                .finish(),
            Self::FailPassword { now_ms } => formatter
                .debug_struct("FailPassword")
                .field("now_ms", now_ms)
                .finish(),
            Self::ResetBackup { message, .. } => formatter
                .debug_struct("ResetBackup")
                .field("len", &len(message))
                .finish(),
        }
    }
}

/// Serials, window ids (`W02`), flags and the language only (D28): never a card serial of a W11
/// kind or a step's text.
impl fmt::Debug for SecretEffect {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenInput {
                serial,
                kind,
                step,
                topmost,
                lang,
            } => formatter
                .debug_struct("OpenInput")
                .field("serial", serial)
                .field("kind", &kind.id())
                .field("step", &step.is_some())
                .field("topmost", topmost)
                .field("lang", lang)
                .finish(),
            Self::Close { serial } => formatter
                .debug_struct("Close")
                .field("serial", serial)
                .finish(),
            Self::OpenDisplay {
                serial,
                kind,
                step,
                timeout_note,
                lang,
            } => formatter
                .debug_struct("OpenDisplay")
                .field("serial", serial)
                .field("kind", &kind.id())
                .field("step", &step.is_some())
                .field("timeout_note", &timeout_note.is_some())
                .field("lang", lang)
                .finish(),
            Self::Form { serial, op } => formatter
                .debug_struct("Form")
                .field("serial", serial)
                .field("op", op)
                .finish(),
            Self::ClearClip { at_exit } => formatter
                .debug_struct("ClearClip")
                .field("at_exit", at_exit)
                .finish(),
        }
    }
}

/// W08 `다 적었습니다` hold (archive `ACKNOWLEDGEMENT_HOLD_MS`).
pub const BACKUP_ACK_HOLD_MS: u64 = 2_000;
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

/// T-BACKUP-FAIL (W10 after a wrong answer, spec/04 §2.3): the same four positions are asked
/// again, and the paper may be what is wrong. `words_again`: closing W10 leads back to the words
/// (S04 or the recovery-phrase list); the new `YubiKey` wallet's W10 has no way back to them.
/// 2026-11-22 (S4d E0a): was yw-app `ui::screens::backup_retry_text`, its texts in
/// `ui::screens::text`.
#[must_use]
pub fn backup_retry_text(lang: Lang, positions: [u8; 4], words_again: bool) -> String {
    let [a, b, c, d] = positions.map(|position| position.to_string());
    let next = if words_again {
        text::BACKUP_RETRY_WORDS_AGAIN
    } else {
        text::BACKUP_RETRY_NO_WORDS
    };
    text::BACKUP_RETRY.fill(lang, [&a, &b, &c, &d, next.get(lang)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_effects_debug_as_ids_and_flags() {
        let open = SecretEffect::OpenInput {
            serial: 7,
            kind: SecretKind::CardPin {
                min: 6,
                max: 127,
                touches: 2,
                per_tx: false,
                serial: 12_345_678,
            },
            step: Some(SecretStep {
                flow: "flow",
                labels: &["one", "two", "three"],
                current: 2,
            }),
            topmost: true,
            lang: Lang::En,
        };
        let shown = format!("{open:?}");
        assert_eq!(
            shown,
            "OpenInput { serial: 7, kind: \"W11\", step: true, topmost: true, lang: En }"
        );
        assert!(!shown.contains("12345678"), "{shown}");
        assert_eq!(
            format!("{:?}", SecretEffect::Close { serial: 7 }),
            "Close { serial: 7 }"
        );
    }

    /// S4 P7b: the display open, the form operations and the clip clear print serials, window
    /// ids, flags and lengths only — never an error text, a card line or backup positions.
    #[test]
    fn display_form_and_clip_effects_debug_without_text() {
        let open = SecretEffect::OpenDisplay {
            serial: 4,
            kind: SecretKind::ShowMnemonic { create: true },
            step: None,
            timeout_note: Some("note text"),
            lang: Lang::Ko,
        };
        assert_eq!(
            format!("{open:?}"),
            "OpenDisplay { serial: 4, kind: \"W08\", step: false, timeout_note: true, lang: Ko }"
        );
        let ops = [
            (SecretFormOp::Busy(true), "Busy(true)"),
            (
                SecretFormOp::Error(Some("error text".to_owned())),
                "Error { len: Some(10) }",
            ),
            (SecretFormOp::Error(None), "Error { len: None }"),
            (
                SecretFormOp::Details(vec!["YubiKey 12345678".to_owned(), "PIN 3".to_owned()]),
                "Details { lines: 2 }",
            ),
            (
                SecretFormOp::Card(Some("card 12345678".to_owned())),
                "Card { len: Some(13) }",
            ),
            (
                SecretFormOp::Info(Some("info".to_owned())),
                "Info { len: Some(4) }",
            ),
            (
                SecretFormOp::FailPassword { now_ms: 1_000 },
                "FailPassword { now_ms: 1000 }",
            ),
            (
                SecretFormOp::ResetBackup {
                    positions: [3, 9, 17, 22],
                    message: Some("retry".to_owned()),
                },
                "ResetBackup { len: Some(5) }",
            ),
        ];
        for (op, expected) in ops {
            let shown = format!("{:?}", SecretEffect::Form { serial: 4, op });
            assert_eq!(shown, format!("Form {{ serial: 4, op: {expected} }}"));
            for text in ["text", "12345678", "card", "info", "retry", "17"] {
                assert!(!shown.contains(text), "{shown}");
            }
        }
        assert_eq!(
            format!("{:?}", SecretEffect::ClearClip { at_exit: true }),
            "ClearClip { at_exit: true }"
        );
    }

    /// The W12 PIN-change titles are those of `PinTarget::change_title` (byte-identical; the
    /// yw-app window test compares the other two target texts).
    #[test]
    fn pin_change_titles_match_the_pin_target_titles() {
        for target in [
            PinTarget::OpenPgpUser,
            PinTarget::OpenPgpAdmin,
            PinTarget::PivPin,
            PinTarget::PivPuk,
        ] {
            for lang in Lang::ALL {
                assert_eq!(target_title(target, lang), target.change_title(lang));
                assert_eq!(
                    CardSecretKind::ChangePin(target).title(lang),
                    target.change_title(lang)
                );
            }
        }
    }

    #[test]
    fn display_kinds_need_capture_exclusion_and_refuse_paste() {
        for kind in [
            SecretKind::ShowMnemonic { create: true },
            SecretKind::ShowKey,
        ] {
            assert!(kind.is_display() && kind.plaintext() && !kind.paste_allowed());
        }
        assert!(SecretKind::ShowMnemonic { create: true }.needs_hold());
        assert!(!SecretKind::ShowMnemonic { create: false }.needs_hold());
        assert!(!SecretKind::Unlock.is_display());
        assert_eq!(SecretKind::CardSecret(CardSecretKind::SetPins).id(), "W12");
    }
}
