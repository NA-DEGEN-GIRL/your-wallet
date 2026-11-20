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

use core::fmt;

use yw_core::keyimport::ImportChain;
use yw_core::lang::Lang;

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
/// `Effect::Secret`). Ids, kinds and flags only, never secret text: a window's buffers are filled
/// by the person typing into the shell's form, and nothing in here is a value.
#[derive(Clone, Copy, PartialEq, Eq)]
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
        }
    }
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
