//! The secret windows' input state machine (spec/04 §4.2–§4.9, D11; spec/15 §3.1, §9.2–§9.4,
//! §11.4 S5): [`SecretForm`] holds one window's state — its fields (`secure_field::SecretField`
//! buffers), the active field, the displayed secret (W08/W09), the messages, the timers and the
//! W08 hold — and takes the neutral events of [`super::input`]. It decides; the platform's shell
//! owns the instance, maps its own input into those events, paints the window from
//! [`SecretView`] and acts on the returned [`FormAction`] (Windows: yw-app `app::App::on_secret`,
//! `ui::secret::paint_form`).
//!
//! Ported from `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs` (`HoldGate`
//! 78-107, confirmation state 180-249, field activation 1559-1571, focus-loss handling 1572-1583)
//! as an app-loop window instead of a one-shot helper: focus loss masks the content (spec/04
//! §4.9) instead of cancelling.
//!
//! 2026-11-24 (spec/15 §11.4 S5-8; spec/04 §4.2, §4.7, §4.8): moved here from yw-app
//! `ui::secret` with its state tests (`tests`, and the S5-7 differential test with copies of the
//! Windows map, `tests::differential`). Unchanged but for these: [`PlatformFlags`] only narrow
//! paste and copy (`secret_word_paste` for W05/W07, `secret_copy` with the user's
//! `allowSecretCopy`; Windows sets both, so it decides as before); the paint stayed in yw-app and
//! reads the form only through [`SecretForm::paint_view`] (its countdown line is
//! `SecretView::countdown_line`, was part of the paint); a display window's form is built only by
//! `Wallet::open_display_window` (`SecretForm::display` is crate-private, S5 plan critic C1), so
//! the shell never names the displayed secret; the seam's test facts are crate-private, reached
//! through `testkit::SecretFormTestExt`. The shell's window constants (timer, paste bound,
//! window size, capture decision) stayed in yw-app. 2026-11-24 (S5-8 review): the view's maker
//! is `paint_view` (was `view`), a name no other fn has, so the source check
//! `the_secret_form_is_read_only_by_its_paint_and_copy` counts every mention of it (a method or
//! path call, or the fn named as a value), as `the_only_consume_is_wallet_code` does.

use core::fmt;

use yw_core::bip39::{is_word, is_word_prefix};
use yw_core::keyimport::ImportChain;
use yw_core::lang::Lang;
use yw_core::password::VaultPassword;
use yw_core::secret::Zeroizing;

use super::input::{SecretButton, SecretKey, SecretPointer, SecretTarget};
use super::{CardSecretKind, DisplaySecret, HoldGate, SecretKind, SecretStep, Submission, text};
use crate::errors::ErrorCode;
use crate::screen::facts::PlatformFlags;
use crate::secure_field::{
    Charset, PushResult, RejectReason, SecretField, finalize_private_key, has_edge_space,
    mnemonic_words, normalize_paste,
};
use crate::yubikey::PinTarget;

/// Inactivity (input windows) or display (W08/W09) lifetime.
pub const SECRET_WINDOW_TIMEOUT_MS: u64 = 300_000;
/// E-INP-008 visibility.
pub const INPUT_ERROR_MS: u64 = 3_000;
/// Input disabled after a wrong password (spec/02 §7.4).
pub const UNLOCK_FAIL_DISABLE_MS: u64 = 1_000;
/// Mnemonic entry buffer (24 × 8 + 23 + 1).
pub const MNEMONIC_TEXT_MAX: usize = 216;
/// W11's steps (2026-11-10): which card to connect, the PIN, the touch — and the bounds.
/// The card step after approval follows them ([`text::CARD_PIN`], spec/10 §9.2). `card` is the
/// card as shown everywhere (`name (#serial)` or `#serial`, 2026-11-15; `None` when unknown).
#[must_use]
pub fn card_pin_steps(lang: Lang, card: Option<&str>) -> String {
    let card = card.map_or_else(|| "YubiKey".to_owned(), |card| format!("YubiKey {card}"));
    text::CARD_PIN_STEPS.fill(lang, [&card])
}

/// A PIN target's name in labels and sentences (`PinTarget::name` in `lang`).
const fn target_name(target: PinTarget, lang: Lang) -> &'static str {
    match target {
        PinTarget::OpenPgpUser => "OpenPGP PIN",
        PinTarget::OpenPgpAdmin => text::NAME_OPENPGP_ADMIN.get(lang),
        PinTarget::PivPin => "PIV PIN",
        PinTarget::PivPuk => "PIV PUK",
    }
}

/// A PIN target's length rule and factory value (`PinTarget::rule` in `lang`).
fn target_rule(target: PinTarget, lang: Lang) -> String {
    let (min, max) = target.bounds();
    let factory = match target {
        PinTarget::OpenPgpUser | PinTarget::PivPin => "123456",
        PinTarget::OpenPgpAdmin | PinTarget::PivPuk => "12345678",
    };
    text::PIN_RULE.fill(lang, [&min.to_string(), &max.to_string(), factory])
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

struct Slot {
    label: String,
    field: SecretField,
    min: usize,
    masked: bool,
}

/// One group of a secret window's button row: each button with its label
/// ([`SecretView::button_labels`]).
pub type ButtonLabels = Vec<(SecretButton, String)>;

/// The state of one secret window.
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent flags of one window"
)]
pub struct SecretForm {
    kind: SecretKind,
    /// The app language the window's texts are drawn in (`Settings::language`).
    lang: Lang,
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
    pressed: Option<SecretButton>,
    note: Option<String>,
    step: Option<SecretStep>,
    /// Extra non-secret lines under the intro (W11: the cards holding the key, the PIN tries).
    details: Vec<String>,
    /// W11: the card to connect as shown everywhere (`name (#serial)`, 2026-11-15); `None`
    /// names it by the kind's serial.
    card: Option<String>,
    /// W08 `create`: what the countdown line adds (where the words are seen again, or that
    /// they are wiped).
    timeout_note: Option<&'static str>,
    /// W08 `create`: the countdown seconds last drawn (a tick repaints when they change).
    countdown_secs: u64,
    /// W10: `확인`/Enter was pressed with a word not in the list — every field counts as left
    /// (red) until the next edit.
    backup_left: bool,
    /// What the platform offers (2026-11-24, S5-8): only narrows paste and copy, never widens
    /// what the window's kind and the user's settings allow (spec/15 §9.3–§9.4).
    flags: PlatformFlags,
}

// 2026-11-18 (S4 A7, spec/15 §11.4 S4): what the secret-window seam (yw-app `app::secret_seam`)
// and the windowed secret characterization (`ui::tour_secrets`) read of a form: counts and flags
// only, never a unit of a field or of the displayed secret. 2026-11-24 (S5-8): crate-private
// here, reached by the shell's tests through `testkit::SecretFormTestExt` (yw-app's test builds
// compile this crate without `cfg(test)`); before, `#[cfg(test)] pub(crate)` in yw-app.
// 2026-11-24 (S5-8 review): so `test_held_units` (the units a form holds, which yw-app's
// `#[cfg(test)]` close log also reads in release test builds) is compiled in every build and
// reachable by any crate through the `pub` testkit trait — a count, never a unit; only the
// source check `testkit_is_named_only_by_tests` keeps production code from it. `test_facts` is
// `#[cfg(debug_assertions)]` again, as it was in yw-app (its readers, the seam's `test_secret`
// and the headless host, are debug test builds only).
impl SecretForm {
    /// The units its fields hold (after a wipe: 0).
    pub(crate) fn test_held_units(&self) -> usize {
        self.slots.iter().map(|slot| slot.field.len()).sum()
    }

    /// Flags and counts: busy, an error, an information or transient line, the detail lines,
    /// the card name, the held units, a displayed secret, capture exclusion, the input pause.
    #[cfg(debug_assertions)]
    pub(crate) fn test_facts(&self) -> String {
        format!(
            "busy={} error={} transient={} info={} details={} card={} units={} display={} excluded={} paused={}",
            self.busy,
            self.error.is_some(),
            self.transient.is_some(),
            self.info.is_some(),
            self.details.len(),
            self.card.is_some(),
            self.test_held_units(),
            self.display.is_some(),
            self.capture_excluded,
            self.disabled_until != 0
        )
    }
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
fn slots_for(kind: SecretKind, lang: Lang) -> Vec<Slot> {
    let slots = match kind {
        SecretKind::SetPassword => vec![
            slot(
                text::LABEL_PASSWORD.get(lang),
                Charset::Printable,
                12,
                128,
                true,
            ),
            slot(
                text::LABEL_PASSWORD_AGAIN.get(lang),
                Charset::Printable,
                12,
                128,
                true,
            ),
        ],
        SecretKind::Unlock | SecretKind::ConfirmPassword => {
            vec![slot(
                text::LABEL_PASSWORD.get(lang),
                Charset::Printable,
                1,
                128,
                true,
            )]
        }
        SecretKind::ChangePassword => vec![
            slot(
                text::LABEL_CURRENT_PASSWORD.get(lang),
                Charset::Printable,
                1,
                128,
                true,
            ),
            slot(
                text::LABEL_NEW_PASSWORD.get(lang),
                Charset::Printable,
                12,
                128,
                true,
            ),
            slot(
                text::LABEL_NEW_PASSWORD_AGAIN.get(lang),
                Charset::Printable,
                12,
                128,
                true,
            ),
        ],
        SecretKind::Mnemonic => vec![slot(
            text::LABEL_WORDS.get(lang),
            Charset::MnemonicText,
            1,
            MNEMONIC_TEXT_MAX,
            false,
        )],
        SecretKind::Passphrase { confirm: true } => vec![
            slot("passphrase", Charset::Printable, 1, 256, true),
            slot(
                text::LABEL_PASSPHRASE_AGAIN.get(lang),
                Charset::Printable,
                1,
                256,
                true,
            ),
        ],
        SecretKind::Passphrase { confirm: false } => {
            vec![slot("passphrase", Charset::Printable, 1, 256, true)]
        }
        SecretKind::PrivateKey {
            chain: ImportChain::Evm,
            ..
        } => vec![slot(
            text::LABEL_EVM_KEY.get(lang),
            Charset::PrivateKeyHex,
            64,
            66,
            false,
        )],
        SecretKind::PrivateKey {
            chain: ImportChain::Sol,
            ..
        } => vec![slot(
            text::LABEL_SOL_KEY.get(lang),
            Charset::KeyText,
            1,
            yw_core::keyimport::SOL_KEY_TEXT_MAX,
            false,
        )],
        SecretKind::PrivateKey {
            chain: ImportChain::Btc,
            ..
        } => vec![slot(
            text::LABEL_BTC_KEY.get(lang),
            Charset::Base58,
            51,
            52,
            false,
        )],
        SecretKind::PrivateKey {
            chain: ImportChain::Zec,
            ..
        } => vec![slot(
            text::LABEL_ZEC_KEY.get(lang),
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
            vec![slot(
                text::NAME_OPENPGP_ADMIN.get(lang),
                Charset::Printable,
                8,
                127,
                true,
            )]
        }
        SecretKind::CardSecret(CardSecretKind::ManagementKey) => vec![slot(
            text::LABEL_MANAGEMENT_KEY.get(lang),
            Charset::PrivateKeyHex,
            48,
            48,
            true,
        )],
        SecretKind::CardSecret(CardSecretKind::ChangePin(target)) => {
            let (min, max) = target.bounds();
            let (min, max) = (usize::from(min), usize::from(max));
            let name = target_name(target, lang);
            vec![
                slot(
                    &text::LABEL_CURRENT.fill(lang, [name]),
                    Charset::Printable,
                    min,
                    max,
                    true,
                ),
                slot(
                    &text::LABEL_NEW.fill(lang, [name]),
                    Charset::Printable,
                    min,
                    max,
                    true,
                ),
                slot(
                    &text::LABEL_NEW_AGAIN.fill(lang, [name]),
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
                text::LABEL_SET_PINS_CURRENT.get(lang),
                Charset::Printable,
                0,
                8,
                true,
            ),
            slot(
                text::LABEL_SET_PINS_NEW.get(lang),
                Charset::Printable,
                8,
                8,
                true,
            ),
            slot(
                text::LABEL_SET_PINS_AGAIN.get(lang),
                Charset::Printable,
                8,
                8,
                true,
            ),
        ],
        SecretKind::Backup { positions } => positions
            .iter()
            .map(|position| {
                slot(
                    &text::LABEL_WORD.fill(lang, [&position.to_string()]),
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

fn intro(
    kind: SecretKind,
    lang: Lang,
    (words, address): (usize, bool),
    card: Option<&str>,
) -> Vec<String> {
    let rule = text::PASSWORD_RULE.get(lang);
    match kind {
        SecretKind::SetPassword => vec![rule.to_owned()],
        // Review L1 (2026-11-13: the DEK rotates, spec/02 §4.4): later contents are out of reach
        // of older copies, but those copies keep the old password and what they held (and a
        // weak old password can be cracked offline later).
        SecretKind::ChangePassword => vec![
            rule.to_owned(),
            text::CHANGE_PASSWORD_NOTE.get(lang).to_owned(),
        ],
        SecretKind::Unlock => vec![text::UNLOCK_INTRO.get(lang).to_owned()],
        SecretKind::ConfirmPassword => vec![text::CONFIRM_INTRO.get(lang).to_owned()],
        SecretKind::Mnemonic => vec![text::MNEMONIC_INTRO.get(lang).to_owned()],
        SecretKind::Passphrase { confirm: true } => {
            vec![text::PASSPHRASE_CONFIRM_INTRO.get(lang).to_owned()]
        }
        SecretKind::Passphrase { confirm: false } => {
            vec![text::PASSPHRASE_INTRO.get(lang).to_owned()]
        }
        SecretKind::PrivateKey { chain, no_words } => vec![
            match chain {
                ImportChain::Evm => text::EVM_KEY_INPUT,
                ImportChain::Sol => text::SOL_KEY_INPUT,
                ImportChain::Btc => text::BTC_KEY_INPUT,
                ImportChain::Zec => text::ZEC_KEY_INPUT,
            }
            .get(lang)
            .to_owned(),
            if no_words {
                text::KEY_ONLY_BACKUP
            } else {
                text::IMPORTED_KEY_BACKUP
            }
            .get(lang)
            .to_owned(),
        ],
        // Without a known first address (an added phrase whose meta has none) only the words.
        SecretKind::ShowMnemonic { .. } => vec![text::SHOW_WORDS.fill(
            lang,
            [
                &words.to_string(),
                if address {
                    text::WITH_ADDRESS.get(lang)
                } else {
                    ""
                },
            ],
        )],
        SecretKind::ShowKey => vec![text::SHOW_KEY_INTRO.get(lang).to_owned()],
        SecretKind::Backup { positions } => {
            let [first, second, third, fourth] = positions.map(|position| position.to_string());
            vec![text::BACKUP_INTRO.fill(lang, [&first, &second, &third, &fourth])]
        }
        SecretKind::CardSecret(CardSecretKind::AdminPin) => {
            vec![text::CARD_ADMIN_PIN.get(lang).to_owned()]
        }
        SecretKind::CardSecret(CardSecretKind::ManagementKey) => {
            vec![text::CARD_MANAGEMENT_KEY.get(lang).to_owned()]
        }
        SecretKind::CardSecret(CardSecretKind::ChangePin(target)) => {
            vec![text::CHANGE_PIN_INTRO.fill(
                lang,
                [target_name(target, lang), &target_rule(target, lang)],
            )]
        }
        SecretKind::CardSecret(CardSecretKind::PivPin) => {
            vec![text::CARD_PIV_PIN.get(lang).to_owned()]
        }
        SecretKind::CardSecret(CardSecretKind::SetPins) => vec![
            text::CARD_SET_PINS.get(lang).to_owned(),
            text::CARD_SET_PINS_SAME.get(lang).to_owned(),
        ],
        SecretKind::CardSecret(CardSecretKind::UserPin { .. }) => {
            vec![text::CARD_USER_PIN.get(lang).to_owned()]
        }
        SecretKind::CardPin {
            touches,
            per_tx,
            serial,
            ..
        } => {
            let serial_card = (serial != 0).then(|| format!("#{serial}"));
            let mut lines = vec![format!(
                "{}. {}",
                card_pin_steps(lang, card.or(serial_card.as_deref())),
                text::CARD_PIN.get(lang)
            )];
            if touches > 1 {
                let line = if per_tx {
                    text::CARD_TOUCHES_PER_TX
                } else {
                    text::CARD_TOUCHES_PER_INPUT
                };
                lines.push(line.fill(lang, [&touches.to_string()]));
            }
            lines
        }
    }
}

/// `true` when `count` is a valid BIP39 length.
#[must_use]
pub const fn valid_word_count(count: usize) -> bool {
    matches!(count, 12 | 15 | 18 | 21 | 24)
}

impl SecretForm {
    /// The language the window's texts are drawn in (its fonts follow it, `theme::FontCache`).
    #[must_use]
    pub const fn lang(&self) -> Lang {
        self.lang
    }

    /// An input window (W01–W07, W10–W12) whose texts are in `lang`, on a platform that offers
    /// `flags` (Windows: [`PlatformFlags::WINDOWS`]). 2026-11-24 (S5-8): `flags` is new; before,
    /// the form (yw-app `ui::secret`) allowed what the window's kind allowed.
    #[must_use]
    pub fn new(
        kind: SecretKind,
        lang: Lang,
        now_ms: u64,
        capture_excluded: bool,
        flags: PlatformFlags,
    ) -> Self {
        Self {
            kind,
            lang,
            slots: slots_for(kind, lang),
            active: 0,
            checkbox: matches!(kind, SecretKind::Mnemonic)
                .then_some((text::PASSPHRASE_CHECKBOX.get(lang), false)),
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
            step: None,
            details: Vec::new(),
            card: None,
            timeout_note: None,
            countdown_secs: 0,
            backup_left: false,
            note: matches!(kind, SecretKind::Mnemonic)
                .then(|| text::PASSPHRASE_NOTE.get(lang).to_owned()),
            flags,
        }
    }

    /// A display window (W08/W09). Capture exclusion is required, so it is always excluded.
    /// 2026-11-24 (spec/15 §11.4 S5-8, §18 30 (나), S5 plan critic C1): crate-private, built only
    /// by `Wallet::open_display_window` for a window whose capture exclusion the shell's
    /// `DisplayHost` verified, and handed to `DisplayHost::fill_and_show` (the shell never names
    /// the secret); before, `pub` in yw-app, where the shell's host built it from the secret the
    /// wallet moved into it.
    #[must_use]
    pub(crate) fn display(
        kind: SecretKind,
        lang: Lang,
        now_ms: u64,
        secret: DisplaySecret,
        flags: PlatformFlags,
    ) -> Self {
        let mut form = Self::new(kind, lang, now_ms, true, flags);
        form.display = Some(secret);
        form
    }

    /// Shows the flow's step indicator above the title.
    pub const fn set_step(&mut self, step: Option<SecretStep>) {
        self.step = step;
    }

    /// W08 `create`: the note after the countdown (where the words can be seen again, or that
    /// they are wiped when the window closes). 2026-11-24 (S5-8): crate-private, set by
    /// `Wallet::open_display_window` (the shell's host set it before).
    /// 2026-11-25 (spec/15 §18 29, A2-6): it takes the catalogue key and resolves it in the
    /// window's language (the language the logic picked the text in before).
    pub(crate) const fn set_timeout_note(&mut self, note: Option<super::TimeoutNote>) {
        self.timeout_note = match note {
            Some(note) => Some(note.text(self.lang)),
            None => None,
        };
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

    /// W08 `create`'s countdown line on a first display (2026-11-10: the seconds left and the
    /// note where the words are seen again); `None` for every other window. 2026-11-24 (S5-8):
    /// was a part of yw-app's `paint_status`.
    fn countdown_line(&self, now_ms: u64) -> Option<String> {
        if !(self.kind.needs_hold() && self.display.is_some()) {
            return None;
        }
        let left = SECRET_WINDOW_TIMEOUT_MS
            .saturating_sub(now_ms.saturating_sub(self.started_ms))
            .div_ceil(1_000);
        let mut line = text::COUNTDOWN.fill(
            self.lang,
            [&(left / 60).to_string(), &format!("{:02}", left % 60)],
        );
        if let Some(note) = self.timeout_note {
            line.push(' ');
            line.push_str(note);
        }
        Some(line)
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

    /// W11: the card its first step names (`Wallet::card_name`, a label — not a secret).
    pub fn set_card(&mut self, card: Option<String>) {
        self.card = card;
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
        self.error = Some(ErrorCode::Vlt001.text_in(self.lang));
    }

    /// A new backup challenge (T-BACKUP-FAIL): new positions, empty fields.
    pub fn reset_backup(&mut self, positions: [u8; 4], message: Option<String>) {
        self.kind = SecretKind::Backup { positions };
        self.slots = slots_for(self.kind, self.lang);
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
                    return Err(ErrorCode::Inp001.text_in(self.lang));
                }
                if !equal(0, 1) {
                    return Err(ErrorCode::Inp002.text_in(self.lang));
                }
            }
            SecretKind::ChangePassword => {
                if !password_ok(1) {
                    return Err(ErrorCode::Inp001.text_in(self.lang));
                }
                if !equal(1, 2) {
                    return Err(ErrorCode::Inp002.text_in(self.lang));
                }
            }
            SecretKind::Passphrase { confirm: true } if !equal(0, 1) => {
                return Err(ErrorCode::Inp002.text_in(self.lang));
            }
            SecretKind::PrivateKey {
                chain: ImportChain::Evm,
                ..
            } => {
                if let Some(slot) = self.slots.first() {
                    finalize_private_key(&slot.field).map_err(|code| code.text_in(self.lang))?;
                }
            }
            SecretKind::PrivateKey {
                chain: ImportChain::Btc,
                ..
            } if self.slots.iter().any(|slot| slot.field.len() < slot.min) => {
                return Err(ErrorCode::Inp023.text_in(self.lang));
            }
            SecretKind::Backup { .. }
                if self.slots.iter().any(|slot| slot.field.len() < slot.min) =>
            {
                return Err(ErrorCode::Inp013.text_in(self.lang));
            }
            SecretKind::CardPin { min, max, .. }
                if self.slots.iter().any(|slot| {
                    !(usize::from(min)..=usize::from(max)).contains(&slot.field.len())
                }) =>
            {
                return Err(
                    text::ERR_CARD_PIN.fill(self.lang, [&min.to_string(), &max.to_string()])
                );
            }
            SecretKind::CardSecret(CardSecretKind::AdminPin)
                if self
                    .slots
                    .iter()
                    .any(|slot| !(8..=127).contains(&slot.field.len())) =>
            {
                return Err(text::ERR_ADMIN_PIN.get(self.lang).to_owned());
            }
            SecretKind::CardSecret(CardSecretKind::ManagementKey)
                if self.slots.iter().any(|slot| {
                    slot.field.len() != 48
                        || !slot.field.as_bytes().iter().all(u8::is_ascii_hexdigit)
                }) =>
            {
                return Err(text::ERR_MANAGEMENT_KEY.get(self.lang).to_owned());
            }
            SecretKind::CardSecret(
                CardSecretKind::PivPin | CardSecretKind::UserPin { piv: true },
            ) if self
                .slots
                .iter()
                .any(|slot| !(6..=8).contains(&slot.field.len())) =>
            {
                return Err(text::ERR_PIV_PIN.get(self.lang).to_owned());
            }
            SecretKind::CardSecret(CardSecretKind::UserPin { piv: false })
                if self
                    .slots
                    .iter()
                    .any(|slot| !(6..=127).contains(&slot.field.len())) =>
            {
                return Err(text::ERR_OPENPGP_PIN.get(self.lang).to_owned());
            }
            SecretKind::CardSecret(CardSecretKind::SetPins) => {
                let current = self.slots.first().map_or(0, |slot| slot.field.len());
                if current != 0 && current != 8 {
                    return Err(text::ERR_SET_PINS_CURRENT.get(self.lang).to_owned());
                }
                if self.slots.iter().skip(1).any(|slot| slot.field.len() != 8) {
                    return Err(text::ERR_SET_PINS_NEW.get(self.lang).to_owned());
                }
                if !equal(1, 2) {
                    return Err(text::ERR_SET_PINS_DIFFER.get(self.lang).to_owned());
                }
                if equal(0, 1) {
                    return Err(text::ERR_SET_PINS_SAME.get(self.lang).to_owned());
                }
                if factory(1) {
                    return Err(text::CARD_NEW_FACTORY.get(self.lang).to_owned());
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
                    return Err(format!(
                        "{}: {}",
                        target_name(target, self.lang),
                        target_rule(target, self.lang)
                    ));
                }
                if !equal(1, 2) {
                    return Err(
                        text::ERR_NEW_DIFFER.fill(self.lang, [target_name(target, self.lang)])
                    );
                }
                if equal(0, 1) {
                    return Err(
                        text::ERR_NEW_SAME.fill(self.lang, [target_name(target, self.lang)])
                    );
                }
                if factory(1) {
                    return Err(text::CARD_NEW_FACTORY.get(self.lang).to_owned());
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
                SecretKind::Passphrase { .. } => ErrorCode::Inp019.text_in(self.lang),
                _ => ErrorCode::Inp001.text_in(self.lang),
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
                    Some(position) => ErrorCode::Inp004
                        .render_in(self.lang, &position.saturating_add(1).to_string()),
                    None if !valid_word_count(count) => ErrorCode::Inp003.text_in(self.lang),
                    None => ErrorCode::Inp005.text_in(self.lang),
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
            ErrorCode::Inp008.text_in(self.lang),
            now_ms.saturating_add(INPUT_ERROR_MS),
        ));
        FormAction::Redraw
    }

    /// One typed unit ([`SecretKey::Char`]; was the `pub` `WM_CHAR` entry `on_char` before
    /// 2026-11-24, S5-7).
    fn on_char(&mut self, unit: u16, now_ms: u64) -> FormAction {
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

    /// A key of the window ([`SecretKey`], mapped by the shell: Windows `ui::secret_input`). Every
    /// key touches the inactivity clock first; a [`FormAction::None`] lets the shell's platform
    /// handle the key (Windows: `Reply::Default`). 2026-11-24 (S5-7): before, `on_key(vk, ctrl,
    /// shift, alt)` compared the Windows virtual-key codes itself in the precedence the map now
    /// applies, and `on_char(unit)` was the `WM_CHAR` entry ([`SecretKey::Char`]).
    pub fn on_key(&mut self, key: SecretKey, now_ms: u64) -> FormAction {
        self.touch(now_ms);
        match key {
            SecretKey::Char(unit) => self.on_char(unit, now_ms),
            SecretKey::Composition => self.non_ascii(now_ms),
            SecretKey::Escape => {
                // A submitted value's job (reveal, removal, `.prev` recovery, unlock) is running
                // and cannot be called back: Esc would only look like a cancel. The window closes
                // with the result (1–2 s).
                if self.busy {
                    FormAction::None
                } else {
                    self.cancel()
                }
            }
            // 2026-11-24 (S5-8): the platform flags narrow paste and copy (spec/15 §9.3–§9.4); a
            // copy with `allowSecretCopy` off still asks the shell, which shows T-COPY-OFF and
            // copies nothing (spec/04 §4.8; `copy_units` is `None` then).
            SecretKey::Paste => {
                if self.paste_kind_allowed() && self.input_enabled(now_ms) {
                    FormAction::Paste
                } else {
                    FormAction::None
                }
            }
            SecretKey::Copy => {
                if self.flags.secret_copy && self.kind.is_display() {
                    FormAction::Copy
                } else {
                    FormAction::None
                }
            }
            SecretKey::Tab { back } => {
                if self.kind == SecretKind::Mnemonic {
                    return self.on_char(0x20, now_ms);
                }
                let count = self.slots.len();
                if count == 0 {
                    return FormAction::None;
                }
                self.active = if back {
                    self.active
                        .checked_sub(1)
                        .unwrap_or(count.saturating_sub(1))
                } else {
                    self.active.saturating_add(1) % count
                };
                FormAction::Redraw
            }
            SecretKey::Other => FormAction::None,
        }
    }

    /// Whether the window's kind takes a paste on this platform (spec/04 §4.7, spec/15 §9.4): the
    /// kind allows it, and the recovery-word and private-key windows (W05, W07) only where the
    /// platform pastes words ([`PlatformFlags::secret_word_paste`]; Windows: yes). 2026-11-24
    /// (S5-8): the flag only narrows; before, the kind alone decided.
    fn paste_kind_allowed(&self) -> bool {
        self.kind.paste_allowed()
            && (self.flags.secret_word_paste
                || !matches!(
                    self.kind,
                    SecretKind::Mnemonic | SecretKind::PrivateKey { .. }
                ))
    }

    /// Whether a display window offers `복사` (spec/04 §4.8): the platform copies secrets
    /// ([`PlatformFlags::secret_copy`]; Windows: yes) **and** the user's `allowSecretCopy`
    /// (`DisplaySecret::copy_allowed`, off by default) is on. 2026-11-24 (S5-8): the flag only
    /// narrows; before, `copy_allowed` alone decided.
    fn copy_offered(&self) -> bool {
        self.flags.secret_copy
            && self
                .display
                .as_ref()
                .is_some_and(|display| display.copy_allowed)
    }

    fn button_enabled(&self, button: SecretButton, now_ms: u64) -> bool {
        match button {
            SecretButton::Primary => self.can_submit(now_ms) || self.display.is_some(),
            SecretButton::Copy => self.copy_offered(),
            SecretButton::Reveal(_) => self.capture_excluded && self.input_enabled(now_ms),
            SecretButton::ClearAll | SecretButton::Checkbox => self.input_enabled(now_ms),
            // Not while a submitted job runs (see `on_key`'s Esc).
            SecretButton::Cancel => !self.busy,
        }
    }

    /// A pointer event of the window ([`SecretPointer`], hit-tested by the shell against the
    /// layout its paint returned; Windows: yw-app `ui::secret_input::HitLayout`); returns the
    /// action and, for a press, whether to capture the pointer (a move or a release never asks).
    /// 2026-11-24 (S5-7): was `on_mouse_down`, `on_mouse_move` and `on_mouse_up(x, y)` over the
    /// rects the form kept from its paint.
    pub fn on_pointer(&mut self, pointer: SecretPointer, now_ms: u64) -> (FormAction, bool) {
        match pointer {
            SecretPointer::Down(target) => self.pointer_down(target, now_ms),
            SecretPointer::Move(over) => (self.pointer_move(&over), false),
            SecretPointer::Up(button) => (self.pointer_up(button, now_ms), false),
        }
    }

    /// `WM_LBUTTONDOWN` on `target`.
    fn pointer_down(&mut self, target: Option<SecretTarget>, now_ms: u64) -> (FormAction, bool) {
        self.touch(now_ms);
        self.masked = false;
        let button = match target {
            Some(SecretTarget::Field(index)) => {
                self.active = index;
                return (FormAction::Redraw, false);
            }
            Some(SecretTarget::Button(button)) => button,
            None => return (FormAction::Redraw, false),
        };
        if !self.button_enabled(button, now_ms) {
            return (FormAction::None, false);
        }
        self.pressed = Some(button);
        match button {
            SecretButton::Primary if self.kind.needs_hold() => {
                self.hold.begin(now_ms);
                (FormAction::Redraw, true)
            }
            SecretButton::Reveal(index) => {
                self.revealing = Some(index);
                (FormAction::Redraw, true)
            }
            _ => (FormAction::Redraw, true),
        }
    }

    /// `WM_MOUSEMOVE` while captured, over the buttons `over`.
    fn pointer_move(&mut self, over: &[SecretButton]) -> FormAction {
        let Some(pressed) = self.pressed else {
            return FormAction::None;
        };
        let inside = over.contains(&pressed);
        if !inside && (self.hold.active() || self.revealing.is_some()) {
            self.hold.cancel();
            self.revealing = None;
            return FormAction::Redraw;
        }
        FormAction::None
    }

    /// `WM_LBUTTONUP` over `button`.
    fn pointer_up(&mut self, button: Option<SecretButton>, now_ms: u64) -> FormAction {
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
        if button != Some(pressed) || !self.button_enabled(pressed, now_ms) {
            return FormAction::Redraw;
        }
        match pressed {
            SecretButton::Primary => self.submit(now_ms),
            SecretButton::Cancel => {
                if self.display.is_some() && !self.kind.needs_hold() {
                    self.wipe();
                    FormAction::Close
                } else {
                    self.cancel()
                }
            }
            SecretButton::ClearAll => {
                for slot in &mut self.slots {
                    slot.field.clear();
                }
                self.active = 0;
                self.error = None;
                FormAction::Redraw
            }
            SecretButton::Copy => FormAction::Copy,
            SecretButton::Checkbox => {
                if let Some((_, checked)) = self.checkbox.as_mut() {
                    *checked = !*checked;
                }
                FormAction::Redraw
            }
            SecretButton::Reveal(_) => FormAction::Redraw,
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
        self.button_enabled(SecretButton::Reveal(0), now_ms)
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
    /// [`ErrorCode::Inp018`] (2026-11-24, S5-8: also for a window whose kind takes no paste on
    /// this platform, which never asked for one).
    pub fn apply_paste(&mut self, units: &[u16]) -> Result<bool, ErrorCode> {
        if !self.paste_kind_allowed() {
            return Err(ErrorCode::Inp018);
        }
        let slot = self.slots.get_mut(self.active).ok_or(ErrorCode::Inp018)?;
        let charset = slot.field.charset();
        let normalized = normalize_paste(units, charset, slot.field.limit())?;
        if !slot.field.replace_with(&normalized) {
            return Err(ErrorCode::Inp018);
        }
        self.error = None;
        Ok(charset == Charset::Printable && has_edge_space(&normalized))
    }

    /// The text to copy (W08: words joined by one space; W09: 64 hex) as UTF-16, a zeroizing copy
    /// for the platform's secret clipboard (Windows only: `App::copy_secret`, source check
    /// `the_secret_form_is_read_only_by_its_paint_and_copy`). 2026-11-24 (S5-8): `None` unless
    /// the window offers `복사` (the platform copies secrets and `allowSecretCopy` is on); before,
    /// any display window's text (the shell checked the setting first, as it still does).
    #[must_use]
    pub fn copy_units(&self) -> Option<Zeroizing<Vec<u16>>> {
        if !self.copy_offered() {
            return None;
        }
        let display = self.display.as_ref()?;
        let mut units = Zeroizing::new(Vec::with_capacity(display.text.expose().len()));
        units.extend(display.text.expose().encode_utf16());
        Some(units)
    }

    /// The read-only view a platform's paint draws the window from ([`SecretView`]; Windows:
    /// yw-app `ui::secret::paint_form`, the only reader, source check
    /// `the_secret_form_is_read_only_by_its_paint_and_copy`, which counts every mention of this
    /// fn's name: the only one outside this fn is `App::on_secret`'s `Msg::Paint` arm). 2026-11-24
    /// (S5-8 review): named `paint_view` (was `view`, which the approval flow's read model shares)
    /// so a path call or the fn named as a value is found too.
    #[must_use]
    pub const fn paint_view(&self) -> SecretView<'_> {
        SecretView { form: self }
    }

    /// The button row in `lang`: the right group (cancel, primary) and the left group (clear all
    /// or copy).
    fn button_labels(&self, now_ms: u64) -> (ButtonLabels, ButtonLabels) {
        let lang = self.lang;
        let primary_label = match self.kind {
            SecretKind::ShowMnemonic { create: true } => {
                if self.hold.active() {
                    let seconds = format!(
                        "{:.1}",
                        f64::from(u32::try_from(self.hold.remaining_ms(now_ms)).unwrap_or(0))
                            / 1_000.0
                    );
                    text::HOLD_PROGRESS.fill(lang, [&seconds])
                } else {
                    text::HOLD.get(lang).to_owned()
                }
            }
            SecretKind::ShowMnemonic { create: false } | SecretKind::ShowKey => {
                text::CLOSE.get(lang).to_owned()
            }
            SecretKind::Unlock => text::UNLOCK.get(lang).to_owned(),
            SecretKind::ChangePassword => text::CHANGE.get(lang).to_owned(),
            SecretKind::Mnemonic | SecretKind::SetPassword => text::NEXT.get(lang).to_owned(),
            SecretKind::PrivateKey { .. } => text::IMPORT.get(lang).to_owned(),
            _ => text::OK.get(lang).to_owned(),
        };
        let mut right: Vec<(SecretButton, String)> = vec![(SecretButton::Primary, primary_label)];
        if self.display.is_none() {
            right.insert(
                0,
                (
                    SecretButton::Cancel,
                    if self.kind == SecretKind::Unlock {
                        text::LATER
                    } else {
                        text::CANCEL
                    }
                    .get(lang)
                    .to_owned(),
                ),
            );
        }
        let mut left: Vec<(SecretButton, String)> = Vec::new();
        if self.display.is_none() {
            left.push((SecretButton::ClearAll, text::CLEAR_ALL.get(lang).to_owned()));
        } else if self.copy_offered() {
            left.push((SecretButton::Copy, text::COPY.get(lang).to_owned()));
        }
        (right, left)
    }
}

/// What a platform's paint reads of a secret window's form (2026-11-24, spec/15 §11.4 S5-8): the
/// texts, flags and counts it draws and, for drawing only, the field contents and the displayed
/// secret as the paint used them before (short-lived zeroizing UTF-16 copies of a field,
/// [`FieldView::render_utf16`]; W05's recovery words as borrowed slices of the field buffer,
/// [`FieldView::words`], no copy, for the word grid; the displayed secret borrowed,
/// [`Self::shown_text`]). Read-only:
/// nothing here changes the form. Its `Debug` is redacted (the window id only), so it never puts
/// a field or the displayed secret in a log or a `Debug` text. Windows: yw-app
/// `ui::secret::paint_form` is its only reader (source check
/// `the_secret_form_is_read_only_by_its_paint_and_copy`). Before S5-8 the paint was the yw-app
/// form's own methods and read its fields.
pub struct SecretView<'a> {
    form: &'a SecretForm,
}

impl fmt::Debug for SecretView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "SecretView({}, [REDACTED])", self.form.kind.id())
    }
}

/// One field of a [`SecretView`] (its `Debug` redacted, like the view's).
pub struct FieldView<'a> {
    slot: &'a Slot,
}

impl fmt::Debug for FieldView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FieldView([REDACTED])")
    }
}

impl<'a> FieldView<'a> {
    /// The field's label.
    #[must_use]
    pub fn label(&self) -> &'a str {
        &self.slot.label
    }

    /// The units it holds.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.slot.field.len()
    }

    /// Whether it holds nothing.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.slot.field.is_empty()
    }

    /// The most units it takes.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.slot.field.limit()
    }

    /// A masked field (passwords, PINs, passphrases: drawn as dots unless `보기` is held).
    #[must_use]
    pub const fn masked(&self) -> bool {
        self.slot.masked
    }

    /// Its content for drawing (`masked`: one dot per unit), a short-lived zeroizing copy
    /// (`SecretField::render_utf16`, spec/04 §4.2).
    #[must_use]
    pub fn render_utf16(&self, masked: bool) -> Zeroizing<Vec<u16>> {
        self.slot.field.render_utf16(masked)
    }

    /// W05: its words, borrowed slices of the field buffer itself (no copy, nothing to wipe), for
    /// the word grid only, as the paint read them before S5-8 (`mnemonic_words(&slot.field)`).
    #[must_use]
    pub fn words(&self) -> Vec<&'a [u8]> {
        mnemonic_words(&self.slot.field)
    }

    /// W05: whether its last unit is a space (the word being typed is the next cell).
    #[must_use]
    pub fn ends_with_space(&self) -> bool {
        self.slot.field.as_bytes().last() == Some(&b' ')
    }
}

impl<'a> SecretView<'a> {
    /// The language its texts are drawn in.
    #[must_use]
    pub const fn lang(&self) -> Lang {
        self.form.lang
    }

    /// The window kind.
    #[must_use]
    pub const fn kind(&self) -> SecretKind {
        self.form.kind
    }

    /// Whether capture exclusion is in effect (`false`: T-CAPTURE-WARN, `보기` off).
    #[must_use]
    pub const fn capture_excluded(&self) -> bool {
        self.form.capture_excluded
    }

    /// The flow's step indicator (`None`: none).
    #[must_use]
    pub const fn step(&self) -> Option<SecretStep> {
        self.form.step
    }

    /// The paragraphs under the title (the window's intro in its language).
    #[must_use]
    pub fn intro(&self) -> Vec<String> {
        let form = self.form;
        let words = form
            .display
            .as_ref()
            .map_or(24, |display| display.text.expose().split(' ').count());
        let address = form
            .display
            .as_ref()
            .is_some_and(|display| display.address.is_some());
        intro(form.kind, form.lang, (words, address), form.card.as_deref())
    }

    /// The non-secret lines after the intro (W11/W12: the card, its PIN tries).
    #[must_use]
    pub fn details(&self) -> &'a [String] {
        &self.form.details
    }

    /// W05's passphrase checkbox: its label and whether it is checked.
    #[must_use]
    pub const fn checkbox(&self) -> Option<(&'static str, bool)> {
        self.form.checkbox
    }

    /// W05's note under a checked checkbox.
    #[must_use]
    pub fn note(&self) -> Option<&'a str> {
        self.form.note.as_deref()
    }

    /// W01/W04's two password conditions (each `None` while its field is empty).
    #[must_use]
    pub fn password_checks(&self) -> Option<(Option<bool>, Option<bool>)> {
        self.form.password_checks()
    }

    /// W10: the first word position not in the list.
    #[must_use]
    pub fn unlisted_position(&self) -> Option<u8> {
        self.form.unlisted_position()
    }

    /// W08 `create`'s countdown line at `now_ms` (`None` for every other window).
    #[must_use]
    pub fn countdown_line(&self, now_ms: u64) -> Option<String> {
        self.form.countdown_line(now_ms)
    }

    /// The error line.
    #[must_use]
    pub fn error(&self) -> Option<&'a str> {
        self.form.error.as_deref()
    }

    /// The transient error line (E-INP-008) while it shows.
    #[must_use]
    pub fn transient(&self) -> Option<&'a str> {
        self.form.transient.as_ref().map(|(text, _)| text.as_str())
    }

    /// The information line.
    #[must_use]
    pub fn info(&self) -> Option<&'a str> {
        self.form.info.as_deref()
    }

    /// A submitted job runs (`확인 중…`).
    #[must_use]
    pub const fn busy(&self) -> bool {
        self.form.busy
    }

    /// The content is masked (T-MASKED, focus lost).
    #[must_use]
    pub const fn masked(&self) -> bool {
        self.form.masked
    }

    /// W08/W09: the displayed secret (words joined by one space, or the key) for drawing only,
    /// borrowed; `None` for an input window.
    #[must_use]
    pub fn shown_text(&self) -> Option<&'a str> {
        self.form
            .display
            .as_ref()
            .map(|display| display.text.expose())
    }

    /// W08: the first address shown under the words (not a secret).
    #[must_use]
    pub fn shown_address(&self) -> Option<&'a str> {
        self.form
            .display
            .as_ref()
            .and_then(|display| display.address.as_deref())
    }

    /// W08: the wallet uses a BIP39 passphrase (the reveal note).
    #[must_use]
    pub fn shown_passphrase_note(&self) -> bool {
        self.form
            .display
            .as_ref()
            .is_some_and(|display| display.passphrase_note)
    }

    /// The fields in order.
    pub fn fields(&self) -> impl Iterator<Item = FieldView<'a>> + use<'a> {
        self.form.slots.iter().map(|slot| FieldView { slot })
    }

    /// The first field (W05: the word buffer).
    #[must_use]
    pub fn first_field(&self) -> Option<FieldView<'a>> {
        self.form.slots.first().map(|slot| FieldView { slot })
    }

    /// The active field's index.
    #[must_use]
    pub const fn active(&self) -> usize {
        self.form.active
    }

    /// The field whose `보기` is held.
    #[must_use]
    pub const fn revealing(&self) -> Option<usize> {
        self.form.revealing
    }

    /// Whether input is enabled at `now_ms` (not busy, not paused, not a display window).
    #[must_use]
    pub fn input_enabled(&self, now_ms: u64) -> bool {
        self.form.input_enabled(now_ms)
    }

    /// W10: the list verdict of field `index`.
    #[must_use]
    pub fn word_mark(&self, index: usize) -> WordMark {
        self.form.word_mark(index)
    }

    /// W05: how many words are typed.
    #[must_use]
    pub fn word_count(&self) -> usize {
        self.form.mnemonic_status().0
    }

    /// The button row at `now_ms`: the right group (cancel, primary) and the left group (clear
    /// all or copy), each button with its label.
    #[must_use]
    pub fn button_labels(&self, now_ms: u64) -> (ButtonLabels, ButtonLabels) {
        self.form.button_labels(now_ms)
    }

    /// Whether `button` is enabled at `now_ms`.
    #[must_use]
    pub fn button_enabled(&self, button: SecretButton, now_ms: u64) -> bool {
        self.form.button_enabled(button, now_ms)
    }

    /// W08's hold is in progress.
    #[must_use]
    pub const fn hold_active(&self) -> bool {
        self.form.hold.active()
    }

    /// W08's hold: the milliseconds still needed at `now_ms`.
    #[must_use]
    pub const fn hold_remaining_ms(&self, now_ms: u64) -> u64 {
        self.form.hold.remaining_ms(now_ms)
    }
}

#[cfg(test)]
mod tests;
