//! YubiKey accounts (spec/10): keys derived from a mnemonic once, imported into one or more
//! YubiKey 5 devices (OpenPGP for secp256k1, PIV for Ed25519), and used for signing on the card
//! afterwards. The PC keeps no secret for these accounts — only the public keys and the slot map
//! (vault tag 5, [`record`]).
//!
//! | module | content |
//! |---|---|
//! | [`apdu`] | ISO 7816-4 command/response framing, chaining, GET RESPONSE |
//! | [`tlv`] | BER-TLV |
//! | [`openpgp`] | OpenPGP card 3.4 builders/parsers and flows (SIG/AUT secp256k1) |
//! | [`piv`] | PIV builders/parsers and flows (Ed25519 import, sign, management key) |
//! | [`sig`] | ECDSA post-processing (low-s, EVM recovery id, BTC DER), Ed25519 verify |
//! | [`plan`] | slot plan: roles, derivation paths, duplicate rules, slot map queries |
//! | [`record`] | vault tag 5 record codec (one record per YubiKey) |
//! | [`enrol`] | derive from the mnemonic, import, read back and compare public keys |
//! | [`manage`] | re-slot an enrolled card ("슬롯 구성 바꾸기"), clear it ("YubiKey 비우기") |
//! | [`sign`] | signing on the card for a planned slot (PIN per operation) |
//! | [`mock`] | APDU-level emulator of both applets for tests (yw-app uses it only under `cfg(test)`; the check script forbids dev-dependencies, so it is always compiled) |
//!
//! yw-core has no OS access: the transport is the [`CardTransport`] trait (PC/SC in yw-win) and
//! the PIV management-key block cipher is [`piv::MgmtCipher`] (Windows CNG in yw-win).
//!
//! **Hardware rule:** nothing in the gate talks to a real card. The only code that writes to a
//! card is [`enrol`], [`manage`] and the PIN/management-key change helpers, and it runs only when
//! the user starts the enrolment wizard or a card action of the `YubiKey` list.
#![allow(
    clippy::doc_markdown,
    reason = "product names (YubiKey, OpenPGP) appear throughout the card documentation"
)]

use core::fmt;

use crate::lang::Lang;

pub mod apdu;
pub mod connect;
pub mod enrol;
pub mod manage;
pub mod mock;
pub mod openpgp;
pub mod piv;
pub mod plan;
pub mod record;
pub mod sig;
pub mod sign;
pub mod text;
pub mod tlv;

#[cfg(test)]
mod tests;

/// Byte transport to one connected card (PC/SC `SCardTransmit` in yw-win, the emulator in tests).
///
/// `transmit` sends one complete command frame and returns `data ‖ SW1 ‖ SW2`. Chaining, GET
/// RESPONSE and status mapping are done above this trait ([`apdu::exchange`]).
pub trait CardTransport {
    /// Sends one frame.
    ///
    /// # Errors
    ///
    /// [`CardError::Transport`] (or [`CardError::CardRemoved`]) when the reader fails.
    fn transmit(&mut self, command: &[u8]) -> Result<Vec<u8>, CardError>;
}

/// Whether a job that sends `command` must end with a warm reset of the card (spec/10 §5.1).
/// Only the read-only instructions this wallet sends are `false`: SELECT (`A4`), GET RESPONSE
/// (`C0`), GET DATA (`CA`/`CB`), GET VERSION (`F1`/`FD`), GET SERIAL (`F8`), GET METADATA
/// (`F7`) and the OpenPGP public-key read (`47 81`). Everything else — VERIFY, management-key
/// authentication, signing, any write, an unknown or too short frame — may leave a PIN verified
/// (a factory YubiKey keeps PW1 valid after a signature, PW1 `82` and PW3 always) or the card
/// changed, so the transport resets the card when it releases it and the next PC/SC client
/// finds nothing verified.
#[must_use]
pub fn needs_reset(command: &[u8]) -> bool {
    let read_only = match command {
        [_, ins, p1, _, ..] => {
            matches!(ins, 0xA4 | 0xC0 | 0xCA | 0xCB | 0xF1 | 0xFD | 0xF8 | 0xF7)
                || (*ins == 0x47 && *p1 == 0x81)
        }
        _ => false,
    };
    !read_only
}

/// Reader-side failure classes (the PC/SC code itself is logged by yw-app, not carried here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportFault {
    /// The smart-card service is not running.
    NoService,
    /// No reader is attached.
    NoReader,
    /// A reader without a card.
    NoCard,
    /// Another program holds the card exclusively.
    Busy,
    /// Any other reader error.
    Io,
}

/// Card operation failure. Values never contain PINs, keys or card data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardError {
    /// The reader or service failed.
    Transport(TransportFault),
    /// The card was removed or reset during the operation.
    CardRemoved,
    /// The applet is not on this card (`6A82` on SELECT).
    AppletMissing,
    /// Wrong PIN / admin PIN; `retries` left (`63Cx` on PIV; on the `OpenPGP` applet of a
    /// `YubiKey` the card answers `6982` and the counter is read again from `6E`/`C4`, spec/10
    /// §9.1). `retries: 0` means the PIN is now blocked (final, like [`CardError::PinBlocked`]).
    WrongPin {
        /// Remaining tries.
        retries: u8,
    },
    /// PIN (or PUK / admin PIN) blocked (`6983`).
    PinBlocked,
    /// Security status not satisfied (`6982`): PIN not verified, management key not
    /// authenticated, or the touch was not given in time.
    SecurityStatus,
    /// Conditions of use not satisfied (`6985`), e.g. a touch timeout on some firmware.
    Conditions,
    /// Incorrect data (`6A80`): the card refused the key or attribute.
    WrongData,
    /// Function, instruction, class or parameters not supported (`6A81`, `6D00`, `6E00`,
    /// `6A86`): firmware too old for this algorithm or slot.
    NotSupported,
    /// Referenced data not found (`6A88`): empty slot.
    NotFound,
    /// Any other status word.
    Status(u16),
    /// The response did not have the expected structure.
    Malformed,
    /// A command is longer than an APDU can carry.
    TooLarge,
    /// The PIV management-key mutual authentication failed (the card's proof was wrong).
    ManagementKeyMismatch,
    /// The PIV management key is PIN-protected (ADMIN DATA flag `02`) and no PIV PIN was given.
    ManagementKeyProtected,
    /// The PIV management key is neither the factory key nor PIN-protected: this wallet does
    /// not know it.
    ManagementKeyUnknown,
    /// The firmware is older than the feature needs (spec/10 §2).
    FirmwareTooOld,
    /// The OpenPGP applet uses a KDF for PINs (KDF-DO set), which this wallet does not support.
    KdfEnabled,
    /// The public key on the card is not the key derived from the mnemonic (or recorded in the
    /// vault): the card is not the enrolled one, or the slot was overwritten.
    KeyMismatch,
    /// A slot this wallet is about to empty or overwrite holds a key the vault record does not
    /// list (another program's key, or a card changed outside this wallet): nothing in that
    /// applet was deleted or written (spec/10 §15).
    ForeignKey,
    /// The serial of the inserted card is not one that holds this key.
    WrongCard,
    /// The card produced a signature that does not verify for the recorded public key.
    BadSignature,
    /// The PIN or admin PIN does not meet the applet's length rules.
    PinFormat,
    /// The card refused an Ed25519 PIV import on firmware 5.7.0–5.7.3 (Yubico documents the
    /// import from 5.7.4, spec/10 §2).
    Ed25519ImportRefused,
    /// The `OpenPGP` admin PIN has one try left and the user did not confirm spending it: nothing
    /// was sent (spec/10 §9.1).
    AdminLastTry,
    /// More than one `YubiKey` is inserted where the wallet must know which card it writes to
    /// (enrolment, adoption, the credentials probe; spec/10 §7.3).
    MultipleCards,
    /// A new PIN, PUK or admin PIN is a published factory value ([`FACTORY_SECRETS`]): nothing
    /// was sent — whoever holds a card with such a secret signs with it (spec/10 §9.3).
    DefaultPin,
    /// An applet reset stopped because a PIN or the PUK did not block within the tries the card
    /// reported (+1): TERMINATE / RESET were not sent, no key was deleted (spec/10 §15.5).
    NotBlocked,
    /// The PIV PUK has one try left and the user did not confirm spending it: nothing was sent
    /// (spec/10 §9.1).
    PukLastTry,
    /// Internal error (derivation failure, invariant).
    Internal,
}

/// The factory values of the card secrets (`OpenPGP` PW1 / PIV PIN `123456`, `OpenPGP` PW3 /
/// PIV PUK `12345678`): never accepted as a new value, never sent as a signing PIN (spec/10 §9.2,
/// §9.3).
pub const FACTORY_SECRETS: [&[u8]; 2] = [b"123456", b"12345678"];

/// Whether `value` is one of [`FACTORY_SECRETS`].
#[must_use]
pub fn is_factory_secret(value: &[u8]) -> bool {
    FACTORY_SECRETS.contains(&value)
}

impl CardError {
    /// Whether another try with a new PIN makes sense (not blocked, not final).
    #[must_use]
    pub const fn pin_retryable(self) -> bool {
        !matches!(
            self,
            Self::PinBlocked | Self::WrongPin { retries: 0 } | Self::Internal
        )
    }
}

impl CardError {
    /// Maps a non-`9000` status word.
    #[must_use]
    pub const fn from_status(sw: u16) -> Self {
        match sw {
            0x6982 => Self::SecurityStatus,
            0x6983 => Self::PinBlocked,
            0x6985 => Self::Conditions,
            0x6A80 => Self::WrongData,
            0x6A82 => Self::AppletMissing,
            0x6A88 => Self::NotFound,
            0x6A81 | 0x6A86 | 0x6D00 | 0x6E00 => Self::NotSupported,
            0x63C0..=0x63CF => Self::WrongPin {
                retries: (sw & 0x000F) as u8,
            },
            _ => Self::Status(sw),
        }
    }

    /// The status word behind the error, when there is one (logs, 2026-11-12).
    #[must_use]
    pub const fn status_word(self) -> Option<u16> {
        match self {
            Self::Status(sw) => Some(sw),
            Self::WrongData => Some(0x6A80),
            Self::NotFound => Some(0x6A88),
            _ => None,
        }
    }

    /// A stable name for logs (D28: variant names only).
    #[must_use]
    pub const fn log_name(self) -> &'static str {
        match self {
            Self::Transport(TransportFault::NoService) => "transport_no_service",
            Self::Transport(TransportFault::NoReader) => "transport_no_reader",
            Self::Transport(TransportFault::NoCard) => "transport_no_card",
            Self::Transport(TransportFault::Busy) => "transport_busy",
            Self::Transport(TransportFault::Io) => "transport_io",
            Self::CardRemoved => "card_removed",
            Self::AppletMissing => "applet_missing",
            Self::WrongPin { .. } => "wrong_pin",
            Self::PinBlocked => "pin_blocked",
            Self::SecurityStatus => "security_status",
            Self::Conditions => "conditions",
            Self::WrongData => "wrong_data",
            Self::NotSupported => "not_supported",
            Self::NotFound => "not_found",
            Self::Status(_) => "status",
            Self::Malformed => "malformed",
            Self::TooLarge => "too_large",
            Self::ManagementKeyMismatch => "management_key_mismatch",
            Self::ManagementKeyProtected => "management_key_protected",
            Self::ManagementKeyUnknown => "management_key_unknown",
            Self::FirmwareTooOld => "firmware_too_old",
            Self::KdfEnabled => "kdf_enabled",
            Self::KeyMismatch => "key_mismatch",
            Self::ForeignKey => "foreign_key",
            Self::WrongCard => "wrong_card",
            Self::BadSignature => "bad_signature",
            Self::PinFormat => "pin_format",
            Self::Ed25519ImportRefused => "ed25519_import_refused",
            Self::AdminLastTry => "admin_last_try",
            Self::MultipleCards => "multiple_cards",
            Self::DefaultPin => "default_pin",
            Self::NotBlocked => "not_blocked",
            Self::PukLastTry => "puk_last_try",
            Self::Internal => "internal",
        }
    }
}

impl CardError {
    /// The user-facing text in `lang` (spec/10, spec/14 `yw_core::yubikey::text`). `Display` is
    /// the Korean text.
    #[must_use]
    pub fn text_in(self, lang: Lang) -> String {
        let text = match self {
            Self::Transport(TransportFault::NoService) => text::ERR_NO_SERVICE,
            Self::Transport(TransportFault::NoReader | TransportFault::NoCard) => text::ERR_NO_CARD,
            Self::Transport(TransportFault::Busy) => text::ERR_BUSY,
            Self::Transport(TransportFault::Io) | Self::CardRemoved => text::ERR_IO,
            Self::AppletMissing => text::ERR_APPLET_MISSING,
            Self::WrongPin { retries: 1 } => text::ERR_WRONG_PIN_LAST,
            Self::WrongPin {
                retries: retries @ 2..,
            } => return text::ERR_WRONG_PIN.fill(lang, [&retries.to_string()]),
            Self::AdminLastTry => text::ERR_ADMIN_LAST_TRY,
            Self::MultipleCards => text::ERR_MULTIPLE_CARDS,
            Self::DefaultPin => text::ERR_DEFAULT_PIN,
            Self::NotBlocked => text::ERR_NOT_BLOCKED,
            Self::PukLastTry => text::ERR_PUK_LAST_TRY,
            Self::WrongPin { retries: 0 } | Self::PinBlocked => text::ERR_PIN_BLOCKED,
            Self::SecurityStatus | Self::Conditions => text::ERR_REFUSED,
            Self::FirmwareTooOld | Self::NotSupported => text::ERR_NOT_SUPPORTED,
            Self::KdfEnabled => text::ERR_KDF,
            Self::KeyMismatch => text::ERR_KEY_MISMATCH,
            Self::ForeignKey => text::ERR_FOREIGN_KEY,
            Self::WrongCard => text::ERR_WRONG_CARD,
            Self::BadSignature => text::ERR_BAD_SIGNATURE,
            Self::PinFormat => text::ERR_PIN_FORMAT,
            Self::Ed25519ImportRefused => text::ERR_ED25519_IMPORT,
            Self::ManagementKeyMismatch => text::ERR_MGMT_MISMATCH,
            Self::ManagementKeyProtected => text::ERR_MGMT_PROTECTED,
            Self::ManagementKeyUnknown => text::ERR_MGMT_UNKNOWN,
            // The cause in brackets (2026-11-12: one sentence for all six hid it).
            Self::Status(sw) => return text::ERR_STATUS.fill(lang, [&format!("{sw:04X}")]),
            Self::WrongData => return text::ERR_STATUS.fill(lang, ["6A80"]),
            Self::NotFound => return text::ERR_STATUS.fill(lang, ["6A88"]),
            Self::Malformed => text::ERR_MALFORMED,
            Self::TooLarge => text::ERR_TOO_LARGE,
            Self::Internal => text::ERR_INTERNAL,
        };
        text.get(lang).to_owned()
    }
}

impl fmt::Display for CardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text_in(Lang::Ko))
    }
}

impl std::error::Error for CardError {}

/// Firmware version `major.minor.patch`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Firmware {
    /// Major.
    pub major: u8,
    /// Minor.
    pub minor: u8,
    /// Patch.
    pub patch: u8,
}

impl Firmware {
    /// Builds a version.
    #[must_use]
    pub const fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Whether this is at least `other`.
    #[must_use]
    pub fn at_least(self, other: Self) -> bool {
        self >= other
    }
}

impl fmt::Display for Firmware {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// OpenPGP secp256k1 import/sign: OpenPGP card 3.4 on YubiKey 5.2.3+ (spec/10 §2).
pub const MIN_FIRMWARE_OPENPGP: Firmware = Firmware::new(5, 2, 3);
/// PIV Ed25519 support: 5.7.0 adds Ed25519/X25519 to PIV (spec/10 §2). Below this the PIV
/// session is refused.
pub const MIN_FIRMWARE_PIV_ED25519: Firmware = Firmware::new(5, 7, 0);
/// PIV Ed25519 key **import** as documented by Yubico ("as of 5.7.4", spec/10 §2). On
/// 5.7.0–5.7.3 the import is attempted; a refusal becomes [`CardError::Ed25519ImportRefused`].
pub const DOCUMENTED_FIRMWARE_PIV_ED25519_IMPORT: Firmware = Firmware::new(5, 7, 4);
