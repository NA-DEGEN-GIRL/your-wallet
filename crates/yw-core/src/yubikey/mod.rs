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
//! | [`sign`] | signing on the card for a planned slot (PIN per operation) |
//! | [`mock`] | APDU-level emulator of both applets for tests (yw-app uses it only under `cfg(test)`; the check script forbids dev-dependencies, so it is always compiled) |
//!
//! yw-core has no OS access: the transport is the [`CardTransport`] trait (PC/SC in yw-win) and
//! the PIV management-key block cipher is [`piv::MgmtCipher`] (Windows CNG in yw-win).
//!
//! **Hardware rule:** nothing in the gate talks to a real card. The only code that writes to a
//! card is [`enrol`] and the PIN/management-key change helpers, and it runs only when the user
//! starts the enrolment wizard.
#![allow(
    clippy::doc_markdown,
    reason = "product names (YubiKey, OpenPGP) appear throughout the card documentation"
)]

use core::fmt;

pub mod apdu;
pub mod enrol;
pub mod mock;
pub mod openpgp;
pub mod piv;
pub mod plan;
pub mod record;
pub mod sig;
pub mod sign;
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
    /// Wrong PIN / admin PIN; `retries` left (`63Cx`).
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
    /// The serial of the inserted card is not one that holds this key.
    WrongCard,
    /// The card produced a signature that does not verify for the recorded public key.
    BadSignature,
    /// The PIN or admin PIN does not meet the applet's length rules.
    PinFormat,
    /// The card refused an Ed25519 PIV import on firmware 5.7.0–5.7.3 (Yubico documents the
    /// import from 5.7.4, spec/10 §2).
    Ed25519ImportRefused,
    /// Internal error (derivation failure, invariant).
    Internal,
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
            Self::WrongCard => "wrong_card",
            Self::BadSignature => "bad_signature",
            Self::PinFormat => "pin_format",
            Self::Ed25519ImportRefused => "ed25519_import_refused",
            Self::Internal => "internal",
        }
    }
}

impl fmt::Display for CardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(TransportFault::NoService) => {
                formatter.write_str("스마트 카드 서비스가 실행 중이 아닙니다.")
            }
            Self::Transport(TransportFault::NoReader | TransportFault::NoCard) => {
                formatter.write_str("YubiKey를 찾을 수 없습니다. 연결한 뒤 다시 시도하세요.")
            }
            Self::Transport(TransportFault::Busy) => formatter.write_str(
                "다른 프로그램이 YubiKey를 쓰고 있습니다. 그 프로그램을 닫고 다시 시도하세요.",
            ),
            Self::Transport(TransportFault::Io) | Self::CardRemoved => {
                formatter.write_str("YubiKey와 통신하지 못했습니다. 다시 연결하고 시도하세요.")
            }
            Self::AppletMissing => {
                formatter.write_str("이 장치에는 필요한 기능(OpenPGP 또는 PIV)이 없습니다.")
            }
            Self::WrongPin { retries } => {
                write!(formatter, "PIN이 틀렸습니다. 남은 시도 {retries}회.")
            }
            Self::PinBlocked => formatter.write_str(
                "PIN이 잠겼습니다. PUK(또는 관리자 PIN)로 풀거나 복구 단어로 다시 등록하세요.",
            ),
            Self::SecurityStatus | Self::Conditions => formatter.write_str(
                "YubiKey가 작업을 거부했습니다. PIN 확인과 터치(시간 안에)를 다시 시도하세요.",
            ),
            Self::FirmwareTooOld | Self::NotSupported => {
                formatter.write_str("이 YubiKey 펌웨어는 이 기능을 지원하지 않습니다.")
            }
            Self::KdfEnabled => formatter
                .write_str("OpenPGP PIN KDF가 켜진 YubiKey는 지원하지 않습니다(spec/10 §11)."),
            Self::KeyMismatch => formatter
                .write_str("YubiKey의 공개키가 기록과 다릅니다. 등록한 YubiKey인지 확인하세요."),
            Self::WrongCard => formatter
                .write_str("이 YubiKey에는 이 계정의 키가 없습니다. 등록한 YubiKey를 연결하세요."),
            Self::BadSignature => formatter.write_str("서명 검증 실패(YubiKey 응답 오류)"),
            Self::PinFormat => formatter.write_str("PIN 길이가 맞지 않습니다."),
            Self::Ed25519ImportRefused => formatter.write_str(
                "이 YubiKey 펌웨어(5.7.0–5.7.3)는 Ed25519 키 가져오기를 거부했습니다. Yubico는 5.7.4부터 지원한다고 안내합니다. Solana 슬롯 없이 등록하거나 5.7.4 이상의 YubiKey를 쓰세요.",
            ),
            Self::ManagementKeyMismatch => formatter.write_str("PIV 관리 키가 맞지 않습니다."),
            Self::ManagementKeyProtected => formatter.write_str(
                "이 YubiKey의 PIV 관리 키는 PIN으로 보호되어 있습니다. PIV PIN을 입력해 다시 시도하세요.",
            ),
            Self::ManagementKeyUnknown => formatter.write_str(
                "PIV 관리 키가 기본값도 PIN 보호도 아닙니다. 'ykman piv access change-management-key --generate --protect'로 PIN 보호로 바꾼 뒤 다시 시도하세요.",
            ),
            Self::WrongData
            | Self::NotFound
            | Self::Status(_)
            | Self::Malformed
            | Self::TooLarge
            | Self::Internal => formatter.write_str("YubiKey 작업 중 오류가 발생했습니다."),
        }
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
