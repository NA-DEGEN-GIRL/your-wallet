//! Zcash recipient parsing (spec/12 §3): transparent `t1`/`t3` (mainnet) and `tm`/`t2`
//! (testnet) Base58Check addresses, ZIP 320 TEX addresses (bech32m, P2PKH only) and ZIP 316
//! revision 0 unified addresses, of which only the transparent receiver is used. Shielded-only
//! addresses (Sapling `zs…`, Sprout `zc…`, a UA without a transparent receiver) are refused with
//! their own error: this wallet does not build shielded transactions (D36).
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::f4jumble::{MAX_LEN as F4_MAX_LEN, MIN_LEN as F4_MIN_LEN, f4jumble_inv};
use super::network::ZecNetwork;
use crate::btc::bech32::{self, Variant};
use crate::codec::base58;

/// Longest recipient text accepted (a UA with several receivers is a few hundred characters).
pub const MAX_RECIPIENT_TEXT: usize = 1_000;
/// P2PKH `scriptPubKey` length.
pub const P2PKH_SPK_LEN: usize = 25;

/// A transparent destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ZecDest {
    /// Pay-to-public-key-hash (20-byte HASH160).
    P2pkh([u8; 20]),
    /// Pay-to-script-hash (20-byte HASH160).
    P2sh([u8; 20]),
}

impl ZecDest {
    /// The output `scriptPubKey`.
    #[must_use]
    pub fn script_pubkey(&self) -> Vec<u8> {
        match self {
            Self::P2pkh(hash) => crate::btc::script::p2pkh_script_pubkey(hash).to_vec(),
            Self::P2sh(hash) => crate::btc::script::p2sh_script_pubkey(hash).to_vec(),
        }
    }

    /// The Base58Check transparent address of this destination on `network`.
    #[must_use]
    pub fn encode(&self, network: ZecNetwork) -> String {
        let (prefix, hash) = match self {
            Self::P2pkh(hash) => (network.p2pkh_prefix(), hash),
            Self::P2sh(hash) => (network.p2sh_prefix(), hash),
        };
        let mut payload = Vec::with_capacity(22);
        payload.extend_from_slice(&prefix);
        payload.extend_from_slice(hash);
        base58::encode_check(&payload)
    }

    /// The destination of a P2PKH / P2SH `scriptPubKey`.
    #[must_use]
    pub fn from_script_pubkey(script: &[u8]) -> Option<Self> {
        match script {
            [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] => {
                <[u8; 20]>::try_from(hash).ok().map(Self::P2pkh)
            }
            [0xa9, 0x14, hash @ .., 0x87] => <[u8; 20]>::try_from(hash).ok().map(Self::P2sh),
            _ => None,
        }
    }
}

/// How the recipient was written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecipientForm {
    /// A transparent `t…` address.
    Transparent,
    /// A ZIP 320 TEX address (always P2PKH).
    Tex,
    /// A ZIP 316 unified address; its transparent receiver is used.
    Unified,
}

impl RecipientForm {
    /// Stored code (journal, payload).
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Transparent => 1,
            Self::Tex => 2,
            Self::Unified => 3,
        }
    }

    /// The form of a stored code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Transparent),
            2 => Some(Self::Tex),
            3 => Some(Self::Unified),
            _ => None,
        }
    }

    /// Display label of the approval window (spec/12 §9).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Transparent => "일반(transparent) 주소",
            Self::Tex => "TEX 주소 (ZIP 320, 일반 주소로만 보냄)",
            Self::Unified => "통합 주소(UA)의 일반(transparent) 수신자",
        }
    }
}

/// A parsed recipient.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecRecipient {
    /// Where the funds go.
    pub dest: ZecDest,
    /// How it was written.
    pub form: RecipientForm,
    /// The text as entered (trimmed; a bech32 string lowercased).
    pub text: String,
}

/// Why a recipient was refused (fixed texts, never the input).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZecAddressError {
    /// Empty input.
    Empty,
    /// Too long or not ASCII.
    Format,
    /// Base58Check or bech32m checksum mismatch.
    Checksum,
    /// A valid address of the other Zcash network.
    WrongNetwork,
    /// A Sapling / Sprout shielded address.
    Shielded,
    /// A unified address without a transparent receiver.
    UnifiedNoTransparent,
    /// A malformed unified address (F4Jumble, padding, items, order).
    UnifiedInvalid,
    /// A ZIP 316 revision-2 address (`tu…`, Draft) or a UA with MUST-understand metadata.
    UnifiedUnsupported,
    /// Anything else (another coin, an unknown prefix).
    Unknown,
}

impl ZecAddressError {
    /// The fixed Korean text (spec/12 §11).
    #[must_use]
    pub const fn text(self) -> &'static str {
        match self {
            Self::Empty => "받는 주소를 입력하세요.",
            Self::Format | Self::Unknown => "Zcash 주소가 아닙니다.",
            Self::Checksum => "주소의 체크섬이 맞지 않습니다. 주소를 다시 확인하세요.",
            Self::WrongNetwork => "다른 Zcash 네트워크의 주소입니다.",
            Self::Shielded => {
                "비공개(shielded) 주소로는 보낼 수 없습니다. 이 지갑은 일반(transparent) 전송만 합니다."
            }
            Self::UnifiedNoTransparent => {
                "이 통합 주소(UA)에는 일반(transparent) 수신자가 없습니다. 받는 사람에게 t 주소나 TEX 주소를 요청하세요."
            }
            Self::UnifiedInvalid => "통합 주소(UA) 형식이 올바르지 않습니다.",
            Self::UnifiedUnsupported => {
                "이 통합 주소(UA) 형식(revision 1 또는 메타데이터)은 아직 지원하지 않습니다. t 주소나 TEX 주소를 요청하세요."
            }
        }
    }
}

impl fmt::Display for ZecAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text())
    }
}

impl std::error::Error for ZecAddressError {}

/// UA receiver typecodes (ZIP 316).
const TYPE_P2PKH: u64 = 0x00;
const TYPE_P2SH: u64 = 0x01;
const TYPE_SAPLING: u64 = 0x02;
const TYPE_ORCHARD: u64 = 0x03;
/// Metadata typecodes 0xC0–0xFC (not receivers); anything above is an unknown receiver.
const TYPE_METADATA_START: u64 = 0xC0;
const TYPE_METADATA_END: u64 = 0xFC;
/// MUST-understand metadata 0xE0–0xFC: a revision-0 UA must not contain any (refused).
const TYPE_MUST_UNDERSTAND_START: u64 = 0xE0;

/// W-ADDR-3 for Zcash transparent addresses (spec/12 §11): `Some((prefix, suffix))` for two
/// different `t1…`/`t3…`/`tm…`/`t2…` addresses whose equal leading and trailing characters after
/// the two-character prefix total at least 5 in any split — the Bitcoin rule
/// ([`crate::btc::address::look_alike_parts`]). A TEX or unified recipient is compared by the
/// encoding of its transparent receiver.
#[must_use]
pub fn look_alike_ends(a: &str, b: &str) -> Option<(usize, usize)> {
    crate::btc::address::look_alike_parts(a.get(2..)?, b.get(2..)?)
}

/// Parses `text` as a recipient on `network`.
///
/// # Errors
///
/// [`ZecAddressError`].
pub fn parse_recipient(text: &str, network: ZecNetwork) -> Result<ZecRecipient, ZecAddressError> {
    let text = text.trim_matches(|c: char| matches!(c, ' ' | '\t' | '\r' | '\n'));
    if text.is_empty() {
        return Err(ZecAddressError::Empty);
    }
    if text.len() > MAX_RECIPIENT_TEXT || !text.is_ascii() {
        return Err(ZecAddressError::Format);
    }
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("zcash:") {
        return Err(ZecAddressError::Unknown);
    }
    if let Some(form) = bech32_form(&lower) {
        return parse_bech32(text, &lower, form, network);
    }
    parse_base58(text, network)
}

#[derive(Clone, Copy)]
enum Bech32Form {
    Tex(ZecNetwork),
    Unified(ZecNetwork),
    UnifiedR1,
    Sapling,
}

fn bech32_form(lower: &str) -> Option<Bech32Form> {
    let hrp = lower.get(..lower.rfind('1')?)?;
    match hrp {
        "tex" => Some(Bech32Form::Tex(ZecNetwork::Mainnet)),
        "textest" => Some(Bech32Form::Tex(ZecNetwork::Testnet)),
        "u" => Some(Bech32Form::Unified(ZecNetwork::Mainnet)),
        "utest" => Some(Bech32Form::Unified(ZecNetwork::Testnet)),
        // ZIP 316 revision 2 (Draft): `tu`/`tutest` may carry transparent receivers but are not
        // read yet; `zu`/`zutest` are shielded-only.
        "tu" | "tutest" => Some(Bech32Form::UnifiedR1),
        "zs" | "ztestsapling" | "zu" | "zutest" => Some(Bech32Form::Sapling),
        _ => None,
    }
}

fn parse_bech32(
    text: &str,
    lower: &str,
    form: Bech32Form,
    network: ZecNetwork,
) -> Result<ZecRecipient, ZecAddressError> {
    if matches!(form, Bech32Form::Sapling) {
        return Err(ZecAddressError::Shielded);
    }
    let decoded =
        bech32::decode_limited(text, MAX_RECIPIENT_TEXT).map_err(|error| match error {
            bech32::Bech32Error::Checksum => ZecAddressError::Checksum,
            _ => ZecAddressError::Format,
        })?;
    match form {
        Bech32Form::Sapling => Err(ZecAddressError::Shielded),
        Bech32Form::UnifiedR1 => Err(ZecAddressError::UnifiedUnsupported),
        Bech32Form::Tex(_) | Bech32Form::Unified(_) if decoded.variant != Variant::Bech32m => {
            Err(ZecAddressError::Checksum)
        }
        Bech32Form::Tex(of) => {
            let bytes =
                bech32::from_five_bits(&decoded.data).map_err(|_| ZecAddressError::Format)?;
            let hash =
                <[u8; 20]>::try_from(bytes.as_slice()).map_err(|_| ZecAddressError::Format)?;
            if of != network {
                return Err(ZecAddressError::WrongNetwork);
            }
            Ok(ZecRecipient {
                dest: ZecDest::P2pkh(hash),
                form: RecipientForm::Tex,
                text: lower.to_owned(),
            })
        }
        Bech32Form::Unified(of) => {
            let jumbled = bech32::from_five_bits(&decoded.data)
                .map_err(|_| ZecAddressError::UnifiedInvalid)?;
            let dest = unified_transparent(&jumbled, of.ua_hrp())?;
            if of != network {
                return Err(ZecAddressError::WrongNetwork);
            }
            Ok(ZecRecipient {
                dest,
                form: RecipientForm::Unified,
                text: lower.to_owned(),
            })
        }
    }
}

fn read_compact(bytes: &[u8], position: &mut usize) -> Option<u64> {
    let first = *bytes.get(*position)?;
    let (value, width) = match first {
        0xfd => {
            let raw = bytes.get(position.checked_add(1)?..position.checked_add(3)?)?;
            let value = u16::from_le_bytes(<[u8; 2]>::try_from(raw).ok()?);
            if value < 0xfd {
                return None;
            }
            (u64::from(value), 3)
        }
        0xfe => {
            let raw = bytes.get(position.checked_add(1)?..position.checked_add(5)?)?;
            let value = u32::from_le_bytes(<[u8; 4]>::try_from(raw).ok()?);
            if value < 0x1_0000 {
                return None;
            }
            (u64::from(value), 5)
        }
        0xff => return None,
        small => (u64::from(small), 1),
    };
    *position = position.checked_add(width)?;
    Some(value)
}

/// The unified items `(typecode, value)` of a jumbled UA payload (ZIP 316 decoding: F4Jumble⁻¹,
/// the 16-byte HRP padding, `CompactSize` typecode and length per item).
///
/// # Errors
///
/// [`ZecAddressError::UnifiedInvalid`].
pub fn unified_items(jumbled: &[u8], hrp: &str) -> Result<Vec<(u64, Vec<u8>)>, ZecAddressError> {
    if !(F4_MIN_LEN..=F4_MAX_LEN).contains(&jumbled.len()) {
        return Err(ZecAddressError::UnifiedInvalid);
    }
    let raw = f4jumble_inv(jumbled).ok_or(ZecAddressError::UnifiedInvalid)?;
    let split = raw
        .len()
        .checked_sub(16)
        .ok_or(ZecAddressError::UnifiedInvalid)?;
    let (items, padding) = raw.split_at(split);
    let mut expected = [0_u8; 16];
    if hrp.len() > 16 {
        return Err(ZecAddressError::UnifiedInvalid);
    }
    for (slot, byte) in expected.iter_mut().zip(hrp.bytes()) {
        *slot = byte;
    }
    if padding != expected {
        return Err(ZecAddressError::UnifiedInvalid);
    }
    let mut out = Vec::new();
    let mut position = 0_usize;
    while position < items.len() {
        let typecode = read_compact(items, &mut position).ok_or(ZecAddressError::UnifiedInvalid)?;
        let length = read_compact(items, &mut position).ok_or(ZecAddressError::UnifiedInvalid)?;
        let length = usize::try_from(length).map_err(|_| ZecAddressError::UnifiedInvalid)?;
        let end = position
            .checked_add(length)
            .ok_or(ZecAddressError::UnifiedInvalid)?;
        let value = items
            .get(position..end)
            .ok_or(ZecAddressError::UnifiedInvalid)?;
        out.push((typecode, value.to_vec()));
        position = end;
    }
    Ok(out)
}

/// The transparent receiver of a revision-0 UA, after the ZIP 316 structural rules: items in
/// strictly increasing typecode order (no duplicates), known receivers of the right length, not
/// both P2PKH and P2SH, at least one shielded receiver, no metadata typecodes.
fn unified_transparent(jumbled: &[u8], hrp: &str) -> Result<ZecDest, ZecAddressError> {
    let items = unified_items(jumbled, hrp)?;
    let mut previous: Option<u64> = None;
    let mut transparent = None;
    let mut shielded = false;
    for (typecode, value) in &items {
        if previous.is_some_and(|last| *typecode <= last) {
            return Err(ZecAddressError::UnifiedInvalid);
        }
        previous = Some(*typecode);
        let expected_len = match *typecode {
            TYPE_P2PKH | TYPE_P2SH => Some(20),
            TYPE_SAPLING | TYPE_ORCHARD => Some(43),
            code if (TYPE_MUST_UNDERSTAND_START..=TYPE_METADATA_END).contains(&code) => {
                return Err(ZecAddressError::UnifiedUnsupported);
            }
            _ => None,
        };
        if expected_len.is_some_and(|len| value.len() != len) {
            return Err(ZecAddressError::UnifiedInvalid);
        }
        match *typecode {
            TYPE_P2PKH | TYPE_P2SH => {
                if transparent.is_some() {
                    return Err(ZecAddressError::UnifiedInvalid);
                }
                let hash = <[u8; 20]>::try_from(value.as_slice())
                    .map_err(|_| ZecAddressError::UnifiedInvalid)?;
                transparent = Some(if *typecode == TYPE_P2PKH {
                    ZecDest::P2pkh(hash)
                } else {
                    ZecDest::P2sh(hash)
                });
            }
            // Optional metadata is skipped (it is not a receiver).
            code if (TYPE_METADATA_START..=TYPE_METADATA_END).contains(&code) => {}
            // Sapling, Orchard and unknown (future) shielded receivers.
            _ => shielded = true,
        }
    }
    if !shielded {
        return Err(ZecAddressError::UnifiedInvalid);
    }
    transparent.ok_or(ZecAddressError::UnifiedNoTransparent)
}

fn parse_base58(text: &str, network: ZecNetwork) -> Result<ZecRecipient, ZecAddressError> {
    let lower2 = text.get(..2).unwrap_or_default();
    if matches!(lower2, "zc" | "zt") {
        // Sprout addresses: Base58Check with a 2-byte prefix and 64 bytes.
        return Err(ZecAddressError::Shielded);
    }
    let payload = base58::decode_check(text).map_err(|error| match error {
        base58::Base58Error::InvalidChecksum => ZecAddressError::Checksum,
        _ => ZecAddressError::Unknown,
    })?;
    let (prefix, hash) = payload
        .split_at_checked(2)
        .ok_or(ZecAddressError::Unknown)?;
    let hash = <[u8; 20]>::try_from(hash).map_err(|_| ZecAddressError::Unknown)?;
    for of in ZecNetwork::ALL {
        let dest = if prefix == of.p2pkh_prefix() {
            ZecDest::P2pkh(hash)
        } else if prefix == of.p2sh_prefix() {
            ZecDest::P2sh(hash)
        } else {
            continue;
        };
        if of != network {
            return Err(ZecAddressError::WrongNetwork);
        }
        return Ok(ZecRecipient {
            dest,
            form: RecipientForm::Transparent,
            text: text.to_owned(),
        });
    }
    Err(ZecAddressError::Unknown)
}

/// The TEX address of a P2PKH hash on `network` (ZIP 320; tests and display).
#[must_use]
pub fn encode_tex(hash: &[u8; 20], network: ZecNetwork) -> String {
    bech32::assemble(
        network.tex_hrp(),
        &bech32::to_five_bits(hash),
        Variant::Bech32m,
    )
}
