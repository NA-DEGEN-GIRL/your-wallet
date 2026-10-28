//! Bitcoin addresses (spec/08 §3.1, §3.3, §6.1, §6.3, §13): the five sendable script kinds, the
//! paste-input policy table (first matching rule wins), canonical re-encoding, script ↔ kind
//! conversion, `HASH160`, the receive/change program by public derivation, and `BtcAddress`
//! (our own P2WPKH addresses only, for indexer requests).
//!
//! Displayed addresses are always `encode_address(kind)`, never the pasted text.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use ripemd::Ripemd160;
use secp256k1::XOnlyPublicKey;
use sha2::{Digest, Sha256};

use super::bech32::{self, Bech32Error};
use super::network::BtcNetwork;
use super::script;
use crate::bip32::path::BtcChain;
use crate::bip32::{AccountXpub, derive_public_child_with};
use crate::codec::base58::{self, Base58Error};
use crate::entropy::{OsRandom, secp_context};
use crate::error::KeyError;

/// base58check payload length of an address (version 1 + hash 20).
const BASE58_PAYLOAD_LEN: usize = 21;
/// Longest base58 address input (spec/08 §6.1).
const MAX_BASE58_INPUT: usize = 64;
/// Prefixes of extended private keys (rule 4).
const XPRV_PREFIXES: [&str; 6] = ["xprv", "tprv", "yprv", "zprv", "vprv", "uprv"];
/// Lightning prefixes, compared case-insensitively (rule 3).
const LIGHTNING_PREFIXES: [&str; 6] = ["lightning:", "lnbc", "lntb", "lntbs", "lnbcrt", "lnurl"];
/// WIF version bytes (mainnet, test networks).
const WIF_VERSIONS: [u8; 2] = [0x80, 0xef];
/// Every base58 version byte of the two supported networks (P2PKH, P2SH).
const KNOWN_VERSIONS: [u8; 4] = [0x00, 0x05, 0x6f, 0xc4];
/// bech32 HRPs of Bitcoin networks (mainnet, test networks, regtest).
const BITCOIN_HRPS: [&str; 3] = ["bc", "tb", "bcrt"];
/// Pay-to-anchor witness program (v1, BIP-less standardness rule of Core 28).
const P2A_PROGRAM: [u8; 2] = [0x4e, 0x73];
const BASE58_ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// A sendable output script kind (spec/08 §6.3), with its hash or program.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptKind {
    /// `76 a9 14 <h20> 88 ac`.
    P2pkh([u8; 20]),
    /// `a9 14 <h20> 87`.
    P2sh([u8; 20]),
    /// `00 14 <h20>`.
    P2wpkh([u8; 20]),
    /// `00 20 <h32>`.
    P2wsh([u8; 32]),
    /// `51 20 <x32>` (valid x-only key when parsed from an address).
    P2tr([u8; 32]),
}

impl fmt::Debug for ScriptKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, bytes): (&str, &[u8]) = match self {
            Self::P2pkh(hash) => ("P2pkh", hash),
            Self::P2sh(hash) => ("P2sh", hash),
            Self::P2wpkh(program) => ("P2wpkh", program),
            Self::P2wsh(program) => ("P2wsh", program),
            Self::P2tr(key) => ("P2tr", key),
        };
        write!(formatter, "{name}({})", crate::hex::encode(bytes))
    }
}

impl ScriptKind {
    /// The approval field `0x0602` text (spec/08 §10).
    #[must_use]
    pub const fn type_label(&self) -> &'static str {
        match self {
            Self::P2pkh(_) => "P2PKH(레거시)",
            Self::P2sh(_) => "P2SH(스크립트)",
            Self::P2wpkh(_) => "P2WPKH",
            Self::P2wsh(_) => "P2WSH(스크립트)",
            Self::P2tr(_) => "P2TR",
        }
    }
}

/// Address input rejection (spec/08 §6.1–§6.3). [`AddressError::text`] gives the fixed §13 text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AddressError {
    /// Nothing left after trimming.
    Empty,
    /// Inner whitespace or control characters, or a character outside the bech32 data set.
    InvalidCharacter,
    /// A `bitcoin:` URI.
    UriNotSupported,
    /// A Lightning invoice, LNURL or `lightning:` URI.
    Lightning,
    /// An extended private key prefix or a WIF private key.
    LooksLikePrivateKey,
    /// Silent payment (`sp1`/`tsp1`).
    SilentPayment,
    /// An address of the other Bitcoin network (or regtest).
    WrongNetwork,
    /// bech32 text with both upper- and lowercase letters.
    MixedCase,
    /// bech32 checksum matches neither variant.
    Bech32Checksum,
    /// v0 with bech32m or v1+ with bech32.
    WrongChecksumVariant,
    /// Invalid 5→8-bit padding.
    InvalidPadding,
    /// Program length not allowed for the version (also bech32 text length errors).
    InvalidProgramLength,
    /// Missing or > 16 witness version.
    InvalidWitnessVersion,
    /// Pay-to-anchor (`bc1pfeessrawgf`): anyone can spend it.
    PayToAnchor,
    /// v1/32 program that is not a valid x-only key: the coins would be lost.
    InvalidTaprootKey,
    /// Witness versions 2–16 (deliberately stricter than BIP350).
    UnsupportedWitnessVersion,
    /// base58check payload not 21 bytes (or input longer than 64 characters).
    Base58Length,
    /// base58check checksum mismatch.
    Base58Checksum,
    /// base58 version byte of no Bitcoin network.
    UnknownVersion,
    /// Anything else.
    NotBitcoinAddress,
}

impl AddressError {
    /// The fixed Korean text of spec/08 §13 for a wallet on `net`.
    #[must_use]
    pub const fn text(self, net: BtcNetwork) -> &'static str {
        match self {
            Self::Empty => "주소를 입력하세요",
            Self::InvalidCharacter => "허용되지 않는 문자가 있습니다",
            Self::NotBitcoinAddress => "Bitcoin 주소가 아닙니다",
            Self::MixedCase => "대소문자가 섞인 bech32 주소는 받지 않습니다",
            Self::Bech32Checksum | Self::Base58Checksum => "주소 체크섬이 틀립니다(오타 확인)",
            Self::WrongChecksumVariant
            | Self::InvalidPadding
            | Self::InvalidProgramLength
            | Self::InvalidWitnessVersion
            | Self::Base58Length => "주소 형식이 올바르지 않습니다",
            Self::WrongNetwork => match net {
                BtcNetwork::Mainnet => "다른 네트워크의 주소입니다(지갑: MAINNET)",
                BtcNetwork::Testnet4 => "다른 네트워크의 주소입니다(지갑: TESTNET4)",
            },
            Self::UnknownVersion => "지원하지 않는 주소 버전입니다",
            Self::PayToAnchor => "P2A 앵커 출력은 누구나 가져갈 수 있어 보낼 수 없습니다",
            Self::InvalidTaprootKey => "유효하지 않은 Taproot 키입니다. 보내면 잃습니다",
            Self::UnsupportedWitnessVersion => "지원하지 않는 세그윗 버전(v2–v16) 주소입니다",
            Self::SilentPayment => "사일런트 페이먼트 미지원",
            Self::Lightning => "라이트닝 미지원",
            Self::UriNotSupported => "주소만 붙여넣으세요",
            Self::LooksLikePrivateKey => "개인키처럼 보입니다. 다른 곳에 붙여넣지 마세요",
        }
    }
}

impl fmt::Display for AddressError {
    /// The §13 text; `WrongNetwork` without the wallet network (use [`AddressError::text`]).
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongNetwork => formatter.write_str("다른 네트워크의 주소입니다"),
            other => formatter.write_str(other.text(BtcNetwork::Mainnet)),
        }
    }
}

impl std::error::Error for AddressError {}

fn starts_with_ignore_case(text: &str, prefix: &str) -> bool {
    text.as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

fn is_base58(text: &str) -> bool {
    text.bytes().all(|byte| BASE58_ALPHABET.contains(&byte))
}

/// Rule 4: an extended private key prefix, or base58check WIF (33/34-byte payload, version
/// 0x80/0xef). The decoded payload is a secret and is wiped.
fn looks_like_private_key(text: &str) -> bool {
    if XPRV_PREFIXES.iter().any(|prefix| text.starts_with(prefix)) {
        return true;
    }
    if text.len() > MAX_BASE58_INPUT || !is_base58(text) {
        return false;
    }
    base58::decode_check_secret(text).is_ok_and(|payload| {
        matches!(payload.len(), 33 | 34)
            && payload
                .first()
                .is_some_and(|version| WIF_VERSIONS.contains(version))
    })
}

const fn map_bech32(error: Bech32Error) -> AddressError {
    match error {
        Bech32Error::InvalidCharacter => AddressError::InvalidCharacter,
        Bech32Error::MixedCase => AddressError::MixedCase,
        Bech32Error::Checksum => AddressError::Bech32Checksum,
        Bech32Error::InvalidWitnessVersion => AddressError::InvalidWitnessVersion,
        Bech32Error::InvalidPadding => AddressError::InvalidPadding,
        Bech32Error::WrongChecksumVariant => AddressError::WrongChecksumVariant,
        // Text length (8–90) and data shorter than the checksum are format errors (spec/08 §6.2).
        Bech32Error::InvalidLength | Bech32Error::ShortData | Bech32Error::InvalidProgramLength => {
            AddressError::InvalidProgramLength
        }
        Bech32Error::NoSeparator | Bech32Error::EmptyHrp => AddressError::NotBitcoinAddress,
    }
}

/// Rules 5b–5g on a string whose HRP is the wallet network's.
fn parse_segwit(text: &str) -> Result<ScriptKind, AddressError> {
    let decoded = bech32::decode_segwit(text).map_err(map_bech32)?;
    let program = decoded.program.as_slice();
    match decoded.version {
        0 => {
            if let Ok(hash) = <[u8; 20]>::try_from(program) {
                Ok(ScriptKind::P2wpkh(hash))
            } else if let Ok(hash) = <[u8; 32]>::try_from(program) {
                Ok(ScriptKind::P2wsh(hash))
            } else {
                Err(AddressError::InvalidProgramLength)
            }
        }
        1 => {
            if program == P2A_PROGRAM {
                return Err(AddressError::PayToAnchor);
            }
            let key =
                <[u8; 32]>::try_from(program).map_err(|_| AddressError::InvalidProgramLength)?;
            XOnlyPublicKey::from_byte_array(key)
                .map(|_| ScriptKind::P2tr(key))
                .map_err(|_| AddressError::InvalidTaprootKey)
        }
        _ => Err(AddressError::UnsupportedWitnessVersion),
    }
}

/// Rule 6 (spec/08 §6.1): base58check, 21-byte payload, version policy.
fn parse_base58(text: &str, net: BtcNetwork) -> Result<ScriptKind, AddressError> {
    if text.len() > MAX_BASE58_INPUT {
        return Err(AddressError::Base58Length);
    }
    let payload = base58::decode_check(text).map_err(|error| match error {
        Base58Error::InvalidChecksum => AddressError::Base58Checksum,
        _ => AddressError::Base58Length,
    })?;
    if payload.len() != BASE58_PAYLOAD_LEN {
        return Err(AddressError::Base58Length);
    }
    let (version, hash) = payload.split_first().ok_or(AddressError::Base58Length)?;
    let hash = <[u8; 20]>::try_from(hash).map_err(|_| AddressError::Base58Length)?;
    if *version == net.p2pkh_version() {
        Ok(ScriptKind::P2pkh(hash))
    } else if *version == net.p2sh_version() {
        Ok(ScriptKind::P2sh(hash))
    } else if KNOWN_VERSIONS.contains(version) {
        Err(AddressError::WrongNetwork)
    } else {
        Err(AddressError::UnknownVersion)
    }
}

/// Parses pasted address text for a wallet on `net` (spec/08 §6.3 table, first match wins):
/// trim ASCII `\t\r\n ` → empty / inner whitespace or control → `bitcoin:` → Lightning →
/// private keys → HRP (`sp`/`tsp`, other Bitcoin network) → bech32 policy → base58 policy →
/// `NotBitcoinAddress`. The network is never inferred from the text.
///
/// # Errors
///
/// The [`AddressError`] of the first matching rule.
pub fn parse_address(input: &str, net: BtcNetwork) -> Result<ScriptKind, AddressError> {
    let text = input.trim_matches(|character| matches!(character, ' ' | '\t' | '\r' | '\n'));
    if text.is_empty() {
        return Err(AddressError::Empty);
    }
    if text
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(AddressError::InvalidCharacter);
    }
    if starts_with_ignore_case(text, "bitcoin:") {
        return Err(AddressError::UriNotSupported);
    }
    if LIGHTNING_PREFIXES
        .iter()
        .any(|prefix| starts_with_ignore_case(text, prefix))
    {
        return Err(AddressError::Lightning);
    }
    if looks_like_private_key(text) {
        return Err(AddressError::LooksLikePrivateKey);
    }
    if let Some(hrp) = text.rfind('1').and_then(|separator| text.get(..separator)) {
        if hrp.eq_ignore_ascii_case("sp") || hrp.eq_ignore_ascii_case("tsp") {
            return Err(AddressError::SilentPayment);
        }
        if BITCOIN_HRPS
            .iter()
            .any(|known| hrp.eq_ignore_ascii_case(known))
        {
            if !hrp.eq_ignore_ascii_case(net.hrp()) {
                return Err(AddressError::WrongNetwork);
            }
            return parse_segwit(text);
        }
    }
    if is_base58(text) {
        return parse_base58(text, net);
    }
    Err(AddressError::NotBitcoinAddress)
}

/// The canonical address of `kind` on `net`: base58check, or lowercase bech32 (v0) / bech32m
/// (v1).
#[must_use]
pub fn encode_address(kind: &ScriptKind, net: BtcNetwork) -> String {
    let base58 = |version: u8, hash: &[u8; 20]| {
        let mut payload = [0_u8; BASE58_PAYLOAD_LEN];
        if let Some((first, rest)) = payload.split_first_mut() {
            *first = version;
            rest.copy_from_slice(hash);
        }
        base58::encode_check(&payload)
    };
    match kind {
        ScriptKind::P2pkh(hash) => base58(net.p2pkh_version(), hash),
        ScriptKind::P2sh(hash) => base58(net.p2sh_version(), hash),
        ScriptKind::P2wpkh(program) => bech32::segwit_string(net.hrp(), 0, program),
        ScriptKind::P2wsh(program) => bech32::segwit_string(net.hrp(), 0, program),
        ScriptKind::P2tr(key) => bech32::segwit_string(net.hrp(), 1, key),
    }
}

/// The scriptPubKey of `kind` (spec/08 §6.4).
#[must_use]
pub fn script_pubkey(kind: &ScriptKind) -> Vec<u8> {
    match kind {
        ScriptKind::P2pkh(hash) => script::p2pkh_script_pubkey(hash).to_vec(),
        ScriptKind::P2sh(hash) => script::p2sh_script_pubkey(hash).to_vec(),
        ScriptKind::P2wpkh(program) => script::p2wpkh_script_pubkey(program).to_vec(),
        ScriptKind::P2wsh(program) => script::p2wsh_script_pubkey(program).to_vec(),
        ScriptKind::P2tr(key) => script::p2tr_script_pubkey(key).to_vec(),
    }
}

/// The kind of a scriptPubKey, for display: exactly the five templates, `None` otherwise. The
/// match is structural (a P2TR key is not re-validated here).
#[must_use]
pub fn kind_from_script(spk: &[u8]) -> Option<ScriptKind> {
    match spk {
        [0x76, 0xa9, 0x14, middle @ .., 0x88, 0xac] => {
            <[u8; 20]>::try_from(middle).ok().map(ScriptKind::P2pkh)
        }
        [0xa9, 0x14, middle @ .., 0x87] => <[u8; 20]>::try_from(middle).ok().map(ScriptKind::P2sh),
        [0x00, 0x14, rest @ ..] => <[u8; 20]>::try_from(rest).ok().map(ScriptKind::P2wpkh),
        [0x00, 0x20, rest @ ..] => <[u8; 32]>::try_from(rest).ok().map(ScriptKind::P2wsh),
        [0x51, 0x20, rest @ ..] => <[u8; 32]>::try_from(rest).ok().map(ScriptKind::P2tr),
        _ => None,
    }
}

/// `HASH160(data) = RIPEMD160(SHA256(data))`.
#[must_use]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    let digest = Ripemd160::digest(Sha256::digest(data));
    let mut out = [0_u8; 20];
    for (slot, byte) in out.iter_mut().zip(digest.iter()) {
        *slot = *byte;
    }
    out
}

/// The P2WPKH program `HASH160(K)` of `m/84'/{coin}'/0'/{chain}/{index}` from the cached account
/// node by two `CKDpub` steps (spec/08 §3.1). No vault and no private key.
///
/// # Errors
///
/// [`KeyError::InvalidPath`] for a hardened `index`, [`KeyError::DerivationFailed`],
/// [`KeyError::RandomnessUnavailable`] for the context seed.
pub fn p2wpkh_program(
    acct: &AccountXpub,
    chain: BtcChain,
    index: u32,
) -> Result<[u8; 20], KeyError> {
    if index & crate::bip32::HARDENED != 0 {
        return Err(KeyError::InvalidPath);
    }
    let ctx = secp_context(&mut OsRandom)?;
    let chain_node = derive_public_child_with(&ctx, acct, chain.index())?;
    let leaf = derive_public_child_with(&ctx, &chain_node, index)?;
    Ok(hash160(&leaf.pubkey))
}

/// One of our own receive/change addresses: lowercase bech32 P2WPKH, built only from a network
/// and a 20-byte program (spec/08 §3.3), so indexer requests can only carry `[0-9a-z]` text.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BtcAddress {
    text: String,
    network: BtcNetwork,
    program: [u8; 20],
}

impl BtcAddress {
    /// The P2WPKH address of `program` on `net`.
    #[must_use]
    pub fn p2wpkh(net: BtcNetwork, program: &[u8; 20]) -> Self {
        Self {
            text: encode_address(&ScriptKind::P2wpkh(*program), net),
            network: net,
            program: *program,
        }
    }

    /// The address text (lowercase, `[0-9a-z]` only).
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The network it was encoded for.
    #[must_use]
    pub const fn network(&self) -> BtcNetwork {
        self.network
    }

    /// The witness program.
    #[must_use]
    pub const fn program(&self) -> &[u8; 20] {
        &self.program
    }

    /// `00 14 <program>`.
    #[must_use]
    pub fn script_pubkey(&self) -> [u8; 22] {
        script::p2wpkh_script_pubkey(&self.program)
    }
}

impl fmt::Debug for BtcAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "BtcAddress({})", self.text)
    }
}

impl fmt::Display for BtcAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.text)
    }
}
