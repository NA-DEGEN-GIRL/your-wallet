//! Bitcoin message signatures for dApp ownership proof (spec/08 §17): BIP137 "Bitcoin Signed
//! Message" (compact recoverable ECDSA, base64, header byte per address type) and BIP322
//! (`simple` for P2WPKH and P2TR key path, `full` for P2SH-P2WPKH). Never a transaction: the
//! message is hashed under the BIP137 prefix or the BIP322 tag, and bytes that are themselves a
//! transaction or a PSBT are refused before display (M03).
//!
//! Output encoding: BIP322 signatures are written **without** the `smp`/`ful` variant prefix of
//! the finalized BIP (verifiers accept the unprefixed form as the pre-final encoding; `UniSat`,
//! `Xverse` and `bip322-js` produce and expect it). P2PKH signs with BIP137 only (the legacy
//! BIP322 form is not implemented).
#![deny(clippy::indexing_slicing)]

use core::fmt;

use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{All, Message, PublicKey, Secp256k1, SecretKey};

use super::account::{BtcKeySource, BtcPubKey, ScriptType, kind_for_key};
use super::address::{ScriptKind, encode_address, hash160, script_pubkey};
use super::amount::Sats;
use super::network::BtcNetwork;
use super::script::p2sh_p2wpkh_script_sig;
use super::sighash::bip143_sighash_p2wpkh;
use super::sign::{BtcKeys, sign_sighash};
use super::taproot::{
    Prevout, check_key_path_witness, sighash_default, sign_key_path, tagged_hash,
};
use super::tx::{
    OutPoint, Transaction, TxIn, TxOut, Txid, parse_transaction, serialize, sha256d, txid,
    write_compact_size,
};
use crate::approval::{AccountRef, ApprovalKind, Approved, ChainRef, SigningPayload};
use crate::entropy::{OsRandom, secp_context};

/// Largest message (bytes of the UTF-8 text).
pub const MAX_BTC_MESSAGE_BYTES: usize = 65_536;
/// BIP137 message prefix (`varint(24) ‖ "Bitcoin Signed Message:\n"`).
pub const BIP137_PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";
/// BIP322 tagged-hash tag.
pub const BIP322_TAG: &[u8] = b"BIP0322-signed-message";
/// PSBT magic (BIP174).
pub const PSBT_MAGIC: &[u8] = b"psbt\xff";

/// Signature protocol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum BtcMessageProtocol {
    /// BIP137 compact ECDSA ("Bitcoin Signed Message").
    Ecdsa = 1,
    /// BIP322 (simple for P2WPKH/P2TR, full for P2SH-P2WPKH).
    Bip322 = 2,
}

impl BtcMessageProtocol {
    /// Digest byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Wire label (`btc_signMessage` `protocol`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ecdsa => "ecdsa",
            Self::Bip322 => "bip322",
        }
    }

    /// Parses the exact wire label.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "ecdsa" => Some(Self::Ecdsa),
            "bip322" => Some(Self::Bip322),
            _ => None,
        }
    }

    /// Whether `script_type` can sign with this protocol (spec/08 §17.2: BIP137 has no Taproot
    /// header; BIP322 for P2PKH needs the legacy form, which is not implemented).
    #[must_use]
    pub const fn supports(self, script_type: ScriptType) -> bool {
        match self {
            Self::Ecdsa => !matches!(script_type, ScriptType::P2tr),
            Self::Bip322 => !matches!(script_type, ScriptType::P2pkh),
        }
    }

    /// The approval field text.
    #[must_use]
    pub const fn label(self, script_type: ScriptType) -> &'static str {
        match (self, script_type) {
            (Self::Ecdsa, _) => "BIP137 ECDSA (Bitcoin Signed Message)",
            (Self::Bip322, ScriptType::P2shP2wpkh) => "BIP322 (full)",
            (Self::Bip322, _) => "BIP322 (simple)",
        }
    }
}

/// Message signing failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcMessageError {
    /// The approval is not a Bitcoin message approval of this payload.
    KindMismatch,
    /// The protocol cannot sign for this address type, or the bytes are a transaction/PSBT.
    Unsupported,
    /// The key does not produce the approved public key or address.
    KeyMismatch,
    /// Key access, derivation, randomness or the post-sign check failed.
    Signing,
}

impl fmt::Display for BtcMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::KindMismatch | Self::Unsupported | Self::KeyMismatch => {
                "내부 검증에 실패해 서명하지 않았습니다."
            }
            Self::Signing => "서명하지 못했습니다(내부 오류)",
        })
    }
}

impl std::error::Error for BtcMessageError {}

/// A finished message signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcMessageSignature {
    /// Base64 signature (BIP137 65 bytes, BIP322 witness stack or full `to_sign`).
    pub signature: String,
    /// The hash that was committed to: the BIP137 magic hash or the BIP322 message hash.
    pub message_hash: [u8; 32],
}

/// `SHA256d(prefix ‖ CompactSize(len) ‖ message)` (BIP137 / Bitcoin Core `signmessage`).
#[must_use]
pub fn bip137_magic_hash(message: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(BIP137_PREFIX.len() + 9 + message.len());
    data.extend_from_slice(BIP137_PREFIX);
    write_compact_size(&mut data, message.len());
    data.extend_from_slice(message);
    sha256d(&data)
}

/// The BIP137 header base (header = base + recovery id): P2PKH 27 (uncompressed) / 31
/// (compressed), P2SH-P2WPKH 35, P2WPKH 39; `None` for P2TR or an uncompressed segwit key.
#[must_use]
pub const fn bip137_header_base(script_type: ScriptType, compressed: bool) -> Option<u8> {
    match (script_type, compressed) {
        (ScriptType::P2pkh, false) => Some(27),
        (ScriptType::P2pkh, true) => Some(31),
        (ScriptType::P2shP2wpkh, true) => Some(35),
        (ScriptType::P2wpkh, true) => Some(39),
        _ => None,
    }
}

/// Signs the BIP137 magic hash (RFC 6979) and returns `header ‖ r ‖ s`.
fn bip137_sign(
    ctx: &Secp256k1<All>,
    secret: &SecretKey,
    header_base: u8,
    hash: [u8; 32],
) -> Result<[u8; 65], BtcMessageError> {
    let signature = ctx.sign_ecdsa_recoverable(Message::from_digest(hash), secret);
    let (recovery, compact) = signature.serialize_compact();
    let id = u8::try_from(i32::from(recovery))
        .ok()
        .filter(|id| *id <= 3)
        .ok_or(BtcMessageError::Signing)?;
    let mut out = [0_u8; 65];
    let (head, body) = out.split_at_mut(1);
    if let Some(first) = head.first_mut() {
        *first = header_base.saturating_add(id);
    }
    body.copy_from_slice(&compact);
    Ok(out)
}

/// Recovers the key of a BIP137 signature: `(public key, compressed, header base)`; `None` for
/// a bad header or signature.
#[must_use]
pub fn bip137_recover(signature: &[u8; 65], message: &[u8]) -> Option<(PublicKey, bool, u8)> {
    let (header, compact) = signature.split_first()?;
    let (base, compressed) = match *header {
        27..=30 => (27, false),
        31..=34 => (31, true),
        35..=38 => (35, true),
        39..=42 => (39, true),
        _ => return None,
    };
    let recovery = RecoveryId::try_from(i32::from(header - base)).ok()?;
    let compact = <[u8; 64]>::try_from(compact).ok()?;
    let signature = RecoverableSignature::from_compact(&compact, recovery).ok()?;
    let ctx = secp_context(&mut OsRandom).ok()?;
    let public = ctx
        .recover_ecdsa(Message::from_digest(bip137_magic_hash(message)), &signature)
        .ok()?;
    Some((public, compressed, base))
}

/// Verifies a base64 BIP137 signature for `address` on `network` (tests, acceptance tooling):
/// the recovered key, its compression and the header's address type must give `address`.
#[must_use]
pub fn bip137_verify(network: BtcNetwork, address: &str, message: &[u8], signature: &str) -> bool {
    let Some(bytes) = crate::codec::base64::decode(signature) else {
        return false;
    };
    let Ok(bytes) = <[u8; 65]>::try_from(bytes.as_slice()) else {
        return false;
    };
    let Some((public, compressed, base)) = bip137_recover(&bytes, message) else {
        return false;
    };
    let script_type = match base {
        27 | 31 => ScriptType::P2pkh,
        35 => ScriptType::P2shP2wpkh,
        _ => ScriptType::P2wpkh,
    };
    let Ok(ctx) = secp_context(&mut OsRandom) else {
        return false;
    };
    kind_for_key(&ctx, script_type, &BtcPubKey::of_point(&public, compressed))
        .is_ok_and(|kind| encode_address(&kind, network) == address)
}

/// `TaggedHash("BIP0322-signed-message", message)`.
#[must_use]
pub fn bip322_message_hash(message: &[u8]) -> [u8; 32] {
    tagged_hash(BIP322_TAG, &[message])
}

/// The BIP322 `to_spend` transaction of `message` for `script_pubkey`.
#[must_use]
pub fn bip322_to_spend(script_pubkey: &[u8], message: &[u8]) -> Transaction {
    let mut script_sig = Vec::with_capacity(34);
    script_sig.push(0x00);
    script_sig.push(0x20);
    script_sig.extend_from_slice(&bip322_message_hash(message));
    Transaction {
        version: 0,
        inputs: vec![TxIn {
            prevout: OutPoint::COINBASE,
            script_sig,
            sequence: 0,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: Sats::ZERO,
            script_pubkey: script_pubkey.to_vec(),
        }],
        lock_time: 0,
    }
}

/// The unsigned BIP322 `to_sign` transaction spending output 0 of `to_spend` (`OP_RETURN`
/// output, version/lock time/sequence 0).
#[must_use]
pub fn bip322_to_sign(to_spend: Txid) -> Transaction {
    Transaction {
        version: 0,
        inputs: vec![TxIn {
            prevout: OutPoint {
                txid: to_spend,
                vout: 0,
            },
            script_sig: Vec::new(),
            sequence: 0,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: Sats::ZERO,
            script_pubkey: vec![0x6a],
        }],
        lock_time: 0,
    }
}

/// Consensus encoding of a witness stack (`CompactSize(n) ‖ (CompactSize(len) ‖ item)…`).
#[must_use]
pub fn encode_witness(witness: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    write_compact_size(&mut out, witness.len());
    for item in witness {
        write_compact_size(&mut out, item.len());
        out.extend_from_slice(item);
    }
    out
}

fn decode_witness(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    fn compact(bytes: &[u8], at: &mut usize) -> Option<usize> {
        let first = *bytes.get(*at)?;
        *at += 1;
        let width = match first {
            0..=0xfc => return Some(usize::from(first)),
            0xfd => 2,
            0xfe => 4,
            0xff => 8,
        };
        let slice = bytes.get(*at..*at + width)?;
        *at += width;
        let mut value = 0_u64;
        for (shift, byte) in slice.iter().enumerate() {
            value |= u64::from(*byte) << (8 * shift);
        }
        usize::try_from(value).ok()
    }
    let mut at = 0;
    let count = compact(bytes, &mut at)?;
    if count > 16 {
        return None;
    }
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let length = compact(bytes, &mut at)?;
        items.push(bytes.get(at..at.checked_add(length)?)?.to_vec());
        at += length;
    }
    (at == bytes.len()).then_some(items)
}

/// A `DER ‖ 0x01` signature item over `sighash` for a compressed key (verification only; the
/// high-R signatures of other wallets are accepted).
fn ecdsa_item_verifies(item: &[u8], key: &[u8], sighash: &[u8; 32]) -> bool {
    let Some((0x01, der)) = item.split_last() else {
        return false;
    };
    let (Ok(signature), Ok(key), Ok(ctx)) = (
        secp256k1::ecdsa::Signature::from_der(der),
        PublicKey::from_slice(key),
        secp_context(&mut OsRandom),
    ) else {
        return false;
    };
    ctx.verify_ecdsa(Message::from_digest(*sighash), &signature, &key)
        .is_ok()
}

/// Verifies an unprefixed (or `smp`-prefixed) BIP322 simple signature for a P2WPKH or P2TR
/// address kind (tests, acceptance tooling).
#[must_use]
pub fn bip322_verify_simple(kind: &ScriptKind, message: &[u8], signature: &str) -> bool {
    let text = signature.strip_prefix("smp").unwrap_or(signature);
    let Some(witness) = crate::codec::base64::decode(text).and_then(|b| decode_witness(&b)) else {
        return false;
    };
    let script = script_pubkey(kind);
    let to_spend = bip322_to_spend(&script, message);
    let to_sign = bip322_to_sign(txid(&to_spend));
    match kind {
        ScriptKind::P2wpkh(program) => {
            let ([sig, key], Some(sighash)) = (
                witness.as_slice(),
                bip143_sighash_p2wpkh(&to_sign, 0, program, Sats::ZERO),
            ) else {
                return false;
            };
            hash160(key) == *program && ecdsa_item_verifies(sig, key, &sighash)
        }
        ScriptKind::P2tr(output) => {
            let prevouts = [Prevout {
                value: Sats::ZERO,
                script_pubkey: script,
            }];
            let (Some(sighash), Ok(ctx)) = (
                sighash_default(&to_sign, 0, &prevouts),
                secp_context(&mut OsRandom),
            ) else {
                return false;
            };
            check_key_path_witness(&ctx, &witness, output, &sighash).is_ok()
        }
        _ => false,
    }
}

/// The first-line marker of a Sign-In-With-Bitcoin message (the CAIP-122 template with the
/// chain name `Bitcoin`, like SIWE and SIWS).
pub const SIWB_MARKER: &str = " wants you to sign in with your Bitcoin account:";

/// The domain a Sign-In-With-Bitcoin message names: the text before [`SIWB_MARKER`] on its
/// first line (leading whitespace skipped, the marker matched without ASCII case). `None`: the
/// message is not a sign-in message (or not UTF-8 text).
#[must_use]
pub fn sign_in_domain(message: &[u8]) -> Option<&str> {
    let text = core::str::from_utf8(message).ok()?;
    let line = text.trim_start().split('\n').next()?;
    // ASCII lowercasing keeps every byte offset, so `at` is a boundary of `line` too.
    let at = line
        .to_ascii_lowercase()
        .find(&SIWB_MARKER.to_ascii_lowercase())?;
    line.get(..at)
}

/// Whether the message bytes are (or plainly encode, as hex or base64 text) a Bitcoin
/// transaction or a PSBT (M03: blocked).
#[must_use]
pub fn looks_like_transaction(message: &[u8]) -> bool {
    let raw = |bytes: &[u8]| bytes.starts_with(PSBT_MAGIC) || parse_transaction(bytes).is_ok();
    if raw(message) {
        return true;
    }
    let Ok(text) = core::str::from_utf8(message) else {
        return false;
    };
    let text = text.trim();
    let hex = text.strip_prefix("0x").unwrap_or(text);
    if hex.len() >= 20
        && let Ok(bytes) = crate::hex::decode(hex)
        && raw(&bytes)
    {
        return true;
    }
    text.len() >= 16 && crate::codec::base64::decode(text).is_some_and(|bytes| raw(&bytes))
}

/// The address of a key with an address type (approval and grant display).
///
/// # Errors
///
/// [`BtcMessageError::KeyMismatch`] for an uncompressed key with a segwit type.
pub fn address_of(
    network: BtcNetwork,
    script_type: ScriptType,
    pubkey: &BtcPubKey,
) -> Result<(ScriptKind, String), BtcMessageError> {
    let ctx = secp_context(&mut OsRandom).map_err(|_| BtcMessageError::Signing)?;
    let kind = kind_for_key(&ctx, script_type, pubkey).map_err(|_| BtcMessageError::KeyMismatch)?;
    let address = encode_address(&kind, network);
    Ok((kind, address))
}

/// Signs `message` for `kind` with `secret` (inside the key-lending closure). `aux` is the BIP340
/// auxiliary randomness of a Taproot signature.
#[expect(
    clippy::too_many_arguments,
    reason = "the approved payload fields, unpacked inside the key-lending closure"
)]
fn sign_with_secret(
    ctx: &Secp256k1<All>,
    secret: &SecretKey,
    script_type: ScriptType,
    kind: &ScriptKind,
    compressed: bool,
    protocol: BtcMessageProtocol,
    message: &[u8],
    aux: &[u8; 32],
) -> Result<BtcMessageSignature, BtcMessageError> {
    if !protocol.supports(script_type) {
        return Err(BtcMessageError::Unsupported);
    }
    if protocol == BtcMessageProtocol::Ecdsa {
        let base =
            bip137_header_base(script_type, compressed).ok_or(BtcMessageError::Unsupported)?;
        let hash = bip137_magic_hash(message);
        let bytes = bip137_sign(ctx, secret, base, hash)?;
        // Post-sign check: the recovered key gives the same address type and key.
        let (public, recovered_compressed, recovered_base) =
            bip137_recover(&bytes, message).ok_or(BtcMessageError::Signing)?;
        if public != PublicKey::from_secret_key(ctx, secret)
            || recovered_compressed != compressed
            || recovered_base != base
        {
            return Err(BtcMessageError::Signing);
        }
        return Ok(BtcMessageSignature {
            signature: crate::codec::base64::encode(&bytes),
            message_hash: hash,
        });
    }
    let script = script_pubkey(kind);
    let to_spend = bip322_to_spend(&script, message);
    let mut to_sign = bip322_to_sign(txid(&to_spend));
    let public = PublicKey::from_secret_key(ctx, secret).serialize();
    let hash = bip322_message_hash(message);
    match (script_type, kind) {
        (ScriptType::P2wpkh, ScriptKind::P2wpkh(program)) => {
            let sighash = bip143_sighash_p2wpkh(&to_sign, 0, program, Sats::ZERO)
                .ok_or(BtcMessageError::Signing)?;
            let sig = sign_sighash(ctx, secret, &sighash).map_err(|_| BtcMessageError::Signing)?;
            let witness = vec![sig, public.to_vec()];
            Ok(BtcMessageSignature {
                signature: crate::codec::base64::encode(&encode_witness(&witness)),
                message_hash: hash,
            })
        }
        (ScriptType::P2shP2wpkh, ScriptKind::P2sh(_)) => {
            let key_hash = hash160(&public);
            let sighash = bip143_sighash_p2wpkh(&to_sign, 0, &key_hash, Sats::ZERO)
                .ok_or(BtcMessageError::Signing)?;
            let sig = sign_sighash(ctx, secret, &sighash).map_err(|_| BtcMessageError::Signing)?;
            if let Some(input) = to_sign.inputs.first_mut() {
                input.script_sig = p2sh_p2wpkh_script_sig(&key_hash).to_vec();
                input.witness = vec![sig, public.to_vec()];
            }
            Ok(BtcMessageSignature {
                signature: crate::codec::base64::encode(&serialize(&to_sign, true)),
                message_hash: hash,
            })
        }
        (ScriptType::P2tr, ScriptKind::P2tr(output)) => {
            let prevouts = [Prevout {
                value: Sats::ZERO,
                script_pubkey: script.clone(),
            }];
            let sighash =
                sighash_default(&to_sign, 0, &prevouts).ok_or(BtcMessageError::Signing)?;
            let (sig, signed_output) = sign_key_path(ctx, secret, None, &sighash, aux)
                .map_err(|_| BtcMessageError::Signing)?;
            if signed_output != *output {
                return Err(BtcMessageError::KeyMismatch);
            }
            Ok(BtcMessageSignature {
                signature: crate::codec::base64::encode(&encode_witness(&[sig.to_vec()])),
                message_hash: hash,
            })
        }
        _ => Err(BtcMessageError::Unsupported),
    }
}

/// Signs an approved Bitcoin message (spec/08 §17.3). The key of the payload's source must give
/// the approved public key and address; the bytes are checked once more against M03.
///
/// # Errors
///
/// [`BtcMessageError`]; nothing is returned on error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_message(
    keys: &crate::vault::Vault,
    approved: Approved,
) -> Result<BtcMessageSignature, BtcMessageError> {
    sign_message_with(keys, &approved)
}

/// The approval checks shared by the vault and card paths: a Bitcoin message approval of this
/// payload's chain and key, the size and M03 bounds, the approved address and the source's
/// address type. Returns the payload and its address kind.
fn approved_payload(
    approved: &Approved,
) -> Result<(&crate::approval::BtcMessagePayload, ScriptKind), BtcMessageError> {
    let SigningPayload::BtcMessage(payload) = approved.payload() else {
        return Err(BtcMessageError::KindMismatch);
    };
    let chain_ok = matches!(
        approved.chain(),
        ChainRef::Bitcoin { network, genesis }
            if network == payload.network.id() && genesis == payload.network.genesis()
    );
    let account_ok = payload
        .pubkey
        .compressed()
        .is_ok_and(|key| approved.account() == AccountRef::Bitcoin(key));
    if approved.kind() != ApprovalKind::BtcMessage || !chain_ok || !account_ok {
        return Err(BtcMessageError::KindMismatch);
    }
    if payload.message.len() > MAX_BTC_MESSAGE_BYTES || looks_like_transaction(&payload.message) {
        return Err(BtcMessageError::Unsupported);
    }
    let (kind, address) = address_of(payload.network, payload.script_type, &payload.pubkey)?;
    if address != payload.address {
        return Err(BtcMessageError::KeyMismatch);
    }
    if payload.source.script_type() != payload.script_type {
        return Err(BtcMessageError::KeyMismatch);
    }
    Ok((payload, kind))
}

pub(crate) fn sign_message_with<K: BtcKeys>(
    keys: &K,
    approved: &Approved,
) -> Result<BtcMessageSignature, BtcMessageError> {
    let (payload, kind) = approved_payload(approved)?;
    let aux = keys.aux_rand().map_err(|_| BtcMessageError::Signing)?;
    let compressed = payload.pubkey.is_compressed();
    keys.with_btc_key(payload.network, payload.source, 0, |ctx, secret| {
        let public = PublicKey::from_secret_key(ctx, secret);
        if BtcPubKey::of_point(&public, compressed) != payload.pubkey {
            return Ok(Err(BtcMessageError::KeyMismatch));
        }
        Ok(sign_with_secret(
            ctx,
            secret,
            payload.script_type,
            &kind,
            compressed,
            payload.protocol,
            &payload.message,
            &aux,
        ))
    })
    .map_err(|_| BtcMessageError::Signing)?
}

/// Failure of a `YubiKey` Bitcoin message signature (spec/10 §10, §13): nothing is returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcMessageCardError {
    /// The approval or the post-sign check failed (as for vault signing; `KindMismatch` also
    /// for a source other than `BtcKeySource::Hardware`).
    Sign(BtcMessageError),
    /// The card operation failed.
    Card(crate::yubikey::CardError),
}

impl fmt::Display for BtcMessageCardError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sign(error) => error.fmt(formatter),
            Self::Card(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for BtcMessageCardError {}

impl From<BtcMessageError> for BtcMessageCardError {
    fn from(error: BtcMessageError) -> Self {
        Self::Sign(error)
    }
}

impl From<crate::yubikey::CardError> for BtcMessageCardError {
    fn from(error: crate::yubikey::CardError) -> Self {
        Self::Card(error)
    }
}

/// The BIP137 `header ‖ r ‖ s` of a card signature over `hash`: the card gives no recovery id,
/// so each id is tried and the one that recovers the recorded key is kept.
fn bip137_from_card(
    ctx: &Secp256k1<All>,
    der: &[u8],
    hash: [u8; 32],
    public: &PublicKey,
    header_base: u8,
) -> Result<[u8; 65], BtcMessageError> {
    let mut signature =
        secp256k1::ecdsa::Signature::from_der(der).map_err(|_| BtcMessageError::Signing)?;
    signature.normalize_s();
    let compact = signature.serialize_compact();
    for id in 0_u8..=3 {
        let Ok(recovery) = RecoveryId::try_from(i32::from(id)) else {
            continue;
        };
        let Ok(recoverable) = RecoverableSignature::from_compact(&compact, recovery) else {
            continue;
        };
        if ctx
            .recover_ecdsa(Message::from_digest(hash), &recoverable)
            .is_ok_and(|key| key == *public)
        {
            let mut out = [0_u8; 65];
            let (head, body) = out.split_at_mut(1);
            if let Some(first) = head.first_mut() {
                *first = header_base.saturating_add(id);
            }
            body.copy_from_slice(&compact);
            return Ok(out);
        }
    }
    Err(BtcMessageError::Signing)
}

/// Signs an approved Bitcoin message of a `YubiKey` account on the card (spec/10 §13): the same
/// approval checks as [`sign_message`] (kind, chain, account, size, M03, address, address
/// type), then one card signature (`yubikey::sign::sign_btc`: DER, low-s, verified against the
/// recorded key) of
///
/// - BIP137: the magic hash; the recovery id is found by recovering the recorded key, then the
///   same post-sign check as the vault path (recovered key, compression and header type);
/// - BIP322 simple (P2WPKH): the BIP143 sighash of `to_sign`, witness `[DER ‖ 01, pubkey]`;
/// - BIP322 full (P2SH-P2WPKH): the same sighash with the nested script, the whole `to_sign`.
///
/// Each BIP322 item is verified again against the recorded key (the card may give high-R
/// signatures, which verifiers accept). A `YubiKey` account is never P2TR.
///
/// # Errors
///
/// [`BtcMessageCardError`]; nothing is returned on error.
#[expect(
    clippy::needless_pass_by_value,
    reason = "the one-time approval token is consumed by signing (spec/03 §11.5)"
)]
pub fn sign_message_card(
    approved: Approved,
    card: super::sign::CardSighashSigner<'_>,
) -> Result<BtcMessageSignature, BtcMessageCardError> {
    let (payload, kind) = approved_payload(&approved)?;
    if !payload.source.is_hardware() || !payload.pubkey.is_compressed() {
        return Err(BtcMessageError::KindMismatch.into());
    }
    if !payload.protocol.supports(payload.script_type) {
        return Err(BtcMessageError::Unsupported.into());
    }
    let ctx = secp_context(&mut OsRandom).map_err(|_| BtcMessageError::Signing)?;
    let public = payload
        .pubkey
        .compressed()
        .map_err(|_| BtcMessageError::KeyMismatch)?;
    let point = PublicKey::from_slice(&public).map_err(|_| BtcMessageError::KeyMismatch)?;
    let message = &payload.message;
    if payload.protocol == BtcMessageProtocol::Ecdsa {
        let base =
            bip137_header_base(payload.script_type, true).ok_or(BtcMessageError::Unsupported)?;
        let hash = bip137_magic_hash(message);
        let der = card(hash)?;
        let bytes = bip137_from_card(&ctx, &der, hash, &point, base)?;
        let (recovered, compressed, recovered_base) =
            bip137_recover(&bytes, message).ok_or(BtcMessageError::Signing)?;
        if recovered != point || !compressed || recovered_base != base {
            return Err(BtcMessageError::Signing.into());
        }
        return Ok(BtcMessageSignature {
            signature: crate::codec::base64::encode(&bytes),
            message_hash: hash,
        });
    }
    let script = script_pubkey(&kind);
    let to_spend = bip322_to_spend(&script, message);
    let mut to_sign = bip322_to_sign(txid(&to_spend));
    let key_hash = hash160(&public);
    let sighash = bip143_sighash_p2wpkh(&to_sign, 0, &key_hash, Sats::ZERO)
        .ok_or(BtcMessageError::Signing)?;
    let mut item = card(sighash)?;
    item.push(0x01);
    if !ecdsa_item_verifies(&item, &public, &sighash) {
        return Err(BtcMessageError::Signing.into());
    }
    let hash = bip322_message_hash(message);
    let signature = match (payload.script_type, &kind) {
        (ScriptType::P2wpkh, ScriptKind::P2wpkh(program)) if *program == key_hash => {
            encode_witness(&[item, public.to_vec()])
        }
        (ScriptType::P2shP2wpkh, ScriptKind::P2sh(_)) => {
            if let Some(input) = to_sign.inputs.first_mut() {
                input.script_sig = p2sh_p2wpkh_script_sig(&key_hash).to_vec();
                input.witness = vec![item, public.to_vec()];
            }
            serialize(&to_sign, true)
        }
        _ => return Err(BtcMessageError::Unsupported.into()),
    };
    Ok(BtcMessageSignature {
        signature: crate::codec::base64::encode(&signature),
        message_hash: hash,
    })
}

/// What a Bitcoin message approval shows besides the bytes (spec/08 §17.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcMessageRequest {
    /// Approval id.
    pub id: crate::approval::ApprovalId,
    /// Requesting site.
    pub origin: crate::policy::BrowserOrigin,
    /// The account's network (= settings network).
    pub network: BtcNetwork,
    /// Key source of the address.
    pub source: BtcKeySource,
    /// Public key of the address.
    pub pubkey: BtcPubKey,
    /// Address type.
    pub script_type: ScriptType,
    /// Account label (user text, escaped here).
    pub label: String,
    /// Derivation path text, or the imported-key note.
    pub path: String,
    /// Protocol.
    pub protocol: BtcMessageProtocol,
    /// Message bytes.
    pub message: Vec<u8>,
}

/// Builds the approval draft of a Bitcoin message request (spec/08 §17.4).
///
/// # Errors
///
/// [`crate::approval::DisplayError`] (defensive; also for a protocol the address type cannot use
/// or a key that does not give an address).
pub fn build_btc_message_request(
    request: &BtcMessageRequest,
) -> Result<crate::approval::ApprovalDraft, crate::approval::DisplayError> {
    use crate::approval::message::{inline_value, push_message_body};
    use crate::approval::{
        ApprovalDisplay, ApprovalDraft, ApprovalOrigin, BtcMessagePayload, DisplayError,
        DisplayField, FieldKey, Signer, SimulationBinding,
    };
    use crate::evm::risk::{self, M03, M04, M06};

    if !request.protocol.supports(request.script_type) {
        return Err(DisplayError::InvalidText);
    }
    let (_, address) = address_of(request.network, request.script_type, &request.pubkey)
        .map_err(|_| DisplayError::InvalidText)?;
    let public = request
        .pubkey
        .compressed()
        .map_err(|_| DisplayError::InvalidText)?;
    let mut fields = vec![
        DisplayField::new(FieldKey::ORIGIN, "", request.origin.as_str())?,
        DisplayField::new(
            FieldKey::NETWORK,
            "",
            request.network.display_name().to_owned(),
        )?,
        DisplayField::new(
            FieldKey::ACCOUNT,
            "",
            format!(
                "{}\n{}\n{address}",
                inline_value(&request.label),
                inline_value(&request.path)
            ),
        )?,
        DisplayField::new(
            FieldKey::MESSAGE_FORMAT,
            "",
            request.protocol.label(request.script_type),
        )?,
    ];
    let mut warnings = vec![risk::warning(M04, None)];
    if request.message.len() > MAX_BTC_MESSAGE_BYTES {
        warnings.push(risk::warning(M03, Some("64KiB를 넘는 메시지입니다")));
    }
    if looks_like_transaction(&request.message) {
        warnings.push(risk::warning(M03, None));
    }
    // A sign-in message is bound to the site it names (SIWE S01, SIWS W01).
    if let Some(domain) = sign_in_domain(&request.message)
        && !crate::sol::msgsign::domain_matches(domain, &request.origin)
    {
        warnings.push(risk::warning(M06, None));
    }
    push_message_body(&mut fields, &mut warnings, &request.message)?;
    let display = ApprovalDisplay::new(
        format!(
            "[{}] 메시지 서명 (소유 증명)",
            request.network.display_name()
        ),
        fields,
        warnings,
    )?;
    Ok(ApprovalDraft {
        id: request.id,
        origin: ApprovalOrigin::Site(request.origin.clone()),
        chain: ChainRef::Bitcoin {
            network: request.network.id(),
            genesis: request.network.genesis(),
        },
        account: AccountRef::Bitcoin(public),
        signer: Signer::FromPayload,
        kind: ApprovalKind::BtcMessage,
        payload: SigningPayload::BtcMessage(Box::new(BtcMessagePayload {
            network: request.network,
            source: request.source,
            pubkey: request.pubkey,
            script_type: request.script_type,
            address,
            protocol: request.protocol,
            message: request.message.clone(),
        })),
        display,
        simulation: SimulationBinding::NotApplicable,
    })
}

#[cfg(test)]
mod tests;
