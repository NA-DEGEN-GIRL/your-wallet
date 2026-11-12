//! The dApp transaction parser (spec/07 §20.2): legacy and v0 messages and signed transactions
//! with every Agave sanitize rule the wallet relies on, and the re-encoding identity. Unlike the
//! template parser (`sol::message`, §9) it accepts any program and any number of signers; what
//! the instructions do is `decode`'s job.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use crate::sol::address::{
    COMPUTE_BUDGET_PROGRAM, ED25519_PRECOMPILE, SECP256K1_PRECOMPILE, SECP256R1_PRECOMPILE,
    SYSTEM_PROGRAM, SolAddress,
};
use crate::sol::keys::verify_strict;
use crate::sol::message::{CompiledIx, encode_legacy_message};
use crate::sol::shortvec::{self, ShortVecError};
use crate::sol::template::SOL_MAX_TX_BYTES;

/// Most transactions in one `sol_signAllTransactions` request.
pub const SOL_TX_MAX_BATCH: usize = 32;
/// Most top-level instructions in one transaction (a wallet rule, not Agave's).
pub const SOL_TX_MAX_IX: usize = 64;
/// Most account keys of a message, static plus loaded (Agave sanitize).
pub const SOL_TX_MAX_KEYS: usize = 256;
/// The version prefix of a v0 message.
const V0_PREFIX: u8 = 0x80;
/// Length of one signature slot.
const SIGNATURE_LEN: usize = 64;
/// `AdvanceNonceAccount` (System tag 4, u32 LE): the first four data bytes of a durable-nonce
/// instruction 0.
const ADVANCE_NONCE_TAG: [u8; 4] = [4, 0, 0, 0];

/// Message format.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolTxVersion {
    /// No prefix (first byte `< 0x80`).
    Legacy,
    /// Prefix `0x80` with address table lookups.
    V0,
}

/// The three header counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MessageHeader {
    /// Signatures required (the first `required` static keys sign).
    pub required: u8,
    /// Of the signers, how many are read-only (the last ones).
    pub readonly_signed: u8,
    /// Of the other static keys, how many are read-only (the last ones).
    pub readonly_unsigned: u8,
}

/// One v0 address table lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupRef {
    /// The lookup table account.
    pub table: SolAddress,
    /// Table indices loaded as writable.
    pub writable: Vec<u8>,
    /// Table indices loaded as read-only.
    pub readonly: Vec<u8>,
}

/// A parsed legacy or v0 message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolTxMessage {
    /// Format.
    pub version: SolTxVersion,
    /// Header.
    pub header: MessageHeader,
    /// Static account keys (pairwise distinct).
    pub static_keys: Vec<SolAddress>,
    /// Recent blockhash (or the durable nonce value).
    pub blockhash: [u8; 32],
    /// Compiled instructions (program index always static and not the fee payer).
    pub(crate) instructions: Vec<CompiledIx>,
    /// Address table lookups (empty for legacy).
    pub lookups: Vec<LookupRef>,
}

/// A parsed signed (or partially signed) transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SolWireTx {
    /// One slot per required signer; an all-zero slot is unsigned.
    pub signatures: Vec<[u8; 64]>,
    /// The exact message bytes (what every signature covers).
    pub message_bytes: Vec<u8>,
    /// The parsed message.
    pub message: SolTxMessage,
}

/// Why bytes are not an acceptable dApp transaction (spec/07 §20.2; all are -32602 / X01).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolTxError {
    /// No bytes.
    Empty,
    /// Over 1,232 bytes (a message alone: over 1,232 − 65).
    TooLarge,
    /// A compact-u16 length is non-minimal or overflows.
    ShortVec,
    /// The input ends early.
    Truncated,
    /// A message version other than legacy and v0 (the prefix byte).
    Version(u8),
    /// The header counts are inconsistent with the static keys.
    Header,
    /// More than 256 account keys (static plus loaded).
    TooManyKeys,
    /// A static key appears twice.
    DuplicateKey,
    /// A program index is 0 (the fee payer) or not a static key.
    ProgramIndex,
    /// An account index is past the static plus loaded keys.
    AccountIndex,
    /// A lookup loads no address.
    EmptyLookup,
    /// More than 64 instructions.
    TooManyInstructions,
    /// The signature count differs from the required signers.
    SignatureCount,
    /// Bytes after the message.
    TrailingBytes,
    /// Re-encoding the parsed message gives other bytes.
    Encoding,
    /// The key is not one of the message's signers.
    NotSigner,
}

impl fmt::Display for SolTxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("사이트 거래 형식이 올바르지 않습니다: ")?;
        match self {
            Self::Empty => formatter.write_str("비어 있음"),
            Self::TooLarge => formatter.write_str("1,232바이트를 넘음"),
            Self::ShortVec => formatter.write_str("길이 표기(compact-u16)가 잘못됨"),
            Self::Truncated => formatter.write_str("중간에 끝남"),
            Self::Version(prefix) => write!(formatter, "지원하지 않는 메시지 버전({prefix:#04x})"),
            Self::Header => formatter.write_str("header 값이 계정 키와 맞지 않음"),
            Self::TooManyKeys => formatter.write_str("계정 키가 256개를 넘음"),
            Self::DuplicateKey => formatter.write_str("같은 계정 키가 두 번 있음"),
            Self::ProgramIndex => formatter.write_str("프로그램 인덱스가 잘못됨"),
            Self::AccountIndex => formatter.write_str("계정 인덱스가 범위 밖"),
            Self::EmptyLookup => formatter.write_str("주소를 하나도 읽지 않는 조회 테이블 항목"),
            Self::TooManyInstructions => formatter.write_str("명령이 64개를 넘음"),
            Self::SignatureCount => formatter.write_str("서명 수가 필요한 서명자 수와 다름"),
            Self::TrailingBytes => formatter.write_str("끝에 남는 바이트가 있음"),
            Self::Encoding => formatter.write_str("다시 인코딩한 바이트가 다름"),
            Self::NotSigner => formatter.write_str("이 계정은 거래의 서명자가 아님"),
        }
    }
}

impl std::error::Error for SolTxError {}

impl From<ShortVecError> for SolTxError {
    fn from(error: ShortVecError) -> Self {
        match error {
            ShortVecError::Truncated => Self::Truncated,
            ShortVecError::Overflow | ShortVecError::Alias => Self::ShortVec,
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], SolTxError> {
        let end = self.at.checked_add(len).ok_or(SolTxError::Truncated)?;
        let slice = self.bytes.get(self.at..end).ok_or(SolTxError::Truncated)?;
        self.at = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], SolTxError> {
        self.take(N)?.try_into().map_err(|_| SolTxError::Truncated)
    }

    fn short_len(&mut self) -> Result<usize, SolTxError> {
        let rest = self.bytes.get(self.at..).ok_or(SolTxError::Truncated)?;
        let (value, used) = shortvec::decode(rest)?;
        self.at = self.at.checked_add(used).ok_or(SolTxError::Truncated)?;
        Ok(usize::from(value))
    }

    /// `shortvec(n) ‖ (table ‖ shortvec(w) ‖ w ‖ shortvec(r) ‖ r)*`; each lookup loads at least
    /// one address.
    fn lookups(&mut self) -> Result<Vec<LookupRef>, SolTxError> {
        let count = self.short_len()?;
        let mut lookups = Vec::new();
        for _ in 0..count {
            let table = SolAddress::from_bytes(self.array::<32>()?);
            let n_writable = self.short_len()?;
            let writable = self.take(n_writable)?.to_vec();
            let n_readonly = self.short_len()?;
            let readonly = self.take(n_readonly)?.to_vec();
            if writable.is_empty() && readonly.is_empty() {
                return Err(SolTxError::EmptyLookup);
            }
            lookups.push(LookupRef {
                table,
                writable,
                readonly,
            });
        }
        Ok(lookups)
    }
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    shortvec::encode_into(u16::try_from(len).unwrap_or(u16::MAX), out);
}

/// Parses a message (legacy or v0) of at most 1,232 − 65 bytes, with the identity check.
///
/// # Errors
///
/// [`SolTxError`]; no partial result.
pub fn parse_message_any(msg: &[u8]) -> Result<SolTxMessage, SolTxError> {
    if msg.is_empty() {
        return Err(SolTxError::Empty);
    }
    if msg.len() > SOL_MAX_TX_BYTES.saturating_sub(SIGNATURE_LEN.saturating_add(1)) {
        return Err(SolTxError::TooLarge);
    }
    parse_body(msg)
}

/// Rules 2–10 of spec/07 §20.2 over exactly `msg`.
fn parse_body(msg: &[u8]) -> Result<SolTxMessage, SolTxError> {
    let first = *msg.first().ok_or(SolTxError::Empty)?;
    let mut reader = Reader { bytes: msg, at: 0 };
    let version = if first & 0x80 == 0 {
        SolTxVersion::Legacy
    } else if first == V0_PREFIX {
        reader.at = 1;
        SolTxVersion::V0
    } else {
        return Err(SolTxError::Version(first));
    };
    let [required, readonly_signed, readonly_unsigned] = reader.array::<3>()?;
    let n_static = reader.short_len()?;
    let signers = usize::from(required);
    if required == 0
        || signers > n_static
        || readonly_signed >= required
        || usize::from(readonly_unsigned) > n_static.saturating_sub(signers)
    {
        return Err(SolTxError::Header);
    }
    if n_static > SOL_TX_MAX_KEYS {
        return Err(SolTxError::TooManyKeys);
    }
    let mut static_keys: Vec<SolAddress> = Vec::with_capacity(n_static);
    for _ in 0..n_static {
        let key = SolAddress::from_bytes(reader.array::<32>()?);
        if static_keys.contains(&key) {
            return Err(SolTxError::DuplicateKey);
        }
        static_keys.push(key);
    }
    let blockhash = reader.array::<32>()?;
    let n_ix = reader.short_len()?;
    if n_ix > SOL_TX_MAX_IX {
        return Err(SolTxError::TooManyInstructions);
    }
    let mut instructions = Vec::with_capacity(n_ix);
    for _ in 0..n_ix {
        let [program] = reader.array::<1>()?;
        if program == 0 || usize::from(program) >= n_static {
            return Err(SolTxError::ProgramIndex);
        }
        let n_accounts = reader.short_len()?;
        let accounts = reader.take(n_accounts)?.to_vec();
        let data_len = reader.short_len()?;
        let data = reader.take(data_len)?.to_vec();
        instructions.push(CompiledIx {
            program,
            accounts,
            data,
        });
    }
    let lookups = if version == SolTxVersion::V0 {
        reader.lookups()?
    } else {
        Vec::new()
    };
    let total = lookups.iter().fold(n_static, |total, lookup| {
        total
            .saturating_add(lookup.writable.len())
            .saturating_add(lookup.readonly.len())
    });
    if total > SOL_TX_MAX_KEYS {
        return Err(SolTxError::TooManyKeys);
    }
    if instructions
        .iter()
        .flat_map(|ix| ix.accounts.iter())
        .any(|index| usize::from(*index) >= total)
    {
        return Err(SolTxError::AccountIndex);
    }
    if reader.at != msg.len() {
        return Err(SolTxError::TrailingBytes);
    }
    let message = SolTxMessage {
        version,
        header: MessageHeader {
            required,
            readonly_signed,
            readonly_unsigned,
        },
        static_keys,
        blockhash,
        instructions,
        lookups,
    };
    if encode_message_any(&message) != msg {
        return Err(SolTxError::Encoding);
    }
    Ok(message)
}

/// Parses a transaction: `shortvec(n) ‖ n × 64-byte signatures ‖ message` with `n` equal to the
/// required signers, at most 1,232 bytes in all.
///
/// # Errors
///
/// [`SolTxError`]; no partial result.
pub fn parse_wire_tx(tx: &[u8]) -> Result<SolWireTx, SolTxError> {
    if tx.is_empty() {
        return Err(SolTxError::Empty);
    }
    if tx.len() > SOL_MAX_TX_BYTES {
        return Err(SolTxError::TooLarge);
    }
    let mut reader = Reader { bytes: tx, at: 0 };
    let count = reader.short_len()?;
    if count == 0 {
        return Err(SolTxError::SignatureCount);
    }
    let slots = reader.take(
        count
            .checked_mul(SIGNATURE_LEN)
            .ok_or(SolTxError::Truncated)?,
    )?;
    let signatures: Vec<[u8; 64]> = slots
        .chunks_exact(SIGNATURE_LEN)
        .filter_map(|slot| <[u8; 64]>::try_from(slot).ok())
        .collect();
    let message_bytes = tx.get(reader.at..).ok_or(SolTxError::Truncated)?;
    if message_bytes.is_empty() {
        return Err(SolTxError::Truncated);
    }
    let message = parse_body(message_bytes)?;
    if usize::from(message.header.required) != count || signatures.len() != count {
        return Err(SolTxError::SignatureCount);
    }
    Ok(SolWireTx {
        signatures,
        message_bytes: message_bytes.to_vec(),
        message,
    })
}

/// The bytes of a message: legacy as `sol::message` encodes it; v0 as `0x80 ‖` the same body
/// `‖ shortvec(n) ‖ (table ‖ shortvec(w) ‖ w ‖ shortvec(r) ‖ r)*`.
#[must_use]
pub fn encode_message_any(message: &SolTxMessage) -> Vec<u8> {
    let keys: Vec<[u8; 32]> = message
        .static_keys
        .iter()
        .map(|key| key.to_bytes())
        .collect();
    let header = [
        message.header.required,
        message.header.readonly_signed,
        message.header.readonly_unsigned,
    ];
    let body = encode_legacy_message(header, &keys, &message.blockhash, &message.instructions);
    match message.version {
        SolTxVersion::Legacy => body,
        SolTxVersion::V0 => {
            let mut out = Vec::with_capacity(body.len().saturating_add(1));
            out.push(V0_PREFIX);
            out.extend_from_slice(&body);
            push_len(&mut out, message.lookups.len());
            for lookup in &message.lookups {
                out.extend_from_slice(lookup.table.as_bytes());
                push_len(&mut out, lookup.writable.len());
                out.extend_from_slice(&lookup.writable);
                push_len(&mut out, lookup.readonly.len());
                out.extend_from_slice(&lookup.readonly);
            }
            out
        }
    }
}

impl SolTxMessage {
    /// Number of top-level instructions.
    #[must_use]
    pub fn instruction_count(&self) -> usize {
        self.instructions.len()
    }

    /// The program of each instruction, in order (always a static key).
    #[must_use]
    pub fn program_ids(&self) -> Vec<SolAddress> {
        self.instructions
            .iter()
            .filter_map(|ix| self.static_keys.get(usize::from(ix.program)).copied())
            .collect()
    }

    /// Instruction `index`: its program, account indices (into static then loaded keys) and
    /// data.
    #[must_use]
    pub fn instruction(&self, index: usize) -> Option<(&SolAddress, &[u8], &[u8])> {
        let ix = self.instructions.get(index)?;
        let program = self.static_keys.get(usize::from(ix.program))?;
        Some((program, ix.accounts.as_slice(), ix.data.as_slice()))
    }

    /// Whether account `index` signs.
    #[must_use]
    pub fn is_signer(&self, index: usize) -> bool {
        index < usize::from(self.header.required)
    }

    /// Whether static key `index` is writable by the header rule (runtime demotion of programs
    /// and sysvars is not applied).
    #[must_use]
    pub fn is_writable_static(&self, index: usize) -> bool {
        let signers = usize::from(self.header.required);
        if index < signers {
            index < signers.saturating_sub(usize::from(self.header.readonly_signed))
        } else {
            index < self.static_keys.len()
                && index
                    < self
                        .static_keys
                        .len()
                        .saturating_sub(usize::from(self.header.readonly_unsigned))
        }
    }

    /// Writable and read-only addresses loaded through the lookups.
    #[must_use]
    pub fn loaded_counts(&self) -> (usize, usize) {
        self.lookups
            .iter()
            .fold((0, 0), |(writable, readonly), lookup| {
                (
                    writable.saturating_add(lookup.writable.len()),
                    readonly.saturating_add(lookup.readonly.len()),
                )
            })
    }

    /// Whether account `index` (static, then loaded writable, then loaded read-only) is writable
    /// by the header rule and the load order.
    #[must_use]
    pub fn is_writable_index(&self, index: usize) -> bool {
        match index.checked_sub(self.static_keys.len()) {
            None => self.is_writable_static(index),
            Some(loaded) => loaded < self.loaded_counts().0,
        }
    }

    /// Static plus loaded keys.
    #[must_use]
    pub fn account_count(&self) -> usize {
        let (writable, readonly) = self.loaded_counts();
        self.static_keys
            .len()
            .saturating_add(writable)
            .saturating_add(readonly)
    }

    /// The signer slot of `public`: the unique `k < required` with `static_keys[k] == public`.
    ///
    /// # Errors
    ///
    /// [`SolTxError::NotSigner`] when the key is absent or only a non-signer account.
    pub fn signer_slot(&self, public: &[u8; 32]) -> Result<u8, SolTxError> {
        self.static_keys
            .iter()
            .position(|key| key.as_bytes() == public)
            .filter(|index| self.is_signer(*index))
            .and_then(|index| u8::try_from(index).ok())
            .ok_or(SolTxError::NotSigner)
    }

    /// The fee payer (static key 0).
    #[must_use]
    pub fn fee_payer(&self) -> Option<SolAddress> {
        self.static_keys.first().copied()
    }

    /// A durable-nonce transaction (spec/07 §20.2): instruction 0 is System `AdvanceNonceAccount`
    /// (first four data bytes `04 00 00 00`, trailing bytes allowed) whose first account exists
    /// and is writable by the header rule or the load order. Returns the nonce account index and
    /// the authority index (the third account) when present. As Agave or looser, never tighter:
    /// a false positive only adds X08 and refuses a send.
    #[must_use]
    pub fn durable_nonce(&self) -> Option<(u8, Option<u8>)> {
        let (program, accounts, data) = self.instruction(0)?;
        if *program != SYSTEM_PROGRAM || data.get(..4) != Some(ADVANCE_NONCE_TAG.as_slice()) {
            return None;
        }
        let nonce = *accounts.first()?;
        self.is_writable_index(usize::from(nonce))
            .then(|| (nonce, accounts.get(2).copied()))
    }

    /// Signatures the precompile instructions verify (`data[0]` of each Ed25519, Secp256k1 and
    /// Secp256r1 instruction): each is charged like a transaction signature.
    #[must_use]
    pub fn precompile_signatures(&self) -> u64 {
        (0..self.instructions.len())
            .filter_map(|index| self.instruction(index))
            .filter(|(program, _, _)| {
                [
                    ED25519_PRECOMPILE,
                    SECP256K1_PRECOMPILE,
                    SECP256R1_PRECOMPILE,
                ]
                .contains(program)
            })
            .map(|(_, _, data)| u64::from(data.first().copied().unwrap_or(0)))
            .sum()
    }

    /// Whether two `ComputeBudget` instructions share a tag (the runtime fails the transaction).
    #[must_use]
    pub fn duplicate_compute_budget(&self) -> bool {
        let mut seen = Vec::new();
        for index in 0..self.instructions.len() {
            if let Some((program, _, data)) = self.instruction(index)
                && *program == COMPUTE_BUDGET_PROGRAM
                && let Some(tag) = data.first()
            {
                if seen.contains(tag) {
                    return true;
                }
                seen.push(*tag);
            }
        }
        false
    }
}

/// An all-zero signature slot (not yet signed).
fn is_unsigned(signature: &[u8; 64]) -> bool {
    signature.iter().all(|byte| *byte == 0)
}

impl SolWireTx {
    /// Signature slot `index`.
    #[must_use]
    pub fn slot(&self, index: usize) -> Option<&[u8; 64]> {
        self.signatures.get(index)
    }

    /// The transaction bytes (`shortvec(n) ‖ signatures ‖ message`); for a parsed transaction
    /// exactly its input.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = shortvec::encode(u16::try_from(self.signatures.len()).unwrap_or(u16::MAX));
        for signature in &self.signatures {
            out.extend_from_slice(signature);
        }
        out.extend_from_slice(&self.message_bytes);
        out
    }

    /// The transaction with slot `slot` replaced by `signature` and nothing else changed: the
    /// result is parsed again and must carry the same message bytes.
    ///
    /// # Errors
    ///
    /// [`SolTxError::NotSigner`] for a slot past the signers; any parse error of the result;
    /// [`SolTxError::Encoding`] when the message bytes would change.
    pub fn with_signature(&self, slot: u8, signature: &[u8; 64]) -> Result<Vec<u8>, SolTxError> {
        let index = usize::from(slot);
        if index >= self.signatures.len() {
            return Err(SolTxError::NotSigner);
        }
        let mut bytes = self.to_bytes();
        let prefix = shortvec::encode(u16::try_from(self.signatures.len()).unwrap_or(u16::MAX));
        let start = index
            .checked_mul(SIGNATURE_LEN)
            .and_then(|offset| offset.checked_add(prefix.len()))
            .ok_or(SolTxError::Truncated)?;
        let end = start
            .checked_add(SIGNATURE_LEN)
            .ok_or(SolTxError::Truncated)?;
        bytes
            .get_mut(start..end)
            .ok_or(SolTxError::Truncated)?
            .copy_from_slice(signature);
        let again = parse_wire_tx(&bytes)?;
        if again.message_bytes != self.message_bytes {
            return Err(SolTxError::Encoding);
        }
        Ok(bytes)
    }

    /// Whether every non-zero slot other than `ours` is a valid signature of its signer
    /// (`verify_strict`); with `require_all`, also that none of them is zero (a send).
    #[must_use]
    pub fn foreign_signatures_ok(&self, ours: u8, require_all: bool) -> bool {
        self.signatures
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != usize::from(ours))
            .all(|(index, signature)| {
                if is_unsigned(signature) {
                    return !require_all;
                }
                self.message.static_keys.get(index).is_some_and(|key| {
                    verify_strict(key.as_bytes(), &self.message_bytes, signature)
                })
            })
    }
}
