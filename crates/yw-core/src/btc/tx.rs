//! Transaction model, strict parser and serializer (spec/08 §6.5), and size estimates (§7.2).
//!
//! The parser is shared by previous-transaction verification (arbitrary versions and scripts,
//! §5) and post-sign verification (§11.2). It never panics: minimal `CompactSize` only, values
//! capped at `0x0200_0000` and at the remaining bytes, element counts checked against the
//! remaining bytes before any allocation (input 41, output 9, witness item 1), a strict segwit
//! marker/flag, at least one non-empty witness in segwit form, at least one input and one
//! output, every output value and their sum `<= MAX_MONEY`, and no trailing bytes.
#![deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use core::fmt;

use sha2::{Digest, Sha256};

use super::MAX_MONEY;
use super::amount::Sats;
use crate::hex::{self, HexError};

/// Largest `CompactSize` value accepted (Core `MAX_SIZE`).
pub const MAX_COMPACT_SIZE: u64 = 0x0200_0000;
/// Smallest serialized input (outpoint 36 + script length 1 + sequence 4).
pub const MIN_INPUT_SIZE: usize = 41;
/// Smallest serialized output (value 8 + script length 1).
pub const MIN_OUTPUT_SIZE: usize = 9;
/// Smallest serialized witness item (length 1).
pub const MIN_WITNESS_ITEM_SIZE: usize = 1;
/// Witness scale factor.
pub const WITNESS_SCALE_FACTOR: u64 = 4;

/// `SHA256(SHA256(data))`.
#[must_use]
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    Sha256::digest(Sha256::digest(data)).into()
}

/// A transaction id in internal byte order (the `SHA256d` output). Displayed reversed, as
/// lowercase hex (`^[0-9a-f]{64}$`).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Txid([u8; 32]);

impl Txid {
    /// Wraps internal-order bytes.
    #[must_use]
    pub const fn from_bytes(internal: [u8; 32]) -> Self {
        Self(internal)
    }

    /// Internal-order bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Internal-order bytes by value.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Parses display-order text: exactly 64 lowercase hex digits (uppercase is rejected).
    ///
    /// # Errors
    ///
    /// [`HexError`] for a wrong length or a non-lowercase-hex digit.
    pub fn from_display_hex(text: &str) -> Result<Self, HexError> {
        let mut bytes = hex::decode_array::<32>(text)?;
        bytes.reverse();
        Ok(Self(bytes))
    }

    /// Display-order lowercase hex.
    #[must_use]
    pub fn to_display_hex(self) -> String {
        let mut bytes = self.0;
        bytes.reverse();
        hex::encode(&bytes)
    }
}

impl fmt::Debug for Txid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Txid({})", self.to_display_hex())
    }
}

impl fmt::Display for Txid {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_display_hex())
    }
}

/// A previous output reference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OutPoint {
    /// Transaction id (internal order).
    pub txid: Txid,
    /// Output index.
    pub vout: u32,
}

impl OutPoint {
    /// The coinbase prevout `0^32:0xFFFFFFFF`.
    pub const COINBASE: Self = Self {
        txid: Txid([0; 32]),
        vout: u32::MAX,
    };
}

impl fmt::Display for OutPoint {
    /// `<txid display hex>:<vout decimal>` (the `BtcMeta` outpoint text, spec/08 §12.3).
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}:{}", self.txid, self.vout)
    }
}

/// A transaction input.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TxIn {
    /// The output being spent.
    pub prevout: OutPoint,
    /// `scriptSig` (empty for our P2WPKH inputs).
    pub script_sig: Vec<u8>,
    /// `nSequence`.
    pub sequence: u32,
    /// Witness stack (empty for non-witness inputs).
    pub witness: Vec<Vec<u8>>,
}

/// A transaction output.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TxOut {
    /// Amount.
    pub value: Sats,
    /// `scriptPubKey`.
    pub script_pubkey: Vec<u8>,
}

/// A transaction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Transaction {
    /// `nVersion` (any value for previous transactions; 2 for ours).
    pub version: u32,
    /// Inputs.
    pub inputs: Vec<TxIn>,
    /// Outputs.
    pub outputs: Vec<TxOut>,
    /// `nLockTime`.
    pub lock_time: u32,
}

impl Transaction {
    /// `true` when any input has a non-empty witness (serialized in segwit form).
    #[must_use]
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|input| !input.witness.is_empty())
    }

    /// `true` for a coinbase: exactly one input spending `0^32:0xFFFFFFFF` (spec/08 §5 step 6).
    #[must_use]
    pub fn is_coinbase(&self) -> bool {
        matches!(self.inputs.as_slice(), [only] if only.prevout == OutPoint::COINBASE)
    }
}

/// Strict parser rejection (spec/08 §6.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TxParseError {
    /// The bytes end inside a field.
    Truncated,
    /// A `CompactSize` that has a shorter encoding.
    NonMinimalCompactSize,
    /// A `CompactSize` above `0x0200_0000` or above the remaining bytes, or a count whose
    /// minimum serialized size exceeds the remaining bytes.
    CompactSizeTooLarge,
    /// Segwit marker `0x00` not followed by flag `0x01`.
    InvalidSegwitFlag,
    /// Segwit form but every witness is empty.
    EmptyWitnesses,
    /// No inputs.
    NoInputs,
    /// No outputs.
    NoOutputs,
    /// An output value above `MAX_MONEY`.
    ValueTooLarge,
    /// The output values sum above `MAX_MONEY`.
    TotalTooLarge,
    /// Bytes after `nLockTime`.
    TrailingBytes,
}

impl fmt::Display for TxParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "transaction is truncated",
            Self::NonMinimalCompactSize => "non-minimal CompactSize",
            Self::CompactSizeTooLarge => "CompactSize is too large",
            Self::InvalidSegwitFlag => "invalid segwit flag",
            Self::EmptyWitnesses => "segwit transaction without witness data",
            Self::NoInputs => "transaction has no inputs",
            Self::NoOutputs => "transaction has no outputs",
            Self::ValueTooLarge => "output value above MAX_MONEY",
            Self::TotalTooLarge => "output total above MAX_MONEY",
            Self::TrailingBytes => "trailing bytes after the transaction",
        })
    }
}

impl std::error::Error for TxParseError {}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], TxParseError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(TxParseError::Truncated)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(TxParseError::Truncated)?;
        self.position = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TxParseError> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| TxParseError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, TxParseError> {
        Ok(u8::from_le_bytes(self.array::<1>()?))
    }

    fn u16(&mut self) -> Result<u16, TxParseError> {
        Ok(u16::from_le_bytes(self.array::<2>()?))
    }

    fn u32(&mut self) -> Result<u32, TxParseError> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, TxParseError> {
        Ok(u64::from_le_bytes(self.array::<8>()?))
    }

    /// Minimal `CompactSize`, `<= 0x0200_0000` and `<=` the bytes left after it.
    fn compact_size(&mut self) -> Result<usize, TxParseError> {
        let value = match self.u8()? {
            0xfd => {
                let value = self.u16()?;
                if value < 0xfd {
                    return Err(TxParseError::NonMinimalCompactSize);
                }
                u64::from(value)
            }
            0xfe => {
                let value = self.u32()?;
                if value < 0x1_0000 {
                    return Err(TxParseError::NonMinimalCompactSize);
                }
                u64::from(value)
            }
            0xff => {
                let value = self.u64()?;
                if value < 0x1_0000_0000 {
                    return Err(TxParseError::NonMinimalCompactSize);
                }
                value
            }
            small => u64::from(small),
        };
        if value > MAX_COMPACT_SIZE {
            return Err(TxParseError::CompactSizeTooLarge);
        }
        let value = usize::try_from(value).map_err(|_| TxParseError::CompactSizeTooLarge)?;
        if value > self.remaining() {
            return Err(TxParseError::CompactSizeTooLarge);
        }
        Ok(value)
    }

    /// An element count whose `count × min_size` fits in the remaining bytes.
    fn count(&mut self, min_size: usize) -> Result<usize, TxParseError> {
        let count = self.compact_size()?;
        match count.checked_mul(min_size) {
            Some(needed) if needed <= self.remaining() => Ok(count),
            _ => Err(TxParseError::CompactSizeTooLarge),
        }
    }

    fn var_bytes(&mut self) -> Result<&'a [u8], TxParseError> {
        let length = self.compact_size()?;
        self.take(length)
    }
}

/// Byte offsets the txid of the original bytes needs (spec/08 §5 step 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Layout {
    /// Start of the input-count `CompactSize` (6 for segwit form, 4 otherwise).
    pub(crate) inputs_start: usize,
    /// End of the last output.
    pub(crate) outputs_end: usize,
}

/// [`parse_transaction`] plus the [`Layout`] of the parsed bytes.
pub(crate) fn parse_with_layout(bytes: &[u8]) -> Result<(Transaction, Layout), TxParseError> {
    let mut reader = Reader::new(bytes);
    let version = reader.u32()?;
    let segwit = reader.peek() == Some(0);
    if segwit {
        reader.u8()?;
        if reader.u8()? != 1 {
            return Err(TxParseError::InvalidSegwitFlag);
        }
    }
    let inputs_start = reader.position;
    let input_count = reader.count(MIN_INPUT_SIZE)?;
    if input_count == 0 {
        return Err(TxParseError::NoInputs);
    }
    let mut inputs = Vec::with_capacity(input_count);
    for _ in 0..input_count {
        let txid = Txid(reader.array::<32>()?);
        let vout = reader.u32()?;
        let script_sig = reader.var_bytes()?.to_vec();
        let sequence = reader.u32()?;
        inputs.push(TxIn {
            prevout: OutPoint { txid, vout },
            script_sig,
            sequence,
            witness: Vec::new(),
        });
    }
    let output_count = reader.count(MIN_OUTPUT_SIZE)?;
    if output_count == 0 {
        return Err(TxParseError::NoOutputs);
    }
    let mut outputs = Vec::with_capacity(output_count);
    let mut total = 0_u64;
    for _ in 0..output_count {
        let value = Sats::new(reader.u64()?).ok_or(TxParseError::ValueTooLarge)?;
        total = total
            .checked_add(value.get())
            .filter(|sum| *sum <= MAX_MONEY)
            .ok_or(TxParseError::TotalTooLarge)?;
        let script_pubkey = reader.var_bytes()?.to_vec();
        outputs.push(TxOut {
            value,
            script_pubkey,
        });
    }
    let outputs_end = reader.position;
    if segwit {
        for input in &mut inputs {
            let item_count = reader.count(MIN_WITNESS_ITEM_SIZE)?;
            let mut items = Vec::with_capacity(item_count);
            for _ in 0..item_count {
                items.push(reader.var_bytes()?.to_vec());
            }
            input.witness = items;
        }
        if inputs.iter().all(|input| input.witness.is_empty()) {
            return Err(TxParseError::EmptyWitnesses);
        }
    }
    let lock_time = reader.u32()?;
    if reader.remaining() != 0 {
        return Err(TxParseError::TrailingBytes);
    }
    Ok((
        Transaction {
            version,
            inputs,
            outputs,
            lock_time,
        },
        Layout {
            inputs_start,
            outputs_end,
        },
    ))
}

/// Parses a serialized transaction with the strict rules of spec/08 §6.5.
///
/// # Errors
///
/// The first [`TxParseError`].
pub fn parse_transaction(bytes: &[u8]) -> Result<Transaction, TxParseError> {
    parse_with_layout(bytes).map(|(tx, _)| tx)
}

/// Appends a minimal `CompactSize`.
pub(crate) fn write_compact_size(out: &mut Vec<u8>, value: usize) {
    let value = u64::try_from(value).unwrap_or(u64::MAX);
    if let Ok(small) = u8::try_from(value)
        && small < 0xfd
    {
        out.push(small);
    } else if let Ok(medium) = u16::try_from(value) {
        out.push(0xfd);
        out.extend_from_slice(&medium.to_le_bytes());
    } else if let Ok(large) = u32::try_from(value) {
        out.push(0xfe);
        out.extend_from_slice(&large.to_le_bytes());
    } else {
        out.push(0xff);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// `CompactSize` length of `value`.
const fn compact_size_len(value: usize) -> usize {
    if value < 0xfd {
        1
    } else if value <= 0xffff {
        3
    } else if value <= 0xffff_ffff {
        5
    } else {
        9
    }
}

fn var_len(bytes: &[u8]) -> usize {
    compact_size_len(bytes.len()).saturating_add(bytes.len())
}

fn serialized_len(tx: &Transaction, segwit: bool) -> usize {
    let mut length = 8_usize
        .saturating_add(compact_size_len(tx.inputs.len()))
        .saturating_add(compact_size_len(tx.outputs.len()));
    for input in &tx.inputs {
        length = length
            .saturating_add(40)
            .saturating_add(var_len(&input.script_sig));
        if segwit {
            length = length.saturating_add(compact_size_len(input.witness.len()));
            for item in &input.witness {
                length = length.saturating_add(var_len(item));
            }
        }
    }
    for output in &tx.outputs {
        length = length
            .saturating_add(8)
            .saturating_add(var_len(&output.script_pubkey));
    }
    if segwit {
        length = length.saturating_add(2);
    }
    length
}

/// Serializes `tx`. With `with_witness` and at least one non-empty witness the segwit form
/// (`marker 0x00, flag 0x01`, witnesses before `nLockTime`) is written; otherwise the legacy form.
#[must_use]
pub fn serialize(tx: &Transaction, with_witness: bool) -> Vec<u8> {
    let segwit = with_witness && tx.has_witness();
    let mut out = Vec::with_capacity(serialized_len(tx, segwit));
    out.extend_from_slice(&tx.version.to_le_bytes());
    if segwit {
        out.extend_from_slice(&[0x00, 0x01]);
    }
    write_compact_size(&mut out, tx.inputs.len());
    for input in &tx.inputs {
        out.extend_from_slice(input.prevout.txid.as_bytes());
        out.extend_from_slice(&input.prevout.vout.to_le_bytes());
        write_compact_size(&mut out, input.script_sig.len());
        out.extend_from_slice(&input.script_sig);
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }
    write_compact_size(&mut out, tx.outputs.len());
    for output in &tx.outputs {
        out.extend_from_slice(&output.value.get().to_le_bytes());
        write_compact_size(&mut out, output.script_pubkey.len());
        out.extend_from_slice(&output.script_pubkey);
    }
    if segwit {
        for input in &tx.inputs {
            write_compact_size(&mut out, input.witness.len());
            for item in &input.witness {
                write_compact_size(&mut out, item.len());
                out.extend_from_slice(item);
            }
        }
    }
    out.extend_from_slice(&tx.lock_time.to_le_bytes());
    out
}

/// `SHA256d(serialize(tx, false))` (internal order).
#[must_use]
pub fn txid(tx: &Transaction) -> Txid {
    Txid(sha256d(&serialize(tx, false)))
}

/// `SHA256d(serialize(tx, true))` (internal order; equals the txid without witnesses).
#[must_use]
pub fn wtxid(tx: &Transaction) -> [u8; 32] {
    sha256d(&serialize(tx, true))
}

/// `3 × len(base) + len(total)` weight units.
#[must_use]
pub fn weight(tx: &Transaction) -> u64 {
    let base = u64::try_from(serialized_len(tx, false)).unwrap_or(u64::MAX);
    let total = u64::try_from(serialized_len(tx, tx.has_witness())).unwrap_or(u64::MAX);
    base.saturating_mul(WITNESS_SCALE_FACTOR.saturating_sub(1))
        .saturating_add(total)
}

/// `ceil(weight / 4)` virtual bytes.
#[must_use]
pub fn vsize(tx: &Transaction) -> u64 {
    weight(tx).div_ceil(WITNESS_SCALE_FACTOR)
}

/// Weight of the fixed part: `(version 4 + lock_time 4 + n_in 1 + n_out 1) × 4 + marker/flag 2`.
pub const ESTIMATE_BASE_WEIGHT: u64 = 42;
/// Weight of one P2WPKH input: `41 × 4 + witness 107` (count 1, length 1, low-R signature 71,
/// length 1, compressed key 33).
pub const ESTIMATE_INPUT_WEIGHT: u64 = 271;
/// Largest count or script length the estimate's one-byte `CompactSize` covers.
const ESTIMATE_MAX_COMPACT: usize = 252;

/// Pre-signing weight of `inputs` P2WPKH inputs and outputs with the given scriptPubKey lengths
/// (spec/08 §7.2): `42 + 271·k + Σ 4·(9 + len)`. Real signed weight is never larger.
///
/// `None` for 0 inputs or outputs, or more than 252 inputs, outputs or script bytes (the formula
/// assumes one-byte `CompactSize` fields).
#[must_use]
pub fn estimate_weight(inputs: usize, output_spk_lens: &[usize]) -> Option<u64> {
    if inputs == 0
        || inputs > ESTIMATE_MAX_COMPACT
        || output_spk_lens.is_empty()
        || output_spk_lens.len() > ESTIMATE_MAX_COMPACT
        || output_spk_lens
            .iter()
            .any(|len| *len > ESTIMATE_MAX_COMPACT)
    {
        return None;
    }
    let mut weight = ESTIMATE_INPUT_WEIGHT
        .checked_mul(u64::try_from(inputs).ok()?)?
        .checked_add(ESTIMATE_BASE_WEIGHT)?;
    for len in output_spk_lens {
        let output = u64::try_from(*len)
            .ok()?
            .checked_add(9)?
            .checked_mul(WITNESS_SCALE_FACTOR)?;
        weight = weight.checked_add(output)?;
    }
    Some(weight)
}

/// `ceil(estimate_weight / 4)`.
#[must_use]
pub fn estimate_vsize(inputs: usize, output_spk_lens: &[usize]) -> Option<u64> {
    estimate_weight(inputs, output_spk_lens).map(|weight| weight.div_ceil(WITNESS_SCALE_FACTOR))
}
