//! Transparent-only Zcash v5 transactions (ZIP 225; spec/12 §5): the strict serializer and
//! parser, and the ZIP 244 transaction identifier.
//!
//! Layout (all integers little-endian):
//!
//! | field | bytes |
//! |---|---|
//! | `header` = `fOverwintered ‖ nVersion` = `0x80000005` | 4 |
//! | `nVersionGroupId` = `0x26A7270A` | 4 |
//! | `nConsensusBranchId` | 4 |
//! | `lock_time` | 4 |
//! | `nExpiryHeight` | 4 |
//! | `tx_in_count`, `tx_in` (outpoint 36, `script_sig` var, `nSequence` 4) | var |
//! | `tx_out_count`, `tx_out` (value 8, `script_pubkey` var) | var |
//! | `nSpendsSapling` = 0, `nOutputsSapling` = 0, `nActionsOrchard` = 0 | 1 + 1 + 1 |
//!
//! The parser accepts exactly this shape: any shielded part is refused
//! ([`ZecTxError::Shielded`]), because this wallet never builds or tracks one.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::blake2b::blake2b_256;
use crate::btc::tx::write_compact_size;
use crate::hex;

/// `fOverwintered | 5` (ZIP 225).
pub const V5_HEADER: u32 = 0x8000_0005;
/// v5 version group id (ZIP 225).
pub const V5_VERSION_GROUP_ID: u32 = 0x26A7_270A;
/// Largest serialized size we parse (a v5 transparent transaction we build is far smaller).
pub const MAX_TX_BYTES: usize = 100_000;
/// Largest value of one output or of the sum (zatoshis; 21 million ZEC).
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;

/// A transaction outpoint: txid in internal byte order and output index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ZecOutPoint {
    /// Txid, internal byte order (the display hex reversed).
    pub txid: [u8; 32],
    /// Output index.
    pub index: u32,
}

impl ZecOutPoint {
    /// The 36 serialized bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 36] {
        let mut out = [0_u8; 36];
        let (txid, index) = out.split_at_mut(32);
        txid.copy_from_slice(&self.txid);
        index.copy_from_slice(&self.index.to_le_bytes());
        out
    }
}

/// A transparent input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecTxIn {
    /// Spent output.
    pub prevout: ZecOutPoint,
    /// `scriptSig` (empty before signing).
    pub script_sig: Vec<u8>,
    /// `nSequence`.
    pub sequence: u32,
}

/// A transparent output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecTxOut {
    /// Value in zatoshis.
    pub value: u64,
    /// `scriptPubKey`.
    pub script_pubkey: Vec<u8>,
}

/// A transparent-only v5 transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZecTx {
    /// `nConsensusBranchId`.
    pub branch_id: u32,
    /// `lock_time`.
    pub lock_time: u32,
    /// `nExpiryHeight`.
    pub expiry_height: u32,
    /// Inputs.
    pub inputs: Vec<ZecTxIn>,
    /// Outputs.
    pub outputs: Vec<ZecTxOut>,
}

/// Why bytes are not a transparent-only v5 transaction we accept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZecTxError {
    /// Fewer bytes than a field needs.
    Truncated,
    /// Not `0x80000005` / `0x26A7270A`.
    NotV5,
    /// A non-minimal or oversized `CompactSize`.
    CompactSize,
    /// A Sapling or Orchard part is present.
    Shielded,
    /// An output value (or the sum) above `MAX_MONEY`.
    Value,
    /// Bytes after the Orchard count, or more than [`MAX_TX_BYTES`].
    TrailingBytes,
}

impl fmt::Display for ZecTxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "transaction is truncated",
            Self::NotV5 => "not a v5 transaction",
            Self::CompactSize => "invalid CompactSize",
            Self::Shielded => "transaction has a shielded part",
            Self::Value => "output value above MAX_MONEY",
            Self::TrailingBytes => "trailing bytes after the transaction",
        })
    }
}

impl std::error::Error for ZecTxError {}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ZecTxError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(ZecTxError::Truncated)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(ZecTxError::Truncated)?;
        self.position = end;
        Ok(slice)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ZecTxError> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| ZecTxError::Truncated)
    }

    fn u32(&mut self) -> Result<u32, ZecTxError> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }

    fn u64(&mut self) -> Result<u64, ZecTxError> {
        Ok(u64::from_le_bytes(self.array::<8>()?))
    }

    fn compact_size(&mut self) -> Result<usize, ZecTxError> {
        let [first] = self.array::<1>()?;
        let value = match first {
            0xfd => {
                let value = u16::from_le_bytes(self.array::<2>()?);
                if value < 0xfd {
                    return Err(ZecTxError::CompactSize);
                }
                u64::from(value)
            }
            0xfe => {
                let value = u32::from_le_bytes(self.array::<4>()?);
                if value < 0x1_0000 {
                    return Err(ZecTxError::CompactSize);
                }
                u64::from(value)
            }
            0xff => return Err(ZecTxError::CompactSize),
            small => u64::from(small),
        };
        let value = usize::try_from(value).map_err(|_| ZecTxError::CompactSize)?;
        if value > self.bytes.len().saturating_sub(self.position) {
            return Err(ZecTxError::CompactSize);
        }
        Ok(value)
    }

    fn var_bytes(&mut self) -> Result<&'a [u8], ZecTxError> {
        let length = self.compact_size()?;
        self.take(length)
    }
}

/// Parses a transparent-only v5 transaction (strict: see the module table).
///
/// # Errors
///
/// [`ZecTxError`].
pub fn parse_tx(bytes: &[u8]) -> Result<ZecTx, ZecTxError> {
    if bytes.len() > MAX_TX_BYTES {
        return Err(ZecTxError::TrailingBytes);
    }
    let mut reader = Reader { bytes, position: 0 };
    if reader.u32()? != V5_HEADER || reader.u32()? != V5_VERSION_GROUP_ID {
        return Err(ZecTxError::NotV5);
    }
    let branch_id = reader.u32()?;
    let lock_time = reader.u32()?;
    let expiry_height = reader.u32()?;
    let input_count = reader.compact_size()?;
    let mut inputs = Vec::with_capacity(input_count.min(1_000));
    for _ in 0..input_count {
        let txid = reader.array::<32>()?;
        let index = reader.u32()?;
        let script_sig = reader.var_bytes()?.to_vec();
        let sequence = reader.u32()?;
        inputs.push(ZecTxIn {
            prevout: ZecOutPoint { txid, index },
            script_sig,
            sequence,
        });
    }
    let output_count = reader.compact_size()?;
    let mut outputs = Vec::with_capacity(output_count.min(1_000));
    let mut total = 0_u64;
    for _ in 0..output_count {
        let value = reader.u64()?;
        total = total.checked_add(value).ok_or(ZecTxError::Value)?;
        if value > MAX_MONEY || total > MAX_MONEY {
            return Err(ZecTxError::Value);
        }
        let script_pubkey = reader.var_bytes()?.to_vec();
        outputs.push(ZecTxOut {
            value,
            script_pubkey,
        });
    }
    // nSpendsSapling, nOutputsSapling, nActionsOrchard: all zero, nothing after them.
    for _ in 0..3 {
        if reader.compact_size()? != 0 {
            return Err(ZecTxError::Shielded);
        }
    }
    if reader.position != bytes.len() {
        return Err(ZecTxError::TrailingBytes);
    }
    Ok(ZecTx {
        branch_id,
        lock_time,
        expiry_height,
        inputs,
        outputs,
    })
}

/// The v5 serialization.
#[must_use]
pub fn serialize_tx(tx: &ZecTx) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        23 + tx
            .inputs
            .iter()
            .map(|input| 41 + input.script_sig.len())
            .sum::<usize>()
            + tx.outputs
                .iter()
                .map(|output| 9 + output.script_pubkey.len())
                .sum::<usize>(),
    );
    out.extend_from_slice(&V5_HEADER.to_le_bytes());
    out.extend_from_slice(&V5_VERSION_GROUP_ID.to_le_bytes());
    out.extend_from_slice(&tx.branch_id.to_le_bytes());
    out.extend_from_slice(&tx.lock_time.to_le_bytes());
    out.extend_from_slice(&tx.expiry_height.to_le_bytes());
    write_compact_size(&mut out, tx.inputs.len());
    for input in &tx.inputs {
        out.extend_from_slice(&input.prevout.to_bytes());
        write_compact_size(&mut out, input.script_sig.len());
        out.extend_from_slice(&input.script_sig);
        out.extend_from_slice(&input.sequence.to_le_bytes());
    }
    write_compact_size(&mut out, tx.outputs.len());
    for output in &tx.outputs {
        out.extend_from_slice(&output.value.to_le_bytes());
        write_compact_size(&mut out, output.script_pubkey.len());
        out.extend_from_slice(&output.script_pubkey);
    }
    out.extend_from_slice(&[0, 0, 0]);
    out
}

/// `"ZcashTxHash_" ‖ LE32(branch_id)` (ZIP 244 T / S root personalisation).
#[must_use]
pub fn root_persona(branch_id: u32) -> [u8; 16] {
    let mut persona = *b"ZcashTxHash_\0\0\0\0";
    if let Some(tail) = persona.get_mut(12..) {
        tail.copy_from_slice(&branch_id.to_le_bytes());
    }
    persona
}

/// ZIP 244 T.1 `header_digest`.
#[must_use]
pub fn header_digest(tx: &ZecTx) -> [u8; 32] {
    blake2b_256(
        b"ZTxIdHeadersHash",
        &[
            &V5_HEADER.to_le_bytes(),
            &V5_VERSION_GROUP_ID.to_le_bytes(),
            &tx.branch_id.to_le_bytes(),
            &tx.lock_time.to_le_bytes(),
            &tx.expiry_height.to_le_bytes(),
        ],
    )
}

/// ZIP 244 T.2a `prevouts_digest`.
#[must_use]
pub fn prevouts_digest(tx: &ZecTx) -> [u8; 32] {
    let bytes: Vec<u8> = tx
        .inputs
        .iter()
        .flat_map(|input| input.prevout.to_bytes())
        .collect();
    blake2b_256(b"ZTxIdPrevoutHash", &[&bytes])
}

/// ZIP 244 T.2b `sequence_digest`.
#[must_use]
pub fn sequence_digest(tx: &ZecTx) -> [u8; 32] {
    let bytes: Vec<u8> = tx
        .inputs
        .iter()
        .flat_map(|input| input.sequence.to_le_bytes())
        .collect();
    blake2b_256(b"ZTxIdSequencHash", &[&bytes])
}

/// ZIP 244 T.2c `outputs_digest`.
#[must_use]
pub fn outputs_digest(tx: &ZecTx) -> [u8; 32] {
    let mut bytes = Vec::new();
    for output in &tx.outputs {
        bytes.extend_from_slice(&output.value.to_le_bytes());
        write_compact_size(&mut bytes, output.script_pubkey.len());
        bytes.extend_from_slice(&output.script_pubkey);
    }
    blake2b_256(b"ZTxIdOutputsHash", &[&bytes])
}

/// ZIP 244 T.2 `transparent_digest` (txid form).
#[must_use]
pub fn transparent_txid_digest(tx: &ZecTx) -> [u8; 32] {
    if tx.inputs.is_empty() && tx.outputs.is_empty() {
        return blake2b_256(b"ZTxIdTranspaHash", &[]);
    }
    blake2b_256(
        b"ZTxIdTranspaHash",
        &[
            &prevouts_digest(tx),
            &sequence_digest(tx),
            &outputs_digest(tx),
        ],
    )
}

/// ZIP 244 T.3 `sapling_digest` of an empty Sapling bundle.
#[must_use]
pub fn empty_sapling_digest() -> [u8; 32] {
    blake2b_256(b"ZTxIdSaplingHash", &[])
}

/// ZIP 244 T.4 `orchard_digest` of an empty Orchard bundle.
#[must_use]
pub fn empty_orchard_digest() -> [u8; 32] {
    blake2b_256(b"ZTxIdOrchardHash", &[])
}

/// The ZIP 244 txid digest in internal byte order (`txid` of the test vectors).
#[must_use]
pub fn txid(tx: &ZecTx) -> [u8; 32] {
    txid_with(tx, &empty_sapling_digest(), &empty_orchard_digest())
}

/// [`txid`] with given Sapling / Orchard digests (the official vectors carry shielded parts).
pub(crate) fn txid_with(tx: &ZecTx, sapling: &[u8; 32], orchard: &[u8; 32]) -> [u8; 32] {
    blake2b_256(
        &root_persona(tx.branch_id),
        &[
            &header_digest(tx),
            &transparent_txid_digest(tx),
            sapling,
            orchard,
        ],
    )
}

/// The txid as RPC display hex (bytes reversed, lowercase).
#[must_use]
pub fn txid_display(txid: &[u8; 32]) -> String {
    let mut reversed = *txid;
    reversed.reverse();
    hex::encode(&reversed)
}

/// Display hex (64 lowercase or uppercase digits) back to internal order.
///
/// # Errors
///
/// [`hex::HexError`] for anything else.
pub fn txid_from_display(text: &str) -> Result<[u8; 32], hex::HexError> {
    let mut bytes = hex::decode_array::<32>(text)?;
    bytes.reverse();
    Ok(bytes)
}
