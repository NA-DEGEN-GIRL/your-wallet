//! Legacy message/transaction encoding and the strict template parser with re-encoding identity
//! (spec/07 §7, §9).
//!
//! Account order follows solana-sdk `CompiledKeys` (fee payer, then writable signers, readonly
//! signers, writable non-signers, readonly non-signers, each group ascending by raw bytes). The
//! only accepted message in v1 is `T_SOL` (`header [1, 0, 2]`, keys
//! `[from, to, System, ComputeBudget]`, instructions limit → price → transfer).
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::address::{COMPUTE_BUDGET_PROGRAM, SYSTEM_PROGRAM, SolAddress, SolCluster};
use super::shortvec::{self, ShortVecError};
use super::template::{
    SOL_MAX_COMPUTE_UNITS, SOL_MAX_TX_BYTES, SolAsset, SolTransferCore, T_SOL_HEADER,
    set_compute_unit_limit_data, set_compute_unit_price_data, system_transfer_data,
};

/// Strict parser failure (spec/07 §9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolParseError {
    /// The input ends early.
    Truncated,
    /// A compact-u16 length is malformed.
    ShortVec(ShortVecError),
    /// A versioned message (`0x80`, `0x81`, …).
    Versioned,
    /// Not one of the wallet's templates (header, key count or instruction count).
    UnknownTemplate,
    /// Not exactly one signature.
    BadSignatureCount,
    /// A key appears twice.
    DuplicateKey,
    /// A program or account index is out of range.
    BadIndex,
    /// The program index points to another program.
    UnexpectedProgram,
    /// Account count or indices differ from the template.
    BadAccounts,
    /// Instruction data length or tag differs from the template.
    BadData,
    /// The header roles or the in-group ascending order are violated.
    BadGroupOrder,
    /// A mint outside the allowlist (`T_SPL`, v1.1).
    NotAllowlisted,
    /// An associated token account differs from its derivation (`T_SPL`, v1.1).
    AtaMismatch,
    /// Zero amount.
    ZeroAmount,
    /// Compute-unit limit outside `1..=1_400_000`.
    BadComputeLimit,
    /// Bytes after the last instruction.
    TrailingBytes,
    /// Longer than 1,232 bytes.
    TooLarge,
}

impl fmt::Display for SolParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Solana 메시지가 지갑 템플릿과 다릅니다")
    }
}

impl std::error::Error for SolParseError {}

impl From<ShortVecError> for SolParseError {
    fn from(error: ShortVecError) -> Self {
        Self::ShortVec(error)
    }
}

/// A compiled instruction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CompiledIx {
    /// Program key index.
    pub(crate) program: u8,
    /// Account key indices.
    pub(crate) accounts: Vec<u8>,
    /// Data.
    pub(crate) data: Vec<u8>,
}

fn push_len(out: &mut Vec<u8>, len: usize) {
    shortvec::encode_into(u16::try_from(len).unwrap_or(u16::MAX), out);
}

/// The generic legacy message encoder (templates and the solana-sdk vector test only).
pub(crate) fn encode_legacy_message(
    header: [u8; 3],
    keys: &[[u8; 32]],
    blockhash: &[u8; 32],
    instructions: &[CompiledIx],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        3_usize
            .saturating_add(3)
            .saturating_add(keys.len().saturating_mul(32))
            .saturating_add(32)
            .saturating_add(3),
    );
    out.extend_from_slice(&header);
    push_len(&mut out, keys.len());
    for key in keys {
        out.extend_from_slice(key);
    }
    out.extend_from_slice(blockhash);
    push_len(&mut out, instructions.len());
    for ix in instructions {
        out.push(ix.program);
        push_len(&mut out, ix.accounts.len());
        out.extend_from_slice(&ix.accounts);
        push_len(&mut out, ix.data.len());
        out.extend_from_slice(&ix.data);
    }
    out
}

/// The message bytes of a transfer (`T_SOL`, spec/07 §8.2).
#[must_use]
pub fn encode_message(core: &SolTransferCore, blockhash: &[u8; 32]) -> Vec<u8> {
    match core.asset {
        SolAsset::Sol => encode_legacy_message(
            T_SOL_HEADER,
            &[
                core.from.to_bytes(),
                core.to.to_bytes(),
                SYSTEM_PROGRAM.to_bytes(),
                COMPUTE_BUDGET_PROGRAM.to_bytes(),
            ],
            blockhash,
            &[
                CompiledIx {
                    program: 3,
                    accounts: Vec::new(),
                    data: set_compute_unit_limit_data(core.cu_limit),
                },
                CompiledIx {
                    program: 3,
                    accounts: Vec::new(),
                    data: set_compute_unit_price_data(core.cu_price_micro),
                },
                CompiledIx {
                    program: 2,
                    accounts: vec![0, 1],
                    data: system_transfer_data(core.amount),
                },
            ],
        ),
    }
}

/// `01 ‖ signature ‖ message`.
#[must_use]
pub fn assemble_transaction(signature: &[u8; 64], message: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(message.len().saturating_add(65));
    out.push(0x01);
    out.extend_from_slice(signature);
    out.extend_from_slice(message);
    out
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], SolParseError> {
        let end = self.at.checked_add(len).ok_or(SolParseError::Truncated)?;
        let slice = self
            .bytes
            .get(self.at..end)
            .ok_or(SolParseError::Truncated)?;
        self.at = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, SolParseError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(SolParseError::Truncated)
    }

    fn array32(&mut self) -> Result<[u8; 32], SolParseError> {
        self.take(32)?
            .try_into()
            .map_err(|_| SolParseError::Truncated)
    }

    fn short_len(&mut self) -> Result<usize, SolParseError> {
        let rest = self.bytes.get(self.at..).ok_or(SolParseError::Truncated)?;
        let (value, used) = shortvec::decode(rest)?;
        self.at = self.at.checked_add(used).ok_or(SolParseError::Truncated)?;
        Ok(usize::from(value))
    }

    fn instruction(&mut self, n_keys: usize) -> Result<CompiledIx, SolParseError> {
        let program = self.byte()?;
        if usize::from(program) >= n_keys {
            return Err(SolParseError::BadIndex);
        }
        let n_accounts = self.short_len()?;
        let accounts = self.take(n_accounts)?.to_vec();
        if accounts.iter().any(|index| usize::from(*index) >= n_keys) {
            return Err(SolParseError::BadIndex);
        }
        let data_len = self.short_len()?;
        let data = self.take(data_len)?.to_vec();
        Ok(CompiledIx {
            program,
            accounts,
            data,
        })
    }
}

fn le_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn le_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

/// Checks one instruction against its template slot: program key, exact accounts, data length
/// and tag; returns the data payload after the tag.
fn expect_ix<'a>(
    ix: &'a CompiledIx,
    keys: &[[u8; 32]],
    program: &SolAddress,
    accounts: &[u8],
    tag: &[u8],
    data_len: usize,
) -> Result<&'a [u8], SolParseError> {
    let key = keys
        .get(usize::from(ix.program))
        .ok_or(SolParseError::BadIndex)?;
    if key != program.as_bytes() {
        return Err(SolParseError::UnexpectedProgram);
    }
    if ix.accounts != accounts {
        return Err(SolParseError::BadAccounts);
    }
    if ix.data.len() != data_len || !ix.data.starts_with(tag) {
        return Err(SolParseError::BadData);
    }
    ix.data.get(tag.len()..).ok_or(SolParseError::BadData)
}

/// Parses a message strictly as one of the wallet's templates (spec/07 §9 steps 2–9). The
/// template constants of spec/07 §10 are not enforced here (intent creation enforces them and
/// the re-encoding identity binds them).
///
/// # Errors
///
/// [`SolParseError`]; no partial result.
pub fn parse_message(
    msg: &[u8],
    cluster: SolCluster,
) -> Result<(SolTransferCore, [u8; 32]), SolParseError> {
    // The cluster only matters for the SPL allowlist (v1.1).
    let _ = cluster;
    if msg.len() > SOL_MAX_TX_BYTES.saturating_sub(65) {
        return Err(SolParseError::TooLarge);
    }
    let mut reader = Reader { bytes: msg, at: 0 };
    let first = *msg.first().ok_or(SolParseError::Truncated)?;
    if first & 0x80 != 0 {
        return Err(SolParseError::Versioned);
    }
    let header: [u8; 3] = reader
        .take(3)?
        .try_into()
        .map_err(|_| SolParseError::Truncated)?;
    if header != T_SOL_HEADER {
        return Err(SolParseError::UnknownTemplate);
    }
    let n_keys = reader.short_len()?;
    if n_keys != 4 {
        return Err(SolParseError::UnknownTemplate);
    }
    let mut keys: Vec<[u8; 32]> = Vec::with_capacity(4);
    for _ in 0..n_keys {
        let key = reader.array32()?;
        if keys.contains(&key) {
            return Err(SolParseError::DuplicateKey);
        }
        keys.push(key);
    }
    let blockhash = reader.array32()?;
    let n_ix = reader.short_len()?;
    if n_ix != 3 {
        return Err(SolParseError::UnknownTemplate);
    }
    let limit_ix = reader.instruction(n_keys)?;
    let price_ix = reader.instruction(n_keys)?;
    let transfer_ix = reader.instruction(n_keys)?;
    let limit = expect_ix(&limit_ix, &keys, &COMPUTE_BUDGET_PROGRAM, &[], &[0x02], 5)?;
    let price = expect_ix(&price_ix, &keys, &COMPUTE_BUDGET_PROGRAM, &[], &[0x03], 9)?;
    let lamports = expect_ix(
        &transfer_ix,
        &keys,
        &SYSTEM_PROGRAM,
        &[0, 1],
        &[0x02, 0, 0, 0],
        12,
    )?;
    // Roles: key 0 the writable signer (fee payer), key 1 the writable non-signer, keys 2–3 the
    // readonly non-signers (the two programs) in ascending raw-byte order.
    let (Some(readonly_a), Some(readonly_b)) = (keys.get(2), keys.get(3)) else {
        return Err(SolParseError::Truncated);
    };
    if readonly_a != SYSTEM_PROGRAM.as_bytes()
        || readonly_b != COMPUTE_BUDGET_PROGRAM.as_bytes()
        || readonly_a >= readonly_b
    {
        return Err(SolParseError::BadGroupOrder);
    }
    let (Some(from), Some(to)) = (keys.first(), keys.get(1)) else {
        return Err(SolParseError::Truncated);
    };
    let cu_limit = le_u32(limit).ok_or(SolParseError::BadData)?;
    let cu_price_micro = le_u64(price).ok_or(SolParseError::BadData)?;
    let amount = le_u64(lamports).ok_or(SolParseError::BadData)?;
    if amount == 0 {
        return Err(SolParseError::ZeroAmount);
    }
    if !(1..=SOL_MAX_COMPUTE_UNITS).contains(&cu_limit) {
        return Err(SolParseError::BadComputeLimit);
    }
    if reader.at != msg.len() {
        return Err(SolParseError::TrailingBytes);
    }
    Ok((
        SolTransferCore {
            from: SolAddress::from_bytes(*from),
            to: SolAddress::from_bytes(*to),
            asset: SolAsset::Sol,
            amount,
            cu_limit,
            cu_price_micro,
        },
        blockhash,
    ))
}

/// Parses a signed transaction: `tx[0] == 0x01`, the 64-byte signature, then the message.
///
/// # Errors
///
/// [`SolParseError`].
pub fn parse_transaction(
    tx: &[u8],
    cluster: SolCluster,
) -> Result<(SolTransferCore, [u8; 32], [u8; 64]), SolParseError> {
    if tx.len() > SOL_MAX_TX_BYTES {
        return Err(SolParseError::TooLarge);
    }
    let count = *tx.first().ok_or(SolParseError::Truncated)?;
    if count != 0x01 {
        return Err(SolParseError::BadSignatureCount);
    }
    let signature: [u8; 64] = tx
        .get(1..65)
        .ok_or(SolParseError::Truncated)?
        .try_into()
        .map_err(|_| SolParseError::Truncated)?;
    let message = tx.get(65..).ok_or(SolParseError::Truncated)?;
    let (core, blockhash) = parse_message(message, cluster)?;
    Ok((core, blockhash, signature))
}

/// Re-encoding identity (spec/07 §9): the message parses and re-encodes to exactly the same bytes.
///
/// # Errors
///
/// The parser error, or [`SolParseError::BadData`] when the re-encoding differs.
pub fn parse_identical(
    msg: &[u8],
    cluster: SolCluster,
) -> Result<(SolTransferCore, [u8; 32]), SolParseError> {
    let (core, blockhash) = parse_message(msg, cluster)?;
    if encode_message(&core, &blockhash) != msg {
        return Err(SolParseError::BadData);
    }
    Ok((core, blockhash))
}
