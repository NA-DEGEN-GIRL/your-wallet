//! Legacy message/transaction encoding and the strict template parser with re-encoding identity
//! (spec/07 §7, §9).
//!
//! Account order follows solana-sdk `CompiledKeys` (fee payer, then writable signers, readonly
//! signers, writable non-signers, readonly non-signers, each group ascending by raw bytes). The
//! only accepted messages are `T_SOL` (`header [1, 0, 2]`, keys `[from, to, System,
//! ComputeBudget]`, instructions limit → price → transfer) and `T_SPL` (v1.1, `header [1, 0, 6]`,
//! keys `[from] ++ sort{from_ata, to_ata} ++ sort{to, mint, System, Token, ATA, ComputeBudget}`,
//! instructions limit → price → ATA `CreateIdempotent` → Token `TransferChecked`).
#![deny(clippy::indexing_slicing)]

use core::fmt;

use super::address::{
    ATA_PROGRAM, COMPUTE_BUDGET_PROGRAM, CurveClass, SYSTEM_PROGRAM, SolAddress, SolCluster,
    TOKEN_PROGRAM, curve_class,
};
use super::shortvec::{self, ShortVecError};
use super::template::{
    ATA_CREATE_IDEMPOTENT, SOL_MAX_COMPUTE_UNITS, SOL_MAX_TX_BYTES, SolAsset, SolTransferCore,
    SplAccounts, T_SOL_HEADER, T_SPL_HEADER, TOKEN_TRANSFER_CHECKED_TAG,
    set_compute_unit_limit_data, set_compute_unit_price_data, spl_entry, system_transfer_data,
    transfer_checked_data,
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
    /// `T_SPL`: a mint outside the cluster's allowlist, or decimals other than its pinned value.
    NotAllowlisted,
    /// `T_SPL`: an associated token account differs from its local derivation.
    AtaMismatch,
    /// `T_SPL`: the recipient wallet is not a canonical large-order curve point (a PDA, token
    /// account or unspendable key); tokens sent to its ATA could never be moved.
    RecipientOffCurve,
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

/// The `T_SPL` keys and instructions of a core (spec/07 §8.3), `None` for SOL or when the ATAs
/// cannot be derived.
fn spl_layout(core: &SolTransferCore) -> Option<(Vec<[u8; 32]>, Vec<CompiledIx>)> {
    let accounts = SplAccounts::of(core)?;
    let entry = accounts.entry;
    let mut writable = [accounts.from_ata.to_bytes(), accounts.to_ata.to_bytes()];
    writable.sort_unstable();
    let mut readonly = [
        core.to.to_bytes(),
        entry.mint.to_bytes(),
        SYSTEM_PROGRAM.to_bytes(),
        entry.token_program.to_bytes(),
        ATA_PROGRAM.to_bytes(),
        COMPUTE_BUDGET_PROGRAM.to_bytes(),
    ];
    readonly.sort_unstable();
    let mut keys = Vec::with_capacity(9);
    keys.push(core.from.to_bytes());
    keys.extend_from_slice(&writable);
    keys.extend_from_slice(&readonly);
    let index = |key: &SolAddress| -> Option<u8> {
        keys.iter()
            .position(|known| known == key.as_bytes())
            .and_then(|position| u8::try_from(position).ok())
    };
    let budget = index(&COMPUTE_BUDGET_PROGRAM)?;
    let instructions = vec![
        CompiledIx {
            program: budget,
            accounts: Vec::new(),
            data: set_compute_unit_limit_data(core.cu_limit),
        },
        CompiledIx {
            program: budget,
            accounts: Vec::new(),
            data: set_compute_unit_price_data(core.cu_price_micro),
        },
        CompiledIx {
            program: index(&ATA_PROGRAM)?,
            accounts: vec![
                0,
                index(&accounts.to_ata)?,
                index(&core.to)?,
                index(&entry.mint)?,
                index(&SYSTEM_PROGRAM)?,
                index(&entry.token_program)?,
            ],
            data: ATA_CREATE_IDEMPOTENT.to_vec(),
        },
        CompiledIx {
            program: index(&entry.token_program)?,
            accounts: vec![
                index(&accounts.from_ata)?,
                index(&entry.mint)?,
                index(&accounts.to_ata)?,
                0,
            ],
            data: transfer_checked_data(core.amount, entry.decimals),
        },
    ];
    Some((keys, instructions))
}

/// The message bytes of a transfer (`T_SOL` spec/07 §8.2, `T_SPL` §8.3). For SPL both ATAs are
/// derived locally; if that were ever impossible the result is empty, which every parser and the
/// re-encoding identity reject (nothing is signed).
#[must_use]
pub fn encode_message(core: &SolTransferCore, blockhash: &[u8; 32]) -> Vec<u8> {
    match core.asset {
        SolAsset::Spl(_) => spl_layout(core).map_or_else(Vec::new, |(keys, instructions)| {
            encode_legacy_message(T_SPL_HEADER, &keys, blockhash, &instructions)
        }),
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
    let (expected_keys, expected_ix) = match header {
        T_SOL_HEADER => (4, 3),
        T_SPL_HEADER => (9, 4),
        _ => return Err(SolParseError::UnknownTemplate),
    };
    let n_keys = reader.short_len()?;
    if n_keys != expected_keys {
        return Err(SolParseError::UnknownTemplate);
    }
    let mut keys: Vec<[u8; 32]> = Vec::with_capacity(n_keys);
    for _ in 0..n_keys {
        let key = reader.array32()?;
        if keys.contains(&key) {
            return Err(SolParseError::DuplicateKey);
        }
        keys.push(key);
    }
    let blockhash = reader.array32()?;
    let n_ix = reader.short_len()?;
    if n_ix != expected_ix {
        return Err(SolParseError::UnknownTemplate);
    }
    let core = if header == T_SPL_HEADER {
        parse_spl(&mut reader, &keys, cluster)?
    } else {
        parse_sol(&mut reader, &keys)?
    };
    if core.amount == 0 {
        return Err(SolParseError::ZeroAmount);
    }
    if !(1..=SOL_MAX_COMPUTE_UNITS).contains(&core.cu_limit) {
        return Err(SolParseError::BadComputeLimit);
    }
    if reader.at != msg.len() {
        return Err(SolParseError::TrailingBytes);
    }
    Ok((core, blockhash))
}

/// The two `ComputeBudget` instructions (limit, then price) at the head of every template.
fn parse_budget(reader: &mut Reader<'_>, keys: &[[u8; 32]]) -> Result<(u32, u64), SolParseError> {
    let limit_ix = reader.instruction(keys.len())?;
    let price_ix = reader.instruction(keys.len())?;
    let limit = expect_ix(&limit_ix, keys, &COMPUTE_BUDGET_PROGRAM, &[], &[0x02], 5)?;
    let price = expect_ix(&price_ix, keys, &COMPUTE_BUDGET_PROGRAM, &[], &[0x03], 9)?;
    Ok((
        le_u32(limit).ok_or(SolParseError::BadData)?,
        le_u64(price).ok_or(SolParseError::BadData)?,
    ))
}

/// `T_SOL` instructions and roles (header `[1, 0, 2]`, 4 keys, 3 instructions).
fn parse_sol(reader: &mut Reader<'_>, keys: &[[u8; 32]]) -> Result<SolTransferCore, SolParseError> {
    let (cu_limit, cu_price_micro) = parse_budget(reader, keys)?;
    let transfer_ix = reader.instruction(keys.len())?;
    let lamports = expect_ix(
        &transfer_ix,
        keys,
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
    Ok(SolTransferCore {
        from: SolAddress::from_bytes(*from),
        to: SolAddress::from_bytes(*to),
        asset: SolAsset::Sol,
        amount: le_u64(lamports).ok_or(SolParseError::BadData)?,
        cu_limit,
        cu_price_micro,
    })
}

fn key_at(keys: &[[u8; 32]], index: u8) -> Result<SolAddress, SolParseError> {
    keys.get(usize::from(index))
        .copied()
        .map(SolAddress::from_bytes)
        .ok_or(SolParseError::BadIndex)
}

/// Whether `keys[range]` holds exactly the keys at `indices` in strictly ascending order.
fn group_is(keys: &[[u8; 32]], range: core::ops::Range<usize>, indices: &[u8]) -> bool {
    let Some(group) = keys.get(range.clone()) else {
        return false;
    };
    let mut wanted: Vec<usize> = indices.iter().map(|index| usize::from(*index)).collect();
    wanted.sort_unstable();
    wanted.dedup();
    wanted.len() == group.len()
        && wanted.iter().copied().eq(range)
        && group.windows(2).all(|pair| match pair {
            [a, b] => a < b,
            _ => false,
        })
}

/// `T_SPL` instructions, roles, allowlist and ATA derivation (spec/07 §8.3, §9 steps 5–7).
fn parse_spl(
    reader: &mut Reader<'_>,
    keys: &[[u8; 32]],
    cluster: SolCluster,
) -> Result<SolTransferCore, SolParseError> {
    let (cu_limit, cu_price_micro) = parse_budget(reader, keys)?;
    let create_ix = reader.instruction(keys.len())?;
    let transfer_ix = reader.instruction(keys.len())?;
    // ③ ATA CreateIdempotent(payer = key 0, ata, wallet, mint, System, Token), data `01`.
    if key_at(keys, create_ix.program)? != ATA_PROGRAM {
        return Err(SolParseError::UnexpectedProgram);
    }
    // ④ Token TransferChecked(source, mint, destination, owner = key 0), data `0c ‖ u64 ‖ u8`.
    if key_at(keys, transfer_ix.program)? != TOKEN_PROGRAM {
        return Err(SolParseError::UnexpectedProgram);
    }
    let [
        payer,
        to_ata_index,
        to_index,
        mint_index,
        system_index,
        token_index,
    ] = <[u8; 6]>::try_from(create_ix.accounts.as_slice())
        .map_err(|_| SolParseError::BadAccounts)?;
    let [from_ata_index, transfer_mint, destination, owner] =
        <[u8; 4]>::try_from(transfer_ix.accounts.as_slice())
            .map_err(|_| SolParseError::BadAccounts)?;
    if payer != 0
        || owner != 0
        || key_at(keys, system_index)? != SYSTEM_PROGRAM
        || token_index != transfer_ix.program
        || transfer_mint != mint_index
        || destination != to_ata_index
    {
        return Err(SolParseError::BadAccounts);
    }
    if create_ix.data != ATA_CREATE_IDEMPOTENT {
        return Err(SolParseError::BadData);
    }
    let [tag, a0, a1, a2, a3, a4, a5, a6, a7, decimals] =
        <[u8; 10]>::try_from(transfer_ix.data.as_slice()).map_err(|_| SolParseError::BadData)?;
    if tag != TOKEN_TRANSFER_CHECKED_TAG {
        return Err(SolParseError::BadData);
    }
    let amount = u64::from_le_bytes([a0, a1, a2, a3, a4, a5, a6, a7]);
    // Roles (spec/07 §7): key 0 the payer only; keys 1–2 exactly the two token accounts; keys
    // 3–8 exactly {to, mint, System, Token, ATA, ComputeBudget}; each group strictly ascending.
    let readonly = [
        to_index,
        mint_index,
        system_index,
        token_index,
        create_ix.program,
        budget_index(keys)?,
    ];
    if from_ata_index == 0
        || readonly.contains(&0)
        || !group_is(keys, 1..3, &[from_ata_index, to_ata_index])
        || !group_is(keys, 3..9, &readonly)
    {
        return Err(SolParseError::BadGroupOrder);
    }
    let from = key_at(keys, 0)?;
    let to = key_at(keys, to_index)?;
    let mint = key_at(keys, mint_index)?;
    let entry = spl_entry(cluster, &mint).ok_or(SolParseError::NotAllowlisted)?;
    if decimals != entry.decimals || entry.token_program != TOKEN_PROGRAM {
        return Err(SolParseError::NotAllowlisted);
    }
    if curve_class(to.as_bytes()) != CurveClass::OnCurve {
        return Err(SolParseError::RecipientOffCurve);
    }
    let core = SolTransferCore {
        from,
        to,
        asset: SolAsset::Spl(entry),
        amount,
        cu_limit,
        cu_price_micro,
    };
    let accounts = SplAccounts::of(&core).ok_or(SolParseError::AtaMismatch)?;
    if key_at(keys, from_ata_index)? != accounts.from_ata
        || key_at(keys, to_ata_index)? != accounts.to_ata
    {
        return Err(SolParseError::AtaMismatch);
    }
    Ok(core)
}

/// The index of `ComputeBudget` (its presence is checked by [`parse_budget`]).
fn budget_index(keys: &[[u8; 32]]) -> Result<u8, SolParseError> {
    keys.iter()
        .position(|key| key == COMPUTE_BUDGET_PROGRAM.as_bytes())
        .and_then(|position| u8::try_from(position).ok())
        .ok_or(SolParseError::UnexpectedProgram)
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
