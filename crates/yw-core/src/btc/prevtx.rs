//! Previous-transaction verification (spec/08 §5, CVE-2020-14199): an input's amount and script
//! are taken only from the raw transaction whose hash is the expected txid. The txid is computed
//! over the original byte ranges (`raw[0..4] ‖ raw[s..e] ‖ raw[len-4..]`), never over a
//! re-serialization, so the hash covers exactly the bytes the values were read from.
#![deny(clippy::indexing_slicing)]

use core::fmt;

use sha2::{Digest, Sha256};

use super::BTC_MAX_PREV_TX_BYTES;
use super::amount::Sats;
use super::tx::{OutPoint, TxParseError, Txid, parse_with_layout};

/// A previous output that passed every check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VerifiedPrevOut {
    /// `(expected_txid, vout)`.
    pub outpoint: OutPoint,
    /// The output value (1 ..= `MAX_MONEY`).
    pub value: Sats,
    /// One input spending `0^32:0xFFFFFFFF`: needs 100 confirmations before selection.
    pub is_coinbase: bool,
}

/// Verification failure; the UTXO is left out of balance, selection and display.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrevTxError {
    /// More than `BTC_MAX_PREV_TX_BYTES` (shown as "검증 불가 UTXO").
    TooLarge,
    /// The strict parser rejected the bytes.
    Malformed(TxParseError),
    /// The hash of the original bytes is not the expected txid.
    TxidMismatch,
    /// `vout` is not an output index of the transaction.
    VoutOutOfRange,
    /// The output script is not the expected P2WPKH script of ours.
    ScriptMismatch,
    /// The output value is 0.
    ZeroValue,
}

impl fmt::Display for PrevTxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "검증 불가 UTXO",
            Self::Malformed(_) => "이전 거래 형식이 올바르지 않습니다",
            Self::TxidMismatch => "이전 거래 해시가 일치하지 않습니다",
            Self::VoutOutOfRange => "이전 거래에 해당 출력이 없습니다",
            Self::ScriptMismatch => "이전 거래 출력이 이 지갑의 주소가 아닙니다",
            Self::ZeroValue => "이전 거래 출력 금액이 0입니다",
        })
    }
}

impl std::error::Error for PrevTxError {}

/// `SHA256d` of the non-witness serialization taken from the original bytes.
fn txid_of_original(raw: &[u8], inputs_start: usize, outputs_end: usize) -> Option<Txid> {
    let version = raw.get(..4)?;
    let body = raw.get(inputs_start..outputs_end)?;
    let lock_time = raw.get(raw.len().checked_sub(4)?..)?;
    let mut hasher = Sha256::new();
    hasher.update(version);
    hasher.update(body);
    hasher.update(lock_time);
    Some(Txid::from_bytes(Sha256::digest(hasher.finalize()).into()))
}

/// Verifies output `vout` of the raw previous transaction (spec/08 §5 steps 1–6):
/// size `<= 400,000`, strict parse, txid of the original bytes `== expected_txid`,
/// `vout < outputs.len()`, scriptPubKey `== expected_script` (`00 14 <our program>`), value ≥ 1.
///
/// # Errors
///
/// The first failing step's [`PrevTxError`].
pub fn verify_prev_output(
    raw: &[u8],
    expected_txid: &Txid,
    vout: u32,
    expected_script: &[u8; 22],
) -> Result<VerifiedPrevOut, PrevTxError> {
    if raw.len() > BTC_MAX_PREV_TX_BYTES {
        return Err(PrevTxError::TooLarge);
    }
    let (tx, layout) = parse_with_layout(raw).map_err(PrevTxError::Malformed)?;
    let txid = txid_of_original(raw, layout.inputs_start, layout.outputs_end)
        .ok_or(PrevTxError::Malformed(TxParseError::Truncated))?;
    if txid != *expected_txid {
        return Err(PrevTxError::TxidMismatch);
    }
    let output = usize::try_from(vout)
        .ok()
        .and_then(|index| tx.outputs.get(index))
        .ok_or(PrevTxError::VoutOutOfRange)?;
    if output.script_pubkey.as_slice() != expected_script.as_slice() {
        return Err(PrevTxError::ScriptMismatch);
    }
    if output.value == Sats::ZERO {
        return Err(PrevTxError::ZeroValue);
    }
    Ok(VerifiedPrevOut {
        outpoint: OutPoint {
            txid: *expected_txid,
            vout,
        },
        value: output.value,
        is_coinbase: tx.is_coinbase(),
    })
}
