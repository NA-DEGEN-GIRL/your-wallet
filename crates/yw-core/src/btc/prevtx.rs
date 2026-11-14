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
    /// The output script is not the expected script of ours.
    ScriptMismatch,
    /// The output value is 0.
    ZeroValue,
}

impl PrevTxError {
    /// The fixed text in `lang` (`Display` is the Korean one).
    #[must_use]
    pub const fn text_in(self, lang: crate::lang::Lang) -> &'static str {
        use super::text as t;
        match self {
            Self::TooLarge => t::PREV_TOO_LARGE,
            Self::Malformed(_) => t::PREV_MALFORMED,
            Self::TxidMismatch => t::PREV_TXID_MISMATCH,
            Self::VoutOutOfRange => t::PREV_VOUT,
            Self::ScriptMismatch => t::PREV_SCRIPT,
            Self::ZeroValue => t::PREV_ZERO,
        }
        .get(lang)
    }
}

impl fmt::Display for PrevTxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.text_in(crate::lang::Lang::Ko))
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
/// `vout < outputs.len()`, scriptPubKey `== expected_script` (our output script of the account
/// type: P2PKH, P2SH-P2WPKH, P2WPKH or P2TR), value ≥ 1.
///
/// # Errors
///
/// The first failing step's [`PrevTxError`].
pub fn verify_prev_output(
    raw: &[u8],
    expected_txid: &Txid,
    vout: u32,
    expected_script: &[u8],
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
    if output.script_pubkey.as_slice() != expected_script {
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
