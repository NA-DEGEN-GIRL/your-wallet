//! Zcash transparent send-only core (spec/12, D36): networks and genesis pins, recipient
//! parsing (t-addresses, ZIP 320 TEX, the transparent receiver of a ZIP 316 unified address via
//! F4Jumble), the transparent-only v5 transaction (ZIP 225), the ZIP 244 txid and `SIGHASH_ALL`
//! digest over personalised BLAKE2b, the ZIP 317 fee, the network-upgrade table with the
//! node cross-check and expiry rule, planning, signing (vault key or `YubiKey`), post-sign
//! verification and the approval request. Shielded transactions are out of scope.
//!
//! Like `btc`, nothing here touches the network, clocks or files: node observations are
//! arguments (spec/01 §2.2). Journal records are `journal::zec`.
//!
//! App order (spec/12 §10): `upgrade::tx_consensus` → `plan::plan_send` →
//! `display::build_zec_request` → `ApprovalStore::issue`/`consume` →
//! `journal::zec::check_plan_allowed` → `sign::sign_plan` / `sign::sign_plan_card` (each ends
//! with `sign::verify_signed`) → `journal::zec::ZecRecord::new_signed` → `sendrawtransaction` →
//! `journal::zec::set_state`.
#![deny(clippy::indexing_slicing)]
#![allow(
    clippy::doc_markdown,
    reason = "protocol names (BLAKE2b, F4Jumble, Base58Check, OpenPGP, ZIP numbers) are prose"
)]

pub mod account;
pub mod address;
pub mod blake2b;
pub mod display;
pub mod f4jumble;
pub mod fee;
pub mod network;
pub mod plan;
pub mod sighash;
pub mod sign;
pub mod tx;
pub mod upgrade;

pub use account::{ZecAccount, ZecKeySource};
pub use address::{RecipientForm, ZecAddressError, ZecDest, ZecRecipient, parse_recipient};
pub use network::ZecNetwork;
pub use plan::{ZecAmount, ZecPlan, ZecPlanError, ZecSendRequest, ZecUtxo, plan_send};
pub use sign::{ZecSignError, ZecSignedTx, sign_plan, sign_plan_card, verify_signed};
pub use tx::{TransparentParts, ZecOutPoint, ZecTx, transparent_parts};
pub use upgrade::{ConsensusObservation, TxConsensus, UpgradeError, tx_consensus};

/// Zatoshis per ZEC.
pub const ZATS_PER_ZEC: u64 = 100_000_000;
/// Smallest recipient output and smallest change output (zatoshis). zcashd/Zebra's dust
/// threshold for a P2PKH output is 54 zats; 1,000 is the conservative floor (spec/12 §7.3).
pub const ZEC_DUST: u64 = 1_000;
/// Most inputs in one transaction.
pub const ZEC_MAX_INPUTS: usize = 50;
/// Absolute fee cap (zatoshis): 0.01 ZEC (ZIP 317 fee of 50 inputs is 0.0025 ZEC).
pub const ZEC_FEE_ABS_CAP: u64 = 1_000_000;
/// `nSequence` of every input (`0xFFFFFFFF`: no lock time, no replacement in Zcash).
pub const ZEC_SEQUENCE: u32 = 0xFFFF_FFFF;
/// Confirmations before an incoming output is spendable.
pub const ZEC_MIN_CONF: u32 = 1;
/// Refresh period while a transaction is in flight (seconds).
pub const ZEC_POLL_SECS: u64 = 30;
/// Most UTXOs kept from one node / indexer answer: the largest ones (dust dropped first, never a
/// failure — spec/12 §4.3).
pub const ZEC_MAX_UTXOS: usize = 1_000;
/// Outputs worth at most this many zatoshis are ignored (never listed, never spent): below the
/// dust floor or not worth one input's ZIP 317 marginal fee (dust griefing, spec/12 §4.3).
pub const ZEC_MIN_UTXO: u64 = if fee::MARGINAL_FEE > ZEC_DUST {
    fee::MARGINAL_FEE
} else {
    ZEC_DUST
};
/// Blocks past `nExpiryHeight` before an unmined record counts as expired (reorg margin: a
/// replaced block at the expiry height could still include it).
pub const ZEC_EXPIRED_AFTER: u32 = 10;
/// Consecutive "not found" answers (after the first seen) before `BroadcastUnknown`.
pub const ZEC_NOT_FOUND_LIMIT: u32 = 10;
/// Terminal ZEC journal records kept.
pub const ZEC_JOURNAL_FINAL_KEEP: usize = 64;
/// Largest signed transaction stored in a journal record.
pub const ZEC_MAX_JOURNAL_RAW: usize = 32_768;

/// `12.34567890` (8 decimals, trailing zeros kept to 8 places like the BTC display).
#[must_use]
pub fn format_zec(zats: u64) -> String {
    format!("{}.{:08}", zats / ZATS_PER_ZEC, zats % ZATS_PER_ZEC)
}

/// `0.00100000 ZEC (100,000 zats)`.
#[must_use]
pub fn format_zec_and_zats(zats: u64) -> String {
    format!(
        "{} ZEC ({} zats)",
        format_zec(zats),
        crate::btc::amount::format_sats_grouped(zats)
    )
}

/// Parses a user ZEC amount (`0.001`, up to 8 decimals; same rules as the BTC amount field).
///
/// # Errors
///
/// [`crate::btc::AmountError`].
pub fn parse_user_zec(text: &str) -> Result<u64, crate::btc::AmountError> {
    crate::btc::amount::parse_user_btc(text).map(crate::btc::Sats::get)
}

/// Confirmations of a transaction mined at `height` with tip `tip` (0 above the tip).
#[must_use]
pub const fn conf(height: u32, tip: u32) -> u32 {
    crate::btc::conf(height, tip)
}

#[cfg(test)]
mod tests;
