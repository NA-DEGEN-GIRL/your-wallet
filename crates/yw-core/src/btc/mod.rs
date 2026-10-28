//! Bitcoin send-only core (spec/08, M8): networks and genesis pins, amounts in sats, bech32 /
//! bech32m (own implementation, D6), the address parsing policy (base58check through
//! `codec::base58`), script templates and dust, the strict transaction parser and serializer,
//! the four account types ([`account`]: P2PKH / P2SH-P2WPKH / P2WPKH / P2TR, BIP44/49/84/86,
//! HD accounts and imported single keys), the legacy and BIP143 sighashes, BIP341 key-path
//! Taproot ([`taproot`]), previous-transaction verification (CVE-2020-14199) and the ECDSA /
//! Schnorr helpers used by signing. Nothing here touches the network, clocks or files:
//! RPC/indexer observations are arguments (spec/01 §2.2). Journal records are `journal::btc`.
//!
//! Encoding layer: [`network`], [`amount`], [`bech32`], [`address`], [`account`], [`script`],
//! [`tx`], [`sighash`], [`taproot`], [`prevtx`]. Sending: [`fee`] (rates, floor, caps), [`select`] (coin selection,
//! layout, send-max, RBF plans), [`policy`] (`B01`–`B08`, fixed texts, node answers),
//! [`display`] (approval payload, fields, warnings), [`sign`] (`sign_plan` and the strict
//! witness checker), [`verify`] (post-sign checks) and [`meta`] (`BtcMeta`, discovery, verified
//! set).
//!
//! App order (spec/08 §11.1): `BtcMeta::spendable` → `fee::choose_fee_rate` →
//! `select::plan_send` / `plan_fee_bump` → `display::build_btc_request` →
//! `ApprovalStore::issue`/`consume` → `journal::btc::check_plan_allowed` +
//! `sign::check_recorded_amounts` → `sign::sign_plan` → `verify::verify_signed` →
//! `journal::btc::BtcRecord::new_signed` + `push_record` → `policy::check_mempool_accept` →
//! `journal::btc::set_state(Broadcasting)` + `BtcMeta::on_broadcasting` →
//! `policy::broadcast_outcome` → `set_state(..)`.
#![deny(clippy::indexing_slicing)]

pub mod account;
pub mod address;
pub mod amount;
pub mod bech32;
pub mod display;
pub mod fee;
pub mod meta;
pub mod network;
pub mod policy;
pub mod prevtx;
pub mod script;
pub mod select;
pub mod sighash;
pub mod sign;
pub mod taproot;
pub mod tx;
pub mod verify;

pub use account::{BtcAccountId, BtcAccountKey, BtcKeySource, BtcPubKey, ScriptType};
pub use address::{AddressError, BtcAddress, ScriptKind, encode_address, parse_address};
pub use amount::{AmountError, Sats};
pub use display::{BtcSendFacts, btc_payload, build_btc_request};
pub use fee::{FeeChoice, FeeRate, FeeSelection, FeeSource};
pub use meta::{BtcAccounts, BtcMeta, Discovery};
pub use network::BtcNetwork;
pub use select::{
    BumpRequest, BumpSource, PlanError, SendAmount, SendPlan, SendRequest, Utxo, plan_fee_bump,
    plan_send,
};
pub use sign::{
    BtcImportedKeys, BtcKeys, ImportedBtcSecret, SignError, SignedTx, check_recorded_amounts,
    sign_plan,
};
pub use tx::{OutPoint, Transaction, TxIn, TxOut, Txid};
pub use verify::{PostSignError, VerifiedSignedTx, verify_signed};

/// Largest amount in sats (21,000,000 BTC).
pub const MAX_MONEY: u64 = 2_100_000_000_000_000;
/// Discovery gap: unused addresses scanned past the last used one (spec/08 §3.2, §3.4).
pub const BTC_GAP_LIMIT: u32 = 20;
/// "New address" is refused once this many unused receive addresses are outstanding.
pub const BTC_GAP_HARD_LIMIT: u32 = 100;
/// Transaction version of every transaction we build.
pub const BTC_TX_VERSION: u32 = 2;
/// Input sequence: replaceable (BIP125) and `nLockTime` enforced.
pub const BTC_SEQUENCE: u32 = 0xFFFF_FFFD;
/// The only signature hash type (`SIGHASH_ALL`): the witness signature suffix byte and, as a
/// little-endian `u32`, the last field of the BIP143 preimage.
pub const SIGHASH_ALL: u8 = 0x01;
/// Most inputs in one transaction.
pub const BTC_MAX_INPUTS: usize = 100;
/// Confirmations before an output of someone else may be spent.
pub const BTC_MIN_CONF: u32 = 1;
/// Confirmations before a coinbase output may be spent.
pub const BTC_COINBASE_MATURITY: u32 = 100;
/// Smallest change output (P2WPKH dust, sats); less is added to the fee.
pub const BTC_CHANGE_DUST: u64 = 294;
/// Incoming outputs of others below this many sats are frozen automatically (dust attacks).
pub const BTC_AUTO_FREEZE_BELOW: u64 = 1_000;
/// Fee-rate floor in sat/kvB (1 sat/vB).
pub const BTC_FEE_FLOOR_DEFAULT: u64 = 1_000;
/// Fee-rate cap in sat/kvB (500 sat/vB); above it the send form's typed override is required.
pub const BTC_FEE_RATE_CAP: u64 = 500_000;
/// Fee-rate limit in sat/kvB (10,000 sat/vB) that no override lifts.
pub const BTC_FEE_RATE_UNOVERRIDABLE: u64 = 10_000_000;
/// Absolute fee cap in sats (0.005 BTC).
pub const BTC_FEE_ABS_CAP: u64 = 500_000;
/// Fee ratio confirmation: high risk when `fee × 50 > amount` (2 %).
pub const BTC_FEE_RATIO_CONFIRM: u64 = 50;
/// `estimatesmartfee` targets: fast / normal / slow.
pub const BTC_CONF_TARGETS: [u32; 3] = [2, 6, 24];
/// Largest previous transaction accepted for verification (spec/08 §5).
pub const BTC_MAX_PREV_TX_BYTES: usize = 400_000;
/// Largest signed transaction stored in a journal record (spec/08 §12.4).
pub const BTC_MAX_JOURNAL_RAW: usize = 32_768;
/// Terminal BTC journal records kept (spec/02 §5.4).
pub const BTC_JOURNAL_FINAL_KEEP: usize = 64;
/// Minimum spacing between BTC request starts (Core and indexer).
pub const BTC_REQ_MIN_INTERVAL_MS: u64 = 200;
/// Refresh period while a transaction is in flight.
pub const BTC_POLL_SECS: u64 = 60;
/// Chain check (`check_chain`) cache lifetime.
pub const BTC_CHAIN_RECHECK_SECS: u64 = 600;
/// Waits before the three retries after HTTP 429.
pub const BTC_429_BACKOFF_MS: [u64; 3] = [2_000, 4_000, 8_000];
/// Automatic refreshes are skipped this long after a 429 abort.
pub const BTC_429_COOLDOWN_SECS: u64 = 300;
/// Default Esplora base URL for mainnet (not a secret; no trailing `/`).
pub const BTC_ESPLORA_DEFAULT_MAINNET: &str = "https://mempool.space/api";
/// Default Esplora base URL for testnet4.
pub const BTC_ESPLORA_DEFAULT_TESTNET4: &str = "https://mempool.space/testnet4/api";
/// Most UTXO candidates accepted in one indexer response.
pub const BTC_INDEXER_MAX_UTXOS: usize = 1_000;
/// Indexer/Core tip difference above which W-BTC-IDX-LAG is shown.
pub const BTC_INDEXER_TIP_LAG_WARN: u32 = 3;
/// Consecutive "not found" observations before `BroadcastUnknown`.
pub const BTC_NOT_FOUND_LIMIT: u32 = 10;
/// Discovery (spec/08 §3.4) scans a chain at most this many addresses past its start index: an
/// indexer reporting history for every address cannot grow the watch set without bound.
pub const BTC_DISCOVERY_MAX_SCAN: u32 = 1_000;
/// Issue indices of each chain stay below this (receive and change, spec/08 §3.2): issuance
/// stops there and the watch set (§3.3) never has more addresses per chain.
pub const BTC_MAX_ADDRESS_INDEX: u32 = 10_000;
/// `nLockTime` values from here on are Unix times, not heights (Core `LOCKTIME_THRESHOLD`): a
/// Core tip this high is implausible, refused by `check_chain` and never used as a lock time.
pub const BTC_LOCKTIME_THRESHOLD: u32 = 500_000_000;
/// Planning is refused while the Core tip is more than this many blocks above the indexer tip
/// (`esplora` `TipHeight`, spec/08 §2 step 4): `lock_time = tip` would not be final elsewhere.
pub const BTC_PLAN_TIP_AHEAD_MAX: u32 = 6;

/// Confirmations of a transaction at `height` with the Core tip `tip_height` (spec/08 §4.3):
/// `tip_height - height + 1`, or 0 when the indexer height is above the tip.
#[must_use]
pub const fn conf(height: u32, tip_height: u32) -> u32 {
    match tip_height.checked_sub(height) {
        Some(depth) => depth.saturating_add(1),
        None => 0,
    }
}

#[cfg(test)]
mod send_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod types_tests;
