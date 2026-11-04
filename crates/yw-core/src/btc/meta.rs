//! `BtcMeta` (one BTC account: meta `btc` for BIP84 account 0, `btc_accounts` for the others,
//! spec/08 §12.3, §12.3a, spec/02 §5.3): the account key (HD node of any type or an imported key),
//! issue indices (§3.2), discovery (§3.4) as a pure state machine driven by indexer `tx_count`
//! observations, history marking, the verified UTXO set with its update rules (§4.7-4/5/6,
//! auto-freeze, user freeze), spendable candidates and balance (§7.4), sent-script hashes,
//! the tip regression rule (§2 step 2), `change_next` reconciliation with the journal (§3.2) and
//! own change insertion on confirmation (§12.2-5), and the strict JSON codec.
//!
//! The JSON writer emits the §12.3 key order; the reader rejects unknown or missing keys, wrong
//! types and formats (lowercase hex, sats as decimal strings, outpoints `"<txid>:<vout>"`) and
//! bound violations, which the app handles as a meta validation failure (spec/02 §5.3). Version 1
//! objects are BIP84 account 0 (unchanged bytes); version 2 objects carry `script_type` and `key`.
//! [`BtcAccounts`] is the `btc_accounts` container (other accounts of both networks, selection).
#![deny(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use core::fmt;

use secp256k1::PublicKey;
use sha2::{Digest, Sha256};
use yw_json::{Number, Object, Value};

use super::account::{
    BTC_MAX_HD_ACCOUNT, BtcAccountId, BtcAccountKey, BtcPubKey, HwBtcKey, ScriptType,
};
use super::address::{BtcAddress, ScriptKind, kind_from_script};
use super::amount::Sats;
use super::display::BtcSendFacts;
use super::network::BtcNetwork;
use super::prevtx::VerifiedPrevOut;
use super::select::{SendPlan, Utxo};
use super::tx::{OutPoint, Txid};
use super::{
    BTC_AUTO_FREEZE_BELOW, BTC_COINBASE_MATURITY, BTC_DISCOVERY_MAX_SCAN, BTC_GAP_HARD_LIMIT,
    BTC_GAP_LIMIT, BTC_LOCKTIME_THRESHOLD, BTC_MAX_ADDRESS_INDEX, BTC_MIN_CONF, MAX_MONEY, conf,
};
use crate::bip32::path::BtcChain;
use crate::bip32::{AccountXpub, HARDENED};
use crate::error::KeyError;

/// `BtcMeta.version`.
pub const BTC_META_VERSION: u64 = 1;
/// Most `verified` entries.
pub const MAX_VERIFIED: usize = 4_096;
/// Most `frozen` entries.
pub const MAX_FROZEN: usize = 1_024;
/// Most `unfrozen` entries (oldest dropped first).
pub const MAX_UNFROZEN: usize = 1_024;
/// Most `sent_scripts` entries (oldest dropped first).
pub const MAX_SENT_SCRIPTS: usize = 4_096;
/// A Core tip this far below `max_tip_seen` is refused (spec/08 §2 step 2).
pub const TIP_REGRESSION_ALLOWANCE: u32 = 6;

const KEYS: [&str; 14] = [
    "version",
    "network",
    "account_pubkey",
    "account_chain_code",
    "receive_next",
    "change_next",
    "last_used_receive",
    "last_used_change",
    "discovery_done",
    "max_tip_seen",
    "verified",
    "frozen",
    "unfrozen",
    "sent_scripts",
];
const VERIFIED_KEYS: [&str; 7] = [
    "outpoint",
    "value",
    "chain",
    "index",
    "height",
    "is_coinbase",
    "own",
];
const FROZEN_KEYS: [&str; 2] = ["outpoint", "reason"];
/// Largest storable `receive_next`/`change_next` (`< 2^31`).
const MAX_NEXT: u32 = HARDENED - 1;

/// Why an outpoint is frozen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FreezeReason {
    /// Frozen by the user.
    User = 1,
    /// A small foreign deposit frozen automatically (dust attack defence).
    Auto = 2,
}

impl FreezeReason {
    /// JSON code.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Inverse of [`FreezeReason::code`].
    #[must_use]
    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::User),
            2 => Some(Self::Auto),
            _ => None,
        }
    }
}

/// One verified output of ours (spec/08 §5, §12.3 `verified`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VerifiedUtxo {
    /// Outpoint.
    pub outpoint: OutPoint,
    /// Value taken from the hash-verified previous transaction.
    pub value: Sats,
    /// Our chain.
    pub chain: BtcChain,
    /// Our index.
    pub index: u32,
    /// Block height (server based).
    pub height: u32,
    /// Coinbase output.
    pub is_coinbase: bool,
    /// Our own change, inserted from the journal (never auto-frozen).
    pub own: bool,
}

impl VerifiedUtxo {
    /// A verified previous output of a listed UTXO.
    #[must_use]
    pub const fn from_prev(prev: &VerifiedPrevOut, listed: &ListedUtxo) -> Self {
        Self {
            outpoint: prev.outpoint,
            value: prev.value,
            chain: listed.chain,
            index: listed.index,
            height: listed.height,
            is_coinbase: prev.is_coinbase,
            own: false,
        }
    }

    /// As a selection candidate.
    #[must_use]
    pub const fn utxo(&self) -> Utxo {
        Utxo {
            outpoint: self.outpoint,
            value: self.value,
            chain: self.chain,
            index: self.index,
            height: self.height,
            is_coinbase: self.is_coinbase,
        }
    }

    /// Confirmed (coinbase: mature) at `tip_height`.
    #[must_use]
    pub const fn is_mature(&self, tip_height: u32) -> bool {
        let confirmations = conf(self.height, tip_height);
        confirmations >= BTC_MIN_CONF
            && (!self.is_coinbase || confirmations >= BTC_COINBASE_MATURITY)
    }
}

/// A confirmed UTXO candidate the indexer listed for one of our addresses in this refresh
/// (`UtxoCandidate` with `conf(height, tip) >= 1`, mapped to our path).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ListedUtxo {
    /// Outpoint.
    pub outpoint: OutPoint,
    /// Chain of the address queried.
    pub chain: BtcChain,
    /// Index of the address queried.
    pub index: u32,
    /// Block height.
    pub height: u32,
}

/// What a refresh changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RefreshReport {
    /// Newly verified outputs added.
    pub inserted: u32,
    /// Outputs no longer listed (spent or hidden) removed.
    pub removed: u32,
    /// Small foreign outputs frozen automatically ("작은 입금 자동 동결(먼지 공격 방지)").
    pub auto_frozen: u32,
    /// Outputs not added because a bound (4,096 verified / 1,024 frozen) is full.
    pub skipped: u32,
}

/// Balance summary (spec/08 §4.7-6); in-flight outpoints are excluded everywhere.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct BtcBalance {
    /// Confirmed (coinbase mature), not frozen: what selection may use.
    pub available: Sats,
    /// Confirmed, frozen (shown separately).
    pub frozen: Sats,
    /// Verified but not yet confirmed enough (unconfirmed own change, immature coinbase).
    pub pending: Sats,
}

/// The receive address to show (spec/08 §3.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReceiveAddress {
    /// An issued, unused index.
    Existing(u32),
    /// A newly issued index: `receive_next` was incremented, persist meta **before** showing it.
    Issued(u32),
}

impl ReceiveAddress {
    /// The receive index.
    #[must_use]
    pub const fn index(self) -> u32 {
        match self {
            Self::Existing(index) | Self::Issued(index) => index,
        }
    }
}

/// A `BtcMeta` operation refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetaError {
    /// settings `bitcoin.network` differs from `BtcMeta.network` (all BTC calls blocked).
    NetworkMismatch,
    /// "새 주소": 20 or more unused receive addresses; confirm with the warning first.
    GapWarning {
        /// `unused_tail`.
        unused: u32,
    },
    /// "새 주소": 100 or more unused receive addresses.
    GapHardLimit,
    /// No non-hardened index left.
    IndexExhausted,
    /// An index outside the issued range.
    OutOfRange,
    /// A Core tip at or above 500,000,000 (`BTC_LOCKTIME_THRESHOLD`): never stored.
    TipImplausible,
    /// Core tip more than 6 blocks below `max_tip_seen`.
    TipRegression {
        /// `getblockchaininfo.blocks`.
        blocks: u32,
        /// `max_tip_seen`.
        max_tip_seen: u32,
    },
    /// The outpoint is not in `verified`.
    NotVerified,
    /// A bound (`verified`, `frozen`) is full.
    Full,
    /// Discovery is not finished.
    DiscoveryIncomplete,
    /// The account uses one fixed address ("새 주소" refused; a one-key account also has no
    /// address mode to switch).
    SingleAddress,
    /// Public derivation failed.
    Key(KeyError),
}

impl fmt::Display for MetaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NetworkMismatch => formatter.write_str(super::policy::texts::NETWORK_MISMATCH),
            Self::GapWarning { .. } => formatter.write_str(
                "미사용 주소가 20개를 넘으면 다른 지갑으로 복구할 때 이후 입금이 보이지 않을 수 있습니다",
            ),
            Self::GapHardLimit => {
                formatter.write_str("미사용 주소가 100개 이상이라 새 주소를 발급할 수 없습니다")
            }
            Self::IndexExhausted => formatter.write_str("더 발급할 주소 인덱스가 없습니다"),
            Self::OutOfRange => formatter.write_str("발급하지 않은 주소입니다"),
            Self::TipRegression { .. } => {
                formatter.write_str("노드 블록 높이가 이전에 본 값보다 낮습니다")
            }
            Self::TipImplausible => formatter.write_str(super::policy::texts::TIP_IMPLAUSIBLE),
            Self::NotVerified => formatter.write_str("검증된 UTXO가 아닙니다"),
            Self::Full => formatter.write_str("BTC 데이터 공간이 부족합니다"),
            Self::DiscoveryIncomplete => formatter.write_str("주소 검색 미완료"),
            Self::SingleAddress => {
                formatter.write_str("이 계정은 주소 하나만 써서 새 주소를 만들 수 없습니다")
            }
            Self::Key(_) => formatter.write_str(super::policy::texts::DERIVATION_FAILED),
        }
    }
}

impl std::error::Error for MetaError {}

impl From<KeyError> for MetaError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

/// The meta `btc` JSON is invalid (spec/02 §5.3 meta validation failure); names the field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BtcMetaError(pub &'static str);

impl fmt::Display for BtcMetaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid btc meta field: {}", self.0)
    }
}

impl std::error::Error for BtcMetaError {}

/// One BTC account's state (spec/08 §12.3): meta `btc` holds the BIP84 account 0 (JSON version
/// 1, unchanged), meta `btc_accounts` the other accounts (JSON version 2, [`BtcAccounts`]).
/// A single imported key has one address `(Receive, 0)`: `receive_next = 1`, `change_next = 0`,
/// no discovery, change back to that address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcMeta {
    pub(crate) network: BtcNetwork,
    pub(crate) account: BtcAccountKey,
    pub(crate) receive_next: u32,
    pub(crate) change_next: u32,
    pub(crate) last_used_receive: Option<u32>,
    pub(crate) last_used_change: Option<u32>,
    pub(crate) discovery_done: bool,
    pub(crate) max_tip_seen: u32,
    pub(crate) verified: Vec<VerifiedUtxo>,
    pub(crate) frozen: Vec<(OutPoint, FreezeReason)>,
    pub(crate) unfrozen: Vec<OutPoint>,
    pub(crate) sent_scripts: Vec<[u8; 32]>,
}

fn script_hash(script: &[u8]) -> [u8; 32] {
    Sha256::digest(script).into()
}

impl BtcMeta {
    /// Fresh meta of the BIP84 account 0 for `network` with the node from
    /// `Vault::btc_account_xpub(network.coin_type())` (BTC enable, network change, meta reset):
    /// indices 0, nothing verified, discovery pending.
    #[must_use]
    pub const fn new(network: BtcNetwork, account: AccountXpub) -> Self {
        Self::with_key(network, BtcAccountKey::primary(account))
    }

    /// Fresh meta of any account: an HD account starts like [`BtcMeta::new`]; a single key gets
    /// its one address issued (`receive_next = 1`) and needs no discovery.
    #[must_use]
    pub const fn with_key(network: BtcNetwork, account: BtcAccountKey) -> Self {
        let single = account.is_single();
        Self {
            network,
            account,
            receive_next: if single { 1 } else { 0 },
            change_next: 0,
            last_used_receive: None,
            last_used_change: None,
            discovery_done: single,
            max_tip_seen: 0,
            verified: Vec::new(),
            frozen: Vec::new(),
            unfrozen: Vec::new(),
            sent_scripts: Vec::new(),
        }
    }

    /// Network copy.
    #[must_use]
    pub const fn network(&self) -> BtcNetwork {
        self.network
    }

    /// The account: address type and public key material (HD node `m/{p}'/{coin}'/{a}'` or a
    /// single key).
    #[must_use]
    pub const fn account(&self) -> &BtcAccountKey {
        &self.account
    }

    /// The account identity.
    #[must_use]
    pub const fn id(&self) -> BtcAccountId {
        self.account.id()
    }

    /// One key with one address (an imported key or an EVM account's key: no discovery, no
    /// "새 주소").
    #[must_use]
    pub const fn is_single(&self) -> bool {
        self.account.is_single()
    }

    /// An imported key's account (vault tag 4 record).
    #[must_use]
    pub const fn is_imported(&self) -> bool {
        self.account.is_imported()
    }

    /// Next receive index to issue.
    #[must_use]
    pub const fn receive_next(&self) -> u32 {
        self.receive_next
    }

    /// Next change index to use.
    #[must_use]
    pub const fn change_next(&self) -> u32 {
        self.change_next
    }

    /// Highest receive index with history.
    #[must_use]
    pub const fn last_used_receive(&self) -> Option<u32> {
        self.last_used_receive
    }

    /// Highest change index with history.
    #[must_use]
    pub const fn last_used_change(&self) -> Option<u32> {
        self.last_used_change
    }

    /// Discovery finished (sending is refused otherwise).
    #[must_use]
    pub const fn discovery_done(&self) -> bool {
        self.discovery_done
    }

    /// Highest Core tip seen.
    #[must_use]
    pub const fn max_tip_seen(&self) -> u32 {
        self.max_tip_seen
    }

    /// Verified outputs.
    #[must_use]
    pub fn verified(&self) -> &[VerifiedUtxo] {
        &self.verified
    }

    /// Frozen outpoints.
    #[must_use]
    pub fn frozen(&self) -> &[(OutPoint, FreezeReason)] {
        &self.frozen
    }

    /// Outpoints the user unfroze (never auto-frozen again).
    #[must_use]
    pub fn unfrozen(&self) -> &[OutPoint] {
        &self.unfrozen
    }

    /// `SHA-256(scriptPubKey)` of recipients we sent to.
    #[must_use]
    pub fn sent_scripts(&self) -> &[[u8; 32]] {
        &self.sent_scripts
    }

    /// The settings network must equal the meta copy (spec/08 §2).
    ///
    /// # Errors
    ///
    /// [`MetaError::NetworkMismatch`]: block every BTC call and send.
    pub fn check_network(&self, settings: BtcNetwork) -> Result<(), MetaError> {
        if settings == self.network {
            Ok(())
        } else {
            Err(MetaError::NetworkMismatch)
        }
    }

    const fn next_of(&self, chain: BtcChain) -> u32 {
        match chain {
            BtcChain::Receive => self.receive_next,
            BtcChain::Change => self.change_next,
        }
    }

    /// Our address of `(chain, index)` by public derivation (a single key: `(Receive, 0)` only).
    ///
    /// # Errors
    ///
    /// [`KeyError`] (hardened index, derivation, randomness).
    pub fn address(&self, chain: BtcChain, index: u32) -> Result<BtcAddress, KeyError> {
        self.account.address(self.network, chain, index)
    }

    /// The `verify_prev_output` expected script (our output of the account type) of
    /// `(chain, index)`.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub fn expected_script(&self, chain: BtcChain, index: u32) -> Result<Vec<u8>, KeyError> {
        self.account.script(chain, index)
    }

    /// The watch set (spec/08 §3.3): receive `[0, receive_next)` then change `[0, change_next)`,
    /// with their addresses; each chain stops at `BTC_MAX_ADDRESS_INDEX`. A single key watches
    /// its one address.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub fn watch_set(&self) -> Result<Vec<(BtcChain, u32, BtcAddress)>, KeyError> {
        let deriver = self.account.deriver()?;
        let mut out = Vec::new();
        for chain in [BtcChain::Receive, BtcChain::Change] {
            for index in 0..self.next_of(chain).min(BTC_MAX_ADDRESS_INDEX) {
                let kind = deriver.kind(chain, index)?;
                out.push((chain, index, BtcAddress::ours(self.network, kind)));
            }
        }
        Ok(out)
    }

    const fn receive_start(&self) -> u32 {
        match self.last_used_receive {
            Some(used) => used.saturating_add(1),
            None => 0,
        }
    }

    /// `unused_tail = receive_next − (last_used_receive + 1 or 0)`.
    #[must_use]
    pub const fn unused_receive_tail(&self) -> u32 {
        self.receive_next.saturating_sub(self.receive_start())
    }

    fn issue_receive(&mut self) -> Result<u32, MetaError> {
        let index = self.receive_next;
        let next = index.checked_add(1).ok_or(MetaError::IndexExhausted)?;
        if next > MAX_NEXT || next > BTC_MAX_ADDRESS_INDEX {
            return Err(MetaError::IndexExhausted);
        }
        self.receive_next = next;
        Ok(index)
    }

    /// The receive screen's address (spec/08 §3.2): the smallest index of
    /// `[last_used_receive + 1 (or 0), receive_next)`, or a newly issued one when that range is
    /// empty (persist meta before showing it).
    ///
    /// # Errors
    ///
    /// [`MetaError::IndexExhausted`].
    pub fn receive_address(&mut self) -> Result<ReceiveAddress, MetaError> {
        if self.is_single() {
            return Ok(ReceiveAddress::Existing(0));
        }
        if self.account.fixed_address() {
            // Fixed-address mode: always `(Receive, 0)`, issued once (spec/08 §3.5).
            return if self.receive_next > 0 {
                Ok(ReceiveAddress::Existing(0))
            } else {
                self.issue_receive().map(ReceiveAddress::Issued)
            };
        }
        let start = self.receive_start();
        if start < self.receive_next {
            return Ok(ReceiveAddress::Existing(start));
        }
        self.issue_receive().map(ReceiveAddress::Issued)
    }

    /// "새 주소" (spec/08 §3.2): issues `receive_next`. With 20 or more unused addresses the
    /// warning must be confirmed first (`gap_confirmed`); with 100 or more it is refused. Persist
    /// meta before showing the address.
    ///
    /// # Errors
    ///
    /// [`MetaError::GapWarning`], [`MetaError::GapHardLimit`], [`MetaError::IndexExhausted`],
    /// [`MetaError::SingleAddress`] for a one-key account or an HD account in fixed-address mode.
    pub fn new_receive_address(&mut self, gap_confirmed: bool) -> Result<u32, MetaError> {
        if self.account.fixed_address() {
            return Err(MetaError::SingleAddress);
        }
        let unused = self.unused_receive_tail();
        if unused >= BTC_GAP_HARD_LIMIT {
            return Err(MetaError::GapHardLimit);
        }
        if unused >= BTC_GAP_LIMIT && !gap_confirmed {
            return Err(MetaError::GapWarning { unused });
        }
        self.issue_receive()
    }

    /// Receiving and change always use `(Receive, 0)` ([`BtcAccountKey::fixed_address`]).
    #[must_use]
    pub const fn fixed_address(&self) -> bool {
        self.account.fixed_address()
    }

    /// Switches an HD account between fixed-address mode (`true`: receive only at `(Receive, 0)`,
    /// change back to it) and HD mode (`false`: a new receive address each time, the change
    /// chain), spec/08 §3.5. Indices, history and outputs are kept: discovery and the watch set
    /// are the same in both modes. Returns whether meta changed.
    ///
    /// # Errors
    ///
    /// [`MetaError::SingleAddress`] for a one-key account (always one address).
    pub const fn set_single_address(&mut self, on: bool) -> Result<bool, MetaError> {
        if !self.account.is_hd() {
            return Err(MetaError::SingleAddress);
        }
        if self.account.fixed_address() == on {
            return Ok(false);
        }
        self.account = self.account.with_single_address(on);
        Ok(true)
    }

    /// Marks discovery as not finished (sending blocked until [`Discovery::apply`]).
    pub const fn mark_discovery_pending(&mut self) {
        self.discovery_done = false;
    }

    /// History of the watched address `(chain, index)` from the indexer `tx_count`
    /// (spec/08 §3.2): `tx_count > 0` raises `last_used_*`. Returns whether meta changed.
    ///
    /// # Errors
    ///
    /// [`MetaError::OutOfRange`] for an index that was never issued.
    pub fn mark_history(
        &mut self,
        chain: BtcChain,
        index: u32,
        tx_count: u64,
    ) -> Result<bool, MetaError> {
        if index >= self.next_of(chain) {
            return Err(MetaError::OutOfRange);
        }
        if tx_count == 0 {
            return Ok(false);
        }
        let slot = match chain {
            BtcChain::Receive => &mut self.last_used_receive,
            BtcChain::Change => &mut self.last_used_change,
        };
        if slot.is_some_and(|used| used >= index) {
            return Ok(false);
        }
        *slot = Some(index);
        Ok(true)
    }

    /// The listed outputs that still need `getrawtransaction` + `verify_prev_output`.
    #[must_use]
    pub fn unverified(&self, listed: &[ListedUtxo]) -> Vec<ListedUtxo> {
        listed
            .iter()
            .filter(|item| !self.verified.iter().any(|v| v.outpoint == item.outpoint))
            .copied()
            .collect()
    }

    /// Applies a complete refresh (spec/08 §4.7-4/5, §7.6). `listed` is every confirmed
    /// candidate of the watch set in this refresh (call only when the refresh completed),
    /// `newly` the outputs of `listed` that passed `verify_prev_output` now, `in_flight` the
    /// outpoints of in-flight journal entries (`journal::btc::in_flight_outpoints`), `own` our
    /// change outpoints (`journal::btc::own_outputs`). Heights follow the listing; entries not
    /// listed are removed unless in flight; new foreign outputs below 1,000 sats are frozen
    /// automatically unless the user unfroze them; frozen entries of removed outputs go too.
    pub fn apply_refresh(
        &mut self,
        listed: &[ListedUtxo],
        newly: &[VerifiedUtxo],
        in_flight: &[OutPoint],
        own: &[OutPoint],
    ) -> RefreshReport {
        let mut report = RefreshReport::default();
        for entry in &mut self.verified {
            if let Some(item) = listed.iter().find(|item| item.outpoint == entry.outpoint) {
                entry.height = item.height;
            }
        }
        let before = self.verified.len();
        self.verified.retain(|entry| {
            listed.iter().any(|item| item.outpoint == entry.outpoint)
                || in_flight.contains(&entry.outpoint)
        });
        report.removed =
            u32::try_from(before.saturating_sub(self.verified.len())).unwrap_or(u32::MAX);
        for candidate in newly {
            let is_listed = listed
                .iter()
                .any(|item| item.outpoint == candidate.outpoint);
            let known = self
                .verified
                .iter()
                .any(|entry| entry.outpoint == candidate.outpoint);
            if !is_listed || known {
                continue;
            }
            if self.verified.len() >= MAX_VERIFIED {
                report.skipped = report.skipped.saturating_add(1);
                continue;
            }
            let mut entry = *candidate;
            entry.own = entry.own || own.contains(&entry.outpoint);
            let small = entry.value.get() < BTC_AUTO_FREEZE_BELOW;
            if !entry.own && small && !self.unfrozen.contains(&entry.outpoint) {
                if self.frozen.len() >= MAX_FROZEN {
                    report.skipped = report.skipped.saturating_add(1);
                    continue;
                }
                if !self.frozen.iter().any(|(op, _)| *op == entry.outpoint) {
                    self.frozen.push((entry.outpoint, FreezeReason::Auto));
                }
                report.auto_frozen = report.auto_frozen.saturating_add(1);
            }
            self.verified.push(entry);
            report.inserted = report.inserted.saturating_add(1);
        }
        let verified = &self.verified;
        self.frozen
            .retain(|(outpoint, _)| verified.iter().any(|entry| entry.outpoint == *outpoint));
        report
    }

    /// Inserts our own change after its transaction confirmed (spec/08 §12.2-5); updates the
    /// height if present. Returns whether meta changed.
    ///
    /// # Errors
    ///
    /// [`MetaError::Full`] when `verified` is full.
    pub fn insert_own(&mut self, utxo: VerifiedUtxo) -> Result<bool, MetaError> {
        let utxo = VerifiedUtxo { own: true, ..utxo };
        if let Some(entry) = self
            .verified
            .iter_mut()
            .find(|entry| entry.outpoint == utxo.outpoint)
        {
            let changed = *entry != utxo;
            *entry = utxo;
            return Ok(changed);
        }
        if self.verified.len() >= MAX_VERIFIED {
            return Err(MetaError::Full);
        }
        self.verified.push(utxo);
        Ok(true)
    }

    /// The freeze reason of `outpoint`.
    #[must_use]
    pub fn frozen_reason(&self, outpoint: &OutPoint) -> Option<FreezeReason> {
        self.frozen
            .iter()
            .find_map(|(op, reason)| (op == outpoint).then_some(*reason))
    }

    /// User freeze of a verified output.
    ///
    /// # Errors
    ///
    /// [`MetaError::NotVerified`], [`MetaError::Full`].
    pub fn freeze(&mut self, outpoint: OutPoint) -> Result<(), MetaError> {
        if !self.verified.iter().any(|entry| entry.outpoint == outpoint) {
            return Err(MetaError::NotVerified);
        }
        self.unfrozen.retain(|op| *op != outpoint);
        if let Some(entry) = self.frozen.iter_mut().find(|(op, _)| *op == outpoint) {
            entry.1 = FreezeReason::User;
            return Ok(());
        }
        if self.frozen.len() >= MAX_FROZEN {
            return Err(MetaError::Full);
        }
        self.frozen.push((outpoint, FreezeReason::User));
        Ok(())
    }

    /// Unfreezes an outpoint and remembers it in `unfrozen` (never auto-frozen again; the
    /// oldest record is dropped above 1,024).
    pub fn unfreeze(&mut self, outpoint: OutPoint) {
        self.frozen.retain(|(op, _)| *op != outpoint);
        if !self.unfrozen.contains(&outpoint) {
            self.unfrozen.push(outpoint);
            while self.unfrozen.len() > MAX_UNFROZEN {
                self.unfrozen.remove(0);
            }
        }
    }

    /// Selection candidates (spec/08 §7.4): confirmed (coinbase: 100), not frozen, not in flight.
    #[must_use]
    pub fn spendable(&self, tip_height: u32, in_flight: &[OutPoint]) -> Vec<Utxo> {
        self.verified
            .iter()
            .filter(|entry| {
                entry.is_mature(tip_height)
                    && self.frozen_reason(&entry.outpoint).is_none()
                    && !in_flight.contains(&entry.outpoint)
            })
            .map(VerifiedUtxo::utxo)
            .collect()
    }

    /// Balance (spec/08 §4.7-6), in-flight outpoints excluded.
    #[must_use]
    pub fn balance(&self, tip_height: u32, in_flight: &[OutPoint]) -> BtcBalance {
        let mut out = BtcBalance::default();
        for entry in &self.verified {
            if in_flight.contains(&entry.outpoint) {
                continue;
            }
            let slot = if !entry.is_mature(tip_height) {
                &mut out.pending
            } else if self.frozen_reason(&entry.outpoint).is_some() {
                &mut out.frozen
            } else {
                &mut out.available
            };
            *slot = slot.checked_add(entry.value).unwrap_or(Sats::MAX);
        }
        out
    }

    /// Every `outpoint → value` of `verified` (for `sign::check_recorded_amounts`).
    #[must_use]
    pub fn recorded_amounts(&self) -> Vec<(OutPoint, Sats)> {
        self.verified
            .iter()
            .map(|entry| (entry.outpoint, entry.value))
            .collect()
    }

    /// The smallest confirmation count of `outpoints` (server based); `None` if one is unknown.
    #[must_use]
    pub fn min_confirmations(&self, outpoints: &[OutPoint], tip_height: u32) -> Option<u32> {
        let mut minimum: Option<u32> = None;
        for outpoint in outpoints {
            let entry = self
                .verified
                .iter()
                .find(|entry| entry.outpoint == *outpoint)?;
            let confirmations = conf(entry.height, tip_height);
            minimum = Some(minimum.map_or(confirmations, |m| m.min(confirmations)));
        }
        minimum
    }

    /// Whether we never sent to `script` (B05).
    #[must_use]
    pub fn is_first_time(&self, script: &[u8]) -> bool {
        !self.sent_scripts.contains(&script_hash(script))
    }

    /// Records a recipient after `Submitted` (spec/08 §11.3); the oldest of more than 4,096 is
    /// dropped. Returns whether meta changed.
    pub fn record_sent_script(&mut self, script: &[u8]) -> bool {
        let hash = script_hash(script);
        if self.sent_scripts.contains(&hash) {
            return false;
        }
        self.sent_scripts.push(hash);
        while self.sent_scripts.len() > MAX_SENT_SCRIPTS {
            self.sent_scripts.remove(0);
        }
        true
    }

    /// Applies `getblockchaininfo.blocks` (spec/08 §2 step 2): refused at or above
    /// 500,000,000 (a lock-time timestamp, never a height) or when more than 6 below
    /// `max_tip_seen`, otherwise `max_tip_seen = max(max_tip_seen, blocks)`. (The chain check
    /// passes a value already limited by the indexer tip when it has one.) Returns whether meta
    /// changed.
    ///
    /// # Errors
    ///
    /// [`MetaError::TipImplausible`], [`MetaError::TipRegression`].
    pub fn observe_tip(&mut self, blocks: u32) -> Result<bool, MetaError> {
        if blocks >= BTC_LOCKTIME_THRESHOLD {
            return Err(MetaError::TipImplausible);
        }
        if blocks < self.max_tip_seen.saturating_sub(TIP_REGRESSION_ALLOWANCE) {
            return Err(MetaError::TipRegression {
                blocks,
                max_tip_seen: self.max_tip_seen,
            });
        }
        if blocks > self.max_tip_seen {
            self.max_tip_seen = blocks;
            return Ok(true);
        }
        Ok(false)
    }

    /// "블록 높이 기록 초기화" (spec/08 §2 step 2): forgets `max_tip_seen` after a Core endpoint
    /// reported a wrong, too high tip that now blocks every check (`TipRegression`). The next
    /// check stores the tip it sees again. Returns whether meta changed.
    pub const fn reset_max_tip(&mut self) -> bool {
        let changed = self.max_tip_seen != 0;
        self.max_tip_seen = 0;
        changed
    }

    /// Startup reconciliation (spec/08 §3.2): `change_next = max(meta, journal floor)` with the
    /// floor from `journal::btc::change_next_floor`. Returns whether meta changed.
    pub fn reconcile_change_next(&mut self, journal_floor: Option<u32>) -> bool {
        match journal_floor {
            _ if self.is_single() => false,
            Some(floor) if floor > self.change_next && floor <= MAX_NEXT => {
                self.change_next = floor;
                true
            }
            _ => false,
        }
    }

    /// A transaction entered `Broadcasting` (spec/08 §3.2): `change_next = max(change_next,
    /// change_index + 1)`. Returns whether meta changed.
    ///
    /// # Errors
    ///
    /// [`MetaError::IndexExhausted`].
    pub fn on_broadcasting(&mut self, change_index: Option<u32>) -> Result<bool, MetaError> {
        let Some(index) = change_index.filter(|_| !self.is_single()) else {
            return Ok(false);
        };
        let next = index.checked_add(1).ok_or(MetaError::IndexExhausted)?;
        if next > MAX_NEXT || next > BTC_MAX_ADDRESS_INDEX {
            return Err(MetaError::IndexExhausted);
        }
        if next > self.change_next {
            self.change_next = next;
            return Ok(true);
        }
        Ok(false)
    }

    /// A send was refused by the node without being relayed (`sendrawtransaction` `-25`/`-26`,
    /// spec/08 §3.2): `change_next` goes back to `change_index` when it was raised for this
    /// transaction only (`change_next == change_index + 1`), so the index is used again. Returns
    /// whether meta changed.
    pub fn on_send_rejected(&mut self, change_index: Option<u32>) -> bool {
        match change_index {
            _ if self.is_single() => false,
            Some(index) if index.checked_add(1) == Some(self.change_next) => {
                self.change_next = index;
                true
            }
            _ => false,
        }
    }

    /// `(chain, index)` when `script` is one of this account's addresses in
    /// `[0, next + BTC_GAP_LIMIT)` of either chain (a single key: its one address) (B07).
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub fn own_recipient(&self, script: &[u8]) -> Result<Option<(BtcChain, u32)>, KeyError> {
        let Some(kind) = kind_from_script(script) else {
            return Ok(None);
        };
        let deriver = self.account.deriver()?;
        if self.is_single() {
            return Ok(
                (deriver.kind(BtcChain::Receive, 0)? == kind).then_some((BtcChain::Receive, 0))
            );
        }
        let ours = matches!(
            (self.account.script_type(), kind),
            (ScriptType::P2pkh, ScriptKind::P2pkh(_))
                | (ScriptType::P2shP2wpkh, ScriptKind::P2sh(_))
                | (ScriptType::P2wpkh, ScriptKind::P2wpkh(_))
                | (ScriptType::P2tr, ScriptKind::P2tr(_))
        );
        if !ours {
            return Ok(None);
        }
        for chain in [BtcChain::Receive, BtcChain::Change] {
            let end = self
                .next_of(chain)
                .saturating_add(BTC_GAP_LIMIT)
                .min(HARDENED);
            for index in 0..end {
                if deriver.kind(chain, index)? == kind {
                    return Ok(Some((chain, index)));
                }
            }
        }
        Ok(None)
    }

    /// Every scriptPubKey [`BtcMeta::own_recipient`] recognises: `[0, next + BTC_GAP_LIMIT)` of
    /// both chains (a single key: its one address). The cross-identity journal rules (spec/08
    /// §12.1 "같은 주소의 다른 계정") and the import alias check (§3.5) match by these scripts.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub fn owned_scripts(&self) -> Result<Vec<Vec<u8>>, KeyError> {
        let deriver = self.account.deriver()?;
        if self.is_single() {
            return Ok(vec![deriver.script(BtcChain::Receive, 0)?]);
        }
        let mut out = Vec::new();
        for chain in [BtcChain::Receive, BtcChain::Change] {
            let end = self
                .next_of(chain)
                .saturating_add(BTC_GAP_LIMIT)
                .min(HARDENED);
            for index in 0..end {
                out.push(deriver.script(chain, index)?);
            }
        }
        Ok(out)
    }

    /// The approval facts of `plan` (spec/08 §10): available balance, minimum input
    /// confirmations, first-time and own-address recipient.
    ///
    /// # Errors
    ///
    /// [`KeyError`].
    pub fn send_facts(
        &self,
        plan: &SendPlan,
        tip_height: u32,
        in_flight: &[OutPoint],
    ) -> Result<BtcSendFacts, KeyError> {
        let script = plan.recipient_script();
        let outpoints: Vec<OutPoint> = plan.inputs().iter().map(|input| input.outpoint).collect();
        Ok(BtcSendFacts {
            verified_balance: self.balance(tip_height, in_flight).available,
            min_confirmations: self.min_confirmations(&outpoints, tip_height),
            first_time_recipient: self.is_first_time(&script),
            own_recipient: self.own_recipient(&script)?,
        })
    }
}

/// Discovery of spec/08 §3.4 as a state machine: ask [`Discovery::next_request`], query the
/// indexer `Address` of that `(chain, index)`, feed `tx_count` to [`Discovery::observe`], repeat
/// until it returns `None`, then [`Discovery::apply`]. A cancelled or failed run is simply
/// dropped (meta keeps `discovery_done == false`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discovery {
    scans: [Scan; 2],
    checked: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Scan {
    next_index: u32,
    gap: u32,
    last: Option<u32>,
    done: bool,
    /// The scan stops at this index (`BTC_DISCOVERY_MAX_SCAN` past its start, never above
    /// `BTC_MAX_ADDRESS_INDEX`).
    limit: u32,
}

const CHAINS: [BtcChain; 2] = [BtcChain::Receive, BtcChain::Change];

impl Discovery {
    /// Full discovery from index 0 of both chains (import, BTC enable, network change), at most
    /// `BTC_DISCOVERY_MAX_SCAN` addresses per chain.
    #[must_use]
    pub const fn full() -> Self {
        let limit = if BTC_DISCOVERY_MAX_SCAN < BTC_MAX_ADDRESS_INDEX {
            BTC_DISCOVERY_MAX_SCAN
        } else {
            BTC_MAX_ADDRESS_INDEX
        };
        let scan = Scan {
            next_index: 0,
            gap: 0,
            last: None,
            done: false,
            limit,
        };
        Self {
            scans: [scan, scan],
            checked: 0,
        }
    }

    /// "더 찾기": each chain 20 more addresses from its current `next` (the gap rule continues
    /// when history appears), at most `BTC_DISCOVERY_MAX_SCAN` per chain.
    #[must_use]
    pub const fn more(meta: &BtcMeta) -> Self {
        const fn scan(next: u32, last: Option<u32>) -> Scan {
            let wanted = next.saturating_add(BTC_DISCOVERY_MAX_SCAN);
            let limit = if wanted < BTC_MAX_ADDRESS_INDEX {
                wanted
            } else {
                BTC_MAX_ADDRESS_INDEX
            };
            Scan {
                next_index: next,
                gap: 0,
                last,
                done: next >= limit || next >= MAX_NEXT,
                limit,
            }
        }
        Self {
            scans: [
                scan(meta.receive_next, meta.last_used_receive),
                scan(meta.change_next, meta.last_used_change),
            ],
            checked: 0,
        }
    }

    /// The address to query next, `None` when finished.
    #[must_use]
    pub fn next_request(&self) -> Option<(BtcChain, u32)> {
        self.scans
            .iter()
            .zip(CHAINS)
            .find(|(scan, _)| !scan.done)
            .map(|(scan, chain)| (chain, scan.next_index))
    }

    /// Feeds the `tx_count` of the address returned by [`Discovery::next_request`].
    pub fn observe(&mut self, tx_count: u64) {
        let Some(scan) = self.scans.iter_mut().find(|scan| !scan.done) else {
            return;
        };
        if tx_count > 0 {
            scan.last = Some(scan.next_index);
            scan.gap = 0;
        } else {
            scan.gap = scan.gap.saturating_add(1);
        }
        scan.next_index = scan.next_index.saturating_add(1);
        if scan.gap >= BTC_GAP_LIMIT || scan.next_index >= scan.limit || scan.next_index >= MAX_NEXT
        {
            scan.done = true;
        }
        self.checked = self.checked.saturating_add(1);
    }

    /// Addresses checked so far (progress).
    #[must_use]
    pub const fn checked(&self) -> u32 {
        self.checked
    }

    /// Both chains finished.
    #[must_use]
    pub fn is_done(&self) -> bool {
        self.scans.iter().all(|scan| scan.done)
    }

    /// Writes the result: `next = max(next, last + 1 or 0)`, `last_used_* = max(..)`,
    /// `discovery_done = true`.
    ///
    /// # Errors
    ///
    /// [`MetaError::DiscoveryIncomplete`] before both chains finished.
    pub fn apply(&self, meta: &mut BtcMeta) -> Result<(), MetaError> {
        if !self.is_done() {
            return Err(MetaError::DiscoveryIncomplete);
        }
        if meta.is_single() {
            // One address, nothing to discover (its history comes with the refresh).
            meta.discovery_done = true;
            return Ok(());
        }
        for (scan, chain) in self.scans.iter().zip(CHAINS) {
            let found_next = scan.last.map_or(0, |last| last.saturating_add(1));
            let (next, last_used) = match chain {
                BtcChain::Receive => (&mut meta.receive_next, &mut meta.last_used_receive),
                BtcChain::Change => (&mut meta.change_next, &mut meta.last_used_change),
            };
            *next = (*next)
                .max(found_next.min(BTC_MAX_ADDRESS_INDEX))
                .min(MAX_NEXT);
            *last_used = match (*last_used, scan.last) {
                (Some(a), Some(b)) => Some(a.max(b)),
                (a, b) => a.or(b),
            };
        }
        meta.discovery_done = true;
        Ok(())
    }
}

// ---- JSON codec ----

fn object_with<'a>(
    value: &'a Value,
    keys: &[&str],
    field: &'static str,
) -> Result<&'a Object, BtcMetaError> {
    let object = value.as_object().ok_or(BtcMetaError(field))?;
    if object.len() != keys.len()
        || object.keys().any(|key| !keys.contains(&key))
        || keys.iter().any(|key| object.get(key).is_none())
    {
        return Err(BtcMetaError(field));
    }
    Ok(object)
}

/// [`object_with`] that also allows the `optional` keys (each at most once).
fn object_with_optional<'a>(
    value: &'a Value,
    keys: &[&str],
    optional: &[&str],
    field: &'static str,
) -> Result<&'a Object, BtcMetaError> {
    let object = value.as_object().ok_or(BtcMetaError(field))?;
    let present = optional
        .iter()
        .filter(|key| object.get(key).is_some())
        .count();
    if object.len() != keys.len().saturating_add(present)
        || object
            .keys()
            .any(|key| !keys.contains(&key) && !optional.contains(&key))
        || keys.iter().any(|key| object.get(key).is_none())
    {
        return Err(BtcMetaError(field));
    }
    Ok(object)
}

/// The optional account-object key of an HD account's address mode (spec/08 §12.3): absent =
/// fixed-address mode (the default, also for metas written before the mode existed); written only
/// as `false` (HD mode), so the default keeps earlier bytes.
pub const SINGLE_ADDRESS_KEY: &str = "single_address";

fn get<'a>(object: &'a Object, key: &'static str) -> Result<&'a Value, BtcMetaError> {
    object.get(key).ok_or(BtcMetaError(key))
}

fn integer(value: &Value, max: u64, field: &'static str) -> Result<u64, BtcMetaError> {
    value
        .as_number()
        .and_then(Number::as_u64)
        .filter(|number| *number <= max)
        .ok_or(BtcMetaError(field))
}

fn u32_field(value: &Value, max: u32, field: &'static str) -> Result<u32, BtcMetaError> {
    integer(value, u64::from(max), field)
        .and_then(|n| u32::try_from(n).map_err(|_| BtcMetaError(field)))
}

fn optional_u32(value: &Value, max: u32, field: &'static str) -> Result<Option<u32>, BtcMetaError> {
    if value.is_null() {
        Ok(None)
    } else {
        u32_field(value, max, field).map(Some)
    }
}

fn boolean(value: &Value, field: &'static str) -> Result<bool, BtcMetaError> {
    value.as_bool().ok_or(BtcMetaError(field))
}

fn hex_array<const N: usize>(value: &Value, field: &'static str) -> Result<[u8; N], BtcMetaError> {
    value
        .as_str()
        .and_then(|text| crate::hex::decode_array::<N>(text).ok())
        .ok_or(BtcMetaError(field))
}

fn decimal_u64(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    let canonical = match bytes {
        [b'0'] => true,
        [first, ..] => (b'1'..=b'9').contains(first) && bytes.iter().all(u8::is_ascii_digit),
        [] => false,
    };
    if !canonical || bytes.len() > 20 {
        return None;
    }
    text.parse::<u64>().ok()
}

fn sats_string(value: &Value, field: &'static str) -> Result<Sats, BtcMetaError> {
    value
        .as_str()
        .and_then(decimal_u64)
        .filter(|sats| *sats <= MAX_MONEY)
        .and_then(Sats::new)
        .ok_or(BtcMetaError(field))
}

/// Parses `"<txid display hex>:<vout decimal>"` (lowercase hex, canonical decimal).
#[must_use]
pub fn parse_outpoint(text: &str) -> Option<OutPoint> {
    let (txid, vout) = text.split_once(':')?;
    let txid = Txid::from_display_hex(txid).ok()?;
    let vout = u32::try_from(decimal_u64(vout)?).ok()?;
    Some(OutPoint { txid, vout })
}

fn outpoint(value: &Value, field: &'static str) -> Result<OutPoint, BtcMetaError> {
    value
        .as_str()
        .and_then(parse_outpoint)
        .ok_or(BtcMetaError(field))
}

fn chain_of(value: &Value) -> Result<BtcChain, BtcMetaError> {
    match integer(value, 1, "verified.chain")? {
        0 => Ok(BtcChain::Receive),
        _ => Ok(BtcChain::Change),
    }
}

fn array<'a>(
    value: &'a Value,
    max: usize,
    field: &'static str,
) -> Result<&'a [Value], BtcMetaError> {
    value
        .as_array()
        .filter(|items| items.len() <= max)
        .ok_or(BtcMetaError(field))
}

fn verified_entry(value: &Value) -> Result<VerifiedUtxo, BtcMetaError> {
    let object = object_with(value, &VERIFIED_KEYS, "verified")?;
    let value_sats = sats_string(get(object, "value")?, "verified.value")?;
    if value_sats == Sats::ZERO {
        return Err(BtcMetaError("verified.value"));
    }
    Ok(VerifiedUtxo {
        outpoint: outpoint(get(object, "outpoint")?, "verified.outpoint")?,
        value: value_sats,
        chain: chain_of(get(object, "chain")?)?,
        index: u32_field(
            get(object, "index")?,
            HARDENED.saturating_sub(1),
            "verified.index",
        )?,
        height: u32_field(get(object, "height")?, u32::MAX, "verified.height")?,
        is_coinbase: boolean(get(object, "is_coinbase")?, "verified.is_coinbase")?,
        own: boolean(get(object, "own")?, "verified.own")?,
    })
}

fn has_duplicates<T: PartialEq>(items: &[T]) -> bool {
    items.iter().enumerate().any(|(position, item)| {
        items
            .iter()
            .skip(position.saturating_add(1))
            .any(|other| other == item)
    })
}

fn string(text: impl Into<String>) -> Value {
    Value::String(text.into())
}

fn number(value: u64) -> Value {
    Value::Number(Number::from_u64(value))
}

fn optional(value: Option<u32>) -> Value {
    value.map_or(Value::Null, |value| number(u64::from(value)))
}

fn object(members: Vec<(&str, Value)>) -> Value {
    Object::from_pairs(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
    .map_or(Value::Null, Value::Object)
}

/// Keys of a version 2 account object (`btc_accounts.accounts[]`): version 1's with the
/// account node replaced by `script_type` and `key`.
const KEYS_V2: [&str; 14] = [
    "version",
    "network",
    "script_type",
    "key",
    "receive_next",
    "change_next",
    "last_used_receive",
    "last_used_change",
    "discovery_done",
    "max_tip_seen",
    "verified",
    "frozen",
    "unfrozen",
    "sent_scripts",
];
/// `key.hd` of a version 2 object.
const HD_KEYS: [&str; 3] = ["account", "pubkey", "chain_code"];
/// `key.imported` of a version 2 object.
const IMPORTED_KEYS: [&str; 2] = ["id", "pubkey"];
/// `key.evm` of a version 2 object (the key of EVM account `index`, `m/44'/60'/0'/0/i`).
const EVM_KEYS: [&str; 2] = ["index", "pubkey"];
/// `key.yubikey` of a version 2 object (a `YubiKey` key, spec/10 §3.3: `kind` `btc` = address
/// key `m/{44|49|84}'/{coin}'/0'/0/i`, `evm` = the EVM key `m/44'/60'/0'/0/i`; the public key is
/// a display cache, the vault tag-5 slot map is the source of truth).
const HW_KEYS: [&str; 3] = ["kind", "index", "pubkey"];
/// `btc_accounts.selected.yubikey`.
const HW_ID_KEYS: [&str; 3] = ["script_type", "kind", "index"];
/// `BtcMeta` version of the non-primary accounts.
pub const BTC_META_VERSION_V2: u64 = 2;

fn decode_hex_bytes(value: &Value, field: &'static str) -> Result<Vec<u8>, BtcMetaError> {
    value
        .as_str()
        .filter(|text| {
            text.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .and_then(|text| crate::hex::decode(text).ok())
        .ok_or(BtcMetaError(field))
}

/// The `key` object of a version 2 account.
fn account_key(value: &Value, script_type: ScriptType) -> Result<BtcAccountKey, BtcMetaError> {
    let object = value.as_object().ok_or(BtcMetaError("key"))?;
    if object.len() != 1 {
        return Err(BtcMetaError("key"));
    }
    if let Some(hd) = object.get("hd") {
        let hd = object_with(hd, &HD_KEYS, "key.hd")?;
        let account = u32_field(get(hd, "account")?, MAX_NEXT, "key.hd.account")?;
        let pubkey = hex_array::<33>(get(hd, "pubkey")?, "key.hd.pubkey")?;
        let chain_code = hex_array::<32>(get(hd, "chain_code")?, "key.hd.chain_code")?;
        let key = BtcAccountKey::hd(script_type, account, AccountXpub { pubkey, chain_code })
            .map_err(|_| BtcMetaError("key.hd"))?;
        if key.id() == BtcAccountId::PRIMARY {
            // BIP84 account 0 lives in meta `btc` (version 1).
            return Err(BtcMetaError("key.hd"));
        }
        return Ok(key);
    }
    if let Some(evm) = object.get("evm") {
        let evm = object_with(evm, &EVM_KEYS, "key.evm")?;
        let index = u32_field(get(evm, "index")?, MAX_NEXT, "key.evm.index")?;
        let pubkey = hex_array::<33>(get(evm, "pubkey")?, "key.evm.pubkey")?;
        return BtcAccountKey::evm_shared(index, script_type, pubkey)
            .map_err(|_| BtcMetaError("key.evm"));
    }
    if let Some(hw) = object.get("yubikey") {
        let hw = object_with(hw, &HW_KEYS, "key.yubikey")?;
        let index = u32_field(get(hw, "index")?, MAX_NEXT, "key.yubikey.index")?;
        let key = get(hw, "kind")?
            .as_str()
            .and_then(|kind| HwBtcKey::from_json(kind, index))
            .ok_or(BtcMetaError("key.yubikey.kind"))?;
        let pubkey = hex_array::<33>(get(hw, "pubkey")?, "key.yubikey.pubkey")?;
        return BtcAccountKey::hardware(key, script_type, pubkey)
            .map_err(|_| BtcMetaError("key.yubikey"));
    }
    let imported = object_with(
        object.get("imported").ok_or(BtcMetaError("key"))?,
        &IMPORTED_KEYS,
        "key.imported",
    )?;
    let id = hex_array::<16>(get(imported, "id")?, "key.imported.id")?;
    if id == [0; 16] {
        return Err(BtcMetaError("key.imported.id"));
    }
    let pubkey = BtcPubKey::parse(&decode_hex_bytes(
        get(imported, "pubkey")?,
        "key.imported.pubkey",
    )?)
    .map_err(|_| BtcMetaError("key.imported.pubkey"))?;
    BtcAccountKey::single(id, script_type, pubkey).map_err(|_| BtcMetaError("key.imported"))
}

/// `frozen`, `unfrozen` and `sent_scripts` of a `BtcMeta` object (bounds, no duplicates).
type Marks = (Vec<(OutPoint, FreezeReason)>, Vec<OutPoint>, Vec<[u8; 32]>);

fn parse_marks(root: &Object) -> Result<Marks, BtcMetaError> {
    let frozen = array(get(root, "frozen")?, MAX_FROZEN, "frozen")?
        .iter()
        .map(|item| {
            let object = object_with(item, &FROZEN_KEYS, "frozen")?;
            let reason = FreezeReason::from_code(integer(
                get(object, "reason")?,
                u64::MAX,
                "frozen.reason",
            )?)
            .ok_or(BtcMetaError("frozen.reason"))?;
            Ok((
                outpoint(get(object, "outpoint")?, "frozen.outpoint")?,
                reason,
            ))
        })
        .collect::<Result<Vec<_>, BtcMetaError>>()?;
    let frozen_outpoints: Vec<OutPoint> = frozen.iter().map(|(op, _)| *op).collect();
    if has_duplicates(&frozen_outpoints) {
        return Err(BtcMetaError("frozen"));
    }
    let unfrozen = array(get(root, "unfrozen")?, MAX_UNFROZEN, "unfrozen")?
        .iter()
        .map(|item| outpoint(item, "unfrozen"))
        .collect::<Result<Vec<_>, _>>()?;
    if has_duplicates(&unfrozen) {
        return Err(BtcMetaError("unfrozen"));
    }
    let sent_scripts = array(get(root, "sent_scripts")?, MAX_SENT_SCRIPTS, "sent_scripts")?
        .iter()
        .map(|item| hex_array::<32>(item, "sent_scripts"))
        .collect::<Result<Vec<_>, _>>()?;
    if has_duplicates(&sent_scripts) {
        return Err(BtcMetaError("sent_scripts"));
    }
    Ok((frozen, unfrozen, sent_scripts))
}

fn account_key_json(account: &BtcAccountKey) -> Value {
    match account {
        BtcAccountKey::Hd { account, xpub, .. } => object(vec![(
            "hd",
            object(vec![
                ("account", number(u64::from(*account))),
                ("pubkey", string(crate::hex::encode(&xpub.pubkey))),
                ("chain_code", string(crate::hex::encode(&xpub.chain_code))),
            ]),
        )]),
        BtcAccountKey::Single { id, pubkey, .. } => object(vec![(
            "imported",
            object(vec![
                ("id", string(crate::hex::encode(id))),
                ("pubkey", string(crate::hex::encode(pubkey.as_bytes()))),
            ]),
        )]),
        BtcAccountKey::EvmShared {
            evm_index, pubkey, ..
        } => object(vec![(
            "evm",
            object(vec![
                ("index", number(u64::from(*evm_index))),
                ("pubkey", string(crate::hex::encode(pubkey))),
            ]),
        )]),
        BtcAccountKey::Hardware { key, pubkey, .. } => object(vec![(
            "yubikey",
            object(vec![
                ("kind", string(key.json_kind())),
                ("index", number(u64::from(key.index()))),
                ("pubkey", string(crate::hex::encode(pubkey))),
            ]),
        )]),
    }
}

impl BtcMeta {
    /// Strict decode of a `BtcMeta` object (spec/08 §12.3): version 1 (meta `btc`, the BIP84
    /// account 0 node in `account_pubkey`/`account_chain_code`) or version 2 (meta
    /// `btc_accounts`, `script_type` and `key`).
    ///
    /// # Errors
    ///
    /// [`BtcMetaError`] naming the first invalid field: unknown or missing keys, wrong types or
    /// formats, an unknown `version`, an invalid account key, indices `>= 2^31`,
    /// `last_used >= next`, bounds (4,096 / 1,024 / 1,024 / 4,096), duplicates, a version 2
    /// object for BIP84 account 0, or a single key whose state is not its one address.
    pub fn from_json(value: &Value) -> Result<Self, BtcMetaError> {
        let version = value
            .as_object()
            .ok_or(BtcMetaError("btc"))?
            .get("version")
            .ok_or(BtcMetaError("btc"))
            .and_then(|version| integer(version, u64::MAX, "version"))?;
        let (root, account) = match version {
            BTC_META_VERSION => {
                let root = object_with_optional(value, &KEYS, &[SINGLE_ADDRESS_KEY], "btc")?;
                let pubkey = hex_array::<33>(get(root, "account_pubkey")?, "account_pubkey")?;
                if !matches!(pubkey.first(), Some(0x02 | 0x03))
                    || PublicKey::from_byte_array_compressed(pubkey).is_err()
                {
                    return Err(BtcMetaError("account_pubkey"));
                }
                let chain_code =
                    hex_array::<32>(get(root, "account_chain_code")?, "account_chain_code")?;
                (
                    root,
                    BtcAccountKey::primary(AccountXpub { pubkey, chain_code }),
                )
            }
            BTC_META_VERSION_V2 => {
                let root = object_with_optional(value, &KEYS_V2, &[SINGLE_ADDRESS_KEY], "btc")?;
                let script_type = get(root, "script_type")?
                    .as_str()
                    .and_then(ScriptType::parse_json_name)
                    .ok_or(BtcMetaError("script_type"))?;
                (root, account_key(get(root, "key")?, script_type)?)
            }
            _ => return Err(BtcMetaError("version")),
        };
        // The address mode of an HD account; absent = fixed-address mode (spec/08 §12.3).
        let account = match root.get(SINGLE_ADDRESS_KEY) {
            None => account,
            Some(_) if !account.is_hd() => return Err(BtcMetaError(SINGLE_ADDRESS_KEY)),
            Some(flag) => account.with_single_address(boolean(flag, SINGLE_ADDRESS_KEY)?),
        };
        let network = get(root, "network")?
            .as_str()
            .and_then(BtcNetwork::parse_settings_name)
            .ok_or(BtcMetaError("network"))?;
        let index_max = MAX_NEXT;
        let receive_next = u32_field(get(root, "receive_next")?, index_max, "receive_next")?;
        let change_next = u32_field(get(root, "change_next")?, index_max, "change_next")?;
        let last_used_receive = optional_u32(
            get(root, "last_used_receive")?,
            index_max,
            "last_used_receive",
        )?;
        let last_used_change = optional_u32(
            get(root, "last_used_change")?,
            index_max,
            "last_used_change",
        )?;
        if last_used_receive.is_some_and(|used| used >= receive_next) {
            return Err(BtcMetaError("last_used_receive"));
        }
        if last_used_change.is_some_and(|used| used >= change_next) {
            return Err(BtcMetaError("last_used_change"));
        }
        let verified = array(get(root, "verified")?, MAX_VERIFIED, "verified")?
            .iter()
            .map(verified_entry)
            .collect::<Result<Vec<_>, _>>()?;
        let outpoints: Vec<OutPoint> = verified.iter().map(|entry| entry.outpoint).collect();
        if has_duplicates(&outpoints) {
            return Err(BtcMetaError("verified"));
        }
        if account.is_single()
            && (receive_next != 1
                || change_next != 0
                || verified
                    .iter()
                    .any(|entry| entry.chain != BtcChain::Receive || entry.index != 0))
        {
            return Err(BtcMetaError("receive_next"));
        }
        let (frozen, unfrozen, sent_scripts) = parse_marks(root)?;
        Ok(Self {
            network,
            account,
            receive_next,
            change_next,
            last_used_receive,
            last_used_change,
            discovery_done: boolean(get(root, "discovery_done")?, "discovery_done")?,
            max_tip_seen: u32_field(get(root, "max_tip_seen")?, u32::MAX, "max_tip_seen")?,
            verified,
            frozen,
            unfrozen,
            sent_scripts,
        })
    }

    /// The `BtcMeta` object in §12.3 key order (lowercase hex, sats as decimal strings,
    /// outpoints `"<txid>:<vout>"`): version 1 for BIP84 account 0 (meta `btc`, byte-identical to
    /// earlier versions), version 2 for every other account.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let verified = self
            .verified
            .iter()
            .map(|entry| {
                object(vec![
                    ("outpoint", string(entry.outpoint.to_string())),
                    ("value", string(entry.value.get().to_string())),
                    ("chain", number(u64::from(entry.chain.index()))),
                    ("index", number(u64::from(entry.index))),
                    ("height", number(u64::from(entry.height))),
                    ("is_coinbase", Value::Bool(entry.is_coinbase)),
                    ("own", Value::Bool(entry.own)),
                ])
            })
            .collect();
        let frozen = self
            .frozen
            .iter()
            .map(|(outpoint, reason)| {
                object(vec![
                    ("outpoint", string(outpoint.to_string())),
                    ("reason", number(u64::from(reason.code()))),
                ])
            })
            .collect();
        let mut members = match (&self.account, self.account.id() == BtcAccountId::PRIMARY) {
            (BtcAccountKey::Hd { xpub, .. }, true) => vec![
                ("version", number(BTC_META_VERSION)),
                ("network", string(self.network.settings_name())),
                ("account_pubkey", string(crate::hex::encode(&xpub.pubkey))),
                (
                    "account_chain_code",
                    string(crate::hex::encode(&xpub.chain_code)),
                ),
            ],
            (account, _) => vec![
                ("version", number(BTC_META_VERSION_V2)),
                ("network", string(self.network.settings_name())),
                ("script_type", string(account.script_type().json_name())),
                ("key", account_key_json(account)),
            ],
        };
        members.extend([
            ("receive_next", number(u64::from(self.receive_next))),
            ("change_next", number(u64::from(self.change_next))),
            ("last_used_receive", optional(self.last_used_receive)),
            ("last_used_change", optional(self.last_used_change)),
            ("discovery_done", Value::Bool(self.discovery_done)),
            ("max_tip_seen", number(u64::from(self.max_tip_seen))),
            ("verified", Value::Array(verified)),
            ("frozen", Value::Array(frozen)),
            (
                "unfrozen",
                Value::Array(
                    self.unfrozen
                        .iter()
                        .map(|outpoint| string(outpoint.to_string()))
                        .collect(),
                ),
            ),
            (
                "sent_scripts",
                Value::Array(
                    self.sent_scripts
                        .iter()
                        .map(|hash| string(crate::hex::encode(hash)))
                        .collect(),
                ),
            ),
        ]);
        if !self.account.fixed_address() {
            // HD mode only: the default (fixed address) keeps the earlier bytes.
            members.push((SINGLE_ADDRESS_KEY, Value::Bool(false)));
        }
        object(members)
    }
}

/// The meta `btc` value: `null` → `None`, an object → [`BtcMeta::from_json`] (version 1, the
/// BIP84 account 0, only).
///
/// # Errors
///
/// [`BtcMetaError`].
pub fn btc_meta_from_json(value: &Value) -> Result<Option<BtcMeta>, BtcMetaError> {
    if value.is_null() {
        return Ok(None);
    }
    let meta = BtcMeta::from_json(value)?;
    if meta.id() != BtcAccountId::PRIMARY {
        return Err(BtcMetaError("btc"));
    }
    Ok(Some(meta))
}

/// `None` → `null`, `Some` → [`BtcMeta::to_json`].
#[must_use]
pub fn btc_meta_to_json(meta: Option<&BtcMeta>) -> Value {
    meta.map_or(Value::Null, BtcMeta::to_json)
}

// ---- meta `btc_accounts` ----

/// Most accounts in `btc_accounts` (both networks together).
pub const MAX_BTC_ACCOUNTS: usize = 64;
/// `btc_accounts.version`.
pub const BTC_ACCOUNTS_VERSION: u64 = 1;
const ACCOUNTS_KEYS: [&str; 3] = ["version", "selected", "accounts"];

/// Meta `btc_accounts` (spec/08 §12.3a, a new top-level key so earlier app versions keep it
/// unread and unchanged, spec/04 §6.6): every BTC account except BIP84 account 0 (which stays
/// meta `btc`), of both networks, and the selected account. Accounts of the other network stay
/// stored and come back when the network is switched back.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BtcAccounts {
    /// The selected account (`None` = BIP84 account 0, also when the selection is not an account
    /// of the current network).
    pub selected: Option<BtcAccountId>,
    /// The other accounts (each with its own network copy).
    pub accounts: Vec<BtcMeta>,
}

fn account_id_json(id: &BtcAccountId) -> Value {
    match id {
        BtcAccountId::Hd {
            script_type,
            account,
        } => object(vec![(
            "hd",
            object(vec![
                ("script_type", string(script_type.json_name())),
                ("account", number(u64::from(*account))),
            ]),
        )]),
        BtcAccountId::Imported { id } => object(vec![("imported", string(crate::hex::encode(id)))]),
        BtcAccountId::EvmShared {
            evm_index,
            script_type,
        } => object(vec![(
            "evm",
            object(vec![
                ("script_type", string(script_type.json_name())),
                ("index", number(u64::from(*evm_index))),
            ]),
        )]),
        BtcAccountId::Hardware { key, script_type } => object(vec![(
            "yubikey",
            object(vec![
                ("script_type", string(script_type.json_name())),
                ("kind", string(key.json_kind())),
                ("index", number(u64::from(key.index()))),
            ]),
        )]),
    }
}

fn account_id(value: &Value) -> Result<BtcAccountId, BtcMetaError> {
    const FIELD: &str = "btc_accounts.selected";
    let object = value.as_object().ok_or(BtcMetaError(FIELD))?;
    if object.len() != 1 {
        return Err(BtcMetaError(FIELD));
    }
    if let Some(hd) = object.get("hd") {
        let hd = object_with(hd, &["script_type", "account"], FIELD)?;
        return Ok(BtcAccountId::Hd {
            script_type: get(hd, "script_type")?
                .as_str()
                .and_then(ScriptType::parse_json_name)
                .ok_or(BtcMetaError(FIELD))?,
            account: u32_field(get(hd, "account")?, MAX_NEXT, FIELD)?,
        });
    }
    if let Some(evm) = object.get("evm") {
        let evm = object_with(evm, &["script_type", "index"], FIELD)?;
        return Ok(BtcAccountId::EvmShared {
            script_type: get(evm, "script_type")?
                .as_str()
                .and_then(ScriptType::parse_json_name)
                .ok_or(BtcMetaError(FIELD))?,
            evm_index: u32_field(get(evm, "index")?, MAX_NEXT, FIELD)?,
        });
    }
    if let Some(hw) = object.get("yubikey") {
        let hw = object_with(hw, &HW_ID_KEYS, FIELD)?;
        let script_type = get(hw, "script_type")?
            .as_str()
            .and_then(ScriptType::parse_json_name)
            .filter(|script_type| *script_type != ScriptType::P2tr)
            .ok_or(BtcMetaError(FIELD))?;
        let index = u32_field(get(hw, "index")?, MAX_NEXT, FIELD)?;
        let key = get(hw, "kind")?
            .as_str()
            .and_then(|kind| HwBtcKey::from_json(kind, index))
            .ok_or(BtcMetaError(FIELD))?;
        return Ok(BtcAccountId::Hardware { key, script_type });
    }
    let id = hex_array::<16>(object.get("imported").ok_or(BtcMetaError(FIELD))?, FIELD)?;
    Ok(BtcAccountId::Imported { id })
}

impl BtcAccounts {
    /// Strict decode of meta `btc_accounts`; a missing key is the default (no extra accounts).
    ///
    /// # Errors
    ///
    /// [`BtcMetaError`]: unknown or missing keys, `version != 1`, more than 64 accounts, an
    /// invalid account object, or two accounts with the same identity on one network.
    pub fn from_json(value: Option<&Value>) -> Result<Self, BtcMetaError> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let root = object_with(value, &ACCOUNTS_KEYS, "btc_accounts")?;
        if integer(get(root, "version")?, u64::MAX, "btc_accounts.version")? != BTC_ACCOUNTS_VERSION
        {
            return Err(BtcMetaError("btc_accounts.version"));
        }
        let selected = match get(root, "selected")? {
            Value::Null => None,
            other => Some(account_id(other)?),
        };
        let accounts = array(
            get(root, "accounts")?,
            MAX_BTC_ACCOUNTS,
            "btc_accounts.accounts",
        )?
        .iter()
        .map(BtcMeta::from_json)
        .collect::<Result<Vec<_>, _>>()?;
        let keys: Vec<(BtcNetwork, BtcAccountId)> = accounts
            .iter()
            .map(|meta| (meta.network(), meta.id()))
            .collect();
        if has_duplicates(&keys) {
            return Err(BtcMetaError("btc_accounts.accounts"));
        }
        Ok(Self { selected, accounts })
    }

    /// The `btc_accounts` object.
    #[must_use]
    pub fn to_json(&self) -> Value {
        object(vec![
            ("version", number(BTC_ACCOUNTS_VERSION)),
            (
                "selected",
                self.selected.as_ref().map_or(Value::Null, account_id_json),
            ),
            (
                "accounts",
                Value::Array(self.accounts.iter().map(BtcMeta::to_json).collect()),
            ),
        ])
    }

    /// The accounts of `network`.
    pub fn of_network(&self, network: BtcNetwork) -> impl Iterator<Item = &BtcMeta> {
        self.accounts
            .iter()
            .filter(move |meta| meta.network() == network)
    }

    /// Account `id` of `network`.
    #[must_use]
    pub fn get(&self, network: BtcNetwork, id: BtcAccountId) -> Option<&BtcMeta> {
        self.of_network(network).find(|meta| meta.id() == id)
    }

    /// Account `id` of `network`, mutable.
    pub fn get_mut(&mut self, network: BtcNetwork, id: BtcAccountId) -> Option<&mut BtcMeta> {
        self.accounts
            .iter_mut()
            .find(|meta| meta.network() == network && meta.id() == id)
    }

    /// Replaces account `meta.id()` of `meta.network()` or adds it.
    ///
    /// # Errors
    ///
    /// [`MetaError::Full`] at 64 accounts; [`MetaError::NotVerified`] for BIP84 account 0 (it
    /// belongs in meta `btc`).
    pub fn upsert(&mut self, meta: BtcMeta) -> Result<(), MetaError> {
        if meta.id() == BtcAccountId::PRIMARY {
            return Err(MetaError::NotVerified);
        }
        if let Some(slot) = self.get_mut(meta.network(), meta.id()) {
            *slot = meta;
            return Ok(());
        }
        if self.accounts.len() >= MAX_BTC_ACCOUNTS {
            return Err(MetaError::Full);
        }
        self.accounts.push(meta);
        Ok(())
    }

    /// The selected account on `network` (`PRIMARY` when nothing or a missing account is
    /// selected).
    #[must_use]
    pub fn selected_on(&self, network: BtcNetwork) -> BtcAccountId {
        match self.selected {
            Some(id) if self.get(network, id).is_some() => id,
            _ => BtcAccountId::PRIMARY,
        }
    }

    /// The account the Bitcoin tab works with on `network`: the selected one; otherwise BIP84
    /// account 0 when the wallet has it on `network` (`has_primary`); otherwise — a key-only
    /// wallet, whose accounts are all imported single keys — the first account of `network`.
    /// `None` when `network` has no account at all.
    #[must_use]
    pub fn active_on(&self, network: BtcNetwork, has_primary: bool) -> Option<BtcAccountId> {
        match self.selected_on(network) {
            BtcAccountId::PRIMARY if !has_primary => self.first_on(network),
            id => Some(id),
        }
    }

    /// The first account of `network` in list order.
    #[must_use]
    pub fn first_on(&self, network: BtcNetwork) -> Option<BtcAccountId> {
        self.of_network(network).next().map(BtcMeta::id)
    }

    /// The account holding the wallet-level `max_tip_seen` of `network` (the chain check's
    /// regression bound, spec/08 §2 step 2): BIP84 account 0 when the wallet has it on `network`
    /// (`has_primary`, meta `btc`), otherwise the first account of `network` (a key-only
    /// wallet). `None` when `network` has no account.
    #[must_use]
    pub fn tip_holder(&self, network: BtcNetwork, has_primary: bool) -> Option<BtcAccountId> {
        if has_primary {
            Some(BtcAccountId::PRIMARY)
        } else {
            self.first_on(network)
        }
    }

    /// Removes account `id` of `network` (a deleted imported key, or an account whose vault
    /// record is gone) and returns it. The selection falls back when it was this account.
    /// Without BIP84 account 0 on `network` (`has_primary == false`) the removed account may
    /// have held the wallet-level tip: the next holder keeps the higher `max_tip_seen`.
    pub fn remove(
        &mut self,
        network: BtcNetwork,
        id: BtcAccountId,
        has_primary: bool,
    ) -> Option<BtcMeta> {
        let position = self
            .accounts
            .iter()
            .position(|meta| meta.network() == network && meta.id() == id)?;
        let removed = self.accounts.remove(position);
        if self.selected == Some(id) {
            self.selected = None;
        }
        if !has_primary
            && let Some(next) = self.tip_holder(network, false)
            && let Some(holder) = self.get_mut(network, next)
        {
            holder.max_tip_seen = holder.max_tip_seen.max(removed.max_tip_seen);
        }
        Some(removed)
    }

    /// The next free HD account number of `script_type` on `network` (the BIP84 account 0 is
    /// meta `btc`, so P2WPKH starts at 1), `None` above [`BTC_MAX_HD_ACCOUNT`] or when the list is
    /// full.
    #[must_use]
    pub fn next_hd_account(&self, network: BtcNetwork, script_type: ScriptType) -> Option<u32> {
        if self.accounts.len() >= MAX_BTC_ACCOUNTS {
            return None;
        }
        let first = u32::from(script_type == ScriptType::P2wpkh);
        (first..=BTC_MAX_HD_ACCOUNT).find(|candidate| {
            self.get(
                network,
                BtcAccountId::Hd {
                    script_type,
                    account: *candidate,
                },
            )
            .is_none()
        })
    }
}
