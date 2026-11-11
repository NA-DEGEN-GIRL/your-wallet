//! The opt-in received history ("받은 내역", spec/04 §2.6, 2026-11-11): off by default
//! (`settings.json` `receivedHistory`, one switch for every chain). When it is on, the RPC worker
//! reads the selected account's recent incoming transfers through the endpoints the wallet
//! already uses — no other service:
//!
//! - EVM ([`evm`]): `eth_getLogs` of ERC-20 `Transfer` to the account for the chain's token-card
//!   tokens only, scanned incrementally over a bounded recent window. Native-coin deposits are
//!   not visible to standard RPC and are not shown.
//! - Solana ([`sol`]): `getSignaturesForAddress` of the account and its allowlisted token
//!   accounts, then `getTransaction` (jsonParsed) of new signatures only.
//! - Bitcoin ([`btc`]): Esplora `/address/{a}/txs` of the newest used receive addresses, on the
//!   session's paced request line (429 back-off and cooldown included).
//! - `HyperCore` ([`hc`]): `/info` `userNonFundingLedgerUpdates`.
//! - Zcash ([`zec`]): the node's insight-style `getaddressdeltas`, when it has one.
//!
//! Address-poisoning defences (the reason the history was left out before): zero and dust
//! transfers are never listed, only counted ([`DUST`]); tokens that are not on the token card or
//! the allowlist never appear; senders are shown for reading only. Entries live in memory for
//! this run (no meta or vault change). Logs carry the chain, network and counts only.

pub mod btc;
pub mod evm;
pub mod hc;
pub mod sol;
pub mod zec;

use yw_core::evm::address::Address;
use yw_core::evm::amount::U256;
use yw_win::http::HttpsUrl;

use crate::flow::evm::ChainJob;
use crate::hypercore::HcEndpoint;
use crate::sol::flow::SolEndpoint;

/// Most entries kept per list (chain, network and account), newest first.
pub const MAX_ENTRIES: usize = 50;
/// Automatic re-read interval of a shown list (tab entry and `새로고침` read at once).
pub const REFRESH_MS: u64 = 60_000;
/// Most dust keys remembered per list (only for counting each hidden transfer once).
pub const MAX_DUST_KEYS: usize = 500;

// ----- dust thresholds ---------------------------------------------------------------------
//
// One table (spec/04 §2.6). Address poisoning sends zero or tiny transfers from a look-alike
// address so it lands in the history and gets copied later; an incoming amount below its asset's
// threshold — and every zero amount — is never listed, only counted in the muted line
// "먼지 금액·0원 입금 n건은 숨겼습니다(주소 오염 대비)". Real deposits are far above these.

/// SOL: below 0.001 SOL (1,000,000 lamports).
pub const DUST_SOL_LAMPORTS: u64 = 1_000_000;
/// BTC: below 1,000 sats.
pub const DUST_BTC_SATS: u64 = 1_000;
/// ZEC: below 0.0001 ZEC (10,000 zats).
pub const DUST_ZEC_ZATS: u64 = 10_000;
/// Tokens (ERC-20, SPL): below `10^(decimals − 4)` units, i.e. 0.0001 token (one unit for a
/// token with 4 or fewer decimals, so only zero is dust there).
pub const DUST_TOKEN_DIGITS: u8 = 4;
/// `HyperCore` ledger tokens (the allowlist of [`hc`]) and their thresholds: USDC below 0.01,
/// HYPE below 0.001.
pub const DUST_HC: [(&str, &str); 2] = [("USDC", "0.01"), ("HYPE", "0.001")];

/// Every row of the table, for the spec and the tests: `(asset, threshold)`.
pub const DUST: [(&str, &str); 6] = [
    ("SOL", "0.001 SOL"),
    ("BTC", "1,000 sats"),
    ("ZEC", "0.0001 ZEC"),
    ("ERC-20 / SPL", "10^(decimals−4) units (0.0001 token)"),
    ("HyperCore USDC", "0.01"),
    ("HyperCore HYPE", "0.001"),
];

/// The smallest listed amount of a token with `decimals`: `10^(decimals − 4)` units, at least 1.
#[must_use]
pub fn token_dust_units(decimals: u8) -> U256 {
    U256::checked_pow10(decimals.saturating_sub(DUST_TOKEN_DIGITS)).unwrap_or(U256::from_u64(1))
}

// ----- shared types ------------------------------------------------------------------------

/// The chain of a received list (one per activity card; `HyperCore` is its own card on the EVM
/// tab).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecvChain {
    /// The active EVM chain.
    Evm,
    /// Solana.
    Sol,
    /// Bitcoin.
    Btc,
    /// Hyperliquid `HyperCore`.
    Hc,
    /// Zcash (transparent).
    Zec,
}

impl RecvChain {
    /// Every chain, in [`Self::slot`] order.
    pub const ALL: [Self; 5] = [Self::Evm, Self::Sol, Self::Btc, Self::Hc, Self::Zec];

    /// The chain's slot in the command-id blocks (`ui::screens_received::ids`).
    #[must_use]
    pub const fn slot(self) -> u16 {
        match self {
            Self::Evm => 0,
            Self::Sol => 1,
            Self::Btc => 2,
            Self::Hc => 3,
            Self::Zec => 4,
        }
    }

    /// The chain of a slot.
    #[must_use]
    pub fn of_slot(slot: u16) -> Option<Self> {
        Self::ALL.get(usize::from(slot)).copied()
    }

    /// The fixed log word.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Evm => "evm",
            Self::Sol => "sol",
            Self::Btc => "btc",
            Self::Hc => "hypercore",
            Self::Zec => "zec",
        }
    }
}

/// Which list an answer belongs to: the chain, its network and the selected account (switching
/// either starts another list; the old one stays for this run).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ListKey {
    /// Chain.
    pub chain: RecvChain,
    /// Network id text (`eip155:1`, `solana:mainnet`, `hypercore:mainnet`, …).
    pub network: String,
    /// The account (address text; Bitcoin: its first receive address).
    pub account: String,
}

/// One incoming transfer to the account.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    /// Unique within its list (the hash plus the log index, mint or kind when one transaction
    /// carries several transfers).
    pub key: String,
    /// The transaction hash, signature or txid (`해시 복사`; empty when the source gave none).
    pub hash: String,
    /// When it happened (Unix ms), when known.
    pub time_ms: Option<u64>,
    /// Block number, slot or height, when known (shown when there is no time).
    pub block: Option<u64>,
    /// The amount without its symbol (`0.5`, `12.000000`).
    pub amount: String,
    /// The asset symbol.
    pub symbol: String,
    /// The sender (canonical address text), for reading only.
    pub from: Option<String>,
    /// A fixed line instead of a sender (a bridge deposit, a source without senders).
    pub from_note: Option<&'static str>,
    /// Not confirmed yet (Bitcoin mempool, Solana `processed`).
    pub pending: bool,
}

impl Incoming {
    /// Newest first: pending ones, then by time, then by block.
    #[must_use]
    pub fn order(&self) -> (bool, u64, u64) {
        (
            self.pending,
            self.time_ms.unwrap_or(0),
            self.block.unwrap_or(0),
        )
    }
}

/// What one read found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// Listed transfers (above their dust threshold).
    pub entries: Vec<Incoming>,
    /// Keys of zero and dust transfers (counted, never listed).
    pub dust: Vec<String>,
}

/// Where the next read of a list continues (kept by the UI with the list).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Cursor {
    /// Nothing read yet.
    #[default]
    Start,
    /// EVM: the next block to scan and the `eth_getLogs` span that last worked.
    Block {
        /// Next block.
        next: u64,
        /// Span in blocks.
        span: u64,
    },
    /// Solana: the signatures already looked at, newest first (bounded).
    Seen(Vec<String>),
    /// `HyperCore`: the newest ledger time seen (Unix ms).
    Time(u64),
    /// Zcash: the next height to scan.
    Height(u32),
}

/// A finished read.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fetched {
    /// What it found.
    pub found: Found,
    /// Where the next read continues.
    pub cursor: Cursor,
    /// The endpoint cannot list received transfers: this fixed line is shown instead (no more
    /// automatic reads of this list in this run; `새로고침` tries again).
    pub unsupported: Option<&'static str>,
    /// A fixed muted line about this read (a skipped range), until the next read.
    pub note: Option<&'static str>,
}

/// An ERC-20 of the token card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenRef {
    /// Contract.
    pub address: Address,
    /// Ticker shown.
    pub symbol: String,
    /// Decimals.
    pub decimals: u8,
}

/// The chain part of a job.
pub enum JobKind {
    /// EVM token transfers (after the chain check of the worker's cache).
    Evm {
        /// Chain and URL.
        chain: Box<ChainJob>,
        /// The selected account.
        owner: Address,
        /// The chain's token-card tokens that are not hidden.
        tokens: Vec<TokenRef>,
    },
    /// Solana.
    Sol {
        /// Cluster and URL.
        endpoint: SolEndpoint,
        /// The selected account.
        owner: yw_core::sol::SolAddress,
    },
    /// Bitcoin (on the worker's Bitcoin session).
    Btc {
        /// Network and sources.
        target: crate::btc::work::BtcTarget,
        /// Account and addresses.
        work: btc::BtcReceivedWork,
    },
    /// `HyperCore`.
    Hc {
        /// API.
        endpoint: HcEndpoint,
        /// The selected EVM account.
        account: Address,
        /// The first read's `startTime` (Unix ms).
        start_ms: u64,
    },
    /// Zcash.
    Zec {
        /// Network.
        network: yw_core::zec::ZecNetwork,
        /// Endpoint URL (secret).
        url: HttpsUrl,
        /// UTXO source (`bb-rest` has no address deltas here).
        indexer: crate::settings::ZecIndexer,
        /// Our transparent address.
        address: String,
        /// The node tip of the last refresh (already chain-checked).
        tip: u32,
    },
}

impl core::fmt::Debug for JobKind {
    /// The variant only (the jobs carry endpoint URLs, which are secret).
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Evm { .. } => "JobKind::Evm",
            Self::Sol { .. } => "JobKind::Sol",
            Self::Btc { .. } => "JobKind::Btc",
            Self::Hc { .. } => "JobKind::Hc",
            Self::Zec { .. } => "JobKind::Zec",
        })
    }
}

/// A received-history job of the RPC worker.
pub struct ReceivedJob {
    /// UI job id (a stale answer is dropped).
    pub job: u64,
    /// The list.
    pub key: ListKey,
    /// Where the read continues.
    pub cursor: Cursor,
    /// Chain part.
    pub kind: JobKind,
}

impl core::fmt::Debug for ReceivedJob {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "ReceivedJob({})", self.key.chain.word())
    }
}

/// The answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceivedEvent {
    /// UI job id.
    pub job: u64,
    /// The list.
    pub key: ListKey,
    /// The read, or a fixed error text (never a server string).
    pub result: Result<Fetched, String>,
}

/// `Some(text)` of a strict decimal amount string: digits with at most one `.` inside, at most
/// 40 characters (amount strings of a remote API are shown only in this form).
#[must_use]
pub fn decimal_text(text: &str) -> Option<&str> {
    let (integer, fraction) = text.split_once('.').unwrap_or((text, "0"));
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    (text.len() <= 40 && digits(integer) && digits(fraction)).then_some(text)
}

#[cfg(test)]
mod tests {
    use super::{Incoming, decimal_text, token_dust_units};
    use yw_core::evm::amount::U256;

    #[test]
    fn token_dust_is_a_ten_thousandth_of_a_token() {
        assert_eq!(token_dust_units(6), U256::from_u64(100));
        assert_eq!(token_dust_units(18), U256::from_u64(100_000_000_000_000));
        assert_eq!(token_dust_units(4), U256::from_u64(1));
        assert_eq!(token_dust_units(0), U256::from_u64(1));
    }

    #[test]
    fn amounts_from_apis_are_plain_decimals() {
        for good in ["0", "10", "0.5", "14.625485"] {
            assert_eq!(decimal_text(good), Some(good));
        }
        for bad in ["", ".5", "5.", "-1", "1e5", "1.2.3", " 1", "NaN"] {
            assert_eq!(decimal_text(bad), None, "{bad}");
        }
    }

    #[test]
    fn pending_rows_come_first_then_the_newest() {
        let row = |pending, time| Incoming {
            key: String::new(),
            hash: String::new(),
            time_ms: time,
            block: None,
            amount: "1".to_owned(),
            symbol: "X".to_owned(),
            from: None,
            from_note: None,
            pending,
        };
        let mut rows = [row(false, Some(5)), row(true, None), row(false, Some(9))];
        rows.sort_by_key(|row| core::cmp::Reverse(row.order()));
        assert!(rows[0].pending);
        assert_eq!(rows[1].time_ms, Some(9));
    }
}
