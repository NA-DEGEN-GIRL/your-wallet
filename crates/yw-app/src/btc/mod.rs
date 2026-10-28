//! Bitcoin network layer of yw-app (spec/08 §2–§4, §11.3, §12.2; M8): Bitcoin Core JSON-RPC on
//! the `bitcoin:<net>` endpoint ([`rpc`]), the address indexer (`esplora` / `bb-rpc` /
//! `bb-rest`, [`indexer`]), request pacing and HTTP 429 back-off ([`pace`], [`client`]), the
//! connection check `check_chain()` and its session state ([`chain`]), the read pipelines
//! (Esplora `테스트`, discovery, refresh, tracking observation, [`flow`]) and the broadcast
//! primitives ([`broadcast`]).
//!
//! Everything here runs on the `yw-rpc` worker over the shared [`Transport`] and an injected
//! [`Clock`]; nothing touches keys, meta or the journal (those decide with the results). The
//! Core URL contains a token and is never formatted; the Esplora base URL is not secret but is
//! not logged either: logs name the network (`net=<NetworkId>`), the indexer (`idx=`), the path
//! kind or method, HTTP status, RPC code and txid only (spec/04 §8). Server strings (`message`,
//! `reject-reason`, `warnings`, `errors`, HTTP bodies) are never kept for display (spec/08 §13).

pub mod broadcast;
pub mod chain;
pub mod client;
pub mod flow;
pub mod indexer;
pub mod pace;
pub mod rpc;
pub mod work;

use yw_core::btc::BtcNetwork;
use yw_win::http::HttpsUrl;

use crate::errors::ErrorCode;
use crate::flow::evm::Clock;
use crate::logging::Field;
use crate::network::{BtcNet, NetworkId};
use crate::rpc::{RpcFailure, Transport, classify};
use crate::settings::{BtcIndexer, LogLevel};

pub use chain::{BtcBlock, ChainSession, ChainStatus};
pub use client::BtcClient;
pub use indexer::{
    AddrSummary, BtcIndexerReq, BtcIndexerResp, IndexerError, TxSeen, UtxoCandidate,
};
pub use pace::Pace;

/// yw-core network of a settings network.
#[must_use]
pub const fn core_network(net: BtcNet) -> BtcNetwork {
    match net {
        BtcNet::Mainnet => BtcNetwork::Mainnet,
        BtcNet::Testnet4 => BtcNetwork::Testnet4,
    }
}

/// Settings network of a yw-core network.
#[must_use]
pub const fn app_network(net: BtcNetwork) -> BtcNet {
    match net {
        BtcNetwork::Mainnet => BtcNet::Mainnet,
        BtcNetwork::Testnet4 => BtcNet::Testnet4,
    }
}

/// `bitcoin:<net>`.
#[must_use]
pub const fn network_id(net: BtcNetwork) -> NetworkId {
    NetworkId::Bitcoin(app_network(net))
}

/// The `idx=` word of logs (spec/04 §8).
#[must_use]
pub const fn indexer_word(kind: BtcIndexer) -> &'static str {
    match kind {
        BtcIndexer::Esplora => "esplora",
        BtcIndexer::BbRpc => "bb-rpc",
        BtcIndexer::BbRest => "bb-rest",
    }
}

/// The `{인덱서}` name of E-BTC-001 (spec/04 §7; no URL or host).
#[must_use]
pub const fn indexer_display(kind: BtcIndexer) -> &'static str {
    match kind {
        BtcIndexer::Esplora => "Esplora",
        BtcIndexer::BbRpc => "Blockbook JSON-RPC",
        BtcIndexer::BbRest => "Blockbook REST",
    }
}

/// The sources of one network (spec/04 §1.9 `RpcConfig` slice): the Core endpoint (secret,
/// D13), the indexer kind and the Esplora base URL of this network (not secret, never logged).
#[derive(Clone)]
pub struct BtcEndpoint {
    /// Network (settings `bitcoin.network`).
    pub net: BtcNetwork,
    /// `rpc:bitcoin:<net>` URL (Core JSON-RPC, also `bb-rpc` / `bb-rest`).
    pub core_url: HttpsUrl,
    /// `bitcoin.indexer`.
    pub indexer: BtcIndexer,
    /// `bitcoin.esploraBaseUrl.<net>` (no trailing `/`).
    pub esplora_base: HttpsUrl,
}

impl core::fmt::Debug for BtcEndpoint {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "BtcEndpoint({} idx={})",
            network_id(self.net),
            indexer_word(self.indexer)
        )
    }
}

/// Where request log lines go (the app log, or a recorder in tests).
pub trait LogSink: Send + Sync {
    /// One line of area `btc`.
    fn log(&self, level: LogLevel, event: &'static str, fields: &[(&'static str, Field<'_>)]);
}

/// The process log (`crate::logging`, area `btc`).
#[derive(Clone, Copy, Debug, Default)]
pub struct AppLog;

impl LogSink for AppLog {
    fn log(&self, level: LogLevel, event: &'static str, fields: &[(&'static str, Field<'_>)]) {
        crate::logging::log(level, "btc", event, fields);
    }
}

/// The process log sink.
pub static APP_LOG: AppLog = AppLog;

/// What every Bitcoin job runs on: the shared transport, the clock, the session's request line
/// and the log sink.
#[derive(Clone, Copy)]
pub struct BtcEnv<'a> {
    /// Transport (`WinHTTP` client or a fake).
    pub transport: &'a dyn Transport,
    /// Clock (monotonic ms for pacing and deadlines, sleeps for back-off).
    pub clock: &'a dyn Clock,
    /// Session pacing state.
    pub pace: &'a Pace,
    /// Log sink.
    pub log: &'a dyn LogSink,
}

impl core::fmt::Debug for BtcEnv<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BtcEnv")
    }
}

/// Who started a job: automatic refreshes and tracking are skipped during the 429 cooldown,
/// user-initiated ones run (spec/08 §4.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// The 60 s refresh / tracking cycle.
    Automatic,
    /// The user pressed a button (refresh, retry, discovery, send).
    User,
}

/// Why a Bitcoin job stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcError {
    /// BTC is blocked for this session (network mismatch, `check_chain` steps 1–3).
    Blocked(BtcBlock),
    /// A Core call failed (`classify`: E-RPC-001…008; 429 after the retries is E-RPC-004).
    Core(RpcFailure),
    /// An indexer call failed (E-BTC-001…007).
    Indexer(IndexerError),
    /// Cancelled by the user (discovery).
    Cancelled,
    /// An automatic job during the 429 cooldown: nothing was requested.
    Cooldown,
    /// Public derivation failed (`KeyError::DerivationFailed`; never skipped).
    Derivation,
}

impl BtcError {
    /// The classified code (`None` for cancel / cooldown / network mismatch, which have their
    /// own fixed texts).
    #[must_use]
    pub const fn code(self) -> Option<ErrorCode> {
        match self {
            Self::Blocked(block) => block.code(),
            Self::Core(failure) => Some(classify(failure)),
            Self::Indexer(error) => Some(error.code()),
            Self::Derivation => Some(ErrorCode::App009),
            Self::Cancelled | Self::Cooldown => None,
        }
    }

    /// The fixed display text (never a server string); `None` when nothing is shown.
    #[must_use]
    pub fn text(self, indexer: BtcIndexer) -> Option<String> {
        match self {
            Self::Blocked(block) => Some(block.text()),
            Self::Core(failure) => Some(classify(failure).text()),
            Self::Indexer(error) => Some(error.text(indexer)),
            Self::Derivation => Some(ErrorCode::App009.text()),
            Self::Cancelled | Self::Cooldown => None,
        }
    }

    /// The job was aborted by a fourth HTTP 429 (Core or indexer); the cooldown has started.
    #[must_use]
    pub const fn is_rate_limited(self) -> bool {
        match self {
            Self::Core(failure) => client::is_rate_limited(failure),
            Self::Indexer(error) => matches!(error, IndexerError::RateLimited),
            Self::Blocked(_) | Self::Cancelled | Self::Cooldown | Self::Derivation => false,
        }
    }

    /// Log word (code or variant name).
    #[must_use]
    pub const fn log_word(self) -> &'static str {
        match self {
            Self::Blocked(BtcBlock::NetworkMismatch) => "NetworkMismatch",
            Self::Cancelled => "Cancelled",
            Self::Cooldown => "Cooldown",
            _ => match self.code() {
                Some(code) => code.code(),
                None => "unknown",
            },
        }
    }
}

impl core::fmt::Display for BtcError {
    /// The log word (code or variant name; never a server string).
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.log_word())
    }
}

impl std::error::Error for BtcError {}

impl From<IndexerError> for BtcError {
    fn from(error: IndexerError) -> Self {
        Self::Indexer(error)
    }
}

impl From<RpcFailure> for BtcError {
    fn from(failure: RpcFailure) -> Self {
        Self::Core(failure)
    }
}
