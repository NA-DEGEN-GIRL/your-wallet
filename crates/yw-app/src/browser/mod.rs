//! The browser bridge (spec/05, M5): envelope v1, dApp parameter rules, the per-connection
//! dispatcher with its permission/chain state, the read workers and the named-pipe server.
//!
//! Thread model (spec/05 §8.3–§8.4, spec/04 §1.2): each pipe connection has a reader thread
//! ([`BrowserCore::handle_frame`] — answers "immediate" methods from memory, never waits for RPC
//! or approvals) and a writer thread (assigns the outbound `sequence`); reads go to
//! [`read::run_worker`] threads; approval-class requests go to the UI thread as
//! [`DappEvent::Request`]. The UI owns meta; grants changed by the reader thread (revoke,
//! chain switch) are mirrored to meta through [`DappEvent::GrantChanged`].

pub mod chain_params;
pub mod dispatch;
pub mod envelope;
pub mod grants;
pub mod params;
pub mod read;
pub mod server;

use yw_core::evm::address::Address;
use yw_core::evm::chain::ChainInfo;
use yw_core::policy::{BrowserOrigin, Method};
use yw_json::Value;
use yw_win::http::HttpsUrl;

pub use dispatch::BrowserCore;
use envelope::{BrowserEvent, CompatMode, Correlation, Id16, Id32};
use params::TxParams;

/// The pinned extension id file, compiled in (spec/05 §2.3).
const EXTENSION_ID_FILE: &str = include_str!("../../../../extension/extension-id.txt");

/// The pinned extension id (32 `a`–`p`), `None` if the file is malformed.
#[must_use]
pub fn pinned_extension_id() -> Option<&'static str> {
    let id = EXTENSION_ID_FILE.trim_end();
    (id.len() == 32 && id.bytes().all(|byte| (b'a'..=b'p').contains(&byte))).then_some(id)
}

/// `chrome-extension://<id>/`.
#[must_use]
pub fn pinned_origin() -> Option<String> {
    pinned_extension_id().map(|id| format!("chrome-extension://{id}/"))
}

/// Read deadline (D23).
pub const READ_DEADLINE_MS: u64 = 60_000;
/// Connect/signing deadline including unlock and review (D23).
pub const INTERACTIVE_DEADLINE_MS: u64 = 600_000;
/// Hello wait after a connection (spec/05 §8.2).
pub const HELLO_TIMEOUT_MS: u64 = 2_000;
/// Token refill per document per second.
pub const RATE_PER_DOCUMENT: u32 = 20;
/// Token bucket capacity and initial value.
pub const RATE_BURST: u32 = 40;
/// Reads waiting or running per document.
pub const MAX_READS_PER_DOCUMENT: usize = 64;
/// Reads waiting or running overall.
pub const MAX_READS_GLOBAL: usize = 256;
/// Reads waiting or running for one origin that is not connected (no grant while unlocked), over
/// all its documents: one site cannot take every global read slot (spec/05 §8.4).
pub const MAX_READS_PER_UNCONNECTED_ORIGIN: usize = 64;
/// Documents of one origin in the document table: a site churning activations evicts its own
/// oldest documents, not other sites' (spec/05 §4.8).
pub const MAX_DOCUMENTS_PER_ORIGIN: usize = 64;
/// After the user dismisses the unlock window opened for dApp requests (`나중에`), approval-class
/// requests that would open it again from origins not connected at lock time are rejected (4001)
/// for this long instead of popping the window (spec/05 §4.4).
pub const UNLOCK_PROMPT_COOLDOWN_MS: u64 = 30_000;
/// Read worker threads.
pub const READ_WORKERS: usize = 4;
/// Approval items per origin (shared with the UI queue).
pub const MAX_APPROVALS_PER_ORIGIN: usize = crate::ui::approval::MAX_APPROVALS_PER_ORIGIN;
/// Approval items overall.
pub const MAX_APPROVALS_GLOBAL: usize = crate::ui::approval::MAX_APPROVALS_GLOBAL;
/// Document table bound (LRU).
pub const MAX_DOCUMENTS: usize = 512;
/// Origin chain cache bound (LRU, spec/05 §4.3).
pub const MAX_CHAIN_CACHE: usize = 512;
/// Largest serialized read result (1 MiB − 4 KiB, spec/05 §3.5).
pub const MAX_RESULT_BYTES: usize = 1_044_480;
/// `eth_getLogs` range bound.
pub const MAX_LOGS_BLOCK_RANGE: u64 = params::MAX_LOGS_BLOCK_RANGE;
/// Block-number cache age for one-sided `eth_getLogs` ranges.
pub const LOGS_BLOCK_CACHE_MS: u64 = 12_000;

/// A pipe connection id (process-local).
pub type ConnId = u64;

/// The request a response belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Reply {
    /// Connection.
    pub conn: ConnId,
    /// Correlation of the request.
    pub correlation: Correlation,
}

impl Reply {
    /// The pending-table key.
    #[must_use]
    pub const fn key(&self) -> RequestKey {
        RequestKey {
            conn: self.conn,
            activation: self.correlation.activation_nonce,
            request: self.correlation.request_id,
        }
    }
}

/// `(connection, activationNonce, requestId)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RequestKey {
    /// Connection.
    pub conn: ConnId,
    /// Document activation.
    pub activation: Id32,
    /// Request id.
    pub request: Id16,
}

/// A frame for a connection's writer thread (it assigns `sequence`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outbound {
    /// A response.
    Response {
        /// Request correlation.
        correlation: Correlation,
        /// Result or error.
        body: Result<Value, yw_core::policy::ProviderError>,
    },
    /// An event.
    Event {
        /// The connection's last request session.
        session_id: Id32,
        /// Target document.
        activation_nonce: Id32,
        /// Event.
        event: BrowserEvent,
    },
}

/// Where a connection's outbound frames go (the writer channel; tests record them).
pub trait Outlet: Send {
    /// Queues a frame; `false` when the writer is gone.
    fn send(&self, outbound: Outbound) -> bool;
}

impl Outlet for std::sync::mpsc::Sender<Outbound> {
    fn send(&self, outbound: Outbound) -> bool {
        Self::send(self, outbound).is_ok()
    }
}

/// The vault state as the dispatcher needs it (spec/05 §4.4, D30).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultView {
    /// Before the first load result: requests needing the wallet wait like `Locked`.
    Starting,
    /// No wallet: account methods 4100, `eth_accounts` `[]`.
    NoVault,
    /// Locked (also unlocking / passphrase steps): wait for the unlock window.
    Locked,
    /// Backup not confirmed: connect and signing 4100.
    BackupPending,
    /// Unlocked: grants known.
    Unlocked,
    /// Unlocked with a BIP39 passphrase that failed its check value (`App::passphrase_unverified`,
    /// spec/02 §7.5): no grants (meta stays in memory), reads continue, connect and signing
    /// requests end 4100 `ProviderError::PassphraseUnverified`.
    PassphraseUnverified,
    /// Damaged vault or shutting down: like `NoVault`.
    Unavailable,
}

/// A registered EVM chain for the dispatcher and read workers.
#[derive(Clone)]
pub struct ChainEntry {
    /// Definition (with the pinned genesis if any).
    pub info: ChainInfo,
    /// `rpc:eip155:<chainId>` URL (secret, D13), `None` = no endpoint.
    pub url: Option<HttpsUrl>,
}

impl core::fmt::Debug for ChainEntry {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "ChainEntry(eip155:{})", self.info.chain_id)
    }
}

/// The UI-owned part of the dispatcher state (replaced as a whole by the UI thread).
#[derive(Clone, Debug)]
pub struct WalletView {
    /// Vault state.
    pub vault: VaultView,
    /// Registered EVM chains (built-ins + user chains, spec/05 §4.3).
    pub chains: Vec<ChainEntry>,
    /// `RpcMismatch` chains (blocked: switch 4901, reads 4901).
    pub blocked: Vec<u64>,
    /// `settings.json` `evmChainId`.
    pub evm_chain_id: u64,
    /// `allowLocalhostDapps`.
    pub allow_localhost: bool,
    /// The settings Solana cluster (SIWS `Chain ID`, approval binding).
    pub sol_cluster: yw_core::sol::SolCluster,
    /// The settings Bitcoin network (`btc_getNetwork`; grants of another network are unused).
    pub btc_network: yw_core::btc::BtcNetwork,
    /// settings `bitcoin.enabled`: when off, `btc_*` requests other than `btc_getNetwork` and
    /// `btc_disconnect` end 4100 `NoBtcAccount` (spec/05 §4.9).
    pub btc_enabled: bool,
    /// The Solana public keys dApps may use now (the visible accounts, `App::sol_dapp_rows`;
    /// empty while locked): a grant naming another key is not used (spec/05 §4.9).
    pub sol_accounts: Vec<[u8; 32]>,
    /// The Bitcoin addresses dApps may use now on `btc_network` (`App::btc_dapp_rows`; empty
    /// while locked): a grant with any other address is not used.
    pub btc_accounts: Vec<String>,
}

impl Default for WalletView {
    fn default() -> Self {
        Self {
            vault: VaultView::Starting,
            chains: Vec::new(),
            blocked: Vec::new(),
            evm_chain_id: yw_core::evm::chain::SEPOLIA,
            allow_localhost: false,
            sol_cluster: yw_core::sol::SolCluster::Devnet,
            btc_network: yw_core::btc::BtcNetwork::Testnet4,
            btc_enabled: false,
            sol_accounts: Vec::new(),
            btc_accounts: Vec::new(),
        }
    }
}

impl WalletView {
    /// Whether `chain_id` is registered.
    #[must_use]
    pub fn registered(&self, chain_id: u64) -> bool {
        self.chains
            .iter()
            .any(|entry| entry.info.chain_id == chain_id)
    }

    /// The entry of a registered chain.
    #[must_use]
    pub fn chain(&self, chain_id: u64) -> Option<&ChainEntry> {
        self.chains
            .iter()
            .find(|entry| entry.info.chain_id == chain_id)
    }

    /// Whether a Solana grant names a key dApps may use now.
    #[must_use]
    pub fn sol_usable(&self, grant: &yw_core::policy::SolGrant) -> bool {
        self.sol_accounts.contains(&grant.public)
    }

    /// Whether a Bitcoin grant may be used now: Bitcoin on, the settings network, and every
    /// address still one of the wallet's (a grant with a missing address is not used at all).
    #[must_use]
    pub fn btc_usable(&self, grant: &yw_core::policy::BtcGrant) -> bool {
        self.btc_enabled
            && grant.network == self.btc_network
            && grant
                .addresses
                .iter()
                .all(|entry| self.btc_accounts.contains(&entry.address))
    }
}

/// What an approval-class request asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteKind {
    /// `eth_requestAccounts` (window only when not connected).
    RequestAccounts,
    /// `wallet_requestPermissions` (always a window).
    RequestPermissions,
    /// `wallet_revokePermissions` while locked.
    Revoke,
    /// `eth_sendTransaction`.
    Send(Box<TxParams>),
    /// `personal_sign`.
    PersonalSign {
        /// Account.
        account: Address,
        /// Message bytes.
        message: Vec<u8>,
    },
    /// `eth_signTypedData_v4` (already validated against the origin chain).
    TypedData {
        /// Account.
        account: Address,
        /// Source bytes.
        source: Vec<u8>,
        /// The object.
        value: Value,
    },
    /// `sol_connect` (window: pick one Solana account).
    SolConnect,
    /// `btc_requestAccounts` (window: one address per purpose).
    BtcConnect(Vec<yw_core::policy::BtcPurpose>),
    /// `sol_signMessage` / `sol_signIn` (the SIWS text already built from the validated input).
    SolSign {
        /// Signing account (a granted one).
        public: [u8; 32],
        /// Message bytes.
        message: Vec<u8>,
        /// `sol_signIn`.
        sign_in: bool,
    },
    /// `btc_signMessage`.
    BtcSign {
        /// Signing address (a granted one).
        address: String,
        /// Message bytes (UTF-8).
        message: Vec<u8>,
        /// Requested protocol, `None` = the address type's default.
        protocol: Option<yw_core::btc::msgsign::BtcMessageProtocol>,
    },
}

impl SiteKind {
    /// Connect-window requests (`-32002` duplicates, spec/05 §4.2-1).
    #[must_use]
    pub const fn is_connect(&self) -> bool {
        matches!(
            self,
            Self::RequestAccounts
                | Self::RequestPermissions
                | Self::SolConnect
                | Self::BtcConnect(_)
        )
    }

    /// The chain family (grants, revocation and duplicate-window checks are per family).
    #[must_use]
    pub const fn family(&self) -> yw_core::policy::Family {
        match self {
            Self::SolConnect | Self::SolSign { .. } => yw_core::policy::Family::Solana,
            Self::BtcConnect(_) | Self::BtcSign { .. } => yw_core::policy::Family::Bitcoin,
            _ => yw_core::policy::Family::Evm,
        }
    }

    /// Signing requests (spec/05 §4.5: revoked while waiting → 4100).
    #[must_use]
    pub const fn is_signing(&self) -> bool {
        matches!(
            self,
            Self::Send(_)
                | Self::PersonalSign { .. }
                | Self::TypedData { .. }
                | Self::SolSign { .. }
                | Self::BtcSign { .. }
        )
    }
}

/// A request for the UI approval queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteRequest {
    /// Where to answer.
    pub reply: Reply,
    /// Origin.
    pub origin: BrowserOrigin,
    /// The origin chain at request time (spec/05 §4.3: used even if the chain changes later).
    pub chain_id: u64,
    /// Request deadline (monotonic ms, spec/05 §6.4).
    pub deadline_ms: u64,
    /// Method (logs).
    pub method: Method,
    /// What to do.
    pub kind: SiteKind,
    /// The extension compatibility mode of the requesting page (spec/05 §2.12): a badge in the
    /// connect and approval windows only, the origin above stays the real site.
    pub compat_mode: Option<CompatMode>,
}

/// A grant change made by the reader thread that the UI must persist in meta.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantChange {
    /// `wallet_switchEthereumChain` while connected and unlocked.
    Chain(u64),
    /// `wallet_revokePermissions` while unlocked.
    Revoked,
    /// `sol_disconnect` while unlocked.
    SolRevoked,
    /// `btc_disconnect` while unlocked.
    BtcRevoked,
}

/// Events for the UI thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DappEvent {
    /// An approval-class request.
    Request(Box<SiteRequest>),
    /// An approval-class request was cancelled (extension cancel or connection closed): close
    /// its window or drop it from the queue, no response.
    Cancel(RequestKey),
    /// Persist a grant change.
    GrantChanged {
        /// Origin.
        origin: BrowserOrigin,
        /// Change.
        change: GrantChange,
    },
    /// A read worker checked a chain (999 first-use pin, blocked state).
    ChainChecked {
        /// Chain.
        chain_id: u64,
        /// Result.
        check: crate::flow::evm::ChainCheck,
    },
    /// The number of live pipe connections changed (status line).
    Connections(usize),
}

/// The UI side of the dispatcher (the event queue in the app, a recorder in tests).
pub trait DappSink: Send + Sync {
    /// Delivers an event; `false` when the queue is full.
    fn push(&self, event: DappEvent) -> bool;
}

/// The dApp answer of a finished queue item (spec/04 §3.1 table, spec/05 §5); `None` for
/// `Approved` (answered by the flow with the result) and `Cancelled` (no response).
#[must_use]
pub const fn outcome_error(
    outcome: crate::ui::approval::QueueOutcome,
) -> Option<yw_core::policy::ProviderError> {
    use crate::ui::approval::QueueOutcome;
    use yw_core::policy::ProviderError;
    match outcome {
        QueueOutcome::Approved | QueueOutcome::Cancelled => None,
        QueueOutcome::Rejected => Some(ProviderError::UserRejected),
        QueueOutcome::Expired => Some(ProviderError::Expired),
        QueueOutcome::TimedOut => Some(ProviderError::TimedOut),
        QueueOutcome::Revoked | QueueOutcome::NotReady => Some(ProviderError::Unauthorized),
        QueueOutcome::PassphraseUnverified => Some(ProviderError::PassphraseUnverified),
        QueueOutcome::TooManyPending => Some(ProviderError::TooManyPending),
        QueueOutcome::Shutdown => Some(ProviderError::ConnectionClosed),
    }
}
