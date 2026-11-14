//! The `WalletConnect` worker thread (spec/13 §4–§5): one relay WebSocket (JSON-RPC `irn_*`),
//! the [`Engine`], the Verify check, and the bridge to the browser dispatcher as a virtual
//! connection. Session requests become dispatcher requests of the session's synthetic origin, so
//! they meet the same grants, rate limits, approval queue, risk rules and simulation as the
//! extension — except that a locked wallet refuses them (4100) instead of opening the password
//! window (counted, and reported once at the next unlock), `eth_accounts` is empty while locked,
//! and a rejected, expired or timed-out request holds the session's next ones off for
//! [`REQUEST_COOLDOWN_MS`]. Proposals become an `eth_requestAccounts` of the session origin: the
//! connect window's answer approves or rejects, and the panel says which ([`ProposalEnd`]).
//!
//! Inputs arrive on one channel: UI commands, relay text frames (from a reader thread per
//! connection), and the dispatcher's answers and events (through [`WcOutlet`]).

use core::fmt::Write as _;
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};

use yw_core::evm::address::{Address, parse_address};
use yw_core::lang::Lang;
use yw_core::policy::{BrowserOrigin, Method, ProviderError};
use yw_core::secret::Zeroizing;
use yw_json::{Limits, Value};

use super::engine::{
    Engine, Notice, Out, ProposalView, Publish, SETTLE_TAG, Session, SessionRequest,
};
use super::store::WcStore;
use super::verify::{VerifyHttp, VerifyKey};
use super::{Metadata, VerifyStatus, session_origin};
use crate::browser::envelope::{
    BrowserContext, BrowserEvent, Correlation, Id16, Id32, RequestEnvelope, chain_id_hex,
};
use crate::browser::{BrowserCore, ConnId, INTERACTIVE_DEADLINE_MS, Outbound, Outlet, VaultView};
use crate::logging::{self, Field};
use crate::text::{json_object, json_str, json_u64};

/// The dispatcher session id of the bridge (one virtual connection).
const SESSION_ID: Id32 = Id32([0x57; 32]);
/// Relay connect timeout.
const CONNECT_TIMEOUT_MS: u32 = 15_000;
/// Reconnect backoff bounds.
const BACKOFF_MIN_MS: u64 = 1_000;
const BACKOFF_MAX_MS: u64 = 60_000;
/// After an authentication refusal (bad project id) the relay is retried this rarely.
const AUTH_RETRY_MS: u64 = 300_000;
/// An idle connection (no topic left) closes after this.
const IDLE_CLOSE_MS: u64 = 10_000;
/// Relay JWT lifetime (`CRYPTO_JWT_TTL` = 1 day).
const JWT_TTL_S: u64 = 86_400;
/// Messages kept while the relay is down.
const MAX_QUEUED: usize = 256;
/// After a session's signing request was rejected, expired or timed out, its next ones are
/// refused (4001) for this long (and the UI ends its already waiting ones, 4001): a dApp cannot
/// keep an approval window up continuously (spec/13 §5.2).
pub const REQUEST_COOLDOWN_MS: u64 = 15_000;

const RELAY_LIMITS: Limits = Limits {
    max_bytes: 4 * 1_048_576,
    max_depth: 16,
    max_nodes: 4_096,
    max_items: 2_048,
};

/// A relay connection (the `WinHTTP` WebSocket; an in-memory pair in tests).
pub trait RelayLink: Send + Sync {
    /// Sends a text frame; `false` when the connection is gone.
    fn send(&self, text: &str) -> bool;
    /// Blocks for the next text frame; `None` when closed.
    fn receive(&self) -> Option<String>;
    /// Closes (a blocked receive returns `None`).
    fn abort(&self);
}

/// Opens relay connections.
pub trait RelayConnector: Send {
    /// Connects to `url` (`https://…` form of the `wss://` URL with `auth`, `projectId`, `ua`).
    ///
    /// # Errors
    ///
    /// A [`ConnectError`].
    fn connect(&mut self, url: &str) -> Result<Arc<dyn RelayLink>, ConnectError>;
}

/// Why a relay connection failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectError {
    /// The relay refused the project id or the auth token (HTTP 401/403).
    Unauthorized(u32),
    /// Network, TLS or another failure.
    Network,
}

impl RelayLink for yw_win::ws::WebSocket {
    fn send(&self, text: &str) -> bool {
        self.send_text(text).is_ok()
    }

    fn receive(&self) -> Option<String> {
        match yw_win::ws::WebSocket::receive(self) {
            Ok(yw_win::ws::WsMessage::Text(text)) => Some(text),
            Ok(yw_win::ws::WsMessage::Closed) | Err(_) => None,
        }
    }

    fn abort(&self) {
        yw_win::ws::WebSocket::abort(self);
    }
}

/// The production connector.
#[derive(Debug, Default)]
pub struct WsConnector;

impl RelayConnector for WsConnector {
    fn connect(&mut self, url: &str) -> Result<Arc<dyn RelayLink>, ConnectError> {
        let url = yw_win::http::HttpsUrl::parse(url).map_err(|_| ConnectError::Network)?;
        match yw_win::ws::WebSocket::connect(&url, CONNECT_TIMEOUT_MS) {
            Ok(socket) => Ok(Arc::new(socket)),
            Err(yw_win::http::HttpError::Os(error))
                if error.api == "WinHttpReceiveResponse" && matches!(error.code, 401 | 403) =>
            {
                Err(ConnectError::Unauthorized(error.code))
            }
            Err(_) => Err(ConnectError::Network),
        }
    }
}

/// UI commands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WcCommand {
    /// The Reown project id (`None`: not set — the relay stays off).
    Configure(Option<String>),
    /// The unlocked meta state (first unlock only; later ones keep the live state).
    Load(Box<WcStore>),
    /// A pasted or decoded pairing URI.
    Pair(String),
    /// Disconnect one session.
    Disconnect([u8; 32]),
    /// The dispatcher's grants changed (the UI wrote them: an account hidden or removed, a site
    /// disconnected, a connect approved): each session follows its grant — gone → the session
    /// ends (`wc_sessionDelete`), other accounts → `wc_sessionUpdate` + `accountsChanged`.
    SyncGrants,
    /// Stop.
    Shutdown,
}

/// The relay state for the UI.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum RelayStatus {
    /// No project id.
    #[default]
    NoProject,
    /// Nothing to listen to (no session or pairing).
    Idle,
    /// Connecting or reconnecting.
    Connecting,
    /// Connected.
    Connected,
    /// The relay refused the project id (HTTP status).
    Unauthorized(u32),
    /// The last attempt failed (network); retrying.
    Offline,
}

impl RelayStatus {
    /// The status line.
    #[must_use]
    pub fn text(&self, lang: Lang) -> String {
        match self {
            Self::NoProject => text::RELAY_NO_PROJECT.get(lang).to_owned(),
            Self::Idle => text::RELAY_IDLE.get(lang).to_owned(),
            Self::Connecting => text::RELAY_CONNECTING.get(lang).to_owned(),
            Self::Connected => text::RELAY_CONNECTED.get(lang).to_owned(),
            Self::Unauthorized(code) => text::RELAY_UNAUTHORIZED.fill(lang, [&code.to_string()]),
            Self::Offline => text::RELAY_OFFLINE.get(lang).to_owned(),
        }
    }
}

/// A message for the `WalletConnect` panel, worded on the UI thread in the app language
/// ([`WcNotice::text`]; 2026-11-14: the worker sent finished Korean text before).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WcNotice {
    /// The pasted text is not a usable pairing URI.
    Uri(yw_core::walletconnect::UriError),
    /// No Reown project id saved.
    NoProject,
    /// The wallet is locked.
    Locked,
    /// The pairing URI expired.
    Expired,
    /// Paired; waiting for the dApp's proposal.
    Waiting,
    /// An engine notice with the registry names of the chains it lists.
    Engine(Notice, Vec<(u64, String)>),
}

impl WcNotice {
    /// The panel text.
    #[must_use]
    pub fn text(&self, lang: Lang) -> String {
        match self {
            Self::Uri(error) => error.message(lang).to_owned(),
            Self::NoProject => text::PAIR_NO_PROJECT.get(lang).to_owned(),
            Self::Locked => text::PAIR_LOCKED.get(lang).to_owned(),
            Self::Expired => text::PAIR_EXPIRED.get(lang).to_owned(),
            Self::Waiting => text::PAIR_WAITING.get(lang).to_owned(),
            Self::Engine(notice, labels) => {
                let label = |id: u64| {
                    labels
                        .iter()
                        .find(|(chain, _)| *chain == id)
                        .map_or_else(|| format!("eip155:{id}"), |(_, name)| name.clone())
                };
                notice_text(lang, notice, &label)
            }
        }
    }
}

/// A session row for the UI.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionView {
    /// Topic.
    pub topic: [u8; 32],
    /// Synthetic dispatcher origin.
    pub origin: BrowserOrigin,
    /// Claimed metadata.
    pub peer: Metadata,
    /// Verify result.
    pub verify: VerifyStatus,
    /// Accounts.
    pub accounts: Vec<Address>,
    /// Chains.
    pub chains: Vec<u64>,
    /// Expiry (Unix s).
    pub expiry: u64,
    /// Approved at (Unix s).
    pub created: u64,
    /// The dApp confirmed the session (answered its settle or used it); `false` is shown as
    /// `연결 확인 중` until it does or the session ends ([`super::engine::SETTLE_ACK_S`]).
    pub acknowledged: bool,
}

/// How a proposal's connect request ended (the panel says so instead of "arrived").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProposalEnd {
    /// Approved: the session exists.
    Connected,
    /// Approved after the proposal lapsed (or with no session slot left): nothing connected.
    TooLate,
    /// Refused while the wallet was locked (4100 at once — no password window for a remote
    /// dApp — or its window closed by the lock).
    Locked,
    /// Refused with this answer (rejected, expired, no EVM account, …).
    Refused(ProviderError),
}

/// Events for the UI thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WcEvent {
    /// Relay state.
    Status(RelayStatus),
    /// A verified proposal (its connect request follows on the dispatcher).
    Proposal(Box<ProposalView>),
    /// The proposal of this session topic finished, and how.
    ProposalDone([u8; 32], ProposalEnd),
    /// The session list and the state to persist in meta.
    Sessions(Vec<SessionView>, Box<WcStore>),
    /// A session ended: the UI removes its grant and its waiting requests.
    Ended(BrowserOrigin),
    /// A message for the `WalletConnect` panel (pairing errors, refused proposals etc.).
    Notice(WcNotice),
    /// Connect and signing requests refused (4100) while the wallet was locked, reported once
    /// at the next unlock (no window was opened for them).
    RefusedWhileLocked(u32),
}

/// Where worker events go (the UI event queue; a recorder in tests).
pub trait WcSink: Send + Sync {
    /// Delivers an event.
    fn push(&self, event: WcEvent);
}

/// Worker inputs.
#[derive(Debug)]
pub enum Input {
    /// A UI command.
    Command(WcCommand),
    /// A relay text frame of connection `generation`.
    Relay(u64, String),
    /// Connection `generation` closed.
    Closed(u64),
    /// A dispatcher answer or event.
    Dispatcher(Outbound),
}

/// The dispatcher outlet of the bridge.
pub struct WcOutlet(Mutex<Sender<Input>>);

impl core::fmt::Debug for WcOutlet {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WcOutlet")
    }
}

impl Outlet for WcOutlet {
    fn send(&self, outbound: Outbound) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .send(Input::Dispatcher(outbound))
            .is_ok()
    }
}

/// What a dispatcher request of the bridge answers.
#[derive(Clone, Debug)]
enum Waiting {
    /// The connect window of the proposal of session topic `proposal` (session origin `origin`).
    Connect {
        proposal: [u8; 32],
        origin: BrowserOrigin,
    },
    /// A session request.
    Request { topic: [u8; 32], id: u64 },
}

/// The pending relay RPCs of ours.
#[derive(Clone, Debug)]
enum RelayCall {
    Subscribe([u8; 32]),
    Other,
}

/// The worker.
pub struct Worker {
    engine: Engine,
    core: Arc<BrowserCore>,
    conn: ConnId,
    sink: Arc<dyn WcSink>,
    connector: Box<dyn RelayConnector>,
    http: Option<Box<dyn VerifyHttp + Send>>,
    verify_key: Option<VerifyKey>,
    project_id: Option<String>,
    client_seed: Option<Zeroizing<[u8; 32]>>,
    loaded: bool,
    link: Option<Arc<dyn RelayLink>>,
    generation: u64,
    tx: Sender<Input>,
    subscribed: HashMap<[u8; 32], String>,
    calls: HashMap<u64, RelayCall>,
    queued: Vec<Publish>,
    next_attempt_ms: u64,
    backoff_ms: u64,
    idle_since_ms: Option<u64>,
    waiting: HashMap<[u8; 16], Waiting>,
    /// Session topic → monotonic ms until which its signing requests are refused (after one was
    /// rejected, expired or timed out).
    cooldowns: HashMap<[u8; 32], u64>,
    /// Requests refused (4100) while the wallet was locked since the last unlock.
    locked_refusals: u32,
    counter: u64,
    status: RelayStatus,
}

impl core::fmt::Debug for Worker {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Worker")
    }
}

fn hex(topic: &[u8; 32]) -> String {
    yw_core::hex::encode(topic)
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

/// Whether `text` is a Reown Cloud project id (32 lowercase hex digits).
#[must_use]
pub fn valid_project_id(text: &str) -> bool {
    text.len() == 32
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The panel's words for an engine [`Notice`]: wallet text only (nothing the dApp sent is
/// repeated), chains by `label` (this wallet's registry name, else `eip155:N`).
#[must_use]
pub fn notice_text(lang: Lang, notice: &Notice, label: &dyn Fn(u64) -> String) -> String {
    let add_chain = text::HINT_ADD_CHAIN.get(lang);
    let evm_only = text::HINT_EVM_ONLY.get(lang);
    let new_link = text::HINT_NEW_LINK.get(lang);
    let list = |chains: &[u64]| {
        let mut parts: Vec<String> = chains.iter().take(4).map(|id| label(*id)).collect();
        if chains.len() > 4 {
            parts.push(text::MORE_CHAINS.fill(lang, [&(chains.len() - 4).to_string()]));
        }
        parts.join(", ")
    };
    match notice {
        Notice::MissingChains { chains, non_evm } => {
            let mut parts = Vec::new();
            if !chains.is_empty() {
                parts.push(list(chains));
            }
            if *non_evm {
                parts.push(text::NON_EVM_NETWORKS.get(lang).to_owned());
            }
            let hint = if chains.is_empty() {
                evm_only
            } else {
                add_chain
            };
            text::REFUSED_MISSING.fill(lang, [&parts.join(", "), hint])
        }
        Notice::NonEvmOnly => text::REFUSED_NON_EVM_ONLY.fill(lang, [evm_only]),
        Notice::NoChains(chains) if chains.is_empty() => {
            text::REFUSED_NO_CHAIN.get(lang).to_owned()
        }
        Notice::NoChains(chains) => {
            text::REFUSED_NONE_USABLE.fill(lang, [&list(chains), add_chain])
        }
        Notice::Malformed => text::REFUSED_MALFORMED.get(lang).to_owned(),
        Notice::Cooling => {
            text::COOLING.fill(lang, [&super::engine::PROPOSAL_COOLDOWN_S.to_string()])
        }
        Notice::PairingUsed => text::PAIRING_USED.fill(lang, [new_link]),
        Notice::Busy => text::BUSY.get(lang).to_owned(),
        Notice::PairingExpired => text::PAIRING_EXPIRED.fill(lang, [new_link]),
        Notice::SettleRefused => text::SETTLE_REFUSED.get(lang).to_owned(),
        Notice::Unconfirmed => text::UNCONFIRMED.fill(lang, [new_link]),
    }
}

/// The worker's panel texts (spec/13 §6; English spec/14).
pub mod text {
    yw_core::texts! {
        RELAY_NO_PROJECT = "Reown Project ID가 없어 WalletConnect가 꺼져 있습니다"
            / "WalletConnect is off: no Reown Project ID";
        RELAY_IDLE = "대기 중 (연결된 세션 없음)" / "Idle (no connected session)";
        RELAY_CONNECTING = "릴레이에 연결하는 중…" / "Connecting to the relay…";
        RELAY_CONNECTED = "릴레이에 연결됨" / "Connected to the relay";
        RELAY_UNAUTHORIZED(1) = "릴레이가 Project ID를 거부했습니다 (HTTP {0}) — dashboard.reown.com에서 ID와 허용 출처 설정을 확인하세요"
            / "The relay refused the Project ID (HTTP {0}) — check the ID and the allowed origins at dashboard.reown.com";
        RELAY_OFFLINE = "릴레이에 연결할 수 없습니다 — 다시 시도하는 중"
            / "Cannot connect to the relay — retrying";
        HINT_ADD_CHAIN = "설정 → EVM 체인에서 그 네트워크를 추가하거나 RPC를 확인한 뒤 dApp에서 다시 연결하세요."
            / "Add that network or check its RPC in Settings → EVM chains, then connect again from the dApp.";
        HINT_EVM_ONLY = "이 지갑의 WalletConnect는 EVM 네트워크만 지원합니다."
            / "This wallet's WalletConnect supports EVM networks only.";
        HINT_NEW_LINK = "dApp에서 새 QR/링크를 받아 다시 연결하세요."
            / "Get a new QR code or link from the dApp and connect again.";
        MORE_CHAINS(1) = "외 {0}개" / "and {0} more";
        NON_EVM_NETWORKS = "EVM이 아닌 네트워크(Solana·Bitcoin 등)"
            / "non-EVM networks (Solana, Bitcoin, etc.)";
        REFUSED_MISSING(2) = "연결 요청을 거절했습니다: dApp이 이 지갑에서 쓸 수 없는 네트워크를 필수로 요구합니다 — {0}. {1}"
            / "Connection request refused: the dApp requires networks this wallet cannot use — {0}. {1}";
        REFUSED_NON_EVM_ONLY(1) = "연결 요청을 거절했습니다: dApp이 EVM이 아닌 네트워크(Solana·Bitcoin 등)만 요청했습니다. {0}"
            / "Connection request refused: the dApp asked only for non-EVM networks (Solana, Bitcoin, etc.). {0}";
        REFUSED_NO_CHAIN = "연결 요청을 거절했습니다: dApp이 연결할 EVM 네트워크를 지정하지 않았습니다."
            / "Connection request refused: the dApp named no EVM network to connect to.";
        REFUSED_NONE_USABLE(2) = "연결 요청을 거절했습니다: dApp이 요청한 네트워크({0}) 중 이 지갑에서 쓸 수 있는 것이 없습니다. {1}"
            / "Connection request refused: none of the networks the dApp asked for ({0}) can be used in this wallet. {1}";
        REFUSED_MALFORMED = "연결 요청을 거절했습니다: dApp이 보낸 연결 요청의 형식이 올바르지 않습니다."
            / "Connection request refused: the dApp's connection request is malformed.";
        COOLING(1) = "방금 거절했거나 시간이 지난 연결 요청과 같은 연결 주소라 {0}초 동안은 새 요청을 받지 않습니다. 잠시 뒤 dApp에서 다시 연결하세요."
            / "Same link as a connection request just refused or timed out: no new request is taken for {0} s. Connect again from the dApp in a moment.";
        PAIRING_USED(1) = "이 연결 주소(QR/링크)는 이미 쓰였습니다. {0}"
            / "This link (QR/link) was already used. {0}";
        BUSY = "처리하지 않은 연결 요청이 많아 새 요청을 거절했습니다. 열린 연결 창부터 처리하세요."
            / "Too many connection requests are pending, so the new one was refused. Handle the open connection windows first.";
        PAIRING_EXPIRED(1) = "dApp의 연결 요청이 오지 않은 채 연결 주소가 만료되었습니다. {0}"
            / "The link expired before the dApp sent a connection request. {0}";
        SETTLE_REFUSED = "dApp이 방금 승인한 연결을 받아들이지 않아 그 WalletConnect 세션을 지웠습니다. dApp에서 다시 연결하세요."
            / "The dApp did not accept the connection just approved, so that WalletConnect session was removed. Connect again from the dApp.";
        UNCONFIRMED(1) = "dApp이 WalletConnect 연결을 확인하지 않아 세션을 끊었습니다(dApp 창이 닫혔을 수 있습니다). 필요하면 {0}"
            / "The dApp did not confirm the WalletConnect connection, so the session was disconnected (the dApp window may have closed). If needed: {0}";
        PAIR_NO_PROJECT = "먼저 Reown Project ID를 저장하세요 (연결된 사이트 → WalletConnect)."
            / "Save a Reown Project ID first (Connected sites → WalletConnect).";
        PAIR_LOCKED = "지갑 잠금을 해제한 뒤 다시 시도하세요." / "Unlock the wallet, then try again.";
        PAIR_EXPIRED = "연결 주소가 만료되었습니다. dApp에서 새 WalletConnect 주소를 받으세요."
            / "The link has expired. Get a new WalletConnect link from the dApp.";
        PAIR_WAITING = "dApp의 연결 요청을 기다리는 중입니다…"
            / "Waiting for the dApp's connection request…";
    }
}

impl Worker {
    /// A worker on `core` (opens the virtual connection) and its input sender.
    pub fn new(
        core: Arc<BrowserCore>,
        sink: Arc<dyn WcSink>,
        connector: Box<dyn RelayConnector>,
        http: Option<Box<dyn VerifyHttp + Send>>,
    ) -> (Self, Sender<Input>, Receiver<Input>) {
        let (tx, rx) = std::sync::mpsc::channel();
        let conn = core.open_virtual_connection(Box::new(WcOutlet(Mutex::new(tx.clone()))));
        let worker = Self {
            engine: Engine::new(),
            core,
            conn,
            sink,
            connector,
            http,
            verify_key: None,
            project_id: None,
            client_seed: None,
            loaded: false,
            link: None,
            generation: 0,
            tx: tx.clone(),
            subscribed: HashMap::new(),
            calls: HashMap::new(),
            queued: Vec::new(),
            next_attempt_ms: 0,
            backoff_ms: BACKOFF_MIN_MS,
            idle_since_ms: None,
            waiting: HashMap::new(),
            cooldowns: HashMap::new(),
            locked_refusals: 0,
            counter: 0,
            status: RelayStatus::NoProject,
        };
        (worker, tx, rx)
    }

    fn now_ms(&self) -> u64 {
        self.core.clock().now_ms()
    }

    fn now_s(&self) -> u64 {
        self.core.clock().now_unix_ms() / 1_000
    }

    /// Runs until [`WcCommand::Shutdown`] or the channel closes.
    pub fn run(mut self, rx: &Receiver<Input>) {
        loop {
            match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(Input::Command(WcCommand::Shutdown)) | Err(RecvTimeoutError::Disconnected) => {
                    break;
                }
                Ok(input) => {
                    // The registry as of this input (a chain deleted while waiting is gone).
                    self.refresh_chains();
                    self.handle(input);
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
            self.refresh_chains();
            self.tick();
        }
        if let Some(link) = self.link.take() {
            link.abort();
        }
        self.core.close_connection(self.conn);
    }

    /// Handles one input (tests drive the worker through this and [`Self::tick`]).
    pub fn handle(&mut self, input: Input) {
        match input {
            Input::Command(command) => self.command(command),
            Input::Relay(generation, text) if generation == self.generation => self.relay(&text),
            Input::Closed(generation) if generation == self.generation => self.closed(),
            Input::Relay(..) | Input::Closed(_) => {}
            Input::Dispatcher(outbound) => self.dispatcher(outbound),
        }
    }

    fn set_status(&mut self, status: RelayStatus) {
        if self.status != status {
            self.status = status.clone();
            self.sink.push(WcEvent::Status(status));
        }
    }

    fn command(&mut self, command: WcCommand) {
        match command {
            WcCommand::Configure(project_id) => {
                let changed = self.project_id != project_id;
                self.project_id = project_id.filter(|id| valid_project_id(id));
                if changed {
                    self.next_attempt_ms = 0;
                    self.backoff_ms = BACKOFF_MIN_MS;
                    if let Some(link) = self.link.take() {
                        link.abort();
                    }
                    self.subscribed.clear();
                }
                if self.project_id.is_none() {
                    self.set_status(RelayStatus::NoProject);
                }
            }
            WcCommand::Load(store) => {
                if self.loaded && store.client_seed != self.client_seed {
                    // Another wallet's meta (after a reset): the live sessions, proposals and
                    // relay identity belong to the old one and go without a trace in the new.
                    self.forget_wallet();
                }
                if !self.loaded {
                    self.loaded = true;
                    self.client_seed.clone_from(&store.client_seed);
                    let now = self.now_s();
                    let outs = self.engine.restore(store.sessions, now);
                    self.apply(outs);
                    // Restored sessions hear their origin's events (account hidden or removed,
                    // site disconnected) before they make any request.
                    let topics: Vec<[u8; 32]> =
                        self.engine.sessions().iter().map(|s| s.topic).collect();
                    for topic in topics {
                        self.attach(topic);
                    }
                }
                // A session whose grant went (or whose accounts changed) while this worker could
                // not hear it follows the grant now; grants of sessions that no longer exist
                // (deleted while locked) are pruned by the UI from the snapshot below.
                self.sync_grants(None);
                self.push_sessions();
                // `Load` follows every unlock: what was refused meanwhile is said once.
                if self.locked_refusals > 0 {
                    self.sink
                        .push(WcEvent::RefusedWhileLocked(self.locked_refusals));
                    self.locked_refusals = 0;
                }
            }
            WcCommand::Pair(text) => self.pair(&text),
            WcCommand::Disconnect(topic) => {
                let now = self.now_s();
                let outs = self.engine.disconnect(&topic, now);
                self.apply(outs);
            }
            WcCommand::SyncGrants => self.sync_grants(None),
            WcCommand::Shutdown => {}
        }
    }

    /// Registers session `topic`'s synthetic origin as a document of the bridge connection.
    fn attach(&self, topic: [u8; 32]) {
        if let Some(origin) = session_origin(&topic) {
            self.core
                .attach_virtual_document(self.conn, SESSION_ID, Id32(topic), &origin);
        }
    }

    /// Each session (or only `only`) follows its dispatcher grant while unlocked (spec/13 §5.3):
    /// no grant → the session ends (`wc_sessionDelete`); other accounts → `wc_sessionUpdate` +
    /// `accountsChanged`. Locked (grants not loaded): nothing — the session waits for the unlock.
    fn sync_grants(&mut self, only: Option<[u8; 32]>) {
        let Some(grants) = self.core.grants_if_unlocked() else {
            return;
        };
        let now = self.now_s();
        let sessions: Vec<([u8; 32], Vec<Address>, Option<u64>)> = self
            .engine
            .sessions()
            .iter()
            .filter(|s| only.is_none_or(|topic| topic == s.topic))
            .map(|s| (s.topic, s.accounts.clone(), s.chains.first().copied()))
            .collect();
        for (topic, accounts, first_chain) in sessions {
            let Some(origin) = session_origin(&topic) else {
                continue;
            };
            match grants.iter().find(|grant| grant.origin == origin) {
                None => {
                    logging::info("walletconnect", "session.grant_gone", &[]);
                    let outs = self.engine.disconnect(&topic, now);
                    self.apply(outs);
                }
                Some(grant) if grant.accounts != accounts => {
                    let outs = self
                        .engine
                        .update(&topic, Some(grant.accounts.clone()), None, now);
                    self.apply(outs);
                    if let Some(chain) = first_chain {
                        let outs =
                            self.engine
                                .emit(&topic, "accountsChanged", chain, self.now_ms());
                        self.apply(outs);
                    }
                }
                Some(_) => {}
            }
        }
    }

    /// Drops every piece of wallet state (sessions, proposals, pairings, waiting answers, the
    /// relay key and connection); the next [`WcCommand::Load`] starts afresh.
    fn forget_wallet(&mut self) {
        if let Some(link) = self.link.take() {
            link.abort();
        }
        self.generation = self.generation.wrapping_add(1);
        self.engine = Engine::new();
        self.refresh_chains();
        self.subscribed.clear();
        self.calls.clear();
        self.queued.clear();
        self.waiting.clear();
        self.cooldowns.clear();
        self.locked_refusals = 0;
        self.client_seed = None;
        self.loaded = false;
        self.next_attempt_ms = 0;
        self.backoff_ms = BACKOFF_MIN_MS;
        logging::info("walletconnect", "state.replaced", &[]);
    }

    fn pair(&mut self, text: &str) {
        let uri = match yw_core::walletconnect::parse_pairing_uri(text) {
            Ok(uri) => uri,
            Err(error) => {
                self.sink.push(WcEvent::Notice(WcNotice::Uri(error)));
                return;
            }
        };
        if self.project_id.is_none() {
            self.sink.push(WcEvent::Notice(WcNotice::NoProject));
            return;
        }
        if !self.loaded || self.client_seed.is_none() {
            self.sink.push(WcEvent::Notice(WcNotice::Locked));
            return;
        }
        let now = self.now_s();
        if uri.expired(now) {
            self.sink.push(WcEvent::Notice(WcNotice::Expired));
            return;
        }
        let outs = self.engine.pair(&uri, now);
        self.apply(outs);
        self.sink.push(WcEvent::Notice(WcNotice::Waiting));
    }

    // ----- relay connection ------------------------------------------------------------

    fn wants_connection(&self) -> bool {
        self.project_id.is_some() && self.client_seed.is_some() && !self.engine.topics().is_empty()
    }

    /// Periodic work: session expiry, (re)connect with backoff, idle close.
    pub fn tick(&mut self) {
        let now_s = self.now_s();
        let outs = self.engine.tick(now_s);
        self.apply(outs);
        let now = self.now_ms();
        if self.wants_connection() {
            self.idle_since_ms = None;
            if self.link.is_none() && now >= self.next_attempt_ms {
                self.connect(now);
            }
        } else if self.link.is_some() {
            let since = *self.idle_since_ms.get_or_insert(now);
            if now.saturating_sub(since) >= IDLE_CLOSE_MS {
                if let Some(link) = self.link.take() {
                    link.abort();
                }
                self.subscribed.clear();
                self.idle_since_ms = None;
            }
        }
        if self.link.is_none() && self.project_id.is_some() && !self.wants_connection() {
            self.set_status(RelayStatus::Idle);
        }
    }

    fn relay_url(&self) -> Option<String> {
        let project = self.project_id.as_ref()?;
        let seed = self.client_seed.as_ref()?;
        let mut sub = [0_u8; 32];
        yw_core::entropy::fill_random(&mut sub).ok()?;
        let jwt = yw_core::walletconnect::relay_auth_jwt(
            seed,
            &hex(&sub),
            yw_core::walletconnect::RELAY_URL,
            self.now_s(),
            JWT_TTL_S,
        );
        let ua = format!("wc-2/rust-yourwallet-{}/windows", env!("CARGO_PKG_VERSION"));
        Some(format!(
            "https://relay.walletconnect.org/?auth={jwt}&projectId={project}&ua={}",
            percent_encode(&ua)
        ))
    }

    fn connect(&mut self, now: u64) {
        let Some(url) = self.relay_url() else {
            return;
        };
        self.set_status(RelayStatus::Connecting);
        match self.connector.connect(&url) {
            Ok(link) => {
                self.generation = self.generation.wrapping_add(1);
                let generation = self.generation;
                let reader = Arc::clone(&link);
                let tx = self.tx.clone();
                let spawned = std::thread::Builder::new()
                    .name("yw-wc-read".to_owned())
                    .spawn(move || {
                        while let Some(text) = reader.receive() {
                            if tx.send(Input::Relay(generation, text)).is_err() {
                                return;
                            }
                        }
                        let _ = tx.send(Input::Closed(generation));
                    });
                if spawned.is_err() {
                    link.abort();
                    self.next_attempt_ms = now.saturating_add(self.backoff_ms);
                    return;
                }
                self.link = Some(link);
                self.backoff_ms = BACKOFF_MIN_MS;
                self.subscribed.clear();
                logging::info("walletconnect", "relay.connected", &[]);
                self.set_status(RelayStatus::Connected);
                for topic in self.engine.topics() {
                    self.subscribe(topic);
                }
                for publish in core::mem::take(&mut self.queued) {
                    self.send_publish(&publish);
                }
            }
            Err(ConnectError::Unauthorized(code)) => {
                logging::warn(
                    "walletconnect",
                    "relay.unauthorized",
                    &[("code", Field::Num(u64::from(code)))],
                );
                self.next_attempt_ms = now.saturating_add(AUTH_RETRY_MS);
                self.set_status(RelayStatus::Unauthorized(code));
            }
            Err(ConnectError::Network) => {
                logging::info("walletconnect", "relay.failed", &[]);
                self.next_attempt_ms = now.saturating_add(self.backoff_ms);
                self.backoff_ms = (self.backoff_ms * 2).min(BACKOFF_MAX_MS);
                self.set_status(RelayStatus::Offline);
            }
        }
    }

    fn closed(&mut self) {
        self.link = None;
        self.subscribed.clear();
        let now = self.now_ms();
        self.next_attempt_ms = now.saturating_add(self.backoff_ms);
        self.backoff_ms = (self.backoff_ms * 2).min(BACKOFF_MAX_MS);
        logging::info("walletconnect", "relay.closed", &[]);
        self.set_status(RelayStatus::Offline);
    }

    fn next_id(&mut self) -> u64 {
        self.counter = self.counter.wrapping_add(1);
        super::engine::new_id(self.now_ms()).wrapping_add(self.counter)
    }

    fn send_rpc(&mut self, method: &str, params: Value, call: RelayCall) -> bool {
        let Some(link) = self.link.clone() else {
            return false;
        };
        let id = self.next_id();
        let text = yw_json::to_vec(&json_object(vec![
            ("id", json_u64(id)),
            ("jsonrpc", json_str("2.0")),
            ("method", json_str(method)),
            ("params", params),
        ]));
        let Ok(text) = String::from_utf8(text) else {
            return false;
        };
        self.calls.insert(id, call);
        if self.calls.len() > 1_024 {
            self.calls.clear();
        }
        link.send(&text)
    }

    fn subscribe(&mut self, topic: [u8; 32]) {
        if self.subscribed.contains_key(&topic) {
            return;
        }
        let params = json_object(vec![("topic", json_str(&hex(&topic)))]);
        let _ = self.send_rpc("irn_subscribe", params, RelayCall::Subscribe(topic));
    }

    fn unsubscribe(&mut self, topic: [u8; 32]) {
        if let Some(id) = self.subscribed.remove(&topic) {
            let params = json_object(vec![
                ("topic", json_str(&hex(&topic))),
                ("id", json_str(&id)),
            ]);
            let _ = self.send_rpc("irn_unsubscribe", params, RelayCall::Other);
        }
    }

    fn send_publish(&mut self, publish: &Publish) {
        let params = json_object(vec![
            ("topic", json_str(&hex(&publish.topic))),
            ("message", json_str(&publish.message)),
            ("ttl", json_u64(u64::from(publish.ttl))),
            ("tag", json_u64(u64::from(publish.tag))),
        ]);
        if self.send_rpc("irn_publish", params, RelayCall::Other) {
            if publish.tag == SETTLE_TAG {
                // The settle is on its way (not just queued while offline): the wait for the
                // dApp's confirmation starts now.
                let now = self.now_s();
                self.engine.settle_reachable(&publish.topic, now);
            }
        } else if self.queued.len() < MAX_QUEUED {
            self.queued.push(publish.clone());
        }
    }

    fn relay(&mut self, text: &str) {
        let Ok(value) = yw_json::parse(text.as_bytes(), &RELAY_LIMITS) else {
            return;
        };
        let Some(object) = value.as_object() else {
            return;
        };
        let method = object.get("method").and_then(Value::as_str);
        if method == Some("irn_subscription") {
            if let (Some(id), Some(link)) = (object.get("id"), self.link.clone()) {
                let ack = yw_json::to_vec(&json_object(vec![
                    ("id", id.clone()),
                    ("jsonrpc", json_str("2.0")),
                    ("result", Value::Bool(true)),
                ]));
                if let Ok(ack) = String::from_utf8(ack) {
                    let _ = link.send(&ack);
                }
            }
            let data = object
                .get("params")
                .and_then(Value::as_object)
                .and_then(|p| p.get("data"))
                .and_then(Value::as_object);
            let topic = data
                .and_then(|d| d.get("topic"))
                .and_then(Value::as_str)
                .and_then(|t| yw_core::hex::decode_array::<32>(t).ok());
            let message = data.and_then(|d| d.get("message")).and_then(Value::as_str);
            let attestation = data
                .and_then(|d| d.get("attestation"))
                .and_then(Value::as_str);
            if let (Some(topic), Some(message)) = (topic, message) {
                let now = self.now_s();
                let outs = self.engine.on_message(&topic, message, attestation, now);
                self.apply(outs);
            }
            return;
        }
        // A response to one of our calls.
        let Some(id) = object
            .get("id")
            .and_then(Value::as_number)
            .and_then(yw_json::Number::as_u64)
        else {
            return;
        };
        match (self.calls.remove(&id), object.get("result")) {
            (Some(RelayCall::Subscribe(topic)), Some(result)) => {
                let subscription = result.as_str().unwrap_or("").to_owned();
                self.subscribed.insert(topic, subscription);
                // A restored session the dApp had not confirmed can hear it from now on.
                let now = self.now_s();
                self.engine.settle_reachable(&topic, now);
            }
            (Some(_), None) => {
                logging::info("walletconnect", "relay.rpc_error", &[]);
            }
            _ => {}
        }
    }

    // ----- engine outputs --------------------------------------------------------------

    fn apply(&mut self, outs: Vec<Out>) {
        for out in outs {
            match out {
                Out::Subscribe(topic) => self.subscribe(topic),
                Out::Unsubscribe(topic) => self.unsubscribe(topic),
                Out::Publish(publish) => self.send_publish(&publish),
                Out::Proposal(view, input) => self.proposal(*view, &input),
                Out::Request(request) => self.request(&request),
                Out::SessionsChanged => self.push_sessions(),
                Out::Ended(topic) => {
                    if let Some(origin) = session_origin(&topic) {
                        self.sink.push(WcEvent::Ended(origin));
                    }
                }
                Out::Notice(notice) => {
                    let wallet = self.core.wallet();
                    let ids: &[u64] = match &notice {
                        Notice::MissingChains { chains, .. } | Notice::NoChains(chains) => chains,
                        _ => &[],
                    };
                    let labels = ids
                        .iter()
                        .filter_map(|id| {
                            wallet
                                .chains
                                .iter()
                                .find(|entry| entry.info.chain_id == *id)
                                .map(|entry| (*id, format!("{} (eip155:{id})", entry.info.name)))
                        })
                        .collect();
                    self.sink
                        .push(WcEvent::Notice(WcNotice::Engine(notice, labels)));
                }
            }
        }
    }

    fn push_sessions(&self) {
        let views = self
            .engine
            .sessions()
            .iter()
            .filter_map(|session| {
                Some(SessionView {
                    topic: session.topic,
                    origin: session_origin(&session.topic)?,
                    peer: session.peer.clone(),
                    verify: session.verify,
                    accounts: session.accounts.clone(),
                    chains: session.chains.clone(),
                    expiry: session.expiry,
                    created: session.created,
                    acknowledged: session.acknowledged,
                })
            })
            .collect();
        let store = WcStore {
            client_seed: self.client_seed.clone(),
            sessions: self.engine.sessions().to_vec(),
        };
        self.sink.push(WcEvent::Sessions(views, Box::new(store)));
    }

    fn proposal(&mut self, mut view: ProposalView, input: &super::engine::VerifyInput) {
        let now = self.now_s();
        let status = self.http.as_ref().map_or(VerifyStatus::Unknown, |http| {
            super::verify::resolve(&**http, &mut self.verify_key, input, &view.peer.url, now)
        });
        self.engine.set_verify(&view.session_topic, status);
        view.verify = status;
        let Some(origin) = session_origin(&view.session_topic) else {
            return;
        };
        logging::info(
            "walletconnect",
            "proposal",
            &[("verify", Field::Word(status.as_str()))],
        );
        self.sink.push(WcEvent::Proposal(Box::new(view.clone())));
        let deadline = view.expiry.saturating_mul(1_000).min(
            self.core
                .clock()
                .now_unix_ms()
                .saturating_add(INTERACTIVE_DEADLINE_MS),
        );
        // The session origin starts on the first offered chain.
        let Some(first) = view.chains.first().copied() else {
            return;
        };
        self.submit(
            origin.clone(),
            view.session_topic,
            (Method::RequestAccounts, Value::Array(Vec::new()), first),
            deadline,
            Waiting::Connect {
                proposal: view.session_topic,
                origin,
            },
        );
    }

    /// Hands `(method, params, chain)` to the dispatcher as a request of `origin` running on
    /// `chain` (refused 4901 when that chain is not registered or is blocked by then).
    fn submit(
        &mut self,
        origin: BrowserOrigin,
        activation: [u8; 32],
        (method, params, chain_id): (Method, Value, u64),
        deadline_unix_ms: u64,
        waiting: Waiting,
    ) {
        self.counter = self.counter.wrapping_add(1);
        let mut request_id = [0_u8; 16];
        request_id[8..].copy_from_slice(&self.counter.to_be_bytes());
        request_id[0] = 0x57;
        let correlation = Correlation {
            session_id: SESSION_ID,
            sequence: self.counter,
            activation_nonce: Id32(activation),
            request_id: Id16(request_id),
        };
        self.waiting.insert(request_id, waiting);
        let envelope = RequestEnvelope {
            correlation,
            deadline_unix_ms,
            profile_install_id: Id32([0; 32]),
            method: method.as_str().to_owned(),
            params,
            route: method.route(),
            context: BrowserContext {
                tab_id: 0,
                document_id: "walletconnect".to_owned(),
                origin,
                channel_nonce: Id32(activation),
                compat_mode: None,
            },
        };
        self.core.submit(self.conn, &envelope, chain_id);
    }

    fn cool_down(&mut self, topic: [u8; 32]) {
        let now = self.now_ms();
        self.cooldowns.retain(|_, until| *until > now);
        if self.cooldowns.len() < super::engine::MAX_SESSIONS * 2 {
            self.cooldowns
                .insert(topic, now.saturating_add(REQUEST_COOLDOWN_MS));
        }
    }

    fn cooling(&self, topic: &[u8; 32]) -> bool {
        let now = self.now_ms();
        self.cooldowns.get(topic).is_some_and(|until| *until > now)
    }

    fn answer(&mut self, topic: &[u8; 32], id: u64, result: Result<Value, (i64, String)>) {
        let outs = self.engine.respond(topic, id, result);
        self.apply(outs);
    }

    fn request(&mut self, request: &SessionRequest) {
        let Some(session) = self.engine.session(&request.topic).cloned() else {
            return;
        };
        let Some(origin) = session_origin(&request.topic) else {
            return;
        };
        let unsupported = || (4_200_i64, "Unsupported method.".to_owned());
        match request.method.as_str() {
            "eth_accounts" => {
                // The grant's accounts, like the extension's `eth_accounts`: none while locked
                // (spec/05 §4.4) or once the grant is gone; an account hidden or removed a moment
                // ago is never answered from the session's older list.
                let accounts: Vec<[u8; 20]> = self
                    .core
                    .grants_if_unlocked()
                    .and_then(|grants| grants.into_iter().find(|grant| grant.origin == origin))
                    .map(|grant| grant.accounts.iter().map(|a| *a.as_bytes()).collect())
                    .unwrap_or_default();
                let accounts = crate::browser::envelope::accounts_value(&accounts);
                self.answer(&request.topic, request.id, Ok(accounts));
            }
            "personal_sign" | "eth_signTypedData_v4" | "eth_sendTransaction"
                if self.cooling(&request.topic) =>
            {
                // Rejected or expired a moment ago: no new window yet (spec/13 §7.3).
                let error = ProviderError::UserRejected;
                self.answer(
                    &request.topic,
                    request.id,
                    Err((error.code(), error.message().to_owned())),
                );
            }
            "eth_chainId" => self.answer(
                &request.topic,
                request.id,
                Ok(json_str(&chain_id_hex(request.chain_id))),
            ),
            "wallet_switchEthereumChain" => self.switch_chain(&session, request),
            "personal_sign" | "eth_signTypedData_v4" | "eth_sendTransaction" => {
                let Some(method) = Method::parse(&request.method) else {
                    self.answer(&request.topic, request.id, Err(unsupported()));
                    return;
                };
                // The dApp's own deadline when it sent one (it gives up then: an approval shown
                // later could be answered after the dApp already asked again), at most 10 min.
                let now = self.core.clock().now_unix_ms();
                let longest = now.saturating_add(INTERACTIVE_DEADLINE_MS);
                let deadline = request
                    .expiry
                    .map_or(longest, |expiry| expiry.saturating_mul(1_000).min(longest));
                // Runs on the request's chain or not at all (the dispatcher moves the origin to
                // it under its lock, or refuses 4901).
                self.submit(
                    origin,
                    request.topic,
                    (method, request.params.clone(), request.chain_id),
                    deadline,
                    Waiting::Request {
                        topic: request.topic,
                        id: request.id,
                    },
                );
            }
            _ => self.answer(&request.topic, request.id, Err(unsupported())),
        }
    }

    fn switch_chain(&mut self, session: &Session, request: &SessionRequest) {
        let target = request
            .params
            .as_array()
            .and_then(|p| p.first())
            .and_then(Value::as_object)
            .and_then(|o| o.get("chainId"))
            .and_then(Value::as_str)
            .and_then(|text| text.strip_prefix("0x"))
            .and_then(|digits| u64::from_str_radix(digits, 16).ok());
        let Some(target) = target else {
            let error = ProviderError::InvalidParams;
            self.answer(
                &request.topic,
                request.id,
                Err((error.code(), error.message().to_owned())),
            );
            return;
        };
        let wallet = self.core.wallet();
        let refusal = if !wallet.registered(target) {
            Some(ProviderError::UnrecognizedChain)
        } else if wallet.blocked.contains(&target) {
            Some(ProviderError::ChainUnavailable)
        } else {
            None
        };
        if let Some(error) = refusal {
            self.answer(
                &request.topic,
                request.id,
                Err((error.code(), error.message().to_owned())),
            );
            return;
        }
        let now = self.now_s();
        if !session.chains.contains(&target) {
            let outs = self.engine.update(&request.topic, None, Some(target), now);
            self.apply(outs);
        }
        if let Some(origin) = session_origin(&request.topic) {
            self.core.set_origin_chain(&origin, target);
        }
        self.answer(&request.topic, request.id, Ok(Value::Null));
        let outs = self
            .engine
            .emit(&request.topic, "chainChanged", target, self.now_ms());
        self.apply(outs);
    }

    // ----- dispatcher answers and events -----------------------------------------------

    fn dispatcher(&mut self, outbound: Outbound) {
        match outbound {
            Outbound::Response { correlation, body } => {
                let Some(waiting) = self.waiting.remove(&correlation.request_id.0) else {
                    return;
                };
                match waiting {
                    Waiting::Connect { proposal, origin } => {
                        self.connect_answer(proposal, &origin, &body);
                    }
                    Waiting::Request { topic, id } => {
                        // Ended without an answer (the dApp's own short deadline included):
                        // the session's next requests wait (spec/13 §5.2).
                        if matches!(
                            body,
                            Err(ProviderError::UserRejected
                                | ProviderError::Expired
                                | ProviderError::TimedOut)
                        ) {
                            self.cool_down(topic);
                        }
                        self.refused_while_locked(&body);
                        let result = body.map_err(|e| (e.code(), e.message().to_owned()));
                        self.answer(&topic, id, result);
                    }
                }
            }
            Outbound::Event {
                activation_nonce,
                event,
                ..
            } => self.dispatcher_event(activation_nonce.0, &event),
        }
    }

    /// Whether an error answer came while the wallet is locked (or starting). A 4100 then was
    /// given without any window (none opens for a remote dApp): counted, and reported at the
    /// next unlock.
    fn refused_while_locked(&mut self, body: &Result<Value, ProviderError>) -> bool {
        let Err(error) = body else {
            return false;
        };
        let locked = matches!(
            self.core.wallet().vault,
            VaultView::Locked | VaultView::Starting
        );
        if locked && matches!(error, ProviderError::Unauthorized) {
            self.locked_refusals = self.locked_refusals.saturating_add(1);
        }
        locked
    }

    fn connect_answer(
        &mut self,
        proposal: [u8; 32],
        origin: &BrowserOrigin,
        body: &Result<Value, ProviderError>,
    ) {
        let now = self.now_s();
        // Refused at once while locked, or the shown window closed by the lock.
        let locked = self.refused_while_locked(body);
        let accounts: Option<Vec<Address>> = body.as_ref().ok().and_then(|value| {
            value
                .as_array()?
                .iter()
                .map(|item| parse_address(item.as_str()?).ok())
                .collect()
        });
        // The window answered for exactly this proposal's session origin: anything else never
        // approves (the grant it may have stored goes).
        let accounts = accounts
            .filter(|list| !list.is_empty() && super::topic_of_origin(origin) == Some(proposal));
        let (outs, end) = if let Some(accounts) = accounts {
            let outs = self.engine.approve(&proposal, accounts, now);
            if self.engine.session(&proposal).is_some() {
                self.attach(proposal);
                (outs, ProposalEnd::Connected)
            } else {
                // The proposal expired meanwhile (or no session fits): the grant the window
                // stored goes again.
                self.core.remove_grant(origin);
                self.sink.push(WcEvent::Ended(origin.clone()));
                (outs, ProposalEnd::TooLate)
            }
        } else {
            if body.is_ok() {
                // Accounts for another origin (never expected): undo the stored grant.
                self.core.remove_grant(origin);
            }
            let end = match body {
                Err(_) if locked => ProposalEnd::Locked,
                Err(error) => ProposalEnd::Refused(error.clone()),
                Ok(_) => ProposalEnd::Refused(ProviderError::Internal),
            };
            (self.engine.reject(&proposal, 5_000, "User rejected."), end)
        };
        self.apply(outs);
        self.sink.push(WcEvent::ProposalDone(proposal, end));
    }

    fn dispatcher_event(&mut self, topic: [u8; 32], event: &BrowserEvent) {
        let Some(chains) = self.engine.session(&topic).map(|s| s.chains.clone()) else {
            return;
        };
        match event {
            // The session follows its grant as it is now (read with the vault state under one
            // dispatcher lock): lock empties every grant but keeps the session (requests wait
            // for the unlock); unlocked without the grant, the user disconnected the site; other
            // accounts, one was hidden or removed.
            BrowserEvent::AccountsChanged(_) => self.sync_grants(Some(topic)),
            BrowserEvent::ChainChanged(chain) if chains.contains(chain) => {
                let outs = self
                    .engine
                    .emit(&topic, "chainChanged", *chain, self.now_ms());
                self.apply(outs);
            }
            _ => {}
        }
    }

    /// Refreshes the chains the engine offers (registered and not blocked; called before every
    /// input and tick by the run loop) and, while unlocked, drops chains no longer registered
    /// from the sessions (`wc_sessionUpdate`, or the session ends without a chain left).
    pub fn refresh_chains(&mut self) {
        let wallet = self.core.wallet();
        self.engine.supported_chains = wallet
            .chains
            .iter()
            .map(|entry| entry.info.chain_id)
            .filter(|id| !wallet.blocked.contains(id))
            .collect();
        if wallet.vault == VaultView::Unlocked && !wallet.chains.is_empty() {
            let registered: Vec<u64> = wallet.chains.iter().map(|e| e.info.chain_id).collect();
            let outs = self.engine.prune_chains(&registered, self.now_s());
            self.apply(outs);
        }
    }
}

/// A running worker: its input sender and thread.
#[derive(Debug)]
pub struct WcHandle {
    /// Inputs.
    pub tx: Sender<Input>,
    /// Thread.
    pub thread: Option<std::thread::JoinHandle<()>>,
}

impl WcHandle {
    /// Sends a command (`false` when the worker is gone).
    #[must_use]
    pub fn send(&self, command: WcCommand) -> bool {
        self.tx.send(Input::Command(command)).is_ok()
    }
}

/// Starts the worker thread.
#[must_use]
pub fn start(
    core: Arc<BrowserCore>,
    sink: Arc<dyn WcSink>,
    connector: Box<dyn RelayConnector>,
    http: Option<Box<dyn VerifyHttp + Send>>,
) -> Option<WcHandle> {
    let (worker, tx, rx) = Worker::new(core, sink, connector, http);
    let thread = std::thread::Builder::new()
        .name("yw-walletconnect".to_owned())
        .spawn(move || worker.run(&rx))
        .ok()?;
    Some(WcHandle {
        tx,
        thread: Some(thread),
    })
}
