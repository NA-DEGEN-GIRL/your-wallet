//! The `WalletConnect` worker thread (spec/13 §4–§5): one relay WebSocket (JSON-RPC `irn_*`),
//! the [`Engine`], the Verify check, and the bridge to the browser dispatcher as a virtual
//! connection. Session requests become dispatcher requests of the session's synthetic origin, so
//! they meet the same grants, rate limits, approval queue, risk rules and simulation as the
//! extension — except that a locked wallet refuses them (4100) instead of opening the password
//! window, `eth_accounts` is empty while locked, and a rejected or expired request holds the
//! session's next ones off for [`REQUEST_COOLDOWN_MS`]. Proposals become an
//! `eth_requestAccounts` of the session origin: the connect window's answer approves or rejects.
//!
//! Inputs arrive on one channel: UI commands, relay text frames (from a reader thread per
//! connection), and the dispatcher's answers and events (through [`WcOutlet`]).

use core::fmt::Write as _;
use std::collections::HashMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};

use yw_core::evm::address::{Address, parse_address};
use yw_core::policy::{BrowserOrigin, Method, ProviderError};
use yw_core::secret::Zeroizing;
use yw_json::{Limits, Value};

use super::engine::{Engine, Out, ProposalView, Publish, Session, SessionRequest};
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
/// After a session's signing request was rejected or expired, its next ones are refused (4001)
/// for this long: a dApp cannot keep an approval window — and so the paused idle clock — up
/// continuously (spec/13 §7.3).
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
    pub fn text(&self) -> String {
        match self {
            Self::NoProject => "Reown Project ID가 없어 WalletConnect가 꺼져 있습니다".to_owned(),
            Self::Idle => "대기 중 (연결된 세션 없음)".to_owned(),
            Self::Connecting => "릴레이에 연결하는 중…".to_owned(),
            Self::Connected => "릴레이에 연결됨".to_owned(),
            Self::Unauthorized(code) => format!(
                "릴레이가 Project ID를 거부했습니다 (HTTP {code}) — dashboard.reown.com에서 ID와 허용 출처 설정을 확인하세요"
            ),
            Self::Offline => "릴레이에 연결할 수 없습니다 — 다시 시도하는 중".to_owned(),
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
}

/// Events for the UI thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WcEvent {
    /// Relay state.
    Status(RelayStatus),
    /// A verified proposal (its connect request follows on the dispatcher).
    Proposal(Box<ProposalView>),
    /// The proposal of this session topic finished (approved, rejected or expired).
    ProposalDone([u8; 32]),
    /// The session list and the state to persist in meta.
    Sessions(Vec<SessionView>, Box<WcStore>),
    /// A session ended: the UI removes its grant and its waiting requests.
    Ended(BrowserOrigin),
    /// A message for the `WalletConnect` panel (pairing errors etc.).
    Notice(String),
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
    /// rejected or expired).
    cooldowns: HashMap<[u8; 32], u64>,
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
            self.refresh_chains();
            match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(Input::Command(WcCommand::Shutdown)) | Err(RecvTimeoutError::Disconnected) => {
                    break;
                }
                Ok(input) => self.handle(input),
                Err(RecvTimeoutError::Timeout) => {}
            }
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
                }
                // Grants of sessions that no longer exist (deleted while locked) are pruned by
                // the UI from this snapshot.
                self.push_sessions();
            }
            WcCommand::Pair(text) => self.pair(&text),
            WcCommand::Disconnect(topic) => {
                let now = self.now_s();
                let outs = self.engine.disconnect(&topic, now);
                self.apply(outs);
            }
            WcCommand::Shutdown => {}
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
                self.sink.push(WcEvent::Notice(error.message().to_owned()));
                return;
            }
        };
        if self.project_id.is_none() {
            self.sink.push(WcEvent::Notice(
                "먼저 Reown Project ID를 저장하세요 (아래 설정).".to_owned(),
            ));
            return;
        }
        if !self.loaded || self.client_seed.is_none() {
            self.sink.push(WcEvent::Notice(
                "지갑 잠금을 해제한 뒤 다시 시도하세요.".to_owned(),
            ));
            return;
        }
        let now = self.now_s();
        if uri.expired(now) {
            self.sink.push(WcEvent::Notice(
                "연결 주소가 만료되었습니다. dApp에서 새 WalletConnect 주소를 받으세요.".to_owned(),
            ));
            return;
        }
        let outs = self.engine.pair(&uri, now);
        self.apply(outs);
        self.sink.push(WcEvent::Notice(
            "dApp의 연결 요청을 기다리는 중입니다…".to_owned(),
        ));
    }

    fn supported_chains(&self) -> Vec<u64> {
        let wallet = self.core.wallet();
        wallet
            .chains
            .iter()
            .map(|entry| entry.info.chain_id)
            .filter(|id| !wallet.blocked.contains(id))
            .collect()
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
        if !self.send_rpc("irn_publish", params, RelayCall::Other) && self.queued.len() < MAX_QUEUED
        {
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
        if let Some(first) = view.chains.first() {
            self.core.set_origin_chain(&origin, *first);
        }
        self.submit(
            origin.clone(),
            view.session_topic,
            Method::RequestAccounts,
            Value::Array(Vec::new()),
            deadline,
            Waiting::Connect {
                proposal: view.session_topic,
                origin,
            },
        );
    }

    fn submit(
        &mut self,
        origin: BrowserOrigin,
        activation: [u8; 32],
        method: Method,
        params: Value,
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
        self.core.submit(self.conn, &envelope);
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
                // Locked: no accounts, like a locked extension provider (spec/05 §4.4).
                let accounts: Vec<[u8; 20]> = if self.core.wallet().vault == VaultView::Unlocked {
                    session.accounts.iter().map(|a| *a.as_bytes()).collect()
                } else {
                    Vec::new()
                };
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
                self.core.set_origin_chain(&origin, request.chain_id);
                let now = self.core.clock().now_unix_ms();
                let deadline = request
                    .expiry
                    .map_or(now.saturating_add(INTERACTIVE_DEADLINE_MS), |expiry| {
                        expiry.saturating_mul(1_000)
                    });
                self.submit(
                    origin,
                    request.topic,
                    method,
                    request.params.clone(),
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
                        if matches!(
                            body,
                            Err(ProviderError::UserRejected | ProviderError::Expired)
                        ) {
                            self.cool_down(topic);
                        }
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

    fn connect_answer(
        &mut self,
        proposal: [u8; 32],
        origin: &BrowserOrigin,
        body: &Result<Value, ProviderError>,
    ) {
        let now = self.now_s();
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
        let outs = if let Some(accounts) = accounts {
            let outs = self.engine.approve(&proposal, accounts, now);
            if outs.is_empty() {
                // The proposal expired meanwhile: the grant the window stored goes again.
                self.core.remove_grant(origin);
                self.sink.push(WcEvent::Ended(origin.clone()));
            }
            outs
        } else {
            if body.is_ok() {
                // Accounts for another origin (never expected): undo the stored grant.
                self.core.remove_grant(origin);
            }
            self.engine.reject(&proposal, 5_000, "User rejected.")
        };
        self.apply(outs);
        self.sink.push(WcEvent::ProposalDone(proposal));
    }

    fn dispatcher_event(&mut self, topic: [u8; 32], event: &BrowserEvent) {
        let Some(session) = self.engine.session(&topic).cloned() else {
            return;
        };
        let now = self.now_s();
        match event {
            BrowserEvent::AccountsChanged(list) if list.is_empty() => {
                // Lock empties every grant (the session stays, requests wait for the unlock);
                // an unlocked wallet without the grant means the user disconnected the site.
                let unlocked = self.core.wallet().vault == VaultView::Unlocked;
                let granted = session_origin(&topic)
                    .is_some_and(|origin| self.core.grants().iter().any(|g| g.origin == origin));
                if unlocked && !granted {
                    let outs = self.engine.disconnect(&topic, now);
                    self.apply(outs);
                }
            }
            BrowserEvent::AccountsChanged(list) => {
                let accounts: Vec<Address> = list.iter().map(|b| Address::from_bytes(*b)).collect();
                if accounts != session.accounts {
                    let outs = self.engine.update(&topic, Some(accounts), None, now);
                    self.apply(outs);
                    if let Some(chain) = session.chains.first() {
                        let outs =
                            self.engine
                                .emit(&topic, "accountsChanged", *chain, self.now_ms());
                        self.apply(outs);
                    }
                }
            }
            BrowserEvent::ChainChanged(chain) if session.chains.contains(chain) => {
                let outs = self
                    .engine
                    .emit(&topic, "chainChanged", *chain, self.now_ms());
                self.apply(outs);
            }
            _ => {}
        }
    }

    /// Refreshes the chains the engine offers (called on every input by the run loop's user).
    pub fn refresh_chains(&mut self) {
        self.engine.supported_chains = self.supported_chains();
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
