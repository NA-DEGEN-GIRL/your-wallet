//! The `WalletConnect` Sign v2 wallet engine (spec/13 §3–§5): pairings, proposals, sessions and
//! the client-to-client JSON-RPC of `clients/sign/rpc-methods.md` over typed envelopes. Pure: no
//! I/O, no clock (callers pass Unix seconds); the only OS call is the CSPRNG for keys, nonces and
//! ids. The worker ([`super::worker`]) moves [`Out::Publish`]/[`Out::Subscribe`] to the relay and
//! the other outputs to the dispatcher and the UI.
//!
//! Tags and TTLs (`ENGINE_RPC_OPTS` of the reference sign-client): propose response 1101 /
//! reject 1120 (300 s), settle 1102 (300 s), update 1104 and extend 1106 (86,400 s), request
//! response 1109 (300 s; 900 s used by the SDK), event 1110 (300 s), delete 1112 (86,400 s),
//! ping response 1115 (30 s), pairing ping response 1003 and delete response 1001.

use std::collections::VecDeque;

use yw_core::evm::address::Address;
use yw_core::walletconnect::{
    Envelope, X25519Secret, derive_sym_key, open_envelope, seal_envelope, topic_of,
};
use yw_json::{Limits, Value};
use yw_core::secret::Zeroizing;

use super::{Metadata, VerifyStatus, chain_caip2, parse_caip2};
use crate::text::{json_object, json_str, json_u64};

/// Session lifetime (`SESSION_EXPIRY` = 7 days).
pub const SESSION_TTL_S: u64 = 7 * 86_400;
/// A session is extended when less than this is left and the dApp is active.
pub const EXTEND_WHEN_LEFT_S: u64 = 2 * 86_400;
/// Proposals the engine keeps (oldest dropped).
pub const MAX_PROPOSALS: usize = 8;
/// Sessions (the connected-sites bound is shared with browser grants).
pub const MAX_SESSIONS: usize = 64;
/// Methods the wallet serves (spec/13 §5); anything else in a request is answered 4200.
pub const WALLET_METHODS: [&str; 6] = [
    "eth_accounts",
    "eth_chainId",
    "personal_sign",
    "eth_signTypedData_v4",
    "eth_sendTransaction",
    "wallet_switchEthereumChain",
];
/// Events the wallet emits.
pub const WALLET_EVENTS: [&str; 2] = ["chainChanged", "accountsChanged"];
const RECENT_IDS: usize = 512;

const LIMITS: Limits = Limits {
    max_bytes: 1_048_576,
    max_depth: 32,
    max_nodes: 65_536,
    max_items: 32_768,
};

/// One relay publish.
#[derive(Clone, PartialEq, Eq)]
pub struct Publish {
    /// Topic.
    pub topic: [u8; 32],
    /// Envelope (base64).
    pub message: String,
    /// IRN tag.
    pub tag: u32,
    /// IRN TTL (seconds).
    pub ttl: u32,
}

impl core::fmt::Debug for Publish {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "Publish(tag {})", self.tag)
    }
}

/// A pending session proposal as shown to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalView {
    /// JSON-RPC id of `wc_sessionPropose`.
    pub id: u64,
    /// The session topic the approval will create (known before approval: our key is chosen).
    pub session_topic: [u8; 32],
    /// Self-claimed dApp metadata.
    pub peer: Metadata,
    /// Chains that will be approved (required ∪ supported optional), in request order.
    pub chains: Vec<u64>,
    /// Required chains this wallet does not have (non-empty: the proposal is refused 5100).
    pub missing_required: Vec<String>,
    /// Required methods outside [`WALLET_METHODS`] (granted in the namespace but answered 4200).
    pub unsupported_methods: Vec<String>,
    /// Verify result.
    pub verify: VerifyStatus,
    /// Proposal expiry (Unix s).
    pub expiry: u64,
}

/// What the worker needs to run the Verify check of a proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyInput {
    /// The relay message's `attestation` (a Verify v3 JWT), if any.
    pub attestation: Option<String>,
    /// `sha256(decrypted JSON)` hex (the v2 attestation id).
    pub hash: String,
    /// `sha256(encrypted message)` hex (the v3 JWT `id`).
    pub encrypted_id: String,
}

/// An incoming `wc_sessionRequest`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRequest {
    /// Session topic.
    pub topic: [u8; 32],
    /// JSON-RPC id.
    pub id: u64,
    /// `chainId` (eip155 reference).
    pub chain_id: u64,
    /// Method.
    pub method: String,
    /// Params.
    pub params: Value,
    /// `request.expiry` (Unix s), if set.
    pub expiry: Option<u64>,
}

/// Engine output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Out {
    /// Subscribe a topic.
    Subscribe([u8; 32]),
    /// Unsubscribe a topic.
    Unsubscribe([u8; 32]),
    /// Publish a message.
    Publish(Publish),
    /// A new proposal (to verify, then show).
    Proposal(Box<ProposalView>, VerifyInput),
    /// A session request for the wallet.
    Request(Box<SessionRequest>),
    /// The settled session list changed (persist it).
    SessionsChanged,
    /// A session ended (peer delete, expiry or our disconnect).
    Ended([u8; 32]),
}

/// A settled (or settling) session.
#[derive(Clone, PartialEq, Eq)]
pub struct Session {
    /// Topic.
    pub topic: [u8; 32],
    /// Symmetric key.
    pub sym_key: Zeroizing<[u8; 32]>,
    /// The dApp's X25519 public key.
    pub peer_public: [u8; 32],
    /// Self-claimed dApp metadata.
    pub peer: Metadata,
    /// Granted accounts (all on every chain).
    pub accounts: Vec<Address>,
    /// Granted chains.
    pub chains: Vec<u64>,
    /// Granted methods.
    pub methods: Vec<String>,
    /// Granted events.
    pub events: Vec<String>,
    /// Expiry (Unix s).
    pub expiry: u64,
    /// Settle acknowledged by the dApp.
    pub acknowledged: bool,
    /// Verify result at connect time.
    pub verify: VerifyStatus,
    /// When approved (Unix s).
    pub created: u64,
}

impl core::fmt::Debug for Session {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("Session([REDACTED])")
    }
}

impl Session {
    /// The `eip155` session namespace.
    #[must_use]
    pub fn namespaces(&self) -> Value {
        let accounts: Vec<Value> = self
            .chains
            .iter()
            .flat_map(|chain| {
                self.accounts.iter().map(move |account| {
                    json_str(&format!(
                        "{}:0x{}",
                        chain_caip2(*chain),
                        yw_core::hex::encode(account.as_bytes())
                    ))
                })
            })
            .collect();
        json_object(vec![(
            "eip155",
            json_object(vec![
                (
                    "chains",
                    Value::Array(self.chains.iter().map(|c| json_str(&chain_caip2(*c))).collect()),
                ),
                ("accounts", Value::Array(accounts)),
                (
                    "methods",
                    Value::Array(self.methods.iter().map(|m| json_str(m)).collect()),
                ),
                (
                    "events",
                    Value::Array(self.events.iter().map(|e| json_str(e)).collect()),
                ),
            ]),
        )])
    }
}

struct Pairing {
    topic: [u8; 32],
    sym_key: Zeroizing<[u8; 32]>,
    expiry: u64,
}

struct Proposal {
    view: ProposalView,
    pairing_topic: [u8; 32],
    proposer_public: [u8; 32],
    secret: X25519Secret,
    sym_key: Zeroizing<[u8; 32]>,
    methods: Vec<String>,
    events: Vec<String>,
}

/// Our metadata in `wc_sessionSettle`.
#[must_use]
pub fn wallet_metadata() -> Value {
    json_object(vec![
        ("name", json_str("Your Wallet")),
        (
            "description",
            json_str("Your Wallet (Windows desktop wallet)"),
        ),
        ("url", json_str("https://localhost")),
        ("icons", Value::Array(Vec::new())),
    ])
}

fn random_bytes<const N: usize>() -> Option<[u8; N]> {
    let mut out = [0_u8; N];
    yw_core::entropy::fill_random(&mut out).ok()?;
    Some(out)
}

/// A JSON-RPC id: Unix ms × 1000 + 3 random digits (the SDK's `payloadId` shape, ≤ 2^53).
#[must_use]
pub fn new_id(now_ms: u64) -> u64 {
    let extra = random_bytes::<2>().map_or(0, |b| u64::from(u16::from_le_bytes(b)) % 1_000);
    now_ms.saturating_mul(1_000).saturating_add(extra)
}

fn error_value(code: i64, message: &str) -> Value {
    json_object(vec![
        (
            "code",
            yw_json::Number::from_literal(&code.to_string()).map_or(Value::Null, Value::Number),
        ),
        ("message", json_str(message)),
    ])
}

fn rpc_request(id: u64, method: &str, params: Value) -> Value {
    json_object(vec![
        ("id", json_u64(id)),
        ("jsonrpc", json_str("2.0")),
        ("method", json_str(method)),
        ("params", params),
    ])
}

fn rpc_result(id: u64, result: Value) -> Value {
    json_object(vec![
        ("id", json_u64(id)),
        ("jsonrpc", json_str("2.0")),
        ("result", result),
    ])
}

fn rpc_error(id: u64, code: i64, message: &str) -> Value {
    json_object(vec![
        ("id", json_u64(id)),
        ("jsonrpc", json_str("2.0")),
        ("error", error_value(code, message)),
    ])
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .filter(|text| text.len() <= 128)
                .map(str::to_owned)
                .take(256)
                .collect()
        })
        .unwrap_or_default()
}

fn push_unique(list: &mut Vec<String>, item: &str) {
    if !list.iter().any(|known| known == item) {
        list.push(item.to_owned());
    }
}

/// The parsed proposal namespaces: eip155 chain references (required, optional), the required
/// non-eip155 chains, and the requested methods and events.
#[derive(Debug, Default)]
struct Requested {
    required: Vec<u64>,
    optional: Vec<u64>,
    foreign_required: Vec<String>,
    bad_required: bool,
    methods: Vec<String>,
    events: Vec<String>,
}

fn read_namespaces(value: Option<&Value>, required: bool, into: &mut Requested) {
    let Some(object) = value.and_then(Value::as_object) else {
        return;
    };
    for (key, namespace) in object.iter() {
        let namespace_object = namespace.as_object();
        let mut chains = strings(namespace_object.and_then(|o| o.get("chains")));
        // `eip155:10` as the key stands for that one chain (namespaces spec 1.3).
        if key.contains(':') {
            chains.push(key.to_owned());
        }
        let is_eip155 = key == "eip155" || key.starts_with("eip155:");
        if !is_eip155 {
            // Solana, Bitcoin and other namespaces are out of scope (spec/13 §9): a required one
            // refuses the proposal, an optional one is left out of the session.
            if required {
                if chains.is_empty() {
                    into.foreign_required.push(key.to_owned());
                } else {
                    into.foreign_required.extend(chains);
                }
            }
            continue;
        }
        for chain in &chains {
            match parse_caip2(chain) {
                Some(id) => {
                    let list = if required {
                        &mut into.required
                    } else {
                        &mut into.optional
                    };
                    if !list.contains(&id) {
                        list.push(id);
                    }
                }
                None if required => into.bad_required = true,
                None => {}
            }
        }
        if required {
            for method in strings(namespace_object.and_then(|o| o.get("methods"))) {
                push_unique(&mut into.methods, &method);
            }
            for event in strings(namespace_object.and_then(|o| o.get("events"))) {
                push_unique(&mut into.events, &event);
            }
        }
    }
}

/// The wallet engine.
pub struct Engine {
    pairings: Vec<Pairing>,
    proposals: Vec<Proposal>,
    sessions: Vec<Session>,
    recent: VecDeque<([u8; 32], u64)>,
    /// The wallet's supported chains (registered EVM chains), set by the worker.
    pub supported_chains: Vec<u64>,
}

impl core::fmt::Debug for Engine {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "Engine({} sessions, {} proposals)",
            self.sessions.len(),
            self.proposals.len()
        )
    }
}

impl Default for Engine {
    fn default() -> Self {
        Self::new()
    }
}

impl Engine {
    /// An empty engine.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pairings: Vec::new(),
            proposals: Vec::new(),
            sessions: Vec::new(),
            recent: VecDeque::new(),
            supported_chains: Vec::new(),
        }
    }

    /// The sessions.
    #[must_use]
    pub fn sessions(&self) -> &[Session] {
        &self.sessions
    }

    /// The session of `topic`.
    #[must_use]
    pub fn session(&self, topic: &[u8; 32]) -> Option<&Session> {
        self.sessions.iter().find(|s| s.topic == *topic)
    }

    /// The pending proposal `id`.
    #[must_use]
    pub fn proposal(&self, id: u64) -> Option<&ProposalView> {
        self.proposals.iter().find(|p| p.view.id == id).map(|p| &p.view)
    }

    /// Every topic the relay connection must be subscribed to.
    #[must_use]
    pub fn topics(&self) -> Vec<[u8; 32]> {
        self.pairings
            .iter()
            .map(|p| p.topic)
            .chain(self.sessions.iter().map(|s| s.topic))
            .collect()
    }

    /// Restores stored sessions (at unlock); expired ones are dropped.
    pub fn restore(&mut self, sessions: Vec<Session>, now: u64) -> Vec<Out> {
        let mut out = Vec::new();
        for session in sessions {
            if session.expiry > now
                && !self.sessions.iter().any(|known| known.topic == session.topic)
                && self.sessions.len() < MAX_SESSIONS
            {
                out.push(Out::Subscribe(session.topic));
                self.sessions.push(session);
            }
        }
        out
    }

    /// `pair(uri)`: remembers the pairing key and subscribes its topic; the proposal arrives as a
    /// relay message.
    pub fn pair(&mut self, uri: &yw_core::walletconnect::PairingUri, now: u64) -> Vec<Out> {
        self.pairings.retain(|p| p.topic != uri.topic && p.expiry > now);
        if self.pairings.len() >= MAX_PROPOSALS {
            self.pairings.remove(0);
        }
        self.pairings.push(Pairing {
            topic: uri.topic,
            sym_key: uri.sym_key.clone(),
            expiry: uri.expiry.unwrap_or(now + 300).max(now + 60),
        });
        vec![Out::Subscribe(uri.topic)]
    }

    fn key_of(&self, topic: &[u8; 32]) -> Option<Zeroizing<[u8; 32]>> {
        self.sessions
            .iter()
            .find(|s| s.topic == *topic)
            .map(|s| s.sym_key.clone())
            .or_else(|| {
                self.pairings
                    .iter()
                    .find(|p| p.topic == *topic)
                    .map(|p| p.sym_key.clone())
            })
    }

    fn publish(&self, topic: [u8; 32], value: &Value, tag: u32, ttl: u32) -> Option<Out> {
        let key = self.key_of(&topic)?;
        let iv = random_bytes::<12>()?;
        let message = seal_envelope(&key, &iv, &yw_json::to_vec(value), None)?;
        Some(Out::Publish(Publish {
            topic,
            message,
            tag,
            ttl,
        }))
    }

    /// A relay message on `topic` (`message` = base64 envelope).
    pub fn on_message(
        &mut self,
        topic: &[u8; 32],
        message: &str,
        attestation: Option<&str>,
        now: u64,
    ) -> Vec<Out> {
        let Some(key) = self.key_of(topic) else {
            return Vec::new();
        };
        let Some(Envelope::Type0 { iv, sealed }) = Envelope::decode(message) else {
            return Vec::new();
        };
        let Some(plain) = open_envelope(&key, &Envelope::Type0 { iv, sealed }) else {
            return Vec::new();
        };
        let Ok(value) = yw_json::parse(&plain, &LIMITS) else {
            return Vec::new();
        };
        let Some(object) = value.as_object() else {
            return Vec::new();
        };
        let Some(id) = object
            .get("id")
            .and_then(Value::as_number)
            .and_then(yw_json::Number::as_u64)
        else {
            return Vec::new();
        };
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            // A response to one of ours.
            if object.get("result").is_some()
                && let Some(session) = self.sessions.iter_mut().find(|s| s.topic == *topic)
                && !session.acknowledged
            {
                session.acknowledged = true;
                return vec![Out::SessionsChanged];
            }
            return Vec::new();
        };
        // At-least-once delivery: a request seen before is not handled twice.
        if self.recent.contains(&(*topic, id)) {
            return Vec::new();
        }
        if self.recent.len() >= RECENT_IDS {
            self.recent.pop_front();
        }
        self.recent.push_back((*topic, id));
        let params = object.get("params").cloned().unwrap_or(Value::Null);
        let hash = yw_core::hex::encode(&yw_core::codec::sha256(&plain));
        let encrypted_id = yw_core::hex::encode(&yw_core::codec::sha256(message.as_bytes()));
        let is_session = self.sessions.iter().any(|s| s.topic == *topic);
        match method {
            "wc_sessionPropose" if !is_session => {
                let verify = VerifyInput {
                    attestation: attestation.filter(|a| !a.is_empty()).map(str::to_owned),
                    hash,
                    encrypted_id,
                };
                self.on_propose(*topic, id, &params, verify, now)
            }
            "wc_sessionRequest" if is_session => self.on_request(*topic, id, &params, now),
            "wc_sessionPing" => self
                .publish(*topic, &rpc_result(id, Value::Bool(true)), 1115, 30)
                .into_iter()
                .collect(),
            "wc_pairingPing" => self
                .publish(*topic, &rpc_result(id, Value::Bool(true)), 1003, 30)
                .into_iter()
                .collect(),
            "wc_sessionDelete" if is_session => {
                let mut out: Vec<Out> = self
                    .publish(*topic, &rpc_result(id, Value::Bool(true)), 1113, 86_400)
                    .into_iter()
                    .collect();
                out.extend(self.drop_session(topic));
                out
            }
            "wc_pairingDelete" => {
                let out: Vec<Out> = self
                    .publish(*topic, &rpc_result(id, Value::Bool(true)), 1001, 86_400)
                    .into_iter()
                    .collect();
                self.pairings.retain(|p| p.topic != *topic);
                let mut out = out;
                out.push(Out::Unsubscribe(*topic));
                out
            }
            // One-click auth (`wc_sessionAuthenticate`) is not supported: no answer, the dApp falls
            // back to its proposal (spec/13 §9); unknown methods are ignored the same way.
            // Only the controller (this wallet) may update or extend; events go wallet → dApp.
            "wc_sessionUpdate" | "wc_sessionExtend" | "wc_sessionEvent" if is_session => self
                .publish(*topic, &rpc_error(id, 3003, "Unauthorized update request"), 1105, 86_400)
                .into_iter()
                .collect(),
            _ => Vec::new(),
        }
    }

    #[expect(clippy::too_many_lines, reason = "the proposal checks of the namespaces spec in order")]
    fn on_propose(
        &mut self,
        pairing_topic: [u8; 32],
        id: u64,
        params: &Value,
        verify: VerifyInput,
        now: u64,
    ) -> Vec<Out> {
        let reject = |engine: &Self, code: i64, message: &str| -> Vec<Out> {
            engine
                .publish(pairing_topic, &rpc_error(id, code, message), 1120, 300)
                .into_iter()
                .collect()
        };
        let Some(object) = params.as_object() else {
            return reject(self, 1006, "Invalid proposal namespaces");
        };
        let proposer = object.get("proposer").and_then(Value::as_object);
        let Some(proposer_public) = proposer
            .and_then(|p| p.get("publicKey"))
            .and_then(Value::as_str)
            .and_then(|text| yw_core::hex::decode_array::<32>(&text.to_ascii_lowercase()).ok())
        else {
            return reject(self, 1006, "Invalid proposer");
        };
        let relay_ok = object
            .get("relays")
            .and_then(Value::as_array)
            .is_none_or(|relays| {
                relays.iter().any(|relay| {
                    relay
                        .as_object()
                        .and_then(|r| r.get("protocol"))
                        .and_then(Value::as_str)
                        == Some(yw_core::walletconnect::RELAY_PROTOCOL)
                })
            });
        if !relay_ok {
            return reject(self, 5100, "Unsupported relay protocol");
        }
        let peer = Metadata::from_value(proposer.and_then(|p| p.get("metadata")));
        let mut requested = Requested::default();
        read_namespaces(object.get("requiredNamespaces"), true, &mut requested);
        read_namespaces(object.get("optionalNamespaces"), false, &mut requested);
        if requested.bad_required {
            return reject(self, 5100, "Chains must be CAIP-2 compliant");
        }
        let mut missing: Vec<String> = requested.foreign_required.clone();
        for chain in &requested.required {
            if !self.supported_chains.contains(chain) {
                missing.push(chain_caip2(*chain));
            }
        }
        let mut chains: Vec<u64> = requested.required.clone();
        for chain in &requested.optional {
            if self.supported_chains.contains(chain) && !chains.contains(chain) {
                chains.push(*chain);
            }
        }
        if requested.required.is_empty() && requested.optional.is_empty() {
            // No requirements (namespaces spec 1.9): every chain of the wallet.
            chains.clone_from(&self.supported_chains);
        }
        chains.retain(|chain| self.supported_chains.contains(chain));
        let expiry = object
            .get("expiryTimestamp")
            .and_then(Value::as_number)
            .and_then(yw_json::Number::as_u64)
            .unwrap_or(now + 300)
            .min(now + 3_600);
        let mut methods: Vec<String> = WALLET_METHODS.iter().map(|m| (*m).to_owned()).collect();
        let unsupported: Vec<String> = requested
            .methods
            .iter()
            .filter(|m| !WALLET_METHODS.contains(&m.as_str()))
            .cloned()
            .collect();
        for method in &requested.methods {
            push_unique(&mut methods, method);
        }
        let mut events: Vec<String> = WALLET_EVENTS.iter().map(|e| (*e).to_owned()).collect();
        for event in &requested.events {
            push_unique(&mut events, event);
        }
        let Ok(secret) = X25519Secret::generate() else {
            return Vec::new();
        };
        let Some(sym_key) = derive_sym_key(&secret, &proposer_public) else {
            return reject(self, 1006, "Invalid proposer");
        };
        let session_topic = topic_of(&sym_key);
        let view = ProposalView {
            id,
            session_topic,
            peer,
            chains,
            missing_required: missing,
            unsupported_methods: unsupported,
            verify: VerifyStatus::Unknown,
            expiry,
        };
        if !view.missing_required.is_empty() {
            return reject(self, 5100, "Unsupported chains");
        }
        if view.chains.is_empty() {
            return reject(self, 5100, "Unsupported chains");
        }
        if self.proposals.len() >= MAX_PROPOSALS {
            self.proposals.remove(0);
        }
        self.proposals.push(Proposal {
            view: view.clone(),
            pairing_topic,
            proposer_public,
            secret,
            sym_key,
            methods,
            events,
        });
        vec![Out::Proposal(Box::new(view), verify)]
    }

    /// Records the Verify result of a proposal.
    pub fn set_verify(&mut self, id: u64, verify: VerifyStatus) {
        if let Some(proposal) = self.proposals.iter_mut().find(|p| p.view.id == id) {
            proposal.view.verify = verify;
        }
    }

    /// Approves proposal `id` with `accounts` on its chains: the response on the pairing topic,
    /// the subscription and `wc_sessionSettle` on the session topic (spec/13 §3.3).
    pub fn approve(&mut self, id: u64, accounts: Vec<Address>, now: u64) -> Vec<Out> {
        let Some(index) = self.proposals.iter().position(|p| p.view.id == id) else {
            return Vec::new();
        };
        if accounts.is_empty() || self.sessions.len() >= MAX_SESSIONS {
            return self.reject(id, 5000, "User rejected.");
        }
        let proposal = self.proposals.remove(index);
        let session = Session {
            topic: proposal.view.session_topic,
            sym_key: proposal.sym_key.clone(),
            peer_public: proposal.proposer_public,
            peer: proposal.view.peer.clone(),
            accounts,
            chains: proposal.view.chains.clone(),
            methods: proposal.methods.clone(),
            events: proposal.events.clone(),
            expiry: now + SESSION_TTL_S,
            acknowledged: false,
            verify: proposal.view.verify,
            created: now,
        };
        let settle = json_object(vec![
            ("relay", json_object(vec![("protocol", json_str("irn"))])),
            ("namespaces", session.namespaces()),
            (
                "controller",
                json_object(vec![
                    (
                        "publicKey",
                        json_str(&yw_core::hex::encode(&proposal.secret.public())),
                    ),
                    ("metadata", wallet_metadata()),
                ]),
            ),
            ("expiry", json_u64(session.expiry)),
        ]);
        let response = rpc_result(
            id,
            json_object(vec![
                ("relay", json_object(vec![("protocol", json_str("irn"))])),
                (
                    "responderPublicKey",
                    json_str(&yw_core::hex::encode(&proposal.secret.public())),
                ),
            ]),
        );
        let topic = session.topic;
        self.sessions.push(session);
        let mut out = vec![Out::Subscribe(topic)];
        out.extend(self.publish(
            topic,
            &rpc_request(new_id(now * 1_000), "wc_sessionSettle", settle),
            1102,
            300,
        ));
        out.extend(self.publish(proposal.pairing_topic, &response, 1101, 300));
        out.push(Out::SessionsChanged);
        out
    }

    /// Rejects proposal `id` (5000 user rejected, 5100 unsupported chains, …).
    pub fn reject(&mut self, id: u64, code: i64, message: &str) -> Vec<Out> {
        let Some(index) = self.proposals.iter().position(|p| p.view.id == id) else {
            return Vec::new();
        };
        let proposal = self.proposals.remove(index);
        self.publish(proposal.pairing_topic, &rpc_error(id, code, message), 1120, 300)
            .into_iter()
            .collect()
    }

    fn on_request(&mut self, topic: [u8; 32], id: u64, params: &Value, now: u64) -> Vec<Out> {
        let object = params.as_object();
        let request = object
            .and_then(|o| o.get("request"))
            .and_then(Value::as_object);
        let method = request
            .and_then(|r| r.get("method"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let chain = object
            .and_then(|o| o.get("chainId"))
            .and_then(Value::as_str)
            .and_then(parse_caip2);
        let expiry = request
            .and_then(|r| r.get("expiry"))
            .and_then(Value::as_number)
            .and_then(yw_json::Number::as_u64);
        let Some(session) = self.sessions.iter().find(|s| s.topic == topic) else {
            return Vec::new();
        };
        let error = |engine: &Self, code: i64, message: &str| -> Vec<Out> {
            engine
                .publish(topic, &rpc_error(id, code, message), 1109, 300)
                .into_iter()
                .collect()
        };
        if session.expiry <= now {
            return error(self, 7001, "No session for topic");
        }
        let Some(chain_id) = chain.filter(|c| session.chains.contains(c)) else {
            return error(self, 5100, "Unsupported chains");
        };
        if !session.methods.iter().any(|m| m == method) {
            return error(self, 5101, "Unsupported methods");
        }
        if expiry.is_some_and(|expiry| expiry <= now) {
            return error(self, 8000, "Session request expired");
        }
        let params = request
            .and_then(|r| r.get("params"))
            .cloned()
            .unwrap_or(Value::Array(Vec::new()));
        let mut out = Vec::new();
        // An active dApp keeps its session: extend when less than two days are left.
        if session.expiry.saturating_sub(now) < EXTEND_WHEN_LEFT_S {
            out.extend(self.extend(&topic, now));
        }
        out.push(Out::Request(Box::new(SessionRequest {
            topic,
            id,
            chain_id,
            method: method.to_owned(),
            params,
            expiry,
        })));
        out
    }

    /// Answers a session request.
    #[must_use]
    pub fn respond(&self, topic: &[u8; 32], id: u64, result: Result<Value, (i64, String)>) -> Vec<Out> {
        let value = match result {
            Ok(result) => rpc_result(id, result),
            Err((code, message)) => rpc_error(id, code, &message),
        };
        self.publish(*topic, &value, 1109, 300).into_iter().collect()
    }

    /// `wc_sessionEvent` (`chainChanged` data = the chain id number; `accountsChanged` data = the
    /// CAIP-10 accounts of the chain).
    #[must_use]
    pub fn emit(&self, topic: &[u8; 32], name: &str, chain_id: u64, now_ms: u64) -> Vec<Out> {
        let Some(session) = self.session(topic) else {
            return Vec::new();
        };
        let data = match name {
            "chainChanged" => json_u64(chain_id),
            _ => Value::Array(
                session
                    .accounts
                    .iter()
                    .map(|a| {
                        json_str(&format!(
                            "{}:0x{}",
                            chain_caip2(chain_id),
                            yw_core::hex::encode(a.as_bytes())
                        ))
                    })
                    .collect(),
            ),
        };
        let params = json_object(vec![
            (
                "event",
                json_object(vec![("name", json_str(name)), ("data", data)]),
            ),
            ("chainId", json_str(&chain_caip2(chain_id))),
        ]);
        self.publish(*topic, &rpc_request(new_id(now_ms), "wc_sessionEvent", params), 1110, 300)
            .into_iter()
            .collect()
    }

    /// `wc_sessionUpdate` with new accounts and/or chains.
    pub fn update(
        &mut self,
        topic: &[u8; 32],
        accounts: Option<Vec<Address>>,
        add_chain: Option<u64>,
        now: u64,
    ) -> Vec<Out> {
        let Some(session) = self.sessions.iter_mut().find(|s| s.topic == *topic) else {
            return Vec::new();
        };
        if let Some(accounts) = accounts.filter(|a| !a.is_empty()) {
            session.accounts = accounts;
        }
        if let Some(chain) = add_chain
            && !session.chains.contains(&chain)
        {
            session.chains.push(chain);
        }
        let params = json_object(vec![("namespaces", session.namespaces())]);
        let mut out: Vec<Out> = self
            .publish(*topic, &rpc_request(new_id(now * 1_000), "wc_sessionUpdate", params), 1104, 86_400)
            .into_iter()
            .collect();
        out.push(Out::SessionsChanged);
        out
    }

    /// `wc_sessionExtend` to now + 7 days.
    pub fn extend(&mut self, topic: &[u8; 32], now: u64) -> Vec<Out> {
        let Some(session) = self.sessions.iter_mut().find(|s| s.topic == *topic) else {
            return Vec::new();
        };
        session.expiry = now + SESSION_TTL_S;
        let params = json_object(vec![("expiry", json_u64(session.expiry))]);
        let mut out: Vec<Out> = self
            .publish(*topic, &rpc_request(new_id(now * 1_000), "wc_sessionExtend", params), 1106, 86_400)
            .into_iter()
            .collect();
        out.push(Out::SessionsChanged);
        out
    }

    /// Our disconnect: `wc_sessionDelete` (6000 user disconnected), then the session is dropped.
    pub fn disconnect(&mut self, topic: &[u8; 32], now: u64) -> Vec<Out> {
        if self.session(topic).is_none() {
            return Vec::new();
        }
        let params = json_object(vec![
            ("code", json_u64(6_000)),
            ("message", json_str("User disconnected.")),
        ]);
        let mut out: Vec<Out> = self
            .publish(*topic, &rpc_request(new_id(now * 1_000), "wc_sessionDelete", params), 1112, 86_400)
            .into_iter()
            .collect();
        out.extend(self.drop_session(topic));
        out
    }

    fn drop_session(&mut self, topic: &[u8; 32]) -> Vec<Out> {
        let before = self.sessions.len();
        self.sessions.retain(|s| s.topic != *topic);
        if before == self.sessions.len() {
            return Vec::new();
        }
        vec![Out::Unsubscribe(*topic), Out::Ended(*topic), Out::SessionsChanged]
    }

    /// Expiry of sessions, proposals and pairings.
    pub fn tick(&mut self, now: u64) -> Vec<Out> {
        let mut out = Vec::new();
        let expired: Vec<[u8; 32]> = self
            .sessions
            .iter()
            .filter(|s| s.expiry <= now)
            .map(|s| s.topic)
            .collect();
        for topic in expired {
            out.extend(self.drop_session(&topic));
        }
        self.proposals.retain(|p| p.view.expiry > now);
        let gone: Vec<[u8; 32]> = self
            .pairings
            .iter()
            .filter(|p| p.expiry <= now && !self.proposals.iter().any(|q| q.pairing_topic == p.topic))
            .map(|p| p.topic)
            .collect();
        for topic in gone {
            self.pairings.retain(|p| p.topic != topic);
            out.push(Out::Unsubscribe(topic));
        }
        out
    }
}
