//! The dispatcher (spec/05 §6.2, §8.4): per-connection sequence and pending tables, token
//! buckets, the document table and origin-chain cache, immediate permission methods, the read
//! queue and the hand-off of approval-class requests to the UI thread. Grants follow spec/05
//! §4.1–§4.5 (connect, revoke, lock/unlock merges) and chains §4.3 (switching to registered
//! built-in and user chains, 4902 unknown, 4901 blocked).
//!
//! Replaces the archive's synchronous dispatcher (`archive/spec-v2.4:crates/native-host/src/
//! wire.rs:297-578`, lifetime caps and stream-fatal errors) with per-request errors (D23),
//! rate limits and LRU tables (`archive/spec-v2.4:crates/broker/src/lib.rs:390-930` session
//! router, pending/permission stores, without the 4,096 lifetime limit).

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use yw_core::evm::address::Address;
use yw_core::policy::{BrowserOrigin, ConnectedSite, MAX_GRANTS, Method, ProviderError, Route};
use yw_json::Value;

use super::envelope::{
    BrowserEvent, CancelEnvelope, Correlation, EnvelopeError, Id32, Inbound, RequestEnvelope,
    accounts_value, chain_id_hex, parse_inbound,
};
use super::params::{ReadParams, Validated, permission_value, validate};
use super::{
    ConnId, DappEvent, DappSink, GrantChange, INTERACTIVE_DEADLINE_MS, MAX_APPROVALS_GLOBAL,
    MAX_APPROVALS_PER_ORIGIN, MAX_CHAIN_CACHE, MAX_DOCUMENTS, MAX_READS_GLOBAL,
    MAX_READS_PER_DOCUMENT, Outbound, Outlet, RATE_BURST, RATE_PER_DOCUMENT, READ_DEADLINE_MS,
    Reply, RequestKey, SiteKind, SiteRequest, VaultView, WalletView,
};
use crate::flow::evm::Clock;
use crate::logging::{self, Field};

/// A tiny LRU table (≤ 512 entries; linear scans are cheap at that size).
#[derive(Debug)]
struct Lru<K, V> {
    entries: Vec<(K, V, u64)>,
    capacity: usize,
    tick: u64,
}

impl<K: PartialEq + Clone, V> Lru<K, V> {
    const fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::new(),
            capacity,
            tick: 0,
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.saturating_add(1);
        self.tick
    }

    fn get(&mut self, key: &K) -> Option<&V> {
        let tick = self.next_tick();
        let entry = self.entries.iter_mut().find(|(k, _, _)| k == key)?;
        entry.2 = tick;
        Some(&entry.1)
    }

    fn insert(&mut self, key: K, value: V) {
        let tick = self.next_tick();
        if let Some(entry) = self.entries.iter_mut().find(|(k, _, _)| *k == key) {
            entry.1 = value;
            entry.2 = tick;
            return;
        }
        if self.entries.len() >= self.capacity
            && let Some(oldest) = self
                .entries
                .iter()
                .enumerate()
                .min_by_key(|(_, (_, _, stamp))| *stamp)
                .map(|(index, _)| index)
        {
            self.entries.swap_remove(oldest);
        }
        self.entries.push((key, value, tick));
    }

    fn retain(&mut self, keep: impl Fn(&K, &V) -> bool) {
        self.entries.retain(|(key, value, _)| keep(key, value));
    }

    fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.entries.iter().map(|(key, value, _)| (key, value))
    }

    fn iter_mut(&mut self) -> impl Iterator<Item = (&K, &mut V)> {
        self.entries
            .iter_mut()
            .map(|(key, value, _)| (&*key, value))
    }
}

/// A document's token bucket (spec/05 §8.4: 20 tokens/s, capacity and start 40).
#[derive(Clone, Copy, Debug)]
struct Bucket {
    /// Tokens × 1000.
    milli_tokens: u64,
    at_ms: u64,
}

impl Bucket {
    fn full(now_ms: u64) -> Self {
        Self {
            milli_tokens: u64::from(RATE_BURST) * 1_000,
            at_ms: now_ms,
        }
    }

    fn take(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.at_ms);
        let refill = elapsed.saturating_mul(u64::from(RATE_PER_DOCUMENT));
        self.milli_tokens = self
            .milli_tokens
            .saturating_add(refill)
            .min(u64::from(RATE_BURST) * 1_000);
        self.at_ms = now_ms.max(self.at_ms);
        if self.milli_tokens >= 1_000 {
            self.milli_tokens -= 1_000;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Class {
    Read,
    Approval,
}

#[derive(Clone, Copy, Debug)]
struct Pending {
    sequence: u64,
    class: Class,
}

struct Conn {
    outlet: Box<dyn Outlet>,
    max_sequence: u64,
    last_session: Option<Id32>,
    pending: HashMap<(Id32, super::envelope::Id16), Pending>,
    buckets: Lru<Id32, Bucket>,
}

#[derive(Clone, Debug)]
struct ApprovalInfo {
    origin: BrowserOrigin,
    connect: bool,
}

/// A queued read.
#[derive(Clone, Debug)]
pub struct ReadTask {
    /// Where to answer.
    pub reply: Reply,
    /// Document (per-document counters).
    pub document: Id32,
    /// Method.
    pub method: Method,
    /// Normalized params.
    pub params: ReadParams,
    /// The origin chain at request time.
    pub chain_id: u64,
    /// Deadline (monotonic ms).
    pub deadline_ms: u64,
}

struct State {
    conns: HashMap<ConnId, Conn>,
    documents: Lru<Id32, (BrowserOrigin, ConnId)>,
    chain_cache: Lru<BrowserOrigin, u64>,
    wallet: WalletView,
    grants: Vec<ConnectedSite>,
    approvals: HashMap<RequestKey, ApprovalInfo>,
    reads_total: usize,
    reads_per_document: HashMap<Id32, usize>,
    reads: VecDeque<ReadTask>,
    /// Cached `eth_blockNumber` per chain: (value, received at monotonic ms).
    block_numbers: HashMap<u64, (u64, u64)>,
}

/// The shared dispatcher state.
pub struct BrowserCore {
    pinned_id: String,
    state: Mutex<State>,
    reads_ready: Condvar,
    sink: Arc<dyn DappSink>,
    clock: Arc<dyn Clock>,
    next_conn: AtomicU64,
    stopped: AtomicBool,
}

impl core::fmt::Debug for BrowserCore {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BrowserCore")
    }
}

type Answer = Result<Value, ProviderError>;

impl BrowserCore {
    /// A dispatcher for the pinned extension id.
    #[must_use]
    pub fn new(pinned_id: &str, sink: Arc<dyn DappSink>, clock: Arc<dyn Clock>) -> Arc<Self> {
        Arc::new(Self {
            pinned_id: pinned_id.to_owned(),
            state: Mutex::new(State {
                conns: HashMap::new(),
                documents: Lru::new(MAX_DOCUMENTS),
                chain_cache: Lru::new(MAX_CHAIN_CACHE),
                wallet: WalletView::default(),
                grants: Vec::new(),
                approvals: HashMap::new(),
                reads_total: 0,
                reads_per_document: HashMap::new(),
                reads: VecDeque::new(),
                block_numbers: HashMap::new(),
            }),
            reads_ready: Condvar::new(),
            sink,
            clock,
            next_conn: AtomicU64::new(1),
            stopped: AtomicBool::new(false),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The clock (read workers).
    #[must_use]
    pub fn clock(&self) -> &dyn Clock {
        &*self.clock
    }

    /// The UI sink (read workers report chain checks).
    #[must_use]
    pub fn sink(&self) -> &dyn DappSink {
        &*self.sink
    }

    // ----- connections ----------------------------------------------------------------

    /// Registers a connection after its hello.
    pub fn open_connection(&self, outlet: Box<dyn Outlet>) -> ConnId {
        let id = self.next_conn.fetch_add(1, Ordering::Relaxed);
        let count = {
            let mut state = self.lock();
            state.conns.insert(
                id,
                Conn {
                    outlet,
                    max_sequence: 0,
                    last_session: None,
                    pending: HashMap::new(),
                    buckets: Lru::new(MAX_DOCUMENTS),
                },
            );
            state.conns.len()
        };
        let _ = self.sink.push(DappEvent::Connections(count));
        id
    }

    /// A connection ended: its pending approvals are cancelled without a response, its reads'
    /// results are dropped and its documents leave the table (spec/05 §4.8, §8.3).
    pub fn close_connection(&self, conn: ConnId) {
        let (cancelled, count) = {
            let mut state = self.lock();
            state.conns.remove(&conn);
            state.documents.retain(|_, (_, owner)| *owner != conn);
            let keys: Vec<RequestKey> = state
                .approvals
                .keys()
                .filter(|key| key.conn == conn)
                .copied()
                .collect();
            for key in &keys {
                state.approvals.remove(key);
            }
            (keys, state.conns.len())
        };
        for key in cancelled {
            let _ = self.sink.push(DappEvent::Cancel(key));
        }
        let _ = self.sink.push(DappEvent::Connections(count));
    }

    /// Number of live connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.lock().conns.len()
    }

    // ----- responses and events -------------------------------------------------------

    /// Answers a pending request exactly once. Returns `false` when the request is no longer
    /// pending (cancelled, connection gone, already answered): the result is dropped.
    pub fn respond(&self, reply: &Reply, body: Answer) -> bool {
        let mut state = self.lock();
        let key = reply.key();
        state.approvals.remove(&key);
        let Some(conn) = state.conns.get_mut(&reply.conn) else {
            return false;
        };
        let pending_key = (key.activation, key.request);
        match conn.pending.get(&pending_key) {
            Some(pending) if pending.sequence == reply.correlation.sequence => {
                conn.pending.remove(&pending_key);
            }
            _ => return false,
        }
        conn.outlet.send(Outbound::Response {
            correlation: reply.correlation,
            body,
        })
    }

    /// Sends an event to every document of `origin` (spec/05 §4.8).
    pub fn emit(&self, origin: &BrowserOrigin, event: &BrowserEvent) {
        let state = self.lock();
        Self::emit_locked(&state, origin, event);
    }

    fn emit_locked(state: &State, origin: &BrowserOrigin, event: &BrowserEvent) {
        for (activation, (doc_origin, conn_id)) in state.documents.iter() {
            if doc_origin != origin {
                continue;
            }
            let Some(conn) = state.conns.get(conn_id) else {
                continue;
            };
            let Some(session_id) = conn.last_session else {
                continue;
            };
            let _ = conn.outlet.send(Outbound::Event {
                session_id,
                activation_nonce: *activation,
                event: event.clone(),
            });
        }
    }

    fn answer_direct(state: &State, conn: ConnId, correlation: Correlation, body: Answer) {
        if let Some(conn) = state.conns.get(&conn) {
            let _ = conn.outlet.send(Outbound::Response { correlation, body });
        }
    }

    // ----- UI-owned state -------------------------------------------------------------

    /// Replaces the UI-owned view (settings, registry, chain states, vault state).
    pub fn set_wallet(&self, view: WalletView) {
        self.lock().wallet = view;
    }

    /// The current view (tests, UI).
    #[must_use]
    pub fn wallet(&self) -> WalletView {
        self.lock().wallet.clone()
    }

    /// The current grants (empty while locked).
    #[must_use]
    pub fn grants(&self) -> Vec<ConnectedSite> {
        self.lock().grants.clone()
    }

    /// The origin's chain (cache, else the grant's registered chain while unlocked, else
    /// `evmChainId`), inserting it into the cache on first use (spec/05 §4.3).
    fn origin_chain_locked(state: &mut State, origin: &BrowserOrigin) -> u64 {
        if let Some(chain) = state.chain_cache.get(origin) {
            return *chain;
        }
        let chain = state
            .grants
            .iter()
            .find(|site| site.origin == *origin)
            .map(|site| site.chain_id)
            .filter(|chain| state.wallet.registered(*chain))
            .unwrap_or(state.wallet.evm_chain_id);
        state.chain_cache.insert(origin.clone(), chain);
        chain
    }

    /// The origin's chain (see spec/05 §4.3).
    pub fn origin_chain(&self, origin: &BrowserOrigin) -> u64 {
        let mut state = self.lock();
        Self::origin_chain_locked(&mut state, origin)
    }

    /// Wallet locked: grants are forgotten and every connected origin gets
    /// `accountsChanged([])` (spec/05 §4.4).
    pub fn lock_wallet(&self) {
        let mut state = self.lock();
        let origins: Vec<BrowserOrigin> = state.grants.iter().map(|s| s.origin.clone()).collect();
        state.grants.clear();
        for origin in origins {
            Self::emit_locked(&state, &origin, &BrowserEvent::AccountsChanged(Vec::new()));
        }
    }

    /// Wallet unlocked with the meta grants: merges the chain cache (spec/05 §4.3: a cached
    /// chain overrides the grant, else the cache takes the grant's chain; unregistered grant
    /// chains become `evmChainId`) and sends `accountsChanged(accounts)` plus `chainChanged`
    /// where the origin chain changed. Returns the grants whose `chain_id` must be saved.
    pub fn unlock_wallet(&self, grants: Vec<ConnectedSite>) -> Vec<ConnectedSite> {
        let mut state = self.lock();
        let mut changed_grants = Vec::new();
        let mut merged = Vec::with_capacity(grants.len());
        for mut site in grants {
            let cached = state.chain_cache.get(&site.origin).copied();
            let previous_origin_chain = cached;
            let target = match cached {
                Some(chain) => chain,
                None if state.wallet.registered(site.chain_id) => site.chain_id,
                None => state.wallet.evm_chain_id,
            };
            state.chain_cache.insert(site.origin.clone(), target);
            if site.chain_id != target {
                site.chain_id = target;
                changed_grants.push(site.clone());
            }
            let accounts: Vec<[u8; 20]> = site.accounts.iter().map(|a| *a.as_bytes()).collect();
            Self::emit_locked(
                &state,
                &site.origin,
                &BrowserEvent::AccountsChanged(accounts),
            );
            if previous_origin_chain.is_some_and(|chain| chain != target)
                || (previous_origin_chain.is_none() && target != state.wallet.evm_chain_id)
            {
                Self::emit_locked(&state, &site.origin, &BrowserEvent::ChainChanged(target));
            }
            merged.push(site);
        }
        state.grants = merged;
        changed_grants
    }

    /// Connect approved (or grant edited): stores the grant and sends `accountsChanged`.
    pub fn upsert_grant(&self, site: ConnectedSite) {
        let mut state = self.lock();
        let accounts: Vec<[u8; 20]> = site.accounts.iter().map(|a| *a.as_bytes()).collect();
        let origin = site.origin.clone();
        if let Some(existing) = state.grants.iter_mut().find(|s| s.origin == site.origin) {
            *existing = site;
        } else {
            state.grants.push(site);
        }
        Self::emit_locked(&state, &origin, &BrowserEvent::AccountsChanged(accounts));
    }

    /// Disconnect (S13, revoke after unlock): removes the grant and sends `accountsChanged([])`.
    /// Returns whether a grant existed.
    pub fn remove_grant(&self, origin: &BrowserOrigin) -> bool {
        let mut state = self.lock();
        let before = state.grants.len();
        state.grants.retain(|site| site.origin != *origin);
        let removed = state.grants.len() != before;
        if removed {
            Self::emit_locked(&state, origin, &BrowserEvent::AccountsChanged(Vec::new()));
        }
        removed
    }

    /// An account was hidden or deleted: it leaves every grant (empty grants are deleted) and
    /// the affected origins get `accountsChanged` (spec/05 §4.1). Returns the new grant list.
    pub fn remove_account(&self, account: &Address) -> Vec<ConnectedSite> {
        let mut state = self.lock();
        let mut events = Vec::new();
        state.grants.retain_mut(|site| {
            if !site.allows(account) {
                return true;
            }
            let keep = site.remove_account(account);
            let accounts = if keep {
                site.accounts.iter().map(|a| *a.as_bytes()).collect()
            } else {
                Vec::new()
            };
            events.push((site.origin.clone(), accounts));
            keep
        });
        for (origin, accounts) in events {
            Self::emit_locked(&state, &origin, &BrowserEvent::AccountsChanged(accounts));
        }
        state.grants.clone()
    }

    /// A user chain was deleted: origins on it move to `new_default` with `chainChanged`, and
    /// grants on it are rewritten (spec/05 §4.3). Returns the rewritten grants to save.
    pub fn chain_removed(&self, chain_id: u64, new_default: u64) -> Vec<ConnectedSite> {
        let mut state = self.lock();
        let mut moved = Vec::new();
        for (origin, chain) in state.chain_cache.iter_mut() {
            if *chain == chain_id {
                *chain = new_default;
                moved.push(origin.clone());
            }
        }
        let mut rewritten = Vec::new();
        for site in &mut state.grants {
            if site.chain_id == chain_id {
                site.chain_id = new_default;
                rewritten.push(site.clone());
            }
        }
        for origin in moved {
            Self::emit_locked(&state, &origin, &BrowserEvent::ChainChanged(new_default));
        }
        rewritten
    }

    // ----- inbound frames -------------------------------------------------------------

    /// Processes one inbound frame of `conn` (spec/05 §6.2). Never blocks on RPC or the UI.
    pub fn handle_frame(&self, conn: ConnId, frame: &[u8]) {
        let allow_localhost = self.lock().wallet.allow_localhost;
        match parse_inbound(frame, &self.pinned_id, allow_localhost) {
            Err(EnvelopeError::Uncorrelated) => {
                logging::info("browser", "frame.dropped", &[("conn", Field::Num(conn))]);
            }
            Err(EnvelopeError::Invalid(correlation)) => {
                let mut state = self.lock();
                let _ = Self::advance_sequence(&mut state, conn, correlation.sequence);
                Self::log_error("-", &ProviderError::InvalidRequest, conn);
                Self::answer_direct(
                    &state,
                    conn,
                    correlation,
                    Err(ProviderError::InvalidRequest),
                );
            }
            Err(EnvelopeError::LocalhostDisabled(correlation)) => {
                let mut state = self.lock();
                let error = if Self::advance_sequence(&mut state, conn, correlation.sequence) {
                    ProviderError::Unauthorized
                } else {
                    ProviderError::InvalidRequest
                };
                Self::log_error("-", &error, conn);
                Self::answer_direct(&state, conn, correlation, Err(error));
            }
            Ok(Inbound::Cancel(cancel)) => self.cancel(conn, &cancel),
            Ok(Inbound::Request(request)) => self.request(conn, &request),
        }
    }

    fn log_error(method: &'static str, error: &ProviderError, conn: ConnId) {
        logging::info(
            "browser",
            "request.error",
            &[
                ("method", Field::Word(method)),
                ("code", Field::Num(error.code().unsigned_abs())),
                ("conn", Field::Num(conn)),
            ],
        );
    }

    /// spec/05 §6.2-3: `sequence` must exceed the largest seen on this connection.
    fn advance_sequence(state: &mut State, conn: ConnId, sequence: u64) -> bool {
        let Some(conn) = state.conns.get_mut(&conn) else {
            return false;
        };
        if sequence <= conn.max_sequence {
            return false;
        }
        conn.max_sequence = sequence;
        true
    }

    fn cancel(&self, conn: ConnId, cancel: &CancelEnvelope) {
        let approval = {
            let mut state = self.lock();
            if !Self::advance_sequence(&mut state, conn, cancel.sequence) {
                return;
            }
            let Some(entry) = state.conns.get_mut(&conn) else {
                return;
            };
            let key = (cancel.activation_nonce, cancel.request_id);
            match entry.pending.get(&key) {
                Some(pending) if pending.sequence == cancel.request_sequence => {
                    let class = pending.class;
                    entry.pending.remove(&key);
                    let request_key = RequestKey {
                        conn,
                        activation: cancel.activation_nonce,
                        request: cancel.request_id,
                    };
                    state.approvals.remove(&request_key);
                    (class == Class::Approval).then_some(request_key)
                }
                _ => None,
            }
        };
        logging::info("browser", "request.cancel", &[("conn", Field::Num(conn))]);
        if let Some(key) = approval {
            let _ = self.sink.push(DappEvent::Cancel(key));
        }
    }

    #[expect(clippy::too_many_lines, reason = "spec/05 §6.2 steps 3–10 in order")]
    fn request(&self, conn: ConnId, request: &RequestEnvelope) {
        let now = self.clock.now_ms();
        let now_unix = self.clock.now_unix_ms();
        let correlation = request.correlation;
        let reply = Reply { conn, correlation };
        let mut state = self.lock();
        // 3. Sequence.
        if !Self::advance_sequence(&mut state, conn, correlation.sequence) {
            Self::log_error("-", &ProviderError::InvalidRequest, conn);
            Self::answer_direct(
                &state,
                conn,
                correlation,
                Err(ProviderError::InvalidRequest),
            );
            return;
        }
        if let Some(entry) = state.conns.get_mut(&conn) {
            entry.last_session = Some(correlation.session_id);
        }
        // 5. Document table.
        let origin = request.context.origin.clone();
        state
            .documents
            .insert(correlation.activation_nonce, (origin.clone(), conn));
        // 6. Method and route.
        let Some(method) = Method::parse(&request.method) else {
            Self::log_error("-", &ProviderError::UnsupportedMethod, conn);
            Self::answer_direct(
                &state,
                conn,
                correlation,
                Err(ProviderError::UnsupportedMethod),
            );
            return;
        };
        let name = method.as_str();
        let reject = |state: &State, error: ProviderError| {
            Self::log_error(name, &error, conn);
            Self::answer_direct(state, conn, correlation, Err(error));
        };
        if method.route() != request.route {
            reject(&state, ProviderError::InvalidRequest);
            return;
        }
        // 7. Deadline: min(extension deadline, received + route deadline).
        let route_ms = if method.route() == Route::Read {
            READ_DEADLINE_MS
        } else {
            INTERACTIVE_DEADLINE_MS
        };
        let deadline_unix = request
            .deadline_unix_ms
            .min(now_unix.saturating_add(route_ms));
        if now_unix >= deadline_unix {
            reject(&state, ProviderError::TimedOut);
            return;
        }
        let deadline_ms = now.saturating_add(deadline_unix - now_unix);
        // 8. Token bucket (per document) and pending limits.
        let Some(entry) = state.conns.get_mut(&conn) else {
            return;
        };
        let pending_key = (correlation.activation_nonce, correlation.request_id);
        if entry.pending.contains_key(&pending_key) {
            reject(&state, ProviderError::InvalidRequest);
            return;
        }
        let mut bucket = entry
            .buckets
            .get(&correlation.activation_nonce)
            .copied()
            .unwrap_or_else(|| Bucket::full(now));
        let allowed = bucket.take(now);
        entry.buckets.insert(correlation.activation_nonce, bucket);
        if !allowed {
            reject(&state, ProviderError::RateLimited);
            return;
        }
        if method.route() == Route::Read {
            let per_document = state
                .reads_per_document
                .get(&correlation.activation_nonce)
                .copied()
                .unwrap_or(0);
            if per_document >= MAX_READS_PER_DOCUMENT || state.reads_total >= MAX_READS_GLOBAL {
                reject(&state, ProviderError::TooManyPending);
                return;
            }
        }
        // 9. Params.
        let validated = match validate(method, &request.params) {
            Ok(validated) => validated,
            Err(error) => {
                reject(&state, error);
                return;
            }
        };
        // 10. Execute.
        let chain_id = Self::origin_chain_locked(&mut state, &origin);
        let vault = state.wallet.vault;
        let grant = state.grants.iter().find(|s| s.origin == origin).cloned();
        let immediate = |state: &mut State, body: Answer| {
            match &body {
                Ok(_) => logging::info(
                    "browser",
                    "request.ok",
                    &[("method", Field::Word(name)), ("conn", Field::Num(conn))],
                ),
                Err(error) => Self::log_error(name, error, conn),
            }
            Self::answer_direct(state, conn, correlation, body);
        };
        match (method, validated) {
            (Method::Accounts, _) => {
                let accounts = match (vault, &grant) {
                    (VaultView::Unlocked, Some(site)) => site.accounts.clone(),
                    _ => Vec::new(),
                };
                let bytes: Vec<[u8; 20]> = accounts.iter().map(|a| *a.as_bytes()).collect();
                immediate(&mut state, Ok(accounts_value(&bytes)));
            }
            (Method::ChainId, _) => {
                immediate(&mut state, Ok(Value::String(chain_id_hex(chain_id))));
            }
            (Method::NetVersion, _) => {
                immediate(&mut state, Ok(Value::String(chain_id.to_string())));
            }
            (Method::ClientVersion, _) => immediate(
                &mut state,
                Ok(Value::String(format!(
                    "YourWallet/{}",
                    env!("CARGO_PKG_VERSION")
                ))),
            ),
            (Method::GetPermissions, _) => {
                let list = match (vault, &grant) {
                    (VaultView::Unlocked, Some(site)) => {
                        let bytes: Vec<[u8; 20]> =
                            site.accounts.iter().map(|a| *a.as_bytes()).collect();
                        vec![permission_value(
                            site.origin.as_str(),
                            &bytes,
                            site.granted_at_unix_ms,
                        )]
                    }
                    _ => Vec::new(),
                };
                immediate(&mut state, Ok(Value::Array(list)));
            }
            (Method::SwitchEthereumChain, Validated::Switch(target)) => {
                if !state.wallet.registered(target) {
                    immediate(&mut state, Err(ProviderError::UnrecognizedChain));
                } else if state.wallet.blocked.contains(&target) {
                    immediate(&mut state, Err(ProviderError::ChainUnavailable));
                } else if target == chain_id {
                    immediate(&mut state, Ok(Value::Null));
                } else {
                    state.chain_cache.insert(origin.clone(), target);
                    let persist = vault == VaultView::Unlocked && grant.is_some();
                    if persist
                        && let Some(site) = state.grants.iter_mut().find(|s| s.origin == origin)
                    {
                        site.chain_id = target;
                    }
                    immediate(&mut state, Ok(Value::Null));
                    Self::emit_locked(&state, &origin, &BrowserEvent::ChainChanged(target));
                    drop(state);
                    if persist {
                        let _ = self.sink.push(DappEvent::GrantChanged {
                            origin,
                            change: GrantChange::Chain(target),
                        });
                    }
                }
            }
            (Method::RevokePermissions, _) if vault == VaultView::Unlocked => {
                state.grants.retain(|site| site.origin != origin);
                immediate(&mut state, Ok(Value::Null));
                if grant.is_some() {
                    Self::emit_locked(&state, &origin, &BrowserEvent::AccountsChanged(Vec::new()));
                    drop(state);
                    let _ = self.sink.push(DappEvent::GrantChanged {
                        origin,
                        change: GrantChange::Revoked,
                    });
                }
            }
            (Method::RequestAccounts, _) if vault == VaultView::Unlocked && grant.is_some() => {
                let bytes: Vec<[u8; 20]> = grant
                    .iter()
                    .flat_map(|site| site.accounts.iter().map(|a| *a.as_bytes()))
                    .collect();
                immediate(&mut state, Ok(accounts_value(&bytes)));
            }
            (_, Validated::Read(params)) => {
                state.reads_total = state.reads_total.saturating_add(1);
                *state
                    .reads_per_document
                    .entry(correlation.activation_nonce)
                    .or_insert(0) += 1;
                if let Some(entry) = state.conns.get_mut(&conn) {
                    entry.pending.insert(
                        pending_key,
                        Pending {
                            sequence: correlation.sequence,
                            class: Class::Read,
                        },
                    );
                }
                state.reads.push_back(ReadTask {
                    reply,
                    document: correlation.activation_nonce,
                    method,
                    params,
                    chain_id,
                    deadline_ms,
                });
                drop(state);
                self.reads_ready.notify_one();
            }
            (_, validated) => {
                let kind = match (method, validated) {
                    (Method::RequestAccounts, _) => SiteKind::RequestAccounts,
                    (Method::RequestPermissions, _) => SiteKind::RequestPermissions,
                    (Method::RevokePermissions, _) => SiteKind::Revoke,
                    (Method::SendTransaction, Validated::Send(tx)) => SiteKind::Send(tx),
                    (Method::PersonalSign, Validated::PersonalSign { message, account }) => {
                        SiteKind::PersonalSign { account, message }
                    }
                    (
                        Method::SignTypedDataV4,
                        Validated::TypedData {
                            account,
                            source,
                            value,
                        },
                    ) => SiteKind::TypedData {
                        account,
                        source,
                        value,
                    },
                    _ => {
                        immediate(&mut state, Err(ProviderError::Internal));
                        return;
                    }
                };
                if let Err(error) =
                    Self::admit_site(&state, &origin, chain_id, vault, grant.as_ref(), &kind)
                {
                    immediate(&mut state, Err(error));
                    return;
                }
                let key = reply.key();
                if let Some(entry) = state.conns.get_mut(&conn) {
                    entry.pending.insert(
                        pending_key,
                        Pending {
                            sequence: correlation.sequence,
                            class: Class::Approval,
                        },
                    );
                }
                state.approvals.insert(
                    key,
                    ApprovalInfo {
                        origin: origin.clone(),
                        connect: kind.is_connect(),
                    },
                );
                drop(state);
                logging::info(
                    "browser",
                    "request.queued",
                    &[("method", Field::Word(name)), ("conn", Field::Num(conn))],
                );
                let delivered = self.sink.push(DappEvent::Request(Box::new(SiteRequest {
                    reply,
                    origin,
                    chain_id,
                    deadline_ms,
                    method,
                    kind,
                    compat_mode: request.context.compat_mode,
                })));
                if !delivered {
                    let _ = self.respond(&reply, Err(ProviderError::Internal));
                }
            }
        }
    }

    /// Checks of an approval-class request before it is queued (spec/05 §4.1–§4.2, §8.4):
    /// vault state, grant membership, the 256-grant limit, duplicate connect windows, the
    /// origin chain rules of the signing params and the approval limits.
    fn admit_site(
        state: &State,
        origin: &BrowserOrigin,
        chain_id: u64,
        vault: VaultView,
        grant: Option<&ConnectedSite>,
        kind: &SiteKind,
    ) -> Result<(), ProviderError> {
        match vault {
            VaultView::NoVault | VaultView::Unavailable | VaultView::BackupPending => {
                return Err(ProviderError::Unauthorized);
            }
            VaultView::Unlocked => {
                let account = match kind {
                    SiteKind::Send(tx) => Some(tx.from),
                    SiteKind::PersonalSign { account, .. }
                    | SiteKind::TypedData { account, .. } => Some(*account),
                    _ => None,
                };
                if let Some(account) = account
                    && !grant.is_some_and(|site| site.allows(&account))
                {
                    return Err(ProviderError::Unauthorized);
                }
                if kind.is_connect() && grant.is_none() && state.grants.len() >= MAX_GRANTS {
                    return Err(ProviderError::Unauthorized);
                }
            }
            VaultView::Locked | VaultView::Starting => {}
        }
        match kind {
            SiteKind::Send(tx) if tx.chain_id.is_some_and(|id| id != chain_id) => {
                return Err(ProviderError::InvalidParams);
            }
            SiteKind::TypedData { source, value, .. } => {
                yw_core::evm::eip712::validate_typed_data_v4(source, value, chain_id)
                    .map_err(|_| ProviderError::InvalidParams)?;
            }
            _ => {}
        }
        if kind.is_connect()
            && state
                .approvals
                .values()
                .any(|info| info.connect && info.origin == *origin)
        {
            return Err(ProviderError::RequestPending);
        }
        let same_origin = state
            .approvals
            .values()
            .filter(|info| info.origin == *origin)
            .count();
        if same_origin >= MAX_APPROVALS_PER_ORIGIN || state.approvals.len() >= MAX_APPROVALS_GLOBAL
        {
            return Err(ProviderError::TooManyPending);
        }
        Ok(())
    }

    // ----- read queue -----------------------------------------------------------------

    /// Blocks for the next read (`None` after [`BrowserCore::stop`]).
    pub fn next_read(&self) -> Option<ReadTask> {
        let mut state = self.lock();
        loop {
            if self.stopped.load(Ordering::Acquire) {
                return None;
            }
            if let Some(task) = state.reads.pop_front() {
                return Some(task);
            }
            state = self
                .reads_ready
                .wait(state)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }

    /// Takes a queued read without blocking (tests).
    pub fn try_next_read(&self) -> Option<ReadTask> {
        self.lock().reads.pop_front()
    }

    /// Whether the read is still pending (not cancelled, connection alive).
    #[must_use]
    pub fn is_pending(&self, reply: &Reply) -> bool {
        let state = self.lock();
        state.conns.get(&reply.conn).is_some_and(|conn| {
            conn.pending
                .get(&(
                    reply.correlation.activation_nonce,
                    reply.correlation.request_id,
                ))
                .is_some_and(|pending| pending.sequence == reply.correlation.sequence)
        })
    }

    /// Finishes a read: frees its counters and answers if still pending.
    pub fn finish_read(&self, task: &ReadTask, body: Answer) {
        {
            let mut state = self.lock();
            state.reads_total = state.reads_total.saturating_sub(1);
            if let Some(count) = state.reads_per_document.get_mut(&task.document) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.reads_per_document.remove(&task.document);
                }
            }
        }
        let name = task.method.as_str();
        match &body {
            Ok(_) => logging::info(
                "browser",
                "read.ok",
                &[
                    ("method", Field::Word(name)),
                    ("conn", Field::Num(task.reply.conn)),
                ],
            ),
            Err(error) => Self::log_error(name, error, task.reply.conn),
        }
        let _ = self.respond(&task.reply, body);
    }

    /// The cached block number of a chain if younger than `max_age_ms`.
    #[must_use]
    pub fn cached_block_number(&self, chain_id: u64, max_age_ms: u64) -> Option<u64> {
        let now = self.clock.now_ms();
        self.lock()
            .block_numbers
            .get(&chain_id)
            .filter(|(_, at)| now.saturating_sub(*at) <= max_age_ms)
            .map(|(value, _)| *value)
    }

    /// Stores a successful `eth_blockNumber` of a chain.
    pub fn store_block_number(&self, chain_id: u64, value: u64) {
        let now = self.clock.now_ms();
        self.lock().block_numbers.insert(chain_id, (value, now));
    }

    /// Stops the read workers.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.reads_ready.notify_all();
    }

    /// Whether [`BrowserCore::stop`] was called.
    #[must_use]
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
}
