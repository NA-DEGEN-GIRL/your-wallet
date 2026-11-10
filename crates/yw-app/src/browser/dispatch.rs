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
use yw_core::policy::{
    BrowserOrigin, BtcGrant, BtcPurpose, ConnectedSite, Family, MAX_CHAIN_GRANTS, MAX_GRANTS,
    Method, ProviderError, Route, SolGrant,
};
use yw_json::Value;

use super::envelope::{
    BrowserEvent, CancelEnvelope, Correlation, EnvelopeError, Id32, Inbound, RequestEnvelope,
    accounts_value, chain_id_hex, parse_inbound,
};
use super::params::{ReadParams, Validated, permission_value, validate};
use super::{
    ConnId, DappEvent, DappSink, GrantChange, INTERACTIVE_DEADLINE_MS, MAX_APPROVALS_GLOBAL,
    MAX_APPROVALS_PER_ORIGIN, MAX_CHAIN_CACHE, MAX_DOCUMENTS, MAX_READS_GLOBAL,
    MAX_READS_PER_DOCUMENT, MAX_READS_PER_UNCONNECTED_ORIGIN, Outbound, Outlet, RATE_BURST,
    RATE_PER_DOCUMENT, READ_DEADLINE_MS, Reply, RequestKey, SiteKind, SiteRequest, VaultView,
    WalletView,
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
        self.insert_with(key, value, |_, _| true);
    }

    /// Inserts; when full, evicts the least recently used entry that `evictable` accepts (an
    /// entry still in use is kept), falling back to the plain LRU entry so the bound holds.
    fn insert_with(&mut self, key: K, value: V, evictable: impl Fn(&K, &V) -> bool) {
        let tick = self.next_tick();
        if let Some(entry) = self.entries.iter_mut().find(|(k, _, _)| *k == key) {
            entry.1 = value;
            entry.2 = tick;
            return;
        }
        if self.entries.len() >= self.capacity {
            let oldest = |preferred: bool| {
                self.entries
                    .iter()
                    .enumerate()
                    .filter(|(_, (k, v, _))| !preferred || evictable(k, v))
                    .min_by_key(|(_, (_, _, stamp))| *stamp)
                    .map(|(index, _)| index)
            };
            if let Some(victim) = oldest(true).or_else(|| oldest(false)) {
                self.entries.swap_remove(victim);
            }
        }
        self.entries.push((key, value, tick));
    }

    fn contains(&self, key: &K) -> bool {
        self.entries.iter().any(|(k, _, _)| k == key)
    }

    const fn is_full(&self) -> bool {
        self.entries.len() >= self.capacity
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
    /// The native session of this pipe connection: one yw-host process serves one Chrome
    /// native port, i.e. one `sessionId` (spec/05 §6.3). Bound by the first request; an envelope
    /// of another session is refused (security review INFO: no mixing or replaying another
    /// session's envelopes on a live connection).
    last_session: Option<Id32>,
    pending: HashMap<(Id32, super::envelope::Id16), Pending>,
    buckets: Lru<Id32, Bucket>,
}

#[derive(Clone, Debug)]
struct ApprovalInfo {
    origin: BrowserOrigin,
    connect: bool,
    family: Family,
}

/// What [`BrowserCore::admit_site`] checks an approval-class request against.
struct Admission<'a> {
    origin: &'a BrowserOrigin,
    chain_id: u64,
    vault: VaultView,
    grant: Option<&'a ConnectedSite>,
    sol_grant: Option<&'a SolGrant>,
    btc_grant: Option<&'a BtcGrant>,
    now_ms: u64,
}

/// A queued read.
#[derive(Clone, Debug)]
pub struct ReadTask {
    /// Where to answer.
    pub reply: Reply,
    /// Document (per-document counters).
    pub document: Id32,
    /// Origin (per-origin counters).
    pub origin: BrowserOrigin,
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
    /// Solana grants (empty while locked, spec/05 §4.9).
    sol_grants: Vec<SolGrant>,
    /// Bitcoin grants (empty while locked).
    btc_grants: Vec<BtcGrant>,
    approvals: HashMap<RequestKey, ApprovalInfo>,
    reads_total: usize,
    reads_per_document: HashMap<Id32, usize>,
    reads_per_origin: HashMap<BrowserOrigin, usize>,
    reads: VecDeque<ReadTask>,
    /// Cached `eth_blockNumber` per chain: (value, received at monotonic ms).
    block_numbers: HashMap<u64, (u64, u64)>,
    /// Origins that had a grant when the wallet locked (in memory only, cleared at unlock):
    /// they may still open the unlock window during the cooldown.
    locked_connected: Vec<BrowserOrigin>,
    /// Monotonic ms until which unconnected origins cannot reopen the dApp unlock window.
    unlock_cooldown_until_ms: u64,
    /// `wallet_revokePermissions`/`sol_disconnect`/`btc_disconnect` received while locked (the
    /// grants are not loaded): applied before any account event by [`BrowserCore::unlock_wallet`]
    /// (EVM) and [`BrowserCore::unlock_chains`] (Solana, Bitcoin; it clears the list), in memory
    /// only, at most [`MAX_LOCKED_REVOCATIONS`], oldest dropped first.
    revoked_while_locked: Vec<(BrowserOrigin, Family)>,
    /// Virtual connections (the `WalletConnect` bridge, spec/13 §5): not counted as browser pipes.
    virtual_conns: std::collections::HashSet<ConnId>,
}

/// Bound of the disconnects remembered while locked (one per origin and family; more than the
/// EVM, Solana and Bitcoin grant limits together).
pub const MAX_LOCKED_REVOCATIONS: usize = 4 * MAX_CHAIN_GRANTS;

impl State {
    /// Remembers a disconnect of `origin`'s `family` grant received while locked (spec/05 §4.4,
    /// §4.9): once per origin and family, the oldest dropped past [`MAX_LOCKED_REVOCATIONS`].
    fn remember_revocation(&mut self, origin: &BrowserOrigin, family: Family) {
        let list = &mut self.revoked_while_locked;
        list.retain(|(known, which)| !(known == origin && *which == family));
        if list.len() >= MAX_LOCKED_REVOCATIONS {
            list.remove(0);
        }
        list.push((origin.clone(), family));
    }

    /// Live pipe connections (virtual ones excluded).
    fn pipe_count(&self) -> usize {
        self.conns
            .keys()
            .filter(|id| !self.virtual_conns.contains(id))
            .count()
    }

    /// Activations with a request still pending on their connection.
    fn busy_documents(&self) -> std::collections::HashSet<Id32> {
        self.conns
            .values()
            .flat_map(|conn| conn.pending.keys().map(|(activation, _)| *activation))
            .collect()
    }

    /// Records a document: when the table is full, a document of an origin already holding
    /// [`super::MAX_DOCUMENTS_PER_ORIGIN`] entries makes room among its own, otherwise the least
    /// recently used document without a pending request goes (spec/05 §4.8: documents that are
    /// still in use keep receiving events).
    fn note_document(&mut self, activation: Id32, origin: &BrowserOrigin, conn: ConnId) {
        if self.documents.is_full() && !self.documents.contains(&activation) {
            let busy = self.busy_documents();
            let own = self
                .documents
                .iter()
                .filter(|(_, (known, _))| known == origin)
                .count();
            let crowded = own >= super::MAX_DOCUMENTS_PER_ORIGIN;
            self.documents
                .insert_with(activation, (origin.clone(), conn), |key, (known, _)| {
                    !busy.contains(key) && (!crowded || known == origin)
                });
            return;
        }
        self.documents.insert(activation, (origin.clone(), conn));
    }

    /// Caches an origin's chain; when full, an origin with a document in the table (a live page
    /// that was told this chain) is never the one forgotten (spec/05 §4.3: no unannounced chain
    /// change).
    fn cache_chain(&mut self, origin: &BrowserOrigin, chain_id: u64) {
        if self.chain_cache.is_full() && !self.chain_cache.contains(origin) {
            let live: Vec<BrowserOrigin> = self
                .documents
                .iter()
                .map(|(_, (known, _))| known.clone())
                .collect();
            self.chain_cache
                .insert_with(origin.clone(), chain_id, |known, _| !live.contains(known));
            return;
        }
        self.chain_cache.insert(origin.clone(), chain_id);
    }
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
                sol_grants: Vec::new(),
                btc_grants: Vec::new(),
                approvals: HashMap::new(),
                reads_total: 0,
                reads_per_document: HashMap::new(),
                reads_per_origin: HashMap::new(),
                reads: VecDeque::new(),
                block_numbers: HashMap::new(),
                locked_connected: Vec::new(),
                unlock_cooldown_until_ms: 0,
                revoked_while_locked: Vec::new(),
                virtual_conns: std::collections::HashSet::new(),
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
            state.pipe_count()
        };
        let _ = self.sink.push(DappEvent::Connections(count));
        id
    }

    /// Registers a virtual connection (the `WalletConnect` bridge, spec/13 §5): requests are
    /// given with [`BrowserCore::submit`], answers and events go to `outlet` like a pipe's. Not
    /// counted in the browser status line.
    pub fn open_virtual_connection(&self, outlet: Box<dyn Outlet>) -> ConnId {
        let id = self.next_conn.fetch_add(1, Ordering::Relaxed);
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
        state.virtual_conns.insert(id);
        id
    }

    /// A request of a virtual connection: the steps of [`BrowserCore::handle_frame`] after
    /// envelope parsing (session, sequence, document, method and route, deadline, rate limits,
    /// params, execution), on `chain_id` — the chain the `WalletConnect` request names. The
    /// origin moves to that chain under the same lock that runs the request; a chain that is not
    /// registered or is blocked right then refuses it with 4901 (never the origin's previous or
    /// the default chain, spec/13 §5.2).
    pub fn submit(&self, conn: ConnId, request: &RequestEnvelope, chain_id: u64) {
        if self.lock().virtual_conns.contains(&conn) {
            self.request(conn, request, Some(chain_id));
        }
    }

    /// Registers `activation` as a document of `origin` on virtual connection `conn` (bound to
    /// `session`), so the origin's events (`accountsChanged` after an account is hidden or
    /// removed, a revoke, a chain removal) reach the bridge before the session made any request
    /// — a `WalletConnect` session restored at unlock (spec/13 §5.3).
    pub fn attach_virtual_document(
        &self,
        conn: ConnId,
        session: Id32,
        activation: Id32,
        origin: &BrowserOrigin,
    ) {
        let mut state = self.lock();
        if !state.virtual_conns.contains(&conn) || !Self::session_matches(&state, conn, session) {
            return;
        }
        if let Some(entry) = state.conns.get_mut(&conn) {
            entry.last_session = Some(session);
        }
        state.note_document(activation, origin, conn);
    }

    /// The grants while the dispatcher view is unlocked, read under one lock (`None` otherwise:
    /// while locked, starting or passphrase-unverified the grants are not loaded, so their
    /// absence means nothing).
    #[must_use]
    pub fn grants_if_unlocked(&self) -> Option<Vec<ConnectedSite>> {
        let state = self.lock();
        (state.wallet.vault == VaultView::Unlocked).then(|| state.grants.clone())
    }

    /// Sets the chain of a `WalletConnect` session origin without events (each session request
    /// names its chain; the grant follows it).
    pub fn set_origin_chain(&self, origin: &BrowserOrigin, chain_id: u64) {
        let mut state = self.lock();
        if !state.wallet.registered(chain_id) {
            return;
        }
        state.cache_chain(origin, chain_id);
        if let Some(site) = state.grants.iter_mut().find(|s| s.origin == *origin) {
            site.chain_id = chain_id;
        }
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
            state.virtual_conns.remove(&conn);
            (keys, state.pipe_count())
        };
        for key in cancelled {
            let _ = self.sink.push(DappEvent::Cancel(key));
        }
        let _ = self.sink.push(DappEvent::Connections(count));
    }

    /// Number of live connections.
    #[must_use]
    pub fn connection_count(&self) -> usize {
        self.lock().pipe_count()
    }

    // ----- responses and events -------------------------------------------------------

    /// Answers a pending request exactly once. Returns `false` when the request is no longer
    /// pending (cancelled, connection gone, already answered): the result is dropped.
    pub fn respond(&self, reply: &Reply, body: Answer) -> bool {
        let mut state = self.lock();
        let key = reply.key();
        let Some(conn) = state.conns.get_mut(&reply.conn) else {
            return false;
        };
        let pending_key = (key.activation, key.request);
        match conn.pending.get(&pending_key) {
            Some(pending) if pending.sequence == reply.correlation.sequence => {
                conn.pending.remove(&pending_key);
            }
            // A stale answer (another request now uses the same ids) leaves that request's
            // approval record alone.
            _ => return false,
        }
        let sent = conn.outlet.send(Outbound::Response {
            correlation: reply.correlation,
            body,
        });
        state.approvals.remove(&key);
        sent
    }

    /// Sends an event to every document of `origin` (spec/05 §4.8).
    pub fn emit(&self, origin: &BrowserOrigin, event: &BrowserEvent) {
        let state = self.lock();
        Self::emit_locked(&state, origin, event);
    }

    fn emit_locked(state: &State, origin: &BrowserOrigin, event: &BrowserEvent) {
        // spec/05 §4.6: with the localhost toggle off, localhost pages get nothing.
        if origin.is_http() && !state.wallet.allow_localhost {
            return;
        }
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
        state.cache_chain(origin, chain);
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
        let mut origins: Vec<BrowserOrigin> =
            state.grants.iter().map(|s| s.origin.clone()).collect();
        state.grants.clear();
        for origin in &origins {
            Self::emit_locked(&state, origin, &BrowserEvent::AccountsChanged(Vec::new()));
        }
        let sol: Vec<BrowserOrigin> = state.sol_grants.drain(..).map(|g| g.origin).collect();
        for origin in &sol {
            Self::emit_locked(
                &state,
                origin,
                &BrowserEvent::SolAccountsChanged(Vec::new()),
            );
        }
        let btc: Vec<BrowserOrigin> = state.btc_grants.drain(..).map(|g| g.origin).collect();
        for origin in &btc {
            Self::emit_locked(
                &state,
                origin,
                &BrowserEvent::BtcAccountsChanged(Vec::new()),
            );
        }
        origins.extend(sol);
        origins.extend(btc);
        if !origins.is_empty() {
            state.locked_connected = origins;
        }
    }

    /// The user dismissed the unlock window opened for dApp requests (`나중에`): for
    /// [`super::UNLOCK_PROMPT_COOLDOWN_MS`], requests from origins not connected at lock time
    /// that would open it again are rejected with 4001 (spec/05 §4.4).
    pub fn dapp_unlock_dismissed(&self) {
        let until = self
            .clock
            .now_ms()
            .saturating_add(super::UNLOCK_PROMPT_COOLDOWN_MS);
        self.lock().unlock_cooldown_until_ms = until;
    }

    /// Wallet unlocked with the meta grants: the grants of origins that sent
    /// `wallet_revokePermissions` while locked are dropped first (spec/05 §4.4; the list is
    /// cleared by [`BrowserCore::unlock_chains`], so a session without grants — an unverified
    /// passphrase — keeps them for the next unlock), then the chain cache is merged (§4.3: a
    /// cached chain overrides the grant, else the cache takes the grant's chain; unregistered
    /// grant chains become `evmChainId`) and `accountsChanged(accounts)` plus `chainChanged`
    /// where the origin chain changed are sent. Returns the grants whose stored form changed — a
    /// moved `chain_id`, or a dropped grant (no longer in [`BrowserCore::grants`]) — so the
    /// caller writes meta when it is not empty.
    pub fn unlock_wallet(&self, grants: Vec<ConnectedSite>) -> Vec<ConnectedSite> {
        let mut state = self.lock();
        state.locked_connected.clear();
        state.unlock_cooldown_until_ms = 0;
        let mut changed_grants = Vec::new();
        let mut merged = Vec::with_capacity(grants.len());
        for mut site in grants {
            if state
                .revoked_while_locked
                .iter()
                .any(|(origin, family)| *origin == site.origin && *family == Family::Evm)
            {
                changed_grants.push(site);
                continue;
            }
            let cached = state.chain_cache.get(&site.origin).copied();
            let previous_origin_chain = cached;
            let target = match cached {
                Some(chain) => chain,
                None if state.wallet.registered(site.chain_id) => site.chain_id,
                None => state.wallet.evm_chain_id,
            };
            state.cache_chain(&site.origin, target);
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

    /// Wallet unlocked: the Solana and Bitcoin grants of meta are loaded, minus the disconnects
    /// received while locked (the list is cleared here, after [`BrowserCore::unlock_wallet`]
    /// used its EVM entries), and the origins of usable grants get `solAccountsChanged`/
    /// `btcAccountsChanged` (spec/05 §4.9). A grant whose account is not one dApps may use now
    /// ([`WalletView::sol_usable`]/[`WalletView::btc_usable`]: hidden or removed account, another
    /// Bitcoin network, Bitcoin off) is kept but exposes nothing. Call after
    /// [`BrowserCore::set_wallet`] with the account lists. Returns whether a locked-time
    /// disconnect removed a grant (meta must be written).
    pub fn unlock_chains(&self, sol: Vec<SolGrant>, btc: Vec<BtcGrant>) -> bool {
        let mut state = self.lock();
        let revoked = std::mem::take(&mut state.revoked_while_locked);
        let kept = |origin: &BrowserOrigin, family: Family| {
            !revoked
                .iter()
                .any(|(known, which)| known == origin && *which == family)
        };
        let before = sol.len() + btc.len();
        state.sol_grants = sol
            .into_iter()
            .filter(|grant| kept(&grant.origin, Family::Solana))
            .collect();
        state.btc_grants = btc
            .into_iter()
            .filter(|grant| kept(&grant.origin, Family::Bitcoin))
            .collect();
        let changed = state.sol_grants.len() + state.btc_grants.len() != before;
        for grant in &state.sol_grants {
            if state.wallet.sol_usable(grant) {
                Self::emit_locked(
                    &state,
                    &grant.origin,
                    &BrowserEvent::SolAccountsChanged(vec![grant.public]),
                );
            }
        }
        for grant in &state.btc_grants {
            if state.wallet.btc_usable(grant) {
                let event = BrowserEvent::BtcAccountsChanged(btc_addresses(&state, grant));
                Self::emit_locked(&state, &grant.origin, &event);
            }
        }
        changed
    }

    /// The disconnects received while locked and not yet applied (tests).
    #[must_use]
    pub fn locked_revocations(&self) -> Vec<(BrowserOrigin, Family)> {
        self.lock().revoked_while_locked.clone()
    }

    /// Whether one more Solana/Bitcoin grant fits (an origin that already has one of `family`
    /// replaces it; otherwise at most [`MAX_CHAIN_GRANTS`] per family, the meta limit).
    #[must_use]
    pub fn chain_grant_room(&self, origin: &BrowserOrigin, family: Family) -> bool {
        let state = self.lock();
        match family {
            Family::Solana => {
                state.sol_grants.iter().any(|grant| grant.origin == *origin)
                    || state.sol_grants.len() < MAX_CHAIN_GRANTS
            }
            Family::Bitcoin => {
                state.btc_grants.iter().any(|grant| grant.origin == *origin)
                    || state.btc_grants.len() < MAX_CHAIN_GRANTS
            }
            Family::Evm => {
                state.grants.iter().any(|site| site.origin == *origin)
                    || state.grants.len() < MAX_GRANTS
            }
        }
    }

    /// The Solana grants (empty while locked).
    #[must_use]
    pub fn sol_grants(&self) -> Vec<SolGrant> {
        self.lock().sol_grants.clone()
    }

    /// The Bitcoin grants (empty while locked).
    #[must_use]
    pub fn btc_grants(&self) -> Vec<BtcGrant> {
        self.lock().btc_grants.clone()
    }

    /// Solana connect approved: stores the grant and sends `solAccountsChanged`. Refused
    /// (`false`, nothing stored) when a new origin would exceed [`MAX_CHAIN_GRANTS`]: meta with
    /// more entries would not parse.
    pub fn upsert_sol_grant(&self, grant: SolGrant) -> bool {
        let mut state = self.lock();
        let origin = grant.origin.clone();
        let public = grant.public;
        let known = state.sol_grants.iter().any(|g| g.origin == origin);
        if !known && state.sol_grants.len() >= MAX_CHAIN_GRANTS {
            return false;
        }
        state.sol_grants.retain(|known| known.origin != origin);
        state.sol_grants.push(grant);
        Self::emit_locked(
            &state,
            &origin,
            &BrowserEvent::SolAccountsChanged(vec![public]),
        );
        true
    }

    /// Bitcoin connect approved: stores the grant and sends `btcAccountsChanged`. Refused like
    /// [`BrowserCore::upsert_sol_grant`] past [`MAX_CHAIN_GRANTS`].
    pub fn upsert_btc_grant(&self, grant: BtcGrant) -> bool {
        let mut state = self.lock();
        let origin = grant.origin.clone();
        let known = state.btc_grants.iter().any(|g| g.origin == origin);
        if !known && state.btc_grants.len() >= MAX_CHAIN_GRANTS {
            return false;
        }
        let event = BrowserEvent::BtcAccountsChanged(btc_addresses(&state, &grant));
        state.btc_grants.retain(|known| known.origin != origin);
        state.btc_grants.push(grant);
        Self::emit_locked(&state, &origin, &event);
        true
    }

    /// A Solana account was hidden or its imported key removed: every grant naming it is deleted
    /// and its origin gets `solAccountsChanged([])` (spec/05 §4.9: importing the key again does
    /// not bring the connection back). Returns the origins that lost their grant.
    pub fn remove_sol_account(&self, public: &[u8; 32]) -> Vec<BrowserOrigin> {
        let mut state = self.lock();
        let mut removed = Vec::new();
        state.sol_grants.retain(|grant| {
            let gone = grant.public == *public;
            if gone {
                removed.push(grant.origin.clone());
            }
            !gone
        });
        for origin in &removed {
            Self::emit_locked(
                &state,
                origin,
                &BrowserEvent::SolAccountsChanged(Vec::new()),
            );
        }
        removed
    }

    /// A Bitcoin address left the wallet (imported key removed): every grant listing it is
    /// deleted as a whole (a grant is one address per purpose; a partial one is not kept) and
    /// its origin gets `btcAccountsChanged([])`. Returns the origins that lost their grant.
    pub fn remove_btc_address(&self, address: &str) -> Vec<BrowserOrigin> {
        let mut state = self.lock();
        let mut removed = Vec::new();
        state.btc_grants.retain(|grant| {
            let gone = grant.entry(address).is_some();
            if gone {
                removed.push(grant.origin.clone());
            }
            !gone
        });
        for origin in &removed {
            Self::emit_locked(
                &state,
                origin,
                &BrowserEvent::BtcAccountsChanged(Vec::new()),
            );
        }
        removed
    }

    /// Removes the Solana grant of `origin` (S13, `sol_disconnect`); returns whether one existed.
    pub fn remove_sol_grant(&self, origin: &BrowserOrigin) -> bool {
        let mut state = self.lock();
        let before = state.sol_grants.len();
        state.sol_grants.retain(|grant| grant.origin != *origin);
        let removed = state.sol_grants.len() != before;
        if removed {
            Self::emit_locked(
                &state,
                origin,
                &BrowserEvent::SolAccountsChanged(Vec::new()),
            );
        }
        removed
    }

    /// Removes the Bitcoin grant of `origin`; returns whether one existed.
    pub fn remove_btc_grant(&self, origin: &BrowserOrigin) -> bool {
        let mut state = self.lock();
        let before = state.btc_grants.len();
        state.btc_grants.retain(|grant| grant.origin != *origin);
        let removed = state.btc_grants.len() != before;
        if removed {
            Self::emit_locked(
                &state,
                origin,
                &BrowserEvent::BtcAccountsChanged(Vec::new()),
            );
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
            Ok(Inbound::Request(request)) => self.request(conn, &request, None),
        }
    }

    /// `rule`: the broken `eth_sendTransaction` rule's static word (no values, spec/01 §5.4).
    fn log_error(method: &'static str, error: &ProviderError, conn: ConnId) {
        let method = ("method", Field::Word(method));
        let code = ("code", Field::Num(error.code().unsigned_abs()));
        let conn = ("conn", Field::Num(conn));
        match error.rule() {
            Some(rule) => logging::info(
                "browser",
                "request.error",
                &[method, code, ("rule", Field::Word(rule)), conn],
            ),
            None => logging::info("browser", "request.error", &[method, code, conn]),
        }
    }

    /// Whether `session` is this connection's session (or the connection has none yet).
    fn session_matches(state: &State, conn: ConnId, session: Id32) -> bool {
        state
            .conns
            .get(&conn)
            .is_some_and(|entry| entry.last_session.is_none_or(|bound| bound == session))
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
            if !Self::session_matches(&state, conn, cancel.session_id)
                || !Self::advance_sequence(&mut state, conn, cancel.sequence)
            {
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

    /// `chain`: the chain a virtual request runs on ([`BrowserCore::submit`]); `None` for the
    /// extension (the origin chain).
    #[expect(clippy::too_many_lines, reason = "spec/05 §6.2 steps 3–10 in order")]
    fn request(&self, conn: ConnId, request: &RequestEnvelope, chain: Option<u64>) {
        let now = self.clock.now_ms();
        let now_unix = self.clock.now_unix_ms();
        let correlation = request.correlation;
        let reply = Reply { conn, correlation };
        let mut state = self.lock();
        // 3. Session (bound by the first request of the connection) and sequence. A foreign
        // session's envelope neither runs nor moves the sequence.
        if !Self::session_matches(&state, conn, correlation.session_id)
            || !Self::advance_sequence(&mut state, conn, correlation.sequence)
        {
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
        state.note_document(correlation.activation_nonce, &origin, conn);
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
        if method.route() != request.route
            || request
                .context
                .compat_mode
                .is_some_and(|mode| mode.family() != method.family())
        {
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
            let connected = state.wallet.vault == VaultView::Unlocked
                && state.grants.iter().any(|site| site.origin == origin);
            let per_origin = state.reads_per_origin.get(&origin).copied().unwrap_or(0);
            if per_document >= MAX_READS_PER_DOCUMENT
                || state.reads_total >= MAX_READS_GLOBAL
                || (!connected && per_origin >= MAX_READS_PER_UNCONNECTED_ORIGIN)
            {
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
        let chain_id = match chain {
            // A virtual (`WalletConnect`) request runs on the chain it names or not at all.
            Some(chain) => {
                if !state.wallet.registered(chain) || state.wallet.blocked.contains(&chain) {
                    reject(&state, ProviderError::ChainUnavailable);
                    return;
                }
                state.cache_chain(&origin, chain);
                if let Some(site) = state.grants.iter_mut().find(|s| s.origin == origin) {
                    site.chain_id = chain;
                }
                chain
            }
            None => Self::origin_chain_locked(&mut state, &origin),
        };
        let vault = state.wallet.vault;
        let grant = state.grants.iter().find(|s| s.origin == origin).cloned();
        // Only grants of accounts dApps may use now count (a hidden or removed account, another
        // Bitcoin network or Bitcoin off: as if not connected, spec/05 §4.9).
        let sol_grant = (vault == VaultView::Unlocked)
            .then(|| {
                state
                    .sol_grants
                    .iter()
                    .find(|g| g.origin == origin && state.wallet.sol_usable(g))
                    .cloned()
            })
            .flatten();
        let btc_network = state.wallet.btc_network;
        let btc_grant = (vault == VaultView::Unlocked)
            .then(|| {
                state
                    .btc_grants
                    .iter()
                    .find(|g| g.origin == origin && state.wallet.btc_usable(g))
                    .cloned()
            })
            .flatten();
        // Bitcoin off (spec/05 §4.9): only the network name and a disconnect are answered. A
        // connect (the page's connect button, not its silent account reads) also tells the app,
        // which says where Bitcoin is turned on.
        if !state.wallet.btc_enabled
            && method.family() == Family::Bitcoin
            && !matches!(method, Method::BtcGetNetwork | Method::BtcDisconnect)
        {
            reject(&state, ProviderError::BtcDisabled);
            if method == Method::BtcRequestAccounts
                && matches!(vault, VaultView::Unlocked | VaultView::Locked)
            {
                drop(state);
                let _ = self.sink.push(DappEvent::ConnectRefused {
                    origin,
                    error: ProviderError::BtcDisabled,
                });
            }
            return;
        }
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
                    state.cache_chain(&origin, target);
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
            (Method::RevokePermissions, _)
                if matches!(vault, VaultView::Unlocked | VaultView::PassphraseUnverified) =>
            {
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
            (Method::RevokePermissions, _)
                if matches!(vault, VaultView::Locked | VaultView::Starting) =>
            {
                // Locked: the grants are not loaded. Like `sol_disconnect`, the disconnect is
                // answered at once and remembered; the unlock merge drops the grant before any
                // `accountsChanged` and meta is written (spec/05 §4.4). No password window for a
                // disconnect: dismissing one left the site connected, and the unlock then handed
                // it its accounts again. A grant loaded in the instant between the unlock merge
                // and the unlocked view goes at once.
                let removed = grant.is_some();
                if removed {
                    state.grants.retain(|site| site.origin != origin);
                } else {
                    state.remember_revocation(&origin, Family::Evm);
                }
                immediate(&mut state, Ok(Value::Null));
                if removed {
                    Self::emit_locked(&state, &origin, &BrowserEvent::AccountsChanged(Vec::new()));
                    drop(state);
                    let _ = self.sink.push(DappEvent::GrantChanged {
                        origin,
                        change: GrantChange::Revoked,
                    });
                }
            }
            (Method::SolAccounts, _) => {
                let list = sol_grant.as_ref().map_or_else(Vec::new, |grant| {
                    vec![Value::String(yw_core::codec::base58::base58_encode(
                        &grant.public,
                    ))]
                });
                immediate(&mut state, Ok(Value::Array(list)));
            }
            (Method::SolConnect, Validated::SolConnect { only_if_trusted })
                if sol_grant.is_some() || only_if_trusted =>
            {
                // Phantom `onlyIfTrusted`: answered from the grant only, never a window.
                let body = sol_grant
                    .as_ref()
                    .map(|grant| sol_connect_value(&grant.public))
                    .ok_or(ProviderError::UserRejected);
                immediate(&mut state, body);
            }
            (Method::BtcGetAccounts, _) => {
                let list = btc_grant
                    .as_ref()
                    .map_or_else(|| Value::Array(Vec::new()), |g| btc_accounts_value(g, None));
                immediate(&mut state, Ok(list));
            }
            (Method::BtcGetNetwork, _) => {
                let name = match btc_network {
                    yw_core::btc::BtcNetwork::Mainnet => "mainnet",
                    yw_core::btc::BtcNetwork::Testnet4 => "testnet4",
                };
                immediate(&mut state, Ok(Value::String(name.to_owned())));
            }
            (Method::BtcRequestAccounts, Validated::BtcRequestAccounts(purposes))
                if btc_grant.as_ref().is_some_and(|g| {
                    purposes
                        .iter()
                        .all(|purpose| g.addresses.iter().any(|entry| entry.purpose == *purpose))
                }) =>
            {
                let body = btc_grant
                    .as_ref()
                    .map(|g| btc_accounts_value(g, Some(&purposes)))
                    .ok_or(ProviderError::Internal);
                immediate(&mut state, body);
            }
            (Method::SolDisconnect | Method::BtcDisconnect, _) => {
                // Locked: the grants are not loaded; the disconnect is remembered and applied
                // at unlock before any account event, then written to meta (spec/05 §4.9).
                // A passphrase-unverified session has no grants and remembers nothing.
                let solana = method == Method::SolDisconnect;
                let family = if solana {
                    Family::Solana
                } else {
                    Family::Bitcoin
                };
                // Grants are loaded only while unlocked (and in the instant between the unlock
                // merge and the unlocked view): a loaded grant goes at once.
                let removed = if solana {
                    let before = state.sol_grants.len();
                    state.sol_grants.retain(|g| g.origin != origin);
                    before != state.sol_grants.len()
                } else {
                    let before = state.btc_grants.len();
                    state.btc_grants.retain(|g| g.origin != origin);
                    before != state.btc_grants.len()
                };
                if !removed && matches!(vault, VaultView::Locked | VaultView::Starting) {
                    state.remember_revocation(&origin, family);
                }
                immediate(&mut state, Ok(Value::Null));
                if removed {
                    let (event, change) = if solana {
                        (
                            BrowserEvent::SolAccountsChanged(Vec::new()),
                            GrantChange::SolRevoked,
                        )
                    } else {
                        (
                            BrowserEvent::BtcAccountsChanged(Vec::new()),
                            GrantChange::BtcRevoked,
                        )
                    };
                    Self::emit_locked(&state, &origin, &event);
                    drop(state);
                    let _ = self.sink.push(DappEvent::GrantChanged { origin, change });
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
                *state.reads_per_origin.entry(origin.clone()).or_insert(0) += 1;
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
                    origin,
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
                    (Method::SolConnect, _) => SiteKind::SolConnect,
                    (Method::BtcRequestAccounts, Validated::BtcRequestAccounts(purposes)) => {
                        SiteKind::BtcConnect(purposes)
                    }
                    (Method::SolSignMessage, Validated::SolSignMessage { public, message }) => {
                        SiteKind::SolSign {
                            public,
                            message,
                            sign_in: false,
                        }
                    }
                    (Method::SolSignIn, Validated::SolSignIn { public, mut input }) => {
                        // The wallet fills the two required fields the dApp may leave out.
                        if input.domain.is_empty() {
                            input.domain = origin_authority(&origin);
                        }
                        if input.address.is_empty() {
                            input.address = yw_core::codec::base58::base58_encode(&public);
                        }
                        let message = input.to_text().into_bytes();
                        if message.len() > yw_core::sol::msgsign::MAX_SOL_MESSAGE_BYTES {
                            immediate(&mut state, Err(ProviderError::InvalidParams));
                            return;
                        }
                        SiteKind::SolSign {
                            public,
                            message,
                            sign_in: true,
                        }
                    }
                    (
                        Method::BtcSignMessage,
                        Validated::BtcSignMessage {
                            address,
                            message,
                            protocol,
                        },
                    ) => SiteKind::BtcSign {
                        address,
                        message,
                        protocol,
                    },
                    _ => {
                        immediate(&mut state, Err(ProviderError::Internal));
                        return;
                    }
                };
                let admission = Admission {
                    origin: &origin,
                    chain_id,
                    vault,
                    grant: grant.as_ref(),
                    sol_grant: sol_grant.as_ref(),
                    btc_grant: btc_grant.as_ref(),
                    now_ms: now,
                };
                if let Err(error) = Self::admit_site(&state, &admission, &kind) {
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
                        family: kind.family(),
                    },
                );
                drop(state);
                // C8: typed data is checked against the origin chain outside the dispatcher lock,
                // and only while unlocked — a locked wallet queues the request for the unlock
                // window and the approval flow validates it then (no parsing work for pages
                // that cannot be answered yet).
                // The Hyperliquid L1 Agent exception follows the extension site origin only: a
                // `WalletConnect` origin never gets it, whatever Verify says (spec/11 §7 — an
                // attestation is not proof against a non-browser dApp).
                let l1_requester = if crate::walletconnect::is_session_origin(&origin) {
                    yw_core::evm::eip712::HlL1Requester::Nobody
                } else {
                    yw_core::evm::eip712::HlL1Requester::Origin(origin.as_str())
                };
                if vault == VaultView::Unlocked
                    && let SiteKind::TypedData { source, value, .. } = &kind
                    && yw_core::evm::eip712::validate_typed_data_v4_from(
                        source,
                        value,
                        chain_id,
                        l1_requester,
                    )
                    .is_err()
                {
                    Self::log_error(name, &ProviderError::InvalidParams, conn);
                    let _ = self.respond(&reply, Err(ProviderError::InvalidParams));
                    return;
                }
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

    /// Checks of an approval-class request before it is queued (spec/05 §4.1–§4.2, §8.4), all
    /// cheap (C8: typed data is validated by the caller after the lock is released): vault state,
    /// grant membership (a signing request of a site whose connect window is still pending
    /// waits behind it in the queue and is checked again when shown), the 256-grant limit, the
    /// unlock-window cooldown, duplicate connect windows and the approval limits, then the origin
    /// chain rule of `eth_sendTransaction`.
    fn admit_site(
        state: &State,
        admission: &Admission<'_>,
        kind: &SiteKind,
    ) -> Result<(), ProviderError> {
        let origin = admission.origin;
        let family = kind.family();
        let connecting = || {
            state
                .approvals
                .values()
                .any(|info| info.connect && info.origin == *origin && info.family == family)
        };
        match admission.vault {
            VaultView::NoVault | VaultView::Unavailable | VaultView::BackupPending => {
                return Err(ProviderError::Unauthorized);
            }
            // spec/02 §7.5: a mistyped passphrase may have opened another (empty) wallet — no
            // connect or signing until it is unlocked with the verified passphrase.
            VaultView::PassphraseUnverified => {
                return Err(ProviderError::PassphraseUnverified);
            }
            VaultView::Unlocked => {
                let account = match kind {
                    SiteKind::Send(tx) => Some(tx.from),
                    SiteKind::PersonalSign { account, .. }
                    | SiteKind::TypedData { account, .. } => Some(*account),
                    _ => None,
                };
                if let Some(account) = account
                    && !admission.grant.is_some_and(|site| site.allows(&account))
                    && !connecting()
                {
                    return Err(ProviderError::Unauthorized);
                }
                // spec/05 §4.9: a signing request names a granted Solana key / Bitcoin address.
                let chain_ok = match kind {
                    SiteKind::SolSign { public, .. } => {
                        admission.sol_grant.is_some_and(|g| g.public == *public)
                    }
                    SiteKind::BtcSign { address, .. } => admission
                        .btc_grant
                        .is_some_and(|g| g.entry(address).is_some()),
                    _ => true,
                };
                if !chain_ok && !connecting() {
                    return Err(ProviderError::Unauthorized);
                }
                let full = match family {
                    Family::Evm => admission.grant.is_none() && state.grants.len() >= MAX_GRANTS,
                    // A stored grant of the origin (usable or not) is replaced by a connect.
                    Family::Solana => {
                        !state.sol_grants.iter().any(|g| g.origin == *origin)
                            && state.sol_grants.len() >= MAX_CHAIN_GRANTS
                    }
                    Family::Bitcoin => {
                        !state.btc_grants.iter().any(|g| g.origin == *origin)
                            && state.btc_grants.len() >= MAX_CHAIN_GRANTS
                    }
                };
                if kind.is_connect() && full {
                    return Err(if family == Family::Evm {
                        ProviderError::Unauthorized
                    } else {
                        ProviderError::TooManySites
                    });
                }
            }
            VaultView::Locked | VaultView::Starting => {
                // A WalletConnect session never pops the password window (spec/13 §5): a remote
                // dApp could otherwise raise it at will. 4100 until the user unlocks.
                if crate::walletconnect::is_session_origin(origin) {
                    return Err(ProviderError::Unauthorized);
                }
                if admission.now_ms < state.unlock_cooldown_until_ms
                    && !state.locked_connected.contains(origin)
                {
                    return Err(ProviderError::UserRejected);
                }
            }
        }
        if kind.is_connect() && connecting() {
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
        if let SiteKind::Send(tx) = kind
            && tx.chain_id.is_some_and(|id| id != admission.chain_id)
        {
            return Err(ProviderError::InvalidTxParams(
                yw_core::policy::TxRule::ChainId,
            ));
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
            if let Some(count) = state.reads_per_origin.get_mut(&task.origin) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.reads_per_origin.remove(&task.origin);
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

/// `host[:port]` of an origin (the SIWS `domain` a wallet fills in).
fn origin_authority(origin: &BrowserOrigin) -> String {
    match origin.port() {
        Some(port) => format!("{}:{port}", origin.host()),
        None => origin.host().to_owned(),
    }
}

/// `{ "publicKey": base58 }` (`sol_connect` result).
pub(crate) fn sol_connect_value(public: &[u8; 32]) -> Value {
    crate::text::json_object(vec![(
        "publicKey",
        crate::text::json_str(&yw_core::codec::base58::base58_encode(public)),
    )])
}

/// The addresses a Bitcoin grant exposes now (none for another network than the settings one,
/// with Bitcoin off, or when an address is no longer the wallet's).
fn btc_addresses(state: &State, grant: &BtcGrant) -> Vec<String> {
    if state.wallet.btc_usable(grant) {
        grant
            .addresses
            .iter()
            .map(|entry| entry.address.clone())
            .collect()
    } else {
        Vec::new()
    }
}

/// `btc_requestAccounts`/`btc_getAccounts` result: `[{ address, publicKey, purpose,
/// addressType }]` (sats-connect address fields; `publicKey` lowercase hex of the key the
/// address commits to), optionally only the requested purposes.
pub(crate) fn btc_accounts_value(grant: &BtcGrant, purposes: Option<&[BtcPurpose]>) -> Value {
    use crate::text::{json_object, json_str};
    Value::Array(
        grant
            .addresses
            .iter()
            .filter(|entry| purposes.is_none_or(|wanted| wanted.contains(&entry.purpose)))
            .map(|entry| {
                json_object(vec![
                    ("address", json_str(&entry.address)),
                    (
                        "publicKey",
                        json_str(&yw_core::hex::encode(entry.pubkey.as_bytes())),
                    ),
                    ("purpose", json_str(entry.purpose.as_str())),
                    (
                        "addressType",
                        json_str(yw_core::policy::btc_address_type(entry.script_type)),
                    ),
                ])
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use yw_core::policy::BrowserOrigin;

    use super::{BrowserCore, Conn, Lru, Pending};
    use crate::browser::envelope::{Id16, Id32};
    use crate::browser::{DappEvent, DappSink, MAX_DOCUMENTS, MAX_DOCUMENTS_PER_ORIGIN, Outbound};

    struct Quiet;

    impl DappSink for Quiet {
        fn push(&self, _event: DappEvent) -> bool {
            true
        }
    }

    struct Sinkhole;

    impl crate::browser::Outlet for Sinkhole {
        fn send(&self, _outbound: Outbound) -> bool {
            true
        }
    }

    fn core() -> Arc<BrowserCore> {
        BrowserCore::new(
            "abcdefghijklmnopabcdefghijklmnop",
            Arc::new(Quiet),
            Arc::new(crate::flow::evm::SystemClock),
        )
    }

    fn doc(index: usize) -> Id32 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
        bytes[31] = 1;
        Id32(bytes)
    }

    fn site(index: usize) -> BrowserOrigin {
        BrowserOrigin::parse(&format!("https://s{index}.example")).unwrap()
    }

    #[test]
    fn lru_evicts_the_oldest_evictable_entry_and_keeps_its_bound() {
        let mut lru: Lru<u32, bool> = Lru::new(3);
        lru.insert(1, true);
        lru.insert(2, false);
        lru.insert(3, false);
        // Entry 1 (oldest) is in use: entry 2 goes instead.
        lru.insert_with(4, false, |_, in_use| !in_use);
        let keys: Vec<u32> = lru.iter().map(|(key, _)| *key).collect();
        assert!(keys.contains(&1) && !keys.contains(&2) && keys.len() == 3);
        // Nothing evictable: plain LRU so the bound holds.
        lru.insert_with(5, false, |_, _| false);
        assert_eq!(lru.iter().count(), 3);
    }

    #[test]
    fn live_documents_and_their_chains_are_not_evicted() {
        let core = core();
        let mut state = core.lock();
        state.conns.insert(
            1,
            Conn {
                outlet: Box::new(Sinkhole),
                max_sequence: 0,
                last_session: None,
                pending: HashMap::new(),
                buckets: Lru::new(MAX_DOCUMENTS),
            },
        );
        // A full table: one document per site; the oldest one has a request pending.
        for index in 0..MAX_DOCUMENTS {
            state.note_document(doc(index), &site(index), 1);
        }
        if let Some(conn) = state.conns.get_mut(&1) {
            conn.pending.insert(
                (doc(0), Id16([1; 16])),
                Pending {
                    sequence: 1,
                    class: super::Class::Read,
                },
            );
        }
        for index in 0..MAX_DOCUMENTS {
            state.cache_chain(&site(index), 1);
        }
        state.note_document(doc(MAX_DOCUMENTS), &site(MAX_DOCUMENTS), 1);
        assert!(state.documents.contains(&doc(0)), "pending request: kept");
        assert!(
            !state.documents.contains(&doc(1)),
            "oldest idle document went"
        );
        // The chain cache is full: a new origin evicts site 1 (no document left), never a
        // site whose page is still in the table.
        state.cache_chain(&site(MAX_DOCUMENTS), 11_155_111);
        assert!(state.chain_cache.contains(&site(0)));
        assert!(!state.chain_cache.contains(&site(1)));
        assert!(state.chain_cache.contains(&site(MAX_DOCUMENTS)));
        // One origin churning activations only evicts its own documents once at its quota.
        let churn = site(9_999);
        for index in 0..MAX_DOCUMENTS_PER_ORIGIN + 10 {
            state.note_document(doc(10_000 + index), &churn, 1);
        }
        let own = state
            .documents
            .iter()
            .filter(|(_, (origin, _))| *origin == churn)
            .count();
        assert_eq!(own, MAX_DOCUMENTS_PER_ORIGIN);
        assert!(state.documents.contains(&doc(0)));
        assert_eq!(state.documents.iter().count(), MAX_DOCUMENTS);
    }
}
