//! Browser requests on the UI thread (M5): the dispatcher state the UI owns (spec/05 §4.3–§4.6:
//! vault state, registered chains, blocked chains, `evmChainId`, the localhost toggle), the
//! lock/unlock grant merges, approval-class requests in the shared queue (spec/04 §3.1, §3.7),
//! the unlock window opened for dApps (spec/04 §2.5), dApp answers of every queue outcome,
//! signatures and broadcasts, grant persistence in meta (spec/02 §5.3) and the connected-sites
//! screen actions (spec/04 §2.9).

use std::collections::HashMap;
use std::sync::Arc;
use std::thread::JoinHandle;

use yw_core::evm::address::Address;
use yw_core::policy::{BrowserOrigin, ConnectedSite, ProviderError};
use yw_json::Value;
use yw_win::pipe::ServerError;

use crate::app::{App, AppMode};
use crate::app_evm::QueuedItem;
use crate::browser::envelope::accounts_value;
use crate::browser::grants::{sites_from_values, sites_to_values};
use crate::browser::read::{ReadContext, run_worker};
use crate::browser::server::{PipeServer, pipe_name, start};
use crate::browser::{
    BrowserCore, ChainEntry, DappEvent, DappSink, GrantChange, READ_WORKERS, Reply, RequestKey,
    SiteKind, SiteRequest, VaultView, WalletView, outcome_error, pinned_extension_id,
    pinned_origin,
};
use crate::errors::ErrorCode;
use crate::events::{EventQueue, MessageSignFailure, MessageSigned, SignTicket};
use crate::flow::evm::track::BroadcastOutcome;
use crate::flow::evm::{SharedTransport, SystemClock, chain_info};
use crate::logging::{self, Field};
use crate::network::NetworkId;
use crate::ui::approval::{QueueOutcome, QueueSource};
use crate::ui::secret::SecretKind;

/// Chain-switch grant writes are coalesced: at most one meta write per this interval (a page
/// switching chains in a loop must not turn into a stream of vault writes).
pub const GRANT_WRITE_INTERVAL_MS: u64 = 2_000;

/// What answers a signing job when the key worker finishes it, found by the job's
/// [`SignTicket`] (never by queue order, spec/04 §1.2).
#[derive(Clone, Debug)]
pub enum SignWaiter {
    /// An app send (no dApp answer).
    App,
    /// A dApp transaction: answered with the hash after the broadcast.
    Tx(Reply),
    /// A dApp message: answered with the signature.
    Message(Reply),
    /// A Solana/Bitcoin dApp message (spec/07 §19, spec/08 §17).
    Chain(Reply, Box<crate::app_chain_sites::ChainAnswer>),
}

/// The UI side of the browser bridge.
pub struct BrowserUi {
    /// Dispatcher.
    pub core: Arc<BrowserCore>,
    /// Read workers' context (chain checks reset with the RPC worker's).
    pub reads: Arc<ReadContext>,
    /// Pipe server (`None`: see [`Self::pipe_error`]).
    pub server: Option<PipeServer>,
    /// Why there is no server: E-PIPE-001, or E-PIPE-002 when the pipe name was already held
    /// by another server (`ServerError::AlreadyExists`).
    pub pipe_error: Option<ErrorCode>,
    /// Read worker threads.
    pub threads: Vec<JoinHandle<()>>,
    /// Live pipe connections.
    pub connections: usize,
    /// Pending signing jobs by ticket.
    pub waiters: HashMap<SignTicket, SignWaiter>,
    /// dApp transactions waiting for their broadcast.
    pub broadcasts: HashMap<[u8; 32], Reply>,
    /// The unlock window was opened for dApp requests (spec/04 §2.5 `나중에` rejects them).
    pub dapp_unlock: bool,
    /// Grants are loaded into the dispatcher (unlocked with meta).
    pub unlocked: bool,
    /// The lock procedure has started: the dispatcher already behaves as locked while the UI
    /// thread still finishes the lock (no `eth_accounts` answers during the suspend wait).
    pub locking: bool,
    /// Chain-switch grant changes not yet written to meta, and when the last write happened.
    pub grant_write: GrantWrite,
    /// S13 as last drawn: which grant each `연결 해제` button disconnects.
    pub site_rows: SiteRows,
}

/// The S13 page and the grant behind each row button as last drawn (spec/04 §2.9): a button
/// disconnects the `(origin, family)` it was drawn for, even if the lists changed since.
#[derive(Debug, Default)]
pub struct SiteRows {
    /// The page shown (0-based).
    pub page: usize,
    /// `(origin, family)` per row button of that page, in id order.
    pub keys: std::cell::RefCell<Vec<(BrowserOrigin, yw_core::policy::Family)>>,
}

/// Coalesced grant writes ([`GRANT_WRITE_INTERVAL_MS`]).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GrantWrite {
    /// A chain switch is waiting to be written.
    pub dirty: bool,
    /// Monotonic ms of the last grant write.
    pub last_ms: Option<u64>,
}

impl GrantWrite {
    /// Notes a chain switch; returns whether to write now (the interval since the last write
    /// has passed) — otherwise the main timer writes it later ([`Self::due`]).
    pub const fn note_chain_switch(&mut self, now_ms: u64) -> bool {
        self.dirty = true;
        self.due(now_ms)
    }

    /// Whether a pending write is due.
    #[must_use]
    pub const fn due(&self, now_ms: u64) -> bool {
        self.dirty
            && match self.last_ms {
                Some(last) => now_ms.saturating_sub(last) >= GRANT_WRITE_INTERVAL_MS,
                None => true,
            }
    }

    /// A write happened (any grant change).
    pub const fn written(&mut self, now_ms: u64) {
        self.dirty = false;
        self.last_ms = Some(now_ms);
    }
}

impl core::fmt::Debug for BrowserUi {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("BrowserUi")
            .field("connections", &self.connections)
            .finish_non_exhaustive()
    }
}

impl BrowserUi {
    /// Starts the dispatcher, 4 read workers and the pipe server (spec/05 §8.1: within 2 s of
    /// process start). A server failure keeps the dispatcher (E-PIPE-001 banner by the caller).
    #[must_use]
    pub fn start(events: &Arc<EventQueue>, transport: Option<SharedTransport>) -> Self {
        let sink = Arc::clone(events) as Arc<dyn DappSink>;
        let pinned = pinned_extension_id().unwrap_or_default();
        let core = BrowserCore::new(pinned, sink, Arc::new(SystemClock));
        let reads = Arc::new(ReadContext::new(transport));
        let mut threads = Vec::new();
        for index in 0..READ_WORKERS {
            let worker_core = Arc::clone(&core);
            let context = Arc::clone(&reads);
            if let Ok(handle) = std::thread::Builder::new()
                .name(format!("yw-read-{index}"))
                .spawn(move || run_worker(&worker_core, &context))
            {
                threads.push(handle);
            }
        }
        let started = match (pinned_origin(), pipe_name()) {
            (Some(origin), Ok(name)) => start(Arc::clone(&core), &name, origin).map_err(Some),
            _ => Err(None),
        };
        // `AlreadyExists` with the single-instance mutex held: the per-user pipe name was taken
        // by a server this app did not create (spec/05 §8.1, E-PIPE-002).
        let pipe_squatted = matches!(started, Err(Some(ServerError::AlreadyExists)));
        let server = started.ok();
        let pipe_error = match (&server, pipe_squatted) {
            (Some(_), _) => None,
            (None, true) => Some(ErrorCode::Pipe002),
            (None, false) => Some(ErrorCode::Pipe001),
        };
        if pipe_squatted {
            logging::warn(
                "pipe",
                "server.squatted",
                &[("code", Field::Code(ErrorCode::Pipe002))],
            );
        } else if server.is_none() {
            logging::warn(
                "pipe",
                "server.failed",
                &[("code", Field::Code(ErrorCode::Pipe001))],
            );
        }
        Self {
            core,
            reads,
            server,
            pipe_error,
            threads,
            connections: 0,
            waiters: HashMap::new(),
            broadcasts: HashMap::new(),
            dapp_unlock: false,
            unlocked: false,
            locking: false,
            grant_write: GrantWrite::default(),
            site_rows: SiteRows::default(),
        }
    }

    /// Stops accepting and the read workers (shutdown, spec/04 §1.5-1).
    pub fn stop(&mut self) {
        if let Some(server) = self.server.as_mut() {
            server.stop();
        }
        self.core.stop();
    }
}

/// The status-line text (spec/04 §2.6).
#[must_use]
pub fn status_text(browser: Option<&BrowserUi>) -> String {
    match browser {
        Some(browser) if browser.server.is_some() => match browser.connections {
            0 => "브라우저: 연결 없음".to_owned(),
            count => format!("브라우저: 연결 {count}개"),
        },
        Some(browser) => format!(
            "브라우저: 사용 불가 {}",
            browser.pipe_error.unwrap_or(ErrorCode::Pipe001).code()
        ),
        None => format!("브라우저: 사용 불가 {}", ErrorCode::Pipe001.code()),
    }
}

fn hex_signature(signature: &[u8; 65]) -> Value {
    Value::String(format!("0x{}", yw_core::hex::encode(signature)))
}

/// The dApp answer of a broadcast outcome (spec/03 §4.4 table, spec/05 §5): the hash when the
/// node has the transaction or an automatic re-broadcast follows.
///
/// # Errors
///
/// [`ProviderError::BroadcastFailed`] when nothing sends it without the user (definitely
/// refused, another hash, chain mismatch).
pub fn broadcast_answer(
    tx_hash: [u8; 32],
    outcome: BroadcastOutcome,
) -> Result<Value, ProviderError> {
    let known = matches!(
        outcome,
        BroadcastOutcome::Sent
            | BroadcastOutcome::Rejected { known: true }
            | BroadcastOutcome::Unconfirmed { known: true }
    );
    if known || outcome.resends_automatically() {
        Ok(Value::String(format!(
            "0x{}",
            yw_core::hex::encode(&tx_hash)
        )))
    } else {
        Err(ProviderError::BroadcastFailed)
    }
}

fn now_ms() -> u64 {
    yw_win::time::monotonic_ms()
}

impl App {
    pub(crate) fn vault_view(&self) -> VaultView {
        let locking = self.browser.as_ref().is_some_and(|browser| browser.locking);
        match self.mode {
            AppMode::Starting => VaultView::Starting,
            AppMode::NoVault => VaultView::NoVault,
            AppMode::BackupPending => VaultView::BackupPending,
            AppMode::Unlocked {
                alt_passphrase: true,
            } if self.meta.is_some() && !locking => VaultView::PassphraseUnverified,
            AppMode::Unlocked { .. } if self.meta.is_some() && !locking => VaultView::Unlocked,
            AppMode::Locked
            | AppMode::Unlocking
            | AppMode::PassphraseRequired
            | AppMode::PassphraseMismatch
            | AppMode::Unlocked { .. } => VaultView::Locked,
            AppMode::Corrupt { .. } | AppMode::MainMissing | AppMode::ShuttingDown => {
                VaultView::Unavailable
            }
        }
    }

    /// The UI-owned dispatcher view.
    fn wallet_view(&self) -> WalletView {
        let chains = self
            .settings
            .registered_evm()
            .into_iter()
            .filter_map(|chain_id| {
                let info = chain_info(&self.settings, chain_id)?;
                Some(ChainEntry {
                    info,
                    url: self.apikeys.rpc_url(NetworkId::Eip155(chain_id)),
                })
            })
            .collect();
        let blocked = self
            .evm
            .chain_checks
            .iter()
            .filter(|(_, check)| matches!(check, crate::flow::evm::ChainCheck::Mismatch(_)))
            .map(|(chain_id, _)| *chain_id)
            .collect();
        let vault = self.vault_view();
        // The accounts dApps may use now (spec/05 §4.9); none unless unlocked with meta, and no
        // Bitcoin address derivation while Bitcoin is off (no Bitcoin grant is usable then).
        let unlocked = vault == VaultView::Unlocked;
        let sol_accounts = if unlocked {
            self.sol_dapp_rows().iter().map(|row| row.public).collect()
        } else {
            Vec::new()
        };
        let btc_accounts = if unlocked && self.settings.bitcoin.enabled {
            self.btc_dapp_rows()
                .into_iter()
                .map(|row| row.entry.address)
                .collect()
        } else {
            Vec::new()
        };
        WalletView {
            vault,
            chains,
            blocked,
            evm_chain_id: self.settings.evm_chain_id,
            allow_localhost: self.settings.allow_localhost_dapps,
            sol_cluster: self.sol_cluster(),
            btc_network: self.btc_network_now(),
            btc_enabled: self.settings.bitcoin.enabled,
            sol_accounts,
            btc_accounts,
        }
    }

    /// Pushes the UI-owned state to the dispatcher and performs the lock/unlock grant
    /// transitions (spec/05 §4.3–§4.4). Called on every refresh. A session opened with an
    /// unverified passphrase (`VaultView::PassphraseUnverified`) counts as unlocked here, with no
    /// grants: the unlock still ends the dApp unlock window and drains the queue, where its site
    /// items finish `PassphraseUnverified` (spec/02 §7.5).
    pub fn sync_browser(&mut self) {
        let view = self.wallet_view();
        let verified = view.vault == VaultView::Unlocked;
        let unlocked_now = verified || view.vault == VaultView::PassphraseUnverified;
        let left_unlocked = !matches!(self.mode, AppMode::Unlocked { .. });
        let Some(browser) = self.browser.as_mut() else {
            return;
        };
        if left_unlocked {
            browser.locking = false;
        }
        let core = Arc::clone(&browser.core);
        match (browser.unlocked, unlocked_now) {
            (false, true) => {
                browser.unlocked = true;
                let grants = if verified {
                    self.meta
                        .as_ref()
                        .map(|meta| sites_from_values(&meta.connected_sites))
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                let mut locked_view = view.clone();
                locked_view.vault = VaultView::Locked;
                core.set_wallet(locked_view);
                let changed = core.unlock_wallet(grants);
                // Disconnects received while locked are applied here and written below.
                let mut revoked = false;
                if verified && let Some(meta) = self.meta.as_ref() {
                    revoked = core.unlock_chains(
                        crate::browser::grants::sol_sites_from_values(&meta.chain_sites.sol),
                        crate::browser::grants::btc_sites_from_values(&meta.chain_sites.btc),
                    );
                }
                core.set_wallet(view);
                if !changed.is_empty() || revoked {
                    self.write_grants();
                }
                self.after_browser_unlock();
            }
            (true, false) => {
                browser.unlocked = false;
                core.set_wallet(view);
                core.lock_wallet();
            }
            _ => core.set_wallet(view),
        }
    }

    /// The lock procedure starts (minimal hook at the top of `App::lock`): the dispatcher is
    /// locked right away — grants dropped, `accountsChanged([])` sent — instead of after the
    /// suspend wait, so no reader thread answers `eth_accounts` with accounts meanwhile. The
    /// flag holds the locked view until the mode leaves `Unlocked`.
    pub fn browser_lock_begin(&mut self) {
        self.flush_grant_writes();
        let Some(browser) = self.browser.as_mut() else {
            return;
        };
        browser.locking = true;
        self.sync_browser();
    }

    /// Writes the dispatcher's grants to meta and saves it.
    pub(crate) fn write_grants(&mut self) {
        let Some(browser) = self.browser.as_mut() else {
            return;
        };
        browser.grant_write.written(now_ms());
        let core = Arc::clone(&browser.core);
        if let Some(meta) = self.meta.as_mut() {
            meta.connected_sites = sites_to_values(&core.grants());
            meta.chain_sites.sol = core
                .sol_grants()
                .iter()
                .map(crate::browser::grants::sol_site_to_value)
                .collect();
            meta.chain_sites.btc = core
                .btc_grants()
                .iter()
                .map(crate::browser::grants::btc_site_to_value)
                .collect();
            self.save_meta();
        }
    }

    /// Writes a coalesced chain switch now if one is pending (lock, shutdown paths).
    pub(crate) fn flush_grant_writes(&mut self) {
        if self
            .browser
            .as_ref()
            .is_some_and(|browser| browser.grant_write.dirty)
            && matches!(self.mode, AppMode::Unlocked { .. })
        {
            self.write_grants();
        }
    }

    /// Main-timer part of the bridge: a coalesced chain-switch grant write that came due.
    pub(crate) fn browser_tick(&mut self, now: u64) {
        if self
            .browser
            .as_ref()
            .is_some_and(|browser| browser.grant_write.due(now))
        {
            self.flush_grant_writes();
        }
    }

    /// `Vault::load` reported a status: waiting dApp items get the unlock window (locked) or
    /// 4100 (no wallet, damaged vault, backup pending; spec/05 §4.1–§4.2).
    pub(crate) fn browser_vault_loaded(&mut self) {
        let waiting = self
            .evm
            .queue
            .waiting_payloads()
            .any(|item| matches!(item, QueuedItem::Site(_)));
        if !waiting {
            return;
        }
        match self.mode {
            AppMode::Locked => self.open_unlock_for_dapp(),
            AppMode::NoVault
            | AppMode::Corrupt { .. }
            | AppMode::MainMissing
            | AppMode::BackupPending => {
                let outcome = if self.mode == AppMode::BackupPending {
                    QueueOutcome::NotReady
                } else {
                    QueueOutcome::Revoked
                };
                let finished = self
                    .evm
                    .queue
                    .drain_waiting_matching(|item| matches!(item, QueuedItem::Site(_)), outcome);
                for (item, outcome) in finished {
                    self.approval_finished(&item.payload, outcome);
                }
            }
            _ => {}
        }
    }

    /// After the unlock merge: `BackupPending` items end `NotReady`; otherwise the queue moves.
    fn after_browser_unlock(&mut self) {
        if let Some(browser) = self.browser.as_mut() {
            browser.dapp_unlock = false;
        }
        self.show_next_approval();
    }

    /// Handles a bridge event.
    pub fn on_dapp_event(&mut self, event: DappEvent) {
        match event {
            DappEvent::Request(site) => self.on_site_request(*site),
            DappEvent::Cancel(key) => self.cancel_site(key),
            DappEvent::GrantChanged { origin, change } => {
                self.persist_grant_change(&origin, change);
            }
            DappEvent::ChainChecked { chain_id, check } => self.on_chain_check(chain_id, check),
            DappEvent::Connections(count) => {
                if let Some(browser) = self.browser.as_mut() {
                    browser.connections = count;
                }
                self.refresh();
            }
        }
    }

    pub(crate) fn respond(&self, reply: &Reply, body: Result<Value, ProviderError>) {
        if let Some(browser) = self.browser.as_ref() {
            let _ = browser.core.respond(reply, body);
        }
    }

    pub(crate) fn browser_grants(&self) -> Vec<ConnectedSite> {
        self.browser
            .as_ref()
            .map(|browser| browser.core.grants())
            .unwrap_or_default()
    }

    /// The Solana and Bitcoin grants (empty while locked).
    pub(crate) fn chain_grants(
        &self,
    ) -> (
        Vec<yw_core::policy::SolGrant>,
        Vec<yw_core::policy::BtcGrant>,
    ) {
        self.browser.as_ref().map_or_else(
            || (Vec::new(), Vec::new()),
            |browser| (browser.core.sol_grants(), browser.core.btc_grants()),
        )
    }

    fn grant_of(&self, origin: &BrowserOrigin) -> Option<ConnectedSite> {
        self.browser_grants()
            .into_iter()
            .find(|site| site.origin == *origin)
    }

    fn slot_held(&self, chain_id: u64, account: &Address) -> bool {
        self.evm
            .slots
            .iter()
            .any(|(chain, held)| *chain == chain_id && held == account)
    }

    /// The immediate answer to a site request while unlocked, before any queue entry: a send
    /// from an account whose signing slot is held (`TransactionPending`), or a connect in a
    /// key-only wallet without an EVM key (4100 `NoEvmAccount`, spec/05 §4.2 — e.g. a wallet
    /// started from a Bitcoin or Solana key).
    pub(crate) fn unlocked_refusal(&self, site: &SiteRequest) -> Option<ProviderError> {
        if let SiteKind::Send(tx) = &site.kind
            && self.slot_held(site.chain_id, &tx.from)
        {
            return Some(ProviderError::TransactionPending);
        }
        if let Some(error) = self.chain_unlocked_refusal(site) {
            return Some(error);
        }
        (site.kind.is_connect()
            && site.kind.family() == yw_core::policy::Family::Evm
            && self.own_accounts().is_empty())
        .then_some(ProviderError::NoEvmAccount)
    }

    fn on_site_request(&mut self, site: SiteRequest) {
        logging::info(
            "browser",
            "site.request",
            &[("method", Field::Word(site.method.as_str()))],
        );
        match self.mode {
            AppMode::ShuttingDown => {
                self.respond(&site.reply, Err(ProviderError::ConnectionClosed));
                return;
            }
            AppMode::NoVault
            | AppMode::Corrupt { .. }
            | AppMode::MainMissing
            | AppMode::BackupPending => {
                // No wallet, or backup not confirmed (`NotReady`): 4100 (spec/05 §4.1–§4.2).
                self.respond(&site.reply, Err(ProviderError::Unauthorized));
                return;
            }
            AppMode::Unlocked { .. } if self.passphrase_unverified() => {
                // A stale dispatcher view let it through: refused like the dispatcher does.
                if let Some(error) = Self::passphrase_refusal(&site.kind) {
                    self.respond(&site.reply, Err(error));
                    return;
                }
            }
            AppMode::Unlocked { .. } => {
                if let Some(error) = self.unlocked_refusal(&site) {
                    self.respond(&site.reply, Err(error));
                    return;
                }
            }
            _ => {}
        }
        let source = QueueSource::Site {
            origin: site.origin.as_str().to_owned(),
            deadline_ms: site.deadline_ms,
        };
        let reply = site.reply;
        if self
            .evm
            .queue
            .enqueue(source, QueuedItem::Site(Box::new(site)))
            .is_err()
        {
            self.respond(&reply, Err(ProviderError::TooManyPending));
            return;
        }
        if matches!(self.mode, AppMode::Unlocked { .. }) {
            self.show_next_approval();
        } else {
            self.open_unlock_for_dapp();
            self.refresh();
        }
    }

    /// spec/04 §2.5: one topmost unlock window for all waiting dApp requests.
    fn open_unlock_for_dapp(&mut self) {
        if self.mode != AppMode::Locked || self.secret_open() {
            return;
        }
        if let Some(browser) = self.browser.as_mut() {
            browser.dapp_unlock = true;
        }
        self.open_input(SecretKind::Unlock, crate::app::Purpose::Unlock, true);
    }

    /// The dApp unlock window was dismissed (`나중에`): every waiting site item is rejected.
    pub(crate) fn dapp_unlock_dismissed(&mut self) {
        let opened_for_dapp = self
            .browser
            .as_mut()
            .is_some_and(|browser| std::mem::take(&mut browser.dapp_unlock));
        if !opened_for_dapp {
            return;
        }
        // Unconnected pages may not pop the window right back up (spec/05 §4.4 cooldown).
        if let Some(browser) = self.browser.as_ref() {
            browser.core.dapp_unlock_dismissed();
        }
        let finished = self.evm.queue.drain_waiting_matching(
            |item| matches!(item, QueuedItem::Site(_)),
            QueueOutcome::Rejected,
        );
        for (item, outcome) in finished {
            self.approval_finished(&item.payload, outcome);
        }
    }

    fn cancel_site(&mut self, key: RequestKey) {
        let matches =
            |item: &QueuedItem| matches!(item, QueuedItem::Site(site) if site.reply.key() == key);
        let shown = self
            .evm
            .queue
            .shown()
            .is_some_and(|item| matches(&item.payload));
        if shown {
            self.close_approval_window();
        }
        if let Some(id) = self.evm.queue.find(matches)
            && let Some((item, outcome)) = self.evm.queue.cancel(id)
        {
            self.approval_finished(&item.payload, outcome);
        }
        if shown {
            self.show_next_approval();
        }
        self.refresh();
    }

    /// A finished site item: its dApp answer per spec/04 §3.1 (none for `Approved`: the flow
    /// answers with the result) and the send slot release.
    pub(crate) fn site_finished(&mut self, site: &SiteRequest, outcome: QueueOutcome) {
        if let Some(error) = outcome_error(outcome) {
            self.respond(&site.reply, Err(error));
        }
        if outcome != QueueOutcome::Approved
            && let SiteKind::Send(tx) = &site.kind
        {
            self.release_slot(site.chain_id, &tx.from);
        }
    }

    /// The refusal of a connect or signing request while the session's passphrase is
    /// unverified (spec/02 §7.5): 4100 with the reason. A revoke is not refused.
    const fn passphrase_refusal(kind: &SiteKind) -> Option<ProviderError> {
        if kind.is_connect() || kind.is_signing() {
            Some(ProviderError::PassphraseUnverified)
        } else {
            None
        }
    }

    /// Checks of a site item taken from the queue (unlocked): returns `Some(outcome)` when it
    /// finished without a window (already answered or answered by the outcome).
    pub(crate) fn site_preflight(&mut self, site: &SiteRequest) -> Option<QueueOutcome> {
        if self.mode == AppMode::BackupPending {
            return Some(QueueOutcome::NotReady);
        }
        if self.passphrase_unverified() && Self::passphrase_refusal(&site.kind).is_some() {
            // Queued while locked, then unlocked with an unverified passphrase (spec/02 §7.5).
            return Some(QueueOutcome::PassphraseUnverified);
        }
        if let Some(outcome) = self.chain_site_preflight(site) {
            return outcome;
        }
        let grant = self.grant_of(&site.origin);
        match &site.kind {
            SiteKind::SolConnect
            | SiteKind::BtcConnect(_)
            | SiteKind::SolSign { .. }
            | SiteKind::BtcSign { .. } => Some(QueueOutcome::Revoked),
            SiteKind::RequestAccounts if grant.is_some() => {
                let accounts: Vec<[u8; 20]> = grant
                    .iter()
                    .flat_map(|site| site.accounts.iter().map(|a| *a.as_bytes()))
                    .collect();
                self.respond(&site.reply, Ok(accounts_value(&accounts)));
                Some(QueueOutcome::Approved)
            }
            SiteKind::RequestAccounts | SiteKind::RequestPermissions => {
                if grant.is_none() && self.browser_grants().len() >= yw_core::policy::MAX_GRANTS {
                    return Some(QueueOutcome::Revoked);
                }
                None
            }
            SiteKind::Revoke => {
                self.disconnect_site(&site.origin);
                self.respond(&site.reply, Ok(Value::Null));
                Some(QueueOutcome::Approved)
            }
            SiteKind::Send(_) | SiteKind::PersonalSign { .. } | SiteKind::TypedData { .. } => {
                let account = match &site.kind {
                    SiteKind::Send(tx) => tx.from,
                    SiteKind::PersonalSign { account, .. }
                    | SiteKind::TypedData { account, .. } => *account,
                    _ => return Some(QueueOutcome::Revoked),
                };
                if !grant.is_some_and(|grant| grant.allows(&account))
                    || self.account_source(&account).is_none()
                {
                    return Some(QueueOutcome::Revoked);
                }
                if chain_info(&self.settings, site.chain_id).is_none() {
                    self.respond(&site.reply, Err(ProviderError::ChainUnavailable));
                    return Some(QueueOutcome::Cancelled);
                }
                if let SiteKind::Send(tx) = &site.kind {
                    if self.slot_held(site.chain_id, &tx.from) {
                        self.respond(&site.reply, Err(ProviderError::TransactionPending));
                        return Some(QueueOutcome::Cancelled);
                    }
                    self.evm.slots.push((site.chain_id, tx.from));
                }
                None
            }
        }
    }

    /// A reader-thread grant change to persist (spec/05 §4.3, §4.5): a revoke is written at once;
    /// chain switches are coalesced to one write per [`GRANT_WRITE_INTERVAL_MS`] (the dispatcher
    /// already answers from memory; the write follows on the main timer).
    fn persist_grant_change(&mut self, origin: &BrowserOrigin, change: GrantChange) {
        match change {
            GrantChange::Revoked => {
                self.revoke_waiting(origin, yw_core::policy::Family::Evm);
                self.write_grants();
            }
            GrantChange::SolRevoked => {
                self.revoke_waiting(origin, yw_core::policy::Family::Solana);
                self.write_grants();
            }
            GrantChange::BtcRevoked => {
                self.revoke_waiting(origin, yw_core::policy::Family::Bitcoin);
                self.write_grants();
            }
            GrantChange::Chain(_) => {
                let now = now_ms();
                let write = self
                    .browser
                    .as_mut()
                    .is_some_and(|browser| browser.grant_write.note_chain_switch(now));
                if write {
                    self.write_grants();
                }
            }
        }
        self.refresh();
    }

    /// Waiting signing items of `origin` and `family` end `Revoked` (4100, spec/05 §4.5); a shown
    /// one closes.
    pub(crate) fn revoke_waiting(
        &mut self,
        origin: &BrowserOrigin,
        family: yw_core::policy::Family,
    ) {
        let signing_of = |item: &QueuedItem| matches!(item, QueuedItem::Site(site) if site.origin == *origin && site.kind.is_signing() && site.kind.family() == family);
        let finished = self
            .evm
            .queue
            .drain_waiting_matching(signing_of, QueueOutcome::Revoked);
        for (item, outcome) in finished {
            self.approval_finished(&item.payload, outcome);
        }
        if self
            .evm
            .queue
            .shown()
            .is_some_and(|item| signing_of(&item.payload))
        {
            self.close_approval_window();
            if let Some((item, outcome)) = self.evm.queue.finish_shown(QueueOutcome::Revoked) {
                self.approval_finished(&item.payload, outcome);
            }
            self.show_next_approval();
        }
    }

    /// Disconnects a site (S13 `연결 해제`, `wallet_revokePermissions` after unlock).
    pub fn disconnect_site(&mut self, origin: &BrowserOrigin) {
        if let Some(browser) = self.browser.as_ref() {
            browser.core.remove_grant(origin);
        }
        self.revoke_waiting(origin, yw_core::policy::Family::Evm);
        self.write_grants();
        logging::info("browser", "site.disconnected", &[]);
        self.refresh();
    }

    /// S13 `모두 해제`.
    pub fn disconnect_all_sites(&mut self) {
        for site in self.browser_grants() {
            self.disconnect_site(&site.origin);
        }
        let (sol, btc) = self.chain_grants();
        for grant in sol {
            self.disconnect_chain_site(&grant.origin, yw_core::policy::Family::Solana);
        }
        for grant in btc {
            self.disconnect_chain_site(&grant.origin, yw_core::policy::Family::Bitcoin);
        }
    }

    /// An account was hidden or its raw key removed: it leaves every grant (spec/05 §4.1), and
    /// dApp signing requests for it — waiting or shown — end `Revoked` (4100) like a revoked
    /// grant's (security review L4(b); the shown window closes, as on a chain deletion).
    pub fn account_removed_from_sites(&mut self, account: &Address) {
        if let Some(browser) = self.browser.as_ref() {
            browser.core.remove_account(account);
        }
        self.write_grants();
        let for_account = |item: &QueuedItem| {
            matches!(item, QueuedItem::Site(site) if match &site.kind {
                SiteKind::Send(tx) => tx.from == *account,
                SiteKind::PersonalSign { account: signer, .. }
                | SiteKind::TypedData { account: signer, .. } => signer == account,
                _ => false,
            })
        };
        let finished = self
            .evm
            .queue
            .drain_waiting_matching(for_account, QueueOutcome::Revoked);
        for (item, outcome) in finished {
            self.approval_finished(&item.payload, outcome);
        }
        if self
            .evm
            .queue
            .shown()
            .is_some_and(|item| for_account(&item.payload))
        {
            self.close_approval_window();
            if let Some((item, outcome)) = self.evm.queue.finish_shown(QueueOutcome::Revoked) {
                self.approval_finished(&item.payload, outcome);
            }
            self.show_next_approval();
        }
    }

    /// A user chain was deleted (spec/05 §4.3): origins move to `evmChainId`, grants are
    /// rewritten, signing items on that chain end with 4901.
    pub fn chain_removed_from_sites(&mut self, chain_id: u64) {
        let default = self.settings.evm_chain_id;
        if let Some(browser) = self.browser.as_ref() {
            browser.core.chain_removed(chain_id, default);
        }
        self.write_grants();
        let on_chain = |item: &QueuedItem| matches!(item, QueuedItem::Site(site) if site.chain_id == chain_id && site.kind.is_signing());
        let finished = self
            .evm
            .queue
            .drain_waiting_matching(on_chain, QueueOutcome::Cancelled);
        for (item, outcome) in finished {
            if let QueuedItem::Site(site) = &item.payload {
                self.respond(&site.reply, Err(ProviderError::ChainUnavailable));
            }
            self.approval_finished(&item.payload, outcome);
        }
        if self
            .evm
            .queue
            .shown()
            .is_some_and(|item| on_chain(&item.payload))
        {
            self.close_approval_window();
            if let Some((item, outcome)) = self.evm.queue.finish_shown(QueueOutcome::Cancelled) {
                if let QueuedItem::Site(site) = &item.payload {
                    self.respond(&site.reply, Err(ProviderError::ChainUnavailable));
                }
                self.approval_finished(&item.payload, outcome);
            }
            self.show_next_approval();
        }
    }

    /// A connect window was approved with `accounts` on the shown `chain_id` (spec/05 §4.2-5):
    /// grant saved, the answer sent, then `accountsChanged` to the origin's documents. The
    /// accounts are checked against the visible accounts of now — one hidden or removed while
    /// the window was open is refused with 4100 `Unauthorized` like a stale Solana/Bitcoin choice
    /// (security review L4(a)); the caller already made sure `chain_id` is the origin's chain.
    pub(crate) fn connect_approved(
        &mut self,
        site: &SiteRequest,
        accounts: Vec<Address>,
        chain_id: u64,
    ) {
        let own = self.own_accounts();
        if !accounts
            .iter()
            .all(|account| own.iter().any(|(known, _)| known == account))
        {
            logging::info("browser", "site.connect_stale", &[]);
            self.respond(&site.reply, Err(ProviderError::Unauthorized));
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(0));
        let Some(grant) = ConnectedSite::new(site.origin.clone(), accounts, chain_id, now) else {
            self.respond(&site.reply, Err(ProviderError::Internal));
            return;
        };
        let bytes: Vec<[u8; 20]> = grant.accounts.iter().map(|a| *a.as_bytes()).collect();
        let answer = match site.kind {
            SiteKind::RequestPermissions => {
                Value::Array(vec![crate::browser::params::permission_value(
                    grant.origin.as_str(),
                    &bytes,
                    now,
                )])
            }
            _ => accounts_value(&bytes),
        };
        self.respond(&site.reply, Ok(answer));
        if let Some(browser) = self.browser.as_ref() {
            browser.core.upsert_grant(grant);
        }
        self.write_grants();
        logging::info(
            "browser",
            "site.connected",
            &[("accounts", Field::Num(bytes.len() as u64))],
        );
    }

    /// Registers who answers a signing job and returns the job's ticket (the key job and its
    /// result carry it; results are matched by it, never by order).
    pub(crate) fn push_sign_waiter(&mut self, waiter: SignWaiter) -> SignTicket {
        self.evm.next_ticket = self.evm.next_ticket.wrapping_add(1);
        let ticket = SignTicket(self.evm.next_ticket);
        if let Some(browser) = self.browser.as_mut() {
            browser.waiters.insert(ticket, waiter);
        }
        ticket
    }

    pub(crate) fn take_sign_waiter(&mut self, ticket: SignTicket) -> Option<SignWaiter> {
        self.browser
            .as_mut()
            .and_then(|browser| browser.waiters.remove(&ticket))
    }

    /// `SignEvm` finished: a dApp transaction waits for its broadcast; a failure answers -32603.
    pub(crate) fn browser_tx_signed(&mut self, ticket: SignTicket, result: Result<[u8; 32], ()>) {
        if let Some(SignWaiter::Tx(reply)) = self.take_sign_waiter(ticket) {
            match result {
                Ok(hash) => {
                    if let Some(browser) = self.browser.as_mut() {
                        browser.broadcasts.insert(hash, reply);
                    }
                }
                Err(()) => self.respond(&reply, Err(ProviderError::Internal)),
            }
        }
    }

    /// `SignMessage` finished (a lock-cancelled one answers 4001, spec/04 §1.2).
    pub(crate) fn browser_message_signed(&mut self, signed: MessageSigned) {
        if signed.result == Err(MessageSignFailure::Locked) {
            self.evm_sign_locked(signed.ticket);
            return;
        }
        if let Some(SignWaiter::Message(reply)) = self.take_sign_waiter(signed.ticket) {
            match signed.result {
                Ok(signature) => self.respond(&reply, Ok(hex_signature(&signature))),
                Err(_) => self.respond(&reply, Err(ProviderError::Internal)),
            }
        }
    }

    /// A consumed signing job was cancelled by the lock: 4001 (spec/04 §1.2).
    pub(crate) fn browser_sign_cancelled(&mut self, ticket: SignTicket) {
        match self.take_sign_waiter(ticket) {
            Some(
                SignWaiter::Tx(reply) | SignWaiter::Message(reply) | SignWaiter::Chain(reply, _),
            ) => {
                self.respond(&reply, Err(ProviderError::UserRejected));
            }
            Some(SignWaiter::App) | None => {}
        }
    }

    /// The broadcast of a dApp transaction finished (spec/05 §5, spec/03 §4.4, §11.6): the hash
    /// when the node has it or an automatic re-broadcast follows; -32603 `Transaction broadcast
    /// failed.` only when nothing will send it without the user (refused, other hash, chain
    /// mismatch — all journaled as manual-resend-only).
    pub(crate) fn browser_broadcast(&mut self, tx_hash: [u8; 32], outcome: BroadcastOutcome) {
        let Some(reply) = self
            .browser
            .as_mut()
            .and_then(|browser| browser.broadcasts.remove(&tx_hash))
        else {
            return;
        };
        self.respond(&reply, broadcast_answer(tx_hash, outcome));
    }

    /// An endpoint URL changed (spec/03 §1.4): the chain's verification restarts in the RPC
    /// worker, the read workers and the blocked set (the pinned genesis stays).
    pub(crate) fn network_url_changed(&mut self, network: NetworkId) {
        if let NetworkId::Solana(cluster) = network {
            self.sol_url_changed(cluster);
        }
        if let NetworkId::Bitcoin(net) = network {
            self.btc_url_changed(net);
        }
        if let NetworkId::Eip155(chain_id) = network {
            self.evm.chain_checks.remove(&chain_id);
            let _ = self.rpc(crate::workers::rpc::RpcJob::ResetChain { chain_id });
            self.reset_read_chain(chain_id);
        }
    }

    /// Forgets a chain's check in the read workers.
    pub(crate) fn reset_read_chain(&self, chain_id: u64) {
        if let Some(browser) = self.browser.as_ref() {
            browser.reads.reset_chain(chain_id);
        }
    }

    /// Origins waiting for the unlock (S07 T-UNLOCK-PENDING, at most 5 then "외 n건").
    #[must_use]
    pub fn waiting_origins(&self) -> Vec<String> {
        let mut origins: Vec<String> = Vec::new();
        for item in self.evm.queue.waiting_payloads() {
            if let QueuedItem::Site(site) = item
                && !origins.iter().any(|known| known == site.origin.as_str())
            {
                origins.push(site.origin.as_str().to_owned());
            }
        }
        origins
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use super::{BrowserUi, GRANT_WRITE_INTERVAL_MS, GrantWrite, SignWaiter};
    use crate::apikeys::ApiKeys;
    use crate::app::{App, Paths};
    use crate::browser::Reply;
    use crate::browser::envelope::{Correlation, Id16, Id32};
    use crate::events::{EventQueue, MessageSignFailure, MessageSigned};
    use crate::settings::Settings;

    fn app() -> App {
        let dir = std::env::temp_dir().join(format!("yw-app-tickets-{}", std::process::id()));
        let mut app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            Settings::default(),
            ApiKeys::default(),
        );
        let events = Arc::new(EventQueue::new(Box::new(|| {})));
        let core = crate::browser::BrowserCore::new(
            "abcdefghijklmnopabcdefghijklmnop",
            events as Arc<dyn crate::browser::DappSink>,
            Arc::new(crate::flow::evm::SystemClock),
        );
        app.browser = Some(BrowserUi {
            core,
            reads: Arc::new(crate::browser::read::ReadContext::new(None)),
            server: None,
            pipe_error: None,
            threads: Vec::new(),
            connections: 0,
            waiters: HashMap::new(),
            broadcasts: HashMap::new(),
            dapp_unlock: false,
            unlocked: false,
            locking: false,
            grant_write: GrantWrite::default(),
            site_rows: super::SiteRows::default(),
        });
        app
    }

    fn reply(n: u8) -> Reply {
        Reply {
            conn: 1,
            correlation: Correlation {
                session_id: Id32([1; 32]),
                sequence: u64::from(n),
                activation_nonce: Id32([2; 32]),
                request_id: Id16([n; 16]),
            },
        }
    }

    fn broadcast_reply(app: &App, hash: [u8; 32]) -> Option<Reply> {
        app.browser
            .as_ref()
            .and_then(|browser| browser.broadcasts.get(&hash).copied())
    }

    /// C2: signing results are matched to their waiters by ticket, so a result for a later job
    /// (or a dropped one) never answers another dApp request.
    #[test]
    fn signing_results_answer_their_own_ticket() {
        let mut app = app();
        let first = app.push_sign_waiter(SignWaiter::Tx(reply(1)));
        let message = app.push_sign_waiter(SignWaiter::Message(reply(2)));
        let second = app.push_sign_waiter(SignWaiter::Tx(reply(3)));
        let own = app.push_sign_waiter(SignWaiter::App);
        assert!(first != message && message != second && second != own);
        // Out of queue order: the second transaction finishes first.
        app.browser_tx_signed(second, Ok([0x33; 32]));
        assert_eq!(broadcast_reply(&app, [0x33; 32]), Some(reply(3)));
        // The message result only takes the message waiter.
        app.browser_message_signed(MessageSigned {
            ticket: message,
            result: Err(MessageSignFailure::Locked),
        });
        app.browser_tx_signed(first, Ok([0x11; 32]));
        assert_eq!(broadcast_reply(&app, [0x11; 32]), Some(reply(1)));
        // The app send's result answers nobody; an unknown ticket is ignored.
        app.browser_tx_signed(own, Ok([0x44; 32]));
        app.browser_tx_signed(crate::events::SignTicket(999), Ok([0x55; 32]));
        assert_eq!(broadcast_reply(&app, [0x44; 32]), None);
        assert_eq!(broadcast_reply(&app, [0x55; 32]), None);
        assert!(
            app.browser
                .as_ref()
                .is_some_and(|browser| browser.waiters.is_empty())
        );
    }

    fn site(n: u8, kind: crate::browser::SiteKind) -> crate::browser::SiteRequest {
        let method = match kind {
            crate::browser::SiteKind::RequestAccounts => yw_core::policy::Method::RequestAccounts,
            crate::browser::SiteKind::Revoke => yw_core::policy::Method::RevokePermissions,
            _ => yw_core::policy::Method::PersonalSign,
        };
        crate::browser::SiteRequest {
            reply: reply(n),
            origin: yw_core::policy::BrowserOrigin::parse("https://app.example").unwrap(),
            chain_id: yw_core::evm::chain::SEPOLIA,
            deadline_ms: u64::MAX,
            method,
            kind,
            compat_mode: None,
        }
    }

    fn sign_kind() -> crate::browser::SiteKind {
        crate::browser::SiteKind::PersonalSign {
            account: yw_core::evm::address::parse_address(
                "0x9858effd232b4033e47d90003d41ec34ecaeda94",
            )
            .unwrap(),
            message: b"hi".to_vec(),
        }
    }

    /// spec/02 §7.5: while `App::passphrase_unverified` the dispatcher view refuses connect and
    /// signing (4100 `PassphraseUnverified`), a request that slipped through is answered without
    /// a queue entry, and site requests queued while locked end `PassphraseUnverified` once the
    /// session turns out unverified. A verified session is unaffected.
    #[test]
    fn unverified_passphrase_refuses_dapp_connect_and_signing() {
        use crate::app::AppMode;
        use crate::browser::{DappEvent, SiteKind, VaultView};
        use crate::ui::approval::QueueOutcome;

        let mut app = app();
        app.meta = Some(crate::meta::Meta::default());
        app.mode = AppMode::Unlocked {
            alt_passphrase: false,
        };
        assert_eq!(app.vault_view(), VaultView::Unlocked);
        app.mode = AppMode::Unlocked {
            alt_passphrase: true,
        };
        assert!(app.passphrase_unverified());
        assert_eq!(app.vault_view(), VaultView::PassphraseUnverified);
        app.sync_browser();
        let core = Arc::clone(&app.browser.as_ref().unwrap().core);
        assert_eq!(core.wallet().vault, VaultView::PassphraseUnverified);
        assert!(core.grants().is_empty());
        // Preflight of queued items: connect and signing refused, revoke still answered.
        for kind in [
            SiteKind::RequestAccounts,
            SiteKind::RequestPermissions,
            sign_kind(),
        ] {
            assert_eq!(
                app.site_preflight(&site(1, kind)),
                Some(QueueOutcome::PassphraseUnverified)
            );
        }
        assert_eq!(
            app.site_preflight(&site(1, SiteKind::Revoke)),
            Some(QueueOutcome::Approved)
        );
        // A request delivered with a stale view is answered at once, never queued.
        app.on_dapp_event(DappEvent::Request(Box::new(site(2, sign_kind()))));
        app.on_dapp_event(DappEvent::Request(Box::new(site(
            3,
            SiteKind::RequestAccounts,
        ))));
        assert!(app.evm.queue.is_empty());
        // Queued while locked, then unlocked with the unverified passphrase: finished, no window.
        app.mode = AppMode::Locked;
        app.sync_browser();
        app.on_dapp_event(DappEvent::Request(Box::new(site(4, sign_kind()))));
        app.on_dapp_event(DappEvent::Request(Box::new(site(
            5,
            SiteKind::RequestAccounts,
        ))));
        assert_eq!(app.evm.queue.len(), 2);
        app.mode = AppMode::Unlocked {
            alt_passphrase: true,
        };
        // The refresh after the unlock (meta loaded) drains the queue: no window opens.
        app.sync_browser();
        assert!(app.evm.queue.is_empty());
        assert!(app.evm.window.is_none());
        // The same queued request in a verified session reaches its preflight checks normally.
        app.mode = AppMode::Unlocked {
            alt_passphrase: false,
        };
        assert_eq!(
            app.site_preflight(&site(6, SiteKind::RequestAccounts)),
            None
        );
    }

    const ACCOUNT_A: &str = "0x9858effd232b4033e47d90003d41ec34ecaeda94";
    const ACCOUNT_B: &str = "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb";

    fn addr(text: &str) -> yw_core::evm::address::Address {
        yw_core::evm::address::parse_address(text).unwrap()
    }

    /// `app()` unlocked with EVM accounts A (index 0) and B (index 1, hidden when `b_hidden`).
    fn accounts_app(b_hidden: bool) -> App {
        let mut app = app();
        app.mode = crate::app::AppMode::Unlocked {
            alt_passphrase: false,
        };
        let account = |index: u32, address: &str, hidden: bool| crate::meta::Account {
            index,
            label: format!("계정 {}", index + 1),
            address: address.to_owned(),
            hidden,
        };
        app.meta = Some(crate::meta::Meta {
            evm_accounts: vec![
                account(0, ACCOUNT_A, false),
                account(1, ACCOUNT_B, b_hidden),
            ],
            ..crate::meta::Meta::default()
        });
        app
    }

    /// Security review L4(a): an account hidden while the connect window was open is not
    /// granted (4100, nothing stored); visible accounts are, on the chain passed (L4(c): the
    /// shown one).
    #[test]
    fn connect_approval_rechecks_the_accounts_and_stores_the_shown_chain() {
        use crate::browser::SiteKind;
        let mut app = accounts_app(true);
        let core = Arc::clone(&app.browser.as_ref().unwrap().core);
        let request = site(1, SiteKind::RequestAccounts);
        app.connect_approved(
            &request,
            vec![addr(ACCOUNT_A), addr(ACCOUNT_B)],
            yw_core::evm::chain::SEPOLIA,
        );
        assert!(
            core.grants().is_empty(),
            "hidden B: refused, nothing stored"
        );
        app.connect_approved(
            &request,
            vec![addr("0x000000000000000000000000000000000000dead")],
            yw_core::evm::chain::SEPOLIA,
        );
        assert!(core.grants().is_empty(), "not an account of this wallet");
        app.connect_approved(&request, vec![addr(ACCOUNT_A)], 1);
        let grants = core.grants();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].accounts, vec![addr(ACCOUNT_A)]);
        assert_eq!(grants[0].chain_id, 1);
    }

    /// Security review L4(c): the connect window shows the origin's chain of now (not the
    /// request-time chain), the same value the approval then stores.
    #[test]
    fn connect_window_shows_the_origin_chain_of_now() {
        use crate::browser::SiteKind;
        let mut app = accounts_app(false);
        app.sync_browser();
        let core = Arc::clone(&app.browser.as_ref().unwrap().core);
        let request = site(1, SiteKind::RequestPermissions);
        assert_eq!(request.chain_id, yw_core::evm::chain::SEPOLIA);
        // The origin's grant moved to mainnet after the request was queued.
        core.upsert_grant(
            yw_core::policy::ConnectedSite::new(
                request.origin.clone(),
                vec![addr(ACCOUNT_A)],
                yw_core::evm::chain::ETHEREUM_MAINNET,
                0,
            )
            .unwrap(),
        );
        let state = app.connect_state(&request);
        assert_eq!(state.chain_id, yw_core::evm::chain::ETHEREUM_MAINNET);
        assert_eq!(
            Some(state.chain_name),
            app.settings
                .evm_chain_name(yw_core::evm::chain::ETHEREUM_MAINNET)
        );
    }

    /// Security review L4(b): hiding or removing an account ends the dApp signing requests for
    /// it (4100 `Revoked`); other accounts' requests stay queued.
    #[test]
    fn removing_an_account_revokes_its_waiting_signing_requests() {
        use crate::browser::{DappEvent, SiteKind};
        let mut app = accounts_app(false);
        // Queued while locked: they wait.
        app.mode = crate::app::AppMode::Locked;
        app.sync_browser();
        let sign = |account: &str| SiteKind::PersonalSign {
            account: addr(account),
            message: b"hi".to_vec(),
        };
        app.on_dapp_event(DappEvent::Request(Box::new(site(1, sign(ACCOUNT_B)))));
        app.on_dapp_event(DappEvent::Request(Box::new(site(2, sign(ACCOUNT_A)))));
        app.on_dapp_event(DappEvent::Request(Box::new(site(3, sign(ACCOUNT_B)))));
        assert_eq!(app.evm.queue.len(), 3);
        app.account_removed_from_sites(&addr(ACCOUNT_B));
        assert_eq!(app.evm.queue.len(), 1);
        assert!(app.evm.queue.waiting_payloads().all(|item| matches!(
            item,
            crate::app_evm::QueuedItem::Site(site)
                if matches!(&site.kind, SiteKind::PersonalSign { account, .. } if *account == addr(ACCOUNT_A))
        )));
    }

    /// Security review L12: `personal_sign`/`eth_signTypedData_v4` on a chain whose check found
    /// `RpcMismatch` are blocked with E34 (as sends are); an unchecked chain is not blocked.
    #[test]
    fn message_signing_is_blocked_on_a_mismatched_chain() {
        use crate::flow::evm::{ChainCheck, MismatchKind};
        let mut app = app();
        let sepolia = yw_core::evm::chain::SEPOLIA;
        assert!(app.message_chain_failure(sepolia).is_none());
        app.evm
            .chain_checks
            .insert(sepolia, ChainCheck::Mismatch(MismatchKind::ConstantGenesis));
        let failure = app.message_chain_failure(sepolia).unwrap();
        assert_eq!(failure.rule(), yw_core::evm::risk::E34);
        assert_eq!(failure.code, crate::errors::ErrorCode::Rpc006);
        assert!(!failure.retryable);
        assert!(
            app.message_chain_failure(yw_core::evm::chain::ETHEREUM_MAINNET)
                .is_none()
        );
    }

    #[test]
    fn chain_switch_grant_writes_are_coalesced() {
        let mut write = GrantWrite::default();
        assert!(
            write.note_chain_switch(1_000),
            "the first one writes at once"
        );
        write.written(1_000);
        assert!(!write.note_chain_switch(1_100));
        assert!(!write.note_chain_switch(1_200));
        assert!(!write.due(1_000 + GRANT_WRITE_INTERVAL_MS - 1));
        assert!(write.due(1_000 + GRANT_WRITE_INTERVAL_MS));
        write.written(1_000 + GRANT_WRITE_INTERVAL_MS);
        assert!(!write.due(u64::MAX), "nothing pending");
    }
}
