//! Browser requests on the UI thread (M5): the dispatcher state the UI owns (spec/05 §4.3–§4.6:
//! vault state, registered chains, blocked chains, `evmChainId`, the localhost toggle), the
//! lock/unlock grant merges, approval-class requests in the shared queue (spec/04 §3.1, §3.7),
//! the unlock window opened for dApps (spec/04 §2.5), dApp answers of every queue outcome,
//! signatures and broadcasts, grant persistence in meta (spec/02 §5.3) and the connected-sites
//! screen actions (spec/04 §2.9).

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::thread::JoinHandle;

use yw_core::evm::address::Address;
use yw_core::policy::{BrowserOrigin, ConnectedSite, ProviderError};
use yw_json::Value;

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
use crate::events::EventQueue;
use crate::flow::evm::track::BroadcastOutcome;
use crate::flow::evm::{SharedTransport, SystemClock, chain_info};
use crate::logging::{self, Field};
use crate::network::NetworkId;
use crate::ui::approval::{QueueOutcome, QueueSource};
use crate::ui::secret::SecretKind;

/// What answers a queued signing job when the key worker finishes it (FIFO: key jobs complete
/// in queue order, spec/04 §1.2).
#[derive(Clone, Copy, Debug)]
pub enum SignWaiter {
    /// An app send (no dApp answer).
    App,
    /// A dApp transaction: answered with the hash after the broadcast.
    Tx(Reply),
    /// A dApp message: answered with the signature.
    Message(Reply),
}

/// The UI side of the browser bridge.
pub struct BrowserUi {
    /// Dispatcher.
    pub core: Arc<BrowserCore>,
    /// Read workers' context (chain checks reset with the RPC worker's).
    pub reads: Arc<ReadContext>,
    /// Pipe server (`None` = E-PIPE-001).
    pub server: Option<PipeServer>,
    /// Read worker threads.
    pub threads: Vec<JoinHandle<()>>,
    /// Live pipe connections.
    pub connections: usize,
    /// Pending signing jobs in key-queue order.
    pub waiters: VecDeque<SignWaiter>,
    /// dApp transactions waiting for their broadcast.
    pub broadcasts: HashMap<[u8; 32], Reply>,
    /// The unlock window was opened for dApp requests (spec/04 §2.5 `나중에` rejects them).
    pub dapp_unlock: bool,
    /// Grants are loaded into the dispatcher (unlocked with meta).
    pub unlocked: bool,
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
        let server = match (pinned_origin(), pipe_name()) {
            (Some(origin), Ok(name)) => start(Arc::clone(&core), &name, origin).ok(),
            _ => None,
        };
        if server.is_none() {
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
            threads,
            connections: 0,
            waiters: VecDeque::new(),
            broadcasts: HashMap::new(),
            dapp_unlock: false,
            unlocked: false,
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
        _ => format!("브라우저: 사용 불가 {}", ErrorCode::Pipe001.code()),
    }
}

fn hex_signature(signature: &[u8; 65]) -> Value {
    Value::String(format!("0x{}", yw_core::hex::encode(signature)))
}

impl App {
    fn vault_view(&self) -> VaultView {
        match self.mode {
            AppMode::Starting => VaultView::Starting,
            AppMode::NoVault => VaultView::NoVault,
            AppMode::BackupPending => VaultView::BackupPending,
            AppMode::Unlocked { .. } if self.meta.is_some() => VaultView::Unlocked,
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
        WalletView {
            vault: self.vault_view(),
            chains,
            blocked,
            evm_chain_id: self.settings.evm_chain_id,
            allow_localhost: self.settings.allow_localhost_dapps,
        }
    }

    /// Pushes the UI-owned state to the dispatcher and performs the lock/unlock grant
    /// transitions (spec/05 §4.3–§4.4). Called on every refresh.
    pub fn sync_browser(&mut self) {
        let view = self.wallet_view();
        let unlocked_now = view.vault == VaultView::Unlocked;
        let Some(browser) = self.browser.as_mut() else {
            return;
        };
        let core = Arc::clone(&browser.core);
        match (browser.unlocked, unlocked_now) {
            (false, true) => {
                browser.unlocked = true;
                let grants = self
                    .meta
                    .as_ref()
                    .map(|meta| sites_from_values(&meta.connected_sites))
                    .unwrap_or_default();
                let mut locked_view = view.clone();
                locked_view.vault = VaultView::Locked;
                core.set_wallet(locked_view);
                let changed = core.unlock_wallet(grants);
                core.set_wallet(view);
                if !changed.is_empty() {
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

    /// Writes the dispatcher's grants to meta and saves it.
    fn write_grants(&mut self) {
        let Some(core) = self
            .browser
            .as_ref()
            .map(|browser| Arc::clone(&browser.core))
        else {
            return;
        };
        if let Some(meta) = self.meta.as_mut() {
            meta.connected_sites = sites_to_values(&core.grants());
            self.save_meta();
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
            AppMode::Unlocked { .. } => {
                if let SiteKind::Send(tx) = &site.kind
                    && self.slot_held(site.chain_id, &tx.from)
                {
                    self.respond(&site.reply, Err(ProviderError::TransactionPending));
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

    /// Checks of a site item taken from the queue (unlocked): returns `Some(outcome)` when it
    /// finished without a window (already answered or answered by the outcome).
    pub(crate) fn site_preflight(&mut self, site: &SiteRequest) -> Option<QueueOutcome> {
        if self.mode == AppMode::BackupPending {
            return Some(QueueOutcome::NotReady);
        }
        let grant = self.grant_of(&site.origin);
        match &site.kind {
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

    /// A reader-thread grant change to persist (spec/05 §4.3, §4.5).
    fn persist_grant_change(&mut self, origin: &BrowserOrigin, change: GrantChange) {
        if change == GrantChange::Revoked {
            self.revoke_waiting(origin);
        }
        self.write_grants();
        let _ = change;
        self.refresh();
    }

    /// Waiting signing items of `origin` end `Revoked` (4100, spec/05 §4.5); a shown one closes.
    fn revoke_waiting(&mut self, origin: &BrowserOrigin) {
        let signing_of = |item: &QueuedItem| matches!(item, QueuedItem::Site(site) if site.origin == *origin && site.kind.is_signing());
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
        self.revoke_waiting(origin);
        self.write_grants();
        logging::info("browser", "site.disconnected", &[]);
        self.refresh();
    }

    /// S13 `모두 해제`.
    pub fn disconnect_all_sites(&mut self) {
        for site in self.browser_grants() {
            self.disconnect_site(&site.origin);
        }
    }

    /// An account was hidden or its raw key removed: it leaves every grant (spec/05 §4.1).
    pub fn account_removed_from_sites(&mut self, account: &Address) {
        if let Some(browser) = self.browser.as_ref() {
            browser.core.remove_account(account);
        }
        self.write_grants();
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

    /// A connect window was approved with `accounts` (spec/05 §4.2-5): grant saved, the answer
    /// sent, then `accountsChanged` to the origin's documents.
    pub(crate) fn connect_approved(&mut self, site: &SiteRequest, accounts: Vec<Address>) {
        let chain_id = self.browser.as_ref().map_or(site.chain_id, |browser| {
            browser.core.origin_chain(&site.origin)
        });
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

    /// Records who answers the next signing job.
    pub(crate) fn push_sign_waiter(&mut self, waiter: SignWaiter) {
        if let Some(browser) = self.browser.as_mut() {
            browser.waiters.push_back(waiter);
        }
    }

    fn pop_sign_waiter(&mut self) -> Option<SignWaiter> {
        self.browser
            .as_mut()
            .and_then(|browser| browser.waiters.pop_front())
    }

    /// `SignEvm` finished: a dApp transaction waits for its broadcast; a failure answers -32603.
    pub(crate) fn browser_tx_signed(&mut self, result: Result<[u8; 32], ()>) {
        if let Some(SignWaiter::Tx(reply)) = self.pop_sign_waiter() {
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

    /// `SignMessage` finished.
    pub(crate) fn browser_message_signed(
        &mut self,
        result: Result<[u8; 65], yw_core::evm::sign::SignError>,
    ) {
        if let Some(SignWaiter::Message(reply)) = self.pop_sign_waiter() {
            match result {
                Ok(signature) => self.respond(&reply, Ok(hex_signature(&signature))),
                Err(_) => self.respond(&reply, Err(ProviderError::Internal)),
            }
        }
    }

    /// A consumed signing job was cancelled by the lock: 4001 (spec/04 §1.2).
    pub(crate) fn browser_sign_cancelled(&mut self) {
        match self.pop_sign_waiter() {
            Some(SignWaiter::Tx(reply) | SignWaiter::Message(reply)) => {
                self.respond(&reply, Err(ProviderError::UserRejected));
            }
            Some(SignWaiter::App) | None => {}
        }
    }

    /// The broadcast of a dApp transaction finished (spec/05 §5, spec/03 §11.6): the hash when
    /// sent or uncertain, -32603 `Transaction broadcast failed.` when definitely refused.
    pub(crate) fn browser_broadcast(&mut self, tx_hash: [u8; 32], outcome: BroadcastOutcome) {
        let Some(reply) = self
            .browser
            .as_mut()
            .and_then(|browser| browser.broadcasts.remove(&tx_hash))
        else {
            return;
        };
        let body = match outcome {
            BroadcastOutcome::Sent
            | BroadcastOutcome::Rejected { known: true }
            | BroadcastOutcome::Unconfirmed { .. } => Ok(Value::String(format!(
                "0x{}",
                yw_core::hex::encode(&tx_hash)
            ))),
            BroadcastOutcome::HashMismatch
            | BroadcastOutcome::Rejected { known: false }
            | BroadcastOutcome::ChainMismatch => Err(ProviderError::BroadcastFailed),
        };
        self.respond(&reply, body);
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
