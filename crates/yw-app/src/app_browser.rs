//! Browser requests on the UI thread (M5): the dispatcher state the UI owns (spec/05 §4.3–§4.6:
//! vault state, registered chains, blocked chains, `evmChainId`, the localhost toggle), the
//! lock/unlock grant merges, approval-class requests in the shared queue (spec/04 §3.1, §3.7),
//! the unlock window opened for dApps (spec/04 §2.5), dApp answers of every queue outcome,
//! signatures and broadcasts, grant persistence in meta (spec/02 §5.3) and the connected-sites
//! screen actions (spec/04 §2.9).

use std::collections::HashMap;
use std::sync::Arc;

use yw_core::evm::address::Address;
use yw_core::policy::{BrowserOrigin, ConnectedSite, ProviderError};
use yw_json::Value;

use crate::app::{App, AppMode};
use crate::app_approval::AfterOpen;
use crate::app_evm::QueuedItem;
use crate::browser::envelope::accounts_value;
use crate::browser::grants::{sites_from_values, sites_to_values};
use crate::browser::read::ReadContext;
use crate::browser::{
    BrowserCore, ChainEntry, DappEvent, DappSink, GrantChange, Reply, RequestKey, SiteKind,
    SiteRequest, VaultView, WalletView, outcome_error, pinned_extension_id,
};
use crate::errors::ErrorCode;
use crate::events::{EventQueue, MessageSignFailure, MessageSigned, SignTicket};
use crate::flow::evm::track::BroadcastOutcome;
use crate::flow::evm::{Clock, SharedTransport, chain_info};
use crate::logging::{self, Field};
use crate::meta::EvmAccountPref;
use crate::network::NetworkId;
use crate::ui::approval::{QueueOutcome, QueueSource};
use yw_engine::secret::SecretKind;

/// Chain-switch grant writes are coalesced: at most one meta write per this interval (a page
/// switching chains in a loop must not turn into a stream of vault writes).
pub const GRANT_WRITE_INTERVAL_MS: u64 = 2_000;

/// The `YubiKey` accounts of a meta document a dApp grant may name (hidden ones included): the
/// EVM addresses, the Solana keys and the stable addresses (receive 0) of the cards' Bitcoin
/// accounts. Compared across a meta reload by [`App::hardware_accounts_reloaded`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct HardwareSiteAccounts {
    evm: Vec<Address>,
    sol: Vec<[u8; 32]>,
    btc: Vec<String>,
}

impl HardwareSiteAccounts {
    fn of(meta: &crate::meta::Meta) -> Self {
        let evm = meta
            .hw_accounts
            .evm
            .iter()
            .filter_map(|account| yw_core::evm::address::parse_address(&account.address).ok())
            .collect();
        let sol = meta
            .hw_accounts
            .sol
            .iter()
            .filter_map(|account| yw_core::sol::SolAddress::parse(&account.address).ok())
            .map(yw_core::sol::SolAddress::to_bytes)
            .collect();
        let btc = meta
            .btc_accounts
            .accounts
            .iter()
            .filter(|account| account.account().is_hardware())
            .filter_map(|account| {
                let address = account
                    .address(yw_core::bip32::path::BtcChain::Receive, 0)
                    .ok()?;
                Some(address.as_str().to_owned())
            })
            .collect();
        Self { evm, sol, btc }
    }
}

/// The site an EVM dApp signing job answers and the account it signs with: its grant must still
/// name the account when the signature or transaction hash goes out (spec/05 §4.5, 2026-11-13 —
/// before, only Solana dApp transactions were checked again, spec/07 §20.10-4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteSigner {
    /// The requesting origin (a `WalletConnect` session's origin included).
    pub origin: BrowserOrigin,
    /// The signing account.
    pub account: Address,
}

/// What answers a signing job when the key worker finishes it, found by the job's
/// [`SignTicket`] (never by queue order, spec/04 §1.2).
#[derive(Clone, Debug)]
pub enum SignWaiter {
    /// An app send (no dApp answer).
    App,
    /// A dApp transaction: answered with the hash after the broadcast.
    Tx(Reply, SiteSigner),
    /// A dApp message: answered with the signature.
    Message(Reply, SiteSigner),
    /// A Solana/Bitcoin dApp message (spec/07 §19, spec/08 §17).
    Chain(Reply, Box<crate::app_chain_sites::ChainAnswer>),
}

impl SignWaiter {
    /// The dApp request answered (`None`: an app send).
    #[must_use]
    pub const fn reply(&self) -> Option<Reply> {
        match self {
            Self::App => None,
            Self::Tx(reply, _) | Self::Message(reply, _) | Self::Chain(reply, _) => Some(*reply),
        }
    }
}

/// The UI side of the browser bridge. 2026-11-21 (S4 W1, plan §3.3): wallet state only; the pipe
/// server, why there is none and the read worker threads are the shell's
/// (`browser::server::PipeHost`, `App::pipe`; before, the fields `server`, `pipe_error` and
/// `threads` here).
pub struct BrowserUi {
    /// Dispatcher.
    pub core: Arc<BrowserCore>,
    /// Read workers' context (chain checks reset with the RPC worker's).
    pub reads: Arc<ReadContext>,
    /// Live pipe connections.
    pub connections: usize,
    /// Pending signing jobs by ticket.
    pub waiters: HashMap<SignTicket, SignWaiter>,
    /// dApp transactions waiting for their broadcast (the answer checks the signer's grant).
    pub broadcasts: HashMap<[u8; 32], (Reply, SiteSigner)>,
    /// Solana dApp sends waiting for their first broadcast round, by transaction id
    /// (signature 0; several when the same bytes were approved twice, spec/07 §20.8).
    pub sol_broadcasts: HashMap<[u8; 64], Vec<crate::app_sol_dapp::SolBroadcast>>,
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
    /// The dispatcher (spec/05 §8.1). The dispatcher reads `clock`, the App's (2026-11-19, S4
    /// B1a: one time base for the site deadline and the App's approval reads; before, its own
    /// `SystemClock`, the same base). 2026-11-21 (S4 W1): the first half of the old
    /// `BrowserUi::start`; the shell then starts the 4 read workers and the pipe server on it
    /// (`browser::server::PipeHost::start`, the second half), in the same order as before.
    #[must_use]
    pub fn new(
        events: &Arc<EventQueue>,
        transport: Option<SharedTransport>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let sink = Arc::clone(events) as Arc<dyn DappSink>;
        let pinned = pinned_extension_id().unwrap_or_default();
        let core = BrowserCore::new(pinned, sink, clock);
        let reads = Arc::new(ReadContext::new(transport));
        Self {
            core,
            reads,
            connections: 0,
            waiters: HashMap::new(),
            broadcasts: HashMap::new(),
            sol_broadcasts: HashMap::new(),
            dapp_unlock: false,
            unlocked: false,
            locking: false,
            grant_write: GrantWrite::default(),
            site_rows: SiteRows::default(),
        }
    }

    /// Stops the dispatcher and its read workers (shutdown, spec/04 §1.5-1). 2026-11-21 (S4 W1):
    /// the shell stops accepting first (`PipeHost::stop`); before, this fn did both, in that
    /// order.
    pub fn stop(&mut self) {
        self.core.stop();
    }
}

/// The status-line text (spec/04 §2.6) in `lang`. 2026-11-21 (S4 W1): the pipe facts come from
/// the shell's `pipe` (before, from `browser`, which held them). The dispatcher and the pipe end
/// are attached together; a dispatcher with no pipe end (tests) reads E-PIPE-001, as a
/// dispatcher with no server and no recorded failure did before.
#[must_use]
pub fn status_text(
    lang: yw_core::lang::Lang,
    browser: Option<&BrowserUi>,
    pipe: Option<&crate::browser::server::PipeHost>,
) -> String {
    match (browser, pipe) {
        (Some(browser), Some(pipe)) if pipe.server.is_some() => match browser.connections {
            0 => text::STATUS_NONE.get(lang).to_owned(),
            count => text::STATUS_CONNECTED.fill(lang, [&count.to_string()]),
        },
        (Some(_), pipe) => text::STATUS_UNAVAILABLE.fill(
            lang,
            [pipe
                .and_then(|pipe| pipe.error)
                .unwrap_or(ErrorCode::Pipe001)
                .code()],
        ),
        (None, _) => text::STATUS_UNAVAILABLE.fill(lang, [ErrorCode::Pipe001.code()]),
    }
}

/// Browser status line and connect-refusal notices (spec/04 §2.6, spec/05 §4.9; English
/// spec/14 §5).
pub mod text {
    yw_core::texts! {
        STATUS_NONE = "브라우저: 연결 없음" / "Browser: not connected";
        STATUS_CONNECTED(1) = "브라우저: 연결 {0}개" / "Browser: {0} connected";
        STATUS_UNAVAILABLE(1) = "브라우저: 사용 불가 {0}" / "Browser: unavailable {0}";
        /// `{0}` = the site.
        REFUSED_BTC_OFF(1) = "{0}의 Bitcoin 연결 요청을 거부했습니다: Bitcoin이 꺼져 있습니다. 설정 → Bitcoin에서 켠 뒤 다시 연결하세요."
            / "Refused the Bitcoin connect request of {0}: Bitcoin is turned off. Turn it on in Settings → Bitcoin, then connect again.";
        KIND_ORDINALS = "오디널스용 Taproot(P2TR) 주소" / "ordinals Taproot (P2TR) address";
        KIND_PAYMENT = "결제용 SegWit(P2WPKH·P2SH-P2WPKH) 주소" / "payment SegWit (P2WPKH·P2SH-P2WPKH) address";
        KIND_ANY = "Bitcoin 주소" / "Bitcoin address";
        /// `{0}` site, `{1}` network, `{2}` a `KIND_*` text.
        REFUSED_NO_BTC(3) = "{0}의 Bitcoin 연결 요청을 거부했습니다: 지갑에 {1} {2}가 없습니다. Bitcoin 탭에서 그 형식의 계정을 추가한 뒤 다시 연결하세요."
            / "Refused the Bitcoin connect request of {0}: the wallet has no {1} {2}. Add an account of that type in the Bitcoin tab, then connect again.";
        REFUSED_NO_SOL(1) = "{0}의 Solana 연결 요청을 거부했습니다: 지갑에 Solana 계정이 없습니다. Solana 탭에서 계정을 추가하거나 개인키를 가져온 뒤 다시 연결하세요."
            / "Refused the Solana connect request of {0}: the wallet has no Solana account. Add an account or import a private key in the Solana tab, then connect again.";
        REFUSED_NO_EVM(1) = "{0}의 연결 요청을 거부했습니다: 지갑에 EVM 계정이 없습니다. EVM 개인키를 가져온 뒤 다시 연결하세요."
            / "Refused the connect request of {0}: the wallet has no EVM account. Import an EVM private key, then connect again.";
        REFUSED_TOO_MANY(1) = "{0}의 연결 요청을 거부했습니다: 이 체인에 연결된 사이트가 이미 256개입니다. 연결된 사이트 화면에서 하나를 해제한 뒤 다시 연결하세요."
            / "Refused the connect request of {0}: 256 sites are already connected on this chain. Disconnect one on the Connected sites screen, then connect again.";
        /// `{0}` = why.
        MESSAGE_SIGN_FAILED(1) = "사이트의 메시지에 서명하지 못했습니다: {0}" / "Could not sign the site's message: {0}";
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

    /// Tests (2026-11-18, S3 A3): whether the dispatcher holds the view the UI state gives now
    /// (`sync_browser` ran after the last change; spec/05 §4.5).
    #[cfg(test)]
    pub(crate) fn browser_view_current(&self) -> bool {
        self.browser.as_ref().is_some_and(|browser| {
            format!("{:?}", browser.core.wallet()) == format!("{:?}", self.wallet_view())
        })
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
                // Disconnects received while locked (EVM, Solana, Bitcoin) are applied by these
                // two merges and written below.
                let changed = core.unlock_wallet(grants);
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

    /// The lock procedure starts (minimal hook at the top of the lock's first half
    /// `App::lock_steps`; 2026-11-21, S4 W3a: before, of `App::lock`): the dispatcher is
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
        let Some(browser) = self.wallet.browser.as_mut() else {
            return;
        };
        browser.grant_write.written(self.wallet.clock.now_ms());
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
        // Every grant change passes here: `WalletConnect` sessions follow their grants (an
        // account hidden or removed, a site disconnected — restored sessions included).
        self.wc_grants_changed();
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
    /// 4100 (no wallet, damaged vault, backup pending; spec/05 §4.1–§4.2). A `WalletConnect`
    /// request never opens the password window (spec/13 §5.2; the lock ends them anyway).
    pub(crate) fn browser_vault_loaded(&mut self) {
        let waiting = self
            .evm
            .queue
            .waiting_payloads()
            .any(|item| matches!(item, QueuedItem::Site(_)));
        if !waiting {
            return;
        }
        let for_unlock = self.evm.queue.waiting_payloads().any(|item| {
            matches!(item, QueuedItem::Site(site)
                if !crate::walletconnect::is_session_origin(&site.origin))
        });
        match self.mode {
            AppMode::Locked if for_unlock => self.open_unlock_for_dapp(),
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
        self.wc_after_unlock();
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
            DappEvent::ConnectRefused { origin, error } => {
                self.connect_refused_notice(&origin, &error, &[]);
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

    /// Answers a site item refused without a window with `error`; a connect refused for a
    /// reason the user can fix in the app also gets [`Self::connect_refused_notice`].
    pub(crate) fn refuse_site(&mut self, site: &SiteRequest, error: ProviderError) {
        if site.kind.is_connect() {
            let purposes = match &site.kind {
                SiteKind::BtcConnect(purposes) => purposes.as_slice(),
                _ => &[],
            };
            self.connect_refused_notice(&site.origin, &error, purposes);
        }
        self.respond(&site.reply, Err(error));
    }

    /// A one-line notice for a dApp connect refused without a window for a reason the user can
    /// fix here (spec/05 §4.9): Bitcoin off, no account of the requested kind (for Bitcoin the
    /// first purpose `purposes` has no account for), the 256-site limit. Before, only the page
    /// got the 4100, and nothing in the app said what to turn on or add. Shown once per text: a
    /// page asking again adds no banner.
    pub(crate) fn connect_refused_notice(
        &mut self,
        origin: &BrowserOrigin,
        error: &ProviderError,
        purposes: &[yw_core::policy::BtcPurpose],
    ) {
        use yw_core::policy::BtcPurpose;
        // A WalletConnect session's synthetic origin means nothing to the user: its claimed
        // origin label instead (spec/13 §7).
        let site = self.origin_display(origin);
        let lang = self.settings.language;
        let text = match error {
            ProviderError::BtcDisabled => text::REFUSED_BTC_OFF.fill(lang, [&site]),
            ProviderError::NoBtcAccount => {
                let rows = self.btc_dapp_rows();
                let missing = purposes.iter().find(|purpose| {
                    !rows
                        .iter()
                        .any(|row| purpose.accepts(row.entry.script_type))
                });
                let address = match missing {
                    Some(BtcPurpose::Ordinals) => text::KIND_ORDINALS,
                    Some(BtcPurpose::Payment) => text::KIND_PAYMENT,
                    _ => text::KIND_ANY,
                };
                text::REFUSED_NO_BTC.fill(
                    lang,
                    [
                        &site,
                        yw_core::btc::text::network_name(lang, self.btc_network_now()),
                        address.get(lang),
                    ],
                )
            }
            ProviderError::NoSolAccount => text::REFUSED_NO_SOL.fill(lang, [&site]),
            ProviderError::NoEvmAccount => text::REFUSED_NO_EVM.fill(lang, [&site]),
            ProviderError::TooManySites => text::REFUSED_TOO_MANY.fill(lang, [&site]),
            _ => return,
        };
        if self.banners.iter().any(|banner| banner.text == text) {
            return;
        }
        self.notice(text, crate::ui::main_window::Tone::Warn);
        self.refresh();
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
                    self.refuse_site(&site, error);
                    return;
                }
            }
            // A WalletConnect session never opens the password window (spec/13 §5; the
            // dispatcher refuses first, this covers a stale view).
            _ if crate::walletconnect::is_session_origin(&site.origin) => {
                self.respond(&site.reply, Err(ProviderError::Unauthorized));
                return;
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
        // A wallet reset in progress answers the waiting items when it ends (no vault then).
        if self.mode != AppMode::Locked || self.secret_open() || self.reset.running {
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
        // An approved request still waiting for its YubiKey PIN ends too (4001, nothing signed;
        // spec/10 §9.2, 2026-11-13). 2026-11-20 (S4 P9): after the next window's open is answered
        // when one is asked for (`AfterOpen`; before, right after `show_next_approval` returned).
        if shown {
            self.show_next_approval_then(AfterOpen::CardSiteCheckThenRefresh);
        } else {
            self.card_site_check();
            self.refresh();
        }
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
        // A WalletConnect request that ended unanswered (rejected, expired, timed out) takes
        // its session's waiting ones along (4001), like the worker's 15 s hold-off does for the
        // next ones: requests lined up in advance cannot follow each other on screen
        // (spec/13 §5.2).
        if matches!(
            outcome,
            QueueOutcome::Rejected | QueueOutcome::Expired | QueueOutcome::TimedOut
        ) && crate::walletconnect::is_session_origin(&site.origin)
        {
            let finished = self.evm.queue.drain_waiting_matching(
                |item| matches!(item, QueuedItem::Site(waiting) if waiting.origin == site.origin),
                QueueOutcome::Rejected,
            );
            for (item, outcome) in finished {
                self.approval_finished(&item.payload, outcome);
            }
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
            | SiteKind::SolTx { .. }
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
                // An account whose phrase is not backed up: the vault would refuse its key only
                // after the approval (E-VLT-009), so the page is told before any window.
                if let Some(phrase) = self.evm_account_unconfirmed(&account) {
                    self.refuse_unconfirmed(site, phrase);
                    return Some(QueueOutcome::Cancelled);
                }
                // A YubiKey still on its factory PINs: the card step would refuse it only after
                // the approval (spec/10 §9.3), so the page is told before any window.
                if let Some(serial) = self.evm_account_card_gate(&account) {
                    self.refuse_card_defaults(site, serial);
                    return Some(QueueOutcome::Cancelled);
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
    /// 2026-11-20 (S4 P10a): after a revoke, the grants are written and the screen repainted
    /// after the answer of an open the revoke asked for (`AfterOpen::WriteGrantsThenRefresh`;
    /// before, here directly, the repaint after the `match` for every change).
    fn persist_grant_change(&mut self, origin: &BrowserOrigin, change: GrantChange) {
        match change {
            GrantChange::Revoked => {
                self.revoke_waiting(origin, yw_core::policy::Family::Evm);
                self.after_pending_open(AfterOpen::WriteGrantsThenRefresh);
            }
            GrantChange::SolRevoked => {
                self.revoke_waiting(origin, yw_core::policy::Family::Solana);
                self.after_pending_open(AfterOpen::WriteGrantsThenRefresh);
            }
            GrantChange::BtcRevoked => {
                self.revoke_waiting(origin, yw_core::policy::Family::Bitcoin);
                self.after_pending_open(AfterOpen::WriteGrantsThenRefresh);
            }
            GrantChange::Chain(_) => {
                let now = self.clock.now_ms();
                let write = self
                    .browser
                    .as_mut()
                    .is_some_and(|browser| browser.grant_write.note_chain_switch(now));
                if write {
                    self.write_grants();
                }
                self.refresh();
            }
        }
    }

    /// Waiting signing items of `origin` and `family` end `Revoked` (4100, spec/05 §4.5); a shown
    /// one closes, and so does an approved request still waiting for its `YubiKey` PIN whose grant
    /// is gone (2026-11-13, [`Self::card_site_check`]; a card job past its PIN finishes and its
    /// answer checks the grant again).
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
        // 2026-11-20 (S4 P9): the card step's check runs after the next window's open is
        // answered when one is asked for (`AfterOpen`; before, right after `show_next_approval`).
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
            self.show_next_approval_then(AfterOpen::CardSiteCheck);
        } else {
            self.card_site_check();
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

    /// S13 `모든 사이트 연결 해제`: every extension site of the three families and every
    /// `WalletConnect` session (`wc_sessionDelete`, the dApp side ends too).
    pub fn disconnect_all_sites(&mut self) {
        self.wc_disconnect_all();
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
    /// grant's (security review L4(b); the shown window closes, as on a chain deletion), and so
    /// does an approved one still waiting for its `YubiKey` PIN (2026-11-13).
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
        // 2026-11-20 (S4 P9): as in `revoke_waiting`, the card step's check follows the next
        // window's answered open (`AfterOpen`).
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
            self.show_next_approval_then(AfterOpen::CardSiteCheck);
        } else {
            self.card_site_check();
        }
    }

    /// A removed imported EVM key or recovery phrase took `accounts` with it: each address
    /// leaves the grants ([`Self::account_removed_from_sites`]) unless another visible account
    /// still has it — the same key imported beside a derived, added-phrase or `YubiKey` account
    /// (spec/02 §8.4) — like the Solana and Bitcoin helpers keep a key or address the wallet
    /// still shows (spec/05 §4.1). `leaving` names the account-list rows that go with the
    /// removal (meta still lists them).
    pub(crate) fn evm_key_removed_from_sites(
        &mut self,
        accounts: &[Address],
        leaving: impl Fn(EvmAccountPref) -> bool,
    ) {
        let held: Vec<Address> = self
            .account_rows()
            .into_iter()
            .filter(|(pref, ..)| !leaving(*pref))
            .filter_map(|(_, _, address, _)| yw_core::evm::address::parse_address(&address).ok())
            .collect();
        for account in accounts.iter().filter(|account| !held.contains(account)) {
            self.account_removed_from_sites(account);
        }
    }

    /// The `YubiKey` accounts of the meta in memory while the dispatcher holds the grants (a
    /// verified, unlocked session with its meta); `None` otherwise. Taken before a meta reload
    /// replaces the document, for [`Self::hardware_accounts_reloaded`].
    pub(crate) fn hardware_site_accounts(&self) -> Option<HardwareSiteAccounts> {
        let loaded = self
            .browser
            .as_ref()
            .is_some_and(|browser| browser.unlocked)
            && self.vault_view() == VaultView::Unlocked;
        loaded
            .then(|| self.meta.as_ref().map(HardwareSiteAccounts::of))
            .flatten()
    }

    /// A meta reload replaced the document: the `YubiKey` accounts of `before` that it no longer
    /// has — the key worker's reconcile dropped them because no enrolled card holds their key
    /// any more (a card record removed, a card cleared or re-slotted, spec/10 §13) — leave every
    /// dApp grant like a hidden or removed account (spec/05 §4.1, §4.9): `accountsChanged`,
    /// `solAccountsChanged([])`, `btcAccountsChanged([])`, waiting signing items `Revoked`, meta
    /// written. The worker already pruned the stored grants, but the dispatcher keeps its own:
    /// it would go on answering `eth_accounts` with the gone account, write it back, and use it
    /// again once the same card is enrolled. An address or key another visible account still
    /// has (a backup card, the same key imported or derived) stays connected.
    pub(crate) fn hardware_accounts_reloaded(&mut self, before: Option<HardwareSiteAccounts>) {
        let Some(before) = before else {
            return;
        };
        let Some(now) = self.hardware_site_accounts() else {
            return;
        };
        let evm: Vec<Address> = before
            .evm
            .into_iter()
            .filter(|account| !now.evm.contains(account))
            .collect();
        if !evm.is_empty() {
            self.evm_key_removed_from_sites(&evm, |_| false);
        }
        for public in before.sol.iter().filter(|public| !now.sol.contains(public)) {
            self.sol_account_removed_from_sites(public);
        }
        let btc: Vec<String> = before
            .btc
            .into_iter()
            .filter(|address| !now.btc.contains(address))
            .collect();
        if !btc.is_empty() {
            self.btc_addresses_removed_from_sites(&btc);
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
        // The injected clock (2026-11-19, S4 B1a; before, `SystemTime` with a `cfg(test)`
        // approval test clock read).
        let now = self.clock.now_unix_ms();
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

    /// Whether the EVM grant of `signer.origin` still names `signer.account` (spec/05 §4.5: a
    /// signature or transaction hash goes to the site only then; empty while locked).
    pub(crate) fn evm_grant_holds(&self, signer: &SiteSigner) -> bool {
        self.grant_of(&signer.origin)
            .is_some_and(|grant| grant.allows(&signer.account))
    }

    /// Whether the site `waiter` answers may still get a signature from the signer it names
    /// (spec/05 §4.5, 2026-11-13: every dApp signature, not only Solana transactions); an app
    /// send has no site.
    pub(crate) fn waiter_grant_holds(&self, waiter: &SignWaiter) -> bool {
        match waiter {
            SignWaiter::App => true,
            SignWaiter::Tx(_, signer) | SignWaiter::Message(_, signer) => {
                self.evm_grant_holds(signer)
            }
            SignWaiter::Chain(_, answer) => self.chain_grant_holds(answer),
        }
    }

    /// `SignEvm` finished: a dApp transaction waits for its broadcast; a failure answers -32603.
    pub(crate) fn browser_tx_signed(&mut self, ticket: SignTicket, result: Result<[u8; 32], ()>) {
        if let Some(SignWaiter::Tx(reply, signer)) = self.take_sign_waiter(ticket) {
            match result {
                Ok(hash) => {
                    if let Some(browser) = self.browser.as_mut() {
                        browser.broadcasts.insert(hash, (reply, signer));
                    }
                }
                Err(()) => self.respond(&reply, Err(ProviderError::Internal)),
            }
        }
    }

    /// `SignMessage` finished (a lock-cancelled one answers 4001, spec/04 §1.2). The signature
    /// goes out only while the site's grant still names the account; a site disconnected (or the
    /// account hidden) meanwhile gets 4100 and the signature is dropped (spec/05 §4.5,
    /// 2026-11-13).
    pub(crate) fn browser_message_signed(&mut self, signed: MessageSigned) {
        if self.hc_message_signed(&signed) {
            return;
        }
        if signed.result == Err(MessageSignFailure::Locked) {
            self.evm_sign_locked(signed.ticket);
            return;
        }
        if let Some(SignWaiter::Message(reply, signer)) = self.take_sign_waiter(signed.ticket) {
            match signed.result {
                Ok(_) if !self.evm_grant_holds(&signer) => {
                    logging::info("browser", "site.grant_gone", &[]);
                    self.respond(&reply, Err(ProviderError::Unauthorized));
                }
                Ok(signature) => self.respond(&reply, Ok(hex_signature(&signature))),
                Err(failure) => {
                    self.respond(&reply, Err(ProviderError::Internal));
                    // Like a dApp transaction's failure (`on_signed`), the app says why nothing
                    // was signed (the page only gets -32603). A card failure has the card
                    // step's own banner.
                    if let MessageSignFailure::Sign(error) = failure {
                        let lang = self.settings.language;
                        let reason = match error {
                            yw_core::evm::sign::SignError::Vault(error) => {
                                crate::errors::vault_code(error).text_in(lang)
                            }
                            other => other.text_in(lang),
                        };
                        self.banner(None, text::MESSAGE_SIGN_FAILED.fill(lang, [&reason]));
                        self.refresh();
                    }
                }
            }
        }
    }

    /// A consumed signing job was cancelled by the lock: 4001 (spec/04 §1.2).
    pub(crate) fn browser_sign_cancelled(&mut self, ticket: SignTicket) {
        if self.hc_sign_cancelled(ticket) {
            let _ = self.take_sign_waiter(ticket);
            return;
        }
        if let Some(reply) = self
            .take_sign_waiter(ticket)
            .and_then(|waiter| waiter.reply())
        {
            self.respond(&reply, Err(ProviderError::UserRejected));
        }
    }

    /// The broadcast of a dApp transaction finished (spec/05 §5, spec/03 §4.4, §11.6): the hash
    /// when the node has it or an automatic re-broadcast follows; -32603 `Transaction broadcast
    /// failed.` only when nothing will send it without the user (refused, other hash, chain
    /// mismatch — all journaled as manual-resend-only). While unlocked the answer needs the
    /// signer's grant: a site disconnected (or the account hidden) since the approval gets 4100
    /// instead of the hash — the journaled transaction is sent all the same, like a Solana dApp
    /// send (spec/05 §4.5, spec/07 §20.8; 2026-11-13). While locked the grants are put away and
    /// nothing is checked (as for Solana, spec/07 §20.10-5).
    pub(crate) fn browser_broadcast(&mut self, tx_hash: [u8; 32], outcome: BroadcastOutcome) {
        let Some((reply, signer)) = self
            .browser
            .as_mut()
            .and_then(|browser| browser.broadcasts.remove(&tx_hash))
        else {
            return;
        };
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        if unlocked && !self.evm_grant_holds(&signer) {
            logging::info("browser", "site.grant_gone", &[]);
            self.respond(&reply, Err(ProviderError::Unauthorized));
            return;
        }
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
            // A WalletConnect session shows its claimed origin label (spec/13 §7).
            let text = match item {
                QueuedItem::Site(site) => self.site_origin_text(site),
                _ => continue,
            };
            if !origins.contains(&text) {
                origins.push(text);
            }
        }
        origins
    }
}

#[cfg(test)]
mod tests {
    use super::{GRANT_WRITE_INTERVAL_MS, GrantWrite};

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

/// The tests that build an `App` (2026-11-21, S4 W0, spec/09 §2.1), in
/// `app/tests/browser.rs`: a child of this module, so that they keep its access.
#[cfg(test)]
#[path = "app/tests/browser.rs"]
mod app_tests;
