//! The opt-in received history on the UI thread (spec/04 §2.6, 2026-11-11): the switch
//! (`settings.json` `receivedHistory`, off by default), when each shown list is read, and what
//! the answers leave in memory (this run only; a lock forgets them).
//!
//! A list is read only while the switch is on, the wallet is unlocked, the main screen shows
//! that chain's card (its tab; `HyperCore` only while its card is open) and the main window is
//! not hidden or minimized: at most once per [`REFRESH_MS`], at once on tab entry and on the
//! card's `새로고침`. With the switch off nothing is queued.

use std::collections::{HashMap, HashSet};

use yw_core::bip32::path::BtcChain;

use crate::app::{App, AppMode, Screen};
use crate::meta::Tab;
use crate::network::NetworkId;
use crate::received::{
    Cursor, Fetched, Incoming, JobKind, ListKey, MAX_DUST_KEYS, MAX_ENTRIES, PENDING_MISS_MAX,
    REFRESH_MS, ReceivedEvent, ReceivedJob, RecvChain, TokenRef,
};
use crate::workers::rpc::RpcJob;

/// One list (chain, network and account) in memory.
#[derive(Debug, Default)]
pub struct RecvList {
    /// Listed transfers, newest first (at most [`MAX_ENTRIES`]).
    pub entries: Vec<Incoming>,
    /// Zero and dust transfers hidden so far (each counted once).
    pub dust: usize,
    dust_keys: HashSet<String>,
    /// Where the next read continues.
    pub cursor: Cursor,
    /// The job in flight.
    pub busy: Option<u64>,
    /// When the next automatic read is due (monotonic ms).
    pub next_ms: u64,
    /// A read has answered.
    pub loaded: bool,
    /// The last read's failure (fixed text).
    pub error: Option<String>,
    /// The endpoint cannot list received transfers (fixed line; no more automatic reads).
    pub unsupported: Option<&'static str>,
    /// The last read's note.
    pub note: Option<&'static str>,
    /// What this source cannot show (fixed muted line; automatic reads continue).
    pub limited: Option<&'static str>,
    /// Pending rows that went before confirming (replaced or dropped; each counted once).
    pub gone: usize,
    /// Pending rows removed without a definitive answer (neutral wording).
    pub dropped: usize,
    /// Keys counted in `gone` (`true`) or `dropped` (`false`), so a key that comes back is
    /// taken off its count again.
    gone_keys: HashMap<String, bool>,
    /// Bitcoin: the receive indices the last read answered completely.
    pub covered: Vec<u32>,
    /// Bitcoin: reads in a row that missed each pending row's status ([`Fetched::missed`]).
    misses: HashMap<String, u8>,
}

impl RecvList {
    /// Takes a read in (2026-11-13): new rows merged by key (a known row is replaced, e.g.
    /// pending → confirmed; a confirmed row never turns back into a pending one), newest first,
    /// at most [`MAX_ENTRIES`]; dust counted once per key. A pending row goes only when the
    /// read names it in [`Fetched::gone`] or [`Fetched::dropped`] (counted once per key; a key
    /// that comes back later is taken off the count). Before 2026-11-13 a Bitcoin read dropped
    /// every pending row it did not list (`full_view`), even after an address had failed.
    ///
    /// 2026-11-13 review: a pending row named in [`Fetched::missed`] on [`PENDING_MISS_MAX`]
    /// reads in a row (a listing reset the count) goes as `dropped`; an `unsupported` answer
    /// takes the pending rows and the coverage away with the section (they fed the balance
    /// card's "미확정 입금" line and hid the refresh banner before).
    pub fn apply(&mut self, fetched: Fetched) {
        self.loaded = true;
        self.error = None;
        self.note = fetched.note;
        if let Some(text) = fetched.unsupported {
            self.unsupported = Some(text);
            self.entries.retain(|entry| !entry.pending);
            self.covered.clear();
            self.misses.clear();
            return;
        }
        self.unsupported = None;
        self.limited = fetched.limited;
        self.cursor = fetched.cursor;
        self.covered = fetched.covered;
        for key in fetched.found.dust {
            if self.dust_keys.len() < MAX_DUST_KEYS && self.dust_keys.insert(key) {
                self.dust = self.dust.saturating_add(1);
            }
        }
        let mut dropped = fetched.dropped;
        for key in fetched.missed {
            if !self
                .entries
                .iter()
                .any(|entry| entry.pending && entry.key == key)
            {
                continue;
            }
            let count = self.misses.entry(key.clone()).or_insert(0);
            *count = count.saturating_add(1);
            if *count >= PENDING_MISS_MAX {
                dropped.push(key);
            }
        }
        let removals = fetched
            .gone
            .into_iter()
            .map(|key| (key, true))
            .chain(dropped.into_iter().map(|key| (key, false)));
        for (key, definitive) in removals {
            self.misses.remove(&key);
            let before = self.entries.len();
            self.entries
                .retain(|entry| !(entry.pending && entry.key == key));
            if self.entries.len() == before {
                continue;
            }
            if self.gone_keys.len() < MAX_DUST_KEYS && !self.gone_keys.contains_key(&key) {
                self.gone_keys.insert(key, definitive);
                if definitive {
                    self.gone = self.gone.saturating_add(1);
                } else {
                    self.dropped = self.dropped.saturating_add(1);
                }
            }
        }
        for mut entry in fetched.found.entries {
            // Listed again: its misses start over.
            self.misses.remove(&entry.key);
            // Back after all (another backend's mempool, or confirmed): off the count.
            match self.gone_keys.remove(&entry.key) {
                Some(true) => self.gone = self.gone.saturating_sub(1),
                Some(false) => self.dropped = self.dropped.saturating_sub(1),
                None => {}
            }
            match self.entries.iter_mut().find(|known| known.key == entry.key) {
                // A lagging or forked view never turns a confirmed row back (D32).
                Some(known) if !known.pending && entry.pending => {}
                Some(known) => {
                    if entry.pending {
                        for index in &known.via {
                            if !entry.via.contains(index) {
                                entry.via.push(*index);
                            }
                        }
                    }
                    *known = entry;
                }
                None => self.entries.push(entry),
            }
        }
        self.entries
            .sort_by_key(|entry| core::cmp::Reverse(entry.order()));
        self.entries.truncate(MAX_ENTRIES);
    }

    /// The sum of the pending rows' amounts (sats, zats) for the "미확정 입금" line next to the
    /// balance; `None` without pending rows. Display only: never part of a balance.
    #[must_use]
    pub fn pending_sum(&self) -> Option<u64> {
        let mut pending = self.entries.iter().filter(|entry| entry.pending).peekable();
        pending.peek()?;
        Some(
            pending
                .map(|entry| entry.amount_units)
                .fold(0, u64::saturating_add),
        )
    }

    /// Whether the list has `key` as a row or counted it as gone or dropped.
    #[must_use]
    pub fn knows(&self, key: &str) -> bool {
        self.gone_keys.contains_key(key) || self.entries.iter().any(|entry| entry.key == key)
    }

    /// The list's pending rows (what a read must resolve).
    #[must_use]
    pub fn pending_rows(&self) -> Vec<Incoming> {
        self.entries
            .iter()
            .filter(|entry| entry.pending)
            .cloned()
            .collect()
    }
}

/// The received-history state of the run.
#[derive(Debug, Default)]
pub struct ReceivedUi {
    /// Lists by key.
    pub(crate) lists: HashMap<ListKey, RecvList>,
    /// Job counter (stays monotonic across locks).
    pub(crate) job: u64,
    /// The tab of the last tick (a change reads the new tab's lists at once).
    pub(crate) last_tab: Option<Tab>,
    /// `받은 내역 n건 더 보기` per chain slot (this run).
    pub(crate) expanded: [bool; 5],
}

/// A Zcash snapshot's unconfirmed outputs (`height: None`) summed per txid: those of others
/// (deposits, txid not in `own_txids`) and the sum of our own (journal) ones, our change.
#[must_use]
pub fn zec_unconfirmed(
    snapshot: &crate::zec::work::ZecSnapshot,
    own_txids: &[String],
) -> (Vec<(String, u64)>, u64) {
    let mut others: Vec<(String, u64)> = Vec::new();
    let mut own = 0_u64;
    for utxo in snapshot.utxos.iter().filter(|utxo| utxo.height.is_none()) {
        let txid = yw_core::zec::tx::txid_display(&utxo.outpoint.txid);
        if own_txids.contains(&txid) {
            own = own.saturating_add(utxo.value);
        } else if let Some(slot) = others.iter_mut().find(|(known, _)| *known == txid) {
            slot.1 = slot.1.saturating_add(utxo.value);
        } else {
            others.push((txid, utxo.value));
        }
    }
    (others, own)
}

/// When a list that had nothing to ask is looked at again (no request in between).
const RETRY_MS: u64 = 5_000;

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// The chain whose card a `새로고침` id belongs to.
fn refresh_chain(id: u16) -> Option<RecvChain> {
    Some(match id {
        crate::ui::screens_evm::ids::REFRESH => RecvChain::Evm,
        crate::ui::screens_sol::ids::REFRESH => RecvChain::Sol,
        crate::ui::screens_btc::ids::REFRESH => RecvChain::Btc,
        crate::ui::screens_hypercore::ids::REFRESH => RecvChain::Hc,
        crate::ui::screens_zec::ids::REFRESH => RecvChain::Zec,
        _ => return None,
    })
}

impl App {
    /// The chains whose activity cards the main screen shows now (by tab; the `HyperCore` card
    /// on the EVM tab while it is shown and open).
    #[must_use]
    pub fn received_shown(&self) -> Vec<RecvChain> {
        match self.meta.as_ref().map(|meta| meta.prefs.tab) {
            Some(Tab::Evm) => {
                let mut shown = vec![RecvChain::Evm];
                if self.hc_visible() && (!self.hc_foldable() || self.hypercore.unfolded) {
                    shown.push(RecvChain::Hc);
                }
                shown
            }
            Some(Tab::Sol) => vec![RecvChain::Sol],
            Some(Tab::Btc) => vec![RecvChain::Btc],
            Some(Tab::Zec) => vec![RecvChain::Zec],
            None => Vec::new(),
        }
    }

    /// The explorer network of `chain`'s current list (its `ListKey::network` text).
    #[must_use]
    pub fn received_explorer_net(&self, chain: RecvChain) -> Option<crate::explorer::ExplorerNet> {
        self.received_key(chain)
            .and_then(|key| crate::explorer::ExplorerNet::parse(&key.network))
    }

    /// The list `chain`'s card shows now: its network and selected account (`None` when the
    /// card has no usable account).
    #[must_use]
    pub fn received_key(&self, chain: RecvChain) -> Option<ListKey> {
        let key = |network: String, account: String| {
            Some(ListKey {
                chain,
                network,
                account,
            })
        };
        match chain {
            RecvChain::Evm => {
                let (account, ..) = self.selected_account()?;
                key(
                    NetworkId::Eip155(self.settings.evm_chain_id).to_string(),
                    account.to_lower_hex(),
                )
            }
            RecvChain::Hc => {
                if !self.hc_visible() {
                    return None;
                }
                let (account, ..) = self.selected_account()?;
                key(
                    format!("hypercore:{}", self.hc_network().as_str()),
                    account.to_lower_hex(),
                )
            }
            RecvChain::Sol => {
                let (_, _, account) = self.sol_selected()?;
                key(
                    crate::workers::journal::sol_network(self.sol_cluster()).to_string(),
                    account.to_base58(),
                )
            }
            RecvChain::Btc => {
                let ctx = self.btc_ctx();
                ctx.gate().ok()?;
                let first = ctx.btc_meta()?.address(BtcChain::Receive, 0).ok()?;
                key(
                    crate::btc::network_id(ctx.net()).to_string(),
                    first.as_str().to_owned(),
                )
            }
            RecvChain::Zec => {
                if !self.settings.zcash.enabled {
                    return None;
                }
                let account = self.zec_account()?;
                key(
                    NetworkId::Zcash(account.network).to_string(),
                    account.address(),
                )
            }
        }
    }

    /// The tokens the EVM read asks for: the token card's tokens the user did not hide.
    #[must_use]
    pub fn received_tokens(&self, chain_id: u64) -> Vec<TokenRef> {
        self.evm_token_rows(chain_id)
            .into_iter()
            .filter(|row| !self.evm_token_hidden(chain_id, &row.address))
            .map(|row| TokenRef {
                address: row.address,
                symbol: row.ticker,
                decimals: row.decimals,
            })
            .collect()
    }

    /// The chain part of a read of `chain`'s current list (`None`: no endpoint, no data yet).
    #[expect(clippy::too_many_lines, reason = "one arm per chain")]
    fn received_kind(&self, chain: RecvChain, user: bool) -> Option<JobKind> {
        match chain {
            RecvChain::Evm => {
                let chain_id = self.settings.evm_chain_id;
                let (owner, ..) = self.selected_account()?;
                Some(JobKind::Evm {
                    chain: Box::new(self.chain_job(chain_id).ok()?),
                    owner,
                    tokens: self.received_tokens(chain_id),
                })
            }
            RecvChain::Sol => {
                let (_, _, owner) = self.sol_selected()?;
                Some(JobKind::Sol {
                    endpoint: self.sol_endpoint(self.sol_cluster()).ok()?,
                    owner,
                })
            }
            RecvChain::Btc => {
                let pending = self.received_pending(chain);
                let rejected_before = self
                    .received_key(chain)
                    .and_then(|key| self.received.lists.get(&key))
                    .is_some_and(|list| list.cursor == Cursor::BtcRejected);
                let ctx = self.btc_ctx();
                ctx.gate().ok()?;
                let meta = ctx.btc_meta()?;
                let mut target = ctx.target().ok()?;
                target.meta_net = meta.network();
                let next = meta.receive_next();
                // 2026-11-13: the 받기 address and the newest issued one (a first deposit to a
                // new address shows before the refresh marks it used), the addresses the
                // refresh saw pending deposits on and those of the pending rows, then the
                // newest used ones. Before, only the newest 5 used addresses.
                let flagged: Vec<u32> = self
                    .btc
                    .pending_incoming_at
                    .iter()
                    .filter(|(chain, _)| *chain == BtcChain::Receive)
                    .map(|(_, index)| *index)
                    .collect();
                let via: Vec<u32> = pending
                    .iter()
                    .flat_map(|entry| entry.via.iter().copied())
                    .collect();
                let fetch = crate::received::btc::read_indices(
                    next,
                    meta.last_used_receive(),
                    meta.fixed_address() || meta.is_single(),
                    &flagged,
                    &via,
                );
                Some(JobKind::Btc {
                    target,
                    work: Box::new(crate::received::btc::BtcReceivedWork {
                        account: *meta.account(),
                        receive_count: next,
                        change_count: meta.change_next(),
                        fetch,
                        pending,
                        rejected_before,
                        chain: ctx.chain_input(),
                        trigger: if user {
                            crate::btc::Trigger::User
                        } else {
                            crate::btc::Trigger::Automatic
                        },
                    }),
                })
            }
            RecvChain::Hc => {
                let (account, ..) = self.selected_account()?;
                let network = self.hc_network();
                Some(JobKind::Hc {
                    endpoint: crate::hypercore::HcEndpoint {
                        network,
                        api: self.settings.hypercore_api(network),
                    },
                    account,
                    start_ms: now_unix_ms().saturating_sub(crate::received::hc::FIRST_WINDOW_MS),
                })
            }
            RecvChain::Zec => {
                let account = self.zec_account()?;
                // The last chain-checked refresh of this network (its tip and outputs).
                let snapshot = self
                    .zec
                    .snapshot
                    .as_ref()
                    .filter(|(network, _)| *network == account.network)
                    .map(|(_, snapshot)| snapshot)?;
                let own_txids: Vec<String> = self
                    .zec_records()
                    .iter()
                    .map(|record| record.txid_hex().to_ascii_lowercase())
                    .collect();
                let indexer = self.settings.zcash.indexer;
                Some(JobKind::Zec(Box::new(
                    crate::received::zec::ZecReceivedWork {
                        network: account.network,
                        url: self.apikeys.rpc_url(NetworkId::Zcash(account.network))?,
                        indexer,
                        address: account.address(),
                        tip: snapshot.chain.tip,
                        script: account.script_pubkey(),
                        own_outpoints: snapshot
                            .utxos
                            .iter()
                            .map(|utxo| {
                                (
                                    yw_core::zec::tx::txid_display(&utxo.outpoint.txid),
                                    utxo.outpoint.index,
                                )
                            })
                            .collect(),
                        bb_pending: if indexer == crate::settings::ZecIndexer::BbRest {
                            zec_unconfirmed(snapshot, &own_txids).0
                        } else {
                            Vec::new()
                        },
                        own_txids,
                        pending: self.received_pending(chain),
                        confirmed: self
                            .received_key(chain)
                            .and_then(|key| self.received.lists.get(&key))
                            .map(|list| {
                                list.entries
                                    .iter()
                                    .filter(|entry| !entry.pending)
                                    .map(|entry| entry.key.clone())
                                    .collect()
                            })
                            .unwrap_or_default(),
                        user,
                    },
                )))
            }
        }
    }

    /// The pending rows of `chain`'s current list (what the next read must resolve).
    fn received_pending(&self, chain: RecvChain) -> Vec<Incoming> {
        self.received_key(chain)
            .and_then(|key| self.received.lists.get(&key))
            .map(RecvList::pending_rows)
            .unwrap_or_default()
    }

    /// `chain`'s current list while the switch is on.
    #[must_use]
    pub fn received_list(&self, chain: RecvChain) -> Option<&RecvList> {
        if !self.settings.received_history {
            return None;
        }
        self.received_key(chain)
            .and_then(|key| self.received.lists.get(&key))
    }

    /// The pending sum of `chain`'s current list while the switch is on (`None`: off, no list or
    /// no pending row).
    #[must_use]
    pub fn received_pending_sum(&self, chain: RecvChain) -> Option<u64> {
        self.received_list(chain).and_then(RecvList::pending_sum)
    }

    /// Queues a read of `key` (its next automatic read is [`REFRESH_MS`] later either way).
    fn received_start(&mut self, chain: RecvChain, key: &ListKey, user: bool, now: u64) {
        let kind = self.received_kind(chain, user);
        let list = self.received.lists.entry(key.clone()).or_default();
        list.next_ms = now.saturating_add(REFRESH_MS);
        let cursor = list.cursor.clone();
        let Some(kind) = kind else {
            // Nothing to ask yet (no endpoint, Zcash before its first refresh): look again soon;
            // no request is made meanwhile.
            list.next_ms = now.saturating_add(RETRY_MS);
            return;
        };
        self.received.job = self.received.job.wrapping_add(1);
        let job = self.received.job;
        let sent = self.rpc(RpcJob::Received(Box::new(ReceivedJob {
            job,
            key: key.clone(),
            cursor,
            kind,
        })));
        if sent && let Some(list) = self.received.lists.get_mut(key) {
            list.busy = Some(job);
        }
    }

    /// Main-timer part: the shown lists that are due (nothing at all while the switch is off).
    pub fn received_tick(&mut self, now: u64) {
        if !self.settings.received_history
            || !matches!(self.mode, AppMode::Unlocked { .. })
            || self.screen != Screen::Main
            || self.main_hidden()
        {
            return;
        }
        let tab = self.meta.as_ref().map(|meta| meta.prefs.tab);
        let entered = tab != self.received.last_tab;
        self.received.last_tab = tab;
        for chain in self.received_shown() {
            let Some(key) = self.received_key(chain) else {
                continue;
            };
            let list = self.received.lists.entry(key.clone()).or_default();
            if list.busy.is_some() {
                continue;
            }
            if entered {
                list.next_ms = 0;
            }
            if list.unsupported.is_some() || now < list.next_ms {
                continue;
            }
            self.received_start(chain, &key, false, now);
        }
    }

    /// A card's `새로고침` (or the switch turned on): its list is read now (an unsupported one
    /// is tried again; Bitcoin as a user request, which runs during the 429 cooldown).
    fn received_now(&mut self, chain: RecvChain) {
        // Only for a card the main screen shows (S-HC's `새로고침` is not the card's).
        if !self.settings.received_history
            || !matches!(self.mode, AppMode::Unlocked { .. })
            || self.screen != Screen::Main
            || !self.received_shown().contains(&chain)
        {
            return;
        }
        let Some(key) = self.received_key(chain) else {
            return;
        };
        let list = self.received.lists.entry(key.clone()).or_default();
        list.unsupported = None;
        if list.busy.is_none() {
            self.received_start(chain, &key, true, yw_win::time::monotonic_ms());
        }
    }

    /// A read's answer (a stale job's is dropped).
    pub fn received_event(&mut self, event: ReceivedEvent) {
        let Some(list) = self.received.lists.get_mut(&event.key) else {
            return;
        };
        if list.busy != Some(event.job) {
            return;
        }
        list.busy = None;
        match event.result {
            Ok(fetched) => {
                let removed = fetched.gone.len().saturating_add(fetched.dropped.len());
                list.apply(fetched);
                if removed > 0 {
                    crate::logging::info(
                        "app",
                        "received.apply",
                        &[
                            ("chain", crate::logging::Field::Word(event.key.chain.word())),
                            (
                                "gone",
                                crate::logging::Field::Num(
                                    u64::try_from(removed).unwrap_or(u64::MAX),
                                ),
                            ),
                        ],
                    );
                }
            }
            Err(text) => list.error = Some(text),
        }
        self.refresh();
    }

    /// Lock: the lists go (the job counter stays, so a late answer matches nothing).
    pub fn received_lock(&mut self) {
        self.received = crate::app_received::ReceivedUi {
            job: self.received.job,
            ..crate::app_received::ReceivedUi::default()
        };
    }

    /// The switch, `더 보기`, `해시 복사`; a card's `새로고침` also reads its list now but is
    /// not consumed (the card's own handler runs too).
    pub fn on_received_command(&mut self, id: u16) -> bool {
        use crate::ui::screens_received::ids;
        if let Some(chain) = refresh_chain(id) {
            self.received_now(chain);
            return false;
        }
        if let Some(chain) = id
            .checked_sub(ids::TOGGLE_BASE)
            .and_then(RecvChain::of_slot)
            .filter(|_| id < ids::MORE_BASE)
        {
            let on = self
                .controls
                .checked(id)
                .unwrap_or(!self.settings.received_history);
            if on != self.settings.received_history {
                let mut settings = self.settings.clone();
                settings.received_history = on;
                self.save_settings(settings, crate::settings::RECEIVED_HISTORY_KEY);
                if self.settings.received_history {
                    self.received_now(chain);
                } else {
                    self.received_lock();
                }
                self.refresh();
            }
            return true;
        }
        if let Some(slot) = id
            .checked_sub(ids::MORE_BASE)
            .filter(|slot| *slot < ids::CHAINS)
        {
            if let Some(open) = self.received.expanded.get_mut(usize::from(slot)) {
                *open = !*open;
            }
            self.refresh();
            return true;
        }
        if let Some(offset) = id
            .checked_sub(ids::ROW_BASE)
            .filter(|offset| *offset < ids::ROW_SPAN)
        {
            let chain = RecvChain::of_slot(offset / ids::CHAIN_SPAN);
            let row = usize::from(offset % ids::CHAIN_SPAN / ids::ROW_STRIDE);
            let hash = chain
                .and_then(|chain| self.received_key(chain))
                .and_then(|key| self.received.lists.get(&key))
                .and_then(|list| list.entries.get(row))
                .map(|entry| entry.hash.clone())
                .filter(|hash| !hash.is_empty());
            // Offset 0: `해시 복사`; offset 1: `탐색기에서 열기`.
            if let Some(hash) = hash {
                if offset % ids::ROW_STRIDE == 0 {
                    self.copy_text(&hash);
                } else if let Some(net) = chain.and_then(|chain| self.received_explorer_net(chain))
                {
                    self.open_explorer_tx(net, &hash);
                }
            }
            return true;
        }
        false
    }
}
