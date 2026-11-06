//! EVM flows on the UI thread (M4): journal and chain state, balances, the send form (S11),
//! receive (S12), address book (S14), token add (S16), EVM chain settings (S15/S17), fee caps,
//! activity with speed-up/cancel/resend/discard, receipt tracking and the approval queue
//! (spec/03 §3.6–§5, spec/04 §2.6–§2.17, §3.7). RPC work goes to `yw-rpc`, signing and journal
//! commits to `yw-key`.

use std::collections::HashMap;

use yw_core::approval::{ApprovalId, ApprovalStore, TokenMeta};
use yw_core::bip32::path::AccountIndex;
use yw_core::evm::abi::erc20_transfer_data;
use yw_core::evm::address::Address;
use yw_core::evm::amount::{U256, format_amount, format_units};
use yw_core::evm::chain::{ChainInfo, GenesisRule, HYPEREVM_MAINNET, SimulationSupport};
use yw_core::journal::evm::{
    EvmRecord, FLAG_MANUAL_RESEND, FLAG_RPC_HASH_MISMATCH, GroupKey, Transition, groups, in_flight,
    latest_candidate,
};
use yw_core::vault::{EvmKeySource, FileKind, RecordId};
use yw_win::clipboard;

use crate::apikeys::{KeyName, mask_url};
use crate::app::{App, AppMode, Confirm, Screen, SettingsSection};
use crate::app_sol::{ReviewRefusal, SOL_REVIEW_CHANGED_TEXT as REVIEW_CHANGED_TEXT};
use crate::errors::ErrorCode;
use crate::events::{
    BalanceSnapshot, EvmSigned, JournalView, KeyJob, KeyOutcome, RpcEvent, SignFailure,
};
use crate::flow::evm::form::{
    AddressNote, KnownAddress, Quote, add_history, check_recipient, parse_amount, tx_recipients,
};
use crate::flow::evm::prepare::{ReplaceMode, ReplaceTarget, SendIntent};
use crate::flow::evm::track::{BroadcastOutcome, TrackInput, poll_interval_ms};
use crate::flow::evm::user_chain::{
    ChainForm, ProbeError, RpcSpec, ValidChainForm, validate_chain_form,
};
use crate::flow::evm::{
    ChainCheck, ChainJob, MismatchKind, chain_info, default_caps_text, fee_caps, parse_caps,
};
use crate::logging::{self, Field};
use crate::meta::{BookEntry, EvmAccountPref, ListError, TokenEntry};
use crate::network::NetworkId;
use crate::settings::{EvmChainDef, FeeCapsText, Settings, validate_fee_caps};
use crate::text::{hash32_text, is_valid_label, json_object, json_str};
use crate::ui::approval::{ApprovalQueue, QueueOutcome, QueueSource};
use crate::workers::rpc::RpcJob;

/// Balance refresh while S10 is visible (spec/04 §2.6).
pub const BALANCE_REFRESH_MS: u64 = 60_000;
/// Send-form validation after typing stops (spec/04 §2.7).
pub const SEND_DEBOUNCE_MS: u64 = 500;
/// Activity rows shown.
pub const MAX_ACTIVITY_ROWS: usize = 50;

/// The asset being sent.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SendAsset {
    /// The chain's native asset.
    #[default]
    Native,
    /// An ERC-20 token.
    Token(Address),
}

/// S11 state (inputs survive rejection and expiry, spec/04 §2.7).
#[derive(Clone, Debug, Default)]
pub struct SendForm {
    /// Asset.
    pub asset: SendAsset,
    /// Recipient text.
    pub to_text: String,
    /// Amount text.
    pub amount_text: String,
    /// `주소 전체를 직접 확인했습니다` (W-ADDR-3).
    pub ack: bool,
    /// Address-book picker open.
    pub picker: bool,
    /// Last edit (monotonic ms) awaiting validation.
    pub dirty_ms: Option<u64>,
    /// Parsed recipient and notes.
    pub recipient: Option<(Address, Vec<AddressNote>)>,
    /// Recipient error.
    pub recipient_error: Option<ErrorCode>,
    /// Parsed amount.
    pub amount: Option<U256>,
    /// Amount or funds error.
    pub amount_error: Option<ErrorCode>,
    /// Fee quote.
    pub quote: Option<Quote>,
    /// Quote error.
    pub quote_error: Option<ErrorCode>,
    /// Pending quote job.
    pub quote_job: u64,
    /// Pending code job.
    pub code_job: u64,
    /// Recipient has code (W-ADDR-4).
    pub contract: Option<bool>,
    /// `최대` requested: fill when the quote arrives.
    pub max_pending: bool,
    /// Message (T-APPR-EXPIRED, errors).
    pub info: Option<String>,
    /// `HyperEVM` system-address mismatch (spec/11 §5.5): blocks `검토`.
    pub system_error: Option<String>,
}

/// What a send approval is built from: the parsed recipient, the asset and the amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EvmReviewInputs {
    to: Option<Address>,
    asset: SendAsset,
    amount: Option<U256>,
}

impl EvmReviewInputs {
    fn of(form: &SendForm) -> Self {
        Self {
            to: form.recipient.as_ref().map(|(address, _)| *address),
            asset: form.asset,
            amount: form.amount,
        }
    }
}

/// Balances of one chain.
#[derive(Clone, Debug, Default)]
pub struct BalanceState {
    /// Last snapshot.
    pub snapshot: Option<BalanceSnapshot>,
    /// Last error (the old values stay, muted).
    pub error: Option<ErrorCode>,
    /// Outstanding job.
    pub job: u64,
}

/// Tracking state of one nonce group.
#[derive(Clone, Copy, Debug, Default)]
pub struct TrackState {
    /// Next poll (monotonic ms).
    pub next_ms: u64,
    /// A round is running.
    pub busy: bool,
    /// First `latest > nonce` observation.
    pub drop_seen: Option<u64>,
}

/// A queued app approval (send, speed-up, cancel).
#[derive(Clone, Debug)]
pub struct AppApproval {
    /// Chain.
    pub chain_id: u64,
    /// Signing account.
    pub account: Address,
    /// Key source.
    pub signer: EvmKeySource,
    /// What to send (replacements ignore it).
    pub intent: SendIntent,
    /// Replacement target.
    pub replace: Option<ReplaceTarget>,
}

/// A queued approval item: this app's own flows or a dApp request (spec/04 §3.1).
#[derive(Clone, Debug)]
pub enum QueuedItem {
    /// Send, speed-up, cancel.
    App(Box<AppApproval>),
    /// A dApp request (connect, signing, unlock-gated permission).
    Site(Box<crate::browser::SiteRequest>),
    /// A Solana transfer of this app (spec/07 §13).
    Sol(Box<crate::app_sol::SolApprovalItem>),
    /// A Bitcoin send or fee bump of this app (spec/08 §10).
    Btc(Box<crate::app_btc::BtcApprovalItem>),
    /// A Zcash transparent send of this app (spec/12 §9).
    Zec(Box<crate::app_zec::ZecApprovalItem>),
    /// A `HyperCore 전송` of this app (spec/11 §6).
    HyperCore(Box<crate::app_hypercore::HcApprovalItem>),
}

impl QueuedItem {
    /// The EVM chain the item signs on (dApp: the origin chain at request time); 0 for Solana.
    #[must_use]
    pub fn chain_id(&self) -> u64 {
        match self {
            Self::App(item) => item.chain_id,
            Self::Site(site) => site.chain_id,
            Self::Sol(_) | Self::Btc(_) | Self::Zec(_) | Self::HyperCore(_) => 0,
        }
    }

    /// The network of the item (logs).
    #[must_use]
    pub fn network(&self) -> NetworkId {
        match self {
            Self::App(item) => NetworkId::Eip155(item.chain_id),
            Self::Site(site) => NetworkId::Eip155(site.chain_id),
            Self::Sol(item) => crate::workers::journal::sol_network(item.cluster),
            Self::Btc(item) => item.network_id(),
            Self::Zec(item) => item.network_id(),
            Self::HyperCore(item) => NetworkId::Eip155(item.action.network.hyperevm_chain_id()),
        }
    }
}

/// The last sent transaction (S11 result).
#[derive(Clone, Copy, Debug)]
pub struct SentInfo {
    /// Chain.
    pub chain_id: u64,
    /// Hash.
    pub tx_hash: [u8; 32],
}

/// S17 state.
#[derive(Clone, Debug, Default)]
pub struct ChainFormState {
    /// Edited chain id.
    pub editing: Option<u64>,
    /// Inputs (the RPC field is read from its `ES_PASSWORD` edit on save).
    pub chain_id: String,
    /// Name.
    pub name: String,
    /// Symbol.
    pub symbol: String,
    /// Decimals.
    pub decimals: String,
    /// Explorer.
    pub explorer: String,
    /// Simulation.
    pub unsupported: bool,
    /// Message.
    pub message: Option<String>,
    /// Outstanding probe job.
    pub job: u64,
    /// Validated input awaiting the probe / the T-CHAIN-PIN confirmation.
    pub pending: Option<(ValidChainForm, Option<[u8; 32]>)>,
}

/// `다시 고정` state (spec/04 §2.17.4).
#[derive(Clone, Debug, Default)]
pub struct RepinState {
    /// Chain.
    pub chain_id: u64,
    /// The new hash (after the probe).
    pub new: Option<[u8; 32]>,
    /// Probe job.
    pub job: u64,
    /// T-CHAIN-REPIN-ACK.
    pub checked: bool,
    /// Message.
    pub message: Option<String>,
}

/// S14 form state.
#[derive(Clone, Debug, Default)]
pub struct BookForm {
    /// Edited entry (lowercase address).
    pub editing: Option<String>,
    /// Address text.
    pub address: String,
    /// Label text.
    pub label: String,
    /// Verified.
    pub verified: bool,
    /// Message.
    pub message: Option<String>,
}

/// S16 state.
#[derive(Clone, Debug, Default)]
pub struct TokenForm {
    /// Address text.
    pub address: String,
    /// Label text.
    pub label: String,
    /// Looked-up metadata.
    pub found: Option<(Address, TokenMeta)>,
    /// Lookup job.
    pub job: u64,
    /// Message.
    pub message: Option<String>,
}

/// Fee caps editing (spec/04 §2.11).
#[derive(Clone, Debug, Default)]
pub struct CapsForm {
    /// Chain being edited.
    pub chain_id: u64,
    /// maxFee (gwei).
    pub fee: String,
    /// Tip (gwei).
    pub tip: String,
    /// Total (native).
    pub total: String,
    /// Message.
    pub message: Option<String>,
}

/// EVM UI state.
#[derive(Debug, Default)]
pub struct EvmUi {
    /// Journal view while unlocked.
    pub journal: Option<JournalView>,
    /// Chain checks reported by the RPC worker.
    pub chain_checks: HashMap<u64, ChainCheck>,
    /// Balances per chain.
    pub balances: HashMap<u64, BalanceState>,
    /// Next balance refresh.
    pub next_balance_ms: u64,
    /// Tracking per nonce group.
    pub tracking: HashMap<GroupKey, TrackState>,
    /// Last broadcast outcome per hash (activity buttons and notes).
    pub notes: HashMap<[u8; 32], BroadcastOutcome>,
    /// S11.
    pub send: SendForm,
    /// Last sent.
    pub sent: Option<SentInfo>,
    /// Approval queue (app items and dApp requests).
    pub queue: ApprovalQueue<QueuedItem>,
    /// Issued approvals.
    pub store: ApprovalStore,
    /// Send slots `(chain, account)` (spec/03 §3.6).
    pub slots: Vec<(u64, Address)>,
    /// Job counter.
    pub next_job: u64,
    /// Signing-ticket counter (`SignEvm` / `SignMessage` waiters).
    pub next_ticket: u64,
    /// S17.
    pub chain_form: Option<ChainFormState>,
    /// 다시 고정.
    pub repin: Option<RepinState>,
    /// S14.
    pub book: BookForm,
    /// S16.
    pub token: TokenForm,
    /// Fee caps.
    pub caps: Option<CapsForm>,
    /// Group awaiting the discard confirmation.
    pub discard: Option<GroupKey>,
    /// User chain awaiting the delete confirmation.
    pub delete_chain: Option<u64>,
    /// User token awaiting the delete confirmation `(chain, contract)`.
    pub token_delete: Option<(u64, Address)>,
    /// The S10 token card lists the hidden tokens (`숨긴 토큰 n개 보기`; session only).
    pub show_hidden_tokens: bool,
    /// The S11 asset radios of hidden tokens are expanded (`숨긴 토큰 n개 보기`; session only).
    pub send_show_hidden: bool,
    /// The approval window.
    pub window: Option<crate::app_approval::ApprovalUi>,
    /// What the S12 receive QR encodes (session only, spec/04 §2.8).
    pub receive_qr: crate::ui::qr::EvmQrKind,
}

impl EvmUi {
    /// A fresh job id.
    pub fn job(&mut self) -> u64 {
        self.next_job = self.next_job.saturating_add(1);
        self.next_job
    }

    /// Forgets everything that needs the unlocked wallet (lock).
    pub fn clear_unlocked(&mut self) {
        self.journal = None;
        self.tracking.clear();
        self.balances.clear();
        self.notes.clear();
        self.slots.clear();
        self.sent = None;
        self.send = SendForm::default();
        self.book = BookForm::default();
        self.token = TokenForm::default();
        self.discard = None;
        self.token_delete = None;
        self.send_show_hidden = false;
    }

    /// Records of the journal view.
    #[must_use]
    pub fn records(&self) -> &[EvmRecord] {
        self.journal
            .as_ref()
            .map_or(&[], |journal| journal.records.as_slice())
    }

    /// EVM sending is stopped by a damaged journal record (spec/03 §5.1).
    #[must_use]
    pub fn journal_damaged(&self) -> bool {
        self.journal
            .as_ref()
            .is_some_and(|journal| journal.corrupt > 0)
    }

    /// Whether the chain is blocked (E-RPC-006 / E-CHN-008).
    #[must_use]
    pub fn blocked(&self, chain_id: u64) -> Option<MismatchKind> {
        match self.chain_checks.get(&chain_id) {
            Some(ChainCheck::Mismatch(kind)) => Some(*kind),
            _ => None,
        }
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn now_ms() -> u64 {
    yw_win::time::monotonic_ms()
}

/// `0x` + lowercase hash.
#[must_use]
pub fn hash_text(hash: &[u8; 32]) -> String {
    hash32_text(hash)
}

/// Restores the activity notes of journaled refusals (after a restart or unlock the in-memory
/// notes are gone, the record flags are not): a `Signed` record with `manual_resend` shows the
/// failed broadcast with `재전송`·`폐기`, one with `rpc_hash_mismatch` the other-hash note. Notes
/// of this session are kept.
pub fn seed_notes<S: std::hash::BuildHasher>(
    notes: &mut HashMap<[u8; 32], BroadcastOutcome, S>,
    records: &[EvmRecord],
) {
    for record in records
        .iter()
        .filter(|record| record.state == yw_core::journal::evm::TxState::Signed)
    {
        let note = if record.has_flag(FLAG_RPC_HASH_MISMATCH) {
            BroadcastOutcome::HashMismatch
        } else if record.has_flag(FLAG_MANUAL_RESEND) {
            BroadcastOutcome::Rejected { known: false }
        } else {
            continue;
        };
        notes.entry(record.tx_hash).or_insert(note);
    }
}

impl App {
    // ----- chain helpers ------------------------------------------------------------------

    /// The active chain's runtime info.
    #[must_use]
    pub fn active_chain(&self) -> Option<ChainInfo> {
        chain_info(&self.settings, self.settings.evm_chain_id)
    }

    /// A job's chain (definition, caps, URL), or E-KEY-005 without any call.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Key005`] for a missing endpoint, [`ErrorCode::App009`] for an unknown chain.
    pub fn chain_job(&self, chain_id: u64) -> Result<ChainJob, ErrorCode> {
        let info = chain_info(&self.settings, chain_id).ok_or(ErrorCode::App009)?;
        let url = self
            .apikeys
            .rpc_url(NetworkId::Eip155(chain_id))
            .ok_or(ErrorCode::Key005)?;
        let caps = fee_caps(&self.settings, &info);
        Ok(ChainJob { info, caps, url })
    }

    pub(crate) fn rpc(&self, job: RpcJob) -> bool {
        self.rpc_tx.as_ref().is_some_and(|tx| tx.send(job).is_ok())
    }

    /// The selected account: address and key source. A preference that names no listed account
    /// (a key-only wallet's default `{"index": 0}`, a removed key) falls back to the first row.
    #[must_use]
    pub fn selected_account(&self) -> Option<(Address, EvmKeySource, String)> {
        self.preferred_account().or_else(|| {
            let (pref, ..) = self.account_rows().into_iter().next()?;
            self.account_of(pref)
        })
    }

    /// The effective selection: the stored preference when it names a listed account, else the
    /// first row (what [`App::selected_account`] shows).
    #[must_use]
    pub fn selected_pref(&self) -> Option<EvmAccountPref> {
        let stored = self.meta.as_ref()?.prefs.evm_account;
        if self.account_of(stored).is_some() {
            return Some(stored);
        }
        self.account_rows()
            .into_iter()
            .next()
            .map(|(pref, ..)| pref)
    }

    /// The selected EVM account is a `YubiKey` account (no "개인키 보기", spec/10 §13).
    #[must_use]
    pub fn hardware_selected(&self) -> bool {
        matches!(self.selected_pref(), Some(EvmAccountPref::Hardware(_)))
    }

    fn preferred_account(&self) -> Option<(Address, EvmKeySource, String)> {
        self.account_of(self.meta.as_ref()?.prefs.evm_account)
    }

    fn account_of(&self, pref: EvmAccountPref) -> Option<(Address, EvmKeySource, String)> {
        let meta = self.meta.as_ref()?;
        match pref {
            EvmAccountPref::Index(index) => {
                let account = meta
                    .evm_accounts
                    .iter()
                    .find(|account| account.index == index)?;
                let address = yw_core::evm::address::parse_address(&account.address).ok()?;
                Some((
                    address,
                    EvmKeySource::Derived(AccountIndex::new(index).ok()?),
                    account.label.clone(),
                ))
            }
            EvmAccountPref::Record(id) => {
                let raw = meta
                    .evm_raw_accounts
                    .iter()
                    .find(|raw| raw.record_id == id)?;
                let address = yw_core::evm::address::parse_address(&raw.address).ok()?;
                Some((
                    address,
                    EvmKeySource::Raw(RecordId::from_bytes(id)),
                    raw.label.clone(),
                ))
            }
            EvmAccountPref::Hardware(index) => {
                let account = meta
                    .hw_accounts
                    .evm
                    .iter()
                    .find(|account| account.index == index)?;
                let address = yw_core::evm::address::parse_address(&account.address).ok()?;
                Some((
                    address,
                    EvmKeySource::Hardware(AccountIndex::new(index).ok()?),
                    account.label.clone(),
                ))
            }
        }
    }

    /// Visible own accounts `(address, label)`.
    #[must_use]
    pub fn own_accounts(&self) -> Vec<(Address, String)> {
        self.account_rows()
            .into_iter()
            .filter_map(|(_, label, address, _)| {
                yw_core::evm::address::parse_address(&address)
                    .ok()
                    .map(|address| (address, label))
            })
            .collect()
    }

    /// Address book, own accounts and sent history for the form notes. History entries (past
    /// recipients of every EVM chain: the journal records' `to` and decoded ERC-20 recipient,
    /// then the activity rows' counterparties) are compared for look-alikes only and are not
    /// offered by the picker; addresses already listed are not repeated.
    #[must_use]
    pub fn known_addresses(&self) -> Vec<KnownAddress> {
        let mut known: Vec<KnownAddress> = self
            .meta
            .as_ref()
            .map(|meta| {
                meta.book()
                    .into_iter()
                    .filter_map(|entry| {
                        Some(KnownAddress {
                            address: yw_core::evm::address::parse_address(&entry.address).ok()?,
                            name: entry.label,
                            verified: entry.verified,
                            mine: false,
                            history: false,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        known.extend(
            self.own_accounts()
                .into_iter()
                .map(|(address, label)| KnownAddress {
                    address,
                    name: label,
                    verified: false,
                    mine: true,
                    history: false,
                }),
        );
        let journal = self
            .evm
            .records()
            .iter()
            .filter_map(EvmRecord::tx)
            .flat_map(|tx| tx_recipients(&tx));
        add_history(&mut known, journal);
        if let Some(meta) = self.meta.as_ref() {
            let activity = meta
                .activity
                .iter()
                .filter(|(network, _)| network.starts_with("eip155:"))
                .flat_map(|(network, _)| meta.activity_of(network))
                .filter_map(|entry| yw_core::evm::address::parse_address(&entry.counterparty).ok());
            add_history(&mut known, activity);
        }
        known
    }

    /// Address-book names for approval facts.
    #[must_use]
    pub fn address_book_facts(&self) -> Vec<(Address, String)> {
        self.meta
            .as_ref()
            .map(|meta| {
                meta.book()
                    .into_iter()
                    .filter_map(|entry| {
                        Some((
                            yw_core::evm::address::parse_address(&entry.address).ok()?,
                            entry.label,
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Tokens of a chain: registry `(address, symbol or label, decimals, registered)` then meta
    /// tokens.
    #[must_use]
    pub fn chain_tokens(&self, chain_id: u64) -> Vec<(Address, String, u8, bool)> {
        let mut out: Vec<(Address, String, u8, bool)> = chain_info(&self.settings, chain_id)
            .map(|chain| {
                chain
                    .tokens
                    .iter()
                    .map(|token| {
                        // Pegged/bridged registry tokens show their label (spec/03 §1.2).
                        let shown = token.label.unwrap_or(token.symbol);
                        (token.address, shown.to_owned(), token.decimals, true)
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(meta) = self.meta.as_ref() {
            for entry in meta.tokens_of(&NetworkId::Eip155(chain_id).to_string()) {
                if let Ok(address) = yw_core::evm::address::parse_address(&entry.address)
                    && !out.iter().any(|(known, ..)| *known == address)
                {
                    out.push((address, entry.label, entry.decimals, false));
                }
            }
        }
        out
    }

    // ----- unlock, lock, events -----------------------------------------------------------

    /// After meta is loaded in `Unlocked`: read the journal (reconcile follows).
    pub fn evm_after_unlock(&mut self) {
        if matches!(self.mode, AppMode::Unlocked { .. }) {
            self.key(KeyJob::LoadJournal);
            self.evm.next_balance_ms = 0;
        }
    }

    /// Lock: close the approval window, invalidate approvals, drop unlocked state.
    pub fn evm_lock(&mut self) {
        self.close_approval_window();
        self.evm.store.invalidate_all();
        for (item, outcome) in self.evm.queue.lock() {
            self.approval_finished(&item.payload, outcome);
        }
        self.evm.clear_unlocked();
        self.hypercore.clear_unlocked();
    }

    /// Key worker outcomes of the EVM flows.
    pub fn evm_key_outcome(&mut self, outcome: KeyOutcome) {
        match outcome {
            KeyOutcome::Journal(Ok(view)) => {
                if view.corrupt > 0 {
                    self.banner(
                        Some(ErrorCode::Vlt006),
                        "거래 저널이 손상되어 보내기를 멈췄습니다. (E-VLT-006)".to_owned(),
                    );
                }
                if view.sol_corrupt > 0 {
                    self.banner(
                        Some(ErrorCode::Vlt006),
                        "거래 저널이 손상되어 보내기를 멈췄습니다. (E-VLT-006)".to_owned(),
                    );
                }
                if view.btc_corrupt > 0 {
                    self.banner(
                        Some(ErrorCode::Vlt006),
                        "거래 저널이 손상되어 보내기를 멈췄습니다. (E-VLT-006)".to_owned(),
                    );
                }
                seed_notes(&mut self.evm.notes, &view.records);
                self.evm.journal = Some(view);
                self.schedule_tracking(true);
                self.sol_schedule_tracking();
                self.btc_journal_changed();
                self.refresh();
            }
            KeyOutcome::Journal(Err(
                yw_core::error::VaultError::SidecarCorrupt(FileKind::Journal)
                | yw_core::error::VaultError::SidecarVaultMismatch(FileKind::Journal),
            )) => {
                self.banner(Some(ErrorCode::Vlt006), ErrorCode::Vlt006.text());
                self.set_screen(Screen::Confirm(Confirm::JournalCorrupt));
            }
            KeyOutcome::Journal(Err(error)) => {
                logging::warn(
                    "journal",
                    "journal.error",
                    &[("code", Field::Code(crate::errors::vault_code(error)))],
                );
            }
            KeyOutcome::ActivityMoved(rows) => {
                if let Some(meta) = self.meta.as_mut() {
                    for (network, entry) in &rows {
                        meta.upsert_activity(&network.to_string(), entry);
                    }
                }
                self.refresh();
            }
            KeyOutcome::SignedEvm(signed) => self.on_signed(signed),
            _ => {}
        }
    }

    fn on_signed(&mut self, signed: EvmSigned) {
        let EvmSigned { ticket, result } = signed;
        if result == Err(SignFailure::Locked) {
            self.evm_sign_locked(ticket);
            return;
        }
        self.browser_tx_signed(
            ticket,
            result.as_ref().map(|signed| signed.tx_hash).map_err(|_| ()),
        );
        match result {
            Ok(signed) => {
                self.release_slot(signed.chain_id, &signed.account);
                self.evm.sent = Some(SentInfo {
                    chain_id: signed.chain_id,
                    tx_hash: signed.tx_hash,
                });
                self.evm.send = SendForm::default();
                match self.chain_job(signed.chain_id) {
                    Ok(chain) => {
                        let _ = self.rpc(RpcJob::Broadcast {
                            chain,
                            raw: signed.raw,
                            tx_hash: signed.tx_hash,
                        });
                    }
                    Err(code) => self.error_banner(code),
                }
                if matches!(self.screen, Screen::Send) {
                    self.set_screen(Screen::SendResult);
                } else {
                    self.refresh();
                }
            }
            Err(failure) => {
                for (chain_id, account) in std::mem::take(&mut self.evm.slots) {
                    logging::info(
                        "app",
                        "slot.released",
                        &[
                            ("net", Field::Net(NetworkId::Eip155(chain_id))),
                            ("account", Field::Address(account.as_bytes())),
                        ],
                    );
                }
                let message = match failure {
                    SignFailure::Sign(yw_core::evm::sign::SignError::Vault(error)) => {
                        crate::errors::vault_code(error).text()
                    }
                    SignFailure::Sign(_) => ErrorCode::Tx003.text(),
                    SignFailure::JournalFull => ErrorCode::Tx005.text(),
                    SignFailure::JournalWrite(_) => {
                        format!("저널 저장 실패 — {}", ErrorCode::Vlt003.text())
                    }
                    SignFailure::Locked => ErrorCode::App009.text(),
                    SignFailure::Card(error) => error.to_string(),
                };
                logging::warn("app", "sign.failed", &[]);
                self.evm.send.info = Some(message.clone());
                self.banner(None, message);
                self.refresh();
            }
        }
    }

    /// A consumed signing job with `ticket` ended without a signature because of the lock: its
    /// dApp waiter gets 4001 (spec/04 §1.2).
    pub fn evm_sign_locked(&mut self, ticket: crate::events::SignTicket) {
        self.browser_sign_cancelled(ticket);
        self.evm_sign_cancelled();
    }

    /// A signing job ended without a signature because of the lock (signing jobs report
    /// through [`Self::evm_sign_locked`] with their ticket; this keeps the slot bookkeeping).
    pub fn evm_sign_cancelled(&mut self) {
        logging::info("app", "sign.aborted", &[("reason", Field::Word("locked"))]);
        self.evm.slots.clear();
    }

    pub(crate) fn release_slot(&mut self, chain_id: u64, account: &Address) {
        self.evm
            .slots
            .retain(|(chain, held)| !(*chain == chain_id && held == account));
    }

    /// RPC worker events of the EVM flows.
    pub fn evm_rpc_event(&mut self, event: RpcEvent) {
        match event {
            RpcEvent::Chain { chain_id, check } => self.on_chain_check(chain_id, check),
            RpcEvent::Balances {
                job,
                chain_id,
                result,
            } => {
                let state = self.evm.balances.entry(chain_id).or_default();
                if state.job != job {
                    return;
                }
                match result {
                    Ok(snapshot) => {
                        state.snapshot = Some(snapshot);
                        state.error = None;
                    }
                    Err(code) => state.error = Some(code),
                }
                self.on_balances_for_form();
                self.refresh();
            }
            RpcEvent::Quote { job, result } => self.on_quote(job, result),
            RpcEvent::Code {
                job,
                address,
                result,
            } => {
                if job == self.evm.send.code_job
                    && self
                        .evm
                        .send
                        .recipient
                        .as_ref()
                        .is_some_and(|(recipient, _)| *recipient == address)
                {
                    self.evm.send.contract = result.ok();
                    self.refresh();
                }
            }
            RpcEvent::TokenMeta { job, token, result } => {
                if job == self.evm.token.job {
                    match result {
                        Ok(meta) => {
                            if self.evm.token.label.is_empty()
                                && let Some(symbol) = meta
                                    .symbol
                                    .as_deref()
                                    .filter(|symbol| crate::text::is_symbol(symbol))
                            {
                                symbol.clone_into(&mut self.evm.token.label);
                            }
                            self.evm.token.found = Some((token, meta));
                            self.evm.token.message = None;
                        }
                        Err(code) => self.evm.token.message = Some(code.text()),
                    }
                    self.refresh();
                }
            }
            RpcEvent::Simulating { job, since_ms } => self.on_simulating(job, since_ms),
            RpcEvent::Prepared(result) => self.on_prepared(*result),
            RpcEvent::TypedFacts { job, facts, .. } => self.on_typed_facts(job, &facts),
            RpcEvent::Resimulated(result) => self.on_resimulated(*result),
            RpcEvent::Broadcast {
                chain_id,
                tx_hash,
                outcome,
                at_unix_ms,
            } => self.on_broadcast(chain_id, tx_hash, outcome, at_unix_ms),
            RpcEvent::Tracked { key, result } => {
                let now = now_ms();
                let interval = self
                    .group(&key)
                    .map_or(15_000, |group| poll_interval_ms(&group, now_unix_ms()));
                let state = self.evm.tracking.entry(key).or_default();
                state.busy = false;
                state.drop_seen = result.drop_seen_unix_ms;
                state.next_ms = now.saturating_add(interval);
                if result.invalid_receipts > 0 {
                    logging::warn(
                        "rpc",
                        "receipt.invalid",
                        &[("net", Field::Net(NetworkId::Eip155(key.chain_id)))],
                    );
                }
                if !result.transitions.is_empty() {
                    self.apply_transitions(result.transitions);
                }
            }
            RpcEvent::Probe { job, result } => self.on_probe(job, result),
            RpcEvent::Test { .. } => {}
            event @ (RpcEvent::SolBalances { .. }
            | RpcEvent::SolPreviewed(_)
            | RpcEvent::SolPreSigned { .. }
            | RpcEvent::SolTracked(_)
            | RpcEvent::SolScanned { .. }) => self.sol_rpc_event(event),
            RpcEvent::Btc(event) => self.btc_rpc_event(*event),
            RpcEvent::Zec(event) => self.zec_rpc_event(*event),
            RpcEvent::HyperCore(event) => self.hc_rpc_event(*event),
        }
    }

    pub(crate) fn on_chain_check(&mut self, chain_id: u64, check: ChainCheck) {
        if let ChainCheck::Verified {
            genesis,
            pinned_now: true,
        } = check
            && chain_id == HYPEREVM_MAINNET
            && !self
                .settings
                .evm_genesis_pins
                .iter()
                .any(|(id, _)| *id == chain_id)
        {
            let mut settings = self.settings.clone();
            settings.evm_genesis_pins.push((chain_id, genesis));
            self.save_settings(settings, "evmGenesisPins");
            logging::info(
                "app",
                "chain.genesis_pinned",
                &[
                    ("net", Field::Net(NetworkId::Eip155(chain_id))),
                    ("hash", Field::Hash(&genesis)),
                ],
            );
            let name = self.network_name(NetworkId::Eip155(chain_id));
            self.banner(
                None,
                format!(
                    "{name}의 제네시스 해시를 첫 연결에서 고정했습니다: {}",
                    hash32_text(&genesis)
                ),
            );
        }
        if let ChainCheck::Mismatch(kind) = check {
            let code = kind.code();
            if !self
                .evm
                .blocked(chain_id)
                .is_some_and(|known| known == kind)
            {
                logging::warn(
                    "app",
                    "chain.blocked",
                    &[
                        ("net", Field::Net(NetworkId::Eip155(chain_id))),
                        ("code", Field::Code(code)),
                    ],
                );
            }
        }
        if !matches!(check, ChainCheck::Unverified(_)) {
            self.evm.chain_checks.insert(chain_id, check);
        }
        self.refresh();
    }

    // ----- balances -----------------------------------------------------------------------

    /// Requests balances of the active chain (S10 entry, `새로고침`, every 60 s).
    pub fn refresh_balances(&mut self) {
        self.hc_refresh();
        if !matches!(self.mode, AppMode::Unlocked { .. }) {
            return;
        }
        let chain_id = self.settings.evm_chain_id;
        self.evm.next_balance_ms = now_ms().saturating_add(BALANCE_REFRESH_MS);
        let Ok(chain) = self.chain_job(chain_id) else {
            return;
        };
        let Some((owner, _, _)) = self.selected_account() else {
            return;
        };
        let accounts: Vec<Address> = self.own_accounts().into_iter().map(|(a, _)| a).collect();
        let tokens: Vec<Address> = self
            .chain_tokens(chain_id)
            .into_iter()
            .map(|(address, ..)| address)
            .collect();
        let job = self.evm.job();
        self.evm.balances.entry(chain_id).or_default().job = job;
        let _ = self.rpc(RpcJob::Balances {
            job,
            chain,
            accounts,
            tokens,
            token_owner: owner,
        });
    }

    /// Native balance of an account on a chain.
    #[must_use]
    pub fn native_balance(&self, chain_id: u64, account: &Address) -> Option<U256> {
        self.evm
            .balances
            .get(&chain_id)?
            .snapshot
            .as_ref()?
            .native
            .iter()
            .find_map(|(known, balance)| (known == account).then_some(*balance))
    }

    /// Token balance of the selected account.
    #[must_use]
    pub fn token_balance(&self, chain_id: u64, token: &Address) -> Option<U256> {
        self.evm
            .balances
            .get(&chain_id)?
            .snapshot
            .as_ref()?
            .tokens
            .iter()
            .find_map(|(known, balance)| (known == token).then_some(*balance))?
    }

    // ----- tracking -----------------------------------------------------------------------

    /// The current records of a nonce group.
    #[must_use]
    pub fn group(&self, key: &GroupKey) -> Option<Vec<EvmRecord>> {
        let records: Vec<EvmRecord> = self
            .evm
            .records()
            .iter()
            .filter(|record| record.key() == *key)
            .cloned()
            .collect();
        (!records.is_empty()).then_some(records)
    }

    /// Open nonce groups (any state but terminal) of the journal.
    #[must_use]
    pub fn open_groups(&self) -> Vec<(GroupKey, Vec<EvmRecord>)> {
        groups(self.evm.records())
            .into_iter()
            .filter(|(_, members)| members.iter().any(|record| !record.is_terminal()))
            .map(|(key, members)| (key, members.into_iter().cloned().collect()))
            .collect()
    }

    /// Ensures every open group is tracked; `now_too` polls them immediately (reconcile after
    /// unlock, spec/03 §5.4).
    pub fn schedule_tracking(&mut self, now_too: bool) {
        let now = now_ms();
        let open: Vec<GroupKey> = self.open_groups().into_iter().map(|(key, _)| key).collect();
        self.evm.tracking.retain(|key, _| open.contains(key));
        for key in open {
            let state = self.evm.tracking.entry(key).or_default();
            if now_too && !state.busy {
                state.next_ms = now;
            }
        }
    }

    /// Timer part of tracking: start due rounds (paused while locked, spec/03 §4.5).
    pub fn tick_tracking(&mut self, now: u64) {
        if !matches!(self.mode, AppMode::Unlocked { .. }) || self.evm.journal.is_none() {
            return;
        }
        let due: Vec<GroupKey> = self
            .evm
            .tracking
            .iter()
            .filter(|(_, state)| !state.busy && state.next_ms <= now)
            .map(|(key, _)| *key)
            .collect();
        for key in due {
            let Some(group) = self.group(&key) else {
                continue;
            };
            let Ok(chain) = self.chain_job(key.chain_id) else {
                if let Some(state) = self.evm.tracking.get_mut(&key) {
                    state.next_ms = now.saturating_add(60_000);
                }
                continue;
            };
            // A refusal seen this session whose `manual_resend` record flag is not committed
            // yet; once committed, tracking itself honours the flag (and still notices a node
            // that knows the transaction after all).
            let manual = group.iter().any(|record| {
                matches!(
                    self.evm.notes.get(&record.tx_hash),
                    Some(
                        BroadcastOutcome::Rejected { known: false }
                            | BroadcastOutcome::ChainMismatch
                    )
                ) && !record.has_flag(FLAG_MANUAL_RESEND)
            });
            let drop_seen = self
                .evm
                .tracking
                .get(&key)
                .and_then(|state| state.drop_seen);
            if self.rpc(RpcJob::Track {
                chain,
                input: TrackInput {
                    group,
                    drop_seen_unix_ms: drop_seen,
                    now_unix_ms: now_unix_ms(),
                    allow_rebroadcast: !manual,
                },
            }) && let Some(state) = self.evm.tracking.get_mut(&key)
            {
                state.busy = true;
            }
        }
    }

    /// Sends transitions to the key worker (only while unlocked: commits need the DEK).
    pub fn apply_transitions(&mut self, transitions: Vec<Transition>) {
        if matches!(self.mode, AppMode::Unlocked { .. }) && !transitions.is_empty() {
            self.key(KeyJob::JournalApply {
                transitions,
                now_unix_ms: now_unix_ms(),
            });
        }
    }

    fn on_broadcast(
        &mut self,
        chain_id: u64,
        tx_hash: [u8; 32],
        outcome: BroadcastOutcome,
        at_unix_ms: u64,
    ) {
        // A manual `재전송` that could not even re-check the chain leaves a manual-only record:
        // keep offering `재전송`·`폐기` rather than "서명됨".
        let manual_only = self
            .evm
            .records()
            .iter()
            .any(|record| record.tx_hash == tx_hash && record.has_flag(FLAG_MANUAL_RESEND));
        let note = match outcome {
            BroadcastOutcome::ChainUnverified if manual_only => {
                BroadcastOutcome::Rejected { known: false }
            }
            other => other,
        };
        self.evm.notes.insert(tx_hash, note);
        self.browser_broadcast(tx_hash, outcome);
        match outcome {
            BroadcastOutcome::HashMismatch => self.banner(
                None,
                "RPC가 다른 거래 해시를 반환했습니다. 자동으로 다시 보내지 않습니다. 활동에서 확인하세요."
                    .to_owned(),
            ),
            BroadcastOutcome::Rejected { known: false } => {
                self.banner(None, format!("{} (재전송·폐기)", ErrorCode::Tx004.text()));
            }
            BroadcastOutcome::ChainMismatch => self.error_banner(ErrorCode::Rpc006),
            _ => {}
        }
        if let Some(transition) = outcome.transition(tx_hash, at_unix_ms) {
            self.apply_transitions(vec![transition]);
        }
        let _ = chain_id;
        self.schedule_tracking(false);
        self.refresh();
    }

    // ----- timer --------------------------------------------------------------------------

    /// EVM part of the main timer.
    pub fn evm_tick(&mut self, now: u64) {
        self.tick_approval(now);
        self.tick_tracking(now);
        self.browser_tick(now);
        if matches!(self.mode, AppMode::Unlocked { .. })
            && matches!(self.screen, Screen::Main)
            && now >= self.evm.next_balance_ms
        {
            self.refresh_balances();
        }
        if let Some(changed) = self.evm.send.dirty_ms
            && now.saturating_sub(changed) >= SEND_DEBOUNCE_MS
        {
            self.evm.send.dirty_ms = None;
            self.validate_send(true);
        }
    }

    // ----- send form (S11) ----------------------------------------------------------------

    /// The send form's asset decimals and symbol.
    #[must_use]
    pub fn send_asset_meta(&self) -> (u8, String) {
        let chain_id = self.settings.evm_chain_id;
        match self.evm.send.asset {
            SendAsset::Native => self.active_chain().map_or((18, "ETH".to_owned()), |chain| {
                (chain.native_decimals, chain.native_symbol)
            }),
            SendAsset::Token(token) => self
                .chain_tokens(chain_id)
                .into_iter()
                .find(|(address, ..)| *address == token)
                .map_or((18, "?".to_owned()), |(_, symbol, decimals, _)| {
                    (decimals, symbol)
                }),
        }
    }

    /// In-flight transaction of the selected account on the active chain (D20).
    #[must_use]
    pub fn send_in_flight(&self) -> Option<EvmRecord> {
        let (account, ..) = self.selected_account()?;
        let chain_id = self.settings.evm_chain_id;
        let nonce = in_flight(self.evm.records(), chain_id, &account)?;
        let group: Vec<&EvmRecord> = self
            .evm
            .records()
            .iter()
            .filter(|record| {
                record.chain_id == chain_id && record.account == account && record.nonce == nonce
            })
            .collect();
        latest_candidate(&group)
            .or_else(|| group.last().copied())
            .cloned()
    }

    /// Opens S11.
    pub fn open_send(&mut self) {
        self.evm.send.info = None;
        self.set_screen(Screen::Send);
        self.refresh_balances();
    }

    fn intent(&self) -> Option<SendIntent> {
        let (recipient, _) = self.evm.send.recipient.as_ref()?;
        let amount = self.evm.send.amount?;
        Some(match self.evm.send.asset {
            SendAsset::Native => SendIntent {
                to: *recipient,
                value: amount,
                data: Vec::new(),
                access_list: Vec::new(),
                dapp_gas: None,
                dapp_nonce: None,
            },
            SendAsset::Token(token) => SendIntent {
                to: token,
                value: U256::ZERO,
                data: erc20_transfer_data(recipient, &amount),
                access_list: Vec::new(),
                dapp_gas: None,
                dapp_nonce: None,
            },
        })
    }

    /// Validates the form; `remote` also asks for the quote and the recipient code.
    pub fn validate_send(&mut self, remote: bool) {
        let Some((sender, ..)) = self.selected_account() else {
            return;
        };
        let (decimals, _) = self.send_asset_meta();
        let token = match self.evm.send.asset {
            SendAsset::Native => None,
            SendAsset::Token(token) => Some(token),
        };
        let known = self.known_addresses();
        let form = &mut self.evm.send;
        let previous = form.recipient.as_ref().map(|(address, _)| *address);
        match check_recipient(&form.to_text, &sender, token.as_ref(), &known) {
            Ok((address, notes)) => {
                if previous != Some(address) {
                    form.contract = None;
                    form.ack = false;
                }
                form.recipient = Some((address, notes));
                form.recipient_error = None;
            }
            Err(code) => {
                form.recipient = None;
                form.recipient_error = (!form.to_text.trim().is_empty()).then_some(code);
            }
        }
        match parse_amount(&form.amount_text, decimals) {
            Ok(amount) => {
                form.amount = Some(amount);
                form.amount_error = None;
            }
            Err(code) => {
                form.amount = None;
                form.amount_error = (!form.amount_text.is_empty()).then_some(code);
            }
        }
        let recipient = form.recipient.as_ref().map(|(address, _)| *address);
        let asset = form.asset;
        let system_error = recipient.and_then(|recipient| {
            self.hc_system_recipient_error(self.settings.evm_chain_id, &recipient, asset)
        });
        self.evm.send.system_error = system_error;
        if remote {
            self.request_quote();
        }
        self.on_balances_for_form();
        self.refresh();
    }

    fn request_quote(&mut self) {
        let chain_id = self.settings.evm_chain_id;
        let Some((from, ..)) = self.selected_account() else {
            return;
        };
        let Ok(chain) = self.chain_job(chain_id) else {
            self.evm.send.quote_error = Some(ErrorCode::Key005);
            return;
        };
        let intent = self.intent().unwrap_or(SendIntent {
            to: from,
            value: U256::ZERO,
            data: Vec::new(),
            access_list: Vec::new(),
            dapp_gas: None,
            dapp_nonce: None,
        });
        if let Some((recipient, _)) = self.evm.send.recipient.as_ref()
            && self.evm.send.asset == SendAsset::Native
            && self.evm.send.contract.is_none()
        {
            let address = *recipient;
            let job = self.evm.job();
            self.evm.send.code_job = job;
            let _ = self.rpc(RpcJob::Code {
                job,
                chain: chain.clone(),
                address,
            });
        }
        let job = self.evm.job();
        self.evm.send.quote_job = job;
        let _ = self.rpc(RpcJob::Quote {
            job,
            chain,
            from,
            intent,
        });
    }

    fn on_quote(&mut self, job: u64, result: Result<Quote, ErrorCode>) {
        if job != self.evm.send.quote_job {
            return;
        }
        match result {
            Ok(quote) => {
                self.evm.send.quote = Some(quote);
                self.evm.send.quote_error = None;
            }
            Err(code) => {
                self.evm.send.quote = None;
                self.evm.send.quote_error = Some(code);
            }
        }
        if self.evm.send.max_pending {
            self.evm.send.max_pending = false;
            self.fill_max();
        }
        self.on_balances_for_form();
        self.refresh();
    }

    /// Re-checks funds with the latest balances and quote (E-INP-012).
    fn on_balances_for_form(&mut self) {
        let chain_id = self.settings.evm_chain_id;
        let Some((account, ..)) = self.selected_account() else {
            return;
        };
        let (Some(amount), Some(quote)) = (self.evm.send.amount, self.evm.send.quote.clone())
        else {
            return;
        };
        let native = self.native_balance(chain_id, &account);
        let token_balance = match self.evm.send.asset {
            SendAsset::Native => None,
            SendAsset::Token(token) => self.token_balance(chain_id, &token),
        };
        if let Some(native) = native {
            let result = crate::flow::evm::form::check_funds(
                self.evm.send.asset == SendAsset::Native,
                &amount,
                &quote.max_total,
                &native,
                token_balance.as_ref(),
            );
            if let Err(code) = result {
                self.evm.send.amount_error = Some(code);
            }
        }
    }

    /// `최대`.
    pub fn fill_max(&mut self) {
        let chain_id = self.settings.evm_chain_id;
        let Some((account, ..)) = self.selected_account() else {
            return;
        };
        let (decimals, _) = self.send_asset_meta();
        let value = match self.evm.send.asset {
            SendAsset::Native => {
                let Some(quote) = self.evm.send.quote.clone() else {
                    self.evm.send.max_pending = true;
                    self.request_quote();
                    return;
                };
                let Some(balance) = self.native_balance(chain_id, &account) else {
                    return;
                };
                crate::flow::evm::form::max_native(&balance, &quote.max_total)
            }
            SendAsset::Token(token) => self
                .token_balance(chain_id, &token)
                .filter(|balance| !balance.is_zero())
                .ok_or(ErrorCode::Inp012),
        };
        match value {
            Ok(value) => {
                self.evm.send.amount_text = format_units(&value, decimals).replace(',', "");
                self.controls.set_text(
                    crate::ui::screens_evm::ids::SEND_AMOUNT_EDIT,
                    &self.evm.send.amount_text,
                );
                self.validate_send(true);
            }
            Err(code) => {
                self.evm.send.amount_error = Some(code);
                self.refresh();
            }
        }
    }

    /// Whether `검토` is enabled (spec/04 §2.7). Off while an edit awaits its debounced
    /// validation (`dirty_ms`): the shown result is not the input's yet.
    #[must_use]
    pub fn can_review(&self) -> bool {
        let form = &self.evm.send;
        let chain_id = self.settings.evm_chain_id;
        let look_alike = form
            .recipient
            .as_ref()
            .is_some_and(|(_, notes)| notes.iter().any(AddressNote::needs_ack));
        form.dirty_ms.is_none()
            && form.recipient.is_some()
            && form.amount.is_some()
            && form.amount_error.is_none()
            && form.recipient_error.is_none()
            && form
                .quote
                .as_ref()
                .is_some_and(|quote| quote.cap_violation.is_none())
            && (!look_alike || form.ack)
            && form.system_error.is_none()
            && self.evm.blocked(chain_id).is_none()
            && !self.evm.journal_damaged()
            && self.evm.journal.is_some()
            && self.send_in_flight().is_none()
            && matches!(self.mode, AppMode::Unlocked { .. })
    }

    /// The approval item of `검토` (spec/04 §2.7, the EVM counterpart of spec/07 §13.1-1). The
    /// form is validated again first, without any call, and the item is built from that fresh
    /// result only: when the fresh recipient, asset or amount differs from the last shown
    /// validation (an edit inside the 500 ms debounce), nothing is queued and the quote for the
    /// new input is asked for.
    ///
    /// # Errors
    ///
    /// [`ReviewRefusal`].
    pub fn review_item(&mut self) -> Result<AppApproval, ReviewRefusal> {
        let shown = EvmReviewInputs::of(&self.evm.send);
        self.evm.send.dirty_ms = None;
        self.validate_send(false);
        if EvmReviewInputs::of(&self.evm.send) != shown {
            self.request_quote();
            return Err(ReviewRefusal::Changed);
        }
        if !self.can_review() {
            return Err(ReviewRefusal::NotReady);
        }
        let (account, signer, _) = self.selected_account().ok_or(ReviewRefusal::NotReady)?;
        let intent = self.intent().ok_or(ReviewRefusal::NotReady)?;
        Ok(AppApproval {
            chain_id: self.settings.evm_chain_id,
            account,
            signer,
            intent,
            replace: None,
        })
    }

    /// `검토`: queue the approval built from a fresh validation and open A01 (spec/04 §2.7,
    /// §3.5).
    pub fn review_send(&mut self) {
        match self.review_item() {
            Ok(item) => self.enqueue_app(item),
            Err(ReviewRefusal::Changed) => {
                self.evm.send.info = Some(REVIEW_CHANGED_TEXT.to_owned());
                self.refresh();
            }
            Err(ReviewRefusal::NotReady) => {}
        }
    }

    /// Queues an app approval if its send slot is free (spec/03 §3.6).
    pub fn enqueue_app(&mut self, item: AppApproval) {
        if self
            .evm
            .slots
            .iter()
            .any(|(chain, held)| *chain == item.chain_id && *held == item.account)
        {
            self.evm.send.info = Some(ErrorCode::Tx002.text());
            self.refresh();
            return;
        }
        let slot = (item.chain_id, item.account);
        if self
            .evm
            .queue
            .enqueue(QueueSource::App, QueuedItem::App(Box::new(item)))
            .is_ok()
        {
            self.evm.slots.push(slot);
            self.evm.send.info = None;
            self.show_next_approval();
        } else {
            self.evm.send.info = Some(ErrorCode::App005.text());
            self.refresh();
        }
    }

    /// An approval ended (any outcome): free the slot unless it was approved (the slot is held
    /// until the `Signed` record, spec/03 §3.6).
    pub fn approval_finished(&mut self, item: &QueuedItem, outcome: QueueOutcome) {
        let item = match item {
            QueuedItem::App(item) => item,
            QueuedItem::Sol(item) => {
                self.sol_approval_finished(item, outcome);
                return;
            }
            QueuedItem::Btc(item) => {
                self.btc_approval_finished(item, outcome);
                return;
            }
            QueuedItem::Zec(item) => {
                self.zec_approval_finished(item, outcome);
                return;
            }
            QueuedItem::HyperCore(_) => {
                self.hc_approval_finished(outcome);
                return;
            }
            QueuedItem::Site(site) => {
                self.site_finished(site, outcome);
                logging::info(
                    "app",
                    "approval.finished",
                    &[("outcome", Field::Word(outcome_name(outcome)))],
                );
                self.refresh();
                return;
            }
        };
        if outcome != QueueOutcome::Approved {
            self.release_slot(item.chain_id, &item.account);
        }
        if outcome == QueueOutcome::Expired {
            self.evm.send.info = Some("승인 시간이 지났습니다. 다시 검토하세요.".to_owned());
        }
        logging::info(
            "app",
            "approval.finished",
            &[("outcome", Field::Word(outcome_name(outcome)))],
        );
        self.refresh();
    }

    // ----- activity actions ---------------------------------------------------------------

    /// Speed-up or cancel of an open group (spec/03 §4.6).
    pub fn replace_group(&mut self, key: GroupKey, mode: ReplaceMode) {
        let Some(group) = self.group(&key) else {
            return;
        };
        let signer = self
            .account_source(&key.account)
            .unwrap_or(EvmKeySource::Derived(AccountIndex::ZERO));
        self.enqueue_app(AppApproval {
            chain_id: key.chain_id,
            account: key.account,
            signer,
            intent: SendIntent {
                to: key.account,
                value: U256::ZERO,
                data: Vec::new(),
                access_list: Vec::new(),
                dapp_gas: None,
                dapp_nonce: None,
            },
            replace: Some(ReplaceTarget { mode, group }),
        });
    }

    pub(crate) fn account_source(&self, address: &Address) -> Option<EvmKeySource> {
        let meta = self.meta.as_ref()?;
        let text = address.to_lower_hex();
        if let Some(account) = meta
            .evm_accounts
            .iter()
            .find(|account| account.address == text)
        {
            return AccountIndex::new(account.index)
                .ok()
                .map(EvmKeySource::Derived);
        }
        meta.evm_raw_accounts
            .iter()
            .find(|raw| raw.address == text)
            .map(|raw| EvmKeySource::Raw(RecordId::from_bytes(raw.record_id)))
    }

    /// `재전송` of the newest candidate's exact bytes (no re-signing).
    pub fn resend_group(&mut self, key: GroupKey) {
        let Some(group) = self.group(&key) else {
            return;
        };
        let members: Vec<&EvmRecord> = group.iter().collect();
        let Some(latest) = latest_candidate(&members) else {
            return;
        };
        let (raw, hash) = (latest.raw.clone(), latest.tx_hash);
        if let Ok(chain) = self.chain_job(key.chain_id) {
            self.evm.notes.remove(&hash);
            let _ = self.rpc(RpcJob::Broadcast {
                chain,
                raw,
                tx_hash: hash,
            });
        }
    }

    /// `폐기` confirmed.
    pub fn discard_group(&mut self, key: GroupKey) {
        self.apply_transitions(vec![Transition::Discarded {
            key,
            at_unix_ms: now_unix_ms(),
        }]);
    }

    /// `해시 복사`.
    pub fn copy_text(&mut self, text: &str) {
        if let Some(main) = self.main.as_ref() {
            let ok = clipboard::set_text(main, text).is_ok();
            self.info = Some(if ok {
                "복사했습니다.".to_owned()
            } else {
                ErrorCode::Sec002.text()
            });
        }
        self.refresh();
    }

    // ----- address book (S14) ---------------------------------------------------------------

    /// `추가` / `저장` of the book form.
    pub fn save_book(&mut self) {
        let form = self.evm.book.clone();
        let address = match yw_core::evm::address::parse_address(form.address.trim()) {
            Ok(address) => address,
            Err(yw_core::evm::address::AddressError::BadChecksum) => {
                self.evm.book.message = Some(ErrorCode::Inp010.text());
                self.refresh();
                return;
            }
            Err(_) => {
                self.evm.book.message = Some(ErrorCode::Inp009.text());
                self.refresh();
                return;
            }
        };
        if !is_valid_label(&form.label) {
            self.evm.book.message = Some(ErrorCode::Inp017.text());
            self.refresh();
            return;
        }
        let entry = BookEntry {
            address: address.to_lower_hex(),
            label: form.label.clone(),
            verified: form.verified,
            added_at_unix_ms: now_unix_ms(),
        };
        let Some(meta) = self.meta.as_mut() else {
            return;
        };
        let result = if form.editing.is_some() {
            meta.update_book(&entry);
            Ok(())
        } else {
            meta.add_book(&entry)
        };
        match result {
            Ok(()) => {
                self.evm.book = BookForm::default();
                self.save_meta();
            }
            Err(ListError::Duplicate) => self.evm.book.message = Some(ErrorCode::Inp016.text()),
            Err(ListError::Full) => {
                self.evm.book.message = Some("주소록은 최대 500개입니다.".to_owned());
            }
        }
        self.refresh();
    }

    // ----- tokens (S16) ---------------------------------------------------------------------

    /// `조회`.
    pub fn lookup_token(&mut self) {
        let chain_id = self.settings.evm_chain_id;
        let text = self.evm.token.address.trim().to_owned();
        let Ok(token) = yw_core::evm::address::parse_address(&text) else {
            self.evm.token.message = Some(ErrorCode::Inp009.text());
            self.refresh();
            return;
        };
        match self.chain_job(chain_id) {
            Ok(chain) => {
                let job = self.evm.job();
                self.evm.token.job = job;
                self.evm.token.found = None;
                self.evm.token.message = Some("조회 중…".to_owned());
                let _ = self.rpc(RpcJob::TokenMeta { job, chain, token });
            }
            Err(code) => self.evm.token.message = Some(code.text()),
        }
        self.refresh();
    }

    /// `저장` of S16.
    pub fn save_token(&mut self) {
        let chain_id = self.settings.evm_chain_id;
        let Some((token, meta_found)) = self.evm.token.found.clone() else {
            return;
        };
        let Some(decimals) = meta_found.decimals else {
            self.evm.token.message =
                Some("decimals를 읽지 못해 추가할 수 없습니다. (E25)".to_owned());
            self.refresh();
            return;
        };
        let label = self.evm.token.label.clone();
        if !is_valid_label(&label) {
            self.evm.token.message = Some(ErrorCode::Inp017.text());
            self.refresh();
            return;
        }
        let entry = TokenEntry {
            address: token.to_lower_hex(),
            label,
            decimals,
        };
        let network = NetworkId::Eip155(chain_id).to_string();
        let Some(meta) = self.meta.as_mut() else {
            return;
        };
        match meta.add_token(&network, &entry) {
            Ok(()) => {
                self.evm.token = TokenForm::default();
                self.save_meta();
                self.set_screen(Screen::Main);
                self.refresh_balances();
            }
            Err(ListError::Duplicate) => {
                self.evm.token.message = Some("이미 추가한 토큰입니다.".to_owned());
                self.refresh();
            }
            Err(ListError::Full) => {
                self.evm.token.message =
                    Some("토큰은 네트워크당 100개, 전체 1,000개까지입니다.".to_owned());
                self.refresh();
            }
        }
    }

    // ----- EVM chains (S15/S17) -----------------------------------------------------------

    /// Opens S17 for adding (`None`) or editing a user chain.
    pub fn open_chain_form(&mut self, editing: Option<u64>) {
        if editing.is_none()
            && self.settings.evm_chains.len() >= crate::settings::MAX_CUSTOM_EVM_CHAINS
        {
            self.info = Some(ErrorCode::Chn006.text());
            self.refresh();
            return;
        }
        let mut form = ChainFormState {
            editing,
            decimals: "18".to_owned(),
            ..ChainFormState::default()
        };
        if let Some(id) = editing
            && let Some(def) = self
                .settings
                .evm_chains
                .iter()
                .find(|def| def.chain_id == id)
        {
            form.chain_id = id.to_string();
            form.name.clone_from(&def.name);
            form.symbol.clone_from(&def.symbol);
            form.decimals = def.decimals.to_string();
            form.explorer = def.explorer.clone().unwrap_or_default();
            form.unsupported = def.simulation == SimulationSupport::Unsupported;
        }
        self.evm.chain_form = Some(form);
        self.set_screen(Screen::ChainEdit);
    }

    /// `저장` of S17 (spec/04 §2.17.2).
    pub fn save_chain_form(&mut self, rpc_text: &str) {
        let Some(form) = self.evm.chain_form.clone() else {
            return;
        };
        let input = ChainForm {
            chain_id: &form.chain_id,
            name: &form.name,
            symbol: &form.symbol,
            decimals: &form.decimals,
            rpc: rpc_text,
            explorer: &form.explorer,
            simulation: if form.unsupported {
                SimulationSupport::Unsupported
            } else {
                SimulationSupport::Auto
            },
        };
        let valid = match validate_chain_form(&input, &self.settings, &self.apikeys, form.editing) {
            Ok(valid) => valid,
            Err(error) => {
                self.set_chain_message(error.message());
                return;
            }
        };
        let pinned = form.editing.and_then(|id| {
            self.settings
                .evm_chains
                .iter()
                .find(|def| def.chain_id == id)
                .map(|def| def.genesis_hash)
        });
        match valid.rpc.url().cloned() {
            None => self.commit_chain(&valid, None),
            Some(url) => {
                let job = self.evm.job();
                let chain_id = valid.chain_id;
                if let Some(state) = self.evm.chain_form.as_mut() {
                    state.job = job;
                    state.pending = Some((valid, None));
                    state.message = Some("체인을 확인하는 중…".to_owned());
                }
                let _ = self.rpc(RpcJob::Probe {
                    job,
                    url,
                    chain_id,
                    pinned,
                    check_base_fee: form.editing.is_none(),
                });
                self.refresh();
            }
        }
    }

    fn set_chain_message(&mut self, message: String) {
        if let Some(state) = self.evm.chain_form.as_mut() {
            state.message = Some(message);
        }
        self.refresh();
    }

    fn on_probe(&mut self, job: u64, result: Result<[u8; 32], ProbeError>) {
        if let Some(repin) = self.evm.repin.as_mut()
            && repin.job == job
        {
            match result {
                Ok(hash) => {
                    repin.new = Some(hash);
                    repin.message = None;
                    self.set_screen(Screen::Confirm(Confirm::ChainRepin));
                }
                Err(ProbeError::ChainId { .. }) => {
                    repin.message = Some(ErrorCode::Rpc006.text());
                    self.refresh();
                }
                Err(error) => {
                    repin.message = Some(error.message());
                    self.refresh();
                }
            }
            return;
        }
        let Some(state) = self.evm.chain_form.as_mut() else {
            return;
        };
        if state.job != job {
            return;
        }
        match result {
            Ok(genesis) => {
                let Some((valid, _)) = state.pending.take() else {
                    return;
                };
                if valid.rpc.url().is_some() && state.editing.is_none() {
                    state.pending = Some((valid, Some(genesis)));
                    state.message = None;
                    self.set_screen(Screen::Confirm(Confirm::ChainPin));
                } else {
                    self.commit_chain(&valid, Some(genesis));
                }
            }
            Err(error) => {
                state.pending = None;
                state.message = Some(error.message());
                self.refresh();
            }
        }
    }

    /// Writes a validated chain: the URL first (`apikeys.dpapi`), then `settings.json`
    /// (spec/04 §2.17.2-4).
    pub fn commit_chain(&mut self, valid: &ValidChainForm, genesis: Option<[u8; 32]>) {
        let existing = self
            .settings
            .evm_chains
            .iter()
            .find(|def| def.chain_id == valid.chain_id)
            .cloned();
        let Some(genesis) = genesis.or_else(|| existing.as_ref().map(|def| def.genesis_hash))
        else {
            return;
        };
        let network = NetworkId::Eip155(valid.chain_id);
        if let Some(url) = valid.rpc.url() {
            self.apikeys.set_rpc(network, url);
            if !self.save_apikeys() {
                return;
            }
            logging::info("app", "rpc.url_set", &[("net", Field::Net(network))]);
        }
        let mut def = existing.unwrap_or(EvmChainDef {
            chain_id: valid.chain_id,
            name: String::new(),
            symbol: String::new(),
            decimals: 18,
            quicknode_subdomain: None,
            alchemy_label: None,
            explorer: None,
            simulation: SimulationSupport::Auto,
            genesis_hash: genesis,
        });
        def.name.clone_from(&valid.name);
        def.symbol.clone_from(&valid.symbol);
        def.decimals = valid.decimals;
        def.explorer.clone_from(&valid.explorer);
        def.simulation = valid.simulation;
        if let RpcSpec::Template {
            template, entry, ..
        } = &valid.rpc
        {
            match template {
                crate::settings::RpcTemplate::QuickNode => {
                    def.quicknode_subdomain = Some(entry.clone());
                }
                crate::settings::RpcTemplate::Alchemy => def.alchemy_label = Some(entry.clone()),
                crate::settings::RpcTemplate::Manual => {}
            }
        }
        let mut settings = self.settings.clone();
        let editing = settings
            .evm_chains
            .iter()
            .position(|chain| chain.chain_id == def.chain_id);
        match editing {
            Some(index) => {
                if let Some(slot) = settings.evm_chains.get_mut(index) {
                    *slot = def;
                }
            }
            None => settings.evm_chains.push(def),
        }
        self.save_settings(settings, "evmChains");
        logging::info(
            "app",
            if editing.is_some() {
                "chain.edited"
            } else {
                "chain.added"
            },
            &[
                ("net", Field::Net(network)),
                ("hash", Field::Hash(&genesis)),
            ],
        );
        self.evm.chain_checks.remove(&valid.chain_id);
        self.reset_read_chain(valid.chain_id);
        let _ = self.rpc(RpcJob::ResetChain {
            chain_id: valid.chain_id,
        });
        self.evm.chain_form = None;
        self.info = Some("저장했습니다.".to_owned());
        self.set_screen(Screen::Settings(SettingsSection::Chains));
    }

    /// `삭제` of a user chain (spec/04 §2.17.3) — checks before the confirmation.
    pub fn request_delete_chain(&mut self, chain_id: u64) {
        if !matches!(self.mode, AppMode::Unlocked { .. }) {
            return;
        }
        let sending = self.evm.slots.iter().any(|(chain, _)| *chain == chain_id);
        let records = self.evm.records();
        let check = crate::flow::evm::user_chain::check_delete(
            chain_id,
            self.settings.evm_chain_id,
            records,
            sending,
        );
        if let Err(code) = check {
            self.info = Some(code.text());
            self.refresh();
            return;
        }
        self.evm.delete_chain = Some(chain_id);
        self.set_screen(Screen::Confirm(Confirm::ChainDelete));
    }

    /// Deletion confirmed: settings first, then the URL.
    pub fn delete_chain(&mut self, chain_id: u64) {
        let mut settings = self.settings.clone();
        settings
            .evm_chains
            .retain(|chain| chain.chain_id != chain_id);
        settings.fee_caps.retain(|(id, _)| *id != chain_id);
        self.save_settings(settings, "evmChains");
        let network = NetworkId::Eip155(chain_id);
        if self.apikeys.remove(KeyName::Rpc(network)) && self.save_apikeys() {
            logging::info("app", "rpc.url_deleted", &[("net", Field::Net(network))]);
        }
        logging::info("app", "chain.deleted", &[("net", Field::Net(network))]);
        self.evm.chain_checks.remove(&chain_id);
        let _ = self.rpc(RpcJob::ResetChain { chain_id });
        self.reset_read_chain(chain_id);
        self.chain_removed_from_sites(chain_id);
    }

    /// `다시 고정` (spec/04 §2.17.4): fetch the new block-0 hash.
    pub fn start_repin(&mut self, chain_id: u64) {
        let Some(url) = self.apikeys.rpc_url(NetworkId::Eip155(chain_id)) else {
            self.info = Some(ErrorCode::Key005.text());
            self.refresh();
            return;
        };
        let job = self.evm.job();
        self.evm.repin = Some(RepinState {
            chain_id,
            new: None,
            job,
            checked: false,
            message: Some("체인을 확인하는 중…".to_owned()),
        });
        let _ = self.rpc(RpcJob::Probe {
            job,
            url,
            chain_id,
            pinned: None,
            check_base_fee: false,
        });
        self.refresh();
    }

    /// The repin confirmed with T-CHAIN-REPIN-ACK.
    pub fn commit_repin(&mut self) {
        let Some(repin) = self.evm.repin.take() else {
            return;
        };
        let (Some(new), true) = (repin.new, repin.checked) else {
            self.evm.repin = Some(repin);
            return;
        };
        let mut settings = self.settings.clone();
        if repin.chain_id == HYPEREVM_MAINNET {
            settings
                .evm_genesis_pins
                .retain(|(id, _)| *id != repin.chain_id);
            settings.evm_genesis_pins.push((repin.chain_id, new));
        } else if let Some(def) = settings
            .evm_chains
            .iter_mut()
            .find(|def| def.chain_id == repin.chain_id)
        {
            def.genesis_hash = new;
        }
        self.save_settings(settings, "evmGenesisPins");
        logging::info(
            "app",
            "chain.repinned",
            &[
                ("net", Field::Net(NetworkId::Eip155(repin.chain_id))),
                ("hash", Field::Hash(&new)),
            ],
        );
        self.evm.chain_checks.remove(&repin.chain_id);
        self.reset_read_chain(repin.chain_id);
        let _ = self.rpc(RpcJob::ResetChain {
            chain_id: repin.chain_id,
        });
    }

    /// The pinned genesis shown in the chain list (`None` = first connection pins it).
    #[must_use]
    pub fn pinned_genesis(&self, chain_id: u64) -> Option<[u8; 32]> {
        chain_info(&self.settings, chain_id).and_then(|chain| match chain.genesis {
            GenesisRule::Fixed(hash) | GenesisRule::PinOnFirstUse(Some(hash)) => Some(hash),
            GenesisRule::PinOnFirstUse(None) => None,
        })
    }

    // ----- fee caps -----------------------------------------------------------------------

    /// Selects the chain in the fee-cap editor.
    pub fn select_caps_chain(&mut self, chain_id: u64) {
        let Some(chain) = chain_info(&self.settings, chain_id) else {
            return;
        };
        let text = self
            .settings
            .fee_caps
            .iter()
            .find(|(id, _)| *id == chain_id)
            .map_or_else(|| default_caps_text(&chain), |(_, text)| text.clone());
        self.evm.caps = Some(CapsForm {
            chain_id,
            fee: text.max_fee_per_gas_gwei,
            tip: text.max_priority_fee_per_gas_gwei,
            total: text.max_total_fee,
            message: None,
        });
        self.refresh();
    }

    /// `저장` of the fee caps (spec/03 §3.4-7 ranges).
    pub fn save_caps(&mut self, defaults: bool) {
        let Some(form) = self.evm.caps.clone() else {
            return;
        };
        let Some(chain) = chain_info(&self.settings, form.chain_id) else {
            return;
        };
        let text = if defaults {
            default_caps_text(&chain)
        } else {
            FeeCapsText {
                max_fee_per_gas_gwei: form.fee.trim().to_owned(),
                max_priority_fee_per_gas_gwei: form.tip.trim().to_owned(),
                max_total_fee: form.total.trim().to_owned(),
            }
        };
        let value = json_object(vec![
            ("maxFeePerGasGwei", json_str(&text.max_fee_per_gas_gwei)),
            (
                "maxPriorityFeePerGasGwei",
                json_str(&text.max_priority_fee_per_gas_gwei),
            ),
            ("maxTotalFee", json_str(&text.max_total_fee)),
        ]);
        let valid = validate_fee_caps(&value, chain.native_decimals)
            .filter(|caps| parse_caps(caps, chain.native_decimals).is_some());
        let Some(valid) = valid else {
            if let Some(caps) = self.evm.caps.as_mut() {
                caps.message = Some(
                    "maxFee 상한 1–10,000 gwei, tip 상한 0.01–10,000 gwei(maxFee 상한 이하), 총 상한 0.0001–10 범위로 입력하세요."
                        .to_owned(),
                );
            }
            self.refresh();
            return;
        };
        let mut settings = self.settings.clone();
        settings.fee_caps.retain(|(id, _)| *id != form.chain_id);
        if !defaults {
            settings.fee_caps.push((form.chain_id, valid));
        }
        self.save_settings(settings, "feeCaps");
        self.select_caps_chain(form.chain_id);
        if let Some(caps) = self.evm.caps.as_mut() {
            caps.message = Some("저장했습니다.".to_owned());
        }
        self.refresh();
    }

    // ----- display helpers ----------------------------------------------------------------

    /// `X SYM` of a native amount on a chain.
    #[must_use]
    pub fn native_text(&self, chain_id: u64, value: &U256) -> String {
        chain_info(&self.settings, chain_id).map_or_else(
            || value.to_decimal_string(),
            |chain| format_amount(value, chain.native_decimals, &chain.native_symbol),
        )
    }

    /// The masked endpoint text of a chain (S15).
    #[must_use]
    pub fn endpoint_text(&self, chain_id: u64) -> String {
        self.apikeys
            .rpc_url(NetworkId::Eip155(chain_id))
            .map_or_else(
                || "엔드포인트 없음".to_owned(),
                |url| format!("설정됨 {}", mask_url(&url)),
            )
    }

    /// Whether settings are loaded for chain lists (always).
    #[must_use]
    pub const fn settings_ref(&self) -> &Settings {
        &self.settings
    }

    /// The approval id for a new queue item.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Vlt005`] when randomness is unavailable.
    pub fn new_approval_id() -> Result<ApprovalId, ErrorCode> {
        ApprovalId::random().map_err(|_| ErrorCode::Vlt005)
    }
}

/// Fixed outcome names for logs.
#[must_use]
pub const fn outcome_name(outcome: QueueOutcome) -> &'static str {
    match outcome {
        QueueOutcome::Approved => "Approved",
        QueueOutcome::Rejected => "Rejected",
        QueueOutcome::Expired => "Expired",
        QueueOutcome::TimedOut => "TimedOut",
        QueueOutcome::Cancelled => "Cancelled",
        QueueOutcome::Revoked => "Revoked",
        QueueOutcome::TooManyPending => "TooManyPending",
        QueueOutcome::NotReady => "NotReady",
        QueueOutcome::PassphraseUnverified => "PassphraseUnverified",
        QueueOutcome::Shutdown => "Shutdown",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use yw_core::evm::address::Address;
    use yw_core::journal::evm::{
        EvmRecord, FLAG_MANUAL_RESEND, FLAG_RPC_HASH_MISMATCH, Role, TxState,
    };

    use super::seed_notes;
    use crate::flow::evm::track::BroadcastOutcome;

    const BESU_SIGNED: &str = "02f86e048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c080a00f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47a07dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83";

    fn record(flags: u8) -> EvmRecord {
        let sender =
            yw_core::evm::address::parse_address("0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73")
                .unwrap_or(Address::from_bytes([0; 20]));
        let mut record = EvmRecord::new_signed(
            4,
            sender,
            819,
            Role::Original,
            1_790_000_000_000,
            [7; 32],
            "https://app.example",
            "x",
            yw_core::hex::decode(BESU_SIGNED).unwrap(),
        )
        .unwrap();
        record.flags = flags;
        record
    }

    /// Journal records (every chain) and EVM activity rows feed the look-alike history; book
    /// entries are not repeated and history is not offered by the picker.
    #[test]
    fn past_recipients_join_the_known_addresses_as_history() {
        use crate::apikeys::ApiKeys;
        use crate::app::{App, AppMode, Paths};
        use crate::events::JournalView;
        use crate::meta::{ActivityEntry, BookEntry, Meta};
        use crate::settings::Settings;

        let dir = std::env::temp_dir().join(format!("yw-app-evm-known-{}", std::process::id()));
        let mut app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            Settings::default(),
            ApiKeys::default(),
        );
        app.mode = AppMode::Unlocked {
            alt_passphrase: false,
        };
        let book = "0x52908400098527886e0f7030069857d2e4169ee7";
        let from_activity = "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb";
        let mut meta = Meta::default();
        meta.add_book(&BookEntry {
            address: book.to_owned(),
            label: "거래소".to_owned(),
            verified: false,
            added_at_unix_ms: 1,
        })
        .unwrap();
        let row = |counterparty: &str, sig: u8| ActivityEntry {
            account: "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73".to_owned(),
            tx_id: format!("0x{}", "ab".repeat(31) + &format!("{sig:02x}")),
            title: "보내기".to_owned(),
            asset: "native".to_owned(),
            amount: "1".to_owned(),
            counterparty: counterparty.to_owned(),
            status: "succeeded".to_owned(),
            time_unix_ms: u64::from(sig),
        };
        meta.upsert_activity("eip155:84532", &row(from_activity, 1));
        meta.upsert_activity("eip155:84532", &row(book, 2));
        // A Solana row is not an EVM recipient.
        meta.upsert_activity("solana:devnet", &row(from_activity, 3));
        app.meta = Some(meta);
        // The Besu record (chain 4) sends to 0x…aaaa.
        app.evm.journal = Some(JournalView {
            records: vec![record(0)],
            ..JournalView::default()
        });
        let known = app.known_addresses();
        let history: Vec<String> = known
            .iter()
            .filter(|entry| entry.history)
            .map(|entry| entry.address.to_lower_hex())
            .collect();
        assert_eq!(
            history,
            vec![
                "0x000000000000000000000000000000000000aaaa".to_owned(),
                from_activity.to_owned(),
            ]
        );
        assert_eq!(
            known
                .iter()
                .filter(|entry| entry.address.to_lower_hex() == book)
                .count(),
            1
        );
        assert!(
            app.picker_entries()
                .iter()
                .all(|address| address.to_lower_hex() == book)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// spec/04 §2.7 (security review M2): `검토` validates again without a call and refuses when
    /// the fresh recipient or amount differs from the shown one (an edit inside the debounce);
    /// it is off while an edit awaits validation; the item is built from the fresh result only.
    #[test]
    fn review_revalidates_and_refuses_an_edit_inside_the_debounce() {
        use crate::apikeys::ApiKeys;
        use crate::app::{App, AppMode, Paths};
        use crate::app_sol::{ReviewRefusal, SOL_REVIEW_CHANGED_TEXT};
        use crate::events::JournalView;
        use crate::flow::evm::form::Quote;
        use crate::meta::{Account, Meta};
        use crate::settings::Settings;
        use yw_core::evm::amount::U256;

        const TO_A: &str = "0x52908400098527886e0f7030069857d2e4169ee7";
        const TO_B: &str = "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb";
        let dir = std::env::temp_dir().join(format!("yw-app-evm-review-{}", std::process::id()));
        let mut app = App::new(
            Paths {
                data: dir.clone(),
                logs: dir.join("logs"),
            },
            true,
            Settings::default(),
            ApiKeys::default(),
        );
        app.mode = AppMode::Unlocked {
            alt_passphrase: false,
        };
        app.meta = Some(Meta {
            evm_accounts: vec![Account {
                index: 0,
                label: "계정 1".to_owned(),
                address: "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73".to_owned(),
                hidden: false,
            }],
            ..Meta::default()
        });
        app.evm.journal = Some(JournalView::default());
        let quote = Quote {
            gas_limit: 21_000,
            max_fee_per_gas: U256::from_u64(1),
            max_total: U256::from_u64(21_000),
            cap_violation: None,
            estimate_failed: false,
        };
        let to = |text: &str| yw_core::evm::address::parse_address(text).unwrap();
        let one_eth = U256::from_u64(1_000_000_000_000_000_000);
        app.evm.send.to_text = TO_A.to_owned();
        app.evm.send.amount_text = "1".to_owned();
        app.validate_send(false);
        app.evm.send.quote = Some(quote.clone());
        assert!(app.can_review());
        // B / 10 pasted, the debounce has not run: `검토` is off and the shown result is A / 1.
        app.evm.send.to_text = TO_B.to_owned();
        app.evm.send.amount_text = "10".to_owned();
        app.evm.send.dirty_ms = Some(1);
        assert!(!app.can_review());
        assert_eq!(app.review_item().unwrap_err(), ReviewRefusal::Changed);
        assert_eq!(app.evm.send.dirty_ms, None);
        assert_eq!(app.evm.send.recipient.as_ref().unwrap().0, to(TO_B));
        // `review_send` itself shows the fixed text and queues nothing.
        app.evm.send.amount_text = "2".to_owned();
        app.review_send();
        assert_eq!(app.evm.send.info.as_deref(), Some(SOL_REVIEW_CHANGED_TEXT));
        assert!(app.evm.slots.is_empty());
        // The fresh validation is now on screen: the item is built from it (B / 2).
        app.evm.send.quote = Some(quote);
        let item = app.review_item().unwrap();
        assert_eq!(item.intent.to, to(TO_B));
        assert_eq!(item.intent.value, one_eth.checked_mul_u64(2).unwrap());
        // An input error is "not ready", not a change.
        app.evm.send.amount_text = "x".to_owned();
        app.validate_send(false);
        assert_eq!(app.review_item().unwrap_err(), ReviewRefusal::NotReady);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// After a restart the activity notes come back from the journal flags: a manual-resend-only
    /// record offers `재전송`·`폐기` again (and tracking never re-sends it on its own).
    #[test]
    fn journal_flags_restore_the_manual_resend_notes() {
        let manual = record(FLAG_MANUAL_RESEND);
        let mut notes = HashMap::new();
        seed_notes(&mut notes, std::slice::from_ref(&manual));
        assert_eq!(
            notes.get(&manual.tx_hash),
            Some(&BroadcastOutcome::Rejected { known: false })
        );
        let other_hash = record(FLAG_RPC_HASH_MISMATCH);
        let mut notes = HashMap::new();
        seed_notes(&mut notes, std::slice::from_ref(&other_hash));
        assert_eq!(
            notes.get(&other_hash.tx_hash),
            Some(&BroadcastOutcome::HashMismatch)
        );
        // Session notes win; records that are not `Signed` or carry no flag add nothing.
        let mut notes = HashMap::from([(manual.tx_hash, BroadcastOutcome::Sent)]);
        let mut sent = record(FLAG_MANUAL_RESEND);
        sent.state = TxState::Broadcast;
        seed_notes(&mut notes, &[manual.clone(), sent, record(0)]);
        assert_eq!(notes.len(), 1);
        assert_eq!(notes.get(&manual.tx_hash), Some(&BroadcastOutcome::Sent));
    }
}
