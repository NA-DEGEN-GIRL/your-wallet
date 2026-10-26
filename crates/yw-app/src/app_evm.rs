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
use yw_core::journal::evm::{EvmRecord, GroupKey, Transition, groups, in_flight, latest_candidate};
use yw_core::vault::{EvmKeySource, FileKind, RecordId};
use yw_win::clipboard;

use crate::apikeys::{KeyName, mask_url};
use crate::app::{App, AppMode, Confirm, Screen, SettingsSection};
use crate::errors::ErrorCode;
use crate::events::{BalanceSnapshot, JournalView, KeyJob, KeyOutcome, RpcEvent, SignFailure};
use crate::flow::evm::form::{AddressNote, KnownAddress, Quote, check_recipient, parse_amount};
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
    /// Approval queue (app items at M4).
    pub queue: ApprovalQueue<AppApproval>,
    /// Issued approvals.
    pub store: ApprovalStore,
    /// Send slots `(chain, account)` (spec/03 §3.6).
    pub slots: Vec<(u64, Address)>,
    /// Job counter.
    pub next_job: u64,
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
    /// The approval window.
    pub window: Option<crate::app_approval::ApprovalUi>,
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

    /// The selected account: address and key source.
    #[must_use]
    pub fn selected_account(&self) -> Option<(Address, EvmKeySource, String)> {
        let meta = self.meta.as_ref()?;
        match meta.prefs.evm_account {
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

    /// Address book and own accounts for the form notes.
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
                }),
        );
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

    /// Tokens of a chain: registry `(address, symbol, decimals, registered)` then meta tokens.
    #[must_use]
    pub fn chain_tokens(&self, chain_id: u64) -> Vec<(Address, String, u8, bool)> {
        let mut out: Vec<(Address, String, u8, bool)> = chain_info(&self.settings, chain_id)
            .map(|chain| {
                chain
                    .tokens
                    .iter()
                    .map(|token| (token.address, token.symbol.to_owned(), token.decimals, true))
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
        let _ = self.evm.queue.lock();
        self.evm.clear_unlocked();
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
                self.evm.journal = Some(view);
                self.schedule_tracking(true);
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
            KeyOutcome::SignedEvm(result) => self.on_signed(result),
            _ => {}
        }
    }

    fn on_signed(&mut self, result: Result<crate::events::SignedSummary, SignFailure>) {
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
                };
                logging::warn("app", "sign.failed", &[]);
                self.evm.send.info = Some(message.clone());
                self.banner(None, message);
                self.refresh();
            }
        }
    }

    /// A consumed signing item ended without a signature because of the lock (spec/04 §1.2).
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
        }
    }

    fn on_chain_check(&mut self, chain_id: u64, check: ChainCheck) {
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
            let manual = group.iter().any(|record| {
                matches!(
                    self.evm.notes.get(&record.tx_hash),
                    Some(BroadcastOutcome::Rejected { known: false })
                )
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
        self.evm.notes.insert(tx_hash, outcome);
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
            },
            SendAsset::Token(token) => SendIntent {
                to: token,
                value: U256::ZERO,
                data: erc20_transfer_data(recipient, &amount),
                access_list: Vec::new(),
                dapp_gas: None,
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
                crate::flow::evm::form::max_native(
                    &balance,
                    quote.gas_limit,
                    &quote.max_fee_per_gas,
                )
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

    /// Whether `검토` is enabled (spec/04 §2.7).
    #[must_use]
    pub fn can_review(&self) -> bool {
        let form = &self.evm.send;
        let chain_id = self.settings.evm_chain_id;
        let look_alike = form
            .recipient
            .as_ref()
            .is_some_and(|(_, notes)| notes.iter().any(AddressNote::needs_ack));
        form.recipient.is_some()
            && form.amount.is_some()
            && form.amount_error.is_none()
            && form.recipient_error.is_none()
            && form
                .quote
                .as_ref()
                .is_some_and(|quote| quote.cap_violation.is_none())
            && (!look_alike || form.ack)
            && self.evm.blocked(chain_id).is_none()
            && !self.evm.journal_damaged()
            && self.evm.journal.is_some()
            && self.send_in_flight().is_none()
            && matches!(self.mode, AppMode::Unlocked { .. })
    }

    /// `검토`: queue the approval and open A01 (spec/04 §2.7, §3.5).
    pub fn review_send(&mut self) {
        if !self.can_review() {
            return;
        }
        let Some((account, signer, _)) = self.selected_account() else {
            return;
        };
        let Some(intent) = self.intent() else {
            return;
        };
        let chain_id = self.settings.evm_chain_id;
        self.enqueue_app(AppApproval {
            chain_id,
            account,
            signer,
            intent,
            replace: None,
        });
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
        if self.evm.queue.enqueue(QueueSource::App, item).is_ok() {
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
    pub fn approval_finished(&mut self, item: &AppApproval, outcome: QueueOutcome) {
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
            },
            replace: Some(ReplaceTarget { mode, group }),
        });
    }

    fn account_source(&self, address: &Address) -> Option<EvmKeySource> {
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
        QueueOutcome::Shutdown => "Shutdown",
    }
}
