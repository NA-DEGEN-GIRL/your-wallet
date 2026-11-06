//! Solana flows on the UI thread (M7; spec/07 §3, §11–§14, spec/04 §2.6–§2.11): standard accounts
//! and balances (SOL and, since v1.1, the allowlisted tokens' derived ATAs), the SOL/SPL send form
//! (S11) with its asset picker, receive (S12), the approval item and its preview,
//! the post-approval blockhash lookup and signing, the broadcast-loop scheduling, activity, the
//! Solana address book and the recovery scan. RPC work goes to `yw-rpc`, keys and journal commits
//! to `yw-key`.

use core::fmt::Write as _;
use std::collections::HashMap;

use yw_core::approval::Approved;
use yw_core::bip32::path::AccountIndex;
use yw_core::journal::sol::{SolRecord, SolTransition, SolTxState};
use yw_core::slip10::SolKeySource;
use yw_core::sol::broadcast::{LoopState, Outcome, PendingTx, SOL_POLL_INTERVAL_MS};
use yw_core::sol::display::build_sol_transfer_request;
use yw_core::sol::fee::template_cu_limit;
use yw_core::sol::recipient::{
    KnownAddress, KnownKind, RecipientBlock, RecipientCheck, check_recipient_for,
};
use yw_core::sol::rent::{AmountError, format_amount, parse_amount};
use yw_core::sol::template::spl_entries;
use yw_core::sol::token::TokenHolding;
use yw_core::sol::{SolAddress, SolAsset, SolCluster, SplAllowEntry};

use crate::app::{App, AppMode, Screen};
use crate::app_evm::QueuedItem;
use crate::errors::ErrorCode;
use crate::events::{KeyJob, RpcEvent, SolKeysPurpose, SolSignFailure, SolSignedSummary};
use crate::logging::{self, Field};
use crate::meta::{Account, Tab};
use crate::network::NetworkId;
use crate::sol::flow::{
    PreSignError, PreviewJob, PreviewOutcome, PreviewResult, SolEndpoint, TrackJob, TrackResult,
};
use crate::sol::scan::{ScanRow, scan_sources};
use crate::text::is_valid_label;
use crate::ui::approval::{QueueOutcome, QueueSource};
use crate::workers::journal::sol_network;
use crate::workers::rpc::RpcJob;

/// Balance refresh while the Solana tab is visible (spec/04 §2.6).
pub const SOL_BALANCE_REFRESH_MS: u64 = 60_000;
/// Send-form validation after typing stops.
pub const SOL_SEND_DEBOUNCE_MS: u64 = 500;
/// Activity rows shown.
pub const SOL_MAX_ACTIVITY_ROWS: usize = 50;

fn now_ms() -> u64 {
    yw_win::time::monotonic_ms()
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

/// Settings cluster → core cluster.
#[must_use]
pub const fn core_cluster(cluster: crate::network::SolCluster) -> SolCluster {
    match cluster {
        crate::network::SolCluster::Mainnet => SolCluster::Mainnet,
        crate::network::SolCluster::Devnet => SolCluster::Devnet,
    }
}

/// Core cluster → settings cluster.
#[must_use]
pub const fn ui_cluster(cluster: SolCluster) -> crate::network::SolCluster {
    match cluster {
        SolCluster::Mainnet => crate::network::SolCluster::Mainnet,
        SolCluster::Devnet => crate::network::SolCluster::Devnet,
    }
}

/// The error code of a §12.1 block.
#[must_use]
pub const fn recipient_code(block: RecipientBlock) -> ErrorCode {
    match block {
        RecipientBlock::Format(_) => ErrorCode::Inp009,
        RecipientBlock::IsProgram => ErrorCode::Sol001,
        RecipientBlock::Unspendable => ErrorCode::Sol002,
        RecipientBlock::SelfSend => ErrorCode::Sol003,
        RecipientBlock::OffCurveOwner => ErrorCode::Sol006,
    }
}

/// A queued SOL or SPL transfer approval.
#[derive(Clone, Debug)]
pub struct SolApprovalItem {
    /// Cluster.
    pub cluster: SolCluster,
    /// Key source of `from`.
    pub source: SolKeySource,
    /// Sender.
    pub from: SolAddress,
    /// Sender label.
    pub label: String,
    /// §12.1 result (checked for `asset`).
    pub recipient: RecipientCheck,
    /// SOL or an allowlisted token of `cluster`.
    pub asset: SolAsset,
    /// Lamports or raw token units, `None` = send max.
    pub amount: Option<u64>,
}

/// The SOL/SPL send form (inputs survive rejection and expiry).
#[derive(Clone, Debug, Default)]
pub struct SolSendForm {
    /// A non-standard source being moved to a standard account (recovery scan, spec/07 §3.3):
    /// `(source, from)`; the recipient is fixed and the amount is "send max".
    pub moving: Option<(SolKeySource, SolAddress)>,
    /// The asset picker: `None` = SOL, otherwise an allowlisted token of the cluster (v1.1).
    pub token: Option<&'static SplAllowEntry>,
    /// Recipient text.
    pub to_text: String,
    /// Amount text.
    pub amount_text: String,
    /// `최대` (send max: the amount is computed at preview).
    pub send_max: bool,
    /// Picker open.
    pub picker: bool,
    /// Last edit awaiting validation.
    pub dirty_ms: Option<u64>,
    /// Local check result.
    pub check: Option<RecipientCheck>,
    /// Recipient error.
    pub recipient_error: Option<ErrorCode>,
    /// Parsed amount.
    pub amount: Option<u64>,
    /// Amount error.
    pub amount_error: Option<ErrorCode>,
    /// Message (T-APPR-EXPIRED, errors).
    pub info: Option<String>,
}

impl SolSendForm {
    /// The selected asset.
    #[must_use]
    pub const fn asset(&self) -> SolAsset {
        match self.token {
            Some(entry) => SolAsset::Spl(entry),
            None => SolAsset::Sol,
        }
    }
}

/// Shown when the validation at `검토` differs from the one on screen (spec/07 §13.1-1).
pub const SOL_REVIEW_CHANGED_TEXT: &str =
    "입력이 바뀌어 다시 확인했습니다. 받는 주소·자산·금액을 확인한 뒤 다시 검토하세요.";

/// Why `검토` did not queue an approval.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewRefusal {
    /// The form cannot be reviewed (input errors, a pending transfer, the lock, …).
    NotReady,
    /// The fresh validation differs from the shown one: nothing is queued.
    Changed,
}

/// What an approval is built from: the parsed recipient, the asset and the amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReviewInputs {
    to: Option<SolAddress>,
    asset: SolAsset,
    send_max: bool,
    amount: Option<u64>,
}

impl ReviewInputs {
    fn of(form: &SolSendForm) -> Self {
        Self {
            to: form.check.as_ref().map(|check| check.to),
            asset: form.asset(),
            send_max: form.send_max,
            amount: form.amount,
        }
    }
}

/// A final state (`SolApply`) still not in the journal after this long is treated as a failed
/// write: the loop resumes, observes the final state again and asks to write it again.
pub const SOL_APPLY_RETRY_MS: u64 = 10_000;

/// Fixed text while a final state is being written to the journal.
pub const SOL_SAVING_TEXT: &str = "결과를 거래 저널에 저장하는 중";
/// Fixed text after a final state could not be written to the journal (the loop retries).
pub const SOL_SAVE_FAILED_TEXT: &str =
    "결과를 거래 저널에 저장하지 못했습니다. 다시 확인해 저장합니다 (E-VLT-003)";

/// Why a record's loop is stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolHalt {
    /// Genesis mismatch (E-RPC-006): stopped until restart or a URL change.
    ClusterMismatch,
    /// A final state was sent to the key worker (`SolApply`) at monotonic `since_ms`; the record
    /// leaves tracking when the journal no longer has it `Pending`.
    Saving {
        /// When the write was asked.
        since_ms: u64,
    },
}

/// Loop scheduling of one `Pending` record.
#[derive(Clone, Copy, Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent flags of one record's loop"
)]
pub struct SolTrackState {
    /// Decision state.
    pub state: LoopState,
    /// Next round (monotonic ms).
    pub next_ms: u64,
    /// A round is running.
    pub busy: bool,
    /// Genesis checked this session (resume check, spec/07 §15.1).
    pub genesis_checked: bool,
    /// Why the loop is stopped, if it is.
    pub halt: Option<SolHalt>,
    /// A final state could not be written to the journal (shown until the record leaves).
    pub save_failed: bool,
    /// "네트워크/RPC 확인 필요".
    pub notice: bool,
    /// Last round failure.
    pub error: Option<ErrorCode>,
    /// The user asked to re-send the same signed bytes now ("지금 다시 전송", spec/07 §14.3):
    /// the next round starts with `LoopState::send_now`.
    pub send_now: bool,
    /// Endpoint generation: bumped when the cluster's URL changes, so a round started before the
    /// change (its genesis check, its outcome) is discarded when it completes.
    pub generation: u64,
}

/// An approved transfer waiting for its blockhash (spec/07 §13.1 step 5).
#[derive(Debug)]
pub struct PendingSign {
    /// The one-time approval.
    pub approved: Box<Approved>,
    /// Monotonic ms of `consume`.
    pub consumed_at_ms: u64,
    /// Lookup job.
    pub job: u64,
    /// The `YubiKey` PIN of a card transfer (spec/10 §6.4): moved into `SignSolCard` with the
    /// blockhash, wiped with this pending entry otherwise.
    pub pin: Option<crate::app_card::PinBuffer>,
}

/// Recovery scan stage.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ScanStage {
    /// The disclosure notice (confirm first).
    #[default]
    Notice,
    /// Deriving public keys.
    Deriving,
    /// Querying balances.
    Running,
    /// Results shown.
    Done,
}

/// Shown when the selected cluster is not the one whose scan notice was confirmed.
pub const SOL_SCAN_RECONFIRM_TEXT: &str =
    "클러스터가 바뀌었습니다. 이 클러스터의 RPC 공급자에 대한 안내를 다시 확인하세요.";

/// Recovery scan state.
#[derive(Clone, Debug, Default)]
pub struct SolScanState {
    /// Stage.
    pub stage: ScanStage,
    /// The cluster whose disclosure notice was confirmed (from `Deriving` on), then scanned.
    pub cluster: Option<SolCluster>,
    /// Rows.
    pub rows: Vec<ScanRow>,
    /// Job.
    pub job: u64,
    /// Message.
    pub message: Option<String>,
}

/// A Solana account of this wallet: a standard-path account (`m/44'/501'/i'/0'`) or an imported
/// key (vault `tag 3`, spec/02 §8.4). The signer is `SolKeySource::Standard(i)` or
/// `SolKeySource::Imported` (looked up by the public key).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SolAccountId {
    /// Standard path index.
    Derived(u32),
    /// Imported key record id.
    Imported([u8; 16]),
    /// `YubiKey` account `i` (`SolKeySource::Hardware`, meta `hw_accounts.sol`, spec/10 §13).
    Hardware(u32),
}

impl SolAccountId {
    /// The signing key source.
    #[must_use]
    pub fn source(self) -> Option<SolKeySource> {
        match self {
            Self::Derived(index) => AccountIndex::new(index).ok().map(SolKeySource::Standard),
            Self::Imported(_) => Some(SolKeySource::Imported),
            Self::Hardware(index) => AccountIndex::new(index).ok().map(SolKeySource::Hardware),
        }
    }

    /// The path text shown under the account (`m/44'/501'/i'/0'` or the import note).
    #[must_use]
    pub fn path_text(self) -> String {
        match self {
            Self::Derived(index) => format!("m/44'/501'/{index}'/0'"),
            Self::Imported(_) => "가져온 개인키 (복구 단어로 복구되지 않음)".to_owned(),
            Self::Hardware(index) => format!("m/44'/501'/{index}'/0' (YubiKey PIV)"),
        }
    }

    /// Whether this is an imported key.
    #[must_use]
    pub const fn is_imported(self) -> bool {
        matches!(self, Self::Imported(_))
    }

    /// Whether this is a `YubiKey` account (signed on the card).
    #[must_use]
    pub const fn is_hardware(self) -> bool {
        matches!(self, Self::Hardware(_))
    }
}

/// Solana UI state.
#[derive(Debug, Default)]
pub struct SolUi {
    /// Balances per (cluster, account).
    pub balances: HashMap<(SolCluster, SolAddress), u64>,
    /// Allowlisted token holdings per (cluster, account), allowlist order (v1.1).
    pub tokens: HashMap<(SolCluster, SolAddress), Vec<(&'static SplAllowEntry, TokenHolding)>>,
    /// Last balance error per cluster.
    pub balance_error: HashMap<SolCluster, ErrorCode>,
    /// Outstanding balance job.
    pub balance_job: u64,
    /// Next balance refresh.
    pub next_balance_ms: u64,
    /// Account creation in flight.
    pub creating: bool,
    /// Send form.
    pub send: SolSendForm,
    /// The (cluster, account) between enqueue and the `Pending` record (one in flight).
    pub slot: Option<(SolCluster, SolAddress)>,
    /// Approved transfer waiting for its blockhash.
    pub pending_sign: Option<PendingSign>,
    /// Broadcast loop per signature.
    pub tracking: HashMap<[u8; 64], SolTrackState>,
    /// Last sent transfer.
    pub sent: Option<(SolCluster, [u8; 64])>,
    /// The inputs and sender of the last sent transfer, for "다시 보내기" after `Expired` /
    /// `FailedOnChain` (spec/07 §14.3: same inputs, new preview, new intent, new approval).
    pub resend: Option<(SolSendForm, SolAddress)>,
    /// Recovery scan.
    pub scan: SolScanState,
    /// Rename of the selected account.
    pub rename: Option<SolAccountId>,
    /// The token card lists the hidden allowlist tokens (`숨긴 토큰 n개 보기`; session only).
    pub show_hidden_tokens: bool,
    /// Job counter.
    pub next_job: u64,
}

impl SolUi {
    /// A fresh job id.
    pub fn job(&mut self) -> u64 {
        self.next_job = self.next_job.saturating_add(1);
        self.next_job
    }

    /// Forgets everything that needs the unlocked wallet (lock). The broadcast loop needs no
    /// secret, but its journal is re-read after unlock and the loop resumes from it.
    pub fn clear_unlocked(&mut self) {
        self.balances.clear();
        self.tokens.clear();
        self.balance_error.clear();
        self.creating = false;
        self.send = SolSendForm::default();
        self.slot = None;
        self.pending_sign = None;
        self.tracking.clear();
        self.sent = None;
        self.resend = None;
        self.scan = SolScanState::default();
        self.rename = None;
    }
}

impl App {
    // ----- basics -------------------------------------------------------------------------

    /// The selected cluster (settings `solana.cluster`).
    #[must_use]
    pub fn sol_cluster(&self) -> SolCluster {
        core_cluster(self.settings.solana.cluster)
    }

    /// The endpoint of a cluster, or E-KEY-005 without any call.
    ///
    /// # Errors
    ///
    /// [`ErrorCode::Key005`].
    pub fn sol_endpoint(&self, cluster: SolCluster) -> Result<SolEndpoint, ErrorCode> {
        let url = self
            .apikeys
            .rpc_url(NetworkId::Solana(ui_cluster(cluster)))
            .ok_or(ErrorCode::Key005)?;
        Ok(SolEndpoint { cluster, url })
    }

    /// Visible Solana accounts `(id, label, address)`: standard accounts, then imported keys.
    #[must_use]
    pub fn sol_account_rows(&self) -> Vec<(SolAccountId, String, SolAddress)> {
        self.meta.as_ref().map_or_else(Vec::new, |meta| {
            let derived = meta
                .sol_accounts
                .iter()
                .filter(|account| !account.hidden)
                .filter_map(|account| {
                    SolAddress::parse(&account.address).ok().map(|address| {
                        (
                            SolAccountId::Derived(account.index),
                            account.label.clone(),
                            address,
                        )
                    })
                });
            let imported = meta.sol_raw_accounts.iter().filter_map(|raw| {
                SolAddress::parse(&raw.address).ok().map(|address| {
                    (
                        SolAccountId::Imported(raw.record_id),
                        raw.label.clone(),
                        address,
                    )
                })
            });
            let hardware = meta
                .hw_accounts
                .sol
                .iter()
                .filter(|account| !account.hidden)
                .filter_map(|account| {
                    SolAddress::parse(&account.address).ok().map(|address| {
                        (
                            SolAccountId::Hardware(account.index),
                            account.label.clone(),
                            address,
                        )
                    })
                });
            derived.chain(imported).chain(hardware).collect()
        })
    }

    /// The selected Solana account (an imported key when `sol_raw_selected` names one).
    #[must_use]
    pub fn sol_selected(&self) -> Option<(SolAccountId, String, SolAddress)> {
        let meta = self.meta.as_ref()?;
        let wanted = meta.hw_accounts.sol_selected.map_or_else(
            || {
                meta.sol_raw_selected.map_or(
                    SolAccountId::Derived(meta.prefs.sol_account),
                    SolAccountId::Imported,
                )
            },
            SolAccountId::Hardware,
        );
        let rows = self.sol_account_rows();
        rows.iter()
            .find(|(id, ..)| *id == wanted)
            .or_else(|| rows.first())
            .cloned()
    }

    /// Decoded SOL journal records.
    #[must_use]
    pub fn sol_records(&self) -> Vec<SolRecord> {
        self.evm
            .journal
            .as_ref()
            .map_or_else(Vec::new, |journal| journal.sol_records.clone())
    }

    /// SOL sending is stopped by a damaged record (spec/07 §14.1).
    #[must_use]
    pub fn sol_journal_damaged(&self) -> bool {
        self.evm
            .journal
            .as_ref()
            .is_some_and(|journal| journal.sol_corrupt > 0)
    }

    /// The `Pending` record of (cluster, from).
    #[must_use]
    pub fn sol_pending(&self, cluster: SolCluster, from: &SolAddress) -> Option<SolRecord> {
        let records = self.sol_records();
        yw_core::journal::sol::pending_for(&records, cluster, from).cloned()
    }

    /// The account label of an address (own accounts), or the address.
    #[must_use]
    pub fn sol_label(&self, address: &str) -> String {
        self.sol_account_rows()
            .into_iter()
            .find(|(_, _, known)| known.to_base58() == address)
            .map_or_else(|| address.to_owned(), |(_, label, _)| label)
    }

    /// Address book, own accounts and sent history for the §12.1 checks. Only recipients of
    /// successful sends on the selected cluster are `Sent` (known: no first-time warning); every
    /// other sent-history address (failed, expired, pending, other cluster) is `History`, which
    /// is compared for lookalikes only.
    #[must_use]
    pub fn sol_known(&self) -> Vec<KnownAddress> {
        let selected = self.sol_cluster();
        let mut known = Vec::new();
        if let Some(meta) = self.meta.as_ref() {
            for entry in meta.contacts_favorites_first(crate::meta::BookChain::Sol) {
                if let Ok(address) = SolAddress::parse(&entry.address) {
                    known.push(KnownAddress {
                        address,
                        label: entry.label,
                        kind: KnownKind::Book {
                            verified: entry.verified,
                        },
                    });
                }
            }
        }
        for (id, label, address) in self.sol_account_rows() {
            known.push(KnownAddress {
                address,
                label,
                kind: match id {
                    SolAccountId::Derived(index) => KnownKind::Own { index },
                    SolAccountId::Imported(_) => KnownKind::OwnImported,
                    SolAccountId::Hardware(_) => KnownKind::OwnHardware,
                },
            });
        }
        let sent = |succeeded: bool| {
            if succeeded {
                KnownKind::Sent
            } else {
                KnownKind::History
            }
        };
        if let Some(meta) = self.meta.as_ref() {
            for cluster in [SolCluster::Mainnet, SolCluster::Devnet] {
                for entry in meta.activity_of(cluster.network_id()) {
                    if let Ok(address) = SolAddress::parse(&entry.counterparty) {
                        known.push(KnownAddress {
                            address,
                            label: String::new(),
                            kind: sent(cluster == selected && entry.status == "succeeded"),
                        });
                    }
                }
            }
        }
        for record in self.sol_records() {
            if let Some(core) = record.core() {
                known.push(KnownAddress {
                    address: core.to,
                    label: String::new(),
                    kind: sent(record.cluster == selected && record.state == SolTxState::Landed),
                });
            }
        }
        known
    }

    // ----- tab, accounts -------------------------------------------------------------------

    /// Switches the main tab; the first Solana entry derives account 0 (spec/07 §3.1).
    pub fn sol_select_tab(&mut self, tab: Tab) {
        if let Some(meta) = self.meta.as_mut()
            && meta.prefs.tab != tab
        {
            meta.prefs.tab = tab;
            self.save_meta();
        }
        if tab == Tab::Sol {
            self.sol_ensure_account();
            self.sol.next_balance_ms = 0;
        }
        self.refresh();
    }

    /// Derives account 0 when there is none (not in a key-only wallet: no recovery words).
    pub fn sol_ensure_account(&mut self) {
        let empty = self
            .meta
            .as_ref()
            .is_some_and(|meta| meta.sol_accounts.is_empty());
        if empty
            && self.keys.has_mnemonic
            && !self.sol.creating
            && matches!(self.mode, AppMode::Unlocked { .. } | AppMode::BackupPending)
        {
            self.sol_add_account();
        }
    }

    /// `계정 추가`: the next standard index.
    pub fn sol_add_account(&mut self) {
        let Some(index) = self
            .meta
            .as_ref()
            .and_then(crate::meta::Meta::next_sol_index)
        else {
            return;
        };
        let Ok(account) = AccountIndex::new(index) else {
            return;
        };
        self.sol.creating = true;
        self.key(KeyJob::SolKeys {
            purpose: SolKeysPurpose::AddAccount { index },
            sources: vec![SolKeySource::Standard(account)],
        });
    }

    /// Selects a Solana account row.
    pub fn sol_select_account(&mut self, row: usize) {
        let rows = self.sol_account_rows();
        if let Some((id, ..)) = rows.get(row)
            && let Some(meta) = self.meta.as_mut()
        {
            match *id {
                SolAccountId::Derived(index) => {
                    meta.prefs.sol_account = index;
                    meta.sol_raw_selected = None;
                    meta.hw_accounts.sol_selected = None;
                }
                SolAccountId::Imported(record) => {
                    meta.sol_raw_selected = Some(record);
                    meta.hw_accounts.sol_selected = None;
                }
                SolAccountId::Hardware(index) => {
                    meta.hw_accounts.sol_selected = Some(index);
                    meta.sol_raw_selected = None;
                }
            }
            self.sol.rename = None;
            self.save_meta();
        }
        self.refresh();
    }

    /// Saves a renamed Solana account.
    pub fn sol_save_rename(&mut self, label: &str) {
        let Some(target) = self.sol.rename else {
            return;
        };
        let label = label.trim();
        if !is_valid_label(label) {
            self.banner(Some(ErrorCode::Inp017), ErrorCode::Inp017.text());
            self.refresh();
            return;
        }
        if let Some(meta) = self.meta.as_mut() {
            match target {
                SolAccountId::Derived(index) => {
                    if let Some(account) = meta
                        .sol_accounts
                        .iter_mut()
                        .find(|account| account.index == index)
                    {
                        label.clone_into(&mut account.label);
                    }
                }
                SolAccountId::Imported(record) => {
                    if let Some(raw) = meta
                        .sol_raw_accounts
                        .iter_mut()
                        .find(|raw| raw.record_id == record)
                    {
                        label.clone_into(&mut raw.label);
                    }
                }
                SolAccountId::Hardware(index) => {
                    if let Some(account) = meta
                        .hw_accounts
                        .sol
                        .iter_mut()
                        .find(|account| account.index == index)
                    {
                        label.clone_into(&mut account.label);
                    }
                }
            }
        }
        self.sol.rename = None;
        self.save_meta();
        self.refresh();
    }

    /// Hides the selected standard account (not account 0; imported keys are removed instead).
    pub fn sol_hide_selected(&mut self) {
        if let Some((SolAccountId::Hardware(index), ..)) = self.sol_selected() {
            // A hidden YubiKey account comes back when a card with its key is enrolled again.
            let mut hidden = None;
            if let Some(meta) = self.meta.as_mut() {
                for account in &mut meta.hw_accounts.sol {
                    if account.index == index {
                        account.hidden = true;
                        hidden = SolAddress::parse(&account.address).ok();
                    }
                }
                meta.hw_accounts.sol_selected = None;
            }
            self.save_meta();
            if let Some(address) = hidden {
                self.sol_account_removed_from_sites(&address.to_bytes());
            }
            self.refresh();
            return;
        }
        let Some((SolAccountId::Derived(index), ..)) = self.sol_selected() else {
            return;
        };
        if index == 0 {
            return;
        }
        let mut hidden = None;
        if let Some(meta) = self.meta.as_mut() {
            for account in &mut meta.sol_accounts {
                if account.index == index {
                    account.hidden = true;
                    hidden = SolAddress::parse(&account.address).ok();
                }
            }
            meta.prefs.sol_account = 0;
        }
        self.save_meta();
        // A hidden account leaves every dApp connection (spec/05 §4.9).
        if let Some(address) = hidden {
            self.sol_account_removed_from_sites(&address.to_bytes());
        }
        self.refresh();
    }

    /// Key worker result of `SolKeys`.
    pub fn on_sol_keys(
        &mut self,
        purpose: SolKeysPurpose,
        result: Result<Vec<(SolKeySource, SolAddress)>, yw_core::error::VaultError>,
    ) {
        match (purpose, result) {
            (SolKeysPurpose::AddAccount { index }, Ok(keys)) => {
                self.sol.creating = false;
                let Some((_, address)) = keys.first() else {
                    return;
                };
                if let Some(meta) = self.meta.as_mut()
                    && !meta
                        .sol_accounts
                        .iter()
                        .any(|account| account.index == index)
                {
                    meta.sol_accounts.push(Account {
                        index,
                        label: format!("Solana {}", index.saturating_add(1)),
                        address: address.to_base58(),
                        hidden: false,
                    });
                    meta.sol_accounts.sort_by_key(|account| account.index);
                    if meta.sol_accounts.len() == 1 {
                        meta.prefs.sol_account = index;
                    }
                }
                logging::info(
                    "app",
                    "sol.account_added",
                    &[("index", Field::Num(u64::from(index)))],
                );
                self.save_meta();
                self.sol.next_balance_ms = 0;
                self.refresh();
            }
            (SolKeysPurpose::Scan, Ok(keys)) => {
                let cluster = self.sol_cluster();
                // The disclosure was confirmed for one cluster's provider (spec/07 §3.3). A scan
                // reset while deriving (cluster switch) queries nothing; a cluster that differs
                // from the confirmed one needs the notice confirmed again.
                if self.sol.scan.stage != ScanStage::Deriving {
                    return;
                }
                if self.sol.scan.cluster != Some(cluster) {
                    self.sol.scan = SolScanState {
                        message: Some(SOL_SCAN_RECONFIRM_TEXT.to_owned()),
                        ..SolScanState::default()
                    };
                    self.refresh();
                    return;
                }
                match self.sol_endpoint(cluster) {
                    Ok(endpoint) => {
                        let job = self.sol.job();
                        self.sol.scan.job = job;
                        self.sol.scan.stage = ScanStage::Running;
                        self.sol.scan.cluster = Some(cluster);
                        let _ = self.rpc(RpcJob::SolScan {
                            job,
                            endpoint,
                            keys,
                        });
                    }
                    Err(code) => {
                        self.sol.scan.stage = ScanStage::Notice;
                        self.sol.scan.message = Some(code.text());
                    }
                }
                self.refresh();
            }
            (purpose, Err(error)) => {
                if matches!(purpose, SolKeysPurpose::AddAccount { .. }) {
                    self.sol.creating = false;
                } else {
                    self.sol.scan.stage = ScanStage::Notice;
                }
                self.error_banner(crate::errors::vault_code(error));
            }
        }
    }

    // ----- balances -----------------------------------------------------------------------

    /// Asks the balances of the visible accounts (Solana tab, spec/04 §2.6).
    pub fn sol_refresh_balances(&mut self) {
        self.sol.next_balance_ms = now_ms().saturating_add(SOL_BALANCE_REFRESH_MS);
        let cluster = self.sol_cluster();
        let accounts: Vec<SolAddress> = self
            .sol_account_rows()
            .into_iter()
            .map(|(_, _, address)| address)
            .collect();
        if accounts.is_empty() {
            return;
        }
        match self.sol_endpoint(cluster) {
            Ok(endpoint) => {
                let job = self.sol.job();
                self.sol.balance_job = job;
                let _ = self.rpc(RpcJob::SolBalances {
                    job,
                    endpoint,
                    accounts,
                });
            }
            Err(code) => {
                self.sol.balance_error.insert(cluster, code);
            }
        }
    }

    /// The balance of an account on the selected cluster.
    #[must_use]
    pub fn sol_balance(&self, address: &SolAddress) -> Option<u64> {
        self.sol
            .balances
            .get(&(self.sol_cluster(), *address))
            .copied()
    }

    /// The allowlisted token holdings of an account on the selected cluster (allowlist order;
    /// `None` until the first balance refresh). Other tokens are never fetched or shown.
    #[must_use]
    pub fn sol_token_holdings(
        &self,
        address: &SolAddress,
    ) -> Option<&[(&'static SplAllowEntry, TokenHolding)]> {
        self.sol
            .tokens
            .get(&(self.sol_cluster(), *address))
            .map(Vec::as_slice)
    }

    /// The holding of one allowlisted token of an account on the selected cluster.
    #[must_use]
    pub fn sol_token_holding(
        &self,
        address: &SolAddress,
        entry: &SplAllowEntry,
    ) -> Option<TokenHolding> {
        self.sol_token_holdings(address)?
            .iter()
            .find(|(known, _)| known.mint == entry.mint)
            .map(|(_, holding)| *holding)
    }

    /// The assets of the selected cluster: SOL, then the allowlisted tokens in table order.
    #[must_use]
    pub fn sol_assets(&self) -> Vec<SolAsset> {
        let mut assets = vec![SolAsset::Sol];
        assets.extend(spl_entries(self.sol_cluster()).map(SolAsset::Spl));
        assets
    }

    /// Picks the asset of the send form (index into [`Self::sol_assets`]); the recipient and
    /// amount are checked again for the new asset (decimals, SPL off-curve rule).
    pub fn sol_select_asset(&mut self, index: usize) {
        let Some(asset) = self.sol_assets().get(index).copied() else {
            return;
        };
        let token = asset.spl();
        if self.sol.send.token != token {
            self.sol.send.token = token;
            self.sol.send.info = None;
        }
        self.sol_validate_send();
    }

    // ----- events -------------------------------------------------------------------------

    /// RPC worker events of the Solana flows.
    pub fn sol_rpc_event(&mut self, event: RpcEvent) {
        match event {
            RpcEvent::SolBalances {
                job,
                cluster,
                result,
            } => {
                if job != self.sol.balance_job {
                    return;
                }
                match result {
                    Ok(list) => {
                        for row in list {
                            self.sol
                                .balances
                                .insert((cluster, row.address), row.lamports);
                            self.sol.tokens.insert((cluster, row.address), row.tokens);
                        }
                        self.sol.balance_error.remove(&cluster);
                    }
                    Err(code) => {
                        self.sol.balance_error.insert(cluster, code);
                    }
                }
                self.refresh();
            }
            RpcEvent::SolPreviewed(result) => self.on_sol_previewed(*result),
            RpcEvent::SolPreSigned { job, result } => self.on_sol_presigned(job, result),
            RpcEvent::SolTracked(result) => self.on_sol_tracked(&result),
            RpcEvent::SolScanned { job, result } => {
                if job != self.sol.scan.job {
                    return;
                }
                match result {
                    Ok(rows) => {
                        self.sol.scan.rows = rows;
                        self.sol.scan.stage = ScanStage::Done;
                        self.sol.scan.message = None;
                    }
                    Err(code) => {
                        self.sol.scan.stage = ScanStage::Notice;
                        self.sol.scan.message = Some(code.text());
                    }
                }
                self.refresh();
            }
            _ => {}
        }
    }

    /// Main-timer part: balances, form debounce, broadcast-loop rounds.
    pub fn sol_tick(&mut self, now: u64) {
        let on_tab = self
            .meta
            .as_ref()
            .is_some_and(|meta| meta.prefs.tab == Tab::Sol);
        if matches!(self.mode, AppMode::Unlocked { .. })
            && on_tab
            && matches!(self.screen, Screen::Main)
            && now >= self.sol.next_balance_ms
        {
            self.sol_refresh_balances();
        }
        if let Some(changed) = self.sol.send.dirty_ms
            && now.saturating_sub(changed) >= SOL_SEND_DEBOUNCE_MS
        {
            self.sol.send.dirty_ms = None;
            self.sol_validate_send();
        }
        self.sol_tick_tracking(now);
    }

    // ----- send form ----------------------------------------------------------------------

    /// Opens the SOL send form for the selected account.
    pub fn sol_open_send(&mut self) {
        if self.sol.send.moving.is_some() {
            self.sol.send = SolSendForm::default();
        }
        self.sol.send.info = None;
        self.set_screen(Screen::SolSend);
        self.sol_refresh_balances();
    }

    /// Whether the last sent transfer ended `Expired` / `FailedOnChain` and its inputs are kept
    /// ("다시 보내기", spec/07 §14.3).
    #[must_use]
    pub fn sol_can_resend(&self) -> bool {
        let Some((cluster, signature)) = self.sol.sent else {
            return false;
        };
        if self.sol.resend.is_none() {
            return false;
        }
        if let Some(record) = self
            .sol_records()
            .iter()
            .find(|record| record.signature() == signature)
        {
            return matches!(
                record.state,
                SolTxState::Expired | SolTxState::FailedOnChain
            );
        }
        let tx_id = yw_core::codec::base58::base58_encode(&signature);
        self.meta.as_ref().is_some_and(|meta| {
            meta.activity_of(cluster.network_id()).iter().any(|entry| {
                entry.tx_id == tx_id && matches!(entry.status.as_str(), "expired" | "failed")
            })
        })
    }

    /// "다시 보내기": the same inputs back in the send form; `검토` then starts a new preview,
    /// a new intent and a new approval (spec/07 §14.3). Nothing of the old approval is reused.
    pub fn sol_send_again(&mut self) {
        if !self.sol_can_resend() {
            return;
        }
        let Some((form, from)) = self.sol.resend.take() else {
            return;
        };
        if form.moving.is_none()
            && let Some(row) = self
                .sol_account_rows()
                .iter()
                .position(|(_, _, address)| *address == from)
        {
            self.sol_select_account(row);
        }
        self.sol.send = form;
        self.sol.sent = None;
        self.set_screen(Screen::SolSend);
        self.sol_validate_send();
        self.sol_refresh_balances();
    }

    /// The sending account of the form: `(source, from, label)`. An imported key signs as
    /// `SolKeySource::Imported` (found by `from` in the vault).
    #[must_use]
    pub fn sol_form_sender(&self) -> Option<(SolKeySource, SolAddress, String)> {
        if let Some((source, from)) = self.sol.send.moving {
            return Some((source, from, format!("비표준 경로 {}", source.path_text())));
        }
        let (id, label, address) = self.sol_selected()?;
        Some((id.source()?, address, label))
    }

    /// Validates the form (local checks only; the preview does the RPC part).
    pub fn sol_validate_send(&mut self) {
        let Some((_, from, _)) = self.sol_form_sender() else {
            return;
        };
        let known = self.sol_known();
        let cluster = self.sol_cluster();
        let form = &mut self.sol.send;
        // A token of another cluster (cluster switched under a kept form) falls back to SOL.
        if form.token.is_some_and(|entry| entry.cluster != cluster) {
            form.token = None;
        }
        let asset = form.asset();
        if form.to_text.trim().is_empty() {
            form.check = None;
            form.recipient_error = None;
        } else {
            match check_recipient_for(&form.to_text, &from, &known, asset) {
                Ok(check) => {
                    form.check = Some(check);
                    form.recipient_error = None;
                }
                Err(block) => {
                    form.check = None;
                    form.recipient_error = Some(recipient_code(block));
                }
            }
        }
        if form.send_max || form.amount_text.is_empty() {
            form.amount = None;
            form.amount_error = None;
        } else {
            match parse_amount(&form.amount_text, asset.decimals()) {
                Ok(amount) => {
                    form.amount = Some(amount);
                    form.amount_error = None;
                }
                Err(AmountError::Format | AmountError::Zero | AmountError::Overflow) => {
                    form.amount = None;
                    form.amount_error = Some(ErrorCode::Inp011);
                }
            }
        }
        self.refresh();
    }

    /// `최대` (send max): the amount is `balance − max fee`, computed at preview.
    pub fn sol_fill_max(&mut self) {
        self.sol.send.send_max = !self.sol.send.send_max;
        if self.sol.send.send_max {
            self.sol.send.amount_text.clear();
            self.controls
                .set_text(crate::ui::screens_sol::ids::SEND_AMOUNT_EDIT, "");
        }
        self.sol_validate_send();
    }

    /// Whether `검토` is enabled.
    #[must_use]
    pub fn sol_can_review(&self) -> bool {
        let form = &self.sol.send;
        let cluster = self.sol_cluster();
        let Some((_, from, _)) = self.sol_form_sender() else {
            return false;
        };
        form.check.is_some()
            && form.recipient_error.is_none()
            && (form.send_max || (form.amount.is_some() && form.amount_error.is_none()))
            && self.evm.journal.is_some()
            && !self.sol_journal_damaged()
            && self.sol_pending(cluster, &from).is_none()
            && self.sol.slot.is_none()
            && self.sol.pending_sign.is_none()
            && matches!(self.mode, AppMode::Unlocked { .. })
    }

    /// The approval item of `검토` (spec/07 §13.1 step 1). The form is validated again first and
    /// the item is built from that fresh result only: when the fresh recipient, asset or amount
    /// differs from the last shown validation (an edit inside the debounce), nothing is queued.
    ///
    /// # Errors
    ///
    /// [`ReviewRefusal`].
    pub fn sol_review_item(&mut self) -> Result<SolApprovalItem, ReviewRefusal> {
        let shown = ReviewInputs::of(&self.sol.send);
        self.sol.send.dirty_ms = None;
        self.sol_validate_send();
        if ReviewInputs::of(&self.sol.send) != shown {
            return Err(ReviewRefusal::Changed);
        }
        if !self.sol_can_review() {
            return Err(ReviewRefusal::NotReady);
        }
        let (source, from, label) = self.sol_form_sender().ok_or(ReviewRefusal::NotReady)?;
        let recipient = self.sol.send.check.clone().ok_or(ReviewRefusal::NotReady)?;
        Ok(SolApprovalItem {
            cluster: self.sol_cluster(),
            source,
            from,
            label,
            recipient,
            asset: self.sol.send.asset(),
            amount: if self.sol.send.send_max {
                None
            } else {
                self.sol.send.amount
            },
        })
    }

    /// `검토`: queue the approval built from a fresh validation (spec/07 §13.1 step 1 done, step
    /// 2 runs in A01).
    pub fn sol_review(&mut self) {
        let item = match self.sol_review_item() {
            Ok(item) => item,
            Err(ReviewRefusal::Changed) => {
                self.sol.send.info = Some(SOL_REVIEW_CHANGED_TEXT.to_owned());
                self.refresh();
                return;
            }
            Err(ReviewRefusal::NotReady) => return,
        };
        let (cluster, from) = (item.cluster, item.from);
        if self
            .evm
            .queue
            .enqueue(QueueSource::App, QueuedItem::Sol(Box::new(item)))
            .is_ok()
        {
            self.sol.slot = Some((cluster, from));
            self.sol.send.info = None;
            self.show_next_approval();
        } else {
            self.sol.send.info = Some(ErrorCode::App005.text());
            self.refresh();
        }
    }

    /// An approval ended (any outcome; spec/04 §3.1: back to the form with inputs kept).
    pub fn sol_approval_finished(&mut self, _item: &SolApprovalItem, outcome: QueueOutcome) {
        if outcome != QueueOutcome::Approved {
            self.sol.slot = None;
        }
        if outcome == QueueOutcome::Expired {
            self.sol.send.info = Some("승인 시간이 지났습니다. 다시 검토하세요.".to_owned());
        }
        logging::info(
            "app",
            "approval.finished",
            &[(
                "outcome",
                Field::Word(crate::app_evm::outcome_name(outcome)),
            )],
        );
        self.refresh();
    }

    // ----- approval window: preview, consume, sign -----------------------------------------

    /// Step 2 on the RPC worker (called by `start_prepare`).
    pub fn prepare_sol(&mut self, job: u64, item: &SolApprovalItem) {
        let endpoint = match self.sol_endpoint(item.cluster) {
            Ok(endpoint) => endpoint,
            Err(code) => {
                self.show_failure(code, false, code.text());
                return;
            }
        };
        let journal_room = self
            .evm
            .journal
            .as_ref()
            .is_some_and(|journal| journal.sol_room);
        let sent = self.rpc(RpcJob::SolPreview(Box::new(PreviewJob {
            job,
            endpoint,
            source: item.source,
            from: item.from,
            account_label: item.label.clone(),
            recipient: item.recipient.clone(),
            asset: item.asset,
            amount: item.amount,
            fee_cap: self.settings.solana.max_fee_lamports,
            max_cu_price: self.settings.solana.max_cu_price_micro,
            pending_exists: self.sol_pending(item.cluster, &item.from).is_some(),
            journal_room,
        })));
        if !sent {
            self.show_failure(ErrorCode::Rpc001, true, ErrorCode::Rpc001.text());
        }
    }

    fn on_sol_previewed(&mut self, result: PreviewResult) {
        let matches = self
            .evm
            .window
            .as_ref()
            .is_some_and(|window| window.job() == result.job);
        if !matches {
            return;
        }
        match result.outcome {
            PreviewOutcome::Failed { code, retryable } => {
                logging::warn("app", "sol.preview_failed", &[("code", Field::Code(code))]);
                self.show_failure(code, retryable, code.text());
            }
            PreviewOutcome::Ready(prepared) => {
                let Ok(id) = Self::new_approval_id() else {
                    self.show_failure(ErrorCode::Vlt005, false, ErrorCode::Vlt005.text());
                    return;
                };
                let now_unix = now_unix_ms();
                let intent = prepared.intent(id.0, now_unix);
                if prepared.core.cu_limit != template_cu_limit(prepared.core.asset) {
                    self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
                    return;
                }
                match build_sol_transfer_request(&intent, &prepared.genesis, &prepared.facts) {
                    Ok(draft) => self.show_ready_draft_at(draft, None, now_unix),
                    Err(_) => {
                        self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text());
                    }
                }
            }
        }
    }

    /// `consume` succeeded (spec/07 §13.1 step 4): fetch the finalized blockhash now; a
    /// `YubiKey` transfer first goes through the card step (PIN window, spec/10 §9.2) and comes
    /// back in [`App::sol_consumed_card`].
    pub fn sol_consumed(&mut self, approved: Approved, cluster: SolCluster, consumed_at_ms: u64) {
        let approved = match self.card_begin(
            approved,
            crate::app_card::CardJobKind::SolTransfer { cluster },
            None,
        ) {
            Ok(()) => return,
            Err(approved) => *approved,
        };
        self.sol_presign(approved, cluster, consumed_at_ms, None);
    }

    /// The card step's PIN is in: fetch the blockhash, then `SignSolCard` (the SOL signing
    /// deadline runs from `consumed_at_ms`, the PIN submission).
    pub(crate) fn sol_consumed_card(
        &mut self,
        approved: Approved,
        cluster: SolCluster,
        consumed_at_ms: u64,
        pin: crate::app_card::PinBuffer,
    ) {
        self.sol_presign(approved, cluster, consumed_at_ms, Some(pin));
    }

    fn sol_presign(
        &mut self,
        approved: Approved,
        cluster: SolCluster,
        consumed_at_ms: u64,
        pin: Option<crate::app_card::PinBuffer>,
    ) {
        let job = self.sol.job();
        match self.sol_endpoint(cluster) {
            Ok(endpoint) => {
                self.sol.pending_sign = Some(PendingSign {
                    approved: Box::new(approved),
                    consumed_at_ms,
                    job,
                    pin,
                });
                if !self.rpc(RpcJob::SolPreSign { job, endpoint }) {
                    self.sol_abort_sign(ErrorCode::Rpc001);
                }
            }
            Err(code) => {
                drop(approved);
                drop(pin);
                self.sol.slot = None;
                self.sol_abort_message(code);
            }
        }
    }

    fn sol_abort_message(&mut self, cause: ErrorCode) {
        // A YubiKey transfer whose blockhash step failed never reaches the card.
        self.card_abandon_sol();
        let message = format!("{} — {}", ErrorCode::Sol004.text(), cause.text());
        logging::warn("app", "sol.sign_aborted", &[("code", Field::Code(cause))]);
        self.sol.send.info = Some(message.clone());
        self.banner(None, message);
        self.refresh();
    }

    fn sol_abort_sign(&mut self, cause: ErrorCode) {
        self.sol.pending_sign = None;
        self.sol.slot = None;
        self.sol_abort_message(cause);
    }

    fn on_sol_presigned(&mut self, job: u64, result: Result<([u8; 32], u64), PreSignError>) {
        let Some(pending) = self.sol.pending_sign.take() else {
            return;
        };
        if pending.job != job {
            self.sol.pending_sign = Some(pending);
            return;
        }
        match result {
            Ok((blockhash, last_valid_block_height)) => match pending.pin {
                Some(pin) => self.key(KeyJob::SignSolCard {
                    approved: pending.approved,
                    consumed_at_ms: pending.consumed_at_ms,
                    blockhash,
                    last_valid_block_height,
                    now_unix_ms: now_unix_ms(),
                    pin: pin.into_inner(),
                }),
                None => self.key(KeyJob::SignSol {
                    approved: pending.approved,
                    consumed_at_ms: pending.consumed_at_ms,
                    blockhash,
                    last_valid_block_height,
                    now_unix_ms: now_unix_ms(),
                }),
            },
            Err(error) => {
                let code = match error {
                    PreSignError::Rpc(code) => code,
                    PreSignError::ClusterMismatch => ErrorCode::Rpc006,
                    PreSignError::RpcAnomaly => ErrorCode::Rpc005,
                };
                self.sol.slot = None;
                self.sol_abort_message(code);
            }
        }
    }

    /// `SignSol` finished.
    pub fn on_sol_signed(&mut self, result: Result<SolSignedSummary, SolSignFailure>) {
        self.sol.slot = None;
        match result {
            Ok(signed) => {
                logging::info(
                    "app",
                    "sol.signed",
                    &[("net", Field::Net(sol_network(signed.cluster)))],
                );
                self.sol.sent = Some((signed.cluster, signed.signature));
                let form = std::mem::take(&mut self.sol.send);
                self.sol.resend = Some((
                    SolSendForm {
                        moving: form.moving,
                        token: form.token,
                        to_text: form.to_text,
                        amount_text: form.amount_text,
                        send_max: form.send_max,
                        ..SolSendForm::default()
                    },
                    signed.from,
                ));
                self.sol.tracking.insert(
                    signed.signature,
                    SolTrackState {
                        next_ms: 0,
                        // Signed just now after a genesis check (step 5).
                        genesis_checked: true,
                        ..SolTrackState::default()
                    },
                );
                if matches!(self.screen, Screen::SolSend) {
                    self.set_screen(Screen::SolSendResult);
                } else {
                    self.refresh();
                }
                self.sol_tick_tracking(now_ms());
            }
            Err(failure) => {
                let cause = match failure {
                    SolSignFailure::Sign(yw_core::sol::SolSignError::Vault(error)) => {
                        crate::errors::vault_code(error)
                    }
                    SolSignFailure::Sign(yw_core::sol::SolSignError::PendingExists) => {
                        ErrorCode::Tx002
                    }
                    SolSignFailure::Sign(_) | SolSignFailure::AlreadySigned => ErrorCode::Tx003,
                    SolSignFailure::JournalFull => ErrorCode::Tx005,
                    SolSignFailure::JournalWrite(_) => ErrorCode::Vlt003,
                    SolSignFailure::Card(error) => {
                        let message = format!("{} — {error}", ErrorCode::Sol004.text());
                        logging::warn(
                            "app",
                            "sol.sign_aborted",
                            &[("reason", Field::Word("card"))],
                        );
                        self.sol.send.info = Some(message.clone());
                        self.banner(None, message);
                        self.refresh();
                        return;
                    }
                };
                self.sol_abort_message(cause);
            }
        }
    }

    /// A consumed SOL approval ended without a signature because of the lock.
    pub fn sol_sign_cancelled(&mut self) {
        self.sol.slot = None;
        self.sol.pending_sign = None;
        logging::info(
            "app",
            "sol.sign_aborted",
            &[("reason", Field::Word("locked"))],
        );
    }

    // ----- broadcast loop -------------------------------------------------------------------

    /// Starts tracking every `Pending` record of the journal (after unlock / journal change).
    pub fn sol_schedule_tracking(&mut self) {
        let pending: Vec<[u8; 64]> = self
            .sol_records()
            .iter()
            .filter(|record| record.state == SolTxState::Pending)
            .map(SolRecord::signature)
            .collect();
        self.sol
            .tracking
            .retain(|signature, _| pending.contains(signature));
        for signature in pending {
            self.sol.tracking.entry(signature).or_default();
        }
    }

    /// The `Pending` record "지금 다시 전송" acts on: the one just sent (result screen), else the
    /// send form's sender's (spec/07 §14.3). `None` when it is not `Pending`, its loop is stopped
    /// (cluster mismatch, saving a final state) or the app is not tracking it.
    #[must_use]
    pub fn sol_send_now_target(&self) -> Option<[u8; 64]> {
        let records = self.sol_records();
        let pending = |signature: [u8; 64]| {
            records.iter().any(|record| {
                record.signature() == signature && record.state == SolTxState::Pending
            }) && self
                .sol
                .tracking
                .get(&signature)
                .is_some_and(|state| state.halt.is_none())
        };
        if matches!(self.screen, Screen::SolSendResult) {
            return self
                .sol
                .sent
                .map(|(_, signature)| signature)
                .filter(|signature| pending(*signature));
        }
        let (_, from, _) = self.sol_form_sender()?;
        let record = self.sol_pending(self.sol_cluster(), &from)?;
        Some(record.signature()).filter(|signature| pending(*signature))
    }

    /// "지금 다시 전송": re-send the same signed bytes of the pending record right away instead
    /// of waiting for the next re-send period (spec/07 §14.3). Never re-signs; the signature is
    /// the journaled one, so the transfer can land at most once.
    pub fn sol_send_now(&mut self) {
        let Some(signature) = self.sol_send_now_target() else {
            return;
        };
        if let Some(state) = self.sol.tracking.get_mut(&signature) {
            state.send_now = true;
            state.next_ms = 0;
        }
        logging::info("app", "sol.send_now", &[]);
        self.sol_tick_tracking(now_ms());
        self.refresh();
    }

    fn sol_tick_tracking(&mut self, now: u64) {
        let records = self.sol_records();
        // A final state that is still not in the journal long after `SolApply`: the write failed
        // (the key worker reports it only to the log). Resume the loop; it observes the same
        // final state again and asks to write it again.
        for state in self.sol.tracking.values_mut() {
            if let Some(SolHalt::Saving { since_ms }) = state.halt
                && now.saturating_sub(since_ms) >= SOL_APPLY_RETRY_MS
            {
                state.halt = None;
                state.save_failed = true;
                state.next_ms = now;
            }
        }
        let due: Vec<[u8; 64]> = self
            .sol
            .tracking
            .iter()
            .filter(|(_, state)| !state.busy && state.halt.is_none() && now >= state.next_ms)
            .map(|(signature, _)| *signature)
            .collect();
        for signature in due {
            let Some(record) = records.iter().find(|record| {
                record.signature() == signature && record.state == SolTxState::Pending
            }) else {
                continue;
            };
            let Ok(endpoint) = self.sol_endpoint(record.cluster) else {
                if let Some(state) = self.sol.tracking.get_mut(&signature) {
                    state.error = Some(ErrorCode::Key005);
                    state.next_ms = now.saturating_add(5_000);
                }
                continue;
            };
            let Some(state) = self.sol.tracking.get_mut(&signature) else {
                continue;
            };
            if std::mem::take(&mut state.send_now) {
                state.state.send_now();
            }
            let job = TrackJob {
                endpoint,
                signature,
                tx: record.tx.clone(),
                pending: PendingTx {
                    signed_at_ms: record.signed_at_ms,
                    last_valid_block_height: record.last_valid_block_height,
                },
                state: state.state,
                check_genesis: !state.genesis_checked,
                generation: state.generation,
            };
            state.busy = true;
            if !self.rpc(RpcJob::SolTrack(Box::new(job)))
                && let Some(state) = self.sol.tracking.get_mut(&signature)
            {
                state.busy = false;
            }
        }
    }

    /// A broadcast round finished (RPC worker).
    fn on_sol_tracked(&mut self, result: &TrackResult) {
        let now = now_ms();
        let Some(state) = self.sol.tracking.get_mut(&result.signature) else {
            return;
        };
        state.busy = false;
        if result.generation != state.generation {
            // Started before the URL changed: its genesis check and outcome belong to the old
            // endpoint. Drop them and run a fresh round (with the genesis check) right away.
            state.next_ms = now;
            self.refresh();
            return;
        }
        // A "지금 다시 전송" asked while this round ran goes out with the next round, right away.
        state.next_ms = if state.send_now {
            now
        } else {
            now.saturating_add(SOL_POLL_INTERVAL_MS)
        };
        state.state = result.state;
        match result.genesis_ok {
            Some(true) => state.genesis_checked = true,
            Some(false) => state.halt = Some(SolHalt::ClusterMismatch),
            None => {}
        }
        let transition = match result.outcome {
            Ok(Outcome::Pending { notice }) => {
                state.notice = notice;
                state.error = None;
                None
            }
            Ok(Outcome::Landed { slot }) => Some(SolTransition::Landed {
                signature: result.signature,
                slot,
            }),
            Ok(Outcome::FailedOnChain { slot, err }) => Some(SolTransition::FailedOnChain {
                signature: result.signature,
                slot,
                err,
            }),
            Ok(Outcome::Expired) => Some(SolTransition::Expired {
                signature: result.signature,
            }),
            Err(code) => {
                state.error = Some(code);
                None
            }
        };
        if let Some(transition) = transition {
            logging::info(
                "app",
                "sol.terminal",
                &[("kind", Field::Word(transition.name()))],
            );
            if matches!(self.mode, AppMode::Unlocked { .. }) {
                state.halt = Some(SolHalt::Saving { since_ms: now });
                self.key(KeyJob::SolApply {
                    transition,
                    now_unix_ms: now_unix_ms(),
                });
            }
            // Locked: the journal is written after unlock (spec/07 §14.2); the loop resumes from
            // the journal then and observes the same final state.
        }
        self.refresh();
    }

    /// The status text of a pending record.
    #[must_use]
    pub fn sol_record_status(&self, record: &SolRecord) -> String {
        match record.state {
            SolTxState::Pending => {
                let state = self.sol.tracking.get(&record.signature());
                let mut text = if state.is_some_and(|state| state.state.processing) {
                    "처리 중 (confirmed 대기)".to_owned()
                } else {
                    "전송 확인 중".to_owned()
                };
                if let Some(state) = state {
                    if let Some(code) = state.state.preflight_err {
                        let _ = write!(
                            text,
                            " — 재전송 중지: {}",
                            yw_core::sol::broadcast::err::text(code)
                        );
                    }
                    if state.state.anomaly {
                        text.push_str(" — RPC가 다른 서명을 반환함(RpcAnomaly)");
                    }
                    if state.halt == Some(SolHalt::ClusterMismatch) {
                        let _ = write!(text, " — {}", ErrorCode::Rpc006.text());
                    } else if state.save_failed {
                        let _ = write!(text, " — {SOL_SAVE_FAILED_TEXT}");
                    } else if state.halt.is_some() {
                        let _ = write!(text, " — {SOL_SAVING_TEXT}");
                    } else if let Some(code) = state.error {
                        let _ = write!(text, " — 조회 실패 {}", code.code());
                    }
                    if state.notice {
                        let _ = write!(text, " — {}", ErrorCode::Sol005.text());
                    }
                }
                text
            }
            SolTxState::Landed => "성공".to_owned(),
            SolTxState::FailedOnChain => format!(
                "실패: {}",
                yw_core::sol::broadcast::err::text(record.terminal_err)
            ),
            SolTxState::Expired => "만료 (전송되지 않음)".to_owned(),
        }
    }

    // ----- lock, URL changes ----------------------------------------------------------------

    /// Lock: drop the unlocked state (the approval token, if any, is dropped unused).
    pub fn sol_lock(&mut self) {
        self.sol.clear_unlocked();
    }

    /// The `solana:<cluster>` URL changed: re-check the genesis on the next rounds. The new
    /// generation makes a round still running against the old URL a stale one: its genesis check
    /// can neither mark the new URL checked nor halt it.
    pub fn sol_url_changed(&mut self, cluster: crate::network::SolCluster) {
        let cluster = core_cluster(cluster);
        let records = self.sol_records();
        for (signature, state) in &mut self.sol.tracking {
            if records
                .iter()
                .any(|record| record.signature() == *signature && record.cluster == cluster)
            {
                state.generation = state.generation.wrapping_add(1);
                state.genesis_checked = false;
                if state.halt == Some(SolHalt::ClusterMismatch) {
                    state.halt = None;
                }
            }
        }
        self.sol.balance_error.remove(&cluster);
        self.sol.next_balance_ms = 0;
    }

    // ----- receive, book, scan --------------------------------------------------------------

    /// Copies the selected address (not a secret: plain clipboard, spec/07 §12.3).
    pub fn sol_copy_address(&mut self) {
        if let Some((_, _, address)) = self.sol_selected() {
            self.copy_text(&address.to_base58());
        }
    }

    /// Opens the scan screen at its notice.
    pub fn sol_open_scan(&mut self) {
        if !matches!(
            self.sol.scan.stage,
            ScanStage::Deriving | ScanStage::Running
        ) {
            self.sol.scan = SolScanState::default();
        }
        self.set_screen(Screen::SolScan);
    }

    /// Starts the scan after the disclosure was confirmed (spec/07 §3.3) for the selected
    /// cluster; the scan only runs against that cluster.
    pub fn sol_start_scan(&mut self) {
        if self.sol.scan.stage != ScanStage::Notice {
            return;
        }
        let cluster = self.sol_cluster();
        if self.sol_endpoint(cluster).is_err() {
            self.sol.scan.message = Some(ErrorCode::Key005.text());
            self.refresh();
            return;
        }
        self.sol.scan.stage = ScanStage::Deriving;
        self.sol.scan.cluster = Some(cluster);
        self.sol.scan.message = None;
        self.key(KeyJob::SolKeys {
            purpose: SolKeysPurpose::Scan,
            sources: scan_sources(),
        });
        self.refresh();
    }

    /// Scan rows worth showing: funded accounts and standard accounts not yet added.
    #[must_use]
    pub fn sol_scan_rows(&self) -> Vec<ScanRow> {
        let known: Vec<u32> = self
            .meta
            .as_ref()
            .map(|meta| {
                meta.sol_accounts
                    .iter()
                    .map(|account| account.index)
                    .collect()
            })
            .unwrap_or_default();
        self.sol
            .scan
            .rows
            .iter()
            .filter(|row| {
                row.has_funds()
                    && !matches!(row.source, SolKeySource::Standard(index) if known.contains(&index.get()))
            })
            .cloned()
            .collect()
    }

    /// `계정 추가` from a scan row (standard path only).
    pub fn sol_scan_add(&mut self, row: usize) {
        let rows = self.sol_scan_rows();
        let Some(ScanRow {
            source: SolKeySource::Standard(index),
            address,
            ..
        }) = rows.get(row).cloned()
        else {
            return;
        };
        if let Some(meta) = self.meta.as_mut()
            && !meta
                .sol_accounts
                .iter()
                .any(|account| account.index == index.get())
            && meta.sol_accounts.len() < crate::meta::MAX_EVM_ACCOUNTS
        {
            meta.sol_accounts.push(Account {
                index: index.get(),
                label: format!("Solana {}", index.get().saturating_add(1)),
                address: address.to_base58(),
                hidden: false,
            });
            meta.sol_accounts.sort_by_key(|account| account.index);
        }
        self.save_meta();
        self.refresh();
    }

    /// `표준 계정으로 이동` from a non-standard scan row: the send form with the recipient fixed
    /// to the selected standard account and "send max" (spec/07 §3.3).
    pub fn sol_scan_move(&mut self, row: usize) {
        let rows = self.sol_scan_rows();
        let Some(row) = rows.get(row).cloned() else {
            return;
        };
        if row.source.is_standard() {
            return;
        }
        let Some((_, _, target)) = self.sol_selected() else {
            return;
        };
        // Tokens first (moving them needs the SOL for fees), then SOL; the asset can be changed.
        let token = row
            .tokens
            .iter()
            .find(|(_, holding)| holding.balance().is_some_and(|amount| amount > 0))
            .map(|(entry, _)| *entry);
        // The scan's reference balances of the non-standard account, for the form.
        let cluster = self.sol.scan.cluster.unwrap_or_else(|| self.sol_cluster());
        self.sol
            .balances
            .insert((cluster, row.address), row.balance);
        self.sol
            .tokens
            .insert((cluster, row.address), row.tokens.clone());
        self.sol.send = SolSendForm {
            moving: Some((row.source, row.address)),
            token,
            to_text: target.to_base58(),
            send_max: true,
            ..SolSendForm::default()
        };
        self.set_screen(Screen::SolSend);
        self.sol_validate_send();
    }

    /// Lamports as `x.xxxxxxxxx SOL`.
    #[must_use]
    pub fn sol_text(lamports: u64) -> String {
        format!("{} SOL", format_amount(lamports, 9))
    }
}

#[cfg(test)]
mod tests {
    use yw_core::bip32::path::AccountIndex;
    use yw_core::journal::sol::{SolRecord, SolTxState};
    use yw_core::slip10::SolKeySource;
    use yw_core::sol::broadcast::{LoopState, Outcome};
    use yw_core::sol::message::{assemble_transaction, encode_message};
    use yw_core::sol::recipient::KnownKind;
    use yw_core::sol::{SolAddress, SolAsset, SolCluster, SolTransferCore};

    use super::{
        ReviewRefusal, SOL_APPLY_RETRY_MS, SOL_REVIEW_CHANGED_TEXT, SOL_SAVE_FAILED_TEXT,
        SOL_SAVING_TEXT, SOL_SCAN_RECONFIRM_TEXT, ScanStage, SolHalt, now_ms,
    };
    use crate::apikeys::ApiKeys;
    use crate::app::{App, AppMode, Paths, Screen};
    use crate::errors::ErrorCode;
    use crate::events::{JournalView, SolKeysPurpose};
    use crate::meta::{Account, ActivityEntry, Meta, Tab};
    use crate::settings::Settings;
    use crate::sol::flow::TrackResult;

    const OWN: [u8; 32] = [200; 32];
    const TO_A: &str = "Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb";
    const TO_B: &str = "7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm";

    /// An unlocked wallet with Solana account 0 on the send screen (mainnet, empty journal).
    fn app() -> App {
        let dir = std::env::temp_dir().join(format!("yw-app-sol-ui-{}", std::process::id()));
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
        let mut meta = Meta {
            sol_accounts: vec![Account {
                index: 0,
                label: "Solana 1".to_owned(),
                address: SolAddress::from_bytes(OWN).to_base58(),
                hidden: false,
            }],
            ..Meta::default()
        };
        meta.prefs.tab = Tab::Sol;
        app.meta = Some(meta);
        app.evm.journal = Some(JournalView::default());
        app.screen = Screen::SolSend;
        app
    }

    fn addr(text: &str) -> SolAddress {
        SolAddress::parse(text).unwrap()
    }

    /// A journal record of a `T_SOL` transfer from account 0 (fake signature `[sig; 64]`).
    fn record(cluster: SolCluster, state: SolTxState, to: &str, sig: u8) -> SolRecord {
        let core = SolTransferCore {
            from: SolAddress::from_bytes(OWN),
            to: addr(to),
            asset: SolAsset::Sol,
            amount: 1_000_000,
            cu_limit: 600,
            cu_price_micro: 0,
        };
        SolRecord {
            state,
            cluster,
            source: SolKeySource::Standard(AccountIndex::ZERO),
            intent_id: [sig; 16],
            intent_hash: [sig; 32],
            signed_at_ms: 1,
            last_valid_block_height: 1_150,
            terminal_slot: 0,
            terminal_err: 0,
            tx: assemble_transaction(&[sig; 64], &encode_message(&core, &[7; 32])),
        }
    }

    /// `app()` with one `Pending` mainnet record being tracked.
    fn tracking_app() -> (App, [u8; 64]) {
        let mut app = app();
        let pending = record(SolCluster::Mainnet, SolTxState::Pending, TO_A, 0x5a);
        let signature = pending.signature();
        app.evm.journal = Some(JournalView {
            sol_records: vec![pending],
            ..JournalView::default()
        });
        app.sol_schedule_tracking();
        (app, signature)
    }

    fn round(signature: [u8; 64], generation: u64, outcome: Outcome) -> TrackResult {
        TrackResult {
            signature,
            state: LoopState::default(),
            outcome: Ok(outcome),
            genesis_ok: Some(true),
            sends: 0,
            generation,
        }
    }

    #[test]
    fn a_round_from_before_a_url_change_cannot_set_or_clear_the_genesis_flag() {
        let (mut app, signature) = tracking_app();
        // A round with the genesis check runs (generation 0) when the URL changes.
        app.sol.tracking.get_mut(&signature).unwrap().busy = true;
        app.sol_url_changed(crate::network::SolCluster::Mainnet);
        let state = app.sol.tracking[&signature];
        assert_eq!(state.generation, 1);
        assert!(!state.genesis_checked);
        // Its completion is stale: "checked" is not set for the new URL, nothing terminal is
        // applied, and the next round starts at once.
        app.on_sol_tracked(&round(signature, 0, Outcome::Landed { slot: 9 }));
        let state = app.sol.tracking[&signature];
        assert!(!state.busy);
        assert!(!state.genesis_checked);
        assert_eq!(state.halt, None);
        // A stale mismatch cannot halt the new URL either.
        let mut mismatch = round(signature, 0, Outcome::Pending { notice: false });
        mismatch.genesis_ok = Some(false);
        app.on_sol_tracked(&mismatch);
        assert_eq!(app.sol.tracking[&signature].halt, None);
        // The new generation's own check counts.
        app.on_sol_tracked(&round(signature, 1, Outcome::Pending { notice: false }));
        assert!(app.sol.tracking[&signature].genesis_checked);
        mismatch.generation = 1;
        app.on_sol_tracked(&mismatch);
        assert_eq!(
            app.sol.tracking[&signature].halt,
            Some(SolHalt::ClusterMismatch)
        );
        let pending = app.sol_records().remove(0);
        assert!(
            app.sol_record_status(&pending)
                .contains(ErrorCode::Rpc006.text().as_str())
        );
        // A URL change lifts the mismatch halt.
        app.sol_url_changed(crate::network::SolCluster::Mainnet);
        assert_eq!(app.sol.tracking[&signature].halt, None);
    }

    #[test]
    fn a_final_state_not_saved_shows_the_save_texts_not_the_cluster_text() {
        let (mut app, signature) = tracking_app();
        app.on_sol_tracked(&round(signature, 0, Outcome::Landed { slot: 9 }));
        let state = app.sol.tracking[&signature];
        assert!(matches!(state.halt, Some(SolHalt::Saving { .. })));
        let pending = app.sol_records().remove(0);
        let text = app.sol_record_status(&pending);
        assert!(text.contains(SOL_SAVING_TEXT), "{text}");
        assert!(!text.contains(ErrorCode::Rpc006.text().as_str()), "{text}");
        // Still `Pending` in the journal long after `SolApply`: the write failed. The loop
        // resumes (to observe and save again) and says so.
        app.sol_tick_tracking(now_ms().saturating_add(SOL_APPLY_RETRY_MS));
        let state = app.sol.tracking[&signature];
        assert_eq!(state.halt, None);
        assert!(state.save_failed);
        let text = app.sol_record_status(&pending);
        assert!(text.contains(SOL_SAVE_FAILED_TEXT), "{text}");
        assert!(!text.contains(ErrorCode::Rpc006.text().as_str()), "{text}");
        // Once the journal has the final state, the record leaves tracking.
        app.evm.journal = Some(JournalView {
            sol_records: vec![record(SolCluster::Mainnet, SolTxState::Landed, TO_A, 0x5a)],
            ..JournalView::default()
        });
        app.sol_schedule_tracking();
        assert!(app.sol.tracking.is_empty());
    }

    #[test]
    fn only_successful_sends_on_this_cluster_make_a_recipient_known() {
        const TO_C: &str = "GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL";
        const TO_D: &str = "ANf3TEKFL6jPWjzkndo4CbnNdUNkBk4KHPggJs2nu8Xi";
        const TO_E: &str = "D2PPQSYFe83nDzk96FqGumVU8JA7J8vj2Rhjc2oXzEi5";
        let mut app = app();
        let row = |to: &str, status: &str, sig: u8| ActivityEntry {
            account: SolAddress::from_bytes(OWN).to_base58(),
            tx_id: SolAddress::from_bytes([sig; 32]).to_base58(),
            title: "SOL 전송".to_owned(),
            asset: "native".to_owned(),
            amount: "1".to_owned(),
            counterparty: to.to_owned(),
            status: status.to_owned(),
            time_unix_ms: u64::from(sig),
        };
        let mainnet = SolCluster::Mainnet.network_id();
        let devnet = SolCluster::Devnet.network_id();
        {
            let meta = app.meta.as_mut().unwrap();
            meta.upsert_activity(mainnet, &row(TO_A, "expired", 1));
            meta.upsert_activity(mainnet, &row(TO_B, "failed", 2));
            meta.upsert_activity(devnet, &row(TO_C, "succeeded", 3));
        }
        app.evm.journal = Some(JournalView {
            sol_records: vec![
                record(SolCluster::Mainnet, SolTxState::Pending, TO_D, 4),
                record(SolCluster::Devnet, SolTxState::Landed, TO_E, 5),
            ],
            ..JournalView::default()
        });
        let first_time = |app: &mut App, to: &str| {
            app.sol.send.to_text = to.to_owned();
            app.sol_validate_send();
            app.sol.send.check.as_ref().unwrap().first_time
        };
        // Expired, failed, pending, or a success on the other cluster: still a first time.
        for to in [TO_A, TO_B, TO_C, TO_D, TO_E] {
            assert!(first_time(&mut app, to), "{to}");
        }
        assert_eq!(
            app.sol_known()
                .iter()
                .filter(|known| known.kind == KnownKind::History)
                .count(),
            5
        );
        // A success on this cluster makes it known (activity, or a `Landed` journal record).
        app.meta
            .as_mut()
            .unwrap()
            .upsert_activity(mainnet, &row(TO_A, "succeeded", 6));
        assert!(!first_time(&mut app, TO_A));
        app.evm.journal = Some(JournalView {
            sol_records: vec![record(SolCluster::Mainnet, SolTxState::Landed, TO_D, 4)],
            ..JournalView::default()
        });
        assert!(!first_time(&mut app, TO_D));
        // On devnet the devnet successes are the known ones.
        app.settings.solana.cluster = crate::network::SolCluster::Devnet;
        assert!(!first_time(&mut app, TO_C));
        assert!(first_time(&mut app, TO_A));
    }

    #[test]
    fn the_scan_runs_only_for_the_cluster_whose_notice_was_confirmed() {
        let _ = std::fs::create_dir_all(
            std::env::temp_dir().join(format!("yw-app-sol-ui-{}", std::process::id())),
        );
        let mut app = app();
        let url = yw_win::http::HttpsUrl::parse("https://rpc.example.test/v1").unwrap();
        for cluster in [
            crate::network::SolCluster::Mainnet,
            crate::network::SolCluster::Devnet,
        ] {
            app.apikeys
                .set_rpc(crate::network::NetworkId::Solana(cluster), &url);
        }
        app.sol_open_scan();
        app.sol_start_scan();
        assert_eq!(app.sol.scan.stage, ScanStage::Deriving);
        assert_eq!(app.sol.scan.cluster, Some(SolCluster::Mainnet));
        // The cluster is switched while the keys are derived: back to the notice, and the keys
        // that arrive afterwards query nothing.
        assert!(app.on_sol_command(crate::ui::screens_sol::ids::CLUSTER_DEVNET));
        assert_eq!(app.sol_cluster(), SolCluster::Devnet);
        assert_eq!(app.sol.scan.stage, ScanStage::Notice);
        app.on_sol_keys(SolKeysPurpose::Scan, Ok(Vec::new()));
        assert_eq!(app.sol.scan.stage, ScanStage::Notice);
        assert_eq!(app.sol.scan.job, 0);
        // Confirmed for devnet, then the selection changes without a reset: confirm again.
        app.sol_start_scan();
        assert_eq!(app.sol.scan.cluster, Some(SolCluster::Devnet));
        app.settings.solana.cluster = crate::network::SolCluster::Mainnet;
        app.on_sol_keys(SolKeysPurpose::Scan, Ok(Vec::new()));
        assert_eq!(app.sol.scan.stage, ScanStage::Notice);
        assert_eq!(
            app.sol.scan.message.as_deref(),
            Some(SOL_SCAN_RECONFIRM_TEXT)
        );
        assert_eq!(app.sol.scan.job, 0);
        // Confirmed for the selected cluster: the scan runs there.
        app.sol_start_scan();
        app.on_sol_keys(SolKeysPurpose::Scan, Ok(Vec::new()));
        assert_eq!(app.sol.scan.stage, ScanStage::Running);
        assert_eq!(app.sol.scan.cluster, Some(SolCluster::Mainnet));
        assert_ne!(app.sol.scan.job, 0);
        // A second confirmation click while it runs starts nothing.
        let job = app.sol.scan.job;
        app.sol_start_scan();
        assert_eq!(app.sol.scan.stage, ScanStage::Running);
        assert_eq!(app.sol.scan.job, job);
    }

    #[test]
    fn review_uses_a_fresh_validation_and_refuses_a_changed_input() {
        let mut app = app();
        app.sol.send.to_text = TO_A.to_owned();
        app.sol.send.amount_text = "1".to_owned();
        app.sol_validate_send();
        assert_eq!(app.sol.send.check.as_ref().unwrap().to, addr(TO_A));
        // Edits inside the debounce: the shown validation still says A / 1 SOL.
        app.sol.send.to_text = TO_B.to_owned();
        app.sol.send.dirty_ms = Some(1);
        assert_eq!(app.sol_review_item().unwrap_err(), ReviewRefusal::Changed);
        assert_eq!(app.sol.send.check.as_ref().unwrap().to, addr(TO_B));
        assert_eq!(app.sol.send.dirty_ms, None);
        // The fresh validation is now on screen: the item is built from it.
        let item = app.sol_review_item().unwrap();
        assert_eq!(item.recipient.to, addr(TO_B));
        assert_eq!(item.amount, Some(1_000_000_000));
        // The amount too.
        app.sol.send.amount_text = "2".to_owned();
        assert_eq!(app.sol_review_item().unwrap_err(), ReviewRefusal::Changed);
        assert_eq!(app.sol_review_item().unwrap().amount, Some(2_000_000_000));
        // And the asset (a token of another cluster falls back to SOL on validation).
        let devnet_usdc = yw_core::sol::template::spl_entries(yw_core::sol::SolCluster::Devnet)
            .next()
            .unwrap();
        app.sol.send.token = Some(devnet_usdc);
        assert_eq!(app.sol_review_item().unwrap_err(), ReviewRefusal::Changed);
        assert_eq!(app.sol.send.token, None);
        // `검토` itself: the fixed text, nothing queued.
        app.sol.send.to_text = TO_A.to_owned();
        app.sol_review();
        assert_eq!(app.sol.send.info.as_deref(), Some(SOL_REVIEW_CHANGED_TEXT));
        assert!(app.sol.slot.is_none());
        assert_eq!(app.sol.send.check.as_ref().unwrap().to, addr(TO_A));
        // Not reviewable (input error) is not a change.
        app.sol.send.amount_text = "x".to_owned();
        app.sol_validate_send();
        assert_eq!(app.sol_review_item().unwrap_err(), ReviewRefusal::NotReady);
    }
}
