//! Bitcoin on the key worker (spec/08 §2, §3.2, §3.4, §4.7, §11.1–§12.4): the worker owns the
//! session's `BtcMeta` (meta `btc`) and is its only writer, so every change is persisted before
//! the UI shows its result (a receive address after `receive_next` is stored, `change_next`
//! with `Broadcasting`). It signs approved plans and commits the `Signed` record before anything
//! is sent, applies the pre-check / send / tracking results to the journal (yw-core decides),
//! moves finished records to meta `activity` and prunes them, always meta write before journal
//! write (spec/08 §12.4).

use yw_core::approval::Approved;
use yw_core::bip32::path::BtcChain;
use yw_core::btc::fee::{maxfeerate_literal, rate_kvb};
use yw_core::btc::meta::{ListedUtxo, MetaError, ReceiveAddress, RefreshReport, VerifiedUtxo};
use yw_core::btc::policy::{
    BroadcastOutcome, LocalTx, MempoolAccept, PrecheckOutcome, SendRawResult, broadcast_outcome,
    check_mempool_accept,
};
use yw_core::btc::{
    BtcAccountId, BtcAccountKey, BtcAccounts, BtcMeta, BtcNetwork, Discovery, OutPoint, PlanError,
    PostSignError, ScriptType, SendPlan, SignError, Txid, check_recorded_amounts, sign_plan,
    verify_signed,
};
use yw_core::error::{KeyError, StorageError, VaultError};
use yw_core::journal::JournalPlain;
use yw_core::journal::btc::{
    AccountScope, BtcActivityRow, BtcEntries, BtcPushError, BtcRecord, BtcRecordError, BtcTxState,
    TrackObservation, TransitionError, apply_observation, change_next_floor,
    check_abandoned_conflicts, check_plan_allowed, confirmed_inputs, current_record,
    disclosed_duplicate, finished_rows, make_room, normalize_on_startup, of_account,
    prune_finished, push_record, recorded_amounts, refresh_keep_outpoints, related_records,
    set_disclosed, set_last_send_comm_failure, set_state_entry, take_finished_duplicates,
};
use yw_core::vault::{FileKind, RecordId, Vault};

use super::{JournalState, fault_point, view_of};
use crate::btc::network_id;
use crate::btc::work::SignedTxRef;
use crate::events::KeyOutcome;
use crate::logging::{self, Field};
use crate::meta::{self, ActivityEntry, Meta};
use crate::network::NetworkId;

/// The outputs and history of a completed refresh (spec/08 §4.7-2..5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcRefreshUpdate {
    /// Every confirmed candidate listed in this refresh.
    pub listed: Vec<ListedUtxo>,
    /// The listed outputs that passed `verify_prev_output` now.
    pub newly: Vec<VerifiedUtxo>,
    /// `(chain, index, tx_count)` of every watched address.
    pub history: Vec<(BtcChain, u32, u64)>,
    /// `max_tip_seen` to persist (`BtcMeta::observe_tip`).
    pub max_tip_seen: u32,
    /// Wall clock of the refresh (Unix seconds): the 30-day window of live abandoned records
    /// whose inputs `apply_refresh` keeps.
    pub now_unix: u64,
    /// `(chain, index)` of paid addresses whose UTXO list was too large this round: their
    /// `verified` entries are kept as last seen (not listed is not "spent" here).
    pub skipped: Vec<(BtcChain, u32)>,
}

/// A `BtcMeta` change made and persisted by the key worker. Every op names the network it was
/// made for; a different meta `btc` network refuses it (`NetworkMismatch`; a key-only wallet has
/// no meta `btc` and each account carries its own network). Ops on one account name it
/// (`account`); wallet-level facts (`max_tip_seen`) live in the tip holder: BIP84 account 0, or
/// in a wallet without it the first account of the network (`BtcAccounts::tip_holder`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BtcMetaOp {
    /// A fresh BIP84 account 0 `BtcMeta` for `network` (BTC enable, network change, `null` meta
    /// with BTC enabled): `Vault::btc_account_xpub` of the network's coin (spec/08 §2, §3.1).
    Create {
        /// Network.
        network: BtcNetwork,
    },
    /// `계정 추가`: the next HD account of `script_type` on `network` (`m/{44|49|84|86}'/c'/a'`,
    /// spec/08 §3.1) of `mnemonic` (`None`: the primary one; an added mnemonic, spec/02 §8.6),
    /// stored and selected; discovery follows.
    AddAccount {
        /// Network.
        network: BtcNetwork,
        /// Address type.
        script_type: ScriptType,
        /// The mnemonic (`None`: the primary one).
        mnemonic: Option<yw_core::vault::RecordId>,
    },
    /// An imported single key's account (`개인키 가져오기` on the Bitcoin tab sends it after the
    /// vault stored the tag-4 record): stored and selected; no discovery.
    AddImported {
        /// Network of the key.
        network: BtcNetwork,
        /// `BtcAccountKey::single(record id, type, public key)`.
        key: BtcAccountKey,
    },
    /// `계정 추가` with the key of EVM account `evm_index` (`m/44'/60'/0'/0/i`, spec/08 §3.5
    /// "EVM 계정과 같은 키"): one fixed address of `script_type`, stored and selected; no
    /// discovery. Refused when the account exists or its address is already an account's.
    AddEvmShared {
        /// Network.
        network: BtcNetwork,
        /// Address type.
        script_type: ScriptType,
        /// EVM account index.
        evm_index: u32,
    },
    /// The address mode of an HD account (spec/08 §3.5): fixed address (`true`) or HD.
    SetAddressMode {
        /// Network.
        network: BtcNetwork,
        /// Account (HD only).
        account: BtcAccountId,
        /// Fixed-address mode.
        single_address: bool,
    },
    /// The selected account (meta `btc_accounts.selected`).
    Select {
        /// Network.
        network: BtcNetwork,
        /// Account.
        account: BtcAccountId,
    },
    /// A finished discovery (`Discovery::apply`, spec/08 §3.4).
    Discovered {
        /// Network.
        network: BtcNetwork,
        /// Account.
        account: BtcAccountId,
        /// The finished state machine.
        discovery: Box<Discovery>,
    },
    /// A completed refresh (`mark_history`, `apply_refresh`, `observe_tip`).
    Refreshed {
        /// Network.
        network: BtcNetwork,
        /// Account.
        account: BtcAccountId,
        /// Refresh results.
        update: Box<BtcRefreshUpdate>,
    },
    /// A Core tip seen (`observe_tip`, BIP84 account 0).
    Tip {
        /// Network.
        network: BtcNetwork,
        /// `max_tip_seen` from the chain check.
        max_tip_seen: u32,
    },
    /// The receive screen's address (`receive_address`): existing, or issued and persisted
    /// before it is shown (spec/08 §3.2).
    ReceiveAddress {
        /// Network.
        network: BtcNetwork,
        /// Account.
        account: BtcAccountId,
    },
    /// "새 주소" (`new_receive_address`).
    NewReceiveAddress {
        /// Network.
        network: BtcNetwork,
        /// Account.
        account: BtcAccountId,
        /// The 20-unused warning was confirmed ([그래도 발급]).
        gap_confirmed: bool,
    },
    /// User freeze / unfreeze of a verified output (spec/08 §7.6).
    Freeze {
        /// Network.
        network: BtcNetwork,
        /// Account.
        account: BtcAccountId,
        /// Output.
        outpoint: OutPoint,
        /// `true` = freeze.
        frozen: bool,
    },
    /// "블록 높이 기록 초기화" (`BtcMeta::reset_max_tip`, spec/08 §2 step 2; BIP84 account 0).
    ResetTip {
        /// Network.
        network: BtcNetwork,
    },
}

impl BtcMetaOp {
    /// Fixed name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::AddAccount { .. } => "add_account",
            Self::AddImported { .. } => "add_imported",
            Self::AddEvmShared { .. } => "add_evm_shared",
            Self::SetAddressMode { .. } => "address_mode",
            Self::Select { .. } => "select",
            Self::Discovered { .. } => "discovered",
            Self::Refreshed { .. } => "refreshed",
            Self::Tip { .. } => "tip",
            Self::ReceiveAddress { .. } => "receive_address",
            Self::NewReceiveAddress { .. } => "new_receive_address",
            Self::Freeze { .. } => "freeze",
            Self::ResetTip { .. } => "reset_tip",
        }
    }

    const fn network(&self) -> BtcNetwork {
        match self {
            Self::Create { network }
            | Self::AddAccount { network, .. }
            | Self::AddImported { network, .. }
            | Self::AddEvmShared { network, .. }
            | Self::SetAddressMode { network, .. }
            | Self::Select { network, .. }
            | Self::Discovered { network, .. }
            | Self::Refreshed { network, .. }
            | Self::Tip { network, .. }
            | Self::ReceiveAddress { network, .. }
            | Self::NewReceiveAddress { network, .. }
            | Self::Freeze { network, .. }
            | Self::ResetTip { network } => *network,
        }
    }

    /// The account an op changes (`None`: the tip holder / wallet level).
    const fn account(&self) -> Option<BtcAccountId> {
        match self {
            Self::Select { account, .. }
            | Self::SetAddressMode { account, .. }
            | Self::Discovered { account, .. }
            | Self::Refreshed { account, .. }
            | Self::ReceiveAddress { account, .. }
            | Self::NewReceiveAddress { account, .. }
            | Self::Freeze { account, .. } => Some(*account),
            Self::Create { .. }
            | Self::AddAccount { .. }
            | Self::AddImported { .. }
            | Self::AddEvmShared { .. }
            | Self::Tip { .. }
            | Self::ResetTip { .. } => None,
        }
    }
}

/// What a persisted `BtcMeta` change did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcMetaDone {
    /// A fresh `BtcMeta` (discovery follows).
    Created,
    /// Discovery applied (`discovery_done = true`).
    Discovered,
    /// Refresh applied.
    Refreshed(RefreshReport),
    /// Tip stored (or unchanged).
    Tip,
    /// The receive address index; `issued` = newly issued and persisted now.
    Receive {
        /// Receive index.
        index: u32,
        /// Newly issued.
        issued: bool,
    },
    /// Frozen.
    Frozen,
    /// Unfrozen.
    Unfrozen,
    /// `max_tip_seen` forgotten.
    TipReset,
    /// An HD account's address mode changed (or was already the requested one).
    AddressMode(BtcAccountId),
    /// `change_next` raised (startup reconciliation or `Broadcasting`).
    ChangeNext,
    /// Other bookkeeping of a journal step (sent script, own change, tip).
    Updated,
    /// A new account was stored and selected.
    AccountAdded(BtcAccountId),
    /// The selected account changed.
    Selected(BtcAccountId),
    /// An imported key's account was removed with its vault record (`삭제`).
    Removed(BtcAccountId),
}

/// The persisted BTC accounts (the UI replaces its mirror with them).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcMetaUpdate {
    /// The key worker's BIP84 account 0 `BtcMeta` after the change.
    pub meta: Option<Box<BtcMeta>>,
    /// The key worker's other accounts after the change.
    pub accounts: Box<BtcAccounts>,
    /// What changed.
    pub done: BtcMetaDone,
}

/// Why a BTC meta or journal job did nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcKeyError {
    /// No `BtcMeta` in this session (BTC not enabled yet).
    NoMeta,
    /// yw-core refused the change (`NetworkMismatch`, `GapWarning`, `GapHardLimit`, …).
    Meta(MetaError),
    /// The vault (reading the account node, writing meta or journal).
    Vault(VaultError),
    /// The journal transition was refused (`UnknownTx`, `NotAllowed`).
    Journal(TransitionError),
    /// The record's fee/vsize give no `maxfeerate` (never for decoded records).
    Internal,
    /// The account's imported key is no longer in the vault (removed): no address is handed out.
    KeyRemoved,
}

impl BtcKeyError {
    /// Fixed text.
    #[must_use]
    pub fn text(self) -> String {
        match self {
            Self::NoMeta => "Bitcoin이 켜져 있지 않습니다".to_owned(),
            Self::Meta(error) => error.to_string(),
            Self::Vault(error) => crate::errors::vault_code(error).text(),
            Self::Journal(error) => error.to_string(),
            Self::Internal => crate::errors::ErrorCode::Tx003.text(),
            Self::KeyRemoved => {
                "이 계정의 개인키는 지갑에서 삭제되었습니다. 이 계정의 주소로 받지 마세요."
                    .to_owned()
            }
        }
    }
}

/// A signed and journaled BTC transaction ready for the pre-check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcSignedSummary {
    /// Network.
    pub network: BtcNetwork,
    /// The journal's bytes with the `maxfeerate` literal.
    pub tx: SignedTxRef,
    /// Change index (bumped into `change_next` at `Broadcasting`).
    pub change_index: Option<u32>,
    /// The replaced transaction of a fee bump.
    pub replaces: Option<Txid>,
}

/// Why signing produced nothing to send (spec/08 §11.1–§11.2, §12.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcSignFailure {
    /// No `BtcMeta` in this session.
    NoMeta,
    /// settings / `BtcMeta` / plan network differ.
    NetworkMismatch,
    /// A BTC journal entry is damaged (E-VLT-006: BTC sending stops).
    JournalDamaged,
    /// No room even after moving finished records ("거래 저널 공간이 부족합니다").
    JournalFull,
    /// The same transaction (txid) is already in the journal and still tracked.
    DuplicateTx,
    /// The in-flight re-check refused (`InFlight`, `NotBumpable`, `InputInFlight`).
    Plan(PlanError),
    /// `check_recorded_amounts` or `sign_plan` refused (nothing signed).
    Sign(SignError),
    /// Post-sign verification failed (bytes discarded).
    PostSign(PostSignError),
    /// The record failed its own checks (bytes discarded).
    Record(BtcRecordError),
    /// The `Signed` record could not be committed (nothing sent).
    JournalWrite(VaultError),
    /// The `YubiKey` did not sign (spec/10 §6.3; nothing stored or sent).
    Card(crate::yubikey::CardJobError),
}

/// The signing step of a BTC plan: `(vault, approval, plan, account)` → the signed transaction
/// (the vault's `sign_plan` or the card path).
pub type BtcSigner<'a> = dyn FnMut(
        &Vault,
        Approved,
        &SendPlan,
        &BtcAccountKey,
    ) -> Result<yw_core::btc::SignedTx, BtcSignFailure>
    + 'a;

impl BtcSignFailure {
    /// The vault refused the key because its recovery phrase has not passed the backup quiz
    /// (E-VLT-009).
    #[must_use]
    pub const fn backup_unconfirmed(&self) -> bool {
        matches!(
            self,
            Self::Sign(SignError::Vault(VaultError::BackupNotConfirmed))
        )
    }

    /// Fixed text.
    #[must_use]
    pub fn text(self) -> String {
        use yw_core::btc::policy::texts;
        match self {
            Self::NoMeta => "Bitcoin이 켜져 있지 않습니다".to_owned(),
            Self::NetworkMismatch => texts::NETWORK_MISMATCH.to_owned(),
            Self::JournalDamaged => {
                "거래 저널이 손상되어 보내기를 멈췄습니다. (E-VLT-006)".to_owned()
            }
            Self::JournalFull => crate::errors::ErrorCode::Tx005.text(),
            Self::DuplicateTx => BtcPushError::Duplicate.to_string(),
            Self::Plan(error) => error.to_string(),
            Self::Sign(error) => error.to_string(),
            Self::PostSign(_) | Self::Record(_) => texts::POST_SIGN.to_owned(),
            Self::JournalWrite(_) => {
                format!(
                    "저널 저장 실패 — {}",
                    crate::errors::ErrorCode::Vlt003.text()
                )
            }
            Self::Card(error) => error.to_string(),
        }
    }
}

/// A BTC journal step (spec/08 §11.3, §12.1–§12.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BtcJournalOp {
    /// Before the first `testmempoolaccept` of a `Signed` record: flags bit7 ("disclosed",
    /// yw-core `set_disclosed`) is committed, then the bytes are returned for the pre-check. A
    /// hostile RPC may relay what it receives, so from now on a `Rejected` answer or [취소]
    /// still constrains the next send (spec/08 §11.3, §12.1).
    Disclose {
        /// Network.
        network: BtcNetwork,
        /// Record.
        txid: Txid,
    },
    /// The `testmempoolaccept` element of a `Signed` record: yw-core's `check_mempool_accept`
    /// against the record's own txid, wtxid, vsize and fee → `Broadcasting` (with
    /// `on_broadcasting`), `BroadcastUnknown` through `Broadcasting` when the node already has
    /// it, or `Rejected`.
    Precheck {
        /// Network.
        network: BtcNetwork,
        /// Record.
        txid: Txid,
        /// Parsed element.
        accept: MempoolAccept,
    },
    /// The `sendrawtransaction` result (yw-core's `broadcast_outcome`); `Submitted` records the
    /// recipient script. Re-broadcasts from `BroadcastUnknown` keep the state (§12.1 table).
    Sent {
        /// Network.
        network: BtcNetwork,
        /// Record.
        txid: Txid,
        /// Parsed result (`Refused` when nothing was sent).
        result: SendRawResult,
    },
    /// The manual Esplora broadcast returned our txid: records the recipient script (the state
    /// stays `BroadcastUnknown`; tracking moves it on).
    EsploraSent {
        /// Network.
        network: BtcNetwork,
        /// Record.
        txid: Txid,
    },
    /// One tracking round (`apply_observation` per record, own change on `Confirmed`, finished
    /// records to activity, prune).
    Tracked {
        /// Network.
        network: BtcNetwork,
        /// Core tip of the round.
        tip_height: u32,
        /// `max_tip_seen` to persist.
        max_tip_seen: Option<u32>,
        /// yw-core decisions per txid.
        observations: Vec<(Txid, TrackObservation)>,
    },
    /// [취소] of a `Signed` record or [포기] of a `BroadcastUnknown` one (yw-core refuses the
    /// latter before `not_found_count` reaches 10: `BtcRecord::can_abandon`).
    Abandon {
        /// Network.
        network: BtcNetwork,
        /// Record.
        txid: Txid,
    },
}

impl BtcJournalOp {
    /// Fixed name for logs.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Disclose { .. } => "disclose",
            Self::Precheck { .. } => "precheck",
            Self::Sent { .. } => "sent",
            Self::EsploraSent { .. } => "esplora_sent",
            Self::Tracked { .. } => "tracked",
            Self::Abandon { .. } => "abandon",
        }
    }
}

/// What a BTC journal step did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BtcJournalDone {
    /// The record is marked disclosed in the journal: run `testmempoolaccept` with these bytes.
    Disclosed {
        /// Network.
        network: BtcNetwork,
        /// The journal's bytes.
        tx: SignedTxRef,
    },
    /// `Broadcasting` committed (with `change_next`): send these bytes now.
    Broadcasting {
        /// Network.
        network: BtcNetwork,
        /// The journal's bytes.
        tx: SignedTxRef,
    },
    /// The pre-check said the node already has the transaction (`txn-already-in-mempool` /
    /// `txn-already-known`): `Broadcasting` (with `change_next`) then `BroadcastUnknown` were
    /// committed without a send; tracking moves it on (spec/08 §11.3).
    PrecheckKnown {
        /// Record.
        txid: Txid,
        /// Fixed text.
        text: &'static str,
    },
    /// `Rejected` by the pre-check, with the fixed text (the change index stays reusable).
    PrecheckRejected {
        /// Record.
        txid: Txid,
        /// Fixed text.
        text: &'static str,
    },
    /// The send result applied.
    Sent {
        /// Record.
        txid: Txid,
        /// yw-core's outcome.
        outcome: BroadcastOutcome,
    },
    /// The Esplora broadcast noted.
    EsploraNoted {
        /// Record.
        txid: Txid,
    },
    /// A tracking round applied.
    Tracked {
        /// Records whose state changed.
        changed: Vec<(Txid, BtcTxState)>,
    },
    /// `Abandoned`.
    Abandoned {
        /// Record.
        txid: Txid,
    },
}

/// The bytes of a record for the pre-check, send or Esplora post, with its `maxfeerate`
/// literal (the record's actual fee and vsize, spec/08 §8.3).
#[must_use]
pub fn signed_ref(record: &BtcRecord) -> Option<SignedTxRef> {
    Some(SignedTxRef {
        txid: record.txid,
        raw: record.raw.clone(),
        maxfeerate: maxfeerate_literal(rate_kvb(record.fee, u64::from(record.vsize))?)?,
    })
}

/// A BTC activity row as a meta `ActivityEntry` of `bitcoin:<net>` (spec/08 §12.3).
#[must_use]
pub fn btc_activity(row: &BtcActivityRow) -> (NetworkId, ActivityEntry) {
    (
        network_id(row.network),
        ActivityEntry {
            account: row.account.clone(),
            tx_id: row.tx_id.clone(),
            title: row.title.clone(),
            asset: row.asset.clone(),
            amount: row.amount.clone(),
            counterparty: row.counterparty.clone(),
            status: row.status.to_owned(),
            time_unix_ms: row.time_unix_ms,
        },
    )
}

/// The current record of `txid` (the last one in journal order, yw-core `current_record`):
/// a journal step resolves it once and then addresses it by `entry_id`.
fn find_record(plain: &JournalPlain, network: BtcNetwork, txid: &Txid) -> Option<BtcRecord> {
    let records = BtcEntries::from_plain(plain).records();
    current_record(&records, network, txid).cloned()
}

fn commit_journal(vault: &mut Vault, plain: &JournalPlain) -> Result<(), VaultError> {
    let bytes = plain
        .encode()
        .map_err(|_| VaultError::Storage(StorageError::TooLarge))?;
    vault.save_sidecar(FileKind::Journal, &bytes).map(|_| ())
}

impl JournalState {
    /// Sets the session's BTC accounts from the loaded meta document (`LoadMeta`): meta `btc`
    /// (BIP84 account 0) and meta `btc_accounts` (the others).
    pub fn set_btc_meta(&mut self, meta: Option<BtcMeta>, accounts: BtcAccounts) {
        self.btc = meta;
        self.btc_accounts = accounts;
        self.btc_loaded = true;
    }

    /// The session's BIP84 account 0 `BtcMeta`.
    #[must_use]
    pub const fn btc_meta(&self) -> Option<&BtcMeta> {
        self.btc.as_ref()
    }

    /// The session's other BTC accounts.
    #[must_use]
    pub const fn btc_accounts(&self) -> &BtcAccounts {
        &self.btc_accounts
    }

    /// Account `id` of `network` (BIP84 account 0 is meta `btc`).
    fn account_meta(&self, network: BtcNetwork, id: BtcAccountId) -> Option<BtcMeta> {
        if id == BtcAccountId::PRIMARY {
            self.btc.clone().filter(|meta| meta.network() == network)
        } else {
            self.btc_accounts.get(network, id).cloned()
        }
    }

    /// BIP84 account 0 exists on `network` (a mnemonic wallet with Bitcoin on).
    fn has_primary(&self, network: BtcNetwork) -> bool {
        self.btc
            .as_ref()
            .is_some_and(|meta| meta.network() == network)
    }

    /// The network check of an op or a signing (spec/08 §2): meta `btc`'s copy when the wallet
    /// has one; a key-only wallet has none and each of its accounts carries its own network
    /// (`account_meta` only finds accounts of the asked network).
    fn check_network(&self, network: BtcNetwork) -> Result<(), MetaError> {
        self.btc
            .as_ref()
            .map_or(Ok(()), |primary| primary.check_network(network))
    }

    /// The account holding the wallet-level `max_tip_seen` of `network`.
    fn tip_holder(&self, network: BtcNetwork) -> Option<BtcAccountId> {
        self.btc_accounts
            .tip_holder(network, self.has_primary(network))
    }

    /// The session's account keys on `network` (a record's own key gives the scripts of its
    /// key-path P2TR inputs, `related_records`).
    fn keys_on(&self, network: BtcNetwork) -> Vec<BtcAccountKey> {
        self.btc
            .iter()
            .filter(|meta| meta.network() == network)
            .chain(self.btc_accounts.of_network(network))
            .map(|meta| *meta.account())
            .collect()
    }

    /// The records of `meta`'s network touching its account under any identity (spec/08 §12.1
    /// "같은 주소의 다른 계정": an imported key removed and imported again, an alias address).
    fn related(&self, all: &[BtcRecord], meta: &BtcMeta) -> Result<Vec<BtcRecord>, KeyError> {
        let scope = AccountScope::of(meta)?;
        Ok(related_records(all, &scope, &self.keys_on(meta.network())))
    }

    /// Whether `script` is already an address of an account on `network` (spec/08 §3.5): an HD
    /// account's address in its scanned range (`[0, next + gap)` of both chains,
    /// `BtcMeta::own_recipient`) or another imported key's address. A key with such an address is
    /// not imported: one address would get two account identities, and the per-account journal
    /// rules (D20, the abandon rule) could be split between them. An account whose scripts cannot
    /// be derived counts as taken. Before `LoadMeta` the stored meta document is read.
    pub fn btc_address_taken(&self, vault: &Vault, network: BtcNetwork, script: &[u8]) -> bool {
        let (primary, accounts) = if self.btc_loaded {
            (self.btc.clone(), self.btc_accounts.clone())
        } else {
            match vault.open_sidecar(FileKind::Meta) {
                Ok(None) => (None, BtcAccounts::default()),
                Ok(Some((_, plaintext))) => match meta::parse(plaintext.expose()) {
                    Ok(parsed) => (parsed.meta.btc.map(|btc| *btc), parsed.meta.btc_accounts),
                    // An unreadable meta document: nothing to compare with is not proof of
                    // a free address.
                    Err(_) => return true,
                },
                Err(_) => return true,
            }
        };
        primary
            .iter()
            .filter(|meta| meta.network() == network)
            .chain(accounts.of_network(network))
            .any(|meta| meta.own_recipient(script).map_or(true, |hit| hit.is_some()))
    }

    /// Whether a BTC record of imported key `id`'s address may still confirm on any network
    /// (in flight, `Replaced`, or given up / refused inside the 30-day window:
    /// `BtcRecord::may_still_confirm`). Its key may not be removed then: tracking, fee bumps
    /// and the abandon rule still need the account (spec/04 §2.18).
    pub fn btc_imported_busy(&mut self, vault: &Vault, id: [u8; 16], now_unix: u64) -> bool {
        let account = BtcAccountId::Imported { id };
        let metas: Vec<BtcMeta> = self
            .btc_accounts
            .accounts
            .iter()
            .filter(|meta| meta.id() == account)
            .cloned()
            .collect();
        let Ok(plain) = self.current(vault) else {
            // An unreadable journal: the records of a Bitcoin key cannot be checked, so it stays
            // (an EVM or Solana key has no Bitcoin account).
            return !metas.is_empty();
        };
        let records = BtcEntries::from_plain(&plain).records();
        if records
            .iter()
            .any(|record| record.account == account && record.may_still_confirm(now_unix))
        {
            return true;
        }
        metas.iter().any(|meta| {
            self.related(&records, meta).map_or(true, |related| {
                related
                    .iter()
                    .any(|record| record.may_still_confirm(now_unix))
            })
        })
    }

    /// Whether a BTC record of an account of the added mnemonic `id` (any network) may still
    /// confirm (`BtcRecord::may_still_confirm`, also through another identity of the same
    /// address): the mnemonic is not removed then (spec/02 §8.6, like an imported key).
    pub fn btc_mnemonic_busy(
        &mut self,
        vault: &Vault,
        id: yw_core::vault::RecordId,
        now_unix: u64,
    ) -> bool {
        let metas: Vec<BtcMeta> = self
            .btc_accounts
            .accounts
            .iter()
            .filter(|meta| meta.account().mnemonic() == Some(id))
            .cloned()
            .collect();
        let Ok(plain) = self.current(vault) else {
            // An unreadable journal: the records cannot be checked.
            return !metas.is_empty();
        };
        let records = BtcEntries::from_plain(&plain).records();
        if records.iter().any(|record| {
            matches!(record.account, BtcAccountId::Hd { mnemonic: Some(of), .. } if of == id)
                && record.may_still_confirm(now_unix)
        }) {
            return true;
        }
        metas.iter().any(|meta| {
            self.related(&records, meta).map_or(true, |related| {
                related
                    .iter()
                    .any(|record| record.may_still_confirm(now_unix))
            })
        })
    }

    /// Drops imported key `id`'s account (every network) after its vault record was removed and
    /// persists meta. The selection falls back; in a wallet without BIP84 account 0 the next
    /// account keeps the wallet-level tip.
    pub fn btc_remove_imported(
        &mut self,
        vault: &mut Vault,
        id: [u8; 16],
        alt: bool,
    ) -> Vec<KeyOutcome> {
        if !self.btc_loaded {
            // Meta is not read yet: the next `LoadMeta` drops the account (no vault record).
            return Vec::new();
        }
        let account = BtcAccountId::Imported { id };
        let mut accounts = self.btc_accounts.clone();
        let mut removed_on = None;
        for network in BtcNetwork::ALL {
            let has_primary = self.has_primary(network);
            if accounts.remove(network, account, has_primary).is_some() {
                removed_on = Some(network);
            }
        }
        let Some(network) = removed_on else {
            return Vec::new();
        };
        let primary = self.btc.clone();
        let result = self.persist_state(vault, primary.clone(), accounts.clone(), &[], alt);
        Self::log_meta("remove_imported", network, result.is_ok());
        match result {
            Ok(_) => vec![self.meta_update(BtcMetaDone::Removed(account))],
            Err(error) => {
                // The vault is the source of truth: its record is gone, so the session drops the
                // account even though meta could not be written (the next write or `LoadMeta`
                // drops it from the file). The write error is still reported.
                self.btc = primary;
                self.btc_accounts = accounts;
                vec![
                    self.meta_update(BtcMetaDone::Removed(account)),
                    KeyOutcome::BtcMeta(Err(BtcKeyError::Vault(error))),
                ]
            }
        }
    }

    /// `accounts` without imported-key accounts whose vault record is gone (an unreadable
    /// vault leaves them; no meta write can happen then anyway).
    fn without_removed_keys(&self, vault: &Vault, mut accounts: BtcAccounts) -> BtcAccounts {
        let removed: Vec<BtcAccountId> = accounts
            .accounts
            .iter()
            .map(BtcMeta::id)
            .filter(|account| match account {
                BtcAccountId::Imported { id } => {
                    matches!(vault.has_btc_key(RecordId::from_bytes(*id)), Ok(false))
                }
                BtcAccountId::Hd { .. }
                | BtcAccountId::EvmShared { .. }
                | BtcAccountId::Hardware { .. } => false,
            })
            .collect();
        for account in removed {
            for network in BtcNetwork::ALL {
                let _ = accounts.remove(network, account, self.has_primary(network));
            }
        }
        accounts
    }

    /// Refuses an op on an imported-key account whose vault record is gone.
    fn require_key(vault: &Vault, account: BtcAccountId) -> Result<(), BtcKeyError> {
        match account {
            BtcAccountId::Imported { id } => match vault.has_btc_key(RecordId::from_bytes(id)) {
                Ok(true) => Ok(()),
                Ok(false) => Err(BtcKeyError::KeyRemoved),
                Err(error) => Err(BtcKeyError::Vault(error)),
            },
            BtcAccountId::Hd { .. }
            | BtcAccountId::EvmShared { .. }
            | BtcAccountId::Hardware { .. } => Ok(()),
        }
    }

    /// Puts the worker's BTC accounts into a meta document about to be written (the UI's copy
    /// is only a mirror). Imported-key accounts without a vault record are left out.
    pub fn apply_btc_meta(&self, vault: &Vault, document: &mut Meta) {
        if self.btc_loaded {
            document.btc = self.btc.clone().map(Box::new);
            document.btc_accounts = self.without_removed_keys(vault, self.btc_accounts.clone());
        }
    }

    fn update_of(&self, done: BtcMetaDone) -> BtcMetaUpdate {
        BtcMetaUpdate {
            meta: self.btc.clone().map(Box::new),
            accounts: Box::new(self.btc_accounts.clone()),
            done,
        }
    }

    fn meta_update(&self, done: BtcMetaDone) -> KeyOutcome {
        KeyOutcome::BtcMeta(Ok(self.update_of(done)))
    }

    /// Writes `primary` as meta `btc` and `accounts` as meta `btc_accounts` together with the
    /// activity rows not stored yet (same `tx_id` and status), then adopts them. In
    /// alt-passphrase sessions nothing is written (meta is never stored) and the copy lives in
    /// memory only.
    fn persist_state(
        &mut self,
        vault: &mut Vault,
        primary: Option<BtcMeta>,
        accounts: BtcAccounts,
        rows: &[BtcActivityRow],
        alt: bool,
    ) -> Result<Vec<(NetworkId, ActivityEntry)>, VaultError> {
        let mut moved = Vec::new();
        if !alt {
            let mut document = match vault.open_sidecar(FileKind::Meta)? {
                None => Meta::default(),
                Some((_, plaintext)) => {
                    meta::parse(plaintext.expose())
                        .map_err(|_| VaultError::SidecarCorrupt(FileKind::Meta))?
                        .meta
                }
            };
            document.btc = primary.clone().map(Box::new);
            document.btc_accounts = accounts.clone();
            for row in rows {
                let (network, entry) = btc_activity(row);
                let key = network.to_string();
                if document
                    .activity_of(&key)
                    .iter()
                    .any(|known| known.tx_id == entry.tx_id && known.status == entry.status)
                {
                    continue;
                }
                document.upsert_activity(&key, &entry);
                moved.push((network, entry));
            }
            vault.save_sidecar(FileKind::Meta, &document.to_json())?;
        }
        self.btc = primary;
        self.btc_accounts = accounts;
        self.btc_loaded = true;
        self.overlay.extend(moved.iter().cloned());
        Ok(moved)
    }

    /// [`Self::persist_state`] with `candidate` as meta `btc` and the current other accounts.
    fn persist_btc(
        &mut self,
        vault: &mut Vault,
        candidate: Option<BtcMeta>,
        rows: &[BtcActivityRow],
        alt: bool,
    ) -> Result<Vec<(NetworkId, ActivityEntry)>, VaultError> {
        let accounts = self.btc_accounts.clone();
        self.persist_state(vault, candidate, accounts, rows, alt)
    }

    /// [`Self::persist_state`] with `meta` stored in its slot (meta `btc` for BIP84 account 0,
    /// `btc_accounts` otherwise).
    fn persist_account(
        &mut self,
        vault: &mut Vault,
        meta: BtcMeta,
        rows: &[BtcActivityRow],
        alt: bool,
    ) -> Result<Vec<(NetworkId, ActivityEntry)>, BtcKeyError> {
        if meta.id() == BtcAccountId::PRIMARY {
            return self
                .persist_btc(vault, Some(meta), rows, alt)
                .map_err(BtcKeyError::Vault);
        }
        let mut accounts = self.btc_accounts.clone();
        accounts.upsert(meta).map_err(BtcKeyError::Meta)?;
        let primary = self.btc.clone();
        self.persist_state(vault, primary, accounts, rows, alt)
            .map_err(BtcKeyError::Vault)
    }

    fn log_meta(op: &'static str, network: BtcNetwork, ok: bool) {
        logging::info(
            "journal",
            "btc.meta",
            &[
                ("net", Field::Net(network_id(network))),
                ("op", Field::Word(op)),
                ("result", Field::Word(if ok { "ok" } else { "refused" })),
            ],
        );
    }

    /// Applies and persists a `BtcMeta` change (spec/08 §2, §3.2, §3.4, §4.7, §7.6). The
    /// outcome is reported only after the write (a receive address is shown after
    /// `receive_next` is stored).
    pub fn btc_meta_op(&mut self, vault: &mut Vault, op: BtcMetaOp, alt: bool) -> Vec<KeyOutcome> {
        let name = op.name();
        let network = op.network();
        let result = self.btc_meta_op_inner(vault, op, alt);
        Self::log_meta(name, network, result.is_ok());
        vec![KeyOutcome::BtcMeta(result.map(|done| self.update_of(done)))]
    }

    /// The account ops: create (BIP84 account 0), add (HD or imported) and select.
    fn btc_account_op(
        &mut self,
        vault: &mut Vault,
        op: &BtcMetaOp,
        alt: bool,
    ) -> Result<BtcMetaDone, BtcKeyError> {
        match *op {
            BtcMetaOp::Create { network } => {
                let account = vault
                    .btc_account_xpub(network.coin_type())
                    .map_err(BtcKeyError::Vault)?;
                let fresh = BtcMeta::new(network, account);
                self.persist_btc(vault, Some(fresh), &[], alt)
                    .map_err(BtcKeyError::Vault)?;
                Ok(BtcMetaDone::Created)
            }
            BtcMetaOp::AddAccount {
                network,
                script_type,
                mnemonic,
            } => {
                self.btc
                    .as_ref()
                    .ok_or(BtcKeyError::NoMeta)?
                    .check_network(network)
                    .map_err(BtcKeyError::Meta)?;
                let number = self
                    .btc_accounts
                    .next_hd_account_of(network, mnemonic, script_type)
                    .ok_or(BtcKeyError::Meta(MetaError::Full))?;
                let coin = network
                    .account_node(script_type.purpose(), number)
                    .map_err(|error| BtcKeyError::Meta(MetaError::Key(error)))?;
                let xpub = vault
                    .btc_account_xpub_of(mnemonic, coin)
                    .map_err(BtcKeyError::Vault)?;
                let key = BtcAccountKey::hd(script_type, number, xpub)
                    .map_err(|_| BtcKeyError::Internal)?
                    .with_mnemonic(mnemonic);
                self.add_and_select(vault, BtcMeta::with_key(network, key), alt)
            }
            BtcMetaOp::AddImported { network, key } => {
                if !key.is_imported() {
                    return Err(BtcKeyError::Internal);
                }
                self.add_and_select(vault, BtcMeta::with_key(network, key), alt)
            }
            BtcMetaOp::AddEvmShared {
                network,
                script_type,
                evm_index,
            } => {
                self.btc
                    .as_ref()
                    .ok_or(BtcKeyError::NoMeta)?
                    .check_network(network)
                    .map_err(BtcKeyError::Meta)?;
                let index = yw_core::bip32::path::AccountIndex::new(evm_index)
                    .map_err(|error| BtcKeyError::Meta(MetaError::Key(error)))?;
                let pubkey = vault.evm_public_key(index).map_err(BtcKeyError::Vault)?;
                let key = BtcAccountKey::evm_shared(evm_index, script_type, pubkey)
                    .map_err(|_| BtcKeyError::Internal)?;
                if self.account_meta(network, key.id()).is_some() {
                    // The same EVM account and address type twice.
                    return Err(BtcKeyError::Vault(VaultError::DuplicateKey));
                }
                let script = key
                    .script(BtcChain::Receive, 0)
                    .map_err(|error| BtcKeyError::Meta(MetaError::Key(error)))?;
                if self.btc_address_taken(vault, network, &script) {
                    // One address, one account identity (spec/08 §3.5 주소 중복 거부).
                    return Err(BtcKeyError::Vault(VaultError::DuplicateKey));
                }
                self.add_and_select(vault, BtcMeta::with_key(network, key), alt)
            }
            BtcMetaOp::Select { network, account } => {
                if self.account_meta(network, account).is_none() {
                    return Err(BtcKeyError::NoMeta);
                }
                let mut accounts = self.btc_accounts.clone();
                accounts.selected = (account != BtcAccountId::PRIMARY).then_some(account);
                if accounts != self.btc_accounts {
                    let primary = self.btc.clone();
                    self.persist_state(vault, primary, accounts, &[], alt)
                        .map_err(BtcKeyError::Vault)?;
                }
                Ok(BtcMetaDone::Selected(account))
            }
            _ => Err(BtcKeyError::Internal),
        }
    }

    /// Stores a new account (refused when one with its identity exists on `network`) and
    /// selects it.
    fn add_and_select(
        &mut self,
        vault: &mut Vault,
        meta: BtcMeta,
        alt: bool,
    ) -> Result<BtcMetaDone, BtcKeyError> {
        let id = meta.id();
        if self.account_meta(meta.network(), id).is_some() {
            return Err(BtcKeyError::Meta(MetaError::NotVerified));
        }
        let mut accounts = self.btc_accounts.clone();
        accounts.upsert(meta).map_err(BtcKeyError::Meta)?;
        accounts.selected = Some(id);
        let primary = self.btc.clone();
        self.persist_state(vault, primary, accounts, &[], alt)
            .map_err(BtcKeyError::Vault)?;
        Ok(BtcMetaDone::AccountAdded(id))
    }

    /// The history and outputs of a completed refresh applied to `meta` (spec/08 §4.7).
    fn apply_refreshed(&self, meta: &mut BtcMeta, update: &BtcRefreshUpdate) -> RefreshReport {
        for (chain, index, tx_count) in &update.history {
            // An index the indexer answered for but meta never issued is ignored.
            let _ = meta.mark_history(*chain, *index, *tx_count);
        }
        let network = meta.network();
        let all = self
            .plain
            .as_ref()
            .map(|plain| BtcEntries::from_plain(plain).records())
            .unwrap_or_default();
        let records = of_account(&all, network, meta.id());
        // Kept outpoints across identities: a re-imported key keeps the inputs of the old
        // identity's live abandoned record (spec/08 §12.1).
        let related = self.related(&all, meta).unwrap_or_else(|_| records.clone());
        let mut keep = refresh_keep_outpoints(&related, network, update.now_unix);
        // A skipped (crowded) address was not listed at all: keep what it had, except what a
        // confirmed send of ours spent (else it would stay forever: the address is never listed).
        let spent = confirmed_inputs(&related, network);
        keep.extend(
            meta.verified()
                .iter()
                .filter(|entry| {
                    update.skipped.contains(&(entry.chain, entry.index))
                        && !spent.contains(&entry.outpoint)
                })
                .map(|entry| entry.outpoint),
        );
        meta.apply_refresh(
            &update.listed,
            &update.newly,
            &keep,
            &yw_core::journal::btc::own_outputs(&records, network),
        )
    }

    fn btc_meta_op_inner(
        &mut self,
        vault: &mut Vault,
        op: BtcMetaOp,
        alt: bool,
    ) -> Result<BtcMetaDone, BtcKeyError> {
        if matches!(
            op,
            BtcMetaOp::Create { .. }
                | BtcMetaOp::AddAccount { .. }
                | BtcMetaOp::AddImported { .. }
                | BtcMetaOp::AddEvmShared { .. }
                | BtcMetaOp::Select { .. }
        ) {
            return self.btc_account_op(vault, &op, alt);
        }
        let network = op.network();
        self.check_network(network).map_err(BtcKeyError::Meta)?;
        // Wallet-level facts (`max_tip_seen`) live in the tip holder: BIP84 account 0, or the
        // first account of the network in a wallet without it (key-only).
        let holder_id = self.tip_holder(network).ok_or(BtcKeyError::NoMeta)?;
        let mut holder = self
            .account_meta(network, holder_id)
            .ok_or(BtcKeyError::NoMeta)?;
        let target = op.account().unwrap_or(holder_id);
        let mut meta = self
            .account_meta(network, target)
            .ok_or(BtcKeyError::NoMeta)?;
        let done = match op {
            BtcMetaOp::Create { .. }
            | BtcMetaOp::AddAccount { .. }
            | BtcMetaOp::AddImported { .. }
            | BtcMetaOp::AddEvmShared { .. }
            | BtcMetaOp::Select { .. } => return Err(BtcKeyError::Internal),
            BtcMetaOp::SetAddressMode { single_address, .. } => {
                meta.set_single_address(single_address)
                    .map_err(BtcKeyError::Meta)?;
                BtcMetaDone::AddressMode(target)
            }
            BtcMetaOp::Discovered { discovery, .. } => {
                discovery.apply(&mut meta).map_err(BtcKeyError::Meta)?;
                BtcMetaDone::Discovered
            }
            BtcMetaOp::Refreshed { update, .. } => {
                let report = self.apply_refreshed(&mut meta, &update);
                // A regression was already refused by the chain check; keep the stored value.
                if target == holder_id {
                    let _ = meta.observe_tip(update.max_tip_seen);
                } else {
                    let _ = holder.observe_tip(update.max_tip_seen);
                }
                BtcMetaDone::Refreshed(report)
            }
            BtcMetaOp::Tip { max_tip_seen, .. } => {
                meta.observe_tip(max_tip_seen).map_err(BtcKeyError::Meta)?;
                BtcMetaDone::Tip
            }
            BtcMetaOp::ReceiveAddress { .. } => match Self::require_key(vault, target)
                .and_then(|()| meta.receive_address().map_err(BtcKeyError::Meta))
            {
                Ok(ReceiveAddress::Existing(index)) => {
                    return Ok(BtcMetaDone::Receive {
                        index,
                        issued: false,
                    });
                }
                Ok(ReceiveAddress::Issued(index)) => BtcMetaDone::Receive {
                    index,
                    issued: true,
                },
                Err(error) => return Err(error),
            },
            BtcMetaOp::NewReceiveAddress { gap_confirmed, .. } => {
                Self::require_key(vault, target)?;
                let index = meta
                    .new_receive_address(gap_confirmed)
                    .map_err(BtcKeyError::Meta)?;
                BtcMetaDone::Receive {
                    index,
                    issued: true,
                }
            }
            BtcMetaOp::Freeze {
                outpoint, frozen, ..
            } => {
                if frozen {
                    meta.freeze(outpoint).map_err(BtcKeyError::Meta)?;
                    BtcMetaDone::Frozen
                } else {
                    meta.unfreeze(outpoint);
                    BtcMetaDone::Unfrozen
                }
            }
            BtcMetaOp::ResetTip { .. } => {
                meta.reset_max_tip();
                BtcMetaDone::TipReset
            }
        };
        self.store_changed(vault, holder, meta, alt)?;
        Ok(done)
    }

    /// Persists `meta` (an account changed by an op) and `holder` (the tip holder, possibly with
    /// a new `max_tip_seen`; the same account as `meta` when the op was on it, then `meta` wins)
    /// when either changed.
    fn store_changed(
        &mut self,
        vault: &mut Vault,
        holder: BtcMeta,
        meta: BtcMeta,
        alt: bool,
    ) -> Result<(), BtcKeyError> {
        let mut primary = self.btc.clone();
        let mut accounts = self.btc_accounts.clone();
        for changed in [holder, meta] {
            if changed.id() == BtcAccountId::PRIMARY {
                primary = Some(changed);
            } else {
                accounts.upsert(changed).map_err(BtcKeyError::Meta)?;
            }
        }
        if primary != self.btc || accounts != self.btc_accounts {
            self.persist_state(vault, primary, accounts, &[], alt)
                .map_err(BtcKeyError::Vault)?;
        }
        Ok(())
    }

    /// Startup work after the journal is read (spec/08 §3.2, §12.1): `Broadcasting` records
    /// become `BroadcastUnknown`, and `change_next = max(meta, journal floor)`. `Signed` records
    /// stay for the UI's [전송 계속] / [취소].
    pub fn btc_startup(&mut self, vault: &mut Vault, now_unix: u64, alt: bool) -> Vec<KeyOutcome> {
        let mut out = Vec::new();
        let Some(mut next) = self.plain.clone() else {
            return out;
        };
        {
            // Every account's `change_next` against its own records.
            let records = BtcEntries::from_plain(&next).records();
            let reconcile = |meta: &mut BtcMeta| {
                let mine = of_account(&records, meta.network(), meta.id());
                meta.reconcile_change_next(change_next_floor(&mine, meta.network(), meta.account()))
            };
            let mut primary = self.btc.clone();
            let mut accounts = self.btc_accounts.clone();
            let mut changed = primary.as_mut().is_some_and(&reconcile);
            for meta in &mut accounts.accounts {
                changed |= reconcile(meta);
            }
            if changed {
                match self.persist_state(vault, primary, accounts, &[], alt) {
                    Ok(_) => out.push(self.meta_update(BtcMetaDone::ChangeNext)),
                    Err(error) => out.push(KeyOutcome::BtcMeta(Err(BtcKeyError::Vault(error)))),
                }
            }
        }
        match normalize_on_startup(&mut next, now_unix) {
            Ok(change) if !change.is_empty() => match commit_journal(vault, &next) {
                Ok(()) => {
                    logging::info(
                        "journal",
                        "btc.normalized",
                        &[(
                            "count",
                            Field::Num(u64::try_from(change.changed.len()).unwrap_or(0)),
                        )],
                    );
                    out.push(KeyOutcome::Journal(Ok(view_of(&next))));
                    self.plain = Some(next);
                }
                Err(error) => out.push(KeyOutcome::Journal(Err(error))),
            },
            Ok(_) => {}
            Err(_) => logging::warn("journal", "btc.normalize_failed", &[]),
        }
        out
    }

    /// Signs an approved BTC plan (spec/08 §11.1, coreB step 7): room (finished records to
    /// activity first), the in-flight re-check, the recorded-amount check, `sign_plan`,
    /// `verify_signed`, the `Signed` record committed — only then is the transaction returned.
    pub fn sign_btc(
        &mut self,
        vault: &mut Vault,
        approved: Box<Approved>,
        plan: &SendPlan,
        tip_height: u32,
        now_unix_ms: u64,
        alt: bool,
    ) -> Vec<KeyOutcome> {
        self.sign_btc_with(
            vault,
            approved,
            plan,
            (tip_height, now_unix_ms),
            alt,
            &mut |vault, approved, plan, account| {
                sign_plan(vault, approved, plan, account).map_err(BtcSignFailure::Sign)
            },
        )
    }

    /// [`JournalState::sign_btc`] with another signer: the `YubiKey` path (spec/10 §6.3) passes
    /// the card signer (`btc::sign::sign_plan_card`, which runs the post-sign verification
    /// itself); the in-flight, recorded-amount and room checks before signing, the post-sign
    /// verification and the `Signed` commit before anything is returned are the same.
    pub fn sign_btc_with(
        &mut self,
        vault: &mut Vault,
        approved: Box<Approved>,
        plan: &SendPlan,
        (tip_height, now_unix_ms): (u32, u64),
        alt: bool,
        sign_step: &mut BtcSigner<'_>,
    ) -> Vec<KeyOutcome> {
        let mut out = Vec::new();
        let result = self.sign_btc_inner(
            vault,
            *approved,
            plan,
            tip_height,
            now_unix_ms,
            alt,
            &mut out,
            sign_step,
        );
        logging::info(
            "journal",
            "btc.sign",
            &[
                ("net", Field::Net(network_id(plan.network()))),
                (
                    "result",
                    Field::Word(if result.is_ok() { "ok" } else { "refused" }),
                ),
            ],
        );
        out.insert(0, KeyOutcome::SignedBtc(result));
        out
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the signing inputs of one approval"
    )]
    fn sign_btc_inner(
        &mut self,
        vault: &mut Vault,
        approved: Approved,
        plan: &SendPlan,
        tip_height: u32,
        now_unix_ms: u64,
        alt: bool,
        out: &mut Vec<KeyOutcome>,
        sign_step: &mut BtcSigner<'_>,
    ) -> Result<BtcSignedSummary, BtcSignFailure> {
        let network = plan.network();
        self.check_network(network)
            .map_err(|_| BtcSignFailure::NetworkMismatch)?;
        // The plan's account, from the worker's own copy (its cached keys are what sign_plan
        // and verify_signed check against; an imported key's secret comes from its vault
        // record, which must match the account's network, type and compression).
        let meta = self
            .account_meta(network, plan.account().id())
            .ok_or(BtcSignFailure::NoMeta)?;
        let current = self.current(vault).map_err(BtcSignFailure::JournalWrite)?;
        if BtcEntries::from_plain(&current).corrupt > 0 {
            return Err(BtcSignFailure::JournalDamaged);
        }
        let now_unix = now_unix_ms / 1_000;
        let mut trial = current;
        let mut rows = make_room(&mut trial, network, tip_height, now_unix, now_unix_ms)
            .map_err(|_| BtcSignFailure::JournalFull)?;
        // D20 and every input rule per account (spec/08 §12.1). The account's records include
        // those of every other identity spending its scripts or outputs (a removed and
        // re-imported key, an alias address): their in-flight inputs and live abandoned or
        // disclosed rejected records constrain this send as well.
        let all = BtcEntries::from_plain(&trial).records();
        let records = of_account(&all, network, meta.id());
        let related = self
            .related(&all, &meta)
            .map_err(|_| BtcSignFailure::Sign(SignError::Derivation))?;
        check_plan_allowed(&records, plan).map_err(BtcSignFailure::Plan)?;
        if plan.replaces().is_none() {
            check_plan_allowed(&related, plan).map_err(BtcSignFailure::Plan)?;
        }
        check_abandoned_conflicts(&related, plan, now_unix).map_err(BtcSignFailure::Plan)?;
        // An output a confirmed transaction of the account spent is gone for good (D32), even if
        // `verified` still lists it: never signed again (the node would refuse it, and the record
        // would then force every later send onto it, spec/08 §12.1).
        let spent = confirmed_inputs(&related, network);
        if plan
            .inputs()
            .iter()
            .any(|input| spent.contains(&input.outpoint))
        {
            return Err(BtcSignFailure::Sign(SignError::InputNotRecorded));
        }
        let mut recorded = meta.recorded_amounts();
        recorded.extend(recorded_amounts(&related, network));
        check_recorded_amounts(plan, &recorded).map_err(BtcSignFailure::Sign)?;
        let signed = sign_step(vault, approved, plan, meta.account())?;
        let verified =
            verify_signed(&signed.raw, plan, meta.account()).map_err(BtcSignFailure::PostSign)?;
        let maxfeerate = verified
            .maxfeerate()
            .ok_or(BtcSignFailure::PostSign(PostSignError::Vsize))?;
        let mut record = BtcRecord::new_signed(plan, &signed, &verified, now_unix)
            .map_err(BtcSignFailure::Record)?;
        // The same bytes were handed to the RPC before (e.g. re-signed after a pre-check
        // rejection): the new record is disclosed from the start.
        record.disclosed = disclosed_duplicate(&trial, &record);
        // The same transaction signed again (e.g. byte for byte after a pre-check rejection):
        // the finished old record goes to activity first; a tracked one refuses (review H1).
        rows.extend(
            take_finished_duplicates(&mut trial, &record, tip_height, now_unix, now_unix_ms)
                .map_err(|_| BtcSignFailure::DuplicateTx)?,
        );
        if !rows.is_empty() {
            let (primary, accounts) = (self.btc.clone(), self.btc_accounts.clone());
            match self.persist_state(vault, primary, accounts, &rows, alt) {
                Ok(moved) if !moved.is_empty() => out.push(KeyOutcome::ActivityMoved(moved)),
                Ok(_) => {}
                Err(_) => return Err(BtcSignFailure::JournalFull),
            }
        }
        push_record(&mut trial, &record).map_err(|error| match error {
            BtcPushError::Full => BtcSignFailure::JournalFull,
            BtcPushError::Duplicate => BtcSignFailure::DuplicateTx,
        })?;
        if let Err(error) = commit_journal(vault, &trial) {
            logging::warn("journal", "btc.signed_write_failed", &[]);
            return Err(BtcSignFailure::JournalWrite(error));
        }
        logging::info(
            "journal",
            "btc.signed",
            &[
                ("net", Field::Net(network_id(network))),
                ("tx", Field::BtcTxid(verified.txid())),
            ],
        );
        out.push(KeyOutcome::Journal(Ok(view_of(&trial))));
        self.plain = Some(trial);
        Ok(BtcSignedSummary {
            network,
            tx: SignedTxRef {
                txid: verified.txid(),
                raw: verified.raw().to_vec(),
                maxfeerate,
            },
            change_index: plan.change().map(|change| change.index),
            replaces: plan.replaces(),
        })
    }

    /// Applies a BTC journal step and commits (meta first, then the journal).
    pub fn btc_journal(
        &mut self,
        vault: &mut Vault,
        op: BtcJournalOp,
        now_unix_ms: u64,
        alt: bool,
    ) -> Vec<KeyOutcome> {
        let name = op.name();
        let mut out = Vec::new();
        let result = self.btc_journal_inner(vault, op, now_unix_ms, alt, &mut out);
        logging::info(
            "journal",
            "btc.journal",
            &[
                ("op", Field::Word(name)),
                (
                    "result",
                    Field::Word(if result.is_ok() { "ok" } else { "refused" }),
                ),
            ],
        );
        out.push(KeyOutcome::BtcJournal(result));
        out
    }

    /// `change_next` past the record's change index, persisted before the record leaves
    /// `Signed` for `Broadcasting` (spec/08 §3.2, §11.1).
    fn raise_change_next(
        &mut self,
        vault: &mut Vault,
        network: BtcNetwork,
        record: &BtcRecord,
        alt: bool,
        out: &mut Vec<KeyOutcome>,
    ) -> Result<(), BtcKeyError> {
        self.check_network(network).map_err(BtcKeyError::Meta)?;
        // The record's own account (a record of an account this session does not have, e.g. an
        // alt-passphrase session sharing the journal, changes no meta).
        let Some(mut meta) = self.account_meta(network, record.account) else {
            return Ok(());
        };
        if meta
            .on_broadcasting(record.hd_change_index(meta.account()))
            .map_err(BtcKeyError::Meta)?
        {
            self.persist_account(vault, meta, &[], alt)?;
            out.push(self.meta_update(BtcMetaDone::ChangeNext));
        }
        Ok(())
    }

    fn commit_view(
        &mut self,
        vault: &mut Vault,
        next: JournalPlain,
        out: &mut Vec<KeyOutcome>,
    ) -> Result<(), BtcKeyError> {
        if let Err(error) = commit_journal(vault, &next) {
            logging::warn("journal", "journal.write_failed", &[]);
            return Err(BtcKeyError::Vault(error));
        }
        out.push(KeyOutcome::Journal(Ok(view_of(&next))));
        self.plain = Some(next);
        Ok(())
    }

    #[expect(clippy::too_many_lines, reason = "one arm per journal step")]
    fn btc_journal_inner(
        &mut self,
        vault: &mut Vault,
        op: BtcJournalOp,
        now_unix_ms: u64,
        alt: bool,
        out: &mut Vec<KeyOutcome>,
    ) -> Result<BtcJournalDone, BtcKeyError> {
        let now_unix = now_unix_ms / 1_000;
        let mut next = self.current(vault).map_err(BtcKeyError::Vault)?;
        match op {
            BtcJournalOp::Disclose { network, txid } => {
                let record = find_record(&next, network, &txid)
                    .ok_or(BtcKeyError::Journal(TransitionError::UnknownTx))?;
                if record.state != BtcTxState::Signed {
                    return Err(BtcKeyError::Journal(TransitionError::NotAllowed {
                        from: record.state,
                        to: BtcTxState::Broadcasting,
                    }));
                }
                let tx = signed_ref(&record).ok_or(BtcKeyError::Internal)?;
                // Committed before any byte leaves the app (the caller sends only on `Ok`).
                if set_disclosed(&mut next, network, &record.entry_id)
                    .map_err(BtcKeyError::Journal)?
                {
                    self.commit_view(vault, next, out)?;
                }
                Ok(BtcJournalDone::Disclosed { network, tx })
            }
            BtcJournalOp::Precheck {
                network,
                txid,
                accept,
            } => {
                let record = find_record(&next, network, &txid)
                    .ok_or(BtcKeyError::Journal(TransitionError::UnknownTx))?;
                if record.state != BtcTxState::Signed {
                    return Err(BtcKeyError::Journal(TransitionError::NotAllowed {
                        from: record.state,
                        to: BtcTxState::Broadcasting,
                    }));
                }
                let local = LocalTx {
                    txid: record.txid,
                    wtxid: record.wtxid,
                    vsize: u64::from(record.vsize),
                    fee: record.fee,
                };
                let entry = record.entry_id;
                // The RPC answered about these bytes, so it has them (normally already set by
                // `Disclose`; kept for every outcome, `Rejected` included).
                set_disclosed(&mut next, network, &entry).map_err(BtcKeyError::Journal)?;
                match check_mempool_accept(&accept, &local) {
                    PrecheckOutcome::Accepted => {
                        let tx = signed_ref(&record).ok_or(BtcKeyError::Internal)?;
                        self.raise_change_next(vault, network, &record, alt, out)?;
                        set_state_entry(
                            &mut next,
                            network,
                            &entry,
                            BtcTxState::Broadcasting,
                            now_unix,
                        )
                        .map_err(BtcKeyError::Journal)?;
                        self.commit_view(vault, next, out)?;
                        fault_point("btc.after_broadcasting");
                        Ok(BtcJournalDone::Broadcasting { network, tx })
                    }
                    PrecheckOutcome::AlreadyKnown { text } => {
                        // The node already has it (spec/08 §11.3): never `Rejected`. Through
                        // `Broadcasting` (change index used) to `BroadcastUnknown` without a
                        // send; tracking (§12.2) moves it on.
                        self.raise_change_next(vault, network, &record, alt, out)?;
                        set_state_entry(
                            &mut next,
                            network,
                            &entry,
                            BtcTxState::Broadcasting,
                            now_unix,
                        )
                        .map_err(BtcKeyError::Journal)?;
                        set_state_entry(
                            &mut next,
                            network,
                            &entry,
                            BtcTxState::BroadcastUnknown,
                            now_unix,
                        )
                        .map_err(BtcKeyError::Journal)?;
                        self.commit_view(vault, next, out)?;
                        Ok(BtcJournalDone::PrecheckKnown { txid, text })
                    }
                    PrecheckOutcome::Rejected { text } => {
                        set_state_entry(&mut next, network, &entry, BtcTxState::Rejected, now_unix)
                            .map_err(BtcKeyError::Journal)?;
                        self.commit_view(vault, next, out)?;
                        Ok(BtcJournalDone::PrecheckRejected { txid, text })
                    }
                }
            }
            BtcJournalOp::Sent {
                network,
                txid,
                result,
            } => {
                let record = find_record(&next, network, &txid)
                    .ok_or(BtcKeyError::Journal(TransitionError::UnknownTx))?;
                let outcome = broadcast_outcome(&result, &txid);
                let (target, comm_failure) = match &outcome {
                    BroadcastOutcome::Submitted => (BtcTxState::Submitted, false),
                    BroadcastOutcome::BroadcastUnknown { comm_failure, .. } => {
                        (BtcTxState::BroadcastUnknown, *comm_failure)
                    }
                    BroadcastOutcome::Rejected { .. } => (BtcTxState::Rejected, false),
                };
                let mut meta_changed = false;
                let mut meta = self.account_meta(network, record.account);
                if let Some(meta) = meta.as_mut() {
                    if outcome == BroadcastOutcome::Submitted
                        && let Some(script) = record.recipient_script()
                    {
                        meta_changed |= meta.record_sent_script(&script);
                    }
                    // `-25`/`-26`: the node refused without relaying; the change index raised
                    // at `Broadcasting` is used again (spec/08 §3.2).
                    if record.state == BtcTxState::Broadcasting
                        && matches!(outcome, BroadcastOutcome::Rejected { .. })
                    {
                        meta_changed |=
                            meta.on_send_rejected(record.hd_change_index(meta.account()));
                    }
                }
                if meta_changed && let Some(meta) = meta {
                    self.persist_account(vault, meta, &[], alt)?;
                    out.push(self.meta_update(BtcMetaDone::Updated));
                }
                let entry = record.entry_id;
                // A send was attempted: the RPC has the bytes whatever it answered (a `-25`/`-26`
                // `Rejected` record still constrains the next send, spec/08 §12.1).
                let mut journal_changed =
                    set_disclosed(&mut next, network, &entry).map_err(BtcKeyError::Journal)?;
                if record.state.can_transition_to(target) {
                    set_state_entry(&mut next, network, &entry, target, now_unix)
                        .map_err(BtcKeyError::Journal)?;
                    journal_changed = true;
                }
                // Kept across restarts: the manual Esplora broadcast stays offered (§11.3).
                if target != BtcTxState::Rejected {
                    journal_changed |=
                        set_last_send_comm_failure(&mut next, network, &entry, comm_failure)
                            .map_err(BtcKeyError::Journal)?;
                }
                if journal_changed {
                    self.commit_view(vault, next, out)?;
                }
                Ok(BtcJournalDone::Sent { txid, outcome })
            }
            BtcJournalOp::EsploraSent { network, txid } => {
                let record = find_record(&next, network, &txid)
                    .ok_or(BtcKeyError::Journal(TransitionError::UnknownTx))?;
                if let Some(mut meta) = self.account_meta(network, record.account)
                    && let Some(script) = record.recipient_script()
                    && meta.record_sent_script(&script)
                {
                    self.persist_account(vault, meta, &[], alt)?;
                    out.push(self.meta_update(BtcMetaDone::Updated));
                }
                if set_last_send_comm_failure(&mut next, network, &record.entry_id, false)
                    .map_err(BtcKeyError::Journal)?
                {
                    self.commit_view(vault, next, out)?;
                }
                Ok(BtcJournalDone::EsploraNoted { txid })
            }
            BtcJournalOp::Tracked {
                network,
                tip_height,
                max_tip_seen,
                observations,
            } => {
                let mut changed = Vec::new();
                for (txid, observation) in observations {
                    match apply_observation(
                        &mut next,
                        network,
                        &txid,
                        observation,
                        tip_height,
                        now_unix,
                    ) {
                        Ok(change) => changed.extend(change.changed),
                        Err(error) => logging::warn(
                            "journal",
                            "btc.observation_refused",
                            &[(
                                "reason",
                                Field::Word(match error {
                                    TransitionError::UnknownTx => "unknown_tx",
                                    TransitionError::NotAllowed { .. } => "not_allowed",
                                    TransitionError::Encode(_) => "encode",
                                }),
                            )],
                        ),
                    }
                }
                let journal_changed = Some(&next) != self.plain.as_ref();
                let mut meta = self.btc.clone();
                let mut accounts = self.btc_accounts.clone();
                // Meta `btc` of another network changes nothing (the mismatch blocks BTC); a
                // key-only wallet has no meta `btc` and only accounts of `network` are touched.
                if self.check_network(network).is_ok() {
                    if let Some(max) = max_tip_seen
                        && let Some(holder) = self.tip_holder(network)
                    {
                        // A regression was refused by the chain check; keep the stored value.
                        let target = if holder == BtcAccountId::PRIMARY {
                            meta.as_mut()
                        } else {
                            accounts.get_mut(network, holder)
                        };
                        if let Some(target) = target {
                            let _ = target.observe_tip(max);
                        }
                    }
                    for (txid, state) in &changed {
                        // Our change goes to the record's own account, and only when the output
                        // is that account's script (an alt-passphrase session shares the journal
                        // of another wallet).
                        let Some(record) = find_record(&next, network, txid) else {
                            continue;
                        };
                        if *state != BtcTxState::Confirmed || record.state != BtcTxState::Confirmed
                        {
                            continue;
                        }
                        // Its inputs are spent for good (one confirmation is final, D32): out of
                        // every account of the network in the same write as the change, else the
                        // balance counts them and a send picks them until a refresh (none runs
                        // once nothing is in flight; a crowded address is never listed again).
                        let spent: Vec<OutPoint> =
                            record.inputs.iter().map(|input| input.outpoint).collect();
                        if let Some(primary) =
                            meta.as_mut().filter(|primary| primary.network() == network)
                        {
                            primary.forget_spent(&spent);
                        }
                        for account in accounts
                            .accounts
                            .iter_mut()
                            .filter(|account| account.network() == network)
                        {
                            account.forget_spent(&spent);
                        }
                        let target = if record.account == BtcAccountId::PRIMARY {
                            meta.as_mut().filter(|primary| primary.network() == network)
                        } else {
                            accounts.get_mut(network, record.account)
                        };
                        if let Some(target) = target
                            && let Some(utxo) = record.own_change_utxo(target.account())
                        {
                            let _ = target.insert_own(utxo);
                        }
                    }
                    if !changed.is_empty() {
                        // A record that left `Rejected` (a disclosed transaction the RPC relayed
                        // after all) counts for the `change_next` floor again: the change index
                        // `on_send_rejected` gave back is used on chain (spec/08 §3.2).
                        let records = BtcEntries::from_plain(&next).records();
                        let reconcile = |account: &mut BtcMeta| {
                            let mine = of_account(&records, network, account.id());
                            account.reconcile_change_next(change_next_floor(
                                &mine,
                                network,
                                account.account(),
                            ))
                        };
                        if let Some(primary) =
                            meta.as_mut().filter(|primary| primary.network() == network)
                        {
                            let _ = reconcile(primary);
                        }
                        for account in accounts
                            .accounts
                            .iter_mut()
                            .filter(|account| account.network() == network)
                        {
                            let _ = reconcile(account);
                        }
                    }
                }
                let mut rows = finished_rows(&next, network, tip_height, now_unix, now_unix_ms);
                let mut pruned = next.clone();
                let prune_rows = if alt {
                    Vec::new()
                } else {
                    prune_finished(&mut pruned, network, tip_height, now_unix, now_unix_ms)
                };
                for row in prune_rows {
                    if !rows.iter().any(|known| known.tx_id == row.tx_id) {
                        rows.push(row);
                    }
                }
                let meta_changed = meta != self.btc || accounts != self.btc_accounts;
                let mut final_plain = next;
                if meta_changed || !rows.is_empty() {
                    match self.persist_state(vault, meta, accounts, &rows, alt) {
                        Ok(moved) => {
                            if meta_changed {
                                out.push(self.meta_update(BtcMetaDone::Updated));
                            }
                            if !moved.is_empty() {
                                out.push(KeyOutcome::ActivityMoved(moved));
                            }
                            // Meta has the rows: the journal may now drop the pruned records.
                            final_plain = pruned;
                        }
                        Err(error) => {
                            logging::warn(
                                "journal",
                                "meta.write_failed",
                                &[("code", Field::Code(crate::errors::vault_code(error)))],
                            );
                        }
                    }
                }
                if journal_changed || Some(&final_plain) != self.plain.as_ref() {
                    self.commit_view(vault, final_plain, out)?;
                }
                Ok(BtcJournalDone::Tracked { changed })
            }
            BtcJournalOp::Abandon { network, txid } => {
                let record = find_record(&next, network, &txid)
                    .ok_or(BtcKeyError::Journal(TransitionError::UnknownTx))?;
                set_state_entry(
                    &mut next,
                    network,
                    &record.entry_id,
                    BtcTxState::Abandoned,
                    now_unix,
                )
                .map_err(BtcKeyError::Journal)?;
                self.commit_view(vault, next, out)?;
                Ok(BtcJournalDone::Abandoned { txid })
            }
        }
    }
}
