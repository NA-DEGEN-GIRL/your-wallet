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
    BtcMeta, BtcNetwork, Discovery, OutPoint, PlanError, PostSignError, SendPlan, SignError, Txid,
    check_recorded_amounts, sign_plan, verify_signed,
};
use yw_core::error::{StorageError, VaultError};
use yw_core::journal::JournalPlain;
use yw_core::journal::btc::{
    BtcActivityRow, BtcEntries, BtcPushError, BtcRecord, BtcRecordError, BtcTxState,
    TrackObservation, TransitionError, apply_observation, change_next_floor,
    check_abandoned_conflicts, check_plan_allowed, current_record, finished_rows, make_room,
    normalize_on_startup, prune_finished, push_record, recorded_amounts, refresh_keep_outpoints,
    set_last_send_comm_failure, set_state_entry, take_finished_duplicates,
};
use yw_core::vault::{FileKind, Vault};

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
}

/// A `BtcMeta` change made and persisted by the key worker. Every op names the network it was
/// made for; a different `BtcMeta.network` refuses it (`NetworkMismatch`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BtcMetaOp {
    /// A fresh `BtcMeta` for `network` (BTC enable, network change, `null` meta with BTC
    /// enabled): `Vault::btc_account_xpub` of the network's coin (spec/08 §2, §3.1).
    Create {
        /// Network.
        network: BtcNetwork,
    },
    /// A finished discovery (`Discovery::apply`, spec/08 §3.4).
    Discovered {
        /// Network.
        network: BtcNetwork,
        /// The finished state machine.
        discovery: Box<Discovery>,
    },
    /// A completed refresh (`mark_history`, `apply_refresh`, `observe_tip`).
    Refreshed {
        /// Network.
        network: BtcNetwork,
        /// Refresh results.
        update: Box<BtcRefreshUpdate>,
    },
    /// A Core tip seen (`observe_tip`).
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
    },
    /// "새 주소" (`new_receive_address`).
    NewReceiveAddress {
        /// Network.
        network: BtcNetwork,
        /// The 20-unused warning was confirmed ([그래도 발급]).
        gap_confirmed: bool,
    },
    /// User freeze / unfreeze of a verified output (spec/08 §7.6).
    Freeze {
        /// Network.
        network: BtcNetwork,
        /// Output.
        outpoint: OutPoint,
        /// `true` = freeze.
        frozen: bool,
    },
    /// "블록 높이 기록 초기화" (`BtcMeta::reset_max_tip`, spec/08 §2 step 2).
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
            | Self::Discovered { network, .. }
            | Self::Refreshed { network, .. }
            | Self::Tip { network, .. }
            | Self::ReceiveAddress { network }
            | Self::NewReceiveAddress { network, .. }
            | Self::Freeze { network, .. }
            | Self::ResetTip { network } => *network,
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
    /// `change_next` raised (startup reconciliation or `Broadcasting`).
    ChangeNext,
    /// Other bookkeeping of a journal step (sent script, own change, tip).
    Updated,
}

/// A persisted `BtcMeta` (the UI replaces its mirror with it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcMetaUpdate {
    /// The key worker's `BtcMeta` after the change.
    pub meta: Option<Box<BtcMeta>>,
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
}

impl BtcSignFailure {
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
        }
    }
}

/// A BTC journal step (spec/08 §11.3, §12.1–§12.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BtcJournalOp {
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
    /// Sets the session's `BtcMeta` from the loaded meta document (`LoadMeta`).
    pub fn set_btc_meta(&mut self, meta: Option<BtcMeta>) {
        self.btc = meta;
        self.btc_loaded = true;
    }

    /// The session's `BtcMeta`.
    #[must_use]
    pub const fn btc_meta(&self) -> Option<&BtcMeta> {
        self.btc.as_ref()
    }

    /// Puts the worker's `BtcMeta` into a meta document about to be written (the UI's copy is
    /// only a mirror).
    pub fn apply_btc_meta(&self, document: &mut Meta) {
        if self.btc_loaded {
            document.btc = self.btc.clone().map(Box::new);
        }
    }

    fn meta_update(&self, done: BtcMetaDone) -> KeyOutcome {
        KeyOutcome::BtcMeta(Ok(BtcMetaUpdate {
            meta: self.btc.clone().map(Box::new),
            done,
        }))
    }

    /// Writes `candidate` as meta `btc` together with the activity rows not stored yet (same
    /// `tx_id` and status), then adopts it. In alt-passphrase sessions nothing is written (meta
    /// is never stored) and the copy lives in memory only.
    fn persist_btc(
        &mut self,
        vault: &mut Vault,
        candidate: Option<BtcMeta>,
        rows: &[BtcActivityRow],
        alt: bool,
    ) -> Result<Vec<(NetworkId, ActivityEntry)>, VaultError> {
        let mut moved = Vec::new();
        if !alt {
            let mut document = match vault.open_sidecar(FileKind::Meta)? {
                None => Meta::default(),
                Some((_, plaintext)) => {
                    meta::parse(&plaintext)
                        .map_err(|_| VaultError::SidecarCorrupt(FileKind::Meta))?
                        .meta
                }
            };
            document.btc = candidate.clone().map(Box::new);
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
        self.btc = candidate;
        self.btc_loaded = true;
        self.overlay.extend(moved.iter().cloned());
        Ok(moved)
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
        vec![KeyOutcome::BtcMeta(result.map(|done| BtcMetaUpdate {
            meta: self.btc.clone().map(Box::new),
            done,
        }))]
    }

    fn btc_meta_op_inner(
        &mut self,
        vault: &mut Vault,
        op: BtcMetaOp,
        alt: bool,
    ) -> Result<BtcMetaDone, BtcKeyError> {
        if let BtcMetaOp::Create { network } = op {
            let account = vault
                .btc_account_xpub(network.coin_type())
                .map_err(BtcKeyError::Vault)?;
            let fresh = BtcMeta::new(network, account);
            self.persist_btc(vault, Some(fresh), &[], alt)
                .map_err(BtcKeyError::Vault)?;
            return Ok(BtcMetaDone::Created);
        }
        let mut meta = self.btc.clone().ok_or(BtcKeyError::NoMeta)?;
        meta.check_network(op.network())
            .map_err(BtcKeyError::Meta)?;
        let done = match op {
            BtcMetaOp::Create { .. } => BtcMetaDone::Created,
            BtcMetaOp::Discovered { discovery, .. } => {
                discovery.apply(&mut meta).map_err(BtcKeyError::Meta)?;
                BtcMetaDone::Discovered
            }
            BtcMetaOp::Refreshed { update, .. } => {
                for (chain, index, tx_count) in &update.history {
                    // An index the indexer answered for but meta never issued is ignored.
                    let _ = meta.mark_history(*chain, *index, *tx_count);
                }
                let records = self
                    .plain
                    .as_ref()
                    .map(|plain| BtcEntries::from_plain(plain).records())
                    .unwrap_or_default();
                let network = meta.network();
                let report = meta.apply_refresh(
                    &update.listed,
                    &update.newly,
                    &refresh_keep_outpoints(&records, network, update.now_unix),
                    &yw_core::journal::btc::own_outputs(&records, network),
                );
                // A regression was already refused by the chain check; keep the stored value.
                let _ = meta.observe_tip(update.max_tip_seen);
                BtcMetaDone::Refreshed(report)
            }
            BtcMetaOp::Tip { max_tip_seen, .. } => {
                meta.observe_tip(max_tip_seen).map_err(BtcKeyError::Meta)?;
                BtcMetaDone::Tip
            }
            BtcMetaOp::ReceiveAddress { .. } => match meta.receive_address() {
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
                Err(error) => return Err(BtcKeyError::Meta(error)),
            },
            BtcMetaOp::NewReceiveAddress { gap_confirmed, .. } => {
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
        if self.btc.as_ref() != Some(&meta) {
            self.persist_btc(vault, Some(meta), &[], alt)
                .map_err(BtcKeyError::Vault)?;
        }
        Ok(done)
    }

    /// Startup work after the journal is read (spec/08 §3.2, §12.1): `Broadcasting` records
    /// become `BroadcastUnknown`, and `change_next = max(meta, journal floor)`. `Signed` records
    /// stay for the UI's [전송 계속] / [취소].
    pub fn btc_startup(&mut self, vault: &mut Vault, now_unix: u64, alt: bool) -> Vec<KeyOutcome> {
        let mut out = Vec::new();
        let Some(mut next) = self.plain.clone() else {
            return out;
        };
        if let Some(mut meta) = self.btc.clone() {
            let records = BtcEntries::from_plain(&next).records();
            let floor = change_next_floor(&records, meta.network());
            if meta.reconcile_change_next(floor) {
                match self.persist_btc(vault, Some(meta), &[], alt) {
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
        let mut out = Vec::new();
        let result = self.sign_btc_inner(
            vault,
            *approved,
            plan,
            tip_height,
            now_unix_ms,
            alt,
            &mut out,
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
    ) -> Result<BtcSignedSummary, BtcSignFailure> {
        let network = plan.network();
        let meta = self.btc.clone().ok_or(BtcSignFailure::NoMeta)?;
        meta.check_network(network)
            .map_err(|_| BtcSignFailure::NetworkMismatch)?;
        let current = self.current(vault).map_err(BtcSignFailure::JournalWrite)?;
        if BtcEntries::from_plain(&current).corrupt > 0 {
            return Err(BtcSignFailure::JournalDamaged);
        }
        let now_unix = now_unix_ms / 1_000;
        let mut trial = current;
        let mut rows = make_room(&mut trial, network, tip_height, now_unix, now_unix_ms)
            .map_err(|_| BtcSignFailure::JournalFull)?;
        let records = BtcEntries::from_plain(&trial).records();
        check_plan_allowed(&records, plan).map_err(BtcSignFailure::Plan)?;
        check_abandoned_conflicts(&records, plan, now_unix).map_err(BtcSignFailure::Plan)?;
        let mut recorded = meta.recorded_amounts();
        recorded.extend(recorded_amounts(&records, network));
        check_recorded_amounts(plan, &recorded).map_err(BtcSignFailure::Sign)?;
        let signed =
            sign_plan(vault, approved, plan, meta.account()).map_err(BtcSignFailure::Sign)?;
        let verified =
            verify_signed(&signed.raw, plan, meta.account()).map_err(BtcSignFailure::PostSign)?;
        let maxfeerate = verified
            .maxfeerate()
            .ok_or(BtcSignFailure::PostSign(PostSignError::Vsize))?;
        let record = BtcRecord::new_signed(plan, &signed, &verified, now_unix)
            .map_err(BtcSignFailure::Record)?;
        // The same transaction signed again (e.g. byte for byte after a pre-check rejection):
        // the finished old record goes to activity first; a tracked one refuses (review H1).
        rows.extend(
            take_finished_duplicates(&mut trial, &record, tip_height, now_unix, now_unix_ms)
                .map_err(|_| BtcSignFailure::DuplicateTx)?,
        );
        if !rows.is_empty() {
            match self.persist_btc(vault, Some(meta.clone()), &rows, alt) {
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
        let mut meta = self.btc.clone().ok_or(BtcKeyError::NoMeta)?;
        meta.check_network(network).map_err(BtcKeyError::Meta)?;
        if meta
            .on_broadcasting(record.change.map(|change| change.index))
            .map_err(BtcKeyError::Meta)?
        {
            self.persist_btc(vault, Some(meta), &[], alt)
                .map_err(BtcKeyError::Vault)?;
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
                let mut meta = self.btc.clone().filter(|meta| meta.network() == network);
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
                            meta.on_send_rejected(record.change.map(|change| change.index));
                    }
                }
                if meta_changed {
                    self.persist_btc(vault, meta, &[], alt)
                        .map_err(BtcKeyError::Vault)?;
                    out.push(self.meta_update(BtcMetaDone::Updated));
                }
                let entry = record.entry_id;
                let mut journal_changed = false;
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
                if let Some(mut meta) = self.btc.clone()
                    && meta.network() == network
                    && let Some(script) = record.recipient_script()
                    && meta.record_sent_script(&script)
                {
                    self.persist_btc(vault, Some(meta), &[], alt)
                        .map_err(BtcKeyError::Vault)?;
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
                if let Some(meta) = meta.as_mut()
                    && meta.network() == network
                {
                    if let Some(max) = max_tip_seen {
                        // A regression was refused by the chain check; keep the stored value.
                        let _ = meta.observe_tip(max);
                    }
                    let account = *meta.account();
                    for (txid, state) in &changed {
                        // Only change paying this session's account (an alt-passphrase session
                        // shares the journal of another account).
                        if *state == BtcTxState::Confirmed
                            && let Some(utxo) = find_record(&next, network, txid)
                                .and_then(|record| record.own_change_utxo(&account))
                        {
                            let _ = meta.insert_own(utxo);
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
                let meta_changed = meta != self.btc;
                let mut final_plain = next;
                if meta_changed || !rows.is_empty() {
                    match self.persist_btc(vault, meta, &rows, alt) {
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
