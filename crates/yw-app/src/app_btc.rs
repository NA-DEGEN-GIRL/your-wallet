//! Bitcoin on the UI thread (M8; spec/08, spec/04 §2.6–§2.11, §3): the [`BtcUi`] controller
//! holds everything the Bitcoin screens render (balances, tip, lag warning, discovery progress,
//! the send and fee-bump forms, the receive address, the post-sign flow of each transaction,
//! activity rows, confirmation overlays) and turns user actions and worker results into
//! [`BtcAction`]s: key worker jobs (meta and journal writes, signing), RPC worker jobs (every
//! network call), approval items, settings writes. It never renders and never blocks; the App
//! glue at the end of this file executes the actions.
//!
//! Rules enforced here (spec/08): no BTC network call while locked except the Esplora settings
//! `테스트` (§4.4); none while settings `bitcoin.network` and `BtcMeta.network` differ (§2,
//! [설정을 {meta}로 되돌리기] / [{settings}로 바꾸기]); none without the `bitcoin:<net>` endpoint
//! (E-KEY-005); sending needs a finished discovery, no in-flight record (D20, fee bumps
//! allowed), an undamaged BTC journal (E-VLT-006); a receive address is shown only after the key
//! worker stored `receive_next`; the 60 s refresh/tracking tick runs only while unlocked and
//! the worker skips automatic jobs during the 429 cooldown.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use yw_core::approval::{ApprovalDraft, ApprovalId, Approved};
use yw_core::bip32::path::BtcChain;
use yw_core::btc::account::{BtcAccountId, BtcAccountKey, ScriptType};
use yw_core::btc::address::ScriptKind;
use yw_core::btc::amount::{format_btc_and_sats, parse_user_btc, parse_user_sats};
use yw_core::btc::fee::parse_user_sat_per_vb;
use yw_core::btc::meta::{BtcAccounts, BtcBalance, FreezeReason, MetaError};
use yw_core::btc::policy::{BroadcastOutcome, broadcast_outcome, texts};
use yw_core::btc::{
    BTC_CONF_TARGETS, BTC_POLL_SECS, BtcMeta, BtcNetwork, BtcSendFacts, Discovery, FeeRate,
    OutPoint, Sats, SendAmount, SendPlan, Txid, build_btc_request, conf, encode_address,
    parse_address,
};
use yw_core::journal::btc::{
    AccountScope, BTC_FINAL_CONFIRMATIONS, BtcRecord, BtcTxState, TrackMode, abandoned_conflicts,
    bump_target, check_can_send, current_record, in_flight, in_flight_outpoints,
    in_flight_replacements, of_account, related_records, track_mode,
};
use yw_win::http::HttpsUrl;

use crate::apikeys::ApiKeys;
use crate::btc::broadcast::{EsploraPostOutcome, ManualBroadcastGate};
use crate::btc::chain::{BtcBlock, ChainInput, CoreCheckFailure};
use crate::btc::flow::{DiscoveryJob, RefreshJob, TrackItem};
use crate::btc::work::{
    BtcRpcEvent, BtcRpcJob, BtcTarget, FeeInput, PrepareError, PrepareJob, PrepareKind, SignedTxRef,
};
use crate::btc::{BtcEndpoint, BtcError, Trigger, app_network, core_network, network_id};
use crate::errors::ErrorCode;
use crate::events::{JournalView, KeyJob, KeyOutcome};
use crate::logging::{self, Field};
use crate::meta::Meta;
use crate::network::NetworkId;
use crate::settings::{BitcoinSettings, BtcIndexer, validate_esplora_url};
use crate::ui::approval::QueueOutcome;
use crate::workers::journal::btc::{
    BtcJournalDone, BtcJournalOp, BtcKeyError, BtcMetaDone, BtcMetaOp, BtcMetaUpdate,
    BtcRefreshUpdate, BtcSignFailure, BtcSignedSummary, signed_ref,
};
use crate::workers::rpc::RpcJob;

/// Fixed text of the import screen (spec/08 §1.2).
pub const BTC_IMPORT_NOTE: &str = "Bitcoin은 네이티브 세그윗(bc1q…, BIP84) 계정 0을 먼저 찾습니다. 탭루트·호환 세그윗·레거시 주소는 Bitcoin 탭의 [계정 추가]로 더하세요";
/// Refresh / tracking period while unlocked (spec/08 §4.7, §12.2).
pub const BTC_TICK_MS: u64 = BTC_POLL_SECS * 1_000;
/// Activity rows shown.
pub const BTC_MAX_ACTIVITY_ROWS: usize = 50;
/// "주소 검색 미완료" (spec/08 §3.4).
pub const DISCOVERY_INCOMPLETE: &str = "주소 검색 미완료";
/// "미확정 입금 있음(미검증, 교체될 수 있음)" (spec/08 §4.7-2).
pub const PENDING_INCOMING: &str = "미확정 입금 있음(미검증, 교체될 수 있음)";
/// T-APPR-EXPIRED.
pub const APPROVAL_EXPIRED: &str = "승인 시간이 지났습니다. 다시 검토하세요.";
/// "(서버 기준)" suffix of confirmations (spec/08 §12.2-4).
pub const SERVER_BASED: &str = "(서버 기준)";
/// The "블록 높이 기록 초기화" confirmation (spec/08 §2 step 2).
pub const RESET_TIP_TEXT: &str = "이 지갑이 기록한 가장 높은 블록 높이를 지웁니다. 노드(RPC)가 전에 잘못된(너무 높은) 높이를 알려 줘 지금 연결 검사가 계속 실패하는 경우에만 하세요. 노드가 오래된 체인을 보여 주는 경우라면 초기화하지 말고 노드 설정을 확인하세요. 초기화할까요?";
/// UTXO mark of a candidate Core's `gettxout` did not confirm this refresh.
pub const INDEXER_ONLY: &str = "인덱서만 확인(노드 미확인)";

/// Account switch / add refused while a BTC approval is open.
pub const ACCOUNT_SWITCH_BUSY: &str =
    "Bitcoin 승인이 진행 중이라 계정을 바꾸거나 추가할 수 없습니다";
/// Address-mode switch refused while a BTC approval is open.
pub const ADDRESS_MODE_BUSY: &str = "Bitcoin 승인이 진행 중이라 주소 방식을 바꿀 수 없습니다";

/// The address-mode radio of an HD account: fixed address (spec/08 §3.5, the default).
pub const T_BTC_MODE_SINGLE: &str = "고정 주소 하나만 사용 (UniSat·Xverse 방식)";
/// The address-mode radio of an HD account: a new address each time.
pub const T_BTC_MODE_HD: &str = "받을 때마다 새 주소 (HD, 프라이버시↑)";
/// One-line trade-off under the address-mode radios.
pub const T_BTC_MODE_HELP: &str = "고정 주소는 받기·잔돈이 늘 같은 주소(…/0/0)라 관리와 소유 증명이 쉽지만, 누구나 그 주소의 잔액과 거래를 모두 볼 수 있습니다. 새 주소 방식은 프라이버시가 낫지만 주소가 계속 바뀝니다.";
/// The receive note of an HD account in fixed-address mode (spec/04 §2.8).
pub const T_BTC_FIXED_RECEIVE: &str = "이 계정은 주소 하나만 씁니다. 같은 복구 단어를 Electrum/Sparrow/UniSat에 넣으면 같은 주소가 나옵니다.";
/// The key-source radio of `계정 추가`: the standard BTC path (default).
pub const T_BTC_SOURCE_STANDARD: &str = "BTC 표준 경로 (권장, 기본값)";
/// The key-source radio of `계정 추가`: the key of an EVM account.
pub const T_BTC_SOURCE_EVM: &str = "EVM 계정과 같은 키";
/// Help under the standard key source.
pub const T_BTC_SOURCE_STANDARD_HELP: &str = "m/{44·49·84·86}'/{코인}'/{계정}'/0/0 — 같은 복구 단어를 다른 Bitcoin 지갑에 넣어도 같은 주소가 나옵니다.";
/// The warning of an account on an EVM account's key (spec/08 §3.5).
pub const T_BTC_EVM_SHARED: &str = "같은 키를 쓰면 EVM 주소와 BTC 주소의 공개키가 같아져, 누구나 두 주소가 같은 사람 것임을 알 수 있습니다. 다른 BTC 지갑(Electrum·Sparrow)에 복구 단어만 넣으면 이 주소가 보이지 않습니다(복구는 이 지갑이나 개인키 내보내기로).";

/// The key source chosen in `계정 추가` (spec/08 §3.5).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BtcAddSource {
    /// `m/{44|49|84|86}'/{coin}'/a'` (the default).
    #[default]
    Standard,
    /// The key of an EVM account (`m/44'/60'/0'/0/i`), explicit choice and confirmation.
    EvmShared,
}

/// Account delete refused while a BTC approval is open (spec/04 §2.18).
pub const REMOVE_BUSY_APPROVAL: &str = "Bitcoin 승인이 진행 중이라 이 가져온 키를 지울 수 없습니다. 승인을 끝내거나 거절한 뒤 다시 하세요";
/// Account delete refused while the account has an in-flight transaction (spec/04 §2.18).
pub const REMOVE_BUSY_IN_FLIGHT: &str = "이 가져온 키의 주소로 보낸 거래가 아직 확정될 수 있습니다(진행 중, 또는 포기·거절 뒤 30일 이내). 추적과 이중 지불 방지에 이 키가 필요하므로, 거래가 확정되거나 끝난 뒤(포기·거절한 거래는 30일 뒤)에 지울 수 있습니다";

/// One row of the Bitcoin account list (spec/04 §2.6 Bitcoin).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcAccountRow {
    /// Identity.
    pub id: BtcAccountId,
    /// `네이티브 세그윗 계정 0`, `탭루트 계정 1`; an imported key: its shortened address
    /// (`tb1q6r…cpvkl`).
    pub name: String,
    /// The address type with its prefix: `네이티브 세그윗 (bc1q…)`.
    pub kind: String,
    /// Available verified balance at the known tip (the account's last refresh).
    pub available: Sats,
    /// The selected account.
    pub selected: bool,
    /// An imported single key (the "[가져온 키]" badge; not restored by the recovery words).
    pub imported: bool,
    /// The EVM account whose key this account uses (the "[EVM 계정 i 키]" badge).
    pub evm_shared: Option<u32>,
    /// The account receives and gets change at one fixed address.
    pub fixed: bool,
}

/// The shortened address of a single-key account row: first 6 and last 6 characters.
#[must_use]
pub fn short_address(address: &str) -> String {
    let chars: Vec<char> = address.chars().collect();
    if chars.len() <= 14 {
        return address.to_owned();
    }
    let head: String = chars.iter().take(6).collect();
    let tail: String = chars.iter().skip(chars.len().saturating_sub(6)).collect();
    format!("{head}…{tail}")
}

/// `네이티브 세그윗 계정 0` / `가져온 키 · 레거시`.
#[must_use]
pub fn account_label(account: &BtcAccountKey) -> String {
    account.display_name()
}

/// The address type with its prefix: `탭루트 (bc1p…)`, `레거시 (m·n…)`.
#[must_use]
pub fn account_type_text(account: &BtcAccountKey, net: BtcNetwork) -> String {
    let script_type = account.script_type();
    format!("{} ({})", script_type.name(), script_type.prefix(net))
}

/// The active account of `net` in a persisted update (`BtcAccounts::active_on`: the selected
/// one, else BIP84 account 0, else — a key-only wallet — the first account of `net`).
fn active_of(update: &BtcMetaUpdate, net: BtcNetwork) -> Option<BtcMeta> {
    let primary = update.meta.as_deref().filter(|meta| meta.network() == net);
    match update.accounts.active_on(net, primary.is_some())? {
        BtcAccountId::PRIMARY => primary.cloned(),
        id => update.accounts.get(net, id).cloned(),
    }
}

/// Everything the controller reads from the App (borrowed for one call).
pub struct BtcCtx<'a> {
    /// settings.json `bitcoin`.
    pub settings: &'a BitcoinSettings,
    /// The decrypted endpoints (`rpc:bitcoin:<net>`).
    pub apikeys: &'a ApiKeys,
    /// The UI's meta mirror (`btc` is the key worker's last persisted copy).
    pub meta: Option<&'a Meta>,
    /// The journal view.
    pub journal: Option<&'a JournalView>,
    /// `AppMode::Unlocked`.
    pub unlocked: bool,
    /// The wallet has recovery words (`false`: a key-only wallet, whose Bitcoin accounts are
    /// imported single keys only — no BIP84 account 0, no discovery, no `계정 추가`).
    pub has_mnemonic: bool,
    /// Monotonic ms.
    pub now_ms: u64,
    /// Wall clock, Unix ms.
    pub now_unix_ms: u64,
}

impl core::fmt::Debug for BtcCtx<'_> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("BtcCtx")
    }
}

/// Why BTC network calls are not allowed now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcGate {
    /// `bitcoin.enabled == false`.
    Disabled,
    /// Locked (only the Esplora settings `테스트` may call).
    Locked,
    /// No `BtcMeta` yet (being created).
    NoMeta,
    /// A key-only wallet without an imported Bitcoin key on the settings network.
    NoAccount,
    /// settings `bitcoin.network` ≠ `BtcMeta.network`.
    Mismatch {
        /// `BtcMeta.network`.
        meta: BtcNetwork,
        /// settings `bitcoin.network`.
        settings: BtcNetwork,
    },
    /// No `rpc:bitcoin:<net>` URL (E-KEY-005).
    NoEndpoint,
    /// The journal is not read yet.
    JournalLoading,
}

impl BtcGate {
    /// Fixed text.
    #[must_use]
    pub fn text(self) -> String {
        match self {
            Self::Disabled => {
                "Bitcoin이 꺼져 있습니다. 설정 → Bitcoin에서 켤 수 있습니다.".to_owned()
            }
            Self::Locked => "잠금을 해제하세요.".to_owned(),
            Self::NoMeta => "Bitcoin 계정을 준비하는 중입니다…".to_owned(),
            Self::NoAccount => {
                "이 네트워크에는 가져온 Bitcoin 개인키가 없습니다. 개인키를 가져오세요.".to_owned()
            }
            Self::Mismatch { .. } => texts::NETWORK_MISMATCH.to_owned(),
            Self::NoEndpoint => ErrorCode::Key005.text(),
            Self::JournalLoading => "불러오는 중…".to_owned(),
        }
    }
}

impl BtcCtx<'_> {
    /// The settings network.
    #[must_use]
    pub const fn net(&self) -> BtcNetwork {
        core_network(self.settings.network)
    }

    /// The meta mirror's BIP84 account 0 (meta `btc`): a mnemonic wallet's network copy and
    /// `max_tip_seen` live here. A key-only wallet has none.
    #[must_use]
    pub fn primary_meta(&self) -> Option<&BtcMeta> {
        self.meta.and_then(|meta| meta.btc.as_deref())
    }

    /// BIP84 account 0 exists on the settings network.
    fn has_primary(&self) -> bool {
        self.primary_meta()
            .is_some_and(|meta| meta.network() == self.net())
    }

    /// The active account of the settings network: the selected one, else BIP84 account 0,
    /// else (a key-only wallet) the first imported key of this network.
    #[must_use]
    pub fn active_id(&self) -> BtcAccountId {
        self.meta
            .and_then(|meta| meta.btc_accounts.active_on(self.net(), self.has_primary()))
            .unwrap_or(BtcAccountId::PRIMARY)
    }

    /// Account `id` of the settings network (BIP84 account 0 is meta `btc`).
    fn account(&self, id: BtcAccountId) -> Option<&BtcMeta> {
        if id == BtcAccountId::PRIMARY {
            self.primary_meta()
                .filter(|meta| meta.network() == self.net())
        } else {
            self.meta?.btc_accounts.get(self.net(), id)
        }
    }

    /// The selected account's `BtcMeta` (every send, receive, refresh and balance is this
    /// account's).
    #[must_use]
    pub fn btc_meta(&self) -> Option<&BtcMeta> {
        self.account(self.active_id())
    }

    /// The account holding the wallet-level `max_tip_seen` of the settings network: BIP84
    /// account 0, or in a key-only wallet the first account of the network.
    #[must_use]
    pub fn tip_meta(&self) -> Option<&BtcMeta> {
        let id = self
            .meta?
            .btc_accounts
            .tip_holder(self.net(), self.has_primary())?;
        self.account(id)
    }

    /// The derived EVM accounts (`m/44'/60'/0'/0/i`) a BTC account may share a key with, in meta
    /// order: `(index, label, address)` (hidden accounts too).
    #[must_use]
    pub fn evm_accounts(&self) -> Vec<(u32, String, String)> {
        self.meta.map_or_else(Vec::new, |meta| {
            meta.evm_accounts
                .iter()
                .map(|account| {
                    (
                        account.index,
                        account.label.clone(),
                        account.address.clone(),
                    )
                })
                .collect()
        })
    }

    /// The indices of [`BtcCtx::evm_accounts`].
    #[must_use]
    pub fn evm_indices(&self) -> Vec<u32> {
        self.meta.map_or_else(Vec::new, |meta| {
            meta.evm_accounts
                .iter()
                .map(|account| account.index)
                .collect()
        })
    }

    /// The EVM account index and network of the selected account when it uses an EVM account's
    /// key (`개인키 보기` shows its WIF).
    #[must_use]
    pub fn selected_evm_shared(&self) -> Option<(u32, BtcNetwork)> {
        let meta = self.btc_meta()?;
        match meta.id() {
            BtcAccountId::EvmShared { evm_index, .. } => Some((evm_index, meta.network())),
            BtcAccountId::Hd { .. }
            | BtcAccountId::Imported { .. }
            | BtcAccountId::Hardware { .. } => None,
        }
    }

    /// The vault record id of the selected account when it is an imported single key.
    #[must_use]
    pub fn selected_imported(&self) -> Option<[u8; 16]> {
        match self.btc_meta()?.id() {
            BtcAccountId::Imported { id } => Some(id),
            BtcAccountId::Hd { .. }
            | BtcAccountId::EvmShared { .. }
            | BtcAccountId::Hardware { .. } => None,
        }
    }

    /// Every account of the settings network, BIP84 account 0 first (the account list).
    #[must_use]
    pub fn accounts(&self) -> Vec<&BtcMeta> {
        self.accounts_on(self.net())
    }

    /// Every account of `net`, BIP84 account 0 first.
    pub(crate) fn accounts_on(&self, net: BtcNetwork) -> Vec<&BtcMeta> {
        let mut out: Vec<&BtcMeta> = self
            .primary_meta()
            .filter(|meta| meta.network() == net)
            .into_iter()
            .collect();
        if let Some(meta) = self.meta {
            out.extend(meta.btc_accounts.of_network(net));
        }
        out
    }

    /// BTC records of every network.
    #[must_use]
    pub fn all_records(&self) -> &[BtcRecord] {
        self.journal
            .map_or(&[], |journal| journal.btc_records.as_slice())
    }

    /// Records of every account of the settings network (tracking follows all of them).
    #[must_use]
    pub fn network_records(&self) -> Vec<BtcRecord> {
        let net = self.net();
        self.all_records()
            .iter()
            .filter(|record| record.network == net)
            .cloned()
            .collect()
    }

    /// The settings / meta mismatch, if any.
    #[must_use]
    pub fn mismatch(&self) -> Option<(BtcNetwork, BtcNetwork)> {
        let meta = self.primary_meta()?.network();
        (meta != self.net()).then_some((meta, self.net()))
    }

    /// The Core URL of `net`.
    #[must_use]
    pub fn core_url(&self, net: BtcNetwork) -> Option<HttpsUrl> {
        self.apikeys.rpc_url(network_id(net))
    }

    /// The Esplora base of `net` (settings).
    #[must_use]
    pub fn esplora_text(&self, net: BtcNetwork) -> &str {
        match net {
            BtcNetwork::Mainnet => &self.settings.esplora_mainnet,
            BtcNetwork::Testnet4 => &self.settings.esplora_testnet4,
        }
    }

    /// Whether BTC network calls (other than the settings `테스트`) may run now.
    ///
    /// # Errors
    ///
    /// The [`BtcGate`] reason.
    pub fn gate(&self) -> Result<(), BtcGate> {
        if !self.settings.enabled {
            return Err(BtcGate::Disabled);
        }
        if !self.unlocked {
            return Err(BtcGate::Locked);
        }
        if let Some((meta, settings)) = self.mismatch() {
            return Err(BtcGate::Mismatch { meta, settings });
        }
        // A mnemonic wallet always has BIP84 account 0 (created when BTC is turned on); a
        // key-only wallet works with its imported keys of this network only.
        if self.has_mnemonic && self.primary_meta().is_none() {
            return Err(BtcGate::NoMeta);
        }
        if self.btc_meta().is_none() {
            return Err(if self.has_mnemonic {
                BtcGate::NoMeta
            } else {
                BtcGate::NoAccount
            });
        }
        if self.core_url(self.net()).is_none() {
            return Err(BtcGate::NoEndpoint);
        }
        if self.journal.is_none() {
            return Err(BtcGate::JournalLoading);
        }
        Ok(())
    }

    /// The job target of the settings network (after [`Self::gate`]).
    ///
    /// # Errors
    ///
    /// E-KEY-005 without an endpoint, E-BTC-006 for a bad Esplora base.
    pub fn target(&self) -> Result<BtcTarget, ErrorCode> {
        let net = self.net();
        let core_url = self.core_url(net).ok_or(ErrorCode::Key005)?;
        let esplora_base =
            HttpsUrl::parse(self.esplora_text(net)).map_err(|_| ErrorCode::Btc006)?;
        let meta_net = self.primary_meta().map_or(net, BtcMeta::network);
        Ok(BtcTarget {
            endpoint: BtcEndpoint {
                net,
                core_url,
                indexer: self.settings.indexer,
                esplora_base,
            },
            meta_net,
        })
    }

    /// Chain-check inputs (the tip holder's persisted `max_tip_seen`, local UTC seconds).
    #[must_use]
    pub fn chain_input(&self) -> ChainInput {
        ChainInput {
            max_tip_seen: self.tip_meta().map_or(0, BtcMeta::max_tip_seen),
            now_unix_secs: self.now_unix_ms / 1_000,
        }
    }

    /// Why the selected imported key may not be removed now (an approval open, a transaction of
    /// its address that may still confirm: in flight, `Replaced`, or given up / refused inside
    /// the 30-day window, `BtcRecord::may_still_confirm`), `None` when it may (spec/04 §2.18).
    #[must_use]
    pub fn remove_block(&self, id: [u8; 16], slot: bool) -> Option<&'static str> {
        let account = BtcAccountId::Imported { id };
        let selected = self.selected_imported() == Some(id);
        if slot && selected {
            return Some(REMOVE_BUSY_APPROVAL);
        }
        let now_unix = self.now_unix_ms / 1_000;
        BtcNetwork::ALL
            .into_iter()
            .any(|net| {
                let own = of_account(self.all_records(), net, account);
                let related = self
                    .accounts_on(net)
                    .into_iter()
                    .find(|meta| meta.id() == account)
                    .map(|meta| self.related_of(meta))
                    .unwrap_or_default();
                own.iter()
                    .chain(&related)
                    .any(|record| record.may_still_confirm(now_unix))
            })
            .then_some(REMOVE_BUSY_IN_FLIGHT)
    }

    /// The records of `meta`'s network touching its account under any identity (spec/08 §12.1
    /// "같은 주소의 다른 계정": an imported key removed and imported again, an alias address);
    /// its own records when its scripts cannot be derived.
    pub(crate) fn related_of(&self, meta: &BtcMeta) -> Vec<BtcRecord> {
        let net = meta.network();
        let keys: Vec<BtcAccountKey> = self
            .accounts_on(net)
            .into_iter()
            .map(|account| *account.account())
            .collect();
        AccountScope::of(meta).map_or_else(
            |_| of_account(self.all_records(), net, meta.id()),
            |scope| related_records(self.all_records(), &scope, &keys),
        )
    }

    /// The records touching the selected account under any identity (the in-flight inputs and
    /// the abandon rule of a new send, spec/08 §12.1).
    #[must_use]
    pub fn related_records(&self) -> Vec<BtcRecord> {
        self.btc_meta()
            .map_or_else(|| self.records(), |meta| self.related_of(meta))
    }

    /// Records of the selected account on the settings network (D20 and every per-account rule,
    /// spec/08 §12.1).
    #[must_use]
    pub fn records(&self) -> Vec<BtcRecord> {
        of_account(self.all_records(), self.net(), self.active_id())
    }

    /// The record `txid` of the settings network (the current one: the last in journal order,
    /// yw-core `current_record`).
    #[must_use]
    pub fn record(&self, txid: &Txid) -> Option<BtcRecord> {
        current_record(self.all_records(), self.net(), txid).cloned()
    }

    /// Whether the selected account has an in-flight record (D20: per account).
    #[must_use]
    pub fn in_flight(&self) -> bool {
        in_flight(&self.records(), self.net())
    }

    /// Whether any account of the settings network has an in-flight record (tracking).
    #[must_use]
    pub fn network_in_flight(&self) -> bool {
        in_flight(self.all_records(), self.net())
    }

    /// Whether any network has an in-flight record (disable / network change refused).
    #[must_use]
    pub fn any_in_flight(&self) -> bool {
        BtcNetwork::ALL
            .into_iter()
            .any(|net| in_flight(self.all_records(), net))
    }

    /// The BTC journal has damaged entries (E-VLT-006: BTC sending stops).
    #[must_use]
    pub fn journal_damaged(&self) -> bool {
        self.journal.is_some_and(|journal| journal.btc_corrupt > 0)
    }
}

/// A screen of the BTC flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcScreen {
    /// S10 with the Bitcoin tab.
    Main,
    /// S11 for Bitcoin.
    Send,
    /// S11 result.
    SendResult,
    /// The fee-bump form (S10 `수수료 올리기`).
    Bump,
    /// S12 for Bitcoin.
    Receive,
    /// The screen under the confirmation overlay.
    Back,
}

/// What the App glue does for the controller.
#[derive(Debug)]
pub enum BtcAction {
    /// Queue a key worker job.
    Key(Box<KeyJob>),
    /// Send an RPC worker job.
    Rpc(Box<RpcJob>),
    /// Replace the meta mirror's `btc` and `btc_accounts` (the key worker persisted them).
    SetMeta(Option<Box<BtcMeta>>, Box<BtcAccounts>),
    /// Queue an approval item (A01).
    Enqueue(Box<BtcApprovalItem>),
    /// Write settings.json `bitcoin` (`key` = log name); a failed write stops the remaining
    /// actions of the batch (E-APP-002).
    SaveSettings(Box<BitcoinSettings>, &'static str),
    /// Show the confirmation overlay of [`BtcUi::confirm`].
    Confirm,
    /// Show a BTC screen.
    Screen(BtcScreen),
    /// A main-window banner.
    Banner(Option<ErrorCode>, String),
}

/// A queued BTC approval (spec/08 §10): the plan the form made, with its facts.
#[derive(Clone, Debug)]
pub struct BtcApprovalItem {
    /// Network.
    pub network: BtcNetwork,
    /// The plan (bound by the approval payload).
    pub plan: SendPlan,
    /// Approval facts.
    pub facts: BtcSendFacts,
    /// The spending account (address type and keys).
    pub account: BtcAccountKey,
    /// Core tip of the plan.
    pub tip_height: u32,
}

impl BtcApprovalItem {
    /// `bitcoin:<net>`.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        network_id(self.network)
    }

    /// Whether this is a fee bump.
    #[must_use]
    pub fn is_bump(&self) -> bool {
        self.plan.replaces().is_some()
    }
}

/// Fee-rate choice of the forms (spec/08 §8.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BtcFeeChoice {
    /// 빠름 (2 blocks).
    Fast,
    /// 보통 (6 blocks, default).
    #[default]
    Normal,
    /// 느림 (24 blocks).
    Slow,
    /// 직접 입력 (sat/vB).
    Manual,
}

impl BtcFeeChoice {
    /// The label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Fast => "빠름",
            Self::Normal => "보통",
            Self::Slow => "느림",
            Self::Manual => "직접 입력",
        }
    }

    const fn target(self) -> Option<u32> {
        let [fast, normal, slow] = BTC_CONF_TARGETS;
        match self {
            Self::Fast => Some(fast),
            Self::Normal => Some(normal),
            Self::Slow => Some(slow),
            Self::Manual => None,
        }
    }
}

/// Amount unit toggle (spec/08 §7.3).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BtcAmountUnit {
    /// BTC decimal.
    #[default]
    Btc,
    /// sats.
    Sats,
}

/// The fee part shared by the send and fee-bump forms.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BtcFeeForm {
    /// Choice.
    pub choice: BtcFeeChoice,
    /// Manual sat/vB text.
    pub manual_text: String,
    /// Parsed manual rate.
    pub manual: Option<FeeRate>,
    /// Fee error (format, below floor, no estimate).
    pub error: Option<String>,
    /// "수수료(sats)를 정확히 입력해 상한 해제" text.
    pub typed_text: String,
    /// Parsed typed fee.
    pub typed: Option<Sats>,
    /// The planned fee the cap override asks for (shown with the typed field).
    pub needs_typed: Option<Sats>,
}

impl BtcFeeForm {
    fn input(&self) -> Option<FeeInput> {
        match self.choice.target() {
            Some(target) => Some(FeeInput::Target(target)),
            None => self.manual.map(FeeInput::Manual),
        }
    }

    fn validate(&mut self) {
        self.error = None;
        if self.choice == BtcFeeChoice::Manual {
            self.manual = parse_user_sat_per_vb(self.manual_text.trim()).ok();
            if self.manual.is_none() {
                self.error = Some("수수료율 형식이 올바르지 않습니다(sat/vB).".to_owned());
            }
        }
        let typed = self.typed_text.trim();
        self.typed = if typed.is_empty() {
            None
        } else {
            parse_user_sats(typed).ok()
        };
        if !typed.is_empty() && self.typed.is_none() {
            self.error = Some("수수료(sats) 형식이 올바르지 않습니다.".to_owned());
        }
    }
}

/// S11 for Bitcoin (inputs survive rejection and expiry, spec/04 §2.7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BtcSendForm {
    /// Recipient text.
    pub to_text: String,
    /// Parsed recipient.
    pub recipient: Option<ScriptKind>,
    /// Recipient error (spec/08 §13 text).
    pub recipient_error: Option<String>,
    /// Amount text.
    pub amount_text: String,
    /// Unit.
    pub unit: BtcAmountUnit,
    /// Parsed amount.
    pub amount: Option<Sats>,
    /// Amount error.
    pub amount_error: Option<String>,
    /// `최대` (send-max).
    pub send_max: bool,
    /// Fee.
    pub fee: BtcFeeForm,
    /// Plan job in progress.
    pub preparing: Option<u64>,
    /// Message (plan errors, T-APPR-EXPIRED, signing failures).
    pub info: Option<String>,
    /// W-ADDR-3: the recipient looks like this known address (first 4 and last 4 characters
    /// after the prefix equal); the note text.
    pub look_alike: Option<String>,
    /// `주소 전체를 직접 확인했습니다` (needed for `검토` while `look_alike`).
    pub ack: bool,
}

/// The fee-bump form (spec/08 §9).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BtcBumpForm {
    /// The record being replaced (the current bump target).
    pub target: Option<Txid>,
    /// Fee.
    pub fee: BtcFeeForm,
    /// Plan job in progress.
    pub preparing: Option<u64>,
    /// Message.
    pub info: Option<String>,
}

/// The receive address (S12, spec/08 §3.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcReceiveView {
    /// Network.
    pub network: BtcNetwork,
    /// Receive index.
    pub index: u32,
    /// The address as encoded (bech32 lowercase, base58 case-sensitive).
    pub address: String,
    /// `m/{44|49|84|86}'/{coin}'/{account}'/0/{index}`, or `가져온 키`.
    pub path: String,
    /// The account name (`탭루트 계정 0`, `가져온 키 · 레거시`).
    pub account: String,
    /// The address type with its prefix (`탭루트 (bc1p…)`).
    pub kind: String,
    /// QR payload `bitcoin:` + lowercase address.
    pub qr: String,
    /// The network banner (§2 table).
    pub banner: &'static str,
    /// The account receives only at this one address (no `새 주소`).
    pub fixed: bool,
    /// The account has one key (an imported key or an EVM account's key: no index in the title).
    pub single_key: bool,
    /// The explanation under the address (fixed address, imported key, EVM key or HD).
    pub note: String,
}

/// Discovery progress (spec/08 §3.4).
#[derive(Clone, Debug)]
pub struct BtcDiscoveryState {
    /// Running.
    pub running: bool,
    /// "더 찾기".
    pub more: bool,
    /// Addresses checked.
    pub checked: u32,
    /// Failure / cancel text ("주소 검색 미완료" + [다시 시도]).
    pub error: Option<String>,
    /// Job.
    pub job: u64,
    /// The account being discovered (its result is applied to it).
    pub account: BtcAccountId,
    cancel: Option<Arc<AtomicBool>>,
}

impl Default for BtcDiscoveryState {
    fn default() -> Self {
        Self {
            running: false,
            more: false,
            checked: 0,
            error: None,
            job: 0,
            account: BtcAccountId::PRIMARY,
            cancel: None,
        }
    }
}

/// Where a signed transaction is in its send flow (spec/08 §11.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcFlowStage {
    /// `testmempoolaccept` running.
    Prechecking,
    /// The pre-check answer is being applied (Broadcasting / Rejected).
    Applying,
    /// `sendrawtransaction` running.
    Sending,
    /// Waiting for the user ([다시 시도] after a communication error).
    Waiting,
    /// Finished (see the note).
    Done,
}

/// The post-sign flow of one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcTxFlow {
    /// Network.
    pub network: BtcNetwork,
    /// Transaction.
    pub txid: Txid,
    /// Stage.
    pub stage: BtcFlowStage,
    /// Fixed note (rejection text, "전송했습니다", error).
    pub note: Option<String>,
    /// The last Core send was a communication failure (manual Esplora broadcast condition).
    pub comm_failure: bool,
    /// The pre-check failed to communicate: [다시 시도] (the record stays `Signed`).
    pub retry_precheck: bool,
    /// The chain check right before `sendrawtransaction` failed: nothing was sent, the record
    /// stays `Broadcasting` and [같은 바이트 다시 전송] retries (review fix).
    pub retry_send: bool,
    /// Job.
    pub job: u64,
}

/// A BTC confirmation overlay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BtcConfirm {
    /// Network change (no in-flight record; new `BtcMeta`, discovery).
    NetworkChange {
        /// The new network.
        to: BtcNetwork,
    },
    /// T-BTC-BB-OPTIN.
    IndexerOptIn {
        /// The Blockbook indexer.
        indexer: BtcIndexer,
    },
    /// 20 or more unused receive addresses ([이전 주소 사용] / [그래도 발급]).
    GapWarning {
        /// `unused_tail`.
        unused: u32,
    },
    /// [포기] of a `BroadcastUnknown` record.
    Abandon {
        /// Record.
        txid: Txid,
    },
    /// [취소] of a `Signed` record found at startup.
    CancelSigned {
        /// Record.
        txid: Txid,
        /// Its bytes were already handed to the RPC (journal flags bit7): the text says the
        /// transaction may still confirm and the next send reuses one of its inputs.
        disclosed: bool,
    },
    /// T-BTC-ESPLORA-BROADCAST.
    EsploraBroadcast {
        /// Record.
        txid: Txid,
    },
    /// "블록 높이 기록 초기화" after a `TipRegression` block (spec/08 §2 step 2).
    ResetTip,
    /// `계정 추가` with the key of an EVM account (T-BTC-EVM-SHARED, spec/08 §3.5).
    AddEvmShared {
        /// Address type.
        script_type: ScriptType,
        /// EVM account index.
        evm_index: u32,
    },
}

impl BtcConfirm {
    /// `(title, text, yes label)` of the overlay.
    #[must_use]
    pub fn texts(self) -> (&'static str, String, &'static str) {
        match self {
            Self::NetworkChange { to } => (
                "Bitcoin 네트워크 바꾸기",
                format!(
                    "Bitcoin 네트워크를 {}로 바꿉니다. 주소 인덱스·UTXO 캐시·동결·보낸 주소 기록을 새로 시작하고 주소를 다시 찾습니다. 다른 네트워크의 거래 기록은 보존합니다.",
                    to.display_name()
                ),
                "바꾸기",
            ),
            Self::IndexerOptIn { .. } => (
                "Blockbook 인덱서",
                "Blockbook 인덱서는 Bitcoin RPC 엔드포인트에 인덱서 기능이 켜져 있어야 합니다(QuickNode: 유료 BTC Blockbook 애드온, 알케미: UTXO API). 켜져 있지 않으면 Bitcoin 조회가 실패합니다(E-BTC-007). 계속할까요?".to_owned(),
                "계속",
            ),
            Self::GapWarning { .. } => (
                "새 주소",
                "미사용 주소가 20개를 넘으면 다른 지갑으로 복구할 때 이후 입금이 보이지 않을 수 있습니다".to_owned(),
                "그래도 발급",
            ),
            Self::Abandon { .. } => ("거래 포기", texts::ABANDON_CONFIRM.to_owned(), "포기"),
            Self::CancelSigned { disclosed: false, .. } => (
                "서명한 거래 취소",
                "서명했지만 보내지 않은 거래를 취소합니다. 이 거래는 전송하지 않습니다.".to_owned(),
                "취소하기",
            ),
            Self::CancelSigned { disclosed: true, .. } => (
                "서명한 거래 취소",
                texts::CANCEL_DISCLOSED_CONFIRM.to_owned(),
                "취소하기",
            ),
            Self::EsploraBroadcast { .. } => (
                "Esplora로 전송",
                "Bitcoin 노드(RPC)로 보낸 결과를 확인하지 못했습니다. 같은 서명 거래를 설정한 Esplora 서버로 보냅니다. 거래 내용은 어차피 네트워크에 공개되지만, 그 서버는 이 PC의 IP가 이 거래를 보냈다는 것을 알 수 있습니다. 보낼까요?".to_owned(),
                "보내기",
            ),
            Self::ResetTip => (
                "블록 높이 기록 초기화",
                RESET_TIP_TEXT.to_owned(),
                "초기화",
            ),
            Self::AddEvmShared {
                script_type,
                evm_index,
            } => (
                "EVM 계정과 같은 키로 Bitcoin 계정 만들기",
                format!(
                    "EVM 계정 {evm_index}의 키(m/44'/60'/0'/0/{evm_index})로 {} 주소 하나를 만듭니다. 받기와 잔돈은 늘 이 주소입니다. {T_BTC_EVM_SHARED} 그래도 만들까요?",
                    script_type.name()
                ),
                "같은 키로 만들기",
            ),
        }
    }

    /// The no-button label.
    #[must_use]
    pub const fn no_label(self) -> &'static str {
        match self {
            Self::GapWarning { .. } => "이전 주소 사용",
            _ => "취소",
        }
    }
}

/// One activity row of the Bitcoin tab (meta `activity` + journal records, spec/04 §2.6).
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent buttons of one activity row"
)]
pub struct BtcActivityView {
    /// Lowercase display-order txid.
    pub txid: String,
    /// Approval title.
    pub title: String,
    /// Recipient sats.
    pub amount: Option<Sats>,
    /// Recipient address.
    pub counterparty: String,
    /// Status text (`확인 대기` / `확정` + "(서버 기준)", …).
    pub status: String,
    /// Time (Unix ms).
    pub time_unix_ms: u64,
    /// Still in the journal.
    pub journal: bool,
    /// [수수료 올리기].
    pub can_bump: bool,
    /// [같은 바이트 다시 전송].
    pub can_rebroadcast: bool,
    /// [포기].
    pub can_abandon: bool,
    /// [Esplora로 전송].
    pub can_esplora: bool,
    /// [전송 계속] / [취소] of a `Signed` record.
    pub can_continue: bool,
    /// Flow note of this session.
    pub note: Option<String>,
}

/// One verified UTXO for the freeze list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent marks of one UTXO row"
)]
pub struct BtcUtxoView {
    /// Output.
    pub outpoint: OutPoint,
    /// Verified value.
    pub value: Sats,
    /// Confirmations (server based).
    pub confirmations: u32,
    /// Freeze reason.
    pub frozen: Option<FreezeReason>,
    /// Spent by an in-flight record.
    pub in_flight: bool,
    /// Our change.
    pub own: bool,
    /// The indexer's value differed ("서버 응답 불일치").
    pub hint_mismatch: bool,
    /// Core's `gettxout` did not confirm it in the last refresh ("인덱서만 확인").
    pub indexer_only: bool,
}

/// Periodic job state.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BtcJobState {
    /// Outstanding job id.
    pub job: u64,
    /// A job is running.
    pub busy: bool,
    /// Next automatic run (monotonic ms).
    pub next_ms: u64,
}

/// Bitcoin UI state (spec/04 §2.6–§2.11 for Bitcoin).
#[derive(Debug)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent display flags of one tab"
)]
pub struct BtcUi {
    /// Core tip (server based) of the last check.
    pub tip: Option<u32>,
    /// W-BTC-IDX-LAG difference.
    pub lag_warning: Option<u32>,
    /// The fee floor of the last plan.
    pub floor: Option<FeeRate>,
    /// Last refresh / tracking failure (fixed text).
    pub status_error: Option<String>,
    /// The session is blocked (E-RPC-006 / E-BTC-003 text).
    pub blocked: Option<String>,
    /// "미확정 입금 있음(미검증, 교체될 수 있음)".
    pub pending_incoming: bool,
    /// "검증 실패 UTXO n개".
    pub verify_failures: u32,
    /// Outputs whose indexer value differed from the verified one ("서버 응답 불일치").
    pub hint_mismatch: Vec<OutPoint>,
    /// Outputs of the last refresh that only the indexer vouched for (no `gettxout` answer).
    pub indexer_only: Vec<OutPoint>,
    /// The session is blocked because the Core tip is below `max_tip_seen - 6`: [블록 높이 기록
    /// 초기화] is offered.
    pub tip_regressed: bool,
    /// Small deposits frozen automatically by the last refresh.
    pub auto_frozen: u32,
    /// Refresh.
    pub refresh: BtcJobState,
    /// Tracking.
    pub track: BtcJobState,
    /// Discovery.
    pub discovery: BtcDiscoveryState,
    /// S11.
    pub send: BtcSendForm,
    /// Fee-bump form.
    pub bump: BtcBumpForm,
    /// S12.
    pub receive: Option<BtcReceiveView>,
    /// Receive message (gap refusal, errors).
    pub receive_message: Option<String>,
    /// Post-sign flows of this session.
    pub flows: Vec<BtcTxFlow>,
    /// Last signed transaction (S11 result).
    pub result: Option<Txid>,
    /// Open confirmation overlay.
    pub confirm: Option<BtcConfirm>,
    /// Esplora settings `테스트` messages per network.
    pub esplora_tests: Vec<(BtcNetwork, String, bool)>,
    /// Settings message (E-BTC-006, E-KEY-005, refusals).
    pub settings_message: Option<String>,
    /// `check_chain` step 3 passed in this session (a refresh or discovery succeeded).
    pub indexer_verified: bool,
    /// `getmempoolentry` usable (false after `-32601`).
    pub mempool_entry: bool,
    /// An approval is queued or being signed (one BTC approval at a time).
    pub slot: bool,
    /// The send form of the last signed send, restored when the pre-check rejects it.
    last_form: Option<BtcSendForm>,
    receive_pending: bool,
    /// The account of the running refresh (its result is applied to it).
    refresh_account: BtcAccountId,
    /// The account list message (switch refused, add failed).
    pub account_message: Option<String>,
    /// The add-account chooser is open (spec/04 BTC 계정 추가).
    pub add_account_open: bool,
    /// The key source chosen in the add-account chooser (default: the standard path).
    pub add_source: BtcAddSource,
    /// The EVM account of [`BtcAddSource::EvmShared`].
    pub add_evm_index: u32,
    /// The mnemonic of a standard-path account added now (`None`: the primary one; several
    /// mnemonics, spec/02 §8.6). EVM-key accounts are the primary mnemonic's only.
    pub add_mnemonic: Option<yw_core::vault::RecordId>,
    next_job: u64,
}

impl Default for BtcUi {
    fn default() -> Self {
        Self {
            tip: None,
            lag_warning: None,
            floor: None,
            status_error: None,
            blocked: None,
            pending_incoming: false,
            verify_failures: 0,
            hint_mismatch: Vec::new(),
            indexer_only: Vec::new(),
            tip_regressed: false,
            auto_frozen: 0,
            refresh: BtcJobState::default(),
            track: BtcJobState::default(),
            discovery: BtcDiscoveryState::default(),
            send: BtcSendForm::default(),
            bump: BtcBumpForm::default(),
            receive: None,
            receive_message: None,
            flows: Vec::new(),
            result: None,
            confirm: None,
            esplora_tests: Vec::new(),
            settings_message: None,
            indexer_verified: false,
            mempool_entry: true,
            slot: false,
            last_form: None,
            receive_pending: false,
            refresh_account: BtcAccountId::PRIMARY,
            account_message: None,
            add_account_open: false,
            add_source: BtcAddSource::Standard,
            add_evm_index: 0,
            add_mnemonic: None,
            next_job: 0,
        }
    }
}

fn btc_job(job: BtcRpcJob) -> BtcAction {
    BtcAction::Rpc(Box::new(RpcJob::Btc(Box::new(job))))
}

fn key_job(job: KeyJob) -> BtcAction {
    BtcAction::Key(Box::new(job))
}

fn with_settings(
    ctx: &BtcCtx<'_>,
    change: impl FnOnce(&mut BitcoinSettings),
    key: &'static str,
) -> BtcAction {
    let mut settings = ctx.settings.clone();
    change(&mut settings);
    BtcAction::SaveSettings(Box::new(settings), key)
}

/// The status text of a journal record (spec/08 §12.1–§12.2-4).
#[must_use]
pub fn record_status(record: &BtcRecord, tip_height: u32) -> String {
    match record.state {
        BtcTxState::Signed => "서명됨(전송 전)".to_owned(),
        BtcTxState::Broadcasting => "전송 중".to_owned(),
        BtcTxState::Submitted | BtcTxState::InMempool => format!("확인 대기 {SERVER_BASED}"),
        BtcTxState::BroadcastUnknown => "전송 결과 확인 필요".to_owned(),
        BtcTxState::Confirmed => confirmations_text(record.confirmations(tip_height)),
        BtcTxState::Rejected => "거부됨".to_owned(),
        BtcTxState::Replaced => "교체됨".to_owned(),
        BtcTxState::Conflicted => "충돌(다른 거래가 확정됨)".to_owned(),
        BtcTxState::Abandoned => "포기함".to_owned(),
    }
}

/// `확인 대기` / `확정` with "(서버 기준)" (spec/08 §12.2-4): one confirmation is final.
#[must_use]
pub fn confirmations_text(confirmations: u32) -> String {
    if confirmations >= BTC_FINAL_CONFIRMATIONS {
        format!("확정 {SERVER_BASED}")
    } else {
        format!("확인 대기 {SERVER_BASED}")
    }
}

/// "보내지 않았습니다" of a send stopped by the chain check.
pub const NOT_SENT: &str =
    "전송 직전 연결 검사에 실패해 보내지 않았습니다. [같은 바이트 다시 전송]으로 다시 시도하세요";

/// Known addresses of the settings network for W-ADDR-3: Bitcoin address book entries, the
/// recipients of earlier sends (`activity` counterparties) and this wallet's watched addresses
/// (spec/08 §3.3), with the name shown in the note.
fn known_addresses(ctx: &BtcCtx<'_>) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    if let Some(meta) = ctx.meta {
        for entry in &meta.address_book {
            let Some(object) = entry.as_object() else {
                continue;
            };
            if object.get("chain").and_then(yw_json::Value::as_str) != Some("btc") {
                continue;
            }
            if let (Some(address), Some(label)) = (
                object.get("address").and_then(yw_json::Value::as_str),
                object.get("label").and_then(yw_json::Value::as_str),
            ) {
                out.push((address.to_ascii_lowercase(), format!("주소록: {label}")));
            }
        }
        for entry in meta.activity_of(&network_id(ctx.net()).to_string()) {
            if !entry.counterparty.is_empty() {
                out.push((
                    entry.counterparty.to_ascii_lowercase(),
                    "이전에 보낸 주소".to_owned(),
                ));
            }
        }
    }
    if let Some(watch) = ctx.btc_meta().and_then(|meta| meta.watch_set().ok()) {
        for (chain, index, address) in watch {
            let name = match chain {
                BtcChain::Receive => format!("내 받기 주소 #{index}"),
                BtcChain::Change => format!("내 잔돈 주소 #{index}"),
            };
            out.push((address.as_str().to_ascii_lowercase(), name));
        }
    }
    out
}

/// The W-ADDR-3 note of `address` (spec/04 §2.15 row 7 for Bitcoin), `None` when it is not a
/// look-alike of a known address (or is exactly one).
fn look_alike_note(ctx: &BtcCtx<'_>, address: &str) -> Option<String> {
    let known = known_addresses(ctx);
    let lower = address.to_ascii_lowercase();
    if known.iter().any(|(known, _)| *known == lower) {
        return None;
    }
    known
        .iter()
        .find(|(known, _)| yw_core::btc::address::is_look_alike(known, &lower))
        .map(|(_, name)| {
            format!(
                "'{name}'과 앞 4자·끝 4자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다."
            )
        })
}

fn activity_status(status: &str) -> String {
    match status {
        "succeeded" => format!("확정 {SERVER_BASED}"),
        "rejected" => "거부됨".to_owned(),
        "replaced" => "교체됨".to_owned(),
        "conflicted" => "충돌(다른 거래가 확정됨)".to_owned(),
        "abandoned" => "포기함".to_owned(),
        _ => "종결".to_owned(),
    }
}

impl BtcUi {
    fn job(&mut self) -> u64 {
        self.next_job = self.next_job.saturating_add(1);
        self.next_job
    }

    fn flow_mut(&mut self, txid: &Txid) -> Option<&mut BtcTxFlow> {
        self.flows.iter_mut().find(|flow| flow.txid == *txid)
    }

    /// The flow of `txid`, if this session has one.
    #[must_use]
    pub fn flow(&self, txid: &Txid) -> Option<&BtcTxFlow> {
        self.flows.iter().find(|flow| flow.txid == *txid)
    }

    fn start_flow(&mut self, network: BtcNetwork, txid: Txid, stage: BtcFlowStage) -> u64 {
        let job = self.job();
        self.flows.retain(|flow| flow.txid != txid);
        self.flows.push(BtcTxFlow {
            network,
            txid,
            stage,
            note: None,
            comm_failure: false,
            retry_precheck: false,
            retry_send: false,
            job,
        });
        job
    }

    // ----- lifecycle --------------------------------------------------------------------------

    /// Forgets everything that needs the unlocked wallet (lock) and resets the worker's
    /// sessions (the next unlock runs `check_chain` steps 1–4 again).
    pub fn lock(&mut self) -> Vec<BtcAction> {
        if let Some(cancel) = self.discovery.cancel.take() {
            cancel.store(true, Ordering::Relaxed);
        }
        let esplora_tests = core::mem::take(&mut self.esplora_tests);
        let next_job = self.next_job;
        *self = Self {
            esplora_tests,
            next_job,
            ..Self::default()
        };
        vec![btc_job(BtcRpcJob::Reset)]
    }

    /// Meta was loaded after unlock: BTC enabled with `btc == null` (meta reset, alt-passphrase
    /// session) creates a fresh `BtcMeta` and runs discovery (spec/08 §2). A key-only wallet has
    /// no BIP84 account 0 to create: its imported keys are its accounts.
    pub fn after_meta(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        if !ctx.settings.enabled || !ctx.unlocked || ctx.meta.is_none() || !ctx.has_mnemonic {
            return Vec::new();
        }
        if ctx.primary_meta().is_none() {
            if ctx.core_url(ctx.net()).is_none() {
                self.status_error = Some(ErrorCode::Key005.text());
                return Vec::new();
            }
            return vec![key_job(KeyJob::BtcMeta {
                op: BtcMetaOp::Create { network: ctx.net() },
            })];
        }
        if let Some((meta, _)) = ctx.mismatch() {
            self.blocked = Some(texts::NETWORK_MISMATCH.to_owned());
            logging::warn(
                "app",
                "btc.network_mismatch",
                &[("net", Field::Net(network_id(meta)))],
            );
        }
        Vec::new()
    }

    /// The journal view changed: start tracking soon when something is tracked.
    pub fn journal_changed(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        if !self.track.busy && !self.tracked(ctx).is_empty() && self.track.next_ms == 0 {
            self.track.next_ms = ctx.now_ms;
        }
        Vec::new()
    }

    /// The records to track now (yw-core `track_mode`), each with its in-flight replacements
    /// (yw-core `in_flight_replacements`, the Core check before a `Confirmed`, spec/08 §12.2).
    #[must_use]
    pub fn tracked(&self, ctx: &BtcCtx<'_>) -> Vec<TrackItem> {
        // Every account of the network: a record keeps being tracked when another account is
        // selected.
        let records = ctx.network_records();
        let tip = self.tip_or_meta(ctx);
        let now_unix = ctx.now_unix_ms / 1_000;
        records
            .iter()
            .filter_map(|record| {
                let indexer_only = match track_mode(record, &records, tip, now_unix) {
                    TrackMode::Full => false,
                    TrackMode::ConfirmationOnly => true,
                    TrackMode::None => return None,
                };
                Some(TrackItem {
                    txid: record.txid,
                    indexer_only,
                    replacements: in_flight_replacements(&records, record.network, &record.txid),
                })
            })
            .collect()
    }

    fn tip_or_meta(&self, ctx: &BtcCtx<'_>) -> u32 {
        self.tip
            .or_else(|| ctx.tip_meta().map(BtcMeta::max_tip_seen))
            .unwrap_or(0)
    }

    /// The 60 s cycle (spec/08 §4.7, §12.2): tracking of tracked records and a refresh while a
    /// transaction is in flight. Only unlocked and usable; the worker skips these automatic jobs
    /// during the 429 cooldown.
    pub fn tick(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        if ctx.gate().is_err() {
            return Vec::new();
        }
        let mut actions = Vec::new();
        if !self.track.busy && ctx.now_ms >= self.track.next_ms {
            self.track.next_ms = ctx.now_ms.saturating_add(BTC_TICK_MS);
            actions.extend(self.track_now(ctx, Trigger::Automatic));
        }
        if ctx.in_flight()
            && !self.refresh.busy
            && !self.discovery.running
            && ctx.now_ms >= self.refresh.next_ms
        {
            actions.extend(self.refresh(ctx, Trigger::Automatic));
        }
        actions
    }

    fn track_now(&mut self, ctx: &BtcCtx<'_>, trigger: Trigger) -> Vec<BtcAction> {
        let items = self.tracked(ctx);
        if items.is_empty() {
            return Vec::new();
        }
        let Ok(target) = ctx.target() else {
            return Vec::new();
        };
        let job = self.job();
        self.track.job = job;
        self.track.busy = true;
        vec![btc_job(BtcRpcJob::Track {
            job,
            target,
            items,
            mempool_entry: self.mempool_entry,
            trigger,
            chain: ctx.chain_input(),
        })]
    }

    // ----- settings ---------------------------------------------------------------------------

    /// BTC 켜기 with `network` (spec/08 §2): needs the `bitcoin:<net>` endpoint (E-KEY-005).
    /// Writes settings, then creates `BtcMeta` (discovery follows) unless the kept meta is of
    /// the same network.
    pub fn enable(&mut self, ctx: &BtcCtx<'_>, network: BtcNetwork) -> Vec<BtcAction> {
        self.settings_message = None;
        if ctx.core_url(network).is_none() {
            self.settings_message = Some(ErrorCode::Key005.text());
            return Vec::new();
        }
        // A key-only wallet keeps its imported accounts on both networks: only a network change
        // matters (nothing to create).
        let keep = if ctx.has_mnemonic {
            ctx.primary_meta()
                .is_some_and(|meta| meta.network() == network)
        } else {
            network == ctx.net()
        };
        if !keep && ctx.any_in_flight() {
            self.settings_message = Some(texts::IN_FLIGHT.to_owned());
            return Vec::new();
        }
        let mut actions = vec![
            with_settings(
                ctx,
                |settings| {
                    settings.enabled = true;
                    settings.network = app_network(network);
                },
                "bitcoin.enabled",
            ),
            btc_job(BtcRpcJob::Reset),
        ];
        if !ctx.unlocked {
            return actions;
        }
        if keep {
            if ctx.btc_meta().is_some_and(|meta| !meta.discovery_done()) {
                self.discovery.error = Some(DISCOVERY_INCOMPLETE.to_owned());
            }
        } else if ctx.has_mnemonic {
            actions.push(key_job(KeyJob::BtcMeta {
                op: BtcMetaOp::Create { network },
            }));
        }
        actions
    }

    /// BTC 끄기 (spec/08 §2): only without an in-flight record; meta `btc` is kept.
    pub fn disable(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        if ctx.any_in_flight() {
            self.settings_message = Some("진행 중인 Bitcoin 거래가 있어 끌 수 없습니다".to_owned());
            return Vec::new();
        }
        let mut actions = self.lock();
        actions.insert(
            0,
            with_settings(ctx, |settings| settings.enabled = false, "bitcoin.enabled"),
        );
        actions
    }

    /// 네트워크 선택: asks for confirmation (no in-flight record, spec/08 §2 네트워크 바꾸기).
    pub fn choose_network(&mut self, ctx: &BtcCtx<'_>, network: BtcNetwork) -> Vec<BtcAction> {
        self.settings_message = None;
        if network == ctx.net() && ctx.mismatch().is_none() {
            return Vec::new();
        }
        if ctx.any_in_flight() {
            self.settings_message = Some(texts::IN_FLIGHT.to_owned());
            return Vec::new();
        }
        if ctx.core_url(network).is_none() {
            self.settings_message = Some(ErrorCode::Key005.text());
            return Vec::new();
        }
        self.confirm = Some(BtcConfirm::NetworkChange { to: network });
        vec![BtcAction::Confirm]
    }

    /// [설정을 {`BtcMeta` 값}으로 되돌리기] (spec/08 §2 불일치).
    pub fn mismatch_keep_meta(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        let Some((meta, _)) = ctx.mismatch() else {
            return Vec::new();
        };
        self.blocked = None;
        vec![
            with_settings(
                ctx,
                |settings| settings.network = app_network(meta),
                "bitcoin.network",
            ),
            btc_job(BtcRpcJob::Reset),
        ]
    }

    /// [{settings 값}으로 바꾸기]: the network change procedure for the settings value.
    pub fn mismatch_use_settings(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        if ctx.mismatch().is_none() {
            return Vec::new();
        }
        self.choose_network(ctx, ctx.net())
    }

    /// Indexer radio (spec/04 §2.11): `bb-*` needs the T-BTC-BB-OPTIN confirmation first.
    pub fn set_indexer(
        &mut self,
        ctx: &BtcCtx<'_>,
        indexer: BtcIndexer,
        opt_in_confirmed: bool,
    ) -> Vec<BtcAction> {
        if indexer == ctx.settings.indexer {
            return Vec::new();
        }
        if indexer != BtcIndexer::Esplora && !opt_in_confirmed {
            self.confirm = Some(BtcConfirm::IndexerOptIn { indexer });
            return vec![BtcAction::Confirm];
        }
        self.indexer_verified = false;
        self.blocked = None;
        vec![
            with_settings(
                ctx,
                |settings| settings.indexer = indexer,
                "bitcoin.indexer",
            ),
            btc_job(BtcRpcJob::Reset),
        ]
    }

    fn esplora_saved(
        &mut self,
        ctx: &BtcCtx<'_>,
        net: BtcNetwork,
        value: String,
    ) -> Vec<BtcAction> {
        self.indexer_verified = false;
        self.blocked = None;
        self.settings_message = None;
        logging::info(
            "app",
            "btc.esplora_url_set",
            &[("net", Field::Net(network_id(net)))],
        );
        vec![
            with_settings(
                ctx,
                move |settings| match net {
                    BtcNetwork::Mainnet => settings.esplora_mainnet = value,
                    BtcNetwork::Testnet4 => settings.esplora_testnet4 = value,
                },
                "bitcoin.esploraBaseUrl",
            ),
            btc_job(BtcRpcJob::Reset),
        ]
    }

    /// Esplora URL `저장` (spec/04 §2.11, §6.1 `EsploraBaseUrl`, E-BTC-006).
    pub fn save_esplora_url(
        &mut self,
        ctx: &BtcCtx<'_>,
        net: BtcNetwork,
        text: &str,
    ) -> Vec<BtcAction> {
        if let Some(value) = validate_esplora_url(text.trim()) {
            self.esplora_saved(ctx, net, value)
        } else {
            self.settings_message = Some(ErrorCode::Btc006.text());
            Vec::new()
        }
    }

    /// Esplora URL `기본값으로`.
    pub fn default_esplora_url(&mut self, ctx: &BtcCtx<'_>, net: BtcNetwork) -> Vec<BtcAction> {
        self.esplora_saved(ctx, net, net.esplora_default().to_owned())
    }

    /// Esplora URL `테스트`: the EDIT value (or the saved one) once, `GET /block-height/0`
    /// (allowed while locked: no address is sent, spec/08 §4.4).
    pub fn test_esplora_url(
        &mut self,
        ctx: &BtcCtx<'_>,
        net: BtcNetwork,
        text: &str,
    ) -> Vec<BtcAction> {
        let typed = text.trim();
        let candidate = if typed.is_empty() {
            ctx.esplora_text(net)
        } else {
            typed
        };
        let base = validate_esplora_url(candidate).and_then(|value| HttpsUrl::parse(&value).ok());
        let Some(base) = base else {
            self.set_esplora_test(net, ErrorCode::Btc006.text(), false);
            return Vec::new();
        };
        self.set_esplora_test(net, "테스트 중…".to_owned(), false);
        vec![btc_job(BtcRpcJob::EsploraTest { net, base })]
    }

    fn set_esplora_test(&mut self, net: BtcNetwork, message: String, ok: bool) {
        self.esplora_tests.retain(|(known, ..)| *known != net);
        self.esplora_tests.push((net, message, ok));
    }

    /// The Core URL of a network changed (`네트워크 URL`): reset the sessions.
    pub fn url_changed(&mut self) -> Vec<BtcAction> {
        self.indexer_verified = false;
        self.blocked = None;
        vec![btc_job(BtcRpcJob::Reset)]
    }

    /// The overlay's yes button.
    pub fn confirm_yes(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        let Some(confirm) = self.confirm.take() else {
            return vec![BtcAction::Screen(BtcScreen::Back)];
        };
        match confirm {
            BtcConfirm::NetworkChange { to } => {
                if ctx.any_in_flight() {
                    self.settings_message = Some(texts::IN_FLIGHT.to_owned());
                    return vec![BtcAction::Screen(BtcScreen::Back)];
                }
                let mut actions = self.lock();
                actions.insert(
                    0,
                    with_settings(
                        ctx,
                        |settings| settings.network = app_network(to),
                        "bitcoin.network",
                    ),
                );
                if ctx.unlocked && ctx.has_mnemonic {
                    actions.push(key_job(KeyJob::BtcMeta {
                        op: BtcMetaOp::Create { network: to },
                    }));
                }
                actions.push(BtcAction::Screen(BtcScreen::Back));
                actions
            }
            BtcConfirm::IndexerOptIn { indexer } => {
                let mut actions = self.set_indexer(ctx, indexer, true);
                actions.push(BtcAction::Screen(BtcScreen::Back));
                actions
            }
            BtcConfirm::GapWarning { .. } => {
                let mut actions = self.request_receive(ctx, true, true);
                actions.push(BtcAction::Screen(BtcScreen::Receive));
                actions
            }
            BtcConfirm::Abandon { txid } if !Self::abandon_allowed(ctx, &txid) => {
                // Tracking found it meanwhile (or the record changed): nothing to give up.
                vec![BtcAction::Screen(BtcScreen::Back)]
            }
            BtcConfirm::Abandon { txid } | BtcConfirm::CancelSigned { txid, .. } => vec![
                key_job(KeyJob::BtcJournal {
                    op: BtcJournalOp::Abandon {
                        network: ctx.net(),
                        txid,
                    },
                    now_unix_ms: ctx.now_unix_ms,
                }),
                BtcAction::Screen(BtcScreen::Back),
            ],
            BtcConfirm::EsploraBroadcast { txid } => {
                let mut actions = self.esplora_post(ctx, txid);
                actions.push(BtcAction::Screen(BtcScreen::Back));
                actions
            }
            BtcConfirm::ResetTip => {
                let mut actions = Vec::new();
                if ctx.unlocked && ctx.btc_meta().is_some() && ctx.mismatch().is_none() {
                    actions.push(key_job(KeyJob::BtcMeta {
                        op: BtcMetaOp::ResetTip { network: ctx.net() },
                    }));
                }
                actions.push(BtcAction::Screen(BtcScreen::Back));
                actions
            }
            BtcConfirm::AddEvmShared {
                script_type,
                evm_index,
            } => {
                let mut actions = Vec::new();
                if self.add_refused(ctx) {
                    actions.push(BtcAction::Screen(BtcScreen::Back));
                    return actions;
                }
                actions.push(key_job(KeyJob::BtcMeta {
                    op: BtcMetaOp::AddEvmShared {
                        network: ctx.net(),
                        script_type,
                        evm_index,
                    },
                }));
                actions.push(BtcAction::Screen(BtcScreen::Back));
                actions
            }
        }
    }

    /// [블록 높이 기록 초기화] (offered while the session is blocked by a tip regression).
    pub fn reset_tip(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        if !self.tip_regressed || !ctx.unlocked || ctx.btc_meta().is_none() {
            return Vec::new();
        }
        self.confirm = Some(BtcConfirm::ResetTip);
        vec![BtcAction::Confirm]
    }

    /// The overlay's no button.
    pub fn confirm_no(&mut self) -> Vec<BtcAction> {
        let screen = match self.confirm.take() {
            Some(BtcConfirm::GapWarning { .. }) => BtcScreen::Receive,
            _ => BtcScreen::Back,
        };
        vec![BtcAction::Screen(screen)]
    }

    // ----- tab, refresh, discovery ------------------------------------------------------------

    /// The Bitcoin tab was opened (spec/08 §4.7: refresh on open).
    pub fn open_tab(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        if ctx.gate().is_err() || self.discovery.running {
            return Vec::new();
        }
        let mut actions = Vec::new();
        if ctx.btc_meta().is_some_and(BtcMeta::discovery_done) {
            actions.extend(self.refresh(ctx, Trigger::User));
        } else if self.discovery.error.is_none() {
            self.discovery.error = Some(DISCOVERY_INCOMPLETE.to_owned());
        }
        self.track.next_ms = ctx.now_ms;
        actions
    }

    /// `새로고침` (user) or the automatic cycle.
    pub fn refresh(&mut self, ctx: &BtcCtx<'_>, trigger: Trigger) -> Vec<BtcAction> {
        if ctx.gate().is_err() || self.refresh.busy {
            return Vec::new();
        }
        let Some(meta) = ctx.btc_meta().cloned() else {
            return Vec::new();
        };
        self.refresh_with(ctx, &meta, trigger)
    }

    /// Discovery (spec/08 §3.4) of the selected account: full (also [다시 시도]) or "더 찾기"
    /// (`more`). An imported key has one address and no discovery.
    pub fn discover(&mut self, ctx: &BtcCtx<'_>, more: bool) -> Vec<BtcAction> {
        if ctx.gate().is_err() || self.discovery.running {
            return Vec::new();
        }
        let Some(meta) = ctx.btc_meta().cloned() else {
            return Vec::new();
        };
        if meta.is_single() {
            return Vec::new();
        }
        self.discover_with(ctx, &meta, more)
    }

    /// Cancels the running discovery (`discovery_done` stays false).
    pub fn cancel_discovery(&mut self) {
        if let Some(cancel) = self.discovery.cancel.as_ref() {
            cancel.store(true, Ordering::Relaxed);
        }
    }

    // ----- receive ----------------------------------------------------------------------------

    fn request_receive(
        &mut self,
        ctx: &BtcCtx<'_>,
        new: bool,
        gap_confirmed: bool,
    ) -> Vec<BtcAction> {
        self.receive_message = None;
        if let Err(gate) = ctx.gate() {
            self.receive_message = Some(gate.text());
            return Vec::new();
        }
        self.receive_pending = true;
        let network = ctx.net();
        let account = ctx.active_id();
        let op = if new {
            BtcMetaOp::NewReceiveAddress {
                network,
                account,
                gap_confirmed,
            }
        } else {
            BtcMetaOp::ReceiveAddress { network, account }
        };
        vec![key_job(KeyJob::BtcMeta { op })]
    }

    /// Opens S12: the key worker returns the address index after storing any newly issued
    /// `receive_next` (the address is shown only then, spec/08 §3.2).
    pub fn open_receive(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        self.receive = None;
        self.request_receive(ctx, false, false)
    }

    /// "새 주소" (spec/08 §3.2): the gap warning asks first; 100 unused are refused.
    pub fn new_receive_address(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        self.request_receive(ctx, true, false)
    }

    /// The S12 view of `meta`'s receive address `index` (address, path, mode and explanation).
    #[must_use]
    pub fn receive_view(meta: &BtcMeta, index: u32) -> Option<BtcReceiveView> {
        let address = meta.address(BtcChain::Receive, index).ok()?;
        let network = meta.network();
        // Exactly as encoded: bech32 is lowercase already, base58 is case-sensitive.
        let text = address.as_str().to_owned();
        let account = meta.account();
        let path = account.path_text(network, BtcChain::Receive, index);
        let note = match account {
            BtcAccountKey::Single { .. } => {
                "가져온 키 계정은 주소가 하나입니다. 주소를 복사한 뒤 붙여넣은 곳에서 주소 전체를 확인하세요."
                    .to_owned()
            }
            BtcAccountKey::Hardware { .. } => {
                "YubiKey 계정은 주소가 하나입니다. 주소를 복사한 뒤 붙여넣은 곳에서 주소 전체를 확인하세요."
                    .to_owned()
            }
            BtcAccountKey::EvmShared { evm_index, .. } => format!(
                "이 계정은 주소 하나만 씁니다. EVM 계정 {evm_index}과 같은 키({path})입니다. {T_BTC_EVM_SHARED}"
            ),
            BtcAccountKey::Hd { .. } if account.fixed_address() => {
                "받은 돈과 보내고 남은 잔돈이 모두 이 주소로 옵니다(새 주소 없음). 받을 때마다 새 주소를 쓰려면 Bitcoin 탭의 계정 목록 아래 '주소 방식'에서 바꾸세요. 주소를 복사한 뒤 붙여넣은 곳에서 주소 전체를 확인하세요."
                    .to_owned()
            }
            BtcAccountKey::Hd { .. } => {
                "주소를 복사한 뒤 붙여넣은 곳에서 주소 전체를 확인하세요. 새 주소는 아직 쓰지 않은 주소가 20개 이상이면 경고하고 100개면 발급하지 않습니다."
                    .to_owned()
            }
        };
        Some(BtcReceiveView {
            network,
            index,
            path,
            account: account_label(account),
            kind: account_type_text(account, network),
            qr: format!("bitcoin:{text}"),
            address: text,
            banner: network.banner(),
            fixed: account.fixed_address(),
            single_key: account.is_single(),
            note,
        })
    }

    // ----- send form --------------------------------------------------------------------------

    /// Why sending is not possible now (fixed text), `None` when it is.
    #[must_use]
    pub fn send_block(&self, ctx: &BtcCtx<'_>) -> Option<String> {
        if let Err(gate) = ctx.gate() {
            return Some(gate.text());
        }
        if ctx.journal_damaged() {
            return Some("거래 저널이 손상되어 보내기를 멈췄습니다. (E-VLT-006)".to_owned());
        }
        if !ctx.btc_meta().is_some_and(BtcMeta::discovery_done) {
            return Some(DISCOVERY_INCOMPLETE.to_owned());
        }
        if let Err(error) = check_can_send(&ctx.records(), ctx.net()) {
            return Some(error.to_string());
        }
        if self.slot {
            return Some("다른 Bitcoin 승인이 진행 중입니다".to_owned());
        }
        None
    }

    /// Opens S11 for Bitcoin.
    pub fn open_send(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        self.send.info = self.send_block(ctx);
        vec![BtcAction::Screen(BtcScreen::Send)]
    }

    /// Validates the form (local checks; the plan job does the rest).
    pub fn validate(&mut self, ctx: &BtcCtx<'_>) {
        let net = ctx.net();
        let previous = self.send.recipient;
        let form = &mut self.send;
        let to = form.to_text.trim();
        if to.is_empty() {
            form.recipient = None;
            form.recipient_error = None;
        } else {
            match parse_address(to, net) {
                Ok(kind) => {
                    form.recipient = Some(kind);
                    form.recipient_error = None;
                }
                Err(error) => {
                    form.recipient = None;
                    form.recipient_error = Some(error.text(net).to_owned());
                }
            }
        }
        if form.recipient != previous {
            form.ack = false;
            form.look_alike = form
                .recipient
                .and_then(|kind| look_alike_note(ctx, &encode_address(&kind, net)));
        }
        let amount = form.amount_text.trim();
        if form.send_max || amount.is_empty() {
            form.amount = None;
            form.amount_error = None;
        } else {
            let parsed = match form.unit {
                BtcAmountUnit::Btc => parse_user_btc(amount),
                BtcAmountUnit::Sats => parse_user_sats(amount),
            };
            match parsed {
                Ok(value) if value.get() > 0 => {
                    form.amount = Some(value);
                    form.amount_error = None;
                }
                Ok(_) | Err(_) => {
                    form.amount = None;
                    form.amount_error = Some(ErrorCode::Inp011.text());
                }
            }
        }
        form.fee.validate();
    }

    /// Sets the recipient text.
    pub fn set_recipient(&mut self, ctx: &BtcCtx<'_>, text: &str) {
        text.clone_into(&mut self.send.to_text);
        self.send.fee.needs_typed = None;
        self.validate(ctx);
    }

    /// Sets the amount text.
    pub fn set_amount(&mut self, ctx: &BtcCtx<'_>, text: &str) {
        text.clone_into(&mut self.send.amount_text);
        self.send.fee.needs_typed = None;
        self.validate(ctx);
    }

    /// BTC | sats toggle (the text is converted when it parses).
    pub fn set_unit(&mut self, ctx: &BtcCtx<'_>, unit: BtcAmountUnit) {
        if self.send.unit == unit {
            return;
        }
        if let Some(amount) = self.send.amount {
            self.send.amount_text = match unit {
                BtcAmountUnit::Btc => yw_core::btc::amount::format_btc(amount),
                BtcAmountUnit::Sats => amount.get().to_string(),
            };
        }
        self.send.unit = unit;
        self.validate(ctx);
    }

    /// `최대` (send-max).
    pub fn toggle_send_max(&mut self, ctx: &BtcCtx<'_>) {
        self.send.send_max = !self.send.send_max;
        if self.send.send_max {
            self.send.amount_text.clear();
        }
        self.send.fee.needs_typed = None;
        self.validate(ctx);
    }

    /// Fee choice of the send form (`bump = true`: the fee-bump form).
    pub fn set_fee_choice(&mut self, ctx: &BtcCtx<'_>, choice: BtcFeeChoice, bump: bool) {
        let fee = if bump {
            &mut self.bump.fee
        } else {
            &mut self.send.fee
        };
        fee.choice = choice;
        fee.needs_typed = None;
        fee.validate();
        if !bump {
            self.validate(ctx);
        }
    }

    /// Manual sat/vB text.
    pub fn set_manual_rate(&mut self, text: &str, bump: bool) {
        let fee = if bump {
            &mut self.bump.fee
        } else {
            &mut self.send.fee
        };
        text.clone_into(&mut fee.manual_text);
        fee.needs_typed = None;
        fee.validate();
    }

    /// The exact fee typed to lift the cap.
    pub fn set_typed_fee(&mut self, text: &str, bump: bool) {
        let fee = if bump {
            &mut self.bump.fee
        } else {
            &mut self.send.fee
        };
        text.clone_into(&mut fee.typed_text);
        fee.validate();
    }

    /// Whether `검토` is enabled.
    #[must_use]
    pub fn can_review(&self, ctx: &BtcCtx<'_>) -> bool {
        let form = &self.send;
        self.send_block(ctx).is_none()
            && form.preparing.is_none()
            && form.recipient.is_some()
            && form.recipient_error.is_none()
            && (form.send_max || (form.amount.is_some() && form.amount_error.is_none()))
            && form.fee.error.is_none()
            && form.fee.input().is_some()
            && (form.look_alike.is_none() || form.ack)
    }

    /// `주소 전체를 직접 확인했습니다` (W-ADDR-3).
    pub fn toggle_address_ack(&mut self) {
        self.send.ack = !self.send.ack;
    }

    fn prepare_job(
        &mut self,
        ctx: &BtcCtx<'_>,
        kind: PrepareKind,
        fee: &BtcFeeForm,
        layout_seed: [u8; 32],
    ) -> Option<(u64, BtcAction)> {
        let meta = ctx.btc_meta()?.clone();
        let target = ctx.target().ok()?;
        let fee_input = fee.input()?;
        let job = self.job();
        // Across identities: a re-imported key inherits the old identity's constraints.
        let related = ctx.related_records();
        let work = PrepareJob {
            in_flight: in_flight_outpoints(&related, ctx.net()),
            conflicts: abandoned_conflicts(&related, ctx.net(), ctx.now_unix_ms / 1_000),
            meta,
            kind,
            fee: fee_input,
            typed_fee_override: fee.typed,
            layout_seed,
            chain: ctx.chain_input(),
        };
        Some((
            job,
            btc_job(BtcRpcJob::Prepare {
                job,
                target,
                work: Box::new(work),
            }),
        ))
    }

    /// `검토`: plans on the RPC worker (fresh chain check, fee, `plan_send`); a ready plan is
    /// queued for A01, errors stay in the form (spec/08 §10).
    pub fn review(&mut self, ctx: &BtcCtx<'_>, layout_seed: [u8; 32]) -> Vec<BtcAction> {
        self.validate(ctx);
        if !self.can_review(ctx) {
            if self.send.info.is_none() {
                self.send.info = self.send_block(ctx);
            }
            return Vec::new();
        }
        let Some(recipient) = self.send.recipient else {
            return Vec::new();
        };
        let amount = if self.send.send_max {
            SendAmount::Max
        } else {
            match self.send.amount {
                Some(amount) => SendAmount::Exact(amount),
                None => return Vec::new(),
            }
        };
        let fee = self.send.fee.clone();
        match self.prepare_job(
            ctx,
            PrepareKind::Send { recipient, amount },
            &fee,
            layout_seed,
        ) {
            Some((job, action)) => {
                self.send.preparing = Some(job);
                self.send.info = Some("수수료를 계산하는 중…".to_owned());
                vec![action]
            }
            None => Vec::new(),
        }
    }

    /// The record a fee bump replaces now (spec/08 §9: always the latest), with its source.
    #[must_use]
    pub fn bump_target(ctx: &BtcCtx<'_>) -> Option<BtcRecord> {
        bump_target(&ctx.records(), ctx.net()).cloned()
    }

    /// Opens the fee-bump form for the current bump target (D20 allows it while in flight).
    pub fn open_bump(&mut self, ctx: &BtcCtx<'_>) -> Vec<BtcAction> {
        let target = Self::bump_target(ctx).map(|record| record.txid);
        self.bump = BtcBumpForm {
            target,
            info: if target.is_none() {
                Some(texts::NOT_BUMPABLE.to_owned())
            } else {
                ctx.gate().err().map(BtcGate::text)
            },
            ..BtcBumpForm::default()
        };
        vec![BtcAction::Screen(BtcScreen::Bump)]
    }

    /// The fee-bump form's `검토`.
    pub fn review_bump(&mut self, ctx: &BtcCtx<'_>, layout_seed: [u8; 32]) -> Vec<BtcAction> {
        self.bump.fee.validate();
        if let Err(gate) = ctx.gate() {
            self.bump.info = Some(gate.text());
            return Vec::new();
        }
        if ctx.journal_damaged() || self.slot || self.bump.preparing.is_some() {
            return Vec::new();
        }
        let (Some(record), Some(meta)) = (Self::bump_target(ctx), ctx.btc_meta()) else {
            self.bump.info = Some(texts::NOT_BUMPABLE.to_owned());
            return Vec::new();
        };
        if self.bump.target != Some(record.txid) {
            self.bump.target = Some(record.txid);
        }
        let Some(source) = record.bump_source(meta.account()) else {
            self.bump.info = Some(texts::NOT_BUMPABLE.to_owned());
            return Vec::new();
        };
        if self.bump.fee.error.is_some() {
            return Vec::new();
        }
        let fee = self.bump.fee.clone();
        match self.prepare_job(
            ctx,
            PrepareKind::Bump {
                source: Box::new(source),
            },
            &fee,
            layout_seed,
        ) {
            Some((job, action)) => {
                self.bump.preparing = Some(job);
                self.bump.info = Some("수수료를 계산하는 중…".to_owned());
                vec![action]
            }
            None => Vec::new(),
        }
    }

    // ----- approval ---------------------------------------------------------------------------

    /// The approval draft of a queued item (A01 "prepare": `build_btc_request`).
    ///
    /// # Errors
    ///
    /// E-APP-009 when the draft cannot be built.
    pub fn draft(item: &BtcApprovalItem, id: ApprovalId) -> Result<ApprovalDraft, ErrorCode> {
        build_btc_request(id, &item.plan, &item.account, &item.facts).map_err(|_| ErrorCode::App009)
    }

    /// An approval ended (any outcome; inputs are kept, spec/04 §3.1).
    pub fn approval_finished(&mut self, item: &BtcApprovalItem, outcome: QueueOutcome) {
        if outcome != QueueOutcome::Approved {
            self.slot = false;
        }
        if outcome == QueueOutcome::Expired {
            if item.is_bump() {
                self.bump.info = Some(APPROVAL_EXPIRED.to_owned());
            } else {
                self.send.info = Some(APPROVAL_EXPIRED.to_owned());
            }
        }
    }

    /// `consume` succeeded: sign on the key worker (spec/08 §11.1).
    pub fn consumed(
        &mut self,
        ctx: &BtcCtx<'_>,
        approved: Approved,
        item: &BtcApprovalItem,
    ) -> Vec<BtcAction> {
        self.slot = true;
        vec![key_job(KeyJob::SignBtc {
            approved: Box::new(approved),
            plan: Box::new(item.plan.clone()),
            tip_height: item.tip_height,
            now_unix_ms: ctx.now_unix_ms,
        })]
    }

    /// A consumed approval ended without a signature because of the lock.
    pub fn sign_cancelled(&mut self) {
        self.slot = false;
        logging::info(
            "app",
            "btc.sign_aborted",
            &[("reason", Field::Word("locked"))],
        );
    }

    // ----- post-sign --------------------------------------------------------------------------

    fn precheck(
        &mut self,
        ctx: &BtcCtx<'_>,
        network: BtcNetwork,
        tx: SignedTxRef,
    ) -> Vec<BtcAction> {
        let txid = tx.txid;
        // The journal must say "disclosed" before the bytes reach the RPC (spec/08 §11.3): a
        // record not yet marked goes through the key worker first (`Applying`), and
        // `BtcJournalDone::Disclosed` starts the pre-check.
        let disclosed = ctx.record(&txid).is_some_and(|record| record.disclosed);
        let stage = if disclosed {
            BtcFlowStage::Prechecking
        } else {
            BtcFlowStage::Applying
        };
        let job = self.start_flow(network, txid, stage);
        let Ok(target) = ctx.target() else {
            if let Some(flow) = self.flow_mut(&txid) {
                flow.stage = BtcFlowStage::Waiting;
                flow.retry_precheck = true;
                flow.note = Some(ErrorCode::Key005.text());
            }
            return Vec::new();
        };
        if !disclosed {
            return vec![key_job(KeyJob::BtcJournal {
                op: BtcJournalOp::Disclose { network, txid },
                now_unix_ms: ctx.now_unix_ms,
            })];
        }
        vec![btc_job(BtcRpcJob::Precheck {
            job,
            target,
            tx,
            chain: ctx.chain_input(),
        })]
    }

    /// [전송 계속] of a `Signed` record (startup) and [다시 시도] after a failed pre-check.
    pub fn continue_signed(&mut self, ctx: &BtcCtx<'_>, txid: Txid) -> Vec<BtcAction> {
        if ctx.gate().is_err() {
            return Vec::new();
        }
        let Some(record) = ctx.record(&txid) else {
            return Vec::new();
        };
        if record.state != BtcTxState::Signed {
            return Vec::new();
        }
        let Some(tx) = signed_ref(&record) else {
            return Vec::new();
        };
        self.precheck(ctx, record.network, tx)
    }

    /// [취소] of a `Signed` record (confirmation first; the text depends on whether its bytes
    /// were already handed to the RPC).
    pub fn cancel_signed(&mut self, ctx: &BtcCtx<'_>, txid: Txid) -> Vec<BtcAction> {
        let disclosed = ctx.record(&txid).is_some_and(|record| record.disclosed);
        self.confirm = Some(BtcConfirm::CancelSigned { txid, disclosed });
        vec![BtcAction::Confirm]
    }

    /// [같은 바이트 다시 전송] of a `BroadcastUnknown` record (spec/08 §12.2-3), also of a
    /// `Broadcasting` record whose send stopped at the chain check (nothing was sent).
    pub fn rebroadcast(&mut self, ctx: &BtcCtx<'_>, txid: Txid) -> Vec<BtcAction> {
        if ctx.gate().is_err() {
            return Vec::new();
        }
        let Some(record) = ctx.record(&txid) else {
            return Vec::new();
        };
        let retry_send = self.flow(&txid).is_some_and(|flow| flow.retry_send);
        if record.state != BtcTxState::BroadcastUnknown
            && !(record.state == BtcTxState::Broadcasting && retry_send)
        {
            return Vec::new();
        }
        let (Some(tx), Ok(target)) = (signed_ref(&record), ctx.target()) else {
            return Vec::new();
        };
        let job = self.start_flow(record.network, txid, BtcFlowStage::Sending);
        vec![btc_job(BtcRpcJob::Send {
            job,
            target,
            tx,
            chain: ctx.chain_input(),
        })]
    }

    /// [포기] of a `BroadcastUnknown` record (confirmation `ABANDON_CONFIRM` first), only after
    /// tracking did not find it 10 times in a row (spec/08 §12.1, §12.2-3).
    pub fn abandon(&mut self, ctx: &BtcCtx<'_>, txid: Txid) -> Vec<BtcAction> {
        if !Self::abandon_allowed(ctx, &txid) {
            return Vec::new();
        }
        self.confirm = Some(BtcConfirm::Abandon { txid });
        vec![BtcAction::Confirm]
    }

    /// [포기] is offered: a `BroadcastUnknown` record with `not_found_count >= 10` (yw-core
    /// `BtcRecord::can_abandon`).
    fn abandon_allowed(ctx: &BtcCtx<'_>, txid: &Txid) -> bool {
        ctx.record(txid).is_some_and(|record| {
            record.state == BtcTxState::BroadcastUnknown && record.can_abandon()
        })
    }

    /// Whether [Esplora로 전송] is offered for `txid` (spec/08 §11.3; the worker re-checks). The
    /// "last Core send was a communication failure" fact is this session's flow when there is
    /// one, else the journal's persisted flag (it survives a restart).
    #[must_use]
    pub fn esplora_offered(&self, ctx: &BtcCtx<'_>, txid: &Txid) -> bool {
        ctx.settings.indexer == BtcIndexer::Esplora
            && self.indexer_verified
            && ctx.record(txid).is_some_and(|record| {
                record.state == BtcTxState::BroadcastUnknown
                    && self
                        .flow(txid)
                        .map_or(record.last_send_comm_failure, |flow| flow.comm_failure)
            })
    }

    /// [Esplora로 전송] (confirmation T-BTC-ESPLORA-BROADCAST first).
    pub fn esplora_broadcast(&mut self, ctx: &BtcCtx<'_>, txid: Txid) -> Vec<BtcAction> {
        if !self.esplora_offered(ctx, &txid) {
            return Vec::new();
        }
        self.confirm = Some(BtcConfirm::EsploraBroadcast { txid });
        vec![BtcAction::Confirm]
    }

    fn esplora_post(&mut self, ctx: &BtcCtx<'_>, txid: Txid) -> Vec<BtcAction> {
        if ctx.gate().is_err() || !self.esplora_offered(ctx, &txid) {
            return Vec::new();
        }
        let Some(record) = ctx.record(&txid) else {
            return Vec::new();
        };
        let (Some(tx), Ok(target)) = (signed_ref(&record), ctx.target()) else {
            return Vec::new();
        };
        let job = self.job();
        if let Some(flow) = self.flow_mut(&txid) {
            flow.job = job;
            flow.stage = BtcFlowStage::Sending;
        }
        vec![btc_job(BtcRpcJob::EsploraBroadcast {
            job,
            target,
            tx,
            gate: ManualBroadcastGate {
                broadcast_unknown: true,
                comm_failure: true,
            },
        })]
    }

    /// Freeze / unfreeze a verified output (spec/08 §7.6).
    #[must_use]
    pub fn freeze(ctx: &BtcCtx<'_>, outpoint: OutPoint, frozen: bool) -> Vec<BtcAction> {
        if !ctx.unlocked || ctx.btc_meta().is_none() || ctx.mismatch().is_some() {
            return Vec::new();
        }
        vec![key_job(KeyJob::BtcMeta {
            op: BtcMetaOp::Freeze {
                network: ctx.net(),
                account: ctx.active_id(),
                outpoint,
                frozen,
            },
        })]
    }

    // ----- accounts ---------------------------------------------------------------------------

    /// The account list of the settings network (BIP84 account 0 first, then the other HD
    /// accounts and the imported keys in the order they were added): name (an imported key: its
    /// shortened address), address type with its prefix, available verified balance at the
    /// known tip, selection, the imported-key badge.
    #[must_use]
    pub fn account_rows(&self, ctx: &BtcCtx<'_>) -> Vec<BtcAccountRow> {
        let net = ctx.net();
        let active = ctx.active_id();
        let tip = self.tip_or_meta(ctx);
        ctx.accounts()
            .into_iter()
            .map(|meta| {
                let records = of_account(ctx.all_records(), net, meta.id());
                let imported = meta.is_imported();
                let evm_shared = match meta.id() {
                    BtcAccountId::EvmShared { evm_index, .. } => Some(evm_index),
                    _ => None,
                };
                let name = if meta.is_single() {
                    meta.address(BtcChain::Receive, 0).map_or_else(
                        |_| account_label(meta.account()),
                        |address| short_address(address.as_str()),
                    )
                } else {
                    account_label(meta.account())
                };
                BtcAccountRow {
                    id: meta.id(),
                    name,
                    kind: account_type_text(meta.account(), net),
                    available: meta
                        .balance(tip, &in_flight_outpoints(&records, net))
                        .available,
                    selected: meta.id() == active,
                    imported,
                    evm_shared,
                    fixed: meta.fixed_address(),
                }
            })
            .collect()
    }

    /// Clears what belongs to the previously selected account (forms, receive address,
    /// per-account refresh facts, running discovery).
    fn reset_account_view(&mut self) {
        self.cancel_discovery();
        self.discovery = BtcDiscoveryState::default();
        self.refresh.busy = false;
        self.refresh.job = 0;
        self.send = BtcSendForm::default();
        self.bump = BtcBumpForm::default();
        self.receive = None;
        self.receive_message = None;
        self.pending_incoming = false;
        self.verify_failures = 0;
        self.hint_mismatch.clear();
        self.indexer_only.clear();
        self.auto_frozen = 0;
        self.account_message = None;
    }

    /// Selects another account of the settings network (refused while a BTC approval is open).
    pub fn select_account(&mut self, ctx: &BtcCtx<'_>, account: BtcAccountId) -> Vec<BtcAction> {
        self.account_message = None;
        if let Err(gate) = ctx.gate() {
            self.account_message = Some(gate.text());
            return Vec::new();
        }
        if account == ctx.active_id() {
            return Vec::new();
        }
        if self.slot {
            self.account_message = Some(ACCOUNT_SWITCH_BUSY.to_owned());
            return Vec::new();
        }
        vec![key_job(KeyJob::BtcMeta {
            op: BtcMetaOp::Select {
                network: ctx.net(),
                account,
            },
        })]
    }

    /// `계정 추가`: opens the address-type chooser (HD accounts need the recovery words: a
    /// key-only wallet adds Bitcoin accounts with `개인키 가져오기` only). The key source starts
    /// at the standard BTC path; the EVM-shared key is an explicit choice (spec/08 §3.5).
    pub fn open_add_account(&mut self, ctx: &BtcCtx<'_>) {
        self.account_message = if ctx.has_mnemonic {
            ctx.gate().err().map(BtcGate::text)
        } else {
            Some(yw_core::error::VaultError::NoMnemonic.to_string())
        };
        self.add_account_open = self.account_message.is_none();
        self.add_source = BtcAddSource::Standard;
        self.add_evm_index = ctx.evm_indices().first().copied().unwrap_or(0);
        self.add_mnemonic = None;
    }

    /// Closes the chooser without adding.
    pub fn close_add_account(&mut self) {
        self.add_account_open = false;
        self.add_source = BtcAddSource::Standard;
        self.add_mnemonic = None;
    }

    /// The chooser's key source radio (the EVM key is the primary mnemonic's).
    pub fn set_add_source(&mut self, source: BtcAddSource) {
        self.add_source = source;
        if source == BtcAddSource::EvmShared {
            self.add_mnemonic = None;
        }
    }

    /// The chooser's mnemonic radio (`None`: the primary one): the standard path of that
    /// mnemonic.
    pub fn set_add_mnemonic(&mut self, mnemonic: Option<yw_core::vault::RecordId>) {
        self.add_mnemonic = mnemonic;
        self.add_source = BtcAddSource::Standard;
    }

    /// The chooser's EVM account radio (an index of the wallet's derived EVM accounts).
    pub fn set_add_evm_index(&mut self, ctx: &BtcCtx<'_>, evm_index: u32) {
        if ctx.evm_indices().contains(&evm_index) {
            self.add_evm_index = evm_index;
        }
    }

    /// Whether adding an account is refused now (no recovery words, gate, open BTC approval);
    /// sets the reason and closes the chooser.
    fn add_refused(&mut self, ctx: &BtcCtx<'_>) -> bool {
        let reason = if !ctx.has_mnemonic {
            Some(yw_core::error::VaultError::NoMnemonic.to_string())
        } else if let Err(gate) = ctx.gate() {
            Some(gate.text())
        } else if self.slot {
            Some(ACCOUNT_SWITCH_BUSY.to_owned())
        } else {
            None
        };
        if reason.is_some() {
            self.add_account_open = false;
            self.account_message = reason;
            return true;
        }
        false
    }

    /// A chooser address type: with the standard source the next HD account of `script_type`
    /// (`m/{44|49|84|86}'/{coin}'/{n}'`; the key worker stores and selects it, then discovery
    /// runs); with the EVM-shared source the confirmation T-BTC-EVM-SHARED first.
    pub fn add_account(&mut self, ctx: &BtcCtx<'_>, script_type: ScriptType) -> Vec<BtcAction> {
        self.account_message = None;
        if self.add_refused(ctx) {
            return Vec::new();
        }
        if self.add_source == BtcAddSource::EvmShared {
            if !ctx.evm_indices().contains(&self.add_evm_index) {
                self.account_message = Some("EVM 계정을 고르세요".to_owned());
                return Vec::new();
            }
            self.confirm = Some(BtcConfirm::AddEvmShared {
                script_type,
                evm_index: self.add_evm_index,
            });
            return vec![BtcAction::Confirm];
        }
        vec![key_job(KeyJob::BtcMeta {
            op: BtcMetaOp::AddAccount {
                network: ctx.net(),
                script_type,
                mnemonic: self.add_mnemonic,
            },
        })]
    }

    /// Whether a record of an account of the added mnemonic `id` (any network) may still
    /// confirm, or a BTC approval of one of them is open (spec/02 §8.6: removal refused).
    #[must_use]
    pub fn mnemonic_busy(&self, ctx: &BtcCtx<'_>, id: yw_core::vault::RecordId) -> bool {
        let of_mnemonic = |account: &BtcAccountId| matches!(account, BtcAccountId::Hd { mnemonic: Some(of), .. } if *of == id);
        if self.slot && ctx.btc_meta().is_some_and(|meta| of_mnemonic(&meta.id())) {
            return true;
        }
        let now_unix = ctx.now_unix_ms / 1_000;
        if ctx
            .all_records()
            .iter()
            .any(|record| of_mnemonic(&record.account) && record.may_still_confirm(now_unix))
        {
            return true;
        }
        BtcNetwork::ALL.into_iter().any(|net| {
            ctx.accounts_on(net)
                .into_iter()
                .filter(|meta| of_mnemonic(&meta.id()))
                .any(|meta| {
                    ctx.related_of(meta)
                        .iter()
                        .any(|record| record.may_still_confirm(now_unix))
                })
        })
    }

    /// The address mode of the selected HD account (spec/08 §3.5): fixed address (`true`,
    /// receive and change at `…/0/0`) or a new receive address each time with the change chain.
    /// Refused while a BTC approval is open; one-key accounts have no mode.
    pub fn set_address_mode(&mut self, ctx: &BtcCtx<'_>, single_address: bool) -> Vec<BtcAction> {
        self.account_message = None;
        let Some(meta) = ctx.btc_meta() else {
            return Vec::new();
        };
        if !meta.account().is_hd() || meta.fixed_address() == single_address {
            return Vec::new();
        }
        if let Err(gate) = ctx.gate() {
            self.account_message = Some(gate.text());
            return Vec::new();
        }
        if self.slot {
            self.account_message = Some(ADDRESS_MODE_BUSY.to_owned());
            return Vec::new();
        }
        vec![key_job(KeyJob::BtcMeta {
            op: BtcMetaOp::SetAddressMode {
                network: ctx.net(),
                account: meta.id(),
                single_address,
            },
        })]
    }

    // ----- worker results ---------------------------------------------------------------------

    /// A BTC key worker outcome (`BtcMeta`, `SignedBtc`, `BtcJournal`).
    pub fn on_key_outcome(&mut self, ctx: &BtcCtx<'_>, outcome: KeyOutcome) -> Vec<BtcAction> {
        match outcome {
            KeyOutcome::BtcMeta(result) => self.on_meta(ctx, result),
            KeyOutcome::SignedBtc(result) => self.on_signed(ctx, result),
            KeyOutcome::BtcJournal(result) => self.on_journal(ctx, result),
            _ => Vec::new(),
        }
    }

    fn on_meta(
        &mut self,
        ctx: &BtcCtx<'_>,
        result: Result<BtcMetaUpdate, BtcKeyError>,
    ) -> Vec<BtcAction> {
        match result {
            Ok(update) => {
                let meta = update.meta.clone();
                // The selected account after the change (the mirror is updated by the first
                // action, `ctx` still shows the previous one).
                let active = active_of(&update, ctx.net());
                let mut actions = vec![BtcAction::SetMeta(update.meta, update.accounts)];
                match update.done {
                    BtcMetaDone::Created => {
                        logging::info("app", "btc.meta_created", &[]);
                        // Discovery runs against the new meta; the mirror is updated first.
                        if let Some(meta) = meta {
                            actions.extend(self.discover_with(ctx, &meta, false));
                        }
                    }
                    BtcMetaDone::AccountAdded(_)
                    | BtcMetaDone::Selected(_)
                    | BtcMetaDone::Removed(_) => {
                        self.add_account_open = false;
                        self.reset_account_view();
                        if let Some(active) = active {
                            logging::info(
                                "app",
                                "btc.account",
                                &[(
                                    "type",
                                    Field::Word(active.account().script_type().json_name()),
                                )],
                            );
                            actions.extend(if active.discovery_done() {
                                self.refresh_with(ctx, &active, Trigger::User)
                            } else {
                                self.discover_with(ctx, &active, false)
                            });
                        }
                    }
                    BtcMetaDone::Discovered => {
                        self.discovery.running = false;
                        self.discovery.error = None;
                        if let Some(meta) = active {
                            actions.extend(self.refresh_with(ctx, &meta, Trigger::User));
                        }
                    }
                    BtcMetaDone::Refreshed(report) => {
                        self.auto_frozen = report.auto_frozen;
                    }
                    BtcMetaDone::Receive { index, issued } => {
                        if self.receive_pending {
                            self.receive_pending = false;
                            self.receive = active
                                .as_ref()
                                .and_then(|meta| Self::receive_view(meta, index));
                            if issued {
                                logging::info(
                                    "app",
                                    "btc.receive_issued",
                                    &[("index", Field::Num(u64::from(index)))],
                                );
                            }
                            actions.push(BtcAction::Screen(BtcScreen::Receive));
                        }
                    }
                    BtcMetaDone::TipReset => {
                        // Forget the blocked sessions; the next check stores the tip it sees.
                        self.tip_regressed = false;
                        self.blocked = None;
                        self.indexer_verified = false;
                        actions.push(btc_job(BtcRpcJob::Reset));
                        if let Some(meta) = active {
                            actions.extend(self.refresh_with(ctx, &meta, Trigger::User));
                        }
                    }
                    BtcMetaDone::AddressMode(_) => self.on_address_mode(active.as_ref()),
                    BtcMetaDone::Tip
                    | BtcMetaDone::Frozen
                    | BtcMetaDone::Unfrozen
                    | BtcMetaDone::ChangeNext
                    | BtcMetaDone::Updated => {}
                }
                actions
            }
            Err(error) => {
                if self.add_account_open {
                    self.add_account_open = false;
                    self.account_message = Some(error.text());
                    return Vec::new();
                }
                if self.receive_pending {
                    self.receive_pending = false;
                    if let BtcKeyError::Meta(MetaError::GapWarning { unused }) = error {
                        self.confirm = Some(BtcConfirm::GapWarning { unused });
                        return vec![BtcAction::Confirm];
                    }
                    self.receive_message = Some(error.text());
                    return Vec::new();
                }
                if let BtcKeyError::Meta(MetaError::NetworkMismatch) = error {
                    self.blocked = Some(texts::NETWORK_MISMATCH.to_owned());
                }
                self.status_error = Some(error.text());
                Vec::new()
            }
        }
    }

    /// An HD account's address mode was stored: the receive screen shows the address of the new
    /// mode next time.
    fn on_address_mode(&mut self, active: Option<&BtcMeta>) {
        self.receive = None;
        let fixed = active.is_some_and(BtcMeta::fixed_address);
        logging::info(
            "app",
            "btc.address_mode",
            &[("mode", Field::Word(if fixed { "single" } else { "hd" }))],
        );
    }

    /// Discovery against a meta that the mirror may not show yet (right after `Create`).
    fn discover_with(&mut self, ctx: &BtcCtx<'_>, meta: &BtcMeta, more: bool) -> Vec<BtcAction> {
        let Ok(mut target) = ctx.target() else {
            return Vec::new();
        };
        if !ctx.unlocked || !ctx.settings.enabled || meta.network() != ctx.net() {
            return Vec::new();
        }
        target.meta_net = meta.network();
        let discovery = if more {
            Discovery::more(meta)
        } else {
            Discovery::full()
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let job = self.job();
        self.discovery = BtcDiscoveryState {
            running: true,
            more,
            checked: 0,
            error: None,
            job,
            account: meta.id(),
            cancel: Some(Arc::clone(&cancel)),
        };
        vec![btc_job(BtcRpcJob::Discover {
            job,
            target,
            work: DiscoveryJob {
                account: *meta.account(),
                discovery,
                chain: Self::chain_of(ctx, meta),
            },
            cancel,
        })]
    }

    /// Chain-check inputs for a job on `meta`'s account: the wallet's `max_tip_seen` lives in
    /// the tip holder — BIP84 account 0 (`meta` itself right after `Create`, before the mirror
    /// has it), or a key-only wallet's first account (none yet right after its first import:
    /// then `meta`'s own value).
    fn chain_of(ctx: &BtcCtx<'_>, meta: &BtcMeta) -> ChainInput {
        ChainInput {
            max_tip_seen: if meta.id() == BtcAccountId::PRIMARY {
                meta.max_tip_seen()
            } else {
                ctx.tip_meta()
                    .map_or(meta.max_tip_seen(), BtcMeta::max_tip_seen)
            },
            now_unix_secs: ctx.now_unix_ms / 1_000,
        }
    }

    fn refresh_with(
        &mut self,
        ctx: &BtcCtx<'_>,
        meta: &BtcMeta,
        trigger: Trigger,
    ) -> Vec<BtcAction> {
        let Ok(mut target) = ctx.target() else {
            return Vec::new();
        };
        if !ctx.unlocked || meta.network() != ctx.net() || self.refresh.busy {
            return Vec::new();
        }
        target.meta_net = meta.network();
        let records = of_account(ctx.all_records(), meta.network(), meta.id());
        let work = RefreshJob {
            account: *meta.account(),
            receive_count: meta.receive_next(),
            change_count: meta.change_next(),
            known: meta.verified().iter().map(|utxo| utxo.outpoint).collect(),
            // Change on the change chain only: change back to the fixed address `(Receive, 0)`
            // (one-key accounts, fixed-address mode) is not a change-chain index.
            inflight_change: records
                .iter()
                .filter(|record| record.state.is_in_flight())
                .filter_map(|record| record.hd_change_index(meta.account()))
                .collect(),
            chain: Self::chain_of(ctx, meta),
            trigger,
        };
        let job = self.job();
        self.refresh = BtcJobState {
            job,
            busy: true,
            next_ms: ctx.now_ms.saturating_add(BTC_TICK_MS),
        };
        self.refresh_account = meta.id();
        vec![btc_job(BtcRpcJob::Refresh { job, target, work })]
    }

    fn on_signed(
        &mut self,
        ctx: &BtcCtx<'_>,
        result: Result<BtcSignedSummary, BtcSignFailure>,
    ) -> Vec<BtcAction> {
        self.slot = false;
        match result {
            Ok(summary) => {
                logging::info(
                    "app",
                    "btc.signed",
                    &[
                        ("net", Field::Net(network_id(summary.network))),
                        ("tx", Field::BtcTxid(summary.tx.txid)),
                    ],
                );
                self.result = Some(summary.tx.txid);
                if summary.replaces.is_some() {
                    self.bump = BtcBumpForm::default();
                    self.last_form = None;
                } else {
                    let form = core::mem::take(&mut self.send);
                    self.last_form = Some(BtcSendForm {
                        preparing: None,
                        info: None,
                        ..form
                    });
                }
                if !ctx.unlocked {
                    // Locked: the record stays `Signed`; [전송 계속] after unlock.
                    return Vec::new();
                }
                let mut actions = self.precheck(ctx, summary.network, summary.tx);
                actions.push(BtcAction::Screen(BtcScreen::SendResult));
                actions
            }
            Err(failure) => {
                let message = failure.text();
                logging::warn("app", "btc.sign_failed", &[]);
                self.send.info = Some(message.clone());
                self.bump.info = Some(message.clone());
                vec![BtcAction::Banner(None, message)]
            }
        }
    }

    /// `Broadcasting` is committed: send the journal's bytes.
    fn send_committed(
        &mut self,
        ctx: &BtcCtx<'_>,
        network: BtcNetwork,
        tx: SignedTxRef,
    ) -> Vec<BtcAction> {
        let txid = tx.txid;
        let Ok(target) = ctx.target() else {
            return Vec::new();
        };
        if !ctx.unlocked {
            return Vec::new();
        }
        let job = self.job();
        if let Some(flow) = self.flow_mut(&txid) {
            flow.stage = BtcFlowStage::Sending;
            flow.retry_send = false;
            flow.job = job;
        } else {
            self.flows.push(BtcTxFlow {
                network,
                txid,
                stage: BtcFlowStage::Sending,
                note: None,
                comm_failure: false,
                retry_precheck: false,
                retry_send: false,
                job,
            });
        }
        vec![btc_job(BtcRpcJob::Send {
            job,
            target,
            tx,
            chain: ctx.chain_input(),
        })]
    }

    fn on_journal(
        &mut self,
        ctx: &BtcCtx<'_>,
        result: Result<BtcJournalDone, BtcKeyError>,
    ) -> Vec<BtcAction> {
        match result {
            Ok(BtcJournalDone::Disclosed { network, tx }) => {
                self.precheck_disclosed(ctx, network, tx)
            }
            Ok(BtcJournalDone::Broadcasting { network, tx }) => {
                self.send_committed(ctx, network, tx)
            }
            Ok(BtcJournalDone::PrecheckKnown { txid, text }) => {
                // The node already has it: nothing sent, the record is `BroadcastUnknown` and
                // tracking (started now) moves it to `InMempool`/`Confirmed`.
                if let Some(flow) = self.flow_mut(&txid) {
                    flow.stage = BtcFlowStage::Done;
                    flow.note = Some(text.to_owned());
                    flow.comm_failure = false;
                }
                if self.result == Some(txid) {
                    self.last_form = None;
                }
                self.track.next_ms = ctx.now_ms;
                Vec::new()
            }
            Ok(BtcJournalDone::PrecheckRejected { txid, text }) => {
                if let Some(flow) = self.flow_mut(&txid) {
                    flow.stage = BtcFlowStage::Done;
                    flow.note = Some(text.to_owned());
                }
                // Not sent: the inputs come back to the form (fees can be raised and reviewed).
                if self.result == Some(txid)
                    && let Some(form) = self.last_form.take()
                {
                    self.send = BtcSendForm {
                        info: Some(text.to_owned()),
                        ..form
                    };
                }
                Vec::new()
            }
            Ok(BtcJournalDone::Sent { txid, outcome }) => {
                if let Some(flow) = self.flow_mut(&txid) {
                    flow.stage = BtcFlowStage::Done;
                    match outcome {
                        BroadcastOutcome::Submitted => {
                            flow.note = Some("전송했습니다".to_owned());
                            flow.comm_failure = false;
                        }
                        BroadcastOutcome::BroadcastUnknown { text, comm_failure } => {
                            flow.note = Some(text.unwrap_or_else(|| ErrorCode::Tx004.text()));
                            flow.comm_failure = comm_failure;
                        }
                        BroadcastOutcome::Rejected { text } => flow.note = Some(text),
                    }
                }
                self.track.next_ms = ctx.now_ms;
                Vec::new()
            }
            Ok(BtcJournalDone::EsploraNoted { txid }) => {
                if let Some(flow) = self.flow_mut(&txid) {
                    flow.stage = BtcFlowStage::Done;
                    flow.note = Some("Esplora로 전송했습니다".to_owned());
                    flow.comm_failure = false;
                }
                self.track.next_ms = ctx.now_ms;
                Vec::new()
            }
            Ok(BtcJournalDone::Tracked { changed }) => {
                for (txid, state) in changed {
                    logging::info(
                        "app",
                        "btc.state",
                        &[
                            ("tx", Field::BtcTxid(txid)),
                            ("state", Field::Word(state.name())),
                        ],
                    );
                }
                Vec::new()
            }
            Ok(BtcJournalDone::Abandoned { txid }) => {
                self.flows.retain(|flow| flow.txid != txid);
                Vec::new()
            }
            Err(error) => {
                // A journal step that failed before the pre-check ran (disclose, pre-check
                // result): nothing was sent after it, [다시 시도] stays possible.
                for flow in &mut self.flows {
                    if flow.stage == BtcFlowStage::Applying {
                        flow.stage = BtcFlowStage::Waiting;
                        flow.retry_precheck = true;
                        flow.note = Some(error.text());
                    }
                }
                self.status_error = Some(error.text());
                Vec::new()
            }
        }
    }

    /// The record is marked disclosed in the journal: now the bytes may go to `testmempoolaccept`
    /// (only for the flow still waiting for this step, and only while unlocked).
    fn precheck_disclosed(
        &mut self,
        ctx: &BtcCtx<'_>,
        network: BtcNetwork,
        tx: SignedTxRef,
    ) -> Vec<BtcAction> {
        let txid = tx.txid;
        let Some(job) = self
            .flow(&txid)
            .filter(|flow| flow.stage == BtcFlowStage::Applying && flow.network == network)
            .map(|flow| flow.job)
        else {
            return Vec::new();
        };
        let target = if ctx.unlocked {
            ctx.target().ok()
        } else {
            None
        };
        let Some(target) = target else {
            if let Some(flow) = self.flow_mut(&txid) {
                flow.stage = BtcFlowStage::Waiting;
                flow.retry_precheck = true;
                flow.note = Some(ErrorCode::Key005.text());
            }
            return Vec::new();
        };
        if let Some(flow) = self.flow_mut(&txid) {
            flow.stage = BtcFlowStage::Prechecking;
        }
        vec![btc_job(BtcRpcJob::Precheck {
            job,
            target,
            tx,
            chain: ctx.chain_input(),
        })]
    }

    /// A BTC RPC worker event.
    #[expect(clippy::too_many_lines, reason = "one arm per BTC job result")]
    pub fn on_rpc_event(&mut self, ctx: &BtcCtx<'_>, event: BtcRpcEvent) -> Vec<BtcAction> {
        match event {
            BtcRpcEvent::EsploraTest { net, message, ok } => {
                self.set_esplora_test(net, message, ok);
                Vec::new()
            }
            BtcRpcEvent::Progress { job, checked } => {
                if job == self.discovery.job {
                    self.discovery.checked = checked;
                }
                Vec::new()
            }
            BtcRpcEvent::Discovered { job, net, result } => {
                if job != self.discovery.job || !ctx.unlocked {
                    return Vec::new();
                }
                self.discovery.cancel = None;
                match result {
                    Ok(found) => {
                        self.indexer_verified = true;
                        self.note_chain(found.chain.tip_height, found.chain.lag_warning);
                        vec![key_job(KeyJob::BtcMeta {
                            op: BtcMetaOp::Discovered {
                                network: net,
                                account: self.discovery.account,
                                discovery: Box::new(found.discovery),
                            },
                        })]
                    }
                    Err(error) => {
                        self.discovery.running = false;
                        self.note_error(ctx, error);
                        let text = error.text(ctx.settings.indexer).map_or_else(
                            || DISCOVERY_INCOMPLETE.to_owned(),
                            |text| format!("{DISCOVERY_INCOMPLETE} — {text}"),
                        );
                        self.discovery.error = Some(text);
                        Vec::new()
                    }
                }
            }
            BtcRpcEvent::Refreshed { job, net, result } => {
                if job != self.refresh.job {
                    return Vec::new();
                }
                self.refresh.busy = false;
                if !ctx.unlocked {
                    return Vec::new();
                }
                match result {
                    Ok(refreshed) => {
                        self.indexer_verified = true;
                        self.status_error = None;
                        self.note_chain(refreshed.chain.tip_height, refreshed.chain.lag_warning);
                        self.pending_incoming = refreshed.pending_incoming();
                        self.verify_failures = refreshed.verify_failures();
                        self.hint_mismatch = refreshed
                            .verified
                            .iter()
                            .filter(|utxo| utxo.hint_mismatch)
                            .map(|utxo| utxo.outpoint)
                            .collect();
                        self.indexer_only = refreshed.indexer_only();
                        vec![key_job(KeyJob::BtcMeta {
                            op: BtcMetaOp::Refreshed {
                                network: net,
                                account: self.refresh_account,
                                update: Box::new(BtcRefreshUpdate {
                                    listed: refreshed.listed(),
                                    newly: refreshed.newly(),
                                    history: refreshed.history(),
                                    max_tip_seen: refreshed.chain.max_tip_seen,
                                    now_unix: ctx.now_unix_ms / 1_000,
                                }),
                            },
                        })]
                    }
                    Err(BtcError::Cooldown) => Vec::new(),
                    Err(error) => {
                        self.note_error(ctx, error);
                        Vec::new()
                    }
                }
            }
            BtcRpcEvent::Prepared { job, net, result } => {
                let bump = self.bump.preparing == Some(job);
                if !bump && self.send.preparing != Some(job) {
                    return Vec::new();
                }
                if bump {
                    self.bump.preparing = None;
                    self.bump.info = None;
                } else {
                    self.send.preparing = None;
                    self.send.info = None;
                }
                if !ctx.unlocked {
                    return Vec::new();
                }
                match result {
                    Ok(prepared) => {
                        self.note_chain(prepared.chain.tip_height, prepared.chain.lag_warning);
                        self.floor = Some(prepared.floor);
                        // The wallet-level tip lives in the tip holder (BIP84 account 0, or a
                        // key-only wallet's first account of the network).
                        let Some(meta) = ctx.tip_meta() else {
                            return Vec::new();
                        };
                        let (fee, info) = if bump {
                            (&mut self.bump.fee, &mut self.bump.info)
                        } else {
                            (&mut self.send.fee, &mut self.send.info)
                        };
                        if self.slot {
                            *info = Some("다른 Bitcoin 승인이 진행 중입니다".to_owned());
                            return Vec::new();
                        }
                        fee.needs_typed = None;
                        self.slot = true;
                        let mut actions = Vec::new();
                        if prepared.chain.max_tip_seen > meta.max_tip_seen() {
                            actions.push(key_job(KeyJob::BtcMeta {
                                op: BtcMetaOp::Tip {
                                    network: net,
                                    max_tip_seen: prepared.chain.max_tip_seen,
                                },
                            }));
                        }
                        actions.push(BtcAction::Enqueue(Box::new(BtcApprovalItem {
                            network: net,
                            facts: prepared.facts,
                            account: *prepared.plan.account(),
                            tip_height: prepared.chain.tip_height,
                            plan: prepared.plan,
                        })));
                        actions
                    }
                    Err(error) => {
                        let text = error.text(ctx.settings.indexer);
                        let (fee, info) = if bump {
                            (&mut self.bump.fee, &mut self.bump.info)
                        } else {
                            (&mut self.send.fee, &mut self.send.info)
                        };
                        match error {
                            PrepareError::NoEstimate { floor } => {
                                // Manual input only, the floor as default (spec/08 §8.2): the
                                // form can be reviewed again right away.
                                fee.choice = BtcFeeChoice::Manual;
                                floor
                                    .to_string()
                                    .trim_end_matches(" sat/vB")
                                    .clone_into(&mut fee.manual_text);
                                fee.validate();
                                *info = Some(text);
                            }
                            PrepareError::ManualBelowFloor { .. } => fee.error = Some(text),
                            PrepareError::NeedsTypedFee { fee: planned, .. } => {
                                fee.needs_typed = Some(planned);
                                *info = Some(text);
                            }
                            PrepareError::Btc(btc) => {
                                *info = Some(text);
                                self.note_error(ctx, btc);
                            }
                            PrepareError::FeeOverflow
                            | PrepareError::Plan(_)
                            | PrepareError::FeeUnoverridable
                            | PrepareError::Derivation
                            | PrepareError::TipAhead { .. } => *info = Some(text),
                        }
                        Vec::new()
                    }
                }
            }
            BtcRpcEvent::Prechecked {
                job,
                net,
                txid,
                result,
            } => {
                if self.flow(&txid).is_none_or(|flow| flow.job != job) || !ctx.unlocked {
                    return Vec::new();
                }
                match result {
                    Ok(accept) => {
                        if let Some(flow) = self.flow_mut(&txid) {
                            flow.stage = BtcFlowStage::Applying;
                        }
                        vec![key_job(KeyJob::BtcJournal {
                            op: BtcJournalOp::Precheck {
                                network: net,
                                txid,
                                accept,
                            },
                            now_unix_ms: ctx.now_unix_ms,
                        })]
                    }
                    Err(error) => {
                        let text = error
                            .text(ctx.settings.indexer)
                            .unwrap_or_else(|| ErrorCode::Rpc001.text());
                        if let Some(flow) = self.flow_mut(&txid) {
                            flow.stage = BtcFlowStage::Waiting;
                            flow.retry_precheck = true;
                            flow.note = Some(text);
                        }
                        self.note_error(ctx, error);
                        Vec::new()
                    }
                }
            }
            BtcRpcEvent::Sent {
                job,
                net,
                txid,
                result,
            } => {
                if self.flow(&txid).is_none_or(|flow| flow.job != job) || !ctx.unlocked {
                    return Vec::new();
                }
                let result = match result {
                    Ok(result) => result,
                    Err(error) => {
                        // The chain check right before `sendrawtransaction` failed: nothing
                        // was sent. Not `BroadcastUnknown`: the record stays `Broadcasting`
                        // and [같은 바이트 다시 전송] retries (a restart makes it
                        // `BroadcastUnknown`, spec/08 §12.1).
                        let text = error.text(ctx.settings.indexer).map_or_else(
                            || NOT_SENT.to_owned(),
                            |text| format!("{NOT_SENT} — {text}"),
                        );
                        if let Some(flow) = self.flow_mut(&txid) {
                            flow.stage = BtcFlowStage::Waiting;
                            flow.retry_send = true;
                            flow.note = Some(text);
                        }
                        self.note_error(ctx, error);
                        return Vec::new();
                    }
                };
                if let BroadcastOutcome::BroadcastUnknown { comm_failure, .. } =
                    broadcast_outcome(&result, &txid)
                    && let Some(flow) = self.flow_mut(&txid)
                {
                    flow.comm_failure = comm_failure;
                }
                vec![key_job(KeyJob::BtcJournal {
                    op: BtcJournalOp::Sent {
                        network: net,
                        txid,
                        result,
                    },
                    now_unix_ms: ctx.now_unix_ms,
                })]
            }
            BtcRpcEvent::Tracked { job, net, round } => {
                if job != self.track.job {
                    return Vec::new();
                }
                self.track.busy = false;
                if !ctx.unlocked {
                    return Vec::new();
                }
                if round.mempool_entry_unsupported {
                    self.mempool_entry = false;
                }
                if let Some(error) = round.error
                    && error != BtcError::Cooldown
                {
                    self.note_error(ctx, error);
                }
                let Some(chain) = round.chain else {
                    return Vec::new();
                };
                self.note_chain(chain.tip_height, chain.lag_warning);
                if round.observations.is_empty()
                    && ctx
                        .tip_meta()
                        .is_some_and(|meta| meta.max_tip_seen() >= chain.max_tip_seen)
                {
                    return Vec::new();
                }
                vec![key_job(KeyJob::BtcJournal {
                    op: BtcJournalOp::Tracked {
                        network: net,
                        tip_height: chain.tip_height,
                        max_tip_seen: Some(chain.max_tip_seen),
                        observations: round.observations,
                    },
                    now_unix_ms: ctx.now_unix_ms,
                })]
            }
            BtcRpcEvent::EsploraSent {
                job,
                net,
                txid,
                result,
            } => {
                if self.flow(&txid).is_none_or(|flow| flow.job != job) || !ctx.unlocked {
                    return Vec::new();
                }
                match result {
                    Ok(EsploraPostOutcome::Submitted) => vec![key_job(KeyJob::BtcJournal {
                        op: BtcJournalOp::EsploraSent { network: net, txid },
                        now_unix_ms: ctx.now_unix_ms,
                    })],
                    Ok(outcome) => {
                        if let Some(flow) = self.flow_mut(&txid) {
                            flow.stage = BtcFlowStage::Done;
                            flow.note = Some(outcome.text());
                        }
                        Vec::new()
                    }
                    Err(error) => {
                        if let Some(flow) = self.flow_mut(&txid) {
                            flow.stage = BtcFlowStage::Done;
                            flow.note = error.text(ctx.settings.indexer);
                        }
                        Vec::new()
                    }
                }
            }
        }
    }

    fn note_chain(&mut self, tip: u32, lag: Option<u32>) {
        self.tip = Some(tip);
        self.lag_warning = lag;
        self.blocked = None;
        self.tip_regressed = false;
    }

    fn note_error(&mut self, ctx: &BtcCtx<'_>, error: BtcError) {
        match error {
            BtcError::Blocked(block) => {
                self.blocked = Some(block.text());
                self.indexer_verified = false;
                self.tip_regressed = block == BtcBlock::Core(CoreCheckFailure::TipRegressed);
            }
            BtcError::Cooldown | BtcError::Cancelled => {}
            other => self.status_error = other.text(ctx.settings.indexer),
        }
    }

    // ----- display ----------------------------------------------------------------------------

    /// Verified balance at the known tip (in-flight inputs excluded, frozen and immature apart).
    #[must_use]
    pub fn balance(&self, ctx: &BtcCtx<'_>) -> Option<BtcBalance> {
        let meta = ctx.btc_meta()?;
        if ctx.mismatch().is_some() {
            return None;
        }
        Some(meta.balance(
            self.tip_or_meta(ctx),
            &in_flight_outpoints(&ctx.records(), ctx.net()),
        ))
    }

    /// `0.00120000 BTC (120,000 sats)`.
    #[must_use]
    pub fn amount_text(amount: Sats) -> String {
        format_btc_and_sats(amount)
    }

    /// The verified UTXOs for the freeze list.
    #[must_use]
    pub fn utxos(&self, ctx: &BtcCtx<'_>) -> Vec<BtcUtxoView> {
        let Some(meta) = ctx.btc_meta() else {
            return Vec::new();
        };
        let tip = self.tip_or_meta(ctx);
        let in_flight = in_flight_outpoints(&ctx.records(), ctx.net());
        meta.verified()
            .iter()
            .map(|utxo| BtcUtxoView {
                outpoint: utxo.outpoint,
                value: utxo.value,
                confirmations: conf(utxo.height, tip),
                frozen: meta.frozen_reason(&utxo.outpoint),
                in_flight: in_flight.contains(&utxo.outpoint),
                own: utxo.own,
                hint_mismatch: self.hint_mismatch.contains(&utxo.outpoint),
                indexer_only: self.indexer_only.contains(&utxo.outpoint),
            })
            .collect()
    }

    /// Activity of the Bitcoin tab: the settings network's journal records (in flight and not
    /// yet pruned) and meta `activity["bitcoin:<net>"]`, newest first, at most 50.
    #[must_use]
    pub fn activity_rows(&self, ctx: &BtcCtx<'_>) -> Vec<BtcActivityView> {
        let net = ctx.net();
        let tip = self.tip_or_meta(ctx);
        let bump = bump_target(&ctx.records(), net).map(|record| record.txid);
        let mut rows: Vec<BtcActivityView> = ctx
            .records()
            .iter()
            .map(|record| {
                let busy = self.flow(&record.txid).is_some_and(|flow| {
                    flow.stage != BtcFlowStage::Done && flow.stage != BtcFlowStage::Waiting
                });
                let retry_send = self.flow(&record.txid).is_some_and(|flow| flow.retry_send);
                BtcActivityView {
                    txid: record.txid.to_display_hex(),
                    title: record.title(),
                    amount: record.recipient_amount(),
                    counterparty: record.recipient_address().unwrap_or_default(),
                    status: record_status(record, tip),
                    time_unix_ms: record.updated_at_unix.saturating_mul(1_000),
                    journal: true,
                    can_bump: bump == Some(record.txid) && !self.slot,
                    can_rebroadcast: (record.state == BtcTxState::BroadcastUnknown
                        || (record.state == BtcTxState::Broadcasting && retry_send))
                        && !busy,
                    can_abandon: record.state == BtcTxState::BroadcastUnknown
                        && record.can_abandon()
                        && !busy,
                    can_esplora: !busy && self.esplora_offered(ctx, &record.txid),
                    can_continue: record.state == BtcTxState::Signed && !busy,
                    note: self.flow(&record.txid).and_then(|flow| flow.note.clone()),
                }
            })
            .collect();
        if let Some(meta) = ctx.meta {
            let tag = ctx.active_id().activity_tag();
            for entry in meta.activity_of(&network_id(net).to_string()) {
                if entry.account != tag {
                    continue;
                }
                if rows.iter().any(|row| row.txid == entry.tx_id) {
                    continue;
                }
                rows.push(BtcActivityView {
                    amount: entry.amount.parse::<u64>().ok().and_then(Sats::new),
                    txid: entry.tx_id,
                    title: entry.title,
                    counterparty: entry.counterparty,
                    status: activity_status(&entry.status),
                    time_unix_ms: entry.time_unix_ms,
                    journal: false,
                    can_bump: false,
                    can_rebroadcast: false,
                    can_abandon: false,
                    can_esplora: false,
                    can_continue: false,
                    note: None,
                });
            }
        }
        rows.sort_by_key(|row| core::cmp::Reverse(row.time_unix_ms));
        rows.truncate(BTC_MAX_ACTIVITY_ROWS);
        rows
    }

    /// `Signed` records found in the journal ([전송 계속] / [취소], spec/08 §12.1).
    #[must_use]
    pub fn signed_records(&self, ctx: &BtcCtx<'_>) -> Vec<Txid> {
        ctx.network_records()
            .iter()
            .filter(|record| record.state == BtcTxState::Signed)
            .filter(|record| {
                self.flow(&record.txid).is_none_or(|flow| {
                    matches!(flow.stage, BtcFlowStage::Waiting | BtcFlowStage::Done)
                })
            })
            .map(|record| record.txid)
            .collect()
    }

    /// The network banner of the settings network (spec/08 §2 table).
    #[must_use]
    pub fn banner(ctx: &BtcCtx<'_>) -> &'static str {
        ctx.net().banner()
    }
}

// ----- App glue ---------------------------------------------------------------------------------

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

fn layout_seed() -> Option<[u8; 32]> {
    let mut seed = [0_u8; 32];
    yw_core::entropy::fill_random(&mut seed).ok()?;
    Some(seed)
}

impl crate::app::App {
    /// Runs `call` on the controller with a fresh context and executes its actions.
    pub fn btc_call(&mut self, call: impl FnOnce(&mut BtcUi, &BtcCtx<'_>) -> Vec<BtcAction>) {
        let actions = {
            let ctx = BtcCtx {
                settings: &self.settings.bitcoin,
                apikeys: &self.apikeys,
                meta: self.meta.as_ref(),
                journal: self.evm.journal.as_ref(),
                unlocked: matches!(self.mode, crate::app::AppMode::Unlocked { .. }),
                has_mnemonic: self.keys.has_mnemonic,
                now_ms: yw_win::time::monotonic_ms(),
                now_unix_ms: now_unix_ms(),
            };
            call(&mut self.btc, &ctx)
        };
        self.btc_apply(actions);
    }

    /// [`Self::btc_call`] for worker results: the state they change (progress, test messages,
    /// balances, errors) is repainted even when the controller returns no action.
    pub fn btc_call_and_repaint(
        &mut self,
        call: impl FnOnce(&mut BtcUi, &BtcCtx<'_>) -> Vec<BtcAction>,
    ) {
        let mut acted = false;
        self.btc_call(|ui, ctx| {
            let actions = call(ui, ctx);
            acted = !actions.is_empty();
            actions
        });
        if !acted {
            self.refresh();
        }
    }

    /// Executes controller actions in order; a failed settings write stops the batch.
    pub fn btc_apply(&mut self, actions: Vec<BtcAction>) {
        if actions.is_empty() {
            return;
        }
        for action in actions {
            match action {
                BtcAction::Key(job) => self.key(*job),
                BtcAction::Rpc(job) => {
                    if !self.rpc(*job) {
                        self.btc.status_error = Some(ErrorCode::Rpc001.text());
                    }
                }
                BtcAction::SetMeta(btc, accounts) => {
                    // Accounts that left `btc_accounts` (an imported key removed): their stable
                    // addresses leave every dApp grant (spec/05 §4.9).
                    let gone: Vec<String> = self.meta.as_ref().map_or_else(Vec::new, |meta| {
                        meta.btc_accounts
                            .accounts
                            .iter()
                            .filter(|old| accounts.get(old.network(), old.id()).is_none())
                            .filter_map(|old| {
                                let address = old.address(BtcChain::Receive, 0).ok()?;
                                Some(address.as_str().to_owned())
                            })
                            .collect()
                    });
                    if let Some(meta) = self.meta.as_mut() {
                        meta.btc = btc;
                        meta.btc_accounts = *accounts;
                    }
                    if !gone.is_empty() {
                        self.btc_addresses_removed_from_sites(&gone);
                    }
                }
                BtcAction::Enqueue(item) => {
                    if self
                        .evm
                        .queue
                        .enqueue(
                            crate::ui::approval::QueueSource::App,
                            crate::app_evm::QueuedItem::Btc(item),
                        )
                        .is_ok()
                    {
                        self.show_next_approval();
                    } else {
                        self.btc.slot = false;
                        self.btc.send.info = Some(ErrorCode::App005.text());
                    }
                }
                BtcAction::SaveSettings(bitcoin, key) => {
                    if !self.btc_save_settings(&bitcoin, key) {
                        break;
                    }
                }
                BtcAction::Confirm => {
                    self.set_screen(crate::app::Screen::Confirm(crate::app::Confirm::Btc));
                }
                BtcAction::Screen(screen) => {
                    let target = match screen {
                        BtcScreen::Main => crate::app::Screen::Main,
                        BtcScreen::Send => crate::app::Screen::BtcSend,
                        // Like Solana: the result replaces the form only while it is shown.
                        BtcScreen::SendResult => {
                            if !matches!(
                                self.screen,
                                crate::app::Screen::BtcSend | crate::app::Screen::BtcBump
                            ) {
                                continue;
                            }
                            crate::app::Screen::BtcSendResult
                        }
                        BtcScreen::Bump => crate::app::Screen::BtcBump,
                        BtcScreen::Receive => crate::app::Screen::BtcReceive,
                        BtcScreen::Back => {
                            if matches!(self.screen, crate::app::Screen::Confirm(_)) {
                                self.previous_screen.clone()
                            } else {
                                self.screen.clone()
                            }
                        }
                    };
                    self.set_screen(target);
                }
                BtcAction::Banner(code, text) => self.banner(code, text),
            }
        }
        self.refresh();
    }

    /// Writes settings.json with `bitcoin`; `false` when the write failed (E-APP-002, the
    /// previous values stay).
    fn btc_save_settings(&mut self, bitcoin: &BitcoinSettings, key: &'static str) -> bool {
        let mut settings = self.settings.clone();
        settings.bitcoin = bitcoin.clone();
        self.save_settings(settings, key);
        self.settings.bitcoin == *bitcoin
    }

    /// Whether the Bitcoin tab is selected.
    #[must_use]
    pub fn btc_tab_active(&self) -> bool {
        self.meta
            .as_ref()
            .is_some_and(|meta| meta.prefs.tab == crate::meta::Tab::Btc)
    }

    /// Selects the Bitcoin tab (refresh on open, spec/08 §4.7).
    pub fn btc_select_tab(&mut self) {
        if let Some(meta) = self.meta.as_mut()
            && meta.prefs.tab != crate::meta::Tab::Btc
        {
            meta.prefs.tab = crate::meta::Tab::Btc;
            self.save_meta();
        }
        // A key-only wallet's tab works on its imported accounts (no BIP84 account 0).
        self.btc_call(BtcUi::open_tab);
    }

    /// Meta was loaded (unlock): `null` meta with BTC enabled → create and discover (a mnemonic
    /// wallet; a key-only wallet has nothing to create).
    pub fn btc_after_meta(&mut self) {
        self.btc_call(BtcUi::after_meta);
    }

    /// The journal view changed. The Bitcoin tab shown at unlock (`prefs.tab = "btc"`) is
    /// opened once the journal is read (refresh on open, spec/08 §4.7).
    pub fn btc_journal_changed(&mut self) {
        self.btc_call(BtcUi::journal_changed);
        if self.btc_tab_active() && self.btc.refresh.job == 0 && !self.btc.discovery.running {
            self.btc_call(BtcUi::open_tab);
        }
    }

    /// Lock: drop the unlocked state, reset the worker sessions.
    pub fn btc_lock(&mut self) {
        let actions = self.btc.lock();
        for action in actions {
            if let BtcAction::Rpc(job) = action {
                let _ = self.rpc(*job);
            }
        }
    }

    /// Main-timer part (60 s cycle while unlocked).
    pub fn btc_tick(&mut self, now: u64) {
        let _ = now;
        self.btc_call(BtcUi::tick);
    }

    /// A BTC key worker outcome.
    pub fn btc_key_outcome(&mut self, outcome: KeyOutcome) {
        self.btc_call_and_repaint(|ui, ctx| ui.on_key_outcome(ctx, outcome));
    }

    /// A BTC RPC worker event.
    pub fn btc_rpc_event(&mut self, event: BtcRpcEvent) {
        self.btc_call_and_repaint(|ui, ctx| ui.on_rpc_event(ctx, event));
    }

    /// The Core URL of `net` changed.
    pub fn btc_url_changed(&mut self, net: crate::network::BtcNet) {
        let _ = net;
        self.btc_call(|ui, _| ui.url_changed());
    }

    /// BTC 켜기.
    pub fn btc_enable(&mut self, network: BtcNetwork) {
        self.btc_call(|ui, ctx| ui.enable(ctx, network));
    }

    /// BTC 끄기.
    pub fn btc_disable(&mut self) {
        self.btc_call(BtcUi::disable);
    }

    /// 네트워크 선택 (confirmation first).
    pub fn btc_choose_network(&mut self, network: BtcNetwork) {
        self.btc_call(|ui, ctx| ui.choose_network(ctx, network));
    }

    /// [설정을 {`BtcMeta` 값}으로 되돌리기].
    pub fn btc_mismatch_keep_meta(&mut self) {
        self.btc_call(BtcUi::mismatch_keep_meta);
    }

    /// [{settings 값}으로 바꾸기].
    pub fn btc_mismatch_use_settings(&mut self) {
        self.btc_call(BtcUi::mismatch_use_settings);
    }

    /// Indexer radio (`bb-*` asks T-BTC-BB-OPTIN first).
    pub fn btc_set_indexer(&mut self, indexer: BtcIndexer) {
        self.btc_call(|ui, ctx| ui.set_indexer(ctx, indexer, false));
    }

    /// Esplora URL `저장`.
    pub fn btc_save_esplora_url(&mut self, net: BtcNetwork, text: &str) {
        self.btc_call(|ui, ctx| ui.save_esplora_url(ctx, net, text));
    }

    /// Esplora URL `기본값으로`.
    pub fn btc_default_esplora_url(&mut self, net: BtcNetwork) {
        self.btc_call(|ui, ctx| ui.default_esplora_url(ctx, net));
    }

    /// Esplora URL `테스트` (allowed while locked).
    pub fn btc_test_esplora_url(&mut self, net: BtcNetwork, text: &str) {
        self.btc_call(|ui, ctx| ui.test_esplora_url(ctx, net, text));
    }

    /// The BTC confirmation overlay's yes button.
    pub fn btc_confirm_yes(&mut self) {
        self.btc_call(BtcUi::confirm_yes);
    }

    /// The BTC confirmation overlay's no button.
    pub fn btc_confirm_no(&mut self) {
        self.btc_call(|ui, _| ui.confirm_no());
    }

    /// `새로고침`.
    pub fn btc_refresh(&mut self) {
        self.btc_call(|ui, ctx| ui.refresh(ctx, Trigger::User));
    }

    /// Discovery [다시 시도] (`more = false`) or "더 찾기" (`more = true`).
    pub fn btc_discover(&mut self, more: bool) {
        self.btc_call(|ui, ctx| ui.discover(ctx, more));
    }

    /// Cancels the running discovery.
    pub fn btc_cancel_discovery(&mut self) {
        self.btc.cancel_discovery();
        self.refresh();
    }

    /// Opens S12 for Bitcoin.
    pub fn btc_open_receive(&mut self) {
        self.btc_call(BtcUi::open_receive);
    }

    /// "새 주소".
    pub fn btc_new_receive_address(&mut self) {
        self.btc_call(BtcUi::new_receive_address);
    }

    /// Copies the receive address (plain clipboard, not a secret).
    pub fn btc_copy_address(&mut self) {
        if let Some(address) = self.btc.receive.as_ref().map(|view| view.address.clone()) {
            self.copy_text(&address);
        }
    }

    /// Opens S11 for Bitcoin.
    pub fn btc_open_send(&mut self) {
        self.btc_call(BtcUi::open_send);
    }

    /// Form edits (recipient, amount, unit, send-max, fee choice, manual rate, typed fee).
    pub fn btc_form(&mut self, edit: impl FnOnce(&mut BtcUi, &BtcCtx<'_>)) {
        self.btc_call(|ui, ctx| {
            edit(ui, ctx);
            Vec::new()
        });
        self.refresh();
    }

    /// `검토` of the send form.
    pub fn btc_review(&mut self) {
        let Some(seed) = layout_seed() else {
            self.btc.send.info = Some(ErrorCode::Vlt005.text());
            self.refresh();
            return;
        };
        self.btc_call(|ui, ctx| ui.review(ctx, seed));
    }

    /// Opens the fee-bump form (S10 `수수료 올리기`).
    pub fn btc_open_bump(&mut self) {
        self.btc_call(BtcUi::open_bump);
    }

    /// `검토` of the fee-bump form.
    pub fn btc_review_bump(&mut self) {
        let Some(seed) = layout_seed() else {
            self.btc.bump.info = Some(ErrorCode::Vlt005.text());
            self.refresh();
            return;
        };
        self.btc_call(|ui, ctx| ui.review_bump(ctx, seed));
    }

    /// [전송 계속] / pre-check [다시 시도].
    pub fn btc_continue(&mut self, txid: Txid) {
        self.btc_call(|ui, ctx| ui.continue_signed(ctx, txid));
    }

    /// [취소] of a `Signed` record.
    pub fn btc_cancel_signed(&mut self, txid: Txid) {
        self.btc_call(|ui, ctx| ui.cancel_signed(ctx, txid));
    }

    /// [블록 높이 기록 초기화] (confirmation first).
    pub fn btc_reset_tip(&mut self) {
        self.btc_call(BtcUi::reset_tip);
    }

    /// `주소 전체를 직접 확인했습니다` (W-ADDR-3).
    pub fn btc_toggle_address_ack(&mut self) {
        self.btc.toggle_address_ack();
    }

    /// [같은 바이트 다시 전송].
    pub fn btc_rebroadcast(&mut self, txid: Txid) {
        self.btc_call(|ui, ctx| ui.rebroadcast(ctx, txid));
    }

    /// [포기].
    pub fn btc_abandon(&mut self, txid: Txid) {
        self.btc_call(|ui, ctx| ui.abandon(ctx, txid));
    }

    /// [Esplora로 전송].
    pub fn btc_esplora_broadcast(&mut self, txid: Txid) {
        self.btc_call(|ui, ctx| ui.esplora_broadcast(ctx, txid));
    }

    /// Freeze / unfreeze a UTXO.
    pub fn btc_freeze(&mut self, outpoint: OutPoint, frozen: bool) {
        self.btc_call(|_, ctx| BtcUi::freeze(ctx, outpoint, frozen));
    }

    /// A1 "prepare" of a BTC item: the draft from the queued plan (no network call).
    pub(crate) fn prepare_btc(&mut self, item: &BtcApprovalItem) {
        let Ok(id) = Self::new_approval_id() else {
            self.show_failure(ErrorCode::Vlt005, false, ErrorCode::Vlt005.text());
            return;
        };
        match BtcUi::draft(item, id) {
            Ok(draft) => self.show_ready_draft_at(draft, None, now_unix_ms()),
            Err(code) => self.show_failure(code, false, code.text()),
        }
    }

    /// `consume` succeeded for a BTC item; a `YubiKey` account first goes through the card step
    /// (PIN window, then `SignBtcCard`, spec/10 §6.3).
    pub(crate) fn btc_consumed(&mut self, approved: Approved, item: &BtcApprovalItem) {
        let kind = crate::app_card::CardJobKind::Btc {
            plan: Box::new(item.plan.clone()),
            tip_height: item.tip_height,
        };
        if crate::yubikey::btc_plan_role(&item.plan).is_some() {
            self.btc.slot = true;
            if let Err(approved) = self.card_begin(approved, kind, None) {
                self.btc.slot = false;
                drop(approved);
            }
            return;
        }
        self.btc_call(|ui, ctx| ui.consumed(ctx, approved, item));
    }

    /// A BTC approval ended.
    pub(crate) fn btc_approval_finished(&mut self, item: &BtcApprovalItem, outcome: QueueOutcome) {
        self.btc.approval_finished(item, outcome);
        logging::info(
            "app",
            "approval.finished",
            &[
                ("net", Field::Net(item.network_id())),
                (
                    "outcome",
                    Field::Word(crate::app_evm::outcome_name(outcome)),
                ),
            ],
        );
        self.refresh();
    }

    /// The name of a Bitcoin account with the source tag of a derived account (`네이티브 세그윗
    /// 계정 0  [니모닉 2]`, spec/02 §8.6); other keys keep their names.
    #[must_use]
    pub fn btc_account_label(&self, account: &BtcAccountKey) -> String {
        match account {
            BtcAccountKey::Hd {
                mnemonic,
                script_type,
                account: number,
                ..
            } => self.mnemonic_tagged(
                &format!("{} 계정 {number}", script_type.name()),
                mnemonic.map(|id| *id.as_bytes()),
            ),
            other => account_label(other),
        }
    }

    /// The Bitcoin part of [`App::mnemonic_busy`].
    #[must_use]
    pub fn btc_mnemonic_busy(&self, id: yw_core::vault::RecordId) -> bool {
        self.btc.mnemonic_busy(&self.btc_ctx(), id)
    }

    /// The Bitcoin "계정 추가" mnemonic radio (several mnemonics, spec/02 §8.6).
    pub fn btc_pick_mnemonic(&mut self, id: yw_core::vault::RecordId, primary: bool) {
        self.btc.set_add_mnemonic((!primary).then_some(id));
        self.refresh();
    }

    /// The BTC controller context (read-only views for the screens).
    #[must_use]
    pub fn btc_ctx(&self) -> BtcCtx<'_> {
        BtcCtx {
            settings: &self.settings.bitcoin,
            apikeys: &self.apikeys,
            meta: self.meta.as_ref(),
            journal: self.evm.journal.as_ref(),
            unlocked: matches!(self.mode, crate::app::AppMode::Unlocked { .. }),
            has_mnemonic: self.keys.has_mnemonic,
            now_ms: yw_win::time::monotonic_ms(),
            now_unix_ms: now_unix_ms(),
        }
    }
}
