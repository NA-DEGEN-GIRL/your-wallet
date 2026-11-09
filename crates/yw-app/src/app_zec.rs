//! The Zcash tab controller (spec/12 §11, spec/04 §2.6): enable and network, the account (key
//! source and cached public key in meta `zcash`), refresh (chain check, UTXOs, tracking),
//! receive, the send form → plan → approval → signing (vault or `YubiKey`) → disclose →
//! `sendrawtransaction`, and the journal transitions the refresh observes.

use yw_core::approval::Approved;
use yw_core::journal::zec::{ZecRecord, ZecTransition, ZecTxState};
use yw_core::keyimport::ZecKeyInfo;
use yw_core::zec::address::parse_recipient;
use yw_core::zec::upgrade::tx_consensus;
use yw_core::zec::{
    ZecAccount, ZecAmount, ZecKeySource, ZecNetwork, ZecPlan, ZecSendRequest, parse_user_zec,
    plan_send,
};

use crate::app::{App, AppMode};
use crate::errors::ErrorCode;
use crate::events::KeyJob;
use crate::logging::{self, Field};
use crate::network::NetworkId;
use crate::workers::journal::zec::{ZecKeyJob, ZecKeyOutcome, ZecSignedSummary};
use crate::workers::rpc::RpcJob;
use crate::zec::rpc::{SendOutcome, TxStatus, ZecRpcError};
use crate::zec::work::{ZecRpcEvent, ZecRpcJob, ZecSnapshot};

/// The banner of a hardware account whose key no enrolled card holds any more.
pub const T_ZEC_HW_MISSING: &str = "이 Zcash 계정의 YubiKey 키를 등록된 YubiKey에서 찾을 수 없습니다 (슬롯을 바꾸었거나 비웠습니다). 받기와 보내기를 멈췄습니다. 그 키가 있는 YubiKey를 다시 등록하거나, 원하면 키 출처를 '표준'으로 바꾸세요(다른 주소가 됩니다).";

/// Automatic refresh period while the tab is shown (and while a transaction is in flight).
const REFRESH_MS: u64 = yw_core::zec::ZEC_POLL_SECS * 1_000;
/// A record the node refused (`Rejected`) is handed over again at most once per this many
/// blocks until it expires (spec/12 §12.2): the same bytes were just refused, and resending on
/// every 30 s refresh only repeats the answer.
const REJECTED_RESEND_BLOCKS: u32 = 10;
/// `삭제` of an imported Zcash key while a transaction of its account may still confirm.
pub const ZEC_REMOVE_BUSY: &str =
    "진행 중인 Zcash 거래가 이 키를 쓰고 있어 지울 수 없습니다. 확인되거나 만료된 뒤에 지우세요.";
/// `삭제` of an imported Zcash key while its transactions cannot be checked.
pub const ZEC_REMOVE_UNCHECKED: &str = "Zcash 거래 기록을 아직 읽지 못했거나 손상된 Zcash 기록이 있어, 이 키로 보낸 거래가 끝났는지 확인할 수 없습니다. 기록을 읽은 뒤(손상은 복구한 뒤) 다시 지우세요.";

/// The key source the account card offers (spec/12 §2.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SourceChoice {
    /// `m/44'/{133|1}'/0'/0/0` (default).
    #[default]
    Standard,
    /// The EVM key `m/44'/60'/0'/0/i` (explicit, with the linkage warning).
    EvmShared(u32),
}

/// A queued Zcash approval (spec/12 §9).
#[derive(Clone, Debug)]
pub struct ZecApprovalItem {
    /// The plan (bound by the approval payload).
    pub plan: ZecPlan,
}

impl ZecApprovalItem {
    /// `zcash:<net>`.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        NetworkId::Zcash(self.plan.account.network)
    }
}

/// Zcash UI state.
#[derive(Debug, Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent UI flags of one tab"
)]
pub struct ZecUi {
    job: u64,
    /// The last refresh answer of the shown network.
    pub snapshot: Option<(ZecNetwork, Box<ZecSnapshot>)>,
    /// A refresh is running.
    pub refreshing: bool,
    /// The running refresh ends in a review (plan → approval).
    review_after: bool,
    /// The last error (fixed text).
    pub error: Option<String>,
    /// The last information line.
    pub info: Option<String>,
    /// Send form: recipient.
    pub to_text: String,
    /// Send form: amount.
    pub amount_text: String,
    /// Send form: send everything.
    pub send_max: bool,
    /// An approval or signature is in progress (one at a time).
    pub busy: bool,
    /// A public-key job is running.
    key_pending: bool,
    /// Receive card QR shown.
    pub show_qr: bool,
    /// Key-source choice of the account card.
    pub source: SourceChoice,
    /// The EVM-key source needs one more confirmation (T-ZEC-EVM-SHARED).
    pub confirm_shared: bool,
    /// Signed and journaled, waiting for the `Disclose` commit before `sendrawtransaction`.
    pending_send: Option<ZecSignedSummary>,
    /// `(txid, tip)` of the last time a `Rejected` record was handed to the node (the resend
    /// backoff, [`REJECTED_RESEND_BLOCKS`]).
    rejected_resend: Option<([u8; 32], u32)>,
    next_refresh_ms: u64,
    /// The card slot maps of this session were read (the hardware account can be checked).
    hw_checked: bool,
}

/// Whether the account's `YubiKey` key is still on an enrolled card (spec/12 §2.2, spec/10 §15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZecHwState {
    /// Not a hardware account (or no account).
    NotHardware,
    /// The slot maps are not read yet: receive and send wait.
    Unchecked,
    /// An enrolled card holds the key.
    Present,
    /// No enrolled card holds it any more (slot change or clear): receive hidden, sending
    /// blocked, banner; the user may switch to the standard key source.
    Missing,
}

/// Whether some card of `records` (optionally only `serial` in `slots`) holds the Zcash key
/// `index` of `network` with `pubkey`.
fn zec_key_held(
    records: &[yw_core::yubikey::record::HwKeyRecord],
    account: &ZecAccount,
    only: Option<(u32, &[yw_core::yubikey::plan::CardSlot])>,
) -> bool {
    let ZecKeySource::Hardware { index } = account.source else {
        return false;
    };
    records
        .iter()
        .filter(|record| only.is_none_or(|(serial, _)| record.serial == serial))
        .flat_map(|record| &record.slots)
        .filter(|slot| only.is_none_or(|(_, slots)| slots.contains(&slot.slot)))
        .any(|slot| {
            slot.role
                == yw_core::yubikey::plan::KeyRole::Zec {
                    network: account.network,
                    index,
                }
                && slot.public == yw_core::yubikey::record::HwPublicKey::Secp256k1(account.pubkey)
        })
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

impl App {
    /// The Zcash tab is selected.
    #[must_use]
    pub fn zec_tab_active(&self) -> bool {
        self.meta
            .as_ref()
            .is_some_and(|meta| meta.prefs.tab == crate::meta::Tab::Zec)
    }

    /// Selects the Zcash tab (refresh on open).
    pub fn zec_select_tab(&mut self) {
        if let Some(meta) = self.meta.as_mut()
            && meta.prefs.tab != crate::meta::Tab::Zec
        {
            meta.prefs.tab = crate::meta::Tab::Zec;
            self.save_meta();
        }
        self.zec_ensure_account();
        self.zec_refresh(false);
        self.refresh();
    }

    /// The settings network.
    #[must_use]
    pub const fn zec_network(&self) -> ZecNetwork {
        self.settings.zcash.network
    }

    /// The account of the settings network, if known.
    #[must_use]
    pub fn zec_account(&self) -> Option<ZecAccount> {
        self.meta
            .as_ref()
            .and_then(|meta| meta.zcash.get(self.zec_network()).copied())
    }

    /// ZEC journal records of the current network and account.
    #[must_use]
    pub fn zec_records(&self) -> Vec<ZecRecord> {
        let Some(account) = self.zec_account() else {
            return Vec::new();
        };
        self.evm
            .journal
            .as_ref()
            .map(|journal| {
                journal
                    .zec_records
                    .iter()
                    .filter(|record| {
                        record.account.network == account.network
                            && record.account.pubkey == account.pubkey
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// A ZEC journal entry is undecodable (ZEC sending stops).
    #[must_use]
    pub fn zec_journal_damaged(&self) -> bool {
        self.evm
            .journal
            .as_ref()
            .is_some_and(|journal| journal.zec_corrupt > 0)
    }

    fn zec_url(&self) -> Result<yw_win::http::HttpsUrl, ErrorCode> {
        self.apikeys
            .rpc_url(NetworkId::Zcash(self.zec_network()))
            .ok_or(ErrorCode::Key005)
    }

    /// Asks the key worker for the account key when meta has none for the network.
    pub fn zec_ensure_account(&mut self) {
        if !self.settings.zcash.enabled
            || self.zec.key_pending
            || self.zec_account().is_some()
            || !matches!(self.mode, AppMode::Unlocked { .. })
        {
            return;
        }
        self.zec.key_pending = true;
        self.key(KeyJob::Zec(Box::new(ZecKeyJob::PublicKey {
            network: self.zec_network(),
            source: ZecKeySource::DEFAULT,
        })));
    }

    /// Uses another key source for the account (account card).
    pub fn zec_apply_source(&mut self) {
        let source = match self.zec.source {
            SourceChoice::Standard => ZecKeySource::DEFAULT,
            SourceChoice::EvmShared(index) => {
                if !self.zec.confirm_shared {
                    self.zec.confirm_shared = true;
                    self.refresh();
                    return;
                }
                ZecKeySource::EvmShared { evm_index: index }
            }
        };
        self.zec.confirm_shared = false;
        if self.zec.busy || !self.zec_records().iter().all(ZecRecord::is_terminal) {
            self.zec.error =
                Some("진행 중인 Zcash 거래가 있어 키 출처를 바꿀 수 없습니다.".to_owned());
            self.refresh();
            return;
        }
        self.zec.key_pending = true;
        self.key(KeyJob::Zec(Box::new(ZecKeyJob::PublicKey {
            network: self.zec_network(),
            source,
        })));
    }

    /// The hardware account check against the vault's card records (re-evaluated on every meta
    /// load and card record change, since both feed it).
    #[must_use]
    pub fn zec_hw_state(&self) -> ZecHwState {
        let Some(account) = self.zec_account() else {
            return ZecHwState::NotHardware;
        };
        if !account.is_hardware() {
            return ZecHwState::NotHardware;
        }
        if !self.zec.hw_checked {
            return ZecHwState::Unchecked;
        }
        if zec_key_held(&self.card.records, &account, None) {
            ZecHwState::Present
        } else {
            ZecHwState::Missing
        }
    }

    /// The card slot maps were (re)read: the hardware Zcash account is checked from now on.
    pub fn zec_card_records_changed(&mut self) {
        self.zec.hw_checked = true;
        if self.zec_hw_state() == ZecHwState::Missing {
            logging::warn("app", "zec.hardware_key_missing", &[]);
        }
    }

    /// The Zcash accounts (every network) whose `YubiKey` key only card `serial` holds, in one
    /// of `slots`: clearing or re-slotting those slots orphans them (spec/10 §15). The `YubiKey`
    /// clear / slot-change screens warn with this before writing.
    #[must_use]
    pub fn zec_accounts_using_card(
        &self,
        serial: u32,
        slots: &[yw_core::yubikey::plan::CardSlot],
    ) -> Vec<ZecAccount> {
        let Some(meta) = self.meta.as_ref() else {
            return Vec::new();
        };
        ZecNetwork::ALL
            .into_iter()
            .filter_map(|network| meta.zcash.get(network).copied())
            .filter(|account| {
                zec_key_held(&self.card.records, account, Some((serial, slots)))
                    && !self
                        .card
                        .records
                        .iter()
                        .filter(|record| record.serial != serial)
                        .any(|record| zec_key_held(core::slice::from_ref(record), account, None))
            })
            .collect()
    }

    fn zec_all_terminal(&self) -> bool {
        !self.zec.busy && self.zec_records().iter().all(ZecRecord::is_terminal)
    }

    /// Uses the `YubiKey` Zcash slot `index` of the current network as the account (spec/10).
    pub fn zec_use_hardware(&mut self, index: u32) {
        if !self.zec_all_terminal() {
            self.zec.error =
                Some("진행 중인 Zcash 거래가 있어 키 출처를 바꿀 수 없습니다.".to_owned());
            self.refresh();
            return;
        }
        let network = self.zec_network();
        let role = yw_core::yubikey::plan::KeyRole::Zec { network, index };
        let identity = role.key_identity();
        let public = self
            .card
            .records
            .iter()
            .flat_map(|record| &record.slots)
            .find(|slot| slot.role.key_identity() == identity)
            .map(|slot| slot.public);
        let Some(yw_core::yubikey::record::HwPublicKey::Secp256k1(pubkey)) = public else {
            self.zec.error = Some("이 네트워크의 Zcash 키가 등록된 YubiKey가 없습니다.".to_owned());
            self.refresh();
            return;
        };
        self.zec_set_account(ZecAccount {
            network,
            source: ZecKeySource::Hardware { index },
            pubkey,
        });
    }

    /// Imported Zcash keys of the current network (vault tag 6, spec/12 §2.3), in vault order.
    #[must_use]
    pub fn zec_imported_keys(&self) -> Vec<(yw_core::vault::RecordId, ZecKeyInfo)> {
        let network = self.zec_network();
        self.keys
            .zec_keys
            .iter()
            .filter(|(_, info)| info.network == network)
            .cloned()
            .collect()
    }

    /// The vault record of the current account when it is an imported key.
    #[must_use]
    pub fn zec_selected_imported(&self) -> Option<yw_core::vault::RecordId> {
        let account = self
            .zec_account()
            .filter(|account| account.source == ZecKeySource::Imported)?;
        self.keys
            .zec_keys
            .iter()
            .find(|(_, info)| info.network == account.network && info.pubkey == account.pubkey)
            .map(|(id, _)| *id)
    }

    /// Uses the standard key `m/44'/{coin}'/0'/0/0` of the added mnemonic `id` as the account
    /// (spec/02 §8.6; refused while a transaction is in flight, like every source change).
    pub fn zec_use_mnemonic(&mut self, id: yw_core::vault::RecordId) {
        if !self.zec_all_terminal() {
            self.zec.error =
                Some("진행 중인 Zcash 거래가 있어 키 출처를 바꿀 수 없습니다.".to_owned());
            self.refresh();
            return;
        }
        self.zec.key_pending = true;
        self.key(KeyJob::Zec(Box::new(ZecKeyJob::PublicKey {
            network: self.zec_network(),
            source: ZecKeySource::Mnemonic {
                mnemonic: id,
                account: 0,
                index: 0,
            },
        })));
        self.refresh();
    }

    /// The key source's name; an added mnemonic's source names the mnemonic
    /// (`[니모닉 2] Zcash 표준 경로`).
    #[must_use]
    pub fn zec_source_label(&self, source: ZecKeySource) -> String {
        match source {
            ZecKeySource::Mnemonic {
                mnemonic,
                account,
                index,
            } => format!(
                "[{}] {}",
                self.mnemonic_label(mnemonic),
                ZecKeySource::Derived { account, index }.label()
            ),
            other => other.label(),
        }
    }

    /// Uses imported key `position` of the current network's list as the account.
    pub fn zec_use_imported(&mut self, position: usize) {
        let Some((_, info)) = self.zec_imported_keys().into_iter().nth(position) else {
            return;
        };
        if !self.zec_all_terminal() {
            self.zec.error =
                Some("진행 중인 Zcash 거래가 있어 키 출처를 바꿀 수 없습니다.".to_owned());
            self.refresh();
            return;
        }
        self.zec_set_account(info.account());
    }

    /// A Zcash key was imported: it becomes the account of its network when that network is the
    /// tab's and nothing is in flight (otherwise it waits in the list).
    pub fn zec_imported(&mut self, info: &ZecKeyInfo) {
        if info.network == self.zec_network() && self.zec_all_terminal() {
            self.zec_set_account(info.account());
            self.zec.info = Some("가져온 키를 이 네트워크의 Zcash 계정으로 씁니다.".to_owned());
        } else {
            self.zec.info = Some(format!(
                "가져온 키를 목록에 더했습니다 ({}). 그 네트워크에서 '이 키 사용'으로 고르세요.",
                info.network.display_name()
            ));
        }
    }

    /// `삭제` of an imported Zcash key is refused while the account on it has a transaction that
    /// may still confirm (like an imported Bitcoin key, spec/08 §3.5), and while its records
    /// cannot be checked: the journal is not loaded yet or has a damaged ZEC record (the key
    /// worker applies the same rule, `JournalWorker::zec_imported_busy`).
    #[must_use]
    pub fn zec_remove_block(&self, id: [u8; 16]) -> Option<&'static str> {
        let (_, info) = self
            .keys
            .zec_keys
            .iter()
            .find(|(record, _)| *record.as_bytes() == id)?;
        let Some(journal) = self
            .evm
            .journal
            .as_ref()
            .filter(|journal| journal.zec_corrupt == 0)
        else {
            return Some(ZEC_REMOVE_UNCHECKED);
        };
        let busy = journal.zec_records.iter().any(|record| {
            record.account.network == info.network
                && record.account.pubkey == info.pubkey
                && !record.is_terminal()
        });
        (busy
            || (self.zec.busy
                && self
                    .zec_selected_imported()
                    .is_some_and(|key| *key.as_bytes() == id)))
        .then_some(ZEC_REMOVE_BUSY)
    }

    /// An imported Zcash key left the vault: the list drops it, and an account on it goes back
    /// to the default key (made again by the key worker).
    pub fn zec_imported_removed(&mut self, id: [u8; 16]) {
        let removed = self
            .keys
            .zec_keys
            .iter()
            .position(|(record, _)| *record.as_bytes() == id)
            .map(|position| self.keys.zec_keys.remove(position));
        let Some((_, info)) = removed else {
            return;
        };
        let on_it = self.meta.as_ref().is_some_and(|meta| {
            meta.zcash.get(info.network).is_some_and(|account| {
                account.source == ZecKeySource::Imported && account.pubkey == info.pubkey
            })
        });
        if on_it && let Some(meta) = self.meta.as_mut() {
            meta.zcash.clear(info.network);
            self.zec.snapshot = None;
            self.save_meta();
            self.zec_ensure_account();
        }
    }

    fn zec_set_account(&mut self, account: ZecAccount) {
        if let Some(meta) = self.meta.as_mut() {
            meta.zcash.set(account);
            self.save_meta();
        }
        self.zec.snapshot = None;
        self.zec_refresh(false);
        self.refresh();
    }

    /// Turns Zcash on with `network` (or switches the network).
    pub fn zec_enable(&mut self, network: ZecNetwork) {
        if self.zec.busy {
            return;
        }
        // A switch away would stop tracking the in-flight record of this network.
        if network != self.zec_network() && !self.zec_all_terminal() {
            self.zec.error =
                Some("진행 중인 Zcash 거래가 있어 네트워크를 바꿀 수 없습니다.".to_owned());
            self.refresh();
            return;
        }
        let mut settings = self.settings.clone();
        settings.zcash.enabled = true;
        settings.zcash.network = network;
        self.save_settings(settings, "zcash");
        self.zec.snapshot = None;
        self.zec.error = None;
        self.zec_ensure_account();
        self.zec_refresh(false);
    }

    /// Turns Zcash off (only without a transaction in flight).
    pub fn zec_disable(&mut self) {
        if self.zec.busy || !self.zec_records().iter().all(ZecRecord::is_terminal) {
            self.zec.error = Some("진행 중인 Zcash 거래가 있어 끌 수 없습니다.".to_owned());
            self.refresh();
            return;
        }
        let mut settings = self.settings.clone();
        settings.zcash.enabled = false;
        self.save_settings(settings, "zcash");
    }

    /// Selects the UTXO source.
    pub fn zec_set_indexer(&mut self, indexer: crate::settings::ZecIndexer) {
        let mut settings = self.settings.clone();
        settings.zcash.indexer = indexer;
        self.save_settings(settings, "zcash");
        self.zec_refresh(false);
    }

    /// Starts a refresh (chain check, UTXOs, tracking); `review` plans the send form after it.
    pub fn zec_refresh(&mut self, review: bool) {
        if !self.settings.zcash.enabled || !matches!(self.mode, AppMode::Unlocked { .. }) {
            return;
        }
        let Some(account) = self.zec_account() else {
            return;
        };
        let url = match self.zec_url() {
            Ok(url) => url,
            Err(code) => {
                self.zec.error = Some(code.text());
                self.zec.review_after = false;
                self.refresh();
                return;
            }
        };
        let records = self.zec_records();
        let live = || records.iter().filter(|record| record.may_still_confirm());
        let track = live().map(ZecRecord::txid_hex).collect();
        let watch = live().flat_map(ZecRecord::inputs).collect();
        // What is known (spec/12 §4.3), sent from when the next address answer is over its
        // limits: the largest outputs of the last answer and the change of our mined sends,
        // without the outputs our own sends spent or hold.
        let last: &[yw_core::zec::ZecUtxo] = self
            .zec
            .snapshot
            .as_ref()
            .filter(|(network, _)| *network == account.network)
            .map_or(&[], |(_, snapshot)| snapshot.utxos.as_slice());
        let known = yw_core::journal::zec::over_limit_known(last, &records);
        self.zec.job = self.zec.job.wrapping_add(1);
        self.zec.refreshing = true;
        self.zec.review_after = review;
        self.zec.next_refresh_ms = yw_win::time::monotonic_ms().saturating_add(REFRESH_MS);
        let sent = self.rpc(RpcJob::Zec(Box::new(ZecRpcJob::Refresh {
            job: self.zec.job,
            network: account.network,
            url,
            indexer: self.settings.zcash.indexer,
            address: account.address(),
            script_hex: yw_core::hex::encode(&account.script_pubkey()),
            track,
            watch,
            known,
        })));
        if !sent {
            self.zec.refreshing = false;
            self.zec.review_after = false;
        }
    }

    /// Periodic refresh while the tab is shown or a record may still confirm.
    pub fn zec_tick(&mut self, now: u64) {
        if self.zec.refreshing || now < self.zec.next_refresh_ms {
            return;
        }
        let in_flight = self.zec_records().iter().any(ZecRecord::may_still_confirm);
        if self.zec_tab_active() || in_flight {
            self.zec_refresh(false);
        } else {
            self.zec.next_refresh_ms = now.saturating_add(REFRESH_MS);
        }
    }

    /// Lock: forget everything of the session.
    pub fn zec_lock(&mut self) {
        self.zec = ZecUi::default();
    }

    /// `검토`: refresh first (fresh tip, branch id and UTXOs), then plan.
    pub fn zec_review(&mut self) {
        if self.zec.busy {
            self.zec.error = Some("Zcash 승인이 이미 진행 중입니다.".to_owned());
            self.refresh();
            return;
        }
        if self.zec_journal_damaged() {
            self.zec.error = Some(
                yw_core::journal::zec::ZecJournalBlock::Corrupt
                    .text()
                    .to_owned(),
            );
            self.refresh();
            return;
        }
        self.zec.error = None;
        self.zec.info = Some("Zcash 노드를 확인하는 중…".to_owned());
        self.zec_refresh(true);
        self.refresh();
    }

    fn zec_plan(&self, snapshot: &ZecSnapshot) -> Result<ZecPlan, String> {
        let account = self
            .zec_account()
            .ok_or_else(|| "Zcash 계정을 아직 불러오지 못했습니다.".to_owned())?;
        let records = self.zec_records();
        if records.iter().any(ZecRecord::may_still_confirm) {
            return Err(yw_core::journal::zec::ZecJournalBlock::InFlight
                .text()
                .to_owned());
        }
        let recipient = parse_recipient(&self.zec.to_text, account.network)
            .map_err(|error| error.text().to_owned())?;
        let amount = if self.zec.send_max {
            ZecAmount::Max
        } else {
            ZecAmount::Exact(
                parse_user_zec(&self.zec.amount_text)
                    .map_err(|_| "보낼 금액(ZEC)을 올바르게 입력하세요.".to_owned())?,
            )
        };
        // Over the limits only part is shown, but that part can still be sent from.
        if let Some(error) = snapshot.utxo_error
            && error != ZecRpcError::TooMany
        {
            return Err(error.text());
        }
        match self.zec_hw_state() {
            ZecHwState::NotHardware | ZecHwState::Present => {}
            ZecHwState::Unchecked => {
                return Err("YubiKey 정보를 확인하는 중입니다. 잠시 후 다시 시도하세요.".to_owned());
            }
            ZecHwState::Missing => return Err(T_ZEC_HW_MISSING.to_owned()),
        }
        let consensus = tx_consensus(account.network, &snapshot.chain.consensus)
            .map_err(yw_core::zec::UpgradeError::text)?;
        let reserved = self
            .evm
            .journal
            .as_ref()
            .map(|journal| {
                journal
                    .zec_records
                    .iter()
                    .filter(|record| {
                        record.reserves_inputs() && record.account.network == account.network
                    })
                    .flat_map(ZecRecord::inputs)
                    .collect()
            })
            .unwrap_or_default();
        plan_send(
            &account,
            &ZecSendRequest {
                recipient,
                amount,
                utxos: snapshot.utxos.clone(),
                reserved,
                consensus,
            },
        )
        .map_err(yw_core::zec::ZecPlanError::text)
    }

    fn zec_enqueue(&mut self, plan: ZecPlan) {
        let item = ZecApprovalItem { plan };
        if self
            .evm
            .queue
            .enqueue(
                crate::ui::approval::QueueSource::App,
                crate::app_evm::QueuedItem::Zec(Box::new(item)),
            )
            .is_ok()
        {
            self.zec.busy = true;
            self.zec.info = None;
            self.show_next_approval();
        } else {
            self.zec.error = Some(ErrorCode::App005.text());
        }
    }

    /// The approval draft of a queued item (no network call).
    pub(crate) fn prepare_zec(&mut self, item: &ZecApprovalItem) {
        let Ok(id) = yw_core::approval::ApprovalId::random() else {
            self.show_failure(ErrorCode::Vlt005, false, ErrorCode::Vlt005.text());
            return;
        };
        match yw_core::zec::display::build_zec_request(id, &item.plan) {
            Ok(draft) => self.show_ready_draft_at(draft, None, now_unix_ms()),
            Err(_) => self.show_failure(ErrorCode::App009, false, ErrorCode::App009.text()),
        }
    }

    /// `consume` succeeded: a `YubiKey` account goes through the card step, otherwise the vault
    /// signs.
    pub(crate) fn zec_consumed(&mut self, approved: Approved, item: &ZecApprovalItem) {
        if item.plan.account.is_hardware() {
            let kind = crate::app_card::CardJobKind::Zec {
                plan: Box::new(item.plan.clone()),
            };
            if self.card_begin(approved, kind, None).is_err() {
                self.zec.busy = false;
            }
            return;
        }
        self.key(KeyJob::Zec(Box::new(ZecKeyJob::Sign {
            approved: Box::new(approved),
            plan: Box::new(item.plan.clone()),
            now_unix_ms: now_unix_ms(),
        })));
    }

    /// A Zcash approval ended (rejected, expired, cancelled): free the form.
    pub(crate) fn zec_approval_finished(
        &mut self,
        item: &ZecApprovalItem,
        outcome: crate::ui::approval::QueueOutcome,
    ) {
        if outcome != crate::ui::approval::QueueOutcome::Approved {
            self.zec.busy = false;
        }
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

    /// The card step was cancelled.
    pub(crate) fn zec_card_cancelled(&mut self) {
        self.zec.busy = false;
    }

    /// A Zcash key-worker outcome.
    pub fn zec_key_outcome(&mut self, outcome: ZecKeyOutcome) {
        match outcome {
            ZecKeyOutcome::PublicKey(result) => {
                self.zec.key_pending = false;
                match result {
                    Ok(account) => self.zec_set_account(account),
                    Err(text) => self.zec.error = Some(text),
                }
            }
            ZecKeyOutcome::Signed(result) => match result {
                Ok(summary) => {
                    self.zec.info = Some("서명했습니다. Zcash 노드로 보내는 중…".to_owned());
                    self.zec.to_text.clear();
                    self.zec.amount_text.clear();
                    self.zec.send_max = false;
                    let txid = summary.txid;
                    self.zec.pending_send = Some(summary);
                    // Disclose first: the record says "handed to a node" before any RPC sees it.
                    self.key(KeyJob::Zec(Box::new(ZecKeyJob::Journal {
                        txid,
                        transition: ZecTransition::Disclose,
                    })));
                }
                Err(failure) => {
                    self.zec.busy = false;
                    self.zec.info = None;
                    self.zec.error = Some(failure.text());
                }
            },
            ZecKeyOutcome::Journal { txid, state } => {
                // Only after the `Disclose` commit (or a record disclosed already) is the
                // transaction handed to the node (spec/12 §10.1).
                if self
                    .zec
                    .pending_send
                    .as_ref()
                    .is_some_and(|pending| pending.txid == txid)
                    && let Some(pending) = self.zec.pending_send.take()
                {
                    self.zec_send(pending.network, pending.raw, pending.txid);
                }
                if matches!(
                    state,
                    Some(
                        ZecTxState::Confirmed
                            | ZecTxState::Expired
                            | ZecTxState::Discarded
                            | ZecTxState::InputsSpent
                    )
                ) {
                    self.zec.busy = false;
                }
            }
            ZecKeyOutcome::JournalFailed { txid } => {
                // The disclose mark did not reach the disk: nothing is sent. `pending_send`
                // stays; the next refresh marks the record again and sends after that commit.
                if self
                    .zec
                    .pending_send
                    .as_ref()
                    .is_some_and(|pending| pending.txid == txid)
                {
                    self.zec.info = None;
                    self.zec.error = Some(
                        "거래 기록을 저장하지 못해 아직 보내지 않았습니다. 다음 새로고침 때 다시 시도합니다."
                            .to_owned(),
                    );
                }
            }
        }
        self.refresh();
    }

    fn zec_send(&mut self, network: ZecNetwork, raw: Vec<u8>, txid: [u8; 32]) {
        let Ok(url) = self.zec_url() else {
            self.zec.error = Some(
                "엔드포인트가 없어 아직 보내지 못했습니다. 다음 새로고침 때 다시 보냅니다."
                    .to_owned(),
            );
            return;
        };
        let _ = self.rpc(RpcJob::Zec(Box::new(ZecRpcJob::Send {
            network,
            url,
            raw,
            txid,
        })));
    }

    /// Whether the `Rejected` record `txid` may be handed to the node again at `tip`: the first
    /// time, or [`REJECTED_RESEND_BLOCKS`] blocks after the last attempt (which is then `tip`).
    fn zec_resend_due(&mut self, txid: [u8; 32], tip: u32) -> bool {
        if let Some((last, at)) = self.zec.rejected_resend
            && last == txid
            && tip < at.saturating_add(REJECTED_RESEND_BLOCKS)
        {
            return false;
        }
        self.zec.rejected_resend = Some((txid, tip));
        true
    }

    fn zec_journal(&self, txid: [u8; 32], transition: ZecTransition) {
        self.key(KeyJob::Zec(Box::new(ZecKeyJob::Journal {
            txid,
            transition,
        })));
    }

    /// A Zcash RPC result.
    pub fn zec_rpc_event(&mut self, event: ZecRpcEvent) {
        match event {
            ZecRpcEvent::Refreshed {
                job,
                network,
                result,
            } => {
                if job != self.zec.job {
                    return;
                }
                self.zec.refreshing = false;
                let review = core::mem::take(&mut self.zec.review_after);
                match result {
                    Ok(snapshot) => {
                        self.zec.error = snapshot.utxo_error.map(ZecRpcError::text);
                        self.zec_track(&snapshot);
                        if review {
                            self.zec.info = None;
                            match self.zec_plan(&snapshot) {
                                Ok(plan) => self.zec_enqueue(plan),
                                Err(text) => self.zec.error = Some(text),
                            }
                        }
                        self.zec.snapshot = Some((network, snapshot));
                    }
                    Err(error) => {
                        self.zec.info = None;
                        self.zec.error = Some(error.text());
                    }
                }
            }
            ZecRpcEvent::Sent { txid, outcome, .. } => match outcome {
                SendOutcome::Accepted => {
                    self.zec.info = Some(format!(
                        "보냈습니다. txid {}",
                        yw_core::zec::tx::txid_display(&txid)
                    ));
                    self.zec_journal(txid, ZecTransition::Broadcast);
                }
                SendOutcome::Rejected(code) => {
                    self.zec.error = Some(format!(
                        "Zcash 노드가 거래를 거부했습니다 (코드 {code}). 만료 높이가 지나면 입력이 풀립니다."
                    ));
                    // The resend backoff starts now (not on the next 30 s refresh).
                    let tip = self
                        .zec
                        .snapshot
                        .as_ref()
                        .map_or(0, |(_, snapshot)| snapshot.chain.tip);
                    self.zec.rejected_resend = Some((txid, tip));
                    self.zec_journal(txid, ZecTransition::Rejected);
                }
                SendOutcome::Unknown(code) => {
                    self.zec.error = Some(format!(
                        "전송 결과를 알 수 없습니다 ({}). 새로고침 때 다시 확인하고 보냅니다.",
                        code.code()
                    ));
                }
            },
        }
        self.refresh();
    }

    /// The journal transitions a refresh observes (spec/12 §12.2), and re-sending of records
    /// that may still confirm but the node does not know.
    fn zec_track(&mut self, snapshot: &ZecSnapshot) {
        let tip = snapshot.chain.tip;
        for record in self.zec_records() {
            if !record.may_still_confirm() {
                continue;
            }
            let txid = record.txid();
            let status = snapshot
                .tracked
                .iter()
                .find(|(known, _)| *known == record.txid_hex())
                .and_then(|(_, status)| status.as_ref().ok().copied());
            match status {
                Some(TxStatus::Mined(height)) => {
                    self.zec_journal(txid, ZecTransition::Mined(height));
                }
                Some(TxStatus::Known | TxStatus::NotFound)
                    if tip
                        > record
                            .expiry_height()
                            .saturating_add(yw_core::zec::ZEC_EXPIRED_AFTER) =>
                {
                    // "Not found" alone is not proof: Expired (inputs released) only while at
                    // least one input is still unspent; all spent → it may be in the chain.
                    // Unknown (the UTXO lookup failed) → wait for the next refresh, unless this
                    // endpoint can never tell (over the limits, no `gettxout`): then close it
                    // as InputsSpent (inputs stay reserved) instead of blocking sends forever.
                    if let Some(unspent) = snapshot.unspent_watch.as_ref() {
                        let any_unspent =
                            record.inputs().iter().any(|input| unspent.contains(input));
                        self.zec_journal(
                            txid,
                            if any_unspent {
                                ZecTransition::Expired
                            } else {
                                ZecTransition::InputsSpent
                            },
                        );
                    } else if snapshot.watch_unknowable {
                        self.zec_journal(txid, ZecTransition::InputsSpent);
                    }
                }
                Some(TxStatus::NotFound) if tip >= record.expiry_height() => {}
                Some(TxStatus::Known) => {
                    if record.state == ZecTxState::Signed {
                        self.zec_journal(txid, ZecTransition::Broadcast);
                    } else if record.not_found > 0 {
                        self.zec_journal(txid, ZecTransition::InMempool);
                    }
                }
                Some(TxStatus::NotFound) => {
                    if record.state == ZecTxState::Broadcast {
                        self.zec_journal(txid, ZecTransition::NotFound);
                    }
                    // A record the node refused goes again only every
                    // `REJECTED_RESEND_BLOCKS` blocks (each refusal just repeats the answer).
                    if record.state == ZecTxState::Rejected && !self.zec_resend_due(txid, tip) {
                        continue;
                    }
                    // Not known to the node and not expired: hand it over again (disclose
                    // first when it never was).
                    if record.disclosed {
                        self.zec_send(record.account.network, record.raw.clone(), txid);
                    } else {
                        self.zec.pending_send = Some(ZecSignedSummary {
                            network: record.account.network,
                            raw: record.raw.clone(),
                            txid,
                        });
                        self.zec_journal(txid, ZecTransition::Disclose);
                    }
                }
                None => {}
            }
        }
    }
}
