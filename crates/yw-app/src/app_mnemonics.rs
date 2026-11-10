//! Several recovery phrases in one wallet (spec/02 §8.6, spec/04 §2.24): the settings section
//! "복구 단어" (list with label, backup state and actions), "복구 단어 추가 가져오기" (W05 → W06 →
//! address preview → W03), "새 복구 단어 만들기 (추가)" (W03 → W08 → W10), rename, reveal (W03 →
//! W08), removal (strong warning → W03), the "계정 추가" mnemonic picker and the EVM accounts of
//! the added mnemonics (meta `mnemonics`, `EvmAccountPref::Mnemonic`).

use yw_core::bip32::path::AccountIndex;
use yw_core::error::VaultError;
use yw_core::evm::address::Address;
use yw_core::secret::Zeroizing;
use yw_core::vault::{BackupChallenge, EvmKeySource, MnemonicInfo, RecordId};

use crate::app::{App, AppMode, Purpose, Screen, SettingsSection};
use crate::errors::{key_code, vault_code};
use crate::events::KeyJob;
use crate::logging;
use crate::meta::{Account, EvmAccountPref};
use crate::text::is_valid_label;
use crate::ui::main_window::{Ctl, Item, Tone};
use crate::ui::screens_mnemonics::ids;
use crate::ui::secret::{DisplaySecret, SecretKind};
use crate::workers::key::mnemonics::{MnJob, MnOutcome};

/// What a secret window of the recovery-phrase flows is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MnPurpose {
    /// W05 of "복구 단어 추가 가져오기".
    ImportWords,
    /// W06 (two fields) of the same.
    ImportPassphrase,
    /// W03 after the address preview (the vault checks it while adding).
    ImportPassword,
    /// W03 of "새 복구 단어 만들기 (추가)".
    CreatePassword,
    /// W08 of a new or revealed mnemonic (`true`: the quiz follows the hold).
    ShowWords(RecordId, bool),
    /// W10 of mnemonic `id`.
    Backup(RecordId),
    /// W03 of `단어 보기` (`true`: the quiz follows, `백업 확인`).
    RevealPassword(RecordId, bool),
    /// W03 of `지우기`.
    RemovePassword(RecordId),
}

/// The recovery-phrase UI state.
#[derive(Default)]
pub struct MnUi {
    /// The vault's mnemonics (from the last meta load).
    pub infos: Vec<MnemonicInfo>,
    /// The mnemonic whose label is being edited.
    pub rename: Option<RecordId>,
    /// The mnemonic whose removal waits for the warning's confirmation.
    pub confirm_remove: Option<RecordId>,
    /// The words of [`MnUi::confirm_remove`] were shown and held to the end in this removal
    /// (required before removing a phrase whose backup is not confirmed).
    pub remove_revealed: bool,
    /// The typed [`T_MN_REMOVE_WORD`] of an unconfirmed phrase's removal.
    pub remove_typed: String,
    /// Input error of the removal warning.
    pub remove_error: Option<String>,
    /// The "계정 추가" mnemonic picker is open.
    pub add_pick: bool,
    /// The address preview of "복구 단어 추가 가져오기" (EIP-55 account 0).
    pub preview: Option<String>,
    /// The enrolled `YubiKey`s made from the previewed words (T-YK-SAME before saving).
    pub preview_cards: Vec<u32>,
    /// The T-YK-SAME checkbox of the preview.
    pub same_ack: bool,
    /// The passphrase window asks for mnemonic `position` of `count`.
    pub passphrase_for: Option<(usize, usize)>,
    /// The open quiz of an added mnemonic.
    challenge: Option<(RecordId, BackupChallenge)>,
    /// The words between W05 and W06.
    phrase: Option<Zeroizing<Vec<u8>>>,
}

impl core::fmt::Debug for MnUi {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("MnUi")
    }
}

/// T-MN-INTRO.
pub const T_MN_INTRO: &str = "지갑에 복구 단어(니모닉)를 여러 개(최대 8개) 둘 수 있습니다. 복구 단어마다 계정이 따로 생기고, 각 복구 단어는 따로 적어 두어야 합니다 — 한 복구 단어로 다른 복구 단어의 계정을 되찾을 수 없습니다.";
/// T-MN-REMOVE.
pub const T_MN_REMOVE: &str = "이 복구 단어와 그 계정이 지갑에서 사라집니다. 자금은 체인에 그대로 남지만, 이 복구 단어를 따로 적어 두지 않았다면 다시는 그 계정을 열 수 없습니다. 먼저 '단어 보기'로 적어 둔 단어와 같은지 확인하세요.";
/// T-MN-BUSY: removal refused while a transaction of the mnemonic's accounts may still confirm.
pub const T_MN_BUSY: &str = "이 복구 단어의 Solana·Bitcoin·Zcash 계정에서 보낸 거래가 아직 확정될 수 있어(진행 중, 공개된 거래 또는 승인 중) 지울 수 없습니다. 거래가 확정되거나 만료된 뒤에 다시 시도하세요. 거래 저널에 손상된 Solana·Bitcoin·Zcash 기록이 있으면 어느 계정의 거래인지 확인할 수 없어 지우지 않습니다.";
/// T-MN-UNCONFIRMED.
pub const T_MN_UNCONFIRMED: &str = "백업 확인 전입니다. 이 복구 단어의 계정은 받기만 되고 서명(보내기·연결 승인)은 백업 확인 뒤에 됩니다.";
/// T-MN-REMOVE-UNCONFIRMED: removal of a phrase whose backup is not confirmed.
pub const T_MN_REMOVE_UNCONFIRMED: &str = "백업하지 않은 복구 단어입니다. 지우면 이 PC 어디에도 단어가 남지 않아, 이 단어의 계정으로 받은 자산은 단어를 적어 두지 않았다면 영구히 잃습니다. 먼저 '단어 보기'로 단어를 끝까지 보고 적어 둔 뒤, 아래에 확인 문구를 입력해야 지울 수 있습니다.";
/// The phrase typed to remove a phrase whose backup is not confirmed.
pub const T_MN_REMOVE_WORD: &str = "백업 없이 지우기";
/// T-MN-RECEIVE-UNCONFIRMED: the receive screens of an unconfirmed phrase's accounts.
pub const T_MN_RECEIVE_UNCONFIRMED: &str = "백업하지 않은 복구 단어의 계정입니다. 이 주소로 받은 자산은 백업 확인 전에는 보낼 수 없고, 단어를 적어 두지 않은 채 잃으면 영구히 잃습니다. 받기 전에 설정 → 복구 단어에서 '백업 확인'을 마치세요.";
/// T-MN-ALT-PASS: phrases are not added, made or removed in a session opened with an
/// unverified passphrase (the vault refuses it too, spec/02 §7.5, §8.6).
pub const T_MN_ALT_PASS: &str = "확인되지 않은 passphrase로 연 지갑에서는 복구 단어를 더하거나 새로 만들거나 지울 수 없습니다(이 세션의 변경은 저장되지 않고, 같은 복구 단어가 두 번 들어갈 수 있습니다). 잠그고 passphrase를 다시 입력하세요.";

impl App {
    /// The label of mnemonic `id` (meta `mnemonics`; `니모닉 N` by vault position otherwise).
    #[must_use]
    pub fn mnemonic_label(&self, id: RecordId) -> String {
        if let Some(entry) = self.meta.as_ref().and_then(|meta| {
            meta.mnemonics
                .iter()
                .find(|entry| entry.record_id == *id.as_bytes())
        }) {
            return entry.label.clone();
        }
        let position = self
            .mn
            .infos
            .iter()
            .position(|info| info.id == id)
            .unwrap_or(0);
        crate::workers::key::mnemonics::default_label(position.saturating_add(1))
    }

    /// The label of the primary mnemonic.
    #[must_use]
    pub fn primary_mnemonic_label(&self) -> Option<String> {
        let primary = self.mn.infos.iter().find(|info| info.primary)?;
        Some(self.mnemonic_label(primary.id))
    }

    /// The wallet has more than one recovery phrase (account rows then name their source).
    #[must_use]
    pub fn several_mnemonics(&self) -> bool {
        self.mn.infos.len() > 1
    }

    /// `label` with the source tag of a derived account (`계정 1  [니모닉 2]`): the added
    /// mnemonic `mnemonic`'s label, or for the primary mnemonic's account (`None`) its label when
    /// the wallet has several (as the EVM rows); `label` unchanged otherwise.
    #[must_use]
    pub fn mnemonic_tagged(&self, label: &str, mnemonic: Option<[u8; 16]>) -> String {
        let tag = match mnemonic {
            Some(id) => Some(self.mnemonic_label(RecordId::from_bytes(id))),
            None => self
                .several_mnemonics()
                .then(|| self.primary_mnemonic_label())
                .flatten(),
        };
        tag.map_or_else(|| label.to_owned(), |tag| format!("{label}  [{tag}]"))
    }

    /// The name a site, a session or an approval shows for a derived account (2026-11-10):
    /// `{label} ({phrase label})` under the same condition as [`Self::mnemonic_tagged`] —
    /// parentheses, so the approval's `[내 계정: …]` note never nests brackets. Display only:
    /// addresses and grants are compared as before.
    #[must_use]
    pub fn mnemonic_named(&self, label: &str, mnemonic: Option<[u8; 16]>) -> String {
        let tag = match mnemonic {
            Some(id) => Some(self.mnemonic_label(RecordId::from_bytes(id))),
            None => self
                .several_mnemonics()
                .then(|| self.primary_mnemonic_label())
                .flatten(),
        };
        tag.map_or_else(|| label.to_owned(), |tag| format!("{label} ({tag})"))
    }

    /// Whether a Solana, Bitcoin or Zcash journal record of mnemonic `id`'s accounts may still
    /// confirm (a SOL `Pending`, a BTC record in flight / replaced / given up or refused inside
    /// the 30-day window, a ZEC record not final), or a Bitcoin approval of one of its accounts
    /// is open: the mnemonic is not removed then (like an imported key, spec/04 §2.18). A
    /// damaged SOL, BTC or ZEC journal record (its account is unknown) counts as busy, as in the
    /// key worker's check (`JournalState::mnemonic_busy`).
    #[must_use]
    pub fn mnemonic_busy(&self, id: RecordId) -> bool {
        let damaged = self.evm.journal.as_ref().is_some_and(|journal| {
            journal.sol_corrupt > 0 || journal.btc_corrupt > 0 || journal.zec_corrupt > 0
        });
        if damaged {
            return true;
        }
        let sol = self.sol_records().iter().any(|record| {
            record.state == yw_core::journal::sol::SolTxState::Pending
                && record.source.mnemonic() == Some(id)
        });
        let zec = self.evm.journal.as_ref().is_some_and(|journal| {
            journal.zec_records.iter().any(|record| {
                record.account.source.mnemonic() == Some(id) && record.may_still_confirm()
            })
        });
        sol || zec || self.btc_mnemonic_busy(id)
    }

    /// The first address of recovery phrase `id` as the meta has it — its EVM account 0 (the
    /// first phrase's is in `evm_accounts`) —, what W08 and the phrase's card show to compare
    /// with the paper (2026-11-10). Nothing is derived here; `None` when the meta has none.
    #[must_use]
    pub fn mnemonic_first_address(&self, id: RecordId) -> Option<Address> {
        let meta = self.meta.as_ref()?;
        let primary = self
            .mn
            .infos
            .iter()
            .any(|info| info.id == id && info.primary);
        let account = if primary {
            meta.evm_accounts.iter().find(|account| account.index == 0)
        } else {
            meta.mnemonics
                .iter()
                .find(|entry| entry.record_id == *id.as_bytes())?
                .evm
                .iter()
                .find(|account| account.index == 0)
        }?;
        yw_core::evm::address::parse_address(&account.address).ok()
    }

    /// How many accounts recovery phrase `id` has on each chain: `[EVM, Solana, Bitcoin (the
    /// current network), Zcash (networks)]` (the settings card, 2026-11-10).
    #[must_use]
    pub fn mnemonic_account_counts(&self, id: RecordId, primary: bool) -> [usize; 4] {
        use yw_core::btc::BtcAccountKey;
        use yw_core::zec::ZecKeySource;
        let Some(meta) = self.meta.as_ref() else {
            return [0; 4];
        };
        let key = *id.as_bytes();
        let evm = if primary {
            meta.evm_accounts.len()
        } else {
            meta.mnemonics
                .iter()
                .find(|entry| entry.record_id == key)
                .map_or(0, |entry| entry.evm.len())
        };
        let sol = if primary {
            meta.sol_accounts.len()
        } else {
            meta.mnemonic_accounts.sol_of(key).count()
        };
        let network = crate::btc::core_network(self.settings.bitcoin.network);
        let first_btc = usize::from(
            primary
                && meta
                    .btc
                    .as_ref()
                    .is_some_and(|btc| btc.network() == network),
        );
        let btc = meta
            .btc_accounts
            .accounts
            .iter()
            .filter(|account| account.network() == network)
            .filter(|account| match account.account() {
                BtcAccountKey::Hd { mnemonic, .. } => {
                    if primary {
                        mnemonic.is_none()
                    } else {
                        *mnemonic == Some(id)
                    }
                }
                BtcAccountKey::EvmShared { .. } => primary,
                _ => false,
            })
            .count()
            .saturating_add(first_btc);
        let zec = [meta.zcash.mainnet.as_ref(), meta.zcash.testnet.as_ref()]
            .into_iter()
            .flatten()
            .filter(|account| match account.source {
                ZecKeySource::Derived { .. } | ZecKeySource::EvmShared { .. } => primary,
                ZecKeySource::Mnemonic { mnemonic, .. } => !primary && mnemonic == id,
                ZecKeySource::Hardware { .. } | ZecKeySource::Imported => false,
            })
            .count();
        [evm, sol, btc, zec]
    }

    /// The EVM account rows of the added mnemonics `(pref, label, address (lowercase), path)`.
    pub(crate) fn mnemonic_account_rows(&self) -> Vec<(EvmAccountPref, String, String, String)> {
        let Some(meta) = self.meta.as_ref() else {
            return Vec::new();
        };
        meta.mnemonics
            .iter()
            .flat_map(|entry| {
                entry
                    .evm
                    .iter()
                    .filter(|account| !account.hidden)
                    .map(move |account| {
                        (
                            EvmAccountPref::Mnemonic(entry.record_id, account.index),
                            account.label.clone(),
                            account.address.clone(),
                            format!("{} · m/44'/60'/0'/0/{}", entry.label, account.index),
                        )
                    })
            })
            .collect()
    }

    /// The account of `EvmAccountPref::Mnemonic(id, index)`.
    pub(crate) fn mnemonic_account(
        &self,
        id: [u8; 16],
        index: u32,
    ) -> Option<(Address, EvmKeySource, String)> {
        let account = self
            .meta
            .as_ref()?
            .mnemonics
            .iter()
            .find(|entry| entry.record_id == id)?
            .evm
            .iter()
            .find(|account| account.index == index)?;
        let address = yw_core::evm::address::parse_address(&account.address).ok()?;
        Some((
            address,
            EvmKeySource::Mnemonic(RecordId::from_bytes(id), AccountIndex::new(index).ok()?),
            account.label.clone(),
        ))
    }

    /// The key source of an added mnemonic's account with this address.
    pub(crate) fn mnemonic_source(&self, text: &str) -> Option<EvmKeySource> {
        self.meta.as_ref()?.mnemonics.iter().find_map(|entry| {
            let account = entry.evm.iter().find(|account| account.address == text)?;
            Some(EvmKeySource::Mnemonic(
                RecordId::from_bytes(entry.record_id),
                AccountIndex::new(account.index).ok()?,
            ))
        })
    }

    /// The mnemonic account `pref` names, mutably (rename, hide).
    pub(crate) fn mnemonic_account_mut(
        &mut self,
        id: [u8; 16],
        index: u32,
    ) -> Option<&mut Account> {
        self.meta
            .as_mut()?
            .mnemonics
            .iter_mut()
            .find(|entry| entry.record_id == id)?
            .evm
            .iter_mut()
            .find(|account| account.index == index)
    }

    /// Whether "계정 추가" has room in some mnemonic.
    #[must_use]
    pub fn can_add_account(&self) -> bool {
        let Some(meta) = self.meta.as_ref() else {
            return false;
        };
        meta.next_index().is_some()
            || meta
                .mnemonics
                .iter()
                .any(|entry| !entry.evm.is_empty() && entry.next_index().is_some())
    }

    /// "계정 추가": with several mnemonics the picker opens first.
    pub(crate) fn add_account_clicked(&mut self) {
        if self.several_mnemonics() {
            self.mn.add_pick = !self.mn.add_pick;
            self.refresh();
            return;
        }
        self.add_primary_account();
    }

    fn add_primary_account(&mut self) {
        if let Some(index) = self.meta.as_ref().and_then(crate::meta::Meta::next_index) {
            self.key(KeyJob::DeriveAddresses {
                indices: vec![index],
            });
        }
    }

    fn unlocked(&self) -> bool {
        matches!(self.mode, AppMode::Unlocked { .. })
    }

    /// Whether recovery phrases may be added, made or removed now: unlocked, and not a session
    /// opened with an unverified passphrase ([`T_MN_ALT_PASS`]; like a key import).
    #[must_use]
    pub fn mn_phrases_editable(&self) -> bool {
        self.unlocked() && !self.passphrase_unverified()
    }

    /// The primary phrase while its backup quiz is open in an unlocked session: a key-only or
    /// `YubiKey` wallet's first phrase from "새 복구 단어 만들기" (a created wallet waits on S04
    /// instead). Its accounts get the same banners as an added phrase's ([`Self::mn_backup_gate`]).
    fn mn_primary_pending(&self) -> Option<RecordId> {
        if !self.unlocked() {
            return None;
        }
        self.mn
            .infos
            .iter()
            .find(|info| info.primary && !info.backup_confirmed)
            .map(|info| info.id)
    }

    /// The recovery phrase whose open backup quiz gates an account's signatures: the added
    /// phrase `added`, else for a key of the primary phrase (`primary_key`: a derived account,
    /// an EVM key's Bitcoin or Zcash use) the primary one while [`Self::mn_primary_pending`].
    /// For [`Self::mn_receive_banner`] and [`Self::mn_signing_banner`].
    #[must_use]
    pub(crate) fn mn_backup_gate(
        &self,
        added: Option<RecordId>,
        primary_key: bool,
    ) -> Option<RecordId> {
        if added.is_some() || !primary_key {
            return added;
        }
        self.mn_primary_pending()
    }

    /// [`Self::mn_backup_gate`] of an EVM key source.
    #[must_use]
    pub(crate) fn evm_backup_gate(&self, source: EvmKeySource) -> Option<RecordId> {
        match source {
            EvmKeySource::Mnemonic(id, _) => Some(id),
            EvmKeySource::Derived(_) => self.mn_backup_gate(None, true),
            EvmKeySource::Raw(_) | EvmKeySource::Hardware(_) => None,
        }
    }

    /// The phrase of `gate` ([`Self::mn_backup_gate`]) while its backup quiz has not passed: the
    /// vault refuses that key's signatures until then (E-VLT-009, spec/02 §8.6). For the dApp
    /// connect windows and the checks before a dApp signing window (spec/05 §4.5, §4.9).
    #[must_use]
    pub(crate) fn mn_unconfirmed(&self, gate: Option<RecordId>) -> Option<RecordId> {
        let id = gate?;
        self.mn
            .infos
            .iter()
            .any(|info| info.id == id && !info.backup_confirmed)
            .then_some(id)
    }

    /// [`Self::mn_unconfirmed`] of an EVM account of this wallet (its key source as a signature
    /// would use it).
    #[must_use]
    pub(crate) fn evm_account_unconfirmed(&self, account: &Address) -> Option<RecordId> {
        self.account_source(account)
            .and_then(|source| self.mn_unconfirmed(self.evm_backup_gate(source)))
    }

    /// [`Self::mn_backup_gate`] of a Solana key source (the primary phrase's for its derived
    /// paths; none for an imported or `YubiKey` key).
    #[must_use]
    pub(crate) fn sol_backup_gate(
        &self,
        source: yw_core::slip10::SolKeySource,
    ) -> Option<RecordId> {
        use yw_core::slip10::SolKeySource;
        let primary = !matches!(source, SolKeySource::Imported | SolKeySource::Hardware(_));
        self.mn_backup_gate(source.mnemonic(), primary)
    }

    /// [`Self::mn_unconfirmed`] of a Solana key source ([`Self::sol_backup_gate`]).
    #[must_use]
    pub(crate) fn sol_source_unconfirmed(
        &self,
        source: yw_core::slip10::SolKeySource,
    ) -> Option<RecordId> {
        self.mn_unconfirmed(self.sol_backup_gate(source))
    }

    /// [`Self::mn_unconfirmed`] of a Bitcoin key source (an HD account's phrase, the primary one
    /// for an EVM key's use; none for an imported or `YubiKey` key).
    #[must_use]
    pub(crate) fn btc_source_unconfirmed(
        &self,
        source: &yw_core::btc::BtcKeySource,
    ) -> Option<RecordId> {
        use yw_core::btc::BtcKeySource;
        let (added, primary) = match source {
            BtcKeySource::Derived { mnemonic, .. } => (*mnemonic, mnemonic.is_none()),
            BtcKeySource::EvmShared { .. } => (None, true),
            BtcKeySource::Imported { .. } | BtcKeySource::Hardware { .. } => (None, false),
        };
        self.mn_unconfirmed(self.mn_backup_gate(added, primary))
    }

    /// [`Self::mn_backup_gate`] of the selected Bitcoin account (an HD account's phrase, the
    /// primary one for an EVM key's use; none for an imported or `YubiKey` key).
    #[must_use]
    pub(crate) fn btc_backup_gate(&self) -> Option<RecordId> {
        let ctx = self.btc_ctx();
        let account = ctx.btc_meta().map(|meta| *meta.account());
        self.mn_backup_gate(
            account.and_then(|key| key.mnemonic()),
            account.is_some_and(|key| !key.is_imported() && !key.is_hardware()),
        )
    }

    /// [`Self::mn_backup_gate`] of the selected EVM account (S11 and S-HC sign with it).
    #[must_use]
    pub(crate) fn evm_selected_gate(&self) -> Option<RecordId> {
        self.selected_account()
            .and_then(|(_, source, _)| self.evm_backup_gate(source))
    }

    /// Refuses a dApp signing request of an account that cannot sign yet
    /// ([`Self::mn_unconfirmed`] names its phrase): 4100 `BackupUnconfirmed` before any window —
    /// the vault would refuse the key only after the approval, and the page got a bare -32603 —
    /// and one notice saying where the backup is confirmed.
    pub(crate) fn refuse_unconfirmed(
        &mut self,
        site: &crate::browser::SiteRequest,
        phrase: RecordId,
    ) {
        // A WalletConnect session is named by the address its dApp claimed, never by its
        // internal `….walletconnect.invalid` origin (spec/13 §7).
        let text = format!(
            "{}의 서명 요청을 거부했습니다: '{}'의 백업 확인 전이라 이 계정은 받기만 되고 서명은 안 됩니다. 설정 → 복구 단어에서 '백업 확인'을 마치세요.",
            self.origin_display(&site.origin),
            self.mnemonic_label(phrase)
        );
        if !self.banners.iter().any(|banner| banner.text == text) {
            self.notice(text, Tone::Warn);
            self.refresh();
        }
        logging::info("browser", "site.sign_backup_unconfirmed", &[]);
        self.respond(
            &site.reply,
            Err(yw_core::policy::ProviderError::BackupUnconfirmed),
        );
    }

    /// What a send form says when the vault refused its signature after the approval because the
    /// account's recovery phrase has not passed its backup quiz (E-VLT-009). The forms keep
    /// `검토` off while the app knows that ([`Self::mn_send_blocked`]), so this is the vault's
    /// last line of defence speaking: which phrase (`phrase`, when known) and where to finish it,
    /// as the dApp refusal says ([`Self::refuse_unconfirmed`]).
    #[must_use]
    pub(crate) fn backup_refused_text(&self, phrase: Option<RecordId>) -> String {
        let which = phrase.map_or_else(
            || "복구 단어가 백업 확인 전이라".to_owned(),
            |id| format!("'{}'의 백업 확인 전이라", self.mnemonic_label(id)),
        );
        format!(
            "서명하지 않았습니다: {which} 이 계정은 받기만 되고 서명은 안 됩니다. 설정 → 복구 단어에서 '백업 확인'을 마치세요. ({})",
            crate::errors::ErrorCode::Vlt009.code()
        )
    }

    /// The send forms' check before `검토` (S11, Solana, Bitcoin, the Zcash 보내기 card, S-HC):
    /// the sending account's phrase (its [`Self::mn_backup_gate`] `gate`) while its backup quiz
    /// has not passed — the form shows [`Self::mn_signing_banner`] and keeps `검토` off, instead
    /// of building an approval the vault is certain to refuse (E-VLT-009). Display only: the
    /// vault's refusal stays the last line of defence.
    #[must_use]
    pub(crate) fn mn_send_blocked(&self, gate: Option<RecordId>) -> bool {
        self.mn_unconfirmed(gate).is_some()
    }

    /// The tag of a dApp connect-window row whose account cannot sign yet.
    #[must_use]
    pub(crate) fn mn_connect_tag(&self, phrase: Option<RecordId>) -> String {
        phrase.map_or_else(String::new, |id| {
            format!(
                "  [{} 백업 확인 전 — 받기만, 서명 불가]",
                self.mnemonic_label(id)
            )
        })
    }

    /// The recovery-phrase commands; `false` when `id` is not one of them.
    pub(crate) fn on_mn_command(&mut self, id: u16) -> bool {
        let row = |base: u16| {
            id.checked_sub(base)
                .filter(|row| *row < ids::ROW_SPAN)
                .map(usize::from)
        };
        let info_at = |app: &Self, row: usize| app.mn.infos.get(row).copied();
        if let Some(row) = row(ids::PICK_BASE) {
            self.mn.add_pick = false;
            match info_at(self, row) {
                Some(info) if info.primary => self.add_primary_account(),
                Some(info) => {
                    let next = self.meta.as_ref().and_then(|meta| {
                        meta.mnemonics
                            .iter()
                            .find(|entry| entry.record_id == *info.id.as_bytes())?
                            .next_index()
                    });
                    if let Some(index) = next {
                        self.key(KeyJob::Mnemonics(MnJob::Derive { id: info.id, index }));
                    }
                }
                None => {}
            }
            self.refresh();
            return true;
        }
        if self.on_chain_pick(id) {
            return true;
        }
        if let Some(info) = row(ids::RENAME_BASE).and_then(|row| info_at(self, row)) {
            self.mn.rename = Some(info.id);
            self.refresh();
            return true;
        }
        if let Some(info) = row(ids::REVEAL_BASE).and_then(|row| info_at(self, row)) {
            self.open_mn_input(
                SecretKind::ConfirmPassword,
                MnPurpose::RevealPassword(info.id, false),
            );
            return true;
        }
        if let Some(info) = row(ids::BACKUP_BASE).and_then(|row| info_at(self, row)) {
            self.open_mn_input(
                SecretKind::ConfirmPassword,
                MnPurpose::RevealPassword(info.id, true),
            );
            return true;
        }
        if let Some(info) = row(ids::REMOVE_BASE).and_then(|row| info_at(self, row)) {
            self.mn_remove_clicked(info);
            return true;
        }
        match id {
            ids::SECTION_MNEMONICS | ids::MAIN_LINK => {
                self.set_screen(Screen::Settings(SettingsSection::Mnemonics));
            }
            ids::IMPORT if self.mn_phrases_editable() => {
                self.mn.preview = None;
                self.open_mn_input(SecretKind::Mnemonic, MnPurpose::ImportWords);
            }
            ids::CREATE if self.mn_phrases_editable() => {
                self.open_mn_input(SecretKind::ConfirmPassword, MnPurpose::CreatePassword);
            }
            ids::PREVIEW_CONFIRM | ids::PREVIEW_SAME_ACK | ids::PREVIEW_CANCEL => {
                self.on_mn_preview_command(id);
            }
            ids::RENAME_SAVE => self.save_mnemonic_label(),
            ids::RENAME_CANCEL => {
                self.mn.rename = None;
                self.refresh();
            }
            ids::REMOVE_CONFIRM => self.mn_remove_confirmed(),
            ids::REMOVE_REVEAL => {
                if let Some(target) = self.mn.confirm_remove {
                    self.open_mn_input(
                        SecretKind::ConfirmPassword,
                        MnPurpose::RevealPassword(target, false),
                    );
                }
            }
            ids::REMOVE_CANCEL => {
                self.mn_remove_reset(None);
                self.refresh();
            }
            ids::PICK_CANCEL => {
                self.mn.add_pick = false;
                self.refresh();
            }

            _ => return ids::FIXED.contains(&id),
        }
        true
    }

    /// The address preview's controls: `가져오기` (after the T-YK-SAME checkbox when the words
    /// are an enrolled `YubiKey`'s), the checkbox, `취소`.
    fn on_mn_preview_command(&mut self, id: u16) {
        match id {
            ids::PREVIEW_CONFIRM
                if self.mn.preview.is_some()
                    && (self.mn.preview_cards.is_empty() || self.mn.same_ack) =>
            {
                self.open_mn_input(SecretKind::ConfirmPassword, MnPurpose::ImportPassword);
            }
            ids::PREVIEW_SAME_ACK => {
                self.mn.same_ack = !self.mn.same_ack;
                self.refresh();
            }
            ids::PREVIEW_CANCEL => {
                self.mn.preview = None;
                self.mn.preview_cards.clear();
                self.mn.same_ack = false;
                self.key(KeyJob::Mnemonics(MnJob::Discard));
                self.refresh();
            }
            _ => {}
        }
    }

    /// `지우기` of a mnemonic card: the warning, unless a transaction of its accounts may still
    /// confirm (T-MN-BUSY). The primary mnemonic has no `지우기`; nothing is removed in a session
    /// opened with an unverified passphrase ([`T_MN_ALT_PASS`]).
    fn mn_remove_clicked(&mut self, info: MnemonicInfo) {
        if !info.primary && self.mn_phrases_editable() {
            if self.mnemonic_busy(info.id) {
                self.notice(T_MN_BUSY.to_owned(), Tone::Warn);
            } else {
                self.mn_remove_reset(Some(info.id));
            }
        }
        self.refresh();
    }

    /// Opens (or, with `None`, closes) the removal warning with a fresh state.
    fn mn_remove_reset(&mut self, target: Option<RecordId>) {
        self.mn.confirm_remove = target;
        self.mn.remove_revealed = false;
        self.mn.remove_typed.clear();
        self.mn.remove_error = None;
    }

    /// Leaving "복구 단어" for another screen (not an overlay over it) ends its open flows: the
    /// words held between W05 and W06 are wiped, the address preview goes (and with it the key
    /// worker's previewed words, `MnJob::Discard`), and the rename and removal warning close.
    /// The list of phrases, the quiz of an open W10 and the "계정 추가" picker stay.
    pub(crate) fn mn_leaving(&mut self, next: &Screen) {
        let here = Screen::Settings(SettingsSection::Mnemonics);
        let on_section = self.screen == here
            || (matches!(self.screen, Screen::Confirm(_)) && self.previous_screen == here);
        if !on_section || *next == here || matches!(next, Screen::Confirm(_)) {
            return;
        }
        let held = self.mn.phrase.is_some() || self.mn.preview.is_some();
        self.mn.phrase = None;
        self.mn.preview = None;
        self.mn.preview_cards.clear();
        self.mn.same_ack = false;
        self.mn.rename = None;
        self.mn_remove_reset(None);
        if held {
            self.key(KeyJob::Mnemonics(MnJob::Discard));
        }
    }

    /// Whether the removal target's backup is not confirmed (T-MN-REMOVE-UNCONFIRMED applies).
    #[must_use]
    pub fn mn_remove_unconfirmed(&self) -> bool {
        self.mn.confirm_remove.is_some_and(|target| {
            self.mn
                .infos
                .iter()
                .any(|info| info.id == target && !info.backup_confirmed)
        })
    }

    /// The warning's `이 복구 단어 지우기`: W03. A phrase whose backup is not confirmed needs its
    /// words shown to the end in this removal (`단어 보기`) and [`T_MN_REMOVE_WORD`] typed first.
    fn mn_remove_confirmed(&mut self) {
        let Some(target) = self.mn.confirm_remove else {
            return;
        };
        if self.mn_remove_unconfirmed() {
            if !self.mn.remove_revealed {
                self.mn.remove_error =
                    Some("먼저 '단어 보기'로 이 복구 단어를 끝까지 보고 적어 두세요.".to_owned());
                self.refresh();
                return;
            }
            if self.mn.remove_typed.trim() != T_MN_REMOVE_WORD {
                self.mn.remove_error = Some(format!(
                    "지우려면 입력란에 '{T_MN_REMOVE_WORD}'를 정확히 입력하세요."
                ));
                self.refresh();
                return;
            }
        }
        self.mn.remove_error = None;
        self.open_mn_input(
            SecretKind::ConfirmPassword,
            MnPurpose::RemovePassword(target),
        );
    }

    /// `EN_CHANGE` of a recovery-phrase edit; `false` when `id` is not one of them.
    pub fn on_mn_edit_change(&mut self, id: u16) -> bool {
        if id != ids::REMOVE_TYPED_EDIT {
            return false;
        }
        let text = self.controls.text(id, 32).unwrap_or_default();
        self.mn_set_remove_typed(text);
        true
    }

    /// Stores the typed removal phrase (no repaint: it is checked when `지우기` is pressed; also
    /// the tests' way to type).
    pub fn mn_set_remove_typed(&mut self, text: String) {
        self.mn.remove_typed = text;
    }

    /// The prominent banner of a receive screen whose account comes from the phrase `mnemonic`
    /// ([`Self::mn_backup_gate`]) while that phrase's backup is not confirmed (until its quiz
    /// passes).
    pub(crate) fn mn_receive_banner(&self, mnemonic: Option<RecordId>, items: &mut Vec<Item>) {
        let Some(id) = mnemonic else {
            return;
        };
        if self
            .mn
            .infos
            .iter()
            .any(|info| info.id == id && !info.backup_confirmed)
        {
            items.push(Item::Banner(
                format!("{}: {T_MN_RECEIVE_UNCONFIRMED}", self.mnemonic_label(id)),
                Tone::HighRisk,
            ));
            self.mn_backup_now(id, items);
        }
    }

    /// The selected account's band while its recovery phrase ([`Self::mn_backup_gate`]: an added
    /// one, or a key-only wallet's later primary one) waits for the backup quiz (2026-11-08):
    /// the vault refuses its signatures until then (E-VLT-009), so this says it before the send
    /// form and the approval, with the quiz one press away. Display only; the vault's refusal
    /// stays the last line of defence.
    pub(crate) fn mn_signing_banner(&self, mnemonic: Option<RecordId>, items: &mut Vec<Item>) {
        let Some(id) = mnemonic else {
            return;
        };
        if self
            .mn
            .infos
            .iter()
            .any(|info| info.id == id && !info.backup_confirmed)
        {
            items.push(Item::Banner(
                format!(
                    "'{}' 백업 확인 전 — 이 계정은 받기만 되고, 보내기·서명은 백업 확인 뒤에 됩니다.",
                    self.mnemonic_label(id)
                ),
                Tone::Warn,
            ));
            self.mn_backup_now(id, items);
        }
    }

    /// `지금 백업 확인`: the recovery-phrase list's `백업 확인` of `id` (W03 → W08 → W10; the
    /// vault runs the quiz of any phrase in an unlocked session).
    fn mn_backup_now(&self, id: RecordId, items: &mut Vec<Item>) {
        if !self.unlocked() {
            return;
        }
        if let Some(offset) = self
            .mn
            .infos
            .iter()
            .position(|info| info.id == id)
            .and_then(|position| u16::try_from(position).ok())
            .filter(|offset| *offset < ids::ROW_SPAN)
        {
            items.push(Item::Row(vec![Ctl::button(
                ids::BACKUP_BASE.saturating_add(offset),
                "지금 백업 확인",
            )]));
        }
    }

    /// The Solana / Bitcoin / Zcash mnemonic choices (spec/02 §8.6); `false` for other ids.
    fn on_chain_pick(&mut self, id: u16) -> bool {
        if id == ids::SOL_PICK_CANCEL {
            self.sol.add_pick = false;
            self.refresh();
            return true;
        }
        let pick = |base: u16| {
            id.checked_sub(base)
                .filter(|row| *row < ids::ROW_SPAN)
                .and_then(|row| self.mn.infos.get(usize::from(row)).copied())
        };
        if let Some(info) = pick(ids::SOL_PICK_BASE) {
            self.sol_add_account_of(info.id, info.primary);
            self.refresh();
            return true;
        }
        if let Some(info) = pick(ids::BTC_PICK_BASE) {
            self.btc_pick_mnemonic(info.id, info.primary);
            return true;
        }
        if let Some(info) = pick(ids::ZEC_PICK_BASE) {
            if !info.primary {
                self.zec_use_mnemonic(info.id);
            }
            return true;
        }
        false
    }

    fn open_mn_input(&mut self, kind: SecretKind, purpose: MnPurpose) {
        self.open_input(kind, Purpose::Mnemonics(purpose), false);
    }

    fn save_mnemonic_label(&mut self) {
        let label = self.controls.text(ids::RENAME_EDIT, 64).unwrap_or_default();
        if !is_valid_label(&label) {
            self.info = Some(crate::errors::ErrorCode::Inp017.text());
            self.refresh();
            return;
        }
        let Some(target) = self.mn.rename.take() else {
            return;
        };
        let infos = self.mn.infos.clone();
        if let Some(meta) = self.meta.as_mut() {
            // A wallet whose meta has no entries yet (one mnemonic, default label) gets them
            // here; the next meta load fills in the accounts of added mnemonics.
            for (position, info) in infos.iter().enumerate() {
                if !meta
                    .mnemonics
                    .iter()
                    .any(|entry| entry.record_id == *info.id.as_bytes())
                {
                    meta.mnemonics.push(crate::meta::MnemonicEntry {
                        record_id: *info.id.as_bytes(),
                        label: crate::workers::key::mnemonics::default_label(
                            position.saturating_add(1),
                        ),
                        evm: Vec::new(),
                    });
                }
            }
            if let Some(entry) = meta
                .mnemonics
                .iter_mut()
                .find(|entry| entry.record_id == *target.as_bytes())
            {
                entry.label = label;
            }
        }
        self.info = None;
        self.save_meta();
        self.refresh();
    }

    /// A submitted secret window of these flows.
    pub(crate) fn mn_submit(
        &mut self,
        purpose: MnPurpose,
        values: Vec<Zeroizing<Vec<u8>>>,
        checkbox: bool,
    ) {
        let mut values = values.into_iter();
        let mut next = || values.next().unwrap_or_default();
        match purpose {
            MnPurpose::ImportWords => {
                let phrase = next();
                if checkbox {
                    self.mn.phrase = Some(phrase);
                    self.open_mn_input(
                        SecretKind::Passphrase { confirm: true },
                        MnPurpose::ImportPassphrase,
                    );
                } else {
                    self.close_secret();
                    self.key(KeyJob::Mnemonics(MnJob::Preview {
                        phrase,
                        passphrase: None,
                    }));
                }
            }
            MnPurpose::ImportPassphrase => {
                let passphrase = next();
                self.close_secret();
                if let Some(phrase) = self.mn.phrase.take() {
                    self.key(KeyJob::Mnemonics(MnJob::Preview {
                        phrase,
                        passphrase: Some(passphrase),
                    }));
                }
            }
            MnPurpose::ImportPassword => {
                let password = next();
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::Mnemonics(MnJob::CommitImport { password }));
            }
            MnPurpose::CreatePassword => {
                let password = next();
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::Mnemonics(MnJob::Generate { password }));
            }
            MnPurpose::RevealPassword(id, then_backup) => {
                let password = next();
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::Mnemonics(MnJob::Reveal {
                    password,
                    id,
                    then_backup,
                }));
            }
            MnPurpose::RemovePassword(id) => {
                let password = next();
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::Mnemonics(MnJob::Remove { password, id }));
            }
            MnPurpose::Backup(id) => {
                let Some((target, challenge)) = self.mn.challenge else {
                    self.close_secret();
                    return;
                };
                if target != id {
                    self.close_secret();
                    return;
                }
                let words = [next(), next(), next(), next()];
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::Mnemonics(MnJob::Confirm {
                    id,
                    challenge: challenge.id,
                    words,
                }));
            }
            MnPurpose::ShowWords(..) => {}
        }
    }

    /// A cancelled secret window of these flows.
    pub(crate) fn mn_cancel(&mut self, purpose: MnPurpose) {
        match purpose {
            MnPurpose::ImportWords | MnPurpose::ImportPassphrase => {
                self.mn.phrase = None;
            }
            MnPurpose::Backup(_) | MnPurpose::ShowWords(..) => {
                self.mn.challenge = None;
                self.notice(T_MN_UNCONFIRMED.to_owned(), Tone::Warn);
            }
            // `ImportPassword`: the preview stays, `가져오기` asks for the password again.
            MnPurpose::ImportPassword
            | MnPurpose::CreatePassword
            | MnPurpose::RevealPassword(..)
            | MnPurpose::RemovePassword(_) => {}
        }
        self.refresh();
    }

    /// W08's hold finished: the quiz of an added mnemonic; for the phrase whose removal is
    /// open, its words count as shown.
    pub(crate) fn mn_hold_complete(&mut self, purpose: MnPurpose) {
        self.close_secret();
        match purpose {
            MnPurpose::ShowWords(id, true) => {
                self.key(KeyJob::Mnemonics(MnJob::Challenge { id }));
            }
            MnPurpose::ShowWords(id, false) if self.mn.confirm_remove == Some(id) => {
                self.mn.remove_revealed = true;
                self.mn.remove_error = None;
            }
            _ => {}
        }
        self.refresh();
    }

    fn after_change(&mut self) {
        // The meta load reconciles `mnemonics` (new entry and account 0, removed entries,
        // selection) and brings the new mnemonic list.
        self.request_meta();
        self.refresh();
    }

    /// The removed phrase `id`'s Solana and Bitcoin accounts leave meta now (the next meta load
    /// reconciles the rest), then every dApp grant naming one of them goes (spec/05 §4.9, like
    /// an imported key's in `on_imported_key_removed`). The order matters: the site helpers keep
    /// a grant whose key or address is still one of the wallet's accounts, so the accounts must
    /// be gone first. A grant never comes back when the same words are added again.
    fn mn_chain_accounts_removed(&mut self, id: RecordId) {
        let Some(meta) = self.meta.as_mut() else {
            return;
        };
        let sol: Vec<[u8; 32]> = meta
            .mnemonic_accounts
            .sol_of(*id.as_bytes())
            .filter_map(|account| yw_core::sol::SolAddress::parse(&account.address).ok())
            .map(yw_core::sol::SolAddress::to_bytes)
            .collect();
        let btc: Vec<String> = meta
            .btc_accounts
            .accounts
            .iter()
            .filter(|account| account.account().mnemonic() == Some(id))
            .filter_map(|account| {
                let address = account
                    .address(yw_core::bip32::path::BtcChain::Receive, 0)
                    .ok()?;
                Some(address.as_str().to_owned())
            })
            .collect();
        meta.mnemonic_accounts.remove_mnemonic(*id.as_bytes());
        meta.btc_accounts.remove_mnemonic(id);
        self.save_meta();
        for public in &sol {
            self.sol_account_removed_from_sites(public);
        }
        if !btc.is_empty() {
            self.btc_addresses_removed_from_sites(&btc);
        }
    }

    /// A finished recovery-phrase job.
    #[expect(clippy::too_many_lines, reason = "one arm per outcome")]
    pub(crate) fn on_mn_outcome(&mut self, outcome: MnOutcome, now: u64) {
        match outcome {
            MnOutcome::Preview(Ok((address, cards))) => {
                self.mn.preview = Some(address.to_checksum());
                self.mn.preview_cards = cards;
                self.mn.same_ack = false;
                self.set_screen(Screen::Settings(SettingsSection::Mnemonics));
            }
            MnOutcome::Preview(Err(error)) => {
                let code = key_code(error);
                let message = match error {
                    yw_core::error::KeyError::MnemonicUnknownWord { position } => {
                        code.render(&position.to_string())
                    }
                    _ => code.text(),
                };
                self.open_mn_input(SecretKind::Mnemonic, MnPurpose::ImportWords);
                self.with_form(|form| form.set_error(Some(message)));
            }
            MnOutcome::Discarded => {}
            MnOutcome::Added(Ok(_)) => {
                self.close_secret();
                self.mn.preview = None;
                logging::info("app", "mnemonic.added", &[]);
                self.notice(
                    "복구 단어를 추가했습니다. 그 계정 0이 계정 목록에 생겼습니다.".to_owned(),
                    Tone::Info,
                );
                self.after_change();
            }
            MnOutcome::Generated(Ok((id, phrase, address))) => {
                logging::info("app", "mnemonic.generated", &[]);
                self.close_secret();
                self.request_meta();
                self.open_display(
                    SecretKind::ShowMnemonic { create: true },
                    Purpose::Mnemonics(MnPurpose::ShowWords(id, true)),
                    DisplaySecret {
                        text: phrase,
                        address: Some(address.to_checksum()),
                        passphrase_note: false,
                        copy_allowed: self.settings.allow_secret_copy,
                    },
                );
            }
            MnOutcome::Challenge(Ok((id, challenge))) => {
                self.mn.challenge = Some((id, challenge));
                if self.secret_purpose() == Some(Purpose::Mnemonics(MnPurpose::Backup(id))) {
                    self.with_form(|form| {
                        form.reset_backup(
                            challenge.positions,
                            Some(crate::ui::screens::backup_retry_text(
                                challenge.positions,
                                true,
                            )),
                        );
                    });
                } else {
                    self.open_mn_input(
                        SecretKind::Backup {
                            positions: challenge.positions,
                        },
                        MnPurpose::Backup(id),
                    );
                }
            }
            MnOutcome::Confirmed(Ok(id)) => {
                self.close_secret();
                self.mn.challenge = None;
                // Its keys sign from now on: the dApp checks (`mn_unconfirmed`) see it before
                // the meta reload brings the vault's list.
                if let Some(info) = self.mn.infos.iter_mut().find(|info| info.id == id) {
                    info.backup_confirmed = true;
                }
                logging::info("app", "mnemonic.backup_confirmed", &[]);
                self.notice(
                    format!(
                        "{}의 백업을 확인했습니다. 이제 그 계정으로 서명할 수 있습니다.",
                        self.mnemonic_label(id)
                    ),
                    Tone::Info,
                );
                self.after_change();
            }
            MnOutcome::Confirmed(Err(VaultError::BackupMismatch | VaultError::ChallengeStale)) => {
                if let Some((id, _)) = self.mn.challenge {
                    self.key(KeyJob::Mnemonics(MnJob::Challenge { id }));
                }
            }
            MnOutcome::Revealed(Ok((id, phrase, then_backup))) => {
                self.close_secret();
                let passphrase_note = self
                    .mn
                    .infos
                    .iter()
                    .any(|info| info.id == id && info.passphrase_used);
                // The removal of an unconfirmed phrase needs the words held to the end (the
                // 2 s `다 적었습니다`), like a new phrase's first display.
                let hold = then_backup
                    || (self.mn.confirm_remove == Some(id) && self.mn_remove_unconfirmed());
                // The first address as the paper has it (2026-11-10): the meta's EVM account 0 of
                // this phrase, no new derivation; without one, W08 asks for the words only.
                let address = self.mnemonic_first_address(id).map(Address::to_checksum);
                self.open_display(
                    SecretKind::ShowMnemonic { create: hold },
                    Purpose::Mnemonics(MnPurpose::ShowWords(id, then_backup)),
                    DisplaySecret {
                        text: phrase,
                        address,
                        passphrase_note,
                        copy_allowed: self.settings.allow_secret_copy,
                    },
                );
            }
            MnOutcome::Removed(Ok(id)) => {
                self.close_secret();
                self.mn_remove_reset(None);
                logging::info("app", "mnemonic.removed", &[]);
                let removed: Vec<Address> = self
                    .meta
                    .as_ref()
                    .and_then(|meta| {
                        meta.mnemonics
                            .iter()
                            .find(|entry| entry.record_id == *id.as_bytes())
                    })
                    .map(|entry| {
                        entry
                            .evm
                            .iter()
                            .filter_map(|account| {
                                yw_core::evm::address::parse_address(&account.address).ok()
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                // An address another visible account still has (the same key imported, a
                // `YubiKey` account made from the same words) keeps its connections.
                let phrase = *id.as_bytes();
                self.evm_key_removed_from_sites(
                    &removed,
                    |pref| matches!(pref, EvmAccountPref::Mnemonic(of, _) if of == phrase),
                );
                self.mn_chain_accounts_removed(id);
                self.after_change();
            }
            MnOutcome::Derived(Ok((id, index, address))) => {
                // `계정 N` one above the highest of every phrase (2026-11-10: each phrase
                // counted from its own index, so `계정 2` appeared once per phrase).
                let number = self
                    .meta
                    .as_ref()
                    .map_or(1, crate::meta::Meta::next_evm_number);
                if let Some(entry) = self.meta.as_mut().and_then(|meta| {
                    meta.mnemonics
                        .iter_mut()
                        .find(|entry| entry.record_id == *id.as_bytes())
                }) && !entry.evm.iter().any(|account| account.index == index)
                {
                    entry
                        .evm
                        .push(crate::workers::key::new_account(index, number, &address));
                    entry.evm.sort_by_key(|account| account.index);
                    if let Some(meta) = self.meta.as_mut() {
                        meta.prefs.evm_account = EvmAccountPref::Mnemonic(*id.as_bytes(), index);
                    }
                    self.save_meta();
                    self.evm_balances_due();
                }
                self.refresh();
            }
            MnOutcome::Busy(_) => {
                self.close_secret();
                self.mn_remove_reset(None);
                self.notice(T_MN_BUSY.to_owned(), Tone::Warn);
                self.refresh();
            }
            MnOutcome::PassphraseFor(position, count) => {
                self.mn.passphrase_for = Some((position, count));
            }
            MnOutcome::Added(Err(error)) => {
                // Only a mistyped password keeps the held words (and so the preview).
                if error != VaultError::UnlockFailed {
                    self.mn.preview = None;
                }
                self.password_failure(error, now);
            }
            MnOutcome::Generated(Err(error))
            | MnOutcome::Revealed(Err(error))
            | MnOutcome::Removed(Err(error)) => self.password_failure(error, now),
            MnOutcome::Challenge(Err(error))
            | MnOutcome::Confirmed(Err(error))
            | MnOutcome::Derived(Err(error)) => {
                self.close_secret();
                self.error_banner(vault_code(error));
            }
        }
    }
}
