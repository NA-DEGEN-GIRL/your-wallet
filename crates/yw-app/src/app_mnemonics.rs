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
use crate::ui::main_window::Tone;
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
    /// The "계정 추가" mnemonic picker is open.
    pub add_pick: bool,
    /// The address preview of "복구 단어 추가 가져오기" (EIP-55 account 0).
    pub preview: Option<String>,
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
pub const T_MN_BUSY: &str = "이 복구 단어의 Solana·Bitcoin·Zcash 계정에서 보낸 거래가 아직 확정될 수 있어(진행 중, 공개된 거래 또는 승인 중) 지울 수 없습니다. 거래가 확정되거나 만료된 뒤에 다시 시도하세요.";
/// T-MN-UNCONFIRMED.
pub const T_MN_UNCONFIRMED: &str = "백업 확인 전입니다. 이 복구 단어의 계정은 받기만 되고 서명(보내기·연결 승인)은 백업 확인 뒤에 됩니다.";

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

    /// Whether a Solana, Bitcoin or Zcash journal record of mnemonic `id`'s accounts may still
    /// confirm (a SOL `Pending`, a BTC record in flight / replaced / given up or refused inside
    /// the 30-day window, a ZEC record not final), or a Bitcoin approval of one of its accounts
    /// is open: the mnemonic is not removed then (like an imported key, spec/04 §2.18).
    #[must_use]
    pub fn mnemonic_busy(&self, id: RecordId) -> bool {
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
            ids::IMPORT if self.unlocked() => {
                self.mn.preview = None;
                self.open_mn_input(SecretKind::Mnemonic, MnPurpose::ImportWords);
            }
            ids::CREATE if self.unlocked() => {
                self.open_mn_input(SecretKind::ConfirmPassword, MnPurpose::CreatePassword);
            }
            ids::PREVIEW_CONFIRM if self.mn.preview.is_some() => {
                self.open_mn_input(SecretKind::ConfirmPassword, MnPurpose::ImportPassword);
            }
            ids::PREVIEW_CANCEL => {
                self.mn.preview = None;
                self.key(KeyJob::Mnemonics(MnJob::Discard));
                self.refresh();
            }
            ids::RENAME_SAVE => self.save_mnemonic_label(),
            ids::RENAME_CANCEL => {
                self.mn.rename = None;
                self.refresh();
            }
            ids::REMOVE_CONFIRM => {
                if let Some(target) = self.mn.confirm_remove {
                    self.open_mn_input(
                        SecretKind::ConfirmPassword,
                        MnPurpose::RemovePassword(target),
                    );
                }
            }
            ids::REMOVE_CANCEL => {
                self.mn.confirm_remove = None;
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

    /// `지우기` of a mnemonic card: the warning, unless a transaction of its accounts may still
    /// confirm (T-MN-BUSY). The primary mnemonic has no `지우기`.
    fn mn_remove_clicked(&mut self, info: MnemonicInfo) {
        if !info.primary {
            if self.mnemonic_busy(info.id) {
                self.notice(T_MN_BUSY.to_owned(), Tone::Warn);
            } else {
                self.mn.confirm_remove = Some(info.id);
            }
        }
        self.refresh();
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

    /// W08's hold finished: the quiz of an added mnemonic.
    pub(crate) fn mn_hold_complete(&mut self, purpose: MnPurpose) {
        self.close_secret();
        if let MnPurpose::ShowWords(id, true) = purpose {
            self.key(KeyJob::Mnemonics(MnJob::Challenge { id }));
        }
        self.refresh();
    }

    fn after_change(&mut self) {
        // The meta load reconciles `mnemonics` (new entry and account 0, removed entries,
        // selection) and brings the new mnemonic list.
        self.request_meta();
        self.refresh();
    }

    /// A finished recovery-phrase job.
    #[expect(clippy::too_many_lines, reason = "one arm per outcome")]
    pub(crate) fn on_mn_outcome(&mut self, outcome: MnOutcome, now: u64) {
        match outcome {
            MnOutcome::Preview(Ok(address)) => {
                self.mn.preview = Some(address.to_checksum());
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
                            Some(
                                "입력한 단어가 맞지 않습니다. 새 위치로 다시 확인합니다."
                                    .to_owned(),
                            ),
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
                self.open_display(
                    SecretKind::ShowMnemonic {
                        create: then_backup,
                    },
                    Purpose::Mnemonics(MnPurpose::ShowWords(id, then_backup)),
                    DisplaySecret {
                        text: phrase,
                        address: None,
                        passphrase_note,
                        copy_allowed: self.settings.allow_secret_copy,
                    },
                );
            }
            MnOutcome::Removed(Ok(id)) => {
                self.close_secret();
                self.mn.confirm_remove = None;
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
                for address in &removed {
                    self.account_removed_from_sites(address);
                }
                // Its Solana accounts leave every dApp connection too (spec/05 §4.9).
                let sol_removed: Vec<[u8; 32]> = self
                    .meta
                    .as_ref()
                    .map(|meta| {
                        meta.mnemonic_accounts
                            .sol_of(*id.as_bytes())
                            .filter_map(|account| {
                                yw_core::sol::SolAddress::parse(&account.address).ok()
                            })
                            .map(yw_core::sol::SolAddress::to_bytes)
                            .collect()
                    })
                    .unwrap_or_default();
                for public in &sol_removed {
                    self.sol_account_removed_from_sites(public);
                }
                self.after_change();
            }
            MnOutcome::Derived(Ok((id, index, address))) => {
                if let Some(entry) = self.meta.as_mut().and_then(|meta| {
                    meta.mnemonics
                        .iter_mut()
                        .find(|entry| entry.record_id == *id.as_bytes())
                }) && !entry.evm.iter().any(|account| account.index == index)
                {
                    entry.evm.push(Account {
                        index,
                        label: format!("계정 {}", index.saturating_add(1)),
                        address: address.to_lower_hex(),
                        hidden: false,
                    });
                    entry.evm.sort_by_key(|account| account.index);
                    if let Some(meta) = self.meta.as_mut() {
                        meta.prefs.evm_account = EvmAccountPref::Mnemonic(*id.as_bytes(), index);
                    }
                    self.save_meta();
                }
                self.refresh();
            }
            MnOutcome::Busy(_) => {
                self.close_secret();
                self.mn.confirm_remove = None;
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
