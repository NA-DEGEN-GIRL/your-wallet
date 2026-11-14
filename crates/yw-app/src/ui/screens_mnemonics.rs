//! The recovery-phrase screens (spec/04 §2.24): the settings section "복구 단어" (one card per
//! mnemonic with its label, words, backup state and actions; the address preview of
//! "복구 단어 추가 가져오기"; the removal warning) and the "계정 추가" mnemonic picker row.

use yw_core::lang::Text;

use crate::app::{App, AppMode};
use crate::app_mnemonics::text as mn_text;
use crate::ui::main_window::{Ctl, Item, Tone};

/// The recovery-phrase screen texts (spec/04 §2.24).
pub mod text {
    yw_core::texts! {
        NO_PHRASES = "이 지갑에는 아직 복구 단어가 없습니다(개인키·YubiKey로 시작한 지갑). 복구 단어를 더하면 그 계정이 계정 목록에 생깁니다."
            / "This wallet has no recovery phrase yet (it was started from a private key or a YubiKey). When you add one, its accounts appear in the account list.";
        WORDS(1) = "{0}단어" / "{0} words";
        PASSPHRASE_USED = "passphrase 사용" / "passphrase used";
        ACCOUNTS(4) = "계정: EVM {0} · Solana {1} · Bitcoin {2} · Zcash {3}"
            / "Accounts: EVM {0} · Solana {1} · Bitcoin {2} · Zcash {3}";
        PRIMARY = "처음 만든(가져온) 복구 단어 · 지울 수 없음"
            / "first created (imported) recovery phrase · cannot be deleted";
        BACKUP_CONFIRMED = "백업 확인됨" / "backup confirmed";
        BACKUP_PENDING = "백업 확인 전" / "backup not confirmed";
        FIRST_ADDRESS = "첫 주소(종이에 함께 적은 주소):"
            / "First address (written on the paper with the words):";
        SAVE = "저장" / "Save";
        CANCEL = "취소" / "Cancel";
        RENAME = "이름 바꾸기" / "Rename";
        SHOW_WORDS = "단어 보기" / "Show words";
        BACKUP_CHECK = "백업 확인" / "Backup check";
        DELETE = "지우기" / "Delete";
        IMPORT_MORE = "복구 단어 추가 가져오기" / "Import another recovery phrase";
        CREATE_MORE = "새 복구 단어 만들기 (추가)" / "Create another recovery phrase";
        ADDED_HELP = "추가한 복구 단어에서도 EVM·Solana·Bitcoin·Zcash 계정을 만들 수 있습니다(각 탭의 '계정 추가'에서 복구 단어를 고릅니다). 비밀번호를 다시 입력해야 합니다."
            / "Added recovery phrases can make EVM, Solana, Bitcoin and Zcash accounts too (choose the recovery phrase under 'Add account' on each tab). You need to enter the password again.";
        REMOVED_ACCOUNTS = "지워지는 계정" / "Accounts that will be removed";
        REVEAL_STEP = "1. 단어 보기 (끝까지 보고 적어 두기)"
            / "1. Show words (see them to the end and write them down)";
        REVEALED = "단어를 끝까지 보았습니다." / "You saw the words to the end.";
        NOT_REVEALED = "아직 단어를 보지 않았습니다." / "You have not seen the words yet.";
        TYPE_STEP(1) = "2. 확인: '{0}' 입력" / "2. Confirm: type '{0}'";
        DELETE_THIS = "이 복구 단어 지우기" / "Delete this recovery phrase";
        ZEC_ACCOUNT(1) = "Zcash 계정 ({0})" / "Zcash account ({0})";
        PREVIEW_TITLE = "가져올 복구 단어" / "Recovery phrase to import";
        PREVIEW_HELP = "이 복구 단어의 첫 계정(m/44'/60'/0'/0/0) 주소입니다. 다른 지갑에서 보던 주소와 같은지 확인하세요. 다르면 단어나 passphrase가 틀렸습니다."
            / "This is the address of this recovery phrase's first account (m/44'/60'/0'/0/0). Check that it matches the address you saw in your other wallet. If it differs, the words or the passphrase are wrong.";
        YK_SAME(1) = "이 복구 단어는 이 지갑에 등록된 YubiKey {0}의 키를 만든 단어입니다. 가져오면 그 단어가 이 PC의 vault에 저장됩니다."
            / "These words made the keys of YubiKey {0} enrolled in this wallet. Importing them stores the words in this PC's vault.";
        YK_SAME_ACK = "이해했습니다: 이 단어를 이 PC에 저장하면 YubiKey의 보안 이득이 없어집니다"
            / "I understand: storing these words on this PC removes the YubiKey's security benefit";
        IMPORT = "가져오기" / "Import";
        PICK_EVM = "어느 복구 단어에서 계정을 만들까요?"
            / "Which recovery phrase should the account come from?";
        PICK_SOL = "어느 복구 단어에서 Solana 계정을 만들까요? (m/44'/501'/i'/0')"
            / "Which recovery phrase should the Solana account come from? (m/44'/501'/i'/0')";
    }
}

/// Command ids (block 13,600–13,699, `ui::command_ids`).
pub mod ids {
    /// Settings tab "복구 단어".
    pub const SECTION_MNEMONICS: u16 = 13_600;
    /// 복구 단어 추가 가져오기.
    pub const IMPORT: u16 = 13_601;
    /// 새 복구 단어 만들기 (추가).
    pub const CREATE: u16 = 13_602;
    /// Address preview: 가져오기.
    pub const PREVIEW_CONFIRM: u16 = 13_603;
    /// Address preview: 취소.
    pub const PREVIEW_CANCEL: u16 = 13_604;
    /// Label edit: 저장.
    pub const RENAME_SAVE: u16 = 13_605;
    /// Label edit: 취소.
    pub const RENAME_CANCEL: u16 = 13_606;
    /// Label edit field.
    pub const RENAME_EDIT: u16 = 13_607;
    /// Removal warning: 지우기.
    pub const REMOVE_CONFIRM: u16 = 13_608;
    /// Removal warning: 취소.
    pub const REMOVE_CANCEL: u16 = 13_609;
    /// "계정 추가" picker: 취소.
    pub const PICK_CANCEL: u16 = 13_610;
    /// Address preview: the T-YK-SAME checkbox (the words of an enrolled `YubiKey`).
    pub const PREVIEW_SAME_ACK: u16 = 13_613;
    /// Removal warning of an unconfirmed phrase: 단어 보기.
    pub const REMOVE_REVEAL: u16 = 13_614;
    /// Removal warning of an unconfirmed phrase: the typed `백업 없이 지우기`.
    pub const REMOVE_TYPED_EDIT: u16 = 13_615;
    /// Main account card: 복구 단어 관리.
    pub const MAIN_LINK: u16 = 13_611;
    /// Rows per indexed range (`MAX_MNEMONICS`).
    pub const ROW_SPAN: u16 = 8;
    /// Mnemonic card: 이름 바꾸기 (`+ row`).
    pub const RENAME_BASE: u16 = 13_620;
    /// Mnemonic card: 단어 보기.
    pub const REVEAL_BASE: u16 = 13_630;
    /// Mnemonic card: 백업 확인.
    pub const BACKUP_BASE: u16 = 13_640;
    /// Mnemonic card: 지우기.
    pub const REMOVE_BASE: u16 = 13_650;
    /// "계정 추가" picker: one button per mnemonic.
    pub const PICK_BASE: u16 = 13_660;
    /// Solana "계정 추가" picker: one button per mnemonic.
    pub const SOL_PICK_BASE: u16 = 13_670;
    /// Bitcoin "계정 추가" key source: one radio per mnemonic.
    pub const BTC_PICK_BASE: u16 = 13_680;
    /// Zcash key source: `{니모닉 N} 표준 경로 사용`, one button per mnemonic.
    pub const ZEC_PICK_BASE: u16 = 13_690;
    /// Solana "계정 추가" picker: 취소.
    pub const SOL_PICK_CANCEL: u16 = 13_612;

    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        SECTION_MNEMONICS,
        IMPORT,
        CREATE,
        PREVIEW_CONFIRM,
        PREVIEW_CANCEL,
        RENAME_SAVE,
        RENAME_CANCEL,
        RENAME_EDIT,
        REMOVE_CONFIRM,
        REMOVE_CANCEL,
        PICK_CANCEL,
        MAIN_LINK,
        SOL_PICK_CANCEL,
        PREVIEW_SAME_ACK,
        REMOVE_REVEAL,
        REMOVE_TYPED_EDIT,
    ];
}

fn row_id(base: u16, row: usize) -> u16 {
    base.saturating_add(u16::try_from(row).unwrap_or(ids::ROW_SPAN))
}

impl App {
    /// Settings → 복구 단어.
    pub(crate) fn mn_settings_section(&self, items: &mut Vec<Item>) {
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        // Adding, making and removing phrases: not with an unverified passphrase (T-MN-ALT-PASS).
        let editable = self.mn_phrases_editable();
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        items.push(Item::Help(t(mn_text::INTRO)));
        if unlocked && !editable {
            items.push(Item::Help(t(mn_text::ALT_PASS)));
        }
        if self.mn.infos.is_empty() {
            items.push(Item::Help(t(text::NO_PHRASES)));
        }
        for (row, info) in self.mn.infos.iter().enumerate() {
            let label = self.mnemonic_label(info.id);
            items.push(Item::CardStart(Some(label.clone())));
            let [evm, sol, btc, zec] = self.mnemonic_account_counts(info.id, info.primary);
            let mut facts = vec![text::WORDS.fill(lang, [&info.words.to_string()])];
            if info.passphrase_used {
                facts.push(t(text::PASSPHRASE_USED));
            }
            facts.push(text::ACCOUNTS.fill(
                lang,
                [
                    &evm.to_string(),
                    &sol.to_string(),
                    &btc.to_string(),
                    &zec.to_string(),
                ],
            ));
            if info.primary {
                // Added phrases make Solana/Bitcoin/Zcash accounts too since 2026-11-08.
                facts.push(t(text::PRIMARY));
            }
            facts.push(t(if info.backup_confirmed {
                text::BACKUP_CONFIRMED
            } else {
                text::BACKUP_PENDING
            }));
            items.push(Item::Help(facts.join(" · ")));
            // The address written on the paper with the words (W08), to tell the papers apart.
            if let Some(address) = self.mnemonic_first_address(info.id) {
                items.push(Item::Help(t(text::FIRST_ADDRESS)));
                items.push(Item::Mono(yw_core::evm::display::format_address(&address)));
            }
            if !info.backup_confirmed {
                items.push(Item::Banner(t(mn_text::UNCONFIRMED), Tone::Warn));
            }
            if self.mn.rename == Some(info.id) {
                items.push(Item::Row(vec![
                    Ctl::edit(ids::RENAME_EDIT, &label, 260, false, 64),
                    Ctl::primary(ids::RENAME_SAVE, text::SAVE.get(lang)),
                    Ctl::button(ids::RENAME_CANCEL, text::CANCEL.get(lang)),
                ]));
            } else {
                let mut actions = vec![
                    Ctl::button(row_id(ids::RENAME_BASE, row), text::RENAME.get(lang)),
                    Ctl::button(row_id(ids::REVEAL_BASE, row), text::SHOW_WORDS.get(lang)),
                ];
                if !info.backup_confirmed {
                    actions.push(
                        Ctl::primary(row_id(ids::BACKUP_BASE, row), text::BACKUP_CHECK.get(lang))
                            .enabled(unlocked),
                    );
                }
                if !info.primary {
                    actions.push(
                        Ctl::danger(row_id(ids::REMOVE_BASE, row), text::DELETE.get(lang))
                            .enabled(editable),
                    );
                }
                items.push(Item::Row(actions));
            }
            if self.mn.confirm_remove == Some(info.id) {
                self.mn_remove_items(info.id, info.backup_confirmed, items);
            }
            items.push(Item::CardEnd);
        }
        if let Some(address) = &self.mn.preview {
            self.mn_preview_items(address, items);
        }
        let room = self.mn.infos.len() < yw_core::vault::MAX_MNEMONICS;
        items.push(Item::Row(vec![
            Ctl::primary(ids::IMPORT, text::IMPORT_MORE.get(lang)).enabled(editable && room),
            Ctl::button(ids::CREATE, text::CREATE_MORE.get(lang)).enabled(editable && room),
        ]));
        items.push(Item::Help(t(text::ADDED_HELP)));
    }

    /// The removal warning of an added phrase. One whose backup is not confirmed needs its words
    /// shown to the end (`단어 보기`) and [`mn_text::REMOVE_WORD`] typed before `지우기` asks for the
    /// password.
    fn mn_remove_items(
        &self,
        id: yw_core::vault::RecordId,
        backup_confirmed: bool,
        items: &mut Vec<Item>,
    ) {
        // The "지워지는 계정" block (2026-11-10): every account of this phrase on every chain,
        // with its last-read balance.
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        let accounts = self.mn_removed_accounts(id);
        if !accounts.is_empty() {
            items.push(Item::Subtitle(t(text::REMOVED_ACCOUNTS)));
            let _ = crate::ui::removed::removed_items(lang, &accounts, items);
        }
        if backup_confirmed {
            items.push(Item::Banner(t(mn_text::REMOVE), Tone::Danger));
        } else {
            items.push(Item::Banner(t(mn_text::REMOVE_UNCONFIRMED), Tone::HighRisk));
            items.push(Item::Row(vec![Ctl::button(
                ids::REMOVE_REVEAL,
                text::REVEAL_STEP.get(lang),
            )]));
            items.push(Item::Help(t(if self.mn.remove_revealed {
                text::REVEALED
            } else {
                text::NOT_REVEALED
            })));
            items.push(Item::LabeledRow(
                text::TYPE_STEP.fill(lang, [mn_text::REMOVE_WORD.get(lang)]),
                vec![
                    Ctl::edit(
                        ids::REMOVE_TYPED_EDIT,
                        &self.mn.remove_typed,
                        160,
                        false,
                        16,
                    )
                    .enabled(self.mn.remove_revealed),
                ],
            ));
        }
        if let Some(error) = &self.mn.remove_error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::danger(ids::REMOVE_CONFIRM, text::DELETE_THIS.get(lang))
                .enabled(backup_confirmed || self.mn.remove_revealed),
            Ctl::button(ids::REMOVE_CANCEL, text::CANCEL.get(lang)),
        ]));
    }

    /// The accounts of added phrase `id` on every chain (EVM, Solana, the settings network's
    /// Bitcoin, both Zcash networks).
    fn mn_removed_accounts(
        &self,
        id: yw_core::vault::RecordId,
    ) -> Vec<crate::ui::removed::RemovedAccount> {
        let mut accounts = Vec::new();
        for (pref, label, address, _) in self.mnemonic_account_rows() {
            if let crate::meta::EvmAccountPref::Mnemonic(record, _) = pref
                && record == *id.as_bytes()
                && let Ok(address) = yw_core::evm::address::parse_address(&address)
            {
                accounts.push(self.evm_removed(label, &address, false));
            }
        }
        for (account, label, address) in self.sol_account_rows() {
            if account.mnemonic() == Some(*id.as_bytes()) {
                accounts.push(self.sol_removed(label, &address, false));
            }
        }
        let ctx = self.btc_ctx();
        for meta in ctx.accounts() {
            if meta.account().mnemonic() == Some(id)
                && let Ok(address) = meta.address(yw_core::bip32::path::BtcChain::Receive, 0)
            {
                accounts.push(self.btc_removed(
                    crate::app_btc::account_label(self.settings.language, meta.account()),
                    address.as_str(),
                    false,
                ));
            }
        }
        if let Some(meta) = self.meta.as_ref() {
            for account in [meta.zcash.mainnet, meta.zcash.testnet]
                .into_iter()
                .flatten()
            {
                if matches!(account.source, yw_core::zec::ZecKeySource::Mnemonic { mnemonic, .. } if mnemonic == id)
                {
                    accounts.push(
                        self.zec_removed(
                            text::ZEC_ACCOUNT
                                .fill(self.settings.language, [account.network.display_name()]),
                            &account.address(),
                            false,
                        ),
                    );
                }
            }
        }
        accounts
    }

    /// The address preview of "복구 단어 추가 가져오기", with T-YK-SAME when the words are an
    /// enrolled `YubiKey`'s (spec/10 §7.1).
    fn mn_preview_items(&self, address: &str, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(
            text::PREVIEW_TITLE.get(lang).to_owned(),
        )));
        items.push(Item::Help(text::PREVIEW_HELP.get(lang).to_owned()));
        // Grouped like every other EVM address (§3.3).
        items.push(Item::Mono(
            yw_core::evm::address::parse_address(address).map_or_else(
                |_| address.to_owned(),
                |parsed| yw_core::evm::display::format_address(&parsed),
            ),
        ));
        let same = !self.mn.preview_cards.is_empty();
        if same {
            let cards: Vec<String> = self
                .mn
                .preview_cards
                .iter()
                .map(|serial| format!("#{serial}"))
                .collect();
            items.push(Item::Text(text::YK_SAME.fill(lang, [&cards.join(", ")])));
            items.push(Item::Banner(
                crate::app_yubikey::text::YK_SAME.get(lang).to_owned(),
                Tone::HighRisk,
            ));
            items.push(Item::Row(vec![Ctl::check(
                ids::PREVIEW_SAME_ACK,
                text::YK_SAME_ACK.get(lang),
                self.mn.same_ack,
            )]));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::PREVIEW_CONFIRM, text::IMPORT.get(lang))
                .enabled(!same || self.mn.same_ack),
            Ctl::button(ids::PREVIEW_CANCEL, text::CANCEL.get(lang)),
        ]));
        items.push(Item::CardEnd);
    }

    /// The "계정 추가" picker under the EVM account list (several mnemonics).
    pub(crate) fn mn_pick_row(&self, items: &mut Vec<Item>) {
        if !self.mn.add_pick {
            return;
        }
        let lang = self.settings.language;
        items.push(Item::Help(text::PICK_EVM.get(lang).to_owned()));
        let mut buttons: Vec<Ctl> = self
            .mn
            .infos
            .iter()
            .enumerate()
            .map(|(row, info)| {
                let room = self.meta.as_ref().is_some_and(|meta| {
                    if info.primary {
                        meta.next_index().is_some()
                    } else {
                        meta.mnemonics
                            .iter()
                            .find(|entry| entry.record_id == *info.id.as_bytes())
                            .is_some_and(|entry| entry.next_index().is_some())
                    }
                });
                Ctl::button(row_id(ids::PICK_BASE, row), &self.mnemonic_label(info.id))
                    .enabled(room)
            })
            .collect();
        buttons.push(Ctl::button(ids::PICK_CANCEL, text::CANCEL.get(lang)));
        items.push(Item::Row(buttons));
    }

    /// The Solana "계정 추가" picker (several mnemonics, spec/02 §8.6).
    pub(crate) fn sol_pick_row(&self, items: &mut Vec<Item>) {
        if !self.sol.add_pick {
            return;
        }
        let lang = self.settings.language;
        items.push(Item::Help(text::PICK_SOL.get(lang).to_owned()));
        let mut buttons: Vec<Ctl> = self
            .mn
            .infos
            .iter()
            .enumerate()
            .map(|(row, info)| {
                let room = self.meta.as_ref().is_some_and(|meta| {
                    if info.primary {
                        meta.next_sol_index().is_some()
                    } else {
                        meta.mnemonic_accounts
                            .next_sol_index(*info.id.as_bytes())
                            .is_some()
                    }
                });
                Ctl::button(
                    row_id(ids::SOL_PICK_BASE, row),
                    &self.mnemonic_label(info.id),
                )
                .enabled(room && !self.sol.creating)
            })
            .collect();
        buttons.push(Ctl::button(ids::SOL_PICK_CANCEL, text::CANCEL.get(lang)));
        items.push(Item::Row(buttons));
    }
}
