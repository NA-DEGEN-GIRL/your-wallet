//! The recovery-phrase screens (spec/04 §2.22): the settings section "복구 단어" (one card per
//! mnemonic with its label, words, backup state and actions; the address preview of
//! "복구 단어 추가 가져오기"; the removal warning) and the "계정 추가" mnemonic picker row.

use crate::app::{App, AppMode};
use crate::app_mnemonics::{T_MN_INTRO, T_MN_REMOVE, T_MN_UNCONFIRMED};
use crate::ui::main_window::{Ctl, Item, Tone};

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
    ];
}

fn row_id(base: u16, row: usize) -> u16 {
    base.saturating_add(u16::try_from(row).unwrap_or(ids::ROW_SPAN))
}

impl App {
    /// Settings → 복구 단어.
    pub(crate) fn mn_settings_section(&self, items: &mut Vec<Item>) {
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        items.push(Item::Help(T_MN_INTRO.to_owned()));
        if self.mn.infos.is_empty() {
            items.push(Item::Help(
                "이 지갑에는 아직 복구 단어가 없습니다(개인키·YubiKey로 시작한 지갑). 복구 단어를 더하면 그 계정이 계정 목록에 생깁니다."
                    .to_owned(),
            ));
        }
        for (row, info) in self.mn.infos.iter().enumerate() {
            let label = self.mnemonic_label(info.id);
            items.push(Item::CardStart(Some(label.clone())));
            let accounts = if info.primary {
                self.meta.as_ref().map_or(0, |meta| meta.evm_accounts.len())
            } else {
                self.meta.as_ref().map_or(0, |meta| {
                    meta.mnemonics
                        .iter()
                        .find(|entry| entry.record_id == *info.id.as_bytes())
                        .map_or(0, |entry| entry.evm.len())
                })
            };
            let mut facts = vec![format!("{}단어", info.words)];
            if info.passphrase_used {
                facts.push("passphrase 사용".to_owned());
            }
            facts.push(format!("EVM 계정 {accounts}개"));
            if info.primary {
                facts.push("첫 복구 단어(Solana·Bitcoin·Zcash 계정도 이 단어에서)".to_owned());
            }
            facts.push(if info.backup_confirmed {
                "백업 확인됨".to_owned()
            } else {
                "백업 확인 전".to_owned()
            });
            items.push(Item::Help(facts.join(" · ")));
            if !info.backup_confirmed {
                items.push(Item::Banner(T_MN_UNCONFIRMED.to_owned(), Tone::Warn));
            }
            if self.mn.rename == Some(info.id) {
                items.push(Item::Row(vec![
                    Ctl::edit(ids::RENAME_EDIT, &label, 260, false, 64),
                    Ctl::primary(ids::RENAME_SAVE, "저장"),
                    Ctl::button(ids::RENAME_CANCEL, "취소"),
                ]));
            } else {
                let mut actions = vec![
                    Ctl::button(row_id(ids::RENAME_BASE, row), "이름 바꾸기"),
                    Ctl::button(row_id(ids::REVEAL_BASE, row), "단어 보기"),
                ];
                if !info.backup_confirmed {
                    actions.push(
                        Ctl::primary(row_id(ids::BACKUP_BASE, row), "백업 확인").enabled(unlocked),
                    );
                }
                if !info.primary {
                    actions.push(
                        Ctl::danger(row_id(ids::REMOVE_BASE, row), "지우기").enabled(unlocked),
                    );
                }
                items.push(Item::Row(actions));
            }
            if self.mn.confirm_remove == Some(info.id) {
                items.push(Item::Banner(T_MN_REMOVE.to_owned(), Tone::Danger));
                items.push(Item::Row(vec![
                    Ctl::danger(ids::REMOVE_CONFIRM, "이 복구 단어 지우기"),
                    Ctl::button(ids::REMOVE_CANCEL, "취소"),
                ]));
            }
            items.push(Item::CardEnd);
        }
        if let Some(address) = &self.mn.preview {
            items.push(Item::CardStart(Some("가져올 복구 단어".to_owned())));
            items.push(Item::Help(
                "이 복구 단어의 첫 계정(m/44'/60'/0'/0/0) 주소입니다. 다른 지갑에서 보던 주소와 같은지 확인하세요. 다르면 단어나 passphrase가 틀렸습니다."
                    .to_owned(),
            ));
            items.push(Item::Mono(address.clone()));
            items.push(Item::Row(vec![
                Ctl::primary(ids::PREVIEW_CONFIRM, "가져오기"),
                Ctl::button(ids::PREVIEW_CANCEL, "취소"),
            ]));
            items.push(Item::CardEnd);
        }
        let room = self.mn.infos.len() < yw_core::vault::MAX_MNEMONICS;
        items.push(Item::Row(vec![
            Ctl::primary(ids::IMPORT, "복구 단어 추가 가져오기").enabled(unlocked && room),
            Ctl::button(ids::CREATE, "새 복구 단어 만들기 (추가)").enabled(unlocked && room),
        ]));
        items.push(Item::Help(
            "추가한 복구 단어에서는 EVM 계정(이더리움·HyperEVM·HyperCore 등)이 생깁니다. Solana·Bitcoin·Zcash 계정은 첫 복구 단어에서만 만듭니다. 비밀번호를 다시 입력해야 합니다."
                .to_owned(),
        ));
    }

    /// The "계정 추가" picker under the EVM account list (several mnemonics).
    pub(crate) fn mn_pick_row(&self, items: &mut Vec<Item>) {
        if !self.mn.add_pick {
            return;
        }
        items.push(Item::Help("어느 복구 단어에서 계정을 만들까요?".to_owned()));
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
        buttons.push(Ctl::button(ids::PICK_CANCEL, "취소"));
        items.push(Item::Row(buttons));
    }
}
