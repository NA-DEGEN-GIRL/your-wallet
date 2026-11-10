//! The recovery-phrase screens (spec/04 §2.24): the settings section "복구 단어" (one card per
//! mnemonic with its label, words, backup state and actions; the address preview of
//! "복구 단어 추가 가져오기"; the removal warning) and the "계정 추가" mnemonic picker row.

use crate::app::{App, AppMode};
use crate::app_mnemonics::{
    T_MN_ALT_PASS, T_MN_INTRO, T_MN_REMOVE, T_MN_REMOVE_UNCONFIRMED, T_MN_REMOVE_WORD,
    T_MN_UNCONFIRMED,
};
use crate::app_yubikey::T_YK_SAME;
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
        items.push(Item::Help(T_MN_INTRO.to_owned()));
        if unlocked && !editable {
            items.push(Item::Help(T_MN_ALT_PASS.to_owned()));
        }
        if self.mn.infos.is_empty() {
            items.push(Item::Help(
                "이 지갑에는 아직 복구 단어가 없습니다(개인키·YubiKey로 시작한 지갑). 복구 단어를 더하면 그 계정이 계정 목록에 생깁니다."
                    .to_owned(),
            ));
        }
        for (row, info) in self.mn.infos.iter().enumerate() {
            let label = self.mnemonic_label(info.id);
            items.push(Item::CardStart(Some(label.clone())));
            let [evm, sol, btc, zec] = self.mnemonic_account_counts(info.id, info.primary);
            let mut facts = vec![format!("{}단어", info.words)];
            if info.passphrase_used {
                facts.push("passphrase 사용".to_owned());
            }
            facts.push(format!(
                "계정: EVM {evm} · Solana {sol} · Bitcoin {btc} · Zcash {zec}"
            ));
            if info.primary {
                // Added phrases make Solana/Bitcoin/Zcash accounts too since 2026-11-08.
                facts.push("처음 만든(가져온) 복구 단어 · 지울 수 없음".to_owned());
            }
            facts.push(if info.backup_confirmed {
                "백업 확인됨".to_owned()
            } else {
                "백업 확인 전".to_owned()
            });
            items.push(Item::Help(facts.join(" · ")));
            // The address written on the paper with the words (W08), to tell the papers apart.
            if let Some(address) = self.mnemonic_first_address(info.id) {
                items.push(Item::Help("첫 주소(종이에 함께 적은 주소):".to_owned()));
                items.push(Item::Mono(yw_core::evm::display::format_address(&address)));
            }
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
                        Ctl::danger(row_id(ids::REMOVE_BASE, row), "지우기").enabled(editable),
                    );
                }
                items.push(Item::Row(actions));
            }
            if self.mn.confirm_remove == Some(info.id) {
                self.mn_remove_items(info.backup_confirmed, items);
            }
            items.push(Item::CardEnd);
        }
        if let Some(address) = &self.mn.preview {
            self.mn_preview_items(address, items);
        }
        let room = self.mn.infos.len() < yw_core::vault::MAX_MNEMONICS;
        items.push(Item::Row(vec![
            Ctl::primary(ids::IMPORT, "복구 단어 추가 가져오기").enabled(editable && room),
            Ctl::button(ids::CREATE, "새 복구 단어 만들기 (추가)").enabled(editable && room),
        ]));
        items.push(Item::Help(
            "추가한 복구 단어에서도 EVM·Solana·Bitcoin·Zcash 계정을 만들 수 있습니다(각 탭의 '계정 추가'에서 복구 단어를 고릅니다). 비밀번호를 다시 입력해야 합니다."
                .to_owned(),
        ));
    }

    /// The removal warning of an added phrase. One whose backup is not confirmed needs its words
    /// shown to the end (`단어 보기`) and [`T_MN_REMOVE_WORD`] typed before `지우기` asks for the
    /// password.
    fn mn_remove_items(&self, backup_confirmed: bool, items: &mut Vec<Item>) {
        if backup_confirmed {
            items.push(Item::Banner(T_MN_REMOVE.to_owned(), Tone::Danger));
        } else {
            items.push(Item::Banner(
                T_MN_REMOVE_UNCONFIRMED.to_owned(),
                Tone::HighRisk,
            ));
            items.push(Item::Row(vec![Ctl::button(
                ids::REMOVE_REVEAL,
                "1. 단어 보기 (끝까지 보고 적어 두기)",
            )]));
            items.push(Item::Help(if self.mn.remove_revealed {
                "단어를 끝까지 보았습니다.".to_owned()
            } else {
                "아직 단어를 보지 않았습니다.".to_owned()
            }));
            items.push(Item::LabeledRow(
                format!("2. 확인: '{T_MN_REMOVE_WORD}' 입력"),
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
            Ctl::danger(ids::REMOVE_CONFIRM, "이 복구 단어 지우기")
                .enabled(backup_confirmed || self.mn.remove_revealed),
            Ctl::button(ids::REMOVE_CANCEL, "취소"),
        ]));
    }

    /// The address preview of "복구 단어 추가 가져오기", with T-YK-SAME when the words are an
    /// enrolled `YubiKey`'s (spec/10 §7.1).
    fn mn_preview_items(&self, address: &str, items: &mut Vec<Item>) {
        items.push(Item::CardStart(Some("가져올 복구 단어".to_owned())));
        items.push(Item::Help(
            "이 복구 단어의 첫 계정(m/44'/60'/0'/0/0) 주소입니다. 다른 지갑에서 보던 주소와 같은지 확인하세요. 다르면 단어나 passphrase가 틀렸습니다."
                .to_owned(),
        ));
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
            items.push(Item::Text(format!(
                "이 복구 단어는 이 지갑에 등록된 YubiKey {}의 키를 만든 단어입니다. 가져오면 그 단어가 이 PC의 vault에 저장됩니다.",
                cards.join(", ")
            )));
            items.push(Item::Banner(T_YK_SAME.to_owned(), Tone::HighRisk));
            items.push(Item::Row(vec![Ctl::check(
                ids::PREVIEW_SAME_ACK,
                "이해했습니다: 이 단어를 이 PC에 저장하면 YubiKey의 보안 이득이 없어집니다",
                self.mn.same_ack,
            )]));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::PREVIEW_CONFIRM, "가져오기").enabled(!same || self.mn.same_ack),
            Ctl::button(ids::PREVIEW_CANCEL, "취소"),
        ]));
        items.push(Item::CardEnd);
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

    /// The Solana "계정 추가" picker (several mnemonics, spec/02 §8.6).
    pub(crate) fn sol_pick_row(&self, items: &mut Vec<Item>) {
        if !self.sol.add_pick {
            return;
        }
        items.push(Item::Help(
            "어느 복구 단어에서 Solana 계정을 만들까요? (m/44'/501'/i'/0')".to_owned(),
        ));
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
        buttons.push(Ctl::button(ids::SOL_PICK_CANCEL, "취소"));
        items.push(Item::Row(buttons));
    }
}
