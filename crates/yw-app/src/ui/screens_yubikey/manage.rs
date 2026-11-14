//! The card actions of the `YubiKey` list (spec/10 §15, spec/04 §2.19): "슬롯 구성 바꾸기" and
//! "`YubiKey` 비우기", shown in place of the list while open.

use yw_core::lang::{Lang, Text, Tpl};
use yw_core::yubikey::manage::ClearMethod;
use yw_core::yubikey::plan::{CardSlot, PgpKey, address_texts};
use yw_core::yubikey::record::{HwKeyRecord, RecordedSlot};
use yw_core::zec::ZecNetwork;

use super::ids::{self, ReslotAction};
use super::text as t;
use super::{script_label, slot_items, steps_item, zec_network_label};
use crate::app::App;
use crate::app_yubikey::CARD_SCRIPTS;
use crate::app_yubikey::manage::text as mt;
use crate::app_yubikey::manage::{
    Chain, ClearFlow, ClearStep, MAX_RESLOT_INDEX, Preset, ReslotFlow, ReslotStep, YkManage,
    lost_slots,
};
use crate::app_yubikey::text as yk;
use crate::ui::main_window::{Ctl, Item, Tone};

/// The steps of "슬롯 구성 바꾸기".
pub const RESLOT_STEPS: [Text; 4] = [
    t::STEP_RESLOT_CHOOSE,
    t::STEP_CONFIRM,
    t::STEP_PUT_ON_CARD,
    t::STEP_RESULT,
];

fn holders_text(holders: &[u32]) -> String {
    holders
        .iter()
        .map(|serial| format!("#{serial}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// T-YK-KEY-LOST with the keys it names, its checkbox and the typed [`mt::LOSS_WORD`] (spec/10
/// §15): keys connected without recovery words that no other enrolled card holds. `balances` are
/// those keys' balance sentences of the "지워지는 계정" block (2026-11-10), said inside the band.
fn loss_items(
    lang: Lang,
    (lost, balances): (&[RecordedSlot], &[String]),
    (ack_id, edit_id): (u16, u16),
    (acked, typed): (bool, &str),
    items: &mut Vec<Item>,
) {
    if lost.is_empty() {
        return;
    }
    let mut band = mt::YK_KEY_LOST.get(lang).to_owned();
    for sentence in balances {
        band.push(' ');
        band.push_str(sentence);
    }
    items.push(Item::Banner(band, Tone::HighRisk));
    for slot in lost {
        items.push(Item::Text(t::LOST_LINE.fill(
            lang,
            [&slot.slot.label_in(lang), &slot.role.title_in(lang)],
        )));
        for address in address_texts(slot.role, &slot.public).unwrap_or_default() {
            items.push(Item::Mono(address));
        }
    }
    items.push(Item::Row(vec![Ctl::check(
        ack_id,
        mt::YK_KEY_LOST_ACK.get(lang),
        acked,
    )]));
    items.push(Item::LabeledRow(
        t::TYPE_WORD.fill(lang, [mt::LOSS_WORD.get(lang)]),
        vec![Ctl::edit(edit_id, typed, 120, false, 8)],
    ));
}

fn record_items(lang: Lang, record: &HwKeyRecord, items: &mut Vec<Item>) {
    for slot in &record.slots {
        slot_items(
            lang,
            (slot.slot, slot.role),
            slot.touch,
            slot.pin,
            &address_texts(slot.role, &slot.public).unwrap_or_default(),
            items,
        );
    }
}

impl App {
    /// The open card action.
    pub(super) fn yk_manage_items(&self, manage: &YkManage, items: &mut Vec<Item>) {
        match manage {
            YkManage::Reslot(flow) => self.yk_reslot_items(flow, items),
            YkManage::Clear(flow) => self.yk_clear_items(flow, items),
        }
    }

    // ----- 슬롯 구성 바꾸기 ----------------------------------------------------------------------

    fn yk_reslot_items(&self, flow: &ReslotFlow, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Subtitle(
            t::RESLOT_TITLE.fill(lang, [&flow.serial.to_string()]),
        ));
        let current = match flow.step {
            ReslotStep::Choose => 1,
            ReslotStep::Confirm => 2,
            ReslotStep::Running => 3,
            ReslotStep::Result => 4,
        };
        items.push(steps_item(lang, &RESLOT_STEPS, current));
        match flow.step {
            ReslotStep::Choose => self.yk_reslot_choose_items(flow, items),
            ReslotStep::Confirm => self.yk_reslot_confirm_items(flow, items),
            ReslotStep::Running => {
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle(t::RESLOT_RUNNING.get(lang).to_owned()));
                items.push(Item::Text(t::RUNNING_KEEP.get(lang).to_owned()));
                items.push(Item::CardEnd);
            }
            ReslotStep::Result => self.yk_reslot_result_items(flow, items),
        }
    }

    fn yk_reslot_slot_items(&self, flow: &ReslotFlow, key: PgpKey, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let form = flow.form(key);
        items.push(Item::Subtitle(CardSlot::OpenPgp(key).label_in(lang)));
        let chains: Vec<Chain> = Chain::ALL
            .into_iter()
            .filter(|chain| *chain != Chain::Shared || flow.advanced || form.chain == *chain)
            .collect();
        items.push(Item::LabeledRow(
            t::LABEL_CHAIN.get(lang).to_owned(),
            chains
                .into_iter()
                .enumerate()
                .map(|(position, chain)| {
                    Ctl::radio(
                        ids::reslot_id(key, ReslotAction::Chain(chain)),
                        chain.label(lang),
                        form.chain == chain,
                        position == 0,
                    )
                })
                .collect(),
        ));
        let max = MAX_RESLOT_INDEX.to_string();
        items.push(Item::LabeledRow(
            if matches!(form.chain, Chain::Evm | Chain::Shared) {
                t::LABEL_ACCOUNT_INDEX.fill(lang, [&max])
            } else {
                t::LABEL_ADDRESS_INDEX.fill(lang, [&max])
            },
            vec![Ctl::edit(
                match key {
                    PgpKey::Sig => ids::RESLOT_SIG_INDEX_EDIT,
                    PgpKey::Aut => ids::RESLOT_AUT_INDEX_EDIT,
                },
                &form.index_text,
                80,
                false,
                3,
            )],
        ));
        if matches!(form.chain, Chain::Btc | Chain::Shared) {
            items.push(Item::LabeledRow(
                t::LABEL_ADDRESS_TYPE.fill(lang, [self.yk_network().display_name_in(lang)]),
                CARD_SCRIPTS
                    .into_iter()
                    .enumerate()
                    .map(|(position, script)| {
                        Ctl::radio(
                            ids::reslot_id(key, ReslotAction::Script(script)),
                            &script_label(lang, script),
                            form.script == script,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
        }
        if let Ok(planned) = flow.planned(lang, key, self.yk_network()) {
            items.push(Item::Help(
                t::PATH_LINE.fill(lang, [&planned.role.path_text_in(lang)]),
            ));
        }
    }

    fn yk_reslot_choose_items(&self, flow: &ReslotFlow, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::CardStart(Some(
            t::CARD_CURRENT_SLOTS.get(lang).to_owned(),
        )));
        if let Some(before) = flow.before.as_ref() {
            record_items(lang, before, items);
        }
        items.push(Item::Help(t::RESLOT_ONLY_PGP.get(lang).to_owned()));
        if flow
            .before
            .as_ref()
            .is_some_and(|before| !before.has_known_path())
        {
            items.push(Item::Help(t::RESLOT_UNKNOWN_CARD.get(lang).to_owned()));
        }
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(
            t::CARD_NEW_LAYOUT.get(lang).to_owned(),
        )));
        items.push(Item::LabeledRow(
            t::LABEL_PRESET.get(lang).to_owned(),
            Preset::ALL
                .into_iter()
                .enumerate()
                .map(|(position, preset)| {
                    Ctl::radio(
                        ids::preset_id(preset),
                        preset.label(lang),
                        flow.preset == preset,
                        position == 0,
                    )
                })
                .collect(),
        ));
        self.yk_reslot_slot_items(flow, PgpKey::Sig, items);
        self.yk_reslot_slot_items(flow, PgpKey::Aut, items);
        if flow.sig.chain == Chain::Zec || flow.aut.chain == Chain::Zec {
            items.push(Item::LabeledRow(
                t::LABEL_ZEC_NETWORK.get(lang).to_owned(),
                [ZecNetwork::Mainnet, ZecNetwork::Testnet]
                    .into_iter()
                    .enumerate()
                    .map(|(position, network)| {
                        Ctl::radio(
                            if network == ZecNetwork::Mainnet {
                                ids::RESLOT_ZEC_MAIN
                            } else {
                                ids::RESLOT_ZEC_TEST
                            },
                            zec_network_label(lang, network),
                            flow.zec_network == network,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
        }
        items.push(Item::Help(t::STANDARD_PATHS.get(lang).to_owned()));
        items.push(Item::Row(vec![Ctl::check(
            ids::RESLOT_ADVANCED,
            t::ADVANCED.get(lang),
            flow.advanced,
        )]));
        if flow.uses_shared() {
            items.push(Item::Banner(yk::YK_SHARED.get(lang).to_owned(), Tone::Warn));
            items.push(Item::Row(vec![Ctl::check(
                ids::RESLOT_SHARED_ACK,
                t::SHARED_ACK.get(lang),
                flow.shared_ack,
            )]));
        }
        items.push(Item::CardEnd);
        items.push(Item::Help(mt::YK_RESLOT_WORDS.get(lang).to_owned()));
        if let Some(error) = &flow.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::primary(
                ids::RESLOT_NEXT,
                if flow.seed_held {
                    t::BTN_NEXT_CONFIRM
                } else {
                    t::BTN_NEXT_WORDS
                }
                .get(lang),
            ),
            Ctl::button(ids::MANAGE_CANCEL, t::BTN_CANCEL.get(lang)),
        ]));
    }

    #[expect(clippy::too_many_lines, reason = "one screen of the re-slot flow")]
    fn yk_reslot_confirm_items(&self, flow: &ReslotFlow, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let Some(preview) = flow.preview.as_ref() else {
            items.push(Item::CardStart(None));
            items.push(Item::Subtitle(t::CHECKING.get(lang).to_owned()));
            items.push(Item::Text(t::COMPUTING_RESLOT.get(lang).to_owned()));
            items.push(Item::CardEnd);
            items.push(Item::Row(vec![
                Ctl::button(ids::RESLOT_BACK, t::BTN_CHOOSE_AGAIN.get(lang)),
                Ctl::button(ids::MANAGE_CANCEL, t::BTN_CANCEL.get(lang)),
            ]));
            return;
        };
        if let Err(error) = preview.plan {
            items.push(Item::Banner(error.text_in(lang), Tone::Danger));
        }
        if preview.same_as_vault {
            items.push(Item::Banner(
                if preview.words_only {
                    yk::YK_SAME_WORDS
                } else {
                    yk::YK_SAME
                }
                .get(lang)
                .to_owned(),
                Tone::HighRisk,
            ));
            items.push(Item::Row(vec![Ctl::check(
                ids::RESLOT_SAME_ACK,
                t::SAME_ACK_RESLOT.get(lang),
                flow.same_ack,
            )]));
        }
        let others = self.yk_other_records(flow.serial);
        items.push(Item::CardStart(Some(
            t::AFTER_CHANGE.fill(lang, [&flow.serial.to_string()]),
        )));
        items.push(Item::Text(t::RESLOT_CONFIRM_TEXT.get(lang).to_owned()));
        for line in &preview.lines {
            let planned = line.planned;
            slot_items(
                lang,
                (planned.slot, planned.role),
                planned.touch,
                planned.pin,
                &line.addresses,
                items,
            );
            let unchanged = flow.before.as_ref().is_some_and(|before| {
                before.slots.iter().any(|slot| {
                    slot.slot == planned.slot
                        && slot.role.key_identity() == planned.role.key_identity()
                        && slot.public == line.public
                })
            });
            let holders = crate::yubikey::holders(&others, planned.role);
            let relation = match (unchanged, holders.is_empty()) {
                (true, _) => t::RELATION_UNCHANGED.get(lang).to_owned(),
                (false, true) => t::RELATION_PUT.get(lang).to_owned(),
                (false, false) => t::RELATION_PUT_BACKUP.fill(lang, [&holders_text(&holders)]),
            };
            items.push(Item::Field(
                t::FIELD_RELATION.get(lang).to_owned(),
                relation,
            ));
        }
        items.push(Item::CardEnd);
        let dropped = flow.dropped(&others);
        if !dropped.is_empty() {
            items.push(Item::CardStart(Some(t::CARD_DROPPED.get(lang).to_owned())));
            // The "지워지는 계정" block (2026-11-10): addresses and last-read balances.
            let accounts: Vec<crate::ui::removed::RemovedAccount> = dropped
                .iter()
                .map(|(slot, holders)| {
                    let mut account = self.card_removed(slot, &others, true);
                    account.note = Some(match (holders.is_empty(), slot.path_known) {
                        (true, true) => t::DROP_NOT_ELSEWHERE.get(lang).to_owned(),
                        (true, false) => t::DROP_LOST.get(lang).to_owned(),
                        (false, _) => t::DROP_KEPT.fill(lang, [&holders_text(holders)]),
                    });
                    account
                })
                .collect();
            let balances = crate::ui::removed::removed_items(lang, &accounts, items);
            let changed: Vec<CardSlot> = dropped.iter().map(|(slot, _)| slot.slot).collect();
            self.yk_zec_unusable_items(flow.serial, &changed, t::ZEC_UNUSABLE_CHANGE, items);
            // "복구 단어로 언제든 복구" holds only for keys with a known path.
            if dropped.iter().any(|(slot, _)| slot.path_known) {
                items.push(Item::Banner(
                    mt::YK_RESLOT_REMOVED.get(lang).to_owned(),
                    Tone::Warn,
                ));
            }
            items.push(Item::Row(vec![Ctl::check(
                ids::RESLOT_REMOVED_ACK,
                t::REMOVED_ACK.get(lang),
                flow.removed_ack,
            )]));
            loss_items(
                lang,
                (&lost_slots(&dropped), &balances),
                (ids::RESLOT_LOSS_ACK, ids::RESLOT_LOSS_EDIT),
                (flow.loss_ack, &flow.loss_typed),
                items,
            );
            items.push(Item::CardEnd);
        }
        if let Some(error) = &flow.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Help(mt::YK_RESLOT_BACKUP.get(lang).to_owned()));
        items.push(Item::Help(t::ADMIN_NEXT.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::primary(ids::RESLOT_IMPORT, t::STEP_PUT_ON_CARD.get(lang))
                .enabled(flow.can_import(&others)),
            Ctl::button(ids::RESLOT_BACK, t::BTN_CHOOSE_AGAIN.get(lang)),
            Ctl::button(ids::MANAGE_CANCEL, t::BTN_CANCEL.get(lang)),
        ]));
    }

    fn yk_reslot_result_items(&self, flow: &ReslotFlow, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        if let Some(failure) = &flow.failure {
            items.push(Item::Banner(failure.clone(), Tone::Danger));
            items.push(Item::Row(vec![
                Ctl::primary(ids::RESLOT_RETRY, t::BTN_RETRY.get(lang)),
                Ctl::button(ids::RESLOT_BACK, t::BTN_CHOOSE_AGAIN.get(lang)),
                Ctl::button(ids::MANAGE_CANCEL, t::BTN_CANCEL.get(lang)),
            ]));
            return;
        }
        let Some(record) = flow.result.as_ref() else {
            return;
        };
        items.push(Item::Banner(
            t::RESLOT_DONE.fill(lang, [&record.serial.to_string()]),
            Tone::Success,
        ));
        // Done under the factory admin PIN: the card does not sign until its PINs are set
        // (spec/10 §9.3, 2026-11-10).
        if self.yk_card_on_defaults(record.serial) {
            items.push(Item::Banner(
                t::NO_SIGN_BEFORE_PIN.get(lang).to_owned(),
                Tone::Warn,
            ));
            items.push(Item::Row(vec![Ctl::primary(
                ids::RESLOT_PIN_NOW,
                t::BTN_SET_PIN_NOW.get(lang),
            )]));
        }
        items.push(Item::CardStart(Some(format!("YubiKey #{}", record.serial))));
        record_items(lang, record, items);
        items.push(Item::CardEnd);
        let candidates: Vec<(usize, &HwKeyRecord)> = self
            .card
            .records
            .iter()
            .enumerate()
            .filter(|(_, other)| !flow.done.contains(&other.serial))
            .collect();
        if !candidates.is_empty() {
            items.push(Item::CardStart(Some(
                t::CARD_APPLY_BACKUP.get(lang).to_owned(),
            )));
            items.push(Item::Text(mt::YK_RESLOT_BACKUP.get(lang).to_owned()));
            items.push(Item::Help(t::APPLY_HELP.get(lang).to_owned()));
            for (row, other) in candidates {
                let shared = flow.before.as_ref().map_or(0, |before| {
                    other
                        .slots
                        .iter()
                        .filter(|slot| {
                            before
                                .slots
                                .iter()
                                .any(|held| held.role.key_identity() == slot.role.key_identity())
                        })
                        .count()
                });
                items.push(Item::Row(vec![Ctl::button(
                    ids::RESLOT_BACKUP_BASE.saturating_add(u16::try_from(row).unwrap_or(u16::MAX)),
                    &if shared > 0 {
                        t::APPLY_TO_SHARED
                            .fill(lang, [&other.serial.to_string(), &shared.to_string()])
                    } else {
                        t::APPLY_TO.fill(lang, [&other.serial.to_string()])
                    },
                )]));
            }
            items.push(Item::CardEnd);
        }
        items.push(Item::Row(vec![Ctl::primary(
            ids::MANAGE_DONE,
            t::BTN_DONE_WIPE.get(lang),
        )]));
    }

    // ----- YubiKey의 키 지우기 -------------------------------------------------------------------

    /// The method radios of one applet (2026-11-10: named by their result, the recommended one
    /// first), what it does, the irreversible band right under them for a reset, and how it is
    /// done under '어떻게 지우나요 ▸'.
    fn yk_clear_method_items(
        lang: Lang,
        (current, (ours, reset)): (Option<ClearMethod>, (u16, u16)),
        labels: (&str, &str),
        (ours_text, reset_text): (&str, &str),
        (how_ours, how_reset, how_open): (&str, &str, bool),
        items: &mut Vec<Item>,
    ) {
        let Some(method) = current else {
            return;
        };
        items.push(Item::LabeledRow(
            t::LABEL_METHOD.get(lang).to_owned(),
            vec![
                Ctl::radio(ours, labels.0, method == ClearMethod::OurSlots, true),
                Ctl::radio(reset, labels.1, method == ClearMethod::Reset, false),
            ],
        ));
        if method == ClearMethod::Reset {
            items.push(Item::Banner(
                t::RESET_IRREVERSIBLE.get(lang).to_owned(),
                Tone::HighRisk,
            ));
        }
        items.push(Item::Help(
            if method == ClearMethod::OurSlots {
                ours_text
            } else {
                reset_text
            }
            .to_owned(),
        ));
        if how_open {
            items.push(Item::Help(
                if method == ClearMethod::OurSlots {
                    how_ours
                } else {
                    how_reset
                }
                .to_owned(),
            ));
        }
    }

    /// The wallet's Zcash accounts whose key only `slots` of card `serial` hold
    /// (`App::zec_accounts_using_card`): clearing or re-slotting them leaves the Zcash tab
    /// without a signing key (spec/10 §15, spec/12).
    fn yk_zec_unusable_items(
        &self,
        serial: u32,
        slots: &[CardSlot],
        sentence: Tpl<1>,
        items: &mut Vec<Item>,
    ) {
        let lang = self.settings.language;
        for account in self.zec_accounts_using_card(serial, slots) {
            items.push(Item::Banner(
                sentence.fill(lang, [&account.address()]),
                Tone::HighRisk,
            ));
        }
    }

    #[expect(clippy::too_many_lines, reason = "one screen of the clear flow")]
    fn yk_clear_items(&self, flow: &ClearFlow, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Subtitle(
            t::CLEAR_TITLE.fill(lang, [&flow.serial.to_string()]),
        ));
        let Some(before) = flow.before.as_ref() else {
            return;
        };
        match flow.step {
            ClearStep::Running => {
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle(t::CLEAR_RUNNING.get(lang).to_owned()));
                items.push(Item::Text(t::DONT_REMOVE.get(lang).to_owned()));
                items.push(Item::CardEnd);
                return;
            }
            ClearStep::Result => {
                self.yk_clear_result_items(flow, items);
                return;
            }
            ClearStep::Choose => {}
        }
        let has = |pgp: bool| {
            before
                .slots
                .iter()
                .filter(|slot| matches!(slot.slot, CardSlot::OpenPgp(_)) == pgp)
                .count()
        };
        items.push(Item::CardStart(Some(
            t::CARD_WHAT_TO_ERASE.get(lang).to_owned(),
        )));
        if has(true) > 0 {
            items.push(Item::Row(vec![Ctl::check(
                ids::CLEAR_PGP_TOGGLE,
                &t::PGP_KEYS.fill(lang, [&has(true).to_string()]),
                flow.openpgp.is_some(),
            )]));
            Self::yk_clear_method_items(
                lang,
                (flow.openpgp, (ids::CLEAR_PGP_OURS, ids::CLEAR_PGP_RESET)),
                (t::PGP_OURS.get(lang), t::PGP_RESET.get(lang)),
                (
                    mt::YK_CLEAR_PGP_OURS_RESULT.get(lang),
                    mt::YK_CLEAR_PGP_RESET_RESULT.get(lang),
                ),
                (
                    mt::YK_CLEAR_PGP_OURS.get(lang),
                    mt::YK_CLEAR_PGP_RESET.get(lang),
                    flow.how_open,
                ),
                items,
            );
        }
        if has(false) > 0 {
            items.push(Item::Row(vec![Ctl::check(
                ids::CLEAR_PIV_TOGGLE,
                &t::PIV_SLOTS.fill(lang, [&has(false).to_string()]),
                flow.piv.is_some(),
            )]));
            Self::yk_clear_method_items(
                lang,
                (flow.piv, (ids::CLEAR_PIV_OURS, ids::CLEAR_PIV_RESET)),
                (t::PIV_OURS.get(lang), t::PIV_RESET.get(lang)),
                (
                    mt::YK_CLEAR_PIV_OURS_RESULT.get(lang),
                    mt::YK_CLEAR_PIV_RESET_RESULT.get(lang),
                ),
                (
                    mt::YK_CLEAR_PIV_OURS.get(lang),
                    mt::YK_CLEAR_PIV_RESET.get(lang),
                    flow.how_open,
                ),
                items,
            );
            if flow.piv == Some(ClearMethod::OurSlots)
                && !before
                    .firmware
                    .at_least(yw_core::yubikey::piv::DOCUMENTED_FIRMWARE_DELETE_KEY)
            {
                items.push(Item::Help(
                    t::PIV_DELETE_FIRMWARE.fill(lang, [&before.firmware.to_string()]),
                ));
            }
        }
        items.push(Item::Help(mt::YK_CLEAR_SCOPE.get(lang).to_owned()));
        if flow.openpgp.is_some() || flow.piv.is_some() {
            items.push(Item::Row(vec![Ctl::link(
                ids::CLEAR_HOW,
                if flow.how_open {
                    t::HOW_OPEN
                } else {
                    t::HOW_CLOSED
                }
                .get(lang),
            )]));
        }
        items.push(Item::CardEnd);
        let plan = flow.plan();
        if plan.any() {
            let others = self.yk_other_records(flow.serial);
            items.push(Item::CardStart(Some(t::CARD_UNUSABLE.get(lang).to_owned())));
            // The "지워지는 계정" block (2026-11-10): addresses and last-read balances.
            let accounts: Vec<crate::ui::removed::RemovedAccount> = before
                .slots
                .iter()
                .filter(|slot| plan.clears(slot.slot))
                .map(|slot| {
                    let holders = crate::yubikey::holders(&others, slot.role);
                    let mut account = self.card_removed(slot, &others, true);
                    account.label = format!("{} — {}", slot.slot.label_in(lang), account.label);
                    account.note = Some(if holders.is_empty() && !slot.path_known {
                        t::CLEAR_LOST.get(lang).to_owned()
                    } else if holders.is_empty() {
                        t::CLEAR_NOT_ELSEWHERE.get(lang).to_owned()
                    } else {
                        t::CLEAR_KEPT.fill(lang, [&holders_text(&holders)])
                    });
                    account
                })
                .collect();
            let balances = crate::ui::removed::removed_items(lang, &accounts, items);
            let cleared: Vec<CardSlot> = before
                .slots
                .iter()
                .filter(|slot| plan.clears(slot.slot))
                .map(|slot| slot.slot)
                .collect();
            self.yk_zec_unusable_items(flow.serial, &cleared, t::ZEC_UNUSABLE_ERASE, items);
            // "복구 단어로 언제든 복구" holds only for keys with a known path.
            if before
                .slots
                .iter()
                .any(|slot| plan.clears(slot.slot) && slot.path_known)
            {
                items.push(Item::Banner(
                    mt::YK_CLEAR_FUNDS.get(lang).to_owned(),
                    Tone::Warn,
                ));
            }
            loss_items(
                lang,
                (&self.yk_clear_lost(flow), &balances),
                (ids::CLEAR_LOSS_ACK, ids::CLEAR_LOSS_EDIT),
                (flow.loss_ack, &flow.loss_typed),
                items,
            );
            if plan.remaining(before).is_none() {
                items.push(Item::Help(t::NO_SLOT_LEFT.get(lang).to_owned()));
            }
            items.push(Item::CardEnd);
        }
        if !self.yk_clear_allowed(flow) {
            items.push(Item::Banner(
                t::LAST_KEY_CLEAR.get(lang).to_owned(),
                Tone::Danger,
            ));
        }
        items.push(Item::LabeledRow(
            t::TYPE_WORD.fill(lang, [mt::CLEAR_WORD.get(lang)]),
            vec![Ctl::edit(
                ids::CLEAR_CONFIRM_EDIT,
                &flow.typed,
                120,
                false,
                8,
            )],
        ));
        let mut asks: Vec<&str> = Vec::new();
        if plan.openpgp == Some(ClearMethod::OurSlots) {
            asks.push(crate::yubikey::PinKind::OpenPgpAdmin.name(lang));
        }
        if plan.piv == Some(ClearMethod::OurSlots) {
            asks.push("PIV PIN");
        }
        items.push(Item::Help(if asks.is_empty() {
            t::RESET_NO_PIN.get(lang).to_owned()
        } else {
            t::ASKS.fill(lang, [&asks.join(", ")])
        }));
        if let Some(error) = &flow.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::danger(ids::CLEAR_RUN, t::BTN_ERASE_THIS.get(lang))
                .enabled(self.yk_clear_ready(flow)),
            Ctl::button(ids::MANAGE_CANCEL, t::BTN_CANCEL.get(lang)),
        ]));
    }

    fn yk_clear_result_items(&self, flow: &ClearFlow, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        if let Some(failure) = &flow.failure {
            items.push(Item::Banner(failure.clone(), Tone::Danger));
        }
        if let Some(cleared) = flow.result {
            // "이 지갑의 슬롯만 지우기" sent the applet's PIN (OpenPGP admin PIN, PIV PIN): a
            // wrong one is named (spec/10 §9.1).
            let line =
                |name: &str,
                 pin: crate::yubikey::PinKind,
                 asked: Option<ClearMethod>,
                 result: Option<Result<(), yw_core::yubikey::CardError>>| {
                    match (asked, result) {
                        (Some(ClearMethod::OurSlots), Some(Ok(()))) => {
                            Some((t::RESULT_OURS.fill(lang, [name]), Tone::Success))
                        }
                        (Some(ClearMethod::Reset), Some(Ok(()))) => {
                            Some((t::RESULT_RESET.fill(lang, [name]), Tone::Success))
                        }
                        (Some(method), Some(Err(error))) => {
                            let why = if method == ClearMethod::OurSlots {
                                pin.error_text_in(
                                    lang,
                                    error,
                                    &crate::yubikey::PinContext::of(
                                        &self.card.records,
                                        flow.serial,
                                        pin,
                                    ),
                                )
                            } else {
                                error.text_in(lang)
                            };
                            Some((t::RESULT_FAILED.fill(lang, [name, &why]), Tone::Danger))
                        }
                        (Some(_), None) => Some((t::RESULT_SKIPPED.fill(lang, [name]), Tone::Warn)),
                        (None, _) => None,
                    }
                };
            for (text, tone) in [
                line(
                    "OpenPGP",
                    crate::yubikey::PinKind::OpenPgpAdmin,
                    cleared.asked.openpgp,
                    cleared.report.openpgp,
                ),
                line(
                    "PIV",
                    crate::yubikey::PinKind::PivPin,
                    cleared.asked.piv,
                    cleared.report.piv,
                ),
            ]
            .into_iter()
            .flatten()
            {
                items.push(Item::Banner(text, tone));
            }
            match cleared.vault {
                Ok(()) if cleared.removed => {
                    items.push(Item::Text(t::RESULT_RECORD_REMOVED.get(lang).to_owned()));
                }
                Ok(()) => items.push(Item::Text(t::RESULT_SLOTS_REMOVED.get(lang).to_owned())),
                Err(error) => items.push(Item::Banner(
                    t::RESULT_VAULT_FAILED
                        .fill(lang, [&crate::errors::vault_code(error).text_in(lang)]),
                    Tone::Danger,
                )),
            }
            let done = cleared.report.done(cleared.asked);
            if done.openpgp == Some(ClearMethod::Reset) || done.piv == Some(ClearMethod::Reset) {
                items.push(Item::Help(t::RESULT_RESET_PINS.get(lang).to_owned()));
            }
            let known_cleared = flow.before.as_ref().is_some_and(|before| {
                before
                    .slots
                    .iter()
                    .any(|slot| cleared.asked.clears(slot.slot) && slot.path_known)
            });
            if known_cleared {
                items.push(Item::Help(mt::YK_CLEAR_FUNDS.get(lang).to_owned()));
            }
        }
        items.push(Item::Row(vec![Ctl::primary(
            ids::MANAGE_DONE,
            t::BTN_FINISH.get(lang),
        )]));
    }
}
