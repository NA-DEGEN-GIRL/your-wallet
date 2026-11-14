//! The screens of "`YubiKey` 연결하기 (복구 단어 없이)" (spec/10 §7.6, spec/04 §2.19): the scan with
//! one choice per found key, the confirmation with every address in full and the unknown-path
//! note (plus the optional PIN check), then the wizard's result screen.

use yw_core::lang::Text;
use yw_core::yubikey::connect::KeyUse;
use yw_core::yubikey::plan::{CardSlot, address_texts};

use super::text as t;
use super::{grouped_address, ids, slot_items, steps_item};
use crate::app::App;
use crate::app_yubikey::connect::text as ct;
use crate::app_yubikey::connect::{Choice, ConnectForm};
use crate::app_yubikey::{WizardOrigin, WizardStep, YkWizard};
use crate::ui::main_window::{Ctl, Item, Tone};

/// The connect flow's step labels.
pub const CONNECT_STEPS: [Text; 3] = [
    t::STEP_CONNECT_READ,
    t::STEP_CONNECT_ADDRESSES,
    t::STEP_RESULT,
];

impl App {
    /// S21 in the connect flow.
    pub(super) fn yk_connect_screen(
        &self,
        wizard: &YkWizard,
        form: &ConnectForm,
        items: &mut Vec<Item>,
    ) {
        let lang = self.settings.language;
        items.push(Item::Title(
            match wizard.origin {
                WizardOrigin::NewWallet => t::TITLE_NEW_WALLET_CONNECT,
                WizardOrigin::Vault => t::BTN_CONNECT,
            }
            .get(lang)
            .to_owned(),
        ));
        let current = match wizard.step {
            WizardStep::Plan => 1,
            WizardStep::Confirm | WizardStep::Credentials => 2,
            WizardStep::Running | WizardStep::Result => 3,
        };
        items.push(steps_item(lang, &CONNECT_STEPS, current));
        match wizard.step {
            WizardStep::Plan => self.yk_connect_choose_items(form, items),
            WizardStep::Confirm | WizardStep::Credentials => {
                self.yk_connect_confirm_items(form, items);
            }
            WizardStep::Running => {
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle(t::CONNECT_RUNNING.get(lang).to_owned()));
                items.push(Item::Text(t::CONNECT_RUNNING_KEEP.get(lang).to_owned()));
                items.push(Item::CardEnd);
            }
            WizardStep::Result => {
                if wizard.failure.is_none() && wizard.enrolled.is_some() {
                    items.push(Item::Banner(
                        ct::YK_UNKNOWN_PATH.get(lang).to_owned(),
                        Tone::Warn,
                    ));
                }
                self.yk_result_items(wizard, items);
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the scan card, one card per found key, the row"
    )]
    fn yk_connect_choose_items(&self, form: &ConnectForm, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let (btc, zec) = self.yk_connect_networks();
        items.push(Item::CardStart(Some(
            t::CONNECTED_CARD.get(lang).to_owned(),
        )));
        items.push(Item::Text(ct::YK_CONNECT.get(lang).to_owned()));
        let Some(scan) = form.scan.as_ref() else {
            if let Some(error) = &form.scan_error {
                items.push(Item::Banner(error.clone(), Tone::Danger));
            } else {
                items.push(Item::Muted(t::SCANNING.get(lang).to_owned()));
            }
            items.push(Item::CardEnd);
            items.push(Item::Row(vec![
                Ctl::primary(ids::CONNECT_RESCAN, t::BTN_READ_AGAIN.get(lang)).enabled(!form.busy),
                Ctl::button(ids::WIZARD_CANCEL, t::BTN_CANCEL.get(lang)),
            ]));
            return;
        };
        items.push(Item::Field(
            "YubiKey".to_owned(),
            t::SERIAL_FIRMWARE.fill(lang, [&scan.serial.to_string(), &scan.firmware.to_string()]),
        ));
        let counters = crate::yubikey::PinCounters {
            serial: scan.serial,
            pw1: scan.pgp_pin_retries,
            pw3: None,
            piv_pin: scan.piv_pin_retries,
            puk: None,
        };
        for line in counters.lines(
            lang,
            &[
                crate::yubikey::PinKind::OpenPgpUser,
                crate::yubikey::PinKind::PivPin,
            ],
        ) {
            items.push(Item::Help(line));
        }
        for note in &scan.notes {
            items.push(Item::Help(note.text(lang)));
        }
        for (slot, reason) in &scan.unsupported {
            items.push(Item::Help(format!(
                "{}: {}",
                slot.label_in(lang),
                reason.get(lang)
            )));
        }
        if scan.keys.is_empty() {
            items.push(Item::Banner(
                t::NO_READABLE_KEYS.get(lang).to_owned(),
                Tone::Warn,
            ));
        }
        items.push(Item::CardEnd);
        for (row, (slot, chosen)) in form.choices.iter().enumerate() {
            let Some(found) = scan.key(*slot) else {
                continue;
            };
            items.push(Item::CardStart(Some(slot.label_in(lang))));
            items.push(Item::LabeledRow(
                t::LABEL_THIS_KEY.get(lang).to_owned(),
                Choice::offered(slot.curve())
                    .iter()
                    .enumerate()
                    .map(|(position, choice)| {
                        Ctl::radio(
                            ids::connect_choice_id(row, *choice),
                            &choice.label(lang),
                            chosen == choice,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
            let use_ = match chosen {
                Choice::Skip => None,
                Choice::Evm => Some(KeyUse::Evm),
                Choice::Btc(script) => Some(KeyUse::Btc {
                    network: btc,
                    script: *script,
                }),
                Choice::Zec => Some(KeyUse::Zec { network: zec }),
                Choice::Sol => Some(KeyUse::Sol),
            };
            let role = use_.and_then(|use_| use_.role(yw_core::yubikey::plan::UNKNOWN_PATH_FIRST));
            if let Some(role) = role {
                for address in address_texts(role, &found.public).unwrap_or_default() {
                    items.push(Item::Mono(grouped_address(&address)));
                }
                if matches!(chosen, Choice::Btc(_)) {
                    items.push(Item::Help(
                        t::NETWORK_LINE.fill(lang, [btc.display_name_in(lang)]),
                    ));
                } else if *chosen == Choice::Zec {
                    items.push(Item::Help(t::NETWORK_LINE.fill(lang, [zec.display_name()])));
                }
            }
            if matches!(slot, CardSlot::OpenPgp(_)) {
                items.push(Item::Help(t::FORMAT_HELP.get(lang).to_owned()));
            }
            items.push(Item::CardEnd);
        }
        if let Some(error) = &form.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::CONNECT_NEXT, t::BTN_NEXT.get(lang))
                .enabled(!form.busy && !scan.keys.is_empty() && form.error.is_none()),
            Ctl::button(ids::CONNECT_RESCAN, t::BTN_READ_AGAIN.get(lang)).enabled(!form.busy),
            Ctl::button(ids::WIZARD_CANCEL, t::BTN_CANCEL.get(lang)),
        ]));
    }

    fn yk_connect_confirm_items(&self, form: &ConnectForm, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let Some(record) = form.record.as_ref() else {
            return;
        };
        items.push(Item::Banner(
            ct::YK_UNKNOWN_PATH.get(lang).to_owned(),
            Tone::Warn,
        ));
        items.push(Item::CardStart(Some(
            t::CHECK_BEFORE_SAVE.fill(lang, [&record.serial.to_string()]),
        )));
        items.push(Item::Text(t::CONNECT_CONFIRM_TEXT.get(lang).to_owned()));
        for slot in &record.slots {
            slot_items(
                lang,
                (slot.slot, slot.role),
                slot.touch,
                slot.pin,
                &address_texts(slot.role, &slot.public).unwrap_or_default(),
                items,
            );
            let holders: Vec<String> = crate::yubikey::holders(&self.card.records, slot.role)
                .iter()
                .map(|serial| format!("#{serial}"))
                .collect();
            if !holders.is_empty() {
                items.push(Item::Field(
                    t::FIELD_RELATION.get(lang).to_owned(),
                    t::SAME_KEY_HOLDERS.fill(lang, [&holders.join(", ")]),
                ));
            }
        }
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(t::PIN_OWNERSHIP.get(lang).to_owned())));
        items.push(Item::Text(
            crate::ui::secret_text::CARD_USER_PIN
                .get(self.settings.language)
                .to_owned(),
        ));
        if let Some((ok, text)) = &form.pin_note {
            items.push(Item::Banner(
                text.clone(),
                if *ok { Tone::Success } else { Tone::Danger },
            ));
        }
        items.push(Item::Row(vec![
            Ctl::button(ids::CONNECT_PIN, t::PIN_OWNERSHIP.get(lang)).enabled(!form.busy),
        ]));
        items.push(Item::CardEnd);
        if form.scan.as_ref().is_some_and(|scan| scan.defaults.piv_pin) {
            items.push(Item::Banner(
                t::PIV_FACTORY.get(lang).to_owned(),
                Tone::Warn,
            ));
        }
        items.push(Item::Help(t::SIGN_HELP.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::primary(ids::CONNECT_SAVE, t::BTN_SAVE.get(lang)).enabled(!form.busy),
            Ctl::button(ids::CONNECT_BACK, t::BTN_CHOOSE_AGAIN.get(lang)),
            Ctl::button(ids::WIZARD_CANCEL, t::BTN_CANCEL.get(lang)),
        ]));
    }
}
