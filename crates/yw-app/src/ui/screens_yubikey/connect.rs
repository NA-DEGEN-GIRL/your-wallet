//! The screens of "`YubiKey` 연결하기 (복구 단어 없이)" (spec/10 §7.6, spec/04 §2.19): the scan with
//! one choice per found key, the confirmation with every address in full and the unknown-path
//! note (plus the optional PIN check), then the wizard's result screen.

use yw_core::yubikey::connect::KeyUse;
use yw_core::yubikey::plan::{CardSlot, address_texts};

use super::{grouped_address, ids, slot_items};
use crate::app::App;
use crate::app_yubikey::connect::{Choice, ConnectForm, T_YK_CONNECT, T_YK_UNKNOWN_PATH};
use crate::app_yubikey::{WizardOrigin, WizardStep, YkWizard};
use crate::ui::main_window::{Ctl, Item, Tone};

/// The connect flow's step labels.
pub const CONNECT_STEPS: [&str; 3] = ["YubiKey 읽기·키 고르기", "주소 확인", "결과"];

impl App {
    /// S21 in the connect flow.
    pub(super) fn yk_connect_screen(
        &self,
        wizard: &YkWizard,
        form: &ConnectForm,
        items: &mut Vec<Item>,
    ) {
        items.push(Item::Title(match wizard.origin {
            WizardOrigin::NewWallet => "YubiKey 지갑 만들기 — YubiKey 연결하기".to_owned(),
            WizardOrigin::Vault => "YubiKey 연결하기 (복구 단어 없이)".to_owned(),
        }));
        let current = match wizard.step {
            WizardStep::Plan => 1,
            WizardStep::Confirm | WizardStep::Credentials => 2,
            WizardStep::Running | WizardStep::Result => 3,
        };
        items.push(Item::Steps(
            CONNECT_STEPS
                .iter()
                .map(|label| (*label).to_owned())
                .collect(),
            current,
        ));
        match wizard.step {
            WizardStep::Plan => self.yk_connect_choose_items(form, items),
            WizardStep::Confirm | WizardStep::Credentials => {
                self.yk_connect_confirm_items(form, items);
            }
            WizardStep::Running => {
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle(
                    "YubiKey를 다시 읽고 저장하는 중입니다".to_owned(),
                ));
                items.push(Item::Text(
                    "YubiKey를 빼지 마세요. 카드에는 아무것도 쓰지 않습니다.".to_owned(),
                ));
                items.push(Item::CardEnd);
            }
            WizardStep::Result => {
                if wizard.failure.is_none() && wizard.enrolled.is_some() {
                    items.push(Item::Banner(T_YK_UNKNOWN_PATH.to_owned(), Tone::Warn));
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
        let (btc, zec) = self.yk_connect_networks();
        items.push(Item::CardStart(Some("연결한 YubiKey".to_owned())));
        items.push(Item::Text(T_YK_CONNECT.to_owned()));
        let Some(scan) = form.scan.as_ref() else {
            if let Some(error) = &form.scan_error {
                items.push(Item::Banner(error.clone(), Tone::Danger));
            } else {
                items.push(Item::Muted(
                    "연결한 YubiKey를 읽는 중… (PIN 없음, 쓰기 없음)".to_owned(),
                ));
            }
            items.push(Item::CardEnd);
            items.push(Item::Row(vec![
                Ctl::primary(ids::CONNECT_RESCAN, "다시 읽기").enabled(!form.busy),
                Ctl::button(ids::WIZARD_CANCEL, "취소"),
            ]));
            return;
        };
        items.push(Item::Field(
            "YubiKey".to_owned(),
            format!("#{} (펌웨어 {})", scan.serial, scan.firmware),
        ));
        let counters = crate::yubikey::PinCounters {
            serial: scan.serial,
            pw1: scan.pgp_pin_retries,
            pw3: None,
            piv_pin: scan.piv_pin_retries,
            puk: None,
        };
        for line in counters.lines(&[
            crate::yubikey::PinKind::OpenPgpUser,
            crate::yubikey::PinKind::PivPin,
        ]) {
            items.push(Item::Help(line));
        }
        for note in &scan.notes {
            items.push(Item::Help(note.clone()));
        }
        for (slot, reason) in &scan.unsupported {
            items.push(Item::Help(format!("{}: {reason}", slot.label())));
        }
        if scan.keys.is_empty() {
            items.push(Item::Banner(
                "PIN 없이 읽을 수 있는 키(OpenPGP SIG·AUT의 secp256k1, PIV의 Ed25519)가 없습니다. 키가 든 YubiKey인지 확인하세요."
                    .to_owned(),
                Tone::Warn,
            ));
        }
        items.push(Item::CardEnd);
        for (row, (slot, chosen)) in form.choices.iter().enumerate() {
            let Some(found) = scan.key(*slot) else {
                continue;
            };
            items.push(Item::CardStart(Some(slot.label())));
            items.push(Item::LabeledRow(
                "이 키는".to_owned(),
                Choice::offered(slot.curve())
                    .iter()
                    .enumerate()
                    .map(|(position, choice)| {
                        Ctl::radio(
                            ids::connect_choice_id(row, *choice),
                            &choice.label(),
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
                    items.push(Item::Help(format!("네트워크: {}", btc.display_name())));
                } else if *chosen == Choice::Zec {
                    items.push(Item::Help(format!("네트워크: {}", zec.display_name())));
                }
            }
            if matches!(slot, CardSlot::OpenPgp(_)) {
                items.push(Item::Help(
                    "같은 키라도 형식에 따라 주소가 다릅니다. 이전 지갑에서 쓰던 주소가 나오는 형식을 고르세요."
                        .to_owned(),
                ));
            }
            items.push(Item::CardEnd);
        }
        if let Some(error) = &form.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::primary(ids::CONNECT_NEXT, "다음")
                .enabled(!form.busy && !scan.keys.is_empty() && form.error.is_none()),
            Ctl::button(ids::CONNECT_RESCAN, "다시 읽기").enabled(!form.busy),
            Ctl::button(ids::WIZARD_CANCEL, "취소"),
        ]));
    }

    fn yk_connect_confirm_items(&self, form: &ConnectForm, items: &mut Vec<Item>) {
        let Some(record) = form.record.as_ref() else {
            return;
        };
        items.push(Item::Banner(T_YK_UNKNOWN_PATH.to_owned(), Tone::Warn));
        items.push(Item::CardStart(Some(format!(
            "저장하기 전에 확인하세요 — YubiKey #{}",
            record.serial
        ))));
        items.push(Item::Text(
            "아래 주소는 YubiKey에서 읽은 공개키로 이 PC가 계산한 값입니다. 쓰려는 주소와 전체가 같은지 확인하세요."
                .to_owned(),
        ));
        for slot in &record.slots {
            slot_items(
                slot.slot,
                slot.role,
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
                    "관계".to_owned(),
                    format!(
                        "같은 키를 가진 YubiKey: {} — 그 계정에 이 YubiKey를 더합니다",
                        holders.join(", ")
                    ),
                ));
            }
        }
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("PIN으로 소유 확인 (선택)".to_owned())));
        items.push(Item::Text(crate::ui::secret::T_CARD_USER_PIN.to_owned()));
        if let Some((ok, text)) = &form.pin_note {
            items.push(Item::Banner(
                text.clone(),
                if *ok { Tone::Success } else { Tone::Danger },
            ));
        }
        items.push(Item::Row(vec![
            Ctl::button(ids::CONNECT_PIN, "PIN으로 소유 확인 (선택)").enabled(!form.busy),
        ]));
        items.push(Item::CardEnd);
        if form.scan.as_ref().is_some_and(|scan| scan.defaults.piv_pin) {
            items.push(Item::Banner(
                "이 YubiKey의 PIV PIN이 공장 기본값(123456)입니다. 연결한 뒤 'PIN 설정'으로 바꾸기 전에는 이 지갑이 서명하지 않습니다."
                    .to_owned(),
                Tone::Warn,
            ));
        }
        items.push(Item::Help(
            "서명할 때는 지금처럼 YubiKey에 PIN을 입력하고 터치합니다(공장 기본 PIN으로는 서명하지 않음)."
                .to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::primary(ids::CONNECT_SAVE, "저장").enabled(!form.busy),
            Ctl::button(ids::CONNECT_BACK, "← 다시 고르기"),
            Ctl::button(ids::WIZARD_CANCEL, "취소"),
        ]));
    }
}
