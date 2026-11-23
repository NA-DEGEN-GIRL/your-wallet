//! `YubiKey` screens (spec/04 §2.19, spec/10 §7): the S01 card `YubiKey에 키 보관`, S20 (the new
//! `YubiKey` wallet), S21 the enrolment wizard (keys and slots, confirmation with every path and
//! address, credentials, result with "다시 확인" and the defaults change), settings → `YubiKey`
//! (the enrolled cards, their slots, which cards hold each account, `삭제`) and the removal
//! overlay. Fixed sentences are the T-YK-* rows of spec/04 §2.16.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): moved here from yw-app `ui/screens_yubikey.rs` with the
//! bodies unchanged (`impl App` builders became `impl Screen<'_>`, yw-app paths engine paths); its
//! control ids stay there (`ui::screens_yubikey::ids`).

use yw_core::btc::ScriptType;
use yw_core::lang::{Lang, Text};
use yw_core::yubikey::plan::{
    CardSlot, KeyRole, MAX_CARDS, PgpKey, PinPolicy, TouchPolicy, accounts, address_texts,
};
use yw_core::yubikey::record::HwKeyRecord;
use yw_core::zec::ZecNetwork;

use super::Screen;
use crate::cmd::{Row, YkConnectPress, YkManagePress, YkPress};
use crate::form::EditField;
use crate::screen::Tone;
use crate::screen::model::{Ctl, Item};
use crate::screen::rows;
use crate::wallet::AppMode;
use crate::wallet::app_yubikey::text as yk;
use crate::wallet::app_yubikey::{
    CARD_SCRIPTS, MAX_ACCOUNT_INDEX, PGP_TOUCH, PIV_TOUCH, PgpKind, WizardOrigin, WizardStep,
    YkWizard, pgp_press,
};
use text as t;

mod connect;
mod manage;
pub mod text;

/// The wizard's step labels (S21).
pub const WIZARD_STEPS: [Text; 4] = [
    t::STEP_PLAN,
    t::STEP_CONFIRM,
    t::STEP_CREDENTIALS,
    t::STEP_RESULT,
];
/// T-YK-PIN-GUIDE (spec/10 §9.3): what each card secret is for.
pub const T_YK_PIN_GUIDE: [Text; 5] = [
    t::PIN_GUIDE_PW1,
    t::PIN_GUIDE_PW3,
    t::PIN_GUIDE_PIV_PIN,
    t::PIN_GUIDE_PUK,
    t::PIN_GUIDE_MANAGEMENT,
];

/// A step indicator of `labels` in `lang` (`current` 1-based, 0 for none).
fn steps_item(lang: Lang, labels: &[Text], current: usize) -> Item {
    Item::Steps(
        labels
            .iter()
            .map(|label| label.get(lang).to_owned())
            .collect(),
        current,
    )
}

const fn touch_label(lang: Lang, touch: TouchPolicy) -> &'static str {
    match touch {
        TouchPolicy::Never => t::TOUCH_NEVER,
        TouchPolicy::Always => t::TOUCH_ALWAYS,
        TouchPolicy::Cached => t::TOUCH_CACHED,
        TouchPolicy::AlwaysFixed => t::TOUCH_ALWAYS_FIXED,
        TouchPolicy::CachedFixed => t::TOUCH_CACHED_FIXED,
    }
    .get(lang)
}

const fn kind_label(lang: Lang, kind: PgpKind) -> &'static str {
    match kind {
        PgpKind::None => t::KIND_NONE,
        PgpKind::Evm => t::KIND_EVM,
        PgpKind::Btc => t::KIND_BTC,
        PgpKind::Shared => t::KIND_SHARED,
        PgpKind::Zec => t::KIND_ZEC,
    }
    .get(lang)
}

/// "메인넷 (t1…)" / "테스트넷 (tm…)".
#[must_use]
pub const fn zec_network_label(lang: Lang, network: ZecNetwork) -> &'static str {
    match network {
        ZecNetwork::Mainnet => t::ZEC_MAINNET,
        ZecNetwork::Testnet => t::ZEC_TESTNET,
    }
    .get(lang)
}

fn script_label(lang: Lang, script: ScriptType) -> String {
    format!("{} ({})", script.name_in(lang), script.technical())
}

/// One slot's lines: label and title, path, address(es), policies.
/// A slot address in 4-character groups like every other screen (spec/04 §3.3): an EVM address
/// in its checksum groups, a Bitcoin or Solana address as encoded, every character shown.
fn grouped_address(address: &str) -> String {
    yw_core::evm::address::parse_address(address).map_or_else(
        |_| crate::text::grouped(address),
        |parsed| yw_core::evm::display::format_address(&parsed),
    )
}

fn slot_items(
    lang: Lang,
    (slot, role): (CardSlot, KeyRole),
    touch: TouchPolicy,
    pin: PinPolicy,
    addresses: &[String],
    items: &mut Vec<Item>,
) {
    items.push(Item::Subtitle(format!(
        "{} — {}",
        slot.label_in(lang),
        role.title_in(lang)
    )));
    items.push(Item::Field(
        t::FIELD_PATH.get(lang).to_owned(),
        role.path_text_in(lang),
    ));
    for address in addresses {
        items.push(Item::Mono(grouped_address(address)));
    }
    let touch = touch_label(lang, touch);
    let policy = match pin {
        PinPolicy::NotApplicable => t::POLICY_TOUCH.fill(lang, [touch]),
        PinPolicy::Once => t::POLICY_TOUCH_SESSION.fill(lang, [touch]),
        PinPolicy::Always => t::POLICY_TOUCH_EVERY.fill(lang, [touch]),
    };
    items.push(Item::Field(t::FIELD_POLICY.get(lang).to_owned(), policy));
}

impl Screen<'_> {
    /// S20: what the new `YubiKey` wallet is, before W01.
    pub fn yk_wallet_intro(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        items.push(Item::Title(t::TITLE_YK_WALLET.get(lang).to_owned()));
        items.push(steps_item(
            lang,
            &crate::wallet::app_yubikey::YK_WALLET_STEPS,
            0,
        ));
        items.push(Item::CardStart(Some(t::BEFORE_START.get(lang).to_owned())));
        for line in [
            t::INTRO_PAPER,
            t::INTRO_NOT_STORED,
            t::INTRO_CHECK,
            t::INTRO_BACKUP,
            t::INTRO_ADMIN_PIN,
            t::INTRO_TIME,
        ] {
            items.push(Item::Text(line.get(lang).to_owned()));
        }
        items.push(Item::Banner(t::INTRO_WARN.get(lang).to_owned(), Tone::Warn));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(YkPress::NewWalletStart, t::BTN_START.get(lang)),
            Ctl::button(YkPress::NewWalletCancel, t::BTN_CANCEL.get(lang)),
        ]));
    }

    /// Settings → `YubiKey`.
    #[expect(
        clippy::too_many_lines,
        reason = "one card per enrolled YubiKey / slot form"
    )]
    pub fn yk_settings_section(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let unlocked = matches!(self.mode, AppMode::Unlocked { .. });
        if unlocked && let Some(manage) = self.card.manage.as_ref() {
            self.yk_manage_items(manage, items);
            return;
        }
        let records = &self.card.records;
        items.push(Item::CardStart(Some(
            t::CARD_YK_ACCOUNTS.get(lang).to_owned(),
        )));
        items.push(Item::Text(t::YK_LIST.get(lang).to_owned()));
        if self.keys.has_mnemonic {
            items.push(Item::Help(t::YK_MNEMONIC_WALLET.get(lang).to_owned()));
        }
        items.push(Item::Row(vec![
            Ctl::primary(YkPress::EnrolStart, t::BTN_ENROL.get(lang))
                .enabled(unlocked && records.len() < MAX_CARDS),
            Ctl::button(YkConnectPress::Start, t::BTN_CONNECT.get(lang))
                .enabled(unlocked && records.len() < MAX_CARDS),
        ]));
        items.push(Item::Help(
            crate::wallet::app_yubikey::connect::text::YK_CONNECT
                .get(lang)
                .to_owned(),
        ));
        if !unlocked {
            items.push(Item::Help(t::UNLOCK_TO_USE.get(lang).to_owned()));
        }
        items.push(Item::CardEnd);
        let defaults = self
            .meta
            .as_ref()
            .map(|meta| meta.hw_accounts.defaults.clone())
            .unwrap_or_default();
        for (row, record) in records.iter().enumerate() {
            // `YubiKey 메인 (#12345678)` once named (2026-11-15), `YubiKey #12345678` before.
            items.push(Item::CardStart(Some(format!(
                "YubiKey {}",
                self.card_name(record.serial)
            ))));
            // A card on its factory PINs does not sign: said first, and `PIN 설정` is the card's
            // main button (2026-11-10).
            let factory = defaults.contains(&record.serial);
            if factory {
                items.push(Item::Banner(
                    t::FACTORY_BAND.get(lang).to_owned(),
                    Tone::Warn,
                ));
            }
            items.push(Item::Field(
                t::FIELD_FIRMWARE.get(lang).to_owned(),
                record.firmware.to_string(),
            ));
            items.push(Item::Field(
                t::FIELD_SLOTS.get(lang).to_owned(),
                t::COUNT.fill(lang, [&record.slots.len().to_string()]),
            ));
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
            let card_row = Row(u16::try_from(row).unwrap_or(u16::MAX));
            let open = self.card.pin_serial == Some(record.serial);
            let pins_label = match (open, factory) {
                (true, _) => t::BTN_PINS_CLOSE,
                (false, true) => t::BTN_SET_PIN,
                (false, false) => t::BTN_PINS_CHANGE,
            }
            .get(lang);
            // Everyday actions first; the two destructive ones on their own row, named by what
            // they erase (2026-11-08: `삭제` / `YubiKey 비우기` did not say which one touches
            // the card).
            items.push(Item::Row(vec![
                if factory && !open {
                    Ctl::primary(YkPress::Pins(card_row), pins_label)
                } else {
                    Ctl::button(YkPress::Pins(card_row), pins_label)
                }
                .enabled(unlocked),
                Ctl::button(YkManagePress::Reslot(card_row), t::BTN_RESLOT.get(lang))
                    .enabled(unlocked),
                Ctl::button(YkPress::RenameCard(card_row), t::BTN_RENAME_CARD.get(lang))
                    .enabled(unlocked),
            ]));
            if unlocked && self.card.rename == Some(record.serial) {
                self.yk_card_name_items(record.serial, items);
            }
            items.push(Item::Help(t::DANGER.get(lang).to_owned()));
            let removable = self.yk_can_remove();
            items.push(Item::Row(vec![
                Ctl::danger(YkPress::Remove(card_row), t::BTN_REMOVE_RECORD.get(lang))
                    .enabled(unlocked && removable),
                Ctl::danger(YkManagePress::Clear(card_row), t::BTN_ERASE_KEYS.get(lang))
                    .enabled(unlocked),
            ]));
            if unlocked && !removable {
                items.push(Item::Help(t::LAST_KEY.get(lang).to_owned()));
            }
            items.push(Item::CardEnd);
            if open && unlocked {
                self.yk_pin_items(record.serial, items);
            }
        }
        if !records.is_empty() {
            items.push(Item::CardStart(Some(
                t::CARD_PER_ACCOUNT.get(lang).to_owned(),
            )));
            for account in accounts(records) {
                let holders: Vec<String> = account
                    .holders
                    .iter()
                    .enumerate()
                    .map(|(position, holder)| {
                        let name = match holder.slot {
                            CardSlot::OpenPgp(PgpKey::Sig) => "SIG".to_owned(),
                            CardSlot::OpenPgp(PgpKey::Aut) => "AUT".to_owned(),
                            CardSlot::Piv(slot) => format!("PIV {:02x}", slot.id()),
                        };
                        let card = self.card_name(holder.serial);
                        if position == 0 {
                            format!("{card} {name}")
                        } else {
                            t::HOLDER_BACKUP.fill(lang, [&card, &name])
                        }
                    })
                    .collect();
                items.push(Item::Text(format!(
                    "{} ({}) — {}",
                    account.role.title_in(lang),
                    account.role.path_text_in(lang),
                    holders.join(", ")
                )));
            }
            items.push(Item::CardEnd);
        }
    }

    /// The name edit of card `serial` (2026-11-15, spec/10 §8): a plain label field like the
    /// account `이름 바꾸기` (a name is not a secret), `저장`, `이름 지우기` when named, `취소`.
    fn yk_card_name_items(&self, serial: u32, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let current = self
            .meta
            .as_ref()
            .and_then(|meta| meta.card_name(serial))
            .unwrap_or("");
        items.push(Item::Help(t::CARD_NAME_HELP.get(lang).to_owned()));
        let mut row = vec![
            Ctl::edit(EditField::YkCardName, current, 260, false, 64),
            Ctl::primary(YkPress::CardNameSave, t::BTN_SAVE.get(lang)),
        ];
        if !current.is_empty() {
            row.push(Ctl::button(
                YkPress::CardNameClear,
                t::BTN_CLEAR_CARD_NAME.get(lang),
            ));
        }
        row.push(Ctl::button(
            YkPress::CardNameCancel,
            t::BTN_CANCEL.get(lang),
        ));
        items.push(Item::Row(row));
    }

    /// S21: the wizard at its step.
    pub fn yk_wizard_screen(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let Some(wizard) = self.card.wizard.as_ref() else {
            items.push(Item::Muted(t::WIZARD_DONE.get(lang).to_owned()));
            items.push(crate::screen::build::core::back_main(lang));
            return;
        };
        if let Some(form) = wizard.connect.as_deref() {
            self.yk_connect_screen(wizard, form, items);
            return;
        }
        if wizard.origin == WizardOrigin::NewWallet && !wizard.created {
            // Steps 1–3 were the secret windows (2026-11-10).
            items.push(Item::Help(t::STEP_4_OF_5.get(lang).to_owned()));
        }
        items.push(Item::Title(
            match wizard.origin {
                WizardOrigin::NewWallet => t::TITLE_NEW_WALLET_ENROL,
                WizardOrigin::Vault => t::BTN_ENROL,
            }
            .get(lang)
            .to_owned(),
        ));
        let current = match wizard.step {
            WizardStep::Plan => 1,
            WizardStep::Confirm => 2,
            WizardStep::Credentials | WizardStep::Running => 3,
            WizardStep::Result => 4,
        };
        items.push(steps_item(lang, &WIZARD_STEPS, current));
        match wizard.step {
            WizardStep::Plan => self.yk_plan_items(wizard, items),
            WizardStep::Confirm => self.yk_confirm_items(wizard, items),
            WizardStep::Credentials => self.yk_credentials_items(wizard, items),
            WizardStep::Running => {
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle(t::RUNNING_IMPORT.get(lang).to_owned()));
                items.push(Item::Text(t::RUNNING_KEEP.get(lang).to_owned()));
                items.push(Item::CardEnd);
            }
            WizardStep::Result => self.yk_result_items(wizard, items),
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "one card per enrolled YubiKey / slot form"
    )]
    fn yk_pgp_items(&self, wizard: &YkWizard, key: PgpKey, items: &mut Vec<Item>) {
        use crate::wallet::app_yubikey::PgpAction;
        let lang = self.settings.language;
        let form = wizard.pgp(key);
        items.push(Item::CardStart(Some(CardSlot::OpenPgp(key).label_in(lang))));
        items.push(Item::LabeledRow(
            t::LABEL_KEY.get(lang).to_owned(),
            [
                PgpKind::None,
                PgpKind::Evm,
                PgpKind::Btc,
                PgpKind::Zec,
                PgpKind::Shared,
            ]
            .into_iter()
            .enumerate()
            .map(|(position, kind)| {
                Ctl::radio(
                    pgp_press(key, PgpAction::Kind(kind)),
                    kind_label(lang, kind),
                    form.kind == kind,
                    position == 0,
                )
            })
            .collect(),
        ));
        if form.kind == PgpKind::None {
            items.push(Item::CardEnd);
            return;
        }
        let edit = match key {
            PgpKey::Sig => EditField::YkSigIndex,
            PgpKey::Aut => EditField::YkAutIndex,
        };
        let max = MAX_ACCOUNT_INDEX.to_string();
        items.push(Item::LabeledRow(
            if matches!(form.kind, PgpKind::Btc | PgpKind::Zec) {
                t::LABEL_ADDRESS_INDEX.fill(lang, [&max])
            } else {
                t::LABEL_ACCOUNT_INDEX.fill(lang, [&max])
            },
            vec![Ctl::edit(edit, &form.index_text, 80, false, 3)],
        ));
        if matches!(form.kind, PgpKind::Btc | PgpKind::Shared) {
            items.push(Item::LabeledRow(
                t::LABEL_ADDRESS_TYPE.fill(lang, [self.yk_network().display_name_in(lang)]),
                CARD_SCRIPTS
                    .into_iter()
                    .enumerate()
                    .map(|(position, script)| {
                        Ctl::radio(
                            pgp_press(key, PgpAction::Script(script)),
                            &script_label(lang, script),
                            form.script == script,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
        }
        if form.kind == PgpKind::Zec {
            items.push(Item::LabeledRow(
                t::LABEL_ZEC_NETWORK.get(lang).to_owned(),
                [ZecNetwork::Mainnet, ZecNetwork::Testnet]
                    .into_iter()
                    .enumerate()
                    .map(|(position, network)| {
                        Ctl::radio(
                            pgp_press(key, PgpAction::Zec(network)),
                            zec_network_label(lang, network),
                            form.zec == network,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
        }
        items.push(Item::LabeledRow(
            t::LABEL_TOUCH.get(lang).to_owned(),
            PGP_TOUCH
                .into_iter()
                .enumerate()
                .map(|(position, touch)| {
                    Ctl::radio(
                        pgp_press(key, PgpAction::Touch(touch)),
                        touch_label(lang, touch),
                        form.touch == touch,
                        position == 0,
                    )
                })
                .collect(),
        ));
        if let Ok(Some(slot)) = YkWizard::pgp_preview(lang, form, key, self.yk_network()) {
            items.push(Item::Help(
                t::PATH_LINE.fill(lang, [&slot.role.path_text_in(lang)]),
            ));
            if let KeyRole::Btc { index, .. } = slot.role
                && index >= 20
            {
                items.push(Item::Help(t::GAP_LIMIT.get(lang).to_owned()));
            }
        }
        items.push(Item::Help(t::FIXED_TOUCH.get(lang).to_owned()));
        if form.kind == PgpKind::Shared {
            items.push(Item::Banner(yk::YK_SHARED.get(lang).to_owned(), Tone::Warn));
        }
        items.push(Item::CardEnd);
    }

    /// The "백업 복사본" card of the plan screen (the enrolled cards to copy).
    fn yk_backup_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let records = &self.card.records;
        if !records.is_empty() {
            items.push(Item::CardStart(Some(t::BACKUP_COPY.get(lang).to_owned())));
            items.push(Item::Row(vec![Ctl::check(
                YkPress::BackupToggle,
                t::CHECK_BACKUP.get(lang),
                wizard.backup_of.is_some(),
            )]));
            items.push(Item::Help(t::BACKUP_HELP.get(lang).to_owned()));
            if let Some(serial) = wizard.backup_of {
                // Only cards with a known path can be copied from words (spec/10 §7.6); the
                // radio keeps the record's row as its id.
                items.push(Item::LabeledRow(
                    t::LABEL_COPY_FROM.get(lang).to_owned(),
                    records
                        .iter()
                        .enumerate()
                        .filter(|(_, record)| record.has_known_path())
                        .enumerate()
                        .map(|(position, (row, record))| {
                            Ctl::radio(
                                YkPress::Backup(Row(u16::try_from(row).unwrap_or(u16::MAX))),
                                &t::BACKUP_OPTION.fill(
                                    lang,
                                    [
                                        &self.card_name(record.serial),
                                        &record.slots.len().to_string(),
                                    ],
                                ),
                                record.serial == serial,
                                position == 0,
                            )
                        })
                        .collect(),
                ));
                if records.iter().any(|record| !record.has_known_path()) {
                    items.push(Item::Help(yk::YK_BACKUP_UNKNOWN.get(lang).to_owned()));
                }
                if let Some(record) = records.iter().find(|record| record.serial == serial) {
                    for slot in record.slots.iter().filter(|slot| slot.path_known) {
                        items.push(Item::Text(format!(
                            "{} — {} ({})",
                            slot.slot.label_in(lang),
                            slot.role.title_in(lang),
                            slot.role.path_text_in(lang)
                        )));
                    }
                    let skipped: Vec<String> = record
                        .slots
                        .iter()
                        .filter(|slot| !slot.path_known)
                        .map(|slot| {
                            format!(
                                "{} — {}",
                                slot.slot.label_in(lang),
                                slot.role.title_in(lang)
                            )
                        })
                        .collect();
                    if !skipped.is_empty() {
                        items.push(Item::Help(
                            t::SKIPPED_UNKNOWN.fill(lang, [&skipped.join(", ")]),
                        ));
                    }
                }
                items.push(Item::Help(t::BACKUP_SAME.get(lang).to_owned()));
            }
            items.push(Item::CardEnd);
        }
    }

    fn yk_plan_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        if wizard.origin == WizardOrigin::NewWallet {
            items.push(Item::Banner(
                t::WORDS_CHECKED.get(lang).to_owned(),
                Tone::Success,
            ));
        }
        if self.card.records.is_empty() {
            // The defaults of a first card (`YkWizard::new`, spec/10 §3.1), 2026-11-10.
            items.push(Item::Text(
                t::FIRST_DEFAULTS.fill(lang, [self.yk_network().display_name_in(lang)]),
            ));
        }
        self.yk_backup_items(wizard, items);
        if wizard.backup_of.is_none() {
            self.yk_pgp_items(wizard, PgpKey::Sig, items);
            self.yk_pgp_items(wizard, PgpKey::Aut, items);
            if wizard.uses_shared() {
                items.push(Item::Row(vec![Ctl::check(
                    YkPress::SharedAck,
                    t::SHARED_ACK.get(lang),
                    wizard.shared_ack,
                )]));
            }
            items.push(Item::CardStart(Some(t::CARD_PIV_SOL.get(lang).to_owned())));
            items.push(Item::LabeledRow(
                t::LABEL_SOL_COUNT.get(lang).to_owned(),
                vec![Ctl::edit(
                    EditField::YkSolCount,
                    &wizard.sol_count_text,
                    80,
                    false,
                    2,
                )],
            ));
            items.push(Item::LabeledRow(
                t::LABEL_FIRST_INDEX.get(lang).to_owned(),
                vec![Ctl::edit(
                    EditField::YkSolStart,
                    &wizard.sol_start_text,
                    80,
                    false,
                    3,
                )],
            ));
            items.push(Item::LabeledRow(
                t::LABEL_TOUCH.get(lang).to_owned(),
                PIV_TOUCH
                    .into_iter()
                    .enumerate()
                    .map(|(position, touch)| {
                        Ctl::radio(
                            if position == 0 {
                                YkPress::PivTouchAlways
                            } else {
                                YkPress::PivTouchCached
                            },
                            touch_label(lang, touch),
                            wizard.piv_touch == touch,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
            items.push(Item::Help(t::PIV_HELP.get(lang).to_owned()));
            items.push(Item::Help(yk::YK_PIV_FIRMWARE.get(lang).to_owned()));
            items.push(Item::CardEnd);
        }
        if let Some(error) = &wizard.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::primary(
                YkPress::PlanNext,
                if wizard.seed_held {
                    t::BTN_NEXT_CONFIRM
                } else {
                    t::BTN_NEXT_WORDS
                }
                .get(lang),
            ),
            Ctl::button(YkPress::WizardCancel, t::BTN_CANCEL.get(lang)),
        ]));
    }

    fn yk_confirm_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let Some(preview) = wizard.preview.as_ref() else {
            items.push(Item::CardStart(None));
            items.push(Item::Subtitle(t::CHECKING.get(lang).to_owned()));
            items.push(Item::Text(t::COMPUTING.get(lang).to_owned()));
            items.push(Item::CardEnd);
            items.push(Item::Row(vec![
                Ctl::button(YkPress::ConfirmBack, t::BTN_BACK_SLOTS.get(lang)),
                Ctl::button(YkPress::WizardCancel, t::BTN_CANCEL.get(lang)),
            ]));
            return;
        };
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
                YkPress::SameAck,
                t::SAME_ACK.get(lang),
                wizard.same_ack,
            )]));
        }
        if let Err(error) = preview.plan {
            items.push(Item::Banner(error.text_in(lang), Tone::Danger));
        }
        items.push(Item::CardStart(Some(
            t::CARD_CHECK_IMPORT.get(lang).to_owned(),
        )));
        items.push(Item::Text(t::CONFIRM_TEXT.get(lang).to_owned()));
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
            let holders = crate::yubikey::holders(&self.card.records, planned.role);
            let relation = if holders.is_empty() {
                t::RELATION_NEW.get(lang).to_owned()
            } else {
                let kind = if planned.backup_copy {
                    t::BACKUP_COPY
                } else {
                    t::RELATION_ALREADY
                };
                t::RELATION.fill(lang, [kind.get(lang), &self.card_name_list(&holders, ", ")])
            };
            items.push(Item::Field(
                t::FIELD_RELATION.get(lang).to_owned(),
                relation,
            ));
        }
        self.yk_card_items(wizard, items);
        items.push(Item::CardEnd);
        if wizard.applets().1 {
            items.push(Item::Help(yk::YK_PIV_FIRMWARE.get(lang).to_owned()));
        }
        items.push(Item::Help(yk::YK_OVERWRITE.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::primary(YkPress::ConfirmNext, t::BTN_NEXT.get(lang))
                .enabled(wizard.can_continue()),
            Ctl::button(YkPress::ConfirmBack, t::BTN_BACK_SLOTS.get(lang)),
            Ctl::button(YkPress::WizardCancel, t::BTN_CANCEL.get(lang)),
        ]));
    }

    /// The card the wizard enrols (spec/10 §7.3: one card only, identified read-only).
    fn yk_card_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let line = match (&wizard.card, &wizard.card_error) {
            (Some(card), _) => t::CARD_LINE.fill(
                lang,
                [&self.card_name(card.serial), &card.firmware.to_string()],
            ),
            (None, Some(error)) => error.clone(),
            (None, None) => t::READING_CARD.get(lang).to_owned(),
        };
        items.push(Item::Field(t::CONNECTED_CARD.get(lang).to_owned(), line));
        if wizard.card.is_none() && wizard.card_error.is_some() {
            items.push(Item::Row(vec![Ctl::button(
                YkPress::IdentifyAgain,
                t::BTN_READ_AGAIN.get(lang),
            )]));
        }
    }

    /// The keys of the identified card's planned slots an import would destroy (spec/10 §7.4):
    /// each slot with its key's addresses (a secp256k1 key as an EVM and a Bitcoin P2WPKH
    /// address, an Ed25519 key as a Solana address), T-YK-OCCUPIED, its checkbox and the typed
    /// `영구 삭제`.
    fn yk_occupied_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        use yw_core::yubikey::record::HwPublicKey;
        let lang = self.settings.language;
        match &wizard.occupied {
            None if wizard.card.is_some() => {
                items.push(Item::Help(t::READING_SLOTS.get(lang).to_owned()));
            }
            Some(Err(error)) => {
                items.push(Item::Help(t::SLOTS_UNREADABLE.fill(lang, [error])));
            }
            Some(Ok(occupants)) if !occupants.is_empty() => {
                items.push(Item::Banner(
                    yk::YK_OCCUPIED.get(lang).to_owned(),
                    Tone::HighRisk,
                ));
                let shared = KeyRole::Evm {
                    index: yw_core::bip32::path::AccountIndex::ZERO,
                    btc: Some(yw_core::yubikey::plan::BtcUse {
                        network: self.yk_network(),
                        script: ScriptType::P2wpkh,
                    }),
                };
                for occupant in occupants {
                    let (kind, addresses) = match occupant.public {
                        Some(public @ HwPublicKey::Secp256k1(_)) => (
                            t::OCCUPANT_SECP.get(lang),
                            address_texts(shared, &public).unwrap_or_default(),
                        ),
                        Some(public @ HwPublicKey::Ed25519(_)) => (
                            t::OCCUPANT_ED.get(lang),
                            address_texts(
                                KeyRole::Sol {
                                    index: yw_core::bip32::path::AccountIndex::ZERO,
                                },
                                &public,
                            )
                            .unwrap_or_default(),
                        ),
                        None => (t::OCCUPANT_UNKNOWN.get(lang), Vec::new()),
                    };
                    items.push(Item::Subtitle(format!(
                        "{} — {kind}",
                        occupant.slot.label_in(lang)
                    )));
                    for address in addresses {
                        items.push(Item::Mono(grouped_address(&address)));
                    }
                }
                items.push(Item::Row(vec![Ctl::check(
                    YkPress::OverwriteAck,
                    yk::YK_OCCUPIED_ACK.get(lang),
                    wizard.overwrite_ack,
                )]));
                items.push(Item::LabeledRow(
                    t::TYPE_WORD.fill(
                        lang,
                        [crate::wallet::app_yubikey::manage::text::LOSS_WORD.get(lang)],
                    ),
                    vec![Ctl::edit(
                        EditField::YkOverwrite,
                        &wizard.overwrite_typed,
                        120,
                        false,
                        8,
                    )],
                ));
            }
            _ => {}
        }
    }

    fn yk_credentials_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let (pgp, piv) = wizard.applets();
        items.push(Item::CardStart(Some(
            t::CARD_CREDENTIALS.get(lang).to_owned(),
        )));
        items.push(Item::Text(t::CREDENTIALS_TEXT.get(lang).to_owned()));
        self.yk_card_items(wizard, items);
        if pgp {
            items.push(Item::Field(
                "OpenPGP".to_owned(),
                t::CREDENTIALS_PW3.get(lang).to_owned(),
            ));
        }
        if let Some(card) = wizard.card {
            let mut kinds = Vec::new();
            if pgp {
                kinds.push(crate::yubikey::PinKind::OpenPgpAdmin);
            }
            if piv && wizard.management_protected() {
                kinds.push(crate::yubikey::PinKind::PivPin);
            }
            for line in card.counters.lines(lang, &kinds) {
                items.push(Item::Help(line));
            }
        }
        if piv && wizard.management_protected() {
            items.push(Item::Field(
                t::FIELD_PIV_MANAGEMENT.get(lang).to_owned(),
                t::MANAGEMENT_PROTECTED.get(lang).to_owned(),
            ));
        } else if piv {
            items.push(Item::LabeledRow(
                t::FIELD_PIV_MANAGEMENT.get(lang).to_owned(),
                vec![
                    Ctl::radio(
                        YkPress::MgmtDefault,
                        t::MANAGEMENT_DEFAULT.get(lang),
                        wizard.default_management,
                        true,
                    ),
                    Ctl::radio(
                        YkPress::MgmtCustom,
                        t::MANAGEMENT_CUSTOM.get(lang),
                        !wizard.default_management,
                        false,
                    ),
                ],
            ));
            if wizard.management.is_none() {
                items.push(Item::Help(t::MANAGEMENT_UNREAD.get(lang).to_owned()));
            }
        }
        items.push(Item::CardEnd);
        let ready = wizard.can_continue() && wizard.card.is_some();
        items.push(Item::CardStart(Some(t::CARD_HOW.get(lang).to_owned())));
        self.yk_occupied_items(wizard, items);
        if let Some(error) = &wizard.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::primary(YkPress::Import, t::BTN_IMPORT.get(lang))
                .enabled(ready && wizard.can_import()),
        ]));
        items.push(Item::Help(t::YK_IMPORT.get(lang).to_owned()));
        items.push(Item::Row(vec![
            Ctl::button(YkPress::Adopt, t::BTN_ADOPT.get(lang)).enabled(ready),
        ]));
        items.push(Item::Help(t::YK_ADOPT.get(lang).to_owned()));
        items.push(Item::Banner(
            yk::YK_OVERWRITE.get(lang).to_owned(),
            Tone::Warn,
        ));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::button(YkPress::CredBack, t::BTN_BACK.get(lang)),
            Ctl::button(YkPress::WizardCancel, t::BTN_CANCEL.get(lang)),
        ]));
    }

    fn yk_result_items(&self, wizard: &YkWizard, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        if let Some(failure) = &wizard.failure {
            items.push(Item::Banner(failure.clone(), Tone::Danger));
            items.push(Item::Row(vec![
                Ctl::primary(YkPress::Retry, t::BTN_RETRY.get(lang)),
                Ctl::button(YkPress::ConfirmBack, t::BTN_BACK_SLOTS.get(lang)),
                Ctl::button(YkPress::WizardCancel, t::BTN_CANCEL.get(lang)),
            ]));
            return;
        }
        let Some(enrolled) = wizard.enrolled.as_ref() else {
            return;
        };
        let record: &HwKeyRecord = &enrolled.record;
        let done = if wizard.adopt {
            t::ADOPTED
        } else {
            t::IMPORTED
        };
        items.push(Item::Banner(
            done.fill(
                lang,
                [
                    &self.card_name(record.serial),
                    &record.slots.len().to_string(),
                ],
            ),
            Tone::Success,
        ));
        if wizard.created && wizard.connect.is_some() {
            items.push(Item::Banner(
                t::CREATED_CONNECTED.get(lang).to_owned(),
                Tone::Info,
            ));
        } else if wizard.created {
            items.push(Item::Banner(t::CREATED.get(lang).to_owned(), Tone::Info));
        }
        // "가져오기" and "가져오기 없이 등록" both end here (spec/10 §9.3): the PIN card right
        // under the completion band (2026-11-10), the slots already checked in 2/4 folded.
        self.yk_pin_items(record.serial, items);
        for note in &wizard.notes {
            items.push(Item::Banner(note.clone(), Tone::Info));
        }
        let open = self.card.result_details_open;
        items.push(Item::Row(vec![Ctl::link(
            YkPress::ResultDetails,
            if open {
                t::DETAILS_OPEN
            } else {
                t::DETAILS_CLOSED
            }
            .get(lang),
        )]));
        if open {
            items.push(Item::CardStart(Some(format!(
                "YubiKey {}",
                self.card_name(record.serial)
            ))));
            items.push(Item::Field(
                t::FIELD_FIRMWARE.get(lang).to_owned(),
                record.firmware.to_string(),
            ));
            items.push(Item::Help(t::REREAD.get(lang).to_owned()));
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
            items.push(Item::Row(vec![Ctl::button(
                YkPress::Recheck,
                t::BTN_RECHECK.get(lang),
            )]));
            if let Some(lines) = &wizard.check {
                for line in lines {
                    items.push(Item::Text(line.clone()));
                }
            }
            items.push(Item::CardEnd);
        }
        // spec/10 §9.3: a new YubiKey wallet ends with its PIN setup (it cannot be skipped; the
        // PIN card's first line says why `완료` is off).
        let pins_first = wizard.created && wizard.connect.is_none() && !wizard.pins_done();
        items.push(Item::Row(vec![
            Ctl::primary(YkPress::Finish, t::BTN_FINISH.get(lang)).enabled(!pins_first),
            Ctl::button(
                YkPress::Another,
                if wizard.connect.is_some() {
                    t::BTN_ANOTHER_CONNECT
                } else {
                    t::BTN_ANOTHER_ENROL
                }
                .get(lang),
            )
            .enabled(self.card.records.len() < MAX_CARDS && !pins_first),
        ]));
    }

    /// The main-window note after a card signing refused for factory PINs (spec/10 §9.3), with
    /// `PIN 설정` (the card's "PIN 설정" card in the `YubiKey` list).
    pub fn yk_pin_needed_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        if let Some(serial) = self.card.pin_needed {
            items.push(Item::Banner(
                format!(
                    "{} (YubiKey {})",
                    t::YK_PIN_NEEDED.get(lang),
                    self.card_name(serial)
                ),
                Tone::Warn,
            ));
            items.push(Item::Row(vec![Ctl::primary(
                YkPress::PinNeededOpen,
                t::BTN_SET_PIN.get(lang),
            )]));
        }
    }

    /// "기본값 변경 / PIN 설정" of card `serial` (spec/10 §9.3): the defaults still seen, the
    /// PIN guide, and the two modes — "8자리 하나로 통일" (default: one W12 window sets the four
    /// PINs and protects the management key) or one secret at a time.
    #[expect(
        clippy::too_many_lines,
        reason = "the PIN card's first line, defaults, modes and guide in order"
    )]
    pub fn yk_pin_items(&self, serial: u32, items: &mut Vec<Item>) {
        use crate::yubikey::PinTarget;
        let lang = self.settings.language;
        let seen = self.yk_pin_defaults(serial);
        // The mode follows the factory values seen this run until the user picks one
        // (2026-11-10): all three factory → 통일, some → 하나씩 따로, unknown → 통일.
        let factory = [seen.openpgp_admin, seen.piv_pin, seen.piv_management];
        let separate = if self.card.pins_chosen {
            self.card.pins_separate
        } else {
            factory.iter().any(|seen| *seen) && !factory.iter().all(|seen| *seen)
        };
        items.push(Item::CardStart(Some(
            t::PIN_CARD_TITLE.fill(lang, [&self.card_name(serial)]),
        )));
        // The first line: why `완료` waits (a new YubiKey wallet), or that the card does not
        // sign yet (2026-11-10).
        let new_wallet = self.card.wizard.as_ref().is_some_and(|wizard| {
            wizard.created
                && wizard.connect.is_none()
                && wizard
                    .enrolled
                    .as_ref()
                    .is_some_and(|enrolled| enrolled.record.serial == serial)
        });
        if new_wallet && self.yk_pins_first() {
            items.push(Item::Banner(
                t::YK_PINS_FIRST.get(lang).to_owned(),
                Tone::Warn,
            ));
        } else if self.yk_card_on_defaults(serial) {
            items.push(Item::Banner(
                t::NO_SIGN_BEFORE_PIN.get(lang).to_owned(),
                Tone::Warn,
            ));
        }
        if new_wallet {
            items.push(Item::Help(t::STEP_5_OF_5.get(lang).to_owned()));
        }
        // One line of the factory values seen (only those).
        let mut names = Vec::new();
        if seen.openpgp_admin {
            names.push(PinTarget::OpenPgpAdmin.name(lang));
        }
        if seen.piv_pin {
            names.push("PIV PIN");
        }
        if seen.piv_management {
            names.push(t::FIELD_PIV_MANAGEMENT.get(lang));
        }
        if !names.is_empty() {
            let how = if separate {
                t::FACTORY_SEPARATE
            } else {
                t::FACTORY_UNIFIED
            };
            items.push(Item::Banner(
                t::FACTORY_SEEN.fill(lang, [&names.join(" · "), how.get(lang)]),
                Tone::Warn,
            ));
        }
        items.push(Item::LabeledRow(
            t::LABEL_MODE.get(lang).to_owned(),
            vec![
                Ctl::radio(
                    YkPress::PinsUnified,
                    t::MODE_UNIFIED.get(lang),
                    !separate,
                    true,
                ),
                Ctl::radio(
                    YkPress::PinsSeparate,
                    t::MODE_SEPARATE.get(lang),
                    separate,
                    false,
                ),
            ],
        ));
        if separate {
            // The secrets still at their factory values say so (this run's changes count).
            let label = |target: PinTarget, factory: bool| {
                let name = target.name(lang);
                if factory && !self.card.list_changed.contains(&(serial, target)) {
                    t::FACTORY_MARK.fill(lang, [name])
                } else {
                    name.to_owned()
                }
            };
            items.push(Item::Row(vec![
                Ctl::button(
                    YkPress::ChangePw1,
                    &label(PinTarget::OpenPgpUser, seen.openpgp_admin),
                ),
                Ctl::button(
                    YkPress::ChangePw3,
                    &label(PinTarget::OpenPgpAdmin, seen.openpgp_admin),
                ),
            ]));
            items.push(Item::Row(vec![
                Ctl::button(
                    YkPress::ChangePivPin,
                    &label(PinTarget::PivPin, seen.piv_pin),
                ),
                Ctl::button(YkPress::ChangePuk, &label(PinTarget::PivPuk, seen.piv_pin)),
            ]));
            let protect = t::BTN_PROTECT_MANAGEMENT.get(lang);
            let protect = if seen.piv_management && !self.card.list_protected.contains(&serial) {
                t::FACTORY_MARK.fill(lang, [protect])
            } else {
                protect.to_owned()
            };
            items.push(Item::Row(vec![Ctl::button(YkPress::ChangeMgmt, &protect)]));
            items.push(Item::Help(t::YK_PROTECT_MGMT.get(lang).to_owned()));
        } else {
            items.push(Item::Row(vec![Ctl::primary(
                YkPress::SetPins,
                t::BTN_SET_PINS.get(lang),
            )]));
        }
        // The guide and the order behind a link (2026-11-10).
        let open = self.card.pin_guide_open;
        items.push(Item::Row(vec![Ctl::link(
            YkPress::PinGuide,
            if open {
                t::PIN_GUIDE_OPEN
            } else {
                t::PIN_GUIDE_CLOSED
            }
            .get(lang),
        )]));
        if open {
            for line in T_YK_PIN_GUIDE {
                items.push(Item::Text(format!("· {}", line.get(lang))));
            }
            items.push(Item::Help(t::YK_PIN_LOCKS.get(lang).to_owned()));
            items.push(Item::Text(t::YK_PIN_EASY.get(lang).to_owned()));
            items.push(Item::Help(t::YK_PIN_TRADEOFF.get(lang).to_owned()));
        }
        items.push(Item::CardEnd);
    }

    /// The removal overlay's text (spec/10 §7.5).
    #[must_use]
    pub fn yk_remove_text(&self) -> String {
        let lang = self.settings.language;
        let position = self
            .card
            .remove_target
            .and_then(|id| self.card.record_ids.iter().position(|other| *other == id));
        let Some(record) = position.and_then(|position| self.card.records.get(position)) else {
            return t::REMOVE_SELECTED.get(lang).to_owned();
        };
        // One sentence here; the accounts follow as the "지워지는 계정" block (2026-11-10).
        t::REMOVE_TEXT.fill(lang, [&self.card_name(record.serial)])
    }

    /// The removal overlay's accounts (2026-11-10): each key of the card with its addresses and
    /// last-read balance, what still signs for it ("`YubiKey` #m(으)로 계속 서명" / "이 지갑에서 서명
    /// 불가") and how it comes back, then what to do about a lost card.
    pub fn yk_remove_items(&self, items: &mut Vec<Item>) {
        let position = self
            .card
            .remove_target
            .and_then(|id| self.card.record_ids.iter().position(|other| *other == id));
        let Some(record) = position.and_then(|position| self.card.records.get(position)) else {
            return;
        };
        let others: Vec<HwKeyRecord> = self
            .card
            .records
            .iter()
            .filter(|other| other.serial != record.serial)
            .cloned()
            .collect();
        let lang = self.settings.language;
        items.push(Item::Subtitle(
            t::REMOVE_ACCOUNTS.fill(lang, [&self.card_name(record.serial)]),
        ));
        let accounts: Vec<crate::screen::RemovedAccount> = record
            .slots
            .iter()
            .map(|slot| {
                let mut account = self.card_removed(slot, &others, false);
                if crate::yubikey::holders(&others, slot.role).is_empty() {
                    // Only on this card: how the account comes back after the record goes.
                    let back = if yw_core::yubikey::plan::is_unknown_index(slot.role.index()) {
                        t::BACK_UNKNOWN
                    } else {
                        t::BACK_WORDS
                    };
                    account.note = Some(back.get(lang).to_owned());
                }
                account
            })
            .collect();
        let _ = crate::screen::build::removed::removed_items(lang, &accounts, items);
        items.push(Item::Help(t::LOST_CARD.get(lang).to_owned()));
    }
}

/// 2026-11-22 (S4d E0c): moved from `app_card` (render code).
impl Screen<'_> {
    /// The band of an account card or send form whose `YubiKey` is still on its factory PINs
    /// (spec/10 §9.3, 2026-11-10), with `PIN 설정` (that card's "PIN 설정" in 설정 → `YubiKey`).
    /// Display only: the card step's refusal stays the last line of defence.
    pub(crate) fn card_pin_banner(&self, serial: Option<u32>, items: &mut Vec<Item>) {
        let Some(serial) = serial else {
            return;
        };
        let lang = self.settings.language;
        items.push(Item::Banner(
            crate::wallet::app_card::text::PIN_BANNER.fill(lang, [&self.card_name(serial)]),
            Tone::Warn,
        ));
        if let Some(row) = self
            .card
            .records
            .iter()
            .position(|record| record.serial == serial)
            .and_then(|row| u16::try_from(row).ok())
            .filter(|row| *row < rows::YK_PIN_GATES)
        {
            items.push(Item::Row(vec![Ctl::button(
                YkPress::PinGate(Row(row)),
                crate::wallet::app_card::text::SET_PIN.get(lang),
            )]));
        }
    }
}
