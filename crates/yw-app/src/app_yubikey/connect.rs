//! "`YubiKey` 연결하기 (복구 단어 없이)" (spec/10 §7.6, spec/04 §2.19): a card that already holds
//! keys is connected without its recovery words — from S01 (a new `YubiKey` wallet: W01 first,
//! the password held by the key worker) or inside a wallet (settings → `YubiKey`, the chain
//! cards of a key-only / `YubiKey` wallet).
//!
//! Steps (the wizard [`YkWizard`] with [`ConnectForm`]): (1) the single inserted card is read
//! without a PIN (`YkJob::Scan`) and the user says what each found key is — secp256k1: EVM
//! account, Bitcoin address (P2PKH / P2SH-P2WPKH / P2WPKH on the settings network) or Zcash
//! transparent address, Ed25519: Solana — or leaves it out; (2) every resulting address in full
//! with "경로를 알 수 없음 — …" (`connect_record`, no card), the optional PIN check (one VERIFY);
//! (3) `저장` (`YkJob::Connect`: the card is read again and must still hold those keys), then the
//! wizard's result screen ("PIN 설정" and "다시 확인" as after an enrolment).

use yw_core::btc::{BtcNetwork, ScriptType};
use yw_core::secret::Zeroizing;
use yw_core::yubikey::connect::{CardScan, KeyUse, connect_record};
use yw_core::yubikey::plan::{CardSlot, Curve, MAX_CARDS};
use yw_core::yubikey::record::HwKeyRecord;
use yw_core::zec::ZecNetwork;

use super::{WizardOrigin, WizardStep, YkPurpose, YkWizard};
use crate::app::{App, AppMode, Purpose, Screen};
use crate::events::KeyJob;
use crate::logging;
use crate::ui::secret::{CardSecretKind, SecretKind};
use crate::workers::key::yubikey::YkJob;
use crate::yubikey::CardJobError;

/// T-YK-UNKNOWN-PATH: the note of every address of a connected key (spec/10 §7.6).
pub const T_YK_UNKNOWN_PATH: &str = "경로를 알 수 없음 — 이 키는 카드에서 가져왔습니다. 같은 주소가 맞는지 이전에 쓰던 지갑과 비교하세요.";
/// T-YK-CONNECT: what the flow does (S01 card, settings, the scan screen).
pub const T_YK_CONNECT: &str = "이미 키가 들어 있는 YubiKey를 복구 단어 없이 연결합니다. PIN 없이 읽을 수 있는 공개키만 읽고(카드에 아무것도 쓰지 않음) 각 키가 무엇인지 고르면 그 주소를 보여 드립니다. 서명은 지금처럼 YubiKey에서 PIN과 터치로 합니다.";

/// What the user says a found key is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Choice {
    /// Not connected.
    Skip,
    /// EVM account.
    Evm,
    /// Bitcoin address of this type (settings network).
    Btc(ScriptType),
    /// Zcash transparent address.
    Zec,
    /// Solana account.
    Sol,
}

/// The choices of a secp256k1 key (`OpenPGP` SIG/AUT), in radio order.
pub const SECP_CHOICES: [Choice; 6] = [
    Choice::Evm,
    Choice::Btc(ScriptType::P2wpkh),
    Choice::Btc(ScriptType::P2shP2wpkh),
    Choice::Btc(ScriptType::P2pkh),
    Choice::Zec,
    Choice::Skip,
];
/// The choices of an Ed25519 key (PIV).
pub const ED_CHOICES: [Choice; 2] = [Choice::Sol, Choice::Skip];

impl Choice {
    /// Radio label.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Self::Skip => "연결하지 않음".to_owned(),
            Self::Evm => "EVM 계정".to_owned(),
            Self::Btc(script) => format!("Bitcoin {} ({})", script.name(), script.technical()),
            Self::Zec => "Zcash 일반 주소".to_owned(),
            Self::Sol => "Solana 계정".to_owned(),
        }
    }

    /// The choices offered for a key of `curve`.
    #[must_use]
    pub const fn offered(curve: Curve) -> &'static [Self] {
        match curve {
            Curve::Secp256k1 => &SECP_CHOICES,
            Curve::Ed25519 => &ED_CHOICES,
        }
    }
}

/// The connect flow's state inside the wizard (no secret).
#[derive(Clone, Debug, Default)]
pub struct ConnectForm {
    /// The last scan.
    pub scan: Option<CardScan>,
    /// Why the scan failed (no card, several cards, reader).
    pub scan_error: Option<String>,
    /// A scan or the PIN check is running.
    pub busy: bool,
    /// One choice per found key, in scan order.
    pub choices: Vec<(CardSlot, Choice)>,
    /// The record shown on the confirmation (`connect_record`, no card contact).
    pub record: Option<HwKeyRecord>,
    /// Input error of the choice screen.
    pub error: Option<String>,
    /// The result of the optional PIN check (`true` = the card accepted the PIN).
    pub pin_note: Option<(bool, String)>,
}

impl ConnectForm {
    /// The networks of a Bitcoin and a Zcash use.
    fn uses(&self, btc: BtcNetwork, zec: ZecNetwork) -> Vec<(CardSlot, KeyUse)> {
        self.choices
            .iter()
            .filter_map(|(slot, choice)| {
                let use_ = match choice {
                    Choice::Skip => return None,
                    Choice::Evm => KeyUse::Evm,
                    Choice::Btc(script) => KeyUse::Btc {
                        network: btc,
                        script: *script,
                    },
                    Choice::Zec => KeyUse::Zec { network: zec },
                    Choice::Sol => KeyUse::Sol,
                };
                Some((*slot, use_))
            })
            .collect()
    }
}

/// The default choice of the `n`th found key: SIG = EVM, AUT = Bitcoin P2WPKH (the enrolment
/// wizard's defaults), PIV = Solana.
const fn default_choice(slot: CardSlot) -> Choice {
    match slot {
        CardSlot::OpenPgp(yw_core::yubikey::plan::PgpKey::Sig) => Choice::Evm,
        CardSlot::OpenPgp(yw_core::yubikey::plan::PgpKey::Aut) => Choice::Btc(ScriptType::P2wpkh),
        CardSlot::Piv(_) => Choice::Sol,
    }
}

impl App {
    /// The networks a connected Bitcoin / Zcash key is used on: the settings' Bitcoin network,
    /// and the Zcash network of the settings when Zcash is on (else the one matching Bitcoin).
    #[must_use]
    pub fn yk_connect_networks(&self) -> (BtcNetwork, ZecNetwork) {
        let btc = self.yk_network();
        let zec = if self.settings.zcash.enabled {
            self.settings.zcash.network
        } else {
            super::zec_network_for(btc)
        };
        (btc, zec)
    }

    /// Settings → `YubiKey` (and a key-only wallet's chain card) `YubiKey 연결하기`.
    pub fn yk_open_connect(&mut self) {
        if !matches!(self.mode, AppMode::Unlocked { .. }) || self.card.records.len() >= MAX_CARDS {
            return;
        }
        self.yk_connect_begin(WizardOrigin::Vault);
    }

    /// S01 `YubiKey 연결하기 (복구 단어 없이)`: W01 first (the new wallet's password).
    pub fn yk_connect_new_wallet(&mut self) {
        if self.mode != AppMode::NoVault || self.leftover {
            return;
        }
        self.key(KeyJob::YubiKey(YkJob::Discard));
        self.card.wizard = None;
        self.open_input(
            SecretKind::SetPassword,
            Purpose::YubiKey(YkPurpose::ConnectPassword),
            false,
        );
    }

    /// W01 of the S01 entry submitted: the key worker holds the password, the scan starts.
    pub(crate) fn yk_connect_password(&mut self, password: Zeroizing<Vec<u8>>) {
        self.close_secret();
        self.key(KeyJob::YubiKey(YkJob::HoldConnectPassword { password }));
        self.yk_connect_begin(WizardOrigin::NewWallet);
    }

    fn yk_connect_begin(&mut self, origin: WizardOrigin) {
        let mut wizard = YkWizard::new(origin, self.yk_network());
        wizard.connect = Some(Box::default());
        wizard.adopt = true;
        self.card.wizard = Some(wizard);
        self.set_screen(Screen::YubiKey);
        self.yk_connect_rescan();
    }

    fn yk_connect_form(&mut self) -> Option<&mut ConnectForm> {
        self.card
            .wizard
            .as_mut()
            .and_then(|wizard| wizard.connect.as_deref_mut())
    }

    /// `다시 읽기`: reads the inserted card again (read-only).
    pub fn yk_connect_rescan(&mut self) {
        let Some(wizard) = self.card.wizard.as_mut() else {
            return;
        };
        wizard.step = WizardStep::Plan;
        let Some(form) = wizard.connect.as_deref_mut() else {
            return;
        };
        *form = ConnectForm {
            busy: true,
            ..ConnectForm::default()
        };
        logging::info("app", "yubikey.connect_scan", &[]);
        self.key(KeyJob::YubiKey(YkJob::Scan));
        self.refresh();
    }

    /// `Scan` finished.
    pub(crate) fn on_yk_scanned(
        &mut self,
        result: Result<yw_core::yubikey::connect::CardScan, CardJobError>,
    ) {
        let records = self.card.records.clone();
        let Some(form) = self.yk_connect_form() else {
            return;
        };
        form.busy = false;
        match result {
            Ok(scan) => {
                form.choices = scan
                    .keys
                    .iter()
                    .map(|key| (key.slot, default_choice(key.slot)))
                    .collect();
                form.error = records
                    .iter()
                    .any(|record| record.serial == scan.serial)
                    .then(|| {
                        "이 YubiKey는 이미 이 지갑에 등록되어 있습니다. 다시 연결하려면 설정 → YubiKey에서 그 기록을 먼저 지우세요."
                            .to_owned()
                    });
                form.scan = Some(scan);
            }
            Err(error) => form.scan_error = Some(error.to_string()),
        }
        self.refresh();
    }

    /// A choice radio of found key `row`.
    pub fn yk_connect_choose(&mut self, row: usize, choice: Choice) {
        if let Some(form) = self.yk_connect_form()
            && let Some(entry) = form.choices.get_mut(row)
        {
            entry.1 = choice;
            form.error = None;
        }
        self.refresh();
    }

    /// `다음`: the record of the choices (no card), then the confirmation.
    pub fn yk_connect_next(&mut self) {
        let (btc, zec) = self.yk_connect_networks();
        let records = self.card.records.clone();
        let Some(wizard) = self.card.wizard.as_mut() else {
            return;
        };
        let Some(form) = wizard.connect.as_deref_mut() else {
            return;
        };
        let Some(scan) = form.scan.as_ref() else {
            return;
        };
        let uses = form.uses(btc, zec);
        if uses.is_empty() {
            form.error = Some("연결할 키를 하나 이상 고르세요.".to_owned());
            self.refresh();
            return;
        }
        match connect_record(scan, &uses, &records) {
            Ok(record) => {
                form.record = Some(record);
                form.error = None;
                form.pin_note = None;
                wizard.step = WizardStep::Confirm;
            }
            Err(error) => form.error = Some(error.to_string()),
        }
        self.refresh();
    }

    /// `← 다시 고르기`.
    pub fn yk_connect_back(&mut self) {
        if let Some(wizard) = self.card.wizard.as_mut() {
            wizard.step = WizardStep::Plan;
            wizard.failure = None;
        }
        self.refresh();
    }

    /// `PIN으로 소유 확인 (선택)`: W12 with the user PIN of the applet of the connected keys
    /// (`OpenPGP` when there is a secp256k1 key, else PIV).
    pub fn yk_connect_pin(&mut self) {
        let Some(record) = self
            .card
            .wizard
            .as_ref()
            .and_then(|wizard| wizard.connect.as_deref())
            .and_then(|form| form.record.as_ref())
        else {
            return;
        };
        let piv = !record
            .slots
            .iter()
            .any(|slot| slot.role.curve() == Curve::Secp256k1);
        let lines = self.yk_connect_pin_lines(piv);
        self.open_input(
            SecretKind::CardSecret(CardSecretKind::UserPin { piv }),
            Purpose::YubiKey(YkPurpose::ConnectPin),
            false,
        );
        if !lines.is_empty() {
            self.with_form(|form| form.set_details(lines));
        }
    }

    /// The tries left read by the scan (shown before the PIN is entered, spec/10 §9.1).
    fn yk_connect_pin_lines(&self, piv: bool) -> Vec<String> {
        let Some(scan) = self
            .card
            .wizard
            .as_ref()
            .and_then(|wizard| wizard.connect.as_deref())
            .and_then(|form| form.scan.as_ref())
        else {
            return Vec::new();
        };
        let counters = crate::yubikey::PinCounters {
            serial: scan.serial,
            pw1: scan.pgp_pin_retries,
            pw3: None,
            piv_pin: scan.piv_pin_retries,
            puk: None,
        };
        counters.lines(&[if piv {
            crate::yubikey::PinKind::PivPin
        } else {
            crate::yubikey::PinKind::OpenPgpUser
        }])
    }

    /// W12 of the PIN check submitted.
    pub(crate) fn yk_connect_pin_submit(&mut self, pin: Zeroizing<Vec<u8>>) {
        let Some(record) = self
            .card
            .wizard
            .as_ref()
            .and_then(|wizard| wizard.connect.as_deref())
            .and_then(|form| form.record.as_ref())
        else {
            self.close_secret();
            return;
        };
        let curve = if record
            .slots
            .iter()
            .any(|slot| slot.role.curve() == Curve::Secp256k1)
        {
            Curve::Secp256k1
        } else {
            Curve::Ed25519
        };
        let serial = record.serial;
        if yw_core::yubikey::is_factory_secret(&pin) {
            self.with_form(|form| {
                form.set_error(Some(
                    "공장 기본값(123456·12345678)으로는 확인하지 않습니다. 이 YubiKey가 아직 기본 PIN이면 연결한 뒤 'PIN 설정'으로 바꾸세요."
                        .to_owned(),
                ));
            });
            return;
        }
        self.with_form(|form| form.set_busy(true));
        if let Some(form) = self.yk_connect_form() {
            form.busy = true;
        }
        self.key(KeyJob::YubiKey(YkJob::ConnectVerify { serial, curve, pin }));
    }

    /// `ConnectVerify` finished.
    pub(crate) fn on_yk_connect_verified(&mut self, result: Result<(), CardJobError>) {
        // The PIN of the applet that was asked (`yk_connect_pin`), named in its error.
        let kind = match self.yk_connect_form() {
            Some(form)
                if form.record.as_ref().is_some_and(|record| {
                    record
                        .slots
                        .iter()
                        .any(|slot| slot.role.curve() == Curve::Secp256k1)
                }) =>
            {
                crate::yubikey::PinKind::OpenPgpUser
            }
            _ => crate::yubikey::PinKind::PivPin,
        };
        if let Some(form) = self.yk_connect_form() {
            form.busy = false;
        }
        match result {
            Ok(()) => {
                self.close_secret();
                if let Some(form) = self.yk_connect_form() {
                    form.pin_note = Some((
                        true,
                        "PIN이 맞습니다 — 이 YubiKey의 PIN을 알고 있습니다. (PIN은 저장하지 않았습니다)"
                            .to_owned(),
                    ));
                }
            }
            Err(error) => {
                let retry = !matches!(
                    error,
                    CardJobError::Card(
                        yw_core::yubikey::CardError::PinBlocked
                            | yw_core::yubikey::CardError::WrongPin { retries: 0 }
                    )
                );
                let text = error.text_for(kind);
                if retry {
                    self.with_form(|form| {
                        form.set_busy(false);
                        form.set_error(Some(text));
                    });
                } else {
                    self.close_secret();
                    if let Some(form) = self.yk_connect_form() {
                        form.pin_note = Some((false, text));
                    }
                }
            }
        }
        self.refresh();
    }

    /// `저장`: the card is read again and the confirmed record stored (or the wallet created).
    pub fn yk_connect_save(&mut self) {
        let (btc, zec) = self.yk_connect_networks();
        let Some(wizard) = self.card.wizard.as_mut() else {
            return;
        };
        let Some(form) = wizard.connect.as_deref() else {
            return;
        };
        let (Some(record), false) = (form.record.clone(), form.busy) else {
            return;
        };
        let choices = form.uses(btc, zec);
        wizard.step = WizardStep::Running;
        wizard.failure = None;
        self.card.enrol = Some(crate::app_card::EnrolState::Running);
        logging::info("app", "yubikey.connect_save", &[]);
        self.key(KeyJob::YubiKey(YkJob::Connect {
            serial: record.serial,
            choices,
            expected: Box::new(record),
        }));
        self.refresh();
    }

    /// Commands of the connect flow; `false` when `id` is not one of them.
    pub(crate) fn on_yk_connect_command(&mut self, id: u16) -> bool {
        use crate::ui::screens_yubikey::ids;
        if let Some((row, choice)) = ids::connect_choice(id) {
            self.yk_connect_choose(row, choice);
            return true;
        }
        match id {
            ids::CONNECT_START => self.yk_open_connect(),
            ids::CONNECT_NEW_WALLET => self.yk_connect_new_wallet(),
            ids::CONNECT_RESCAN => self.yk_connect_rescan(),
            ids::CONNECT_NEXT => self.yk_connect_next(),
            ids::CONNECT_BACK => self.yk_connect_back(),
            ids::CONNECT_PIN => self.yk_connect_pin(),
            ids::CONNECT_SAVE => self.yk_connect_save(),
            _ => return false,
        }
        true
    }
}
