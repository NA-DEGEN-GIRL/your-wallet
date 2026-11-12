//! The `YubiKey` enrolment wizard, the new `YubiKey` wallet and the `YubiKey` list (spec/10 §7,
//! §9.3; spec/04 §2.19).
//!
//! Wizard (`Screen::YubiKey`, steps [`WizardStep`]): (a) keys and slots — `OpenPGP` SIG and AUT
//! each none / EVM account / Bitcoin single address / EVM shared key with an index, PIV a count
//! of Solana accounts from a start index in the retired slots `82`…, touch policy per applet, or
//! "백업 복사본" of an enrolled card's slot plan; (b) the recovery words once in W05 (+ W06) —
//! held by the key worker from then on, never on the UI thread; (c) the confirmation with every
//! path and address (`enrol::preview`, no card), the pre-card plan checks, the cards already
//! holding the same keys and the same-mnemonic warning; (d) credentials — the inserted card's
//! management key state is read first (`YkJob::ProbeManagement`); the `OpenPGP` admin PIN and
//! the PIV management key in W12 (or the factory key; for a PIN-protected key only the PIV
//! PIN), moved into the job; (e) the result (also after "가져오기 없이 등록") with the recorded
//! slots, "다시 확인" and "기본값 변경 / PIN 설정" (§9.3: "8자리 하나로 통일" by default, or one
//! secret at a time; the management key is generated and stored PIN-protected, never shown),
//! also reachable from the `YubiKey` list; (f)
//! `다른 YubiKey 등록(백업)` back to (a) with the backup copy.
//!
//! New `YubiKey` wallet (S01 card, spec/10 §7.1-1): S20 → W01 → W08 (new words) → W10 (four
//! words, checked in memory by the key worker) → the wizard → `Vault::create_with_hardware`.
//! The words are never written to disk; the key worker wipes them when the wizard ends or the
//! wallet locks.

use yw_core::bip32::path::AccountIndex;
use yw_core::btc::{BtcNetwork, ScriptType};
use yw_core::secret::Zeroizing;
use yw_core::vault::RecordId;
use yw_core::yubikey::enrol::{DefaultsSeen, Enrolled};
use yw_core::yubikey::piv::ManagementState;
use yw_core::yubikey::plan::{
    BtcUse, CardSlot, KeyRole, MAX_CARDS, PgpKey, PinPolicy, PivSlot, PlannedSlot, TouchPolicy,
    validate_plan,
};
use yw_core::yubikey::record::HwKeyRecord;

use crate::app::{App, AppMode, Confirm, PasswordAction, Purpose, Screen, SettingsSection};
use crate::events::{KeyJob, YubiKeyJobError};
use crate::logging;
use crate::ui::main_window::Tone;
use crate::ui::secret::{CardSecretKind, DisplaySecret, SecretKind};
use crate::workers::key::yubikey::{CounterTarget, YkJob, YkOutcome, YkPreview};
use crate::yubikey::{CardJobError, PinCounters, PinKind, PinTarget};

pub mod connect;
pub mod manage;

/// Most Solana accounts on one card (the 20 retired PIV slots `82`–`95`).
pub const MAX_PIV_ACCOUNTS: u32 = 20;
/// Highest index the wizard offers for a key from recovery words: `900..=999` is the band of
/// keys connected without them (spec/10 §7.6, `plan::UNKNOWN_PATH_FIRST`).
pub const MAX_ACCOUNT_INDEX: u32 = yw_core::yubikey::plan::UNKNOWN_PATH_FIRST - 1;

/// T-YK-SAME (spec/10 §7.1-2, user decision 2026-11-05): the entered words are this vault's.
pub const T_YK_SAME: &str = "이 복구 단어는 이 PC의 vault에도 저장되어 있습니다. 복구 단어가 이 PC에 남아 있는 동안 YubiKey는 보안 이득이 없습니다(같은 키를 PC에서도 만들 수 있음). 키를 PC 밖에 두려면 'YubiKey 지갑'(복구 단어를 저장하지 않는 지갑)을 새로 만드세요.";
/// T-YK-SAME-WORDS (spec/10 §7.1-2): the same words are on this PC with another passphrase.
pub const T_YK_SAME_WORDS: &str = "이 복구 단어는 이 PC의 vault에도 저장되어 있습니다(passphrase만 다름). 이 PC의 복구 단어를 손에 넣은 사람에게는 passphrase만이 이 YubiKey의 키를 지킵니다. 키를 PC 밖에 두려면 'YubiKey 지갑'(복구 단어를 저장하지 않는 지갑)을 새로 만들거나 다른 복구 단어를 쓰세요.";
/// T-YK-SHARED (spec/10 §3.2): the two sentences of the shared-key choice.
pub const T_YK_SHARED: &str = "EVM 공유 키는 EVM 주소와 Bitcoin 주소가 같은 공개키에서 나옵니다. Bitcoin에서 그 주소로 한 번이라도 보내면 누구나 그 공개키에서 EVM 주소를 계산할 수 있어 두 체인의 신원이 연결됩니다. 또 표준 Bitcoin 지갑은 이 주소를 찾지 못합니다(경로가 m/44'/60'/…): 복구는 이 지갑으로 같은 복구 단어·같은 인덱스를 다시 등록하거나 그 EVM 개인키를 WIF로 가져와야 합니다.";
/// T-YK-OVERWRITE (spec/10 §7.4).
pub const T_YK_OVERWRITE: &str = "가져오기는 고른 슬롯(OpenPGP SIG/AUT, PIV 82…)에 키를 씁니다. 그 슬롯에 이번에 넣을 키가 아닌 다른 키가 있으면 가져오기 전에 그 키와 주소를 보여 드리고, 지워도 된다고 확인해야만 덮어씁니다. 다른 용도(GPG 등)로 쓰는 슬롯이면 고르지 마세요.";
/// T-YK-OCCUPIED (spec/10 §7.4): planned slots hold keys the enrolment would destroy.
pub const T_YK_OCCUPIED: &str = "이 YubiKey의 아래 슬롯에는 이미 다른 키가 있습니다(이번에 넣을 키가 아님). 가져오면 그 키는 카드에서 영구히 지워지고, 그 키를 다시 만들 복구 단어나 백업이 없으면 그 주소의 자산을 다시 쓸 수 없습니다. 잔액이 있으면 먼저 옮기고, 다른 용도(GPG 등)의 키라면 다른 슬롯을 고르세요.";
/// The checkbox of [`T_YK_OCCUPIED`].
pub const T_YK_OCCUPIED_ACK: &str =
    "이해했습니다: 이 슬롯의 키는 영구히 지워지고 그 주소의 자산을 다시 쓸 수 없을 수 있습니다";
/// The hint after an enrolment refused for a key already in a slot.
pub const T_YK_OCCUPIED_RETRY: &str =
    "'다시 시도'를 누르면 그 슬롯의 키를 보여 드리고, 지워도 된다고 확인한 뒤에만 덮어씁니다.";
/// T-YK-BACKUP-UNKNOWN (spec/10 §7.6): a card connected without recovery words cannot be
/// copied.
pub const T_YK_BACKUP_UNKNOWN: &str = "복구 단어 없이 연결한 키는 경로를 몰라 복구 단어로 다른 YubiKey에 똑같이 넣을 수 없습니다. 백업 복사본은 복구 단어로 등록한 YubiKey에서만 만들 수 있습니다.";
/// T-YK-PARTIAL (spec/10 §7.4).
pub const T_YK_PARTIAL: &str = "일부 슬롯에 키가 이미 들어갔을 수 있습니다. 다시 시도하면 덮어씁니다. 지갑에는 아무것도 기록하지 않았습니다.";
/// T-YK-PIV-FIRMWARE (spec/10 §2, user decision 2026-11-05).
pub const T_YK_PIV_FIRMWARE: &str = "Solana(PIV Ed25519) 키 가져오기는 펌웨어 5.7.4 이상에서 문서화되어 있습니다. 5.7.0–5.7.3 YubiKey는 가져오기를 거부할 수 있고(그때 \"이 펌웨어는 Ed25519 가져오기를 거부했습니다\"), 5.7.0 미만은 PIV 슬롯을 쓸 수 없습니다.";
/// T-YK-WALLET (S01 card, spec/10 §7.1-1).
pub const T_YK_WALLET: &str = "새 복구 단어 24개를 만들어 종이에 적고, 그 단어에서 만든 키를 YubiKey에 넣습니다. 이 PC에는 복구 단어를 저장하지 않고 공개키·주소만 둡니다. 서명은 YubiKey에서 PIN과 터치로 합니다.";

/// What an `OpenPGP` slot of the plan holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PgpKind {
    /// Nothing.
    None,
    /// EVM account `i`.
    Evm,
    /// Bitcoin single address `i` (current network).
    Btc,
    /// EVM account `i` also used as one Bitcoin address (spec/10 §3.2).
    Shared,
    /// Zcash transparent address `i` (`m/44'/{133|1}'/0'/0/i`, spec/10 §3.1).
    Zec,
}

/// The form of one `OpenPGP` slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PgpForm {
    /// What it holds.
    pub kind: PgpKind,
    /// The index text (0–999).
    pub index_text: String,
    /// Bitcoin address type (Bitcoin and shared key).
    pub script: ScriptType,
    /// Touch policy.
    pub touch: TouchPolicy,
    /// Zcash network (Zcash slot).
    pub zec: yw_core::zec::ZecNetwork,
}

impl PgpForm {
    fn new(kind: PgpKind, index: u32) -> Self {
        Self {
            kind,
            index_text: index.to_string(),
            script: ScriptType::P2wpkh,
            touch: TouchPolicy::Always,
            zec: yw_core::zec::ZecNetwork::Mainnet,
        }
    }
}

/// The Zcash network that goes with the Bitcoin network of the settings (testnet4 → testnet).
#[must_use]
pub fn zec_network_for(network: BtcNetwork) -> yw_core::zec::ZecNetwork {
    if network == BtcNetwork::Testnet4 {
        yw_core::zec::ZecNetwork::Testnet
    } else {
        yw_core::zec::ZecNetwork::Mainnet
    }
}

/// T-YK-ABANDON: the new `YubiKey` wallet's wizard `취소` after the words were shown (2026-11-10).
pub const T_YK_ABANDON: &str =
    "지금 그만두면 방금 적은 복구 단어 24개는 지워지고 이 지갑에 쓰이지 않습니다.";
/// T-YK-WORDS-UNUSED: S01's band once a new `YubiKey` wallet's shown words were discarded.
pub const T_YK_WORDS_UNUSED: &str = "방금 적은 복구 단어 종이는 어느 지갑에도 쓰이지 않습니다. 다시 시작하면 새 단어가 나오니 그 종이에 “사용 안 함”이라고 적거나 폐기하세요.";
/// Added to [`T_YK_WORDS_UNUSED`] when a card job may have written keys from those words.
pub const T_YK_WORDS_ON_CARD: &str = "(YubiKey에 이미 넣은 키는 이 종이의 단어로 만든 것입니다.)";

/// How far a new `YubiKey` wallet got with its words, for S01's band when they are discarded
/// before a wallet is made from them (spec/10 §7.1-1, 2026-11-10).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum YkWords {
    /// No new words shown (or they became a wallet).
    #[default]
    None,
    /// W08 showed them (the user may have written them down).
    Shown,
    /// An enrolment job started writing keys made from them to a card.
    OnCard,
}

/// What S08 says after a new `YubiKey` wallet (spec/04 §2.19): the wallet is made from new words
/// (`YubiKey 지갑 만들기`, the backup is that paper) or connected without words (the card holds
/// the only copy of its keys).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YkDone {
    /// Enrolled from new recovery words; the card's serial.
    Created(u32),
    /// Connected without recovery words; the card's serial.
    Connected(u32),
}

/// Where the wizard was started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WizardOrigin {
    /// Settings → `YubiKey` of an unlocked wallet.
    Vault,
    /// The new `YubiKey` wallet (no vault yet; it is created by the first enrolment).
    NewWallet,
}

/// The wizard step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WizardStep {
    /// (a) keys and slots.
    Plan,
    /// (c) the confirmation (the preview is computed by the key worker meanwhile).
    Confirm,
    /// (d) credentials.
    Credentials,
    /// The card job runs.
    Running,
    /// (e) the result (or the failure).
    Result,
}

/// The secret windows of the `YubiKey` flows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum YkPurpose {
    /// W05: the recovery words of an enrolment.
    Mnemonic,
    /// W06: their BIP39 passphrase.
    Passphrase,
    /// W01 of the new `YubiKey` wallet.
    NewPassword,
    /// W08: the new words.
    ShowWords,
    /// W10: the four words.
    Backup,
    /// W12: the `OpenPGP` admin PIN.
    AdminPin,
    /// W12: the PIV management key of the enrolment.
    ManagementKey,
    /// W12: a PIN/PUK change.
    ChangePin(PinTarget),
    /// W12: the PIV PIN of an enrolment whose management key is PIN-protected.
    PivPin,
    /// W12: the PIV PIN for "PIV 관리 키 자동 보호".
    ProtectManagement,
    /// W12: "PIN 하나로 통일".
    SetPins,
    /// W05 of "슬롯 구성 바꾸기" (spec/10 §15.1).
    ReslotMnemonic,
    /// W06 of "슬롯 구성 바꾸기".
    ReslotPassphrase,
    /// W12: the `OpenPGP` admin PIN of "슬롯 구성 바꾸기".
    ReslotAdminPin,
    /// W12: the `OpenPGP` admin PIN of "`YubiKey` 비우기" (our slots only).
    ClearAdminPin,
    /// W12: the PIV PIN of "`YubiKey` 비우기" (our slots only).
    ClearPivPin,
    /// W01 of "`YubiKey` 연결하기" from S01 (spec/10 §7.6).
    ConnectPassword,
    /// W12: the optional PIN check of "`YubiKey` 연결하기".
    ConnectPin,
}

impl YkPurpose {
    /// A window of the `YubiKey` list's card actions ([`manage`]).
    #[must_use]
    pub const fn is_manage(self) -> bool {
        matches!(
            self,
            Self::ReslotMnemonic
                | Self::ReslotPassphrase
                | Self::ReslotAdminPin
                | Self::ClearAdminPin
                | Self::ClearPivPin
        )
    }
}

/// The wizard state (no secret: the words are in the key worker, the credentials only between
/// their window and the job).
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent flags of one wizard"
)]
pub struct YkWizard {
    /// Origin.
    pub origin: WizardOrigin,
    /// Step.
    pub step: WizardStep,
    /// `OpenPGP` SIG.
    pub sig: PgpForm,
    /// `OpenPGP` AUT.
    pub aut: PgpForm,
    /// Solana accounts (PIV) count text.
    pub sol_count_text: String,
    /// First Solana index text.
    pub sol_start_text: String,
    /// PIV touch policy.
    pub piv_touch: TouchPolicy,
    /// "백업 복사본": copy this enrolled card's slot plan.
    pub backup_of: Option<u32>,
    /// The §3.2 checkbox of the shared key.
    pub shared_ack: bool,
    /// The same-mnemonic warning was acknowledged.
    pub same_ack: bool,
    /// Input error of the plan screen.
    pub error: Option<String>,
    /// The plan sent to the preview / the card.
    pub slots: Vec<PlannedSlot>,
    /// The confirmation facts.
    pub preview: Option<YkPreview>,
    /// The key worker holds the recovery words.
    pub seed_held: bool,
    /// Use the factory PIV management key.
    pub default_management: bool,
    /// The inserted card's management key state read at step (d) (`None`: not read).
    pub management: Option<ManagementState>,
    /// The one inserted card, identified at steps (c) and (d) (`YkJob::Identify`): the
    /// enrolment and the management probe go to this serial only (spec/10 §7.3).
    pub card: Option<crate::yubikey::CardFacts>,
    /// Why no card is identified (none, several, reader error); `None` while reading.
    pub card_error: Option<String>,
    /// The planned slots of the identified card holding a key the held words do not derive,
    /// read at step (d) (`YkJob::Occupied`; `None` while reading, `Err` when it could not be
    /// read): an import overwrites them only after [`YkWizard::overwrite_ack`] and the typed
    /// [`manage::LOSS_WORD`] (spec/10 §7.4).
    pub occupied: Option<Result<Vec<yw_core::yubikey::enrol::Occupant>, String>>,
    /// The [`T_YK_OCCUPIED`] checkbox.
    pub overwrite_ack: bool,
    /// The typed [`manage::LOSS_WORD`] (checked when `가져오기` is pressed).
    pub overwrite_typed: String,
    /// The admin PIN between W12 and the job (wiped on drop).
    admin_pin: Option<Zeroizing<Vec<u8>>>,
    /// The words of W05 while W06 asks for the passphrase (wiped on drop).
    phrase: Option<Zeroizing<Vec<u8>>>,
    /// "가져오기 없이 등록" of the running job.
    pub adopt: bool,
    /// The last enrolment.
    pub enrolled: Option<Enrolled>,
    /// The last failure (§7.4).
    pub failure: Option<String>,
    /// "다시 확인" lines.
    pub check: Option<Vec<String>>,
    /// Defaults still to change of the enrolled card.
    pub defaults: DefaultsSeen,
    /// PIN changes done on the result screen.
    pub changed: Vec<PinTarget>,
    /// "8자리 하나로 통일" finished without a failure for the result card.
    pub pins_set: bool,
    /// Notes of the result screen (PIN changed, management key set).
    pub notes: Vec<String>,
    /// A wallet was created by this wizard (new `YubiKey` wallet).
    pub created: bool,
    /// "`YubiKey` 연결하기 (복구 단어 없이)": the wizard runs the connect flow (spec/10 §7.6).
    pub connect: Option<Box<connect::ConnectForm>>,
}

impl core::fmt::Debug for YkWizard {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("YkWizard")
            .field("origin", &self.origin)
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}

/// The next unused index of EVM accounts, Bitcoin `script` addresses of `network`, and Solana
/// accounts over the enrolled cards (the defaults of the next `YubiKey`, spec/10 §3.1).
fn next_indices(
    records: &[HwKeyRecord],
    network: BtcNetwork,
    script: ScriptType,
) -> (u32, u32, u32) {
    let mut evm: Vec<u32> = Vec::new();
    let mut btc: Vec<u32> = Vec::new();
    let mut sol: Vec<u32> = Vec::new();
    // Keys connected without recovery words hold the band 900–999, not paths (spec/10 §7.6).
    for slot in records
        .iter()
        .flat_map(|record| &record.slots)
        .filter(|slot| !yw_core::yubikey::plan::is_unknown_index(slot.role.index()))
    {
        match slot.role {
            KeyRole::Evm { index, .. } => evm.push(index.get()),
            KeyRole::Btc {
                network: net,
                script: kind,
                index,
            } if net == network && kind == script => btc.push(index),
            KeyRole::Btc { .. } | KeyRole::Zec { .. } => {}
            KeyRole::Sol { index } => sol.push(index.get()),
        }
    }
    let next = |used: &[u32]| used.iter().max().map_or(0, |max| max.saturating_add(1));
    (next(&evm), next(&btc), next(&sol))
}

fn parse_index(text: &str, max: u32, what: &str) -> Result<u32, String> {
    text.trim()
        .parse::<u32>()
        .ok()
        .filter(|value| *value <= max)
        .ok_or_else(|| format!("{what}: 0–{max} 사이의 숫자를 넣으세요."))
}

impl YkWizard {
    /// A wizard with the defaults (spec/10 §3.1): the first card SIG = EVM 0, AUT = Bitcoin
    /// P2WPKH 0, one Solana account 0; the next cards the next unused indices.
    #[must_use]
    pub fn new(origin: WizardOrigin, records: &[HwKeyRecord], network: BtcNetwork) -> Self {
        let (evm, btc, sol) = next_indices(records, network, ScriptType::P2wpkh);
        let form = |kind, index| PgpForm {
            zec: zec_network_for(network),
            ..PgpForm::new(kind, index)
        };
        Self {
            origin,
            step: WizardStep::Plan,
            sig: form(PgpKind::Evm, evm),
            aut: form(PgpKind::Btc, btc),
            sol_count_text: "1".to_owned(),
            sol_start_text: sol.to_string(),
            piv_touch: TouchPolicy::Always,
            backup_of: None,
            shared_ack: false,
            same_ack: false,
            error: None,
            slots: Vec::new(),
            preview: None,
            seed_held: false,
            default_management: true,
            management: None,
            card: None,
            card_error: None,
            occupied: None,
            overwrite_ack: false,
            overwrite_typed: String::new(),
            admin_pin: None,
            phrase: None,
            adopt: false,
            enrolled: None,
            failure: None,
            check: None,
            defaults: DefaultsSeen::default(),
            changed: Vec::new(),
            pins_set: false,
            notes: Vec::new(),
            created: false,
            connect: None,
        }
    }

    /// The form of `key`.
    #[must_use]
    pub const fn pgp(&self, key: PgpKey) -> &PgpForm {
        match key {
            PgpKey::Sig => &self.sig,
            PgpKey::Aut => &self.aut,
        }
    }

    const fn pgp_mut(&mut self, key: PgpKey) -> &mut PgpForm {
        match key {
            PgpKey::Sig => &mut self.sig,
            PgpKey::Aut => &mut self.aut,
        }
    }

    /// Whether the plan uses the shared key (the §3.2 checkbox is required).
    #[must_use]
    pub fn uses_shared(&self) -> bool {
        self.backup_of.is_none()
            && (self.sig.kind == PgpKind::Shared || self.aut.kind == PgpKind::Shared)
    }

    /// The planned slot of one `OpenPGP` form (`None` for an empty slot).
    ///
    /// # Errors
    ///
    /// The index text is not a number in range.
    pub fn pgp_preview(
        form: &PgpForm,
        key: PgpKey,
        network: BtcNetwork,
    ) -> Result<Option<PlannedSlot>, String> {
        let label = CardSlot::OpenPgp(key).label();
        let role = match form.kind {
            PgpKind::None => return Ok(None),
            PgpKind::Evm | PgpKind::Shared => {
                let index = parse_index(&form.index_text, MAX_ACCOUNT_INDEX, &label)?;
                let index =
                    AccountIndex::new(index).map_err(|_| format!("{label}: 인덱스 범위"))?;
                KeyRole::Evm {
                    index,
                    btc: (form.kind == PgpKind::Shared).then_some(BtcUse {
                        network,
                        script: form.script,
                    }),
                }
            }
            PgpKind::Btc => KeyRole::Btc {
                network,
                script: form.script,
                index: parse_index(&form.index_text, MAX_ACCOUNT_INDEX, &label)?,
            },
            PgpKind::Zec => KeyRole::Zec {
                network: form.zec,
                index: parse_index(&form.index_text, MAX_ACCOUNT_INDEX, &label)?,
            },
        };
        Ok(Some(PlannedSlot {
            slot: CardSlot::OpenPgp(key),
            role,
            touch: form.touch,
            pin: PinPolicy::NotApplicable,
            backup_copy: false,
        }))
    }

    /// The slot plan of the form (or the backup copy of `records`' card), checked with the
    /// per-card rules (`plan::validate_plan`).
    ///
    /// # Errors
    ///
    /// The text to show on the plan screen.
    pub fn plan(
        &self,
        records: &[HwKeyRecord],
        network: BtcNetwork,
    ) -> Result<Vec<PlannedSlot>, String> {
        let slots = if let Some(serial) = self.backup_of {
            let record = records
                .iter()
                .find(|record| record.serial == serial)
                .ok_or_else(|| "복사할 YubiKey 기록을 찾지 못했습니다.".to_owned())?;
            // A key connected without recovery words has no path: the words cannot make it again
            // (spec/10 §7.6), so only the slots with a known path are copied.
            let copied: Vec<PlannedSlot> = record
                .slots
                .iter()
                .filter(|slot| slot.path_known)
                .map(|slot| PlannedSlot {
                    backup_copy: true,
                    ..slot.planned()
                })
                .collect();
            if copied.is_empty() {
                return Err(T_YK_BACKUP_UNKNOWN.to_owned());
            }
            copied
        } else {
            let mut slots = Vec::new();
            for key in [PgpKey::Sig, PgpKey::Aut] {
                if let Some(slot) = Self::pgp_preview(self.pgp(key), key, network)? {
                    slots.push(slot);
                }
            }
            let count = parse_index(&self.sol_count_text, MAX_PIV_ACCOUNTS, "Solana 계정 수")?;
            let start = parse_index(&self.sol_start_text, MAX_ACCOUNT_INDEX, "첫 Solana 계정")?;
            if count > 0 && start.saturating_add(count - 1) > MAX_ACCOUNT_INDEX {
                return Err(format!(
                    "Solana 계정 인덱스는 {MAX_ACCOUNT_INDEX}까지입니다."
                ));
            }
            for n in 0..count {
                let slot = u8::try_from(n)
                    .ok()
                    .and_then(PivSlot::retired)
                    .ok_or_else(|| "PIV 슬롯은 20개까지입니다.".to_owned())?;
                let index = AccountIndex::new(start.saturating_add(n))
                    .map_err(|_| "Solana 계정 인덱스 범위".to_owned())?;
                slots.push(PlannedSlot {
                    slot: CardSlot::Piv(slot),
                    role: KeyRole::Sol { index },
                    touch: self.piv_touch,
                    pin: PinPolicy::Always,
                    backup_copy: false,
                });
            }
            slots
        };
        if slots.is_empty() {
            return Err("YubiKey에 넣을 키를 하나 이상 고르세요.".to_owned());
        }
        if self.uses_shared() && !self.shared_ack {
            return Err("EVM 공유 키의 안내를 읽고 확인란을 체크하세요.".to_owned());
        }
        validate_plan(&slots).map_err(|error| error.to_string())?;
        Ok(slots)
    }

    /// Whether the plan has `OpenPGP` / PIV slots.
    #[must_use]
    pub fn applets(&self) -> (bool, bool) {
        (
            self.slots
                .iter()
                .any(|slot| matches!(slot.slot, CardSlot::OpenPgp(_))),
            self.slots
                .iter()
                .any(|slot| matches!(slot.slot, CardSlot::Piv(_))),
        )
    }

    /// Whether the inserted card's PIV management key is PIN-protected (read at step (d)).
    #[must_use]
    pub fn management_protected(&self) -> bool {
        self.management.is_some_and(|state| state.protected)
    }

    /// "PIN 설정" of the result card is done (spec/10 §9.3): "8자리 하나로 통일" finished without
    /// a failure, or every secret of the enrolled card's applets was changed one at a time (and
    /// the PIV management key is protected). A new `YubiKey` wallet cannot finish before this.
    #[must_use]
    pub fn pins_done(&self) -> bool {
        if self.pins_set {
            return true;
        }
        let Some(enrolled) = self.enrolled.as_ref() else {
            return false;
        };
        let has = |curve| {
            enrolled
                .record
                .slots
                .iter()
                .any(|slot| slot.role.curve() == curve)
        };
        let changed = |target| self.changed.contains(&target);
        (!has(yw_core::yubikey::plan::Curve::Secp256k1)
            || (changed(PinTarget::OpenPgpUser) && changed(PinTarget::OpenPgpAdmin)))
            && (!has(yw_core::yubikey::plan::Curve::Ed25519)
                || (changed(PinTarget::PivPin)
                    && changed(PinTarget::PivPuk)
                    && !self.defaults.piv_management))
    }

    /// Whether the confirmation allows going on (no plan error, the same-mnemonic warning
    /// acknowledged).
    #[must_use]
    pub fn can_continue(&self) -> bool {
        self.preview.as_ref().is_some_and(|preview| {
            preview.plan.is_ok() && (!preview.same_as_vault || self.same_ack)
        })
    }

    /// The planned slots of the identified card holding a key the plan would destroy (empty
    /// while not read or unreadable: the card job then refuses such a key itself).
    #[must_use]
    pub fn occupants(&self) -> &[yw_core::yubikey::enrol::Occupant] {
        match &self.occupied {
            Some(Ok(occupants)) => occupants,
            _ => &[],
        }
    }

    /// Whether `가져오기` may go on: no key would be destroyed, or the user checked
    /// [`T_YK_OCCUPIED_ACK`] (the typed word is checked when it is pressed).
    #[must_use]
    pub fn can_import(&self) -> bool {
        self.occupants().is_empty() || self.overwrite_ack
    }

    /// Forgets the slot read of step (d) and its confirmation (another card, another read).
    fn reset_occupied(&mut self) {
        self.occupied = None;
        self.overwrite_ack = false;
        self.overwrite_typed.clear();
    }
}

/// A card record's removal, clear or re-slot refused: it holds the last key of an account whose
/// transaction may still confirm (spec/10 §15).
pub const T_YK_BUSY: &str = "이 YubiKey의 키로만 서명하는 계정에서 보낸 거래가 아직 확정될 수 있어(진행 중, 또는 Bitcoin은 포기·거절 뒤 30일 이내) 카드와 지갑의 기록을 바꾸지 않았습니다. 거래가 확정되거나 만료된 뒤에 다시 시도하세요. 거래 저널에 손상된 기록이 있으면 어느 계정의 거래인지 확인할 수 없어 바꾸지 않습니다.";

/// The text of an enrolment failure.
fn failure_text(error: YubiKeyJobError) -> String {
    match error {
        YubiKeyJobError::Key(error) => crate::errors::key_code(error).text(),
        YubiKeyJobError::Vault(error) => crate::errors::vault_code(error).text(),
        YubiKeyJobError::Card(error) => error.to_string(),
        YubiKeyJobError::Busy => T_YK_BUSY.to_owned(),
    }
}

/// [`failure_text`] of a job that sent the card secret `kind`: a wrong or blocked value names
/// that secret (spec/10 §9.1).
fn failure_text_for(error: YubiKeyJobError, kind: PinKind) -> String {
    match error {
        YubiKeyJobError::Card(error) => error.text_for(kind),
        other => failure_text(other),
    }
}

/// T-YK-ENROL-FOREIGN (spec/10 §7.4): an enrolment stopped at a key it does not derive.
pub const T_YK_ENROL_FOREIGN: &str =
    "이 YubiKey의 고른 슬롯에 이번에 넣을 키가 아닌 다른 키가 있어 아무것도 쓰지 않았습니다.";

/// The wizard's text of an enrolment (or connect) failure: the secret a wrong PIN was (the admin
/// PIN before any write of a plan with `OpenPGP` slots, else the PIV PIN), a key found in a slot
/// with how to see it, and the partial-write note only once an import started (spec/10 §7.4).
fn enrol_failure_text(error: YubiKeyJobError, openpgp: bool) -> String {
    use yw_core::yubikey::enrol::EnrolError;
    let enrol = match error {
        YubiKeyJobError::Card(CardJobError::Enrol(enrol)) => Some(enrol),
        _ => None,
    };
    if enrol == Some(EnrolError::Card(yw_core::yubikey::CardError::ForeignKey)) {
        return format!("{T_YK_ENROL_FOREIGN} {T_YK_OCCUPIED_RETRY}");
    }
    let partial = matches!(enrol, Some(EnrolError::Partial(_)));
    let kind = if openpgp && !partial {
        PinKind::OpenPgpAdmin
    } else {
        PinKind::PivPin
    };
    let mut text = failure_text_for(error, kind);
    if partial {
        text.push(' ');
        text.push_str(T_YK_PARTIAL);
    }
    text
}

/// Command ids of the wizard's touch radios: `(policy, id offset)`.
pub const PGP_TOUCH: [TouchPolicy; 4] = [
    TouchPolicy::Always,
    TouchPolicy::Cached,
    TouchPolicy::AlwaysFixed,
    TouchPolicy::CachedFixed,
];
/// The PIV touch choices.
pub const PIV_TOUCH: [TouchPolicy; 2] = [TouchPolicy::Always, TouchPolicy::Cached];
/// The Bitcoin address types a card key can be (no Taproot).
pub const CARD_SCRIPTS: [ScriptType; 3] = [
    ScriptType::P2wpkh,
    ScriptType::P2shP2wpkh,
    ScriptType::P2pkh,
];

impl App {
    /// The current Bitcoin network of the settings (the network of a planned Bitcoin key).
    #[must_use]
    pub fn yk_network(&self) -> BtcNetwork {
        crate::btc::core_network(self.settings.bitcoin.network)
    }

    /// Opens the wizard (Settings → `YubiKey`, a key-only wallet's chain card).
    pub fn yk_open_wizard(&mut self) {
        if !matches!(self.mode, AppMode::Unlocked { .. }) || self.card.records.len() >= MAX_CARDS {
            return;
        }
        let wizard = YkWizard::new(WizardOrigin::Vault, &self.card.records, self.yk_network());
        self.card.wizard = Some(wizard);
        self.set_screen(Screen::YubiKey);
    }

    /// Called by `set_screen` before the screen changes: leaving the wizard (or the new-wallet
    /// intro) or the re-slot flow by any path — another screen, a settings section, the main
    /// window, not only `취소`/`완료` — ends it and the key worker wipes the held 64-byte seed
    /// (`YkJob::Discard`). A running card job keeps its flow until it ends; a confirmation
    /// overlay is not leaving.
    pub(crate) fn yk_leaving(&mut self, next: &Screen) {
        if matches!(next, Screen::Confirm(_)) || *next == self.screen {
            return;
        }
        let wizard_screen = matches!(
            next,
            Screen::YubiKey | Screen::YubiKeyWalletIntro | Screen::Processing(_)
        );
        let wizard_idle = self
            .card
            .wizard
            .as_ref()
            .is_some_and(|wizard| wizard.step != WizardStep::Running);
        let intro_words = self.card.wizard.is_none() && self.screen == Screen::YubiKeyWalletIntro;
        if !wizard_screen && (wizard_idle || intro_words) {
            let new_wallet =
                self.card.wizard.as_ref().is_none_or(|wizard| {
                    wizard.origin == WizardOrigin::NewWallet && !wizard.created
                });
            self.card.wizard = None;
            self.key(KeyJob::YubiKey(YkJob::Discard));
            if new_wallet {
                self.yk_words_dropped();
            }
        }
        let reslot_idle = matches!(
            self.card.manage.as_ref(),
            Some(manage @ manage::YkManage::Reslot(_)) if !manage.running()
        );
        if reslot_idle && *next != Screen::Settings(SettingsSection::YubiKey) {
            self.card.manage = None;
            self.key(KeyJob::YubiKey(YkJob::Discard));
        }
    }

    fn yk_wizard(&mut self) -> Option<&mut YkWizard> {
        self.card.wizard.as_mut()
    }

    /// A new `YubiKey` wallet's words were discarded: when they had been shown, S01's band says
    /// the paper belongs to no wallet (and that a card may hold keys made from it).
    pub(crate) fn yk_words_dropped(&mut self) {
        let words = core::mem::take(&mut self.yk_words);
        if words == YkWords::None {
            return;
        }
        let text = if words == YkWords::OnCard {
            format!("{T_YK_WORDS_UNUSED} {T_YK_WORDS_ON_CARD}")
        } else {
            T_YK_WORDS_UNUSED.to_owned()
        };
        if !self.banners.iter().any(|banner| banner.text == text) {
            self.notice(text, Tone::Warn);
        }
    }

    /// The new `YubiKey` wallet's wizard before its wallet exists (its words were shown on W08):
    /// `취소` asks first ([`Confirm::YkAbandon`]).
    fn yk_abandon_asks(&self) -> bool {
        self.card.wizard.as_ref().is_some_and(|wizard| {
            wizard.origin == WizardOrigin::NewWallet
                && !wizard.created
                && wizard.connect.is_none()
                && wizard.step != WizardStep::Running
        })
    }

    /// Ends the wizard: the key worker wipes the words (and a new wallet's password).
    pub fn yk_close_wizard(&mut self) {
        let wizard = self.card.wizard.take();
        self.key(KeyJob::YubiKey(YkJob::Discard));
        let back = match wizard {
            Some(wizard) if wizard.origin == WizardOrigin::NewWallet && !wizard.created => {
                self.yk_words_dropped();
                Screen::FirstRun
            }
            Some(wizard) if wizard.created => {
                // A new YubiKey wallet ends on S08 like the other first-run paths: the RPC step
                // and the Chrome extension link (spec/04 §2.19).
                let serial = wizard
                    .enrolled
                    .as_ref()
                    .map_or(0, |enrolled| enrolled.record.serial);
                self.done_yubikey = Some(if wizard.connect.is_some() {
                    YkDone::Connected(serial)
                } else {
                    YkDone::Created(serial)
                });
                self.done_imported = false;
                self.keys.done_start = false;
                Screen::Done
            }
            _ => Screen::Settings(SettingsSection::YubiKey),
        };
        if back == Screen::Done && self.meta.is_none() {
            self.request_meta();
        }
        self.set_screen(back);
    }

    /// (a) `다음`: the plan, then W05 (or straight to the preview when the words are held).
    pub fn yk_plan_next(&mut self) {
        let records = self.card.records.clone();
        let network = self.yk_network();
        let Some(wizard) = self.yk_wizard() else {
            return;
        };
        match wizard.plan(&records, network) {
            Err(text) => {
                wizard.error = Some(text);
                self.refresh();
            }
            Ok(slots) => {
                wizard.error = None;
                wizard.slots.clone_from(&slots);
                wizard.preview = None;
                wizard.same_ack = false;
                wizard.step = WizardStep::Confirm;
                wizard.card = None;
                wizard.card_error = None;
                // Which card (spec/10 §7.3): read-only, shown on the confirmation.
                self.key(KeyJob::YubiKey(YkJob::Identify));
                let Some(wizard) = self.card.wizard.as_mut() else {
                    return;
                };
                if wizard.seed_held {
                    self.key(KeyJob::YubiKey(YkJob::Preview {
                        mnemonic: None,
                        slots,
                    }));
                    self.refresh();
                } else {
                    self.refresh();
                    self.open_input(
                        SecretKind::Mnemonic,
                        Purpose::YubiKey(YkPurpose::Mnemonic),
                        false,
                    );
                }
            }
        }
    }

    fn yk_send_preview(
        &mut self,
        phrase: Zeroizing<Vec<u8>>,
        passphrase: Option<Zeroizing<Vec<u8>>>,
    ) {
        self.close_secret();
        let Some(wizard) = self.yk_wizard() else {
            return;
        };
        let slots = wizard.slots.clone();
        self.key(KeyJob::YubiKey(YkJob::Preview {
            mnemonic: Some((phrase, passphrase)),
            slots,
        }));
        self.refresh();
    }

    /// (d) `가져오기` (`adopt` = "가져오기 없이 등록"): the credentials windows, then the job. A
    /// key in a planned slot that the words do not derive is overwritten only after its
    /// checkbox and the typed `영구 삭제` (spec/10 §7.4).
    pub fn yk_import(&mut self, adopt: bool) {
        let Some(wizard) = self.card.wizard.as_mut() else {
            return;
        };
        if !wizard.can_continue() || wizard.card.is_none() {
            return;
        }
        if !adopt && !wizard.occupants().is_empty() {
            if !wizard.overwrite_ack {
                return;
            }
            if wizard.overwrite_typed.trim() != manage::LOSS_WORD {
                wizard.error = Some(format!(
                    "다른 키를 지우고 가져오려면 입력란에 '{}'를 정확히 입력하세요.",
                    manage::LOSS_WORD
                ));
                self.refresh();
                return;
            }
        }
        wizard.error = None;
        wizard.adopt = adopt;
        wizard.admin_pin = None;
        let (pgp, piv) = wizard.applets();
        let protected = piv && wizard.management_protected();
        let custom_key = piv && !protected && !wizard.default_management;
        let counters = wizard.card.map(|card| card.counters);
        if adopt {
            self.yk_run(Zeroizing::new(Vec::new()), Zeroizing::new(Vec::new()), None);
        } else if pgp {
            self.open_input(
                SecretKind::CardSecret(CardSecretKind::AdminPin),
                Purpose::YubiKey(YkPurpose::AdminPin),
                false,
            );
            if let Some(counters) = counters {
                self.yk_show_counters(YkPurpose::AdminPin, counters);
            }
        } else {
            self.yk_piv_credentials(Zeroizing::new(Vec::new()), protected, custom_key, piv);
        }
    }

    /// After the admin PIN (or without `OpenPGP` slots): the PIV PIN window of a PIN-protected
    /// management key, the management key window, or the job with the factory key.
    fn yk_piv_credentials(
        &mut self,
        admin_pin: Zeroizing<Vec<u8>>,
        protected: bool,
        custom_key: bool,
        piv: bool,
    ) {
        if protected || custom_key {
            if let Some(wizard) = self.card.wizard.as_mut() {
                wizard.admin_pin = Some(admin_pin);
            }
            let (kind, purpose) = if protected {
                (CardSecretKind::PivPin, YkPurpose::PivPin)
            } else {
                (CardSecretKind::ManagementKey, YkPurpose::ManagementKey)
            };
            self.open_input(
                SecretKind::CardSecret(kind),
                Purpose::YubiKey(purpose),
                false,
            );
            if let Some(counters) = self
                .card
                .wizard
                .as_ref()
                .and_then(|wizard| wizard.card)
                .map(|card| card.counters)
            {
                self.yk_show_counters(purpose, counters);
            }
        } else {
            self.yk_run(admin_pin, Self::yk_factory_key(piv), None);
        }
    }

    fn yk_factory_key(piv: bool) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(if piv {
            yw_core::yubikey::piv::DEFAULT_MANAGEMENT_KEY.to_vec()
        } else {
            Vec::new()
        })
    }

    /// Hex text of W12 → key bytes.
    fn yk_key_bytes(text: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        if text.len() != 48 {
            return None;
        }
        let digit = |byte: u8| char::from(byte).to_digit(16);
        let mut key = Zeroizing::new(Vec::with_capacity(24));
        for pair in text.chunks_exact(2) {
            let high = pair.first().copied().and_then(digit)?;
            let low = pair.get(1).copied().and_then(digit)?;
            key.push(u8::try_from(high.saturating_mul(16).saturating_add(low)).ok()?);
        }
        Some(key)
    }

    /// Queues the enrolment with the credentials (moved into the job).
    fn yk_run(
        &mut self,
        admin_pin: Zeroizing<Vec<u8>>,
        management_key: Zeroizing<Vec<u8>>,
        piv_pin: Option<Zeroizing<Vec<u8>>>,
    ) {
        self.close_secret();
        let Some(serial) = self
            .card
            .wizard
            .as_ref()
            .and_then(|wizard| wizard.card)
            .map(|card| card.serial)
        else {
            return;
        };
        let admin_last_try = self.yk_take_last_try(serial);
        let Some(wizard) = self.card.wizard.as_mut() else {
            return;
        };
        wizard.step = WizardStep::Running;
        wizard.failure = None;
        // A new wallet's card may now hold keys from the words shown (S01's band if dropped).
        let writes_new_words = wizard.origin == WizardOrigin::NewWallet
            && !wizard.created
            && !wizard.adopt
            && wizard.connect.is_none();
        // The keys shown at step (d) were confirmed for destruction (checked in `yk_import`).
        let overwrite = !wizard.adopt
            && wizard.overwrite_ack
            && wizard.overwrite_typed.trim() == manage::LOSS_WORD;
        let job = YkJob::Enrol {
            serial,
            slots: wizard.slots.clone(),
            admin_pin,
            management_key,
            piv_pin: piv_pin.unwrap_or_default(),
            adopt: wizard.adopt,
            admin_last_try,
            overwrite,
        };
        if writes_new_words {
            self.yk_words = YkWords::OnCard;
        }
        self.card.enrol = Some(crate::app_card::EnrolState::Running);
        logging::info("app", "yubikey.enrol_start", &[]);
        self.key(KeyJob::YubiKey(job));
        self.refresh();
    }

    /// A W12/W05/W06/W01/W10 submission of the `YubiKey` flows.
    #[expect(clippy::too_many_lines, reason = "one arm per secret window")]
    pub(crate) fn yk_submit(
        &mut self,
        purpose: YkPurpose,
        values: Vec<Zeroizing<Vec<u8>>>,
        checkbox: bool,
    ) {
        if purpose.is_manage() {
            self.yk_manage_submit(purpose, values, checkbox);
            return;
        }
        let mut values = values.into_iter();
        let mut next = || values.next().unwrap_or_default();
        match purpose {
            YkPurpose::Mnemonic => {
                let phrase = next();
                if checkbox {
                    if let Some(wizard) = self.card.wizard.as_mut() {
                        wizard.phrase = Some(phrase);
                    }
                    self.open_input(
                        SecretKind::Passphrase { confirm: true },
                        Purpose::YubiKey(YkPurpose::Passphrase),
                        false,
                    );
                } else {
                    self.yk_send_preview(phrase, None);
                }
            }
            YkPurpose::Passphrase => {
                let passphrase = next();
                let phrase = self
                    .card
                    .wizard
                    .as_mut()
                    .and_then(|wizard| wizard.phrase.take());
                match phrase {
                    Some(phrase) => self.yk_send_preview(phrase, Some(passphrase)),
                    None => self.close_secret(),
                }
            }
            YkPurpose::NewPassword => {
                let password = next();
                self.close_secret();
                self.set_screen(Screen::Processing("새 복구 단어를 만드는 중…"));
                self.key(KeyJob::YubiKey(YkJob::Generate { password }));
            }
            YkPurpose::Backup => {
                let words = [next(), next(), next(), next()];
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::YubiKey(YkJob::ConfirmWords { words }));
            }
            YkPurpose::AdminPin => {
                let pin = next();
                let (piv, protected, custom) =
                    self.card
                        .wizard
                        .as_ref()
                        .map_or((false, false, false), |wizard| {
                            let piv = wizard.applets().1;
                            let protected = piv && wizard.management_protected();
                            (
                                piv,
                                protected,
                                piv && !protected && !wizard.default_management,
                            )
                        });
                self.yk_piv_credentials(pin, protected, custom, piv);
            }
            YkPurpose::PivPin => {
                let pin = next();
                let admin = self
                    .card
                    .wizard
                    .as_mut()
                    .and_then(|wizard| wizard.admin_pin.take())
                    .unwrap_or_default();
                self.yk_run(admin, Zeroizing::new(Vec::new()), Some(pin));
            }
            YkPurpose::ProtectManagement => {
                let pin = next();
                self.yk_pin_job(|serial| YkJob::ProtectManagementKey { serial, pin });
            }
            YkPurpose::SetPins => {
                let current = next();
                let new = next();
                // Both guarded last tries (admin PIN, PUK) go with the job; the consents stay
                // until a job runs past the guards (`on_yk_pins_set`), so confirming one does
                // not lose the other.
                let last_tries = self.yk_pin_serial().map_or_else(
                    crate::yubikey::LastTries::default,
                    |serial| crate::yubikey::LastTries {
                        admin: self.card.admin_last_try == Some(serial),
                        puk: self.card.puk_last_try == Some(serial),
                    },
                );
                self.yk_pin_job(|serial| YkJob::SetPins {
                    serial,
                    current,
                    new,
                    last_tries,
                });
            }
            YkPurpose::ManagementKey => {
                let text = next();
                let Some(key) = Self::yk_key_bytes(&text) else {
                    self.with_form(|form| {
                        form.set_error(Some("관리 키는 16진수 48자리입니다.".to_owned()));
                    });
                    return;
                };
                let pin = self
                    .card
                    .wizard
                    .as_mut()
                    .and_then(|wizard| wizard.admin_pin.take())
                    .unwrap_or_default();
                self.yk_run(pin, key, None);
            }
            YkPurpose::ChangePin(target) => {
                let old = next();
                let new = next();
                let Some(serial) = self.yk_pin_serial() else {
                    self.close_secret();
                    return;
                };
                let last_try = match target {
                    PinTarget::OpenPgpAdmin => self.yk_take_last_try(serial),
                    PinTarget::PivPuk => self.yk_take_puk_last_try(serial),
                    PinTarget::OpenPgpUser | PinTarget::PivPin => false,
                };
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::YubiKey(YkJob::ChangePin {
                    serial,
                    target,
                    old,
                    new,
                    last_try,
                }));
            }
            YkPurpose::ConnectPassword => self.yk_connect_password(next()),
            YkPurpose::ConnectPin => self.yk_connect_pin_submit(next()),
            YkPurpose::ShowWords
            | YkPurpose::ReslotMnemonic
            | YkPurpose::ReslotPassphrase
            | YkPurpose::ReslotAdminPin
            | YkPurpose::ClearAdminPin
            | YkPurpose::ClearPivPin => {}
        }
    }

    /// A `YubiKey` secret window was cancelled or closed.
    pub(crate) fn yk_cancel(&mut self, purpose: YkPurpose) {
        match purpose {
            YkPurpose::NewPassword | YkPurpose::ShowWords | YkPurpose::Backup => {
                // The new wallet is abandoned: the worker wipes the words and the password; S01
                // says the paper of words already shown belongs to no wallet.
                self.key(KeyJob::YubiKey(YkJob::Discard));
                self.card.wizard = None;
                self.yk_words_dropped();
                self.set_screen(Screen::FirstRun);
            }
            YkPurpose::Mnemonic | YkPurpose::Passphrase => {
                if let Some(wizard) = self.card.wizard.as_mut() {
                    wizard.phrase = None;
                    if !wizard.seed_held {
                        wizard.step = WizardStep::Plan;
                    }
                }
                self.refresh();
            }
            YkPurpose::AdminPin | YkPurpose::ManagementKey | YkPurpose::PivPin => {
                if let Some(wizard) = self.card.wizard.as_mut() {
                    wizard.admin_pin = None;
                }
                self.refresh();
            }
            YkPurpose::ChangePin(_)
            | YkPurpose::ProtectManagement
            | YkPurpose::SetPins
            | YkPurpose::ConnectPin => {
                self.refresh();
            }
            YkPurpose::ConnectPassword => {
                self.card.wizard = None;
                self.set_screen(Screen::FirstRun);
            }
            YkPurpose::ReslotMnemonic
            | YkPurpose::ReslotPassphrase
            | YkPurpose::ReslotAdminPin
            | YkPurpose::ClearAdminPin
            | YkPurpose::ClearPivPin => self.yk_manage_cancel(purpose),
        }
    }

    /// W08 `다 적었습니다` held: the W10 challenge.
    pub(crate) fn yk_hold_complete(&mut self, purpose: YkPurpose) {
        self.close_secret();
        if purpose == YkPurpose::ShowWords {
            if self.yk_words == YkWords::None {
                self.yk_words = YkWords::Shown;
            }
            self.key(KeyJob::YubiKey(YkJob::Challenge));
        }
        self.refresh();
    }

    fn yk_result_serial(&self) -> Option<u32> {
        self.card
            .wizard
            .as_ref()
            .and_then(|wizard| wizard.enrolled.as_ref())
            .map(|enrolled| enrolled.record.serial)
    }

    /// The card of the "PIN 설정" actions: the wizard's result card while the wizard is open,
    /// otherwise the `YubiKey` list row opened with `PIN 설정`.
    fn yk_pin_serial(&self) -> Option<u32> {
        if self.card.wizard.is_some() {
            self.yk_result_serial()
        } else {
            self.card.pin_serial
        }
    }

    /// The flags of the "PIN 설정" card of `serial` (the wizard's when it shows that card, else
    /// what a card action of this session saw).
    #[must_use]
    pub fn yk_pin_defaults(&self, serial: u32) -> DefaultsSeen {
        self.card
            .wizard
            .as_ref()
            .filter(|_| self.yk_result_serial() == Some(serial))
            .map(|wizard| wizard.defaults)
            .or_else(|| self.card.seen_defaults(serial))
            .unwrap_or_default()
    }

    /// Queues a "PIN 설정" card job for the action's card (the window waits, busy).
    fn yk_pin_job(&mut self, job: impl FnOnce(u32) -> YkJob) {
        let Some(serial) = self.yk_pin_serial() else {
            self.close_secret();
            return;
        };
        self.with_form(|form| form.set_busy(true));
        self.key(KeyJob::YubiKey(job(serial)));
    }

    /// The PIN window of a "PIN 설정" action (the tries left are read meanwhile and shown before
    /// the PIN is entered, spec/10 §9.1).
    fn yk_open_pin_action(&mut self, kind: CardSecretKind, purpose: YkPurpose) {
        if let Some(serial) = self.yk_pin_serial() {
            self.yk_open_card_secret(kind, purpose, serial);
        }
    }

    /// Opens W12 for card `serial` and reads its PIN counters for the window.
    pub(crate) fn yk_open_card_secret(
        &mut self,
        kind: CardSecretKind,
        purpose: YkPurpose,
        serial: u32,
    ) {
        self.open_input(
            SecretKind::CardSecret(kind),
            Purpose::YubiKey(purpose),
            false,
        );
        if self.secret_purpose() == Some(Purpose::YubiKey(purpose)) {
            self.key(KeyJob::YubiKey(YkJob::Counters(CounterTarget::Card(
                serial,
            ))));
        }
    }

    /// The PIN counters a W12 purpose shows.
    const fn yk_counter_kinds(purpose: YkPurpose) -> &'static [PinKind] {
        match purpose {
            YkPurpose::AdminPin
            | YkPurpose::ReslotAdminPin
            | YkPurpose::ClearAdminPin
            | YkPurpose::ChangePin(PinTarget::OpenPgpAdmin) => &[PinKind::OpenPgpAdmin],
            YkPurpose::ChangePin(PinTarget::OpenPgpUser) => &[PinKind::OpenPgpUser],
            YkPurpose::PivPin
            | YkPurpose::ProtectManagement
            | YkPurpose::ClearPivPin
            | YkPurpose::ChangePin(PinTarget::PivPin) => &[PinKind::PivPin],
            YkPurpose::ChangePin(PinTarget::PivPuk) => &[PinKind::PivPuk],
            YkPurpose::SetPins => &[
                PinKind::PivPin,
                PinKind::PivPuk,
                PinKind::OpenPgpAdmin,
                PinKind::OpenPgpUser,
            ],
            YkPurpose::ConnectPin => &[PinKind::OpenPgpUser, PinKind::PivPin],
            YkPurpose::ConnectPassword
            | YkPurpose::Mnemonic
            | YkPurpose::Passphrase
            | YkPurpose::NewPassword
            | YkPurpose::ShowWords
            | YkPurpose::Backup
            | YkPurpose::ManagementKey
            | YkPurpose::ReslotMnemonic
            | YkPurpose::ReslotPassphrase => &[],
        }
    }

    /// Shows the tries left in the open W12 of `purpose` (before the PIN is entered).
    pub(crate) fn yk_show_counters(&mut self, purpose: YkPurpose, counters: PinCounters) {
        if self.secret_purpose() != Some(Purpose::YubiKey(purpose)) {
            return;
        }
        let lines = counters.lines(Self::yk_counter_kinds(purpose));
        if !lines.is_empty() {
            self.with_form(|form| form.set_details(lines));
        }
    }

    /// `Counters` finished: the open W11 or W12 shows the tries left.
    fn on_yk_counters(&mut self, target: CounterTarget, result: Result<PinCounters, CardJobError>) {
        // The card step's read is kept even when it failed: W11 says before the PIN what it
        // found instead (no card, a busy card, another card; 2026-11-10).
        if let CounterTarget::Key(role) = target {
            self.card_counters(role, result);
            return;
        }
        let Ok(counters) = result else {
            return;
        };
        match target {
            CounterTarget::Key(_) => {}
            CounterTarget::Card(serial) => {
                if counters.serial != serial {
                    return;
                }
                if let Some(Purpose::YubiKey(purpose)) = self.secret_purpose() {
                    self.yk_show_counters(purpose, counters);
                }
            }
        }
    }

    /// The consent to spend the `OpenPGP` admin PIN's last try on card `serial` (given by
    /// seeing [`yw_core::yubikey::CardError::AdminLastTry`] and submitting again), used once.
    pub(crate) fn yk_take_last_try(&mut self, serial: u32) -> bool {
        if self.card.admin_last_try == Some(serial) {
            self.card.admin_last_try = None;
            true
        } else {
            false
        }
    }

    /// The consent to spend the PIV PUK's last try on card `serial` (given by seeing
    /// [`yw_core::yubikey::CardError::PukLastTry`] and submitting again), used once.
    pub(crate) fn yk_take_puk_last_try(&mut self, serial: u32) -> bool {
        if self.card.puk_last_try == Some(serial) {
            self.card.puk_last_try = None;
            true
        } else {
            false
        }
    }

    /// A card job of card `serial` was refused for the last try of the admin PIN or the PUK:
    /// the next submission for that card sends it (spec/10 §9.1).
    pub(crate) fn yk_note_last_try(&mut self, serial: u32, error: CardJobError) {
        if error.is_admin_last_try() {
            self.card.admin_last_try = Some(serial);
        }
        if error.is_puk_last_try() {
            self.card.puk_last_try = Some(serial);
        }
    }

    /// Enters step (d): identifies the one inserted card again (it may have been swapped), then
    /// reads its management key state when the plan has PIV (`on_yk_identified`).
    fn yk_enter_credentials(&mut self) {
        let Some(wizard) = self.yk_wizard() else {
            return;
        };
        wizard.step = WizardStep::Credentials;
        wizard.failure = None;
        wizard.error = None;
        wizard.management = None;
        wizard.card = None;
        wizard.card_error = None;
        wizard.reset_occupied();
        self.key(KeyJob::YubiKey(YkJob::Identify));
    }

    /// `Identify` finished: the card the wizard enrols (or why there is none). At step (d) the
    /// card's management key state and the keys already in the planned slots are read next
    /// (read-only).
    fn on_yk_identified(&mut self, result: Result<crate::yubikey::CardFacts, CardJobError>) {
        let Some(wizard) = self.card.wizard.as_mut() else {
            return;
        };
        if !matches!(wizard.step, WizardStep::Confirm | WizardStep::Credentials) {
            return;
        }
        match result {
            Ok(facts) => {
                wizard.card = Some(facts);
                wizard.card_error = None;
                if wizard.step == WizardStep::Credentials {
                    let slots = wizard.slots.clone();
                    let piv = wizard.applets().1;
                    if piv {
                        self.key(KeyJob::YubiKey(YkJob::ProbeManagement {
                            serial: facts.serial,
                        }));
                    }
                    self.key(KeyJob::YubiKey(YkJob::Occupied {
                        serial: facts.serial,
                        slots,
                    }));
                }
            }
            Err(error) => {
                wizard.card = None;
                wizard.card_error = Some(error.to_string());
            }
        }
        self.refresh();
    }

    /// `Occupied` finished: the keys an import would destroy, shown before `가져오기`.
    fn on_yk_occupied(
        &mut self,
        serial: u32,
        result: Result<Vec<yw_core::yubikey::enrol::Occupant>, CardJobError>,
    ) {
        let Some(wizard) = self.card.wizard.as_mut() else {
            return;
        };
        if wizard.step != WizardStep::Credentials
            || wizard.card.map(|card| card.serial) != Some(serial)
        {
            return;
        }
        if let Err(error) = &result {
            crate::logging::info("app", "yubikey.occupied_failed", &error.log_fields());
        }
        wizard.occupied = Some(result.map_err(|error| error.to_string()));
        self.refresh();
    }

    /// A new `YubiKey` wallet's result card still needs its PIN setup (spec/10 §9.3: `완료` and
    /// `다른 YubiKey 등록` wait for it).
    #[must_use]
    pub fn yk_pins_first(&self) -> bool {
        // A card connected without recovery words already has its PINs (factory PINs are
        // still refused at signing, spec/10 §9.2).
        self.card.wizard.as_ref().is_some_and(|wizard| {
            wizard.step == WizardStep::Result
                && wizard.enrolled.is_some()
                && wizard.created
                && wizard.connect.is_none()
                && !wizard.pins_done()
        })
    }

    /// Card `serial` is still on its factory PINs as the wallet knows it (`hw_accounts.defaults`,
    /// or the new wallet's card waiting for its meta): it does not sign (spec/10 §9.3).
    #[must_use]
    pub fn yk_card_on_defaults(&self, serial: u32) -> bool {
        self.card.pending_default_is(serial)
            || self
                .meta
                .as_ref()
                .is_some_and(|meta| meta.hw_accounts.defaults.contains(&serial))
    }

    /// `나중에` of [`Confirm::YkPinLater`]: the result screen ends as `완료` would.
    pub(crate) fn yk_pin_later(&mut self) {
        if matches!(
            self.card.manage,
            Some(crate::app_yubikey::manage::YkManage::Reslot(_))
        ) {
            self.yk_manage_close();
        } else {
            self.yk_close_wizard();
        }
    }

    /// `다시 읽기` of the confirmation / credentials card line.
    pub fn yk_identify_again(&mut self) {
        let Some(wizard) = self.yk_wizard() else {
            return;
        };
        let step = wizard.step;
        wizard.card = None;
        wizard.card_error = None;
        wizard.management = None;
        wizard.reset_occupied();
        if matches!(step, WizardStep::Confirm | WizardStep::Credentials) {
            self.key(KeyJob::YubiKey(YkJob::Identify));
        }
        self.refresh();
    }

    fn on_yk_management(&mut self, result: Result<ManagementState, CardJobError>) {
        if let (Some(wizard), Ok(state)) = (self.card.wizard.as_mut(), result) {
            wizard.management = Some(state);
            if !state.protected {
                wizard.default_management = state.default;
            }
        }
        self.refresh();
    }

    fn on_yk_protected(&mut self, serial: u32, result: Result<(), CardJobError>) {
        match result {
            Ok(()) => {
                self.close_secret();
                if !self.card.list_protected.contains(&serial) {
                    self.card.list_protected.push(serial);
                }
                if let Some(wizard) = self.card.wizard.as_mut() {
                    wizard.defaults.piv_management = false;
                    wizard.defaults.piv_management_protected = true;
                }
                self.yk_note(
                    "PIV 관리 키를 새로 만들어 PIN으로 보호했습니다. 관리 키는 입력할 필요가 없습니다(다음 등록에는 PIV PIN만 묻습니다)."
                        .to_owned(),
                );
                self.yk_defaults_done(serial);
            }
            Err(error) => {
                let text = error.text_for_in(
                    PinKind::PivPin,
                    &crate::yubikey::PinContext::of(&self.card.records, serial, PinKind::PivPin),
                );
                self.with_form(|form| {
                    form.set_busy(false);
                    form.set_error(Some(text));
                });
            }
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the report's done, skipped and failed parts in order"
    )]
    fn on_yk_pins_set(
        &mut self,
        serial: u32,
        result: Result<crate::yubikey::PinReport, CardJobError>,
    ) {
        use core::fmt::Write as _;

        use crate::yubikey::DefaultsStep;
        use yw_core::yubikey::CardError;
        // The guards of the last tries refuse before anything is sent: the consents of this
        // card stay (and the refused one is added). Any other result used or did not need them.
        let guarded = matches!(
            &result,
            Ok(report) if report.done.is_empty()
                && matches!(
                    report.failed,
                    Some((_, CardError::AdminLastTry | CardError::PukLastTry))
                )
        );
        if !guarded {
            self.card.admin_last_try = self.card.admin_last_try.filter(|other| *other != serial);
            self.card.puk_last_try = self.card.puk_last_try.filter(|other| *other != serial);
        }
        let report = match result {
            Ok(report) if !report.done.is_empty() || report.failed.is_none() => report,
            Ok(report) => {
                // The first step failed: nothing changed; the window stays for another try.
                if let Some((_, error)) = report.failed {
                    self.yk_note_last_try(serial, CardJobError::Card(error));
                }
                let records = &self.card.records;
                let text = report
                    .failed
                    .map(|(step, error)| {
                        step.kind().error_text_in(
                            error,
                            &crate::yubikey::PinContext::of(records, serial, step.kind()),
                        )
                    })
                    .unwrap_or_default();
                self.with_form(|form| {
                    form.set_busy(false);
                    form.set_error(Some(format!("바꾼 것 없음. {text}")));
                });
                return;
            }
            Err(error) => {
                self.with_form(|form| {
                    form.set_busy(false);
                    form.set_error(Some(error.to_string()));
                });
                return;
            }
        };
        self.close_secret();
        let names = |steps: &[DefaultsStep]| {
            steps
                .iter()
                .map(|step| step.name())
                .collect::<Vec<_>>()
                .join(", ")
        };
        let mut text = format!("바꾼 것: {}.", names(&report.done));
        if !report.skipped.is_empty() {
            let _ = write!(text, " 건너뜀: {}.", names(&report.skipped));
        }
        if let Some((step, error)) = report.failed {
            let _ = write!(
                text,
                " 실패: {} — {} 그 뒤 항목은 바꾸지 않았습니다.",
                step.name(),
                step.kind().error_text_in(
                    error,
                    &crate::yubikey::PinContext::of(&self.card.records, serial, step.kind())
                )
            );
        } else {
            text.push_str(" 새 PIN은 이 지갑에 저장하지 않으니 따로 기억해 두세요.");
        }
        let has = |step| report.done.contains(&step) || report.skipped.contains(&step);
        if let Some(wizard) = self.card.wizard.as_mut() {
            if has(DefaultsStep::PivPin) && has(DefaultsStep::PivPuk) {
                wizard.defaults.piv_pin = false;
            }
            if has(DefaultsStep::PivManagement) {
                wizard.defaults.piv_management = false;
                wizard.defaults.piv_management_protected = true;
            }
            if has(DefaultsStep::OpenPgpAdmin) && has(DefaultsStep::OpenPgpUser) {
                wizard.defaults.openpgp_admin = false;
            }
            if report.failed.is_none()
                && wizard
                    .enrolled
                    .as_ref()
                    .is_some_and(|enrolled| enrolled.record.serial == serial)
            {
                wizard.pins_set = true;
            }
        }
        self.yk_note(text);
        if report.failed.is_none() {
            self.card.pin_needed = self.card.pin_needed.filter(|other| *other != serial);
            self.card
                .list_defaults
                .retain(|(other, _)| *other != serial);
        }
        if report.failed.is_none()
            && let Some(meta) = self.meta.as_mut()
            && meta.hw_accounts.defaults.contains(&serial)
        {
            meta.hw_accounts.defaults.retain(|other| *other != serial);
            self.save_meta();
        }
        self.refresh();
    }

    // ----- the new YubiKey wallet ------------------------------------------------------------

    /// S01 `YubiKey 지갑 만들기`.
    pub fn yk_new_wallet(&mut self) {
        if self.mode != AppMode::NoVault || self.leftover {
            return;
        }
        self.key(KeyJob::YubiKey(YkJob::Discard));
        self.card.wizard = None;
        self.set_screen(Screen::YubiKeyWalletIntro);
    }

    /// S20 `시작하기`: W01.
    pub fn yk_new_wallet_start(&mut self) {
        self.open_input(
            SecretKind::SetPassword,
            Purpose::YubiKey(YkPurpose::NewPassword),
            false,
        );
    }

    // ----- key worker results ----------------------------------------------------------------

    /// A wizard job finished.
    pub(crate) fn on_yk_outcome(&mut self, outcome: YkOutcome) {
        match outcome {
            YkOutcome::Preview(result) => self.on_yk_preview(result),
            YkOutcome::Words(Ok((phrase, address))) => {
                self.set_screen(Screen::YubiKeyWalletIntro);
                self.open_display(
                    SecretKind::ShowMnemonic { create: true },
                    Purpose::YubiKey(YkPurpose::ShowWords),
                    DisplaySecret {
                        text: phrase,
                        address: Some(address.to_checksum()),
                        passphrase_note: false,
                        copy_allowed: self.settings.allow_secret_copy,
                    },
                );
                if self.secret_purpose() == Some(Purpose::YubiKey(YkPurpose::ShowWords))
                    && self.yk_words == YkWords::None
                {
                    self.yk_words = YkWords::Shown;
                }
            }
            YkOutcome::Words(Err(error)) => {
                self.banner(None, failure_text(error));
                self.set_screen(Screen::YubiKeyWalletIntro);
            }
            YkOutcome::Challenge(Ok(positions)) => {
                if self.secret_purpose() == Some(Purpose::YubiKey(YkPurpose::Backup)) {
                    self.with_form(|form| {
                        form.reset_backup(
                            positions,
                            Some(crate::ui::screens::backup_retry_text(positions, false)),
                        );
                    });
                } else {
                    self.open_input(
                        SecretKind::Backup { positions },
                        Purpose::YubiKey(YkPurpose::Backup),
                        false,
                    );
                }
            }
            YkOutcome::Challenge(Err(error)) | YkOutcome::WordsConfirmed(Err(error)) => {
                self.close_secret();
                self.banner(None, failure_text(error));
                self.refresh();
            }
            YkOutcome::WordsConfirmed(Ok(true)) => {
                self.close_secret();
                if self.yk_words == YkWords::None {
                    self.yk_words = YkWords::Shown;
                }
                let mut wizard = YkWizard::new(WizardOrigin::NewWallet, &[], self.yk_network());
                wizard.seed_held = true;
                self.card.wizard = Some(wizard);
                self.set_screen(Screen::YubiKey);
            }
            YkOutcome::WordsConfirmed(Ok(false)) => self.key(KeyJob::YubiKey(YkJob::Challenge)),
            YkOutcome::Checked(serial, result) => self.on_yk_checked(serial, result),
            YkOutcome::PinChanged(serial, target, result) => {
                self.on_yk_pin_changed(serial, target, result);
            }
            YkOutcome::Occupied(serial, result) => self.on_yk_occupied(serial, result),
            YkOutcome::Identified(result) => self.on_yk_identified(result),
            YkOutcome::Counters(target, result) => self.on_yk_counters(target, result),
            YkOutcome::Management(result) => self.on_yk_management(result),
            YkOutcome::ManagementProtected(serial, result) => self.on_yk_protected(serial, result),
            YkOutcome::PinsSet(serial, result) => self.on_yk_pins_set(serial, result),
            YkOutcome::Removed(Ok(_)) => {
                self.close_secret();
                self.info = Some("YubiKey 기록을 지웠습니다.".to_owned());
                self.key(KeyJob::HardwareKeys);
                self.request_meta();
                self.refresh();
            }
            YkOutcome::Removed(Err(error)) => {
                self.password_failure(error, yw_win::time::monotonic_ms());
            }
            YkOutcome::RemoveBusy(_) => {
                // W03 shows why; nothing was removed.
                self.with_form(|form| {
                    form.set_busy(false);
                    form.set_error(Some(T_YK_BUSY.to_owned()));
                });
                self.refresh();
            }
            YkOutcome::Discarded => {}
            YkOutcome::Manage(outcome) => self.on_yk_manage(outcome),
            YkOutcome::Scanned(result) => self.on_yk_scanned(result),
            YkOutcome::ConnectVerified(result) => self.on_yk_connect_verified(result),
        }
    }

    fn yk_note(&mut self, text: String) {
        if let Some(wizard) = self.card.wizard.as_mut() {
            wizard.notes.push(text);
        } else {
            self.info = Some(text);
        }
        self.refresh();
    }

    fn on_yk_preview(&mut self, result: Result<YkPreview, YubiKeyJobError>) {
        match result {
            Ok(preview) => {
                if let Some(wizard) = self.card.wizard.as_mut() {
                    wizard.seed_held = true;
                    wizard.preview = Some(preview);
                    wizard.step = WizardStep::Confirm;
                }
                self.refresh();
            }
            Err(YubiKeyJobError::Key(error)) => {
                // Wrong words or passphrase: W05 again with the parser's reason.
                let code = crate::errors::key_code(error);
                let message = match error {
                    yw_core::error::KeyError::MnemonicUnknownWord { position } => {
                        code.render(&position.to_string())
                    }
                    _ => code.text(),
                };
                self.open_input(
                    SecretKind::Mnemonic,
                    Purpose::YubiKey(YkPurpose::Mnemonic),
                    false,
                );
                self.with_form(|form| form.set_error(Some(message)));
                self.refresh();
            }
            Err(error) => {
                if let Some(wizard) = self.card.wizard.as_mut() {
                    wizard.step = WizardStep::Plan;
                    wizard.error = Some(failure_text(error));
                }
                self.refresh();
            }
        }
    }

    /// The wizard's part of `on_yubikey_enrolled`.
    pub(crate) fn yk_enrolled(&mut self, result: &Result<(RecordId, Enrolled), YubiKeyJobError>) {
        let created = match (result, self.card.wizard.as_ref()) {
            (Ok(_), Some(wizard)) => wizard.origin == WizardOrigin::NewWallet && !wizard.created,
            _ => false,
        };
        if created {
            // The YubiKey wallet exists and is open (`create_with_hardware`): its words are now
            // that wallet's backup.
            self.yk_words = YkWords::None;
            self.set_mode(AppMode::Unlocked {
                alt_passphrase: false,
            });
            self.idle.input(yw_win::time::monotonic_ms());
            if let Ok((_, enrolled)) = result {
                let bitcoin = enrolled
                    .record
                    .slots
                    .iter()
                    .find_map(|slot| match slot.role {
                        KeyRole::Btc { network, .. }
                        | KeyRole::Evm {
                            btc: Some(BtcUse { network, .. }),
                            ..
                        } => Some(network),
                        _ => None,
                    });
                if let Some(network) = bitcoin
                    && !self.settings.bitcoin.enabled
                {
                    let mut settings = self.settings.clone();
                    settings.bitcoin.enabled = true;
                    settings.bitcoin.network = crate::btc::app_network(network);
                    self.save_settings(settings, "bitcoin.enabled");
                }
            }
        }
        if let (Err(YubiKeyJobError::Card(error)), Some(serial)) = (
            result,
            self.card
                .wizard
                .as_ref()
                .and_then(|wizard| wizard.card)
                .map(|card| card.serial),
        ) {
            self.yk_note_last_try(serial, *error);
        }
        // The user left the wizard while the card worked (`yk_leaving` keeps a running flow): the
        // flow ends now and the key worker wipes the held words (and a connect password); the
        // result is shown as a banner by `on_yubikey_enrolled` (spec/10 §7.1 "떠나면 지움").
        let away = !matches!(
            self.screen,
            Screen::YubiKey
                | Screen::YubiKeyWalletIntro
                | Screen::Processing(_)
                | Screen::Confirm(_)
        );
        if away && self.card.wizard.is_some() {
            self.card.wizard = None;
            self.key(KeyJob::YubiKey(YkJob::Discard));
            self.yk_words_dropped();
            return;
        }
        let Some(wizard) = self.card.wizard.as_mut() else {
            return;
        };
        match result {
            Ok((_, enrolled)) => {
                wizard.created |= created;
                if created {
                    wizard.origin = WizardOrigin::Vault;
                }
                wizard.defaults = enrolled.defaults;
                wizard.enrolled = Some(enrolled.clone());
                wizard.failure = None;
                wizard.check = None;
                wizard.changed.clear();
                wizard.pins_set = false;
                wizard.notes.clear();
            }
            Err(error) => {
                wizard.failure = Some(if wizard.adopt {
                    failure_text(*error)
                } else {
                    enrol_failure_text(*error, wizard.applets().0)
                });
                wizard.enrolled = None;
            }
        }
        wizard.step = WizardStep::Result;
    }

    fn on_yk_checked(
        &mut self,
        serial: u32,
        result: Result<Vec<Result<(), yw_core::yubikey::CardError>>, CardJobError>,
    ) {
        let record = self
            .card
            .records
            .iter()
            .find(|record| record.serial == serial)
            .cloned();
        let lines = match (result, record) {
            (Ok(results), Some(record)) => record
                .slots
                .iter()
                .zip(results)
                .map(|(slot, result)| match result {
                    Ok(()) => format!("{} — 공개키가 기록과 같습니다 ✓", slot.slot.label()),
                    Err(error) => format!("{} — {error}", slot.slot.label()),
                })
                .collect(),
            (Ok(_), None) => vec!["이 YubiKey의 기록을 찾지 못했습니다.".to_owned()],
            (Err(error), _) => vec![format!("확인하지 못했습니다: {error}")],
        };
        if let Some(wizard) = self.card.wizard.as_mut() {
            wizard.check = Some(lines);
        }
        self.refresh();
    }

    fn on_yk_pin_changed(
        &mut self,
        serial: u32,
        target: PinTarget,
        result: Result<(), CardJobError>,
    ) {
        match result {
            Ok(()) => {
                self.close_secret();
                if !self.card.list_changed.contains(&(serial, target)) {
                    self.card.list_changed.push((serial, target));
                }
                if let Some(wizard) = self.card.wizard.as_mut() {
                    if !wizard.changed.contains(&target) {
                        wizard.changed.push(target);
                    }
                    let both = |a: PinTarget, b: PinTarget| {
                        wizard.changed.contains(&a) && wizard.changed.contains(&b)
                    };
                    if both(PinTarget::OpenPgpUser, PinTarget::OpenPgpAdmin) {
                        wizard.defaults.openpgp_admin = false;
                    }
                    if both(PinTarget::PivPin, PinTarget::PivPuk) {
                        wizard.defaults.piv_pin = false;
                    }
                }
                self.yk_note(format!("{}을(를) 바꿨습니다.", target.name()));
                self.yk_defaults_done(serial);
            }
            Err(error) => {
                // A wrong value's text names the secret and carries the tries left (one left:
                // "한 번 더 틀리면 잠깁니다", spec/10 §9.1).
                let text = error.text_for_in(
                    target.kind(),
                    &crate::yubikey::PinContext::of(&self.card.records, serial, target.kind()),
                );
                self.yk_note_last_try(serial, error);
                self.with_form(|form| {
                    form.set_busy(false);
                    form.set_error(Some(text));
                });
            }
        }
    }

    /// Every default of card `serial` was changed: its "기본 PIN 사용 중" note goes.
    fn yk_defaults_done(&mut self, serial: u32) {
        let done = match self.card.wizard.as_ref() {
            Some(wizard) => {
                !wizard.defaults.openpgp_admin
                    && !wizard.defaults.piv_pin
                    && !wizard.defaults.piv_management
            }
            // The `YubiKey` list ("하나씩 따로" outside the wizard): every secret of the card's
            // applets was changed in this session (and the management key protected).
            None => self.card.list_pins_done(serial),
        };
        if done {
            self.card.forget_pending_default(serial);
            self.card.pin_needed = self.card.pin_needed.filter(|other| *other != serial);
            self.card
                .list_defaults
                .retain(|(other, _)| *other != serial);
        }
        if done
            && let Some(meta) = self.meta.as_mut()
            && meta.hw_accounts.defaults.contains(&serial)
        {
            meta.hw_accounts.defaults.retain(|other| *other != serial);
            self.save_meta();
        }
        self.refresh();
    }

    // ----- removal ---------------------------------------------------------------------------

    /// `삭제` of an enrolled card (the list row `row`): the confirmation overlay.
    pub fn yk_remove(&mut self, row: usize) {
        if !matches!(self.mode, AppMode::Unlocked { .. }) || !self.yk_can_remove() {
            return;
        }
        if let Some(id) = self.card.record_ids.get(row).copied() {
            self.card.remove_target = Some(id);
            self.set_screen(Screen::Confirm(Confirm::RemoveYubiKey));
        }
    }

    /// A record may be removed (a wallet without recovery words keeps its last key).
    #[must_use]
    pub fn yk_can_remove(&self) -> bool {
        self.keys.has_mnemonic || self.imported_count() > 0 || self.card.records.len() > 1
    }

    /// Overlay `계속`: W03.
    pub(crate) fn yk_remove_confirmed(&mut self) {
        let previous = self.previous_screen.clone();
        self.set_screen(previous);
        if let Some(id) = self.card.remove_target.take() {
            self.open_input(
                SecretKind::ConfirmPassword,
                Purpose::ConfirmPassword(PasswordAction::RemoveHardwareKey(id)),
                false,
            );
        }
    }

    // ----- commands --------------------------------------------------------------------------

    /// Main-window commands of the `YubiKey` screens; `false` when `id` is not one of them.
    #[expect(clippy::too_many_lines, reason = "one arm per wizard control")]
    pub fn on_yk_command(&mut self, id: u16) -> bool {
        use crate::ui::screens_yubikey::ids;
        if self.on_yk_manage_command(id) || self.on_yk_connect_command(id) {
            return true;
        }
        // The connect flow's result screen: `다시 시도` returns to its confirmation, `다른
        // YubiKey 등록(백업)` reads the next card.
        let connecting = self
            .card
            .wizard
            .as_ref()
            .is_some_and(|wizard| wizard.connect.is_some());
        if connecting && id == ids::RETRY {
            if let Some(wizard) = self.yk_wizard() {
                wizard.step = WizardStep::Confirm;
                wizard.failure = None;
            }
            self.refresh();
            return true;
        }
        if connecting && id == ids::ANOTHER && !self.yk_pins_first() {
            let origin = self
                .card
                .wizard
                .as_ref()
                .map_or(WizardOrigin::Vault, |wizard| wizard.origin);
            if origin == WizardOrigin::Vault && self.card.records.len() < MAX_CARDS {
                self.yk_open_connect();
            }
            return true;
        }
        if connecting && id == ids::CONFIRM_BACK {
            self.yk_connect_back();
            return true;
        }
        if let Some((key, action)) = ids::pgp_action(id) {
            if let Some(wizard) = self.yk_wizard() {
                let form = wizard.pgp_mut(key);
                match action {
                    ids::PgpAction::Kind(kind) => form.kind = kind,
                    ids::PgpAction::Script(script) => form.script = script,
                    ids::PgpAction::Touch(touch) => form.touch = touch,
                    ids::PgpAction::Zec(network) => form.zec = network,
                }
                wizard.error = None;
            }
            self.refresh();
            return true;
        }
        if let Some(row) = ids::remove_row(id) {
            self.yk_remove(row);
            return true;
        }
        if let Some(row) = ids::pins_row(id) {
            let serial = self.card.records.get(row).map(|record| record.serial);
            self.card.pin_serial = if self.card.pin_serial == serial {
                None
            } else {
                serial
            };
            self.refresh();
            return true;
        }
        if let Some(row) = ids::backup_row(id) {
            // Only a card with a known path can be copied (spec/10 §7.6).
            let serial = self
                .card
                .records
                .get(row)
                .filter(|record| record.has_known_path())
                .map(|record| record.serial);
            if let (Some(serial), Some(wizard)) = (serial, self.yk_wizard()) {
                wizard.backup_of = Some(serial);
                wizard.error = None;
            }
            self.refresh();
            return true;
        }
        match id {
            ids::SECTION_YUBIKEY => {
                // Opening the tab again ends a card action that is not talking to the card.
                if self
                    .card
                    .manage
                    .as_ref()
                    .is_some_and(|manage| !manage.running())
                {
                    self.yk_manage_close();
                }
                self.set_screen(Screen::Settings(SettingsSection::YubiKey));
                self.key(KeyJob::HardwareKeys);
            }
            ids::ENROL_START => self.yk_open_wizard(),
            ids::NEW_WALLET => self.yk_new_wallet(),
            ids::NEW_WALLET_START => self.yk_new_wallet_start(),
            ids::NEW_WALLET_CANCEL => {
                self.key(KeyJob::YubiKey(YkJob::Discard));
                self.set_screen(Screen::FirstRun);
            }
            ids::PIV_TOUCH_ALWAYS | ids::PIV_TOUCH_CACHED => {
                if let Some(wizard) = self.yk_wizard() {
                    wizard.piv_touch = if id == ids::PIV_TOUCH_ALWAYS {
                        TouchPolicy::Always
                    } else {
                        TouchPolicy::Cached
                    };
                }
                self.refresh();
            }
            ids::SHARED_ACK => {
                if let Some(wizard) = self.yk_wizard() {
                    wizard.shared_ack = !wizard.shared_ack;
                    wizard.error = None;
                }
                self.refresh();
            }
            ids::BACKUP_TOGGLE => {
                // The first card the words can copy: one with a known path (a card connected
                // without recovery words cannot be made again from words, spec/10 §7.6).
                let first = self
                    .card
                    .records
                    .iter()
                    .find(|record| record.has_known_path())
                    .map(|record| record.serial);
                if let Some(wizard) = self.yk_wizard() {
                    if wizard.backup_of.is_some() {
                        wizard.backup_of = None;
                        wizard.error = None;
                    } else if first.is_some() {
                        wizard.backup_of = first;
                        wizard.error = None;
                    } else {
                        wizard.error = Some(T_YK_BACKUP_UNKNOWN.to_owned());
                    }
                }
                self.refresh();
            }
            ids::OVERWRITE_ACK => {
                if let Some(wizard) = self.yk_wizard() {
                    wizard.overwrite_ack = !wizard.overwrite_ack;
                    wizard.error = None;
                }
                self.refresh();
            }
            ids::PLAN_NEXT => self.yk_plan_next(),
            ids::FINISH | ids::ANOTHER if self.yk_pins_first() => self.refresh(),
            // A card left on its factory PINs does not sign: `완료` asks once (2026-11-10).
            ids::FINISH
                if self
                    .yk_result_serial()
                    .is_some_and(|serial| self.yk_card_on_defaults(serial)) =>
            {
                self.set_screen(Screen::Confirm(Confirm::YkPinLater));
            }
            // The words of a new wallet are not dropped on one click: asked first (2026-11-10).
            ids::WIZARD_CANCEL if self.yk_abandon_asks() => {
                self.set_screen(Screen::Confirm(Confirm::YkAbandon));
            }
            ids::RESULT_DETAILS => {
                self.card.result_details_open = !self.card.result_details_open;
                self.refresh();
            }
            ids::PIN_GUIDE => {
                self.card.pin_guide_open = !self.card.pin_guide_open;
                self.refresh();
            }
            ids::WIZARD_CANCEL | ids::FINISH => self.yk_close_wizard(),
            ids::IDENTIFY_AGAIN => self.yk_identify_again(),
            ids::PIN_NEEDED_OPEN => {
                // The card of the refused signing: its "PIN 설정" card in the YubiKey list.
                self.card.pin_serial = self.card.pin_needed;
                self.set_screen(Screen::Settings(SettingsSection::YubiKey));
                self.key(KeyJob::HardwareKeys);
            }
            gate if (ids::PIN_GATE_BASE..ids::PIN_GATE_BASE + ids::PIN_GATE_SPAN)
                .contains(&gate) =>
            {
                // A form's or account card's band: that card's "PIN 설정" card.
                let row = usize::from(gate - ids::PIN_GATE_BASE);
                if let Some(serial) = self.card.records.get(row).map(|record| record.serial) {
                    self.card.pin_serial = Some(serial);
                    self.set_screen(Screen::Settings(SettingsSection::YubiKey));
                    self.key(KeyJob::HardwareKeys);
                }
            }
            ids::SAME_ACK => {
                if let Some(wizard) = self.yk_wizard() {
                    wizard.same_ack = !wizard.same_ack;
                }
                self.refresh();
            }
            ids::CONFIRM_BACK | ids::ANOTHER => {
                let another = id == ids::ANOTHER;
                let serial = self.yk_result_serial();
                if let Some(wizard) = self.yk_wizard() {
                    wizard.step = WizardStep::Plan;
                    wizard.preview = None;
                    if another {
                        wizard.backup_of = serial;
                        wizard.enrolled = None;
                        wizard.check = None;
                        wizard.notes.clear();
                        wizard.failure = None;
                    }
                }
                self.refresh();
            }
            ids::CONFIRM_NEXT => {
                if self.yk_wizard().is_some_and(|wizard| wizard.can_continue()) {
                    self.yk_enter_credentials();
                }
                self.refresh();
            }
            ids::RETRY => {
                self.yk_enter_credentials();
                self.refresh();
            }
            ids::CRED_BACK => {
                if let Some(wizard) = self.yk_wizard() {
                    wizard.step = WizardStep::Confirm;
                    wizard.failure = None;
                    wizard.error = None;
                }
                self.refresh();
            }
            ids::MGMT_DEFAULT | ids::MGMT_CUSTOM => {
                if let Some(wizard) = self.yk_wizard() {
                    wizard.default_management = id == ids::MGMT_DEFAULT;
                }
                self.refresh();
            }
            ids::IMPORT => self.yk_import(false),
            ids::ADOPT => self.yk_import(true),
            ids::RECHECK => {
                if let Some(serial) = self.yk_result_serial() {
                    self.key(KeyJob::YubiKey(YkJob::Check { serial }));
                }
            }
            ids::CHANGE_PW1 | ids::CHANGE_PW3 | ids::CHANGE_PIV_PIN | ids::CHANGE_PUK => {
                let target = match id {
                    ids::CHANGE_PW1 => PinTarget::OpenPgpUser,
                    ids::CHANGE_PW3 => PinTarget::OpenPgpAdmin,
                    ids::CHANGE_PIV_PIN => PinTarget::PivPin,
                    _ => PinTarget::PivPuk,
                };
                // The tries left of that secret are read and shown before it is typed
                // (spec/10 §9.1).
                self.yk_open_pin_action(
                    CardSecretKind::ChangePin(target),
                    YkPurpose::ChangePin(target),
                );
            }
            ids::CHANGE_MGMT => {
                self.yk_open_pin_action(CardSecretKind::PivPin, YkPurpose::ProtectManagement);
            }
            ids::SET_PINS => self.yk_open_pin_action(CardSecretKind::SetPins, YkPurpose::SetPins),
            ids::PINS_UNIFIED | ids::PINS_SEPARATE => {
                self.card.pins_separate = id == ids::PINS_SEPARATE;
                self.card.pins_chosen = true;
                self.refresh();
            }
            _ => return false,
        }
        true
    }

    /// `EN_CHANGE` of a wizard edit; `false` when `id` is not one of them.
    pub fn on_yk_edit_change(&mut self, id: u16) -> bool {
        use crate::ui::screens_yubikey::ids;
        if self.on_yk_manage_edit_change(id) {
            return true;
        }
        if id == ids::OVERWRITE_EDIT {
            // No repaint while typing: `가져오기` checks the word when pressed.
            let text = self.controls.text(id, 16).unwrap_or_default();
            if let Some(wizard) = self.yk_wizard() {
                wizard.overwrite_typed = text;
            }
            return true;
        }
        if ![
            ids::SIG_INDEX_EDIT,
            ids::AUT_INDEX_EDIT,
            ids::SOL_COUNT_EDIT,
            ids::SOL_START_EDIT,
        ]
        .contains(&id)
        {
            return false;
        }
        let text = self.controls.text(id, 8).unwrap_or_default();
        self.yk_set_text(id, text);
        true
    }

    /// Stores the text of a wizard edit (also the tests' way to type).
    pub fn yk_set_text(&mut self, id: u16, text: String) {
        use crate::ui::screens_yubikey::ids;
        let Some(wizard) = self.yk_wizard() else {
            return;
        };
        match id {
            ids::SIG_INDEX_EDIT => wizard.sig.index_text = text,
            ids::AUT_INDEX_EDIT => wizard.aut.index_text = text,
            ids::SOL_COUNT_EDIT => wizard.sol_count_text = text,
            ids::SOL_START_EDIT => wizard.sol_start_text = text,
            ids::OVERWRITE_EDIT => wizard.overwrite_typed = text,
            _ => {}
        }
        wizard.error = None;
    }
}
