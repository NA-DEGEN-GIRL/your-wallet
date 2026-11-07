//! The card actions of the `YubiKey` list (spec/10 §15, spec/04 §2.19): "슬롯 구성 바꾸기"
//! and "`YubiKey` 비우기". They are shown in place of the list (Settings → `YubiKey`) while open.
//!
//! "슬롯 구성 바꾸기": the current slot map → a preset (EVM+BTC / EVM+ZEC / BTC+ZEC / EVM+EVM)
//! or a custom choice per slot (chain, Bitcoin address type, index; the EVM shared key only
//! under "고급") → the recovery words once in W05 (+ W06), held by the key worker until the flow
//! ends → every new path and address with the accounts this card stops holding → the `OpenPGP`
//! admin PIN (W12) → the card → read back → the slot map and the accounts. Then "백업 `YubiKey`에도
//! 같은 구성 적용" repeats it on the other cards with the held words.
//!
//! "`YubiKey` 비우기": what to clear (`OpenPGP` wallet keys, PIV Solana slots, or both) and how
//! (our slots only, or the applet's factory reset), the accounts that become unusable, the word
//! "비우기" typed, the admin PIN / PIV PIN when only our slots are deleted, then the card and the
//! slot map (a card with no wallet slot left leaves the list).

use yw_core::bip32::path::AccountIndex;
use yw_core::btc::{BtcNetwork, ScriptType};
use yw_core::secret::Zeroizing;
use yw_core::yubikey::manage::{ClearMethod, ClearPlan};
use yw_core::yubikey::plan::{
    BtcUse, CardSlot, KeyRole, PgpKey, PinPolicy, PlannedSlot, TouchPolicy, UNKNOWN_PATH_FIRST,
    validate_plan,
};
use yw_core::yubikey::record::{HwKeyRecord, HwPublicKey, RecordedSlot};
use yw_core::zec::ZecNetwork;

use super::{YkPurpose, failure_text};
use crate::app::App;
use crate::events::{KeyJob, YubiKeyJobError};
use crate::logging;
use crate::ui::secret::{CardSecretKind, SecretKind};
use crate::workers::key::yubikey::YkJob;
use crate::workers::key::yubikey::manage::{Cleared, ManageJob, ManageOutcome, ReslotPreview};

/// The word typed to confirm "`YubiKey` 비우기".
pub const CLEAR_WORD: &str = "비우기";
/// T-YK-RESLOT-WORDS: what happens to the recovery words.
pub const T_YK_RESLOT_WORDS: &str = "새 키를 만들려면 복구 단어가 한 번 필요합니다. 비밀 입력 창에서 받아 키를 만드는 데만 쓰고 저장하지 않으며, 이 작업(백업 YubiKey 적용 포함)을 마치거나 취소하거나 지갑이 잠기면 바로 지웁니다.";
/// T-YK-RESLOT-REMOVED: the accounts this card stops holding (shown only when one of them has a
/// known path, spec/10 §15.1).
pub const T_YK_RESLOT_REMOVED: &str = "카드에서 빠지는 체인은 바꾼 뒤 이 YubiKey로 서명할 수 없습니다. 자금은 체인에 그대로 있고(복구 단어로 언제든 복구), 나중에 같은 구성으로 다시 바꾸면 같은 주소가 그대로 돌아옵니다.";
/// T-YK-KEY-LOST: a key connected without recovery words that no other enrolled card holds is
/// overwritten or cleared (spec/10 §15): it cannot be made again.
pub const T_YK_KEY_LOST: &str = "이 키는 복구 단어가 없습니다 — 지우면 영구히 사라지고 이 주소의 자산을 다시 쓸 수 없습니다. 잔액이 있으면 먼저 다른 주소로 옮기세요.";
/// The phrase typed to confirm that such a key is lost for good.
pub const LOSS_WORD: &str = "영구 삭제";
/// The checkbox of [`T_YK_KEY_LOST`].
pub const T_YK_KEY_LOST_ACK: &str =
    "이해했습니다: 복구 단어가 없는 이 키는 영구히 사라지고 그 주소의 자산을 다시 쓸 수 없습니다";
/// T-YK-RESLOT-BACKUP: backup cards should get the same change.
pub const T_YK_RESLOT_BACKUP: &str = "이 YubiKey의 백업 YubiKey가 있으면 같은 구성으로 바꾸세요. 그렇지 않으면 백업 YubiKey에는 예전 키가 남아 같은 계정을 대신 서명할 수 없습니다.";
/// T-YK-CLEAR-FUNDS (shown only when a cleared slot has a known path).
pub const T_YK_CLEAR_FUNDS: &str = "비우면 아래 계정은 이 YubiKey로 서명할 수 없습니다. 자금은 체인에 그대로 있고 복구 단어로 언제든 복구할 수 있습니다(같은 키를 다시 넣거나 다른 지갑에서).";
/// T-YK-CLEAR-PGP-OURS.
pub const T_YK_CLEAR_PGP_OURS: &str = "OpenPGP에는 '키 삭제' 명령이 없습니다. yubikey-manager의 delete_key와 같이 SIG/AUT 슬롯의 알고리즘 속성을 두 번 바꿔(RSA 4096 → RSA 2048) 그 슬롯의 키를 지웁니다. PIN과 다른 슬롯(DEC)은 그대로이고, '고정' 터치 정책은 남습니다(지우려면 초기화). 관리자 PIN이 필요합니다.";
/// T-YK-CLEAR-PGP-RESET.
pub const T_YK_CLEAR_PGP_RESET: &str = "OpenPGP 애플릿 전체를 공장 상태로 되돌립니다(Yubico 절차: PIN·관리자 PIN을 틀린 값으로 잠근 뒤 TERMINATE·ACTIVATE). 세 슬롯의 모든 키(GPG 등 다른 용도 포함)가 지워지고 PIN은 123456, 관리자 PIN은 12345678로 돌아갑니다. PIN이 필요 없습니다.";
/// T-YK-CLEAR-PIV-OURS.
pub const T_YK_CLEAR_PIV_OURS: &str = "이 지갑이 쓴 PIV 슬롯만 DELETE KEY로 지웁니다(펌웨어 5.7 이상; Yubico 문서는 5.7.4부터). 이 지갑은 PIV 인증서를 쓰지 않으므로 지울 인증서는 없습니다. PIV PIN이 필요하고, 관리 키는 공장 기본값이거나 PIN으로 보호된 경우만 됩니다.";
/// T-YK-CLEAR-PIV-RESET.
pub const T_YK_CLEAR_PIV_RESET: &str = "PIV 애플릿 전체를 공장 상태로 되돌립니다(PIN과 PUK를 틀린 값으로 잠근 뒤 RESET). 모든 PIV 키·인증서(다른 용도 포함)가 지워지고 PIN 123456, PUK 12345678, 관리 키가 공장 기본값으로 돌아갑니다. PIN이 필요 없습니다.";
/// T-YK-CLEAR-SCOPE.
pub const T_YK_CLEAR_SCOPE: &str = "FIDO2·패스키, OTP, OATH는 건드리지 않습니다.";

/// A preset of the two `OpenPGP` slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Preset {
    /// SIG = EVM, AUT = Bitcoin.
    EvmBtc,
    /// SIG = EVM, AUT = Zcash.
    EvmZec,
    /// SIG = Bitcoin, AUT = Zcash.
    BtcZec,
    /// SIG = EVM i, AUT = EVM i + 1.
    EvmEvm,
    /// Chosen per slot.
    Custom,
}

impl Preset {
    /// Every preset in display order.
    pub const ALL: [Self; 5] = [
        Self::EvmBtc,
        Self::EvmZec,
        Self::BtcZec,
        Self::EvmEvm,
        Self::Custom,
    ];

    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::EvmBtc => "EVM + Bitcoin",
            Self::EvmZec => "EVM + Zcash",
            Self::BtcZec => "Bitcoin + Zcash",
            Self::EvmEvm => "EVM + EVM",
            Self::Custom => "직접 고르기",
        }
    }
}

/// What a slot holds in the re-slot form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    /// EVM account `i`.
    Evm,
    /// Bitcoin single address `i`.
    Btc,
    /// Zcash transparent address `i`.
    Zec,
    /// The EVM shared key (advanced, spec/10 §3.2).
    Shared,
}

impl Chain {
    /// Every chain in id order (the radios).
    pub const ALL: [Self; 4] = [Self::Evm, Self::Btc, Self::Zec, Self::Shared];

    /// Display label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Evm => "EVM 계정",
            Self::Btc => "Bitcoin 주소",
            Self::Zec => "Zcash 주소",
            Self::Shared => "EVM 공유 키 (고급)",
        }
    }
}

/// One slot of the re-slot form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlotForm {
    /// The chain.
    pub chain: Chain,
    /// Index text (0–899; the unknown-path band 900–999 is never a path).
    pub index_text: String,
    /// Bitcoin address type (Bitcoin and the shared key).
    pub script: ScriptType,
}

impl SlotForm {
    fn new(chain: Chain, index: u32) -> Self {
        Self {
            chain,
            index_text: index.to_string(),
            script: ScriptType::P2wpkh,
        }
    }
}

/// The step of "슬롯 구성 바꾸기".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReslotStep {
    /// The current map and the new combination.
    Choose,
    /// Every new path and address (the preview is computed meanwhile).
    Confirm,
    /// The card job runs.
    Running,
    /// Done (or failed: [`ReslotFlow::failure`]).
    Result,
}

/// "슬롯 구성 바꾸기" (no secret except the words between W05 and W06, wiped on drop).
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent flags of one flow"
)]
pub struct ReslotFlow {
    /// The card being changed.
    pub serial: u32,
    /// Step.
    pub step: ReslotStep,
    /// The chosen preset.
    pub preset: Preset,
    /// SIG.
    pub sig: SlotForm,
    /// AUT.
    pub aut: SlotForm,
    /// Zcash network of the Zcash slots.
    pub zec_network: ZecNetwork,
    /// "고급": the EVM shared key is offered.
    pub advanced: bool,
    /// The §3.2 checkbox of the shared key.
    pub shared_ack: bool,
    /// The removed-chains warning was acknowledged.
    pub removed_ack: bool,
    /// The [`T_YK_KEY_LOST`] checkbox (a key without recovery words is overwritten).
    pub loss_ack: bool,
    /// The typed [`LOSS_WORD`] (checked when `YubiKey에 넣기` is pressed).
    pub loss_typed: String,
    /// Input error of the choose step (and of the confirmation's typed word).
    pub error: Option<String>,
    /// The new `OpenPGP` slots sent to the preview / the card.
    pub slots: Vec<PlannedSlot>,
    /// The confirmation facts.
    pub preview: Option<ReslotPreview>,
    /// The key worker holds the recovery words.
    pub seed_held: bool,
    phrase: Option<Zeroizing<Vec<u8>>>,
    /// The card's record before this change.
    pub before: Option<HwKeyRecord>,
    /// The card's new record.
    pub result: Option<HwKeyRecord>,
    /// The failure text.
    pub failure: Option<String>,
    /// Cards already changed in this flow (the first one and its backups).
    pub done: Vec<u32>,
}

/// The step of "`YubiKey` 비우기".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClearStep {
    /// What and how, the typed word.
    Choose,
    /// The card job runs.
    Running,
    /// The result.
    Result,
}

/// "`YubiKey` 비우기" (the admin PIN only between its window and the PIV PIN window).
pub struct ClearFlow {
    /// The card.
    pub serial: u32,
    /// Step.
    pub step: ClearStep,
    /// `OpenPGP`: nothing or how.
    pub openpgp: Option<ClearMethod>,
    /// PIV: nothing or how.
    pub piv: Option<ClearMethod>,
    /// The typed confirmation word.
    pub typed: String,
    admin_pin: Option<Zeroizing<Vec<u8>>>,
    /// The card's record before clearing.
    pub before: Option<HwKeyRecord>,
    /// The result.
    pub result: Option<Cleared>,
    /// The failure text.
    pub failure: Option<String>,
    /// Input error of the choose step (the word not typed).
    pub error: Option<String>,
    /// The [`T_YK_KEY_LOST`] checkbox (a key without recovery words is cleared).
    pub loss_ack: bool,
    /// The typed [`LOSS_WORD`] (checked when `비우기` is pressed).
    pub loss_typed: String,
}

impl ClearFlow {
    /// The plan of the choices.
    #[must_use]
    pub const fn plan(&self) -> ClearPlan {
        ClearPlan {
            openpgp: self.openpgp,
            piv: self.piv,
        }
    }
}

/// The open card action.
#[derive(Debug)]
pub enum YkManage {
    /// "슬롯 구성 바꾸기".
    Reslot(ReslotFlow),
    /// "`YubiKey` 비우기".
    Clear(ClearFlow),
}

impl YkManage {
    /// Whether its card job runs.
    #[must_use]
    pub fn running(&self) -> bool {
        match self {
            Self::Reslot(flow) => flow.step == ReslotStep::Running,
            Self::Clear(flow) => flow.step == ClearStep::Running,
        }
    }
}

impl core::fmt::Debug for ReslotFlow {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ReslotFlow")
            .field("serial", &self.serial)
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for ClearFlow {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ClearFlow")
            .field("serial", &self.serial)
            .field("step", &self.step)
            .finish_non_exhaustive()
    }
}

/// Highest index of a re-slotted key: the band from [`UNKNOWN_PATH_FIRST`] is only an account
/// number of keys connected without recovery words, never a path (spec/10 §7.6).
pub const MAX_RESLOT_INDEX: u32 = UNKNOWN_PATH_FIRST - 1;

fn parse_index(text: &str, label: &str) -> Result<u32, String> {
    text.trim()
        .parse::<u32>()
        .ok()
        .filter(|value| *value <= MAX_RESLOT_INDEX)
        .ok_or_else(|| format!("{label}: 0–{MAX_RESLOT_INDEX} 사이의 숫자를 넣으세요."))
}

/// The EVM account index of the card's first EVM slot with a known path (the presets' default;
/// a key connected without recovery words has no path to reuse).
fn known_evm_index(record: &HwKeyRecord) -> Option<u32> {
    record.slots.iter().find_map(|slot| match slot.role {
        KeyRole::Evm { index, .. } if slot.path_known => Some(index.get()),
        _ => None,
    })
}

/// The `OpenPGP` slots of `before` the card no longer holds after the change, with the other
/// cards still holding each (empty: no card can sign it any more). A slot counts as kept only
/// when the same slot keeps both its role and its public key (`after`: the new slots with their
/// derived public keys), so a key connected without recovery words that a derived key replaces
/// is listed.
#[must_use]
pub fn dropped_roles(
    before: &HwKeyRecord,
    after: &[(CardSlot, KeyRole, HwPublicKey)],
    others: &[HwKeyRecord],
) -> Vec<(RecordedSlot, Vec<u32>)> {
    before
        .slots
        .iter()
        .filter(|slot| matches!(slot.slot, CardSlot::OpenPgp(_)))
        .filter(|slot| {
            !after.iter().any(|(card_slot, role, public)| {
                *card_slot == slot.slot
                    && role.key_identity() == slot.role.key_identity()
                    && *public == slot.public
            })
        })
        .map(|slot| {
            let holders = others
                .iter()
                .filter(|other| other.serial != before.serial)
                .filter(|other| {
                    other
                        .slots
                        .iter()
                        .any(|held| held.role.key_identity() == slot.role.key_identity())
                })
                .map(|other| other.serial)
                .collect();
            (*slot, holders)
        })
        .collect()
}

/// The slots of `dropped` whose key is lost for good: connected without recovery words and held
/// by no other enrolled card (spec/10 §15: [`T_YK_KEY_LOST`]).
#[must_use]
pub fn lost_slots(dropped: &[(RecordedSlot, Vec<u32>)]) -> Vec<RecordedSlot> {
    dropped
        .iter()
        .filter(|(slot, holders)| !slot.path_known && holders.is_empty())
        .map(|(slot, _)| *slot)
        .collect()
}

impl ReslotFlow {
    fn new(record: &HwKeyRecord, network: BtcNetwork) -> Self {
        let evm = known_evm_index(record).unwrap_or(0);
        let mut flow = Self {
            serial: record.serial,
            step: ReslotStep::Choose,
            preset: Preset::EvmZec,
            sig: SlotForm::new(Chain::Evm, evm),
            aut: SlotForm::new(Chain::Zec, 0),
            zec_network: if network == BtcNetwork::Testnet4 {
                ZecNetwork::Testnet
            } else {
                ZecNetwork::Mainnet
            },
            advanced: false,
            shared_ack: false,
            removed_ack: false,
            loss_ack: false,
            loss_typed: String::new(),
            error: None,
            slots: Vec::new(),
            preview: None,
            seed_held: false,
            phrase: None,
            before: Some(record.clone()),
            result: None,
            failure: None,
            done: Vec::new(),
        };
        flow.apply_preset(Preset::EvmZec);
        flow
    }

    /// The form of `key`.
    #[must_use]
    pub const fn form(&self, key: PgpKey) -> &SlotForm {
        match key {
            PgpKey::Sig => &self.sig,
            PgpKey::Aut => &self.aut,
        }
    }

    const fn form_mut(&mut self, key: PgpKey) -> &mut SlotForm {
        match key {
            PgpKey::Sig => &mut self.sig,
            PgpKey::Aut => &mut self.aut,
        }
    }

    /// Fills both slots from `preset` (indices: the card's EVM index with a known path, else 0;
    /// EVM+EVM uses `i` and `i + 1`).
    pub fn apply_preset(&mut self, preset: Preset) {
        self.preset = preset;
        let evm = self.before.as_ref().and_then(known_evm_index).unwrap_or(0);
        let (sig, aut) = match preset {
            Preset::EvmBtc => (SlotForm::new(Chain::Evm, evm), SlotForm::new(Chain::Btc, 0)),
            Preset::EvmZec => (SlotForm::new(Chain::Evm, evm), SlotForm::new(Chain::Zec, 0)),
            Preset::BtcZec => (SlotForm::new(Chain::Btc, 0), SlotForm::new(Chain::Zec, 0)),
            Preset::EvmEvm => (
                SlotForm::new(Chain::Evm, evm),
                SlotForm::new(Chain::Evm, evm.saturating_add(1).min(MAX_RESLOT_INDEX)),
            ),
            Preset::Custom => return,
        };
        self.sig = sig;
        self.aut = aut;
    }

    /// Whether the new plan uses the shared key.
    #[must_use]
    pub fn uses_shared(&self) -> bool {
        self.sig.chain == Chain::Shared || self.aut.chain == Chain::Shared
    }

    /// The touch policy kept for `key` (the card's current one; "항상" for a new slot).
    fn touch(&self, key: PgpKey) -> TouchPolicy {
        self.before
            .as_ref()
            .and_then(|record| {
                record
                    .slots
                    .iter()
                    .find(|slot| slot.slot == CardSlot::OpenPgp(key))
            })
            .map_or(TouchPolicy::Always, |slot| slot.touch)
    }

    /// The planned slot of one form.
    ///
    /// # Errors
    ///
    /// The text to show.
    pub fn planned(&self, key: PgpKey, network: BtcNetwork) -> Result<PlannedSlot, String> {
        let form = self.form(key);
        let label = CardSlot::OpenPgp(key).label();
        let index = parse_index(&form.index_text, &label)?;
        let account = || AccountIndex::new(index).map_err(|_| format!("{label}: 인덱스 범위"));
        let role = match form.chain {
            Chain::Evm => KeyRole::Evm {
                index: account()?,
                btc: None,
            },
            Chain::Shared => KeyRole::Evm {
                index: account()?,
                btc: Some(BtcUse {
                    network,
                    script: form.script,
                }),
            },
            Chain::Btc => KeyRole::Btc {
                network,
                script: form.script,
                index,
            },
            Chain::Zec => KeyRole::Zec {
                network: self.zec_network,
                index,
            },
        };
        Ok(PlannedSlot {
            slot: CardSlot::OpenPgp(key),
            role,
            touch: self.touch(key),
            pin: PinPolicy::NotApplicable,
            backup_copy: false,
        })
    }

    /// Both new `OpenPGP` slots, checked with the per-card rules.
    ///
    /// # Errors
    ///
    /// The text to show.
    pub fn plan(&self, network: BtcNetwork) -> Result<Vec<PlannedSlot>, String> {
        let slots = vec![
            self.planned(PgpKey::Sig, network)?,
            self.planned(PgpKey::Aut, network)?,
        ];
        if self.uses_shared() && !self.shared_ack {
            return Err("EVM 공유 키의 안내를 읽고 확인란을 체크하세요.".to_owned());
        }
        validate_plan(&slots).map_err(|error| error.to_string())?;
        Ok(slots)
    }

    /// The slots this card stops holding with the new plan (from the preview's derived public
    /// keys; empty until the preview is there).
    #[must_use]
    pub fn dropped(&self, others: &[HwKeyRecord]) -> Vec<(RecordedSlot, Vec<u32>)> {
        let (Some(before), Some(preview)) = (self.before.as_ref(), self.preview.as_ref()) else {
            return Vec::new();
        };
        let after: Vec<(CardSlot, KeyRole, HwPublicKey)> = preview
            .lines
            .iter()
            .map(|line| (line.planned.slot, line.planned.role, line.public))
            .collect();
        dropped_roles(before, &after, others)
    }

    /// Whether the confirmation allows the import (the typed [`LOSS_WORD`] is checked when
    /// `YubiKey에 넣기` is pressed).
    #[must_use]
    pub fn can_import(&self, others: &[HwKeyRecord]) -> bool {
        let dropped = self.dropped(others);
        self.preview
            .as_ref()
            .is_some_and(|preview| preview.plan.is_ok())
            && (dropped.is_empty() || self.removed_ack)
            && (lost_slots(&dropped).is_empty() || self.loss_ack)
    }

    /// Whether the typed word of a lost key is right (or no key is lost).
    fn loss_word_ok(&self, others: &[HwKeyRecord]) -> bool {
        lost_slots(&self.dropped(others)).is_empty() || self.loss_typed.trim() == LOSS_WORD
    }
}

impl App {
    fn yk_manage_record(&self, row: usize) -> Option<HwKeyRecord> {
        self.card.records.get(row).cloned()
    }

    /// `슬롯 구성 바꾸기` of the list row `row`.
    pub fn yk_reslot_open(&mut self, row: usize) {
        if !matches!(self.mode, crate::app::AppMode::Unlocked { .. }) {
            return;
        }
        let Some(record) = self.yk_manage_record(row) else {
            return;
        };
        // A wizard's held words are not this flow's.
        self.key(KeyJob::YubiKey(YkJob::Discard));
        self.card.wizard = None;
        self.card.pin_serial = None;
        self.card.manage = Some(YkManage::Reslot(ReslotFlow::new(
            &record,
            self.yk_network(),
        )));
        self.refresh();
    }

    /// `YubiKey 비우기` of the list row `row`.
    pub fn yk_clear_open(&mut self, row: usize) {
        if !matches!(self.mode, crate::app::AppMode::Unlocked { .. }) {
            return;
        }
        let Some(record) = self.yk_manage_record(row) else {
            return;
        };
        self.card.pin_serial = None;
        self.card.manage = Some(YkManage::Clear(ClearFlow {
            serial: record.serial,
            step: ClearStep::Choose,
            openpgp: None,
            piv: None,
            typed: String::new(),
            admin_pin: None,
            before: Some(record),
            result: None,
            failure: None,
            error: None,
            loss_ack: false,
            loss_typed: String::new(),
        }));
        self.refresh();
    }

    /// Ends the open card action (the key worker forgets the held words).
    pub fn yk_manage_close(&mut self) {
        if matches!(self.card.manage, Some(YkManage::Reslot(_))) {
            self.key(KeyJob::YubiKey(YkJob::Discard));
        }
        self.card.manage = None;
        self.key(KeyJob::HardwareKeys);
        self.refresh();
    }

    fn reslot(&mut self) -> Option<&mut ReslotFlow> {
        match self.card.manage.as_mut() {
            Some(YkManage::Reslot(flow)) => Some(flow),
            _ => None,
        }
    }

    fn clear_flow(&mut self) -> Option<&mut ClearFlow> {
        match self.card.manage.as_mut() {
            Some(YkManage::Clear(flow)) => Some(flow),
            _ => None,
        }
    }

    /// The other enrolled cards than `serial`.
    #[must_use]
    pub fn yk_other_records(&self, serial: u32) -> Vec<HwKeyRecord> {
        self.card
            .records
            .iter()
            .filter(|record| record.serial != serial)
            .cloned()
            .collect()
    }

    // ----- 슬롯 구성 바꾸기 ----------------------------------------------------------------------

    /// Choose `다음`: the plan, then W05 (or straight to the preview when the words are held).
    pub fn yk_reslot_next(&mut self) {
        let network = self.yk_network();
        let Some(flow) = self.reslot() else {
            return;
        };
        match flow.plan(network) {
            Err(text) => flow.error = Some(text),
            Ok(slots) => {
                flow.error = None;
                flow.slots.clone_from(&slots);
                flow.preview = None;
                flow.removed_ack = false;
                flow.loss_ack = false;
                flow.loss_typed.clear();
                flow.step = ReslotStep::Confirm;
                let serial = flow.serial;
                if flow.seed_held {
                    self.key(KeyJob::YubiKey(YkJob::Manage(ManageJob::ReslotPreview {
                        mnemonic: None,
                        serial,
                        slots,
                    })));
                } else {
                    self.open_input(
                        SecretKind::Mnemonic,
                        crate::app::Purpose::YubiKey(YkPurpose::ReslotMnemonic),
                        false,
                    );
                }
            }
        }
        self.refresh();
    }

    fn yk_reslot_send_preview(
        &mut self,
        phrase: Zeroizing<Vec<u8>>,
        passphrase: Option<Zeroizing<Vec<u8>>>,
    ) {
        self.close_secret();
        let Some(flow) = self.reslot() else {
            return;
        };
        let job = ManageJob::ReslotPreview {
            mnemonic: Some((phrase, passphrase)),
            serial: flow.serial,
            slots: flow.slots.clone(),
        };
        self.key(KeyJob::YubiKey(YkJob::Manage(job)));
        self.refresh();
    }

    /// Confirm `가져오기`: the typed [`LOSS_WORD`] when a key without recovery words is
    /// overwritten, then W12 admin PIN.
    pub fn yk_reslot_import(&mut self) {
        let others = self
            .reslot()
            .map(|flow| flow.serial)
            .map(|serial| self.yk_other_records(serial))
            .unwrap_or_default();
        let Some(flow) = self.reslot().filter(|flow| flow.can_import(&others)) else {
            return;
        };
        if !flow.loss_word_ok(&others) {
            flow.error = Some(format!(
                "확인하려면 입력란에 '{LOSS_WORD}'를 정확히 입력하세요."
            ));
            self.refresh();
            return;
        }
        flow.error = None;
        let serial = flow.serial;
        self.yk_open_card_secret(CardSecretKind::AdminPin, YkPurpose::ReslotAdminPin, serial);
    }

    /// "백업 `YubiKey`에도 같은 구성 적용" to the list row `row`: the same new `OpenPGP` plan on that
    /// card (its own touch policies), with the held words.
    pub fn yk_reslot_backup(&mut self, row: usize) {
        let network = self.yk_network();
        let Some(record) = self.yk_manage_record(row) else {
            return;
        };
        let Some(flow) = self.reslot() else {
            return;
        };
        if flow.done.contains(&record.serial) || !flow.seed_held {
            return;
        }
        flow.serial = record.serial;
        flow.before = Some(record);
        flow.result = None;
        flow.failure = None;
        flow.preview = None;
        flow.removed_ack = false;
        flow.loss_ack = false;
        flow.loss_typed.clear();
        match flow.plan(network) {
            Ok(slots) => {
                flow.slots.clone_from(&slots);
                flow.step = ReslotStep::Confirm;
                let serial = flow.serial;
                self.key(KeyJob::YubiKey(YkJob::Manage(ManageJob::ReslotPreview {
                    mnemonic: None,
                    serial,
                    slots,
                })));
            }
            Err(text) => {
                flow.step = ReslotStep::Choose;
                flow.error = Some(text);
            }
        }
        self.refresh();
    }

    // ----- YubiKey 비우기 ------------------------------------------------------------------------

    /// Whether the clear of the flow is allowed by the slot map (a wallet without recovery words
    /// keeps its last key).
    #[must_use]
    pub fn yk_clear_allowed(&self, flow: &ClearFlow) -> bool {
        let Some(before) = flow.before.as_ref() else {
            return false;
        };
        flow.plan().remaining(before).is_some()
            || self.keys.has_mnemonic
            || self.imported_count() > 0
            || self.card.records.len() > 1
    }

    /// The cleared slots of `flow` whose key is lost for good (connected without recovery words,
    /// held by no other enrolled card: [`T_YK_KEY_LOST`]).
    #[must_use]
    pub fn yk_clear_lost(&self, flow: &ClearFlow) -> Vec<RecordedSlot> {
        let Some(before) = flow.before.as_ref() else {
            return Vec::new();
        };
        let plan = flow.plan();
        let others = self.yk_other_records(flow.serial);
        let cleared: Vec<(RecordedSlot, Vec<u32>)> = before
            .slots
            .iter()
            .filter(|slot| plan.clears(slot.slot))
            .map(|slot| (*slot, crate::yubikey::holders(&others, slot.role)))
            .collect();
        lost_slots(&cleared)
    }

    /// Whether `비우기` is enabled (the typed words are checked when it is pressed).
    #[must_use]
    pub fn yk_clear_ready(&self, flow: &ClearFlow) -> bool {
        flow.step == ClearStep::Choose
            && flow.plan().any()
            && self.yk_clear_allowed(flow)
            && (flow.loss_ack || self.yk_clear_lost(flow).is_empty())
    }

    /// `비우기`: the typed words, the PIN windows the methods need, then the job.
    pub fn yk_clear_run(&mut self) {
        let (ready, lost) = match self.card.manage.as_ref() {
            Some(YkManage::Clear(flow)) => (
                self.yk_clear_ready(flow),
                !self.yk_clear_lost(flow).is_empty(),
            ),
            _ => (false, false),
        };
        let Some(flow) = self.clear_flow() else {
            return;
        };
        if !ready {
            return;
        }
        if flow.typed.trim() != CLEAR_WORD {
            flow.error = Some(format!(
                "확인하려면 입력란에 '{CLEAR_WORD}'를 정확히 입력하세요."
            ));
            self.refresh();
            return;
        }
        if lost && flow.loss_typed.trim() != LOSS_WORD {
            flow.error = Some(format!(
                "복구 단어가 없는 키를 지우려면 입력란에 '{LOSS_WORD}'를 정확히 입력하세요."
            ));
            self.refresh();
            return;
        }
        flow.error = None;
        flow.admin_pin = None;
        if flow.openpgp == Some(ClearMethod::OurSlots) {
            let serial = flow.serial;
            self.yk_open_card_secret(CardSecretKind::AdminPin, YkPurpose::ClearAdminPin, serial);
        } else {
            self.yk_clear_after_admin(Zeroizing::new(Vec::new()));
        }
    }

    fn yk_clear_after_admin(&mut self, admin_pin: Zeroizing<Vec<u8>>) {
        let Some(flow) = self.clear_flow() else {
            return;
        };
        if flow.piv == Some(ClearMethod::OurSlots) {
            flow.admin_pin = Some(admin_pin);
            let serial = flow.serial;
            self.yk_open_card_secret(CardSecretKind::PivPin, YkPurpose::ClearPivPin, serial);
        } else {
            self.yk_clear_job(admin_pin, Zeroizing::new(Vec::new()));
        }
    }

    fn yk_clear_job(&mut self, admin_pin: Zeroizing<Vec<u8>>, piv_pin: Zeroizing<Vec<u8>>) {
        self.close_secret();
        let Some(serial) = self.clear_flow().map(|flow| flow.serial) else {
            return;
        };
        let admin_last_try = !admin_pin.is_empty() && self.yk_take_last_try(serial);
        let Some(flow) = self.clear_flow() else {
            return;
        };
        flow.step = ClearStep::Running;
        flow.failure = None;
        let job = ManageJob::Clear {
            serial: flow.serial,
            plan: flow.plan(),
            admin_pin,
            piv_pin,
            admin_last_try,
        };
        logging::info("app", "yubikey.clear_start", &[]);
        self.key(KeyJob::YubiKey(YkJob::Manage(job)));
        self.refresh();
    }

    // ----- secret windows -------------------------------------------------------------------

    /// A W05/W06/W12 submission of the card actions.
    pub(crate) fn yk_manage_submit(
        &mut self,
        purpose: YkPurpose,
        values: Vec<Zeroizing<Vec<u8>>>,
        checkbox: bool,
    ) {
        let mut values = values.into_iter();
        let mut next = || values.next().unwrap_or_default();
        match purpose {
            YkPurpose::ReslotMnemonic => {
                let phrase = next();
                if checkbox {
                    if let Some(flow) = self.reslot() {
                        flow.phrase = Some(phrase);
                    }
                    self.open_input(
                        SecretKind::Passphrase { confirm: true },
                        crate::app::Purpose::YubiKey(YkPurpose::ReslotPassphrase),
                        false,
                    );
                } else {
                    self.yk_reslot_send_preview(phrase, None);
                }
            }
            YkPurpose::ReslotPassphrase => {
                let passphrase = next();
                match self.reslot().and_then(|flow| flow.phrase.take()) {
                    Some(phrase) => self.yk_reslot_send_preview(phrase, Some(passphrase)),
                    None => self.close_secret(),
                }
            }
            YkPurpose::ReslotAdminPin => {
                let admin_pin = next();
                self.close_secret();
                let Some(serial) = self.reslot().map(|flow| flow.serial) else {
                    return;
                };
                let admin_last_try = self.yk_take_last_try(serial);
                let Some(flow) = self.reslot() else {
                    return;
                };
                flow.step = ReslotStep::Running;
                flow.failure = None;
                let job = ManageJob::Reslot {
                    serial: flow.serial,
                    slots: flow.slots.clone(),
                    admin_pin,
                    admin_last_try,
                };
                logging::info("app", "yubikey.reslot_start", &[]);
                self.key(KeyJob::YubiKey(YkJob::Manage(job)));
                self.refresh();
            }
            YkPurpose::ClearAdminPin => {
                let admin_pin = next();
                self.yk_clear_after_admin(admin_pin);
            }
            YkPurpose::ClearPivPin => {
                let piv_pin = next();
                let admin_pin = self
                    .clear_flow()
                    .and_then(|flow| flow.admin_pin.take())
                    .unwrap_or_default();
                self.yk_clear_job(admin_pin, piv_pin);
            }
            _ => {}
        }
    }

    /// A card action's secret window was cancelled or closed.
    pub(crate) fn yk_manage_cancel(&mut self, purpose: YkPurpose) {
        match purpose {
            YkPurpose::ReslotMnemonic | YkPurpose::ReslotPassphrase => {
                if let Some(flow) = self.reslot() {
                    flow.phrase = None;
                    if !flow.seed_held {
                        flow.step = ReslotStep::Choose;
                    }
                }
            }
            YkPurpose::ClearAdminPin | YkPurpose::ClearPivPin => {
                if let Some(flow) = self.clear_flow() {
                    flow.admin_pin = None;
                }
            }
            _ => {}
        }
        self.refresh();
    }

    // ----- key worker results ----------------------------------------------------------------

    /// A card-action job finished.
    pub(crate) fn on_yk_manage(&mut self, outcome: ManageOutcome) {
        match outcome {
            ManageOutcome::ReslotPreview(serial, result) => self.on_reslot_preview(serial, result),
            ManageOutcome::Reslotted(serial, result) => self.on_reslotted(serial, result),
            ManageOutcome::Cleared(serial, result) => self.on_cleared(serial, result),
        }
        self.refresh();
    }

    fn on_reslot_preview(&mut self, serial: u32, result: Result<ReslotPreview, YubiKeyJobError>) {
        match result {
            Ok(preview) => {
                if let Some(flow) = self.reslot().filter(|flow| flow.serial == serial) {
                    flow.seed_held = true;
                    flow.preview = Some(preview);
                    flow.step = ReslotStep::Confirm;
                }
            }
            Err(YubiKeyJobError::Key(error)) => {
                let code = crate::errors::key_code(error);
                let message = match error {
                    yw_core::error::KeyError::MnemonicUnknownWord { position } => {
                        code.render(&position.to_string())
                    }
                    _ => code.text(),
                };
                self.open_input(
                    SecretKind::Mnemonic,
                    crate::app::Purpose::YubiKey(YkPurpose::ReslotMnemonic),
                    false,
                );
                self.with_form(|form| form.set_error(Some(message)));
            }
            Err(error) => {
                if let Some(flow) = self.reslot() {
                    flow.step = ReslotStep::Choose;
                    flow.error = Some(failure_text(error));
                }
            }
        }
    }

    fn on_reslotted(&mut self, serial: u32, result: Result<HwKeyRecord, YubiKeyJobError>) {
        if let Err(YubiKeyJobError::Card(error)) = &result {
            self.yk_note_last_try(serial, *error);
        }
        let Some(flow) = self.reslot().filter(|flow| flow.serial == serial) else {
            return;
        };
        flow.step = ReslotStep::Result;
        match result {
            Ok(record) => {
                flow.failure = None;
                if !flow.done.contains(&serial) {
                    flow.done.push(serial);
                }
                let roles: Vec<KeyRole> = record.slots.iter().map(|slot| slot.role).collect();
                flow.result = Some(record);
                logging::info("app", "yubikey.reslotted", &[]);
                self.card.unhide_later(roles);
                self.key(KeyJob::HardwareKeys);
                self.request_meta();
            }
            Err(error) => {
                let partial = matches!(
                    error,
                    YubiKeyJobError::Card(crate::yubikey::CardJobError::Enrol(
                        yw_core::yubikey::enrol::EnrolError::Card(_)
                    ))
                );
                let mut text = failure_text(error);
                if partial {
                    text.push(' ');
                    text.push_str(
                        "일부 슬롯에 새 키가 이미 들어갔을 수 있습니다. 지갑의 슬롯 표는 바꾸지 않았습니다. 다시 시도하면 덮어씁니다.",
                    );
                }
                flow.failure = Some(text);
                flow.result = None;
            }
        }
    }

    fn on_cleared(&mut self, serial: u32, result: Result<Cleared, YubiKeyJobError>) {
        if let Err(YubiKeyJobError::Card(error)) = &result {
            self.yk_note_last_try(serial, *error);
        }
        let Some(flow) = self.clear_flow().filter(|flow| flow.serial == serial) else {
            return;
        };
        flow.step = ClearStep::Result;
        match result {
            Ok(cleared) => {
                let reset = cleared.report.done(cleared.asked);
                let any_reset = reset.openpgp == Some(ClearMethod::Reset)
                    || reset.piv == Some(ClearMethod::Reset);
                flow.result = Some(cleared);
                flow.failure = None;
                if any_reset
                    && !cleared.removed
                    && let Some(meta) = self.meta.as_mut()
                    && !meta.hw_accounts.defaults.contains(&serial)
                {
                    // The reset applet has its factory PINs again.
                    meta.hw_accounts.defaults.push(serial);
                    meta.hw_accounts.defaults.sort_unstable();
                    meta.hw_accounts.defaults.truncate(8);
                    self.save_meta();
                }
                if cleared.removed
                    && let Some(meta) = self.meta.as_mut()
                    && meta.hw_accounts.defaults.contains(&serial)
                {
                    meta.hw_accounts.defaults.retain(|other| *other != serial);
                    self.save_meta();
                }
                logging::info("app", "yubikey.cleared", &[]);
                self.key(KeyJob::HardwareKeys);
                self.request_meta();
            }
            Err(error) => {
                flow.failure = Some(failure_text(error));
                flow.result = None;
            }
        }
    }

    // ----- commands --------------------------------------------------------------------------

    /// Main-window commands of the card actions; `false` when `id` is not one of them.
    #[expect(clippy::too_many_lines, reason = "one arm per control")]
    pub fn on_yk_manage_command(&mut self, id: u16) -> bool {
        use crate::ui::screens_yubikey::ids;
        if let Some(row) = ids::reslot_row(id) {
            self.yk_reslot_open(row);
            return true;
        }
        if let Some(row) = ids::clear_row(id) {
            self.yk_clear_open(row);
            return true;
        }
        if let Some(row) = ids::reslot_backup_row(id) {
            self.yk_reslot_backup(row);
            return true;
        }
        if let Some((key, action)) = ids::reslot_action(id) {
            if let Some(flow) = self.reslot() {
                let form = flow.form_mut(key);
                match action {
                    ids::ReslotAction::Chain(chain) => form.chain = chain,
                    ids::ReslotAction::Script(script) => form.script = script,
                }
                flow.preset = Preset::Custom;
                flow.error = None;
            }
            self.refresh();
            return true;
        }
        if let Some(preset) = ids::preset(id) {
            if let Some(flow) = self.reslot() {
                flow.apply_preset(preset);
                flow.error = None;
            }
            self.refresh();
            return true;
        }
        match id {
            ids::RESLOT_ZEC_MAIN | ids::RESLOT_ZEC_TEST => {
                if let Some(flow) = self.reslot() {
                    flow.zec_network = if id == ids::RESLOT_ZEC_MAIN {
                        ZecNetwork::Mainnet
                    } else {
                        ZecNetwork::Testnet
                    };
                }
            }
            ids::RESLOT_ADVANCED => {
                if let Some(flow) = self.reslot() {
                    flow.advanced = !flow.advanced;
                    if !flow.advanced {
                        for key in [PgpKey::Sig, PgpKey::Aut] {
                            if flow.form(key).chain == Chain::Shared {
                                flow.form_mut(key).chain = Chain::Evm;
                            }
                        }
                        flow.shared_ack = false;
                    }
                }
            }
            ids::RESLOT_SHARED_ACK => {
                if let Some(flow) = self.reslot() {
                    flow.shared_ack = !flow.shared_ack;
                    flow.error = None;
                }
            }
            ids::RESLOT_REMOVED_ACK => {
                if let Some(flow) = self.reslot() {
                    flow.removed_ack = !flow.removed_ack;
                }
            }
            ids::RESLOT_LOSS_ACK => {
                if let Some(flow) = self.reslot() {
                    flow.loss_ack = !flow.loss_ack;
                }
            }
            ids::CLEAR_LOSS_ACK => {
                if let Some(flow) = self.clear_flow() {
                    flow.loss_ack = !flow.loss_ack;
                }
            }
            ids::RESLOT_NEXT => {
                self.yk_reslot_next();
                return true;
            }
            ids::RESLOT_BACK => {
                if let Some(flow) = self.reslot() {
                    flow.step = ReslotStep::Choose;
                    flow.preview = None;
                    flow.failure = None;
                    flow.error = None;
                }
            }
            ids::RESLOT_IMPORT | ids::RESLOT_RETRY => {
                if id == ids::RESLOT_RETRY
                    && let Some(flow) = self.reslot()
                {
                    flow.step = ReslotStep::Confirm;
                    flow.failure = None;
                }
                self.yk_reslot_import();
            }
            ids::MANAGE_CANCEL | ids::MANAGE_DONE => {
                self.yk_manage_close();
                return true;
            }
            ids::CLEAR_PGP_TOGGLE | ids::CLEAR_PIV_TOGGLE => {
                if let Some(flow) = self.clear_flow() {
                    let target = if id == ids::CLEAR_PGP_TOGGLE {
                        &mut flow.openpgp
                    } else {
                        &mut flow.piv
                    };
                    *target = match target {
                        Some(_) => None,
                        None => Some(ClearMethod::OurSlots),
                    };
                }
            }
            ids::CLEAR_PGP_OURS | ids::CLEAR_PGP_RESET => {
                if let Some(flow) = self.clear_flow()
                    && flow.openpgp.is_some()
                {
                    flow.openpgp = Some(if id == ids::CLEAR_PGP_OURS {
                        ClearMethod::OurSlots
                    } else {
                        ClearMethod::Reset
                    });
                }
            }
            ids::CLEAR_PIV_OURS | ids::CLEAR_PIV_RESET => {
                if let Some(flow) = self.clear_flow()
                    && flow.piv.is_some()
                {
                    flow.piv = Some(if id == ids::CLEAR_PIV_OURS {
                        ClearMethod::OurSlots
                    } else {
                        ClearMethod::Reset
                    });
                }
            }
            ids::CLEAR_RUN => {
                self.yk_clear_run();
                return true;
            }
            _ => return false,
        }
        self.refresh();
        true
    }

    /// `EN_CHANGE` of a card-action edit; `false` when `id` is not one of them.
    pub fn on_yk_manage_edit_change(&mut self, id: u16) -> bool {
        use crate::ui::screens_yubikey::ids;
        if ![
            ids::RESLOT_SIG_INDEX_EDIT,
            ids::RESLOT_AUT_INDEX_EDIT,
            ids::CLEAR_CONFIRM_EDIT,
            ids::RESLOT_LOSS_EDIT,
            ids::CLEAR_LOSS_EDIT,
        ]
        .contains(&id)
        {
            return false;
        }
        let text = self.controls.text(id, 16).unwrap_or_default();
        self.yk_manage_set_text(id, text);
        true
    }

    /// Stores the text of a card-action edit (also the tests' way to type).
    pub fn yk_manage_set_text(&mut self, id: u16, text: String) {
        use crate::ui::screens_yubikey::ids;
        match id {
            ids::CLEAR_CONFIRM_EDIT => {
                // No repaint while typing: `비우기` checks the word when pressed.
                if let Some(flow) = self.clear_flow() {
                    flow.typed = text;
                }
            }
            ids::CLEAR_LOSS_EDIT => {
                if let Some(flow) = self.clear_flow() {
                    flow.loss_typed = text;
                }
            }
            ids::RESLOT_LOSS_EDIT => {
                // Checked when `YubiKey에 넣기` is pressed.
                if let Some(flow) = self.reslot() {
                    flow.loss_typed = text;
                }
            }
            ids::RESLOT_SIG_INDEX_EDIT | ids::RESLOT_AUT_INDEX_EDIT => {
                if let Some(flow) = self.reslot() {
                    let key = if id == ids::RESLOT_SIG_INDEX_EDIT {
                        PgpKey::Sig
                    } else {
                        PgpKey::Aut
                    };
                    flow.form_mut(key).index_text = text;
                    flow.error = None;
                }
            }
            _ => {}
        }
    }
}
