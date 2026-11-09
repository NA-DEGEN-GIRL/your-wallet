//! The card actions of the `YubiKey` list (spec/10 §15, spec/04 §2.19): "슬롯 구성 바꾸기" and
//! "`YubiKey` 비우기", shown in place of the list while open.

use yw_core::yubikey::manage::ClearMethod;
use yw_core::yubikey::plan::{CardSlot, PgpKey, address_texts};
use yw_core::yubikey::record::{HwKeyRecord, RecordedSlot};
use yw_core::zec::ZecNetwork;

use super::ids::{self, ReslotAction};
use super::{script_label, slot_items, zec_network_label};
use crate::app::App;
use crate::app_yubikey::manage::{
    CLEAR_WORD, Chain, ClearFlow, ClearStep, LOSS_WORD, MAX_RESLOT_INDEX, Preset, ReslotFlow,
    ReslotStep, T_YK_CLEAR_FUNDS, T_YK_CLEAR_PGP_OURS, T_YK_CLEAR_PGP_RESET, T_YK_CLEAR_PIV_OURS,
    T_YK_CLEAR_PIV_RESET, T_YK_CLEAR_SCOPE, T_YK_KEY_LOST, T_YK_KEY_LOST_ACK, T_YK_RESLOT_BACKUP,
    T_YK_RESLOT_REMOVED, T_YK_RESLOT_WORDS, YkManage, lost_slots,
};
use crate::app_yubikey::{CARD_SCRIPTS, T_YK_SAME, T_YK_SHARED};
use crate::ui::main_window::{Ctl, Item, Tone};

/// The steps of "슬롯 구성 바꾸기".
pub const RESLOT_STEPS: [&str; 4] = ["새 구성 고르기", "확인", "YubiKey에 넣기", "결과"];

fn holders_text(holders: &[u32]) -> String {
    holders
        .iter()
        .map(|serial| format!("#{serial}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// T-YK-KEY-LOST with the keys it names, its checkbox and the typed [`LOSS_WORD`] (spec/10 §15):
/// keys connected without recovery words that no other enrolled card holds.
fn loss_items(
    lost: &[RecordedSlot],
    (ack_id, edit_id): (u16, u16),
    (acked, typed): (bool, &str),
    items: &mut Vec<Item>,
) {
    if lost.is_empty() {
        return;
    }
    items.push(Item::Banner(T_YK_KEY_LOST.to_owned(), Tone::HighRisk));
    for slot in lost {
        items.push(Item::Text(format!(
            "{} — {} (복구 단어 없음)",
            slot.slot.label(),
            slot.role.title()
        )));
        for address in address_texts(slot.role, &slot.public).unwrap_or_default() {
            items.push(Item::Mono(address));
        }
    }
    items.push(Item::Row(vec![Ctl::check(
        ack_id,
        T_YK_KEY_LOST_ACK,
        acked,
    )]));
    items.push(Item::LabeledRow(
        format!("확인: '{LOSS_WORD}' 입력"),
        vec![Ctl::edit(edit_id, typed, 120, false, 8)],
    ));
}

fn record_items(record: &HwKeyRecord, items: &mut Vec<Item>) {
    for slot in &record.slots {
        slot_items(
            slot.slot,
            slot.role,
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
        items.push(Item::Subtitle(format!(
            "슬롯 구성 바꾸기 — YubiKey #{}",
            flow.serial
        )));
        let current = match flow.step {
            ReslotStep::Choose => 1,
            ReslotStep::Confirm => 2,
            ReslotStep::Running => 3,
            ReslotStep::Result => 4,
        };
        items.push(Item::Steps(
            RESLOT_STEPS
                .iter()
                .map(|label| (*label).to_owned())
                .collect(),
            current,
        ));
        match flow.step {
            ReslotStep::Choose => self.yk_reslot_choose_items(flow, items),
            ReslotStep::Confirm => self.yk_reslot_confirm_items(flow, items),
            ReslotStep::Running => {
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle("YubiKey에 새 키를 넣는 중입니다".to_owned()));
                items.push(Item::Text(
                    "YubiKey를 빼지 마세요. 몇 초 걸립니다(터치는 필요 없습니다).".to_owned(),
                ));
                items.push(Item::CardEnd);
            }
            ReslotStep::Result => self.yk_reslot_result_items(flow, items),
        }
    }

    fn yk_reslot_slot_items(&self, flow: &ReslotFlow, key: PgpKey, items: &mut Vec<Item>) {
        let form = flow.form(key);
        items.push(Item::Subtitle(CardSlot::OpenPgp(key).label()));
        let chains: Vec<Chain> = Chain::ALL
            .into_iter()
            .filter(|chain| *chain != Chain::Shared || flow.advanced || form.chain == *chain)
            .collect();
        items.push(Item::LabeledRow(
            "체인".to_owned(),
            chains
                .into_iter()
                .enumerate()
                .map(|(position, chain)| {
                    Ctl::radio(
                        ids::reslot_id(key, ReslotAction::Chain(chain)),
                        chain.label(),
                        form.chain == chain,
                        position == 0,
                    )
                })
                .collect(),
        ));
        items.push(Item::LabeledRow(
            if matches!(form.chain, Chain::Evm | Chain::Shared) {
                format!("계정 인덱스 (0–{MAX_RESLOT_INDEX})")
            } else {
                format!("주소 인덱스 (0–{MAX_RESLOT_INDEX})")
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
                format!("주소 형식 ({})", self.yk_network().display_name()),
                CARD_SCRIPTS
                    .into_iter()
                    .enumerate()
                    .map(|(position, script)| {
                        Ctl::radio(
                            ids::reslot_id(key, ReslotAction::Script(script)),
                            &script_label(script),
                            form.script == script,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
        }
        if let Ok(planned) = flow.planned(key, self.yk_network()) {
            items.push(Item::Help(format!("경로: {}", planned.role.path_text())));
        }
    }

    fn yk_reslot_choose_items(&self, flow: &ReslotFlow, items: &mut Vec<Item>) {
        items.push(Item::CardStart(Some("지금 이 YubiKey의 슬롯".to_owned())));
        if let Some(before) = flow.before.as_ref() {
            record_items(before, items);
        }
        items.push(Item::Help(
            "OpenPGP 서명(SIG)·인증(AUT) 두 슬롯만 바꿉니다. PIV(Solana) 슬롯은 그대로입니다."
                .to_owned(),
        ));
        if flow
            .before
            .as_ref()
            .is_some_and(|before| !before.has_known_path())
        {
            items.push(Item::Help(
                "복구 단어 없이 연결한 YubiKey입니다. 바꾸면 SIG·AUT에 입력할 복구 단어의 키가 들어가고 이 YubiKey는 그 복구 단어의 카드가 됩니다. 지금 그 슬롯의 키는 다른 YubiKey에 없으면 영구히 사라집니다(다음 화면에서 확인)."
                    .to_owned(),
            ));
        }
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("새 구성".to_owned())));
        items.push(Item::LabeledRow(
            "조합".to_owned(),
            Preset::ALL
                .into_iter()
                .enumerate()
                .map(|(position, preset)| {
                    Ctl::radio(
                        ids::preset_id(preset),
                        preset.label(),
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
                "Zcash 네트워크".to_owned(),
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
                            zec_network_label(network),
                            flow.zec_network == network,
                            position == 0,
                        )
                    })
                    .collect(),
            ));
        }
        items.push(Item::Help(
            "표준 경로만 씁니다: EVM m/44'/60'/0'/0/i, Bitcoin m/{44|49|84}'/{0|1}'/0'/0/i, Zcash m/44'/{133|1}'/0'/0/i. 터치 정책은 슬롯의 지금 값을 그대로 씁니다."
                .to_owned(),
        ));
        items.push(Item::Row(vec![Ctl::check(
            ids::RESLOT_ADVANCED,
            "고급: EVM 공유 키도 고를 수 있게 하기",
            flow.advanced,
        )]));
        if flow.uses_shared() {
            items.push(Item::Banner(T_YK_SHARED.to_owned(), Tone::Warn));
            items.push(Item::Row(vec![Ctl::check(
                ids::RESLOT_SHARED_ACK,
                "이해했습니다: 공유 키는 두 체인의 신원을 연결할 수 있습니다",
                flow.shared_ack,
            )]));
        }
        items.push(Item::CardEnd);
        items.push(Item::Help(T_YK_RESLOT_WORDS.to_owned()));
        if let Some(error) = &flow.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::primary(
                ids::RESLOT_NEXT,
                if flow.seed_held {
                    "다음 (확인)"
                } else {
                    "다음 (복구 단어 입력)"
                },
            ),
            Ctl::button(ids::MANAGE_CANCEL, "취소"),
        ]));
    }

    #[expect(clippy::too_many_lines, reason = "one screen of the re-slot flow")]
    fn yk_reslot_confirm_items(&self, flow: &ReslotFlow, items: &mut Vec<Item>) {
        let Some(preview) = flow.preview.as_ref() else {
            items.push(Item::CardStart(None));
            items.push(Item::Subtitle("확인 중…".to_owned()));
            items.push(Item::Text(
                "복구 단어에서 새 키의 경로와 주소를 계산하고 있습니다(YubiKey와 통신하지 않음)."
                    .to_owned(),
            ));
            items.push(Item::CardEnd);
            items.push(Item::Row(vec![
                Ctl::button(ids::RESLOT_BACK, "← 다시 고르기"),
                Ctl::button(ids::MANAGE_CANCEL, "취소"),
            ]));
            return;
        };
        if let Err(error) = preview.plan {
            items.push(Item::Banner(error.to_string(), Tone::Danger));
        }
        if preview.same_as_vault {
            items.push(Item::Banner(T_YK_SAME.to_owned(), Tone::HighRisk));
            items.push(Item::Row(vec![Ctl::check(
                ids::RESLOT_SAME_ACK,
                "이해했습니다. 그래도 이 복구 단어의 키를 넣습니다",
                flow.same_ack,
            )]));
        }
        let others = self.yk_other_records(flow.serial);
        items.push(Item::CardStart(Some(format!(
            "바꾼 뒤 YubiKey #{}",
            flow.serial
        ))));
        items.push(Item::Text(
            "아래 경로와 주소는 입력한 복구 단어에서 이 PC가 계산한 값입니다(YubiKey와는 아직 통신하지 않았습니다)."
                .to_owned(),
        ));
        for line in &preview.lines {
            let planned = line.planned;
            slot_items(
                planned.slot,
                planned.role,
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
                (true, _) => "그대로 (지금과 같은 키)".to_owned(),
                (false, true) => "새로 넣음".to_owned(),
                (false, false) => format!(
                    "새로 넣음 — 같은 키를 가진 YubiKey: {} (백업 복사본)",
                    holders_text(&holders)
                ),
            };
            items.push(Item::Field("관계".to_owned(), relation));
        }
        items.push(Item::CardEnd);
        let dropped = flow.dropped(&others);
        if !dropped.is_empty() {
            items.push(Item::CardStart(Some(
                "이 YubiKey에서 빠지는 계정".to_owned(),
            )));
            for (slot, holders) in &dropped {
                let note = match (holders.is_empty(), slot.path_known) {
                    (true, true) => {
                        "다른 YubiKey에 없음 — 바꾼 뒤에는 이 지갑에서 서명할 수 없습니다"
                            .to_owned()
                    }
                    (true, false) => {
                        "복구 단어 없음·다른 YubiKey에도 없음 — 바꾸면 이 키는 영구히 사라집니다"
                            .to_owned()
                    }
                    (false, _) => format!(
                        "{}에 남아 있음 — 그 YubiKey로는 계속 서명할 수 있습니다",
                        holders_text(holders)
                    ),
                };
                items.push(Item::Text(format!(
                    "{} ({}) — {note}",
                    slot.role.title(),
                    slot.path_text()
                )));
            }
            let changed: Vec<CardSlot> = dropped.iter().map(|(slot, _)| slot.slot).collect();
            self.yk_zec_unusable_items(flow.serial, &changed, "바꾼", items);
            // "복구 단어로 언제든 복구" holds only for keys with a known path.
            if dropped.iter().any(|(slot, _)| slot.path_known) {
                items.push(Item::Banner(T_YK_RESLOT_REMOVED.to_owned(), Tone::Warn));
            }
            items.push(Item::Row(vec![Ctl::check(
                ids::RESLOT_REMOVED_ACK,
                "이해했습니다: 빠지는 체인은 이 YubiKey로 서명할 수 없습니다",
                flow.removed_ack,
            )]));
            loss_items(
                &lost_slots(&dropped),
                (ids::RESLOT_LOSS_ACK, ids::RESLOT_LOSS_EDIT),
                (flow.loss_ack, &flow.loss_typed),
                items,
            );
            items.push(Item::CardEnd);
        }
        if let Some(error) = &flow.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Help(T_YK_RESLOT_BACKUP.to_owned()));
        items.push(Item::Help(
            "다음 창에서 OpenPGP 관리자 PIN을 묻습니다(공장 기본값 12345678). 바뀌는 슬롯의 키는 덮어쓰고, 넣은 뒤 YubiKey에서 공개키를 다시 읽어 위 값과 비교합니다."
                .to_owned(),
        ));
        items.push(Item::Row(vec![
            Ctl::primary(ids::RESLOT_IMPORT, "YubiKey에 넣기").enabled(flow.can_import(&others)),
            Ctl::button(ids::RESLOT_BACK, "← 다시 고르기"),
            Ctl::button(ids::MANAGE_CANCEL, "취소"),
        ]));
    }

    fn yk_reslot_result_items(&self, flow: &ReslotFlow, items: &mut Vec<Item>) {
        if let Some(failure) = &flow.failure {
            items.push(Item::Banner(failure.clone(), Tone::Danger));
            items.push(Item::Row(vec![
                Ctl::primary(ids::RESLOT_RETRY, "다시 시도"),
                Ctl::button(ids::RESLOT_BACK, "← 다시 고르기"),
                Ctl::button(ids::MANAGE_CANCEL, "취소"),
            ]));
            return;
        }
        let Some(record) = flow.result.as_ref() else {
            return;
        };
        items.push(Item::Banner(
            format!(
                "YubiKey #{}의 슬롯 구성을 바꿨습니다. YubiKey에서 다시 읽은 공개키가 복구 단어에서 만든 키와 같습니다.",
                record.serial
            ),
            Tone::Success,
        ));
        items.push(Item::CardStart(Some(format!("YubiKey #{}", record.serial))));
        record_items(record, items);
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
                "백업 YubiKey에도 같은 구성 적용".to_owned(),
            )));
            items.push(Item::Text(T_YK_RESLOT_BACKUP.to_owned()));
            items.push(Item::Help(
                "복구 단어는 이 작업을 마칠 때까지만 메모리에 있으므로 다시 묻지 않습니다. 그 YubiKey를 연결하고 고르세요."
                    .to_owned(),
            ));
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
                        format!(
                            "#{}에 같은 구성 적용 (백업: 같은 키 {shared}개)",
                            other.serial
                        )
                    } else {
                        format!("#{}에 같은 구성 적용", other.serial)
                    },
                )]));
            }
            items.push(Item::CardEnd);
        }
        items.push(Item::Row(vec![Ctl::primary(
            ids::MANAGE_DONE,
            "완료 (복구 단어 지우기)",
        )]));
    }

    // ----- YubiKey 비우기 ------------------------------------------------------------------------

    fn yk_clear_method_items(
        current: Option<ClearMethod>,
        (ours, reset): (u16, u16),
        (ours_text, reset_text): (&str, &str),
        items: &mut Vec<Item>,
    ) {
        let Some(method) = current else {
            return;
        };
        items.push(Item::LabeledRow(
            "방법".to_owned(),
            vec![
                Ctl::radio(
                    ours,
                    "이 지갑의 슬롯만 지우기",
                    method == ClearMethod::OurSlots,
                    true,
                ),
                Ctl::radio(
                    reset,
                    "애플릿 초기화 (PIN도 공장 기본값)",
                    method == ClearMethod::Reset,
                    false,
                ),
            ],
        ));
        items.push(Item::Help(
            if method == ClearMethod::OurSlots {
                ours_text
            } else {
                reset_text
            }
            .to_owned(),
        ));
    }

    /// The wallet's Zcash accounts whose key only `slots` of card `serial` hold
    /// (`App::zec_accounts_using_card`): clearing or re-slotting them leaves the Zcash tab
    /// without a signing key (spec/10 §15, spec/12).
    fn yk_zec_unusable_items(
        &self,
        serial: u32,
        slots: &[CardSlot],
        action: &str,
        items: &mut Vec<Item>,
    ) {
        for account in self.zec_accounts_using_card(serial, slots) {
            items.push(Item::Banner(
                format!(
                    "Zcash 계정 {} — 이 YubiKey의 이 슬롯에만 있는 키입니다. {action} 뒤에는 Zcash 탭에서 이 주소로 보낼 수 없습니다(잔액이 있으면 먼저 옮기세요).",
                    account.address()
                ),
                Tone::HighRisk,
            ));
        }
    }

    #[expect(clippy::too_many_lines, reason = "one screen of the clear flow")]
    fn yk_clear_items(&self, flow: &ClearFlow, items: &mut Vec<Item>) {
        items.push(Item::Subtitle(format!(
            "YubiKey 비우기 — YubiKey #{}",
            flow.serial
        )));
        let Some(before) = flow.before.as_ref() else {
            return;
        };
        match flow.step {
            ClearStep::Running => {
                items.push(Item::CardStart(None));
                items.push(Item::Subtitle("YubiKey를 비우는 중입니다".to_owned()));
                items.push(Item::Text("YubiKey를 빼지 마세요.".to_owned()));
                items.push(Item::CardEnd);
                return;
            }
            ClearStep::Result => {
                Self::yk_clear_result_items(flow, items);
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
        items.push(Item::CardStart(Some("무엇을 비울까요?".to_owned())));
        if has(true) > 0 {
            items.push(Item::Row(vec![Ctl::check(
                ids::CLEAR_PGP_TOGGLE,
                &format!(
                    "OpenPGP 지갑 키 (SIG/AUT: EVM·Bitcoin·Zcash, {}개)",
                    has(true)
                ),
                flow.openpgp.is_some(),
            )]));
            Self::yk_clear_method_items(
                flow.openpgp,
                (ids::CLEAR_PGP_OURS, ids::CLEAR_PGP_RESET),
                (T_YK_CLEAR_PGP_OURS, T_YK_CLEAR_PGP_RESET),
                items,
            );
        }
        if has(false) > 0 {
            items.push(Item::Row(vec![Ctl::check(
                ids::CLEAR_PIV_TOGGLE,
                &format!("PIV Solana 슬롯 ({}개)", has(false)),
                flow.piv.is_some(),
            )]));
            Self::yk_clear_method_items(
                flow.piv,
                (ids::CLEAR_PIV_OURS, ids::CLEAR_PIV_RESET),
                (T_YK_CLEAR_PIV_OURS, T_YK_CLEAR_PIV_RESET),
                items,
            );
            if flow.piv == Some(ClearMethod::OurSlots)
                && !before
                    .firmware
                    .at_least(yw_core::yubikey::piv::DOCUMENTED_FIRMWARE_DELETE_KEY)
            {
                items.push(Item::Help(format!(
                    "이 YubiKey의 등록 때 펌웨어는 {}입니다. Yubico는 PIV 키 삭제를 5.7.4부터 문서화했습니다. 카드가 거부하면 'PIV 애플릿 초기화'를 쓰세요.",
                    before.firmware
                )));
            }
        }
        items.push(Item::Help(T_YK_CLEAR_SCOPE.to_owned()));
        items.push(Item::CardEnd);
        let plan = flow.plan();
        if plan.any() {
            let others = self.yk_other_records(flow.serial);
            items.push(Item::CardStart(Some(
                "이 YubiKey로 쓸 수 없게 되는 계정".to_owned(),
            )));
            for slot in before.slots.iter().filter(|slot| plan.clears(slot.slot)) {
                let holders = crate::yubikey::holders(&others, slot.role);
                let note = if holders.is_empty() && !slot.path_known {
                    "복구 단어 없음·다른 YubiKey에도 없음 — 비우면 이 키는 영구히 사라집니다"
                        .to_owned()
                } else if holders.is_empty() {
                    "다른 YubiKey에 없음 — 이 지갑의 계정 목록에서 빠집니다(같은 복구 단어로 다시 넣으면 돌아옵니다)".to_owned()
                } else {
                    format!(
                        "{}에도 있음 — 그 YubiKey로는 계속 서명할 수 있습니다",
                        holders_text(&holders)
                    )
                };
                items.push(Item::Text(format!(
                    "{} — {} ({}) — {note}",
                    slot.slot.label(),
                    slot.role.title(),
                    slot.path_text()
                )));
                for address in address_texts(slot.role, &slot.public).unwrap_or_default() {
                    items.push(Item::Mono(address));
                }
            }
            let cleared: Vec<CardSlot> = before
                .slots
                .iter()
                .filter(|slot| plan.clears(slot.slot))
                .map(|slot| slot.slot)
                .collect();
            self.yk_zec_unusable_items(flow.serial, &cleared, "비운", items);
            // "복구 단어로 언제든 복구" holds only for keys with a known path.
            if before
                .slots
                .iter()
                .any(|slot| plan.clears(slot.slot) && slot.path_known)
            {
                items.push(Item::Banner(T_YK_CLEAR_FUNDS.to_owned(), Tone::Warn));
            }
            loss_items(
                &self.yk_clear_lost(flow),
                (ids::CLEAR_LOSS_ACK, ids::CLEAR_LOSS_EDIT),
                (flow.loss_ack, &flow.loss_typed),
                items,
            );
            if plan.remaining(before).is_none() {
                items.push(Item::Help(
                    "이 YubiKey에 지갑 슬롯이 하나도 남지 않으므로 이 YubiKey 기록을 지갑에서 지웁니다."
                        .to_owned(),
                ));
            }
            if plan.openpgp == Some(ClearMethod::Reset) || plan.piv == Some(ClearMethod::Reset) {
                items.push(Item::Banner(
                    "초기화는 그 애플릿의 다른 키(GPG·PIV 인증서 등 이 지갑이 쓰지 않은 것 포함)도 모두 지우고 PIN을 공장 기본값으로 되돌립니다. 되돌릴 수 없습니다."
                        .to_owned(),
                    Tone::HighRisk,
                ));
            }
            items.push(Item::CardEnd);
        }
        if !self.yk_clear_allowed(flow) {
            items.push(Item::Banner(
                "이 YubiKey가 이 지갑의 마지막 키입니다. 모두 비우면 지갑에 남는 키가 없으므로 비울 수 없습니다. 다른 YubiKey를 먼저 등록하세요."
                    .to_owned(),
                Tone::Danger,
            ));
        }
        items.push(Item::LabeledRow(
            format!("확인: '{CLEAR_WORD}' 입력"),
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
            asks.push("OpenPGP 관리자 PIN");
        }
        if plan.piv == Some(ClearMethod::OurSlots) {
            asks.push("PIV PIN");
        }
        items.push(Item::Help(if asks.is_empty() {
            "초기화는 PIN을 묻지 않습니다(PIN을 일부러 잠근 뒤 초기화합니다).".to_owned()
        } else {
            format!(
                "다음 창에서 {}을(를) 묻습니다. 이 작업에만 쓰고 바로 지웁니다.",
                asks.join(", ")
            )
        }));
        if let Some(error) = &flow.error {
            items.push(Item::Banner(error.clone(), Tone::Danger));
        }
        items.push(Item::Row(vec![
            Ctl::danger(ids::CLEAR_RUN, "비우기").enabled(self.yk_clear_ready(flow)),
            Ctl::button(ids::MANAGE_CANCEL, "취소"),
        ]));
    }

    fn yk_clear_result_items(flow: &ClearFlow, items: &mut Vec<Item>) {
        if let Some(failure) = &flow.failure {
            items.push(Item::Banner(failure.clone(), Tone::Danger));
        }
        if let Some(cleared) = flow.result {
            let line =
                |name: &str,
                 asked: Option<ClearMethod>,
                 result: Option<Result<(), yw_core::yubikey::CardError>>| {
                    match (asked, result) {
                        (Some(ClearMethod::OurSlots), Some(Ok(()))) => Some((
                            format!("{name}: 이 지갑의 슬롯을 지웠습니다."),
                            Tone::Success,
                        )),
                        (Some(ClearMethod::Reset), Some(Ok(()))) => Some((
                            format!("{name}: 공장 상태로 초기화했습니다 (PIN도 기본값)."),
                            Tone::Success,
                        )),
                        (Some(_), Some(Err(error))) => {
                            Some((format!("{name}: 실패 — {error}"), Tone::Danger))
                        }
                        (Some(_), None) => Some((
                            format!("{name}: 앞 단계가 실패해 하지 않았습니다."),
                            Tone::Warn,
                        )),
                        (None, _) => None,
                    }
                };
            for (text, tone) in [
                line("OpenPGP", cleared.asked.openpgp, cleared.report.openpgp),
                line("PIV", cleared.asked.piv, cleared.report.piv),
            ]
            .into_iter()
            .flatten()
            {
                items.push(Item::Banner(text, tone));
            }
            match cleared.vault {
                Ok(()) if cleared.removed => items.push(Item::Text(
                    "이 YubiKey에 지갑 슬롯이 남지 않아 기록을 지웠습니다.".to_owned(),
                )),
                Ok(()) => items.push(Item::Text(
                    "지운 슬롯을 이 지갑의 슬롯 표에서 뺐습니다.".to_owned(),
                )),
                Err(error) => items.push(Item::Banner(
                    format!(
                        "YubiKey는 바뀌었지만 지갑의 슬롯 표를 고치지 못했습니다: {}",
                        crate::errors::vault_code(error).text()
                    ),
                    Tone::Danger,
                )),
            }
            let done = cleared.report.done(cleared.asked);
            if done.openpgp == Some(ClearMethod::Reset) || done.piv == Some(ClearMethod::Reset) {
                items.push(Item::Help(
                    "초기화한 애플릿의 PIN은 공장 기본값입니다(OpenPGP 123456 / 12345678, PIV 123456 / 12345678). 다시 쓰려면 등록한 뒤 'PIN 설정'에서 바꾸세요."
                        .to_owned(),
                ));
            }
            let known_cleared = flow.before.as_ref().is_some_and(|before| {
                before
                    .slots
                    .iter()
                    .any(|slot| cleared.asked.clears(slot.slot) && slot.path_known)
            });
            if known_cleared {
                items.push(Item::Help(T_YK_CLEAR_FUNDS.to_owned()));
            }
        }
        items.push(Item::Row(vec![Ctl::primary(ids::MANAGE_DONE, "완료")]));
    }
}
