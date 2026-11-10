//! Imported-key screens (spec/04 §2.18): the S01 card "개인키로 시작하기", S18 (chain and address
//! type), S19 (address confirmation), the empty-chain card of a key-only wallet, and the imported
//! key part of the Bitcoin account card (`개인키 가져오기` with its address-type radios, `개인키
//! 보기`·`삭제` of the selected imported account; the accounts themselves are rows of the normal
//! Bitcoin account list with the "[가져온 키]" badge). Fixed sentences are the T-KEY-* rows of
//! spec/04 §2.16.

use yw_core::btc::{BtcNetwork, ScriptType};
use yw_core::keyimport::ImportChain;

use crate::app::App;
use crate::app_btc::BtcCtx;
use crate::app_keys::{KEY_START_STEPS, KeyStartView};
use crate::ui::main_window::{Ctl, Item, Tone};
use crate::ui::screens::steps;

/// Command ids (block 13,000–13,199, `ui::command_ids`).
pub mod ids {
    use yw_core::btc::ScriptType;

    /// S01 개인키로 시작하기.
    pub const FIRST_KEY: u16 = 13_000;
    /// S18 chain radio: EVM.
    pub const START_CHAIN_EVM: u16 = 13_001;
    /// S18 chain radio: Solana.
    pub const START_CHAIN_SOL: u16 = 13_002;
    /// S18 chain radio: Bitcoin.
    pub const START_CHAIN_BTC: u16 = 13_003;
    /// S18 시작하기.
    pub const START_NEXT: u16 = 13_004;
    /// S19 맞습니다.
    pub const START_CORRECT: u16 = 13_005;
    /// S19 다릅니다.
    pub const START_WRONG: u16 = 13_006;
    /// Script-type radios (S18 and the Bitcoin tab), `SCRIPT_BASE + id − 1` for ids 1–4.
    pub const SCRIPT_BASE: u16 = 13_010;
    /// Solana tab 개인키 가져오기.
    pub const SOL_IMPORT: u16 = 13_020;
    /// Bitcoin tab 개인키 가져오기.
    pub const BTC_IMPORT: u16 = 13_021;
    /// Selected imported Solana account: 개인키 보기.
    pub const SOL_REVEAL: u16 = 13_022;
    /// Selected imported Solana account: 삭제.
    pub const SOL_REMOVE: u16 = 13_023;
    /// Selected imported Bitcoin account: 개인키 보기 (WIF).
    pub const BTC_REVEAL: u16 = 13_024;
    /// Selected imported Bitcoin account: 삭제.
    pub const BTC_REMOVE: u16 = 13_025;
    /// Bitcoin tab: `다음 (개인키 입력)` of the opened address-type chooser (W07); also the
    /// primary button of a key-only wallet's empty Bitcoin card.
    pub const BTC_IMPORT_NEXT: u16 = 13_026;
    /// Bitcoin tab: `취소` of the opened address-type chooser.
    pub const BTC_IMPORT_CANCEL: u16 = 13_027;

    /// Every fixed id of this module.
    pub const FIXED: &[u16] = &[
        FIRST_KEY,
        START_CHAIN_EVM,
        START_CHAIN_SOL,
        START_CHAIN_BTC,
        START_NEXT,
        START_CORRECT,
        START_WRONG,
        SCRIPT_BASE,
        SCRIPT_BASE + 1,
        SCRIPT_BASE + 2,
        SCRIPT_BASE + 3,
        SOL_IMPORT,
        BTC_IMPORT,
        SOL_REVEAL,
        SOL_REMOVE,
        BTC_REVEAL,
        BTC_REMOVE,
        BTC_IMPORT_NEXT,
        BTC_IMPORT_CANCEL,
    ];

    /// The radio id of an address type (its stable code 1–4).
    #[must_use]
    pub const fn script_id(script: ScriptType) -> u16 {
        SCRIPT_BASE + script.code() as u16 - 1
    }

    /// The address type of a radio id.
    #[must_use]
    pub fn script_of(id: u16) -> Option<ScriptType> {
        let offset = id.checked_sub(SCRIPT_BASE).filter(|offset| *offset < 4)?;
        ScriptType::from_code(u8::try_from(offset).ok()?.checked_add(1)?)
    }
}

/// T-KEYSTART-1 (S01 card): what "개인키로 시작하기" makes.
pub const T_KEY_START_CARD: &str = "MetaMask·Phantom·Electrum 등에서 내보낸 개인키 하나로 지갑을 만듭니다. 복구 단어(24단어)는 만들지 않습니다.";
/// T-KEYSTART-BACKUP (S18, S19): the backup is the original private key.
pub const T_KEY_START_BACKUP: &str = "복구 단어 없이 개인키로 지갑을 만듭니다. 이 지갑의 백업은 지금 입력할 원래 개인키뿐입니다. 이 PC나 지갑 파일을 잃으면 원래 개인키로만 되살릴 수 있으니, 원래 개인키를 종이 등 안전한 곳에 따로 보관하세요.";
/// T-KEYSTART-OK (S08 after the flow).
pub const T_KEY_START_OK: &str = "개인키로 지갑을 만들었습니다. 이제 지갑을 쓸 수 있습니다.";
/// T-KEYSTART-SCRIPT (S18, Bitcoin tab): which address type to pick.
pub const T_BTC_SCRIPT: &str = "이전 지갑에서 이 키로 쓰던 주소와 같은 형식을 고르세요. 다음 화면에서 주소를 보고 확인합니다. 5·9로 시작하는 압축되지 않은 WIF는 P2PKH(레거시)만 쓸 수 있습니다.";
/// T-BTC-IMPORTED (Bitcoin account card): what an imported key's account is.
pub const T_BTC_IMPORTED: &str = "가져온 개인키는 Bitcoin 계정 목록에 \"[가져온 키]\"로 보입니다. 주소 하나만 쓰고(잔돈도 같은 주소로 돌아옴) 복구 단어로 복구되지 않습니다. 잔액·받기·보내기는 다른 계정과 같습니다.";
/// The closed Bitcoin-tab import row: what `개인키 가져오기` is for.
pub const T_BTC_IMPORT_HINT: &str = "다른 지갑에서 쓰던 Bitcoin 개인키(WIF)도 이 목록에 더할 수 있습니다. 누르면 주소 형식을 고릅니다.";
/// T-REMOVE-IMPORTED (S10 overlay for Solana/Bitcoin imported keys).
pub const T_REMOVE_IMPORTED: &str = "선택한 가져온 개인키 계정을 이 지갑에서 지웁니다. 가져온 개인키는 복구 단어로 복구되지 않으므로, 지우고 나면 원래 개인키 없이는 이 계정의 자산에 다시 접근할 수 없습니다. 지우기 전에 이 계정의 '개인키 보기'로 개인키를 내보내 안전하게 보관했는지 확인하세요. 계속하려면 비밀번호를 입력하세요.";

/// "이 지갑에는 {체인} 계정이 없습니다".
#[must_use]
pub fn no_accounts_text(chain: ImportChain) -> String {
    format!("이 지갑에는 {} 계정이 없습니다.", chain.name())
}

fn chain_help(chain: ImportChain) -> &'static str {
    match chain {
        ImportChain::Evm => {
            "16진수 64자리 개인키(0x 선택) — MetaMask·Rabby의 '개인키 내보내기' 값입니다. 모든 EVM 체인(기본 7개와 직접 추가한 체인)에서 같은 주소로 쓰입니다."
        }
        ImportChain::Sol => {
            "Phantom·Solflare의 '개인키 내보내기'(base58) 또는 solana-keygen JSON 파일의 내용입니다."
        }
        ImportChain::Btc => {
            "WIF 형식(5·K·L로 시작하면 mainnet, 9·c로 시작하면 testnet4) — Electrum 'Export private key', Bitcoin Core dumpprivkey 값입니다."
        }
        ImportChain::Zec => {
            "압축 WIF(K·L로 시작하면 mainnet, c로 시작하면 testnet) 또는 16진수 64자리 — zcashd dumpprivkey 값입니다. 일반(transparent) 주소 하나로 씁니다."
        }
    }
}

/// The label of an address type for an imported key: plain name (as in `계정 추가`), the mainnet
/// prefix and the technical name — `네이티브 세그윗 (bc1q…, P2WPKH)` (the network comes from the
/// WIF).
#[must_use]
pub fn script_choice_label(script: ScriptType) -> String {
    format!(
        "{} ({}, {})",
        script.name(),
        script.prefix(BtcNetwork::Mainnet),
        script.technical()
    )
}

/// The four address-type radios (account chooser order: native segwit first).
fn script_radios(selected: ScriptType) -> Item {
    Item::LabeledRow(
        "주소 형식".to_owned(),
        ScriptType::CHOICES
            .into_iter()
            .enumerate()
            .map(|(index, script)| {
                Ctl::radio(
                    ids::script_id(script),
                    &script_choice_label(script),
                    script == selected,
                    index == 0,
                )
            })
            .collect(),
    )
}

impl App {
    /// S18: chain (and Bitcoin script type) before W01.
    pub fn key_start_intro(&self, items: &mut Vec<Item>) {
        let flow = &self.keys.start;
        items.push(Item::Title("개인키로 시작하기".to_owned()));
        items.push(steps(KEY_START_STEPS, 0));
        items.push(Item::CardStart(Some(
            "어떤 체인의 개인키입니까?".to_owned(),
        )));
        items.push(Item::LabeledRow(
            "체인".to_owned(),
            vec![
                Ctl::radio(
                    ids::START_CHAIN_EVM,
                    "EVM (이더리움 등)",
                    flow.chain == ImportChain::Evm,
                    true,
                ),
                Ctl::radio(
                    ids::START_CHAIN_SOL,
                    "Solana",
                    flow.chain == ImportChain::Sol,
                    false,
                ),
                Ctl::radio(
                    ids::START_CHAIN_BTC,
                    "Bitcoin",
                    flow.chain == ImportChain::Btc,
                    false,
                ),
            ],
        ));
        items.push(Item::Help(chain_help(flow.chain).to_owned()));
        if flow.chain == ImportChain::Btc {
            items.push(script_radios(flow.script));
            items.push(Item::Help(T_BTC_SCRIPT.to_owned()));
        }
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some("이 지갑의 백업".to_owned())));
        items.push(Item::Banner(T_KEY_START_BACKUP.to_owned(), Tone::Warn));
        items.push(Item::Help(
            "개인키로 시작한 지갑에서는 복구 단어로 계정을 더 만드는 기능(계정 추가·복구 단어 보기)이 없습니다. 메인 화면의 '개인키 가져오기'로 다른 개인키를 더할 수 있습니다(체인마다 최대 15개)."
                .to_owned(),
        ));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(ids::START_NEXT, "시작하기"),
            Ctl::button(crate::ui::screens::ids::INTRO_CANCEL, "취소"),
        ]));
    }

    /// S19: the address of the entered key.
    pub fn key_start_address(view: &KeyStartView, items: &mut Vec<Item>) {
        items.push(Item::Title("주소 확인".to_owned()));
        items.push(steps(KEY_START_STEPS, 3));
        items.push(Item::CardStart(None));
        items.push(Item::Text(format!(
            "입력한 개인키의 {} 주소입니다. 이전 지갑에서 쓰던 주소와 전체가 같은지 확인하세요.",
            view.chain.name()
        )));
        if let Some((script, network)) = view.btc {
            items.push(Item::Field(
                "주소 형식".to_owned(),
                format!(
                    "{} ({}, {})",
                    script.name(),
                    script.prefix(network),
                    script.technical()
                ),
            ));
            items.push(Item::Field(
                "네트워크".to_owned(),
                network.display_name().to_owned(),
            ));
        }
        // In 4-character groups like every other address (spec/04 §3.3): EVM in its checksum
        // groups, Solana and Bitcoin as encoded.
        items.push(Item::Mono(match view.chain {
            ImportChain::Evm => yw_core::evm::address::parse_address(&view.address).map_or_else(
                |_| view.address.clone(),
                |parsed| yw_core::evm::display::format_address(&parsed),
            ),
            _ => crate::ui::screens_btc::grouped(&view.address),
        }));
        items.push(Item::CardEnd);
        items.push(Item::Banner(T_KEY_START_BACKUP.to_owned(), Tone::Warn));
        items.push(Item::Row(vec![
            Ctl::primary(ids::START_CORRECT, "맞습니다"),
            Ctl::button(ids::START_WRONG, "다릅니다"),
        ]));
        items.push(Item::Help(
            "다르면 '다릅니다'를 눌러 개인키를 다시 입력하세요. Bitcoin은 주소 형식이 다르면 주소도 다릅니다 — 앞 화면에서 형식을 바꿀 수 있습니다."
                .to_owned(),
        ));
    }

    /// A chain tab without any account in a key-only wallet.
    pub fn no_accounts_card(&self, chain: ImportChain, items: &mut Vec<Item>) {
        let import_id = match chain {
            ImportChain::Evm => crate::ui::screens::ids::IMPORT_KEY,
            ImportChain::Sol => ids::SOL_IMPORT,
            ImportChain::Btc => ids::BTC_IMPORT_NEXT,
            ImportChain::Zec => crate::ui::screens_zec::ids::IMPORT,
        };
        items.push(Item::CardStart(None));
        items.push(Item::Subtitle(no_accounts_text(chain)));
        items.push(Item::Text(if self.card.records.is_empty() {
            "이 지갑은 개인키로 시작해 복구 단어가 없습니다. 이 체인을 쓰려면 그 체인의 개인키를 가져오세요."
                .to_owned()
        } else {
            "이 YubiKey 지갑에는 복구 단어가 저장되어 있지 않습니다. 이 체인을 쓰려면 같은 복구 단어로 YubiKey에 이 체인의 키를 등록하거나(설정 → YubiKey), 그 체인의 개인키를 가져오세요."
                .to_owned()
        }));
        items.push(Item::Help(chain_help(chain).to_owned()));
        if chain == ImportChain::Btc {
            items.push(script_radios(self.keys.btc_script));
            items.push(Item::Help(T_BTC_SCRIPT.to_owned()));
        }
        let unlocked = matches!(self.mode, crate::app::AppMode::Unlocked { .. });
        items.push(Item::Row(vec![
            Ctl::primary(import_id, "개인키 가져오기").enabled(self.can_import(chain)),
            Ctl::button(crate::ui::screens_yubikey::ids::ENROL_START, "YubiKey 등록")
                .enabled(unlocked && self.card.records.len() < yw_core::yubikey::plan::MAX_CARDS),
            Ctl::button(
                crate::ui::screens_yubikey::ids::CONNECT_START,
                "YubiKey 연결하기 (복구 단어 없이)",
            )
            .enabled(unlocked && self.card.records.len() < yw_core::yubikey::plan::MAX_CARDS),
        ]));
        // Every account of the tab hidden (a `YubiKey` wallet): the way back is here too.
        let family = match chain {
            ImportChain::Evm => Some(crate::app_hidden::Family::Evm),
            ImportChain::Sol => Some(crate::app_hidden::Family::Sol),
            ImportChain::Btc | ImportChain::Zec => None,
        };
        if let Some(family) = family {
            self.hidden_items(family, items);
        }
        items.push(Item::CardEnd);
    }

    /// The imported-key part of the Bitcoin account card (inside the card, after the account
    /// rows): for the selected imported account its backup note and `개인키 보기`·`삭제`; then
    /// `개인키 가져오기` with the address-type radios.
    pub fn btc_imported_items(&self, ctx: &BtcCtx<'_>, items: &mut Vec<Item>) {
        let unlocked = matches!(self.mode, crate::app::AppMode::Unlocked { .. });
        if ctx.selected_imported().is_some() {
            items.push(Item::Help(if self.key_only() {
                crate::ui::secret::T_KEY_ONLY_BACKUP.to_owned()
            } else {
                crate::ui::secret::T_IMPORTED_KEY_BACKUP.to_owned()
            }));
            items.push(Item::Row(vec![
                Ctl::button(ids::BTC_REVEAL, "개인키 보기").enabled(unlocked),
                Ctl::danger(ids::BTC_REMOVE, "삭제")
                    .enabled(unlocked && self.can_remove_imported()),
            ]));
        } else if ctx.selected_evm_shared().is_some() {
            // An account on an EVM account's key (spec/08 §3.5): its WIF can be exported; it is
            // not a vault record, so there is nothing to delete.
            items.push(Item::Help(crate::app_btc::T_BTC_EVM_SHARED.to_owned()));
            items.push(Item::Row(vec![
                Ctl::button(ids::BTC_REVEAL, "개인키 보기").enabled(unlocked),
            ]));
        }
        items.push(Item::Rule);
        if !self.keys.btc_import_open {
            // Closed by default, like `계정 추가`: one short line and the button; the address
            // type chooser opens on demand (an uncommon action that used to fill the card).
            items.push(Item::Help(T_BTC_IMPORT_HINT.to_owned()));
            items.push(Item::Row(vec![
                Ctl::button(ids::BTC_IMPORT, "개인키 가져오기")
                    .enabled(self.can_import(ImportChain::Btc)),
            ]));
            return;
        }
        items.push(Item::Help(T_BTC_IMPORTED.to_owned()));
        items.push(script_radios(self.keys.btc_script));
        items.push(Item::Help(T_BTC_SCRIPT.to_owned()));
        items.push(Item::Row(vec![
            Ctl::primary(ids::BTC_IMPORT_NEXT, "다음 (개인키 입력)")
                .enabled(self.can_import(ImportChain::Btc)),
            Ctl::button(ids::BTC_IMPORT_CANCEL, "취소"),
        ]));
    }
}
