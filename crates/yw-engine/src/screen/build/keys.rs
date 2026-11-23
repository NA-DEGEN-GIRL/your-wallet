//! Imported-key screens (spec/04 §2.18): the S01 card "개인키로 시작하기", S18 (chain and address
//! type), S19 (address confirmation), the empty-chain card of a key-only wallet, and the imported
//! key part of the Bitcoin account card (`개인키 가져오기` with its address-type radios, `개인키
//! 보기`·`삭제` of the selected imported account; the accounts themselves are rows of the normal
//! Bitcoin account list with the "[가져온 키]" badge). Fixed sentences are the T-KEY-* rows of
//! spec/04 §2.16.
//!
//! 2026-11-24 (spec/15 §11.2, §11.4 S5-5): moved here from yw-app `ui/screens_keys.rs` with the
//! bodies unchanged (`impl App` builders became `impl Screen<'_>`, yw-app paths engine paths); its
//! control ids stay there (`ui::screens_keys::ids`).

use yw_core::btc::{BtcNetwork, ScriptType};
use yw_core::keyimport::ImportChain;
use yw_core::lang::{Lang, Text};

use super::Screen;
use crate::cmd::{CorePress, KeysPress, Press, YkConnectPress, YkPress, ZecPress};
use crate::screen::Tone;
use crate::screen::build::core::steps;
use crate::screen::model::{Ctl, Item};
use crate::wallet::app_btc::BtcCtx;
use crate::wallet::app_keys::{KEY_START_STEPS, KeyStartView};

/// The imported-key screen texts (spec/04 §2.18, T-KEYSTART-*, T-BTC-IMPORTED,
/// T-REMOVE-IMPORTED).
pub mod text {
    yw_core::texts! {
        /// T-KEYSTART-1 (S01 card): what "개인키로 시작하기" makes.
        KEY_START_CARD = "MetaMask·Phantom·Electrum 등에서 내보낸 개인키 하나로 지갑을 만듭니다. 복구 단어(24단어)는 만들지 않습니다."
            / "Makes a wallet from one private key exported from MetaMask, Phantom, Electrum and others. No recovery words (24 words) are created.";
        /// T-KEYSTART-BACKUP (S18, S19): the backup is the original private key.
        KEY_START_BACKUP = "복구 단어 없이 개인키로 지갑을 만듭니다. 이 지갑의 백업은 지금 입력할 원래 개인키뿐입니다. 이 PC나 지갑 파일을 잃으면 원래 개인키로만 되살릴 수 있으니, 원래 개인키를 종이 등 안전한 곳에 따로 보관하세요."
            / "This makes a wallet from a private key, without recovery words. Its only backup is the original private key you are about to enter. If you lose this PC or the wallet file, only the original private key can restore it, so keep the original private key separately in a safe place, such as on paper.";
        /// T-KEYSTART-OK (S08 after the flow).
        KEY_START_OK = "개인키로 지갑을 만들었습니다. 이제 지갑을 쓸 수 있습니다."
            / "The wallet was created from the private key. You can use the wallet now.";
        /// T-KEYSTART-SCRIPT (S18, Bitcoin tab): which address type to pick.
        BTC_SCRIPT = "이전 지갑에서 이 키로 쓰던 주소와 같은 형식을 고르세요. 다음 화면에서 주소를 보고 확인합니다. 5·9로 시작하는 압축되지 않은 WIF는 P2PKH(레거시)만 쓸 수 있습니다."
            / "Choose the same address type you used with this key in your previous wallet. The next screen shows the address so you can check it. An uncompressed WIF starting with 5 or 9 can only use P2PKH (legacy).";
        /// T-BTC-IMPORTED (Bitcoin account card): what an imported key's account is.
        BTC_IMPORTED = "가져온 개인키는 Bitcoin 계정 목록에 \"[가져온 키]\"로 보입니다. 주소 하나만 쓰고(잔돈도 같은 주소로 돌아옴) 복구 단어로 복구되지 않습니다. 잔액·받기·보내기는 다른 계정과 같습니다."
            / "An imported private key appears in the Bitcoin account list as \"[imported key]\". It uses a single address (change comes back to the same address) and cannot be restored from recovery words. Balance, receive and send work like other accounts.";
        /// The closed Bitcoin-tab import row: what `개인키 가져오기` is for.
        BTC_IMPORT_HINT = "다른 지갑에서 쓰던 Bitcoin 개인키(WIF)도 이 목록에 더할 수 있습니다. 누르면 주소 형식을 고릅니다."
            / "You can also add a Bitcoin private key (WIF) from another wallet to this list. Press the button to choose the address type.";
        /// T-REMOVE-IMPORTED (S10 overlay for Solana/Bitcoin imported keys).
        REMOVE_IMPORTED = "선택한 가져온 개인키 계정을 이 지갑에서 지웁니다. 가져온 개인키는 복구 단어로 복구되지 않으므로, 지우고 나면 원래 개인키 없이는 이 계정의 자산에 다시 접근할 수 없습니다. 지우기 전에 이 계정의 '개인키 보기'로 개인키를 내보내 안전하게 보관했는지 확인하세요. 계속하려면 비밀번호를 입력하세요."
            / "Deletes the selected imported private-key account from this wallet. Imported private keys cannot be restored from recovery words, so once deleted, this account's assets cannot be reached again without the original private key. Before deleting, make sure you exported the private key with this account's 'Show private key' and stored it safely. Enter your password to continue.";
        NO_ACCOUNTS(1) = "이 지갑에는 {0} 계정이 없습니다." / "This wallet has no {0} account.";
        HELP_EVM = "16진수 64자리 개인키(0x 선택) — MetaMask·Rabby의 '개인키 내보내기' 값입니다. 모든 EVM 체인(기본 7개와 직접 추가한 체인)에서 같은 주소로 쓰입니다."
            / "A private key of 64 hexadecimal characters (0x optional) — the value of 'Export private key' in MetaMask or Rabby. It has the same address on every EVM chain (the 7 built-in ones and chains you added).";
        HELP_SOL = "Phantom·Solflare의 '개인키 내보내기'(base58) 또는 solana-keygen JSON 파일의 내용입니다."
            / "The 'Export private key' value (base58) from Phantom or Solflare, or the contents of a solana-keygen JSON file.";
        HELP_BTC = "WIF 형식(5·K·L로 시작하면 mainnet, 9·c로 시작하면 testnet4) — Electrum 'Export private key', Bitcoin Core dumpprivkey 값입니다."
            / "WIF format (starting with 5, K or L: mainnet; 9 or c: testnet4) — the value of Electrum's 'Export private key' or Bitcoin Core's dumpprivkey.";
        HELP_ZEC = "압축 WIF(K·L로 시작하면 mainnet, c로 시작하면 testnet) 또는 16진수 64자리 — zcashd dumpprivkey 값입니다. 일반(transparent) 주소 하나로 씁니다."
            / "A compressed WIF (starting with K or L: mainnet; c: testnet) or 64 hexadecimal characters — the value of zcashd dumpprivkey. It is used as one regular (transparent) address.";
        ADDRESS_TYPE = "주소 형식" / "Address type";
        TITLE = "개인키로 시작하기" / "Start with a private key";
        WHICH_CHAIN = "어떤 체인의 개인키입니까?" / "Which chain is the private key for?";
        CHAIN = "체인" / "Chain";
        EVM_RADIO = "EVM (이더리움 등)" / "EVM (Ethereum and others)";
        BACKUP_TITLE = "이 지갑의 백업" / "This wallet's backup";
        NO_ADD_ACCOUNT = "복구 단어가 없어 “계정 추가”는 없습니다 — 나중에 설정 → 복구 단어에서 더하면 생깁니다. 메인 화면의 '개인키 가져오기'로 다른 개인키를 더할 수 있습니다(체인마다 최대 15개)."
            / "Without recovery words there is no “Add account” — it appears if you add recovery words later in Settings → Recovery words. You can add other private keys with 'Import private key' on the main screen (up to 15 per chain).";
        START = "시작하기" / "Start";
        CANCEL = "취소" / "Cancel";
        ADDRESS_TITLE = "주소 확인" / "Check the address";
        ADDRESS_LEAD(1) = "입력한 개인키의 {0} 주소입니다. 이전 지갑에서 쓰던 주소와 전체가 같은지 확인하세요."
            / "This is the {0} address of the private key you entered. Check that all of it matches the address from your previous wallet.";
        NETWORK = "네트워크" / "Network";
        CORRECT = "맞습니다" / "It matches";
        WRONG = "다릅니다" / "It differs";
        WRONG_HELP = "다르면 '다릅니다'를 눌러 개인키를 다시 입력하세요. Bitcoin은 주소 형식이 다르면 주소도 다릅니다 — 앞 화면에서 형식을 바꿀 수 있습니다."
            / "If it differs, press 'It differs' and enter the private key again. For Bitcoin, a different address type gives a different address — you can change the type on the previous screen.";
        KEY_ONLY_NOTE = "이 지갑은 개인키로 시작해 복구 단어가 없습니다. 이 체인을 쓰려면 그 체인의 개인키를 가져오세요."
            / "This wallet was started from a private key and has no recovery words. To use this chain, import a private key for it.";
        YUBIKEY_NOTE = "이 YubiKey 지갑에는 복구 단어가 저장되어 있지 않습니다. 이 체인을 쓰려면 같은 복구 단어로 YubiKey에 이 체인의 키를 등록하거나(설정 → YubiKey), 그 체인의 개인키를 가져오세요."
            / "This YubiKey wallet stores no recovery words. To use this chain, enrol this chain's key on a YubiKey with the same recovery words (Settings → YubiKey), or import a private key for that chain.";
        IMPORT_KEY = "개인키 가져오기" / "Import private key";
        ENROL_YUBIKEY = "YubiKey 등록" / "Enrol YubiKey";
        CONNECT_YUBIKEY = "YubiKey 연결하기 (복구 단어 없이)" / "Connect YubiKey (no recovery words)";
        SHOW_KEY = "개인키 보기" / "Show private key";
        DELETE = "삭제" / "Delete";
        NEXT_KEY = "다음 (개인키 입력)" / "Next (enter private key)";
    }
}

/// "이 지갑에는 {체인} 계정이 없습니다".
#[must_use]
pub fn no_accounts_text(lang: Lang, chain: ImportChain) -> String {
    text::NO_ACCOUNTS.fill(lang, [chain.name()])
}

const fn chain_help(lang: Lang, chain: ImportChain) -> &'static str {
    match chain {
        ImportChain::Evm => text::HELP_EVM,
        ImportChain::Sol => text::HELP_SOL,
        ImportChain::Btc => text::HELP_BTC,
        ImportChain::Zec => text::HELP_ZEC,
    }
    .get(lang)
}

/// The label of an address type for an imported key: plain name (as in `계정 추가`), the mainnet
/// prefix and the technical name — `네이티브 세그윗 (bc1q…, P2WPKH)` (the network comes from the
/// WIF).
#[must_use]
pub fn script_choice_label(lang: Lang, script: ScriptType) -> String {
    format!(
        "{} ({}, {})",
        script.name_in(lang),
        script.prefix(BtcNetwork::Mainnet),
        script.technical()
    )
}

/// The four address-type radios (account chooser order: native segwit first).
fn script_radios(lang: Lang, selected: ScriptType) -> Item {
    Item::LabeledRow(
        text::ADDRESS_TYPE.get(lang).to_owned(),
        ScriptType::CHOICES
            .into_iter()
            .enumerate()
            .map(|(index, script)| {
                Ctl::radio(
                    KeysPress::Script(script),
                    &script_choice_label(lang, script),
                    script == selected,
                    index == 0,
                )
            })
            .collect(),
    )
}

impl Screen<'_> {
    /// S18: chain (and Bitcoin script type) before W01.
    pub fn key_start_intro(&self, items: &mut Vec<Item>) {
        let flow = &self.keys.start;
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        items.push(Item::Title(t(text::TITLE)));
        items.push(steps(KEY_START_STEPS.map(|step| step.get(lang)), 0));
        items.push(Item::CardStart(Some(t(text::WHICH_CHAIN))));
        items.push(Item::LabeledRow(
            t(text::CHAIN),
            vec![
                Ctl::radio(
                    KeysPress::StartChainEvm,
                    text::EVM_RADIO.get(lang),
                    flow.chain == ImportChain::Evm,
                    true,
                ),
                Ctl::radio(
                    KeysPress::StartChainSol,
                    "Solana",
                    flow.chain == ImportChain::Sol,
                    false,
                ),
                Ctl::radio(
                    KeysPress::StartChainBtc,
                    "Bitcoin",
                    flow.chain == ImportChain::Btc,
                    false,
                ),
            ],
        ));
        items.push(Item::Help(chain_help(lang, flow.chain).to_owned()));
        if flow.chain == ImportChain::Btc {
            items.push(script_radios(lang, flow.script));
            items.push(Item::Help(t(text::BTC_SCRIPT)));
        }
        items.push(Item::CardEnd);
        items.push(Item::CardStart(Some(t(text::BACKUP_TITLE))));
        items.push(Item::Banner(t(text::KEY_START_BACKUP), Tone::Warn));
        items.push(Item::Help(t(text::NO_ADD_ACCOUNT)));
        items.push(Item::CardEnd);
        items.push(Item::Row(vec![
            Ctl::primary(KeysPress::StartNext, text::START.get(lang)),
            Ctl::button(CorePress::IntroCancel, text::CANCEL.get(lang)),
        ]));
    }

    /// S19: the address of the entered key.
    pub fn key_start_address(&self, view: &KeyStartView, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        items.push(Item::Title(t(text::ADDRESS_TITLE)));
        items.push(steps(KEY_START_STEPS.map(|step| step.get(lang)), 3));
        items.push(Item::CardStart(None));
        items.push(Item::Text(
            text::ADDRESS_LEAD.fill(lang, [view.chain.name()]),
        ));
        if let Some((script, network)) = view.btc {
            items.push(Item::Field(
                t(text::ADDRESS_TYPE),
                format!(
                    "{} ({}, {})",
                    script.name_in(lang),
                    script.prefix(network),
                    script.technical()
                ),
            ));
            items.push(Item::Field(
                t(text::NETWORK),
                network.display_name_in(lang).to_owned(),
            ));
        }
        // In 4-character groups like every other address (spec/04 §3.3): EVM in its checksum
        // groups, Solana and Bitcoin as encoded.
        items.push(Item::Mono(match view.chain {
            ImportChain::Evm => yw_core::evm::address::parse_address(&view.address).map_or_else(
                |_| view.address.clone(),
                |parsed| yw_core::evm::display::format_address(&parsed),
            ),
            _ => crate::text::grouped(&view.address),
        }));
        items.push(Item::CardEnd);
        items.push(Item::Banner(t(text::KEY_START_BACKUP), Tone::Warn));
        items.push(Item::Row(vec![
            Ctl::primary(KeysPress::StartCorrect, text::CORRECT.get(lang)),
            Ctl::button(KeysPress::StartWrong, text::WRONG.get(lang)),
        ]));
        items.push(Item::Help(t(text::WRONG_HELP)));
    }

    /// A chain tab without any account in a key-only wallet.
    pub fn no_accounts_card(&self, chain: ImportChain, items: &mut Vec<Item>) {
        let import: Press = match chain {
            ImportChain::Evm => CorePress::ImportKey.into(),
            ImportChain::Sol => KeysPress::SolImport.into(),
            ImportChain::Btc => KeysPress::BtcImportNext.into(),
            ImportChain::Zec => ZecPress::Import.into(),
        };
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        items.push(Item::CardStart(None));
        items.push(Item::Subtitle(no_accounts_text(lang, chain)));
        items.push(Item::Text(t(if self.card.records.is_empty() {
            text::KEY_ONLY_NOTE
        } else {
            text::YUBIKEY_NOTE
        })));
        items.push(Item::Help(chain_help(lang, chain).to_owned()));
        if chain == ImportChain::Btc {
            items.push(script_radios(lang, self.keys.btc_script));
            items.push(Item::Help(t(text::BTC_SCRIPT)));
        }
        let unlocked = matches!(self.mode, crate::wallet::AppMode::Unlocked { .. });
        items.push(Item::Row(vec![
            Ctl::primary(import, text::IMPORT_KEY.get(lang)).enabled(self.can_import(chain)),
            Ctl::button(YkPress::EnrolStart, text::ENROL_YUBIKEY.get(lang))
                .enabled(unlocked && self.card.records.len() < yw_core::yubikey::plan::MAX_CARDS),
            Ctl::button(YkConnectPress::Start, text::CONNECT_YUBIKEY.get(lang))
                .enabled(unlocked && self.card.records.len() < yw_core::yubikey::plan::MAX_CARDS),
        ]));
        // Every account of the tab hidden (a `YubiKey` wallet): the way back is here too.
        let family = match chain {
            ImportChain::Evm => Some(crate::wallet::app_hidden::Family::Evm),
            ImportChain::Sol => Some(crate::wallet::app_hidden::Family::Sol),
            ImportChain::Btc | ImportChain::Zec => None,
        };
        if let Some(family) = family {
            self.hidden_items(family, items);
        }
        items.push(Item::CardEnd);
    }

    /// The selected Bitcoin account's key parts of the account card (2026-11-15, the shared
    /// card of `screen::build::accounts`): its buttons after `이름 바꾸기`·`숨기기` — `개인키 보기`
    /// and `삭제` of an imported key, `개인키 보기` of an account on an EVM account's key — and the
    /// reminder under them (T-IMPORTED-KEY-BACKUP / T-KEY-ONLY-BACKUP, T-BTC-EVM-SHARED).
    #[must_use]
    pub fn btc_key_parts(&self, ctx: &BtcCtx<'_>) -> (Vec<Ctl>, Option<Item>) {
        let unlocked = matches!(self.mode, crate::wallet::AppMode::Unlocked { .. });
        let lang = self.settings.language;
        if ctx.selected_imported().is_some() {
            let help = if self.key_only() {
                crate::secret::text::KEY_ONLY_BACKUP.get(lang)
            } else {
                crate::secret::text::IMPORTED_KEY_BACKUP.get(lang)
            };
            return (
                vec![
                    Ctl::button(KeysPress::BtcReveal, text::SHOW_KEY.get(lang))
                        .compact()
                        .enabled(unlocked),
                    Ctl::danger(KeysPress::BtcRemove, text::DELETE.get(lang))
                        .compact()
                        .enabled(unlocked && self.can_remove_imported()),
                ],
                Some(Item::Help(help.to_owned())),
            );
        }
        if ctx.selected_evm_shared().is_some() {
            // An account on an EVM account's key (spec/08 §3.5): its WIF can be exported; it is
            // not a vault record, so there is nothing to delete.
            return (
                vec![
                    Ctl::button(KeysPress::BtcReveal, text::SHOW_KEY.get(lang))
                        .compact()
                        .enabled(unlocked),
                ],
                Some(Item::Help(
                    crate::wallet::app_btc::T_BTC_EVM_SHARED
                        .get(lang)
                        .to_owned(),
                )),
            );
        }
        (Vec::new(), None)
    }

    /// `개인키 가져오기` of the Bitcoin account card's actions, or `None` while its chooser is
    /// open (the chooser has `다음`·`취소`).
    #[must_use]
    pub fn btc_import_action(&self) -> Option<Ctl> {
        (!self.keys.btc_import_open).then(|| {
            Ctl::button(
                KeysPress::BtcImport,
                text::IMPORT_KEY.get(self.settings.language),
            )
            .compact()
            .enabled(self.can_import(ImportChain::Btc))
        })
    }

    /// The import part of the Bitcoin account card's footer: closed, one short line (the address
    /// type chooser opens on demand, an uncommon action that used to fill the card); open,
    /// T-BTC-IMPORTED, the address-type radios, T-KEYSTART-SCRIPT and `다음`·`취소`.
    pub fn btc_import_items(&self, items: &mut Vec<Item>) {
        let lang = self.settings.language;
        let t = |entry: Text| entry.get(lang).to_owned();
        if !self.keys.btc_import_open {
            items.push(Item::Help(t(text::BTC_IMPORT_HINT)));
            return;
        }
        items.push(Item::Help(t(text::BTC_IMPORTED)));
        items.push(script_radios(lang, self.keys.btc_script));
        items.push(Item::Help(t(text::BTC_SCRIPT)));
        items.push(Item::Row(vec![
            Ctl::primary(KeysPress::BtcImportNext, text::NEXT_KEY.get(lang))
                .enabled(self.can_import(ImportChain::Btc)),
            Ctl::button(KeysPress::BtcImportCancel, text::CANCEL.get(lang)),
        ]));
    }
}
