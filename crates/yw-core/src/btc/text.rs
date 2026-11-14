//! The Bitcoin approval texts in Korean and English (spec/14): the send and fee-bump display
//! (spec/08 §10), the `B01`–`B08` warning texts and the message-signing display (spec/08 §17.4).
//!
//! The names of other btc modules that reach the approval display (network name and banner,
//! address-type names, account names, path notes, the recipient type label and the fee source)
//! are mapped here per language; the Korean side delegates to the original function, so its bytes
//! cannot drift (the catalogue copies are checked against it in the tests).

use super::BTC_CONF_TARGETS;
use super::account::{BtcAccountKey, HwBtcKey, ScriptType};
use super::address::ScriptKind;
use super::fee::FeeSource;
use super::network::BtcNetwork;
use crate::bip32::path::BtcChain;
use crate::lang::Lang;

crate::texts! {
    /// `BtcNetwork::display_name` of mainnet.
    NETWORK_MAINNET = "Bitcoin 메인넷" / "Bitcoin mainnet";
    /// `BtcNetwork::banner` of testnet4.
    BANNER_TESTNET4 = "BITCOIN TESTNET4 — 가치 없음" / "BITCOIN TESTNET4 — NO VALUE";
    /// `ScriptType::name`.
    SCRIPT_P2PKH = "레거시" / "Legacy";
    SCRIPT_P2SH_P2WPKH = "호환 세그윗" / "Nested SegWit";
    SCRIPT_P2WPKH = "네이티브 세그윗" / "Native SegWit";
    SCRIPT_P2TR = "탭루트" / "Taproot";
    /// `BtcAccountKey::display_name` (`{0}` the address-type name).
    ACCOUNT_HD(2) = "{0} 계정 {1}" / "{0} account {1}";
    ACCOUNT_HD_ADDED(2) = "{0} 계정 {1} (추가한 복구 단어)" / "{0} account {1} (added recovery words)";
    ACCOUNT_IMPORTED(1) = "가져온 키 · {0}" / "Imported key · {0}";
    ACCOUNT_EVM_KEY(2) = "EVM 계정 {0} 키 · {1}" / "EVM account {0} key · {1}";
    ACCOUNT_YUBIKEY_ADDRESS(2) = "YubiKey · {0} 주소 {1}" / "YubiKey · {0} address {1}";
    ACCOUNT_YUBIKEY_EVM(2) = "YubiKey EVM 계정 {0} 키 · {1}" / "YubiKey EVM account {0} key · {1}";
    /// `BtcAccountKey::path_text` of an imported key.
    PATH_IMPORTED = "가져온 키" / "Imported key";
    /// The path text of a `YubiKey` key connected without recovery words.
    PATH_UNKNOWN_YUBIKEY = "경로를 알 수 없음 (YubiKey)" / "Path unknown (YubiKey)";
    /// `ScriptKind::type_label` (field `0x0602`).
    TYPE_P2PKH = "P2PKH(레거시)" / "P2PKH (legacy)";
    TYPE_P2SH = "P2SH(스크립트)" / "P2SH (script)";
    TYPE_P2WSH = "P2WSH(스크립트)" / "P2WSH (script)";
    /// `FeeSource::text` (field `0x0606`; `{0}` one of the speeds below).
    FEE_SOURCE_ESTIMATE_SPEED(2) = "노드 추정({0}, {1}블록 목표)" / "Node estimate ({0}, {1}-block target)";
    FEE_SOURCE_ESTIMATE(1) = "노드 추정({0}블록 목표)" / "Node estimate ({0}-block target)";
    FEE_SPEED_FAST = "빠름" / "fast";
    FEE_SPEED_NORMAL = "보통" / "normal";
    FEE_SPEED_SLOW = "느림" / "slow";
    FEE_SOURCE_MANUAL = "직접 입력" / "Entered manually";
    FEE_SOURCE_FLOOR = "하한 적용" / "Floor applied";

    /// Titles.
    TITLE_FEE_BUMP(1) = "[{0}] 수수료 올리기" / "[{0}] Bump fee";
    TITLE_SEND(2) = "[{0}] 보내기: {1} BTC" / "[{0}] Send: {1} BTC";
    TITLE_MESSAGE(1) = "[{0}] 메시지 서명 (소유 증명)" / "[{0}] Sign message (proof of ownership)";

    /// Field `0x0605` (change).
    CHANGE_SAME_ADDRESS = "같은 주소" / "same address";
    CHANGE_BACK(2) = "{0} BTC — 이 지갑으로 돌아옴 {1}" / "{0} BTC — returns to this wallet {1}";
    CHANGE_NONE(1) = "잔돈 없음: {0} sats 수수료에 추가" / "No change: {0} sats added to the fee";
    /// Field `0x0604` (inputs).
    CONFIRMATIONS_UNKNOWN = "최소 확인 수 알 수 없음 (서버 기준)"
        / "Minimum confirmations unknown (server data)";
    CONFIRMATIONS(1) = "최소 확인 수 {0} (서버 기준)" / "Minimum confirmations {0} (server data)";
    INPUTS(3) = "{0}개, 합계 {1}\n모든 입력 금액은 이전 거래 해시로 검증됨\n{2}"
        / "{0}, total {1}\nEvery input amount verified by its previous transaction hash\n{2}";
    /// Field `0x0606` (fee).
    FEE(5) = "{0}\n{1} (계획 vsize {2} vB 기준, 서명 후 실제 값은 같거나 높음)\n보내는 금액의 {3}%\n출처: {4}"
        / "{0}\n{1} (at the planned vsize {2} vB; the actual value after signing is the same or higher)\n{3}% of the amount sent\nSource: {4}";
    FEE_OVERRIDE = "상한 해제: 보내기 화면에서 수수료를 정확히 입력함"
        / "Cap lifted: the exact fee was entered on the send screen";
    /// Field `0x0608` (balance after approval).
    BALANCE_BASE(1) = "검증 잔액 {0} BTC 기준" / "based on the verified balance {0} BTC";
    BALANCE_UNKNOWN(1) = "알 수 없음 ({0})" / "unknown ({0})";
    /// Field `0x0609` (fee bump).
    REPLACES_DECREASED(2) = "수신 금액 감소(B06): {0} → {1} sats"
        / "Recipient amount reduced (B06): {0} → {1} sats";
    REPLACES_SAME_RECIPIENT = "수신자 변경 없음" / "Recipient unchanged";
    REPLACES(5) = "교체 대상 {0}\n수수료 {1} → {2} sats (+{3})\n{4}"
        / "Replaces {0}\nFee {1} → {2} sats (+{3})\n{4}";
    REPLACES_BIP125_MIN = "교체 최소 수수료(BIP125)를 적용함"
        / "Minimum replacement fee (BIP125) applied";
    /// Field `0x0640` (advanced).
    TXID_AFTER_SIGNING = "서명 후 결정 (레거시 입력)" / "decided after signing (legacy inputs)";
    ADVANCED(8) = "version {0}\nnLockTime {1} (= 블록 높이 {2})\nRBF 가능 (sequence 0x{3})\n입력 형식 {4}\nvsize {5} vB · weight {6} WU (서명 전 추정)\ntxid {7}"
        / "version {0}\nnLockTime {1} (= block height {2})\nRBF enabled (sequence 0x{3})\nInput type {4}\nvsize {5} vB · weight {6} WU (estimated before signing)\ntxid {7}";

    /// `B01`–`B08` (spec/08 §10).
    B01_FEE_UNOVERRIDABLE = "수수료율이 10,000 sat/vB를 넘습니다 — 어떤 입력으로도 보낼 수 없습니다"
        / "Fee rate above 10,000 sat/vB — it cannot be sent with any input";
    B02_FEE_CAP_BLOCKED = "수수료가 상한(500 sat/vB 또는 0.005 BTC)을 넘습니다 — 보내기 화면에서 수수료(sats)를 정확히 입력해야 상한이 해제됩니다"
        / "Fee above the cap (500 sat/vB or 0.005 BTC) — enter the exact fee (sats) on the send screen to lift the cap";
    B03_FEE_CAP_OVERRIDDEN = "수수료 상한(500 sat/vB 또는 0.005 BTC)을 직접 입력으로 해제했습니다"
        / "Fee cap (500 sat/vB or 0.005 BTC) lifted by entering the fee manually";
    B04_FEE_RATIO = "수수료가 보내는 금액의 2%를 넘습니다" / "Fee above 2% of the amount sent";
    B05_FIRST_TIME = "처음 보내는 주소입니다. 주소 전체를 확인하고, 큰 금액은 소액 시험 송금 뒤 보내세요."
        / "First send to this address. Check the whole address, and send a small test amount before a large one.";
    B06_RECIPIENT_DECREASED = "수신 금액 감소: 늘어난 수수료만큼 받는 금액이 줄어듭니다"
        / "Recipient amount reduced: the recipient gets less by the added fee";
    B06_UTXOS_EXCLUDED(1) = "UTXO {0}개는 포함되지 않음(입력 최대 100개)"
        / "{0} UTXOs left out (at most 100 inputs)";
    B07_OWN_ADDRESS(1) = "이 지갑의 주소입니다 ({0})" / "This is an address of this wallet ({0})";
    B08_LEGACY_RECIPIENT = "레거시 형식(P2PKH) 주소입니다" / "Legacy (P2PKH) address";
    B08_SCRIPT_RECIPIENT = "스크립트 주소(P2SH·P2WSH)입니다: 수신자가 스크립트를 관리합니다"
        / "Script address (P2SH·P2WSH): the recipient controls a script";

    /// Message signing (spec/08 §17.4): the M03 cause of an oversized message.
    MESSAGE_TOO_LARGE = "64KiB를 넘는 메시지입니다" / "The message is larger than 64 KiB";
}

/// The network name of titles (`Bitcoin 메인넷` / `Bitcoin mainnet`, `Bitcoin testnet4`).
#[must_use]
pub fn network_name(lang: Lang, network: BtcNetwork) -> &'static str {
    match (lang, network) {
        (Lang::Ko, _) | (_, BtcNetwork::Testnet4) => network.display_name(),
        (Lang::En, BtcNetwork::Mainnet) => NETWORK_MAINNET.en,
    }
}

/// The network banner (field `0x0002`).
#[must_use]
pub fn network_banner(lang: Lang, network: BtcNetwork) -> &'static str {
    match (lang, network) {
        (Lang::Ko, _) | (_, BtcNetwork::Mainnet) => network.banner(),
        (Lang::En, BtcNetwork::Testnet4) => BANNER_TESTNET4.en,
    }
}

/// The plain address-type name (`ScriptType::name`).
#[must_use]
pub fn script_name(lang: Lang, script_type: ScriptType) -> &'static str {
    match lang {
        Lang::Ko => script_type.name(),
        Lang::En => match script_type {
            ScriptType::P2pkh => SCRIPT_P2PKH.en,
            ScriptType::P2shP2wpkh => SCRIPT_P2SH_P2WPKH.en,
            ScriptType::P2wpkh => SCRIPT_P2WPKH.en,
            ScriptType::P2tr => SCRIPT_P2TR.en,
        },
    }
}

/// The account display name (`BtcAccountKey::display_name`).
#[must_use]
pub fn account_name(lang: Lang, account: &BtcAccountKey) -> String {
    if lang == Lang::Ko {
        return account.display_name();
    }
    match account {
        BtcAccountKey::Hd {
            mnemonic,
            script_type,
            account,
            ..
        } => {
            let template = if mnemonic.is_some() {
                ACCOUNT_HD_ADDED
            } else {
                ACCOUNT_HD
            };
            template.fill(
                lang,
                [script_name(lang, *script_type), &account.to_string()],
            )
        }
        BtcAccountKey::Single { script_type, .. } => {
            ACCOUNT_IMPORTED.fill(lang, [script_name(lang, *script_type)])
        }
        BtcAccountKey::EvmShared {
            evm_index,
            script_type,
            ..
        } => ACCOUNT_EVM_KEY.fill(
            lang,
            [&evm_index.to_string(), script_name(lang, *script_type)],
        ),
        BtcAccountKey::Hardware {
            key: HwBtcKey::Address(index),
            script_type,
            ..
        } => ACCOUNT_YUBIKEY_ADDRESS
            .fill(lang, [script_name(lang, *script_type), &index.to_string()]),
        BtcAccountKey::Hardware {
            key: HwBtcKey::Evm(index),
            script_type,
            ..
        } => ACCOUNT_YUBIKEY_EVM.fill(lang, [&index.to_string(), script_name(lang, *script_type)]),
    }
}

/// Whether `account` is a `YubiKey` key connected without recovery words (no path).
fn unknown_hardware_path(account: &BtcAccountKey) -> bool {
    matches!(
        account,
        BtcAccountKey::Hardware { key: HwBtcKey::Address(index) | HwBtcKey::Evm(index), .. }
            if crate::yubikey::plan::is_unknown_index(*index)
    )
}

/// The path text of `(chain, index)` (`BtcAccountKey::path_text`).
#[must_use]
pub fn path_text(
    lang: Lang,
    account: &BtcAccountKey,
    network: BtcNetwork,
    chain: BtcChain,
    index: u32,
) -> String {
    match (lang, account) {
        (Lang::En, BtcAccountKey::Single { .. }) => PATH_IMPORTED.en.to_owned(),
        (Lang::En, _) if unknown_hardware_path(account) => PATH_UNKNOWN_YUBIKEY.en.to_owned(),
        _ => account.path_text(network, chain, index),
    }
}

/// The account node text (`BtcAccountKey::node_text`).
#[must_use]
pub fn node_text(lang: Lang, account: &BtcAccountKey, network: BtcNetwork) -> String {
    match (lang, account) {
        (Lang::En, BtcAccountKey::Single { .. }) => PATH_IMPORTED.en.to_owned(),
        (Lang::En, _) if unknown_hardware_path(account) => PATH_UNKNOWN_YUBIKEY.en.to_owned(),
        _ => account.node_text(network),
    }
}

/// The recipient type label of field `0x0602` (`ScriptKind::type_label`).
#[must_use]
pub fn type_label(lang: Lang, kind: &ScriptKind) -> &'static str {
    match (lang, kind) {
        (Lang::En, ScriptKind::P2pkh(_)) => TYPE_P2PKH.en,
        (Lang::En, ScriptKind::P2sh(_)) => TYPE_P2SH.en,
        (Lang::En, ScriptKind::P2wsh(_)) => TYPE_P2WSH.en,
        _ => kind.type_label(),
    }
}

/// The fee source text of field `0x0606` (`FeeSource::text`).
#[must_use]
pub fn fee_source_text(lang: Lang, source: FeeSource) -> String {
    if lang == Lang::Ko {
        return source.text();
    }
    match source {
        FeeSource::Estimate { target } => {
            let speed = match BTC_CONF_TARGETS {
                [fast, _, _] if target == fast => Some(FEE_SPEED_FAST),
                [_, normal, _] if target == normal => Some(FEE_SPEED_NORMAL),
                [_, _, slow] if target == slow => Some(FEE_SPEED_SLOW),
                _ => None,
            };
            let target = target.to_string();
            match speed {
                Some(speed) => FEE_SOURCE_ESTIMATE_SPEED.fill(lang, [speed.get(lang), &target]),
                None => FEE_SOURCE_ESTIMATE.fill(lang, [&target]),
            }
        }
        FeeSource::Manual => FEE_SOURCE_MANUAL.get(lang).to_owned(),
        FeeSource::Floor => FEE_SOURCE_FLOOR.get(lang).to_owned(),
    }
}
