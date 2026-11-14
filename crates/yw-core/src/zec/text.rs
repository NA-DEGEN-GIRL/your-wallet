//! The Zcash approval texts in Korean and English (spec/12 §9, spec/14).
//!
//! The names of other zec modules that reach the approval display (the testnet banner, the
//! recipient form label, the key source label and path text) are mapped here per language; the
//! Korean side delegates to the original function, so its bytes cannot drift (the catalogue
//! copies are checked against it in the tests).

use super::account::ZecKeySource;
use super::address::RecipientForm;
use super::network::ZecNetwork;
use crate::lang::Lang;

crate::texts! {
    /// `ZecNetwork::banner` of testnet.
    BANNER_TESTNET = "ZCASH TESTNET — 가치 없음" / "ZCASH TESTNET — NO VALUE";
    /// `RecipientForm::label` (field `ZEC_FORM`).
    FORM_TRANSPARENT = "일반(transparent) 주소" / "Transparent address";
    FORM_TEX = "TEX 주소 (ZIP 320, 일반 주소로만 보냄)"
        / "TEX address (ZIP 320, sent to a transparent address only)";
    FORM_UNIFIED = "통합 주소(UA)의 일반(transparent) 수신자"
        / "Transparent receiver of a unified address (UA)";
    /// `ZecKeySource::label`.
    SOURCE_STANDARD = "Zcash 표준 경로" / "Zcash standard path";
    SOURCE_PATH(2) = "Zcash 경로 (계정 {0}, 주소 {1})" / "Zcash path (account {0}, address {1})";
    SOURCE_STANDARD_ADDED = "Zcash 표준 경로 (추가한 복구 단어)"
        / "Zcash standard path (added recovery words)";
    SOURCE_PATH_ADDED(2) = "Zcash 경로 (계정 {0}, 주소 {1}, 추가한 복구 단어)"
        / "Zcash path (account {0}, address {1}, added recovery words)";
    SOURCE_EVM(1) = "EVM 계정 {0} 키" / "EVM account {0} key";
    SOURCE_YUBIKEY_CARD(1) = "YubiKey (카드 키 {0})" / "YubiKey (card key {0})";
    SOURCE_YUBIKEY(1) = "YubiKey (주소 {0})" / "YubiKey (address {0})";
    SOURCE_IMPORTED = "가져온 키" / "Imported key";
    /// `ZecKeySource::path_text`.
    PATH_IMPORTED = "가져온 개인키 (복구 단어 밖)" / "Imported private key (outside the recovery words)";
    PATH_UNKNOWN = "경로를 알 수 없음" / "Path unknown";

    /// Z05 (always shown).
    Z05_PUBLIC = "일반(transparent) 전송은 보내는 주소·받는 주소·금액이 블록체인에 공개됩니다."
        / "A transparent send makes the sending address·recipient address·amount public on the blockchain.";
    /// Z01.
    Z01_OWN_ADDRESS = "받는 주소가 이 계정의 주소입니다 (수수료만 나갑니다)."
        / "The recipient is this account's own address (only the fee is spent).";
    /// Z02.
    Z02_TEX = "TEX 주소: 받는 사람이 일반(transparent) 자금만 받겠다고 요청한 주소입니다. 이 거래는 일반 입력만 씁니다."
        / "TEX address: the recipient asked to receive transparent funds only. This transaction uses transparent inputs only.";
    /// Z03.
    Z03_UA_TRANSPARENT = "통합 주소(UA)의 일반(transparent) 수신자로 보냅니다. 받는 지갑에는 비공개가 아닌 일반 잔액으로 들어갑니다."
        / "Sending to the transparent receiver of a unified address (UA). The receiving wallet gets a public transparent balance, not a shielded one.";
    /// Z04.
    Z04_EXPIRY_CAPPED = "다음 네트워크 업그레이드 전에 만료되도록 만료 높이를 앞당겼습니다."
        / "The expiry height was moved earlier so the transaction expires before the next network upgrade.";
    /// Z06.
    Z06_FIRST_TIME = "처음 보내는 주소입니다. 주소 전체를 확인하고, 큰 금액은 소액 시험 송금 뒤 보내세요."
        / "First send to this address. Check the whole address, and send a small test amount before a large one.";

    /// Title.
    TITLE(2) = "[{0}] 보내기: {1} ZEC" / "[{0}] Send: {1} ZEC";
    /// Field `ZEC_TO` of a TEX or UA recipient.
    TO_ENTERED(2) = "{0}\n입력한 주소: {1}" / "{0}\nEntered address: {1}";
    /// Field `ZEC_CHANGE`.
    CHANGE_BACK(2) = "{0} ZEC — 같은 주소로 돌아옴 {1}" / "{0} ZEC — returns to the same address {1}";
    CHANGE_FOLDED(1) = "잔돈 없음: {0} zats 수수료에 추가" / "No change: {0} zats added to the fee";
    CHANGE_NONE = "잔돈 없음" / "No change";
    /// Field `ZEC_FEE`.
    FEE(4) = "{0}\nZIP 317 기본 수수료 {1} zats (입력 {2}개, 출력 {3}개)"
        / "{0}\nZIP 317 conventional fee {1} zats ({2} inputs, {3} outputs)";
    /// Field `ZEC_EXPIRY`.
    EXPIRY(6) = "블록 {0} (다음 블록 {1}부터 {2}블록, 약 {3}분 안에 포함되지 않으면 무효)\n네트워크 업그레이드 {4} (branch id {5})"
        / "Block {0} (invalid unless included within {2} blocks from the next block {1}, about {3} min)\nNetwork upgrade {4} (branch id {5})";
    EXPIRY_NEXT_UPGRADE(1) = "다음 업그레이드 활성화 높이 {0}" / "Next upgrade activation height {0}";
    /// Field `ZEC_INPUTS`.
    INPUTS(2) = "{0}개, 합계 {1}\n입력 금액과 스크립트는 서명(ZIP 244)에 포함되어, 틀리면 거래가 무효가 됩니다"
        / "{0}, total {1}\nInput amounts and scripts are part of the signature (ZIP 244); if they are wrong, the transaction is invalid";
    INPUTS_EXCLUDED(2) = "가장 큰 입력 {0}개만 씁니다 — 나머지 {1}개는 이 주소에 남습니다"
        / "Only the {0} largest inputs are used — the other {1} stay on this address";
    /// Field `ZEC_ADVANCED`.
    ADVANCED(1) = "v5 거래 (ZIP 225), 일반(transparent) 입력·출력만\nnLockTime 0 · sequence 0xFFFFFFFF\nSIGHASH_ALL (ZIP 244)\n{0}"
        / "v5 transaction (ZIP 225), transparent inputs·outputs only\nnLockTime 0 · sequence 0xFFFFFFFF\nSIGHASH_ALL (ZIP 244)\n{0}";
    ADVANCED_SEND_MAX = "보내기 최대: 모든 확인된 잔액 − 수수료" / "Send max: all confirmed balance − fee";
    ADVANCED_FIXED = "지정 금액" / "Specified amount";
}

/// The network banner (field `0x0002`).
#[must_use]
pub fn network_banner(lang: Lang, network: ZecNetwork) -> &'static str {
    match (lang, network) {
        (Lang::Ko, _) | (_, ZecNetwork::Mainnet) => network.banner(),
        (Lang::En, ZecNetwork::Testnet) => BANNER_TESTNET.en,
    }
}

/// The recipient form label (`RecipientForm::label`).
#[must_use]
pub fn form_label(lang: Lang, form: RecipientForm) -> &'static str {
    match lang {
        Lang::Ko => form.label(),
        Lang::En => match form {
            RecipientForm::Transparent => FORM_TRANSPARENT.en,
            RecipientForm::Tex => FORM_TEX.en,
            RecipientForm::Unified => FORM_UNIFIED.en,
        },
    }
}

/// The key source label (`ZecKeySource::label`).
#[must_use]
pub fn source_label(lang: Lang, source: ZecKeySource) -> String {
    use crate::yubikey::plan::{UNKNOWN_PATH_FIRST, is_unknown_index};
    if lang == Lang::Ko {
        return source.label();
    }
    match source {
        ZecKeySource::Derived {
            account: 0,
            index: 0,
        } => SOURCE_STANDARD.get(lang).to_owned(),
        ZecKeySource::Derived { account, index } => {
            SOURCE_PATH.fill(lang, [&account.to_string(), &index.to_string()])
        }
        ZecKeySource::Mnemonic {
            account: 0,
            index: 0,
            ..
        } => SOURCE_STANDARD_ADDED.get(lang).to_owned(),
        ZecKeySource::Mnemonic { account, index, .. } => {
            SOURCE_PATH_ADDED.fill(lang, [&account.to_string(), &index.to_string()])
        }
        ZecKeySource::EvmShared { evm_index } => SOURCE_EVM.fill(lang, [&evm_index.to_string()]),
        ZecKeySource::Hardware { index } if is_unknown_index(index) => SOURCE_YUBIKEY_CARD.fill(
            lang,
            [&index
                .saturating_sub(UNKNOWN_PATH_FIRST)
                .saturating_add(1)
                .to_string()],
        ),
        ZecKeySource::Hardware { index } => SOURCE_YUBIKEY.fill(lang, [&index.to_string()]),
        ZecKeySource::Imported => SOURCE_IMPORTED.get(lang).to_owned(),
    }
}

/// The key source path text (`ZecKeySource::path_text`).
#[must_use]
pub fn path_text(lang: Lang, source: ZecKeySource, network: ZecNetwork) -> String {
    match (lang, source) {
        (Lang::En, ZecKeySource::Imported) => PATH_IMPORTED.en.to_owned(),
        (Lang::En, ZecKeySource::Hardware { index })
            if crate::yubikey::plan::is_unknown_index(index) =>
        {
            PATH_UNKNOWN.en.to_owned()
        }
        _ => source.path_text(network),
    }
}
