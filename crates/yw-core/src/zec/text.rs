//! The Zcash approval texts in Korean and English (spec/12 §9, spec/14).
//!
//! The names of other zec modules that reach the approval display (the testnet banner, the
//! recipient form label, the key source label and path text) and the fixed error texts of the
//! zec modules (address, plan, signer, upgrade) are here too (2026-11-14, Step 3: the modules
//! read this catalogue for both languages; their Korean-only methods are gone).

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

    // ----- ZecAddressError (spec/12 §11) --------------------------------------------------------
    ADDR_EMPTY = "받는 주소를 입력하세요." / "Enter the recipient address.";
    ADDR_NOT_ZCASH = "Zcash 주소가 아닙니다." / "This is not a Zcash address.";
    ADDR_CHECKSUM = "주소의 체크섬이 맞지 않습니다. 주소를 다시 확인하세요."
        / "The address checksum does not match. Check the address again.";
    ADDR_WRONG_NETWORK = "다른 Zcash 네트워크의 주소입니다."
        / "This address is for the other Zcash network.";
    ADDR_SHIELDED = "비공개(shielded) 주소로는 보낼 수 없습니다. 이 지갑은 일반(transparent) 전송만 합니다."
        / "Cannot send to a shielded address. This wallet only makes transparent sends.";
    ADDR_UA_NO_TRANSPARENT = "이 통합 주소(UA)에는 일반(transparent) 수신자가 없습니다. 받는 사람에게 t 주소나 TEX 주소를 요청하세요."
        / "This unified address (UA) has no transparent receiver. Ask the recipient for a t address or a TEX address.";
    ADDR_UA_INVALID = "통합 주소(UA) 형식이 올바르지 않습니다."
        / "The unified address (UA) is malformed.";
    ADDR_UA_UNSUPPORTED = "이 통합 주소(UA) 형식(revision 1 또는 메타데이터)은 아직 지원하지 않습니다. t 주소나 TEX 주소를 요청하세요."
        / "This unified address (UA) format (revision 1 or metadata) is not supported yet. Ask for a t address or a TEX address.";

    // ----- ZecPlanError -------------------------------------------------------------------------
    PLAN_AMOUNT(1) = "보낼 금액이 올바르지 않습니다 (최소 {0} ZEC)."
        / "The amount to send is invalid (minimum {0} ZEC).";
    PLAN_INSUFFICIENT(2) = "확인된 잔액이 부족합니다: 필요 {0} (수수료 포함), 사용 가능 {1}."
        / "Not enough confirmed balance: needed {0} (fee included), available {1}.";
    PLAN_TOO_MANY_INPUTS(1) = "입력이 {0}개를 넘어야 해서 한 번에 보낼 수 없습니다. 금액을 나눠 보내세요."
        / "This would need more than {0} inputs, so it cannot be sent at once. Send the amount in parts.";
    PLAN_FEE_HIGH = "수수료가 상한을 넘습니다." / "The fee exceeds the cap.";
    PLAN_NO_FUNDS = "보낼 수 있는 확인된 잔액이 없습니다." / "There is no confirmed balance to send.";

    // ----- ZecSignError -------------------------------------------------------------------------
    SIGN_APPROVAL_MISMATCH = "승인 내용과 서명할 거래가 다릅니다."
        / "The transaction to sign differs from what was approved.";
    SIGN_KEY_MISMATCH = "서명 키가 이 Zcash 계정의 키와 다릅니다. 서명을 멈췄습니다."
        / "The signing key differs from this Zcash account's key. Signing stopped.";
    SIGN_VERIFY = "Zcash 거래 서명 검증에 실패해 폐기했습니다."
        / "The Zcash transaction failed signature verification and was discarded.";

    // ----- UpgradeError (spec/12 §11) -----------------------------------------------------------
    UPGRADE_UNKNOWN(1) = "노드가 이 지갑이 모르는 네트워크 업그레이드(branch id {0})를 알려 주었습니다. 지갑을 업데이트하기 전에는 보낼 수 없습니다."
        / "The node reported a network upgrade this wallet does not know (branch id {0}). You cannot send until the wallet is updated.";
    UPGRADE_NOT_V5(1) = "현재 네트워크 업그레이드(branch id {0})에서는 이 지갑의 거래 형식(v5)을 쓸 수 없습니다."
        / "This wallet's transaction format (v5) cannot be used under the current network upgrade (branch id {0}).";
    UPGRADE_MISMATCH(2) = "노드의 네트워크 업그레이드(branch id {0})가 지갑의 표({1})와 다릅니다. 노드나 지갑 버전을 확인하세요."
        / "The node's network upgrade (branch id {0}) differs from the wallet's table ({1}). Check the node or wallet version.";
    UPGRADE_TOO_CLOSE(1) = "네트워크 업그레이드가 곧(블록 {0}) 활성화됩니다. 활성화된 뒤에 다시 보내세요."
        / "A network upgrade activates soon (block {0}). Send again after it activates.";
    UPGRADE_TIP = "노드의 블록 높이가 올바르지 않습니다." / "The node's block height is invalid.";
}

/// The network banner (field `0x0002`).
#[must_use]
pub const fn network_banner(lang: Lang, network: ZecNetwork) -> &'static str {
    network.banner_in(lang)
}

/// The recipient form label.
#[must_use]
pub const fn form_label(lang: Lang, form: RecipientForm) -> &'static str {
    form.label_in(lang)
}

/// The key source label.
#[must_use]
pub fn source_label(lang: Lang, source: ZecKeySource) -> String {
    source.label_in(lang)
}

/// The key source path text.
#[must_use]
pub fn path_text(lang: Lang, source: ZecKeySource, network: ZecNetwork) -> String {
    source.path_text_in(lang, network)
}
