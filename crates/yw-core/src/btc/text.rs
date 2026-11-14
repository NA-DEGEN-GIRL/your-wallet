//! The Bitcoin approval texts in Korean and English (spec/14): the send and fee-bump display
//! (spec/08 §10), the `B01`–`B08` warning texts and the message-signing display (spec/08 §17.4).
//!
//! It also holds the other user-visible btc texts: network name and banner, address-type names,
//! account names, path notes, the recipient type label, the fee source, and the fixed error and
//! confirmation texts of spec/08 §12–§13 (2026-11-14, Step 3: these were Korean literals in their
//! modules before, with the same Korean bytes). The modules' `*_in(lang)` methods read them.

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

    /// `ScriptType::label_in` of the recommended type (`{0}` name, `{1}` prefix).
    SCRIPT_CHOICE_RECOMMENDED(2) = "{0} ({1}, 권장)" / "{0} ({1}, recommended)";

    /// `AccountKeyError`.
    ERR_PUBLIC_KEY = "공개키 형식이 올바르지 않습니다" / "The public key format is invalid";
    ERR_UNCOMPRESSED_NOT_P2PKH = "비압축 키는 레거시(P2PKH) 주소로만 쓸 수 있습니다"
        / "An uncompressed key can only be used for a legacy (P2PKH) address";
    ERR_ACCOUNT_RANGE = "계정 번호가 범위를 벗어났습니다" / "The account number is out of range";
    ERR_HARDWARE_TAPROOT = "YubiKey에는 탭루트 키를 둘 수 없습니다"
        / "A YubiKey cannot hold a Taproot key";

    /// `AddressError::text_in` (spec/08 §13).
    ADDR_EMPTY = "주소를 입력하세요" / "Enter an address";
    ADDR_INVALID_CHARACTER = "허용되지 않는 문자가 있습니다" / "Contains characters that are not allowed";
    ADDR_NOT_BITCOIN = "Bitcoin 주소가 아닙니다" / "Not a Bitcoin address";
    ADDR_MIXED_CASE = "대소문자가 섞인 bech32 주소는 받지 않습니다"
        / "bech32 addresses with mixed case are not accepted";
    ADDR_CHECKSUM = "주소 체크섬이 틀립니다(오타 확인)" / "Wrong address checksum (check for typos)";
    ADDR_FORMAT = "주소 형식이 올바르지 않습니다" / "The address format is invalid";
    ADDR_WRONG_NETWORK = "다른 네트워크의 주소입니다" / "Address of another network";
    ADDR_WRONG_NETWORK_MAINNET = "다른 네트워크의 주소입니다(지갑: MAINNET)"
        / "Address of another network (wallet: MAINNET)";
    ADDR_WRONG_NETWORK_TESTNET4 = "다른 네트워크의 주소입니다(지갑: TESTNET4)"
        / "Address of another network (wallet: TESTNET4)";
    ADDR_UNKNOWN_VERSION = "지원하지 않는 주소 버전입니다" / "Unsupported address version";
    ADDR_PAY_TO_ANCHOR = "P2A 앵커 출력은 누구나 가져갈 수 있어 보낼 수 없습니다"
        / "Anyone can take a P2A anchor output, so you cannot send to it";
    ADDR_INVALID_TAPROOT_KEY = "유효하지 않은 Taproot 키입니다. 보내면 잃습니다"
        / "Invalid Taproot key. Anything sent to it is lost";
    ADDR_UNSUPPORTED_WITNESS = "지원하지 않는 세그윗 버전(v2–v16) 주소입니다"
        / "Unsupported SegWit version (v2–v16) address";
    ADDR_SILENT_PAYMENT = "사일런트 페이먼트 미지원" / "Silent payments not supported";
    ADDR_LIGHTNING = "라이트닝 미지원" / "Lightning not supported";
    ADDR_URI = "주소만 붙여넣으세요" / "Paste the address only";
    ADDR_PRIVATE_KEY = "개인키처럼 보입니다. 다른 곳에 붙여넣지 마세요"
        / "This looks like a private key. Do not paste it anywhere";

    /// `AmountError`.
    AMOUNT_FORMAT = "금액 형식이 올바르지 않습니다" / "The amount format is invalid";
    AMOUNT_ABOVE_MAX = "금액이 최대값(21,000,000 BTC)을 넘습니다"
        / "The amount exceeds the maximum (21,000,000 BTC)";

    /// `FeeError` (`{0}` the floor rate).
    FEE_NO_ESTIMATE = "수수료 추정이 없습니다. 직접 입력하세요" / "No fee estimate. Enter the fee manually";
    FEE_BELOW_FLOOR(1) = "수수료율이 노드 하한({0})보다 낮습니다"
        / "The fee rate is below the node floor ({0})";
    FEE_OVERFLOW = "수수료 계산 범위를 넘었습니다" / "Fee calculation out of range";

    /// `MetaError`.
    META_GAP_WARNING = "미사용 주소가 20개를 넘으면 다른 지갑으로 복구할 때 이후 입금이 보이지 않을 수 있습니다"
        / "With more than 20 unused addresses, later deposits may not show when you restore in another wallet";
    META_GAP_LIMIT = "미사용 주소가 100개 이상이라 새 주소를 발급할 수 없습니다"
        / "There are 100 or more unused addresses, so no new address can be issued";
    META_INDEX_EXHAUSTED = "더 발급할 주소 인덱스가 없습니다" / "No address index left to issue";
    META_OUT_OF_RANGE = "발급하지 않은 주소입니다" / "This address has not been issued";
    META_TIP_REGRESSION = "노드 블록 높이가 이전에 본 값보다 낮습니다"
        / "The node block height is lower than a value seen before";
    META_NOT_VERIFIED = "검증된 UTXO가 아닙니다" / "Not a verified UTXO";
    META_FULL = "BTC 데이터 공간이 부족합니다" / "Not enough space for BTC data";
    META_DISCOVERY_INCOMPLETE = "주소 검색 미완료" / "Address discovery not finished";
    META_SINGLE_ADDRESS = "이 계정은 주소 하나만 써서 새 주소를 만들 수 없습니다"
        / "This account uses a single address, so no new address can be made";

    /// `BtcMessageError::Signing` (the other variants use `SIGN_INTERNAL`).
    MESSAGE_ERR_SIGNING = "서명하지 못했습니다(내부 오류)" / "Could not sign (internal error)";

    /// `PrevTxError`.
    PREV_TOO_LARGE = "검증 불가 UTXO" / "Unverifiable UTXO";
    PREV_MALFORMED = "이전 거래 형식이 올바르지 않습니다" / "The previous transaction is malformed";
    PREV_TXID_MISMATCH = "이전 거래 해시가 일치하지 않습니다"
        / "The previous transaction hash does not match";
    PREV_VOUT = "이전 거래에 해당 출력이 없습니다" / "The previous transaction has no such output";
    PREV_SCRIPT = "이전 거래 출력이 이 지갑의 주소가 아닙니다"
        / "The previous transaction output is not an address of this wallet";
    PREV_ZERO = "이전 거래 출력 금액이 0입니다" / "The previous transaction output amount is 0";

    /// `PlanError` (`{0}`, `{1}` grouped sats).
    PLAN_DUST(1) = "받는 금액이 최소값({0} sats) 미만입니다" / "The amount is below the minimum ({0} sats)";
    PLAN_INSUFFICIENT(2) = "잔액이 부족합니다(필요 {0} sats, 사용 가능 {1} sats)"
        / "Insufficient balance (needed {0} sats, available {1} sats)";

    /// `policy::texts` (spec/08 §12.1, §13).
    IN_FLIGHT = "진행 중인 Bitcoin 거래가 확인된 뒤 보낼 수 있습니다. 수수료 올리기는 가능합니다"
        / "You can send once the pending Bitcoin transaction is confirmed. You can still bump its fee";
    INPUT_IN_FLIGHT = "진행 중인 거래가 쓰는 입력은 다시 쓸 수 없습니다"
        / "Inputs used by a pending transaction cannot be used again";
    NOT_BUMPABLE = "수수료를 올릴 수 있는 거래가 아닙니다" / "The fee of this transaction cannot be bumped";
    DERIVATION_FAILED = "주소 파생에 실패했습니다" / "Address derivation failed";
    PLAN_OVERFLOW = "거래 크기 또는 금액 계산 범위를 넘었습니다"
        / "Transaction size or amount calculation out of range";
    NETWORK_MISMATCH = "BTC 네트워크 설정이 지갑 데이터와 다릅니다"
        / "The BTC network setting differs from the wallet data";
    KEY_MISMATCH = "파생한 키가 계정 공개키와 다릅니다. 서명을 중단했습니다"
        / "The derived key differs from the account public key. Signing was stopped";
    AMOUNT_RECORD_MISMATCH = "기록된 입력 금액과 계획 금액이 다릅니다. 서명을 중단했습니다"
        / "A recorded input amount differs from the planned amount. Signing was stopped";
    APPROVAL_MISMATCH = "승인한 내용과 서명할 거래가 다릅니다. 서명하지 않았습니다"
        / "The transaction to sign differs from what you approved. Not signed";
    SIGN_INTERNAL = "내부 검증에 실패해 서명하지 않았습니다." / "Not signed because an internal check failed.";
    POST_SIGN = "서명 검증 실패(내부 오류). 거래를 폐기했습니다"
        / "Signature check failed (internal error). The transaction was discarded";
    PRECHECK_MISMATCH = "노드 검사 결과가 로컬 계산과 다릅니다"
        / "The node check result differs from the local calculation";
    TXID_MISMATCH = "응답 txid 불일치" / "Response txid mismatch";
    UNKNOWN_REJECT = "알 수 없는 거부 사유" / "Unknown rejection reason";
    RPC_MISSING_INPUTS = "입력이 없거나 이미 사용되었습니다" / "Inputs are missing or already spent";
    RPC_REJECTED = "노드가 거래를 거부했습니다" / "The node rejected the transaction";
    RPC_ERROR_CODE(1) = "RPC 오류(코드 {0})" / "RPC error (code {0})";
    ABANDON_CONFIRM = "이 거래는 이미 다른 노드에 퍼졌다면 나중에 확정될 수 있습니다. 포기한 뒤 같은 사람에게 다시 보내면 두 거래가 모두 확정되어 두 번 지불될 수 있습니다. 그래서 다음 보내기는 이 거래의 입력을 하나 이상 다시 써서, 둘 중 하나만 확정되게 합니다(30일 동안)."
        / "If this transaction already spread to other nodes, it may still confirm later. If you abandon it and send to the same person again, both transactions may confirm and you pay twice. So the next send reuses at least one input of this transaction, so that only one of the two can confirm (for 30 days).";
    CANCEL_DISCLOSED_CONFIRM = "서명한 거래를 취소합니다. 이 거래는 이미 노드(RPC)에 전달되었을 수 있어, 그 노드가 퍼뜨렸다면 나중에 확정될 수 있습니다. 두 번 지불되지 않도록 다음 보내기는 이 거래의 입력을 하나 이상 다시 써서 이 거래를 무효로 만듭니다(30일 동안)."
        / "This cancels the signed transaction. It may already have reached the node (RPC), and if that node spread it, it may still confirm later. To avoid paying twice, the next send reuses at least one input of this transaction and so invalidates it (for 30 days).";
    REJECTED_DISCLOSED = "노드가 거부했습니다. 다만 노드(RPC)가 이 거래를 이미 받았으므로, 다음 보내기는 이 거래의 입력을 하나 이상 다시 써서 둘 중 하나만 확정되게 합니다(30일 동안). 입력은 보내기 화면에 남아 있으니 수수료를 바꿔 다시 검토하세요."
        / "The node rejected it. But the node (RPC) already received this transaction, so the next send reuses at least one of its inputs so that only one of the two can confirm (for 30 days). Your input is still on the send screen: change the fee and review again.";
    ABANDONED_NOT_CONFLICTED = "포기한 거래의 입력을 이번 보내기에 쓸 수 없어 보내지 않았습니다(두 번 지불 방지). 그 입력의 동결을 풀거나, 포기한 거래가 확정·충돌로 끝나거나 30일이 지난 뒤 다시 하세요"
        / "Not sent: this send cannot use an input of the abandoned transaction (double-payment protection). Unfreeze that input, or try again once the abandoned transaction ends confirmed or conflicted, or after 30 days";
    TIP_IMPLAUSIBLE = "노드가 알려준 블록 높이가 올바르지 않아 보내지 않았습니다"
        / "Not sent: the block height reported by the node is invalid";
    CHANGE_INDEX_EXHAUSTED = "잔돈 주소 인덱스를 모두 써서 잔돈이 있는 거래를 만들 수 없습니다"
        / "All change address indexes are used, so a transaction with change cannot be made";
    INPUT_NOT_RECORDED = "승인하는 동안 입력 UTXO가 검증 목록에서 빠졌습니다(이미 사용되었거나 인덱서 목록에서 사라짐). 서명하지 않았습니다. 다시 검토하세요"
        / "An input UTXO left the verified list during the approval (already spent or gone from the indexer list). Not signed. Review again";

    /// `reject_reason_text` (Core `reject-reason` tokens, spec/08 §13).
    REJECT_MIN_FEE = "수수료율이 노드 최소값보다 낮습니다" / "The fee rate is below the node minimum";
    REJECT_INSUFFICIENT_FEE = "교체 수수료가 부족합니다" / "The replacement fee is too low";
    REJECT_CONFLICT = "다른 미확정 거래와 충돌합니다" / "Conflicts with another unconfirmed transaction";
    REJECT_NON_FINAL = "잠금 시간이 아직 지나지 않았습니다(노드 높이 확인)"
        / "The lock time has not passed yet (check the node height)";
    REJECT_DUST = "먼지 출력이 있습니다" / "Has a dust output";
    REJECT_MAX_FEE = "수수료 상한을 넘었습니다" / "The fee cap was exceeded";
    REJECT_ALREADY_SENT = "이미 전송된 거래입니다" / "The transaction was already sent";
}

/// The network name of titles (`Bitcoin 메인넷` / `Bitcoin mainnet`, `Bitcoin testnet4`).
#[must_use]
pub const fn network_name(lang: Lang, network: BtcNetwork) -> &'static str {
    match network {
        BtcNetwork::Mainnet => NETWORK_MAINNET.get(lang),
        BtcNetwork::Testnet4 => "Bitcoin testnet4",
    }
}

/// The network banner (field `0x0002`; spec/08 §2: mainnet on red, testnet4 on orange).
#[must_use]
pub const fn network_banner(lang: Lang, network: BtcNetwork) -> &'static str {
    match network {
        BtcNetwork::Mainnet => "BITCOIN MAINNET",
        BtcNetwork::Testnet4 => BANNER_TESTNET4.get(lang),
    }
}

/// The plain address-type name (account rows, receive screen, approval).
#[must_use]
pub const fn script_name(lang: Lang, script_type: ScriptType) -> &'static str {
    match script_type {
        ScriptType::P2pkh => SCRIPT_P2PKH,
        ScriptType::P2shP2wpkh => SCRIPT_P2SH_P2WPKH,
        ScriptType::P2wpkh => SCRIPT_P2WPKH,
        ScriptType::P2tr => SCRIPT_P2TR,
    }
    .get(lang)
}

/// The account display name (`BtcAccountKey::display_name_in`).
#[must_use]
pub fn account_name(lang: Lang, account: &BtcAccountKey) -> String {
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

/// The path text of `(chain, index)` (`BtcAccountKey::path_text_in`).
#[must_use]
pub fn path_text(
    lang: Lang,
    account: &BtcAccountKey,
    network: BtcNetwork,
    chain: BtcChain,
    index: u32,
) -> String {
    account.path_text_in(lang, network, chain, index)
}

/// The account node text (`BtcAccountKey::node_text_in`).
#[must_use]
pub fn node_text(lang: Lang, account: &BtcAccountKey, network: BtcNetwork) -> String {
    account.node_text_in(lang, network)
}

/// The recipient type label of field `0x0602` (spec/08 §10).
#[must_use]
pub const fn type_label(lang: Lang, kind: &ScriptKind) -> &'static str {
    match kind {
        ScriptKind::P2pkh(_) => TYPE_P2PKH.get(lang),
        ScriptKind::P2sh(_) => TYPE_P2SH.get(lang),
        ScriptKind::P2wpkh(_) => "P2WPKH",
        ScriptKind::P2wsh(_) => TYPE_P2WSH.get(lang),
        ScriptKind::P2tr(_) => "P2TR",
    }
}

/// The fee source text of field `0x0606` (spec/08 §8.2).
#[must_use]
pub fn fee_source_text(lang: Lang, source: FeeSource) -> String {
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
