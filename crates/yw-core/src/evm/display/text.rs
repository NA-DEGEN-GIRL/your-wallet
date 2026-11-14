//! Fixed texts of the EVM approval displays (spec/03 §7.3, §8.3–§8.4, §9, §11.2; English spec/14
//! §4). yw-app's plain-language summary matches titles and sub-labels against these entries.

crate::texts! {
    EMPTY_STRING = "(빈 문자열)" / "(empty string)";
    EMPTY_MESSAGE = "(빈 메시지)" / "(empty message)";
    EMPTY_VALUE = "(빈 값)" / "(empty value)";
    NONE_PAREN = "(없음)" / "(none)";
    NONE = "없음" / "none";
    YES = "예" / "yes";
    NO = "아니오" / "no";
    UNKNOWN = "알 수 없음" / "unknown";
    UNKNOWN_WITH(1) = "알 수 없음 ({0})" / "unknown ({0})";
    NOT_COMPUTABLE = "계산 불가" / "cannot be computed";

    // Address notes (spec/03 §2.2, §8.5).
    NOTE_CONTRACT = "컨트랙트" / "contract";
    NOTE_EOA = "일반 계정(EOA)" / "regular account (EOA)";
    NOTE_DELEGATED = "위임된 계정(EIP-7702) → " / "delegated account (EIP-7702) → ";
    NOTE_KIND_UNKNOWN = "계정 종류 확인 불가" / "account type unknown";
    NOTE_MINE = "내 계정: " / "My account: ";
    NOTE_BOOK = "주소록: " / "Address book: ";
    NOTE_VERIFIED = " ✓ 확인됨" / " ✓ verified";

    // Amounts and times (spec/03 §2.4–§2.5, §8.3).
    RAW_UNVERIFIED_DECIMALS(4) = "{0} (원시 단위) {1} (미확인 · decimals {2} 적용 시 {3})"
        / "{0} (raw units) {1} (unverified · with decimals {2}: {3})";
    RAW_UNVERIFIED(2) = "{0} (원시 단위) {1} (미확인)" / "{0} (raw units) {1} (unverified)";
    NO_EXPIRY_RAW(1) = "{0} (사실상 만료 없음)" / "{0} (effectively no expiry)";
    BYTES_HEX(2) = "0x{0} ({1}바이트)" / "0x{0} ({1} bytes)";
    BYTES(1) = "{0}바이트" / "{0} bytes";
    UNLIMITED = "무제한" / "unlimited";
    EFFECTIVELY_UNLIMITED(1) = "{0} (사실상 무제한)" / "{0} (effectively unlimited)";
    NO_EXPIRY = "만료 없음" / "no expiry";
    AMOUNT_OR_TOKEN_ID(1) = "{0} (금액 또는 토큰 ID)" / "{0} (amount or token ID)";
    BLOCK_ONLY = "사용 블록에서만 유효" / "valid only in the block where it is used";

    // Call titles (spec/03 §7.3).
    SEND_NATIVE(1) = "{0} 보내기" / "Send {0}";
    MULTICALL(1) = "묶음 호출 ({0}개)" / "Batch call ({0} calls)";
    UNINTERPRETED_LABEL(1) = "해석되지 않은 컨트랙트 호출 ({0})" / "Uninterpreted contract call ({0})";
    UNINTERPRETED = "해석되지 않은 컨트랙트 호출" / "Uninterpreted contract call";
    CANCEL_TITLE(1) = "거래 취소 (nonce {0})" / "Cancel transaction (nonce {0})";
    SIWE_TITLE = "로그인 요청 (SIWE)" / "Sign-in request (SIWE)";
    MESSAGE_TITLE = "메시지 서명" / "Message signature";
    TYPED_TITLE = "타입 데이터 서명" / "Typed data signature";

    // Transaction fields (spec/03 §6.4, §11.2).
    TREE_TRUNCATED(1) = "(표시 한도 초과: 항목 {0}개 생략)" / "(over the display limit: {0} item(s) omitted)";
    OVER_LIMIT_BYTES(1) = "(표시 한도 초과: {0}바이트)" / "(over the display limit: {0} bytes)";
    SUM_UNAVAILABLE(1) = "합산 불가 · {0}" / "cannot be summed · {0}";
    NFT_UNVERIFIED(2) = "NFT #{0} · {1} (미확인)" / "NFT #{0} · {1} (unverified)";
    MULTI_UNVERIFIED(3) = "{0} × {1} · {2} (미확인)" / "{0} × {1} · {2} (unverified)";
    APPROVAL_ERC20(3) = "{0}\n사용자: {1}\n금액: {2}" / "{0}\nSpender: {1}\nAmount: {2}";
    APPROVAL_721_REVOKED(2) = "{0} #{1}\n개별 승인 해제" / "{0} #{1}\nSingle approval revoked";
    APPROVAL_721(3) = "{0} #{1}\n승인 대상: {2}" / "{0} #{1}\nApproved: {2}";
    APPROVAL_FOR_ALL(3) = "{0} 전체\n운영자: {1}\n{2}" / "{0} (all)\nOperator: {1}\n{2}";
    PERMISSION_GRANTED = "권한 부여" / "Permission granted";
    PERMISSION_REVOKED = "권한 해제" / "Permission revoked";
    APPROVAL_PERMIT2(4) = "{0} (Permit2)\n사용자: {1}\n금액: {2}\n만료: {3}"
        / "{0} (Permit2)\nSpender: {1}\nAmount: {2}\nExpires: {3}";
    APPROVAL_PERMIT2_LOCKDOWN(2) = "{0} (Permit2) 승인 해제\n사용자: {1}" / "{0} (Permit2) approval revoked\nSpender: {1}";
    SIM_BASIS(2) = "블록 {0} · {1}" / "Block {0} · {1}";
    SIM_NONE_UNSUPPORTED = "시뮬레이션 없음: 미지원 체인" / "No simulation: unsupported chain";
    SIM_NONE_SKIPPED = "시뮬레이션 없음: 차단 조건으로 실행하지 않음" / "No simulation: not run because the request is blocked";
    SIM_NONE_UNKNOWN_CAUSE = "알 수 없는 원인" / "unknown cause";
    SIM_NONE(1) = "시뮬레이션 없음: {0}" / "No simulation: {0}";
    OTHER_EVENTS(1) = "기타 이벤트 {0}개" / "{0} other event(s)";
    FEE_WITH_L1_MAX(2) = "{0} (L1 데이터 수수료 최대 {1} 포함)" / "{0} (including up to {1} L1 data fee)";
    FEE_WITH_L1_ESTIMATE(2) = "{0} (L1 데이터 수수료 약 {1} 포함)" / "{0} (including about {1} L1 data fee)";
    ACCESS_LIST(2) = "주소 {0}개 · 슬롯 {1}개" / "{0} address(es) · {1} slot(s)";
    ACCESS_ITEM(2) = "\n{0} · 슬롯 {1}개" / "\n{0} · {1} slot(s)";
    CALLDATA_NONE = "없음 (0바이트)" / "none (0 bytes)";
    CALLDATA(3) = "{0}바이트 · selector 0x{1}\n0x{2}" / "{0} bytes · selector 0x{1}\n0x{2}";
    REPLACES(2) = "0x{0}\n기존 최대 수수료 {1}" / "0x{0}\nPrevious max fee {1}";

    // personal_sign and SIWE (spec/03 §9).
    HASH32 = "정확히 32바이트입니다 — 해시에 서명하는 것일 수 있습니다" / "Exactly 32 bytes — you may be signing a hash";
    CONTROL_CHARS = "TAB·줄바꿈 외의 제어 문자가 있습니다" / "Contains control characters other than TAB and line breaks";
    SIWE_DOMAIN = "도메인" / "Domain";
    SIWE_ADDRESS = "주소" / "Address";
    SIWE_STATEMENT = "설명" / "Statement";
    SIWE_CHAIN_ID = "체인 ID" / "Chain ID";
    SIWE_ISSUED_AT = "발급 시각" / "Issued at";
    SIWE_EXPIRATION = "만료 시각" / "Expiration time";
    SIWE_NOT_BEFORE = "유효 시작" / "Not before";
    SIWE_REQUEST_ID = "요청 ID" / "Request ID";
    SIWE_RESOURCES = "리소스" / "Resources";

    // Typed data (spec/03 §8.3).
    STRUCT = "(구조)" / "(struct)";
    EMPTY_DOMAIN = "(빈 도메인)" / "(empty domain)";
    UNKNOWN_SCHEMA(1) = "알 수 없는 형식: {0}" / "Unknown format: {0}";
    HL_UNINTERPRETED_SUFFIX = " (해석하지 않은 형식 — 원문 필드 표시)" / " (uninterpreted format — raw fields shown)";
    ACTION_PERMIT = "토큰 사용 허가 서명 (permit)" / "Token spending permit signature (permit)";
    ACTION_DAI_PERMIT = "DAI 사용 허가 서명" / "DAI permit signature";
    ACTION_PERMIT2 = "Permit2 승인 서명" / "Permit2 approval signature";
    ACTION_PERMIT2_TRANSFER = "Permit2 즉시 이체 서명" / "Permit2 immediate transfer signature";
    ACTION_PERMIT2_WITNESS = "Permit2 즉시 이체 서명(조건 포함)" / "Permit2 immediate transfer signature (with conditions)";
    ACTION_SEAPORT = "NFT 마켓 주문 서명" / "NFT marketplace order signature";
    ACTION_HL_TRANSFER = "HyperCore 전송 서명" / "HyperCore transfer signature";
    ACTION_HL_AGENT = "Hyperliquid 거래 권한 위임 서명" / "Hyperliquid trading delegation signature";
    ACTION_HL_BUILDER = "Hyperliquid 빌더 수수료 승인 서명" / "Hyperliquid builder fee approval signature";
    ACTION_HL_MULTISIG = "Hyperliquid 멀티시그 계정 전환 서명" / "Hyperliquid multisig conversion signature";
    ACTION_HL_UNKNOWN = "Hyperliquid 계정 작업 서명 (해석하지 못함)" / "Hyperliquid account action signature (not interpreted)";
    ACTION_HL_L1 = "Hyperliquid 주문·거래 서명" / "Hyperliquid order/trade signature";
    HL_AGENT = "API 지갑(에이전트) 승인 — 거래 권한 위임" / "API wallet (agent) approval — trading delegation";
    HL_BUILDER = "빌더 수수료 승인" / "Builder fee approval";
    HL_MULTISIG = "멀티시그 계정으로 전환 — 이후 이 계정의 작업에는 서명자 목록(signers)의 서명이 필요합니다"
        / "Convert to a multisig account — afterwards this account's actions need signatures from the signers list";
    HL_UNKNOWN = "해석하지 못한 Hyperliquid 계정 작업 — 아래 원문 필드를 모두 확인하세요"
        / "Uninterpreted Hyperliquid account action — check every raw field below";
    HL_MAINNET = "HyperCore 메인넷 (Mainnet)" / "HyperCore mainnet (Mainnet)";
    HL_TESTNET = "HyperCore 테스트넷 (Testnet)" / "HyperCore testnet (Testnet)";
    HL_WITHDRAW_DESTINATION = "\nArbitrum One의 이 주소로 USDC가 들어갑니다" / "\nUSDC arrives at this address on Arbitrum One";
    HL_WITHDRAW_AMOUNT(3) = "{0} USDC\nArbitrum 도착 = 금액 − {1} USDC = {2} USDC"
        / "{0} USDC\nArrives on Arbitrum = amount − {1} USDC = {2} USDC";
    HL_SPOT_TO_PERP = "현물(spot) → 선물(perp)" / "spot → perp";
    HL_PERP_TO_SPOT = "선물(perp) → 현물(spot)" / "perp → spot";
    HL_SIGNERS(2) = "{0}명 중 {1}명의 서명이 필요합니다" / "{1} of {0} signers must sign";
    HL_SIGNERS_UNREADABLE(1) = "{0}\n서명자 목록을 해석할 수 없습니다" / "{0}\nThe signers list cannot be interpreted";
    HL_NOT_ADDRESS(1) = "{0}\n주소 형식이 아닙니다" / "{0}\nNot an address";
    HL_EVM_MOVE = "\nHyperEVM 시스템 주소 — 이 토큰을 HyperEVM의 같은 주소(서명 계정)로 옮기는 작업입니다"
        / "\nHyperEVM system address — this moves the token to the same address (the signing account) on HyperEVM";
    HL_SYSTEM_NOT_SPOT = "\n이 토큰의 HyperEVM 시스템 주소이지만 서명 계정 자신의 현물(spot)→현물 이동이 아닙니다 — HyperEVM 이동으로 확인할 수 없습니다"
        / "\nThis token's HyperEVM system address, but not a spot-to-spot move from the signing account itself — it cannot be confirmed as a HyperEVM move";
    HL_SYSTEM_OTHER_TOKEN = "\nHyperEVM 시스템 주소이지만 이 토큰에 연결된 주소가 아닙니다"
        / "\nA HyperEVM system address, but not the one linked to this token";
    HL_SYSTEM_UNCONFIRMED = "\nHyperEVM 시스템 주소이지만 토큰을 spotMeta로 확인하지 못해 이 토큰의 주소인지 알 수 없습니다"
        / "\nA HyperEVM system address, but the token could not be checked with spotMeta, so it is unknown whether it is this token's address";
    HL_SYSTEM = "\nHyperEVM 시스템 주소입니다 — 이 작업으로 보내면 자산을 잃을 수 있습니다"
        / "\nA HyperEVM system address — sending with this action may lose the assets";
    HL_SELF = "\n서명 계정과 같은 주소입니다" / "\nSame address as the signing account";
    HL_NO_BOOK = "\n내 계정·주소록 확인 불가" / "\nYour accounts and address book could not be checked";
    HL_L1_MAINNET = "HyperCore 메인넷 (source a)" / "HyperCore mainnet (source a)";
    HL_L1_TESTNET = "HyperCore 테스트넷 (source b)" / "HyperCore testnet (source b)";
    HL_L1_UNKNOWN_SOURCE(1) = "알 수 없음 (source {0})" / "unknown (source {0})";
    HL_L1_HASH(1) = "0x{0}\n주문·취소 등 거래 작업의 msgpack 해시입니다 — 내용은 해석할 수 없습니다"
        / "0x{0}\nThe msgpack hash of a trading action such as an order or cancel — its content cannot be interpreted";
    SEAPORT_RANGE(2) = "시작 {0} → 종료 {1} (시간에 따라 변함)" / "start {0} → end {1} (changes over time)";
    SEAPORT_ANY_TOKEN(2) = "컬렉션의 아무 토큰 × {0} · {1}" / "any token of the collection × {0} · {1}";
    SEAPORT_CRITERIA(3) = "기준 루트 0x{0} × {1} · {2}" / "criteria root 0x{0} × {1} · {2}";
    SEAPORT_UNKNOWN_ITEM(1) = "알 수 없는 itemType {0}" / "unknown itemType {0}";
    SEAPORT_RECIPIENT = "\n받는 주소: " / "\nRecipient: ";
    DAI_ALLOWED = "무제한 허용" / "unlimited allowance";
    DAI_REVOKED = "허용 해제" / "allowance revoked";
    PERMIT2_TRANSFER_NOTE = "이 서명으로 spender가 토큰을 바로 가져갈 수 있습니다" / "With this signature the spender can take the tokens at once";

    // Typed-data sub-labels (spec/03 §8.3).
    TD_ACTION = "작업" / "Action";
    TD_SIGNERS = "서명자 (signers)" / "Signers (signers)";
    TD_TOKEN = "토큰" / "Token";
    TD_OWNER = "소유자" / "Owner";
    TD_SPENDER = "사용자" / "Spender";
    TD_AMOUNT = "금액" / "Amount";
    TD_DEADLINE = "기한" / "Deadline";
    TD_ALLOWED = "허용" / "Allowed";
    TD_ITEM(1) = "항목 {0} " / "Item {0} ";
    TD_ALLOWANCE_EXPIRY = "허용 만료" / "Allowance expiry";
    TD_SIG_DEADLINE = "서명 기한" / "Signature deadline";
    TD_NOTE = "안내" / "Note";
    TD_WITNESS = "witness 타입" / "witness type";
    TD_NETWORK = "네트워크" / "Network";
    TD_ACTION_HASH = "작업 해시 (connectionId)" / "Action hash (connectionId)";
    TD_START = "시작 시각" / "Start time";
    TD_END = "종료 시각" / "End time";
    TD_YOU_GIVE = "내가 주는 것" / "You give";
    TD_YOU_RECEIVE = "내가 받는 것" / "You receive";
    TD_OTHERS_RECEIVE = "다른 사람이 받는 것" / "Others receive";
}
