//! EVM call titles (spec/03 §7.1), revert reasons (§7.4), simulation causes (§6.3), fee-cap and
//! gas causes (§3.4–§3.5) and built-in chain names (§1.1); English spec/14 §4.

crate::texts! {
    // spec/03 §7.1 call titles (`{0}` = native symbol, `{1}` = wrapped symbol where used).
    TITLE_TOKEN_TRANSFER = "토큰 전송" / "Token transfer";
    TITLE_TOKEN_APPROVE = "토큰 사용 승인" / "Token spending approval";
    TITLE_TOKEN_TRANSFER_FROM = "토큰 이체" / "Token transfer from";
    TITLE_ALLOWANCE_INCREASE = "토큰 승인 증가" / "Token approval increase";
    TITLE_ALLOWANCE_DECREASE = "토큰 승인 감소" / "Token approval decrease";
    TITLE_APPROVAL_FOR_ALL = "컬렉션 전체 권한" / "Permission over the whole collection";
    TITLE_NFT_TRANSFER = "NFT 이체" / "NFT transfer";
    TITLE_NFT_APPROVE = "NFT 개별 승인" / "Single NFT approval";
    TITLE_MULTI_TOKEN_TRANSFER = "멀티 토큰 이체" / "Multi-token transfer";
    TITLE_MULTI_TOKEN_BATCH = "멀티 토큰 일괄 이체" / "Multi-token batch transfer";
    TITLE_WRAP = "{native} → {wrapped} 변환" / "Convert {native} → {wrapped}";
    TITLE_UNWRAP = "{wrapped} → {native} 변환" / "Convert {wrapped} → {native}";
    TITLE_PERMIT2_APPROVE = "Permit2 승인" / "Permit2 approval";
    TITLE_PERMIT2_LOCKDOWN = "Permit2 승인 해제" / "Permit2 approval revoke";
    TITLE_PERMIT2_INVALIDATE_NONCES = "Permit2 nonce 무효화" / "Permit2 nonce invalidation";
    TITLE_PERMIT2_INVALIDATE_SIGNATURES = "Permit2 서명 무효화" / "Permit2 signature invalidation";
    TITLE_PERMIT_SUBMIT = "permit 제출" / "Submit permit";
    TITLE_DAI_PERMIT_SUBMIT = "DAI permit 제출" / "Submit DAI permit";

    // spec/03 §7.4 revert reasons.
    REVERT_NO_REASON = "이유 없이 되돌려짐" / "Reverted without a reason";
    REVERT_UNREADABLE = "메시지 형식 불명" / "Unreadable message";
    REVERT_UNVERIFIED_MESSAGE(1) = "(검증되지 않은 컨트랙트 메시지) \"{0}\"" / "(unverified contract message) \"{0}\"";
    REVERT_CUSTOM_ERROR(2) = "사용자 정의 오류 0x{0} ({1}바이트)" / "Custom error 0x{0} ({1} bytes)";
    PANIC_GENERIC = "일반" / "generic";
    PANIC_ASSERT = "assert 실패" / "assert failed";
    PANIC_OVERFLOW = "산술 오버플로" / "arithmetic overflow";
    PANIC_DIVISION = "0으로 나눔" / "division by zero";
    PANIC_ENUM = "잘못된 enum 변환" / "invalid enum conversion";
    PANIC_STORAGE = "저장소 바이트 배열 인코딩 오류" / "storage byte array encoding error";
    PANIC_POP = "빈 배열 pop" / "pop on an empty array";
    PANIC_INDEX = "배열 범위 초과" / "array index out of bounds";
    PANIC_MEMORY = "메모리 과다 할당" / "too much memory allocated";
    PANIC_UNINITIALIZED = "초기화되지 않은 함수 호출" / "call to an uninitialized function";

    // spec/03 §6.3 simulation causes.
    SIM_RPC_UNSUPPORTED = "RPC가 eth_simulateV1을 지원하지 않습니다(체인 설정에서 시뮬레이션을 \"미지원\"으로 바꿀 수 있습니다)"
        / "The RPC does not support eth_simulateV1 (you can set simulation to \"unsupported\" in the chain settings)";
    SIM_NONCE_USED = "nonce가 이미 사용되었습니다. 다른 곳에서 이 계정으로 거래가 전송되었을 수 있습니다"
        / "The nonce is already used. A transaction may have been sent from this account elsewhere";
    SIM_PREVIOUS_PENDING = "앞선 거래가 아직 처리되지 않았습니다" / "An earlier transaction has not been processed yet";
    SIM_FEE_TOO_LOW = "최대 수수료가 현재 기본 수수료보다 낮습니다" / "The max fee is lower than the current base fee";
    SIM_GAS_TOO_LOW = "가스 한도가 최소 필요량보다 작습니다" / "The gas limit is below the minimum required";
    SIM_INSUFFICIENT_FUNDS = "잔액이 보낼 금액과 최대 수수료의 합보다 적습니다"
        / "The balance is less than the amount plus the max fee";
    SIM_GAS_ABOVE_BLOCK = "가스 한도가 블록 가스 한도를 넘습니다" / "The gas limit exceeds the block gas limit";
    SIM_NODE_ERROR(1) = "시뮬레이션 노드 오류(코드 {0})" / "Simulation node error (code {0})";
    SIM_TIMEOUT = "시뮬레이션 응답이 없습니다(10초)" / "No simulation response (10 s)";
    SIM_RATE_LIMITED = "RPC 요청 한도를 넘었습니다" / "The RPC request limit was exceeded";
    SIM_TRANSPORT = "시뮬레이션 RPC에 연결할 수 없습니다" / "Cannot connect to the simulation RPC";
    SIM_TOO_LARGE = "시뮬레이션 응답이 너무 큽니다" / "The simulation response is too large";
    SIM_MALFORMED = "시뮬레이션 응답 형식이 올바르지 않습니다" / "The simulation response is malformed";
    SIM_REASON(1) = "이유: {0}" / "Reason: {0}";
    SIM_EXECUTION_ERROR(1) = "이유: 실행 오류(가스 부족 등, 코드 {0})" / "Reason: execution error (out of gas or similar, code {0})";
    SIM_GAS_USED_ABOVE_LIMIT = "사용 가스가 가스 한도를 넘습니다" / "The gas used exceeds the gas limit";
    SIM_NATIVE_UNCONFIRMED(1) = "{0} 이동이 확인되지 않습니다" / "The {0} transfer is not confirmed";
    SIM_CLOCK_SKEW(1) = "기준 블록 시각이 현재와 {0}초 다릅니다" / "The block time differs from now by {0} s";
    SIM_SUM_OVERFLOW = "금액 합산이 범위를 넘었습니다" / "An amount sum is out of range";
    SIM_ROWS_OMITTED(1) = "표시 한도를 넘어 {0}행을 생략했습니다" / "{0} row(s) omitted over the display limit";

    // spec/03 §3.4–§3.5 fee caps and gas.
    CAP_PRIORITY(2) = "우선 수수료 {0} > 상한 {1}" / "Priority fee {0} > cap {1}";
    CAP_MAX_FEE(2) = "최대 가스 가격 {0} > 상한 {1}" / "Max gas price {0} > cap {1}";
    CAP_TOTAL(2) = "최대 수수료 {0} > 상한 {1}" / "Max fee {0} > cap {1}";
    CAP_OVERFLOW = "수수료 계산이 범위를 넘었습니다" / "The fee calculation is out of range";
    SMALL_BLOCK(1) = "HyperEVM 작은 블록 한도({0})를 넘는 거래입니다 — 계정에 큰 블록 사용이 켜져 있지 않으면 포함되지 않을 수 있습니다"
        / "The transaction exceeds the HyperEVM small-block limit ({0}) — it may not be included unless big blocks are enabled for the account";

    // spec/03 §1.1 built-in chain names (other built-in names are the same in both languages).
    CHAIN_ETHEREUM = "Ethereum 메인넷" / "Ethereum Mainnet";
    CHAIN_SEPOLIA = "Sepolia 테스트넷" / "Sepolia Testnet";
    CHAIN_HYPEREVM = "HyperEVM 메인넷" / "HyperEVM Mainnet";
    SEAPORT_11_LABEL = "OpenSea Seaport 1.1(구버전)" / "OpenSea Seaport 1.1 (legacy)";
}
