//! Cause lines of the EVM risk rules (spec/03 §10.2–§10.3; English spec/14 §3).

crate::texts! {
    UNLIMITED_HUGE = "2^128 이상의 승인 — 사실상 무제한" / "Approval of 2^128 or more — effectively unlimited";
    UNLIMITED_ABOVE_BALANCE = "잔액보다 큰 승인 — 사실상 무제한" / "Approval larger than the balance — effectively unlimited";
    EXCESS_LARGER = "보내는 자산이 거래 금액보다 많이 나갑니다" / "More of the sent asset leaves than the transaction amount";
    EXCESS_UNSHOWN(1) = "거래에 없는 다른 자산 {0}개도 나갑니다" / "{0} other asset(s) not in the transaction also leave";
    EXCESS_BOTH(1) = "보내는 자산이 거래 금액보다 많이 나가고, 거래에 없는 다른 자산 {0}개도 나갑니다"
        / "More of the sent asset leaves than the transaction amount, and {0} other asset(s) not in the transaction also leave";
    ENDS_SUFFIX(1) = "끝 {0}자" / "last {0} characters";
    ENDS_PREFIX(1) = "앞 {0}자" / "first {0} characters";
    ENDS_BOTH(2) = "앞 {0}자·끝 {1}자" / "first {0} and last {1} characters";
    LOOK_ALIKE_HISTORY(2) = "보낸 내역에 있는 주소와 {0}가 같습니다: {1}" / "Same {0} as an address in your send history: {1}";
    LOOK_ALIKE_MINE(3) = "내 계정 '{0}'과 {1}가 같습니다: {2}" / "Same {1} as your account '{0}': {2}";
    LOOK_ALIKE_BOOK(3) = "주소록 '{0}'과 {1}가 같습니다: {2}" / "Same {1} as address book entry '{0}': {2}";
    MULTICALL_EMPTY = "내부 호출이 없는 묶음 호출" / "Batch call without inner calls";
    MULTICALL_UNINTERPRETED = "해석되지 않은 호출 포함" / "Contains uninterpreted calls";
    R4_UNRESOLVED = "시뮬레이션 로그로 토큰 종류(ERC-20/ERC-721)를 정할 수 없습니다"
        / "The simulation logs cannot tell the token kind (ERC-20/ERC-721)";
    R6_UNCONFIRMED = "해석한 승인·이동이 시뮬레이션 로그에 없거나 다릅니다"
        / "The interpreted approval or transfer is missing from the simulation logs or differs";
    ACCOUNT_CODE_UNKNOWN = "서명 계정의 코드를 확인할 수 없습니다" / "The signing account's code cannot be checked";
    ONLY_UNVERIFIED_RECEIPTS = "받는 자산은 등록되지 않은 토큰·NFT뿐입니다" / "The only assets received are unregistered tokens or NFTs";
    SITE_RECIPIENT = "사이트가 정한 주소입니다 — 받는 주소가 맞는지 확인하세요"
        / "The site chose this address — check that the recipient is right";
    OTHER_EVENTS(1) = "기타 이벤트 {0}개" / "Other events: {0}";
    ORDER_ONLY_UNVERIFIED = "받는 것이 등록되지 않은 토큰·NFT뿐입니다" / "All you receive are unregistered tokens or NFTs";
}
