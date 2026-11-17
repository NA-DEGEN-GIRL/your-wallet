//! Fixed texts of the approval window A01 and the connect window (spec/04 §3, spec/05 §4.2;
//! English spec/14 §2). The signing window draws them in its request's display language
//! (`ApprovalDisplay::lang`, digested), the connect window in the app language.

yw_core::texts! {
    // Window chrome (spec/04 §3.4–§3.6).
    TITLE_APPROVAL = "Your Wallet — 승인 요청" / "Your Wallet — Approval request";
    TITLE_CONNECT = "Your Wallet — 사이트 연결" / "Your Wallet — Connect site";
    APPROVE = "승인" / "Approve";
    APPROVE_HOLD = "승인 (2초 길게 누르기)" / "Approve (hold 2 s)";
    CONNECT = "연결" / "Connect";
    CANNOT_APPROVE = "승인할 수 없음" / "Cannot approve";
    SIMULATING_BUTTON = "시뮬레이션 중…" / "Simulating…";
    REJECT = "거부" / "Reject";
    ACK = "위 경고를 모두 확인했습니다" / "I have read all the warnings above";
    DETAILS_OPEN = "자세히 ▾  (나머지 항목·원본 데이터)" / "Details ▾  (other fields · raw data)";
    DETAILS_CLOSED = "자세히 ▸  (나머지 항목·원본 데이터)" / "Details ▸  (other fields · raw data)";
    SUMMARY = "요약" / "Summary";
    RETRY_SIMULATION = "시뮬레이션 다시 시도" / "Retry simulation";
    LEVEL_HIGH = "고위험" / "High risk";
    LEVEL_BLOCKED = "차단" / "Blocked";
    LEVEL_CAUTION = "주의" / "Caution";
    LEVEL_INFO = "정보" / "Info";
    REMAINING(1) = "남은 시간 {0}" / "Time left {0}";
    WAITING(1) = "대기 {0}건" / "{0} waiting";
    HELD(2) = "{0}.{1}초" / "{0}.{1} s";
    CHECKING = "확인 중…" / "Checking…";
    SIMULATING_START = "시뮬레이션 중… (0/10초)" / "Simulating… (0/10 s)";
    AI_SKIP_BLOCKED = "승인할 수 없는 요청이라 AI 설명을 요청하지 않았습니다."
        / "The request cannot be approved, so no AI explanation was requested.";
    AI_SKIP_FAILED = "요청을 준비하지 못해 AI 설명을 요청하지 않았습니다."
        / "The request could not be prepared, so no AI explanation was requested.";

    // Status line (spec/04 §3.4, §7 T-SIM-*).
    SIM_CHANGED = "시뮬레이션 결과가 바뀌었습니다" / "The simulation result changed";
    SIM_CHANGED_STEP = ". 다시 확인하세요" / ". Check again";
    SIM_RESIM_FAILED = "다시 실행한 시뮬레이션이 성공하지 못했습니다" / "The re-run simulation did not succeed";
    SIM_RESIM_FAILED_STEP = ". 경고를 확인하고 다시 승인하세요." / ". Check the warnings and approve again.";
    ARM_WAIT = "잠시 뒤 버튼이 켜집니다 (실수 클릭을 막는 1초 대기)"
        / "The button turns on in a moment (a 1 s wait against accidental clicks)";
    ARM_WAIT_BACKGROUND = "이 창을 클릭해 앞으로 가져오면 1초 뒤 버튼이 켜집니다"
        / "Click this window to bring it to the front; the button turns on 1 s later";
    ACK_FIRST = "경고를 읽고 아래 '위 경고를 모두 확인했습니다'에 체크하세요"
        / "Read the warnings and tick 'I have read all the warnings above' below";
    HOLD_NOW = "'승인'을 2초 동안 누르고 있으세요" / "Hold down 'Approve' for 2 seconds";
    HOLD_EARLY = "2초가 되기 전에 놓았습니다 — 다시 2초 동안 누르세요"
        / "Released before 2 seconds — hold it again for 2 seconds";
    CONNECT_PICK = "연결할 계정을 하나 이상 고르세요" / "Choose at least one account to connect";

    // Header badges (spec/04 §3.2, app chrome only).
    BADGE_DEVNET = "Solana devnet (테스트) — 실제 자산이 아닙니다" / "Solana devnet (test) — not real assets";
    BADGE_TESTNET = "테스트넷 — 실제 자산이 아닙니다" / "Testnet — not real assets";
    BADGE_MAINNET = "메인넷 — 실제 자산" / "Mainnet — real assets";
    BADGE_HC_TESTNET = "HyperCore 테스트넷 — 실제 자산이 아닙니다" / "HyperCore testnet — not real assets";
    BADGE_WALLETCONNECT = "WalletConnect 세션" / "WalletConnect session";
    BADGE_HTTP = "로컬 개발 사이트(http)" / "Local development site (http)";
    BADGE_PUNYCODE = "국제화 도메인(punycode)" / "Internationalized domain (punycode)";
    BADGE_PUNYCODE_CHECK = "국제화 도메인(punycode) — 주소를 다시 확인하세요"
        / "Internationalized domain (punycode) — check the address again";
    BADGE_COMPAT(1) = "호환 모드: {0}" / "Compatibility mode: {0}";
    BADGE_CUSTOM_CHAIN(1) = "사용자 추가 체인 (chainId {0})" / "User-added chain (chainId {0})";
    BADGE_YUBIKEY = "YubiKey로 서명" / "Signed with YubiKey";
    BADGE_TOUCHES(1) = " · 터치 {0}회" / " · {0} touch(es)";

    // Content (spec/04 §3.2).
    SECTION_CHANGES = "자산 변화 (시뮬레이션 결과)" / "Asset changes (simulation result)";
    CHANGES_PARTIAL = "시뮬레이션에서 확인된 부분만 표시합니다." / "Only what the simulation confirmed is shown.";
    CHANGES_NONE = "시뮬레이션 결과가 없어 자산 변화를 표시할 수 없습니다."
        / "There is no simulation result, so asset changes cannot be shown.";
    SECTION_SOL_TX_MONEY = "자산 변화·수수료 (시뮬레이션 참고)" / "Asset changes · fee (simulation, reference)";
    SECTION_MONEY = "금액·수수료" / "Amount · fee";
    FEE = "수수료" / "Fee";
    FEE_EXPECTED(2) = "예상 {0} (최대 {1})" / "Expected {0} (max {1})";
    FEE_MAX(1) = "최대 {0}" / "Max {0}";
    SECTION_WARNINGS = "확인할 경고" / "Warnings to check";
    ACK_HINT = "맨 위의 고위험 경고를 읽고, 이해했으면 아래에 체크하세요."
        / "Read the high-risk warning at the top and, if you understand it, tick the box below.";
    SECTION_KEY = "핵심 정보" / "Key details";
    SUB_LOGIN = "로그인 내용" / "Log-in details";
    SUB_MESSAGE = "메시지 원문" / "Original message";
    SECTION_NOTES = "참고" / "Notes";
    REMARK(1) = "참고: {0}" / "Note: {0}";
    ADDRESS_NOTE(1) = "받는 주소: {0}" / "Recipient: {0}";
    PREPARING = "요청을 준비하는 중입니다…" / "Preparing the request…";
    SIMULATING(1) = "시뮬레이션 중… ({0}/10초)" / "Simulating… ({0}/10 s)";
    TOKEN = "토큰" / "token";

    // Summary sentences (spec/04 §3.2 요약). `{0}` is the place: `{network}에서 ` / `On {network}: `.
    PLACE(1) = "{0}에서 " / "On {0}: ";
    REVOKE(1) = "{0}아래 주소의 권한을 거둡니다(승인 해제)." / "{0}Revokes the permission of the address below (approval revoked).";
    GRANT_TOKEN(3) = "{0}아래 주소에 {1} 사용 권한을 줍니다: {2}." / "{0}Gives the address below permission to spend {1}: {2}.";
    GRANT_INCREASE_ZERO(2) = "{0}아래 주소의 {1} 사용 권한을 늘리는 거래이지만 늘리는 양이 0이라 이미 준 권한은 그대로입니다(승인 해제가 아닙니다)."
        / "{0}A transaction that increases the {1} allowance of the address below, but by 0, so the permission already given stays as it is (this is not a revoke).";
    GRANT_INCREASE(3) = "{0}아래 주소의 {1} 사용 권한을 늘립니다: +{2} (이미 준 권한에 더해집니다)."
        / "{0}Increases the {1} allowance of the address below: +{2} (added to the permission already given).";
    GRANT_FOR_ALL(1) = "{0}아래 주소에 이 컬렉션 NFT 전체를 옮길 권한을 줍니다."
        / "{0}Gives the address below permission to move every NFT of this collection.";
    GRANT_PERMIT2_TX(3) = "{0}아래 주소가 {1} {2} 쓸 수 있게 하는 거래입니다."
        / "{0}A transaction that lets the address below spend {1} {2}.";
    PERMIT_SIG(2) = "{0}아래 주소가 {1} 가져갈 수 있게 하는 서명입니다. 거래 없이 서명만으로 쓰일 수 있습니다."
        / "{0}A signature that lets the address below take {1}. It can be used with the signature alone, without a transaction.";
    PERMIT2_BATCH(2) = "{0}아래 주소가 토큰 {1}종을 쓸 수 있게 하는 서명입니다."
        / "{0}A signature that lets the address below spend {1} kinds of tokens.";
    PERMIT2_SIG(3) = "{0}아래 주소가 {1} {2} 쓸 수 있게 하는 서명입니다." / "{0}A signature that lets the address below spend {1} {2}.";
    PERMIT2_TRANSFER(2) = "{0}아래 주소가 {1} 바로 가져갈 수 있게 하는 서명입니다." / "{0}A signature that lets the address below take {1} at once.";
    TOKEN_KINDS(1) = "토큰 {0}종을" / "{0} kinds of tokens";
    HL_AGENT(1) = "{0}아래 주소(API 지갑)에 내 계정으로 주문·취소할 권한을 줍니다."
        / "{0}Gives the address below (an API wallet) permission to place and cancel orders for your account.";
    UNLIMITED_OBJECT(2) = "{0}{1} 무제한으로" / "an unlimited amount of {0}";
    UNTIL(1) = "{0}까지" / "until {0}";
    NO_TIME_LIMIT = "기한 없이" / "with no time limit";
    PERSONAL(1) = "{0}메시지에 서명합니다. 거래를 보내지는 않지만, 서명은 로그인이나 권한 확인에 쓰일 수 있습니다."
        / "{0}Signs a message. It sends no transaction, but the signature can be used for a log-in or a permission check.";
    SIWE(2) = "{0}{1} 사이트 로그인(Sign-In with Ethereum) 메시지에 서명합니다. 거래를 보내지는 않습니다."
        / "{0}Signs a site log-in message (Sign-In with Ethereum) for {1}. It sends no transaction.";
    TYPED_GENERIC(1) = "{0}구조화된 데이터(EIP-712)에 서명합니다. 토큰 사용 권한(permit) 같은 권한을 줄 수 있으니 아래 내용을 확인하세요."
        / "{0}Signs structured data (EIP-712). It can grant permissions such as a token permit, so check the content below.";
    TYPED_ACTION(2) = "{0}'{1}'에 서명합니다(EIP-712). 서명만으로 권한이나 자산이 넘어갈 수 있으니 아래 경고와 내용을 확인하세요."
        / "{0}Signs '{1}' (EIP-712). The signature alone can hand over permissions or assets, so check the warnings and content below.";
    SEND(3) = "{0}{1}{2} 아래 주소로 보냅니다." / "{0}Sends {1} to the address below.";
    SEND_ASSET(2) = "{0}{1} 보냅니다." / "{0}Sends {1}.";
    ASSET_SOL = "SOL을" / "SOL";
    ASSET_BTC = "BTC를" / "BTC";
    ASSET_ZEC = "ZEC를" / "ZEC";
    SIWB(2) = "{0}{1} 사이트 로그인(Sign-In with Bitcoin) 메시지에 서명합니다. 거래 서명이나 전송은 하지 않습니다."
        / "{0}Signs a site log-in message (Sign-In with Bitcoin) for {1}. It does not sign or send a transaction.";
    CONTRACT_CALL(2) = "{0}컨트랙트를 호출합니다: {1}. 아래 자산 변화와 경고를 확인하세요."
        / "{0}Calls a contract: {1}. Check the asset changes and warnings below.";
    SPEED_UP(1) = "{0}아직 확정되지 않은 거래를 더 높은 수수료로 다시 보냅니다(가속)."
        / "{0}Sends an unconfirmed transaction again with a higher fee (speed up).";
    CANCEL(1) = "{0}아직 확정되지 않은 거래를 취소합니다(같은 nonce로 0을 보내는 거래)."
        / "{0}Cancels an unconfirmed transaction (a transaction that sends 0 with the same nonce).";
    FEE_BUMP(1) = "{0}아직 확정되지 않은 거래의 수수료를 올려 다시 보냅니다."
        / "{0}Sends an unconfirmed transaction again with a higher fee.";
    OWNERSHIP(1) = "{0}메시지에 서명해 이 주소의 소유를 증명합니다. 거래 서명이나 전송은 하지 않습니다."
        / "{0}Signs a message to prove that you own this address. It does not sign or send a transaction.";
    HYPERCORE(2) = "{0}Hyperliquid HyperCore 작업에 서명합니다: {1}. 서명하면 Hyperliquid가 바로 처리하며 되돌릴 수 없습니다."
        / "{0}Signs a Hyperliquid HyperCore action: {1}. Once signed, Hyperliquid processes it immediately and it cannot be undone.";
    SIWS(1) = "{0}사이트 로그인(Sign-In-With-Solana) 메시지에 서명합니다. 거래 서명이나 전송은 하지 않습니다."
        / "{0}Signs a site log-in message (Sign-In-With-Solana). It does not sign or send a transaction.";
    SOL_TX_SEND(1) = "{0}사이트가 만든 Solana 거래에 서명하고 지갑이 바로 전송합니다. 되돌릴 수 없습니다."
        / "{0}Signs a Solana transaction made by the site, and the wallet sends it at once. This cannot be undone.";
    SOL_TX_SIGN(2) = "{0}사이트가 만든 Solana 거래 {1}건에 서명해 사이트에 돌려줍니다. 지갑은 전송하지 않습니다."
        / "{0}Signs {1} Solana transaction(s) made by the site and returns them to the site. The wallet does not send them.";

    // Connect window (spec/05 §4.2).
    CONNECT_EVM = "이 사이트는 선택한 계정의 주소, 잔액, 거래 기록을 볼 수 있습니다. 서명과 전송은 매번 따로 승인합니다."
        / "This site can see the address, balance and transaction history of the accounts you choose. Every signature and send is approved separately.";
    CONNECT_SOL = "이 사이트는 선택한 계정의 공개키를 볼 수 있습니다. 메시지 서명과 거래 서명·전송은 매번 따로 승인합니다."
        / "This site can see the public key of the account you choose. Every message signature and transaction signature or send is approved separately.";
    CONNECT_BTC = "이 사이트는 선택한 주소와 공개키를 볼 수 있습니다. 이 지갑은 Bitcoin에서 메시지 서명(소유 증명)만 지원하며, 거래 서명과 전송은 할 수 없습니다. 메시지 서명은 매번 따로 승인합니다."
        / "This site can see the addresses and public keys you choose. On Bitcoin this wallet only supports message signatures (proof of ownership); it cannot sign or send transactions. Every message signature is approved separately.";
    CONNECT_SECTION_EVM = "연결할 계정 (1–16개)" / "Accounts to connect (1–16)";
    CONNECT_SECTION_SOL = "연결할 Solana 계정 (1개)" / "Solana account to connect (1)";
    CONNECT_SECTION_BTC = "연결할 Bitcoin 주소 (용도마다 1개, 받기 주소 0번)" / "Bitcoin addresses to connect (1 per purpose, receive address 0)";
    CONNECT_LIMIT = "한 사이트에 연결할 수 있는 계정은 16개까지입니다." / "At most 16 accounts can be connected to one site.";
    CONNECT_DEFAULT(1) = "사이트가 기본으로 쓰는 계정: {0} (체크한 계정 중 목록의 첫 계정)"
        / "Account the site uses by default: {0} (the first checked account in the list)";
    CONNECT_NETWORK = "현재 네트워크" / "Current network";
    CONNECT_ORIGIN = "요청 출처" / "Requested by";
}
