//! Fixed texts of the Solana send approval (`L01`–`L08`, spec/07 §13.3), the SIWS / message
//! approval (spec/07 §19) and the shared Solana reasons (cluster name, transaction error codes,
//! fee and rent rules) in Korean and English (spec/14).

crate::texts! {
    // ----- cluster, shared ---------------------------------------------------------------------
    CLUSTER_DEVNET = "Solana devnet (테스트)" / "Solana devnet (test)";
    NETWORK_GENESIS(2) = "{0}\ngenesis 확인됨: {1}" / "{0}\ngenesis verified: {1}";
    RPC_ANOMALY = "RPC 응답 값이 비정상입니다" / "The RPC returned an implausible value";
    SIM_FAILED(1) = "실패: {0}" / "Failed: {0}";

    // ----- transaction error codes (broadcast::err) --------------------------------------------
    ERR_FEE_BALANCE = "수수료를 낼 잔액이 부족합니다" / "Not enough balance to pay the fee";
    ERR_RENT = "rent 기준을 채우지 못했습니다" / "The rent minimum was not met";
    ERR_ACCOUNT_NOT_FOUND = "계정을 찾을 수 없습니다" / "Account not found";
    ERR_SYSTEM = "System 명령이 실패했습니다" / "A System instruction failed";
    ERR_TOKEN = "토큰 명령이 실패했습니다" / "A token instruction failed";
    ERR_CU = "계산 한도(CU)를 넘었습니다" / "The compute limit (CU) was exceeded";
    ERR_BLOCKHASH = "블록해시를 찾을 수 없습니다(일시적)" / "Blockhash not found (temporary)";
    ERR_ALREADY = "이미 처리된 거래입니다" / "The transaction was already processed";
    ERR_PROGRAM = "프로그램 명령이 실패했습니다" / "A program instruction failed";
    ERR_UNKNOWN = "알 수 없는 거래 오류" / "Unknown transaction error";

    // ----- fee errors --------------------------------------------------------------------------
    FEE_OVERFLOW = "수수료 계산이 범위를 넘습니다" / "The fee calculation is out of range";
    FEE_QUERY_FAILED = "RPC에서 수수료를 확인하지 못했습니다" / "Could not check the fee with the RPC";
    FEE_FORMULA_CHANGED = "RPC 수수료가 지갑 계산과 다릅니다 — 수수료 공식이 바뀌었을 수 있습니다"
        / "The RPC fee differs from the wallet's calculation — the fee formula may have changed";
    FEE_ABOVE_CAP = "수수료가 설정한 상한을 넘습니다" / "The fee is above the cap you set";

    // ----- rent errors -------------------------------------------------------------------------
    RENT_NEW_ACCOUNT(1) = "새 계정에는 최소 {0} SOL을 보내야 합니다"
        / "A new account needs at least {0} SOL";
    RENT_RECIPIENT_BELOW(2) = "받는 계정의 잔액이 rent 기준({0} SOL)보다 적어 최소 {1} SOL을 보내야 합니다"
        / "The receiving account's balance is below the rent minimum ({0} SOL), so at least {1} SOL must be sent";
    RENT_SENDER_DUST(1) = "보낸 뒤 남는 잔액은 0이거나 {0} SOL 이상이어야 합니다"
        / "The balance left after sending must be 0 or at least {0} SOL";
    RENT_INSUFFICIENT = "잔액이 부족합니다(수수료 포함)" / "Insufficient balance (fee included)";
    RENT_ZERO = "0은 보낼 수 없습니다" / "Cannot send 0";
    RENT_NO_TOKEN_ACCOUNT = "보내는 계정에 이 토큰의 토큰 계정(ATA)이 없습니다(잔액 0)"
        / "The sending account has no token account (ATA) for this token (balance 0)";
    RENT_INSUFFICIENT_TOKENS = "토큰 잔액이 부족합니다" / "Insufficient token balance";
    RENT_SOL_RESERVE(2) = "SOL이 부족합니다: 수수료와 받는 토큰 계정 생성비(필요할 때)를 내고도 {0} SOL이 남아야 합니다(필요 {1} SOL)"
        / "Not enough SOL: {0} SOL must remain after the fee and the receiving token account's creation cost (when needed) (needed {1} SOL)";

    // ----- L01 reasons (SolBlock) --------------------------------------------------------------
    BLOCK_CLUSTER_MISMATCH = "RPC가 다른 Solana 클러스터를 가리킵니다(제네시스 불일치)"
        / "The RPC points to a different Solana cluster (genesis mismatch)";
    BLOCK_TOKEN_ACCOUNT = "지갑 주소가 아니라 토큰 계정/mint 주소입니다"
        / "This is a token account/mint address, not a wallet address";
    BLOCK_PROGRAM = "받는 주소가 프로그램입니다" / "The recipient is a program";
    BLOCK_PENDING = "이 계정의 이전 전송을 확인 중입니다"
        / "A previous transfer from this account is still being confirmed";
    BLOCK_JOURNAL_FULL = "거래 저널 공간이 부족합니다" / "The transaction journal is full";
    BLOCK_FROZEN = "보내는 토큰 계정이 동결되어 있습니다(토큰 발행자가 막음)"
        / "The sending token account is frozen (blocked by the token issuer)";
    BLOCK_RECIPIENT_ATA = "받는 사람의 토큰 계정(ATA)이 동결되었거나 이 토큰의 계정이 아닙니다"
        / "The recipient's token account (ATA) is frozen or is not an account of this token";

    // ----- send approval -----------------------------------------------------------------------
    NO_NAME = "(이름 없음)" / "(no name)";
    TITLE_SOL_TRANSFER = "SOL 전송" / "SOL transfer";
    TITLE_TOKEN_TRANSFER = "토큰 전송" / "Token transfer";
    LOOKALIKE_HEAD = "앞 3자 또는 뒤 3자가 같은 다른 주소입니다 — 주소 오염 공격일 수 있습니다"
        / "A different address with the same first 3 or last 3 characters — this may be an address poisoning attack";
    LOOKALIKE_BOOK(2) = "주소록 '{0}'과 비슷함: {1}" / "Similar to address book '{0}': {1}";
    LOOKALIKE_OWN(2) = "내 계정 '{0}'과 비슷함: {1}" / "Similar to my account '{0}': {1}";
    LOOKALIKE_SENT(1) = "보낸 내역의 주소와 비슷함: {0}" / "Similar to an address in your send history: {0}";
    SIM_CU_OVER(2) = "CU 초과: 사용 {0} > 한도 {1}" / "CU over the limit: used {0} > limit {1}";
    SIM_OK(1) = "성공(CU {0})" / "Success (CU {0})";
    SIM_NO_RESULT = "결과 없음(참고 정보이며 승인을 막지 않습니다)"
        / "No result (reference only; it does not block approval)";
    L01_CAUSE(1) = "보낼 수 없습니다: {0}" / "Cannot send: {0}";
    L02_TEXT = "일반 지갑이 아님: 프로그램 소유 주소(PDA)나 토큰 계정일 수 있음"
        / "Not a regular wallet: may be a program-owned address (PDA) or a token account";
    L04_TEXT = "받는 주소가 프로그램 소유 계정입니다 — 일반 지갑이 아닐 수 있습니다"
        / "The recipient is a program-owned account — it may not be a regular wallet";
    L05_TEXT(1) = "시뮬레이션에서 실패했거나 계산 한도를 넘었습니다 — 수수료만 잃을 수 있습니다\n{0}"
        / "It failed in simulation or exceeded the compute limit — you may lose the fee and get nothing\n{0}";
    L06_TEXT = "처음 보내는 주소입니다. 주소 전체를 확인하고, 큰 금액은 소액 시험 송금 뒤 보내세요."
        / "First send to this address. Check the whole address, and send a small test amount before a large one.";
    L07_TEXT(1) = "비표준 경로 계정입니다 ({0})" / "Non-standard path account ({0})";
    L08_SOL = "보내기 최대: 보낸 뒤 이 계정의 SOL 잔액은 0이 됩니다"
        / "Send max: this account's SOL balance will be 0 after sending";
    L08_SPL(1) = "보내기 최대: 보낸 뒤 이 계정의 {0} 잔액은 0이 됩니다(SOL은 남습니다)"
        / "Send max: this account's {0} balance will be 0 after sending (SOL remains)";
    FEE_RPC_LOWER(1) = "{0} lamports (지갑 최대보다 낮은 RPC 추정)"
        / "{0} lamports (RPC estimate below the wallet maximum)";
    NOT_CHECKED = "확인하지 못함" / "could not check";
    FEE_TEXT(8) = "기본 수수료 {0} lamports × 서명 1\n우선 수수료 {1} lamports (CU 한도 {2} × 가격 {3} micro-lamports/CU, 올림)\n최대 합계 {4} SOL ({5} lamports)\n사용자 상한 {6} lamports\nRPC getFeeForMessage: {7}"
        / "Base fee {0} lamports × 1 signature\nPriority fee {1} lamports (CU limit {2} × price {3} micro-lamports/CU, rounded up)\nMax total {4} SOL ({5} lamports)\nYour cap {6} lamports\nRPC getFeeForMessage: {7}";
    RECIPIENT_BOOK_VERIFIED(1) = "주소록: {0} ✓ 확인됨" / "Address book: {0} ✓ verified";
    RECIPIENT_BOOK(1) = "주소록: {0}" / "Address book: {0}";
    RECIPIENT_OWN(2) = "내 계정 #{0}: {1}" / "My account #{0}: {1}";
    RECIPIENT_OWN_IMPORTED(1) = "내 계정(가져온 개인키): {0}" / "My account (imported private key): {0}";
    RECIPIENT_OWN_HARDWARE(1) = "내 계정(YubiKey): {0}" / "My account (YubiKey): {0}";
    RECIPIENT_OWN_MNEMONIC(1) = "내 계정(추가한 복구 단어): {0}" / "My account (added recovery phrase): {0}";
    RECIPIENT_SENT = "보낸 적 있는 주소" / "Address you have sent to before";
    RECIPIENT_NEW = "새 계정(아직 없음)" / "New account (does not exist yet)";
    RECIPIENT_NO_SOL_ACCOUNT = "SOL 계정 없음(새 지갑일 수 있음 — 토큰을 받는 데는 문제없음)"
        / "No SOL account (may be a new wallet — receiving tokens is not a problem)";
    RECIPIENT_SPL_OWNER = "받는 지갑(소유자) 주소입니다. 토큰은 아래 '자산·금액'의 받는 토큰 계정(ATA)으로 갑니다."
        / "This is the receiving wallet (owner) address. The tokens go to the receiving token account (ATA) under 'Asset · amount' below.";
    SPL_AMOUNT(6) = "{0}\n{1} (원시 단위, decimals {2})\nmint (허용 목록 고정):\n{3}\n토큰 프로그램: SPL Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)\n보내는 토큰 계정(내 ATA):\n{4}\n받는 토큰 계정(받는 지갑의 ATA, 지갑이 계산):\n{5}"
        / "{0}\n{1} (raw units, decimals {2})\nmint (pinned in the allowlist):\n{3}\nToken program: SPL Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)\nSending token account (my ATA):\n{4}\nReceiving token account (the recipient wallet's ATA, computed by the wallet):\n{5}";
    ATA_EXISTS(2) = "받는 토큰 계정이 이미 있습니다(RPC 참고) — 생성 비용 없음.\n거래에는 '없으면 만들기'(CreateIdempotent) 명령이 항상 들어갑니다. 실행 때 없으면 최대 {0} SOL({1} lamports, rent)을 보내는 계정이 냅니다."
        / "The receiving token account already exists (RPC, reference) — no creation cost.\nThe transaction always includes a 'create if missing' (CreateIdempotent) instruction. If the account is missing at execution, the sending account pays up to {0} SOL ({1} lamports, rent).";
    ATA_MISSING(2) = "받는 토큰 계정이 없습니다(RPC 참고) — 이 거래가 만듭니다.\n생성 비용(rent) 최대 {0} SOL({1} lamports)을 보내는 계정이 냅니다(받는 사람 소유 계정에 들어감)."
        / "The receiving token account does not exist (RPC, reference) — this transaction creates it.\nThe sending account pays its creation cost (rent) of up to {0} SOL ({1} lamports), which goes into an account the recipient owns.";
    INSUFFICIENT = "부족" / "insufficient";
    BALANCE_AFTER(2) = "{0} SOL → {1} (RPC 기준)" / "{0} SOL → {1} (per RPC)";
    TOKEN_BALANCE_AFTER(2) = "{0} → {1} (RPC 기준)" / "{0} → {1} (per RPC)";
    NO_TOKEN_ACCOUNT_BALANCE(1) = "{0} 토큰 계정 없음 (RPC 기준)" / "No {0} token account (per RPC)";
    SPL_TOTAL(5) = "{0}\nSOL 최대 {1} SOL ({2} lamports = 수수료 최대 {3} + 토큰 계정 생성 rent {4})"
        / "{0}\nSOL up to {1} SOL ({2} lamports = max fee {3} + token account creation rent {4})";
    VALIDITY = "승인 창은 표시 후 120초에 만료(남은 시간은 상태 줄). 승인 즉시 서명하며 거래는 약 30초 뒤 만료"
        / "The approval window expires 120 s after it is shown (time left in the status bar). It signs as soon as you approve, and the transaction expires after about 30 s";

    // ----- message signing and SIWS ------------------------------------------------------------
    W07_VERSION = "Version은 1이어야 합니다" / "Version must be 1";
    W07_ISSUED_AT = "Issued At 시각 형식이 틀립니다" / "Issued At has an invalid time format";
    W07_EXPIRATION = "Expiration Time 시각 형식이 틀립니다" / "Expiration Time has an invalid time format";
    W07_NOT_BEFORE = "Not Before 시각 형식이 틀립니다" / "Not Before has an invalid time format";
    SIWS_DOMAIN = "도메인" / "Domain";
    SIWS_ADDRESS = "주소" / "Address";
    SIWS_STATEMENT = "설명" / "Statement";
    SIWS_VERSION = "버전" / "Version";
    SIWS_ISSUED_AT = "발급 시각" / "Issued at";
    SIWS_EXPIRATION = "만료 시각" / "Expires at";
    SIWS_NOT_BEFORE = "유효 시작" / "Not before";
    SIWS_REQUEST_ID = "요청 ID" / "Request ID";
    SIWS_RESOURCES = "리소스" / "Resources";
    NONE = "(없음)" / "(none)";
    MESSAGE_TITLE_SHORT = "메시지 서명" / "Sign message";
    M01_VERSIONED = "버전이 붙은 Solana 거래 메시지처럼 시작합니다"
        / "It starts like a versioned Solana transaction message";
    M01_TOO_LONG = "64KiB를 넘는 메시지입니다" / "The message is larger than 64 KiB";
    M02_NOT_SIGNER = "서명자 목록에 이 계정이 없습니다" / "This account is not in the signer list";
    OFFCHAIN_FORMAT(1) = "Solana 오프체인 메시지 v0 (형식 {0}) — 아래는 머리글을 뺀 본문"
        / "Solana off-chain message v0 (format {0}) — the body below is without the header";
    ACTION_SIWS = "로그인 요청 (SIWS)" / "Sign-in request (SIWS)";
    ACTION_MESSAGE = "메시지 서명 (소유 증명)" / "Sign message (proof of ownership)";
    MESSAGE_ERR_INTERNAL = "내부 검증에 실패해 서명하지 않았습니다."
        / "Internal verification failed, so nothing was signed.";
    MESSAGE_ERR_SIGNING = "서명하지 못했습니다(내부 오류)" / "Could not sign (internal error)";
}
