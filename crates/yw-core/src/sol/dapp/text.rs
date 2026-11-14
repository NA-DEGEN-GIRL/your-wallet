//! Fixed texts of the dApp Solana transaction approval (spec/07 §20.6): instruction titles and
//! account labels, the field values `0x0510`–`0x051A`, the `X01`–`X20` cause lines, the decoder's
//! `Unknown` reasons and the lookup-table errors, in Korean and English (spec/14).

crate::texts! {
    // ----- decoder reasons and lookup-table errors ---------------------------------------------
    MALFORMED = "형식이 맞지 않음" / "malformed";
    ATA_MISMATCH = "ATA 주소가 유도값과 다릅니다" / "The ATA address differs from its derivation";
    UNRESOLVED = "조회 테이블을 해석하지 못함" / "lookup table not resolved";
    ALT_MISSING(1) = "조회 테이블이 없습니다: {0}" / "The lookup table does not exist: {0}";
    ALT_NOT_TABLE(1) = "조회 테이블이 아닙니다: {0}" / "Not a lookup table: {0}";
    ALT_INDEX = "조회 테이블 인덱스가 범위 밖입니다" / "A lookup table index is out of range";
    ALT_DUPLICATE = "조회한 주소가 다른 계정 키와 겹칩니다"
        / "A loaded address duplicates another account key";

    // ----- position prefixes (": " is added by the code) ---------------------------------------
    AT_TX_IX(2) = "거래 {0} 명령 {1}" / "Transaction {0} instruction {1}";
    AT_TX(1) = "거래 {0}" / "Transaction {0}";
    AT_IX(1) = "명령 {0}" / "Instruction {0}";

    // ----- address notes -----------------------------------------------------------------------
    TAG_SIGNER = "[서명]" / "[signer]";
    TAG_WRITABLE = "[쓰기]" / "[writable]";
    TAG_TABLE(1) = "[테이블 {0}]" / "[table {0}]";
    TAG_PROGRAM(1) = "[{0} 프로그램]" / "[{0} program]";
    TAG_MY_WALLET = "[내 지갑]" / "[my wallet]";
    TAG_MY_TOKEN_SYMBOL(1) = "[내 토큰 계정 · {0}]" / "[my token account · {0}]";
    TAG_MY_TOKEN = "[내 토큰 계정]" / "[my token account]";
    TAG_BOOK_VERIFIED(1) = "[주소록: {0} ✓]" / "[address book: {0} ✓]";
    TAG_BOOK(1) = "[주소록: {0}]" / "[address book: {0}]";
    TAG_MY_ACCOUNT(1) = "[내 계정: {0}]" / "[my account: {0}]";
    TAG_SENT = "[보낸 적 있는 주소]" / "[sent to before]";
    TAG_LOOKALIKE = "[비슷한 주소 주의]" / "[similar address: caution]";

    // ----- amounts -----------------------------------------------------------------------------
    AMOUNT_LISTED(3) = "{0} {1} ({2} 원시 단위)" / "{0} {1} ({2} raw units)";
    AMOUNT_DECIMALS(3) = "{0} 토큰 ({1} 원시 단위, decimals {2})" / "{0} tokens ({1} raw units, decimals {2})";
    AMOUNT_RPC_DECIMALS(3) = "{0} 토큰 ({1} 원시 단위, decimals {2} RPC 참고)"
        / "{0} tokens ({1} raw units, decimals {2} from RPC, reference)";
    AMOUNT_RAW(1) = "{0} (원시 단위)" / "{0} (raw units)";
    RAW_UNITS(1) = "{0} 원시 단위" / "{0} raw units";
    OPTION_NONE(1) = "{0} 없음" / "{0}: none";
    SIZE_BYTES(1) = "크기 {0}바이트" / "Size {0} bytes";

    // ----- account labels ----------------------------------------------------------------------
    L_FUNDING = "자금 계정" / "Funding account";
    L_NEW_ACCOUNT = "새 계정" / "New account";
    L_OWNER_PROGRAM = "소유 프로그램" / "Owner program";
    L_ACCOUNT = "계정" / "Account";
    L_NEW_OWNER_PROGRAM = "새 소유 프로그램" / "New owner program";
    L_FROM = "보내는 계정" / "Sending account";
    L_TO = "받는 계정" / "Receiving account";
    L_BASE = "기준 계정" / "Base account";
    L_NONCE = "nonce 계정" / "Nonce account";
    L_NONCE_AUTHORITY = "nonce 권한" / "Nonce authority";
    L_CURRENT_AUTHORITY = "현재 권한" / "Current authority";
    L_NEW_AUTHORITY = "새 권한" / "New authority";
    L_MINT_AUTHORITY = "발행 권한" / "Mint authority";
    L_FREEZE_AUTHORITY = "동결 권한" / "Freeze authority";
    L_TOKEN_ACCOUNT = "토큰 계정" / "Token account";
    L_OWNER = "소유자" / "Owner";
    L_MULTISIG = "멀티시그 계정" / "Multisig account";
    L_FROM_TOKEN = "보내는 토큰 계정" / "Sending token account";
    L_TO_TOKEN = "받는 토큰 계정" / "Receiving token account";
    L_OWNER_DELEGATE = "소유자·위임자" / "Owner · delegate";
    L_DELEGATE = "위임받는 주소" / "Delegate";
    L_MINT_OR_TOKEN = "mint·토큰 계정" / "Mint · token account";
    L_CLOSING = "닫는 토큰 계정" / "Token account being closed";
    L_REST_TO = "남은 SOL을 받는 주소" / "Receives the remaining SOL";
    L_OWNER_CLOSE = "소유자·닫기 권한" / "Owner · close authority";
    L_WSOL = "wrapped SOL 토큰 계정" / "Wrapped SOL token account";
    L_RENT_PAYER = "rent를 내는 계정" / "Account paying the rent";
    L_ATA_DERIVED = "토큰 계정(ATA, 유도값 확인됨)" / "Token account (ATA, derivation verified)";
    L_OWNER_WALLET = "소유 지갑" / "Owner wallet";
    L_TOKEN_PROGRAM = "토큰 프로그램" / "Token program";
    L_NESTED = "중첩된 토큰 계정" / "Nested token account";
    L_NESTED_MINT = "중첩 mint" / "Nested mint";
    L_OWNER_TOKEN = "소유 토큰 계정" / "Owner token account";
    L_OWNER_MINT = "소유 mint" / "Owner mint";
    L_WALLET = "지갑" / "Wallet";
    L_PROGRAM = "프로그램" / "Program";
    L_ACCOUNT_N(1) = "계정 {0}" / "Account {0}";
    L_BEFORE = "이전" / "Before";
    L_AFTER = "이후" / "After";
    L_CLOSED = "닫힘" / "Closed";
    L_CREATED = "새로 만들어짐" / "Newly created";
    L_TOKEN_MINT = "토큰 계정 · mint" / "Token account · mint";

    // ----- System instructions -----------------------------------------------------------------
    T_CREATE_ACCOUNT = "계정 만들기 (CreateAccount)" / "Create account (CreateAccount)";
    T_ASSIGN = "소유 프로그램 바꾸기 (Assign)" / "Change owner program (Assign)";
    T_SOL_TRANSFER = "SOL 보내기 (Transfer)" / "Send SOL (Transfer)";
    T_CREATE_WITH_SEED = "seed로 계정 만들기 (CreateAccountWithSeed)"
        / "Create account with seed (CreateAccountWithSeed)";
    TRAILING_BYTES(1) = "뒤에 붙은 바이트(런타임이 무시): {0}" / "Trailing bytes (ignored by the runtime): {0}";
    T_ADVANCE_NONCE = "durable nonce 진행 (AdvanceNonceAccount)" / "Advance durable nonce (AdvanceNonceAccount)";
    T_WITHDRAW_NONCE = "nonce 계정에서 꺼내기 (WithdrawNonceAccount)"
        / "Withdraw from nonce account (WithdrawNonceAccount)";
    T_INIT_NONCE = "nonce 계정 초기화 (InitializeNonceAccount)"
        / "Initialize nonce account (InitializeNonceAccount)";
    T_AUTHORIZE_NONCE = "nonce 권한 바꾸기 (AuthorizeNonceAccount)"
        / "Change nonce authority (AuthorizeNonceAccount)";
    T_ALLOCATE = "공간 할당 (Allocate)" / "Allocate space (Allocate)";
    T_ALLOCATE_WITH_SEED = "seed 계정 공간 할당 (AllocateWithSeed)"
        / "Allocate space for seed account (AllocateWithSeed)";
    T_ASSIGN_WITH_SEED = "seed 계정 소유 프로그램 바꾸기 (AssignWithSeed)"
        / "Change seed account owner program (AssignWithSeed)";
    T_TRANSFER_WITH_SEED = "seed 계정에서 SOL 보내기 (TransferWithSeed)"
        / "Send SOL from seed account (TransferWithSeed)";
    T_UPGRADE_NONCE = "nonce 계정 갱신 (UpgradeNonceAccount)" / "Upgrade nonce account (UpgradeNonceAccount)";

    // ----- Token instructions ------------------------------------------------------------------
    AUTH_MINT_TOKENS = "발행 권한(MintTokens)" / "Mint authority (MintTokens)";
    AUTH_FREEZE = "동결 권한(FreezeAccount)" / "Freeze authority (FreezeAccount)";
    AUTH_ACCOUNT_OWNER = "토큰 계정 소유자(AccountOwner)" / "Token account owner (AccountOwner)";
    AUTH_CLOSE = "닫기 권한(CloseAccount)" / "Close authority (CloseAccount)";
    T_INIT_MINT = "mint 초기화 (InitializeMint)" / "Initialize mint (InitializeMint)";
    T_INIT_ACCOUNT = "토큰 계정 초기화 (InitializeAccount)" / "Initialize token account (InitializeAccount)";
    REQUIRED_SIGNATURES(1) = "필요 서명 {0}개" / "Required signatures: {0}";
    T_INIT_MULTISIG = "멀티시그 초기화 (InitializeMultisig)" / "Initialize multisig (InitializeMultisig)";
    T_TOKEN_TRANSFER = "토큰 보내기 (Transfer)" / "Send tokens (Transfer)";
    DELEGATE_LIMIT(1) = "위임 한도 {0}" / "Delegation limit {0}";
    T_APPROVE = "토큰 사용 권한 위임 (Approve)" / "Delegate token spending (Approve)";
    T_REVOKE = "위임 해제 (Revoke)" / "Revoke delegation (Revoke)";
    CHANGED_AUTHORITY(1) = "바뀌는 권한: {0}" / "Authority changed: {0}";
    T_SET_AUTHORITY = "권한 변경 (SetAuthority)" / "Change authority (SetAuthority)";
    T_MINT_TO = "토큰 발행 (MintTo)" / "Mint tokens (MintTo)";
    T_BURN = "토큰 소각 (Burn)" / "Burn tokens (Burn)";
    T_CLOSE = "토큰 계정 닫기 (CloseAccount)" / "Close token account (CloseAccount)";
    T_FREEZE = "토큰 계정 동결 (FreezeAccount)" / "Freeze token account (FreezeAccount)";
    T_THAW = "토큰 계정 동결 해제 (ThawAccount)" / "Thaw token account (ThawAccount)";
    T_TRANSFER_CHECKED = "토큰 보내기 (TransferChecked)" / "Send tokens (TransferChecked)";
    T_APPROVE_CHECKED = "토큰 사용 권한 위임 (ApproveChecked)" / "Delegate token spending (ApproveChecked)";
    T_MINT_TO_CHECKED = "토큰 발행 (MintToChecked)" / "Mint tokens (MintToChecked)";
    T_BURN_CHECKED = "토큰 소각 (BurnChecked)" / "Burn tokens (BurnChecked)";
    T_SYNC_NATIVE = "wrapped SOL 잔액 맞추기 (SyncNative)" / "Sync wrapped SOL balance (SyncNative)";
    EXTENSION_TYPES(1) = "확장 유형: {0}" / "Extension types: {0}";
    T_GET_SIZE = "계정 크기 조회 (GetAccountDataSize)" / "Query account size (GetAccountDataSize)";
    T_IMMUTABLE_OWNER = "소유자 고정 (InitializeImmutableOwner)" / "Lock the owner (InitializeImmutableOwner)";
    T_AMOUNT_TO_UI = "금액 표기 변환 (AmountToUiAmount)" / "Convert amount notation (AmountToUiAmount)";
    UI_AMOUNT(1) = "금액 표기: {0}" / "Amount notation: {0}";
    T_UI_TO_AMOUNT = "금액 표기 변환 (UiAmountToAmount)" / "Convert amount notation (UiAmountToAmount)";
    T_EXTENSION(1) = "Token-2022 확장 명령 {0} (해석하지 않음)"
        / "Token-2022 extension instruction {0} (uninterpreted)";

    // ----- ATA and Compute Budget instructions -------------------------------------------------
    T_ATA_IDEMPOTENT = "토큰 계정 만들기, 있으면 그대로 (CreateIdempotent)"
        / "Create token account, keep it if it exists (CreateIdempotent)";
    T_ATA_CREATE = "토큰 계정 만들기 (Create)" / "Create token account (Create)";
    T_RECOVER_NESTED = "중첩 토큰 계정 회수 (RecoverNested)" / "Recover nested token account (RecoverNested)";
    CB_HEAP = "힙 크기 요청 (RequestHeapFrame), 바이트" / "Request heap size (RequestHeapFrame), bytes";
    CB_CU_LIMIT = "CU 한도 (SetComputeUnitLimit)" / "CU limit (SetComputeUnitLimit)";
    CB_CU_PRICE = "CU 가격 (SetComputeUnitPrice), micro-lamports/CU"
        / "CU price (SetComputeUnitPrice), micro-lamports/CU";
    CB_DATA_LIMIT = "읽는 계정 데이터 한도 (SetLoadedAccountsDataSizeLimit), 바이트"
        / "Loaded account data limit (SetLoadedAccountsDataSizeLimit), bytes";

    // ----- instruction list --------------------------------------------------------------------
    UNKNOWN_PROGRAM = "알 수 없는 프로그램" / "Unknown program";
    MEMO_TEXT(1) = "메모: {0}" / "Memo: {0}";
    MEMO_HEX(1) = "메모(hex):\n{0}" / "Memo (hex):\n{0}";
    T_MEMO = "메모" / "Memo";
    T_PRECOMPILE(1) = "서명 검증 {0}건 (계정 사용 없음)" / "Signature verification: {0} (no accounts used)";
    T_UNKNOWN_REASON(1) = "해석하지 않음 — {0}" / "Uninterpreted — {0}";
    T_UNKNOWN = "해석하지 않음" / "Uninterpreted";
    ACCOUNT_UNRESOLVED(2) = "{0}: 조회 테이블 인덱스 {1} (해석 못 함)" / "{0}: lookup table index {1} (unresolved)";
    DATA_BYTES(1) = "데이터 {0}바이트" / "Data {0} bytes";
    NO_INSTRUCTIONS = "명령 없음" / "No instructions";

    // ----- signers, writable accounts, lookups -------------------------------------------------
    SIGNER_FEE_PAYER(1) = "서명자 {0} · 수수료 지불" / "Signer {0} · fee payer";
    SIGNER_N(1) = "서명자 {0}" / "Signer {0}";
    SLOT_WALLET = "지갑이 서명합니다" / "The wallet signs";
    SLOT_MISSING_SEND = "서명 없음 — 지갑이 전송할 수 없습니다" / "No signature — the wallet cannot send";
    SLOT_MISSING = "서명 없음 (사이트가 나중에 채움)" / "No signature (the site fills it in later)";
    SLOT_SITE_OK = "사이트가 넣은 서명 (확인됨)" / "Signature added by the site (verified)";
    SITE_SIGNATURE_BAD = "사이트가 넣은 서명이 맞지 않습니다" / "A signature added by the site does not verify";
    DEMOTED = "(런타임에서 읽기 전용)" / "(read-only at runtime)";
    WRITABLE_UNKNOWN = "조회 테이블을 해석하지 못해 테이블에서 오는 쓰기 가능한 주소를 알 수 없습니다"
        / "The lookup tables could not be resolved, so the writable addresses they give are unknown";
    NONE = "없음" / "None";
    NO_TABLES_LEGACY = "조회 테이블 없음 (legacy 거래)" / "No lookup tables (legacy transaction)";
    NO_TABLES = "조회 테이블 없음" / "No lookup tables";
    TABLE_N(1) = "테이블 {0}" / "Table {0}";
    TABLE_DEACTIVATED = "비활성화된 테이블" / "Deactivated table";
    KIND_WRITE = "쓰기" / "writable";
    KIND_READ = "읽기" / "read-only";
    LOOKUP_ENTRY(2) = "{0} · 인덱스 {1}" / "{0} · index {1}";
    UNRESOLVED_ERROR(1) = "해석하지 못함: {0}" / "Could not resolve: {0}";

    // ----- changes, simulation, fee ------------------------------------------------------------
    CHANGES_NO_SIM = "시뮬레이션 결과가 없어 변화를 확인할 수 없습니다"
        / "No simulation result, so the changes cannot be checked";
    CHANGES_NONE = "지켜본 계정(내 지갑·내 토큰 계정·새 계정)에 변화 없음"
        / "No change in the watched accounts (my wallet · my token accounts · new accounts)";
    CHANGE_SOL(4) = "내 지갑 SOL {0} SOL ({1} → {2} lamports{3})" / "My wallet SOL {0} SOL ({1} → {2} lamports{3})";
    FEE_INCLUDED = ", 수수료 포함" / ", fee included";
    TOKEN_FALLBACK = "토큰" / "tokens";
    CHANGE_TOKEN_RPC(2) = "{0} 토큰 (decimals {1} RPC 참고)" / "{0} tokens (decimals {1} from RPC, reference)";
    CHANGE_TOKEN(2) = "내 토큰{0} {1}" / "My token{0} {1}";
    AUTH_CHANGE_OWNER = "권한 변화: 토큰 계정 소유자" / "Authority change: token account owner";
    AUTH_CHANGE_DELEGATE = "권한 변화: 토큰 계정 위임자" / "Authority change: token account delegate";
    AUTH_CHANGE_CLOSE = "권한 변화: 토큰 계정 닫기 권한" / "Authority change: token account close authority";
    AUTH_CHANGE_WALLET = "권한 변화: 내 지갑의 소유 프로그램" / "Authority change: my wallet's owner program";
    SIM_OK(1) = "성공 (CU {0})" / "Success (CU {0})";
    SIM_NO_RESULT = "결과 없음" / "No result";
    SIM_REPLACED = "블록해시를 바꿔 시뮬레이션함(replaceRecentBlockhash) — 참고용"
        / "Simulated with a replaced blockhash (replaceRecentBlockhash) — reference only";
    FEE_RPC_NONE = "RPC가 답하지 않음 (getFeeForMessage)" / "No answer from the RPC (getFeeForMessage)";
    FEE_REJECTED(1) = "계산값 {0} (ComputeBudget 명령을 런타임이 거부 — 처리되지 않으며 우선 수수료 없이 계산)"
        / "Computed {0} (the runtime rejects the ComputeBudget instructions — not processed; computed without a priority fee)";
    FEE_EXACT(1) = "계산값 {0} (거래 바이트로 계산)" / "Computed {0} (from the transaction bytes)";
    FEE_RANGE(1) = "계산값 {0} (CU 한도가 없어 범위로 계산)" / "Computed {0} (a range: no CU limit)";
    FEE_PAYER_ME = "수수료 지불: 내 지갑" / "Fee payer: my wallet";
    FEE_CAP(1) = "사용자 상한 {0} lamports" / "Your cap {0} lamports";
    FEE_PAYER_OTHER = "수수료 지불: 다른 계정" / "Fee payer: another account";

    // ----- X cause lines -----------------------------------------------------------------------
    X_EXTENSION(1) = "Token-2022 확장 명령 {0}" / "Token-2022 extension instruction {0}";
    X_PROGRAM_NAMED(2) = "{0} 프로그램 {1}" / "{0} program {1}";
    X_PROGRAM(1) = "프로그램 {0}" / "Program {0}";
    X04_CAUSE = "토큰 사용 권한 위임" / "Delegate token spending";
    X07_CAUSE(1) = "남은 SOL을 받는 주소 {0}" / "Receives the remaining SOL: {0}";
    X10_DEACTIVATED(1) = "비활성화된 테이블 {0}" / "Deactivated table {0}";
    X01_NEED_ALL = "전송하려면 다른 서명이 모두 있어야 합니다" / "Sending needs every other signature";
    X01_NONCE_SEND = "durable nonce 거래는 지갑이 전송하지 않습니다"
        / "The wallet does not send durable nonce transactions";
    X01_SCAN = "복구 스캔 계정으로는 사이트 거래에 서명하지 않습니다"
        / "A recovery-scan account does not sign site transactions";
    X13_OTHER_PAYER = "수수료는 다른 계정이 냅니다" / "Another account pays the fee";
    X13_SITE_SIGNED = "사이트가 넣은 서명이 있습니다" / "The site added signatures";
    X12_UNREAD(1) = "mint {0} · 확장을 읽지 못했습니다" / "mint {0} · its extensions could not be read";
    X14_CAUSE(2) = "{0} lamports > 상한 {1} lamports" / "{0} lamports > cap {1} lamports";
    X14_CAUSE_MAX(2) = "최대 {0} lamports > 상한 {1} lamports" / "up to {0} lamports > cap {1} lamports";
    X20_CAUSE(2) = "RPC {0} lamports · 계산값 {1}" / "RPC {0} lamports · computed {1}";

    // ----- per-transaction fields, title, summary ----------------------------------------------
    SUB_TX(2) = "거래 {0}/{1}" / "Transaction {0}/{1}";
    VALIDITY_NONCE = "durable nonce — 만료 없음\n서명한 거래는 언제든 제출될 수 있습니다"
        / "durable nonce — no expiry\nThe signed transaction can be submitted at any time";
    BLOCKHASH_OK = "블록해시 유효 확인됨 (RPC, processed)" / "Blockhash verified as valid (RPC, processed)";
    BLOCKHASH_UNCHECKED = "블록해시 확인 안 됨 — 만료되었거나 RPC보다 새것"
        / "Blockhash not verified — expired or newer than the RPC";
    VALIDITY(1) = "{0}\n블록해시는 약 150블록 뒤 만료됩니다 — 늦게 승인하면 거래가 실패할 수 있습니다"
        / "{0}\nThe blockhash expires after about 150 blocks — approving late can make the transaction fail";
    TITLE_SIGN_SEND = "사이트 거래 서명 후 전송" / "Sign and send site transaction";
    TITLE_SIGN = "사이트 거래 서명" / "Sign site transaction";
    TITLE_SIGN_N(1) = "사이트 거래 {0}건 서명" / "Sign {0} site transactions";
    PREFLIGHT_SKIP = "preflight 검사: 생략 (skipPreflight)" / "Preflight check: skipped (skipPreflight)";
    PREFLIGHT(1) = "preflight 검사: 함 (commitment {0})" / "Preflight check: on (commitment {0})";
    MIN_SLOT_NONE = "minContextSlot: 없음" / "minContextSlot: none";
    MIN_SLOT(1) = "minContextSlot: {0} (첫 전송만)" / "minContextSlot: {0} (first send only)";
    RESEND = "재전송: 만료될 때까지 지갑이 직접 (maxRetries 0)"
        / "Resending: by the wallet itself until expiry (maxRetries 0)";
    SUMMARY_SIGN_ONLY(1) = "서명만 — 서명한 거래를 사이트에 돌려줍니다 (지갑은 전송하지 않음)\n거래 {0}건"
        / "Sign only — the signed transactions go back to the site (the wallet does not send them)\nTransactions: {0}";
    SUMMARY_SEND = "서명 후 전송 — 지갑이 서명하고 바로 전송합니다\n거래 1건"
        / "Sign and send — the wallet signs and sends right away\nTransactions: 1";

    // ----- payload errors (SolTxPayloadError) --------------------------------------------------
    PAYLOAD_COUNT = "사이트 거래 수가 맞지 않습니다" / "The number of site transactions is wrong";
    PAYLOAD_SLOT = "서명자 슬롯이 맞지 않습니다" / "The signer slot does not match";
    PAYLOAD_LOADED = "조회 테이블 주소 수가 맞지 않습니다"
        / "The number of lookup table addresses does not match";
    PAYLOAD_MISSING_SIGNATURE = "전송하려면 다른 서명이 모두 필요합니다"
        / "Sending needs all other signatures";
    PAYLOAD_DURABLE_NONCE = "durable nonce 거래는 지갑이 전송하지 않습니다"
        / "The wallet does not send durable nonce transactions";
    PAYLOAD_SOURCE = "복구 스캔 계정으로는 서명하지 않습니다"
        / "Recovery scan accounts do not sign";

    // ----- parse errors (SolTxError: PARSE_ERROR with one reason) ------------------------------
    PARSE_ERROR(1) = "사이트 거래 형식이 올바르지 않습니다: {0}" / "The site transaction is malformed: {0}";
    PARSE_EMPTY = "비어 있음" / "empty";
    PARSE_TOO_LARGE = "1,232바이트를 넘음" / "over 1,232 bytes";
    PARSE_SHORT_VEC = "길이 표기(compact-u16)가 잘못됨" / "invalid length prefix (compact-u16)";
    PARSE_TRUNCATED = "중간에 끝남" / "ends early";
    PARSE_VERSION(1) = "지원하지 않는 메시지 버전({0})" / "unsupported message version ({0})";
    PARSE_HEADER = "header 값이 계정 키와 맞지 않음" / "header values do not match the account keys";
    PARSE_TOO_MANY_KEYS = "계정 키가 256개를 넘음" / "more than 256 account keys";
    PARSE_DUPLICATE_KEY = "같은 계정 키가 두 번 있음" / "an account key appears twice";
    PARSE_PROGRAM_INDEX = "프로그램 인덱스가 잘못됨" / "invalid program index";
    PARSE_ACCOUNT_INDEX = "계정 인덱스가 범위 밖" / "account index out of range";
    PARSE_EMPTY_LOOKUP = "주소를 하나도 읽지 않는 조회 테이블 항목"
        / "a lookup table entry that loads no address";
    PARSE_TOO_MANY_IX = "명령이 64개를 넘음" / "more than 64 instructions";
    PARSE_SIGNATURE_COUNT = "서명 수가 필요한 서명자 수와 다름"
        / "the signature count differs from the required signers";
    PARSE_TRAILING = "끝에 남는 바이트가 있음" / "trailing bytes";
    PARSE_ENCODING = "다시 인코딩한 바이트가 다름" / "re-encoded bytes differ";
    PARSE_NOT_SIGNER = "이 계정은 거래의 서명자가 아님" / "this account is not a signer of the transaction";

    // ----- signer errors (SolTxSignError) ------------------------------------------------------
    SIGN_DEADLINE = "승인 후 서명까지 시간이 너무 오래 걸려 서명하지 않았습니다"
        / "Too much time passed between approval and signing, so nothing was signed";
    SIGN_TABLES_CHANGED = "조회 테이블 주소가 승인한 값과 달라 서명하지 않았습니다"
        / "The lookup table addresses differ from the approved ones, so nothing was signed";
    SIGN_FOREIGN = "사이트가 넣은 서명이 맞지 않아 서명하지 않았습니다"
        / "A signature added by the site is invalid, so nothing was signed";
    SIGN_INTERNAL = "내부 검증에 실패해 서명하지 않았습니다."
        / "Internal verification failed, so nothing was signed.";
    SIGN_POST = "서명하지 못했습니다(내부 오류)" / "Could not sign (internal error)";
}
