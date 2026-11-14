//! Fixed texts of the EVM screens (S10 network, tokens and activity, S11 send and result, S12
//! receive, S15 `EVM 체인` and fee caps, S16 token add, S17 chain add/edit and the T-CHAIN-PIN /
//! T-CHAIN-REPIN confirmations; spec/04 §2.6–§2.8, §2.11, §2.16, §2.17) in Korean and English
//! (spec/14 §5).

yw_core::texts! {
    // ----- S15 add row, S17 title -------------------------------------------------------------
    CHAIN_ADD_HELP = "다른 EVM 체인(L1·L2)은 여기서 추가합니다 — chainId·RPC 주소를 넣으면 chainId와 블록 0을 확인해 등록합니다."
        / "Add other EVM chains (L1·L2) here — enter the chainId and RPC address, and the chainId and block 0 are checked before the chain is registered.";
    CHAIN_ADD = "EVM 체인 추가" / "Add EVM chain";
    CHAIN_EDIT_TITLE = "EVM 체인 편집" / "Edit EVM chain";

    // ----- activity -----------------------------------------------------------------------------
    STATUS_SUCCEEDED = "성공" / "Succeeded";
    STATUS_FAILED = "실패" / "Failed";
    STATUS_DROPPED = "폐기됨" / "Discarded";
    STATUS_REPLACED = "대체됨" / "Replaced";
    STATUS_EXPIRED = "만료" / "Expired";
    STATUS_REJECTED = "거부됨" / "Rejected";
    STATUS_CONFLICTED = "충돌" / "Conflicted";
    STATUS_STOPPED = "중단됨" / "Stopped";
    /// The recipient heading (`{0}` = a `TO_*` part or empty).
    RECIPIENT(1) = "받는 주소{0}" / "Recipient{0}";
    TO_BOOK(1) = " → 주소록: {0}" / " → Address book: {0}";
    TO_MINE(1) = " → 내 계정: {0}" / " → My account: {0}";
    REC_HASH_MISMATCH = "RPC가 다른 거래 해시를 반환했습니다 (재전송·폐기)"
        / "The RPC returned a different transaction hash (rebroadcast/discard)";
    REC_SEND_FAILED = "전송 실패 — 재전송하거나 폐기하세요" / "Send failed — rebroadcast or discard it";
    REC_CONFIRMING = "전송 확인 중" / "Confirming the send";
    REC_SIGNED = "서명됨" / "Signed";
    REC_BROADCAST = "전송됨" / "Sent";
    REC_FINAL_FAILED(1) = "확정 (실행 실패, 블록 {0})" / "Final (execution failed, block {0})";
    REC_FINAL(1) = "확정 (블록 {0})" / "Final (block {0})";
    REC_NONCE_USED = "다른 거래가 이 nonce를 사용" / "Another transaction used this nonce";
    RAW_UNITS(1) = "{0} (원시 단위)" / "{0} (raw units)";
    HIDDEN_TOKEN_TAG = " · [숨긴 토큰]" / " · [hidden token]";
    SENT_TITLE = "보낸 거래" / "Sent transactions";
    SENT_NONE = "아직 보낸 거래가 없습니다." / "No transactions sent yet.";
    /// Replace-by-fee has one name on every chain (Bitcoin's `수수료 올리기`).
    SPEED_UP = "수수료 올리기" / "Speed up";
    CANCEL_TX = "취소" / "Cancel";
    RESEND = "재전송" / "Rebroadcast";
    DISCARD = "폐기" / "Discard";
    ACTIVITY_FOLD = "이전 활동 접기 ▾" / "Hide earlier activity ▾";
    ACTIVITY_MORE(1) = "이전 활동 {0}건 더 보기 ▸" / "Show {0} earlier ▸";

    // ----- status line, network card --------------------------------------------------------------
    RPC_NO_ADDRESS = "RPC 주소 없음 (E-KEY-005)" / "No RPC address (E-KEY-005)";
    /// `{0}` code, `{1}` the browser status.
    RPC_BLOCKED(2) = "RPC: 차단 {0}   ·   {1}" / "RPC: blocked {0}   ·   {1}";
    CONNECTED = "연결됨" / "Connected";
    UNCHECKED = "확인 전" / "Not checked";
    BLOCKED_TAG = " (차단됨)" / " (blocked)";
    BLOCKED_CODE(1) = "차단 {0}" / "Blocked {0}";
    /// What a built-in mainnet's name is checked for before `MAINNET_SUFFIX` is added.
    MAINNET_WORD = "메인넷" / "Mainnet";
    MAINNET_SUFFIX(1) = "{0} (메인넷)" / "{0} (Mainnet)";
    REPIN_IN_SETTINGS = "설정에서 다시 고정" / "Re-pin in settings";
    RPC_TEST = "RPC 테스트" / "Test RPC";
    RPC_SETTINGS = "RPC 설정" / "RPC settings";
    IMPORTED_KEY = "가져온 개인키" / "Imported private key";
    /// `{0}` amount, `{1}` block.
    BALANCE_AT_BLOCK(2) = "잔액 {0} (블록 {1})" / "Balance {0} (block {1})";
    REFRESH_FAILED(1) = " — 갱신 실패 {0}" / " — refresh failed {0}";

    // ----- token card -----------------------------------------------------------------------------
    TOKENS_TITLE = "토큰" / "Tokens";
    TOKENS_NONE = "표시할 토큰이 없습니다. '토큰 추가'로 컨트랙트 주소를 넣으면 잔액을 함께 봅니다."
        / "No tokens to show. Add a contract address with 'Add token' to see its balance here.";
    TOKENS_NONE_SHOWN = "보이는 토큰이 없습니다. 숨긴 토큰은 아래에서 다시 볼 수 있습니다."
        / "No visible tokens. Hidden tokens can be shown again below.";
    TOKEN_ADD = "토큰 추가" / "Add token";
    HIDE_ZERO_COUNT(1) = "잔액 0 숨기기 ({0}개)" / "Hide zero balances ({0})";
    HIDE_ZERO = "잔액 0 숨기기" / "Hide zero balances";
    HIDDEN_FOLD_COUNT(1) = "숨긴 토큰 {0}개 접기 ▾" / "Hide {0} hidden tokens ▾";
    HIDDEN_SHOW_COUNT(1) = "숨긴 토큰 {0}개 보기 ▸" / "Show {0} hidden tokens ▸";
    /// T-TOKEN-HIDDEN: the note above the hidden token rows (spec/04 §2.6).
    TOKEN_HIDDEN_NOTE = "숨긴 토큰은 이 목록과 보내기 화면의 자산 선택에서만 빠집니다. 자산은 그대로입니다."
        / "Hidden tokens are only left out of this list and the send screen's asset choice. The assets stay as they are.";
    BALANCE_UNKNOWN = "잔액 알 수 없음" / "Balance unknown";
    HIDDEN = "숨김" / "Hidden";
    NAME_HIDDEN(1) = "{0} · 숨김" / "{0} · hidden";
    SEND = "보내기" / "Send";
    UNHIDE = "다시 보이기" / "Show";
    HIDE = "숨기기" / "Hide";
    DELETE = "삭제" / "Delete";
    USER_TOKEN(1) = "{0} (사용자 추가)" / "{0} (added by you)";
    NAME_BALANCE_UNKNOWN(1) = "{0} · 잔액 모름" / "{0} · balance unknown";

    // ----- S11 -----------------------------------------------------------------------------------
    SEND_TITLE(1) = "보내기 — {0}" / "Send — {0}";
    TESTNET_BAND = "테스트넷 — 실제 자산이 아닙니다" / "Testnet — not real assets";
    IN_FLIGHT = "이 계정의 이전 거래가 아직 확정되지 않았습니다. 확정된 뒤 보낼 수 있습니다."
        / "This account's previous transaction is not final yet. You can send once it is.";
    FROM_ACCOUNT = "보내는 계정" / "From account";
    BALANCE_SUFFIX(1) = " · 잔액 {0}" / " · balance {0}";
    SWITCH_ACCOUNT = "다른 계정으로 바꾸기 (메인)" / "Switch account (main)";
    RECIPIENT_CARD = "받는 사람" / "Recipient";
    RECIPIENT_FIELD = "받는 주소" / "To address";
    PICK_FROM_BOOK = "주소록에서 선택" / "Pick from address book";
    ADDRESS_FORMAT = "0x로 시작하는 42자 주소" / "A 42-character address starting with 0x";
    CHECK_WHOLE = "앞뒤만이 아니라 주소 전체를 확인하세요."
        / "Check the whole address, not only its start and end.";
    ACK_WHOLE = "주소 전체를 직접 확인했습니다" / "I checked the whole address myself";
    ASSET_CARD = "보낼 자산과 금액" / "Asset and amount";
    ASSET = "자산" / "Asset";
    HIDDEN_FOLD = "숨긴 토큰 접기 ▾" / "Hide hidden tokens ▾";
    HIDDEN_TOKENS = "숨긴 토큰" / "Hidden tokens";
    AT_BLOCK(1) = " (블록 {0} 기준)" / " (as of block {0})";
    HELD_UNREAD(1) = "보유 {0}: 잔액을 아직 읽지 못했습니다" / "Holding {0}: balance not read yet";
    /// `{0}` amount, `{1}` the `AT_BLOCK` part or empty.
    HELD(2) = "보유 {0}{1}" / "Holding {0}{1}";
    TOKEN_CONTRACT(1) = "토큰 컨트랙트 {0}" / "Token contract {0}";
    AMOUNT_FIELD(1) = "금액 ({0})" / "Amount ({0})";
    MAX = "최대" / "Max";
    AMOUNT_HINT_NATIVE = "예: 0.01 · '최대'는 수수료를 뺀 잔액 전부입니다."
        / "e.g. 0.01 · 'Max' is the whole balance minus the fee.";
    AMOUNT_HINT_TOKEN(1) = "예: 0.01 · '최대'는 이 토큰 잔액 전부입니다. 수수료는 {0}로 따로 냅니다."
        / "e.g. 0.01 · 'Max' is the whole token balance. The fee is paid separately in {0}.";
    NO_FEE_ASSET(1) = "수수료를 낼 {0}이(가) 부족합니다 — 이 계정에 {0}을(를) 먼저 받으세요."
        / "Not enough {0} to pay the fee — receive {0} on this account first.";
    /// `{0}` the fee summary, `{1}` the native holding.
    FEE_HELD(2) = "{0} (보유 {1})" / "{0} (holding {1})";
    BALANCE_UNKNOWN_SHORT = "잔액 모름" / "balance unknown";
    FEE_DETAIL(1) = "계산: {0}" / "Calculation: {0}";
    FEE_DETAIL_HIDE = "수수료 계산 숨기기 ▾" / "Hide fee calculation ▾";
    FEE_DETAIL_SHOW = "수수료 계산 보기 (가스 한도·gwei) ▸" / "Show fee calculation (gas limit·gwei) ▸";
    ESTIMATE_FAILED = "가스 추정 실패 — 거래가 실패할 수 있습니다 (승인 창에서 확인)"
        / "Gas estimation failed — the transaction may fail (check in the approval window)";
    REVIEW = "검토" / "Review";
    CANCEL = "취소" / "Cancel";
    PICK_MINE(1) = "내 계정: {0}" / "My account: {0}";
    PICK_FAVORITE(1) = "★ 주소록: {0}" / "★ Address book: {0}";
    PICK_BOOK(1) = "주소록: {0}" / "Address book: {0}";
    PICK_NONE = "일치하는 주소록 항목이 없습니다. 주소록에 저장하면 여기에서 고를 수 있습니다."
        / "No matching address-book entry. Save one to the address book to pick it here.";

    // ----- S11 result, S12 -----------------------------------------------------------------------
    RESULT_TITLE = "보내기 결과" / "Send result";
    RESULT_SENT = "전송했습니다. 블록에 포함되면(확인 1) 활동에 '확정'으로 표시됩니다."
        / "Sent. Once it is in a block (1 confirmation), Activity shows it as 'Final'.";
    STATE = "상태" / "Status";
    TX_HASH = "거래 해시" / "Transaction hash";
    BACK_MAIN = "메인으로" / "Back to main";
    RECEIVE_TITLE(1) = "받기 — {0}" / "Receive — {0}";
    BACKUP_PENDING = "백업 확인 전입니다. 확인을 마치기 전에는 큰 금액을 받지 마세요."
        / "The backup is not confirmed yet. Do not receive large amounts until it is.";
    TESTNET_ADDRESS = "테스트넷 주소입니다." / "This is a testnet address.";
    RECEIVE_ONLY(1) = "{0} 네트워크의 자산만 이 주소로 받으세요."
        / "Receive only assets of the {0} network at this address.";
    PLAIN_QR(1) = "주소만 담은 QR에는 네트워크 정보가 없습니다. 보내는 쪽(거래소 출금 화면 등)에서 네트워크를 {0}(으)로 직접 고르세요."
        / "A QR code with only the address carries no network. The sender (an exchange withdrawal screen, …) must pick {0} as the network themselves.";

    // ----- S16 -----------------------------------------------------------------------------------
    TOKEN_TITLE(1) = "토큰 추가 — {0}" / "Add token — {0}";
    CONTRACT_ADDRESS = "컨트랙트 주소" / "Contract address";
    LOOKUP = "조회" / "Look up";
    TOKEN_HELP = "토큰의 컨트랙트 주소를 넣고 '조회'를 누르면 체인에서 소수 자릿수와 기호를 읽습니다. 공식 사이트나 탐색기에서 확인한 주소만 쓰세요."
        / "Enter the token's contract address and press 'Look up' to read its decimals and symbol from the chain. Use only an address you checked on the official site or an explorer.";
    UNREADABLE = "읽을 수 없음" / "unreadable";
    SYMBOL_UNSHOWABLE = "(표시할 수 없는 기호)" / "(symbol cannot be shown)";
    /// `{0}` decimals, `{1}` symbol.
    TOKEN_META(2) = "decimals: {0}, 체인에서 읽은 기호: {1}" / "decimals: {0}, symbol read from the chain: {1}";
    LABEL = "라벨" / "Label";
    LABEL_HELP = "목록과 승인 창에 보일 이름입니다. 컨트랙트 주소와 함께 표시됩니다."
        / "The name shown in the list and approval windows, together with the contract address.";
    SAVE = "저장" / "Save";

    // ----- S15 chains and fee caps -----------------------------------------------------------------
    CHAINS_TITLE = "EVM 체인" / "EVM chains";
    CHAINS_HELP = "기본 체인 7개(Ethereum·Sepolia·HyperEVM·Arbitrum One·Base·BNB Smart Chain·Robinhood Chain)와 직접 추가한 체인입니다. 체인마다 RPC 주소가 있어야 쓸 수 있고, 연결할 때마다 chainId와 첫 블록(제네시스)을 다시 확인합니다."
        / "The 7 built-in chains (Ethereum·Sepolia·HyperEVM·Arbitrum One·Base·BNB Smart Chain·Robinhood Chain) and chains you added. Each chain needs an RPC address, and every connection checks the chainId and the first block (genesis) again.";
    /// `{0}` symbol, `{1}` decimals, `{2}` simulation, `{3}` state, `{4}` the endpoint text.
    CHAIN_LINE(5) = "{0}, 소수 {1} · 시뮬레이션 {2} · {3} · RPC 주소: {4}"
        / "{0}, decimals {1} · simulation {2} · {3} · RPC address: {4}";
    QUICKNODE_ENTRY(1) = "QuickNode 서브도메인 {0}" / "QuickNode subdomain {0}";
    ALCHEMY_ENTRY(1) = "알케미 라벨 {0}" / "Alchemy label {0}";
    EXPLORER_ENTRY(1) = "탐색기 {0}" / "Explorer {0}";
    PIN_ON_FIRST = "첫 연결 때 고정" / "pinned on first connection";
    EDIT = "편집" / "Edit";
    REPIN = "다시 고정" / "Re-pin";
    CAPS_TITLE = "EVM 수수료 상한 (고급)" / "EVM fee caps (advanced)";
    CAPS_HELP = "지갑이 계산한 수수료가 이 값을 넘으면 보내기를 막습니다(잘못된 RPC가 수수료를 부풀리는 것을 막는 안전장치). 보통은 바꿀 필요가 없습니다."
        / "Sending is blocked when the fee the wallet computes exceeds these values (a safeguard against a bad RPC inflating the fee). Usually there is no need to change them.";
    CHAIN = "체인" / "Chain";
    CAPS_PICK = "상한을 바꿀 체인을 고르세요." / "Pick the chain whose caps to change.";
    CAPS_FEE = "maxFee 상한 (gwei)" / "maxFee cap (gwei)";
    CAPS_TIP = "tip 상한 (gwei)" / "tip cap (gwei)";
    CAPS_TOTAL(1) = "총 최대 수수료 ({0})" / "Total max fee ({0})";
    DEFAULTS = "기본값으로" / "Reset";
    CAPS_RANGE = "범위: maxFee 1–10,000 gwei, tip 0.01–10,000 gwei(maxFee 상한 이하), 총 0.0001–10. 다음 준비부터 적용됩니다."
        / "Ranges: maxFee 1–10,000 gwei, tip 0.01–10,000 gwei (at most the maxFee cap), total 0.0001–10. Applies from the next preparation.";

    // ----- S17 -----------------------------------------------------------------------------------
    CHAIN_ID_HELP = "체인 고유 번호입니다(10진수). 체인 공식 문서나 chainlist에서 확인하세요."
        / "The chain's unique number (decimal). Check it in the chain's official docs or on chainlist.";
    NAME = "이름" / "Name";
    NATIVE_HELP = "수수료를 내는 기본 자산의 기호와 소수 자릿수입니다(대부분 18)."
        / "The symbol and decimals of the native asset that pays fees (mostly 18).";
    CREDENTIAL_SET = "설정됨" / "set";
    CREDENTIAL_NONE = "없음" / "none";
    RPC_HINT_QUICKNODE(1) = "https:// 주소 또는 QuickNode 서브도메인(예 base-sepolia). 자격 정보: {0}"
        / "An https:// address or a QuickNode subdomain (e.g. base-sepolia). Credential: {0}";
    RPC_HINT_ALCHEMY(1) = "https:// 주소 또는 알케미 라벨(예 base-sepolia). 자격 정보: {0}"
        / "An https:// address or an Alchemy label (e.g. base-sepolia). Credential: {0}";
    RPC_HINT_MANUAL = "https:// 주소 (직접 입력 템플릿)" / "An https:// address (manual template)";
    RPC_ADDRESS = "RPC 주소" / "RPC address";
    RPC_KEEP(1) = "{0} · 비워 두면 기존 주소를 유지합니다." / "{0} · Leave empty to keep the current address.";
    EXPLORER_OPTIONAL = "탐색기 URL(선택)" / "Explorer URL (optional)";
    SIMULATION = "시뮬레이션" / "Simulation";
    SIM_AUTO = "auto (항상 시도)" / "auto (always try)";
    SIM_UNSUPPORTED = "unsupported (호출하지 않음)" / "unsupported (never called)";
    SIM_HELP = "승인 전에 거래 결과를 미리 실행해 보는 기능입니다. RPC가 지원하지 않으면 unsupported를 고르세요. 그 체인의 승인은 언제나 고위험 경고와 함께 표시됩니다."
        / "Runs the transaction ahead of the approval to preview its result. Pick unsupported if the RPC does not support it; approvals on that chain then always show a high-risk warning.";
    /// T-CHAIN-PIN (`{0}` chainId, `{1}` name, `{2}` RPC, `{3}` genesis hash).
    CHAIN_PIN(4) = "이 체인의 제네시스 해시를 지금 받은 값으로 고정합니다. 이후 연결할 때마다 chainId와 이 값을 비교하고, 다르면 이 체인을 쓰지 않습니다. 해시가 공식 자료(체인 문서·탐색기)의 값과 같은지 확인하세요.\nchainId {0}\n이름 {1}\nRPC {2}\n제네시스 {3}"
        / "Pins this chain's genesis hash to the value just received. Every later connection compares the chainId and this value, and the chain is not used if they differ. Check that the hash matches the official sources (chain docs, explorer).\nchainId {0}\nName {1}\nRPC {2}\nGenesis {3}";
    /// T-CHAIN-REPIN (`{0}` pinned, `{1}` new).
    CHAIN_REPIN(2) = "고정된 제네시스 해시와 RPC가 알려준 값이 다릅니다. RPC가 다른 체인을 가리키거나 체인이 새로 시작되었을 수 있습니다. 새 값을 공식 자료로 확인한 경우에만 다시 고정하세요.\n고정된 값 {0}\n새 값     {1}"
        / "The pinned genesis hash differs from the value the RPC reported. The RPC may point to another chain, or the chain may have restarted. Re-pin only if you checked the new value against official sources.\nPinned {0}\nNew    {1}";
}
