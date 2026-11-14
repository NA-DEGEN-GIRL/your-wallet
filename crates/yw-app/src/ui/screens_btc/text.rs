//! Fixed texts of the Bitcoin screens (S10 tab, send and fee-bump forms, result, S12 receive,
//! S15 Bitcoin section; spec/04 §2.6–§2.8, §2.11, §2.16, spec/08, spec/14). 2026-11-14 (Step 3):
//! Korean literals in `screens_btc.rs` before, with the same Korean bytes.

yw_core::texts! {
    /// The received history's unconfirmed deposits under the balance (`{0}` amount; shared with
    /// the Zcash card).
    PENDING_LINE(1) = "미확정 입금 {0} (0 확인 — 바뀌거나 취소될 수 있습니다, 아직 쓸 수 없음)"
        / "Unconfirmed deposit {0} (0 confirmations — it may change or be cancelled; not spendable yet)";
    /// T-BTC-ESPLORA-NOTE (spec/04 §2.16).
    T_BTC_ESPLORA_NOTE = "인덱서(Esplora 서버)는 조회하는 주소와 이 PC의 IP를 봅니다. 기본값은 mempool.space이며 자체 Esplora 서버로 바꿀 수 있습니다. mempool.space에 연결되지 않으면 아래 Esplora URL을 https://blockstream.info/api (testnet4는 https://blockstream.info/testnet4/api)로 바꾸고 테스트하세요. Esplora URL은 평문으로 저장되므로 토큰·API 키가 들어 있는 URL은 넣지 마세요."
        / "The indexer (Esplora server) sees the addresses you look up and this PC's IP. The default is mempool.space; you can switch to your own Esplora server. If mempool.space does not connect, change the Esplora URL below to https://blockstream.info/api (testnet4: https://blockstream.info/testnet4/api) and test it. The Esplora URL is stored in plain text, so do not enter a URL that contains a token or API key.";
    /// Journal damage of the BTC entries (spec/08 §12.4, E-VLT-006).
    JOURNAL_DAMAGED = "거래 저널의 Bitcoin 기록이 손상되어 Bitcoin 보내기를 멈췄습니다. (E-VLT-006)"
        / "The Bitcoin entries of the transaction journal are damaged, so Bitcoin sending is stopped. (E-VLT-006)";
    /// Help under the account list (spec/04 §2.6 Bitcoin).
    ACCOUNTS_HELP = "주소 형식은 계정마다 고정입니다(BIP44·49·84·86). 다른 지갑에서 복구할 때 같은 형식을 고르세요."
        / "The address format is fixed per account (BIP44·49·84·86). Choose the same format when you restore in another wallet.";
    /// Help of the add-account chooser.
    ADD_ACCOUNT_HELP = "잘 모르면 네이티브 세그윗을 고르세요. 탭루트 주소로는 일부 거래소가 보내 주지 않습니다. 레거시·호환 세그윗은 오래된 서비스용입니다."
        / "If unsure, choose Native SegWit. Some exchanges do not send to Taproot addresses. Legacy and Nested SegWit are for older services.";

    /// The settings name with its Korean particle (`mainnet으로`, `testnet4로`; English: the name).
    WITH_EURO(1) = "{0}으로" / "{0}";
    WITH_RO(1) = "{0}로" / "{0}";
    /// The mismatch buttons (spec/08 §2; `{0}` the name with its particle).
    MISMATCH_KEEP(1) = "설정을 {0} 되돌리기" / "Set the setting back to {0}";
    MISMATCH_USE(1) = "{0} 바꾸기" / "Switch to {0}";

    /// The usual wait of the fee radios (2·6·24 blocks).
    WAIT_FAST = "약 20분" / "about 20 min";
    WAIT_NORMAL = "약 1시간" / "about 1 hour";
    WAIT_SLOW = "약 4시간" / "about 4 hours";
    NO_ESTIMATE = "추정 없음" / "no estimate";
    /// The plain name of a recipient's address type.
    KIND_P2PKH = "레거시 (P2PKH)" / "Legacy (P2PKH)";
    KIND_P2SH = "호환 세그윗·스크립트 (P2SH)" / "Nested SegWit · script (P2SH)";
    KIND_P2WPKH = "네이티브 세그윗 (P2WPKH)" / "Native SegWit (P2WPKH)";
    KIND_P2WSH = "스크립트 세그윗 (P2WSH)" / "Script SegWit (P2WSH)";
    KIND_P2TR = "탭루트 (P2TR)" / "Taproot (P2TR)";
    /// The selected account's name before BTC has one.
    ACCOUNT_FALLBACK = "Bitcoin 계정" / "Bitcoin account";
    /// Post-sign flow stages.
    STAGE_PRECHECK = "노드 사전 검사(testmempoolaccept) 중…" / "Node pre-check (testmempoolaccept)…";
    STAGE_APPLYING = "저널에 기록하는 중…" / "Writing to the journal…";
    STAGE_SENDING = "전송 중…" / "Sending…";

    /// Gate and status line of the tab.
    RPC_SETUP = "RPC 설정하기" / "Set up RPC";
    STATUS_NO_RPC = "RPC 주소 없음 (E-KEY-005)" / "No RPC address (E-KEY-005)";
    STATUS_BLOCKED = "차단됨" / "Blocked";
    STATUS_CONNECTED(1) = "연결됨 · 블록 높이 {0} (서버 기준)" / "Connected · block height {0} (server data)";
    STATUS_UNCHECKED = "확인 전" / "Not checked";
    STATUS_GENESIS_OK = "genesis 확인됨" / "genesis verified";
    /// `{0}` network id, `{1}` RPC state, `{2}` indexer name, `{3}` its check.
    STATUS_LINE(4) = "Core RPC ({0}): {1}   ·   인덱서: {2} ({3})" / "Core RPC ({0}): {1}   ·   Indexer: {2} ({3})";
    /// Discovery.
    DISCOVERY_PROGRESS(2) = "{0} 검사한 주소 {1}개" / "{0} Addresses checked: {1}";
    DISCOVERY_MORE = "주소를 더 찾는 중…" / "Searching for more addresses…";
    DISCOVERY_RUNNING = "주소를 찾는 중…" / "Searching for addresses…";
    CANCEL = "취소" / "Cancel";
    RETRY = "다시 시도" / "Try again";
    FIND_MORE = "더 찾기" / "Find more";

    /// The account list.
    ACCOUNTS_TITLE = "Bitcoin 계정" / "Bitcoin accounts";
    BADGE_IMPORTED = "가져온 키" / "Imported key";
    BADGE_EVM_KEY(1) = "EVM 계정 {0} 키" / "EVM account {0} key";
    ADD_ACCOUNT = "계정 추가" / "Add account";
    ADDRESS_MODE(1) = "주소 방식 — {0}" / "Address mode — {0}";
    MNEMONIC = "복구 단어" / "Recovery words";
    ADDED_MNEMONIC_HELP = "추가한 복구 단어의 표준 경로 m/{44·49·84·86}'/{코인}'/{계정}'에서 만듭니다(계정 0부터)."
        / "Created on the standard path m/{44·49·84·86}'/{coin}'/{account}' of the added recovery words (from account 0).";
    KEY_SOURCE = "키 출처" / "Key source";
    NO_EVM_ACCOUNTS = "EVM 계정이 없습니다" / "There are no EVM accounts";
    EVM_PICK_HELP = "주소 형식을 누르면 확인 창이 열립니다. 그 EVM 계정의 키로 주소 하나를 만듭니다."
        / "Pressing an address format opens a confirmation. One address is created with that EVM account's key.";

    /// The balance card.
    AVAILABLE_NOTE = "사용 가능 (확인 1 이상, 서버 기준)" / "Available (1+ confirmations, server data)";
    FROZEN(1) = "동결 {0}" / "Frozen {0}";
    PENDING_BALANCE(1) = "확인 대기 {0} (아직 쓸 수 없음)" / "Awaiting confirmation {0} (not spendable yet)";
    BALANCE_DASH = "잔액 —" / "Balance —";
    BALANCE_UNKNOWN = "잔액 알 수 없음" / "Balance unknown";
    VERIFY_FAILURES(1) = "검증 실패 UTXO {0}개" / "UTXOs that failed verification: {0}";
    SKIPPED_ADDRESSES(1) = "UTXO가 너무 많아 목록을 받지 못한 주소 {0}개 — 그 주소의 UTXO는 지난번에 확인한 그대로 두며 이미 쓰였을 수 있습니다"
        / "Addresses whose UTXO list could not be read because it is too long: {0} — their UTXOs stay as last checked and may already be spent";
    HINT_MISMATCH(1) = "서버 응답 불일치 UTXO {0}개 (검증한 값을 씁니다)"
        / "UTXOs where the server answer differs: {0} (the verified values are used)";
    AUTO_FROZEN(1) = "작은 입금 자동 동결(먼지 공격 방지) {0}개"
        / "Small deposits frozen automatically (dust attack protection): {0}";

    /// The UTXO card.
    UTXO_TITLE = "UTXO (검증됨)" / "UTXOs (verified)";
    UTXO_HELP = "UTXO는 받은 돈 한 건 한 건입니다. 작은 입금은 먼지 공격을 막으려고 자동으로 동결합니다. 위 계정 카드의 잔액은 이전 거래로 검증한 UTXO 가운데 확인 수 1 이상(서버 기준)인 것의 합이고, 진행 중 거래가 쓰는 UTXO는 빠집니다."
        / "A UTXO is one single amount you received. Small deposits are frozen automatically to block dust attacks. The balance on the account card above is the sum of the UTXOs verified by their previous transactions with 1+ confirmations (server data); UTXOs used by a pending transaction are left out.";
    NO_UTXOS = "검증된 UTXO가 없습니다." / "No verified UTXOs.";
    UTXO_FROZEN = "동결" / "frozen";
    UTXO_AUTO_FROZEN = "자동 동결(작은 입금, 먼지 공격 방지)" / "frozen automatically (small deposit, dust attack protection)";
    UTXO_IN_FLIGHT = "진행 중 거래가 사용" / "used by a pending transaction";
    UTXO_OWN = "내 잔돈" / "my change";
    UTXO_HINT = "서버 응답 불일치" / "server answer differs";
    UNFREEZE = "해제" / "Unfreeze";
    FREEZE = "동결" / "Freeze";
    UTXO_HIDDEN(2) = "UTXO {0}개는 목록에 표시하지 않았습니다(표시 상한 {1}개)."
        / "{0} UTXOs are not listed (display limit {1}).";

    /// The activity card (`{1}` of the row lines is ` → …` or empty).
    ACTIVITY_TITLE = "보낸 거래" / "Sent transactions";
    NO_ACTIVITY = "아직 보낸 거래가 없습니다." / "No sent transactions yet.";
    TO_BOOK(1) = "→ 주소록: {0}" / "→ Address book: {0}";
    TO_OWN(1) = "→ 내 계정: {0}" / "→ My account: {0}";
    ROW_AMOUNT_TO(2) = "받는 금액 {0} · 받는 주소{1}" / "Amount {0} · Recipient{1}";
    ROW_TO(1) = "받는 주소{0}" / "Recipient{0}";
    BUMP_FEE = "수수료 올리기" / "Bump fee";
    REBROADCAST = "같은 바이트 다시 전송" / "Resend the same bytes";
    ABANDON = "포기" / "Abandon";
    ESPLORA_SEND = "Esplora로 전송" / "Send via Esplora";
    CONTINUE_SEND = "전송 계속" / "Continue sending";

    /// The tab while Bitcoin is off.
    DISABLED_HELP_MNEMONIC = "설정 → Bitcoin에서 켜면 네이티브 세그윗(bc1q…) 계정 0의 주소를 찾아 잔액을 보여줍니다. 다른 주소 형식(탭루트·호환 세그윗·레거시)은 켠 뒤 [계정 추가]로 더하고, 다른 지갑의 WIF 개인키는 [개인키 가져오기]로 더합니다. 먼저 네트워크(RPC)에 bitcoin 주소가 있어야 합니다."
        / "Turn it on in Settings → Bitcoin to find the addresses of Native SegWit (bc1q…) account 0 and show the balance. After that, add other address formats (Taproot, Nested SegWit, Legacy) with [Add account] and WIF private keys from other wallets with [Import private key]. A bitcoin address must be set in Network (RPC) first.";
    DISABLED_HELP_KEYS = "설정 → Bitcoin에서 켜면 가져온 Bitcoin 개인키의 잔액을 보여주고 받기·보내기를 할 수 있습니다. 먼저 네트워크(RPC)에 bitcoin 주소가 있어야 합니다."
        / "Turn it on in Settings → Bitcoin to see the balance of imported Bitcoin private keys and to receive and send. A bitcoin address must be set in Network (RPC) first.";
    BTC_SETTINGS = "Bitcoin 설정" / "Bitcoin settings";
    NETWORK = "네트워크" / "Network";
    TIP_REGRESSED_HELP = "노드 블록 높이가 이 지갑이 전에 본 높이보다 6블록 넘게 낮습니다. 노드(RPC)를 바꿨거나 이전 노드가 잘못된 높이를 알려 준 경우에만 기록을 초기화하세요."
        / "The node block height is more than 6 blocks below the height this wallet saw before. Reset the record only if you changed the node (RPC) or the previous node reported a wrong height.";
    RESET_TIP = "블록 높이 기록 초기화" / "Reset the block height record";
    SIGNED_PENDING(1) = "서명했지만 보내지 않은 Bitcoin 거래가 {0}건 있습니다. 아래 활동에서 [전송 계속] 또는 [취소]를 고르세요."
        / "Signed Bitcoin transactions not sent: {0}. Choose [Continue sending] or [Cancel] in the activity below.";

    /// The selected account card.
    RECEIVE_HINT = "받을 주소는 '받기'를 누르면 새로 만듭니다." / "Press 'Receive' to create a receive address.";
    SEND = "보내기" / "Send";
    RECEIVE = "받기" / "Receive";
    REFRESH = "새로고침" / "Refresh";
    REFRESHING = "새로고침 중…" / "Refreshing…";
    SEND_BLOCKED(1) = "보내기: {0}" / "Send: {0}";

    /// The fee part of the forms.
    EXPECTED_FEE = "예상 수수료" / "Expected fee";
    FEE_ABOUT(2) = "약 {0} sats ({1} BTC)" / "about {0} sats ({1} BTC)";
    FEE_ESTIMATE_HELP = "입력 1개·출력 2개 기준 — UTXO를 여러 개 쓰면 늘어납니다. 검토에서 다시 계산합니다."
        / "For 1 input and 2 outputs — more UTXOs make it higher. Review calculates it again.";
    FEE_OVER_CAP = "이 수수료율은 상한을 넘어 검토 뒤 수수료(sats)를 직접 입력해야 합니다."
        / "This fee rate is above the cap: after review you must enter the fee (sats) yourself.";
    FEE = "수수료" / "Fee";
    FEE_LOADING = "수수료 추정을 불러오는 중…" / "Loading fee estimates…";
    FEE_CHOICE_HELP = "빠름·보통·느림 = 노드 추정(2·6·24블록). 추정이 없으면(testnet4에서 흔함) 직접 입력만 됩니다."
        / "Fast·Normal·Slow = node estimates (2·6·24 blocks). Without an estimate (common on testnet4) only manual entry works.";
    FEE_RATE_LABEL = "수수료율 (sat/vB)" / "Fee rate (sat/vB)";
    FLOOR_NOTE(1) = "수수료 하한 {0} (노드 기준): 추정이 하한보다 낮으면 하한을 적용합니다(하한 적용). 직접 입력은 하한 이상이어야 합니다."
        / "Fee floor {0} (node data): an estimate below the floor uses the floor (Floor applied). A manual entry must be at or above the floor.";
    FLOOR_UNKNOWN = "수수료 하한(1 sat/vB와 노드 최소값 중 큰 값)은 검토할 때 노드에서 확인합니다."
        / "The fee floor (the larger of 1 sat/vB and the node minimum) is checked with the node at review.";
    TYPED_FEE_BANNER(1) = "수수료(sats)를 정확히 입력해 상한 해제 — 계획 수수료 {0}"
        / "Enter the exact fee (sats) to lift the cap — planned fee {0}";
    TYPED_FEE_LABEL = "수수료(sats)" / "Fee (sats)";

    /// The send form.
    SEND_TITLE(1) = "보내기 — {0}" / "Send — {0}";
    FROM_ACCOUNT = "보내는 계정" / "From account";
    AVAILABLE_VERIFIED(1) = "사용 가능 {0} (검증됨, 확인 1 이상 서버 기준)"
        / "Available {0} (verified, 1+ confirmations, server data)";
    RECIPIENT_CARD = "받는 사람" / "Recipient";
    RECIPIENT_ADDRESS = "받는 주소" / "Recipient address";
    PICK_FROM_BOOK = "주소록에서 선택" / "Pick from address book";
    ADDRESS_HINT = "bc1…·tb1… 등 Bitcoin 주소" / "A Bitcoin address such as bc1… or tb1…";
    ADDRESS_KIND(1) = "주소 종류: {0}" / "Address type: {0}";
    CHECK_WHOLE = "강조된 앞뒤 4자만 보지 말고 가운데까지 주소 전체를 확인하세요."
        / "Check the whole address, the middle too, not only the highlighted first and last 4 characters.";
    /// `{0}` label, `{1}` ` ✓ 확인됨` or empty.
    BOOK_ENTRY(2) = "주소록: {0}{1}" / "Address book: {0}{1}";
    VERIFIED = "✓ 확인됨" / "✓ verified";
    ADDR_ACK = "주소 전체를 직접 확인했습니다" / "I checked the whole address myself";
    AMOUNT_CARD = "금액과 수수료" / "Amount and fee";
    AVAILABLE_UNREAD = "사용 가능: 잔액을 아직 읽지 못했습니다" / "Available: the balance has not been read yet";
    AVAILABLE(1) = "사용 가능 {0}" / "Available {0}";
    AMOUNT = "금액" / "Amount";
    MAX = "최대" / "Max";
    MAX_HELP = "최대: 동결되지 않은 확인된 UTXO(최대 100개)의 합에서 수수료를 뺀 금액을 보냅니다(승인 창에서 확인)."
        / "Max: sends the sum of the unfrozen confirmed UTXOs (up to 100) minus the fee (shown in the approval window).";
    AMOUNT_HINT = "BTC는 소수 8자리까지(예 0.0012) · sats는 정수(예 120000)"
        / "BTC with up to 8 decimals (e.g. 0.0012) · sats as a whole number (e.g. 120000)";
    REVIEW = "검토" / "Review";

    /// The fee-bump form.
    BUMP_TITLE(1) = "수수료 올리기 — {0}" / "Bump fee — {0}";
    REPLACED_TX = "교체 대상 거래" / "Transaction to replace";
    STATUS(1) = "상태: {0}" / "Status: {0}";
    CURRENT_FEE(2) = "현재 수수료 {0} · {1}" / "Current fee {0} · {1}";
    /// `{1}` ` (보내기 최대: …)` or empty.
    BUMP_AMOUNT(2) = "받는 금액 {0}{1} · 받는 주소:" / "Amount {0}{1} · Recipient:";
    BUMP_SEND_MAX_NOTE = "(보내기 최대: 수수료가 오른 만큼 받는 금액이 줄어듭니다)"
        / "(send max: the recipient gets less by the fee increase)";
    BUMP_HELP = "새 수수료는 이전 수수료 + 노드 최소 증분 이상이고 수수료율이 더 높아야 합니다. 받는 주소·금액은 그대로이고(보내기 최대 거래는 받는 금액이 줄어듭니다) 매번 새로 승인합니다."
        / "The new fee must be at least the old fee plus the node's minimum increment, at a higher fee rate. Recipient and amount stay the same (a send-max transaction's amount goes down), and every bump is approved anew.";

    /// The result screen.
    RESULT_BUMP = "수수료 올리기 결과" / "Fee bump result";
    RESULT_SEND = "보내기 결과" / "Send result";
    NO_RESULT = "표시할 결과가 없습니다." / "No result to show.";
    BACK_MAIN = "메인으로" / "Back to main";
    SIGNED_BANNER = "서명하고 저널에 기록했습니다. 아래 해시는 이 지갑이 계산한 값입니다."
        / "Signed and written to the journal. The hash below is the value this wallet computed.";
    FINISHED_SEE_ACTIVITY = "종결 (활동 참고)" / "Finished (see activity)";
    RESULT_STATUS(2) = "상태: {0} ({1})" / "Status: {0} ({1})";
    COPY_HASH = "해시 복사" / "Copy hash";
    NOT_SENT_KEPT = "전송하지 않았습니다. 입력은 보내기 화면에 남아 있으니 수수료를 바꿔 다시 검토하세요."
        / "Not sent. Your input is still on the send screen: change the fee and review again.";
    TO_SEND_SCREEN = "보내기 화면으로" / "Back to send";

    /// S12 receive.
    RECEIVE_TITLE(1) = "받기 — {0}" / "Receive — {0}";
    PREPARING_ADDRESS = "주소를 준비하는 중…" / "Preparing the address…";
    FIXED_ADDRESS(1) = "{0} · 고정 주소" / "{0} · fixed address";
    RECEIVE_INDEX(2) = "{0} · 받기 주소 {1}번" / "{0} · receive address #{1}";
    ADDRESS_FORMAT(1) = "주소 형식: {0}" / "Address format: {0}";
    NEW_ADDRESS = "새 주소" / "New address";

    /// S15 Bitcoin section.
    SETTINGS_CARD = "Bitcoin 사용과 네트워크" / "Bitcoin use and network";
    ENABLE = "Bitcoin 사용" / "Use Bitcoin";
    TESTNET4_RADIO = "testnet4 (테스트, 가치 없음)" / "testnet4 (test, no value)";
    ENABLE_HELP = "켤 때 고른 네트워크의 BIP84 주소를 찾습니다. 켠 뒤 네트워크를 바꾸면(진행 중 거래가 없을 때만) 주소 인덱스·UTXO 캐시·동결·보낸 주소 기록을 새로 시작하고 다시 찾습니다. 끄면 데이터는 남습니다."
        / "Turning it on searches the BIP84 addresses of the chosen network. Changing the network after that (only without a pending transaction) starts the address indexes, UTXO cache, freezes and sent-address record over and searches again. Turning it off keeps the data.";
    RPC_SET = "설정됨" / "set";
    RPC_NONE(1) = "없음 — {0}" / "none — {0}";
    RPC_LINE(2) = "Core RPC 주소 {0}: {1}" / "Core RPC address {0}: {1}";
    GO_NETWORK = "네트워크(RPC) 설정으로" / "Network (RPC) settings";
    INDEXER_CARD = "주소 조회 서버(인덱서)" / "Address lookup server (indexer)";
    INDEXER = "인덱서" / "Indexer";
    INDEXER_HELP = "Esplora: 무료·키 없음(기본 mempool.space). bb-rpc: Core URL의 bb_* (QuickNode BTC Blockbook 유료 애드온). bb-rest: Core URL의 /api/v2/ (알케미 UTXO API)."
        / "Esplora: free, no key (default mempool.space). bb-rpc: bb_* on the Core URL (QuickNode BTC Blockbook paid add-on). bb-rest: /api/v2/ on the Core URL (Alchemy UTXO API).";
    SAVE = "저장" / "Save";
    DEFAULT = "기본값으로" / "Default";
    TEST = "테스트" / "Test";
    ESPLORA_TEST_HELP = "`테스트`는 입력 칸의 값(비어 있으면 저장된 값)으로 GET /block-height/0을 한 번 보냅니다. 주소를 보내지 않으므로 잠긴 상태에서도 됩니다. `저장`은 테스트를 요구하지 않으며 쓰기 전에 연결 검사가 다시 확인합니다."
        / "`Test` sends one GET /block-height/0 with the value in the field (the saved value if empty). It sends no address, so it also works while locked. `Save` does not require a test; the connection check verifies again before use.";
}
