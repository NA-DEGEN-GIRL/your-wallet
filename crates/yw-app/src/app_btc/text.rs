//! Fixed texts of the Bitcoin controller (spec/08, spec/04 §2.6–§2.11, spec/14): gate and form
//! messages, confirmation overlays, record and activity statuses, receive notes and the W-ADDR-3
//! look-alike note. 2026-11-14 (Step 3): these were Korean `&str` constants and literals in
//! `app_btc.rs` before, with the same Korean bytes.

yw_core::texts! {
    /// The import screen note (spec/08 §1.2).
    BTC_IMPORT_NOTE = "Bitcoin은 네이티브 세그윗(bc1q…, BIP84) 계정 0을 먼저 찾습니다. 탭루트·호환 세그윗·레거시 주소는 Bitcoin 탭의 “계정 추가”로 더하세요."
        / "Bitcoin first looks for Native SegWit (bc1q…, BIP84) account 0. Add Taproot, Nested SegWit or Legacy addresses with “Add account” on the Bitcoin tab.";
    /// "주소 검색 미완료" (spec/08 §3.4).
    DISCOVERY_INCOMPLETE = "주소 검색 미완료" / "Address discovery not finished";
    /// The refresh's yes/no banner while the received history is off (spec/08 §4.7-2).
    PENDING_INCOMING = "미확정 입금 있음 (0 확인, 미검증 — 바뀌거나 취소될 수 있습니다). 금액과 txid는 '받은 내역도 보기'를 켜면 보입니다."
        / "Unconfirmed incoming funds (0 confirmations, unverified — they may change or be cancelled). Turn on 'Also show received' to see the amount and txid.";
    /// The same banner while the received history has not found everything yet.
    PENDING_INCOMING_UNREAD = "미확정 입금 있음 (0 확인, 미검증 — 바뀌거나 취소될 수 있습니다). 받은 내역에서 아직 다 찾지 못했습니다."
        / "Unconfirmed incoming funds (0 confirmations, unverified — they may change or be cancelled). The received history has not found all of them yet.";
    /// T-APPR-EXPIRED.
    APPROVAL_EXPIRED = "승인 시간이 지났습니다. 다시 검토하세요." / "The approval timed out. Review again.";
    /// `검토`'s progress line.
    BTC_PREPARING = "수수료를 계산하는 중…" / "Calculating the fee…";
    /// "(서버 기준)" suffix of confirmations (spec/08 §12.2-4).
    SERVER_BASED = "(서버 기준)" / "(server data)";
    /// The "블록 높이 기록 초기화" confirmation (spec/08 §2 step 2).
    RESET_TIP_TEXT = "이 지갑이 기록한 가장 높은 블록 높이를 지웁니다. 노드(RPC)가 전에 잘못된(너무 높은) 높이를 알려 줘 지금 연결 검사가 계속 실패하는 경우에만 하세요. 노드가 오래된 체인을 보여 주는 경우라면 초기화하지 말고 노드 설정을 확인하세요. 초기화할까요?"
        / "This clears the highest block height this wallet recorded. Do it only if the node (RPC) once reported a wrong (too high) height and the connection check now keeps failing. If the node shows an old chain, do not reset; check the node settings instead. Reset?";
    /// UTXO mark of a candidate Core's `gettxout` did not confirm.
    INDEXER_ONLY = "인덱서만 확인(노드 미확인)" / "Indexer only (not confirmed by the node)";
    /// Account switch / add refused while a BTC approval is open.
    ACCOUNT_SWITCH_BUSY = "Bitcoin 승인이 진행 중이라 계정을 바꾸거나 추가할 수 없습니다"
        / "A Bitcoin approval is in progress, so accounts cannot be switched or added";
    /// Address-mode switch refused while a BTC approval is open.
    ADDRESS_MODE_BUSY = "Bitcoin 승인이 진행 중이라 주소 방식을 바꿀 수 없습니다"
        / "A Bitcoin approval is in progress, so the address mode cannot be changed";
    /// The address-mode radio: fixed address (spec/08 §3.5).
    T_BTC_MODE_SINGLE = "고정 주소 하나만 사용 (UniSat·Xverse 방식)" / "One fixed address only (like UniSat and Xverse)";
    /// The address-mode radio: a new address each time.
    T_BTC_MODE_HD = "받을 때마다 새 주소 (HD, 프라이버시↑)" / "A new address for each receive (HD, more privacy)";
    /// One-line trade-off under the address-mode radios.
    T_BTC_MODE_HELP = "고정 주소는 받기·잔돈이 늘 같은 주소(…/0/0)라 관리와 소유 증명이 쉽지만, 누구나 그 주소의 잔액과 거래를 모두 볼 수 있습니다. 새 주소 방식은 프라이버시가 낫지만 주소가 계속 바뀝니다."
        / "With a fixed address, receives and change always use the same address (…/0/0): easy to manage and to prove ownership, but anyone can see all of its balance and transactions. New addresses give more privacy, but the address keeps changing.";
    /// The receive note of an HD account in fixed-address mode (spec/04 §2.8).
    T_BTC_FIXED_RECEIVE = "이 계정은 주소 하나만 씁니다. 같은 복구 단어를 Electrum/Sparrow/UniSat에 넣으면 같은 주소가 나옵니다."
        / "This account uses a single address. The same recovery words in Electrum/Sparrow/UniSat give the same address.";
    /// The key-source radio of `계정 추가`: the standard BTC path.
    T_BTC_SOURCE_STANDARD = "BTC 표준 경로 (권장, 기본값)" / "Standard BTC path (recommended, default)";
    /// The key-source radio of `계정 추가`: the key of an EVM account.
    T_BTC_SOURCE_EVM = "EVM 계정과 같은 키" / "Same key as an EVM account";
    /// Help under the standard key source.
    T_BTC_SOURCE_STANDARD_HELP = "m/{44·49·84·86}'/{코인}'/{계정}'/0/0 — 같은 복구 단어를 다른 Bitcoin 지갑에 넣어도 같은 주소가 나옵니다."
        / "m/{44·49·84·86}'/{coin}'/{account}'/0/0 — the same recovery words in another Bitcoin wallet give the same address.";
    /// The warning of an account on an EVM account's key (spec/08 §3.5).
    T_BTC_EVM_SHARED = "같은 키를 쓰면 EVM 주소와 BTC 주소의 공개키가 같아져, 누구나 두 주소가 같은 사람 것임을 알 수 있습니다. 다른 BTC 지갑(Electrum·Sparrow)에 복구 단어만 넣으면 이 주소가 보이지 않습니다(복구는 이 지갑이나 개인키 내보내기로)."
        / "With the same key, the EVM and BTC addresses share a public key, so anyone can tell that both belong to the same person. Other BTC wallets (Electrum, Sparrow) do not show this address from the recovery words alone (restore it with this wallet or a private key export).";
    /// Account delete refused while a BTC approval is open (spec/04 §2.18).
    REMOVE_BUSY_APPROVAL = "Bitcoin 승인이 진행 중이라 이 가져온 키를 지울 수 없습니다. 승인을 끝내거나 거절한 뒤 다시 하세요"
        / "A Bitcoin approval is in progress, so this imported key cannot be deleted. Finish or reject the approval, then try again";
    /// Account delete refused while the account has an in-flight transaction (spec/04 §2.18).
    REMOVE_BUSY_IN_FLIGHT = "이 가져온 키의 주소로 보낸 거래가 아직 확정될 수 있습니다(진행 중, 또는 포기·거절 뒤 30일 이내). 추적과 이중 지불 방지에 이 키가 필요하므로, 거래가 확정되거나 끝난 뒤(포기·거절한 거래는 30일 뒤)에 지울 수 있습니다"
        / "A transaction sent from this imported key's address may still confirm (in progress, or within 30 days after abandoning or rejection). The key is needed for tracking and double-payment protection, so it can be deleted once the transaction is confirmed or finished (30 days later for an abandoned or rejected one)";
    /// "보내지 않았습니다" of a send stopped by the chain check.
    NOT_SENT = "전송 직전 연결 검사에 실패해 보내지 않았습니다. [같은 바이트 다시 전송]으로 다시 시도하세요"
        / "Not sent: the connection check just before sending failed. Try again with [Resend the same bytes]";

    /// `BtcGate::text`.
    GATE_DISABLED = "Bitcoin이 꺼져 있습니다. 설정 → Bitcoin에서 켤 수 있습니다."
        / "Bitcoin is off. You can turn it on in Settings → Bitcoin.";
    GATE_LOCKED = "잠금을 해제하세요." / "Unlock the wallet.";
    GATE_NO_META = "Bitcoin 계정을 준비하는 중입니다…" / "Preparing the Bitcoin account…";
    GATE_NO_ACCOUNT = "이 네트워크에는 가져온 Bitcoin 개인키가 없습니다. 개인키를 가져오세요."
        / "There is no imported Bitcoin private key on this network. Import a private key.";
    GATE_LOADING = "불러오는 중…" / "Loading…";
    GATE_JOURNAL_CLOSED = "거래 저널을 열지 못해 Bitcoin 조회·보내기를 멈췄습니다. 맨 위 안내의 '선택 다시 보기'에서 고르세요."
        / "The transaction journal could not be opened, so Bitcoin lookups and sending are stopped. Choose in 'Show the choice again' in the notice at the top.";

    /// `BtcFeeChoice::label`.
    FEE_FAST = "빠름" / "Fast";
    FEE_NORMAL = "보통" / "Normal";
    FEE_SLOW = "느림" / "Slow";
    FEE_MANUAL = "직접 입력" / "Manual";
    /// Fee form errors.
    FEE_RATE_FORMAT = "수수료율 형식이 올바르지 않습니다(sat/vB)." / "The fee rate format is invalid (sat/vB).";
    FEE_SATS_FORMAT = "수수료(sats) 형식이 올바르지 않습니다." / "The fee (sats) format is invalid.";

    /// `BtcConfirm::texts` and `no_label`.
    CONFIRM_NETWORK_TITLE = "Bitcoin 네트워크 바꾸기" / "Switch the Bitcoin network";
    CONFIRM_NETWORK_TEXT(1) = "Bitcoin 네트워크를 {0}로 바꿉니다. 주소 인덱스·UTXO 캐시·동결·보낸 주소 기록을 새로 시작하고 주소를 다시 찾습니다. 다른 네트워크의 거래 기록은 보존합니다."
        / "This switches the Bitcoin network to {0}. Address indexes, the UTXO cache, freezes and the sent-address record start over and addresses are searched again. The transaction records of the other network are kept.";
    CONFIRM_NETWORK_YES = "바꾸기" / "Switch";
    CONFIRM_INDEXER_TITLE = "Blockbook 인덱서" / "Blockbook indexer";
    CONFIRM_INDEXER_TEXT = "Blockbook 인덱서는 Bitcoin RPC 엔드포인트에 인덱서 기능이 켜져 있어야 합니다(QuickNode: 유료 BTC Blockbook 애드온, 알케미: UTXO API). 켜져 있지 않으면 Bitcoin 조회가 실패합니다(E-BTC-007). 계속할까요?"
        / "The Blockbook indexer needs the indexer feature enabled on the Bitcoin RPC endpoint (QuickNode: paid BTC Blockbook add-on, Alchemy: UTXO API). Without it, Bitcoin lookups fail (E-BTC-007). Continue?";
    CONFIRM_CONTINUE = "계속" / "Continue";
    CONFIRM_GAP_TITLE = "새 주소" / "New address";
    CONFIRM_GAP_YES = "그래도 발급" / "Issue anyway";
    CONFIRM_ABANDON_TITLE = "거래 포기" / "Abandon transaction";
    CONFIRM_ABANDON_YES = "포기" / "Abandon";
    CONFIRM_CANCEL_TITLE = "서명한 거래 취소" / "Cancel signed transaction";
    CONFIRM_CANCEL_TEXT = "서명했지만 보내지 않은 거래를 취소합니다. 이 거래는 전송하지 않습니다."
        / "This cancels a transaction that was signed but not sent. It will not be sent.";
    CONFIRM_CANCEL_YES = "취소하기" / "Cancel it";
    CONFIRM_ESPLORA_TITLE = "Esplora로 전송" / "Send via Esplora";
    CONFIRM_ESPLORA_TEXT = "Bitcoin 노드(RPC)로 보낸 결과를 확인하지 못했습니다. 같은 서명 거래를 설정한 Esplora 서버로 보냅니다. 거래 내용은 어차피 네트워크에 공개되지만, 그 서버는 이 PC의 IP가 이 거래를 보냈다는 것을 알 수 있습니다. 보낼까요?"
        / "The result of sending through the Bitcoin node (RPC) could not be confirmed. The same signed transaction is sent to the configured Esplora server. The transaction becomes public on the network anyway, but that server can learn that this PC's IP sent it. Send?";
    CONFIRM_SEND_YES = "보내기" / "Send";
    CONFIRM_RESET_TIP_TITLE = "블록 높이 기록 초기화" / "Reset the block height record";
    CONFIRM_RESET_YES = "초기화" / "Reset";
    CONFIRM_EVM_SHARED_TITLE = "EVM 계정과 같은 키로 Bitcoin 계정 만들기"
        / "Create a Bitcoin account with an EVM account's key";
    /// `{0}` EVM account index, `{1}` its path, `{2}` address type, `{3}` [`T_BTC_EVM_SHARED`].
    CONFIRM_EVM_SHARED_TEXT(4) = "EVM 계정 {0}의 키({1})로 {2} 주소 하나를 만듭니다. 받기와 잔돈은 늘 이 주소입니다. {3} 그래도 만들까요?"
        / "This creates one {2} address with the key of EVM account {0} ({1}). Receives and change always use this address. {3} Create it anyway?";
    CONFIRM_EVM_SHARED_YES = "같은 키로 만들기" / "Create with the same key";
    CONFIRM_NO_GAP = "이전 주소 사용" / "Use the previous address";
    CONFIRM_NO = "취소" / "Cancel";

    /// `record_status`, `confirmations_text`, `activity_status` (spec/08 §12.1–§12.2-4).
    STATUS_SIGNED = "서명됨(전송 전)" / "Signed (not sent)";
    STATUS_BROADCASTING = "전송 중" / "Sending";
    /// `{0}` [`SERVER_BASED`].
    STATUS_WAITING(1) = "확인 대기 {0}" / "Awaiting confirmation {0}";
    STATUS_UNKNOWN = "전송 결과 확인 필요" / "Send result needs checking";
    STATUS_REJECTED = "거부됨" / "Rejected";
    STATUS_REPLACED = "교체됨" / "Replaced";
    STATUS_CONFLICTED = "충돌(다른 거래가 확정됨)" / "Conflicted (another transaction confirmed)";
    STATUS_ABANDONED = "포기함" / "Abandoned";
    /// `{0}` [`SERVER_BASED`].
    STATUS_CONFIRMED(1) = "확정 {0}" / "Confirmed {0}";
    STATUS_FINISHED = "종결" / "Finished";

    /// `known_addresses_on` names (`{0}` a book label or account name, `{1}` index).
    KNOWN_BOOK(1) = "주소록: {0}" / "Address book: {0}";
    KNOWN_OWN_RECEIVE(2) = "내 계정 '{0}'의 받기 주소 #{1}" / "Receive address #{1} of my account '{0}'";
    KNOWN_OWN_CHANGE(2) = "내 계정 '{0}'의 잔돈 주소 #{1}" / "Change address #{1} of my account '{0}'";
    KNOWN_SENT = "이전에 보낸 주소" / "An address you sent to before";
    /// `ends_text`.
    ENDS_SUFFIX(1) = "끝 {0}자" / "last {0} characters";
    ENDS_PREFIX(1) = "앞 {0}자" / "first {0} characters";
    ENDS_BOTH(2) = "앞 {0}자·끝 {1}자" / "first {0} and last {1} characters";
    /// The W-ADDR-3 note (`{0}` the known name, `{1}` the equal ends).
    LOOK_ALIKE(2) = "'{0}'과 {1}가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다."
        / "Same {1} as '{0}', but a different address. This may be an address-poisoning attack.";

    /// Settings messages.
    DISABLE_IN_FLIGHT = "진행 중인 Bitcoin 거래가 있어 끌 수 없습니다"
        / "Bitcoin cannot be turned off while a Bitcoin transaction is in progress";
    TESTING = "테스트 중…" / "Testing…";

    /// `receive_view` notes.
    RECEIVE_NOTE_IMPORTED = "가져온 키 계정은 주소가 하나입니다. 주소를 복사한 뒤 붙여넣은 곳에서 주소 전체를 확인하세요."
        / "An imported key account has one address. After copying it, check the whole address where you paste it.";
    RECEIVE_NOTE_YUBIKEY = "YubiKey 계정은 주소가 하나입니다. 주소를 복사한 뒤 붙여넣은 곳에서 주소 전체를 확인하세요."
        / "A YubiKey account has one address. After copying it, check the whole address where you paste it.";
    /// `{0}` EVM account index, `{1}` path, `{2}` [`T_BTC_EVM_SHARED`].
    RECEIVE_NOTE_EVM(3) = "이 계정은 주소 하나만 씁니다. EVM 계정 {0}과 같은 키({1})입니다. {2}"
        / "This account uses a single address, with the same key as EVM account {0} ({1}). {2}";
    RECEIVE_NOTE_FIXED = "받은 돈과 보내고 남은 잔돈이 모두 이 주소로 옵니다(새 주소 없음). 받을 때마다 새 주소를 쓰려면 Bitcoin 탭의 계정 목록 아래 '주소 방식'에서 바꾸세요. 주소를 복사한 뒤 붙여넣은 곳에서 주소 전체를 확인하세요."
        / "Received funds and the change of your sends all come to this address (no new addresses). To use a new address for each receive, change 'Address mode' under the account list on the Bitcoin tab. After copying the address, check the whole address where you paste it.";
    RECEIVE_NOTE_HD = "주소를 복사한 뒤 붙여넣은 곳에서 주소 전체를 확인하세요. 새 주소는 아직 쓰지 않은 주소가 20개 이상이면 경고하고 100개면 발급하지 않습니다."
        / "After copying the address, check the whole address where you paste it. A new address is warned about at 20 or more unused addresses and not issued at 100.";

    /// Send form and flow messages.
    JOURNAL_DAMAGED = "거래 저널이 손상되어 보내기를 멈췄습니다. (E-VLT-006)"
        / "The transaction journal is damaged, so sending is stopped. (E-VLT-006)";
    OTHER_APPROVAL = "다른 Bitcoin 승인이 진행 중입니다" / "Another Bitcoin approval is in progress";
    PICK_EVM = "EVM 계정을 고르세요" / "Choose an EVM account";
    SENT = "전송했습니다" / "Sent";
    SENT_ESPLORA = "Esplora로 전송했습니다" / "Sent via Esplora";
}
