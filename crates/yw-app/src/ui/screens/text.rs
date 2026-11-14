//! Fixed texts of the core screens S01–S15 and the main-window shell (spec/04 §2, spec/14).

yw_core::texts! {
    // ----- shared helpers (used by the chain screens too) -----
    /// Create/import flow step.
    STEP_PASSWORD = "비밀번호 정하기" / "Set a password";
    /// Create flow step.
    STEP_WRITE_WORDS = "복구 단어 적기" / "Write down the recovery words";
    /// Create flow step.
    STEP_BACKUP_CHECK = "백업 확인" / "Check the backup";
    /// Import flow step.
    STEP_ENTER_WORDS = "복구 단어 입력" / "Enter the recovery words";
    /// Import flow step.
    STEP_FIRST_ADDRESS = "첫 주소 확인" / "Check the first address";
    /// The `← 메인으로` link.
    BACK_MAIN = "← 메인으로" / "← Back to main";
    /// Its tooltip.
    BACK_MAIN_TIP = "메인으로 (Esc)" / "Back to main (Esc)";
    /// The tooltip of a main card's `새로고침` (F5 presses the visible one).
    T_REFRESH_TIP = "새로고침 (F5)" / "Refresh (F5)";
    /// The language card's help line (spec/04 §2.11).
    LANGUAGE_HELP = "앱 화면과 승인 창의 언어입니다. 바꾸면 바로 적용되고, 이미 열린 승인 창은 처음 언어로 남습니다."
        / "The language of the app screens and approval windows. A change applies at once; an approval window that is already open keeps its language.";
    /// S08 `QuickNode 주소`'s help (2026-11-10).
    T_DONE_QUICKNODE = "QuickNode 대시보드의 엔드포인트 주소(https://….quiknode.pro/…/)를 통째로 붙여넣으세요. 쓸 체인(Ethereum·Arbitrum·Base·Solana·Bitcoin 등)은 대시보드에서 그 엔드포인트에 켜 두어야 합니다. 입력은 가려지고, 이 Windows 사용자만 풀 수 있게 암호화해 저장합니다."
        / "Paste the whole endpoint address from the QuickNode dashboard (https://….quiknode.pro/…/). The chains you use (Ethereum, Arbitrum, Base, Solana, Bitcoin …) must be enabled for that endpoint in the dashboard. The input is hidden and stored encrypted so that only this Windows user can decrypt it.";
    /// The `RPC 공급자` card's `QuickNode` note (2026-11-10).
    T_QUICKNODE_CHAINS = "QuickNode는 대시보드에서 쓸 체인(Ethereum·Arbitrum·Base·Solana·Bitcoin 등)을 엔드포인트에 하나씩 켜야 그 네트워크가 작동합니다."
        / "With QuickNode, a network works only after its chain (Ethereum, Arbitrum, Base, Solana, Bitcoin …) is enabled for the endpoint in the dashboard.";
    /// T-FIRST-1, sentence 1.
    T_FIRST_1 = "Your Wallet은 이 PC에서만 쓰는 개인용 암호화폐 지갑입니다."
        / "Your Wallet is a personal crypto wallet used only on this PC.";
    /// T-FIRST-1, sentence 2.
    T_FIRST_2 = "돈을 보내거나 사이트에 서명할 때는 언제나 이 앱의 확인 창에서 내용을 보고 직접 승인합니다."
        / "Whenever you send money or sign for a site, you check the details in this app's approval window and approve them yourself.";
    /// T-FIRST-1, sentence 3.
    T_FIRST_3 = "지갑을 만들 때 받는 복구 단어 24개가 유일한 백업입니다. 종이에 적어 안전한 곳에 보관하세요."
        / "The 24 recovery words you get when creating the wallet are its only backup. Write them on paper and keep it in a safe place.";
    /// T-BACKUP-FAIL: {0}–{3} the positions, {4} the next step.
    BACKUP_RETRY(5) = "입력한 단어 중 종이와 다른 것이 있습니다. 같은 위치({0}·{1}·{2}·{3}번째)를 다시 묻습니다. {4}"
        / "Some of the words you entered differ from your paper. The same positions (words {0}, {1}, {2} and {3}) are asked again. {4}";
    /// T-BACKUP-FAIL next step when the words can be shown again.
    BACKUP_RETRY_WORDS_AGAIN = "종이에 잘못 적었을 수 있으니, 이 창을 닫고 복구 단어를 다시 보면서 이 네 단어를 종이와 대조해 고치세요."
        / "You may have written them down wrong: close this window, view the recovery words again and correct these four words on your paper.";
    /// T-BACKUP-FAIL next step when the words cannot be shown again.
    BACKUP_RETRY_NO_WORDS = "종이의 이 네 단어를 다시 확인하세요. 종이가 틀렸는지 알 수 없다면 이 창을 닫아 만들기를 취소하고(단어는 지워집니다) 처음부터 다시 만드세요."
        / "Check these four words on your paper again. If you cannot tell whether the paper is wrong, close this window to cancel the creation (the words are erased) and start over.";
    /// The selected-account card of a network without an RPC address: {0} the network.
    NO_ENDPOINT(1) = "이 네트워크({0})의 RPC 주소가 아직 없어 잔액을 읽을 수 없습니다."
        / "This network ({0}) has no RPC address yet, so the balance cannot be read.";
    /// The selected-account card while its balance read failed and there is no earlier value.
    T_BALANCE_FAILED = "잔액을 읽지 못했습니다." / "The balance could not be read.";
    /// Under the big balance while the first read of the network is on its way.
    T_BALANCE_LOADING = "잔액을 불러오는 중…" / "Loading the balance…";
    /// `HH:MM 갱신`.
    UPDATED_AT(1) = "{0} 갱신" / "updated {0}";
    /// `블록 N 기준 · …`.
    AT_BLOCK_WHEN(2) = "블록 {0} 기준 · {1}" / "at block {0} · {1}";
    /// `블록 N 기준`.
    AT_BLOCK(1) = "블록 {0} 기준" / "at block {0}";
    /// A balance kept from before a failed read, without a time.
    UPDATE_FAILED = "갱신 실패" / "update failed";
    /// A balance kept from before a failed read: {0} `HH:MM`.
    UPDATE_FAILED_SINCE(1) = "{0} 이후 갱신 실패" / "update failed since {0}";
    /// The network card's band of a failed balance read: {0} short name, {1} code.
    BALANCE_FAILURE(2) = "RPC {0} ({1}) — 잔액을 갱신하지 못했습니다. 'RPC 테스트'로 원인을 확인하세요."
        / "RPC {0} ({1}) — the balance could not be updated. Use 'Test RPC' to find the cause.";
    /// The empty Zcash activity card: received deposits are not in the sent list.
    T_ACTIVITY_RECEIVED = "받은 입금은 이 목록(보낸 거래)에 나오지 않습니다. 아래 '받은 내역도 보기'를 켜면 최근 받은 내역을 따로 보여 줍니다(기본 꺼짐)."
        / "Received deposits do not appear in this list (sent transactions). Turn on 'Also show received' below to see recent deposits separately (off by default).";
    /// T-ALT-PASS (every screen while `App::passphrase_unverified`, spec/04 §2.1).
    T_ALT_PASS = "passphrase 확인값과 맞지 않는 passphrase로 연 지갑입니다. 오타라면 이 지갑은 원래 지갑이 아닌 다른(빈) 지갑이고, 여기로 받은 자산은 지금 입력한 passphrase와 대소문자·공백까지 정확히 같은 값을 다시 넣어야만 꺼낼 수 있습니다. 그래서 받기와 사이트 연결·서명을 막았습니다. 추가한 계정·계정 이름·주소록·연결 기록도 저장되지 않습니다. 잘못 입력했다면 잠그고 다시 여세요."
        / "This wallet was opened with a passphrase that does not match the passphrase check. If it was a typo, this is a different (empty) wallet, not your original one, and assets received here can only be taken out by entering exactly this passphrase again, including case and spaces. So receiving, site connections and signing are blocked. Added accounts, account names, address book entries and connection records are not saved either. If you mistyped, lock and open the wallet again.";
    /// Shown when `받기` is pressed in that mode.
    T_ALT_PASS_RECEIVE = "확인되지 않은 passphrase로 연 지갑에서는 받기를 쓸 수 없습니다. 잠그고 passphrase를 다시 입력하세요."
        / "Receiving is not available in a wallet opened with an unverified passphrase. Lock and enter the passphrase again.";
    /// T-MAINNET: the main-screen badge of a network with real assets.
    T_MAINNET = "메인넷 — 실제 자산" / "Mainnet — real assets";
    /// The `내 계정` help of a wallet with recovery words that has an imported key.
    T_ACCOUNTS_BACKUP = "'가져온 개인키' 계정은 복구 단어로 복구되지 않습니다 — 그 개인키를 따로 백업하세요."
        / "'Imported private key' accounts are not restored from the recovery words — back up those private keys separately.";
    /// That help of a key-only wallet (no recovery words).
    T_ACCOUNTS_KEY_ONLY = "이 지갑은 개인키로 시작해 복구 단어가 없습니다. 모든 계정은 '가져온 키'이며 각각의 원래 개인키가 유일한 백업입니다."
        / "This wallet started from a private key and has no recovery words. Every account is an 'imported key', and each original private key is its only backup.";
    /// The `내 계정` help of a wallet without recovery words that has `YubiKey` cards.
    T_ACCOUNTS_YUBIKEY = "이 지갑은 복구 단어를 저장하지 않습니다. [YubiKey] 계정의 키는 카드 안에만 있고, 백업은 등록할 때 적은 복구 단어입니다(복구 단어 없이 연결한 키는 그 카드와 같은 키를 가진 백업 카드)."
        / "This wallet stores no recovery words. The keys of [YubiKey] accounts exist only on the card, and their backup is the recovery words written down at enrolment (for a key connected without recovery words, a backup card holding the same key).";
    /// Its last sentence when the wallet also has imported keys.
    T_ACCOUNTS_IMPORTED = "[가져온 키]는 원래 개인키가 백업입니다."
        / "For [imported key] accounts, the original private key is the backup.";
    /// Added to T-ACCOUNTS-BACKUP when a wallet with recovery words has `YubiKey` accounts.
    T_ACCOUNTS_YUBIKEY_WORDS = "[YubiKey] 계정은 YubiKey를 등록할 때 쓴 복구 단어로 복구됩니다(이 지갑의 복구 단어와 다를 수 있음)."
        / "[YubiKey] accounts are restored from the recovery words used when the YubiKey was enrolled (they may differ from this wallet's recovery words).";
    /// The imported-key removal confirmation.
    T_REMOVE_KEY = "선택한 가져온 개인키 계정을 이 지갑에서 지웁니다. 가져온 개인키는 복구 단어로 복구되지 않으므로, 지우고 나면 원래 개인키 없이는 이 계정의 자산에 다시 접근할 수 없습니다. 지우기 전에 설정 → 보안 → '개인키 보기'로 개인키를 내보내 안전하게 보관했는지 확인하세요. 계속하려면 비밀번호를 입력하세요."
        / "Removes the selected imported private-key account from this wallet. Imported private keys are not restored from the recovery words, so once removed, the assets of this account cannot be reached again without the original private key. Before removing, make sure you exported the private key with Settings → Security → 'Show private key' and stored it safely. Enter your password to continue.";
    /// The EVM `폐기` confirmation.
    T_DISCARD = "폐기는 이 앱에서 추적만 멈추고 '폐기됨'으로 표시합니다. 네트워크에서 거래를 취소하지는 않습니다. 이미 전파된 거래라면 나중에 처리될 수 있고, 그 사이 같은 송금을 다시 보내면 두 거래가 모두 처리되어 두 번 지불될 수 있습니다. 확실히 막으려면 폐기 대신 '취소'(같은 nonce의 취소 거래)를 쓰고, 다시 보내기 전에 탐색기에서 이 거래가 사라졌는지 확인하세요."
        / "Discarding only stops tracking in this app and marks the transaction 'discarded'. It does not cancel the transaction on the network. A transaction already broadcast may still be processed later, and if you send the same transfer again in the meantime, both may be processed and you pay twice. To be sure, use 'Cancel' (a cancel transaction with the same nonce) instead of discarding, and check in the explorer that this transaction is gone before sending again.";
    /// T-TOKEN-DELETE: `삭제` of a user-added EVM token.
    T_TOKEN_DELETE = "이 토큰을 이 네트워크의 토큰 목록에서 지웁니다. 토큰이나 잔액은 그대로이며 블록체인에는 아무것도 보내지 않습니다. 같은 컨트랙트 주소로 언제든 다시 추가할 수 있습니다. 지운 뒤 이 토큰의 활동 기록은 원시 단위로 보입니다."
        / "Removes this token from this network's token list. The token and its balance stay as they are, and nothing is sent to the blockchain. You can add it again at any time with the same contract address. After removal, this token's activity is shown in raw units.";
    /// The `vault.ywv` facts line: {0} generation, {1} last write time.
    VAULT_FILE(2) = "지갑 파일(vault.ywv): 저장 횟수(세대) {0} · 마지막 저장 {1}. 기억하는 것보다 작거나 이전 시각이면 파일이 예전 사본으로 바뀌었을 수 있습니다."
        / "Wallet file (vault.ywv): save count (generation) {0} · last saved {1}. If it is lower or earlier than you remember, the file may have been replaced by an older copy.";
    /// The banner when the meta remembers a newer `vault.ywv` generation: {0} seen, {1} found.
    ROLLBACK(2) = "지갑 파일(vault.ywv)이 예전 사본으로 바뀌었을 수 있습니다: 이 지갑은 세대 {0}까지 저장했는데 지금 파일은 세대 {1}입니다. 직접 백업에서 되돌린 것이 아니라면 지운 계정·키가 다시 나타나거나 최근 변경이 사라졌을 수 있으니 확인하세요."
        / "The wallet file (vault.ywv) may have been replaced by an older copy: this wallet saved up to generation {0}, but the file is now generation {1}. Unless you restored it from a backup yourself, removed accounts or keys may have come back or recent changes may be lost, so check.";
    /// The banner when the crash-report exclusion failed at startup (review L9).
    T_WER_UNPROTECTED = "Windows 오류 보고(WER) 제외 등록에 실패했습니다. 이 앱이 비정상 종료되면 메모리 덤프가 남을 수 있고, 덤프에는 잠금 해제 중인 지갑 키가 들어 있을 수 있습니다."
        / "Excluding this app from Windows Error Reporting (WER) failed. If the app crashes, a memory dump may be left, and the dump may contain wallet keys of the unlocked session.";
    // ----- header, settings-file banner -----
    /// The settings-file banner: {0} the tamper text.
    SETTINGS_TAMPERED_BANNER(1) = "{0}. 지금은 앱에 저장된 값을 씁니다. 직접 바꾼 것이 아니라면 '앱에 저장된 값으로 되돌리기'를 누르세요."
        / "{0}. The values saved in the app are used for now. If you did not change it yourself, press 'Restore the app's saved values'.";
    /// Settings-file banner primary button.
    SETTINGS_RESTORE = "앱에 저장된 값으로 되돌리기" / "Restore the app's saved values";
    /// Settings-file banner second button.
    SETTINGS_ACCEPT_FILE = "파일 값 사용…" / "Use the file's values…";
    /// Closes the banners.
    DISMISS_BANNERS = "알림 닫기" / "Dismiss notices";
    /// An empty cap value.
    DEFAULT_VALUE = "기본값" / "default";
    /// Settings-file difference: {0} now, {1} file.
    DIFF_AUTO_LOCK(2) = "자동 잠금: 지금 {0}분 → 파일 {1}분 (autoLockMinutes)"
        / "Auto-lock: now {0} min → file {1} min (autoLockMinutes)";
    /// Settings-file difference of the fee caps: {0} network, then now/file pairs.
    DIFF_FEE_CAPS(7) = "EVM 수수료 상한 — {0}: maxFee {1} → {2} gwei · 우선 수수료 {3} → {4} gwei · 총 {5} → {6} (feeCaps)"
        / "EVM fee caps — {0}: maxFee {1} → {2} gwei · priority fee {3} → {4} gwei · total {5} → {6} (feeCaps)";
    /// Settings-file difference of the Bitcoin indexer: {0} now, {1} file.
    DIFF_INDEXER(2) = "Bitcoin 주소 조회 서버: 지금 {0} → 파일 {1} (bitcoin.indexer/esploraBaseUrl) — 파일 값을 쓰면 주소 조회가 그 서버로 갑니다"
        / "Bitcoin address lookup server: now {0} → file {1} (bitcoin.indexer/esploraBaseUrl) — with the file's value, address lookups go to that server";
    /// Settings-file difference: a new user chain, {0} name, {1} chain id.
    DIFF_NEW_CHAIN(2) = "새 사용자 체인: {0} (chainId {1}) — 앱이 제네시스를 고정한 적 없음 (evmChains)"
        / "New user chain: {0} (chainId {1}) — the app never pinned its genesis (evmChains)";
    // ----- backup card (settings → security) -----
    /// The recovery card of a wallet with one phrase.
    BACKUP_CARD_HELP = "복구 단어(니모닉)는 지갑 전체의 백업입니다. 보기 전에 비밀번호를 다시 묻고, 화면 캡처에서 제외된 창에 보여줍니다."
        / "The recovery words (mnemonic) are the backup of the whole wallet. Your password is asked again before they are shown, in a window excluded from screen capture.";
    /// The backup status subtitle.
    BACKUP_STATUS_TITLE = "백업 현황 — 이 지갑을 다시 열려면" / "Backup status — to open this wallet again";
    /// Under the backup status.
    BACKUP_STATUS_HELP = "이 PC의 비밀번호는 백업이 아닙니다. 보기 전에 비밀번호를 다시 묻고, 화면 캡처에서 제외된 창에 보여줍니다."
        / "The password on this PC is not a backup. Your password is asked again before anything is shown, in a window excluded from screen capture.";
    /// Reveal button with several phrases.
    REVEAL_FIRST_MNEMONIC = "첫 복구 단어 보기" / "Show first recovery words";
    /// Reveal button.
    REVEAL_MNEMONIC = "복구 단어 보기" / "Show recovery words";
    /// Reveal key button.
    REVEAL_KEY = "개인키 보기" / "Show private key";
    /// Link to the recovery-phrase tab.
    MANAGE_MNEMONICS = "복구 단어 관리 ▸" / "Manage recovery words ▸";
    /// Backup status line of a phrase: {0} label, {1} word count, {2} passphrase note, {3} first note, {4} quiz state.
    BACKUP_STATUS_PHRASE(5) = "· {0} · {1}단어{2}{3} · {4}" / "· {0} · {1} words{2}{3} · {4}";
    /// The first phrase's note.
    BACKUP_STATUS_FIRST = " (첫 복구 단어)" / " (first recovery words)";
    /// Quiz passed.
    BACKUP_CONFIRMED = "백업 확인됨 ✓" / "backup checked ✓";
    /// Quiz not passed.
    BACKUP_NOT_CONFIRMED = "백업 확인 전 ⚠ — 설정 → 복구 단어에서 '백업 확인'"
        / "backup not checked ⚠ — Settings → Recovery words → 'Check backup'";
    /// Imported keys line: {0} count.
    BACKUP_STATUS_IMPORTED(1) = "· 가져온 개인키 {0}개 — 복구 단어로 되찾을 수 없고, 각각 원래 개인키가 백업입니다"
        / "· {0} imported private keys — not recoverable from recovery words; each original private key is its backup";
    /// Card key without words on several cards: {0} key title, {1} cards.
    BACKUP_STATUS_CARD_ON(2) = "· {0} — 복구 단어 없음, {1}에 있음" / "· {0} — no recovery words, on {1}";
    /// Card key without words on one card: {0} key title, {1} card.
    BACKUP_STATUS_CARD_ONLY(2) = "· {0} — 복구 단어 없음, {1}에만 있음 ⚠" / "· {0} — no recovery words, only on {1} ⚠";
    /// Card key from words: {0} key title, {1} cards.
    BACKUP_STATUS_CARD_WORDS(2) = "· {0} — YubiKey {1} · 복구 단어로 다시 만들 수 있음"
        / "· {0} — YubiKey {1} · can be recreated from recovery words";
    // ----- settings tabs: where else -----
    /// Security tab.
    ELSEWHERE_SECURITY = "복구 단어별 보기·백업 확인은 '복구 단어' 탭에 있습니다."
        / "Viewing each set of recovery words and checking backups is on the 'Recovery words' tab.";
    /// Chains tab.
    ELSEWHERE_CHAINS = "토큰 추가는 메인 화면의 '토큰' 카드에 있습니다." / "Adding tokens is on the main screen's 'Tokens' card.";
    /// Bitcoin tab.
    ELSEWHERE_BITCOIN = "Bitcoin 계정과 주소 방식은 메인 화면의 Bitcoin 탭에 있습니다."
        / "Bitcoin accounts and address types are on the main screen's Bitcoin tab.";
    /// YubiKey tab.
    ELSEWHERE_YUBIKEY = "서명할 때는 승인 뒤 PIN 창이 저절로 열립니다." / "When signing, the PIN window opens by itself after approval.";
    /// Other tab.
    ELSEWHERE_OTHER = "Zcash는 메인 화면의 Zcash 탭에서 켭니다." / "Zcash is turned on in the main screen's Zcash tab.";
    // ----- main toolbar -----
    /// Toolbar.
    ADDRESS_BOOK = "주소록" / "Address book";
    /// Toolbar.
    SITES_WC = "사이트·WalletConnect" / "Sites · WalletConnect";
    /// Toolbar.
    SETTINGS = "설정" / "Settings";
    /// Toolbar tooltip.
    SETTINGS_TIP = "설정 (Ctrl+,)" / "Settings (Ctrl+,)";
    /// Toolbar.
    LOCK = "잠금" / "Lock";
    /// Toolbar tooltip.
    LOCK_TIP = "잠금 (Ctrl+L)" / "Lock (Ctrl+L)";
    /// Before the wallet loaded.
    STARTING = "지갑을 불러오는 중…" / "Loading the wallet…";
    /// The processing card.
    PLEASE_WAIT = "잠시만 기다려 주세요" / "Please wait";
    // ----- S01 first run -----
    /// Leftover files of an earlier wallet.
    LEFTOVER = "이전 지갑의 파일이 데이터 폴더에 남아 있습니다. 앱을 종료하고 파일을 다른 곳으로 옮긴 뒤 다시 실행하세요."
        / "Files of an earlier wallet are left in the data folder. Quit the app, move the files elsewhere and start it again.";
    /// Opens the data folder.
    OPEN_FOLDER = "폴더 열기" / "Open folder";
    /// Moves the leftover files.
    LEFTOVER_MOVE = "남은 파일을 reset- 폴더로 옮기기…" / "Move the leftover files to a reset- folder…";
    /// S01 new-wallet card.
    FIRST_NEW_TITLE = "새로 시작합니다" / "Start fresh";
    /// S01 new-wallet card text.
    FIRST_NEW_TEXT = "새 지갑을 만들고 복구 단어 24개를 종이에 적습니다. 5분쯤 걸립니다."
        / "Create a new wallet and write its 24 recovery words on paper. It takes about 5 minutes.";
    /// S01/S02 create.
    CREATE_WALLET = "새 지갑 만들기" / "Create a new wallet";
    /// S01 `YubiKey` wallet.
    FIRST_YK_WALLET = "YubiKey에 보관하는 새 지갑" / "New wallet kept on a YubiKey";
    /// S01 `YubiKey` wallet help: {0} the wallet description.
    FIRST_YK_WALLET_HELP(1) = "YubiKey에 보관하는 새 지갑: {0} YubiKey 5(펌웨어 5.2.3 이상, Solana 계정은 5.7.4 이상)가 필요합니다."
        / "New wallet kept on a YubiKey: {0} Requires a YubiKey 5 (firmware 5.2.3 or later; 5.7.4 or later for Solana accounts).";
    /// S01 existing-wallet card.
    FIRST_EXISTING_TITLE = "이미 쓰던 지갑이 있습니다" / "I already have a wallet";
    /// S01 import.
    FIRST_IMPORT = "복구 단어로 가져오기" / "Import with recovery words";
    /// S01 key start.
    FIRST_KEY = "개인키로 시작하기" / "Start with a private key";
    /// S01 `YubiKey` connect.
    FIRST_YK_CONNECT = "YubiKey 연결하기 (복구 단어 없이)" / "Connect a YubiKey (no recovery words)";
    /// S01 import help.
    FIRST_IMPORT_HELP = "· 복구 단어로 가져오기: 다른 지갑에서 쓰던 영어 복구 단어(니모닉) 12·15·18·21·24개로 그 지갑을 그대로 가져옵니다."
        / "· Import with recovery words: brings in a wallet you used elsewhere, as it is, from its 12, 15, 18, 21 or 24 English recovery words (mnemonic).";
    /// S01 key help: {0} the key-start description.
    FIRST_KEY_HELP(1) = "· 개인키로 시작하기: {0}" / "· Start with a private key: {0}";
    /// S01 `YubiKey` connect help.
    FIRST_YK_CONNECT_HELP = "· YubiKey 연결하기: 이미 키가 들어 있는 YubiKey(새 PC, 다시 설치)를 복구 단어 없이 연결합니다. 카드의 공개키만 읽고 아무것도 쓰지 않습니다."
        / "· Connect a YubiKey: connects a YubiKey that already holds keys (new PC, reinstall) without recovery words. Only the card's public keys are read; nothing is written.";
    // ----- S02 create intro -----
    /// S02 card.
    BEFORE_START = "시작하기 전에" / "Before you start";
    /// S02 line.
    CREATE_INTRO_1 = "· 종이와 펜을 준비하세요. 다음 화면들에서 복구 단어 24개와 첫 주소를 적습니다."
        / "· Have paper and a pen ready. On the next screens you write down 24 recovery words and the first address.";
    /// S02 line.
    CREATE_INTRO_2 = "· 복구 단어는 종이(또는 금속)에만 적고 사진·클라우드·메신저에 남기지 마세요."
        / "· Write the recovery words only on paper (or metal); never keep them in photos, the cloud or messengers.";
    /// S02 line.
    CREATE_INTRO_3 = "· 화면 공유·녹화를 끄고 주변에 사람이나 카메라가 없는지 확인하세요."
        / "· Turn off screen sharing and recording, and make sure no people or cameras are around.";
    /// S02 help.
    CREATE_INTRO_HELP = "복구 단어를 아는 사람은 누구든 지갑의 자산을 옮길 수 있습니다. 이 앱도 복구 단어를 대신 보관하거나 되찾아 주지 못합니다."
        / "Anyone who knows the recovery words can move the wallet's assets. This app cannot keep the recovery words for you or recover them.";
    /// Start button.
    START = "시작하기" / "Start";
    /// Cancel button.
    CANCEL = "취소" / "Cancel";
    // ----- backup pending -----
    /// Title.
    BACKUP_PENDING_TITLE = "백업 확인이 필요합니다" / "Backup check needed";
    /// Banner.
    BACKUP_PENDING_BANNER = "백업 확인이 끝나지 않았습니다. 확인 전에는 보내기·서명·dApp 승인을 쓸 수 없습니다."
        / "The backup check is not finished. Until it is, sending, signing and dApp approvals are not available.";
    /// Text.
    BACKUP_PENDING_TEXT = "복구 단어를 다시 보고, 그중 단어 4개를 입력해 종이에 바르게 적었는지 확인합니다."
        / "View the recovery words again and enter 4 of them to check that they are written correctly on paper.";
    /// S04 button.
    BACKUP_CHECK = "복구 단어 보고 백업 확인" / "View recovery words and check backup";
    /// Receive button.
    RECEIVE = "받기" / "Receive";
    /// Reset help.
    BACKUP_PENDING_RESET = "복구 단어를 적지 못했거나 잃어버렸다면, 이 지갑에 자산을 받기 전에 초기화하고 새로 만드세요."
        / "If you could not write down the recovery words or lost them, reset and create a new wallet before receiving any assets into this one.";
    // ----- S05/S06 import -----
    /// S05 title.
    IMPORT_WALLET = "기존 지갑 가져오기" / "Import an existing wallet";
    /// S05 card.
    IMPORT_NEED_TITLE = "준비할 것" / "What you need";
    /// S05 line.
    IMPORT_NEED_WORDS = "· 다른 지갑에서 쓰던 영어 복구 단어(BIP39 니모닉) 12·15·18·21·24개"
        / "· The 12, 15, 18, 21 or 24 English recovery words (BIP39 mnemonic) you used in another wallet";
    /// S05 line.
    IMPORT_NEED_PASSPHRASE = "· 그 지갑에서 BIP39 passphrase(25번째 단어)를 썼다면 그 passphrase"
        / "· If that wallet used a BIP39 passphrase (25th word), that passphrase";
    /// S05 help.
    IMPORT_KEY_HINT = "복구 단어 없이 개인키(EVM·Solana·Bitcoin)만 있다면 첫 화면의 '개인키로 시작하기'를 쓰세요. 이미 지갑이 있다면 메인 화면의 '개인키 가져오기'로 더할 수 있습니다."
        / "If you only have a private key (EVM, Solana, Bitcoin) and no recovery words, use 'Start with a private key' on the first screen. If you already have a wallet, add it with 'Import private key' on the main screen.";
    /// S06 text.
    IMPORT_ADDRESS_TEXT = "가져온 지갑의 첫 주소입니다. 이전 지갑에서 쓰던 주소와 전체가 같은지 확인하세요."
        / "This is the first address of the imported wallet. Check that it is exactly the address you used in your earlier wallet.";
    /// S06 button.
    IMPORT_CORRECT = "맞습니다" / "It matches";
    /// S06 button.
    IMPORT_WRONG = "다릅니다" / "It differs";
    /// S06 help.
    IMPORT_ADDRESS_HELP = "다르면 복구 단어의 순서·철자나 passphrase를 확인하세요. '다릅니다'를 누르면 복구 단어를 다시 입력합니다."
        / "If it differs, check the order and spelling of the recovery words or the passphrase. 'It differs' lets you enter the recovery words again.";
    // ----- S07 locked -----
    /// S07 title.
    LOCKED_TITLE = "지갑이 잠겨 있습니다" / "The wallet is locked";
    /// S07 text.
    LOCKED_TEXT = "계정과 잔액을 보려면 비밀번호로 잠금을 해제하세요." / "Unlock with your password to see accounts and balances.";
    /// S07 button.
    UNLOCK = "잠금 해제" / "Unlock";
    /// S07 auto-lock note: {0} minutes.
    LOCKED_AUTO_LOCK(1) = "{0}분 동안 쓰지 않거나, Windows를 잠그거나 절전에 들어가면 지갑이 자동으로 잠깁니다."
        / "The wallet locks itself after {0} minutes without use, or when Windows locks or goes to sleep.";
    /// S07 damaged file help.
    LOCKED_DAMAGED = "비밀번호가 맞는데도 계속 열리지 않으면 지갑 파일이 손상되었을 수 있습니다. 같은 비밀번호로 이전 사본(.prev) 복구를 시도할 수 있습니다. 지갑 파일이 정상이면 복구하지 않고 그대로 엽니다."
        / "If the wallet keeps failing to open although the password is right, the wallet file may be damaged. You can try restoring the previous copy (.prev) with the same password. If the wallet file is fine, it simply opens without restoring.";
    /// S07 link.
    RECOVER_PREV = "이전 사본(.prev)으로 복구" / "Restore the previous copy (.prev)";
    /// S07 label.
    FORGOT_PASSWORD = "비밀번호를 잊었나요?" / "Forgot your password?";
    /// S07 link.
    RESET_WALLET = "지갑 초기화…" / "Reset wallet…";
    // ----- T-PASS-MISMATCH -----
    /// Title.
    MISMATCH_TITLE = "passphrase 확인" / "Check the passphrase";
    /// Banner.
    MISMATCH_BANNER = "passphrase가 다를 수 있습니다. 다른 passphrase는 다른(빈) 지갑을 엽니다."
        / "The passphrase may be different. A different passphrase opens a different (empty) wallet.";
    /// Checkbox.
    MISMATCH_CHECK = "다른 passphrase는 다른(빈) 지갑을 엽니다" / "A different passphrase opens a different (empty) wallet";
    /// Button.
    MISMATCH_RETRY = "다시 입력" / "Enter again";
    /// Button.
    MISMATCH_CONTINUE = "이 passphrase로 계속" / "Continue with this passphrase";
    // ----- S08 done -----
    /// S08 title.
    DONE_TITLE = "준비되었습니다" / "All set";
    /// S08 `YubiKey` wallet created: {0} serial.
    DONE_YK_CREATED(1) = "YubiKey 지갑을 만들었습니다 (YubiKey #{0})." / "The YubiKey wallet was created (YubiKey #{0}).";
    /// Its backup note.
    DONE_YK_CREATED_BACKUP = "이 지갑의 백업은 방금 적은 복구 단어 24개입니다. 이 PC에는 저장하지 않았으니 종이를 안전하게 보관하세요."
        / "This wallet's backup is the 24 recovery words you just wrote down. They are not stored on this PC, so keep the paper safe.";
    /// S08 `YubiKey` connected: {0} serial.
    DONE_YK_CONNECTED(1) = "YubiKey를 연결했습니다 (YubiKey #{0})." / "The YubiKey was connected (YubiKey #{0}).";
    /// Its backup note.
    DONE_YK_CONNECTED_BACKUP = "복구 단어 없이 카드의 공개키로 연결했습니다. 이 PC에는 개인키도 복구 단어도 없어 카드가 그 키의 유일한 사본일 수 있습니다 — 카드를 잃었을 때를 대비해 원래 백업(복구 단어 등)이 있는지 확인하세요."
        / "Connected with the card's public keys, without recovery words. This PC has neither private keys nor recovery words, so the card may be the only copy of those keys — make sure the original backup (recovery words etc.) exists in case the card is lost.";
    /// S08 after an import.
    DONE_IMPORTED = "지갑을 가져왔습니다. 이제 지갑을 쓸 수 있습니다." / "The wallet was imported. You can use it now.";
    /// Its backup note.
    DONE_IMPORTED_BACKUP = "이 지갑의 백업은 방금 입력한 복구 단어(와 passphrase)입니다. 그 종이 백업을 계속 안전하게 보관하세요."
        / "This wallet's backup is the recovery words (and passphrase) you just entered. Keep that paper backup safe.";
    /// S08 after the backup check.
    DONE_BACKUP_OK = "백업을 확인했습니다. 이제 지갑을 쓸 수 있습니다." / "The backup was checked. You can use the wallet now.";
    /// S08 card.
    DONE_SETUP = "처음 설정" / "First setup";
    /// S08 button.
    DONE_OPEN_WALLET = "지갑 열기" / "Open wallet";
    /// S08 ①.
    DONE_RPC_TITLE = "① 블록체인 연결(RPC)" / "① Blockchain connection (RPC)";
    /// S08 ① summary: {0} addresses, {1} working, {2} failed.
    DONE_RPC_SUMMARY(3) = "RPC 주소 {0}개 · 이번 실행 테스트: 작동 {1} · 실패 {2}"
        / "{0} RPC addresses · tests this run: {1} working · {2} failed";
    /// Opens the network settings.
    OPEN_RPC_SETTINGS = "RPC 설정 열기" / "Open RPC settings";
    /// S08 ① text.
    DONE_RPC_NEED = "잔액을 보고 돈을 보내려면 블록체인 노드에 연결할 RPC 주소가 필요합니다."
        / "To see balances and send money, you need an RPC address that connects to a blockchain node.";
    /// S08 ① field.
    QUICKNODE_ADDRESS = "QuickNode 주소" / "QuickNode address";
    /// S08 ① button.
    DONE_CONNECT = "연결하기" / "Connect";
    /// S08 ① link.
    DONE_OTHER_PROVIDERS = "알케미·직접 입력은 설정에서 ▸" / "Alchemy or manual entry in settings ▸";
    /// S08 ① help for other providers.
    DONE_PROVIDER_HELP = "선택한 RPC 공급자의 자격 정보나 주소는 설정 → 네트워크(RPC)에서 넣습니다."
        / "Enter the selected RPC provider's credentials or addresses in Settings → Network (RPC).";
    /// S08 ① button.
    DONE_SET_RPC = "RPC 설정하기" / "Set up RPC";
    /// S08 ① link.
    DONE_RPC_JSON = "rpc.json이 있습니다 — 설정에서 가져오기 ▸" / "rpc.json found — import it in settings ▸";
    /// S08 results: {0} network.
    OPEN_ROW(1) = "{0} 행 열기 ▸" / "Open the {0} row ▸";
    /// S08 results: {0} network.
    TESTING_NAME(1) = "… {0} 테스트 중" / "… testing {0}";
    /// S08 results count: {0} total, {1} working.
    WORKS_OF(2) = "{0}개 중 {1}개 작동" / "{1} of {0} working";
    /// S08 results count while testing: {0} total, {1} working, {2} testing.
    WORKS_OF_TESTING(3) = "{0}개 중 {1}개 작동 · {2}개 테스트 중" / "{1} of {0} working · {2} being tested";
    /// S08 results help.
    DONE_FAILED_HELP = "QuickNode 대시보드에서 그 체인을 켰는지 확인한 뒤 설정 → 네트워크(RPC)의 “모두 테스트”로 다시 확인하세요. 나머지는 지금 쓸 수 있습니다."
        / "Check that the chain is enabled in the QuickNode dashboard, then test again with “Test all” in Settings → Network (RPC). The others can be used now.";
    /// S08 ②.
    DONE_DAPP_TITLE = "② dApp 연결 (선택, 둘 중 하나)" / "② dApp connection (optional, either one)";
    /// S08 ②: {0} extension status.
    CHROME_EXTENSION_STATUS(1) = "Chrome 확장: {0}" / "Chrome extension: {0}";
    /// S08 ② button.
    HOW_TO_INSTALL = "설치 방법" / "How to install";
    /// `WalletConnect` without a project id.
    NO_PROJECT_ID = "Project ID 없음" / "no Project ID";
    /// `WalletConnect` configured.
    CONFIGURED = "설정됨" / "configured";
    /// S08 ③.
    DONE_DEPOSIT_TITLE = "③ 첫 입금 시험" / "③ First deposit test";
    /// S08 ③ text.
    DONE_DEPOSIT_TEXT = "실제 자산은 소액으로 받기 → 보내기를 한 번 해 보세요." / "With real assets, try receive → send once with a small amount.";
    /// S08 ③ on Sepolia.
    DONE_DEPOSIT_SEPOLIA = " EVM 탭은 Sepolia 테스트넷으로 시작합니다." / " The EVM tab starts on the Sepolia testnet.";
    /// S08 ③ other network: {0} network.
    DONE_DEPOSIT_NETWORK(1) = " 지금 EVM 네트워크: {0}." / " Current EVM network: {0}.";
    /// S08 balance card on Sepolia.
    DONE_BALANCE_SEPOLIA = "· EVM 탭은 Sepolia 테스트넷으로 시작합니다 — 쓰던 네트워크를 고르세요"
        / "· The EVM tab starts on the Sepolia testnet — choose the network you used";
    /// S08 balance card button.
    DONE_SHOW_MAINNET = "Ethereum 메인넷으로 보기" / "Show Ethereum mainnet";
    /// S08 balance card: {0} network.
    DONE_BALANCE_NETWORK(1) = "· EVM 탭은 지금 {0}입니다 — 다른 네트워크는 메인 화면의 네트워크 칩에서 고르세요"
        / "· The EVM tab is on {0} — choose other networks with the network chip on the main screen";
    /// S08 balance card: accounts.
    DONE_BALANCE_ACCOUNTS = "· 계정은 자동으로 찾지 않습니다. 이전 지갑에서 계정을 여러 개 썼다면 “내 계정 → 계정 추가”를 차례로 누르세요. Solana의 다른 경로는 Solana 탭 “다른 경로 스캔”."
        / "· Accounts are not searched automatically. If you used several accounts in your earlier wallet, press “My accounts → Add account” for each. For other Solana paths, use “Scan other paths” on the Solana tab.";
    /// S08 balance card: both chains off.
    DONE_OFF_BOTH = "· Bitcoin·Zcash는 꺼져 있습니다 — 설정 → Bitcoin, Zcash 탭에서 켜면 보입니다(Bitcoin은 네이티브 세그윗 계정 0부터)."
        / "· Bitcoin and Zcash are off — turn them on in Settings → Bitcoin and on the Zcash tab to see them (Bitcoin from native SegWit account 0).";
    /// S08 balance card: Bitcoin off.
    DONE_OFF_BITCOIN = "· Bitcoin은 꺼져 있습니다 — 설정 → Bitcoin에서 켜면 보입니다(네이티브 세그윗 계정 0부터)."
        / "· Bitcoin is off — turn it on in Settings → Bitcoin to see it (from native SegWit account 0).";
    /// S08 balance card: Zcash off.
    DONE_OFF_ZCASH = "· Zcash는 꺼져 있습니다 — Zcash 탭에서 켜면 보입니다." / "· Zcash is off — turn it on in the Zcash tab to see it.";
    /// S08 balance card title.
    DONE_NO_BALANCE = "잔액이 안 보이면" / "If no balance shows";
    // ----- S09 recovery -----
    /// S09 title.
    RECOVERY_TITLE = "지갑 파일 복구" / "Wallet file recovery";
    /// S09 missing file.
    RECOVERY_MISSING = "지갑 파일이 없고 이전 사본(.prev)이 있습니다." / "The wallet file is missing and a previous copy (.prev) exists.";
    /// S09 help.
    RECOVERY_PREV_HELP = "이전 사본으로 복구하면 마지막 변경(예: 가져온 개인키)이 사라질 수 있습니다. 지금 파일은 지우지 않고 데이터 폴더에 vault.ywv.corrupt-<시각> 이름으로 옮겨 두며, 복구 뒤 그 이름을 알려 드립니다(직접 되돌리는 방법: 복구 안내)."
        / "Restoring the previous copy may lose the last change (for example an imported private key). The current file is not deleted: it is moved in the data folder to the name vault.ywv.corrupt-<time>, which is shown after the restore (to undo it yourself: recovery guide).";
    /// Data folder field.
    DATA_FOLDER = "데이터 폴더" / "Data folder";
    /// S09 button.
    RECOVERY_RESTORE = "이전 사본으로 복구" / "Restore previous copy";
    /// S09 button.
    EXIT = "종료" / "Quit";
    /// S09 help.
    RECOVERY_NEVER_DELETES = "앱은 지갑 파일을 지우거나 덮어쓰지 않습니다. 복구 단어가 있으면 언제든 새로 가져올 수 있습니다."
        / "The app never deletes or overwrites wallet files. With the recovery words you can always import the wallet again.";
    /// S09 reset help.
    RECOVERY_RESET = "복구할 수 없다면: 지갑 파일을 데이터 폴더 안의 reset- 폴더로 옮겨 두고 처음부터 시작합니다."
        / "If it cannot be restored: the wallet files are moved to a reset- folder inside the data folder and you start over.";
    // ----- S10 main: EVM hero card, accounts -----
    /// A blocked chain's balance caption: {0} block, {1} code.
    AT_BLOCK_FAILED(2) = "블록 {0} 기준 · 갱신 실패 {1}" / "at block {0} · update failed {1}";
    /// No balance.
    BALANCE_NONE = "잔액 —" / "Balance —";
    /// Balance not read on a blocked chain.
    BALANCE_NOT_YET = "잔액을 아직 읽지 못했습니다. RPC 연결을 확인하고 새로고침하세요."
        / "The balance has not been read yet. Check the RPC connection and refresh.";
    /// Token summary: {0} the tokens.
    TOKENS_LINE(1) = "토큰: {0}" / "Tokens: {0}";
    /// Send button.
    SEND = "보내기" / "Send";
    /// Refresh link.
    REFRESH = "새로고침" / "Refresh";
    /// Network label.
    NETWORK = "네트워크" / "Network";
    /// Sepolia pill.
    TESTNET_PILL = "테스트넷 — 실제 자산이 아닙니다" / "Testnet — not real assets";
    /// Accounts card.
    MY_ACCOUNTS = "내 계정" / "My accounts";
    /// Account tag of an imported key.
    IMPORTED_KEY_TAG = "가져온 키" / "imported key";
    /// Save button.
    SAVE = "저장" / "Save";
    /// Rename button.
    RENAME = "이름 바꾸기" / "Rename";
    /// Hide button.
    HIDE = "숨기기" / "Hide";
    /// Delete button.
    DELETE = "삭제" / "Delete";
    /// Add account button.
    ADD_ACCOUNT = "계정 추가" / "Add account";
    /// Import key button.
    IMPORT_KEY = "개인키 가져오기" / "Import private key";
    /// Recovery-phrase link.
    ADD_MANAGE_MNEMONICS = "복구 단어 추가·관리" / "Add or manage recovery words";
    // ----- settings -----
    /// Back to S08.
    BACK_DONE = "← 처음 설정으로" / "← Back to first setup";
    /// Settings tab.
    TAB_SECURITY = "보안" / "Security";
    /// Settings tab.
    TAB_MNEMONICS = "복구 단어" / "Recovery";
    /// Settings tab.
    TAB_NETWORK = "네트워크(RPC)" / "Network (RPC)";
    /// Settings tab.
    TAB_CHAINS = "EVM 체인" / "EVM chains";
    /// Settings tab.
    TAB_AI = "AI 설명" / "AI";
    /// Settings tab.
    TAB_OTHER = "브라우저·정보" / "Browser · info";
    /// Advanced toggle, open.
    ADVANCED_HIDE = "고급 설정 숨기기 ▾" / "Hide advanced settings ▾";
    /// Advanced toggle, closed.
    ADVANCED_SHOW = "고급 설정 보기 ▸" / "Show advanced settings ▸";
    /// Security card.
    AUTO_LOCK_TITLE = "자동 잠금" / "Auto-lock";
    /// Security card help.
    AUTO_LOCK_HELP = "정한 시간 동안 쓰지 않으면 지갑을 잠급니다. Windows를 잠그거나 절전에 들어갈 때도 잠깁니다."
        / "Locks the wallet when it is not used for the set time. It also locks when Windows locks or goes to sleep.";
    /// Security field.
    AUTO_LOCK_LABEL = "잠그기까지(분, 1–60)" / "Lock after (min, 1–60)";
    /// Security card.
    SECRETS_TITLE = "복구 단어·개인키" / "Recovery words · private keys";
    /// Key-only wallet help.
    SECRETS_KEY_ONLY = "이 지갑은 개인키로 시작해 복구 단어가 없습니다. 각 계정의 백업은 그 원래 개인키이며, 보기 전에 비밀번호를 다시 묻고 화면 캡처에서 제외된 창에 보여줍니다."
        / "This wallet started from a private key and has no recovery words. Each account's backup is its original private key; your password is asked again before it is shown, in a window excluded from screen capture.";
    /// Show-key note.
    SECRETS_KEY_NOTE = "개인키 보기는 메인 화면에서 선택한 EVM 계정의 키를 보여줍니다. Solana·Bitcoin의 가져온 개인키는 각 탭의 계정에서 '개인키 보기'를 누르세요."
        / "'Show private key' shows the key of the EVM account selected on the main screen. For imported Solana and Bitcoin keys, press 'Show private key' at the account on each tab.";
    /// Copy checkbox.
    ALLOW_COPY = "복구 단어·개인키 복사 허용" / "Allow copying recovery words and private keys";
    /// Copy help.
    ALLOW_COPY_HELP = "기본은 꺼짐입니다. 켜면 복사한 값은 클립보드 기록에 남지 않고 30초 뒤 지워집니다."
        / "Off by default. When on, a copied value is kept out of the clipboard history and cleared after 30 seconds.";
    /// Password card.
    PASSWORD_TITLE = "비밀번호" / "Password";
    /// Password card help.
    PASSWORD_HELP = "이 PC에서 지갑을 열 때 쓰는 비밀번호입니다. 바꿔도 복구 단어와 주소는 그대로입니다."
        / "The password that opens the wallet on this PC. Changing it keeps the recovery words and addresses.";
    /// Password button.
    CHANGE_PASSWORD = "비밀번호 변경" / "Change password";
    /// File card.
    FILE_PROTECTION_TITLE = "지갑 파일과 보호 상태" / "Wallet file and protection";
    /// WER excluded.
    WER_PROTECTED = "Windows 오류 보고(WER)에서 이 앱을 제외했습니다: 비정상 종료 때 메모리 덤프를 남기지 않습니다."
        / "This app is excluded from Windows Error Reporting (WER): no memory dump is left after a crash.";
    /// Reset card.
    RESET_TITLE = "지갑 초기화" / "Reset wallet";
    /// Reset card help.
    RESET_CARD_HELP = "이 PC의 지갑 파일을 데이터 폴더 안의 reset- 폴더로 옮기고(지우지 않음) 처음 화면으로 돌아갑니다. 다시 쓰려면 복구 단어·원래 개인키, 또는 YubiKey(“YubiKey 연결하기 (복구 단어 없이)”)가 필요합니다."
        / "Moves this PC's wallet files to a reset- folder inside the data folder (nothing is deleted) and returns to the first screen. To use the wallet again you need the recovery words, the original private keys, or a YubiKey (“Connect a YubiKey (no recovery words)”).";
    // ----- settings → network (RPC) -----
    /// Card.
    RPC_PROVIDER_TITLE = "RPC 공급자" / "RPC provider";
    /// rpc.json note.
    RPC_JSON_FOUND = "rpc.json이 있습니다 — 맨 아래 “rpc.json에서 가져오기”로 한 번에 넣을 수 있습니다."
        / "rpc.json found — “Import from rpc.json” at the bottom adds it all at once.";
    /// Card help.
    RPC_PROVIDER_HELP = "RPC는 지갑이 블록체인에서 잔액을 읽고 거래를 보낼 때 쓰는 연결 주소입니다. QuickNode나 알케미 계정 정보를 한 번 넣으면 아래 모든 네트워크의 주소를 자동으로 만들 수 있습니다."
        / "RPC is the connection address the wallet uses to read balances from the blockchain and send transactions. Enter your QuickNode or Alchemy account details once to create the addresses of all networks below automatically.";
    /// Template radio.
    TPL_QUICKNODE = "QuickNode 멀티체인" / "QuickNode multichain";
    /// Template radio and provider name.
    ALCHEMY = "알케미" / "Alchemy";
    /// Template radio.
    TPL_MANUAL = "직접 입력" / "Manual entry";
    /// No value.
    NONE = "없음" / "none";
    /// Stored QuickNode credentials: {0} state.
    QN_STORED(1) = "저장된 QuickNode 자격 정보: {0} (저장된 값은 다시 보이지 않습니다)"
        / "Stored QuickNode credentials: {0} (stored values are never shown again)";
    /// Field.
    QN_NAME = "엔드포인트 이름" / "Endpoint name";
    /// Field help.
    QN_NAME_HELP = "QuickNode 엔드포인트 주소 https://<이름>.quiknode.pro/… 의 <이름> 부분입니다. 대시보드의 주소 전체를 이 칸이나 토큰 칸에 붙여넣어도 됩니다(이름과 토큰을 알아서 나눕니다)."
        / "The <name> part of the QuickNode endpoint address https://<name>.quiknode.pro/…. You may also paste the whole address from the dashboard into this field or the token field (name and token are split for you).";
    /// Field.
    QN_TOKEN = "토큰" / "Token";
    /// Field help.
    QN_TOKEN_HELP = "주소 끝의 긴 문자열입니다. 입력한 값은 가려지고, 저장하면 Windows가 이 사용자 계정에서만 풀 수 있게 암호화합니다."
        / "The long string at the end of the address. The input is hidden, and when saved Windows encrypts it so that only this user account can decrypt it.";
    /// Stored Alchemy key: {0} state.
    ALCHEMY_STORED(1) = "저장된 알케미 키: {0} (저장된 값은 다시 보이지 않습니다)"
        / "Stored Alchemy key: {0} (stored values are never shown again)";
    /// Field.
    API_KEY = "API 키" / "API key";
    /// Field help.
    ALCHEMY_KEY_HELP = "알케미 대시보드의 API Key입니다. 입력한 값은 가려집니다." / "The API Key from the Alchemy dashboard. The input is hidden.";
    /// Manual help.
    MANUAL_HELP = "직접 입력: 아래 '네트워크별 RPC 주소'에서 네트워크마다 '입력'으로 https:// 주소를 넣으세요."
        / "Manual entry: in 'RPC addresses by network' below, use 'Enter' on each network to add its https:// address.";
    /// Button.
    GENERATE = "저장하고 RPC 주소 만들기" / "Save and create RPC addresses";
    /// Button.
    TPL_SAVE = "자격 정보만 저장" / "Save credentials only";
    /// Button.
    TPL_DELETE = "자격 정보 삭제" / "Delete credentials";
    /// Banner.
    TPL_DELETED = "자격 정보를 지웠습니다. 이미 만든 네트워크별 RPC 주소는 그대로입니다."
        / "The credentials were deleted. RPC addresses already created for each network stay as they are.";
    /// Help.
    GENERATE_HELP = "'저장하고 RPC 주소 만들기'는 위 칸의 자격 정보를 저장하고 아래 목록의 주소를 한 번에 만든 뒤 하나씩 테스트합니다. 이미 있는 주소는 덮어쓸지 따로 묻습니다."
        / "'Save and create RPC addresses' saves the credentials above, creates the addresses in the list below at once and tests them one by one. You are asked separately before existing addresses are overwritten.";
    /// Card.
    RPC_LIST_TITLE = "네트워크별 RPC 주소" / "RPC addresses by network";
    /// Card help.
    RPC_LIST_HELP = "'테스트'는 그 주소가 올바른 네트워크를 가리키는지 한 번 확인합니다. 주소에는 토큰이 들어 있어 '교체'를 누르면 가린 형태로만 보입니다."
        / "'Test' checks once that the address points to the right network. Addresses contain tokens, so 'Replace' shows them masked only.";
    /// Row button.
    REPLACE = "교체" / "Replace";
    /// Row button.
    ENTER = "입력" / "Enter";
    /// Row button.
    TEST = "테스트" / "Test";
    /// Row tag.
    WORKS = "작동" / "Working";
    /// Row tag.
    FAILED = "실패" / "Failed";
    /// Row tag.
    TESTING = "테스트 중" / "Testing";
    /// Open row without an address: {0} network.
    ROW_NO_ADDRESS(1) = "{0} · 주소 없음" / "{0} · no address";
    /// Open row: {0} network, {1} masked address.
    ROW_ADDRESS(2) = "{0} · 지금 주소 {1}" / "{0} · current address {1}";
    /// Open row: {0} provider.
    ROW_TEMPLATE_STORED(1) = "{0} 자격 정보가 저장되어 있습니다 — 위 “저장하고 RPC 주소 만들기”로 비어 있는 주소를 한 번에 만들 수 있습니다."
        / "{0} credentials are stored — “Save and create RPC addresses” above creates the empty addresses at once.";
    /// Open row help.
    ROW_PASTE_HELP = "https:// 로 시작하는 전체 주소를 붙여넣으세요. 저장 전에 형식을 검사하고, 저장하면 바로 테스트합니다."
        / "Paste the whole address starting with https://. Its format is checked before saving, and it is tested right after saving.";
    /// Banner.
    RPC_URL_DELETED = "RPC 주소를 지웠습니다." / "The RPC address was deleted.";
    /// Card.
    DORMANT_TITLE = "보관 중인 항목" / "Kept entries";
    /// Card help: {0} count.
    DORMANT_HELP(1) = "이 버전에서 쓰지 않는 RPC 항목 {0}개를 지우지 않고 보관하고 있습니다(등록되지 않은 체인의 주소나 다른 버전의 앱이 쓴 항목). 체인을 다시 추가하거나 다른 버전으로 돌아가면 다시 쓰입니다."
        / "{0} RPC entries not used by this version are kept, not deleted (addresses of unregistered chains, or entries written by another app version). They are used again when you add the chain back or return to that version.";
    /// Button.
    DORMANT_DELETE = "보관 항목 삭제" / "Delete kept entries";
    /// RPC list summary: {0} with address, {1} networks, {2} working, {3} failed, {4} untested.
    RPC_LIST_SUMMARY(5) = "RPC 주소 {0}/{1}개 설정 · 이번 실행 테스트: 작동 {2} · 실패 {3} · 안 함 {4}"
        / "RPC addresses {0}/{1} set · tests this run: {2} working · {3} failed · {4} not run";
    /// Failed networks label.
    FAILED_NETWORKS = "실패한 네트워크" / "Failed networks";
    /// Test-all button while busy: {0} current, {1} total.
    TESTING_PROGRESS(2) = "테스트 중 {0}/{1}" / "Testing {0}/{1}";
    /// Test-all button.
    TEST_ALL = "모두 테스트" / "Test all";
    // ----- settings → browser · info -----
    /// Card.
    EXTENSION_TITLE = "브라우저 확장" / "Browser extension";
    /// Button.
    EXTENSION_OPEN = "Chrome 확장 설치 방법·폴더" / "Chrome extension setup · folder";
    /// Card help.
    WC_HELP = "확장 없이 dApp의 WalletConnect QR·링크로 연결합니다(EVM). 처음 한 번 Reown Project ID가 필요하고, 연결·세션 관리는 '연결된 사이트 · WalletConnect' 화면에서 합니다."
        / "Connects through a dApp's WalletConnect QR code or link, without the extension (EVM). It needs a Reown Project ID once; connections and sessions are managed on the 'Connected sites · WalletConnect' screen.";
    /// Field.
    STATUS = "상태" / "Status";
    /// `WalletConnect` off.
    WC_OFF = "Project ID 없음 — 꺼져 있음" / "No Project ID — off";
    /// `WalletConnect` on: {0} sessions.
    WC_ON(1) = "Project ID 설정됨 · 세션 {0}개" / "Project ID set · {0} sessions";
    /// Button.
    WC_OPEN_SITES = "연결된 사이트 · WalletConnect 열기" / "Open connected sites · WalletConnect";
    /// Card.
    BROWSER_LINK_TITLE = "브라우저 연결" / "Browser connection";
    /// Card help.
    BROWSER_LINK_HELP = "Chrome 확장과 이 앱을 잇는 설정입니다. 사이트의 연결·서명 요청은 언제나 이 앱의 승인 창에서 확인합니다."
        / "Settings that link the Chrome extension and this app. Site connection and signing requests are always checked in this app's approval window.";
    /// Checkbox.
    AUTOLAUNCH = "dApp 요청 시 앱 자동 실행" / "Start the app on a dApp request";
    /// Help.
    AUTOLAUNCH_HELP = "끄면 앱이 꺼져 있을 때 사이트의 지갑 요청은 실패합니다." / "When off, a site's wallet requests fail while the app is not running.";
    /// Checkbox.
    LOCALHOST = "localhost dApp 허용 (개발용)" / "Allow localhost dApps (development)";
    /// Help.
    LOCALHOST_HELP = "dApp을 직접 개발할 때만 켜세요. http://localhost·127.0.0.1 페이지가 연결을 요청할 수 있게 됩니다."
        / "Turn on only when you develop a dApp yourself. Pages on http://localhost and 127.0.0.1 can then request a connection.";
    /// Card.
    DIAGNOSTICS_TITLE = "진단" / "Diagnostics";
    /// Card help.
    DIAGNOSTICS_HELP = "로그에는 비밀번호·니모닉·개인키·API 키·RPC 엔드포인트 URL이 없습니다. 주소와 거래 해시는 있을 수 있습니다."
        / "Logs contain no passwords, mnemonics, private keys, API keys or RPC endpoint URLs. They may contain addresses and transaction hashes.";
    /// Button.
    OPEN_LOG_FOLDER = "로그 폴더 열기" / "Open log folder";
    /// Field.
    LOG_LEVEL = "로그 수준" / "Log level";
    /// Help.
    LOG_LEVEL_HELP = "문제를 조사할 때만 debug로 바꾸세요. 기본값은 info입니다." / "Switch to debug only while investigating a problem. The default is info.";
    /// Card.
    ABOUT_TITLE = "정보" / "About";
    /// Field.
    VERSION = "버전" / "Version";
    /// Field.
    SHORTCUTS = "단축키" / "Shortcuts";
    /// Field value.
    SHORTCUTS_TEXT = "Ctrl+L 잠금 · Ctrl+1 / 2 / 3 / 4 체인 탭(EVM·Solana·Bitcoin·Zcash) · F5 새로고침 · Ctrl+, 설정 · Esc 뒤로·취소 · Tab 다음 칸 · PgUp / PgDn 한 쪽 스크롤 · Ctrl+Home / End 맨 위·맨 아래"
        / "Ctrl+L lock · Ctrl+1 / 2 / 3 / 4 chain tabs (EVM, Solana, Bitcoin, Zcash) · F5 refresh · Ctrl+, settings · Esc back/cancel · Tab next field · PgUp / PgDn scroll a page · Ctrl+Home / End top/bottom";
    // ----- confirmation overlays -----
    /// OK button.
    OK = "확인" / "OK";
    /// Copy-on overlay.
    C_COPY_TITLE = "복사 허용" / "Allow copying";
    /// Copy-on overlay text.
    C_COPY_TEXT = "복사를 허용하면 복구 단어(니모닉)·개인키를 클립보드에 넣을 수 있습니다. 클립보드 기록·클라우드 동기화에서는 제외하고 30초 뒤 지우지만, 그 사이에는 다른 프로그램이 읽을 수 있습니다. 그 전에 앱이 비정상 종료되면 다음에 앱을 열 때 지우며, 그때까지는 클립보드에 남습니다."
        / "Allowing copying lets recovery words (mnemonic) and private keys go to the clipboard. They are kept out of the clipboard history and cloud sync and cleared after 30 seconds, but other programs can read them in the meantime. If the app crashes before that, they are cleared the next time the app opens and stay on the clipboard until then.";
    /// Button.
    C_ALLOW = "허용" / "Allow";
    /// Localhost overlay.
    C_LOCALHOST_TITLE = "localhost dApp 허용" / "Allow localhost dApps";
    /// Localhost overlay text.
    C_LOCALHOST_TEXT = "개발용 설정입니다. 켜면 http://localhost 와 http://127.0.0.1 페이지가 지갑 연결을 요청할 수 있습니다."
        / "A development setting. When on, pages on http://localhost and http://127.0.0.1 can request a wallet connection.";
    /// Button.
    C_TURN_ON = "켜기" / "Turn on";
    /// Reveal overlay text.
    C_REVEAL_TEXT = "화면 근처의 사람이나 카메라가 볼 수 있습니다. 계속하려면 비밀번호를 입력하세요."
        / "People or cameras near the screen can see it. Enter your password to continue.";
    /// Button.
    C_CONTINUE = "계속" / "Continue";
    /// Generate overlay.
    C_GENERATE_TITLE = "RPC 주소 만들기" / "Create RPC addresses";
    /// Button.
    C_CREATE = "만들기" / "Create";
    /// RPC delete overlay.
    C_RPC_DELETE_TITLE = "RPC 주소 지우기" / "Delete RPC address";
    /// Button.
    C_REMOVE = "지우기" / "Delete";
    /// Template delete overlay.
    C_TPL_DELETE_TITLE = "자격 정보 지우기" / "Delete credentials";
    /// LLM key overlay.
    C_LLM_KEY_TITLE = "AI API 키 지우기" / "Delete AI API key";
    /// LLM key overlay text.
    C_LLM_KEY_TEXT = "저장된 AI 설명용 API 키를 지웁니다. 저장된 키는 다시 볼 수 없어, AI 설명을 다시 쓰려면 키를 다시 넣어야 합니다."
        / "Deletes the stored API key for AI explanations. A stored key cannot be shown again, so to use AI explanations again you must enter the key again.";
    /// `YubiKey` abandon overlay.
    C_YK_ABANDON_TITLE = "YubiKey 지갑 만들기를 그만둘까요?" / "Stop creating the YubiKey wallet?";
    /// Button.
    C_YK_ABANDON_YES = "그만두기" / "Stop";
    /// PIN later overlay.
    C_PIN_LATER_TITLE = "PIN을 나중에 설정할까요?" / "Set the PIN later?";
    /// PIN later overlay text.
    C_PIN_LATER_TEXT = "PIN을 설정하기 전에는 이 YubiKey로 서명하지 않습니다. 나중에 설정 → YubiKey에서 바꿀 수 있습니다."
        / "This YubiKey is not used for signing until its PIN is set. You can change it later in Settings → YubiKey.";
    /// Button.
    C_PIN_LATER_YES = "나중에" / "Later";
    /// Key removal overlay.
    C_REMOVE_KEY_TITLE = "가져온 개인키 삭제" / "Delete imported private key";
    /// `YubiKey` record removal overlay.
    C_REMOVE_YK_TITLE = "YubiKey 기록 삭제" / "Delete YubiKey record";
    /// Chain pin overlay.
    C_CHAIN_PIN_TITLE = "체인 추가 — 제네시스 고정" / "Add chain — pin genesis";
    /// Button.
    C_CHAIN_PIN_YES = "고정하고 저장" / "Pin and save";
    /// Chain re-pin overlay and button.
    C_REPIN = "다시 고정" / "Pin again";
    /// Chain delete overlay.
    C_CHAIN_DELETE_TITLE = "체인 삭제" / "Delete chain";
    /// Chain delete overlay text.
    C_CHAIN_DELETE_TEXT = "체인 정의, RPC 주소, 수수료 상한을 지웁니다. 이 체인의 토큰·활동 기록은 남고, 같은 chainId를 다시 추가하면 다시 보입니다."
        / "Deletes the chain definition, its RPC address and fee caps. The chain's tokens and activity stay and show again when the same chainId is added back.";
    /// Address book overlay.
    C_BOOK_DELETE_TITLE = "주소록 항목 삭제" / "Delete address book entry";
    /// Token overlay.
    C_TOKEN_DELETE_TITLE = "토큰 삭제" / "Delete token";
    /// Disconnect overlay.
    C_DISCONNECT_TITLE = "모든 사이트 연결 해제" / "Disconnect all sites";
    /// Disconnect overlay text.
    C_DISCONNECT_TEXT = "연결된 모든 사이트의 연결을 해제합니다. 사이트는 다시 연결을 요청해야 계정을 볼 수 있습니다."
        / "Disconnects all connected sites. A site has to request a connection again to see your accounts.";
    /// Disconnect overlay text with `WalletConnect` sessions: {0} sessions.
    C_DISCONNECT_WC_TEXT(1) = "연결된 모든 사이트의 연결을 해제하고 WalletConnect 세션 {0}개도 끊습니다(dApp 쪽 연결도 끊깁니다). 사이트는 다시 연결을 요청해야 계정을 볼 수 있습니다."
        / "Disconnects all connected sites and also ends {0} WalletConnect sessions (the dApp side is disconnected too). A site has to request a connection again to see your accounts.";
    /// Button.
    C_DISCONNECT_YES = "모두 해제" / "Disconnect all";
    /// Settings-file overlay.
    C_SETTINGS_FILE_TITLE = "설정 파일 값 사용" / "Use the settings file's values";
    /// Settings-file overlay text.
    C_SETTINGS_FILE_TEXT = "settings.json의 아래 값을 그대로 씁니다. 이 PC에서 직접 바꾼 경우에만 고르세요. 모르는 변경이면 '취소'를 누른 뒤 '앱에 저장된 값으로 되돌리기'를 누르세요."
        / "Uses the values below from settings.json as they are. Choose this only if you changed them yourself on this PC. For a change you do not recognise, press 'Cancel' and then 'Restore the app's saved values'.";
    /// Button.
    C_SETTINGS_FILE_YES = "파일 값 사용" / "Use the file's values";
    /// `WalletConnect` overlay.
    C_WC_DISCONNECT_TITLE = "모든 WalletConnect 세션 끊기" / "End all WalletConnect sessions";
    /// `WalletConnect` overlay text: {0} sessions.
    C_WC_DISCONNECT_TEXT(1) = "WalletConnect 세션 {0}개를 모두 끊을까요? 다시 쓰려면 dApp마다 QR이나 링크로 새로 연결해야 합니다."
        / "End all {0} WalletConnect sessions? To use them again, connect each dApp anew with its QR code or link.";
    /// Button.
    C_WC_DISCONNECT_YES = "모두 끊기" / "End all";
    /// Discard overlay.
    C_DISCARD_TITLE = "거래 폐기" / "Discard transaction";
    /// Button.
    C_DISCARD_YES = "폐기" / "Discard";
    /// LLM overlay.
    C_LLM_ON_TITLE = "AI 설명 켜기" / "Turn on AI explanations";
    /// Prune overlay text: {0} count, {1} names.
    C_PRUNE_TEXT(2) = "이 버전에서 쓰지 않는 항목 {0}개({1})를 apikeys.dpapi에서 지웁니다. 나중에 그 체인을 다시 추가하거나 다른 버전의 앱을 쓰면 주소·자격 정보를 다시 입력해야 합니다."
        / "Deletes {0} entries not used by this version ({1}) from apikeys.dpapi. If you later add the chain back or use another app version, you must enter the addresses and credentials again.";
    /// Removal overlay block.
    C_REMOVED_ACCOUNT = "지워지는 계정" / "Account to be removed";
    /// Field.
    C_TOKEN = "토큰" / "Token";
    /// Help.
    C_CONTRACT_ADDRESS = "컨트랙트 주소" / "Contract address";
    /// Field.
    C_ACCOUNT = "계정" / "Account";
    /// Checkbox.
    C_OVERWRITE = "기존 주소 덮어쓰기" / "Overwrite existing addresses";
    /// Checkbox.
    C_UNDERSTOOD = "이해했습니다" / "I understand";
    /// Checkbox.
    C_REPIN_CHECK = "새 제네시스 해시를 공식 자료로 확인했습니다" / "I checked the new genesis hash against official sources";
    /// Button.
    C_KEEP_CREATING = "계속 만들기" / "Keep creating";
    /// Button.
    C_PIN_NOW = "지금 PIN 설정" / "Set PIN now";
    /// RPC delete, manual.
    C_RPC_AGAIN_MANUAL = "“입력”으로 다시 넣어야 합니다" / "enter it again with “Enter”";
    /// RPC delete, template: {0} provider, {1} state.
    C_RPC_AGAIN_TEMPLATE(2) = "“저장하고 RPC 주소 만들기”({0} 자격 정보: {1}) 또는 “입력”으로 다시 넣어야 합니다"
        / "add it again with “Save and create RPC addresses” ({0} credentials: {1}) or “Enter”";
    /// RPC delete, refill note.
    C_RPC_REFILL = " 공급자 템플릿의 자격 정보가 저장돼 있어 다음 실행 때 템플릿 주소로 다시 채워집니다. 다른 주소를 쓰려면 지우지 말고 “교체”하세요."
        / " The provider template's credentials are stored, so the template address fills it again at the next start. To use another address, use “Replace” instead of deleting.";
    /// RPC delete text: {0} network name, {1} network id, {2} how to add again, {3} refill note.
    C_RPC_DELETE_TEXT(4) = "{0} ({1})의 RPC 주소를 지웁니다. 저장된 주소는 다시 볼 수 없어, 다시 쓰려면 {2}.{3} 이 네트워크에 확정 전 거래가 있으면 주소를 다시 넣을 때까지 상태 확인이 멈춥니다."
        / "Deletes the RPC address of {0} ({1}). A stored address cannot be shown again; to use one again, {2}.{3} If this network has unconfirmed transactions, their status checks stop until an address is added again.";
    /// Template delete, Alchemy.
    C_TPL_DELETE_ALCHEMY = "저장된 알케미 API 키를 지웁니다. 저장된 값은 다시 볼 수 없습니다. 이미 만든 네트워크별 RPC 주소는 그대로이고, 새 체인 주소를 만들 때 다시 넣어야 합니다."
        / "Deletes the stored Alchemy API key. Stored values cannot be shown again. RPC addresses already created stay as they are; enter the key again to create addresses for new chains.";
    /// Template delete, `QuickNode`.
    C_TPL_DELETE_QUICKNODE = "저장된 QuickNode 자격 정보(엔드포인트 이름·토큰)를 지웁니다. 저장된 값은 다시 볼 수 없습니다. 이미 만든 네트워크별 RPC 주소는 그대로이고, 새 체인 주소를 만들 때 다시 넣어야 합니다."
        / "Deletes the stored QuickNode credentials (endpoint name and token). Stored values cannot be shown again. RPC addresses already created stay as they are; enter them again to create addresses for new chains.";
    /// Generate overlay text.
    C_GENERATE_TEXT = "선택한 템플릿으로 아래 네트워크의 RPC 주소를 만듭니다. 이미 주소가 있는 네트워크는 '기존 주소 덮어쓰기'를 켰을 때만 바꿉니다."
        / "Creates RPC addresses for the networks below with the selected template. Networks that already have an address change only with 'Overwrite existing addresses' on.";
    /// Generate overlay: an existing address.
    C_GENERATE_EXISTING = " — 기존 주소 있음" / " — has an address";
    /// Generate overlay: skipped.
    C_GENERATE_SKIPPED = "\n건너뜀(템플릿 항목 없음):" / "\nSkipped (no template entry):";
}
