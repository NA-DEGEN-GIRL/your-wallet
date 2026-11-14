//! Fixed texts of the `YubiKey` screens (spec/04 §2.19, spec/10 §7, §9, §15; English spec/14):
//! S20, the enrolment wizard, settings → `YubiKey`, the PIN card, "`YubiKey` 연결하기 (복구 단어
//! 없이)", `슬롯 구성 바꾸기` and `YubiKey의 키 지우기`.

yw_core::texts! {
    // ----- shared ------------------------------------------------------------------------------
    BTN_CANCEL = "취소" / "Cancel";
    BTN_NEXT = "다음" / "Next";
    BTN_RETRY = "다시 시도" / "Try again";
    BTN_FINISH = "완료" / "Done";
    BTN_READ_AGAIN = "다시 읽기" / "Read again";
    BTN_CHOOSE_AGAIN = "← 다시 고르기" / "← Choose again";
    BTN_NEXT_CONFIRM = "다음 (확인)" / "Next (confirm)";
    BTN_NEXT_WORDS = "다음 (복구 단어 입력)" / "Next (enter recovery words)";
    /// The `PIN 설정` button (the card list's action, the factory-PIN bands).
    BTN_SET_PIN = "PIN 설정" / "Set PIN";
    /// `PIN 설정하기` (the PIN card's and the re-slot result's button).
    BTN_SET_PIN_NOW = "PIN 설정하기" / "Set PIN now";
    STEP_CONFIRM = "확인" / "Confirm";
    STEP_RESULT = "결과" / "Result";
    STEP_PUT_ON_CARD = "YubiKey에 넣기" / "Put on YubiKey";
    CHECKING = "확인 중…" / "Checking…";
    FIELD_PATH = "경로" / "Path";
    FIELD_POLICY = "정책" / "Policy";
    FIELD_FIRMWARE = "펌웨어" / "Firmware";
    FIELD_RELATION = "관계" / "Relation";
    FIELD_PIV_MANAGEMENT = "PIV 관리 키" / "PIV management key";
    /// `{0}` the path.
    PATH_LINE(1) = "경로: {0}" / "Path: {0}";
    LABEL_TOUCH = "터치" / "Touch";
    LABEL_ZEC_NETWORK = "Zcash 네트워크" / "Zcash network";
    /// `{0}` the Bitcoin network.
    LABEL_ADDRESS_TYPE(1) = "주소 형식 ({0})" / "Address type ({0})";
    /// `{0}` the highest index.
    LABEL_ACCOUNT_INDEX(1) = "계정 인덱스 (0–{0})" / "Account index (0–{0})";
    /// `{0}` the highest index.
    LABEL_ADDRESS_INDEX(1) = "주소 인덱스 (0–{0})" / "Address index (0–{0})";
    /// `{0}` the word to type.
    TYPE_WORD(1) = "확인: '{0}' 입력" / "Confirm: type '{0}'";
    SHARED_ACK = "이해했습니다: 공유 키는 두 체인의 신원을 연결할 수 있습니다"
        / "I understand: the shared key can link my identities on the two chains";
    RUNNING_KEEP = "YubiKey를 빼지 마세요. 몇 초 걸립니다(터치는 필요 없습니다)."
        / "Do not remove the YubiKey. It takes a few seconds (no touch needed).";
    NO_SIGN_BEFORE_PIN = "PIN을 설정하기 전에는 이 YubiKey로 서명하지 않습니다."
        / "This YubiKey does not sign until its PIN is set.";
    BACKUP_COPY = "백업 복사본" / "Backup copy";
    TOUCH_NEVER = "터치 없음" / "No touch";
    TOUCH_ALWAYS = "항상" / "Always";
    TOUCH_CACHED = "15초 유지" / "Cached 15 s";
    TOUCH_ALWAYS_FIXED = "항상(고정)" / "Always (fixed)";
    TOUCH_CACHED_FIXED = "15초 유지(고정)" / "Cached 15 s (fixed)";
    POLICY_TOUCH(1) = "터치: {0}" / "Touch: {0}";
    POLICY_TOUCH_SESSION(1) = "터치: {0} · PIN: 세션마다" / "Touch: {0} · PIN: once per session";
    POLICY_TOUCH_EVERY(1) = "터치: {0} · PIN: 서명마다" / "Touch: {0} · PIN: every signature";
    KIND_NONE = "없음" / "None";
    KIND_EVM = "EVM 계정" / "EVM account";
    KIND_BTC = "Bitcoin 주소" / "Bitcoin address";
    KIND_SHARED = "EVM 공유 키" / "EVM shared key";
    KIND_ZEC = "Zcash 주소" / "Zcash address";
    ZEC_MAINNET = "메인넷 (t1…)" / "Mainnet (t1…)";
    ZEC_TESTNET = "테스트넷 (tm…)" / "Testnet (tm…)";

    // ----- fixed sentences (spec/04 §2.16 T-YK-*) ------------------------------------------------
    /// T-YK-PINS-FIRST: a new `YubiKey` wallet's result screen until "PIN 설정" is done.
    YK_PINS_FIRST = "YubiKey 지갑은 PIN 설정을 마쳐야 끝납니다. 공장 기본 PIN(123456 / 12345678)으로는 서명하지 않습니다 — 아래 'PIN 설정하기'로 PIN을 바꾸세요."
        / "The YubiKey wallet is finished only after the PIN setup. It does not sign with the factory default PINs (123456 / 12345678) — change the PIN with 'Set PIN now' below.";
    /// T-YK-PIN-NEEDED: the main-window note after a signing refused for factory PINs.
    YK_PIN_NEEDED = "이 YubiKey는 공장 기본 PIN을 쓰고 있어 서명하지 않았습니다. PIN을 설정한 뒤 다시 서명하세요."
        / "This YubiKey uses its factory default PIN, so it did not sign. Set the PIN, then sign again.";
    /// T-YK-LIST (settings → `YubiKey`).
    YK_LIST = "YubiKey 계정은 복구 단어에서 만든 키를 YubiKey에 넣어 두고, 서명할 때마다 YubiKey에서 PIN과 터치로 서명합니다. 이 PC에는 공개키·주소·슬롯 표만 있습니다. 같은 키를 여러 YubiKey에 넣어 서로의 백업으로 쓸 수 있습니다(최대 8개)."
        / "YubiKey accounts keep keys made from recovery words on the YubiKey, and every signature is made on the YubiKey with the PIN and a touch. This PC holds only public keys, addresses and the slot table. The same keys can go on several YubiKeys as backups of each other (up to 8).";
    /// T-YK-MNEMONIC-WALLET: the recommendation in a wallet that stores its words.
    YK_MNEMONIC_WALLET = "이 지갑의 복구 단어로 등록하면 그 단어가 이 PC에도 있으므로 보안 이득이 없습니다. 다른 복구 단어로 등록하거나, 키를 PC 밖에 두려면 첫 화면의 'YubiKey 지갑'(복구 단어를 저장하지 않는 지갑)을 새로 만드세요."
        / "Enrolling with this wallet's recovery words adds no security, because those words are also on this PC. Enrol with other recovery words, or to keep the keys off the PC, create a new 'YubiKey wallet' (a wallet that does not store recovery words) from the first screen.";
    /// T-YK-PIN-GUIDE (spec/10 §9.3): what each card secret is for.
    PIN_GUIDE_PW1 = "OpenPGP PIN: EVM·Bitcoin 서명할 때마다 입력 (기본 123456, 6자 이상)"
        / "OpenPGP PIN: entered for every EVM and Bitcoin signature (default 123456, 6 or more characters)";
    PIN_GUIDE_PW3 = "OpenPGP 관리자 PIN: 키를 넣을 때, OpenPGP PIN이 잠겼을 때 (기본 12345678, 8자 이상)"
        / "OpenPGP admin PIN: when importing keys and when the OpenPGP PIN is locked (default 12345678, 8 or more characters)";
    PIN_GUIDE_PIV_PIN = "PIV PIN: Solana 서명할 때 (기본 123456, 6–8자)"
        / "PIV PIN: for Solana signatures (default 123456, 6–8 characters)";
    PIN_GUIDE_PUK = "PIV PUK: PIV PIN이 잠겼을 때 풀기 (기본 12345678, 6–8자)"
        / "PIV PUK: unlocks a locked PIV PIN (default 12345678, 6–8 characters)";
    PIN_GUIDE_MANAGEMENT = "PIV 관리 키: 앱이 자동으로 만들어 PIN으로 잠가 보관 (입력할 필요 없음)"
        / "PIV management key: made by the app and kept locked with the PIN (nothing to enter)";
    /// T-YK-PIN-LOCKS.
    YK_PIN_LOCKS = "각각 3번 틀리면 따로 잠깁니다. 하나가 잠겨도 다른 쪽(OpenPGP/PIV)은 그대로이고, FIDO2·패스키 로그인은 이 중 어느 것과도 관계없습니다."
        / "Each locks on its own after 3 wrong tries. If one locks, the other side (OpenPGP/PIV) stays as it is, and FIDO2/passkey sign-in is unrelated to all of them.";
    /// T-YK-PIN-EASY.
    YK_PIN_EASY = "편하게 쓰려면: 8자리 하나로 통일하세요 (네 개 모두 같은 값). 기본값 그대로 두면 YubiKey를 가진 사람이 서명할 수 있습니다."
        / "For ease of use: use one 8-character PIN (the same value for all four). If you keep the defaults, anyone holding the YubiKey can sign.";
    /// T-YK-PIN-TRADEOFF (the unified mode).
    YK_PIN_TRADEOFF = "순서: PIV PIN → PIV PUK → PIV 관리 키(새로 만들어 PIN으로 보호) → OpenPGP 관리자 PIN → OpenPGP PIN. 하나로 통일하면 잠기기 전까지 맞혀 볼 기회가 늘고(네 곳 각 3번), 서명 PIN을 아는 사람이 관리자 권한도 갖습니다. 개인용으로는 괜찮은 선택입니다."
        / "Order: PIV PIN → PIV PUK → PIV management key (made new and protected with the PIN) → OpenPGP admin PIN → OpenPGP PIN. One PIN for all gives more guesses before everything locks (3 at each of four places), and whoever knows the signing PIN also has admin rights. For personal use it is a reasonable choice.";
    /// T-YK-PROTECT-MGMT (the separate mode).
    YK_PROTECT_MGMT = "PIV 관리 키 자동 보호: 새 관리 키를 이 PC에서 무작위로 만들어 YubiKey에 PIN으로 잠가 둡니다('ykman piv access change-management-key --generate --protect'와 같음). 현재 PIV PIN만 묻고, 관리 키는 보여 주지도 묻지도 않습니다."
        / "Protect PIV management key: a new management key is made at random on this PC and locked on the YubiKey with the PIN (the same as 'ykman piv access change-management-key --generate --protect'). Only the current PIV PIN is asked; the management key is never shown or asked.";
    /// T-YK-IMPORT: the "가져오기" choice.
    YK_IMPORT = "복구 단어에서 고른 키를 YubiKey에 씁니다. 그 슬롯에 이번에 넣을 키가 아닌 다른 키가 있으면 위의 확인을 마친 뒤에만 덮어씁니다."
        / "Writes the chosen keys from the recovery words to the YubiKey. If a slot holds a key other than the one being imported, it is overwritten only after the confirmation above.";
    /// T-YK-ADOPT (spec/10 §7.5).
    YK_ADOPT = "YubiKey에 이미 같은 복구 단어의 키가 들어 있을 때 씁니다. 카드에는 아무것도 쓰지 않고, 카드의 공개키가 복구 단어와 맞는지만 확인해 지갑에 연결합니다(재설치·새 PC·지갑 초기화 후)."
        / "Use this when the YubiKey already holds keys of the same recovery words. Nothing is written to the card; the wallet only checks that the card's public keys match the recovery words and connects them (after a reinstall, a new PC or a wallet reset).";

    // ----- step labels -------------------------------------------------------------------------
    STEP_PLAN = "키·슬롯 고르기" / "Choose keys and slots";
    STEP_CREDENTIALS = "자격 정보" / "Credentials";
    STEP_PASSWORD = "비밀번호" / "Password";
    STEP_WRITE_WORDS = "복구 단어 적기" / "Write down recovery words";
    STEP_BACKUP_CHECK = "백업 확인" / "Backup check";
    STEP_SET_PIN = "PIN 정하기" / "Choose PIN";
    STEP_CONNECT_READ = "YubiKey 읽기·키 고르기" / "Read YubiKey and choose keys";
    STEP_CONNECT_ADDRESSES = "주소 확인" / "Check addresses";
    STEP_RESLOT_CHOOSE = "새 구성 고르기" / "Choose new layout";

    // ----- S20 ---------------------------------------------------------------------------------
    TITLE_YK_WALLET = "YubiKey 지갑 만들기" / "Create a YubiKey wallet";
    BEFORE_START = "시작하기 전에" / "Before you start";
    INTRO_PAPER = "· 종이와 펜, YubiKey를 준비하세요. 새 복구 단어 24개를 한 번 보여 드립니다."
        / "· Have paper, a pen and the YubiKey ready. The 24 new recovery words are shown once.";
    INTRO_NOT_STORED = "· 복구 단어는 이 PC에 저장하지 않습니다. 적은 종이가 이 지갑의 유일한 백업입니다."
        / "· The recovery words are not stored on this PC. The paper you write them on is this wallet's only backup.";
    INTRO_CHECK = "· 단어 4개로 바르게 적었는지 확인한 뒤, YubiKey에 넣을 키를 고르고 가져옵니다."
        / "· After checking 4 words to see that you wrote them correctly, you choose the keys for the YubiKey and import them.";
    INTRO_BACKUP = "· 같은 단어로 백업 YubiKey를 바로 더 등록할 수 있습니다(마칠 때까지 메모리에만 있음)."
        / "· You can enrol backup YubiKeys with the same words right away (they stay only in memory until you finish).";
    INTRO_ADMIN_PIN = "· OpenPGP 관리자 PIN(새 카드는 12345678)이 필요합니다."
        / "· The OpenPGP admin PIN is needed (12345678 on a new card).";
    INTRO_TIME = "· 10분쯤 걸리고, 중간에 유휴 한도(기본 10분) 넘게 입력이 없으면 처음부터 다시 합니다."
        / "· It takes about 10 minutes; with no input for longer than the idle limit (10 minutes by default), you start over.";
    INTRO_WARN = "복구 단어를 아는 사람은 누구든 YubiKey 없이 자산을 옮길 수 있습니다. 사진·클라우드에 남기지 마세요."
        / "Anyone who knows the recovery words can move the assets without the YubiKey. Do not keep them in photos or the cloud.";
    BTN_START = "시작하기" / "Start";

    // ----- settings → YubiKey ------------------------------------------------------------------
    CARD_YK_ACCOUNTS = "YubiKey 계정" / "YubiKey accounts";
    BTN_ENROL = "YubiKey 등록" / "Enrol YubiKey";
    /// The connect flow's button and title.
    BTN_CONNECT = "YubiKey 연결하기 (복구 단어 없이)" / "Connect YubiKey (without recovery words)";
    UNLOCK_TO_USE = "잠금을 해제하면 쓸 수 있습니다." / "Available after unlocking.";
    FACTORY_BAND = "PIN: 공장 기본값 — 서명 안 됨" / "PIN: factory default — cannot sign";
    FIELD_SLOTS = "슬롯" / "Slots";
    /// `{0}` a count.
    COUNT(1) = "{0}개" / "{0}";
    BTN_PINS_CLOSE = "PIN 설정 닫기" / "Close PIN setup";
    BTN_PINS_CHANGE = "PIN 설정 / 기본값 변경 (PIN 안내)" / "Set PIN / change defaults (PIN guide)";
    BTN_RESLOT = "슬롯 구성 바꾸기" / "Change slot layout";
    DANGER = "위험한 작업" / "Dangerous actions";
    BTN_REMOVE_RECORD = "지갑에서 기록 지우기 (카드는 그대로)" / "Remove record from wallet (card unchanged)";
    BTN_ERASE_KEYS = "YubiKey의 키 지우기…" / "Erase keys on the YubiKey…";
    LAST_KEY = "이 지갑의 마지막 키라 기록을 지울 수 없습니다(지갑 초기화로만 가능)."
        / "This is the wallet's last key, so its record cannot be removed (only by resetting the wallet).";
    CARD_PER_ACCOUNT = "계정별 YubiKey" / "YubiKeys per account";
    /// `{0}` serial, `{1}` slot.
    HOLDER_BACKUP(2) = "#{0} {1}(백업)" / "#{0} {1} (backup)";

    // ----- wizard ------------------------------------------------------------------------------
    WIZARD_DONE = "YubiKey 등록이 끝났습니다." / "YubiKey enrolment has finished.";
    STEP_4_OF_5 = "4/5단계 · YubiKey에 넣기" / "Step 4/5 · Put on YubiKey";
    TITLE_NEW_WALLET_ENROL = "YubiKey 지갑 만들기 — YubiKey 등록" / "Create a YubiKey wallet — enrol YubiKey";
    RUNNING_IMPORT = "YubiKey에 키를 넣는 중입니다" / "Putting keys on the YubiKey";
    LABEL_KEY = "넣을 키" / "Key";
    GAP_LIMIT = "주소 인덱스가 20 이상이면 다른 지갑으로 복구할 때 gap limit을 늘려야 합니다."
        / "With an address index of 20 or more, other wallets need a larger gap limit to recover it.";
    FIXED_TOUCH = "'고정'을 고르면 관리자 PIN을 아는 프로그램도 터치를 끌 수 없지만, 나중에 바꾸려면 OpenPGP 초기화와 재등록이 필요합니다."
        / "With 'fixed', even a program that knows the admin PIN cannot turn the touch off, but changing it later needs an OpenPGP reset and a new enrolment.";
    CHECK_BACKUP = "백업 YubiKey 만들기 (같은 키 복사)" / "Make a backup YubiKey (copy the same keys)";
    BACKUP_HELP = "같은 키를 다른 YubiKey에도 넣어 예비용으로 씁니다. 이미 등록한 YubiKey의 슬롯 구성을 그대로 따릅니다. 다른 구성(예: 같은 EVM 키 + 새 Zcash 키)은 이 체크를 끄고 아래에서 슬롯을 직접 고르세요 — 다른 YubiKey에 이미 있는 키는 확인 화면에 표시만 하고 그대로 넣습니다."
        / "Puts the same keys on another YubiKey as a spare, following the slot layout of the enrolled YubiKey. For another layout (e.g. the same EVM key + a new Zcash key), untick this and choose the slots below — keys already on another YubiKey are only marked on the confirmation screen and put on as they are.";
    LABEL_COPY_FROM = "복사할 YubiKey" / "YubiKey to copy";
    /// `{0}` serial, `{1}` slot count.
    BACKUP_OPTION(2) = "#{0} (슬롯 {1}개)" / "#{0} ({1} slots)";
    SKIPPED_UNKNOWN(1) = "복구 단어 없이 연결한 키는 복사하지 않습니다: {0}"
        / "Keys connected without recovery words are not copied: {0}";
    BACKUP_SAME = "같은 슬롯·같은 경로·같은 정책으로 이 YubiKey에 넣습니다. 같은 복구 단어(+ passphrase)를 입력해야 합니다."
        / "They go onto this YubiKey with the same slots, paths and policies. Enter the same recovery words (+ passphrase).";
    WORDS_CHECKED = "복구 단어 확인을 마쳤습니다. 이제 YubiKey에 넣을 키를 고르세요. 첫 YubiKey를 가져오면 지갑이 만들어집니다."
        / "The recovery words are checked. Now choose the keys for the YubiKey. The wallet is created when the first YubiKey is imported.";
    /// `{0}` the Bitcoin network.
    FIRST_DEFAULTS(1) = "처음이면 기본 선택 그대로 다음을 눌러도 됩니다(SIG: EVM 계정 0 · AUT: {0} 네이티브 세그윗 주소 0 · PIV: Solana 계정 1개(인덱스 0부터) · 터치: 항상)."
        / "The first time, you can keep the default choices and press Next (SIG: EVM account 0 · AUT: {0} Native SegWit address 0 · PIV: 1 Solana account (from index 0) · Touch: always).";
    CARD_PIV_SOL = "PIV — Solana 계정" / "PIV — Solana accounts";
    LABEL_SOL_COUNT = "Solana 계정 수 (0–20)" / "Number of Solana accounts (0–20)";
    LABEL_FIRST_INDEX = "첫 계정 인덱스" / "First account index";
    PIV_HELP = "PIV 보관 슬롯 82부터 차례로 Solana 계정 m/44'/501'/i'/0'을 넣습니다. Solana를 쓰지 않으면 0으로 두세요."
        / "Solana accounts m/44'/501'/i'/0' go into the PIV retired slots from 82 on. If you do not use Solana, leave it at 0.";
    COMPUTING = "복구 단어에서 고른 키의 경로와 주소를 계산하고 있습니다(YubiKey와 통신하지 않음)."
        / "Computing the paths and addresses of the chosen keys from the recovery words (no YubiKey communication).";
    BTN_BACK_SLOTS = "← 슬롯 다시 고르기" / "← Choose slots again";
    SAME_ACK = "이해했습니다. 그래도 이 복구 단어로 등록합니다" / "I understand. Enrol with these recovery words anyway";
    CARD_CHECK_IMPORT = "가져오기 전에 확인하세요" / "Check before importing";
    CONFIRM_TEXT = "아래 경로와 주소는 입력한 복구 단어에서 이 PC가 계산한 값입니다(YubiKey와는 아직 통신하지 않았습니다). 쓰려는 주소와 전체가 같은지 확인하세요."
        / "The paths and addresses below were computed by this PC from the recovery words you entered (no YubiKey communication yet). Check that each address matches the one you intend to use in full.";
    RELATION_NEW = "새 키" / "New key";
    /// `{0}` backup copy / already elsewhere, `{1}` the cards.
    RELATION(2) = "{0} — 같은 경로를 가진 YubiKey: {1}" / "{0} — YubiKeys with the same path: {1}";
    RELATION_ALREADY = "이미 다른 YubiKey에 있음 (이 YubiKey에도 같은 키를 넣습니다)"
        / "Already on another YubiKey (the same key also goes on this YubiKey)";
    /// `{0}` serial, `{1}` firmware.
    CARD_LINE(2) = "YubiKey #{0} (펌웨어 {1}) — 이 YubiKey에만 씁니다."
        / "YubiKey #{0} (firmware {1}) — only this YubiKey is written.";
    READING_CARD = "연결한 YubiKey를 읽는 중…" / "Reading the connected YubiKey…";
    CONNECTED_CARD = "연결한 YubiKey" / "Connected YubiKey";
    READING_SLOTS = "고른 슬롯에 이미 있는 키를 읽는 중… (PIN 없이 읽기만)"
        / "Reading the keys already in the chosen slots… (read only, no PIN)";
    /// `{0}` why (a full sentence).
    SLOTS_UNREADABLE(1) = "고른 슬롯을 읽지 못했습니다: {0} 가져오기는 다른 키가 있으면 아무것도 쓰기 전에 멈춥니다."
        / "Could not read the chosen slots: {0} The import stops before writing anything if another key is there.";
    OCCUPANT_SECP = "secp256k1 키 (EVM · Bitcoin P2WPKH로 본 주소)" / "secp256k1 key (addresses as EVM · Bitcoin P2WPKH)";
    OCCUPANT_ED = "Ed25519 키 (Solana 주소)" / "Ed25519 key (Solana address)";
    OCCUPANT_UNKNOWN = "이 지갑이 읽지 못하는 키 (RSA 등 — GPG 키일 수 있음)"
        / "A key this wallet cannot read (RSA, … — may be a GPG key)";
    CARD_CREDENTIALS = "YubiKey 자격 정보" / "YubiKey credentials";
    CREDENTIALS_TEXT = "YubiKey를 하나만 연결하세요. PIN·관리 키는 이 작업에만 쓰고 바로 지웁니다(저장하지 않음)."
        / "Connect only one YubiKey. The PIN and management key are used for this task only and wiped right away (not stored).";
    CREDENTIALS_PW3 = "관리자 PIN(PW3)을 다음 창에서 입력합니다 (공장 기본값 12345678)."
        / "The admin PIN (PW3) is entered in the next window (factory default 12345678).";
    MANAGEMENT_PROTECTED = "관리 키: PIN으로 보호됨 — PIV PIN만 입력" / "Management key: PIN-protected — enter only the PIV PIN";
    MANAGEMENT_DEFAULT = "기본 관리 키 사용" / "Use the default management key";
    MANAGEMENT_CUSTOM = "관리 키 직접 입력 (16진수 48자리)" / "Enter the management key (48 hex digits)";
    MANAGEMENT_UNREAD = "연결한 YubiKey의 관리 키 설정을 아직 읽지 못했습니다. ykman으로 PIN 보호(--protect)를 해 둔 YubiKey라면 연결한 뒤 '← 이전' → '다음'으로 다시 읽으세요."
        / "The connected YubiKey's management key setting has not been read yet. If the YubiKey was PIN-protected with ykman (--protect), connect it and read again with '← Back' → 'Next'.";
    CARD_HOW = "어떻게 등록할까요?" / "How should it be enrolled?";
    BTN_IMPORT = "복구 단어에서 키를 넣기 (처음 등록)" / "Put keys from the recovery words (first enrolment)";
    BTN_ADOPT = "이미 넣은 키 연결하기 (가져오기 없이 등록)" / "Connect keys already on it (enrol without import)";
    BTN_BACK = "← 이전" / "← Back";
    /// `{0}` serial, `{1}` slot count.
    ADOPTED(2) = "YubiKey #{0}을(를) 가져오기 없이 등록했습니다 (카드에 쓰지 않음, 슬롯 {1}개)."
        / "YubiKey #{0} enrolled without import (nothing written to the card, {1} slots).";
    /// `{0}` serial, `{1}` slot count.
    IMPORTED(2) = "YubiKey #{0}에 키를 가져왔습니다 (슬롯 {1}개)." / "Keys imported to YubiKey #{0} ({1} slots).";
    CREATED_CONNECTED = "YubiKey 지갑을 만들었습니다. 복구 단어 없이 카드의 공개키로 연결했으므로 이 PC에는 개인키도 복구 단어도 없습니다 — 카드를 잃었을 때를 대비해 원래 백업(복구 단어 등)이 있는지 확인하세요."
        / "The YubiKey wallet was created. It was connected through the card's public keys without recovery words, so this PC has neither private keys nor recovery words — check that you have the original backup (recovery words, …) in case the card is lost.";
    CREATED = "YubiKey 지갑을 만들었습니다. 복구 단어는 이 PC에 저장하지 않았습니다 — 적은 종이를 안전하게 보관하세요. 백업 YubiKey를 지금 더 등록할 수 있습니다."
        / "The YubiKey wallet was created. The recovery words were not stored on this PC — keep the paper safe. You can enrol more backup YubiKeys now.";
    DETAILS_CLOSED = "슬롯·주소 자세히 ▸" / "Slot and address details ▸";
    DETAILS_OPEN = "슬롯·주소 자세히 ▾" / "Slot and address details ▾";
    REREAD = "YubiKey에서 다시 읽은 공개키와 그 주소입니다." / "The public keys read back from the YubiKey and their addresses.";
    BTN_RECHECK = "다시 확인" / "Check again";
    BTN_ANOTHER_CONNECT = "다른 YubiKey 연결" / "Connect another YubiKey";
    BTN_ANOTHER_ENROL = "다른 YubiKey 등록(백업)" / "Enrol another YubiKey (backup)";

    // ----- PIN card ----------------------------------------------------------------------------
    PIN_CARD_TITLE(1) = "기본값 변경 / PIN 설정 — YubiKey #{0}" / "Change defaults / set PIN — YubiKey #{0}";
    STEP_5_OF_5 = "5/5단계 · PIN 정하기" / "Step 5/5 · Choose PIN";
    /// `{0}` the secrets, `{1}` how they are changed.
    FACTORY_SEEN(2) = "공장 기본값: {0} — {1}" / "Factory defaults: {0} — {1}";
    FACTORY_SEPARATE = "아래 '공장값 — 바꿔야 함' 버튼으로 하나씩 바꿉니다."
        / "Change them one by one with the 'factory value — change it' buttons below.";
    FACTORY_UNIFIED = "아래 “PIN 설정하기” 한 번으로 모두 바꿉니다." / "One “Set PIN now” below changes them all.";
    LABEL_MODE = "방식" / "Mode";
    MODE_UNIFIED = "8자리 하나로 통일 (권장)" / "One 8-character PIN (recommended)";
    /// The separate mode (named by `secret_text::CARD_SET_PINS_SAME`).
    MODE_SEPARATE = "하나씩 따로" / "One at a time";
    FACTORY_MARK(1) = "{0} (공장값 — 바꿔야 함)" / "{0} (factory value — change it)";
    BTN_PROTECT_MANAGEMENT = "PIV 관리 키 자동 보호" / "Protect PIV management key";
    BTN_SET_PINS = "PIN 설정하기 (8자리 하나)" / "Set PIN now (one 8-character PIN)";
    PIN_GUIDE_CLOSED = "PIN 안내 ▸" / "PIN guide ▸";
    PIN_GUIDE_OPEN = "PIN 안내 ▾" / "PIN guide ▾";

    // ----- removal overlay ---------------------------------------------------------------------
    REMOVE_SELECTED = "선택한 YubiKey 기록을 지웁니다." / "Removes the selected YubiKey record.";
    REMOVE_TEXT(1) = "YubiKey #{0}의 기록을 이 지갑에서 지웁니다. YubiKey 안의 키는 지우지 않습니다. 계속하려면 비밀번호를 입력하세요."
        / "Removes the record of YubiKey #{0} from this wallet. The keys on the YubiKey are not erased. Enter your password to continue.";
    REMOVE_ACCOUNTS(1) = "YubiKey #{0}의 계정" / "Accounts of YubiKey #{0}";
    BACK_UNKNOWN = "이 지갑에서 서명 불가 — 카드를 'YubiKey 연결하기 (복구 단어 없이)'로 다시 연결하면 돌아옵니다(이 카드를 잃거나 키를 지우면 영구히 사라집니다)"
        / "Cannot sign in this wallet — it comes back if you connect the card again with 'Connect YubiKey (without recovery words)' (lost for good if this card is lost or its keys erased)";
    BACK_WORDS = "이 지갑에서 서명 불가 — 같은 복구 단어로 다시 등록하면 돌아옵니다"
        / "Cannot sign in this wallet — it comes back if you enrol again with the same recovery words";
    LOST_CARD = "잃어버린 YubiKey라면: 기록을 지워도 카드의 키는 그대로입니다 — 백업 YubiKey나 복구 단어로 새 카드를 등록해 자산을 옮기세요."
        / "If the YubiKey is lost: removing the record leaves the card's keys as they are — enrol a new card with a backup YubiKey or the recovery words and move the assets.";

    // ----- connect (spec/10 §7.6) --------------------------------------------------------------
    TITLE_NEW_WALLET_CONNECT = "YubiKey 지갑 만들기 — YubiKey 연결하기" / "Create a YubiKey wallet — connect YubiKey";
    CONNECT_RUNNING = "YubiKey를 다시 읽고 저장하는 중입니다" / "Reading the YubiKey again and saving";
    CONNECT_RUNNING_KEEP = "YubiKey를 빼지 마세요. 카드에는 아무것도 쓰지 않습니다."
        / "Do not remove the YubiKey. Nothing is written to the card.";
    SCANNING = "연결한 YubiKey를 읽는 중… (PIN 없음, 쓰기 없음)" / "Reading the connected YubiKey… (no PIN, no writes)";
    /// `{0}` serial, `{1}` firmware.
    SERIAL_FIRMWARE(2) = "#{0} (펌웨어 {1})" / "#{0} (firmware {1})";
    NO_READABLE_KEYS = "PIN 없이 읽을 수 있는 키(OpenPGP SIG·AUT의 secp256k1, PIV의 Ed25519)가 없습니다. 키가 든 YubiKey인지 확인하세요."
        / "There are no keys readable without a PIN (secp256k1 in OpenPGP SIG/AUT, Ed25519 in PIV). Check that the YubiKey holds keys.";
    LABEL_THIS_KEY = "이 키는" / "This key is";
    NETWORK_LINE(1) = "네트워크: {0}" / "Network: {0}";
    FORMAT_HELP = "같은 키라도 형식에 따라 주소가 다릅니다. 이전 지갑에서 쓰던 주소가 나오는 형식을 고르세요."
        / "The same key gives different addresses in different formats. Choose the format that shows the address you used in your previous wallet.";
    CHECK_BEFORE_SAVE(1) = "저장하기 전에 확인하세요 — YubiKey #{0}" / "Check before saving — YubiKey #{0}";
    CONNECT_CONFIRM_TEXT = "아래 주소는 YubiKey에서 읽은 공개키로 이 PC가 계산한 값입니다. 쓰려는 주소와 전체가 같은지 확인하세요."
        / "The addresses below were computed by this PC from the public keys read from the YubiKey. Check that each matches the address you intend to use in full.";
    SAME_KEY_HOLDERS(1) = "같은 키를 가진 YubiKey: {0} — 그 계정에 이 YubiKey를 더합니다"
        / "YubiKeys with the same key: {0} — this YubiKey is added to that account";
    PIN_OWNERSHIP = "PIN으로 소유 확인 (선택)" / "Check ownership with PIN (optional)";
    PIV_FACTORY = "이 YubiKey의 PIV PIN이 공장 기본값(123456)입니다. 연결한 뒤 'PIN 설정'으로 바꾸기 전에는 이 지갑이 서명하지 않습니다."
        / "This YubiKey's PIV PIN is the factory default (123456). This wallet does not sign until you change it with 'Set PIN' after connecting.";
    SIGN_HELP = "서명할 때는 지금처럼 YubiKey에 PIN을 입력하고 터치합니다(공장 기본 PIN으로는 서명하지 않음)."
        / "To sign, you enter the PIN and touch the YubiKey as before (it does not sign with a factory default PIN).";
    BTN_SAVE = "저장" / "Save";

    // ----- 슬롯 구성 바꾸기 (spec/10 §15.1) -----------------------------------------------------
    /// `{0}` slot, `{1}` title.
    LOST_LINE(2) = "{0} — {1} (복구 단어 없음)" / "{0} — {1} (no recovery words)";
    RESLOT_TITLE(1) = "슬롯 구성 바꾸기 — YubiKey #{0}" / "Change slot layout — YubiKey #{0}";
    RESLOT_RUNNING = "YubiKey에 새 키를 넣는 중입니다" / "Putting the new keys on the YubiKey";
    LABEL_CHAIN = "체인" / "Chain";
    CARD_CURRENT_SLOTS = "지금 이 YubiKey의 슬롯" / "Current slots of this YubiKey";
    RESLOT_ONLY_PGP = "OpenPGP 서명(SIG)·인증(AUT) 두 슬롯만 바꿉니다. PIV(Solana) 슬롯은 그대로입니다."
        / "Only the two OpenPGP slots, signature (SIG) and authentication (AUT), change. The PIV (Solana) slots stay.";
    RESLOT_UNKNOWN_CARD = "복구 단어 없이 연결한 YubiKey입니다. 바꾸면 SIG·AUT에 입력할 복구 단어의 키가 들어가고 이 YubiKey는 그 복구 단어의 카드가 됩니다. 지금 그 슬롯의 키는 다른 YubiKey에 없으면 영구히 사라집니다(다음 화면에서 확인)."
        / "This YubiKey was connected without recovery words. After the change, SIG and AUT hold keys of the recovery words you enter, and this YubiKey becomes a card of those recovery words. The keys now in those slots are lost for good unless another YubiKey holds them (checked on the next screen).";
    CARD_NEW_LAYOUT = "새 구성" / "New layout";
    LABEL_PRESET = "조합" / "Combination";
    STANDARD_PATHS = "표준 경로만 씁니다: EVM m/44'/60'/0'/0/i, Bitcoin m/{44|49|84}'/{0|1}'/0'/0/i, Zcash m/44'/{133|1}'/0'/0/i. 터치 정책은 슬롯의 지금 값을 그대로 씁니다."
        / "Only standard paths are used: EVM m/44'/60'/0'/0/i, Bitcoin m/{44|49|84}'/{0|1}'/0'/0/i, Zcash m/44'/{133|1}'/0'/0/i. The touch policy keeps the slot's current value.";
    ADVANCED = "고급: EVM 공유 키도 고를 수 있게 하기" / "Advanced: also offer the EVM shared key";
    COMPUTING_RESLOT = "복구 단어에서 새 키의 경로와 주소를 계산하고 있습니다(YubiKey와 통신하지 않음)."
        / "Computing the paths and addresses of the new keys from the recovery words (no YubiKey communication).";
    SAME_ACK_RESLOT = "이해했습니다. 그래도 이 복구 단어의 키를 넣습니다" / "I understand. Put the keys of these recovery words anyway";
    AFTER_CHANGE(1) = "바꾼 뒤 YubiKey #{0}" / "YubiKey #{0} after the change";
    RESLOT_CONFIRM_TEXT = "아래 경로와 주소는 입력한 복구 단어에서 이 PC가 계산한 값입니다(YubiKey와는 아직 통신하지 않았습니다)."
        / "The paths and addresses below were computed by this PC from the recovery words you entered (no YubiKey communication yet).";
    RELATION_UNCHANGED = "그대로 (지금과 같은 키)" / "Unchanged (the same key as now)";
    RELATION_PUT = "새로 넣음" / "Newly put";
    RELATION_PUT_BACKUP(1) = "새로 넣음 — 같은 키를 가진 YubiKey: {0} (백업 복사본)"
        / "Newly put — YubiKeys with the same key: {0} (backup copy)";
    CARD_DROPPED = "이 YubiKey에서 빠지는 계정" / "Accounts leaving this YubiKey";
    DROP_NOT_ELSEWHERE = "다른 YubiKey에 없음 — 바꾼 뒤에는 이 지갑에서 서명할 수 없습니다"
        / "Not on another YubiKey — after the change it cannot be signed in this wallet";
    DROP_LOST = "복구 단어 없음·다른 YubiKey에도 없음 — 바꾸면 이 키는 영구히 사라집니다"
        / "No recovery words and not on another YubiKey — the change loses this key for good";
    DROP_KEPT(1) = "{0}에 남아 있음 — 그 YubiKey로 계속 서명할 수 있습니다" / "Still on {0} — that YubiKey can keep signing";
    /// `{0}` the Zcash address.
    ZEC_UNUSABLE_CHANGE(1) = "Zcash 계정 {0} — 이 YubiKey의 이 슬롯에만 있는 키입니다. 바꾼 뒤에는 Zcash 탭에서 이 주소로 보낼 수 없습니다(잔액이 있으면 먼저 옮기세요)."
        / "Zcash account {0} — its key is only in this slot of this YubiKey. After the change, the Zcash tab cannot send from this address (if there is a balance, move it first).";
    /// `{0}` the Zcash address.
    ZEC_UNUSABLE_ERASE(1) = "Zcash 계정 {0} — 이 YubiKey의 이 슬롯에만 있는 키입니다. 지운 뒤에는 Zcash 탭에서 이 주소로 보낼 수 없습니다(잔액이 있으면 먼저 옮기세요)."
        / "Zcash account {0} — its key is only in this slot of this YubiKey. After erasing, the Zcash tab cannot send from this address (if there is a balance, move it first).";
    REMOVED_ACK = "이해했습니다: 빠지는 체인은 이 YubiKey로 서명할 수 없습니다"
        / "I understand: chains leaving this YubiKey can no longer be signed with it";
    ADMIN_NEXT = "다음 창에서 OpenPGP 관리자 PIN을 묻습니다(공장 기본값 12345678). 바뀌는 슬롯의 키는 덮어쓰고, 넣은 뒤 YubiKey에서 공개키를 다시 읽어 위 값과 비교합니다."
        / "The next window asks for the OpenPGP admin PIN (factory default 12345678). The keys of changed slots are overwritten, and after the import the public keys are read back from the YubiKey and compared with the values above.";
    RESLOT_DONE(1) = "YubiKey #{0}의 슬롯 구성을 바꿨습니다. YubiKey에서 다시 읽은 공개키가 복구 단어에서 만든 키와 같습니다."
        / "The slot layout of YubiKey #{0} was changed. The public keys read back from the YubiKey match the keys made from the recovery words.";
    CARD_APPLY_BACKUP = "백업 YubiKey에도 같은 구성 적용" / "Apply the same layout to backup YubiKeys";
    APPLY_HELP = "복구 단어는 이 작업을 마칠 때까지만 메모리에 있으므로 다시 묻지 않습니다. 그 YubiKey를 연결하고 고르세요."
        / "The recovery words stay in memory until this task ends, so they are not asked again. Connect that YubiKey and choose it.";
    /// `{0}` serial, `{1}` count.
    APPLY_TO_SHARED(2) = "#{0}에 같은 구성 적용 (백업: 같은 키 {1}개)" / "Apply the same layout to #{0} (backup: {1} same keys)";
    APPLY_TO(1) = "#{0}에 같은 구성 적용" / "Apply the same layout to #{0}";
    BTN_DONE_WIPE = "완료 (복구 단어 지우기)" / "Done (wipe recovery words)";

    // ----- YubiKey의 키 지우기 (spec/10 §15.2) --------------------------------------------------
    LABEL_METHOD = "방법" / "Method";
    RESET_IRREVERSIBLE = "되돌릴 수 없습니다: 초기화는 그 기능의 다른 키(GPG·PIV 인증서 등 이 지갑이 쓰지 않은 것 포함)도 모두 지우고 PIN을 공장 기본값으로 되돌립니다."
        / "This cannot be undone: a reset also erases every other key of that function (including GPG keys, PIV certificates and others this wallet did not use) and returns the PINs to the factory defaults.";
    CLEAR_TITLE(1) = "YubiKey의 키 지우기 — YubiKey #{0}" / "Erase keys on the YubiKey — YubiKey #{0}";
    CLEAR_RUNNING = "YubiKey의 키를 지우는 중입니다" / "Erasing keys on the YubiKey";
    DONT_REMOVE = "YubiKey를 빼지 마세요." / "Do not remove the YubiKey.";
    CARD_WHAT_TO_ERASE = "무엇을 지울까요?" / "What should be erased?";
    PGP_KEYS(1) = "OpenPGP 지갑 키 (SIG/AUT: EVM·Bitcoin·Zcash, {0}개)" / "OpenPGP wallet keys (SIG/AUT: EVM, Bitcoin, Zcash; {0})";
    PGP_OURS = "이 지갑의 키만 지우기 (권장)" / "Erase only this wallet's keys (recommended)";
    PGP_RESET = "OpenPGP 전체 초기화 — 다른 키도 지움" / "Reset all of OpenPGP — erases other keys too";
    PIV_SLOTS(1) = "PIV Solana 슬롯 ({0}개)" / "PIV Solana slots ({0})";
    PIV_OURS = "Solana 키만 지우기 (권장)" / "Erase only the Solana keys (recommended)";
    PIV_RESET = "PIV 전체 초기화 — 인증서 등 다른 키도 지움" / "Reset all of PIV — erases certificates and other keys too";
    /// `{0}` the firmware.
    PIV_DELETE_FIRMWARE(1) = "이 YubiKey의 등록 때 펌웨어는 {0}입니다. Yubico는 PIV 키 삭제를 5.7.4부터 문서화했습니다. 카드가 거부하면 'PIV 애플릿 초기화'를 쓰세요."
        / "This YubiKey's firmware at enrolment is {0}. Yubico documents PIV key deletion from 5.7.4. If the card refuses, use 'Reset all of PIV'.";
    HOW_CLOSED = "어떻게 지우나요 ▸" / "How is it erased? ▸";
    HOW_OPEN = "어떻게 지우나요 ▾" / "How is it erased? ▾";
    CARD_UNUSABLE = "이 YubiKey로 쓸 수 없게 되는 계정" / "Accounts this YubiKey will no longer sign for";
    CLEAR_LOST = "복구 단어 없음·다른 YubiKey에도 없음 — 지우면 이 키는 영구히 사라집니다"
        / "No recovery words and not on another YubiKey — erasing loses this key for good";
    CLEAR_NOT_ELSEWHERE = "다른 YubiKey에 없음 — 이 지갑의 계정 목록에서 빠집니다(같은 복구 단어로 다시 넣으면 돌아옵니다)"
        / "Not on another YubiKey — it leaves this wallet's account list (it comes back if the same recovery words are put on again)";
    CLEAR_KEPT(1) = "{0}에도 있음 — 그 YubiKey로 계속 서명할 수 있습니다" / "Also on {0} — that YubiKey can keep signing";
    NO_SLOT_LEFT = "이 YubiKey에 지갑 슬롯이 하나도 남지 않으므로 이 YubiKey 기록을 지갑에서 지웁니다."
        / "No wallet slot is left on this YubiKey, so its record is removed from the wallet.";
    LAST_KEY_CLEAR = "이 YubiKey가 이 지갑의 마지막 키입니다. 모두 지우면 지갑에 남는 키가 없으므로 지울 수 없습니다. 다른 YubiKey를 먼저 등록하세요."
        / "This YubiKey holds the wallet's last key. Erasing everything would leave the wallet without a key, so it cannot be erased. Enrol another YubiKey first.";
    RESET_NO_PIN = "초기화는 PIN을 묻지 않습니다(PIN을 일부러 잠근 뒤 초기화합니다)."
        / "A reset does not ask for a PIN (it locks the PIN on purpose, then resets).";
    /// `{0}` the secrets asked.
    ASKS(1) = "다음 창에서 {0}을(를) 묻습니다. 이 작업에만 쓰고 바로 지웁니다."
        / "The next window asks for the {0}. It is used for this task only and wiped right away.";
    BTN_ERASE_THIS = "이 YubiKey의 키 지우기" / "Erase this YubiKey's keys";
    /// `{0}` OpenPGP / PIV.
    RESULT_OURS(1) = "{0}: 이 지갑의 키를 지웠습니다." / "{0}: this wallet's keys were erased.";
    RESULT_RESET(1) = "{0}: 전체를 공장 상태로 초기화했습니다 (PIN도 기본값)." / "{0}: fully reset to factory state (PINs back to defaults).";
    /// `{0}` OpenPGP / PIV, `{1}` why.
    RESULT_FAILED(2) = "{0}: 실패 — {1}" / "{0}: failed — {1}";
    RESULT_SKIPPED(1) = "{0}: 앞 단계가 실패해 하지 않았습니다." / "{0}: not done because an earlier step failed.";
    RESULT_RECORD_REMOVED = "이 YubiKey에 지갑 슬롯이 남지 않아 기록을 지웠습니다."
        / "No wallet slot is left on this YubiKey, so its record was removed.";
    RESULT_SLOTS_REMOVED = "지운 슬롯을 이 지갑의 슬롯 표에서 뺐습니다." / "The erased slots were taken out of this wallet's slot table.";
    /// `{0}` the vault error.
    RESULT_VAULT_FAILED(1) = "YubiKey는 바뀌었지만 지갑의 슬롯 표를 고치지 못했습니다: {0}"
        / "The YubiKey changed, but the wallet's slot table could not be updated: {0}";
    RESULT_RESET_PINS = "초기화한 애플릿의 PIN은 공장 기본값입니다(OpenPGP 123456 / 12345678, PIV 123456 / 12345678). 다시 쓰려면 등록한 뒤 'PIN 설정'에서 바꾸세요."
        / "The PINs of a reset applet are the factory defaults (OpenPGP 123456 / 12345678, PIV 123456 / 12345678). To use it again, enrol it and change them in 'Set PIN'.";
}
