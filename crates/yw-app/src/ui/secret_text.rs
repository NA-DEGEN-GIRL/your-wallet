//! Fixed texts of the secret windows W01–W12 (spec/04 §4, spec/10 §7, §9; English spec/14).
//! The windows draw them in the app language (`Settings::language`) held by the form.

yw_core::texts! {
    // Window titles (spec/04 §4.1).
    TITLE_SET_PASSWORD = "비밀번호 정하기" / "Set a password";
    UNLOCK = "잠금 해제" / "Unlock";
    TITLE_CONFIRM_PASSWORD = "비밀번호 확인" / "Confirm password";
    TITLE_CHANGE_PASSWORD = "비밀번호 변경" / "Change password";
    TITLE_MNEMONIC = "복구 단어 입력" / "Enter recovery words";
    TITLE_PASSPHRASE = "passphrase 입력" / "Enter passphrase";
    TITLE_PRIVATE_KEY = "개인키 가져오기" / "Import private key";
    TITLE_SHOW_MNEMONIC = "복구 단어 (니모닉)" / "Recovery words (mnemonic)";
    TITLE_SHOW_KEY = "개인키 보기" / "View private key";
    TITLE_BACKUP = "백업 확인" / "Backup check";
    TITLE_ADMIN_PIN = "YubiKey 관리자 PIN" / "YubiKey admin PIN";
    TITLE_MANAGEMENT_KEY = "YubiKey PIV 관리 키" / "YubiKey PIV management key";
    TITLE_SET_PINS = "YubiKey PIN 하나로 통일" / "Use one PIN for the YubiKey";
    TITLE_USER_PIN = "YubiKey PIN 확인 (선택)" / "Check YubiKey PIN (optional)";
    // W12 PIN change titles (`PinTarget::change_title`).
    TITLE_CHANGE_OPENPGP_PIN = "OpenPGP PIN 바꾸기" / "Change OpenPGP PIN";
    TITLE_CHANGE_ADMIN_PIN = "OpenPGP 관리자 PIN 바꾸기" / "Change OpenPGP admin PIN";
    TITLE_CHANGE_PIV_PIN = "PIV PIN 바꾸기" / "Change PIV PIN";
    TITLE_CHANGE_PIV_PUK = "PIV PUK 바꾸기" / "Change PIV PUK";
    /// The `OpenPGP` admin PIN in labels and sentences (`PinTarget::OpenPgpAdmin`).
    NAME_OPENPGP_ADMIN = "OpenPGP 관리자 PIN" / "OpenPGP admin PIN";
    /// A PIN target's length rule: bounds and factory value.
    PIN_RULE(3) = "영문·숫자·기호(ASCII) {0}–{1}자입니다(공장 기본값 {2})."
        / "Letters, digits and symbols (ASCII), {0}–{1} characters (factory default {2}).";

    // Field labels.
    LABEL_PASSWORD = "비밀번호" / "Password";
    LABEL_PASSWORD_AGAIN = "비밀번호 확인" / "Confirm password";
    LABEL_CURRENT_PASSWORD = "현재 비밀번호" / "Current password";
    LABEL_NEW_PASSWORD = "새 비밀번호" / "New password";
    LABEL_NEW_PASSWORD_AGAIN = "새 비밀번호 확인" / "Confirm new password";
    LABEL_WORDS = "복구 단어" / "Recovery words";
    LABEL_PASSPHRASE_AGAIN = "passphrase 확인" / "Confirm passphrase";
    LABEL_EVM_KEY = "개인키 (16진수 64자리)" / "Private key (64 hex digits)";
    LABEL_SOL_KEY = "Solana 개인키 (base58 keypair 또는 JSON 배열)"
        / "Solana private key (base58 keypair or JSON array)";
    LABEL_BTC_KEY = "Bitcoin 개인키 (WIF)" / "Bitcoin private key (WIF)";
    LABEL_ZEC_KEY = "Zcash 개인키 (압축 WIF 또는 16진수 64자리)"
        / "Zcash private key (compressed WIF or 64 hex digits)";
    LABEL_MANAGEMENT_KEY = "PIV 관리 키 (16진수 48자리)" / "PIV management key (48 hex digits)";
    LABEL_CURRENT(1) = "현재 {0}" / "Current {0}";
    LABEL_NEW(1) = "새 {0}" / "New {0}";
    LABEL_NEW_AGAIN(1) = "새 {0} 확인" / "Confirm new {0}";
    LABEL_SET_PINS_CURRENT = "현재 PIN (공장 기본값이면 비워 두기)"
        / "Current PIN (leave empty if factory default)";
    LABEL_SET_PINS_NEW = "새 PIN (8자)" / "New PIN (8 characters)";
    LABEL_SET_PINS_AGAIN = "새 PIN 확인" / "Confirm new PIN";
    LABEL_WORD(1) = "{0}번째 단어" / "Word {0}";

    // Intro lines.
    PASSWORD_RULE = "비밀번호는 영문·숫자·기호(ASCII) 12–128자입니다. 단어 4개 이상을 이은 긴 문장을 권장합니다. 잊으면 복구 단어(니모닉)로만 복구할 수 있습니다."
        / "The password is 12–128 letters, digits and symbols (ASCII). A long phrase of four or more words is recommended. If you forget it, you can recover only with the recovery words (mnemonic).";
    CHANGE_PASSWORD_NOTE = "비밀번호를 바꾸면 암호화 키도 새로 만들어, 바꾼 뒤의 내용은 예전 사본으로 열 수 없습니다. 바꾸기 전에 만든 지갑 파일 사본(백업한 vault.ywv 등)은 예전 비밀번호로 계속 열리고 그때의 내용이 드러납니다(예전 비밀번호가 약했다면 나중에 오프라인으로 풀릴 수 있습니다)."
        / "Changing the password also makes a new encryption key, so what is stored after the change cannot be opened with older copies. Copies of the wallet file made before the change (such as a backed-up vault.ywv) still open with the old password and reveal what they held then (if the old password was weak, it may be cracked offline later).";
    UNLOCK_INTRO = "지갑을 열려면 비밀번호를 입력하세요." / "Enter your password to open the wallet.";
    CONFIRM_INTRO = "계속하려면 비밀번호를 다시 입력하세요." / "Enter your password again to continue.";
    MNEMONIC_INTRO = "다른 지갑에서 쓰던 영어 복구 단어(BIP39 니모닉) 12·15·18·21·24개를 순서대로 입력하세요. 공백 또는 Tab으로 다음 칸으로 넘어갑니다. 목록에 없는 단어는 빨간색으로 표시합니다."
        / "Enter the 12, 15, 18, 21 or 24 English recovery words (BIP39 mnemonic) you used in another wallet, in order. Space or Tab moves to the next box. Words that are not in the list are shown in red.";
    PASSPHRASE_CONFIRM_INTRO = "이전 지갑에서 쓰던 BIP39 passphrase를 두 번 입력하세요. ASCII만 지원합니다."
        / "Enter the BIP39 passphrase you used in your previous wallet twice. Only ASCII is supported.";
    PASSPHRASE_INTRO = "이 지갑의 BIP39 passphrase를 입력하세요." / "Enter this wallet's BIP39 passphrase.";
    EVM_KEY_INPUT = "가져올 EVM 개인키(16진수 64자리, 0x 선택)를 입력하세요."
        / "Enter the EVM private key to import (64 hex digits, 0x optional).";
    /// W07 help of a Solana key (spec/04 §2.18).
    SOL_KEY_INPUT = "Phantom·Solflare의 '개인키 내보내기'로 받은 base58 문자열(64바이트 keypair) 또는 solana-keygen JSON 파일의 내용([숫자 64개])을 붙여넣으세요. 주소(32바이트)는 개인키가 아닙니다."
        / "Paste the base58 string (64-byte keypair) from 'Export private key' in Phantom or Solflare, or the content of a solana-keygen JSON file ([64 numbers]). An address (32 bytes) is not a private key.";
    /// W07 help of a Zcash key (spec/12 §2.3).
    ZEC_KEY_INPUT = "Zcash 개인키를 붙여넣으세요: 압축 WIF(K·L로 시작하면 mainnet, c로 시작하면 testnet — Zcash 탭의 네트워크와 같아야 함) 또는 16진수 64자리(지금 Zcash 탭의 네트워크로 씀). 일반(transparent) 주소 하나로 씁니다."
        / "Paste a Zcash private key: compressed WIF (starting with K or L is mainnet, with c is testnet — it must match the network of the Zcash tab) or 64 hex digits (used on the current network of the Zcash tab). It is used as one transparent address.";
    /// W07 help of a Bitcoin key (spec/04 §2.18).
    BTC_KEY_INPUT = "WIF 형식 개인키(5·K·L로 시작하면 mainnet, 9·c로 시작하면 testnet4)를 붙여넣으세요. 주소 형식은 앞 화면에서 고른 것으로 만듭니다."
        / "Paste a private key in WIF format (starting with 5, K or L is mainnet, with 9 or c is testnet4). The address type is the one you chose on the previous screen.";
    /// T-IMPORTED-KEY (W07, spec/04 §2.16): imported keys are not covered by the recovery words.
    IMPORTED_KEY_BACKUP = "주의: 가져온 개인키는 이 지갑의 복구 단어(24단어)로 복구되지 않습니다. 이 PC나 지갑 파일을 잃으면 이 계정은 원래 개인키로만 되살릴 수 있으니, 원래 개인키를 따로 안전하게 보관하세요."
        / "Caution: imported private keys are not recovered by this wallet's recovery words (24 words). If you lose this PC or the wallet file, this account can be restored only with the original private key, so keep the original private key safe separately.";
    /// T-KEY-ONLY (W07 of a wallet without recovery words, spec/04 §2.16).
    KEY_ONLY_BACKUP = "주의: 이 지갑에는 복구 단어가 없습니다. 이 계정의 백업은 지금 입력하는 원래 개인키뿐입니다. 이 PC나 지갑 파일을 잃으면 원래 개인키로만 되살릴 수 있으니, 원래 개인키를 종이 등 안전한 곳에 따로 보관하세요."
        / "Caution: this wallet has no recovery words. The only backup of this account is the original private key you are entering now. If you lose this PC or the wallet file, it can be restored only with the original private key, so keep the original private key separately in a safe place, such as on paper.";
    /// W08: `{0}` the word count, `{1}` [`WITH_ADDRESS`] or empty.
    SHOW_WORDS(2) = "아래 {0}단어{1}를 순서대로 종이에 적으세요. 이 단어들이 지갑의 유일한 백업이며, 아는 사람은 누구든 자산을 옮길 수 있습니다. 이 창은 화면 캡처에서 제외됩니다."
        / "Write the {0} words below{1} on paper, in order. These words are the wallet's only backup, and anyone who knows them can move your assets. This window is excluded from screen capture.";
    WITH_ADDRESS = "와 첫 주소" / " and the first address";
    SHOW_KEY_INTRO = "개인키입니다. 다른 사람에게 보여주거나 사진·클라우드에 남기지 마세요. 이 창은 화면 캡처에서 제외됩니다."
        / "This is a private key. Do not show it to anyone or leave it in photos or the cloud. This window is excluded from screen capture.";
    BACKUP_INTRO(4) = "적은 종이를 보고 {0}, {1}, {2}, {3}번째 단어를 입력하세요."
        / "Looking at your paper, enter words {0}, {1}, {2} and {3}.";
    /// W12 PIN change: `{0}` the secret's name, `{1}` its [`PIN_RULE`].
    CHANGE_PIN_INTRO(2) = "YubiKey를 하나만 연결하고 현재 {0}과(와) 새 {0}을(를) 입력하세요. {1} 이 지갑은 PIN을 저장하지 않으니 새 {0}을(를) 따로 기억해 두세요."
        / "Connect only one YubiKey and enter the current {0} and the new {0}. {1} This wallet does not store PINs, so remember the new {0} yourself.";

    // YubiKey (spec/10 §7.3, §7.6, §9).
    /// W11 (spec/10 §9.2): the card step after approval, after its three steps
    /// ([`CARD_PIN_STEPS`]).
    CARD_PIN = "PIN은 이 서명 한 번에만 쓰고 바로 지웁니다."
        / "The PIN is used for this one signature only and wiped right away.";
    /// W11's steps (2026-11-10): `{0}` is `YubiKey` or `YubiKey #serial`.
    CARD_PIN_STEPS(1) = "1. {0} 연결 → 2. PIN 입력 후 확인 → 3. 깜박이면 15초 안에 터치 (승인 뒤 120초 안에)"
        / "1. Connect {0} → 2. Enter the PIN and confirm → 3. When it blinks, touch it within 15 s (within 120 s of approval)";
    CARD_TOUCHES_PER_TX(1) = "YubiKey 터치 {0}회가 필요합니다 (거래마다 한 번, 15초 유지 정책이면 첫 터치 뒤 15초 안의 거래는 터치 없이 서명됩니다)."
        / "{0} YubiKey touches are needed (one per transaction; with the 15 s cached-touch policy, transactions within 15 s of the first touch are signed without a touch).";
    CARD_TOUCHES_PER_INPUT(1) = "YubiKey 터치 {0}회가 필요합니다 (입력마다 한 번, 15초 유지 정책이면 첫 터치 뒤 15초 안의 입력은 터치 없이 서명됩니다)."
        / "{0} YubiKey touches are needed (one per input; with the 15 s cached-touch policy, inputs within 15 s of the first touch are signed without a touch).";
    /// W12 admin PIN (spec/10 §7.3).
    CARD_ADMIN_PIN = "YubiKey를 하나만 연결하고 OpenPGP 관리자 PIN(PW3, 8–127자, 공장 기본값 12345678)을 입력하세요. 키를 가져오는 동안 한 번만 쓰고 바로 지웁니다."
        / "Connect only one YubiKey and enter the OpenPGP admin PIN (PW3, 8–127 characters, factory default 12345678). It is used once while the keys are imported and wiped right away.";
    /// W12 management key (spec/10 §7.3).
    CARD_MANAGEMENT_KEY = "YubiKey의 PIV 관리 키를 16진수 48자리로 입력하세요(ykman이 보여주는 형식). 이 지갑은 관리 키를 저장하지 않으며, 이번 작업에만 쓰고 바로 지웁니다."
        / "Enter the YubiKey's PIV management key as 48 hex digits (the format ykman shows). This wallet does not store the management key; it is used for this task only and wiped right away.";
    /// W12 of the optional ownership check of "`YubiKey` 연결하기" (spec/10 §7.6).
    CARD_USER_PIN = "선택 사항입니다: 이 YubiKey의 PIN을 한 번 확인해 카드가 내 것인지 봅니다(VERIFY 한 번 — 서명·터치·쓰기 없음). 틀리면 남은 시도가 하나 줄어듭니다. 공장 기본 PIN(123456)은 보내지 않습니다. 확인하지 않아도 연결할 수 있고, 서명할 때는 언제나 PIN과 터치가 필요합니다."
        / "Optional: checks this YubiKey's PIN once to see that the card is yours (one VERIFY — no signature, touch or write). A wrong PIN takes one try off the remaining tries. The factory default PIN (123456) is not sent. You can connect without checking, and signing always needs the PIN and a touch.";
    /// W12 PIV PIN (spec/10 §7.3, §9.3).
    CARD_PIV_PIN = "YubiKey를 하나만 연결하고 PIV PIN(6–8자, 공장 기본값 123456)을 입력하세요. PIN으로 보호된 PIV 관리 키를 꺼내는 데 한 번만 쓰고 바로 지웁니다."
        / "Connect only one YubiKey and enter the PIV PIN (6–8 characters, factory default 123456). It is used once to unlock the PIN-protected PIV management key and wiped right away.";
    /// W12 "PIN 하나로 통일" (spec/10 §9.3).
    CARD_SET_PINS = "YubiKey를 하나만 연결하세요. 새 8자 PIN 하나를 OpenPGP PIN·OpenPGP 관리자 PIN·PIV PIN·PIV PUK에 똑같이 넣고, PIV 관리 키는 자동으로 새로 만들어 PIN으로 보호합니다. 현재 값이 공장 기본값이면 '현재 PIN'을 비워 두고, 전에 하나로 통일했다면 그 8자를 넣으세요. 공장 기본값(12345678)은 새 PIN으로 쓸 수 없습니다. 중간에 실패하면 거기서 멈추고 바뀐 것만 알려 드립니다."
        / "Connect only one YubiKey. One new 8-character PIN is set as the OpenPGP PIN, OpenPGP admin PIN, PIV PIN and PIV PUK alike, and a new PIV management key is made automatically and protected by the PIN. If the current values are the factory defaults, leave 'Current PIN' empty; if you unified them before, enter those 8 characters. The factory default (12345678) cannot be the new PIN. If a step fails, it stops there and tells you only what changed.";
    /// The unified W12's warning (2026-11-10): one current value is sent to all four secrets.
    CARD_SET_PINS_SAME = "지금 네 값이 모두 같을 때만(공장값이거나 전에 통일한 값) 쓰세요. 다르면 “하나씩 따로”를 쓰세요. 틀린 현재 값은 그 PIN의 남은 시도를 1회 줄입니다."
        / "Use this only when all four values are the same now (factory values or values you unified before). If they differ, use “One at a time”. A wrong current value takes one try off that PIN's remaining tries.";
    /// W12: a new PIN / PUK / admin PIN that is a factory value (spec/10 §9.3).
    CARD_NEW_FACTORY = "공장 기본값(123456·12345678)은 새 PIN으로 쓸 수 없습니다 — YubiKey를 가진 사람이 그 값으로 바로 서명할 수 있습니다. 다른 값을 고르세요."
        / "A factory default (123456 or 12345678) cannot be a new PIN — anyone holding the YubiKey could sign with it right away. Choose another value.";

    // W01/W04 status line (2026-11-12).
    PW_RULE_OK = "✓ 12–128자" / "✓ 12–128 characters";
    PW_RULE_SHORT = "✗ 12자 이상 필요" / "✗ At least 12 characters needed";
    PW_RULE_EMPTY = "· 12–128자" / "· 12–128 characters";
    PW_SAME = "✓ 두 칸이 같음" / "✓ Both fields match";
    PW_DIFFERENT = "✗ 두 칸이 다름" / "✗ The two fields differ";
    PW_AGAIN = "· 확인 칸에 한 번 더 입력" / "· Enter it once more in the confirm field";

    // Validation errors.
    ERR_CARD_PIN(2) = "PIN은 영문·숫자·기호(ASCII) {0}–{1}자입니다."
        / "The PIN is {0}–{1} letters, digits and symbols (ASCII).";
    ERR_ADMIN_PIN = "관리자 PIN은 영문·숫자·기호(ASCII) 8–127자입니다."
        / "The admin PIN is 8–127 letters, digits and symbols (ASCII).";
    ERR_MANAGEMENT_KEY = "관리 키는 16진수(0–9, a–f) 48자리입니다."
        / "The management key is 48 hex digits (0–9, a–f).";
    ERR_PIV_PIN = "PIV PIN은 영문·숫자·기호(ASCII) 6–8자입니다."
        / "The PIV PIN is 6–8 letters, digits and symbols (ASCII).";
    ERR_OPENPGP_PIN = "OpenPGP PIN은 영문·숫자·기호(ASCII) 6–127자입니다."
        / "The OpenPGP PIN is 6–127 letters, digits and symbols (ASCII).";
    ERR_SET_PINS_CURRENT = "현재 PIN은 비워 두거나(공장 기본값) 전에 통일한 8자를 넣으세요."
        / "Leave the current PIN empty (factory defaults) or enter the 8 characters you unified before.";
    ERR_SET_PINS_NEW = "새 PIN은 영문·숫자·기호(ASCII) 정확히 8자입니다."
        / "The new PIN is exactly 8 letters, digits and symbols (ASCII).";
    ERR_SET_PINS_DIFFER = "새 PIN 두 칸이 서로 다릅니다." / "The two new PIN fields differ.";
    ERR_SET_PINS_SAME = "새 PIN이 현재 값과 같습니다." / "The new PIN is the same as the current value.";
    ERR_NEW_DIFFER(1) = "새 {0} 두 칸이 서로 다릅니다." / "The two new {0} fields differ.";
    ERR_NEW_SAME(1) = "새 {0}이(가) 현재 값과 같습니다." / "The new {0} is the same as the current value.";

    // Form content.
    PASSPHRASE_CHECKBOX = "BIP39 passphrase 사용" / "Use a BIP39 passphrase";
    PASSPHRASE_NOTE = "이전 지갑에서 BIP39 passphrase(25번째 단어)를 썼을 때만 켜세요. ASCII만 지원합니다."
        / "Turn this on only if you used a BIP39 passphrase (25th word) in your previous wallet. Only ASCII is supported.";
    UNLISTED_WORD(1) = "{0}번째 칸의 단어가 BIP39 단어 목록에 없습니다. 오타인지, 종이의 철자를 다시 보세요."
        / "Word {0} is not in the BIP39 word list. Check for a typo, and check the spelling on your paper again.";
    /// W08 countdown: minutes, seconds (two digits).
    COUNTDOWN(2) = "{0}:{1} 남음 — 지나면 창이 닫힙니다" / "{0}:{1} left — then the window closes";
    CHECKING = "확인 중…" / "Checking…";
    /// T-CAPTURE-WARN (spec/04 §4.5).
    CAPTURE_WARN = "화면 캡처 제외가 적용되지 않았습니다. 화면 공유·녹화 중이면 입력하지 마세요."
        / "This window is not excluded from screen capture. Do not type while sharing or recording the screen.";
    /// T-MASKED (spec/04 §4.9).
    MASKED = "창이 비활성화되어 내용을 가렸습니다. 창을 클릭하면 다시 표시합니다."
        / "The window is inactive, so its content is hidden. Click the window to show it again.";
    FIRST_ADDRESS = "첫 주소 (계정 1) — 함께 적어 두면 복구할 때 맞는지 확인할 수 있습니다"
        / "First address (account 1) — write it down too, so you can check it when you recover";
    PASSPHRASE_REVEAL_NOTE = "이 지갑은 passphrase를 사용합니다. passphrase는 저장되지 않으므로 따로 보관해야 합니다."
        / "This wallet uses a passphrase. The passphrase is not stored, so you must keep it separately.";
    /// W05 counter: words, characters, limit.
    WORDS_TYPED(3) = "{0}단어 입력 · {1}/{2}" / "{0} words entered · {1}/{2}";
    WORD_LISTED = "목록에 있음" / "In the list";
    WORD_UNLISTED = "목록에 없는 단어" / "Not in the list";
    REVEAL = "보기" / "Show";
    /// The step indicator: flow, current step, step count.
    STEPS(3) = "{0} · {1}/{2}단계" / "{0} · step {1}/{2}";

    // Buttons.
    /// W08 hold in progress: seconds left (one decimal).
    HOLD_PROGRESS(1) = "다 적었습니다 ({0}초)" / "I have written them down ({0} s)";
    HOLD = "다 적었습니다 (2초 길게 누르기)" / "I have written them down (hold 2 s)";
    CLOSE = "닫기" / "Close";
    CHANGE = "변경" / "Change";
    NEXT = "다음" / "Next";
    IMPORT = "가져오기" / "Import";
    OK = "확인" / "OK";
    LATER = "나중에" / "Later";
    CANCEL = "취소" / "Cancel";
    CLEAR_ALL = "모두 지우기" / "Clear all";
    COPY = "복사" / "Copy";
}
