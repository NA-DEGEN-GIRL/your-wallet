//! Fixed texts of the `YubiKey` core (spec/10, spec/14): card errors, plan and enrolment
//! errors, slot and role labels, touch policies and the connect scan's reasons, in Korean and
//! English.

crate::texts! {
    // ----- card errors (`CardError`) -----------------------------------------------------------
    ERR_NO_SERVICE = "스마트 카드 서비스가 실행 중이 아닙니다." / "The smart card service is not running.";
    ERR_NO_CARD = "YubiKey를 찾을 수 없습니다. 연결한 뒤 다시 시도하세요."
        / "No YubiKey found. Connect it and try again.";
    ERR_BUSY = "다른 프로그램이 YubiKey를 쓰고 있습니다. 그 프로그램을 닫고 다시 시도하세요."
        / "Another program is using the YubiKey. Close that program and try again.";
    ERR_IO = "YubiKey와 통신하지 못했습니다. 다시 연결하고 시도하세요."
        / "Could not talk to the YubiKey. Reconnect it and try again.";
    ERR_APPLET_MISSING = "이 장치에는 필요한 기능(OpenPGP 또는 PIV)이 없습니다."
        / "This device lacks a function it needs (OpenPGP or PIV).";
    ERR_WRONG_PIN_LAST = "PIN이 틀렸습니다. 남은 시도 1회 — 한 번 더 틀리면 잠깁니다."
        / "Wrong PIN. 1 try left — one more wrong PIN locks it.";
    ERR_WRONG_PIN(1) = "PIN이 틀렸습니다. 남은 시도 {0}회." / "Wrong PIN. {0} tries left.";
    ERR_ADMIN_LAST_TRY = "OpenPGP 관리자 PIN 시도가 1회 남았습니다. 한 번 더 틀리면 잠깁니다(잠기면 'YubiKey의 키 지우기'의 OpenPGP 애플릿 초기화 뒤 다시 등록해야 합니다). 정확한 관리자 PIN이 확실하면 다시 입력해 제출하세요 — 그때는 마지막 시도로 카드에 보냅니다."
        / "1 OpenPGP admin PIN try is left. One more wrong PIN locks it (then you must reset the OpenPGP applet with 'Erase keys on the YubiKey' and enrol again). If you are sure of the admin PIN, enter it again and submit — it is then sent to the card as the last try.";
    ERR_MULTIPLE_CARDS = "YubiKey가 둘 이상 연결되어 있습니다. YubiKey를 하나만 연결하세요."
        / "More than one YubiKey is connected. Connect only one YubiKey.";
    ERR_DEFAULT_PIN = "공장 기본값(123456·12345678)은 새 PIN으로 쓸 수 없습니다 — YubiKey를 가진 사람이 그 값으로 바로 서명할 수 있습니다. 다른 값을 고르세요."
        / "A factory default (123456 or 12345678) cannot be a new PIN — anyone holding the YubiKey could sign with it right away. Choose another value.";
    ERR_NOT_BLOCKED = "애플릿 초기화를 멈췄습니다: PIN이 카드가 알려 준 횟수 안에 잠기지 않았습니다. 키는 지우지 않았습니다(PIN 남은 시도는 줄었을 수 있습니다). YubiKey를 다시 연결하고 한 번 더 시도하세요."
        / "The applet reset stopped: the PIN did not lock within the number of tries the card reported. No keys were erased (the PIN's remaining tries may have gone down). Reconnect the YubiKey and try once more.";
    ERR_PUK_LAST_TRY = "PIV PUK 시도가 1회 남았습니다. 한 번 더 틀리면 PUK가 잠기고, 그 뒤 PIV PIN까지 잠기면 PIV 초기화밖에 방법이 없습니다(복구 단어 없이 연결한 Solana 키는 그때 영구히 사라집니다). 정확한 PUK가 확실하면 다시 입력해 제출하세요 — 그때는 마지막 시도로 카드에 보냅니다."
        / "1 PIV PUK try is left. One more wrong PUK locks it, and if the PIV PIN then locks too, only a PIV reset is left (Solana keys connected without recovery words are then lost for good). If you are sure of the PUK, enter it again and submit — it is then sent to the card as the last try.";
    ERR_PIN_BLOCKED = "PIN이 잠겼습니다. PUK(또는 관리자 PIN)로 풀거나 복구 단어로 다시 등록하세요."
        / "The PIN is locked. Unlock it with the PUK (or the admin PIN), or enrol again with the recovery words.";
    ERR_REFUSED = "YubiKey가 작업을 거부했습니다. PIN 확인과 터치(시간 안에)를 다시 시도하세요."
        / "The YubiKey refused the operation. Try the PIN check and the touch (in time) again.";
    ERR_NOT_SUPPORTED = "이 YubiKey 펌웨어는 이 기능을 지원하지 않습니다."
        / "This YubiKey firmware does not support this function.";
    ERR_KDF = "OpenPGP PIN KDF가 켜진 YubiKey는 지원하지 않습니다(spec/10 §11)."
        / "A YubiKey with OpenPGP PIN KDF turned on is not supported (spec/10 §11).";
    ERR_KEY_MISMATCH = "YubiKey의 공개키가 기록과 다릅니다. 등록한 YubiKey인지 확인하세요."
        / "The YubiKey's public key differs from the record. Check that this is the enrolled YubiKey.";
    ERR_FOREIGN_KEY = "이 슬롯에는 지갑이 기록한 키가 아닌 다른 키가 있습니다. 다른 프로그램(GPG 등)이 넣은 키일 수 있어 이 애플릿에서는 아무것도 지우거나 덮어쓰지 않았습니다. 그 키가 필요 없다는 것이 확실하면 그 프로그램으로 지우거나 'YubiKey의 키 지우기'의 애플릿 초기화를 쓰세요."
        / "This slot holds a key other than the one the wallet recorded. Another program (GPG, …) may have put it there, so nothing in this applet was erased or overwritten. If you are sure that key is not needed, erase it with that program or use the applet reset in 'Erase keys on the YubiKey'.";
    ERR_WRONG_CARD = "이 YubiKey에는 이 계정의 키가 없습니다. 등록한 YubiKey를 연결하세요."
        / "This YubiKey does not hold this account's key. Connect the enrolled YubiKey.";
    ERR_BAD_SIGNATURE = "서명 검증 실패(YubiKey 응답 오류)" / "Signature check failed (YubiKey answer error)";
    ERR_PIN_FORMAT = "PIN 길이가 맞지 않습니다." / "The PIN length is wrong.";
    ERR_ED25519_IMPORT = "이 YubiKey 펌웨어(5.7.0–5.7.3)는 Ed25519 키 가져오기를 거부했습니다. Yubico는 5.7.4부터 지원한다고 안내합니다. Solana 슬롯 없이 등록하거나 5.7.4 이상의 YubiKey를 쓰세요."
        / "This YubiKey firmware (5.7.0–5.7.3) refused the Ed25519 key import. Yubico documents support from 5.7.4. Enrol without Solana slots or use a YubiKey with 5.7.4 or later.";
    ERR_MGMT_MISMATCH = "PIV 관리 키가 맞지 않습니다." / "The PIV management key is wrong.";
    ERR_MGMT_PROTECTED = "이 YubiKey의 PIV 관리 키는 PIN으로 보호되어 있습니다. PIV PIN을 입력해 다시 시도하세요."
        / "This YubiKey's PIV management key is protected by the PIN. Enter the PIV PIN and try again.";
    ERR_MGMT_UNKNOWN = "PIV 관리 키가 기본값도 PIN 보호도 아닙니다. 이 지갑의 'PIV 관리 키 자동 보호'가 중간에 멈췄다면 PIV PIN으로 그 작업을 다시 실행하면 복구됩니다. 직접 정한 키라면 'ykman piv access change-management-key --generate --protect'로 PIN 보호로 바꾼 뒤 다시 시도하세요."
        / "The PIV management key is neither the default nor PIN-protected. If this wallet's 'Protect PIV management key' stopped halfway, running it again with the PIV PIN repairs it. If you set the key yourself, switch it to PIN protection with 'ykman piv access change-management-key --generate --protect' and try again.";
    /// `{0}`: the status word (`6A80`, four hex digits).
    ERR_STATUS(1) = "YubiKey 작업 중 오류가 발생했습니다 (SW {0})." / "A YubiKey operation failed (SW {0}).";
    ERR_MALFORMED = "YubiKey 작업 중 오류가 발생했습니다 (응답 형식이 다름)."
        / "A YubiKey operation failed (unexpected answer format).";
    ERR_TOO_LARGE = "YubiKey 작업 중 오류가 발생했습니다 (명령이 너무 김)."
        / "A YubiKey operation failed (command too long).";
    ERR_INTERNAL = "YubiKey 작업 중 오류가 발생했습니다 (내부 오류)."
        / "A YubiKey operation failed (internal error).";

    // ----- plan and enrolment errors (`PlanError`, `EnrolError`) -------------------------------
    PLAN_SLOT_COUNT = "슬롯을 1개 이상 24개 이하로 고르세요." / "Choose between 1 and 24 slots.";
    PLAN_DUPLICATE_SLOT(1) = "{0} 슬롯을 두 번 골랐습니다." / "Slot {0} was chosen twice.";
    PLAN_DUPLICATE_PATH(1) = "{0}: 같은 경로의 키가 이 YubiKey의 다른 슬롯에 이미 있습니다."
        / "{0}: a key with the same path is already in another slot of this YubiKey.";
    PLAN_WRONG_APPLET(1) = "{0}: 이 슬롯에는 그 종류의 키를 넣을 수 없습니다(OpenPGP = secp256k1, PIV = Ed25519)."
        / "{0}: this kind of key cannot go into this slot (OpenPGP = secp256k1, PIV = Ed25519).";
    PLAN_UNSUPPORTED_ROLE(1) = "{0}: 지원하지 않는 키입니다(탭루트 불가, 인덱스 범위 확인)."
        / "{0}: unsupported key (no Taproot; check the index range).";
    PLAN_POLICY(1) = "{0}: 터치·PIN 정책이 맞지 않습니다." / "{0}: the touch/PIN policy does not fit.";
    PLAN_ALREADY_ENROLLED = "이 YubiKey는 이미 등록되어 있습니다. 다시 등록하려면 먼저 등록을 지우세요."
        / "This YubiKey is already enrolled. To enrol it again, remove its enrolment first.";
    PLAN_TOO_MANY_CARDS = "YubiKey는 최대 8개까지 등록할 수 있습니다." / "Up to 8 YubiKeys can be enrolled.";
    PLAN_NOT_A_COPY(1) = "{0}: '백업 복사본'으로 골랐지만 다른 YubiKey에 같은 키가 없습니다."
        / "{0}: chosen as 'Backup copy', but no other YubiKey holds the same key.";
    PLAN_DIFFERENT_MNEMONIC = "입력한 복구 단어가 이미 등록한 YubiKey의 복구 단어와 다릅니다."
        / "The recovery words you entered differ from those of the YubiKeys already enrolled.";
    ENROL_SERIAL_MISMATCH = "YubiKey 일련번호를 확인하지 못했습니다. 하나만 연결하세요."
        / "Could not confirm the YubiKey serial number. Connect only one.";

    // ----- slots, roles, policies --------------------------------------------------------------
    /// `{0}` the slot id (hex), `{1}` the retired slot number.
    SLOT_PIV_RETIRED(2) = "PIV {0} (보관 {1})" / "PIV {0} (retired {1})";
    SLOT_PGP_SIG = "OpenPGP 서명(SIG)" / "OpenPGP signature (SIG)";
    SLOT_PGP_AUT = "OpenPGP 인증(AUT)" / "OpenPGP authentication (AUT)";
    /// The path text of a key connected without recovery words (`T_UNKNOWN_PATH`).
    UNKNOWN_PATH = "경로를 알 수 없음" / "Path unknown";
    UNSUPPORTED_PATH = "(지원하지 않는 경로)" / "(unsupported path)";
    TITLE_EVM_CARD(1) = "EVM 계정 (카드 키 {0})" / "EVM account (card key {0})";
    /// `{0}` the script name, `{1}` the card key number.
    TITLE_BTC_CARD(2) = "Bitcoin {0} 주소 (카드 키 {1})" / "Bitcoin {0} address (card key {1})";
    TITLE_SOL_CARD(1) = "Solana 계정 (카드 키 {0})" / "Solana account (card key {0})";
    TITLE_ZEC_CARD(1) = "Zcash 일반(transparent) 주소 (카드 키 {0})"
        / "Zcash transparent address (card key {0})";
    TITLE_EVM(1) = "EVM 계정 {0}" / "EVM account {0}";
    /// `{0}` the account index, `{1}` the script name.
    TITLE_EVM_SHARED(2) = "EVM 계정 {0} + Bitcoin {1} (공유 키)" / "EVM account {0} + Bitcoin {1} (shared key)";
    /// `{0}` the script name, `{1}` the address index.
    TITLE_BTC(2) = "Bitcoin {0} 주소 {1}" / "Bitcoin {0} address {1}";
    TITLE_SOL(1) = "Solana 계정 {0}" / "Solana account {0}";
    TITLE_ZEC(1) = "Zcash 일반(transparent) 주소 {0}" / "Zcash transparent address {0}";
    SCRIPT_P2PKH = "레거시(P2PKH)" / "Legacy (P2PKH)";
    SCRIPT_P2SH_P2WPKH = "호환 세그윗(P2SH-P2WPKH)" / "Nested SegWit (P2SH-P2WPKH)";
    SCRIPT_P2WPKH = "네이티브 세그윗(P2WPKH)" / "Native SegWit (P2WPKH)";
    SCRIPT_P2TR = "탭루트(미지원)" / "Taproot (unsupported)";
    TOUCH_NEVER = "터치 없음" / "No touch";
    TOUCH_ALWAYS = "항상 터치" / "Always touch";
    TOUCH_CACHED = "터치 후 15초 유지" / "Touch, cached 15 s";
    TOUCH_ALWAYS_FIXED = "항상 터치(고정)" / "Always touch (fixed)";
    TOUCH_CACHED_FIXED = "터치 후 15초 유지(고정)" / "Touch, cached 15 s (fixed)";

    // ----- connect scan (spec/10 §7.6) ---------------------------------------------------------
    SCAN_RSA = "RSA 키 — 이 지갑은 쓸 수 없습니다" / "RSA key — this wallet cannot use it";
    SCAN_PGP_ED25519 = "OpenPGP Ed25519 키 — Solana는 PIV 슬롯의 Ed25519 키만 씁니다"
        / "OpenPGP Ed25519 key — Solana uses only Ed25519 keys in PIV slots";
    SCAN_OTHER_CURVE = "secp256k1이 아닌 곡선의 키 — 이 지갑은 쓸 수 없습니다"
        / "Key on a curve other than secp256k1 — this wallet cannot use it";
    SCAN_UNKNOWN_KEY = "이 지갑이 모르는 키 — 쓸 수 없습니다" / "Key unknown to this wallet — it cannot be used";
    SCAN_NO_PUBLIC = "공개키를 읽지 못했습니다 — 빈 슬롯일 수 있습니다"
        / "Could not read the public key — the slot may be empty";
    SCAN_NO_METADATA = "메타데이터를 읽지 못했습니다 — 이 지갑은 쓸 수 없습니다"
        / "Could not read the metadata — this wallet cannot use it";
    SCAN_NOT_ED25519 = "Ed25519가 아닌 키(P-256·RSA 등) — 이 지갑은 쓸 수 없습니다"
        / "Not an Ed25519 key (P-256, RSA, …) — this wallet cannot use it";
    SCAN_POLICY = "PIN 정책 '없음' 등 이 지갑이 쓰지 않는 정책의 키입니다"
        / "A key with a policy this wallet does not use (such as PIN policy 'never')";
    SCAN_BAD_PUBLIC = "올바르지 않은 공개키" / "Invalid public key";
    NOTE_APPLET_MISSING = "애플릿이 없습니다" / "No applet";
    NOTE_FIRMWARE = "펌웨어가 오래되어 쓸 수 없습니다" / "The firmware is too old to use";
    NOTE_KDF = "PIN KDF가 켜져 있어 이 지갑은 쓸 수 없습니다" / "PIN KDF is on, so this wallet cannot use it";
    NOTE_UNREADABLE = "읽지 못했습니다" / "Could not read it";
    NOTE_OPENPGP(1) = "OpenPGP(EVM·Bitcoin·Zcash 키): {0}" / "OpenPGP (EVM, Bitcoin, Zcash keys): {0}";
    NOTE_PIV(1) = "PIV(Solana 키): {0}" / "PIV (Solana keys): {0}";
}
