//! The texts of the S15 `rpc.json에서 가져오기` card and its confirmation (spec/04 §2.11), which
//! the network section draws ([`super::core`]).
//!
//! 2026-11-24 (spec/15 §11.4 S5-5, S5 plan critic C7): moved here unchanged from yw-app
//! `app_rpc_import::text` with the builders; the file's read, parse and delete stay the
//! shell's (`app_rpc_import`), the plan the wallet's (`crate::wallet::app_rpc_plan`).

/// The S15 `rpc.json에서 가져오기` texts (spec/04 §2.11).
pub mod text {
    yw_core::texts! {
        /// The card's note on the source file (before an import).
        JSON_PLAINTEXT = "이 파일에는 RPC 주소와 그 토큰이 암호화되지 않은 채 들어 있어, 이 Windows 사용자로 도는 다른 프로그램도 읽을 수 있습니다. 가져온 뒤 개발 스크립트에 더 쓰지 않으면 지우세요."
            / "This file holds RPC addresses and their tokens unencrypted, so other programs running as this Windows user can read it. After importing, delete it unless development scripts still need it.";
        /// The card's warning right after an import.
        JSON_LEFT = "가져오기를 마쳤습니다. 앱에는 암호화해 저장했지만 rpc.json에는 같은 주소·토큰이 암호화되지 않은 채 남아 있습니다. 개발 스크립트(probe-rpc 등)에 더 쓰지 않으면 지우세요."
            / "Import finished. The app saved them encrypted, but rpc.json still holds the same addresses and tokens unencrypted. Delete it unless development scripts (probe-rpc and others) still need it.";
        /// The delete confirmation.
        JSON_DELETE_CONFIRM = "rpc.json을 지웁니다. 휴지통으로 가지 않아 되돌릴 수 없습니다. 앱에 저장한 RPC 주소는 그대로이고, 개발 스크립트가 이 파일을 쓴다면 scripts\\dev-rpc-setup.ps1로 다시 만들어야 합니다."
            / "rpc.json will be deleted. It does not go to the Recycle Bin, so this cannot be undone. The RPC addresses saved in the app stay; if development scripts use this file, recreate it with scripts\\dev-rpc-setup.ps1.";
        CARD_TITLE = "rpc.json에서 가져오기" / "Import from rpc.json";
        CARD_HELP = "개발용 설정 파일(%USERPROFILE%\\.yw-dev\\rpc.json)에 있는 RPC 주소를 읽어 위 '네트워크별 RPC 주소' 목록에 넣습니다. 저장하기 전에 가린 목록으로 한 번 더 확인합니다."
            / "Reads the RPC addresses in the development settings file (%USERPROFILE%\\.yw-dev\\rpc.json) into the 'RPC address per network' list above. A masked list is shown for one more check before saving.";
        DELETE = "지우기" / "Delete";
        CANCEL = "취소" / "Cancel";
        IMPORT_BUTTON = "rpc.json에서 가져오기" / "Import from rpc.json";
        DELETE_FILE = "rpc.json 지우기…" / "Delete rpc.json…";
        CONFIRM_TITLE = "rpc.json에서 가져오기 — 확인" / "Import from rpc.json — confirm";
        CONFIRM_LEAD = "다음 RPC 주소를 가져옵니다(주소에는 토큰이 있어 가린 형태로만 보입니다):"
            / "These RPC addresses will be imported (they contain tokens, so they are shown masked only):";
        HAS_ADDRESS = " — 기존 주소 있음" / " — has an address already";
        OFF_TEMPLATE = " — 템플릿과 다른 주소(이 네트워크에 그대로 저장)"
            / " — differs from the template (saved as is for this network)";
        SAME_ENDPOINT = "모든 주소가 같은 QuickNode 엔드포인트(이름·토큰)입니다. RPC 공급자를 'QuickNode 멀티체인'으로 바꾸고 이름·토큰을 템플릿 자격 정보로 함께 저장합니다."
            / "All addresses use the same QuickNode endpoint (name and token). The RPC provider is changed to 'QuickNode multichain' and the name and token are saved as the template credentials too.";
        EXISTING(1) = "이미 주소가 있는 네트워크가 {0}개 있습니다. 덮어쓰거나, 비어 있는 네트워크에만 넣을 수 있습니다."
            / "{0} networks already have an address. You can overwrite them or fill only the empty networks.";
        OVERWRITE = "덮어쓰기" / "Overwrite";
        FILL_EMPTY = "비어 있는 네트워크만" / "Empty networks only";
        IMPORT = "가져오기" / "Import";
        SAVE_NOTE = "저장은 '교체'와 같습니다: Windows가 이 사용자 계정에서만 풀 수 있게 암호화해 apikeys.dpapi에 둡니다."
            / "Saving works like 'Replace': Windows encrypts it so only this user account can open it, in apikeys.dpapi.";
    }
}
