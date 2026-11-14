//! User-visible error codes and their fixed Korean and English messages (spec/04 §7). Remote or OS
//! strings are never shown; every failure is classified into an [`ErrorCode`] and displayed as
//! `"<문구> (<코드>)"` in the app language.

use yw_core::error::{KeyError, StorageError, VaultError};
use yw_core::lang::{Lang, Text};

/// The spec/04 §7 messages in both languages (D31: spec/04 §7 is their canonical owner, with an
/// English column since 2026-11-14), plus the E-RPC short names. `{n}`, `{항목}`/`{item}` and
/// `{인덱서}`/`{indexer}` are filled by [`ErrorCode::render_in`], not by `Tpl::fill`.
pub mod text {
    yw_core::texts! {
        APP001 = "설정 파일을 읽지 못해 기본값을 사용합니다."
            / "The settings file could not be read, so defaults are used.";
        APP002 = "설정을 저장하지 못했습니다. 디스크 공간과 권한을 확인하세요."
            / "The settings could not be saved. Check disk space and permissions.";
        APP004 = "Windows 잠금 감지를 켜지 못했습니다. 자리를 비울 때 직접 잠그세요."
            / "Windows lock detection could not be turned on. Lock the wallet yourself when you step away.";
        APP005 = "요청이 너무 많아 일부를 처리하지 못했습니다. 잠시 기다린 뒤 다시 시도하세요. dApp이 요청을 계속 보내면 그 사이트의 연결을 해제하세요."
            / "Too many requests, so some were not processed. Wait a moment and try again. If a dApp keeps sending requests, disconnect that site.";
        APP009 = "내부 오류가 발생했습니다. 앱을 다시 시작해 보고, 반복되면 로그 폴더 %LOCALAPPDATA%\\YourWallet\\v3\\logs의 yw-app.log에서 오류 코드 줄을 확인하세요."
            / "An internal error occurred. Restart the app; if it happens again, look for the error code line in yw-app.log in the log folder %LOCALAPPDATA%\\YourWallet\\v3\\logs.";
        PIPE001 = "브라우저 연결을 시작하지 못했습니다. 앱을 다시 실행하세요."
            / "The browser connection could not be started. Restart the app.";
        PIPE002 = "다른 프로그램이 지갑 연결 채널을 점유하고 있습니다. 브라우저 연결 없이 계속합니다. 모르는 프로그램이 실행 중인지 확인하고, PC를 다시 시작한 뒤 앱을 다시 실행하세요."
            / "Another program is holding the wallet connection channel. Continuing without the browser connection. Check for unknown programs running, then restart the PC and the app.";
        VLT001 = "비밀번호가 올바르지 않거나 vault 파일이 손상되었습니다. 대부분 입력 실수이니 Caps Lock과 한/영 상태를 확인하고 다시 입력하세요. 맞는 비밀번호로도 계속 실패하면 파일 손상일 수 있습니다(복구 안내 참고)."
            / "The password is wrong or the vault file is damaged. It is usually a typing mistake: check Caps Lock and the keyboard input language, then type it again. If the correct password keeps failing, the file may be damaged (see the recovery guide).";
        VLT002 = "지갑 파일을 읽을 수 없습니다. 손상되었거나 다른 버전의 파일입니다. 더 새로운 버전의 앱이 쓴 파일이면 앱을 최신 버전으로 업데이트하세요. 앱은 이 파일을 지우거나 덮어쓰지 않습니다."
            / "The wallet file cannot be read. It is damaged or from a different version. If a newer version of the app wrote it, update the app to the latest version. The app never deletes or overwrites this file.";
        VLT003 = "지갑 파일을 저장하지 못했습니다. 디스크 공간과 권한을 확인하세요."
            / "The wallet file could not be saved. Check disk space and permissions.";
        VLT005 = "안전한 난수를 얻지 못해 작업을 중단했습니다. 앱을 다시 시작해 다시 시도하고, 반복되면 로그 폴더의 yw-app.log에서 이 코드 줄을 확인하세요."
            / "Secure random numbers were unavailable, so the operation was stopped. Restart the app and try again; if it happens again, look for this code's line in yw-app.log in the log folder.";
        VLT006 = "지갑 부가 파일(meta·저널)을 읽을 수 없습니다. 복구 단어와 키는 이 파일에 없어 그대로입니다. 더 새로운 버전의 앱이 쓴 파일이면 앱을 최신 버전으로 업데이트한 뒤 다시 여세요."
            / "The wallet side files (meta, journal) cannot be read. Your recovery words and keys are not in these files and are unchanged. If a newer version of the app wrote them, update the app to the latest version and open it again.";
        VLT007 = "메모리를 잠그지 못해 잠금 해제하지 않았습니다. 다른 프로그램을 닫거나 PC를 다시 시작한 뒤 다시 잠금 해제하세요."
            / "Memory could not be locked, so the wallet was not unlocked. Close other programs or restart the PC, then unlock again.";
        VLT008 = "지갑 내용이 손상되었습니다. 이전 사본(.prev)으로 복구할 수 있습니다."
            / "The wallet contents are damaged. You can restore the previous copy (.prev).";
        VLT009 = "백업 확인을 먼저 끝내세요."
            / "Finish the backup check first.";
        VLT010 = "가져온 개인키는 체인마다 최대 15개입니다."
            / "You can import at most 15 private keys per chain.";
        VLT011 = "이미 가져온 개인키이거나, 지갑의 다른 계정과 주소가 같은 키입니다."
            / "This private key was already imported, or it has the same address as another account in the wallet.";
        VLT012 = "이 지갑에는 복구 단어가 없습니다. 개인키로 시작한 지갑은 계정 추가·복구 단어 보기를 쓸 수 없습니다."
            / "This wallet has no recovery words. A wallet started from a private key cannot add accounts or show recovery words.";
        VLT013 = "개인키로 시작한 지갑의 마지막 키는 지울 수 없습니다. 지갑 전체를 지우려면 앱을 닫고 데이터 폴더의 파일을 직접 옮기세요."
            / "The last key of a wallet started from a private key cannot be deleted. To remove the whole wallet, close the app and move the files in the data folder yourself.";
        VLT014 = "새 버전 앱이 저장한 지갑입니다. 앱을 업데이트하세요. 비밀번호는 맞습니다. 이전 사본(.prev)으로 되돌리지 마세요 — 새 버전에서 추가한 키가 빠집니다. 앱은 이 파일을 지우거나 덮어쓰지 않습니다."
            / "This wallet was saved by a newer version of the app. Update the app. Your password is correct. Do not go back to the previous copy (.prev) — keys added in the newer version would be missing. The app never deletes or overwrites this file.";
        INP001 = "비밀번호는 영문·숫자·기호(ASCII) 12–128자여야 합니다."
            / "The password must be 12–128 letters, digits or symbols (ASCII).";
        INP002 = "두 입력이 다릅니다."
            / "The two entries differ.";
        INP003 = "단어 수는 12, 15, 18, 21, 24 중 하나여야 합니다."
            / "The word count must be 12, 15, 18, 21 or 24.";
        INP004 = "{n}번째 단어가 BIP39 영어 단어 목록에 없습니다."
            / "Word {n} is not in the BIP39 English word list.";
        INP005 = "니모닉이 올바르지 않습니다. 단어 철자와 순서를 확인하세요."
            / "The recovery words are not valid. Check the spelling and order of the words.";
        INP006 = "개인키는 16진수 64자리여야 합니다."
            / "A private key must be 64 hexadecimal characters.";
        INP007 = "사용할 수 없는 개인키입니다."
            / "This private key cannot be used.";
        INP008 = "영문(ASCII)만 입력할 수 있습니다. 한/영 키로 영문 입력으로 바꾸세요."
            / "Only English letters (ASCII) can be entered. Switch the keyboard to English input.";
        INP013 = "입력한 단어가 맞지 않습니다."
            / "The words you entered do not match.";
        INP017 = "이름은 1–32자이고 앞뒤 공백·제어 문자·보이지 않는 문자를 쓸 수 없습니다."
            / "Names must be 1–32 characters, without leading or trailing spaces, control characters or invisible characters.";
        INP018 = "붙여넣은 내용에 허용되지 않는 문자가 있거나 너무 깁니다."
            / "The pasted text contains characters that are not allowed, or is too long.";
        INP019 = "passphrase는 영문·숫자·기호(ASCII) 1–256자여야 합니다."
            / "The passphrase must be 1–256 letters, digits or symbols (ASCII).";
        INP020 = "Solana 개인키는 base58 64바이트 keypair(Phantom·Solflare 내보내기) 또는 숫자 64개의 JSON 배열(solana-keygen 파일)이어야 합니다."
            / "A Solana private key must be a base58 64-byte keypair (Phantom or Solflare export) or a JSON array of 64 numbers (solana-keygen file).";
        INP021 = "입력한 값은 32바이트라 개인키가 아니라 Solana 주소(공개키)로 보입니다. 지갑의 '개인키 내보내기'로 받은 값을 넣으세요."
            / "The value is 32 bytes, so it looks like a Solana address (public key), not a private key. Enter the value from your wallet's 'Export private key'.";
        INP022 = "keypair의 공개키 부분이 개인키와 맞지 않습니다. 값이 잘리거나 바뀌지 않았는지 확인하세요."
            / "The public-key part of the keypair does not match the private key. Check that the value was not cut off or changed.";
        INP023 = "Bitcoin 개인키는 WIF(5·K·L·9·c로 시작하는 base58 51–52자)여야 합니다. 글자와 체크섬을 확인하세요."
            / "A Bitcoin private key must be a WIF (base58, 51–52 characters, starting with 5, K, L, 9 or c). Check the characters and the checksum.";
        INP024 = "압축되지 않은 키(5·9로 시작하는 WIF)는 P2PKH(레거시) 주소에만 쓸 수 있습니다. 주소 형식을 P2PKH로 고르세요."
            / "An uncompressed key (WIF starting with 5 or 9) can only be used for P2PKH (legacy) addresses. Choose the P2PKH address type.";
        INP025 = "Zcash 개인키는 압축 WIF(K·L·c로 시작하는 base58 52자) 또는 16진수 64자리여야 합니다. 압축되지 않은 WIF(5·9로 시작)는 받지 않습니다."
            / "A Zcash private key must be a compressed WIF (base58, 52 characters, starting with K, L or c) or 64 hexadecimal characters. Uncompressed WIFs (starting with 5 or 9) are not accepted.";
        INP026 = "이 WIF는 다른 Zcash 네트워크의 키입니다(K·L = 메인넷, c = 테스트넷). Zcash 탭의 네트워크를 바꾼 뒤 가져오세요."
            / "This WIF is a key for the other Zcash network (K, L = mainnet; c = testnet). Switch the network on the Zcash tab, then import.";
        SEC001 = "화면 캡처 제외를 적용하지 못해 표시하지 않습니다."
            / "Screen capture exclusion could not be applied, so nothing is shown.";
        SEC002 = "클립보드를 사용할 수 없습니다. 잠시 후 다시 시도하세요."
            / "The clipboard is unavailable. Try again in a moment.";
        KEY001 = "저장된 RPC 주소·API 키를 읽을 수 없습니다. 다른 PC나 다른 Windows 사용자에서 데이터 폴더를 옮겨 왔다면 정상입니다(이 파일은 저장한 사용자만 풀 수 있습니다). 설정 → 네트워크(RPC)에서 다시 넣으세요."
            / "The saved RPC addresses and API keys cannot be read. This is expected if the data folder came from another PC or Windows user (only the user who saved this file can open it). Enter them again in Settings → Network (RPC).";
        KEY002 = "공급자 템플릿 입력 형식이 올바르지 않습니다. QuickNode는 대시보드의 엔드포인트 주소 https://<이름>.<체인>.quiknode.pro/<토큰>/ 에서 첫 '.' 앞의 <이름>과 '.quiknode.pro/' 바로 뒤의 <토큰>을 넣고, 알케미는 대시보드의 API Key를 넣으세요."
            / "The provider template input is not in the right format. For QuickNode, take the dashboard endpoint address https://<name>.<chain>.quiknode.pro/<token>/ and enter the <name> before the first '.' and the <token> right after '.quiknode.pro/'; for Alchemy, enter the dashboard API Key.";
        KEY003 = "RPC URL은 https:// 로 시작하는 올바른 주소여야 합니다."
            / "The RPC URL must be a valid address that starts with https://.";
        KEY004 = "선택한 RPC 공급자의 자격 정보가 저장되어 있지 않습니다. 설정 → 네트워크(RPC) → “RPC 공급자”에서 먼저 저장하세요."
            / "No credentials are saved for the selected RPC provider. Save them first in Settings → Network (RPC) → “RPC provider”.";
        KEY005 = "RPC 주소가 없습니다. 설정 → 네트워크(RPC) → “네트워크별 RPC 주소”에서 입력하거나 “저장하고 RPC 주소 만들기”로 만드세요."
            / "There is no RPC address. Enter one in Settings → Network (RPC) → “RPC address per network” or create it with “Save and create RPC addresses”.";
        RPC001 = "네트워크에 연결할 수 없습니다. 인터넷 연결을 확인하고, 계속되면 설정 → 네트워크(RPC)에서 이 네트워크의 테스트를 눌러 보세요."
            / "Cannot connect to the network. Check your internet connection; if it continues, press Test for this network in Settings → Network (RPC).";
        RPC002 = "RPC 응답 시간이 초과되었습니다. 잠시 후 다시 시도하고, 계속되면 설정 → 네트워크(RPC)에서 테스트하거나 다른 RPC URL로 바꾸세요."
            / "The RPC response timed out. Try again in a moment; if it continues, test it in Settings → Network (RPC) or switch to another RPC URL.";
        RPC003 = "RPC 엔드포인트가 인증을 거부했습니다. 설정 → 네트워크(RPC)에서 이 네트워크의 URL(토큰)을 확인하세요. QuickNode 멀티체인이면 대시보드에서 이 체인이 그 엔드포인트에 켜져 있어야 합니다."
            / "The RPC endpoint refused authentication. Check this network's URL (token) in Settings → Network (RPC). For a QuickNode multichain endpoint, this chain must be enabled on it in the dashboard.";
        RPC004 = "요청 한도를 넘었습니다. 잠시 후 다시 시도하세요. 계속되면 공급자 대시보드에서 요금제의 초당 요청 한도와 크레딧 사용량을 확인하세요."
            / "The request limit was exceeded. Try again in a moment. If it continues, check your plan's requests-per-second limit and credit usage in the provider dashboard.";
        RPC005 = "RPC 응답 형식이 올바르지 않습니다. 설정 → 네트워크(RPC)에서 테스트해 이 네트워크용 URL(경로 포함)이 맞는지 확인하세요."
            / "The RPC response is malformed. Run Test in Settings → Network (RPC) to check that the URL (including the path) is the one for this network.";
        RPC006 = "RPC가 다른 네트워크를 가리킵니다. 작업을 중단했습니다. 설정 → 네트워크(RPC) → 테스트로 이 네트워크의 URL을 확인하고 맞는 URL로 바꾸세요."
            / "The RPC points to a different network. The operation was stopped. Check this network's URL with Settings → Network (RPC) → Test and switch to the correct URL.";
        RPC007 = "RPC가 요청을 거부했습니다. 설정 → 네트워크(RPC)에서 테스트해 보세요. QuickNode 멀티체인이면 대시보드에서 이 체인이 그 엔드포인트에 켜져 있는지, 요금제가 이 요청을 지원하는지 확인하세요."
            / "The RPC refused the request. Run Test in Settings → Network (RPC). For a QuickNode multichain endpoint, check in the dashboard that this chain is enabled on it and that your plan supports this request.";
        RPC008 = "보안 연결(TLS)을 맺지 못했습니다. PC의 날짜·시간이 맞는지, 보안 프로그램·프록시가 HTTPS 연결을 가로채지 않는지 확인하세요."
            / "A secure connection (TLS) could not be made. Check that the PC's date and time are correct and that no security program or proxy intercepts HTTPS connections.";
        RPC009 = "RPC 엔드포인트에 리퍼러·도메인 허용 목록이 걸려 있습니다. 공급자 대시보드에서 해제하세요(토큰 인증·IP 허용 목록은 무방, D13)."
            / "The RPC endpoint has a referrer or domain allowlist. Remove it in the provider dashboard (token authentication and IP allowlists are fine, D13).";
        RPC010 = "엔드포인트 테스트 실패: {항목} 불일치 — 다른 네트워크의 URL입니다."
            / "Endpoint test failed: {item} mismatch — this URL is for a different network.";
        INP009 = "주소 형식이 올바르지 않습니다."
            / "The address format is not valid.";
        INP010 = "주소의 대소문자 체크섬이 맞지 않습니다. 주소를 다시 확인하세요."
            / "The address's upper/lower-case checksum does not match. Check the address again.";
        INP011 = "금액 형식이 올바르지 않습니다."
            / "The amount format is not valid.";
        INP012 = "잔액이 부족합니다(수수료 포함)."
            / "Insufficient balance (fee included).";
        INP014 = "0 주소로는 보낼 수 없습니다."
            / "You cannot send to the zero address.";
        INP015 = "받는 주소가 이 토큰의 컨트랙트입니다. 보내면 잃습니다."
            / "The recipient is this token's contract. Anything sent there is lost.";
        INP016 = "이미 주소록에 있는 주소입니다."
            / "This address is already in the address book.";
        SIM001 = "시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다"
            / "The transaction failed in simulation — you may lose the fee and get nothing";
        SIM002 = "시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다"
            / "No simulation result — the real effect cannot be checked";
        SIM003 = "시뮬레이션 미지원 체인 — 실제 효과를 확인할 수 없습니다"
            / "Simulation is not supported on this chain — the real effect cannot be checked";
        SIM004 = "시뮬레이션 결과 불완전 — 일부 효과를 확인할 수 없습니다"
            / "Incomplete simulation result — some effects cannot be checked";
        CHN001 = "RPC의 chainId({n})가 입력한 chainId와 다릅니다."
            / "The RPC's chainId ({n}) differs from the chainId you entered.";
        CHN002 = "RPC에 연결하지 못해 체인을 확인할 수 없습니다."
            / "Cannot connect to the RPC, so the chain cannot be checked.";
        CHN003 = "이미 등록된 chainId입니다."
            / "This chainId is already registered.";
        CHN004 = "{항목} 형식이 올바르지 않습니다."
            / "The {item} format is not valid.";
        CHN005 = "같은 이름의 체인이 이미 있습니다."
            / "A chain with the same name already exists.";
        CHN006 = "사용자 체인은 최대 32개입니다."
            / "You can add at most 32 user chains.";
        CHN007 = "진행 중인 거래나 승인 대기가 있는 체인은 삭제할 수 없습니다. 확정된 뒤 다시 시도하세요."
            / "A chain with transactions in progress or pending approvals cannot be deleted. Try again once they are final.";
        CHN008 = "체인 정보가 바뀌었습니다 (제네시스 불일치)"
            / "The chain information has changed (genesis mismatch)";
        CHN009 = "사용 중인 체인은 삭제할 수 없습니다. 네트워크를 먼저 바꾸세요."
            / "The chain in use cannot be deleted. Switch networks first.";
        CHN010 = "EIP-1559를 지원하지 않는 체인입니다."
            / "This chain does not support EIP-1559.";
        TX001 = "수수료가 설정한 상한을 넘습니다. 네트워크가 붐비면 잠시 후 다시 시도하거나, 설정 → EVM 체인 → 고급 설정 보기의 EVM 수수료 상한을 확인하세요."
            / "The fee exceeds the cap you set. If the network is busy, try again later, or check the EVM fee cap in Settings → EVM chains → Show advanced settings.";
        TX002 = "이 계정의 이전 거래가 아직 확정되지 않았습니다. 아래 활동에서 상태를 확인하세요. 확정되면 보낼 수 있고, EVM은 활동의 “수수료 올리기”·“취소”를 쓸 수 있습니다."
            / "A previous transaction from this account is not final yet. Check its status in Activity below. You can send once it is final; on EVM you can use “Raise fee” or “Cancel” in Activity.";
        TX003 = "내부 검증에 실패해 거래를 보내지 않았습니다. 앱을 다시 시작해 다시 시도하고, 반복되면 로그 폴더의 yw-app.log에서 이 코드 줄을 확인하세요."
            / "Internal verification failed, so the transaction was not sent. Restart the app and try again; if it happens again, look for this code's line in yw-app.log in the log folder.";
        TX004 = "전송 결과를 확인할 수 없습니다. 다시 보내지 마세요 — 거래가 이미 전송되었을 수 있습니다. 활동에서 상태를 확인하세요."
            / "The send result cannot be confirmed. Do not send again — the transaction may already have been sent. Check its status in Activity.";
        TX005 = "거래 저널 공간이 부족합니다. 진행 중인 거래가 확정되거나 폐기되면 공간이 생깁니다."
            / "The transaction journal is full. Space frees up when transactions in progress become final or are discarded.";
        UI001 = "요청 내용을 안전하게 표시할 수 없어 거부했습니다."
            / "The request could not be shown safely, so it was rejected.";
        SOL001 = "받는 주소가 프로그램·시스템·토큰 mint 주소입니다. 보내면 잃습니다."
            / "The recipient is a program, system or token mint address. Anything sent there is lost.";
        SOL002 = "받는 주소는 아무도 쓸 수 없는 주소입니다. 보내면 잃습니다."
            / "The recipient is an address nobody can use. Anything sent there is lost.";
        SOL003 = "보내는 계정과 같은 주소로는 보낼 수 없습니다."
            / "You cannot send to the sending account's own address.";
        SOL004 = "승인한 전송을 서명 전에 멈췄습니다(아무것도 서명·전송하지 않음). 다시 검토하세요."
            / "The approved transfer was stopped before signing (nothing was signed or sent). Review it again.";
        SOL005 = "전송 확인이 오래 걸립니다. 네트워크·RPC 상태를 확인하세요(자동 재서명 없음)."
            / "Confirming the transfer is taking a long time. Check the network and RPC status (nothing is re-signed automatically).";
        SOL006 = "토큰은 일반 지갑 주소로만 보낼 수 있습니다. 이 주소는 프로그램 소유 주소(PDA)나 토큰 계정이라 받은 토큰을 옮길 수 없습니다."
            / "Tokens can only be sent to a regular wallet address. This address is a program-owned address (PDA) or a token account, so tokens received there cannot be moved.";
        BTC001 = "Bitcoin 인덱서({인덱서})에 연결할 수 없습니다. 잠시 후 다시 시도하거나 설정 → Bitcoin에서 인덱서를 바꾸세요."
            / "Cannot connect to the Bitcoin indexer ({indexer}). Try again in a moment or change the indexer in Settings → Bitcoin.";
        BTC002 = "Bitcoin 인덱서 요청 한도를 넘었습니다. 몇 분 뒤 다시 시도하세요. 공용 서버(mempool.space 등)는 요청 수를 제한합니다."
            / "The Bitcoin indexer's request limit was exceeded. Try again in a few minutes. Public servers (mempool.space and others) limit the number of requests.";
        BTC003 = "Bitcoin 인덱서가 다른 네트워크를 가리킵니다. 설정 → Bitcoin에서 인덱서와 Esplora URL을 확인하세요."
            / "The Bitcoin indexer points to a different network. Check the indexer and the Esplora URL in Settings → Bitcoin.";
        BTC004 = "Bitcoin 인덱서 응답 형식이 올바르지 않습니다. 설정 → Bitcoin에서 인덱서 종류가 그 서버와 맞는지 확인하세요."
            / "The Bitcoin indexer's response is malformed. Check in Settings → Bitcoin that the indexer type matches that server.";
        BTC005 = "인덱서가 주소 조회를 거부했습니다. 주소의 UTXO가 너무 많거나(공용 mempool.space는 500개 초과 시 거부) 인덱서의 네트워크가 다를 수 있습니다."
            / "The indexer refused the address lookup. The address may have too many UTXOs (public mempool.space refuses more than 500), or the indexer may be on a different network.";
        BTC006 = "Esplora URL은 https:// 로 시작하고 ?·#·끝 '/'가 없어야 하며, 토큰이 들어가는 공급자 URL(QuickNode·알케미)은 쓸 수 없습니다."
            / "The Esplora URL must start with https:// and have no ?, # or trailing '/'; provider URLs that contain a token (QuickNode, Alchemy) cannot be used.";
        BTC007 = "Bitcoin 인덱서가 요청을 거부했습니다(인증 또는 인덱서 애드온 권한). 설정 → Bitcoin에서 인덱서를 Esplora로 바꾸거나 공급자 대시보드에서 애드온을 켜세요."
            / "The Bitcoin indexer refused the request (authentication or indexer add-on permission). Switch the indexer to Esplora in Settings → Bitcoin or enable the add-on in the provider dashboard.";
        BTC008 = "Esplora 서버가 거래 전송을 거부했습니다. 활동에서 상태를 확인하고 필요하면 수수료를 올리세요."
            / "The Esplora server refused to send the transaction. Check its status in Activity and raise the fee if needed.";
        RPC001_SHORT = "연결 실패" / "Connection failed";
        RPC002_SHORT = "시간 초과" / "Timed out";
        RPC003_SHORT = "인증 거부" / "Authentication refused";
        RPC004_SHORT = "요청 한도 초과" / "Rate limited";
        RPC005_SHORT = "응답 형식 오류" / "Malformed response";
        RPC006_SHORT = "다른 네트워크" / "Wrong network";
        RPC007_SHORT = "요청 거부" / "Request refused";
        RPC008_SHORT = "보안 연결 실패" / "TLS failed";
        RPC009_SHORT = "허용 목록 거부" / "Allowlist refused";
        RPC010_SHORT = "네트워크 불일치" / "Network mismatch";
    }
}

/// A classified error (spec/04 §7 table).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// `settings.json` unreadable or invalid key.
    App001,
    /// `settings.json` / `apikeys.dpapi` write failure.
    App002,
    /// Session notification registration failed.
    App004,
    /// Event queue full.
    App005,
    /// Internal error.
    App009,
    /// Pipe creation failed.
    Pipe001,
    /// The pipe name is held by a server this app did not create (squatter).
    Pipe002,
    /// `UnlockFailed`.
    Vlt001,
    /// Malformed / unsupported vault.
    Vlt002,
    /// Vault storage failure.
    Vlt003,
    /// Randomness unavailable.
    Vlt005,
    /// Sidecar corrupt.
    Vlt006,
    /// `VirtualLock` / out of memory.
    Vlt007,
    /// Payload corrupt.
    Vlt008,
    /// Backup not confirmed.
    Vlt009,
    /// Raw key limit.
    Vlt010,
    /// Duplicate raw key.
    Vlt011,
    /// Key-only wallet: no recovery words.
    Vlt012,
    /// The last key of a key-only wallet.
    Vlt013,
    /// The payload authenticated but was written by a newer build (`UnsupportedPayload`).
    Vlt014,
    /// Password rule.
    Inp001,
    /// Confirmation mismatch.
    Inp002,
    /// Mnemonic word count.
    Inp003,
    /// Unknown mnemonic word (position in the message).
    Inp004,
    /// Mnemonic checksum / format.
    Inp005,
    /// Private key format.
    Inp006,
    /// Invalid private key.
    Inp007,
    /// Non-ASCII / IME.
    Inp008,
    /// Backup mismatch.
    Inp013,
    /// Label rule.
    Inp017,
    /// Paste rejected.
    Inp018,
    /// Passphrase rule.
    Inp019,
    /// Solana key format.
    Inp020,
    /// Solana key text is an address (32 bytes).
    Inp021,
    /// Solana keypair halves do not match.
    Inp022,
    /// Bitcoin WIF format.
    Inp023,
    /// Uncompressed WIF with a segwit/taproot type.
    Inp024,
    /// Zcash key text (spec/12 §2.3).
    Inp025,
    /// Zcash WIF of the other network.
    Inp026,
    /// Capture exclusion failed on a display window.
    Sec001,
    /// Clipboard unavailable.
    Sec002,
    /// `apikeys.dpapi` unreadable.
    Key001,
    /// Template credential format.
    Key002,
    /// RPC URL format.
    Key003,
    /// Template credential missing.
    Key004,
    /// No endpoint for the network.
    Key005,
    /// DNS / connect failure.
    Rpc001,
    /// Timeout.
    Rpc002,
    /// HTTP 401/403.
    Rpc003,
    /// HTTP 429.
    Rpc004,
    /// Malformed response.
    Rpc005,
    /// Wrong network.
    Rpc006,
    /// Other JSON-RPC error.
    Rpc007,
    /// TLS failure.
    Rpc008,
    /// Referrer / origin allowlist.
    Rpc009,
    /// Endpoint test mismatch.
    Rpc010,
    /// Address format.
    Inp009,
    /// EIP-55 checksum mismatch.
    Inp010,
    /// Amount format.
    Inp011,
    /// Insufficient balance (fee included).
    Inp012,
    /// Zero address.
    Inp014,
    /// Recipient is the token contract.
    Inp015,
    /// Address-book duplicate.
    Inp016,
    /// Simulation reverted (band).
    Sim001,
    /// No simulation result (band).
    Sim002,
    /// Simulation unsupported (band).
    Sim003,
    /// Simulation incomplete (band).
    Sim004,
    /// Chain add: RPC chain id differs.
    Chn001,
    /// Chain add: RPC unreachable.
    Chn002,
    /// Chain id already registered.
    Chn003,
    /// Chain input format.
    Chn004,
    /// Chain name duplicate.
    Chn005,
    /// More than 32 user chains.
    Chn006,
    /// Delete refused: open transactions or approvals.
    Chn007,
    /// Pinned genesis mismatch.
    Chn008,
    /// Delete refused: active chain.
    Chn009,
    /// Chain add: no EIP-1559 base fee.
    Chn010,
    /// Fee cap exceeded (E05).
    Tx001,
    /// Transaction in flight (E06).
    Tx002,
    /// Post-sign verification failed.
    Tx003,
    /// Broadcast result unknown.
    Tx004,
    /// Journal full.
    Tx005,
    /// Display validation failure.
    Ui001,
    /// SOL recipient is a program, sysvar or allowlisted mint (spec/07 §12.1-2).
    Sol001,
    /// SOL recipient is a small-order or non-canonical point (§12.1-3).
    Sol002,
    /// SOL recipient is the sending account (§12.1-4).
    Sol003,
    /// An approved SOL transfer stopped before signing (§13.1 steps 4–6): nothing was signed.
    Sol004,
    /// SOL signature status: network/RPC check needed (§14.2, 120 s pending).
    Sol005,
    /// SPL recipient is off-curve (a PDA or token account; spec/07 §12.1-6, v1.1).
    Sol006,
    /// Bitcoin indexer unreachable: transport error, timeout, TLS, HTTP 3xx/5xx/other
    /// (spec/08 §4.3; `{인덱서}` = indexer display name, optional cause code).
    Btc001,
    /// Bitcoin indexer HTTP 429 after three retries (spec/08 §4.4).
    Btc002,
    /// Bitcoin indexer genesis mismatch (spec/08 §2 step 3): BTC blocked for the session.
    Btc003,
    /// Bitcoin indexer response malformed (fields, integers, hex, `Content-Type`, 404).
    Btc004,
    /// Esplora address lookup HTTP 400.
    Btc005,
    /// Esplora URL format (settings).
    Btc006,
    /// Bitcoin indexer authentication / add-on refused (HTTP 401·403, `bb-*` `-32601`).
    Btc007,
    /// Manual Esplora `POST /tx` HTTP 400 (spec/08 §11.3).
    Btc008,
}

impl ErrorCode {
    /// `"E-XXX-nnn"`.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::App001 => "E-APP-001",
            Self::App002 => "E-APP-002",
            Self::App004 => "E-APP-004",
            Self::App005 => "E-APP-005",
            Self::App009 => "E-APP-009",
            Self::Pipe001 => "E-PIPE-001",
            Self::Pipe002 => "E-PIPE-002",
            Self::Vlt001 => "E-VLT-001",
            Self::Vlt002 => "E-VLT-002",
            Self::Vlt003 => "E-VLT-003",
            Self::Vlt005 => "E-VLT-005",
            Self::Vlt006 => "E-VLT-006",
            Self::Vlt007 => "E-VLT-007",
            Self::Vlt008 => "E-VLT-008",
            Self::Vlt009 => "E-VLT-009",
            Self::Vlt010 => "E-VLT-010",
            Self::Vlt011 => "E-VLT-011",
            Self::Vlt012 => "E-VLT-012",
            Self::Vlt013 => "E-VLT-013",
            Self::Vlt014 => "E-VLT-014",
            Self::Inp001 => "E-INP-001",
            Self::Inp002 => "E-INP-002",
            Self::Inp003 => "E-INP-003",
            Self::Inp004 => "E-INP-004",
            Self::Inp005 => "E-INP-005",
            Self::Inp006 => "E-INP-006",
            Self::Inp007 => "E-INP-007",
            Self::Inp008 => "E-INP-008",
            Self::Inp013 => "E-INP-013",
            Self::Inp017 => "E-INP-017",
            Self::Inp018 => "E-INP-018",
            Self::Inp019 => "E-INP-019",
            Self::Inp020 => "E-INP-020",
            Self::Inp021 => "E-INP-021",
            Self::Inp022 => "E-INP-022",
            Self::Inp023 => "E-INP-023",
            Self::Inp024 => "E-INP-024",
            Self::Inp025 => "E-INP-025",
            Self::Inp026 => "E-INP-026",
            Self::Sec001 => "E-SEC-001",
            Self::Sec002 => "E-SEC-002",
            Self::Key001 => "E-KEY-001",
            Self::Key002 => "E-KEY-002",
            Self::Key003 => "E-KEY-003",
            Self::Key004 => "E-KEY-004",
            Self::Key005 => "E-KEY-005",
            Self::Rpc001 => "E-RPC-001",
            Self::Rpc002 => "E-RPC-002",
            Self::Rpc003 => "E-RPC-003",
            Self::Rpc004 => "E-RPC-004",
            Self::Rpc005 => "E-RPC-005",
            Self::Rpc006 => "E-RPC-006",
            Self::Rpc007 => "E-RPC-007",
            Self::Rpc008 => "E-RPC-008",
            Self::Rpc009 => "E-RPC-009",
            Self::Rpc010 => "E-RPC-010",
            Self::Inp009 => "E-INP-009",
            Self::Inp010 => "E-INP-010",
            Self::Inp011 => "E-INP-011",
            Self::Inp012 => "E-INP-012",
            Self::Inp014 => "E-INP-014",
            Self::Inp015 => "E-INP-015",
            Self::Inp016 => "E-INP-016",
            Self::Sim001 => "E-SIM-001",
            Self::Sim002 => "E-SIM-002",
            Self::Sim003 => "E-SIM-003",
            Self::Sim004 => "E-SIM-004",
            Self::Chn001 => "E-CHN-001",
            Self::Chn002 => "E-CHN-002",
            Self::Chn003 => "E-CHN-003",
            Self::Chn004 => "E-CHN-004",
            Self::Chn005 => "E-CHN-005",
            Self::Chn006 => "E-CHN-006",
            Self::Chn007 => "E-CHN-007",
            Self::Chn008 => "E-CHN-008",
            Self::Chn009 => "E-CHN-009",
            Self::Chn010 => "E-CHN-010",
            Self::Tx001 => "E-TX-001",
            Self::Tx002 => "E-TX-002",
            Self::Tx003 => "E-TX-003",
            Self::Tx004 => "E-TX-004",
            Self::Tx005 => "E-TX-005",
            Self::Ui001 => "E-UI-001",
            Self::Sol001 => "E-SOL-001",
            Self::Sol002 => "E-SOL-002",
            Self::Sol003 => "E-SOL-003",
            Self::Sol004 => "E-SOL-004",
            Self::Sol005 => "E-SOL-005",
            Self::Sol006 => "E-SOL-006",
            Self::Btc001 => "E-BTC-001",
            Self::Btc002 => "E-BTC-002",
            Self::Btc003 => "E-BTC-003",
            Self::Btc004 => "E-BTC-004",
            Self::Btc005 => "E-BTC-005",
            Self::Btc006 => "E-BTC-006",
            Self::Btc007 => "E-BTC-007",
            Self::Btc008 => "E-BTC-008",
        }
    }

    /// Every code, in declaration order (tests, spec/04 §7).
    pub const ALL: [Self; 97] = [
        Self::App001,
        Self::App002,
        Self::App004,
        Self::App005,
        Self::App009,
        Self::Pipe001,
        Self::Pipe002,
        Self::Vlt001,
        Self::Vlt002,
        Self::Vlt003,
        Self::Vlt005,
        Self::Vlt006,
        Self::Vlt007,
        Self::Vlt008,
        Self::Vlt009,
        Self::Vlt010,
        Self::Vlt011,
        Self::Vlt012,
        Self::Vlt013,
        Self::Vlt014,
        Self::Inp001,
        Self::Inp002,
        Self::Inp003,
        Self::Inp004,
        Self::Inp005,
        Self::Inp006,
        Self::Inp007,
        Self::Inp008,
        Self::Inp013,
        Self::Inp017,
        Self::Inp018,
        Self::Inp019,
        Self::Inp020,
        Self::Inp021,
        Self::Inp022,
        Self::Inp023,
        Self::Inp024,
        Self::Inp025,
        Self::Inp026,
        Self::Sec001,
        Self::Sec002,
        Self::Key001,
        Self::Key002,
        Self::Key003,
        Self::Key004,
        Self::Key005,
        Self::Rpc001,
        Self::Rpc002,
        Self::Rpc003,
        Self::Rpc004,
        Self::Rpc005,
        Self::Rpc006,
        Self::Rpc007,
        Self::Rpc008,
        Self::Rpc009,
        Self::Rpc010,
        Self::Inp009,
        Self::Inp010,
        Self::Inp011,
        Self::Inp012,
        Self::Inp014,
        Self::Inp015,
        Self::Inp016,
        Self::Sim001,
        Self::Sim002,
        Self::Sim003,
        Self::Sim004,
        Self::Chn001,
        Self::Chn002,
        Self::Chn003,
        Self::Chn004,
        Self::Chn005,
        Self::Chn006,
        Self::Chn007,
        Self::Chn008,
        Self::Chn009,
        Self::Chn010,
        Self::Tx001,
        Self::Tx002,
        Self::Tx003,
        Self::Tx004,
        Self::Tx005,
        Self::Ui001,
        Self::Sol001,
        Self::Sol002,
        Self::Sol003,
        Self::Sol004,
        Self::Sol005,
        Self::Sol006,
        Self::Btc001,
        Self::Btc002,
        Self::Btc003,
        Self::Btc004,
        Self::Btc005,
        Self::Btc006,
        Self::Btc007,
        Self::Btc008,
    ];

    /// The catalogue entry of this code (spec/04 §7 table, both languages).
    #[must_use]
    pub const fn catalogue(self) -> Text {
        match self {
            Self::App001 => text::APP001,
            Self::App002 => text::APP002,
            Self::App004 => text::APP004,
            Self::App005 => text::APP005,
            Self::App009 => text::APP009,
            Self::Pipe001 => text::PIPE001,
            Self::Pipe002 => text::PIPE002,
            Self::Vlt001 => text::VLT001,
            Self::Vlt002 => text::VLT002,
            Self::Vlt003 => text::VLT003,
            Self::Vlt005 => text::VLT005,
            Self::Vlt006 => text::VLT006,
            Self::Vlt007 => text::VLT007,
            Self::Vlt008 => text::VLT008,
            Self::Vlt009 => text::VLT009,
            Self::Vlt010 => text::VLT010,
            Self::Vlt011 => text::VLT011,
            Self::Vlt012 => text::VLT012,
            Self::Vlt013 => text::VLT013,
            Self::Vlt014 => text::VLT014,
            Self::Inp001 => text::INP001,
            Self::Inp002 => text::INP002,
            Self::Inp003 => text::INP003,
            Self::Inp004 => text::INP004,
            Self::Inp005 => text::INP005,
            Self::Inp006 => text::INP006,
            Self::Inp007 => text::INP007,
            Self::Inp008 => text::INP008,
            Self::Inp013 => text::INP013,
            Self::Inp017 => text::INP017,
            Self::Inp018 => text::INP018,
            Self::Inp019 => text::INP019,
            Self::Inp020 => text::INP020,
            Self::Inp021 => text::INP021,
            Self::Inp022 => text::INP022,
            Self::Inp023 => text::INP023,
            Self::Inp024 => text::INP024,
            Self::Inp025 => text::INP025,
            Self::Inp026 => text::INP026,
            Self::Sec001 => text::SEC001,
            Self::Sec002 => text::SEC002,
            Self::Key001 => text::KEY001,
            Self::Key002 => text::KEY002,
            Self::Key003 => text::KEY003,
            Self::Key004 => text::KEY004,
            Self::Key005 => text::KEY005,
            Self::Rpc001 => text::RPC001,
            Self::Rpc002 => text::RPC002,
            Self::Rpc003 => text::RPC003,
            Self::Rpc004 => text::RPC004,
            Self::Rpc005 => text::RPC005,
            Self::Rpc006 => text::RPC006,
            Self::Rpc007 => text::RPC007,
            Self::Rpc008 => text::RPC008,
            Self::Rpc009 => text::RPC009,
            Self::Rpc010 => text::RPC010,
            Self::Inp009 => text::INP009,
            Self::Inp010 => text::INP010,
            Self::Inp011 => text::INP011,
            Self::Inp012 => text::INP012,
            Self::Inp014 => text::INP014,
            Self::Inp015 => text::INP015,
            Self::Inp016 => text::INP016,
            Self::Sim001 => text::SIM001,
            Self::Sim002 => text::SIM002,
            Self::Sim003 => text::SIM003,
            Self::Sim004 => text::SIM004,
            Self::Chn001 => text::CHN001,
            Self::Chn002 => text::CHN002,
            Self::Chn003 => text::CHN003,
            Self::Chn004 => text::CHN004,
            Self::Chn005 => text::CHN005,
            Self::Chn006 => text::CHN006,
            Self::Chn007 => text::CHN007,
            Self::Chn008 => text::CHN008,
            Self::Chn009 => text::CHN009,
            Self::Chn010 => text::CHN010,
            Self::Tx001 => text::TX001,
            Self::Tx002 => text::TX002,
            Self::Tx003 => text::TX003,
            Self::Tx004 => text::TX004,
            Self::Tx005 => text::TX005,
            Self::Ui001 => text::UI001,
            Self::Sol001 => text::SOL001,
            Self::Sol002 => text::SOL002,
            Self::Sol003 => text::SOL003,
            Self::Sol004 => text::SOL004,
            Self::Sol005 => text::SOL005,
            Self::Sol006 => text::SOL006,
            Self::Btc001 => text::BTC001,
            Self::Btc002 => text::BTC002,
            Self::Btc003 => text::BTC003,
            Self::Btc004 => text::BTC004,
            Self::Btc005 => text::BTC005,
            Self::Btc006 => text::BTC006,
            Self::Btc007 => text::BTC007,
            Self::Btc008 => text::BTC008,
        }
    }

    /// [`Self::message`] in `lang` (spec/04 §7, English column).
    #[must_use]
    pub const fn message_in(self, lang: Lang) -> &'static str {
        self.catalogue().get(lang)
    }

    /// The English message (spec/04 §7, English column).
    #[must_use]
    pub const fn message_en(self) -> &'static str {
        self.catalogue().en
    }

    /// [`Self::text`] in `lang`: `"<message> (<code>)"`.
    #[must_use]
    pub fn text_in(self, lang: Lang) -> String {
        format!("{} ({})", self.message_in(lang), self.code())
    }

    /// [`ErrorCode::short_name`] in `lang` ("E-RPC-003 · Authentication refused").
    #[must_use]
    pub const fn short_name_in(self, lang: Lang) -> Option<&'static str> {
        let text = match self {
            Self::Rpc001 => text::RPC001_SHORT,
            Self::Rpc002 => text::RPC002_SHORT,
            Self::Rpc003 => text::RPC003_SHORT,
            Self::Rpc004 => text::RPC004_SHORT,
            Self::Rpc005 => text::RPC005_SHORT,
            Self::Rpc006 => text::RPC006_SHORT,
            Self::Rpc007 => text::RPC007_SHORT,
            Self::Rpc008 => text::RPC008_SHORT,
            Self::Rpc009 => text::RPC009_SHORT,
            Self::Rpc010 => text::RPC010_SHORT,
            _ => return None,
        };
        Some(text.get(lang))
    }

    /// [`ErrorCode::code_with_name`] in `lang`.
    #[must_use]
    pub fn code_with_name_in(self, lang: Lang) -> String {
        match self.short_name_in(lang) {
            Some(name) => format!("{} · {name}", self.code()),
            None => self.code().to_owned(),
        }
    }

    /// [`ErrorCode::render`] in `lang`. The value is data (a number, a field name or an indexer
    /// name the caller already gives in `lang`) and is inserted as is.
    #[must_use]
    pub fn render_in(self, lang: Lang, value: &str) -> String {
        let message = self.message_in(lang);
        let filled = match (message.find('{'), message.find('}')) {
            (Some(open), Some(close)) if open < close => {
                let (head, rest) = message.split_at(open);
                let tail = rest
                    .get(close.saturating_sub(open).saturating_add(1)..)
                    .unwrap_or("");
                format!("{head}{value}{tail}")
            }
            _ => message.to_owned(),
        };
        format!("{filled} ({})", self.code())
    }

    /// [`ErrorCode::render_with_cause`] in `lang`.
    #[must_use]
    pub fn render_with_cause_in(self, lang: Lang, value: &str, cause: Option<Self>) -> String {
        let rendered = self.render_in(lang, value);
        match cause {
            Some(cause) => {
                let suffix = format!(" ({})", self.code());
                let head = rendered.strip_suffix(&suffix).unwrap_or(&rendered);
                format!("{head} ({}, {})", self.code(), cause.code())
            }
            None => rendered,
        }
    }
}

/// Classifies a vault error (spec/04 §7 "분류 입력").
#[must_use]
pub const fn vault_code(error: VaultError) -> ErrorCode {
    match error {
        VaultError::UnlockFailed => ErrorCode::Vlt001,
        VaultError::Malformed | VaultError::UnsupportedVersion | VaultError::UnsupportedParams => {
            ErrorCode::Vlt002
        }
        VaultError::Storage(_) => ErrorCode::Vlt003,
        VaultError::SidecarCorrupt(_)
        | VaultError::SidecarVaultMismatch(_)
        | VaultError::SidecarUnsupported(_) => ErrorCode::Vlt006,
        VaultError::OutOfMemory => ErrorCode::Vlt007,
        VaultError::PayloadCorrupt => ErrorCode::Vlt008,
        VaultError::UnsupportedPayload => ErrorCode::Vlt014,
        VaultError::BackupNotConfirmed => ErrorCode::Vlt009,
        VaultError::BackupMismatch | VaultError::ChallengeStale => ErrorCode::Inp013,
        VaultError::RecordLimit => ErrorCode::Vlt010,
        VaultError::DuplicateKey => ErrorCode::Vlt011,
        VaultError::NoMnemonic => ErrorCode::Vlt012,
        VaultError::LastKey => ErrorCode::Vlt013,
        VaultError::Key(key) => key_code(key),
        // The UI offers no removal of the primary mnemonic (spec/04 §2.24).
        VaultError::InvalidState | VaultError::RecordNotFound | VaultError::PrimaryMnemonic => {
            ErrorCode::App009
        }
    }
}

/// Classifies a key error.
#[must_use]
pub const fn key_code(error: KeyError) -> ErrorCode {
    match error {
        KeyError::RandomnessUnavailable => ErrorCode::Vlt005,
        KeyError::PasswordTooShort | KeyError::PasswordTooLong | KeyError::PasswordInvalidChar => {
            ErrorCode::Inp001
        }
        KeyError::PassphraseTooLong
        | KeyError::PassphraseInvalidChar
        | KeyError::PassphraseEmpty => ErrorCode::Inp019,
        KeyError::MnemonicWordCount => ErrorCode::Inp003,
        KeyError::MnemonicUnknownWord { .. } => ErrorCode::Inp004,
        KeyError::MnemonicFormat | KeyError::MnemonicChecksum => ErrorCode::Inp005,
        KeyError::InvalidPrivateKey => ErrorCode::Inp007,
        KeyError::SolKeyFormat => ErrorCode::Inp020,
        KeyError::SolKeyIsAddress => ErrorCode::Inp021,
        KeyError::SolKeyMismatch => ErrorCode::Inp022,
        KeyError::WifFormat => ErrorCode::Inp023,
        KeyError::WifUncompressedScript => ErrorCode::Inp024,
        KeyError::ZecKeyFormat => ErrorCode::Inp025,
        KeyError::ZecKeyNetwork => ErrorCode::Inp026,
        KeyError::InvalidEntropyLength
        | KeyError::InvalidPath
        | KeyError::InvalidAccountIndex
        | KeyError::DerivationFailed
        | KeyError::InvalidExtendedKey
        | KeyError::Internal => ErrorCode::App009,
    }
}

/// `StorageError` name for logs (no paths).
#[must_use]
pub const fn storage_name(error: StorageError) -> &'static str {
    match error {
        StorageError::NotFound => "NotFound",
        StorageError::AlreadyExists => "AlreadyExists",
        StorageError::GenerationConflict => "GenerationConflict",
        StorageError::Corrupt => "Corrupt",
        StorageError::TooLarge => "TooLarge",
        StorageError::Io(_) => "Io",
    }
}

#[cfg(test)]
mod tests {
    use super::{ErrorCode, vault_code};
    use yw_core::error::{KeyError, VaultError};
    use yw_core::lang::Lang;

    #[test]
    fn rendering_fills_one_placeholder_and_appends_code() {
        assert_eq!(
            ErrorCode::Inp004.render_in(Lang::Ko, "3"),
            "3번째 단어가 BIP39 영어 단어 목록에 없습니다. (E-INP-004)"
        );
        assert_eq!(
            ErrorCode::Rpc010.render_in(Lang::Ko, "chainId"),
            "엔드포인트 테스트 실패: chainId 불일치 — 다른 네트워크의 URL입니다. (E-RPC-010)"
        );
        let unlock = ErrorCode::Vlt001.text_in(Lang::Ko);
        assert!(unlock.starts_with("비밀번호가 올바르지 않거나 vault 파일이 손상되었습니다. "));
        assert!(unlock.contains("Caps Lock") && unlock.ends_with(" (E-VLT-001)"));
    }

    #[test]
    fn messages_name_a_next_step() {
        assert!(
            ErrorCode::Tx004
                .message_in(Lang::Ko)
                .contains("다시 보내지 마세요 — 거래가 이미 전송되었을 수 있습니다")
        );
        assert!(
            ErrorCode::App009
                .text_in(Lang::Ko)
                .contains("%LOCALAPPDATA%\\YourWallet\\v3\\logs")
        );
        assert!(
            ErrorCode::Rpc006
                .message_in(Lang::Ko)
                .contains("설정 → 네트워크(RPC) → 테스트")
        );
        assert!(
            ErrorCode::Tx001
                .message_in(Lang::Ko)
                .contains("EVM 수수료 상한")
        );
        for code in [ErrorCode::Vlt002, ErrorCode::Vlt006, ErrorCode::Vlt014] {
            assert!(
                code.message_in(Lang::Ko).contains("업데이트"),
                "{}",
                code.code()
            );
        }
        for code in [ErrorCode::Rpc003, ErrorCode::Rpc007] {
            assert!(
                code.message_in(Lang::Ko).contains("QuickNode 멀티체인"),
                "{}",
                code.code()
            );
        }
        for code in [
            ErrorCode::Rpc001,
            ErrorCode::Rpc002,
            ErrorCode::Rpc005,
            ErrorCode::Rpc007,
            ErrorCode::Rpc008,
        ] {
            // One sentence of cause, then at least one sentence of what to do.
            assert!(
                code.message_in(Lang::Ko).matches(". ").count() >= 1,
                "{}",
                code.code()
            );
            assert!(
                code.message_in(Lang::Ko).ends_with("세요."),
                "{}",
                code.code()
            );
        }
        // 2026-11-10: these name where to go or what to try next as well.
        for code in [
            ErrorCode::Key001,
            ErrorCode::Key004,
            ErrorCode::Key005,
            ErrorCode::Rpc004,
            ErrorCode::Tx002,
            ErrorCode::Tx003,
            ErrorCode::Tx005,
            ErrorCode::Vlt005,
            ErrorCode::Vlt007,
            ErrorCode::Btc004,
            ErrorCode::App005,
        ] {
            assert!(
                code.message_in(Lang::Ko).matches(". ").count() >= 1,
                "{}",
                code.code()
            );
        }
        assert!(
            ErrorCode::Key005
                .message_in(Lang::Ko)
                .contains("“저장하고 RPC 주소 만들기”")
        );
        // E-KEY-002 names the item after the hint, as the S15 handler appends it.
        let item = ErrorCode::Key002
            .text_in(Lang::Ko)
            .replace(" (E-KEY-002)", " (토큰) (E-KEY-002)");
        assert!(item.contains("<토큰>") && item.ends_with("(토큰) (E-KEY-002)"));
        // No message has an unfilled placeholder other than the documented ones.
        assert!(!ErrorCode::Key002.message_in(Lang::Ko).contains('{'));
    }

    #[test]
    fn every_code_has_an_english_message() {
        use std::collections::HashSet;
        use yw_core::lang::{Lang, has_hangul};
        let codes: HashSet<&str> = ErrorCode::ALL.iter().map(|code| code.code()).collect();
        assert_eq!(codes.len(), ErrorCode::ALL.len(), "ALL lists a code twice");
        // Every message entry of the catalogue belongs to one code (the rest are short names).
        let shorts = super::text::ALL
            .iter()
            .filter(|entry| entry.name.ends_with("_SHORT"))
            .count();
        assert_eq!(super::text::ALL.len() - shorts, ErrorCode::ALL.len());
        for code in ErrorCode::ALL {
            let (ko, en) = (code.message_in(Lang::Ko), code.message_in(Lang::En));
            assert_eq!(ko, code.message_in(Lang::Ko), "{}", code.code());
            assert!(!en.trim().is_empty(), "{}", code.code());
            assert!(!has_hangul(en), "{}: Hangul in English", code.code());
            // Same sentence shape: a placeholder in one language is in the other, and a full stop
            // at the end stays a full stop.
            assert_eq!(ko.contains('{'), en.contains('{'), "{}", code.code());
            assert_eq!(ko.ends_with('.'), en.ends_with('.'), "{}", code.code());
            assert!(
                code.text_in(Lang::En)
                    .ends_with(&format!(" ({})", code.code()))
            );
            if let Some(name) = code.short_name_in(Lang::En) {
                assert!(!has_hangul(name) && !name.is_empty(), "{}", code.code());
            }
        }
    }

    #[test]
    fn english_rendering_fills_the_placeholder_and_keeps_the_code() {
        use yw_core::lang::Lang;
        assert_eq!(
            ErrorCode::Inp004.render_in(Lang::En, "3"),
            "Word 3 is not in the BIP39 English word list. (E-INP-004)"
        );
        assert_eq!(
            ErrorCode::Btc001.render_with_cause_in(Lang::En, "Esplora", Some(ErrorCode::Rpc002)),
            "Cannot connect to the Bitcoin indexer (Esplora). Try again in a moment or change the \
             indexer in Settings → Bitcoin. (E-BTC-001, E-RPC-002)"
        );
        assert_eq!(
            ErrorCode::Rpc003.code_with_name_in(Lang::En),
            "E-RPC-003 · Authentication refused"
        );
        assert_eq!(
            ErrorCode::Rpc003.code_with_name_in(Lang::Ko),
            "E-RPC-003 · 인증 거부"
        );
        assert_eq!(ErrorCode::Tx001.code_with_name_in(Lang::En), "E-TX-001");
        assert!(
            ErrorCode::Tx004
                .message_in(Lang::En)
                .contains("Do not send again")
        );
        assert!(!ErrorCode::Key002.message_in(Lang::En).contains('{'));
        assert!(
            ErrorCode::App009
                .text_in(Lang::En)
                .contains("%LOCALAPPDATA%\\YourWallet\\v3\\logs")
        );
    }

    #[test]
    fn unlock_failure_and_tamper_share_one_code() {
        assert_eq!(vault_code(VaultError::UnlockFailed), ErrorCode::Vlt001);
        assert_eq!(
            vault_code(VaultError::Key(KeyError::MnemonicUnknownWord {
                position: 2
            })),
            ErrorCode::Inp004
        );
        assert_eq!(vault_code(VaultError::OutOfMemory), ErrorCode::Vlt007);
        // A newer build's payload is not damage: no `.prev` restore is suggested.
        assert_eq!(
            vault_code(VaultError::UnsupportedPayload),
            ErrorCode::Vlt014
        );
        assert!(
            ErrorCode::Vlt014
                .text_in(Lang::Ko)
                .starts_with("새 버전 앱이 저장한 지갑입니다. 앱을 업데이트하세요.")
        );
    }
}
