# yw-app 화면·동작

상위 문서: [spec.md](../spec.md)

yw-app(지갑 본체, D3)의 프로세스·스레드 구조, 화면과 흐름, 승인 창, 비밀 입력·표시 창(D11), 자동 잠금(D12), 설정 파일, 오류·로그(D28), 파일 위치를 정한다. 다음은 다른 문서가 소유하며 이 문서는 소비만 한다.

| 소유 문서 | 이 문서가 쓰는 것 |
|---|---|
| [01](01-repo-build.md) | yw-win 안전 API 이름·시그니처(§7), 비밀 타입 규칙(§5.3) |
| [02](02-core-keys-vault.md) | `Vault` API·`VaultStatus`, 비밀번호·passphrase·니모닉 규칙 판정, 백업 challenge, reveal, meta 형식(§5.3), `.prev` 복구, VirtualLock 슬롯 |
| [03](03-evm.md) | 기본 EVM 체인 표(1·11155111·999, 공급자 템플릿 항목 `templates {quicknode_subdomain, alchemy_label}`, `default_caps`)·체인 확인(§1), 사용자 체인 `NetworkId` `eip155:<chainId>`와 런타임 `ChainInfo` 구성(§1), EVM 준비·수수료(§3.4, 사용자 체인 기본 상한 포함)·시뮬레이션과 그 상태 분류(§6)·위험 규칙(§10), `ApprovalRequest`·`ApprovalDisplay`·`FieldKey`(§11), 표시 정규 인코딩·digest(§11.3, 모든 체인 공통), `ApprovalStore`(§11.5), `format_units`, 저널, 가속·취소 |
| [05](05-browser.md) | pipe·디스패처, 연결 창 내용(§4.2), 잠금 중 동작(§4.4), 승인 큐 한도(§8.4), 요청 기한(§6.4), 오류 코드(§5) |
| [06](06-llm-explain.md) | AI 설명 패널 내용·상태, `llm_explain` 설정 |
| [07](07-solana.md)·[08](08-bitcoin.md) | SOL·BTC 보내기 흐름·표시 필드·경고, 받기 QR 내용, `solana` 설정, BTC 네트워크 선택·`bitcoin.indexer`·`bitcoin.esploraBaseUrl`의 의미([08] §2·§4.3), 네트워크별 공급자 템플릿 항목·연결 검사([07] §15.1, [08] §2) |

- yw-app은 unsafe 금지(D4)다. 모든 Win32 호출은 yw-win 안전 래퍼(§1.8)를 거치고, yw-app은 windows-sys에 직접 의존하지 않는다.
- 사용자에게 보이는 문자열은 한국어, 식별자·상수·코드·파일 이름은 영어다. 기술 용어(nonce, gwei, chainId, passphrase)는 그대로 쓴다.
- 주소는 yw-app 어디에서도 줄이지 않는다(`0x1234…abcd` 금지).

## 1. 프로세스와 스레드

### 1.1 실행 인자와 단일 인스턴스
상수: 단일 인스턴스 뮤텍스는 사설 네임스페이스 안에 둔다. 경계 설명자 이름 `YourWallet.v3`(`INSTANCE_BOUNDARY`), 별칭 `YourWalletV3`(`INSTANCE_ALIAS`), 뮤텍스 이름 `app.<세션 ID>`(`INSTANCE_MUTEX` + `ProcessIdToSessionId`, 전체 이름 `YourWalletV3\app.<세션 ID>`). 주 창 클래스 `YourWalletV3Main`, 인자 `--background`.
- 인자는 없음 또는 정확히 `--background` 하나만 허용한다. 그 밖이면 종료 코드 2.
- `process::SingleInstance::acquire_private(경계, 별칭, 이름)`([01] §7.6)의 값은 프로세스 끝까지 유지한다. 순서: `CreateBoundaryDescriptorW(경계)` → `AddSIDToBoundaryDescriptor(사용자 SID)` → `AddIntegrityLabelToBoundaryDescriptor(S-1-16-8192 Medium)` → `CreatePrivateNamespaceW(DACL D:P(A;;GA;;;<사용자 SID>), 별칭)`, 이미 있으면(`ERROR_ALREADY_EXISTS`) `OpenPrivateNamespaceW`(사라졌으면 최대 5회 재시도) → `CreateMutexW(같은 DACL, "<별칭>\<이름>")`. `Err(InstanceError::AlreadyRunning)`(`ERROR_ALREADY_EXISTS (183)`, 같은 프로세스가 네임스페이스를 이미 열었을 때의 `ERROR_DUP_NAME (52)`)이면 두 번째 인스턴스다([05] §8.1의 첫 pipe 인스턴스 검사는 그 뒤의 두 번째 방어선이다). 경계에 사용자 SID와 Medium 무결성 레이블이 들어 있으므로 이 사용자의 Medium 이상 프로세스만 네임스페이스를 만들거나 열 수 있다. 예전의 `Local\YourWallet.v3.app`은 세션의 아무 프로세스(Low 무결성 포함)나 먼저 만들어 지갑 시작을 막을 수 있었다(점유). 세션 ID를 이름에 넣어 세션마다 하나라는 예전 `Local\` 범위를 유지한다.
- 두 번째 인스턴스:
  - `--background`(yw-host가 실행, D24): 아무것도 하지 않고 종료 코드 0.
  - 인자 없음(사용자 실행): `ui::find_windows(YourWalletV3Main)`(`FindWindowExW`로 그 클래스의 최상위 창 최대 16개) → 각 `(poster, pid)`마다 `security::verify_process(pid, 자기 실행 파일)`([01] §7.6: `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` → 토큰 무결성 ≥ Medium(`GetTokenInformation(TokenIntegrityLevel)`) → `QueryFullProcessImageNameW`가 `current_exe()`와 같은 파일(정규화 후 대소문자 무시 비교)). 검증된 창에만 `process::allow_set_foreground_window(pid)` → `poster.post(WM_YW_ACTIVATE, 0)` → 종료 코드 0. 창 클래스 이름은 아무 프로세스나 등록할 수 있으므로, 검증에 실패한 창에는 전경 권한도 메시지도 주지 않는다. 창을 못 찾으면 200 ms 간격 10회 재시도 후 종료 코드 0. 끝까지 검증에 실패한 창만 찾았으면 오류 상자("실행 중인 Your Wallet 창을 확인하지 못했습니다. 같은 이름의 창이 이 실행 파일이 아닌 다른 프로그램(또는 다른 위치의 Your Wallet)에 속해 있어 전환하지 않았습니다. …") 후 종료 코드 10.
- 첫 인스턴스가 `WM_YW_ACTIVATE`를 받으면 주 창을 보이고(최소화면 `SW_RESTORE`) `SetForegroundWindow`. 잠겨 있으면 W02도 연다.
- `--background` 첫 인스턴스는 주 창을 숨긴 채 시작하고, 잠금 해제·승인이 필요한 요청이 오면 그 창만 띄운다(§2.5, §3.6).
- 주 창 닫기(X, Alt+F4) = 앱 종료(§1.5). 트레이 아이콘은 없다. 종료 뒤 dApp 요청이 오면 `settings.json`의 `browserAutoLaunch`가 true일 때만 yw-host가 `--background`로 다시 실행한다(D24, [05] §7.4). false면 yw-host가 요청마다 4900으로 응답한다. M5에서 Chrome job object 때문에 yw-app이 Chrome과 함께 종료되면 자동 실행을 끄고 수동 실행으로 바꾼다(D24, [05] §11-3).
- 종료 코드: 0 정상·인계, 2 인자 오류, 10 초기화 실패(데이터 폴더, 창 클래스, 주 창, 두 번째 인스턴스가 검증에 실패한 창만 찾음).

### 1.2 스레드
| 스레드 | 소유 | 하는 일 | 하지 않는 일 |
|---|---|---|---|
| UI `main` | 모든 HWND, `App` 상태, 승인 큐, 잠금 해제 동안의 평문 meta 사본 | 메시지 루프, 화면, 타이머, 자동 잠금 판정, 클립보드 | 16 ms를 넘을 수 있는 일(KDF, 네트워크, fsync) |
| 키 `yw-key` | `yw_core::Vault`(단독 소유, [02] §7.2), meta·journal 쓰기 | `KeyQueue` 처리: 생성·가져오기·잠금 해제·reveal·서명·백업 확인·meta 저장 | 네트워크 |
| RPC `yw-rpc` | `RpcConfig` 사본(§1.9) | `RpcJob` FIFO: 잔액, 수수료, nonce, 시뮬레이션, 전송, 영수증 | DEK 접근 |
| `yw-read-0..3` | [05] §8.4 read 작업 큐 | dApp read 전달([03] §12), `yw-rpc`와 같은 `yw_win::http::Client`(Send + Sync) 공유 | DEK 접근 |
| pipe | named pipe 연결 | [05] §8.3 | DEK 접근 |
| LLM `yw-llm` (M6) | 별도 `http::Client` | [06] | DEK 접근 |

- 비동기 런타임 크레이트를 쓰지 않는다. `std::thread`, `std::sync::{mpsc, Mutex, Condvar}`만 쓴다.
- `KeyQueue { q: Mutex<VecDeque<KeyJob>>, cv: Condvar }`. `KeyJob::Lock`만 `push_front`로 넣는다([02] §7.2 "lock 요청은 큐 맨 앞"). 키 작업자는 `Lock`을 처리하면서 큐에 남은 다른 작업을 모두 yw-app 오류 `KeyJobError::Locked`로 끝낸다(yw-core `KeyError`가 아님). 제어 작업 `Lock`·`Load`·`Shutdown`은 취소되지 않는다(§5.3이 `Lock` 뒤에 넣는 `Load`가 살아남아야 잠금 뒤의 vault 상태를 UI가 안다). `Lock`은 진행 중인 작업(최대 Argon2 2회) 뒤에 실행된다.
- 잠금 세대: UI가 `lock_epoch: u64`를 소유하고 §5.3 1단계에서 1 올린다. 모든 `KeyJob`은 넣을 때의 값을 싣고 `KeyResult`가 그 값을 되돌린다. UI는 값이 현재와 다른 결과를 버린다(실린 비밀 버퍼는 drop으로 소거). 예외: `Sign` 결과는 이미 소비된 승인이므로 epoch와 무관하게 처리한다(성공이면 저널 `Signed`가 커밋된 상태이므로 전송까지 진행하고, 잠긴 동안의 상태 처리는 §5.3 마지막 항목). 소비된 `Signing` 항목의 `Sign`이 `Locked`로 끝나면 dApp 4001 `User rejected the request.`, [03] §3.6 송신 슬롯 해제, 저널 기록 없음, 로그 `sign.aborted reason=locked`.
- 비밀 버퍼(비밀번호, passphrase, 니모닉, 개인키 입력)는 `Zeroizing<Vec<u8>>`로 채널에 이동한다(복사 금지). 받은 쪽은 쓰고 바로 drop한다.

### 1.3 이벤트 큐와 메시지 번호
```rust
pub const WM_YW_EVENTS: u32     = WM_APP + 1; // 0x8001, 이벤트 큐 초인종
pub const WM_YW_ACTIVATE: u32   = WM_APP + 2; // 두 번째 인스턴스 → 첫 인스턴스
pub const WM_YW_CHILD_DONE: u32 = WM_APP + 3; // 승인·비밀 창 → 주 창, wParam = 창 id
pub const WM_YW_LOCK_SHORTCUT: u32 = WM_APP + 4; // 메시지 루프 관찰자가 Ctrl+L(어느 창이든)을 보면 주 창에 post
pub const WM_YW_TAB_SHORTCUT: u32 = WM_APP + 5;  // Ctrl+1/2/3/4 → 주 창에 post(wParam 1–4), 주 창이 전경인 S10에서만 체인 탭(§2.1)
pub const EVENT_QUEUE_CAP: usize = 4096;
pub const MAIN_TIMER_MS: u32 = 250;           // 큐 보조 배출, 자동 잠금 판정, 기한 검사

pub enum UiEvent {  // Dapp: [05] 요청 도착·취소·연결 종료, Tx: [03]/[07]/[08] 저널·영수증, Llm: [06](u64 = generation)
    Key(KeyResult), Rpc(RpcJobId, Result<RpcOutput, RpcFailure>), Dapp(DappEvent), Tx(TxStatusUpdate),
    Llm(QueueId, u64, Result<Explanation, ExplainError>),
}
pub struct EventQueue { q: Mutex<VecDeque<UiEvent>>, poster: yw_win::ui::Poster }
impl EventQueue {
    pub fn push(&self, e: UiEvent) -> Result<(), QueueFull>; // len == EVENT_QUEUE_CAP이면 Err
    pub fn drain(&self) -> Vec<UiEvent>;                     // UI 스레드만 호출
}
```
- `push`는 큐가 비어 있다가 채워질 때만 `poster.post(WM_YW_EVENTS, 0)`(`PostMessageW`)을 보낸다. 실패해도 `MAIN_TIMER_MS` 타이머가 큐를 비운다.
- `QueueFull`: pipe 쪽은 그 요청에 내부 오류로 응답하고([05]), RPC 쪽은 결과를 버리고 작업 실패로 처리한다(로그 E-APP-005).
- 메시지 루프는 앱 전체에 하나다. 중첩 모달 루프(`MessageBoxW`, `DialogBox*`, 이식 코드의 `run_loop`)를 쓰지 않는다. 확인 대화상자는 주 창 안의 오버레이 패널이다. 이식 코드의 `PostQuitMessage`는 `WM_YW_CHILD_DONE`으로 바꾼다.

### 1.4 시작 순서
1. `process::init_process()`(`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800)`), `ui::init()`(`SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` + `InitCommonControlsEx`), `process::exclude_from_error_reporting()`([01] §5.4). 실패해도 계속하고 4단계에서 로그로 남긴다. WER 제외 실패는 로그만이 아니라 5단계 뒤 배너("Windows 오류 보고(WER) 제외 등록에 실패했습니다. 이 앱이 비정상 종료되면 메모리 덤프가 남을 수 있고, 덤프에는 잠금 해제 중인 지갑 키가 들어 있을 수 있습니다.")와 설정 → 보안 → "지갑 파일과 보호 상태" 줄로도 보인다(2026-11-01 검토 L9).
2. 인자 확인, 단일 인스턴스 뮤텍스(§1.1).
3. 환경 변수 `LOCALAPPDATA`가 절대 경로가 아니면 종료 코드 10. `%LOCALAPPDATA%\YourWallet\`, `v3\`, `logs\`를 이 순서로 `security::ensure_private_dir(폴더, 사용자 SID)`([01] §7.6)로 만들거나 검사한다(아래 1–4).
   1. 데이터 폴더 ACL(시작마다): 없는 폴더는 `CreateDirectoryW`에 SDDL `O:<사용자 SID>D:PAI(A;OICI;FA;;;<사용자 SID>)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)S:(ML;OICI;NRNW;;;ME)`를 줘서 만든다: 보호된 DACL(상속 끊음) — 사용자·SYSTEM·Administrators 모두 권한, 폴더와 파일에 상속(OI·CI) — 과 Medium 필수 레이블(no-read-up·no-write-up: Low 무결성 프로세스는 같은 사용자여도 안을 읽지도 쓰지도 못한다; DPAPI 사용자 범위의 `apikeys.dpapi`를 Low 프로세스가 읽어 `CryptUnprotectData`하는 길을 막는다). 안에서 만드는 `vault.ywv`·`meta`·저널·`settings.json`·`apikeys.dpapi`·로그는 이 ACE와 레이블을 상속한다(따로 설정하지 않는다).
   2. 이미 있는 폴더: 소유자·DACL·레이블(`GetNamedSecurityInfoW(OWNER|DACL|LABEL)`)을 읽는다. 소유자가 사용자·SYSTEM(`S-1-5-18`)·Administrators(`S-1-5-32-544`)가 아니면 거부. 위 상태(보호됨, 다른 SID에 허용 ACE 없음 — 상속된 읽기 전용 ACE도 포함, NULL DACL은 모두에게 허용으로 본다 —, 사용자 ACE가 OI·CI 모두 권한, 레이블 ≥ Medium·NR·NW·OI·CI)면 그대로 둔다. 아니면 `SetNamedSecurityInfoW(DACL|PROTECTED_DACL)`와 `(LABEL)`로 위 DACL·레이블을 다시 쓴다(하위 항목의 상속 ACE는 시스템이 다시 계산한다). 예: 프로필 전체에 다른 그룹(샌드박스 그룹 등)의 RX가 상속된 PC에서 예전 빌드가 만든 폴더 — 조용히 고치고 로그 `datadir.acl_repaired`(dir, folder, entries)를 남긴다. 고친 뒤에도 다른 SID가 허용되면 거부. 다시 쓰기에 실패했는데 다른 SID 허용이 없으면(보호·레이블만 빠짐) 계속한다.
   3. 폴더 바로 안의 항목(재분석 지점 제외): 소유자가 위 세 SID가 아니면 거부. 다른 SID에 허용 ACE가 있으면 명시 DACL을 빈 비보호 DACL로 바꿔(`UNPROTECTED_DACL`) 폴더에서 상속된 ACE만 남긴다.
   4. 거부(`PrivateDirError::Untrusted`): 오류 상자("데이터 폴더(%LOCALAPPDATA%\YourWallet)를 열지 않았습니다. 이 폴더나 안의 파일이 다른 계정의 소유이거나, 이 사용자가 고칠 수 없는 방식으로 다른 계정에 열려 있습니다. 지갑 파일을 보호하기 위해 시작을 멈춥니다.") 후 종료 코드 10. 폴더가 재분석 지점이거나 폴더가 아니거나 만들 수 없으면 기존 "데이터 폴더를 만들지 못했습니다…" 후 종료 코드 10. 앱은 데이터 폴더 밖의 ACL을 바꾸지 않는다(`%LOCALAPPDATA%` 등 상위 폴더의 상속 상태와 무관하게 동작).
4. 로그 시작(§8), `app.start`(버전, OS 빌드, `--background` 여부).
5. `settings.json`(§6.1), `apikeys.dpapi`(§6.3) 읽기. 실패 항목은 기본값 + 배너.
6. 창 클래스 등록(§1.7), 주 창 생성(숨김). `session::register_session_notifications(&main)`(`WTSRegisterSessionNotification`, `NOTIFY_FOR_THIS_SESSION = 0`). 실패하면 1초 간격 최대 30회 재시도, 끝내 실패하면 배너 E-APP-004.
7. 키·RPC·read 작업자, pipe 서버 시작([05]: 프로세스 시작 2 s 안). pipe 생성 실패는 치명이 아니다(배너 E-PIPE-001, 브라우저 연동 없이 계속). 단일 인스턴스 뮤텍스를 쥔 채 첫 인스턴스 생성이 `AlreadyExists`면 이 사용자의 고정 pipe 이름을 다른 프로그램이 점유한 것이다: 로그 `pipe server.squatted`(E-PIPE-002) + 배너 E-PIPE-002, 상태 줄 `브라우저: 사용 불가 E-PIPE-002`, 브라우저 연동 없이 계속([05] §8.1).
8. 키 작업자가 `Vault::load` → `VaultStatus`([02] §6.3)를 보고한다.
9. `--background`가 아니면 주 창을 표시한다(S01·S07·S09). `Locked`면 W02를 자동으로 연다.
10. 메시지 루프.

### 1.5 종료 순서
계기: 주 창 `Msg::Close`(`WM_CLOSE`), `Msg::EndSession`(`WM_ENDSESSION`, wParam = TRUE), `Msg::SessionLogoff`(`WM_WTSSESSION_CHANGE`, wParam `WTS_SESSION_LOGOFF (0x6)`). `Msg::QueryEndSession`(`WM_QUERYENDSESSION`)에는 `Reply::Handled(1)`(TRUE)을 반환하고 종료 절차는 시작하지 않는다(`Msg` 변형은 [01] §7.7).
1. `AppMode::ShuttingDown`. pipe 서버가 새 요청을 받지 않게 한다([05]).
2. 잠금 절차(§5.3, `LockReason::Shutdown`).
3. 큐와 창의 모든 항목 → `QueueOutcome::Shutdown`.
4. 키 작업자의 `LockDone`을 최대 5초 기다린 뒤 채널을 닫는다(저널 쓰기 중단 방지). RPC·read·LLM 작업자에는 종료를 알리고 최대 2초 join한다(진행 중 호출이 끝나지 않으면 기다리지 않고 다음 단계로 간다). 전송·영수증 확인은 다음 시작 때 저널이 이어받는다([03]).
5. `session::unregister_session_notifications`, 창 파괴.
6. `app.stop`, 로그 flush, 종료 코드 0. `panic = "abort"`(D28)이면 이 절차가 돌지 않으며, 디스크 일관성은 원자적 쓰기(§9)와 저널이 지킨다.

### 1.6 DPI·글꼴·색
- 크기 상수는 96 DPI 기준 DIP이고 `GetDpiForWindow`로 환산한다. `WM_DPICHANGED`: lParam 제안 사각형으로 `SetWindowPos`, 새 DPI로 글꼴을 다시 만들고 다시 배치한다.
- 확인함(M3): yw-app `build.rs`의 `cargo:rustc-link-arg-bins=/MANIFEST:EMBED`·`/MANIFESTINPUT:<yw-app.manifest>`로 comctl32 v6·PerMonitorV2 매니페스트가 들어간다(같은 `build.rs`가 아이콘 리소스도 링크한다, §1.7). 매니페스트는 필수다(없으면 `InitCommonControlsEx(ICC_STANDARD_CLASSES)`가 실패). 매니페스트가 DPI를 먼저 정하므로 `ui::init`의 `SetProcessDpiAwarenessContext`는 `ERROR_ACCESS_DENIED`를 돌려주고 이를 성공으로 본다([01] §7.7).
- 테마는 라이트만. 모든 창(주 창, 비밀 창 W01–W10, 승인 창 A01)은 아래 디자인 시스템(`ui::theme`)만 쓴다. 검토 기록은 `docs/ux-review-20261028.md`, `docs/ux-review-20261031.md`, `docs/ux-review-20261107.md`.
- 글꼴 크기 단계(본문 `Malgun Gothic`, 없으면 `Segoe UI`; 고정폭 `Consolas`): 보조 문구·도움말 9pt, 본문·라벨·버튼 10pt(굵게 = 강조), 카드 제목 굵게 11pt, 승인 창 요약 굵게 12pt, 화면 제목 굵게 14pt, 잔액·환영 제목 굵게 20pt. 주소·해시·hex·개인키 `Consolas` 10pt(강조 묶음 굵게), 니모닉 표시 `Consolas` 14pt, calldata 등 hex 원본 `Consolas` 9pt.
- 간격은 4 DIP 격자: 4(묶음 안) · 8(관련 줄) · 12(카드 안 항목) · 16(카드 안쪽 여백·카드 사이) · 24(창 여백). 모서리 반지름 카드 8, 버튼·띠 6. 주 창 내용 폭은 최대 880 DIP(넓은 창에서는 가운데).
- 구성 요소: 회색 창 배경 위의 흰 **카드**(구역마다 하나, 제목 11pt), 카드 제목 아래·기술 입력 칸 아래의 **도움말 줄**(9pt, 평이한 한국어로 "무엇이고 왜 필요한지"), 라벨·값 줄, 단계 표시(1/3 2/3 3/3), 큰 잔액 표시. 기술 설정(수수료 상한, CU 가격, 로그 수준, 제네시스 해시, 가스 계산식)은 `고급 설정 보기 ▸`(보내기 폼은 `수수료 계산 보기 ▸`) 뒤에 둔다.
- 버튼(yw-win 소유자 그리기 `ControlKind::Button(ButtonStyle)`): **주 버튼**(파랑 채움, 화면마다 하나 — 체인 탭은 `보내기`·`받기` 두 개), **보조 버튼**(흰 바탕·회색 테두리), **위험 버튼**(흰 바탕·빨간 테두리·빨간 글자: 삭제·연결 해제·폐기·격리), **링크 버튼**(글자만: `← 메인으로`, `고급 설정 보기 ▸`, `새로고침`), **탭·칩**(선택 = 파랑 채움: 체인 탭, 네트워크, 설정 구역). 비활성은 회색. 체크박스·라디오·읽기 전용 칸의 배경은 놓인 카드·창 색을 따른다.
- 상태 색은 뜻마다 하나이고, 띠에는 항상 상태 이름 태그를 붙인다(색만으로 구분하지 않는다): **정보**(파랑), **완료**(초록), **주의**(노랑), **고위험**(빨강 띠), **차단**(진한 빨강 채움·흰 글자: 그 기능을 멈춤 — 차단된 체인, 손상된 저널, 수수료 상한 초과, 승인할 수 없는 요청), **오류**(빨강 띠: 코드가 있는 실패·입력 오류), **테스트넷**(연파랑). Bitcoin 네트워크 배너(`BITCOIN MAINNET`·`BITCOIN TESTNET4 — 가치 없음`)는 태그 없이 전용 색을 쓴다.
- 색 토큰(`ui::theme`, [06]이 참조):

```text
BG #F3F4F6 창 배경            CARD #FFFFFF 카드              CARD_BORDER #E1E4E8 카드 테두리·구분선
TEXT #1F1F1F 본문             MUTED #5F6368 보조 문구·오래된 잔액   BORDER #C8C8C8 입력 칸 테두리
FOCUS·PRIMARY_BG #0F6CBD 포커스·주 버튼·진행   ESCAPE_TEXT #A4262C 이스케이프 표기(§3.3)
INFO_BG #E8F1FB / INFO_TEXT #0F4C81 정보       SUCCESS_BG #DFF6DD / SUCCESS_TEXT #0E700E 완료
WARN_BG #FFF4CE / WARN_TEXT #7A5C00 주의·주소 주석   DANGER_BG #FDE7E9 / DANGER_TEXT #A4262C 고위험·오류
BLOCKED_BG #A4262C / BLOCKED_TEXT #FFFFFF 차단   TESTNET_BG #E8F0FE 테스트넷 띠·배지
AI_PANEL_BG #F3F0FA / AI_PANEL_BORDER #D9D0EE [06] AI 패널   QR_DARK #000000 / QR_LIGHT #FFFFFF
BTC_MAINNET_BG #C42B1C / BTC_MAINNET_TEXT #FFFFFF, BTC_TESTNET4_BG #F7A23B(글자 TEXT) [08] §2 네트워크 배너(A01 헤더)
```

#### 1.6.1 체인 배지 (2026-11-06)
- 체인·네트워크 이름 앞에는 작은 둥근 배지를 그린다(`ui::badge::Badge`, 본문 옆 16 DIP·화면 제목 옆 20 DIP, 글자와 6 DIP 간격): 체인 탭(`EVM`·`Solana`·`Bitcoin`), S10 네트워크 칩(EVM 체인마다)·Solana 클러스터 칩, 보내기·받기 제목과 카드 제목, 보내기 결과의 상태 줄, S10 활동 카드 제목, S13 연결된 사이트의 `네트워크` 줄, S14 계열 탭·카드 제목·Bitcoin 네트워크 줄, S15 `EVM 체인` 목록, 승인 창 헤더의 `네트워크` 값(앞). HyperCore 화면은 `Badge::hyperliquid()`를 쓴다.
- 배지는 **원래 그린 단순 표식**이다(공식 로고 파일·상표 이미지를 복사하지 않는다): Ethereum 남보라 원 + 두 조각 마름모, Sepolia 같은 표식(테스트넷 처리), Arbitrum One 남색 원 + 파란 육각형 + "A", Base 파란 원 + 흰 고리, BNB Smart Chain 노란 원 + 속이 빈 흰 마름모, Robinhood Chain 초록 원 + "R", HyperEVM·Hyperliquid 짙은 청록 원 + 청록 "H", Solana 짙은 원 + 비스듬한 막대 셋(청록→보라), Bitcoin 주황 원 + "₿", Zcash 금색 원 + 어두운 "Z"([12](12-zcash.md) §11; testnet도 테스트넷 처리). EVM 계열(탭·주소록)은 회청색 원 + 마름모. 사용자 추가 체인은 이름의 첫 ASCII 영문자·숫자(없으면 마름모)를 흰 글자로, 원 색은 chainId에서 정한 색상(채도·명도 고정)으로 그린다. 테스트넷(Sepolia·Solana devnet·Bitcoin testnet4)은 원 색을 회색 쪽으로 45% 흐리게 하고 오른쪽 아래에 흰 원 + "T"를 붙인다.
- 그리기: 단위 정사각형 안의 도형(원·고리·선분·호·다각형) 부호 거리로 픽셀마다 1픽셀 안티에일리어싱 덮임을 계산해 미리 곱한 `0xAARRGGBB`를 만들고(그 DPI의 픽셀 크기로 매번 다시 계산, 비트맵 파일 없음), GDI `AlphaBlend`로 합성한다(`yw_win::ui::PaintDc::draw_argb`; 소유자 그리기 버튼은 `Control::set_icon` — 배지, 6 DIP, 라벨을 함께 가운데 정렬). 그래서 100–200% DPI와 직접 그리는 승인 창에서도 같은 선명도다. 배지는 표시 장식이며 승인 digest·표시 모델([03] §11)에 들어가지 않는다.

### 1.7 창 클래스
시작 때 한 번만 등록한다(이식 코드처럼 호출마다 `RegisterClassW`를 부르지 않는다).

| 클래스 | 용도 | 스타일 | 확장 스타일 | 비밀 클래스 |
|---|---|---|---|---|
| `YourWalletV3Main` | 주 창(화면은 자식 패널) | `WS_OVERLAPPEDWINDOW\|WS_CLIPCHILDREN\|WS_VSCROLL` | `WS_EX_APPWINDOW` | 아니오 |
| `YourWalletV3Panel` | 화면 패널, 직접 그리는 목록 | `WS_CHILD\|WS_CLIPCHILDREN\|WS_VSCROLL` | — | 아니오 |
| `YourWalletV3Approval` | 승인·연결 창 | `WS_OVERLAPPED\|WS_CAPTION\|WS_SYSMENU\|WS_THICKFRAME\|WS_MINIMIZEBOX` | `WS_EX_TOPMOST\|WS_EX_APPWINDOW\|WS_EX_DLGMODALFRAME` | 아니오 |
| `YourWalletV3SecretInput` | 비밀 입력 창 W01–W07, W10 | `WS_OVERLAPPED\|WS_CAPTION\|WS_SYSMENU` | `WS_EX_APPWINDOW\|WS_EX_DLGMODALFRAME` (dApp 요청으로 연 W02·W06은 `\|WS_EX_TOPMOST`) | 예, `capture: CaptureExclusion::Preferred` |
| `YourWalletV3SecretView` | 비밀 표시 창 W08·W09 | `WS_OVERLAPPED\|WS_CAPTION\|WS_SYSMENU` | `WS_EX_APPWINDOW\|WS_EX_DLGMODALFRAME` | 예, `capture: CaptureExclusion::Required` |

- 비밀 클래스는 `ClassSpec { name, secret: true, capture }`로 등록한다([01] §7.7). `capture`는 캡처 제외 실패 처리다(§4.5): `Required` = 창 파괴·비밀 미표시, `Preferred` = 창 유지·경고 배너. 비밀 아닌 클래스에는 캡처 제외를 적용하지 않는다.
- **앱 아이콘**: 둥근 사각 타일(왼쪽 위 짙은 남색 `#352A9C` → 오른쪽 아래 청록 `#0B8A80` 대각 그라데이션) 위의 흰 지갑(둥근 몸통, 덮개 선, 오른쪽 끈과 둥근 똑딱단추). 독자 도안이며 다른 지갑의 로고(여우·토끼 등)를 닮지 않는다. `scripts/make-icons.mjs`가 절차적으로(부호 거리 도형 + 초과 표본 안티에일리어싱) 그리고, 32 px 이하는 가장자리를 픽셀 격자에 맞추고 24 px 이하는 끈을 똑딱단추 점만 남겨 16 px에서도 읽히게 한다. 출력: `crates/yw-app/icons/yw-app.ico`(16·20·24·32·40·48·64 = 32비트 BMP, 256 = PNG)와 같은 이미지의 컴파일된 리소스 `yw-app.res`(RT_ICON 1–8 + RT_GROUP_ICON 1, 언어 0x0409), 미리 보기 `docs/icon-preview.png`. `build.rs`가 `.res`를 링크 인자로 넘긴다([01] §2.4). 모든 클래스의 `hIcon`·`hIconSm` = 그 그룹을 `LoadImageW`로 `SM_CXICON`·`SM_CXSMICON`(시스템 DPI) 크기로 읽은 것(프로세스당 한 번, 해제 안 함; 리소스가 없는 테스트 바이너리는 `IDI_APPLICATION`, [01] §7.7). 제목 표시줄(`WS_EX_DLGMODALFRAME` 창 포함, Windows 11에서 확인)·작업 표시줄·Alt-Tab은 클래스 아이콘을, 탐색기·시작 메뉴 바로가기(`yw-app.exe,0`, [01] §9.2)는 exe의 아이콘 그룹을 쓴다. 생성 결과는 커밋하고 check.ps1 icons 단계(30)가 같은지 확인한다.

주 창 960×680 DIP(최소 720×520), 비밀 창 640×480(W04·W10은 640×560, W05는 24칸 때문에 720×600, W08·W09는 820×680), 승인 창 §3.6. M3 주 창은 화면을 직접 그리고 표준 컨트롤을 직접 소유한다. 세로 스크롤 막대는 늘 보이고 내용이 창에 다 들어가면 비활성이다(`SIF_DISABLENOSCROLL`, 내용에 따라 폭이 바뀌지 않는다). 스크롤(휠·터치패드는 1/120 단위로 누적, 한 칸 = `SPI_GETWHEELSCROLLLINES`줄 × 20 DIP, 마우스 휠 한 칸은 약 60 ms 동안 4단계로 미끄러진다; 막대 화살표 20 DIP, 막대 안 클릭 한 쪽, 엄지 끌기는 실시간)은 다시 배치하지 않는다: 배치된 사각형을 옮기고 `ScrollWindowEx(SW_SCROLLCHILDREN|SW_INVALIDATE)`로 남는 픽셀·자식 컨트롤을 함께 옮긴 뒤 드러난 띠만 그린다(`app_scroll`). 보기 가장자리를 넘는 컨트롤만 보이기·숨기기를 바꾼다. 띠와 자식 컨트롤은 그 스크롤을 처리한 메시지 핸들러가 끝난 직후, 다음 메시지를 꺼내기 전에 동기로 그린다(yw-win `Window::update_now`): 핸들러 안에서 바로 보낸 `WM_PAINT`는 앱 상태가 빌려진 채라 그릴 수 없어 기본 처리로 유효화만 되고 옛 픽셀(버튼·글자의 겹친 잔상)이 남았다(2026-11-07). 같은 이유로 바쁜 동안 온 `WM_PAINT`는 버리지 않고 미뤄 두었다가(`Window::defer_paint`) 실행 중인 핸들러가 모두 끝나면 다시 그린다. `YourWalletV3Panel`·`YourWalletV3Approval`은 owner-draw 목록·승인 창이 생기는 M4에서 등록한다.

### 1.8 yw-win 사용 API
이름·시그니처·오류 타입의 정본은 [01] §7이다(D31). yw-app이 쓰는 것:

| 용도 | yw-win API([01] §7) |
|---|---|
| 창 | `ui::{init, register_class(&ClassSpec { name, secret, capture: CaptureExclusion }), create_window(&WindowSpec, Box<dyn Handler>) -> Result<Window, UiError>}`, `Handler::on(&mut self, &Window, &Msg) -> Reply`, `Window::{show, hide, …, poster}`, `ui::controls`(비밀 아닌 값) |
| 루프·깨우기 | `ui::run_loop(observe)`(§5.1 유휴 입력), `ui::Poster::post(msg, wparam)`(§1.3) |
| 캡처 제외 | `ui::exclude_from_capture(&Window) -> Result<(), UiError>`(`UiError::CaptureExclusionFailed`). 비밀 클래스는 `create_window`가 숨긴 채 적용하고, 실패 처리는 `ClassSpec.capture`(`CaptureExclusion::{Required, Preferred}`)를 따른다(§1.7, §4.5) |
| 그리기·입력 | `PaintDc::{fill_rect, round_rect, ellipse, draw_text, measure, select_font}`, `Font::create`, `input::is_down(vk)`. 버튼은 `ControlKind::Button(ButtonStyle)`(소유자 그리기, §1.6 스타일을 yw-app이 넘긴다), `Control::{set_backdrop, set_button_style}`(체크박스·라디오·버튼 모서리 배경 = 놓인 카드·창 색) |
| 화면 투어(개발 전용) | `ui::capture::{capture_client, dev_tour_redraw, dev_tour_flush, dev_tour_lift_capture_exclusion}`, 스크롤 잔상 점검용 `dev_tour_post_wheel`·`dev_tour_post_vscroll`·`dev_tour_app_env`·`dev_tour_clear_of_pointer` — `#[cfg(debug_assertions)]`라 release 빌드에 없다. 앱 코드는 쓰지 않고 `ui::tour`(`#[ignore]` 테스트)만 쓴다(§11) |
| 클립보드 | `clipboard::{set_text, set_secret_text -> SecretClip, clear_secret(owner, &SecretClip), read_text(owner, max) -> (WipeBuf<u16>, u32), clear_if_unchanged}`, `ClipError::{Busy, TooLong, Os}` |
| 단일 인스턴스 | `process::SingleInstance::acquire_private`, `ui::find_windows -> Vec<(Poster, u32)>`, `security::verify_process`, `process::allow_set_foreground_window`(§1.1) |
| 세션·전원·종료 | `session::{register_session_notifications, unregister_session_notifications}`, `Msg::{SessionLock, SessionUnlock, SessionDisconnect, SessionLogoff, Suspend, Resume, QueryEndSession, EndSession}`(§1.5, §5.1) |
| DPAPI·파일 | `dpapi::{protect -> Vec<u8>, unprotect -> WipeBuf<u8>}`(`WinError`), `file::{atomic_write, read_limited, ensure_dir}`(`FileError`) |
| HTTP | `http::{Client, HttpsUrl, Timeouts}`(§1.9) |

- yw-win은 zeroize를 쓰지 않으므로 비밀은 `WipeBuf`로 돌려준다. yw-app은 받은 즉시 쓰거나 yw-core 비밀 타입(`yw_core::secret`의 `Zeroizing` 재수출)으로 옮긴 뒤 drop한다([01] §5.3).
- 비밀 클래스의 메시지 차단(§4.4 목록)과 재진입 처리는 [01] §7.7이다. 차단된 메시지는 핸들러에 오지 않는다.
- `Msg::MouseActivate`: 승인·비밀 창은 자신이 전경 창이 아니면 `Reply::Handled(MA_ACTIVATEANDEAT = 2)`(클릭 관통 방지, 이식 `archive/spec-v2.4:crates/approval-ui/src/native.rs:996-1005`).

모듈 배치(yw-app 정본, EVM 모듈 이름은 [03] §0과 같다; [01] §2.1 트리는 이 목록을 따른다): `crates/yw-app/src/{lib,main,app,events,settings,apikeys,logging,errors,store}.rs`, `workers/{key,rpc,read}.rs`(§1.2), `rpc/{mod,evm}.rs`(`mod` = 공용 전송 §1.9, `rpc::evm` = EVM RPC 호출·JSON↔코어 타입; eth_simulateV1 응답 파서만 M2, 나머지 M4), `flow/evm.rs`(`flow::evm`: EVM 처리 순서·저널 I/O·영수증 추적, M4), `browser/`(M5, [05]: `browser::envelope` §6.5, `browser::params` §3.3–3.4, 디스패처), `explain/`(M6, [06]), `sol/{rpc,flow,scan}.rs`(M7, [07]), `btc/`(M8, [08]), `ui/{main_window,screens/*,approval,interaction,secret,secure_field,text_layout,qr,theme}.rs`.

### 1.9 RPC 전송 (모든 체인 공용)
[03] §1.4, [05] §3.5, [07] §15.2, [08] §4.1이 말하는 공용 전송 규칙이다.
- 전송: yw-win `http::Client`([01] §7.4: https만, TLS 1.2/1.3, 리다이렉트·쿠키·인증 끔, Origin 헤더 없음). `yw-rpc`·`yw-read-*`가 `Arc<Client>` 하나를 공유하고 `yw-llm`은 따로 만든다. `Timeouts { resolve 5 s, connect 5 s, send 10 s, receive 10 s }`([03] §1.4 호출당 10 s).
- `RpcConfig { endpoints: Vec<(NetworkId, HttpsUrl)>, evm_chains: Vec<EvmChainDef>, genesis_pins: Vec<(NetworkId, [u8; 32])>, btc_indexer: BtcIndexer, esplora_base: [(NetworkId, HttpsUrl); 2] }`, `pub enum BtcIndexer { Esplora, BbRpc, BbRest }`(설정 문자열 `"esplora"`/`"bb-rpc"`/`"bb-rest"`), `esplora_base` = `bitcoin:mainnet`·`bitcoin:testnet4` 순서의 `bitcoin.esploraBaseUrl` 값. `endpoints` = §6.3 `rpc:<NetworkId>` 값 전부, 체인 정의·고정 제네시스·`bitcoin.indexer`·`bitcoin.esploraBaseUrl`은 §6.1(D10: 지갑 비밀 아님).
- **엔드포인트(D13, 공급자 무관)**: 네트워크(`eip155:<chainId>`, `solana:<cluster>`, `bitcoin:<net>`)의 URL = `endpoints`의 그 `NetworkId` 값뿐이다. 공급자 템플릿 자격 정보(§6.3 `tpl:*`)는 URL을 만드는 입력 편의(§2.11.1)일 뿐 런타임에 쓰지 않고 작업자에 보내지 않는다. 다른 네트워크·다른 공급자 URL로 대체(fallback)하지 않는다. 값이 없으면 엔드포인트 없음: 그 네트워크의 호출을 하지 않고 E-KEY-005(EVM 준비·서명은 [03] E35 차단 → §3.5 `Failed { code: E-KEY-005, retryable: false }`, dApp read는 [05] §5 `ChainUnavailable`, SOL 미리보기 시작 안 함 [07] §15.1, BTC는 켤 수 없음 [08] §2), 상태 줄 "엔드포인트 없음". 템플릿으로 만든 URL·직접 입력한 URL·사용자 체인 URL 모두에 체인 확인([03] §1.4, [07] §15.1, [08] §2)을 똑같이 한다. BTC는 그 URL로 Core JSON-RPC(POST)를 쓰고, 주소 인덱서는 `btc_indexer`로 정한다([08] §2·§4): `Esplora`(기본) = `esplora_base`의 그 네트워크 URL ‖ 경로 GET(`http::Client::get`, 같은 `Arc<Client>`, 인증 없음; 비밀이 아니라 settings.json에 있다), `BbRpc` = Core URL에 `bb_*` JSON-RPC POST, `BbRest` = `<Core URL, 끝 '/' 제거>/api/v2/<경로>` GET. Esplora URL은 대체 경로가 아니라 별도로 설정한 원천이다. Core 전송 실패 시 Esplora `POST /tx`는 사용자 확인 뒤에만 한다([08] §11.3). URL·체인 정의·고정 제네시스·`bitcoin.indexer`·`bitcoin.esploraBaseUrl`을 바꾸면 새 `RpcConfig`를 작업자에 보내고 해당 네트워크의 체인 확인 상태를 초기화한다(BTC는 [08] §2 연결 검사를 다시 한다).
- 체인 확인 결과 표시(EVM, 판정은 [03] §1.4): chainId 불일치 → E-RPC-006. 제네시스 불일치는 상수 제네시스 체인(1·11155111·42161·8453·56·4663)이면 E-RPC-006, 최초 신뢰로 고정한 체인(HyperEVM 999·사용자 체인)이면 E-CHN-008 "체인 정보가 바뀌었습니다 (제네시스 불일치)" + `다시 고정`(§2.17.4). 두 경우 모두 그 체인은 읽기·보내기·서명이 차단된다. HyperEVM은 고정값이 없을 때 첫 체인 확인(`eth_chainId` 일치)에서 받은 블록 0 해시를 고정한다: RPC 작업자가 `UiEvent::Rpc`로 알리면 UI 스레드가 `settings.json` `evmGenesisPins`(§6.1)에 쓰고 배너 T-GENESIS-PINNED. 쓰기 실패 → E-APP-002, 이번 실행 동안 메모리 값으로 비교한다. 여러 작업자가 동시에 관측하면 먼저 온 값을 고정하고 나머지는 비교한다.
- JSON-RPC 2.0, 요청마다 증가하는 u64 `id`, 응답 `id` 대조. 응답 상한(`max_response`)은 메서드별로 체인 문서가 정하고([03] §1.4, [07] §15.2, [08] §4.2–4.3, dApp read는 [05] §3.5), 정하지 않은 호출은 1 MiB.
- 재시도: 체인 문서가 정한 경우만([03] §1.4·§4.4, [08] §4.4). 그 밖에는 재시도하지 않고 §7 코드로 실패한다(사용자 `다시 시도`). 분류: `HttpError::Timeout` → E-RPC-002, `Tls` → E-RPC-008, `TooLarge` → E-RPC-005, `Os` → E-RPC-001, HTTP 401·403 → E-RPC-003, 429 → E-RPC-004.
- 로그·화면에는 엔드포인트를 `NetworkId`로만 가리킨다. URL은 어느 부분도(호스트 포함 — QuickNode 호스트에는 엔드포인트 이름이 들어간다, 경로·쿼리·토큰) 쓰지 않는다(D13, D28, §8). yw-app은 `HttpsUrl`을 `Display`·`Debug`로 포맷하지 않는다([01] §7.4의 `Display`는 호스트를 보이므로 로그·화면·오류 문자열 경로에 넣지 않는다). 설정 화면의 URL은 §2.11.1 가린 형태만 보인다.

## 2. 화면과 흐름

### 2.1 앱 상태와 화면 목록
```rust
pub enum AppMode { NoVault, Locked, Unlocking, PassphraseRequired, PassphraseMismatch, BackupPending,
                   Unlocked { alt_passphrase: bool }, Corrupt { prev_available: bool }, MainMissing, ShuttingDown }
```
`AppMode`는 [02] `VaultStatus`에 진행 상태(`Unlocking`, `ShuttingDown`)를 더한 화면용 사본이다.
- 주 창 화면: S01 첫 실행(`NoVault`), S02 생성 안내, S03 처리 중(KDF 진행 표시), S04 백업 대기(`BackupPending`), S05 가져오기, S06 첫 주소 확인, S07 잠금 화면(`Locked`·`PassphraseRequired`), S08 완료, S09 복구(`Corrupt`·`MainMissing`), S10 메인(`Unlocked`), S11 보내기·결과, S12 받기, S13 연결된 사이트, S14 주소록, S15 설정, S16 토큰 추가, S17 EVM 체인 추가·편집(§2.17), S18 개인키로 시작하기(체인·주소 형식), S19 개인키 주소 확인(§2.18), S20 YubiKey 지갑 만들기, S21 YubiKey 등록 마법사(§2.19), S22 지갑 초기화(§2.20), S23 Chrome 확장 설치(§2.21).
- 별도 최상위 창: W01–W12 비밀 창(§4.1; W11·W12는 YubiKey, [10]. 옛 W13 "새 PIV 관리 키"는 2026-11-06에 없앰), A01 승인·연결 창(§3).
- 비밀 창이 열려 있는 동안 주 창은 `EnableWindow(FALSE)`다. 승인 창은 주 창을 막지 않는다.
- 주 창 자식 컨트롤의 명령 ID(`WM_COMMAND`)는 화면 모듈마다 `ids`에 두고, 고정 ID와 목록형 범위(계정·주소록·스캔 행·사이트 등)가 서로 겹치지 않으며 각 범위가 그 목록의 최대 길이(행 수 × 행당 ID 수)를 담는다. 전체 지도와 시험은 `ui::command_ids`(1·2는 쓰지 않음). 승인 창·비밀 창은 자식 컨트롤 없이 직접 그리고 영역으로 판정하므로 명령 ID가 없다.
- `Unlocked`의 S10 상단 막대(흰 띠): 왼쪽 "Your Wallet", 오른쪽 `주소록`, `사이트·WalletConnect`(S13, 2026-11-07 — 확장 연결과 WalletConnect가 같은 화면임을 이름에 보인다), `설정`, `잠금 (Ctrl+L)`. 그 아래 체인 탭(`EVM (이더리움 등)`·`Solana`·`Bitcoin`·`Zcash`, 탭 모양; 키보드 Ctrl+1·Ctrl+2·Ctrl+3·Ctrl+4 — 메시지 루프 관찰자가 숫자 키 '1'–'4'(`events::chain_tab_key`)를 보면 주 창에 `WM_YW_TAB_SHORTCUT`(`WM_APP + 5`, wParam = 탭 번호)을 post하고, 주 창이 전경이고 S10이 그 탭을 켜 보이며 비밀 창이 없을 때만 탭을 누른 것과 같이 처리한다)과 네트워크 칩. 다른 화면은 맨 위 링크 `← 메인으로`. `alt_passphrase == true`(`App::passphrase_unverified()`)이면 **모든 화면** 맨 위에 닫을 수 없는 고위험 띠 T-ALT-PASS를 보이고, 모든 체인의 `받기`(S12)를 끈다(누르면 T-ALT-PASS-RECV). 브라우저 다리는 이 상태의 연결·서명 요청을 4100 `PassphraseUnverified`(이유를 담은 메시지)로 끝내고(디스패처 상태 `VaultView::PassphraseUnverified`, 큐에 있던 요청은 §3.1 `PassphraseUnverified`), 읽기 요청은 계속 처리한다([02] §7.5, [05] §4.2·§5). 앱의 보내기는 허용한다.
- 사용자에게 보이는 용어: "니모닉"은 "복구 단어"로 부르고 처음 나오는 곳에 "(니모닉)"을 붙인다. 오류 문구(§7)와 코드는 바꾸지 않는다.

### 2.2 첫 실행 (S01)
- `NoVault`일 때. 데이터 폴더에 `meta.ywm`·`journal.ywj` 또는 그 `.prev`가 남아 있으면 생성·가져오기 버튼을 끄고 T-LEFTOVER와 폴더 경로, `폴더 열기`(§2.14), 링크 `남은 파일을 reset- 폴더로 옮기기…`(§2.20)를 보인다. 파일은 사용자가 직접 옮기거나 §2.20으로 옮긴다([02] §6.3). 앱이 지갑 파일을 옮기는 것은 사용자가 확인한 §2.20뿐이고, 지우지는 않는다. 검사는 데이터 폴더 자체만 보므로 `reset-*` 하위 폴더의 파일은 막지 않는다.
- 환영 화면(2026-11-08 두 묶음으로 정리 — 기본 창 첫 화면에 다섯 입구가 모두 보인다; 이전에는 카드 네 개를 세로로 늘어놓아 `YubiKey 연결하기 (복구 단어 없이)`가 스크롤 맨 아래였다): 큰 제목 "Your Wallet", T-FIRST-1의 앞 두 문장(무엇인지 · 모든 서명은 이 앱 확인 창에서), 카드 "새로 시작합니다"(설명 "새 지갑을 만들고 복구 단어 24개를 종이에 적습니다. 5분쯤 걸립니다." + 도움말 T-FIRST-1 셋째 문장(복구 단어 24개가 유일한 백업) + 주 버튼 `새 지갑 만들기`·보조 버튼 `YubiKey에 보관하는 새 지갑`(§2.19) + 도움말 "YubiKey에 보관하는 새 지갑: " + T-YK-WALLET + 필요한 YubiKey), 카드 "이미 쓰던 지갑이 있습니다"(한 줄에 `복구 단어로 가져오기`·`개인키로 시작하기`(§2.18)·`YubiKey 연결하기 (복구 단어 없이)`(§2.19) + 각각의 한 줄 도움말 — 개인키 줄은 T-KEYSTART-CARD). T-LEFTOVER면 다섯 버튼 모두 끈다.

### 2.3 새 지갑 만들기
단계 표시 `1 비밀번호 정하기 · 2 복구 단어 적기 · 3 백업 확인`을 S02(아직 시작 전)와 W01(1/3)·W08(2/3)·W10(3/3) 머리에 보인다(비밀 창은 "새 지갑 만들기 · n/3단계"와 점 세 개).

| 단계 | 화면 | 동작·검증 |
|---|---|---|
| 1 | S02 | 제목 "새 지갑 만들기", 단계 표시, 카드 "시작하기 전에"(T-CREATE-1 세 줄 + 도움말 "복구 단어를 아는 사람은 누구든 지갑의 자산을 옮길 수 있습니다…"). 주 버튼 `시작하기`, `취소`. |
| 2 | W01 | 비밀번호 2회. [02] 규칙(D8: 0x20–0x7E, 12–128자) 위반 E-INP-001, 불일치 E-INP-002. passphrase는 묻지 않는다([02] §8.1). |
| 3 | S03 | `KeyJob::CreateWallet` → `Vault::create_wallet` → `BackupPending`, 24단어 버퍼 반환. 이어서 기본 meta 쓰기. "지갑을 만드는 중입니다. 몇 초 걸립니다." 생성·가져오기·개인키로 시작하기가 실패하면 오류 띠를 보이고 S01로 가정하지 않고 `KeyJob::Load`로 상태를 다시 읽는다: vault가 이미 저장된 뒤 다음 단계(주소 조회 등)가 실패했으면 S07(잠금 해제하면 S04), 저장 전 실패면 S01. |
| 4 | W08 | 24단어 + 계정 0 EVM 주소(EIP-55, `m/44'/60'/0'/0/0`). 둘 다 종이에 적게 한다([02] §8.3). 캡처 제외 실패 시 표시하지 않고 E-SEC-001(§4.5 `Required`; 지갑은 `BackupPending`으로 남고 S04에서 다시 시도). `다 적었습니다`를 2초 길게 눌러야 다음으로 간다. |
| 5 | W10 | `backup_challenge()`의 위치 4개 단어(주소는 묻지 않는다). `KeyJob::ConfirmBackup` → `confirm_backup`. `BackupMismatch` → T-BACKUP-FAIL, 새 challenge(새 id)로 다시 입력. 2026-11-08부터 틀린 뒤의 challenge는 **같은 위치 4개**를 다시 묻는다(vault가 그 복구 단어의 틀린 위치를 성공·잠금 때까지 기억; 새 YubiKey 지갑의 메모리 속 단어도 같다). 이전에는 새 위치를 뽑아서 종이에 한 단어를 잘못 적었어도 다음 질문이 그 위치를 비켜 가면 통과했다. 결과는 여전히 네 단어 전체의 일치/불일치뿐이라 위치별 맞음/틀림은 알 수 없다. 횟수 제한 없음. |
| 6 | S08 | 제목 "준비되었습니다", T-BACKUP-OK(완료 띠; 가져오기 흐름 뒤에는 백업 확인을 하지 않았으므로 T-IMPORT-OK와 도움말 "이 지갑의 백업은 방금 입력한 복구 단어(와 passphrase)입니다…"). 저장된 RPC 엔드포인트(§6.3 `rpc:*`)가 하나도 없으면 카드 "마지막 단계: 블록체인 연결(RPC)"(무엇이고 왜 필요한지 한 줄 + 도움말) 안에 주 버튼 `RPC 설정하기`(S15 `네트워크(RPC)`, §2.11.1)와 `나중에`. 있으면 주 버튼 `지갑 열기`. → S10. |

S04(백업 대기): 잠금 해제 직후 백업이 확인되지 않았을 때. 제목 "백업 확인이 필요합니다", T-BACKUP-PENDING(주의 띠), 카드에 무엇을 하는지 한 줄과 주 버튼 `복구 단어 보고 백업 확인`(W03 → W08 → W10), `받기`(S12, 상단 경고 T-BACKUP-RECV), `잠금`, 카드 아래 링크 `지갑 초기화…`(§2.20). 서명·개인키 표시·개인키 가져오기는 없다([02] §7.1). 이 상태에서 dApp 승인 항목은 즉시 `NotReady`.
- S04로 들어갈 때(생성 직후 `Created`, 잠금 해제 뒤 `BackupPending`) meta를 읽는다(`request_meta`): S12가 계정 0을 보이기 위해서다. meta가 오면 설정 스냅샷 검사(§6.7)를 하고 S04에 머문다(대기 화면·S07·S10이었다면 S04로). 저널·잔액·YubiKey 후속 작업은 백업 확인 뒤 다시 읽는 meta에서 한다. meta 읽기가 실패하면 S04에 T-META-FAILED(§2.22). S12의 `← 메인으로`는 이 모드에서 S04로 간다(S10이 아니다).
- 2026-11-06 수정: 이전에는 `BackupPending`에서 meta를 읽지 않아 S04 → `받기`의 S12가 "계정을 불러오는 중…"에서 멈췄고, 그 화면의 `← 메인으로`는 meta를 요청한 뒤 S03("불러오는 중…")으로 갔는데 meta 응답이 `Unlocked`일 때만 그 화면을 떠나서 영원히 기다렸다(현장 로그: `backup.written_ack` 뒤 종료 → 새 빌드 → `BackupPending` → `settings.snapshot_created` → 멈춤). 회귀 시험 `app::tests::backup_pending_after_restart_shows_s04_and_receive`(이전 빌드 형식 meta, 재시작, S04·S12·`← 메인으로`, §2.22 시간 제한).

### 2.4 기존 지갑 가져오기 (니모닉)
단계 표시 `1 비밀번호 정하기 · 2 복구 단어 입력 · 3 첫 주소 확인`(S05 시작 전, W01 1/3, W05·W06 2/3, S06 3/3).

| 단계 | 화면 | 동작·검증 |
|---|---|---|
| 1 | S05 | 제목 "기존 지갑 가져오기", 단계 표시, 카드 "준비할 것": "다른 지갑에서 쓰던 영어 복구 단어(BIP39 니모닉) 12·15·18·21·24개", "BIP39 passphrase(25번째 단어)를 썼다면 그 passphrase", 도움말로 개인키 안내("복구 단어 없이 개인키(EVM·Solana·Bitcoin)만 있다면 첫 화면의 '개인키로 시작하기'… 이미 지갑이 있다면 메인 화면의 '개인키 가져오기'", §2.18)와 [08] §1.2 고정 문구. 주 버튼 `시작하기`, `취소`. |
| 2 | W01 | 비밀번호 2회(§2.3). |
| 3 | W05 | 니모닉 입력(§4.2). 단어마다 BIP39 목록 검사(E-INP-004 "{n}번째 단어"). `다음`은 단어 수가 12/15/18/21/24이고 모든 단어가 목록에 있을 때만 켜진다. 체크박스 `BIP39 passphrase 사용`(기본 끔, T-IMPORT-PASS). |
| 4 | W06 | (체크한 경우) passphrase 2회, 0x20–0x7E 1–256자(D8). 불일치 E-INP-002. |
| 5 | S03→S06 | `KeyJob::PreviewImport`: 키 작업자가 버퍼를 `PendingImport`로 보관하고, yw-core 파생 함수로 vault 없이 계정 0 EVM 주소만 계산한다(체크섬 오류 E-INP-005). S06: 단계 표시 3/3, 카드에 T-IMPORT-ADDR + 주소 전체(4자 묶음). 주 버튼 `맞습니다` → 6. `다릅니다`·취소·잠금 → `KeyJob::DiscardImport`(소거) 후 3으로. 아래 도움말 "다르면 복구 단어의 순서·철자나 passphrase를 확인하세요…". |
| 6 | S03 | `KeyJob::CommitImport` → `Vault::import_mnemonic`(백업 확인됨, `Unlocked`) → 기본 meta 쓰기 → 버퍼 소거. 계정은 EVM 인덱스 0 하나(자동 계정 탐색 없음). |
| 7 | S08 | → S10. |

비밀 버퍼는 5단계에서 키 작업자로 이동한다. 그 전에 취소하면 UI가 즉시 소거한다.

### 2.5 잠금 해제 (S07, W02, W06)
- S07: 큰 제목 "지갑이 잠겨 있습니다", "계정과 잔액을 보려면 비밀번호로 잠금을 해제하세요.", 주 버튼 `잠금 해제`(W02), 도움말로 자동 잠금 조건("{n}분 동안 쓰지 않거나, Windows를 잠그거나 절전에 들어가면…"). 기다리는 dApp 요청이 있으면 T-UNLOCK-PENDING(정보 띠)과 origin 목록(최대 5개, 나머지 "외 n건"). 계정·잔액·주소는 보이지 않는다(meta가 잠겨 있다).
- W02 비밀번호 → `KeyJob::Unlock` → S03("확인 중…").
  - `UnlockFailed` → E-VLT-001([02] §7.4 문구). 칸을 비우고 입력과 확인 버튼을 1초 비활성화. 횟수 제한 없음. 한 번 실패한 뒤 `.prev`가 있으면 S07에 도움말 T-UNLOCK-PREV와 링크 `이전 사본(.prev)으로 복구`(W03 → `recover_from_prev`, [02] §6.3 `Locked`에서의 복구: 키 구간 손상은 비밀번호 오류와 구분되지 않는다. 본 파일이 열리면 복구하지 않고 그대로 연다)를 보인다.
  - `UnsupportedPayload`(비밀번호는 맞지만 새 버전 앱이 쓴 payload, [02] §4.5 단계 10) → W02에 E-VLT-014 "새 버전 앱이 저장한 지갑입니다. 앱을 업데이트하세요". S09로 가지 않고 `.prev` 복구를 제안하지 않는다(T-UNLOCK-PREV 링크도 끈다). 파일은 그대로 둔다.
  - `PayloadCorrupt` → E-VLT-008, S09로 간다(`Corrupt { prev_available }`). 다시 `Load`하지 않는다(헤더가 정상이라 `Locked`가 되어 S09가 사라진다). 이후 잠금 등으로 `Load`가 `Locked`를 돌려줘도 앱은 "payload 손상" 상태를 기억해 S09를 유지하고, `이전 사본으로 복구`는 `Locked`에서도 동작한다.
  - `PassphraseRequired` → W06(passphrase 1칸) → `enter_passphrase`. W06 `나중에`(Esc)는 `KeyJob::Lock`으로 `Locked`(S07)에 돌아간다(`PassphraseRequired`에 머물지 않는다). `PassphraseMismatch` → 오버레이 T-PASS-MISMATCH: `다시 입력`(W06), `이 passphrase로 계속`(체크 "다른 passphrase는 다른(빈) 지갑을 엽니다"를 켜야 활성) → `Unlocked { alt_passphrase: true }`(T-ALT-PASS 띠, 받기·dApp 연결·서명 차단, §2.1).
  - 복구 단어가 여럿이고 passphrase를 쓰는 것이 둘 이상이면(§2.24) W06을 니모닉마다 차례로 연다. 창 안내: "복구 단어 {n}개 중 {k}번째의 passphrase를 입력하세요."(meta가 아직 잠겨 있어 라벨 대신 순서). 불일치·계속은 그 니모닉에만 적용된다([02] §7.5).
  - VirtualLock 실패(yw-win 슬롯 할당 실패, `OutOfMemory`) → E-VLT-007, 잠금 해제하지 않는다([02] §7.3 권고).
  - 성공: `BackupPending`이면 S04, 아니면 meta 읽기 → S10. meta·journal이 `SidecarCorrupt`·`SidecarVaultMismatch`면 오버레이 E-VLT-006에서 `이전 사본(.prev) 사용` 또는 `격리하고 새로 시작`을 고르게 한다(journal은 T-JOURNAL-RESET 확인 후에만, [02] §6.3). 이어서 저널 복구([03])와 승인 큐 처리(§3.7).
- dApp 요청 때문에 자동으로 연 W02·W06은 `WS_EX_TOPMOST`이고 전경이 아니면 작업 표시줄을 깜박인다(§3.6). 이 창의 `나중에`(Esc)는 잠금 해제를 기다리던 dApp 항목을 모두 `Rejected`로 끝낸다([05] §4.4: 해제 창은 하나, 결과 공유). 사용자가 직접 연 창의 `나중에`는 창만 닫는다.
- S09(`Corrupt`·`MainMissing`): E-VLT-002(payload 손상이면 E-VLT-008) 또는 "지갑 파일이 없고 이전 사본(.prev)이 있습니다." `.prev`가 있으면 `이전 사본으로 복구`(W03 → `recover_from_prev`, 문구 T-RECOVER-PREV), 없으면 폴더 경로와 `폴더 열기`, `종료`. 손상 파일은 덮어쓰지 않는다(격리 이름 `vault.ywv.corrupt-<unix초>`). W03을 취소하거나 틀린 비밀번호면 다시 `Load`하지 않고 요청했던 화면(S09·S07)으로 돌아간다. `.prev`가 없거나 `.prev`도 손상이면 W03에 그 사실을 알린다. 성공하면 S10/S04에 "이전 사본(.prev)으로 복구했습니다…" 정보 띠. 본 파일을 격리했으면 그 정확한 파일 이름(`vault.ywv.corrupt-<unix초>`, 키 작업자가 `KeyOutcome::Quarantined`로 알림)을 정보 띠에 넣어 사용자가 직접 되돌릴 수 있게 한다(`docs/recovery-guide.ko.md`). S09 도움말도 복구 전에 "지금 파일은 지우지 않고 `vault.ywv.corrupt-<시각>`으로 옮겨 두며, 복구 뒤 그 이름을 알려 준다"고 알린다.

### 2.6 메인 (S10)
- 배치(위 → 아래, 체인 탭마다 같음): 상단 막대 → 체인 탭 → 카드 "네트워크"(칩, 테스트넷 띠, 차단·저널 띠, 상태 줄 도움말) → **선택 계정 카드**(계정 이름, 경로, 큰 잔액 20pt와 기준 블록, EVM·Solana는 잔액이 있는 보이는 토큰 한 줄 요약 — EVM "토큰: 125.5 USDC · 0.3 WETH (아래 토큰 카드)"(최대 4개, 2026-11-08; Solana는 허용 목록 토큰 줄), 전체 주소, 주 버튼 `보내기`·`받기`, 링크 `새로고침`. 엔드포인트가 없으면(2026-11-08, EVM·Solana) 잔액 도움말이 "이 네트워크({이름})의 RPC 주소가 아직 없어 잔액을 읽을 수 없습니다."(`ui::screens::no_endpoint_text`)이고, 눌러도 E-KEY-005뿐인 `새로고침` 대신 보조 버튼 `RPC 설정하기`. Bitcoin의 E-KEY-005 띠 버튼과 Zcash 링크도 같은 이름 `RPC 설정하기`(이전 Solana·Bitcoin `설정에서 URL 입력`)) → 카드 "내 계정"(계정 목록 라디오 — 계정이 하나뿐이면 그 행은 주소·잔액 줄 대신 "{경로} · 주소와 잔액은 위 카드에 있습니다"(`T_SINGLE_ACCOUNT`, EVM·Solana; 2026-11-07, 10-31 검토 D3), 선택 행의 `이름 바꾸기`·`숨기기`/`삭제`(위험), `계정 추가`·`개인키 가져오기`) → 카드 "토큰" → 카드 "활동". 빈 목록에는 다음에 할 일을 알려주는 도움말을 보인다("아직 보낸 거래가 없습니다. 보낸 거래는 여기에서…").
- 체인 탭: 구현된 단계만(M4 `EVM`, M7 `Solana`, M8 `Bitcoin`, D36 `Zcash`). **Zcash 탭**([12](12-zcash.md) §11)은 한 화면에 네트워크(배지 붙은 mainnet·testnet 칩, 그 아래 네트워크 띠 — 다른 탭처럼 네트워크 카드 안, 엔드포인트 상태 — 없으면 링크 `RPC 설정하기`이고 같은 E-KEY-005를 탭 위 빨간 띠로 또 보이지 않는다, UTXO 원천)·계정(키 출처, 확인된 잔액, 2026-11-07부터 그 네트워크의 가져온 키 줄 `[가져온 키] {주소}`와 `이 키 사용`, 가져온 키 계정이면 `개인키 보기`(압축 WIF)·`삭제`, 끝에 `개인키 가져오기` — [12] §2.3)·받기(일반 주소, QR, T-ZEC-RECEIVE)·보내기(t·TEX·UA, 금액/최대, 검토 → 승인 창)·활동 카드를 차례로 보이고, 꺼져 있으면 카드 "Zcash (일반 주소 전용)"에 `Zcash mainnet 켜기`/`Zcash testnet 켜기`(두 네트워크 모두 URL이 없으면 링크 `RPC 설정하기`도)만 보인다. 각 탭의 "내 계정" 카드에 `개인키 가져오기`가 있다(그 체인의 키, §2.18). 가져온 계정은 라벨 뒤에 배지 "[가져온 키]"와 도움말 "가져온 키 · 복구 단어로 복구되지 않음"을 보인다. 키 전용 지갑(복구 단어 없음, [02] §8.5)은 파생 기능(`계정 추가`, `다른 경로 스캔`, 파생 Bitcoin 계정·발견, 복구 단어 보기)을 숨기고, 계정이 없는 체인 탭은 "이 지갑에는 {체인} 계정이 없습니다."와 `개인키 가져오기`만 보인다.
- EVM 네트워크 선택: 기본 체인 7개(`Ethereum 메인넷`, `Sepolia 테스트넷`, HyperEVM, `Arbitrum One`, `Base`, `BNB Smart Chain`, `Robinhood Chain`; 이름은 [03] §1.1) 다음에 사용자 체인(§2.17, `evmChains` 순서, 이름 옆 배지 T-CUSTOM-CHAIN). 차단된 체인(E-RPC-006·E-CHN-008)도 목록에 남기고 "(차단됨)"을 붙인다. 고르면 S10에 그 오류 배너와(E-CHN-008이면) `설정에서 다시 고정`(S15)을 보이고 잔액·보내기는 끈다. 선택은 `settings.json` `evmChainId`(§6.1, D30)이고, 잠긴 동안 [05]가 캐시 없는 origin의 `eth_chainId`로 쓴다. Solana 클러스터는 `solana.cluster`([07] §10), BTC 네트워크는 `bitcoin.network`([08] §2, D26)로 모두 `settings.json`에 있다. 테스트넷(Sepolia, [07]의 테스트 네트워크)이면 상단에 `TESTNET_BG` 띠 "테스트넷 — 실제 자산이 아닙니다". Bitcoin testnet4는 [08] §2 전용 배너 `BITCOIN TESTNET4 — 가치 없음`만 보인다(메인·보내기·받기·결과 화면 모두; 같은 뜻의 띠를 두 겹으로 그리지 않는다). 기본 메인넷(Ethereum 메인넷 1, HyperEVM 999, Arbitrum One 42161, Base 8453, BNB Smart Chain 56, Robinhood Chain 4663)과 Solana mainnet이면 빨간(`BTC_MAINNET_BG`) 띠 T-MAINNET "메인넷 — 실제 자산"(Bitcoin은 [08] §2 `BITCOIN MAINNET`). 같은 조건에서 승인 창 A01 헤더에도 T-MAINNET 배지를 보인다(§3.2 헤더; 대상은 S10의 선택 네트워크가 아니라 그 요청의 체인·클러스터). 사용자 체인에는 테스트넷 구분이 없으므로 띠·배지를 그리지 않는다. 기본값은 그대로다(EVM Sepolia, Solana mainnet, Bitcoin 꺼짐).
- 상태 줄: `RPC: 연결됨 | 엔드포인트 없음 (E-KEY-005) | 오류 E-RPC-0nn | 차단 E-CHN-008`(네트워크 이름만, URL·호스트 없음, §1.9), `브라우저: 연결 n개 | 연결 없음 | 사용 불가 E-PIPE-001 | 사용 불가 E-PIPE-002`. 엔드포인트 없음이면 잔액·보내기를 끄고 `설정에서 URL 입력`(S15 §2.11.1)을 보인다.
- 계정 목록: 라벨, 전체 주소(§3.3 주소 그리기), 기본 자산 잔액, 경로 또는 `가져온 개인키`. 카드 도움말 T-ACCOUNTS(파생 계정만 복구 단어로 복구되고 가져온 개인키는 아니다). 선택 행 버튼: `보내기`, `받기`, `이름 바꾸기`, 파생 계정 `숨기기`(meta `hidden`), 개인키 계정 `삭제`(확인 오버레이 T-REMOVE-KEY → W03 → `remove_evm_raw_key`). 삭제 오버레이는 계정 라벨·주소(라벨은 겹칠 수 있으므로 모든 체인에서 주소를 함께)와 선택한 EVM 네트워크의 마지막으로 읽은 기본 자산 잔액을 보인다: 0보다 크면 고위험 띠 "이 계정에 잔액이 있습니다: … 먼저 옮기거나 개인키를 내보내세요", 모르면 주의 띠 "잔액을 확인하지 못했습니다…", 0이면 "다른 네트워크와 토큰 잔액은 확인하지 않았습니다" 도움말. 숨기기·삭제는 [05] §4.1에 알린다(grant에서 제외). **숨긴 계정 되돌리기**(2026-11-08, `app_hidden`, 명령 ID 16,200–16,589): 숨기면 정보 띠 "'{라벨}'을(를) 숨겼습니다. 이 계정의 사이트 연결도 해제했습니다. '내 계정' 아래 '숨긴 계정'에서 다시 볼 수 있습니다."; EVM·Solana "내 계정" 카드 끝(계정이 모두 숨겨진 YubiKey 지갑이면 T-NO-ACCOUNTS 카드 끝)에 숨긴 계정이 있으면 링크 `숨긴 계정 n개 보기 ▸`/`접기 ▾`(이번 실행에서만 기억). 펼치면 도움말(자산은 그대로, 사이트 연결은 dApp에서 다시)과 행마다 흐린 줄 "{라벨} · {출처} · 숨김", 전체 주소(§3.3), 마지막으로 읽은 잔액, `다시 보이기`(meta `hidden = false`만 바꾸고 grant는 되살리지 않는다; 정보 띠 "…다시 보이게 했습니다. 사이트에서 쓰려면 dApp에서 다시 연결하세요."). 이전에는 숨긴 계정을 다시 보일 방법이 없었다(`계정 추가`는 최대 인덱스 + 1). 단, 지우는 가져온 EVM 키의 주소가 (숨기지 않은) 파생 계정의 주소와 같으면(그 계정의 개인키를 가져온 경우) 파생 계정이 남으므로 사이트 연결을 끊지 않는다. 가져온 계정의 기본 라벨(`가져온 계정 N`·`가져온 Solana N`)은 같은 접두어의 기존 라벨 중 가장 큰 N + 1이다(`개수 + 1`은 삭제 뒤 번호가 겹친다).
- `계정 추가`: 다음 EVM 인덱스(기본 라벨 "계정 {i+1}"), 또는 `개인키 가져오기`(W07 → `import_evm_private_key`, `Unlocked`에서만; W07 안내에 T-IMPORTED-KEY). 상한은 [02] §5.3(파생 100, 개인키 15).
- **Bitcoin 탭 계정**([08] §3.5–§3.6): 배치는 다른 탭과 같다 — 네트워크 카드(배너·상태 줄·`새로고침`·`더 찾기`) → 선택 계정 카드(이름, 노드·형식, 큰 사용 가능 잔액, 주 버튼 `보내기`·`받기`) → 카드 "Bitcoin 계정" → UTXO → 활동(키 전용 지갑에 Bitcoin 키가 아직 없으면 계정 카드만). 카드 "Bitcoin 계정" — 계정마다 라디오 한 행 `{이름} · {형식 (접두)} · {사용 가능 잔액}`(예: `네이티브 세그윗 계정 0 · 네이티브 세그윗 (bc1q…) · 0.00100000 BTC (100,000 sats)`; 가져온 키는 배지와 줄인 주소 `[가져온 키] {주소 앞 6자}…{끝 6자} · 레거시 (1…) · …`), 고르면 그 계정으로 전환(key worker가 `btc_accounts.selected`를 저장한 뒤 새로고침, 발견 전이면 발견). EVM 키 계정 행은 배지 `[EVM 계정 {i} 키]`와 줄인 주소. 목록 아래(선택 계정이 HD일 때) **주소 방식**: `주소 방식 — {계정 이름}`, 라디오 `고정 주소 하나만 사용 (UniSat·Xverse 방식)`(기본) / `받을 때마다 새 주소 (HD, 프라이버시↑)`, 한 줄 도움말 T-BTC-MODE-HELP; 바꾸면 `BtcMetaOp::SetAddressMode`(meta 쓰기 후 반영, BTC 승인이 열려 있으면 "Bitcoin 승인이 진행 중이라 주소 방식을 바꿀 수 없습니다")([08] §3.5). 아래 `계정 추가` → 같은 카드에 도움말 "주소 형식을 고르세요. 잘 모르면 네이티브 세그윗을 고르세요…", **키 출처** 라디오(`BTC 표준 경로 (권장, 기본값)` 기본 + 도움말 T-BTC-SOURCE-STANDARD-HELP / `EVM 계정과 같은 키` — 고르면 주의 띠 T-BTC-EVM-SHARED와 EVM 계정 라디오 `{라벨} · {줄인 주소} · m/44'/60'/0'/0/{i}`), 형식 버튼 4개(mainnet `네이티브 세그윗 (bc1q…, 권장)`, `탭루트 (bc1p…)`, `호환 세그윗 (3…)`, `레거시 (1…)`; testnet4 `tb1q`·`tb1p`·`2`·`m·n`)와 `취소`. 표준 경로면 형식 버튼이 바로 HD 계정을 더하고(새 계정은 고정 주소 모드), EVM 키면 형식 버튼이 확인 오버레이(제목 "EVM 계정과 같은 키로 Bitcoin 계정 만들기", "EVM 계정 {i}의 키(m/44'/60'/0'/0/{i})로 {형식} 주소 하나를 만듭니다. 받기와 잔돈은 늘 이 주소입니다." + T-BTC-EVM-SHARED + "그래도 만들까요?", 버튼 `같은 키로 만들기`·`취소`)를 연다. 중복(같은 EVM 계정·형식, 이미 계정의 주소)은 E-VLT-011을 목록 아래 띠로 보인다. 선택한 EVM 키 계정은 목록 아래 T-BTC-EVM-SHARED 도움말과 `개인키 보기`(WIF, T-REVEAL-WARN → W03 → W09; `삭제` 없음). 카드 도움말: 계정마다 주소 형식이 정해지고 같은 복구 단어에서 BIP44·49·84·86으로 다른 지갑에서도 복구된다. BTC 승인이 열려 있으면 전환·추가를 막는다. 선택 계정 카드 제목은 계정 이름, 그 아래 `{노드} · {형식 (접두)}`(예: `m/86'/0'/0' · 탭루트 (bc1p…)`). 가져온 키 계정에는 `더 찾기`가 없다. 잔액·UTXO·활동(meta 활동은 그 계정의 `account` 태그만)·받기·보내기·수수료 올리기는 선택 계정의 것이다(가져온 키도 같다). 가져온 키 줄이 선택돼 있으면 목록 아래에 백업 도움말과 `개인키 보기`·`삭제`(§2.18). 카드 끝: T-BTC-IMPORTED, 주소 형식 라디오, T-KEYSTART-SCRIPT, `개인키 가져오기`. 키 전용 지갑은 `계정 추가` 없이 이 부분만 있고, 기본 계정 없이 가져온 키 계정만 보인다(그 네트워크에 없으면 "이 네트워크에는 가져온 Bitcoin 개인키가 없습니다…", 하나도 없으면 T-NO-ACCOUNTS; Bitcoin이 꺼져 있으면 꺼짐 카드 아래 T-NO-ACCOUNTS 카드).
- 토큰 잔액: 레지스트리 토큰([03])과 meta `tokens`. `토큰 추가`(S16). Solana 탭(v1.1): 카드 "토큰 (선택한 계정)"은 그 클러스터의 [07] §8.3 허용 목록 토큰만 보인다(토큰마다 로컬 파생 ATA 하나만 조회, `토큰 추가` 없음, 다른 토큰·NFT는 받아도 보이지 않는다). 행 = 기호와 잔액(고정 decimals) · 원시 단위·"RPC finalized 기준(참고)" · "mint (허용 목록 고정)"과 mint 전체(묶음) · 링크 `{기호} 보내기`(잔액 > 0·엔드포인트 있음·`Unlocked`일 때만, 그 토큰을 고른 보내기 화면)·`숨기기`. ATA가 없으면 0과 "이 계정에는 아직 {기호} 토큰 계정(ATA)이 없습니다. 받으면 보내는 쪽이 만듭니다.", 동결이면 동결 안내, ATA 자리에 다른 형식의 계정이면 잔액 대신 "확인할 수 없음". 선택 계정 카드에는 큰 SOL 잔액 아래 한 줄 "허용 목록 토큰: 25.000000 USDC (아래 토큰 카드)"(숨긴 토큰은 빼고).
- **토큰 행 숨기기**(2026-11-03, 스캠·쓰지 않는 토큰 정리용): EVM 토큰 카드의 행 = 라벨(사용자 토큰은 "{라벨} (사용자 추가)")과 잔액 · 컨트랙트 전체(§3.3) · 링크 `{기호} 보내기`(2026-11-08, Solana 토큰 카드와 같게: 보이는 행, 잔액 > 0, 엔드포인트 있음, `Unlocked`일 때만 켜짐 — 그 토큰을 고른 S11을 연다; 명령 ID 3,440–3,559) · 링크 `숨기기` · 사용자 토큰만 위험 버튼 `삭제`(레지스트리 토큰은 숨길 수만 있다). 행 아래 체크 `잔액 0인 토큰 숨기기`(기본 끔): 켜면 잔액을 읽었고 0인 행을 감추고 도움말 "잔액이 0인 토큰 n개를 감췄습니다. 잔액이 생기면 다시 보입니다."(잔액을 못 읽은 행은 감추지 않는다). 숨긴 토큰이 있으면 링크 `숨긴 토큰 n개 보기 ▸`/`숨긴 토큰 n개 접기 ▾`: 펼치면 T-TOKEN-HIDDEN 도움말과 숨긴 행을 흐리게(`{라벨} · {잔액} · 숨김`, 컨트랙트 전체) `다시 보이기`(사용자 토큰은 `삭제`도)와 함께 보인다. 직접 숨긴 행은 잔액 0 규칙보다 우선해 이 목록에 있다. 보이는 행이 없으면 "보이는 토큰이 없습니다. 숨긴 토큰은 아래에서 다시 볼 수 있습니다." Solana 카드도 같은 `숨기기`·`숨긴 토큰 n개 보기`·`다시 보이기`(클러스터별, 잔액 0 체크 없음)를 둔다. 숨김과 `잔액 0인 토큰 숨기기`는 meta `token_view`([02] §5.3)에 네트워크별로 저장하고, 펼침 상태는 실행 중에만 둔다.
  - 숨김은 **표시 전용**이다. 잔액 조회, 승인 창(A01)의 토큰 인식(레지스트리 신뢰, E19 모방 토큰 검사)·위험 규칙·시뮬레이션 해석은 숨김과 무관하게 레지스트리와 meta `tokens` 전체를 쓴다. 활동 행은 기록이므로 숨긴 토큰 것도 그대로 보이고 금액 뒤에 `[숨긴 토큰]` 태그를 붙인다. EVM 보내기(S11)의 `자산` 라디오 라벨에는 2026-11-08부터 보유량을 붙인다(`USDC · 125.5`, 못 읽었으면 `USDC · 잔액 모름`), 토큰을 고르면 그 아래 "보유 125.5 USDC (블록 N 기준)" 한 줄(표시만, 검사·승인 규칙은 그대로). `자산` 라디오는 숨긴 토큰을 빼고 `숨긴 토큰 n개 보기 ▸`로 펼친 줄 "숨긴 토큰"에 보인다(잔액 0 규칙은 적용하지 않는다; 이미 고른 자산이 숨긴 토큰이면 늘 펼치고 접기 링크는 끈다; 라디오 id는 숨김과 무관하게 같은 토큰을 가리킨다). Solana 보내기 폼의 자산 라디오는 그대로다(허용 목록 2개).
  - 사용자 토큰 `삭제` → 확인 오버레이 "토큰 삭제"(T-TOKEN-DELETE, 필드 "토큰" = 라벨, "컨트랙트 주소"와 전체 주소) → `삭제`면 meta `tokens`에서 지우고 그 숨김 표시도 지운다(다시 추가하면 보이는 상태로 시작). 보내기 폼이 그 토큰을 골라 두었으면 기본 자산으로 바꾼다.
- **HyperCore 카드**(EVM 탭, D34, [11] §8): 설정 `hypercore.enabled`(기본 켜짐)이면 토큰 카드와 활동 카드 사이에 카드 "Hyperliquid HyperCore 메인넷|테스트넷" — 네트워크 라디오(`hypercore.network`), 같은 EVM 주소의 선물 USDC(계정 가치·출금 가능)·현물 잔액, 버튼 `보내기(Core)`·`현물↔선물 이동`·`Arbitrum으로 출금`·`HyperEVM으로 이동`·`HyperEVM에서 Core로 이동`·`새로고침`, "HyperCore 활동 (이번 실행)"(작업·금액·받는 주소·nonce·Hyperliquid 응답 상태). 카드 제목과 S-HC 화면 제목 앞에 `Badge::hyperliquid()`. 테스트넷이면 `TESTNET_BG` 띠, 메인넷이면 빨간(`BTC_MAINNET_BG`) 띠 "HyperCore 메인넷: 실제 자산"(카드의 네트워크는 선택한 EVM 체인과 따로라 위 EVM 띠와 구분되는 문구; 2026-11-07). 거래(주문) 기능은 없다.
- 잔액 갱신: S10 진입 시, `새로고침`, S10이 보이고 `Unlocked`인 동안 60초마다. 값 옆에 기준 블록 번호. 실패하면 이전 값을 `MUTED`로 두고 오류 코드를 붙인다.
- 활동: meta `activity`([02] §5.3 `ActivityEntry`, 모든 체인 공통 스키마; 이 지갑이 보낸 거래만, 네트워크당 최대 500)와 진행 중 저널 항목. 받은 거래 목록은 만들지 않고, 활동의 주소에는 복사·선택 버튼을 두지 않는다(주소 오염 대비, [07] §12.3). 행 = 로컬 시각(`YYYY-MM-DD HH:MM`, yw-win `time::local_wall_ms`; 변환 실패면 UTC 표기), 계정 라벨, 종류·금액([03]/[07]/[08] 문자열), 상태, 해시 전체, `해시 복사`, 탐색기 URL이 있는 체인(사용자 체인 §2.17의 입력값, 또는 기본 체인 [03] §1.1의 `explorer` — Arbitrum One·Base·BNB Smart Chain·Robinhood Chain; 사용자 체인 값이 우선)이면 `탐색기 링크 복사`(`{explorer}/tx/{해시}`를 `clipboard::set_text`; 앱은 URL을 열지 않는다, §2.14). 진행 중 EVM 거래에는 `가속`·`취소`([03] `EvmSpeedUp`·`EvmCancel`), BTC 거래에는 `수수료 올리기`([08] §9)가 있고 모두 새 승인 창을 거친다. 2026-11-08(EVM): 행에 Solana·Zcash처럼 "받는 주소 {4자 묶음 전체}" 줄(ERC-20은 해석한 토큰 받는 사람)과, 주소록·내 계정이면 표시 전용 " → 주소록: {이름}"/" → 내 계정: {라벨}"(복사·선택 버튼은 여전히 없음); `nonce n`은 진행 중인 행에만; 최근 10행만 그리고 나머지는 링크 `이전 활동 n건 더 보기 ▸`/`이전 활동 접기 ▾`(이번 실행에서만 기억, 명령 ID 3,560 — 행 버튼 id는 그대로 행 번호). 진행 중인 행(`가속`·`취소`·`재전송`·`폐기`가 있는 행)은 10행 밖이어도 접지 않고 늘 그리며, n은 접힌 끝난 행의 수다. 빈 활동 카드(EVM·Solana·Bitcoin)에는 "받은 입금은 이 목록에 나오지 않습니다. 선택 계정의 잔액(새로고침)으로 확인하세요."(`T_ACTIVITY_RECEIVED`)를 붙인다.
- 거래 상태 문구(D32: 모든 체인에서 확인 1 = 확정, 추가 확인·`finalized` 대기 없음): EVM `확정 (블록 N)`·`확정 (실행 실패, 블록 N)`(검증한 영수증이 블록에 있으면 바로, [03] §4.5); Solana `전송 확인 중`·`처리 중 (confirmed 대기)`(`processed`)·`성공`·`실패: …`·`만료 (전송되지 않음)`([07] §14.2); Bitcoin `확인 대기 (서버 기준)`·`확정 (서버 기준)`(확인 1, [08] §12.2-4). 확인 수를 `n/6`처럼 세는 표시는 없다. Solana 보내기 결과 화면과 보내기 화면의 진행 중 안내에는 `Pending`인 동안 `지금 다시 전송`(T-SOL-SEND-NOW)이 있다([07] §14.3).
- 저널 손상([03]): EVM 보내기를 끄고 배너 "거래 저널이 손상되어 보내기를 멈췄습니다. (E-VLT-006)". 자동 삭제하지 않는다.

S16 토큰 추가: 컨트랙트 주소(§2.15) → RPC `decimals()`·`symbol()`([03]) → "decimals: n, 체인에서 읽은 기호: X". 기호는 `^[A-Za-z0-9]{1,11}$`일 때만 보이고 아니면 "(표시할 수 없는 기호)". 사용자가 라벨(§2.10 규칙, 기본값 = 통과한 기호)을 확인해야 meta `tokens`에 저장된다. 이후 이 라벨과 컨트랙트 주소를 함께 보인다. 추가한 토큰은 S10 토큰 카드에서 `숨기기`하거나 `삭제`(확인 T-TOKEN-DELETE)할 수 있다(위 "토큰 행 숨기기"). 자동 발견은 없다(받은 토큰을 찾아 목록에 넣지 않는다).

### 2.7 보내기 (S11, EVM 네이티브 자산·ERC-20)
| 필드 | 입력 | 검증 |
|---|---|---|
| 보내는 계정 | 선택 계정(변경 가능) | — |
| 자산 | 기본 자산 또는 계정의 토큰 | — |
| 받는 주소 | EDIT, 붙여넣기 허용, 그 위 `즐겨찾기` 칩 줄(§2.10, 최대 5개 `★ 이름 · 0x1234…abcd`, 누르면 채움), `주소록에서 선택`(주소록·내 계정만, ★ 항목 먼저, 입력한 글자로 거른 목록). 최근 받는 사람·활동에서 고르기는 없다. 칩·목록으로 채운 주소도 직접 입력과 같은 검사(§2.15 형식·체크섬·유사 주소·처음 보내는 주소)를 받는다 | §2.15 |
| 금액 | EDIT 10진 문자열, `최대` 버튼 | §2.15 |

- 폼은 카드 세 개 — "보내는 계정"(잔액, 전체 주소, 링크 `다른 계정으로 바꾸기 (메인)`), "받는 사람"(주소 칸 + 도움말 "0x로 시작하는 42자 주소입니다. 붙여넣은 뒤에는 앞뒤만이 아니라 주소 전체를 확인하세요."), "보낼 자산과 금액"(자산, 금액 + 도움말, 수수료) — 과 주 버튼 `검토`, `취소`. 아래 도움말 "'검토'를 누르면 승인 창에서 시뮬레이션 결과와 함께 최종 확인합니다. 아직 아무것도 보내지 않습니다."
- 수수료는 지갑이 계산하며(D20, [03] §3.4) 선택지가 없다. 입력이 모두 유효하면(입력 정지 후 500 ms) "예상 최대 수수료: {X} {네이티브 심볼}"을 보이고, 계산식 "(가스 한도 {g} × 최대 {f} gwei)"(OP-stack 체인이면 끝에 " + L1 데이터 수수료 최대 {l} {심볼}", [03] §3.4a; X는 L1 몫을 포함하고 `최대` 버튼도 이 X를 뺀다)는 링크 `수수료 계산 보기 (가스 한도·gwei) ▸`를 펼쳤을 때 도움말 줄로 보인다. 그 체인의 상한(§6.1 `feeCaps`) 초과는 E-TX-001(차단 띠)로 막는다(D16의 차단 조건).
- `최대`: 네이티브 자산이면 잔액 − 가스 한도 × maxFeePerGas(최신 견적), 0 이하면 E-INP-012. 토큰이면 토큰 잔액 전부.
- (체인, 계정)에 진행 중 거래가 있으면(D20) 폼을 끄고 T-SEND-INFLIGHT와 그 거래의 상태·해시를 보인다.
- `검토`는 차단 오류가 없고, W-ADDR-3이면 `주소 전체를 직접 확인했습니다`를 체크했을 때 켜진다. 입력을 바꾼 뒤 입력 지연 검사(500 ms)가 돌기 전에는 꺼진다. `검토`를 누르면 RPC 없이 입력을 그 자리에서 다시 검사하고, 그 결과(받는 주소·자산·금액)가 화면에 보이던 검사 결과와 다르면 승인을 열지 않고 "입력이 바뀌어 다시 확인했습니다. 받는 주소·자산·금액을 확인한 뒤 다시 검토하세요."만 보인다(SOL [07] §13.1-1과 같은 규칙). 승인 요청은 이 새 검사 결과로만 만든다.
- `검토` → 준비·시뮬레이션([03]) → A01(출처 "Your Wallet 앱", 모든 체인 같은 문구; 시뮬레이션이 성공하지 못해도 고위험 확인 후 승인할 수 있다, §3.2.1, D15) → 승인 → 서명·저널·전송([03]) → 결과 화면("전송했습니다" + 해시 + 상태). 거부 → 폼으로(입력 유지). 만료(§3.5, 표시 + 120 s) → 창이 `Expired`로 닫히고 폼으로(입력 유지) + T-APPR-EXPIRED. 다시 `검토`하면 준비부터 다시 하고 새 승인(새 id, 새 `ApprovalStore::issue`)을 만든다. 모든 체인(EVM·SOL·BTC) 공통이다.
- SOL·BTC 보내기 폼의 필드와 순서는 [07] §13·[08] §7–8이 정하고, 입력 칸·검토·승인 창 규칙은 이 절과 §3을 따른다. Solana(v1.1): 카드는 "보내는 계정"·"받는 사람"·"보낼 자산과 금액". 마지막 카드 첫 줄은 라디오 `자산`(SOL, 그 클러스터의 허용 목록 토큰 순서). 토큰을 고르면 "{기호} · SPL Token · 보유 {잔액}", 잔액 설명, mint 전체(묶음)를 보이고, 금액 칸 라벨은 `금액 ({기호})`(고정 decimals로 파싱), `보내기 최대`는 토큰 전액(SOL은 수수료와 필요하면 받는 토큰 계정 생성비만 나감), 수수료 도움말은 그 자산의 CU 한도와 "받는 사람에게 {기호} 토큰 계정이 없으면 이 거래가 만들고 생성 비용(rent)을 보내는 계정의 SOL로 냅니다". 받는 사람 카드에 "{기호}을(를) 받을 사람의 지갑 주소를 넣으세요. 토큰 계정(ATA) 주소가 아닙니다 — 받는 토큰 계정은 지갑이 계산합니다." 곡선 밖 주소는 E-SOL-006(입력 단계 차단). 자산을 바꾸면 받는 주소·금액을 그 자산 규칙으로 다시 검사하고, 클러스터를 바꾸면 폼을 비운다. 복구 스캔의 "표준 계정으로 이동"([07] §3.3)도 이 폼을 쓰며 자산은 고를 수 있고 보내기 최대는 고정이다. 수수료를 직접 입력해 상한을 푸는 [08] §8.3 확인은 보내기 폼에서 한다(승인 창에는 입력 칸이 없다).

- Solana 보내기 폼의 수수료 줄(2026-11-08): "예상 수수료 약 0.000005 SOL (최대 {상한} SOL) — 최종 수수료는 승인 창에서 확인합니다."; lamports·CU 한도 계산은 EVM처럼 링크 `수수료 계산 보기 (lamports·CU) ▸`(`ADVANCED_TOGGLE`) 안. 상한(`maxFeeLamports`, B01–B04)과 승인 창의 최종 수수료는 그대로다.

### 2.8 받기 (S12)
- 표시: 화면 제목 배지 + "받기 — {네트워크}"(세 체인 같음, 2026-11-08 — 이전 EVM은 "받기"뿐, Solana는 배지 없이 "받기 — Solana"), 카드 제목 "{계정 라벨} · {네트워크}", 테스트넷이면 테스트넷 띠 "테스트넷 주소입니다", 기본 EVM 메인넷·Solana mainnet이면 S10과 같은 T-MAINNET 띠(S11 보내기도 같다; Solana는 S10에도 — Bitcoin은 원래 모든 화면에 띠), 도움말 "보내는 사람에게 아래 주소나 QR을 알려주세요. 이 네트워크의 자산만 보내야 합니다.", 전체 주소(§3.3 주소 그리기), 주 버튼 `주소 복사`(Bitcoin HD는 `새 주소`도)와 복사 안내, (EVM) RECEIVE_SHARED_ADDRESS_NOTE, QR 종류 선택·QR, 파생 경로. 2026-11-08부터 주소와 `주소 복사`가 QR **앞**에 온다: 기본 창(960×680)에서 띠가 붙어도 주소 확인과 복사가 첫 화면에서 끝난다(이전에는 큰 QR 뒤라 화면 끝이나 밖). 복사 동작·클립보드 규칙·문구는 그대로다. 주소는 vault에서 다시 파생한 값이다([02] §5.3).
- Bitcoin: 카드 제목 `{계정 이름} · 받기 주소 {i}번`(HD 모드), `{계정 이름} · 고정 주소`(고정 주소 모드, 기본), 계정 이름만(가져온 키·EVM 키), 첫 줄 `주소 형식: {형식 (접두)}`(예: `탭루트 (tb1p…)`), 고정 주소 모드면 정보 띠 T-BTC-FIXED-RECEIVE, QR, 전체 주소(인코딩 그대로), 경로 `m/{44|49|84|86}'/{coin}'/{a}'/0/{i}`(고정 주소 모드는 늘 `…/0/0`; 가져온 키 `가져온 키`; EVM 키 `m/44'/60'/0'/0/{i}`), `주소 복사`, HD 모드 계정만 `새 주소`, 아래 도움말(고정 주소: "받은 돈과 보내고 남은 잔돈이 모두 이 주소로 옵니다(새 주소 없음). 받을 때마다 새 주소를 쓰려면 Bitcoin 탭의 계정 목록 아래 '주소 방식'에서 바꾸세요. …"; EVM 키: "이 계정은 주소 하나만 씁니다. EVM 계정 {i}과 같은 키({경로})입니다." + T-BTC-EVM-SHARED)([08] §3.2, §3.5, §3.6).
- Solana(v1.1) 도움말: "보내는 사람에게 아래 주소나 QR을 알려주세요. SOL과 허용 목록 토큰({기호들})을 받을 수 있습니다. 다른 토큰은 받아도 이 지갑에 보이지 않고 보낼 수 없습니다." + "토큰을 보내는 쪽에는 이 지갑 주소를 알려주면 됩니다(토큰 계정 주소는 상대 지갑이 계산합니다)." QR 내용은 그대로 지갑 주소다.
- QR 내용: EVM `ethereum:<EIP-55 주소>@<chainId>`(EIP-681, 이식 `archive/spec-v2.4:demo/sepolia-wallet/src/receive_qr.rs:132-139`, chainId 매개변수화), SOL base58 그대로([07] §12.3), BTC `bitcoin:` + 인코딩 그대로의 주소(bech32·bech32m 소문자, base58은 대소문자 유지, [08] §3.6).
- EVM QR 선택(`ui::qr::EvmQrKind`, 실행 중에만 유지·저장 안 함): 라디오 `지갑 앱용 QR (네트워크 포함)`(기본, EIP-681) / `주소만 QR (거래소 앱용)`(EIP-55 주소 그대로, `qr::evm_receive_payload`). 주소만이면 QR 위에 "주소만 담은 QR에는 네트워크 정보가 없습니다. 보내는 쪽(거래소 출금 화면 등)에서 네트워크를 {네트워크}(으)로 직접 고르세요." `주소 복사` 안내 바로 아래(QR 위)에 항상 `qr::RECEIVE_SHARED_ADDRESS_NOTE`(같은 주소가 다른 EVM 체인에서도 쓰이지만 선택한 네트워크의 자산만 보인다; 2026-11-08 이전에는 카드 끝).
- 생성 `qrcodegen::QrCode::encode_text(payload, QrCodeEcc::Medium)`. 그리기: 조용한 영역 4모듈, 모듈 = max(6, round(8 × dpi / 96)) 정수 픽셀, GDI `FillRect`로 `QR_LIGHT` 바탕에 `QR_DARK`. 6 px 모듈이 들어가지 않으면 QR 대신 "창을 넓히면 QR이 표시됩니다"(배치 규칙 이식 `receive_qr.rs:51-130`). 행렬은 캐시하지 않는다.
- `주소 복사`: `clipboard::set_text`(일반 복사). 이어서 "주소를 복사했습니다. 붙여넣은 곳에서 주소 전체를 확인하세요."

### 2.9 연결된 사이트 (S13)
- 화면 제목 "연결된 사이트 · WalletConnect"(S10 상단 막대 `사이트·WalletConnect`, 설정 → 브라우저·정보의 `연결된 사이트 · WalletConnect 열기`). 맨 위 WalletConnect 카드([13] §6–§8, 2026-11-07): Project ID가 없으면 카드 "WalletConnect 연결 — 처음 한 번 준비"(소개, `릴레이` 줄, 소제목 "1단계: Reown Project ID 저장" + 입력 칸·주 버튼 `저장`·어디서 받는지 도움말, 소제목 "2단계: dApp에 연결" + "Project ID를 저장하면 여기에 … 나타납니다")만 보이고 꺼진 연결 컨트롤은 그리지 않는다. Project ID가 있으면 카드 "WalletConnect 연결"(소개, 두 줄 "1. dApp의 WalletConnect 창에서 '링크 복사'를 누르거나, QR을 Win+Shift+S로 캡처합니다." "2. '클립보드에서 연결'을 누릅니다…", 주 버튼 `클립보드에서 연결`(2026-11-08: 누를 때만 클립보드를 읽어 `wc:` 텍스트면 바로 연결, 아니면 이미지로 보고 QR 해독 — 이전의 `클립보드 이미지에서 QR 읽기`와 같은 경로; 클립보드에 쓰지 않고 내용은 로그에 남기지 않는다), `또는 연결 주소 (wc:…)` + 보조 버튼 `연결`, 링크 `다른 방법 (이미지 파일) ▸`(펼치면 `이미지 파일 경로` + `이미지 파일에서 QR 읽기`), 알림, `릴레이`, `Reown Project ID` 값 한 줄과 링크 `Project ID 바꾸기 ▸`/`접기 ▾` — 펼치면 입력 칸·`저장`; 비우고 저장하면 끔) 다음에 세션 카드. 그 아래가 확장 연결 목록이다.
- meta `connected_sites`([02] §5.3 `ConnectedSite`, 최대 256개, 의미는 [05] §4.1): origin 전체, 허용 계정 `accounts`(1–16개, 반환 순서, 첫 번째 = 선택 계정, 전체 주소), 체인 `chain_id`, 연결 시각 `granted_at_unix_ms`. `http` origin에는 "로컬 개발 사이트(http)" 배지.
- 맨 위 도움말 "연결된 사이트는 아래 계정의 주소를 볼 수 있고, EVM 사이트는 잔액과 거래 기록도 읽을 수 있습니다. 서명과 전송은 매번 이 앱의 확인 창에서 따로 승인합니다."와, 연결이 있으면 개수 줄 `연결 EVM {n}곳 · Solana {n}곳 · Bitcoin {n}곳`(0인 계열은 뺀다).
- 사이트마다 카드(제목 = `{origin 전체}  ·  {계열}`, 계열 `EVM`·`Solana`·`Bitcoin` — 한 사이트가 여러 체인에 연결되면 계열마다 카드가 하나씩이다): 네트워크, 연결 시각, 볼 수 있는 계정 수와 각 계정(라벨 + 전체 주소), 위험 버튼 `연결 해제`. 맨 아래 위험 버튼 `모든 사이트 연결 해제`. WalletConnect 세션 카드 아래 위험 버튼 `모든 WalletConnect 세션 끊기`도 2026-11-08부터 같은 확인 오버레이(`Confirm::WcDisconnectAll`: "WalletConnect 세션 n개를 모두 끊을까요? 다시 쓰려면 dApp마다 QR이나 링크로 새로 연결해야 합니다.", `모두 끊기`(위험)·`취소`)를 거친다(세션 하나의 `연결 해제`는 확인 없음). 연결이 없으면 카드 "연결된 사이트가 없습니다" + "dApp 사이트에서 '지갑 연결'을 누르고 이 앱의 연결 창에서 승인하면 여기에 표시됩니다."
- `연결 해제`(행), `모든 사이트 연결 해제`(확인 오버레이) → [05] §4.5. 그 origin의 대기 항목은 `Revoked`(§3.7).
- Solana·Bitcoin 연결(meta `sol_sites`·`btc_sites`, [05] §4.9)은 EVM 카드 다음에 같은 모양의 카드로 보인다: 네트워크(`Solana (메시지 서명·소유 증명만)`, `Bitcoin 메인넷 (메시지 서명·소유 증명만)`), 연결 시각, Solana는 계정 라벨(내 Solana 계정 목록에 있으면)과 base58 공개키, Bitcoin은 목적(`결제용 주소 (payment…)`·`오디널스용 주소 (ordinals…)`·`연결할 주소`)과 전체 주소, 위험 버튼 `연결 해제`(그 계열 grant만 지우고 그 계열의 대기 서명 항목만 `Revoked`). `모든 사이트 연결 해제`는 세 계열 모두 지운다.
- 쪽: EVM·Solana·Bitcoin을 이은 목록(최대 3 × 256개)을 한 쪽에 50개씩 보인다(행 수 제한 없음). 쪽이 둘 이상이면 카드 아래에 `n / m쪽 (연결 k곳, 한 쪽에 50곳)`과 `이전 쪽`·`다음 쪽`(해당할 때만, id 6,702·6,703). 행 버튼 id(6,710 + 쪽 안 순번)는 그 화면을 그릴 때 기록한 **(origin, 계열)** 을 가리킨다(`app_browser::SiteRows`): 그린 뒤 목록이 바뀌어도(dApp의 해제 등) 버튼은 그려진 사이트만 해제하고 다른 사이트로 밀리지 않는다.

### 2.10 주소록 (S14)
- 항목 = meta `address_book`의 `AddressBookEntry {chain, address, label, verified, added_at_unix_ms}`([02] §5.3, 최대 500; `added_at_unix_ms` = 추가 시각 unix ms). `verified` = 체크박스 "다른 경로(전화·대면 등)로 이 주소를 확인했습니다".
- 계열(2026-11-06, [02] §5.3): `chain`은 체인 계열이다. **EVM 항목 하나는 모든 EVM 체인**(내장 7개·사용자 추가 체인, EVM 주소를 받는 다른 보내기 화면 포함)에서 같이 쓰이고, Solana 항목은 mainnet·devnet에서 같이 쓰인다. Bitcoin 항목은 주소가 속한 네트워크(mainnet `bc1…`·`1…`·`3…` / testnet4 `tb1…`·`m…`·`n…`·`2…`)의 보내기 화면에만 나온다. 체인별 옛 EVM 항목은 읽을 때 하나로 합친다([02] §5.3 이전 규칙).
- 화면(`ui::screens_book`): 링크 `← 메인으로`, 제목 "주소록", 카드 "주소 추가"(편집 중이면 "{계열} 주소 편집"): 도움말, 탭 줄 `체인` = `EVM`·`Solana`·`Bitcoin`(체인 배지 §1.6.1, 편집 중에는 숨김) + 계열 공유 도움말, `주소`(편집 중 읽기 전용), `이름`, 체크 `다른 경로(…)로 이 주소를 확인했습니다`, 체크 `★ 즐겨찾기 (보내기 화면 맨 위에 표시)`, 주 버튼 `추가`/`저장`, 편집 중 `취소`. 그 아래 계열마다 카드 `EVM 주소록 — 모든 EVM 체인 공용 (n개)`·`Solana 주소록 — mainnet·devnet 공용 (n개)`·`Bitcoin 주소록 (n개)`(배지 + 제목): 행 = 이름(★, "✓ 확인됨"), 전체 주소(§3.3 묶음), Bitcoin은 네트워크 줄(배지 + `Bitcoin mainnet`/`Bitcoin testnet4`), 링크 `☆ 즐겨찾기`/`★ 즐겨찾기 해제`, `편집`, 위험 `삭제`. 행 순서 = 즐겨찾기(별 붙인 순서) 먼저, 나머지는 저장 순서. 비어 있으면 "{계열} 주소록이 비어 있습니다. …".
- 즐겨찾기(★): meta `address_book_favorites`([02] §5.3)에 둔다(항목 멤버가 아님 — 이전 버전 호환). 표시 전용이라 승인·위험 판단은 읽지 않는다. 모든 보내기 폼(EVM·Solana·Bitcoin, EVM 주소를 받는 다른 폼도 `app_book::BookTarget::Evm`으로 같은 칩)의 받는 주소 칸 위에 `즐겨찾기` 줄로 그 폼의 계열·네트워크에 맞는 ★ 항목을 최대 5개 칩(`★ {이름} · {앞…끝}`, EVM 체크섬 `0x` + 4자 … 끝 4자)으로 보이고, 누르면 칸을 채우고 검사를 돌린다. `주소록에서 선택` 목록도 ★ 항목을 먼저(`★ 주소록: {이름}`) 보인다. Bitcoin 폼에도 `주소록에서 선택`(그 네트워크 항목만, 입력한 글자로 거름)이 있다.
- 주소: 체인별 검증(§2.15)과 정규형 저장. 같은 계열에 같은 주소가 있으면 E-INP-016. 새 항목이 같은 계열의 기존 항목과 유사 주소(EVM §2.15 7행 규칙, Solana [07] §12.1 앞·뒤 3자, Bitcoin [08] §10 앞 4·끝 4자)이면 고위험 띠 "주소록의 '{이름}'과 앞·끝 글자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있으니 주소 전체를 확인한 뒤 저장하세요."와 `주소 전체를 직접 확인했습니다` 체크를 보이고, 체크 전에는 `추가`·`저장`을 끈다.
- 이름(주소록·계정·토큰 라벨 공통): [02] `Label` 규칙(1–32 스칼라, 금지 문자, 앞뒤 공백 금지; 입력 앞뒤 공백은 잘라 저장)에 더해 §3.3 표시 금지 문자도 거부한다 → E-INP-017.
- 다른 화면에서 저장(인라인 `주소록에 저장`, 이름 한 칸 + `저장`·`취소`, 위 유사 주소 확인 포함, `verified = false`로 저장 — 확인 표시는 S14 `편집`에서): (1) 보내기 폼 — 검사를 통과한 받는 주소가 주소록·내 계정에 없으면 그 아래 링크 `＋ 이 주소를 주소록에 저장`, (2) 보내기 결과 화면 — 보낸 받는 주소(EVM은 ERC-20이면 토큰 받는 사람, SOL은 받는 지갑, BTC는 받는 주소)가 없으면 카드 "받는 주소 {앞…끝}는 주소록에 없습니다." + `주소록에 저장`, 저장하면 완료 띠 "받는 주소를 주소록에 저장했습니다. …", (3) S10 활동 행 — 받는 주소가 주소록·내 계정에 없으면 링크 `이 주소 저장`(프롬프트는 그 행 아래). 저장하면 보내기 폼은 검사를 다시 돌려 "주소록: {이름}"을 보인다. 프롬프트는 화면을 바꾸면 닫힌다.
- `추가`, `편집`(이름·확인·★만, 주소·계열은 그대로), `삭제`(확인 오버레이 T-BOOK-DELETE: "'{이름}' ({앞…끝}) 항목을 주소록에서 지웁니다." + EVM이면 "EVM 항목은 모든 EVM 체인에서 함께 지워집니다." / Solana면 "Solana mainnet·devnet에서 함께 지워집니다." + "블록체인에는 아무것도 보내지 않으며, 같은 주소를 언제든 다시 추가할 수 있습니다."; 지우면 별도 지운다). 쓰기는 키 작업자의 meta 저장(원자적, [02] §6).
- 명령 id 14,000–15,699(`ui::screens_book::ids`, `ui::command_ids`): 폼 14,000–14,016, 즐겨찾기 칩 14,020–14,027, Bitcoin 목록 14,030–14,069, Solana 활동 `이 주소 저장` 14,080–14,143, S14 행 14,200 + 3 × 행(★·편집·삭제). EVM 활동 행은 기존 범위의 7번째 id(오프셋 6), Bitcoin 활동 행은 8번째(오프셋 7)를 쓴다.

### 2.11 설정 (S15)
화면: 링크 `← 메인으로`, 제목 "설정", 구역 탭 `보안`·`복구 단어`(§2.24)·`YubiKey`·`네트워크(RPC)`·`EVM 체인`·`Solana`·`Bitcoin`·`AI 설명`(M6)·`브라우저·정보`(선택한 탭은 채움; 2026-11-08 — 키·백업 탭을 앞에 모으고 `브라우저·진단·정보`를 `브라우저·정보`로 줄여 9개가 기본 창 폭에서 한 줄에 들어가게 했다. 명령 id는 그대로). 보안 구역의 "복구 단어·개인키" 카드는 복구 단어가 둘 이상이거나 가져온 키·YubiKey가 있으면 소제목 "백업 현황 — 이 지갑을 다시 열려면"과 줄 목록(복구 단어마다 "{라벨} · n단어 [+ passphrase] [(첫 복구 단어)] · 백업 확인됨 ✓/백업 확인 전 ⚠", "가져온 개인키 n개 — …각각 원래 개인키가 백업", "YubiKey n개 — 복구 단어 없이 연결한 키는 그 카드…가 유일한 사본 ⚠" 또는 "…복구 단어로 다시 만들 수 있습니다"), "이 PC의 비밀번호는 백업이 아닙니다…" 도움말을 보이고(`App::backup_status_lines`, 상태만 — 값·단어 없음), 버튼은 `첫 복구 단어 보기`·`개인키 보기`·링크 `복구 단어 관리 ▸`(복구 단어가 둘 이상일 때). 이전 문구 "복구 단어(니모닉)는 지갑 전체의 백업입니다"는 복구 단어 하나뿐인 지갑에만 남는다. 탭 줄 아래에는 그 구역의 지도 한 줄(`ui::screens::settings_map`, "이 구역: …" — 구역의 카드 이름과, 설정 밖에 있는 관련 기능의 자리: 토큰 추가는 메인 토큰 카드, Bitcoin 계정·주소 방식은 Bitcoin 탭, Zcash 켜기는 Zcash 탭, YubiKey 서명은 승인 뒤 PIN 창; 2026-11-07)을 둔다. 설정 검색은 없다(구역 8개와 지도 줄로 충분하다고 보고 미룸, docs/ux-review-20261107.md). 구역 안의 항목은 카드로 묶고 카드마다 한 줄 설명(도움말)을 둔다 — 보안: "자동 잠금", "복구 단어·개인키", "비밀번호"; 네트워크(RPC): "RPC 공급자"(RPC가 무엇이고 템플릿이 무엇을 해 주는지, 입력 칸마다 어디서 찾는 값인지), "네트워크별 RPC 주소", (보관 항목), 개발용 "rpc.json에서 가져오기"(파일이 있을 때만, 맨 아래 — 가져오기 확인 카드는 결정을 기다리므로 맨 위); EVM 체인: "EVM 체인"; Solana: "Solana 네트워크"; Bitcoin: "Bitcoin 사용과 네트워크", "주소 조회 서버(인덱서)", "Esplora URL"; AI 설명: "AI 설명 (선택 기능)"(상태 줄·`AI 설명 사용`), "AI 공급자 (OpenAI 호환)"(엔드포인트·모델·응답 형식·max_tokens, `저장`·`연결 테스트`), "AI API 키"(설정됨/없음, `키 저장`·`키 삭제`); 브라우저·정보: "브라우저 확장"(연결 상태, `Chrome 확장 설치 방법·폴더`), "WalletConnect"(무엇인지, 상태 `Project ID 없음 — 꺼져 있음`/`Project ID 설정됨 · 세션 n개`, `연결된 사이트 · WalletConnect 열기`), "브라우저 연결", "진단", "정보". 기술 항목은 `고급 설정 보기 ▸`를 켰을 때만 보인다: EVM 수수료 상한, 체인별 고정 제네시스 해시, Solana 수수료·CU 가격 상한, 로그 수준. `고급 설정 보기`를 켠 상태는 앱이 실행되는 동안만 유지하고 저장하지 않는다(보내기 폼의 `수수료 계산 보기`와 같은 상태). 템플릿 자격 정보의 `삭제`는 위험 버튼 `자격 정보 삭제`, URL이 없는 네트워크 행의 `교체`는 `입력`으로 보인다(같은 동작).

| 구역 | 항목 | 동작 |
|---|---|---|
| 보안 | 자동 잠금(분) | 1–60, `autoLockMinutes` |
| 보안 | 니모닉·개인키 복사 허용 | 켤 때 T-COPY-ON 오버레이 확인, `allowSecretCopy` |
| 보안 | 니모닉 보기 / 개인키 보기 / 비밀번호 변경 | §2.12, §2.13 |
| 네트워크 | RPC 공급자 | 템플릿 라디오(`rpc.template`, §6.1): `QuickNode 멀티체인`(엔드포인트 이름 EDIT + 토큰 EDIT `ES_PASSWORD`, 둘 다 256자; 어느 칸에든 대시보드의 엔드포인트 주소 전체를 붙여넣을 수 있다 — `apikeys::quicknode_credentials`가 이름·토큰으로 나누고, 틀린 칸은 E-KEY-002 + `QuickNodeField::label`) / `알케미`(키 EDIT `ES_PASSWORD`) / `직접 입력`(입력 칸 없음). 입력 칸은 붙여넣기 허용·복사 불가. `저장`·`삭제`(선택한 템플릿의 자격 정보, §6.3 `tpl:quicknode`·`tpl:alchemy`; 저장된 값은 다시 보이지 않고 "설정됨/없음"만), `네트워크 URL 생성`(§2.11.1, `직접 입력`이면 비활성). 자격 정보를 바꾸거나 지워도 이미 만든 URL은 그대로다(런타임은 네트워크별 URL만, §1.9) |
| 네트워크 | 네트워크 URL | §2.11.1 목록: `NetworkId`마다(기본 EVM 3 + 사용자 체인 + `solana:*` 2 + `bitcoin:*` 2) 상태·가린 URL, `교체`·`테스트`·`삭제`(§6.3 `rpc:<NetworkId>`) |
| 네트워크 | 보관 중인 항목 | 보관 항목(§6.3 고아 `rpc:*`·모르는 이름, §6.6)이 있을 때만 카드: 개수와 설명, 위험 버튼 `보관 항목 삭제` → 확인 오버레이(항목 이름 목록, 이름은 비밀 아님) → `ApiKeys::prune_dormant` + 저장(실패 E-APP-002, 파일을 다시 읽어 항목이 남음). 로그 `apikeys.pruned count=<n>` |
| 네트워크 | EVM 체인 | 목록: 기본 7개(1·11155111·999·42161·8453·56·4663) + 사용자 체인(최대 32, §2.17). 행 = 이름, chainId, 네이티브 심볼·소수 자릿수, 엔드포인트 상태(설정됨·없음; URL은 `네트워크 URL` 목록에서 가린 형태로만), 사용자 체인의 템플릿 식별자(`quicknodeSubdomain`·`alchemyLabel`, 있으면; 비밀 아님), 시뮬레이션 `auto`/`unsupported`, 고정 제네시스 해시(전체 hex; HyperEVM 고정 전은 "첫 연결 때 고정"), 상태(연결됨·확인 전·차단). 목록 아래 도움말 "다른 EVM 체인(L1·L2)은 여기서 추가합니다 — chainId·RPC URL을 넣으면 chainId와 블록 0을 확인해 등록합니다."와 버튼 `EVM 체인 추가`(S17), 사용자 체인 행의 `편집`(S17)·`삭제`(§2.17.3), 최초 신뢰 체인이 E-CHN-008이면 `다시 고정`(§2.17.4). 기본 체인은 편집·삭제가 없다 |
| 네트워크 | EVM 수수료 상한 | 체인 선택(기본 7 + 사용자 체인) + 3값(§6.1 `feeCaps`), `기본값으로`. 기본값은 [03] §3.4(기본 체인 `default_caps`, 사용자 체인은 [03]의 보수적 기본값) |
| Solana (M7) | 클러스터, 수수료 상한, 다른 경로 스캔 | [07] §10·§3.3. 엔드포인트는 `네트워크 URL` 목록의 `solana:<cluster>` 행(§6.3 `rpc:solana:<cluster>`) |
| Bitcoin (M8) | 켜기·네트워크 선택 | `bitcoin.enabled`·`bitcoin.network`(§6.1), 켜기·네트워크 변경 조건은 [08] §2(그 네트워크의 `rpc:bitcoin:<net>` URL이 없으면 켤 수 없음, E-KEY-005; 인덱서와 무관). 체크박스 `Bitcoin 사용`(켜기·끄기) + 네트워크 라디오 `mainnet`/`testnet4`: 꺼져 있을 때 라디오는 `bitcoin.network`만 쓰고(확인 창·`BtcMeta` 변경 없음) `Bitcoin 사용`이 그 네트워크로 켠다. 켜진 뒤 라디오는 [08] §2 네트워크 바꾸기(확인 창). Core 엔드포인트는 `네트워크 URL` 목록의 `bitcoin:<net>` 행([08] §4.2) |
| Bitcoin (M8) | 인덱서 | 라디오 `bitcoin.indexer`: `Esplora`(기본, 무료·키 없음) / `Blockbook JSON-RPC (bb-rpc)`(Core URL에 `bb_*`, QuickNode BTC Blockbook 유료 애드온 필요) / `Blockbook REST (bb-rest)`(Core URL `/api/v2/`, 알케미 UTXO API). 형식은 URL·호스트에서 추론하지 않는다([08] §2). `bb-rpc`·`bb-rest`를 고르면 오버레이 T-BTC-BB-OPTIN 확인 뒤 저장한다. 언제든 바꿀 수 있고 바꾸면 새 `RpcConfig` + [08] §2 연결 검사. 라디오 아래 고정 문구 T-BTC-ESPLORA-NOTE |
| Bitcoin (M8) | Esplora URL | 네트워크마다 한 줄(`mainnet`·`testnet4`): 현재 값 전체(비밀이 아니므로 가리지 않음) + 일반 EDIT(붙여넣기·복사 허용) + `저장`(§6.1 형식, 위반 E-BTC-006) · `기본값으로`([08] §15 `BTC_ESPLORA_DEFAULT_*`) · `테스트`. `테스트` = EDIT 값(비어 있으면 저장된 값)으로 `GET <URL>/block-height/0` 1회(호출당 10 s, 재시도 없음; 주소를 보내지 않으므로 잠긴 상태에서도 허용, [08] §4.4): 본문이 그 네트워크의 [08] §2 제네시스면 T-BTC-IDX-OK, 다른 64자 hex면 E-BTC-003, 그 밖은 [08] §4.3 분류(E-BTC-001·004·007). `저장`은 `테스트`를 요구하지 않는다(사용 전 [08] §2 연결 검사 3단계가 다시 확인). `indexer`가 `esplora`가 아니어도 편집할 수 있다. 저장 → 새 `RpcConfig` + [08] §2 연결 검사, 로그 `btc.esplora_url_set net=<NetworkId>`(URL 없음) |
| 브라우저 | localhost dApp 허용 | 켤 때 T-LOCALHOST-ON 확인, `allowLocalhostDapps`(D22, [05] §4.6) |
| 브라우저 | dApp 요청 시 앱 자동 실행 | `browserAutoLaunch`(D24, 기본 켬). 끄면 yw-app이 꺼져 있을 때 dApp 요청은 4900 |
| 브라우저 | WalletConnect·연결된 사이트 | "WalletConnect" 카드의 `연결된 사이트 · WalletConnect 열기` → S13 |
| AI 설명 (M6) | [06] §2 | [06] |
| 진단 | 로그 수준, 로그 폴더 열기 | §8, §2.14 |
| 정보 | 버전, 데이터 폴더 경로, `폴더 열기`, "단축키" 줄(Ctrl+L 잠금 · Ctrl+1/2/3/4 체인 탭 · Tab 다음 칸) | §2.14 |

- 템플릿 자격 정보 형식(`저장` 때 검사, 위반 E-KEY-002 + 항목 이름): QuickNode 엔드포인트 이름은 소문자로 바꾼 뒤 `^[a-z0-9]+(-[a-z0-9]+)*$` 1–63자(호스트 첫 라벨), QuickNode 토큰 `^[A-Za-z0-9_-]{16,128}$`(URL 경로 한 단계), 알케미 키 `^[A-Za-z0-9_-]{16,128}$`(URL 경로). 구현 시 확인: 실제 이름·토큰·키의 길이·문자 집합. 다르면 이 정규식만 고친다.
- 변경은 즉시 `settings.json`에 원자적으로 쓴다(`apikeys.dpapi` 항목은 §6.3). 실패 → E-APP-002, 화면 값을 되돌린다. 읽기 전용 `settings.json`(§6.6 더 새로운 `version`, `Settings::read_only()`)이면 쓰지 않고 이번 실행의 메모리에만 적용한다(로그 `settings.changed key=<키> saved=no`).
- 수수료 상한·사용자 체인 정의 변경은 다음 준비부터 적용한다. 이미 표시 중인 승인 창은 그대로 둔다(표시 내용은 digest로 묶여 있다, [03] §11).

#### 2.11.1 RPC 엔드포인트 (D13)
런타임은 네트워크별 URL(§6.3 `rpc:<NetworkId>`)만 쓴다(§1.9). 템플릿은 그 URL을 만드는 입력 편의이고, 템플릿으로 만든 URL도 네트워크별로 `교체`할 수 있다. 사용자의 현재 공급자는 QuickNode다(D13).

**템플릿 URL** — `fn template_url(t: RpcTemplate, cred: &TemplateCred, entry: Option<&str>) -> Option<HttpsUrl>`(순수 함수, `RpcTemplate { QuickNode, Alchemy, Manual }`):

| 템플릿 | 자격 정보(§6.3) | 네트워크 항목(`entry`) 출처 | URL |
|---|---|---|---|
| QuickNode 멀티체인 | `tpl:quicknode` = 엔드포인트 이름 + 토큰 | 서브도메인·경로: 기본 EVM [03] §1.1 `templates.quicknode_subdomain`(Ethereum 메인넷 = 서브도메인 없음)·`templates.quicknode_path`(HyperEVM = `nanoreth`), SOL [07] §15.1, BTC [08] §2, 사용자 체인 `evmChains[].quicknodeSubdomain` | `https://<이름>.<서브도메인>.quiknode.pro/<토큰>/`, 서브도메인 없음이면 `https://<이름>.quiknode.pro/<토큰>/`; 경로가 있으면 끝에 붙인다(예 `…/<토큰>/nanoreth`) |
| 알케미 | `tpl:alchemy` = 키 | 라벨: [03] §1.1 `templates.alchemy_label`, [07] §15.1, [08] §2, `evmChains[].alchemyLabel` | `https://<라벨>.g.alchemy.com/v2/<KEY>` |
| 직접 입력 | 없음 | — | 만들지 않음(`None`) |

- 그 네트워크의 템플릿 항목이 없으면(예: 그 템플릿 식별자가 없는 사용자 체인) `None`. BTC는 두 템플릿 모두 항목이 있다(QuickNode testnet4 서브도메인 `btc-testnet4`, [08] §2). 만든 문자열은 `HttpsUrl::parse`를 거치고, 실패하면 그 네트워크를 건너뛴다(입력 검사가 있으므로 방어 중복). 서브도메인 표는 구현 시 각 공급자 대시보드와 대조한다(D13).

**`네트워크 URL 생성`**
1. 템플릿이 `직접 입력`이면 비활성. 입력 칸에 값이 있으면 먼저 `저장`과 같이 검사(E-KEY-002)·저장한다. 선택한 템플릿의 자격 정보가 저장돼 있지 않으면 E-KEY-004.
2. 대상 = 등록된 모든 네트워크(기본 EVM 3, 사용자 체인, `solana:*` 2, `bitcoin:*` 2; 아래 목록과 같이 각 체인 탭이 구현된 단계부터) 중 `template_url`이 `Some`인 것. 오버레이 T-RPC-GENERATE: 대상(네트워크 이름·`NetworkId`, 이미 URL이 있으면 "기존 URL 있음"), 템플릿 항목이 없어 건너뛰는 네트워크, 체크박스 `기존 URL 덮어쓰기`(기본 끔). `생성` / `취소`.
3. URL이 없는 대상과, 체크했을 때 URL이 있는 대상에 새 URL을 넣는다. 사용자 EVM 체인의 새 URL은 저장 전에 §2.17.2-2 확인(chainId·고정 제네시스 일치; 순서대로, 호출당 10 s, 재시도 없음)을 통과한 것만 쓰고, 실패한 체인은 기존 값(또는 없음)을 유지한다. 기본 네트워크는 네트워크 호출 없이 쓴다(다음 사용 때 체인 확인, [03] §1.4·[07] §15.1·[08] §2).
4. `apikeys.dpapi`를 한 번 쓴다(§6.3; 실패 → E-APP-002, 메모리 값 되돌림). 성공 → 새 `RpcConfig`, 바뀐 네트워크의 체인 확인 상태 초기화, T-RPC-GENERATED(실패한 사용자 체인은 네트워크 이름 + 코드). 로그 `rpc.generated`(`NetworkId` 목록만).

**네트워크 URL 목록** — 행 = 네트워크 이름, `NetworkId`, 상태(`설정됨`·`없음`), 가린 URL, 버튼 `교체`·`테스트`·`삭제`. 순서: 기본 EVM 3 → 사용자 체인(`evmChains` 순서) → `solana:mainnet`·`solana:devnet` → `bitcoin:mainnet`·`bitcoin:testnet4`(각 체인 탭이 구현된 단계부터).
- 가린 표시 `mask_url(&HttpsUrl) -> String` = `https://` + `●●●●` + (호스트가 `.quiknode.pro`로 끝나면 `.quiknode.pro`, `.g.alchemy.com`으로 끝나면 `.g.alchemy.com`, 그 밖은 없음) + `/●●●●`. 엔드포인트 이름·서브도메인·라벨·경로·토큰은 어디에도 보이지 않는다. 저장된 URL을 평문으로 다시 보는 기능은 없다(바꾸려면 `교체`).
- `교체`: EDIT(`ES_PASSWORD`, 붙여넣기 허용, 복사 불가) + `저장`·`취소`. `HttpsUrl::parse` 위반 E-KEY-003. 사용자 EVM 체인은 저장 전 §2.17.2-2 확인(통과해야 저장). 저장 → `apikeys.dpapi`(§6.3) → 새 `RpcConfig`, 그 네트워크의 체인 확인 상태 초기화. 로그 `rpc.url_set net=<NetworkId>`.
- `테스트`: `교체` 칸에 값이 있으면 그 값(형식 검사 먼저, E-KEY-003), 비어 있으면 저장된 URL(없으면 E-KEY-005)로 1회 호출(호출당 10 s, 재시도 없음, 저장과 무관):

  | 체인 | 호출 | 일치 조건 | 불일치 |
  |---|---|---|---|
  | EVM `eip155:<id>` | `eth_chainId` | 결과 == `<id>`의 정규 hex(소문자 비교) | E-RPC-010 (`chainId`, RPC 값을 10진으로 함께) |
  | Solana `solana:<cluster>` | `getGenesisHash` | [07] §15.1 genesis hash | E-RPC-010 (`genesis`) |
  | Bitcoin `bitcoin:<net>` | `getblockchaininfo` | `chain` == [08] §2 값(`"main"`·`"testnet4"`) | E-RPC-010 (`chain`) |

  일치 → T-RPC-OK. 결과 형식 이상 → E-RPC-005, 그 밖은 §1.9 분류(HTTP 401/403 → E-RPC-003, 리퍼러·origin 허용 목록 거부 → E-RPC-009). 구현 시 확인: 사용 중인 공급자(현재 QuickNode)에서 잘못된 토큰·허용 목록 거부 때의 HTTP 상태·JSON-RPC 코드. 구분할 수 없으면 둘 다 E-RPC-003으로 보이고 허용 목록 안내를 덧붙인다. BTC 인덱서는 여기서 `테스트`하지 않는다(Esplora는 Bitcoin 설정의 `Esplora URL` `테스트`, 모든 인덱서는 [08] §2 연결 검사 3단계가 BTC 첫 호출 때 한다). RPC가 준 문자열은 보이지 않는다(§7). 로그 `rpc.test net=<NetworkId> result=<코드|ok>`.
- `삭제`: `rpc:<NetworkId>` 제거 → `apikeys.dpapi` → 새 `RpcConfig`, 로그 `rpc.url_deleted net=<NetworkId>`. 그 네트워크는 엔드포인트 없음(E-KEY-005)이 된다. 진행 중 거래의 영수증·상태 추적은 URL을 다시 넣을 때까지 멈추고 저널은 그대로 둔다([03]·[07]·[08]). 사용자 체인 정의는 지우지 않는다(체인 삭제는 §2.17.3).

### 2.12 니모닉·개인키 보기
1. `니모닉 보기` → T-REVEAL-WARN → W03 → `KeyJob::Reveal { password, what: Mnemonic }` → `reveal_mnemonic`(`BackupPending`·`Unlocked`, 매번 Argon2, S03 진행 표시).
2. 성공 → `Zeroizing` 버퍼를 W08로 이동. passphrase 지갑이면 W08 아래에 "이 지갑은 passphrase를 사용합니다. passphrase는 저장되지 않으므로 따로 보관해야 합니다."
3. `개인키 보기`: EVM 계정 선택 → W03 → `reveal_evm_private_key`(`Unlocked`만) → W09(소문자 hex 64자, [02] §9 형식 그대로). 가져온 Solana·Bitcoin 키는 그 탭에서 선택한 가져온 계정의 `개인키 보기` → T-REVEAL-WARN → W03 → `reveal_imported_key` → W09(Solana base58 64바이트 keypair, Bitcoin WIF; 64자를 넘으면 44자씩 줄을 나눠 그리고 복사는 원문 그대로). 파생(니모닉) SOL·BTC 개인키 표시는 없다. 키 전용 지갑의 보안 구역에는 `복구 단어 보기`가 없다.
4. `UnlockFailed` → E-VLT-001, 1초 비활성 후 W03 유지.

### 2.13 비밀번호 변경
W04(현재, 새, 새 확인) → 새 비밀번호 검사(E-INP-001/002) → `KeyJob::ChangePassword` → S03 "비밀번호를 바꾸는 중…". DEK는 그대로이고 다시 감싸기만 한다(D7). 현재 비밀번호 오류 → E-VLT-001(1초 비활성). `Rewrap` 쓰기 실패 → E-VLT-003, vault는 이전 상태(이전 비밀번호 유효). 성공(`PasswordChange::Complete`) → "비밀번호를 바꿨습니다. 이미 만들어 둔 지갑 파일 사본(백업한 vault.ywv, 이전 사본, 격리된 손상 파일)은 예전 비밀번호로 계속 열립니다 — 예전 비밀번호가 샜다면 그런 사본을 지우세요." `Rewrap`은 반영됐지만 뒤이은 `PayloadRewrite`가 실패(`PrevNotRefreshed`, [02] §4.4) → 실패라고 하지 않는다: "비밀번호를 바꿨습니다. 지금부터는 새 비밀번호로 엽니다. 다만 이전 복사본(vault.ywv.prev)을 새 비밀번호로 다시 쓰지 못해, 그 복사본은 다음 저장 전까지 예전 비밀번호로만 열릴 수 있습니다. 이미 만들어 둔 지갑 파일 사본도 예전 비밀번호로 계속 열립니다."
- DEK를 바꾸지 않으므로 비밀번호 변경은 이미 새어 나간 사본을 회수하지 못한다(2026-11-01 검토 L1, [02] §4.4). W04 안내에 "바꾸기 전에 만든 지갑 파일 사본(백업한 vault.ywv, .prev)은 예전 비밀번호로 계속 열립니다."를, 설정 → 보안 → 비밀번호 카드에 `T_PASSWORD_OLD_COPIES`(사본은 예전 비밀번호로 열리고 사본 + 예전 비밀번호로 지금 파일도 풀린다; 예전 비밀번호가 샜다면 사본을 지우고 자산을 새 지갑으로 옮기는 것이 확실하다)를 보인다. 대처는 `docs/recovery-guide.ko.md`.

### 2.14 폴더 열기
`std::process::Command::new(<%SystemRoot%>\explorer.exe).arg(<폴더>)`(`SystemRoot`가 없으면 `C:\Windows`). 셸 API·URL은 쓰지 않는다. 로그 폴더 버튼 옆에 T-LOG-FOLDER.

### 2.15 입력 검증
**EVM 주소**(받는 주소, 주소록, 토큰 컨트랙트). 앞뒤의 공백·탭·CR·LF만 잘라낸다.

| 순서 | 검사 | 결과 |
|---|---|---|
| 1 | `0x` + hex 40자 | 아니면 E-INP-009 |
| 2 | 대소문자 혼합이면 EIP-55 체크섬 일치(전부 소문자·대문자 허용, [03] §2) | 불일치 E-INP-010 |
| 3 | 0 주소 | E-INP-014 차단 |
| 4 | (ERC-20) 선택 토큰의 컨트랙트 주소 | E-INP-015 차단 |
| 5 | 보내는 계정과 같음 | W-ADDR-1 "보내는 계정과 같은 주소입니다." |
| 6 | 주소록·내 계정에 정확히 있음 | 주석 "주소록: {이름}"(verified면 "✓ 확인됨" 덧붙임) 또는 "내 계정: {라벨}" |
| 7 | 같지 않지만 `0x` 뒤 hex 40자의 일치하는 앞 P자 + 일치하는 끝 S자 ≥ 6(어떤 나눔이든: 3+3·2+4·4+2·6+0…, 대소문자 무시)인 주소가 주소록·내 계정·**보낸 내역**에 있음(여럿이면 일치 글자가 가장 많은 것, 같으면 주소록·내 계정 우선) | W-ADDR-3 "'{이름}'과 앞 P자·끝 S자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다."(한쪽이 0이면 그쪽은 빼고, 보낸 내역이면 "보낸 내역에 있는 주소(0x…)와 …"), 확인 체크 필요. 무작위 주소가 아는 주소 하나와 우연히 걸릴 확률 ≈ 16⁻⁶ · (1 + 6·15/16) ≈ 3.9e-7(합 5면 ≈ 5.4e-6) |
| 8 | 6·7 해당 없음(보낸 내역과 정확히 같아도) | W-ADDR-2 "주소록에 없는 주소입니다. 주소 전체를 확인하세요." |
| 9 | (네이티브 자산) `eth_getCode`가 비어 있지 않음 | W-ADDR-4 "컨트랙트 주소입니다. 받는 쪽이 이 자산을 처리할 수 있는지 확인하세요." |

**보낸 내역(아는 주소, Solana와 같은 방식).** 모든 EVM 체인 저널 레코드의 거래 `to`와, ERC-20 `transfer`(`a9059cbb`)·`transferFrom`(`23b872dd`) 호출이면 엄격 디코드([03] §7.1)한 받는 주소, 그리고 meta `activity["eip155:*"]`의 상대 주소. 중복과 0 주소는 뺀다. 보낸 내역은 7의 닮은 주소 검사에만 쓰고 받는 사람 고르기 목록에는 넣지 않는다.

**금액**: 이식 `archive/spec-v2.4:demo/sepolia-wallet/src/erc20.rs:222-266` `parse_token_amount`와 [03] `parse_units`. 숫자와 `.` 하나, 부호·지수·쉼표·공백 금지, 소수 자리 ≤ decimals, 0 초과, 입력 ≤ 128바이트 → 위반 E-INP-011. 네이티브 자산(ETH 등, 소수 자릿수는 그 체인 값)은 금액 + 최대 수수료 ≤ 잔액, 토큰은 금액 ≤ 토큰 잔액이고 최대 수수료 ≤ 네이티브 잔액 → 위반 E-INP-012.

**SOL·BTC**: 주소·금액 파서와 유사 주소·처음 보내는 주소 경고는 [07] §12·[08]의 규칙(예: SOL 앞뒤 3자)을 따르고, 6번 주석은 같다.

### 2.16 주요 문구
| ID | 위치 | 문구 |
|---|---|---|
| T-FIRST-1 | S01 | Your Wallet은 이 PC에서만 쓰는 개인용 암호화폐 지갑입니다. / 돈을 보내거나 사이트에 서명할 때는 언제나 이 앱의 확인 창에서 내용을 보고 직접 승인합니다. / 지갑을 만들 때 받는 복구 단어 24개가 유일한 백업입니다. 종이에 적어 안전한 곳에 보관하세요. (세 줄) |
| T-LEFTOVER | S01 | 이전 지갑의 파일이 데이터 폴더에 남아 있습니다. 앱을 종료하고 파일을 다른 곳으로 옮긴 뒤 다시 실행하세요. |
| T-RESET-INTRO | S22 | 이 PC의 지갑 파일을 옮겨 두고 처음 화면으로 돌아갑니다. 자산은 블록체인에 그대로 있지만, 이 지갑을 다시 쓰려면 복구 단어(니모닉) — 여러 개면 각각 — 또는 원래 개인키가 있어야 합니다. YubiKey의 키는 카드에 남아 'YubiKey 연결하기 (복구 단어 없이)'로 다시 연결할 수 있습니다. (2026-11-08: 복구 단어 여러 개·YubiKey 연결 반영) |
| T-RESET-NOUNLOCK | S22 | 비밀번호를 잊었어도 진행할 수 있습니다. 잠금 해제 없이 파일만 옮깁니다. |
| T-RESET-MOVE | S22 | 지갑 파일(vault.ywv와 이전 사본 .prev, meta.ywm, journal.ywj, 격리된 손상 파일)을 지우지 않고 데이터 폴더 안의 새 폴더로 옮깁니다. 옮긴 파일은 예전 비밀번호로 계속 열리며, 되돌리는 방법은 복구 안내(recovery-guide)와 새 폴더의 README-reset.txt에 있습니다. |
| T-RESET-YUBIKEY | S22 | YubiKey를 쓰는 지갑이었다면 YubiKey 안의 키는 그대로 남습니다. 초기화는 YubiKey를 지우거나 바꾸지 않습니다. 다시 쓰려면 복구 단어로 지갑을 가져온 뒤 YubiKey를 다시 등록하거나, 복구 단어 없이 첫 화면의 'YubiKey 연결하기 (복구 단어 없이)'로 카드의 키를 다시 연결하세요. |
| T-RESET-SETTINGS | S22 | 설정(settings.json)과 저장한 API 키·RPC 주소(apikeys.dpapi)는 기본으로 그대로 둡니다. 새 지갑에서도 같은 RPC 설정을 씁니다. |
| T-RESET-IN-FLIGHT | S22 | 보내는 중인 거래가 있습니다. 초기화해도 이미 보낸 거래는 블록체인에서 계속 처리되지만, 이 앱에서는 결과를 더 볼 수 없습니다. 끝난 뒤에 초기화하는 것을 권합니다. |
| T-META-FAILED | 세션 화면 위 | 계정 이름·주소록·연결한 사이트·보안 설정 기록이 담긴 meta 파일(meta.ywm)을 불러오지 못했습니다. 파일은 그대로 두었고, 불러오기에 성공할 때까지 이 파일에 아무것도 쓰지 않습니다. '다시 불러오기'를 누르거나, '잠금'을 누른 뒤 다시 잠금 해제해 보세요. 계속 실패하면 디스크 공간과 백신의 파일 차단을 확인하고 로그 폴더의 yw-app.log를 보세요. 그래도 안 되면 앱을 종료하고 데이터 폴더를 통째로 백업한 뒤 복구 안내(recovery-guide)를 따르세요. (뒤에 오류 코드) |
| T-WAIT-STALLED | S03·S12 | 30초가 지나도 불러오기가 끝나지 않았습니다. '다시 불러오기'를 누르거나, '잠금'을 누른 뒤 다시 잠금 해제해 보세요. 그래도 안 되면 앱을 종료했다가 다시 실행하세요. 계속되면 로그 폴더의 yw-app.log를 확인하고, 복구 단어(또는 원래 개인키)가 있다면 잠금 화면의 '지갑 초기화…'로 처음부터 시작할 수 있습니다. |
| T-EXT-MISSING | S23 | 확장 폴더를 찾지 못했습니다. 설치 프로그램(install.cmd)을 다시 실행하면 앱 폴더 안에 extension 폴더가 만들어집니다. |
| T-CREATE-1 | S02 | · 종이와 펜을 준비하세요. 다음 화면들에서 복구 단어 24개와 첫 주소를 적습니다. / · 복구 단어는 종이(또는 금속)에만 적고 사진·클라우드·메신저에 남기지 마세요. / · 화면 공유·녹화를 끄고 주변에 사람이나 카메라가 없는지 확인하세요. (세 줄) |
| T-PW-RULE | W01·W04 | 비밀번호는 영문·숫자·기호(ASCII) 12–128자입니다. 단어 4개 이상을 이은 긴 문장을 권장합니다. 잊으면 복구 단어(니모닉)로만 복구할 수 있습니다. |
| T-MN-SHOW | W08 | 아래 {n}단어와 첫 주소를 순서대로 종이에 적으세요. 이 단어들이 지갑의 유일한 백업이며, 아는 사람은 누구든 자산을 옮길 수 있습니다. 이 창은 화면 캡처에서 제외됩니다. |
| T-BACKUP-1 | W10 | 적은 종이를 보고 {p1}, {p2}, {p3}, {p4}번째 단어를 입력하세요. |
| T-BACKUP-FAIL | W10 | 입력한 단어 중 종이와 다른 것이 있습니다. 같은 위치({a}·{b}·{c}·{d}번째)를 다시 묻습니다. + 다음 단계 한 문장: 단어를 다시 볼 수 있는 흐름(S04, 설정 → 복구 단어)은 "종이에 잘못 적었을 수 있으니, 이 창을 닫고 복구 단어를 다시 보면서 이 네 단어를 종이와 대조해 고치세요.", 새 YubiKey 지갑(창을 닫으면 단어가 지워짐)은 "종이의 이 네 단어를 다시 확인하세요. 종이가 틀렸는지 알 수 없다면 이 창을 닫아 만들기를 취소하고(단어는 지워집니다) 처음부터 다시 만드세요." (`ui::screens::backup_retry_text`) |
| T-BACKUP-OK | S08 | 백업을 확인했습니다. 이제 지갑을 쓸 수 있습니다. |
| T-IMPORT-OK | S08(가져오기 뒤) | 지갑을 가져왔습니다. 이제 지갑을 쓸 수 있습니다. |
| T-BACKUP-PENDING | S04 | 백업 확인이 끝나지 않았습니다. 확인 전에는 보내기·서명·dApp 승인을 쓸 수 없습니다. |
| T-BACKUP-RECV | S12 | 백업 확인 전입니다. 확인을 마치기 전에는 큰 금액을 받지 마세요. |
| T-IMPORT-PASS | W05 | 이전 지갑에서 BIP39 passphrase(25번째 단어)를 썼을 때만 켜세요. ASCII만 지원합니다. |
| T-IMPORT-ADDR | S06 | 가져온 지갑의 첫 주소입니다. 이전 지갑에서 쓰던 주소와 전체가 같은지 확인하세요. |
| T-UNLOCK-PENDING | S07·W02 | 잠금 해제를 기다리는 요청 {n}건: {origin 목록} |
| T-PASS-MISMATCH | S07 | passphrase가 다를 수 있습니다. 다른 passphrase는 다른(빈) 지갑을 엽니다. |
| T-ALT-PASS | 모든 화면(고위험 띠, 닫기 없음) | passphrase 확인값과 맞지 않는 passphrase로 연 지갑입니다. 오타라면 이 지갑은 원래 지갑이 아닌 다른(빈) 지갑이고, 여기로 받은 자산은 지금 입력한 passphrase와 대소문자·공백까지 정확히 같은 값을 다시 넣어야만 꺼낼 수 있습니다. 그래서 받기와 사이트 연결·서명을 막았습니다. 계정 이름·주소록·연결 기록도 저장되지 않습니다. 잘못 입력했다면 잠그고 다시 여세요. |
| T-ALT-PASS-RECV | S10(`받기`) | 확인되지 않은 passphrase로 연 지갑에서는 받기를 쓸 수 없습니다. 잠그고 passphrase를 다시 입력하세요. |
| T-UNLOCK-PREV | S07(잠금 해제 실패 뒤, `.prev` 있음) | 비밀번호가 맞는데도 계속 열리지 않으면 지갑 파일이 손상되었을 수 있습니다. 같은 비밀번호로 이전 사본(.prev) 복구를 시도할 수 있습니다. 지갑 파일이 정상이면 복구하지 않고 그대로 엽니다. |
| T-ACCOUNTS | S10 `내 계정` | 보내기·받기에 쓸 계정을 고르세요. 경로(m/44'/60'/…)가 있는 계정은 복구 단어로 복구되지만, '가져온 개인키' 계정은 복구 단어로 복구되지 않으니 그 개인키를 따로 백업하세요. |
| T-IMPORTED-KEY | W07 | 주의: 가져온 개인키는 이 지갑의 복구 단어(24단어)로 복구되지 않습니다. 이 PC나 지갑 파일을 잃으면 이 계정은 원래 개인키로만 되살릴 수 있으니, 원래 개인키를 따로 안전하게 보관하세요. |
| T-REMOVE-KEY | S10 삭제 확인 | 선택한 가져온 개인키 계정을 이 지갑에서 지웁니다. 가져온 개인키는 복구 단어로 복구되지 않으므로, 지우고 나면 원래 개인키 없이는 이 계정의 자산에 다시 접근할 수 없습니다. 지우기 전에 설정 → 보안 → '개인키 보기'로 개인키를 내보내 안전하게 보관했는지 확인하세요. 계속하려면 비밀번호를 입력하세요. |
| T-TOKEN-DELETE | S10 토큰 `삭제` 확인 | 이 토큰을 이 네트워크의 토큰 목록에서 지웁니다. 토큰이나 잔액은 그대로이며 블록체인에는 아무것도 보내지 않습니다. 같은 컨트랙트 주소로 언제든 다시 추가할 수 있습니다. 지운 뒤 이 토큰의 활동 기록은 원시 단위로 보입니다. |
| T-TOKEN-HIDDEN | S10 숨긴 토큰 목록 위 | 숨기기는 이 목록과 보내기 화면의 자산 선택에서만 감춥니다. 잔액 조회, 승인 창의 토큰 확인, 활동 기록은 그대로입니다. |
| T-DISCARD | S10 `폐기` 확인 | 폐기는 이 앱에서 추적만 멈추고 '폐기됨'으로 표시합니다. 네트워크에서 거래를 취소하지는 않습니다. 이미 전파된 거래라면 나중에 처리될 수 있고, 그 사이 같은 송금을 다시 보내면 두 거래가 모두 처리되어 두 번 지불될 수 있습니다. 확실히 막으려면 폐기 대신 '취소'(같은 nonce의 취소 거래)를 쓰고, 다시 보내기 전에 탐색기에서 이 거래가 사라졌는지 확인하세요. |
| T-MAINNET | S10 메인 화면(EVM 탭: Ethereum 메인넷 1·HyperEVM 999·Arbitrum One 42161·Base 8453·BNB Smart Chain 56·Robinhood Chain 4663, Solana 탭: mainnet) 빨간 띠, A01 승인 창 헤더 배지(그 요청의 체인이 위 기본 메인넷이거나 Solana mainnet). 사용자 체인·Bitcoin은 해당 없음(Bitcoin은 [08] §2 배너) | 메인넷 — 실제 자산 |
| T-JOURNAL-RESET | S07 | 거래 저널을 새로 시작하면 진행 중 거래 기록이 사라질 수 있습니다. |
| T-RECOVER-PREV | S09 | 이전 사본으로 복구하면 마지막 변경(예: 가져온 개인키)이 사라질 수 있습니다. |
| T-REVEAL-WARN | S15 | 화면 근처의 사람이나 카메라가 볼 수 있습니다. 계속하려면 비밀번호를 입력하세요. |
| T-COPY-ON | S15 | 복사를 허용하면 복구 단어(니모닉)·개인키를 클립보드에 넣을 수 있습니다. 클립보드 기록·클라우드 동기화에서는 제외하고 30초 뒤 지우지만, 그 사이에는 다른 프로그램이 읽을 수 있습니다. |
| T-COPY-OFF | W08·W09 | 복사가 꺼져 있습니다. 설정에서 바꿀 수 있습니다. |
| T-COPIED | W08·W09 | 클립보드에 복사했습니다. 30초 뒤 지웁니다. |
| T-PASTE-CLEARED | W01–W07 | 붙여넣은 뒤 클립보드를 비웠습니다. Windows 클립보드 기록(Win+V)을 쓴다면 그 항목도 지우세요. |
| T-PASTE-EDGE-SPACE | W01–W04·W06 | 앞/뒤 공백이 포함되어 있습니다. 공백도 그대로 비밀번호·passphrase의 일부가 됩니다. |
| T-MASKED | W05·W07–W10 | 창이 비활성화되어 내용을 가렸습니다. 창을 클릭하면 다시 표시합니다. |
| T-CAPTURE-WARN | W01–W07·W10 | 화면 캡처 제외가 적용되지 않았습니다. 화면 공유·녹화 중이면 입력하지 마세요. |
| T-LOCALHOST-ON | S15 | 개발용 설정입니다. 켜면 http://localhost 와 http://127.0.0.1 페이지가 지갑 연결을 요청할 수 있습니다. |
| T-SEND-INFLIGHT | S11 | 이 계정의 이전 거래가 아직 확정되지 않았습니다. 확정된 뒤 보낼 수 있습니다. |
| T-EVM-SENT | S11 EVM 결과 | 전송했습니다. 블록에 포함되면(확인 1) 활동에 '확정'으로 표시됩니다. |
| T-SOL-SEND-NOW | S11 Solana 결과·보내기 화면(`Pending`일 때, 버튼 `지금 다시 전송` 아래) | 서명한 같은 거래를 바로 다시 보냅니다. 서명이 같아 한 번만 처리됩니다. 블록해시가 만료된 것이 RPC로 확인되면 새로 서명해 다시 보낼 수 있습니다. |
| T-APPR-EXPIRED | S11(가속·취소·수수료 올리기는 S10) | 승인 시간이 지났습니다. 다시 검토하세요. |
| T-LOG-FOLDER | S15 | 로그에는 비밀번호·니모닉·개인키·API 키·RPC 엔드포인트 URL이 없습니다. 주소와 거래 해시는 있을 수 있습니다. |
| T-RPC-OK | S15 | 엔드포인트가 작동합니다. ({네트워크 이름}, {확인 항목}) — 확인 항목 예: `chainId 1`, `genesis 일치`, `chain main` |
| T-RPC-GENERATE | S15 | 선택한 템플릿으로 아래 네트워크의 RPC URL을 만듭니다. 이미 URL이 있는 네트워크는 '기존 URL 덮어쓰기'를 켰을 때만 바꿉니다. |
| T-RPC-GENERATED | S15 | RPC URL {n}개를 만들었습니다. 템플릿 항목이 없는 네트워크 {m}개는 직접 입력하세요: {네트워크 이름 목록} |
| T-CUSTOM-CHAIN | S10·S15·A01 헤더 배지 | 사용자 추가 체인 (chainId {n}) |
| T-GENESIS-PINNED | S10 | {체인 이름}의 제네시스 해시를 첫 연결에서 고정했습니다: {해시} |
| T-CHAIN-PIN | S17 | 이 체인의 제네시스 해시를 지금 받은 값으로 고정합니다. 이후 연결할 때마다 chainId와 이 값을 비교하고, 다르면 이 체인을 쓰지 않습니다. 해시가 공식 자료(체인 문서·탐색기)의 값과 같은지 확인하세요. |
| T-CHAIN-REPIN | S15 | 고정된 제네시스 해시와 RPC가 알려준 값이 다릅니다. RPC가 다른 체인을 가리키거나 체인이 새로 시작되었을 수 있습니다. 새 값을 공식 자료로 확인한 경우에만 다시 고정하세요. |
| T-CHAIN-REPIN-ACK | S15 (체크박스) | 새 제네시스 해시를 공식 자료로 확인했습니다 |
| T-CHAIN-DELETE | S15 | 체인 정의, RPC URL, 수수료 상한을 지웁니다. 이 체인의 토큰·활동 기록은 남고, 같은 chainId를 다시 추가하면 다시 보입니다. |
| T-BTC-ESPLORA-NOTE | S15 Bitcoin | 인덱서(Esplora 서버)는 조회하는 주소와 이 PC의 IP를 봅니다. 기본값은 mempool.space이며 자체 Esplora 서버로 바꿀 수 있습니다. Esplora URL은 평문으로 저장되므로 토큰·API 키가 들어 있는 URL은 넣지 마세요. |
| T-BTC-BB-OPTIN | S15 Bitcoin(오버레이) | Blockbook 인덱서는 Bitcoin RPC 엔드포인트에 인덱서 기능이 켜져 있어야 합니다(QuickNode: 유료 BTC Blockbook 애드온, 알케미: UTXO API). 켜져 있지 않으면 Bitcoin 조회가 실패합니다(E-BTC-007). 계속할까요? |
| T-BTC-IDX-OK | S15 Bitcoin | Esplora 서버가 작동합니다. ({네트워크 이름}, genesis 일치) |
| W-BTC-IDX-LAG | S10 Bitcoin 배너 | 인덱서와 노드의 블록 높이가 {n} 차이 납니다. 잔액·확인 수가 늦게 반영될 수 있습니다. ([08] §2 4단계, 차단 아님) |
| T-BTC-ESPLORA-BROADCAST | S10 활동(오버레이) | Bitcoin 노드(RPC)로 보낸 결과를 확인하지 못했습니다. 같은 서명 거래를 설정한 Esplora 서버로 보냅니다. 거래 내용은 어차피 네트워크에 공개되지만, 그 서버는 이 PC의 IP가 이 거래를 보냈다는 것을 알 수 있습니다. 보낼까요? ([08] §11.3) |
| T-SIM-RUNNING | A01 | 시뮬레이션 중… ({n}/10초) |
| T-SIM-NODIFF | A01 | 시뮬레이션 결과가 없어 자산 변화를 표시할 수 없습니다. |
| T-SIM-PARTIAL | A01 | 시뮬레이션에서 확인된 부분만 표시합니다. |
| T-SIM-CHANGED | A01 | 시뮬레이션 결과가 바뀌었습니다. 다시 확인하세요 |
| T-SIM-RESIM-FAILED | A01 | 다시 실행한 시뮬레이션이 성공하지 못했습니다. 경고를 확인하고 다시 승인하세요. |

시뮬레이션 상태 띠 문구는 §7 E-SIM-001–004가 정본이다(§3.2.1).

가져온 개인키(§2.18) 문구:

| ID | 위치 | 문구 |
|---|---|---|
| T-KEYSTART-CARD | S01 | MetaMask·Phantom·Electrum 등에서 내보낸 개인키 하나로 지갑을 만듭니다. 복구 단어(24단어)는 만들지 않습니다. |
| T-KEYSTART-BACKUP | S18·S19·S08 | 복구 단어 없이 개인키로 지갑을 만듭니다. 이 지갑의 백업은 지금 입력할 원래 개인키뿐입니다. 이 PC나 지갑 파일을 잃으면 원래 개인키로만 되살릴 수 있으니, 원래 개인키를 종이 등 안전한 곳에 따로 보관하세요. |
| T-KEYSTART-OK | S08(개인키로 시작 뒤) | 개인키로 지갑을 만들었습니다. 이제 지갑을 쓸 수 있습니다. |
| T-KEYSTART-SCRIPT | S18·Bitcoin 탭 | 이전 지갑에서 이 키로 쓰던 주소와 같은 형식을 고르세요. 다음 화면에서 주소를 보고 확인합니다. 5·9로 시작하는 압축되지 않은 WIF는 P2PKH(레거시)만 쓸 수 있습니다. |
| T-KEY-ONLY | W07(복구 단어 없는 지갑) | 주의: 이 지갑에는 복구 단어가 없습니다. 이 계정의 백업은 지금 입력하는 원래 개인키뿐입니다. 이 PC나 지갑 파일을 잃으면 원래 개인키로만 되살릴 수 있으니, 원래 개인키를 종이 등 안전한 곳에 따로 보관하세요. |
| T-SOL-KEY-INPUT | W07(Solana) | Phantom·Solflare의 '개인키 내보내기'로 받은 base58 문자열(64바이트 keypair) 또는 solana-keygen JSON 파일의 내용([숫자 64개])을 붙여넣으세요. 주소(32바이트)는 개인키가 아닙니다. |
| T-BTC-KEY-INPUT | W07(Bitcoin) | WIF 형식 개인키(5·K·L로 시작하면 mainnet, 9·c로 시작하면 testnet4)를 붙여넣으세요. 주소 형식은 앞 화면에서 고른 것으로 만듭니다. |
| T-ACCOUNTS-KEY-ONLY | S10 `내 계정`(키 전용 지갑) | 보내기·받기에 쓸 계정을 고르세요. 이 지갑은 개인키로 시작해 복구 단어가 없습니다. 모든 계정은 '가져온 키'이며 각각의 원래 개인키가 유일한 백업입니다. |
| T-NO-ACCOUNTS | S10(키 전용 지갑, 계정 없는 체인) | 이 지갑에는 {체인} 계정이 없습니다. |
| T-REMOVE-IMPORTED | S10 Solana·Bitcoin 가져온 키 삭제 확인 | 선택한 가져온 개인키 계정을 이 지갑에서 지웁니다. 가져온 개인키는 복구 단어로 복구되지 않으므로, 지우고 나면 원래 개인키 없이는 이 계정의 자산에 다시 접근할 수 없습니다. 지우기 전에 이 계정의 '개인키 보기'로 개인키를 내보내 안전하게 보관했는지 확인하세요. 계속하려면 비밀번호를 입력하세요. |
| T-BTC-IMPORTED | Bitcoin 탭 계정 카드(`개인키 가져오기` 위) | 가져온 개인키는 Bitcoin 계정 목록에 "[가져온 키]"로 보입니다. 주소 하나만 쓰고(잔돈도 같은 주소로 돌아옴) 복구 단어로 복구되지 않습니다. 잔액·받기·보내기는 다른 계정과 같습니다. |
| T-BTC-MODE-HELP | Bitcoin 탭 계정 카드(주소 방식 라디오 아래) | 고정 주소는 받기·잔돈이 늘 같은 주소(…/0/0)라 관리와 소유 증명이 쉽지만, 누구나 그 주소의 잔액과 거래를 모두 볼 수 있습니다. 새 주소 방식은 프라이버시가 낫지만 주소가 계속 바뀝니다. |
| T-BTC-FIXED-RECEIVE | S12 Bitcoin(고정 주소 모드, 정보 띠) | 이 계정은 주소 하나만 씁니다. 같은 복구 단어를 Electrum/Sparrow/UniSat에 넣으면 같은 주소가 나옵니다. |
| T-BTC-SOURCE-STANDARD-HELP | Bitcoin `계정 추가`(키 출처 `BTC 표준 경로` 아래) | m/{44·49·84·86}'/{코인}'/{계정}'/0/0 — 같은 복구 단어를 다른 Bitcoin 지갑에 넣어도 같은 주소가 나옵니다. |
| T-BTC-EVM-SHARED | Bitcoin `계정 추가`(키 출처 `EVM 계정과 같은 키`, 주의 띠)·확인 오버레이·EVM 키 계정의 받기·계정 카드 | 같은 키를 쓰면 EVM 주소와 BTC 주소의 공개키가 같아져, 누구나 두 주소가 같은 사람 것임을 알 수 있습니다. 다른 BTC 지갑(Electrum·Sparrow)에 복구 단어만 넣으면 이 주소가 보이지 않습니다(복구는 이 지갑이나 개인키 내보내기로). |

YubiKey(§2.19, [10]) 문구 — 정본은 `app_yubikey`·`ui::screens_yubikey`·`ui::secret`의 상수:

| ID | 위치 | 문구(요지) |
|---|---|---|
| T-YK-WALLET | S01 카드 "YubiKey에 키 보관" | 새 복구 단어 24개를 만들어 종이에 적고, 그 단어에서 만든 키를 YubiKey에 넣습니다. 이 PC에는 복구 단어를 저장하지 않고 공개키·주소만 둡니다. 서명은 YubiKey에서 PIN과 터치로 합니다. |
| T-YK-SAME | S21 확인(고위험 띠) | [10] §7.1-2의 사용자 결정 문구("이 복구 단어는 이 PC의 vault에도 저장되어 있습니다…'YubiKey 지갑'…을 새로 만드세요.") |
| T-YK-SHARED | S21 키·슬롯(공유 키, 주의 띠) | [10] §3.2의 두 문장(신원 연결, 표준 지갑이 찾지 못함·복구 방법) |
| T-YK-OVERWRITE | S21 확인·자격 정보 | 가져오기를 하면 이 YubiKey의 고른 슬롯(OpenPGP SIG/AUT, PIV 82…)에 있던 키는 지워지고 바뀝니다. 다른 용도(GPG 등)로 쓰던 슬롯이면 고르지 마세요. |
| T-YK-PARTIAL | S21 결과(카드 쓰기 중 실패) | 일부 슬롯에 키가 이미 들어갔을 수 있습니다. 다시 시도하면 덮어씁니다. 지갑에는 아무것도 기록하지 않았습니다. |
| T-YK-PIV-FIRMWARE | S21 키·슬롯·확인(PIV) | Solana(PIV Ed25519) 키 가져오기는 펌웨어 5.7.4 이상에서 문서화되어 있습니다. 5.7.0–5.7.3은 거부할 수 있고, 5.7.0 미만은 PIV 슬롯을 쓸 수 없습니다. |
| T-YK-IMPORT / T-YK-ADOPT | S21 자격 정보("어떻게 등록할까요?") | `복구 단어에서 키를 넣기 (처음 등록)`: 복구 단어에서 고른 키를 YubiKey에 씁니다. 그 슬롯에 있던 키는 덮어씁니다. / `이미 넣은 키 연결하기 (가져오기 없이 등록)`: YubiKey에 이미 같은 복구 단어의 키가 들어 있을 때 씁니다. 카드에는 아무것도 쓰지 않고, 카드의 공개키가 복구 단어와 맞는지만 확인해 지갑에 연결합니다(재설치·새 PC·지갑 초기화 후). |
| T-YK-PIN-GUIDE | "기본값 변경 / PIN 설정"(S21 결과, 설정 → YubiKey) | 다섯 줄: OpenPGP PIN — EVM·Bitcoin 서명할 때마다 입력 (기본 123456, 6자 이상) / OpenPGP 관리자 PIN — 키를 넣을 때, OpenPGP PIN이 잠겼을 때 (기본 12345678, 8자 이상) / PIV PIN — Solana 서명할 때 (기본 123456, 6–8자) / PIV PUK — PIV PIN이 잠겼을 때 풀기 (기본 12345678, 6–8자) / PIV 관리 키 — 앱이 자동으로 만들어 PIN으로 잠가 보관 (입력할 필요 없음) |
| T-YK-PIN-LOCKS / T-YK-PIN-EASY | 같은 카드 | 각각 3번 틀리면 따로 잠깁니다. 하나가 잠겨도 다른 쪽(OpenPGP/PIV)은 그대로이고, FIDO2·패스키 로그인은 이 중 어느 것과도 관계없습니다. / 편하게 쓰려면: 8자리 하나로 통일하세요 (네 개 모두 같은 값). 기본값 그대로 두면 YubiKey를 가진 사람이 서명할 수 있습니다. |
| T-YK-PIN-TRADEOFF / T-YK-PROTECT-MGMT | 같은 카드("통일" / "따로") | 순서(PIV PIN → PUK → 관리 키 → OpenPGP 관리자 PIN → OpenPGP PIN)와 같은 값의 대가(시도 횟수가 늘고 서명 PIN이 관리자 권한도 줌; 개인용으로는 괜찮음) / PIV 관리 키 자동 보호: 새 관리 키를 이 PC에서 무작위로 만들어 PIN으로 잠가 둡니다(ykman `--generate --protect`와 같음). 현재 PIV PIN만 묻습니다. |
| T-YK-LIST | 설정 → YubiKey | YubiKey 계정은 복구 단어에서 만든 키를 YubiKey에 넣어 두고 … 같은 키를 여러 YubiKey에 넣어 서로의 백업으로 쓸 수 있습니다(최대 8개). |
| T-YK-MNEMONIC-WALLET | 설정 → YubiKey(니모닉 지갑) | 이 지갑의 복구 단어로 등록하면 그 단어가 이 PC에도 있으므로 보안 이득이 없습니다 … 'YubiKey 지갑'을 새로 만드세요. |
| T-CARD-ADMIN-PIN / T-CARD-MANAGEMENT-KEY | W12 | 관리자 PIN(8–127자, 기본 12345678) / 관리 키 16진수 48자리 — 이번 작업에만 쓰고 바로 지웁니다. |
| T-CARD-PIV-PIN / T-CARD-SET-PINS | W12 | PIV PIN(6–8자, 기본 123456) — PIN으로 보호된 관리 키를 꺼내는 데 한 번만 쓰고 지웁니다. / 새 8자 PIN 하나를 OpenPGP PIN·관리자 PIN·PIV PIN·PUK에 똑같이 넣고 관리 키는 자동으로 PIN 보호합니다. 현재 값이 공장 기본값이면 비워 두기, 전에 통일했다면 그 8자. 중간에 실패하면 멈추고 바뀐 것만 알립니다. |

### 2.17 EVM 체인 추가·편집·삭제 (S17, D14)
기본 체인(1·11155111·999·42161·8453·56·4663)은 [03] §1.1 상수이며 편집·삭제할 수 없다(RPC URL §2.11.1, 수수료 상한, HyperEVM `다시 고정`만). 사용자 체인은 최대 `MAX_CUSTOM_EVM_CHAINS = 32`개이고, 비밀이 아닌 정의(템플릿 식별자 포함)는 `settings.json` `evmChains`(§6.1), RPC URL은 토큰이 들어 있으므로(D13) `apikeys.dpapi` `rpc:eip155:<chainId>`(§6.3)에 둔다. 런타임은 이 URL만 쓴다(§1.9). S15 `EVM 체인`에서 연다. 추가·편집은 S15를 열 수 있으면 언제나(이미 32개면 `추가` → E-CHN-006), 삭제는 `Unlocked`에서만(§2.17.3). dApp은 체인을 추가할 수 없다(`wallet_addEthereumChain` 거부, D14, [05]).

#### 2.17.1 입력
| 필드 | 입력 | 검증 |
|---|---|---|
| chainId | EDIT 10진 정수. 편집 때는 고정(바꾸려면 삭제 후 추가) | 숫자만·앞자리 0 없음, 1 ≤ n ≤ 9,223,372,036,854,775,771(EIP-2294) → E-CHN-004. 기본 체인·기존 사용자 체인과 같으면 E-CHN-003 |
| 이름 | EDIT | §2.10 이름 규칙(E-INP-017). 기본 체인·다른 사용자 체인 이름과 같으면(ASCII 대소문자 무시) E-CHN-005 |
| 네이티브 심볼 | EDIT | `^[A-Za-z0-9]{1,11}$`(S16 기호 규칙과 같음) → E-CHN-004 |
| 소수 자릿수 | EDIT, 기본 18 | 0–36([02] `TokenEntry.decimals`와 같은 범위) → E-CHN-004 |
| RPC | EDIT 1칸(`ES_PASSWORD`). `https://`로 시작하면 URL. 아니면 선택한 템플릿(`rpc.template`, §6.1)의 네트워크 식별자: `QuickNode 멀티체인`이면 서브도메인(예 `base-sepolia`), `알케미`면 라벨(예 `base-sepolia`). 안내 문구에 현재 템플릿과 자격 정보 저장 여부를 보인다 | URL: `HttpsUrl::parse`(E-KEY-003). 식별자: 소문자로 바꾸고 (알케미면 끝의 `.g.alchemy.com`을 뗀 뒤) `^[a-z0-9]+(-[a-z0-9]+)*$` 1–63자 → E-CHN-004. 템플릿이 `직접 입력`이면 URL만 받는다(E-KEY-003). 그 템플릿 자격 정보(§6.3 `tpl:quicknode`·`tpl:alchemy`)가 없으면 E-KEY-004. URL = §2.11.1 `template_url`(식별자 → `rpc:eip155:<chainId>`에 들어갈 URL). 편집 때 비우면 그대로 |
| 탐색기 URL(선택) | EDIT | `HttpsUrl::parse` 통과, ≤ 256바이트, `?`·`#` 없음, 끝 `/`는 뗀다 → E-CHN-004 |
| 시뮬레이션 | 라디오 `auto`(기본: 항상 `eth_simulateV1` 시도) / `unsupported`(호출하지 않고 E-SIM-003 띠, D15) | — |

#### 2.17.2 저장 (추가, RPC 변경)
1. §2.17.1 검사. RPC를 바꾸지 않는 편집(이름·심볼·소수 자릿수·탐색기·시뮬레이션)은 RPC 호출 없이 4로 간다.
2. `저장` → "체인을 확인하는 중…". RPC 작업자가 입력한 URL 또는 템플릿으로 만든 URL(§2.11.1)로 `eth_chainId` → `eth_getBlockByNumber(["0x0", false])`(호출당 10 s, 재시도 없음, 사용자가 다시 `저장`). §2.11.1의 `교체`·`네트워크 URL 생성`도 사용자 체인 URL을 쓰기 전에 이 단계를 거친다(편집과 같은 판정: chainId 일치 + 블록 0 해시 == 고정값).
   - 전송·HTTP·JSON-RPC 오류 → E-CHN-002 + 원인 코드(§1.9 분류, 예 "(E-CHN-002, E-RPC-002)"). `eth_chainId`가 정규 quantity가 아니거나 블록 0 `hash`가 32바이트 hex가 아님 → E-CHN-002 + E-RPC-005.
   - chainId ≠ 입력 → E-CHN-001(RPC 값을 10진 정수로 보인다; 파싱한 값이므로 원격 문자열 표시 금지(§7)에 걸리지 않는다).
   - 편집이면 블록 0 해시 ≠ 고정값 → E-CHN-008, 저장하지 않는다(다른 체인을 가리키는 URL).
   - 추가면 이어서 `eth_feeHistory(["0x1","latest",[50]])`에 `baseFeePerGas`가 없을 때 E-CHN-010([03] §1.6-4, EIP-1559 없음), 저장하지 않는다.
3. 추가면 확인 오버레이 T-CHAIN-PIN: chainId, 이름, RPC(템플릿이면 "QuickNode 서브도메인 {식별자}"·"알케미 라벨 {식별자}", URL이면 §2.11.1 가린 형태), 받은 제네시스 해시 전체(`Consolas`). `고정하고 저장` / `취소`(최초 신뢰, D14).
4. 쓰기: RPC를 넣었으면(URL·식별자 모두) `apikeys.dpapi` `rpc:eip155:<chainId>`에 그 URL을 먼저 쓰고 `settings.json` `evmChains`를 쓴다. 식별자를 넣었으면 그 템플릿 키(`quicknodeSubdomain` 또는 `alchemyLabel`)를 함께 바꾸고, URL을 넣었으면 템플릿 키는 그대로 둔다(나중에 `네트워크 URL 생성`의 `기존 URL 덮어쓰기`에서만 쓰인다). 뒤쪽 쓰기가 실패하면 E-APP-002이고, 추가였으면 남은 URL은 고아 항목으로 다음 읽기에서 무시된다(§6.3). 편집이었으면 URL은 2단계 확인을 통과한 새 값으로 바뀐 채이고 템플릿 키만 이전 값이다. 성공 → 새 `RpcConfig`(§1.9), 그 체인 확인 상태 초기화, "저장했습니다". `feeCaps`는 사용자가 바꿀 때만 쓴다(없으면 기본값, §6.1).

#### 2.17.3 삭제
- `Unlocked`에서만(미종결 저널 확인에 DEK 필요, D10). 거부: 활성 체인(`evmChainId`) → E-CHN-009. 그 체인(`eip155:<chainId>`)에 미종결 저널 레코드([03] §5)나 송신 슬롯·승인 큐 항목([03] §3.6, §3.7)이 있으면 → E-CHN-007.
- 확인 오버레이 T-CHAIN-DELETE → `settings.json`(`evmChains` 항목과 `feeCaps["eip155:<chainId>"]` 제거) → `apikeys.dpapi`(`rpc:eip155:<chainId>` 제거). meta의 그 `NetworkId` `tokens`·`activity`는 지우지 않는다. 그 체인을 가리키는 사이트 연결·origin 체인 캐시 처리는 [05] §4.3.

#### 2.17.4 다시 고정 (E-CHN-008)
- 대상: 최초 신뢰로 고정한 체인(HyperEVM `evmGenesisPins`, 사용자 체인 `genesisHash`)이 E-CHN-008일 때. 상수 제네시스 체인(1·11155111·42161·8453·56·4663)에는 없다.
- `다시 고정` → `eth_chainId`(≠ chainId면 E-RPC-006, 다시 고정 불가)와 블록 0 해시를 새로 받는다(오류는 §2.17.2-2와 같음) → 오버레이 T-CHAIN-REPIN: 고정된 해시와 새 해시 전체를 위아래로(`Consolas`). 체크박스 T-CHAIN-REPIN-ACK를 켜야 `다시 고정`이 켜진다 → `settings.json` 쓰기 → 새 `RpcConfig`, 체인 확인 상태 초기화.

### 2.18 개인키로 시작하기·개인키 가져오기 (S18, S19, D9)
형식·vault 규칙은 [02] §8.4–§8.5, Solana 서명은 [07] §3.4. 단계 표시 `1 비밀번호 정하기 · 2 개인키 입력 · 3 주소 확인`(S18 시작 전, W01 1/3, W07 2/3, S19 3/3; 비밀 창 머리 "개인키로 시작하기 · n/3단계").

| 단계 | 화면 | 동작·검증 |
|---|---|---|
| 1 | S18 | S01 `개인키로 시작하기`. 제목 "개인키로 시작하기", 카드 "어떤 체인의 개인키입니까?": 라디오 `EVM (이더리움 등)`(기본)·`Solana`·`Bitcoin`과 체인별 형식 도움말. Bitcoin이면 라디오 "주소 형식"(계정 추가와 같은 순서·이름, 쉬운 이름 먼저·기술 이름 끝) `네이티브 세그윗 (bc1q…, P2WPKH)`(기본)·`탭루트 (bc1p…, P2TR)`·`호환 세그윗 (3…, P2SH-P2WPKH)`·`레거시 (1…, P2PKH)` + T-KEYSTART-SCRIPT. 카드 "이 지갑의 백업": T-KEYSTART-BACKUP(주의 띠) + 도움말(계정 추가·복구 단어 보기 없음, 다른 체인 키는 나중에 가져올 수 있음, 체인마다 15개). 주 버튼 `시작하기`, `취소`(S01, 보관한 버퍼 소거). |
| 2 | W01 | 비밀번호 2회(§2.3과 같은 규칙). passphrase는 묻지 않는다. |
| 3 | W07 | 그 체인의 개인키 입력(§4.1, T-KEY-ONLY). |
| 4 | S03→S19 | `KeyJob::PreviewKeyStart`: 키 작업자가 비밀번호·키 버퍼를 보관하고 `ImportKey::parse` → `preview`로 주소만 계산한다(vault 없음). 형식 오류는 W07을 다시 열고 그 오류(E-INP-006/007/020–024)를 보인다(비밀번호는 작업자가 계속 보관). S19: 제목 "주소 확인", "입력한 개인키의 {체인} 주소입니다. 이전 지갑에서 쓰던 주소와 전체가 같은지 확인하세요.", Bitcoin이면 "주소 형식"(`탭루트 (tb1p…, P2TR)`처럼 그 네트워크의 접두)·"네트워크" 줄, 주소 전체, T-KEYSTART-BACKUP, 주 버튼 `맞습니다`, `다릅니다`(`KeyJob::DiscardKeyStart { keep_password: true }` → S18; 다시 `시작하기`는 W01 없이 W07로). |
| 5 | S03 | `KeyJob::CommitKeyStart` → `Vault::create_with_key`(`Unlocked`) → 키 전용 기본 meta([02] §5.3: `evm_accounts = []`, 그 키의 목록·선택 — Bitcoin 키는 meta `btc_accounts`의 가져온 키 계정, 그 체인 탭) → 버퍼 소거. Bitcoin 키면 설정 `bitcoin.enabled = true`, `bitcoin.network` = 그 키의 네트워크(WIF 버전 바이트)로 쓴다([08] §3.5). |
| 6 | S08 | T-KEYSTART-OK(완료 띠) + T-KEYSTART-BACKUP(주의 띠). 백업 확인 단계는 없다. 이후 §2.3 6단계와 같다. |

**개인키 가져오기(지갑이 있을 때)**: 각 체인 탭 "내 계정"의 `개인키 가져오기`(`Unlocked`이고 그 체인 가져온 키 < 15일 때만; T-ALT-PASS 세션은 끔) → W07(그 체인, 니모닉 지갑은 T-IMPORTED-KEY, 키 전용 지갑은 T-KEY-ONLY) → EVM `KeyJob::ImportPrivateKey`, Solana·Bitcoin `KeyJob::ImportKey { spec }` → `Vault::import_key` → meta 목록에 "가져온 계정 n"·"가져온 Solana n"으로 더한다. Bitcoin 키는 목록 대신 Bitcoin 계정이 된다: UI가 `KeyJob::BtcMeta { AddImported { network, key: BtcAccountKey::single(..) } }`를 보내 key worker가 meta `btc_accounts`에 저장·선택한다([08] §3.5). Bitcoin 탭의 `개인키 가져오기`는 `계정 추가`처럼 처음에는 닫혀 있다(한 줄 도움말 T-BTC-IMPORT-HINT "다른 지갑에서 쓰던 Bitcoin 개인키(WIF)도 이 목록에 더할 수 있습니다. 누르면 주소 형식을 고릅니다." + 버튼). 누르면 같은 카드에 T-BTC-IMPORTED, 주소 형식 라디오(기본 네이티브 세그윗), T-KEYSTART-SCRIPT, 주 버튼 `다음 (개인키 입력)`(→ W07)·`취소`가 열린다(열림 상태는 실행 중에만 유지). 키 전용 지갑에서 Bitcoin 키가 하나도 없을 때의 T-NO-ACCOUNTS 카드는 라디오를 처음부터 보이고 주 버튼 `개인키 가져오기`가 바로 W07을 연다. 키의 네트워크가 설정과 다르면 정보 띠로 알린다. 오류는 W07에 남는다(E-VLT-010 체인별 15개, E-VLT-011 중복 — Bitcoin은 그 주소가 이미 HD 계정의 검색 범위나 다른 가져온 키의 주소일 때도, [08] §3.5 — 형식 오류).

**계정 목록**
- EVM: 파생 계정 다음에 가져온 계정(기존). 키 전용 지갑의 EVM 탭에 EVM 키가 없으면 T-NO-ACCOUNTS 카드. 선택 계정 설정(`prefs.evm_account`)이 목록에 없는 계정을 가리키면 첫 행을 선택 계정으로 쓴다.
- Solana: 표준 계정 다음에 가져온 계정(meta `sol_raw_accounts`). 선택(`sol_raw_selected`)한 가져온 계정으로 보내기 폼을 열면 출처가 `SolKeySource::Imported`이고 SOL·허용 목록 SPL 보내기, 받기, 잔액, 저널, 만료 증명이 표준 계정과 같다([07] §3.4). 선택 행 버튼: 파생 `이름 바꾸기`·`숨기기`, 가져온 키 `이름 바꾸기`·`개인키 보기`·`삭제`(위험). 키 전용 지갑은 계정 0을 파생하지 않는다.
- Bitcoin: 가져온 키는 별도 카드 없이 "Bitcoin 계정" 목록의 행이다(§2.6 Bitcoin 탭 계정, [08] §3.5–§3.6): 배지 "[가져온 키]", 줄인 주소, 형식, 사용 가능 잔액; 고르면 그 계정의 잔액·UTXO·받기(그 주소 하나)·보내기(잔돈은 같은 주소)·활동. 선택한 가져온 계정의 버튼: `개인키 보기`(WIF)·`삭제`(위험). 키 전용 지갑은 기본 BIP84 계정·발견·`계정 추가`가 없고, 가져온 키 계정의 첫 계정이 연결 검사의 최고 블록 높이를 보관한다.

**삭제**: EVM은 기존 `삭제`(T-REMOVE-KEY → W03 → `remove_evm_raw_key`). Solana·Bitcoin은 `삭제` → T-REMOVE-IMPORTED(계정 라벨·주소) → W03 → `KeyJob::RemoveImportedKey` → `Vault::remove_imported_key`. 키 전용 지갑의 마지막 키는 `삭제`가 꺼져 있고 vault도 `LastKey`(E-VLT-013)로 거부한다. Bitcoin 키는 그 계정에 BTC 승인이 열려 있거나 그 주소의 거래가 아직 확정될 수 있으면(진행 중, `Replaced`, 포기·공개된 거부 뒤 30일 이내 — 다시 가져온 같은 키의 옛 레코드 포함, [08] §3.5·§12.1) 확인 창 전에 이유를 보이고 멈춘다("Bitcoin 승인이 진행 중이라 이 가져온 키를 지울 수 없습니다…" / "이 가져온 키의 주소로 보낸 거래가 아직 확정될 수 있습니다(진행 중, 또는 포기·거절 뒤 30일 이내)…"; key worker도 다시 확인해 `ImportedKeyBusy`면 W03에 같은 문구). 지운 뒤 key worker가 그 계정을 meta `btc_accounts`에서 지우고(`BtcMetaDone::Removed`) 선택은 기본 계정(키 전용 지갑은 첫 계정)으로 돌아간다. 끝난 거래의 활동 행은 남는다. Zcash 키(2026-11-08)는 그 계정의 ZEC 기록이 아직 확정될 수 있거나, 기록을 확인할 수 없으면 — 저널을 아직 읽지 못했거나 손상된 ZEC 기록이 있으면 — 확인 창 전에 멈추고(`ZEC_REMOVE_BUSY` / `ZEC_REMOVE_UNCHECKED`), key worker도 비밀번호 전에 같은 규칙으로 다시 확인한다(`JournalWorker::zec_imported_busy`: 읽을 수 없는 저널·손상 기록은 진행 중으로 본다, 추가한 복구 단어 지우기와 같음; 거절하면 W03에 Zcash 문구).

**브라우저**: dApp 연결은 EVM 계정만 쓴다(키 전용 지갑은 가져온 EVM 키). EVM 계정이 하나도 없으면 연결 요청은 4100 `NoEvmAccount`(이유 문구, [05] §5)로 끝나고 연결 창을 열지 않는다. 잠금·자동 잠금·잠금 해제·브라우저 다리는 키 전용 지갑에서도 같다.

### 2.19 YubiKey 등록·YubiKey 지갑 (S20, S21, [10] §7, §9.3)
형식·카드 절차·검사 규칙은 [10](10-yubikey.md). 화면 모듈 `ui::screens_yubikey`(명령 ID 13,200–13,399), 상태 `app_yubikey::YkWizard`(`CardUi::wizard`), 키 작업자 작업 `KeyJob::YubiKey(YkJob)`.

- **진입**: 설정 → `YubiKey` 탭(등록한 YubiKey 목록과 주 버튼 `YubiKey 등록`), 키 전용·YubiKey 지갑의 T-NO-ACCOUNTS 카드의 `YubiKey 등록`, S01 카드 `YubiKey 지갑 새로 만들기`(S20; 설명 "새 복구 단어 24개를 만들어 종이에만 적고, 그 키를 YubiKey에 넣습니다. 이 PC에는 복구 단어가 남지 않습니다."). `Unlocked`에서만(S20은 `NoVault`). 카드 8개면 끈다.
- **S21 단계 표시** `1 키·슬롯 고르기 · 2 확인 · 3 자격 정보 · 4 결과`.
  1. 키·슬롯: 카드 `OpenPGP 서명(SIG)`·`OpenPGP 인증(AUT)` — 라디오 "넣을 키" `없음`·`EVM 계정`·`Bitcoin 주소`·`EVM 공유 키`, "계정 인덱스"/"주소 인덱스 (0–999)" EDIT, Bitcoin·공유 키는 "주소 형식 ({현재 Bitcoin 네트워크})" `네이티브 세그윗 (P2WPKH)`(기본)·`호환 세그윗 (P2SH-P2WPKH)`·`레거시 (P2PKH)`, "터치" `항상`(기본)·`15초 유지`·`항상(고정)`·`15초 유지(고정)`, 경로 도움말(Bitcoin 인덱스 ≥ 20이면 gap limit 안내), 공유 키면 T-YK-SHARED(주의 띠)와 체크박스(켜야 다음). 카드 `PIV — Solana 계정` — "Solana 계정 수 (0–20)", "첫 계정 인덱스", 터치 `항상`·`15초 유지`, 보관 슬롯 82부터 차례로, T-YK-PIV-FIRMWARE. 기본값: 첫 YubiKey SIG = EVM 0, AUT = Bitcoin P2WPKH 0, Solana 1개(0부터); 다음 YubiKey는 기록된 카드들의 다음 인덱스. 등록한 카드가 있으면 카드 `백업 복사본` — 체크박스 "백업 YubiKey 만들기 (같은 키 복사)"와 설명 "같은 키를 다른 YubiKey에도 넣어 예비용으로 씁니다. 이미 등록한 YubiKey의 슬롯 구성을 그대로 따릅니다.", 복사할 카드 라디오(그 카드의 슬롯·경로·정책을 그대로, `backup_copy`). 주 버튼 `다음 (복구 단어 입력)`(키 작업자가 단어를 보관 중이면 `다음 (확인)`), `취소`. 입력 오류(범위·빈 계획·`validate_plan`)는 위험 띠.
  2. 복구 단어: W05(+ BIP39 passphrase 체크 시 W06 두 칸) → `YkJob::Preview` — 키 작업자가 시드를 보관하고(UI 스레드에는 남지 않음) `enrol::preview`로 경로·주소를 계산한다(카드 통신 없음). 단어 오류는 W05를 다시 열고 그 오류.
  3. 확인: 슬롯마다 "{슬롯 이름} — {역할 제목}", 경로, 주소(EVM 체크섬·Bitcoin·Solana base58, 공유 키는 둘 다), 정책(터치·PIV PIN), 관계(`새 키` / 같은 경로를 가진 YubiKey 일련번호, 백업 복사본 여부). `plan::validate_before_card` 오류는 위험 띠(`PlanError` 문구)이고 `다음`이 꺼진다. 입력한 단어(+ passphrase)가 이 vault의 것이면(EVM 계정 0 주소 비교) T-YK-SAME(고위험 띠)과 체크박스 "이해했습니다. 그래도 이 복구 단어로 등록합니다" — 켜야 `다음`. PIV가 있으면 T-YK-PIV-FIRMWARE, 언제나 T-YK-OVERWRITE. `← 슬롯 다시 고르기`(단어는 보관), `취소`.
  4. 자격 정보: 들어올 때 PIV 슬롯이 있으면 꽂힌 카드의 관리 키 상태를 읽는다(`YkJob::ProbeManagement`, 읽기만, [10] §7.3). OpenPGP 슬롯이 있으면 관리자 PIN을 W12에서. PIV: 관리 키가 PIN으로 보호되어 있으면 필드 "관리 키: PIN으로 보호됨 — PIV PIN만 입력"(가져오기 때 W12 PIV PIN), 아니면 라디오 `기본 관리 키 사용`·`관리 키 직접 입력 (16진수 48자리)`(W12; 읽은 기본값 여부로 처음 선택, 못 읽었으면 도움말). 카드 "어떻게 등록할까요?" — 주 버튼 `복구 단어에서 키를 넣기 (처음 등록)`(W12 → `YkJob::Enrol`) + T-YK-IMPORT, `이미 넣은 키 연결하기 (가져오기 없이 등록)`(쓰기 없이 공개키만 읽음, [10] §7.5) + T-YK-ADOPT, T-YK-OVERWRITE. 아래 `← 이전`, `취소`. 진행 중에는 "YubiKey에 키를 넣는 중입니다".
  5. 결과(두 등록 방식 모두): 완료 띠, 카드 일련번호·펌웨어와 다시 읽은 슬롯별 경로·주소·정책, `다시 확인`(`sign::check_key` 읽기 전용, 슬롯마다 "공개키가 기록과 같습니다 ✓" 또는 오류), 언제나 카드 **"기본값 변경 / PIN 설정 — YubiKey #n"**([10] §9.3): 남은 기본값 띠, 소제목 "PIN 안내"와 T-YK-PIN-GUIDE 다섯 줄, T-YK-PIN-LOCKS, T-YK-PIN-EASY, "방식" 라디오 `8자리 하나로 통일 (권장)`(기본)·`하나씩 따로`. 통일: `PIN 설정하기 (8자리 하나)`(W12 통일 → `YkJob::SetPins`: PIV PIN → PUK → 관리 키 자동 보호 → OpenPGP 관리자 PIN → OpenPGP PIN, 실패하면 거기서 멈추고 "바꾼 것: … 실패: …" 알림) + T-YK-PIN-TRADEOFF. 따로: `OpenPGP PIN`·`OpenPGP 관리자 PIN`·`PIV PIN`·`PIV PUK`(W12 현재·새·새 확인), `PIV 관리 키 자동 보호`(W12 PIV PIN → `YkJob::ProtectManagementKey`; 관리 키는 보이지도 묻지도 않음) + T-YK-PROTECT-MGMT. 모두 바꾸면(또는 통일이 실패 없이 끝나면) meta `hw_accounts.defaults`에서 그 일련번호를 지운다. 주 버튼 `완료`(키 작업자가 단어를 지운다; 새 YubiKey 지갑이면 2026-11-08부터 메인 대신 S08 — 다른 첫 실행 갈래처럼 RPC 카드와 Chrome 확장 링크를 보이고, 완료 띠는 "YubiKey 지갑을 만들었습니다 (YubiKey #n)." + 도움말 "이 지갑의 백업은 방금 적은 복구 단어 24개입니다…", 복구 단어 없이 연결한 경우 "YubiKey를 연결했습니다 (YubiKey #n)." + 도움말 "…카드가 그 키의 유일한 사본일 수 있습니다…"), `다른 YubiKey 등록(백업)`(1단계로, 이 카드의 백업 복사본이 선택된 채, 단어 보관 유지). 실패는 위험 띠(카드 쓰기 중이면 T-YK-PARTIAL)와 `다시 시도`(4단계로)·`← 슬롯 다시 고르기`·`취소`.
- **S20 YubiKey 지갑 만들기**: 제목, 생성 단계 표시(§2.3과 같은 세 단계, 비밀 창 머리 "YubiKey 지갑 만들기 · n/3단계"), 카드 "시작하기 전에"(네 줄)와 주의 띠, `시작하기`·`취소`. W01 → `YkJob::Generate`(키 작업자가 24단어를 만들고 비밀번호와 함께 보관, vault 없음) → W08(만들기 모양: 24단어 + EVM 계정 0 주소, 2초 길게 누르기) → W10(`YkJob::Challenge`/`ConfirmWords`: 보관한 단어로 위치 4개, [02] §8.3과 같은 상수 시간 비교, 틀리면 같은 위치로 다시 — §2.3) → S21(원점 `NewWallet`). 첫 `가져오기`가 성공하면 `Vault::create_with_hardware`로 니모닉 없는 vault를 만들고(`Unlocked`), 슬롯 표의 기본 meta(파생 계정 없음, `hw_accounts`·Bitcoin `key.yubikey` 계정, 첫 계정 선택, 첫 키의 탭)와 Bitcoin 키가 있으면 `bitcoin.enabled`·네트워크를 쓴다. 단어는 디스크에 쓰지 않고, `완료`·`취소`·유휴 폐기(§5.1)·잠금에서 지운다.
- **설정 → YubiKey**: T-YK-LIST, 니모닉 지갑이면 T-YK-MNEMONIC-WALLET, `YubiKey 등록`. 카드마다 "YubiKey #{일련번호}" 카드(펌웨어, 슬롯 수, 슬롯별 경로·주소·정책, 기본값 안내 띠, `PIN 설정 / 기본값 변경 (PIN 안내)` — 누르면 그 아래에 결과 화면과 같은 "기본값 변경 / PIN 설정" 카드가 열리고 버튼이 `PIN 설정 닫기`가 된다(`CardUi::pin_serial`), `삭제`). "계정별 YubiKey": `{역할} ({경로}) — #{일련번호} {SIG|AUT|PIV xx}, …(백업)`.
- **삭제**: `삭제` → 확인 오버레이(그 카드에만 있는 계정 목록, YubiKey 안의 키는 지우지 않음) → W03 → `YkJob::Remove` → `Vault::remove_hardware_key` → 계정 다시 맞춤(meta 다시 읽기). 복구 단어 없는 지갑의 마지막 키는 끈다(`LastKey`). 2026-11-08: 카드의 버튼 줄은 일반 작업(`PIN 설정 / 기본값 변경`, `슬롯 구성 바꾸기`) 한 줄과 도움말 "위험한 작업" 아래 위험 버튼 두 개 — `지갑에서 기록 지우기 (카드는 그대로)`(이전 `삭제`)와 `YubiKey의 키 지우기…`(이전 `YubiKey 비우기`) — 로 나눈다. 기록 지우기가 꺼져 있으면 "이 지갑의 마지막 키라 기록을 지울 수 없습니다(지갑 초기화로만 가능)." 확인 문구는 이 카드에만 있는 키가 복구 단어 없이 연결한 키(경로 모름)이면 "…카드를 'YubiKey 연결하기 (복구 단어 없이)'로 다시 연결하면 돌아옵니다 — 이 카드를 잃거나 비우면 영구히 사라집니다."(이전에는 늘 "같은 복구 단어로 다시 등록하면 돌아옵니다").
- **슬롯 구성 바꾸기·YubiKey 비우기**([10] §15): 복구 단어 없이 연결한 키(경로 모름)를 다른 카드가 갖지 않은 채 덮어쓰거나 비우면 "복구 단어로 언제든 복구" 문구 대신 위험 띠 T-YK-KEY-LOST("이 키는 복구 단어가 없습니다 — 지우면 영구히 사라지고 이 주소의 자산을 다시 쓸 수 없습니다…")와 그 주소, 확인 체크, 입력란 `영구 삭제`가 더 필요하다(2026-11-08). 슬롯 구성 바꾸기의 인덱스 칸은 "(0–899)".
- **YubiKey 연결하기 (복구 단어 없이)**(2026-11-07, [10] §7.6; 모듈 `app_yubikey::connect`·`ui::screens_yubikey::connect`, 명령 ID 13,500–13,506과 선택 라디오 13,720–13,927): 진입 — S01 카드 "YubiKey에 키 보관"의 `YubiKey 연결하기 (복구 단어 없이)`(설명 "이미 키가 들어 있는 YubiKey(새 PC, 다시 설치)를 복구 단어 없이 연결합니다. 카드의 공개키만 읽고 아무것도 쓰지 않습니다.", `NoVault`; W01 → 키 작업자가 비밀번호 보관), 설정 → `YubiKey`의 같은 버튼(아래 T-YK-CONNECT), 키 전용·YubiKey 지갑의 T-NO-ACCOUNTS 카드. S21이 연결 모드로 열리고 단계 표시는 `1 YubiKey 읽기·키 고르기 · 2 주소 확인 · 3 결과`, 제목 "YubiKey 연결하기 (복구 단어 없이)"(S01에서는 "YubiKey 지갑 만들기 — YubiKey 연결하기").
  1. 읽기·고르기: 카드 "연결한 YubiKey" — T-YK-CONNECT, "YubiKey #{일련번호} (펌웨어 x.y.z)", PIN 남은 횟수 줄(OpenPGP PIN·PIV PIN, §9.1 문구), 못 읽은 애플릿과 쓸 수 없는 키(슬롯: 이유). 찾은 키마다 카드 "{슬롯 이름}" — 라디오 "이 키는": secp256k1 `EVM 계정`·`Bitcoin 네이티브 세그윗 (P2WPKH)`·`Bitcoin 호환 세그윗 (P2SH-P2WPKH)`·`Bitcoin 레거시 (P2PKH)`·`Zcash 일반 주소`·`연결하지 않음`, Ed25519 `Solana 계정`·`연결하지 않음`; 고른 용도의 주소(4자 묶음 전체), Bitcoin·Zcash는 "네트워크: …", OpenPGP 키는 "같은 키라도 형식에 따라 주소가 다릅니다. 이전 지갑에서 쓰던 주소가 나오는 형식을 고르세요." 주 버튼 `다음`, `다시 읽기`, `취소`. 읽기 실패(카드 없음·여러 장·리더)는 위험 띠와 `다시 읽기`. 이미 등록된 카드면 위험 띠 "이 YubiKey는 이미 이 지갑에 등록되어 있습니다…".
  2. 주소 확인: 주의 띠 **T-YK-UNKNOWN-PATH** "경로를 알 수 없음 — 이 키는 카드에서 가져왔습니다. 같은 주소가 맞는지 이전에 쓰던 지갑과 비교하세요.", 카드 "저장하기 전에 확인하세요 — YubiKey #n"(슬롯마다 등록 확인 화면과 같은 줄, 경로 칸 "경로를 알 수 없음", 같은 키를 가진 등록 카드가 있으면 관계 줄), 카드 "PIN으로 소유 확인 (선택)" — W12 문구 T-CARD-USER-PIN과 결과 띠, `PIN으로 소유 확인 (선택)`(W12 `YubiKey PIN 확인 (선택)`, OpenPGP PIN 6–127 또는 PIV PIN 6–8, 남은 횟수 줄; 공장 PIN 123456은 창에서 거부). PIV PIN이 공장값이면 주의 띠. 주 버튼 `저장`, `← 다시 고르기`, `취소`. 저장 중 "YubiKey를 다시 읽고 저장하는 중입니다".
  3. 결과: 등록 결과 화면과 같다(띠 "YubiKey #n을(를) 가져오기 없이 등록했습니다…", T-YK-UNKNOWN-PATH, 슬롯·주소, `다시 확인`, "기본값 변경 / PIN 설정"). 새 지갑이면 정보 띠 "YubiKey 지갑을 만들었습니다. 복구 단어 없이 카드의 공개키로 연결했으므로…"이고 PIN 설정을 강제하지 않는다(`완료`가 켜짐). `다른 YubiKey 연결`(설정에서 연 경우 다음 카드 읽기). 실패는 위험 띠와 `다시 시도`(2단계로).
  - 계정 이름·경로: 900–999 대역 계정은 "YubiKey 카드 키 n"·"YubiKey Solana 카드 키 n", 경로 칸은 "경로를 알 수 없음 (YubiKey)"(EVM 계정 줄·Solana·Bitcoin·Zcash 키 출처 문구·승인 창 계정 줄 모두). 등록 마법사의 인덱스 칸은 "(0–899)".

### 2.20 지갑 초기화 (S22) — 2026-11-06
더 진행할 수 없을 때(비밀번호 분실, 백업 확인 전 복구 단어 분실, 열리지 않는 파일) 지갑 파일을 **지우지 않고** 옮긴 뒤 S01로 돌아간다. 모듈 `app_reset`(상태 `ResetUi`), 화면 `ui::screens_reset`(명령 ID 13,400–13,449), 파일 이동 `store::reset`, 키 작업자 작업 `KeyJob::ResetWallet { stamp, include_settings }`(제어 작업: 잠금 절차의 `Lock`에 취소되지 않는다) → `KeyOutcome::WalletReset`.

- **진입**(링크·버튼 `지갑 초기화…`): S07(잠금 해제 아래, 도움말 "비밀번호를 잊었거나 더 진행할 수 없다면…"), S09, S04(도움말 "복구 단어를 적지 못했거나 잃어버렸다면, 이 지갑에 자산을 받기 전에…"), S01 T-LEFTOVER 띠(`남은 파일을 reset- 폴더로 옮기기…`), 설정 → 보안 카드 "지갑 초기화"(위험 버튼), T-WAIT-STALLED. **잠금 해제가 필요 없다.** `Starting`·`ShuttingDown`·진행 중에는 열지 않는다.
- **S22 내용**: 제목 "지갑 초기화", 고위험 띠 T-RESET-INTRO, 잠금 해제 상태에서 추적 중인 거래(EVM·Solana·Bitcoin·Zcash 저널의 끝나지 않은 기록 — Zcash는 모든 네트워크·계정 —, 그리고 응답이 아직 없거나 결과 불명인 HyperCore 전송)가 있으면 주의 띠 T-RESET-IN-FLIGHT(막지 않는다). 카드 "무엇을 하나요": T-RESET-NOUNLOCK, T-RESET-MOVE, "옮길 곳" `<데이터 폴더>\reset-<날짜시각(UTC)>`, "옮길 파일"(지금 폴더에 있는 이름; 열 때와 체크 상자를 바꿀 때 다시 읽음), T-RESET-YUBIKEY(YubiKey가 등록된 지갑이면 정보 띠 추가), T-RESET-SETTINGS, 체크 상자 `설정과 API 키도 함께 옮기기 (앱 설정을 처음 상태로)`(기본 끔). 카드 "확인": "계속하려면 아래 칸에 '초기화'를 입력한 뒤, 빨간 버튼을 2초 동안 누르고 있으세요.", EDIT "확인 문구"(앞뒤 공백 무시, 정확히 `초기화`), 길게 누르기 영역(`Item::Hold`, 아래), `취소`(연 화면으로 돌아감).
- **길게 누르기 영역** `Item::Hold`: 자식 컨트롤이 아니라 주 창이 그리는 사각형(위험 색, 아래쪽 진행 막대). 확인 문구 전에는 꺼진 색과 "'초기화'를 입력하면 누를 수 있습니다". 주 창 `Msg::MouseDown`이 영역 안이면 `HoldGate`(W08과 같은 2초, 포인터만)를 시작하고 마우스를 잡는다(`SetCapture`). 영역을 벗어나거나 떼거나 화면이 바뀌거나 잠그면 취소. 주 타이머(250 ms)가 진행을 그리고 2초가 차면 실행한다.
- **실행**: 로그 `reset.start`(설정 이동 여부, 진행 중 거래 여부) → 잠금 절차 그대로(§5.3: 비밀 창·승인 창을 닫고 대기 중 dApp 항목을 끝내고 버퍼를 지우고 대기 키 작업을 취소, `Lock`·`Load` 대기열) → WalletConnect 작업 스레드를 멈추고 UI 상태를 비움(옛 지갑의 세션·릴레이 키가 새 지갑으로 넘어가지 않게, [13] §8) → S03 "지갑 파일을 옮기는 중…" → `ResetWallet`. 키 작업자는 vault를 잠그고 버리고(잠금 해제 없이) `store::reset::move_wallet_files`를 부른다. vault·meta·journal 쓰기는 모두 이 스레드에서만 일어나므로 옮기는 동안·뒤에 그 파일을 쓰는 일이 없다. 초기화가 도는 동안 도착한 `Loaded`는 사실(`leftover`)만 받고 화면을 바꾸지 않는다.
- **옮기는 파일**(`store::reset`): 데이터 폴더 바로 아래의 파일 중 `vault.ywv`·`meta.ywm`·`journal.ywj`이거나 그 이름 + `.`으로 시작하는 것(`.prev`, `.tmp`, `.prev.tmp`, `.corrupt-<t>`). 체크 상자를 켜면 `settings.json`·`apikeys.dpapi`(+`.tmp`)도. 폴더(`logs`, 이전 `reset-*`)와 그 밖의 파일은 그대로. 순서는 `vault.ywv` 먼저(중간에 실패해도 열리는 지갑이 남지 않고, 남은 sidecar는 S01 T-LEFTOVER로 보인다), 나머지는 이름순. 옮길 것이 없으면 폴더를 만들지 않는다.
- **새 폴더**: `<데이터 폴더>\reset-<YYYYMMDDTHHMMSSZ>`(UTC; 이미 있으면 `-2`…`-9`). 데이터 폴더 안에 만들어 데이터 폴더의 보호된 DACL(현재 사용자·SYSTEM·Administrators, §1.4-3)을 물려받는다. 데이터 폴더나 새 폴더가 재분석 지점이면 거부. 파일은 `MoveFileExW(WRITE_THROUGH)`(덮어쓰지 않음)로 옮기고 두 폴더를 flush. 끝으로 `README-reset.txt`(옮긴 파일 목록과 되돌리는 방법; 쓰지 못해도 이동은 유효). 다음 시작의 `ensure_private_dir(v3)`는 이 폴더를 항목으로 검사한다(§1.4-3).
- **끝**: 성공 → `reset.done`(파일 수). 설정을 옮겼으면 메모리의 설정·API 키를 기본값으로. 이전 지갑의 파일 사실(`payload_damaged`·`.prev`·격리 이름·설정 스냅샷 검사·세대 경고)을 지우고 정보 띠 T-RESET-DONE("지갑을 초기화했습니다. 지갑 파일 {n}개를 지우지 않고 {폴더} 폴더로 옮겼습니다…"; 진행 중 거래가 있었으면 "보내던 거래는 블록체인에서 계속 처리됩니다…" 추가) → `KeyJob::Load` → `NoVault` → S01(T-LEFTOVER 없음: 남은 파일 검사는 데이터 폴더 자체만 본다). 실패 → 오류 띠(폴더를 못 만들었으면 아무것도 옮기지 않았다는 문장, 중간 실패면 옮기지 못한 파일 이름과 이미 옮긴 수·폴더) → `Load`로 지금 파일 상태를 다시 읽는다.
- 되돌리는 방법은 [docs/recovery-guide.ko.md](../docs/recovery-guide.ko.md) "지갑 초기화와 되돌리기". YubiKey 안의 키는 건드리지 않는다([10] §7.5).
- 시험: `store::reset` 단위 시험(옮기는 이름, 설정 유지·이동, 이름 충돌 `-2`, 빈 폴더, T-LEFTOVER 없음), `app::tests::wallet_reset_from_the_lock_screen_returns_to_first_run`(S07에서 비밀번호 없이, 문구 전에는 꺼짐, 절반 누르기는 무효, S01·파일 위치·설정 유지).

### 2.21 Chrome 확장 설치 (S23) — 2026-11-06
확장을 로드하는 방법과 폴더를 앱 안에서 보인다. 모듈 `app_extension`, 화면 `ui::screens_reset`.

- **진입**: 설정 → 브라우저·정보 → 카드 "브라우저 확장"(연결 상태 한 줄 + `Chrome 확장 설치 방법·폴더`), 확장이 아직 연결되지 않았으면(상태 `Never`·`Unknown`) S08 아래와 S13 "연결된 사이트가 없습니다" 카드의 링크 `브라우저에서 쓰려면: Chrome 확장 설치 방법`. `← 돌아가기`는 연 화면으로.
- **연결 상태**(싸게 알 수 있는 것만): 파이프 연결이 지금 있으면 "확장이 지금 이 앱에 연결되어 있습니다.", 잠금 해제 상태에서 EVM·Solana·Bitcoin 연결 사이트가 있으면 "확장이 연결된 적 있음 (연결된 사이트가 있습니다).", 없으면 "아직 연결되지 않음 — …", 잠겨 있으면 "지금은 연결되어 있지 않습니다. 연결 기록(연결된 사이트)은 잠금을 해제하면 보입니다."
- **설치 방법**: 1. Chrome 주소창에 chrome://extensions 입력 2. 오른쪽 위 '개발자 모드' 켜기 3. '압축해제된 확장 프로그램을 로드합니다' → 아래 폴더 선택 4. 퍼즐 아이콘에서 고정 5. (2026-11-08) 툴바의 Your Wallet 아이콘에서 '연결됨'이 보이면 끝(위 연결 상태도 바뀜). 도움말 T-EXT-COMPAT(지갑 목록에 Your Wallet이 없는 dApp이면 확장 아이콘 → 'MetaMask처럼 보이기'·'Phantom처럼'·'UniSat'·'Xverse처럼' → 탭 새로고침, 실제 같은 종류 확장은 끔; 줄인 글 T-EXT-COMPAT-SHORT는 S13 빈 카드와 설정 → 브라우저 확장 카드에도), 앱을 업데이트한 뒤에는 확장 카드의 '새로고침'.
- **확장 폴더**: 설치 사본 `<yw-app.exe가 있는 폴더>\extension`(install.ps1). 디버그 빌드는 그것이 없을 때만 저장소의 `extension\`(`CARGO_MANIFEST_DIR\..\..`). 후보는 재분석 지점이 아닌 폴더이고 이름이 `extension`이며 안에 재분석 지점이 아닌 일반 파일 `manifest.json`이 있어야 한다. 없으면 주의 띠 T-EXT-MISSING과 "있어야 할 곳".
- **버튼**: `폴더 열기`(§2.14 `explorer.exe`, 인자는 위에서 확인한 경로뿐 — 다른 곳의 문자열을 넘기지 않는다), `경로 복사`(일반 클립보드, 비밀 아님), `chrome://extensions 주소 복사`(Chrome은 다른 프로그램이 `chrome://` 주소를 여는 것을 막으므로 복사 뒤 "Chrome 주소창에 붙여넣으세요"). 폴더가 없으면 앞의 둘은 끈다.
- 시험: `app_extension::tests::installed_folder_first_then_the_repository`(설치 폴더 우선, 저장소 대체, release에는 대체 없음, 이름·manifest 검사).

### 2.22 기다림 시간 제한 (T-WAIT-STALLED) — 2026-11-06
S03(`Processing`)과 요청한 meta(`KeyJob::LoadMeta`, `App::request_meta`)는 시각을 잰다(`app_reset::WaitWatch`). 30초(`WAIT_TIMEOUT_MS`)가 지나도 끝나지 않으면 화면은 계속 기다리되(늦게 온 결과는 그대로 반영) S03 카드 아래와 S12의 "계정을 불러오는 중…" 자리에 오류 띠 T-WAIT-STALLED와 `다시 불러오기`(세션이 열려 있을 때 meta 다시 요청), `잠금`, `로그 폴더 열기`, `지갑 초기화…`를 보이고 `wait.timeout`을 로그에 남긴다. 세션이 열린 화면(S10·S04·S12)이 계정 목록을 쓰는데 meta가 없고 요청도 없으면 주 타이머가 요청한다(`wait.meta_requested`). 잠그면 시계를 지운다.

**meta 읽기 실패(T-META-FAILED, 2026-11-08):** `KeyJob::LoadMeta`가 `SidecarCorrupt`·`SidecarVaultMismatch`(E-VLT-006 오버레이) 말고 다른 오류로 끝나면(읽기, 또는 잠금 해제 때의 맞춤 쓰기 실패 — 디스크 가득 등) 기본 meta를 대신 쓰지 않는다: 그 meta를 저장하면 봉인된 진짜 meta(주소록·사이트·이름·보안 스냅샷)를 덮기 때문이다. 메모리에는 meta가 없고(`WaitWatch::meta_failed`), `save_meta`는 아무것도 쓰지 않으며(`meta.save_skipped`), 주 타이머는 다시 요청하지 않는다. 오류 띠(코드)와 함께 세션의 모든 화면 위에 T-META-FAILED와 `다시 불러오기`·`잠금`(S10은 도구 막대의 것)·`로그 폴더 열기`를 보이고, 계정 자리는 "계정 목록을 불러오지 못했습니다. 위 안내를 보세요.". 다음 `request_meta`가 이 상태를 지우고, 읽기가 성공해야 meta가 다시 생긴다. 화면은 S10(백업 확인 전이면 S04).

### 2.23 HyperCore 전송 (S-HC) — 2026-11-06

[11] §5의 폼 하나(`Screen::HyperCore`): 제목 `보내기 (HyperCore)`·`현물↔선물 USDC 이동`·`Arbitrum으로 USDC 출금`·`HyperEVM으로 이동` + 네트워크 이름, 테스트넷 띠, 카드 "서명 계정", 카드 "내용"(작업별: 자산 라디오 `USDC — 선물(perp) 잔액`/현물 토큰, 받는 주소 편집과 §2.15 주소 문구·`주소 전체를 직접 확인했습니다`, 방향 라디오, 출금 수수료 안내 띠, HyperEVM 연결 토큰 라디오와 시스템 주소), `금액`, 검증 오류 띠, `검토`(500 ms 디바운스 뒤, 오류 없음·주소 오염이면 체크·진행 중 서명 없음)·`취소`. `검토` → A01 `HyperCore 전송`(§3, [11] §6). 승인 → 서명(vault 또는 YubiKey PIN·터치) → `POST /exchange` → S10 카드 활동에 상태. `HyperEVM에서 Core로 이동`은 이 폼이 아니라 HyperEVM 체인의 S11(받는 주소 `0x2222…2222`, HYPE)을 연다. S11은 HyperEVM(999·998)에서 시스템 주소로 보낼 때 자산·주소 짝을 검사해 맞지 않으면 차단 띠를 보이고 `검토`를 끈다([11] §5-5).

### 2.24 복구 단어 여러 개 (설정 → 복구 단어) — 2026-11-07

D37, [02] §8.6. 설정 탭 `복구 단어`(S15)와 메인 EVM 계정 카드의 링크 `복구 단어 추가·관리`로 연다.

- **목록**: 안내 T-MN-INTRO("지갑에 복구 단어(니모닉)를 여러 개(최대 8개) 둘 수 있습니다. 복구 단어마다 계정이 따로 생기고, 각 복구 단어는 따로 적어 두어야 합니다 — 한 복구 단어로 다른 복구 단어의 계정을 되찾을 수 없습니다."). 니모닉마다 카드 하나(제목 = 라벨, 기본 `복구 단어 N` — 2026-11-08, 이전 버전이 저장한 `니모닉 N`은 그대로 두고 둘 다 기본 라벨로 센다(`meta::default_mnemonic_number`; 새 번호는 두 표기 중 가장 큰 N + 1)): 단어 수 · passphrase 사용 · EVM 계정 n개 · 첫 복구 단어면 "처음 만든(가져온) 복구 단어 · 지울 수 없음"(이전 "…Solana·Bitcoin·Zcash 계정도 이 단어에서"는 추가 복구 단어도 다른 체인 계정을 만들게 된 뒤 틀린 말이었다) · 백업 상태. `복구 단어 추가 가져오기`의 미리보기 주소는 4자 묶음(§3.3). 백업 확인 전이면 경고 띠 T-MN-UNCONFIRMED("백업 확인 전입니다. 이 복구 단어의 계정은 받기만 되고 서명(보내기·연결 승인)은 백업 확인 뒤에 됩니다."). 버튼: `이름 바꾸기`(라벨 편집, Label 규칙 [02] §5.3, meta `mnemonics`), `단어 보기`(W03 → W08 보기, 화면 캡처 차단 창), `백업 확인`(확인 전일 때: W03 → W08(2초 확인) → W10), `지우기`(주 니모닉에는 없음).
- **복구 단어 추가 가져오기**(`Unlocked`만, 8개 미만): W05(단어, passphrase 체크) → [W06 두 칸] → 키 작업자가 단어를 보관하고 계정 0 주소를 계산 → 같은 구역에 카드 `가져올 복구 단어`(주소 Mono, "다른 지갑에서 보던 주소와 같은지 확인하세요") `가져오기`·`취소` → `가져오기`는 W03 비밀번호 → `add_mnemonic`. 그 단어가 등록된 YubiKey의 단어면(마스터 지문, 2026-11-08, [10] §7.1) 카드에 "이 복구 단어는 이 지갑에 등록된 YubiKey #n의 키를 만든 단어입니다…", 위험 띠 T-YK-SAME, 확인 체크(명령 ID 13,613)가 나오고 체크 전에는 `가져오기`가 꺼진다. 틀린 비밀번호는 W03에 E-VLT-001(단어는 계속 보관), 같은 시드는 E-VLT-011, 단어 오류는 W05에 다시. 성공: 정보 띠 "복구 단어를 추가했습니다…", meta를 다시 읽어 그 니모닉의 계정 0이 생긴다. `취소`·잠금·지갑 초기화, 그리고 이 구역을 떠나는 것(겹쳐 뜨는 확인 창 말고 다른 화면으로)은 보관한 단어(W05와 W06 사이 앱 메모리의 단어 포함)와 주소 미리보기를 지운다(`MnJob::Discard`; 잠금·초기화는 `MnUi` 전체를 처음 상태로).
- **새 복구 단어 만들기 (추가)**: W03 → `generate_mnemonic` → W08(첫 표시, 2초 확인) → W10 4단어 확인(틀리면 같은 위치로 다시, §2.3). 중간에 닫으면 백업 확인 전으로 남고(정보 띠 T-MN-UNCONFIRMED), 목록의 `백업 확인`으로 이어 한다.
- **지우기**(추가한 니모닉만): 카드 안에 위험 띠 T-MN-REMOVE("이 복구 단어와 그 계정이 지갑에서 사라집니다. 자금은 체인에 그대로 남지만, 이 복구 단어를 따로 적어 두지 않았다면 다시는 그 계정을 열 수 없습니다. 먼저 '단어 보기'로 적어 둔 단어와 같은지 확인하세요.")와 `이 복구 단어 지우기`·`취소` → W03 → `remove_mnemonic`. 그 계정(EVM·Solana·Bitcoin)의 dApp 연결을 지우고 meta를 다시 맞춘다(선택은 첫 계정으로; Bitcoin 계정은 meta에서 빠지고, 그 니모닉 키를 쓰던 Zcash 계정은 표준 경로로 다시 만든다). Solana·Bitcoin 연결은 그 계정을 meta에서 먼저 뺀 뒤 지운다(2026-11-08, [02] §8.6 — 그렇지 않으면 "아직 계정인 키" 규칙이 연결을 남긴다); 같은 단어를 다시 더해도 연결은 돌아오지 않는다. 잔액 검사는 하지 않는다(경고가 대신한다). 주 니모닉은 지울 수 없다(지갑 초기화 §2.20).
  - **백업 확인 전 니모닉(2026-11-08):** 경고는 위험 띠 T-MN-REMOVE-UNCONFIRMED("백업하지 않은 복구 단어입니다. 지우면 이 PC 어디에도 단어가 남지 않아…")이고, 카드 안에 `1. 단어 보기 (끝까지 보고 적어 두기)`(W03 → W08, 2초 `다 적었습니다` 누르기; 끝까지 눌러야 "보았음"), `2. 확인: '백업 없이 지우기' 입력` EDIT(보기 전에는 꺼짐; 명령 ID 13,614–13,615)가 있다. `이 복구 단어 지우기`는 보기 전에는 꺼져 있고, 누를 때 입력 문구를 검사해 틀리면 위험 띠로 멈춘다. 그 니모닉 계정의 받기 화면(EVM S12, Solana·Bitcoin 받기, Zcash 탭의 받기 카드)은 확인 문항을 통과할 때까지 위험 띠 "{라벨}: " + T-MN-RECEIVE-UNCONFIRMED("백업하지 않은 복구 단어의 계정입니다…")를 보인다. 2026-11-08: 그 띠 아래 버튼 `지금 백업 확인`(목록의 `백업 확인`과 같은 W03 → W08 → W10, 명령 ID는 그 니모닉의 `BACKUP_BASE + n`), 그리고 EVM·Solana 선택 계정 카드에도 그 니모닉의 계정이면 주의 띠 "'{라벨}' 백업 확인 전 — 이 계정은 받기만 되고, 보내기·서명은 백업 확인 뒤에 됩니다." + `지금 백업 확인`(`App::mn_signing_banner`, 표시 전용 — 서명하는 순간 vault의 거부 E-VLT-009는 그대로 마지막 방어선). 이전에는 보내기 폼·승인을 다 마친 뒤에야 E-VLT-009로 알았다.
  - **진행 중 거래가 있으면 거부(2026-11-08, 가져온 키 삭제 §2.18과 같은 규칙):** 그 니모닉의 Solana·Bitcoin·Zcash 계정의 저널 기록이 아직 확정될 수 있으면 — SOL `Pending`, BTC `BtcRecord::may_still_confirm`(진행 중·`Replaced`·30일 안의 포기·공개된 거부, 같은 주소의 다른 계정 레코드 포함), ZEC 종결 전(`Signed`·`Broadcast`·`Rejected`) — 또는 그 계정의 BTC 승인이 열려 있으면 `지우기`가 경고 대신 T-MN-BUSY("이 복구 단어의 Solana·Bitcoin·Zcash 계정에서 보낸 거래가 아직 확정될 수 있어(진행 중, 공개된 거래 또는 승인 중) 지울 수 없습니다. 거래가 확정되거나 만료된 뒤에 다시 시도하세요.")를 보인다. 키 작업자도 비밀번호 전에 같은 검사를 다시 해 거절한다(`MnOutcome::Busy`, 저널을 읽지 못하면 거절). 지운 뒤에는 그 니모닉 계정의 (이미 종결된) SOL·BTC·ZEC 저널 기록을 저널에서 지운다: 계정이 없어졌고, 이전 빌드는 그 기록 버전(아래 §6.6)을 손상 본문으로 읽기 때문이다.
- **계정 목록**(S10 EVM): 니모닉이 둘 이상이면 파생 계정 행에 출처 표시 `[니모닉 1]`·`[니모닉 2]`와 경로 도움말 "니모닉 2 · m/44'/60'/0'/0/i"; 가져온 키 `[가져온 키]`, YubiKey `[YubiKey]`는 그대로. 추가한 니모닉의 계정은 주 니모닉 계정 뒤, 가져온 키 앞에 온다. `이름 바꾸기`·`숨기기`(계정 0 제외)·`개인키 보기`는 주 니모닉 계정과 같다.
- **계정 추가**: 니모닉이 둘 이상이면 아래에 고르기 줄 "어느 복구 단어에서 계정을 만들까요?" + 니모닉별 버튼(가득 찬 니모닉은 비활성) + `취소`. 하나면 지금처럼 바로 더한다. 새 계정이 선택된다.
- **다른 체인(2026-11-08):** 추가한 니모닉도 Solana·Bitcoin·Zcash 계정을 만든다([02] §8.6; HyperEVM·HyperCore·WalletConnect·브라우저 연결은 EVM 계정으로 이미 됨). 출처 표시와 순서는 EVM과 같다(니모닉이 둘 이상이면 파생 계정 행에 `[니모닉 N]`; 가져온 키·YubiKey 배지는 그대로).
  - **Solana 탭**: 추가한 니모닉의 표준 계정 `m/44'/501'/i'/0'`(출처 태그 8)은 주 니모닉 계정 뒤, 가져온 키 앞. `계정 추가`는 니모닉이 둘 이상이면 고르기 줄 "어느 복구 단어에서 Solana 계정을 만들까요? (m/44'/501'/i'/0')" + 니모닉별 버튼 + `취소`(명령 ID 13,670–13,677, 13,612). 받기·보내기·SPL·dApp 연결·메시지 서명(SIWS 포함)·`이름 바꾸기`·`숨기기`(계정 0 제외)는 주 니모닉 계정과 같다. 다른 경로 스캔은 주 니모닉만. 수신자가 그 계정이면 `KnownKind::OwnMnemonic`("내 계정(추가한 복구 단어): {라벨}"). 지갑이 Solana를 쓰고 있으면(`sol_accounts`가 있음) 잠금 해제 때 새 니모닉의 계정 0을 만든다.
  - **Bitcoin 탭**: `계정 추가`의 형식 고르기 위에 니모닉이 둘 이상이면 라디오 `복구 단어`(니모닉별, 명령 ID 13,680–13,687; 기본 주 니모닉). 추가한 니모닉을 고르면 `키 출처`(EVM 키) 선택은 숨기고 그 니모닉의 표준 경로 `m/{44|49|84|86}'/{coin}'/{n}'`로 만든다(계정 번호는 형식마다 0부터; 주 니모닉의 네이티브 세그윗 계정 0은 meta `btc`). 네 형식, 고정 주소/HD 모드(계정마다), 받기·보내기·수수료 올리기·발견·UTXO·소유 증명·dApp 연결은 다른 HD 계정과 같다. 계정 행 이름은 `{형식} 계정 {n}  [{니모닉 라벨}]`. Bitcoin이 켜져 있으면 잠금 해제 때 새 니모닉의 네이티브 세그윗 계정 0을 그 네트워크에 만든다(고르면 발견 미완료 띠와 `다시 시도`). EVM 키 Bitcoin 계정은 주 니모닉의 EVM 계정만.
  - **Zcash 탭**: 계정 카드에 `추가한 복구 단어` 줄 — 추가한 니모닉마다 `{니모닉 라벨} 표준 경로 사용`(쓰는 중이면 `(사용 중)`, 명령 ID 13,690–13,697). 누르면 그 니모닉의 `m/44'/{133|1}'/0'/0/0`(출처 코드 5)이 그 네트워크의 계정이 된다(진행 중 거래가 있으면 거부, 다른 키 출처 바꾸기와 같음). 키 출처 줄은 `[니모닉 2] Zcash 표준 경로 · m/44'/133'/0'/0/0`.
- 키 전용·YubiKey 지갑도 같은 구역에서 복구 단어를 더할 수 있다. 처음 더한 것이 주 니모닉이 되고 파생 기능(계정 추가, Solana·Bitcoin·Zcash 파생 계정)이 나타난다. 새로 만든 첫 니모닉은 다음 잠금 해제부터 S04(백업 대기)가 된다(지갑 단위 백업 규칙 그대로).

## 3. 승인 창 (A01, 모든 체인)

### 3.1 큐 항목과 결과
```rust
pub const APPROVE_ARM_DELAY_MS: u64 = 1_000;
pub const HIGH_RISK_HOLD_MS: u64 = 2_000;      // 이식 HIGH_RISK_HOLD_MILLISECONDS
pub const APPROVAL_TICK_MS: u32 = 50;
pub const MIN_REMAINING_TO_SHOW_MS: u64 = 5_000;
// 큐 한도는 [05] §8.4: MAX_APPROVALS_PER_ORIGIN = 16, MAX_APPROVALS_GLOBAL = 64

pub struct QueueId(pub u64);                    // 프로세스 안에서 단조 증가
pub enum QueueSource { App, Site { origin: BrowserOrigin /* yw_core::policy, [05] §4.7 */, request: DappRequestRef, deadline: Instant } } // deadline: [05] §6.4
pub enum QueueKind {
    Connect(ConnectRequest),                    // [05] §4.2 "사이트 연결"
    Signing(SigningRequest),                    // [03]/[07]/[08]가 준비해 ApprovalRequest를 만든다
}
pub const SIM_WAIT_MAX_MS: u64 = 10_000;        // 시뮬레이션 대기 상한([03] §1.4 호출당 10 s), 넘으면 NoResult
pub enum PrepareStage { Building, Simulating { since: Instant } }   // 체인 파이프라인이 eth_simulateV1 직전에 UiEvent::Rpc로 알린다
pub enum PrepareState { Preparing(PrepareStage), Ready(ReadyContent), Failed { code: ErrorCode, retryable: bool } }
pub enum SimState { Ok, Unsupported, NoResult, Reverted, Incomplete } // §3.2.1, 분류 정본 [03] §6.3
pub fn sim_state(r: &ApprovalRequest) -> Option<SimState>; // EVM 거래 3종(EvmTransaction·EvmSpeedUp·EvmCancel)만 Some.
                                                          // 메시지·SOL·BTC(D27)와 시뮬레이션 전에 차단된 요청([03] §3.7)은 None
pub enum ReadyContent { Signing(ApprovalRequest /* [03] §11.1 */), Connect(ConnectView /* [05] §4.2 */) }
pub enum QueueOutcome {
    Approved(ApprovedResult),   // Signing: [03] ApprovalStore::consume 성공, Connect: 선택 계정
    Rejected, Expired, TimedOut, Cancelled, Revoked, TooManyPending, NotReady, Shutdown,
}
```

| `QueueOutcome` | 뜻 | dApp 응답(정본 [05] §5, [03] §11.6) |
|---|---|---|
| `Rejected` | 거부·창 닫기·잠금으로 닫힘·잠금 해제 창 `나중에` | 4001 `User rejected the request.` |
| `Expired` | 승인 창 내용 표시(Ready) 후 120 s(D23, [03] §11.5 `issue` 시점) | 4001 `Request expired.` |
| `TimedOut` | dApp 요청 기한 만료([05] §6.4) | -32603 `Request timed out.` |
| `Cancelled` | 확장 cancel·연결 끊김 | 응답 없음 |
| `Revoked` | 대기 중 그 origin 연결 해제 | 4100 `Unauthorized.` |
| `TooManyPending` | 큐 한도 초과 | -32005 `Too many pending requests.` |
| `NotReady` | `BackupPending`에서 Site 서명·연결 요청([05] §4.2·§8.4) | 4100 `Unauthorized.`([05] §5) |
| `PassphraseUnverified` | 잠김 중 큐에 들어간 Site 서명·연결 요청이 확인되지 않은 passphrase 세션(`App::passphrase_unverified()`, [02] §7.5)으로 풀림 | 4100 `ProviderError::PassphraseUnverified`(이유 메시지, [05] §5) |
| `Shutdown` | 앱 종료 | 4900 `Wallet connection closed.` |

App 항목(이 앱의 보내기·가속·취소·수수료 올리기)은 dApp 응답이 없다. `Rejected`·`Expired`면 그 흐름을 시작한 화면으로 돌아간다(보내기 폼은 입력 유지, §2.7; `Expired`는 T-APPR-EXPIRED). 다시 검토하면 새 승인을 만든다.

**Solana·Bitcoin dApp 항목(2026-10-31, [05] §3.6·§4.9, [07] §19, [08] §17)**: 연결(`sol_connect`·`btc_requestAccounts`)은 같은 "사이트 연결" 창을 쓰되 계정 목록이 **라디오**다(Solana 1개; Bitcoin은 목적마다 한 그룹, 행 라벨 앞에 `[결제용] `·`[오디널스용] `, 주소는 받기 주소 0번 전체). 안내 문구는 `이 사이트는 선택한 주소와 공개키를 볼 수 있습니다. 이 지갑은 Solana·Bitcoin에서 메시지 서명(소유 증명)만 지원하며, 거래 서명과 전송은 할 수 없습니다. 메시지 서명은 매번 따로 승인합니다.`, 구역 제목 `연결할 Solana 계정 (1개)`·`연결할 Bitcoin 주소 (용도마다 1개, 받기 주소 0번)`. 모든 그룹에 하나씩 골라야 `연결`이 켜진다. 메시지 서명(`ApprovalKind::SolMessage`·`SolSignIn`·`BtcMessage`)은 EVM `personal_sign`과 같은 창·준비 시간(1 s)·고위험 확인·일회 소비·120 s 만료·digest 규칙을 쓰고, 요약 문장은 "{네트워크}에서 메시지에 서명해 이 주소의 소유를 증명합니다. 거래 서명이나 전송은 하지 않습니다."(SIWS는 "사이트 로그인(Sign-In-With-Solana) 메시지에 서명합니다. …"). 차단 경고(`M01`–`M03`, `W01`–`W04`, `W07`)가 있으면 `거부`만 가능하다. AI 설명 패널은 없다. 서명은 키 작업 `SignChainMessage`가 하고 잠금으로 취소되면 4001이다.

**HyperCore 전송(2026-11-06, D34, [11] §6)**: 앱 항목 `QueuedItem::HyperCore`(origin 앱, 준비 없이 바로 Ready). 요약 문장 "{네트워크}에서 Hyperliquid HyperCore 작업에 서명합니다: {작업}. 서명하면 Hyperliquid가 바로 처리하며 되돌릴 수 없습니다." + 받는 주소. 시뮬레이션 카드 대신 "금액·수수료" 구역(`0x0703`·`0x0704`), 핵심 정보(`0x0701`·`0x0702`), 세부 정보(nonce, 원본 typed data). 헤더 배지 T-MAINNET 또는 "HyperCore 테스트넷 — 실제 자산이 아닙니다"(테스트넷 색). H03(주소 오염)이면 고위험 확인. 승인 뒤 서명은 EVM typed-data와 같은 키 작업(`SignMessage`, YubiKey는 카드 단계)이고, 결과는 dApp이 아니라 HyperCore 제출(`POST /exchange`)로 간다. dApp의 Hyperliquid typed data는 `EvmTypedData` 그대로이며 표시만 [11] §7로 구조화한다.

### 3.2 배치 (위 → 아래)
`ApprovalDisplay { title, fields, warnings, risk, ack_required }`와 `DisplayField { key, sub_label, value, critical, volatile }`([03] §11.1)를 다음 영역에 나눠 그린다.

| 영역 | 스크롤 | 내용 |
|---|---|---|
| 제목 표시줄 | — | 고정 `Your Wallet — 승인 요청`(연결은 `Your Wallet — 사이트 연결`) |
| 헤더 | 고정 | 흰 띠(테스트넷이면 `TESTNET_BG`, BTC는 [08] §2 배너 색)에 라벨·값 두 칸: 키 `0x0001` 요청 출처, `0x0002` 네트워크, `0x0003` 서명 계정([07]·[08]도 같은 키). 아래 배지(둥근 알약): 출처가 `http`면 "로컬 개발 사이트(http)", 호스트에 `xn--` 라벨이 있으면 "국제화 도메인(punycode)"([05] §4.2). 확장 호환 모드에서 온 요청이면 "호환 모드: MetaMask"·"호환 모드: Rabby"·"호환 모드: Phantom"·"호환 모드: UniSat"·"호환 모드: Xverse"([05] §2.12–§2.13, 출처는 실제 사이트 origin 그대로). Solana·Bitcoin dApp 요청은 네트워크 배지를 그 체인의 것(Solana 클러스터, BTC 배너)으로 그린다. 사용자 체인이면 T-CUSTOM-CHAIN, 테스트넷(Sepolia·Solana devnet)이면 테스트넷 문구, 기본 메인넷(Ethereum 1·HyperEVM 999·Arbitrum One 42161·Base 8453·BNB Smart Chain 56·Robinhood Chain 4663)·Solana mainnet이면 빨간 배지 T-MAINNET(§2.6과 같은 조건·문구, BTC는 [08] §2 배너) |
| 시뮬레이션 띠 | 고정 | 헤더 바로 아래. `sim_state`가 `Ok`가 아니면 `고위험` 태그가 붙은 `DANGER_BG` 띠(§3.2.1). `Ok`·`None`이면 없음 |
| 요약 | 스크롤 맨 위 | 정보색 카드 "요약": 평이한 한국어 한 문장(굵게 12pt) + 그 문장이 가리키는 **전체 주소**(4자 묶음, 줄이지 않음 — §0) + 그 주소에 대한 지갑의 주석(`[ ]` 안의 "일반 계정(EOA)", "주소록: {이름}" 등을 "·"로 이음) + `title`(9pt 보조, 예 `[Sepolia 테스트넷] SepoliaETH 보내기: 0.01 SepoliaETH`). 문장은 표시 모델에서만 만든다(digest 밖, `approval_view::summary`): 네이티브 보내기·SOL·BTC "{네트워크}에서 {금액}을(를) 아래 주소로 보냅니다."(조사는 금액 끝소리로), 그 밖 EVM 거래 "{네트워크}에서 컨트랙트를 호출합니다: {title의 동작}. 아래 자산 변화와 경고를 확인하세요.", 가속·취소·수수료 올리기·`personal_sign`·typed data는 종류별 고정 문장. 2026-11-08: SIWE로 해석된 `personal_sign`(제목 동작 "로그인 요청 (SIWE)")은 "{네트워크}에서 {SIWE 도메인 필드} 사이트 로그인(Sign-In with Ethereum) 메시지에 서명합니다. 거래를 보내지는 않습니다."(도메인이 요청 사이트와 다르면 S01 차단), 알려진 typed data(제목 동작이 있는 것: permit, Permit2, Seaport 등)는 "{네트워크}에서 '{제목 동작}'에 서명합니다(EIP-712). 서명만으로 권한이나 자산이 넘어갈 수 있으니 아래 경고와 내용을 확인하세요."; 알 수 없는 형식("타입 데이터 서명")은 이전 문장 |
| 자산 변화 | 스크롤 | 카드 "자산 변화 (시뮬레이션 결과)". `Ok`: 키 `0x0110`–`0x0113`, `0x0130`(시뮬레이션 기준). `Incomplete`: 받은 행 + `MUTED` T-SIM-PARTIAL. `Unsupported`·`NoResult`·`Reverted`: `MUTED` T-SIM-NODIFF. SOL·BTC는 카드 "금액·수수료"(해당 문서의 금액·수수료·잔돈 행). 메시지 서명(`personal_sign`·typed data, Solana `sol_signMessage`·`sol_signIn`, Bitcoin `btc_signMessage`)에는 이 카드가 없다(자산이 움직이지 않으므로 "시뮬레이션 결과가 없어…" 문구도 보이지 않는다) |
| 경고 | 스크롤 | 카드 "확인할 경고": `warnings` 순서대로(등급 내림차순, [03] §10.1; 띠로 올린 시뮬레이션 경고는 빼고) 등급 태그와 함께 — 고위험 `DANGER_BG`, 차단 `BLOCKED_BG`, 주의 `WARN_BG`. `ack_needed`(§3.4)면 목록 아래에 체크박스 **1개** "위 경고를 모두 확인했습니다"(D16, 띠 포함 경고 수와 무관). 목록이 비어 있고 확인이 필요하면(띠만 있는 경우) "맨 위의 고위험 경고를 읽고, 이해했으면 아래에 체크하세요." 2026-11-08: **정보** 등급 줄은 그 뒤 별도 구역 "참고"에 같은 순서로 보인다(정보 줄만 있으면 "참고"만 — 메시지 서명의 M04·SIWE S09 등이 "확인할 경고"라는 제목을 달지 않게 해 그 제목이 경고 피로로 묻히지 않게). 모든 줄은 그대로 보이고 접지 않으며 digest·등급·`ack_needed`는 바뀌지 않는다(그리는 쪽만, `approval_view::signing_view`). |
| 핵심 정보 | 스크롤 | 카드 "핵심 정보": 위에 나오지 않은 `critical == true` 필드를 `fields` 순서대로. **critical 필드는 접지 않는다** |
| 자세히 | 스크롤 | 링크 `자세히 ▸ (나머지 항목·원본 데이터)`로 접힘(메시지 서명에도 맞는 일반 이름): 위에 나오지 않은 `critical == false` 필드 전부를 `fields` 순서대로, 원본 데이터(키 `0x0140`–`0x014F`, 액세스 리스트·calldata)는 그 뒤에. `risk ≥ High`면 펼친 채 시작 |
| AI 설명 | 고정 | M6, [06] §6: 버튼 바로 위, 본문 10줄 높이를 미리 확보 |
| 하단 | 고정 | 흰 띠. 상태 줄(남은 시간 `m:ss`, "대기 중인 다른 요청 n건", 길게 누르기 진행, 끝에 사용자가 할 일 한 문장 — 2026-11-08, `app_approval::next_step`, 표시 전용: 연결 창에서 고른 계정이 없으면 "연결할 계정을 하나 이상 고르세요", 확인 체크가 필요하고 비어 있으면 "경고를 읽고 아래 '위 경고를 모두 확인했습니다'에 체크하세요", 고위험 길게 누르기를 2초 전에 놓았으면 다음 누름까지 "2초가 되기 전에 놓았습니다 — 다시 2초 동안 누르세요", 무장 대기는 아래 문구, 고위험이고 무장되었으면 "'승인'을 2초 동안 누르고 있으세요". 이전의 "경고를 확인하고 체크한 뒤…" 문구는 남은 시간 때문에 한 번도 보이지 않았다), 버튼 `거부`(보조) `승인`(주 버튼, 무장 전에는 회색 — 내용·확인 체크는 갖춰졌고 창의 시간 조건(1초 대기·전경·누름 간격)만 남았으면 상태 줄 끝에 "잠시 뒤 버튼이 켜집니다 (실수 클릭을 막는 1초 대기)", 창이 뒤에 있으면 "이 창을 클릭해 앞으로 가져오면 1초 뒤 버튼이 켜집니다"(`ApprovalSession::arm_waiting`, 표시 전용 — 무장 계산은 그대로; 2026-11-07)), 대기 요청이 있으면 링크 버튼 `이 사이트의 대기 요청 모두 거부` |

- 필드 라벨 = [03] §11.2(및 [07]·[08])의 키 이름, `sub_label`이 있으면 "{이름} · {sub_label}". yw-app의 라벨 표에 없는 키가 오면 그 요청을 표시하지 않고 `Rejected` + E-UI-001.
- `Connect` 내용은 [05] §4.2 그대로다(안내 문구, EVM 계정 체크박스 + 라벨 + 전체 주소, 기본 선택, 현재 체인, `거부`/`연결`). 위험 등급은 정보, 선택이 0개이거나 16개를 넘으면 `연결` 비활성([02] §5.3 `ConnectedSite.accounts` 1..=16).

#### 3.2.1 시뮬레이션 상태 (EVM 거래, D15)
시뮬레이션은 항상 시도하고(`simulation = unsupported` 체인 제외) 결과와 무관하게 승인할 수 있다. 상태는 창에 항상 명시한다.

| 상태 | 뜻(분류 정본 [03] §6.3) | 화면 | 승인 |
|---|---|---|---|
| (진행 중) | `Preparing(Simulating)`: 호출 중, 최대 `SIM_WAIT_MAX_MS` | 첫 준비: 내용 대신 스피너(`FOCUS`, 50 ms 틱) + T-SIM-RUNNING. 승인 클릭 후 재실행(§3.4): 내용 유지, 상태 줄·버튼에 스피너 | 버튼 비활성 |
| `Ok` | 시뮬레이션 성공·해석 완료 | 띠 없음, 자산 변화(diff) | 등급대로 |
| `Unsupported` | 체인 `simulation = unsupported`, 호출하지 않음 | 띠 E-SIM-003 | 고위험 확인 |
| `NoResult` | RPC 오류·10 s 초과·한도 초과·메서드 미지원·응답 형식 이상·해석 불가 | 띠 E-SIM-002 + 원인 | 고위험 확인 |
| `Reverted` | `status 0x0`(revert·VM 오류) | 띠 E-SIM-001 + 되돌림 이유([03] §7.4 해석, 해석 불가면 그 사실) | 고위험 확인 |
| `Incomplete` | 응답은 있으나 효과 일부를 확인·해석하지 못함 | 띠 E-SIM-004 + 원인, 확인된 행만 | 고위험 확인 |

- 띠: [03]이 비성공 상태마다 표시 모델에 넣는 고위험 시뮬레이션 경고(digest 포함, [03] §10.2·§11) 1개를 경고 목록 대신 고정 띠에 그린다. 경고 `text`의 첫 줄은 §7 E-SIM-00n 문구 그대로(spec.md D15와 같은 문자열, 굵게), 둘째 줄부터 원인([03] §6.3 표시 열, 되돌림 이유)이다. yw-app은 첫 줄 끝에 상태별 코드 `(E-SIM-00n)`을 덧붙여 그린다(digest 밖, 상태와 1:1). 띠는 §3.3 렌더러로 그리고 줄바꿈하며 자르지 않는다. 띠가 높아도 하단 고정 영역은 줄지 않는다(띠 최대 높이 = 창 높이의 1/3, 넘으면 띠 안 스크롤).
- 고위험 확인 = D16의 체크박스 1개 "위 경고를 모두 확인했습니다" + `승인` 2초 길게 누르기. 해석되지 않은 호출(E12)과 시뮬레이션 비성공이 함께면 띠와 경고 목록에 둘 다 보이고 체크박스는 여전히 1개다(D16).
- 진행 중 표시는 `SIM_WAIT_MAX_MS` 안에 끝난다. 그때까지 결과가 없으면 체인 파이프라인이 `NoResult`(시간 초과)로 요청을 만들고 늦게 온 응답은 버린다(작업 id 불일치). 시뮬레이션 실패는 `Failed`(§3.5)가 아니다.
- `NoResult` 띠에는 `시뮬레이션 다시 시도`가 있다: 같은 거래로 [03] §6.6 재시뮬레이션 경로(기한 유지, 결과로 표시 교체·체크 해제). `Unsupported`·`Reverted`·`Incomplete`에는 없다.

### 3.3 표시 규칙
- **자르지 않는다.** 값은 줄바꿈하고 넘치면 스크롤한다. 말줄임표·툴팁 전용 표시는 없다. 접을 수 있는 것은 `자세히` 영역(`critical == false` 필드와 원본 데이터)뿐이고, critical 필드·경고·시뮬레이션 띠·요약은 접지 않는다.
- 줄바꿈(`ui::text_layout`): 공백에서 나누고, 한 단어가 폭을 넘으면 문자 단위로 나눈다. 덧붙이는 문자는 없다. LF는 줄바꿈이다. 값은 최대 270,000바이트·필드 1,024개([03] §11.2)이므로 배치는 폭이 바뀔 때만 다시 하고 보이는 줄만 그린다. 시험: 줄 조각을 이으면 원래 값과 같다(줄바꿈 지점의 공백 1개 제외).
- 주소 그리기: 전체를 4자 묶음으로 그리기 간격만 넓힌다(문자를 넣지 않는다). 강조는 체인 문서를 따른다: EVM 없음, SOL 가운데 묶음 굵게([07] §12.3), BTC 앞 6자·뒤 6자 굵게([08] §10). 주소가 주소록·내 계정과 정확히 같으면 "주소록: {이름}"(verified면 "✓ 확인됨") / "내 계정: {라벨}", 앞 4·끝 4자만 같으면 W-ADDR-3을 `WARN_BG` 주석으로 값 아래에 붙인다. 이 주석은 yw-app이 meta로 만들며 `ApprovalDisplay`와 digest에 들어가지 않는다([03] 빌더의 주소록 라벨·SOL 경고와는 별개의 보조 표시).
- hex 원본: 폭이 80열 이상이면 한 줄 32바이트, 아니면 16바이트. 줄 앞에 오프셋 `[0x0000]`. calldata는 첫 줄에 셀렉터 4바이트만.
- **표시 금지 문자**: 이식 `archive/spec-v2.4:crates/approval-wire/src/lib.rs:1266-1300`(`validate_text`: 빈 값·앞뒤 공백 금지, `is_forbidden_display_character`: 제어 문자와 U+00AD, U+034F, U+061C, U+115F–1160, U+17B4–17B5, U+180B–180F, U+200B–200F, U+2028–202E, U+2060–206F, U+3164, U+FE00–FE0F, U+FEFF, U+FFA0, U+FFF9–FFFB, U+1BCA0–1BCA3, U+1D173–1D17A, U+E0000–E0FFF). 단, 값 안의 LF는 허용한다.
  - 신뢰하지 않는 텍스트는 [03] §9.2가 `[U+XXXX]`(대문자 hex 4–6자리)로 이스케이프해 둔다. yw-app은 `\[U\+[0-9A-F]{4,6}\]` 부분을 `ESCAPE_TEXT` 색으로 그린다(원문에 같은 글자가 있어도 같은 모양이므로 무해하다).
  - yw-app은 그리기 전에 제목·필드·경고 문자열을 모두 다시 검사한다. 금지 문자가 남아 있으면 표시하지 않고 `Rejected` + E-UI-001(방어 중복).
- 금액은 [03] `format_units`·`format_amount` 결과 그대로 그린다. 글리프 없는 문자는 대체 사각형으로 보인다(숨기지 않는다).

### 3.4 버튼과 상호작용
`ApprovalInteraction`을 이식한다(`archive/spec-v2.4:crates/approval-ui/src/lib.rs:140-475`, 테스트 `lib.rs:580-1006`) → `yw_app::ui::interaction`(순수 모듈). 바꿀 점:
1. 위험 사상: [03] `Info`·`Caution` → 이식 `Standard`, `High` → `High`, `Blocked` → 상호작용 없음(승인 버튼 비활성, 거부만). `sim_state`가 `Ok`·`None`이 아니면 등급과 무관하게 `High`로 사상한다(방어 중복, D15). 만료는 `ApprovalGate.deadline`으로 판정하고, `read_request`·`write_response`(`lib.rs:477-506`)와 one-shot `PRESENTED`는 버린다.
2. `armed: bool`과 `set_armed(now, bool)`을 추가한다. `armed == false`면 `ApproveActivated`와 hold 시작을 무시하고, 진행 중인 hold를 지우고 그 입력원을 block한다.
3. `physical_down`은 `input::is_down(VK_LBUTTON / VK_SPACE)`로 채운다. 입력 일관성 검사이며 주입 입력을 구분하지 못한다(보안 경계 아님, spec.md §2.2).

```rust
pub struct ApprovalGate {      // UI 스레드가 창마다 유지
    prepare: PrepareState, ack_checked: bool /* 체크박스 1개(D16) */, connect_selected: usize,
    ready_at: Instant, is_foreground: bool, deadline: Instant, submitting: bool,
}
// D16: 확인은 등급에서만 파생한다([03] §10.1 ack_required = (risk == High), 경고별 ack 없음).
// 셋 중 하나라도 참이면 체크 1개(방어 중복), 고위험(§3.4-1 사상 포함)이면 2초 누르기.
pub fn ack_needed(r: &ApprovalRequest) -> bool {
    r.display.ack_required || r.display.risk == RiskLevel::High
        || matches!(sim_state(r), Some(s) if !matches!(s, SimState::Ok))   // D15: 시뮬레이션 비성공
}
// [06]: AI 상태를 인자로 받지 않는다. Preparing(진행 중 시뮬레이션 포함)·Failed는 항상 거짓.
pub fn can_approve(g: &ApprovalGate, now: Instant) -> bool {
    let (content_ok, ack_req) = match &g.prepare {
        PrepareState::Ready(ReadyContent::Signing(r)) => (r.display.risk != RiskLevel::Blocked, ack_needed(r)),
        PrepareState::Ready(ReadyContent::Connect(_)) => ((1..=16).contains(&g.connect_selected), false), // [02] §5.3
        _ => (false, false),
    };
    content_ok && (!ack_req || g.ack_checked)
        && now >= g.ready_at + Duration::from_millis(APPROVE_ARM_DELAY_MS)
        && g.is_foreground && now < g.deadline && !g.submitting
}
```
매 이벤트와 50 ms 타이머마다 `set_armed(now, can_approve(..))`. 타이머·상호작용 이벤트는 아래 막대(상태 줄·버튼·hold 진행 막대)만, 그 표시 내용(남은 시간 초, hold 진행, 활성 모양, 버튼 글자)이 바뀐 때만 다시 그린다(`invalidate_rect`). 머리·시뮬레이션 띠·스크롤 패널은 내용이 바뀔 때만 다시 그린다(시뮬레이션 카운트다운도 보기가 같으면 그리지 않음). `승인` 버튼은 승인 입력이 지금 받아들여질 때만 활성 모양이다(`ApprovalSession::approve_ready`: armed, 게이트 열림, 마지막 누름에서 1초 이상 또는 hold 진행 중). 차단 등급이면 버튼 글자 "승인할 수 없음".

**빠른 클릭 유도 방어.** (1) armed가 아닐 때 받은 모든 포인터·키 누름(창 어디든, 키 자동 반복 포함 — 다른 버튼·본문·AI 패널·스크롤 막대 클릭, 비활성 창을 활성화하며 먹힌 클릭, 승인 버튼에서의 Enter·Space 밖 모든 키는 `InteractionEvent::OtherPress`)은 1초 대기를 다시 시작한다(`ready_at = max(ready_at, now)`). 창이 (다시) 활성화될 때(전경 false → true, 매 이벤트·타이머에서 확인, `WM_ACTIVATEAPP(TRUE)`)도 다시 시작한다. (2) 승인 입력(승인 버튼의 Enter·포인터 누름·Space)은 창 안 **직전 누름에서 1초 이상** 지나 시작해야 한다 — 버튼이 이미 armed였어도 그렇지 않으면 아무 일도 하지 않는다. 직전 누름은 표시 교체·상호작용 재시작을 넘어 기억한다. 오른쪽·가운데·X 버튼 누름(`WM_RBUTTONDOWN`·`WM_MBUTTONDOWN`·`WM_XBUTTONDOWN` → `Msg::OtherButtonDown`)과 비클라이언트 영역(제목 표시줄·캡션 버튼·테두리·창 스크롤 막대) 누름·더블클릭(`WM_NC?BUTTONDOWN`·`WM_NC?BUTTONDBLCLK` → `Msg::NonClientButtonDown`)도 승인 창·본문 패널·AI 패널에서 `OtherPress`다(`interaction::stray_press`); 시스템 처리(이동·닫기·스크롤)는 `Reply::Default`로 그대로 둔다.

| Win32 입력 | `InteractionEvent` |
|---|---|
| `승인` 위 `WM_LBUTTONDOWN`(+`SetCapture`) | `PointerPressed { inside, click_through: !창이 전경이었음, physical_down }` |
| 캡처 중 `WM_MOUSEMOVE` / `WM_LBUTTONUP`(+`ReleaseCapture`) | `PointerMoved { inside }` / `PointerReleased { physical_down }` |
| `승인` 포커스에서 `WM_KEYDOWN VK_SPACE` / `WM_KEYUP VK_SPACE` | `SpacePressed { repeat: lParam bit 30, physical_down }` / `SpaceReleased { physical_down }` |
| `승인` 포커스에서 Enter | `ApproveActivated { physical }`(High에서는 무시). `physical` = 그 메시지의 키 상태에서 Enter가 눌려 있음(`GetKeyState`, `input::is_down_in_message`) **그리고** 주입 입력이 아님(`input::injected`). 다른 프로그램이 `PostMessage`·`SendMessage`로 넣은 `WM_KEYDOWN`은 키 상태를 바꾸지 않으므로 `physical == false` → 승인하지 않고 누름으로만 센다(Space·포인터의 `is_down` 대조와 같은 취지, 보안 검토 L5) |
| `거부` 클릭, `거부` 포커스에서 Enter·Space, Esc, X, Alt+F4 | `RejectActivated` |
| `WM_KILLFOCUS`(다른 창으로) / `WM_ACTIVATEAPP(0)` / 예기치 않은 `WM_CAPTURECHANGED` / `WM_CANCELMODE` | `FocusLost` / `ForegroundLost` / `CaptureLost` / `CancelMode` |
| `WM_TIMER` 50 ms | `Tick` |

- 정보·주의: 클릭(같은 버튼 위에서 누르고 떼기) 또는 `승인` 포커스에서 Enter·Space([03] §10.1).
- 고위험(시뮬레이션 비성공 포함): 버튼 글자 "승인 (2초 길게 누르기)". 확인 체크를 켠 뒤 마우스나 Space로 2초 연속 누른다(D16, 모든 체인 공통). 진행은 버튼 위 막대(`FOCUS`)와 "{0.0}초". Enter 무시. 시뮬레이션 진행 중에는 버튼 글자 "시뮬레이션 중…"과 스피너, 비활성.
- 초기 포커스 `거부`. Tab: `거부` → 확인 체크박스 → `승인` → `자세히` → 스크롤 영역. 스크롤: 휠, PageUp/PageDown, 스크롤 영역 포커스에서 화살표.
- 상호작용이 `Approved`가 되면: `Connect`는 선택 계정으로 바로 `Approved`([05] §4.2 5단계). `Signing`은 `submitting = true`, 상태 줄 "확인 중…", 체인 파이프라인에 `approve(id, shown_digest)`를 보낸다. EVM은 [03] §6.6 결과에 따라:
  - 시뮬레이션이 60 s보다 오래되어 다시 실행하는 동안(D23; `Unsupported`는 다시 실행하지 않음) → 상태 줄·버튼 T-SIM-RUNNING과 스피너, 최대 `SIM_WAIT_MAX_MS`.
  - 소비 성공 → 창을 닫고 서명·전송은 S11 결과 화면·활동에 나온다.
  - 재시뮬레이션이 성공했고 결과가 다름 → 표시 교체, 상태 줄 T-SIM-CHANGED, 체크 해제, `ready_at = now`, 새 `ApprovalInteraction`(기한 그대로), `submitting = false`.
  - 재시뮬레이션이 성공하지 못함(`NoResult`·`Reverted`·`Incomplete`) → 이전 표시와 같더라도 같은 처리로 표시를 교체해 비성공 띠(§3.2.1)를 보이고 상태 줄 T-SIM-RESIM-FAILED. 새 클릭(체크 + 2초 누르기)을 요구한다. 그 시도 시각부터 60 s 안의 다음 클릭은 다시 실행하지 않고 소비한다([03] §6.6).
  - 서명 전 단계 실패(소비 실패 등) → `Failed`(§3.5).
- 표시 모델이 바뀌면(준비 완료, 교체) 진행 중 hold를 지우고 확인 체크를 끄고 `ready_at = now`.

### 3.5 준비·기한
- 창은 큐에서 꺼내는 즉시 열고 `Preparing(Building)`("요청을 준비하는 중입니다…", 승인 비활성)으로 시작한다. 준비는 RPC 작업자와 체인 파이프라인이 한다. EVM 거래는 시뮬레이션 직전에 `Preparing(Simulating)`(T-SIM-RUNNING, §3.2.1)으로 바뀌고, 성공이든 비성공이든 결과가 나오면 `Ready`다.
- `Failed`: 서명할 거래 자체를 만들지 못한 경우다(시뮬레이션 전 필수 RPC: 체인 확인·nonce·수수료·가스 등의 실패, 준비 시간 초과; 세부는 [03] §3.7). 시뮬레이션 실패는 여기에 오지 않는다(§3.2.1). 경고 영역 맨 위에 §7 문구와 코드. `retryable`(E-RPC-001·002·004)이면 `다시 시도`로 준비를 다시 시작한다(기한 유지). 차단 조건(D16: 수수료 상한 초과 등 서명 형식 위반)이 표시 모델의 차단 경고로 오면 그 경고를 그대로 보인다.
- 승인 만료 규칙은 이 절이 모든 체인(EVM·SOL·BTC)의 정본이다. 체인 문서는 별도 만료·`새로고침` 상태를 두지 않는다.
- 기한 `deadline = min(Site 요청 기한([05] §6.4, 연결·서명 600 s, D23), 표시 + 120 s)`. `표시`는 Ready 내용을 처음 그린 시각이며 UI는 이때 [03] `ApprovalStore::issue`를 부른다(D23). `Preparing` 동안은 Site 기한만 적용한다. App 항목은 `표시 + 120 s`만. 상태 줄에 남은 시간, 0이면 해당 결과(`TimedOut` 또는 `Expired`)로 창을 닫는다. 꺼낼 때 남은 시간이 `MIN_REMAINING_TO_SHOW_MS`보다 작으면 창을 열지 않고 `TimedOut`.
- `Expired`: Site 항목은 dApp에 4001 `Request expired.`(§3.1). App 항목은 앱이 그 흐름을 시작한 화면(보내기는 폼, 입력값 유지, §2.7)으로 돌아가 T-APPR-EXPIRED를 보인다. 같은 승인을 되살리거나 연장하지 않는다. 다시 검토하면 준비부터 다시 하고 새 승인(새 id, 새 `issue`)을 만든다.

### 3.6 창 동작
- 기본 820×710 DIP, 최소 520×460(이식 `native.rs:40-60`). AI 설명 패널을 확보하는 창(M6, [06] §6)은 높이에 240 DIP를 더한다(820×950, 최소 520×700). 작업 영역보다 크면 맞춘다. 주 창이 있는 모니터(없으면 기본 모니터) 가운데.
- `WS_EX_TOPMOST`. 연 직후 `SetForegroundWindow`, 전경이 되지 못하면 `FlashWindowEx(FLASHW_ALL | FLASHW_TIMERNOFG, 0)`.
- 클릭 관통 방지: `MA_ACTIVATEANDEAT`(§1.8), `click_through` 이벤트, `APPROVE_ARM_DELAY_MS`.
- 화면 캡처 제외는 적용하지 않는다(비밀 없음, D11 대상 아님). 소유 창 없음.

### 3.7 큐
- 창은 한 번에 하나, 순서는 도착 순(FIFO, [05] §8.4). App 항목은 현재 창 바로 다음에 넣는다.
- 한도: origin당 16, 전체 64(표시 중 포함, [05] §8.4). 넘으면 즉시 `TooManyPending`. 같은 origin 연결 창 중복은 [05] §4.2(-32002).
- `Locked`·`PassphraseRequired`·`Unlocking`: 꺼내지 않는다. 큐가 비어 있지 않으면 W02를 연다(§2.5). `BackupPending`: Site 서명·연결 항목은 즉시 `NotReady`([05] §4.2·§8.4).
- 잠기는 순간 표시 중인 창은 닫고 `Rejected`([05] §4.4, [03] `invalidate_all`). 대기 중인 항목은 남아 잠금 해제를 기다린다(기한 유지).
- dApp 취소([05] §8.4): 대기 중이면 제거, 표시 중이면 창을 바로 닫는다. 둘 다 `Cancelled`.
- 연결 해제(S13, `wallet_revokePermissions`): 그 origin의 Site 서명 항목은 `Revoked`.
- 대기 중 기한 만료 → `TimedOut`(꺼낼 때와 `MAIN_TIMER_MS`마다 검사).
- `이 사이트의 대기 요청 모두 거부`: 표시 중 항목과 같은 origin의 대기 항목 모두 `Rejected`.

### 3.8 AI 설명 패널 (M6)
내용·상태·문구는 [06]. 이 문서의 규칙: 하단 고정 영역의 버튼 위, 배경 `AI_PANEL_BG`, 제목 "AI 설명 (참고용, 틀릴 수 있음)", 키보드 포커스 없음, 결과가 와도 다른 영역의 배치 불변, 문자열은 §3.3 렌더러로 그린다. `can_approve`·`ApprovalInteraction`·위험 등급·digest는 패널과 무관하다. 고위험(`High`) 요청은 경고 확인 체크 전까지 본문 대신 안내 한 줄만 보인다([06] §6). "설명 불일치"로 접힌 본문은 패널 클릭으로 펼친다([06] §5.4). 패널 클릭·스크롤은 승인 누름 간격 규칙의 "다른 누름"이다(§3.4).

### 3.9 시험 (자동)
- AP-1: 이식 `lib.rs:580-1006` 테스트 전부 통과(위험 사상 적용).
- AP-2(빠른 클릭): armed 아님에서의 누름은 대기를 다시 시작한다(10,999 ms 누름 뒤 11,000 ms 클릭 무시, 12,000 ms 승인); 창 활성화도 다시 시작; 아무 누름 뒤 999 ms의 승인 누름(포인터·Enter·고위험 포인터·Space hold) 무시, 1,000 ms 수락; 오른쪽·가운데·X 버튼과 비클라이언트 누름도 대기 재시작·누름 간격에 들어감; 빠른 클릭 연속 + 자동 반복 Enter는 1초 멈춘 뒤의 누름만 승인.
- AP-2: `armed=false`에서 Enter·클릭·2초 hold → `Pending`. 고위험 경고 2개: 체크박스는 1개, 체크 끔 + 2초 hold → `Pending`; 체크 켬 + 1.9초 / 2.0초 → `Pending` / `Approved`. `risk == High`인데 `ack_required == false`인 비정상 입력도 체크 필요(D16, 방어 중복). `Blocked` → 어떤 입력도 `Approved` 아님. `ready_at` + 999 ms 클릭 → 무시. 표시 교체 중 hold → 취소, 체크 해제.
- AP-3: 같은 origin 17번째·전체 65번째 → `TooManyPending`. 남은 기한 4,999 ms → 창 없이 `TimedOut`. `Preparing` 30 s 뒤 Ready → `Expired`는 Ready 표시 + 120 s(준비 시간 불포함). App 항목 `Expired` → 폼 입력 유지, 다시 검토 시 새 승인 id(이전 id `consume` 실패). `Connect` 선택 16개 → `can_approve` 참, 17개 → 거짓. 표시 중 잠금 → `Rejected`, 대기 항목은 남음. 연결 해제 → 그 origin 대기 항목 `Revoked`.
- AP-4: 이스케이프되지 않은 U+202E, 라벨 표에 없는 `FieldKey` → 표시 없이 `Rejected` + E-UI-001. 270,000바이트 값과 공백 없는 3,000자 문자열 배치 → 줄 조각을 이으면 원문과 같음.
- AP-5: `can_approve`에 AI 상태 인자가 없다([06] E2와 함께 확인).
- AP-6(시뮬레이션 상태, D15): `Preparing(Simulating)` 동안 클릭·Enter·2초 hold → `Pending`. `Unsupported`·`NoResult`·`Reverted`·`Incomplete` 각각: 띠 1개 + 체크박스 1개, 체크 끔 + 2초 hold → `Pending`, 체크 켬 + 2.0초 → `Approved`, Enter → 무시. 비성공인데 `risk`가 `Caution`이고 `ack_required == false`인 비정상 입력도 체크·hold 필요. `Ok` + 정보 등급 → 클릭으로 `Approved`. `Blocked`(수수료 상한 초과 등) → `sim_state`와 무관하게 어떤 입력도 `Approved` 아님. E12 + `NoResult` → 체크박스 1개. 모의 시계로 `Simulating` 10,000 ms에 결과 없음 → `NoResult` Ready, 그 뒤 도착한 응답은 버림. 재시뮬레이션: `Ok` 표시 중 클릭 → 재실행 `NoResult` → 표시 교체·체크 해제·`ready_at = now`·T-SIM-RESIM-FAILED, 이전 클릭으로 소비되지 않음; 이어서 체크 + 2초 → `Approved`(재실행 없음). `Failed`의 `retryable`에 E-SIM 코드가 없다.

## 4. 비밀 입력·표시 창 (D11)

### 4.1 창 종류
| ID | 제목 | 필드: 문자 집합, 길이 | 화면 표시 | 붙여넣기 | 복사 | 캡처 제외(§4.5) |
|---|---|---|---|---|---|---|
| W01 | 비밀번호 정하기 | 비밀번호·확인 `Printable` 12–128 | 가림(●) | 허용 | 없음 | `Preferred` |
| W02 | 잠금 해제 | 비밀번호 `Printable` 1–128 | 가림 | 허용 | 없음 | `Preferred` |
| W03 | 비밀번호 확인 | 비밀번호 `Printable` 1–128 | 가림 | 허용 | 없음 | `Preferred` |
| W04 | 비밀번호 변경 | 현재 1–128, 새·확인 12–128 | 가림 | 허용 | 없음 | `Preferred` |
| W05 | 복구 단어 입력 | `MnemonicText` ≤ 216바이트(24 × 8 + 23 + 1) | 평문, 단어별 칸 격자 | 허용 | 없음 | `Preferred` |
| W06 | passphrase 입력 | 가져오기: passphrase·확인, 잠금 해제: 1칸. `Printable` 1–256 | 가림 | 허용 | 없음 | `Preferred` |
| W07 | 개인키 가져오기 | 체인별: EVM `PrivateKeyHex` ≤ 66, Solana `KeyText` 1–640, Bitcoin `Base58` 51–52 (§2.18) | 평문 | 허용 | 없음 | `Preferred` |
| W08 | 복구 단어 (니모닉) | — | 평문 3열 × (n/3)행, 열 우선 번호(24단어: 1–8, 9–16, 17–24) + 첫 주소 | — | 토글 | `Required` |
| W09 | 개인키 보기 | — | 평문(EVM hex 64자, Solana base58 keypair, Bitcoin WIF) | — | 토글 | `Required` |
| W10 | 백업 확인 | 단어 4칸 `BackupWord` ≤ 8 | 평문 | 금지 | 없음 | `Preferred` |
| W11 | YubiKey PIN | `Printable` OpenPGP 6–127 / PIV 6–8 ([10] §9.1) | 가림 | 허용 | 없음 | `Preferred` |
| W12 | YubiKey 관리자 PIN · PIV 관리 키 · PIV PIN · PIN/PUK 바꾸기 · PIN 하나로 통일 | 관리자 PIN `Printable` 8–127, 관리 키 `PrivateKeyHex` 정확히 48, PIV PIN 6–8, 통일 3칸(현재: 비움 또는 8, 새·새 확인 정확히 8), 바꾸기 3칸(현재·새·새 확인, 대상 범위: PW1 6–127, PW3 8–127, PIV PIN·PUK 6–8; 새 두 칸 같고 현재와 달라야 함) | 가림 | 허용 | 없음 | `Preferred` |

- 배치(§1.6): 회색 창 배경에 (만들기·가져오기 흐름이면) "{흐름} · n/3단계"와 단계 점, 제목 14pt, 안내 문구(보조색), 내용을 담는 흰 카드(입력 칸·단어 격자·체크박스·오류), 아래 버튼 줄(왼쪽 `모두 지우기`/`복사`, 오른쪽 `취소`/`나중에`와 주 버튼). W01의 주 버튼은 `다음`, W08 단어 격자는 번호(보조색) + 단어(14pt), 첫 주소는 4자 묶음으로 보인다.
- 가림 칸은 글자 수만큼 U+25CF를 그린다. 칸 옆 `보기`를 누르고 있는 동안만 평문을 그린다(§4.5 실패 시 비활성).
- 글자 수 "{len}/{max}". 커서는 항상 끝이다(이동·선택·실행 취소 없음). `모두 지우기` 버튼.
- `SECRET_WINDOW_TIMEOUT_MS = 300_000`: 입력 창은 마지막 입력 후, 표시 창은 표시 후. 넘으면 버퍼를 소거하고 닫는다("시간이 지나 창을 닫았습니다").

### 4.2 입력 버퍼
`SecureAsciiBuffer`(`archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs:118-178`)를 이식해 넓힌다 → `yw_app::ui::secure_field::SecretField`.
```rust
pub enum Charset { Printable, MnemonicText, PrivateKeyHex, BackupWord, Base58, KeyText }
pub enum PushResult { Accepted, Full, Rejected(RejectReason) }
pub enum RejectReason { NonAscii, NotAllowed, DoubleSpace, Position }
pub struct SecretField { bytes: Zeroizing<Vec<u8>>, limit: usize, charset: Charset }
impl SecretField {
    pub fn new(charset: Charset, limit: usize) -> Result<Self, FieldError>; // capacity == limit 확인
    pub fn push_unit(&mut self, u: u16) -> PushResult;   // WM_CHAR 1단위
    pub fn backspace(&mut self) -> bool;                 // 지운 바이트를 0으로 덮음
    pub fn clear(&mut self);                             // 전부 0으로 덮고 길이 0
    pub fn take(self) -> Zeroizing<Vec<u8>>;             // 작업자로 이동
    pub fn render_utf16(&self, masked: bool) -> Zeroizing<Vec<u16>>; // 그리기용 단기 사본
}
```

| `Charset` | 받는 값 | 변환·거부 |
|---|---|---|
| `Printable` | 0x20–0x7E | ≥ 0x80 → `NonAscii` |
| `MnemonicText` | `a`–`z`, 공백 | `A`–`Z`는 소문자로. 맨 앞 공백·연속 공백은 `DoubleSpace`(조용히 무시). 끝 공백은 확정 때 뗀다. 그 밖 `NotAllowed` |
| `PrivateKeyHex` | `0`–`9`, `a`–`f` | `A`–`F`는 소문자로. `x`는 길이 1이고 첫 글자 `0`일 때만(`Position`, `X` 거부). 확정 시 `0x`를 떼고 정확히 64자(E-INP-006), 범위는 [02] |
| `BackupWord` | `a`–`z` | `A`–`Z`는 소문자로 |
| `Base58` | base58 알파벳(`0`·`O`·`I`·`l` 없음) | 그 밖 `NotAllowed`. 확정 시 51자 미만이면 E-INP-023, 나머지 검사는 [02] §8.4 |
| `KeyText` | ASCII 영숫자, `[`, `]`, `,`, 공백 | 맨 앞·연속 공백은 `DoubleSpace`(조용히 무시), 끝 공백은 확정 때 뗀다. 붙여넣기는 `MnemonicText`처럼 공백·탭·CR·LF 연속을 공백 하나로. 형식 판정은 [02] §8.4 |

- 그리기: 매 `WM_PAINT`마다 `render_utf16` 단기 사본으로 `DrawTextW`를 부르고 바로 drop(이식 `recovery_native.rs:342-367`). 비밀 문자열을 OS EDIT 컨트롤, 창 제목, `WM_SETTEXT`, 툴팁에 넣지 않는다.
- W05는 [02] §2.4(단어별 입력 칸, 단일 공백 연결)에 맞춰 버퍼를 단어별 칸 격자 "{i}. word"로 그린다. 공백·Tab이 다음 칸으로 가는 키다. 목록에 없는 완성 단어는 `DANGER_TEXT`. 넘기는 값은 소문자 단어를 공백 하나로 이은 문자열이다.

### 4.3 키 처리
| 입력 | 동작 |
|---|---|
| `WM_CHAR` 0x20–0x7E | 활성 칸 `push_unit` |
| `WM_CHAR` ≥ 0x80(서로게이트 포함) | 거부, 칸 아래 E-INP-008 |
| Backspace(0x08) / Enter(0x0D) | `backspace` / 다음 칸, 마지막 칸이면 확정 |
| Tab, Shift+Tab(`WM_KEYDOWN`) | 칸 이동(W05에서는 다음 단어 칸) |
| Esc | 모든 버퍼 소거 후 닫기 |
| Ctrl+V, Shift+Insert | 붙여넣기(§4.7), 금지 창이면 무시 |
| Ctrl+C | W08·W09에서만 복사(§4.8) |
| 그 밖의 Ctrl·Alt 조합, 0x01–0x1F의 나머지, 0x7F | 무시 |
| `WM_LBUTTONDOWN` | 칸 활성화(이식 `recovery_native.rs:1559-1571`) |

### 4.4 차단 메시지
비밀 클래스 wndproc(yw-win, [01] §7.7)은 다음을 핸들러·`DefWindowProcW`에 넘기지 않고 0을 반환한다(이식 `recovery_native.rs:1468-1498`): `WM_GETTEXT`, `WM_GETTEXTLENGTH`, `WM_GETOBJECT`, `WM_PRINT`, `WM_PRINTCLIENT`, `WM_COPY`, `WM_CUT`, `WM_PASTE`, `WM_CLEAR`, `WM_UNDO`, `WM_CONTEXTMENU`, `WM_DROPFILES`, `WM_RBUTTONDOWN`, `WM_RBUTTONUP`, `WM_MBUTTONDOWN`, `WM_MBUTTONUP`, `WM_IME_STARTCOMPOSITION`, `WM_IME_COMPOSITION`, `WM_IME_ENDCOMPOSITION`, `WM_IME_CHAR`, `WM_IME_KEYDOWN`, `WM_IME_KEYUP`. 비밀 상태를 붙인 뒤에는 `WM_SETTEXT`도. 우리 붙여넣기·복사는 키 처리에서 직접 하므로 `WM_PASTE`·`WM_COPY`를 쓰지 않는다. 차단된 IME 메시지는 핸들러에 오지 않으므로 IME 사용은 §4.6처럼 `Msg::KeyDown`·`Msg::Char`로만 감지한다.

### 4.5 화면 캡처 제외
1. 비밀 클래스 `ui::create_window`가 창을 숨긴 채 만들고 핸들러를 붙이기 전에 `exclude_from_capture`를 한다: `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE = 0x11)` 후 `GetWindowDisplayAffinity == 0x11` 확인([01] §7.7, 이식 `recovery_native.rs:615-679`). 비밀 상태는 아직 없다.
2. 성공하면 비밀 상태를 붙이고 `show`. 설정 또는 읽기 확인이 실패하면 로그 `secret.capture_exclusion=failed capture=<Required|Preferred>`를 남기고 클래스의 `ClassSpec.capture`(§1.7, [01] §7.7)에 따라:
   - `CaptureExclusion::Required`(`YourWalletV3SecretView`: 니모닉·개인키 **표시** W08·W09): yw-win이 창을 파괴하고 `UiError::CaptureExclusionFailed`를 돌려준다. 비밀은 표시하지 않는다(표시할 버퍼는 창에 옮기지 않고 즉시 소거). 주 창에 E-SEC-001. W08 생성 흐름이면 지갑은 `BackupPending`으로 남고 S04에서 다시 시도한다(§2.3).
   - `CaptureExclusion::Preferred`(`YourWalletV3SecretInput`: 비밀번호·passphrase W01–W04·W06, 니모닉·개인키 **입력** W05·W07, 백업 확인 W10): 창을 유지하고 연다(실패 사실을 yw-app에 알리는 방식은 [01] §7.7). 내용 위 상단에 닫을 수 없는 `DANGER_BG` 경고 배너 T-CAPTURE-WARN을 창이 닫힐 때까지 보인다. 가림 칸의 `보기` 버튼은 끈다.

### 4.6 IME·비ASCII
- `Msg::KeyDown { vk: VK_PROCESSKEY (0xE5) }`(IME가 처리 중인 키) 또는 `Msg::Char(u ≥ 0x80)` → 칸 아래 E-INP-008을 3초 보이고 입력은 버퍼에 넣지 않는다.
- 비밀 창은 생성 때(캡처 제외 직후) `ImmAssociateContextEx(hwnd, NULL, 0)`으로 입력 컨텍스트를 떼어 IME가 조합하지 못하게 한다(yw-win, 기능 `Win32_UI_Input_Ime`). `WM_IME_*` 차단(§4.3)은 그대로 둔다(이중 방어). 실패해도 차단만으로 동작한다.
- 구현 시 확인: 한글 입력 모드에서 키를 누르면 위 둘 중 하나가 오거나 ASCII만 입력되는지(UI-M3-05).

### 4.7 붙여넣기
허용: W01–W07. 금지: W10(종이 백업 확인이 목적).
1. `clipboard::read_text(owner, PASTE_MAX_UTF16_UNITS = 4096)` → `(units: WipeBuf<u16>, seq)`. `TooLong`이거나 텍스트가 없으면 E-INP-018.
2. 새 `Zeroizing` 버퍼로 정규화. **`Printable`(비밀번호 W01–W04, BIP39 passphrase W06)은 그대로 쓴다:** 끝의 줄바꿈 하나(`CR LF`, `LF` 또는 `CR`)만 떼고 공백·탭은 절대 다듬지 않는다(passphrase `" TREZOR "`와 `"TREZOR"`는 다른 지갑이다). 그 밖에 바꿔야 할 단위가 있으면(탭, 앞의 줄바꿈, 두 번째 줄바꿈 등) 고치지 않고 전체를 거부한다(E-INP-018). 그 밖의 칸(니모닉·개인키 hex·WIF·base58·키 텍스트)은 앞뒤 공백·탭·CR·LF를 떼고, `MnemonicText`·`KeyText`는 공백·탭·CR·LF 연속을 공백 하나로, `A`–`Z`를 소문자로(해당 칸). 모든 단위를 활성 칸 `Charset`으로 검사해 하나라도 거부되거나 길이를 넘으면 전체를 거부하고(부분 삽입 없음) E-INP-018.
3. 통과하면 활성 칸 내용을 그 값으로 바꾸고(W05는 단어 칸에 나눠 넣음) `units`를 소거한다. `Printable` 값이 공백으로 시작하거나 끝나면 T-PASTE-EDGE-SPACE를 보인다(값은 그대로).
4. 통과했든 E-INP-018로 거부했든 읽은 텍스트는 비밀일 수 있으므로 `clipboard::clear_if_unchanged(owner, seq)`를 부른다(읽기는 시퀀스 번호를 바꾸지 않는다). true면 T-PASTE-CLEARED(거부 때는 오류와 함께). false(사이에 클립보드가 바뀜)면 아무것도 지우지 않는다.

`OpenClipboard` 재시도는 yw-win이 한다(20 ms 간격 5회, [01] §7.3). `ClipError::Busy`·`Os`면 추가 재시도 없이 E-SEC-002.

### 4.8 복사 (설정 토글)
- `allowSecretCopy == false`(기본): W08·W09에 `복사` 버튼이 없고 Ctrl+C에는 T-COPY-OFF.
- `true`: `복사` 버튼과 Ctrl+C. 내용은 W08 = 단어를 공백 하나로 이은 문자열, W09 = 64 hex. `clipboard::set_secret_text`가 한 번의 `OpenClipboard`…`CloseClipboard` 안에서 `CF_UNICODETEXT (13)`(문자열 + NUL)과 `RegisterClipboardFormatW`로 등록한 `"ExcludeClipboardContentFromMonitorProcessing"`·`"CanIncludeInClipboardHistory"`·`"CanUploadToCloudClipboard"`를 각각 DWORD 0으로 넣는다(모니터·기록·클라우드 동기화 제외, D11).
- 같은 `OpenClipboard`…`CloseClipboard` 안에서 등록 형식 `"YourWalletV3SecretClipNonce"`에 복사마다 새 16바이트 난수(`BCryptGenRandom`)를 함께 넣는다. 반환된 `SecretClip`(그 nonce)을 `App.secret_clip = Some((clip, now))`에 둔다. `SECRET_CLIPBOARD_TTL_MS = 30_000` 뒤, 그리고 잠금·종료 때 `clear_secret(clip)`: 클립보드를 열어 그 형식에 같은 nonce가 아직 있을 때만 비운다(다른 복사로 바뀌었으면 지우지 않는다). T-COPIED.
- 시퀀스 번호로 판정하지 않는 이유: `CloseClipboard`가 합성 형식(`CF_LOCALE`·`CF_TEXT`·`CF_OEMTEXT`)을 더하며 번호를 다시 올리므로, 닫기 전에 읽은 번호는 자동 삭제 때 결코 같지 않았다(적대적 검토로 확인, yw-win `tests/clipboard_winsta.rs`가 사설 window station에서 실제 클립보드로 시험).
- 한계: 클립보드 전역 메모리는 시스템 소유라 0으로 덮을 수 없다(`EmptyClipboard`는 해제만). 앱이 비정상 종료하면 자동 삭제가 없다.

### 4.9 비활성화·닫기
- 클릭 관통 방지는 §1.8과 같다.
- `WM_ACTIVATEAPP(0)` 또는 다른 프로세스 창으로 가는 `WM_KILLFOCUS`(이식 `recovery_native.rs:1572-1583`): 평문 창(W05, W07–W10)은 내용 영역을 T-MASKED로 가리고 다시 활성화되면 다시 그린다(버퍼 유지). 가림 칸 창은 `보기`만 끈다.
- 닫기(X, Esc, 완료, 시간 초과, 잠금): 모든 `SecretField`를 `clear`, 표시 버퍼 drop(zeroize), `WM_NCDESTROY`에서 `GWLP_USERDATA`를 지운 뒤(yw-win) `WM_YW_CHILD_DONE`.
- W08 `다 적었습니다`는 2초 hold(`BACKUP_ACK_HOLD_MS = 2_000`, 이식 `HoldGate` `recovery_native.rs:78-107`). 포인터가 버튼 밖으로 나가거나 포커스를 잃으면 취소.

### 4.10 시험 (자동)
- SW-1: 이식 `recovery_native.rs:1610-1738` 테스트(2초 hold, 고정 용량 버퍼, 소거, 창 없는 차단 판정, 시간 초과·포커스 잃음) 통과.
- SW-2: `Printable`에 0x1F·0x7F·0xAC00·서로게이트 → 거부, 버퍼 불변. `MnemonicText`에 `"  Abandon  ABOUT "` 단위 입력 → `abandon about `. `PrivateKeyHex`에 `0X…`·중간 `x`·65자 → 거부. `backspace` 뒤 내부 용량의 지운 위치 = 0.
- SW-3: 붙여넣기 `"abandon\r\n abandon\tabout"` → `abandon abandon about`, `"abandon 1"` → 전체 거부, 시퀀스 같음/다름 → 비움/유지. `Printable`: `"  pass word \r\n"` → `"  pass word "`, `" TREZOR "` 그대로(같은 지갑 주소) + T-PASTE-EDGE-SPACE, 탭·앞 줄바꿈·줄바꿈 둘 → 거부. 비밀 복사 → 닫기가 번호를 올려도 `clear_secret`이 비움, 다른 복사 뒤에는 유지.
- SW-4: 차단 목록 22개와 비밀 상태를 붙인 뒤의 `WM_SETTEXT` → 0 반환, 핸들러 미호출. `exclude_from_capture` 실패 모의(설정 실패, 읽기 값 ≠ 0x11 각각) → `Required`(W08·W09)는 창 파괴·`CaptureExclusionFailed`·비밀 버퍼 미전달·E-SEC-001, `Preferred`(W01·W05·W10)는 T-CAPTURE-WARN 배너와 함께 열리고 `보기` 비활성.

## 5. 자동 잠금 (D12)

### 5.1 계기
`pub enum LockReason { Manual, Idle, SessionLock, SessionDisconnect, Suspend, Shutdown }`, `IDLE_CHECK_MS = 1_000`.

| 계기 | 감지 | 사유 |
|---|---|---|
| 수동 | 상단 `잠금`, Ctrl+L | `Manual` |
| 유휴 | 앱 기준 마지막 입력에서 `autoLockMinutes` × 60,000 ms 경과(주 창 1초 타이머) | `Idle` |
| Windows 세션 잠금 | `Msg::SessionLock`(`WM_WTSSESSION_CHANGE (0x2B1)`, wParam `WTS_SESSION_LOCK (0x7)`) | `SessionLock` |
| 사용자 전환·원격 끊김 | `Msg::SessionDisconnect`(`WM_WTSSESSION_CHANGE`, wParam `WTS_CONSOLE_DISCONNECT (0x2)`·`WTS_REMOTE_DISCONNECT (0x4)`) | `SessionDisconnect` |
| 절전·최대 절전 | `Msg::Suspend`(`WM_POWERBROADCAST (0x218)`, wParam `PBT_APMSUSPEND (0x4)`; 숨은 주 창도 최상위 창이라 받는다) | `Suspend` |
| 종료 | §1.5(`Msg::Close`·`EndSession`·`SessionLogoff`) | `Shutdown` |

- **유휴 기준은 앱 기준 입력이다.** `GetLastInputInfo`(시스템 전체)는 쓰지 않는다(다른 프로그램을 쓰는 동안에도 잠겨야 한다). `ui::run_loop` 관찰 콜백이 yw-app 창으로 가는 `WM_KEYDOWN`, `WM_SYSKEYDOWN`, `WM_CHAR`, `WM_LBUTTONDOWN`, `WM_RBUTTONDOWN`, `WM_MBUTTONDOWN`, `WM_MOUSEWHEEL`마다 `last_input = Instant::now()`. 마우스 이동은 세지 않는다.
- 승인 창이나 W08·W09가 열려 있는 동안 유휴 판정을 멈춘다(각 창에 자체 시간 제한이 있다). 닫혀도 `last_input`은 그대로다: 창 안의 입력(승인·거절 클릭, 스크롤)은 이미 입력으로 셌으므로, 사용자가 만지지 않고 만료되거나 저절로 끝난 창(예: 아무도 보지 않은 dApp·WalletConnect 요청)은 지갑을 열어 두지 못하고 닫히는 즉시 잠길 수 있다. 잠금 해제 직후 `last_input = now`.
- vault가 아직 없을 때(`NoVault`, 첫 실행 흐름) 가져오기·생성·개인키로 시작하기 중인 비밀(UI의 비밀번호·복구 단어, 미리보기 뒤 키 작업자가 쥔 비밀번호·니모닉·개인키)이 있으면 같은 유휴 시간 뒤 버린다: 비밀 창을 닫고, UI 버퍼를 지우고, `DiscardImport`·`DiscardKeyStart { keep_password: false }`로 키 작업자 버퍼도 지운 뒤 S01과 정보 띠("오래 입력이 없어 … 지웠습니다").
- 구현 시 확인(Modern Standby): 대상 PC가 S0ix(`powercfg /a`에 "S0 Low Power Idle")면 시작 메뉴 절전에서 데스크톱 앱이 `PBT_APMSUSPEND`를 받지 못할 수 있다. 이때 UI-M3-08 ③의 합격 로그는 `Suspend` 또는 `SessionLock`이다. 둘 다 없으면 yw-win `session`에 `RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE)`을 추가한다([01] §7.6).

### 5.2 잠긴 동안의 요청
- 승인이 필요한 dApp 요청은 기한까지 큐에서 기다리고 W02를 띄운다(§2.5, §3.7). 그 밖의 메서드는 [05] §4.4.
- 잠긴 동안 yw-app은 평문 meta 사본(계정 목록 포함)을 갖지 않는다.

### 5.3 잠금 절차 (UI 스레드, 순서대로)
1. `AppMode::Locked`, `lock_epoch += 1`(§1.2), 유휴 타이머 정지.
2. `KeyQueue.push_front(KeyJob::Lock)`(→ `Vault::lock`: 슬롯 소거·VirtualUnlock, [02] §7.2; 큐의 나머지 작업 `KeyJobError::Locked`). 이어서 `KeyJob::Load`(제어 작업, 취소되지 않음)를 넣어 잠금 뒤의 상태를 다시 읽는다: 잠금 직전에 끝난 `CreateWallet`·`CommitImport`의 결과는 이전 epoch라 버려지지만 vault는 생겼으므로 `Loaded { Locked }`로 S01이 아니라 S07이 된다.
3. 열린 비밀 창(W01–W10)을 모두 닫는다(§4.9). 진행 중인 생성·가져오기 흐름 취소(`DiscardImport`).
4. `secret_clip`이 있으면 `clear_if_unchanged`.
5. 표시 중인 승인 창을 닫고 `Rejected`. 대기 항목은 남긴다(§3.7). [03] `ApprovalStore::invalidate_all`.
6. 평문 meta 사본(라벨, 주소록, 연결 기록, 잔액 캐시)을 drop하고 화면을 S07로.
7. [05]에 잠금을 알린다(`AppEvent::Locked` → `accountsChanged([])`, [05] §4.8).
8. 로그 `lock reason=<LockReason>`.

- `Suspend`: 2단계 뒤 UI 스레드가 키 작업자의 `LockDone`을 최대 1.5초 기다린다(진행 중 작업이 Argon2면 그 안에 끝나지 않을 수 있다. 구현 시 확인: 대상 PC의 Argon2 1회 시간, [02] §7.4). 잔여 위험(결정): Argon2 작업(최대 2회, 비밀번호 변경) 도중 최대 절전에 들어가면 DEK 슬롯이 소거되기 전에 hiberfil에 기록될 수 있다. 이는 spec.md §2.2 비목표의 최대 절전 파일(hiberfil.sys)·페이지 파일 잔여 위험(VirtualLock은 최대 절전을 막지 못한다)으로 보고 BitLocker(spec.md §2.4)로 완화하며, 다른 스레드에서 슬롯을 지우는 경로는 만들지 않는다.
- 잠긴 동안 저널 커밋은 없다(DEK 필요, D10). 진행 중이던 `eth_sendRawTransaction`(그리고 [07]·[08]의 전송) 호출은 끝까지 기다리되 결과 상태는 메모리에만 두고, 영수증 폴링은 멈춘다. 잠금 해제 직후 [03] §5.4 reconcile이 상태를 확정한다([03] §4.5와 같음).

### 5.4 시험
- LK-1: 모의 시계로 유휴 = 설정 분 − 1초 → 잠기지 않음, + 0초 → 잠김. 다른 앱 입력만 계속 → 잠김. 승인 창(A01, 모든 체인: 표시 중인 승인 항목)이 열린 채 설정 분 경과 → 잠기지 않음; 사용자가 답해 닫으면 그 입력부터 다시 셈, 입력 없이 만료돼 닫히면 바로 잠김.
- LK-2: `Lock` 전에 큐에 있던 `KeyJob` → `KeyJobError::Locked`. 진행 중 작업 뒤 바로 `Lock` 처리(다른 작업보다 먼저). `Lock` 직전에 끝난 `Unlock`·`Reveal` 결과(이전 `lock_epoch`) → UI가 버리고 `Locked` 유지·버퍼 소거. 소비된 서명 항목의 `Sign`이 `Locked` → dApp 4001, 송신 슬롯 해제, 저널 레코드 없음.
- LK-3: 주 창 핸들러에 `Msg::SessionDisconnect` → 잠금 `SessionDisconnect`. `Msg::SessionLogoff`·`Msg::EndSession` → §1.5 종료 절차(`LockReason::Shutdown`). `Msg::QueryEndSession` → `Reply::Handled(1)`, 상태 변화 없음.

## 6. 설정

### 6.1 settings.json
평문이며 비밀이 없다(키는 §6.3). 최대 64 KiB, yw-json 엄격 파서(중복 키 거부), 키 순서가 고정된 yw-json 직렬화로 쓴다.
```json
{
  "version": 1,
  "autoLockMinutes": 10,
  "allowSecretCopy": false,
  "allowLocalhostDapps": false,
  "browserAutoLaunch": true,
  "evmChainId": 11155111,
  "evmChains": [],
  "evmGenesisPins": {},
  "feeCaps": {
    "eip155:1":        { "maxFeePerGasGwei": "200",  "maxPriorityFeePerGasGwei": "5",   "maxTotalFee": "0.05" },
    "eip155:11155111": { "maxFeePerGasGwei": "1000", "maxPriorityFeePerGasGwei": "100", "maxTotalFee": "1" }
  },
  "rpc": { "template": "quicknode" },
  "solana": { "max_fee_lamports": 100000, "max_cu_price_micro": 1000000, "cluster": "mainnet" },
  "bitcoin": { "enabled": false, "network": "mainnet", "indexer": "esplora",
               "esploraBaseUrl": { "mainnet": "https://mempool.space/api", "testnet4": "https://mempool.space/testnet4/api" } },
  "llm_explain": { "enabled": false, "endpoint": "", "model": "", "response_format": "json_schema", "max_tokens": 0, "privacy_notice_version": 0 },
  "hypercore": { "enabled": true, "network": "mainnet", "testnetApi": "https://api.hyperliquid-testnet.xyz" },
  "logLevel": "info"
}
```

| 키 | 타입 | 기본값 | 규칙 |
|---|---|---|---|
| `version` | integer | 1 | 이 형식의 주 버전(`SETTINGS_VERSION = 1`). 1보다 큰 정수 = 더 새로운 앱의 파일 → 읽기 전용(§6.6). 그 밖(0, 음수, 정수 아님, 없음) → 파일 전체 무효(yw-host도 이 키를 읽는다, 아래 `browserAutoLaunch`) |
| `autoLockMinutes` | integer | 10 | 1–60 (D12) |
| `allowSecretCopy` | bool | false | §4.8 |
| `allowLocalhostDapps` | bool | false | D22, [05] §4.6 |
| `browserAutoLaunch` | bool | true | D24. yw-host는 `settings.json`에서 `version`과 이 키만 읽고 쓰지 않는다(spec.md §4.1, [05] §7.4). yw-host 판정: 루트 객체·`version == 1`·bool 값이면 그 값, 그 밖(파일 없음, 읽기·크기·파싱 오류, `version ≠ 1`, 키 없음·bool 아님)은 true |
| `evmChainId` | integer | 11155111 | 기본 체인 1·11155111·999·42161·8453·56·4663 또는 `evmChains`에 있는 chainId(D14). 활성 EVM 체인(D30, §2.6). `evmChains` 다음에 검증한다 |
| `evmChains` | array | `[]` | 사용자 EVM 체인(§2.17), 0..=32개(`MAX_CUSTOM_EVM_CHAINS`), 배열 순서 = 표시 순서. 항목 `EvmChainDef`(아래) |
| `evmGenesisPins` | object | `{}` | 최초 신뢰로 고정한 기본 체인 제네시스(§1.9). 키는 [03] §1.1에서 제네시스 상수가 없는 기본 체인의 `NetworkId`(현재 `"eip155:999"`만), 값 `Hash32`. 없으면 첫 연결 때 고정 |
| `feeCaps` | object | 위 값(= [03] §1.1 `default_caps`) | 키는 기본 체인 또는 `evmChains`에 있는 체인의 `NetworkId`(`eip155:<chainId>`). 없는 체인은 기본값(기본 체인 [03] §1.1 `default_caps`, 사용자 체인 [03] §3.4 보수적 기본값). `maxFeePerGasGwei` 1–10,000, `maxPriorityFeePerGasGwei` 0.01–10,000이고 ≤ maxFee 상한, `maxTotalFee`(네이티브 단위) 0.0001–10([03] §3.4-7). 값은 10진 문자열(gwei 소수 ≤ 9자리, 네이티브 ≤ 그 체인 소수 자릿수, [03] `parse_units`) |
| `rpc` | object | `{"template": "quicknode"}` | `template` = `"quicknode"`·`"alchemy"`·`"manual"`(S15 `RPC 공급자` 라디오, §2.11.1 `RpcTemplate`). 입력 편의(URL 생성·S17 식별자 해석)에만 쓰고 런타임 엔드포인트에는 영향이 없다(§1.9). 다른 키나 다른 값 → `rpc` 객체 단위 기본값. 템플릿 자격 정보와 네트워크별 URL은 토큰이 들어 있으므로 여기 두지 않고 §6.3 `tpl:*`·`rpc:<NetworkId>`에 둔다(D13) |
| `solana` | object | [07] §10 | M7부터. 키·범위·기본값은 [07] §10 |
| `bitcoin` | object | 위 값 | M8부터, 의미는 [08] §2 소유. `enabled` bool. `network` = `"mainnet"`·`"testnet4"`(D26·D30), 바꾸기는 진행 중 BTC 저널 항목이 없을 때만. `indexer` = `"esplora"`(기본: `esploraBaseUrl`의 Esplora REST GET, 무료·키 없음)·`"bb-rpc"`(Core 엔드포인트 URL에 Blockbook `bb_*` JSON-RPC POST, QuickNode BTC Blockbook 유료 애드온)·`"bb-rest"`(`<Core URL>/api/v2/` Blockbook REST GET, 알케미 UTXO API)([08] §2·§4.3), 언제든 변경 가능. `esploraBaseUrl` = 아래 `EsploraBaseUrls`(비밀이 아니므로 여기 둔다; 토큰이 든 Core URL은 §6.3). `enabled`·`network`·`indexer`가 없거나 틀리거나 네 키 밖의 키가 있으면 `bitcoin` 객체 단위 기본값(`esploraBaseUrl` 포함). `esploraBaseUrl`은 아래 규칙으로 키 단위 검증 |
| `zcash` | object | `{"enabled": false, "network": "mainnet", "indexer": "node"}` | D36, 의미는 [12](12-zcash.md) §2.1 소유. `network` = `"mainnet"`·`"testnet"`, `indexer` = `"node"`(같은 엔드포인트의 `getaddressutxos`)·`"bb-rest"`(같은 엔드포인트의 Blockbook REST). 모르는 하위 키·형식 오류는 객체 전체를 기본값으로(배너 E-APP-001). 끄기·네트워크 바꾸기는 진행 중 ZEC 저널 항목이 없을 때만 |
| `llm_explain` | object | [06] §2.1 | 검증·되돌림은 [06] §2.1 |
| `hypercore` | object | `enabled` bool(기본 true), `network` `mainnet`\|`testnet`(기본 mainnet), `testnetApi` HTTPS ≤ 256바이트·`?`/`#` 없음·끝 `/` 제거(기본 공식 주소). 메인넷 API는 고정([11] §8) | 키 하나라도 틀리면 객체 전체 기본값 + 배너 |
| `logLevel` | string | `"info"` | `error`·`warn`·`info`·`debug` |

```
EvmChainDef = { "chainId": u64, "name": Label, "symbol": string, "decimals": u8,
                "quicknodeSubdomain"?: string, "alchemyLabel"?: string, "explorer"?: string,
                "simulation": "auto" | "unsupported", "genesisHash": Hash32 }      // 직렬화 키 순서 = 이 순서, 없는 선택 키는 생략
Hash32 = "0x" + 소문자 hex 64자
```
- `chainId`: JSON 정수(yw-json `as_u64`), 1..=9,223,372,036,854,775,771(EIP-2294), 기본 체인 id가 아니고 배열 안에서 유일. `name`: [02] `Label` + §3.3 표시 금지 문자 없음, 기본 체인 이름·다른 항목 이름과 다름(ASCII 대소문자 무시). `symbol`: `^[A-Za-z0-9]{1,11}$`. `decimals`: 0..=36. `quicknodeSubdomain`·`alchemyLabel`: 각각 `^[a-z0-9]+(-[a-z0-9]+)*$` 1–63자, 공급자 템플릿 식별자(§2.11.1 `template_url`의 `entry`; [03] §1.1 `templates`와 같은 역할). URL 생성에만 쓰고 런타임 엔드포인트는 `rpc:eip155:<chainId>`뿐이다(§1.9). `explorer`: `HttpsUrl::parse` 통과, ≤ 256바이트, `?`·`#`·끝 `/` 없음. `genesisHash`: 추가 때 고정한 블록 0 해시(§2.17.2). 그 밖 키 → 그 항목 무효.
- 이 체인의 `NetworkId`는 `eip155:<chainId>`(10진, [03] §1)이고 meta `tokens`·`activity`, `feeCaps`, `apikeys.dpapi` `rpc:*`가 이 키를 쓴다. RPC URL은 여기 두지 않는다(§6.3 `rpc:eip155:<chainId>`).

```
EsploraBaseUrls = { "mainnet": EsploraBaseUrl, "testnet4": EsploraBaseUrl }   // 직렬화는 항상 두 키, 이 순서
```
- `EsploraBaseUrl`([08] §2): `HttpsUrl::parse` 통과([01] §7.4: https만, userinfo·fragment 거부, 호스트 소문자화, 포트 선택), 전체 ≤ 256바이트, `?`·`#` 없음, 끝 `/` 없음(경로가 없으면 호스트[:포트]로 끝난다). 경로는 비었거나 `/`로 구분된 세그먼트 1개 이상이고 세그먼트마다 `^[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,63}$`(`.`·`..`·퍼센트 인코딩 없음). 호스트가 `quiknode.pro`·`g.alchemy.com`이거나 그 하위 도메인이면 거부한다(토큰이 든 공급자 URL을 평문 settings.json에 두지 않는다, D13). 저장 값은 파싱 후 정규형(소문자 호스트). 화면 `저장` 위반은 E-BTC-006. 기본값 `https://mempool.space/api` / `https://mempool.space/testnet4/api`([08] §15).
- `esploraBaseUrl` 검증: 키가 없으면 두 네트워크 모두 기본값(배너 없음). 객체가 아니면 기본값 + 배너 `bitcoin.esploraBaseUrl`. 키는 `mainnet`·`testnet4`만(모르는 키는 무시 + 배너), 빠진 키는 그 네트워크 기본값(배너 없음), 형식 위반 값은 그 키만 기본값 + 배너 `bitcoin.esploraBaseUrl.<net>`. 이 키 단위 되돌림은 `enabled`·`network`·`indexer`에 영향을 주지 않는다.

### 6.2 읽기·검증·쓰기
- 파일 없음: 모두 기본값. 첫 변경 때 만든다.
- 64 KiB 초과, JSON 오류, 중복 키, 루트가 객체가 아님, `version`이 정수가 아니거나 0·없음: 전체를 기본값으로 쓰고 배너 E-APP-001(`settings.json`). 파일은 그대로 두고 다음 변경 때 덮어쓴다.
- `version` > 1(더 새로운 앱의 파일): 읽기 전용(§6.6). 값은 모두 기본값, 배너 E-APP-001에 "settings.json은 더 새로운 버전(n)의 앱이 쓴 파일입니다 — 읽기 전용으로 열었고 이번 실행의 설정 변경은 저장되지 않습니다. 앱을 최신 버전으로 업데이트하세요". 이번 실행의 변경은 메모리에만 적용하고 파일 내용은 바꾸지 않는다(쓰기는 읽은 바이트를 그대로 다시 쓴다).
- 최상위 키마다 따로 검증한다. 틀린 키는 그 키만 기본값이고 배너에 키 이름을 보인다. 객체 값(`feeCaps`의 네트워크 항목, `rpc`, `solana`, `bitcoin`, `llm_explain`)은 그 객체 단위로 되돌린다(예외: `bitcoin.esploraBaseUrl`은 네트워크 키 단위, §6.1). 모르는 최상위 키는 새 부 버전의 키로 보고 배너 없이 보존해 다음 쓰기에서 알려진 키 뒤에 읽은 순서대로 다시 쓴다(§6.6). 모르는 `feeCaps` 네트워크 키는 무시하고 배너에 보이며 다음 쓰기에서 사라진다.
- 검증 순서: `evmChains` → `evmChainId`·`evmGenesisPins`·`feeCaps`(등록된 체인 집합에 의존). `evmChains`는 항목 단위다: 무효 항목, 기본 체인·앞 항목과 chainId 또는 이름이 겹치는 항목, 33번째부터는 버리고 배너 "evmChains[i]"(배열이 아니면 전체 `[]`). 예외: 2026-11-06에 기본 체인이 된 id(42161·8453·56·4663)의 항목은 배너 없이 버린다 — 기본 체인이 그 id를 이어받고 `rpc:eip155:<id>` URL·`feeCaps`는 그대로 쓰인다(다음 저장 때 항목이 파일에서 빠진다). 스냅샷(§6.7)의 그 체인 고정 제네시스는 상수 제네시스가 대신하므로 되돌리지 않는다. 버린 체인의 `feeCaps`·`rpc:*` 항목은 고아로 무시된다. `evmGenesisPins`는 키 단위(모르는 키·형식 오류는 그 키만 버림).
- 쓰기: 메모리의 전체 설정을 직렬화해 §9 원자적 쓰기(알려진 키는 §6.1 순서, 그 뒤 보존한 모르는 최상위 키). 검증을 통과한 값만 메모리에 들어간다.
- 무결성: 평문 파일이라 앱 밖에서 바뀔 수 있다. 보안 관련 값은 잠금 해제 뒤 meta의 스냅샷과 대조한다(§6.7). `settings.json`·`apikeys.dpapi`가 재분석 지점이면 읽지 않는다(파일 전체 무효와 같음).
- 반영: `autoLockMinutes` 다음 판정부터, `allowLocalhostDapps` [05]의 다음 요청부터, `browserAutoLaunch` yw-host의 다음 실행 판단부터, `evmChainId` 즉시(S10 새로고침), `evmChains`·`evmGenesisPins` 즉시(새 `RpcConfig`, 그 체인 확인 상태 초기화, §1.9), `feeCaps` 다음 준비부터, `rpc.template` 즉시(S15·S17 입력 해석만), `bitcoin.indexer`·`bitcoin.esploraBaseUrl` 즉시(새 `RpcConfig`, [08] §2 연결 검사 다시), `logLevel` 다음 줄부터.

### 6.3 apikeys.dpapi
- 파일 = `CryptProtectData` 출력 그대로. `pOptionalEntropy` = ASCII `your-wallet/v3/apikeys`(22바이트), `szDataDescr` = NULL, `pPromptStruct` = NULL, 플래그 `CRYPTPROTECT_UI_FORBIDDEN (0x1)`(`CRYPTPROTECT_LOCAL_MACHINE` 없음 → 현재 사용자, D13). 복호화도 같은 entropy·플래그.
- 평문(최대 131,072바이트):
```
offset 0   magic       8 bytes  "YWAPIK01"
offset 8   count       u8       0..=48
반복 count번:
           name_len    u8       1..=32
           name        ASCII    "rpc:" NetworkId | "tpl:quicknode" | "tpl:alchemy" | "llm"   (같은 이름 두 번 금지, 그 밖 이름은 아래 이름 형식 규칙: 모르는 이름은 보존, §6.6)
                                NetworkId = "eip155:" <chainId 10진, 앞자리 0 없음>   // 기본 1·11155111·999 + settings evmChains
                                          | "solana:mainnet" | "solana:devnet" | "bitcoin:mainnet" | "bitcoin:testnet4"
           value_len   u16 BE   1..=2048
           value       bytes    rpc:*: 그 네트워크의 엔드포인트 URL 전체(토큰 포함), yw-win `HttpsUrl::parse` 통과(https만, ≤ 2048바이트, [01] §7.4, D13)
                                / tpl:quicknode: <이름> ":" <토큰>  (이름 ^[a-z0-9]+(-[a-z0-9]+)*$ 1–63, 토큰 ^[A-Za-z0-9_-]{16,128}$, §2.11)
                                / tpl:alchemy: ^[A-Za-z0-9_-]{16,128}$ (§2.11)
                                / llm: 0x21–0x7E 1–512자([06] §2.1)
                                / llm:host: 키를 저장할 때의 LLM 엔드포인트 소문자 host[:port], 1–300바이트 [a-z0-9.:_\[\]-] (키를 이 호스트에만 보낸다, [06] §2.1; 이전 버전은 모르는 이름으로 보존)
끝: 남는 바이트 없음
```
- 상한 근거: `tpl:*` 2 + `llm` 1 + EVM 기본 3 + 사용자 체인 32 + SOL 2 + BTC 2 = 42 ≤ 48개, 42 × (1 + 32 + 2 + 2048) < 131,072. 가장 긴 이름 `rpc:eip155:9223372036854775771` = 30바이트 ≤ 32.
- 런타임 엔드포인트는 `rpc:*`뿐이다(§1.9). `tpl:*`는 나중에 추가한 체인이나 토큰 교체 때 URL을 다시 만들기 위한 템플릿 자격 정보이고(§2.11.1) 런타임 호출에 쓰지 않는다.
- `settings.json`을 먼저 읽는다(§1.4-5). `rpc:eip155:<chainId>` 중 기본 체인도 `evmChains`에도 없는 것은 고아 항목이다: 엔드포인트로 쓰지 않고(`RpcConfig`에 없음) 로그 `apikeys.orphan`(이름만)을 남기며, 보존해 저장 때마다 그대로 다시 쓴다(§6.6). 같은 chainId 체인이 다시 등록되면(다음 실행, 또는 그 체인의 URL을 새로 저장) 다시 쓰인다. 사용자가 그 항목을 지우는 동작(`ApiKeys::remove`·`prune_dormant` = S15 `보관 항목 삭제`, §2.11)만 지운다.
- 이름 형식: `^[a-z0-9][a-z0-9:._-]*$` 1–32바이트. 이 버전이 아는 이름(위 표)은 값까지 검증한다. 형식에 맞지만 모르는 이름(예 `tpl:infura`, `rpc:solana:testnet`)은 새 버전의 항목으로 보고 값 바이트(1–2,048)를 해석하지 않은 채 보존해 다시 쓴다(§6.6). 아는 계열의 잘못된 이름(`rpc:eip155:01`처럼 정규형이 아닌 chainId, `rpc:`)과 형식 밖 이름(대문자·공백)은 형식 오류다.
- 복호화 결과(`WipeBuf<u8>`)는 바로 파싱해 `Zeroizing` 값으로 옮긴다. UI 스레드가 모든 항목을 소유하고(저장 때 평문을 다시 만들기 위해), `rpc:*` URL만 `RpcConfig`(§1.9)로 RPC·read 작업자에 복사해 종료 때까지 보관한다(D10: RPC URL·API 키는 지갑 비밀이 아니다). `tpl:*`는 작업자에 보내지 않는다. LLM 키는 [06](기능이 꺼져 있으면 복호화하지 않음).
- 형식 오류·복호화 실패(다른 사용자·다른 PC): E-KEY-001, 모든 항목 없음으로 취급(엔드포인트 없음). 다음 저장 때 덮어쓴다.
- 저장: 메모리의 항목(쓰는 항목 다음에 보존한 고아·모르는 항목, 합계 48개 안에서; 넘치면 보존 항목을 뒤에서부터 뺀다)으로 평문을 새로 만들어 `protect` → §9 원자적 쓰기. 모두 지우면 `count = 0`.
- URL 전체가 비밀이다(D13): 경로에 토큰·키가 있고, 호스트에도 QuickNode 엔드포인트 이름이 있다. URL·호스트·토큰·템플릿 자격 정보를 로그·문구·화면에 쓰지 않는다. 로그는 항목 이름(`rpc:<NetworkId>`·`tpl:*`)만, 화면은 §2.11.1 가린 형태만 쓴다.

### 6.4 meta `prefs`
[02] §5.3 meta의 `prefs` 객체(이 문서 소유). 네트워크 선택은 여기 두지 않는다(`settings.json`, D30). 모르는 키나 형식 오류는 `prefs` 전체를 기본값으로 되돌리고 로그를 남긴다. `alt_passphrase` 세션에서는 메모리에만 둔다.

| 키 | 타입 | 기본값 | 규칙 |
|---|---|---|---|
| `evm_account` | object | `{"index":0}` | `{"index": u32}`(meta `evm_accounts`에 있음) 또는 `{"record_id": Hex16}`(`evm_raw_accounts`에 있음) |
| `sol_account` | integer | 0 | meta `sol_accounts`의 `index`(M7) |
| `tab` | string | `"evm"` | `"evm"`·`"sol"`·`"btc"`·`"zec"`(구현된 것만; 이전 버전은 `"zec"`을 모르는 값으로 보고 `prefs`를 기본값으로 되돌린다) |

BTC 계정 선택은 `prefs`에 두지 않는다(알려진 객체에 키를 더하면 이전 버전이 `prefs`를 버린다, §6.6). 선택한 BTC 계정은 새 최상위 키 `btc_accounts.selected`에 둔다([08] §12.3a, D26).

### 6.5 시험 (자동)
- ST-1(`settings.json`): `evmChains` 33개 → 32개 + 배너. chainId 999·중복 chainId·이름 "sepolia 테스트넷"(대소문자만 다름)·`decimals` 37·`simulation` `"off"`·대문자 `genesisHash`·`explorer`에 `?` → 그 항목만 버림. `evmChainId` = 버린 체인 → 11155111 + 배너. `feeCaps["eip155:<버린 id>"]` → 무시. `evmGenesisPins["eip155:1"]` → 그 키만 버림. 모르는 키(예 `rpcUrl`)가 있는 항목·`quicknodeSubdomain` `"Base_Sepolia"` → 그 항목만 버림. 모르는 최상위 키(`rpcUrl`) → 배너 없음, 보존(쓰기 끝에 그대로). `version` 0·`"2"`·-1·1.5 → 파일 전체 무효. `rpc.template` `"infura"`·`rpc.provider` 키 → `rpc` 기본값 + 배너. `bitcoin.indexer` `"blockbook"` → `bitcoin` 객체 기본값(`"esplora"`, mempool.space URL 2개) + 배너. `bitcoin`에 `esploraBaseUrl` 없음 → 기본 URL, 배너 없음. `esploraBaseUrl.mainnet`이 `http://mempool.space/api`·`https://mempool.space/api/`·`https://mempool.space/api?x=1`·`https://u@mempool.space/api`·`https://mempool.space/api/../x`·`https://mempool.space/a%20b`·`https://x.btc.quiknode.pro/tok`·`https://bitcoin-mainnet.g.alchemy.com/v2/k`·257바이트 → 그 키만 기본값 + 배너 `bitcoin.esploraBaseUrl.mainnet`, `enabled`·`network`·`indexer`·`testnet4` 값은 유지. `https://MEMPOOL.space/api` → `https://mempool.space/api`로 정규화. `https://blockstream.info/testnet4/api`·`https://esplora.example.com:3002` 통과. `esploraBaseUrl.signet` 키 → 무시 + 배너. 왕복 직렬화 → 키 순서 고정(`esploraBaseUrl`은 항상 두 키), 바이트 동일.
- ST-2(`apikeys.dpapi` 평문): 42개 항목(`tpl:*` 2, `llm`, `rpc:*` 39)·각 `rpc:*` 2,048바이트 URL 왕복. `count` 49, 같은 이름 2개, `rpc:eip155:01`·`rpc:eip155:abc`·`rpc:`, 이름 33바이트, `TPL:infura`·`tpl infura`, `tpl:quicknode` 값에 `:` 없음·대문자 이름·토큰 15자, 고아 `rpc:*` 값이 `http://` → 형식 오류(E-KEY-001, 모든 항목 없음). 등록 안 된 `rpc:eip155:8453` → 엔드포인트 아님, 다음 저장에도 그대로(등록하면 다시 쓰임, URL을 새로 저장하면 교체, `remove`·`prune_dormant`로만 지움). 모르는 이름 `tpl:infura`·`rpc:solana:testnet`(UTF-8 아닌 값 포함) → 보존, 평문 바이트 동일 왕복. 쓰는 항목 48개 + 보존 항목 → 보존 항목을 빼고 `count` 48. `RpcConfig.endpoints`에 `tpl:*` 값이 없음. S15 `QuickNode` 입력 도우미(`quicknode_credentials`): 엔드포인트 이름 칸이나 토큰 칸에 붙인 `https://<이름>[.<서브도메인>].quiknode.pro/<토큰>/[경로]`(`wss://` 포함, 앞뒤 공백 무시) → 이름(소문자)·토큰, 다른 칸이 비었거나 같은 URL·같은 값이면 통과, 다르면 그 칸 E-KEY-002. 포트·라벨 3개 이상·토큰 15자·`http://`·알케미 URL → URL로 보지 않음.
- ST-3(S17 입력 판정, 순수 함수): chainId `0`·`01`·9,223,372,036,854,775,772 → E-CHN-004, 11155111 → E-CHN-003. RPC 칸(시험용 가짜 자격 정보): `rpc.template = "quicknode"` + `tpl:quicknode` 있음, `Base-Sepolia` → `quicknodeSubdomain` `base-sepolia`, URL `https://<이름>.base-sepolia.quiknode.pro/<토큰>/`; `rpc.template = "alchemy"` + `tpl:alchemy` 있음, `Base-Sepolia.g.alchemy.com` → `alchemyLabel` `base-sepolia`, URL `https://base-sepolia.g.alchemy.com/v2/<KEY>`; 그 템플릿 자격 정보 없음 → E-KEY-004; `rpc.template = "manual"` + `base-sepolia` → E-KEY-003; `base.sepolia` → E-CHN-004; `http://x` → E-KEY-003. 모의 RPC: chainId 응답 `0x2105` ≠ 입력 8452 → E-CHN-001, 블록 0 `hash` 31바이트 → E-CHN-002 + E-RPC-005, 편집 중 해시 ≠ 고정값 → E-CHN-008·저장 없음. 삭제: 활성 체인 → E-CHN-009, 미종결 저널 레코드 → E-CHN-007.
- ST-4(§2.11.1 엔드포인트, 순수 함수 + 모의 RPC, 시험용 가짜 이름·토큰·키): `template_url` QuickNode `eip155:1`(서브도메인 없음) → `https://<이름>.quiknode.pro/<토큰>/`, `eip155:11155111` → `https://<이름>.<[03] 서브도메인>.quiknode.pro/<토큰>/`, 알케미 `solana:devnet` → `https://<[07] 라벨>.g.alchemy.com/v2/<KEY>`, 항목 없는 네트워크·`Manual` → `None`(생성 대상에서 빠지고 T-RPC-GENERATED의 건너뜀 목록에 나옴). `기존 URL 덮어쓰기` 끔 → 기존 `rpc:*` 바이트 동일, 켬 → 교체. 사용자 체인 생성 URL의 chainId 불일치 → 그 체인만 쓰지 않음. `mask_url` 결과에 이름·서브도메인·라벨·토큰·키 부분 문자열이 없음. 엔드포인트 없는 네트워크 → 호출 0회, E-KEY-005(EVM 준비 `Failed`, `retryable == false`). `테스트`: EVM `eth_chainId` `0x2105` (기대 1) → E-RPC-010, SOL 다른 genesis → E-RPC-010, BTC `chain` `"test"` → E-RPC-010, HTTP 401 → E-RPC-003. Bitcoin `Esplora URL` `테스트`(모의 서버): testnet4 줄에 testnet4 제네시스 → T-BTC-IDX-OK, mainnet·testnet3 제네시스 → E-BTC-003, 404·본문 끝 `\n` → E-BTC-004, 500 → E-BTC-001, 요청 경로는 `/block-height/0`뿐(주소 없음). 위 모든 경우 로그 줄에 URL·호스트·토큰이 없고 `net=<NetworkId>`만 있음.
- ST-5(§6.6 형식 호환, `tests/compat.rs`, 고정 파일 `tests/fixtures/compat/`): 이전 릴리스의 `settings-v1.json`(공백·줄바꿈 있음) → 배너 없음, 값 그대로, 왕복 바이트 동일. 새 부 버전 `settings-v1-newer-minor.json`(모르는 최상위 키 `uiTheme`·`addressLabels`) → 배너 없음, 값을 바꿔 저장하면 알려진 키 다음에 두 키가 읽은 순서·값 그대로. 새 주 버전 `settings-v2.json` → 배너(읽기 전용), 기본값, 값을 바꿔도 `to_json`이 원본 바이트와 같음. 모르는 키 60,000바이트 + 사용자 체인 32개 → 64 KiB 안에 맞추려고 모르는 키를 빼고 배너 없이 다시 읽힘. 새 부 버전 meta `meta-v3-newer-minor.json`(`watch_only`·`ui_layout`) → 열림, 계정 이름을 바꿔 저장하면 두 키가 끝에 그대로, `yw-meta/4` → 형식 오류. 업그레이드 시나리오: v2 settings(사용자 체인 안 보임)로 읽은 `rpc:eip155:84532`가 다른 저장을 거쳐도 남고 v1 settings로 다시 읽으면 엔드포인트로 돌아옴.

### 6.6 형식 호환 (업그레이드·이전 버전으로 되돌리기)
데이터 폴더 `v3`의 파일을 여러 앱 버전이 번갈아 읽고 쓸 수 있으므로 다음 규칙을 지킨다. 목적: 한 버전이 다른 버전의 데이터를 지우거나 덮어써 잃지 않는다.

| 파일 | 버전 표시 | 같은 주 버전의 새 부 버전 (읽는 쪽이 모르는 내용) | 더 새로운 주 버전 | 더 오래된 주 버전 |
|---|---|---|---|---|
| `settings.json` | `version` 정수(현재 1) | 모르는 **최상위 키**: 배너 없이 보존, 쓰기 때 알려진 키 뒤에 읽은 순서·값 그대로 | `version` > 1: 읽기 전용(값은 기본값, 배너 E-APP-001, 이번 실행의 변경은 메모리에만, 파일 내용 불변) | 알려진 이전 버전은 읽을 때 메모리에서 이행하고 다음 쓰기에 현재 버전으로 쓴다. 현재 1이 첫 버전이므로 이행할 이전 버전은 없고 0·정수 아님은 손상(§6.2) |
| `meta.ywm` 평문 | `schema` = `"yw-meta/3"` | 모르는 **최상위 키**: 보존, 쓰기 때 알려진 키 뒤에 그대로([02] §5.3). 2026-10-29에 선택 최상위 키 `sol_raw_accounts`·`sol_raw_selected`·`btc_accounts`를 더했다(이전 버전은 보존만 한다; 가져온 Bitcoin 키는 `btc_accounts`의 계정). 2026-11-03에 `token_view`(토큰 행 숨김, §2.6)를 같은 방식으로 더했다. 2026-11-07에 `btc_accounts_ext`([08] §12.3b)를 더했다(아래 행) | 없음: `schema`는 데이터 폴더 `v3`과 함께만 바뀐다(다른 `schema`는 형식 오류, E-VLT-006) | 없음(v1·v2는 이행하지 않음, D7) |
| `meta.ywm` Bitcoin 계정 (2026-11-05/06 빌드, 고침 2026-11-07) | (`schema` 그대로) | 그 빌드는 HD 모드 표시 `single_address`를 `btc`·`btc_accounts` 계정 객체 **안에**, EVM·YubiKey 키 Bitcoin 계정(`key.evm`·`key.yubikey`)과 그 선택을 `btc_accounts` **안에** 써서, 그 전 빌드가 meta 전체를 E-VLT-006으로 거부했다. 이 버전은 그것을 새 최상위 키 `btc_accounts_ext`로 옮겨 쓰고 이전 배치도 읽는다(다음 meta 저장에서 이행). **되돌리기 안내**: 이전 빌드로 되돌렸다가 meta 오류(E-VLT-006)를 봤다면 `.prev` 복구나 "meta 새로 시작"을 하지 않는다(최근 계정·라벨·설정이 사라진다). 새 버전을 다시 설치해 잠금 해제하고 meta가 저장되게 한 번 바꾼 뒤(계정 라벨·선택 등) 되돌린다. 그래도 이전 빌드에서는 EVM·YubiKey 키 Bitcoin 계정이 보이지 않는다(보존만) | — | — |
| `vault.ywv` payload | `payload_magic` `YWPAY003` | 2026-10-29 확장(가져온 개인키, [02] §4.6): `tag 3`·`tag 4` record, `Bip39` 없는 키 전용 payload, `payload_ct_len` 상한 4,096. `tag 1`·`tag 2` 배치는 그대로라 이 버전은 이전 vault를 그대로 연다. 이전 버전은 확장된 vault를 E-VLT-008(또는 E-VLT-002)로 본다: 이전 버전으로 되돌렸다면 `.prev` 복구를 하지 말고 새 버전을 다시 설치한다(복구하면 마지막 가져오기가 사라진다, 손상으로 본 파일은 격리 보존). 이 버전부터 인증된 payload의 모르는 tag는 E-VLT-014(`UnsupportedPayload`, `.prev` 제안 없음)다. 앞으로 tag를 더하는 버전은 이 경로를 따른다([02] §4.6 형식 확장 규칙) | — | — |
| `vault.ywv` payload (복구 단어 여러 개, 2026-11-07) | (`payload_magic` 그대로) | `tag 1` record 2–8개([02] §4.6, D37). 이전 빌드는 두 번째 `tag 1`에서 E-VLT-014(`UnsupportedPayload`, `.prev` 제안 없음)로 멈추고 파일을 그대로 둔다(되돌린 경우 새 버전을 다시 설치하거나, 새 버전에서 추가한 복구 단어를 모두 지우면 이전 빌드가 다시 연다). meta 선택 키 `mnemonics`와 prefs `{"mnemonic", "index"}`는 이전 빌드가 각각 보존·기본값으로 되돌린다. 니모닉이 하나인 vault·meta는 바뀌지 않는다 | — | — |
| `meta.ywm` 추가한 복구 단어의 Solana·Bitcoin·Zcash 계정 (2026-11-08) | (`schema` 그대로) | 새 선택 최상위 키 `mnemonic_accounts`(Solana 계정과 선택, Zcash 계정, [02] §5.3)와 `btc_accounts_mn`(Bitcoin HD 계정과 선택, [08] §12.3c)에만 쓴다. `sol_accounts`·`prefs`·`btc`·`btc_accounts`·`btc_accounts_ext`·`zcash`·`mnemonics`에는 새 멤버·값을 넣지 않는다(이전 빌드가 엄격하게 읽거나 그 항목을 버림). 그런 계정을 선택해 둔 채 이전 빌드(복구 단어 여러 개를 여는 2026-11-07 빌드)로 열면 그 빌드는 두 키를 보존만 하고 주 니모닉 계정을 보인다(Zcash는 그 네트워크의 표준 계정을 다시 만든다). 새 빌드로 돌아오면 `mnemonic_accounts.zec`가 그 네트워크 계정으로 다시 쓰인다 | — | — |
| `journal.ywj` 추가한 복구 단어의 기록 (2026-11-08) | (magic 그대로) | 추가한 니모닉 계정의 기록만 새 레코드 버전: SOL `record_version = 2`([07] §14.1), BTC `record_version = 3`([08] §12.4), ZEC `record_version = 2`([12] §12.1) — 헤더 뒤에 16바이트 니모닉 record id. 주 니모닉·가져온 키·YubiKey 계정의 기록은 바이트가 그대로다(시험이 0834dfb 빌드의 SHA-256과 대조). **이전 빌드**(2026-11-07)는 새 버전 본문을 본문 오류로 본다: 그 체인의 보내기만 멈추고("저널 손상", E-VLT-006) 바이트를 그대로 두며 서명·전송·삭제하지 않는다 — 잘못 서명하거나 자금을 잃지 않는다. 그 빌드는 추가한 니모닉이 있는 vault를 어차피 열지 못하고(E-VLT-014), 니모닉을 지우면 이 빌드가 그 니모닉의 (종결된) 기록을 저널에서 지우므로(§2.24) 되돌린 뒤에도 남지 않는다 | — | — |
| `journal.ywj` 평문 | magic `YWJPL003` | 2026-11-06 확장(Zcash, [12](12-zcash.md) §12.1): entry `kind 4`. 이전 버전의 디코더는 모르는 `kind`를 `SidecarCorrupt(Journal)`로 본다: Zcash를 보낸 뒤 이전 버전으로 되돌렸다면 저널을 초기화하거나 `.prev`로 복구하지 말고 새 버전을 다시 설치한다. 앞으로 kind를 더하는 버전도 같은 안내를 따른다. 2026-11-07 확장: Zcash 기록(`kind 4`)의 상태 바이트 `7` = `InputsSpent`([12] §12.1). 2026-11-06 빌드의 디코더는 모르는 상태 값을 같은 `SidecarCorrupt(Journal)`로 본다 — 같은 안내(초기화·`.prev` 복구 금지, 새 버전 재설치) | — | — |
| `apikeys.dpapi` 평문 | magic `YWAPIK01` | 모르는 **항목 이름**(§6.3 이름 형식): 값 바이트를 해석하지 않고 보존, 저장 때 다시 씀. 등록 안 된 네트워크의 `rpc:*`(고아)도 같이 보존 | 없음: magic은 데이터 폴더와 함께만 바뀐다(다른 magic은 형식 오류, E-KEY-001) | 없음 |

- 새 부 버전이 지켜야 할 것(쓰는 쪽 규칙): 새 데이터는 **새 최상위 키**(settings·meta) 또는 **새 항목 이름**(apikeys)으로만 더한다. 이미 있는 키의 의미·값 범위를 바꾸거나 알려진 객체·레코드 안에 키를 더하는 것은 주 버전 변경이다(settings는 `version` + 1, meta·apikeys·vault·journal은 새 데이터 폴더 `v4`). 이전 버전은 알려진 객체 안의 모르는 키를 지금처럼 그 객체 단위 오류로 처리한다(§6.2, [02] §5.3).
- 보존한 키·항목은 이 버전에서 쓰지 않는다(엔드포인트·설정값으로 해석하지 않음). 크기 상한(settings 64 KiB, meta 8 MiB, apikeys 48개)을 넘게 되면 알려진 값이 우선이고, 보존한 것을 뒤에서부터 빼고 쓴다.
- 손상과 구별: 알려진 키의 형식 오류·중복 키·필수 키 없음은 지금까지처럼 그 키(또는 파일) 단위 오류다.
- 사용자 안내: 업그레이드 전에 앱을 닫고 `%LOCALAPPDATA%\YourWallet\v3` 폴더를 통째로 복사해 둔다(docs/install.ko.md §5). 새 버전에서 이전 버전으로 되돌린 경우 `settings.json`이 읽기 전용이면 새 버전을 다시 설치한다.

### 6.7 보안 설정 스냅샷 (2026-11-01 검토 M1·L15·L17)
`settings.json`은 평문이고 인증이 없다(D30). 그래서 어디로 데이터를 보내고 거래에 얼마까지 쓰는지를 정하는 값은 vault로 암호화된 meta의 선택 키 `security_settings`([02] §5.3, AEAD — 앱 밖에서 바꾸면 복호화가 실패하거나 값이 맞지 않는다)에도 둔다.

- **담는 값**: `llm_explain`의 동의(`enabled`, 엔드포인트 소문자 `host[:port]`, `privacy_notice_version`), genesis 고정값(`evmGenesisPins`의 HyperEVM + 사용자 체인 `genesisHash`), `feeCaps`, `autoLockMinutes`, `bitcoin.indexer`·`bitcoin.esploraBaseUrl`.
- **쓰기**: 앱이 `settings.json`을 쓸 때마다(UI 변경, 첫 사용 고정, 다시 고정) meta가 열려 있으면 메모리의 설정으로 스냅샷을 다시 만들어 meta와 함께 쓴다. 잠긴 동안(meta 없음) 쓴 키는 이름을 기억해 두었다가 다음 대조에서 그 값을 받아들인다(genesis 고정값은 예외: 스냅샷과 다르면 언제나 되돌림).
- **대조**: 잠금 해제 뒤 meta를 읽으면 메모리의 설정(= 시작 때 읽은 파일 + 그 뒤 앱이 바꾼 값)과 스냅샷을 비교한다.
  - LLM: 파일에서 켜져 있는데(실효) 스냅샷에 지금 엔드포인트 호스트에 대한 동의(켜짐 + 같은 호스트 + 현재 안내 버전)가 없으면 `enabled = false`로 바꿔 파일에도 쓰고 배너("AI 설명 설정이 앱 밖에서 바뀌어(동의한 주소와 다름) AI 설명을 껐습니다. …"). 사용자가 S15에서 다시 켜고 안내에 동의해야 켜진다. `yw-llm` 작업자는 이 대조가 끝나기 전(잠금 해제 전 포함)에는 시작하지 않는다.
  - LLM 키: 호스트가 묶이지 않은 이전 버전의 키(`llm:host` 없음, §6.3)는 시작 때 `settings.json`의 엔드포인트에 묶지 않는다. 대조 뒤 스냅샷의 동의 호스트에만 묶는다(메모리; 다음 `apikeys.dpapi` 저장 때 기록).
  - genesis 고정값: 스냅샷에 있는 체인의 고정값이 파일에서 없어졌거나 다르면 스냅샷 값으로 되돌려 파일에도 쓰고 배너("설정 파일의 체인 genesis 고정값이 앱 밖에서 지워지거나 바뀌어, 앱에 저장된 값으로 되돌렸습니다."). 다시 첫 사용 고정(TOFU)하지 않는다. 스냅샷에 없는 HyperEVM 고정값(잠긴 동안의 첫 사용 고정)은 받아들인다.
  - `feeCaps`·`autoLockMinutes`·`bitcoin.indexer`/`esploraBaseUrl`·스냅샷에 없는 사용자 체인: 스냅샷 값을 쓰고(없는 체인은 쓰지 않음, 활성 체인이면 11155111로) 파일은 그대로 둔다. 배너 "설정 파일이 앱 밖에서 바뀌었습니다 — 확인하세요. 지금은 앱에 저장된 값을 씁니다. 직접 바꾼 것이 아니라면 '앱에 저장된 값으로 되돌리기'를 누르세요." + 다른 값마다 쉬운 말 한 줄(2026-11-08, `App::settings_file_lines`: "자동 잠금: 지금 10분 → 파일 60분 (autoLockMinutes)", 바뀐 체인마다 "EVM 수수료 상한 — {체인}: maxFee a → b gwei · 우선 수수료 … · 총 … (feeCaps)", "Bitcoin 주소 조회 서버: 지금 {종류} (mainnet {URL} · testnet4 {URL}) → 파일 … — 파일 값을 쓰면 주소 조회가 그 서버로 갑니다", "새 사용자 체인: {이름} (chainId n) — 앱이 제네시스를 고정한 적 없음 (evmChains)"; 모두 비밀이 아닌 값이고 JSON 키는 괄호 안 보조 표기) + 주 버튼 `앱에 저장된 값으로 되돌리기`(파일을 스냅샷 값으로 다시 씀, 안전한 쪽) · 보조 버튼 `파일 값 사용…` → 확인 오버레이 `Confirm::SettingsFile`(제목 "설정 파일 값 사용", "settings.json의 아래 값을 그대로 씁니다. 이 PC에서 직접 바꾼 경우에만 고르세요…", 같은 줄 목록, `파일 값 사용`/`취소`; 오버레이에서는 머리 띠를 다시 그리지 않음) → 파일 값으로 바꾸고 스냅샷 갱신. 이전에는 키 이름만 보였고 두 버튼이 같은 모양이었으며 `파일 값 사용`은 확인 없이 모든 파일 값을 받아들였다. 결정 전에 다른 설정을 바꿔 저장하면 파일은 쓰고 있는 값(스냅샷 값)으로 쓰여 배너가 사라진다.
  - 스냅샷이 없으면(이 기능 이전의 meta, 새 지갑, meta를 새로 시작함) 그때의 설정으로 한 번 만들고 로그 `settings.snapshot_created`를 남긴다(업그레이드 경로: 그 순간의 파일을 믿는다).
- **vault 세대(L17)**: meta는 함께 본 가장 큰 `vault.ywv` `generation`(`vault_generation_seen`)을 meta를 쓸 때마다·비밀번호 변경 뒤 기록한다. 잠금 해제 뒤 파일의 generation이 그보다 작으면 배너 "지갑 파일(vault.ywv)이 예전 사본으로 바뀌었을 수 있습니다: …"와 로그 `vault.generation_backwards`. 잠금 화면(S07)과 설정 → 보안 "지갑 파일과 보호 상태"에 "지갑 파일(vault.ywv): 저장 횟수(세대) n · 마지막 저장 YYYY-MM-DD HH:MM"을 보인다.
- 남는 위험: meta를 지우거나 손상시켜 "새로 시작"(E-VLT-006)을 고르게 하면 스냅샷이 없어져 그때의 파일 값을 다시 믿는다. vault·meta를 같은 백업에서 함께 되돌리면 서로 맞는 옛 상태라 드러나지 않는다.

## 7. 오류·메시지 정책
- RPC·LLM·OS가 준 문자열은 화면에 그대로 보이지 않는다(spec.md §2.1). 예외: AI 설명 패널(§3.8)은 [06] §5–§6 필터를 거친 파생 텍스트를 별도 패널에만 표시한다(spec.md §2.1 예외). 모든 오류는 `ErrorCode`로 분류해 고정 한국어 문구 + `(코드)`로 보인다. 문구는 원인 한 문장 다음에 사용자가 할 수 있는 다음 행동을 적는다. 예: "RPC 응답 시간이 초과되었습니다. 잠시 후 다시 시도하고, 계속되면 설정 → 네트워크(RPC)에서 테스트하거나 다른 RPC URL로 바꾸세요. (E-RPC-002)". 체인 문서가 정한 고정 문구 표([08] §13 등)는 그 표를 쓴다.
- 분류 입력은 HTTP 상태, JSON-RPC `error.code`, WinHTTP·Win32 오류 번호, 내부 enum(`VaultError`·`KeyError`·`journal::JournalError`, [02] §10)이다. 문자열로 분류해야 하면(공급자의 허용 목록 거부 등) yw-app 안의 고정 부분 문자열 비교만 쓰고 그 문자열은 보이지 않는다. 오류 문구·배너에는 엔드포인트를 네트워크 이름으로만 가리키고 URL·호스트를 넣지 않는다(§1.9).
- 로그: 코드는 `warn` 이상으로 항상 남긴다. 원격 메시지 문자열은 `debug`에서만, 0x20–0x7E 밖을 `?`로 바꾸고 256바이트로 잘라 남긴다.
- 배너는 사용자가 닫을 때까지 남고 같은 코드는 한 번만 보인다(`알림 닫기`가 모두 닫는다). 오류·경고는 빨강(오류) 띠이고, 코드 없는 알림은 뜻에 맞는 색을 쓴다(`App::notice`, 2026-11-07): T-GENESIS-PINNED는 정보, "HyperEVM이 등록되어 있지 않습니다… 설정 → EVM 체인에서 추가하세요"는 주의. 설정 파일 변조·되돌림 경고(LLM 강제 끔, genesis 고정값 복원, vault 세대 역행)는 빨강 그대로다.

| 코드 | 상황(원인 enum) | 문구 |
|---|---|---|
| E-APP-001 | `settings.json` 읽기 실패·무효 키, 더 새로운 `version`(§6.2·§6.6: {키} 자리에 읽기 전용 안내) | 설정 파일을 읽지 못해 기본값을 사용합니다. ({키}) |
| E-APP-002 | `settings.json` 쓰기 실패 | 설정을 저장하지 못했습니다. 디스크 공간과 권한을 확인하세요. |
| E-APP-004 | 세션 알림 등록 실패 | Windows 잠금 감지를 켜지 못했습니다. 자리를 비울 때 직접 잠그세요. |
| E-APP-005 | 이벤트 큐 가득 참 | 요청이 너무 많아 일부를 처리하지 못했습니다. |
| E-APP-009 | 내부 오류(`InvalidState`, `RecordNotFound`, `KeyError::Internal` 등) | 내부 오류가 발생했습니다. 앱을 다시 시작해 보고, 반복되면 로그 폴더 %LOCALAPPDATA%\YourWallet\v3\logs의 yw-app.log에서 오류 코드 줄을 확인하세요. |
| E-PIPE-001 | pipe 생성 실패 | 브라우저 연결을 시작하지 못했습니다. 앱을 다시 실행하세요. |
| E-PIPE-002 | pipe 이름 점유(첫 인스턴스 `AlreadyExists`, [05] §8.1) | 다른 프로그램이 지갑 연결 채널을 점유하고 있습니다. 브라우저 연결 없이 계속합니다. 모르는 프로그램이 실행 중인지 확인하고, PC를 다시 시작한 뒤 앱을 다시 실행하세요. |
| E-VLT-001 | `UnlockFailed`(비밀번호 오류와 손상을 구분하지 않는다, [02] §10) | 비밀번호가 올바르지 않거나 vault 파일이 손상되었습니다. 대부분 입력 실수이니 Caps Lock과 한/영 상태를 확인하고 다시 입력하세요. 맞는 비밀번호로도 계속 실패하면 파일 손상일 수 있습니다(복구 안내 참고). |
| E-VLT-002 | `Malformed`, `UnsupportedVersion`, `UnsupportedParams` | 지갑 파일을 읽을 수 없습니다. 손상되었거나 다른 버전의 파일입니다. 더 새로운 버전의 앱이 쓴 파일이면 앱을 최신 버전으로 업데이트하세요. 앱은 이 파일을 지우거나 덮어쓰지 않습니다. |
| E-VLT-003 | `Storage` | 지갑 파일을 저장하지 못했습니다. 디스크 공간과 권한을 확인하세요. |
| E-VLT-005 | `RandomnessUnavailable` | 안전한 난수를 얻지 못해 작업을 중단했습니다. |
| E-VLT-006 | `SidecarCorrupt`, `SidecarVaultMismatch`, 저널 손상 | 지갑 부가 파일(meta·저널)을 읽을 수 없습니다. 복구 단어·키와 자산에는 영향이 없습니다. 더 새로운 버전의 앱이 쓴 파일이면 앱을 최신 버전으로 업데이트한 뒤 다시 여세요. |
| E-VLT-007 | `OutOfMemory`, VirtualLock 실패 | 메모리를 잠그지 못해 잠금 해제하지 않았습니다. |
| E-VLT-008 | `PayloadCorrupt` | 지갑 내용이 손상되었습니다. 이전 사본(.prev)으로 복구할 수 있습니다. |
| E-VLT-009 | `BackupNotConfirmed` | 백업 확인을 먼저 끝내세요. |
| E-VLT-010 | `RecordLimit` | 가져온 개인키는 체인마다 최대 15개입니다. |
| E-VLT-011 | `DuplicateKey` | 이미 가져온 개인키이거나, 지갑의 다른 계정과 주소가 같은 키입니다. |
| E-VLT-012 | `NoMnemonic` | 이 지갑에는 복구 단어가 없습니다. 개인키로 시작한 지갑은 계정 추가·복구 단어 보기를 쓸 수 없습니다. |
| E-VLT-013 | `LastKey` | 개인키로 시작한 지갑의 마지막 키는 지울 수 없습니다. 지갑 전체를 지우려면 앱을 닫고 데이터 폴더의 파일을 직접 옮기세요. |
| E-VLT-014 | `UnsupportedPayload` | 새 버전 앱이 저장한 지갑입니다. 앱을 업데이트하세요. 비밀번호는 맞습니다. 이전 사본(.prev)으로 되돌리지 마세요 — 새 버전에서 추가한 키가 빠집니다. 앱은 이 파일을 지우거나 덮어쓰지 않습니다. |
| E-INP-001 | `PasswordTooShort`·`TooLong`·`InvalidChar` | 비밀번호는 영문·숫자·기호(ASCII) 12–128자여야 합니다. |
| E-INP-002 | 확인 불일치(UI) | 두 입력이 다릅니다. |
| E-INP-003 | `MnemonicWordCount` | 단어 수는 12, 15, 18, 21, 24 중 하나여야 합니다. |
| E-INP-004 | `MnemonicUnknownWord { position }` | {n}번째 단어가 BIP39 영어 단어 목록에 없습니다. |
| E-INP-005 | `MnemonicChecksum`, `MnemonicFormat` | 니모닉이 올바르지 않습니다. 단어 철자와 순서를 확인하세요. |
| E-INP-006 | 개인키 형식(UI) | 개인키는 16진수 64자리여야 합니다. |
| E-INP-007 | `InvalidPrivateKey` | 사용할 수 없는 개인키입니다. |
| E-INP-008 | 비ASCII·IME | 영문(ASCII)만 입력할 수 있습니다. 한/영 키로 영문 입력으로 바꾸세요. |
| E-INP-009 | 주소 형식 | 주소 형식이 올바르지 않습니다. |
| E-INP-010 | EIP-55 불일치 | 주소의 대소문자 체크섬이 맞지 않습니다. 주소를 다시 확인하세요. |
| E-INP-011 | 금액 형식 | 금액 형식이 올바르지 않습니다. |
| E-INP-012 | 잔액 부족 | 잔액이 부족합니다(수수료 포함). |
| E-INP-013 | `BackupMismatch` | 입력한 단어가 맞지 않습니다. |
| E-INP-014 | 0 주소 | 0 주소로는 보낼 수 없습니다. |
| E-INP-015 | 토큰 컨트랙트로 전송 | 받는 주소가 이 토큰의 컨트랙트입니다. 보내면 잃습니다. |
| E-INP-016 | 주소록 중복 | 이미 주소록에 있는 주소입니다. |
| E-INP-017 | 이름 규칙 | 이름은 1–32자이고 앞뒤 공백·제어 문자·보이지 않는 문자를 쓸 수 없습니다. |
| E-INP-018 | 붙여넣기 거부 | 붙여넣은 내용에 허용되지 않는 문자가 있거나 너무 깁니다. |
| E-INP-019 | `PassphraseTooLong`·`InvalidChar`·`Empty` | passphrase는 영문·숫자·기호(ASCII) 1–256자여야 합니다. |
| E-INP-020 | `SolKeyFormat` | Solana 개인키는 base58 64바이트 keypair(Phantom·Solflare 내보내기) 또는 숫자 64개의 JSON 배열(solana-keygen 파일)이어야 합니다. |
| E-INP-021 | `SolKeyIsAddress` | 입력한 값은 32바이트라 개인키가 아니라 Solana 주소(공개키)로 보입니다. 지갑의 '개인키 내보내기'로 받은 값을 넣으세요. |
| E-INP-022 | `SolKeyMismatch` | keypair의 공개키 부분이 개인키와 맞지 않습니다. 값이 잘리거나 바뀌지 않았는지 확인하세요. |
| E-INP-023 | `WifFormat` | Bitcoin 개인키는 WIF(5·K·L·9·c로 시작하는 base58 51–52자)여야 합니다. 글자와 체크섬을 확인하세요. |
| E-INP-024 | `WifUncompressedScript` | 압축되지 않은 키(5·9로 시작하는 WIF)는 P2PKH(레거시) 주소에만 쓸 수 있습니다. 주소 형식을 P2PKH로 고르세요. |
| E-INP-025 | `ZecKeyFormat` | Zcash 개인키는 압축 WIF(K·L·c로 시작하는 base58 52자) 또는 16진수 64자리여야 합니다. 압축되지 않은 WIF(5·9로 시작)는 받지 않습니다. |
| E-INP-026 | `ZecKeyNetwork` | 이 WIF는 다른 Zcash 네트워크의 키입니다(K·L = 메인넷, c = 테스트넷). Zcash 탭의 네트워크를 바꾼 뒤 가져오세요. |
| E-SEC-001 | 캡처 제외 실패(`CaptureExclusion::Required` 창 W08·W09, §4.5. `Preferred` 창은 T-CAPTURE-WARN) | 화면 캡처 제외를 적용하지 못해 표시하지 않습니다. |
| E-SEC-002 | 클립보드 열기 실패 | 클립보드를 사용할 수 없습니다. 잠시 후 다시 시도하세요. |
| E-KEY-001 | `apikeys.dpapi` 읽기 실패 | 저장된 RPC 엔드포인트·API 키를 읽을 수 없습니다. 다시 입력하세요. |
| E-KEY-002 | 템플릿 자격 정보 형식(QuickNode 엔드포인트 이름·토큰, 알케미 키, §2.11). {항목}은 문구 끝, 코드 앞에 붙인다 | 공급자 템플릿 입력 형식이 올바르지 않습니다. QuickNode는 대시보드의 엔드포인트 주소 https://<이름>.<체인>.quiknode.pro/<토큰>/ 에서 첫 '.' 앞의 <이름>과 '.quiknode.pro/' 바로 뒤의 <토큰>을 넣고, 알케미는 대시보드의 API Key를 넣으세요. ({항목}) |
| E-KEY-003 | RPC URL 형식(`HttpsUrl::parse` 실패, `직접 입력` 템플릿에 URL이 아닌 값) | RPC URL은 https:// 로 시작하는 올바른 주소여야 합니다. |
| E-KEY-004 | 템플릿 자격 정보 없음(`네트워크 URL 생성`, S17 서브도메인·라벨 입력, §2.11.1·§2.17.1) | 선택한 RPC 공급자 템플릿의 자격 정보가 없습니다. 설정 → RPC 공급자에서 먼저 저장하세요. |
| E-KEY-005 | 네트워크 엔드포인트 없음(`rpc:<NetworkId>` 없음: 그 네트워크의 조회·준비·서명·`테스트`·BTC 켜기, [03] E35, §1.9) | RPC 엔드포인트가 없습니다. 설정 → 네트워크 URL에서 이 네트워크의 URL을 만들거나 입력하세요. |
| E-RPC-001 | DNS·연결 실패 | 네트워크에 연결할 수 없습니다. 인터넷 연결을 확인하고, 계속되면 설정 → 네트워크(RPC)에서 이 네트워크의 테스트를 눌러 보세요. |
| E-RPC-002 | 시간 초과 | RPC 응답 시간이 초과되었습니다. 잠시 후 다시 시도하고, 계속되면 설정 → 네트워크(RPC)에서 테스트하거나 다른 RPC URL로 바꾸세요. |
| E-RPC-003 | HTTP 401·403 | RPC 엔드포인트가 인증을 거부했습니다. 설정 → 네트워크(RPC)에서 이 네트워크의 URL(토큰)을 확인하세요. QuickNode 멀티체인이면 대시보드에서 이 체인이 그 엔드포인트에 켜져 있어야 합니다. |
| E-RPC-004 | HTTP 429, 한도 초과 코드 | 요청 한도를 넘었습니다. 잠시 후 다시 시도하세요. |
| E-RPC-005 | 응답 형식 이상 | RPC 응답 형식이 올바르지 않습니다. 설정 → 네트워크(RPC)에서 테스트해 이 네트워크용 URL(경로 포함)이 맞는지 확인하세요. |
| E-RPC-006 | chainId 불일치, 상수 제네시스 체인(1·11155111)의 제네시스 불일치([03] §1.4) | RPC가 다른 네트워크를 가리킵니다. 작업을 중단했습니다. 설정 → 네트워크(RPC) → 테스트로 이 네트워크의 URL을 확인하고 맞는 URL로 바꾸세요. |
| E-RPC-007 | 그 밖의 JSON-RPC 오류, 그 밖의 HTTP 상태(404 포함) | RPC가 요청을 거부했습니다. 설정 → 네트워크(RPC)에서 테스트해 보세요. QuickNode 멀티체인이면 대시보드에서 이 체인이 그 엔드포인트에 켜져 있는지, 요금제가 이 요청을 지원하는지 확인하세요. |
| E-RPC-008 | TLS 실패 | 보안 연결(TLS)을 맺지 못했습니다. PC의 날짜·시간이 맞는지, 보안 프로그램·프록시가 HTTPS 연결을 가로채지 않는지 확인하세요. |
| E-RPC-009 | 리퍼러·origin 허용 목록 거부 | RPC 엔드포인트에 리퍼러·도메인 허용 목록이 걸려 있습니다. 공급자 대시보드에서 해제하세요(토큰 인증·IP 허용 목록은 무방, D13). |
| E-RPC-010 | 엔드포인트 `테스트` 결과 불일치(§2.11.1). {항목} = `chainId`(EVM; 문구 끝에 " (RPC chainId {n})", 파싱한 10진 값), `genesis`(SOL), `chain`(BTC; 원격 문자열은 보이지 않음) | 엔드포인트 테스트 실패: {항목} 불일치 — 다른 네트워크의 URL입니다. |
| E-BTC-001 | Bitcoin 인덱서 연결 실패: 전송 오류·시간 초과·TLS(원인 코드 E-RPC-001·002·008을 함께 보인다, 예 "(E-BTC-001, E-RPC-002)"), HTTP 3xx·5xx·그 밖 상태([08] §4.3). {인덱서} = `Esplora`·`Blockbook JSON-RPC`·`Blockbook REST`(URL·호스트 없음) | Bitcoin 인덱서({인덱서})에 연결할 수 없습니다. 잠시 후 다시 시도하거나 설정 → Bitcoin에서 인덱서를 바꾸세요. |
| E-BTC-002 | 인덱서 HTTP 429가 재시도 3회 뒤에도 계속됨([08] §4.4; 일반 RPC의 E-RPC-004 대신) | Bitcoin 인덱서 요청 한도를 넘었습니다. 몇 분 뒤 다시 시도하세요. 공용 서버(mempool.space 등)는 요청 수를 제한합니다. |
| E-BTC-003 | 인덱서 제네시스 불일치([08] §2 3단계, `Esplora URL` `테스트`). 그 세션의 BTC 호출 차단 | Bitcoin 인덱서가 다른 네트워크를 가리킵니다. 설정 → Bitcoin에서 인덱서와 Esplora URL을 확인하세요. |
| E-BTC-004 | 인덱서 응답 형식 이상(필드·정수·hex·`Content-Type`·예상 밖 404, [08] §4.1·§4.3) | Bitcoin 인덱서 응답 형식이 올바르지 않습니다. |
| E-BTC-005 | Esplora 주소 조회 HTTP 400([08] §4.3: UTXO 수 초과·다른 네트워크 주소) | 인덱서가 주소 조회를 거부했습니다. 주소의 UTXO가 너무 많거나(공용 mempool.space는 500개 초과 시 거부) 인덱서의 네트워크가 다를 수 있습니다. |
| E-BTC-006 | `Esplora URL` 형식(§6.1 `EsploraBaseUrl`, S15 `저장`) | Esplora URL은 https:// 로 시작하고 ?·#·끝 '/'가 없어야 하며, 토큰이 들어가는 공급자 URL(QuickNode·알케미)은 쓸 수 없습니다. |
| E-BTC-007 | 인덱서 인증·권한 거부: HTTP 401·403, `bb-*` 애드온 미활성(QuickNode `-32601` 등, [08] §4.3) | Bitcoin 인덱서가 요청을 거부했습니다(인증 또는 인덱서 애드온 권한). 설정 → Bitcoin에서 인덱서를 Esplora로 바꾸거나 공급자 대시보드에서 애드온을 켜세요. |
| E-BTC-008 | Esplora 수동 전송 `POST /tx` HTTP 400([08] §11.3; 본문의 노드 거부 사유는 보이지 않고 `debug` 로그만) | Esplora 서버가 거래 전송을 거부했습니다. 활동에서 상태를 확인하고 필요하면 수수료를 올리세요. |
| E-SIM-001 | `Reverted`: revert·VM 오류(§3.2.1, [03] §6.3). 고위험 띠, 승인 가능(D15) | 시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다 |
| E-SIM-002 | `NoResult`: RPC 오류·시간 초과(10 s)·한도 초과·메서드 미지원·응답 형식 이상·해석 불가. 고위험 띠, 승인 가능 | 시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다 |
| E-SIM-003 | `Unsupported`: 체인 `simulation = unsupported`. 고위험 띠, 승인 가능 | 시뮬레이션 미지원 체인 — 실제 효과를 확인할 수 없습니다 |
| E-SIM-004 | `Incomplete`: 결과 일부를 확인·해석하지 못함. 고위험 띠, 승인 가능 | 시뮬레이션 결과 불완전 — 일부 효과를 확인할 수 없습니다 |
| E-CHN-001 | 체인 추가·RPC 변경: `eth_chainId` ≠ 입력(§2.17.2) | RPC의 chainId({n})가 입력한 chainId와 다릅니다. |
| E-CHN-002 | 체인 추가·RPC 변경·다시 고정: RPC 연결·응답 실패(원인 코드를 함께 보인다) | RPC에 연결하지 못해 체인을 확인할 수 없습니다. |
| E-CHN-003 | 이미 있는 chainId(기본 체인 포함) | 이미 등록된 chainId입니다. |
| E-CHN-004 | 체인 입력 형식(chainId 범위, 심볼, 소수 자릿수, QuickNode 서브도메인·알케미 라벨, 탐색기 URL) | {항목} 형식이 올바르지 않습니다. |
| E-CHN-005 | 체인 이름 중복 | 같은 이름의 체인이 이미 있습니다. |
| E-CHN-006 | 사용자 체인 32개 초과 | 사용자 체인은 최대 32개입니다. |
| E-CHN-007 | 삭제 거부: 미종결 저널·송신 슬롯·승인 대기 | 진행 중인 거래나 승인 대기가 있는 체인은 삭제할 수 없습니다. 확정된 뒤 다시 시도하세요. |
| E-CHN-008 | 최초 신뢰 고정 체인(HyperEVM·사용자 체인)의 제네시스 불일치(§1.9, §2.17.4) | 체인 정보가 바뀌었습니다 (제네시스 불일치) |
| E-CHN-009 | 삭제 거부: 활성 체인 | 사용 중인 체인은 삭제할 수 없습니다. 네트워크를 먼저 바꾸세요. |
| E-CHN-010 | 사용자 체인 추가: `baseFeePerGas` 없음([03] §1.6-4) | EIP-1559를 지원하지 않는 체인입니다. |
| E-TX-001 | 수수료 상한 초과([03] E05) | 수수료가 설정한 상한을 넘습니다. 네트워크가 붐비면 잠시 후 다시 시도하거나, 설정 → EVM 체인 → 고급 설정 보기의 EVM 수수료 상한을 확인하세요. |
| E-TX-002 | 진행 중 거래(D20, [03] E06) | 이 계정의 이전 거래가 아직 확정되지 않았습니다. |
| E-TX-003 | 서명 후 자체 검증 실패 | 내부 검증에 실패해 거래를 보내지 않았습니다. |
| E-TX-004 | 전송 결과 불명 | 전송 결과를 확인할 수 없습니다. 다시 보내지 마세요 — 거래가 이미 전송되었을 수 있습니다. 활동에서 상태를 확인하세요. |
| E-TX-005 | `journal::JournalError::Full`([02] §5.4 추가 전 검사, [03] E06; 모든 체인, 서명·전송 없음) | 거래 저널 공간이 부족합니다. |
| E-UI-001 | 표시 검증 실패 | 요청 내용을 안전하게 표시할 수 없어 거부했습니다. |
| E-SOL-001 | SOL 받는 주소가 프로그램·sysvar·허용 목록 mint([07] §12.1-2, 입력 단계 차단) | 받는 주소가 프로그램·시스템·토큰 mint 주소입니다. 보내면 잃습니다. |
| E-SOL-002 | SOL 받는 주소가 small-order·비정규 점([07] §12.1-3) | 받는 주소는 아무도 쓸 수 없는 주소입니다. 보내면 잃습니다. |
| E-SOL-003 | SOL 받는 주소 = 보내는 계정([07] §12.1-4) | 보내는 계정과 같은 주소로는 보낼 수 없습니다. |
| E-SOL-004 | 승인 뒤 서명 전 단계 실패([07] §13.1 4–6: 블록해시 조회·제네시스·범위·저널·서명 검증; 원인 코드를 함께 보인다) | 승인한 전송을 서명 전에 멈췄습니다(아무것도 서명·전송하지 않음). 다시 검토하세요. |
| E-SOL-005 | `Pending` 120 s 경과([07] §14.2 `SOL_PENDING_NOTICE_SECS`) | 전송 확인이 오래 걸립니다. 네트워크·RPC 상태를 확인하세요(자동 재서명 없음). |
| E-SOL-006 | SPL 받는 주소가 곡선 밖(PDA·토큰 계정, [07] §12.1-6, v1.1, 입력 단계 차단) | 토큰은 일반 지갑 주소로만 보낼 수 있습니다. 이 주소는 프로그램 소유 주소(PDA)나 토큰 계정이라 받은 토큰을 옮길 수 없습니다. |
| E-LLM-* | [06] §7 | [06] (패널 안에만) |

새 상황은 같은 형식(`E-<영역>-<3자리>`)으로 이 표에 추가한다.

## 8. 로그 (D28)
- 파일: `logs\yw-app.log`, 순환 `yw-app.1.log` … `yw-app.4.log`(총 5개). yw-host 로그는 [05].
- 순환: 한 줄을 쓰기 전 현재 크기 + 줄 길이가 `LOG_FILE_MAX_BYTES = 1_048_576`을 넘으면 닫고, `.4` 삭제, `.3→.4`, `.2→.3`, `.1→.2`, 현재→`.1`로 이름을 바꾸고 새 파일을 연다. `.1`–`.4` 단계의 실패는 무시한다. 현재 파일이 이름 바꾸기 뒤에도 남아 있으면(다른 프로그램이 잡고 있음 등) 그 파일을 비우고(truncate) 첫 줄에 `WARN log rotate.failed`를 쓴 뒤 계속 쓴다. 비우기도 실패하면 이번 실행 동안 파일 로그를 멈춘다(크기 상한을 넘겨 계속 커지지 않는다).
- 형식: UTF-8, LF, 한 줄 ≤ 1,024바이트(넘으면 자름). `2026-10-26T12:34:56.789Z WARN rpc E-RPC-002 method=eth_simulateV1 net=eip155:11155111 ms=12000`. 시각은 UTC. 필드 값은 0x21–0x7E만(나머지 `?`). 엔드포인트는 `net=<NetworkId>`로만 가리키고 `host=`·`url=` 필드는 없다(D13: QuickNode 호스트에는 엔드포인트 이름이 들어간다, §1.9). BTC 인덱서는 `idx=esplora|bb-rpc|bb-rest`와 경로 종류만 쓴다(`esplora`: `utxo`·`address`·`tx-status`·`tx-hex`·`block-height`·`tip-height`·`tx-post`, `bb-rest`: `utxo`·`address`·`tx`·`block-index`). 비밀이 아닌 Esplora 기준 URL도 쓰지 않는다([08] §4.1).
- `Mutex<LogWriter>`(버퍼). `warn` 이상은 즉시 flush, 나머지는 2초마다와 종료 때. `logLevel` 이상만 쓴다. 텔레메트리·업로드 경로는 없다.

| 기록한다 | 기록하지 않는다 |
|---|---|
| 시작·종료(버전, OS 빌드, 인자), `AppMode` 전이, 잠금 사유, 잠금 해제 성공·실패(횟수만) | 비밀번호, passphrase, 니모닉 단어, 개인키, 시드, DEK·KEK, 백업 확인 답 |
| 오류 코드와 분류 입력(HTTP 상태, JSON-RPC 코드, Win32 오류 번호, enum 이름) | API 키, RPC 엔드포인트 URL의 어느 부분도(호스트·엔드포인트 이름·경로·쿼리·토큰), 템플릿 자격 정보, `Authorization` 헤더 |
| RPC 메서드 이름, `NetworkId`, 지연, 응답 크기 | RPC·LLM 요청·응답 본문(`debug`의 잘린 원격 오류 문자열 제외, §7) |
| dApp 요청: 메서드 이름, 내부 요청 번호, `QueueOutcome` | dApp origin, personal_sign 내용, 타입 데이터, calldata |
| 거래: 체인, 계정 주소, nonce, 해시·txid, 저널 상태 전이 | 금액, 주소록 이름, 계정·토큰 라벨 |
| 설정 변경(키 이름; `apikeys.dpapi`는 항목 이름 `rpc:<NetworkId>`·`tpl:*`만: `rpc.url_set`·`rpc.url_deleted`·`rpc.generated`·`rpc.test`·`tpl.saved`·`tpl.deleted`; `bitcoin.esploraBaseUrl`은 `btc.esplora_url_set net=<NetworkId>`, URL 없음), 사용자 체인 추가·편집·삭제와 제네시스 고정·다시 고정(`chain.added`·`chain.edited`·`chain.deleted`·`chain.genesis_pinned`·`chain.repinned`, `NetworkId`·해시; 템플릿 식별자도 쓰지 않는다), 캡처 제외 결과, 클립보드 동작 종류, `MetaAddressMismatch`([02]) | 클립보드 내용, API 키 값, `apikeys.dpapi` 항목 값 |

주소와 거래 해시는 D28에 따라 기록할 수 있다. origin은 브라우징 기록에 해당하는 개인정보로 보고 기록하지 않는다.

## 9. 파일 위치
데이터 폴더 `%LOCALAPPDATA%\YourWallet\v3\`(spec.md §4.3).

| 파일 | 내용 | 형식 소유 | 쓰는 스레드 |
|---|---|---|---|
| `vault.ywv`(+`.prev`) | vault v3 | [02] | 키 |
| `meta.ywm`(+`.prev`) | 계정·주소록·연결 기록·토큰·활동·`prefs`(§6.4) | [02] §5.3 | 키 |
| `journal.ywj`(+`.prev`) | 진행 중 거래 저널 | [02]·[03]·[07]·[08] | 키 |
| `settings.json` | §6.1(사용자 EVM 체인 정의·고정 제네시스·Bitcoin 인덱서와 Esplora URL 포함, 비밀 없음) | 이 문서 | UI |
| `apikeys.dpapi` | §6.3(네트워크별 RPC 엔드포인트 URL `rpc:<NetworkId>`, 템플릿 자격 정보 `tpl:quicknode`·`tpl:alchemy`, LLM 키) | 이 문서 | UI |
| `logs\yw-app*.log` | §8 | 이 문서 | 모든 스레드(뮤텍스) |

- `settings.json`·`apikeys.dpapi` 원자적 쓰기는 yw-win `file::atomic_write`(spec.md §4.3, [01] §7.2: 재분석 지점 거부 → 남은 `<이름>.tmp` 삭제 → `create_new` → `sync_all` → `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)` → 부모 디렉터리 flush)다. 실패(`FileError`)는 둘 다 E-APP-002. 시작 시 남은 `*.tmp`는 지운다. vault·meta·journal의 `.prev` 회전 절차는 [02] §6.
- 앱은 지갑 파일(vault·meta·journal과 `.prev`)을 지우지 않는다. 옮기는 것은 사용자가 확인한 지갑 초기화(§2.20: `v3\reset-<UTC>\`로 이동, 설정·API 키는 선택)뿐이다. 다른 지갑으로 바꾸려면 사용자가 직접 옮기거나 §2.20을 쓴다([02] §6.3).
- `reset-<YYYYMMDDTHHMMSSZ>\`(§2.20): 초기화로 옮긴 파일과 `README-reset.txt`. 앱은 이 폴더를 읽거나 쓰지 않는다(되돌리기는 사용자가 직접, recovery-guide).

## 10. 수동 체크리스트 (M3·M4 UI)
판정 기준과 기록 방식은 [09]. 각 항목을 1회 수행한다.

| ID | 단계 | 절차 | 합격 |
|---|---|---|---|
| UI-M3-01 | M3 | 새 지갑 생성 → W08에서 전체 화면 캡처(Win+Shift+S 전체 화면, PrtScn, OBS 디스플레이 캡처)와 OBS 윈도우 캡처(그 창 선택), W01·W02·W05·W07·W10에서도 같은 캡처 | 전체 화면 캡처 결과에 해당 창이 나타나지 않고 그 자리에 뒤 창·바탕화면이 보인다(spec.md §5 M3). OBS 윈도우 캡처는 내용 없는 빈(검은) 프레임. 전체 화면 캡처에 창 모양의 검은/빈 사각형이 보이면 불합격(원인 조사) |
| UI-M3-02 | M3 | W08에서 Ctrl+C, 우클릭, 마우스 끌기(토글 끔) | 클립보드 변화 없음, T-COPY-OFF |
| UI-M3-03 | M3 | 토글 켜고 W08 `복사` → Win+V 기록 확인 → 30초 대기 | 기록에 없음, 30초 뒤 붙여넣기 결과 빈 값 |
| UI-M3-04 | M3 | 토글 켜고 복사 → 10초 안에 다른 텍스트 복사 → 30초 대기 | 다른 텍스트가 남아 있음 |
| UI-M3-05 | M3 | 한글 입력 모드로 W01에 입력 | 버퍼 변화 없음, E-INP-008 |
| UI-M3-06 | M3 | 니모닉을 메모장에서 복사해 W05에 붙여넣기 | 단어 칸 표시, T-PASTE-CLEARED, 이후 붙여넣기 결과 빈 값 |
| UI-M3-07 | M3 | 백업 확인에 틀린 단어 → 같은 위치로 맞는 값 | T-BACKUP-FAIL(같은 위치 4개) 후 성공, S08 |
| UI-M3-08 | M3 | 자동 잠금 4경로: ① 1분 설정 후 1분간 다른 앱만 사용 ② Win+L ③ 시작 → 전원 → 절전 후 다시 켜기 ④ `잠금`·Ctrl+L | 각각 잠김, 로그 `lock reason`이 `Idle`·`SessionLock`·`Suspend`·`Manual`(③은 Modern Standby PC면 `Suspend` 또는 `SessionLock`, §5.1) |
| UI-M3-09 | M3 | 앱 종료 → 재실행 → 잠금 해제 / 틀린 비밀번호 | 같은 첫 주소 / E-VLT-001, 1초 비활성 |
| UI-M3-10 | M3 | 앱 실행 중 exe 재실행, `--background` 재실행 | 기존 창이 앞으로 / 변화 없음, 프로세스 1개 |
| UI-M3-11 | M3 | `QuickNode 멀티체인`에 실제 엔드포인트 이름·토큰 붙여넣기 → `저장` → `네트워크 URL 생성` → `eip155:1`·`eip155:11155111` `테스트` → 재시작 → 같은 `테스트`(빈 칸); 토큰 한 글자 바꾼 URL을 Sepolia `교체` 칸에 넣고 `테스트`; Ethereum 메인넷 URL을 Sepolia `교체` 칸에 넣고 `테스트`; Sepolia URL `삭제` 후 S10; 다른 Windows 사용자로 `apikeys.dpapi` 복사 후 실행 | T-RPC-OK, 목록은 가린 형태만, 이름·토큰·URL·호스트가 화면·로그에 없음(로그는 `net=<NetworkId>`만) / E-RPC-003(구현 시 확인: QuickNode의 잘못된 토큰 응답, §2.11.1) / E-RPC-010 "엔드포인트 테스트 실패: chainId 불일치 — 다른 네트워크의 URL입니다. (RPC chainId 1)" / 상태 줄 "엔드포인트 없음 (E-KEY-005)" / E-KEY-001 |
| UI-M3-12 | M3 | `abandon … about` 가져오기 | S06 첫 주소 `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` |
| UI-M3-13 | M3 | passphrase 지갑 가져오기 → 재시작 → 다른 passphrase 입력 | T-PASS-MISMATCH, 계속 시 T-ALT-PASS 배너 |
| UI-M3-14 | M3 | 125%·150% 배율 모니터 사이 창 이동 | 글자·QR 잘림 없음 |
| UI-M4-01 | M4 | Sepolia ETH 보내기(주소 붙여넣기) | 승인 창 헤더·제목·자산 변화 표시, 확정까지 활동 갱신 |
| UI-M4-02 | M4 | Sepolia ERC-20 보내기 | 같음, 토큰 라벨·컨트랙트 주소 표시 |
| UI-M4-03 | M4 | 되돌려지는 거래(ETH를 받지 않는 컨트랙트 — Sepolia USDC 컨트랙트 주소 — 로 SepoliaETH 소액; 잔액 초과 금액은 §2.15 E-INP-012로 폼에서 막힘) 검토 → 체크 없이 2초 누르기 → 체크 + 2초 누르기 | "시뮬레이션 중…" 동안 승인 비활성, 이어서 맨 위 띠 E-SIM-001 "시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다" + 되돌림 이유, 자산 변화 T-SIM-NODIFF / 진행 없음 / 전송, 활동 `failed`(영수증 status 0) |
| UI-M4-04 | M4 | 네트워크를 끊고 검토 | 시뮬레이션 전 단계 실패 `Failed` E-RPC-001, `다시 시도` 있음, 승인 불가(서명할 거래 없음) |
| UI-M4-05 | M4 | 전송 직후 작업 관리자로 강제 종료 → 재실행·잠금 해제 | 활동에 같은 해시, 상태 갱신([03]) |
| UI-M4-06 | M4 | 진행 중 거래가 있는 계정에서 보내기 | T-SEND-INFLIGHT, 폼 비활성 |
| UI-M4-07 | M4 | 주소록 항목과 앞 4·끝 4자가 같은 주소 입력 | W-ADDR-3, 체크 전 `검토` 비활성, 승인 창 주석 |
| UI-M4-08 | M4 | 받기 QR을 휴대폰 지갑으로 스캔 | 같은 주소와 chainId |
| UI-M4-09 | M4 | 보내기 검토 후 승인 창을 120초 방치 → `검토` 다시 | 만료로 닫힘, 폼 입력 유지, T-APPR-EXPIRED / 새 승인 창(남은 시간 2:00부터) |
| UI-M4-10 | M4 | 다른 창을 클릭하는 중에 승인 창이 뜨게 함 | 첫 클릭이 승인되지 않음 |
| UI-M4-11 | M4 | Sepolia URL을 `교체`로 `eth_simulateV1`을 지원하지 않는 공급자의 URL로 바꿈(구현 시 확인: 해당 공급자) → ETH 보내기 검토 → 체크 + 2초 → 원래 URL로 되돌림(`교체` 또는 `네트워크 URL 생성` + `기존 URL 덮어쓰기`) | 띠 E-SIM-002 "시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다" + 원인, `시뮬레이션 다시 시도` 있음, 승인·전송·확정 |
| UI-M4-12 | M4 | `QuickNode 멀티체인` 자격 정보 저장 상태에서 S17 체인 추가: Sepolia 서브도메인(`ethereum-sepolia`, 구현 시 대시보드와 대조) + chainId 1234 / chainId 11155111 / 정상 체인(예: Base Sepolia 84532, 서브도메인 `base-sepolia`, 시뮬레이션 `unsupported`) / 템플릿을 `직접 입력`으로 바꾸고 서브도메인 입력 | E-CHN-001(RPC 값 11155111 표시) / E-CHN-003 / T-CHAIN-PIN에 "QuickNode 서브도메인 base-sepolia"와 제네시스 해시 전체, 저장 후 네트워크 선택에 T-CUSTOM-CHAIN 배지, `네트워크 URL` 목록에 `eip155:84532` 설정됨(가린 형태), `settings.json` `quicknodeSubdomain`, 받기 QR `@84532` / E-KEY-003 |
| UI-M4-13 | M4 | `simulation = unsupported` 체인(UI-M4-12)과 HyperEVM에서 각각 소액 네이티브 보내기 | 전자는 띠 E-SIM-003 "시뮬레이션 미지원 체인 — 실제 효과를 확인할 수 없습니다", 체크 + 2초 후 전송·확정. HyperEVM은 첫 연결 때 T-GENESIS-PINNED, `settings.json` `evmGenesisPins["eip155:999"]`, 시뮬레이션 상태가 띠 또는 자산 변화로 표시되고 전송·확정 |
| UI-M4-14 | M4 | 앱 종료 → UI-M4-12 체인의 `settings.json` `genesisHash` 마지막 hex 1자 변경 → 실행·그 체인 선택 → S15 `다시 고정`(체크 전/후) | "(차단됨)", 배너 E-CHN-008 "체인 정보가 바뀌었습니다 (제네시스 불일치)", 보내기 불가 / T-CHAIN-REPIN에 두 해시, 체크 전 버튼 비활성, 고정 후 정상 |
| UI-M4-15 | M4 | 사용자 체인 삭제: 활성 상태 / 미종결 거래 중 / 확정 후 | E-CHN-009 / E-CHN-007 / T-CHAIN-DELETE 후 목록·`settings.json`·`rpc:eip155:<id>`에서 사라지고 다시 추가하면 활동 기록이 다시 보임 |
| UI-M4-16 | M4 | Sepolia 보내기 승인 창을 61초 이상 열어 둠 → 네트워크 끊고 `승인` → 네트워크 연결 → 체크 + 2초 | 재시뮬레이션 중 "시뮬레이션 중…" 후 띠 E-SIM-002·T-SIM-RESIM-FAILED·체크 해제, 첫 클릭으로 소비되지 않음 / 다음 승인으로 전송 |

## 11. 화면 투어 (개발 전용)
주요 화면과 창의 스크린샷(`docs/screenshots/`, 목록과 설명은 그 폴더의 `README.md`)을 만드는 개발 도구다. 판정 기준이 아니다.
- 실행: `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/screenshot-tour.ps1`. yw-app의 `#[ignore]` 테스트 `ui::tour::screenshot_tour`(테스트 빌드에만 있다)를 돌려 BMP를 `target/screenshot-tour/`에 쓰고, System.Drawing으로 PNG로 바꾼다. 확장 팝업은 `scripts/popup-preview.html`(팝업 마크업 + `chrome` 대역, 실제 `popup.css`·`popup.js`; `<body>`가 `popup.html`과 같은지 `scripts/popup-preview.test.mjs`가 확인한다)을 127.0.0.1 임시 정적 서버로 열어 헤드리스 Edge/Chrome으로 찍는다(브라우저가 없으면 건너뜀).
- 장면: 첫 실행·만들기·가져오기·개인키로 시작하기·YubiKey 지갑(S20, 만든 뒤의 S08), 잠금, 세 체인 메인, Zcash 탭(꺼짐, testnet 켜짐 — 공개 BIP44 testnet 벡터의 공개키, URL 없음), EVM 메인의 HyperCore 카드, 설정 → 브라우저·정보(지도 줄·WalletConnect 카드), EVM 토큰 카드(숨긴 토큰 펼침, 지어낸 사용자 토큰), 보내기(EVM·Solana 토큰), 받기, 승인 창(시뮬레이션 성공·결과 없음·Solana 토큰·AI 설명·사이트 연결·Solana 메시지 서명), 설정(RPC·AI·YubiKey), 연결된 사이트(EVM과 Solana·Bitcoin), YubiKey 등록 마법사(키·슬롯, 확인, 자격 정보, W12, 결과)와 W11 카드 단계, 지갑 초기화(S22)·Chrome 확장 설치(S23), 확장 팝업. YubiKey 장면은 카드·키 작업자 없이 공개 시험 니모닉에서 투어가 직접 계산한 미리보기·기록(지어낸 일련번호 12345678)을 쓴다. dApp 요청은 투어 브라우저 코어에 넣은 지어낸 연결(grant)과 요청으로 만들고 거부로 끝낸다(서명 없음).
- 데이터: 버리는 임시 데이터 폴더(끝나면 삭제)만 쓰고 `%LOCALAPPDATA%\YourWallet`은 읽지도 쓰지도 않는다. vault·키 작업자·RPC 작업자를 만들지 않는다. 생성 흐름 화면의 단어는 BIP39 공개 시험 벡터(엔트로피 0, 24단어), 메인 화면은 공개 시험 니모닉(`abandon` × 11 + `about`) 지갑의 주소이고, 잔액·사이트·UTXO는 지어낸 값이다. RPC URL은 연결하지 않는 `*.example.test`, EVM 승인 창은 `app_approval::smoke`의 고정 응답(`tests/fixtures/eth_simulateV1/S2`·`S4`)으로, Solana 토큰(devnet USDC) 승인 창은 투어 안의 고정 Solana 응답(`SolTourRpc`: 받는 ATA 없음, 2026-10-28 실측 rent)으로 준비한다. 브라우저 다리는 투어 전용 pipe 이름(`\\.\pipe\YourWallet.tour.<pid>`)으로 연다.
- 캡처: yw-win `ui::capture`(`#[cfg(debug_assertions)]`, release 빌드에 없음). `RedrawWindow(RDW_UPDATENOW | RDW_ALLCHILDREN)`로 창과 자식 컨트롤을 동기로 다시 그리고 `GdiFlush` 뒤, 창 자신의 클라이언트 DC에서 `BitBlt`로 복사한다(`PrintWindow(PW_RENDERFULLCONTENT)`는 마지막 DWM 프레임을 돌려줘 반쯤 그린 화면이 찍혔다). 캡처 제외 창(W01–W10)은 검게 찍히므로 **투어 프로세스가 직접 만든 창에 한해** 캡처 직전 `dev_tour_lift_capture_exclusion`(`WDA_NONE`)을 부른다. 앱의 비밀 창 생성 경로(§4.5)는 바뀌지 않는다.
- 스크롤 잔상 점검: `#[ignore]` 테스트 `ui::tour::scroll`(`cargo test -p yw-app --lib ui::tour::scroll -- --ignored --nocapture`)이 모든 네트워크에 `*.example.test` URL을 넣은 설정 → 네트워크(RPC) 화면에서 휠(미끄러짐 중간 프레임 포함)·터치패드 크기 델타·막대 줄/쪽/끝·미끄러지는 중 재배치(RPC `테스트` 결과)를 실제 메시지로 보내고, 창이 보여 주는 화면을 같은 위치의 전체 다시 그리기·새 배치와 비교한다. 다른 픽셀이 하나라도 있으면 실패한다(`YW_SCROLL_DUMP`가 있으면 두 화면을 BMP로 남긴다). 같은 장면을 두 환경에서 돈다: `plain`(투어처럼 DPI 비인식 = 96 DPI를 시스템이 늘림, 고전 컨트롤)과 `app`(설치된 앱처럼 앱 매니페스트의 활성화 컨텍스트로 comctl32 v6 테마 컨트롤, 스레드 Per-Monitor-V2 = 모니터 DPI; `dev_tour_app_env`). 테마 컨트롤은 멈춘 포인터 아래에서 호버 음영이 남으므로 창이 포인터 위에 있으면 먼저 옆으로 옮긴다(`dev_tour_clear_of_pointer`). 스크린숏 투어 스크립트는 `ui::tour::screenshot_tour`만 돈다.

## 미결 사항

없음. 이전 미결 1(yw-win `Msg` 세션·종료 변형과 캡처 제외 실패 대체)은 [01] §7.7의 `Msg::{SessionDisconnect, SessionLogoff, QueryEndSession, EndSession}`과 `ClassSpec.capture: CaptureExclusion::{Required, Preferred}`로 해소되어 삭제했다(§1.5, §1.7, §4.5, §5.1).

[01]: 01-repo-build.md
[02]: 02-core-keys-vault.md
[03]: 03-evm.md
[05]: 05-browser.md
[06]: 06-llm-explain.md
[07]: 07-solana.md
[08]: 08-bitcoin.md
[09]: 09-testing.md
[10]: 10-yubikey.md
