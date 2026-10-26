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
상수: 뮤텍스 이름 `Local\YourWallet.v3.app`(Rust 리터럴 `"Local\\YourWallet.v3.app"`), 주 창 클래스 `YourWalletV3Main`, 인자 `--background`.
- 인자는 없음 또는 정확히 `--background` 하나만 허용한다. 그 밖이면 종료 코드 2.
- `process::SingleInstance::acquire(이름)`([01] §7.6, `CreateMutexW`)의 값은 프로세스 끝까지 유지한다. `Err(InstanceError::AlreadyRunning)`(`ERROR_ALREADY_EXISTS (183)`)이면 두 번째 인스턴스다([05] §8.1의 첫 pipe 인스턴스 검사는 그 뒤의 두 번째 방어선이다).
- 두 번째 인스턴스:
  - `--background`(yw-host가 실행, D24): 아무것도 하지 않고 종료 코드 0.
  - 인자 없음(사용자 실행): `ui::find_window(YourWalletV3Main)` → `(poster, pid)` → `process::allow_set_foreground_window(pid)` → `poster.post(WM_YW_ACTIVATE, 0)` → 종료 코드 0. 창을 못 찾으면 200 ms 간격 10회 재시도 후 종료 코드 0.
- 첫 인스턴스가 `WM_YW_ACTIVATE`를 받으면 주 창을 보이고(최소화면 `SW_RESTORE`) `SetForegroundWindow`. 잠겨 있으면 W02도 연다.
- `--background` 첫 인스턴스는 주 창을 숨긴 채 시작하고, 잠금 해제·승인이 필요한 요청이 오면 그 창만 띄운다(§2.5, §3.6).
- 주 창 닫기(X, Alt+F4) = 앱 종료(§1.5). 트레이 아이콘은 없다. 종료 뒤 dApp 요청이 오면 `settings.json`의 `browserAutoLaunch`가 true일 때만 yw-host가 `--background`로 다시 실행한다(D24, [05] §7.4). false면 yw-host가 요청마다 4900으로 응답한다. M5에서 Chrome job object 때문에 yw-app이 Chrome과 함께 종료되면 자동 실행을 끄고 수동 실행으로 바꾼다(D24, [05] §11-3).
- 종료 코드: 0 정상·인계, 2 인자 오류, 10 초기화 실패(데이터 폴더, 창 클래스, 주 창).

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
- `KeyQueue { q: Mutex<VecDeque<KeyJob>>, cv: Condvar }`. `KeyJob::Lock`만 `push_front`로 넣는다([02] §7.2 "lock 요청은 큐 맨 앞"). 키 작업자는 `Lock`을 처리하면서 큐에 남은 다른 작업을 모두 yw-app 오류 `KeyJobError::Locked`로 끝낸다(yw-core `KeyError`가 아님). `Lock`은 진행 중인 작업(최대 Argon2 2회) 뒤에 실행된다.
- 잠금 세대: UI가 `lock_epoch: u64`를 소유하고 §5.3 1단계에서 1 올린다. 모든 `KeyJob`은 넣을 때의 값을 싣고 `KeyResult`가 그 값을 되돌린다. UI는 값이 현재와 다른 결과를 버린다(실린 비밀 버퍼는 drop으로 소거). 예외: `Sign` 결과는 이미 소비된 승인이므로 epoch와 무관하게 처리한다(성공이면 저널 `Signed`가 커밋된 상태이므로 전송까지 진행하고, 잠긴 동안의 상태 처리는 §5.3 마지막 항목). 소비된 `Signing` 항목의 `Sign`이 `Locked`로 끝나면 dApp 4001 `User rejected the request.`, [03] §3.6 송신 슬롯 해제, 저널 기록 없음, 로그 `sign.aborted reason=locked`.
- 비밀 버퍼(비밀번호, passphrase, 니모닉, 개인키 입력)는 `Zeroizing<Vec<u8>>`로 채널에 이동한다(복사 금지). 받은 쪽은 쓰고 바로 drop한다.

### 1.3 이벤트 큐와 메시지 번호
```rust
pub const WM_YW_EVENTS: u32     = WM_APP + 1; // 0x8001, 이벤트 큐 초인종
pub const WM_YW_ACTIVATE: u32   = WM_APP + 2; // 두 번째 인스턴스 → 첫 인스턴스
pub const WM_YW_CHILD_DONE: u32 = WM_APP + 3; // 승인·비밀 창 → 주 창, wParam = 창 id
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
1. `process::init_process()`(`SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x800)`), `ui::init()`(`SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2)` + `InitCommonControlsEx`), `process::exclude_from_error_reporting()`([01] §5.4). 실패해도 계속하고 4단계에서 로그로 남긴다.
2. 인자 확인, 단일 인스턴스 뮤텍스(§1.1).
3. 환경 변수 `LOCALAPPDATA`가 절대 경로가 아니면 종료 코드 10. `%LOCALAPPDATA%\YourWallet\v3\`와 `logs\`가 없으면 만든다.
4. 로그 시작(§8), `app.start`(버전, OS 빌드, `--background` 여부).
5. `settings.json`(§6.1), `apikeys.dpapi`(§6.3) 읽기. 실패 항목은 기본값 + 배너.
6. 창 클래스 등록(§1.7), 주 창 생성(숨김). `session::register_session_notifications(&main)`(`WTSRegisterSessionNotification`, `NOTIFY_FOR_THIS_SESSION = 0`). 실패하면 1초 간격 최대 30회 재시도, 끝내 실패하면 배너 E-APP-004.
7. 키·RPC·read 작업자, pipe 서버 시작([05]: 프로세스 시작 2 s 안). pipe 생성 실패는 치명이 아니다(배너 E-PIPE-001, 브라우저 연동 없이 계속).
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
- 구현 시 확인: yw-app `build.rs`의 `cargo:rustc-link-arg-bins=/MANIFEST:EMBED`·`/MANIFESTINPUT:<yw-app.manifest>`로 comctl32 v6·PerMonitorV2 매니페스트를 넣을 수 있는지. 안 되면 매니페스트 없이 위 API 호출과 고전 모양 표준 컨트롤을 쓴다(기능 영향 없음).
- 테마는 라이트만. 글꼴: 본문·라벨·버튼 `Malgun Gothic`(없으면 `Segoe UI`) 10pt, 화면 제목 굵게 13pt, 승인 창 제목 굵게 12pt, 주소·해시·hex·개인키 `Consolas` 10pt, 니모닉 표시 `Consolas` 14pt, calldata 등 hex 원본 `Consolas` 9pt.
- 색 토큰(`ui::theme`, [06]이 참조):

```text
BG #FFFFFF 창 배경          TEXT #1F1F1F 본문             MUTED #5F6368 보조 문구·오래된 잔액
BORDER #C8C8C8 구분선        FOCUS #0F6CBD 포커스·진행 막대   ESCAPE_TEXT #A4262C 이스케이프 표기(§3.3)
DANGER_BG #FDE7E9 / DANGER_TEXT #A4262C 고위험·차단        WARN_BG #FFF4CE / WARN_TEXT #7A5C00 주의·주소 주석
TESTNET_BG #E8F0FE 테스트넷 띠·배지   AI_PANEL_BG #F3F0FA [06] AI 패널   QR_DARK #000000 / QR_LIGHT #FFFFFF
```

### 1.7 창 클래스
시작 때 한 번만 등록한다(이식 코드처럼 호출마다 `RegisterClassW`를 부르지 않는다).

| 클래스 | 용도 | 스타일 | 확장 스타일 | 비밀 클래스 |
|---|---|---|---|---|
| `YourWalletV3Main` | 주 창(화면은 자식 패널) | `WS_OVERLAPPEDWINDOW` | `WS_EX_APPWINDOW` | 아니오 |
| `YourWalletV3Panel` | 화면 패널, 직접 그리는 목록 | `WS_CHILD\|WS_CLIPCHILDREN\|WS_VSCROLL` | — | 아니오 |
| `YourWalletV3Approval` | 승인·연결 창 | `WS_OVERLAPPED\|WS_CAPTION\|WS_SYSMENU\|WS_THICKFRAME\|WS_MINIMIZEBOX` | `WS_EX_TOPMOST\|WS_EX_APPWINDOW\|WS_EX_DLGMODALFRAME` | 아니오 |
| `YourWalletV3SecretInput` | 비밀 입력 창 W01–W07, W10 | `WS_OVERLAPPED\|WS_CAPTION\|WS_SYSMENU` | `WS_EX_APPWINDOW\|WS_EX_DLGMODALFRAME` (dApp 요청으로 연 W02·W06은 `\|WS_EX_TOPMOST`) | 예, `capture: CaptureExclusion::Preferred` |
| `YourWalletV3SecretView` | 비밀 표시 창 W08·W09 | `WS_OVERLAPPED\|WS_CAPTION\|WS_SYSMENU` | `WS_EX_APPWINDOW\|WS_EX_DLGMODALFRAME` | 예, `capture: CaptureExclusion::Required` |

- 비밀 클래스는 `ClassSpec { name, secret: true, capture }`로 등록한다([01] §7.7). `capture`는 캡처 제외 실패 처리다(§4.5): `Required` = 창 파괴·비밀 미표시, `Preferred` = 창 유지·경고 배너. 비밀 아닌 클래스에는 캡처 제외를 적용하지 않는다.

주 창 960×680 DIP(최소 720×520), 비밀 창 640×480(W08·W09는 820×680), 승인 창 §3.6.

### 1.8 yw-win 사용 API
이름·시그니처·오류 타입의 정본은 [01] §7이다(D31). yw-app이 쓰는 것:

| 용도 | yw-win API([01] §7) |
|---|---|
| 창 | `ui::{init, register_class(&ClassSpec { name, secret, capture: CaptureExclusion }), create_window(&WindowSpec, Box<dyn Handler>) -> Result<Window, UiError>}`, `Handler::on(&mut self, &Window, &Msg) -> Reply`, `Window::{show, hide, …, poster}`, `ui::controls`(비밀 아닌 값) |
| 루프·깨우기 | `ui::run_loop(observe)`(§5.1 유휴 입력), `ui::Poster::post(msg, wparam)`(§1.3) |
| 캡처 제외 | `ui::exclude_from_capture(&Window) -> Result<(), UiError>`(`UiError::CaptureExclusionFailed`). 비밀 클래스는 `create_window`가 숨긴 채 적용하고, 실패 처리는 `ClassSpec.capture`(`CaptureExclusion::{Required, Preferred}`)를 따른다(§1.7, §4.5) |
| 그리기·입력 | `PaintDc::{fill_rect, draw_text, measure, select_font}`, `Font::create`, `input::is_down(vk)` |
| 클립보드 | `clipboard::{set_text, set_secret_text -> u32, read_text(owner, max) -> (WipeBuf<u16>, u32), clear_if_unchanged}`, `ClipError::{Busy, TooLong, Os}` |
| 단일 인스턴스 | `process::SingleInstance::acquire`, `ui::find_window -> Option<(Poster, u32)>`, `process::allow_set_foreground_window`(§1.1) |
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
- 체인 확인 결과 표시(EVM, 판정은 [03] §1.4): chainId 불일치 → E-RPC-006. 제네시스 불일치는 상수 제네시스 체인(1·11155111)이면 E-RPC-006, 최초 신뢰로 고정한 체인(HyperEVM 999·사용자 체인)이면 E-CHN-008 "체인 정보가 바뀌었습니다 (제네시스 불일치)" + `다시 고정`(§2.17.4). 두 경우 모두 그 체인은 읽기·보내기·서명이 차단된다. HyperEVM은 고정값이 없을 때 첫 체인 확인(`eth_chainId` 일치)에서 받은 블록 0 해시를 고정한다: RPC 작업자가 `UiEvent::Rpc`로 알리면 UI 스레드가 `settings.json` `evmGenesisPins`(§6.1)에 쓰고 배너 T-GENESIS-PINNED. 쓰기 실패 → E-APP-002, 이번 실행 동안 메모리 값으로 비교한다. 여러 작업자가 동시에 관측하면 먼저 온 값을 고정하고 나머지는 비교한다.
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
- 주 창 화면: S01 첫 실행(`NoVault`), S02 생성 안내, S03 처리 중(KDF 진행 표시), S04 백업 대기(`BackupPending`), S05 가져오기, S06 첫 주소 확인, S07 잠금 화면(`Locked`·`PassphraseRequired`), S08 완료, S09 복구(`Corrupt`·`MainMissing`), S10 메인(`Unlocked`), S11 보내기·결과, S12 받기, S13 연결된 사이트, S14 주소록, S15 설정, S16 토큰 추가, S17 EVM 체인 추가·편집(§2.17).
- 별도 최상위 창: W01–W10 비밀 창(§4.1), A01 승인·연결 창(§3).
- 비밀 창이 열려 있는 동안 주 창은 `EnableWindow(FALSE)`다. 승인 창은 주 창을 막지 않는다.
- `Unlocked`의 상단 막대: 체인 탭, 네트워크 선택, `연결된 사이트`, `주소록`, `설정`, `잠금`(Ctrl+L). `alt_passphrase == true`이면 상시 배너 T-ALT-PASS([02] §7.5).

### 2.2 첫 실행 (S01)
- `NoVault`일 때. 데이터 폴더에 `meta.ywm`·`journal.ywj` 또는 그 `.prev`가 남아 있으면 생성·가져오기 버튼을 끄고 T-LEFTOVER와 폴더 경로, `폴더 열기`(§2.14)를 보인다. 파일은 사용자가 직접 옮긴다([02] §6.3). 앱은 지갑 파일을 옮기거나 지우지 않는다.
- 문구 T-FIRST-1, 버튼 `새 지갑 만들기`, `기존 지갑 가져오기`.

### 2.3 새 지갑 만들기
| 단계 | 화면 | 동작·검증 |
|---|---|---|
| 1 | S02 | T-CREATE-1. `다음`. |
| 2 | W01 | 비밀번호 2회. [02] 규칙(D8: 0x20–0x7E, 12–128자) 위반 E-INP-001, 불일치 E-INP-002. passphrase는 묻지 않는다([02] §8.1). |
| 3 | S03 | `KeyJob::CreateWallet` → `Vault::create_wallet` → `BackupPending`, 24단어 버퍼 반환. 이어서 기본 meta 쓰기. "지갑을 만드는 중입니다. 몇 초 걸립니다." |
| 4 | W08 | 24단어 + 계정 0 EVM 주소(EIP-55, `m/44'/60'/0'/0/0`). 둘 다 종이에 적게 한다([02] §8.3). 캡처 제외 실패 시 표시하지 않고 E-SEC-001(§4.5 `Required`; 지갑은 `BackupPending`으로 남고 S04에서 다시 시도). `다 적었습니다`를 2초 길게 눌러야 다음으로 간다. |
| 5 | W10 | `backup_challenge()`의 위치 4개 단어 + 첫 주소 끝 6자. `KeyJob::ConfirmBackup` → `confirm_backup`. `BackupMismatch` → T-BACKUP-FAIL, 새 challenge(새 위치)로 다시 입력. 횟수 제한 없음. |
| 6 | S08 | T-BACKUP-OK. 저장된 RPC 엔드포인트(§6.3 `rpc:*`)가 하나도 없으면 `RPC 엔드포인트 설정`(S15 `RPC 공급자`, §2.11.1)과 `나중에`. → S10. |

S04(백업 대기): 잠금 해제 직후 백업이 확인되지 않았을 때. T-BACKUP-PENDING, 버튼 `니모닉 보고 백업 확인`(W03 → W08 → W10), `받기`(S12, 상단 경고 T-BACKUP-RECV), `잠금`. 서명·개인키 표시·개인키 가져오기는 없다([02] §7.1). 이 상태에서 dApp 승인 항목은 즉시 `NotReady`.

### 2.4 기존 지갑 가져오기 (니모닉)
| 단계 | 화면 | 동작·검증 |
|---|---|---|
| 1 | S05 | 안내 "12·15·18·21·24단어 BIP39 영어 니모닉을 가져옵니다." EVM 개인키는 지갑을 만든 뒤 `계정 추가`에서 가져온다([02] §8.2). |
| 2 | W01 | 비밀번호 2회(§2.3). |
| 3 | W05 | 니모닉 입력(§4.2). 단어마다 BIP39 목록 검사(E-INP-004 "{n}번째 단어"). `다음`은 단어 수가 12/15/18/21/24이고 모든 단어가 목록에 있을 때만 켜진다. 체크박스 `BIP39 passphrase 사용`(기본 끔, T-IMPORT-PASS). |
| 4 | W06 | (체크한 경우) passphrase 2회, 0x20–0x7E 1–256자(D8). 불일치 E-INP-002. |
| 5 | S03→S06 | `KeyJob::PreviewImport`: 키 작업자가 버퍼를 `PendingImport`로 보관하고, yw-core 파생 함수로 vault 없이 계정 0 EVM 주소만 계산한다(체크섬 오류 E-INP-005). S06: T-IMPORT-ADDR + 주소 전체. `맞습니다` → 6. `다릅니다`·취소·잠금 → `KeyJob::DiscardImport`(소거) 후 3으로. |
| 6 | S03 | `KeyJob::CommitImport` → `Vault::import_mnemonic`(백업 확인됨, `Unlocked`) → 기본 meta 쓰기 → 버퍼 소거. 계정은 EVM 인덱스 0 하나(자동 계정 탐색 없음). |
| 7 | S08 | → S10. |

비밀 버퍼는 5단계에서 키 작업자로 이동한다. 그 전에 취소하면 UI가 즉시 소거한다.

### 2.5 잠금 해제 (S07, W02, W06)
- S07: "지갑이 잠겨 있습니다.", `잠금 해제`(W02). 기다리는 dApp 요청이 있으면 T-UNLOCK-PENDING과 origin 목록(최대 5개, 나머지 "외 n건"). 계정·잔액·주소는 보이지 않는다(meta가 잠겨 있다).
- W02 비밀번호 → `KeyJob::Unlock` → S03("확인 중…").
  - `UnlockFailed` → E-VLT-001([02] §7.4 문구). 칸을 비우고 입력과 확인 버튼을 1초 비활성화. 횟수 제한 없음.
  - `PassphraseRequired` → W06(passphrase 1칸) → `enter_passphrase`. `PassphraseMismatch` → 오버레이 T-PASS-MISMATCH: `다시 입력`(W06), `이 passphrase로 계속`(체크 "다른 passphrase는 다른(빈) 지갑을 엽니다"를 켜야 활성) → `Unlocked { alt_passphrase: true }`.
  - VirtualLock 실패(yw-win 슬롯 할당 실패, `OutOfMemory`) → E-VLT-007, 잠금 해제하지 않는다([02] §7.3 권고).
  - 성공: `BackupPending`이면 S04, 아니면 meta 읽기 → S10. meta·journal이 `SidecarCorrupt`·`SidecarVaultMismatch`면 오버레이 E-VLT-006에서 `이전 사본(.prev) 사용` 또는 `격리하고 새로 시작`을 고르게 한다(journal은 T-JOURNAL-RESET 확인 후에만, [02] §6.3). 이어서 저널 복구([03])와 승인 큐 처리(§3.7).
- dApp 요청 때문에 자동으로 연 W02·W06은 `WS_EX_TOPMOST`이고 전경이 아니면 작업 표시줄을 깜박인다(§3.6). 이 창의 `나중에`(Esc)는 잠금 해제를 기다리던 dApp 항목을 모두 `Rejected`로 끝낸다([05] §4.4: 해제 창은 하나, 결과 공유). 사용자가 직접 연 창의 `나중에`는 창만 닫는다.
- S09(`Corrupt`·`MainMissing`): E-VLT-002 또는 "지갑 파일이 없고 이전 사본(.prev)이 있습니다." `.prev`가 있으면 `이전 사본으로 복구`(W03 → `recover_from_prev`, 문구 T-RECOVER-PREV), 없으면 폴더 경로와 `폴더 열기`, `종료`. 손상 파일은 덮어쓰지 않는다.

### 2.6 메인 (S10)
- 체인 탭: 구현된 단계만(M4 `EVM`, M7 `Solana`, M8 `Bitcoin`). 개인키 계정만으로는 SOL·BTC를 쓸 수 없다.
- EVM 네트워크 선택: 기본 체인 3개(`Ethereum 메인넷`, `Sepolia 테스트넷`, HyperEVM; 이름은 [03] §1.1) 다음에 사용자 체인(§2.17, `evmChains` 순서, 이름 옆 배지 T-CUSTOM-CHAIN). 차단된 체인(E-RPC-006·E-CHN-008)도 목록에 남기고 "(차단됨)"을 붙인다. 고르면 S10에 그 오류 배너와(E-CHN-008이면) `설정에서 다시 고정`(S15)을 보이고 잔액·보내기는 끈다. 선택은 `settings.json` `evmChainId`(§6.1, D30)이고, 잠긴 동안 [05]가 캐시 없는 origin의 `eth_chainId`로 쓴다. Solana 클러스터는 `solana.cluster`([07] §10), BTC 네트워크는 `bitcoin.network`([08] §2, D26)로 모두 `settings.json`에 있다. 테스트넷(Sepolia, [07]·[08]의 테스트 네트워크)이면 상단에 `TESTNET_BG` 띠 "테스트넷 — 실제 자산이 아닙니다". 사용자 체인에는 테스트넷 구분이 없으므로 띠를 그리지 않는다.
- 상태 줄: `RPC: 연결됨 | 엔드포인트 없음 (E-KEY-005) | 오류 E-RPC-0nn | 차단 E-CHN-008`(네트워크 이름만, URL·호스트 없음, §1.9), `브라우저: 연결 n개 | 연결 없음 | 사용 불가 E-PIPE-001`. 엔드포인트 없음이면 잔액·보내기를 끄고 `설정에서 URL 입력`(S15 §2.11.1)을 보인다.
- 계정 목록: 라벨, 전체 주소(§3.3 주소 그리기), 기본 자산 잔액, 경로 또는 `가져온 개인키`. 선택 행 버튼: `보내기`, `받기`, `이름 바꾸기`, 파생 계정 `숨기기`(meta `hidden`), 개인키 계정 `삭제`(W03 → `remove_evm_raw_key`). 숨기기·삭제는 [05] §4.1에 알린다(grant에서 제외).
- `계정 추가`: 다음 EVM 인덱스(기본 라벨 "계정 {i+1}"), 또는 `개인키 가져오기`(W07 → `import_evm_private_key`, `Unlocked`에서만). 상한은 [02] §5.3(파생 100, 개인키 15).
- 토큰 잔액: 레지스트리 토큰([03])과 meta `tokens`. `토큰 추가`(S16).
- 잔액 갱신: S10 진입 시, `새로고침`, S10이 보이고 `Unlocked`인 동안 60초마다. 값 옆에 기준 블록 번호. 실패하면 이전 값을 `MUTED`로 두고 오류 코드를 붙인다.
- 활동: meta `activity`([02] §5.3 `ActivityEntry`, 모든 체인 공통 스키마; 이 지갑이 보낸 거래만, 네트워크당 최대 500)와 진행 중 저널 항목. 받은 거래 목록은 만들지 않고, 활동의 주소에는 복사·선택 버튼을 두지 않는다(주소 오염 대비, [07] §12.3). 행 = 로컬 시각, 계정 라벨, 종류·금액([03]/[07]/[08] 문자열), 상태, 해시 전체, `해시 복사`, 탐색기 URL이 있는 사용자 체인(§2.17)이면 `탐색기 링크 복사`(`{explorer}/tx/{해시}`를 `clipboard::set_text`; 앱은 URL을 열지 않는다, §2.14). 진행 중 EVM 거래에는 `가속`·`취소`([03] `EvmSpeedUp`·`EvmCancel`), BTC 거래에는 `수수료 올리기`([08] §9)가 있고 모두 새 승인 창을 거친다.
- 저널 손상([03]): EVM 보내기를 끄고 배너 "거래 저널이 손상되어 보내기를 멈췄습니다. (E-VLT-006)". 자동 삭제하지 않는다.

S16 토큰 추가: 컨트랙트 주소(§2.15) → RPC `decimals()`·`symbol()`([03]) → "decimals: n, 체인에서 읽은 기호: X". 기호는 `^[A-Za-z0-9]{1,11}$`일 때만 보이고 아니면 "(표시할 수 없는 기호)". 사용자가 라벨(§2.10 규칙, 기본값 = 통과한 기호)을 확인해야 meta `tokens`에 저장된다. 이후 이 라벨과 컨트랙트 주소를 함께 보인다.

### 2.7 보내기 (S11, EVM 네이티브 자산·ERC-20)
| 필드 | 입력 | 검증 |
|---|---|---|
| 보내는 계정 | 선택 계정(변경 가능) | — |
| 자산 | 기본 자산 또는 계정의 토큰 | — |
| 받는 주소 | EDIT, 붙여넣기 허용, `주소록에서 선택`(주소록·내 계정만, 입력한 글자로 거른 목록). 최근 받는 사람·활동에서 고르기는 없다 | §2.15 |
| 금액 | EDIT 10진 문자열, `최대` 버튼 | §2.15 |

- 수수료는 지갑이 계산하며(D20, [03] §3.4) 선택지가 없다. 입력이 모두 유효하면(입력 정지 후 500 ms) "예상 최대 수수료: {X} {네이티브 심볼} (가스 한도 {g} × 최대 {f} gwei)"를 보인다. 그 체인의 상한(§6.1 `feeCaps`) 초과는 E-TX-001로 막는다(D16의 차단 조건).
- `최대`: 네이티브 자산이면 잔액 − 가스 한도 × maxFeePerGas(최신 견적), 0 이하면 E-INP-012. 토큰이면 토큰 잔액 전부.
- (체인, 계정)에 진행 중 거래가 있으면(D20) 폼을 끄고 T-SEND-INFLIGHT와 그 거래의 상태·해시를 보인다.
- `검토`는 차단 오류가 없고, W-ADDR-3이면 `주소 전체를 직접 확인했습니다`를 체크했을 때 켜진다.
- `검토` → 준비·시뮬레이션([03]) → A01(출처 "Your Wallet (이 앱)"; 시뮬레이션이 성공하지 못해도 고위험 확인 후 승인할 수 있다, §3.2.1, D15) → 승인 → 서명·저널·전송([03]) → 결과 화면("전송했습니다" + 해시 + 상태). 거부 → 폼으로(입력 유지). 만료(§3.5, 표시 + 120 s) → 창이 `Expired`로 닫히고 폼으로(입력 유지) + T-APPR-EXPIRED. 다시 `검토`하면 준비부터 다시 하고 새 승인(새 id, 새 `ApprovalStore::issue`)을 만든다. 모든 체인(EVM·SOL·BTC) 공통이다.
- SOL·BTC 보내기 폼의 필드와 순서는 [07] §13·[08] §7–8이 정하고, 입력 칸·검토·승인 창 규칙은 이 절과 §3을 따른다. 수수료를 직접 입력해 상한을 푸는 [08] §8.3 확인은 보내기 폼에서 한다(승인 창에는 입력 칸이 없다).

### 2.8 받기 (S12)
- 표시: 계정 라벨, 네트워크(테스트넷이면 `TESTNET_BG` 배지와 "테스트넷 주소입니다"), 전체 주소(§3.3 주소 그리기, 12pt), 파생 경로, QR. 주소는 vault에서 다시 파생한 값이다([02] §5.3).
- QR 내용: EVM `ethereum:<EIP-55 주소>@<chainId>`(EIP-681, 이식 `archive/spec-v2.4:demo/sepolia-wallet/src/receive_qr.rs:132-139`, chainId 매개변수화), SOL base58 그대로([07] §12.3), BTC `bitcoin:` + 소문자 주소([08]).
- 생성 `qrcodegen::QrCode::encode_text(payload, QrCodeEcc::Medium)`. 그리기: 조용한 영역 4모듈, 모듈 = max(6, round(8 × dpi / 96)) 정수 픽셀, GDI `FillRect`로 `QR_LIGHT` 바탕에 `QR_DARK`. 6 px 모듈이 들어가지 않으면 QR 대신 "창을 넓히면 QR이 표시됩니다"(배치 규칙 이식 `receive_qr.rs:51-130`). 행렬은 캐시하지 않는다.
- `주소 복사`: `clipboard::set_text`(일반 복사). 이어서 "주소를 복사했습니다. 붙여넣은 곳에서 주소 전체를 확인하세요."

### 2.9 연결된 사이트 (S13)
- meta `connected_sites`([02] §5.3 `ConnectedSite`, 최대 256개, 의미는 [05] §4.1): origin 전체, 허용 계정 `accounts`(1–16개, 반환 순서, 첫 번째 = 선택 계정, 전체 주소), 체인 `chain_id`, 연결 시각 `granted_at_unix_ms`. `http` origin에는 "로컬 개발 사이트(http)" 배지.
- `연결 해제`(행), `모두 해제`(확인 오버레이) → [05] §4.5. 그 origin의 대기 항목은 `Revoked`(§3.7).

### 2.10 주소록 (S14)
- 항목 = meta `address_book`의 `AddressBookEntry {chain, address, label, verified, added_at_unix_ms}`([02] §5.3, 최대 500; `added_at_unix_ms` = 추가 시각 unix ms). `verified` = 체크박스 "다른 경로(전화·대면 등)로 이 주소를 확인했습니다".
- 주소: 체인별 검증(§2.15)과 정규형 저장. 같은 체인에 같은 주소가 있으면 E-INP-016.
- 이름(주소록·계정·토큰 라벨 공통): [02] `Label` 규칙(1–32 스칼라, 금지 문자, 앞뒤 공백 금지)에 더해 §3.3 표시 금지 문자도 거부한다 → E-INP-017.
- `추가`, `편집`, `삭제`(확인 오버레이). 쓰기는 키 작업자의 meta 저장(원자적, [02] §6).

### 2.11 설정 (S15)
| 구역 | 항목 | 동작 |
|---|---|---|
| 보안 | 자동 잠금(분) | 1–60, `autoLockMinutes` |
| 보안 | 니모닉·개인키 복사 허용 | 켤 때 T-COPY-ON 오버레이 확인, `allowSecretCopy` |
| 보안 | 니모닉 보기 / 개인키 보기 / 비밀번호 변경 | §2.12, §2.13 |
| 네트워크 | RPC 공급자 | 템플릿 라디오(`rpc.template`, §6.1): `QuickNode 멀티체인`(엔드포인트 이름 EDIT + 토큰 EDIT `ES_PASSWORD`) / `알케미`(키 EDIT `ES_PASSWORD`) / `직접 입력`(입력 칸 없음). 입력 칸은 붙여넣기 허용·복사 불가. `저장`·`삭제`(선택한 템플릿의 자격 정보, §6.3 `tpl:quicknode`·`tpl:alchemy`; 저장된 값은 다시 보이지 않고 "설정됨/없음"만), `네트워크 URL 생성`(§2.11.1, `직접 입력`이면 비활성). 자격 정보를 바꾸거나 지워도 이미 만든 URL은 그대로다(런타임은 네트워크별 URL만, §1.9) |
| 네트워크 | 네트워크 URL | §2.11.1 목록: `NetworkId`마다(기본 EVM 3 + 사용자 체인 + `solana:*` 2 + `bitcoin:*` 2) 상태·가린 URL, `교체`·`테스트`·`삭제`(§6.3 `rpc:<NetworkId>`) |
| 네트워크 | EVM 체인 | 목록: 기본 3개(1·11155111·999) + 사용자 체인(최대 32, §2.17). 행 = 이름, chainId, 네이티브 심볼·소수 자릿수, 엔드포인트 상태(설정됨·없음; URL은 `네트워크 URL` 목록에서 가린 형태로만), 사용자 체인의 템플릿 식별자(`quicknodeSubdomain`·`alchemyLabel`, 있으면; 비밀 아님), 시뮬레이션 `auto`/`unsupported`, 고정 제네시스 해시(전체 hex; HyperEVM 고정 전은 "첫 연결 때 고정"), 상태(연결됨·확인 전·차단). `추가`(S17), 사용자 체인 행의 `편집`(S17)·`삭제`(§2.17.3), 최초 신뢰 체인이 E-CHN-008이면 `다시 고정`(§2.17.4). 기본 체인은 편집·삭제가 없다 |
| 네트워크 | EVM 수수료 상한 | 체인 선택(기본 3 + 사용자 체인) + 3값(§6.1 `feeCaps`), `기본값으로`. 기본값은 [03] §3.4(기본 체인 `default_caps`, 사용자 체인은 [03]의 보수적 기본값) |
| Solana (M7) | 클러스터, 수수료 상한, 다른 경로 스캔 | [07] §10·§3.3. 엔드포인트는 `네트워크 URL` 목록의 `solana:<cluster>` 행(§6.3 `rpc:solana:<cluster>`) |
| Bitcoin (M8) | 켜기·네트워크 선택 | `bitcoin.enabled`·`bitcoin.network`(§6.1), 켜기·네트워크 변경 조건은 [08] §2(그 네트워크의 `rpc:bitcoin:<net>` URL이 없으면 켤 수 없음, E-KEY-005; 인덱서와 무관). Core 엔드포인트는 `네트워크 URL` 목록의 `bitcoin:<net>` 행([08] §4.2) |
| Bitcoin (M8) | 인덱서 | 라디오 `bitcoin.indexer`: `Esplora`(기본, 무료·키 없음) / `Blockbook JSON-RPC (bb-rpc)`(Core URL에 `bb_*`, QuickNode BTC Blockbook 유료 애드온 필요) / `Blockbook REST (bb-rest)`(Core URL `/api/v2/`, 알케미 UTXO API). 형식은 URL·호스트에서 추론하지 않는다([08] §2). `bb-rpc`·`bb-rest`를 고르면 오버레이 T-BTC-BB-OPTIN 확인 뒤 저장한다. 언제든 바꿀 수 있고 바꾸면 새 `RpcConfig` + [08] §2 연결 검사. 라디오 아래 고정 문구 T-BTC-ESPLORA-NOTE |
| Bitcoin (M8) | Esplora URL | 네트워크마다 한 줄(`mainnet`·`testnet4`): 현재 값 전체(비밀이 아니므로 가리지 않음) + 일반 EDIT(붙여넣기·복사 허용) + `저장`(§6.1 형식, 위반 E-BTC-006) · `기본값으로`([08] §15 `BTC_ESPLORA_DEFAULT_*`) · `테스트`. `테스트` = EDIT 값(비어 있으면 저장된 값)으로 `GET <URL>/block-height/0` 1회(호출당 10 s, 재시도 없음; 주소를 보내지 않으므로 잠긴 상태에서도 허용, [08] §4.4): 본문이 그 네트워크의 [08] §2 제네시스면 T-BTC-IDX-OK, 다른 64자 hex면 E-BTC-003, 그 밖은 [08] §4.3 분류(E-BTC-001·004·007). `저장`은 `테스트`를 요구하지 않는다(사용 전 [08] §2 연결 검사 3단계가 다시 확인). `indexer`가 `esplora`가 아니어도 편집할 수 있다. 저장 → 새 `RpcConfig` + [08] §2 연결 검사, 로그 `btc.esplora_url_set net=<NetworkId>`(URL 없음) |
| 브라우저 | localhost dApp 허용 | 켤 때 T-LOCALHOST-ON 확인, `allowLocalhostDapps`(D22, [05] §4.6) |
| 브라우저 | dApp 요청 시 앱 자동 실행 | `browserAutoLaunch`(D24, 기본 켬). 끄면 yw-app이 꺼져 있을 때 dApp 요청은 4900 |
| 브라우저 | 연결된 사이트 | S13 |
| AI 설명 (M6) | [06] §2 | [06] |
| 진단 | 로그 수준, 로그 폴더 열기 | §8, §2.14 |
| 정보 | 버전, 데이터 폴더 경로, `폴더 열기` | §2.14 |

- 템플릿 자격 정보 형식(`저장` 때 검사, 위반 E-KEY-002 + 항목 이름): QuickNode 엔드포인트 이름은 소문자로 바꾼 뒤 `^[a-z0-9]+(-[a-z0-9]+)*$` 1–63자(호스트 첫 라벨), QuickNode 토큰 `^[A-Za-z0-9_-]{16,128}$`(URL 경로 한 단계), 알케미 키 `^[A-Za-z0-9_-]{16,128}$`(URL 경로). 구현 시 확인: 실제 이름·토큰·키의 길이·문자 집합. 다르면 이 정규식만 고친다.
- 변경은 즉시 `settings.json`에 원자적으로 쓴다(`apikeys.dpapi` 항목은 §6.3). 실패 → E-APP-002, 화면 값을 되돌린다.
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
2. 대상 = 등록된 모든 네트워크(기본 EVM 3, 사용자 체인, `solana:*` 2, `bitcoin:*` 2) 중 `template_url`이 `Some`인 것. 오버레이 T-RPC-GENERATE: 대상(네트워크 이름·`NetworkId`, 이미 URL이 있으면 "기존 URL 있음"), 템플릿 항목이 없어 건너뛰는 네트워크, 체크박스 `기존 URL 덮어쓰기`(기본 끔). `생성` / `취소`.
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
3. `개인키 보기`: EVM 계정 선택 → W03 → `reveal_evm_private_key`(`Unlocked`만) → W09(소문자 hex 64자, [02] §9 형식 그대로). SOL·BTC 개인키 표시는 없다.
4. `UnlockFailed` → E-VLT-001, 1초 비활성 후 W03 유지.

### 2.13 비밀번호 변경
W04(현재, 새, 새 확인) → 새 비밀번호 검사(E-INP-001/002) → `KeyJob::ChangePassword` → S03 "비밀번호를 바꾸는 중…". DEK는 그대로이고 다시 감싸기만 한다(D7). 현재 비밀번호 오류 → E-VLT-001(1초 비활성). 쓰기 실패 → E-VLT-003, vault는 이전 상태. 성공 → "비밀번호를 바꿨습니다."

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
| 7 | 같지 않지만 `0x` 뒤 앞 4자와 끝 4자가 주소록·내 계정 주소와 같음(대소문자 무시) | W-ADDR-3 "'{이름}'과 앞 4자·끝 4자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다.", 확인 체크 필요 |
| 8 | 6·7 해당 없음 | W-ADDR-2 "주소록에 없는 주소입니다. 주소 전체를 확인하세요." |
| 9 | (네이티브 자산) `eth_getCode`가 비어 있지 않음 | W-ADDR-4 "컨트랙트 주소입니다. 받는 쪽이 이 자산을 처리할 수 있는지 확인하세요." |

**금액**: 이식 `archive/spec-v2.4:demo/sepolia-wallet/src/erc20.rs:222-266` `parse_token_amount`와 [03] `parse_units`. 숫자와 `.` 하나, 부호·지수·쉼표·공백 금지, 소수 자리 ≤ decimals, 0 초과, 입력 ≤ 128바이트 → 위반 E-INP-011. 네이티브 자산(ETH 등, 소수 자릿수는 그 체인 값)은 금액 + 최대 수수료 ≤ 잔액, 토큰은 금액 ≤ 토큰 잔액이고 최대 수수료 ≤ 네이티브 잔액 → 위반 E-INP-012.

**SOL·BTC**: 주소·금액 파서와 유사 주소·처음 보내는 주소 경고는 [07] §12·[08]의 규칙(예: SOL 앞뒤 3자)을 따르고, 6번 주석은 같다.

### 2.16 주요 문구
| ID | 위치 | 문구 |
|---|---|---|
| T-FIRST-1 | S01 | 이 PC에 지갑이 없습니다. 새로 만들거나 기존 니모닉으로 가져오세요. |
| T-LEFTOVER | S01 | 이전 지갑의 파일이 데이터 폴더에 남아 있습니다. 앱을 종료하고 파일을 다른 곳으로 옮긴 뒤 다시 실행하세요. |
| T-CREATE-1 | S02 | 다음 화면에 24단어 니모닉과 첫 주소가 표시됩니다. 종이(또는 금속)에만 적고 사진·클라우드·메신저에 남기지 마세요. 화면 공유·녹화를 끄고 주변에 사람이나 카메라가 없는지 확인하세요. |
| T-PW-RULE | W01·W04 | 비밀번호는 영문·숫자·기호(ASCII) 12–128자입니다. 단어 4개 이상을 이은 긴 문장을 권장합니다. 잊으면 니모닉으로만 복구할 수 있습니다. |
| T-MN-SHOW | W08 | 아래 {n}단어와 첫 주소를 순서대로 적으세요. 이 창은 화면 캡처에서 제외됩니다. |
| T-BACKUP-1 | W10 | 적은 종이를 보고 {p1}, {p2}, {p3}, {p4}번째 단어와 첫 주소의 마지막 6자를 입력하세요. |
| T-BACKUP-FAIL | W10 | 입력한 단어 또는 주소가 맞지 않습니다. 새 위치로 다시 확인합니다. |
| T-BACKUP-OK | S08 | 백업을 확인했습니다. 이제 지갑을 쓸 수 있습니다. |
| T-BACKUP-PENDING | S04 | 백업 확인이 끝나지 않았습니다. 확인 전에는 보내기·서명·dApp 승인을 쓸 수 없습니다. |
| T-BACKUP-RECV | S12 | 백업 확인 전입니다. 확인을 마치기 전에는 큰 금액을 받지 마세요. |
| T-IMPORT-PASS | W05 | 이전 지갑에서 BIP39 passphrase(25번째 단어)를 썼을 때만 켜세요. ASCII만 지원합니다. |
| T-IMPORT-ADDR | S06 | 가져온 지갑의 첫 주소입니다. 이전 지갑에서 쓰던 주소와 전체가 같은지 확인하세요. |
| T-UNLOCK-PENDING | S07·W02 | 잠금 해제를 기다리는 요청 {n}건: {origin 목록} |
| T-PASS-MISMATCH | S07 | passphrase가 다를 수 있습니다. 다른 passphrase는 다른(빈) 지갑을 엽니다. |
| T-ALT-PASS | S10 | 가져올 때와 다른 passphrase로 연 지갑입니다. 계정 이름·주소록·연결 기록이 저장되지 않습니다. |
| T-JOURNAL-RESET | S07 | 거래 저널을 새로 시작하면 진행 중 거래 기록이 사라질 수 있습니다. |
| T-RECOVER-PREV | S09 | 이전 사본으로 복구하면 마지막 변경(예: 가져온 개인키)이 사라질 수 있습니다. |
| T-REVEAL-WARN | S15 | 화면 근처의 사람이나 카메라가 볼 수 있습니다. 계속하려면 비밀번호를 입력하세요. |
| T-COPY-ON | S15 | 복사를 허용하면 니모닉·개인키를 클립보드에 넣을 수 있습니다. 클립보드 기록·클라우드 동기화에서는 제외하고 30초 뒤 지우지만, 그 사이에는 다른 프로그램이 읽을 수 있습니다. |
| T-COPY-OFF | W08·W09 | 복사가 꺼져 있습니다. 설정에서 바꿀 수 있습니다. |
| T-COPIED | W08·W09 | 클립보드에 복사했습니다. 30초 뒤 지웁니다. |
| T-PASTE-CLEARED | W01–W07 | 붙여넣은 뒤 클립보드를 비웠습니다. Windows 클립보드 기록(Win+V)을 쓴다면 그 항목도 지우세요. |
| T-MASKED | W05·W07–W10 | 창이 비활성화되어 내용을 가렸습니다. 창을 클릭하면 다시 표시합니다. |
| T-CAPTURE-WARN | W01–W07·W10 | 화면 캡처 제외가 적용되지 않았습니다. 화면 공유·녹화 중이면 입력하지 마세요. |
| T-LOCALHOST-ON | S15 | 개발용 설정입니다. 켜면 http://localhost 와 http://127.0.0.1 페이지가 지갑 연결을 요청할 수 있습니다. |
| T-SEND-INFLIGHT | S11 | 이 계정의 이전 거래가 아직 확정되지 않았습니다. 확정된 뒤 보낼 수 있습니다. |
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

### 2.17 EVM 체인 추가·편집·삭제 (S17, D14)
기본 체인(1·11155111·999)은 [03] §1.1 상수이며 편집·삭제할 수 없다(RPC URL §2.11.1, 수수료 상한, HyperEVM `다시 고정`만). 사용자 체인은 최대 `MAX_CUSTOM_EVM_CHAINS = 32`개이고, 비밀이 아닌 정의(템플릿 식별자 포함)는 `settings.json` `evmChains`(§6.1), RPC URL은 토큰이 들어 있으므로(D13) `apikeys.dpapi` `rpc:eip155:<chainId>`(§6.3)에 둔다. 런타임은 이 URL만 쓴다(§1.9). S15 `EVM 체인`에서 연다. 추가·편집은 S15를 열 수 있으면 언제나(이미 32개면 `추가` → E-CHN-006), 삭제는 `Unlocked`에서만(§2.17.3). dApp은 체인을 추가할 수 없다(`wallet_addEthereumChain` 거부, D14, [05]).

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
3. 추가면 확인 오버레이 T-CHAIN-PIN: chainId, 이름, RPC(템플릿이면 "QuickNode 서브도메인 {식별자}"·"알케미 라벨 {식별자}", URL이면 §2.11.1 가린 형태), 받은 제네시스 해시 전체(`Consolas`). `고정하고 저장` / `취소`(최초 신뢰, D14).
4. 쓰기: RPC를 넣었으면(URL·식별자 모두) `apikeys.dpapi` `rpc:eip155:<chainId>`에 그 URL을 먼저 쓰고 `settings.json` `evmChains`를 쓴다. 식별자를 넣었으면 그 템플릿 키(`quicknodeSubdomain` 또는 `alchemyLabel`)를 함께 바꾸고, URL을 넣었으면 템플릿 키는 그대로 둔다(나중에 `네트워크 URL 생성`의 `기존 URL 덮어쓰기`에서만 쓰인다). 뒤쪽 쓰기가 실패하면 E-APP-002이고, 추가였으면 남은 URL은 고아 항목으로 다음 읽기에서 무시된다(§6.3). 편집이었으면 URL은 2단계 확인을 통과한 새 값으로 바뀐 채이고 템플릿 키만 이전 값이다. 성공 → 새 `RpcConfig`(§1.9), 그 체인 확인 상태 초기화, "저장했습니다". `feeCaps`는 사용자가 바꿀 때만 쓴다(없으면 기본값, §6.1).

#### 2.17.3 삭제
- `Unlocked`에서만(미종결 저널 확인에 DEK 필요, D10). 거부: 활성 체인(`evmChainId`) → E-CHN-009. 그 체인(`eip155:<chainId>`)에 미종결 저널 레코드([03] §5)나 송신 슬롯·승인 큐 항목([03] §3.6, §3.7)이 있으면 → E-CHN-007.
- 확인 오버레이 T-CHAIN-DELETE → `settings.json`(`evmChains` 항목과 `feeCaps["eip155:<chainId>"]` 제거) → `apikeys.dpapi`(`rpc:eip155:<chainId>` 제거). meta의 그 `NetworkId` `tokens`·`activity`는 지우지 않는다. 그 체인을 가리키는 사이트 연결·origin 체인 캐시 처리는 [05] §4.3.

#### 2.17.4 다시 고정 (E-CHN-008)
- 대상: 최초 신뢰로 고정한 체인(HyperEVM `evmGenesisPins`, 사용자 체인 `genesisHash`)이 E-CHN-008일 때. 상수 제네시스 체인(1·11155111)에는 없다.
- `다시 고정` → `eth_chainId`(≠ chainId면 E-RPC-006, 다시 고정 불가)와 블록 0 해시를 새로 받는다(오류는 §2.17.2-2와 같음) → 오버레이 T-CHAIN-REPIN: 고정된 해시와 새 해시 전체를 위아래로(`Consolas`). 체크박스 T-CHAIN-REPIN-ACK를 켜야 `다시 고정`이 켜진다 → `settings.json` 쓰기 → 새 `RpcConfig`, 체인 확인 상태 초기화.

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
| `Shutdown` | 앱 종료 | 4900 `Wallet connection closed.` |

App 항목(이 앱의 보내기·가속·취소·수수료 올리기)은 dApp 응답이 없다. `Rejected`·`Expired`면 그 흐름을 시작한 화면으로 돌아간다(보내기 폼은 입력 유지, §2.7; `Expired`는 T-APPR-EXPIRED). 다시 검토하면 새 승인을 만든다.

### 3.2 배치 (위 → 아래)
`ApprovalDisplay { title, fields, warnings, risk, ack_required }`와 `DisplayField { key, sub_label, value, critical, volatile }`([03] §11.1)를 다음 영역에 나눠 그린다.

| 영역 | 스크롤 | 내용 |
|---|---|---|
| 제목 표시줄 | — | 고정 `Your Wallet — 승인 요청`(연결은 `Your Wallet — 사이트 연결`) |
| 헤더 | 고정 | 키 `0x0001` 요청 출처, `0x0002` 네트워크, `0x0003` 서명 계정([07]·[08]도 같은 키). 출처가 `http`면 "로컬 개발 사이트(http)", 호스트에 `xn--` 라벨이 있으면 "국제화 도메인(punycode)" 배지([05] §4.2). 사용자 체인이면 배지 T-CUSTOM-CHAIN. 테스트넷이면 `TESTNET_BG` |
| 시뮬레이션 띠 | 고정 | 헤더 바로 아래. `sim_state`가 `Ok`가 아니면 `DANGER_BG` 고위험 띠(§3.2.1). `Ok`·`None`이면 없음 |
| 제목 | 스크롤 맨 위 | `title`(굵게 12pt, 예 `[Sepolia 테스트넷] 토큰 전송: 10 USDC`) |
| 경고 | 스크롤 | `warnings` 순서대로(등급 내림차순, [03] §10.1; 띠로 올린 시뮬레이션 경고는 빼고). 고위험·차단 `DANGER_BG`, 주의 `WARN_BG`, 정보는 일반. `ack_needed`(§3.4)면 경고 목록 아래에 체크박스 **1개** "위 경고를 모두 확인했습니다"(D16, 띠 포함 경고 수와 무관) |
| 자산 변화 | 스크롤 | 머리줄 "시뮬레이션 결과". `Ok`: 키 `0x0110`–`0x0113`, `0x0130`(시뮬레이션 기준). `Incomplete`: 받은 행 + `MUTED` T-SIM-PARTIAL. `Unsupported`·`NoResult`·`Reverted`: `MUTED` T-SIM-NODIFF. SOL·BTC는 해당 문서의 금액·수수료·잔돈 행 |
| 상세 | 스크롤 | 나머지 필드를 `fields` 순서대로 |
| 원본 데이터 | 스크롤 | `critical == false`이고 키가 `0x0140`–`0x014F`(액세스 리스트, calldata)인 필드. 머리줄 `원본 데이터 ▸`로 접힘. `risk ≥ High`면 펼친 채 시작 |
| AI 설명 | 고정 | M6, [06] §6: 버튼 바로 위, 본문 10줄 높이를 미리 확보 |
| 하단 | 고정 | 상태 줄(남은 시간 `m:ss`, "대기 중인 다른 요청 n건", 길게 누르기 진행), 버튼 `거부` `승인`, 대기 요청이 있으면 링크 버튼 `이 사이트의 대기 요청 모두 거부` |

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
- **자르지 않는다.** 값은 줄바꿈하고 넘치면 스크롤한다. 말줄임표·툴팁 전용 표시는 없다. 접을 수 있는 것은 원본 데이터 영역(비-critical)뿐이다.
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
매 이벤트와 50 ms 타이머마다 `set_armed(now, can_approve(..))`. `승인` 버튼은 `armed`일 때만 활성 모양이다. 차단 등급이면 버튼 글자 "승인할 수 없음".

| Win32 입력 | `InteractionEvent` |
|---|---|
| `승인` 위 `WM_LBUTTONDOWN`(+`SetCapture`) | `PointerPressed { inside, click_through: !창이 전경이었음, physical_down }` |
| 캡처 중 `WM_MOUSEMOVE` / `WM_LBUTTONUP`(+`ReleaseCapture`) | `PointerMoved { inside }` / `PointerReleased { physical_down }` |
| `승인` 포커스에서 `WM_KEYDOWN VK_SPACE` / `WM_KEYUP VK_SPACE` | `SpacePressed { repeat: lParam bit 30, physical_down }` / `SpaceReleased { physical_down }` |
| `승인` 포커스에서 Enter | `ApproveActivated`(High에서는 무시) |
| `거부` 클릭, `거부` 포커스에서 Enter·Space, Esc, X, Alt+F4 | `RejectActivated` |
| `WM_KILLFOCUS`(다른 창으로) / `WM_ACTIVATEAPP(0)` / 예기치 않은 `WM_CAPTURECHANGED` / `WM_CANCELMODE` | `FocusLost` / `ForegroundLost` / `CaptureLost` / `CancelMode` |
| `WM_TIMER` 50 ms | `Tick` |

- 정보·주의: 클릭(같은 버튼 위에서 누르고 떼기) 또는 `승인` 포커스에서 Enter·Space([03] §10.1).
- 고위험(시뮬레이션 비성공 포함): 버튼 글자 "승인 (2초 길게 누르기)". 확인 체크를 켠 뒤 마우스나 Space로 2초 연속 누른다(D16, 모든 체인 공통). 진행은 버튼 위 막대(`FOCUS`)와 "{0.0}초". Enter 무시. 시뮬레이션 진행 중에는 버튼 글자 "시뮬레이션 중…"과 스피너, 비활성.
- 초기 포커스 `거부`. Tab: `거부` → 확인 체크박스 → `승인` → `원본 데이터` → 스크롤 영역. 스크롤: 휠, PageUp/PageDown, 스크롤 영역 포커스에서 화살표.
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
- 기본 820×710 DIP, 최소 520×460(이식 `native.rs:40-60`). 작업 영역보다 크면 맞춘다. 주 창이 있는 모니터(없으면 기본 모니터) 가운데.
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
내용·상태·문구는 [06]. 이 문서의 규칙: 하단 고정 영역의 버튼 위, 배경 `AI_PANEL_BG`, 제목 "AI 설명 (참고용, 틀릴 수 있음)", 키보드 포커스 없음, 결과가 와도 다른 영역의 배치 불변, 문자열은 §3.3 렌더러로 그린다. `can_approve`·`ApprovalInteraction`·위험 등급·digest는 패널과 무관하다.

### 3.9 시험 (자동)
- AP-1: 이식 `lib.rs:580-1006` 테스트 전부 통과(위험 사상 적용).
- AP-2: `armed=false`에서 Enter·클릭·2초 hold → `Pending`. 고위험 경고 2개: 체크박스는 1개, 체크 끔 + 2초 hold → `Pending`; 체크 켬 + 1.9초 / 2.0초 → `Pending` / `Approved`. `risk == High`인데 `ack_required == false`인 비정상 입력도 체크 필요(D16, 방어 중복). `Blocked` → 어떤 입력도 `Approved` 아님. `ready_at` + 999 ms 클릭 → 무시. 표시 교체 중 hold → 취소, 체크 해제.
- AP-3: 같은 origin 17번째·전체 65번째 → `TooManyPending`. 남은 기한 4,999 ms → 창 없이 `TimedOut`. `Preparing` 30 s 뒤 Ready → `Expired`는 Ready 표시 + 120 s(준비 시간 불포함). App 항목 `Expired` → 폼 입력 유지, 다시 검토 시 새 승인 id(이전 id `consume` 실패). `Connect` 선택 16개 → `can_approve` 참, 17개 → 거짓. 표시 중 잠금 → `Rejected`, 대기 항목은 남음. 연결 해제 → 그 origin 대기 항목 `Revoked`.
- AP-4: 이스케이프되지 않은 U+202E, 라벨 표에 없는 `FieldKey` → 표시 없이 `Rejected` + E-UI-001. 270,000바이트 값과 공백 없는 3,000자 문자열 배치 → 줄 조각을 이으면 원문과 같음.
- AP-5: `can_approve`에 AI 상태 인자가 없다([06] E2와 함께 확인).
- AP-6(시뮬레이션 상태, D15): `Preparing(Simulating)` 동안 클릭·Enter·2초 hold → `Pending`. `Unsupported`·`NoResult`·`Reverted`·`Incomplete` 각각: 띠 1개 + 체크박스 1개, 체크 끔 + 2초 hold → `Pending`, 체크 켬 + 2.0초 → `Approved`, Enter → 무시. 비성공인데 `risk`가 `Caution`이고 `ack_required == false`인 비정상 입력도 체크·hold 필요. `Ok` + 정보 등급 → 클릭으로 `Approved`. `Blocked`(수수료 상한 초과 등) → `sim_state`와 무관하게 어떤 입력도 `Approved` 아님. E12 + `NoResult` → 체크박스 1개. 모의 시계로 `Simulating` 10,000 ms에 결과 없음 → `NoResult` Ready, 그 뒤 도착한 응답은 버림. 재시뮬레이션: `Ok` 표시 중 클릭 → 재실행 `NoResult` → 표시 교체·체크 해제·`ready_at = now`·T-SIM-RESIM-FAILED, 이전 클릭으로 소비되지 않음; 이어서 체크 + 2초 → `Approved`(재실행 없음). `Failed`의 `retryable`에 E-SIM 코드가 없다.

## 4. 비밀 입력·표시 창 (D11)

### 4.1 창 종류
| ID | 제목 | 필드: 문자 집합, 길이 | 화면 표시 | 붙여넣기 | 복사 | 캡처 제외(§4.5) |
|---|---|---|---|---|---|---|
| W01 | 비밀번호 설정 | 비밀번호·확인 `Printable` 12–128 | 가림(●) | 허용 | 없음 | `Preferred` |
| W02 | 잠금 해제 | 비밀번호 `Printable` 1–128 | 가림 | 허용 | 없음 | `Preferred` |
| W03 | 비밀번호 확인 | 비밀번호 `Printable` 1–128 | 가림 | 허용 | 없음 | `Preferred` |
| W04 | 비밀번호 변경 | 현재 1–128, 새·확인 12–128 | 가림 | 허용 | 없음 | `Preferred` |
| W05 | 니모닉 입력 | `MnemonicText` ≤ 216바이트(24 × 8 + 23 + 1) | 평문, 단어별 칸 격자 | 허용 | 없음 | `Preferred` |
| W06 | passphrase | 가져오기: passphrase·확인, 잠금 해제: 1칸. `Printable` 1–256 | 가림 | 허용 | 없음 | `Preferred` |
| W07 | 개인키 가져오기 | `PrivateKeyHex` ≤ 66 | 평문 | 허용 | 없음 | `Preferred` |
| W08 | 니모닉 표시 | — | 평문 3열 × (n/3)행, 열 우선 번호(24단어: 1–8, 9–16, 17–24) + 첫 주소 | — | 토글 | `Required` |
| W09 | 개인키 표시 | — | 평문 64 hex | — | 토글 | `Required` |
| W10 | 백업 확인 | 단어 4칸 `BackupWord` ≤ 8, 주소 끝 `HexSuffix` = 6 | 평문 | 금지 | 없음 | `Preferred` |

- 가림 칸은 글자 수만큼 U+25CF를 그린다. 칸 옆 `보기`를 누르고 있는 동안만 평문을 그린다(§4.5 실패 시 비활성).
- 글자 수 "{len}/{max}". 커서는 항상 끝이다(이동·선택·실행 취소 없음). `모두 지우기` 버튼.
- `SECRET_WINDOW_TIMEOUT_MS = 300_000`: 입력 창은 마지막 입력 후, 표시 창은 표시 후. 넘으면 버퍼를 소거하고 닫는다("시간이 지나 창을 닫았습니다").

### 4.2 입력 버퍼
`SecureAsciiBuffer`(`archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs:118-178`)를 이식해 넓힌다 → `yw_app::ui::secure_field::SecretField`.
```rust
pub enum Charset { Printable, MnemonicText, PrivateKeyHex, BackupWord, HexSuffix }
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
| `HexSuffix` | `0`–`9`, `a`–`f`, `A`–`F` | 그대로(비교는 [02] §8.3이 소문자화) |

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
- 구현 시 확인: 한글 입력 모드에서 IME 메시지를 차단한 상태로 키를 누르면 위 둘 중 하나가 오는지. 둘 다 오지 않으면(UI-M3-05 불합격) 또는 조합 창이 화면에 나타나면 대체안으로 창 생성 시 `ImmAssociateContextEx(hwnd, NULL, 0)`을 yw-win에 넣고(기능 `Win32_UI_Input_Ime` 추가, [01]) UI-M3-05 합격 기준을 "ASCII만 입력됨"으로 바꾼다.

### 4.7 붙여넣기
허용: W01–W07. 금지: W10(종이 백업 확인이 목적).
1. `clipboard::read_text(owner, PASTE_MAX_UTF16_UNITS = 4096)` → `(units: WipeBuf<u16>, seq)`. `TooLong`이거나 텍스트가 없으면 E-INP-018.
2. 새 `Zeroizing` 버퍼로 정규화: 앞뒤 공백·탭·CR·LF 제거. `MnemonicText`는 공백·탭·CR·LF 연속을 공백 하나로, `A`–`Z`를 소문자로. 모든 단위를 활성 칸 `Charset`으로 검사해 하나라도 거부되거나 길이를 넘으면 전체를 거부하고(부분 삽입 없음) E-INP-018. 클립보드는 건드리지 않는다.
3. 통과하면 활성 칸 내용을 그 값으로 바꾸고(W05는 단어 칸에 나눠 넣음) `units`를 소거한다.
4. `clipboard::clear_if_unchanged(owner, seq)`가 true면 T-PASTE-CLEARED. false(사이에 클립보드가 바뀜)면 아무것도 지우지 않는다.

`OpenClipboard` 재시도는 yw-win이 한다(20 ms 간격 5회, [01] §7.3). `ClipError::Busy`·`Os`면 추가 재시도 없이 E-SEC-002.

### 4.8 복사 (설정 토글)
- `allowSecretCopy == false`(기본): W08·W09에 `복사` 버튼이 없고 Ctrl+C에는 T-COPY-OFF.
- `true`: `복사` 버튼과 Ctrl+C. 내용은 W08 = 단어를 공백 하나로 이은 문자열, W09 = 64 hex. `clipboard::set_secret_text`가 한 번의 `OpenClipboard`…`CloseClipboard` 안에서 `CF_UNICODETEXT (13)`(문자열 + NUL)과 `RegisterClipboardFormatW`로 등록한 `"ExcludeClipboardContentFromMonitorProcessing"`·`"CanIncludeInClipboardHistory"`·`"CanUploadToCloudClipboard"`를 각각 DWORD 0으로 넣는다(모니터·기록·클라우드 동기화 제외, D11).
- 반환된 시퀀스 번호를 `App.secret_clip = Some((seq, now))`에 둔다. `SECRET_CLIPBOARD_TTL_MS = 30_000` 뒤, 그리고 잠금·종료 때 `clear_if_unchanged(seq)`. 번호가 바뀌었으면 지우지 않는다. T-COPIED.
- 한계: 클립보드 전역 메모리는 시스템 소유라 0으로 덮을 수 없다(`EmptyClipboard`는 해제만). 앱이 비정상 종료하면 자동 삭제가 없다.

### 4.9 비활성화·닫기
- 클릭 관통 방지는 §1.8과 같다.
- `WM_ACTIVATEAPP(0)` 또는 다른 프로세스 창으로 가는 `WM_KILLFOCUS`(이식 `recovery_native.rs:1572-1583`): 평문 창(W05, W07–W10)은 내용 영역을 T-MASKED로 가리고 다시 활성화되면 다시 그린다(버퍼 유지). 가림 칸 창은 `보기`만 끈다.
- 닫기(X, Esc, 완료, 시간 초과, 잠금): 모든 `SecretField`를 `clear`, 표시 버퍼 drop(zeroize), `WM_NCDESTROY`에서 `GWLP_USERDATA`를 지운 뒤(yw-win) `WM_YW_CHILD_DONE`.
- W08 `다 적었습니다`는 2초 hold(`BACKUP_ACK_HOLD_MS = 2_000`, 이식 `HoldGate` `recovery_native.rs:78-107`). 포인터가 버튼 밖으로 나가거나 포커스를 잃으면 취소.

### 4.10 시험 (자동)
- SW-1: 이식 `recovery_native.rs:1610-1738` 테스트(2초 hold, 고정 용량 버퍼, 소거, 창 없는 차단 판정, 시간 초과·포커스 잃음) 통과.
- SW-2: `Printable`에 0x1F·0x7F·0xAC00·서로게이트 → 거부, 버퍼 불변. `MnemonicText`에 `"  Abandon  ABOUT "` 단위 입력 → `abandon about `. `PrivateKeyHex`에 `0X…`·중간 `x`·65자 → 거부. `backspace` 뒤 내부 용량의 지운 위치 = 0.
- SW-3: 붙여넣기 `"abandon\r\n abandon\tabout"` → `abandon abandon about`, `"abandon 1"` → 전체 거부·클립보드 유지, 성공 후 시퀀스 같음/다름 → 비움/유지.
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
- 승인 창이나 W08·W09가 열려 있는 동안 유휴 판정을 멈추고, 닫히면 그때부터 다시 센다(각 창에 자체 시간 제한이 있다). 잠금 해제 직후 `last_input = now`.
- 구현 시 확인(Modern Standby): 대상 PC가 S0ix(`powercfg /a`에 "S0 Low Power Idle")면 시작 메뉴 절전에서 데스크톱 앱이 `PBT_APMSUSPEND`를 받지 못할 수 있다. 이때 UI-M3-08 ③의 합격 로그는 `Suspend` 또는 `SessionLock`이다. 둘 다 없으면 yw-win `session`에 `RegisterSuspendResumeNotification(hwnd, DEVICE_NOTIFY_WINDOW_HANDLE)`을 추가한다([01] §7.6).

### 5.2 잠긴 동안의 요청
- 승인이 필요한 dApp 요청은 기한까지 큐에서 기다리고 W02를 띄운다(§2.5, §3.7). 그 밖의 메서드는 [05] §4.4.
- 잠긴 동안 yw-app은 평문 meta 사본(계정 목록 포함)을 갖지 않는다.

### 5.3 잠금 절차 (UI 스레드, 순서대로)
1. `AppMode::Locked`, `lock_epoch += 1`(§1.2), 유휴 타이머 정지.
2. `KeyQueue.push_front(KeyJob::Lock)`(→ `Vault::lock`: 슬롯 소거·VirtualUnlock, [02] §7.2; 큐의 나머지 작업 `KeyJobError::Locked`).
3. 열린 비밀 창(W01–W10)을 모두 닫는다(§4.9). 진행 중인 생성·가져오기 흐름 취소(`DiscardImport`).
4. `secret_clip`이 있으면 `clear_if_unchanged`.
5. 표시 중인 승인 창을 닫고 `Rejected`. 대기 항목은 남긴다(§3.7). [03] `ApprovalStore::invalidate_all`.
6. 평문 meta 사본(라벨, 주소록, 연결 기록, 잔액 캐시)을 drop하고 화면을 S07로.
7. [05]에 잠금을 알린다(`AppEvent::Locked` → `accountsChanged([])`, [05] §4.8).
8. 로그 `lock reason=<LockReason>`.

- `Suspend`: 2단계 뒤 UI 스레드가 키 작업자의 `LockDone`을 최대 1.5초 기다린다(진행 중 작업이 Argon2면 그 안에 끝나지 않을 수 있다. 구현 시 확인: 대상 PC의 Argon2 1회 시간, [02] §7.4). 잔여 위험(결정): Argon2 작업(최대 2회, 비밀번호 변경) 도중 최대 절전에 들어가면 DEK 슬롯이 소거되기 전에 hiberfil에 기록될 수 있다. 이는 spec.md §2.2 비목표의 최대 절전 파일(hiberfil.sys)·페이지 파일 잔여 위험(VirtualLock은 최대 절전을 막지 못한다)으로 보고 BitLocker(spec.md §2.4)로 완화하며, 다른 스레드에서 슬롯을 지우는 경로는 만들지 않는다.
- 잠긴 동안 저널 커밋은 없다(DEK 필요, D10). 진행 중이던 `eth_sendRawTransaction`(그리고 [07]·[08]의 전송) 호출은 끝까지 기다리되 결과 상태는 메모리에만 두고, 영수증 폴링은 멈춘다. 잠금 해제 직후 [03] §5.4 reconcile이 상태를 확정한다([03] §4.5와 같음).

### 5.4 시험
- LK-1: 모의 시계로 유휴 = 설정 분 − 1초 → 잠기지 않음, + 0초 → 잠김. 다른 앱 입력만 계속 → 잠김. 승인 창이 열린 채 설정 분 경과 → 잠기지 않고 닫힌 뒤부터 다시 셈.
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
  "logLevel": "info"
}
```

| 키 | 타입 | 기본값 | 규칙 |
|---|---|---|---|
| `version` | integer | 1 | 정확히 1. 다르면 파일 전체 무효(yw-host도 이 키를 읽는다, 아래 `browserAutoLaunch`) |
| `autoLockMinutes` | integer | 10 | 1–60 (D12) |
| `allowSecretCopy` | bool | false | §4.8 |
| `allowLocalhostDapps` | bool | false | D22, [05] §4.6 |
| `browserAutoLaunch` | bool | true | D24. yw-host는 `settings.json`에서 `version`과 이 키만 읽고 쓰지 않는다(spec.md §4.1, [05] §7.4). yw-host 판정: 루트 객체·`version == 1`·bool 값이면 그 값, 그 밖(파일 없음, 읽기·크기·파싱 오류, `version ≠ 1`, 키 없음·bool 아님)은 true |
| `evmChainId` | integer | 11155111 | 기본 체인 1·11155111·999 또는 `evmChains`에 있는 chainId(D14). 활성 EVM 체인(D30, §2.6). `evmChains` 다음에 검증한다 |
| `evmChains` | array | `[]` | 사용자 EVM 체인(§2.17), 0..=32개(`MAX_CUSTOM_EVM_CHAINS`), 배열 순서 = 표시 순서. 항목 `EvmChainDef`(아래) |
| `evmGenesisPins` | object | `{}` | 최초 신뢰로 고정한 기본 체인 제네시스(§1.9). 키는 [03] §1.1에서 제네시스 상수가 없는 기본 체인의 `NetworkId`(현재 `"eip155:999"`만), 값 `Hash32`. 없으면 첫 연결 때 고정 |
| `feeCaps` | object | 위 값(= [03] §1.1 `default_caps`) | 키는 기본 체인 또는 `evmChains`에 있는 체인의 `NetworkId`(`eip155:<chainId>`). 없는 체인은 기본값(기본 체인 [03] §1.1 `default_caps`, 사용자 체인 [03] §3.4 보수적 기본값). `maxFeePerGasGwei` 1–10,000, `maxPriorityFeePerGasGwei` 0.01–10,000이고 ≤ maxFee 상한, `maxTotalFee`(네이티브 단위) 0.0001–10([03] §3.4-7). 값은 10진 문자열(gwei 소수 ≤ 9자리, 네이티브 ≤ 그 체인 소수 자릿수, [03] `parse_units`) |
| `rpc` | object | `{"template": "quicknode"}` | `template` = `"quicknode"`·`"alchemy"`·`"manual"`(S15 `RPC 공급자` 라디오, §2.11.1 `RpcTemplate`). 입력 편의(URL 생성·S17 식별자 해석)에만 쓰고 런타임 엔드포인트에는 영향이 없다(§1.9). 다른 키나 다른 값 → `rpc` 객체 단위 기본값. 템플릿 자격 정보와 네트워크별 URL은 토큰이 들어 있으므로 여기 두지 않고 §6.3 `tpl:*`·`rpc:<NetworkId>`에 둔다(D13) |
| `solana` | object | [07] §10 | M7부터. 키·범위·기본값은 [07] §10 |
| `bitcoin` | object | 위 값 | M8부터, 의미는 [08] §2 소유. `enabled` bool. `network` = `"mainnet"`·`"testnet4"`(D26·D30), 바꾸기는 진행 중 BTC 저널 항목이 없을 때만. `indexer` = `"esplora"`(기본: `esploraBaseUrl`의 Esplora REST GET, 무료·키 없음)·`"bb-rpc"`(Core 엔드포인트 URL에 Blockbook `bb_*` JSON-RPC POST, QuickNode BTC Blockbook 유료 애드온)·`"bb-rest"`(`<Core URL>/api/v2/` Blockbook REST GET, 알케미 UTXO API)([08] §2·§4.3), 언제든 변경 가능. `esploraBaseUrl` = 아래 `EsploraBaseUrls`(비밀이 아니므로 여기 둔다; 토큰이 든 Core URL은 §6.3). `enabled`·`network`·`indexer`가 없거나 틀리거나 네 키 밖의 키가 있으면 `bitcoin` 객체 단위 기본값(`esploraBaseUrl` 포함). `esploraBaseUrl`은 아래 규칙으로 키 단위 검증 |
| `llm_explain` | object | [06] §2.1 | 검증·되돌림은 [06] §2.1 |
| `logLevel` | string | `"info"` | `error`·`warn`·`info`·`debug` |

```
EvmChainDef = { "chainId": u64, "name": Label, "symbol": string, "decimals": u8,
                "quicknodeSubdomain"?: string, "alchemyLabel"?: string, "explorer"?: string,
                "simulation": "auto" | "unsupported", "genesisHash": Hash32 }      // 직렬화 키 순서 = 이 순서, 없는 선택 키는 생략
Hash32 = "0x" + 소문자 hex 64자
```
- `chainId`: JSON 정수(yw-json `as_u64`), 1..=9,223,372,036,854,775,771(EIP-2294), 1·11155111·999가 아니고 배열 안에서 유일. `name`: [02] `Label` + §3.3 표시 금지 문자 없음, 기본 체인 이름·다른 항목 이름과 다름(ASCII 대소문자 무시). `symbol`: `^[A-Za-z0-9]{1,11}$`. `decimals`: 0..=36. `quicknodeSubdomain`·`alchemyLabel`: 각각 `^[a-z0-9]+(-[a-z0-9]+)*$` 1–63자, 공급자 템플릿 식별자(§2.11.1 `template_url`의 `entry`; [03] §1.1 `templates`와 같은 역할). URL 생성에만 쓰고 런타임 엔드포인트는 `rpc:eip155:<chainId>`뿐이다(§1.9). `explorer`: `HttpsUrl::parse` 통과, ≤ 256바이트, `?`·`#`·끝 `/` 없음. `genesisHash`: 추가 때 고정한 블록 0 해시(§2.17.2). 그 밖 키 → 그 항목 무효.
- 이 체인의 `NetworkId`는 `eip155:<chainId>`(10진, [03] §1)이고 meta `tokens`·`activity`, `feeCaps`, `apikeys.dpapi` `rpc:*`가 이 키를 쓴다. RPC URL은 여기 두지 않는다(§6.3 `rpc:eip155:<chainId>`).

```
EsploraBaseUrls = { "mainnet": EsploraBaseUrl, "testnet4": EsploraBaseUrl }   // 직렬화는 항상 두 키, 이 순서
```
- `EsploraBaseUrl`([08] §2): `HttpsUrl::parse` 통과([01] §7.4: https만, userinfo·fragment 거부, 호스트 소문자화, 포트 선택), 전체 ≤ 256바이트, `?`·`#` 없음, 끝 `/` 없음(경로가 없으면 호스트[:포트]로 끝난다). 경로는 비었거나 `/`로 구분된 세그먼트 1개 이상이고 세그먼트마다 `^[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,63}$`(`.`·`..`·퍼센트 인코딩 없음). 호스트가 `quiknode.pro`·`g.alchemy.com`이거나 그 하위 도메인이면 거부한다(토큰이 든 공급자 URL을 평문 settings.json에 두지 않는다, D13). 저장 값은 파싱 후 정규형(소문자 호스트). 화면 `저장` 위반은 E-BTC-006. 기본값 `https://mempool.space/api` / `https://mempool.space/testnet4/api`([08] §15).
- `esploraBaseUrl` 검증: 키가 없으면 두 네트워크 모두 기본값(배너 없음). 객체가 아니면 기본값 + 배너 `bitcoin.esploraBaseUrl`. 키는 `mainnet`·`testnet4`만(모르는 키는 무시 + 배너), 빠진 키는 그 네트워크 기본값(배너 없음), 형식 위반 값은 그 키만 기본값 + 배너 `bitcoin.esploraBaseUrl.<net>`. 이 키 단위 되돌림은 `enabled`·`network`·`indexer`에 영향을 주지 않는다.

### 6.2 읽기·검증·쓰기
- 파일 없음: 모두 기본값. 첫 변경 때 만든다.
- 64 KiB 초과, JSON 오류, 중복 키, 루트가 객체가 아님, `version` 오류: 전체를 기본값으로 쓰고 배너 E-APP-001. 파일은 그대로 두고 다음 변경 때 덮어쓴다.
- 최상위 키마다 따로 검증한다. 틀린 키는 그 키만 기본값이고 배너에 키 이름을 보인다. 객체 값(`feeCaps`의 네트워크 항목, `rpc`, `solana`, `bitcoin`, `llm_explain`)은 그 객체 단위로 되돌린다(예외: `bitcoin.esploraBaseUrl`은 네트워크 키 단위, §6.1). 모르는 최상위 키·`feeCaps` 네트워크 키는 무시하고 배너에 보이며 다음 쓰기에서 사라진다.
- 검증 순서: `evmChains` → `evmChainId`·`evmGenesisPins`·`feeCaps`(등록된 체인 집합에 의존). `evmChains`는 항목 단위다: 무효 항목, 기본 체인·앞 항목과 chainId 또는 이름이 겹치는 항목, 33번째부터는 버리고 배너 "evmChains[i]"(배열이 아니면 전체 `[]`). 버린 체인의 `feeCaps`·`rpc:*` 항목은 고아로 무시된다. `evmGenesisPins`는 키 단위(모르는 키·형식 오류는 그 키만 버림).
- 쓰기: 메모리의 전체 설정을 직렬화해 §9 원자적 쓰기. 검증을 통과한 값만 메모리에 들어간다.
- 반영: `autoLockMinutes` 다음 판정부터, `allowLocalhostDapps` [05]의 다음 요청부터, `browserAutoLaunch` yw-host의 다음 실행 판단부터, `evmChainId` 즉시(S10 새로고침), `evmChains`·`evmGenesisPins` 즉시(새 `RpcConfig`, 그 체인 확인 상태 초기화, §1.9), `feeCaps` 다음 준비부터, `rpc.template` 즉시(S15·S17 입력 해석만), `bitcoin.indexer`·`bitcoin.esploraBaseUrl` 즉시(새 `RpcConfig`, [08] §2 연결 검사 다시), `logLevel` 다음 줄부터.

### 6.3 apikeys.dpapi
- 파일 = `CryptProtectData` 출력 그대로. `pOptionalEntropy` = ASCII `your-wallet/v3/apikeys`(22바이트), `szDataDescr` = NULL, `pPromptStruct` = NULL, 플래그 `CRYPTPROTECT_UI_FORBIDDEN (0x1)`(`CRYPTPROTECT_LOCAL_MACHINE` 없음 → 현재 사용자, D13). 복호화도 같은 entropy·플래그.
- 평문(최대 131,072바이트):
```
offset 0   magic       8 bytes  "YWAPIK01"
offset 8   count       u8       0..=48
반복 count번:
           name_len    u8       1..=32
           name        ASCII    "rpc:" NetworkId | "tpl:quicknode" | "tpl:alchemy" | "llm"   (같은 이름 두 번 금지, 그 밖 이름은 형식 오류)
                                NetworkId = "eip155:" <chainId 10진, 앞자리 0 없음>   // 기본 1·11155111·999 + settings evmChains
                                          | "solana:mainnet" | "solana:devnet" | "bitcoin:mainnet" | "bitcoin:testnet4"
           value_len   u16 BE   1..=2048
           value       bytes    rpc:*: 그 네트워크의 엔드포인트 URL 전체(토큰 포함), yw-win `HttpsUrl::parse` 통과(https만, ≤ 2048바이트, [01] §7.4, D13)
                                / tpl:quicknode: <이름> ":" <토큰>  (이름 ^[a-z0-9]+(-[a-z0-9]+)*$ 1–63, 토큰 ^[A-Za-z0-9_-]{16,128}$, §2.11)
                                / tpl:alchemy: ^[A-Za-z0-9_-]{16,128}$ (§2.11)
                                / llm: 0x21–0x7E 1–512자([06] §2.1)
끝: 남는 바이트 없음
```
- 상한 근거: `tpl:*` 2 + `llm` 1 + EVM 기본 3 + 사용자 체인 32 + SOL 2 + BTC 2 = 42 ≤ 48개, 42 × (1 + 32 + 2 + 2048) < 131,072. 가장 긴 이름 `rpc:eip155:9223372036854775771` = 30바이트 ≤ 32.
- 런타임 엔드포인트는 `rpc:*`뿐이다(§1.9). `tpl:*`는 나중에 추가한 체인이나 토큰 교체 때 URL을 다시 만들기 위한 템플릿 자격 정보이고(§2.11.1) 런타임 호출에 쓰지 않는다.
- `settings.json`을 먼저 읽는다(§1.4-5). `rpc:eip155:<chainId>` 중 기본 체인도 `evmChains`에도 없는 것은 고아 항목이다: 무시하고 로그 `apikeys.orphan`(이름만), 다음 저장 때 사라진다.
- 복호화 결과(`WipeBuf<u8>`)는 바로 파싱해 `Zeroizing` 값으로 옮긴다. UI 스레드가 모든 항목을 소유하고(저장 때 평문을 다시 만들기 위해), `rpc:*` URL만 `RpcConfig`(§1.9)로 RPC·read 작업자에 복사해 종료 때까지 보관한다(D10: RPC URL·API 키는 지갑 비밀이 아니다). `tpl:*`는 작업자에 보내지 않는다. LLM 키는 [06](기능이 꺼져 있으면 복호화하지 않음).
- 형식 오류·복호화 실패(다른 사용자·다른 PC): E-KEY-001, 모든 항목 없음으로 취급(엔드포인트 없음). 다음 저장 때 덮어쓴다.
- 저장: 메모리의 항목으로 평문을 새로 만들어 `protect` → §9 원자적 쓰기. 모두 지우면 `count = 0`.
- URL 전체가 비밀이다(D13): 경로에 토큰·키가 있고, 호스트에도 QuickNode 엔드포인트 이름이 있다. URL·호스트·토큰·템플릿 자격 정보를 로그·문구·화면에 쓰지 않는다. 로그는 항목 이름(`rpc:<NetworkId>`·`tpl:*`)만, 화면은 §2.11.1 가린 형태만 쓴다.

### 6.4 meta `prefs`
[02] §5.3 meta의 `prefs` 객체(이 문서 소유). 네트워크 선택은 여기 두지 않는다(`settings.json`, D30). 모르는 키나 형식 오류는 `prefs` 전체를 기본값으로 되돌리고 로그를 남긴다. `alt_passphrase` 세션에서는 메모리에만 둔다.

| 키 | 타입 | 기본값 | 규칙 |
|---|---|---|---|
| `evm_account` | object | `{"index":0}` | `{"index": u32}`(meta `evm_accounts`에 있음) 또는 `{"record_id": Hex16}`(`evm_raw_accounts`에 있음) |
| `sol_account` | integer | 0 | meta `sol_accounts`의 `index`(M7) |
| `tab` | string | `"evm"` | `"evm"`·`"sol"`·`"btc"`(구현된 것만) |

BTC 계정 선택 키는 없다. BTC v1은 계정 0(m/84'/{coin}'/0')만 쓴다([08] §1.1–1.2, D26).

### 6.5 시험 (자동)
- ST-1(`settings.json`): `evmChains` 33개 → 32개 + 배너. chainId 999·중복 chainId·이름 "sepolia 테스트넷"(대소문자만 다름)·`decimals` 37·`simulation` `"off"`·대문자 `genesisHash`·`explorer`에 `?` → 그 항목만 버림. `evmChainId` = 버린 체인 → 11155111 + 배너. `feeCaps["eip155:<버린 id>"]` → 무시. `evmGenesisPins["eip155:1"]` → 그 키만 버림. 모르는 키(예 `rpcUrl`)가 있는 항목·`quicknodeSubdomain` `"Base_Sepolia"` → 그 항목만 버림. `rpc.template` `"infura"`·`rpc.provider` 키 → `rpc` 기본값 + 배너. `bitcoin.indexer` `"blockbook"` → `bitcoin` 객체 기본값(`"esplora"`, mempool.space URL 2개) + 배너. `bitcoin`에 `esploraBaseUrl` 없음 → 기본 URL, 배너 없음. `esploraBaseUrl.mainnet`이 `http://mempool.space/api`·`https://mempool.space/api/`·`https://mempool.space/api?x=1`·`https://u@mempool.space/api`·`https://mempool.space/api/../x`·`https://mempool.space/a%20b`·`https://x.btc.quiknode.pro/tok`·`https://bitcoin-mainnet.g.alchemy.com/v2/k`·257바이트 → 그 키만 기본값 + 배너 `bitcoin.esploraBaseUrl.mainnet`, `enabled`·`network`·`indexer`·`testnet4` 값은 유지. `https://MEMPOOL.space/api` → `https://mempool.space/api`로 정규화. `https://blockstream.info/testnet4/api`·`https://esplora.example.com:3002` 통과. `esploraBaseUrl.signet` 키 → 무시 + 배너. 왕복 직렬화 → 키 순서 고정(`esploraBaseUrl`은 항상 두 키), 바이트 동일.
- ST-2(`apikeys.dpapi` 평문): 42개 항목(`tpl:*` 2, `llm`, `rpc:*` 39)·각 `rpc:*` 2,048바이트 URL 왕복. `count` 49, 같은 이름 2개, `rpc:eip155:01`, 이름 33바이트, 모르는 이름 `tpl:infura`, `tpl:quicknode` 값에 `:` 없음·대문자 이름·토큰 15자 → 형식 오류(E-KEY-001, 모든 항목 없음). 등록 안 된 `rpc:eip155:8453` → 무시, 다음 저장에서 빠짐. `RpcConfig.endpoints`에 `tpl:*` 값이 없음.
- ST-3(S17 입력 판정, 순수 함수): chainId `0`·`01`·9,223,372,036,854,775,772 → E-CHN-004, 11155111 → E-CHN-003. RPC 칸(시험용 가짜 자격 정보): `rpc.template = "quicknode"` + `tpl:quicknode` 있음, `Base-Sepolia` → `quicknodeSubdomain` `base-sepolia`, URL `https://<이름>.base-sepolia.quiknode.pro/<토큰>/`; `rpc.template = "alchemy"` + `tpl:alchemy` 있음, `Base-Sepolia.g.alchemy.com` → `alchemyLabel` `base-sepolia`, URL `https://base-sepolia.g.alchemy.com/v2/<KEY>`; 그 템플릿 자격 정보 없음 → E-KEY-004; `rpc.template = "manual"` + `base-sepolia` → E-KEY-003; `base.sepolia` → E-CHN-004; `http://x` → E-KEY-003. 모의 RPC: chainId 응답 `0x2105` ≠ 입력 8452 → E-CHN-001, 블록 0 `hash` 31바이트 → E-CHN-002 + E-RPC-005, 편집 중 해시 ≠ 고정값 → E-CHN-008·저장 없음. 삭제: 활성 체인 → E-CHN-009, 미종결 저널 레코드 → E-CHN-007.
- ST-4(§2.11.1 엔드포인트, 순수 함수 + 모의 RPC, 시험용 가짜 이름·토큰·키): `template_url` QuickNode `eip155:1`(서브도메인 없음) → `https://<이름>.quiknode.pro/<토큰>/`, `eip155:11155111` → `https://<이름>.<[03] 서브도메인>.quiknode.pro/<토큰>/`, 알케미 `solana:devnet` → `https://<[07] 라벨>.g.alchemy.com/v2/<KEY>`, 항목 없는 네트워크·`Manual` → `None`(생성 대상에서 빠지고 T-RPC-GENERATED의 건너뜀 목록에 나옴). `기존 URL 덮어쓰기` 끔 → 기존 `rpc:*` 바이트 동일, 켬 → 교체. 사용자 체인 생성 URL의 chainId 불일치 → 그 체인만 쓰지 않음. `mask_url` 결과에 이름·서브도메인·라벨·토큰·키 부분 문자열이 없음. 엔드포인트 없는 네트워크 → 호출 0회, E-KEY-005(EVM 준비 `Failed`, `retryable == false`). `테스트`: EVM `eth_chainId` `0x2105` (기대 1) → E-RPC-010, SOL 다른 genesis → E-RPC-010, BTC `chain` `"test"` → E-RPC-010, HTTP 401 → E-RPC-003. Bitcoin `Esplora URL` `테스트`(모의 서버): testnet4 줄에 testnet4 제네시스 → T-BTC-IDX-OK, mainnet·testnet3 제네시스 → E-BTC-003, 404·본문 끝 `\n` → E-BTC-004, 500 → E-BTC-001, 요청 경로는 `/block-height/0`뿐(주소 없음). 위 모든 경우 로그 줄에 URL·호스트·토큰이 없고 `net=<NetworkId>`만 있음.

## 7. 오류·메시지 정책
- RPC·LLM·OS가 준 문자열은 화면에 그대로 보이지 않는다(spec.md §2.1). 예외: AI 설명 패널(§3.8)은 [06] §5–§6 필터를 거친 파생 텍스트를 별도 패널에만 표시한다(spec.md §2.1 예외). 모든 오류는 `ErrorCode`로 분류해 고정 한국어 문구 + `(코드)`로 보인다. 예: "RPC 응답 시간이 초과되었습니다. (E-RPC-002)". 체인 문서가 정한 고정 문구 표([08] §13 등)는 그 표를 쓴다.
- 분류 입력은 HTTP 상태, JSON-RPC `error.code`, WinHTTP·Win32 오류 번호, 내부 enum(`VaultError`·`KeyError`·`journal::JournalError`, [02] §10)이다. 문자열로 분류해야 하면(공급자의 허용 목록 거부 등) yw-app 안의 고정 부분 문자열 비교만 쓰고 그 문자열은 보이지 않는다. 오류 문구·배너에는 엔드포인트를 네트워크 이름으로만 가리키고 URL·호스트를 넣지 않는다(§1.9).
- 로그: 코드는 `warn` 이상으로 항상 남긴다. 원격 메시지 문자열은 `debug`에서만, 0x20–0x7E 밖을 `?`로 바꾸고 256바이트로 잘라 남긴다.
- 배너는 사용자가 닫을 때까지 남고 같은 코드는 한 번만 보인다.

| 코드 | 상황(원인 enum) | 문구 |
|---|---|---|
| E-APP-001 | `settings.json` 읽기 실패·무효 키 | 설정 파일을 읽지 못해 기본값을 사용합니다. ({키}) |
| E-APP-002 | `settings.json` 쓰기 실패 | 설정을 저장하지 못했습니다. 디스크 공간과 권한을 확인하세요. |
| E-APP-004 | 세션 알림 등록 실패 | Windows 잠금 감지를 켜지 못했습니다. 자리를 비울 때 직접 잠그세요. |
| E-APP-005 | 이벤트 큐 가득 참 | 요청이 너무 많아 일부를 처리하지 못했습니다. |
| E-APP-009 | 내부 오류(`InvalidState`, `RecordNotFound`, `KeyError::Internal` 등) | 내부 오류가 발생했습니다. 로그를 확인하세요. |
| E-PIPE-001 | pipe 생성 실패 | 브라우저 연결을 시작하지 못했습니다. 앱을 다시 실행하세요. |
| E-VLT-001 | `UnlockFailed` | 비밀번호가 올바르지 않거나 vault 파일이 손상되었습니다. |
| E-VLT-002 | `Malformed`, `UnsupportedVersion`, `UnsupportedParams` | 지갑 파일을 읽을 수 없습니다. 손상되었거나 다른 버전의 파일입니다. |
| E-VLT-003 | `Storage` | 지갑 파일을 저장하지 못했습니다. 디스크 공간과 권한을 확인하세요. |
| E-VLT-005 | `RandomnessUnavailable` | 안전한 난수를 얻지 못해 작업을 중단했습니다. |
| E-VLT-006 | `SidecarCorrupt`, `SidecarVaultMismatch`, 저널 손상 | 지갑 부가 파일(meta·저널)을 읽을 수 없습니다. |
| E-VLT-007 | `OutOfMemory`, VirtualLock 실패 | 메모리를 잠그지 못해 잠금 해제하지 않았습니다. |
| E-VLT-008 | `PayloadCorrupt` | 지갑 내용이 손상되었습니다. 이전 사본(.prev)으로 복구할 수 있습니다. |
| E-VLT-009 | `BackupNotConfirmed` | 백업 확인을 먼저 끝내세요. |
| E-VLT-010 | `RecordLimit` | 가져온 개인키는 최대 15개입니다. |
| E-VLT-011 | `DuplicateKey` | 이미 가져온 개인키입니다. |
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
| E-INP-013 | `BackupMismatch` | 입력한 단어 또는 주소가 맞지 않습니다. |
| E-INP-014 | 0 주소 | 0 주소로는 보낼 수 없습니다. |
| E-INP-015 | 토큰 컨트랙트로 전송 | 받는 주소가 이 토큰의 컨트랙트입니다. 보내면 잃습니다. |
| E-INP-016 | 주소록 중복 | 이미 주소록에 있는 주소입니다. |
| E-INP-017 | 이름 규칙 | 이름은 1–32자이고 앞뒤 공백·제어 문자·보이지 않는 문자를 쓸 수 없습니다. |
| E-INP-018 | 붙여넣기 거부 | 붙여넣은 내용에 허용되지 않는 문자가 있거나 너무 깁니다. |
| E-INP-019 | `PassphraseTooLong`·`InvalidChar`·`Empty` | passphrase는 영문·숫자·기호(ASCII) 1–256자여야 합니다. |
| E-SEC-001 | 캡처 제외 실패(`CaptureExclusion::Required` 창 W08·W09, §4.5. `Preferred` 창은 T-CAPTURE-WARN) | 화면 캡처 제외를 적용하지 못해 표시하지 않습니다. |
| E-SEC-002 | 클립보드 열기 실패 | 클립보드를 사용할 수 없습니다. 잠시 후 다시 시도하세요. |
| E-KEY-001 | `apikeys.dpapi` 읽기 실패 | 저장된 RPC 엔드포인트·API 키를 읽을 수 없습니다. 다시 입력하세요. |
| E-KEY-002 | 템플릿 자격 정보 형식(QuickNode 엔드포인트 이름·토큰, 알케미 키, §2.11) | 공급자 템플릿 입력 형식이 올바르지 않습니다. ({항목}) |
| E-KEY-003 | RPC URL 형식(`HttpsUrl::parse` 실패, `직접 입력` 템플릿에 URL이 아닌 값) | RPC URL은 https:// 로 시작하는 올바른 주소여야 합니다. |
| E-KEY-004 | 템플릿 자격 정보 없음(`네트워크 URL 생성`, S17 서브도메인·라벨 입력, §2.11.1·§2.17.1) | 선택한 RPC 공급자 템플릿의 자격 정보가 없습니다. 설정 → RPC 공급자에서 먼저 저장하세요. |
| E-KEY-005 | 네트워크 엔드포인트 없음(`rpc:<NetworkId>` 없음: 그 네트워크의 조회·준비·서명·`테스트`·BTC 켜기, [03] E35, §1.9) | RPC 엔드포인트가 없습니다. 설정 → 네트워크 URL에서 이 네트워크의 URL을 만들거나 입력하세요. |
| E-RPC-001 | DNS·연결 실패 | 네트워크에 연결할 수 없습니다. |
| E-RPC-002 | 시간 초과 | RPC 응답 시간이 초과되었습니다. |
| E-RPC-003 | HTTP 401·403 | RPC 엔드포인트가 인증을 거부했습니다. 설정 → 네트워크 URL에서 이 네트워크의 URL(토큰)을 확인하세요. |
| E-RPC-004 | HTTP 429, 한도 초과 코드 | 요청 한도를 넘었습니다. 잠시 후 다시 시도하세요. |
| E-RPC-005 | 응답 형식 이상 | RPC 응답 형식이 올바르지 않습니다. |
| E-RPC-006 | chainId 불일치, 상수 제네시스 체인(1·11155111)의 제네시스 불일치([03] §1.4) | RPC가 다른 네트워크를 가리킵니다. 작업을 중단했습니다. |
| E-RPC-007 | 그 밖의 JSON-RPC 오류 | RPC가 요청을 거부했습니다. |
| E-RPC-008 | TLS 실패 | 보안 연결(TLS)을 맺지 못했습니다. |
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
| E-TX-001 | 수수료 상한 초과([03] E05) | 수수료가 설정한 상한을 넘습니다. |
| E-TX-002 | 진행 중 거래(D20, [03] E06) | 이 계정의 이전 거래가 아직 확정되지 않았습니다. |
| E-TX-003 | 서명 후 자체 검증 실패 | 내부 검증에 실패해 거래를 보내지 않았습니다. |
| E-TX-004 | 전송 결과 불명 | 전송 결과를 확인할 수 없습니다. 활동에서 상태를 확인하세요. |
| E-TX-005 | `journal::JournalError::Full`([02] §5.4 추가 전 검사, [03] E06; 모든 체인, 서명·전송 없음) | 거래 저널 공간이 부족합니다. |
| E-UI-001 | 표시 검증 실패 | 요청 내용을 안전하게 표시할 수 없어 거부했습니다. |
| E-LLM-* | [06] §7 | [06] (패널 안에만) |

새 상황은 같은 형식(`E-<영역>-<3자리>`)으로 이 표에 추가한다.

## 8. 로그 (D28)
- 파일: `logs\yw-app.log`, 순환 `yw-app.1.log` … `yw-app.4.log`(총 5개). yw-host 로그는 [05].
- 순환: 한 줄을 쓰기 전 현재 크기 + 줄 길이가 `LOG_FILE_MAX_BYTES = 1_048_576`을 넘으면 닫고, `.4` 삭제, `.3→.4`, `.2→.3`, `.1→.2`, 현재→`.1`로 이름을 바꾸고 새 파일을 연다. 순환 실패는 무시하고 계속 쓴다.
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
- 앱은 지갑 파일(vault·meta·journal과 `.prev`)을 옮기거나 지우지 않는다. 다른 지갑으로 바꾸려면 사용자가 직접 옮긴다([02] §6.3).

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
| UI-M3-07 | M3 | 백업 확인에 틀린 단어 → 새 위치로 맞는 값 | T-BACKUP-FAIL 후 성공, S08 |
| UI-M3-08 | M3 | 자동 잠금 4경로: ① 1분 설정 후 1분간 다른 앱만 사용 ② Win+L ③ 시작 → 전원 → 절전 후 다시 켜기 ④ `잠금`·Ctrl+L | 각각 잠김, 로그 `lock reason`이 `Idle`·`SessionLock`·`Suspend`·`Manual`(③은 Modern Standby PC면 `Suspend` 또는 `SessionLock`, §5.1) |
| UI-M3-09 | M3 | 앱 종료 → 재실행 → 잠금 해제 / 틀린 비밀번호 | 같은 첫 주소 / E-VLT-001, 1초 비활성 |
| UI-M3-10 | M3 | 앱 실행 중 exe 재실행, `--background` 재실행 | 기존 창이 앞으로 / 변화 없음, 프로세스 1개 |
| UI-M3-11 | M3 | `QuickNode 멀티체인`에 실제 엔드포인트 이름·토큰 붙여넣기 → `저장` → `네트워크 URL 생성` → `eip155:1`·`eip155:11155111` `테스트` → 재시작 → 같은 `테스트`(빈 칸); 토큰 한 글자 바꾼 URL을 Sepolia `교체` 칸에 넣고 `테스트`; Ethereum 메인넷 URL을 Sepolia `교체` 칸에 넣고 `테스트`; Sepolia URL `삭제` 후 S10; 다른 Windows 사용자로 `apikeys.dpapi` 복사 후 실행 | T-RPC-OK, 목록은 가린 형태만, 이름·토큰·URL·호스트가 화면·로그에 없음(로그는 `net=<NetworkId>`만) / E-RPC-003(구현 시 확인: QuickNode의 잘못된 토큰 응답, §2.11.1) / E-RPC-010 "엔드포인트 테스트 실패: chainId 불일치 — 다른 네트워크의 URL입니다. (RPC chainId 1)" / 상태 줄 "엔드포인트 없음 (E-KEY-005)" / E-KEY-001 |
| UI-M3-12 | M3 | `abandon … about` 가져오기 | S06 첫 주소 `0x9858EfFD232B4033E47d90003D41EC34EcaEda94` |
| UI-M3-13 | M3 | passphrase 지갑 가져오기 → 재시작 → 다른 passphrase 입력 | T-PASS-MISMATCH, 계속 시 T-ALT-PASS 배너 |
| UI-M3-14 | M3 | 125%·150% 배율 모니터 사이 창 이동 | 글자·QR 잘림 없음 |
| UI-M4-01 | M4 | Sepolia ETH 보내기(주소 붙여넣기) | 승인 창 헤더·제목·자산 변화 표시, 확정까지 활동 갱신 |
| UI-M4-02 | M4 | Sepolia ERC-20 보내기 | 같음, 토큰 라벨·컨트랙트 주소 표시 |
| UI-M4-03 | M4 | 되돌려지는 거래(잔액보다 큰 토큰 전송) 검토 → 체크 없이 2초 누르기 → 체크 + 2초 누르기 | "시뮬레이션 중…" 동안 승인 비활성, 이어서 맨 위 띠 E-SIM-001 "시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다" + 되돌림 이유, 자산 변화 T-SIM-NODIFF / 진행 없음 / 전송, 활동 `failed`(영수증 status 0) |
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
