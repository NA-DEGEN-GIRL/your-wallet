# Android 이식 타당성 검토 — 2026-11-07 (HEAD `82ff8a1`)

지금 Windows 지갑의 보안 수준을 Android 앱으로도 만들 수 있는지 검토했다. **코드는 바꾸지 않았다**(이 문서와
README 링크 한 줄만 추가). 여섯 영역을 따로 조사해 합쳤다: ① 플랫폼 보안 기본 요소(Keystore·FLAG_SECURE·
클립보드·IME·메모리·백업·오버레이·접근성) ② Rust 코어 이식(NDK·의존성·FFI·재사용률) ③ UI와 승인 화면
④ dApp 연결·네트워크·백그라운드 제한 ⑤ YubiKey(NFC·USB) ⑥ 배포·업데이트·위협 모델·노력 추정.

표기:

- **[확인]** 이 저장소나 이 PC에서 직접 확인함(파일·줄 수·`cargo metadata`·허용 목록 검사 실행 결과)
- **[문서]** Android·Yubico·WalletConnect 등 공식 문서 기준
- **[2차]** 뉴스·블로그·제3자 문서 기준(공식 확인 전)
- **[미확인]** 기기·하드웨어에서 재어 봐야 함. 모두 §7 P0 스파이크 항목이다
- **[추정]** 노력·크기 추정치

> Android용 Rust 타깃은 설치돼 있지 않아 **아무것도 Android용으로 컴파일하지 않았다**[확인]. 의존성 결론은
> `cargo metadata --locked --offline --filter-platform <타깃>`과 `scripts/check-core-deps.mjs --metadata`
> 실행 결과이며(lockfile·작업 트리 무변경), 빌드 결과가 아니다.

---

## 1. 결론

### 1.1 판정: **조건부 GO** — MVP 범위로 시작하고, 전체 패리티는 P0 스파이크 뒤 따로 정한다

- 서명·승인·저장 보증의 중심은 `yw-core`에 있고, `yw-core`는 OS를 쓰는 곳이 `getrandom::fill`
  (`crates/yw-core/src/entropy/mod.rs`) 하나뿐이다[확인: `cfg(windows|target_os|…)`, `std::fs/net/process/thread/time`
  없음, `#![forbid(unsafe_code)]`]. 그래서 다음은 **같은 코드로, 바이트 단위로** 옮겨진다: vault v3(Argon2id
  256 MiB/t3/p4 + XChaCha20-Poly1305, spec/02 §4), meta·journal 봉인, D10의 작업마다 복호·파생·소거, 코어가 만든
  승인 표시·표시 digest·승인 digest·one-shot 소비(spec/03 §11.3–11.5), 위험 규칙, BTC 이전 트랜잭션 검증,
  YubiKey APDU·OpenPGP·PIV 흐름, WalletConnect X25519/HKDF/JWT. vault·meta·journal 파일은 고정 big-endian 형식이라
  Windows와 Android에서 그대로 호환된다.
- 비용은 암호가 아니라 **`yw-app`을 Win32에서 떼어내는 일**이다. `yw-app/src`의 127개 파일 중 75개가 `yw_win`을
  import한다[확인]. 승인 세션·arm 지연·디스패처·journal 대조·WalletConnect 엔진을 Java로 다시 쓰면 보안 핵심 로직이
  두 벌이 되므로, 플랫폼 중립 엔진 크레이트로 옮긴 뒤 Android 셸은 그 엔진만 쓰는 구조가 필요하다(§3).
- 노력[추정]: 좁은 MVP 20–30 인주(person-week), 전체 패리티 34–50 인주. 다른 렌즈의 추정은 4–7 인월로 더 낮다.
  차이와 근거는 §7.

### 1.2 "같은 보안 수준"의 정의

다음 세 조건을 모두 만족하면 "같은 수준"으로 본다.

1. `spec.md` §2.1의 방어 대상 각 행이 Android에서도 **같은 방법이나 그보다 강한 방법**으로 방어된다.
2. §2.2 비목표에 대응하는 Android 비목표를 명시하고, 그 경계가 Windows보다 넓어지지 않는다.
   Windows의 경계는 "같은 사용자 권한의 코드 = 게임 오버"다. Android에서는 앱마다 다른 UID로 격리되므로 일반 앱은
   경계 안쪽(방어 대상)으로 들어오고, 경계는 "**사용자가 강한 권한을 준 앱**(접근성 서비스, 오버레이, 알림 리스너,
   기기 관리자)과 **root·부트로더 해제·TEE 장악**"으로 옮겨진다.
3. 맞출 수 없는 속성은 숨기지 않고 spec/14(신설 제안)에서 **비목표로 옮기거나 기능을 뺀다**(§2.3 게이트 규칙:
   "검증할 수 없으면 차단" 금지).

**예외 하나:** 키보드(IME)는 모든 폰에 있고 대개 제3자·클라우드 학습 앱이라 "사용자가 준 권한"으로 비목표에 넣을 수
없다. 그래서 **앱 내 키패드가 필수**다. 이게 없으면 Windows보다 크게 약해진다.

### 1.3 Android가 더 강한 점

- **앱 샌드박스(UID 분리)**: 일반 앱은 우리 파일·메모리를 읽지 못한다. Windows의 "같은 사용자 악성코드 = 비목표"보다 기준선이 높다[문서].
- **최대 절전 파일 없음**: `hiberfil.sys` 잔여 위험(§2.2)이 사라진다. 스왑은 대개 zRAM(압축 RAM)이다[문서].
- **저장소 암호화 기본**(파일 기반 암호화). BitLocker 권고는 "강한 잠금 화면 자격 증명" 권고로 바뀐다.
- **FLAG_SECURE**는 스크린샷·화면 녹화·MediaProjection·비보안 디스플레이 캐스팅·최근 앱 썸네일까지 막는다[문서].
- **Android 12+**는 다른 UID의 신뢰되지 않은 오버레이를 통과한 터치를 기본으로 막는다[문서].
- **API 36(Android 16)+**에서 `accessibilityDataSensitive` 뷰는 도구가 아닌 접근성 서비스의 `dispatchGesture`
  주입을 막는다[문서]. Windows의 주입 입력 검사(`physical_down`, spec/04 §3.4-3)는 "보안 경계 아님"이었으므로 이 점은 Android가 더 강하다.
- **Keystore**(TEE/StrongBox)는 키를 하드웨어에 묶는다. DPAPI보다 같거나 강하다.
- **네트워크 보안 설정 기본값**: 평문 금지, 사용자가 설치한 CA 불신(API 24+ 대상). CT는 API 36에서 선택, API 37에서 기본[문서].

### 1.4 맞출 수 없는 것

| # | 속성 | 이유 | 처리 제안 |
|---|---|---|---|
| U1 | 브라우저가 보증하는 dApp origin(확장 `port.sender`) | Chrome Android는 확장이 없고, Firefox Android의 `connectNative`는 GeckoView 임베더 전용[문서] | WalletConnect만 사용. origin은 dApp이 주장한 값 + Verify. "확인 불가" 경고가 거의 모든 승인에 붙는다(경고 피로) |
| U2 | 클립보드 기록·클라우드 동기화·모니터 제외(D11) | Android에 대응 포맷이 없다. `EXTRA_IS_SENSITIVE`(API 33)는 미리보기만 숨긴다. 키보드 앱이 자체 클립보드 기록을 둔다[문서] | 비밀 복사 기능을 Android에서 **뺀다** |
| U3 | 승인 창을 강제로 앞에 띄우기(spec/04 §3.6) | Android 10+ 백그라운드 액티비티 시작 금지[문서] | 딥링크(사용자 시작) 또는 알림 탭으로만 연다. 보안 차이가 아니라 UX 차이 |
| U4 | API 34–35에서 접근성 악성 앱의 2초 누르기 주입 차단 | `dispatchGesture` 차단은 API 36+[문서]. `isAccessibilityTool`은 서비스가 스스로 선언하고 Play 정책으로만 강제되므로, 사이드로드된 악성 서비스가 거짓 선언할 수 있다[미확인] | minSdk와 함께 결정(§8 Q1). API 36 미만에서는 경고 띠 |
| U5 | 앱 제거 뒤 데이터 보존 | 앱 제거 = 앱 전용 데이터(vault) 삭제. Windows는 `%LOCALAPPDATA%\YourWallet`이 남는다 | 복구는 니모닉·YubiKey. 설치 안내에 크게 경고 |
| U6 | 하드웨어 신뢰 UI(보이는 것 = 서명되는 것) | Android Protected Confirmation은 AOSP에서 폐기됐고 secp256k1·Ed25519를 지원한 적 없다[문서] | Windows도 없음(동일). 다만 폰이 악성코드의 더 흔한 표적 |
| U7 | NFC에서 서명마다 YubiKey 터치 | 터치 정책 "Always"가 NFC 필드 세션 안에서 서명마다 새 존재 확인을 요구하는지 Yubico 문서에 없다[미확인] | 하드웨어 시험 전까지 "탭 1회가 마지막 방어선"으로 약하게 적는다 |
| U8 | 가장 강한 플랫폼 설정과 소스 빌드 설치의 공존 | Advanced Protection은 출처를 알 수 없는 앱의 설치·업데이트를 막는다[문서]. ADB 설치도 막는지는 2차 자료뿐[미확인] | P0에서 사용자 폰으로 확인(§8 Q2) |
| U9 | 저사양 폰에서 Argon2 256 MiB | 2–3 GB RAM·Android Go·32비트 사용자 공간 폰에서는 lmkd가 프로세스를 죽인다(깔끔한 OOM 오류가 아님). §4.5가 정확한 파라미터만 받으므로 낮추면 새 형식(v4) | 64비트·4 GB+ 폰만 지원. 잠금 해제 전 메모리 확인 후 거절 |

### 1.5 확인하지 못한 것 (모두 §7 P0에서 확인)

- Android용 실제 컴파일: rust-std 미설치[확인]. `secp256k1-sys`의 C 빌드가 NDK r30의 새 clang에서 경고·오류를 낼 수 있다.
  NDK `.cmd` 래퍼가 `D:\#Programming`의 `#`에 MSVC처럼 걸리는지도 모른다.
- 사용자 폰에서 Argon2 KDF_V3 1회 시간과 최대 메모리. spec/02 §7.4·§11은 10 s를 넘으면 `KDF_V3` 개정 사안으로 본다.
  `argon2 0.5.3`은 `parallel` 기능 없이 4개 lane을 순차 계산하고 aarch64 SIMD 경로가 없어 멀티코어 이득이 없다.
- YubiKey NFC 터치 의미(U7), Advanced Protection과 ADB(U8), 사이드로드 앱의 `isAccessibilityTool` 거짓 선언(U4).
- 스크린샷으로 맞춘 자체 QR 디코더(`qr_decode.rs`)가 카메라 프레임(흐림·원근·반사·저대비)에서 동작하는지.
- `.so` 크기(코어+엔진 ABI당 3–5 MB로 추정)와 16 KB 페이지 정렬.

---

## 2. Windows 보호 수단 ↔ Android 대응

판정: **동일** / **강함**(Android가 더 강함) / **조건부**(표의 조건을 지켜야 동일) / **약함** / **불가**.
최소 API는 그 기능이 생긴 API 레벨이다.

| # | Windows 보호 수단(근거) | Android 대응(최소 API) | 차이·잔여 위험 | 판정 |
|---|---|---|---|---|
| 1 | vault v3: Argon2id 256 MiB/t3/p4 + XChaCha20-Poly1305(D7, spec/02 §4) | 같은 `yw-core` 코드. 파일은 `getNoBackupFilesDir()` | 저사양 폰 lmkd 종료(U9). 32비트 주소 공간에서 연속 256 MiB 예약은 위험 → arm64 전용 | 조건부 |
| 2 | BitLocker 권고(§2.4) | 파일 기반 암호화(기본) + 강한 잠금 화면. 선택: Keystore 비인증 AES-256-GCM 키로 vault 파일을 한 겹 더 감싸는 **기기 결속**(`VaultStorage` 어댑터 안, v3 내부 형식 무변경) | 기기 결속 시 백업·기기 간 전송·포렌식 복사본은 그 기기 밖에서 오프라인 추측이 불가능해진다. Keystore는 키 추출은 막지만 장악된 OS가 키를 **쓰는 것**은 막지 못한다[문서] | 강함(선택 시) |
| 3 | DPAPI(`apikeys.dpapi`, D10·D13) | Keystore AES-256-GCM 키(TEE). NDK에는 Keystore API가 없어 Java 경유 | 하드웨어 결속이라 같거나 강함 | 동일 이상 |
| 4 | DEK·passphrase를 VirtualLock 페이지에(D10, spec/02 §7.3) | `LockedSlot` = `mmap` 1페이지 + `mlock` + `MADV_DONTDUMP`, 프로세스 `PR_SET_DUMPABLE 0`. 앱 `RLIMIT_MEMLOCK`은 64 KiB(Android 14부터 CTS 강제)[문서]. 페이지 크기는 4096 고정이 아니라 `sysconf`(16 KB 페이지 기기) | `mlock` 실패 시 닫힘(E-VLT-007과 같게). Argon2 256 MiB 버퍼·짧은 평문 버퍼는 Windows처럼 잠그지 못한다 | 동일 |
| 5 | 최대 절전·페이지 파일 잔여(§2.2 비목표) | 최대 절전 없음. zRAM 스왑. 일부 OEM의 "RAM Plus"는 저장소 스왑 → `mlock`한 슬롯은 제외됨 | 잠그지 못한 버퍼는 OEM 저장소 스왑에 갈 수 있다 | 강함 |
| 6 | 크래시 덤프 업로드 없음, `panic = "abort"`(D28) | 같은 설정. SIGABRT 시 `/data/tombstones`에 스택·레지스터 주변 메모리(시스템 전용, bugreport에 포함)[문서] | WER 덤프와 비슷한 잔여 위험. 소거가 창을 좁힐 뿐 없애지 못한다 | 동일 |
| 7 | 비밀 창 `WDA_EXCLUDEFROMCAPTURE`(D11) | `FLAG_SECURE` + `setRecentsScreenshotEnabled(false)`(33) + `View.setContentSensitivity`(35) + 스크린샷 감지(34)·녹화 콜백(35)은 경고 신호로만. 비밀 버퍼를 넘기기 전에 창 플래그를 다시 읽어 확인(spec/04 §4.5 "Required"와 같은 뜻) | Google 문서상 API 30 이하에서는 약 70% 기기만 안정적으로 보호(minSdk 34면 해당 없음). root·LSPosed(DisableFlagSecure)·OEM 미러링으로 우회 가능 | 조건부 |
| 8 | 직접 그린 비밀 입력: EDIT 컨트롤 없음, IME 분리, `WM_GETTEXT`·`WM_GETOBJECT` 차단(D11, spec/04 §4.2–4.6) | **앱 내 키패드 View**(InputConnection을 열지 않음): 비밀번호·PIN은 ASCII 여러 층, BIP39는 a–z + 접두어 완성, 키는 hex·base58 패드. `importantForAutofill=noExcludeDescendants`, `importantForContentCapture=no`, `accessibilityDataSensitive`, `contentDescription`에 텍스트 없음 | `IME_FLAG_NO_PERSONALIZED_LEARNING`은 "보장 아님"(문서 원문 취지)이라 대안이 안 된다. 12–128자 비밀번호 입력 마찰 | 조건부(키패드 없으면 **약함**) |
| 9 | 복사 기본 금지, 허용 시 기록·클라우드·모니터 제외 + 30초 삭제(D11) | 비밀 복사 기능 제거. 붙여넣기만 허용하고 붙여넣은 뒤 클립 지움. 주소 등 비밀 아닌 복사는 `EXTRA_IS_SENSITIVE`(33) | U2 | 불가(기능 제거) |
| 10 | 자동 잠금: 유휴·세션 잠금·절전·수동(D12) | `onStop`, `ACTION_SCREEN_OFF`, `onTrimMemory`, `dispatchTouchEvent` 기반 유휴, 수동. 프로세스 종료 = 잠금(DEK 소멸) | Rust `Instant`는 `CLOCK_MONOTONIC`이라 깊은 절전 동안 멈춘다 → 120 s 승인 기한이 절전 중 흐르지 않는다. 화면 꺼짐·백그라운드 전환마다 반드시 잠그고 열린 승인을 거부해야 맞다(spec/04 §5.3과 같은 규칙) | 동일 |
| 11 | 승인 1 s arm 지연 + 고위험 2 s 누르기, 전면일 때만(spec/04 §3.4, `ui/interaction.rs`) | 같은 `interaction.rs`(순수, Win32 결합은 `stray_press`의 `yw_win::ui::Msg` 하나). `ACTION_DOWN/MOVE/UP/CANCEL`·두 번째 손가락·가림 플래그·`onWindowFocusChanged(false)`/`onPause`를 `InteractionEvent`로 변환. 포커스 회복·`onResume`마다 arm 재시작 | API 34–35에서는 접근성 서비스가 hold를 주입할 수 있다(U4). 딥링크 전환 직후 dApp을 누르던 엄지 아래에 승인 버튼이 오므로 arm 지연이 데스크톱보다 더 중요하다 | API 36+ 강함 / 34–35 약함 |
| 12 | 승인 창 가림 방지(최상위 창) | Android 12+ 기본 차단, `setHideOverlayWindows(true)`(31, `HIDE_OVERLAY_WINDOWS`), `filterTouchesWhenObscured`, `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`는 직접 검사해 `OtherPress`로 센다 | 부분 가림은 화면 조광기·채팅 버블 같은 정상 오버레이에서도 생긴다(오탐). 나란히 놓은 다중 창은 가림 플래그가 안 생겨 포커스·arm 규칙만이 방어 | 동일 이상 |
| 13 | 승인 표시 무결성: 코어가 만든 표시만, digest 결속, one-shot(§2.1, spec/03 §11) | 같은 Rust. Java는 Rust가 준 줄·사각형만 그린다. 줄바꿈(`text_layout`)과 금지 문자 재검사(spec/04 §3.3)도 Rust. **보조 창 금지**(Dialog·PopupWindow·Spinner·Toast는 별도 창이라 FLAG_SECURE·가림 보호를 물려받지 않을 수 있다) | 두 셸의 표시가 어긋날 위험 → 양쪽 모두 코어 표시 모델만 그린다 | 동일 |
| 14 | 승인 창 앞으로(`SetForegroundWindow`·`WS_EX_TOPMOST`·`FlashWindowEx`, spec/04 §3.6) | 딥링크(사용자 시작이라 허용) 또는 `VISIBILITY_SECRET` 알림(일반 문구만) 탭. 전체 화면 인텐트·`SYSTEM_ALERT_WINDOW` 쓰지 않음 | U3 | 불가(UX) |
| 15 | 같은 사용자 악성코드 = 비목표(§2.2) | UID 샌드박스. 남는 것은 사용자가 준 권한(접근성·오버레이·IME·알림 리스너)과 root | 기준선 상승. 대신 접근성·IME 악성코드가 Android 지갑의 주 위협(Crocodilus, SparkCat 등)[2차] | 강함 |
| 16 | 관리자·커널 장악 = 비목표 | root·부트로더 해제·LSPosed·TEE 장악 = 비목표. Play Integrity 게이트 금지(§2.3, Google 서버 의존, GrapheneOS 실패, 자가 빌드 앱 미인식). 원하면 로컬 key attestation 결과를 **정보 배지로만** | 고급 사용자 중 root 기기가 흔하다. 키 증명 루트는 2026-02 신규 ECDSA P-384 루트와 기존 RSA 루트를 모두 둬야 한다[2차] | 동일(비목표) |
| 17 | 확장 → yw-host → 사용자 전용 named pipe, 고정 확장 ID(D3, D22–D24) | 없음 | U1 | 불가 |
| 18 | WalletConnect v2(D35, spec/13) | 같은 엔진 + Java I/O(§4) | 백그라운드에서 relay 유지 불가 → 잠금 시 동작 재설계(§4.3) | 동일(보안) / UX 다름 |
| 19 | RPC TLS(WinHTTP: 리디렉션·캐시·쿠키 끔, Origin·Referer 없음, 전체 기한, spec/01 §7.4) | `HttpsURLConnection` 같은 설정 + 전체 기한 감시 스레드(`disconnect()`). 네트워크 보안 설정: 평문 금지(LLM localhost 예외), 시스템 CA만, CT 켬. Java 예외는 JNI를 넘기 전 고정 열거형으로 바꾼다(예외 문구에 URL·호스트가 들어가므로 D13 위반 방지) | 사설 CA로 운영하는 자체 RPC는 Windows에서는 되지만 Android에서는 설정이 필요 | 동일 이상 |
| 20 | YubiKey PC/SC(D33, spec/10) | NFC `IsoDep`(프레임워크) / USB-C `UsbManager` + 자체 CCID | U7. NFC에서 PIN이 무선으로 평문 전송(SCP11b 미지원) | USB 동일 / NFC 미확인 |
| 21 | 의존성 허용 목록(D5), unsafe는 `yw-win`만(D4) | aarch64에서 `libc 0.2.189` 1개 추가(이미 Cargo.lock·오프라인 캐시에 있음), 두 번째 unsafe 크레이트 `yw-android`. Android SDK·NDK·JDK가 새 툴체인. Gradle·AndroidX·Kotlin 배제 | 정책 문구 개정 필요(D4·D5, spec/01 §3.3) | 개정 필요 |
| 22 | 소스만 배포, `install.cmd`(D1) | 사용자 PC에서 빌드 → 사용자 키로 서명 → `adb install -r` | 서명 키가 새 업데이트 신뢰 루트. 분실 시 업데이트 불가(삭제 후 재설치 = vault 삭제). Advanced Protection 충돌(U8). 정책 변경 가능성 | 조건부 |
| 23 | 디스크·백업 파일 도난(§2.1) | vault·meta·journal은 `no_backup`에. `allowBackup=false` + `dataExtractionRules`로 cloud-backup·device-transfer·cross-platform-transfer(Android 16 QPR2) 전부 제외 | API 31+에서 일부 OEM은 `allowBackup=false`여도 기기 간 전송을 한다[문서] → `no_backup` 경로가 핵심 | 동일 |
| 24 | 텔레메트리 없음(D28) | FCM 푸시·Play Integrity·Play 서비스 의존 없음 | 백그라운드 요청 알림 불가(§4.3) | 동일 |
| 25 | 앱 내부 공격 면 없음(데스크톱 웹 콘텐츠 없음) | 인앱 dApp 브라우저(WebView) 만들지 않음(§4.4) | — | 동일 |
| 26 | 작업 하이재킹 해당 없음 | minSdk 30+로 StrandHogg 계열 수정, 승인 액티비티는 비공개(exported=false)·`excludeFromRecents`·별도 `taskAffinity`. target 37에서 `allowCrossUidActivitySwitchFromBelow=false` | — | 동일 |

---

## 3. 아키텍처 제안

### 3.1 크레이트 배치

```
yw-core     (그대로)  #![forbid(unsafe_code)], 의존: 허용 목록 + yw-json
yw-json     (그대로)
yw-engine   (신설)    #![forbid(unsafe_code)], 의존: yw-core, yw-json만
              ← yw-app에서 이동: workers, flow, btc, sol, zec, hypercore, rpc, walletconnect(engine·store·worker·
                 qr_decode·verify 로직), browser(dispatch·grants·params·envelope; server.rs 제외), explain, meta,
                 settings, store, errors, network, logging, text, token_view, yubikey 흐름, ui::interaction,
                 ui::text_layout
              ← 플랫폼 trait: Http/Transport, RelayLink·RelayConnector(이미 있음), VerifyHttp(이미 있음), Clock,
                 Fs(atomic_write·read_limited), SecretStore(DPAPI|Keystore), LockedPageAlloc, CardSource+MgmtCipher,
                 P256Verify, ImageSource, Doorbell
              ← 앱 상태 기계(Rc<RefCell<App>>)는 command/event API를 가진 Controller로 추출
yw-win      (그대로)  Windows 구현. unsafe 허용
yw-app      (축소)    Win32 셸: ui/, 창 처리기, 메시지 루프
yw-host     (그대로)  Windows 전용
yw-android  (신설)    cdylib. unsafe 허용(yw-win과 같은 규칙: 모듈별 #![allow(unsafe_code)], unsafe 블록당 연산 1개,
                      // SAFETY: 주석). 손으로 쓴 JNI + mlock/madvise/prctl + Android 쪽 trait 구현
android/    (신설)    Java 소스, AndroidManifest.xml, res. Gradle 없이 스크립트로 빌드
```

이미 있는 경계가 이 분리를 돕는다[확인]: `yw-core`의 `VaultStorage`(vault/mod.rs:91), `LockedSlot`(:131),
`CardTransport`(yubikey/mod.rs:52), `MgmtCipher`(yubikey/piv.rs:143); `yw-app`의 `rpc::Transport`,
`walletconnect::{RelayLink, RelayConnector, WcSink}`, `verify::VerifyHttp`, `explain::LlmTransport`,
`flow::evm::Clock`, `yubikey::CardSource`, `browser::{Outlet, DappSink}`. WalletConnect는 이미 모든 요청을
`browser::BrowserCore`의 가상 연결로 보내므로 디스패처(grant·승인 큐·arm 지연·위험·시뮬레이션)가 그대로 따라간다.

### 3.2 재사용률

생산 코드 줄 수(테스트 제외, 코어 렌즈 측정). 참고로 `src/` 전체(파일 내 테스트 포함)는 `yw-core` 71,106줄,
`yw-app` 101,152줄이고, `yw-app`의 `tests/`까지 합치면 127,997줄이다[확인].

| 구성 | 줄 | Android 재사용 |
|---|---:|---|
| `yw-core` | 54,937 | 100% 그대로(테스트 16.3k줄은 Windows 호스트에서 계속 돈다) |
| `yw-json` | 834 | 100% |
| `yw-app` 순수 모듈(`yw_win` 미사용: walletconnect/engine, qr_decode, browser/dispatch 등) | 20,866 | 약 100% |
| `yw-app` 서비스 전용(`yw_win`의 http 51회·time 50·cng 7·ws 6·file 6·dpapi 4·mem 3·pcsc 1만 사용) | 21,773 | 약 90%(trait 뒤로) |
| `yw-app` GUI 결합(app_*.rs, main.rs, lock.rs, browser/server.rs) | 30,266 | 40–50%(상태 기계 추출 후) |
| `yw-app` ui/ | 21,271 | 약 0%(단 순수 모듈 `interaction.rs` 758줄·`text_layout`은 재사용) |
| `yw-win` | 11,035 | 0%(Android 구현 새로) |
| `yw-host` | 630 | 0%(불필요) |
| **합계** | **약 161.6k** | **그대로 47% · trait 도입 후 60% · app_* 추출 후 68%** |

새로 쓸 것: Rust 약 50k줄 상당(Win32 UI·yw-win·yw-host·app_* 나머지의 Android 대응) + Java UI 전체.
코어 자체는 전체 작업의 약 2%다[추정].

### 3.3 FFI: 새 크레이트 없이 손으로 쓴 JNI

| 선택지 | 판정 | 이유 |
|---|---|---|
| `jni` 크레이트 | 거부 | 새 크레이트 약 10개(jni-sys, combine, cesu8, thiserror, log, walkdir …) → D5 위반 |
| UniFFI | 거부 | proc-macro·syn·quote·anyhow·bytes·camino 등 + Kotlin 쪽 JNA(제3자 네이티브 라이브러리) → 이중 위반 |
| 순수 C ABI | 불가 | ART에는 FFM/Panama가 없어 Java는 JNI로만 네이티브를 부른다 |
| **손으로 쓴 raw JNI**(`yw-android`) | **권장** | `JNI_OnLoad` 하나만 export하고 `RegisterNatives`로 등록(Android JNI tips 권장). Edition 2024는 `#[unsafe(no_mangle)]`. `panic = "abort"`라 JNI 경계를 넘는 unwind가 없다 |

`JNIEnv` 함수 표는 JNI 명세상 고정 인덱스라 필요한 칸만 선언한다: `FindClass`(6), `ExceptionClear`(17),
`GetArrayLength`(171), `NewByteArray`(176), `GetByteArrayRegion`(200), `SetByteArrayRegion`(208),
`RegisterNatives`(215), `ExceptionCheck`(228). 인덱스를 컴파일러가 검사하지 않으므로 에뮬레이터에서 CheckJNI로 확인한다.

**좁은 허리(narrow waist)** — 네이티브 메서드 4개, Rust 스레드는 Java를 부르지 않는다(`AttachCurrentThread`·전역
참조·`jclass` 캐시 불필요):

| 메서드 | 역할 |
|---|---|
| `byte[] call(byte[] cmd)` | `yw-json`으로 인코딩한 명령 |
| `byte[] next(long timeoutMs)` | 전용 Java 스레드 하나가 막고 기다리는 이벤트 poll → 메인 Looper로 전달. Windows `WM_YW_EVENTS` 초인종(spec/04 §1.3) 대체 |
| `void ioComplete(long id, int status, byte[] body)` | Java가 한 플랫폼 I/O(HTTPS, WSS 프레임, NFC APDU, Keystore unwrap, ECB·P-256)의 결과. 요청은 `next`로 나가고 완료는 이걸로 들어온다 |
| `void secretKey(int field, int codeUnit)` | 키패드 입력을 한 글자씩 네이티브 `WipeBuf`로(yw-win `ui/secure_text.rs`와 같은 방식). 비밀이 Java `String`이 되지 않는다 |

비밀 표시(W05 단어 격자, W08 니모닉, W09 키)는 `char[]`를 `Canvas.drawText(char[], …)`로 그린 뒤 0으로 지운다.
Skia 글리프·GPU 버퍼는 남는 사본이며, spec/02 §7.3이 데스크톱에서 받아들인 짧은 힙 사본과 같은 급이다.

`mlock`·`mmap`·`madvise`·`prctl`은 (a) 이미 aarch64 의존성 그래프에 있는 `libc`를 `yw-android`의 직접 의존으로
쓰거나 (b) bionic 심볼 4개를 `extern "C"`로 직접 선언할 수 있다. 상수(`MADV_DONTDUMP`, `PR_SET_DUMPABLE`)를
손으로 옮기는 실수를 피하려면 (a)가 낫다. 결정 필요(§8 Q3).

### 3.4 UI 스택: Java + 프레임워크 View만

| 선택지 | 판정 | 이유 |
|---|---|---|
| Kotlin + Compose + AndroidX + Gradle/AGP | 거부 | `androidx.compose.ui:ui-android 1.8.0` 직접 의존 24개(kotlinx-coroutines, emoji2, profileinstaller 등), `material3-android 1.3.2` 15개 추가, 전이 그래프와 AGP 빌드 그래프는 수백 개[추정]. Compose `Dialog`·`Popup`은 별도 창이라 `SecureFlagPolicy` 전에는 FLAG_SECURE를 물려받지 않았다 |
| Rust 네이티브 UI(Slint, egui) | 거부 | `android-activity`·`winit` 등 크레이트 수십 개. 그래도 TalkBack·BiometricPrompt·알림·`accessibilityDataSensitive`는 JNI가 필요(NDK로 닿는 건 FLAG_SECURE 정도) |
| **Java + 프레임워크 View** | **권장** | `android.jar`는 컴파일 전용. APK에는 우리 dex와 Rust `.so`만 → 런타임 의존 0. 보안 표면(승인 화면, 비밀 입력, 니모닉·키 표시)은 직접 그린다 |

원칙은 **"Rust가 정하고 Java는 그린다"**: `ApprovalSession`·`ApprovalGate`·`ApprovalStore`·`text_layout`·금지 문자
재검사는 Rust에 있고, Java는 정규화한 터치·포커스·수명주기 이벤트를 타임스탬프와 함께 넘기고 Rust가 준 줄·사각형을
그린다. MotionEvent·수명주기 → `InteractionEvent` 변환을 Rust 호스트 표 테스트로 두고, 기존 AP-1..AP-5를 기준으로 유지한다.

AndroidX를 쓰지 않으므로 BiometricPrompt는 프레임워크 `android.hardware.biometrics.BiometricPrompt`(API 28,
`setAllowedAuthenticators`는 30), 카메라는 Camera2(API 21)를 쓴다. CameraX(`camera-camera2 1.4.2` 직접 의존 7개)와
ML Kit(비공개 Play 서비스 코드)는 쓰지 않는다.

### 3.5 빌드와 의존성 정책

- **Rust 타깃**: `aarch64-linux-android`(실기기) + `x86_64-linux-android`(에뮬레이터 전용). armv7은 뺀다(32비트에서 256 MiB
  연속 할당이 불안정하고 허용 목록 변형이 하나 더 생긴다). 설치(`rustup target add …`)는 사용자 승인 후(§8 Q4).
- **의존성 그래프**[확인, `cargo metadata` + 허용 목록 검사]:
  - `aarch64-linux-android`: 실패 항목은 `libc=0.2.189 not in allowlist`와 libc의 미검토 `build.rs` 둘뿐. 경로는
    `sha2`·`keccak` → `cpufeatures 0.2.17` → `libc`(aarch64-linux-android에 무조건 의존)와 `getrandom` → `libc`.
    어떤 cfg로도 aarch64에서는 못 뺀다. `libc`는 이미 Cargo.lock·오프라인 캐시에 있으므로 `--offline --locked`가
    그대로 성립하고 `cargo update`가 필요 없다. Cargo.lock에는 `jni`·`jni-sys`·`sha1`이 없다[확인].
  - `x86_64-linux-android`: `--cfg curve25519_dalek_backend="serial"`이 없으면 `curve25519-dalek-derive`·`proc-macro2`·
    `quote`·`syn`·`unicode-ident`가 들어온다(`.cargo/config.toml`이 serial을 MSVC 타깃에만 설정). 넣으면 Windows와
    같은 40개.
  - → `scripts/check-core-deps.mjs`의 `TARGET = "x86_64-pc-windows-msvc"`(10행)를 타깃별 표로 바꾸고 Android 표에
    `libc=0.2.189` 런타임과 libc `build.rs`를 추가. `.cargo/config.toml`에 `[target.x86_64-linux-android]`(및
    안전하게 aarch64에도) serial cfg 추가. D4·D5·spec/01 §3.3 개정.
- **getrandom**: 기본 백엔드(`linux_android_with_fallback`) 유지. spec/02 §1.1이 `getrandom_backend` cfg를 금지하고,
  `linux_raw`로 바꿔도 aarch64에서는 `cpufeatures` 때문에 libc가 남는다. minSdk ≥ 28이면 bionic `getrandom`이 항상 있어
  `/dev/urandom` 대체 경로를 타지 않는다. 실패 시 생성 중단 규칙은 그대로다.
- **secp256k1-sys 0.11.0**: `build.rs`는 OS 분기 없는 `cc::Build`. `cc 1.4.2`가 Windows 호스트에서 NDK
  `<triple><api>-clang.cmd`를 인식한다. 스크립트가 `CC_<타깃>`·`AR_<타깃>`·`CARGO_TARGET_<T>_LINKER`를 설정.
- **16 KB 페이지**: NDK r28+는 기본 16 KB 정렬. `llvm-readelf -Wl`로 LOAD align 2**14와 RELRO 끝 정렬을 확인하고,
  아니면 `-Wl,-z,max-page-size=16384`. `zipalign -P 16`.
- **APK 빌드(Gradle 없음)**: `aapt2 compile/link` → `javac --release` (`android.jar` 대상) → `d8` → `zipalign` →
  `apksigner`. 별도 `scripts/build-android.ps1`(`check.ps1`은 환경의 `RUSTFLAGS`를, `install.ps1`은 링커 재정의를
  거부하므로 섞지 않는다). SDK build-tools·NDK·JDK 버전과 SHA-256을 `install.ps1`의 도구 검사처럼 고정·확인.
  `CARGO_TARGET_DIR`·`TMP`는 `#`이 없는 경로로.
  Gradle을 피할 수 없게 되면 `verification-metadata.xml`(`pgp,sha256`)과 키링을 커밋하되 런타임 의존은 0으로 유지.
- **이 PC의 도구**[확인, 읽기 전용]: `%LOCALAPPDATA%\Android\Sdk`에 NDK r30(30.0.16248370, aarch64 clang 26–37 래퍼),
  `platforms/android-36`, build-tools 36.0.0·37.0.0, android-35 시스템 이미지, cmdline-tools. JDK 21.0.12는
  `%LOCALAPPDATA%\Programs\jdk-21`에 있으나 PATH·`JAVA_HOME` 미설정(스크립트가 설정). Rust Android 타깃만 없다.
- **플랫폼 하한**: minSdk 34(`accessibilityDataSensitive`, 스크린샷 감지, Ed25519 TEE, StrandHogg 수정 포함),
  targetSdk 36(37 대상이 되면 `allowCrossUidActivitySwitchFromBelow`). 권장 기기: Android 16(API 36)+.
  arm64-v8a 전용. 64비트·4 GB+ RAM.

### 3.6 Keystore로 할 수 있는 것과 없는 것

- KeyMint `EcCurve`는 P-224/256/384/521과 Curve25519뿐이다. **secp256k1 없음**[문서]. EVM·BTC·ZEC·HyperCore 키는
  Windows처럼 소프트웨어 키로 남고 작업마다 복호·파생·소거한다(D10). Ed25519 서명은 TEE KeyMint v2(API 33)에만 있고
  StrongBox는 지원하지 않는다. StrongBox 범위: RSA-2048, AES-128/256, ECDSA/ECDH P-256, HMAC-SHA256, 3DES.
- 쓸 곳은 둘: (a) **기기 결속 외피**(§2 #2, 비인증 TEE 키, v3 형식 무변경), (b) API 키·RPC URL 저장(DPAPI 대체).
- **생체 빠른 잠금 해제**는 별개다. DEK를 생체 인증 키로 감싸면 지식 요소(비밀번호)를 생체로 바꾸는 것이므로 D7·D10의
  의미가 바뀐다. 제안: 기본 끔. 켜면 StrongBox AES-GCM(TEE 대체), 작업마다 `CryptoObject`
  (`setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`), `setInvalidatedByBiometricEnrollment(true)`,
  `setUnlockedDeviceRequired(true)`, 재부팅 후·N일마다 비밀번호 요구, 비밀번호 경로는 항상 유지. Android 16 QPR2
  Identity Check는 신뢰 장소 밖에서 화면 잠금 자격 대체를 없앨 수 있다[2차]. 위협 모델 변화를 spec에 적는다(§8 Q7).

---

## 4. dApp 연결

### 4.1 확장 경로는 사라진다

Chrome Android에는 확장이 없고, Firefox Android의 `runtime.connectNative`는 GeckoView 임베더 전용이라 다른 앱과
말할 수 없다[문서]. spec/05의 확장 + native messaging 구조는 Android에 대응물이 없다. **EVM dApp 연결은
WalletConnect v2만** 남는다(D35). 함께 잃는 것이 브라우저가 보증하던 origin(U1)이다. SIWE 도메인 검사는 주장값끼리의
비교가 된다.

### 4.2 WalletConnect 재사용

- `yw_win` 참조 0: `yw-core` walletconnect(uri 220·crypto 217·jwt 128줄), `yw-app` walletconnect/engine.rs(1,128)·
  store.rs·qr_decode.rs(1,406), browser/dispatch.rs(1,916)·grants.rs·params.rs.
- 플랫폼 결합은 몇 곳뿐: walletconnect/worker.rs:90–121(`yw_win::ws::WebSocket`에 대한 `RelayLink`, `WsConnector`),
  worker.rs:568(UA 접미사 `/windows` → `/android`), verify.rs:165–194(`yw_win::http::Client`, `yw_win::cng::p256_verify`),
  browser/mod.rs:23·181(`HttpsUrl`), browser/read.rs(RPC 읽기 전달), browser/server.rs(named pipe — Android에 불필요).
- 할 일: 이 모듈들을 `yw-engine`으로 옮기고, `HttpsUrl`을 코어 소유의 가리는(redacting) URL 타입으로 바꾸고, 읽기
  전달용 `RpcHttp` trait를 기존 `RelayConnector`·`VerifyHttp` 옆에 둔다. 기존 mock 종단 테스트(walletconnect/tests.rs)를
  새 크레이트로 옮겨 계속 통과시킨다.

### 4.3 네트워킹과 수명주기

- **HTTPS**: `HttpsURLConnection`(Conscrypt/BoringSSL, Mainline으로 OS 업데이트와 별개로 갱신, TLS 1.3 기본, 0-RTT 없음)[문서].
  리디렉션·캐시 끔, `CookieHandler` 없음, TLS 1.2+, 전체 기한 감시, 응답 크기 상한은 yw-win과 같게.
- **WebSocket**: 프레임워크에 공개 WebSocket 클라이언트가 없다(`java.net.http` 미포함, 보통 OkHttp를 쓰지만 okhttp+okio+
  kotlin-stdlib라 거부). RFC 6455 클라이언트를 **Java로** `SSLSocketFactory.getDefault()` 위에 쓴다. 이유: 핸드셰이크의
  `Sec-WebSocket-Accept` 검증에 SHA-1이 필요한데 Rust 허용 목록에는 sha2만 있다[확인: Cargo.lock에 sha1 없음] — Java
  `MessageDigest`로 해결. **`SSLSocket`은 호스트 이름을 검증하지 않는다** → `HttpsURLConnection.getDefaultHostnameVerifier()`
  또는 `SSLParameters`의 HTTPS 식별 알고리즘을 명시하고 SNI를 설정. 4 MiB 메시지 상한, 15 s ping, 2 s close, 기존 backoff.
  (코어 렌즈는 프레이밍을 Rust에 두는 안도 냈다. 핸드셰이크는 Java가 하고 프레이밍만 Rust에 둘 수도 있으나, 단순함을
  위해 Java를 권장한다.)
- **백그라운드 제한**: Doze는 유지보수 창 밖에서 네트워크를 끊고, Android 15는 유효한 프로세스 수명주기 밖에서 시작한
  요청을 실패시킨다. `dataSync` FGS는 24시간에 6시간 상한(target 15+), `shortService`는 약 3분[문서]. 지갑용 상시
  서비스는 정당화가 어렵다.
- **푸시**: Reown 푸시는 FCM + WalletConnect 호스팅 푸시 서버 등록(relay 클라이언트 ID ↔ 기기 토큰 연결)이 필요하다[문서].
  Google 의존과 메타데이터 유출이라 D28과 맞지 않는다 → **쓰지 않는다**.
- **잠금 동작 재설계(새 D행 필요)**: 지금 spec/13 §5.2·§8은 "잠가도 relay 연결 유지, 들어오는 요청은 4100 거절(잠금 해제
  창 없음)"이다. Android에서는 백그라운드 전환 = 잠금이 보통이라 폰 하나로 dApp(Chrome) ↔ 지갑을 오가면 거의 모든 요청이
  4100이 된다. 제안: **액티비티가 보이고 잠금이 풀린 동안에만 relay에 연결**하고, 잠그거나 백그라운드로 가면 연결을 닫는다.
  요청은 relay 우편함이 TTL(`wc_sessionRequest` 300 s, tag 1108) 또는 요청 expiry까지 붙잡고, 지난 것은 기존 8000 처리.
  이미 spec/13 §8이 "첫 잠금 해제 전에는 연결하지 않고 우편함이 기다린다"로 같은 모양을 쓴다. 승인 응답을 보내는 중에
  사용자가 dApp으로 돌아가면 `shortService`(≤3분, 권한 불필요)로 마무리만 한다. 대가: 사용자가 300 s 안에 앱을 열고 잠금을
  풀지 않으면 요청이 만료된다(§8 Q8).
- **대기 트랜잭션 추적**: 지금도 journal 작업자는 잠금 해제 동안에만 돌고 journal 키는 DEK에서 HKDF로 파생된다. 잠긴
  상태에서는 읽을 수도 없으므로 WorkManager·JobScheduler·FGS가 필요 없다. 다음 잠금 해제 때 journal에서 이어 간다(D32).
  대기 항목에 "추적 일시 중지(잠김)"를 표시.

### 4.4 딥링크·QR·인앱 브라우저

- **페어링 입력**: ① 붙여넣기(데스크톱과 같음) ② 인텐트 필터 `wc:`와 자체 스킴(`yourwallet://wc?uri=`) — 페어링 화면을
  **미리 채우기만** 하고 "다른 앱이 열었음"을 표시, 자동 페어링 금지, 기존 15 s 쿨다운·제안 8개 상한 유지 ③ Camera2
  `ImageReader(YUV_420_888)`의 Y 평면을 `rowStride`를 지켜 복사해 `qr_decode::Gray::new`(qr_decode.rs:38)에 넣는다. ROI 자르기·
  축소, 작업 스레드에서 초당 5–10회. 카메라 같은 테스트 픽스처(흐림·원근·반사·저대비) 추가. `wc:` URI에 pairing symKey가
  들어 있으므로 **스캐너 화면도 FLAG_SECURE**.
- **스킴은 소유 검증이 없다**: 다른 지갑이나 악성 앱도 `wc:`·우리 스킴을 등록할 수 있다(페어링 URI 가로채기 → 키 손실은
  없지만 혼란). 반대로 아무 앱이나 조작한 `wc:` 인텐트를 보낼 수 있고, 보낸 쪽 식별(`ComponentCaller`)은 보낸 쪽이
  `setShareIdentityEnabled(true)`일 때만 된다[문서]. Verified App Links와 WalletConnect Link Mode는 HTTPS 도메인의
  `assetlinks.json`에 서명 인증서 지문이 필요한데, 사용자마다 서명 키가 다르고 공용 도메인이 없어 **쓸 수 없다**(Link Mode는
  spec/13 §9에서 이미 범위 밖).
- **dApp으로 돌아가기**: v1은 `redirect.native` 자동 이동을 하지 않고 "dApp으로 돌아가세요"만 표시. 나중에 넣는다면 딥링크로
  시작한 세션에만, 평범한 커스텀 스킴 VIEW 인텐트만(`intent:` URI·명시적 컴포넌트·패키지 거부).
- **인앱 dApp 브라우저(WebView + EIP-1193 주입): 만들지 않는다.** `addJavascriptInterface`는 iframe 포함 모든 프레임에
  노출되고 호출한 프레임의 URL을 안전하게 알 수 없다[문서]. 프레임별 `sourceOrigin`·`isMainFrame`을 주는
  `addWebMessageListener`는 `androidx.webkit`(새 의존)이다. 게다가 적대적 웹 콘텐츠가 지갑 자체 UI 안에서 승인 화면을
  흉내 낼 수 있다. WebView Safe Browsing은 Play 서비스 의존이다.
- **Bitcoin dApp 서명**: v1 없음(Android 표준 없음, WalletConnect bip122는 spec/13 §9 범위 밖). 앱 내 BTC·ZEC 송수신은 무관.

### 4.5 Solana Mobile Wallet Adapter(선택, 2단계)

- MWA 2.0: 지갑이 인텐트가 준 포트(49152–65535)의 **localhost WebSocket 서버**를 최소 10 s 연다. 인텐트
  `solana-wallet:/v1/associate/local?association=<P-256 공개키>&port=&v=`. 암호: P-256 ECDSA(HELLO_REQ), P-256 ECDH,
  HKDF-SHA256, AES-128-GCM(순번 AAD)[문서]. 우리 Rust 허용 목록에는 p256·aes-gcm이 없지만 모두 플랫폼 JCA에 있다
  (Windows에서 WalletConnect Verify의 P-256을 CNG로 하는 것과 같은 방식). 서명은 raw r‖s라 DER 변환 필요.
- 범위: D25와 같게 **메시지 서명만**(`authorize`·`reauthorize`·`deauthorize`·`get_capabilities`, `sign_messages`, SIWS).
  `sign_transactions`·`sign_and_send_transactions`는 -32601. 단, MWA 필수 기능에 `signAndSendTransaction`이 있어
  **규격 비준수**가 되고 일부 dApp·선택기가 숨길 수 있다.
- 신원: 네이티브 dApp은 Digital Asset Links + 호출 패키지로 확인 가능, 웹 dApp은 TWA가 아니면 주장값뿐.
  Chrome의 Local Network Access 롤아웃으로 웹 dApp이 localhost에 붙을 때 권한 프롬프트가 뜬다[문서]. 웹 dApp이 원격
  리플렉터 방식으로 옮겨 가면 wss 리플렉터 클라이언트도 필요해진다.
- 127.0.0.1에만 바인드, 연결 1개만 받는다. Android 17 `ACCESS_LOCAL_NETWORK`는 LAN 대상이라 loopback에는 불필요[문서].
- 노력 +10–15일[추정]. MVP에는 넣지 않는다(§8 Q9).

---

## 5. YubiKey (NFC·USB)

### 5.1 코어는 준비돼 있다

- `yw-core/src/yubikey`(약 7.5k줄: apdu, tlv, openpgp, piv, plan, record, enrol, manage, sign, sig, mock)는 OS 접근이
  없다. 플랫폼 지점은 `CardTransport::transmit`(프레임 하나 입력 → `data‖SW1SW2`)과 등록 때만 쓰는 `piv::MgmtCipher`뿐.
- `yw-app/src/yubikey.rs:22`가 `MODE = ApduMode::Short`(짧은 APDU + CLA|0x10 체이닝, 255바이트 조각)를 쓴다. 가장 큰
  프레임은 261바이트 = `IsoDep` 짧은 APDU 최대라 확장 길이를 지원하지 않는 폰(`isExtendedLengthApduSupported()==false`)도
  된다. Solana 1,232바이트 메시지는 약 5개 프레임.

### 5.2 전송

| 전송 | 구현 | 비고 |
|---|---|---|
| NFC | `IsoDep.transceive()`(블로킹, 메인 스레드 금지), reader mode + `FLAG_READER_SKIP_NDEF_CHECK`(YubiKey OTP NDEF가 브라우저를 여는 것 방지), `setTimeout` 약 5 s, `getMaxTransceiveLength() >= 261` 검사. `TagLostException` → `CardError::CardRemoved` | 프레임워크만으로 됨 |
| USB-C | `UsbManager`로 CCID 인터페이스 찾기·권한(벤더 0x1050 `USB_DEVICE_ATTACHED` 필터)·`claimInterface`. CCID 직접: `PC_to_RDR_IccPowerOn`(0x62), `PC_to_RDR_XfrBlock`(0x6F), `RDR_to_PC_DataBlock`(0x80), 10바이트 헤더·순번, **터치 대기 중 카드가 보내는 시간 연장 상태를 계속 읽기** | yubikit의 `UsbSmartCardConnection`(약 700줄, Apache-2.0)을 참고(소스 주석에 출처). Yubico Authenticator 등 다른 앱이 인터페이스를 쥐고 있을 수 있다 |

**yubikit-android(3.3.0)는 쓰지 않는다**: 새 Maven 의존이고, `OpenPgpSession`·`PivSession`이 우리 카드 로직을 한 벌 더
갖고 있어 우리 규칙(서명 중 쓰기 명령 없음, VERIFY 전 공개키 대조, 공장 PIN 거부, OpenPGP PW1 6982 재시도 읽기, spec/10 §5.2)을
우회하게 된다. 실제 이점인 CCID·NFC 디스패치는 직접 쓸 만큼 작다.

### 5.3 범위: 폰은 서명만

- 카드 등록·재슬롯·삭제는 **Windows에서만**. 공개 슬롯 표(serial, firmware, fingerprint, slots, roles, pubkeys — 모두 공개
  정보)를 Windows가 "YubiKey 설명자" QR로 내보내고 폰이 자체 QR 디코더로 읽는다. 그러면 폰은 **복구 문구·admin PIN·
  MgmtCipher를 갖지 않는다**. `adopt_card`(spec/10 §7.5)는 파생 공개키 확인에 니모닉이 필요하므로 폰에서 하면 이 이점이
  사라진다. 설명자가 조작돼도 서명 흐름은 PIN 전송 전에 카드 공개키가 기록과 다르면 `KeyMismatch`로 거부한다.
- **"폰에 시드 없음"(YubiKey 전용 계정) 모드**를 의미 있는 잔액의 권장 구성으로 둔다. 폰의 소프트웨어 계정은 잃어도 되는
  핫 잔액용(§2.4와 같은 취지).

### 5.4 NFC 한 번 탭 = 한 작업

지금 키 작업자는 PC/SC 연결을 쥔 채 `check_pin`(VERIFY)과 서명을 따로 한다(spec/10 §9.2). NFC에서는 **필드 세션 하나**로
바꾼다: 데이터·Solana blockhash를 먼저 받기 → PIN 패드 → "YubiKey를 폰에 대세요" → SELECT·serial·공개키·VERIFY·승인 소비·
모든 서명 → 완료(햅틱). VERIFY 전에 태그를 잃으면 PIN 시도를 쓰지 않고 다시 탭을 요청한다(VERIFY는 최대한 늦게).
Solana의 20 s 서명 기한은 PIN 제출부터 세므로 blockhash는 탭 요청 전에 받는다. 입력이 많은 BTC 전송은 N번의 PSO:CDS
동안 키를 대고 있어야 한다(각 수백 ms로 추정, 재야 함). 기존 120 s 카드 단계 상한 유지.

### 5.5 미확인과 제약

- **터치 의미[미확인]**: Yubico 개발자 가이드는 NFC에서 탭이 금색 접점 터치와 "같은 기능"을 한다고만 한다. 터치 정책
  "Always"(OpenPGP UIF 01, PIV 02)가 한 필드 세션 안에서 서명마다 새 존재 확인을 요구하는지는 문서에 없다. 한 번 탭이
  세션 전체를 덮는다면 N개 입력 BTC·ZEC 전송이 N회 터치가 아니라 탭 1회이고, 탭 순간 프로세스를 장악한 악성코드가 가로챈
  PIN으로 다시 VERIFY해 추가 digest에 서명할 수 있다. 하드웨어 시험 전까지 승인 배지를 NFC "탭 1회" / USB "N회 터치"로
  나누고, spec/10 §1의 "터치가 마지막 방어선"을 NFC에서는 약하게 적는다. `yubikey::mock`에 "세션당 터치 1회" 모드를 추가해
  게이트 테스트로 덮는다.
- **PIN이 NFC 무선으로 평문**(VERIFY APDU). SCP11b(펌웨어 5.7.2+, P-256 ECDH + AES-128)가 막지만 `yw-core`에 P-256·AES-CBC·
  CMAC가 없고 허용 목록이 금지한다. 하려면 `javax.crypto`로 `MgmtCipher` 같은 trait 뒤에. 엿들은 PIN만으로는 키가 없으면
  쓸모없으므로 **미룬다**. FIPS 시리즈는 FIPS 모드에서 NFC로 OpenPGP·PIV를 쓰려면 SCP03/SCP11이 필수[문서].
- **Restricted NFC**: 펌웨어 5.7의 새 NFC 키는 USB 전원을 3초 받기 전까지 NFC가 제한된다[문서]. 폰만 있는 사용자를 위해
  첫 사용 안내가 필요.
- **PIN 패드**: 앱 내 키패드, FLAG_SECURE, `accessibilityDataSensitive`, `filterTouchesWhenObscured`, 숫자마다 Rust
  `Zeroizing` 버퍼로, IME·클립보드·작업 간 캐시 없음(spec/10 §9.1과 같은 규칙).

### 5.6 YubiKey + 폰은 폰 전용 키보다 실제로 안전한가

| 공격 | 폰 전용 소프트웨어 키 | YubiKey 계정 |
|---|---|---|
| root 아닌 악성 앱(접근성 트로이 등) | 샌드박스가 메모리 읽기를 막음. UI 속임수에는 둘 다 노출(arm 지연·FLAG_SECURE·승인 규칙으로 대응) | 거의 같음 |
| root·커널 익스플로잇 | 다음 잠금 해제 때 복구 문구까지 유출, 이후 언제든 탈취 | 탭하는 동안 digest 바꿔치기·추가 서명이 최대. 지속적인 키 탈취 없음 |
| vault 복사·폰 도난 | Argon2id + 비밀번호에 의존 | 공개 슬롯 표만 노출(spec/10 §1·§8) |
| 표시 무결성 | 폰 화면이 유일한 표시 | 같음(Windows와 같은 한계) |

결론: 고액 계정에는 실질적 개선이며 Windows 위협 모델과 맞는다. StrongBox는 secp256k1·Ed25519가 없어 서명 키 대체가
아니고, DEK 기기 결속 용도뿐이다(root 악성코드 방어로 설명하지 않는다).

---

## 6. 배포·업데이트·위협 모델 변화

### 6.1 배포

- **Google 개발자 인증**[문서]: 인증받지 않은 앱은 2026-09-30부터 브라질·인도네시아·싱가포르·태국의 인증 기기에서, 2027년부터
  전 세계(Android 7+ 인증 기기)에서 설치가 막힌다. **ADB 설치는 예외**("ADB로 자기 기기에 수정·미인증 앱을 빌드·시험·설치"
  허용). ADB 없이 미인증 앱을 설치·업데이트하려면 1회성 "고급 흐름"(개발자 모드, 재시작, 24시간 대기; ADB로 대기를 건너뛰는
  방법은 "현재 지원하지 않음"). 대안인 무료 제한 배포 계정은 신분증 없이 기기 20대까지지만 Google 계정과 패키지·키 등록이 필요.
- **권장 경로(D1 유지)**: 사용자 Windows PC에서 소스 빌드 → 사용자가 만든 키로 서명 → `adb install -r`. 업데이트는 같은 키.
  APK Signature Scheme v3는 계획된 키 교체를 지원. 설치 후 USB 디버깅을 끄도록 안내. Play Store·F-Droid 배포 없음.
  서명하지 않은 APK의 재현성 확인(고정 타임스탬프·zip 순서, `.so`에 `--remap-path-prefix`)은 선택. 서명된 APK는 사용자마다
  다른 것이 정상.
- **서명 키 = 새 업데이트 신뢰 루트**(D1의 "소스 커밋 + Cargo.lock"과 같은 자리): 분실하면 업데이트 불가 → 삭제 후 재설치 →
  vault 삭제(복구는 니모닉 + YubiKey 재채택). 유출되고 공격자가 ADB나 물리 접근까지 가지면 vault를 물려받는 악성 업데이트로
  비밀번호를 피싱할 수 있다. 키스토어 파일은 저장소·지갑 데이터 폴더 밖의 별도 폴더에 두고 백업.
- **Advanced Protection 충돌(U8)**: Google 지원 문서는 이 모드가 "출처를 알 수 없는 앱의 설치를 막고, 그렇게 설치한 앱의
  업데이트도 막는다"고 한다. ADB 설치도 막는다는 건 2차 자료뿐이다. 이 모드는 동시에 도구가 아닌 접근성 서비스를 막는,
  접근성 악성코드에 대한 가장 강한 플랫폼 방어다(Android 17에서 확대)[2차]. 즉 **가장 안전한 Android 설정과 소스 빌드
  사이드로드가 서로 당긴다**. P0에서 사용자 폰으로 확인.
- **정책 변동**: ADB 예외는 지금의 보장이지 영구 보장이 아니다.

### 6.2 업데이트

자동 업데이트 없음(Windows와 같은 §2.2 비목표). 업데이트 = 새 소스 빌드 + 같은 키 서명 + `adb install -r`. 서명 키가
같으면 앱 데이터(vault)는 유지된다. 두 셸이 생기므로 이후 모든 스펙 변경이 두 UI에 반영돼야 하고 수동 체크리스트(spec/09)도
대략 두 배가 된다.

### 6.3 위협 모델 변화 (spec/14 §1 초안)

`spec.md` §2.1 행별:

| §2.1 공격자 | Android |
|---|---|
| 악성 dApp·피싱·오염된 프론트엔드 | 동일(코어 표시). origin은 주장값 + Verify(U1) |
| 다른 크롬 확장·웹 스크립트 | **행 소멸** → "`wc:` 인텐트를 보내는 임의 앱"으로 대체: 미리 채우기만, 자동 페어링 금지, 15 s 쿨다운 |
| 우리 확장·yw-host 오염 | **행 소멸** → relay·Verify 오염: 요청 위조·스팸은 가능, 승인 내용은 코어가 다시 만든다 |
| 악성·오류 RPC | 동일 |
| 노트북·디스크·백업 도난 | 폰 도난: 파일 기반 암호화 + Argon2 vault + 백업·전송 제외. 선택 기기 결속 |
| 의존성 오염 | + Android SDK·NDK·JDK·rustup 타깃. Java 쪽 Maven 0 |
| 우발적 비밀 노출 | FLAG_SECURE 계열. 비밀 복사 제거. tombstone 잔여 |
| 약한 시드 | 동일(bionic `getrandom`) |

새 행(Android 전용):

| 공격자 | 방어 |
|---|---|
| 접근성 서비스 악성코드(화면 읽기·제스처 주입) | `accessibilityDataSensitive`(34: 읽기·동작 제한, 36: 주입 차단), 켜진 비도구 접근성 서비스를 나열하는 경고 띠, API 36 미만 경고 |
| 오버레이·탭재킹 | Android 12+ 기본 차단, `setHideOverlayWindows`, 가림 플래그 거부 |
| 악성·클라우드 키보드 | 앱 내 키패드 필수 |
| 가짜 "시드 백업" 유도(Crocodilus: 1,200+ 기기에서 약 280만 달러)[2차] | 니모닉 입력은 온보딩·복구 화면에서만, 사용자 체크리스트 |
| 갤러리 OCR 시드 탈취(SparkCat·SparkKitty)[2차] | 비밀 화면 FLAG_SECURE로 스크린샷 차단, "시드 사진 금지" 체크리스트 |
| 서명 키 유출 + ADB·물리 접근 | 설치 후 USB 디버깅 끄기, 키스토어 보관 |

Android 비목표(§2.2 대응): root·부트로더 해제·LSPosed·TEE 장악; 잠금이 풀린 폰의 탈취; 사용자가 정확히 표시된 악성 거래를
승인하는 것; OEM의 FLAG_SECURE·백업 예외 버그; (사용자가 받아들이면) API 36 미만의 접근성 제스처 주입.

Android 운영 권고(§2.4 대응, 코드 게이트 아님): 강한 잠금 화면 자격 증명, Android 16+, 접근성 권한을 준 앱 점검, 설치 후 USB
디버깅 끄기, APK 서명 키 백업, 시드 사진 금지, Advanced Protection은 U8 확인 후 결정.

### 6.4 여러 기기(Windows + Android, 같은 니모닉, 동기화 없음)

- EVM: spec/03 §3.6이 `pending != latest`면 보내지 않으므로 RPC가 보는 다른 기기의 대기 트랜잭션은 잡힌다. 남는 같은 nonce
  경쟁은 journal에서 Replaced·Dropped로 끝나며 이중 지불은 없다.
- BTC: 새로고침이 Core `gettxout [txid,vout,true]`(멤풀 포함, spec/08 §4.7-3)를 쓰고 Esplora는 멤풀에서 쓴 출력을 빼므로
  대부분 잡힌다. 남는 경쟁은 full-RBF 교체로 끝난다. **단, "Abandoned·Rejected는 30일간 입력 재사용" 규칙(spec/08 §12.1)은
  기기별이라, A 기기의 BroadcastUnknown 뒤 B 기기에서 다시 보내면 두 번 지불될 수 있다.**
- SOL: 두 지불이 독립. ZEC: RBF 없음, 충돌 거래 거부. HyperCore: nonce는 밀리초 타임스탬프, 서명자별 최근 100개 창.
- 제안: vault·meta·journal은 독립 유지. 기기별 계정 분할(예: Android는 EVM 계정 1·자체 BTC 계정)을 안내하고, 선택 meta 플래그
  "이 계정은 다른 기기에서도 씀"으로 보내기 화면에 주의 띠. "서명한 기기가 아닌 곳에서 Abandon·재전송하지 말 것"을 문서화.

---

## 7. 단계별 계획

단위는 집중 인주(pw, spec.md §5와 같은 관례). 테스트는 영역별 표적 테스트만, 기기 확인은 체크리스트 1회(§2.3).

| 단계 | 내용 | 노력 | 끝 조건 |
|---|---|---|---|
| **S** 스펙 | spec/14-android.md(위협 모델 차이 표: D7·D10·D11·D12·D13·D24·D33·D35 → Android 대응·최소 API·잔여 차이), D37(Android 조건부 GO), D4·D5·D1·spec/13 §8 개정안 | 0.5–1 | 사용자 승인 |
| **P0** 스파이크 | (승인 후) Rust Android 타깃 설치 → `yw-core`를 임시 cdylib로 빌드, `JNI_OnLoad` + `selfTest()`로 기존 KAT(BIP39/32, SLIP-10, secp256k1, Ed25519, XChaCha20-Poly1305) 실행 → 에뮬레이터와 사용자 폰 · Argon2 KDF_V3 시간·최대 메모리 측정(spec/09 기록) · `llvm-readelf` 16 KB 정렬·`.so` 크기 · SDK 도구만으로 APK 빌드, 사용자 키 서명, `adb install` · Advanced Protection 켠 상태에서 ADB 설치 확인 · NFC `IsoDep` APDU 왕복 + 터치 "Always" 탭 횟수 시험 · `check-core-deps.mjs` 타깃별 표 | 1–2(코어만은 2–4일) | Argon2가 lmkd 종료 없이 10 s 기준 이내; adb 설치 성공; NFC 왕복 성공. 하나라도 실패하면 §8로 돌아가 재결정 |
| **P1** 엔진 분리 | `yw-engine` 신설, 순수·서비스 모듈 이동, 플랫폼 trait, app_*.rs 상태 기계 → Controller. **Windows가 기준 구현으로 계속 통과**(browser_dispatch·walletconnect mock·approval_interaction 등 표적 테스트) | 4–8 | Windows 빌드·표적 테스트 통과, yw-app는 셸만 |
| **P2** 플랫폼 층 | `yw-android`(JNI·mlock·prctl), Java 셸 골격, 원자적 저장(fsync·rename·디렉터리 fsync), Keystore 저장소, HTTPS, 시계, 수명주기 자동 잠금, 보안 창 기반 클래스, 앱 내 키패드, 빌드·서명·설치 스크립트, Android 의존성 검사 | 3–5 | 빈 vault 만들기·잠금 해제가 폰에서 동작 |
| **P3** MVP 흐름 | 생성·가져오기·잠금 해제·백업 확인; EVM 기본 체인 ETH·ERC-20 송수신 + 시뮬레이션·승인 액티비티·journal·속도 올리기·취소; BTC P2WPKH·P2TR 송수신 + 이전 트랜잭션 검증·RBF; 설정·RPC 템플릿 | 6–8 | Sepolia·testnet4 종단 1회 |
| **P4** WalletConnect | Java WSS(호스트 검증·SNI), `wc:` 딥링크·붙여넣기·Camera2 QR, ES256 Verify(JCA), 수명주기 재설계 | 2–3 | mock relay 테스트 + 실제 dApp 1회 |
| **P5** YubiKey NFC | `IsoDepTransport`, 필드 세션 재구성, 설명자 QR(Windows 내보내기·Android 가져오기), PIN 패드, mock 세션 모드 | 2–3 | 등록된 슬롯으로 EVM·BTC 서명 |
| **P6** 강화·인수 | 2개 기기(Pixel·Samsung, Android 14–16) 체크리스트 1회: 오버레이·접근성 시험 앱, FLAG_SECURE·최근 앱·화면 공유, 키보드, `bmgr` 백업 제외, journal 중 프로세스 종료, 제스처 취소, 백그라운드 시작 제한; Android 설치 안내 | 2–3 | 체크리스트 통과 |
| **MVP 합계** | | **약 20–30** | |
| 패리티 추가 | SOL·SPL 2–3, ZEC 1.5–2, HyperCore 1–1.5, YubiKey 등록·관리 + USB CCID 3–4, 가져온 키·키 전용 vault 1.5–2, LLM 1, 남은 화면·설정 3–5, 인수 1–2 | +14–20 | |
| **패리티 합계** | | **약 34–50** | |
| 선택 | MWA(Solana 메시지 서명) +2–3, 생체 빠른 잠금 해제 +1–2, SCP11b +1–2, StrongBox DEK 결속 +0.5 | | |

MVP에서 미루는 것: SOL·SPL, ZEC, HyperCore, LLM 설명, YubiKey 등록·재슬롯·삭제, USB CCID, 가져온 키·키 전용 vault, 생체 잠금
해제, MWA. **만들지 않는 것**: 인앱 dApp 브라우저, FCM 푸시, Play Integrity 게이트.

**추정치의 차이**: 렌즈별로 패리티 추정이 4–7 인월(약 17–30 pw, 플랫폼 보안·코어·UI 렌즈)과 34–50 pw(배포 렌즈, 위 표)로
갈렸다. 위 표가 모든 체인·하드웨어 인수·스펙 작업을 항목별로 셌기 때문에 보수적이다. 플랫폼 보안 렌즈가 낸 "좁은 첫 조각
6–8주(EVM·vault·승인·WalletConnect, YubiKey 없음)"는 P1 엔진 분리를 충분히 세지 않은 낙관치로 본다. 이 저장소는
2026-08-20 첫 커밋부터 2026-11-07까지 315 커밋을 AI 보조로 진행했으므로 달력 시간은 인주보다 훨씬 짧을 수 있지만, 폰·
YubiKey·테스트넷을 든 사람이 해야 하는 확인은 줄지 않는다.

**가장 큰 위험**: P1이 동작 중인 Windows 지갑의 75개 파일을 건드린다. trait 뒤로 단계적으로 옮기고 Windows를 기준 구현으로
두되, 사용자의 "테스트는 가볍게" 원칙과 충돌하는 지점이므로 어느 표적 테스트를 기준으로 삼을지 미리 정한다(§8 Q12).

---

## 8. 열린 질문 (사용자 결정 필요)

1. **대상 폰과 하한**: 쓸 폰의 모델·Android 버전·RAM은? minSdk 34로 두고 API 34–35의 접근성 제스처 주입을 비목표로 받아들일지,
   아니면 Android 16(API 36)+만 지원할지.
2. **Advanced Protection**: 켤 생각인가? 켜면 소스 빌드 설치·업데이트가 막힐 수 있다(P0에서 확인).
3. **정책 개정 승인**: (a) aarch64에서 `libc 0.2.189` 허용, (b) 두 번째 unsafe 크레이트 `yw-android`(libc 직접 의존 또는
   `extern "C"` 직접 선언 중 택1), (c) Android SDK·NDK·JDK 툴체인 신뢰, (d) Gradle·AndroidX·Kotlin 배제(Java + 프레임워크 View).
4. **P0 도구 설치**: `rustup target add aarch64-linux-android x86_64-linux-android` 설치 승인.
5. **MVP 범위**: EVM + BTC + WalletConnect + YubiKey NFC(배포 렌즈 안)인가, EVM + WalletConnect만(더 좁게)인가.
6. **폰에 시드를 둘 것인가**: "폰에 시드 없음"(YubiKey 전용 계정, 슬롯 표는 Windows에서 QR로) 모드를 기본 권장으로 할지.
7. **생체 빠른 잠금 해제**: 원하는가(기본 끔, 켜면 D7·D10 의미가 바뀐다).
8. **WalletConnect 잠금 동작 변경**: Android에서는 "잠그면 연결을 닫고 우편함이 300 s 붙잡음"으로 바꾸고, 백그라운드 요청 알림
   (FCM)은 포기하는 데 동의하는가.
9. **Solana MWA**: 2단계로 필요한가(메시지 서명만, 규격 비준수 감수).
10. **비밀 복사 제거**: Android에서 니모닉·키·비밀번호 복사 기능을 아예 빼는 데 동의하는가.
11. **여러 기기**: Windows와 같은 니모닉을 폰에서도 쓸 것인가. 그렇다면 기기별 계정 분할 규칙을 정할지.
12. **엔진 분리 시점과 시험 범위**: P1을 언제 할지, Windows 회귀 확인에 어떤 표적 테스트를 기준으로 할지.
13. **Argon2가 폰에서 느리거나 죽을 때**: 저사양 기기를 지원하지 않을지, vault v4(모바일 파라미터, Windows에도 영향)를 검토할지.
14. **YubiKey 모델·펌웨어**: 5.7 Restricted NFC나 FIPS 시리즈(NFC에 SCP 필수)가 있는가. USB-C 키도 쓰는가.

---

## 9. 출처

### 저장소(읽기 전용)

- `spec.md` §2(위협 모델), §5, D1, D3–D5, D7, D10–D13, D22–D28, D32–D36
- `spec/01-repo-build.md` §3.3, §5.1, §7.4 · `spec/02-core-keys-vault.md` §1.1, §4, §4.5, §6.2, §7.3–7.4, §11 ·
  `spec/03-evm.md` §3.6, §11.3–11.5 · `spec/04-app-ui.md` §1.3, §3.3–3.6, §4, §5 · `spec/05-browser.md` §1, §4 ·
  `spec/08-bitcoin.md` §4.7, §12.1 · `spec/09-testing.md` · `spec/10-yubikey.md` §1, §5.1–5.2, §7.5, §8, §9 ·
  `spec/13-walletconnect.md` §4, §5.2, §7, §8, §9
- `crates/yw-core/src/{lib.rs, entropy/mod.rs, vault/mod.rs, yubikey/mod.rs, yubikey/apdu.rs, yubikey/piv.rs}`
- `crates/yw-app/src/{app.rs, events.rs, yubikey.rs, ui/interaction.rs, ui/approval_view.rs, walletconnect/{mod.rs, worker.rs,
  verify.rs, qr_decode.rs, engine.rs}, browser/{mod.rs, server.rs, read.rs}}`
- `crates/yw-win/src/{mem.rs, http.rs, ws.rs}` · `scripts/check-core-deps.mjs` · `Cargo.toml` · `Cargo.lock` · `.cargo/config.toml`
- 명령(작업 트리 무변경): `cargo metadata --locked --offline --filter-platform <aarch64|x86_64|armv7-linux-android…>`,
  `node scripts/check-core-deps.mjs --metadata <파일>`, `cargo tree --offline --locked -p yw-core --target aarch64-linux-android`,
  `rustup target list --installed`, `%LOCALAPPDATA%\Android\Sdk\ndk\30.0.16248370\source.properties`
- 로컬 레지스트리 소스: `getrandom-0.3.3`(backends.rs), `cpufeatures-0.2.17`, `secp256k1-sys-0.11.0`(build.rs), `cc-1.4.2`(lib.rs)

### Android 공식(developer.android.com · source.android.com · AOSP)

- Keystore·KeyMint: https://developer.android.com/privacy-and-security/keystore ·
  https://developer.android.com/reference/android/security/keystore/KeyProperties ·
  https://android.googlesource.com/platform/hardware/interfaces/+/refs/heads/main/security/keymint/aidl/android/hardware/security/keymint/EcCurve.aidl ·
  https://source.android.com/docs/security/features/keystore/features
- Protected Confirmation 폐기: https://android.googlesource.com/platform/system/security/+/07fec0ff ·
  https://developer.android.com/reference/android/security/ConfirmationPrompt
- 화면·오버레이·접근성: https://developer.android.com/security/fraud-prevention/activities ·
  https://developer.android.com/privacy-and-security/risks/tapjacking ·
  https://developer.android.com/reference/android/view/WindowManager.LayoutParams#FLAG_SECURE ·
  https://developer.android.com/about/versions/15/features ·
  https://developer.android.com/about/versions/14/features/screenshot-detection ·
  https://developer.android.com/reference/android/view/View#setAccessibilityDataSensitive(int) ·
  https://developer.android.com/privacy-and-security/advanced-protection-mode ·
  https://developer.android.com/privacy-and-security/risks/strandhogg ·
  https://developer.android.com/guide/components/activities/background-starts
- 클립보드·IME: https://developer.android.com/develop/ui/views/touch-and-input/copy-paste ·
  https://developer.android.com/privacy-and-security/risks/secure-clipboard-handling ·
  https://developer.android.com/reference/android/content/ClipDescription ·
  https://developer.android.com/reference/android/view/inputmethod/EditorInfo#IME_FLAG_NO_PERSONALIZED_LEARNING
- 메모리·크래시·백업: https://developer.android.com/topic/performance/memory-management ·
  https://source.android.com/docs/core/perf/lmkd · https://source.android.com/docs/core/perf/memory-limiter ·
  https://source.android.com/docs/core/tests/debug/native-crash · https://developer.android.com/identity/data/autobackup
- NDK·JNI·페이지: https://developer.android.com/ndk/guides/jni-tips · https://developer.android.com/ndk/downloads ·
  https://developer.android.com/reference/dalvik/annotation/optimization/CriticalNative ·
  https://developer.android.com/guide/practices/page-sizes
- 생체·빌드: https://developer.android.com/reference/android/hardware/biometrics/BiometricPrompt.Builder ·
  https://developer.android.com/build/dependency-verification
- 네트워크·백그라운드: https://developer.android.com/privacy-and-security/security-config ·
  https://developer.android.com/about/versions/10/behavior-changes-all ·
  https://developer.android.com/about/versions/15/behavior-changes-all ·
  https://source.android.com/docs/core/ota/modular-system/conscrypt ·
  https://developer.android.com/training/monitoring-device-state/doze-standby ·
  https://developer.android.com/develop/background-work/services/fgs/service-types ·
  https://developer.android.com/develop/background-work/services/fgs/timeout ·
  https://developer.android.com/privacy-and-security/risks/unsafe-hostname ·
  https://developer.android.com/privacy-and-security/local-network-permission
- 딥링크·WebView: https://developer.android.com/training/app-links/verify-android-applinks ·
  https://developer.android.com/privacy-and-security/risks/unsafe-use-of-deeplinks ·
  https://developer.android.com/reference/android/app/ComponentCaller ·
  https://developer.android.com/develop/ui/views/layout/webapps/native-api-access-jsbridge
- NFC·USB: https://developer.android.com/reference/android/nfc/tech/IsoDep ·
  https://developer.android.com/reference/android/nfc/NfcAdapter · https://developer.android.com/develop/connectivity/usb/host
- 배포·서명: https://developer.android.com/developer-verification · https://developer.android.com/developer-verification/guides ·
  https://developer.android.com/developer-verification/guides/faq ·
  https://support.google.com/android-developer-console/answer/16561738?hl=en ·
  https://support.google.com/android/answer/16339980?hl=en ·
  https://android-developers.googleblog.com/2026/03/android-developer-verification-rolling-out-to-all-developers.html ·
  https://android-developers.googleblog.com/2025/12/enhancing-android-security-stop-malware.html ·
  https://source.android.com/docs/security/apksigning/v3
- AndroidX 의존 수(POM): https://dl.google.com/android/maven2/androidx/compose/ui/ui-android/1.8.0/ui-android-1.8.0.pom ·
  https://dl.google.com/android/maven2/androidx/compose/material3/material3-android/1.3.2/material3-android-1.3.2.pom ·
  https://dl.google.com/android/maven2/androidx/camera/camera-camera2/1.4.2/camera-camera2-1.4.2.pom ·
  https://issuetracker.google.com/issues/158188351

### Rust·JNI·빌드

- https://doc.rust-lang.org/rustc/platform-support/android.html · https://docs.rs/getrandom/0.3.3/getrandom/ ·
  https://docs.oracle.com/en/java/javase/21/docs/specs/jni/functions.html ·
  https://mozilla.github.io/uniffi-rs/latest/kotlin/gradle.html ·
  https://blog.rust-lang.org/2023/01/09/android-ndk-update-r25.html · https://github.com/rust-lang/rust/pull/120593 ·
  https://groups.google.com/g/android-ndk-announce/c/FZVxJPRjGvc ·
  https://docs.slint.dev/latest/docs/slint/guide/platforms/mobile/android/ ·
  https://f-droid.org/docs/Reproducible_Builds/ · https://f-droid.org/docs/Build_Metadata_Reference/

### Yubico

- https://github.com/Yubico/yubikit-android · https://developers.yubico.com/yubikit-android/ ·
  https://developers.yubico.com/yubikit-android/Release_Notes.html
- 참고 소스: https://raw.githubusercontent.com/Yubico/yubikit-android/main/core/src/main/java/com/yubico/yubikit/core/smartcard/SmartCardProtocol.java ·
  https://raw.githubusercontent.com/Yubico/yubikit-android/main/android/src/main/java/com/yubico/yubikit/android/transport/usb/connection/UsbSmartCardConnection.java ·
  https://raw.githubusercontent.com/Yubico/yubikit-android/main/android/src/main/java/com/yubico/yubikit/android/transport/nfc/NfcReaderDispatcher.java ·
  https://raw.githubusercontent.com/Yubico/yubikit-android/main/android/build.gradle.kts
- https://developers.yubico.com/Developer_Program/Guides/YubiKey_Hardware.html ·
  https://docs.yubico.com/yesdk/users-manual/application-piv/pin-touch-policies.html ·
  https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-apps-openpgp.html ·
  https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-firmware-5.7.html ·
  https://docs.yubico.com/hardware/yubikey/yk-tech-manual/yk5-fips-140-compare.html ·
  https://docs.yubico.com/yesdk/users-manual/sdk-programming-guide/secure-channel-protocol.html ·
  https://developers.yubico.com/Secure_Domain/Technical_Deep_Dive.html ·
  https://yubico.com/blog/now-available-for-purchase-yubikey-5-series-and-security-key-series-with-new-5-7-firmware ·
  https://github.com/open-keychain/open-keychain/wiki/Security-Tokens

### dApp 연결

- WalletConnect·Reown: https://docs.reown.com/walletkit/android/mobile-linking ·
  https://docs.walletconnect.com/wallets/react-native/mobile-linking.md ·
  https://docs.walletconnect.com/walletkit/android/notifications/push ·
  https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods
- Solana MWA: https://solana-mobile.github.io/mobile-wallet-adapter/spec/spec.html ·
  https://docs.solanamobile.com/recipes/mobile-wallet-adapter/local-network-access ·
  https://groups.google.com/a/chromium.org/g/blink-dev/c/O6GMKt44Ups
- 브라우저 확장: https://developer.chrome.com/docs/extensions/nativeMessaging ·
  https://firefox-source-docs.mozilla.org/mobile/android/geckoview/consumer/web-extensions.html ·
  https://discourse.mozilla.org/t/seeking-guidance-on-native-app-messaging-in-firefox-android-add-on-development-1/124323
- 체인: https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets ·
  https://bitcoincore.org/en/releases/28.0/

### 2차 자료(뉴스·블로그·제3자 — 공식 확인 전)

- AOSP 미러 커밋: https://gitlab.e.foundation/e/os/android_hardware_interfaces/-/commit/81f075b2ca8b51a9737a321fa828a846a4401909 ·
  https://gitlab.e.foundation/e/os/android_system_core/-/commit/1447120f78bd653ed7d3501f4c1588a1aec15d99 ·
  https://gerrit.omnirom.org/plugins/gitiles/android_system_core/+/1447120f78bd653ed7d3501f4c1588a1aec15d99%5E%21
- 키 증명: https://bayton.org/android/android-enterprise-faq/key-attestation-root-certificate-change/ ·
  https://grapheneos.org/articles/attestation-compatibility-guide
- 화면·접근성·Advanced Protection: https://androidauthority.com/android-15-apps-selectively-hide-sensitive-content-screen-sharing-3436855 ·
  https://github.com/LSPosed/DisableFlagSecure · https://thehackernews.com/2026/03/android-17-blocks-non-accessibility.html ·
  https://www.androidauthority.com/android-17-beta-2-advanced-protection-mode-accessibility-apps-3648860 ·
  https://www.androidauthority.com/android-16-advanced-protection-mode-3518368 ·
  https://www.androidauthority.com/identity-check-expanded-app-support-3589693 ·
  https://guardsquare.com/mobile-app-security-research-center/malware/accessibility-data-sensitive ·
  https://guardsquare.com/mobile-app-security-research-center/malware/hide-non-system-overlays ·
  https://www.esper.io/blog/android-14-accessibility-security-feature ·
  https://proandroiddev.com/screen-recording-detection-android-15-26ee709b66b4 ·
  https://proandroiddev.com/multitasking-intrusion-and-preventing-screenshots-in-android-app-15bd8757c24d ·
  https://commonsware.com/blog/2019/12/10/securing-jetpack-compose.html
- .NET for Android API 미러(Android API 설명): https://learn.microsoft.com/dotnet/api/android.app.activity.setrecentsscreenshotenabled ·
  https://learn.microsoft.com/dotnet/api/android.views.view.setaccessibilitydatasensitive ·
  https://learn.microsoft.com/dotnet/api/android.views.view.contentsensitivity ·
  https://learn.microsoft.com/en-us/dotnet/api/android.views.window.sethideoverlaywindows?view=net-android-37.0 ·
  https://learn.microsoft.com/en-us/dotnet/api/android.security.keystore.keygenparameterspec.builder.setuserauthenticationrequired ·
  https://learn.microsoft.com/pl-pl/dotnet/api/android.app.notification.visibility
- 클립보드·키보드: https://9to5google.com/2022/08/16/android-13-clipboard/ ·
  https://codeql.github.com/codeql-query-help/java/java-android-sensitive-keyboard-cache ·
  https://codeql.github.com/codeql-query-help/java/java-android-insecure-local-key-gen ·
  https://www.xda-developers.com/api-apps-keyboard-incognito-mode/
- 메모리·KDF: https://bgr.com/2183496/disable-ram-plus-expansion-on-android/ · https://bitwarden.com/help/kdf-algorithms/ ·
  https://community.bitwarden.com/t/argon2id-is-this-too-much-for-android/69391 ·
  https://dev.to/treszyk/architecture-vs-brute-force-what-i-learned-benchmarking-kdfs-for-my-thesis-18bo
- 배포: https://thehackernews.com/2026/03/google-adds-24-hour-wait-for-unverified.html ·
  https://9to5google.com/2026/08/18/google-gradually-rolling-out-androids-advanced-sideloading-ahead-of-developer-verification/ ·
  https://www.androidauthority.com/android-sideloading-developer-verification-first-wave-rollout-3717921/ ·
  https://hereket.github.io/posts/android_from_command_line
- dApp·WebView·카메라: https://www.androidauthority.com/chrome-for-android-with-extensions-demo-3540132 ·
  https://chromeunboxed.com/chrome-for-android-may-get-extension-support-but-its-likely-not-what-you-think/ ·
  https://www.securityweek.com/safe-browsing-now-default-android/ ·
  https://dynamsoft.com/codepool/android-barcode-detection-fast-moving-object.html
- 악성코드 사례: https://decrypt.co/312378/crocodilus-malware-draining-crypto-wallets-android ·
  https://securelist.com/sparkkitty-ios-android-malware/116793/ ·
  https://thehackernews.com/2025/02/sparkcat-malware-uses-ocr-to-extract.html
