# Android 앱

2026-11-17 신설(`spec.md` D40). 주인 승인(2026-11-17): 기능 동등, 앱 내 브라우저 우선 + WalletConnect 유지, 지문 잠금 해제(선택), 화면 모델 공유(§11.3), 새 크레이트 `yw-platform`·`yw-engine`·`yw-android`. 구현은 §17 단계로 진행 중이다. 이 문서가 Android판의 범위, 위협 모델 차이, 구조, 저장·잠금·생체 인식, 앱 내 브라우저, 승인·비밀 화면, YubiKey 전송, 빌드·설치와 단계의 정본이 된다. 체인·서명·위험 규칙·승인 digest·오류 코드는 기존 문서가 그대로 정본이며 Android판은 그 규칙을 바꾸지 않는다. 이 문서와 다른 문서가 다르면 `spec.md`가 이기고, 이 문서는 Android에서만 다른 점을 정한다. 기존 결정(D1–D39)을 Android에서 어떻게 읽는지는 §15에 모았다.

2026-11-17 같은 날, 앞선 조사 `docs/android-feasibility-20261107.md`(아래 "타당성 검토")와 대조해 고쳤다. 초안과 달라진 결정은 그 자리에 `(2026-11-17: …)`로 적었다. 같은 날 문서 검토의 지적으로 다시 고친 곳은 `(2026-11-17 검토: …)`로 적었다. 기기에서 재어 봐야 하는 것은 §16 P0 스파이크로 모았고, 주인이 정할 것은 §18에 남겼다.

## 1. 목표와 범위

- **기능은 Windows판과 같다**: EVM(내장 7개 + 사용자 체인)·Solana·Bitcoin·Zcash(일반)·HyperCore, 복구 단어 여러 개, 가져온 키, 주소록, 활동, 토큰, 사이트 연결, WalletConnect v2, YubiKey 5, AI 설명(선택), 한국어·영어(D39). 기능 차이는 다음뿐이다:
  1. 비밀 복사가 없다(§9.3).
  2. 복구 단어·개인키 칸은 붙여넣기를 받지 않는다(§9.4).
  3. WalletConnect 요청은 앱이 앞에 있고 잠금이 풀린 동안만 받는다(§12.1).
  4. 사설 CA로 운영하는 RPC는 지원하지 않는다(§12).
  5. WalletConnect QR은 카메라로 읽는다. 클립보드 비트맵·이미지 파일의 QR(D35)은 없다(§12.2).
  6. YubiKey 키 가져오기·PIN·관리 키 변경은 USB-C로만 한다(§10).
  7. 하드웨어 키보드로는 승인하지 않는다(§8.1).
  - (2026-11-17 검토: 초안은 "예외는 둘이다"라고 1–2만 적었다.)
- **브라우저 확장 대신 앱 내 브라우저**(§7). Android Chrome은 확장을 쓸 수 없다. 앱 내 브라우저는 확장과 같은 `provider-main.js`를 주입하므로 Solana·Bitcoin dApp 연결(호환 모드 포함)도 Windows판과 같다. WalletConnect는 다른 기기(PC 브라우저)의 dApp을 폰에서 서명하는 경로로 함께 둔다([13], 수명은 §12.1).
- 대상: `arm64-v8a`. 빌드 하한은 Android 10(API 29)이다(시험 기기에 맞춤). 보호 수준은 API에 따라 다르다(§1.1).
- 배포: 소스만(D1). 사용자가 빌드해 직접 설치한다(사이드로드, §14). Play 스토어·자동 업데이트 없음. 릴리스 서명 키는 사용자가 만들고 저장소에 넣지 않는다.
- Windows판과 데이터 파일을 주고받지 않는다. 기기를 옮기는 정식 방법은 복구 단어(또는 개인키·YubiKey 연결, [10] §7.6)다. 이유: Android의 파일은 기기 키로 한 번 더 감싸므로(§5.2) 다른 기기에서 열리지 않는다.
- 범위 밖: Solana Mobile Wallet Adapter(Windows판에 없는 기능, §18), FCM·WalletConnect 푸시(§12.1), Play Integrity·SafetyNet 판정으로 기능을 막는 것(Google 서버 의존, 자가 빌드 앱을 인식하지 못함, `spec.md` §2.3), 홈 화면 위젯·알림의 잔액 표시. 기기 키 증명(key attestation) 결과는 원하면 설정의 정보 표시로만 쓴다.

### 1.1 보호 등급

앱이 실행 중 API 레벨로 등급을 정해 설정 → 보안에 보인다. 표의 빠지는 보호는 위 등급 대비 누적이다.

| 등급 | API | 빠지는 보호 |
|---|---|---|
| 완전 | 36+ | 없음¹(비도구 접근성 서비스의 제스처 주입 차단 포함) |
| 기본 | 34–35 | 비도구 접근성 서비스의 제스처 주입 차단(§8.3), 인증서 투명성 검사(API 36, §12). API 34는 `setContentSensitivity`·화면 녹화 콜백(API 35, §9.1)도 |
| 약함 | 31–33 | + `accessibilityDataSensitive`·스크린샷 감지(API 34). API 31–32는 최근 앱 미리보기 끄기(`setRecentsScreenshotEnabled`, API 33)도 |
| 시험용 | 29–30 | + 다른 앱 겹침 창 숨기기(`setHideOverlayWindows`)와 신뢰하지 않는 겹침 창 위 터치 차단(API 31, §8.2). API 29는 작업 하이재킹(StrandHogg 계열) 수정(API 30, §8.4)도 |

¹ '완전'도 접근성 서비스가 `TYPE_ACCESSIBILITY_OVERLAY`로 승인 화면을 덮는 것은 막지 못한다(모든 등급의 잔여, §2.2). (2026-11-17 검토: 초안 표는 인증서 투명성·`setContentSensitivity`·녹화 콜백·작업 하이재킹 수정과 이 잔여를 빠뜨렸다.)

- '약함'과 '시험용' 등급, 그리고 보안 패치(`Build.VERSION.SECURITY_PATCH`)가 1년 넘게 지난 기기에서는 모든 화면 위에 닫을 수 없는 띠 `이 기기는 보호가 약합니다(시험용으로만 쓰세요)`를 보인다. 막지는 않는다(`spec.md` §2.3: 확인할 수 없다고 차단하지 않는다).
- 실자금은 API 34 이상, 권장은 Android 16(API 36) 이상이다(근거: 타당성 검토 §3.5).
- (2026-11-17: 초안은 API 29를 하한으로만 적었다. 타당성 검토는 minSdk 34를 권했다. 시험 기기 때문에 하한 29는 유지하고 등급과 띠로 차이를 알린다.)

### 1.2 같은 지갑을 여러 기기에서

- Windows판과 Android판에 같은 복구 단어를 넣어 쓸 수 있다(2026-11-07 주인 답). 두 기기의 vault·meta·journal은 독립이며 동기화하지 않는다.
- 대가: 구획화를 잃는다. 폰 하나가 장악되면 같은 복구 단어에서 나온 Windows판 계정도 위험하다(타당성 검토가 이식을 미룬 첫째 이유). 권장 구성은 폰에는 잃어도 되는 잔액만 두고, 큰 잔액은 Windows판에만 두거나 폰에서는 시드 없는 YubiKey 전용 계정으로 쓰는 것이다(타당성 검토 §5.3, §18 Q6). 설치 안내와 첫 실행 화면이 이를 알린다. (2026-11-17 검토: 초안은 이 대가를 적지 않았다.)
- 체인별 결과:
  - EVM: 보내기 전 `pending != latest` 검사([03] §3.6)가 다른 기기의 대기 거래를 대부분 잡는다. 남는 같은 nonce 경쟁은 Replaced·Dropped로 끝난다.
  - Bitcoin: '포기·거절 뒤 30일 입력 재사용'([08] §12.1)은 기기마다 따로다. 한 기기에서 전송 결과를 모르는 거래를 다른 기기에서 다시 보내면 **두 번 지불될 수 있다**.
  - Solana는 두 지불이 따로 처리된다. Zcash는 충돌 거래가 거부된다. HyperCore nonce는 밀리초 시각이다.
- 규칙: 거래를 포기하거나 다시 보내는 것은 그 거래에 서명한 기기에서만 한다(안내 문서와 활동 화면 설명). 기기별로 계정을 나눠 쓰기를 권한다.
- 계정 설정 `다른 기기에서도 씀`을 켜면 그 계정의 보내기 화면에 주의 띠 `이 계정은 다른 기기에서도 씁니다. 대기 거래를 확인하세요`를 보인다. 이 값은 meta의 새 선택 키다. 구현할 때 [02] §5.3을 같은 커밋에서 고친다.

## 2. 위협 모델 차이 (`spec.md` §2 대비)

### 2.1 더하는 방어 대상

- **폰 분실·도난**: 잠긴 폰에서 파일을 빼내도 오프라인 대입을 할 수 없다(기기 키 감쌈 §5.2 + vault Argon2id). 앱 UID 안에서 코드를 실행한 공격자(예: 장악된 `:browser` 프로세스, §7.4)에게는 이 감쌈이 보호가 아니다(§2.4). 잠기지 않은 폰을 집어 든 사람은 앱이 잠겨 있으면 비밀번호(또는 등록된 지문)가 있어야 한다.
- **다른 앱**: Android는 앱마다 다른 사용자 ID와 샌드박스다. 앱 내부 저장소는 다른 앱이 읽지 못한다. Windows판의 "같은 사용자 악성코드"(비목표)보다 강한 경계이므로, 다른 일반 앱은 방어 대상이다.
- **오버레이·탭재킹**: 다른 앱 창이 승인 화면을 가리거나 위에 겹친 상태의 터치는 받지 않는다(§8.2).
- **화면 캡처·녹화·최근 앱 미리보기·화면 AI**: 비밀 화면은 `FLAG_SECURE`와 빈 assist 구조(§9.1).
- **키보드 앱(IME)**: 비밀번호·PIN·복구 단어·개인키는 시스템 키보드로 받지 않는다(§9.2). 키보드 앱은 모든 입력을 보는 제3자다.
- **알림을 읽는 앱**: 알림 접근 권한을 받은 앱은 모든 알림을 읽는다. 그래서 앱의 알림에는 주소·금액·출처·비밀을 넣지 않는다(§3.3).
- **백업·기기 이전**: 앱 데이터는 Android 백업·기기 간 이전에서 뺀다(§5.1).

### 2.2 비목표

- 루팅·부트로더 해제 기기, 커널·TEE 취약점(보안 패치가 오래된 기기 포함). 이런 기기에서는 기기 키 감쌈과 생체 인식 키가 보호를 주장하지 않는다(vault Argon2id는 그대로 남는다).
- 접근성 서비스의 악용을 API 36 미만에서 완전히 막는 것. API 34–35에서 `accessibilityDataSensitive`는 비도구 서비스의 읽기와 노드 동작을 막는다. 그러나 좌표로 넣는 제스처(`dispatchGesture`)는 API 36부터 막힌다. 접근성 서비스가 `TYPE_ACCESSIBILITY_OVERLAY`로 승인 화면의 받는 주소·금액을 덮는 것은 모든 API에서 잔여 위험이다. 읽지 않고 덮기만 하면 되고, 이 창은 신뢰 창이라 Android 12 터치 차단·가림 플래그·`setHideOverlayWindows`가 해당되지 않을 가능성이 크다(§16 P0-13). (2026-11-17: 초안은 API 34에서 접근성 악용이 막힌다고 적었다. 제스처 주입은 API 36부터다.)
- 켜 둔 USB·무선 디버깅(ADB 셸)과 셸 권한을 위임받은 앱(Shizuku 등). 셸 권한(`INJECT_EVENTS`)으로 넣은 터치는 어떤 API로도 거를 수 없어 arm 지연과 2초 누르기를 통과한다(`adb shell input swipe x y x y 2000`). `MotionEvent`의 장치·source·도구 종류 검사는 Windows의 `physical` 검사처럼 보안 경계가 아니다. 지문 승인(§6.4)이 마지막 확인에 손가락을 요구해 이 틈을 메운다.
- WebView(Chromium) 엔진 자체의 0-day. 렌더러는 격리 프로세스이고, 엔진은 Play 스토어로 업데이트된다. 브라우저 쪽 코드를 지갑 상태가 없는 `:browser` 프로세스에 두는 것(§7.4)은 §18 Q1에서 주인이 정할 때까지 권고다. 두더라도 그 분리는 주 프로세스의 메모리(DEK)만 지킨다. 같은 앱 UID라 파일과 Keystore 키는 함께 쓰므로, 브라우저 쪽이 장악되면 기기 키로 `vault.ywv`를 풀어 가져가 오프라인 Argon2 대입을 할 수 있다(§2.4). (2026-11-17 검토: 초안은 `:browser`를 정해진 것으로 보고 이 비목표의 근거로 썼다.)

### 2.3 운영 권고

- 보안 업데이트가 계속 나오는 기기를 쓴다. 패치가 1년 넘게 멈춘 기기는 시험용으로만 쓴다(§1.1 띠).
- 화면 잠금(PIN·패턴·비밀번호)을 켠다. 기기 키는 화면 잠금이 있어야 TEE의 보호를 제대로 받는다.
- 필요 없는 접근성 서비스를 끈다.
- USB 디버깅은 설치·업데이트할 때만 켜고 끝나면 끈다. 무선 디버깅은 쓰지 않는다. Shizuku 같은 셸 권한 위임 앱과 함께 쓰지 않는다.
- 복구 단어를 사진으로 찍지 않는다(갤러리 사진을 읽는 OCR 악성코드). 복구 단어는 지갑을 만들거나 복구할 때만 입력한다(가짜 `시드 백업` 유도 앱).

### 2.4 Windows판보다 약하거나 다른 점 (숨기지 않는다)

| 항목 | Android | 처리 |
|---|---|---|
| 브라우저가 보증한 출처 | 앱 내 브라우저는 WebView가 준 `sourceOrigin`(같은 급). WalletConnect는 주장값 + Verify([13] §7) | 그대로 표시 |
| 비밀 복사 | 클립보드 기록·동기화 제외 수단 없음 | 기능 없음(§9.3) |
| 붙여넣은 비밀 | 지울 수 없는 Java `String`·키보드 기록에 남음 | 복구 단어·개인키 붙여넣기 금지(§9.4) |
| 승인 창 앞으로 띄우기 | 백그라운드 Activity 시작 금지 | 사용자가 앱을 열 때만 보임(UX 차이) |
| 접근성 오버레이로 승인 화면 덮기 | 막을 API 없음 | 경고 띠(§8.3), 잔여 |
| 접근성 제스처 주입 | API 36부터 차단 | 보호 등급(§1.1), 지문 승인(§6.4) |
| ADB·Shizuku 셸 주입 | 막을 API 없음 | 디버깅 끄기, 경고 띠(§8.2), 지문 승인 |
| 앱 제거 | vault도 지워짐 | 복구 단어 백업 강조(§5.2, §14.2) |
| 하드웨어 신뢰 표시 | 없음(Protected Confirmation 폐기, secp256k1·Ed25519 미지원) | Windows와 같음 |
| YubiKey NFC 터치 | 탭 1회가 세션 전체를 덮을 수 있음(미확인, P0-17). [10] §1의 '터치가 마지막 방어선'이 NFC에서는 약하다 | 배지 구분(§10). 큰 잔액은 USB-C로 쓴다 |
| YubiKey NFC 전송 | PIN(VERIFY)이 암호화되지 않고 RF로 감 | 서명만 NFC 허용, 키 가져오기·PIN·관리 키 변경은 USB-C만(§10) |
| 하드웨어 키보드 주입 | 주입된 `KeyEvent`(adb `input keyevent`, Shizuku)를 실제 키와 구별할 수 없음(Windows `physical` 검사 없음) | 키보드 승인 없음(§8.1) |
| 같은 UID의 다른 프로세스 | `:browser`(§7.4)가 장악되면 파일·`yw.device.v1`·`apikeys.ks`를 함께 씀 | 기기 키 감쌈은 '파일을 들고 나간' 공격만 막는다(§5.2). DEK는 주 프로세스 메모리에만 |
| 같은 복구 단어를 두 기기에 | 폰 하나가 장악되면 Windows판의 같은 계정도 위험(구획화 상실, 타당성 검토 첫머리) | 기기별 계정 분할, 큰 잔액은 폰에 시드 없는 구성(YubiKey 전용 계정, §10·§18 Q6, 타당성 검토 §5.3) — §1.2 |
| WalletConnect 요청 | 앱이 앞에 있고 잠금이 풀린 동안만 받음 | 릴레이 우편함 TTL 안에서 기다림(§12.1) |
| 사설 CA RPC | 사용자 설치 CA 불신 | 지원하지 않음(§12) |

- Android에만 있는 공격자: 접근성 악성코드(화면 읽기·덮기·주입), 가짜 `시드 백업` 유도 앱, 갤러리 사진의 복구 단어를 읽는 OCR 악성코드, 서명 키 유출 + ADB(§14.2). 대응은 위 표와 §8–§9, §2.3의 권고다.
- `spec.md` D40의 '같거나 높게'는 보호 등급 '완전'(API 36+), USB·무선 디버깅 꺼짐, 사용자가 설치한 접근성 서비스 없음, YubiKey는 USB-C로 쓰거나 P0-17이 통과한 뒤, 이 기기에만 있는 계정(같은 복구 단어를 Windows판과 함께 쓰지 않음)일 때의 주장이다. 그때도 위 표의 승인 화면 앞으로 띄우기·접근성 오버레이 덮기·사설 CA·앱 제거 시 vault 삭제는 다르거나 약하다. (2026-11-17 검토: 초안은 앞의 세 조건만 적었고 같은 복구 단어의 구획화 상실과 NFC를 표에서 뺐다.)

## 3. 구조

### 3.1 층

```
yw-json, yw-core            그대로 (플랫폼 독립)
   ▲
yw-platform, yw-engine      신설: 순수 타입·플랫폼 trait, 그리고 yw-app에서 떼어 낸 앱 로직·화면 모델 (§11)
   ▲              ▲
yw-win ─ yw-app   yw-android ─ android/ (Java 앱, Gradle)
(Windows)         (JNI 경계, cdylib `libyw.so`)
```

- 키·서명·승인 판단·위험 규칙·digest는 모두 Rust(`libyw.so`) 안에서 한다. Java는 화면과 OS 서비스(네트워크 소켓, NFC, USB, Keystore, 생체 인식, WebView)만 맡는다. 원칙: "Rust가 정하고 Java는 그린다".
- 앱 코드는 Java(`javac --release`, 대상 `compileSdk`)로만 쓴다. Kotlin·Kotlin Gradle 플러그인·Compose·AppCompat·Material은 쓰지 않는다. (2026-11-17: 초안은 Kotlin이었다. 승인한 Android 의존이 Gradle·AGP·`androidx.webkit`뿐이라 Java로 바꿨다. 근거: 타당성 검토 §3.4.)
- `yw-android`는 `yw-win`처럼 `unsafe`를 허용하는 두 번째이자 마지막 크레이트다(파일마다 `#![allow(unsafe_code)]`, 블록마다 `// SAFETY:`). libc 함수와 상수는 `libc` 크레이트를 쓰고(§4.1), JNI 함수표만 직접 선언한다.
- **비밀은 Java 객체에 모으지 않는다**: Java `String`은 지울 수 없고, 배열은 가비지 컬렉터가 옮기며 사본을 남길 수 있다(ART는 이동형 GC). 앱 키보드(§9.2)는 키 하나를 누를 때마다 `secretKey(field, codeUnit)`로 네이티브 버퍼(Windows `ui/secure_text.rs`와 같은 방식, 엔진의 `SecretForm`)에 한 글자씩 넘기고 Java 쪽에는 남기지 않는다. 붙여넣기는 예외다(§9.4). 비밀 표시(복구 단어·개인키)는 `secretFill`(§3.2)로 Rust가 비밀 View가 가진 `char[]`에 직접 쓰고, View는 그것을 `Canvas.drawText(char[], …)`로 그리고 화면을 닫거나 가릴 때 0으로 지운다. `Effect`·화면 모델(`next()`의 yw-json 바이트)에는 비밀 텍스트가 들어가지 않는다. 비밀 화면의 모델은 핸들과 글자 수만 싣는다. Skia 글리프·GPU 버퍼의 사본은 [02] §7.3이 받아들인 짧은 사본과 같은 급의 잔여다. (2026-11-17: 초안은 Java `ByteArray`에 모아 한 번에 넘겼다. 2026-11-17 검토: 초안의 네 메서드에는 비밀을 Java로 내보내는 길이 `next()`의 JSON뿐이라 Java `String`으로 풀릴 수 있었다.)
- 단일 주 Activity + 화면별 View. 승인 화면과 비밀 화면은 별도 창(Activity)이며 §8·§9의 창 플래그를 쓴다. 앱 내 브라우저는 별도 Activity이고, §18 Q1에서 정하면 별도 프로세스 `:browser`에서 돈다(§7.4). 이 Activity들 사이의 이동은 백그라운드가 아니다(§5.4).
- WebView 렌더러는 Android가 격리 프로세스로 띄운다. 페이지 코드는 앱 프로세스의 메모리에 접근하지 못한다.

### 3.2 JNI 경계

- `libyw.so`는 `JNI_OnLoad` 하나만 내보내고 `RegisterNatives`로 다섯 메서드를 등록한다.
  - `byte[] call(byte[] cmd)`: yw-json으로 인코딩한 `Cmd`.
  - `byte[] next(long timeoutMs)`: `Effect`·화면 모델·플랫폼 I/O 요청. 전용 Java 스레드가 기다려 받아 메인 Looper로 넘긴다(Windows `WM_YW_EVENTS` 대체). 비밀 텍스트는 싣지 않는다(§3.1).
  - `void ioComplete(long id, int status, byte[] body)`: Java가 한 HTTPS·WSS·NFC·USB·Keystore·`javax.crypto` 작업의 결과. 지문 잠금 해제의 DEK(§6.2)도 이 길로 오며, Java는 호출 직후 `body`를 0으로 채운다(잔여는 §6.2).
  - `void secretKey(int field, int codeUnit)`: 앱 키보드의 한 글자(§9.2).
  - `int secretFill(long handle, char[] out)`: 비밀 표시. 화면 모델이 준 핸들의 비밀 텍스트를 Rust가 `SetCharArrayRegion`으로 Java가 할당한 `out`에 직접 쓰고 쓴 글자 수를 돌려준다(Rust 쪽 중간 버퍼는 0으로 지움). 핸들은 그 비밀 화면이 열려 있고 잠금이 풀린 동안만 유효하며, 그 밖에는 0을 돌려주고 아무것도 쓰지 않는다. `out`은 비밀 View만 가지며 화면을 닫을 때 `Arrays.fill`로 지운다. (2026-11-17 검토로 더함.)
- Rust 스레드는 Java를 부르지 않는다(`AttachCurrentThread`·전역 참조·`jclass` 캐시 없음). `panic = "abort"`라 JNI 경계를 넘는 unwind가 없다.
- 직접 선언한 `JNIEnv` 함수표 인덱스는 컴파일러가 검사하지 않으므로 에뮬레이터 CheckJNI로 확인한다(§13).

### 3.3 Java 쪽 규칙

- **로그**: 릴리스 빌드는 logcat에 쓰지 않는다. 앱 로그는 Rust 로거([04] §8, D28) 하나뿐이다.
- **예외 문구**: Java 예외는 JNI를 넘기 전에 고정 열거형(종류 + 숫자)으로 바꾼다. `getMessage()`에는 URL·호스트·경로가 들어가므로 Rust로 넘기거나 어디에도 쓰지 않는다(D13·D28).
- **잡히지 않은 예외**: `Thread.setDefaultUncaughtExceptionHandler`로 기본 처리기를 바꾼다. 기본 처리기는 스택과 예외 문구를 logcat에 쓰기 때문이다. 새 처리기는 `call`로 고정 사건(`java_uncaught`)만 보내고, Rust가 로그 한 줄을 쓴 뒤 슬롯을 지우고 `_exit`한다(§5.3 패닉과 같은 끝). 예외 클래스 이름·문구·스택은 쓰지 않는다.
- **알림**: 앱이 내는 알림은 고정 문구뿐이다(예: §12.1 전경 서비스의 `서명 응답을 보내는 중`). 주소·금액·출처·사이트 이름·비밀을 넣지 않는다. 요청이 왔다는 알림도 내지 않는다.

## 4. 의존성 (D1·D5·[01] §3 예외)

### 4.1 Rust

- 레지스트리 크레이트와 그 버전은 바뀌지 않고 `cargo update`도 없다. 그러나 `Cargo.lock`은 작업 공간 멤버마다 항목을 두므로, `yw-platform`·`yw-engine`·`yw-android`를 만드는 커밋마다 그 로컬 멤버 항목(과 `yw-android` → `libc`, `yw-engine` → `qrcodegen` 같은 의존 줄)이 더해지거나 바뀐다. 그렇지 않으면 `--locked` 빌드가 실패한다. 이 `Cargo.lock` 변경은 AGENTS.md 규칙 1대로 그 커밋마다 주인의 승인을 받는다. (2026-11-17 검토: 초안은 "`Cargo.lock`은 바뀌지 않는다"고 적었다.) 대상 `aarch64-linux-android`(NDK 링커)를 더한다. 에뮬레이터용 `x86_64-linux-android`는 CheckJNI 확인에만 쓴다.
- `aarch64-linux-android`에서는 `sha2`·`keccak` → `cpufeatures` → `libc`, `getrandom` → `libc` 경로로 `libc 0.2.189`가 yw-core 의존 닫힘에 들어온다. 어떤 cfg로도 뺄 수 없다. `Cargo.lock`·오프라인 캐시에는 이미 있다. (2026-11-17: 초안과 D40은 "새 크레이트 없음"이라 적었다. 타당성 검토 §3.5의 `cargo metadata` 결과로 바로잡았다.)
- 그래서 `scripts/check-core-deps.mjs`의 대상 타깃을 표로 바꾼다(`x86_64-pc-windows-msvc`, `aarch64-linux-android`, 에뮬레이터용 `x86_64-linux-android`). Android 표에만 `libc=0.2.189`와 그 `build.rs`를 더한다. `yw-platform`·`yw-engine`·`yw-android`의 POLICY 항목을 더한다([01] §3.3 개정). `qrcodegen 1.8.0`은 화면 모델의 QR(§11.3)이 두 플랫폼에 같은 모듈 행렬을 주도록 `yw-engine`의 허용으로 옮긴다(화면 모델을 옮기는 S5 커밋). yw-app·yw-android는 yw-engine을 거쳐서만 쓴다(`spec.md` D5 개정).
- `yw-android`는 같은 `libc`를 직접 의존해 `mlock`·`madvise`·`prctl`·`sysconf`·`mmap`과 상수(`MADV_DONTDUMP`, `PR_SET_DUMPABLE`, `_SC_PAGESIZE`)를 쓴다. 손으로 옮긴 상수는 쓰지 않는다.
- `.cargo/config.toml`에 `[target.aarch64-linux-android]`와 `[target.x86_64-linux-android]`의 `--cfg curve25519_dalek_backend="serial"`을 더한다. 없으면 x86_64에서 `curve25519-dalek-derive`·`syn` 등이 들어온다.
- getrandom은 기본 백엔드 그대로다([02] §1.1). minSdk ≥ 28이면 bionic `getrandom`이 늘 있다.
- 빌드 PC 경로: 지금 `.cargo/config.toml`은 exe가 빌드한 PC에서만 쓰인다는 이유로 `--remap-path-prefix`를 쓰지 않는다. `.so`는 폰으로 가고 tombstone·bugreport에 패닉 위치 문자열이 실릴 수 있으므로 Android 빌드는 경로를 지운다(§13).

### 4.2 Android

- 빌드 도구는 Gradle·AGP, 런타임 라이브러리는 `androidx.webkit` 하나만 직접 의존한다. `androidx.webkit`은 문서 시작 스크립트 주입과 출처가 붙은 메시지 통로(§7.2) 때문에 꼭 필요하다.
- `androidx.webkit`의 전이 의존은 아직 확인하지 않았다(§16 P0-7). POM을 훑은 조사는 `androidx.annotation`·`androidx.core` 등과 그것을 거친 `kotlin-stdlib`가 들어올 수 있다고 보였지만, 고정할 버전에서 Gradle이 실제로 해석한 결과가 아니므로 사실로 적지 않는다. P0-7에서 고정 버전의 `releaseRuntimeClasspath`를 해석해 정확한 목록을 `android/runtime-deps.txt`에 적는다. 그 뒤 `scripts/check-android-deps.mjs`가 해석 결과와 한 줄씩 대조한다(목록 밖 아티팩트·버전 차이 = 실패). 대조는 R8 축소 전 그래프 기준이다. 목록을 바꾸는 것은 의존성 추가와 같다(AGENTS.md 규칙 1).
- 쓰지 않는 것: Compose·AppCompat·`androidx.biometric`·CameraX·ML Kit·OkHttp·`yubikit-android`·Kotlin 플러그인. 생체 인식은 프레임워크 `android.hardware.biometrics.BiometricPrompt`(API 28), 카메라는 Camera2. 스크린 리더 노드는 프레임워크 `AccessibilityNodeProvider`(§9.1). 릴리스는 R8로 축소한다.
- (2026-11-17: 초안은 "AGP와 `androidx.webkit` 하나"라고만 적었다.)

### 4.3 공급망

Gradle은 빌드 때 사용자 PC에서 많은 제3자 코드를 실행하는 새 신뢰 면이다. 타당성 검토 §3.5는 Gradle 없이 `aapt2`·`javac`·`d8`·`zipalign`·`apksigner`만으로도 빌드됨을 확인했다. 2026-11-17 주인 승인으로 Gradle을 쓰고, 그 대안은 기록으로 남긴다.

- `gradle-wrapper.jar`는 바이너리라 커밋하지 않는다(D1, AGENTS.md 규칙 6). `scripts/build-android.ps1`이 고정 버전의 공식 Gradle 배포 zip을 받아, 저장소에 적은 SHA-256과 맞을 때만 푼다. 그 값은 처음 한 번 Gradle 공개 체크섬과 대조해 적는다.
- 저장소는 Google Maven·Maven Central만 쓴다. Gradle 플러그인 포털·`mavenLocal`·`jitpack`은 쓰지 않는다.
- `gradle/verification-metadata.xml`은 `pgp,sha256`으로 모든 아티팩트(플러그인·전이 포함)를 검증한다. 신뢰 키링은 ASCII armor 형식 `gradle/verification-keyring.keys`만 커밋한다. 이진 `gradle/verification-keyring.gpg`는 커밋하지 않고 `.gitignore`에 넣는다(D1, AGENTS.md 규칙 6). `.gitattributes`에 `*.keys` LF를, `scripts/privacy-scan.mjs`의 확장자 목록에 `.keys`를 더한다(§13). 서명이 없는 아티팩트는 sha256만 허용하고 그 목록을 파일에 남긴다. (2026-11-17 검토: 초안은 키링 형식을 정하지 않았다.)
- 모든 버전은 정확히 고정한다(범위·`+`·동적 버전 금지). `dependencyLocking`을 쓰고 `--no-daemon`으로 돌린다.

### 4.4 도구와 출처

- JDK는 AGP가 요구하는 17 계열의 정확한 한 빌드(배포처·버전·빌드 번호)를 P0-6에서 정해 그 zip의 SHA-256과 함께 `android/toolchain.sha256`에 적는다(범위 아님). Android SDK platform 36, NDK 30. `compileSdk`·`targetSdk` 36, `minSdk` 29. (2026-11-17 검토: 초안은 "JDK 17 이상"이라는 범위였다.)
- 버전 고정만으로는 부족하고 신뢰한 해시의 출처가 있어야 한다. NDK는 developer.android.com/ndk/downloads에 공개된 zip 체크섬, JDK는 배포처(예: Adoptium)가 공개한 SHA-256, Gradle은 공식 배포 체크섬과 대조한다. 그 zip의 SHA-256을 `android/toolchain.sha256`에 적는다. `scripts/build-android.ps1`은 빌드마다 기록과 설치된 도구의 버전을 확인하고 다르면 멈춘다.
- build-tools·platform·platform-tools는 `sdkmanager`가 Google 저장소 목록(HTTPS)의 체크섬으로 확인한다. 우리가 값을 고정하지 못한다(잔여, 문서화).
- 이 PC에 전부터 있던 NDK는 받은 경위를 모르므로 쓰지 않는다. 공식 zip을 새로 받는다(§16 P0-6).

## 5. 저장과 잠금

### 5.1 위치

- 앱의 백업 제외 저장소 `noBackupFilesDir/v3/`(`Context.getNoBackupFilesDir()`)에 Windows판과 같은 이름(`vault.ywv`, `meta.ywm`, `journal.ywj`, `settings.json`, `logs/`, `.prev`·E-VLT-006 보관본 포함)을 둔다. `apikeys.dpapi` 대신 `apikeys.ks`(§5.2), 지문 키 파일 `bio.ywb`(§6.2)도 같은 곳이다. (2026-11-17: 초안은 `filesDir`였다. 일부 제조사의 기기 이전 예외를 한 층 더 막는다.)
- `android:allowBackup="false"`, `fullBackupContent="false"`, `dataExtractionRules`는 `cloud-backup`·`device-transfer`·`cross-platform-transfer` 모두 제외한다. 일부 제조사는 API 31+에서 `allowBackup=false`여도 기기 간 이전을 하므로 백업 제외 경로가 핵심 방어다.
- 외부 저장소·`MediaStore`에 쓰지 않는다. 내보내기는 사용자가 고른 위치에 비밀 아닌 것만 쓴다.
- 쓰기는 원자적이다: 임시 파일 → `FileDescriptor.sync()`(fsync) → `rename`. 디렉터리도 fsync한다.

### 5.2 기기 키 감쌈

- vault·meta·journal·apikeys 파일은 디스크에 쓸 때 Keystore AES-256-GCM 키 `yw.device.v1`(사용자 인증 불필요, 내보낼 수 없음, TEE)로 한 번 더 감싼다. 형식: `"YWK1" ‖ iv(12) ‖ ct ‖ tag(16)`, AAD = 파일 종류 문자열.
- StrongBox는 기기 키에 쓰지 않는다. 파일을 쓸 때마다 보안 요소를 거치면 느릴 수 있기 때문이다. P0-10 측정 뒤 다시 정한다. (2026-11-17: 초안은 StrongBox가 있으면 StrongBox였다.)
- `setUnlockedDeviceRequired(true)`(기기 화면 잠금이 풀린 동안만 사용)를 켠다. 잠긴 폰에서 앱 프로세스가 파일을 풀지 못한다. 대가: 화면 꺼짐과 겹친 쓰기가 실패할 수 있다. 쓰기는 원자적이라 실패하면 이전 파일이 남고, 저널 쓰기가 실패하면 전송하지 않는다([03] §4.3, fail closed). P0-10에서 이 경합을 재 보고, 쓸 수 없는 정도면 끄고 그 이유를 여기 적는다.
- 안쪽 형식(vault v3 [02] §4, meta, journal)은 바이트 그대로다. 감싸고 푸는 것은 저장 계층(`yw-android`의 파일 서비스)이며 yw-core는 바뀌지 않는다.
- 효과: 파일을 빼내도 이 기기의 TEE 밖에서는 열 수 없어 오프라인 비밀번호 대입이 불가능하다.
- 대가: 기기가 초기화되거나 키가 사라지면 파일을 열 수 없다. 앱을 지우면(Android는 앱 제거 때 앱 데이터를 지운다. Windows는 데이터 폴더가 남는다) 또는 서명 키를 잃어 지우고 다시 설치하면 vault도 사라진다(§14.2). 복구는 복구 단어·개인키 백업·YubiKey 재연결뿐이다. 설치 안내, 첫 실행 화면, 백업 확인 화면이 이를 크게 알린다.
- 한계: Keystore는 키를 꺼내 가는 것은 막지만, 루트·커널을 장악한 공격자가 이 기기 안에서 키를 쓰는 것은 막지 못한다(§2.2 비목표와 같음). 기기 키는 '파일을 들고 나간' 공격에 대한 방어다.
- 기기 키를 만들 수 없으면(Keystore 오류) 지갑을 만들지 않는다(fail closed).

### 5.3 메모리 슬롯

- `LockedSlot`([02] §7.3)은 `mmap` 익명 페이지 + `mlock` + `madvise(MADV_DONTDUMP)`로 구현한다. 실패하면 잠금 해제하지 않는다(E-VLT-007과 같은 규칙).
- 슬롯 크기는 `sysconf(_SC_PAGESIZE)`(4 KB 또는 16 KB 기기)로 정한다. 앱의 `RLIMIT_MEMLOCK`은 64 KiB이므로 잠그는 슬롯 합계가 이를 넘지 않게 한다.
- 주 프로세스는 `Application.onCreate`에서 `libyw.so`를 올리고 `JNI_OnLoad` 안에서 무엇보다 먼저 `prctl(PR_SET_DUMPABLE, 0)`을 부른다. 그래서 `:browser`(§7.4)나 어떤 Activity보다 먼저 설정된다. 같은 UID의 다른 프로세스가 `/proc/<pid>/mem`·ptrace로 DEK를 읽지 못하게 하는 것이 목적이다. `:browser` 프로세스는 `libyw.so`를 올리지 않는다.
- **패닉**: `yw-android`의 패닉 훅은 로그 한 줄([04] §1.5와 같음)을 쓴 뒤 모든 `LockedSlot`을 0으로 지우고 `abort` 대신 `_exit`로 끝낸다. `abort`(SIGABRT)는 debuggerd가 `/data/tombstones`에 스택·레지스터 주변 메모리를 남기고(bugreport에 포함), `PR_SET_DUMPABLE 0`으로도 막히지 않기 때문이다. Java 쪽 잡히지 않은 예외도 같은 끝으로 간다(§3.3). 네이티브 SIGSEGV의 tombstone은 남는다(ART가 그 처리기를 쓰므로 바꾸지 않는다, Windows WER 덤프와 같은 급의 잔여).
- Argon2id 매개변수는 바꾸지 않는다(m = 256 MiB, t = 3, p = 4, D7). Android는 메모리가 모자라면 오류를 돌려주지 않고 lmkd가 프로세스를 죽인다. 그래서 Argon2를 시작하기 전에 `ActivityManager.isLowRamDevice()`가 참이거나 `MemoryInfo.totalMem` < 4 GiB이면 지원하지 않는 기기로 알리고 vault를 만들거나 열지 않는다. 원자적 쓰기와 회전 재개([02] §4.4) 덕에 도중에 죽어도 데이터는 손상되지 않지만, 매번 죽는 기기에서는 쓸 수 없다.
- 시험 기기에서 1회 시간·최대 메모리를 재서 [09]에 남긴다(§16 P0-3). 10 s를 넘으면 `KDF_V3` 변경, 곧 D7 개정 사안으로 본다([02] 미결 #3). 매개변수를 낮추는 것은 새 형식(v4)이며 이 문서의 범위가 아니다.
- 잔여: Argon2 256 MiB 버퍼와 짧은 평문 버퍼는 잠그지 못하며, 일부 제조사의 저장소 스왑(RAM Plus 등)으로 나갈 수 있다.

### 5.4 자동 잠금 ([04] §5, D12 예외)

- 유휴 시간(1–60분, 기본 10분)과 수동 잠금은 같다. 더해서: 화면이 꺼지면(`ACTION_SCREEN_OFF`) 즉시 잠근다.
- **백그라운드의 정의**: 이 앱의 어느 프로세스에도 시작된(`onStart` 뒤 `onStop` 전) Activity가 없을 때다. 한 Activity의 `onStop`이 아니다. 주 Activity·승인 Activity·비밀 Activity·브라우저 Activity를 서로 오가는 것은 백그라운드가 아니다. 주 프로세스가 수를 센다: 주 프로세스의 Activity는 `onStart`·`onStop`에서 직접, `:browser`의 Activity는 바운드 서비스(§7.4)로 알린다. 바운드 서비스 연결이 끊기면(`:browser` 종료) 그 프로세스의 수는 0이 된다. 다른 프로세스의 알림은 바인더로 늦게 올 수 있으므로 수가 0이 된 뒤 500 ms 동안 다시 오르지 않을 때 백그라운드로 본다. (2026-11-17 검토: 초안은 주 Activity의 `onStop`을 썼다. 그러면 승인·비밀·브라우저 Activity를 여는 것이 백그라운드가 되어, 설정 0에서는 승인 화면을 열자마자 잠그고 그 승인을 거부로 닫으며, 기본 1분이면 앱 내 브라우저를 1분 쓰면 잠기고 WalletConnect 연결이 끊겼다.)
- 앱이 백그라운드로 가면 그 시각을 `SystemClock.elapsedRealtime()`(깊은 절전에도 흐름)으로 기록하고, 설정 시간(0–10분, 기본 1분) 뒤 잠근다. 0이면 백그라운드로 판정한 즉시 잠근다.
- 백그라운드 프로세스는 Android가 얼릴 수 있어 타이머가 제때 돌지 않는다. 그래서 백그라운드에서 다시 앞으로 올 때(수가 0에서 오를 때, 그 Activity의 `onStart`) 무엇을 그리기 전에 먼저 경과를 검사하고, 넘었으면 잠근 뒤 잠금 화면부터 그린다.
- 백그라운드에 있는 동안 DEK는 `mlock` 슬롯(§5.3)에 남고 UID 샌드박스가 지킨다. 잠금이 풀린 채 집어 든 폰은 비목표다(Windows의 잠기지 않은 노트북과 같다). 프로세스가 끝나면 DEK가 사라지므로 잠긴 것과 같다.
- 백그라운드 즉시 잠금(0)은 앱을 오갈 때마다 Argon2와 비밀번호를 요구해 짧은 비밀번호를 부추길 수 있다. 이 점을 설정 설명에 적는다.
- 잠금은 진행 중 승인을 거부로 닫고 비밀 화면을 닫는다([04] §5.3).

## 6. 생체 인식(지문)

### 6.1 원칙

- 선택 기능이며 기본은 끔. 비밀번호는 그대로 지갑의 근본이고, 지문은 이 기기에서 비밀번호 입력을 대신하는 편의 경로다.
- 켜기: 잠금 해제된 상태에서 설정 → 보안 → `지문으로 잠금 해제` → 비밀번호 다시 입력 → 지문 확인.
- 위협 모델 변화: 지문 잠금 해제를 켜면 그 기기에서 지갑을 여는 요소가 '아는 것(비밀번호)'에서 '이 기기 + 등록된 손가락'으로 바뀐다. D7·D10의 의미가 이 기기에서만 달라진다. vault 파일 자체는 여전히 비밀번호로만 열리므로 다른 기기·백업에는 영향이 없다.
- **기기 자격 증명은 쓰지 않는다**: `DEVICE_CREDENTIAL`·`setDeviceCredentialAllowed(true)`를 어느 경로에도 허용하지 않는다. 기기 PIN은 `adb shell input text`로 넣을 수 있어 지문의 의미(손가락이 있음)가 사라진다.
- 지문 키는 모두 강한(Class 3) 생체 인식만 받는다: API 30+는 `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`와 `setAllowedAuthenticators(BIOMETRIC_STRONG)`. API 29에는 그 API가 없다. `CryptoObject`를 붙인 `BiometricPrompt`가 Class 3만 허용하는지 P0-11에서 확인하고, 확인되지 않으면 API 29에서는 지문 기능을 켤 수 없게 한다.

### 6.2 잠금 해제 방식

- Keystore AES-256-GCM 키 `yw.bio.v1`: 사용자 인증 필수, 사용할 때마다 인증(`CryptoObject`, 시간 창 없음), 강한 생체 인식만(§6.1), 새 지문이 등록되면 무효(`setInvalidatedByBiometricEnrollment(true)`), `setUnlockedDeviceRequired(true)`, StrongBox가 있으면 StrongBox.
- 이 키로 vault의 DEK를 감싼 `bio.ywb` = `"YWB1" ‖ iv ‖ GCM(DEK)`(AAD = vault 헤더의 키 구간 `header[0..130]`(`KEY_SECTION_END`, [02] §4.1–§4.2: `vault_id`·KDF 매개변수·salt·`wrap_nonce`·`wrapped_dek`)의 SHA-256)를 저장한다. 이 구간은 `PayloadRewrite`가 그대로 두고 `Rewrap`만 바꾸며, `Rewrap`(비밀번호 변경) 전에는 `bio.ywb`를 지운다(§6.3). (2026-11-17 검토: 초안은 헤더 176바이트 전체였다. 그 안의 `generation`·`payload_nonce`는 쓰기마다 바뀌므로 백업 확인·키 추가 같은 payload 쓰기 뒤 지문 잠금 해제가 실패하고 스스로 꺼졌다.) 지문 성공 → `BiometricPrompt`가 연 `Cipher`로 DEK를 풀어 바로 슬롯에 넣고 Java 배열을 0으로 채운다 → Rust가 그 DEK로 payload를 연다(yw-core 새 함수 `Vault::unlock_with_dek`). 열리지 않으면(DEK 불일치·헤더 변경) `bio.ywb`와 키를 지우고 비밀번호를 받는다.
- **`unlock_with_dek`는 비밀번호 경로와 같은 절차다**: KEK 유도만 빼고 헤더·payload 검증, 끝나지 않은 DEK 회전(`PrevDek`, payload tag 7)의 재개, 사이드카가 열리지 않을 때의 E-VLT-006 처리를 비밀번호 잠금 해제와 같은 코드로 한다([02] §4.4·§4.5·§7.2). 재개에 비밀번호가 필요한 단계가 있으면 지문 경로는 비밀번호를 받는다. 새 공개 API이므로 구현할 때 [02] §4.4·§10.3을 같은 커밋에서 고친다.
- 잔여 위험: `Cipher` 출력은 잠깐 Java 힙에 있다(가비지 컬렉터가 복사했을 수 있음). 문서로 남긴다.

### 6.3 비밀번호가 여전히 필요한 경우

- 처음 켤 때, 새 지문이 등록되어 키가 무효가 됐을 때, 지문 시도가 시스템에 의해 잠겼을 때.
- 기기를 다시 켠 뒤 첫 잠금 해제(Android 기기 잠금과 같은 규칙).
- 마지막 비밀번호 입력 뒤 72시간이 지났을 때(비밀번호를 잊지 않게; Android 기기 잠금의 강한 인증 주기와 같음).
- Windows판이 비밀번호를 다시 묻는 모든 작업: 복구 단어·개인키 보기, 비밀번호 변경, 복구 단어 추가·지우기, 개인키 가져오기·지우기, YubiKey 등록 기록 지우기, 지문 잠금 해제·지문 승인 끄기.
- 비밀번호 변경은 DEK를 바꾼다([02] §4.4). 회전을 시작하기 전에 `bio.ywb`와 키를 지운다. 회전이 중간에 끊겨도 옛 DEK를 감싼 파일이 남지 않는다. 변경이 끝난 뒤 다시 켜도록 안내한다.

### 6.4 지문 승인 (선택, 지문 잠금 해제를 켜면 기본 켬)

- 승인 화면의 `승인` 뒤에 `BiometricPrompt`(시스템 화면)로 한 번 더 확인한다. 고위험은 체크박스 + 2초 누르기([04] §3.4–§3.7) 뒤 지문이다. 시스템 화면이라 다른 앱이 겹치거나 접근성 서비스·ADB 셸이 대신 누를 수 없다.
- **언제나 `CryptoObject`에 묶는다**: 승인용 Keystore 키 `yw.confirm.v1`(HMAC-SHA256, 사용할 때마다 인증, 강한 생체 인식만, 등록 변경 시 무효, `setUnlockedDeviceRequired(true)`)로 `Mac`을 만들고, 지문 성공 뒤 그 `Mac`으로 승인 digest의 MAC을 계산할 수 있어야 지문 확인으로 친다. MAC 값은 쓰지 않는다. 키를 쓸 수 있었다는 것이 TEE가 강한 생체 인식을 확인했다는 증거다. 기기 자격 증명 대체는 없다(§6.1). 키가 무효가 되면 지문 승인을 끄고 비밀번호로 다시 켜게 한다. (2026-11-17: 초안은 키 없이 `BiometricPrompt` 결과만 썼다. 그러면 API 29에서 약한 생체 인식이 통과할 수 있다.)
- 지문 승인은 판단을 바꾸지 않는다: 위험 등급·digest·`consume` 규칙은 그대로이고, 지문은 사용자의 손이 있다는 추가 확인일 뿐이다. 지문 취소는 거부가 아니라 승인 화면으로 돌아간다. 시스템 화면이 떠 있던 동안 승인 화면은 포커스를 잃었으므로 arm 대기는 처음부터다(§8.4).
- 지문 승인은 주입된 누름을 막지만, 덮인 표시(§2.2 접근성 오버레이)를 본 사용자가 지문을 대는 것은 막지 못한다.
- 강요 위험(잠든 사이 손가락 등)을 설정 화면에 적는다. 이 위험이 걱정되면 지문 승인을 켜고 지문 잠금 해제는 끈다. 그 조합도 허용한다: `yw.confirm.v1`은 DEK를 감싸지 않는다.

## 7. 앱 내 브라우저 (확장 대체, [05])

### 7.1 화면

- 브라우저 탭: 주소 표시줄(출처를 언제나 전부 보임, 호스트 강조), 뒤로·앞으로·새로 고침, 연결된 사이트 목록과 즐겨찾기, 탭 여러 개(최대 8).
- `https://`만 연다. `http://`는 localhost 토글([05] §4.6)이 켜졌을 때 `localhost`·`127.0.0.1`만(D22, [05] §4.7은 IPv6 리터럴 출처를 거부한다. 2026-11-17 검토: 초안은 `[::1]`도 열었으나 그 페이지의 요청은 모두 출처 해석에서 실패했다). 그 밖 스킴(`intent:`, `file:`, `content:`, `javascript:`, `data:` 최상위)은 열지 않는다. `wc:` 링크는 WalletConnect 페어링 화면으로 넘긴다(§12.2).

### 7.2 provider 주입과 출처

- `WebViewCompat.addDocumentStartJavaScript`로 `provider-main.js`(확장과 같은 파일, 빌드 때 복사)와 작은 브리지 스크립트를 허용 출처의 문서 시작에 넣는다. 브리지는 확장의 `content.js` 역할(페이지 `postMessage` ↔ 앱)을 한다.
- **허용 출처 규칙**(`allowedOriginRules`): `addDocumentStartJavaScript`와 `addWebMessageListener`에 같은 집합을 준다. 언제나 `https://*`(모든 https 출처) 하나이고, localhost 토글이 켜진 동안에만 `http://localhost`·`http://127.0.0.1`을 더한다. 토글이 바뀌면 두 등록을 지우고(`ScriptHandler.remove`, `removeWebMessageListener`) 새 집합으로 다시 등록한다. `*`(모든 출처)는 쓰지 않는다. 규칙 문법이 이 뜻 그대로인지(`https://*`가 모든 https 호스트를, localhost 규칙이 모든 포트를 덮는지)는 P0-9에서 확인하고, localhost 포트를 덮지 않으면 사용자가 연 포트의 규칙만 더한다. 규칙과 별개로 앱은 `sourceOrigin`을 [05] §4.7(`BrowserOrigin::parse`)과 토글로 다시 검사한다. (2026-11-17 검토로 더함: 초안은 규칙을 정하지 않았다.)
- 브리지 스크립트는 확장과 같은 정적 감사를 받는다: `scripts/audit-extension.mjs`의 대상에 넣어 `eval`·`Function`·동적 import·`fetch`·`innerHTML`·URL 리터럴을 금지한다(§13).
- 요청은 `WebViewCompat.addWebMessageListener`의 통로 하나로만 받는다. 리스너가 받는 `sourceOrigin`은 WebView가 정한 값이며 Chrome `port.sender`와 같은 신뢰 근거다([05] §1). `isMainFrame`이 거짓이면 받지 않는다(최상위 프레임만, 확장과 같음).
- `addJavascriptInterface`는 쓰지 않는다(호출한 출처를 알 수 없음).
- 그 뒤는 Windows판과 같다: envelope v1([05] §6), 메서드 표·파라미터 검사([05] §3), 권한·grant([05] §4), 오류 코드([05] §5), 디스패처, 승인 큐, 잠금 대기. 페이지 브리지는 보안 경계가 아니며 앱이 경로·출처·파라미터를 다시 검사한다. Windows에서 확장 background router가 맡던 한도·기한은 §7.6이 주인을 정한다.
- 호환 모드(MetaMask·Rabby·Phantom·UniSat·Xverse, [05] §2.12–§2.13)는 브라우저 설정에 둔다.

### 7.3 WebView 설정

- JavaScript 켬, 파일·콘텐츠 접근 끔(`setAllowFileAccess(false)`·`setAllowContentAccess(false)`), `file:` URL의 교차 접근 끔, 혼합 콘텐츠 금지(`MIXED_CONTENT_NEVER_ALLOW`), 릴리스 빌드에서 WebView 디버깅 끔.
- 텔레메트리: 매니페스트에 `<meta-data android:name="android.webkit.WebView.MetricsOptOut" android:value="true"/>`(D28).
- Safe Browsing: 켤 수 있지만 보호로 주장하지 않는다. Play 서비스가 있을 때만 동작하고, 방문하는 URL의 해시 앞부분을 Google에 보낸다(D28). 브라우저 설정에 이를 적고 끌 수 있게 한다. 기본값은 §18에서 정한다. (2026-11-17: 초안은 "Safe Browsing 켬"을 보호처럼 적었다.)
- 새 창(`window.open`)은 같은 앱의 새 탭으로 열고 그 탭의 출처를 따로 다룬다. 다운로드는 묻는다.
- 페이지가 띄우는 창은 지갑 UI를 흉내 내지 못하게 한다:
  - `alert`·`confirm`·`prompt`·`beforeunload`(`onJsAlert`·`onJsConfirm`·`onJsPrompt`·`onJsBeforeUnload`)는 시스템 대화 상자로 띄우지 않는다. 탭의 페이지 영역 안에 출처와 함께 그린다.
  - 파일 선택(`onShowFileChooser`)은 거부한다.
  - 카메라·마이크·기타 권한(`onPermissionRequest`)과 위치(`onGeolocationPermissionsShowPrompt`)는 거부한다. 앱은 이 권한을 매니페스트에 요청하지 않는다(카메라는 §12.2 QR만, 앱 화면에서).
- 쿠키·저장소는 `:browser` 프로세스의 WebView 데이터 폴더에 있고 Chrome과 공유하지 않는다. 설정 → 브라우저 → `사이트 데이터 지우기`.

### 7.4 격리와 위장 방지

- **별도 프로세스**(§18 Q1에서 주인이 정할 때까지 권고. 이 절과 §3.1·§15·§17 A4의 `:browser`는 이 조건 아래의 설계다): 브라우저 Activity와 WebView는 `android:process=":browser"`에서 돈다(`WebView.setDataDirectorySuffix("browser")`). WebView 렌더러는 Android가 격리하지만, 네트워크·HTTP 해석 등 브라우저 쪽 코드는 그 WebView를 띄운 프로세스 안에서 돈다. 이 프로세스에는 `libyw.so`의 지갑 상태·DEK가 없다.
- **분리가 지키는 것은 주 프로세스의 메모리(DEK)뿐이다**(그것도 `PR_SET_DUMPABLE 0`이 `:browser`보다 먼저 설정될 때, §5.3). `:browser`는 같은 앱 UID라 `noBackupFilesDir`의 파일을 읽고 Keystore 키 `yw.device.v1`을 쓸 수 있다. 그래서 브라우저 쪽 코드가 장악되면 `vault.ywv`를 기기 키로 풀어 가져가 오프라인 Argon2 대입을 할 수 있고, `apikeys.ks`의 RPC URL·키도 읽을 수 있다. 기기 키 감쌈(§5.2)은 이것을 막지 못한다(§2.4). 사용자 인증이 필요한 `yw.bio.v1`·`yw.confirm.v1`은 지문 없이 쓸 수 없다. (2026-11-17 검토: 초안은 분리가 지갑 전체를 지키는 것처럼 적었다.)
- 브라우저 프로세스는 `addWebMessageListener`로 받은 (탭, 문서 세대, `sourceOrigin`, `isMainFrame`, 메시지)만 주 프로세스의 바운드 서비스로 넘긴다. 이 서비스는 `android:exported="false"`다. 두 프로세스는 같은 앱 UID라 내보낼 필요가 없다. 서명 권한(`protectionLevel=signature`)으로 내보내는 방식은 쓰지 않는다(이득 없이 공격 면만 는다). 브라우저 프로세스는 Windows의 yw-host와 같이 내용을 해석하지 않는 중계이고, 주 프로세스가 경로·출처·파라미터를 다시 검사한다([05] §1).
- **주 프로세스는 WebView를 만들지 않는다.** 도움말·안내 화면도 WebView로 그리지 않는다. 데이터 폴더가 갈라지고, 브라우저 쪽 코드가 DEK가 있는 프로세스로 들어오기 때문이다.
- **위장 방지**: 페이지는 브라우저 틀(주소 표시줄·출처) 안에서만 그려진다. 전체 화면(`onShowCustomView`, Fullscreen API)은 끈다. 승인은 언제나 별도 승인 Activity(§8)에서만 하며, 웹 페이지 안의 어떤 버튼도 승인이 아니다. 첫 실행 안내가 이를 알린다.
- **프레임**: `addDocumentStartJavaScript`는 iframe에도 스크립트를 넣으므로 `provider-main.js`·브리지는 `window.top === window`일 때만 provider를 설치한다. 앱은 `isMainFrame`이 거짓인 메시지를 버린다(§7.2).
- **기능 확인**: `WebViewFeature.DOCUMENT_START_SCRIPT`·`WEB_MESSAGE_LISTENER`가 지원되지 않는 WebView에서는 브라우저 탭을 끄고 `WebView를 업데이트하세요`를 보인다(fail closed, 다른 주입 방식으로 대체하지 않는다).
- 별도 프로세스는 주인 확인이 필요한 권고다(§18 Q1). 주인이 받아들이지 않으면 브라우저 Activity는 주 프로세스에서 돌고, §2.2의 WebView 0-day 비목표는 브라우저 쪽 코드가 DEK가 있는 프로세스 안에 있다는 뜻으로 다시 적으며, 이 절의 바운드 서비스 중계는 같은 프로세스 안의 호출이 된다.
- **승인 Activity 시작**: 요청은 `:browser`가 앞에 있는 동안 오므로, 주 프로세스가 승인 Activity를 띄울 때 보이는 Activity는 다른 프로세스(같은 UID)의 것이다. Android 10+ 백그라운드 Activity 시작 규칙이 이것을 허용하는지 P0-9에서 확인한다. 허용되지 않으면 `:browser`가 주 프로세스의 지시를 받아 승인 Activity를 띄운다(승인 Activity는 여전히 주 프로세스에서 돈다).

### 7.5 문서 수명과 대기 요청 ([05] §2·§6 대비)

- 탭마다 **문서 세대**를 둔다. 최상위 프레임이 새 문서로 바뀔 때(같은 문서 안의 `pushState`·해시 이동은 제외), 탭을 닫을 때, 렌더러가 끝났을 때(`onRenderProcessGone`) 세대를 올린다. 앱은 문서마다 `activationNonce`([05] §2.6–§2.8)를 만들어 브리지에 주고, 요청을 (탭, 세대, `sourceOrigin`, `activationNonce`)에 묶는다. 확장의 content port 하나 = activation 하나([05] §2.8)와 같은 뜻이지만 **문서 수명에 대해서만** 같다. 확장은 이 값을 격리된 content world에만 두는데, WebView 브리지는 페이지와 같은 JS world에서 돌므로 Android에서는 페이지 스크립트가 이 값을 볼 수 있다. 그래서 이 값은 비밀이 아니며 보안 근거는 WebView가 정한 (탭, 세대, `sourceOrigin`)이다. (2026-11-17 검토: 초안은 [05] §6.1을 가리켰고 비밀 여부를 적지 않았다.)
- 세대가 바뀌면 그 문서의 대기 요청은 모두 페이지 취소로 끝낸다(확장의 `pagehide` → content의 `disconnect`([05] §2.7) → background가 그 activation의 대기 요청을 모두 native `cancel`([05] §2.8)하는 것과 같음): 승인 화면을 닫고, 승인을 버리고(아무것도 서명하지 않음), 4001로 기록한다(응답은 갈 곳이 없다). PIN을 기다리는 YubiKey 단계도 같다([05] §4.5). 이미 저널에 기록된 전송은 계속되고 활동에 보인다.
- 응답은 요청을 받은 그 `JavaScriptReplyProxy`로만, 세대·출처·`activationNonce`가 그대로일 때만 보낸다. 새 문서(같은 출처라도)에는 이전 문서의 응답·이벤트를 보내지 않는다. grant 재확인([05] §4.5)과 Solana 거래의 서명 칸 검사([07] §20.10)는 이 규칙 위에서 성립한다.
- 응답 프록시가 문서마다 새로 생기는지는 P0-9에서 확인한다. 확인 전에도 위의 세대 검사로 막는다.

### 7.6 한도와 기한 ([05] §2.8 router 대체)

- Windows에서는 확장 background router가 문서별 토큰 버킷, 대기 상한, JSON 크기 한도, 요청 기한(D23)을 맡는다. Android의 브리지는 페이지의 JS world에서 돌아 믿을 수 없으므로, 그 일을 **주 프로세스의 yw-engine 문서 라우터**(Rust, 공통 코드로 시험)가 맡는다. 문서 키는 (탭, 세대)다. (2026-11-17 검토로 더함: 초안은 이 일의 주인을 정하지 않았다.)
  - [05] §2.8의 상수를 그대로 쓴다: `RATE_PER_SECOND`·`RATE_BURST`(문서별 토큰 버킷, 부족 → -32005 "Rate limit exceeded."), `MAX_PENDING_PER_DOCUMENT`·`MAX_GLOBAL_PENDING`(→ -32005 "Too many pending requests."), `MAX_ACTIVE_DOCUMENTS`(가득 차면 대기가 0인 문서 중 가장 오래 쓰지 않은 것을 닫음, 없으면 새 문서의 요청을 받지 않음), `REQUEST_LIMITS`([05] §2.9, 넘으면 -32600 "Request too large." 또는 -32600 "Invalid request."), `READ_DEADLINE_MS`·`INTERACTIVE_DEADLINE_MS`(만료 → -32603 "Request timed out."과 디스패처 취소, reason `deadline`).
  - 그 뒤 디스패처의 [05] §8.4 한도(문서당 토큰 버킷, read 상한, 승인 큐 상한)는 Windows처럼 따로 적용한다. 두 층의 순서와 오류 코드는 Windows와 같다.
  - `:browser`는 내용을 해석하지 않는다(§7.4). 다만 바이트 길이가 `REQUEST_LIMITS`의 메시지 상한을 넘는 메시지는 바인더로 넘기지 않고 -32600 "Request too large."로 답한다. 바인더 트랜잭션 버퍼(프로세스 공용 약 1 MB)보다 큰 메시지를 넘기는 방법(나눠 보내기 또는 `SharedMemory`)은 P0-9에서 정한다.
- 시험: A4 test-dapp 시나리오에 토큰 버킷 소진(-32005), 대기 상한, 너무 큰 요청(-32600), read 기한·승인 기한 만료(-32603 + 승인 화면 닫힘)를 넣는다.

## 8. 승인 화면 ([04] §3)

### 8.1 같은 규칙

- 상태 기계(`ui/interaction.rs`의 규칙)는 공유 크레이트의 같은 코드다: arm 지연 1초(창이 보이고 포커스를 얻은 뒤부터), 비무장 중 누름은 대기를 다시 시작, 다시 활성화되면 다시 대기, 고위험 체크박스 + 2초 연속 누르기, 표시 변경 시 초기화, 120초 만료, 잠금 시 거부, 대기열 사이트당 16·전체 64.
- 거부 먼저: 처음 포커스는 `거부`. 터치 화면에서는 `거부`를 엄지가 먼저 닿는 쪽(아래 왼쪽)에, `승인`을 그 반대쪽에 둔다.
- **하드웨어 키보드로는 승인하지 않는다**: Enter(모든 위험 등급)와 고위험 Space 누르기로 승인하지 않는다. 승인은 터치(와 지문 승인 §6.4)로만 한다. Android 앱은 주입된 `KeyEvent`(adb `input keyevent`, Shizuku)를 실제 키와 구별할 수 없어 Windows의 `physical` 검사(주입된 Enter는 승인하지 않음)를 지킬 수 없기 때문이다. 키 입력은 비무장 중 누름처럼 arm 대기를 다시 시작한다. 거부는 키보드로도 된다(자동 반복 무시). (2026-11-17 검토: 초안은 고위험 아래에서 Enter 승인을 남겼다.)
- 표시는 yw-core가 정확한 서명 payload에서 만든 그대로이며 값을 자르지 않는다(주소 전부, 줄 바꿈, §8.5).

### 8.2 탭재킹과 주입

- 승인 화면의 루트 View가 `onFilterTouchEventForSecurity`를 덮어써 모든 터치의 플래그를 직접 본다. `MotionEvent.FLAG_WINDOW_IS_OBSCURED` 또는 `FLAG_WINDOW_IS_PARTIALLY_OBSCURED`가 붙은 터치는 상태 기계에 비무장 중 누름으로 넣고(대기 다시 시작) 버린다(버튼·체크박스에 가지 않음). `filterTouchesWhenObscured`는 켜지 않는다: 켜면 프레임워크가 가려진 터치를 View에 닿기 전에 버려 상태 기계가 보지 못하고, 부분 가림은 거르지도 않는다. 부분 가림은 화면 조광기·채팅 버블 같은 정상 겹침 창에서도 생긴다(오탐, 사용자에게는 `다른 앱이 화면 위에 있습니다`). (2026-11-17 검토: 초안은 `filterTouchesWhenObscured`와 "비무장 누름으로 다룸"을 함께 적었으나 둘은 함께 성립하지 않는다.)
- API 31+: `setHideOverlayWindows(true)`(`HIDE_OVERLAY_WINDOWS` 권한)로 승인·비밀 화면이 떠 있는 동안 다른 앱의 겹침 창을 숨긴다.
- `Settings.Global`의 `adb_enabled` 또는 `adb_wifi_enabled`가 켜져 있으면 승인 화면과 비밀 화면에 경고 띠 `USB·무선 디버깅이 켜져 있습니다. 컴퓨터가 대신 누를 수 있습니다`를 보인다. 지문 승인(§6.4)을 켜면 마지막 확인에 손가락이 필요하므로 셸 주입만으로는 승인되지 않는다.

### 8.3 접근성 서비스

- 사용자가 설치한(시스템 이미지에 없는) 접근성 서비스가 하나라도 켜져 있으면 승인 화면과 비밀 화면 위에 경고 띠를 보인다: 그 앱 이름과 `이 앱은 화면을 읽고, 덮고, 대신 누를 수 있습니다`. `isAccessibilityTool` 선언은 서비스가 스스로 하는 것이라(사이드로드 앱은 거짓 선언 가능) 도구 선언 여부로 경고를 빼지 않는다. (2026-11-17: 초안은 "시스템 기본 제외"였다.)
- API 34+: 승인 버튼·체크박스·비밀 화면에 `setAccessibilityDataSensitive(YES)`. API 34–35에서는 비도구 서비스의 읽기·노드 동작만 막히고 제스처 주입은 막히지 않는다. API 36+에서 비도구 서비스의 제스처 주입이 막힌다(§1.1).
- 지문 승인(§6.4)은 주입된 누름을 막지만, 덮인 표시를 본 사용자가 지문을 대는 것은 막지 못한다. 접근성 오버레이 가림의 플랫폼 완화로 알려진 것은 Advanced Protection의 비도구 접근성 서비스 차단뿐이다. 이것은 2차 자료로만 확인했고, 타당성 검토는 그 차단을 Android 17(API 37)의 확대로 적었다(미확인, §16 P0-18). 이 모드는 사이드로드 설치와 충돌할 수 있다(§14.3). (2026-11-17 검토: 초안은 Android 16+에서 막는다고 사실처럼 적었다.)

### 8.4 창과 작업

- 승인·비밀 Activity는 `exported=false`, `excludeFromRecents=true`, 앱 기본과 다른 `taskAffinity`이고 앱 내부에서만 시작한다. 다른 앱이 인텐트로 열 수 없다. minSdk 29에는 작업 하이재킹(StrandHogg 계열) 수정이 일부 없으므로 이 속성이 더 중요하다.
- 승인·비밀 화면에는 보조 창(`Dialog`·`PopupWindow`·`Spinner` 드롭다운·`Toast`·`AlertDialog`)을 쓰지 않는다. 별도 창이라 `FLAG_SECURE`·가림 검사를 물려받지 않을 수 있다. 선택 목록·확인은 같은 창 안에서 그린다.
- `SYSTEM_ALERT_WINDOW`·전체 화면 인텐트·잠금 화면 위 표시 권한을 요청하지 않는다. 승인 화면은 사용자가 앱을 열었거나 앱 안(앱 내 브라우저 포함)에서 요청이 생겼을 때만 보인다(Android 10+ 백그라운드 Activity 시작 금지, `:browser`가 앞에 있을 때는 §7.4·P0-9).
- `onWindowFocusChanged(false)`·`onPause`는 비활성으로, 포커스 회복·`onResume`은 다시 활성으로 상태 기계에 넣어 arm 대기를 처음부터 시작한다. 두 번째 손가락·`ACTION_CANCEL`은 비무장 누름으로 다룬다. 딥링크·탭 전환 직후에는 dApp을 누르던 손가락이 승인 버튼 위에 있을 수 있으므로 arm 지연은 줄이지 않는다.

### 8.5 좁은 화면

- 줄 나누기는 같은 `text_layout`(Rust)에 화면 폭과 글자 폭만 바꿔 넘긴다. 자르지 않는다([04] §3.3).
- 고정폭 열 수가 40 미만이면 원본 16진수는 줄마다 8바이트로 보인다([04] §3.3의 '80열 미만 16바이트' 규칙에 더한다. 구현할 때 [04] §3.3을 같은 커밋에서 고친다).
- **모두 본 뒤 arm**: 받는 주소·금액 등 critical 필드, 위험 경고, 시뮬레이션 띠가 한 번씩 모두 화면에 보여야 arm 대기(1초)가 시작된다(`ApprovalGate`의 `seen_all`). 보이지 않은 영역이 남아 있으면 `승인` 버튼에 `끝까지 내려 보세요`를 보인다. 표시가 바뀌면 `seen_all`도 처음부터다. 이 규칙은 yw-engine 공통 코드이며 Android에서 켠다. Windows 적용은 따로 정한다(§18). 근거: 타당성 검토 §3.4, 2026-11-07 주인 답 '추천안'.
- 글꼴 크기·화면 크기 설정이나 분할 화면 때문에 열 수가 28 미만이면 arm하지 않고 `창을 넓히거나 글꼴을 줄이세요`를 보인다.

## 9. 비밀 화면 ([04] §4)

### 9.1 창

- 복구 단어·개인키 보기·입력, 비밀번호·PIN 입력 화면, WalletConnect QR 스캐너(§12.2)는 `FLAG_SECURE`(캡처·녹화·화면 공유·최근 앱 미리보기 차단)다. 플래그를 설정하지 못하면 열지 않는다(fail closed). 비밀 버퍼를 화면에 넘기기 직전에 창 플래그를 다시 읽어 확인한다([04] §4.5의 `Required`와 같은 뜻). 승인 화면은 Windows판처럼 비밀이 없으므로 `FLAG_SECURE`가 아니다.
- 비밀은 직접 그린다. 비밀 View는 화면 모델에서 핸들만 받고 텍스트는 `secretFill`(§3.2)로 자기 `char[]`에 받는다. `EditText`·`TextView`·`String`·알림·제목에 넣지 않는다.
- 비밀 화면의 루트 View는 `importantForAutofill=noExcludeDescendants`, `importantForContentCapture=no`(API 30+), API 34+ `setAccessibilityDataSensitive(YES)`, API 35+ `setContentSensitivity(SENSITIVE)`다. `contentDescription`·접근성 노드에 비밀 텍스트를 넣지 않고, `onProvideStructure`·`onProvideVirtualStructure`·`onProvideAutofillStructure`는 빈 구현으로 덮는다(화면 AI·어시스턴트·자동 채우기가 텍스트를 가져가지 못하게).
- API 33+ 모든 Activity에 `setRecentsScreenshotEnabled(false)`.
- 스크린샷 감지(API 34)·녹화 콜백(API 35)은 경고 신호로만 쓴다.
- 스크린 리더: 직접 그린 승인 View·키보드·단어 격자는 프레임워크 `AccessibilityNodeProvider`로 가상 노드를 만든다(AndroidX `ExploreByTouchHelper` 안 씀). 비밀 View의 노드는 텍스트를 싣지 않는다.

### 9.2 앱 키보드

- 비밀번호·PIN·passphrase·복구 단어·개인키 입력은 앱 자체 키보드로 받는다(시스템 키보드 앱을 거치지 않음). 키를 누를 때마다 한 글자씩 네이티브로 넘긴다(§3.1).
- 키 배치는 고정이다(무작위 배열 아님 — 오타가 늘고 어깨너머 보기는 막지 못한다). 키를 누를 때 확대 미리보기 없음, 소리·진동은 시스템 설정을 따른다.
- 복구 단어 입력은 BIP39 목록 자동 완성(앞 4글자)을 앱 키보드 위에 보인다.
- `IME_FLAG_NO_PERSONALIZED_LEARNING`은 보장이 아니므로 시스템 키보드로 비밀을 받는 대안이 되지 않는다.

### 9.3 복사

- **비밀(복구 단어·개인키·비밀번호) 복사 기능은 Android판에 없다.** Windows판 설정 `비밀 복사 허용`도 보이지 않는다. 기능 동등성(§1)의 예외다(D11, 근거: 타당성 검토 §1.4 U2, 2026-11-07 주인 동의).
- 이유: Android에는 클립보드 기록·클라우드 동기화·모니터 제외(D11)에 해당하는 표시가 없다. `ClipDescription.EXTRA_IS_SENSITIVE`(API 33)는 미리보기만 숨기고, 키보드 앱이 자체 클립보드 기록을 둔다. 30초 뒤 지워도 그 사본은 지우지 못한다.
- 주소·거래 해시 등 비밀 아닌 값의 복사는 허용하고 `EXTRA_IS_SENSITIVE`를 붙이지 않는다.
- (2026-11-17: 초안은 Windows처럼 기본 끔 + 켜면 30초 뒤 지움이었다.)

### 9.4 붙여넣기 ([04] §4.7 대비)

- 복구 단어(W05)와 개인키(W07) 칸은 붙여넣기를 받지 않는다(Windows와 다름). 앱 키보드로만 입력한다.
- 비밀번호·passphrase·PIN 칸은 붙여넣기를 받고, 붙여넣은 직후 클립보드를 지운다(`clearPrimaryClip`, API 28+).
- 잔여 위험: 붙여넣은 값은 `ClipData` → `CharSequence`라 지울 수 없는 Java `String`으로 앱 힙에 남고, 키보드 앱의 클립보드 기록에 이미 있을 수 있다. [04] §4.8의 클립보드 잔여와 같은 급으로 본다.

## 10. YubiKey ([10])

- APDU·PIN·슬롯·등록·서명 규칙은 [10] 그대로다(`yw_core::yubikey`는 전송과 무관하다). Android는 플랫폼 지점 둘을 새로 구현한다:
  - `CardTransport`(아래 NFC·USB-C).
  - `yw_core::yubikey::piv::MgmtCipher`(PIV 관리 키 상호 인증의 AES·3DES 한 블록, [10] §4·§5.3): Windows는 yw-app이 CNG로 구현한다. Android는 `yw-android`가 플랫폼 I/O 요청으로 Java `javax.crypto.Cipher`(`AES/ECB/NoPadding`, `DESede/ECB/NoPadding`)에 맡기고 `ioComplete`로 결과 블록을 받는다. 잔여: 관리 키 바이트가 `SecretKeySpec`과 Java 배열로 Java 힙에 들어가며 지울 수 없는 사본이 남을 수 있다(§6.2의 DEK 잔여와 같은 급). 관리 키는 지갑 비밀이 아니지만 카드에 쓰는 권한이다.
- **등록·관리 범위**: 키 가져오기(등록, [10] §7.3: OpenPGP PW3 VERIFY 뒤 가져오기, PIV 관리 키 상호 인증 뒤 슬롯마다 가져오기), PIN·PUK·관리자 PIN 변경, PIN 통일, 관리 키 변경·보호([10] §5.3.3, §9.3)는 **USB-C로만** 한다. NFC로 시작하면 아무 APDU도 보내기 전에 고정 문구 `이 작업은 USB-C로 연결해서 하세요. NFC는 암호화되지 않습니다` / `Connect the YubiKey by USB-C for this. NFC is not encrypted.`로 멈춘다. NFC로는 서명, 읽기만 하는 작업(카드 식별, 가져오기 없이 등록 [10] §7.5, 복구 단어 없이 연결 [10] §7.6)만 한다. 이유: 가져오기는 파생한 개인키 바이트를, PIN 변경은 새 PIN을, PIV는 관리 키 교환을 RF로 평문 전송한다(SCP11b 미지원). 엿들은 서명 PIN은 카드 없이 쓸모없지만 엿들은 가져오기는 키 그 자체다. USB-C에서도 가져오기 APDU의 개인키 바이트는 Java `byte[]`(USB 전송 버퍼)를 지나며, Java는 전송 직후 0으로 채운다(가비지 컬렉터 사본은 §6.2와 같은 급의 잔여).
- (2026-11-17 검토: 초안은 "등록·관리도 Android에서 할 수 있다(기능 동등)"를 전송 구분 없이 적었다. 타당성 검토 §5.3은 등록·재슬롯·삭제를 **Windows에서만** 하라고 권했다. 이 문서는 그 권고에서 벗어나 USB-C 등록을 허용한다: Android판만 쓰는 사용자도 YubiKey를 쓸 수 있게 하는 기능 동등(2026-11-17 주인 승인)을 따르되, NFC 평문 전송의 위험은 받아들이지 않는다. 등록하는 폰은 복구 단어·관리자 PIN을 다루게 되므로 타당성 검토의 '폰에 시드 없음' 이점은 그 폰에서 등록하지 않을 때만 남는다.)
  - **NFC**(YubiKey 5 NFC): `IsoDep`.
  - **USB-C**: `UsbManager` + CCID(`PC_to_RDR_XfrBlock`). 장치 권한은 사용자가 시스템 창에서 허락한다. CCID 응답의 시간 연장 상태(터치 대기)를 계속 읽는다. 다른 앱(Yubico Authenticator 등)이 인터페이스를 쥐고 있으면 `다른 앱이 YubiKey를 쓰고 있습니다`.
- 라이브러리: `yubikit-android`는 쓰지 않는다(새 Maven 의존이고, 자체 OpenPGP·PIV 세션이 [10] §5.2의 규칙을 우회한다).
- 프레임 크기는 지금처럼 짧은 APDU + 체이닝(`ApduMode::Short`, 최대 261바이트)이다. `IsoDep.getMaxTransceiveLength() < 261`이면 지원하지 않는 폰으로 알린다.
- NFC 읽기는 reader mode + `FLAG_READER_SKIP_NDEF_CHECK`(YubiKey OTP의 NDEF가 브라우저를 여는 것 방지), `IsoDep.setTimeout` 약 5 s, 작업 스레드에서만 `transceive`. 태그가 떨어지면 `CardRemoved`.
- **한 번 탭 = 한 작업**: NFC에서는 서명에 필요한 네트워크 값(Solana blockhash 포함)을 먼저 받는다 → PIN을 앱 키보드로 받는다 → `YubiKey를 휴대폰 뒷면에 대세요` → 한 필드 세션 안에서 SELECT·serial·공개키 대조·VERIFY·승인 `consume`·모든 서명을 끝낸다. VERIFY는 최대한 늦게 보낸다. VERIFY 전에 태그가 떨어지면 PIN 시도를 쓰지 않고 다시 대 달라고 한다. 카드 단계 상한 120 s는 그대로다([10] §9).
- PIN 창(W11)은 "YubiKey를 휴대폰 뒷면에 대세요(NFC) 또는 연결하세요(USB)"로 바뀐다.
- **터치 의미(미확인)**: NFC 한 필드 세션에서 터치 정책 `always`가 서명마다 새 확인을 요구하는지 확인되지 않았다(§16 P0-17). 확인 전까지 승인 화면의 카드 배지는 NFC `탭 1회`, USB `터치 N회`로 나눈다. [10] §1의 '터치가 마지막 방어선'은 NFC에서 '탭 한 번이 세션 전체를 덮을 수 있다'로 약하게 읽는다. `yubikey::mock`에 '세션당 터치 1회' 모드를 더해 시험한다.
- NFC로 보내는 서명 PIN(VERIFY)은 암호화되지 않는다(SCP11b 미지원, 잔여. 엿들어도 카드가 없으면 쓸 수 없다). FIPS 시리즈는 FIPS 모드에서 NFC로 OpenPGP·PIV를 쓸 수 없다. 펌웨어 5.7의 새 키는 USB 전원을 3초 받기 전까지 NFC가 제한된다(Restricted NFC). 첫 사용 안내에 적는다.
- 자동 시험은 `yw_core::yubikey::mock`만 쓴다. 실제 카드는 주인이 시험한다(AGENTS.md 규칙 3).
- 선택 후속: Windows가 공개 슬롯 표를 QR로 내보내고 폰이 읽어 '폰에 시드 없는 YubiKey 전용 계정'을 쓰는 방식(큰 잔액 권장 구성, 타당성 검토 §5.3, §18).

## 11. 공유 크레이트 분리

### 11.1 현재 상태 (2026-11-17 조사)

- yw-app은 약 15만 3천 줄(그중 시험 약 4만)이다. `windows_sys`를 직접 쓰는 곳은 없고 모두 `yw_win`을 거친다.
- **이미 떼어 낼 수 있는 것**: `flow/`, `rpc/`, `btc/`, `sol/`, `zec/`, `walletconnect/`, `browser/`(파이프 서버 `server.rs` 제외), `explain/`, `received/`, `workers/`, `events.rs`, `errors.rs`, `network.rs`, `settings.rs`, `meta.rs`, `ui/interaction.rs`, `ui/approval.rs`, `ui/approval_view.rs`, `ui/secure_field.rs`. 이들은 UI를 부르지 않고 OS에는 `yw_win`의 몇 가지 서비스나 이미 있는 trait(`rpc::Transport`, `flow::evm::Clock`, `explain::LlmTransport`, WalletConnect `RelayLink`·`RelayConnector`·`WcSink`·`VerifyHttp`, `yubikey::CardSource`, `browser::DappSink`·`Outlet`)으로만 닿는다.
- **어려운 곳**: 중앙 `App`(`app.rs`)이 Win32 핸들(`main`, `controls`, `fonts`, `secret`)과 지갑 상태를 한 구조체에 담고, 약 54개 파일이 `impl App`을 더한다. 화면 → 로직은 Win32 컨트롤 id(`WM_COMMAND`)와 HWND 편집 칸에서 다시 읽는 값(35곳)이고, 로직 → 화면은 `self.refresh()`(410곳), `controls.set_text`, `set_timer`, `notice`의 직접 호출이다. 승인 흐름(준비·재시뮬레이션·`consume`·서명)도 승인 창 코드(`app_approval.rs`) 안에 있다.
- **방향이 틀린 의존**: 순수 타입 `HttpsUrl`·`EndpointUrl`·`HttpError`·`Response`·`Timeouts`가 `yw-win/src/http.rs`(unsafe 허용 파일)에 있고 67개 파일이 `yw_win::http`를 참조한다. `received/hc.rs` → `app_hypercore`, `yubikey.rs` → `ui::theme`(조사 함수), `browser/mod.rs` → `ui::approval`(상수), `catalogues.rs` → `ui` 문구 모듈. `yw-app/src`의 33개 파일이 `monotonic_ms`를 직접 부른다(`Clock` trait가 있는데도). (2026-11-17 다시 셈: 초안의 31개·22개는 덜 셌다.) (2026-11-17 S2: `received/hc.rs` → `app_hypercore`는 정리함 — 순수 함수 `api_units`를 `hypercore.rs`로 옮겼다.) (2026-11-17 S2: `yubikey.rs` → `ui::theme`도 정리함 — 한국어 조사 함수 `object_particle`·`direction_particle`을 `text.rs`로 옮겼다.) (2026-11-17 S2: Windows 시계 `SystemClock`을 `flow::evm`에서 yw-app `system_clock.rs`로 옮기고 `RpcWorker::production`을 없앴다 — 파이프라인은 `yw_platform::Clock` trait만 부른다. 운영 시계는 그대로 `GetTickCount64` 기반이다.) (2026-11-17 S2: RPC 전송 이음매 `Transport`·`HttpReply`를 yw-app `rpc`에서 `yw_platform::http`로, `impl Transport for Client`를 yw-win `http`로 옮겼다 — `rpc`는 `yw_win`을 부르지 않는다.) (2026-11-17 S2: WalletConnect 이음매 — 릴레이 소켓 trait `RelayLink`는 `yw_platform::ws::WsLink`(구현은 yw-win `ws`)로, 연결자 `WsConnector`는 `app_walletconnect`로, Verify HTTP는 `Transport`에 대한 포괄 구현으로, P-256 검증은 `resolve`의 인자(`P256Verify`, 작업자가 `start`에서 받음)로 바꿨다. `walletconnect/`는 `yw_win`을 부르지 않는다. UA 접미사 `…/windows`(`worker.rs`)는 그대로 두고 S3에서 플랫폼 인자로 만든다.) (2026-11-17 S2: LLM 설명의 `WinHTTP` 전송 `WinHttpTransport`를 `explain/request.rs`에서 yw-app `explain_transport.rs`로 옮기고 `ExplainService::start`가 전송 생성 함수를 받게 했다(서비스가 시작될 때만 작업자 스레드에서 부름, D21). `explain/`의 지역 경과 시간은 `Instant`로 잰다. `explain/`은 `yw_win`을 부르지 않는다.) (2026-11-17 S2: 로그를 나눴다 — `logging`은 형식·정화·수준 거름과 `LogSink` trait만 갖고(`LogLevel`은 `settings`에서, `is_commit`은 `build_info`에서 옮김), 순환 파일 `LogWriter`와 `init`은 yw-app `log_file.rs`로 옮겼다. sink는 완성된 줄만 받는다(D28).) (2026-11-17 S2: `YubiKey` PC/SC 전송 `PcscTransport`·CNG 관리 키 암호 `CngCipher`·리더 원천 `PcscSource`를 `yubikey.rs`에서 yw-app `card_pcsc.rs`로 옮겼다 — `yubikey`는 `yw_win`을 부르지 않는다. 에뮬레이터 원천 `MockSource`는 항상 컴파일되는 `#[doc(hidden)] pub`이 되고, 시험 코드만 만든다는 것을 소스 검사가 확인한다.) (2026-11-17 S2: 키 작업자가 플랫폼을 받는다 — `KeyWorker::new(dir, KeyDeps { platform, clock, cards })`. `KeyPlatform`(`open_storage` → `WalletStore`(`VaultStorage` + sidecar 복구 이동), `new_slot`, `move_wallet_files`)은 `workers/key/platform.rs`에 있고, Windows 구현 `store::WinKeyPlatform`은 전과 같은 `FileStorage`·`VirtualLock` 슬롯 `LockedSlotBox`·`store::reset::move_wallet_files`를 넘긴다. `main.rs`가 그것과 `SystemClock`·`PcscSource`를 준다. vault 기록 시각은 주입된 시계의 벽시계, Solana 서명 시각 검사(`workers/journal.rs`)는 주입된 시계의 단조 시각(Windows: 전과 같은 `GetTickCount64`)이다. 순수한 이름·보고 형식(`file_name`, `with_suffix`, `is_set_aside`, `ResetReport`, `ResetError`, `README_NAME`, `FOLDER_PREFIX`)은 `wallet_files.rs`로 옮겼다. `workers/`는 `crate::store`·`yw_win`을 부르지 않는다. 시험용 원시 meta 쓰기 `KeyWorker::test_write_meta_bytes`는 그대로 `cfg(test)`다(배포 빌드에 넣지 않는다, 주인 결정).) (2026-11-17 S2 P 단계 끝: 네트워크 배지가 앱 모듈을 부르지 않게 `network::SolCluster::core`·`BtcNet::core`를 더했다(`app_sol::core_cluster`·`btc::core_network`는 이것을 부른다). 옮길 모듈 안의 `pub(crate)`·`pub(super)` 항목 중 나중 경계를 넘어 쓰이는 것(`browser::dispatch::sol_connect_value`·`btc_accounts_value`, `app_chain_sites`가 씀)은 `pub`으로 바꿨다. 남은 문서 속 앱 모듈 언급도 평이한 말로 바꿨다. 옮길 모듈(`flow`·`rpc`·`btc`·`sol`·`zec`·`walletconnect`·`browser`(`server.rs` 제외)·`explain`·`received`·`workers`, `events`·`errors`·`network`·`settings`·`meta`·`text`·`token_view`·`explorer`·`apikeys`·`hypercore`·`yubikey`·`logging`·`wallet_files`, `ui`의 승인 모델·`badge`·`secure_field`)에서 `yw_win`과 Windows 전용 앱 모듈을 찾는 검사가 비었다(문서·시험 코드 포함).) (2026-11-17 S2 P9–P12 검토: 위 감사는 하나를 빠뜨렸다 — 남는 App 시험(`app/tests.rs`)이 `cfg(test)`인 키 작업자 도우미 `workers::key::tests::yubikey_wallet`과 `KeyWorker::test_write_meta_bytes`도 불렀다. `cfg(test)`는 크레이트를 넘지 못하므로 다음처럼 정했다. `test_write_meta_bytes`는 없앴다 — 그것을 쓰던 App 시험 둘은 같은 파일에서 vault 세션을 하나 더 열어 원시 meta를 봉인한다(yw-app 시험 코드라 배포 빌드에 없다). `yubikey_wallet`은 E3에서 키 작업자와 함께 `yw_engine::testkit`(항상 컴파일, 문서에서 숨김, 에뮬레이터만 씀)으로 옮긴다. 실제 파일 위의 시험은 `WinKeyPlatform::deps_with_cards`에 리더 없는 원천 `yubikey::NoReaders`(또는 에뮬레이터)를 주고, 기계의 PC/SC 리더(`PcscSource`)는 `main.rs`만 받는다(시험 코드까지 읽는 소스 검사 `pcsc_readers_only_from_main`). `MockSource` 검사와 이 검사는 yw-engine `src`가 생기면 그것도 읽는다. 키 작업자 단위 시험의 시계는 벽시계도 고정값이고(`SystemTime` 없음), 메모리 플랫폼 위라 지울 폴더가 없다. 앞의 검사에 `crate::workers::key::tests::`·`test_write_meta_bytes`를 더하면 남는 것은 E3에서 옮길 `yubikey_wallet` 호출 세 곳뿐이다.) (2026-11-17 S2 E1: `crates/yw-engine`을 만들었다(로컬 의존 yw-core·yw-json·yw-platform, unsafe 금지, [01] §2.3b·§5.1). `text`·`errors`·`network`·`logging`(형식)·`yubikey`(순수, `MockSource` 포함)·`wallet_files`와 `ui`의 `approval`→`approval/mod.rs`, `interaction`→`approval/interaction.rs`, `approval_text`→`approval/text.rs`, `text_layout`→`approval/layout.rs`, `secure_field`→`secure_field.rs`를 이름만 바꿔 옮겼다(내용은 `use` 경로와 문서 줄만 다름). yw-app은 옛 경로로 다시 내보낸다(`lib.rs`·`ui/mod.rs`, S3–S4에서 없앰). `browser/mod.rs`는 이제 `yw_engine::approval`을 부르므로 `browser` → `ui::approval` 방향 틀린 의존도 정리함. 이 모듈들의 문구 카탈로그는 `yw_engine::catalogues`에 실제 경로(`yw_engine::errors::text` 등)로 옮겼다([14] §2·§5). `ui::badge`는 아직 옮길 수 없는 `meta::BookChain`을 써서 `meta`와 함께 E2에서 옮긴다. `testkit`(`yubikey_wallet` 등)은 키 작업자와 함께 E3에서 만든다.)

### 11.2 목표 구조

```
yw-platform  (신설, 의존성 0, unsafe 금지)  순수 타입(HttpsUrl·EndpointUrl·HttpError·Response·Timeouts·파일 오류 종류)
                                           + 플랫폼 trait(Clock, Http, WebSocket, Files, SecretStore(DPAPI/Keystore),
                                             Clipboard, CardSource, Wake(작업 결과 알림), Browser 출구)
                                           (yw-core의 `CardTransport`·`piv::MgmtCipher`는 그대로 yw-core trait이며
                                            구현은 yw-app(PC/SC·CNG)과 yw-android(NFC·USB-C·javax.crypto, §10)가 한다)
yw-win       yw-platform의 순수 타입을 쓴다(정의를 옮김). 그 밖은 지금과 같다.
yw-engine    (신설, unsafe 금지) 지갑 상태 `Wallet` + 명령 `Cmd` + 효과 `Effect` + 화면 모델(§11.3)
             + 위 "이미 떼어 낼 수 있는 것" 전부 + 승인 흐름
yw-app       Windows 셸: `Wallet`을 담고, Win32 입력 → `Cmd`, `Effect` → Win32, 화면 모델 → Win32 컨트롤·GDI
yw-android   Android 셸: JNI(§3.2), 입력 → `Cmd`, `Effect` → Java, 화면 모델 → JNI로 넘김
```

### 11.3 화면 모델 공유 (권장)

- 지금 Windows 화면은 이미 선언형 목록(`Vec<Item>`, `ui/main_window.rs`)이다. `Item`·`Ctl`에서 `yw_win` 타입(`ControlKind`, `Color`)을 의미 종류(제목·문단·주소·금액·버튼(`Cmd`)·입력 칸(필드 id)·드롭다운·알림 띠·QR 등)로 바꾸면, 화면을 만드는 코드(`ui/screens*.rs` 약 2만 줄)를 `yw-engine`으로 옮겨 **두 플랫폼이 같은 화면 목록을 그린다**. 기능이 같다는 것이 구조로 보장되고, 새 기능은 한 번만 만든다.
- 각 플랫폼은 그리기만 한다: Windows는 지금 컨트롤·GDI로(픽셀이 바뀌지 않아야 한다 — 스크린숏 투어로 대조), Android는 View로(좁은 화면에 맞춘 세로 배치).
- 입력 칸 값은 HWND에서 다시 읽지 않고 `Cmd::Edit(field, value)`로 엔진의 폼 상태에 둔다(비밀 칸은 지금처럼 `secure_field`).
- 플랫폼 예외(Android에서 비밀 복사 없음 §9.3, 붙여넣기 §9.4, 좁은 화면 `seen_all` §8.5)는 화면 모델의 플랫폼 플래그로 켜고 끈다. 화면 목록을 플랫폼마다 따로 만들지 않는다.

### 11.4 순서 (각 단계 = 커밋 하나 이상, Windows 동작 불변, 게이트 + 스크린숏 투어 대조)

| 단계 | 내용 | 위험 |
|---|---|---|
| S1 | `yw-platform` 신설, `HttpsUrl` 등 순수 타입을 `yw-win`에서 옮김(`HttpError::Os`는 OS 오류 코드 숫자로, WebSocket 업그레이드 거절은 `UpgradeRefused(u16)`), `Clock` trait를 `yw-platform`으로 옮김. **끝남(2026-11-17).** `monotonic_ms` 직접 호출(33개 파일)을 `Clock`으로 바꾸는 일은 S2(엔진으로 옮기는 모듈: `explain/`, `workers/journal.rs` 등)와 S4(`impl App`)로 미뤘다 — 지금 바꾸면 S4에서 같은 곳을 다시 고치게 된다 | 낮음, 기계적 |
| S2 | 방향 틀린 의존 4곳 정리, `yw-engine` 신설 후 "이미 떼어 낼 수 있는 것" 이동(시험 포함). (2026-11-17 S2 P1–P4 투어 대조: 한국어 조사 함수 이동(P2)을 포함한 P1–P4 뒤의 한국어 투어(`-Lang ko -SkipPopup`, 58장)를 S1 커밋(`719050f`)의 투어와 바이트 단위로 비교했다. 56장은 같고, `22-approval-ai-explain`·`23-settings-ai` 두 장은 모의 LLM 서버의 임시 루프백 포트 숫자만 다르다(실행마다 바뀜). 그 밖의 픽셀 차이는 없다.) (2026-11-17 S2 P9–P12 투어 대조: 네트워크 배지 경로를 바꾼 P12(`4db3b79`)와 그 검토 수정 뒤의 한국어 투어(`-Lang ko -SkipPopup`, 58장)를 같은 `719050f` 투어와 비교했다. 56장은 바이트 단위로 같고, 같은 두 장(`22-approval-ai-explain`·`23-settings-ai`)은 모의 LLM 서버의 루프백 포트 숫자 한 줄만 다르다.) | 낮음–중간, 파일 이동이 큼 |
| S3 | `Cmd`·`Effect` 도입: 컨트롤 id → `Cmd` 표, `refresh`·`notice`·`set_timer`·클립보드·`controls.set_text`를 `Effect`로, 폼 값을 엔진 상태로 | 중간–높음, 410곳 |
| S4 | `App` 분리: 지갑 상태 → `yw-engine::Wallet`, Win32 핸들은 `yw-app`에 남김. 승인 흐름(`approved`·재시뮬레이션·`consume_and_sign`)을 엔진으로, 승인 창은 "신뢰 입력 신호 → `InteractionEvent`"만 남김 | 높음, 승인 보안 규칙 회귀 위험 — `tests/approval_interaction.rs`·`approval_golden.rs`를 먼저 늘린다 |
| S5 | 화면 모델 중립화(§11.3)와 `ui/screens*.rs` 이동. 비밀 입력 상태 기계(`SecretForm`)를 VK 코드 대신 중립 키 이벤트로 | 중간, 픽셀 회귀는 투어로 확인 |

- S1–S2는 안드로이드와 상관없이 해도 손해가 없다(의존 방향 정리). S3–S5가 본 작업이다.
- 승인 창의 신뢰 입력 신호는 플랫폼마다 다르다: Windows는 `injected()`·`GetKeyState`·전경 여부·`MA_ACTIVATEANDEAT`, Android는 가림 플래그(§8.2)·창 포커스·터치 down/up·지문 승인(§6.4). 둘 다 같은 `ApprovalInteraction`에 같은 의미의 사건으로 넣는다. `MotionEvent` → `InteractionEvent` 변환은 Rust 표 시험으로 둔다.
- Windows 전용으로 남는 것: 파이프 서버·native messaging, DPAPI, PC/SC, `explorer.exe` 실행, `rpc.json` 가져오기, 설치 기록(`build_info.rs`), 확장 설치 안내, 창 위치(`window.json`), 스크린숏 투어 캡처.

## 12. 네트워크

- HTTPS(RPC·인덱서·LLM)는 Java `HttpsURLConnection`이다. yw-win HTTP와 같은 설정: 리디렉션 끔(`setInstanceFollowRedirects(false)`), 캐시 끔, `CookieHandler` 없음, `Origin`·`Referer` 없음, TLS 1.2+, 응답 크기 상한 동일, 전체 기한은 감시 스레드가 넘으면 `disconnect()`.
- WebSocket(WalletConnect 릴레이)은 Java가 `SSLSocketFactory.getDefault()`로 TLS를 열고 **호스트 이름 검증을 직접 켠다**(`SSLParameters.setEndpointIdentificationAlgorithm("HTTPS")`, SNI 설정). `SSLSocket`은 기본으로 호스트 이름을 검증하지 않는다. HTTP 업그레이드 핸드셰이크와 `Sec-WebSocket-Accept`(SHA-1) 검증도 Java(`MessageDigest`)가 한다(Rust 허용 목록에 sha1이 없다). 그 뒤 RFC 6455 프레이밍·마스킹·한도(4 MiB 메시지, 15 s ping, 2 s close, 기존 backoff)는 Rust(yw-engine, 순수 로직이라 시험 가능)가 한다. (2026-11-17: 초안은 핸드셰이크까지 Rust였다.)
- 요청·응답 해석과 한도는 Windows판과 같은 Rust 코드다. Java 예외는 고정 열거형으로 바꿔 넘긴다(§3.3).
- `network_security_config`: 평문 HTTP 금지(localhost 토글 예외), 사용자 설치 CA 불신(시스템 CA만), 인증서 투명성(API 36+) 켬. 사설 CA로 운영하는 자체 RPC는 지원하지 않는다(Windows와 다름).
- RPC URL·토큰·API 키는 `apikeys.ks`(§5.2)에 두고 로그에 남기지 않는다(D13·D28).

### 12.1 WalletConnect 수명 ([13] §5.2·§8 대비)

- Android는 백그라운드 프로세스를 얼리고 네트워크를 끊는다(Doze, 앱 대기 버킷). 그래서 릴레이 연결을 늘 유지할 수 없다. **앱이 앞에 있고 잠금이 풀린 동안에만 릴레이에 연결**하고, 잠그거나 백그라운드로 가면 연결을 닫는다. '앞에 있음'과 '백그라운드'는 §5.4의 앱 단위 정의다(앱 내 브라우저·승인 화면을 쓰는 동안은 앞에 있다). Windows는 잠가도 연결을 유지하고 요청을 4100으로 거절한다([13] §8).
- **이미 받은 요청**(디스패처 큐·승인 화면에 있는 것):
  - 잠글 때: Windows와 같이 4100으로 끝낸다([13] §5.2). 연결을 닫기 전에 그 응답을 보내고(닫기 기한 2 s 안), 그 사이 보내지 못한 응답은 버린다(dApp은 기한 만료로 본다).
  - 잠그지 않고 백그라운드로 갈 때: 큐에 그대로 둔다. 연결을 닫기 전에 이미 만든 응답만 보낸다. 다시 앞으로 오면 다시 연결하고, 요청 기한(`expiryTimestamp`·10분) 안이면 이어서 승인하고 답한다. 그 전에 잠기거나 프로세스가 끝나면 위 규칙대로 보내지 못하고 dApp은 기한 만료로 본다(릴레이는 이미 받은 요청을 다시 주지 않는다).
- 연결이 닫힌 사이 요청은 릴레이 우편함이 TTL(`wc_sessionRequest` 300 s) 또는 요청 만료까지 붙잡고, 다시 연결하면 받는다. 지난 요청은 기존 8000 처리다.
- 승인 응답을 보내는 중에 사용자가 앱을 떠나도 그 응답만 마무리하도록, 사용자가 `승인`을 누른 순간(앱이 앞에 있으므로 전경 서비스를 시작할 수 있다) 전경 서비스를 시작하고 응답을 보내면(또는 3분 뒤) 끝낸다. API 34+는 `shortService` 유형(약 3분, `FOREGROUND_SERVICE` 권한). `shortService`가 없는 API 29–33은 유형 없는 일반 전경 서비스를 같은 3분 상한으로 쓴다. 어느 쪽이든 진행 알림은 고정 문구 `서명 응답을 보내는 중`뿐이며 주소·금액·출처·dApp 이름을 싣지 않는다(§3.3). 이 서비스는 응답 하나를 보내는 동안만 릴레이 연결을 유지하며 새 요청을 받지 않는다. (2026-11-17 검토: 초안은 API 34부터 있는 `shortService`만 적었다.)
- 푸시(FCM·WalletConnect 푸시 서버)는 쓰지 않는다: Google 의존과 기기 토큰·릴레이 ID 연결이라 D28과 맞지 않는다. 대가: 사용자가 300 s 안에 앱을 열지 않으면 요청이 만료된다. 2026-11-07 답에서 이 항목은 미정이었다(§18).
- 대기 거래 추적(journal 작업자)은 Windows처럼 잠금이 풀린 동안에만 돈다. WorkManager·JobScheduler·상시 전경 서비스를 쓰지 않는다. 잠긴 동안 활동 목록에 `추적 일시 중지(잠김)`를 보인다(D32: 다음 잠금 해제 때 이어 간다).

### 12.2 페어링 입력

- 입력: ① 붙여넣기 ② 인텐트 필터 `wc:` ③ 앱 내 브라우저의 `wc:` 링크 ④ 카메라 QR(Camera2 `ImageReader` `YUV_420_888`의 Y 평면을 `rowStride`대로 복사해 기존 `qr_decode`에 넣음, CameraX·ML Kit 안 씀). 어느 경로든 페어링 화면을 **미리 채우기만** 하고, ②에는 `다른 앱이 열었습니다`를 보인다. 자동 페어링은 없다. 15 s 쿨다운·제안 8개 상한은 그대로다([13]).
- `wc:` 스킴은 소유 검증이 없어 다른 앱도 등록·전송할 수 있다. Verified App Links·Link Mode는 사용자마다 서명 키가 달라 쓸 수 없다.
- `wc:` URI에 pairing symKey가 들어 있으므로 QR 스캐너 화면도 `FLAG_SECURE`다(§9.1).
- 승인 뒤 dApp으로 자동 이동(`redirect.native`)하지 않고 `dApp으로 돌아가세요`만 보인다.

## 13. 빌드와 게이트

- 저장소의 `android/`에 Gradle 프로젝트를 둔다. `scripts/build-android.ps1`(UTF-8 BOM, CRLF)이 빌드한다:
  1. 툴체인 해시 확인(§4.4).
  2. `cargo build --locked --release --target aarch64-linux-android -p yw-android`. NDK 링커·`CC_<타깃>`·`AR_<타깃>`은 이 스크립트가 설정한다. `CARGO_TARGET_DIR`·`TMP`는 `#`이 없는 경로로 둔다(NDK `.cmd` 래퍼, §16 P0-2). 빌드 PC 경로 지우기도 이 빌드의 일부다: 스크립트가 `--remap-path-prefix`(작업 폴더 → `yw`, cargo 홈·rustup 홈 → 중립 이름)를 `cargo --config "target.aarch64-linux-android.rustflags=[…]"`로 넘긴다. 경로는 PC마다 다르므로 `.cargo/config.toml`에 고정하지 않는다. `RUSTFLAGS`·`CARGO_ENCODED_RUSTFLAGS`·`CARGO_TARGET_*_RUSTFLAGS` 환경 변수는 쓰지 않고, 설정되어 있으면 멈춘다(`RUSTFLAGS`는 `.cargo/config.toml`의 `[target.*-linux-android]` rustflags를 통째로 대신해 serial cfg가 빠진다). `--config`의 배열은 설정 파일의 배열과 합쳐지므로 serial cfg는 남는다. 이것은 P0-4에서 `cargo build -vv` 출력의 `curve25519_dalek_backend="serial"`로 확인한다.
  3. `.so` 검사: `libyw.so`의 LOAD 정렬 2**14(`llvm-readelf -Wl`, 아니면 링커 인자 `-Wl,-z,max-page-size=16384`를 더해 다시 빌드), `%USERPROFILE%`·작업 폴더·cargo 홈 경로 문자열이 없음(있으면 실패).
  4. Gradle(`--no-daemon`, 검증 메타데이터 강제)이 서명 전 APK를 만든다. Gradle은 cargo를 부르지 않는다(Rust용 Gradle 플러그인 금지). `libyw.so`는 소스 트리에 복사하지 않는다: Gradle `sourceSets.main.jniLibs.srcDirs`를 빌드 폴더(`android/app/build/rustJniLibs`)로 둔다. (2026-11-17: 초안은 `jniLibs/arm64-v8a`에 복사했다. 소스 트리에 바이너리가 생겨 D1·AGENTS.md 규칙 6과 충돌한다.)
  5. `zipalign -P 16 -f`로 APK를 정렬하고 `zipalign -c -P 16`으로 확인한다.
  6. `apksigner`로 사용자 키 서명(§14.1). 서명은 정렬 뒤에만 한다(서명 뒤 정렬하면 서명이 깨진다).
  - (2026-11-17 검토: 초안은 경로 지우기를 `cargo build` 뒤 단계로, `zipalign`을 APK를 만드는 Gradle 앞 단계로 적었다.)
- `check.ps1`의 `RUSTFLAGS` 거부·링커 규칙과 섞지 않는다. `install.ps1`은 Android를 빌드하지 않는다. 그 무결성 레이블 검사는 `crates\`만 보며 `android\`는 그 밖이다(설치기가 Android를 빌드하게 되면 다시 정한다).
- **무시 규칙**: `android/`를 만드는 커밋(A2)에서 `.gitignore`에 `*.so`, `*.apk`, `*.aab`, `*.idsig`, `android/**/build/`, `android/.gradle/`, `gradle-wrapper.jar`, `verification-keyring.gpg`(§4.3), `local.properties`를 더한다. `local.properties`에는 `sdk.dir`로 `<user>` 경로가 들어가므로, privacy-scan이 `.properties`를 보게 되면 무시하지 않은 파일이 게이트를 깬다.
- **Windows 게이트**: `scripts/check.ps1`은 Windows에서 `--workspace`로 clippy·test·fuzz·build를 돈다. `yw-android`는 거기서 빈 크레이트로 컴파일된다(본문은 모두 `#![cfg(target_os = "android")]`). `check-core-deps.mjs`에 `yw-android` POLICY 항목이 있어야 deps 단계가 실패하지 않는다(§4.1).
- **`android` 단계**(종료 코드 31): `build-android.ps1 -Check`를 부른다 — `cargo clippy --target aarch64-linux-android -p yw-android -- -D warnings`, `check-core-deps.mjs`의 Android 표, `check-android-deps.mjs`(§4.2), Gradle `assembleDebug` + JVM 단위 시험. SDK·NDK·JDK가 없거나 `-Offline`인데 Gradle 캐시가 없으면 `android: skipped (<이유>)`를 출력하고 넘어간다. 기기 시험(계측 시험)은 게이트에 넣지 않는다.
  - 건너뛰기의 한계: Windows에서 `yw-android`는 빈 크레이트라, 건너뛰면 두 번째 `unsafe` 크레이트의 코드(`// SAFETY:`, clippy `-D warnings`)와 Android 의존 표를 아무것도 검사하지 않는다. 그래서:
    - rustup 타깃 `aarch64-linux-android`와 NDK(`secp256k1-sys`의 C 빌드에 필요)가 있으면 JDK·SDK가 없어도 clippy와 `check-core-deps.mjs`의 Android 표는 건너뛰지 않는다. 건너뛰는 것은 Gradle 부분뿐이다.
    - `check.ps1 -RequireAndroid` 또는 `YW_CHECK_ANDROID=1`이면 건너뛰기가 실패(31)가 된다(yw-host 시험의 `YW_CHECK=1`과 같은 방식).
    - `yw-android`에 본문이 생기는 A2부터는 `yw-android`·`yw-engine`·`android/`를 바꾸는 커밋 전 게이트를 `-RequireAndroid`로 돌린다. 그 커밋에서 AGENTS.md §2에 이를 적는다.
  - (2026-11-17 검토: 초안은 도구가 없으면 늘 건너뛰었다. 지금 주인 PC에는 JDK가 없다.)
- **브리지 감사**: 브리지 스크립트(§7.2)는 `extension/src` 밖의 새 JavaScript라 지금 `scripts/audit-extension.mjs`가 보지 않는다. 감사 대상 목록에 넣는다. `provider-main.js`는 빌드 때 `extension/src`에서 복사하며 두 벌을 커밋하지 않는다.
- `.gitattributes`에 `*.java *.xml *.kts *.pro *.properties *.keys` LF를 더하고, `scripts/privacy-scan.mjs`의 확장자 목록에 `.java .xml .kts .pro .properties .keys`를 더한다(`.keys`는 §4.3의 키링).
- 에뮬레이터용 `x86_64-linux-android` 빌드는 CheckJNI로 JNI 함수표 인덱스를 확인할 때만 쓴다.
- 재현성(선택): 같은 소스를 두 번 빌드해 서명 전 APK·`.so` 해시를 비교한다. 서명된 APK는 사용자마다 다른 것이 정상이다.
- 기기 시험은 연결된 시험 기기에서 `adb`로 하고, 시험 데이터는 공개 시험 니모닉과 가짜 값만 쓴다.

## 14. 설치와 업데이트 (D1)

### 14.1 경로

- 사용자 PC에서 소스 빌드 → 사용자가 만든 키로 서명(`apksigner`, APK 서명 v2+v3) → `adb install -r`. 업데이트도 같은 키로 같은 경로다. Google 개발자 인증 규칙에서 ADB 설치는 예외이지만 영구 보장은 아니다.
- 설치 대상 사용자를 정한다: 스크립트가 `pm list users`를 보이고 개인 프로필(`--user 0` 등)에만 설치한다. 관리 정책 아래의 작업 프로필에는 설치하지 않는다.
- 업데이트마다 수동 체크리스트([09])를 Android판에도 돈다.

### 14.2 서명 키

- 서명 키가 업데이트의 신뢰 루트다(Windows의 '소스 커밋 + `Cargo.lock`'과 같은 자리). 키스토어 파일은 저장소와 지갑 데이터 밖의 별도 폴더에 두고 따로 백업한다.
- 잃으면 업데이트할 수 없다: 지우고 다시 설치해야 하며 그때 vault가 지워진다(§5.2). 복구 단어·키 백업이 없으면 자금을 잃는다.
- 유출되고 공격자가 ADB나 기기를 손에 넣으면, vault를 물려받는 악성 업데이트로 비밀번호를 가로챌 수 있다. 그래서 설치·업데이트가 끝나면 USB 디버깅을 끈다(스크립트 마지막 단계에서 확인받는다, §2.3).

### 14.3 플랫폼 설정과의 충돌

- **Samsung Auto Blocker**(One UI 6.1.1+ 출시 기기에서 기본 켬): 사이드로드와 USB 명령을 막는다. 설치·업데이트 직전에 끄고 끝나면 다시 켠다(§16 P0-19).
- **Play Protect**: 끄지 않는다(다른 악성 앱 방어). 개발자 옵션 `USB를 통해 설치된 앱 확인`과 `유해 앱 감지 개선`이 켜져 있으면 자가 빌드 지갑 APK 정보가 Google로 갈 수 있으므로(D28) 설치 전에 확인하고, `코드 수준 검사` 권유는 거절한다(§16 P0-20).
- **Advanced Protection**(Android 16+): 출처를 알 수 없는 앱의 설치·업데이트를 막는다(공식 문서). 비도구 접근성 서비스도 막는다는 것은 2차 자료뿐이고 타당성 검토는 그 차단을 Android 17(API 37)에 둔다(미확인). 맞다면 접근성 악성코드에 대한 가장 강한 방어다(§8.3). 둘이 서로 당기며, ADB 설치도 막는지와 접근성 서비스 차단이 어느 API부터인지는 확인 전이다(§16 P0-18).

## 15. 기존 결정과의 관계

Android판에서는 이 표가 표에 적은 모든 결정보다 우선한다(`spec.md` D40). 표에 없는 결정은 Android에서도 그대로다. 크레이트 분리(§11)는 Android판만이 아니라 작업 공간 전체를 바꾸므로 D4·D5 자체를 고친다(`spec.md` D4·D5의 2026-11-17 줄). (2026-11-17 검토: 초안 D40은 D4·D5·D11·D12만 예외로 적었고 D1을 "그대로"로 적었다.)

| 결정 | Android판 |
|---|---|
| D1 대상 환경·소스 배포·설치 | 소스만 배포는 그대로. 대상은 Android 10(API 29)+ `arm64-v8a`(§1). 설치는 `install.cmd`가 아니라 사용자 PC 빌드 → **사용자 키로 APK 서명(필수, D1의 "코드 서명은 하지 않는다"의 예외)** → `adb install`이며, 그 서명 키가 업데이트 신뢰 루트다(§13–§14) |
| D3·D22–D24 확장·native messaging·파이프 | 없음. 앱 내 브라우저(§7), `:browser` → 주 프로세스는 내보내지 않은 바운드 서비스(§7.4, §18 Q1 조건). 호환 모드는 확장 팝업 대신 브라우저 설정(§7.2). router 한도·D23 기한은 yw-engine 문서 라우터(§7.6). localhost 토글은 D22와 같은 두 호스트만(§7.1) |
| D4 `unsafe`는 yw-win만 | `yw-android`도 같은 규칙(파일마다 `#![allow(unsafe_code)]`, 블록마다 `// SAFETY:`). AGENTS.md §6의 "`unsafe` only in yw-win"은 `yw-android`를 만드는 커밋에서 고친다 |
| D5 의존성 허용 목록 | 타깃별 표. Android 표에 `libc 0.2.189`(+ `build.rs`). `qrcodegen`은 yw-engine(§4.1). Android 빌드 도구는 Gradle·AGP, 런타임은 `androidx.webkit`과 확인한 전이 닫힘(§4) |
| D7·D10 vault·메모리 | 형식·매개변수 그대로. 기기 키로 한 번 더 감쌈(§5.2). 지문 잠금 해제를 켜면 DEK를 비밀번호가 아닌 지문 키로도 감싼 `bio.ywb`가 생겨 그 기기에서만 의미가 바뀐다(§6.1–§6.2) |
| D11 비밀 창·복사 | `FLAG_SECURE`·빈 assist 구조·앱 키보드(§9). 비밀 복사 없음(§9.3), 복구 단어·개인키 붙여넣기 없음(§9.4) |
| D12 자동 잠금 | 화면 꺼짐 즉시, 백그라운드(앱 단위, §5.4) 설정 시간(기본 1분) 뒤 잠금 추가 |
| D13 API 키 저장 | DPAPI 대신 Keystore 감쌈 `apikeys.ks`(§5.2) |
| D28 로그·외부 전송·패닉 | logcat 없음, Java 예외 문구·스택 안 씀(§3.3), 패닉 훅은 슬롯을 지운 뒤 `abort` 대신 `_exit`(§5.3, tombstone을 남기지 않으려고), WebView `MetricsOptOut`, Safe Browsing은 켜면 방문 URL의 해시 앞부분을 Google에 보낸다(알리고 끌 수 있음, 기본값 §18 Q5, §7.3), 알림에 값 없음 |
| D33 YubiKey | NFC·USB-C 전송, 한 번 탭 = 한 작업. NFC에서는 터치가 마지막 방어선이라는 주장이 약하고(P0-17 전), 키 가져오기·PIN·관리 키 변경은 USB-C로만(§10) |
| D35 WalletConnect | 앞에 있고 잠금이 풀린 동안만 연결(§12.1). 입력은 붙여넣기에 더해 인텐트 필터 `wc:`·앱 내 브라우저 `wc:` 링크·카메라 QR. 클립보드 비트맵·이미지 파일 QR은 없음(§12.2) |

## 16. P0 스파이크

각 항목은 표의 "필요 시점" 단계를 시작하기 전에 시험 기기와 에뮬레이터에서 확인한다(§17). 결과는 [09]와 이 문서의 해당 절에 날짜와 함께 적는다. "필요 시점"까지 결과가 없으면 그 단계를 시작하지 않는다. 필요 시점이 A2인 항목 중 하나라도 실패하면 §18로 돌아가 다시 정하고, 다른 항목이 실패하면 그 단계 전에 해당 절을 다시 정한다. (2026-11-17 검토: 초안은 모든 항목을 "A2 전에"라고 적었으나 표의 필요 시점은 A5–A7·설치 안내 전까지 있다.) 실제 YubiKey·다른 기기가 필요한 항목은 주인이 한다(AGENTS.md 규칙 3).

| 번호 | 확인할 것 | 필요 시점 | 하는 사람 |
|---|---|---|---|
| P0-1 | Rust `aarch64-linux-android` 타깃 설치 뒤 yw-core를 임시 cdylib로 빌드하고 `JNI_OnLoad` + `selfTest()`로 기존 KAT(BIP39/32, SLIP-10, secp256k1, Ed25519, XChaCha20-Poly1305)를 시험 기기와 x86_64 에뮬레이터(CheckJNI)에서 실행 | A2 | 에이전트 |
| P0-2 | `secp256k1-sys`의 C 빌드가 NDK clang에서 경고·오류 없이 되는지, NDK `.cmd` 래퍼가 저장소 경로의 `#`에 걸리는지 | A2 | 에이전트 |
| P0-3 | 시험 기기에서 Argon2 `KDF_V3` 1회 시간과 최대 메모리. 통과: lmkd 종료 없음, 10 s 이내(§5.3) | A2 | 에이전트 |
| P0-4 | `libyw.so` 크기, 16 KB 페이지 정렬(`llvm-readelf -Wl`, `zipalign -c -P 16`), `--config`로 넘긴 `--remap-path-prefix` 뒤 `.so`에 빌드 PC 경로가 없음, 그 빌드에 serial cfg(`curve25519_dalek_backend="serial"`)가 그대로 있음(`cargo build -vv`, §13) | A2 | 에이전트 |
| P0-5 | `check-core-deps.mjs` 타깃별 표로 aarch64·x86_64 Android 그래프 검사: `libc 0.2.189` + `build.rs`만 새로 나오는지(§4.1) | A2 | 에이전트 |
| P0-6 | 툴체인 출처: NDK·JDK·Gradle 공식 zip을 새로 받아 공개 체크섬과 대조하고 SHA-256 기록. 전부터 있던 NDK는 쓰지 않음(§4.4) | A2 | 에이전트(설치 승인은 주인) |
| P0-7 | `androidx.webkit` 고정 버전의 Gradle `releaseRuntimeClasspath` 실제 닫힘(`kotlin-stdlib` 등이 들어오는지)과 `verification-metadata`(`pgp,sha256`) 오프라인 빌드. 결과로 `android/runtime-deps.txt`를 만든다(§4.2) | A2 | 에이전트 |
| P0-8 | APK 빌드 → 사용자 키 서명 → `adb install` 성공. 어느 사용자·프로필(작업 프로필, Private Space)에 설치되는지 `pm list users`로 확인(§14.1) | A2 | 에이전트 |
| P0-9 | 시험 기기 WebView에서 `DOCUMENT_START_SCRIPT`·`WEB_MESSAGE_LISTENER` 지원, iframe에 문서 시작 스크립트가 들어가는지, 렌더러가 별도 프로세스인지, `:browser` 프로세스 + `setDataDirectorySuffix` 동작, `JavaScriptReplyProxy`가 문서마다 새로 생기는지, `allowedOriginRules`의 `https://*`·localhost 규칙이 뜻한 출처·포트를 덮는지(§7.2), `:browser` Activity만 앞에 있을 때 주 프로세스가 승인 Activity를 띄울 수 있는지(Android 10+ 백그라운드 Activity 시작 규칙, §7.4), 바인더 한도보다 큰 메시지의 전달(§7.6), Activity 사이 이동이 §5.4의 백그라운드로 잡히지 않는지(§7.4–§7.6) | A2 | 에이전트 |
| P0-10 | Keystore AES-256-GCM 기기 키로 파일마다 감싸고 풀 때의 지연(TEE 대 StrongBox), 키 생성 실패, 화면 잠금 변경 뒤 키 유지, `setUnlockedDeviceRequired`와 화면 꺼짐 직후 쓰기의 경합(§5.2) | A2 | 에이전트 |
| P0-11 | API 29에서 `CryptoObject`를 붙인 `BiometricPrompt`가 Class 3 생체 인식만 받는지, 기기 자격 증명 경로가 없는지, 지문 등록 변경 시 키 무효(§6.1) | A5 | 에이전트 |
| P0-12 | `adb shell input swipe x y x y 2000`이 arm 지연 뒤 2초 누르기를 통과하는지(통과가 예상됨)와 지문 승인으로 막히는지(§2.2, §6.4) | A5 | 에이전트 |
| P0-13 | 시험용 접근성 서비스의 `TYPE_ACCESSIBILITY_OVERLAY`가 승인 화면 위에서 `setHideOverlayWindows`로 숨겨지는지, `FLAG_WINDOW_IS_(PARTIALLY_)OBSCURED`가 생기는지(API 31+ 기기 필요, §2.2) | A5 | 주인(기기) |
| P0-14 | 사이드로드한 접근성 서비스가 `isAccessibilityTool`을 거짓 선언해 `accessibilityDataSensitive`를 피할 수 있는지(API 34+ 기기 필요, §8.3) | A5 | 주인(기기) |
| P0-15 | `FLAG_SECURE`·빈 assist 구조로 화면 AI 질문·Circle to Search·최근 앱·화면 공유가 비밀 화면을 가져가지 못하는지(§9.1) | A5 | 주인(기기) |
| P0-16 | 자체 QR 디코더(`qr_decode`)가 Camera2 프레임(흐림·원근·반사·저대비)에서 동작하는지(§12.2) | A7 | 에이전트 |
| P0-17 | NFC `IsoDep` APDU 왕복(`getMaxTransceiveLength` ≥ 261)과 터치 정책 `always`가 한 필드 세션에서 서명마다 새 터치를 요구하는지(§10) | A6 | 주인(실제 카드) |
| P0-18 | Advanced Protection을 켠 상태에서 ADB 설치·업데이트가 막히는지(Android 16 기기 필요), 비도구 접근성 서비스를 막는지와 어느 API부터인지(타당성 검토: API 37, 2차 자료, §8.3·§14.3) | 설치 안내 전 | 주인(기기) |
| P0-19 | Samsung Auto Blocker가 `adb install`·업데이트를 막는지와 끄고 켜는 절차(Galaxy 기기 필요, §14.3) | 설치 안내 전 | 주인(기기) |
| P0-20 | Play Protect가 자가 빌드 APK의 `adb install`을 검사·업로드·경고·차단하는지(§14.3) | 설치 안내 전 | 에이전트(시험 기기) |

- (2026-11-17: 초안에는 스파이크 단계가 없었다. 타당성 검토 §7 P0를 이어받고 이 문서의 선택(앱 내 브라우저, 기기 키, Gradle)으로 생긴 확인을 더했다.)

## 17. 단계

| 단계 | 내용 | 끝났다는 기준 |
|---|---|---|
| A0 | 이 문서 확정, `spec.md` D40, 타당성 검토와 대조(2026-11-17) | 주인 승인(2026-11-17, 끝남) |
| A1 | 공유 크레이트 분리 S1–S5(§11.4). Windows판 동작은 바뀌지 않는다. P0와 나란히 해도 된다 | 단계마다 게이트 통과, 스크린숏 투어 차이 없음 |
| P0 | 스파이크(§16) 중 필요 시점이 A2인 항목 | 결과 기록, 실패 없음(실패하면 §18로) |
| A2 | Android 뼈대: `yw-android`·`android/`, `build-android.ps1`·의존성 검사·게이트 `android` 단계·무시 규칙(§13), 기기 키(§5.2), 패닉 훅·Java 예외 처리기(§3.3, §5.3), 보호 등급·디버깅 띠(§1.1, §8.2), 비밀 화면 창(§9.1)과 앱 키보드(§9.2, `secretKey`·`secretFill` §3.2)를 비밀번호·복구 단어 화면(W01·W02·W05·W06·W08·W10)에, vault 만들기·잠금 해제, EVM 계정 보기 | 시험 기기에서 실행 |
| A3 | 승인 화면(§8.1, §8.4–§8.5)·나머지 비밀 화면(§9.1)·서명·RPC(§12): EVM·Solana·Bitcoin·Zcash·HyperCore 보내기 | 체인별 시험넷 체크리스트(주인) |
| A4 | 앱 내 브라우저(§7, `:browser` 프로세스는 §18 Q1 조건, 문서 수명, 한도·기한 §7.6) | test-dapp 시나리오 통과(§7.6의 한도·기한 포함) |
| A5 | 생체 인식(§6), 붙여넣기 규칙(§9.3–§9.4), 탭재킹·접근성(§8.2–§8.3) | P0-11–P0-15, 체크리스트 |

- **A5가 끝나기 전 빌드는 시험용이다**: 탭재킹·접근성 방어(§8.2–§8.3)가 없으므로 공개 시험 니모닉과 시험넷만 쓰고 실자금을 넣지 않는다. 앱은 A5 전 빌드에서 모든 화면에 §1.1의 '시험용' 띠를 보인다. (2026-11-17 검토: 초안은 비밀 화면 보호를 A3, 앱 키보드를 A5에 두어 A2–A4가 시스템 키보드·`FLAG_SECURE` 없이 비밀번호·복구 단어를 다뤘다.)
| A6 | YubiKey NFC·USB(§10) | mock 시험, P0-17, 실제 카드 체크리스트(주인) |
| A7 | WalletConnect(§12.1–§12.2), 설정 전체, AI 설명, 영어, 스크린숏 투어, 설치 안내(§14), Android 수동 체크리스트([09]) | 기능 표 대조, P0-16·P0-18–P0-20 |

## 18. 열린 질문

주인이 정할 것. 정하면 이 절에서 지우고 해당 절에 날짜와 함께 적는다.

1. **`:browser` 별도 프로세스**(§7.4): 복잡도(프로세스 둘, 바운드 서비스 중계)를 받아들이고 WebView 브라우저 쪽 코드를 DEK가 있는 프로세스 밖에 둘지. 얻는 것은 주 프로세스 메모리(DEK)의 분리뿐이다(파일·Keystore 키는 같은 UID라 공유, §7.4). §2.2·§3.1·§15·§17 A4의 `:browser`는 이 답에 달려 있다.
2. **WalletConnect 푸시**(§12.1): 2026-11-07 답에서 미정. 이 문서는 쓰지 않는 쪽(요청은 300 s 안에 앱을 열어야 받음)으로 적었다.
3. **Solana Mobile Wallet Adapter**(§1): 2026-11-07 답에서 미정. 지금은 범위 밖.
4. **좁은 화면 `seen_all`을 Windows에도**(§8.5): 켜면 [04] §3.4를 고친다.
5. **Safe Browsing 기본값**(§7.3): 켬(Play 서비스가 있으면 일부 피싱 차단, URL 해시 앞부분 전송) 또는 끔.
6. **'폰에 시드 없음' YubiKey 전용 계정**(§10): 후속으로 만들지.
7. **Advanced Protection 권장 구성**(§14.3): P0-18 결과 뒤, 설치·업데이트 때마다 껐다 켜는 절차를 받아들이고 권장할지.
