# 보안 검토 — 2026-11-01 (HEAD `5a1ef9e`)

개인용 소프트웨어 지갑의 현재 코드를 위협 모델 `spec.md` §2 기준으로 검토했다. **자금을 빼앗는 결함은
찾지 못했다.** 중심 보증 — 승인 창의 표시는 코어가 payload에서 직접 만든 값이고, 서명 바이트와 표시의 출처가
같으며, 승인 digest가 id·origin·체인·genesis·계정·payload 원 바이트·표시 digest·시뮬레이션 상태·만료를 모두
결속하고, 승인 없이는 서명이 나가지 않으며, vault의 KDF·AEAD·AAD가 고정되어 있다 — 은 추적한 범위에서
실제로 성립했다. 발견한 것은 **MEDIUM 4, LOW 17, INFO 11**과, 스펙이 약속한 문장과 코드가 어긋나는 **편차 19건**이다.

- 검토 기준: `spec.md` §2.1(방어 대상)·§2.2(비목표)·D-table, 각 `spec/0x` 장, "코어가 만든 표시만 근거로 한다"는
  중심 주장, 그리고 스펙이 차단(blocked)으로 규정한 규칙들
- 범위: 6개 영역 병렬 — 브라우저 브리지·확장, 정책/디스패치/파라미터/grant, vault/KDF/키 파생/RNG/메모리,
  서명/디코드/승인 표시, 디스크/승인 창 무결성/네트워크, 공급망·설치 프로그램. 저장소의 대부분을 덮었다
- 실행 검증(모두 통과): `cargo test -p yw-core`(280 lib + 통합), `cargo test -p yw-app --test browser_dispatch
  --test browser_chain_dispatch --test browser_params --test browser_envelope`(49), `--test approval_interaction`(37),
  `cargo test -p yw-win --lib http::`(7), `node extension/tests/{shared,content,provider-main,manifest}.test.mjs`,
  의존성 허용 목록 게이트, 확장 정적 감사. PoC 6종은 `target/tmp/`에만 있고 저장소는 무변경
  (변경은 이 문서 하나, `git status`로 확인)
- 심각도: **CRITICAL** 지금 자금 탈취 · **HIGH** 조건만 맞으면 탈취 · **MEDIUM** 사용자가 검토했다고 믿는 것과
  실제 승인 대상이 어긋나거나, 보증·차단 규칙이 깨지거나, 전면 DoS · **LOW** 좁은 조건의 위반·안전장치 약화 ·
  **INFO** 설계상 수용했거나 악용 경로가 없음

비목표(§2.2)는 비목표로 두었다. "같은 Windows 사용자 권한의 악성코드"가 전제인 항목에는 그 사실을 적었다.

---

## 1. 발견 사항

### 1.1 MEDIUM

#### M1. 평문 `settings.json`만 고쳐도 승인 창의 데이터가 공격자 호스트로 조용히 흘러간다 — LLM 엔드포인트 동의가 파일을 따라오지 않는다

- 위치: `crates/yw-app/src/settings.rs:597-601`(로더는 `enabled`와 `endpoint`를 서로 대조하지 않는다),
  `crates/yw-app/src/explain/config.rs:123-128`(`effectively_enabled`는 `privacy_notice_version >= 1`만 본다),
  `crates/yw-app/src/app.rs:611-619`(기동 시 `llm:host` 없는 키를 현재 endpoint 호스트에 **자동 바인딩**),
  대조: `crates/yw-app/src/app_llm.rs:395-398`(UI 저장 경로에서만 `enabled = false`)
- 분류: CWE-345 / CWE-494. 규격: spec/06 §2.1 "엔드포인트를 바꾸면 `enabled=false`로 되돌린다"
- 영향: `settings.json`을 평문 편집(또는 오래된 백업 복원, 도난 후 반납, 동기화 폴더)하는 것만으로 다음
  실행부터 승인 창마다 **서명 계정 주소·사이트 origin·받는 주소·금액·시뮬레이션 결과·personal_sign/SIWE
  문장·EIP-712 필드**가 공격자 HTTPS 호스트로 전송된다. `privacy_notice_version`도 평문이라 1로 위조하면
  동의 화면을 다시 볼 수 없고 `banners=[]`이라 표시가 없다. 구버전이 남긴 호스트 미바인딩 키는 새 호스트에
  자동으로 붙어 그대로 전송된다. 서명 대상은 안전하나(§2.2: AI 텍스트는 승인 근거가 아님) 승인 내용 전체가 노출된다.
- 근거(실측): `target/tmp/poc-E-urls.rs`가 실제 `settings::load`에 원본/변조 바이트를 넣어
  `original: enabled=true … banners=[]` → `tampered: enabled=true endpoint=https://attacker.example/… notice=1
  effectively_enabled=true banners=[]`를 확인.
- 수정 제안: `load_llm` 끝에서 파싱한 호스트를 "동의 시점 호스트"로 저장해 두고(`privacy_notice_host` 새 키)
  다르면 `enabled=false` + E-APP-001 배너. `llm:host` 유무와 무관하게 호스트가 바뀌면 키를 보류로 취급.
- 신뢰도: 확실(코드 3곳 + PoC).

#### M2. EVM 지갑 보내기 `검토`가 500 ms 디바운스 **이전** 검증값(이전 받는 주소·금액)으로 승인 창을 만든다

- 위치: `crates/yw-app/src/app_evm_commands.rs:26-34`(EN_CHANGE는 텍스트와 `dirty_ms`만 갱신), `:101-105`
  (`SEND_REVIEW`는 `edit_text`로 텍스트만 옮기고 `validate_send`를 **호출하지 않는다**),
  `crates/yw-app/src/app_evm.rs:50`(`SEND_DEBOUNCE_MS = 500`), `:1136-1141`(500 ms 뒤에야 `validate_send(true)`),
  `:1394-1415`(`can_review`는 `dirty_ms`를 보지 않는다), `:1190-1211`(`intent()`는 마지막 검증 산출물
  `form.recipient`·`form.amount` 사용)
- 분류: CWE-367 (TOCTOU)
- 영향: 받는 주소 A·1 ETH 상태에서 주소를 B로 붙여넣고 곧바로 `검토`를 누르면(붙여넣기→클릭은 전형적으로 500 ms
  안이다) 10 ETH가 아니라 **이전 값 1 ETH·이전 주소 A**로 승인 창이 뜬다. 창과 서명 바이트는 일치하므로
  표시/서명 불일치는 아니지만, **방금 입력한 값이 조용히 무시된다.** 폼은 창 뒤에 가려지고 알려 주는 문구가 없으며,
  `주소 전체를 직접 확인했습니다` 체크 상태까지 이전 주소 기준으로 승계된다. SOL은 같은 상황에서 "입력이 바뀌어
  다시 확인했습니다"로 거부하고 `crates/yw-app/src/app_sol.rs:1098-1104`에서 재검증하며, BTC도 재동기한다 —
  EVM 지갑 보내기 경로에만 그 규칙이 없다(spec/07 §13.1-1의 대응물 부재).
- 근거: 위 경로 전부 추적(폼 상태 → `intent()` → `ApprovalDraft`). `SEND_REVIEW` 처리에서 `validate_send` 호출 0회.
- 수정 제안: `SEND_REVIEW`에서 RPC 없는 동기 재검증을 먼저 수행하고, 결과가 화면 값과 다르면 SOL처럼 승인을 열지
  않는다. 최소 변경은 `can_review`에 `dirty_ms.is_none()`을 넣어 디바운스 중 `검토`를 비활성화.
- 신뢰도: 확실.

#### M3. 인식된 typed-data 스키마에서 표시 한도 초과(T16 차단)가 사라지고, 1,024필드를 넘으면 차단 창 대신 내부 오류가 된다

- 위치: `crates/yw-core/src/evm/display/mod.rs:1374-1385`(인식 스키마 분기에서 `scan.exceeded`를 **버리고**
  `scan.hidden`만 합친다), `:1386`(`exceeded`는 `tree.exceeded || domain_exceeded`뿐 — `tree`는 걸은 적이 없다),
  `:1398-1400`(T16 push), `crates/yw-core/src/approval/display.rs:280-282`(`TooMany`),
  `crates/yw-app/src/flow/evm/prepare.rs:767-772`(→ `Ui001` 실패 창)
- 분류: CWE-1023
- 영향: spec/03 §8.4는 트리 표시 한도(깊이 8·리프 512·문자열/bytes 1024) 초과 시 **T16 차단**을 요구하고 T16은
  §10.4의 차단 규칙 8개 중 하나다. 인식 스키마(Permit2 PermitBatch, Seaport OrderComponents 등)는 필드 표시를
  `structured_fields`로 하지만 한도 계산용 트리 워크의 `exceeded`가 반영되지 않아 **한도를 넘은 요청이 차단 없이
  승인 가능**하다. 더 큰 입력은 필드 상한(1,024)에 먼저 걸려 `DisplayError::TooMany` → 초안 생성 실패 →
  내부 오류(`E-APP-009`/E-UI-001) 창이 된다. 즉 같은 초과가 "통과 / 내부 오류"로 갈리고, 중간 구간(리프 512 초과·
  필드 1,024 이하)은 아예 통과한다. 차단 규칙이 존재하는 이유(사용자가 다 검토할 수 없는 크기)가 무력화된다.
- 근거(실측, `target/tmp/poc-D-sign.exe`): PermitBatch 200 details(리프 800) → `built, fields=807, T16=false`;
  258 details(필드 1,032) → `Err(TooMany)`; 대조군 **미인식** 스키마 600 리프 → `fields=517 T16=true risk=Blocked`.
- 수정 제안: 인식 스키마 분기에서도 `scan.exceeded`를 `exceeded`에 합치고, `structured_fields`가 만드는 필드 수도
  같은 카운터에 넣어 필드 상한 도달 시 `TooMany` 실패가 아니라 T16 차단 요청이 되게 한다.
- 신뢰도: 확실.

#### M4. 페이지(또는 다른 확장) 스크립트가 채널을 선점하면 지갑 provider가 문서 수명 동안 조용히 무력화된다

- 위치: `extension/src/provider-main.js:1436`(`channel === null`일 때만 `bridge-init` 수용),
  `extension/src/content.js:40-48` + `extension/src/content-core.js:68-75,87`(content는 `chrome.storage.local.get`
  완료 **뒤에야** `bridge-init`을 보낸다), 폐기 지점 `extension/src/shared.js:265`
- 분류: CWE-362 / CWE-696
- 영향: `document_start` 직후 페이지 스크립트(또는 같은 창에 주입되는 다른 확장의 MAIN-world 스크립트)가 자기
  채널 값으로 `bridge-init`을 postMessage하면 provider가 그 값을 채널로 확정한다. 뒤늦게 온 진짜 `bridge-init`은
  `channel !== null`이라 버려지고, 이후 모든 요청이 공격자 채널로 나가 content의 채널 대조에서 폐기된다.
  요청은 앱에 도달하지 않고 provider는 요청당 `REQUEST_TIMEOUT_MS = 605 s`(`provider-main.js:11`) 동안 매달린 뒤
  -32603으로 실패하며 pending 64개가 차면 -32005가 된다. `isConnected()`는 true이고 EIP-6963 등록도 정상이라
  dApp은 "연결됨"으로 본다. 채널을 잡은 뒤 `{kind:"disconnect"}`를 보내면 `enterDead()`로 복구도 불가능하다.
  자금 위험은 없고 가용성·UX 손실이나 공격은 스크립트 한 줄로 결정적으로 성공한다. spec/05 §2.5가 "채널이 없을 때
  받아들인다"만 정하고 **누가 보낼 수 있는지**를 정하지 않은 공백이 원인이다.
- 근거(실측): `node target/tmp/poc-A-1-bridge-init-lockout.mjs`(실제 모듈 로드, spawn 없음) →
  `provider accepted a page-forged bridge-init; isConnected() = true` · `request channel: eeeeeeee…` ·
  `shared.parsePageMessage(request, contentChannel) => null` · `content port messages: 0`.
- 수정 제안: `bridge-init`을 받았는데 채널이 이미 있고 `pending.size === 0`이면 새 채널로 갈아타되 확정한 모드는
  유지(스펙 조건부 수정 + 테스트 P6 갱신). 또는 content가 storage 읽기 전에 동기 `bridge-init`을 먼저 보낸다.
- 신뢰도: 확실.

### 1.2 LOW

#### L1. 비밀번호 변경이 DEK를 회전하지 않는다 — 이전 vault 사본 + 나중에 알려진 옛 비밀번호가 이후 세대를 연다

- 위치: `crates/yw-core/src/vault/session.rs:1164`(DEK 재사용; 새 값은 `kdf_salt`·`wrap_nonce`·`payload_nonce`뿐),
  spec/02:375("DEK 유지")
- 분류: CWE-522. 영향: 사용자가 만든 `vault.ywv` 사본, 갱신 전 `.prev`, `vault.ywv.corrupt-*`, 이전 백업이 모두
  **옛 비밀번호로 계속 열린다.** 그 사본에서 풀린 DEK가 현재 파일과 같으므로 사본과 옛 비밀번호를 함께 얻은
  공격자는 최신 파일까지 복호화한다. "비밀번호가 샜으니 바꿨다"가 유출된 사본에 대해 회수를 만들지 못한다.
- 근거(실측): `target/tmp/poc-C-dek` — 사본 보관 → A→B 변경 → 현재 파일은 A로 실패(의도), **사본은 A로 열리고
  `reveal_mnemonic` 성공**, `vault_id` 불변.
- 수정: (i) 최소 — `docs/recovery-guide.ko.md`와 비밀번호 변경 화면에 명시. (ii) 변경 시 DEK 회전 + payload 1회 재작성.
- 신뢰도: 확실. §2.2: 디스크·백업 도난은 범위 안.

#### L2. 승인 잔액 조회 집합과 승인 위험 판정 집합이 달라, 시뮬레이션 로그에만 있는 승인은 E14 "잔액보다 큰 승인"이 불가능

- 위치: `crates/yw-app/src/flow/evm/prepare.rs:431-449`(잔액 `balanceOf`는 `calldata_approvals`만 순회),
  `:344-347`(diff 승인은 조회 목록에만 추가), `crates/yw-core/src/evm/risk/mod.rs:231-244`(diff가 있으면
  `approval_intents`는 diff만), `:54-64`(`AboveBalance`는 `facts.balance(token)` 필요)
- 분류: CWE-1023. 영향: 로그에서만 보이는 승인(미해석 calldata가 낸 승인, 라우터가 대신 내는 승인)은 잔액 사실이
  없어 "사실상 무제한" 고위험이 절대 발화하지 않는다. 같은 호출이 해석되는 경우엔 정상 동작한다. 로그 승인에는
  보통 E12(미해석 호출, 고위험)도 붙어 전체 등급은 유지되나 **어떤 승인이 무제한으로 표시되는지**가 갈린다.
- 근거(실측): `poc-D-sign.exe` P2 — `facts`만 바꿔 `E14=false` → `E14=true`.
- 수정: 잔액 조회 대상을 `diff 승인 ∪ calldata 승인`으로 넓힌다(기존 `MAX_FACT_LOOKUPS`/E27 규칙 사용).
- 신뢰도: 확실.

#### L3. `to`가 주소 분류 슬롯을 하나 먹어, 승인 16건이면 마지막 spender가 조용히 미분류된다

- 위치: `crates/yw-app/src/flow/evm/prepare.rs:314-316`(`addresses`를 `vec![decoded.tx.to]`로 시작), `:334-347`,
  `:450-459`(`.take(MAX_FACT_LOOKUPS)`), `crates/yw-core/src/evm/risk/mod.rs:464-477`(`code_of`가 `None`이면
  E16/E21/E39 모두 미발화)
- 분류: CWE-1050. 영향: R5가 multicall 내부 호출을 16개로 제한하므로 `approve` 16건이 정확히 상한인데,
  목록이 `[to, s1..s16]` 17개가 되어 **s16이 잘린다.** 그 승인 행만 "EOA/미등록 컨트랙트/확인 불가" 분류가 빠진다
  (E27은 발화하나 행 단위 표식이 없다). 자금 위험은 없고 리뷰 보조 정보의 결손.
- 수정: `to`를 별도 슬롯으로 두거나 목록 한도를 `1 + MAX_FACT_LOOKUPS`로, 또는 잘림이 있으면 `limited` 강제.
- 신뢰도: 확실.

#### L4. 숨김/삭제된 계정이 열려 있는 창과 grant에 반영되지 않는다 (3건)

- (a) 숨김/삭제된 계정이 **연결 창 승인으로 grant에 들어간다**: `app_browser.rs:900-925`(`connect_approved`에
  재대조 없음), 계정 스냅샷 `app_approval.rs:998,1020,1045`, 숨김 필터 `app.rs:2728`, 숨김 무시 `app_evm.rs:1530`.
  창이 열린 사이 [계정 숨기기]를 하면 숨긴 계정이 grant에 남아 `eth_accounts`에 나오고 계속 서명된다 —
  spec/05 §4.1("숨기면 grant에서 빠진다")이 그 origin에서 무효가 된다. SOL/BTC 연결은 같은 상황을 4100으로
  처리하므로(`app_chain_sites.rs:297,333-337`) EVM만 비대칭이다.
- (b) 숨김/삭제가 **표시 중인 서명 창을 닫지 않는다**: `app_browser.rs:855-860`(`remove_account` + `write_grants`만) vs
  `:774-785,802-827`(`wallet_revokePermissions`는 `revoke_waiting`), `:864-896`(체인 삭제는 drain + 창 종료).
  서명자는 준비 단계에서 캡처되므로(`app_approval.rs:1292-1309`) grant에 없는 계정으로 서명이 완료된다.
- (c) **연결 창의 체인 표시와 저장 값이 어긋난다**: 창은 열릴 때 `chain_name`을 스냅샷하고(`app_approval.rs:1045`)
  승인 시 `core.origin_chain`을 다시 읽어 저장한다(`app_browser.rs:901-907`). 승인 창 없는
  `wallet_switchEthereumChain`(`dispatch.rs:1150-1174`)이 그 사이 체인을 바꾸면 Sepolia를 보여 주는 창에서 mainnet
  grant가 저장된다.
- 분류: CWE-672 / CWE-449. 수정: (a) 승인 시 `own_accounts()` 재검증 후 4100 + 창 유지, (b) `revoke_waiting` +
  창 종료(체인 삭제 경로 복사), (c) 매 렌더 시 `origin_chain` 조회 후 변경 시 재그리기.
- 신뢰도: 확실(코드 + PoC case 3). 본인 계정이라 자금 위험은 낮고 계약·화면 불일치다.

#### L5. 합성 `WM_KEYDOWN(VK_RETURN)`(PostMessage)이 Standard 등급 요청을 승인한다 — Enter만 물리 입력 대조가 없다

- 위치: `crates/yw-app/src/ui/interaction.rs:269-274`(`armed && spaced`만 본다), `app_approval.rs:2382-2384`,
  대조: 포인터 `app_approval.rs:2205-2209,2245-2247`·Space `:2390-2393`는 `is_down`으로 실제 키 상태 확인.
  `crates/yw-win/src/input.rs:18-28`의 `injected()`는 호출자 0곳
- 분류: CWE-345 / CWE-602. 영향: 같은 데스크톱의 아무 프로세스나 `PostMessage(hwnd, WM_KEYDOWN, VK_RETURN, …)`로,
  포커스가 `승인`이고 표시 후 1 s가 지난 시점에 Standard 등급 거래를 승인시킬 수 있다(High는 Enter 무시로 면역).
  승인 내용은 화면과 같으므로 "다른 거래로 서명"이 아니라 "읽지 않은 거래의 서명"이다.
- 수정: Standard도 짧은 Space 홀드로 통일해 물리 검사를 타게 하거나, 수신 메시지의 `lParam` bit 30/31·
  `GetMessageTime` 대조를 붙인다. 신뢰도: 코드 확실, 실제 성립은 추정(같은 데스크톱).

#### L6. origin 형식 검증이 확장 JS와 yw-app에서 서로 다르다 — 수용된 페이지의 모든 요청이 -32600이 된다

- 위치(수용): `extension/src/shared.js:152-167`, 사본 `provider-main.js:1572-1587`;
  (거부) `crates/yw-app/src/browser/envelope.rs:382`, `crates/yw-core/src/policy/mod.rs:72-113`, 거부 사례 `:202,207`
- 분류: CWE-1288. 영향: `https://example.com./…`(절대 FQDN), `https://host:0/…`, 253바이트 호스트 페이지에서
  content는 연결되고 봉투도 가지만 앱이 매 요청 -32600만 돌려준다(승인 창 없음, 페이지는 연결된 것으로 보임).
  spec/05 §2.4 "같은 규칙을 네 곳"의 실제 이탈.
- 근거: `poc-A-2-origin-mismatch.mjs` — 두 문자열 모두 JS 수용/앱 거부 확인.
- 수정: JS에 후행 점·`:0`·256바이트 초과 거부를 추가해 집합을 맞추고 네 곳을 테스트로 고정. 신뢰도: 확실.

#### L7. 설치 프로그램이 "빌드해 온 소스·빌드 폴더"의 ACL은 확인하지 않는다

- 위치: `scripts/install.ps1:1262-1312`(소스 확정), `:1448,1498-1499`(원본 해시 → 복사 → 복사본 해시),
  대조 `:342-353`, `:288-308`, `:801-824`, `:1313-1334`. `Get-AclProblem` 호출처는 344·347·404·818뿐
- 분류: CWE-494 / CWE-829. 영향: 설치 프로그램은 설치 폴더·상위 폴더·cargo/rustup 파일·상위 `.cargo\config.toml`을
  다른 로컬 사용자가 바꿀 수 있는지 검사해 거부하지만, 바이너리가 나오는 **저장소 트리와 `target\release\`는 보지
  않는다.** 다른 사용자가 Modify를 갖는 곳(`C:\dev`·`D:\`·공용 폴더)에 clone했다면 그 사용자가
  `target\release\yw-app.exe`·`extension\src\*.js`를 바꿔 둘 수 있고 다음 설치가 그것을 사설 DACL 폴더에 설치한다.
  해시 비교는 원본/복사본이 같은 출처라 못 막고, 설치 기록에 해시도 없다. `-NoBuild`는 폭을 넓힌다.
  이 PC는 저장소 ACL이 상속 전용 + 신뢰 SID뿐이라 현재는 악용 불가(조건부).
- 수정: 설치 전에 `$root`·`$releaseDir`·`extension\`에 같은 ACL 검사를 적용하고 `-AllowUnsafeSourcePath` 없이는
  종료 1. 또는 설치 기록에 파일 해시를 남겨 다음 실행에서 비교. 신뢰도: 확실.

#### L8. 데이터 폴더 안의 재분석 지점(파일 링크)은 ACL 검사도 거부도 안 되는데, 볼트 읽기 경로는 링크를 따라간다

- 위치: `crates/yw-win/src/security.rs:790-792`(진입점 열거에서 재분석 지점 무검사 `continue`), 읽기
  `crates/yw-app/src/store.rs:123-129`, `yw-win/src/file.rs:232-243`(링크 추종), `file.rs:208-209`는 `atomic_write`만
  거부, 커밋의 폴더 flush 실패 무시 `store.rs:228`, 주석 불일치 `security.rs:751-753`
- 분류: CWE-59. 영향: 세 파일이 다른 위치를 가리키는 링크로 바뀌면 사설 DACL 밖에서 읽히고 flush 실패도 조용하다.
  암호문이라 기밀성 피해는 제한적이나 §2.1 행 4의 폴더 DACL 보장이 그 파일에는 적용되지 않는다.
- 수정: `FileStorage`에서 세 파일에 링크 거부를 적용하거나 대상 ACL 검사 + `flush_dir` 오류 승격. 주석을 맞춘다.
- 신뢰도: 확실.

#### L9. WER 제외 등록 실패가 사용자에게 보이지 않는다

- 위치: `crates/yw-win/src/process.rs:267-288`, 호출 `main.rs:123-126` → `:197-208`은 WARN 로그만
- 분류: CWE-778 / CWE-212. 영향: 제외가 실패하면 크래시 시 WER 보고서(로컬 덤프가 켜진 PC면 미니덤프)가 만들어질 수
  있고 덤프에는 잠금 해제 DEK·비밀 입력 버퍼가 남을 수 있는데 사용자는 "덤프 없음"으로 오인한다. D28이 조용히 깨진다.
- 수정: 실패 시 배너 또는 설정 화면 상시 표기. 신뢰도: 코드 확실, 덤프 발생은 추정.

#### L10. 미등록 토큰의 `decimals`/`symbol`을 RPC에서 그대로 받아 주 금액 표기를 만든다

- 위치: `crates/yw-app/src/flow/evm/prepare.rs:352-376`, `crates/yw-core/src/evm/display/mod.rs:121-144`(포맷 부분이
  RPC 값, 원시 단위는 항상 병기), `crates/yw-core/src/evm/risk/mod.rs:66-80`(E19 심볼 스푸핑 검사)
- 분류: CWE-345. 영향: 악성/오류 RPC가 `decimals=0`을 주면 원시 1,000,000이 "1,000,000 USDC (미확인 · 원시 단위
  1,000,000)"처럼 등록 토큰과 같은 모양으로 보인다. 원시 값 병기로 서명 바이트와 갈라지지는 않는다(방어 심층).
- 수정: 미확인 토큰은 원시 단위를 앞에 두거나, `decimals` 조회 실패와 같은 형식으로 통일. 신뢰도: 확실.

#### L11. `personal_sign` 인자 순서를 뒤바꾼 요청이 조용히 뒤바뀐 의미로 승인된다

- 위치: `crates/yw-app/src/browser/params.rs:696-707`. `[A0, A1]`처럼 메시지가 20바이트 hex이고 둘째가 주소면
  통과한다(spec/05 §3.4는 거부라고 적혀 있다). PoC case 1 확인. 창에 실제 바이트가 hex로 보여 눈치챌 수는 있다.
- 분류: CWE-1287. 수정: 순서 모호성을 경고로 표시하거나 스펙대로 거부. 신뢰도: 확실.

#### L12. `RpcMismatch`(차단) 체인에서도 `personal_sign`·`eth_signTypedData_v4`가 서명된다

- 위치: spec/03 §1.4는 "불일치 → … 보내기·서명은 E34(차단)"인데 트랜잭션 경로만 `prepare.rs:831-849`에서 차단하고,
  메시지 경로는 `app_approval.rs:1388-1396`이 불일치를 보지 않으며 `site_preflight`도 체인 삭제만 검사한다
  (`app_browser.rs:753-756`). 서명은 브로드캐스트가 없어 자금 위험은 없으나 표시된 네트워크가 RPC와 다른 상태에서
  서명이 나간다. 수정: 메시지 경로에도 E34 차단. 분류: CWE-1023. 신뢰도: 확실.

#### L13. `btc_signMessage`의 주소 매칭이 대소문자 구분 — 유효한 대문자 bech32가 4100으로 거부된다

- 위치: `crates/yw-app/src/browser/chain_params.rs:186-199`(형식만 검사, 정규화 없음),
  `crates/yw-app/src/app_chain_sites.rs:448-464,503-506`(정확 일치). BIP173은 전체 대문자 표기를 허용한다.
- 분류: CWE-178. 수정: bech32/bech32m은 소문자로 정규화 후 매칭, base58은 유지. 호환성 문제(서명 바이트 불변).
- 신뢰도: 확실.

#### L14. `wallet_revokePermissions`·`sol_disconnect`·`btc_disconnect`가 `BackupPending`에서 4100으로 끝난다

- 위치: `crates/yw-app/src/browser/dispatch.rs:1469-1473`(상태를 종류와 무관하게 거부). spec/05 §5의 4100 행은
  서명·연결과 vault 없음만 열거한다. 그 상태에서 창을 못 띄우므로 방어 가능한 선택이나 문언 이탈. 문서 보완 필요.
- 신뢰도: 확실.

#### L15. `settings.json`에 무결성·신선도 검사가 없다 — HyperEVM 핀 삭제, 수수료 상한 인상, `autoLock` 60분, 인덱서 교체가 배너 없이 수용된다

- 위치: `settings.rs:739-755`(핀은 `eip155:999`만 검증), 사용 `flow/evm/mod.rs:311-321`(핀이 없으면
  `PinOnFirstUse(None)`로 되돌아간다), `settings.rs:538-562`(상한 1–10000 gwei·총액 ≤ 10 native), `:712-720`(1–60분),
  `:627-661`(esploraBaseUrl), `:917-1035`(파일 무결성 장치 없음)
- 분류: CWE-345 / CWE-354. 영향: 핀 삭제 → 다음 연결에서 공격자 RPC의 블록 0 해시로 재-TOFU되고 그 값이 다시
  고정된다(잔액·확정 판정·수수료 추정·시뮬레이션 표시가 공격자 손에). `feeCaps` 인상은 최대 수수료를 연다.
  근거(실측): `poc-E-urls` — `auto_lock=60 pins=0 feeCaps=[…10000…] banners=[]`.
- 수정: 핀 부재/변경 배너, 기본값과 다른 상한 표시. 더 나아가려면 설정 MAC. 신뢰도: 확실(수용), 피해는 추정.

#### L16. 원시 난수원이 "실패 없이 상수만 내는" 경우 nonce·salt 재사용을 감지하지 않는다

- 위치: `crates/yw-core/src/entropy/mod.rs:111-118`(`random_array_with` 무검사), 대조 `:104-107`(DEK는 전바이트
  동일 검사). 영향: 세션 중 고착되면 같은 DEK로 같은 XChaCha20 nonce가 쓰여 스트림 XOR 누출 + Poly1305 키 재사용.
- 분류: CWE-323 / CWE-330. 수정: 같은 전바이트 검사 추가. 신뢰도: 확실(코드), 발생은 추정.

#### L17. 롤백 미방어 — `generation`은 파일 자신의 값으로만 CAS하고 어디에도 기억하지 않는다

- 위치: `crates/yw-core/src/vault/session.rs:387-426`, `crates/yw-app/src/store.rs:196-205`, spec/02:547(명시).
  영향: 이전 세대 파일·백업으로 바꿔치기해도 경고 없이 수용되고(L1 때문에 현재 비밀번호로 열린다) 삭제한 가져온
  키가 부활하고 연결·라벨·주소록이 되감기고 journal 레코드가 사라진다. 수정: `generation` 표시 등. 신뢰도: 확실.

---

## 2. 규격·주석 vs 코드 편차

스펙이 약속한 문장과 코드가 다른 지점이다. 이 저장소는 스펙이 계약이므로 악용 불가여도 기록한다.
"코드가 맞음"은 스펙 문구가 낡았거나 서로 모순인 경우다.

| # | 편차 | 위치 | 방향 |
|---|---|---|---|
| S1 | 인식 스키마에서 T16(표시 한도 초과, 차단) 미발화 | spec/03 §8.4 vs M3 | 코드 |
| S2 | EVM 지갑 보내기 `검토`에 재검증 규칙 없음(SOL은 spec/07 §13.1-1로 요구) | M2 | 코드 |
| S3 | 메시지 서명이 `RpcMismatch`에서 차단되지 않는다 | spec/03 §1.4 vs L12 | 코드 |
| S4 | `personal_sign` 역순 거부 보장 없음 | spec/05 §3.4 vs L11 | 코드 |
| S5 | origin 검증 규칙 4곳 불일치 | spec/05 §2.4 vs L6 | 코드 |
| S6 | `bridge-init` 발신자 귀속 규칙 부재 | spec/05 §2.5 | 스펙(M4의 근거) |
| S7 | `sender.origin` 대조가 조건부 — Chrome이 주지 않으면 생략 | `background-core.js:549-551` | 코드(심층화 여지) |
| S8 | `BackupPending`에서 revoke/해제가 4100 | spec/05 §5 vs L14 | 스펙 보완 |
| S9 | 자산 변화 행 순서가 §11.2 키 순서와 다르다(§6.4 행 우선순위를 코드가 택함) | `evm/display/mod.rs:555-572` | 스펙 내부 충돌 |
| S10 | `BackupPending`에서 `change_password` 허용 | spec/02:619 vs `session.rs:1155` | 스펙(열거가 상위집합) |
| S11 | `reveal_*` 반환 타입이 §9는 `Zeroizing<String>`, 코드·§10.3은 더 강한 `SecretString` | spec/02:776-777 | 스펙 내부 모순 |
| S12 | content 전달 이벤트 목록 표가 §2.8·§4.8과 모순 | spec/05 §2.7 vs `shared.js:229-249` | 스펙 낡음(코드가 맞음) |
| S13 | `PIPE_INSTANCES` 이중 정의, `browser/mod.rs:72` 값 미사용 | spec/05 §8.4 vs `pipe.rs:63` | 코드(죽은 상수) |
| S14 | 폐기 검사(CRL/OCSP)를 의도적으로 켜지 않는다 | `yw-win/src/http.rs:15-19` | 설계(문서화됨, D13 위반 아님) |
| S15 | HTTPS가 프록시 자동 검색(AutoProxy/WPAD/PAC)을 쓴다 | `http.rs:476` | 설계(네트워크 입력을 따름) |
| S16 | HTTPS IPv6 리터럴 불가(루프백 `http://[::1]`는 허용), 대문자 스킴 거부 | `http.rs:92-97` vs `:233` | 코드(우회 가능) |
| S17 | `security.rs` 주석 "storage code rejects them"이 실제와 다르다 | `security.rs:751-753` vs L8 | 코드(주석) |
| S18 | `input::injected()`가 정의만 되고 호출자 0곳 | `input.rs:18-28` | 코드(죽은 코드) |
| S19 | `0x`+홀수 hex 메시지는 hex가 아니라 문자 그대로 서명된다(표시도 문자 그대로) | spec/03 §9.1 vs `eip191.rs:54-80` | 명세 일치·dApp 호환 차이 |

---

## 3. 보증이 실제로 성립함을 확인한 영역

"취약점이 없다"의 근거다. 각 항목은 코드 위치까지 확인했다.

1. **승인 digest의 결속 범위** — `crates/yw-core/src/approval/store.rs:190-234`에 id·kind·origin·chain(태그+
   chainId+genesis)·account·**payload 원 바이트**·표시 digest·시뮬레이션 상태(태그/verdict/블록/sim_digest/사유)·
   `expires_unix_ms`가 모두 들어간다. `consume`은 표시된 digest를 상수 시간 비교하고 불일치면 `Invalidated`,
   만료는 단조 시계, `risk == Blocked`면 `Blocked`, `Approved`는 `Clone` 없음. 서명 함수는 `Approved.payload()`만
   쓰고 다른 경로로 필드를 재구성하지 않는다(`evm/sign/mod.rs:253-266`). 1비트 변경·재사용·만료 테스트가 이를 고정한다.
2. **표시와 서명 바이트의 단일 출처** — EVM은 `decoded.tx`로 표시를 만들고 같은 `tx`를 payload로 넣는다
   (`evm/display/mod.rs:529,637-647`). chainId는 표시·payload·서명 검사가 같은 값이고 서명 후
   `keccak(preimage)` 일치·`decode_signed`·9필드 비교·복구 주소 비교를 모두 통과해야 반환한다(`evm/sign/mod.rs:157-183`).
   EIP-712는 해시 워드와 표시 노드를 **같은 루프**에서 만든다(`eip712/schema.rs:638-671`). BTC는 payload가 unsigned tx
   원 바이트 전체이고 `sign_plan`이 `approved.payload() == btc_payload(plan)`을 바이트 단위로 요구하며
   (`btc/sign.rs:521-533`), 서명 후 `verify_signed`가 재직렬화·비증인 동일성·형식별 엄격 검사·잔돈 재파생·수수료/
   dust/weight를 재확인하고 입력 금액은 이전 tx 원 바이트로 재계산 검증한다(`btc/prevtx.rs:59-99`). SOL은 intent
   transcript가 from/to/asset/amount/cu/price/fee cap/flags까지 결속되고(`sol/intent.rs:62-99`) `encode_message` →
   `parse_message` → 재인코딩 동일성을 통과해야 서명한다(`sol/sign.rs:211-219`).
3. **origin의 출처** — 페이지가 준 값이 아니라 `port.sender`만 쓴다(`background-core.js:526-563`: `frameId === 0`·
   `documentLifecycle === "active"`·`documentId` 형식·URL 8192자 상한 강제). 앱은 `topOrigin`을 **다시 파싱**하고
   `frameOrigin === topOrigin`·`extensionId == 고정값`을 재검사하며(`envelope.rs:356-386`), 표시는 그 파싱 결과를 쓴다
   (`approval_view.rs:689,724`). 페이지·확장이 준 "표시용 문자열"을 신뢰하는 곳은 없다.
4. **승인 없는 실행 경로의 봉쇄** — 37개 화이트리스트(`policy/method.rs:89-127`), 표 밖은 4200, `route` 불일치는
   -32600(`dispatch.rs:1001-1009`). 서명 메서드를 read로 위장하는 경로가 없다(PoC case 6). `eth_sign`·
   `wallet_addEthereumChain`·`eth_sendRawTransaction`은 4200. 큐 진입(`admit_site`)과 표시 직전(`site_preflight`)에
   vault·grant·한도·체인 삭제를 재검사한다.
5. **vault 암호** — Argon2id v0x13, m=262144 KiB/t=3/p=4가 생성·해제 양쪽 동일하고 헤더 값이 `KDF_V3`와 **정확히
   일치**해야 하며 불일치는 KDF 실행 전에 거부된다(`format.rs:212-214`) → 파라미터 다운그레이드 불가. KEK는 HKDF로
   DEK와 분리. wrap AAD = `header[0..82]`, payload AAD = 헤더 전체, 사이드카 AAD = 사이드카 헤더로 어느 필드 단일
   치환도 AEAD 실패하며 §4.5 변조표 테스트가 고정한다. 모든 쓰기가 24바이트 새 nonce를 뽑는다.
6. **서명 엄격성** — EVM: RFC6979 + low-s + 서명 후 재검증, 디코더가 `s ≤ n/2`·canonical RLP 강제. BTC: strict DER
   왕복·`r<2^255`·low-S·`SIGHASH_ALL`·즉시 verify, Schnorr은 BIP340 aux rand + verify. Ed25519 `verify_strict`.
   BIP39 체크섬·엄격 파싱, WIF 압축 플래그, SLIP-0010 hardened 전용.
7. **SIWE / personal_sign** — 표시(텍스트 또는 hex)와 EIP-191 preimage가 같은 `bytes`에서 나오고
   (`evm/display/mod.rs:775-845`), 32바이트·제어문자는 hex+P04, 비UTF-8은 hex+P01. SIWE는 도메인을 origin과 대조해
   S01/S02 차단, 주소·체크섬 S03, 만료 S04 차단, 문법 실패 시에도 marker-only로 authority를 검사한다(`evm/siwe.rs:512-546`).
   본문 전문이 항상 함께 표시된다.
8. **메모리 위생** — 잠금 슬롯 1페이지 `VirtualLock`, 놓기 전 전 구간 zeroize, `LockedBox::drop`이 페이지 전체
   wipe→unlock→free(`mem.rs:225-235`), payload 용량 전체 zeroize, Argon2 블록 메모리 zeroize, 실패 경로도 wipe 후
   오류. 키 타입 `Debug` 가림. `panic = "abort"` + WER 제외.
9. **디스크** — 데이터 폴더는 사용자·SYSTEM·Administrators 보호 DACL + Medium NR/NW 라벨, 소유자 불일치 시 기동 중단,
   수리 후 재검사. 쓰기는 재분석 지점 거부 + `CREATE_NEW`→`FlushFileBuffers`→`MoveFileExW(WRITE_THROUGH)`.
10. **승인 창 게이트** — 1 s 무장 + 직전 입력과 1 s 간격(`interaction.rs:112-130,237-240`), 비전경 클릭은 활성화
    클릭으로 소비하고 click-through면 홀드 미시작, High는 체크박스+2 s **연속** 홀드이며 포커스·캡처 상실·릴리스에서
    리셋, 내용 교체 시 체크·홀드 초기화, 승인은 1회만(`app_approval.rs:1719-1721,909-916`), 120 s 만료, 소비는
    표시 중 digest와 상수시간 비교(`approval/store.rs:510-527`). 37개 상호작용 테스트 통과. 비밀 창에
    `WDA_EXCLUDEFROMCAPTURE`.
11. **네트워크** — 세션에 TLS 1.2|1.3만(`http.rs:492-498`), 리디렉트 `NEVER` + `WINHTTP_DISABLE_REDIRECTS`,
    쿠키·자동 인증·Referer·Origin 없음, `SECURITY_FLAG_IGNORE_*` 미사용, 단계별·총량 타임아웃과 응답 상한, URL
    2048바이트·userinfo 거부·`#` 금지, `HttpsUrl`의 `Display`는 `https://[redacted]`. LLM은 HTTPS 또는 루프백 3종만(D21).
12. **로그** — 필드 타입이 `&'static str`/`NetworkId`/`ErrorCode`/주소/해시로 고정이라 임의 문자열이 못 들어가고
    유일한 동적 필드 `LlmHost`만 정화한다(`logging.rs:24-46,132-135`). AI 본문·프롬프트·키·RPC URL이 없다.
13. **클립보드** — 복사 기본 꺼짐, 비밀 복사는 기록·동기화·모니터 제외 포맷을 먼저 쓰고 하나라도 실패하면 클립보드를
    비우고 텍스트를 넣지 않으며, 30 s 뒤 논스가 남아 있을 때만 비운다(`clipboard.rs:123-179`).
14. **프로세스 경계** — pipe는 `O:<SID>D:P(A;;GA;;;<SID>)` DACL + `FIRST_PIPE_INSTANCE` + `PIPE_REJECT_REMOTE_CLIENTS`,
    이후 인스턴스는 첫 인스턴스의 소유자·DACL과 재대조. yw-host는 hello **전에** 소유자 SID·서버 pid·`verify_process`
    (이미지·무결성 RID ≥ Medium)를 확인하고 실패 시 아무것도 보내지 않는다. `AllowSetForegroundWindow`는 검증된
    pid에만. 확장 ID는 호스트 argv·앱 hello·`install.ps1` 재계산 3중 고정이고 manifest에 `externally_connectable`이
    없으며 팝업 포트는 `sender.id`까지 확인한다.
15. **의존성·빌드** — `check-core-deps.mjs`는 `--locked` 메타데이터로 정확한 `name=version` 허용 목록과 비교하고
    경로/git 소스·dev-dep·허용 밖 build.rs/proc-macro·금지 feature·미도달 허용 항목을 모두 실패로 처리한다. 외부
    크레이트 54개 전부 `Cargo.lock` checksum 존재, `.cargo/config.toml`에 registry 대체 없음. 확장 정적 감사는
    manifest 키·아이콘·popup 인라인·eval/`innerHTML`/fetch/원격 URL·심볼릭 링크·경로 이탈을 막는다.

---

## 4. INFO (실재하나 악용 경로가 좁다)

- **봉투 `sessionId`가 연결과 대조되지 않아 새 연결에서 봉투 재생이 가능** — `envelope.rs:299`, `dispatch.rs:979-981`.
  `sequence`가 연결마다 0부터라 이전 봉투를 재생하면 승인 창이 다시 뜬다(같은 서명 대상이라 자금 위험 없음).
- **`sequence`를 2^53−1로 오염시키면 그 연결 전체가 영구 -32600** — `dispatch.rs:918-928`, `envelope.rs:269-271`.
- **`context`의 `tabId`·`documentId`·`channelNonce`는 검증만 하고 쓰지 않는다** — 문서 식별이 `activationNonce`
  하나에 의존하고, 확장이 nonce를 재사용해도 앱이 감지하지 못한다.
- **읽기 passthrough**: 미연결·잠금에서도 `eth_call`·`eth_getLogs`(10,000블록)·`eth_estimateGas`가 임의
  `from/to/data`로 전달된다(스펙대로). 악성 페이지가 RPC 쿼터를 태우고 지갑을 고정 IP 프록시로 쓸 수 있다.
- **`wallet_switchEthereumChain`이 미연결 origin도 승인 없이 자기 체인을 바꾼다**(스펙대로).
- **RPC URL(베어러 토큰)이 소거되지 않는 `String` 힙 3개로 남는다** — `http.rs:84-90,163-166`, `Display`는 가림.
- **quarantine 파일명이 초 단위라 같은 초의 두 번째 격리가 실패한다** — `store.rs:238-241`(재시도로 풀림).
- **`passphrase_check`는 4바이트(2^-32)** — 설계이며 오타 지적은 이미 스펙에 있다.
- **`0x`+홀수 hex `personal_sign`은 문자 그대로 서명된다**(S19) — 표시도 문자 그대로라 안전, dApp 호환 차이.
- **yw-app은 pipe 클라이언트가 yw-host.exe인지 확인하지 않는다**(pid는 로그용, spec/05 §8.1 명시). 서버는 DACL로
  보호되므로 비대칭이 정당하나, 같은 사용자 프로세스가 임의 origin 라벨로 승인 창을 띄울 수 있다.
- **`check.ps1`의 환경 변수 위생이 `install.ps1`보다 좁다** — `check.ps1:33-35`는 RUSTFLAGS 계열 4개만 보고,
  `install.ps1:1010-1037`은 `RUSTC_WRAPPER`·`CC`·`CFLAGS`까지 지우고 `--config`로 링커를 고정한다. 게이트 통과가
  "설치와 같은 조건"을 뜻하지 않는다.

## 5. 비목표·잔여 위험 (§2.2 매핑)

결함이 아니라 이번 검토로 확인된 "남는 위험"이다. `docs/install.ko.md`·§2.4에 일부만 적혀 있으므로 사용자
체크리스트로 보완할 만하다.

- 같은 사용자 악성코드 전제: L5(합성 Enter), L15·M1(평문 설정 파일 신뢰), INFO(pipe 클라이언트 미검증).
- 디스크·백업 도난: **범위 안**이고 암호화로 막힌다. 단 L1(DEK 미회전)·L17(롤백)이 "유출 후 회수"를 제한한다.
  볼트를 풀지 않고도 `settings.json`과 로그에서 **사용 네트워크 + 계정 주소 + tx 해시(→ 공개 탐색기로 전체 이력)** 를
  얻는다(D28이 주소를 허용하므로 규격 위반은 아님).
- RPC 단일 의존: 잔액·확인 수·UTXO 완전성·수수료 추정·시뮬레이션 표시는 설정한 RPC를 신뢰한다(D13·D32). 서명 대상
  자체는 RPC가 바꿀 수 없다 — 이번 검토에서도 바꾸는 경로를 찾지 못했다.
- 폐기 검사 미사용(S14)·AutoProxy/WPAD(S15)·WER 덤프(L9)는 암호화로 덮이지 않는 채널이다.

## 6. 권고 순서

1. **M2·M3** — 사용자가 검토했다고 믿는 창의 내용이 어긋나는 두 곳(보내기 재검증, T16 차단 복원). 효과 대비 변경량이 작다.
2. **M1** — 로더에서 endpoint 호스트와 동의 호스트를 대조(변경 시 `enabled=false` + 배너).
3. **M4** — `bridge-init` 재수용 규칙(조건 한 줄 + 스펙 문구·P6 테스트).
4. **L4(a)(b)(c)·L12·L11** — 승인 창 **열린 뒤** 상태 변화 재검증과 메시지 경로 E34. 승인 계약의 구멍들이다.
5. **L2·L3** — 승인 잔액 조회 집합, 주소 분류 슬롯. 리뷰 보조 정보의 결손.
6. **L16** — `random_array_with` 고착 검사(비용 0). **L8** — 파일 링크 거부 + `flush_dir` 오류 승격.
7. **L1·L17·L15** — 회수·롤백·설정 무결성은 문서와 화면 표시로 먼저 좁히고, 필요하면 MAC.
8. **L6·L5·L7·L9·L10·L13·L14** 그리고 S1~S19 — 검증 규칙 동기화, Enter 홀드 통일, 소스 트리 ACL, WER 실패 노출,
   스펙·주석 정리(특히 S1·S2·S5·S6·S12·S17).

## 7. 재현물과 환경 한계

PoC(모두 `target/tmp/`, 저장소 무변경):

| 파일 | 확인 |
|---|---|
| `poc-D-sign.rs` / `.exe` | M3(T16 소실) · L2(E14 미발화) · 대조군 |
| `poc-A-1-bridge-init-lockout.mjs` | M4 채널 선점 → 요청 폐기 |
| `poc-A-2-origin-mismatch.mjs` | L6 JS 수용 / 앱 거부 |
| `poc-E-urls.rs` / `.exe` | M1·L15 `settings::load` 변조 수용 |
| `poc-C-dek/`(별도 크레이트) | L1 옛 사본이 옛 비밀번호로 열림 |
| `run-poc-B.ps1` + `poc-B-1.rs` | L11 · L4(b) · read passthrough 등 6케이스 |

회귀: 3절의 스위트 전부 통과. **환경 한계 2가지** — (a) 이 샌드박스는 Node `child_process` 파이프가 EPERM이라
`node --test <dir>`·`privacy-scan.mjs`·`check-core-deps.mjs`(직접 실행)가 실패한다(cargo 테스트와 `node <단일 파일>`로
우회했고 데스크톱에서는 정상이며 저장소 결함이 아니다). (b) `%LOCALAPPDATA%`가 읽히지 않아 디스크 DACL은 실측이
아니라 SDDL 문자열과 `Set/GetNamedSecurityInfoW` 경로 추적으로 판정했다.

## 8. 처리 결과 (2026-11-01)

이 저장소 `main`에서 아래 항목을 처리했다(각 항목에 회귀 테스트). 설정·vault·설치·yw-win 저장소 항목(M1·L1·L7·L8·L9·
L15·L16·L17, S10·S11·S13·S17, INFO `check.ps1` 환경 위생)은 다른 작업자가 `b0deb44`에서 처리했고 병합 커밋으로 `main`에
들어왔다. S14·S15는 "설계"라 조치 없음.

| 항목 | 결과 | 커밋 | 비고 |
|---|---|---|---|
| M1 / L15 | 고침 | `b0deb44` | vault로 암호화된 meta `security_settings` 스냅샷(LLM 동의 host·enabled·안내 버전, genesis 고정값, `feeCaps`, `autoLockMinutes`, BTC indexer·Esplora). 앱이 설정을 쓸 때마다 갱신, 잠금 해제 뒤마다 대조: 동의 없는 엔드포인트로 켜진 LLM → 끄고(파일도) 배너, 대조 전에는 `yw-llm` 작업자를 만들지 않음. 묶이지 않은 옛 LLM 키는 스냅샷의 동의 host에만 묶음. genesis 고정값이 없어지거나 바뀌면 되돌림(다시 TOFU 안 함). 나머지는 스냅샷 값 + 배너(`파일 값 사용` / `앱에 저장된 값으로 되돌리기`). spec/02 §5.3, spec/04 §6.7, spec/06 |
| M2 / S2 | 고침 | `2c83c07` | `검토`가 RPC 없이 다시 검사하고, 화면 값과 다르면 SOL과 같은 "입력이 바뀌어 다시 확인했습니다…"로 승인을 열지 않는다. `dirty_ms` 동안 `검토` 비활성(첫 입력 때 다시 그림). spec/04 §2.7 |
| M3 / S1 | 고침 | `2d913a9` | 인식 스키마도 message 전체를 트리 한도로 재서 T16. typed data 필드 목록은 1,023개에서 멈추고 마지막 칸에 "(표시 한도 초과: 항목 N개 생략)" + T16(차단) — `TooMany` 내부 오류가 아니다. spec/03 §8.4 |
| M4 / S6 | 고침 | `cdd620f` | content가 저장소 읽기 **전에** 채널만 담은 `bridge-claim`을 동기로 보낸다(페이지 스크립트보다 먼저 큐에 들어가 먼저 전달). provider는 그 채널로만 `bridge-init`을 받아 브리지를 연다. 제안된 "pending 0이면 `bridge-init` 재수용"은 **채택하지 않았다**: 페이지가 유휴 때마다 채널을 다시 가로챌 수 있다. 남는 한계(채널은 관찰 가능 — 페이지는 자기 자신만 속인다, 다른 확장의 document_start MAIN 스크립트, claim 미전달 시 이전 규칙)는 spec/05 §2.5에 적었다. P6·C1·E4(실제 스크립트 종단) 테스트 |
| L1 | 문서 | `b0deb44` | DEK는 회전하지 않는다(vault·meta·journal이 따로 커밋되어 형식 변경 없이는 중단에 안전하지 않음, spec/02 §4.4). 복구 안내서·W04·설정 → 보안·변경 완료 문구에 "옛 사본은 옛 비밀번호로 열린다"와 대처(니모닉으로 새 vault)를 적음 |
| L2 | 고침 | `43336f8`, `6f85ae1` | 잔액 조회 = calldata 승인 ∪ diff ERC-20 승인(0 아닌 금액), `MAX_FACT_LOOKUPS`/E27 안에서 |
| L3 | 고침 | `43336f8`, `6f85ae1` | `to`는 16칸 밖의 자기 칸(목록 1 + 16). 16 spender 모두 분류, 17이면 E27 |
| L4 (a)(b)(c) | 고침 | `845b2ff` | (a) 승인 시 보이는 계정과 다시 대조, 숨김·삭제 계정이 있으면 SOL/BTC와 같은 4100(요청이 끝나므로 창은 닫힘 — "창 유지"는 SOL/BTC 대칭으로 해석). (b) 숨김·삭제 시 그 계정의 대기·표시 중 서명 요청을 `Revoked`(4100)로 끝내고 표시 창을 닫는다(체인 삭제 경로와 같은 방식). (c) 연결 창은 그릴 때마다 origin 체인을 다시 읽고, 승인 시 그려진 체인과 다르면 승인하지 않고 새 체인으로 다시 그려 1 s 재무장, grant에는 보인 체인을 저장. (c)의 승인 시점 분기는 실제 창이 필요해 단위 테스트는 `connect_state`의 현재 체인 읽기와 `connect_approved`의 저장 체인까지 |
| L5 / S18 | 고침 | `3d49b7b` | `ApproveActivated { physical }`: `GetKeyState`(메시지 시점 키 상태 — 게시·전송된 `WM_KEYDOWN`은 바꾸지 않음, 새 `input::is_down_in_message`) && `!input::injected()`(이제 호출처 있음). 합성 Enter는 승인하지 않고 누름으로만 센다. yw-win 테스트가 실제 창에 `PostMessage`·`SendMessage`한 Enter가 "안 눌림"으로 읽히는지 확인 |
| L6 / S5 | 고침 | `cdd620f` | JS 3곳(shared.js·provider-main.js 사본·background)이 §4.7 문법(라벨 `[a-z0-9_-]{1,63}`, 끝 점·빈 라벨 거부, host ≤ 253, origin ≤ 256, 포트 0 거부)을 적용. 공유 벡터 `extension/native-host/v1-origins.golden.json`을 S3·B7·P1·yw-core `r_origin_rule_matches_the_shared_golden`이 함께 쓴다 |
| L7 | 고침 | `b0deb44` | `install.ps1`이 저장소 루트·`scripts\`·`extension\`과 빌드 결과(`target\release` 또는 `CARGO_TARGET_DIR`) ACL을 확인(다른 사용자가 쓸 수 있으면 종료 1, `-AllowUnsafeSourcePath`면 경고 후 계속), 설치한 파일마다 SHA-256을 기록하고 바뀌면 경고. spec/01 §9 |
| L8 / S17 | 고침 | `b0deb44` | `FileStorage`가 vault·meta·journal과 `.prev`의 재분석 지점을 읽기(`FILE_FLAG_OPEN_REPARSE_POINT` 핸들 확인)·커밋 모두에서 거부, 폴더 flush 실패는 오류(쓰기 전 미리 flush). `settings.json`·`apikeys.dpapi`도 링크를 따라 읽지 않음. `security.rs` 주석 정정. spec/02 §6.2 |
| L9 | 고침 | `b0deb44` | WER 제외 실패 → 배너 + 설정 → 보안 한 줄. spec/04 |
| L10 | 고침 | `0a62dbc` | 미등록 토큰: `{원시} (원시 단위) {기호} (미확인 · decimals {d} 적용 시 {환산})` — decimals 조회 실패와 같은 모양으로 원시 값이 앞 |
| L11 / S4 | 고침(거부) | `c68ea63` | message 자리가 주소 모양(`0x`+40 hex)이면 스펙대로 -32602. 20바이트 hex 그 자체를 메시지로 보내는 알려진 dApp이 없어 경고 대신 거부 |
| L12 / S3 | 고침 | `48aea42` | `personal_sign`·`eth_signTypedData_v4`도 체인이 `RpcMismatch`면 E34 실패 창(RPC를 부르지 않으므로 이미 알려진 불일치만) |
| L13 | 고침 | `c147a9a` | `bc1`/`tb1`/`bcrt1` 주소는 파라미터 검사에서 소문자로 정규화, 대소문자 섞임은 -32602(BIP173), base58은 그대로 |
| L14 / S8 | 문서 + 일부 반박 | `5fda2f6` | spec/05 §5에 기록. 실측: `BackupPending`(과 vault 없음)에서 `wallet_revokePermissions`는 4100이지만 **`sol_disconnect`·`btc_disconnect`는 4100이 아니라 `null`**(지울 grant가 없고 아무것도 기억하지 않음) — 검토문의 그 부분은 코드와 다르다. 세 경우를 테스트로 고정 |
| L16 | 고침 | `b0deb44` | `random_array_with`(salt·nonce)도 DEK처럼 모든 바이트가 같으면 `RandomnessUnavailable`. spec/02 |
| L17 | 고침(표시) | `b0deb44` | 잠금 화면·설정 → 보안에 vault generation과 마지막 쓰기 시각 표시. meta가 본 가장 큰 generation(`vault_generation_seen`)을 기억하고 `vault.ywv`가 되감기면 배너 + 로그 `vault.generation_backwards`. 거부는 하지 않음(spec/02 롤백 문단) |
| S7 | 고침 | `8e52979` | `sender.origin`이 없으면 거부(Chrome ≥ 80은 항상 줌, manifest 최소 120) |
| S9 | 스펙 | `a1011c4` | §11.2: 보냄·받음 행은 키 순서가 아니라 §6.4 행 순서 |
| S10 | 스펙 | `b0deb44` | spec/02: `BackupPending`에서 비밀번호 변경 허용(코드가 맞음) |
| S11 | 스펙 | `b0deb44` | spec/02 §9: `reveal_*` 반환 타입을 `SecretString`으로(§10.3과 일치) |
| S12 | 스펙 | `a1011c4` | §2.7: content가 넘기는 이벤트 4종으로 갱신(코드가 맞음) |
| S13 | 고침 | `b0deb44` | 쓰지 않는 `browser::PIPE_INSTANCES` 삭제(`pipe.rs`의 값 하나만 남음) |
| S16 | 고침 | `73c43c8` | `HttpsUrl` 스킴 대소문자 무관(소문자 정규화), 대괄호 IPv6 리터럴 host 허용(zone id 없음). spec/01 §7.4 |
| S19 | 스펙 | `a1011c4` | §9.1: `0x`+홀수 hex는 문자열로 서명·표시(의도한 호환 차이) |
| INFO `sessionId` | 고침 | `e546ed1` | 연결의 첫 request가 세션을 묶고, 다른 세션 봉투는 -32600(cancel은 버림)·순번 불변. 새 연결의 첫 봉투 재생은 남는 한계(spec/05 §6.3) |
| INFO `check.ps1` 환경 | 고침 | `b0deb44` | 게이트가 설치와 같은 빌드 변수(`RUSTC*`, `CARGO_PROFILE_*`, `CC`·`CFLAGS` 등)를 지우고 같은 `--config`(래퍼 끄기, 링커 `link.exe`)를 준다. 목록 일치는 `install.test.mjs`. spec/01 §4.1 |

게이트(`scripts/check.ps1 -Offline`)와 환경 메모: 이 PC에서는 저장소의 `target\` 아래에 있는 실행 파일만 제한을 받는다.
`%TEMP%`에 폴더를 만들면 액세스 거부(os error 5)가 나고, yw-host `owner` 테스트의 무결성 검사도 실패한다. 같은 바이너리를
`target` 밖에 복사하면 통과하므로 저장소 결함이 아니라 환경 문제다. 그래서 `CARGO_TARGET_DIR`를 저장소 밖으로 두고
게이트를 돌렸다. fmt·deps·clippy·test·fuzz·build는 통과했다. ext-test는 8개 파일이 모두 통과했지만 H1
`yw-host-process.test.mjs`는 저장소의 `target\debug\yw-host.exe`를 직접 실행해서 멈췄다(같은 시각 다른 작업자의 worktree
게이트도 같은 곳에서 멈춤). script-test·privacy·audit-ext·icons는 단계별로 돌려 모두 통과했다.

원인과 조치(병합 뒤): 저장소 루트에 외부 도구가 붙인 Low 무결성 레이블(`(ML;OICI;NW;;;LW)`)이 `target\`으로 상속되어, 그
아래 빌드된 exe가 Low 무결성으로 실행된 것이다. 이제 `check.ps1`이 이를 감지해 그 실행에서만 `CARGO_TARGET_DIR`을 저장소 밖
사설 폴더 `%LOCALAPPDATA%\YourWallet-dev\target`(현재 사용자·SYSTEM·Administrators만, 상속 끊음)으로 바꾸고 한 줄 알린다.
H1도 `CARGO_TARGET_DIR`을 따른다. 저장소의 ACL은 바꾸지 않는다(spec/01 §4.1, spec/09 §2.2).
