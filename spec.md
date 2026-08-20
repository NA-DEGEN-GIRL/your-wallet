# EVM Self-Custody Wallet — 시스템 명세 최종안 v2.3

- 상태: 최종 설계 기준안
- 기준일: 2026-08-12
- 대상: 데스크톱 EOA 지갑 1차 구현
- 운영 프로필: 1인 유지보수 baseline / General Mainnet / Hardened Public
- 규범 용어: **MUST/반드시**, **SHOULD/권고**, **MAY/선택**

v2.2는 v2.1의 보안 구조를 유지하면서 1인 운영 가능성을 위해 출시 등급, release-key profile,
독립 review gate와 플랫폼 중립 FFI 요구를 명확화했다.

v2.3은 v2.2의 구조를 그대로 유지하고 두 가지 누락을 보완한다.

1. **프로토콜 유효성 한도와 사용자 정책 한도의 분리** — 트랜잭션당 가스 상한처럼
   초과 시 트랜잭션 자체가 무효가 되는 합의 규칙을, 재확인으로 통과 가능한 사용자 정책 cap과
   구분해 서명 전에 fail closed 한다. (§9.4, §11.1, §22)
2. **broadcast 이후 lifecycle** — reorg·drop·replacement로 인한 pending 상태 변화와
   nonce ledger 재조정, 확정성 표시를 상태 기계에 포함한다. (§1.5, §9.5, §9.7, §13.2, §16.4, §16.5, §20)

---

## 0. 목표와 개정 원칙

### 0.1 배경

이 프로젝트는 다음 문제를 동시에 해결한다.

1. 패키지·빌드·배포 공급망 오염이 지갑 자산 손실로 이어질 수 있다.
2. 기존 지갑은 사용자가 실질적으로 검토하기 어려운 규모의 코드를 신뢰하게 한다.
3. 과도하게 불편한 보안 설계는 사용자를 다른 지갑으로 이탈시킨다.

### 0.2 목표

- **G1. Self-custody:** 개인키와 시드는 사용자 기기 밖으로 나가지 않는다.
- **G2. 최소 신뢰:** 비밀을 다루는 코드와 서명 승인 경로를 사람이 검토 가능한 규모로 줄인다.
- **G3. 오염 격리:** 비밀을 보유하지 않는 구성요소의 오염이 개인키 유출로 이어지지 않게 한다.
- **G4. 서명 투명성:** 사용자가 실제로 서명되는 바이트와 그 의미를 가능한 정확히 검증할 수 있게 한다.
- **G5. 독립 복구:** 이 소프트웨어와 배포 서버가 사라져도 표준 도구로 자산을 복구할 수 있게 한다.
- **G6. 실사용성:** 일상적인 dApp 사용이 가능해야 한다.

### 0.3 보장 범위

G3는 다음 범위에서 보장한다.

- 브라우저 확장, native host shim, Broker, RPC, 토큰 메타데이터, ABI·시뮬레이션 공급자가 악성화되어도 개인키 원문을 읽을 수 없어야 한다.
- 악성 구성요소가 임의 요청·승인 스팸·DoS·프라이버시 침해를 일으킬 수 있다는 사실은 숨기지 않는다.
- Key Agent, Secret Input Frontend, 암호 라이브러리, 컴파일러, 커널 또는 관리자 권한이 직접 악성인 경우까지 소프트웨어 구조만으로 완전 방어한다고 주장하지 않는다.
- 악성 서명 구현은 ECDSA nonce나 선택적 실패를 은닉 채널로 사용할 수 있으므로 “어떤 공급망 공격에도 키 유출 불가”라는 절대 표현은 사용하지 않는다.

### 0.4 주요 설계 유도

| 목표 | 결정 | 근거 |
|---|---|---|
| G2, G3 | Key Agent를 네트워크·브라우저·일반 GUI에서 분리 | Secret TCB와 파서 공격면 축소 |
| G3 | 확장·shim·Broker는 비밀 0 | 오염 피해를 요청 위조·기만·DoS로 제한 |
| G4 | 승인된 request digest와 실제 signing payload를 결합 | 표시한 A와 서명한 B가 달라지는 TOCTOU 차단 |
| G4 | 공개 API에서 raw hash signing 제거 | `eth_sign` 금지 원칙을 내부 경계까지 유지 |
| G5 | BIP39/BIP32/BIP44와 문서화된 파생 정책 | 다른 표준 지갑을 통한 탈출 경로 |
| G2, G3 | 웹뷰·원격 실행 코드 배제 | npm/원격 JavaScript 실행 경로 축소 |
| G6 | 읽기와 공개 메타데이터는 잠금 상태에서도 제공 | 불필요한 언락 마찰 제거 |
| G4, G6 | 시뮬레이션은 제공하되 추정치로 표시 | 사용성 확보와 RPC 기만 방지 |

### 0.5 개정 규칙

- §0.2 목표와 §3 우선순위는 프로젝트 정체성이다.
- 기술·라이브러리·UI·단계 구성은 목표를 더 잘 만족하는 대안이 있으면 교체할 수 있다.
- 편의성은 복구·서명 정확성·엔트로피·비밀 위생·기만 방지를 약화시킬 수 없다.
- 표준 상태가 Draft/Stagnant인 기능은 자동 채택하지 않는다. 지원 시 별도 ADR과 위협 검토가 필요하다.
- 현재 생태계 목록은 명세 본문에 영구 고정하지 않고 서명된 versioned data로 관리한다.

---

## 1. 시스템 범위와 위협 모델

### 1.1 시스템 정의

로컬에서 동작하는 데스크톱 EVM self-custody 지갑이다.

- 1차 계정 모델은 **secp256k1 EOA**다.
- dApp 연동은 EIP-1193/EIP-6963 브라우저 확장을 사용한다.
- native GUI와 CLI 승인 프런트엔드를 제공한다.
- 초기 네트워크 범위는 Ethereum 호환 JSON-RPC와 명시적으로 지원하는 트랜잭션 타입에 한정한다.
- “EVM 호환”이라는 이유만으로 체인별 비표준 트랜잭션·서명 형식을 자동 지원하지 않는다.

### 1.2 사용자

- 1차 사용자: 기술적으로 숙련된 본인.
- 2차 사용자: 하드웨어 지갑 없이 쓰는 일반 사용자.
- 고급 옵션을 몰라도 안전한 기본값을 유지해야 한다.

### 1.3 보호 자산

- BIP39 entropy, mnemonic, passphrase
- BIP32 seed, master/child private key, chain code
- vault password와 vault key
- 미브로드캐스트 signed transaction
- RPC API key와 인증 header
- 사이트별 계정 연결 정보와 주소 간 연결성
- 사용자의 승인 의도와 승인 상태

### 1.4 방어 대상

- 악성 dApp과 피싱 페이지
- 오염된 브라우저 확장 또는 native host shim
- 악성·오작동 RPC, 익스플로러, 토큰/ABI/clear-sign 데이터 공급자
- malformed JSON, RLP, typed transaction, EIP-712, ABI, IPC 입력
- 저장 장치 탈취에 의한 vault 오프라인 공격
- 다른 OS 사용자와 잘못된 파일·IPC 권한
- nonce 경쟁, timeout, 재전송·replacement 혼동
- 의존성·빌드 스크립트·배포·업데이트 오염
- 주소 포이즈닝, Unicode 동형문자, bidi/control 문자, 원격 이미지 공격
- 승인 스팸, 포커스 탈취, click-through, 승인 습관화

### 1.5 부분 방어 또는 비목표

- 커널·root·Administrator·디버거 권한 침해
- 같은 로그인 세션을 완전히 장악한 악성 프로세스
- 물리 접근, cold boot, evil maid, DMA, 하드웨어 사이드채널
- 악성 펌웨어·CPU·컴파일러가 Secret TCB를 직접 오염한 경우
- 사용자가 정확한 내용을 보고도 악성 행위를 의도적으로 승인한 경우
- 체인 합의 실패, 검열, 재조직, 브리지 또는 스마트컨트랙트 버그

같은 사용자 권한 프로세스의 우발적 IPC 접근은 줄이지만, 메모리 읽기·UI 자동화·화면 위조까지 완전 방어한다고 주장하지 않는다.

체인 재조직과 검열은 **방어 대상이 아니지만 정상 동작 조건이다.** 이들을 막을 수는 없으므로
비목표이나, 발생 시 지갑의 pending transaction 상태와 nonce ledger가 체인 상태와 어긋나서는 안 된다.
방어 불가와 처리 불필요는 구분한다. 처리 요구사항은 §9.5, §9.7에 있다.

### 1.6 필수 보안 불변식

1. 개인키는 Key Agent와 명시적 복구/export 경로 외부에 평문으로 나타나지 않는다.
2. 네트워크 접근 프로세스는 mnemonic, seed, private key, vault key를 보유하지 않는다.
3. 모든 서명은 fresh한 사용자 승인 하나에 결합된다.
4. 승인된 request digest와 실제 signing payload가 바이트 단위로 동일하게 결합된다.
5. raw hash signing 공개 경로는 존재하지 않는다.
6. 모든 네트워크·확장·메타데이터 입력은 적대적으로 취급된다.
7. 복구 절차는 프로젝트 바이너리 없이 독립 구현으로 실제 검증된다.
8. 모호하거나 지원되지 않는 형식은 fail closed 한다.
9. chain 또는 document lifetime이 바뀌면 관련 pending approval은 무효가 된다.

### 1.7 적합성 및 운영 프로필

문서 전체를 한 번에 구현하는 것이 아니라, 아래 프로필 중 하나를 명시적으로 선택한다. 어느 프로필에서도 핵심 보안 불변식을 축소하지 않는다.

- **Core Security Baseline — 모든 프로필에서 필수**
  - Broker/Key Agent 분리
  - Approval Frontend와 Secret Input Frontend의 권한 분리
  - typed signer only, 표시-서명 digest 결합, 서명 후 재검증
  - 표준 복구, versioned vault, strict parser와 fail-closed method firewall
- **Private Mainnet Canary — 1인 개발·자가 사용**
  - 지원 OS와 브라우저를 각각 하나로 제한할 수 있다.
  - TTY 기반 one-shot helper와 수동 update를 사용할 수 있다.
  - 독립 review 전에는 별도 canary 계정의 손실 가능한 극소액만 사용하며 일반 사용자용 안전성을 주장하지 않는다.
- **General Mainnet — 일반 실사용 배포**
  - 지원한다고 주장하는 각 플랫폼의 integration test와 문서화된 독립 보안 review를 통과해야 한다.
  - 해결되지 않은 Critical/High finding이 없어야 한다.
- **Hardened Public — 불특정 다수 또는 고액 사용 권고 배포**
  - 다중 release key/threshold, 역할 분리, 외부 공개 검증 채널과 전문 보안 감사를 요구한다.

선택하지 않은 기능·플랫폼·method는 부분 구현하지 않고 명시적으로 비지원 처리한다.

---

## 2. 완료와 출시 기준

### 2.1 완료의 정의

다음만으로 완료로 보지 않는다.

- 컴파일 성공
- 단위 테스트 통과
- 테스트넷에서 한 번 동작
- 기능 목록 완성

### 2.2 공통 출시 차단 조건

다음 중 하나라도 남으면 실제 자산을 사용하는 어떤 프로필에도 진입하지 않는다.

- 복구 경로·파생 경로 미검증
- signing payload와 승인 화면 결합 미검증
- unknown transaction/method를 암묵적으로 처리
- vault format·KDF·AEAD 결정 미확정
- Secret TCB에 불필요한 네트워크 또는 일반 GUI 의존성 존재
- secret 입력 경로가 Secret TCB에서 누락됨
- crash dump·로그·swap·hibernate 경로 미검토
- 재현 빌드·artifact 서명·업데이트 rollback 검사가 없음
- 실제 독립 복구 훈련 미실시

### 2.3 출시 등급

- **Development/Testnet:** 실제 가치가 있는 자산을 넣지 않는다.
- **Private Mainnet Canary:** 모든 §2.2 gate를 통과한 뒤, 구현자 본인의 격리된 canary 계정과 손실 가능한 극소액만 사용한다. 독립 review가 완료되지 않았음을 UI·문서에 표시하고 제3자 배포나 일반 안전성 주장을 하지 않는다.
- **General Mainnet:** §16.7 독립 review를 통과하고 Critical/High finding을 해결한 뒤 일반 실사용을 허용한다.
- **Hardened Public:** General Mainnet 조건에 더해 §15의 hardened release profile과 전문 외부 감사를 통과해야 고액 사용을 권장할 수 있다.

독립 review는 반드시 상업적 감사 계약을 뜻하지는 않지만, 주 구현자와 독립된 검토자가 명시된 범위·방법·finding·조치 결과를 남겨야 한다.

### 2.4 단계적 자금 사용

1. 공식 벡터와 오프라인 테스트
2. 로컬 개발 체인
3. registry에서 현재 지원 상태가 확인된 앱 테스트넷 전 경로
4. 서명된 Private Mainnet Canary release와 격리된 극소액 계정
5. 독립 review 후 General Mainnet 계정

고액 장기 보관은 Hardened Public profile과 별도 하드웨어 서명자 도입 전까지 권장 사용 사례가 아니다.

---

## 3. 우선순위

충돌 시 다음 순서를 따른다.

1. 복구 가능성
2. 서명 정확성
3. 엔트로피 무결성
4. 비밀 취급
5. 기만 방지
6. 공급망 최소화
7. 사용 편의성
8. 기능 개수

- 1~5를 편의성으로 타협하지 않는다.
- 사용자가 내용을 실제로 읽게 하는 사용성은 기만 방지의 일부다.
- 불완전한 기능은 위험하게 부분 지원하지 않고 명시적으로 거부한다.

---

## 4. 아키텍처와 신뢰 경계

### 4.1 프로세스 구조

```text
[dApp / hostile page]
          │ EIP-1193 / EIP-6963
          ▼
[Browser Extension]
- secret 0
- 정상 시 frame/top origin 수집
- 오염 시 origin 위조 가능
          │ browser native messaging
          ▼
[Native Host Shim]
- secret 0
- framing/size limit/relay만 수행
          │ user-only local IPC
          ▼
[Broker Daemon]
- secret 0
- session/permission/RPC/simulation/nonce/broadcast
          │ inherited private channel
          ▼
[Key Agent — Secret TCB]
- vault/derivation/canonical encoding/policy/signing
- network 없음, 범용 GUI 없음
        ┌─┴──────────────────────────────┐
        │ inherited one-shot channel     │ inherited one-shot channel
        ▼                                ▼
[Approval Frontend]               [Secret Input Frontend]
- Authorization TCB               - Secret-input TCB
- display/approve only             - password/passphrase/import/export
- seed/key/password 없음           - network 없음, 즉시 소거

[CLI client] ── local IPC ──> [Broker]
```

### 4.2 TCB 구분

- **Secret TCB:** Key Agent, Secret Input Frontend, 암호 라이브러리, vault/derivation/signing 코드, 최소 OS 추상화.
- **Authorization TCB:** Approval GUI/TTY와 canonical display protocol. 손상 시 무단 승인·기만은 가능하지만 키 원문을 읽을 수 없어야 한다.
- **Non-secret components:** 확장, shim, Broker, RPC, ABI·simulation·metadata. 손상 시 임의 요청·DoS·프라이버시 침해는 가능하지만 키 원문을 얻을 수 없어야 한다.

### 4.3 Key Agent

- 네트워크 socket 생성과 DNS API 사용을 빌드·런타임에서 차단한다.
- 일반 파일시스템 대신 제한된 vault storage interface만 사용한다.
- 공개 socket/pipe를 listen하지 않고 Broker가 만든 inherited handle만 사용한다.
- single instance와 vault file lock을 보장한다.
- Approval/Secret Input helper는 release manifest에 고정된 hash, version, code-signing identity, 비사용자 쓰기 설치 경로를 모두 검증한 뒤 직접 실행한다.
- 임의 child process 실행을 금지하고 고정 helper만 allowlist한다.
- IPC에서는 versioned·bounded typed wire message만 받으며 raw JSON, 원격 ABI 문서, HTML 또는 scriptable metadata를 직접 파싱하지 않는다.
- wire에서 역직렬화된 값은 항상 `Untrusted*` 상태다. strict validation을 통과해야만 외부에서 직접 생성·역직렬화할 수 없는 내부 `CanonicalTransaction`/`ValidatedTypedData`로 승격한다.
- typed request만 받으며 `sign_hash(bytes32)` 같은 범용 공개 메서드는 금지한다.
- account, chain, sign kind, exact payload, request nonce, browser-reported origin/document context, canonical display model hash와 provenance hash를 포함한 immutable request digest를 생성한다.
- origin·simulation이 독립적으로 신뢰되는 것은 아니지만, **사용자가 본 값과 승인된 값이 바뀌지 않도록** digest에 결합한다.
- 승인 응답은 동일 digest와 one-time nonce에 결합되고 한 번만 소비된다.
- cancel, timeout, lock, process restart 뒤 승인 token은 무효다.

### 4.4 Approval Frontend

- Key Agent가 검증한 고정 binary를 one-shot으로 실행한다.
- inherited private channel만 사용한다.
- 외부 문자열을 자체 해석해 핵심 의미를 만들지 않는다.
- 핵심 필드는 Key Agent가 만든 canonical display model에서 온다.
- 결과는 `approve/reject + request digest + nonce`만 반환한다.
- vault password, passphrase, mnemonic, private key를 입력·표시하지 않는다.
- network, remote font/image, telemetry를 사용하지 않는다.

### 4.5 Secret Input Frontend

- vault password, 저장하지 않는 BIP39 passphrase, import/export 시 mnemonic·private key만 제한적으로 취급한다.
- 일반 승인 UI와 코드·프로토콜·프로세스를 분리한다.
- Key Agent가 검증된 binary를 one-shot으로 실행하고 inherited private channel만 쓴다.
- network, 일반 파일 접근, clipboard output, logging, crash upload를 금지한다.
- mutable secret buffer를 사용하고 전달 직후·종료 시 소거한다.
- UI toolkit과 FFI를 Secret TCB dependency inventory에 포함한다.
- 초기 릴리스는 OS password manager 자동 저장을 제공하지 않는다. 향후 도입 시 OS credential service를 Secret TCB에 추가한다.

### 4.6 Broker

- private key, seed, mnemonic, vault plaintext를 받는 API가 없다.
- dApp, RPC, ABI, simulation, metadata 입력을 적대적으로 취급한다.
- nonce reservation과 pending transaction ledger를 account+chain 단위로 관리한다.
- Broker가 손상되어도 새 명시적 승인 없이 Key Agent가 서명하지 않는다.
- 전달된 origin은 승인 화면에 **브라우저 보고값·독립 검증 안 됨**으로 표시한다.

### 4.7 표시-서명 결합

- Key Agent가 최종 signing payload를 직접 생성한다.
- account, chainId, tx type, nonce, fee, to, value, calldata hash, typed-data domain/hash는 같은 payload에서 도출한다.
- ABI 이름, token symbol, simulation은 별도 보조 정보이며 provenance를 붙이고 실제 표시된 보조 정보의 hash도 approval digest에 결합한다.
- 승인 뒤 nonce, fee, gas, recipient, calldata, chain, sign kind가 바뀌면 다시 승인한다.
- 서명 뒤 signed bytes를 재디코드해 승인 객체와 다시 비교한다.

### 4.8 서명자 추상화

공개 추상화는 typed operation만 제공한다. 아래 `Canonical*`/`Validated*` 타입은 Key Agent 내부 검증 후에만 생성되며 IPC decoder나 외부 caller가 직접 구성할 수 없다. Broker 경계에서는 별도의 `Untrusted*Request` wire type을 사용한다.

- `derive_address(path)`
- `sign_transaction(CanonicalTransaction)`
- `sign_personal_message(ValidatedMessage)`
- `sign_typed_data_v4(ValidatedTypedData)`
- `capabilities()`
- 향후 전용 `sign_eip7702_authorization(ValidatedAuthorization)`

저수준 crypto module 내부에는 digest 서명 primitive가 필요할 수 있으나 IPC/FFI/상위 signer interface로 노출하지 않는다. 하드웨어 서명자가 반환한 signature도 payload와 expected public key로 검증한다.

### 4.9 플랫폼 중립 core와 FFI

- canonical transaction, typed-data validation, derivation, vault format과 policy engine은 OS·GUI·transport 개념에 의존하지 않는다.
- 공개 core interface는 versioned 구조체, 고정 폭 정수, 길이 제한 byte array와 명시적 error code로 표현 가능해야 한다.
- 파일 경로, socket/pipe handle, window handle, OS 문자열·allocator type은 core 공개 API에 나타나지 않는다.
- storage, OS CSPRNG, monotonic clock, secure-memory, process sandbox, UI와 transport는 좁은 adapter 경계로 주입한다.
- FFI는 ownership, lifetime, allocation/free 주체, zeroization 책임, panic/exception 전파 금지를 문서화한다.
- FFI에도 raw secret export와 raw hash signing을 일반 능력으로 노출하지 않는다.

이 제약은 모바일 코드를 미리 구현하기 위한 것이 아니라, 데스크톱 전용 세부가 신뢰 핵심을 오염시키지 않게 하기 위한 것이다.

---

## 5. 계정 생성, 백업과 복구

### 5.1 생성 정책

- 신규 일반 프로필은 128-bit entropy의 12단어 BIP39 English mnemonic을 기본으로 한다.
- 256-bit entropy의 24단어 생성은 고급 옵션으로 제공할 수 있다.
- 12단어도 secp256k1의 실질 보안 수준과 부합하며, 24단어가 자산 보안을 단순히 두 배 높인다고 표현하지 않는다.
- import는 표준 12/15/18/21/24단어를 지원하고 wordlist를 명시적으로 선택한다.
- 언어 자동 판별이 모호하면 거부한다. 신규 생성은 English wordlist로 고정한다.
- checksum, NFKD normalization, 공식 테스트 벡터를 적용한다.
- mnemonic→seed는 BIP39 그대로 PBKDF2-HMAC-SHA512, iteration 2048, output 64 bytes를 사용하며 vault용 Argon2id로 임의 교체하지 않는다.
- entropy는 OS CSPRNG 결과로만 생성한다.

### 5.2 파생 정책

- 신규 계정 기본 경로는 `m/44'/60'/0'/0/{index}`다.
- index는 0부터 순차 증가하며 자동으로 건너뛰지 않는다.
- 각 계정의 path/index를 언제든 확인 가능하게 한다.
- 다른 지갑에서 가져온 mnemonic을 위한 common legacy path 탐색은 별도 고급 복구 기능으로 둔다.
- path 후보를 자동 혼합하지 않고 실제 사용한 path를 항상 표시한다.

### 5.3 BIP39 passphrase

- “25번째 단어”가 아니라 **BIP39 passphrase**라고 표기한다.
- 기본은 비활성이다.
- 모든 passphrase가 유효한 다른 지갑을 만들기 때문에 오타 자동 검출이 불가능함을 경고한다.
- 활성화 시 두 번 입력, 첫 주소/address fingerprint 확인, 별도 백업 확인을 요구한다.
- 사용자는 다음 중 하나를 선택한다.
  - vault 안에 암호화하여 저장
  - 매 unlock마다 Secret Input Frontend에서 입력하고 저장하지 않음
- vault에 함께 저장한 passphrase는 별도 인증 요소가 아니며 vault password 하나가 둘을 함께 보호한다.
- 저장하지 않는 모드는 매 unlock 때 파생된 첫 주소/fingerprint를 확인한다.
- 복구에는 mnemonic과 정확한 passphrase가 모두 필요하다.

### 5.4 vault의 루트 표현

- mnemonic 지갑의 encrypted payload는 BIP39 entropy, wordlist ID, derivation profile, passphrase 저장 정책을 보관한다.
- seed, master private key, 모든 child private key를 중복 영속화하지 않는다.
- unlock 때 seed/master를 파생하고 lock 때 소거한다.
- 저장형 passphrase는 같은 encrypted payload에 둔다.
- raw-key/import 계정은 mnemonic 계정과 구분한 versioned record type으로 저장한다.

### 5.5 백업 완료 gate

- 백업 확인 전 mainnet 수신 주소 copy와 서명을 비활성화한다.
- 무작위 위치 단어 확인과 첫 주소 확인을 모두 수행한다.
- recovery card에 wordlist, derivation path, first address/fingerprint, passphrase 사용 여부를 기록할 수 있다.
- passphrase 자체는 mnemonic과 분리 보관하도록 안내한다.
- screenshot, cloud sync folder, 일반 clipboard 저장을 권장하지 않는다.
- encrypted vault backup은 운영 편의용이며 mnemonic(+passphrase) 독립 복구를 대체하지 않는다.

### 5.6 계정 발견

EVM은 token-only activity 등으로 자동 account discovery가 불완전할 수 있다.

- highest used index를 비밀이 아닌 recovery metadata로 export할 수 있다.
- 복구 wizard는 기본 범위를 스캔하고 사용자가 계속 확장할 수 있게 한다.
- balance 0·nonce 0만으로 미사용 계정이라고 단정하지 않는다.
- 수동 path/index 입력을 제공한다.
- 여러 chain을 조회할 때 생기는 privacy 비용을 설명한다.

### 5.7 독립 복구 훈련

출시 전 깨끗한 환경에서 다음을 수행한다.

1. 프로젝트 binary를 사용하지 않는다.
2. 독립 BIP39/BIP32 구현에 mnemonic/passphrase를 입력한다.
3. index 0, 1, highest used index의 주소를 비교한다.
4. 소액 자산을 실제 이동한다.
5. 절차와 결과를 기록한다.

### 5.8 키 가져오기

- raw private key, Web3 keystore, 다른 mnemonic import는 초기 필수 기능이 아니다.
- 지원 시 각각 별도 account type으로 유지하고 mnemonic으로 변환하지 않는다.
- Web3 keystore import는 KDF parameter/file size 상한과 parser fuzzing을 요구한다.
- import key의 보안은 과거 노출 이력보다 좋아질 수 없음을 표시한다.

---

## 6. 암호, 엔트로피와 vault

### 6.1 암호 구현

- secp256k1, Keccak-256, SHA-2, HMAC, PBKDF2, Argon2id, AEAD를 직접 구현하지 않는다.
- Ethereum의 Keccak-256을 FIPS SHA3-256으로 대체하지 않는다.
- 라이브러리 version, source, audit history, unsafe/build script를 기록한다.
- ECDSA nonce는 감사된 deterministic nonce 생성(RFC 6979 계열)을 사용하고 caller가 nonce를 주입할 수 없다.
- 보조 난수를 섞는 구현은 exact profile과 failure behavior를 고정한다.
- low-s canonical signature와 recovery parity를 검증한다.
- 서명 직후 public-key recovery로 signer address와 payload를 검증한다.
- BIP32 `IL >= n`, zero child key, leading-zero serialization을 공식 벡터와 property test로 검증한다.
- exact signature byte 비교는 동일 deterministic profile을 강제한 벡터에서만 사용한다.

### 6.2 엔트로피

- 플랫폼의 blocking-safe OS CSPRNG를 감사된 얇은 abstraction으로 호출한다.
  - Linux: `getrandom`
  - Windows: `BCryptGenRandom`
  - macOS: system CSPRNG API
- RNG failure, partial read, initialization failure는 즉시 중단한다.
- 시간, PID, mouse movement, 자체 PRNG를 entropy source로 쓰지 않는다.
- production binary에 deterministic test RNG가 link되지 않게 경계를 분리한다.
- fork/snapshot 가능한 환경에서 userspace RNG state를 장기 cache하지 않는다.
- 모든 VM/WSL을 일괄 위험으로 취급하지 않는다. deterministic image/snapshot clone, OS RNG 오류, 미지원 OS를 구체적으로 경고한다.
- zero/repetition sanity check는 catastrophic failure 탐지일 뿐 entropy 품질 증명으로 표현하지 않는다.
- 외부 주사위 entropy는 초기 릴리스에서 제공하지 않는다. 지원 시 bias 처리, domain separation, 절차·벡터를 별도 명세한다.

### 6.3 vault password와 KDF

- vault password와 BIP39 passphrase를 UI·코드에서 명확히 구분한다.
- Argon2id를 사용하며 실행 시간만으로 parameter를 정하지 않는다.
- 지원 desktop의 최소 profile은 RFC 9106 두 번째 권고값인 Argon2id `m=64 MiB, t=3, p=4`보다 약하지 않게 한다.
- 일반 desktop 기본 profile은 먼저 memory cost를 정한 뒤 목표 지연시간에 맞춰 iteration을 조정하며, 시간 목표를 맞추기 위해 memory를 최소값 아래로 조용히 낮추지 않는다.
- 더 높은 memory cost를 실제 지원 장치에서 benchmark하고 profile ID와 정확한 parameter를 vault header에 기록한다.
- memory allocation 실패 시 약한 KDF로 자동 fallback하지 않고 명시적으로 중단한다.
- 빈 문자열, 상용구, 매우 짧은 password는 거부한다.
- 임의 대문자/특수문자 규칙보다 긴 passphrase 또는 password-manager 생성값을 권장한다.
- KDF가 약한 password를 안전하게 만들 수 없음을 표시한다.
- KDF parameter는 vault header에 저장하되 memory/iteration/parallelism 상한을 검증한 뒤 할당한다.
- 약한 기존 profile은 성공적 unlock 뒤 명시적 migration으로만 강화한다.

### 6.4 vault 암호화 format

format은 최소 다음을 포함한다.

- magic
- format version
- vault UUID
- KDF identifier/parameters/salt
- AEAD identifier/nonce
- ciphertext
- authenticated metadata/AAD

요구사항:

- release마다 하나의 검토된 AEAD suite를 고정한다.
- nonce length/generation은 선택한 AEAD 규격을 따른다.
- version, algorithm IDs, vault UUID, 보안 관련 header를 AAD로 인증한다.
- unknown version/algorithm을 거부한다.
- 자동 downgrade하지 않는다.
- 잘못된 password와 손상 파일을 외부에 과도하게 구분해 oracle을 만들지 않는다.
- 과거의 유효한 encrypted vault로의 rollback은 로컬 AEAD만으로 완전 검출할 수 없음을 문서화한다.

### 6.5 저장 안정성

- vault directory와 파일은 current user 전용 permission을 사용한다.
- vault, backup, temporary path의 symlink/reparse point/hardlink, owner, ACL을 검사한다.
- 안전한 handle-relative/open-no-follow 방식으로 연다.
- 같은 directory에 temp file을 만들고 permission을 먼저 설정한다.
- write → flush/fsync → verify readback → atomic rename → directory fsync 순서를 적용한다.
- migration 전 encrypted backup을 만들고 새 파일 검증 뒤 교체한다.
- 각 단계 crash fault injection을 수행한다.
- SSD/COW/journal filesystem에서 secure delete를 보장한다고 주장하지 않는다.

### 6.6 공개 store

- address, label, chain setting, cached balance 등 잠금 상태 조회에 필요한 정보는 public store에 둘 수 있다.
- public store도 privacy 정보이므로 user-only ACL을 적용한다.
- 손상된 public store가 signing payload, trusted address, security policy를 바꿀 수 없어야 한다.
- trusted label/policy 변경은 Key Agent 승인 뒤 integrity-protected record에 기록한다.


---

## 7. 비밀 취급과 프로세스 hardening

### 7.1 secret type

- mnemonic, seed, private key, chain code, passphrase, vault key는 전용 secret type을 사용한다.
- secret type은 `Debug`, serialization, implicit clone을 기본 금지한다.
- 불가피한 copy는 위치·수명을 review에서 추적한다.
- immutable language string에 비밀을 저장하지 않는다.

### 7.2 입력과 출력

- 비밀은 command-line argument, environment variable, URL, 일반 IPC log로 전달하지 않는다.
- CLI는 stdin pipe가 아니라 controlling TTY/Console API에서 echo 없이 읽는다.
- GUI secret 입력은 Secret Input Frontend만 담당한다.
- non-TTY password·승인은 기본 거부한다.
- mnemonic/private key는 일반 clipboard copy/paste를 기본 금지한다.
- vault password paste를 허용하더라도 helper 내부에서만 받고 clipboard를 확실히 삭제했다고 과도하게 주장하지 않는다.
- secret export는 별도 high-risk flow, 재인증, 명시적 destination 선택을 요구한다.

### 7.3 메모리

- secret buffer는 가능한 page-locked memory에 둔다.
- `mlock`/`VirtualLock` 성공 여부를 확인하고 실패를 숨기지 않는다.
- high-security mode는 page lock 실패 시 fail closed할 수 있다.
- 사용 뒤 explicit zeroization을 하되 compiler, allocator, hidden copy 때문에 절대 보장이라고 표현하지 않는다.
- FFI ownership, length, zeroization 책임을 문서화한다.
- secret allocation을 일반 reuse pool에 반환하지 않는다.

### 7.4 dump, swap, suspend

- Linux core dump/ptrace 노출을 줄이고 dump exclusion을 적용한다.
- Windows WER/minidump에 Secret TCB를 포함하지 않도록 설정한다.
- macOS crash report 경로를 검토한다.
- suspend, session lock, user switch, hibernate 감지 시 즉시 lock을 시도한다.
- resume 뒤 항상 locked 상태로 시작한다.
- page lock이 hibernation file까지 완전 보호한다고 주장하지 않는다.

### 7.5 잠금 정책

- idle timeout 뒤 복호화 비밀을 소거하고 locked state로 전환한다.
- timer reset은 실제 서명, 명시적 사용자 activity, unlock 관리 동작만 수행한다.
- balance polling/RPC traffic은 timer를 갱신하지 않는다.
- approval 대기 중 sleep, lock, chain switch가 발생하면 요청을 거부한다.
- unlock state는 disk에 저장하지 않는다.

### 7.6 process privilege

- Key Agent는 최소 privilege token/sandbox/profile로 실행한다.
- network, 광범위한 file read, 임의 child process를 차단한다. 검증된 Approval/Secret Input helper만 예외다.
- sandbox 적용 여부와 failure를 진단 화면에 표시한다.
- safe-language secret core는 원칙적으로 `unsafe`를 금지한다.
- OS/crypto FFI를 위한 unsafe는 작은 별도 module로 격리하고 독립 review한다.

---

## 8. 서명 메서드와 정책

### 8.1 공통 규칙

- 요청 account는 지갑 소유 계정이고 해당 site/session에 노출 승인된 계정이어야 한다.
- request byte size, JSON depth, array count, string length에 hard limit을 둔다.
- duplicate JSON key, IEEE-754 precision loss, invalid hex, overlong quantity를 거부한다.
- account, chain, sign kind, document lifetime이 대기 중 바뀌면 취소한다.
- signature 반환 전 recovery와 exact payload를 검증한다.

### 8.2 `eth_sign`

- 지원하지 않는다.
- 4200/unsupported method로 명시적으로 거부한다.
- 상위 signer, IPC, FFI에도 raw hash signing을 노출하지 않는다.

### 8.3 `personal_sign`

- EIP-191 version `0x45` 규칙으로 서명한다.
- 두 관행적 parameter order를 strict하게 파싱하되 address 위치를 막연히 추측하지 않는다.
- request address가 선택 account와 다르면 거부한다.
- hex bytes를 정확히 복원한 뒤 표시한다.
  - printable UTF-8: escaped text, byte length, hash
  - ERC-4361 SIWE: domain, URI, address, chain ID, nonce, issued/expiry/not-before, resources
  - invalid/non-printable UTF-8: 기본 거부
- SIWE `domain` authority, `URI` origin, top-level origin을 표준화해 비교한다. scheme/host/port를 단순 문자열로 비교하지 않는다.
- SIWE address/chainId를 현재 account/chain과 대조한다.
- nonce 형식과 time fields를 검사하고 최근 승인 nonce replay cache를 둘 수 있다. 이는 server-side nonce 검증을 대체하지 않는다.
- 일치하더라도 extension compromise 시 browser origin을 독립 검증할 수 없음을 숨기지 않는다.
- 매우 긴 message는 거부한다.

### 8.4 `eth_signTypedData_v4`

- v4만 초기 지원하며 v1/v3는 비지원이다.
- duplicate key를 거부하고 256-bit integer를 손실 없이 처리한다.
- type graph, recursion, array, bytes/string length에 상한을 둔다.
- EIP-712 hash는 Key Agent가 직접 계산한다.
- domain의 모든 field와 primary type을 표시한다.
- domain `chainId`가 현재 chain과 다르면 거부한다.
- `chainId` 부재는 cross-chain replay 위험으로 기본 거부한다. 검토된 schema만 예외로 둘 수 있다.
- `verifyingContract` 부재/zero는 high-risk로 기본 거부한다.
- domain separator, struct hash, final digest를 raw details에서 확인 가능하게 한다.
- EIP-712 자체가 replay protection을 제공한다고 표현하지 않는다.

### 8.5 위험 typed data

최소 다음을 별도 식별한다.

- ERC-2612 permit 및 DAI-style permit
- Permit2 permit/transfer
- ERC-3009 transfer authorization
- ERC-4494 NFT permit
- NFT operator/batch permit
- order, exchange, bridge, session-key처럼 자산 권한을 주는 known schema

표시 항목:

- chain
- token/collection full address
- owner/from
- spender/operator/to
- human amount와 raw amount/tokenId
- nonce
- deadline/expiry의 local time과 UTC
- batch count와 각 item
- infinite amount, no expiry, chain-wide/cross-chain scope

schema name은 dApp 제공 문자열만으로 신뢰하지 않는다. bundled·signed clear-sign data가 chainId, contract, code/proxy condition에 결합될 때만 검증된 해석으로 표시한다.

ERC-7730 사용 시 다음을 적용한다.

- ERC 문서 자체의 현재 status와 별개로, production은 registry build 시점에 **immutable released/Active**로 확인된 schema version만 pin한다.
- `-next` draft와 release-candidate schema는 production에서 사용하지 않는다.
- released descriptor도 권위 있는 signing payload가 아니라 보조 metadata다. 서명된 registry, contract/code/proxy context와 결합되지 않으면 검증된 해석으로 표시하지 않는다.

### 8.6 EIP-7702

EIP-7702 type 4와 authorization은 EOA의 동작을 바꾸는 고위험 기능이다.

- 초기 릴리스는 type 4 transaction과 authorization signing을 거부한다.
- account 화면과 모든 approval 화면에 account code/delegation 상태를 표시한다.
- delegated account의 일반 type 0/1/2 transaction도 별도 위험 badge를 갖는다.
- 상태는 RPC 관측값이므로 endpoint, block number/hash를 표시한다.
- 향후 지원하려면 별도 module과 review가 필요하며 다음을 표시한다.
  - authority account
  - chain scope와 `chain_id=0` 여부
  - delegate full address와 code hash
  - authorization nonce
  - 기존/변경 후 delegation
  - revoke 여부
  - outer type 4 transaction 전체 field
- delegation 변경은 2단계 승인과 독립 simulation을 요구한다.
- outer execution이 실패해도 authorization 처리가 되돌아가지 않을 수 있음을 명시한다.

### 8.7 EIP-5792와 account abstraction

- `wallet_getCapabilities`는 실제 capability만 보고하며, 요청 account가 site에 연결되지 않았으면 4100으로 거부한다. 지원 여부와 계정 정보를 불필요하게 노출하지 않는다.
- 초기 EOA 릴리스는 `wallet_sendCalls`/`wallet_getCallsStatus`/`wallet_showCallsStatus`를 4200으로 명시적 거부한다.
- 지원 시 order, chain, from, atomicity, capability semantics, status lifecycle 전체를 구현한다.
- unsupported required capability가 있으면 batch 전체를 거부한다.
- 일부 call만 조용히 실행하지 않는다.
- paymaster, ERC-4337 UserOperation, EIP-7702 upgrade를 암묵적으로 활성화하지 않는다.
- batch 전체 합계와 각 call을 개별 검토 가능하게 한다.

---

## 9. 트랜잭션 구성, nonce와 broadcast

### 9.1 초기 지원 transaction type

지원:

- legacy type 0 — 반드시 EIP-155 replay-protected form만 생성
- EIP-2930 type 1
- EIP-1559 type 2

초기 비지원:

- EIP-4844 type 3 blob transaction
- EIP-7702 type 4
- unknown EIP-2718 type
- chain-specific custom envelope

비지원 type을 무시하거나 type 2로 변환하지 않는다.

### 9.2 request normalization

- `from`, `to`, `value`, `data/input`, `gas`, fee, nonce, access list, type, chainId를 strict schema로 검증한다.
- `data`와 `input`이 모두 있고 다르면 거부한다.
- `gasPrice`와 EIP-1559 fee field가 충돌하면 거부한다.
- access-list address/storage-key length, duplicate, total count를 검증한다.
- type 0에서 unprotected signature를 생성하거나 import해 재서명하지 않는다.
- 누락 field는 wallet policy로 채우되 approval 전에 최종값을 고정한다.
- dApp가 준 explicit value를 조용히 덮어쓰지 않는다.
- `to=null`은 contract creation으로 별도 표시한다.

### 9.3 address와 value

- 모든 address는 정확히 20-byte인지 검증한다.
- UI는 EIP-55 checksum을 사용하고 invalid mixed-case checksum은 거부한다.
- zero/burn address는 경고한다.
- 256-bit arithmetic overflow/underflow를 검사한다.
- token human amount와 함께 raw base-unit value와 decimals provenance를 확인 가능하게 한다.
- `to`, spender, operator, verifyingContract, delegate는 approval 화면에서 축약하지 않는다.

### 9.4 fee와 gas

- gas estimate와 fee suggestion은 RPC 보조값이며 권위가 아니다.
- approval 화면에 gas limit, fee model, gas price 또는 max fee/priority fee, **maximum total fee**, base fee와 source를 표시한다.
- estimate failure를 성공처럼 처리하지 않는다.
- 최종 gas/fee가 바뀌면 다시 승인한다.

#### 프로토콜 유효성 한도와 사용자 정책 한도의 분리

두 종류의 상한을 혼동하지 않는다. 성격이 다르므로 처리도 다르다.

- **사용자 정책 cap**: 과다 지출 방지를 위한 로컬 정책이다.
  chain별로 제공하며, 초과 시 별도 high-risk 재확인 또는 거부로 처리한다.
  사용자가 인지하고 통과시킬 수 있다.
- **프로토콜 유효성 한도**: 초과하면 합의 규칙상 트랜잭션 자체가 무효다.
  대표적으로 트랜잭션당 가스 상한(Ethereum mainnet은 Fusaka 활성화 이후 EIP-7825의 `2^24` 가스)이 있다.
  **재확인으로 통과시킬 수 없으며 서명 전에 fail closed 한다.**

요구사항:

- registry entry의 protocol limit(§11.1)을 서명 전에 검사한다.
- 초과 요청은 승인 화면에 도달하기 전에 거부하고, 사용자 정책 cap 초과와 구분되는 사유를 표시한다.
- 이 검사는 §1.6의 fail-closed 불변식에 속한다. 서명 후 broadcast 실패로 발견하지 않는다.
  무효 트랜잭션을 서명하면 nonce reservation과 pending ledger에 불필요한 혼란이 생긴다.
- 한도 값은 하드포크로 변경되므로 명세 본문의 규범 값이 아니라 registry versioned data에서 온다.
- registry entry에 값이 없는 chain은 해당 검사를 생략하되, **검증되지 않았음을 approval 화면에 표시**한다.
  값 부재를 무제한으로 해석하지 않는다.
- 여러 chain이 서로 다른 한도와 fee model을 가지므로 chain 전환 시 재검사한다.

### 9.5 nonce 관리

단순 request serialization만으로 충분하지 않다.

- account+chain mutex와 pending nonce ledger를 둔다.
- RPC `pending` nonce, local pending transaction, 외부 wallet transaction을 비교한다.
- nonce를 approval 단계에서 reserve하고 reject/expiry 때 해제한다.
- same nonce conflict를 감지한다.
- dApp-specified nonce는 advanced flow로 표시한다.
- replacement/cancel은 기존 tx hash, nonce, fee 변화, 예상 효과를 표시한다.
- approval 대기 중 external nonce 변화가 감지되면 request를 재구성하고 다시 승인한다.
- **포함되었던 transaction이 reorg/drop으로 사라지면 해당 nonce를 다시 미사용으로 되돌린다.**
  단일 confirmation을 근거로 nonce를 영구 소비 처리하지 않는다.
- ledger는 chain의 latest nonce를 권위로 삼아 주기적으로 재조정하며,
  로컬 기록과 chain 상태가 어긋나면 로컬 추정을 우선하지 않는다.
- 재조정 결과 사용자가 이미 본 pending 목록이 바뀌면 조용히 갱신하지 않고 명시적으로 알린다.

### 9.6 서명 후 검증

- signed bytes를 decode해 approved object와 다시 비교한다.
- recovered sender가 selected account와 일치해야 한다.
- chainId, type, nonce, to, value, data, gas, fee, access list가 정확히 일치해야 한다.
- local tx hash를 계산한다.

### 9.7 broadcast

- 기본은 하나의 명시된 write endpoint로 `eth_sendRawTransaction`을 호출한다.
- RPC return hash가 local hash와 다르면 endpoint error다.
- timeout 뒤 새 transaction을 즉시 만들지 않고 local hash로 조회한다.
- 동일 signed bytes 재전송은 가능하지만 기록·표시한다.
- fee replacement는 새 payload이므로 새 승인이 필요하다.
- unbroadcast signed transaction을 disk에 보존해야 하면 vault 수준으로 암호화하고 lifetime을 제한한다.

#### broadcast 이후 lifecycle

broadcast는 종료 상태가 아니다. 다음 전이를 명시적으로 추적한다.

`SUBMITTED → PENDING → INCLUDED → (CONFIRMED → FINALIZED | REORGED | DROPPED | REPLACED)`

- **단일 confirmation을 확정으로 표시하지 않는다.** 포함된 transaction은 reorg로 사라질 수 있다.
- confirmation depth 또는 chain이 제공하는 finality 정보를 함께 표시하고,
  그 값의 출처(endpoint, block number/hash)를 밝힌다.
- mempool에서 evict되었거나 장기간 미포함인 transaction은 DROPPED 후보로 구분해 표시하며,
  사용자에게 replacement/cancel 경로를 안내한다.
- REORGED/DROPPED 전이 시 §9.5의 nonce ledger 재조정을 수행한다.
- 상태 변화는 RPC 관측값이므로 receipt와 inclusion 정보를 무조건 신뢰하지 않는다.
  high-risk 확인이 필요하면 독립 endpoint로 교차 확인한다.
- **L2와 sequencer 기반 chain의 즉시 confirmation은 sequencer의 약속이며 L1 확정이 아니다.**
  registry에 해당 chain의 확정 모델이 기록되어 있으면 그에 맞게 표시하고,
  soft confirmation을 최종 확정처럼 표현하지 않는다.

---

## 10. Clear-signing, decoding과 simulation

### 10.1 approval 정보의 권위 순서

1. exact payload에서 직접 도출한 canonical field
2. bundled·검증된 schema에 결합된 해석
3. RPC simulation/trace
4. dApp 또는 원격 metadata가 주장한 설명

하위 정보가 상위 정보를 덮어쓰지 않는다.

### 10.2 calldata

- 항상 selector, target full address, calldata byte length/hash를 표시한다.
- 내장 decoder 최소 대상:
  - `transfer`
  - `transferFrom`
  - `approve`
  - `increaseAllowance`
  - `setApprovalForAll`
  - ERC-721/1155 safe transfer variants
- 4-byte selector만으로 ABI를 확정하지 않는다.
- 원격 ABI는 chainId+address+code hash 또는 검증된 deployment에 결합되지 않으면 추정이다.
- decode failure는 “안전”이 아니라 “해석 불가”로 표시한다.
- 일반 mode에서는 unknown calldata를 거부한다.
- advanced blind-sign mode를 제공하려면 별도 build flag/profile, 강한 경고, 재인증, full raw data view가 필요하다.

### 10.3 proxy와 code

- target code existence와 code hash를 표시할 수 있다.
- proxy detection은 보조 정보이며 완전성을 주장하지 않는다.
- verified schema가 proxy를 허용하면 implementation condition을 검사한다.
- high-value mode는 code/proxy 상태를 복수 endpoint로 비교할 수 있다.

### 10.4 simulation

- exact transaction field와 sender를 사용한다.
- 가능하면 EIP-1898 block hash에 state를 고정한다.
- endpoint, block number/hash, timestamp, method를 표시한다.
- 항상 **현재 RPC 상태에 대한 추정이며 실행 결과를 보장하지 않음**을 표시한다.
- state change, MEV, proxy upgrade, reorg, malicious RPC로 결과가 달라질 수 있다.
- 성공 simulation을 초록색 “안전” 판정으로 사용하지 않는다.
- native/token balance diff, allowance diff, NFT operator change를 우선 표시한다.
- trace unsupported/failure/disagreement를 숨기지 않는다.
- 독립 endpoint 교차 검증은 privacy 비용을 함께 경고한다.

### 10.5 UI 위험 표시

- 색상 외에 icon과 text를 함께 사용한다.
- infinite approval, NFT-all approval, unknown calldata, contract creation, delegate change, cross-chain signature, abnormal fee를 별도 분류한다.
- approve button은 default focus가 아니며 Enter/Space accidental activation을 막는다.
- window가 cursor 아래에 갑자기 나타나지 않고 click-through를 방지한다.
- high-risk는 2단계 확인 또는 hold-to-confirm을 사용한다.
- request queue, duplicate collapse, rate limit, expiry를 둔다.

---

## 11. 체인 registry와 RPC

### 11.1 registry entry

chain list는 명세 본문이 아니라 별도 signed/versioned data artifact로 관리한다.

각 entry는 최소 다음을 포함한다.

- chainId
- canonical name
- native asset symbol/decimals
- mainnet/testnet/deprecated status
- genesis block hash 또는 검토된 chain fingerprint
- 선택적 finalized checkpoint
- supported transaction types와 fee model
- **protocol limits** — 트랜잭션당 가스 상한 등 초과 시 트랜잭션이 무효가 되는 합의 규칙 값과
  그 값이 적용되는 fork/기준 시점. 값이 없으면 `unverified`로 표기하며 무제한을 의미하지 않는다
- **확정 모델** — reorg 특성, 권장 confirmation depth, sequencer 기반 soft confirmation 여부
- explorer URLs
- default RPC endpoints
- official source와 review date
- entry version과 expiry/review date

### 11.2 최신성·서명

- registry는 app release에 내장되거나 signed data-only update로만 갱신한다.
- General Mainnet/Hardened Public에서는 registry signing key를 executable release key와 분리한다. Single-maintainer baseline에서 같은 key를 쓰는 예외는 §15.5에 따르며, 이때 registry 변경은 unattended data update가 아니라 full release로 취급한다.
- remote registry를 자동 신뢰하지 않는다.
- version, expiry, rollback protection을 검증한다.
- deprecated/EOL chain은 신규 기본 목록에서 제외하고 기존 사용자에게 경고한다.
- testnet 이름, 역할, 교체 일정은 명세 본문의 규범 값이 아니다. 각 registry release 때 공식 운영 source와 실제 endpoint 상태를 다시 검증하며 과거의 예정 일정을 현재 사실로 간주하지 않는다.
- L1/L2/testnet 목록은 명세에 영구 고정하지 않고 registry release에서 관리한다.
- **protocol limit과 확정 모델은 하드포크로 변경된다.** registry release마다 각 chain의 현재 fork 상태를
  공식 source로 재확인하고, 확인되지 않은 값은 추정치로 채우지 않고 `unverified`로 남긴다.

### 11.3 chain 검증

- dApp의 name, symbol, decimals, explorer는 권위가 아니다.
- `eth_chainId`가 요청 chainId와 일치해야 한다.
- known chain은 가능하면 genesis hash/fingerprint도 대조한다.
- chainId+genesis 검사가 malicious RPC의 canonical membership을 암호학적으로 증명하지는 않음을 문서화한다.
- high-risk user는 복수 독립 endpoint 또는 own node를 사용할 수 있다.
- failover 때 동일 검증을 반복한다.
- explorer link는 registry URL만 기본 활성화하고 클릭 전 full host를 표시한다.
- chain switch는 모든 pending chain-specific request/approval을 취소한다.
- add와 switch를 외부 요청 하나로 자동 처리하지 않는다.

### 11.4 unknown/custom chain

- 수동 추가 unknown chain은 `UNVERIFIED CHAIN`으로 표시한다.
- chainId, RPC host, genesis hash, native asset를 전체 표시한다.
- known chainId를 unknown metadata로 덮어쓰지 못하게 한다.
- custom transaction format은 별도 구현 없이는 지원하지 않는다.

### 11.5 RPC URL와 SSRF

- dApp-proposed RPC는 HTTPS만 허용한다.
- userinfo, `javascript:`, `data:`, `file:`, non-HTTP scheme을 거부한다.
- redirect는 기본 금지한다.
- dApp-originated request는 loopback, private, link-local, multicast, cloud metadata address 접근을 막는다.
- DNS resolve 뒤 actual IP를 검사하고 rebinding을 고려한다.
- localhost는 developer mode에서 사용자가 직접 추가한 `127.0.0.1`/`::1`만 허용한다.
- private-LAN RPC는 별도 advanced setting과 경고가 필요하다.
- TLS verification disable option은 제공하지 않는다.

### 11.6 RPC parser와 resource limit

- request/response byte limit, JSON depth, array length, timeout, redirect, concurrency limit을 둔다.
- quantity는 canonical hex와 범위를 검증한다.
- error body를 그대로 log/UI에 넣지 않는다.
- URL path/query/header credential을 log에 남기지 않는다.
- native host와 Broker 양쪽에 독립 limit을 둔다.

### 11.7 credential

- API-key URL과 custom header는 secret이다.
- vault 또는 별도 encrypted credential store에 저장한다.
- UI에는 scheme+host만 기본 표시하고 path/query/header를 mask한다.
- basic-auth userinfo URL은 거부한다.
- export 기본값은 credential 제외다.

### 11.8 privacy와 RPC 불신

- endpoint가 IP, address, account linkage, query time을 관측할 수 있음을 설명한다.
- endpoint cross-check는 정확성을 높이지만 더 많은 사업자에게 정보를 노출한다.
- polling interval, background stop, account별 endpoint 분리를 제공할 수 있다.
- balance, nonce, token metadata, simulation, receipt는 모두 RPC가 거짓말할 수 있는 값이다.

---

## 12. 브라우저 확장, provider와 IPC

### 12.1 origin 신뢰 한계

native messaging이 native host에 보장하는 caller는 **extension ID**이지 dApp web origin이 아니다.

- page/top origin은 extension이 수집해 전달한다.
- 정상 extension에서는 site permission과 표시용으로 사용한다.
- compromised extension은 이를 위조할 수 있다.
- origin은 key security의 독립 신뢰 근거가 아니다.
- “extension이 완전히 불신되어도 origin permission이 완전 보장된다”는 주장을 하지 않는다.

### 12.2 extension 구현

- Manifest V3를 사용한다.
- remote hosted code, `eval`, dynamic code generation, remote script/WASM을 금지한다.
- build step/npm dependency 없는 plain audited JavaScript module을 기본으로 한다.
- package 내부 static asset만 사용한다.
- strict extension CSP를 적용하고 untrusted HTML을 `innerHTML`로 삽입하지 않는다.
- permission은 `nativeMessaging`과 필요한 최소 content-script/storage 범위로 제한한다.
- broad tabs/history/clipboard/webRequest permission은 명확한 근거 없이는 사용하지 않는다.
- provider object와 EIP-6963 detail을 freeze한다.
- EIP-6963 icon은 package 내부 PNG/WebP data URI를 사용하고 SVG를 사용하지 않는다.

### 12.3 provider injection과 document lifetime

- secure context에만 inject한다.
- third-party iframe에는 기본 inject하지 않는다.
- sandboxed frame과 opaque/null origin을 제한한다.
- localhost exception은 explicit developer setting으로만 둔다.
- account는 기본 미노출이고 `eth_accounts`는 승인 계정만 반환한다.
- request를 browser profile, tabId, frameId, documentId, top/frame origin, extension nonce에 결합한다.
- navigation, frame detach, document replacement, origin change, service-worker restart 뒤 불확실한 request는 취소한다.
- response는 같은 document/channel에만 전달한다.
- page↔content bridge는 strict schema, size limit, `event.source` check, channel nonce를 사용한다.
- DOM/HTML 문자열을 protocol로 사용하지 않는다.

### 12.4 EIP-1193 behavior

- `request`, `on`, `removeListener` semantics를 준수한다.
- error code를 일관되게 쓴다.
  - 4001 user rejected
  - 4100 unauthorized
  - 4200 unsupported method
  - 4900 disconnected
  - 4901 chain disconnected
- `accountsChanged`, `chainChanged`, `connect`, `disconnect`를 정확히 발생시킨다.
- `wallet_getPermissions`/`wallet_requestPermissions`을 지원한다.
- chain switch 시 pending request를 취소한다.

### 12.5 초기 method support matrix

| Method | 상태 | 정책 |
|---|---|---|
| `eth_requestAccounts`, `eth_accounts` | 지원 | native 연결 승인, 최소 계정 노출, unlock 불필요 |
| `eth_chainId`, `net_version` | 지원 | Broker 선택 chain만 반환 |
| 검토된 read-only `eth_*` | 지원 | allowlist RPC proxy |
| `eth_sendTransaction` | 지원 | type 0/1/2, exact payload 승인 |
| `personal_sign` | 지원 | §8.3 |
| `eth_signTypedData_v4` | 지원 | §8.4~8.5 |
| `wallet_switchEthereumChain` | 지원 | 승인, pending 취소 |
| `wallet_addEthereumChain` | 지원 | registry/SSRF/chain 검증 |
| `wallet_watchAsset` | 지원 | §12.6 |
| permission methods | 지원 | 연결 권한만 기억 가능 |
| `wallet_getCapabilities` | 지원 | 실제 capability만 보고 |
| `wallet_sendCalls`, `wallet_getCallsStatus`, `wallet_showCallsStatus` | 초기 비지원 | 4200, partial execution 금지 |
| `eth_sign`, `eth_signTransaction`, `eth_sendRawTransaction` | 비지원 | raw/blind signing 차단 |
| typed-data v1/v3, encryption/decryption | 비지원 | 4200 |
| unknown method | 비지원 | RPC로 자동 전달하지 않음 |

### 12.6 `wallet_watchAsset`

- 초기에는 EIP-747 ERC-20만 처리한다.
- chainId와 full contract address를 표시하고 사용자 승인을 받는다.
- contract code, decimals range, symbol/name의 control/bidi/homoglyph를 검사한다.
- dApp metadata와 on-chain 응답이 다르면 경고한다.
- contract address를 최종 identity로 사용한다.
- dApp image URL을 fetch/render하지 않는다.
- 응답이 기존 watch 상태를 불필요하게 노출하지 않게 한다.

### 12.7 method firewall

- wallet-local: account, chain, permission, add/switch/watchAsset
- signing/write: explicit allowlist와 native approval
- read-only RPC: 검토된 allowlist만 proxy
- 금지: `personal_*`, `admin_*`, `debug_*`, `engine_*`, `miner_*`, `txpool_*`, dApp의 `eth_sendRawTransaction`
- unknown method를 무조건 RPC에 전달하지 않는다.

### 12.8 account permission

- permission은 browser profile/extension install identity/top origin/frame origin/account/chain 범위로 저장한다.
- connection approval과 signature approval을 구분한다.
- connection은 기억할 수 있으나 signature는 기억하지 않는다.
- expiry와 즉시 revoke를 제공한다.
- extension compromise 시 origin permission을 속일 수 있다는 한계를 표시한다.

### 12.9 native messaging

- host manifest allowed origin을 정확한 extension ID로 고정한다.
- Chromium/Firefox manifest 차이를 별도 구현·테스트한다.
- protocol은 version, role, request ID, message type을 포함한다.
- JSON UTF-8 framing을 strict하게 parse하고 duplicate key를 거부한다.
- 양방향 1 MiB hard limit을 적용한다.
- stdout에는 protocol frame만 쓰고 log는 stderr로 보낸다.
- timeout, cancellation, duplicate ID, replay를 처리한다.
- Windows는 binary stdio mode를 명시적으로 설정한다.

### 12.10 local IPC

Broker 공개 IPC:

- localhost TCP를 사용하지 않는다.
- Linux: owner-only runtime dir, UDS 0600, parent 0700, `SO_PEERCRED`, symlink/path 검사.
- macOS: owner-only UDS와 peer credential 확인.
- Windows: current SID 한정 DACL, `PIPE_REJECT_REMOTE_CLIENTS`, first-pipe-instance, remote client 거부.
- protocol version/role handshake, bounded frame, timeout, request nonce를 적용한다.
- peer UID/SID는 같은 사용자 malware를 구분하지 못함을 명시한다.

Broker↔Key Agent, Key Agent↔helper는 공개 IPC 대신 inherited private channel을 사용한다.


---

## 13. GUI, CLI와 사용성

### 13.1 GUI 기술

- 웹뷰 기반 framework를 사용하지 않는다.
- native UI 또는 검토된 비웹 renderer를 사용한다.
- 일반 Approval GUI는 Authorization TCB다.
- Secret Input Frontend와 recovery/export 화면은 Secret TCB로 별도 계산한다.
- GUI 없는 headless/CLI build가 가능하고 dependency tree 차이를 출력한다.
- remote font/image와 telemetry SDK를 사용하지 않는다.

### 13.2 approval 화면 필수 field

- selected account label과 full address
- browser-reported origin과 `독립 검증 안 됨` 상태
- chain name, chainId, mainnet/testnet/deprecated/custom status
- sign method 또는 transaction type
- nonce
- full critical address
- native/token amount와 필요 시 raw base units
- account delegation/code 상태와 provenance
- calldata selector/hash 또는 typed-data domain/hash
- maximum fee
- protocol limit 검증 상태 (검증됨 / `unverified`)
- simulation provenance와 한계
- 모든 risk warning

### 13.3 address 표시

- 일반 목록은 축약할 수 있다.
- approval 화면의 critical address는 full EIP-55 string을 기본 표시한다.
- user label 옆에서도 address를 숨기지 않는다.
- copy는 full checksum address를 사용한다.
- recent history의 유사 address를 contact로 자동 제안하지 않는다.

### 13.4 anti-spoofing

- 선택적 user anti-phishing phrase를 native approval window에 표시한다.
- app identity, version, code-signing status를 확인 가능하게 한다.
- web page가 모방할 수 있는 popup 모양만 보안 근거로 삼지 않는다.
- OS notification에는 기본적으로 amount/address를 노출하지 않는다.
- approval helper executable identity가 manifest와 다르면 창을 띄우지 않고 중단한다.

### 13.5 CLI

- GUI와 같은 policy engine/canonical display를 사용한다.
- secret과 approval은 controlling TTY에서만 받는다.
- untrusted string의 ANSI/control sequence를 escape한다.
- shell history에 secret이 들어갈 option을 제공하지 않는다.
- `--json`은 secret을 포함하지 않고 schema version을 갖는다.
- SSH/remote terminal 사용 시 입력·화면 trust 한계를 경고한다.

### 13.6 읽기와 쓰기

잠금 없이 허용:

- public store의 account address
- chain setting
- cached balance/history
- pending transaction 상태와 confirmation depth
- connected site 목록

unlock과 fresh approval 필요:

- 모든 signature
- mnemonic/private key export
- BIP39 passphrase policy 변경
- trusted label/security policy 변경
- RPC credential export

### 13.7 사용자 policy

- contact, fee cap, amount warning threshold를 제공할 수 있다.
- trusted address와 small-amount threshold는 경고 수준만 조정하며 signature approval을 생략하지 않는다.
- site account connection은 기억할 수 있다.
- signature, permit, EIP-7702 authorization approval은 기억하지 않는다.

---

## 14. 토큰, metadata, history와 privacy

### 14.1 token identity

- token identity의 기본 key는 `(chainId, contract address)`다.
- symbol/name/decimals만으로 token을 식별하지 않는다.
- approval 화면에 contract full address를 표시한다.
- dApp metadata와 on-chain response가 다르면 경고한다.
- on-chain metadata도 malicious contract가 반환할 수 있음을 고려한다.

### 14.2 remote media

- 초기 릴리스는 token/NFT remote image를 표시하지 않는다.
- SVG, HTML, scriptable media를 렌더링하지 않는다.
- 향후 지원 시 별도 sandbox process, byte/pixel/decompression limit, no-cookie fetch, private-IP 차단을 요구한다.

### 14.3 history와 address poisoning

- RPC/indexer history는 untrusted 정보다.
- zero-value transfer, fake token, 유사 prefix/suffix address를 구분한다.
- history address를 contact로 자동 등록하지 않는다.
- `최근 보낸 주소` shortcut은 full-address 확인을 요구한다.
- user-created contact만 trusted label로 취급한다.

### 14.4 ENS/name service

- 초기 릴리스에서는 필수 기능이 아니다.
- 지원 시 chain, resolver provenance, final full address를 표시한다.
- Unicode name은 escaped/punycode form을 함께 표시한다.
- name resolution failure나 reverse record만으로 identity를 확정하지 않는다.

### 14.5 telemetry

- 기본 telemetry와 automatic crash upload는 없다.
- opt-in diagnostics는 payload allowlist 방식으로 구성한다.
- address, tx/message content, full RPC URL/credential을 제외한다.
- remote kill switch나 executable logic download를 사용하지 않는다.

---

## 15. 공급망, build, release와 update

### 15.1 TCB inventory

각 release는 다음을 별도 제공한다.

- Secret TCB dependency tree — Key Agent와 Secret Input Frontend를 분리 표시
- Authorization TCB dependency tree
- Non-secret dependency tree
- compiler, linker, SDK, build container
- build script, procedural macro, FFI, unsafe 목록

### 15.2 dependency policy

- lockfile과 vendor source를 저장소에 포함한다.
- network-offline build가 가능해야 한다.
- 새 dependency는 사유, 대안, LOC, unsafe, build script, maintainer risk를 review한다.
- default feature를 맹목적으로 사용하지 않고 최소 feature를 명시한다.
- Secret TCB는 proc-macro/build.rs/unsafe dependency를 가능한 제거한다.
- source tarball/vendor tree hash와 upstream commit/tag provenance를 기록한다.
- dependency를 영구 동결하지 않고 advisory와 maintenance 상태를 정기 검토한다.

### 15.3 toolchain

- compiler/toolchain version을 pin한다.
- downloaded artifact checksum/signature를 검증한다.
- hermetic build environment를 versioned한다.
- Secret TCB는 두 독립 환경에서 재빌드해 hash 또는 허용된 차이를 비교한다.
- bootstrap compiler risk는 완전 제거할 수 없음을 명시하고 필요 시 diverse double-compilation 절차를 검토한다.

### 15.4 자동 gate

- format/lint, warnings-as-errors
- unit/integration/property/fuzz test
- dependency source/license/advisory 검사
- duplicate dependency/feature tree 검사
- unsafe/FFI/build script/proc-macro inventory diff
- offline build
- SBOM 생성
- reproducibility 검사
- Secret TCB network symbol/일반 GUI dependency 부재 검사
- helper manifest hash와 install ACL 검사
- extension remote-code/eval/CSP/permission 검사
- sanitizers, Miri 또는 동등한 UB 검사

### 15.5 release

#### 공통 요구사항

- manifest에 source commit, toolchain, artifact hash, SBOM, registry version, helper binary hash와 release profile을 기록한다.
- root/release private key는 개발·빌드·배포 서버와 분리된 offline 또는 hardware-protected 환경에서만 사용한다.
- key rotation, revocation, loss recovery를 첫 release 전에 실제 시험한다.
- release manifest는 monotonic version, artifact hash, 이전 release manifest hash를 포함하고 서명된다.
- Windows/macOS code signing은 배포 identity 확인에 쓰되 reproducible build의 대체로 삼지 않는다.
- platform signing 때문에 최종 bytes가 달라지면 서명 전 payload와 manifest를 기준으로 비교한다.
- installer는 user-writable path hijack, DLL search path, native-host manifest path 변조를 방지한다.

#### Single-maintainer baseline

1인 운영에서는 다음 축소 profile을 사용할 수 있다.

- root/targets threshold는 `1`일 수 있다.
- 단일 offline 또는 hardware-protected signing key와, 별도 장소의 sealed recovery copy를 사용한다.
- signing key는 평상시 개발 장치에 연결하지 않으며 모든 executable update는 수동 ceremony를 거친다.
- executable과 registry/clear-sign data에 같은 key를 사용한다면 data-only unattended update를 금지하고 모든 data 변경을 full release로 취급한다.
- release hash와 signature를 서로 독립된 두 공개 채널에 게시한다.
- 이 profile은 **단일 signing key compromise에 대한 저항을 제공하지 않는다**고 명시한다.

#### Hardened Public profile

- offline root는 최소 2-of-3 threshold를 사용한다.
- root, executable targets, chain registry, clear-sign data 역할을 서로 다른 key로 분리한다.
- 가능한 경우 key를 독립 장치·장소·관리자에 분산한다.
- targets/snapshot/timestamp 또는 동등한 TUF-style metadata로 version, expiry, mix-and-match, freeze와 rollback을 방어한다.
- public transparency/checkpoint 채널을 운영한다.

### 15.6 update

- Key Agent의 unattended silent auto-update를 금지한다.
- signature, role, version, expiry와 rollback policy를 검증하고 executable은 사용자 확인 뒤 적용한다.
- dedicated data role이 없는 Single-maintainer baseline에서는 registry/clear-sign data도 full release와 같은 절차를 따른다.
- dedicated data role을 사용하는 경우에도 strict schema, size/resource limit, version binding을 검증하고 executable code·script·template language로 해석하지 않는다.
- 만료된 update metadata는 **새 update 활성화만 차단**하며 기존 wallet의 unlock, recovery와 signing을 원격으로 중단시키지 않는다. 명확한 경고를 표시한다.
- highest accepted version/checkpoint를 로컬에 보관하고 낮은 version을 거부한다.
- 전체 OS snapshot 또는 디스크 rollback은 로컬 rollback 상태까지 되돌릴 수 있으므로, 강한 방어가 필요하면 외부 transparency/checkpoint와 대조한다.
- browser store extension auto-update는 별도 위험으로 기록한다.
- extension protocol/version이 비정상이면 Broker가 연결을 거부할 수 있다.
- update 실패 시 이전에 검증된 version으로 복귀한다.
- vault migration은 app update와 분리된 atomic transaction으로 처리한다.
- revoked release 또는 key compromise 시 사용자가 별도 채널에서 검증 가능한 incident notice 절차를 둔다.

---

## 16. 검증과 보안 test

### 16.1 공식 vector

최소 다음을 실제 assert한다.

- BIP39 12/15/18/21/24 word entropy↔mnemonic↔seed, NFKD, passphrase
- BIP32 leading-zero와 invalid-child edge case
- EIP-155 legacy signing
- EIP-2718 envelope
- EIP-2930 type 1
- EIP-1559 type 2
- EIP-191 personal message
- EIP-712 official case
- EIP-55 checksum
- vault format 자체 vector

### 16.2 differential test

production dependency와 다른 독립 구현으로 비교한다.

- path별 private/public derivation
- address
- transaction signing hash
- serialized unsigned/signed transaction
- recovered sender
- EIP-712 domain/message/final digest

### 16.3 fuzz target

- vault header/ciphertext parser
- BIP39 import parser
- JSON-RPC/native-messaging frame
- EIP-712 type/value parser
- RLP/typed transaction parser
- ABI/calldata decoder
- chain registry
- URL/SSRF validator
- token metadata parser
- approval protocol state machine

corpus에는 duplicate key, huge number, deep nesting, invalid UTF-8, bidi/control char, selector collision, truncated frame를 포함한다.

### 16.4 state machine

다음 전이를 명시하고 model/property test한다.

`RECEIVED → VALIDATED → RESOLVED → (SIMULATED 또는 SIMULATION_NA) → DISPLAYED → APPROVED → SIGNED → (BROADCAST 또는 BROADCAST_NA)`

- method별로 적용되지 않는 단계는 명시적 `*_NA` 상태로 기록하고 조용히 건너뛰지 않는다.
- reject/cancel/timeout/lock/chain change/document replacement는 terminal state다.
- APPROVED는 정확히 한 번 SIGNED로 전이한다.
- request digest가 다르면 전이가 실패한다.
- unsupported method/type와 **protocol limit 초과는 DISPLAYED 전에 fail closed**한다.

broadcast 이후 lifecycle도 별도 상태 기계로 model/property test한다.

`SUBMITTED → PENDING → INCLUDED → (CONFIRMED → FINALIZED | REORGED | DROPPED | REPLACED)`

- INCLUDED에서 REORGED/DROPPED로의 역전이가 허용되며, 이때 nonce 해제가 정확히 한 번 일어난다.
- FINALIZED는 terminal이며 되돌아가지 않는다. 어떤 depth를 FINALIZED로 볼지는 chain별 registry 값에서 온다.
- REPLACED는 같은 nonce의 다른 payload가 포함된 경우이며 원본 tx는 DROPPED로 수렴한다.

### 16.5 fault/concurrency test

- vault write 각 단계 crash
- RPC timeout 직전/직후 broadcast
- RPC hash mismatch
- protocol limit 초과 요청이 승인 화면에 도달하지 않고 거부되는지
- `unverified` protocol limit chain에서 표시가 누락되지 않는지
- 포함된 transaction의 reorg/drop 후 nonce ledger 재조정
- L2 soft confirmation이 최종 확정으로 표시되지 않는지
- 여러 dApp의 동시 nonce request
- 외부 wallet의 same-account nonce 사용
- suspend/resume/session lock
- extension service worker restart
- browser navigation/document replacement 중 response
- Broker/Key Agent/helper abnormal exit
- registry/update rollback, expiry, key rotation/revocation
- helper binary replacement와 user-writable install path
- delegated account의 type 0/1/2 request

### 16.6 platform integration

아래 중 **해당 release가 지원한다고 명시한 플랫폼·브라우저만** 필수 gate다. 미지원 대상은 배포 artifact를 제공하지 않는다.

- Windows named-pipe DACL, remote-client reject, native-host registry, `VirtualLock`
- Linux UDS permission/peer credential/runtime dir, `mlock`
- macOS socket/launch/lock behavior
- Chromium/Firefox native messaging
- extension ID 고정과 update
- GUI/headless dependency difference
- code-signing과 unsigned reproducibility comparison

### 16.7 독립 review

release candidate마다 다음 관점의 공격적 self-review를 먼저 기록한다.

- recoverability
- entropy와 key lifecycle
- crypto/signing correctness
- secret-input path와 memory hygiene
- display-sign binding
- EIP-712/permit/EIP-7702 risk
- nonce/broadcast
- chain/RPC/SSRF
- browser origin/document lifetime/permission limitation
- supply chain/release/update
- usability와 approval habituation

외부 독립 review는 다음을 만족한다.

- 검토자는 해당 구현의 주 작성자가 아니어야 한다.
- 최소 범위는 Secret TCB, vault/derivation/signing, canonical encoding, approval protocol과 release/update path다.
- 사용한 commit과 build artifact, 검토 방법, finding severity, 수정 commit과 재검증 결과를 공개 또는 보존한다.
- General Mainnet 진입 전 Critical/High finding은 모두 해결하거나 기능을 제거한다.
- Private Mainnet Canary는 외부 review 전에 가능하지만 §2.3의 격리·극소액·비배포 조건을 지켜야 한다.
- Hardened Public 및 고액 사용 권고에는 전문 외부 감사와 재현 빌드 검증을 요구한다.

---

## 17. 운영과 사고 대응

### 17.1 local audit log

- allowlist 기반 structured log를 쓴다.
- secret, full RPC URL, message/calldata 원문, full address를 기본 log에 넣지 않는다.
- security event는 request ID, method, chainId, endpoint host, result, local tx hash만 필요한 범위에서 기록한다.
- log는 user-only ACL과 rotation을 적용한다.

### 17.2 사용자 비상 기능

- 즉시 lock
- 모든 site permission revoke
- extension disconnect
- pending request 전체 reject
- RPC credential 삭제
- read-only recovery mode

remote kill switch는 제공하지 않는다.

### 17.3 vulnerability response

- security contact와 disclosure process를 공개한다.
- compromised release/extension/registry/clear-sign key의 revocation 절차를 제공한다.
- signer compromise 가능성이 있으면 새 안전 환경에서 mnemonic으로 복구하고 **새 seed**로 자산을 이동하도록 안내한다.
- software update만으로 이미 노출된 seed가 다시 안전해진다고 표현하지 않는다.

---

## 18. 필수 산출물

- threat model과 TCB inventory
- architecture/approval protocol ADR
- entropy/KDF/vault format 문서와 vector
- derivation/recovery guide
- chain registry schema, provenance, signing/update procedure
- RPC/SSRF policy
- EIP method support matrix
- transaction type support matrix
- dependency/unsafe/build-script inventory
- reproducible build/release verification guide
- platform hardening guide
- fuzz corpus/result
- self-review 및 independent review record
- release profile, signing-key ceremony와 rollback/transparency 문서
- 사용자용 plain-language recovery guide
- incident-response guide
- LLM/agent용 금지 규칙 요약

---

## 19. 구현 단계

### Phase 0 — 문서와 threat model

- invariants, TCB, format, support matrix 확정
- library candidate와 dependency budget 확정

### Phase 1 — offline secret core

- entropy, BIP39/BIP32, vault, typed signer
- network/GUI 없음
- official/differential vector 통과

### Phase 2 — Key Agent와 secret input

- inherited private IPC
- minimal Secret Input Frontend
- vault unlock/lock/zeroization

### Phase 3 — approval binding

- TTY Approval Frontend
- request digest와 one-shot approval
- state-machine/property test

### Phase 4 — read-only Broker/RPC

- chain registry, strict RPC, SSRF, balance
- signing 없음

### Phase 5 — type 0/1/2 transaction

- nonce ledger, fee, simulation, broadcast
- testnet integration

### Phase 6 — native GUI

- canonical renderer, accessibility, anti-spoofing
- Secret TCB dependency 증가 여부 재검토

### Phase 7 — browser extension

- EIP-1193/EIP-6963, permission, native messaging
- hostile-page/navigation integration test

### Phase 8 — signed canary와 review

- reproducible signed release
- §2.3 조건의 격리된 Private Mainnet Canary
- independent security review와 finding 수정
- review 통과 뒤 General Mainnet 승격

### Phase 9 — 선택 기능

- verified clear-sign registry
- hardware wallet
- EIP-5792
- EIP-7702는 별도 high-risk project

---

## 20. 알려진 한계

- software wallet은 hardware isolation과 물리 확인 화면을 제공하지 못한다.
- Authorization UI 손상은 키 원문 유출 없이도 잘못된 승인을 만들 수 있다.
- Secret Input Frontend 손상은 vault password/passphrase 유출로 이어질 수 있다.
- extension 손상은 dApp origin과 site permission을 속일 수 있다.
- chainId/genesis 확인만으로 canonical chain을 완전 증명할 수 없다.
- simulation은 미래 실행 결과를 보장하지 않는다.
- memory zeroization/page locking은 OS/compiler/hibernate에 대해 절대 보장이 아니다.
- token metadata/history는 malicious contract/RPC/indexer에 의해 조작될 수 있다.
- BIP39 passphrase 오타는 유효한 다른 wallet을 만들며 자동 검출할 수 없다.
- automatic account discovery는 token-only account를 놓칠 수 있다.
- 과거의 유효한 encrypted vault로 disk가 rollback된 사실은 local file만으로 완전 탐지할 수 없다.
- audit와 reproducible build는 malicious compiler/hardware를 완전히 제거하지 않는다.
- Single-maintainer baseline의 threshold-1 release key는 key compromise의 단일 실패 지점이다.
- local highest-version 기록은 전체 OS snapshot/disk rollback과 함께 되돌아갈 수 있다.
- 외부 review 전 Private Mainnet Canary는 실험 단계이며 일반 사용 안전성의 근거가 아니다.
- transaction 포함 여부와 confirmation depth는 RPC 관측값이며 reorg로 뒤집힐 수 있다. 지갑은 확정성을 보장하지 않는다.
- L2/sequencer chain의 즉시 confirmation은 sequencer의 약속이며 L1 확정과 다르다.
- registry의 protocol limit은 검토 시점의 값이다. 하드포크 이후 registry가 갱신되지 않으면 해당 검사는 무효하며, 이 경우 `unverified`로 표시될 뿐 안전을 보장하지 않는다.

---

## 21. 모바일 확장 — 범위 외

현재 구현 범위는 데스크톱이지만 §4.9의 platform-neutral core 제약은 현재부터 적용한다.

- typed request, canonical encoding, derivation, vault format과 signing policy는 OS·process model과 독립적으로 유지한다.
- core 입출력은 bounded byte array와 versioned simple data type으로 표현 가능해야 한다.
- 파일 경로, desktop IPC handle, window type과 UI toolkit type을 core 공개 인터페이스에 노출하지 않는다.
- storage, RNG, secure-memory와 user-authorization은 platform adapter로 분리한다.
- public FFI는 raw secret/raw hash signing을 노출하지 않으며 ownership·zeroization contract를 가진다.
- WalletConnect 등 mobile transport는 별도 non-secret module로 둔다.
- 모바일은 단일 OS process일 수 있으나 Secret-input path와 Authorization UI의 논리적 권한 분리는 유지한다.
- iOS/Android keystore가 seed를 직접 secp256k1 signing한다고 가정하지 않는다.
- 현실적 구조는 platform key로 vault key/seed를 wrapping하고 biometric으로 사용 허가하는 방식이다.
- device-bound wrapping은 mnemonic independent recovery를 대체하지 않는다.
- 작은 화면에서도 critical address/amount를 숨기거나 축약하지 않는다.

---

## 22. 규범·참고 자료

구현 시 특정 commit/date에 pin하여 검토한다.

- BIP-0032: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
- BIP-0039: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
- BIP-0044: https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki
- RFC 9106 Argon2: https://www.rfc-editor.org/rfc/rfc9106
- The Update Framework specification: https://theupdateframework.github.io/specification/latest/
- EIP-55: https://eips.ethereum.org/EIPS/eip-55
- EIP-155: https://eips.ethereum.org/EIPS/eip-155
- EIP-191: https://eips.ethereum.org/EIPS/eip-191
- EIP-712: https://eips.ethereum.org/EIPS/eip-712
- EIP-1193: https://eips.ethereum.org/EIPS/eip-1193
- EIP-1474: https://eips.ethereum.org/EIPS/eip-1474
- EIP-1898: https://eips.ethereum.org/EIPS/eip-1898
- EIP-2255: https://eips.ethereum.org/EIPS/eip-2255
- EIP-2718: https://eips.ethereum.org/EIPS/eip-2718
- EIP-2930: https://eips.ethereum.org/EIPS/eip-2930
- EIP-3085: https://eips.ethereum.org/EIPS/eip-3085
- EIP-3326: https://eips.ethereum.org/EIPS/eip-3326
- ERC-4361 SIWE: https://eips.ethereum.org/EIPS/eip-4361
- EIP-5593: https://eips.ethereum.org/EIPS/eip-5593
- EIP-5792: https://eips.ethereum.org/EIPS/eip-5792
- EIP-6963: https://eips.ethereum.org/EIPS/eip-6963
- EIP-747: https://eips.ethereum.org/EIPS/eip-747
- EIP-7702: https://eips.ethereum.org/EIPS/eip-7702
- EIP-7825 Transaction Gas Limit Cap: https://eips.ethereum.org/EIPS/eip-7825
- ERC-7730 Draft: https://eips.ethereum.org/EIPS/eip-7730
- Chromium Native Messaging: https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging
- Mozilla Native Messaging: https://developer.mozilla.org/docs/Mozilla/Add-ons/WebExtensions/Native_messaging
- Chrome MV3 remote hosted code: https://developer.chrome.com/docs/extensions/develop/migrate/remote-hosted-code
- Ethereum networks: https://ethereum.org/developers/docs/networks/
