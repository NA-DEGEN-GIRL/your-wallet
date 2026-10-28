# Your Wallet — 개인용 소프트웨어 지갑 명세 v3

- 상태: **구현 완료 · 수동 검증 대기** (M0–M8 구현, 마일스톤별 수동 체크리스트와 M9는 [spec/09](spec/09-testing.md)·`docs/acceptance/`에서 진행)
- 기준일: 2026-10-29
- 대상: Windows 11 x64 데스크톱 1대, Chrome 1개, 사용자 1명(작성자 본인)
- 이전 명세: v2.4와 Windows 격리 설계는 git 태그 `archive/spec-v2.4`(브랜치 `archive/windows-isolation`)에 보존. v3는 그 내용을 **대체**한다.
- 규범 용어: **MUST/반드시**, **SHOULD/권고**, **MAY/선택**. 이 문서와 `spec/` 세부 문서가 충돌하면 이 문서가 우선한다.

## 문서 구성

| 문서 | 내용 |
|---|---|
| `spec.md` (이 문서) | 목표, 위협 모델, 결정 사항(D-번호), 아키텍처, 마일스톤과 완료 조건 |
| [spec/01-repo-build.md](spec/01-repo-build.md) | 저장소 정리, 워크스페이스·크레이트, 의존성 허용 목록, lint, 검사 스크립트, 아카이브 이식 목록 |
| [spec/02-core-keys-vault.md](spec/02-core-keys-vault.md) | 엔트로피, BIP39·BIP32·SLIP-0010, vault v3 바이트 형식, 비밀번호, 잠금 상태 기계, 메모리 처리, 백업 확인 |
| [spec/03-evm.md](spec/03-evm.md) | EVM 체인 표, 주소·금액 규칙, 트랜잭션 구성·서명·검증, 가스·수수료, nonce, 시뮬레이션(필수), 해석·위험 규칙, 서명 메시지 |
| [spec/04-app-ui.md](spec/04-app-ui.md) | yw-app 화면·흐름, 승인 창, 비밀 표시 보호, 설정, 자동 잠금, 파일 위치 |
| [spec/05-browser.md](spec/05-browser.md) | 크롬 확장, native messaging, yw-host, named pipe 프로토콜, dApp 메서드·권한 |
| [spec/06-llm-explain.md](spec/06-llm-explain.md) | 선택 기능: LLM 거래 설명 |
| [spec/07-solana.md](spec/07-solana.md) | Solana 전송 전용 |
| [spec/08-bitcoin.md](spec/08-bitcoin.md) | Bitcoin 전송 전용 |
| [spec/09-testing.md](spec/09-testing.md) | 테스트 벡터, 퍼징, 수동 체크리스트, 마일스톤별 판정 기준 |

---

## 1. 목표

1. **직접 검토 가능한 작은 지갑.** 키를 다루는 코드와 그 의존성을 혼자 읽을 수 있는 규모로 유지한다.
2. **공급망 오염 차단.** 지갑 본체는 고정·검토된 소수 크레이트만 쓰고, 크롬 확장은 npm 의존성 0인 순수 JS로 만든다. 확장은 비밀을 전혀 갖지 않는다.
3. **무엇에 서명하는지 정확히 안다.** 승인 창은 dApp·확장이 보낸 설명이 아니라 코어가 실제 서명 대상을 직접 해석한 내용과 **시뮬레이션 결과**를 보여준다. 시뮬레이션을 할 수 없거나 실패한 경우에는 그 사실을 고위험 경고로 분명히 보여주고, 사용자가 확인하면 서명할 수 있다.
4. **표준 복구.** 24단어 BIP39 니모닉 하나로 다른 표준 지갑에서 모든 체인 자산을 복구할 수 있다. 예외: 가져온 개인키 계정은 니모닉 밖이며 원래 개인키로만 복구한다(D9, D29).
5. **실사용.** EVM은 dApp 연결까지, Solana·Bitcoin은 지갑 앱에서 보내기·받기만 한다.

## 2. 위협 모델

### 2.1 방어 대상 (각 항목은 자동 테스트 또는 1회 체크리스트로 판정한다)

| 공격자 | 방어 방법 |
|---|---|
| 악성 dApp, 피싱 사이트, 오염된 dApp 프론트엔드(npm 포함) | 승인 창은 코어가 실제 payload에서 만든 표시와 시뮬레이션 결과만 근거로 한다. `eth_sign` 미지원. 무한 승인·permit·setApprovalForAll·해석 불가 호출은 고위험 표시. |
| 다른 크롬 확장, 오염된 웹페이지 스크립트 | 확장은 비밀이 없다. native messaging은 고정된 확장 ID만 허용한다. 승인은 브라우저 밖 네이티브 창에서만 한다. |
| 우리 확장·yw-host 오염 | 요청 위조·스팸은 가능하지만 승인 창 내용은 코어가 다시 만들므로 다른 거래로 서명시킬 수 없다. |
| 악성·오류 RPC(QuickNode·알케미 등 공급자 포함) | 서명 대상은 코어가 만든다. 체인 ID·제네시스 해시 고정, 수수료 상한, BTC 입력 금액은 이전 트랜잭션 해시로 검증. RPC가 보낸 문자열은 화면에 그대로 표시하지 않는다(예외: AI 설명 패널은 [06](spec/06-llm-explain.md) §5–§6 필터를 거친 파생 텍스트로 별도 표시). |
| 노트북·디스크·백업 파일 도난 | Argon2id(256 MiB) + XChaCha20-Poly1305 vault. BitLocker 사용 권고. |
| 지갑 자체 의존성 오염 | 버전 고정, 허용 목록 검사, 허용 목록 크레이트의 로컬 레지스트리 소스 검토(`check-core-deps.mjs --list`), Cargo.lock 변경 검토. |
| 우발적 비밀 노출(화면 공유·녹화·클립보드 기록·크래시 덤프·로그) | 비밀 창 화면 캡처 제외, 복사 기본 금지, 클립보드 기록·동기화 제외, 메모리 즉시 소거, 텔레메트리·덤프 업로드 없음. |
| 약한 시드 | OS CSPRNG 256비트, 실패 시 생성 중단, 대체 난수원 없음. |

### 2.2 비목표 (방어를 주장하지 않으며 게이트로 만들지 않는다)

- 같은 Windows 사용자 권한으로 실행된 악성코드, 관리자·커널·드라이버·펌웨어 장악, UAC 우회. **PC가 장악되면 지갑도 장악된 것으로 본다.**
- 전원이 켜진 상태의 탈취, evil maid, DMA, cold boot, 사이드채널. 최대 절전 파일(hiberfil.sys)·페이지 파일에 비밀이 남을 가능성(VirtualLock은 최대 절전을 막지 못한다 — BitLocker로 완화).
- 사용자가 정확히 표시된 악성 거래를 승인하는 것.
- 다중 사용자, 바이너리 배포(미리 빌드한 실행 파일·설치 패키지), 코드 서명·자동 업데이트, 고액 장기 보관. 저장소는 소스로만 공개할 수 있고(예: GitHub), 설치는 각자 자기 PC에서 소스를 빌드해 한다(D1). 다른 사람의 사용을 지원하는 제품이 아니다.
- 비ASCII 비밀번호·BIP39 passphrase(다른 지갑에서 만든 한글 passphrase 복구 포함).
- RPC 공급자 단일 의존에서 오는 잔여 위험: 잔액·확인 수·UTXO 완전성 위조, Solana 만료 판정 위조에 의한 이중 지불(로컬 시계 90초 검사로 범위를 줄인다). 서명 대상 자체는 RPC가 바꿀 수 없다.
- LLM 설명(D21)의 정확성. AI 텍스트는 별도 패널의 참고 정보이며 승인 근거가 아니다.

### 2.3 게이트 규칙

- 모든 완료 조건은 **자동 테스트 통과** 또는 **체크리스트 1회 수행**으로 판정할 수 있어야 한다.
- "검증할 수 없으면 차단" 형태의 조건은 금지한다. 증명할 수 없는 속성은 §2.2로 옮기고 이유를 한 줄로 적는다.
- 문서 내용을 해시로 고정하는 검사, 소스 모양을 문자열로 고정하는 검사는 만들지 않는다.

### 2.4 운영 권고 (사용자 체크리스트, 코드 게이트 아님)

- 일상 Windows 계정은 표준 사용자(관리자 아님)로 쓴다.
- BitLocker를 켠다.
- 핫 잔액은 잃어도 되는 금액으로 한정한다.
- 니모닉은 종이(또는 금속)에만 적고, 사진·클라우드·메신저에 남기지 않는다.

---

## 3. 결정 사항

결정을 바꾸려면 이 표를 먼저 고친다. 세부 문서는 이 표를 따른다.

| ID | 결정 |
|---|---|
| D1 | 대상 환경: Windows 11 x64(22H2 이상), Chrome 120 이상. 배포 형태: **소스만**. 미리 빌드한 실행 파일·zip·설치 패키지는 만들지도 배포하지도 않는다. 설치는 소스 체크아웃(Git 또는 GitHub "Download ZIP")의 루트 `install.cmd`(→ `scripts/install.ps1`) 한 번으로 한다: 빌드 도구(rustup, Visual Studio Build Tools C++) 확인 — 없으면 winget 명령을 보여 주고 사용자가 동의할 때만 실행 — → `cargo build --release --locked -p yw-app -p yw-host` → 관리자 권한 없이 현재 사용자 범위(`%LOCALAPPDATA%\Programs\YourWallet`: 두 exe와 확장 런타임 파일 사본, HKCU native host 등록, 시작 메뉴 바로가기)에 설치. Chrome 확장은 사용자가 설치 폴더의 `extension\`을 직접 압축해제 로드한다. 업데이트는 `git pull` 후 `install.cmd` 재실행, 제거는 `uninstall.cmd`. 코드 서명은 하지 않는다. 무결성의 기준은 소스 커밋과 `Cargo.lock` 체크섬이다([spec/01](spec/01-repo-build.md) §9). |
| D2 | 위협 모델은 §2를 따른다. 별도 Windows 계정·서비스·LPAC·프로세스 격리 장치는 만들지 않는다. |
| D3 | 프로세스: `extension`(순수 JS) → Chrome이 실행하는 `yw-host.exe` → 사용자 전용 named pipe → `yw-app.exe`(지갑 본체, 단일 인스턴스). 키·vault·승인 창·RPC는 모두 yw-app에 있다. |
| D4 | 크레이트: `yw-core`(플랫폼 독립, 네트워크·GUI·unsafe 없음), `yw-json`(자체 엄격 JSON, 의존성 0), `yw-win`(windows-sys 래퍼, **unsafe는 이 크레이트에만 허용**), `yw-app`(바이너리), `yw-host`(바이너리). |
| D5 | yw-core 서드파티 의존성은 [spec/01](spec/01-repo-build.md) §3의 허용 목록으로 고정한다(M0–M6: 런타임 30개 + 빌드 전용 4개, `ripemd` 포함 — BIP32 fingerprint·BTC HASH160용). 로컬 크레이트 의존은 yw-core → yw-json만 허용한다(yw-json은 의존성 0). 목록 밖 크레이트가 들어오면 검사 스크립트가 실패한다. yw-win은 `windows-sys 0.61.2`·`windows-link 0.2.1`만, yw-app은 추가로 `qrcodegen 1.8.0`만 쓴다. Solana 단계(M7)에서 런타임 4개(`ed25519-dalek`, `ed25519`, `signature`, `curve25519-dalek`)와 빌드 전용 2개(`rustc_version`, `semver`)를 추가하고 curve25519-dalek의 build.rs를 허용하며, `.cargo/config.toml`로 serial 백엔드를 고정한다. |
| D6 | 직접 구현: BIP39(영어 단어 목록 내장), JSON, RLP, ABI 디코딩, EIP-712 해시(아카이브 이식), base58, bech32, SLIP-0010, WinHTTP·named pipe·클립보드 래퍼. 직접 구현 금지: secp256k1, Ed25519, Keccak, SHA-2, HMAC, PBKDF2, HKDF, Argon2, ChaCha20-Poly1305. |
| D7 | vault v3: 무작위 32바이트 DEK로 내용을 암호화하고, DEK는 비밀번호에서 Argon2id로 만든 KEK로 감싼다. 메타데이터·저널도 DEK에서 HKDF로 파생한 키로 암호화한다. 형식은 [spec/02](spec/02-core-keys-vault.md). 이전 vault(v1·데모 v2)는 이전하지 않는다(니모닉으로 다시 가져온다). |
| D8 | vault 비밀번호: 출력 가능한 ASCII(0x20–0x7E), 12–128자. BIP39 passphrase: 선택, 출력 가능한 ASCII 0–256자, 디스크에 저장하지 않고 잠금 해제 때마다 입력한다. 따라서 `unicode-normalization`을 쓰지 않는다. |
| D9 | 새 지갑은 24단어(256비트)만 생성한다. 가져오기는 12/15/18/21/24단어. 개인키 가져오기는 체인마다 최대 15개: EVM 원시 개인키(16진수 64자리), Solana base58 64바이트 keypair(Phantom·Solflare 내보내기)·`solana-keygen` JSON 배열(공개키 반쪽 검증), Bitcoin WIF(mainnet `0x80`·테스트넷 `0xef` → testnet4, 압축·비압축) + 사용자가 고른 주소 형식(P2PKH·P2SH-P2WPKH·P2WPKH·P2TR, 비압축 키는 P2PKH만). 니모닉 없이 개인키 하나로 지갑을 시작할 수도 있다(**키 전용 지갑**: 계정 추가·복구 단어 보기·passphrase가 없고 백업은 원래 개인키, 다른 체인 키는 나중에 가져온다). vault 형식은 [spec/02](spec/02-core-keys-vault.md) §4.6(tag 3 `SolKey`·tag 4 `BtcKey`, `Bip39` 선택), 규칙은 §8.4–§8.5, 화면은 [spec/04](spec/04-app-ui.md) §2.18. 가져온 Bitcoin 키의 보내기는 Bitcoin 주소 형식 작업과 통합할 때 연결한다(그 전에는 주소·내보내기만). |
| D10 | 잠금 해제 상태에서 메모리에 두는 지갑 비밀은 DEK(32바이트)와, 사용 중인 경우 BIP39 passphrase뿐이며 둘 다 VirtualLock 페이지에 둔다. 니모닉·시드·개인키는 서명·표시 때마다 복호화·파생하고 사용 직후 0으로 지운다. RPC·LLM API 키는 지갑 비밀이 아니며 DPAPI에서 꺼낸 뒤 프로세스 수명 동안 해당 작업 스레드에 둘 수 있다. |
| D11 | 니모닉·개인키·비밀번호 창: `WDA_EXCLUDEFROMCAPTURE` 적용, OS EDIT 컨트롤 대신 직접 그린다. 복사는 기본 금지이고 설정 토글로 허용한다. 허용 시 클립보드 기록·클라우드 동기화·모니터 제외 포맷을 붙이고 30초 뒤 자동 삭제한다. |
| D12 | 자동 잠금: 유휴 10분(1–60분 설정), Windows 세션 잠금, 절전 진입, 수동 잠금. |
| D13 | RPC 공급자는 특정 회사에 묶지 않는다. 네트워크(`eip155:<chainId>`, `solana:<cluster>`, `bitcoin:<net>`)마다 HTTPS JSON-RPC 엔드포인트 URL 하나를 쓴다. URL에 토큰이 들어가므로 URL 전체를 비밀로 보고 DPAPI(현재 사용자)로 암호화해 `apikeys.dpapi`에 저장한다. 입력 편의용 템플릿: **QuickNode 멀티체인**(엔드포인트 이름 + 토큰 1회 입력 → `https://<이름>.<네트워크 서브도메인>.quiknode.pro/<토큰>/`, Ethereum 메인넷은 서브도메인 없음), 알케미(키 1개 → `https://<host>.g.alchemy.com/v2/<KEY>`), 직접 입력. 템플릿으로 만든 URL도 네트워크별로 덮어쓸 수 있다(서브도메인 표는 구현 시 각 공급자 대시보드와 대조). 사용자의 현재 공급자는 QuickNode다. HTTPS는 WinHTTP(TLS 1.2/1.3만). WinHTTP는 Origin·Referer 헤더를 보내지 않으므로 엔드포인트에 리퍼러/도메인 허용 목록을 걸지 않는다(토큰 인증·IP 허용 목록은 무방). 개발 중 실서비스 확인(프로브·E2E)은 저장소 밖 `%USERPROFILE%\.yw-dev\rpc.json`(네트워크 ID → URL 객체, 예: `{"eip155:1": "https://…", "eip155:11155111": "https://…"}`) 또는 환경 변수 `YW_RPC_JSON`(그 파일 경로)에서 읽고, URL·토큰을 출력·로그에 남기지 않는다([01](spec/01-repo-build.md) §4, [09](spec/09-testing.md)). |
| D14 | EVM 체인: 기본 제공 = Ethereum mainnet(1), Sepolia(11155111), HyperEVM mainnet(999). 사용자는 설정에서 EVM 체인을 추가할 수 있다(chainId, 이름, 네이티브 심볼·소수 자릿수, HTTPS RPC URL 또는 공급자 템플릿(D13), 탐색기 URL 선택). 추가 시 `eth_chainId`가 입력과 같아야 하고 블록 0 해시를 받아 고정(최초 신뢰)하며, 이후 연결마다 둘을 다시 확인한다. 체인마다 `simulation` 속성(`auto` 기본 / `unsupported`)을 둔다. dApp의 `wallet_addEthereumChain`은 계속 거부하고, `wallet_switchEthereumChain`은 등록된 체인으로만 허용한다. |
| D15 | **EVM 시뮬레이션은 항상 시도한다.** 모든 `eth_sendTransaction`은 서명할 그대로의 트랜잭션을 `eth_simulateV1`(`validation:true`, `traceTransfers:true`)로 실행해 결과(자산 변화·이벤트·revert)를 승인 창에 보여준다. 시뮬레이션이 성공하지 못해도(미지원 체인, RPC 오류·시간 초과, 응답 이상, revert) **승인은 가능**하다. 이때 승인 창은 원인별 고위험 경고("시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다" / "시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다")를 맨 위에 표시하고 D16의 고위험 확인을 요구한다. 체인 `simulation = unsupported`면 호출하지 않고 바로 "시뮬레이션 미지원 체인" 경고로 처리한다. |
| D16 | 해석할 수 없는 calldata는 허용하되 "해석되지 않은 컨트랙트 호출" 고위험으로 표시한다. 시뮬레이션 결과까지 없으면 두 경고를 함께 보여준다. 고위험 승인은 모든 체인에서 공통으로 "위 경고를 모두 확인했습니다" 체크박스 **1개** + 승인 버튼 2초 길게 누르기로 한다. 승인을 막는(차단) 조건은 서명 형식 자체가 잘못된 경우뿐이다(예: typed data의 chainId 불일치, SIWE 도메인 불일치, 금지된 트랜잭션 필드, 수수료 상한 초과). |
| D17 | 타입 데이터는 `eth_signTypedData_v4`만 지원한다. 알려진 스키마(EIP-2612, DAI permit, Permit2, Seaport)는 구조화해 보여주고, 그 밖은 필드 트리로 보여주며 고위험으로 표시한다. domain.chainId가 현재 체인과 다르면 거부, 없으면 고위험. |
| D18 | `personal_sign`은 UTF-8 텍스트로 보여주고 SIWE(ERC-4361)를 해석해 도메인을 origin과 비교한다. UTF-8이 아니면 hex로 보여주고 고위험. |
| D19 | 트랜잭션은 EIP-1559(type 2)만 만든다. 컨트랙트 배포(`to` 없음), type 1/3/4(EIP-7702), blob은 거부한다. |
| D20 | (체인, 계정)마다 진행 중인 트랜잭션은 1개만 허용한다. 수수료는 지갑이 계산하고 dApp이 보낸 수수료 필드는 무시한다. 가스 한도는 dApp 값과 추정치×1.2 중 큰 값, 상한 16,777,216. |
| D21 | LLM 거래 설명은 선택 기능(기본 꺼짐, M6)이다. 참고용이며 승인 판단·위험 표시·승인 digest에 영향을 주지 않는다. 엔드포인트는 HTTPS, 또는 로컬 모델용 `http://127.0.0.1`·`http://localhost`·`http://[::1]`만 허용한다. |
| D22 | 확장은 기존 `extension/`을 유지하고 알려진 버그를 고친다. manifest `key`로 ID를 고정한다. https 페이지만 지원하고, `http://localhost`·`http://127.0.0.1`은 yw-app 설정 토글(기본 꺼짐)로 허용한다. 최상위 프레임만 지원한다. 호환 모드(확장 팝업에서 선택, 기본 꺼짐): `metamask` = 우리 provider가 `window.ethereum`을 차지하고 `isMetaMask: true`와 최소 `_metamask` 호환 API를 제공하며 EIP-6963 목록에 "MetaMask" 이름(rdns `io.metamask`)으로 알린다. `rabby` = 같은 방식에 `isRabby: true`, 이름 "Rabby Wallet"(rdns `io.rabby`). 호환 모드에서는 다른 확장의 EIP-6963 알림 중 같은 rdns 및 MetaMask·Rabby의 것을 가로채 dApp에 전달하지 않는다(최선 노력이다. 실제 MetaMask·Rabby를 꺼 두는 것을 권장한다). 어느 모드든 비밀은 확장에 들어가지 않고 모든 요청은 yw-app 승인 창으로 간다. |
| D23 | 확장↔yw-host 메시지는 기존 v1 봉투 형식을 유지한다. 단, 요청 단위 오류는 해당 요청에만 오류로 응답하고 스트림을 끊지 않는다. 요청 기한: 읽기 60초, 연결·서명 600초(잠금 해제·검토 시간 포함). 승인 창 자체는 표시 후 120초에 만료되고, 시뮬레이션이 60초보다 오래되면 승인 클릭 시 다시 실행한다. |
| D24 | named pipe 이름은 `\\.\pipe\YourWallet.v3.<사용자 SID>`, 현재 사용자 전용 DACL, `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`. yw-app이 꺼져 있고 `settings.json`의 `browserAutoLaunch`가 true(기본)면 yw-host가 yw-app을 실행시키고 최대 10초 기다린다. 실패하면 yw-host가 요청마다 4900으로 응답한다. Chrome의 job object 때문에 yw-app이 Chrome과 함께 종료되는지는 **아직 확인하지 않았다**(수동 체크 [spec/09](spec/09-testing.md) M5-13 대기; `spawn_detached`는 `CREATE_BREAKAWAY_FROM_JOB`을 먼저 시도한다). 함께 종료되면 `browserAutoLaunch` 기본값을 false로 바꾸고 수동 실행으로 바꾼다. |
| D25 | Solana: 전송 전용. v1은 SOL만, v1.1은 허용 목록 SPL 토큰(USDC·USDT). 경로 m/44'/501'/{i}'/0'. 가져온 개인키 계정(D9, [spec/07](spec/07-solana.md) §3.4)도 같은 보내기·받기 흐름을 쓴다(키 출처 태그 6 `Imported`, 비표준 경로 규칙 없음). |
| D26 | Bitcoin: 전송 전용. 받기는 BIP84(P2WPKH), 메인넷 m/84'/0'/0', testnet4 m/84'/1'/0'. 지갑마다 네트워크 하나(mainnet 또는 testnet4). 주소별 UTXO·내역 조회 인덱서는 설정 `bitcoin.indexer`로 고른다: **기본 `esplora`**(무료·키 없음, 기본 URL `https://mempool.space/api`, testnet4 `https://mempool.space/testnet4/api`, 설정에서 다른 Esplora URL로 변경 가능), 선택 `bb-rpc`(QuickNode BTC Blockbook 애드온, 유료 추가 요금), 선택 `bb-rest`(알케미 UTXO API). 어느 인덱서든 주소 단위로만 호출하고 xpub은 보내지 않는다. 인덱서는 믿지 않는다: 입력 금액·스크립트는 Bitcoin Core RPC(`getrawtransaction`, 현재 QuickNode `bitcoin:<net>` 엔드포인트)로 받은 원 거래의 해시를 txid와 대조해 검증한다. Core가 원 거래를 주지 못하면(txindex 없음 등) 인덱서의 원본 hex(`TxRaw`)로 받아 같은 해시 검증을 한다(검증 실패 UTXO는 쓰지 않음, [spec/08](spec/08-bitcoin.md) §4.7-4). 브로드캐스트·수수료 추정도 Core RPC로 한다. 예외: Core 전송이 통신 실패로 결과 불명(`BroadcastUnknown`)이고 인덱서가 `esplora`이면 사용자가 확인한 경우에만 같은 바이트를 Esplora `POST /tx`로 1회 수동 전송할 수 있다([spec/08](spec/08-bitcoin.md) §11.3). |
| D27 | 모든 체인의 서명은 같은 승인 창 구조를 쓴다. BTC·SOL은 지갑이 정해진 템플릿으로 거래를 만들므로 시뮬레이션 없이 결정적 해석만으로 표시한다(SOL은 `simulateTransaction`을 참고 정보로만 사용). |
| D28 | 텔레메트리·크래시 업로드 없음. `panic = "abort"`. 로그는 로컬 파일만, 비밀·주소 외 개인정보·API 키를 기록하지 않는다. |
| D29 | 니모닉 하나로 모든 체인 키를 파생한다. 체인별 경로: EVM m/44'/60'/0'/0/i(테스트넷 동일), Solana m/44'/501'/i'/0'(devnet 동일), Bitcoin 메인넷 m/84'/0'/0'/{0,1}/i, testnet4 m/84'/1'/0'/{0,1}/i. 새 지갑 생성 시에는 BIP39 passphrase를 쓰지 않고, passphrase는 가져오기에서만 지원한다. 가져온 개인키(D9)는 니모닉 밖에 있다: 복구 단어로 복구되지 않고, 화면은 가져온 계정마다 "가져온 키" 배지와 그 사실을 보인다. 키 전용 지갑에는 파생 계정이 없다. |
| D30 | 네트워크 선택(EVM 활성 체인, Solana 클러스터, Bitcoin 네트워크)과 `browserAutoLaunch`는 평문 `settings.json`에 둔다. 사이트별 연결·체인 권한은 암호화된 meta에 둔다. 잠긴 동안 `eth_accounts`는 `[]`, `eth_chainId`는 사이트별 메모리 캐시 또는 활성 체인을 돌려준다. |
| D31 | 문서 간 우선순위: 오류 코드·메시지는 [05](spec/05-browser.md) §5, 승인 digest·표시 인코딩은 [03](spec/03-evm.md) §11, meta·주소록·계정 스키마는 [02](spec/02-core-keys-vault.md) §5, check.ps1과 크레이트 구성은 [01](spec/01-repo-build.md)이 기준이다. |

---

## 4. 아키텍처

### 4.1 프로세스와 데이터 흐름

```
[웹페이지/dApp]
   │ window.ethereum (EIP-1193 / EIP-6963)
[extension: provider-main.js (MAIN world)]
   │ window.postMessage (채널 nonce)
[extension: content.js (ISOLATED)]
   │ chrome.runtime port
[extension: background.js (service worker)]
   │ chrome.runtime.connectNative("com.your_wallet.native")
[yw-host.exe]  ← Chrome이 실행. 비밀 없음. 프레임 크기 검사 후 그대로 중계.
   │ \\.\pipe\YourWallet.v3.<SID>  (4바이트 LE 길이 + UTF-8 JSON)
[yw-app.exe]   ← 지갑 본체. 단일 인스턴스.
   ├─ yw-core: vault, 키 파생, 서명, EVM/SOL/BTC 인코딩·해석, 정책
   ├─ 승인 창·비밀 입력/표시 창 (raw Win32)
   └─ RPC 클라이언트 (WinHTTP → QuickNode 등 네트워크별 엔드포인트)
```

- 확장은 비밀을 저장·처리하지 않는다. 계정 주소, 체인 ID, 요청·응답만 지나간다.
- yw-host는 메시지 내용을 해석하지 않는다. 길이·크기만 검사하고 pipe로 넘긴다. 예외: yw-app에 연결할 수 없을 때 요청마다 4900을 응답하기 위해 `version`·`kind`와 상관 필드 4개(`sessionId`, `activationNonce`, `requestId`, `sequence`)만 읽는다. 또 yw-app을 실행하기 전 `settings.json`의 `version`과 `browserAutoLaunch`만 읽는다(D24). 모든 검증과 정책은 yw-app이 한다.
- BTC·SOL 기능은 브라우저와 무관하게 yw-app 화면에서만 쓴다.

### 4.2 크레이트 계층

```
yw-json  (std, unsafe 금지, 의존성 0)
   ▲
yw-core  (std, unsafe 금지, 네트워크·GUI·OS 호출 없음; yw-json은 EIP-712 입력 등에 사용)
   ▲
yw-win   (windows-sys, unsafe는 여기서만, 안전한 API로 감싸 제공)
   ▲
yw-app   (yw-core + yw-json + yw-win + qrcodegen, unsafe 금지)
yw-host  (yw-json + yw-win, unsafe 금지)
```

- yw-core는 네트워크 데이터를 직접 받지 않는다. yw-app이 RPC 응답을 yw-json으로 파싱해 yw-core 타입으로 넘긴다.
- yw-core는 `getrandom` 외의 OS 기능을 호출하지 않는다. 파일 입출력은 yw-app이 yw-win으로 한다.

### 4.3 디스크

```
%LOCALAPPDATA%\YourWallet\v3\
  vault.ywv        vault v3 (니모닉·개인키·메타데이터 키 근거)
  meta.ywm         암호화된 메타데이터 (계정, 라벨, 주소록, 연결된 사이트, 토큰, 활동, 선택 계정·탭)
  journal.ywj      암호화된 진행 중 트랜잭션 저널
  settings.json    비밀이 아닌 설정 — 평문: 자동 잠금 시간·토글, 활성 네트워크 선택(EVM 체인·Solana 클러스터·
                   Bitcoin 네트워크), 사용자 EVM 체인 정의(evmChains), 최초 신뢰 제네시스 고정(evmGenesisPins),
                   수수료 상한, RPC 템플릿 종류, Bitcoin 인덱서·Esplora URL, LLM 설정, browserAutoLaunch(yw-host가 읽음), 로그 수준
  apikeys.dpapi    네트워크별 RPC 엔드포인트 URL(토큰 포함)·템플릿 자격 정보·LLM API 키 (DPAPI)
  logs\            로컬 로그 (비밀 없음)
```

확장의 호환 모드(D22, `metamask`·`rabby`)는 이 폴더가 아니라 Chrome 확장 저장소(`chrome.storage.local`)에 둔다([spec/05](spec/05-browser.md) §2.12).

쓰기는 모두 "임시 파일 → FlushFileBuffers → MoveFileExW(REPLACE_EXISTING|WRITE_THROUGH)"로 한다. 세부는 [spec/02](spec/02-core-keys-vault.md), [spec/04](spec/04-app-ui.md). 여러 앱 버전이 이 폴더를 번갈아 써도 서로의 데이터를 지우지 않도록 형식 호환 규칙(모르는 키·항목 보존, 더 새로운 `settings.json`은 읽기 전용)을 [spec/04](spec/04-app-ui.md) §6.6이 정한다. 형식을 깨는 변경은 새 폴더(`v4`)로 한다.

---

## 5. 마일스톤

각 마일스톤은 이전 마일스톤의 완료 조건을 깨지 않아야 한다. 세부 판정 기준은 [spec/09](spec/09-testing.md).

| ID | 범위 | 완료 조건 (요약) |
|---|---|---|
| **M0** 정리·뼈대 | main에서 구 코드 제거, 새 워크스페이스, 의존성 검사·`check.ps1` | `scripts/check.ps1` 통과(fmt, clippy, test, 의존성 허용 목록, 확장 테스트, privacy scan). 구 코드는 아카이브 태그로만 참조. |
| **M1** 키·vault | yw-core: 엔트로피, BIP39, BIP32(xprv/xpub 문자열 인코딩 포함, 테스트용), base58check, vault v3, 비밀번호 규칙, 백업 확인 로직 | BIP39(Trezor)·BIP32(벡터 1–5, 전체 문자열 비교) 공식 벡터, abandon 니모닉→EVM 주소 벡터, vault v3 골든 테스트, 변조·오답 비밀번호 거부 테스트 통과. |
| **M2** EVM 코어 | yw-core: RLP, type 2 서명·서명 후 검증, EIP-191, EIP-712, ABI 해석, 시뮬레이션 결과 해석, 승인 표시 모델, 위험 규칙 | EIP-155·EIP-1559(Besu)·EIP-191·EIP-712(Ether Mail) 서명 벡터 재현, 셀렉터·토픽 표 테스트, 시뮬레이션 응답 픽스처(전·후 Glamsterdam) 해석 테스트 통과. |
| **M3** 앱 뼈대 | yw-win, yw-app: 첫 실행, 생성·가져오기·백업 확인·잠금 해제·잠금, 비밀 표시 보호, 설정(RPC 엔드포인트) | 수동 체크리스트: 캡처 제외 확인(캡처 도구·OBS 결과에 비밀 창이 나타나지 않음), 복사 차단·토글·자동 삭제(Win+V 기록에 없음), 자동 잠금 4가지 경로, 재시작 후 vault 열기. |
| **M4** EVM 단독 전송 | RPC 클라이언트, 잔액, ETH·ERC-20 보내기(시뮬레이션·승인·저널·영수증), 받기 QR, 사용자 EVM 체인 추가 | Sepolia에서 ETH·ERC-20 송금 E2E, 시뮬레이션 실패·미지원 시 고위험 경고 + 확인 후에만 승인되는지 확인, HyperEVM(또는 `simulation = unsupported` 체인)에서 소액 송금 E2E, 앱 강제 종료 후 저널 복구 확인. |
| **M5** 브라우저 연동 | yw-host, pipe, 확장 버그 수정, 등록 스크립트, dApp 메서드·권한 | Sepolia dApp에서 연결·읽기·송금·personal_sign·SIWE·typed data(Permit2 포함) E2E, 다른 확장 ID 연결 거부, 오류 요청 후에도 세션 유지 확인. |
| **M6** LLM 설명 (선택) | OpenAI 호환 API로 설명 생성 | 꺼진 상태에서 네트워크 호출 0, 켜진 상태에서도 승인 흐름이 LLM 실패와 무관함을 확인. |
| **M7** Solana | SLIP-0010, Ed25519, SOL 보내기·받기, (v1.1) SPL 허용 목록 | SLIP-0010·RFC 8032 벡터, abandon 니모닉→Phantom 경로 주소 벡터, devnet E2E, 이중 서명 방지 테스트. |
| **M8** Bitcoin | BIP84, 주소 파싱(5종), P2WPKH 서명, 입력 검증, 수수료 정책 | BIP143·BIP173/350·BIP84 벡터, testnet4 E2E, 입력 금액 위조 픽스처 거부, Sparrow/Electrum 복구 확인. |
| **M9** 메인넷 소액 | 체크리스트 | [spec/09](spec/09-testing.md) §메인넷 체크리스트 1회 수행 후 소액만 사용. |

예상 작업량(집중 작업일 기준): M0–M5 약 30–40일, M7 v1(SOL) 약 23–36일 + v1.1(SPL) 8–12일, M8 약 40–60일.

---

## 6. 아카이브에서 가져오는 것과 버리는 것

자세한 파일·줄 범위는 [spec/01](spec/01-repo-build.md) §6.

- **가져온다(수정해서):** `secret-core`(BIP32, vault 코드 패턴, 비밀번호), `wallet-model`(경계 타입, EIP-191/712 preimage), `eip712`(serde 제거), `wallet-protocol`의 승인 digest·표시 파생 일부, `key-agent`의 서명 후 검증·백업 확인 흐름·저널 패턴, `broker`의 메서드 허용 목록·파라미터 검증, `native-host`의 프레이밍, `approval-ui`·`approval-wire`의 승인 창 상태 기계·표시 문자 규칙, `secret-input-ui`의 WM_CHAR 비밀 입력·캡처 제외, 데모의 RPC 클라이언트·ERC-20·QR·원자적 쓰기·벡터, `extension/` 전체, `scripts/privacy-scan.mjs`, `docs/recovery-guide.ko.md`.
- **버린다:** `platform-windows`, `key-agent-service*`, `key-agent-debugger*`, `dashboard`, 데모의 egui·ureq·자체 vault, `scripts/architecture-scan.mjs`, `scripts/release/*`(audit-extension 제외), `scripts/service-probe/*`, `scripts/windows-evidence/*`, Windows 설계 문서·ADR·개발 로그.
