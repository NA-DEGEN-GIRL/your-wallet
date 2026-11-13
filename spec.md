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
| [spec/07-solana.md](spec/07-solana.md) | Solana 전송 + dApp 거래 서명(spec/07 §20): 지갑 앱 보내기는 템플릿, dApp은 연결·메시지 서명·SIWS(§19)와 사이트가 만든 거래의 서명·전송(§20) |
| [spec/08-bitcoin.md](spec/08-bitcoin.md) | Bitcoin 전송 전용, dApp은 소유 증명(연결·메시지 서명)만(§17) |
| [spec/09-testing.md](spec/09-testing.md) | 테스트 벡터, 퍼징, 수동 체크리스트, 마일스톤별 판정 기준 |
| [spec/10-yubikey.md](spec/10-yubikey.md) | 선택 기능: YubiKey 계정(니모닉에서 파생한 키를 YubiKey에 가져와 카드에서 서명, PC에는 공개키·슬롯 표만) |
| [spec/11-hypercore.md](spec/11-hypercore.md) | Hyperliquid HyperCore: 같은 EVM 주소의 잔액 보기와 사용자 서명 전송(거래 없음), dApp Hyperliquid 서명 표시 |
| [spec/12-zcash.md](spec/12-zcash.md) | Zcash 일반(transparent) 전송 전용(D36): 주소(t·TEX·UA 일반 수신자), v5 거래, ZIP 244 서명, ZIP 317 수수료, 업그레이드 표 대조 |
| [spec/13-walletconnect.md](spec/13-walletconnect.md) | WalletConnect v2(Reown): 확장 외 두 번째 dApp 연결(`wc:` 붙여넣기·스크린샷 QR), EVM만, 주장한 출처 표시와 Verify |

---

## 1. 목표

1. **직접 검토 가능한 작은 지갑.** 키를 다루는 코드와 그 의존성을 혼자 읽을 수 있는 규모로 유지한다.
2. **공급망 오염 차단.** 지갑 본체는 고정·검토된 소수 크레이트만 쓰고, 크롬 확장은 npm 의존성 0인 순수 JS로 만든다. 확장은 비밀을 전혀 갖지 않는다.
3. **무엇에 서명하는지 정확히 안다.** 승인 창은 dApp·확장이 보낸 설명이 아니라 코어가 실제 서명 대상을 직접 해석한 내용과 **시뮬레이션 결과**를 보여준다. 시뮬레이션을 할 수 없거나 실패한 경우에는 그 사실을 고위험 경고로 분명히 보여주고, 사용자가 확인하면 서명할 수 있다.
4. **표준 복구.** 24단어 BIP39 니모닉 하나로 다른 표준 지갑에서 모든 체인 자산을 복구할 수 있다. 예외: 가져온 개인키 계정은 니모닉 밖이며 원래 개인키로만 복구한다(D9, D29).
5. **실사용.** EVM은 dApp 연결까지 한다. Solana는 지갑 앱에서 보내기·받기를 하고 dApp과는 연결·메시지 서명·거래 서명(서명만 또는 서명 후 전송)까지 한다(D25, D27, D38). Bitcoin은 지갑 앱에서 보내기·받기를 하고 dApp과는 소유 증명(연결 + 메시지 서명)만 한다(D26–D27).

## 2. 위협 모델

### 2.1 방어 대상 (각 항목은 자동 테스트 또는 1회 체크리스트로 판정한다)

| 공격자 | 방어 방법 |
|---|---|
| 악성 dApp, 피싱 사이트, 오염된 dApp 프론트엔드(npm 포함) | 승인 창은 코어가 실제 payload에서 만든 표시와 시뮬레이션 결과만 근거로 한다. `eth_sign` 미지원. 무한 승인·permit·setApprovalForAll·해석 불가 호출은 고위험 표시. Solana dApp 거래(D38): X 규칙(해석하지 않은 프로그램은 고위험, Approve·SetAuthority·Assign·CloseAccount 경고), 쓰기 가능한 계정 목록, 시뮬레이션 전·후 차이(자산·권한), Token-2022 민트 확장 검사, 서명 결과를 돌려주기 직전의 사이트 권한 재확인 — 2026-11-13부터 모든 dApp 서명(EVM·Solana·Bitcoin 메시지)과 EVM 거래 해시에도, 승인 뒤 YubiKey PIN을 기다리는 요청은 연결 해제·페이지 종료 때 서명 없이 끝난다([05] §4.5). |
| 다른 크롬 확장, 오염된 웹페이지 스크립트 | 확장은 비밀이 없다. native messaging은 고정된 확장 ID만 허용한다. 승인은 브라우저 밖 네이티브 창에서만 한다. |
| 우리 확장·yw-host 오염 | 요청 위조·스팸은 가능하지만 승인 창 내용은 코어가 다시 만들므로 다른 거래로 서명시킬 수 없다. |
| 악성·오류 RPC(QuickNode·알케미 등 공급자 포함) | 서명 대상은 코어가 만든다(예외: Solana dApp 거래는 사이트가 바이트를 만든다 — 코어가 legacy·v0을 해석하고 다시 인코딩한 값이 원본과 같은지 확인하며, 그 바이트를 승인 digest에 묶고, 블록해시를 바꾸지 않고 자기 서명 슬롯 하나에만 서명한다, D38). 체인 ID·제네시스 해시 고정, 수수료 상한, BTC 입력 금액은 이전 트랜잭션 해시로 검증. RPC가 보낸 문자열은 화면에 그대로 표시하지 않는다(예외: AI 설명 패널은 [06](spec/06-llm-explain.md) §5–§6 필터를 거친 파생 텍스트로 별도 표시). |
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
- RPC 공급자 단일 의존에서 오는 잔여 위험: 잔액·확인 수·UTXO 완전성 위조, Solana 만료 판정 위조에 의한 이중 지불. 설정한 RPC는 신뢰하며(D32) 추가 확인 수나 시계 대기로 범위를 줄이지 않는다. 서명 대상 자체는 RPC가 바꿀 수 없다.
- 확인 1개로 확정한 거래가 체인 재구성으로 빠지는 경우(D32). 체인 자체의 문제로 보고 지갑은 감지·복구하지 않는다.
- Solana dApp 거래(D38)의 RPC 사실: 조회 테이블(ALT) 내용, 실행 전 계정 상태, 시뮬레이션, 민트 데이터는 RPC가 준 값이다. 거짓 RPC는 표시를 위조할 수 있지만 서명하는 바이트는 바꾸지 못한다. 서명 후 전송은 서명 직전에 테이블을 다시 읽어 비교하므로 앞뒤가 다른 RPC는 잡지만, 일관되게 거짓말하는 RPC는 잡지 못한다.
- Solana 서명만(sign-only) 결과는 지갑 밖으로 나가며, 사이트는 만료 전 언제든(durable nonce 거래는 아무 때나) 그 거래를 전송할 수 있다.
- 120초 승인 창이 블록해시 유효 시간(약 30초, 150블록, [07](spec/07-solana.md) §16)보다 오래 남을 수 있다(만료된 거래는 체인이 받지 않는다).
- dApp 블록해시의 `lastValidBlockHeight`는 `processed`에서 읽으므로 포크 전환 뒤 실제보다 낮을 수 있다. 그 결과는 이른 `만료` 표시와 재전송 중단뿐이고, 지갑은 dApp 거래를 다시 서명하지 않으므로 이중 지불은 없다.
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
| D7 | vault v3: 무작위 32바이트 DEK로 내용을 암호화하고, DEK는 비밀번호에서 Argon2id로 만든 KEK로 감싼다. 메타데이터·저널도 DEK에서 HKDF로 파생한 키로 암호화한다. 비밀번호를 바꿀 때마다 DEK도 새로 만든다(2026-11-13, 중단에 안전한 단계 이행, [spec/02](spec/02-core-keys-vault.md) §4.4). 형식은 [spec/02](spec/02-core-keys-vault.md). 이전 vault(v1·데모 v2)는 이전하지 않는다(니모닉으로 다시 가져온다). |
| D8 | vault 비밀번호: 출력 가능한 ASCII(0x20–0x7E), 12–128자. BIP39 passphrase: 선택, 출력 가능한 ASCII 0–256자, 디스크에 저장하지 않고 잠금 해제 때마다 입력한다. 따라서 `unicode-normalization`을 쓰지 않는다. |
| D9 | 새 지갑은 24단어(256비트)만 생성한다. 가져오기는 12/15/18/21/24단어. 개인키 가져오기는 체인마다 최대 15개: EVM 원시 개인키(16진수 64자리), Solana base58 64바이트 keypair(Phantom·Solflare 내보내기)·`solana-keygen` JSON 배열(공개키 반쪽 검증), Bitcoin WIF(mainnet `0x80`·테스트넷 `0xef` → testnet4, 압축·비압축) + 사용자가 고른 주소 형식(P2PKH·P2SH-P2WPKH·P2WPKH·P2TR, 비압축 키는 P2PKH만), Zcash 압축 WIF(`0x80`/`0xEF`, Zcash 탭의 네트워크) 또는 16진수 64자리(2026-11-07, tag 6 `ZecKey`, [spec/12](spec/12-zcash.md) §2.3). 니모닉 없이 개인키 하나로 지갑을 시작할 수도 있다(**키 전용 지갑**: 계정 추가·복구 단어 보기·passphrase가 없고 백업은 원래 개인키, 다른 체인 키는 나중에 가져온다). vault 형식은 [spec/02](spec/02-core-keys-vault.md) §4.6(tag 3 `SolKey`·tag 4 `BtcKey`, `Bip39` 선택), 규칙은 §8.4–§8.5, 화면은 [spec/04](spec/04-app-ui.md) §2.18. 가져온 Bitcoin 키도 계정 하나로 보내기·받기를 한다(주소 하나, 잔돈은 같은 주소; 서명은 `BtcKeySource::Imported`, [spec/08](spec/08-bitcoin.md) §3.5·§11.1). |
| D10 | 잠금 해제 상태에서 메모리에 두는 지갑 비밀은 DEK(32바이트)와, 사용 중인 경우 BIP39 passphrase뿐이며 둘 다 VirtualLock 페이지에 둔다. 니모닉·시드·개인키는 서명·표시 때마다 복호화·파생하고 사용 직후 0으로 지운다. RPC·LLM API 키는 지갑 비밀이 아니며 DPAPI에서 꺼낸 뒤 프로세스 수명 동안 해당 작업 스레드에 둘 수 있다. |
| D11 | 니모닉·개인키·비밀번호 창: `WDA_EXCLUDEFROMCAPTURE` 적용, OS EDIT 컨트롤 대신 직접 그린다. 복사는 기본 금지이고 설정 토글로 허용한다. 허용 시 클립보드 기록·클라우드 동기화·모니터 제외 포맷을 붙이고 30초 뒤 자동 삭제한다. |
| D12 | 자동 잠금: 유휴 10분(1–60분 설정), Windows 세션 잠금, 절전 진입, 수동 잠금. |
| D13 | RPC 공급자는 특정 회사에 묶지 않는다. 네트워크(`eip155:<chainId>`, `solana:<cluster>`, `bitcoin:<net>`, `zcash:<net>`)마다 HTTPS JSON-RPC 엔드포인트 URL 하나를 쓴다. URL에 토큰이 들어가므로 URL 전체를 비밀로 보고 DPAPI(현재 사용자)로 암호화해 `apikeys.dpapi`에 저장한다. 입력 편의용 템플릿: **QuickNode 멀티체인**(엔드포인트 이름 + 토큰 1회 입력 → `https://<이름>.<네트워크 서브도메인>.quiknode.pro/<토큰>/`, Ethereum 메인넷은 서브도메인 없음), 알케미(키 1개 → `https://<host>.g.alchemy.com/v2/<KEY>`), 직접 입력. 템플릿으로 만든 URL도 네트워크별로 덮어쓸 수 있다(서브도메인 표는 구현 시 각 공급자 대시보드와 대조). 사용자의 현재 공급자는 QuickNode다. HTTPS는 WinHTTP(TLS 1.2/1.3만). WinHTTP는 Origin·Referer 헤더를 보내지 않으므로 엔드포인트에 리퍼러/도메인 허용 목록을 걸지 않는다(토큰 인증·IP 허용 목록은 무방). 개발 중 실서비스 확인(프로브·E2E)은 저장소 밖 `%USERPROFILE%\.yw-dev\rpc.json`(네트워크 ID → URL 객체, 예: `{"eip155:1": "https://…", "eip155:11155111": "https://…"}`) 또는 환경 변수 `YW_RPC_JSON`(그 파일 경로)에서 읽고, URL·토큰을 출력·로그에 남기지 않는다([01](spec/01-repo-build.md) §4, [09](spec/09-testing.md)). |
| D14 | EVM 체인: 기본 제공 = Ethereum mainnet(1), Sepolia(11155111), HyperEVM mainnet(999), **Arbitrum One(42161), Base(8453), BNB Smart Chain(56), Robinhood Chain(4663)**(2026-11-06 추가, 값·출처 [spec/03](spec/03-evm.md) §1.1·§1.1a; OP-stack(Base)의 L1 데이터 수수료는 최대 수수료·상한 검사에 더한다, §3.4a). 그 밖 L1·L2는 사용자 체인이다. 사용자는 설정에서 EVM 체인을 추가할 수 있다(chainId, 이름, 네이티브 심볼·소수 자릿수, HTTPS RPC URL 또는 공급자 템플릿(D13), 탐색기 URL 선택). 추가 시 `eth_chainId`가 입력과 같아야 하고 블록 0 해시를 받아 고정(최초 신뢰)하며, 이후 연결마다 둘을 다시 확인한다. 체인마다 `simulation` 속성(`auto` 기본 / `unsupported`)을 둔다. dApp의 `wallet_addEthereumChain`은 계속 거부하고, `wallet_switchEthereumChain`은 등록된 체인으로만 허용한다. |
| D15 | **EVM 시뮬레이션은 항상 시도한다.** 모든 `eth_sendTransaction`은 서명할 그대로의 트랜잭션을 `eth_simulateV1`(`validation:true`, `traceTransfers:true`)로 실행해 결과(자산 변화·이벤트·revert)를 승인 창에 보여준다. 시뮬레이션이 성공하지 못해도(미지원 체인, RPC 오류·시간 초과, 응답 이상, revert) **승인은 가능**하다. 이때 승인 창은 원인별 고위험 경고("시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다" / "시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다")를 맨 위에 표시하고 D16의 고위험 확인을 요구한다. 체인 `simulation = unsupported`면 호출하지 않고 바로 "시뮬레이션 미지원 체인" 경고로 처리한다. |
| D16 | 해석할 수 없는 calldata는 허용하되 "해석되지 않은 컨트랙트 호출" 고위험으로 표시한다. 시뮬레이션 결과까지 없으면 두 경고를 함께 보여준다. 고위험 승인은 모든 체인에서 공통으로 "위 경고를 모두 확인했습니다" 체크박스 **1개** + 승인 버튼 2초 길게 누르기로 한다. 승인을 막는(차단) 조건은 서명 형식 자체가 잘못된 경우뿐이다(예: typed data의 chainId 불일치, SIWE 도메인 불일치, 금지된 트랜잭션 필드, 수수료 상한 초과). |
| D17 | 타입 데이터는 `eth_signTypedData_v4`만 지원한다. 알려진 스키마(EIP-2612, DAI permit, Permit2, Seaport)는 구조화해 보여주고, 그 밖은 필드 트리로 보여주며 고위험으로 표시한다. domain.chainId가 현재 체인과 다르면 거부, 없으면 고위험. |
| D18 | `personal_sign`은 UTF-8 텍스트로 보여주고 SIWE(ERC-4361)를 해석해 도메인을 origin과 비교한다. UTF-8이 아니면 hex로 보여주고 고위험. |
| D19 | 트랜잭션은 EIP-1559(type 2)만 만든다. 컨트랙트 배포(`to` 없음), type 1/3/4(EIP-7702), blob은 거부한다. |
| D20 | (체인, 계정)마다 진행 중인 트랜잭션은 1개만 허용한다(진행 중 = D32의 확정 전). Solana dApp 전송은 예외: (클러스터, 서명 계정)당 Pending 16건, 모든 클러스터·계정 합 32건 상한, 넘으면 -32002(지갑이 dApp 거래를 다시 서명하지 않으므로 한 건 규칙이 필요 없다, D38). 수수료는 지갑이 계산하고 dApp이 보낸 수수료 필드는 무시한다. 가스 한도는 dApp 값과 추정치×1.2 중 큰 값, 상한 16,777,216. |
| D21 | LLM 거래 설명은 선택 기능(기본 꺼짐, M6)이다. 참고용이며 승인 판단·위험 표시·승인 digest에 영향을 주지 않는다. 엔드포인트는 HTTPS, 또는 로컬 모델용 `http://127.0.0.1`·`http://localhost`·`http://[::1]`만 허용한다. |
| D22 | 확장은 기존 `extension/`을 유지하고 알려진 버그를 고친다. manifest `key`로 ID를 고정한다. https 페이지만 지원하고, `http://localhost`·`http://127.0.0.1`은 yw-app 설정 토글(기본 꺼짐)로 허용한다. 최상위 프레임만 지원한다. 호환 모드(확장 팝업에서 선택, 기본 꺼짐): `metamask` = 우리 provider가 `window.ethereum`을 차지하고 `isMetaMask: true`와 최소 `_metamask` 호환 API를 제공하며 EIP-6963 목록에 "MetaMask" 이름(rdns `io.metamask`)으로 알린다. `rabby` = 같은 방식에 `isRabby: true`, 이름 "Rabby Wallet"(rdns `io.rabby`). 호환 모드에서는 다른 확장의 EIP-6963 알림 중 같은 rdns 및 MetaMask·Rabby의 것을 가로채 dApp에 전달하지 않는다(최선 노력이다. 실제 MetaMask·Rabby를 꺼 두는 것을 권장한다). 어느 모드든 비밀은 확장에 들어가지 않고 모든 요청은 yw-app 승인 창으로 간다. **Solana·Bitcoin 호환 모드(2026-10-31)**는 EVM 모드와 별개로 팝업에서 고른다([05] §2.13): `solCompatMode` = `off`(기본, Wallet Standard 지갑 "Your Wallet (Solana)"만 등록 — EVM 기본 모드의 EIP-6963 이름은 "Your Wallet (EVM)"이다. 두 지갑이 같은 이름 "Your Wallet"이던 때 Uniswap 등이 한 항목으로 합쳐 Solana 연결까지 이어 해서 2026-11-11에 나눴다, [05] §2.13) / `phantom`(Wallet Standard 이름 "Phantom" + `window.phantom.solana` shim, 아이콘은 우리 것 — Wallet Standard 목록에서는 실제 Phantom을 숨길 수 없으므로 팝업이 실제 Phantom을 끄라고 경고), `btcCompatMode` = `off`(기본, Bitcoin은 아무것도 주입하지 않음) / `unisat`(`window.unisat`) / `xverse`(sats-connect `XverseProviders.BitcoinProvider` + WBIP004 `btc_providers`). Solana dApp 지원은 연결·메시지 서명·거래 서명(서명만, 서명 후 전송)이다(D25, D38). Bitcoin dApp 지원은 연결 + 메시지 서명뿐이다(D26). |
| D23 | 확장↔yw-host 메시지는 기존 v1 봉투 형식을 유지한다. 단, 요청 단위 오류는 해당 요청에만 오류로 응답하고 스트림을 끊지 않는다. 요청 기한: 읽기 60초, 연결·서명 600초(잠금 해제·검토 시간 포함). 승인 창 자체는 표시 후 120초에 만료되고, 시뮬레이션이 60초보다 오래되면 승인 클릭 시 다시 실행한다. |
| D24 | named pipe 이름은 `\\.\pipe\YourWallet.v3.<사용자 SID>`, 현재 사용자 전용 DACL, `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`. yw-app이 꺼져 있고 `settings.json`의 `browserAutoLaunch`가 true(기본)면 yw-host가 yw-app을 실행시키고 최대 10초 기다린다. 실패하면 yw-host가 요청마다 4900으로 응답한다. Chrome의 job object 때문에 yw-app이 Chrome과 함께 종료되는지는 **아직 확인하지 않았다**(수동 체크 [spec/09](spec/09-testing.md) M5-13 대기; `spawn_detached`는 `CREATE_BREAKAWAY_FROM_JOB`을 먼저 시도한다). 함께 종료되면 `browserAutoLaunch` 기본값을 false로 바꾸고 수동 실행으로 바꾼다(기본값은 이미 저장된 true에 닿지 않으므로 그 값도 끈다, spec/09 M5-13). |
| D25 | Solana: 지갑 앱의 보내기·받기는 지갑이 템플릿으로 만든다(T_SOL·T_SPL, [07] §9). **dApp 연결**(2026-10-31 소유 증명, 2026-11-12 거래 서명 추가, [07] §19–§20, [05] §3.6): 계정 1개 연결, 메시지 서명(Sign-In-With-Solana 포함), **사이트가 만든 거래의 서명·전송**(2026-11-12, 사용자가 위험을 받아들임, D38). 메서드는 `sol_signTransaction`·`sol_signAllTransactions`(≤ 32건, 창 하나·승인 하나)·`sol_signAndSendTransaction`이고, 페이지 API는 Wallet Standard `solana:signTransaction`·`solana:signAndSendTransaction`(`supportedTransactionVersions: ["legacy", 0]`)과 Phantom shim(폐기된 `message` 형식 포함)이다. legacy와 v0(조회 테이블 포함), 모든 프로그램(해석하지 않은 프로그램은 원본 표시 + 고위험, 차단하지 않음), 사이트가 넣은 부분 서명, 지갑이 아닌 수수료 지불자를 받는다. 소프트웨어 키(주 니모닉·가져온 키·더한 니모닉)와 YubiKey 키 모두 쓴다. 버전 `0x81` 이상은 거부한다. 거래로 해석되는 바이트는 메시지로 서명하지 않는다(M01, [07] §19.2). 형식이 틀린 오프체인 메시지도 서명하지 않는다. 지갑 앱의 보내기는 계속 T_SOL·T_SPL만 만든다. v1은 SOL만, v1.1은 허용 목록 SPL 토큰(USDC·USDT). 경로 m/44'/501'/{i}'/0'. 가져온 개인키 계정(D9, [spec/07](spec/07-solana.md) §3.4)도 같은 보내기·받기 흐름을 쓴다(키 출처 태그 6 `Imported`, 비표준 경로 규칙 없음). **받은 내역(2026-11-11, opt-in)**: 받은 거래 목록은 기본으로 만들지 않지만, 사용자가 활동 카드의 `받은 내역도 보기`(settings `receivedHistory`, 기본 꺼짐)를 켜면 모든 체인에서 선택 계정의 최근 입금을 이미 쓰는 RPC·인덱서로 읽어 이번 실행 동안 표시만 한다 — 0·먼지 금액은 숨기고(개수만), 허용 목록·토큰 카드 밖 토큰은 읽지 않으며, 보낸 주소는 표시 전용(복사·선택 없음, 유사 주소 태그)이다([04] §2.6). |
| D26 | Bitcoin: 전송 전용(지갑 앱의 보내기·받기, 보관용 — 오디널스·인스크립션·룬은 범위 밖). **dApp 연결은 소유 증명만**(2026-10-31, [08] §17, [05] §3.6): UniSat·Xverse 호환 모드에서만 주소(목적마다 계정 하나의 받기 주소 0번)를 연결하고 메시지에 서명(BIP137 ECDSA, BIP322 simple·full)한다. PSBT·거래 서명·전송·인스크립션 메서드는 항상 4200 "이 지갑은 Bitcoin에서 메시지 서명(소유 증명)만 지원합니다". 주소 형식은 **계정마다** 하나다: 네이티브 세그윗 P2WPKH(BIP84, 기본·계정 0), 탭루트 P2TR(BIP86 키 경로), 호환 세그윗 P2SH-P2WPKH(BIP49), 레거시 P2PKH(BIP44). 기본 계정은 BIP84 계정 0(메인넷 m/84'/0'/0', testnet4 m/84'/1'/0')이고, Bitcoin 탭의 [계정 추가]로 형식을 골라 같은 니모닉의 다음 계정(`m/{44\|49\|84\|86}'/{coin}'/{n}'`)을 더한다. 가져온 단일 키(WIF, vault 태그 4)도 계정 하나가 된다(주소 하나, gap 검색 없음, 잔돈은 같은 주소). 한 거래는 한 계정의 입력만 쓰고 잔돈은 그 계정의 잔돈 체인(같은 형식)으로 간다([spec/08](spec/08-bitcoin.md) §3.5). 지갑마다 네트워크 하나(mainnet 또는 testnet4). 주소별 UTXO·내역 조회 인덱서는 설정 `bitcoin.indexer`로 고른다: **기본 `esplora`**(무료·키 없음, 기본 URL `https://mempool.space/api`, testnet4 `https://mempool.space/testnet4/api`, 설정에서 다른 Esplora URL로 변경 가능), 선택 `bb-rpc`(QuickNode BTC Blockbook 애드온, 유료 추가 요금), 선택 `bb-rest`(알케미 UTXO API). 어느 인덱서든 주소 단위로만 호출하고(선택한 계정의 주소: bech32·bech32m 소문자 또는 base58check, 질의 경로는 바뀌지 않음) xpub은 보내지 않는다. 인덱서는 믿지 않는다: 입력 금액·스크립트는 Bitcoin Core RPC(`getrawtransaction`, 현재 QuickNode `bitcoin:<net>` 엔드포인트)로 받은 원 거래의 해시를 txid와 대조해 검증한다. Core가 원 거래를 주지 못하면(txindex 없음 등) 인덱서의 원본 hex(`TxRaw`)로 받아 같은 해시 검증을 한다(검증 실패 UTXO는 쓰지 않음, [spec/08](spec/08-bitcoin.md) §4.7-4). 브로드캐스트·수수료 추정도 Core RPC로 한다. 예외: Core 전송이 통신 실패로 결과 불명(`BroadcastUnknown`)이고 인덱서가 `esplora`이면 사용자가 확인한 경우에만 같은 바이트를 Esplora `POST /tx`로 1회 수동 전송할 수 있다([spec/08](spec/08-bitcoin.md) §11.3). |
| D27 | 모든 체인의 서명은 같은 승인 창 구조를 쓴다. BTC·SOL은 지갑이 정해진 템플릿으로 거래를 만들므로 시뮬레이션 없이 결정적 해석만으로 표시한다(SOL은 `simulateTransaction`을 참고 정보로만 사용). BTC의 dApp 서명은 **메시지 서명뿐**이다(`BtcMessage`). SOL의 dApp 서명은 메시지 서명(`ApprovalKind::SolMessage`·`SolSignIn`)과 거래 서명(`SolTransaction = 0x23`, 2026-11-12, D38)이다. 메시지 서명은 EVM `personal_sign`과 같은 창·digest·일회 소비·만료 규칙을 쓴다. dApp 거래는 시뮬레이션 묶음이 `NotApplicable`이고, 시뮬레이션·조회 테이블·실행 전 상태는 표시 필드라 표시 digest에 묶인다. 시뮬레이션은 참고 정보이며 실패하거나 결과가 없으면 고위험(X09)이다. 승인 창에는 origin(+ punycode 배지), 호환 모드 배지, 체인·네트워크, 서명 계정 주소 전체, 메시지, 경고가 보인다. |
| D28 | 텔레메트리·크래시 업로드 없음. `panic = "abort"`. 로그는 로컬 파일만, 비밀·주소 외 개인정보·API 키를 기록하지 않는다. |
| D29 | 니모닉 하나로 모든 체인 키를 파생한다. 체인별 경로: EVM m/44'/60'/0'/0/i(테스트넷 동일), Solana m/44'/501'/i'/0'(devnet 동일), Bitcoin `m/{purpose}'/{coin}'/{account}'/{0,1}/i` — purpose는 계정의 주소 형식(44 P2PKH, 49 P2SH-P2WPKH, 84 P2WPKH, 86 P2TR), coin은 메인넷 0·testnet4 1, 기본 계정은 m/84'/0'/0'(testnet4 m/84'/1'/0'), 추가 계정은 형식별 다음 account 번호(0–99; P2WPKH는 1부터). 새 지갑 생성 시에는 BIP39 passphrase를 쓰지 않고, passphrase는 가져오기에서만 지원한다. 가져온 개인키(D9)는 니모닉 밖에 있다: 복구 단어로 복구되지 않고, 화면은 가져온 계정마다 "가져온 키" 배지와 그 사실을 보인다. 키 전용 지갑에는 파생 계정이 없다. **Bitcoin 고정 주소(2026-11-05, [08](spec/08-bitcoin.md) §3.5):** HD 계정은 기본으로 주소 하나만 쓴다(UniSat·Xverse 방식) — 받기는 늘 그 형식의 표준 첫 주소 `m/{44|49|84|86}'/{coin}'/a'/0/0`, 잔돈도 그 주소로 돌아온다. 같은 복구 단어를 Electrum·Sparrow·UniSat에 넣으면 같은 주소가 나오고, 나중에 키를 하드웨어 키로 옮겨도 주소가 같으며 소유 증명 주소가 하나다. 주소 재사용·잔액 공개는 사용자가 받아들인 대가다. 발견(gap 20)과 감시 집합은 그대로라 다른 HD 주소로 받은 돈도 보이고 쓸 수 있으며, 계정마다 "받을 때마다 새 주소"(HD)로 바꿀 수 있다. **EVM 계정과 같은 키(선택):** [계정 추가]에서 명시적으로 고르고 확인하면 Bitcoin 계정이 EVM 계정 i의 키 m/44'/60'/0'/0/i(testnet4도 같은 경로)를 그 주소 형식으로 쓴다(주소 하나). 두 주소의 공개키가 같아 같은 사람 것임이 드러나고, 다른 BTC 지갑에 복구 단어만 넣으면 이 주소가 보이지 않는다(복구는 이 지갑이나 개인키(WIF) 내보내기). 기본은 BTC 표준 경로다. |
| D30 | 네트워크 선택(EVM 활성 체인, Solana 클러스터, Bitcoin 네트워크)과 `browserAutoLaunch`는 평문 `settings.json`에 둔다. 사이트별 연결·체인 권한은 암호화된 meta에 둔다. 잠긴 동안 `eth_accounts`는 `[]`, `eth_chainId`는 사이트별 메모리 캐시 또는 활성 체인을 돌려준다. |
| D31 | 문서 간 우선순위: 오류 코드·메시지는 [05](spec/05-browser.md) §5, 승인 digest·표시 인코딩은 [03](spec/03-evm.md) §11, meta·주소록·계정 스키마는 [02](spec/02-core-keys-vault.md) §5, check.ps1과 크레이트 구성은 [01](spec/01-repo-build.md)이 기준이다. |
| D32 | **확인 1개 = 확정(모든 체인).** 설정한 RPC(D13·D26의 인덱서 포함)를 신뢰한다. 추가 확인 수·`finalized` 대기·긴 안전 타이머는 사용자에게 아무것도 주지 않으므로 두지 않는다. 확인 1개로 확정한 거래가 재구성으로 빠지는 것은 체인 문제로 보고 범위 밖이다(§2.2). EVM: 검증한 영수증이 블록에 있으면(1 확인) 그 자리에서 `Finalized`([03](spec/03-evm.md) §4.5; 영수증의 해시·보낸 주소·nonce 검증과 가짜 영수증 방어는 유지). Bitcoin: 확인 1이면 `Confirmed`가 최종이고 추적을 끝내며, 진행 중 규칙(D20) 해제·잔돈 UTXO 사용·포기/공개 거래 충돌 해소도 확인 1로 한다([08](spec/08-bitcoin.md) §12.2; 팁 높이 이상값 검사는 유지). Solana: `confirmed` commitment가 최종이다. 모든 조회는 `confirmed`이고, 만료 증명은 RPC(`confirmed`)의 블록 높이 > 서명한 거래의 `lastValidBlockHeight`이고 `getSignatureStatuses` 이력 검색에 없을 때 한 번으로 성립한다(벽시계·단조 시계 최소 시간, 두 번 관측 없음). 그 뒤에만 새 블록해시로 다시 서명할 수 있고, 그 전에는 **같은 서명 거래를 즉시 다시 전송**("지금 다시 전송")할 수 있다(같은 서명이므로 두 번 지불되지 않음). 저널은 첫 전송 전에 기록한다([07](spec/07-solana.md) §14). |
| D33 | **YubiKey 계정(선택, 2026-11-04).** 니모닉에서 고른 키를 한 번 파생해 YubiKey 5에 가져온다: secp256k1(EVM `m/44'/60'/0'/0/i`, Bitcoin 단일 주소 `m/{44\|49\|84}'/{coin}'/0'/0/i`, Zcash 일반 주소 `m/44'/{133\|1}'/0'/0/i`(2026-11-06), 또는 EVM 키를 BTC 주소로도 쓰는 공유 키)는 OpenPGP SIG·AUT(카드당 최대 2개, 펌웨어 5.2.3+), Ed25519(Solana `m/44'/501'/i'/0'`)는 PIV `82`–`95`·`9A`–`9E`(5.7+). 인덱스는 슬롯마다 사용자가 고른다. 다른 YubiKey에 이미 있는 경로도 그 키의 복사본으로 넣는다(2026-11-12, 확인 화면이 "이미 다른 YubiKey에 있음"으로 알림). 그래서 한 카드에 복사한 키와 새 키를 섞을 수 있다(예: #1 = EVM 0 + BTC 0, #2 = EVM 0 + ZEC 0). 이전에는 슬롯을 "백업 복사본"으로 명시해야만 허용했다(`PathOnOtherCard`, 없앰). PC는 공개키·일련번호·슬롯 표(vault tag 5)만 저장하고 니모닉을 저장하지 않는다. 서명은 승인 창 뒤 PIN(작업마다 입력, 캐시 없음) + 터치(기본 "항상")로 카드가 한다. 표시 무결성은 여전히 PC 승인 창에 있다. 탭루트·카드당 secp256k1 3개 이상은 범위 밖. 세부: [spec/10](spec/10-yubikey.md). |
| D34 | **Hyperliquid HyperCore(2026-11-06).** 같은 secp256k1 EVM 계정의 HyperCore 잔액(선물 `clearinghouseState`의 계정 가치·출금 가능, 현물 `spotClearinghouseState` + `spotMeta` 토큰 정보)을 EVM 탭 카드로 보이고, 지갑이 직접 만드는 **사용자 서명 작업만** 보낸다: `usdSend`·`spotSend`(Core 안 보내기), `usdClassTransfer`(현물↔선물), `withdraw3`(Arbitrum 출금, 고정 수수료 1 USDC), `sendAsset`(Core → HyperEVM 같은 주소, 토큰 시스템 주소), HyperEVM → Core는 기존 EVM 보내기(시스템 주소 가드). **거래(주문·취소·레버리지·API 지갑 승인)는 범위 밖**이다. 서명은 EIP-712 `HyperliquidSignTransaction` v1 도메인을 기존 EVM 키 경로(vault·YubiKey)의 typed-data 서명으로 하고, 승인 창 종류 `HyperCore 전송`(kind 0x40)이 네트워크·작업·받는 주소(주소 오염 검사)·토큰·금액·수수료·원본 typed data를 보인다. API는 공식 주소(메인넷 고정, 테스트넷만 HTTPS로 변경 가능), 응답 `status ok/err`가 활동 상태다(거래 해시 없음, nonce = ms 시각). dApp의 Hyperliquid typed data는 인식해 구조화하고 API 지갑 승인·L1 Agent(chainId 1337) 서명은 고위험으로 표시한다. 세부: [spec/11](spec/11-hypercore.md). |
| D35 | **WalletConnect v2(Reown) 지갑 연결(2026-11-06).** 브라우저 확장 외에 WalletConnect Sign v2로 dApp을 연결한다: 입력은 dApp의 `wc:` URI 붙여넣기(기본)와 스크린샷 QR(클립보드 비트맵·이미지 파일, 자체 QR 복호기). 릴레이는 `wss://relay.walletconnect.org`(did:key Ed25519 JWT)이고 **사용자가 dashboard.reown.com에서 만든 Project ID가 있어야 켜진다(기본 ID 없음)**. 1단계는 `eip155`만(Solana·Bitcoin 네임스페이스 범위 밖), 처리 메서드는 `eth_accounts`·`eth_chainId`(세션에서)·`personal_sign`·`eth_signTypedData_v4`·`eth_sendTransaction`·`wallet_switchEthereumChain`, 나머지 4200. 요청은 세션별 합성 출처(`*.walletconnect.invalid`)의 가상 연결로 확장과 같은 디스패처·승인 창·arm 지연·위험 규칙·시뮬레이션·잠금 대기를 지난다. 메타데이터는 사이트가 주장한 값이므로 모든 창에 "WalletConnect: {url} (사이트가 주장한 주소 — 확인되지 않음)"을 보이고, Verify(v3 JWT·v2 폴백)가 일치를 알리면 "일치(서버 알림)"(증명이 아니므로 주의 톤, 2026-11-10 이전 "확인됨"), 불일치·사기는 고위험(C02·C03). 세션 키와 릴레이 키는 봉인된 meta에 저장되어 재시작 뒤에도 유지된다. 세부: [spec/13](spec/13-walletconnect.md). |
| D36 | **Zcash 일반(transparent) 전송 전용(2026-11-06).** Bitcoin(D26)과 같은 방식의 Zcash 탭: 네트워크(mainnet·testnet)마다 고정 P2PKH 주소 하나, 기본 키는 니모닉의 `m/44'/133'/0'/0/0`(testnet `m/44'/1'/0'/0/0`, ZIP 316 일반 파생과 같음). 선택 키 출처는 `EVM 계정과 같은 키`(명시적 선택·연결성 경고, 기본 아님)와 YubiKey OpenPGP 슬롯(D33). 보내기 대상은 t 주소·TEX(ZIP 320)·통합 주소(ZIP 316)의 일반 수신자뿐이고, 비공개(Sapling·Orchard) 거래와 비공개 주소로 받기는 범위 밖이다(받기 화면이 Zashi 등 비공개 지갑을 안내). 거래는 v5(ZIP 225), 서명은 ZIP 244 `SIGHASH_ALL`(모든 입력 금액·스크립트에 서명하므로 인덱서 값이 틀리면 거래가 무효일 뿐이라 이전 거래 검증이 없다), 수수료는 ZIP 317 기본값. 네트워크 업그레이드는 지갑의 표와 노드 `getblockchaininfo`(`consensus.nextblock`)를 대조해 다르거나 모르는 branch id면 보내지 않고, 만료 높이는 다음 업그레이드를 넘지 않는다. 데이터 원천은 `zcash:<net>` 엔드포인트(D13; `getaddressutxos` 또는 같은 엔드포인트의 Blockbook REST). 진행 중 1건(D20)·공개 거래 입력 예약은 Bitcoin과 같고, 만료 높이가 지나면 입력이 풀린다. 가져온 개인키(압축 WIF 또는 16진수 64자리, vault tag 6 `ZecKey`, 2026-11-07)도 그 네트워크 계정의 키 출처로 쓸 수 있다(`ZecKeySource::Imported`, D9, [spec/12](spec/12-zcash.md) §2.3). 세부: [spec/12](spec/12-zcash.md). |
| D37 | **복구 단어 여러 개(2026-11-07).** 한 지갑(vault)에 BIP39 니모닉을 최대 8개 둔다(흔한 지갑의 "비밀 복구 구문 여러 개"). 각 니모닉은 vault `Bip39` record(tag 1) 하나이며 record id(16바이트 난수)가 니모닉 id다. 첫 record가 **주 니모닉**으로 기존 계정 목록·Solana·Bitcoin·Zcash 파생과 `EvmKeySource::Derived`가 쓰고 바이트 배치는 그대로라 니모닉 하나인 vault는 바뀌지 않는다. 더한 니모닉은 EVM 계정(`m/44'/60'/0'/0/i`, `EvmKeySource::Mnemonic(id, i)`; HyperEVM·HyperCore·WalletConnect·브라우저 연결 포함)을 만든다 — 2026-11-08부터 Solana(태그 8 `m/44'/501'/i'/0'`)·Bitcoin(네 형식의 HD 계정, 고정 주소/HD 모드)·Zcash(`m/44'/{133|1}'/0'/0/0`, 코드 5) 계정도 만든다: 키 출처가 니모닉 id를 가지고(없으면 주 니모닉, 바이트 그대로), 그 계정의 저널 기록만 새 레코드 버전(SOL 2·BTC 3·ZEC 2, 이전 빌드는 그 체인 보내기만 멈춤)이며 meta는 새 최상위 키 `mnemonic_accounts`·`btc_accounts_mn`에 둔다([02] §8.6, [07] §3.5, [08] §3.5·§12.3c, [12] §2.4, [04] §2.24·§6.6). 그 계정의 거래가 아직 확정될 수 있으면 그 니모닉을 지우지 않는다. passphrase·백업 확인은 니모닉마다 따로이며, 백업 확인 전 니모닉의 키로는 서명하지 않는다. 가져오기·만들기·지우기는 비밀번호를 다시 받고, 같은 시드(단어 + passphrase)는 상수 시간 비교로 거부한다. 주 니모닉은 지우지 않는다. 니모닉이 2개 이상인 vault는 이전 빌드가 `UnsupportedPayload`(E-VLT-014, `.prev` 제안 없음)로 연다. 세부: [02](spec/02-core-keys-vault.md) §4.6·§5.3·§8.6, [04](spec/04-app-ui.md) §2.24. |
| D38 | **Solana dApp 거래(2026-11-12).** 세부는 [07](spec/07-solana.md) §20. **종류**: `ApprovalKind::SolTransaction = 0x23` 하나(`is_chain_message` 밖, 새 `is_sol_transaction()`). 모드 `SolTxMode {SignOnly = 1, SignAndSend = 2}`와 `SolSendOptions`는 payload에 있어 digest에 묶인다. **시뮬레이션 묶음**: `NotApplicable`(`check_draft`의 묶음 규칙은 그대로). 시뮬레이션·ALT 주소·실행 전 상태는 표시 필드라 표시 digest에 묶인다. 승인할 때나 서명 직전에 다시 시뮬레이션하지 않는다("더 나빠짐" 검사는 ExactOut 스왑·슬리피지를 거부하게 된다). **해석하지 않은 명령**: X02 고위험, 차단하지 않는다. 내 서명자나 내 토큰 계정이 그 명령에 전달되면 X03 고위험을 더한다. 모르는 프로그램, 알지만 해석하지 않는 프로그램(Stake·Vote·로더·Config·ALT; 이름을 보인다), 형식이 맞지 않는 명령, Token-2022 확장 명령(태그 25 이상)이 모두 여기에 든다. 프리컴파일(Ed25519·Secp256k1·Secp256r1)은 서명 수를 해석하고 자산을 옮기지 않으므로 X02가 아니다. **서명만 경로**: 체인 메시지 경로(`consume_and_sign` → `KeyJob::SignChainMessage{,Card}` → `ChainSignature::SolTxs` → `browser_chain_message_signed`). 서명 전 RPC·저널·활동 기록이 없고(X11이 알림), 잠금·취소는 4001. **서명 후 전송 경로**: 저널 먼저(`sign_sol_inner`와 같은 방식). 서명 전 RPC → `KeyJob::SignSolDapp{,Card}` → 저널 v3 기록 → 기존 전송 루프 → 첫 라운드 뒤 응답. **진행 중 규칙**: dApp 전송은 D20 한 건 규칙의 예외다(지갑이 dApp 거래를 다시 서명하지 않음). 대신 (클러스터, 서명 계정)당 Pending v3 기록 16건, 저널 전체 32건(`SOL_JOURNAL_MAX_RECORDS` 64 중 절반, 나머지는 지갑 앱 보내기 몫) 상한을 두고, 넘거나 저널 자리가 없으면 -32002 `TransactionPending`. **dApp 블록해시의 lvbh**: `isBlockhashValid(B, processed)` → `(true, S)`, 그다음 `getLatestBlockhash(processed, minContextSlot S)`, 그다음 `getBlockHeight(confirmed)`로 기존 범위 검사(`h+SOL_MIN_LVBH_AHEAD ≤ lvbh ≤ h+SOL_MAX_LVBH_AHEAD`). 저장하는 lvbh는 그 processed 최신값이고 만료 판정(`expiry_round`·`decide`)은 그대로다. **durable nonce**: 판정은 Agave `get_durable_nonce`와 같거나 넓다 — 명령 0이 System이고 data 앞 4바이트가 `04 00 00 00`(뒤 바이트 허용)이며 첫 계정이 쓰기 가능하면 nonce 거래다. 서명만은 X08 고위험으로 허용한다. 전송은 파라미터 단계에서 -32602 "durable nonce cannot be sent by the wallet"이고 `check_draft`와 서명기도 거부한다. 저널에 넣지 않는다. **상한**: 한 요청의 거래 ≤ 32건(창 하나·승인 하나), 거래당 최상위 명령 ≤ 64개(파싱 규칙, -32602), 거래 ≤ 1,232 B(16진수 2,464자). **여러 건 전송**: `signAndSendAll`과 Wallet Standard의 여러 입력 전송은 provider의 순차 반복이다(wire 메서드 없음). 중간에 실패하면 이미 보낸 서명을 `data: {signatures: [base58…]}`에 담아 거부한다. **전송 옵션**: `skipPreflight`는 그 기록의 모든 전송에(v3 플래그), `preflightCommitment`는 preflight 하는 모든 전송에(v3 플래그 비트), `minContextSlot`은 첫 전송에만(메모리) 쓴다. `maxRetries`·`commitment`·`mode`는 버린다(루프는 늘 `maxRetries:0`). 별칭은 `recent→processed`, `single`·`singleGossip→confirmed`, `root`·`max→finalized`. **시뮬레이션**: 먼저 `replaceRecentBlockhash:false`. `BlockhashNotFound`(코드 7)이고 nonce 거래가 아닐 때만 `true`로 다시 하고 X19 주의 "블록해시를 바꿔 시뮬레이션했습니다"를 보인다. 실패·결과 없음은 X09 고위험. **ALT 신뢰**: 주소는 RPC가 준 값이고(X10 주의), 해석한 주소를 payload digest(`SolTxItem.loaded`)에 묶는다. 서명 후 전송은 서명 전에 테이블을 다시 해석해 코어가 비교한다(`TablesChanged` → -32603). 서명만은 다시 읽지 않는다(잔여 위험, §2.2). **권한 재확인**: 서명한 바이트나 전송 서명을 담은 응답 직전에 출처의 연결 권한이 여전히 그 공개키를 가리켜야 한다. 아니면 바이트를 버리고 4100 `Unauthorized`로 답한다(전송은 이미 저널에 있으므로 계속 전송되고 활동에 보인다). **엔드포인트**: 세 메서드 모두 필요하다(미리보기에 RPC를 쓴다). 없으면 preflight에서 4901 `ChainUnavailable`. **체인 파라미터**: 선택 `chain ∈ {"solana:mainnet","solana:devnet"}`. 앱 클러스터와 같아야 하며 아니면 -32602. **복구 스캔 출처**(`needs_move_rule`): `check_draft`, 서명기(`PolicyMismatch`), X01에서 거부한다. **수수료 상한**: 지갑이 수수료 지불자(키 0)일 때만 X14 고위험(차단 아님). 기본 상한 100,000 lamports. **Token-2022**: 태그 0–24는 "Token-2022" 이름으로 해석하고, 25 이상(확장 명령: 수수료 전송·기밀 전송·CPI 가드 등)은 해석하지 않은 명령이라 원본 + X02 고위험(내 서명자·토큰 계정이 있으면 X03). 민트 TLV 12 PermanentDelegate·14 TransferHook은 X17 고위험, 1 TransferFeeConfig는 X12 주의. **사이트 부분 서명**: 검증에 실패하면 X01 차단(체인에 들어갈 수 없는 형식 오류). 전송 모드에서 필요한 서명이 빠지면 파라미터 단계 -32602와 X01. **AI 패널**: 끔(`ai_kind = None`). **wire 인코딩**: 소문자 16진수(`sol_signMessage`와 같음). **Phantom 폐기 형식** `request({params:{message: bs58}})`: 지원한다. provider가 base58을 풀어 `shortvec(required) ‖ 64·required 0바이트 ‖ message`로 감싸 같은 wire 메서드를 부르고, Phantom 결과 형태(`{publicKey, signature}`·`{publicKey, signatures}`)로 돌려준다. **런타임 한도**: 계정 키 128개 초과·중복 ComputeBudget 명령은 X18 주의(차단 아님). **규칙·키**: 위험 규칙 계열 `X`(X01–X19, `core/evm/risk/rules.rs` 중앙 표), FieldKey `0x0510–0x051A`·`0x0540`. 새 `ProviderError` 변형은 없다([05] §5). |

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
- BTC·SOL 보내기·받기는 yw-app 화면에서만 쓴다. Bitcoin은 브라우저와 소유 증명(연결 + 메시지 서명)만 한다(D26–D27, [05] §2.13·§3.6). Solana는 브라우저와 연결·메시지 서명에 더해 사이트가 만든 거래의 서명·전송을 한다(D25, D38, [07] §20). 그 바이트도 yw-app이 해석해 승인 창에 보이고 서명한다.

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

확장의 호환 모드(D22, `compatMode` `metamask`·`rabby`, `solCompatMode` `phantom`, `btcCompatMode` `unisat`·`xverse`)는 이 폴더가 아니라 Chrome 확장 저장소(`chrome.storage.local`)에 둔다([spec/05](spec/05-browser.md) §2.12–§2.13). Solana·Bitcoin dApp 연결은 meta의 선택 키 `sol_sites`·`btc_sites`([05] §4.9)에 둔다.

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
| **M7.2** Solana dApp 거래 | 사이트가 만든 legacy·v0(ALT) 거래의 서명만·서명 후 전송(D38, [07] §20), Wallet Standard·Phantom shim, YubiKey | [spec/09](spec/09-testing.md) M7-10 이후의 devnet E2E 목록 1회 수행: wallet-adapter 데모(legacy·v0), v0+ALT 스왑과 skipPreflight, 다른 수수료 지불자의 부분 서명, signAll ×3, signAndSend 착지와 활동 표시, durable nonce 서명만, YubiKey 서명(3회 터치)·전송, Phantom `message` 형식, 전송 중 잠금(서명 응답, 잠금 해제 뒤 재개), `signMessage`로 보낸 거래 바이트의 M01 차단. |
| **M8** Bitcoin | BIP84(기본)·BIP44/49/86 계정, 주소 파싱(5종), P2PKH·P2SH-P2WPKH·P2WPKH·P2TR 서명, 입력 검증, 수수료 정책 | BIP143·BIP173/350·BIP84·BIP49·BIP86·BIP341 벡터, Core sighash.json(레거시), testnet4 E2E, 입력 금액 위조 픽스처 거부, Sparrow/Electrum 복구 확인. |
| **M9** 메인넷 소액 | 체크리스트 | [spec/09](spec/09-testing.md) §메인넷 체크리스트 1회 수행 후 소액만 사용. |

예상 작업량(집중 작업일 기준): M0–M5 약 30–40일, M7 v1(SOL) 약 23–36일 + v1.1(SPL) 8–12일, M8 약 40–60일.

---

## 6. 아카이브에서 가져오는 것과 버리는 것

자세한 파일·줄 범위는 [spec/01](spec/01-repo-build.md) §6.

- **가져온다(수정해서):** `secret-core`(BIP32, vault 코드 패턴, 비밀번호), `wallet-model`(경계 타입, EIP-191/712 preimage), `eip712`(serde 제거), `wallet-protocol`의 승인 digest·표시 파생 일부, `key-agent`의 서명 후 검증·백업 확인 흐름·저널 패턴, `broker`의 메서드 허용 목록·파라미터 검증, `native-host`의 프레이밍, `approval-ui`·`approval-wire`의 승인 창 상태 기계·표시 문자 규칙, `secret-input-ui`의 WM_CHAR 비밀 입력·캡처 제외, 데모의 RPC 클라이언트·ERC-20·QR·원자적 쓰기·벡터, `extension/` 전체, `scripts/privacy-scan.mjs`, `docs/recovery-guide.ko.md`.
- **버린다:** `platform-windows`, `key-agent-service*`, `key-agent-debugger*`, `dashboard`, 데모의 egui·ureq·자체 vault, `scripts/architecture-scan.mjs`, `scripts/release/*`(audit-extension 제외), `scripts/service-probe/*`, `scripts/windows-evidence/*`, Windows 설계 문서·ADR·개발 로그.
