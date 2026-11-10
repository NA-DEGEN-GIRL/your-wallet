# 처음 실제 사용 체크리스트 (메인넷·소액)

실제 자산을 처음 넣기 전에 위에서부터 차례로 한 번 한다. 금액은 체인마다 잃어도 되는 소액(약 10–20 USD 상당)만 쓴다.
자세한 절차: 설치 [install.ko.md](install.ko.md), 백업·복구 [recovery-guide.ko.md](recovery-guide.ko.md), 판정 기준
[spec/09](../spec/09-testing.md) §5.11(M9).

멈춤 규칙(모든 단계): 주소가 한 글자라도 다르거나, 승인 창의 받는 주소·금액·네트워크·수수료가 내가 한 일과 다르면
**거부**하고 더 진행하지 않는다. 실제 복구 단어는 이 앱 밖(다른 지갑 앱·사진·클라우드·메신저)에 절대 넣지 않는다.

## 0. 준비

- [ ] 종이·펜(복구 단어용), 휴대폰(받기 QR 대조용).
- [ ] 대조용 지갑 앱(공식 배포처에서): EVM은 MetaMask 또는 Rabby, Solana는 Phantom 또는 Solflare, Bitcoin은
      Sparrow(네 주소 형식 모두) 또는 Electrum(BIP39 seed, 탭루트 없음), Zcash는 Zashi 또는 YWallet.
- [ ] QuickNode 엔드포인트 하나(쓸 체인을 대시보드에서 각각 켠다). WalletConnect를 쓸 거면 dashboard.reown.com의
      Project ID(32자리).
- [ ] (권장, spec.md §2.4) 일상 Windows 계정이 표준 사용자이고 BitLocker가 켜져 있다.

## 1. 설치·업데이트

1. [ ] 저장소 폴더에서 `git status`(내가 바꾸지 않은 파일·새 파일이 없어야 함)와 `git log -1 --format=%h`(설치할
   커밋)를 본다.
2. [ ] 낮은 무결성 레이블 확인: `icacls "<저장소 폴더>"` 출력에 `Mandatory Label\Low Mandatory Level` 줄이 있으면, 직접
   붙인 것이 아닌 한 설치 전에 되돌린다(하위 항목에 따로 붙은 레이블이 남으면 끝에 `/T`). 다시 `icacls`로 그 줄이
   없어졌는지 본다.

   ```
   icacls "<저장소 폴더>" /setintegritylevel (OI)(CI)M
   ```

   레이블을 붙인 도구(코딩 도구의 샌드박스 등)는 그 뒤 저장소에 쓰지 못할 수 있다. 설치가 끝난 뒤 다시 붙여도 이미
   설치한 앱에는 영향이 없고, 다음 업데이트 때 다시 묻는다.
3. [ ] 레이블을 그대로 두고 설치하면 `install.cmd`가 목록과 위 명령을 보이고 묻는다. 1의 `git status`가 깨끗할 때만
   정확히 `계속`(또는 `continue`)을 입력한다(한/영 상태 주의 — 두 번까지 다시 묻는다). Enter만 누르면 설치를 취소한다.
4. [ ] (업데이트면) 앱을 닫고(작업 관리자에 `yw-app.exe`도 없게) 데이터 폴더를 복사해 둔다.

   ```powershell
   Copy-Item -Recurse "$env:LOCALAPPDATA\YourWallet\v3" "$env:LOCALAPPDATA\YourWallet\v3-backup-$(Get-Date -Format yyyyMMdd)"
   ```

5. [ ] `install.cmd` 실행 → 끝 요약의 커밋이 1과 같은지 본다.
6. [ ] Chrome 확장: 처음이면 `chrome://extensions` → 개발자 모드 → 압축해제된 확장 로드 →
   `%LOCALAPPDATA%\Programs\YourWallet\extension`, 카드의 ID가 `nnpjlobjgbanccjddghlpaafpohfkeph`인지 확인.
   업데이트면 카드의 **새로고침**(↻)과 열려 있던 dApp 탭 새로고침.
7. [ ] 앱을 열고 설정 → 브라우저·정보 → 정보의 "버전 0.3.0 · 커밋 …"이 1의 커밋으로 시작하는지 본다.

## 2. 다른 지갑과 주소 대조 (연습용 복구 단어로)

실제 복구 단어는 다른 앱에 넣지 않으므로 대조는 버릴 연습용 지갑으로 한다. 이 단계의 단어·지갑은 끝나면 다시 쓰지 않는다.

1. [ ] 처음 화면 → 새 지갑 만들기 → 연습용 단어를 적고 백업 확인 → RPC 연결(3-2와 같음).
2. [ ] EVM(두 번째 계정은 `계정 추가`): MetaMask/Rabby에 같은 단어 → 계정 1·2 주소가 이 앱의 계정 1·2
   (`m/44'/60'/0'/0/0`, `…/1`)와 같다. HyperCore 계정은 이 EVM 주소 그대로다.
3. [ ] Solana(두 번째 계정은 Solana 탭의 `계정 추가`): Phantom/Solflare(경로 `m/44'/501'/0'/0'`) → 계정 0·1이
   Solana 1·2와 같다.
4. [ ] Bitcoin(설정 → Bitcoin → "Bitcoin 사용", 네트워크 mainnet; 다른 형식은 Bitcoin 탭 `계정 추가`): 형식마다
   받기 0번(`…/0/0`) 주소가 같다 — 네이티브 세그윗 `m/84'/0'/0'`(bc1q…), 탭루트 `m/86'/0'/0'`(bc1p…, Sparrow),
   호환 세그윗 `m/49'/0'/0'`(3…), 레거시 `m/44'/0'/0'`(1…). 기본 '고정 주소' 방식은 받기·잔돈 모두 이 주소 하나다
   (HD 방식으로 바꾼 계정은 받기 0–4도 대조).
5. [ ] Zcash(Zcash 탭 → `Zcash mainnet 켜기`): Zashi·YWallet의 일반(transparent, `t1…`) 주소 — 계정 0의 첫 주소
   (`m/44'/133'/0'/0/0`) — 와 같다.
6. [ ] 대조가 끝나면 다른 앱들에서 연습용 지갑을 지우고, 이 앱은 설정 → 보안 → 지갑 초기화(칸에 `초기화` 입력 후 빨간
   버튼 2초)로 처음 화면으로 돌아간다. "설정과 API 키도 함께 옮기기"를 켜지 않으면 RPC 주소는 그대로 남는다.

## 3. 실제 지갑과 복구 훈련 (입금 전)

1. [ ] 화면을 볼 사람·카메라가 없는 곳에서 새 지갑 만들기 → 24단어와 첫 주소(계정 1)를 종이에 적고 백업 확인.
   종이는 PC와 다른 곳에 둔다.
2. [ ] 완료 화면 '처음 설정' → **QuickNode 주소**에 대시보드 주소 전체 → **연결하기** → "13개 중 n개 작동".
   ✗인 네트워크는 대시보드에서 그 체인을 켠 뒤 설정 → 네트워크(RPC) → **모두 테스트**.
3. [ ] 복구 훈련: 각 탭에서 쓸 주소(EVM 계정 1, Solana 1, Bitcoin 형식별 받기 0번, Zcash)를 적는다 → 설정 → 보안 →
   지갑 초기화(설정과 API 키는 남김) → 기존 지갑 가져오기 → 종이의 24단어 → 적어 둔 주소가 모두 같다.
   초기화는 파일을 지우지 않고 `%LOCALAPPDATA%\YourWallet\v3\reset-<시각>`으로 옮긴다. 가져온 개인키·YubiKey·추가
   복구 단어는 초기화 뒤 다시 더해야 하므로 이 훈련은 그것들을 더하기 **전에** 한다.
4. [ ] 설정 → 보안의 '백업 현황'이 종이의 복구 단어로 이 지갑을 다시 열 수 있다고 말하는지 본다.

## 4. 받기 → 보내기 (체인마다 소액, 쓰는 것만)

공통: 받기 화면의 QR을 휴대폰으로 읽어 화면의 주소와 전체를 비교한다(EVM은 종이의 첫 주소와도). 화면 위 띠가 빨간
"메인넷 — 실제 자산"인지 본다. 입금이 보이면(`새로고침` 또는 F5) 절반쯤을 본인의 다른 주소(거래소 입금 주소 등)로
보내고, 승인 창에서 빨간 메인넷 알약·받는 주소 전체·금액·수수료를 읽은 뒤 승인한다. 결과는 활동 행과 탐색기로 확인한다.

- [ ] EVM: 네트워크 칩에서 Ethereum 메인넷(EVM 탭은 Sepolia로 시작한다). 쓰는 체인마다 — Ethereum, Arbitrum One,
      Base, BNB Smart Chain, HyperEVM, Robinhood Chain — 받기·보내기 1회. 토큰(USDC 등)은 선택(토큰을 보낼 때 수수료는
      그 체인의 기본 자산으로 낸다).
- [ ] Solana: Solana 탭의 네트워크를 Solana mainnet으로 → SOL 받기·보내기. SPL 토큰은 선택.
- [ ] Bitcoin: 쓰는 주소 형식마다 받기 → 1 확인을 기다린 뒤 보내기. 보내기 폼의 수수료 미리 보기(빠름·보통·느림의
      sat/vB와 예상 수수료)와 승인 창의 실제 수수료가 크게 다르지 않은지 본다.
- [ ] Zcash: 일반 주소(`t1…`)로 받기 → 보내기. 비공개(shielded) 주소로 받는 기능은 없다.
- [ ] HyperCore(EVM 탭의 HyperCore 카드; HyperEVM·Arbitrum이 아닌 체인에서는 접혀 있어 `펼치기 ▸`): Hyperliquid 공식
      안내의 최소 입금액을 먼저 확인하고 USDC를 소액 입금한다(거래소 출금 또는 app.hyperliquid.xyz). `보내기(Core)`로
      본인 다른 주소에 1회. **Arbitrum 출금**은 1 USDC보다 큰 금액으로 하고, 승인 창의 "Arbitrum 도착 = 금액 − 1 USDC
      = …"와 Arbitrum One에 실제로 도착한 금액(금액 − 1 USDC, 몇 분 걸림)이 같은지 본다.

## 5. dApp 연결과 메시지 서명

- [ ] Chrome 확장: 메인넷 dApp 하나에서 "지갑 연결" → Your Wallet(목록에 없으면 툴바의 Your Wallet 아이콘에서
      'MetaMask처럼 보이기' — Solana는 'Phantom처럼', Bitcoin은 'UniSat처럼'·'Xverse처럼' — 를 고르고 탭 새로고침) →
      연결 창의 사이트 주소와 고른 계정을 보고 연결.
- [ ] 메시지 서명은 로그인 하나씩만: EVM `personal_sign`(SIWE)은 승인 창의 도메인이 지금 사이트와 같은지, Solana
      로그인(SIWS)·메시지와 Bitcoin 메시지·로그인(SIWB)은 서명 계정과 메시지 원문을 읽고 승인한다. 첫 사용에서는 토큰
      승인(approve)·permit·Permit2 서명을 하지 않는다 — 요약이 권한을 주는 문장("…권한을 줍니다", "…쓸 수 있게 /
      가져갈 수 있게 하는 서명")이면 거부.
- [ ] 끝나면 사이트·WalletConnect 화면에서 그 사이트 연결을 해제한다.
- [ ] WalletConnect(EVM, 선택): 사이트·WalletConnect 화면 → Project ID 저장 → dApp의 WalletConnect 연결 주소(`wc:…`)를
      복사 → **클립보드에서 연결** → 연결 창의 "사이트가 주장한 주소"와 Verify 배지를 보고 연결 → 메시지 서명 1회 →
      세션 끊기.

## 6. YubiKey (쓸 때만)

- [ ] YubiKey 5(펌웨어 5.2.3 이상, Solana는 5.7.4 이상). 설정 → YubiKey → `YubiKey 등록`, 또는 처음 화면의
      'YubiKey에 보관하는 새 지갑'(1 비밀번호 · 2 복구 단어 적기 · 3 백업 확인 · 4 YubiKey에 넣기 · 5 PIN 정하기).
- [ ] **PIN 먼저**: 결과 화면의 PIN 카드에서 바로 `PIN 설정하기`(8자리 하나로 통일). 공장 기본 PIN인 카드의 계정은
      받기만 되고 서명은 막힌다. 새 PIN은 따로 기억한다(앱에 저장하지 않는다).
- [ ] Sepolia·devnet에서 YubiKey 계정으로 한 번 보낸 뒤 메인넷 소액: 승인 → PIN 창 → 깜박이면 15초 안에 터치.
- [ ] 설정 → 보안 '백업 현황'에서 YubiKey 키마다 "복구 단어로 다시 만들 수 있음"인지 본다. "복구 단어 없음 … ⚠"인
      키에는 잃어도 되는 금액만 둔다(같은 키를 가진 백업 YubiKey가 있으면 그 카드로도 서명할 수 있다).

## 7. 복구 단어 여러 개 (쓸 때만)

- [ ] 설정 → 복구 단어 → `새 복구 단어 만들기 (추가)` 또는 `복구 단어 추가 가져오기`(최대 8개). 단어와 첫 주소를
      복구 단어마다 **따로** 적고 백업 확인 — 확인 전에는 받기만 된다.
- [ ] 복구 단어 카드의 "첫 주소"가 종이와 같고, 계정 이름 뒤 `[복구 단어 n]`으로 구분되는지 본다. 각 탭의
      `계정 추가`에서 복구 단어를 골라 계정을 만든다.
- [ ] passphrase를 쓴 복구 단어는 잠금 해제 때 차례로 묻는다.

## 8. 로그와 문제가 생겼을 때

- 로그: `%LOCALAPPDATA%\YourWallet\v3\logs\yw-app.log`(+ `.1`–`.4`, 1 MiB씩), 설정 → 브라우저·정보 → 진단 →
  `로그 폴더 열기`. 비밀번호·복구 단어·키·RPC 주소·dApp 주소는 남지 않고, 계정 주소와 거래 해시는 있을 수 있다.
  yw-host(브라우저 연결)는 로그를 쓰지 않는다.
- 알릴 때는 오류 코드(`E-…`)가 있는 줄만 보낸다. 복구 단어·비밀번호·RPC 주소는 절대 함께 보내지 않는다.
- 데이터는 `%LOCALAPPDATA%\YourWallet\v3`, 프로그램은 `%LOCALAPPDATA%\Programs\YourWallet`. 문제 해결 표:
  [install.ko.md](install.ko.md) §9.
