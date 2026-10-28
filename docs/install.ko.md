# 설치·업그레이드·제거 안내

미리 빌드된 배포 zip(`YourWallet-<버전>-win-x64.zip`)으로 Your Wallet을 설치하는 방법이다(spec.md D1).
관리자 권한 없이 현재 Windows 사용자에게만 설치하며, 지갑 데이터는 설치·업그레이드·제거 때 건드리지 않는다.
소스에서 직접 빌드하는 방법은 [README](../README.md)와 [spec/01](../spec/01-repo-build.md)을 본다.

## 요구 사항

- Windows 11 x64(22H2 이상), Chrome 120 이상
- Windows PowerShell 5.1(Windows에 기본 포함) 또는 PowerShell 7
- 관리자 권한은 필요 없다. 설치는 `%LOCALAPPDATA%\Programs\YourWallet`, 현재 사용자 시작 메뉴(`%APPDATA%`),
  `HKCU`(현재 사용자 레지스트리)만 바꾼다.

## zip에 들어 있는 것

| 파일 | 내용 |
|---|---|
| `yw-app.exe` | 지갑 본체(키·vault·승인 창·RPC) |
| `yw-host.exe` | Chrome이 실행하는 native messaging 중계 프로그램(비밀 없음) |
| `extension\` | Chrome 확장(압축해제 로드용, 실행에 필요한 파일만) |
| `install.ps1`, `uninstall.ps1` | 설치·제거 스크립트 |
| `README-설치.txt` | 짧은 안내 |
| `SHA256SUMS` | 위 파일 전부의 SHA-256 |

## 1. 내려받기와 무결성 확인

1. zip 파일의 SHA-256을 배포자가 zip과 **다른 경로**로 알려 준 값(릴리스 메모, 메신저 등)과 비교한다.

   ```powershell
   Get-FileHash .\YourWallet-0.3.0-win-x64.zip
   ```

   값이 한 글자라도 다르면 쓰지 않는다. zip 안의 `SHA256SUMS`는 전송 중 손상·일부만 풀린 경우를 잡지만,
   zip 자체를 바꾼 사람은 `SHA256SUMS`도 바꿀 수 있으므로 진본 확인은 이 단계(또는 같은 커밋의 소스 재빌드)로만 한다.
2. (선택) 해시를 확인했다면 zip 파일 우클릭 → 속성 → 아래쪽 **차단 해제** 체크 → 확인. 그러면 압축을 푼
   프로그램에 "인터넷에서 받은 파일" 표시가 붙지 않아 첫 실행 때 SmartScreen 창이 뜨지 않는다.
3. 압축을 푼다(탐색기 "압축 풀기" 또는 `Expand-Archive`). `YourWallet-<버전>` 폴더 하나가 생긴다.
   이 폴더는 설치 뒤 지워도 된다.
4. 압축을 푼 파일을 직접 확인하려면 그 폴더에서:

   ```powershell
   Get-Content .\SHA256SUMS -Encoding UTF8 | ForEach-Object {
       $hash, $file = $_ -split '  ', 2
       if ((Get-FileHash -Algorithm SHA256 -LiteralPath $file).Hash -eq $hash) { "OK    $file" } else { "실패  $file" }
   }
   ```

   Git Bash가 있으면 `sha256sum -c SHA256SUMS`도 된다. `install.ps1`은 설치 전에 같은 확인을 자동으로 하고,
   하나라도 다르면 아무것도 바꾸지 않고 멈춘다(종료 코드 2).

## 2. 설치

압축을 푼 폴더에서 PowerShell을 열고(탐색기 주소창에 `powershell` 입력) 실행한다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -DryRun   # 할 일만 보기(아무것도 바꾸지 않음)
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1           # 설치
```

`-ExecutionPolicy Bypass`는 이 한 번의 실행에만 적용되며 시스템 실행 정책을 바꾸지 않는다.

설치 스크립트가 하는 일:

1. `SHA256SUMS`로 압축을 푼 모든 파일과 확장 ID(`nnpjlobjgbanccjddghlpaafpohfkeph`)를 확인한다.
2. 바꿀 파일을 실행 중인 `yw-app`·`yw-host`가 쓰고 있으면 닫아 달라고 묻는다. 강제로 종료하지 않는다.
   `C`를 입력하면 지갑 앱에 정상 종료를 요청한다(창의 닫기 버튼과 같다: 잠근 뒤 종료).
3. `%LOCALAPPDATA%\Programs\YourWallet\`에 복사한다. 내용이 같은 파일은 건너뛰고, 이전 버전에만 있던 파일은 지운다.
4. `yw-host.exe` 옆에 Chrome native host manifest(`com.your_wallet.native.json`)를 쓰고 검증한다.
5. `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.your_wallet.native`에 그 manifest를 등록한다.
6. 시작 메뉴에 `Your Wallet` 바로가기를 만든다.
7. 확장 로드 방법을 출력한다.

여러 번 실행해도 결과가 같다. 지갑 데이터 폴더 `%LOCALAPPDATA%\YourWallet\`은 읽지도 바꾸지도 않는다.

| 옵션 | 뜻 |
|---|---|
| `-InstallDir <폴더>` | 설치 폴더(기본 `%LOCALAPPDATA%\Programs\YourWallet`). 비어 있거나 이전 설치 폴더여야 한다 |
| `-NoShortcut` | 시작 메뉴 바로가기를 만들지 않는다 |
| `-NoNativeHost` | HKCU 등록을 하지 않는다(manifest 파일은 쓴다). 이 경우 확장은 앱에 연결되지 않는다 |
| `-DryRun` | 확인과 할 일 출력만 한다 |

| 종료 코드 | 뜻 |
|---|---|
| 0 | 성공(`-DryRun` 포함) |
| 1 | 환경·경로 오류: `LOCALAPPDATA` 없음, 64비트 Windows 아님, 설치 경로에 `" % & ^ \| < > !`가 있음, 설치 기록 없는 비어 있지 않은 폴더, 지갑 데이터 폴더와 겹침 |
| 2 | 패키지 무결성 오류: `SHA256SUMS` 없음·형식 오류, 파일 누락·해시 불일치, 확장 ID 불일치 |
| 3 | 취소: 사용자가 `Q`를 입력했거나, 비대화형 실행이라 실행 중인 프로그램을 닫아 달라고 물을 수 없음 |
| 4 | 파일 복사·삭제 실패 |
| 5 | native host manifest 검증 또는 HKCU 등록 실패 |
| 6 | 시작 메뉴 바로가기 생성 실패 |
| 9 | 예상하지 못한 오류(출력된 줄 번호와 함께 알린다) |

사용자 이름에 `&`·`%`·`!` 같은 문자가 있으면 기본 경로를 쓸 수 없다(Chrome이 `cmd.exe`로 host를 실행할 수 있어서다).
`-InstallDir C:\YourWallet`처럼 단순한 경로를 지정한다.

## 3. Chrome 확장 로드 (처음 한 번)

1. Chrome 주소창에 `chrome://extensions`를 입력한다.
2. 오른쪽 위 **개발자 모드**를 켠다.
3. **압축해제된 확장 프로그램을 로드합니다** → `%LOCALAPPDATA%\Programs\YourWallet\extension` 폴더를 선택한다
   (폴더 선택 창 주소창에 `%LOCALAPPDATA%\Programs\YourWallet\extension`을 그대로 붙여 넣어도 된다).
4. 카드에 표시된 ID가 `nnpjlobjgbanccjddghlpaafpohfkeph`인지 확인한다. 다르면 쓰지 말고 그 카드를 삭제한다.
   ID가 다르면 yw-host가 연결을 거부한다.
5. 툴바의 퍼즐 아이콘 → Your Wallet 옆 핀을 누르면 호환 모드 팝업을 바로 열 수 있다.

Chrome을 켤 때 "개발자 모드 확장 프로그램" 경고가 뜰 수 있다(웹 스토어 배포를 하지 않으므로 정상).
소스 저장소의 `extension\` 폴더로 로드한 카드가 이미 있으면 먼저 삭제하고 설치 폴더의 `extension`을 로드한다.

## 4. 첫 실행

1. 시작 메뉴 → **Your Wallet**.
2. 코드 서명을 하지 않은 프로그램이라 "Windows의 PC 보호"(SmartScreen) 창이 뜰 수 있다. 1단계에서 zip 해시를
   확인했다면 **추가 정보** → **실행**. (1단계의 "차단 해제"를 했다면 뜨지 않는다.)
   Windows 보안의 **스마트 앱 컨트롤**이 "켜기"이면 서명되지 않은 프로그램 실행이 막힐 수 있다. 이 문서는 그 설정을
   바꾸라고 권하지 않는다. 상태는 Windows 보안 → 앱 및 브라우저 컨트롤 → 스마트 앱 컨트롤 설정에서 볼 수 있다.
3. 새 지갑 만들기 → 24개 복구 단어를 종이에 적고 백업 확인을 마친다([복구 안내](recovery-guide.ko.md)).
4. RPC 설정(QuickNode 멀티체인 템플릿):
   1. QuickNode 대시보드에서 엔드포인트 주소(HTTP Provider)를 확인한다. 모양은 `https://<이름>.quiknode.pro/<토큰>/`
      또는 체인 서브도메인이 붙은 `https://<이름>.<체인>.quiknode.pro/<토큰>/`이다. `<이름>`은 첫 `.` 앞,
      `<토큰>`은 `.quiknode.pro/` 바로 뒤의 경로 한 조각이다(뒤에 `nanoreth` 같은 경로가 더 있어도 넣지 않는다).
      멀티체인 엔드포인트에서 쓸 체인(Ethereum, Sepolia, HyperEVM, Solana, Bitcoin mainnet·testnet4)을 **각각 켜야** 한다.
      켜지 않은 체인은 테스트가 E-RPC-003(인증 거부) 또는 E-RPC-007(요청 거부, HTTP 404 포함)로 실패한다.
   2. 앱의 **설정** → **네트워크(RPC)** → RPC 공급자에서 **QuickNode 멀티체인**을 고른다.
   3. **엔드포인트 이름**과 **토큰**을 넣고 **저장**한다. 저장한 값은 Windows DPAPI로 암호화되어 다시 보이지 않는다.
      E-KEY-002가 나오면 이름 칸에 주소 전체나 대문자·`_`가 들어갔는지, 토큰 칸에 `/`가 들어갔는지 확인한다.
   4. **네트워크 URL 생성** → **생성**. 네트워크별 주소가 한 번에 만들어진다(HyperEVM은 `…/<토큰>/nanoreth`,
      Bitcoin testnet4는 `<이름>.btc-testnet4.quiknode.pro`).
   5. 아래 **네트워크별 RPC 주소**에서 쓰는 네트워크마다 **테스트**. 실패하는 네트워크는 대시보드에서 그 체인이 켜져
      있는지 확인하거나 **교체**로 `https://` 주소를 직접 넣는다.

   RPC 주소 전체(이름·토큰 포함)가 비밀이다. 스크린샷·메신저·이슈에 붙이지 않는다. Bitcoin 조회는 기본으로 키가
   필요 없는 Esplora(mempool.space)를 쓴다(설정 → Bitcoin). mempool.space에 연결되지 않으면(E-BTC-001·E-BTC-002가
   계속됨) 설정 → Bitcoin → **Esplora URL**을 `https://blockstream.info/api`(testnet4는
   `https://blockstream.info/testnet4/api`)로 바꾸고 **저장** → **테스트**한다. 되돌릴 때는 **기본값으로**.
5. dApp 연결: 확장이 로드된 Chrome에서 dApp의 지갑 연결을 누르면 yw-app 승인 창이 뜬다. 앱이 꺼져 있으면
   yw-host가 자동으로 실행한다(설정 → 브라우저·진단·정보 → "dApp 요청 시 앱 자동 실행", 기본 켜짐).

## 5. 업그레이드

1. **업그레이드 전 v3 폴더 백업.** 지갑 앱을 닫고(가능하면 진행 중인 거래가 없을 때)
   `%LOCALAPPDATA%\YourWallet\v3` 폴더 전체를 다른 곳(예: `v3-backup-<날짜>`)에 복사한다. 새 버전에 문제가 있어
   이전 버전으로 되돌릴 때 이 사본을 쓴다. 보관 주의는 8단계와 같다(복사본도 복구 단어 수준으로 보관, 클라우드
   동기화 폴더에 두지 않는다). 아래 예의 위치는 `uninstall.ps1 -RemoveWalletData`가 함께 지운다.

   ```powershell
   Copy-Item -Recurse "$env:LOCALAPPDATA\YourWallet\v3" "$env:LOCALAPPDATA\YourWallet\v3-backup-$(Get-Date -Format yyyyMMdd)"
   ```
2. 새 zip을 받아 1단계대로 확인하고 새 폴더에 푼다.
3. 그 폴더에서 `install.ps1`을 실행한다. 지갑 앱이 실행 중이면 닫아 달라고 묻는다(강제 종료하지 않음).
   설치된 버전과 새 버전이 출력되고, 바뀐 파일만 교체한다.
4. `chrome://extensions`의 Your Wallet 카드에서 새로고침 버튼을 누르고, 열려 있던 dApp 탭도 새로고침한다.

지갑 데이터(`%LOCALAPPDATA%\YourWallet\v3`)는 그대로 남아 새 버전이 이어서 쓴다. 이전 vault 형식(v1·v2)은
옮기지 않는다(spec.md D7: 복구 단어로 다시 가져온다).

버전 사이의 파일 호환(spec/04 §6.6):

- 새 버전이 설정(`settings.json`)·메타(`meta.ywm`)에 새 항목을 더해도, 그 파일을 이전 버전으로 열면 모르는 항목을
  지우지 않고 그대로 다시 쓴다. `apikeys.dpapi`의 모르는 항목과 지금 등록되지 않은 체인의 RPC 주소도 지우지 않는다.
- 새 버전이 설정 형식 자체를 바꾼 경우(`settings.json`의 `version`이 더 큼) 이전 버전은 그 파일을 **읽기 전용**으로
  열고 "settings.json은 더 새로운 버전…" 배너(E-APP-001)를 보인다. 이때 설정 변경은 이번 실행에만 적용되고 파일에
  저장되지 않는다. 새 버전을 다시 설치하면 그대로 이어서 쓴다.
- vault·저널 형식이 바뀌는 큰 변경은 새 데이터 폴더(`v4`)를 쓰므로 `v3` 폴더를 덮어쓰지 않는다.
- 되돌리기: 앱을 닫고 이전 버전 zip으로 `install.ps1`을 실행한다. 데이터까지 이전 상태로 돌리려면 `v3` 폴더를
  1단계의 사본으로 통째로 바꾼다(사본 이후의 계정 이름·주소록·활동 기록 변경은 사라진다. 자산은 체인에 있으므로
  영향이 없다).

## 6. 제거

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\YourWallet\uninstall.ps1" -DryRun   # 지울 것만 보기
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\YourWallet\uninstall.ps1"
```

- 설치 폴더 안의 `uninstall.ps1`을 실행하면 그 폴더를 제거한다(`-InstallDir`로 다른 곳에 설치했어도 같다).
  다른 곳에 둔 사본으로 제거할 때는 `-InstallDir <설치 폴더>`를 준다.
- 지우는 것: 시작 메뉴 바로가기(이 설치를 가리킬 때만), HKCU native host 등록(이 설치의 manifest를 가리킬 때만),
  설치 폴더에서 `install.ps1`이 설치한 파일(`yw-install.json` 목록)과 manifest. 목록에 없는 파일은 남긴다.
- **지우지 않는 것: 지갑 데이터 `%LOCALAPPDATA%\YourWallet\`**. 다시 설치하면 그대로 쓴다.
- Chrome 확장 카드는 `chrome://extensions`에서 직접 **삭제**한다.
- 지갑 데이터까지 지우려면 `-RemoveWalletData`를 붙인다. 직접 연 PowerShell 창에서 `DELETE MY WALLET`을 정확히
  입력해야 하며, 그 밖의 입력이나 비대화형 실행은 아무것도 지우지 않고 멈춘다. **지우기 전에 종이에 적은 24개
  복구 단어(passphrase를 썼다면 그것도)를 다시 확인한다. 그것이 지갑의 유일한 백업이다.**

| 종료 코드 | 뜻 |
|---|---|
| 0 | 성공(`-DryRun`, 이미 제거된 경우 포함) |
| 1 | 환경 오류, 또는 설치 기록 없는 폴더라 프로그램 파일을 지우지 않음 |
| 3 | 취소: 사용자 취소, 확인 문구 불일치, 비대화형 실행 |
| 4 | 일부 항목을 지우지 못함(yw-app·Chrome을 닫고 다시 실행) |
| 9 | 예상하지 못한 오류 |

## 7. 파일 위치

| 위치 | 내용 |
|---|---|
| `%LOCALAPPDATA%\Programs\YourWallet\` | `yw-app.exe`, `yw-host.exe`, `extension\`, `uninstall.ps1`, `README-설치.txt`, `com.your_wallet.native.json`(native host manifest), `yw-install.json`(설치 기록) |
| `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.your_wallet.native` | 기본값 = 위 manifest 경로 |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Your Wallet.lnk` | 시작 메뉴 바로가기 |
| `%LOCALAPPDATA%\YourWallet\v3\vault.ywv` (+`.prev`) | vault(복구 단어·키, vault 비밀번호로 암호화) |
| `%LOCALAPPDATA%\YourWallet\v3\meta.ywm` (+`.prev`) | 계정·주소록·연결된 사이트·토큰·활동(암호화) |
| `%LOCALAPPDATA%\YourWallet\v3\journal.ywj` (+`.prev`) | 진행 중 거래 저널(암호화) |
| `%LOCALAPPDATA%\YourWallet\v3\settings.json` | 비밀이 아닌 설정(평문) |
| `%LOCALAPPDATA%\YourWallet\v3\apikeys.dpapi` | RPC 주소·템플릿 자격 정보·LLM 키(Windows DPAPI, 이 PC의 이 사용자만 풀 수 있음) |
| `%LOCALAPPDATA%\YourWallet\v3\logs\yw-app.log` (+`.1`–`.4`) | 로그(1 MiB씩 5개 순환, 비밀·RPC 주소·dApp origin 없음) |

yw-host는 로그 파일을 쓰지 않는다. 문제를 알릴 때는 `logs\yw-app.log`의 오류 코드 줄을 보내되, 복구 단어·비밀번호·
RPC 주소는 절대 함께 보내지 않는다.

## 8. 백업

1. **복구 단어 24개(와 쓴 경우 BIP39 passphrase)가 유일한 백업이다.** 종이(또는 금속)에 적어 PC와 다른 곳에 둔다.
   사진·클라우드·메신저·암호 관리자에 저장하지 않는다([복구 안내](recovery-guide.ko.md)).
2. (선택) 라벨·주소록·연결된 사이트까지 보존하려면 지갑 앱을 닫은 뒤(가능하면 진행 중인 거래가 없을 때)
   `%LOCALAPPDATA%\YourWallet\v3` 폴더 전체를 오프라인 저장 장치에 복사한다.
   - vault·meta·journal은 vault 비밀번호로 암호화되어 있지만, 복사본을 가진 사람은 비밀번호를 무차별 대입해 볼 수
     있으므로 복구 단어와 같은 수준으로 보관한다.
   - `apikeys.dpapi`는 이 PC의 이 Windows 사용자만 풀 수 있다. 다른 PC·사용자로 옮기면 RPC 주소를 다시 넣는다.
   - 되돌릴 때는 지갑 앱을 닫고 `v3` 폴더를 통째로 바꾼다.
3. 파일 백업이 있어도 복구 단어가 없으면 PC 분실·고장·비밀번호 분실 때 지갑을 되살릴 수 없다.

## 9. 문제 해결

| 증상 | 원인·조치 |
|---|---|
| `install.ps1`이 종료 코드 2 | 파일이 손상되었거나 일부만 풀렸다. zip을 다시 받아 해시를 확인하고 새 폴더에 푼다 |
| `install.ps1`이 종료 코드 3 | 지갑 앱이나 Chrome이 파일을 쓰고 있다. 앱 창을 닫고(안 보이면 시작 메뉴로 열어서 닫기) Chrome 창을 모두 닫은 뒤 다시 실행 |
| dApp이 "Wallet is unavailable."(4900) | 앱이 꺼져 있고 자동 실행이 꺼져 있거나 실행에 실패했다. 시작 메뉴로 앱을 먼저 실행한다 |
| 확장 service worker 콘솔에 `Specified native messaging host not found.` | HKCU 등록이 없다(`-NoNativeHost`로 설치했거나 다른 스크립트가 지웠다). `install.ps1`을 다시 실행 |
| `Access to the specified native messaging host is forbidden.` | 확장 ID가 다르다. 설치 폴더의 `extension`을 로드했는지, ID가 `nnpjlobjgbanccjddghlpaafpohfkeph`인지 확인 |
| 설치한 앱 대신 다른 창이 앞으로 나온다 | 다른 위치(예: 소스 빌드)의 yw-app이 이미 실행 중이다. 한 번에 하나만 실행된다. 그 앱을 닫고 다시 실행 |
| 네트워크 테스트가 E-RPC-003 또는 E-RPC-007 | QuickNode 멀티체인이면 대시보드에서 그 체인을 엔드포인트에 켰는지 확인. 아니면 그 네트워크 URL(토큰)을 다시 만들거나 **교체** |
| Bitcoin 잔액이 안 보이고 E-BTC-001·E-BTC-002가 계속 | mempool.space에 연결되지 않는다. 설정 → Bitcoin → Esplora URL을 `https://blockstream.info/api`(testnet4: `https://blockstream.info/testnet4/api`)로 바꾸고 테스트 |
| "settings.json은 더 새로운 버전…읽기 전용" 배너 | 더 새로운 버전으로 쓴 데이터를 이전 버전으로 열었다. 설정 변경이 저장되지 않으니 새 버전을 다시 설치(5단계) |
| E-APP-009(내부 오류)가 반복 | 앱을 다시 시작. 반복되면 `%LOCALAPPDATA%\YourWallet\v3\logs\yw-app.log`의 오류 코드 줄을 확인(7단계 주의대로 비밀은 빼고 알린다) |
| 잠금 해제에서 E-VLT-001 | 대부분 입력 실수다. Caps Lock·한/영 상태를 확인하고 다시 입력. 맞는 비밀번호로도 계속 실패하면 [복구 안내](recovery-guide.ko.md) |

## 10. 소스 빌드에서 옮겨 오는 경우

`scripts\register-native-host.ps1`로 등록해 쓰던 PC라면:

- `install.ps1`이 HKCU 등록을 설치 폴더의 manifest로 바꾼다(이전 값을 출력한다). 지갑 데이터는 같은 폴더를 쓰므로 그대로다.
- `%LOCALAPPDATA%\YourWallet\bin\`의 이전 실행 파일은 앱·Chrome을 닫은 뒤 직접 지워도 된다.
  `scripts\unregister-native-host.ps1`은 어느 설치를 가리키든 등록을 지우므로, 실행했다면 `install.ps1`을 다시 실행한다.
- 저장소의 `extension\`으로 로드한 확장 카드는 삭제하고 설치 폴더의 `extension`을 로드한다.

## 11. 배포 zip 만들기 (개발자)

저장소 루트에서:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\package.ps1                  # check.ps1 -Offline 게이트 포함
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\package.ps1 -SkipCheck       # 개발 중 반복(배포 금지)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\package.ps1 -IncludeTestDapp # extension\test-dapp 포함
```

결과는 `dist\YourWallet-<버전>-win-x64.zip`과 `.sha256`이다. 마지막 줄의 SHA-256을 zip과 다른 경로로 알린다.
규칙은 [spec/01](../spec/01-repo-build.md) §9, 수동 확인 목록은 [spec/09](../spec/09-testing.md) §5.12.
