# 설치·업데이트·제거 안내

Your Wallet은 미리 빌드한 실행 파일을 배포하지 않는다(spec.md D1). 소스를 받아 자기 PC에서 빌드해 설치한다.
저장소 루트의 `install.cmd` 하나가 빌드 도구 확인 → 빌드 → 현재 사용자 설치까지 한다. 관리자 권한이 필요 없고,
지갑 데이터 `%LOCALAPPDATA%\YourWallet\`은 설치·업데이트·제거 때 건드리지 않는다.

## 1. 준비

- Windows 11 x64(22H2 이상), Chrome 120 이상, 인터넷(처음 빌드할 때 Rust 툴체인과 의존성을 내려받는다).
- 소스: `git clone <저장소 주소>`, 또는 GitHub의 **Code → Download ZIP** → 압축 풀기. ZIP이면 풀기 전에 zip 파일
  우클릭 → 속성 → **차단 해제**를 체크해 두면 `install.cmd`를 열 때 경고 창이 뜨지 않는다(뜨면 "추가 정보 → 실행").
- 빌드 도구: rustup(Rust 1.95.0은 `rust-toolchain.toml`대로 빌드할 때 자동으로 받는다)과 Visual Studio 2022
  Build Tools의 "C++를 사용한 데스크톱 개발". 없으면 `install.cmd`가 무엇이 없는지 보여 주고 다음 명령을 지금
  실행할지 묻는다(`Y`일 때만 실행). Build Tools는 수 GB이고 관리자 권한 확인 창이 뜬다. Node.js는 필요 없다.

  ```
  winget install --id Rustlang.Rustup -e
  winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"
  ```

## 2. 설치

저장소 폴더의 **`install.cmd`** 를 더블클릭한다. 끝나면 창이 기다리므로 결과를 읽고 아무 키나 누른다.

1. 확장 파일과 확장 ID(`nnpjlobjgbanccjddghlpaafpohfkeph`)를 확인한다.
2. 빌드 도구를 확인한다(없으면 위 winget 명령을 제안).
3. `cargo build --release --locked -p yw-app -p yw-host`. cargo 출력이 그대로 보인다. 의존성은 `Cargo.lock`의
   체크섬으로 고정된다. 처음에는 몇 분 걸린다.
4. `%LOCALAPPDATA%\Programs\YourWallet\`에 `yw-app.exe`, `yw-host.exe`, `uninstall.ps1`, `extension\`(확장 실행에 필요한
   파일만)을 복사한다. 이전 설치가 있으면 업그레이드라고 알리고 바뀐 파일만 바꾼다. 실행 중인 yw-app·yw-host가 그
   파일을 쓰고 있으면 닫아 달라고 묻는다(강제 종료하지 않는다. `C` = 지갑 앱에 정상 종료 요청, `Q` = 취소).
5. Chrome native host manifest(`com.your_wallet.native.json`)를 쓰고 검증한 뒤
   `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.your_wallet.native`에 등록한다.
6. 시작 메뉴에 `Your Wallet` 바로가기를 만들고 설치 기록(`yw-install.json`)을 쓴다.
7. 확장 폴더 경로를 클립보드에 복사하고 다음 할 일을 출력한다.

Chrome은 설치 폴더의 확장 사본을 쓰므로 `git pull`만으로는 로드된 확장이 바뀌지 않는다(다시 설치해야 바뀐다).
여러 번 실행해도 결과가 같다.

| 옵션 (`install.cmd <옵션>`) | 뜻 |
|---|---|
| `-DryRun` | 확인과 할 일 출력만 한다(빌드·복사·등록·winget 없음) |
| `-InstallDir <폴더>` | 설치 폴더(기본 `%LOCALAPPDATA%\Programs\YourWallet`). 비어 있거나 이전 설치 폴더여야 한다 |
| `-NoBuild` | 빌드하지 않고 이미 있는 `target\release`의 exe를 설치한다 |
| `-NoShortcut` | 시작 메뉴 바로가기를 만들지 않는다 |
| `-NoNativeHost` | HKCU 등록을 하지 않는다(그러면 확장이 앱에 연결되지 않는다) |

종료 코드: 0 성공, 1 환경·경로 오류, 2 소스·빌드 결과 오류(확장 ID 불일치 등), 3 취소(비대화형이라 물을 수 없음 포함),
4 파일 복사 실패, 5 native host manifest·등록 실패, 6 바로가기 실패, 7 빌드 도구 없음, 8 빌드 실패, 9 예상하지 못한 오류.
사용자 이름에 `&`·`%`·`!` 같은 문자가 있으면 기본 경로를 쓸 수 없다(Chrome이 `cmd.exe`로 host를 실행할 수 있어서다).
`install.cmd -InstallDir C:\YourWallet`처럼 단순한 경로를 준다.

## 3. Chrome 확장 로드 (처음 한 번)

Chrome → `chrome://extensions` → 오른쪽 위 **개발자 모드** 켜기 → **압축해제된 확장 프로그램을 로드합니다** →
`%LOCALAPPDATA%\Programs\YourWallet\extension` 선택(설치 직후 클립보드에 있으므로 폴더 선택 창 주소창에 Ctrl+V).
카드에 표시된 ID가 `nnpjlobjgbanccjddghlpaafpohfkeph`인지 확인한다. 다르면 그 카드를 삭제한다(yw-host가 연결을 거부한다).
툴바의 퍼즐 아이콘 → Your Wallet 핀을 누르면 호환 모드 팝업을 바로 열 수 있다. Chrome을 켤 때 뜨는 "개발자 모드
확장 프로그램" 경고는 정상이다(웹 스토어 배포를 하지 않는다).

## 4. 첫 실행

1. 시작 메뉴 → **Your Wallet**. 자기 PC에서 빌드한 프로그램이라 SmartScreen 창은 보통 뜨지 않는다. Windows 보안의
   **스마트 앱 컨트롤**이 "켜기"이면 서명되지 않은 프로그램 실행이 막힐 수 있다(이 문서는 설정 변경을 권하지 않는다).
2. 새 지갑 만들기 → 24개 복구 단어를 종이에 적고 백업 확인을 마친다([복구 안내](recovery-guide.ko.md)).
3. RPC 설정(QuickNode 멀티체인 템플릿):
   1. QuickNode 대시보드의 엔드포인트 주소(HTTP Provider)는 `https://<이름>.quiknode.pro/<토큰>/` 또는
      `https://<이름>.<체인>.quiknode.pro/<토큰>/` 모양이다. `<이름>`은 첫 `.` 앞, `<토큰>`은 `.quiknode.pro/` 바로 뒤의
      경로 한 조각이다. 쓸 체인(Ethereum, Sepolia, HyperEVM, Solana, Bitcoin mainnet·testnet4)을 엔드포인트에서 **각각
      켜야** 한다(켜지 않은 체인은 테스트가 E-RPC-003 또는 E-RPC-007).
   2. 앱의 **설정** → **네트워크(RPC)** → RPC 공급자 **QuickNode 멀티체인** → **엔드포인트 이름**과 **토큰** → **저장**
      (Windows DPAPI로 암호화되어 다시 보이지 않는다). E-KEY-002면 이름 칸에 주소 전체·대문자·`_`가, 토큰 칸에 `/`가
      들어가지 않았는지 확인한다.
   3. **네트워크 URL 생성** → **생성** → 아래 **네트워크별 RPC 주소**에서 네트워크마다 **테스트**. 실패하는 네트워크는
      대시보드에서 그 체인을 켜거나 **교체**로 `https://` 주소를 직접 넣는다.

   RPC 주소 전체(이름·토큰 포함)가 비밀이다. 스크린샷·메신저·이슈에 붙이지 않는다. Bitcoin 조회는 기본으로 키가 필요
   없는 Esplora(mempool.space)를 쓴다. 연결되지 않으면(E-BTC-001·E-BTC-002가 계속) 설정 → Bitcoin → **Esplora URL**을
   `https://blockstream.info/api`(testnet4는 `https://blockstream.info/testnet4/api`)로 바꾸고 **저장** → **테스트**.
4. dApp 연결: 확장이 로드된 Chrome에서 dApp의 지갑 연결을 누르면 yw-app 승인 창이 뜬다. 앱이 꺼져 있으면 yw-host가
   자동으로 실행한다(설정 → 브라우저·진단·정보 → "dApp 요청 시 앱 자동 실행", 기본 켜짐).

## 5. 업데이트

1. (권장) 앱을 닫고(진행 중인 거래가 없을 때) `%LOCALAPPDATA%\YourWallet\v3` 폴더를 복사해 둔다. 새 버전에 문제가
   있어 되돌릴 때 쓴다. 보관 주의는 8과 같다. 아래 위치는 `uninstall.cmd -RemoveWalletData`가 함께 지운다.

   ```powershell
   Copy-Item -Recurse "$env:LOCALAPPDATA\YourWallet\v3" "$env:LOCALAPPDATA\YourWallet\v3-backup-$(Get-Date -Format yyyyMMdd)"
   ```
2. 저장소 폴더에서 `git pull`(ZIP으로 받았다면 새 ZIP을 새 폴더에 푼다).
3. `install.cmd` 실행. "기존 설치를 찾았습니다 … 업그레이드합니다"가 나오고 바뀐 파일만 바꾼다.
4. `chrome://extensions`의 Your Wallet 확장 카드에서 **새로고침**을 누르고, 열려 있던 dApp 탭도 새로고침한다.

지갑 데이터는 그대로 남아 새 버전이 이어서 쓴다(버전 사이 파일 호환은 spec/04 §6.6: 이전 버전은 새 항목을 지우지 않고,
더 새로운 형식의 `settings.json`은 읽기 전용으로 연다). 되돌리기: 앱을 닫고 이전 커밋으로(`git checkout <커밋>`)
`install.cmd`를 실행한다. 데이터까지 되돌리려면 `v3` 폴더를 1의 사본으로 통째로 바꾼다(사본 이후의 라벨·주소록·활동
변경은 사라지고, 자산은 체인에 있으므로 영향이 없다).

## 6. 제거

저장소의 **`uninstall.cmd`** 를 실행한다(`uninstall.cmd -DryRun` = 지울 것만 보기). 저장소를 지웠다면 설치 폴더의 사본:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:LOCALAPPDATA\Programs\YourWallet\uninstall.ps1"
```

- 지우는 것: 시작 메뉴 바로가기(이 설치를 가리킬 때만), HKCU native host 등록(이 설치의 manifest를 가리킬 때만),
  설치 폴더에서 설치 기록(`yw-install.json`)에 적힌 파일과 manifest. 기록에 없는 파일은 남긴다.
  `-InstallDir`로 다른 곳에 설치했다면 `uninstall.cmd -InstallDir <폴더>`.
- **지우지 않는 것: 지갑 데이터 `%LOCALAPPDATA%\YourWallet\`**(위치를 마지막에 출력한다). 다시 설치하면 그대로 쓴다.
- Chrome 확장 카드는 `chrome://extensions`에서 직접 **삭제**한다.
- 지갑 데이터까지 지우려면 `uninstall.cmd -RemoveWalletData` 후 창에 `DELETE MY WALLET`을 정확히 입력한다. 그 밖의
  입력이나 비대화형 실행은 아무것도 지우지 않는다. **지우기 전에 종이에 적은 24개 복구 단어(passphrase를 썼다면 그것도)를
  다시 확인한다. 그것이 지갑의 유일한 백업이다.**

종료 코드: 0 성공(`-DryRun`, 이미 제거된 경우 포함), 1 환경 오류 또는 설치 기록 없는 폴더(프로그램 파일을 지우지 않음),
3 취소·확인 문구 불일치·비대화형, 4 일부 항목을 지우지 못함(yw-app·Chrome을 닫고 다시 실행), 9 예상하지 못한 오류.

## 7. 파일 위치

| 위치 | 내용 |
|---|---|
| `%LOCALAPPDATA%\Programs\YourWallet\` | `yw-app.exe`, `yw-host.exe`, `extension\`, `uninstall.ps1`, `com.your_wallet.native.json`(native host manifest), `yw-install.json`(설치 기록: 버전·커밋·파일 목록) |
| `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.your_wallet.native` | 기본값 = 위 manifest 경로 |
| `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Your Wallet.lnk` | 시작 메뉴 바로가기 |
| `%LOCALAPPDATA%\YourWallet\v3\vault.ywv` (+`.prev`) | vault(복구 단어·키, vault 비밀번호로 암호화) |
| `%LOCALAPPDATA%\YourWallet\v3\meta.ywm` (+`.prev`) | 계정·주소록·연결된 사이트·토큰·활동(암호화) |
| `%LOCALAPPDATA%\YourWallet\v3\journal.ywj` (+`.prev`) | 진행 중 거래 저널(암호화) |
| `%LOCALAPPDATA%\YourWallet\v3\settings.json` | 비밀이 아닌 설정(평문) |
| `%LOCALAPPDATA%\YourWallet\v3\apikeys.dpapi` | RPC 주소·템플릿 자격 정보·LLM 키(Windows DPAPI, 이 PC의 이 사용자만 풀 수 있음) |
| `%LOCALAPPDATA%\YourWallet\v3\logs\yw-app.log` (+`.1`–`.4`) | 로그(1 MiB씩 5개 순환, 비밀·RPC 주소·dApp origin 없음) |

yw-host는 로그 파일을 쓰지 않는다. 문제를 알릴 때는 `logs\yw-app.log`의 오류 코드 줄만 보내고, 복구 단어·비밀번호·
RPC 주소는 절대 함께 보내지 않는다.

## 8. 백업

1. **복구 단어 24개(와 쓴 경우 BIP39 passphrase)가 유일한 백업이다.** 종이(또는 금속)에 적어 PC와 다른 곳에 둔다.
   사진·클라우드·메신저·암호 관리자에 저장하지 않는다([복구 안내](recovery-guide.ko.md)).
2. (선택) 라벨·주소록·연결된 사이트까지 보존하려면 앱을 닫은 뒤 `%LOCALAPPDATA%\YourWallet\v3` 폴더 전체를 오프라인
   저장 장치에 복사한다. vault·meta·journal은 암호화되어 있지만 사본을 가진 사람은 비밀번호를 무차별 대입해 볼 수
   있으므로 복구 단어와 같은 수준으로 보관한다. `apikeys.dpapi`는 이 PC의 이 사용자만 풀 수 있다(다른 PC면 RPC 주소를
   다시 넣는다). 되돌릴 때는 앱을 닫고 `v3` 폴더를 통째로 바꾼다.

## 9. 문제 해결

| 증상 | 원인·조치 |
|---|---|
| 종료 코드 7(빌드 도구 없음) | 출력된 winget 명령으로 설치하거나 다시 실행해 `Y`. Build Tools를 설치한 직후면 새 창에서 다시 실행(필요하면 재시작) |
| 종료 코드 8(빌드 실패) | cargo 출력의 첫 `error` 줄을 본다. `link.exe`·`kernel32.lib`이면 Visual Studio Installer → 수정 → "C++를 사용한 데스크톱 개발"·Windows SDK, 내려받기 오류면 인터넷 연결 |
| 종료 코드 3 | 지갑 앱이나 Chrome이 파일을 쓰고 있다. 앱 창을 닫고(안 보이면 시작 메뉴로 열어서 닫기) Chrome 창을 모두 닫은 뒤 다시 실행 |
| dApp이 "Wallet is unavailable."(4900) | 앱이 꺼져 있고 자동 실행이 꺼져 있거나 실행에 실패했다. 시작 메뉴로 앱을 먼저 실행한다 |
| 확장 service worker 콘솔에 `Specified native messaging host not found.` | HKCU 등록이 없다(`-NoNativeHost`로 설치했거나 다른 스크립트가 지웠다). `install.cmd`를 다시 실행 |
| `Access to the specified native messaging host is forbidden.` | 확장 ID가 다르다. 설치 폴더의 `extension`을 로드했는지, ID가 `nnpjlobjgbanccjddghlpaafpohfkeph`인지 확인 |
| 설치한 앱 대신 다른 창이 앞으로 나온다 | 다른 위치(예: `target\release`)의 yw-app이 이미 실행 중이다. 한 번에 하나만 실행된다. 그 앱을 닫고 다시 실행 |
| 네트워크 테스트가 E-RPC-003 또는 E-RPC-007 | QuickNode 멀티체인이면 대시보드에서 그 체인을 켰는지 확인. 아니면 그 네트워크 URL을 다시 만들거나 **교체** |
| "settings.json은 더 새로운 버전…읽기 전용" 배너 | 더 새로운 버전으로 쓴 데이터를 이전 버전으로 열었다. 새 버전을 다시 설치(5) |
| E-APP-009(내부 오류)가 반복 | 앱을 다시 시작. 반복되면 `logs\yw-app.log`의 오류 코드 줄을 확인(7의 주의대로 비밀은 빼고 알린다) |
| 잠금 해제에서 E-VLT-001 | 대부분 입력 실수다. Caps Lock·한/영 상태를 확인. 맞는 비밀번호로도 계속 실패하면 [복구 안내](recovery-guide.ko.md) |

## 10. 이전 설치에서 옮기기

- 예전 배포 zip의 `install.ps1`로 설치한 PC: `install.cmd`가 같은 설치 폴더를 업그레이드로 인식하고, zip에만 있던
  파일(`README-설치.txt`)을 지운다.
- 예전 `scripts\register-native-host.ps1`(삭제됨)로 등록한 PC: `install.cmd`가 HKCU 등록을 설치 폴더의 manifest로 바꾸고
  이전 값을 출력한다. 그 스크립트가 쓰던 `%LOCALAPPDATA%\YourWallet\bin\`은 지갑 데이터 폴더 안이라 스크립트가 건드리지
  않으므로, 앱·Chrome을 닫은 뒤 그 `bin` 폴더만 직접 지운다(`v3` 폴더는 지우지 않는다).
- 저장소의 `extension\`으로 로드한 확장 카드는 삭제하고 설치 폴더의 `extension`을 로드한다(그래야 `git pull`이 로드된
  확장을 바꾸지 않는다). ID가 같아 앱의 연결된 사이트는 그대로이고, 확장 팝업의 호환 모드만 다시 고른다.
