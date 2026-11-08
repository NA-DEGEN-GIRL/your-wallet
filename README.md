# Your Wallet

Windows 11 PC 한 대에서 작성자 본인이 쓰는 개인용 소프트웨어 지갑이다. 지갑 본체(`yw-app`)가
키·vault·승인 창·RPC를 모두 갖고, Chrome 확장(npm 의존성 0)은 비밀 없이 요청만 중계한다.
키를 다루는 코드와 의존성을 혼자 검토할 수 있는 규모로 유지하고, 승인 창은 코어가 실제 서명
대상을 해석한 내용과 시뮬레이션 결과를 보여준다. EVM은 dApp 연결까지, Solana·Bitcoin은
지갑 앱에서 보내기·받기만 한다. 24단어 BIP39 니모닉 하나로 표준 지갑에서 복구할 수 있다.

## 상태

- **구현 완료 · 수동 검증 대기.** M0–M8 전 마일스톤을 구현했다: 키·vault(M1), EVM 코어(M2), 앱 뼈대(M3),
  EVM 송금·사용자 체인(M4), 브라우저 연동과 MetaMask·Rabby 호환 모드(M5), 선택 기능 LLM 설명(M6),
  Solana 송금과 v1.1 SPL 허용 목록(M7), Bitcoin 송금(M8). 이후 Bitcoin 계정별 주소 형식 4종(P2WPKH·P2TR·
  P2SH-P2WPKH·P2PKH)과 개인키 가져오기(EVM·Solana·Bitcoin WIF — 가져온 Bitcoin 키도 계정 목록에서 받기·보내기,
  복구 단어 없이 개인키로 시작하는 지갑)를 더했다. 자동 검사(`scripts/check.ps1`)는 통과하며,
  마일스톤별 수동 체크리스트와 라이브 확인은 [docs/acceptance/](docs/acceptance/)에서 진행 중이다
  (아직 남은 예: Chrome job object에서 yw-app 생존 확인 M5-13, 메인넷 소액 M9).
- 미리 빌드한 실행 파일은 배포하지 않는다. 저장소는 소스로만 공개하고, 각자 자기 PC에서 빌드해 설치한다
  (아래 "설치", spec.md D1·§2.2).
- 실제 자산을 넣지 않는다. 메인넷 사용은 M9 체크리스트 이후 소액만.
- 마일스톤과 완료 조건: [spec.md](spec.md) §5, 판정 기준: [spec/09-testing.md](spec/09-testing.md).

## 설치

준비: Windows 11 x64, Chrome. 소스는 `git clone` 또는 GitHub의 **Code → Download ZIP**(압축 풀기)으로 받는다.
Rust(rustup)나 Visual Studio C++ 빌드 도구가 없으면 설치 스크립트가 무엇이 없는지 보여 주고, 동의하면 winget으로 설치한다.

1. 저장소 폴더의 **`install.cmd`** 를 더블클릭한다. 소스를 빌드하고(처음에는 몇 분) 현재 사용자에게
   `%LOCALAPPDATA%\Programs\YourWallet`으로 설치한다(관리자 권한 불필요).
2. Chrome → `chrome://extensions` → 개발자 모드 → 압축해제된 확장 프로그램 로드 →
   `%LOCALAPPDATA%\Programs\YourWallet\extension`(설치가 끝나면 이 경로가 클립보드에 있다). 앱의 설정 →
   브라우저·정보 → `Chrome 확장 설치 방법·폴더`에도 같은 안내와 `폴더 열기`·`경로 복사`가 있다.
3. 시작 메뉴 → **Your Wallet** → 지갑 만들기(24단어 종이 백업) → 설정 → 네트워크(RPC)
   ([docs/install.ko.md](docs/install.ko.md) "첫 실행").

업데이트는 `git pull` 후 `install.cmd`를 다시 실행하고 확장 카드에서 새로고침한다. 제거는 `uninstall.cmd`
(지갑 데이터 `%LOCALAPPDATA%\YourWallet`은 남긴다). 옵션·백업·문제 해결: [docs/install.ko.md](docs/install.ko.md).

## 개발

빌드 전제([spec/01](spec/01-repo-build.md) §3.8): Windows 11 x64 22H2 이상, rustup + `rust-toolchain.toml`(Rust 1.95.0,
clippy·rustfmt), Visual Studio Build Tools "C++를 사용한 데스크톱 개발"(MSVC + Windows SDK; secp256k1-sys 빌드·링크),
Node.js 22 이상(검사·확장 테스트용, npm 패키지 설치 없음, 설치에는 필요 없음), Git 2.x,
Windows PowerShell 5.1 또는 PowerShell 7, Chrome 120 이상.

```powershell
cargo build --release --locked        # target\release\yw-app.exe, target\release\yw-host.exe
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1            # 저장소 게이트
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Offline   # 첫 빌드 이후
```

`scripts/check.ps1`은 fmt, 의존성 허용 목록, clippy, test, build, 확장·스크립트 테스트,
privacy scan, 확장 정적 감사를 차례로 실행하고 첫 실패에서 멈춘다(종료 코드는 spec/01 §4.1).
`Cargo.lock`은 커밋하며 `cargo update`·`cargo generate-lockfile`을 쓰지 않는다(spec/01 §3.6).
native host 등록은 `install.cmd`가 한다(spec/05 §9). 확장 소스를 고치며 시험할 때는 저장소의 `extension\`을
압축해제 로드해도 된다(manifest `key`가 같아 ID `nnpjlobjgbanccjddghlpaafpohfkeph`도 같다).

## 문서

| 문서 | 내용 |
|---|---|
| [spec.md](spec.md) | 목표, 위협 모델, 결정 사항, 아키텍처, 마일스톤 |
| [spec/](spec/) | 01 저장소·빌드, 02 키·vault, 03 EVM, 04 앱 UI, 05 브라우저, 06 LLM 설명, 07 Solana, 08 Bitcoin, 09 테스트 |
| [docs/install.ko.md](docs/install.ko.md) | 설치·업데이트·제거, 첫 실행(RPC), 파일 위치, 문제 해결 |
| [docs/recovery-guide.ko.md](docs/recovery-guide.ko.md) | 백업·복구 안내 |
| [docs/acceptance/](docs/acceptance/) | 체크리스트·라이브 확인 기록 |
| [docs/screenshots/](docs/screenshots/) | 화면 투어(주요 화면·승인 창·확장 팝업, 시험용 값) |
| [docs/ux-review-20261107.md](docs/ux-review-20261107.md) | 최근 UI/UX 검토(고친 것·남긴 것; 이전 [10-31](docs/ux-review-20261031.md)) |
| [docs/security-review-20261101.md](docs/security-review-20261101.md) | 보안 검토(발견·권고 순서·스펙 편차) |
| [docs/android-feasibility-20261107.md](docs/android-feasibility-20261107.md) | Android 이식 타당성 검토(같은 보안 수준의 조건·맞출 수 없는 것·단계 계획, 코드 변경 없음) |

## 보안 범위

방어 대상과 비목표는 [spec.md](spec.md) §2가 정한다. 같은 Windows 사용자 권한의 악성코드나
관리자·커널 장악은 범위 밖이다(PC가 장악되면 지갑도 장악된 것으로 본다).

## 이전 코드

v2.4 명세와 Windows 격리 설계·구현은 태그 `archive/spec-v2.4`(브랜치 `archive/windows-isolation`)에만
있다. 이식은 `git show archive/spec-v2.4:<path>`로 필요한 줄만 옮긴다(spec/01 §1.5·§6).
