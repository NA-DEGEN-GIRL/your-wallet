# Your Wallet

Windows 11 PC 한 대에서 작성자 본인이 쓰는 개인용 소프트웨어 지갑이다. 지갑 본체(`yw-app`)가
키·vault·승인 창·RPC를 모두 갖고, Chrome 확장(npm 의존성 0)은 비밀 없이 요청만 중계한다.
키를 다루는 코드와 의존성을 혼자 검토할 수 있는 규모로 유지하고, 승인 창은 코어가 실제 서명
대상을 해석한 내용과 시뮬레이션 결과를 보여준다. EVM은 dApp 연결까지, Solana·Bitcoin은
지갑 앱에서 보내기·받기만 한다. 24단어 BIP39 니모닉 하나로 표준 지갑에서 복구할 수 있다.

## 상태

- 현재 마일스톤: **M1 키·vault** 완료(yw-core: 엔트로피, BIP39, BIP32, base58, vault v3; yw-json 파서). 다음은 M2(EVM 코어).
- 실제 자산을 넣지 않는다. 메인넷 사용은 M9 체크리스트 이후 소액만.
- 마일스톤과 완료 조건: [spec.md](spec.md) §5, 판정 기준: [spec/09-testing.md](spec/09-testing.md).

## 빌드 전제 ([spec/01](spec/01-repo-build.md) §3.8)

- Windows 11 x64 22H2 이상
- rustup + `rust-toolchain.toml`(Rust 1.95.0, clippy·rustfmt)
- Visual Studio Build Tools "C++를 사용한 데스크톱 개발"(MSVC + Windows SDK; secp256k1-sys 빌드·링크)
- Node.js 22 이상(npm 패키지 설치 없음), Git 2.x, Windows PowerShell 5.1 또는 PowerShell 7
- Chrome 120 이상(M5부터)

## 빌드와 검사

```powershell
cargo build --release --locked        # target\release\yw-app.exe, target\release\yw-host.exe
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1            # 저장소 게이트
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Offline   # 첫 빌드 이후
```

`scripts/check.ps1`은 fmt, 의존성 허용 목록, clippy, test, build, 확장·스크립트 테스트,
privacy scan, 확장 정적 감사를 차례로 실행하고 첫 실패에서 멈춘다(종료 코드는 spec/01 §4.1).
`Cargo.lock`은 커밋하며 `cargo update`·`cargo generate-lockfile`을 쓰지 않는다(spec/01 §3.6).

## 문서

| 문서 | 내용 |
|---|---|
| [spec.md](spec.md) | 목표, 위협 모델, 결정 사항, 아키텍처, 마일스톤 |
| [spec/](spec/) | 01 저장소·빌드, 02 키·vault, 03 EVM, 04 앱 UI, 05 브라우저, 06 LLM 설명, 07 Solana, 08 Bitcoin, 09 테스트 |
| [docs/recovery-guide.ko.md](docs/recovery-guide.ko.md) | 백업·복구 안내 |
| [docs/acceptance/](docs/acceptance/) | 체크리스트·라이브 확인 기록 |

## 보안 범위

방어 대상과 비목표는 [spec.md](spec.md) §2가 정한다. 같은 Windows 사용자 권한의 악성코드나
관리자·커널 장악은 범위 밖이다(PC가 장악되면 지갑도 장악된 것으로 본다).

## 이전 코드

v2.4 명세와 Windows 격리 설계·구현은 태그 `archive/spec-v2.4`(브랜치 `archive/windows-isolation`)에만
있다. 이식은 `git show archive/spec-v2.4:<path>`로 필요한 줄만 옮긴다(spec/01 §1.5·§6).
