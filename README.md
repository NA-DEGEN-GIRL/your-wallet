# Your Wallet

**[English](#english)**

Windows 11 PC 한 대에서 쓰는 개인용 소프트웨어 지갑이다. 소스로만 공개한다. 지갑 앱(`yw-app`)이 키, 암호화된 vault,
승인 창, 모든 네트워크 접근을 맡는다. Chrome 확장(npm 의존성 0)은 dApp 요청만 중계하고 비밀은 전혀 보지 않는다.
코드와 의존성은 한 사람이 검토할 수 있는 규모로 유지하고, 승인 창은 서명할 바이트를 코어가 직접 해석한 내용과
시뮬레이션 결과를 보여준다.

> **상태:** 기능 구현 완료, 자동 검사(`scripts/check.ps1`) 전부 통과. 실제 네트워크 사용은 이제 시작 단계라
> 처음에는 소액으로 쓴다. 미리 빌드한 실행 파일은 배포하지 않으며, 각자 자기 PC에서 빌드해 설치한다.

## 기능

**체인**
- **EVM** — Ethereum, Arbitrum One, Base, BNB Smart Chain, Robinhood Chain, HyperEVM, Sepolia와 직접 추가한
  EVM 체인(처음 쓸 때 genesis 해시 고정). 네이티브 코인과 ERC-20 토큰(기본 목록 + 직접 추가, 숨기기/다시 보이기),
  체인별 수수료 상한(Base L1 데이터 수수료 포함).
- **Solana** — SOL과 허용 목록의 USDC/USDT.
- **Bitcoin** — 네이티브 세그윗(`bc1q`, 기본), 탭루트(`bc1p`), 호환 세그윗(`3…`), 레거시(`1…`) 계정.
  기본은 계정마다 고정 주소 하나(UniSat·Xverse 방식), 원하면 받을 때마다 새 주소(HD).
- **Zcash** — 일반(transparent) 주소만. t-주소, TEX, 통합 주소(UA)의 일반 수신자로 보낼 수 있다.
- **HyperCore**(Hyperliquid) — 잔액, 전송, 현물↔선물 이동, Arbitrum 출금, HyperEVM↔HyperCore 이동. 트레이딩은 없다.

**키**
- OS 난수로 24단어 BIP39 생성과 백업 확인 퀴즈, 12–24단어 가져오기(passphrase 선택).
- 한 지갑에 복구 단어 최대 8개, 단어마다 백업 확인을 따로 하고 모든 체인 계정을 만들 수 있다.
- 개인키 가져오기(EVM hex, Solana base58/JSON, Bitcoin WIF, Zcash WIF)와 개인키로만 시작하는 지갑.
- **YubiKey 5**(펌웨어 5.7+): 키가 카드 안에 있고 카드에서 서명한다 — EVM·Bitcoin·Zcash는 OpenPGP secp256k1
  (카드당 2자리), Solana는 PIV Ed25519. 복구 단어에서 키를 넣어 여러 카드에 백업하거나, 복구 단어 없이 카드를
  연결할 수 있다. PIN 설정, 슬롯 구성 바꾸기, 비우기를 앱에서 한다.
- vault: Argon2id(256 MiB) 키 감싸기 + XChaCha20-Poly1305. 데이터 폴더는 내 Windows 계정만 접근하게 잠근다.

**서명 안전장치**
- 승인 창은 코어가 직접 해석한 내용만 보여준다(사이트가 준 문구를 믿지 않음). 시뮬레이션(`eth_simulateV1`,
  실패해도 막지 않음), 위험 규칙(승인·permit·드레이너·비슷한 주소·SIWE/SIWS/SIWB 도메인 검사), digest에 묶인
  1회용 승인, 1초 대기, 고위험은 2초 누르기.
- 비밀 창은 화면 캡처에서 빠지고, 비밀 복사는 기본 꺼짐, 복사하면 자동으로 지운다.
- 선택 기능: AI가 요청을 설명(내 API 키 사용, 판단은 하지 않음).

**dApp**
- Chrome 확장: EVM은 EIP-1193/EIP-6963, 필요하면 MetaMask·Rabby처럼 보이는 호환 모드. Solana는 Wallet Standard·
  Phantom 모드, Bitcoin은 UniSat·Xverse 모드. Solana·Bitcoin dApp은 연결과 **메시지 서명(소유 증명)만** 된다.
- WalletConnect v2(EVM): `wc:` 링크를 붙여넣거나 스크린샷의 QR을 읽어 연결한다. 사이트 주소는 사이트가 주장한
  값이라 Verify로 확인되기 전에는 그렇게 표시한다.

**일상 기능**
- 모든 EVM 체인이 같이 쓰는 주소록과 즐겨찾기, 비슷한 주소(주소 오염) 경고, 토큰 보내기 링크, 체인별 활동,
  지갑 초기화(파일을 지우지 않고 옆으로 옮김), QuickNode/Alchemy 템플릿 RPC 설정.

## 설치

준비: Windows 11 x64, Chrome. 소스는 `git clone` 또는 GitHub **Code → Download ZIP**으로 받는다.

1. 저장소 폴더의 **`install.cmd`** 를 더블클릭한다. 소스를 빌드하고(처음에는 몇 분) 현재 사용자에게
   `%LOCALAPPDATA%\Programs\YourWallet`로 설치한다(관리자 권한 불필요). Rust나 Visual Studio C++ 빌드 도구가 없으면
   무엇이 없는지 보여 주고, 동의할 때만 winget으로 설치한다.
2. Chrome `chrome://extensions` → 개발자 모드 → **압축해제된 확장 프로그램 로드** →
   `%LOCALAPPDATA%\Programs\YourWallet\extension` 선택(설치가 끝나면 경로가 클립보드에 있다. 앱의 설정 → 브라우저
   화면에도 같은 안내가 있다).
3. 시작 메뉴에서 **Your Wallet**을 열고 지갑을 만들거나 가져온 뒤, 완료 화면에서 RPC를 연결한다.

업데이트는 `git pull` 후 `install.cmd`를 다시 실행하고 확장 카드에서 새로고침한다. 제거는 `uninstall.cmd`
(지갑 데이터 `%LOCALAPPDATA%\YourWallet`은 남긴다). 설치 스크립트가 저장소 폴더에 *Low* 무결성 레이블이 있다고
경고하면(일부 샌드박스 도구가 붙인다) 낮은 권한 프로세스가 소스를 바꿀 수 있다는 뜻이다.
`icacls "<저장소 폴더>" /setintegritylevel (OI)(CI)M`으로 지우거나, 알고 계속하려면 확인한다.

실제 자산을 넣기 전에는 짧은 [첫 사용 체크리스트](docs/first-use-checklist.ko.md)를 따른다.
자세한 설치·문제 해결은 [docs/install.ko.md](docs/install.ko.md).

## 개발

전제([spec/01](spec/01-repo-build.md)): Windows 11 x64, rustup과 고정 툴체인(`rust-toolchain.toml`, Rust 1.95.0),
Visual Studio Build Tools(C++ 데스크톱 개발), Node.js 22+(검사용, npm 패키지 없음), Git, PowerShell 5.1 또는 7.

```powershell
cargo build --release --locked
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Offline   # 저장소 게이트
```

게이트는 fmt, 의존성 허용 목록, clippy, 테스트, fuzz-lite, 빌드, 확장·스크립트 테스트, 개인정보 검사, 확장 정적
감사, 아이콘 검사를 차례로 실행한다. `Cargo.lock`은 커밋하며 `cargo update`는 쓰지 않는다. 새 크레이트는 더하지
않는다(`scripts/check-core-deps.mjs`가 허용 목록을 강제).

## 보안 범위

방어 대상과 비목표는 [spec.md](spec.md) §2가 정한다. 요약: 내 Windows 사용자 권한으로 도는 악성코드나 관리자·커널
장악은 범위 밖이다 — PC가 장악되면 지갑도 장악된 것으로 본다(YubiKey를 쓰면 키 자체는 PC 밖에 남는다).
범위 안: 보이는 것과 다른 서명, 악성 사이트와 WalletConnect 상대, 같은 PC의 다른 사용자, 키 분실, 버전 간 데이터
손실. 설정한 RPC 공급자는 신뢰한다.

## 문서

| 문서 | 내용 |
|---|---|
| [spec.md](spec.md) | 목표, 위협 모델, 결정 사항, 아키텍처 |
| [spec/](spec/) | 01 저장소·빌드 · 02 키·vault · 03 EVM · 04 앱 UI · 05 브라우저 · 06 AI 설명 · 07 Solana · 08 Bitcoin · 09 테스트 · 10 YubiKey · 11 HyperCore · 12 Zcash · 13 WalletConnect |
| [docs/install.ko.md](docs/install.ko.md) | 설치·업데이트·제거, 첫 실행, 파일 위치, 문제 해결 |
| [docs/first-use-checklist.ko.md](docs/first-use-checklist.ko.md) | 첫 실제 사용 체크리스트(짧은 버전) |
| [docs/recovery-guide.ko.md](docs/recovery-guide.ko.md) | 백업·복구 안내 |
| [docs/acceptance/](docs/acceptance/) | 자세한 수동 확인 목록 |
| [docs/screenshots/](docs/screenshots/) | 화면 투어(시험용 값) |
| [docs/ux-review-20261109.md](docs/ux-review-20261109.md) | 최근 UI/UX 검토(이전: [11-08](docs/ux-review-20261108.md), [11-07](docs/ux-review-20261107.md), [10-31](docs/ux-review-20261031.md)) |
| [docs/security-review-20261101.md](docs/security-review-20261101.md) | 보안 검토와 처리 결과 |
| [docs/android-feasibility-20261107.md](docs/android-feasibility-20261107.md) | Android 이식 타당성(조사만, 계획 없음) |

---

## English

[↑ 한국어](#your-wallet)

A personal, source-only software wallet for one Windows 11 PC. The wallet app (`yw-app`) holds the keys, the
encrypted vault, the approval windows and all network access. A small Chrome extension with zero npm
dependencies only relays dApp requests and never sees a secret. The code and its dependencies are kept small
enough for one person to review, and every approval window shows what the core actually decoded from the bytes
being signed, together with a simulation of the result.

> **Status:** feature-complete and passing the full automated gate (`scripts/check.ps1`). Real-network use by the
> owner has just started — use small amounts first. No prebuilt binaries are published; you build it yourself.

### Features

**Chains**
- **EVM** — Ethereum, Arbitrum One, Base, BNB Smart Chain, Robinhood Chain, HyperEVM, Sepolia, plus any EVM chain
  you add (genesis hash pinned on first use). Native coins and ERC-20 tokens (built-in registry + your own tokens,
  hide/show), fee caps per chain (Base L1 data fee included).
- **Solana** — SOL and allow-listed USDC/USDT.
- **Bitcoin** — native segwit (`bc1q`, default), taproot (`bc1p`), nested segwit (`3…`) and legacy (`1…`) accounts;
  one fixed address per account by default (UniSat/Xverse style) or a new address per receive (HD).
- **Zcash** — transparent addresses only (send to t-addr, TEX and the transparent receiver of a unified address).
- **HyperCore** (Hyperliquid) — balances, transfers, spot↔perp, withdraw to Arbitrum, HyperEVM↔HyperCore moves.
  No trading.

**Keys**
- 24-word BIP39 generation from the OS RNG with a backup quiz; import 12–24 words with an optional passphrase.
- Up to 8 recovery phrases in one wallet, each with its own backup check; accounts on every chain per phrase.
- Private-key import (EVM hex, Solana base58/JSON, Bitcoin WIF, Zcash WIF) and wallets that start from a key only.
- **YubiKey 5** (firmware 5.7+): keys live on the card and sign there — OpenPGP secp256k1 for EVM/Bitcoin/Zcash
  (2 slots per card), PIV Ed25519 for Solana. Enrol from your recovery words onto one or more cards (backups),
  or connect a card without words. PIN setup, slot switching and clearing are built in.
- Vault: Argon2id (256 MiB) key wrapping + XChaCha20-Poly1305; the data folder is locked to your Windows account.

**Signing safety**
- Approval windows built from the core's own decoding (never from text the site supplies), simulation
  (`eth_simulateV1`, never blocks), risk rules (approvals, permits, drainers, look-alike addresses, SIWE/SIWS/SIWB
  domain checks), digest-bound one-shot approvals, a 1 s arm delay and a 2 s hold for high-risk requests.
- Secret windows are excluded from screen capture; copying secrets is off by default and clipboard copies are
  cleared automatically.
- Optional AI explanation of a request (your own API key; never decides anything).

**dApps**
- Chrome extension: EIP-1193/EIP-6963 for EVM, with optional compatibility modes that look like MetaMask or Rabby;
  Solana Wallet Standard / Phantom mode; UniSat / Xverse modes for Bitcoin. Solana and Bitcoin dApps can connect
  and request **message signatures only** (proof of ownership) — no transaction signing for them.
- WalletConnect v2 (EVM): paste a `wc:` link or read the QR from a screenshot. The site's address is self-claimed
  and shown as such unless Verify confirms it.

**Everyday**
- Address book shared across all EVM chains, favorites, look-alike (address-poisoning) warnings, token send links,
  activity per chain, wallet reset (files are moved aside, never deleted), RPC setup from a QuickNode/Alchemy
  template.

### Install

Requirements: Windows 11 x64 and Chrome. Get the source with `git clone` or GitHub **Code → Download ZIP**.

1. Double-click **`install.cmd`** in the repository folder. It builds from source (a few minutes the first time) and
   installs to `%LOCALAPPDATA%\Programs\YourWallet` for the current user — no administrator rights needed. If Rust
   or the Visual Studio C++ build tools are missing it tells you what is missing and installs them with winget only
   if you agree.
2. In Chrome open `chrome://extensions`, turn on Developer mode, choose **Load unpacked** and select
   `%LOCALAPPDATA%\Programs\YourWallet\extension` (the path is on the clipboard after installing; the app's
   Settings → Browser page has the same guide).
3. Start **Your Wallet** from the Start menu, create or import a wallet, and connect RPC from the finish screen.

Update: `git pull`, run `install.cmd` again, press reload on the extension card. Uninstall: `uninstall.cmd`
(your wallet data in `%LOCALAPPDATA%\YourWallet` is kept). If the installer warns that the repository folder has a
*Low* integrity label (some sandboxing tools add one), low-integrity processes could modify the source; remove it
with `icacls "<repo folder>" /setintegritylevel (OI)(CI)M` or confirm to continue.

Before putting real funds in, follow the short [first-use checklist](docs/first-use-checklist.ko.md) (Korean).

### Development

Prerequisites ([spec/01](spec/01-repo-build.md)): Windows 11 x64, rustup with the pinned toolchain
(`rust-toolchain.toml`, Rust 1.95.0), Visual Studio Build Tools (C++ desktop workload), Node.js 22+ (checks only, no
npm packages), Git, PowerShell 5.1 or 7.

```powershell
cargo build --release --locked
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Offline   # the repository gate
```

The gate runs fmt, the dependency allowlist, clippy, tests, fuzz-lite, build, extension and script tests, a
privacy scan, the extension static audit and the icon check. `Cargo.lock` is committed; never run `cargo update`.
New crates are not added — `scripts/check-core-deps.mjs` enforces the allowlist.

### Security model

What is defended and what is not is defined in [spec.md](spec.md) §2. In short: a PC already controlled by malware
running as your Windows user (or an administrator/kernel compromise) is out of scope — if the PC is compromised,
the wallet is too (a YubiKey still keeps the keys themselves off the PC). In scope: signing something other than
what is shown, malicious sites and WalletConnect peers, other users on the PC, key loss, and data loss across
versions. The configured RPC provider is trusted.

### Documents

| Document | Contents |
|---|---|
| [spec.md](spec.md) | Goals, threat model, decisions, architecture |
| [spec/](spec/) | 01 repo/build · 02 keys/vault · 03 EVM · 04 app UI · 05 browser · 06 AI explanation · 07 Solana · 08 Bitcoin · 09 testing · 10 YubiKey · 11 HyperCore · 12 Zcash · 13 WalletConnect |
| [docs/install.ko.md](docs/install.ko.md) | Install, update, uninstall, first run, file locations, troubleshooting (Korean) |
| [docs/first-use-checklist.ko.md](docs/first-use-checklist.ko.md) | Short first real-use checklist (Korean) |
| [docs/recovery-guide.ko.md](docs/recovery-guide.ko.md) | Backup and recovery (Korean) |
| [docs/acceptance/](docs/acceptance/) | Detailed manual checklists |
| [docs/screenshots/](docs/screenshots/) | Screen tour (test values only) |
| [docs/ux-review-20261109.md](docs/ux-review-20261109.md) | Latest UX review (earlier: [11-08](docs/ux-review-20261108.md), [11-07](docs/ux-review-20261107.md), [10-31](docs/ux-review-20261031.md)) |
| [docs/security-review-20261101.md](docs/security-review-20261101.md) | External-style security review and its resolution |
| [docs/android-feasibility-20261107.md](docs/android-feasibility-20261107.md) | Android port feasibility (research only; not planned) |
