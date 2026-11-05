# 저장소·빌드·의존성

상위 문서: [spec.md](../spec.md)

이 문서는 D1·D4·D5·D6·D8·D10·D13·D14·D21·D24·D28을 저장소 구조, Cargo 설정, 검사 스크립트, 코딩 규칙, 이식 목록, yw-win API로 구체화한다. 아래 수치(크레이트 수, lock 항목 수, 스크립트 동작)는 2026-10-26에 Rust 1.95.0·Node 22.23.2로 같은 매니페스트를 임시 워크스페이스에서 실행해 확인한 값이다.

---

## 1. M0 정리 절차

### 1.1 전제

- 구 트리는 태그 `archive/spec-v2.4`(= `7cb8338`)와 브랜치 `archive/windows-isolation`에 있다. main(`b5cd63a`)의 이식·유지 대상 파일은 태그와 같다. 예외는 `scripts/privacy-scan.mjs`(main 219줄, 태그 223줄)·`scripts/privacy-scan.test.mjs`(main 243줄, 태그 258줄) 두 파일이며 이식 기준은 main 판이다(README는 다시 쓰므로 무관).
- M0는 **커밋 1개 `start v3`**로 끝난다. 이 커밋은 구 트리 삭제, 새 워크스페이스 뼈대, 검사 스크립트, `spec.md`·`spec/`를 함께 담는다. 코드 이식은 M1부터 한다(§1.5).
- 원격 저장소가 없으므로 시작 전에 `git bundle create <다른 디스크>\your-wallet-<날짜>.bundle --all`을 **권고**한다.

### 1.2 삭제 목록 (main에서 `git ls-files`로 확인한 파일 수)

| 경로 | 파일 수 | 비고 |
|---|---:|---|
| `crates/` 전체 | 204 | approval-ui 8, approval-wire 2, broker 6, chain-registry 8, dashboard 3, eip712 6, key-agent 11, key-agent-debugger 8, key-agent-debugger-wire 2, key-agent-service 4, key-agent-service-helper-bootstrap 6, key-agent-service-rpc-sys 14, key-agent-service-wire 5, native-host 6, platform-windows 81, secret-core 10, secret-input-ui 9, wallet-model 7, wallet-protocol 8. 이식 대상도 지운다(태그에서 가져온다). |
| `demo/` | 13 | sepolia-wallet 전체 |
| `.github/` | 2 | `ci.yml`, `release-evidence-policy.yml`. 원격이 없어 실행되지 않으므로 CI 파일을 두지 않는다. 게이트는 `scripts/check.ps1` 하나다. |
| `docs/` 중 `recovery-guide.ko.md` 외 전부 | 9 | `adr/0001-…`, `designs/windows-key-agent-service.md`, `architecture.md`, `development-resume.md`, `development-status.md`, `development.md`, `protocol-contract.md`, `release-security.md`, `security-decisions.md` |
| `scripts/architecture-scan.mjs`, `scripts/architecture-diagnostic.test.mjs` | 2 | |
| `scripts/release/` | 19 (+2 이동) | `audit-extension.mjs`·`audit-extension.test.mjs`는 §1.3대로 이동하고 나머지 19개를 지운다. |
| `scripts/service-probe/` | 8 | |
| `scripts/windows-evidence/` | 7 | |
| `scripts/test-focused.ps1`, `scripts/test-focused.test.ps1`, `scripts/launcher-contract.test.ps1`, `scripts/run-sepolia-wallet.ps1` | 4 | |
| `TEST-WALLET.cmd`, `RUN-SEPOLIA-WALLET.cmd`, `SECURITY.md` | 3 | `SECURITY.md`는 v2.4 위협 모델을 설명하므로 지우고 README가 spec.md §2를 가리킨다. |
| `extension/tests/native-host-process.test.mjs` | 1 | 구 broker·native-host를 cargo로 빌드한다. M5에서 yw-host용으로 새로 쓴다([05](05-browser.md)). |

합계 272개 삭제, 추적 파일 303 → 31. 비추적·무시 파일 `__pycache__/`, `repair_windows_cap_acl.py`(태그에도 없음; 보존하려면 먼저 저장소 밖으로 옮긴다), `target/`, `artifacts/`, `demo/sepolia-wallet/target/`(구 `.gitignore`만 무시하므로 남기면 새 `.gitignore`에서 비추적 파일이 된다)도 작업 트리에서 지운다.

### 1.3 유지·이동·수정 목록

| 경로 | 처리 |
|---|---|
| `extension/` (16개) | 유지. 수정은 M5([05](05-browser.md)). |
| `scripts/privacy-scan.mjs`, `scripts/privacy-scan.test.mjs` | 유지, §4.3 규칙 추가. |
| `scripts/release/audit-extension.mjs` → `scripts/audit-extension.mjs` | `git mv`. 도우미를 `scripts/lib/strict-json.mjs`로 추출(§4.4). |
| `scripts/release/audit-extension.test.mjs` → `scripts/audit-extension.test.mjs` | `git mv`, import 경로·해시 단언 수정. |
| `scripts/check.ps1` | 전부 다시 쓴다(§4.1). |
| `rust-toolchain.toml`, `rustfmt.toml` | 그대로. |
| `clippy.toml` | `allow-unwrap-in-tests = true`, `allow-expect-in-tests = true` 추가(§5.2). |
| `.gitattributes`, `.gitignore` | §1.4 내용으로 교체. |
| `Cargo.toml` | §3.1로 교체. `Cargo.lock`은 **지우지 않는다**(§3.6 seed). |
| `README.md` | 60줄 이하로 다시 쓴다: 한 문단 소개, 상태(현재 마일스톤), 빌드 전제(§3.8), `cargo build --release --locked`, `scripts/check.ps1`, 문서 목록(spec.md·spec/), 구 코드는 태그 `archive/spec-v2.4`, 보안 범위는 spec.md §2. |
| `docs/recovery-guide.ko.md` | 유지. demo·Key Agent를 언급하는 3–8행과 56–69행(`## 구현 완료 조건` 절 전체)을 지운다. 14행 "12개 또는 24개" → "24개"(D9). 41행 → "새 지갑은 passphrase를 쓰지 않습니다. passphrase는 다른 지갑에서 가져올 때만 입력합니다."(D29). v3 경로(SOL·BTC)는 M9 체크리스트에서 갱신([09](09-testing.md)). |
| `spec.md`, `spec/*.md` | 추가. |

### 1.4 실행 순서 (Git Bash, 저장소 루트)

두 부분을 저장소 밖(예: `$TEMP`)에 각각 파일로 저장하고 저장소 루트에서 `bash -e "$TEMP/m0a.sh"`, (새 파일 작성 후) `bash -e "$TEMP/m0b.sh"`로 실행한다. 대화형 셸에 붙여 넣지 않는다(검사 실패 시 `exit`로 멈춰야 한다).

```bash
# m0a.sh — 전제 확인과 삭제
test "$(git rev-parse --short 'archive/spec-v2.4^{commit}')" = 7cb8338 || { echo "STOP: tag"; exit 1; }   # 태그 객체 자체는 68026d9
test -z "$(git status --porcelain | grep -v -x -e ' M spec.md' -e '?? spec/' -e '?? __pycache__/' -e '?? repair_windows_cap_acl.py' \
  -e '?? scripts/dev-rpc-setup.ps1' -e '?? scripts/probe-rpc.mjs')" \
  || { echo "STOP: unexpected working tree changes"; exit 1; }
test "$(for p in crates demo .github docs scripts/release scripts/service-probe scripts/windows-evidence; do
  git ls-files -- "$p" | wc -l; done | xargs)" = "204 13 2 10 21 8 7" || { echo "STOP: unexpected file counts"; exit 1; }
git mv scripts/release/audit-extension.mjs scripts/audit-extension.mjs
git mv scripts/release/audit-extension.test.mjs scripts/audit-extension.test.mjs
git rm -r -q -- crates demo .github scripts/release scripts/service-probe scripts/windows-evidence \
  docs/adr docs/designs docs/architecture.md docs/development-resume.md docs/development-status.md \
  docs/development.md docs/protocol-contract.md docs/release-security.md docs/security-decisions.md \
  scripts/architecture-scan.mjs scripts/architecture-diagnostic.test.mjs scripts/test-focused.ps1 \
  scripts/test-focused.test.ps1 scripts/launcher-contract.test.ps1 scripts/run-sepolia-wallet.ps1 \
  TEST-WALLET.cmd RUN-SEPOLIA-WALLET.cmd SECURITY.md extension/tests/native-host-process.test.mjs
test "$(git ls-files | wc -l)" -eq 31 || { echo "STOP: unexpected tracked file count"; exit 1; }
rm -rf __pycache__ repair_windows_cap_acl.py target artifacts demo
# --- 손으로: §2 트리, §3.1–3.2 매니페스트, §4 스크립트, 아래 .gitattributes/.gitignore, README, spec/ 작성 ---
# m0b.sh — 단어 목록, lock seed, 게이트, 커밋
mkdir -p crates/yw-core/src/bip39
node -e 'const fs=require("fs");const w=[...fs.readFileSync(process.argv[1],"utf8").matchAll(/"([a-z]+)"/g)].map(m=>m[1]);if(w.length!==2048)process.exit(1);fs.writeFileSync(process.argv[2],w.join("\n")+"\n")' \
  "$HOME/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/bip39-2.2.0/src/language/english.rs" crates/yw-core/src/bip39/english.txt
test "$(sha256sum crates/yw-core/src/bip39/english.txt | cut -d' ' -f1)" = \
  2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda || { echo "STOP: wordlist"; exit 1; }
cargo metadata --offline --format-version 1 --filter-platform x86_64-pc-windows-msvc > /dev/null   # lock 정리(§3.6)
test "$(grep -c '^\[\[package\]\]' Cargo.lock)" -eq 47 || { echo "STOP: lock seed"; exit 1; }   # §3.6
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1   # 0
git add -A && git commit -m "start v3" -m "Replace the v2.4 tree with the v3 skeleton. Old code: archive/spec-v2.4 (7cb8338)."
```

`.gitattributes` (전체, 한 줄에 하나씩): `* text=auto`, `*.rs`·`*.toml`·`*.md`·`*.js`·`*.mjs`·`*.json`·`*.txt`·`*.yml`·`*.lock`·`*.template`·`.gitignore`·`.gitattributes`는 `text eol=lf`, `*.ps1`·`*.cmd`는 `text eol=crlf`. 구 항목(`*.cs`, `*.rc`, 삭제된 런처·MIDL 파일)은 없앤다. `english.txt`는 LF 기준 SHA-256을 BIP39 테스트(M1)가 확인하므로 `*.txt eol=lf`가 반드시 있어야 한다.

`.gitignore` (전체): `/target/`, `/vendor/`, `/.idea/`, `/.vscode/`, `/node_modules/`, `/coverage/`, `/artifacts/`, `/fuzz/target/`, `/fuzz/artifacts/`, `/tools/*/target/`, `__pycache__/`, `*.pdb`, `*.ilk`, `*.dmp`, `*.log`, `*.tmp`, `*.bak`, `.env`, `.env.*`, `!.env.example`, `*.ywv`, `*.ywm`, `*.ywj`, `*.dpapi`, `*.vault`, `*.wallet`, `*.keystore`, `*.key`, `*.p12`, `*.pfx`, `*.jks`, `*private*.pem`, `/extension/native-host/com.your_wallet.native.json`, `!/extension/native-host/com.your_wallet.native.json.template` (한 줄에 하나씩).

### 1.5 이식 방법 (M1 이후)

- 출처는 `git show archive/spec-v2.4:<path>`로 읽고 필요한 줄 범위만 새 모듈로 옮긴다. `git checkout archive/spec-v2.4 -- <path>`로 파일을 통째로 되살리지 않는다.
- 이식 커밋 메시지에 출처를 `archive/spec-v2.4:<path>:<lines>` 형식으로 적는다(§6 표와 같은 표기).
- 옮긴 코드는 §5 규칙과 새 의존성 경계(serde·thiserror·windows·platform-windows 제거)를 지켜야 하며, 원본 테스트를 함께 옮긴다.

### 1.6 M0 완료 조건

1. `scripts/check.ps1`가 종료 코드 0(§4.1). 이때 크레이트 5개는 빈 뼈대이고 yw-core는 EVM 단계 서드파티 직접 의존성 12개(+로컬 yw-json)를 모두 선언한다(허용 목록의 "도달하지 않음" 검사 때문에).
2. `git ls-files`에 §1.2 경로가 없다.
3. §4.5 음성 체크리스트 1회 수행.

---

## 2. 워크스페이스 구성

### 2.1 디렉터리 트리

```
Cargo.toml  Cargo.lock  rust-toolchain.toml  rustfmt.toml  clippy.toml  .gitattributes  .gitignore  README.md  spec.md
install.cmd  uninstall.cmd         소스 설치·제거 진입점(더블클릭, ASCII·CRLF, §9)
.cargo/config.toml                 M7부터(§3.4)
crates/
  yw-core/   Cargo.toml  clippy.toml(§5.1)  src/  tests/{*.rs, vectors/}   (모듈 §2.2, 테스트 배치 [09](09-testing.md) §2.1)
  yw-json/   Cargo.toml  src/{lib.rs, parse.rs, value.rs, write.rs, frame.rs}  tests/
  yw-win/    Cargo.toml  src/{lib.rs, error.rs, time.rs, mem.rs, file.rs, dpapi.rs, clipboard.rs,
                              http.rs, pipe.rs, session.rs, process.rs, input.rs, ui/{mod.rs, window.rs,
                              msg.rs, paint.rs, controls.rs, secure_text.rs}}  tests/   (API §7)
  yw-app/    Cargo.toml  build.rs(선택, [04](04-app-ui.md) §1.6)  yw-app.manifest  tests/
             icons/{yw-app.ico, yw-app.res}   (앱 아이콘, `scripts/make-icons.mjs`가 만들고 커밋, [04](04-app-ui.md) §1.7)
             src/{lib.rs, main.rs, app.rs, events.rs, errors.rs, settings.rs, apikeys.rs(네트워크별 RPC 엔드포인트 URL
                  `rpc:eip155:<chainId>`·`rpc:solana:<cluster>`·`rpc:bitcoin:<net>`·공급자 템플릿 자격 정보·LLM 키, D13, [04](04-app-ui.md) §6.3), logging.rs,
                  store.rs(`VaultStorage` 구현, [09](09-testing.md) §2.1), workers/{key, rpc, read}.rs([04](04-app-ui.md) §1.2),
                  rpc/{mod.rs(공용 전송, [04](04-app-ui.md) §1.9), evm.rs(`rpc::evm`: eth_simulateV1 응답 파서 M2([09](09-testing.md) §3.8), 전송·호출 M4)}, flow/evm.rs(`flow::evm`, M4),
                  browser/{mod.rs, params.rs, envelope.rs, …}(`browser::params`·`browser::envelope`, M5, [05](05-browser.md)),
                  explain/(M6, [06](06-llm-explain.md)), sol/(M7, [07](07-solana.md) §2), btc/(M8, [08](08-bitcoin.md)),
                  ui/{main_window, screens/*, approval, interaction, secret, secure_field, text_layout, qr, theme}.rs}
                  (배치 [04](04-app-ui.md) §1.8, EVM 모듈 이름 [03](03-evm.md) §0)
  yw-host/   Cargo.toml  src/{lib.rs, main.rs}  tests/               ([05](05-browser.md))
extension/   manifest.json  package.json  extension-id.txt(M5)  src/*.js  popup/*  icons/icon-{16,32,48,128}.png([05] §2.2)
             native-host/*  tests/*.test.mjs  test-dapp/(M5)
scripts/     check.ps1  check-core-deps.mjs  privacy-scan.mjs  privacy-scan.test.mjs
             audit-extension.mjs  audit-extension.test.mjs  lib/strict-json.mjs
             extension-key.mjs   (M5, [05](05-browser.md) §2.3)
             install.ps1  uninstall.ps1  install.test.mjs   (소스 빌드·현재 사용자 설치·제거와 그 시험, §9, [05](05-browser.md) §9)
             probe-rpc.mjs   (수동 실서비스 프로브, M2 전. check.ps1 대상 아님, §4.7)
             dev-rpc-setup.ps1 (개발용 rpc.json 대화형 생성, §4.8)
             screenshot-tour.ps1(화면 투어, [04](04-app-ui.md) §11)
             make-icons.mjs  lib/png.mjs   (앱·확장 아이콘 생성기와 PNG 도우미, Node 내장 모듈만. `--check`는 check.ps1 icons 단계, §4.1)
fuzz/        퍼징, 별도 워크스페이스·루트 exclude([09](09-testing.md) §2.4) — 아직 없음(만들 때 이 위치)
tools/       btc-oracle/(M8, [08](08-bitcoin.md) §14.3)  sol-oracle/(M7, [07](07-solana.md) §17.3) — 개발 전용 차등 오라클. 각각 자체 [workspace]·Cargo.lock,
             루트 exclude(§3.1), check.ps1·허용 목록 대상 아님, 설치되지 않음 — 아직 없음(만들 때 이 위치)
spec/        01 … 09
docs/        install.ko.md(설치·업데이트·제거)  recovery-guide.ko.md  acceptance/(체크리스트·라이브 확인 기록, [09](09-testing.md) §1·§2.5)
             icon-preview.png(아이콘 미리 보기, make-icons.mjs 출력)
```

### 2.2 yw-core 모듈

`src/lib.rs`는 `#![forbid(unsafe_code)]`와 아래 모듈 선언만 둔다. 모듈 경로는 이 표가 정본이고(D31) 세부 문서는 이 이름을 그대로 쓴다. 하위 파일 구성은 세부 문서가 정한다. 단계는 그 모듈이 처음 필요한 마일스톤이다.

| 모듈 | 단계 | 내용 | 세부 |
|---|---|---|---|
| `secret` | M1 | `SecretBytes<N>`, `SecretVec`, `SecretString` (§5.3) | 이 문서 |
| `error` | M1 | 모듈별 오류 enum과 수동 `Display` | §5.2 |
| `entropy` | M1 | `RandomSource`(crate 내부), `OsRandom`, `fill_random(&mut [u8]) -> Result<(), KeyError>`(getrandom, 실패는 `KeyError::RandomnessUnavailable`), `secp_context`(§3.5 `seeded_randomize`), `random_nonzero_id`, `random_below(n)`(거부 샘플링). OS 호출은 여기서만. | [02](02-core-keys-vault.md) |
| `bip39` (`src/bip39/mod.rs` + `english.txt`, `include_str!`) | M1 | 생성(24단어), 가져오기, 시드 | [02](02-core-keys-vault.md) |
| `bip32` (+`bip32::xkey`, `bip32::path`) | M1 | secp256k1 HD 파생(`Bip32Path`, 엄격 경로). 공개 파생 `AccountXpub`·`derive_public_child`(비강화 색인만, BTC 주소용, M8에서 사용). `xkey`: `XKeyParts`, `decode_xkey`, `encode_xkey`, fingerprint = HASH160[0..4](`ripemd`, D5) — M1 벡터 1–5 전체 문자열 비교용. `path`: `AccountIndex`, `BtcCoin`, `BtcChain`, `evm_path`, `btc_path`, `sol_path`(D29; `sol_path`는 M7에 `slip10`과 함께 추가) | [02](02-core-keys-vault.md), [08](08-bitcoin.md) |
| `slip10` | M7 | Ed25519 hardened-only 파생 | [07](07-solana.md) |
| `password` | M1 | `VaultPassword`, `Bip39Passphrase` (D8) | [02](02-core-keys-vault.md) |
| `vault` | M1 | vault v3, KEK/DEK, 백업 확인, DEK 파생 하위 키로 meta·journal 봉투 | [02](02-core-keys-vault.md) |
| `hex` | M1 | 엄격 hex(주소·벡터) | [03](03-evm.md) |
| `codec::base58` | M1 | base58, base58check(SHA-256d 4바이트). SOL·BTC 공유(D6) | [02](02-core-keys-vault.md), [07](07-solana.md), [08](08-bitcoin.md) |
| `codec::transcript` | M2 | `Transcript` 정규 인코딩(승인·표시 digest) | [03](03-evm.md) |
| `evm::address` | M1 | `Address`(`[u8; 20]`), EIP-55 파싱·표시 | [03](03-evm.md) |
| `evm::{chain, amount, fee, rlp, tx, sign, abi, decode, eip191, eip712, siwe, simulate, risk, display}` | M2 | EVM 나머지. `amount`에 `U256`·`format_units`/`parse_units`, `fee`에 수수료·가스·대체 수수료 | [03](03-evm.md) |
| `journal` (+`journal::{evm, sol, btc}`) | M4 | 체인 공통 이진 컨테이너 코덱(entry = `kind` u8 ‖ `body_len` u32 BE ‖ body)·`JournalError`([02] §5.4). 체인별 레코드 본문 코덱·상태 기계: `journal::evm`(M4, kind 0x01), `journal::sol`(M7, 0x02), `journal::btc`(M8, 0x03) | [02](02-core-keys-vault.md) §5.4, [03](03-evm.md) §5, [07](07-solana.md) §14, [08](08-bitcoin.md) §12.4 |
| `approval` | M2 | 승인 세션·digest·`Approved` 토큰·공통 표시 모델(필드, 위험, 금지 문자) | [03](03-evm.md) §11, [04](04-app-ui.md) |
| `policy` | M2 | M2: `BrowserOrigin`(승인 모델이 쓴다, [03] §0·§11). M5: 나머지 — dApp 메서드 허용 목록·route, 연결 권한, 공급자 오류 코드(`ProviderError`) | [03](03-evm.md), [05](05-browser.md) |
| `sol::*` | M7 | 주소, 메시지, 서명, 표시(base58은 `codec::base58`, 저널 레코드는 `journal::sol`) | [07](07-solana.md) |
| `btc::*` | M8 | 주소(bech32/bech32m; base58check는 `codec::base58`), 계정 형식(`account`: P2PKH·P2SH-P2WPKH·P2WPKH·P2TR), sighash(레거시·BIP143), `taproot`(BIP341 키 경로), tx, 수수료, 표시(저널 레코드는 `journal::btc`) | [08](08-bitcoin.md) |

규칙: yw-core는 시간·파일·네트워크·스레드·환경 변수를 쓰지 않는다. 시각이 필요하면 호출자가 단조 `now_ms: u64`(yw-win `time::monotonic_ms`)나 벽시계 `now_unix_ms: u64`(유닉스 ms, yw-app이 구함)를 인자로 넘긴다. yw-core는 yw-json(의존성 0)에 의존한다. `evm::eip712`가 `yw_json::Value`를 입력으로 받기 때문이다([03](03-evm.md) §0). 외부 허용 목록은 바뀌지 않는다. RPC 응답은 여전히 yw-app이 yw-json으로 파싱해 yw-core 타입으로 넘기며 yw-core는 네트워크 데이터를 직접 받지 않는다.

### 2.3 yw-json 공개 API

RFC 8259 엄격 파서와 결정적 출력기. 의존성 0, `#![forbid(unsafe_code)]`, `#![deny(clippy::indexing_slicing, clippy::arithmetic_side_effects)]`.

```rust
pub struct Limits { pub max_bytes: usize, pub max_depth: u32, pub max_nodes: u32, pub max_items: u32 }
impl Limits { pub const REQUEST: Limits; pub const RESPONSE: Limits; }   // 값과 depth·nodes·items 정의는 [05] §2.9. 다른 문서가 프로필을 추가할 수 있다
pub enum Value { Null, Bool(bool), Number(Number), String(String), Array(Vec<Value>), Object(Object) }
pub struct Number(String);   // 문법 검증된 원문 토큰. f64 변환 없음
impl Number { pub fn as_u64(&self) -> Option<u64> /* 숫자만: 부호·'.'·지수 없음(앞자리 0은 문법이 거부). RPC·EIP-712 정수 */;
              pub fn as_u64_allow_dot_zero(&self) -> Option<u64> /* as_u64 + `<digits>.0`. [05] §6.1 봉투 정수 필드 전용 */;
              pub fn as_i64(&self) -> Option<i64>;
              pub fn is_integer(&self) -> bool /* 소수점·지수 없음 */; pub fn is_negative_zero(&self) -> bool;
              pub fn as_str(&self) -> &str /* 10진 문자열로 금액 해석용 */;
              pub fn from_literal(s: &str) -> Result<Number, ParseError> /* RFC 8259 number 문법 검증 후 원문 보관.
                                                    to_vec가 그대로 출력([08] maxfeerate `0.00012000`) */ }
pub struct Object(Vec<(String, Value)>);   // 원문 순서 유지, 키 중복은 파싱 오류
impl Object { pub fn get(&self, key: &str) -> Option<&Value>; pub fn keys(&self) -> impl Iterator<Item=&str>;
              pub fn len(&self) -> usize;
              pub fn from_pairs(pairs: Vec<(String, Value)>) -> Option<Object> /* 순서 유지, 키 중복이면 None. yw-app 설정·meta 출력용 */ }
// Number::from_u64(n: u64) -> Number: 10진 원문(같은 용도)
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Value, ParseError>;
pub fn to_vec(value: &Value) -> Vec<u8>;   // 공백 없음, 객체는 삽입 순서, 문자열은 RFC 8259 최소 escape
pub enum ParseError { TooLarge, InvalidUtf8, Syntax { offset: usize }, DuplicateKey { offset: usize },
                      TooDeep, TooManyNodes, TooManyItems, LoneSurrogate { offset: usize },
                      TrailingData { offset: usize } }
```

거부: BOM, 제어 문자(U+0000–U+001F) 원문, 짝 없는 `\uD800–\uDFFF`, 앞자리 0(`01`), `+`, `NaN`/`Infinity`, 후행 쉼표, 최상위 뒤 데이터(공백 제외). 오류 `Display`는 입력 내용을 담지 않는다. 정수 접근자 시험([05] §10.2 R-J1에 포함): `1.0`은 `as_u64_allow_dot_zero` 통과·`as_u64` 실패, `1e0`·`1.00`·`-1`은 둘 다 실패, `18446744073709551616`은 둘 다 `None`.

`frame` 모듈: native messaging·pipe 공통 프레이밍(4바이트 LE 길이 + payload, `read_frame`/`write_frame`, 상한 1,048,576), API는 [05](05-browser.md) §7.3.

### 2.4 크레이트 의존 규칙 (검사 스크립트가 강제, §4.2)

| 크레이트 | 로컬 의존 | 외부 의존(직접) | 종류 |
|---|---|---|---|
| yw-core | yw-json | §3.3 단계 목록 | lib |
| yw-json | 없음 | 없음 | lib |
| yw-win | 없음 | windows-sys | lib |
| yw-app | yw-core, yw-json, yw-win | qrcodegen | bin (`#![windows_subsystem = "windows"]`) |
| yw-host | yw-json, yw-win | 없음 | bin (콘솔 서브시스템) |

yw-app·yw-host는 창·OS 호출이 없는 로직을 `lib.rs`에 두고 `tests/`로 시험하며 `main.rs`는 진입만 한다([09](09-testing.md) §2.1). 모든 멤버: `[dev-dependencies]` 금지, `build.rs` 금지(예외: yw-app은 실행 파일 링크 인자만 출력하는 `build.rs`를 [04](04-app-ui.md)가 필요로 할 때 둘 수 있다. 허용되는 링크 인자는 manifest 포함(`/MANIFEST:EMBED`·`/MANIFESTINPUT:`)과 커밋된 Win32 리소스 파일 `crates/yw-app/icons/yw-app.res`(앱 아이콘, link.exe가 cvtres로 변환)뿐이다. `build.rs`는 무엇도 컴파일·생성·다운로드하지 않는다. `.res`는 `scripts/make-icons.mjs`가 만들고 check.ps1 icons 단계가 커밋본과 같은지 확인한다).

---

## 3. Cargo 설정과 의존성

### 3.1 루트 `Cargo.toml` (전체)

```toml
[workspace]
resolver = "3"
members = ["crates/yw-core", "crates/yw-json", "crates/yw-win", "crates/yw-app", "crates/yw-host"]
exclude = ["fuzz", "tools/btc-oracle", "tools/sol-oracle"]   # 각자 워크스페이스·lock([09] §2.4, [08] §14.3, [07] §17.3), 허용 목록 대상 아님, 배포하지 않음

[workspace.package]
version = "0.3.0"
edition = "2024"
rust-version = "1.95"
license = "Apache-2.0 OR MIT"
publish = false

[workspace.dependencies]
# yw-core, EVM 단계(D5). 모두 정확한 버전(=)과 default-features = false.
secp256k1 = { version = "=0.31.1", default-features = false, features = ["alloc", "recovery"] }
sha2 = { version = "=0.10.9", default-features = false }
sha3 = { version = "=0.10.8", default-features = false }
ripemd = { version = "=0.1.3", default-features = false }   # BIP32 fingerprint(M1)·BTC HASH160(M8)
hmac = { version = "=0.12.1", default-features = false }
pbkdf2 = { version = "=0.12.2", default-features = false, features = ["hmac"] }
hkdf = { version = "=0.12.4", default-features = false }
argon2 = { version = "=0.5.3", default-features = false, features = ["zeroize"] }
chacha20poly1305 = { version = "=0.10.1", default-features = false, features = ["alloc"] }
zeroize = { version = "=1.8.1", default-features = false, features = ["alloc"] }
subtle = { version = "=2.6.1", default-features = false }
getrandom = { version = "=0.3.3", default-features = false }
# M7 Solana 단계 진입 커밋에서 주석 해제(§3.4):
# ed25519-dalek = { version = "=2.2.0", default-features = false, features = ["fast", "zeroize"] }
# curve25519-dalek = { version = "=4.1.3", default-features = false, features = ["precomputed-tables", "zeroize"] }
qrcodegen = { version = "=1.8.0", default-features = false }
windows-sys = { version = "=0.61.2", default-features = false }   # feature 목록은 crates/yw-win/Cargo.toml에만
yw-core = { path = "crates/yw-core" }
yw-json = { path = "crates/yw-json" }
yw-win = { path = "crates/yw-win" }

[workspace.lints.rust]
unsafe_code = "forbid"
unsafe_op_in_unsafe_fn = "deny"
missing_debug_implementations = "warn"
unexpected_cfgs = { level = "warn", check-cfg = ['cfg(curve25519_dalek_backend, values("serial"))'] }

[workspace.lints.clippy]
all = { level = "deny", priority = -1 }
pedantic = { level = "deny", priority = -1 }
unwrap_used = "deny"
expect_used = "deny"
panic = "deny"
todo = "deny"
unimplemented = "deny"
print_stdout = "deny"
print_stderr = "deny"
dbg_macro = "deny"
mem_forget = "deny"
exit = "deny"

[profile.dev]
panic = "abort"

[profile.dev.package."*"]
opt-level = 3            # 의존성만 최적화: 디버그 테스트에서 Argon2id 256 MiB가 실용 속도로 돈다

[profile.release]
codegen-units = 1
lto = "fat"
overflow-checks = true
panic = "abort"
strip = "symbols"
debug = false
```

`cargo clippy -- -D warnings`이므로 `warn` 수준도 실패한다. `[profile.dev.package."*"]`는 [02](02-core-keys-vault.md)·[09](09-testing.md)가 요구하는 argon2·blake2 최적화를 포함한다(워크스페이스 멤버는 제외). 테스트 하네스는 `panic` 설정을 무시하고 unwind로 돈다(확인함).

### 3.2 크레이트별 `Cargo.toml`

모든 멤버의 `[package]`: `name = "<크레이트>"`, `version.workspace = true`, `edition.workspace = true`, `rust-version.workspace = true`, `license.workspace = true`, `publish.workspace = true`. yw-win 외 넷은 `[lints] workspace = true`. `[dependencies]` 항목은 모두 `<name>.workspace = true` 한 줄씩이다.

| 크레이트 | `[dependencies]` |
|---|---|
| yw-core | argon2, chacha20poly1305, getrandom, hkdf, hmac, pbkdf2, ripemd, secp256k1, sha2, sha3, subtle, zeroize(서드파티 12), yw-json (+M7 ed25519-dalek, curve25519-dalek) |
| yw-json | 없음(빈 `[dependencies]`) |
| yw-app | qrcodegen, yw-core, yw-json, yw-win |
| yw-host | yw-json, yw-win |

```toml
# crates/yw-win/Cargo.toml (package 표 외 전체)
[dependencies.windows-sys]
workspace = true
features = [
    "Win32_Foundation", "Win32_Graphics_Gdi", "Win32_Networking_WinHttp", "Win32_Security",
    "Win32_Security_Authorization", "Win32_Security_Credentials", "Win32_Security_Cryptography",
    "Win32_Storage_FileSystem", "Win32_System_Console", "Win32_System_DataExchange", "Win32_System_ErrorReporting", "Win32_System_IO",
    "Win32_System_LibraryLoader", "Win32_System_Memory", "Win32_System_Ole", "Win32_System_Pipes",
    "Win32_System_RemoteDesktop", "Win32_System_SystemInformation", "Win32_System_Threading",
    "Win32_UI_Controls", "Win32_UI_HiDpi", "Win32_UI_Input", "Win32_UI_Input_KeyboardAndMouse",
    "Win32_UI_WindowsAndMessaging",
]

# workspace lints를 상속하지 않고 복사한다: 상속과 개별 재정의는 함께 쓸 수 없고, 상속된 forbid는 모듈에서 풀 수 없다.
[lints.rust]
unsafe_code = "deny"                 # FFI 모듈의 #![allow(unsafe_code)]로만 푼다(§5.1)
unsafe_op_in_unsafe_fn = "deny"
missing_debug_implementations = "warn"

[lints.clippy]
# §3.1 [workspace.lints.clippy]의 12줄(all … exit)을 그대로 쓰고 다음 2줄을 더한다.
undocumented_unsafe_blocks = "deny"
multiple_unsafe_ops_per_block = "deny"
```

windows-sys feature 추가·삭제는 크레이트 수를 바꾸지 않지만 yw-win Cargo.toml 변경으로 리뷰한다. `Win32_System_IO`는 `ConnectNamedPipe`·`ReadFile`·`WriteFile`·`OVERLAPPED`의 cfg 게이트이고, `GetCurrentInputMessageSource`는 `Win32_UI_Input`에 있다. 기능별 사용처는 §7 첫머리.

### 3.3 허용 목록 (x86_64-pc-windows-msvc, `name=version`)

| 집합 | 크레이트 |
|---|---|
| **EVM 런타임 30** (M0–M6) | aead=0.5.2 argon2=0.5.3 base64ct=1.8.3 blake2=0.10.6 block-buffer=0.10.4 cfg-if=1.0.4 chacha20=0.9.1 chacha20poly1305=0.10.1 cipher=0.4.4 cpufeatures=0.2.17 crypto-common=0.1.7 digest=0.10.7 generic-array=0.14.7 getrandom=0.3.3 hkdf=0.12.4 hmac=0.12.1 inout=0.1.4 keccak=0.1.6 opaque-debug=0.3.1 pbkdf2=0.12.2 poly1305=0.8.0 ripemd=0.1.3 secp256k1=0.31.1 secp256k1-sys=0.11.0 sha2=0.10.9 sha3=0.10.8 subtle=2.6.1 typenum=1.20.1 universal-hash=0.5.1 zeroize=1.8.1 |
| **빌드 전용 4** | cc=1.4.2 find-msvc-tools=0.1.10 shlex=2.0.1 version_check=0.9.5 |
| Solana 추가(M7) 런타임 4 + 빌드 2 | ed25519-dalek=2.2.0 ed25519=2.2.3 signature=2.2.0 curve25519-dalek=4.1.3 / rustc_version=0.4.1 semver=1.0.28 |
| yw-win | windows-sys=0.61.2 windows-link=0.2.1 |
| yw-app 추가 | qrcodegen=1.8.0 |
| yw-json | 없음 |

- 검사 결과(확인함): EVM 단계 yw-core 34, yw-json 0, yw-win 2, yw-app 37, yw-host 2. Solana 단계 yw-core 40, yw-app 43. Bitcoin 단계(M8)는 추가 크레이트가 없다(D5).
- `build.rs` 허용: generic-array, getrandom, secp256k1-sys (+M7 curve25519-dalek). proc-macro는 어느 단계에서도 0개.
- 출처는 crates.io만. 라이선스: MIT/Apache-2.0, CC0-1.0(secp256k1, secp256k1-sys), BSD-3-Clause(subtle), MIT(generic-array, qrcodegen).
- 2026-10-24 기준 RustSec advisory-db(커밋 21d909e)와 OSV에서 위 버전에 열린 권고 없음. curve25519-dalek 4.1.3은 RUSTSEC-2024-0344 수정판이므로 `=4.1.3`을 직접 고정한다(4.2.0은 yank).

### 3.4 단계 진입 절차

**M7 (Solana)** — 한 커밋에서:
1. 루트의 `ed25519-dalek`, `curve25519-dalek` 주석 해제, yw-core에 `ed25519-dalek.workspace = true`, `curve25519-dalek.workspace = true` 추가.
2. `.cargo/config.toml` 생성:
   ```toml
   [target.x86_64-pc-windows-msvc]
   rustflags = ["--cfg", 'curve25519_dalek_backend="serial"']
   ```
   serial 백엔드는 AVX2용 proc-macro `curve25519-dalek-derive`와 proc-macro2·quote·syn·unicode-ident를 빌드 그래프에서 뺀다. 이 설정을 `cargo metadata --filter-platform`과 빌드가 모두 따르는 것을 확인했다.
3. `crates/yw-core/src/sol/mod.rs`에 가드:
   ```rust
   #[cfg(not(any(curve25519_dalek_backend = "serial", doc, doctest)))]
   compile_error!("Solana phase requires --cfg curve25519_dalek_backend=\"serial\" (.cargo/config.toml); RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS override it");
   ```
   환경 변수 `RUSTFLAGS`가 있으면 config의 rustflags가 통째로 무시되므로, 사용자가 그런 환경에서 빌드해도 조용히 다른 의존성으로 빌드되지 않는다(확인함, M7 구현 때 `RUSTFLAGS=-Dwarnings cargo check -p yw-core`로 다시 확인). `doc`·`doctest`를 빼는 이유: rustdoc은 config의 `rustflags`를 받지 않아 `cargo test`의 doctest 수집 단계에서 가드가 오탐한다(확인함, 2026-10-27). doctest는 rustc로 빌드된 라이브러리를 링크하므로 가드의 목적은 그대로다. `check.ps1`은 이 변수들이 비어 있지 않으면 종료 코드 11로 실패한다.
4. `scripts/check-core-deps.mjs`의 `PHASES`에 `"sol"` 추가.
5. §3.6 절차로 lock 갱신. Cargo.lock에는 컴파일되지 않는 `curve25519-dalek-derive`·`fiat-crypto`·`proc-macro2`·`quote`·`syn`·`unicode-ident` 항목도 생긴다(lock은 cfg와 무관, 59개가 됨을 확인함). 허용 여부 판단은 검사 스크립트가 한다.

**M8 (Bitcoin)** — 의존성·허용 목록·`PHASES` 변경 없음(`ripemd`는 M0부터 허용 목록에 있다, D5).

### 3.5 feature 규칙

| 크레이트 | 반드시 켬 | 금지(검사 스크립트가 워크스페이스 통합 feature로 확인) |
|---|---|---|
| secp256k1 | alloc, recovery | rand, global-context, hashes, serde |
| argon2 | zeroize | alloc, password-hash, rand |
| chacha20poly1305, aead | alloc(chacha20poly1305) | getrandom, rand_core (getrandom 0.2.17·rand_core 0.6.4가 추가로 들어온다) |
| zeroize | alloc | derive (proc-macro) |
| getrandom | — | wasm_js |
| pbkdf2 | hmac | — |
| ed25519-dalek | fast, zeroize | asm, batch, digest, hazmat, legacy_compatibility, pem, pkcs8, rand_core, serde (hazmat의 `raw_sign`은 이중 공개키 오라클) |
| curve25519-dalek | precomputed-tables, zeroize (digest는 ed25519-dalek이 켬) | group, group-bits, legacy_compatibility, rand_core, serde |
| ed25519 / signature | — | pem, pkcs8, serde, serde_bytes / derive, digest, rand_core |

feature는 dev·다른 멤버를 포함해 워크스페이스 전체에서 통합되므로, yw-app이 금지 feature를 켜도 yw-core 검사가 실패한다(의도된 엄격함).

feature 선택에 따른 코드 의무(세부 [02](02-core-keys-vault.md)):
- argon2에 `alloc`이 없으므로 `Argon2::hash_password_into_with_memory(pwd, salt, out, &mut blocks)`를 쓰고, 호출자 소유 `Vec<Block>`(`params.block_count()`개)을 사용 후 `Block::zeroize()`로 지운다.
- secp256k1에 `rand`가 없으므로 `Secp256k1::new()` 뒤 `seeded_randomize(&[u8; 32])`를 `entropy::fill_random` 값으로 호출한다.

### 3.6 Cargo.lock 정책

1. `Cargo.lock`은 커밋한다. `check.ps1`의 cargo 명령은 모두 `--locked`.
2. **M0 seed:** 기존 Cargo.lock을 그대로 둔 채 매니페스트를 바꾸고 `cargo metadata --offline --format-version 1 --filter-platform x86_64-pc-windows-msvc`를 한 번 실행한다. 쓰지 않는 항목이 정리되고 qrcodegen 1.8.0만 추가되어 47개 `[[package]]`가 된다(확인함): 허용 34 + windows-sys·windows-link·qrcodegen + 로컬 5 + getrandom의 비Windows 의존(libc, r-efi, wasi, wasip2, wit-bindgen; 컴파일되지 않음). `ripemd 0.1.3`은 main의 Cargo.lock에 이미 있으므로(구 secret-core 의존) 새 resolve 없이 seed에 남는다. 허용 목록 편입은 M0 커밋에서 4의 (e)–(g)(허용 목록, 소스 검토, 권고 조회 날짜 기록)로 처리한다. 새로 resolve하면 cc 1.5.1·cfg-if 1.0.5·find-msvc-tools 0.1.14로 바뀌어 허용 목록이 깨진다.
3. **금지:** `cargo generate-lockfile`, 인자 없는 `cargo update`, Cargo.lock 삭제. `--locked` 없이 cargo를 실행했다면 커밋 전 `git diff Cargo.lock`이 비어 있는지 확인한다.
4. **크레이트 추가·변경 절차:** (a) `[workspace.dependencies]`에 `=` 고정과 `default-features = false`로 추가 → (b) `cargo metadata --format-version 1 --filter-platform x86_64-pc-windows-msvc`(캐시에 있으면 `--offline`)로 lock 갱신 → (c) 의도와 다른 전이 버전은 `cargo update -p <name>@<현재> --precise <목표>` → (d) `git diff Cargo.lock`의 추가·변경 `[[package]]`(name, version, checksum)를 커밋 메시지에 나열 → (e) 같은 커밋에서 `check-core-deps.mjs` 허용 목록·`PHASES` 갱신 → (f) `node scripts/check-core-deps.mjs --list`가 출력한 새 크레이트의 소스 디렉터리(`~/.cargo/registry/src/…/<name>-<ver>`)를 읽어 검토(build.rs·unsafe·네트워크·파일 접근 위주) → (g) RustSec advisory-db와 OSV에서 `name=version` 조회, 조회 날짜를 커밋 메시지에 기록 → (h) `check.ps1` 통과.

### 3.7 소스 검토와 vendor

- 검토 대상은 검사 스크립트가 보고한 폐포뿐이다. `--list`가 각 크레이트의 로컬 registry 소스 경로를 준다(네트워크 불필요).
- `cargo vendor --locked --versioned-dirs vendor`는 **선택**이다. lock 전체(비Windows 크레이트 포함)를 받으므로 캐시에 없는 항목(예: wasi 0.14.7) 때문에 네트워크가 필요하다. `/vendor`는 gitignore이며 커밋하지 않고, `.cargo/config.toml`의 source replacement로 쓰지 않는다. 빌드는 항상 crates.io + Cargo.lock checksum이다.
- 권고 조회(cargo-audit·cargo-deny 미설치 전제): 단계 진입 시와 M9 체크리스트에서 허용 목록 전체를 RustSec·OSV에서 수동 조회한다([09](09-testing.md)).

### 3.8 빌드 전제 조건

| 항목 | 요구 |
|---|---|
| OS | Windows 11 x64 22H2 이상(D1) |
| Rust | rustup + `rust-toolchain.toml`(1.95.0, components clippy·rustfmt, profile minimal). 기계 기본 툴체인과 무관. |
| C 컴파일러·링커 | Visual Studio Build Tools의 "C++를 사용한 데스크톱 개발" 워크로드(MSVC + Windows SDK). secp256k1-sys가 cc로 libsecp256k1 C 소스를 컴파일하고, `x86_64-pc-windows-msvc` 링크에도 필요하다. |
| Node.js | 22 이상(확장 테스트·스크립트). npm 패키지 설치 없음. 설치(§9)에는 필요 없다. |
| Git | 2.x (privacy-scan이 `git ls-files` 사용) |
| PowerShell | Windows PowerShell 5.1 또는 7.x |
| Chrome | 120 이상(M5부터) |

빌드: `cargo build --release --locked` → `target\release\yw-app.exe`, `target\release\yw-host.exe`. 첫 빌드는 crates.io 다운로드가 필요할 수 있다. 이후 `check.ps1 -Offline` 가능. 설치(§9)는 `install.cmd`가 같은 빌드(`-p yw-app -p yw-host`)를 그 PC에서 하고 결과를 설치 폴더로 복사한다. 실행 파일은 배포하지 않는다(D1). 도구가 없는 PC에서 `install.cmd`가 보여 주고 동의를 받아 실행하는 명령: `winget install --id Rustlang.Rustup -e`, `winget install --id Microsoft.VisualStudio.2022.BuildTools -e --override "--wait --passive --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended"`.

### 3.9 재현성과 빌드 경로

`.cargo/config.toml`(전체):

```toml
[target.x86_64-pc-windows-msvc]
rustflags = ["--cfg", 'curve25519_dalek_backend="serial"', "-C", "link-arg=/Brepro"]
```

- `--cfg curve25519_dalek_backend="serial"`: §3.4 M7.
- `/Brepro`: MSVC 링커가 PE 헤더·디버그 디렉터리의 시각 대신 내용 해시를 쓴다(같은 입력 → 같은 exe). PDB 경로는 rustc가 이미 `/PDBALTPATH:%_PDB%`로 파일 이름만 남긴다(확인함).
- 의존성과 std의 패닉 위치 문자열에는 이 PC의 절대 경로가 들어간다(`C:\Users\<이름>\.cargo\registry\src\…`, rust-src가 설치된 툴체인의 `…\lib\rustlib\src\rust\library\…`; 워크스페이스 크레이트는 상대 경로라 해당 없음). `--remap-path-prefix`는 접두사 일치뿐이라 사용자 이름을 숨기는 값을 PC와 무관하게 config에 적을 수 없고(`C:\Users\=~`는 `~<이름>\…`를 남긴다), cargo `trim-paths`는 1.95에서 불안정(확인함, 2026-10-28), rustflags 환경 변수는 §3.4·§4.1이 금지한다. 실행 파일은 빌드한 PC에서만 쓰고 배포하지 않으므로(D1) 경로를 지우지 않는다: 이 경로 문자열은 그 PC 밖으로 나가지 않는다. `install.ps1`(§9.2)도 경로 정리 없이 같은 `cargo build`를 쓴다(rustflags 환경 변수가 있으면 그 빌드에서만 지운다).

---

## 4. 검사 스크립트

### 4.1 `scripts/check.ps1` (전체)

```powershell
# scripts/check.ps1 — 저장소 게이트. 사용: powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 [-Step <name>] [-Offline]
[CmdletBinding()]
param(
    [ValidateSet("all", "fmt", "deps", "clippy", "test", "fuzz", "build", "ext-test", "script-test", "privacy", "audit-ext", "icons")]
    [string]$Step = "all",
    [switch]$Offline
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"
$Root = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot "..")).Path
Set-Location -LiteralPath $Root

function Fail([int]$Code, [string]$Message) {
    [Console]::Error.WriteLine("check: FAIL $Code $Message")
    exit $Code
}
function Invoke-Step([string]$Name, [int]$Code, [string]$Exe, [string[]]$ArgList) {
    if ($Step -ne "all" -and $Step -ne $Name) { return }
    Write-Host "check: $Name"
    & $Exe @ArgList
    if ($LASTEXITCODE -ne 0) { Fail $Code "$Name (exit $LASTEXITCODE)" }
}
function Get-Tests([string]$Dir, [int]$Code) {
    $files = @(Get-ChildItem -LiteralPath $Dir -Filter "*.test.mjs" -File | Sort-Object Name | ForEach-Object { $_.FullName })
    if ($files.Count -eq 0) { Fail $Code "no tests in $Dir" }
    return $files
}

# 설치(scripts/install.ps1 Invoke-Build)와 같은 빌드 조건: 컴파일러·빌드 설정을 바꾸는 환경 변수를 이 게이트 프로세스에서만
# 지우고(시스템·사용자 설정은 그대로), cargo에 --config로 컴파일러 래퍼를 끄고 링커를 기본 link.exe로 고정한다. 그래야 게이트
# 통과가 설치 빌드와 같은 조건을 뜻한다. 이름·접두사·--config 값은 install.ps1과 같아야 한다(scripts/install.test.mjs가 확인;
# 게이트는 dev·test 프로필도 빌드하므로 CARGO_PROFILE_RELEASE_ 대신 CARGO_PROFILE_ 전체를 지운다). RUSTFLAGS 계열은 지우지
# 않고 거부한다(아래, 종료 11).
$ClearedBuildVariableNames = @('RUSTC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER')
$ClearedBuildVariablePrefixes = @('CARGO_PROFILE_', 'CARGO_BUILD_RUSTC', 'CC', 'CFLAGS', 'CXX', 'CXXFLAGS')
$BuildConfigOverrides = @("build.rustc-wrapper=''", "build.rustc-workspace-wrapper=''", "target.x86_64-pc-windows-msvc.linker='link.exe'")
$clearedNames = @([Environment]::GetEnvironmentVariables('Process').Keys | ForEach-Object { [string]$_ } | Where-Object {
    $name = $_
    @($ClearedBuildVariableNames | Where-Object { $name.Equals($_, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0 -or
    @($ClearedBuildVariablePrefixes | Where-Object { $name.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0
} | Sort-Object)
foreach ($name in $clearedNames) { [Environment]::SetEnvironmentVariable($name, [NullString]::Value, 'Process') }
if ($clearedNames.Count -gt 0) { Write-Host "check: cleared for this run: $($clearedNames -join ', ')" }
$config = @(foreach ($setting in $BuildConfigOverrides) { '--config'; $setting })
# clippy는 cargo-clippy가 RUSTC_WORKSPACE_WRAPPER(clippy-driver)로 돌므로 그 키는 덮어쓰지 않는다.
$clippyConfig = @(foreach ($setting in $BuildConfigOverrides | Where-Object { $_ -notlike 'build.rustc-workspace-wrapper=*' }) { '--config'; $setting })

$cargoVersion = & cargo --version 2>$null
if ($LASTEXITCODE -ne 0 -or "$cargoVersion" -notmatch '^cargo 1\.95\.0 ') { Fail 10 "cargo 1.95.0 required (rust-toolchain.toml)" }
$nodeVersion = & node --version 2>$null
if ($LASTEXITCODE -ne 0 -or "$nodeVersion" -notmatch '^v(\d+)\.' -or [int]$Matches[1] -lt 22) { Fail 10 "Node.js 22+ required" }
foreach ($name in "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS") {
    if ([Environment]::GetEnvironmentVariable($name)) { Fail 11 "$name must be unset (.cargo/config.toml owns rustflags)" }
}
$net = @("--locked"); if ($Offline) { $net += "--offline" }
$deps = @("scripts/check-core-deps.mjs"); if ($Offline) { $deps += "--offline" }

# 빌드 폴더([09] §2.2): 결과가 호스트 ACL 특성에 좌우되지 않게 한다. 빌드 폴더(CARGO_TARGET_DIR, 없으면 target\)나 그것을 담은
# 저장소 루트에 Medium보다 낮은 무결성 레이블(Low·Untrusted; 일부 샌드박스 도구가 저장소에 붙인다)이 있으면 그 아래 만든 exe가
# 레이블을 물려받아 Low 무결성으로 돌고(yw-win·yw-host 무결성 검사, H1, %TEMP% 쓰기가 실패한다), 빌드 폴더가 재분석 지점이면
# 다른 곳에 쓴다. 그때는 이 실행에서만 저장소 밖 사설 폴더 %LOCALAPPDATA%\YourWallet-dev\target(현재 사용자·SYSTEM·
# Administrators만, 상속 끊음, 레이블 없음)을 CARGO_TARGET_DIR로 쓰고 한 줄 출력한다. 저장소의 ACL은 바꾸지 않는다.
# 레이블은 Get-Acl이 돌려주지 않으므로 GetNamedSecurityInfoW(LABEL_SECURITY_INFORMATION)로 읽는다(메모리에서만 만드는
# P/Invoke: Add-Type처럼 %TEMP%에 쓰지 않는다).
$UserSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$TrustedSids = @($UserSid, 'S-1-5-18', 'S-1-5-32-544')
$script:NativeSecurity = $null
function Get-NativeSecurity {
    if ($null -ne $script:NativeSecurity) { return $script:NativeSecurity }
    $assembly = [Reflection.Emit.AssemblyBuilder]::DefineDynamicAssembly((New-Object Reflection.AssemblyName('YwCheckNative')), [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $type = $assembly.DefineDynamicModule('YwCheckNative').DefineType('YwCheckNative.Advapi', 'Public, Class')
    $out = [IntPtr].MakeByRefType()
    foreach ($m in @(
        @('advapi32.dll', 'GetNamedSecurityInfoW', [int], @([string], [int], [int], $out, $out, $out, $out, $out)),
        @('advapi32.dll', 'ConvertSecurityDescriptorToStringSecurityDescriptorW', [bool], @([IntPtr], [int], [int], $out, [IntPtr])),
        @('kernel32.dll', 'LocalFree', [IntPtr], @([IntPtr])))) {
        $method = $type.DefinePInvokeMethod($m[1], $m[0], [Reflection.MethodAttributes]'Public, Static, PinvokeImpl',
            [Reflection.CallingConventions]::Standard, $m[2], [type[]]$m[3],
            [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Unicode)
        $method.SetImplementationFlags([Reflection.MethodImplAttributes]::PreserveSig)
    }
    $script:NativeSecurity = $type.CreateType()
    return $script:NativeSecurity
}
# $Path의 무결성 레이블이 Medium보다 낮으면 이유 문장, 아니면 $null(레이블 없음 = Medium).
function Get-LowLabel([string]$Path) {
    $native = Get-NativeSecurity
    $owner = [IntPtr]::Zero; $group = [IntPtr]::Zero; $dacl = [IntPtr]::Zero; $sacl = [IntPtr]::Zero; $sd = [IntPtr]::Zero
    $status = $native::GetNamedSecurityInfoW($Path, 1, 0x10, [ref]$owner, [ref]$group, [ref]$dacl, [ref]$sacl, [ref]$sd)   # SE_FILE_OBJECT, LABEL_SECURITY_INFORMATION
    if ($status -ne 0) { return "integrity label unreadable (error $status)" }
    try {
        $text = [IntPtr]::Zero
        if (-not $native::ConvertSecurityDescriptorToStringSecurityDescriptorW($sd, 1, 0x10, [ref]$text, [IntPtr]::Zero)) { return "integrity label unreadable" }
        try { $sddl = [Runtime.InteropServices.Marshal]::PtrToStringUni($text) } finally { [void]$native::LocalFree($text) }
    } finally { [void]$native::LocalFree($sd) }
    foreach ($ace in [regex]::Matches($sddl, '\(ML;[^;]*;[^;]*;[^;]*;[^;]*;([^)]+)\)')) {
        $sid = $ace.Groups[1].Value
        $level = switch -Regex ($sid) { '^LW$' { 0x1000 } '^(ME|MP|HI|SI)$' { 0x2000 } '^S-1-16-(\d+)$' { [int]$Matches[1] } default { 0 } }
        if ($level -lt 0x2000) { return "integrity label $sid (below Medium)" }
    }
    return $null
}
# 빌드 폴더로 쓸 수 없으면 이유, 아니면 $null. 아직 없는 폴더는 가장 가까운 있는 상위 폴더의 레이블을 본다(물려받으므로).
function Get-BuildDirProblem([string]$Dir) {
    $paths = @()
    if (Test-Path -LiteralPath $Dir) {
        $item = Get-Item -LiteralPath $Dir -Force
        if (-not $item.PSIsContainer) { return "not a folder" }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return "reparse point (link)" }
        $paths += $Dir
    } else {
        $parent = [IO.Path]::GetDirectoryName($Dir)
        while (-not [string]::IsNullOrEmpty($parent) -and -not (Test-Path -LiteralPath $parent)) { $parent = [IO.Path]::GetDirectoryName($parent) }
        if (-not [string]::IsNullOrEmpty($parent)) { $paths += $parent }
    }
    $rootPrefix = $Root.TrimEnd('\') + '\'
    if ($Dir.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) { $paths += $Root }
    foreach ($path in $paths) {
        $problem = Get-LowLabel $path
        if ($null -ne $problem) { return "$problem on $path" }
    }
    return $null
}
# 사설 폴더 확인: 링크가 아니고, 소유자·허용 ACE가 현재 사용자·SYSTEM·Administrators뿐이고, 낮은 레이블이 없다. $Protected면
# 상속도 끊겨 있어야 한다. 문제가 없으면 $null.
function Get-PrivateDirProblem([string]$Dir, [bool]$Protected) {
    $item = Get-Item -LiteralPath $Dir -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { return "not a plain folder" }
    $acl = Get-Acl -LiteralPath $Dir
    if ($Protected -and -not $acl.AreAccessRulesProtected) { return "inherits permissions from its parent" }
    $sd = New-Object Security.AccessControl.RawSecurityDescriptor($acl.Sddl)
    if ($null -eq $sd.Owner -or $TrustedSids -notcontains $sd.Owner.Value) { return "owner is not the current user, SYSTEM or Administrators" }
    if ($null -eq $sd.DiscretionaryAcl) { return "no DACL" }
    foreach ($ace in $sd.DiscretionaryAcl) {
        if ($ace -isnot [Security.AccessControl.QualifiedAce]) { return "unknown ACE" }
        if ($ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and $TrustedSids -notcontains $ace.SecurityIdentifier.Value) {
            return "access granted to $($ace.SecurityIdentifier.Value)"
        }
    }
    return Get-LowLabel $Dir
}
function New-PrivateDir([string]$Dir) {
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in $TrustedSids) {
        $security.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),
            [Security.AccessControl.FileSystemRights]::FullControl, [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
    }
    $extensions = 'System.IO.FileSystemAclExtensions' -as [type]   # PowerShell 7(.NET); 5.1(.NET Framework)은 CreateDirectory(path, security)
    if ($null -ne $extensions) { [void]$extensions::CreateDirectory($security, $Dir) } else { [void][IO.Directory]::CreateDirectory($Dir, $security) }
}
$TargetDir = if ([string]::IsNullOrEmpty($env:CARGO_TARGET_DIR)) { Join-Path $Root "target" } else { [IO.Path]::GetFullPath([IO.Path]::Combine($Root, $env:CARGO_TARGET_DIR)) }
$problem = Get-BuildDirProblem $TargetDir
if ($null -ne $problem) {
    if ([string]::IsNullOrEmpty($env:LOCALAPPDATA)) { Fail 12 "build folder $TargetDir unsuitable ($problem) and LOCALAPPDATA is not set" }
    $privateBase = Join-Path $env:LOCALAPPDATA "YourWallet-dev"
    $privateTarget = Join-Path $privateBase "target"
    try {
        if (-not (Test-Path -LiteralPath $privateBase)) { New-PrivateDir $privateBase }
        $privateProblem = Get-PrivateDirProblem $privateBase $true
        if ($null -eq $privateProblem -and (Test-Path -LiteralPath $privateTarget)) { $privateProblem = Get-PrivateDirProblem $privateTarget $false }
    } catch {
        $privateProblem = $_.Exception.Message
    }
    if ($null -ne $privateProblem) { Fail 12 "build folder $TargetDir unsuitable ($problem); private folder $privateBase unusable ($privateProblem): remove it and run again" }
    Write-Host "check: build folder $TargetDir unsuitable ($problem); using CARGO_TARGET_DIR=$privateTarget"
    $env:CARGO_TARGET_DIR = $privateTarget
}

Invoke-Step "fmt" 20 "cargo" @("fmt", "--all", "--", "--check")
Invoke-Step "deps" 21 "node" $deps
Invoke-Step "clippy" 22 "cargo" (@("clippy", "--workspace", "--all-targets") + $net + $clippyConfig + @("--", "-D", "warnings"))
Invoke-Step "test" 23 "cargo" (@("test", "--workspace") + $net + $config)
$env:YW_FUZZ_RUNS = "20000"                                           # fuzz-lite 스모크([09] §2.4): 무시된 fuzz_lite_*를 2만 회씩
Invoke-Step "fuzz" 29 "cargo" (@("test", "--workspace") + $net + $config + @("--", "--ignored", "fuzz_lite"))
$env:YW_FUZZ_RUNS = $null                                             # 직접 --ignored로 돌리면 1,000,000회
Invoke-Step "build" 24 "cargo" (@("build", "--workspace") + $net + $config)   # <빌드 폴더>\debug\yw-host.exe ([09] §2.2, [05] H1)
$env:YW_CHECK = "1"                                                   # 확장 프로세스 테스트가 skip 대신 실패([09])
if ($Step -in "all", "ext-test") { Invoke-Step "ext-test" 25 "node" (@("--test") + (Get-Tests "extension/tests" 25)) }
if ($Step -in "all", "script-test") { Invoke-Step "script-test" 26 "node" (@("--test") + (Get-Tests "scripts" 26)) }
Invoke-Step "privacy" 27 "node" @("scripts/privacy-scan.mjs")
Invoke-Step "audit-ext" 28 "node" @("scripts/audit-extension.mjs", "check", "--extension-root", "extension")
Invoke-Step "icons" 30 "node" @("scripts/make-icons.mjs", "--check")   # 커밋된 아이콘 = 생성기 출력([04] §1.7, [05] §2.2)
Write-Host "check: OK"
exit 0
```

빌드 조건은 설치(§9.2-5)와 같다(2026-11-01 검토 INFO): `RUSTC`·`RUSTC_WRAPPER`·`RUSTC_WORKSPACE_WRAPPER`와 이름이 `CARGO_PROFILE_`·`CARGO_BUILD_RUSTC`·`CC`·`CFLAGS`·`CXX`·`CXXFLAGS`로 시작하는 변수를 게이트 프로세스에서 지우고(지운 이름을 한 줄 출력), clippy·test·fuzz·build에 설치와 같은 `--config`(래퍼 끄기, 링커 `link.exe`)를 준다(clippy는 `build.rustc-workspace-wrapper`를 빼고: cargo-clippy가 그 변수로 clippy-driver를 건다). 목록 일치는 `scripts/install.test.mjs`가 확인한다. rustflags 4개는 지우지 않고 거부한다(11).

빌드 폴더(2026-11-01): 게이트 결과는 호스트 ACL 특성에 좌우되지 않아야 한다. 빌드 폴더(`CARGO_TARGET_DIR`, 없으면 `target\`; 저장소 안이면 저장소 루트도)에 Medium보다 낮은 무결성 레이블(Low·Untrusted — 일부 샌드박스 도구가 저장소에 붙인다)이 있거나 빌드 폴더가 재분석 지점이면, 그 실행에서만 `CARGO_TARGET_DIR`을 저장소 밖 사설 폴더 `%LOCALAPPDATA%\YourWallet-dev\target`으로 바꾸고 한 줄(`check: build folder … unsuitable (…); using CARGO_TARGET_DIR=…`) 출력한다. 레이블이 붙은 폴더에서 만든 exe는 Low 무결성으로 실행되어 yw-win·yw-host 무결성 검사, [05] H1, `%TEMP%` 쓰기가 환경 때문에 실패하기 때문이다. `YourWallet-dev`는 없으면 현재 사용자·SYSTEM·Administrators 모든 권한·상속 끊음으로 만들고, 있으면 링크가 아님·소유자와 허용 ACE가 그 셋뿐·상속 끊김·낮은 레이블 없음을 확인한다(그 아래 `target`도 링크·다른 SID·낮은 레이블 없음). 저장소의 ACL은 바꾸지 않는다. 바뀐 `CARGO_TARGET_DIR`은 모든 단계(확장·스크립트 테스트 포함)에 넘어가고, `extension/tests/yw-host-process.test.mjs`는 `CARGO_TARGET_DIR`(상대 경로면 작업 폴더 기준, cargo와 같음)의 `debug\yw-host.exe`를 실행한다.

종료 코드: 0 통과, 1 스크립트 자체 오류(잘못된 `-Step` 포함), 10 cargo 1.95.0 또는 Node 22+ 없음, 11 rustflags 환경 변수 설정됨, 12 빌드 폴더가 부적합한데 사설 폴더를 만들거나 쓸 수 없음(`LOCALAPPDATA` 없음, 기존 `YourWallet-dev`의 권한이 다름 — 지우고 다시 실행), 20 fmt, 21 의존성 허용 목록, 22 clippy, 23 cargo test, 29 fuzz-lite 스모크(`fuzz`, test 다음·build 앞: `#[ignore]`된 `fuzz_lite_*` 테스트를 `YW_FUZZ_RUNS=20000`으로 디버그 빌드에서 실행; 각 테스트는 이 변수가 없으면 1,000,000회), 24 cargo build, 25 확장 테스트, 26 스크립트 테스트, 27 privacy scan, 28 확장 정적 감사, 30 아이콘(`scripts/make-icons.mjs --check`: 앱 `.ico`·`.res`, 확장 `icons/*.png`, `provider-main.js`의 `PROVIDER_ICON`, `docs/icon-preview.png`를 메모리에서 다시 만들어 커밋본과 바이트 비교; 다르거나 없으면 생성기 종료 1, 사용법·입출력 오류 2). 첫 실패에서 멈춘다. 모든 마일스톤 완료 조건은 이 스크립트의 0을 포함한다. (PowerShell 5.1에서 단계 선택, 종료 코드 11, 잘못된 `-Step`의 1을 확인함.)

### 4.2 `scripts/check-core-deps.mjs` (전체)

```js
// scripts/check-core-deps.mjs — 워크스페이스 크레이트별 의존성 폐포를 허용 목록과 정확히 비교한다.
// Usage: node scripts/check-core-deps.mjs [--offline] [--list] [--metadata <file>]
//   --metadata <file>: cargo를 실행하지 않고 그 파일의 `cargo metadata` JSON을 검사한다(scripts/check-core-deps.test.mjs).
// Exit: 0 = OK, 1 = 정책 위반, 2 = cargo metadata 실행/해석 실패.
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const TARGET = "x86_64-pc-windows-msvc";
export const CRATES_IO = "registry+https://github.com/rust-lang/crates.io-index";
// 단계 진입 커밋에서만 바꾼다(spec/01 §3.4): M7 → "sol" 추가.
export const PHASES = new Set([]);

// name=version:n (런타임에 링크) | :b (빌드 시에만 실행: build-dependency와 그 폐포)
const table = (text) => Object.fromEntries(text.trim().split(/\s+/).map((entry) => entry.split(":")));
const CORE_EVM = table(`
aead=0.5.2:n argon2=0.5.3:n base64ct=1.8.3:n blake2=0.10.6:n block-buffer=0.10.4:n cfg-if=1.0.4:n
chacha20=0.9.1:n chacha20poly1305=0.10.1:n cipher=0.4.4:n cpufeatures=0.2.17:n crypto-common=0.1.7:n
digest=0.10.7:n generic-array=0.14.7:n getrandom=0.3.3:n hkdf=0.12.4:n hmac=0.12.1:n inout=0.1.4:n
keccak=0.1.6:n opaque-debug=0.3.1:n pbkdf2=0.12.2:n poly1305=0.8.0:n ripemd=0.1.3:n secp256k1=0.31.1:n
secp256k1-sys=0.11.0:n sha2=0.10.9:n sha3=0.10.8:n subtle=2.6.1:n typenum=1.20.1:n
universal-hash=0.5.1:n zeroize=1.8.1:n
cc=1.4.2:b find-msvc-tools=0.1.10:b shlex=2.0.1:b version_check=0.9.5:b`);
const CORE_SOL = table(`ed25519-dalek=2.2.0:n ed25519=2.2.3:n signature=2.2.0:n curve25519-dalek=4.1.3:n
rustc_version=0.4.1:b semver=1.0.28:b`);
const WIN = table(`windows-sys=0.61.2:n windows-link=0.2.1:n`);
const APP = table(`qrcodegen=1.8.0:n`);

const CORE = { ...CORE_EVM, ...(PHASES.has("sol") ? CORE_SOL : {}) };
export const POLICY = {
  "yw-core": { allow: CORE, local: ["yw-json"] },
  "yw-json": { allow: {}, local: [] },
  "yw-win": { allow: WIN, local: [] },
  "yw-app": { allow: { ...CORE, ...WIN, ...APP }, local: ["yw-core", "yw-json", "yw-win"] },
  "yw-host": { allow: WIN, local: ["yw-json", "yw-win"] },
};
export const BUILD_RS_ALLOW = new Set(["generic-array", "getrandom", "secp256k1-sys", ...(PHASES.has("sol") ? ["curve25519-dalek"] : [])]);
export const OWN_BUILD_RS_ALLOW = new Set(["yw-app"]);
export const FORBIDDEN_FEATURES = {
  secp256k1: ["rand", "global-context", "hashes", "serde"], argon2: ["alloc", "password-hash", "rand"],
  chacha20poly1305: ["getrandom", "rand_core"], aead: ["getrandom", "rand_core"], zeroize: ["derive"],
  getrandom: ["wasm_js"], "ed25519-dalek": ["asm", "batch", "digest", "hazmat", "legacy_compatibility", "pem", "pkcs8", "rand_core", "serde"],
  "curve25519-dalek": ["group", "group-bits", "legacy_compatibility", "rand_core", "serde"],
  ed25519: ["pem", "pkcs8", "serde", "serde_bytes"], signature: ["derive", "digest", "rand_core"],
};

/**
 * Checks one `cargo metadata --format-version 1` document against the policy.
 * Returns `{ errors, ok, listing }`: violations, the per-crate OK lines and the `--list` rows.
 * Throws when the document lacks the fields it reads (the CLI reports that as exit 2).
 */
export function checkMetadata(meta) {
  const pkgs = new Map(meta.packages.map((p) => [p.id, p]));
  const nodes = new Map(meta.resolve.nodes.map((n) => [n.id, n]));
  const key = (p) => `${p.name}=${p.version}`;
  const errors = [];
  const ok = [];
  const listing = [];

  for (const id of meta.workspace_members) {
    const p = pkgs.get(id);
    if (!(p.name in POLICY)) errors.push(`${p.name}: workspace member without a policy`);
    if (p.dependencies.some((d) => d.kind === "dev")) errors.push(`${p.name}: dev-dependencies are forbidden`);
    if (p.targets.some((t) => t.kind.includes("custom-build")) && !OWN_BUILD_RS_ALLOW.has(p.name)) errors.push(`${p.name}: build.rs is forbidden`);
  }

  for (const [root, policy] of Object.entries(POLICY)) {
    const rootId = meta.workspace_members.find((id) => pkgs.get(id).name === root);
    if (!rootId) { errors.push(`${root}: workspace member not found`); continue; }
    // BFS over normal + build edges (dev edges ignored); a crate reached at runtime is "n".
    const seen = new Map();
    const queue = [[rootId, "n"]];
    while (queue.length) {
      const [id, mode] = queue.shift();
      if (seen.get(id) === "n" || seen.get(id) === mode) continue;
      seen.set(id, mode);
      for (const d of nodes.get(id).deps) {
        const kinds = d.dep_kinds.map((k) => k.kind);
        if (kinds.includes(null)) queue.push([d.pkg, mode]);
        if (kinds.includes("build")) queue.push([d.pkg, "b"]);
      }
    }
    const reached = new Set();
    for (const [id, mode] of seen) {
      if (id === rootId) continue;
      const p = pkgs.get(id), k = key(p), at = `${root} -> ${k}`;
      if (p.source === null) {
        if (!policy.local.includes(p.name)) errors.push(`${at}: local crate not allowed here`);
        continue;
      }
      reached.add(k);
      listing.push(`${root}\t${mode === "n" ? "runtime" : "build"}\t${k}\t${dirname(p.manifest_path)}`);
      if (p.source !== CRATES_IO) errors.push(`${at}: non-crates.io source ${p.source}`);
      if (!(k in policy.allow)) errors.push(`${at}: not in allowlist (${mode === "n" ? "runtime" : "build-time"})`);
      else if (policy.allow[k] === "b" && mode === "n") errors.push(`${at}: allowlisted build-only but linked at runtime`);
      if (p.targets.some((t) => t.kind.includes("custom-build")) && !BUILD_RS_ALLOW.has(p.name)) errors.push(`${at}: unreviewed build.rs`);
      if (p.targets.some((t) => t.kind.includes("proc-macro"))) errors.push(`${at}: proc-macro (curve25519-dalek-derive means the serial backend cfg is missing)`);
      const bad = (FORBIDDEN_FEATURES[p.name] ?? []).filter((f) => nodes.get(id).features.includes(f));
      if (bad.length) errors.push(`${at}: forbidden features ${bad.join(",")} (workspace-unified)`);
    }
    for (const k of Object.keys(policy.allow)) if (!reached.has(k)) errors.push(`${root}: ${k} allowlisted but not reached (prune or fix phase)`);
    if (!errors.some((e) => e.startsWith(root))) ok.push(`${root} deps check OK: ${reached.size} crates (${TARGET})`);
  }
  return { errors, ok, listing };
}

function loadMetadata(argv) {
  const file = argv.indexOf("--metadata");
  if (file >= 0) {
    if (!argv[file + 1]) throw new Error("--metadata needs a file");
    return JSON.parse(readFileSync(argv[file + 1], "utf8"));
  }
  const args = ["metadata", "--format-version", "1", "--locked", "--filter-platform", TARGET];
  if (argv.includes("--offline")) args.push("--offline");
  return JSON.parse(execFileSync("cargo", args, { encoding: "utf8", maxBuffer: 64 << 20, windowsHide: true }));
}

const firstLine = (error) => (error instanceof Error ? error.message.split("\n")[0] : "unknown");
const invokedPath = process.argv[1];
if (invokedPath !== undefined && resolve(invokedPath) === resolve(fileURLToPath(import.meta.url))) {
  let result;
  try {
    result = checkMetadata(loadMetadata(process.argv));
  } catch (error) {
    console.error(`deps check: cargo metadata failed: ${firstLine(error)}`);
    process.exit(2);
  }
  for (const line of result.ok) console.log(line);
  const phases = [...PHASES].join(",") || "evm";
  if (process.argv.includes("--list")) console.log(result.listing.join("\n"));
  if (result.errors.length) { console.error(`deps check FAILED (${TARGET}, phases: ${phases}):\n  ${result.errors.join("\n  ")}`); process.exit(1); }
  console.log(`deps check OK (${TARGET}, phases: ${phases})`);
}
```

`--filter-platform`은 필수다(없으면 오프라인에서 wasi 다운로드를 시도해 실패하고, 비Windows 의존까지 섞인다). 출처의 59줄 검사기(yw-core 단일 루트)를 다섯 루트·단계·멤버 규칙으로 확장한 것이다. 검사 본체는 `checkMetadata(meta)`(가져와도 CLI는 실행되지 않는다)이고, `scripts/check-core-deps.test.mjs`가 허용 목록과 정확히 같은 합성 그래프(통과)와 위반 종류별 변형(허용 목록 밖·빌드 전용의 런타임 링크·dev-dependency·자체 build.rs·금지 feature·crates.io 밖 출처·proc-macro·검토 안 된 build.rs·도달하지 않는 허용 항목·허용 안 된 로컬 크레이트·정책 없는/없는 멤버)과 `--metadata` CLI의 종료 코드 0·1·2를 cargo 없이 시험한다(script-test 단계).

### 4.3 `scripts/privacy-scan.mjs` 변경

기존 구조(인벤토리 = `git ls-files --cached --others --exclude-standard --deduplicate -z`, symlink 안전 읽기, 규칙 이름·건수만 출력, 인프라 실패는 고정 문구 + 종료 1)를 유지하고 다음만 바꾼다.

- `allowedExtensions`에서 `.cs` 삭제. 결과: `.html .js .json .md .mjs .ps1 .rs .toml .yml`.
- 규칙 표를 아래로 교체한다. `vectorsAllowed: true` 규칙은 `TEST_VECTOR_PATH`에 맞는 경로에서 건너뛴다.

```js
const TEST_VECTOR_PATH = /^(?:crates\/[^/]+\/tests\/|crates\/[^/]+\/src\/(?:[^/]+\/)*tests\.rs$|tools\/[^/]+\/tests\/|extension\/tests\/|scripts\/[^/]+\.test\.mjs$|spec\/)/u;
const BIP39_WORDS = new URL("../crates/yw-core/src/bip39/english.txt", import.meta.url); // 스캐너 자신의 저장소에서 읽는다
const forbidden = [
  { name: "private-key-assignment", vectorsAllowed: true, expression: /private[_-]?key\s*[:=]\s*["'][0-9a-f]{64}["']/iu },
  { name: "authorization-header", expression: /authorization\s*:\s*bearer\s+[a-z0-9._~-]{12,}/iu },
  { name: "seed-phrase-label", vectorsAllowed: true, expression: /(?:mnemonic|seed[_ -]?phrase)\s*[:=]\s*["'][a-z]+(?:\s+[a-z]+){11,23}["']/iu },
  { name: "production-secret-marker", expression: /\[(?:SECRET|PASSWORD|TOKEN|PRIVATE_KEY)\]/u },
  { name: "alchemy-key-url", expression: /\.g\.alchemy\.com\/v2\/[A-Za-z0-9_-]{16,}/u },
  { name: "quicknode-url", expression: /\.quiknode\.pro\/[A-Za-z0-9_-]{16,}/u },   // D13 템플릿: https://<이름>.<서브도메인>.quiknode.pro/<토큰>/
  { name: "llm-api-key", expression: /\bsk-[A-Za-z0-9_-]{20,}/u },
  { name: "labeled-private-key-hex", vectorsAllowed: true,
    expression: /(?:priv(?:ate)?|secret|signing)[_ -]?key[^\n]{0,80}?(?<![0-9A-Fa-f])(?:0x)?[0-9A-Fa-f]{64}(?![0-9A-Fa-f])/iu },
  { name: "bip39-word-sequence", vectorsAllowed: true, detect: (text, words) => {
      let run = 0, last = -1;   // 공백·따옴표·쉼표·대괄호로만 이어진 BIP39 단어 12개 이상
      for (const m of text.matchAll(/[a-z]+/gu)) {
        const joined = last >= 0 && /^[\s"',[\]]+$/u.test(text.slice(last, m.index));
        run = words.has(m[0]) ? (joined ? run + 1 : 1) : 0;
        last = m.index + m[0].length;
        if (run >= 12) return true;
      }
      return false; } },
];
```

- `scanRepository`는 규칙마다 `expression.test(text)` 또는 `detect(text, words)`를 적용한다. `words`는 `BIP39_WORDS`를 LF로 나눈 `Set`이며 2048개가 아니면 인프라 실패다. 결과 보고는 기존처럼 규칙 이름·건수만.
- 표시 없는 `0x`+64hex는 해시(tx·genesis·typehash)와 모양이 같아 검사하지 않는다. 키를 가리키는 이름이 같은 줄에 있을 때만 잡는다. `<KEY>`·`{KEY}`·`<토큰>`·`docs-demo` 같은 자리표시는 16자 미만이거나 문자 집합 밖이라 잡히지 않는다.
- 엔드포인트 URL 규칙은 D13 템플릿 두 공급자(알케미 경로 키, QuickNode 경로 토큰)의 모양만 잡는다. 다른 공급자의 토큰 URL은 잡지 못하므로 개발용 URL 파일은 저장소 밖에만 둔다(§4.6).
- 단어 목록 파일을 읽지 못하면 인프라 실패(종료 1).
- 테스트(`privacy-scan.test.mjs`) 추가: 새 규칙 5개(`alchemy-key-url`, `quicknode-url`, `llm-api-key`, `labeled-private-key-hex`, `bip39-word-sequence`) 각각 양성 1건, `<KEY>`·`<토큰>` 자리표시·`https://docs-demo.quiknode.pro/`·genesis 해시·영어 문장 음성, `crates/x/tests/v.rs`·`crates/x/src/m/tests.rs`·`tools/x/tests/v.rs`·`spec/02.md`의 벡터 면제, 비면제 경로의 벡터 검출. 픽스처 문자열은 기존처럼 조각을 이어 붙여 저장소 자체가 걸리지 않게 만든다. 기존 "retains all four forbidden source signatures"는 9개로, C# 하네스 테스트는 `.rs`로 바꾼다.
- 추가(L2 검토): 확장자에 `.txt .cmd .css .template`을 더한다(`crates/yw-core/src/bip39/english.txt`는 단어 목록 자체라 `bip39-word-sequence`에서만 제외). 규칙 4개를 더한다: `infura-project-id-url`(아무 호스트의 `/v3/` + 16진 32자, 뒤에 영숫자·`_`·`-`가 이어지지 않을 때), `api-key-query-value`(`api-key=`·`apikey=`·`api_key=`, 대소문자 무시; 값이 비었거나 `<…>`·`${…}`·`{…}`·`YOUR_`/`YOUR-`로 시작·`x` 3자 이상이면 자리표시), `email-address`(허용: 정확히 `noreply@anthropic.com`, `example.com`·`example.org`와 그 하위 도메인, 예약 TLD `.example`), `windows-profile-path`(`<드라이브>:\Users\<이름>`, `\`·`\\`·`/` 모두; 허용 이름: `<…>`, `%USERNAME%`, `$env:USERNAME`, `${env:USERNAME}`, `{user}`·`{name}`·`{username}`, `Public`·`Default`·`Default User`·`All Users`; `%USERPROFILE%`은 `Users`를 포함하지 않아 걸리지 않는다). 테스트 픽스처는 파일 + 정확한 값 단위로 명시 허용한다(통째 제외 없음).
- 따름 규칙: 니모닉·개인키가 든 테스트 값은 `crates/*/tests/**`(KAT·벡터 위치, [09](09-testing.md) §2.1), `crates/*/src/**/tests.rs`(`#[cfg(test)] mod tests;`), `tools/*/tests/**`(오라클, §2.1)에만 둔다. 같은 파일 안의 인라인 `mod tests`에는 두지 않는다.

### 4.4 `scripts/audit-extension.mjs` 이동

- `scripts/lib/strict-json.mjs` 생성: `archive/spec-v2.4:scripts/release/release-manifest.mjs:98-100`(한도 상수), `:144-150`(`fail`·`isPlainObject`, 오류 클래스는 `StrictJsonError`로 개명), `:152-158`(`decodeUtf8`), `:160-283`(`parseStrictJson`)을 옮긴다. 다른 함수는 옮기지 않는다.
- `audit-extension.mjs`: import를 `./lib/strict-json.mjs`로 바꾸고 `evidence` 명령, `canonicalEncode`, 해시 출력(`extensionManifestSha256`, `packageSourceTreeSha256`)을 지운다. `auditExtensionRoot`는 `{ packagedFiles }`만 반환하고 CLI는 `check --extension-root <dir>`만 받아 성공 시 `EXTENSION_STATIC_AUDIT_PASS`를 출력한다. 금지 패턴·manifest 계약은 M0에서 그대로 둔다.
- `audit-extension.test.mjs`: 첫 테스트의 해시 단언 삭제, 나머지 그대로.
- M5에서 manifest의 `key` 필드(D22)와 localhost matches를 추가할 때 `validateManifest`의 키 집합·`matches` 기대값을 같은 커밋에서 바꾼다. `key`가 있으면 확장 ID(= `SHA-256(base64 디코딩한 key)` 앞 16바이트를 hex로 쓰고 `0-f`를 `a-p`로 바꾼 32자)를 계산해 `EXTENSION_STATIC_AUDIT_PASS id=<id>`로 출력한다. 기대 `matches`는 [05](05-browser.md)의 manifest 정의와 같아야 한다.

### 4.5 M0 1회 음성 체크리스트 (검사가 실제로 막는지)

각 항목은 수정 → (Cargo.toml을 바꾼 경우 `cargo metadata --offline --format-version 1 --filter-platform x86_64-pc-windows-msvc > $null`로 lock 갱신) → `check.ps1 -Step <step> -Offline` → 기대 실패 확인 → `git checkout -- .`로 되돌린다(Cargo.lock 포함. 인덱스로 되돌리므로 M0 커밋 전에 하면 먼저 `git add -A`). 1–3은 임시 워크스페이스에서 같은 결과를 확인했다.

| # | 변경 | 기대 |
|---|---|---|
| 1 | yw-host에 `chacha20poly1305 = { workspace = true, features = ["getrandom"] }` | deps 21: 금지 feature, getrandom 0.2.17·rand_core 0.6.4 비허용, yw-host 폐포 위반 |
| 2 | yw-json에 `[dev-dependencies] zeroize.workspace = true` | deps 21: dev-dependencies 금지 |
| 3 | yw-core에 `qrcodegen.workspace = true`(lock은 yw-core 의존 목록 한 줄만 바뀜) | deps 21: `yw-core -> qrcodegen=1.8.0: not in allowlist (runtime)` |
| 4 | yw-core lib.rs에 `fn f() -> u8 { None.unwrap() }` | clippy 22 |
| 5 | `RUSTFLAGS=-Cdebuginfo=0` 설정 후 실행 | 11 |
| 6 | 비면제 `.rs`에 alchemy 키 모양 URL, 이어서 QuickNode 토큰 모양 URL(각각 따로) | privacy 27 |
| 7 | `extension/src/background.js`에 `eval("1")` | audit-ext 28 |

### 4.6 개발용 실서비스 RPC 설정 (D13)

- 개발 중 실서비스에 붙는 도구(프로브 §4.7, `#[ignore]` 실서비스 테스트·E2E [09](09-testing.md) §2.5·§5)는 엔드포인트 URL을 환경 변수 `YW_RPC_JSON`(설정 파일 경로)이 있으면 그 파일에서, 없으면 `%USERPROFILE%\.yw-dev\rpc.json`에서 읽는다. URL을 명령줄 인자·다른 환경 변수로 받지 않는다(프로세스 목록·셸 기록에 남는다).
- 형식: UTF-8 JSON 객체 하나, ≤ 64 KiB, 엄격 파싱(중복 키 거부; Node 도구는 `scripts/lib/strict-json.mjs`의 `decodeUtf8`·`parseStrictJson`). 키 = [02](02-core-keys-vault.md) §5.3 `NetworkId`(예 `eip155:1`, `eip155:11155111`, `eip155:999`, `solana:devnet`, `bitcoin:testnet4`), 값 = HTTPS JSON-RPC URL 전체(토큰 포함, `https://`만, ≤ 2048바이트, userinfo·fragment 없음 — yw-win `HttpsUrl`(§7.4)과 같은 규칙). 예: `{"eip155:1":"https://…","eip155:11155111":"https://…","eip155:999":"https://…"}`. 도구는 자기가 쓰는 키만 읽고 나머지는 무시한다.
- URL 전체가 비밀이다(D13). 출력·로그·오류 문구·`docs/acceptance/` 기록·커밋 메시지에는 URL·호스트·토큰 대신 `NetworkId`만 쓴다. 설정 파일 파싱·검증 오류도 고정 문구 + 키 이름만 출력한다(값·파서 메시지 출력 금지).
- 파일은 저장소 밖에 둔다. 도구는 설정 파일의 실제 경로(`realpath`)가 저장소 루트 아래이면 읽지 않고 실패한다. `%USERPROFILE%\.yw-dev\`는 저장소 밖이므로 `.gitignore` 변경은 없다. 저장소에 잘못 들어온 URL은 privacy scan(§4.3)이 알케미·QuickNode 모양만 잡는다.
- 제품 코드(yw-app·yw-host 실행 파일)는 이 파일·변수를 읽지 않는다. 앱의 엔드포인트는 `apikeys.dpapi`([04](04-app-ui.md) §6.3)뿐이다.

### 4.7 `scripts/probe-rpc.mjs` (수동 실서비스 프로브)

[03](03-evm.md) §1.3(네이티브 이동 로그)·§1.5(A1–A5, A9 (a)(b)(d))·D14(내장 체인 chainId·블록 0 해시)와 Solana·Bitcoin 엔드포인트 연결을 실제 공급자로 확인하는 사람용 도구다(구현 완료, 2026-10-27 실측 결과는 [03] §1.5·[08] §4.5). M2 전에, 그리고 공급자·엔드포인트를 바꿀 때 실행한다. 네트워크와 비밀이 필요하므로 `check.ps1` 단계가 아니고 `*.test.mjs`도 없다([09](09-testing.md) §1 규칙 4). Node 22, npm 의존성 0(`node:*`만), 전역 `fetch`.

- 실행: `node scripts/probe-rpc.mjs`. 설정은 §4.6. 설정 파일 실제 경로가 저장소 안이면 실패한다.
- EVM(`eip155:1`, `eip155:11155111`, `eip155:999`, 없는 키는 `skip`): `eth_chainId`, 블록 0 해시(1·11155111은 상수 비교, 999는 값만 출력), 최신 블록(base fee·gasLimit), `eth_simulateV1` 5회(블록 1개·호출 1개, `traceTransfers:true`, `validation:true`, `"latest"`, gas 1,000,000, maxFee = 2×baseFee + 1 gwei, tip 1 gwei; 발신자는 실행마다 새 무작위 주소이고 `stateOverrides`로 1 ETH를 넣는다): `sim fresh 1wei`(새 주소로 1 wei), `sim self 1wei`(자기 자신), `sim revert`(`stateOverrides`로 코드 `0x63deadbeef6000526004601cfd` = 4바이트 `0xdeadbeef` revert를 넣은 주소 호출), `sim no-funds`(잔액 0 발신자가 1 ETH 전송 → 최상위 오류 코드 확인), `sim chainId+type`(호출 객체에 `chainId`·`type 0x2` 포함). `eip155:999` URL이 `/evm`으로 끝나면 같은 검사를 `/nanoreth` 경로로 한 번 더 한다(`eip155:999/nano`).
- Solana(`solana:mainnet`, `solana:devnet`): `getGenesisHash` 비교. Bitcoin(`bitcoin:mainnet`, `bitcoin:testnet4`): `getblockhash 0` 비교, `getblockchaininfo.chain`, `bb_getBlockHash ["0"]`(Blockbook 애드온 활성 여부).
- 출력: 검사마다 한 줄 `<NetworkId> <검사 이름> ok|err key=value…`(예: `eip155:11155111 sim fresh 1wei ok status=0x1 gasUsed=204600 maxUsedGas=204600 logs=1 nativeEmitter=fffe …`), 마지막 줄 `summary: …`. 오류는 `http`·`code`와, URL의 호스트·경로 조각을 `[redacted]`로 바꾸고 URL 모양을 `[url]`로 바꾼 RPC 메시지 앞 80자만 보여준다. URL·호스트·토큰·예외 문자열은 출력하지 않는다.
- 종료 코드: 0 = 모든 검사 ok, 1 = 하나라도 err(설정 파일 없음 포함). `sim no-funds`는 최상위 오류가 기대값이므로 항상 err로 나오며, 판정은 사람이 [03] §1.5 표로 한다.
- 출력에는 비밀이 없으므로 그대로 `docs/acceptance/probe-<YYYYMMDD>.md`([09](09-testing.md) §2.5)에 붙여 기록한다.

### 4.8 `scripts/dev-rpc-setup.ps1` (개발용 RPC 설정 도우미)

§4.6의 `rpc.json`을 만드는 대화형 PowerShell 스크립트다(Windows PowerShell 5.1 호환, UTF-8 BOM). 실행: `powershell -NoProfile -ExecutionPolicy Bypass -File scriptsdev-rpc-setup.ps1`(직접 연 터미널에서).

- 입력: QuickNode 엔드포인트 이름(`https://<이름>.<체인>.quiknode.pro/<API 키>/`의 `<이름>`)과 API 키(`Read-Host -AsSecureString`, 화면에 표시 안 함). 이름 칸에 전체 URL을 붙여넣으면 이름·키를 뽑아 쓴다.
- 네트워크 7개(`eip155:1` 서브도메인 없음, `eip155:11155111` `ethereum-sepolia`, `eip155:999` `hype-mainnet` + `/nanoreth`, `solana:mainnet`·`solana:devnet`, `bitcoin:mainnet` `btc`, `bitcoin:testnet4` `btc-testnet4`)의 URL을 만들어 각각 한 번 호출로 확인(`eth_chainId` / `getGenesisHash` / `getblockhash 0`)한다. 실패한 네트워크는 대시보드 URL을 그 자리에서 붙여넣거나 건너뛴다. 확인된 것만 기존 파일에 병합해 저장한다(UTF-8, BOM 없음).
- URL·토큰은 출력하지 않는다. 결과 표는 `NetworkId`·이름·OK/실패만 보여준다.

## 5. 코딩 규칙

### 5.1 unsafe와 경계

- `unsafe`는 yw-win에만 있다. yw-core·yw-json·yw-app·yw-host는 workspace lint `unsafe_code = "forbid"`에 더해 `lib.rs`/`main.rs`에 `#![forbid(unsafe_code)]`를 둔다.
- yw-win은 FFI 모듈 파일 첫 줄에만 `#![allow(unsafe_code)]`를 두고, 모든 `unsafe` 블록에 `// SAFETY:` 주석(어떤 전제가 왜 성립하는지)과 블록당 unsafe 연산 1개(clippy `undocumented_unsafe_blocks`, `multiple_unsafe_ops_per_block`).
- yw-win 공개 API에 원시 `HANDLE`·`HWND`·포인터를 노출하지 않는다. 모든 핸들은 `Drop`에서 닫는 RAII 타입이다. `static mut` 금지(전역 상태는 atomic·`OnceLock`).
- yw-app은 windows-sys에 직접 의존하지 않는다. Win32 GUI 전체(클래스, wndproc, 루프, 그리기)는 yw-win의 안전 API다.
- `crates/yw-core/clippy.toml`(루트 clippy.toml 내용 + 아래)로 yw-core의 OS 접근을 lint로 막는다(확인함: yw-core에서만 오류, yw-app은 무관):
  ```toml
  disallowed-types = [ "std::time::Instant", "std::time::SystemTime", "std::fs::File", "std::fs::OpenOptions",
                       "std::net::TcpStream", "std::net::TcpListener", "std::net::UdpSocket", "std::process::Command" ]
  disallowed-methods = [ "std::thread::spawn", "std::env::var", "std::env::var_os", "std::fs::read",
                         "std::fs::write", "std::fs::read_to_string" ]
  ```

### 5.2 panic 금지와 오류

- `unwrap`·`expect`·`panic!`·`todo!`·`unimplemented!`·`dbg!`·`print*`·`std::process::exit`·`mem::forget`은 clippy deny. 예외: `#[test]` 함수와 `#[cfg(test)]` 모듈의 `unwrap`·`expect`(clippy.toml `allow-unwrap-in-tests`, `allow-expect-in-tests`). 통합 테스트의 도우미 함수는 `Result`를 반환한다.
- `main`은 `std::process::ExitCode`를 반환한다(소멸자가 돌아 비밀이 지워진다).
- pedantic lint를 개별로 끌 때는 항목 단위 `#[expect(clippy::<lint>, reason = "...")]`만 쓴다(사라지면 경고 → 실패).
- 오류는 모듈별 수동 enum + `impl Display` + `impl std::error::Error`. thiserror 등 매크로 크레이트 금지. 오류 값과 `Display`에 비밀·dApp/RPC 원문·URL·호스트·경로를 담지 않는다(고정 문구 + 숫자 코드, 대상 네트워크는 `NetworkId`).
- 파서(yw-json 전체, yw-core `bip39`·`bip32::xkey`·`codec::base58`·`vault`·`journal`(하위 모듈 포함)·`evm::{rlp, abi, decode, eip712}`·`sol::*`·`btc::*`)는 모듈 상단에 `#![deny(clippy::indexing_slicing)]`. 길이·금액 계산(yw-json, `evm::amount`, `btc` 수수료)은 `#![deny(clippy::arithmetic_side_effects)]`로 `checked_*`만 쓴다. release에도 `overflow-checks = true`이므로 남은 overflow는 abort(D28)다.

### 5.3 비밀 타입

`yw-core::secret`:

```rust
pub struct SecretBytes<const N: usize>(zeroize::Zeroizing<[u8; N]>);   // 키, 시드, DEK 복사본, 엔트로피
pub struct SecretVec(zeroize::Zeroizing<Vec<u8>>);     // 생성 시 용량 고정, 용량 초과 push는 오류(재할당 사본 방지)
pub struct SecretString(zeroize::Zeroizing<String>);   // 니모닉 문구, 비밀번호, API 키(같은 용량 규칙)
impl<const N: usize> SecretBytes<N> { pub fn new(src: &mut [u8; N]) -> Self /* src를 0으로 */; pub fn expose(&self) -> &[u8; N]; }
```

- `yw_core::secret`은 `pub use zeroize::{Zeroize, Zeroizing};`로 재수출한다. yw-app은 zeroize에 직접 의존하지 않고(D5) 이 재수출로 `Zeroizing<…>`을 쓴다. yw-core 공개 API는 `Zeroizing<…>`을 직접 반환해도 되고([02](02-core-keys-vault.md)) 위 래퍼를 써도 된다. 규칙은 같다.
- 래퍼는 `Clone`·`Copy`·`Display`·`PartialEq`·serde 계열을 구현하지 않는다. 비교는 `subtle::ConstantTimeEq`. `Debug`는 `SecretBytes<32>([REDACTED])`처럼 길이 외 정보를 출력하지 않는다.
- 비밀을 담은 일반 `[u8; N]`·`Vec`·`String` 지역 변수는 쓰고 난 즉시 `zeroize()`한다. 형 변환(UTF-16 ↔ UTF-8, hex 등)은 용량을 미리 정한 비밀 타입으로 직접 쓴다.
- yw-win은 zeroize를 쓸 수 없으므로 자체 `mem::wipe(&mut [u8])`/`wipe_u16`(`write_volatile` + `compiler_fence(SeqCst)`)과 `mem::WipeBuf`(용량 고정, Drop에서 wipe)를 쓴다. yw-win → yw-core 경계는 `with_secret(|bytes| …)` 클로저로 넘겨 yw-core 비밀 타입에 바로 복사한다.
- 잠금 해제 중 상주 지갑 비밀은 `yw_win::mem::LockedBox<320>` 하나(= [02](02-core-keys-vault.md) §7.3 `SLOT_LEN`, `LockedSlot` 배치: [0..32) DEK, `passphrase_used` vault이면 BIP39 passphrase)뿐이다(D10). RPC·LLM API 키는 지갑 비밀이 아니며 해당 작업 스레드가 `SecretString`으로 프로세스 수명 동안 보관할 수 있다(D10).

### 5.4 로깅 (D28)

- 파일 로그는 yw-app만 쓴다. 위치·순환·한 줄 형식·수준은 [04](04-app-ui.md) §8, yw-host는 [05](05-browser.md)가 정한다. yw-core·yw-json·yw-win은 로그를 쓰지 않고 오류 값만 돌려준다.
- 로그 API는 정적 이벤트 이름과 타입이 정해진 필드만 받는다(`format!`으로 만든 임의 문자열을 받지 않는다). 문자열 필드는 `&'static str` 또는 yw-app이 만든 값(`NetworkId`, 오류 코드)뿐이다.
- 비밀 타입은 `Display`가 없으므로 넘길 수 없다. 기록 금지: 비밀, API 키, **RPC 엔드포인트 URL 전체와 그 호스트 이름**(D13: URL 전체가 비밀이다. QuickNode 호스트 `<이름>.<서브도메인>.quiknode.pro`에는 엔드포인트 이름이, 경로에는 토큰이 들어 있고 다른 공급자도 같은 위험이 있다. RPC 대상은 [02](02-core-keys-vault.md) §5.3 `NetworkId`(예 `eip155:11155111`, `solana:devnet`)로만 기록한다), dApp·RPC·확장이 보낸 원문, origin, 파일 경로(사용자명 포함), 라벨·메모. LLM 엔드포인트(D21)는 RPC 엔드포인트가 아니므로 호스트만 허용([06](06-llm-explain.md) §8, 경로·쿼리 금지). 허용: 주소(D28), tx 해시, 체인 ID, `NetworkId`, 메서드 이름, 오류 코드, 소요 시간, 개수.
- 크래시 덤프·텔레메트리 업로드 없음. yw-app은 시작 시 `process::exclude_from_error_reporting()`(§7.6)을 호출한다(**권고**, 실패해도 계속).

### 5.5 기타

- 스레드: 창은 UI 스레드 하나가 소유한다. 작업 스레드(키, RPC, pipe)는 결과를 큐에 넣고 `ui::Poster::post(msg, 0)`으로 깨운다([04](04-app-ui.md) §1.2–1.3). 메시지 `wParam`에 포인터를 넣지 않는다.
- 비밀은 스레드 사이로 옮길 때 소유권 이동만 한다(복사 금지).
- 문자열 표시는 항상 [03](03-evm.md)·[04](04-app-ui.md)의 표시 문자 규칙을 거친다. GDI 텍스트는 `DT_NOPREFIX`로 그린다(§7.7).
- 테스트 벡터 위치: 니모닉·개인키를 포함한 벡터는 §4.3의 면제 경로에만 둔다. 공식 벡터 목록은 [09](09-testing.md).

---

## 6. 아카이브 이식 목록

| 출처 | 대상 | 필수 변경 |
|---|---|---|
| `archive/spec-v2.4:crates/secret-core/src/error.rs:4-53` | `yw-core::error`, `vault` 오류 | thiserror 제거·수동 `Display`; `DerivationExhausted` 삭제; 오답 비밀번호와 변조는 같은 `AuthenticationFailed`(유지) |
| `archive/spec-v2.4:crates/secret-core/src/storage.rs:5-51` | `yw-core::vault` 저장소 trait | generation CAS 의미 유지, 구현은 yw-app(`yw-win::file`) |
| `archive/spec-v2.4:crates/secret-core/src/mnemonic.rs:12-208,272-341` | `yw-core::bip39` | bip39 크레이트 호출(3, 67, 84-97, 126-140)을 자체 구현으로; `english.txt` 내장; 생성 24단어만(D9); 가져오기 형태 규칙은 `archive/spec-v2.4:demo/sepolia-wallet/src/wallet_secret.rs:739-751`; NFKD 제거(D8) |
| `archive/spec-v2.4:crates/secret-core/src/mnemonic.rs:210-270` | `yw-core::password::Bip39Passphrase` | NFKD 제거, 0x20–0x7E 0–256자(D8), 정확한 용량 검사 유지 |
| `archive/spec-v2.4:crates/secret-core/src/bip32.rs:12-225,273-298,392-426,448-544` | `yw-core::bip32` | invalid-child 건너뛰기(227-271, 300-389, 428-446, 테스트 500-515) 삭제 → `Err(DerivationFailed)`; 임의 경로(BIP84 포함) 일반화; 주소 계산은 `evm::address`로 |
| `archive/spec-v2.4:crates/secret-core/src/password.rs:8-155` | `yw-core::password::VaultPassword` | NFC·공백 매핑 제거, 0x20–0x7E 12–128자(D8), 테스트 재작성 |
| `archive/spec-v2.4:crates/secret-core/src/vault.rs:16-39,540-801,865-887,1100-1159` | `yw-core::vault` | v3 형식([02](02-core-keys-vault.md))으로 재설계. 헤더 AAD·정확한 파라미터 거부·`Cursor`·`fill_random_nonzero` 패턴만 재사용; v1 골든(1373-1413) 폐기 |
| `archive/spec-v2.4:crates/secret-core/src/vault.rs:41-65,159-197,433-484,933-994,1198-1351` | `yw-core::vault` 백업 확인 | 상태 기계·상수 시간 비교·집계 후 판정 유지; 단어 수·문항 수는 [02](02-core-keys-vault.md) |
| `archive/spec-v2.4:crates/secret-core/src/signing.rs:14-120,250-279` | `yw-core::evm::sign` | `wallet_protocol::AuthorizedOperation` → `approval::Approved`([03](03-evm.md) §11.5); `recovery_id ≤ 1` 유지 |
| `archive/spec-v2.4:crates/secret-core/src/signing.rs:122-248` | `yw-core::evm::rlp` | `encode_length`의 saturating/`unwrap_or` → 정확한 오류; type 0/1 인코딩은 [03](03-evm.md)이 정한 벡터 재현 범위만 |
| `archive/spec-v2.4:crates/wallet-model/src/bounded.rs:1-478` | `yw-core::{hex, evm::address, evm::amount}` | EIP-55: 전부 소문자·전부 대문자·체크섬 일치 혼합만 허용(354-360, 196-199, 241-243 수정, 테스트 455-462 반전); U256 연산 추가(`archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:4204-4363`, `rpc.rs:153-180`, `erc20.rs:49-107`) |
| `archive/spec-v2.4:crates/wallet-model/src/codec.rs:1-206` | `yw-core::codec` | 변경 없음 |
| `archive/spec-v2.4:crates/wallet-model/src/operation.rs:1-605` | `yw-core::evm::{tx, eip191, eip712}` | 운영 경로는 type 2만(D19); `schema_id` 제거; 한도 상수 유지 |
| `archive/spec-v2.4:crates/wallet-model/src/chain.rs:1-158` | `yw-core::evm::chain` | `ChainIdentity {chain_id, genesis_hash}`·`BlockAnchor`만, 나머지 삭제 |
| `archive/spec-v2.4:crates/wallet-model/src/context.rs:42-229,322-424` | `yw-core::policy` | `BrowserOrigin`·고정 길이 ID 유지; localhost 토글(D22); `SimulationProvenance`(427-484)는 이식하지 않는다 — 시뮬레이션 결과·결과 없음의 표현은 [03](03-evm.md) §6(D15) |
| `archive/spec-v2.4:crates/eip712/src/schema.rs:100-233,426-543` + `error.rs:4-91` | `yw-core::evm::eip712` | serde·`json.rs` 삭제, 입력은 `yw_json::Value`([03](03-evm.md) §8); schema exception(90-98, 186-208) → D17; 해시 코어 불변 |
| `archive/spec-v2.4:crates/eip712/tests/vectors.rs:1-371` | `crates/yw-core/tests/evm_eip712.rs` | Ether Mail 벡터 유지, 212-256은 D17에 맞게 수정 |
| `archive/spec-v2.4:crates/wallet-protocol/src/approval.rs:16-541,708-765` | `yw-core::approval` | digest에서 registry·ruleset·rpc_observations·protocol_validity 제거; 시뮬레이션은 필수 조건이 아니다(D15: 결과 없음·revert도 고위험 확인 후 승인, 바인딩은 [03](03-evm.md) §6.5·§11.4); platform 창 타입 → 호출자 `now_ms` |
| `archive/spec-v2.4:crates/wallet-protocol/src/authorization.rs:36-325,470-837,957-1370` | `yw-core::approval` + `evm::display` | chain_registry·ReleaseChannel 삭제(390-445, 657-665, 796-955); wei-hex → 10진 단위; 512/1023바이트 거부 → 스크롤 표시; typed data 허용(D17) |
| `archive/spec-v2.4:crates/wallet-protocol/src/nonce.rs:1-1317` | `yw-core::journal` | ChainIdentity 단순화; 확정 슬롯 정리(4096 수명 상한 제거); D20 |
| `archive/spec-v2.4:crates/wallet-protocol/src/validation.rs:35-441` | `yw-core::evm::tx` | type 2만, `to` 없음 거부, dApp 수수료 무시(D19·D20); schema allowlist 삭제 |
| `archive/spec-v2.4:crates/wallet-protocol/src/error.rs:5-178` | `yw-core::policy::ProviderError` | 4001/4100/4200/-32000/-32602/-32603 매핑과 고정 문구 유지 |
| `archive/spec-v2.4:crates/wallet-protocol/src/policy.rs:1-127` | 버림 | |
| `archive/spec-v2.4:crates/key-agent/src/lib.rs:118-272,274-389` | yw-app `flow::evm`(서명 흐름) + `evm::sign` | settings lease·전송 바인딩 삭제; "서명 전 저널 → 서명 → 서명 후 검증 → 반환 전 저널" 순서 유지 |
| `archive/spec-v2.4:crates/key-agent/src/lib.rs:391-905` | `yw-core::evm::{rlp, tx}` | 엄격 디코더(`MAX_RLP_DEPTH` 4)·필드별 재검증·sender 복구를 서명 후 필수 검사로 |
| `archive/spec-v2.4:crates/key-agent/src/lib.rs:907-1051` | `crates/yw-core/src/evm/sign/tests.rs`(단위 테스트, [09] §3.5) | EIP-155 공식 예제 등 그대로 |
| `archive/spec-v2.4:crates/key-agent/src/vault_session.rs:27-751,876-1188` | yw-app 세션 + `yw-core::vault` | offline deadline(321-611) 삭제; 2계정 고정 일반화; 24단어 |
| `archive/spec-v2.4:crates/key-agent/src/durable.rs:1-44,84-156,725-1231,1452-2283` | `yw-core::journal` | 키는 DEK에서 HKDF(D7); `WindowsGenerationStore`(285-461) → yw-app 파일 저장; 4096 상한 → 정리 |
| `archive/spec-v2.4:crates/broker/src/lib.rs:24-225,390-930,992-1066` | `yw-core::policy` + yw-app `browser` | [05](05-browser.md) §3.1의 27개 메서드·route(`eth_sign` 없음); 수명 상한 → LRU·속도 제한; `require_chain_signing_eligibility`(259-279) 삭제 |
| `archive/spec-v2.4:crates/broker/src/params.rs:1-829` | yw-app `browser::params` (yw-json) | 알려진 버그 8개 수정([05](05-browser.md)), 707-726 테스트 반전 |
| `archive/spec-v2.4:crates/native-host/src/lib.rs:81-225,444-572` | `yw-json::frame` (+ yw-host) | serde → yw-json; `_setmode` unsafe(46-79) 삭제 → `yw_win::process::{StdIn, StdOut}` |
| `archive/spec-v2.4:crates/native-host/src/wire.rs:21-49,600-1038,1041-1575` | yw-app `browser::envelope` | 요청 단위 오류(D23), `event` 인코더 추가, ReleaseAttestation 삭제 |
| `archive/spec-v2.4:crates/native-host/src/wire.rs:297-578`, `main.rs:9-23` | 버림 | 동기 dispatcher·4096 프레임 상한·종료 코드 78 → 전이중 중계 재작성 |
| `archive/spec-v2.4:crates/approval-ui/src/lib.rs:15-466,647-989` | yw-app `ui::interaction` | 순수 상태 기계와 테스트 그대로; 스트림 codec(477-506) 삭제 |
| `archive/spec-v2.4:crates/approval-ui/src/native.rs:40-1090` | yw-app `ui::approval` on `yw-win::ui` | windows → windows-sys(yw-win 내부); `PRESENTED`(59, 88-90) 삭제; 클래스 1회 등록; `PostQuitMessage`(1013-1016) → 앱 메시지; 모달 루프 → 앱 루프 |
| `archive/spec-v2.4:crates/approval-wire/src/lib.rs:231-777,1212-1300` | `yw-core::approval` 표시 모델 + `evm::display` | Genesis/Ruleset/RpcObservations 필수(616-631) 삭제; NotPerformed 차단(729-754) 삭제 → 시뮬레이션 결과 없음·revert를 고위험 경고로 표시(D15·D16); typed data·ERC-20·시뮬레이션 의미 추가; 금지 문자 규칙(1277-1300) 유지 |
| `archive/spec-v2.4:crates/approval-wire/src/lib.rs:57-229,779-1210` | 버림 | hello/finish·wire codec |
| `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs:118-249,342-470` | `yw-win::ui::secure_text` | ASCII 정책별 입력(§7.7), 표시용 UTF-16 사본 즉시 wipe |
| `archive/spec-v2.4:crates/secret-input-ui/src/recovery_native.rs:615-679,1453-1607` | `yw-win::ui` 비밀 창 모드 | 숨긴 상태에서 캡처 제외 + 읽기 확인, 차단 메시지 목록 그대로; 실패 처리는 `ClassSpec.capture`(§7.7)로 분기; `PRESENTED`(69, 596-598) 삭제 |
| `archive/spec-v2.4:crates/secret-input-ui/src/lib.rs:18-73,472-572` | 참고만 | CredUI 쓰지 않음(D11: 직접 그림; CredUI 창은 캡처 제외 불가) |
| `archive/spec-v2.4:demo/sepolia-wallet/src/rpc.rs:866-1218,1228-1464,1981-2129` | yw-app `rpc`(공용 전송, `rpc/mod.rs`) | ureq → `yw-win::http`, serde → yw-json; id 카운터; 미지 필드 허용 |
| `archive/spec-v2.4:demo/sepolia-wallet/src/rpc.rs:491-856,2132-3760` | yw-app `rpc::evm` | 알케미 전용 URL 조립 → 네트워크별 엔드포인트 URL(D13: `apikeys.dpapi`의 `rpc:eip155:<chainId>`, 공급자 템플릿, [04](04-app-ui.md) §6.3); 메인넷 genesis 하나 → 등록된 체인마다 고정 genesis(내장 1·11155111은 상수, 999와 사용자 체인은 처음 연결·추가 시 고정, D14, [03](03-evm.md) §1); 한도는 [03](03-evm.md); 테스트는 가짜 transport |
| `archive/spec-v2.4:demo/sepolia-wallet/src/erc20.rs:1-583` | `yw-core::evm::{abi, decode, amount}` | 로직 그대로, 체인 매개변수화 |
| `archive/spec-v2.4:demo/sepolia-wallet/src/receive_qr.rs:1-262` | yw-app `ui::qr` + `evm::address` | egui 그리기(170-221) → `PaintDc::fill_rect`; 체인 ID 매개변수 |
| `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:5228-5410,6148-6403` | `yw-win::file` | create_new → 쓰기 → FlushFileBuffers → MoveFileExW → 부모 flush 패턴 |
| `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:6554-6773` | `evm::amount` + 수수료 정책 | Sepolia 데모 상한(75-83) 삭제, 정책은 [03](03-evm.md) |
| `archive/spec-v2.4:demo/sepolia-wallet/src/wallet_secret.rs:864-1176` | `crates/yw-core/src/{bip39,bip32,evm/address}/tests.rs`([09] §3.2–3.4) | 벡터 그대로 + Trezor BIP39 벡터([09](09-testing.md)) |
| `archive/spec-v2.4:demo/sepolia-wallet/src/vault_v2.rs:22-74` | 참고만 | HKDF 하위 키 info 분리, 테스트 전용 축소 KDF 파라미터 패턴 |
| `archive/spec-v2.4:crates/platform-windows/src/broker_channel.rs:505-558,704-760,889-918` | 참고만(`yw-win::pipe`) | SDDL·생성 플래그 대조용 |
| `archive/spec-v2.4:extension/` | `extension/`(그대로 유지) | M0: `tests/native-host-process.test.mjs`만 삭제; 버그·`key`·localhost는 M5([05](05-browser.md)) |
| `archive/spec-v2.4:scripts/release/audit-extension.mjs:1-225`, `release-manifest.mjs:98-283` | `scripts/audit-extension.mjs`, `scripts/lib/strict-json.mjs` | §4.4 |
| `scripts/privacy-scan.mjs:1-219`, `scripts/privacy-scan.test.mjs:1-243` (main 판, 유지 파일) | 같은 경로 | §4.3 |
| `archive/spec-v2.4:docs/protocol-contract.md:874-1313` | [05](05-browser.md) 참고 | |

---

## 7. yw-win 안전 API

공통: `pub struct WinError { pub api: &'static str, pub code: u32 }`(Debug·Clone·Copy·Eq, `Display` = `"<api> failed: 0x<code:08X>"`). 실패 시 `GetLastError()`를 즉시 읽고 `FormatMessageW`는 쓰지 않는다. 문자열 인자는 내부에서 NUL 종료 UTF-16으로 바꾸며 내부 NUL은 오류다. 공개 API에는 원시 핸들·포인터가 없고 모든 핸들은 `Drop`에서 닫는다. `lib.rs`는 `pub use error::WinError; pub use process::{current_user_sid_string, spawn_detached, allow_set_foreground_window, StdIn, StdOut};`로 [05](05-browser.md) §7.8의 경로를 그대로 제공한다(M3는 `WinError`·`allow_set_foreground_window`만; `pipe`와 나머지 재수출은 M5에서 추가).

feature 사용처: Foundation(핸들·오류·`LocalFree`), Graphics_Gdi(그리기), Networking_WinHttp(`http`), Security(`SECURITY_ATTRIBUTES`, `GetTokenInformation`, `CreateFileW`·`CreateNamedPipeW` 게이트), Security_Authorization(SDDL·SID 문자열), Security_Cryptography(DPAPI), Storage_FileSystem(`file`, 파이프 플래그, `GetFileType`), System_Console(`GetStdHandle`), System_DataExchange(클립보드), System_ErrorReporting(`WerAddExcludedApplication`), System_IO(`OVERLAPPED`, `GetOverlappedResult`, `CancelIoEx`), System_LibraryLoader(`GetModuleHandleW`, `SetDefaultDllDirectories`), System_Memory(`Virtual*`, `Global*`), System_Ole(`CF_UNICODETEXT`), System_Pipes, System_RemoteDesktop(`WTSRegisterSessionNotification`), System_SystemInformation(`GetTickCount64`, `GetTickCount`), System_Threading(뮤텍스·이벤트·`CreateProcessW`·`OpenProcessToken`), UI_Controls(`InitCommonControlsEx`), UI_HiDpi, UI_Input(`GetCurrentInputMessageSource`), UI_Input_KeyboardAndMouse(`GetAsyncKeyState`, `GetKeyState`, `GetLastInputInfo`, `SetCapture`), UI_WindowsAndMessaging(창·메시지·`SetWindowDisplayAffinity`·`AllowSetForegroundWindow`, `WTS_*` 세션 변경 값·`WM_QUERYENDSESSION`·`WM_ENDSESSION`도 여기에 있다(확인함), 따라서 §7.7 `Msg` 추가에 feature 변경 없음).

### 7.1 `time`, `mem`

```rust
pub fn monotonic_ms() -> u64;      // GetTickCount64. yw-core에 넘기는 now_ms의 출처
pub fn system_idle_ms() -> Option<u64>;   // GetTickCount().wrapping_sub(LASTINPUTINFO.dwTime) (32비트 감김 처리). GetLastInputInfo 실패 → None:
                                           // 호출자는 앱 자체의 마지막 입력 시각으로 대신한다(0을 돌려주면 유휴 잠금이 영영 안 걸린다)
pub fn local_wall_ms(unix_ms: u64) -> Option<u64>;   // FileTimeToLocalFileTime(현재 표준시간대 편차): 표시용 현지 시각(활동 행, [04] §2.6)

pub struct LockedBox<const N: usize> { /* 페이지 1개; const 단언 1 ≤ N ≤ 4096; Send + Sync; Clone 없음 */ }   // yw-app: LockedBox<320> = [02] §7.3 슬롯
impl<const N: usize> LockedBox<N> {
    pub fn new_zeroed() -> Result<Self, WinError>;  // VirtualAlloc(4096, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) → VirtualLock
    pub fn expose(&self) -> &[u8; N];
    pub fn expose_mut(&mut self) -> &mut [u8; N];
}   // Drop: 4096바이트 wipe → VirtualUnlock → VirtualFree(MEM_RELEASE). Debug: "LockedBox<N>([REDACTED])"
pub fn wipe(buf: &mut [u8]);       // write_volatile + compiler_fence(SeqCst)
pub fn wipe_u16(buf: &mut [u16]);
pub struct WipeBuf<T: Copy + Default> { /* 용량 고정 Vec<T>, 초과 push는 Err, Drop에서 wipe */ }
```

`VirtualLock` 실패(예: `ERROR_WORKING_SET_QUOTA`)는 `Err`로 돌려주고 대체 경로를 두지 않는다. 처리는 [02](02-core-keys-vault.md).

### 7.2 `file`, `dpapi`

```rust
pub enum FileError { NotFound, ReparsePoint, TooLarge, Os(WinError), Io(std::io::ErrorKind) }
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), FileError>;         // bytes ≤ 64 MiB
pub enum AtomicWrite { Durable, DirFlushFailed(FileError) }                      // 교체는 끝남; DirFlushFailed = 경고
pub fn atomic_write_detailed(path: &Path, bytes: &[u8]) -> Result<AtomicWrite, FileError>;   // 아래 (5) 실패를 경고로 구분
pub fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>, FileError>;        // 크기 > max → TooLarge
pub fn read_limited_no_reparse(path: &Path, max: u64) -> Result<Vec<u8>, FileError>; // 재분석 지점이면 ReparsePoint(따라가지 않음):
                                                                                  // symlink_metadata 확인 후 FILE_FLAG_OPEN_REPARSE_POINT로
                                                                                  // 열어 핸들 속성을 다시 확인하고 읽는다(검토 L8). vault·meta·
                                                                                  // journal(+.prev)·settings.json·apikeys.dpapi 읽기에 쓴다
pub fn ensure_dir(path: &Path) -> Result<(), FileError>;                         // create_dir_all, 재분석 지점 거부
// atomic_write의 단계를 yw-app VaultStorage([02] §6.2 커밋 1–6단계)가 따로 쓰도록 공개한다(M3):
pub fn tmp_path(path: &Path) -> PathBuf;                                          // <target>.tmp
pub fn reject_reparse_point(path: &Path) -> Result<(), FileError>;                // 아래 (1)
pub fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), FileError>;     // 아래 (3)
pub fn replace_file(from: &Path, to: &Path) -> Result<(), FileError>;            // 아래 (4)
pub fn rename_no_replace(from: &Path, to: &Path) -> Result<(), FileError>;       // MoveFileExW(WRITE_THROUGH), 대상이 있으면 실패
pub fn flush_dir(dir: &Path) -> Result<(), FileError>;                           // 아래 (5)
pub fn protect(plain: &[u8], entropy: &[u8]) -> Result<Vec<u8>, WinError>;        // dpapi, plain ≤ 1 MiB
pub fn unprotect(blob: &[u8], entropy: &[u8]) -> Result<WipeBuf<u8>, WinError>;   // dpapi
```

- `atomic_write`(spec.md §4.3): (1) 부모 디렉터리·대상이 재분석 지점(`symlink_metadata` + `FILE_ATTRIBUTE_REPARSE_POINT`)이면 `ReparsePoint` → (2) 남은 `<target>.tmp` 삭제 → (3) `OpenOptions::create_new`, 공유 0으로 열어 `write_all` → `sync_all`(= `FlushFileBuffers`) → 닫기 → (4) `MoveFileExW(tmp, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)` → (5) 부모 디렉터리 자체를 `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`·`GENERIC_WRITE`로 열어(재분석 지점은 따라가지 않고 그 자체를 연다 → 속성에 `FILE_ATTRIBUTE_REPARSE_POINT`가 있으면 `ReparsePoint`) `FlushFileBuffers`. (3)–(4) 실패 시 임시 파일 삭제를 시도하고 원래 오류를 돌려준다. (4)가 성공한 뒤 (5)만 실패하면 새 내용은 이미 제자리에 있으므로 `atomic_write`는 `Ok(())`, `atomic_write_detailed`는 `Ok(AtomicWrite::DirFlushFailed(e))`(경고: 정전 시 이름 바꾸기가 아직 디스크에 없을 수 있음)다. 임시 파일은 항상 같은 디렉터리(같은 볼륨)다.
- DPAPI: `CryptProtectData`/`CryptUnprotectData`, 현재 사용자 범위(`CRYPTPROTECT_LOCAL_MACHINE` 없음), `CRYPTPROTECT_UI_FORBIDDEN`, 설명·prompt NULL. 출력 버퍼는 복사 → `wipe` → `LocalFree`. `entropy` 값은 [04](04-app-ui.md).

### 7.3 `clipboard`

```rust
pub enum ClipError { Busy, TooLong, Os(WinError) }
pub fn set_text(owner: &ui::Window, text: &str) -> Result<(), ClipError>;               // 비밀 아님(주소 등), ≤ 4096자
pub fn set_secret_text(owner: &ui::Window, text: &[u16]) -> Result<u32, ClipError>;     // ≤ 4096단위, 반환 = 설정 직후 순번
pub fn read_text(owner: &ui::Window, max_units: usize) -> Result<(WipeBuf<u16>, u32), ClipError>;  // (내용, 순번)
pub fn clear_if_unchanged(owner: &ui::Window, seq: u32) -> Result<bool, ClipError>;     // 순번이 같을 때만 비움
```

- 공통: `OpenClipboard(owner)`(20 ms 간격 5회, 실패 시 `Busy`) … `CloseClipboard`. 텍스트는 `GlobalAlloc(GMEM_MOVEABLE)` 메모리에 UTF-16으로 직접 쓰고 `SetClipboardData(CF_UNICODETEXT = 13)`.
- `set_secret_text`: `EmptyClipboard` → `RegisterClipboardFormatW`로 얻은 `ExcludeClipboardContentFromMonitorProcessing`, `CanIncludeInClipboardHistory`, `CanUploadToCloudClipboard`에 각각 DWORD 0 → 마지막에 텍스트 → `GetClipboardSequenceNumber()`(클립보드를 연 채로 읽는다: 닫은 직후 다른 프로세스가 복사하면 그 순번을 잡아 남의 내용을 지울 수 있다) → `CloseClipboard` → 그 순번 반환. 제외 형식 하나라도 실패하면 텍스트 없이 `EmptyClipboard` 후 오류. `SetClipboardData`가 실패하면(소유권이 넘어가지 않음) 블록을 잠가 0으로 지운 뒤 `GlobalFree`.
- `read_text`: `GlobalSize`가 0(실패 또는 빈 블록)이면 텍스트 없음, NUL은 처음 `max_units + 1`단위까지만 찾는다(그 안에 없고 블록이 더 길면 `TooLong`).
- 자동 삭제(D11 30초)는 yw-app 타이머가 `clear_if_unchanged(owner, seq)`로 한다. 순번이 다르면(사용자가 이후 다른 것을 복사) 건드리지 않는다. 잠금·종료 때도 같은 호출([04](04-app-ui.md)).
- 시스템이 해제한 GlobalAlloc 메모리는 지워지지 않는다(§2.2 범위 밖).

### 7.4 `http`

```rust
pub struct HttpsUrl { /* 원문 */ }      // Debug/Display: "https://[redacted]" (호스트·경로·쿼리 모두 숨김 — RPC URL 전체가 비밀, D13)
impl HttpsUrl { pub fn parse(s: &str) -> Result<Self, HttpError>;
                pub fn host(&self) -> &str; }   // LLM 엔드포인트 표시·로그([06] §2.2·§6·§8) 전용. RPC 엔드포인트에는 쓰지 않는다(§5.4)
pub struct LoopbackUrl { /* 원문 */ }   // Debug/Display: "http://<host>[:port]/…"
impl LoopbackUrl { pub fn parse(s: &str) -> Result<Self, HttpError>; }
pub enum EndpointUrl { Https(HttpsUrl), Loopback(LoopbackUrl) }   // LLM 엔드포인트(D21). RPC는 HttpsUrl만(D13)
impl EndpointUrl { pub fn parse(s: &str) -> Result<Self, HttpError>; }   // scheme으로 분기
pub struct Timeouts { pub resolve_ms: u32, pub connect_ms: u32, pub send_ms: u32, pub receive_ms: u32 }  // Default 없음
pub struct Response { pub status: u16, pub content_type: Option<String>, pub body: Vec<u8> }
pub enum HttpError { InvalidUrl, InvalidHeader, Timeout, Tls, TooLarge, Os(WinError) }
pub struct Client { /* 세션 핸들 + 종류(Https | Loopback); Send + Sync */ }
impl Client {
    pub fn new(timeouts: Timeouts) -> Result<Self, HttpError>;            // HTTPS 전용
    pub fn new_loopback(timeouts: Timeouts) -> Result<Self, HttpError>;   // loopback http 전용
    pub fn post(&self, url: &EndpointUrl, headers: &[(&str, &str)], body: &[u8], max_response: usize) -> Result<Response, HttpError>;
    pub fn post_json(&self, url: &HttpsUrl, bearer: Option<&[u8]>, body: &[u8], max_response: usize) -> Result<Response, HttpError>;
    pub fn get(&self, url: &HttpsUrl, max_response: usize) -> Result<Response, HttpError>;
}
```

- `HttpsUrl`: `https://`만(스킴은 대소문자 무관, 정규형은 소문자), host `[a-z0-9.-]{1,253}`(소문자화) 또는 대괄호 IPv6 리터럴(`[` hex·`:`(`::` 한 번)·선택 점 IPv4 꼬리 `]`, zone id `%` 없음, 소문자화, `WinHttpConnect`에는 대괄호 없이 — 루프백 `[::1]`과 같은 경로; 보안 검토 S16), 포트 1–65535 선택, 경로는 `/`로 시작하는 출력 가능 ASCII(공백 없음), 전체 ≤ 2048바이트, userinfo·fragment 거부. `LoopbackUrl`: `http://`만, host는 `127.0.0.1`·`localhost`(소문자화)·`[::1]`(IPv6 리터럴) 중 하나, 포트·경로·길이·거부 규칙은 `HttpsUrl`과 같다. 클라이언트 종류와 URL 종류가 다르면 `InvalidUrl`.
- 세션: `new`는 `WinHttpOpen("YourWallet/3", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, NULL, NULL, 0)`(동기)이고 `WINHTTP_OPTION_SECURE_PROTOCOLS = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3` 설정이 실패하면 `new` 실패. `new_loopback`은 `WINHTTP_ACCESS_TYPE_NO_PROXY`. 공통: `WINHTTP_OPTION_REDIRECT_POLICY = WINHTTP_OPTION_REDIRECT_POLICY_NEVER`, `WinHttpSetTimeouts`, `WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE = 16384`. LLM은 RPC와 다른 `Client`(세션)를 쓴다([06](06-llm-explain.md) §4.1).
- 시간 제한(Default 없음, 호출자가 정함): RPC([03](03-evm.md) §1.4, 07·08 공용) `Timeouts { 5000, 5000, 10000, 10000 }`, LLM `Timeouts { 10000, 10000, 10000, 10000 }`. WinHTTP 값은 단계별(수신은 읽기 한 번마다)이므로, 요청마다 전체 기한 = 네 값의 합(RPC 30 s, LLM 40 s)을 두고 본문 읽기 반복이 그것을 넘지 않게 한다: 읽기마다 남은 시간을 확인해 지났으면 `Timeout`, 다음 읽기의 `WINHTTP_OPTION_RECEIVE_TIMEOUT`을 `min(receive_ms, 남은 시간)`으로 줄인다(바이트를 조금씩 흘리는 서버가 요청을 무한히 붙잡지 못한다). 앞 단계도 같은 기한 안에 둔다: `WinHttpSendRequest` 전에 요청 핸들에 `WinHttpSetTimeouts(min(resolve_ms, 남은), min(connect_ms, 남은), min(send_ms, 남은), min(receive_ms, 남은))`, `WinHttpReceiveResponse` 전에 다시 `WinHttpSetTimeouts`(남은 시간 기준)와 `WINHTTP_OPTION_RECEIVE_RESPONSE_TIMEOUT = min(receive_ms, 남은 시간)`(기본 90 s이고 `WinHttpSetTimeouts`가 바꾸지 않는다). 각 값은 최소 1 ms, 기한이 이미 지났으면 단계를 시작하지 않고 `Timeout`, 설정 실패는 요청 실패다. 호출자는 여전히 자기 기한(03 호출당 10 s, 06 `REQUEST_DEADLINE_MS`)을 넘겨 돌아온 결과를 `Timeout`으로 보고 버린다.
- 요청: HTTPS만 `WINHTTP_FLAG_SECURE`(loopback은 없음). `WINHTTP_OPTION_DISABLE_FEATURE = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_REDIRECTS | WINHTTP_DISABLE_AUTHENTICATION`. `post`는 호출자 헤더만 보낸다(이름 `^[A-Za-z0-9-]{1,64}$`, 값 0x20–0x7E ≤ 4096바이트, 위반은 `InvalidHeader`). `post_json`·`get`은 같은 내부 경로의 래퍼다: `Accept: application/json`, POST에 `Content-Type: application/json`, `bearer`가 있으면 `Authorization: Bearer <값>`. 헤더 버퍼는 `WipeBuf<u16>`. Origin 헤더 없음(D13). `SECURITY_FLAG_IGNORE_*` 금지. 인증서 폐기 확인(`WINHTTP_OPTION_ENABLE_FEATURE = WINHTTP_ENABLE_SSL_REVOCATION`)은 켜지 않는다: CRL/OCSP 응답자에 닿지 못하는 네트워크(캡티브 포털, 필터링, 공급자 쪽 장애)에서 TLS 핸드셰이크 자체가 실패해 RPC·LLM이 모두 막히기 때문이다. 체인 검증은 그대로다.
- 응답: 상태 코드(`WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER`)와 `WINHTTP_QUERY_CONTENT_TYPE`(없거나 256바이트 초과·비ASCII면 `None`)를 그대로 돌려준다. `Content-Length` 또는 누적 읽기가 `max_response`(≤ 16 MiB)를 넘으면 본문을 더 읽지 않고 즉시 `TooLarge`. 요청 본문 ≤ 1 MiB. `ERROR_WINHTTP_TIMEOUT`(12002) → `Timeout`, `ERROR_WINHTTP_SECURE_FAILURE`(12175) → `Tls`. 오류에 URL·호스트를 넣지 않는다. 호출자(yw-app RPC 계층)는 RPC 실패를 로그·화면 오류에 `NetworkId`·메서드 이름·`HttpError` 종류·HTTP 상태로만 남긴다(§5.4, D13).
- `[::1]`은 `WinHttpConnect`에 대괄호 없이(`::1`) 넘긴다(구현 시 확인, §8-3).

### 7.5 `pipe`

```rust
pub fn wallet_pipe_name(user_sid: &str) -> String;   // r"\\.\pipe\YourWallet.v3." + sid (D24)
pub fn user_only_sddl(user_sid: &str) -> String;     // "O:" + sid + "D:P(A;;GA;;;" + sid + ")"
pub enum ServerError { AlreadyExists, Os(WinError) }
pub struct Server { /* 대기 인스턴스, 활성 연결 수(Arc 카운터) */ }
impl Server {
    pub fn create(name: &str, sddl: &str) -> Result<Self, ServerError>;
    pub fn accept(&mut self) -> Result<Duplex, ServerError>;            // 블록
}
pub enum ConnectError { NotFound, Busy, Other(u32) }
pub fn connect_client(name: &str) -> Result<Duplex, ConnectError>;
pub fn wait(name: &str, timeout_ms: u32) -> bool;                       // WaitNamedPipeW
pub struct Duplex { /* overlapped 핸들 */ }
impl Duplex {
    pub fn split(self) -> (PipeReader, PipeWriter);                     // PipeReader: Read + Send, PipeWriter: Write + Send
    pub fn server_pid(&self) -> Option<u32>;                            // GetNamedPipeServerProcessId
    pub fn client_pid(&self) -> Option<u32>;                            // GetNamedPipeClientProcessId
    pub fn owner_sid(&self) -> Result<String, WinError>;                // GetSecurityInfo(handle, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION)
    pub fn owned_by_current_user(&self) -> bool;                        // owner_is(owner_sid(), current_user_sid_string())
}
pub fn owner_is(owner: Result<String, WinError>, expected: Result<String, WinError>) -> bool;   // 둘 다 Ok, 비어 있지 않음, 같음
impl PipeReader { pub fn cancel_handle(&self) -> PipeCanceller; }       // PipeCanceller: Send, cancel() = CancelIoEx
// M5 추가: yw-app 종료 시 accept를 멈추는 정지 핸들과 R-P2(DACL 확인)용 보안 요약
// ServerError::Stopped; impl Server { pub fn stop_handle(&self) -> ServerStop /* Clone + Send + Sync, stop() */;
//   pub fn security_summary(&self) -> Result<SecuritySummary, WinError>; } // GetSecurityInfo: owner SID, protected, ACE 목록(type, mask, SID)
```

- `Server::create`: SDDL → `ConvertStringSecurityDescriptorToSecurityDescriptorW`(`bInheritHandle = FALSE`, `LocalFree`로 해제). 첫 인스턴스 `CreateNamedPipeW(name, PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 4, 65536, 65536, 1000, &sa)`. `ERROR_ACCESS_DENIED` → `AlreadyExists`(다른 yw-app 또는 선점). 수치·처리는 [05](05-browser.md) §8.1과 같다.
- `accept`: 대기 인스턴스에 `ConnectNamedPipe`(overlapped, `ERROR_PIPE_CONNECTED`도 성공). 연결되면 활성 연결 수 < 4일 때 `FILE_FLAG_FIRST_PIPE_INSTANCE`만 뺀 같은 인자로 다음 대기 인스턴스를 만든 뒤 `Duplex`를 돌려준다. 4개가 모두 연결 중이면 하나가 닫힐(`Duplex` 양쪽 반이 drop) 때까지 기다렸다가 만든다. 이름이 사용자마다 고정이라, 우리 인스턴스가 모두 닫힌 사이 다른 사용자가 같은 이름으로 파이프를 만들면 첫 인스턴스 플래그 없는 다음 인스턴스가 그 파이프에 붙는다. 그래서 `create`는 첫 인스턴스의 보안 요약(소유자·DACL 보호·ACE)을 읽어 두고, 이후 인스턴스마다 같은 요약인지 확인한다(보안 설명자는 파이프 단위로 공유된다). 다르면 그 인스턴스를 닫고 `AlreadyExists`(yw-app은 경고 로그 후 재시도).
- `connect_client`: `CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, NULL)`. `ERROR_FILE_NOT_FOUND` → `NotFound`, `ERROR_PIPE_BUSY` → `Busy`(호출자가 `wait` 후 재시도), 그 밖 → `Other(code)`.
- 서버 소유자 확인: 클라이언트 핸들의 `owner_sid()`는 서버가 파이프에 준 소유자다(`GENERIC_READ`에 `READ_CONTROL` 포함). 다른 사용자의 프로세스는 소유자를 이 사용자 SID로 둘 수 없으므로(`SeRestorePrivilege` 필요) 이름을 선점한 파이프를 가려낸다. yw-host는 hello를 보내기 전에 `owner_is(owner_sid(), current_user_sid_string())`가 아니면 연결을 버리고 UNAVAILABLE(요청마다 4900)로 간다([05](05-browser.md) §8.1). yw-app의 SDDL(`O:<SID>`)은 관리자 권한으로 실행돼도 소유자를 사용자 SID로 둔다.
- 서버 프로세스 확인: 같은 사용자의 Low 무결성 프로세스는 소유자 확인을 통과하는 파이프를 만들 수 있으므로, yw-host는 이어서 `server_pid()`(`GetNamedPipeServerProcessId`)를 `security::verify_process(pid, <yw-host 폴더>\yw-app.exe)`로 확인하고(§7.6) 실패하면 마찬가지로 hello 없이 UNAVAILABLE로 간다. 검증된 pid만 `allow_set_foreground_window`에 넘긴다.
- 모든 I/O는 overlapped(호출마다 `OVERLAPPED` + 수동 리셋 이벤트, `GetOverlappedResult(wait = TRUE)`): 동기 핸들에서는 대기 중인 `ReadFile`이 다른 스레드의 `WriteFile`을 막아(동기 파일 객체 직렬화) 전이중 중계가 불가능하다. 한 핸들을 두 반쪽이 공유하고(`Arc`), 마지막 반쪽이 drop될 때 `CloseHandle`만으로 닫는다: `DisconnectNamedPipe`는 상대가 아직 읽지 않은 데이터(예: 마지막 hello-reject)를 버리므로, 클라이언트가 연결 완료 전에 떠난 인스턴스를 다시 쓸 때만 부른다. `ERROR_BROKEN_PIPE`·`ERROR_PIPE_NOT_CONNECTED`·0바이트 읽기는 `Read`의 EOF(`Ok(0)`). `PipeCanceller::cancel` 뒤에는 대기 중인 읽기·쓰기가 `ERROR_OPERATION_ABORTED`로 끝나고, 이후 읽기·쓰기는 시작하지 않고 같은 오류다. 프레임 형식은 [05](05-browser.md).

### 7.6 `session`, `process`

```rust
pub fn register_session_notifications(window: &ui::Window) -> Result<(), WinError>;   // WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION)
pub fn unregister_session_notifications(window: &ui::Window);                          // WTSUnRegisterSessionNotification
pub fn init_process() -> Result<(), WinError>;             // SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)
pub fn current_user_sid_string() -> Result<String, WinError>;   // OpenProcessToken(TOKEN_QUERY) → GetTokenInformation(TokenUser) → ConvertSidToStringSidW → LocalFree
pub enum InstanceError { AlreadyRunning, Os(WinError) }
pub struct SingleInstance { /* 뮤텍스 핸들 + 사설 네임스페이스 핸들, 프로세스 끝까지 보유 */ }
impl SingleInstance { pub fn acquire_private(boundary: &str, alias: &str, name: &str) -> Result<Self, InstanceError>; }   // 이름은 [04] §1.1
// security (spec/05 §8.1 H1, [04] §1.1·§1.4-3)
pub const MEDIUM_INTEGRITY_RID: u32 = 0x2000;
pub fn process_integrity_rid(pid: u32) -> Result<u32, WinError>;   // OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) → OpenProcessToken(TOKEN_QUERY) → GetTokenInformation(TokenIntegrityLevel) → 마지막 하위 권한
pub fn process_image_path(pid: u32) -> Result<PathBuf, WinError>;  // QueryFullProcessImageNameW(PROCESS_NAME_WIN32)
pub fn same_file_path(a: &Path, b: &Path) -> bool;                  // 둘 다 fs::canonicalize 후 유니코드 대문자화 비교, 해석 실패 = false
pub enum ProcessCheckError { Query(WinError), LowIntegrity(u32), OtherImage }
pub fn verify_process(pid: u32, expected_image: &Path) -> Result<(), ProcessCheckError>;   // 무결성 ≥ Medium && 이미지 == expected_image
pub fn current_session_id() -> Result<u32, WinError>;              // ProcessIdToSessionId
pub struct PathSecurity { pub owner: String, pub dacl_present: bool, pub dacl_protected: bool, pub aces: Vec<PathAce>, pub label: Option<PathAce> }
pub fn path_security(path: &Path) -> Result<PathSecurity, WinError>;   // GetNamedSecurityInfoW(OWNER | DACL | LABEL)
pub struct PrivateDir { pub created: bool, pub repaired: bool, pub entries_repaired: u32 }
pub enum PrivateDirError { Untrusted, NotPlainDir, Os(WinError), Io(io::ErrorKind) }
pub fn ensure_private_dir(path: &Path, user_sid: &str) -> Result<PrivateDir, PrivateDirError>;   // 데이터 폴더 ACL([04] §1.4-3)
pub fn spawn_detached(exe: &Path, args: &[&str]) -> Result<(), WinError>;
pub fn allow_set_foreground_window(pid: u32) -> bool;     // AllowSetForegroundWindow
pub struct StdIn;  pub struct StdOut;                     // Read / Write: GetStdHandle + ReadFile / WriteFile (버퍼 없음)
pub fn std_handles_are_pipes() -> bool;                   // GetFileType(stdin/stdout) == FILE_TYPE_PIPE
pub fn exclude_from_error_reporting() -> Result<(), WinError>;   // WerAddExcludedApplication(현재 exe의 파일 이름 `yw-app.exe`, FALSE): WER은 파일 이름으로 맞추므로 전체 경로는 맞지 않는다
```

- 세션: 알림은 `WM_WTSSESSION_CHANGE`의 `ui::Msg::SessionLock`(`WTS_SESSION_LOCK` 0x7)/`SessionUnlock`(`WTS_SESSION_UNLOCK` 0x8)/`SessionDisconnect`(`WTS_CONSOLE_DISCONNECT` 0x2·`WTS_REMOTE_DISCONNECT` 0x4)/`SessionLogoff`(`WTS_SESSION_LOGOFF` 0x6), `WM_POWERBROADCAST`의 `Suspend`/`Resume`(`PBT_APMSUSPEND`/`PBT_APMRESUMEAUTOMATIC`), Windows 종료·로그오프의 `QueryEndSession`(`WM_QUERYENDSESSION`)/`EndSession`(`WM_ENDSESSION`)으로 온다(디코딩 §7.7). 등록 실패(`RPC_S_INVALID_BINDING` 등)의 재시도 정책은 yw-app([04](04-app-ui.md) §1.4). `WM_POWERBROADCAST`·`WM_QUERYENDSESSION`·`WM_ENDSESSION`은 최상위 창에만 오므로 알림을 받는 창은 `HWND_MESSAGE`가 아닌 최상위 창(숨김 가능)이다. 창 파괴 전에 `unregister_session_notifications`.
- `init_process`: yw-app([04](04-app-ui.md) §1.4)과 yw-host(`main` 첫 줄, 실패해도 계속) 모두 시작하자마자 부른다.
- `acquire_private`: `CreateBoundaryDescriptorW(boundary)` + `AddSIDToBoundaryDescriptor(현재 사용자 SID)` + `AddIntegrityLabelToBoundaryDescriptor(S-1-16-8192)` → `CreatePrivateNamespaceW(DACL D:P(A;;GA;;;<사용자 SID>), alias)`, `ERROR_ALREADY_EXISTS`면 `OpenPrivateNamespaceW`(사라졌으면 최대 5회), 같은 프로세스가 이미 연 별칭(`ERROR_DUP_NAME`)은 `AlreadyRunning` → `CreateMutexW(같은 DACL, FALSE, "<alias>\<name>")`, `ERROR_ALREADY_EXISTS`(183)면 핸들을 닫고 `AlreadyRunning`. 네임스페이스는 `ClosePrivateNamespace(h, 0)`으로 닫는다(파괴하지 않는다: 다른 인스턴스가 열고 있을 수 있다). `Local\` 이름 뮤텍스는 세션의 아무 프로세스(Low 무결성 포함)나 먼저 만들어 점유할 수 있어 쓰지 않는다.
- `verify_process`: 열거나 읽지 못하면 `Query`(거부). Low(0x1000)·Untrusted는 `LowIntegrity`. 이미지가 다르면 `OtherImage`. yw-host의 pipe 서버 검증([05](05-browser.md) §8.1)과 yw-app의 두 번째 인스턴스 인계([04](04-app-ui.md) §1.1)가 쓴다.
- `ensure_private_dir`: 없으면 `CreateDirectoryW` + SDDL `O:<SID>D:PAI(A;OICI;FA;;;<SID>)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)S:(ML;OICI;NRNW;;;ME)`. 있으면 재분석 지점·파일이면 `NotPlainDir`, 소유자가 사용자·SYSTEM·Administrators가 아니면 `Untrusted`, 그 상태가 아니면 `SetNamedSecurityInfoW(DACL | PROTECTED_DACL)` + `(LABEL)`로 고친다(다른 SID 허용이 남으면 `Untrusted`). 이어서 바로 안의 항목(재분석 지점 제외): 소유자가 셋 밖이면 `Untrusted`, 다른 SID 허용 ACE가 있으면 빈 비보호 DACL(`UNPROTECTED_DACL`)로 바꿔 상속 ACE만 남긴다. 규칙 전체는 [04](04-app-ui.md) §1.4-3.
- `spawn_detached`: 인자는 `^[A-Za-z0-9._:-]{1,64}$`만 허용(`--background` 포함), exe 경로에 `"`가 있으면 오류, 명령줄 = `"<exe>" <args…>`. `CreateProcessW(…, bInheritHandles = FALSE, DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB, NULL, <exe 디렉터리>, …)`, `ERROR_ACCESS_DENIED`면 `CREATE_BREAKAWAY_FROM_JOB` 없이 1회 재시도. 프로세스·스레드 핸들은 즉시 닫는다. 핸들 상속을 끄는 이유: yw-host가 Chrome에서 받은 표준 핸들(파이프)이 yw-app에 복제되면 yw-host가 끝나도 Chrome 쪽 파이프 끝이 닫히지 않는다. std `Command`는 `bInheritHandles = TRUE`로 프로세스를 만들므로 쓰지 않는다.
- `StdIn`/`StdOut`은 CRT 텍스트 모드·std 콘솔 처리·`LineWriter`를 거치지 않는 원시 바이트 입출력이다(yw-host, [05](05-browser.md) §7.2). `StdOut::flush`는 아무 일도 하지 않는다(버퍼 없음).

### 7.7 `ui`, `input`

```rust
pub fn init() -> Result<(), WinError>;   // SetProcessDpiAwarenessContext(PER_MONITOR_AWARE_V2) + InitCommonControlsEx. 첫 창 전 1회.
                                         // 매니페스트가 이미 PMv2를 정한 경우의 ERROR_ACCESS_DENIED(5)는 성공으로 본다([04] §1.6)
pub enum CaptureExclusion { Required /* 니모닉·개인키 표시 창 */, Preferred /* 비밀번호·니모닉·개인키 입력 창 */ }
pub struct ClassSpec { pub name: &'static str, pub secret: bool, pub capture: CaptureExclusion }   // capture는 secret = true일 때만 의미
pub fn register_class(spec: &ClassSpec) -> Result<(), WinError>;                 // 이름마다 1회, 두 번째는 Ok(()). 클래스 아이콘([04] §1.7):
                                         // 실행 파일의 RT_GROUP_ICON 1을 LoadImageW로 SM_CXICON·SM_CXSMICON(시스템 DPI) 크기로 한 번 읽어
                                         // hIcon·hIconSm에 쓴다(프로세스 수명, 해제하지 않음). 리소스가 없으면(테스트 바이너리) IDI_APPLICATION
pub enum WindowKind { Main, Owned { owner: Hwnd }, Floating /* 소유자 없는 대화 상자형: 승인 창 */, Child { parent: Hwnd } /* WS_CHILD|WS_VSCROLL 패널 */, HiddenTopLevel }
pub struct WindowSpec { /* builder: WindowSpec::new(class, kind).title(&str).size(w, h /* DIP */).min_size(w, h).visible(bool).topmost(bool).resizable(bool) */ }
pub fn create_window(spec: &WindowSpec, handler: Box<dyn Handler>) -> Result<Window, UiError>;
pub fn exclude_from_capture(w: &Window) -> Result<(), UiError>;                  // 설정 후 읽기 확인(비밀 클래스는 create_window가 호출)
pub trait Handler { fn on(&mut self, w: &Window, m: &Msg) -> Reply; }
pub enum Reply { Default, Handled(isize) }
pub enum Msg { Create, Paint, Size { w: i32, h: i32 }, DpiChanged { dpi: u32 }, Char(u16), KeyDown { vk: u16, repeat: bool },
  KeyUp { vk: u16 }, MouseDown { x: i32, y: i32 }, MouseUp { x: i32, y: i32 }, MouseMove { x: i32, y: i32 }, Wheel(i16),
  MouseActivate, Timer(usize), VScroll { code: u16 /* SB_* */ }, Command { id: u16, code: u16 }, ActivateApp(bool), KillFocus { to_foreign: bool },
  CaptureChanged, CancelMode, Close, Destroy, SessionLock, SessionUnlock, SessionDisconnect, SessionLogoff, Suspend, Resume,
  QueryEndSession, EndSession, ImeAttempt, App { msg: u32, wparam: usize } }
pub struct Hwnd(/* usize */);   // Copy + Eq, 불투명 식별자(포인터로 쓸 수 없음)
pub struct Window { /* Hwnd; !Send */ }
// Window: hwnd, show, hide, destroy, enable, set_topmost, set_foreground, flash, invalidate, invalidate_rect(Rect), take_paint_stats() -> PaintStats, set_title, set_timer(id, ms),
//         kill_timer, dpi, px(dip), client_rect, set_capture, release_capture, set_focus, is_foreground, focus_within, center_on, poster,
//         is_alive, begin_paint() -> PaintDc, measure_text(&Font, &[u16], max_w, DrawFlags) -> (w, h)   // Paint 밖 배치 계산(GetDC)
//         capture_excluded() -> bool   // 비밀 클래스: exclude_from_capture 성공 여부(Preferred 실패면 false), 그 밖 false
//         set_rect(Rect), set_vscroll(pos, page, max), vscroll_track_pos() -> i32   // Child 패널 배치·세로 스크롤(M4 승인 창)
pub struct Poster { /* Send + Sync */ }
impl Poster { pub fn post(&self, msg: u32, wparam: usize) -> Result<(), WinError>; }   // PostMessageW, msg ≥ WM_APP
pub enum InputKind { Key { vk: Option<u16> /* WM_(SYS)KEYDOWN = Some, WM_CHAR = None */ }, Mouse }   // vk: 앱 단축키(Ctrl+L, [04] §5.1)
pub fn run_loop(observe: &mut dyn FnMut(InputKind, Hwnd)) -> i32;   // GetMessageW/TranslateMessage/DispatchMessageW, 키·마우스 메시지마다 observe
pub fn quit(code: i32);                                               // PostQuitMessage
pub fn message_box(owner: Option<&Window>, text: &str, caption: &str, kind: MbKind) -> MbResult;   // 시작 실패 등 창 이전 오류만
pub fn find_windows(class: &'static str) -> Vec<(Poster, u32)>;   // FindWindowExW(NULL, 이전, class) 반복(최대 16) + GetWindowThreadProcessId → (그 창의 Poster, pid). 두 번째 인스턴스 인계용([04] §1.1). 클래스 이름은 아무 프로세스나 쓸 수 있으므로 호출자가 security::verify_process로 확인한다
pub enum UiError { Os(WinError), CaptureExclusionFailed }
pub mod input { pub fn is_down(vk: u16) -> bool; /* GetAsyncKeyState 최상위 비트 */  pub fn is_down_in_message(vk: u16) -> bool; /* GetKeyState 최상위 비트: 처리 중 메시지 시점의 키 상태(게시·전송된 WM_KEYDOWN은 바꾸지 않음) */  pub fn injected() -> bool; /* GetCurrentInputMessageSource → IMO_INJECTED */ }
// 사용처: 승인 창 포인터·Space hold는 is_down, 승인 버튼 Enter는 is_down_in_message && !injected([04] §3.3)
```

- wndproc는 yw-win 트램펄린 하나다. 상태 `RefCell<Box<dyn Handler>>`는 스레드 지역 등록부(hwnd → 상태)로만 찾는다. `GWLP_USERDATA`는 다른 프로세스도 쓸 수 있으므로 믿지 않는다(표시용으로만 쓴다). `WM_NCCREATE`는 `create_window`가 이 스레드에서 지금 만드는 상태(스레드 지역 "creating" 칸)와 `lpCreateParams`가 정확히 같고, 창의 user data가 0이며 아직 등록되지 않았을 때만 그것을 받아 등록한다(칸은 한 번 쓰면 비운다; 진행 중인 생성이 없으면 `CREATESTRUCTW`도 읽지 않는다). `WM_NCDESTROY`에서 등록을 지우고 해제한다. `GetMessageW`는 게시된 메시지만 돌려주므로, `run_loop`는 트램펄린이 lParam을 역참조하거나 수명을 바꾸는 메시지(`WM_NCCREATE`·`WM_CREATE`·`WM_NCDESTROY`·`WM_DESTROY`·`WM_GETMINMAXINFO`·`WM_DPICHANGED`·`WM_DRAWITEM`·`WM_CTLCOLORSTATIC`·`WM_CTLCOLORBTN`)가 게시돼 오면 버린다(시스템은 이들을 보내기만 한다). `Window`·`Control`의 메서드는 창(컨트롤은 부모 창)이 파괴된 뒤에는 아무것도 하지 않거나 중립값을 돌려준다(재사용된 hwnd 값을 건드리지 않는다).
- 재진입(핸들러 실행 중 같은 창으로 동기 메시지)은 `try_borrow_mut` 실패로 감지해 핸들러를 부르지 않고, 비밀 차단 판정 뒤 `DefWindowProcW`로 넘긴다. 핸들러는 같은 창에 동기 메시지를 일으키는 API를 피하고 `Poster`로 미룬다.
- 비밀 클래스(`ClassSpec.secret = true`): `create_window`는 숨긴 채 `CreateWindowExW` 직후, 핸들러를 붙이기 전에 `exclude_from_capture`(= `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` → `GetWindowDisplayAffinity` 값이 `0x11`이 아니면 실패)를 호출한다. 설정 또는 읽기 확인이 실패하면 `ClassSpec.capture`에 따라:
  - `CaptureExclusion::Required`(니모닉·개인키 **표시** 창): 창을 파괴하고 `Err(UiError::CaptureExclusionFailed)`. 앱은 오류를 보여 주고 비밀을 표시하지 않는다([04](04-app-ui.md) §4.5).
  - `CaptureExclusion::Preferred`(비밀번호, 니모닉·개인키 **입력** 창): 창을 유지하고(숨김, 핸들러 연결, 아래 메시지 차단 동일) `Ok(Window)`를 돌려주며 `capture_excluded() == false`. 앱은 `show` 전에 보이는 경고 배너를 붙인다([04](04-app-ui.md) §4.5).
  - 분기는 내부 순수 함수 `capture_outcome(mode: CaptureExclusion, excluded: bool) -> CaptureOutcome { Excluded, Unprotected, Destroy }`이며 4경우를 창 없이 단위 테스트한다. `capture`는 클래스 단위이므로 정책이 다른 창은 다른 클래스로 등록한다([04](04-app-ui.md) §1.7).
- 비밀 클래스의 wndproc는 `capture`·캡처 제외 결과와 무관하게 [04](04-app-ui.md) §4.4의 정확히 22개 메시지(와일드카드 없음: `WM_RBUTTONDBLCLK`·`WM_IME_SETCONTEXT`·`WM_IME_NOTIFY` 등은 막지 않는다)와, 비밀 상태를 붙인 뒤(`create_window` 반환 후, `armed`)에는 `WM_SETTEXT`도 핸들러와 `DefWindowProcW` 없이 0을 반환한다. 막기 전에 `WM_IME_STARTCOMPOSITION`은 `Msg::ImeAttempt`로 핸들러에 알린다([04](04-app-ui.md) §4.4). 판정은 순수 함수 `is_blocked_secret_msg(msg: u32, armed: bool) -> bool`이며 그 목록 그대로 창 없이 단위 테스트한다. Microsoft는 캡처 제외를 보안 보장으로 보지 않는다(§2.2 범위).
- `WM_DPICHANGED`에 `Default`면 제안 사각형으로 `SetWindowPos`(wParam의 두 워드가 같은 DPI일 때만 lParam을 읽는다). 크기는 DIP, `scale(v, dpi) = v * dpi / 96`(checked). `WM_CLOSE` 기본 = `DestroyWindow`. yw-win은 `PostQuitMessage`를 스스로 부르지 않는다(앱이 `quit`).
- 세션·종료 메시지 디코딩: `WM_WTSSESSION_CHANGE`의 wParam `WTS_CONSOLE_DISCONNECT`(0x2)·`WTS_REMOTE_DISCONNECT`(0x4) → `SessionDisconnect`, `WTS_SESSION_LOGOFF`(0x6) → `SessionLogoff`, `WTS_SESSION_LOCK`(0x7) → `SessionLock`, `WTS_SESSION_UNLOCK`(0x8) → `SessionUnlock`, 그 밖 값은 핸들러에 오지 않는다(`DefWindowProcW`). `WM_QUERYENDSESSION` → `QueryEndSession`(`Reply::Default` = `DefWindowProcW` = TRUE, 종료 허용). `WM_ENDSESSION`은 wParam = TRUE일 때만 `EndSession`이고 FALSE(종료 취소)는 핸들러에 오지 않는다. `EndSession` 핸들러가 반환한 뒤 Windows는 프로세스를 언제든 끝낼 수 있다(앱 처리는 [04](04-app-ui.md) §1.5·§5.1).
- 그리기: `PaintDc`(`Msg::Paint` 안에서만, BeginPaint/EndPaint RAII, 이중 버퍼: 갱신 영역 크기의 메모리 비트맵(흰색으로 시작)에 그린 뒤 끝날 때 `BitBlt` 한 번, 해제 전 비트맵을 흰색으로 덮음. `WM_ERASEBKGND`는 지우지 않고 1을 돌려주며 `invalidate`·`invalidate_rect`도 지우기 없이 무효화한다 — 주기적 다시 그리기가 깜빡이지 않게) — `fill_rect(Rect, Color)`(QR 모듈 포함), `frame_rect(Rect, Color)`, `set_text_color(Color)`, `draw_text(&[u16], Rect, DrawFlags)`, `measure_wrapped(&[u16], max_w, DrawFlags) -> h`(`DT_CALCRECT`; 높이는 `DrawFlags::WRAP`으로 잰다 — `DT_VCENTER`가 든 `LINE`은 높이 0 사각형에서 절반 값을 낸다)(`DrawTextW`, `DT_NOPREFIX`를 항상 더함), `measure(&[u16], max_w) -> (fit_chars, width)`(`GetTextExtentExPointW`), `select_font(&Font)`. `Font::create(face: &str, size_pt: u16, bold: bool, dpi: u32) -> Result<Font, WinError>`(`CreateFontW`, Drop에서 `DeleteObject`). `Rect { x, y, w, h: i32 }`, `Color(u32 /* 0xRRGGBB */)`, `MbKind::{Info, Warning, Error}`, `MbResult::{Ok}`.
- `controls`: 비밀이 아닌 값용 BUTTON·EDIT·STATIC·체크박스·owner-draw LISTBOX 생성과 자기 컨트롤 텍스트 get/set(`GetWindowTextW`, 길이 상한). 알림은 `Msg::Command`. 푸시 버튼은 `ControlKind::Button(ButtonStyle)`(`BS_OWNERDRAW`): 부모 wndproc가 `WM_DRAWITEM`에서 스타일(채움·글자·테두리·눌림·비활성·포커스 색, 모서리 반지름 DIP)대로 그린다. lParam(`DRAWITEMSTRUCT`)은 wParam이 그 부모 아래 우리 owner-draw 버튼의 id일 때만 읽고, 구조체의 `CtlType`·`CtlID`·`hwndItem`이 그 버튼과 같아야 그린다. `Control::set_backdrop(Color)`은 체크박스·라디오·읽기 전용 칸이 `WM_CTLCOLORSTATIC`·`WM_CTLCOLORBTN`에서 받을 배경(놓인 카드·창 색)이고, `Control::set_button_style`은 같은 컨트롤의 스타일만 바꾼다([04] §1.6).
- `capture`(개발 전용, `#[cfg(debug_assertions)]`): `capture_client(Hwnd) -> Capture { width, height, bmp }`(창 자신의 클라이언트 DC에서 `BitBlt` → 24비트 BMP, Gdi feature만 씀), `dev_tour_redraw`, `dev_tour_flush`(`GdiFlush`), `dev_tour_lift_capture_exclusion(&Window)`(`WDA_NONE`, 투어 프로세스가 만든 창에만). 앱 경로는 쓰지 않는다([04] §11).
- 비밀 입력(D11, OS EDIT 미사용):

```rust
pub enum CharPolicy { PrintableAscii /* 0x20–0x7E: 비밀번호·passphrase */, LowerWords /* a–z, ' ': 니모닉 */, Hex /* 0-9a-fA-F, 선택적 0x: 개인키 */ }
pub enum CharResult { Accepted, Rejected, Backspace, Submit, Ignored }
pub struct SecureTextField { /* WipeBuf<u8>, 용량 = max_len */ }
impl SecureTextField {
    pub fn new(policy: CharPolicy, max_len: usize) -> Self;
    pub fn on_char(&mut self, unit: u16) -> CharResult;   // 0x08 → 마지막 바이트 wipe, 0x0D → Submit, 정책 밖·비ASCII·서로게이트 → Rejected
    pub fn len(&self) -> usize;  pub fn clear(&mut self);  pub fn set_masked(&mut self, on: bool);
    pub fn paint(&self, dc: &mut PaintDc<'_>, r: Rect, focused: bool);   // masked: '•' × len, 아니면 WipeBuf<u16> 임시 사본으로 그린 뒤 wipe
    pub fn with_secret<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R;
}
```

[04](04-app-ui.md)가 `SecretField`처럼 자체 위젯을 yw-app에 두더라도, 그 버퍼는 `WipeBuf` 또는 yw-core 비밀 타입이어야 하고 그리기는 `PaintDc`를 쓴다.

### 7.8 테스트

- 순수(`#[cfg(test)]`): `HttpsUrl`·`LoopbackUrl`·`EndpointUrl::parse` 경계(`http://example.com`·`http://127.0.0.2` 거부, `http://[::1]:11434/…` 허용, `HTTPS://`·`https://[2001:db8::1]:8545/` 허용·정규화, 잘못된 IPv6 리터럴 거부), `HttpsUrl`의 `{:?}`·`{}` 출력에 호스트·경로 문자열이 없음, 헤더 검사, `is_blocked_secret_msg`, `capture_outcome` 4경우(성공은 둘 다 `Excluded`, 실패는 `Required` → `Destroy`·`Preferred` → `Unprotected`), `wallet_pipe_name`·`user_only_sddl`, `Msg` 디코딩(`WM_WTSSESSION_CHANGE` wParam 0x2·0x4·0x6·0x7·0x8과 그 밖 값, `WM_QUERYENDSESSION`, `WM_ENDSESSION` wParam TRUE·FALSE 포함), `SecureTextField` 정책·backspace·용량, `spawn_detached` 인자 검증, `owner_is`, WER 파일 이름, 클립보드 순번을 닫기 전에 읽음·NUL 탐색 상한, 전체 HTTP 기한 계산, `WM_NCCREATE` 채택 규칙·게시 금지 메시지·`WM_DPICHANGED` wParam, 디렉터리 flush 실패의 경고 결과, 다른 파이프에 붙은 이후 인스턴스 거부(같은 사용자의 DACL이 다른 "선점" 파이프로), 숨김 창에 위조한 `GWLP_USERDATA`·`WM_NCCREATE`·게시된 `WM_NCDESTROY`/`WM_DRAWITEM`이 상태에 닿지 않음.
- Windows 통합(`crates/yw-win/tests/`, 개발 PC의 `cargo test`): pipe 왕복과 전이중 동시 읽기·쓰기, 두 번째 `Server::create`의 `AlreadyExists`, 연결 4개일 때 다음 인스턴스 보류, 서버가 쓰고 바로 닫아도 데이터가 도착함, 양 끝의 `owner_sid`, 취소 뒤 대기 중·이후 쓰기의 `ERROR_OPERATION_ABORTED`, loopback HTTP 정상 응답과 조금씩 흘리는 본문의 전체 기한 `Timeout`, 정션에 대한 `flush_dir`의 `ReparsePoint`, `atomic_write` 덮어쓰기·남은 임시 파일 처리, DPAPI 왕복과 다른 entropy 실패, `LockedBox` 생성·해제, 사설 네임스페이스 `SingleInstance` 이중 획득 실패·해제 후 재획득·`Local\<별칭>` 점유에 영향 없음, 데이터 폴더 ACL(테스트마다 `icacls /inheritance:r`로 명시 ACL을 준 임시 기반 폴더: 새 폴더 3단계가 보호 DACL·Medium NR/NW 레이블이고 안의 `vault.ywv`·`apikeys.dpapi`·로그가 사용자·SYSTEM·Administrators만 상속, 다른 그룹 RX가 상속된 기존 폴더와 명시 허용 ACE가 있는 파일의 자동 수리, 정션 거부). 순수 단위: 무결성 판정, 경로 비교, `decide_dir`·`decide_entry`(소유자·추가 허용·보호·레이블·NULL DACL·거부 ACE), 단계별 HTTP 시간 제한 계산. yw-host `tests/owner.rs`: 서버 프로세스 검사 거부 → hello 없음, 실제 `verify_process`(자기 이미지 통과, 다른 파일·없는 pid 거부). 네트워크·화면 캡처·세션 잠금은 수동 체크리스트([09](09-testing.md)).

---

## 8. 미결 사항

1. **구현 시 확인 — yw-host가 실행한 yw-app의 수명(D24, M5).** Chrome이 native host를 job object에 넣고 연결 종료 때 job을 정리하면 yw-host가 띄운 yw-app도 함께 종료될 수 있다(`spawn_detached`는 `CREATE_BREAKAWAY_FROM_JOB`을 먼저 시도한다, §7.6). 확인: 확장 연결 → yw-app 자동 실행 → Chrome 완전 종료 후 yw-app 생존 여부([09](09-testing.md) M5-13). 함께 종료되면 D24의 대안을 그대로 적용한다: `browserAutoLaunch` 기본값을 `false`로 바꾸고([04](04-app-ui.md) §6.1, [05](05-browser.md) §7.4) 사용자가 yw-app을 먼저 실행한다(yw-app이 없으면 요청마다 4900). D24 변경은 필요 없다.
2. **구현 시 확인 — `WerAddExcludedApplication`.** feature 이름과 심볼은 windows-sys 0.61.2에 있고 해당 feature로 크레이트 컴파일을 확인했지만, 실제로 Windows 11에서 이 호출이 fast-fail 보고(`panic = "abort"`)를 WER 업로드 대상에서 빼는지는 확인하지 않았다. 확인: 테스트 빌드에서 의도적 abort 후 "안정성 모니터"·`%LOCALAPPDATA%\Microsoft\Windows\WER\ReportQueue`에 보고가 생기는지. 효과가 없으면 이 호출을 빼고 D28의 "크래시 업로드 없음"은 "지갑이 업로드하지 않음"으로 한정한다.
3. **구현 시 확인 — loopback `[::1]`(§7.4).** `WinHttpConnect`가 IPv6 리터럴을 대괄호 없이 받는지 [06](06-llm-explain.md) §10 mock 테스트에서 확인한다. 대체: 대괄호 포함 형태, 둘 다 실패하면 `LoopbackUrl`에서 `[::1]`을 거부한다.

---

## 9. 소스 설치 (D1)

미리 빌드한 실행 파일은 만들지도 배포하지도 않는다. 사용자는 소스 체크아웃(Git 또는 GitHub "Download ZIP")의 루트 `install.cmd`로 자기 PC에서 빌드하고 현재 사용자 범위에 설치한다. 사용자 안내는 [docs/install.ko.md](../docs/install.ko.md), 판정은 [09](09-testing.md) §5.12(INS-1은 자동 시험 §9.4). native host 등록도 이 스크립트가 한다([05](05-browser.md) §9).

### 9.1 파일

| 경로 | 역할 |
|---|---|
| `install.cmd` | 루트의 더블클릭 진입점. `"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0scripts\install.ps1" %*` → `pause`(창이 바로 닫히지 않게) → 스크립트의 종료 코드로 끝난다 |
| `uninstall.cmd` | 같은 방식으로 `scripts\uninstall.ps1` |
| `scripts/install.ps1` | 확장 확인 → 빌드 도구 확인 → 빌드 → 설치(§9.2) |
| `scripts/uninstall.ps1` | 제거(§9.3). install.ps1이 설치 폴더에도 사본을 둔다(저장소를 지운 뒤에도 제거할 수 있게) |
| `scripts/install.test.mjs` | 자동 시험(check.ps1 script-test, §9.4) |

`.cmd` 두 파일은 ASCII, 두 `.ps1`은 한국어 문자열이 있으므로 UTF-8 BOM(없으면 Windows PowerShell 5.1이 ANSI로 읽는다). 모두 CRLF(`.gitattributes` `*.ps1`·`*.cmd` `eol=crlf`; GitHub ZIP도 이 속성대로 만들어진다). 두 스크립트는 Windows PowerShell 5.1·PowerShell 7 호환이다. `-ExecutionPolicy Bypass`는 그 실행에만 적용되며 시스템 실행 정책을 바꾸지 않는다.

### 9.2 `scripts/install.ps1`

`install.cmd [-InstallDir <폴더>] [-FixPermissions] [-AllowUnsafeToolchainPath] [-AllowAncestorCargoConfig] [-AllowUnsafeSourcePath] [-NoShortcut] [-NoNativeHost] [-NoBuild] [-DryRun]`. 관리자 권한 불필요. 기본 설치 폴더 `%LOCALAPPDATA%\Programs\YourWallet`. 저장소 루트 = 스크립트 폴더의 `..`(`Cargo.toml`·`Cargo.lock`·`extension\manifest.json`·`scripts\uninstall.ps1`이 없으면 종료 1). 버전 = 루트 `Cargo.toml` `[workspace.package] version`, 커밋 = `.git`이 있고 믿을 수 있는 git(4)이 있을 때 `<git 전체 경로> -C <루트> rev-parse --short=12 HEAD`(없으면 null; `.git`은 있는데 그런 git이 없으면 "커밋 표시를 건너뜁니다"를 출력하고 계속).

**신뢰하는 SID**(이 절 전체): 현재 사용자, SYSTEM `S-1-5-18`, Administrators `S-1-5-32-544`, TrustedInstaller `S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464`. 그 밖의 SID(Users `S-1-5-32-545`, Authenticated Users `S-1-5-11`, Everyone `S-1-1-0`, INTERACTIVE `S-1-5-4`, 다른 사용자 SID 등)는 신뢰하지 않는다. 설치 프로그램은 설치 폴더(6의 `-FixPermissions`) 밖의 어떤 폴더 권한도 바꾸지 않는다.

1. 환경: Windows, 64비트, `LOCALAPPDATA` 절대 경로, 빌드 22621 미만이면 경고. 출력이 리디렉션되면 UTF-8로 쓴다.
2. 설치 경로: 정규화한 절대 경로, `"`·`%`·`&`·`^`·`|`·`<`·`>`·`!`·제어 문자 금지([05] §9.1과 같은 규칙), 드라이브 문자로 시작하고 루트가 아님, 지갑 데이터 폴더 `%LOCALAPPDATA%\YourWallet`·저장소·빌드 결과 폴더(`target\release`, `CARGO_TARGET_DIR`가 있으면 그 아래 `release`)와 겹치지 않음, 그 경로로 만든 manifest가 8의 검증을 통과. 위반은 종료 1.
   **상위 폴더**(빌드 전에 확인, `Get-InstallAncestorProblems`): 다른 사용자가 상위 폴더를 옮기고 같은 경로에 자기 폴더를 만들면 HKCU 등록이 가리키는 경로의 `yw-host.exe`를 그 사용자가 정하게 된다. `-InstallDir`이면 드라이브 루트까지, 기본 경로면 `%USERPROFILE%`과 그 아래만(기본 경로가 프로필 아래가 아니면 검사하지 않음), 설치 폴더의 이미 있는 상위 폴더 A마다 U(A) = A 자체에 적용되는 허용 ACE(상속받은 것 포함, 상속 전용 제외, 거부 ACE 무시)가 신뢰하지 않는 SID에 주는 권한의 합(CREATOR OWNER `S-1-3-0`·CREATOR GROUP `S-1-3-1`·OWNER RIGHTS `S-1-3-4`와 AppContainer `S-1-15-2-*`·`S-1-15-3-*`는 뺀다: 앞의 둘은 유효 ACE로는 아무에게도 권한을 주지 않고, OWNER RIGHTS는 아래에서 확인한 소유자에게만, AppContainer SID는 사용자 SID 쪽 권한이 함께 있어야만 접근을 준다)을 구해 다음이면 종료 1:
   - (가) A가 링크(재분석 지점: 정션·심볼릭 링크)이거나 파일, 소유자가 신뢰하지 않는 SID, DACL 없음, ACL을 읽을 수 없음, 또는 U(A)에 `FILE_DELETE_CHILD`(0x40)·`WRITE_DAC`·`WRITE_OWNER`·`GENERIC_ALL`이 있음(아무 하위 항목이나 지우거나 옮길 수 있고, 권한을 스스로 줄 수 있다).
   - (나) U(A)에 `DELETE`가 있고, A가 드라이브 루트가 아니며, A의 부모 P에서 U(P)에 파일 추가(0x2)·폴더 추가(0x4)·`GENERIC_WRITE`가 있음(A를 옮긴 뒤 P에 같은 이름의 폴더를 만들 수 있다).
   - 거부하지 않는 것: 읽기·실행 권한; 파일·폴더 추가만(예: `C:\`의 Authenticated Users "폴더 만들기"와 상속 전용 수정 권한) — 이미 있는 하위 폴더를 바꿀 수 없고, 아직 없는 중간 폴더는 7에서 설치 프로그램이 직접 만든다; 부모에 추가 권한이 없는 폴더의 `DELETE`(예: 다른 계정에 수정 권한을 준 `%TEMP%`) — 옮기거나 지울 수만 있어 설치가 깨질 뿐 바꿔치기는 안 된다; 드라이브 루트의 `DELETE`(루트는 옮길 수 없다).
   - 없는 상위 폴더를 만나면 멈춘다. 설치 폴더 자체의 권한은 6이 본다. 오류 문구는 문제 폴더와 이유를 나열하고 사용자 프로필 아래 경로를 권하며, 시스템 폴더 권한을 고치라고 하지 않는다.
3. 확장: 런타임 파일 = `manifest.json` + `popup/*`(파일만) + `src/*.js`(`^[A-Za-z0-9._-]+\.js$`인 파일만) + `icons/*.png`(`^[A-Za-z0-9._-]+\.png$`인 파일만), 이 순서이고 폴더마다 서수 정렬. 세 폴더는 모두 있어야 하고 비어 있으면 안 된다. 하위 폴더·다른 파일·reparse point가 있으면 종료 2. 이 목록은 `scripts/audit-extension.mjs`의 `auditExtensionRoot().packagedFiles`와 같아야 한다(설치에 Node가 필요 없도록 재구현, 일치는 §9.4; 파일 내용 감사는 check.ps1 audit-ext). `package.json`·`extension-id.txt`·`native-host/`·`tests/`·`test-dapp/`은 설치하지 않는다. `manifest.json`의 `key`로 계산한 ID([05] §2.3)가 `nnpjlobjgbanccjddghlpaafpohfkeph`가 아니면 아무것도 바꾸지 않고 종료 2.
4. 빌드 도구(`-NoBuild`면 건너뜀): `rust-toolchain.toml` channel이 스크립트의 `$RustToolchain`(`1.95.0`)과 다르면 종료 2(둘을 함께 바꾼다). Rust 도구는 **PATH에서 찾지 않는다**: `CARGO_HOME`이 드라이브 문자로 시작하는 절대 경로면 `%CARGO_HOME%\bin`, 아니면 `%USERPROFILE%\.cargo\bin`에 `rustup.exe`·`cargo.exe`·`rustc.exe`(rustup 프록시)가 모두 있어야 "있음"이고, 이후 모든 실행은 그 전체 경로로 한다(PATH에만 cargo가 있으면 "없음"과 함께 그 경로는 쓰지 않는다고 출력). MSVC(`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64`가 설치 경로를 돌려줌). Windows SDK(`Windows Kits\10\Lib\*\um\x64\kernel32.lib`)가 없으면 경고만 한다. 없는 도구와 §3.8의 winget 명령을 출력하고, 대화형이면 `Y/N`을 물어 **Y일 때만** 그 명령을 실행(콘솔 상속, 순서대로)한 뒤 다시 확인한다(winget rustup은 `%USERPROFILE%\.cargo\bin`에 설치하므로 PATH 갱신 없이 찾는다). N, 비대화형(`UserInteractive` 아님·입력 리디렉션·`-NonInteractive`), winget 없음, 설치 뒤에도 없음은 종료 7. `-DryRun`은 묻지도 실행하지도 않는다. Node.js는 확인하지 않는다(필요 없음).
   **도구 위치 권한**(`Get-ToolPathProblem`, Rust 도구가 있으면 `-DryRun`에서도): 세 파일 각각과 그 폴더, 파일이 심볼릭 링크면(rustup은 `cargo.exe` 등을 `rustup.exe`로의 링크로 만들 수 있다) 링크 대상 파일과 그 폴더까지(최대 8단계) 6의 `Get-AclProblem`을 적용한다: 소유자가 신뢰하는 SID가 아니거나, 신뢰하지 않는 SID에 쓰기·추가·쓰기 특성·하위 삭제·삭제·권한 변경·소유권 가져오기(`GENERIC_WRITE`·`GENERIC_ALL`, 따라서 수정·모든 권한 포함)를 주는 허용 ACE(상속 전용 포함, CREATOR OWNER 상속 전용 제외)가 있으면 문제. 실제로 실행하는 이 파일들만 보고 다른 PATH 항목은 보지 않는다. 문제가 있으면 문제 경로와 위험(그 사용자가 도구를 바꿔치기하면 빌드하는 exe에 자기 코드를 넣는다)을 설명하고 종료 7; `-AllowUnsafeToolchainPath`면 같은 설명 뒤 경고하고 계속한다. 폴더 권한은 바꾸지 않는다.
   **git**(커밋 표시에만 쓴다): 후보 = `%ProgramFiles%`·`%ProgramFiles(x86)%`·`%ProgramW6432%`의 `Git\cmd\git.exe`, 그다음 PATH의 `git`(찾기만 하고 위치를 다시 확인). 드라이브 경로이고, 폴더가 Program Files 아래이거나 현재 사용자 소유이며, `Get-ToolPathProblem`을 통과하는 첫 후보를 쓴다. 없으면 커밋 없이 계속한다(설치를 막지 않는다).
5. 빌드(`-NoBuild`·`-DryRun`이면 하지 않음; `-DryRun`은 아래 명령줄과 지울 환경 변수를 출력): 빌드 동안(버전 확인 포함)만 이 프로세스 환경에서 다음 변수를 지우고 끝나면(실패해도) 원래 값으로 되돌린다(자식 cargo·rustc·빌드 스크립트·cc는 지운 환경을 물려받는다; 시스템·사용자 설정은 그대로): rustflags 4개(§4.1, 기존처럼 변수마다 경고), `RUSTC`·`RUSTC_WRAPPER`·`RUSTC_WORKSPACE_WRAPPER`, 이름이 `CARGO_PROFILE_RELEASE_`·`CARGO_BUILD_RUSTC`·`CC`·`CFLAGS`·`CXX`·`CXXFLAGS`로 시작하는 모든 변수(대소문자 무시; 예 `CC_x86_64_pc_windows_msvc`, `CXXFLAGS_x86_64-pc-windows-msvc`, `CARGO_BUILD_RUSTC_WRAPPER`). 저장소 루트에서 `<cargo> +1.95.0 --version`(실패하면 `<rustup> toolchain install 1.95.0 --profile minimal` 후 재시도)의 첫 줄이 `cargo 1.95.0`(뒤에 공백 또는 끝)이 아니면, `<rustc> +1.95.0 -vV`의 첫 줄이 `rustc 1.95.0 …`이 아니거나 `release: 1.95.0`이 아니면 **종료 7**(경고가 아니다), `host: x86_64-pc-windows-msvc`가 아니면 종료 7. 빌드 명령(인자 배열로 넘김):
   `<cargo> +1.95.0 --config profile.release.codegen-units=1 --config profile.release.lto='fat' --config profile.release.overflow-checks=true --config profile.release.panic='abort' --config profile.release.strip='symbols' --config profile.release.debug=false --config build.rustc-wrapper='' --config build.rustc-workspace-wrapper='' --config target.x86_64-pc-windows-msvc.linker='link.exe' build --release --locked -p yw-app -p yw-host`
   `profile.release.*` 값은 §3.1 `[profile.release]`와 정확히 같다(같은지는 §9.4가 확인). 빈 래퍼 두 개는 설정 파일의 컴파일러 래퍼를 끄고(빈 문자열 = 래퍼 없음), 링커는 rustc의 MSVC 기본값 `link.exe`로 고정한다. 명령줄 `--config`는 환경 변수와 상위 폴더·`CARGO_HOME`의 `.cargo\config.toml`보다 우선하므로 그쪽의 profile 설정이 릴리스 빌드를 바꾸지 못한다. 문자열은 TOML 리터럴(`'fat'`)로 쓴다: Windows PowerShell 5.1은 네이티브 인자 안의 큰따옴표를 escape하지 않아 `"fat"`이 cargo에 `fat`(잘못된 TOML)으로 간다; 리터럴 문자열은 5.1과 PowerShell 7에서 같은 명령줄이 된다. 출력은 그대로 보이고, 네트워크는 첫 crate 내려받기에만 쓰며 내용은 `Cargo.lock` 체크섬으로 고정한다. 실패는 흔한 원인 안내와 함께 종료 8. `-NoBuild`인데 `yw-app.exe`·`yw-host.exe`가 없으면 종료 2.
   **cargo 설정 파일**(`Confirm-CargoConfigs`, 빌드 직전, `-DryRun`에서도; `-NoBuild`면 보지 않음): cargo는 저장소 루트와 그 모든 상위 폴더의 `.cargo\config.toml`·`.cargo\config`, 그리고 `CARGO_HOME`의 것을 적용한다. 저장소 루트의 부모부터 드라이브 루트까지 각 폴더의 `.cargo\config.toml`·`.cargo\config`가 있으면(저장소 자신의 `.cargo`와, 4의 CARGO_HOME 폴더 — `%CARGO_HOME%` 또는 `%USERPROFILE%\.cargo` — 와 같은 `.cargo`는 빼고, 대소문자 무시) 그 목록을 출력하고 **종료 7**; `-AllowAncestorCargoConfig`면 목록과 경고 뒤 계속. `CARGO_HOME\config.toml`·`CARGO_HOME\config`는 사용자 설정이라 거부하지 않고, 빌드를 바꾸는 키(`build.rustc*`·`build.rustflags`, `target.<대상>.linker`·`target.<대상>.rustflags`, `profile.release.*`, `patch.*`·`source.*`·`paths`)가 있으면 그 키 이름을 경고로 출력한다(키 찾기는 표 머리·점 키·한 줄 인라인 표를 보는 근사; 경고 전용).
   경로 정리(`--remap-path-prefix`)는 하지 않는다(§3.9).
**소스·빌드 폴더 권한(2026-11-01 검토 L7, `Confirm-SourcePathsTrusted`):** 3의 확장 확인 직후 저장소 루트·`scripts\`·`scripts\uninstall.ps1`·`extension\`과 3의 런타임 파일·그 폴더, 5의 빌드 뒤(또는 `-NoBuild`) 빌드 폴더(`target` 또는 `CARGO_TARGET_DIR`)·`release\`·`yw-app.exe`·`yw-host.exe`의 보안 설명자에 6의 설치 폴더 규칙(`Get-AclProblem`)을 적용한다. 단 로그온 세션에 주어지지 않는 SID — S-1-4-*(non-unique authority; 샌드박스가 현재 사용자의 제한 토큰에 넣는 제한 SID)와 AppContainer S-1-15-2-*·S-1-15-3-* — 의 ACE는 뺀다(그런 토큰은 사용자 SID 권한도 함께 있어야 접근한다). 위반은 목록 출력 후 **종료 1**, `-AllowUnsafeSourcePath`면 경고 후 계속. 이유: 설치 폴더가 사설이어도, 다른 사용자가 저장소·빌드 폴더의 파일을 미리 바꿔 두면 그 코드가 사설 폴더에 설치된다(원본·복사본 해시 비교는 같은 출처라 막지 못한다).

6. 설치 폴더 상태: 없음·빈 폴더 → 새 설치. 설치 기록 `yw-install.json`(UTF-8 BOM 없음, `{"product":"YourWallet","version","commit","state":"installing"|"installed","files":[상대 경로…],"hashes":{상대 경로: 소문자 SHA-256 hex}}`; `hashes`는 `installed` 기록에만 있고(2026-11-01부터) 예전 기록(`hashes`·`commit` 없음, 예전 배포 zip 설치)도 읽는다)이 있으면 `hashes`의 각 파일을 설치 폴더의 파일과 비교해 다르거나 없으면 경고("설치한 뒤 바뀐 파일이 있습니다 … 이번 설치가 소스의 파일로 다시 씁니다")를 출력하고, "기존 설치를 찾았습니다 … 업그레이드합니다"(같은 버전·커밋이면 "바뀐 파일만 고칩니다", 낮은 버전이면 경고)를 출력한다. 기록 없이 비어 있지 않거나 기록이 손상된 폴더는 종료 1. **권한:** 다른 로컬 사용자가 설치 폴더의 `yw-host.exe`·`yw-app.exe`·확장 파일·manifest를 바꾸면 지갑이 그 코드를 실행하므로, 남은 폴더(빈 폴더·이전 설치, 기본 경로 포함)는 폴더와 안의 모든 항목의 보안 설명자를 검사한다: 소유자가 현재 사용자·SYSTEM(`S-1-5-18`)·Administrators(`S-1-5-32-544`)가 아니거나, 그 밖의 SID(Users·Authenticated Users·Everyone 등)에 쓰기·추가·쓰기 특성·하위 삭제·삭제·권한 변경·소유권 가져오기(`GENERIC_WRITE`·`GENERIC_ALL` 포함)를 주는 허용 ACE가 있으면(상속 전용 ACE 포함, CREATOR OWNER의 상속 전용 ACE만 예외, 거부 ACE 무시) 종료 1. `-FixPermissions`이고 폴더가 현재 사용자 소유일 때만 폴더에 아래 DACL을 쓰고 안의 항목은 명시 ACE를 지워 상속만 받게 한 뒤 다시 검사한다. 새 폴더는 7에서 처음부터 현재 사용자·SYSTEM·Administrators 모든 권한(하위 상속), 부모 상속을 끊은 DACL로 만들고(`DirectorySecurity`로 생성, DACL만 `SetAccessControl`; `Set-Acl`은 SACL까지 써서 표준 사용자에게 `SeSecurityPrivilege` 오류), 만든 뒤 링크가 아님·소유자·DACL(보호됨, `Get-AclProblem` 통과)·빈 폴더를 다시 확인한다. 없는 상위 폴더(기본 경로의 `Programs` 포함)도 위에서 아래로 하나씩 같은 DACL로 만들고 같은 확인을 한다(만들기 직전에 이미 있으면, 또는 다른 사용자가 먼저 만들어 소유자가 다르면 종료 4). 그래서 `C:\` 바로 아래처럼 Authenticated Users가 폴더를 만들 수 있고 만든 폴더에 수정 권한을 물려주는 곳에서도 새 폴더는 안전하지만, 안내 문구는 사용자 프로필 아래 경로를 권한다.
7. 계획과 복사: 설치 파일 = `yw-app.exe`·`yw-host.exe`(빌드 결과), `uninstall.ps1`, `extension/<3의 목록>`. 대상 SHA-256이 같으면 건너뛰고, 이전 기록에만 있는 파일은 지운다. 덮어쓰거나 지울 파일을 `FileShare.None` 쓰기 열기로 시험해 잠긴 파일과 그 파일을 실행 중인 yw-app·yw-host(PID)를 보이고, 닫는 방법(yw-app 창 닫기 = 잠금 후 정상 종료, 창이 숨어 있으면 시작 메뉴 실행으로 창 표시, yw-host는 Chrome 종료)을 안내한 뒤 Enter(다시 확인)·`C`(yw-app에 `CloseMainWindow` = `WM_CLOSE`, 15초 대기)·`Q`(종료 3)를 묻는다. **프로세스를 강제 종료하지 않는다.** 비대화형이면 묻지 않고 종료 3. 다른 경로의 yw-app이 실행 중이면 단일 인스턴스([04] §1.1) 때문에 설치본이 그 창을 띄운다고 경고한다. 복사: 기록을 `installing`(이전 ∪ 새 목록)으로 먼저 쓰고, 파일마다 복사 후 해시 재확인, 이전 설치 파일 삭제와 빈 하위 폴더 정리. 실패는 종료 4. 확장은 사본이므로 `git pull`만으로는 Chrome에 로드된 확장이 바뀌지 않는다.
8. manifest: `<설치 폴더>\com.your_wallet.native.json`, [05] §9.1 형식의 `[ordered]` → `ConvertTo-Json -Depth 3`, UTF-8 BOM 없음, 내용이 같으면 쓰지 않는다. 쓴 파일을 [05] §9.3 `validate-manifest.mjs`와 같은 규칙의 PowerShell 구현으로 검증(정확한 키 5개, 이름·`stdio`, 설명 1–128자, `path` = 드라이브 절대 경로·구간 규칙·마지막 `yw-host.exe`(대소문자 무시)·`%&^!`·자리표시자 없음, `allowed_origins` = 정확히 `chrome-extension://<id>/` 하나, BOM·잘못된 UTF-8 거부). 두 구현의 일치는 §9.4가 시험한다. 실패는 종료 5. `-NoNativeHost`여도 manifest는 쓴다.
9. 등록(`-NoNativeHost`가 아니면): `HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.your_wallet.native` 기본값 = manifest 경로(`New-Item -Force` + 다시 읽기). 이미 같으면 그대로, 다른 값(예: 예전 개발용 `%LOCALAPPDATA%\YourWallet\bin`)이면 이전 값을 출력하고 바꾼다. 실패는 종료 5. Chrome 외 브라우저(Edge 등)는 등록하지 않는다.
10. 바로가기(`-NoShortcut`가 아니면): `[Environment]::GetFolderPath('Programs')\Your Wallet.lnk`, `WScript.Shell` COM, 대상 `yw-app.exe`, 인자 없음, 작업 폴더 = 설치 폴더, 아이콘 `yw-app.exe,0`(exe의 첫 아이콘 그룹 = 앱 아이콘, [04] §1.7). 실패는 종료 6.
11. 기록을 `installed`(새 목록, 설치 폴더 파일마다 SHA-256 `hashes`)로 쓰고(같으면 쓰지 않음), 대화형이면 `<설치 폴더>\extension` 경로를 클립보드에 넣은 뒤 요약을 출력한다: 설치 경로와 소스(버전·커밋), "Chrome → chrome://extensions → 개발자 모드 → 압축해제된 확장 프로그램 로드 → `<설치 폴더>\extension`"(클립보드에 넣었으면 그 안내, ID 확인), 업그레이드면 "확장 카드에서 새로고침", 첫 실행·RPC 안내, 업데이트(`git pull` → `install.cmd`), 제거(`uninstall.cmd`), 지갑 데이터 위치.

`-DryRun`은 1–4의 확인과 5–10의 할 일 출력만 하고 빌드·winget·파일·레지스트리·바로가기·클립보드를 바꾸지 않는다(7에서 묻지 않는다). 같은 소스로 다시 실행하면 아무 파일도 다시 쓰지 않는다(멱등; 변경 없는 재빌드는 exe를 다시 링크하지 않고, `/Brepro`라 같은 입력은 같은 exe다). 예상하지 못한 예외는 줄 번호와 함께 종료 9. 지갑 데이터 `%LOCALAPPDATA%\YourWallet\`은 어떤 경로로도 읽거나 쓰지 않는다. 점 소싱(`. .\scripts\install.ps1`)하면 함수만 정의된다(§9.4).

| 종료 코드 | 뜻 |
|---|---|
| 0 | 성공(`-DryRun` 포함) |
| 1 | 환경·인자 오류(저장소 파일 없음, 2·6의 경로·상위 폴더·폴더·권한 규칙, 소스·빌드 폴더 권한(`-AllowUnsafeSourcePath` 없음)) |
| 2 | 소스·빌드 결과 오류(3의 확장 파일·ID, `rust-toolchain.toml`이 1.95.0이 아님, `-NoBuild`인데 exe 없음) |
| 3 | 취소 또는 비대화형이라 물을 수 없음(7) |
| 4 | 파일 복사·삭제·기록 실패 |
| 5 | manifest 검증·HKCU 등록 실패 |
| 6 | 시작 메뉴 바로가기 실패 |
| 7 | 빌드 도구 없음(4), 다른 사용자가 바꿀 수 있는 위치의 Rust 도구(4, `-AllowUnsafeToolchainPath` 없음), cargo·rustc가 1.95.0이 아님·Rust 기본 대상이 msvc가 아님·저장소 바깥 상위 폴더의 cargo 설정 파일(5, `-AllowAncestorCargoConfig` 없음) |
| 8 | 빌드 실패 |
| 9 | 예상하지 못한 오류 |

### 9.3 `scripts/uninstall.ps1`

`uninstall.cmd [-InstallDir <폴더>] [-NoShortcut] [-NoNativeHost] [-RemoveWalletData] [-DryRun]`. `-InstallDir` 기본값은 스크립트 옆에 `yw-install.json`이 있으면(설치 폴더 안의 사본) 그 폴더, 아니면 `%LOCALAPPDATA%\Programs\YourWallet`.

1. 현재 폴더를 임시 폴더로 옮긴다(설치 폴더 안의 사본을 실행해도 폴더를 지울 수 있게). 설치 경로가 지갑 데이터 폴더와 겹치면 종료 1.
2. 지울 프로그램 파일 = `yw-install.json` 목록(경로 검사, 설치 폴더 밖 무시) + manifest + 기록 파일. 기록이 없거나 손상된 비어 있지 않은 폴더는 파일을 지우지 않고(바로가기·등록은 처리) 종료 1.
3. `-RemoveWalletData`: 무엇이든 지우기 전에 `%LOCALAPPDATA%\YourWallet` 전체 삭제 확인을 받는다. 24단어 안내를 출력하고, 대화형일 때만 `DELETE MY WALLET`(대소문자 구분) 입력을 받는다. 불일치·비대화형은 아무것도 지우지 않고 종료 3. 이때는 위치와 상관없이 실행 중인 yw-app도 닫아야 한다.
4. install.ps1 7과 같은 방식(강제 종료 없음)으로 잠긴 `yw-app.exe`·`yw-host.exe`를 닫아 달라고 묻는다. 취소·비대화형은 종료 3.
5. 바로가기는 대상이 `<설치 폴더>\yw-app.exe`일 때만, HKCU 키는 기본값이 `<설치 폴더>\com.your_wallet.native.json`일 때만 지운다(다른 설치의 등록은 남기고 출력).
6. 프로그램 파일 삭제 → 빈 하위 폴더 → 비었으면 설치 폴더. 기록에 없던 파일은 남기고 경고한다.
7. 지갑 데이터는 3에서 확인받았을 때만 지운다. 그 밖에는 "지우지 않았습니다"와 경로를 출력한다.
8. 마지막에 Chrome 확장 카드 삭제 안내, "24개 복구 단어(쓴 경우 passphrase 포함)가 유일한 백업" 안내, 지갑 데이터 폴더 위치를 출력한다.

종료 코드: 0 성공(`-DryRun`, 이미 제거됨 포함), 1 환경 오류·기록 없는 폴더, 3 취소·확인 문구 불일치·비대화형, 4 일부 항목 삭제 실패, 9 예상하지 못한 오류.

### 9.4 시험 (`scripts/install.test.mjs`)

check.ps1 script-test 단계(26)에서 실행한다. `install.cmd`가 쓰는 Windows PowerShell 5.1로 실제 스크립트를 실행하되 빌드하지 않는다(`-NoBuild` + 가짜 exe가 든 `CARGO_TARGET_DIR`; 빌드 함수는 가짜 `.cmd` 도구로 시험). 자식 프로세스의 `LOCALAPPDATA`와 설치 폴더는 임시 폴더이고 `-NoShortcut -NoNativeHost -NonInteractive`라 HKCU·시작 메뉴·클립보드를 바꾸지 않는다(HKCU는 읽기만). 시험마다 만든 임시 폴더는 `icacls /inheritance:r`로 상속을 끊고 현재 사용자·SYSTEM·Administrators 모든 권한만 준다: 호스트 `%TEMP%`의 ACL(다른 계정에 준 수정 권한 등)에 결과가 좌우되지 않게 한다.

- INS-1 일치(5.1, 그리고 `pwsh.exe`가 있으면 7): 점 소싱한 `Test-NativeManifestFile`과 `validateNativeManifestFile`의 판정이 manifest 표본 44개(정상, 대문자 `YW-HOST.EXE`, 공백·한글 경로, 드라이브 바로 아래, 설명 128·129자·이모지 130단위·빈 설명, 다른 ID, origin 2개, 끝 `/` 없음, 끝 `\n`, 대문자 ID, 와일드카드, 자리표시자, origin 문자열·빈 배열, 키 추가·누락, 이름·`type`, `%`·`&`·`^`·`!`, 제어 문자, 상대·UNC·`..`·끝 점·끝 공백·빈 구간·`/` 구분·드라이브 루트, `yw-app.exe`, 접미사만 일치, 숫자 `path`, JSON 아님, 최상위 배열·null, UTF-8 BOM, 잘못된 UTF-8)에서 같다. `Get-ExtensionRuntimeFiles extension` = `auditExtensionRoot("extension").packagedFiles`, `$ExtensionId` = `extension/extension-id.txt`, `Get-ExtensionIdFromKey` = `extensionIdFromKey`.
- 흐름(5.1): 기본 폴더 `-DryRun` → 0, 폴더 없음. 설치 → 0, 설치 폴더 = 설치 파일 + manifest + 기록, 확장 파일 바이트 일치, manifest가 `validateNativeManifestFile` 통과, 기록의 버전·상태·목록. 재실행 → 수정 시각 불변. 예전 zip 기록(`README-설치.txt` 포함)에서 업그레이드 → 바뀐 exe 복사, 그 파일 삭제, 기록 갱신. 거부(`a&b` 경로, 기록 없는 비어 있지 않은 폴더, 데이터 폴더 아래, 저장소 아래 → 1; exe 없는 `-NoBuild` → 2) 때 아무것도 생기거나 바뀌지 않음. 설치 폴더의 `uninstall.ps1`로 `-DryRun` → 불변, `-RemoveWalletData`(비대화형) → 3·불변, 제거 → 0·설치 폴더 없음·데이터 폴더 그대로·그 경로 출력, 다시 제거 → 0.
- 권한(5.1): 점 소싱한 `Get-AclProblem`의 SDDL 표본(소유자 Everyone·Users → 거부, SYSTEM·Administrators 소유 → 통과, CREATOR OWNER 상속 전용 → 통과·상속 전용 아님 → 거부, Users 상속 전용 수정·Authenticated Users·Everyone 수정, DELETE·WRITE_DAC·WRITE_OWNER·`GA`·`GW` → 거부, Users 읽기·Everyone 거부 ACE → 통과, NULL DACL → 거부). 새 설치 폴더 → 보호된 DACL에 현재 사용자·SYSTEM·Administrators 모든 권한 3개만(상속 아님), 설치 파일은 그 셋만 상속. Everyone:Modify ACE를 더한 빈 폴더 → 1, 아무것도 쓰지 않고 ACL 그대로(`-FixPermissions -DryRun`도 그대로) → `-FixPermissions` → 0, 같은 3개 ACE. 이전 설치의 `yw-host.exe`에 Everyone:Modify → 1 → `-FixPermissions` → 0, 상속만.
- 소스 거부(저장소 사본): manifest `key`가 다른 ID → 2, `extension/icons`에 `.png`가 아닌 파일 → 2, `extension/src`에 `.js`가 아닌 파일 → 2, 모두 설치 폴더가 생기지 않음.
- 상위 폴더(5.1, `-InstallDir`): 없는 중간 폴더 2개 아래 설치 → 0, 만든 세 폴더 모두 보호된 3개 ACE. 그리고 각각 `-InstallDir <A>\YourWallet`(또는 그 아래): Everyone `(DC)` → 1(`-DryRun`도 1), 아무것도 생기지 않음; Users `(OI)(CI)M`을 물려받은 기존 중간 폴더 → 1; Authenticated Users `(WDAC)` → 1; 정션 → 1, 대상 폴더 그대로; Authenticated Users `(AD)` + `(OI)(CI)(IO)M`(`C:\` 모양) 아래 없는 폴더 → 0, 그 폴더는 보호됨; INTERACTIVE `M`(그 폴더만) + Everyone 읽기(`%TEMP%` 모양, 부모는 추가 권한 없음) → 0.
- 빌드 도구 위치(5.1, 점 소싱한 `Get-RustTools`·`Get-ToolPathProblem`): `CARGO_HOME` 절대 경로 → `<CARGO_HOME>\bin\*.exe`; 없음·상대 경로·빈 값 → `%USERPROFILE%\.cargo\bin`; 두 곳에 없고 PATH에만 가짜 `cargo.exe` → 모두 null. 도구 파일 하나에 Everyone:M → 그 파일만 문제, bin 폴더에 Everyone `(OI)(CI)M` → 세 파일 모두 문제(경로에 bin 포함). 심볼릭 링크를 만들 수 있으면 링크 대상 폴더에 Everyone:M → 링크한 도구가 문제(대상 경로 포함). 실제 스크립트 `-DryRun`: 위 쓰기 가능 bin → 7, 출력에 `-AllowUnsafeToolchainPath`; 그 스위치를 붙이면 0이고 계획에 그 cargo 전체 경로; PATH에만 cargo → 0, 그 경로는 "쓰지 않는다"로만 나온다.
- cargo 설정 파일(5.1, 밀폐: 설정 파일은 모두 임시 트리 안에 만들고, 임시 루트 위 폴더의 결과는 걸러 낸다): 점 소싱한 `Get-AncestorCargoConfigs` — `<t>\outer\mid\repo`의 상위 `<t>\outer\mid\.cargo\config`·`<t>\outer\.cargo\config.toml` → 두 경로(가까운 것부터), 저장소 자신의 `.cargo` 제외, CARGO_HOME = `<t>\OUTER\.cargo`(대소문자 다름)이면 그 폴더 제외. `Get-CargoConfigRiskyKeys` 표본: 주석·문자열 안 `#`, `[build] rustc-wrapper`, `[target.<triple>] linker`, `[target.'cfg(windows)'] rustflags`, `[profile.release]` vs `[profile.dev]`, `[patch.crates-io]` 인라인 표, `[source.crates-io] replace-with`, 점 키·따옴표 키·중첩 인라인 표·`paths`; `rustdoc`·`[env]`·`runner`·`[registries]`는 키 아님. 저장소 사본 `-DryRun`(기본 폴더 = 임시 프로필 아래): 상위 `.cargo\config.toml` → 7, 목록에 그 경로, 출력에 `-AllowAncestorCargoConfig`, 빌드 계획 없음; 스위치 → 0, 계획에 새 `--config` 세 개, `CARGO_HOME\config.toml`의 위험 키 이름 경고(`profile.dev` 아님); CARGO_HOME이 그 상위 `.cargo`이면 임시 트리 경로는 거부 목록에 없음.
- 빌드(5.1, 그리고 `pwsh.exe`가 있으면 7; 점 소싱한 `Invoke-Build`에 가짜 `rustup.cmd`·`cargo.cmd`·`rustc.cmd`): `CC`·`CC_<triple>`(밑줄·하이픈)·`CFLAGS`·`CFLAGS_<triple>`·`CXX`·`CXXFLAGS`·`CXXFLAGS_<triple>`·`RUSTC`·`RUSTC_WRAPPER`·`RUSTC_WORKSPACE_WRAPPER`·`CARGO_BUILD_RUSTC`·`CARGO_BUILD_RUSTC_WRAPPER`·`CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER`·`CARGO_PROFILE_RELEASE_*`(패키지별 포함)·`RUSTFLAGS`·`CARGO_ENCODED_RUSTFLAGS`를 설정해 실행 → 0. 가짜 도구가 받은 호출이 정확히 `+1.95.0 --version`, `+1.95.0 -vV`, 빌드 인자 하나씩이고, 빌드 인자 = `+1.95.0`, `--config profile.release.<키>=<값>`(큰따옴표·공백 없음; 따옴표를 뗀 값의 집합이 저장소 `Cargo.toml` `[profile.release]`와 같음), `--config build.rustc-wrapper=''`·`--config build.rustc-workspace-wrapper=''`·`--config target.x86_64-pc-windows-msvc.linker='link.exe'`, `build --release --locked -p yw-app -p yw-host`. 빌드 프로세스 환경에 위 변수가 하나도 없고 관계없는 변수와 PATH는 남음, `Invoke-Build`가 끝난 뒤 위 변수가 원래 값으로 돌아옴. 가짜 cargo가 `1.94.0`·`1.95.0-nightly`, 가짜 rustc가 `1.96.0`이면 → 7, 빌드 호출 없음.
- 소스·빌드 폴더 권한·설치 기록 해시(5.1, 2026-11-01 검토 L7, 밀폐 저장소 사본): AppContainer SID(`*S-1-15-2-1`)의 수정 권한 → 무시하고 0; 점 소싱한 `Get-SourceAclProblem`은 S-1-4-* 쓰기 ACE 무시·Authenticated Users 거부, `Get-AclProblem`(설치 폴더 규칙)은 S-1-4-*도 거부. Authenticated Users 수정 권한을 저장소 루트·`extension\manifest.json`·release 폴더·`yw-host.exe`에 각각 주면 → 1, 설치 폴더 없음, `-AllowUnsafeSourcePath` → 0 + 경고. 흐름 시험: 설치 기록 `hashes` 키 = 설치 파일 목록, 값 = 각 파일 SHA-256; 같은 소스 재실행에 경고 없음; 설치된 `yw-host.exe`를 바꾸면 다음 실행이 그 이름으로 경고하고 원래 내용으로 되돌림. `check.ps1`의 지울 변수 이름·접두사·`--config`가 install.ps1과 같고(게이트는 `CARGO_PROFILE_` 전체) clippy·test·fuzz·build 단계가 그 `--config`를 넘김(정적 비교).

winget 제안·실제 빌드·HKCU 등록·바로가기·클립보드·잠긴 파일 대화는 자동 시험하지 않는다([09] §5.12 수동). 깨끗한 환경에서 설치 프로그램을 손으로 시험할 때는 Windows 샌드박스(Windows Sandbox)를 쓸 수 있다.

### 9.5 한계

- 코드 서명을 하지 않는다(D1). 그 PC에서 빌드한 exe에는 인터넷 영역 표시(MOTW)가 없어 보통 SmartScreen 창이 뜨지 않지만, 스마트 앱 컨트롤이 켜진 PC에서는 서명 없는 exe 실행이 막힐 수 있다. GitHub "Download ZIP"으로 받은 `install.cmd`에는 MOTW가 붙어 열 때 경고가 뜰 수 있다(zip 속성의 "차단 해제" 후 압축 풀기, 또는 "실행").
- 진본 확인의 기준은 소스(저장소 출처와 커밋)와 `Cargo.lock` 체크섬이다. 설치는 그 PC에서 빌드한 결과만 복사하므로 별도 해시 목록을 두지 않는다.
- 자동 업데이트는 없다. 업데이트는 `git pull`(또는 새 ZIP) 후 `install.cmd` 재실행.
- 첫 빌드는 인터넷이 필요하다(rustup 툴체인, crates.io). Build Tools 설치는 관리자 권한 확인과 수 GB 내려받기가 필요하다.
- 도구 위치 검사는 rustup 프록시(`<bin>\rustup.exe`·`cargo.exe`·`rustc.exe`와 링크 대상)까지다. 프록시가 실행하는 `RUSTUP_HOME`(기본 `%USERPROFILE%\.rustup`)의 툴체인 파일, MSVC·Windows SDK(관리자 설치), 링크 자체의 보안 설명자(읽으면 대상의 것이 나온다)는 검사하지 않는다. 명령줄 `--config`는 `[profile.release]`의 6개 키만 다시 준다: cargo가 저장소 루트의 상위 폴더와 `CARGO_HOME`에서 읽는 `.cargo\config.toml`의 다른 설정(예: `build.rustc-wrapper`, `target.<triple>.linker`·`rustflags`, `[profile.release.package.*]`, source 교체)은 막지 않는다.
