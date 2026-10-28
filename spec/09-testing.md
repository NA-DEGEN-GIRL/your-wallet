# 테스트·판정 기준

상위 문서: [spec.md](../spec.md)

- 범위: spec.md §2.3 게이트 규칙과 §5 완료 조건을 판정하는 방법 — 테스트 배치, `scripts/check.ps1`, 퍼징, 라이브 확인, 기지 답(KAT) 벡터 전체 목록, 부정·보안 테스트, M0–M9 체크리스트, 프로토콜 변경 회귀 절차.
- 02–08의 테스트 표는 각 모듈의 사례 목록이다. 이 문서는 (a) 값 전문([03](03-evm.md) §13이 위임), (b) 여러 문서에 걸친 테스트, (c) 마일스톤 판정 순서를 정한다. 같은 항목이 양쪽에 있으면 **값은 이 문서, 사례 목록은 해당 문서**가 정본이다.
- 출처 표기: **[공식]** 표준 문서·원 저자 벡터, **[아카이브]** `archive/spec-v2.4`의 테스트, **[로컬]** 이 문서 작성 중 공식 벡터를 먼저 재현한 독립 구현(순수 Python secp256k1·Ed25519·Keccak, libsecp256k1 0.31.1)으로 계산한 값.

## 1. 원칙

1. 모든 완료 조건은 셋 중 하나로 판정한다: (a) `scripts/check.ps1`의 자동 테스트, (b) 수동 실행 도구(§2.4 퍼징, §2.5 라이브 확인), (c) §5 체크리스트 1회 수행. 판정 방법이 없는 조건은 만들지 않는다(spec §2.3).
2. 문서 내용 해시 고정, 소스 모양 문자열 검사는 만들지 않는다. 허용되는 고정값은 **프로토콜·형식 출력의 KAT**뿐이다: 서명·주소·직렬화 바이트, 우리 파일 형식의 골든 바이트, 프로토콜 데이터(BIP39 단어 목록)의 해시.
3. 테스트는 코드 옆에 둔다(§2.1): 단위 테스트는 같은 파일의 `#[cfg(test)] mod tests`, 내부 항목(`pub(crate)`·`#[cfg(test)]`)이나 니모닉·키 값이 필요한 테스트는 `src/<모듈>/tests.rs`(01 §4.3 privacy 면제), 공개 API만 쓰는 KAT는 `crates/<crate>/tests/*.rs`, 벡터 데이터는 `crates/yw-core/tests/vectors/`(`*.rs` 상수 표 또는 원본 그대로 복사한 `*.json`). yw-core는 일반 의존성으로 yw-json을 쓴다(D5, 01 §2.4). `[dev-dependencies]`는 모든 멤버에서 금지다(01 §2.4). 벡터 JSON은 `include_str!("…/vectors/<file>.json")`로 컴파일 때 넣고 `yw_json::parse(…, &Limits::RESPONSE)`로 읽는다(1 MiB를 넘는 파일은 테스트가 더 큰 `Limits` 값을 만든다). yw-core 테스트는 `std::fs`를 쓰지 않는다(`crates/yw-core/clippy.toml`, 01 §5.1).
4. `cargo test`는 외부 네트워크·API 키·사람 조작 없이 통과해야 한다. loopback mock 서버(127.0.0.1:0)는 허용한다([06](06-llm-explain.md) §10). 외부 네트워크가 필요한 확인은 §2.5(`scripts/probe-rpc.mjs`, `#[ignore]` `live_probe`)나 §5로만 한다.
5. 결정성: 시각은 인자(단조 `now_ms: u64` = yw-win `time::monotonic_ms` 값, 벽시계 `now_unix_ms: u64`; yw-core는 `Instant`·`SystemTime` 금지, 01 §2.2·§5.1)로, 난수는 `#[cfg(test)]` 주입(`ScriptedRandom`·`FailingRandom`, [02](02-core-keys-vault.md) §1.1, 따라서 `src/<모듈>/tests.rs`)으로 넣는다. OS 시계·OS RNG 결과를 단정하지 않는다.
6. 공식 벡터는 출처 바이트 그대로 복사하고 고치지 않는다. 실패하면 코드를 고친다. [로컬] 값이 공식 값과 충돌하면 공식 값을 따르고 이 문서를 고친다.
7. 체크리스트 결과는 `docs/acceptance/<M>-<YYYYMMDD>.md`에 남긴다: 커밋 해시, 빌드 프로필, 항목 ID별 통과/실패와 한 줄 메모, 측정값(예: Argon2 시간). 니모닉·비밀번호·API 키·RPC 엔드포인트 URL·호스트·토큰(D13, 대상은 `NetworkId`로만)·주소록 이름은 적지 않는다(주소·tx hash는 D28 허용 범위).
8. 마일스톤은 이전 마일스톤의 자동 테스트를 깨지 않아야 한다(spec §5). 각 마일스톤 판정 시 `check.ps1` 전체를 그 커밋에서 다시 실행한다.

## 2. 배치와 실행

### 2.1 크레이트별 배치

| 위치 | 내용 | 실행 |
|---|---|---|
| `crates/yw-core/src/**` | 단위 테스트(같은 파일 `mod tests`, 니모닉·키 값 없음) | `cargo test` |
| `crates/yw-core/src/<모듈>/tests.rs`(`#[cfg(test)] mod tests;`, 모듈 이름은 01 §2.2) | 내부 API가 필요한 테스트: `entropy`(02 §11.1), `bip39`(§3.2), `bip32`(§3.3, `ckd_from_il`), `evm/address`(ACC-1–5), `evm/sign`(§3.5, legacy 인코더), `vault`(§3.12 G1–G5, 02 §11.6–11.8의 변조 표·`PayloadRewrite`·`change_password`·상태 기계·백업: `KDF_TEST`·`MemStorage`·`HeapSlot`·KDF 호출 카운터), `journal`(M4, §3.13 V13) | `cargo test` |
| `crates/yw-core/tests/{evm_accounts,evm_consts,evm_abi,evm_simulate,evm_eip712,evm_eip191,evm_siwe,evm_approval,evm_journal,sol_*,btc_*}.rs` | 공개 API만 쓰는 KAT·부정·상태 기계. 내부 항목이 필요해지면 그 테스트를 `src/<모듈>/tests.rs`로 옮긴다(SOL·BTC 서명·파생 KAT 포함) | `cargo test` |
| `crates/yw-core/tests/vectors/` | 벡터 데이터 + `SOURCES.md`(파일별 URL, 원본 커밋, 가져온 날짜, 라이선스) | — |
| `crates/yw-json/tests/` | 엄격 파서·한도 골든·프레이밍(05 R-F1, R-J1) | `cargo test` |
| `crates/yw-win/tests/` | 실제 Win32: DPAPI 왕복(§4.1 V-DPAPI), 파일 쓰기·이동 래퍼. 파일은 `std::env::temp_dir()` 아래 새 폴더 | `cargo test` |
| `crates/yw-app/src/lib.rs` + `tests/` | GUI를 뺀 로직: RPC 응답 파서, 정책, 저널 구동, 승인 상호작용 상태 기계, 봉투, 디스패처, `VaultStorage` 구현의 중단 지점(§4.1 V-FS, `#[cfg(test)] commit_until`을 쓰므로 `src/store.rs`의 단위 테스트), pipe DACL·첫 인스턴스(05 R-P2, 이름 `\\.\pipe\YourWallet.test.<pid>.<n>`). 픽스처 `tests/fixtures/eth_simulateV1/`. 사용자 체인 추가·제네시스 고정·메서드별 호출 수는 가짜 RPC 전송(호출 기록)으로(§4.2 X-21–X-24, 03 EVM-V16, EVM-V17의 `flow::evm` 사례) | `cargo test` |
| `crates/yw-app/tests/live_probe.rs` | §2.5 L-LIMITS, 03 §1.5 A6–A8·A9(c)–(e), 03 §1.2 확인 행(`eth_getCode`·`decimals`·`symbol`·Seaport `information()`·`getConduit`·999 Permit2 immutable 제외 비교), 앱 경로 체인 확인과 읽기 전용 `prepare`(서명·전송 없음) (`#[ignore]`, 엔드포인트는 01 §4.6 개발 설정, 출력은 `NetworkId`만) | 수동 |
| `scripts/probe-rpc.mjs` | §2.5 L-SIM·L-REVERT·L-HYPEREVM·L-GENESIS. 정본 01 §4.7(Node 22, npm 의존성 0). `*.test.mjs`가 아니므로 `node --test`·check.ps1 대상 아님 | 수동 |
| `crates/yw-host/src/lib.rs` + `tests/` | 인자(R-H1)·UNAVAILABLE 응답기(R-H2)·중계·크기 초과 종료 코드(R-H3)·`auto_launch_enabled`와 연결 루프(R-H4) — 05 §10.2 R-H1–R-H4. 실제 프로세스 시험은 05 H1(`extension/tests/yw-host-process.test.mjs`) | `cargo test` |
| `extension/tests/*.test.mjs` | node:test(05 §10.1) | `node --test` |
| `scripts/*.test.mjs` | privacy-scan, check-core-deps | `node --test` |
| `fuzz/` | 별도 워크스페이스(§2.4) | 수동 |
| `tools/btc-oracle/`, `tools/sol-oracle/` | 차등 오라클(08 §14.3, 07 §17.3 교차 확인). 저장소 안의 별도 워크스페이스(각자 `[workspace]`·`Cargo.lock`), 루트 `Cargo.toml` `[workspace] exclude`(01 §3.1). 의존성 허용 목록·`check-core-deps.mjs`·check.ps1 대상이 아니고 어떤 배포 바이너리에도 들어가지 않는다 | 수동 |
| `extension/test-dapp/` | M5 수동 E2E 페이지(§5.7) | 수동 |

- yw-app·yw-host는 `src/lib.rs`(로직)와 `src/main.rs`(진입점)로 나눈다. 퍼징·통합 테스트가 파서를 직접 부르기 위해서다.
- GUI(창·그리기)는 자동 테스트하지 않는다. 승인 창 A01은 렌더 하네스 `cargo test -p yw-app --lib app_approval::smoke -- --ignored`(픽스처 준비 결과를 실제 `App` 승인 경로에 넣어 몇 초 띄움, 네트워크·키 없음; `YW_SMOKE_FIXTURE`·`YW_SMOKE_HOLD_MS`)로 사람이 캡처해 확인한다(판정용 자동 테스트 아님). 승인 상호작용·비밀 입력 버퍼·잠금 판정은 순수 상태 기계로 분리해 테스트한다([04](04-app-ui.md) §3.9, §4.10, §5.4).
- 장애 주입: yw-app은 **debug 빌드에서만**(`cfg!(debug_assertions)`) 환경 변수 `YW_FAULT_POINT`를 읽고, 이름이 같은 지점에 도달하면 `std::process::abort()`한다. release 빌드는 읽지 않는다(05 §10.1의 yw-host 시험용 변수 `YW_TEST_PIPE_NAME`·`YW_TEST_NO_SPAWN`·`YW_TEST_DATA_DIR`과 같은 방식). 지점 이름은 §5.5(M4-8)·§5.9(M7-4)·§5.10(M8-4).
- 프로필: 루트 `Cargo.toml`의 `[profile.dev.package."*"] opt-level = 3`(01 §3.1, argon2·blake2 포함). 운영 파라미터 Argon2(256 MiB)는 §3.12 G1·G3·G4·G5의 4회만 쓰고, 나머지는 `KDF_TEST`(02 §4.5)를 쓴다.

### 2.2 `scripts/check.ps1`

단계·순서·종료 코드·인자(`-Step`, `-Offline`)는 [01](01-repo-build.md) §4.1이 정본이다(D31). 요약: 도구 확인(10 = cargo 1.95.0·Node 22+ 없음, 11 = rustflags 환경 변수 설정됨) → fmt 20 → deps 21(`check-core-deps.mjs`) → clippy 22 → test 23 → build 24(`cargo build --workspace --locked`, 05 H1이 쓰는 `target\debug\yw-host.exe`) → `YW_CHECK=1` 설정 → ext-test 25 → script-test 26 → privacy 27 → audit-ext 28. 0 = 통과, 1 = 스크립트 자체 오류. 첫 실패에서 멈춘다. 대상 PC에서 전체 10분 이내를 목표로 한다(권고).

- deps 출력 `yw-core deps check OK: <N> crates (x86_64-pc-windows-msvc)`의 `<N>`: M0–M6 = 34(런타임 30 + 빌드 4, D5), M7 이후 40(+런타임 4·빌드 2; M8은 추가 없음). 같은 단계의 yw-app 줄은 37 / 43.
- `YW_CHECK=1`이면 05 H1은 skip 대신 실패한다.
- check.ps1이 실행하지 않는 것: 퍼징, `--ignored` 테스트, `scripts/probe-rpc.mjs`, 오라클(`tools/`), 체크리스트.

### 2.3 이식 테스트

02 §12, 03 §0, 05 §10.2, 07 §14.1, 08 §14가 이미 적은 출처는 생략한다. 아래는 그 밖의 항목이다.

| 출처 | 새 위치 | 처리 |
|---|---|---|
| `archive/spec-v2.4:crates/wallet-model/src/bounded.rs:390-478` | yw-core `evm::amount`·`evm::address` | 대문자 hex 거부 단정(455-462)은 EIP-55 규칙(03 §2.1)으로 반대로 |
| `archive/spec-v2.4:crates/wallet-model/src/codec.rs:190-205` | yw-core `codec::transcript`(`Transcript`) | 그대로 |
| `archive/spec-v2.4:crates/wallet-model/src/operation.rs:564-604` | yw-core `evm::eip191` | 그대로(EIP-191 10진 길이) |
| `archive/spec-v2.4:crates/wallet-protocol/src/approval.rs:708-765` | yw-core `approval` | 03 §11.4 transcript로 |
| `archive/spec-v2.4:crates/wallet-protocol/src/authorization.rs:1105-1166` | yw-core `approval` | 1322-(typed data 거부)는 반대로 |
| `archive/spec-v2.4:crates/wallet-protocol/src/validation.rs:330-441`, `error.rs:166-177` | yw-app `browser::params`(M5) | 오류 코드는 05 §5 |
| `archive/spec-v2.4:crates/key-agent/src/lib.rs:907-1051` | yw-core `src/evm/sign/tests.rs` | EIP-155: r·s 주입 대신 실제 RFC 6979 서명 단정 |
| `archive/spec-v2.4:crates/key-agent/src/durable.rs:1732-1940,2087-2157` | yw-core `journal::evm`(M4) | 저장소는 `MemStorage`, 상태는 03 §5.2 |
| `archive/spec-v2.4:crates/eip712/tests/vectors.rs:1-371` | yw-core `tests/evm_eip712.rs` | 212-256(바인딩 누락 거부)은 T03·T10으로 변경(03 §8.1) |
| `archive/spec-v2.4:crates/approval-ui/src/lib.rs:647-989` | yw-app 승인 상호작용 | 2초 누르기·클릭 관통·포커스 손실(03 §10.1, 04 §3.4·§3.9) |
| `archive/spec-v2.4:demo/sepolia-wallet/src/erc20.rs:1-583` 내 테스트 | yw-core `evm::abi` | `transfer` 68바이트 빌더·디코더 |
| `archive/spec-v2.4:demo/sepolia-wallet/src/rpc.rs:2132-3760` | yw-app `rpc::evm` | ureq 전송 → 가짜 전송 trait |
| `scripts/privacy-scan.test.mjs`(main 판, 유지 파일, 01 §1.3·§6. 태그 판은 쓰지 않는다) | 같은 경로 | 01 §4.3 테스트 추가: 새 규칙 5개(`alchemy-key-url`, `quicknode-url`, `llm-api-key`, `labeled-private-key-hex`, `bip39-word-sequence`; 규칙 전체 9개) 양성·음성(`<KEY>`·`<토큰>` 자리표시, `https://docs-demo.quiknode.pro/` 음성 포함), `TEST_VECTOR_PATH` 면제 경로, 기존 "retains all four …" → 9개 |
| `archive/spec-v2.4:extension/tests/{extension,native-contract,provider-main}.test.mjs` | `extension/tests/` | 05 §10.1(261·433·515 반전, `native-host-process.test.mjs` → H1) |

### 2.4 퍼징

- 위치: 저장소 루트의 `fuzz/`(cargo-fuzz 기본 배치). 자체 `[workspace]`와 `Cargo.lock`을 가진 별도 워크스페이스이며 루트 `Cargo.toml`의 `[workspace] exclude`에 넣는다. `libfuzzer-sys`와 cargo-fuzz는 여기서만 쓰고 D5 허용 목록 대상이 아니다(`check-core-deps.mjs`는 루트 워크스페이스만 본다). 배포 바이너리에 들어가지 않는다.
- 의존성: `yw-core`, `yw-json`, `yw-app`, `yw-host`(경로), `libfuzzer-sys`(만들 때 crates.io 최신으로 `=` 고정, 버전은 `fuzz/README.md`에 기록).
- 도구: `fuzz/rust-toolchain.toml`에 nightly 날짜 고정(`nightly-YYYY-MM-DD`, 만들 때 정함), `cargo install cargo-fuzz --locked`(버전 기록).
- 실행(저장소 루트): `cargo +nightly fuzz run <target> -s none --debug-assertions -- -max_total_time=600 -timeout=2 -rss_limit_mb=2048 -max_len=<표>`. 대상 크레이트는 unsafe가 없으므로 sanitizer 없이(`-s none`) 패닉·산술 오버플로·무한 루프·메모리 폭주만 찾는다.
- 시드 corpus `fuzz/corpus/<target>/`(커밋): 표의 출처 벡터. `fuzz/artifacts/`는 `.gitignore`.

| target | 진입(정본) | 불변식(위반 = 실패) | max_len | 시드 |
|---|---|---|---|---|
| `json` | `yw_json::parse(b, &Limits::REQUEST)`(05 §2.9) | 패닉 없음. Ok → 직렬화 → 재파싱이 같은 값. 중복 키·한도 초과는 항상 Err | 65,536 | 05 골든 전부 |
| `frame` | `yw_json::frame::read_frame`를 Cursor에서 EOF까지(05 §7.3) | 길이 > 1 MiB·0이면 페이로드를 읽기 전 `Oversized`. 읽은 프레임을 `write_frame`하면 입력 앞부분과 같은 바이트 | 8,192 | `02 00 00 00 7b 7d` |
| `envelope` | yw-app `browser::envelope` 파서(05 §6.5) | Ok → 인코드 → 파싱 동일 | 8,192 | 05 §10.3 골든 |
| `rlp` | `yw_core::evm::rlp::decode_exact`(03 §4.1) | Ok → 재인코딩 == 입력 | 4,096 | §3.5 서명 거래들 |
| `signed_tx` | `decode_signed`(03 §4.3) | Ok → 재인코딩 == 입력, 복구 주소 결정적 | 4,096 | EIP-1559 Besu |
| `abi` | `decode_call(chain, to, data)`; 첫 바이트로 `to`를 레지스트리 주소/임의 주소 중 선택(03 §7.2) | 패닉 없음. `Known`이면 같은 인수로 재인코딩 == data | 8,192 | §3.6 셀렉터 + 정규 인수 |
| `eip712` | yw-json 파싱 → `validate_typed_data_v4(src, v, 11155111)`(03 §8.1) | 패닉 없음. Ok → digest 두 번 계산이 같음 | 131,072 | Ether Mail, §5.7 T23–T27 |
| `simulate` | yw-app `rpc::evm` eth_simulateV1 응답 파서 → yw-core `evm::simulate` 해석(03 §6.2) | 패닉 없음. 결과는 diff 또는 §3.8 경고([결과 없음] E01·[실행 실패] E02·[결과 불완전] E03·E04·E07–E09) 중 하나. 응답 바이트만으로 승인 등급이 차단이 되지 않는다(D15·D16) | 65,536 | §3.8 S1–S11 |
| `siwe` | `evm::siwe` 파서(03 §9.3) | 패닉 없음. 파싱 성공 메시지는 필드 재조립 == 원문 | 4,096 | §4.2 SIWE 기본형 |
| `sol_base58` | `codec::base58::base58_decode_32`(07 §5) | Ok → 인코드 == 입력 | 64 | 07 §17.2 |
| `sol_shortvec` | `sol::shortvec::decode`(07 §6) | Ok → 인코드 == 소비한 바이트 | 8 | §3.9 표 |
| `sol_tx` | `parse_transaction`(07 §9) | Ok → 재인코딩 == 입력 | 1,232 | T_SOL·T_SPL 골든 |
| `sol_journal` | `journal::sol` 본문 디코더(07 §14.1 SOL body, 02 §5.4 `kind 0x02` entry의 body만) | 패닉 없음 | 2,048(02 §5.4 SOL 최대 본문보다 큼) | 왕복 테스트 출력 |
| `btc_tx` | `yw_core::btc::tx` 파서(08 §6.5) | Ok → 재직렬화 == 입력, txid 결정적 | 65,536 | BIP143 거래, Core `tx_valid.json` |
| `btc_address` | `parse_address(s, Mainnet/Testnet4)`(08 §6.3) | Ok → `encode_address`가 소문자 정규형이고 재파싱이 같은 `ScriptKind` | 128 | BIP173/350·key_io |
| `vault_header` | `peek_generation` + 디코드 1–7단계(02 §4.5) | 패닉 없음, Argon2 호출 0회 | 4,096 | §3.12 골든 |

- 판정: 마일스톤에 해당하는 대상 전부 600초씩, 충돌·시간 초과(입력당 2초)·RSS 초과 0건. 파서·디코더 코드가 바뀐 커밋 뒤에도 해당 대상을 다시 돌린다.
- 충돌 처리: `cargo fuzz tmin`으로 줄인 입력을 소유 크레이트의 `tests/regressions/<target>-<n>.bin`에 넣고 `include_bytes!` 회귀 테스트를 추가한 뒤 고친다.
- **구현 시 확인:** cargo-fuzz·libFuzzer가 x86_64-pc-windows-msvc nightly에서 `-s none`으로 빌드·실행되는지. 안 되면 대체 경로: 각 대상의 불변식을 소유 크레이트의 `#[test] #[ignore] fn fuzz_lite_<target>()`로 두고, 자체 xorshift64*(고정 seed 기록)로 시드를 비트 반전·바이트 삽입·삭제·잘라내기 변형해 대상당 1,000,000회 실행한다(`cargo test --release -- --ignored fuzz_lite`). 판정 기준은 같다. 외부 크레이트는 쓰지 않는다.

### 2.5 라이브 확인 (구현 시 확인)

외부 서비스 동작은 문서로 보장되지 않으므로 설정한 공급자(현재 QuickNode, D13)의 엔드포인트로 1회 관측한다. BTC 기본 인덱서 Esplora(공용 mempool.space, D26)는 URL이 비밀이 아니므로 `curl.exe -s -i`로 관측하고 출력을 그대로 기록할 수 있다(08 §4.5 E1–E3; `probe-rpc.mjs` 범위 밖). 공급자·엔드포인트·Esplora URL을 바꾸면 해당 묶음을 다시 한다(§6 R2).

- 엔드포인트(D13, 정본 01 §4.6): 환경 변수 `YW_RPC_JSON`(설정 파일 경로)이 있으면 그 파일, 없으면 `%USERPROFILE%\.yw-dev\rpc.json`(저장소 밖, `NetworkId` → HTTPS JSON-RPC URL 객체, 예 `{"eip155:1":"https://…","eip155:11155111":"https://…","eip155:999":"https://…"}`). 엄격 파싱·크기 한도·저장소 안 경로 거부는 01 §4.6. URL을 명령줄 인자·다른 환경 변수로 받지 않는다. URL 전체가 비밀이므로 URL·호스트(QuickNode는 엔드포인트 이름 포함)·토큰을 표준 출력·오류 출력·로그·기록 파일·패닉 메시지·커밋 메시지에 쓰지 않고 `NetworkId`로만 가리킨다. 앱 데이터(`apikeys.dpapi`)는 읽지 않는다. 제품 코드는 이 파일을 읽지 않으므로(01 §4.6) 앱을 거치는 E2E(§5)는 같은 URL을 앱 설정에 저장해(M3-8, DPAPI) 쓴다.
- 도구(같은 설정 출처): (1) `node scripts/probe-rpc.mjs` — 정본 01 §4.7(구현 완료). Node 22+, npm 의존성 0. 이 절은 판정만 정한다. (2) `cargo test -p yw-app --test live_probe -- --ignored --test-threads=1 --nocapture` — yw-app `rpc::evm`(M4) 경로로 L-LIMITS와 03 §1.5 A6–A8·A9(c)(e) 재현(`--nocapture`로 `<NetworkId> <검사> ok|err key=value` 줄을 본다). (3) `scripts/dev-rpc-setup.ps1`(01 §4.8) — 설정 파일 생성.
- 스크립트 출력(01 §4.7): 검사마다 `<NetworkId> <검사 이름> ok|err key=value…`(검사 이름 `eth_chainId`, `genesis`, `latest block`, `sim fresh 1wei`, `sim self 1wei`, `sim revert`, `sim no-funds`, `sim chainId+type`, Solana `getGenesisHash`, Bitcoin `getblockhash 0`·`getblockchaininfo`·`bb_getBlockHash 0`), 마지막 `summary:` 줄. `bb_getBlockHash 0` 줄은 Blockbook 애드온이 꺼져 있으면 `err code=-32601`이 정상이다(기본 인덱서는 `esplora`, 08 §4.3; `bb-rpc`를 쓰기로 했을 때만 `ok`가 기대값). 시뮬레이션 줄의 키: `status`, `gasUsed`(10진), `maxUsedGas`, `logs`, `nativeEmitter`(`eeee`·`fffe`·`none`), `errCode`, `revertData`. 오류 줄: `http`, `code`, 가린 메시지 80자. `sim no-funds`는 최상위 오류가 기대값이라 항상 `err`이다. 시뮬레이션 내용은 사람이 아래 표로 판정한다.
- 기록: `docs/acceptance/probe-<YYYYMMDD>.md`에 날짜, 스크립트 출력 전체(비밀 없음, 01 §4.7), 항목별 판정, `live_probe`가 관측한 필드 이름·오류 코드·지연. URL·호스트·토큰은 적지 않는다(`NetworkId`만).
- **1차 실측 완료(2026-10-27, QuickNode)**: 아래 L-SIM·L-REVERT·L-HYPEREVM·L-GENESIS 모두 기대대로(결과 요약은 03 §1.5). 999는 `/evm` 경로에서 `eth_simulateV1` -32601·블록 0 실패, `/nanoreth` 경로에서 모두 성공 → 템플릿 경로 `nanoreth`, 기본 `simulation = auto`. Bitcoin은 mainnet·testnet4 Core RPC 동작(`getblockhash 0` 제네시스 일치, `chain` `main`·`testnet4`), Blockbook 애드온은 미활성(`-32601`) — 기본 인덱서가 `esplora`이므로 M8을 막지 않는다(08 §4.5). 같은 날 mempool.space Esplora 응답 형태·제네시스도 확인했다(08 §4.5 사전 실측). 이 기록을 `docs/acceptance/probe-20261027.md`로 M0에서 옮긴다.

먼저 수행하는 프로브(`probe-rpc.mjs`, M2 착수 전·공급자 변경 시). 시나리오는 01 §4.7.

| ID | 대상(`NetworkId`) | 도구·출력 줄 | 관측(사람이 판정) | 반영 |
|---|---|---|---|---|
| L-SIM | `eip155:1`, `eip155:11155111` | `sim fresh 1wei`·`sim self 1wei`·`sim chainId+type` | `status=0x1`; `nativeEmitter`: 1 = `eeee`, 11155111 = `fffe`(자기 자신 전송은 `none`이 정상, EIP-7708); `sim fresh` `gasUsed`: 1 = 21000, 11155111 = 204600; `sim chainId+type` ok; 플랜·권한 오류(`http=401/403`) 없음 | 03 §1.5 A1·A2·A3·A5, §3.8 S1·S2 |
| L-REVERT | `eip155:1`, `eip155:11155111` | `sim revert`, `sim no-funds` | `status=0x0`, `errCode=3`, `revertData=0xdeadbeef`; `sim no-funds` `code=-38014` | A4, S3, S4 |
| L-HYPEREVM | `eip155:999`(`/nanoreth`) | `sim *` 5줄 | `sim fresh`·`self`·`chainId+type` `status=0x1` + `nativeEmitter` `eeee`, `sim revert` `status=0x0`·`errCode=3`, `sim no-funds` `code=-32003` | 999 기본 `simulation`(D14, 03 §1.1·§1.5 A9(b)): 기대대로면 `auto`, `-32601`이면 `unsupported`(E36). feeHistory·999 레지스트리(A9(c)(e))는 `live_probe`(M4, M4-13 전) |
| L-GENESIS | `eip155:1`, `eip155:11155111`, `eip155:999` | `eth_chainId`·`genesis`·`latest block` | 1·11155111: 두 줄 `ok`(03 §1.1 상수 = §3.11). 999: `eth_chainId ok`, `genesis` 해시 출력(1차 실측 `0xd8fcc13b6a195b88b7b2da3722ff6cad767b13a8c1e9ffb1c73aa9d216d895f0`), `latest block gasLimit=3000000` | 1·11155111 불일치는 엔드포인트 오류(상수를 고치지 않는다). 999 해시는 상수가 아니다(03 §1.1 `PinOnFirstUse`): 공개 탐색기 1곳과 대조해 기록하고 M4-13 첫 고정값과 비교 |
| L-LIMITS | `eip155:1`, `eip155:11155111` | `live_probe`(`probe-rpc.mjs` 범위 밖, 01 §4.7) | `eth_feeHistory(["0xa","latest",[50]])` reward 개수(A7), `eth_getLogs` 10,000블록 범위 수락·`eth_simulateV1` 지연(A8) | A7·A8 "다를 때" |

| 묶음 | 항목 | 시점 | 실패 시 |
|---|---|---|---|
| EVM | L-SIM·L-REVERT·L-HYPEREVM·L-GENESIS(`probe-rpc.mjs`) | M2 착수 전(가장 먼저), 공급자·엔드포인트 변경 시 | 위 표 "반영" 열. L-SIM·L-REVERT 형태가 S1–S3과 다르면 픽스처 추가. A5 실패(플랜·권한 때문에 `eth_simulateV1` 불가)는 승인을 막지 않는다(D15): D13 네트워크별 URL로 다른 엔드포인트·공급자로 바꾸거나 그 체인 `simulation = unsupported` |
| EVM | L-LIMITS, 03 §1.5 A1–A8·A9(c)–(e) (`live_probe`) | M4(`rpc::evm` 전송·호출 구현 후, M4-13 전; A6은 M4-2 전송 직후) | 03 §1.5 "다를 때" 열. `probe-rpc.mjs` 결과와 다르면 원인(공급자·엔드포인트 변경, 코드 차이)을 기록 |
| EVM | L-ORIGIN: WinHTTP 요청(Origin·Referer 없음)이 엔드포인트의 리퍼러·도메인 허용 목록 거부(HTTP 401/403 또는 JSON-RPC 오류)를 받지 않음 | M3(엔드포인트 저장 직후, M3-8) | 공급자 대시보드에서 그 엔드포인트의 리퍼러·도메인 허용 목록 제거(토큰 인증·IP 허용 목록은 무방, D13) |
| SOL | 07 §16 설정한 공급자 행(이력 검색, `getFeeForMessage` 우선 수수료 포함, `maxRetries:0`, dataSlice), 07 §10 CU 측정 | M7 착수 시 | 07 §16 "실패 시" |
| BTC | 08 §4.5 E1–E3(Esplora, `curl.exe`)·C1–C3(Core, `probe-rpc.mjs`·`rpc.json`). B1–B4는 `bitcoin.indexer`를 `bb-rpc`·`bb-rest`로 쓰기로 한 경우만 | M8 착수 전, Esplora URL·공급자 변경 시 | 08 §4.5 판정·대안: mempool.space 실패면 다른 Esplora URL 또는 선택 인덱서. 쓸 수 있는 인덱서가 없거나 Core 원본·`TxRaw`가 모두 실패할 때만 M8 중단(D26). 애드온 미활성은 중단 사유가 아니다 |

## 3. 기지 답(KAT) 벡터

### 3.1 파일 규칙

| 파일(`crates/yw-core/tests/vectors/`) | 내용 | 출처 |
|---|---|---|
| `bip39_trezor_en.json` | trezor/python-mnemonic `vectors.json`의 `"english"` 배열 그대로, 24개 `[entropy, mnemonic, seed, xprv]` | [공식] github.com/trezor/python-mnemonic `vectors.json` |
| `bip32.json` | `{"valid": [{"seed", "chains":[{"path","xpub","xprv"}]}], "invalid": [[키, 사유]]}` — 벡터 1–4(경로 17개, 경로의 `<sub>H</sub>`는 `'`로 표기), 벡터 5 무효 키 16개 | [공식] bitcoin/bips `bip-0032.mediawiki` |
| `slip10_ed25519.json` | 벡터 1·2의 Ed25519 절(경로 12개) | [공식] satoshilabs/slips `slip-0010.md` |
| `rfc8032.json` | §7.1 TEST 1, 2, 3, 1024, SHA(abc) | [공식] RFC 8032 |
| `base58_encode_decode.json` | 21개 `[hex, base58]` | [공식] bitcoin/bitcoin `src/test/data/` |
| `btc/` | 08 §14.1(key_io, tx_valid/invalid, 복구 주소 파일), `btc/esplora/`(08 §4.5 E1–E3 실측 응답 원문: `address`·`utxo`·`tx-status`·`tx-hex`·`block-height` 본문과 `Content-Type`, 출처 URL·날짜를 `README`에; 08 §14.2 `esplora_*` 픽스처) | [공식]·[체크리스트] |

`SOURCES.md`는 각 파일의 URL·원본 커밋·가져온 날짜·라이선스를 적는다. 해시는 적지 않는다(원칙 2).

### 3.2 BIP39 (M1, `src/bip39/tests.rs`)

| ID | 입력 | 기대 | 출처 |
|---|---|---|---|
| B39-1 | `bip39_trezor_en.json` 24개 전부(엔트로피 16/24/32바이트, 12/18/24단어), passphrase `"TREZOR"` | entropy→phrase, phrase→entropy, phrase→seed 64바이트 일치. seed→master xprv 전체 문자열(`encode_xkey`)이 vectors.json의 xprv와 같다 | [공식] |
| B39-1a | 대표값 `00`×16 | `abandon`×11 `about`, seed `c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04`, `xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF` | [공식] |
| B39-1b | `ff`×16 | `zoo`×11 `wrong`, seed 앞 16바이트 `ac27495480225222079d7be181583751` | [공식] |
| B39-1c | `00`×32 | `abandon`×23 `art`, seed 앞 16바이트 `bda85446c68413707090a52022edd26a`, `xprv9s21ZrQH143K32qBagUJAMU2LsHg3ka7jqMcV98Y7gVeVyNStwYS3U7yVVoDZ4btbRNf4h6ibWpY22iRmXq35qgLs79f312g2kj5539ebPM` | [공식] |
| B39-1d | `9e885d952ad362caeb4efe34a8e91bd2` | `ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic` | [공식] |
| B39-2 | 0 엔트로피 16/20/24/28/32바이트 | `…about`(12), `…address`(15), `…agent`(18), `…admit`(21), `…art`(24) 왕복 | [아카이브] `demo/sepolia-wallet/src/wallet_secret.rs:917-942` |
| B39-3 | 빈 passphrase seed | about: `5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4`; art: `408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840` | [로컬] |
| B39-4 | 단어 목록 | 2048개, 첫 `abandon`, 끝 `zoo`, 엄격 오름차순, 3–8자 `[a-z]`, 앞 4글자 유일, 파일 SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`(02 §2.1 구현 시 확인) | [공식] |

### 3.3 BIP32 (M1, `src/bip32/tests.rs`)

| 벡터 | seed | 경로 |
|---|---|---|
| 1 | `000102030405060708090a0b0c0d0e0f` | `m`, `m/0'`, `m/0'/1`, `m/0'/1/2'`, `m/0'/1/2'/2`, `m/0'/1/2'/2/1000000000` |
| 2 | `fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542` | `m`, `m/0`, `m/0/2147483647'`, `…/1`, `…/2147483646'`, `…/2` |
| 3 | `4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be` | `m`, `m/0'` (선행 0 보존) |
| 4 | `3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678` | `m`, `m/0'`, `m/0'/1'` (선행 0 보존) |
| 5 | — | 무효 확장 키 16개 전부 `decode_xkey` 거부 |

- 비교(M1, spec §5): 벡터 1–4 모든 경로에서 우리 파생 결과를 `encode_xkey`로 직렬화한 xprv·xpub 문자열이 `bip32.json`의 공식 문자열과 바이트 단위로 같다(부모 fingerprint = HASH160 포함, `ripemd`는 D5). 표본 확인값: 벡터 1 `m` xprv `xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi`, 벡터 1 최종 xpub `xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy`, 벡터 3 `m/0'` xprv `xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L`, 벡터 4 `m/0'/1'` xprv `xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1`. chain code·개인키 표는 02 §11.3. [공식]
- 벡터 5: 16개 모두 `decode_xkey`가 `Err`. 사유(테스트 이름에 씀): 버전·키 종류 불일치 2, 공개키 접두 04/01 2, 개인키 접두 04/01 2, depth 0인데 부모 fingerprint ≠ 0 2, depth 0인데 index ≠ 0 2, 알 수 없는 버전 2, 개인키 0·n 2, 곡선 밖 공개키 1, 체크섬 1.

### 3.4 EVM 계정·주소 (M1·M2; ACC-1–5 `src/evm/address/tests.rs`, ACC-6–8 = 03 EVM-V05 `tests/evm_accounts.rs`)

| ID | 입력 | 기대 | 출처 |
|---|---|---|---|
| ACC-1 | about, passphrase 없음, `m/44'/60'/0'/0/0` | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`, 키 `1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727` | [아카이브] `demo/sepolia-wallet/src/wallet_secret.rs:964-998` + [로컬] |
| ACC-2 | about, `m/44'/60'/0'/0/1` | `0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0`, 키 `9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6` | 같음 |
| ACC-3 | art(24단어), `/0`, `/1` | `0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb`(키 `1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f`), `0xf785bD075874b8423D3583728a981399f31e95aA`(키 `0855b75d03a8830e390b5483d81694c9c7121d971e092145cf8b9c6fa3a5b373`) | [로컬], M9-3에서 독립 지갑으로 1회 대조 |
| ACC-4 | about, passphrase `"TREZOR"`, `/0` | `0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6`, `passphrase_check = dc929830` | 02 §11.4 |
| ACC-5 | raw key `00…01` | `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf` | [아카이브] `wallet_secret.rs:1080-1096` |
| ACC-6 | EIP-55 수락 | `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed`, `0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359`, `0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB`, `0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb`, `0x52908400098527886E0F7030069857D2E4169EE7`, `0x8617E340B3D01FA5F11F306F4090FD50E238070D`, `0xde709f2102306220921060314715629080e2fb77`, `0x27b1fdb04752bbc536007a920d24acb045561c26`, 각각 전부 소문자·전부 대문자 형태 | [공식] ERC-55 |
| ACC-7 | EIP-55 거부 | `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD`(끝 1글자 대소문자 반전) → `BadChecksum`; `0X5aae…`, 39·41자리, `g` 포함, 접두 없음 → 형식 오류 | 03 §2.1 |
| ACC-8 | `to_checksum` | 위 8개의 소문자 → 표기 그대로, `0x9d8a…` → `0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F` | [로컬] |

### 3.5 EVM 서명 (M2, `src/evm/sign/tests.rs`, 03 EVM-V01–V03·V06)

모든 서명은 `sign_ecdsa_recoverable`(RFC 6979, 추가 엔트로피 없음)로 **실제로 계산해** 바이트 일치를 단정한다. legacy·임의 chainId 인코딩은 `#[cfg(test)]` 도우미로만 만든다(03 §3.1, D19). 그래서 이 절은 통합 테스트가 아니라 단위 테스트 파일이다.

**EVM-V01 EIP-155** [공식] eips.ethereum.org/EIPS/eip-155 — 키 `0x46`×32, nonce 9, gasPrice 20,000,000,000, gas 21,000, to `0x3535…35`(20바이트), value 10^18, data 빈 값, chainId 1.

```
signing data  ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080
signing hash  daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53
v 37  r 28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276
      s 67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83
signed        f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83
sender        0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F
tx hash       33469b22e9f636356c4160a87eb19df52b7412e8eac32a4a55ffe88ea8350788   [로컬]
```

**EVM-V02 EIP-1559(Besu)** [공식] ethereumjs `packages/tx/test/testData/eip1559.ts`("// Source: Besu") — 키 `8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63`, chainId 4, nonce 819, maxPriorityFeePerGas 75,853, maxFeePerGas 121,212, gas 35,552, to `0x000000000000000000000000000000000000aaaa`, value 43,203,529, data·accessList 빈 값.

```
preimage      02eb048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c0
signing hash  e0b52197916ca4528d05e8abfe4fd902e91dbd3137a423856228e737d984f6b2
yParity 0     r 0f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47
              s 7dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83
signed        02f86e048203338301284d8301d97c828ae094000000000000000000000000000000000000aaaa8402933bc980c080a00f924cb68412c8f1cfd74d9b581c71eeaf94fff6abdde3e5b02ca6b2931dcf47a07dd1c50027c3e31f8b565e25ce68a5072110f61fce5eee81b195dd51273c2f83
sender        0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73
tx hash       2e564c87eb4b40e7f469b2eec5aa5d18b0b46a24e8bf0919439cfb0e8fcae446   [로컬]
```

원본 픽스처는 RLP로 감싼 `0xb871…`로 저장한다. 비교는 위 `0x02…` 정규 바이트로 한다. `decode_signed`(03 §4.3 3단계)가 이 바이트를 받아들이고 9필드·복구 주소(= sender)가 일치해야 한다. chainId 4는 03 §1.1 표 밖이므로 `Eip1559Tx` 승인 경로가 아니라 시험 도우미로 서명한다.

**EVM-V03 EIP-191 `personal_sign`**

| 키 | 메시지 | digest | 서명(`r‖s‖v`) | 서명자 | 출처 |
|---|---|---|---|---|---|
| `4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318` | `Some data` | `1da44b586eb0729ff70a73c326926f6ed5a25f5b056e7f47fbc6e58d86871655` | `b91467e570a6466aa9e9876cbcd013baba02900b8979d43fe208a4a4f339f5fd6007e74cd82e037b800186422fc2da167c747ef045e5d18a5f5d4300f8e1a0291c` | `0x2c7536E3605D9C16a7a3D7b1898e529396a65c23` | [공식] web3.js `accounts.sign` 문서 |
| `4af1bceebf7f3634ec3cff8a2c38e51178d5d4ce585c52d6043e5e2cc3418bb0` | `Hello, world!` | `b453bd4e271eed985cbab8231da609c4ce0a9cf1f763b6c1594e76315510e0f1` [로컬] | `90a938f7457df6e8f741264c32697fc52f9a8f867c52dd70713d9d2d472f2e415d9c94148991bbe1f4a1818d1dff09165782749c877f5cf1eff4ef126e55714d1c` | `0x29C76e6aD8f28BB1004902578Fb108c507Be341b` | [공식] MetaMask eth-sig-util `personal-sign.test.ts` |

preimage = `0x19 ‖ "Ethereum Signed Message:\n" ‖ 10진(len) ‖ message`(`archive/spec-v2.4:crates/wallet-model/src/operation.rs:398-415`, 테스트 593-604).

**EVM-V03 EIP-712 Ether Mail** [공식] EIPs `assets/eip-712/Example.js`, 원문 JSON은 `archive/spec-v2.4:crates/eip712/tests/vectors.rs:6-42` 그대로.

```
domainSeparator  f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f
hashStruct(Mail) c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e
digest           be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2
key = keccak256("cow")  c85ef7d79691fe79573b1a7064c19c1a9819ebdbd1faaab1a8ec92344438aaf4
signer 0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826
v 28  r 4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d
      s 07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b91562
```

chainId 1 기준이므로 테스트는 `validate_typed_data_v4(…, chain_id = 1)`로 부른다. 같은 원문을 `chain_id = 11155111`로 부르면 T01 거부.

**EVM-V06 RLP**: 거부 `[0x81,0x01]`, `[0x01,0x02]`, `[0xb8,0x01,0x80]`(`archive/spec-v2.4:crates/key-agent/src/lib.rs:959-964`). EVM-V01·V02 서명 바이트의 모든 접두(길이 0..len−1)와 뒤 1바이트 추가가 `decode_signed`/`decode_exact`에서 거부된다(`lib.rs:1013-1027` 방식).

### 3.6 상수 표 (M2, `tests/evm_consts.rs`, 03 EVM-V04)

테스트는 각 서명 문자열을 Keccak-256해 코드의 상수와 비교한다(상수는 코드 표, 문자열은 테스트 안). 모든 값 [로컬]: 순수 Python Keccak과 RustCrypto sha3 0.10.8이 바이트 단위로 같았고 openchain·4byte·원 소스와 대조했다.

```
셀렉터 (41)
a9059cbb transfer(address,uint256)              095ea7b3 approve(address,uint256)
23b872dd transferFrom(address,address,uint256)  39509351 increaseAllowance(address,uint256)
a457c2d7 decreaseAllowance(address,uint256)     a22cb465 setApprovalForAll(address,bool)
42842e0e safeTransferFrom(address,address,uint256)
b88d4fde safeTransferFrom(address,address,uint256,bytes)
f242432a safeTransferFrom(address,address,uint256,uint256,bytes)
2eb2c2d6 safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)
d0e30db0 deposit()                              2e1a7d4d withdraw(uint256)
87517c45 approve(address,address,uint160,uint48)
cc53287f lockdown((address,address)[])          65d9723c invalidateNonces(address,address,uint48)
3ff9dcb1 invalidateUnorderedNonces(uint256,uint256)
2b67b570 permit(address,((address,uint160,uint48,uint48),address,uint256),bytes)
2a2d80d1 permit(address,((address,uint160,uint48,uint48)[],address,uint256),bytes)
36c78516 transferFrom(address,address,uint160,address)
0d58b1db transferFrom((address,address,uint160,address)[])
30f28b7a permitTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes)
edd9444b permitTransferFrom(((address,uint256)[],uint256,uint256),(address,uint256)[],address,bytes)
137c29fe permitWitnessTransferFrom(((address,uint256),uint256,uint256),(address,uint256),address,bytes32,string,bytes)
927da105 allowance(address,address,address)
ac9650d8 multicall(bytes[])  5ae401dc multicall(uint256,bytes[])  1f0464d1 multicall(bytes32,bytes[])
d505accf permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
8fcbaf0c permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)
3593564c execute(bytes,bytes[],uint256)         24856bc3 execute(bytes,bytes[])
fb0f3ee1 fulfillBasicOrder((address,uint256,uint256,address,address,address,uint256,uint256,uint8,uint256,uint256,bytes32,uint256,bytes32,bytes32,uint256,(uint256,address)[],bytes))
fd9f1e10 cancel((address,address,(uint8,address,uint256,uint256,uint256)[],(uint8,address,uint256,uint256,uint256,address)[],uint8,uint256,uint256,bytes32,uint256,bytes32,uint256)[])
5b34b966 incrementCounter()
313ce567 decimals()  95d89b41 symbol()  06fdde03 name()  70a08231 balanceOf(address)  dd62ed3e allowance(address,address)
08c379a0 Error(string)  4e487b71 Panic(uint256)

topic0 (12)
ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef Transfer(address,address,uint256)
8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925 Approval(address,address,uint256)
17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c31 ApprovalForAll(address,address,bool)
c3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62 TransferSingle(address,address,address,uint256,uint256)
4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb TransferBatch(address,address,address,uint256[],uint256[])
e1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c Deposit(address,uint256)
7fcf532c15f0a6db0bd6d0e038bea71d30d808c7d98cb3bf7268a95bf5081b65 Withdrawal(address,uint256)
da9fa7c1b00402c17d0161b249b1ab8bbec047c5a52207b9c112deffd817036b Approval(address,address,address,uint160,uint48)
c6a377bfc4eb120024a8ac08eef205be16b817020812c73223e81d1bdb9708ec Permit(address,address,address,uint160,uint48,uint48)
89b1add15eff56b3dfe299ad94e01f2b52fbcb80ae1a3baea6ae8c04cb2b98a4 Lockdown(address,address,address)
55eb90d810e1700b35a8e7e25395ff7f2b2259abd7415ca2284dfb1c246418f3 NonceInvalidation(address,address,address,uint48,uint48)
3704902f963766a4e561bbaab6e6cdc1b1dd12f6e9e99648da8843b3f46b918d UnorderedNonceInvalidation(address,uint256,uint256)

EIP-712 typeHash (11) — PD = "PermitDetails(address token,uint160 amount,uint48 expiration,uint48 nonce)"
                        TP = "TokenPermissions(address token,uint256 amount)"
8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
8cad95687ba82c2ce50e74f7b754645e5117c3a5bec8151c0726d5857980a866 EIP712Domain(string name,uint256 chainId,address verifyingContract)
6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9 Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)
ea2aa0a1be11a07ed86d755c93467f4f82362b452371d1ba94d1715123511acb Permit(address holder,address spender,uint256 nonce,uint256 expiry,bool allowed)
65626cad6cb96493bf6f5ebea28756c966f023ab9e8a83a7101849d5573b3678 PD
f3841cd1ff0085026a6327b620b67997ce40f282c88a8e905a7a5626e310f3d0 "PermitSingle(PermitDetails details,address spender,uint256 sigDeadline)" + PD
af1b0d30d2cab0380e68f0689007e3254993c596f2fdd0aaa7f4d04f79440863 "PermitBatch(PermitDetails[] details,address spender,uint256 sigDeadline)" + PD
618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1 TP
939c21a48a8dbe3a9a2404a1d46691e4d39f6583d6ec6b35714604c986d80106 "PermitTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline)" + TP
fcf35f5ac6a2c28868dc44c302166470266239195f02b0ee408334829333b766 "PermitBatchTransferFrom(TokenPermissions[] permitted,address spender,uint256 nonce,uint256 deadline)" + TP
fa445660b7e21515a59617fcd68910b487aa5808b8abda3d78bc85df364b2c2f "OrderComponents(address offerer,address zone,OfferItem[] offer,ConsiderationItem[] consideration,uint8 orderType,uint256 startTime,uint256 endTime,bytes32 zoneHash,uint256 salt,bytes32 conduitKey,uint256 counter)ConsiderationItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount,address recipient)OfferItem(uint8 itemType,address token,uint256 identifierOrCriteria,uint256 startAmount,uint256 endAmount)"
```

추가 단정: Seaport `0x00000000`(fulfillBasicOrder_efficient_6GL6yc)은 표 상수로만 두고 Keccak 검사에서 뺀다. 같은 셀렉터가 다른 함수 이름에도 등록돼 있다는 사실(예: `0xa22cb465`)은 테스트하지 않는다(03 §7.1: DB 이름을 쓰지 않음).

### 3.7 도메인 separator (M2, 03 EVM-V04)

`keccak256(typeHash ‖ keccak(name) [‖ keccak(version)] ‖ uint256(chainId) ‖ address)`. 모두 [로컬](두 Keccak 구현 일치, 체인에서 읽은 값 아님). DAI 값은 널리 알려진 메인넷 `DOMAIN_SEPARATOR`와 같다.

| 도메인 | 입력 | separator |
|---|---|---|
| Permit2 mainnet | 3필드, `"Permit2"`, 1, `0x000000000022D473030F116dDEE9F6B43aC78BA3` | `866a5aba21966af95d6c7ab78eb2b2fc913915c28be3b9aa07cc04ff903e3f28` |
| Permit2 Sepolia | 3필드, `"Permit2"`, 11155111, 같은 주소 | `94c1dec87927751697bfc9ebf6fc4ca506bed30308b518f0e9d6c5f74bbafdb8` |
| Seaport 1.6 mainnet | 4필드, `"Seaport"`, `"1.6"`, 1, `0x0000000000000068F116a894984e2DB1123eB395` | `fce34bc6e1752c1117e5063116d25cad2fa2bdcf15ff2d2e275eece7dc31ba64` |
| DAI mainnet | 4필드, `"Dai Stablecoin"`, `"1"`, 1, `0x6B175474E89094C44Da98b954EedeAC495271d0F` | `dbb8cf42e1ecb028be3f3dbc922e1d878b963f411dc388ced501601c60f7c6f7` |
| Ether Mail | 4필드, `"Ether Mail"`, `"1"`, 1, `0xCcCC…cCcC` | `f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f` |

### 3.8 `eth_simulateV1` 픽스처 (M2, 03 EVM-V08)

- 파일: `crates/yw-app/tests/fixtures/eth_simulateV1/<ID>.response.json`(RPC 응답 원문 바이트). 테스트는 이 바이트를 yw-app `rpc::evm`의 eth_simulateV1 응답 파서 → yw-core `evm::simulate`(03 §6.2–6.4, §1.3)로 넘긴다. 요청 거래·`now`는 테스트 코드에 둔다. `rpc::evm`의 나머지(전송·호출)는 M4지만 이 응답 파서는 spec §5 M2 완료 조건이므로 M2에 먼저 만든다(네트워크 없음).
- 03 §6.3 블록 시각 검사(차 300 s)를 피하기 위해 `now_unix = 픽스처 timestamp + 12`로 주입한다(S13 제외). 요청 origin은 `yw-app`(지갑 보내기)이다. 기대 "통과"는 차단·고위험 경고가 없다는 뜻이다(정보·주의 경고 E28·E33 등은 허용).
- 시뮬레이션이 성공하지 못한 경우의 기대는 **배너**(맨 위 고위험 경고)로 적는다(D15). 약칭과 규칙(03 §6.3·§10.2): **[결과 없음]** E01 — 전송 오류·시간 초과·429·최상위 RPC 오류·응답 형식 이상·크기 초과("시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다" + 원인), **[미지원]** E36 — 체인 `simulation = unsupported`("시뮬레이션 미지원 체인 — 실제 효과를 확인할 수 없습니다", `eth_simulateV1` 호출 0), **[실행 실패]** E02 — `status 0x0`("시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다" + 이유), **[결과 불완전]** E03(사용 가스 > 가스 한도)·E04(네이티브 이동 미확인)·E07(블록 시각 차 > 300 s)·E08·E09 — 응답은 해석했으나 확인 실패("시뮬레이션 결과가 불완전합니다" + 원인). 가스 추정 실패 E37(03 §3.5, 대체 가스)도 같은 고위험이며 시뮬레이션 상태 규칙과 함께 맨 위에 둔다(03 §10.1). 원인 줄 문구와 조건별 규칙 배정은 03 §6.3이 정본이고 다르면 03을 따라 이 표를 고친다. 공통 기대: 승인 창 맨 위, 등급 고위험(차단 아님, `ack_required`), 체크박스 1개 + 2초 누르기 전에는 `Approved`가 되지 않고 둘 다 하면 된다(D16, 04 AP-2·AP-6). 승인 입력을 무시하는 것은 시뮬레이션 진행 중(≤ 10 s, 04 AP-6 `Preparing(Simulating)`)뿐이고, 실패 결과가 표시된 뒤에는 위 조작으로 승인할 수 있다. 해석 불가 calldata와 겹치면 E12와 함께 표시하고 체크박스는 여전히 1개다.
- `H(x)` = `"0x"` + 바이트 x를 32번 반복한 소문자 hex. `PAD(a)` = 주소 a를 32바이트로 왼쪽 0 채움. 계정: user = ACC-1 `0x9858effd…eda94`, 기존 수신자 = ACC-2 `0x6fac4d18…ab9c0`, 새 수신자 = ACC-3 `0xf278cf59…1cdb`.

S2(정본 형태, Sepolia, Glamsterdam 후, 새 계정으로 0.01 ETH):

```json
{"jsonrpc":"2.0","id":1,"result":[{"number":"0x9a0000","hash":"H(b1)","parentHash":"H(b0)",
 "timestamp":"0x6ac64ee0","baseFeePerGas":"0x3b9aca00","gasLimit":"0x3938700","gasUsed":"0x31f38",
 "blockAccessListHash":"H(ba)","slotNumber":"0x1234",
 "calls":[{"status":"0x1","returnData":"0x","gasUsed":"0x31f38","maxUsedGas":"0x31f38",
  "logs":[{"address":"0xfffffffffffffffffffffffffffffffffffffffe",
   "topics":["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef","PAD(user)","PAD(new)"],
   "data":"0x000000000000000000000000000000000000000000000000002386f26fc10000",
   "logIndex":"0x0","blockNumber":"0x9a0000","transactionHash":"H(c1)","transactionIndex":"0x0",
   "blockHash":"H(b1)","blockTimestamp":"0x6ac64ee0","removed":false}]}]}]}
```

요청: chainId 11155111, from user, to new, value `0x2386f26fc10000`, data 빈 값, nonce 0, gas_limit `0x3bf10`(245,520 = ⌈204,600×1.2⌉), maxFee `0x77359400`(2 gwei), tip `0x5f5e100`(0.1 gwei). `timestamp 0x6ac64ee0` = Sepolia `amsterdam_time`(1,791,294,816) + 86,400.

| ID | S2 대비 변경 | 기대(03 규칙) |
|---|---|---|
| S1 | chainId 1, timestamp `0x6a000000`, to = 기존 수신자, gasUsed·maxUsedGas `0x5208`, 요청 gas `0x6270`(25,200), emitter `0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee`, `blockAccessListHash`·`slotNumber` 없음 | 통과. 네이티브 −0.01 ETH, 예상 수수료 21,000 × 1.1 gwei = 0.0000231 ETH, `native-emitter-mismatch` 로그 없음 |
| S2 | — | 통과. 네이티브 −0.01, 예상 수수료 204,600 × 1.1 gwei = 0.00022506 ETH |
| S3 | `status "0x0"`, logs `[]`, `returnData` = `08c379a0` ‖ ABI string `"insufficient balance"`, `error {"code":3,"message":"execution reverted: SECRET-MARKER","data":<returnData>}` | [실행 실패] E02 고위험, `Simulated Reverted`. 원인 줄: "(검증되지 않은 컨트랙트 메시지)" + `"insufficient balance"`(03 §7.4). 자산 변화 없음. 표시 모델 어디에도 `SECRET-MARKER` 없음 |
| S3b | S3에서 `error.code -32015`, data 없음 | [실행 실패] E02 고위험, "실행 오류(가스 부족 등, 코드 -32015)" |
| S4 | `result` 없이 `"error":{"code":-38014,"message":"insufficient funds for gas * price + value"}` | [결과 없음] E01 고위험(`None RpcError`), 원인 줄 "잔액이 보낼 금액과 최대 수수료의 합보다 적습니다", 원문 message 미표시 |
| S5 | 블록·호출·로그에 모르는 키 추가: `"futureBlock":{"a":[1,2]}`, `"futureCall":"0x1"`, `"futureLog":null` | S2와 diff·sim_digest 동일 |
| S6 | S2 로그 앞에 같은 topics·data의 `0xeeee…` 로그 추가 | 네이티브 −0.01(−0.02 아님). `0xeeee…` 로그는 diff·기타 이벤트에 없음(03 §1.3-2) |
| S7 | logs `[]` (value > 0) | [결과 불완전] E04 고위험, "SepoliaETH 이동이 확인되지 않습니다" |
| S7b | S2의 emitter를 `0xeeee…`로 바꿈(SYSTEM 로그 없음) | 통과(ERC7528 계수), 로컬 로그 `native-emitter-mismatch` 1줄(03 §1.3-3) |
| S8 | 호출 `gasUsed "0x3bf11"` | [결과 불완전] E03 고위험(`Simulated Incomplete`), "사용 가스가 가스 한도를 넘습니다"(03 §6.3) |
| S8b | `maxUsedGas "0x3bf11"`(gasUsed 그대로) | S8과 같음 |
| S9 | 각각(파일 S9a–S9i 순서): `result []`; 블록 2개; `calls []`; 호출 2개; `status "0x2"`; `baseFeePerGas` 없음; `gasUsed "0x0g"`; `id` 2; `result`와 `error` 동시 | 모두 `Malformed` → [결과 없음] E01 고위험, "시뮬레이션 응답 형식이 올바르지 않습니다" |
| S10 | to = 토큰 T `0x1111…1111`, value 0, data = `a9059cbb ‖ PAD(기존 수신자) ‖ uint256(1,000,000)`; 로그: address T, Transfer, topics `[…, PAD(user), PAD(기존 수신자)]`, data 1,000,000; 네이티브 로그 없음 | 통과. Token(T) −1,000,000 원시 단위, E33(미등록 토큰) 정보 |
| S10b | S10에서 로그 data 999,999 | E13 고위험 + 확인 체크(R6) |
| S11 | 호출 객체에 `"status"` 키 2번 | yw-json `DuplicateKey` → `Malformed` → [결과 없음] E01 고위험 |
| S12 | (파일 없음) 가짜 전송이 10 s 동안 응답 없음 | [결과 없음] E01 고위험(`None Timeout`), "시뮬레이션 응답이 없습니다(10초)". 같은 요청의 S2 결과와 표시 바이트·승인 digest 다름 |
| S13 | S2를 `now = timestamp + 301`로 해석 | [결과 불완전] E07 고위험, "기준 블록 시각이 현재와 301초 다릅니다" |
| S14 | S2와 `parentHash`만 다른 응답 | 표시 바이트 동일, 승인 digest 다름(03 §11.4) |
| S1h | S1을 HyperEVM 형태로(`maxUsedGas` 없음, 요청 chainId 999) | 통과, `maxUsedGas` = None |
| S3c | S2에서 `status "0x0"`, logs `[]`, gasUsed `0x3aaa`, `returnData`·`error.data` `0xdeadbeef`, `error.code` 3(L-REVERT 형태) | [실행 실패] E02, "이유: 사용자 정의 오류 0xdeadbeef (4바이트)" |
| S4h | 최상위 `error.code` -32003(L-HYPEREVM 형태) | S4와 같음 |
| S16 | 요청 to = user, value 1 wei; 응답 logs `[]`, gasUsed `0x2ee0`(12,000, Sepolia 자기 자신 전송 실측) | 통과(E04 없음) |
| S15 | (파일 없음, M4 `flow::evm` — X-24) S2 요청에서 chainId만 8453으로, 그 체인은 `simulation = unsupported`인 사용자 체인(이름 `Test L2`, 네이티브 `ETH`/18) | 준비 전 과정에서 가짜 전송의 `eth_simulateV1` 호출 0회, [미지원] E36 고위험(`None Unsupported`). 같은 체인을 `auto`로 등록하면 호출 1회 |

재시뮬레이션(03 §6.6, 단조 시계 주입): S2 응답 후 60 s에 클릭 → 재시뮬레이션 없음, 61 s → 재시뮬레이션. 새 응답이 S2와 `parentHash`만 다르면 `replace` 후 같은 클릭으로 소비, S10b처럼 안정 부분이 다르면 새 클릭 요구. 재시뮬레이션이 실패하면(S3·S4·S12 각각) 표시를 그 배너로 교체하고 그 클릭은 소비하지 않는다: 서명 0, 체크 해제, 새 체크 + 2초 누르기 뒤에만 `Approved`(차단 아님). -38012/-32005는 03 §6.6-3(수수료 재계산 후 새 클릭). S15 체인은 61 s 뒤 클릭에도 호출 0.

### 3.9 Solana (M7, `tests/sol_*.rs`)

**SLIP-0010 Ed25519** [공식] `slip-0010.md`. 형식 `경로 | chain code | 개인키 | 공개키(0x00 접두)`.

```
벡터 1  seed 000102030405060708090a0b0c0d0e0f
m                 90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb 2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7 00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed
m/0'              8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69 68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3 008c8a13df77a28f3445213a0f432fde644acaa215fc72dcdf300d5efaa85d350c
m/0'/1'           a320425f77d1b5c2505a6b1b27382b37368ee640e3557c315416801243552f14 b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2 001932a5270f335bed617d5b935c80aedb1a35bd9fc1e31acafd5372c30f5c1187
m/0'/1'/2'        2e69929e00b5ab250f49c3fb1c12f252de4fed2c1db88387094a0f8c4c9ccd6c 92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9 00ae98736566d30ed0e9d2f4486a64bc95740d89c7db33f52121f8ea8f76ff0fc1
m/0'/1'/2'/2'     8f6d87f93d750e0efccda017d662a1b31a266e4a6f5993b15f5c1f07f74dd5cc 30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662 008abae2d66361c879b900d204ad2cc4984fa2aa344dd7ddc46007329ac76c429c
…/1000000000'     68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230 8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793 003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a
벡터 2  seed fffcf9f6…484542 (BIP32 벡터 2와 같음)
m                 ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b 171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012 008fe9693f8fa62a4305a140b9764c5ee01e455963744fe18204b4fb948249308a
m/0'              0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d 1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635 0086fab68dcb57aa196c77c5f264f215a112c22a912c10d123b0d03c3c28ef1037
m/0'/2147483647'  138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4 005ba3b9ac6e90e83effcd25ac4e58a1365a9e35a3d3ae5eb07b9e4d90bcf7506d
…/1'              73bd9fff1cfbde33a1b846c27085f711c0fe2d66fd32e139d3ebc28e5a4a6b90 3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c 002e66aa57069c86cc18249aecf5cb5a9cebbfd6fadeab056254763874a9352b45
…/2147483646'     0902fe8a29f9140480a00ef244bd183e8a13288e4412d8389d140aac1794825a 5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72 00e33c0f7d81d843c572275f287498e8d408654fdf0d1e065b84e2e6f157aab09b
…/2'              5d70af781f3a37b829f0d060924d5e960bdc02e85423494afc0b1a41bbe196d4 551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d 0047150c75db263559a70d5778bf36abbab30fb061ad69f69ece61a72b0cfa4fc0
```

비강화 성분(`m/0`, `m/44'/501'/0'/0`)은 `Slip10Path` 파싱에서 `InvalidPath`.

**RFC 8032 §7.1** [공식] (`SigningKey::from_bytes(secret)` → 공개키, `sign(msg)` 바이트 일치, `verify_strict` 통과)

```
TEST 1  secret 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60  public d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
        msg (빈 값)  sig e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b
TEST 2  secret 4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb  public 3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c
        msg 72       sig 92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00
TEST 3  secret c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7  public fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025
        msg af82     sig 6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a
```

TEST 1024·SHA(abc)는 `rfc8032.json`에서 같은 방식으로 검사한다.

**니모닉 → 주소**: 07 §17.1 표 전체(02 §3.5 `SolKeySource`의 `Standard`·`Bip44Account`·`Bip44Root`·`RawSeed` 4종 × about·art, 공개키는 02 §10.3 `Vault::sol_public_keys`). 핵심값: about `m/44'/501'/0'/0'` = `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk`(공개키 `f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7`), `/1'/0'` = `Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb`, `/2'/0'` = `7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm`; art `m/44'/501'/0'/0'` = `3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx`, `/1'/0'` = `5frqxtii9LeGq2bz3dSNokvZcEooF483MzeU24JrhcTA`. 출처: [공식에 준함] qntx/kobe `vectors/solana.json`, KeystoneHQ keystone3-firmware `rust/apps/solana/src/address.rs`, LedgerHQ ledger-live coin-solana, soramitsu fearless-iOS 테스트 + [로컬].

**compact-u16** [공식] solana-sdk short-vec 테스트

| 값 | 바이트 | 값 | 바이트 | 값 | 바이트 |
|---|---|---|---|---|---|
| `0x0` | `00` | `0xff` | `ff 01` | `0x4000` | `80 80 01` |
| `0x7f` | `7f` | `0x100` | `80 02` | `0x7fff` | `ff ff 01` |
| `0x80` | `80 01` | `0x3fff` | `ff 7f` | `0xffff` | `ff ff 03` |

거부: `80 00`, `80 80 00`(비정규), `ff ff 04`(> 0xffff), `80 80 80`(셋째 바이트 연속 비트), `80`(잘림).

**PDA·ATA** [공식] anza-xyz solana-sdk `test_create_program_address`(program `BPFLoaderUpgradeab1e11111111111111111111111`): `["", [1]]` → `BwqrghZA2htAcqq8dzP1WDAhTXYTYWj7CHxF5j7TDBAe`; `["☉", [0]]` → `13yWmRpaTR4r5nAktwLqMpRNr28tnVUZw26rTvPSSB19`; `["Talking","Squirrels"]` → `2fnQrngrQT4SeLcdToJAD96phoEjNL2man2kfRLCASVk`; `[SeedPubey1111111111111111111111111111111111 32B, [1]]` → `976ymqVnfE32QFe6NfGDctSvVa36LWnvYxhU6G2232YL`. ATA(v1.1): `HAgk14…`의 USDC(`EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`) ATA = `5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt`, bump 254. 탐색은 bump 255→1, 결과는 곡선 밖이어야 한다. `Hh8Qw…`의 USDC ATA = `8X8ts1CnpZmtqApE2rREA97xEJuSRcomPGVcMFdS2cgY`, bump 255. v1.1 구현: `sol::pda` 벡터 테스트, `sol::tests_spl` (T_SPL 골든·파서 거부·서명·저널·표시), `sol::token`(mint·토큰 계정 레이아웃·decimals 고정), `sol::rent` SPL 규칙, `sol::recipient` SPL 곡선 밖 차단.

**인코딩·메시지**: base58 `base58_encode_decode.json` 21개 + 경계값(07 §17.2), System Transfer 42 lamports data `02 00 00 00 2a 00 00 00 00 00 00 00`, solana-sdk `test_sdk_serialize` 206바이트, T_SOL(message 202 B, tx 267 B)·T_SPL(372 B, 437 B) 골든은 07 §17.3 값 그대로. 제네시스: mainnet `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d`, devnet `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG`.

### 3.10 Bitcoin (M8, `tests/btc_*.rs`)

- **BIP84** [공식] `bip-0084.mediawiki`(about, passphrase 없음): rootpub `zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF`, 계정 xpub `zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs`, `0/0` `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`(program `c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2`), `0/1` `bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g`, `1/0` `bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el`. 공개키·fingerprint·chain code는 08 §14.1. zpub 두 값은 M1 `bip32::xkey::encode_xkey`에 zpub 버전 바이트 `04b24746`을 넣어 비교할 수 있다(선택; 08 §1.2는 내보내기 제외). CKDpub(02 §11.4 M8 행, 08 §14.1): `Vault::btc_account_xpub(BtcCoin::Mainnet)`이 돌려준 `yw_core::bip32::AccountXpub`에서 `bip32::derive_public_child`로 `0/0`·`0/1`·`1/0`을 공개 파생한 공개키가 위 주소의 공개키와 같다.
- **BIP84 24단어** [로컬](위 공식값을 같은 구현으로 재현한 뒤 계산, M9-3 독립 지갑 대조): art `0/0` `bc1qzmtrqsfuaf6l6kkcsseumq26ukaphfj9skkug6`(pub `03c5db199831f23a3a1575518c8e9e948bfd495481aac442dec64b447ee76bd6fa`), `0/1` `bc1qyn0ml52dy0udru3nafudt6af7x2kv7ngysfk0k`, `1/0` `bc1qes80p0st92xjem9aw48v57fk35f44kjzm2064m`.
- **BIP143 Native P2WPKH** [공식] `bip-0143.mediawiki`: 값 전부 08 §14.1 표(hashPrevouts `96b827c8…fd37`, hashSequence `52b0a642…9a3b`, hashOutputs `863ef3e1…e5e5`, sighash `c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670`). 서명 `304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01`은 secp256k1 0.31.1의 `sign_ecdsa`와 `sign_ecdsa_low_r` 둘 다 이 문서 작성 중 바이트 그대로 재현했다[로컬]. 따라서 바이트 일치를 단정한다.
- **BIP173/BIP350** [공식]: 문자열 단계 벡터(BIP173 유효 bech32 7·무효 12, BIP350 유효 bech32m 7·무효 14)는 체크섬 디코더에, 주소 단계 벡터(BIP350 유효 8·무효 15)는 정책 파서에 넣는다. BIP173의 v1+ "유효" 주소 3개(`bc1pw508…7k7grplx`, `BC1SW50QA3JX3S`, `bc1zw508…vg6kdaj`)는 BIP350 이후 무효(bech32 체크섬)이므로 `WrongChecksumVariant`가 기대값이다. 디코더 단계에서 유효한 v1-40바이트·v2·v16 주소는 정책 단계에서 거부된다(08 §6.3 5g). 입력별 기대값은 08 §14.1 주소 표가 정본이다.
- **Bitcoin Core 데이터**: 08 §14.1(base58·key_io·tx_valid·tx_invalid).

### 3.11 체인 상수 (M2·M7·M8)

| 상수 | 값 | 출처 |
|---|---|---|
| Ethereum mainnet chainId·genesis | 1, `0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3` | [공식] geth `params/config.go` + 공개 노드 |
| Sepolia chainId·genesis | 11155111(`0xaa36a7`), `0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9` | 같음 |
| HyperEVM mainnet chainId·genesis·기본 `simulation` | 999(`0x3e7`). 블록 0 해시는 코드 상수가 아니다(03 §1.1 `PinOnFirstUse`, 첫 연결에서 고정): §2.5 L-GENESIS 관측값을 공개 탐색기 1곳과 대조해 기록만 한다(M4-13 비교용). 기본 `simulation`(`auto`/`unsupported`)은 §2.5 L-HYPEREVM 결과로 03 §1.1 상수에 넣는다 | [프로브] |
| HyperEVM 작은 블록 가스 한도 | 3,000,000(03 §1.1 `small_block_gas_limit`; 초과 가스 한도는 E38 주의, 03 §3.5. 03 §1.5 A9(d) 관측값과 다르면 03 상수와 이 값을 함께 고친다) | [공식] Hyperliquid 문서 + [프로브] |
| Sepolia `amsterdam_time` | 1,791,294,816(2026-10-06 13:53:36 UTC, epoch 353024); mainnet `None` | [공식] EIP-7773 |
| 거래 가스 상한 | 16,777,216(EIP-7825) | [공식] |
| Bitcoin genesis | mainnet `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`, testnet4 `00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043` | [공식] Core `chainparams.cpp` |
| Solana genesis | §3.9 | [공식] |

테스트는 코드 상수가 이 표와 같은지 본다(레지스트리 회귀, 03 EVM-V16 "내장 3체인 상수"). 기본 제공 EVM 체인은 정확히 1·11155111·999이고 각각 `simulation` 값을 가진다(D14 기본 `auto`, 999는 L-HYPEREVM 결과). 1·11155111은 `GenesisRule::Fixed`(위 해시), 999는 `PinOnFirstUse(None)`과 `small_block_gas_limit = Some(3_000_000)`, 나머지 둘은 `None`.

### 3.12 vault v3 골든 (M1, `src/vault/tests.rs`)

입력은 02 §11.6 고정값(password `"correct horse battery staple"`, entropy `00`×32, created_unix 1,790,000,000, vault_id `000102…0f`, DEK `202122…3f`, kdf_salt `404142…4f`, wrap_nonce `505152…67`, payload_nonce `707172…87`, record_id `909192…9f`, generation 1, backup_state 0, passphrase_used 0)과 운영 파라미터(`KDF_V3`)다.

| ID | 절차 | 기대 |
|---|---|---|
| G1 | `seal_create_with(material, KDF_V3)` | 272바이트(176 + 96). SHA-256이 첫 구현 때 고정한 상수와 같다(02 §11.6) |
| G2 | 바이트 필드 검사(02 §4.2 오프셋) | magic `YWVLT003`, version 3, header_len 176, kdf_id 1, m 262144, t 3, p 4, generation 1, payload_ct_len 96, flags·reserved 0, 각 고정값이 제자리 |
| G3 | **독립 복호**: 테스트 코드가 vault 모듈을 쓰지 않고 `argon2`·`hkdf`·`chacha20poly1305`를 직접 호출해 02 §4.3 키 계층(Argon2id → HKDF salt `your-wallet/v3/kdf` info `your-wallet/v3/kek` → wrap AAD `header[0..82]` → payload AAD `header[0..176]`)대로 복호 | DEK = `202122…3f`, payload magic `YWPAY003`, record 1개, entropy `00`×32 |
| G4 | 공개 API로 `unlock` | 성공, `BackupPending`, 계정 0 = ACC-3 `0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb` |
| G5 | 오답 비밀번호 | `UnlockFailed` |

- G1 상수 기록 절차: `cargo test -p yw-core --lib vault::tests::print_golden_sha256 -- --ignored --exact`로 출력(그 함수만 `#[expect(clippy::print_stdout, reason = "golden")]`) → G3이 통과하는 것을 확인한 커밋에서만 상수로 넣는다. 이후 G1 실패는 형식 변경이므로 02 `VAULT_VERSION`을 올리거나 변경을 되돌린다.
- 비밀번호 변경·`PayloadRewrite`·변조 표 등 나머지 vault 테스트는 같은 파일에서 02 §11.6을 `KDF_TEST`와 KDF 호출 카운터로 수행한다.

### 3.13 저널·승인 골든 (V13 M4, V14 M2; 03 EVM-V13·V14)

G1과 같은 절차로 고정한다: 테스트가 아래 입력으로 바이트를 만들고, 모듈 코드를 쓰지 않는 독립 디코드(02 §5.4 entry 프레이밍, 03 §5.1 오프셋 표, §11.3–11.4 필드 순서를 테스트 안에서 직접 읽음)가 통과한 커밋에서 hex를 상수로 넣는다.

- **V13**(M4, `journal` 모듈과 함께; `src/journal/tests.rs`): EVM-V02 서명 바이트로 03 §5.1 레코드(`journal::evm`)를 인코드한다. chain_id 4(시험 도우미), account = V02 sender, nonce 819, state 1 `Signed`, role 0 `Original`, receipt_status 0, flags 0, created·updated 1,790,000,000,000, last_broadcast 0, tx_hash = V02 tx hash, approval_digest `a0a1…bf`, 포함 정보 0, origin `"yw-app"`, label `"[t] x"`. 본문 302바이트(raw 113). 골든은 02 §5.4 entry 전체 = `01`(kind EVM) ‖ `0000012e`(body_len 302, u32 BE) ‖ 본문 = 307바이트다.
- **V14**(M2, S2 픽스처 파서가 있는 `crates/yw-app/tests/`): 03 EVM-V14대로 `SimulationBinding` 태그(03 §11.1, §11.4 `sim_tag`)마다 골든 1개, 각각 display bytes(`YWDSP003…`)·display_digest·승인 digest. 공통: id `000102…0f`, Sepolia(genesis §3.11), ACC-1, created 1,791,381,216,000, expires 1,791,381,336,000.
  - 공통 고정 입력(M2 구현): `ChainFacts::default()`(계정 코드 EOA, 분류·토큰·주소록 없음), 해석·빌더·`issue`의 `now_unix_ms` = created, signer `Derived(0)`. 태그 1·2는 App 출처라 E28(정보)이 표시에 들어간다.
  - 태그 1 `Simulated`: §3.8 S2 요청·해석, origin App(`yw-app`), kind `EvmTransaction` 0x10. digest에 verdict `Ok`(0) ‖ number `0x9a0000` ‖ parent_hash `H(b0)` ‖ timestamp `0x6ac64ee0` ‖ base_fee 1 gwei(32바이트 BE) ‖ S2 응답의 sim_digest(03 §6.5).
  - 태그 2 `None`: 같은 요청을 S4 응답으로 해석, reason `RpcError`(5). 표시에 E01 경고(원인 줄 포함), `0x0121` `알 수 없음`, `0x0130` `시뮬레이션 없음: …`. diff 필드(`0x0110`–`0x0113`) 없음.
  - 태그 0 `NotApplicable`: EVM-V03 `Some data` `personal_sign`, origin `https://app.example`, kind `EvmPersonalSign` 0x13.
  - `sim_tag` 인코딩(03 §11.4) 이전 형식으로 계산한 값이 있으면 버리고 이 세 입력으로 다시 고정한다. 1비트 변경(verdict·reason·태그 포함)·`consume`·`replace`·`SimulationBindingMismatch` 사례 목록은 03 EVM-V14가 정본이다.

## 4. 부정·보안 테스트

### 4.1 키·vault·파일 (M1, M3)

| ID | 조작 | 기대 | 정본 |
|---|---|---|---|
| V-1 | 헤더 필드별 1비트 반전, 모든 길이 절단, 끝 1바이트 추가 | `Malformed`/`UnsupportedVersion`/`UnsupportedParams`는 Argon2 0회, 키 구간 변조는 `UnlockFailed`, payload 변조는 `PayloadCorrupt` | 02 §11.6 표 |
| V-2 | 오답 비밀번호와 `wrapped_dek` 변조 | 같은 `UnlockFailed`, 같은 화면 문구 | 02 §7.4 |
| V-3 | `KDF_TEST` 파일을 공개 API로 | `UnsupportedParams` | 02 §4.5 |
| V-4 | 사이드카 교차(meta를 journal로), 다른 vault의 meta, 1비트 변조 | 거부, `SidecarVaultMismatch`/`SidecarCorrupt` | 02 §11.7 |
| V-5 | 비밀번호 11자·129자·`0x7F`·`0x1F`·`é` / 12자·128자·공백 포함 | 거부 / 수락 | 02 §10.1 |
| V-6 | passphrase 257바이트·비ASCII / 0·256바이트, `" TREZOR"` | 거부 / 수락, `"TREZOR"`와 다른 seed | 02 §11.2 |
| V-7 | 니모닉: `abandon`×12(체크섬), `abandonn`, 11·13·25단어, `Abandon`, 선행·후행·이중 공백, 탭, NBSP, 257바이트 | `MnemonicChecksum`/`MnemonicUnknownWord{position}`/`MnemonicWordCount`/`MnemonicFormat` | 02 §2.4 |
| V-8 | RNG 실패·고착(32바이트 동일) | `RandomnessUnavailable`, 커밋 0회, 대체 난수원 없음 | 02 §11.1 |
| V-FS | yw-app `VaultStorage` 구현(yw-win 파일 함수 사용)의 `commit`을 단계 k(02 §6.2의 1–6) 직후 멈춘 뒤 새 저장소 객체로 `Vault::load`. 실제 임시 폴더, 같은 모듈의 `#[cfg(test)] commit_until(step)`로 멈춘다 | k ≤ 3: 이전 세대로 `Locked`, 고아 `.tmp` 삭제. k ≥ 4: 새 세대 `Locked`. 본 파일 삭제 → `MainMissing`. 본 파일 절단 → `Corrupt{prev_available:true}`, 본 파일 바이트 불변 | 02 §6 |
| V-DPAPI | `apikeys.dpapi` 왕복, 엔트로피 다르게 복호, 1바이트 변조 | 성공 / 실패 / 실패 | 04 §6.3 |

### 4.2 EVM·승인 (M2, M4, M5, M6)

단계(그 모듈이 생기는 마일스톤, 01 §2.2·03 §0): X-1–X-3·X-25는 dApp 파라미터 검증·라우팅(`browser::params`)이라 M5(§5.6 M5-14), X-5·X-17·X-18·X-21–X-24는 송신 슬롯·저널·RPC 흐름·사용자 체인 등록(`flow::evm`, `journal`, `rpc::evm`)이라 M4(§5.5 M4-12), X-19는 M6(§5.8 M6-1), 나머지는 M2(§5.3 M2-2).

| ID | 조작 | 기대 | 정본 |
|---|---|---|---|
| X-1 | `eth_sendTransaction` 키: `authorizationList`, `blobVersionedHashes`, `blobs`, `maxFeePerBlobGas`, `commitments`, `proofs`, `foo` 각각 | -32602, 창 없음 | 03 §3.2 |
| X-2 | `type` `0x1`·`0x3`·`0x4`, `to` 없음·null, `chainId` ≠ 활성, `gas` 16,777,217, data와 input 다른 바이트, data 131,073바이트 | -32602 | 03 §3.2 |
| X-3 | `from` ≠ 연결 계정 | 4100 | 03 §3.2 |
| X-4 | dApp `maxFeePerGas: "0x1"` | 창 열림, E31 정보, 서명된 거래의 maxFee = 지갑 계산값 | 03 §3.4 |
| X-5 | 같은 (체인, 계정)에 진행 중 거래 / 송신 슬롯 사용 중 | E06 차단 / -32002 | 03 §3.6, 05 §5 |
| X-6 | typed data domain.chainId = 1, 활성 Sepolia | T01 거부, 창 없음 | 03 §10.3 |
| X-7 | chainId 없음 / verifyingContract 없음 / Permit2 주소인데 다른 스키마 / `BulkOrder` | T03 고위험 / T10 주의 / T02 거부 / T02 거부 | 03 §8.3 |
| X-8 | 중복 타입 키, 순환 타입, 정수 `-0`·`1.0`·`1e0` | 거부 | `archive/spec-v2.4:crates/eip712/tests/vectors.rs:93-210` |
| X-9 | SIWE(origin `https://app.example`, 기본형 아래) 변형: domain `evil.example`; `http://app.example`; address 다름·체크섬 오류; Expiration `2020-01-01T00:00:00Z`; port `:8443`; Chain ID 1; Not Before `2099-01-01T00:00:00Z`; Nonce 7자; CR 포함 | S01·S02·S03·S04 차단, S05·S06·S07 주의, S08 고위험(마지막 두 개) | 03 §9.4 |
| X-10 | personal_sign `0xff00fe` / U+202E 포함 텍스트 | P01 고위험·hex 표시 / `[U+202E]` 이스케이프·P02 | 03 §9.2 |
| X-11 | 시뮬레이션 실패 S3·S3b(E02), S4·S9·S11·S12(E01), S7(E04)·S8·S8b(E03)·S13(E07)(S15 E36은 X-24) | §3.8 배너가 맨 위, 등급 고위험(차단 아님). 체크 끔 + 2초 누르기 / 체크 켬 + 1.9초 → `Pending`, 체크 켬 + 2.0초 → `Approved`(04 AP-2·AP-6) | D15·D16, 03 §10.1 |
| X-12 | 이중 계수 S6 | 네이티브 1회 계수 | 03 §1.3 |
| X-13 | 해석 불가 calldata + 시뮬레이션 성공 / + [결과 없음](S12 방식) | E12 고위험, 확인 체크 전 누르기 불가 / E12와 [결과 없음] 두 경고 함께, 체크박스 1개 + 2초 누르기로 `Approved` | D16, 03 §7.2 R7 |
| X-14 | 승인 일회 소비: 같은 `ApprovalId`로 `consume` 2회 / shown digest 1비트 다름 / 만료 후(120 s) / 잠금 후 | 둘째 오류 / `Invalidated` / 오류 / `invalidate_all`로 오류 | 03 §11.5 |
| X-15 | 승인 digest 입력 임의 1비트 변경(종류·origin·체인·계정·payload·표시·sim·만료), sim 있음 ↔ 없음 | digest 변화 | 03 §11.4 |
| X-16 | 오래된 시뮬레이션(61 s) / 그 재시뮬레이션이 실패 | 재시뮬레이션, 결과 다르면 새 클릭 / 배너로 표시 교체, 그 클릭 미소비·서명 0, 새 체크 + 2초 누르기 필요(§3.8) | 03 §6.6 |
| X-17 | 서명 후 검증 실패 주입(서명 바이트 1비트, 다른 키로 서명) | `PostSignVerification`, 저널 0, 전송 0 | 03 §4.3 |
| X-18 | RPC가 다른 tx hash 반환 | 저널 `Signed` + `rpc_hash_mismatch`, 자동 재전송 없음 | 03 §4.4 |
| X-19 | LLM: 꺼짐 / AI 상태 6종 / 날조된 주소·금액·숫자 | 전송 0회 / `can_approve`·digest·위험 동일 / `Mismatch`로 AI 텍스트 전부 숨김 | 06 §10 E1, E2, E4 |
| X-20 | 표시 문자열에 U+202E·U+200B·U+FEFF(토큰 심볼·typed data string·SIWE statement) | `[U+XXXX]` 이스케이프, `DisplayField::new` 재검사 통과 | 03 §9.2, §11.2 |
| X-21 | 사용자 체인 추가: 입력 chainId 8453, 가짜 RPC `eth_chainId` = `0x1` | 거부, 저장 0, 체인 목록 불변 | D14 |
| X-22 | 사용자 체인 추가: chainId 1·11155111·999 / 이미 추가한 사용자 체인과 같은 chainId | 각각 거부(RPC 호출 0), 기존 항목 불변 | D14 |
| X-23 | 추가 시 블록 0 해시 H1 고정 → 재시작(또는 RPC URL 변경) 뒤 연결에서 (a) 블록 0 = H2 (b) `eth_chainId` ≠ 등록값 | (a) 그 체인 읽기·보내기·서명·dApp 읽기 전부 체인 불일치 오류. H2를 보여 주는 확인 창에서 사용자가 다시 고정해야만 해제(취소 → 계속 오류), 재고정 뒤 정상 (b) 같은 오류, 재고정 없이 URL을 고칠 때까지 유지. 기본 제공 체인은 §3.11 상수와 비교(03 §1.4) | D14 |
| X-24 | `simulation = unsupported` 체인 보내기(§3.8 S15), 61 s 뒤 클릭 포함 | `eth_simulateV1` 호출 0, [미지원], 체크 + 2초 누르기로 서명·전송 | D14·D15 |
| X-25 | dApp `wallet_switchEthereumChain` 사용자 체인(8453) / 999 / 미등록 `0x89` / `wallet_addEthereumChain`(유효한 EIP-3085 파라미터) | `null` + `chainChanged` / 같음 / 4902 `UnrecognizedChain` / 4200 `UnsupportedMethod`, 창 없음, 체인 목록 불변 | D14, 05 §5 |

SIWE 기본형(LF 줄바꿈, 끝 LF 없음, 검사 시각 2026-10-26T00:00:00Z, 활성 체인 11155111, 서명 계정 ACC-1):

```
app.example wants you to sign in with your Ethereum account:
0x9858EfFD232B4033E47d90003D41EC34EcaEda94

Sign in to Example.

URI: https://app.example/login
Version: 1
Chain ID: 11155111
Nonce: 32891756
Issued At: 2026-10-25T23:59:00Z
```

### 4.3 브라우저 경로 (M5)

정본은 05 §10. 이 문서는 spec.md가 요구하는 항목의 위치만 정한다.

| 요구 | 테스트 |
|---|---|
| 다른 origin의 pipe 클라이언트 | 05 R-H1(인자: 정확한 origin만 통과, 끝 `/` 누락·대문자·다른 ID 거부), H1(잘못된 origin 인자 → 종료 2·출력 없음), R-P1(hello `extensionOrigin` 불일치 → `hello-reject "origin"`) |
| 큰 프레임 | 05 R-F1(길이 0·1,048,577 → 읽기 전 `Oversized`), R-H3(종료 코드 4/5), S2·R-J1(`bytes` 사례), R-E2(결과 > 1,044,480 B → 요청 단위 오류) |
| yw-app 없음·자동 실행(D24) | 05 R-H2(UNAVAILABLE 응답기: 골든 request → 4900, cancel·형식 오류 → 출력 없음), R-H4(`browserAutoLaunch` false → spawn 0회·즉시 4900·종료 3, 그 밖 → spawn 1회 후 10 s에 UNAVAILABLE), H1(debug 빌드 `YW_TEST_PIPE_NAME`·`YW_TEST_NO_SPAWN=1`·`YW_TEST_DATA_DIR`) |
| 잘못된 JSON·중복 키 | 05 R-J1(정수 `1.0`: `as_u64_allow_dot_zero` 수락·`as_u64` 거부 포함, 01 §2.3), R-D2(파싱 불가 프레임 뒤에도 연결 유지·다음 요청 정상, D23) |
| 요청 단위 오류·세션 유지 | 05 B3, B4, R-D2 |
| 수명 상한 없음 | 05 B1(5,000), R-D1(10,000) |
| 취소 전파 | 05 P5, B5, R-D3 |
| pipe DACL·첫 인스턴스 | 05 R-P2 |
| 메서드 목록 일치 | 05 S1, R-M1(`v1-methods.golden.json`) |
| 호환 모드(D22, 05 §2.12) | 05 P7–P11(모드 전달·플래그·`window.ethereum` 우선권·EIP-6963 가로채기·`_metamask.isUnlocked`), C5, E1–E2(저장소 → 페이지 → native 봉투), B8, S4, PO1–PO3(팝업), M1·M2(`action`, 팝업 port), R-E3(선택 `context.compatMode` 엄격 검사·승인 큐 전달·배지), audit(`action`·`popup/` 검사) |

### 4.4 Solana·Bitcoin (M7, M8)

| ID | 조작 | 기대 | 정본 |
|---|---|---|---|
| SOL-N1 | 만료 전 재서명 8사례(가짜 RPC) | 07 §17.4 ①–⑧ | 07 §14.3 |
| SOL-N2 | 템플릿 밖 메시지(명령 추가·순서·프로그램 ID·0x80/0x81 접두·header·중복 ComputeBudget), 202바이트(T_SOL)·372바이트(T_SPL) 각 비트 반전 | 거부 또는 동일성 검사 실패 | 07 §17.4 |
| SOL-N3 | 자기 자신, small-order·비정규 점 수신자, rent0 미만 새 계정, 남는 잔액 0 < r < rent0, 제네시스 불일치 / 곡선 밖(off-curve) 수신자 | 차단 / 곡선 밖은 고위험 `L02`(차단 아님, 07 §12.1-6: PDA·토큰 계정일 수 있음) | 07 §11–§15 |
| SOL-N4 | 공개 절반이 다른 64바이트 keypair | `from_keypair_bytes` 실패 | 07 §17.1 |
| SOL-N5 | (v1.1) T_SPL 템플릿 밖(ATA Create·Transfer·Token-2022·계정·그룹·역할), 허용 목록 밖·다른 클러스터 mint, decimals 9, ATA 불일치, 곡선 밖·small-order 받는 지갑, 372바이트 각 비트 반전 / RPC가 mint decimals 9·다른 owner·81바이트 / ATA 자리에 다른 mint·owner·동결 / 모르는 토큰 | 거부(`NotAllowlisted`·`AtaMismatch`·`RecipientOffCurve` 등) / `RpcAnomaly`(메시지 decimals는 6 그대로) / `Invalid`·동결 차단 / 조회·표시 없음 | 07 §8.3, §9, §12.1-6, §15.4 |
| BTC-N1 | 이전 거래 금액 위조(출력 금액 1바이트 변경, txid는 원본) | `TxidMismatch`, 후보 제외 | 08 §14.2 |
| BTC-N2 | 스크립트 불일치·vout 범위 밖·뒤 바이트·비정규 CompactSize | 각각 거부 | 08 §14.2 |
| BTC-N3 | 기록 금액과 계획 금액 다름 | 서명 전 중단 | 08 §5 |
| BTC-N4 | P2A·v2·v1/40·mainnet 지갑에 tb 주소·혼합 대소문자 | 08 §6.3 거부 코드 | 08 §14.1 |
| BTC-N5 | 수수료율·절대 상한 초과, dust 출력, 진행 중 두 번째 송금 | 차단 | 08 §8, §12.1 |
| BTC-N6 | 서버 문자열(`message`, `reject-reason`, Esplora 오류 본문) | 화면 모델에 없음 | 08 §14.2 |
| BTC-N7 | Esplora 응답 변조: `value` 소수·지수·문자열·음수·앞자리 0·`MAX_MONEY` 초과, `status` 모순(`confirmed:false` + 높이), `address` 반향 불일치, 개수 모순, text 경로 끝 `\n`·대문자 hex·잘못된 `Content-Type` | `MalformedResponse`(E-BTC-004), 후보·이력 반영 없음 | 08 §14.2 `esplora_*` |
| BTC-N8 | 인덱서 제네시스가 testnet3·signet·다른 네트워크(`esploraBaseUrl` 오설정), 429 4회 연속 | E-BTC-003 차단·주소 요청 0회 / 백오프 2·4·8 s 뒤 E-BTC-002, 발견 미완료 | 08 §14.2 `chain_check_indexer_genesis`·`indexer_429_backoff` |

## 5. 마일스톤 판정 체크리스트

각 항목은 `- [ ] ID 절차 → 기대`. 결과는 원칙 7대로 기록한다. "자동"은 `check.ps1` 통과로 판정한다.

### 5.1 M0 정리·뼈대

- [ ] M0-1 `git tag -l archive/spec-v2.4` → 한 줄. `git show archive/spec-v2.4:crates/secret-core/src/vault.rs` 성공.
- [ ] M0-2 `git ls-files`에 `crates/platform-windows`, `crates/key-agent-service*`, `crates/key-agent-debugger*`, `crates/dashboard`, `demo/`, `scripts/architecture-scan.mjs`, `scripts/service-probe/`, `scripts/windows-evidence/`, `scripts/release/`(audit-extension 이전 후) 없음.
- [ ] M0-3 `cargo metadata --no-deps --format-version 1` 워크스페이스 멤버 = yw-core, yw-json, yw-win, yw-app, yw-host 정확히 5개. `fuzz`는 `exclude`(01 §3.1).
- [ ] M0-4 `pwsh -File scripts/check.ps1` → 종료 코드 0, 출력에 `yw-core deps check OK: 34 crates (x86_64-pc-windows-msvc)`.
- [ ] M0-5 01 §4.5 음성 체크리스트 전 항목 1회(기대 종료 코드는 그 표). 같은 절차로 다음 4건도: (a) yw-core에 `serde = "1"` → 21(레지스트리 캐시에 없으면 lock 갱신은 온라인) (b) yw-core 소스에 `unsafe {}` → 22(clippy가 forbid 오류를 먼저 보고) (c) 들여쓰기 깨기 → 20 (d) 비면제 `crates/yw-core/src/lib.rs` 주석에 `private_key = "<64 hex>"` → 27(테스트 경로는 01 §4.3 `TEST_VECTOR_PATH` 면제라 걸리지 않는다).
- [ ] M0-6 도구: `rustc +1.95.0 -V`(rust-toolchain.toml), `node -v` ≥ 22, MSVC C 컴파일러(secp256k1-sys 빌드) 확인.

### 5.2 M1 키·vault (자동 + 수동 도구)

- [ ] M1-1 B39-1–4, BIP32 벡터 1–5(§3.3, 전체 xprv·xpub 문자열), ACC-1–5 통과.
- [ ] M1-2 G1–G5 통과. G1 상수를 넣은 커밋에서 G3이 통과했음을 기록.
- [ ] M1-3 V-1–V-8 통과(V-FS는 yw-app `store.rs`·yw-win `file`이 생기는 M3-12에서 판정). 02 §11.1–11.8 통과. 단 단계 표시 항목은 그 마일스톤에서 판정한다: §11.7 journal 컨테이너(M4-12), §11.5 SLIP-0010·`SolKeySource`(M7-1), §11.3 `derive_public_child`·§11.4 CKDpub 행(M8-2).
- [ ] M1-4 측정(기록만): release 빌드에서 대상 PC Argon2 1회 시간(02 §7.4).
- [ ] M1-5 수동 도구: 퍼징 `vault_header` 600 s, 충돌 0(§2.4).

### 5.3 M2 EVM 코어 (자동 + 수동 도구)

- [ ] M2-1 03 EVM-V01–V12·V14(§3.13 태그 0·1·2 골든)와 EVM-V17의 코어 사례(03 §6.3 표 각 행 → 규칙·`SimulationBinding`·`risk == High`·`ack_required`·차단 없음·`issue` → `consume` 성공(체크 + 2.0 s 입력 순서 자체는 yw-app `ui::interaction` 04 AP-2(M3)·AP-6(M4-12)에서 판정), E12 + E01 체크박스 1개, 경고 순서, 결과 없음 바인딩 60 s 뒤 재시뮬레이션 없음, R8, E37 + 03 §3.5 대체 가스 벡터, E38 주의) 통과(값은 §3.4–3.8, §3.13). V13(저널)·V16(체인 설정)과 V17의 `flow::evm` 사례는 M4-12, V15는 M4·M5 E2E.
- [ ] M2-2 X-4, X-6–X-16, X-20 통과(나머지 X는 §4.2 단계 표시대로 M4-12·M5-14·M6-1). `policy` 모듈은 `BrowserOrigin`으로 M2에 시작하므로(01 §2.2) 05 R-ERR 중 `BrowserOrigin::parse`(05 §4.7) 사례도 여기서 통과한다(R-ERR 나머지는 M5-14).
- [ ] M2-3 퍼징 `json`, `rlp`, `signed_tx`, `abi`, `eip712`, `simulate`, `siwe` 각 600 s, 충돌 0.
- [ ] M2-4 §2.5 프로브 L-SIM·L-REVERT·L-HYPEREVM·L-GENESIS(`node scripts/probe-rpc.mjs`, 엔드포인트는 D13 개발 설정 `%USERPROFILE%\.yw-dev\rpc.json` 또는 `YW_RPC_JSON`, 설정한 공급자 = 현재 QuickNode) 출력과 종료 코드(0/1)를 기록. L-HYPEREVM으로 999 기본 `simulation`을 03 §1.1 상수와 §3.11에 반영하고, L-GENESIS의 999 해시는 기록만 한다(상수 아님, §3.11). L-SIM·L-REVERT 응답 형태가 §3.8 S1–S3과 다르면 픽스처를 추가한 뒤 M2를 판정한다. 종료 1의 원인이 999 시뮬레이션 미지원이나 A5 실패(플랜·권한)뿐이면 M2를 막지 않는다(D15): 다른 엔드포인트·공급자로 교체 또는 그 체인 `simulation = unsupported`로 기록. 1·11155111의 `chain`·`genesis` 불일치는 M2 전에 엔드포인트를 고친다. 출력·기록 파일에 URL·호스트·토큰이 없고 `NetworkId`만 있음을 확인.

### 5.4 M3 앱 뼈대 (수동, 04 §10 UI-M3-01–14 포함)

준비: release 빌드, `%LOCALAPPDATA%\YourWallet\v3` 없음(있으면 `v3.bak`으로 이름 변경), 시험 비밀번호 `m3-test-password!`, 클립보드 기록(Win+V) 켬, OBS Studio 설치.

- [ ] M3-1 새 지갑 생성 → W08(24단어 표시) 상태에서: (a) Win+Shift+S 전체 화면 캡처 → 그림판에 붙여넣기 (b) PrtScn (c) OBS "디스플레이 캡처" 미리보기 → (a)(b)(c) 결과에 W08이 나타나지 않고 뒤 화면이 보인다(창 자리에 검은 영역이 보이면 불합격, spec §5 M3). (d) OBS "윈도우 캡처"(W08 선택, 캡처 방식 Windows 10 1903+) 미리보기 → 내용 없는 빈/검은 프레임. 같은 확인을 W01·W02·W05·W07·W10에서 (a)·(c)로 반복.
- [ ] M3-2 W08에서 Ctrl+C·우클릭·끌기(복사 토글 끔) → 메모장 붙여넣기 결과가 이전 클립보드, Win+V 목록에 새 항목 없음.
- [ ] M3-3 설정 `allowSecretCopy` 켬 → W08 `복사` → 메모장 붙여넣기 성공 → Win+V 목록에 그 항목 없음 → 30초 뒤 붙여넣기 결과 빈 값. 다시 복사 → 10초 안에 다른 텍스트 복사 → 30초 뒤 그 텍스트 유지(UI-M3-04). 토글 끔으로 되돌림.
- [ ] M3-4 백업 확인: 틀린 단어 → 실패(어느 칸인지 알려주지 않음) → 새 challenge로 정답 → 완료. 앱 재시작 후 백업 대기 화면 없음.
- [ ] M3-5 자동 잠금 4경로(각각 잠긴 뒤 로그 `lock reason=` 확인): `autoLockMinutes` 1 → 다른 앱만 61초 사용 → `Idle`; Win+L → 복귀 시 `SessionLock`; 시작 → 전원 → 절전 → 깨움 → `Suspend`; `잠금` 버튼·Ctrl+L → `Manual`. 잠긴 동안 비밀 창이 모두 닫혀 있음.
- [ ] M3-6 앱 종료 → 재실행 → 잠금 해제 → 계정 0 주소가 생성 직후 백업 화면의 주소와 같음. 틀린 비밀번호 → 02 §7.4 문구, 1초 입력 비활성.
- [ ] M3-7 가져오기(`v3` 폴더를 이름 변경해 `NoVault`로 시작, 끝나면 되돌림): about → `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`; 같은 니모닉 + passphrase `TREZOR` → `0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6`; passphrase에 한글 입력 시도 → 거부(E-INP-008). raw key `0x000…001` 가져오기 → `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf`.
- [ ] M3-8 RPC 엔드포인트 저장(04 UI-M3-11, D13): 내장 3체인(`eip155:1`·`eip155:11155111`·`eip155:999`)에 설정한 공급자(현재 QuickNode) URL을 템플릿(엔드포인트 이름 + 토큰) 또는 직접 입력으로 저장(값은 §2.5 개발 설정과 같은 URL, 기록에 남기지 않음) → `apikeys.dpapi`에서 토큰 앞 8자·엔드포인트 이름 검색(`Select-String -SimpleMatch`) 0건 → 재시작 후 네트워크마다 `연결 확인` 성공. §2.5 L-ORIGIN 기록.
- [ ] M3-9 로그 비밀 검사: M3 전 과정 뒤 `logs\` 전체에서 시험 비밀번호, M3-7 니모닉 단어열(`abandon abandon`), raw key hex, 엔드포인트 토큰 앞 8자, 엔드포인트 이름·`quiknode`(호스트, 01 §5.4), `TREZOR`를 검색 → 모두 0건. RPC 로그 줄은 `NetworkId`로만 대상을 가리킨다.
- [ ] M3-10 원자적 쓰기: 비밀번호 변경 확인을 누른 직후(Argon2 진행 중) 작업 관리자로 yw-app 종료 → 재실행 → 이전 또는 새 비밀번호 중 정확히 하나로 열림, `Corrupt` 없음, `.tmp` 남지 않음.
- [ ] M3-11 04 §10 UI-M3-05·06·10·13·14 수행(UI-M3-11은 M3-8, 나머지 UI-M3 항목은 M3-1–M3-10이 덮는다).
- [ ] M3-12 자동: V-DPAPI·V-FS(§4.1), 04 §6.5 ST-2(`apikeys.dpapi` 평문 형식: 네트워크별 URL 왕복·형식 오류·미등록 항목 무시) 통과.

### 5.5 M4 EVM 단독 전송 (자동 + Sepolia·HyperEVM 수동, 04 §10 UI-M4-01–16 포함)

준비: Sepolia ETH 0.05 이상(공개 faucet), 등록 토큰 1종 잔액(03 §1.2 Sepolia USDC: Circle faucet, 주소는 구현 시 확인), 수신 주소 2개(기존 사용 주소, 한 번도 쓰지 않은 주소). HyperEVM(999) 계정 0에 HYPE 소액(송금 + 수수료, 1 USD 상당 이하). 사용자 체인용으로 HTTPS RPC 엔드포인트가 있는 EVM 테스트넷 1개(설정한 공급자 또는 공개 RPC, 구현 시 선택), 999 기본 `simulation`이 `auto`(§2.5 L-HYPEREVM)면 그 체인 faucet 잔액도. 내장 3체인 엔드포인트는 M3-8로 앱에 저장(설정한 공급자 = 현재 QuickNode, 원본은 D13 개발 설정과 같은 URL, 기록에 남기지 않음). UI-M4-11용으로 `eth_simulateV1`을 지원하지 않는 Sepolia 엔드포인트 1개(구현 시 확인).

- [ ] M4-1 잔액이 Sepolia Etherscan 값과 같음.
- [ ] M4-2 기존 주소로 0.001 ETH(UI-M4-01): 승인 창 제목 `[Sepolia 테스트넷]`, 받는 주소 EIP-55 전체, 보냄 −0.001, 최대 수수료, 시뮬레이션 블록 표시 → 승인 → 영수증 status 1, 영수증 `gasUsed` == 승인 창 시뮬레이션 `gasUsed`(21,000을 가정하지 않는다, 03 §1.3), Etherscan과 해시 일치. 영수증·시뮬레이션·그 시점 `eth_estimateGas` 값을 §2.5 probe 파일에 기록.
- [ ] M4-3 새 주소로 0.001 ETH → 가스 한도 245,520 근처(추정 204,600 × 1.2)로 성공. 21,000 고정 실패가 없음.
- [ ] M4-4 ERC-20 전송(UI-M4-02) → 토큰 라벨·컨트랙트 주소·10진 금액, diff가 Transfer 로그와 일치, 성공 후 잔액 갱신.
- [ ] M4-5 시뮬레이션 실패 → 맨 위 고위험 배너(D15, §3.8 약칭, 차단 아님). 각 경우: "시뮬레이션 중…"(≤ 10 s) 동안만 승인 입력이 무시됨(04 AP-6) → 결과 표시 뒤 맨 위 배너·원인 줄 확인 → 체크 없이 2초 누르기 → 승인 안 됨 → 체크 → 2초 누르기 가능: (a) ETH를 받지 않는 컨트랙트(Sepolia USDC 컨트랙트 주소)로 0.0001 ETH(UI-M4-03; 잔액을 넘는 금액은 보내기 폼이 E-INP-012로 막는다, 04 §2.15) → [실행 실패] E02 + revert 이유(가스 추정도 실패하면 E37 "가스 추정 실패"가 함께 맨 위, 대체 가스 03 §3.5) → 체크 + 2초 누르기로 실제 승인 → Etherscan 영수증 status 0, 수수료만 차감. (b) 잔액보다 큰 ETH도 폼이 E-INP-012로 막으므로 -38014 [결과 없음] E01은 자동(§3.8 S4, 04 AP-6)으로 판정하고, 수동은 UI-M4-11·UI-M4-16의 E01로 대신한다. (c) Wi-Fi 끈 뒤 검토(UI-M4-04) → 체인 확인·nonce·수수료 조회 실패로 E35 "거래를 준비할 수 없음" **차단**(03 §10.2·§3.7; 시뮬레이션 배너가 아니다 — 서명할 거래를 만들지 못함): 승인 불가·거부만, 서명·저널·전송 0 → Wi-Fi 켜고 다시 시도 → 정상 승인 창.
- [ ] M4-6 승인 창을 61–110초 연 뒤 승인 → 로그에 재시뮬레이션 1회, 결과 같으면 그대로 진행. 다시 보내기 검토 → 61–90초에 Wi-Fi 끄고 승인 클릭(UI-M4-16) → "시뮬레이션 중…" 뒤 재시뮬레이션 실패 → 표시가 [결과 없음] E01 배너로 바뀌고 T-SIM-RESIM-FAILED, 그 클릭은 소비되지 않음(서명·전송 0), 체크 해제 → Wi-Fi 켬 → 체크 + 2초 누르기 → 재시뮬레이션 없이(03 §6.6-1) 서명·전송·영수증 status 1. 또 한 번 검토 → 120초 방치 → 만료(UI-M4-09).
- [ ] M4-7 첫 거래 미확정 중 두 번째 보내기 → 차단(E06, UI-M4-06).
- [ ] M4-8 저널 복구(debug 빌드, `YW_FAULT_POINT` 지점마다 0.0001 ETH 1회):

| 지점 | 위치(03) | 재시작·잠금 해제 후 기대 |
|---|---|---|
| `evm.after_journal_signed` | §5.3 2단계 커밋 직후, 전송 전 | `Signed` → §5.4가 같은 raw 재전송 → 같은 tx hash로 포함 |
| `evm.after_send_raw` | `eth_sendRawTransaction` 응답 직후, `Broadcast` 커밋 전 | `eth_getTransactionByHash` 존재 → `Broadcast` → 포함, 재서명 없음 |
| (수동) 작업 관리자 강제 종료 | "전송 확인 중" 표시 동안(UI-M4-05) | 같은 해시가 활동에 있고 상태 갱신 |

  각 경우 Etherscan에서 그 nonce의 거래가 정확히 1개이고 저널의 서명 레코드가 1개다.
- [ ] M4-9 받기 QR을 휴대폰 카메라로 읽음 → `ethereum:<EIP-55 주소>@11155111`, 화면 문자열과 같음(UI-M4-08).
- [ ] M4-10 Sepolia 수수료 상한을 설정 최솟값으로 낮춤 → E05 차단 → 원복.
- [ ] M4-11 04 §10 UI-M4-07·10·11 수행(UI-M4-11: Sepolia 엔드포인트를 `eth_simulateV1` 미지원 엔드포인트로 재정의 → [결과 없음] E01 + 원인 → 체크 + 2초로 전송·확정 → 재정의 삭제).
- [ ] M4-12 자동(`journal`·`journal::evm`·`flow::evm`과 `rpc::evm`의 전송·호출이 생기는 단계): 03 EVM-V13 전부(§3.13 V13 골든, 03 §5.2 상태 전이 표, 손상 레코드 거부, 자리 없음 → `journal::JournalError::Full` → E06 "거래 저널 공간이 부족합니다"), 03 EVM-V16 전부(내장 3체인 상수 §3.11, `validate_user_chain` 경계, 추가·재연결 체인 확인, `RpcMismatch` → E34·4901, 999 첫 연결 고정), 03 EVM-V17의 `flow::evm` 사례(`simulation = unsupported` → 가짜 전송 `eth_simulateV1` 0회·E36, 재시뮬레이션 실패 → `None`으로 `replace` + 새 클릭, 가스 추정 실패 → E37·대체 가스로 계속), 02 §11.7 journal 컨테이너 항목, X-5·X-17·X-18·X-21–X-24, 04 §3.9 AP-6, 04 §6.5 ST-1(`settings.json` `evmChains`·`evmGenesisPins`)·ST-3(S17 입력 판정) 통과.
- [ ] M4-13 HyperEVM(999) 소액 송금(계정 0 → 계정 1, UI-M4-13): 첫 연결에서 체인 확인(chainId `0x3e7`) 통과와 블록 0 해시 고정(T-GENESIS-PINNED, `evmGenesisPins["eip155:999"]` = §2.5 L-GENESIS 기록값), 승인 창 제목에 HyperEVM 네트워크 이름. 가스 한도가 `small_block_gas_limit` 3,000,000(§3.11, 03 §1.1) 이하이므로 E38 없음(초과 시 E38은 주의 등급이라 승인 조작을 바꾸지 않는다; 경계는 M2-1 EVM-V17). 999 기본 `simulation`이 `unsupported`면 맨 위 [미지원] E36(로그에 999 `eth_simulateV1` 줄 0) → 체크 없이 2초 누르기 → 승인 안 됨 → 체크 + 2초 → 영수증 status 1, HyperEVM 탐색기와 해시 일치. `auto`면 시뮬레이션 결과 표시로 같은 송금이 성공하고, [미지원] 절차는 M4-14 (d)에서 한다.
- [ ] M4-14 사용자 체인(설정, D14, UI-M4-12·14·15): (a) chainId를 실제와 다르게 입력 → 거부(E-CHN-001), 목록 불변 (b) chainId 1·11155111·999 → 중복 거부 (c) 올바른 값 + `simulation = unsupported` → 추가(T-CHAIN-PIN) (d) (999가 `auto`일 때) 그 체인 소액 송금을 M4-13 절차로 → [미지원] E36, 확인 후 영수증 status 1 (e) 앱 재시작 → 그 체인 잔액 조회 정상(chainId·블록 0 재확인 통과) (f) `settings.json`의 그 체인 `genesisHash` 1자 변경 → E-CHN-008 차단(E34), `다시 고정` 후 정상(UI-M4-14) (g) 삭제: 활성 상태·미종결 거래 중 거부, 확정 후 삭제(UI-M4-15).
- [ ] M4-15 §2.5 `live_probe`(L-LIMITS, 03 §1.5 A1–A8·A9(c)–(e); A6은 M4-2 전송 직후, A9는 M4-13 전) 기록. `probe-rpc.mjs` 결과와 다른 항목은 원인을 적는다.

### 5.6 M5 브라우저 연동 (자동 + 수동, 05 §10 포함)

준비: `cargo build --release`, `scripts/register-native-host.ps1`, 확장 로드(05 §9.4), yw-app `allowLocalhostDapps` 켬, M4-14 사용자 체인 등록 유지(chainId 137이 아닐 것), `node extension/test-dapp/serve.mjs` → `http://localhost:5173/`.

- [ ] M5-1 test-dapp 전 버튼(§5.7 T01–T32) 기대 결과 일치.
- [ ] M5-2 다른 확장 ID: `extension/`을 복사해 `manifest.json`의 `key` 삭제 후 로드(원본 확장은 끔) → 사본으로 T03 → 4900, 사본 service worker 콘솔에 `Access to the specified native messaging host is forbidden`, 작업 관리자에 새 yw-host 없음.
- [ ] M5-3 `target\release\yw-host.exe chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/` 직접 실행 → 1초 안에 종료 코드 2, yw-app 로그에 연결 없음.
- [ ] M5-4 오류 뒤 세션 유지: T28·T29 직후 T03 성공. yw-app 로그의 연결이 끊기지 않음.
- [ ] M5-5 `chrome://serviceworker-internals`에서 worker Stop → 새로고침 없이 T03 성공.
- [ ] M5-6 `browserAutoLaunch` true(기본), yw-app 종료 상태에서 T03 → yw-app이 `--background`로 시작, 10초 안에 응답(D24). 잠금 상태에서 T07 → 잠금 해제 창 → 해제 후 승인 창.
- [ ] M5-7 승인 창이 열린 동안 다른 탭 T06 응답. T07 승인 창이 열린 상태에서 dApp 탭 닫기 → 2초 안에 창 닫힘, 저널·Etherscan에 거래 없음.
- [ ] M5-8 잠금 → test-dapp 로그에 `accountsChanged([])`, 해제 → 계정 복귀. 앱에서 연결 해제 → 계정 사라짐.
- [ ] M5-9 `allowLocalhostDapps` 끔 → T01 4100, 켬 → 동작.
- [ ] M5-10 공개 dApp 1개(구현 시 확인: app.uniswap.org의 Sepolia 지원): EIP-6963 목록에 Your Wallet, 연결, Permit2 서명 창이 `Permit2 승인 서명` 구조 표시, swap 거래는 Universal Router 라벨 + E12 + 시뮬레이션 성공. 지원하지 않으면 이 항목은 "해당 없음"으로 기록한다(T01–T32가 판정 근거).
- [ ] M5-11 05 §10.4 7번(직접 실행 플래그 켬·끔 각각 T01–T06).
- [ ] M5-12 `settings.json`에 `"browserAutoLaunch": false`, yw-app 종료 상태에서 T03 → 4900 `Wallet is unavailable.`, 작업 관리자에 yw-app 없음(yw-host가 실행하지 않음). true로 되돌림.
- [ ] M5-13 T03으로 yw-app 자동 실행 → Chrome 완전 종료(백그라운드 실행 포함) → yw-app 생존 여부 기록(D24 job object). 함께 종료되면 D24 대안 적용: `browserAutoLaunch` 기본값을 false로 바꾸고 수동 실행 안내, M5-6을 "yw-app 수동 실행 후 T03 성공"으로 재판정.
- [ ] M5-14 자동: 05 §10.1·§10.2 전 사례(JS S1–S4·P1–P11·C1–C5·E1–E2·B1–B8·PO1–PO3·N1·manifest M1·M2·H1, Rust R-F1·R-J1·R-H1–R-H4·R-P1·R-P2·R-E1–R-E3·R-M1·R-V1·R-ERR·R-D1–R-D5·R-G1)와 X-1–X-3·X-25 통과(H1은 `YW_CHECK=1`이라 skip 없이 실행됨, §2.2). 퍼징 `frame`·`envelope` 각 600 s, 충돌 0.

호환 모드(D22, 05 §2.12) 준비: 확장 카드의 새로고침 버튼으로 확장을 다시 읽고 열린 탭을 새로고침한다. 툴바의 퍼즐 아이콘 → Your Wallet 옆 핀을 눌러 아이콘("Y")을 고정한다. 모드를 바꾼 뒤에는 **항상 dApp 탭을 새로고침**한다(다음 페이지 로드부터 적용). 실제 MetaMask·Rabby 켬/끔은 `chrome://extensions`의 사용 토글로 한다.

- [ ] M5-15 팝업: Your Wallet 아이콘 클릭 → 카드 "Your Wallet 앱 연결 상태"(색 상태 표시), 모드 카드 3개("기본 (Your Wallet)", "MetaMask처럼 보이기", "Rabby처럼 보이기", 카드마다 한 줄 설명), "모드 변경은 다음 페이지 로드부터 적용됩니다…" 안내, 경고 "호환 모드를 쓸 때는 실제 MetaMask·Rabby 확장을 꺼 두세요. 켜져 있으면 dApp이 그 지갑에 연결될 수 있습니다."가 보인다. Chrome을 새로 켠 직후(요청 전) 상태 "확인 불가". test-dapp T03 뒤 다시 열면 "연결됨". `browserAutoLaunch` false + yw-app 종료 상태에서 T03(4900) 뒤 "연결 안 됨". 팝업을 닫았다 열어도 고른 모드가 유지된다. 팝업 우클릭 → "검사"의 콘솔에 오류·CSP 위반이 없다.
- [ ] M5-16 MetaMask·Rabby 끔, 모드 "MetaMask처럼 보이기" → test-dapp 새로고침: C01 PASS(`isMetaMask` true, `isYourWallet` true, accessor), C05 PASS(목록에 "MetaMask (io.metamask)" 하나뿐, Your Wallet 항목 없음). C02 → yw-app 연결 창: 큰 글씨 origin `http://localhost:5173`(실제 사이트), 배지 "호환 모드: MetaMask" → 연결 → 계정. C03 → SIWE 서명 창(S09 정보, 필드 표, 같은 배지) → 승인 → ecrecover PASS. C04 → `true`. yw-app 잠금 → C04 → `false`. 해제 후 C05 목록의 "MetaMask (io.metamask)로 연결" 버튼 → 창 없이 계정.
- [ ] M5-17 같은 조건에서 "Rabby처럼 보이기" → 새로고침: C01(`isRabby` true), C05 "Rabby Wallet (io.rabby)" 하나, C02 연결 창 배지 "호환 모드: Rabby"(연결 해제 후 확인), C03 SIWE 서명 창에도 같은 배지.
- [ ] M5-18 "기본 (Your Wallet)"로 되돌림 → **새로고침 전** C01은 이전 모드 그대로(문서마다 고정), 새로고침 후 C01 "default mode" PASS(`isMetaMask` false), C05·T32 Your Wallet 하나, T01 연결 창에 호환 모드 배지 없음.
- [ ] M5-19 실제 MetaMask 켬(가능하면 Rabby도 따로 켬)에서 M5-16을 반복하고 C01·C05·C02 결과를 기록한다. 기대: Your Wallet이 MetaMask 자리를 차지하고 실제 MetaMask 알림은 C05 목록에 없다. 실제 지갑이 이기면(C01 "another MetaMask-like wallet", C05에 io.metamask 둘, 또는 MetaMask 팝업이 뜸) 05 §2.12 한계로 기록하고 팝업 경고와 일치함을 확인한다. 같은 상태에서 기본 모드로 바꾸면 C05 목록에 실제 MetaMask·Rabby가 그대로 보인다(가로채지 않음).
- [ ] M5-20 실제 MetaMask 전용 dApp, Sepolia(구현 시 확인: MetaMask 버튼만 있거나 `window.ethereum.isMetaMask`만 검사하는 dApp. 후보: MetaMask 공식 Test Dapp `https://metamask.github.io/test-dapp/`). 실제 MetaMask 끔·켬 각각, 모드 "MetaMask처럼 보이기": dApp의 MetaMask 연결 → yw-app 연결 창(그 사이트의 실제 https origin + "호환 모드: MetaMask") → 연결; SIWE 로그인(있으면, 없으면 personal_sign) → yw-app 서명 창 → 승인 → dApp이 로그인·서명 결과를 받음; `eth_signTypedData_v4` 1회. yw-app "연결된 사이트"에 그 origin이 보인다. 맞는 dApp이 없으면 C01–C05를 판정 근거로 하고 "해당 없음"으로 기록한다.

### 5.7 `extension/test-dapp/`

순수 HTML·JS, 외부 스크립트·npm 없음. 확장 `src/` 밖이므로 audit-extension 대상이 아니다.

| 파일 | 내용 |
|---|---|
| `serve.mjs` | `node:http` 정적 서버. `127.0.0.1:5173`과 `[::1]:5173`에만 바인드, 이 폴더 파일만, 디렉터리 목록 없음, `Content-Type` 고정 표, 30줄 안팎 |
| `index.html` | 버튼 T01–T32(T20b 포함), "MetaMask 전용 dApp 흉내" 구역 C01–C05와 지갑 선택 목록, 입력칸(수신 주소, 금액, 토큰 주소), 결과 로그(`<pre>`, `textContent`만) |
| `app.js` | T01–T32: EIP-6963 `requestProvider`로 Your Wallet 선택, 없으면 `window.ethereum`(호환 모드에서는 Your Wallet rdns 알림이 없으므로 `window.ethereum` = 우리 provider). C01–C04: `window.ethereum.isMetaMask`만 검사하고 `window.ethereum`만 쓴다. C05: 받은 EIP-6963 알림을 uuid로 모아 이름·rdns 목록과 항목별 연결 버튼을 만든다 |
| `keccak.js` | 시험용 Keccak-256(약 80줄). personal_sign·SIWE 서명을 ecrecover 프리컴파일(`0x…01`) `eth_call`로 검증 |

WETH = Sepolia `0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14`(03 §1.2, 구현 시 확인), Permit2 = `0x000000000022D473030F116dDEE9F6B43aC78BA3`, A0/A1 = 연결 계정 0/1.

| ID | 요청 | 기대 |
|---|---|---|
| T01 | `eth_requestAccounts` | 연결 창 → `[A0]`, 이벤트 `accountsChanged` |
| T02 | `eth_accounts`(연결 전/후), `wallet_getPermissions` | `[]` / `[A0]`, EIP-2255 객체 |
| T03 | `eth_chainId`, `net_version`, `web3_clientVersion` | `0xaa36a7`, `11155111`, `YourWallet/<버전>` |
| T04 | `wallet_switchEthereumChain` `0x1` → `0x3e7` → (M4-14 사용자 체인) → `0xaa36a7` / `0x89`(미등록) | `chainChanged` 4회(각 값, 창 없음) / 4902 |
| T05 | `wallet_revokePermissions` → `eth_accounts` | `null` → `[]`(이후 T01 다시) |
| T06 | `eth_blockNumber`, `eth_getBalance(A0)`, `eth_call`(WETH `balanceOf(A0)`), `eth_estimateGas`, `eth_feeHistory`, `eth_getLogs`(최근 10블록, WETH) | 결과가 Etherscan과 모순 없음 |
| T07 | ETH 0.0001 → A1 | 승인 → tx hash, 영수증 성공 |
| T08 | WETH `deposit()` 0.001 ETH | `weth_deposit` 해석, diff ETH −0.001·WETH +0.001 |
| T09 | WETH `transfer(A1, 0.0005e18)` | `erc20_transfer`, Transfer 로그 확인 |
| T10 | WETH `approve(Permit2, 10^15)` | `erc20_approve`, 라벨 `[Uniswap Permit2]`, E20 주의 |
| T11 | WETH `approve(Permit2, 2^256−1)` | E14 고위험 + 체크 + 2초 누르기 |
| T12 | WETH `approve(A1, 1)` | E16 고위험(EOA spender) |
| T13 | WETH에 `0xdeadbeef` + 0 32바이트(fallback → deposit 0) | E12 "해석되지 않은 호출" 고위험 + 체크, 시뮬레이션 성공 |
| T14 | WETH `withdraw(10^30)` | 맨 위 [실행 실패] E02(§3.8) + E37 "가스 추정 실패"(03 §3.5 대체 가스), 둘 다 고위험·차단 아님(승인 가능). 체크 없이 2초 누르기 → 승인 안 됨 → 체크 → 누르기 가능 확인 → 거부 4001(서명·전송 0) |
| T15 | `eth_sendTransaction` + `authorizationList: []` | -32602, 창 없음 |
| T16 | `type:"0x4"` / `to` 없음 / `chainId:"0x1"` / `from:A1`(미연결) | -32602 / -32602 / -32602 / 4100 |
| T17 | T07 + `maxFeePerGas:"0x1"` | E31 정보, Etherscan의 maxFee ≠ 1 wei |
| T18 | `personal_sign`("Hello, Your Wallet" UTF-8 hex, A0) | 텍스트 표시, 서명 → ecrecover = A0 |
| T19 | `personal_sign`(`0xff00fe`) | hex 표시, P01 고위험 |
| T20 | SIWE: 첫 줄 `http://localhost:5173 wants you to sign in with your Ethereum account:`(scheme 명시), URI `http://localhost:5173`, Chain ID 11155111, Nonce 16자, Issued At 현재 | S09 정보, 필드 표, ecrecover = A0 |
| T20b | T20에서 scheme 생략(`localhost:5173 wants …`) | S02 차단(생략 scheme = `https` ≠ origin `http`, 03 §9.3) |
| T21 | SIWE domain `evil.example` | S01 차단 |
| T22 | SIWE Expiration 과거 | S04 차단 |
| T23 | v4 Permit2 `PermitSingle`(Sepolia 도메인, token WETH, amount 2^160−1, expiration 0, nonce 0, spender A1, sigDeadline 현재+1,800) | `Permit2 승인 서명`, 무제한, "사용 블록에서만 유효", T05·T09. 서명 뒤 `eth_call` Permit2 `permit(A0, PermitSingle, sig)`(selector `0x2b67b570`)가 되돌려지지 않음 |
| T24 | v4 EIP-2612 `Permit`(도메인 `{name:"Test Token",version:"1",chainId:11155111,verifyingContract:WETH}`, owner A0, spender Permit2, value 2^256−1) | `토큰 사용 허가 서명`, 무제한, T05 |
| T25 | v4 Ether Mail(chainId 11155111) | 미인식 스키마 트리, T04 고위험 |
| T26 | v4 domain chainId 1 | T01 거부(-32602), 창 없음 |
| T27 | v4 chainId 없음 | T03 고위험 |
| T28 | `eth_sign`, `eth_signTransaction`, `eth_sendRawTransaction`, `eth_signTypedData_v3`, `wallet_sendCalls`, `wallet_addEthereumChain`(유효한 EIP-3085 파라미터, chainId `0x89`), `foo_bar` | 각 4200, 창 없음, yw-app 체인 목록 불변 |
| T29 | 2 MiB 문자열 `personal_sign` / 깊이 40 params | 확장에서 -32600 "Request too large." / 같음 |
| T30 | `eth_blockNumber` 순차 5,000회 | 5,000 성공(속도 제한 -32005가 나오면 250 ms 대기 후 재시도해 최종 성공) |
| T31 | T07을 보낸 뒤 승인 창에서 결정하지 않고 탭 닫기 | M5-7 기대 |
| T32 | `eip6963:requestProvider` | 공지 1개, rdns `io.github.na-degen-girl.yourwallet`(기본 모드. 호환 모드에서는 C05로 판정) |

"MetaMask 전용 dApp 흉내"(05 §2.12, 모드를 바꾼 뒤 새로고침):

| ID | 동작 | 기대(MetaMask 모드 / Rabby 모드 / 기본 모드) |
|---|---|---|
| C01 | `window.ethereum` 속성 종류와 `isMetaMask`·`isRabby`·`isYourWallet`·`_metamask.isUnlocked` 표시 | accessor, `true`·`false`·`true`·function / accessor, `true`·`true`·`true`·function / data, `false`·`false`·`true`·undefined("MetaMask 전용 dApp은 지갑을 못 찾음"이 기본 모드의 PASS) |
| C02 | `window.ethereum`으로 `eth_requestAccounts`(`isMetaMask`가 아니면 "MetaMask를 찾을 수 없습니다") | 연결 창(실제 origin + "호환 모드: MetaMask" / "호환 모드: Rabby") → `[A0]` / 같음 / "MetaMask를 찾을 수 없습니다" |
| C03 | `window.ethereum`으로 SIWE(T20과 같은 메시지) `personal_sign` + ecrecover | 서명 창(S09 정보, 배지) → ecrecover = A0 / 같음 / 동작 안 함 |
| C04 | `window.ethereum._metamask.isUnlocked()` | 연결·해제 상태 `true`, 잠김·미연결 `false` / 같음 / 동작 안 함 |
| C05 | `requestProvider` 뒤 300 ms 동안 모은 알림을 이름·rdns·uuid로 나열, 항목별 "…로 연결" 버튼 | MetaMask·Rabby rdns 항목이 정확히 하나(`io.metamask`, `isYourWallet` true)이고 Your Wallet rdns 항목 없음 / 같음(`io.rabby`) / Your Wallet 하나, 다른 지갑은 그대로 |

### 5.8 M6 LLM 설명 (선택)

- [ ] M6-1 자동: 06 §10 E1–E12 통과(X-19 포함). 순수 사례는 `crates/yw-app/src/explain/tests.rs`·`explain/config.rs`, loopback mock(127.0.0.1:0)·실제 WinHTTP 사례는 `crates/yw-app/tests/llm_mock.rs`(E1·E2·E3·E4·E5·E8·E9·E10·E11·응답 주입 시도).
- [ ] M6-1b 자동(UI 명령 ID): `ui::command_ids` 시험 — 모든 고정 ID와 목록형 범위가 겹치지 않고 범위마다 최대 목록(스캔 107행 × 2, 계정 0..=999, 사이트 256, 주소록 500 등)을 담음, Solana 스캔 41번째 이후 행 버튼이 그 행 동작으로 가는 회귀 시험(`app_sol_commands::tests`).
- [ ] M6-2 수동: 기능 끔 → M4-2 수행 → `logs\`에 `llm_explain` 줄 0, 외부 연결 대상은 설정한 RPC 엔드포인트(현재 QuickNode, D13)뿐(기록에는 호스트 대신 `NetworkId`).
- [ ] M6-3 수동: 실제 공급자 켬 → 켜기 고지 표시, T09·T23 설명 1회씩 패널 표시, 결과 도착 전후 버튼 위치 동일(06 §10 수동). 엔드포인트를 틀린 URL로 바꿈 → 패널 오류 문구, 승인 정상.

### 5.9 M7 Solana

- [ ] M7-1 자동: §3.9 전부, 02 §11.5(SLIP-0010·`SolKeySource`·`sol_public_keys`·`with_ed25519_seed`), 07 §17.1–17.4, SOL-N1–N4.
- [ ] M7-2 퍼징 `sol_base58`, `sol_shortvec`, `sol_tx`, `sol_journal` 각 600 s.
- [ ] M7-3 §2.5 SOL 라이브 확인 + 07 §10 CU 측정. 측정으로 CU 상수를 확정하기 전 mainnet 전송 금지.
- [ ] M7-4 devnet E2E: 07 §17.6 1–9. 4번 장애 주입 지점 이름은 `sol.after_journal_pending`(07 §14.2 `Pending` fsync 직후, 전송 전). 6번의 devnet RPC 재정의는 설정에서 저장해 `apikeys.dpapi`의 `rpc:solana:devnet` 항목(04 §6.3)으로 넣고, 끝나면 지운다.
- [ ] M7-5 T_SOL·T_SPL 골든 교차 확인(07 §17.3, 저장소 안 별도 워크스페이스 `tools/sol-oracle/`(§2.1), 1회) 기록.
- [ ] M7-6 호환성: 시험 vault에서 만든 24단어 시험 니모닉을 Phantom 또는 Solflare에 가져옴 → 계정 0·1 주소가 yw-app과 같음.
- [ ] M7-7 (v1.1) 자동: SOL-N5, 07 §17.3 T_SPL 골든·PDA·ATA 벡터, 07 §17.4 SPL 항목(`sol::tests_spl`, `sol::token`, `tests/sol_spl_flow.rs`, `tests/sol_journal_worker.rs` SPL 사례), 퍼징 시드에 T_SPL 골든.
- [ ] M7-8 (v1.1) §2.5 SOL 라이브에 SPL 항목: mint 확인(owner·82바이트·decimals 6), rent165, T_SPL `getFeeForMessage`, T_SPL CU 측정(새 ATA·기존 ATA 각 10회, 07 §10 bump 모델) → `SPL_TRANSFER_CU_LIMIT` 확정. 측정 전 mainnet SPL 전송 금지.
- [ ] M7-9 (v1.1) devnet USDC E2E: 07 §17.6-8(faucet, 새 수신자 ATA 생성, 기존 ATA, 토큰 보내기 최대, 모르는 토큰 숨김, 곡선 밖 받는 주소 차단). USDT는 devnet 공식 mint가 없어 M9 mainnet 소액 체크리스트(07 미결 4).

### 5.10 M8 Bitcoin

- [ ] M8-1 착수 검사 08 §4.5 E1–E3·C1–C3(§2.5) 통과 기록(B1–B4는 선택 인덱서를 쓸 때만). 판정·대안은 08 §4.5: 기본 `esplora`로 진행하며 Blockbook 애드온이 없어도 M8은 진행한다. 쓸 수 있는 인덱서가 없거나 이전 거래 원본을 받을 수 없을 때만 중단(D26). E1–E3 응답 원문을 `crates/yw-core/tests/vectors/btc/esplora/`(§3.1)에 저장한다.
- [ ] M8-2 자동: §3.10, 02 §11.3 `derive_public_child`·§11.4 CKDpub 행, 08 §14.1–14.2(`esplora_*`·`indexer_*` 포함, M8-1에서 저장한 Esplora 실측 응답 픽스처 포함), 04 §6.5 ST-1(`bitcoin.esploraBaseUrl`)·ST-4(Esplora `테스트`), BTC-N1–N8.
- [ ] M8-3 오라클 08 §14.3(`tools/btc-oracle/`, §2.1) 통과, 퍼징 `btc_tx`·`btc_address` 각 600 s.
- [ ] M8-4 testnet4 E2E 08 §14.4 1–8(기본 인덱서 `esplora`, `esploraBaseUrl` 기본값). 6번 장애 주입 지점 `btc.after_broadcasting`(08 §12.1 `Broadcasting` 저장 직후). 8번 `bb-rpc` 부분은 선택 인덱서를 쓰지 않을 때 E-BTC-007 확인으로 수행한다.
- [ ] M8-5 복구 08 §14.5 1–2.

### 5.11 M9 메인넷 소액 (수동, 1회)

- [ ] M9-1 판정 커밋에서 `check.ps1` 통과, M0–M8(M6 선택) 기록이 모두 있음. release 빌드를 `register-native-host.ps1`로 설치.
- [ ] M9-2 Glamsterdam 상태 확인: EIP-7773 표에 mainnet 활성 시각이 있으면 §6 R1을 먼저 마쳤음.
- [ ] M9-3 독립 도구 호환 훈련(가치 없는 시험 니모닉): yw-app 시험 vault가 만든 24단어 → (a) MetaMask 또는 Rabby: EVM 계정 0·1 (b) Phantom 또는 Solflare: SOL 계정 0·1 (c) Sparrow(Native Segwit, m/84'/0'/0')와 Electrum(BIP39 seed, p2wpkh): BTC 받기 0–4·잔돈 0–1 → 모두 yw-app과 같음. 같은 단계에서 ACC-3·BIP84 art 값(§3.10)도 도구 하나로 1회 대조한다. 도구는 공식 배포처에서 받는다. 시험 니모닉은 이후 쓰지 않는다.
- [ ] M9-4 실제 지갑 생성: 새 vault(24단어), 종이(또는 금속)에 단어와 계정 0 주소 기록, 백업 확인 완료. 사진·클라우드·메신저에 남기지 않음(spec §2.4).
- [ ] M9-5 종이 백업 복구 훈련(실제 니모닉은 다른 앱에 넣지 않는다, 08 §14.5-3): yw-app 종료 → `%LOCALAPPDATA%\YourWallet\v3`를 `v3.drill-bak`으로 이름 변경 → 네트워크 끊음 → yw-app 실행 → 종이의 24단어로 가져오기 → EVM 계정 0(종이의 주소와 일치), SOL 계정 0, BTC 받기 0의 주소를 적어 둠 → yw-app 종료 → 새 `v3` 폴더 삭제 → `v3.drill-bak`을 `v3`로 되돌림 → 실행·잠금 해제 → 세 주소가 같음.
- [ ] M9-6 첫 입금 전 받기 주소 확인: 체인마다 받기 QR을 휴대폰 카메라로 읽어 화면 문자열과 전체 비교, EVM은 종이 기록과도 비교.
- [ ] M9-7 소액 왕복(체인마다 약 10–20 USD 상당, 잃어도 되는 금액): 거래소·다른 지갑 → yw-app 입금 확인(탐색기 일치) → yw-app에서 원래 쪽(또는 본인 다른 주소)으로 절반 송금 → 성공·탐색기 일치. ETH(mainnet), SOL(mainnet, 제네시스 확인 배너), BTC(mainnet, 1 확인 후 송금, 수수료율 상한 안). ERC-20·SPL(v1.1)은 선택.
- [ ] M9-8 mainnet dApp 1개에서 연결·`personal_sign`만 수행 후 연결 해제(승인·permit 서명은 하지 않음).
- [ ] M9-9 운영 권고(spec §2.4): 일상 계정이 표준 사용자(`net user <이름>`에 Administrators 없음), `manage-bde -status C:` 보호 켜짐, 핫 잔액 상한 결정·기록.
- [ ] M9-10 이후 소액만 사용. 상한을 넘기려면 이 체크리스트를 다시 수행하지 않고 spec §2.2(고액 장기 보관 비목표)를 따른다.

## 6. 프로토콜 변경 회귀 절차

변경을 알게 되면 아래를 수행하고 `docs/acceptance/regress-<항목>-<YYYYMMDD>.md`에 남긴다. 확인 주기: R1·R3은 월 1회 공식 페이지(EIP-7773 표, Solana SIMD·릴리스 노트)를 본다(운영 권고).

| ID | 계기 | 다시 할 것 |
|---|---|---|
| R1 | Glamsterdam mainnet 활성 시각 확정 | 03 §1.1 mainnet `amsterdam_time` 상수 수정 → S1·S2·S6·S7b의 mainnet 변형 픽스처 추가(chainId 1, timestamp ≥ 상수, emitter `0xff…fe`) → `check.ps1` → 활성 후 03 §1.5 A1을 mainnet에 다시 수행 → mainnet 새 주소 소액 ETH 1회(M9-7 ETH) |
| R1b | EIP-7708·2780·8037 Last Call 이후 값 변경(2026-11-01 마감) | 03 §1.3 상수, S2 가스(`0x31f38`), M4-3 기대값 수정 → Sepolia A1 재수행 |
| R2 | 설정한 공급자(현재 QuickNode)의 `eth_simulateV1`·Solana·Bitcoin Core RPC(선택 인덱서 Blockbook 애드온 포함) API 변경·폐지 공지(HyperEVM 포함), 공급자·엔드포인트 변경(D13), 또는 Esplora 인덱서(기본 mempool.space) API·요청 한도 변경, `bitcoin.esploraBaseUrl`·`bitcoin.indexer` 변경 | §2.5 해당 묶음 재수행(EVM은 `probe-rpc.mjs` 먼저, BTC 인덱서는 08 §4.5 E1–E3 또는 B1–B4), 응답 형태가 바뀌었으면 픽스처 추가(`btc/esplora/`), 999 기본 `simulation`을 L-HYPEREVM으로 재판정 → M4-2·M4-5·M4-13, M7-4 2·3, M8-4 2·3 |
| R3 | Solana 프로토콜 변경(SIMD-0553 수수료, SIMD-0437 rent 단계, 슬롯 시간, commitment, 트랜잭션 형식) | 07 §16 표 재확인 → 07 §10 CU 측정 → 07 §17.4 수수료·rent 경계 테스트에 새 값(예: rent 696 lamports/byte, base fee 2,500) 추가 → M7-4 1–5 |
| R4 | Bitcoin Core 정책(최소 중계 수수료, dust), testnet4 재설정 | 08 §15 상수 검토 → 08 §14.2 수수료 테스트 → M8-4 2–5 |
| R5 | Chrome 주요 버전(MV3 수명, native messaging 실행 방식·정책) | M5-1 T01·T03·T07·T18·T30, M5-5, M5-6, M5-11, M5-13 |
| R6 | Windows 기능 업데이트 | M3-1(a)(c), M3-3, M3-5 |
| R7 | Rust 툴체인·크레이트 버전 변경(D5 표 먼저 수정) | `check.ps1`(허용 목록 수 갱신), 해당 마일스톤 퍼징 전 대상 600 s, `tools/` 오라클 |
| R8 | 지갑 파일 형식 변경 | 새 골든 G1–G3(저널 형식이면 V13), 이전 형식은 D7 방식(이전하지 않음)이면 거부 테스트, M3-6·M3-10 |

## 7. 미결 사항

결정이 필요한 미결 사항은 없다(캡처 판정은 spec §5 M3, Solana 단계 크레이트 수는 D5로 정리됨). 아래는 구현 시 확인 항목과 실패 시 대안이다.

1. **cargo-fuzz** (x86_64-pc-windows-msvc nightly, `-s none`): §2.4. 안 되면 같은 절의 fuzz-lite `#[ignore]` 테스트.
2. **외부 서비스 동작**(설정한 공급자, 현재 QuickNode; BTC 기본 인덱서 mempool.space Esplora): §2.5 표(`probe-rpc.mjs` 프로브 먼저, `live_probe` L-LIMITS·03 §1.5 A1–A9, L-ORIGIN, 07 §16, 08 §4.5 E·C, 선택 인덱서면 B). 실패 시 그 표의 "실패 시" 열. HyperEVM 기본 `simulation`과 블록 0 해시는 L-HYPEREVM·L-GENESIS로 정한다.
3. **Chrome job object** (D24): M5-13. yw-app이 함께 종료되면 자동 실행을 끄고 수동 실행으로 바꾼다.
4. **단일 출처 외부 값**: Sepolia WETH·USDC 주소(03 §1.2) — 틀리면 Etherscan 검증 주소로 03 §1.2와 test-dapp 상수를 함께 고친다. app.uniswap.org의 Sepolia 지원 — 없으면 M5-10 "해당 없음". M9-3 도구의 경로 지원 — 안 되면 같은 줄의 다른 도구.
5. **[로컬]만으로 계산한 주소**(ACC-3, BIP84 art): M9-3에서 독립 지갑으로 1회 대조. 다르면 공식 벡터 재현을 다시 확인하고 이 문서를 고친다(원칙 6).
