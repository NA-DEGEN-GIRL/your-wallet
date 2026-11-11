# Solana 전송 전용 (M7)

상위 문서: [spec.md](../spec.md)

D25·D27·D29의 세부 명세다. Solana 보내기·받기는 yw-app 화면에서만 한다. 브라우저(dApp)와는 **소유 증명(연결 + 메시지 서명·SIWS)만** 한다(§19, 2026-10-31). 지갑이 정해진 템플릿으로만 거래를 만들고, 승인 창은 서명할 바이트를 다시 파싱한 결과로 그린다. 시뮬레이션은 참고 정보다(D27). 키 파생 알고리즘·키 접근 API는 [02](02-core-keys-vault.md) §3.5·§10.3, meta·주소록·계정·`ActivityEntry` 스키마와 저널 컨테이너 프레이밍은 [02] §5.3·§5.4(SOL 저널 본문 바이트 형식은 이 문서 §14.1), 승인 요청 모델·digest는 [03](03-evm.md) §11, 승인 창 동작·설정 파일은 [04](04-app-ui.md) §3·§6, 의존성 검사는 [01](01-repo-build.md), 테스트 판정은 [09](09-testing.md)를 따른다(D31). 상수는 각 절의 `rust` 코드 블록에 있다.

## 1. 범위

| 단계 | 포함 | 비고 |
|---|---|---|
| **v1 (M7)** | SOL 받기(주소·QR), SOL 잔액(참고), SOL 보내기(템플릿 T_SOL), 보내기 최대, 복구 스캔(§3.3)과 비표준 경로 자금 이동, mainnet·devnet | 필수 |
| **v1.1 (M7 후속)** | 허용 목록 SPL 토큰(USDC·USDT, classic Token program `Tokenkeg…`만) 받기·잔액·보내기(템플릿 T_SPL), 받는 쪽 ATA 자동 생성(CreateIdempotent), 복구 스캔의 토큰 잔액·토큰별 전액 이동 | v1 완료 조건을 깨지 않는다. 구현 2026-10-28([acceptance](../docs/acceptance/m7-spl-20261028.md)) |
| **가져온 개인키 (2026-10-29)** | base58 64바이트 keypair(Phantom·Solflare 내보내기)·`solana-keygen` JSON 배열 가져오기(§3.4), 그 계정의 SOL·허용 목록 SPL 받기·잔액·보내기(T_SOL·T_SPL 그대로), 가져온 키 내보내기(base58 keypair)·삭제, 개인키로 시작한 지갑(복구 단어 없음, [02] §8.5) | D9·D25. 구현 2026-10-29([acceptance](../docs/acceptance/keys-import-20261029.md)) |
| **범위 밖** | Token-2022, 허용 목록 밖 토큰·NFT(잔액도 숨김), v0·v1(0x81) 트랜잭션, address lookup table, durable nonce, 스테이킹, 스왑, 계정 닫기, memo, dApp의 트랜잭션 서명·전송(dApp은 §19의 연결·메시지 서명만), 파생(니모닉) 계정의 개인키 내보내기, Solana Pay URI(`solana:`), 받은 거래 내역(예외: [04] §2.6 opt-in `받은 내역`, 2026-11-11, §12.3), testnet 클러스터, 다중 서명자 | 추가하려면 spec.md D25를 먼저 고친다 |

- 수수료 지불자는 항상 보내는 계정이다. 서명자는 항상 1명이다.
- 한 (클러스터, 보내는 계정)에 진행 중(`Pending`, §14) 전송은 1개만 허용한다(D20과 같은 규칙).

## 2. 모듈 배치와 핵심 타입

| 위치 | 내용 | 네트워크 |
|---|---|---|
| `yw_core::codec::base58` | M1에서 구현된 base58·base58check([02] §0) 모듈. SOL은 §5의 엄격 고정 길이 디코더 `base58_decode_32`·`base58_decode_64`만 (없으면) 추가한다. | 없음 |
| `yw-core::sol::{shortvec, address, pda, keys, message, template, token, fee, rent, intent, broadcast, display}` | §3–§14의 순수 로직(저널 레코드 제외). `token`은 §15.4 SPL 계정 데이터 파서·분류(v1.1). 시간은 인자로 받는다(`now_ms: u64`). | 없음 |
| `yw_core::journal::sol` (M7) | SOL 저널 본문 코덱(§14.1)·상태 전이(§14.2). 컨테이너 코덱·`JournalError`는 `journal`([01] §2.2, [02] §5.4) | 없음 |
| `yw-app::sol::{rpc, flow, scan}` | Solana JSON-RPC(`apikeys.dpapi`에 저장한 `solana:<cluster>` 엔드포인트 URL 하나, 공급자 무관(D13, [04] §6.3, §15.1), WinHTTP + yw-json), 미리보기·서명·브로드캐스트 루프 구동, 복구 스캔 | 있음 |

```rust
// yw-core::sol (요약; 이름은 다른 문서가 그대로 쓴다)
pub struct SolAddress([u8; 32]);                       // Debug는 base58 전체
pub enum SolCluster { Mainnet = 1, Devnet = 2 }
// SolKeySource는 [02] §3.5 `yw_core::slip10::SolKeySource`를 그대로 쓴다(이 문서에서 다시 정의하지 않는다, AccountIndex는 [02] §3.3):
//   enum SolKeySource { Standard(AccountIndex), Bip44Account(AccountIndex), Bip44Root, RawSeed,
//                       SolletLegacy { wallet: u32, account: u32 }, Imported }   // Imported: §3.4
pub enum SolAsset { Sol, Spl(&'static SplAllowEntry) }   // v1은 `Sol`만, v1.1(2026-10-28)에서 `Spl` 추가. decimals()·symbol()·tag()
pub struct SolTransferCore {                           // 메시지 바이트가 결정하는 값 전부(블록해시 제외)
    pub from: SolAddress, pub to: SolAddress, pub asset: SolAsset,
    pub amount: u64,             // SOL: lamports, SPL: 원시 단위
    pub cu_limit: u32, pub cu_price_micro: u64,
}                                // SPL의 from_ata·to_ata는 core에서 파생(§8.3, `SplAccounts::of(core)`)하며 저장하지 않는다
pub struct SolTransferIntent {                         // id = ApprovalRequest.id ([03] §11.1)
    pub id: [u8; 16], pub cluster: SolCluster, pub source: SolKeySource, pub core: SolTransferCore,
    pub max_fee_lamports: u64, pub fee_cap_lamports: u64, pub flags: u8, pub created_at_ms: u64,
}
pub struct SignedSolTransfer { pub tx: Vec<u8>, pub signature: [u8; 64], pub message_sha256: [u8; 32] }
```

## 3. 키 파생과 복구 스캔

### 3.1 표준 경로

- 경로 `m/44'/501'/{i}'/0'`(D29). SLIP-0010 Ed25519(HMAC 키 `"ed25519 seed"`, hardened만)의 알고리즘, `Slip10Path`(hardened 성분만, 비hardened 입력은 오류, 자동 승격 금지), crate 내부 `slip10_ed25519(seed: &[u8; 64], path)`, 벡터는 [02] §3.5.
- 계정 0은 복구 단어 지갑에서 아직 없으면 세션의 meta를 읽을 때(잠금 해제, Zcash 계정과 같은 때) 파생해 meta `sol_accounts`에 [02] §5.3 `Account {index, label, address(base58), hidden}`로 저장한다(2026-11-10: 전에는 Solana 화면 첫 진입 때만 파생해, Solana 탭을 연 적 없는 지갑의 Solana dApp 연결이 4100 `NoSolAccount`로 끝났다. 파생 중에 온 연결은 [05] §4.9대로 기다린다). Solana 화면 진입도 없으면 파생한다. 계정 추가는 i를 1씩 늘린다. 상한은 [02] §5.3(100개)·§3.3(`i ≤ 999`).
- 저장된 `address`는 표시용 캐시다([02] §5.3). 서명 때는 키 접근 클로저 안에서 다시 파생한 공개키가 `intent.core.from`과 같아야 한다(다르면 `KeyMismatch`, 서명 안 함).
- 같은 시드를 EVM(`"Bitcoin seed"`)과 Solana(`"ed25519 seed"`)가 공유하는 것은 표준이며 키가 섞이지 않는다.
- BIP39 passphrase(D8, 가져오기에서만 D29)는 모든 Solana 주소를 바꾼다.

```rust
// 키 접근은 [02] §10.3의 Vault API만 쓴다. 64바이트 BIP39 시드는 이 문서의 코드에 오지 않는다.
//   pub(crate) fn with_ed25519_seed<T>(&self, src: SolKeySource, f: impl FnOnce(&[u8; 32]) -> R<T>) -> R<T>; // §3.2 다섯 출처 모두
//   pub fn sol_public_keys(&self, srcs: &[SolKeySource]) -> R<Vec<[u8; 32]>>;   // 한 번에 ≤ 128개. 계정 추가·캐시 재계산·스캔(§3.3)
pub(crate) fn signing_key(k: &[u8; 32]) -> ed25519_dalek::SigningKey;   // with_ed25519_seed 클로저 안에서만 호출
// SigningKey는 drop 시 zeroize(feature "zeroize"). k는 RFC 8032 비밀 시드다. 스칼라로 직접 쓰지 않는다(SHA-512·clamp는 ed25519-dalek 내부).
```

### 3.2 키 출처 표

| `SolKeySource` | 태그 | 경로 | 쓰는 지갑 | 생성 | 스캔 |
|---|---|---|---|---|---|
| `Standard(i)` | 1 | `m/44'/501'/i'/0'` | Phantom, Solflare, Backpack, solana-keygen(`--derivation-path` 값 없이) | 예 | 예 |
| `Bip44Account(i)` | 2 | `m/44'/501'/i'` | Ledger Live, Sollet "bip44", Trust(보고됨) | 아니오 | 예 |
| `Bip44Root` | 3 | `m/44'/501'` | solana-keygen `prompt://` 기본, Sollet "bip44Root" | 아니오 | 예 |
| `RawSeed` | 4 | 파생 없음: BIP39 seed[0..32] | `solana-keygen new`(경로 없음) | 아니오 | 예 |
| `SolletLegacy { wallet, account }` | 5 | `m/501'/wallet'/0/account`를 secp256k1 BIP32(`"Bitcoin seed"`, [02] §3.1)로 파생한 32바이트 개인키를 Ed25519 시드로 사용 | Sollet(폐기) | 아니오 | 선택(MAY), "고급" 아래 |
| `Imported` | 6 | 파생 없음: vault `SolKey` record(`tag 3`, [02] §4.6)의 시드, 공개키(`intent.core.from`)로 찾음. 매개변수 `(a, b) = (0, 0)` | Phantom·Solflare·solana-keygen에서 내보낸 개인키(§3.4) | 가져오기 | 아니오 |
| `Hardware(i)` | 7 | YubiKey PIV 슬롯의 `m/44'/501'/i'/0'`([10] §3.1) | — | YubiKey 등록 | 아니오 |
| `Mnemonic(id, i)` | 8 | 추가한 니모닉 `id`(vault `Bip39` record, [02] §8.6)의 `m/44'/501'/i'/0'`. 매개변수 `(a, b) = (i, 0)`, 저널·transcript는 그 뒤에 record id 16바이트(§13.2, §14.1) | 다른 지갑의 복구 단어(Phantom 등 표준 경로) | 예(§3.5) | 아니오 |

- 타입은 [02] §3.5 `SolKeySource`(`Standard`·`Bip44Account`의 `i`는 `AccountIndex`, 0..=999)이고, 출처별 32바이트 시드 계산은 [02] §10.3 `with_ed25519_seed`·`sol_public_keys`가 이 표대로 한다.
- 태그 5는 구현 시 확인: spl-token-wallet의 `deriveSeed` 소스와 대조한 벡터 1개를 얻지 못하면 구현하지 않는다.
- Math Wallet의 비hardened `0` 끝 경로는 SLIP-0010에서 존재할 수 없으므로 호환을 주장하지 않는다.

### 3.3 복구 스캔(읽기 전용)

- 설정 → Solana → "다른 경로 스캔". 시작 전에 "조회하는 모든 주소가 RPC 공급자(설정한 `solana:<cluster>` 엔드포인트의 운영자, §15.1)에 전달되어 서로 연결될 수 있다"를 표시하고 확인을 받는다. 확인은 그때 선택한 클러스터에만 유효하다: 공개키 파생 중 클러스터를 바꾸면 스캔은 안내 단계로 돌아가 아무 주소도 조회하지 않고, 파생이 끝났을 때 선택한 클러스터가 확인한 클러스터와 다르면 "클러스터가 바뀌었습니다…"를 표시하고 새 클러스터의 안내를 다시 확인받는다.
- `sol_public_keys`를 한 번 호출해(태그 1·2는 0..=`SOL_SCAN_MAX_INDEX` 전부, 합계 107개 ≤ [02] §10.3 상한 128. 태그 5(`SolletLegacy`)를 구현하지 않았으면 그 5개를 빼고 102개로 호출한다) 공개키만 받고(시드 소거는 [02] §7.3, D10), 네트워크 조회는 주소만으로 한다.
- 태그 1·2: i = 0부터 증가, 연속 `SOL_SCAN_GAP`개가 비면 중단, `i ≤ SOL_SCAN_MAX_INDEX`. "빔" = `getBalance == 0`이고(v1.1) 허용 목록 ATA가 모두 없음. 태그 3·4: 각 1개. 태그 5: `wallet` = 0, `account` = 0..=4.
- 결과 표: 경로, 주소 전체, SOL 잔액(참고), (v1.1) 허용 토큰 잔액. 태그 1의 새 계정은 "계정 추가"로 meta에 넣는다.
- 비표준 경로(태그 2–5) 자금은 "표준 계정으로 이동"만 허용한다: 받는 주소는 사용자가 고른 **자기 표준 계정**으로 고정, SOL은 보내기 최대(§11), SPL은 토큰별 전액. 일반 승인 흐름(§13)을 그대로 거치며 승인 창에 "비표준 경로 계정"(주의 `L07`)과 경로를 표시한다. 서명 키는 `with_ed25519_seed(intent.source, …)`로 얻는다. 비표준 계정에서 임의 주소로 보내기는 없다(서명 직전에 보내기 최대·자기 표준 계정 여부를 다시 확인한다, §13.1-6). 이동 폼은 그 계정에 허용 목록 토큰 잔액이 있으면 그 토큰을 먼저 고른다(토큰 이동에 SOL 수수료가 필요하므로 SOL 보내기 최대는 마지막). 자산은 바꿀 수 있고 보내기 최대는 고정이다.
- (2026-11-10) **받는 계정**: "자기 표준 계정"은 주 니모닉의 표준 계정(`SolAccountId::Derived`, meta `sol_accounts`)뿐이다 — 서명 직전 규칙(§13.1-6)이 주 시드의 `Standard(0..=999)`만 대조하므로 YubiKey·가져온 키·추가한 니모닉 계정으로는 서명되지 않는다. Solana 탭에서 고른 계정이 그런 계정이면 그 계정, 아니면 주 니모닉의 첫 보이는 표준 계정으로 보낸다. 결과 화면에 `옮겨 받을 계정: {라벨} · {경로}`를 보이고, 그런 계정이 없으면 "받을 계정이 없습니다…" 띠와 함께 `표준 계정으로 이동`을 끈다. 이동 폼의 받는 주소가 `sol_accounts`의 주소가 아니면(이전 폼 복원 등) 이유 띠를 보이고 `검토`를 끈다.
- (2026-11-10) **결과 유지**: 결과는 클러스터를 바꾸거나 잠그거나 `다시 스캔`(안내 단계로, 고지 재확인)을 누를 때까지 남는다. 스캔 화면을 다시 열면 같은 클러스터의 결과를 그대로 보이고(자산마다 한 번씩 옮기므로), 이동 폼을 연 행의 주소는 계정 잔액 조회에 함께 넣어(스캔에서 이미 같은 공급자에 보낸 주소) 그 행의 잔액을 최신 참고값으로 보인다. 다음 이동은 그 최신 값으로 토큰을 고른다. 이동을 보낸 결과 화면에는 `스캔 결과로`가 있다.

```rust
pub const SOL_SCAN_GAP: u32 = 5;
pub const SOL_SCAN_MAX_INDEX: u32 = 49;
```

### 3.4 가져온 개인키 (D9, [02] §8.4)

- 입력 형식(`yw_core::keyimport`, 앞뒤 ASCII 공백·탭·CR·LF 무시, ASCII만, ≤ `SOL_KEY_TEXT_MAX` = 640바이트):
  1. **base58 64바이트 keypair**: `seed[32] ‖ public[32]`(Phantom·Solflare "개인키 내보내기", 보통 87–88자). base58 디코드 결과가 64바이트가 아니면 거부: 32바이트면 `KeyError::SolKeyIsAddress`(E-INP-021, "주소(공개키)로 보입니다"), 그 밖은 `SolKeyFormat`(E-INP-020).
  2. **`solana-keygen` JSON**: `[`·`]` 사이에 쉼표로 나눈 10진수 정확히 64개(각 0–255, 부호·지수·앞자리 0 금지, 숫자 주위 공백·줄바꿈 허용). 개수·형식 위반은 `SolKeyFormat`.
  - 두 형식 모두 `public == Ed25519(seed).verifying_key()`여야 한다(다르면 `SolKeyMismatch`, E-INP-022). 32바이트 시드만 있는 형식(hex 64자 등)은 받지 않는다.
- 저장: vault `SolKey` record(`tag 3`: 시드 32 + 공개키 32). 디코드 때 공개키를 시드에서 다시 계산해 비교한다. 같은 공개키를 두 번 가져오면 `DuplicateKey`, 체인당 15개 상한(`RecordLimit`). 파생 계정과 같은 키를 가져오는 것은 막지 않는다(서로 다른 계정 행으로 보인다).
- meta: `sol_raw_accounts`(`{record_id, label, address}`)와 선택 `sol_raw_selected`([02] §5.3). 계정 목록은 표준 계정 다음에 가져온 계정을 "[가져온 키]" 배지와 함께 보인다([04] §2.18).
- 서명: 출처 `SolKeySource::Imported`(태그 6). `sign_transfer`는 `Vault::with_imported_ed25519_seed(&intent.core.from, …)`로 그 공개키의 record를 찾아 시드를 빌린다(없으면 `Vault(RecordNotFound)`, 키 전용 지갑의 파생 출처는 `Vault(NoMnemonic)`). 나머지 서명 절차(§13.1-6: 기한, 승인 대조, 수수료 규칙, 재인코딩 동일성, 공개키 대조, `verify_strict`)는 같다.
- 가져온 키는 §3.3의 "비표준 경로 규칙"(보내기 최대·자기 표준 계정만)을 받지 않는다: `SolKeySource::needs_move_rule()`이 태그 2–5에만 참이다. 승인 창 `L07`도 없고, 계정 필드의 경로 줄은 "가져온 개인키 (복구 단어 밖)"이다. 수신자가 자기 가져온 계정이면 `KnownKind::OwnImported`("내 계정(가져온 개인키): {라벨}").
- 저널: SOL 레코드 헤더의 출처 태그 6, `(a, b) = (0, 0)`(§14.1). 태그 6에 0이 아닌 매개변수는 `SolRecordError::Source`.
- 내보내기: `Vault::reveal_imported_key`가 base58 64바이트 keypair를 돌려준다(W09, 비밀번호 재입력, 복사 토글 규칙 [04] §4.8).

### 3.5 추가한 복구 단어의 계정 (2026-11-08, D37, [02] §8.6)

- 출처 `SolKeySource::Mnemonic(id, i)`(태그 8): 경로는 표준 경로 그대로이고 시드만 그 니모닉의 것(그 니모닉의 passphrase 포함, [02] §7.5)이다. `sol_public_keys`는 니모닉마다 BIP39 시드를 한 번 계산한다. `with_ed25519_seed`는 그 니모닉의 백업 확인 전이면 `BackupNotConfirmed`(받기 주소 계산은 된다). 없는 `id`는 `RecordNotFound`.
- `is_standard()`가 참이고 `needs_move_rule()`은 거짓이다(비표준 경로 규칙·`L07` 없음). 다른 경로 스캔(§3.3)은 주 니모닉만 본다.
- meta: 계정은 선택 최상위 키 `mnemonic_accounts.sol`(`{mnemonic, index, label, address, hidden}`), 선택은 `mnemonic_accounts.sol_selected`([02] §5.3). 선택 우선순위: YubiKey(`hw_accounts.sol_selected`) → 추가한 니모닉 → 가져온 키(`sol_raw_selected`) → `prefs.sol_account`.
- 승인·서명·저널: intent transcript(§13.2)와 메시지 digest(§19)가 record id를 묶고, 저널 레코드는 버전 2(§14.1). 나머지 흐름(미리보기, 수수료, 재인코딩 동일성, `verify_strict`, 방송 루프)은 같다.

## 4. 의존성

D5: 런타임 4개(`ed25519-dalek`, `ed25519`, `signature`, `curve25519-dalek`) + 빌드 전용 2개(`rustc_version`, `semver`), curve25519-dalek build.rs 허용, serial 백엔드(`.cargo/config.toml`). 모두 레지스트리 캐시에 있고 `--offline`으로 해석된다.

```toml
# [workspace.dependencies] ([01] §3.1의 주석 처리된 줄을 M7 진입 커밋([01] §3.4)에서 활성화)
ed25519-dalek    = { version = "=2.2.0", default-features = false, features = ["fast", "zeroize"] }
curve25519-dalek = { version = "=4.1.3", default-features = false, features = ["precomputed-tables", "zeroize"] }
```

```toml
# .cargo/config.toml (저장소 루트)
[target.x86_64-pc-windows-msvc]
rustflags = ["--cfg", 'curve25519_dalek_backend="serial"']
```

| 항목 | 값 |
|---|---|
| 런타임 추가 (allowlist `:n`) | `ed25519-dalek=2.2.0`, `ed25519=2.2.3`, `signature=2.2.0`, `curve25519-dalek=4.1.3` |
| 빌드 전용 추가 (`:b`) | `rustc_version=0.4.1`, `semver=1.0.28` (curve25519-dalek build.rs가 사용) |
| `BUILD_RS_ALLOW` 추가 | `curve25519-dalek` |
| proc-macro | 0개 유지. serial 백엔드라 `curve25519-dalek-derive`와 그 의존(proc-macro2, quote, syn, unicode-ident)이 빠진다. |
| 금지 feature (검사 스크립트에 추가) | ed25519-dalek: `hazmat`, `batch`, `rand_core`, `serde`, `pkcs8`, `pem`, `legacy_compatibility`, `digest`, `asm` / curve25519-dalek: `group`, `group-bits`, `rand_core`, `serde`, `legacy_compatibility` / ed25519: `pkcs8`, `pem`, `serde`, `serde_bytes` / signature: `rand_core`, `digest` |
| 이미 허용된 공유 의존 | `sha2`, `digest`, `subtle`, `zeroize`, `cpufeatures`, `cfg-if` 등(추가 없음) |

- 확인됨(2026-10-26, Rust 1.95.0, scratch 크레이트): 위 `.cargo/config.toml`만으로 `cargo tree`·`cargo metadata --filter-platform x86_64-pc-windows-msvc`·빌드 모두 serial 백엔드(`curve25519_dalek_backend="serial"`)로 해석되고, 검사 스크립트의 실패 항목은 위 표의 7건뿐이었다. 환경 변수 `RUSTFLAGS`가 설정되면 config의 rustflags를 덮어써 derive proc-macro가 돌아오며, 이 경우 검사 스크립트가 "proc-macro in core closure"로 실패한다(의도된 탐지).
- 4.1.0–4.1.2는 RUSTSEC-2024-0344 대상이므로 curve25519-dalek를 `=4.1.3`으로 직접 고정한다. ed25519-dalek 2.x는 RUSTSEC-2022-0093(double public key oracle) 수정판이다. ed25519-dalek 3.0 / curve25519-dalek 5.0은 sha2 0.11 계열이라 쓰지 않는다.
- 허용 API(이 밖은 쓰지 않는다): `SigningKey::from_bytes`, `SigningKey::verifying_key`, `Signer::sign`, `VerifyingKey::from_bytes`, `VerifyingKey::verify_strict`, `VerifyingKey::to_bytes`, `Signature::from_bytes`/`to_bytes`, `CompressedEdwardsY::from_slice`, `CompressedEdwardsY::decompress`, `EdwardsPoint::is_small_order`, `EdwardsPoint::compress`. `from_keypair_bytes`·`ExpandedSecretKey`·`raw_sign`은 쓰지 않는다. 공개키를 비밀키 옆에 받아 서명하는 API를 만들지 않는다.
- Solana SDK·`solana-*`·`spl-*`·`bs58`·`five8`·`borsh`·`bincode` 크레이트는 출하 코드에 넣지 않는다. 차등 테스트 오라클(§17.3)은 저장소 안 `tools/sol-oracle/`에서만 쓴다: 자체 `[workspace]`·`Cargo.lock`을 가진 별도 워크스페이스이고 루트 `Cargo.toml`의 `exclude`에 있으며([01] §2.1·§3.1), 허용 목록 검사·`check.ps1` 대상이 아니고 출하하지 않는다. 출하 크레이트의 dev-dependency로도 넣지 않는다(dev-dependency도 빌드 스크립트를 실행하므로, [01] §2.4).

## 5. base58 (엄격)

- 알파벳: `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`(Bitcoin), 체크섬 없음. 모듈 `yw_core::codec::base58`(M1, [02] §0).

```rust
pub fn base58_encode(bytes: &[u8]) -> String;                        // M1에 있음
pub fn base58_decode_32(s: &str) -> Result<[u8; 32], Base58Error>;   // 주소·블록해시·제네시스
pub fn base58_decode_64(s: &str) -> Result<[u8; 64], Base58Error>;   // 서명 (RPC 응답 대조용)
pub enum Base58Error { Empty, BadLength, InvalidChar { pos: usize }, WrongDecodedLength, NonCanonical }
// 구현: M1의 `codec::base58::Base58Error`(InvalidCharacter·InvalidChecksum·InvalidLength·TooLong, 비엄격 디코더용)에
// 위 다섯 변형을 더했다. 엄격 디코더는 이 다섯만 돌려준다.
```

| 규칙 | 32바이트 | 64바이트 |
|---|---|---|
| 허용 문자열 길이 (디코딩 전 검사) | 32–44 | 64–88 |
| 알파벳 밖 문자(공백·`0`·`O`·`I`·`l`·`+`·비ASCII 포함) | `InvalidChar` | 같음 |
| 선행 `'1'` k개 ↔ 선행 0바이트 k개 | 보존 | 같음 |
| 디코딩 결과 길이 ≠ N | `WrongDecodedLength` | 같음 |
| `base58_encode(decoded) != s` | `NonCanonical` | 같음 |

- 인코딩: 선행 0바이트마다 `'1'`, 나머지는 big-endian 정수의 58진 표현. 32바이트 전부 0 → `11111111111111111111111111111111`(32자), 전부 0xFF → 44자.
- UI 입력은 붙여넣은 문자열의 앞뒤 ASCII 공백(0x20, 0x09, 0x0A, 0x0D)만 제거한 뒤 파서에 넘긴다. 중간 공백·URI(`solana:`)·쿼리는 오류다.
- 퍼징 대상(§17.5).

## 6. compact-u16 (short_vec)

- 인코딩: 7비트씩 little-endian, 이어지는 바이트가 있으면 0x80. 1–3바이트.
- 디코딩(`shortvec::decode(buf) -> Result<(u16, usize), ShortVecError>`):

```text
v = 0
for i in 0..3:
    b = buf[i]                       // 없으면 Truncated
    if i == 2 and b > 0x03: Overflow // 셋째 바이트는 2비트만, continuation 금지
    if i > 0 and b == 0x00: Alias    // 비최소 인코딩 ([80 00], [80 80 00])
    v |= (b & 0x7F) << (7*i)
    if b & 0x80 == 0: return (v, i+1)
```

- 템플릿 안의 모든 길이는 0x7F 이하이므로 실제로는 1바이트다. 파서는 그래도 위 디코더를 쓴다.

## 7. 레거시 메시지·트랜잭션 형식

```text
transaction = shortvec(num_signatures) || signature[64] * num_signatures || message
message     = header[3] || shortvec(n_keys) || key[32] * n_keys || recent_blockhash[32]
              || shortvec(n_ix) || instruction * n_ix
header      = num_required_signatures u8 || num_readonly_signed u8 || num_readonly_unsigned u8
instruction = program_id_index u8 || shortvec(n_acc) || account_index u8 * n_acc
              || shortvec(data_len) || data[data_len]
```

- 서명 = Ed25519(서명 키, message 전체 바이트). 트랜잭션 ID = `base58_encode(signature)`.
- message 첫 바이트의 최상위 비트가 1이면 versioned(0x80 = v0, 0x81 = v1)다. 우리 메시지는 항상 `0x01`로 시작한다.
- 계정 순서(규범): ① 수수료 지불자(=보내는 계정) ② 나머지 writable signer ③ readonly signer ④ writable non-signer ⑤ readonly non-signer. ②–⑤ 그룹 안은 **32바이트 원시값 오름차순**. 같은 키는 한 번만 넣고 플래그는 OR로 합친다. 이 규칙은 solana-sdk `CompiledKeys`(BTreeMap 순회)와 같다(확인: `anza-xyz/solana-sdk` `message/src/compiled_keys.rs` `compile`·`try_into_message_components`).
- 최대 트랜잭션 크기 `SOL_MAX_TX_BYTES = 1232`. T_SOL 267바이트, T_SPL 437바이트(고정).
- 내부 범용 인코더 `encode_legacy_message(header, keys, blockhash, ixs) -> Vec<u8>`(pub(crate))는 템플릿 빌더와 §17.3 벡터 테스트만 쓴다.

## 8. 명령 템플릿

### 8.1 프로그램·상수 주소

| 이름 | base58 | 원시값(hex) |
|---|---|---|
| System | `11111111111111111111111111111111` | `00`×32 |
| ComputeBudget | `ComputeBudget111111111111111111111111111111` | `0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000` |
| Token (classic) | `TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA` | `06ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a9` |
| Associated Token Account | `ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL` | `8c97258f4e2489f1bb3d1029148e0d830b5a1399daff1084048e7bd8dbe9f859` |

명령 데이터(정수는 모두 little-endian):

| 명령 | 프로그램 | data | 계정 |
|---|---|---|---|
| SetComputeUnitLimit | ComputeBudget | `02` ‖ u32 units (5B) | 없음 |
| SetComputeUnitPrice | ComputeBudget | `03` ‖ u64 micro-lamports/CU (9B) | 없음 |
| System Transfer | System | `02 00 00 00` ‖ u64 lamports (12B) | 0 `[w,s]` from, 1 `[w]` to |
| ATA CreateIdempotent (v1.1) | ATA | `01` (1B) | 0 `[w,s]` payer, 1 `[w]` 생성할 ATA, 2 `[]` 소유 지갑, 3 `[]` mint, 4 `[]` System, 5 `[]` Token |
| Token TransferChecked (v1.1) | Token | `0c` ‖ u64 amount ‖ u8 decimals (10B) | 0 `[w]` source, 1 `[]` mint, 2 `[w]` destination, 3 `[s]` owner |

출처: solana-sdk `compute-budget-interface/src/lib.rs`(tag 2/3), `system-interface`(Transfer = u32 2), `solana-program/associated-token-account` `interface/src/instruction.rs`(계정 6개, data `[1]`), `solana-program/token` `interface/src/instruction.rs`(`transfer_checked`, tag 12). ComputeBudget 명령은 각각 정확히 1번만 넣는다(중복은 런타임이 `DuplicateInstruction`으로 거부).

### 8.2 T_SOL (v1): message 202바이트, 트랜잭션 267바이트

- header `[1, 0, 2]`, keys `[from, to, System, ComputeBudget]`(System `00…` < ComputeBudget `03…`이므로 §7 정렬과 일치).

| message 오프셋 | 길이 | 값 |
|---|---|---|
| 0 | 3 | `01 00 02` |
| 3 | 1 | `04` |
| 4 / 36 / 68 / 100 | 32씩 | from / to / System / ComputeBudget |
| 132 | 32 | recent_blockhash |
| 164 | 1 | `03` (명령 3개) |
| 165 | 8 | `03 00 05 02` ‖ u32 cu_limit |
| 173 | 12 | `03 00 09 03` ‖ u64 cu_price_micro |
| 185 | 17 | `02 02 00 01 0c 02 00 00 00` ‖ u64 lamports |

트랜잭션 = `01` ‖ signature[64] ‖ message.

### 8.3 T_SPL (v1.1): message 372바이트, 트랜잭션 437바이트

- `from_ata = ATA(from, Token, mint)`, `to_ata = ATA(to, Token, mint)`(§8.4). 둘 다 로컬 계산, RPC 값을 쓰지 않는다.
- header `[1, 0, 6]`, n_keys 9: `[from] ++ sort{from_ata, to_ata} ++ sort{to, mint, System, Token, ATA, ComputeBudget}`(§7 정렬).
- 명령 4개, 순서 고정: ① SetComputeUnitLimit ② SetComputeUnitPrice ③ CreateIdempotent(payer=from, ata=to_ata, wallet=to, mint, System, Token) ④ TransferChecked(source=from_ata, mint, destination=to_ata, owner=from, amount, decimals=허용 목록 고정값).
- 받는 ATA가 이미 있어도 ③은 항상 넣는다(있으면 아무것도 하지 않음, 다른 소유자면 실패).
- 받는 지갑 `to`는 곡선 위의 정규 점이어야 한다(§12.1-6: SPL은 곡선 밖 주소를 차단, 파서도 `RecipientOffCurve`로 거부). PDA·토큰 계정을 소유자로 한 ATA의 토큰은 아무도 옮길 수 없기 때문이다.
- 인코더 `encode_message`는 ATA를 파생하지 못하면(확률상 없음) 빈 메시지를 돌려주고, 모든 파서·재인코딩 동일성이 이를 거부한다(서명 없음).

허용 목록(코드에 고정, `pub static SPL_ALLOWLIST: [SplAllowEntry; 3]`, `SplAllowEntry { cluster, symbol: &str, mint: SolAddress, decimals: 6, token_program: SolAddress(Token) }`; 조회 `spl_entries(cluster)`·`spl_entry(cluster, mint)`·`is_allowlisted_mint(addr)`):

| 클러스터 | 기호 | mint | decimals |
|---|---|---|---|
| mainnet | USDC | `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` | 6 |
| mainnet | USDT | `Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB` | 6 |
| devnet | USDC(Circle devnet) | `4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU`(2026-10-27·2026-10-28 `getAccountInfo`: owner = Token, 82바이트, decimals 6, initialized) | 6 |

- 토큰 식별은 mint 주소로만 한다. 온체인 메타데이터(이름·기호·로고)는 읽지 않는다. decimals·토큰 프로그램·기호는 이 표의 고정값만 쓰고 RPC 값(mint 데이터의 decimals, `jsonParsed`의 `uiAmount` 등)은 쓰지 않는다. RPC가 다른 decimals를 말하면 미리보기가 `RpcAnomaly`로 막을 뿐 메시지의 decimals는 바뀌지 않는다(§15.4).

### 8.4 PDA·ATA 파생

```rust
pub fn is_on_curve_solana(b: &[u8; 32]) -> bool;   // CompressedEdwardsY::from_slice(b).decompress().is_some() — Solana와 같은 의미
pub fn create_program_address(seeds: &[&[u8]], program: &SolAddress) -> Result<SolAddress, PdaError>;
pub fn find_program_address(seeds: &[&[u8]], program: &SolAddress) -> Result<(SolAddress, u8), PdaError>;   // BadSeeds·NoBump
pub fn associated_token_address(wallet: &SolAddress, token_program: &SolAddress, mint: &SolAddress) -> Result<(SolAddress, u8), PdaError>;
```

- `create_program_address`: seed 최대 16개, 각 ≤ 32바이트. `h = SHA-256(seed_1 ‖ … ‖ seed_n ‖ program_id ‖ "ProgramDerivedAddress")`. `is_on_curve_solana(h)`이면 `PdaError::OnCurve`.
- `find_program_address`: bump = 255, 254, …, 1 순서로 seeds ‖ [bump]를 시도해 첫 성공을 반환. 255회 모두 실패하면 `unreachable` 대신 오류를 반환한다(확률상 발생하지 않음).
- ATA seeds = `[wallet, token_program, mint]`, program = ATA 프로그램.

## 9. 엄격 파서와 재인코딩 동일성

```rust
pub fn parse_message(msg: &[u8], cluster: SolCluster) -> Result<(SolTransferCore, [u8; 32]), SolParseError>;
pub fn parse_transaction(tx: &[u8], cluster: SolCluster) -> Result<(SolTransferCore, [u8; 32], [u8; 64]), SolParseError>;
pub fn encode_message(core: &SolTransferCore, blockhash: &[u8; 32]) -> Vec<u8>;
```

파서 순서(어느 단계든 실패하면 즉시 오류, 부분 결과 없음):

1. tx: `tx[0] == 0x01`(서명 1개), 길이 ≥ 65, message = `tx[65..]`.
2. `msg[0] & 0x80 != 0` → `Versioned`(0x80·0x81 포함). header가 `[1,0,2]`이면 T_SOL, `[1,0,6]`이면 T_SPL, 그 밖 `UnknownTemplate`.
3. n_keys(shortvec) = 4 / 9. 키 중복 → `DuplicateKey`.
4. 블록해시 32바이트, n_ix = 3 / 4.
5. 각 명령: 인덱스 < n_keys, 계정 수·데이터 길이·태그가 템플릿과 정확히 같다. 프로그램 인덱스가 가리키는 키가 기대한 프로그램 주소와 같다.
6. 그룹 검사: header가 말하는 writable/readonly 구분이 템플릿 역할과 같고, 각 그룹 안이 엄격 오름차순(§7).
7. T_SPL(v1.1, 순서대로): ③의 프로그램 = ATA, ④의 프로그램 = Token(`Tokenkeg…`; 아니면 `UnexpectedProgram`) → ③ 계정 6개 `[0, to_ata, to, mint, System, Token]`·④ 계정 4개 `[from_ata, mint, to_ata, 0]`로 서로 일치(③의 Token 계정 = ④의 프로그램, 아니면 `BadAccounts`) → ③ data `01`, ④ data 10바이트·태그 `0c`(`BadData`) → 그룹: 키 0만 payer, 키 1–2 = {from_ata, to_ata}, 키 3–8 = {to, mint, System, Token, ATA, ComputeBudget}, 각 그룹 엄격 오름차순(`BadGroupOrder`) → `mint`가 `cluster`의 허용 목록에 있고 decimals가 그 고정값과 같다(아니면 둘 다 `NotAllowlisted`) → `to`가 곡선 위 정규 점(`curve_class == OnCurve`, 아니면 `RecipientOffCurve`) → `from_ata`·`to_ata`가 §8.4 파생값과 같다(`AtaMismatch`).
8. `amount > 0`, `1 ≤ cu_limit ≤ 1_400_000`(트랜잭션 최대 CU). 템플릿 상수(§10) 일치는 intent 생성 때 강제하고, 승인 요청(`build_sol_transfer_request`)과 서명(`sign_transfer`)이 다시 확인하며 아래 동일성 검사가 보장한다(벡터 테스트가 다른 한도를 쓸 수 있도록 파서는 상수를 강제하지 않는다. 450·40,000 CU 골든(§17.3)은 파서·직접 키 서명 벡터이고, 키 볼트 서명 테스트는 템플릿 한도의 같은 거래를 같은 RFC 8032 키의 직접 서명과 대조한다).
9. 남는 바이트 → `TrailingBytes`.

재인코딩 동일성(서명 직전·저널 로드 때 모두): `encode_message(core', bh') == msg` 그리고 서명 직전에는 `core' == intent.core`, `bh' == 가져온 블록해시`. 다르면 서명하지 않는다(`EncodingMismatch`).

`SolParseError` 변형: `Truncated, ShortVec(ShortVecError), Versioned, UnknownTemplate, BadSignatureCount, DuplicateKey, BadIndex, UnexpectedProgram, BadAccounts, BadData, BadGroupOrder, NotAllowlisted, AtaMismatch, RecipientOffCurve, ZeroAmount, BadComputeLimit, TrailingBytes, TooLarge`. `RecipientOffCurve`(v1.1)는 T_SPL의 받는 지갑이 곡선 밖·small-order·비정규 점일 때다. 저널 로드도 같은 파서를 쓰므로 레코드의 `cluster` 바이트가 허용 목록을 정한다(mainnet USDC 거래를 devnet 레코드로 바꾸면 본문 오류).

## 10. 수수료

```text
max_fee = SOL_BASE_FEE_LAMPORTS_PER_SIG × 1 + ceil(cu_price_micro × cu_limit / 1_000_000)   // u128로 계산, u64 초과 시 오류
```

```rust
pub const SOL_BASE_FEE_LAMPORTS_PER_SIG: u64 = 5_000;   // 프로토콜 값, §16에서 재확인, getFeeForMessage로 교차 확인
pub const SOL_TRANSFER_CU_LIMIT: u32 = 600;              // 측정 완료(2026-10-27): devnet·mainnet 각각 새 계정·기존 계정 ×10, unitsConsumed 최대 450 → 450 + 150
pub const SPL_TRANSFER_CU_LIMIT: u32 = 60_000;           // 측정 완료(2026-10-28): 기존 ATA 4,842, 새 ATA c255 + 1,500 × (255 − bump), c255 13,923–13,932 → bump ≥ 225 전부
pub const fn template_cu_limit(asset: SolAsset) -> u32;  // Sol → 600, Spl → 60,000 (intent 생성 때 강제)
```

- 우선 수수료는 **요청한 한도** 기준으로 청구되므로 한도를 항상 명시한다(생략 시 기본 한도가 builtin 명령당 3,000, 그 밖 200,000 CU).
- CU 한도 측정(M7 착수 시 1회, 프로토콜 변경 시 반복): devnet(과 mainnet)에서 실제 템플릿을 `simulateTransaction`(`sigVerify:false`, `replaceRecentBlockhash:true`)으로 경우마다 10회 실행해 `unitsConsumed` 최대값 m을 구한다. T_SOL = m + 150. T_SPL은 표본 m이 받는 ATA의 bump에 달려 있다(ATA 프로그램의 `find_program_address`가 실패한 bump마다 `create_program_address` 1회 = 1,500 CU, 2026-10-28 실측 `units = c255 + 1,500 × (255 − bump)`, 받는 쪽 ATA의 bump는 지갑이 로컬로 안다). 그래서 T_SPL 한도 L은 새 ATA 경우의 c255(= 측정값 − 1,500 × (255 − bump), 경우별 최대)로 정한다: `c255 + 1,500 × 30 ≤ L`(bump ≥ 225 전부, 미달 확률 약 2^-30)이고 `ceil1000((c255 + 1,500 × 20) × 1.25) ≤ L`. 2026-10-28: c255 = 13,923–13,932(로그에 찍히는 base58 주소 길이로 몇 CU 차이), 표본 최대 28,923(bump 245), 기존 ATA 4,842 → L = 60,000 확정(`docs/acceptance/m7-spl-20261028.md`). 상수와 측정 날짜를 코드 주석에 남긴다. 한도는 RPC 값으로 실행 중에 바꾸지 않는다. 한도를 넘는 드문 받는 주소는 시뮬레이션이 실패(CU 초과)로 보여 `L05`가 된다.
- CU 가격: `getRecentPrioritizationFees`(§15)의 `prioritizationFee` 값들을 오름차순 정렬해 `idx = (n × 3) / 4`(n=0이면 0) 값을 p75로 쓴다. `cu_price = min(p75, max_cu_price_micro, floor((fee_cap − 5_000) × 1_000_000 / cu_limit))`, `fee_cap` = 설정 `max_fee_lamports`(intent의 `fee_cap_lamports`). 따라서 `max_fee ≤ fee_cap`이 항상 성립한다.
- 설정(평문 `settings.json`의 `solana` 객체, [04] §6.1, 클러스터 선택 위치는 D30):

| 키 | 기본값 | 범위 | 의미 |
|---|---|---|---|
| `max_fee_lamports` | 100_000 | 10_000–10_000_000 | 한 전송의 최대 수수료(fee cap) |
| `max_cu_price_micro` | 1_000_000 | 0–100_000_000 | CU 가격 상한(micro-lamports/CU) |
| `cluster` | `"mainnet"` | `"mainnet"`, `"devnet"` | 화면의 현재 클러스터 |

- `getFeeForMessage` 교차 확인(미리보기 메시지, §13): `null`이면 새 미리보기 블록해시로 1회 재시도 후 `FeeQueryFailed`(승인 불가). `rpc_fee > max_fee` → `FeeFormulaChanged`(승인 불가, 상수 검토 필요). `rpc_fee < max_fee` → 일반 전송은 허용하고 "RPC 추정 X lamports"를 함께 표시, **SOL 보내기 최대는 거부**(`FeeFormulaChanged`, 잔액이 0이 되지 않아 rent 규칙 위반으로 실패하므로). 직접 입력한 금액이 보낸 뒤 잔액을 정확히 0으로 만드는 경우(§11 `r == 0`)도 보내기 최대로 보고 거부한다. SPL 보내기 최대는 토큰 전액이고 SOL 계정을 비우지 않으므로 일반 전송처럼 허용한다(v1.1). 같으면 통과.

## 11. rent

- `rent0 = getMinimumBalanceForRentExemption(0)`, `rent165 = getMinimumBalanceForRentExemption(165)`(v1.1)을 **미리보기 때마다** 조회한다. 상수로 고정하지 않는다(값이 SIMD-0437로 바뀌는 중, §16).
- 범위 이상(`rent0 ∉ 1..=SOL_RENT0_SANITY_MAX`, `rent165 ∉ 1..=SOL_RENT165_SANITY_MAX`) → `RpcAnomaly`(승인 불가). rent 금액은 온체인 sysvar가 정하므로 이 값은 표시·사전 검사용이다.

| 경우 | 규칙 (위반 시 승인 불가) |
|---|---|
| SOL, 받는 계정 없음(`getAccountInfo` = null) 또는 `lamports` 0으로 보고됨 | `amount ≥ rent0` (`BelowRentForNewAccount`, "새 계정에는 최소 X SOL") |
| SOL, 받는 계정이 있고 `0 < lamports < rent0`(rent 납부 계정) | `lamports + amount ≥ rent0` (`RecipientBelowRent { needed = rent0 − lamports }`; 런타임은 rent 기준 미만으로 남는 쓰기 계정을 거부한다). `lamports ≥ rent0`이면 규칙 없음 |
| SOL, 보낸 뒤 남는 잔액 `r = balance − amount − max_fee` | `r == 0` 또는 `r ≥ rent0` (`SenderDust`). 직접 입력한 금액이라도 `r == 0`이면 §10 `getFeeForMessage` 교차 확인에서 보내기 최대로 본다(RPC 수수료가 더 낮으면 실제로는 rent0 미만이 남아 실패하므로 `FeeFormulaChanged`) |
| SOL 보내기 최대 | `amount = balance − max_fee`, `r = 0`. `amount ≥ 1`이어야 하고 받는 계정이 없으면 위 첫 규칙도 적용 |
| SPL, 보내는 SOL 잔액 `r = balance − max_fee − (to_ata 없음 ? rent165 : 0)` | `r ≥ rent0` (`SolReserve { needed = max_fee + rent + rent0, rent0 }`; SOL 계정을 비우는 SPL 전송은 없음) |
| SPL, 토큰 수량 | `0 < amount ≤ from_ata.amount`(`InsufficientTokens`). `from_ata` 없음 → `NoTokenAccount`. SPL 보내기 최대 = `from_ata.amount` 전부(0이면 `InsufficientTokens`) |

- `balance`·계정 존재·토큰 잔액은 RPC 값이라 참고값이다. RPC가 속이면 트랜잭션이 실패할 뿐(수수료 손실 가능) 받는 사람·금액은 바뀌지 않는다.
- SPL(v1.1, yw-core `rent`): `check_rent165`, `check_spl_send(balance, max_fee, rent0, rent165, to_ata_exists, token_balance: Option<u64>, amount) -> Result<SplSendCheck { sol_after, token_after, rent }, RentError>`(검사 순서: rent0·rent165 범위 → amount 0 → `from_ata` 없음 → 토큰 부족 → SOL 예비), `spl_send_max_amount(token_balance)`. `RentError`에 `NoTokenAccount`·`InsufficientTokens`·`SolReserve { needed, rent0 }`를 더했다.
- rent 표시(§13.3 `0x0503`): 받는 ATA가 없으면(RPC) "이 거래가 만듭니다 — 생성 비용(rent) 최대 X SOL(N lamports)을 보내는 계정이 냅니다", 있으면 "이미 있습니다 — 생성 비용 없음(실행 때 없으면 최대 X SOL)". `0x0505`의 SOL 최대 차감 = `max_fee + (to_ata 없음 ? rent165 : 0)`.
- 금액 입력: `parse_amount(s, decimals) -> Result<u64, AmountError>`. 형식 `^(0|[1-9][0-9]*)(\.[0-9]{1,d})?$`(d = 9 또는 6), 부호·지수·쉼표·공백 금지, 0 금지, u64 초과 금지. 표시: `"<정수부>.<d자리>"`(뒤 0 유지) + 원시 정수(천 단위 쉼표).

```rust
pub const SOL_RENT0_SANITY_MAX: u64 = 2_000_000;
pub const SOL_RENT165_SANITY_MAX: u64 = 5_000_000;
```

## 12. 수신자 검사와 주소 중독 방지

### 12.1 로컬 검사(RPC 없음, 순서대로)

| # | 검사 | 결과 |
|---|---|---|
| 1 | §5 엄격 base58 → 32바이트 | 실패 시 입력 오류 |
| 2 | 아래 `SOL_BLOCKED_RECIPIENTS`에 있거나 어느 클러스터든 허용 목록 mint | 차단(무시 불가) `RecipientIsProgram` |
| 3 | `decompress()`가 Some인데 `is_small_order()`이거나 재압축 불일치(`compress() != to`, 비정규 y) | 차단 `RecipientUnspendable` (System ID `111…1`도 y=0 small-order 점) |
| 4 | `to == from` | 차단 `SelfSend` |
| 5 | `to`가 자기 다른 Solana 계정 | 허용, "내 계정 #i" 표시 |
| 6 | `is_on_curve_solana(to) == false` | SOL: 고위험 `OffCurve`(`L02`, "일반 지갑이 아님: 프로그램 소유 주소(PDA)나 토큰 계정일 수 있음"). SPL(v1.1): 차단 `OffCurveOwner`(E-SOL-006, 입력 단계; `check_recipient_for(input, from, known, asset)`). 곡선 밖 주소를 소유자로 한 ATA의 토큰은 아무도 옮길 수 없고, 흔한 실수(상대의 토큰 계정 주소를 붙여넣기)를 막는다. 파서도 `RecipientOffCurve`로 거부한다(§9) |
| 7 | 주소록·자기 계정·보낸 내역의 주소 E(≠ to)와 앞 `SOL_LOOKALIKE_CHARS`자 또는 뒤 `SOL_LOOKALIKE_CHARS`자가 같음 | 고위험 `Lookalike`(`L03`, "주소록 '<라벨>'과 앞/뒤가 같은 다른 주소"), 해당 항목 이름 표시 |
| 8 | 주소록·자기 계정·**선택한 클러스터에서 성공한(`Landed`/`"succeeded"`) 전송**의 받는 주소 어디에도 없음 | 주의 `FirstTime`(`L06`, "처음 보내는 주소", 체크 없음), 소액 시험 송금 권고 문구. 실패·만료·진행 중 전송과 다른 클러스터의 전송은 받는 주소를 "아는 주소"로 만들지 않고(`KnownKind::History`) 7번 비교에만 쓴다. 중독 주소는 7번이 고위험으로 잡는다 |

```rust
pub const SOL_LOOKALIKE_CHARS: usize = 3;   // 관측된 중독 주소는 양끝 3자 이상 일치
pub const SOL_BLOCKED_RECIPIENTS: [&str; 27] = [   // 전부 32바이트로 디코딩됨을 확인. 테스트가 디코딩·중복 없음을 단언
    "11111111111111111111111111111111", "ComputeBudget111111111111111111111111111111", "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo", "So11111111111111111111111111111111111111112", "Stake11111111111111111111111111111111111111",
    "Vote111111111111111111111111111111111111111", "BPFLoaderUpgradeab1e11111111111111111111111", "BPFLoader2111111111111111111111111111111111",
    "BPFLoader1111111111111111111111111111111111", "NativeLoader1111111111111111111111111111111", "Config1111111111111111111111111111111111111",
    "AddressLookupTab1e1111111111111111111111111", "Sysvar1111111111111111111111111111111111111", "SysvarRent111111111111111111111111111111111",
    "SysvarC1ock11111111111111111111111111111111", "SysvarRecentB1ockHashes11111111111111111111", "SysvarEpochSchedu1e111111111111111111111111",
    "SysvarFees111111111111111111111111111111111", "Sysvar1nstructions1111111111111111111111111", "SysvarS1otHashes111111111111111111111111111",
    "SysvarStakeHistory1111111111111111111111111", "Ed25519SigVerify111111111111111111111111111", "KeccakSecp256k11111111111111111111111111111",
];
```

- 위 목록 중 여럿(Tokenkeg, ATA, Memo, Sysvar 일부 등)은 on-curve라 곡선 검사로 걸러지지 않으므로 목록이 필요하다. 목록에 없는 프로그램은 §12.2가 잡는다.

### 12.2 RPC 참고 분류(`getAccountInfo`, dataSlice 길이 0)

| RPC 결과 | 처리 |
|---|---|
| null | "새 계정"(§11 rent 규칙) |
| owner = System, executable=false | 정상 |
| (SPL) null | 정상(SOL 계정이 없는 새 지갑도 토큰을 받을 수 있다. "SOL 계정 없음" 표시, rent0 규칙 없음) |
| owner = Token 또는 Token-2022 | 차단 `RecipientIsTokenAccount`("지갑 주소가 아니라 토큰 계정/mint 주소") |
| executable = true | 차단 `RecipientIsProgram` |
| 그 밖 owner | 고위험 "프로그램 소유 계정"(`L04`) |

RPC 분류로 **차단**하는 것은 실패 방향(서비스 거부만 가능)이라 허용한다. RPC 분류로 경고를 **없애지** 않는다.

### 12.3 화면 규칙

- 받은 거래 내역은 기본으로 가져오지 않고 보여주지 않는다. "최근 보낸 사람" 목록이 없다. 받는 주소 입력의 자동 완성은 주소록과 자기 계정에서만 한다. 예외(2026-11-11, D25): 사용자가 [04] §2.6 `받은 내역도 보기`를 켜면 genesis 확인 뒤 선택 계정과 그 허용 목록 토큰의 ATA(로컬 파생)마다 `getSignaturesForAddress`(limit 20), 처음 보는 서명만 `getTransaction`(`jsonParsed`, `maxSupportedTransactionVersion` 0, 한 번에 최대 20개, 본 서명은 메모리에 200개까지)을 읽는다(평소 1 + 1 + 토큰 수 요청). 입금 = 실패하지 않았고 계정이 서명하지 않았으며 그 계정의 SOL 잔액(보낸 주소: 가장 많이 줄어든 계정, 없으면 수수료 지불자) 또는 그 계정이 소유한 허용 목록 토큰 잔액이 늘어난 거래. 0·먼지(SOL < 0.001, 토큰 < 0.0001개)는 행이 아니라 개수만, 다른 mint는 읽지도 세지도 않는다. 보낸 주소는 표시 전용(복사·선택 없음, 유사 주소면 고위험 태그)이다.
- 보낸 내역(저널·meta `activity`, [02] §5.3·[04] §2.6)은 지갑 자신이 서명한 거래만 담으므로, 2026-11-11부터 그 받는 주소는 전체(띄어쓰기 없이, 앞 4자·끝 4자 강조)를 누르면 복사되고 주소록에 없으면 ☆ `이 주소 저장`이 같은 줄 끝에 있다([04] §2.6 "복사 줄과 아이콘"; 2026-11-10까지는 표시만 하고 복사·선택 버튼이 없었다). **받은 내역의 보낸 주소는 절대 복사·선택·저장할 수 없다**(위 항목, 주소 오염 대비). 거래 ID(서명, base58 88자)는 공개 정보라 보내기 결과 화면에 `해시 복사`, 활동 행은 거래 ID 줄을 누르면 복사된다(2026-11-10, Bitcoin·EVM과 같다 — 탐색기에서 확인할 때 손으로 옮겨 적지 않게). 2026-11-11부터 그 줄 끝에 아이콘 ↗ `탐색기에서 열기`·🔗 `탐색기 링크 복사`, 계정 카드 주소 줄 끝에 ↗ `탐색기에서 주소 보기`가 있다(기본 Solscan `https://solscan.io/tx/{hash}`·`/account/{address}`, devnet은 끝에 `?cluster=devnet`; 바꾸기는 [04] §2.11 "블록 탐색기", 여는 방법 [04] §2.14). 받는 사람 주소에는 탐색기 버튼을 두지 않는다.
- 주소 표시는 항상 전체를 4자 묶음으로 끊고, 처음·마지막 묶음은 보통 굵기, 가운데 묶음은 굵게 표시한다(중독 주소는 양끝만 맞춘다). 생략(`…`) 표시는 어디에서도 쓰지 않는다([04](04-app-ui.md)의 주소 표시 규칙). 예외(2026-11-11, [04] §3.3): 이 지갑이 아는 주소를 보는 곳(선택 계정 카드의 내 주소, 토큰 카드의 mint, 보낸 거래 활동의 받는 주소)은 묶음 없이 전체를 쓰고 앞 4자·끝 4자를 강조한다.
- 주소록 항목: [02] §5.3 `AddressBookEntry {chain:"sol", address(base58), label, verified, added_at_unix_ms}`. 승인 창 `0x0501`은 정확히 일치하는 항목의 라벨과 `verified` 여부를 값에 넣는다.
- 받기 화면: 주소 전체(묶음 표시), QR(qrcodegen, 내용 = base58 문자열 그대로, ECC Medium; 이식 근거 `archive/spec-v2.4:demo/sepolia-wallet/src/receive_qr.rs:156-160`), 경로, 클러스터. 주소 복사는 비밀이 아니므로 일반 클립보드를 쓴다.
- 허용 목록 밖 토큰은 잔액·존재를 표시하지 않는다(v1.1 구현: 잔액은 허용 목록 토큰마다 로컬 파생한 ATA 하나를 `getAccountInfo`(base64)로만 읽는다. `getTokenAccountsByOwner`·`jsonParsed`는 쓰지 않으므로 다른 토큰·NFT·ATA가 아닌 토큰 계정은 조회조차 하지 않는다). ATA 자리에 다른 형식의 계정이 있으면 "확인할 수 없음"으로 잔액을 보이지 않는다(§15.4 `Invalid`).

## 13. 승인 흐름

### 13.1 순서

1. **입력·로컬 검사**: 계정, 자산, 받는 주소(§12.1), 금액(§11). 같은 (클러스터, from)에 `Pending`이 있으면 "이전 전송 확인 중"으로 막는다. `검토`를 누르면 입력을 그 자리에서 다시 검사하고, 그 결과(받는 주소·자산·금액)가 화면에 보이던 검사 결과(입력 검사: 온전한 주소·금액은 바로, 아니면 입력 정지 500 ms 뒤 — [04] §2.7)와 다르면 승인을 열지 않고 고정 문구("입력이 바뀌어 다시 확인했습니다…")만 보인다. 승인 요청은 이 새 검사 결과로만 만든다.
2. **미리보기(RPC, 모두 `commitment:"confirmed"`; D32: 설정한 RPC를 신뢰하고 `confirmed`를 최종으로 본다)**: `getGenesisHash`(불일치 시 중단, §15.1) → `getBalance(from)` → `getAccountInfo(to)` → (SPL) `getAccountInfo(mint)`·`getAccountInfo(from_ata)`·`getAccountInfo(to_ata)`(데이터 포함, §15.4) → `getMinimumBalanceForRentExemption(0)`(SPL은 이어서 `(165)`) → `getRecentPrioritizationFees` → `getLatestBlockhash`(미리보기 전용, 서명에 쓰지 않음) → 미리보기 메시지로 `getFeeForMessage`(§10) → `simulateTransaction`(서명 64바이트 0, `sigVerify:false`, `replaceRecentBlockhash:true`, 참고).
3. **승인 요청 생성·표시**: §13.2 intent와 §13.3 표시로 [03] §11.1 `ApprovalDraft`를 만들고(`build_sol_transfer_request`), `ApprovalStore::issue`([03] §11.5)가 `ApprovalRequest`(digest는 [03] §11.3·§11.4)를 만든다. 창에 Ready로 표시하는 순간 draft를 만들고 바로 `issue`를 호출하므로 `created_unix_ms` = intent `created_at_ms` = 표시 시각, 만료 = 표시 + 120 s(D23). 기한·만료 동작은 모든 체인 공통으로 [04] §3.5가 정본이다: 남은 시간이 0이 되면 창은 `QueueOutcome::Expired`로 닫히고 보내기 화면으로 돌아간다(입력 값 유지, [04] §2.7 T-APPR-EXPIRED). 다시 `검토`하면 1단계부터 새로 진행한다(새 미리보기, 새 intent id, **새 승인**). 만료된 승인·intent는 재사용하지 않으며, SOL만의 별도 만료 상태나 창 안의 재준비 버튼은 없다. 거부도 같은 화면으로 돌아간다(입력 값 유지). D23의 "60초보다 오래된 시뮬레이션은 클릭 때 재실행"은 승인 근거인 EVM 시뮬레이션(D15)용이다. SOL 시뮬레이션은 참고(D27, `simulation: None`)라 다시 실행하지 않는다.
4. **승인**: [04] §3.4 공통 조작. 고위험 경고가 있으면 D16의 "위 경고를 모두 확인했습니다" 체크박스 1개 + 2초 누르기. `ApprovalStore::consume(id, shown_digest, now)`가 1회용 `Approved`(복제 불가, [03] §11.5)를 돌려주면 그 시각을 `consumed_at_ms`로 기록한다.
5. **서명 직전 조회**: `getGenesisHash` 재확인 → `getLatestBlockhash({commitment:"confirmed"})` → `(blockhash, lastValidBlockHeight)`. 그 뒤 `getBlockHeight(confirmed) = h`에 대해 `h + SOL_MIN_LVBH_AHEAD ≤ lvbh ≤ h + SOL_MAX_LVBH_AHEAD`가 아니면 `RpcAnomaly`. confirmed 블록해시의 lvbh는 그 블록 높이 + 150이고 `h`는 그 뒤에 묻으므로 `lvbh ≤ h + 150`이다. 하한 `h + 100`은 두 호출 사이 진행 50블록(약 10 s)을 허용하는 가장 좁은 값이며, 너무 낮은 lvbh가 만료 증명(§14.3-1 `높이 > lvbh`)을 앞당기는 것을 막는다.
6. **서명(yw-core)**: `now_ms ≤ consumed_at_ms + SOL_SIGN_DEADLINE_SECS × 1000` 확인 → `Approved`의 kind = `SolTransfer`·account = `intent.core.from` 확인 → intent 생성 규칙 재확인(키 사용 전, 실패는 `PolicyMismatch`): `cu_limit = template_cu_limit(asset)`, `max_fee_lamports = max_fee(cu_limit, cu_price)`(§10 공식), `max_fee ≤ fee_cap ≤ 10_000_000`(설정 범위), 비표준 경로(§3.3)면 `flags`에 보내기 최대가 있고 받는 주소가 같은 시드의 표준 계정(`Standard(0..=999)`를 128개씩 파생해 대조)일 것 → `encode_message` → §9 파싱·재인코딩 동일성 → `with_ed25519_seed(intent.source, |k| …)`(§3.1) 안에서 `signing_key(k)` → 공개키 = from 확인 → 서명 → 키 소거 → `VerifyingKey::verify_strict` → 트랜잭션 조립·재파싱. 이식 근거(서명 후 재검증 패턴): `archive/spec-v2.4:crates/key-agent/src/lib.rs:328-345`.
7. **저널 기록 후 브로드캐스트**(§14). 저널 쓰기가 실패로 보고되면 저널을 디스크에서 다시 읽는다. 새 `Pending` 레코드가 그대로 있으면(쓰기는 반영됨) 기록된 것으로 보고 평소처럼 추적·전송한다(재시작 뒤 재개될 레코드를 "보내지 않음"으로 버리지 않는다). 없을 때만 서명 바이트를 버린다(전송한 적 없으므로 안전).

- 4–6 사이의 어떤 실패(시간 초과, 잠금, RPC 오류, 불일치)도 서명 전이면 아무것도 남기지 않는다. 승인은 소비되었으므로 다시 보내려면 1단계부터 새 승인이 필요하다.
- 같은 `intent_hash`로 저널에 레코드가 이미 있으면 서명하지 않는다(`AlreadySigned`). 그다음 키 작업자가 저널 자체에서 같은 (클러스터, from)의 `Pending`을 다시 확인하고, 있으면 서명하지 않는다(`SolSignError::PendingExists`, E-TX-002).
- `build_sol_transfer_request`도 템플릿 CU 한도·최대 수수료 공식·상한, 그리고 표시할 수신자 검사 결과의 주소(`facts.recipient.to`)가 core가 정한 받는 주소와 같은지를 확인하고, 아니면 승인 요청을 만들지 않는다(`DisplayError`, 창은 실패 표시).
- 6단계 서명 전에 §14.1 저널 자리 검사([02] §5.4 추가 전 검사)를 한다. 통과하지 못하면 `journal::JournalError::Full`로 서명·전송하지 않는다(E-TX-005 "거래 저널 공간이 부족합니다", [04] §7). 2단계 미리보기도 같은 검사를 해 `L01`로 미리 막는다.

```rust
// [03] §11.1에 더하는 SOL 변형 (값·태그는 [03] §11에 등록)
ChainRef::Solana { cluster: SolCluster, genesis: [u8; 32] }   // 태그 2; digest: push_u8(2) push_u8(cluster) push_bytes(genesis)
AccountRef::Sol([u8; 32])                                      // account_bytes = from 공개키 32바이트
ApprovalKind::SolTransfer = 0x20                               // origin은 항상 ApprovalOrigin::App
SigningPayload::SolTransfer(SolTransferIntent)                 // signing_payload_bytes = §13.2 transcript 바이트
pub fn build_sol_transfer_request(intent: &SolTransferIntent, genesis: &[u8; 32],
                                  facts: &SolPreviewFacts /* 2단계 조회 결과 */) -> Result<ApprovalDraft, DisplayError>; // issue 전, [03] §11.1
// 표시 시각은 intent.created_at_ms가 가진다. yw-app은 같은 now_unix_ms로 intent를 만들고 바로 `issue`한다.
pub fn sign_transfer(vault: &Vault, approved: Approved, consumed_at_ms: u64,
                     blockhash: [u8; 32], now_ms: u64) -> Result<SignedSolTransfer, SolSignError>;
pub const SOL_SIGN_DEADLINE_SECS: u64 = 20;      // consume → 서명 시작 (승인 창 만료 120 s와 별개)
pub const SOL_MAX_LVBH_AHEAD: u64 = 300;
pub const SOL_MIN_LVBH_AHEAD: u64 = 100;         // lvbh = 블록해시 높이 + 150 ≤ h + 150, 진행 여유 50블록
```

### 13.2 intent 정규 인코딩

`Transcript`(BE 정수, `push_bytes`는 u32 BE 길이 접두; 이식 `archive/spec-v2.4:crates/wallet-model/src/codec.rs:28-109`)로 다음 순서. 이 transcript 바이트가 `SigningPayload::SolTransfer`의 서명 대상 바이트이고 `intent_hash`는 그 해시다:

```text
start_domain("your-wallet/sol/transfer-intent", 1)
push_bytes(id[16])  push_u8(cluster)  push_bytes(genesis_hash[32])
push_u8(source_tag)  push_u32(a)  push_u32(b)          // §3.2 태그(1–8); Standard/Bip44Account/Hardware/Mnemonic: a=AccountIndex 값,b=0; SolletLegacy: a=wallet,b=account; 나머지(Imported 포함) 0,0
[push_bytes(mnemonic_record_id 16)]                    // 태그 8(추가한 니모닉, §3.5)일 때만; 다른 태그의 바이트는 그대로
push_bytes(from[32])  push_bytes(to[32])
push_u8(asset_tag)                                      // 1=SOL, 2=SPL
  SPL이면: push_bytes(mint[32]) push_bytes(token_program[32]) push_u8(decimals) push_bytes(from_ata[32]) push_bytes(to_ata[32])
push_u64(amount)  push_u32(cu_limit)  push_u64(cu_price_micro)
push_u64(max_fee_lamports)  push_u64(fee_cap_lamports)
push_u8(flags)                                          // 표시한 경고: bit0 send_max, bit1 off_curve, bit2 first_time, bit3 lookalike, bit4 program_owned, bit5 sim_warning, bit6 non_standard_path
push_u64(created_at_ms)
intent_hash = SHA-256(transcript)
```

- `flags`는 intent 생성 때 정해지는 경고 집합이며 intent 해시에 들어간다. 각 비트는 §13.3 경고 표의 `Warning`(등급 명시)으로 `ApprovalDisplay.warnings`에 들어간다. 고위험 경고가 하나라도 있으면 `ack_required = true`이고, 승인 창은 D16의 "위 경고를 모두 확인했습니다" 체크박스 1개 + 2초 누르기를 요구한다(비트마다 체크하지 않으며, 체크 상태는 해시에 넣지 않는다).
- 잔액·rent·RPC 수수료 추정·시뮬레이션 결과는 서명 바이트를 바꾸지 않으므로 intent에 넣지 않는다(표시 모델과 그 digest에만 있다).
- `id`는 getrandom 16바이트이며 `ApprovalRequest.id`와 같다. 재검토(만료·거부 후 `검토`)·다시 보내기(§14.3)마다 새로 만든다.

### 13.3 승인 창 표시 필드·경고

제목은 [03] §11.1 형식(예 `[Solana devnet (테스트)] SOL 전송: 1.000000000 SOL`, SPL `[Solana mainnet] 토큰 전송: 1.000000 USDC`). 필드 키는 [03] §11.2의 공통 헤더 `0x0001`–`0x0003`과 SOL 범위 `0x05xx`([03] §11.2에 등록)이고 표시 순서는 키 순서다. SOL은 표시 교체(`replace`)를 쓰지 않으므로 volatile 필드가 없다.

| 키 | 필드 | 출처 | critical | 비고 |
|---|---|---|---|---|
| `0x0001` | 요청 출처 | 로컬 | 예 | `ApprovalOrigin::App`("yw-app"), 표시 값 `Your Wallet 앱` |
| `0x0002` | 네트워크 | 로컬 + 제네시스 확인 | 예 | "Solana mainnet" / devnet은 별도 색 배너 "Solana devnet (테스트)" |
| `0x0003` | 보내는 계정 | meta + intent | 예 | 라벨, 경로(`m/44'/501'/0'/0'` 등), 주소 전체. 비표준 경로면 `L07` |
| `0x0501` | 받는 주소 | intent | 예 | §12.3 묶음 표시, 주소록 라벨·verified, "내 계정 #i". SPL: 받는 **지갑**(소유자) 주소임을 밝히고 토큰은 `0x0502`의 받는 ATA로 간다고 적는다. SOL 계정이 없으면 "SOL 계정 없음(새 지갑일 수 있음 — 토큰을 받는 데는 문제없음)" |
| `0x0502` | 자산·금액 | intent | 예 | SOL: `1.000000000 SOL` + `1,000,000,000 lamports`. SPL(`sub_label` = 허용 목록 기호): `1.000000 USDC`, `1,000,000 (원시 단위, decimals 6)`, mint 전체(묶음, 한 줄), 토큰 프로그램 `SPL Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)`, 보내는 ATA·받는 ATA 전체(각각 한 줄, 승인 창은 그 줄을 주소 글꼴로 그린다) |
| `0x0503` | ATA 생성(SPL) | RPC 참고 + rent | 예 | §11 rent 표시: 없으면 "이 거래가 만듭니다 — 생성 비용(rent) 최대 X SOL(N lamports)을 보내는 계정이 냅니다", 있으면 "이미 있습니다 — 생성 비용 없음". SOL에는 없다 |
| `0x0504` | 수수료 | 로컬 | 예 | 기본 5,000 × 1, 우선 수수료 = cu_limit × cu_price / 1e6 올림, 최대 합계, 사용자 상한, RPC `getFeeForMessage` 값 |
| `0x0505` | 최대 총 차감 | 로컬 | 예 | SOL: 금액 + 최대 수수료. SPL: 토큰 금액, 그리고 SOL 최대 = 최대 수수료 + (받는 ATA 없음 ? rent165 : 0) (`max_sol_debit`) |
| `0x0506` | 잔액 | RPC 참고 | | 전 → 후, "RPC 기준" 표기. SPL은 토큰 줄과 SOL 줄 둘 다 |
| `0x0507` | 시뮬레이션 | RPC 참고 | | "성공(CU n)" 또는 "실패: <정규화 분류>". 실패·`unitsConsumed > cu_limit`이면 `L05`. 승인을 막지 않는다(D27) |
| `0x0508` | 유효 시간 | 로컬 | | "승인 창은 표시 후 120초에 만료(남은 시간은 상태 줄). 승인 즉시 서명하며 거래는 약 30초 뒤 만료" |
| `0x0509` | 감사 | 로컬 | | intent_hash(hex) |

경고(`Warning`, [03] §10.1; `RuleId` 상위 바이트 `'L'`(0x4C), [03] §10.1에 등록 — `'S'`는 SIWE가 쓴다). 순서·`ack_required` 계산은 [03] §10.1, 체크박스·누르기는 D16·[04] §3.4. 경고별 확인 체크는 없다: 확인 필요 여부는 등급에서만 나온다(고위험이 하나라도 있으면 `ack_required = true`, "위 경고를 모두 확인했습니다" 체크박스 1개 + 2초 누르기).

| RuleId | `flags` 비트 | 조건 | 등급 |
|---|---|---|---|
| `L01` | — | 승인 불가 조건(아래), 사유별 문구 | 차단 |
| `L02` | bit1 | `OffCurve`(§12.1-6) | 고위험 |
| `L03` | bit3 | `Lookalike`(§12.1-7) | 고위험 |
| `L04` | bit4 | 프로그램 소유 계정(§12.2) | 고위험 |
| `L05` | bit5 | 시뮬레이션 실패·CU 초과(`0x0507`) | 고위험 |
| `L06` | bit2 | `FirstTime`(§12.1-8) | 주의 |
| `L07` | bit6 | 비표준 경로 계정(§3.3) | 주의 |
| `L08` | bit0 | 보내기 최대(보낸 뒤 SOL 또는 토큰 잔액 0; SPL 문구는 "이 계정의 USDC 잔액은 0이 됩니다(SOL은 남습니다)") | 정보 |

- 블록해시는 보안 필드로 표시하지 않는다. RPC가 준 문자열(로그·오류 메시지)은 그대로 표시하지 않고 §15.3 분류만 표시한다.
- 승인 불가 조건(`L01`): 클러스터 불일치, `FeeFormulaChanged`/`FeeQueryFailed`, §11 규칙 위반, 잔액 부족(RPC 기준), §12.2 차단, `RpcAnomaly`, 같은 계정의 `Pending` 존재, 저널 자리 없음(`JournalError::Full`, §14.1). SPL(v1.1, §15.4): mint 데이터가 고정값과 다름·`from_ata` 자리에 다른 계정(`RpcAnomaly`), 보내는 토큰 계정 동결(`SolBlock::TokenAccountFrozen`), 받는 ATA가 동결이거나 이 mint·지갑의 토큰 계정이 아님(`SolBlock::RecipientTokenAccountUnusable`). §12.1 1–4번 차단은 입력 단계에서 막으므로 창을 띄우지 않는다. 승인 창 만료는 경고가 아니라 [04] §3.5의 `Expired` 결과다(§13.1-3).

## 14. 저널과 브로드캐스트 상태 기계

### 14.1 레코드

`journal.ywj` 컨테이너(암호화·원자적 쓰기)는 [02] §5.2, 평문 프레이밍은 [02] §5.4의 이진 형식 `entry = kind u8 ‖ body_len u32 BE ‖ body`가 정본이다. SOL entry는 `kind = 0x02`(체인 판별자; EVM `0x01`, BTC `0x03`)이고 body는 아래 이진 레코드 바이트 그대로다(JSON·hex 변환 없음). body[0] `record_kind`는 `0x02` 고정이며 읽을 때 검사만 한다([03] §5와 같은 규칙). 정수 BE.

```text
off  size  field
0    1     record_kind = 0x02
1    1     record_version = 1
2    1     state: 1 Pending, 2 Landed, 3 FailedOnChain, 4 Expired
3    1     cluster: 1 mainnet, 2 devnet
4    1     source_tag (§3.2)          5  4+4  source_a u32, source_b u32 (§13.2와 같은 규칙)
13   16    intent_id                  29 32   intent_hash
61   8     signed_at_ms (Unix ms)     69 8    last_valid_block_height
77   8     terminal_slot (없으면 0)   85 2    terminal_err (§15.3 코드, 없으면 0)
87   2     tx_len (65..=1232)         89 tx_len  서명된 트랜잭션 바이트
```

```rust
pub const SOL_JOURNAL_HEADER_LEN: usize = 89;                                       // 고정 헤더 H (오프셋 0..=88)
pub const SOL_JOURNAL_MNEMONIC_LEN: usize = 16;                                     // 버전 2의 니모닉 record id
pub const SOL_JOURNAL_MAX_BODY: usize =
    SOL_JOURNAL_HEADER_LEN + SOL_JOURNAL_MNEMONIC_LEN + SOL_MAX_TX_BYTES;          // 89 + 16 + 1,232 = 1,337 ([02] §5.4 SOL 최대 본문)
```

- 고정 헤더 크기는 **H = 89바이트**이고 `body_len = 89 + tx_len`이어야 한다. 실제 템플릿 본문은 T_SOL 356바이트(89 + 267), T_SPL 526바이트(89 + 437).
- **레코드 버전 2 (추가한 니모닉의 계정, 2026-11-08, §3.5).** 출처 태그 8의 레코드는 `record_version = 2`이고 헤더 89바이트 뒤 `[89]`에 니모닉 record id 16바이트(0 아님)가 오고 트랜잭션은 `[105]`부터다(`body_len = 105 + tx_len`; `intent_hash` 등 헤더 위치는 같다). 버전 1에 태그 8은 `Source`, 버전 2에 다른 태그는 `Header`, 0인 id는 `Source`로 거부한다. 다른 출처의 레코드는 버전 1 바이트 그대로다. 그래서 SOL 최대 본문(상한 검사용 `SOL_JOURNAL_MAX_BODY`)은 89 + 16 + 1,232 = **1,337바이트**다([02] §5.4가 이 값을 쓴다; 버전 1 본문은 최대 1,321). 이전 빌드는 버전 2를 본문 오류로 본다(SOL 보내기만 멈춤, 바이트 보존, [04] §6.6).
- 서명·블록해시·from·to·금액은 tx 바이트 안에 있다. 로드 때 헤더 검사(`record_kind == 0x02`, `record_version == 1`, `state` 1–4, `cluster` 1–2, `source_tag` 1–6과 §13.2의 a·b 규칙, `body_len == 89 + tx_len`, `Pending`·`Expired`면 `terminal_slot == 0`·`terminal_err == 0`) + `parse_transaction` + 재인코딩 동일성 + `verify_strict(from)`이 모두 성공해야 한다. 실패는 [02] §5.4 **본문 오류**다: SOL 보내기만 끄고 "저널 손상"(E-VLT-006)을 표시하며, 그 entry는 브로드캐스트하지 않고 자동 삭제하지 않으며 바이트 그대로 보존한다. 프레이밍 오류(`kind`·`body_len` 범위 등)는 [02] §5.4가 처리한다.
- 이식 근거(먼저 기록하고 나중에 내보내는 패턴): `archive/spec-v2.4:crates/key-agent/src/durable.rs:725-806,1100-1129`. 이 문서의 상태 수는 4개로 줄인다.
- 정리: 터미널 상태(2–4) 레코드는 meta `activity["solana:mainnet" | "solana:devnet"]`([02] §5.3)에 아래 `ActivityEntry`로 옮긴(meta 쓰기 성공) 뒤 저널에서 삭제한다. `Pending`은 자동 삭제하지 않는다.
- 저널 자리 검사(서명 전, [02] §5.4 추가 전 검사): 새 `Pending`을 만들 서명 전에 `entry_count + 1 ≤ 256`, SOL entry 수 + 1 ≤ `SOL_JOURNAL_MAX_RECORDS`, `현재 평문 길이 + 5 + SOL_JOURNAL_MAX_BODY ≤ 16 MiB`를 본다. 넘으면 SOL 종결 레코드를 오래된 것(`signed_at_ms` 오름차순)부터 activity로 옮긴 뒤 지우며 다시 보고, 그래도 넘으면 `journal::JournalError::Full`로 서명·전송하지 않는다(E-TX-005 "거래 저널 공간이 부족합니다", [04] §7). 다른 체인 entry는 지우지 않는다.
- 종결 레코드 → [02] §5.3 `ActivityEntry`(SOL 전용 스키마는 없다):

| `ActivityEntry` 필드 | SOL 값 |
|---|---|
| `account` | from(보내는 계정, base58) |
| `tx_id` | `base58_encode(signature)`(트랜잭션 ID, §7) |
| `title` | §13.3 승인 제목. tx 바이트·cluster에서 같은 빌더로 다시 만든다(서명 당시 제목과 같은 문자열) |
| `asset` | SOL `"native"`, SPL mint base58 |
| `amount` | 원시 단위 10진 문자열(SOL lamports, SPL 토큰 원시 u64) |
| `counterparty` | to(받는 지갑 주소, base58; SPL도 ATA가 아니라 지갑 주소) |
| `status` | `Landed` → `"succeeded"`, `FailedOnChain` → `"failed"`, `Expired` → `"expired"` |
| `time_unix_ms` | 종결 상태를 관측한 시각(벽시계 Unix ms) |

### 14.2 상태 전이

```text
(서명 완료) --저널 fsync--> Pending --confirmed, err=null--> Landed
                             |--confirmed, err≠null--> FailedOnChain   (수수료 차감됨)
                             |--만료 증명(§14.3)------> Expired         (전송되지 않음)
```

브로드캐스트 루프(yw-app, 판단 함수는 yw-core `sol::broadcast::decide`로 순수 함수화):

| 주기·사건 | 동작 |
|---|---|
| 첫 전송 | 저널에 `Pending` 기록이 디스크에 반영된 뒤 `sendTransaction`(§15.2, `skipPreflight:false`, `maxRetries:0`). 이 세션의 첫 라운드(서명 직후, 재시작·잠금 해제 뒤 재개)는 상태 조회보다 **먼저** 보낸다: 상태 조회 실패가 첫 전송을 막지 않으며, 그 전송 결과(재전송 주기, 결정적 오류 플래그)는 조회가 실패해도 기록한다 |
| 매 `SOL_POLL_INTERVAL_MS` | `getSignatureStatuses([sig], {searchTransactionHistory:false})` |
| 매 `SOL_REBROADCAST_INTERVAL_MS` | 상태가 null이고 재전송 중지 플래그가 없으면 **같은 바이트·같은 파라미터**로 `sendTransaction`, 그리고 `getEpochInfo(confirmed)`(한 응답의 `blockHeight`·`absoluteSlot`, §14.3) |
| 상태 `confirmationStatus:"confirmed"` 또는 `"finalized"`, `err:null` | `Landed{slot}` 저장, 종료(D32: `confirmed`가 최종) |
| 상태 `confirmed`/`finalized`, `err≠null` | `FailedOnChain{slot, err}` 저장, 종료 |
| 상태 `processed` | "처리 중" 표시, 재전송 생략, 계속 조회. 아직 최종으로 보지 않는다 |
| 전송 응답 서명 ≠ 로컬 `base58(sig)` | `RpcAnomaly` 기록, 상태 유지 |
| preflight 오류: `BlockhashNotFound`·전송 오류·시간 초과 | 계속 재전송 |
| preflight 오류: 결정적 거래 오류(§15.3 1–6) | 재전송 중지(메모리 플래그), 오류 표시, `Pending` 유지(전달되지 않았음을 증명할 수 없음) |
| 사용자 "지금 다시 전송"(§14.3) | 다음 라운드를 바로 시작해 상태 조회보다 먼저 **같은 바이트**로 `sendTransaction`(세션 첫 라운드와 같음). 결정적 preflight 오류로 멈춘 재전송 플래그도 풀린다(같은 서명이므로 두 번 처리되지 않음) |
| `SOL_PENDING_NOTICE_SECS` 경과 | "네트워크/RPC 확인 필요" 표시(안내만, 대기 조건 아님). 자동 재서명 없음 |

- 재전송은 서명 바이트가 같으므로(Ed25519 결정적) 같은 거래를 여러 번 보내도 한 번만 처리된다. **새 블록해시로 다시 서명하는 일은 루프 안에 없다.**
- yw-app 재시작·잠금 해제 후 `Pending` 레코드마다 루프를 재개한다. 잠금 중에도 루프는 계속할 수 있다(비밀 불필요). 상태 저장은 잠금 해제 후에 한다.
- 종결 상태를 키 작업자에 저장 요청(`SolApply`)하면 그 레코드의 루프를 멈추고 "결과를 거래 저널에 저장하는 중"을 표시한다. `SOL_APPLY_RETRY_MS`(10 s) 뒤에도 저널에 `Pending`으로 남아 있으면 저장 실패로 보고 "결과를 거래 저널에 저장하지 못했습니다. 다시 확인해 저장합니다 (E-VLT-003)"를 표시하며 루프를 다시 돌려 같은 종결 상태를 다시 저장한다(같은 전이는 멱등). 이때 클러스터 불일치 문구(E-RPC-006)는 쓰지 않는다.

```rust
pub const SOL_POLL_INTERVAL_MS: u64 = 1_000;
pub const SOL_REBROADCAST_INTERVAL_MS: u64 = 2_500;
pub const SOL_PENDING_NOTICE_SECS: u64 = 120;
pub const SOL_JOURNAL_MAX_RECORDS: usize = 64;
```

### 14.3 만료 증명과 재전송

설정한 RPC를 신뢰한다(D32). 높이 라운드(매 `SOL_REBROADCAST_INTERVAL_MS`, §14.2) **한 번**이 아래를 이 순서로 모두 만족하면 `Expired`를 저장한다. 벽시계·단조 시계 최소 시간과 두 번 관측은 없다(이전의 90초 하한과 연속 2라운드 조건은 D32로 폐지).

1. `getEpochInfo({commitment:"confirmed"})` **한 응답**의 `blockHeight > last_valid_block_height`. 같은 응답의 `absoluteSlot`을 `s`로 둔다(높이와 슬롯을 따로 묻지 않는다).
2. 그 뒤 `getSignatureStatuses([sig], {searchTransactionHistory:true})`의 값이 `null`이고 그 응답의 `context.slot ≥ s`(1과 같거나 더 앞선 RPC 시점에서 본 null만 인정한다. 뒤처진 노드의 null은 무시 — 대기가 아니라 응답 일관성 검사다).

- 2에서 null이 아니면(슬롯과 무관하게) 위 전이표대로 처리한다(`confirmed`/`finalized` → `Landed`/`FailedOnChain`, `processed` → 처리 중).
- **새 블록해시로 다시 서명**(새 intent·새 승인)은 `Expired` 뒤에만 할 수 있다. 높이 ≤ lvbh인 동안에는 레코드가 `Pending`이라 (클러스터, from)의 새 전송이 막히고(§13.1-1, D20) 재서명은 제공하지 않는다(`may_resign` = 높이 > lvbh).
- **그 전에는 기다리게 하지 않는다**: 보내기 결과 화면과 보내기 화면의 진행 중 안내에 "지금 다시 전송" 버튼을 둔다. 저널에 기록한 **같은 서명 거래**를 즉시 다시 보낸다(§14.2 표). 서명이 같으므로 몇 번 보내도 한 번만 처리되어 두 번 지불될 수 없다. 루프 정지(클러스터 불일치, 종결 상태 저장 중) 중에는 보이지 않는다.
- lvbh 자체는 서명 직전에 `h + 100 ≤ lvbh ≤ h + 300`으로 검사했다(§13.1-5).
- RPC 하나가 1·2를 위조해 만드는 이중 지불은 spec.md §2.2 비목표다(D32: 설정한 RPC를 신뢰한다).
- `Expired`·`FailedOnChain` 화면의 "다시 보내기"는 같은 입력으로 1단계(§13.1)를 새로 시작한다: 새 intent id, 새 미리보기, **새 승인**. 이전 승인·intent를 재사용하지 않는다. 저널은 언제나 첫 전송 전에 기록한다(§14.2).

## 15. 클러스터 고정과 RPC

### 15.1 엔드포인트와 제네시스

| 클러스터 | 네트워크 ID | QuickNode 템플릿 (D13, 서브도메인은 구현 시 대시보드와 대조) | 알케미 템플릿 | genesis hash |
|---|---|---|---|---|
| mainnet | `solana:mainnet` | `https://<이름>.solana-mainnet.quiknode.pro/<토큰>/` | `https://solana-mainnet.g.alchemy.com/v2/<KEY>` | `5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d` |
| devnet | `solana:devnet` | `https://<이름>.solana-devnet.quiknode.pro/<토큰>/` | `https://solana-devnet.g.alchemy.com/v2/<KEY>` | `EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG` |

- 엔드포인트 = `apikeys.dpapi`(DPAPI, spec.md §4.3)에 저장한 그 클러스터의 HTTPS JSON-RPC URL 하나(항목 `rpc:solana:mainnet`·`rpc:solana:devnet`, [04] §6.3, D13). 공급자를 가정하지 않는다: 위 템플릿(QuickNode 멀티체인·알케미)으로 만들거나 직접 입력하며, 템플릿으로 만든 URL도 클러스터별로 덮어쓸 수 있다. 사용자의 현재 공급자는 QuickNode다. 엔드포인트가 없으면 Solana RPC 호출을 하지 않고 미리보기를 시작하지 않는다(설정 → 네트워크 안내). URL 전체를 비밀로 보므로 평문 `settings.json`에는 두지 않는다([04] §6.1). 제네시스 고정은 공급자·URL과 무관하게 같다.
- `getGenesisHash`를 미리보기 시작, 서명 직전, `Pending` 재개 때마다 호출해 선택한 클러스터 값과 비교한다. 다르면 `ClusterMismatch`로 중단한다(Solana 트랜잭션에는 체인 ID가 없고 블록해시만 클러스터를 묶는다). 엔드포인트 URL을 바꾸면 그 클러스터의 `Pending` 레코드마다 세대 번호를 올리고 제네시스를 다시 확인한다. URL을 바꾸기 전에 시작한 라운드의 결과(제네시스 확인 성공·불일치, 상태 판정)는 끝나도 버리고 새 라운드를 바로 시작한다.
- devnet 시험은 mainnet과 다른 계정 인덱스를 쓰도록 권고한다(운영 권고, 강제 아님).
- URL에 토큰이 들어가므로 로그·오류 메시지에 URL을 남기지 않는다(D13·D28).
- 개발 중 실서비스 프로브는 D13대로 저장소 밖 `%USERPROFILE%\.yw-dev\rpc.json`(또는 환경 변수 `YW_RPC_JSON`이 가리키는 파일)의 `"solana:mainnet"`·`"solana:devnet"` 키에서 URL을 읽고, URL·토큰을 출력·로그에 남기지 않는다([09](09-testing.md)).

### 15.2 메서드(JSON-RPC 2.0, POST, 요청마다 증가하는 `id`를 응답과 대조)

| 메서드 | params | 사용 | 신뢰 | CU(알케미 기준 참고) |
|---|---|---|---|---|
| `getGenesisHash` | `[]` | §15.1 | 결정(불일치 시 중단) | 10 |
| `getLatestBlockhash` | `[{"commitment":"confirmed"}]` → `{blockhash, lastValidBlockHeight}` | 미리보기·서명 | 블록해시는 수신자·금액을 바꿀 수 없음. lvbh는 §13.1-5 범위 검사 | 20 |
| `getBlockHeight` | `[{"commitment":"confirmed"}]` | 범위 검사(§13.1-5) | lvbh 범위만 | 20 |
| `getEpochInfo` | `[{"commitment":"confirmed"}]` → `{blockHeight, absoluteSlot, …}` | 만료 증명(§14.3-1, 높이·슬롯을 한 응답에서) | §14.3-2 슬롯 대조와 함께 | 참고 |
| `getBalance` | `[addr, {"commitment":"confirmed"}]` → `{value}` | 잔액·사전 검사 | 참고 | 10 |
| `getAccountInfo` | `[addr, {"encoding":"base64","commitment":"confirmed","dataSlice":{"offset":0,"length":0}}]`(받는 주소), mint·토큰 계정(파생 ATA)은 dataSlice 없이 base64(§15.4). 잔액도 이것뿐이다: `getTokenAccountsByOwner`·`jsonParsed`는 쓰지 않는다 | §12.2, §15.4, S10 토큰 잔액 | 참고(차단 방향만) | 10 |
| `getMinimumBalanceForRentExemption` | `[0 \| 165, {"commitment":"confirmed"}]` | §11 | 참고 + 범위 검사 | 10 |
| `getRecentPrioritizationFees` | `[[writable 주소들]]`(SOL: from,to / SPL: from,from_ata,to_ata) | §10 | 참고 + 상한 | 10 |
| `getFeeForMessage` | `[base64(message), {"commitment":"confirmed"}]` → `{value: u64\|null}` | §10 교차 확인 | 참고(불일치는 차단 방향) | 20 |
| `simulateTransaction` | `[base64(tx), {"encoding":"base64","sigVerify":false,"replaceRecentBlockhash":true,"commitment":"confirmed"}]` | 참고 표시 | 참고(D27) | 20 |
| `sendTransaction` | `[base64(tx), {"encoding":"base64","skipPreflight":false,"preflightCommitment":"confirmed","maxRetries":0}]` → 서명 base58 | 브로드캐스트 | 반환 서명은 로컬과 대조 | 20 |
| `getSignatureStatuses` | `[[sig_b58], {"searchTransactionHistory":bool}]` → `{context:{slot}, value:[null \| {slot, confirmations, err, confirmationStatus}]}` | §14 | `Landed` 판정 근거(RPC 의존, spec.md §2.2). 이력 조회는 `context.slot`도 읽는다(§14.3-2, 없으면 응답 오류) | 20 |

- 메서드·params는 Solana 표준 JSON-RPC이며 공급자와 무관하다. 호출 비용 단위는 공급자마다 다르다(알케미 CU, QuickNode 크레딧). 위 CU 열은 알케미 기준 참고값일 뿐이고, QuickNode 메서드별 크레딧은 이 문서에 고정하지 않는다(구현 시 QuickNode 요금 문서·대시보드로 확인). 설계는 호출 비용에 의존하지 않는다.
- base58 인코딩 요청은 쓰지 않는다(1,232바이트 제한 등). 항상 `"encoding":"base64"`.
- JSON 정수(lamports, slot, 블록 높이, fee)는 yw-json이 f64를 거치지 않고 u64로 파싱해야 한다. 음수·소수·지수·u64 초과는 응답 오류.
- `confirmations` 필드는 쓰지 않는다(Alpenglow 이후 의미 없음). `confirmationStatus`와 `err`만 본다.
- 응답의 알 수 없는 필드는 무시한다. 필수 필드가 없거나 타입이 다르면 `RpcAnomaly`.
- TLS·URL·응답 크기는 [01] §7.4 `http`, 호출당 시간 제한(10 s)은 [03] §1.4와 같다.

### 15.3 오류 분류(표시·`terminal_err` 코드)

`1` 수수료 잔액 부족(`"InsufficientFundsForFee"`), `2` rent 부족(`{"InsufficientFundsForRent":…}`), `3` 계정 없음(`"AccountNotFound"`), `4` System 명령 실패(`{"InstructionError":[i,…]}`, i가 System 명령), `5` 토큰·ATA 명령 실패(같은 형식), `6` CU 한도 초과(`InstructionError`의 `ComputationalBudgetExceeded`), `7` 블록해시 없음(일시, `"BlockhashNotFound"`), `8` 이미 처리됨(`"AlreadyProcessed"`), `0xFFFF` 그 밖 전부. 분류는 `err` JSON 구조로만 하고 문자열 메시지는 쓰지 않는다.

### 15.4 SPL 계정 데이터(v1.1, 참고 + 교차 확인)

- 조회: `getAccountInfo(addr, {"encoding":"base64","commitment":"confirmed"})`(dataSlice 없음, `jsonParsed` 쓰지 않음). `data`는 `["<base64>", "base64"]`여야 하고 엄격 base64(RFC 4648 패딩, 정규 비트, 4,096바이트 상한)로 디코딩한다(yw-app `sol::rpc::account_data`). 어긋나면 응답 오류(`Malformed`).
- mint(82바이트, yw-core `sol::token::parse_mint`·`check_mint`): owner = 고정 토큰 프로그램, `data.len == 82`, `COption` 태그 0/1, `data[44] == 고정 decimals`, `data[45] == 1`(initialized). 없음·불일치 → `MintMismatch` → `RpcAnomaly`(승인 불가). 메시지의 decimals는 언제나 허용 목록 값이다(RPC가 9라고 해도 6으로 서명하지 않고 막을 뿐).
- 토큰 계정(165바이트, `parse_token_account`): `mint = [0..32]`, `owner = [32..64]`, `amount = u64 LE [64..72]`, delegate `COption` `[72..108]`, `state = [108]`(0 미초기화, 1 정상, 2 동결, 그 밖 거부), is_native `COption<u64>` `[109..121]`, close authority `COption` `[129..165]`. `classify_holding(entry, wallet, account) -> TokenHolding`: null → `Missing`, 프로그램 = 고정 토큰 프로그램·165바이트·mint 일치·owner = wallet·is_native 없음·state 1 → `Active(amount)`, state 2 → `Frozen(amount)`, 그 밖 → `Invalid`.
- 미리보기: `from_ata` `Missing` → `NoTokenAccount`(§11), `Frozen` → `TokenAccountFrozen`, `Invalid` → `RpcAnomaly`. `to_ata` `Missing` → 생성(rent165), `Active` → 있음, `Frozen`·`Invalid` → `RecipientTokenAccountUnusable`.
- 잔액(S10 토큰 카드·복구 스캔): 허용 목록 토큰마다 파생 ATA의 `classify_holding` 결과만 보인다(`Missing`은 0과 "토큰 계정 없음", `Invalid`는 "확인할 수 없음").

## 16. 프로토콜 사실 (구현 시 재확인)

M7 착수 때 공식 문서로 다시 확인하고, 바뀌었으면 해당 상수·규칙을 고친다.

| 사실 (2026-10 기준) | 이 문서의 영향 |
|---|---|
| SIMD-0525: 슬롯 200 ms(2026-10-09 완전 적용). 최근 블록해시 유효 150블록 ≈ 30초 | 승인 후 블록해시 조회·즉시 서명(§13). 만료는 높이로만 판정(§14.3, 시계 하한 없음) |
| Alpenglow(2026-10-21): `confirmed`와 `finalized`가 같고 약 150 ms. `confirmed`는 이후 제거 예정, `confirmations`는 최종 전 0·최종 후 null | 모든 조회 `confirmed`(D32: `confirmed`가 최종). `confirmationStatus`가 `confirmed`·`finalized`면 종결. `confirmed`가 제거되면 같은 값인 `finalized`로 바꾼다 |
| SIMD-0437: rent 단계적 인하(현재 5,080 lamports/byte, 2026-11 이후 696 예상) | rent 매번 조회(§11), 범위 상한만 고정 |
| durable nonce 폐지 진행(대체안 확정 후 약 6개월) | 사용하지 않음 |
| v1 트랜잭션 형식(0x81, 4,096바이트; SIMD-0296/0385) 2026-09-15 활성화. legacy·v0는 유지 | legacy만 사용, 파서가 0x80·0x81 거부 |
| SIMD-0553(기본 수수료 공식 변경) 거버넌스 대기 | `SOL_BASE_FEE_LAMPORTS_PER_SIG`, `getFeeForMessage` 교차 확인(§10) |
| 기본 수수료 5,000 lamports/서명, 우선 수수료 = 요청 CU 한도 × 가격 | §10 |
| 템플릿 CU 사용량(System·ComputeBudget 명령 각 150 CU 예상; ATA 생성은 받는 ATA bump에 따라 실패한 bump마다 +1,500 CU) | §10 측정 절차 |
| 설정한 공급자(현재 QuickNode; 공급자·엔드포인트를 바꾸면 그 공급자로 다시 확인, mainnet·devnet 각각): `getSignatureStatuses`의 `searchTransactionHistory:true` 지원 범위, `getFeeForMessage`에 우선 수수료 포함 여부, `sendTransaction`의 `maxRetries:0` 준수, `getAccountInfo` dataSlice 지원. QuickNode 템플릿 서브도메인(`solana-mainnet`·`solana-devnet`, §15.1)은 대시보드와 대조. **2026-10-27 실측(`docs/acceptance/m7-live-20261027.md`)**: 이력 검색 동작(mainnet 약 5일·devnet 약 31일 전 서명이 `true`에서만 finalized), `getFeeForMessage`는 우선 수수료 포함(600 CU × 1,000,000 µL → 5,600), dataSlice 0/0 동작, rent0 650,240·rent165 1,488,440(5,080 lamports/byte 계열). `maxRetries:0`은 전송 없이 확인할 수 없어 M7-4 devnet E2E에서 본다. **2026-10-28 v1.1 실측(`docs/acceptance/m7-spl-20261028.md`)**: rent165 1,488,440(양 클러스터), T_SPL `getFeeForMessage` 우선 수수료 포함(60,000 CU × 1,000 µL → 5,060), base64 `getAccountInfo`로 mint·ATA 데이터 반환, T_SPL 시뮬레이션 CU는 위 §10 bump 모델과 일치 | 실패 시: 이력 검색이 안 되면 §14.3-2를 `searchTransactionHistory:false`로 하고, 사용자가 탐색기에서 미처리를 확인했다는 체크를 추가로 요구한다(시계 대기는 두지 않는다, D32). 우선 수수료 미포함이면 §10 비교를 `rpc_fee + priority == max_fee`로 바꾼다 |

## 17. 테스트 벡터와 수락 테스트

### 17.1 키

- SLIP-0010 Ed25519 벡터 1·2 전체([02] §11.5, [09] §3.9), 예: seed `000102…0f`, `m/0'/1'/2'/2'/1000000000'` → 개인키 `8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793`, 공개키 `003c24da049451555d51a7014a37337aa4e12d41e485abccfa46b47dfb2af54b7a`. 비hardened 성분 → 오류.
- RFC 8032 §7.1 TEST 1·2·3·1024·SHA(abc): 비밀→공개, 서명 바이트 일치. TEST 1: secret `9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60` → public `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`, sig(빈 메시지) `e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b`.
- 니모닉 → 주소(passphrase 없음). 12단어 열과 24단어 `/0'/0'`은 독립 구현·qntx/kobe·Keystone·Ledger Live·fearless-iOS로 교차 확인된 값, 나머지 24단어 값은 SLIP-0010·RFC 8032 벡터를 통과한 독립 구현의 결과다.

| 경로 (`SolKeySource`) | `abandon`×11 `about` | `abandon`×23 `art` |
|---|---|---|
| `m/44'/501'/0'/0'` (1, i=0) | `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk` | `3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx` |
| `m/44'/501'/1'/0'` (1, i=1) | `Hh8QwFUA6MtVu1qAoq12ucvFHNwCcVTV7hpWjeY1Hztb` | `5frqxtii9LeGq2bz3dSNokvZcEooF483MzeU24JrhcTA` |
| `m/44'/501'/2'/0'` (1, i=2) | `7WktogJEd2wQ9eH2oWusmcoFTgeYi6rS632UviTBJ2jm` | `3SuKj3MZU9dMZ9oR1R7afttihZFkWpfUmduuv9rmfMa1` |
| `m/44'/501'/0'` (2, i=0) | `GjJyeC1r2RgkuoCWMyPYkCWSGSGLcz266EaAkLA27AhL` | `4BZp4ci5rhNYqbayj1uppeTas1osK2Q4b74x7UENC5Hd` |
| `m/44'/501'/1'` (2, i=1) | `ANf3TEKFL6jPWjzkndo4CbnNdUNkBk4KHPggJs2nu8Xi` | `7bDLWB6YMdFHVRonYoTzikCFSoC5Ls4SKxbnydpLTPCM` |
| `m/44'/501'` (3) | `D2PPQSYFe83nDzk96FqGumVU8JA7J8vj2Rhjc2oXzEi5` | `BkWizA4ezeYB3jbixzPnzj6r2QuGekZXXFQHstDJE8wK` |
| seed[0..32] (4) | `EHqmfkN89RJ7Y33CXM6uCzhVeuywHoJXZZLszBHHZy7o` | `31fsSBAugfgtWp4WZLgr1D9TBkgiS13d5eK3GWBQwRct` |

`HAgk14…`의 공개키 hex = `f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7`.

- API 음성 테스트: `SigningKey::from_keypair_bytes`에 공개 절반이 다른 64바이트를 넣으면 실패(라이브러리 성질 확인용, 출하 코드는 이 함수를 쓰지 않음). 서명 후 `verify_strict` 실패 주입 → `SolSignError`.

### 17.2 인코딩

- base58: Bitcoin Core `src/test/data/base58_encode_decode.json`(원시, 체크섬 없음) 전체 + §8.1·§12.1 주소의 왕복 + 경계(32바이트 0 → 32자 `1…1`, 0xFF×32 → `JEKNVnkbo3jma5nREBBJCDoXFVeKkD56V3xKrvRmWxFG`, `00 ‖ FF×31` → `14uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofL`, `01 ‖ 00×31` → 43자 `4uQeVj5tqViQh7yWWGStvkEG1Zmhx6uasJtWCJziofM`). 음성: 길이 31·45, `0OIl`, 공백, 비정규(선행 `1` 누락·추가), 33바이트로 디코딩되는 44자.
- compact-u16: `0→00`, `0x7f→7f`, `0x80→80 01`, `0xff→ff 01`, `0x100→80 02`, `0x3fff→ff 7f`, `0x4000→80 80 01`, `0x7fff→ff ff 01`, `0xffff→ff ff 03`. 음성: `80 00`, `80 80 00`, `ff ff 04`, `80 80 80`, `80`(잘림).

### 17.3 메시지·서명

- solana-sdk `transaction/src/lib.rs` `test_sdk_serialize`(범용 인코더 + 결정적 서명): keypair 앞 32바이트 `ff6524187c17a71584cc9b05b93a794b9ce374c1d7268e16080ee5ef775d05da`, 206바이트 기대값

```text
01788aa2b93bd1f19d479d4a830457361c26b4de52403e3d3e162e11cbbb883e2b0b26eb11ef52f08b82d9e3d609f28ddf5e1db86e3e
2057893f8b64dd148904050100010324649efc21a161b93e5963c3faf9bbbdab76f15af80e44dbe73e9d058e1bd27501010104050607
0809090909090909090909090909090909080706050401010102020204050607080901010101010101010101010101010908070605
040202020000000000000000000000000000000000000000000000000000000000000000010202000103010203
```

- T_SOL 골든(자체 생성, 위 sdk 벡터를 재현한 독립 구현으로 계산; M7 착수 시 `tools/sol-oracle/`(§4)의 solana-sdk `Message::new(&[set_compute_unit_limit(450), set_compute_unit_price(1000), transfer(from,to,1_000_000)], Some(&from))`로 1회 교차 확인 후 고정): from = abandon/about `m/44'/501'/0'/0'`, to = `Hh8Qw…`, lamports 1,000,000, cu_limit 450, cu_price 1,000, 블록해시 `07`×32(`US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx`), max_fee 5,001.

```text
message (202B, 필드 순서대로 이어 붙인다)
header,n_keys  01000204
from           f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7
to             f8029acf5cbcbdd5ac46ec147f3b78a3df6e5022ef0411db2bab650d329a4cd4
System         0000000000000000000000000000000000000000000000000000000000000000
ComputeBudget  0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000
blockhash      0707070707070707070707070707070707070707070707070707070707070707
n_ix           03
ix0            03000502c2010000
ix1            03000903e803000000000000
ix2            020200010c0200000040420f0000000000
signature      5DpEKELbVjwDHeTJzKG8EoYQdahDegeR6onWnyBqhTBiz4b1k1YMEKutLioNjVgc1Z1wTZuFLDLW2Y6vU4cu2k2u
SHA-256(message)  09337675ae070066af49c172b5367e9007f506407d5be1bd73b846972d1edcd4
SHA-256(tx 267B)  7ecb80478f954ea1a3625bf0ee1776ff0991c3f8e6ceb33c6f7b198f3929f788
```

- T_SPL 골든(같은 조건, USDC, amount 1,000,000, decimals 6, cu_limit 40,000): from_ata `5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt`(bump 254), to_ata `8X8ts1CnpZmtqApE2rREA97xEJuSRcomPGVcMFdS2cgY`(bump 255). 키 순서 `[HAgk14…, 5N3f1…, 8X8ts…, 111…1, ComputeBudget…, Tokenkeg…, ATokenGP…, EPjFW…, Hh8Qw…]`. 명령 `(4, [], 02409c0000)`, `(4, [], 03e803000000000000)`, `(6, [0,2,8,7,3,5], 01)`, `(5, [1,7,2,0], 0c40420f000000000006)`. message 372B SHA-256 `db305edc2a3c1a3bcde2ac525684340d7a56a8e816c41e86d8231f795ca6d9e8`, signature `5iVhrE6aU2jjv4CyoJKYkqAd3xpPcdPynaGWW32yt6daMUZm1jAdVWq4aSyFNpB4eyU2SGhB6p7tB8eLrMdoGt8L`, tx 437B SHA-256 `46315e8842900c9dc7f7fab61f0ed80b71ff5c6b622bdf157b6986acccf95e7f`, max_fee 5,040. 교차 확인 방법은 T_SOL과 같다(spl-associated-token-account·spl-token 인터페이스 크레이트를 `tools/sol-oracle/`에서). v1.1 구현(2026-10-28)이 message·서명·tx 해시와 키 순서·명령을 그대로 재현했다(`sol::tests_spl::t_spl_golden`). 서명이 템플릿 한도를 강제하므로(§9-8) 키 볼트 서명 테스트(`spl_signing_matches_the_reference_key_and_journals_526_bytes`)는 60,000 CU의 같은 거래를 같은 키의 직접 서명과 대조하고, 40,000 CU 골든은 승인 요청에서 거부됨을 확인한다.
- System Transfer 42 lamports data = `02 00 00 00 2a 00 00 00 00 00 00 00`.
- PDA(solana-sdk `test_create_program_address`, program `BPFLoaderUpgradeab1e11111111111111111111111`): seeds `["", [1]]` → `BwqrghZA2htAcqq8dzP1WDAhTXYTYWj7CHxF5j7TDBAe`; `["☉"(UTF-8), [0]]` → `13yWmRpaTR4r5nAktwLqMpRNr28tnVUZw26rTvPSSB19`; `["Talking","Squirrels"]` → `2fnQrngrQT4SeLcdToJAD96phoEjNL2man2kfRLCASVk`; `[SeedPubey1111111111111111111111111111111111 원시 32B, [1]]` → `976ymqVnfE32QFe6NfGDctSvVa36LWnvYxhU6G2232YL`.
- ATA: `HAgk14…`의 USDC ATA = `5N3f1tj9v1vc5TUZ8S7mCAnVmjVKrfnzXWhxLaxyZAgt`, bump 254(fearless-iOS 테스트와 일치).
- 곡선 분류: `HAgk14…` on-curve, 위 ATA off-curve, `111…1` small-order, ComputeBudget off-curve, Tokenkeg on-curve(→ 금지 주소 표로 차단).

### 17.4 음성·상태 기계 테스트(자동, yw-core)

- 파서 거부: 명령 추가·삭제·순서 변경, 프로그램 ID 변경, ComputeBudget 중복, header 값 변경, 키 중복, 그룹 정렬 위반, 0x80·0x81 접두, 서명 수 0·2, 남는 바이트, amount 0, cu_limit 0·1_400_001, 허용 목록 밖 mint, decimals 불일치, ATA 불일치, 1바이트 변조 전수(T_SOL 202바이트 각 비트 반전 → 거부되거나 다른 core로 파싱되어 동일성 검사 실패). T_SPL(v1.1): 위 항목 + ATA `Create`(data `00`)·TransferChecked 대신 Transfer(태그 3)·계정 목록 어긋남(payer·owner ≠ 0, 목적지 ≠ 생성 ATA, mint 불일치, System·Token 자리)·Token-2022 프로그램·쓰기 그룹/읽기 그룹 순서·역할 바꿈·곡선 밖·small-order 받는 지갑(`RecipientOffCurve`)·다른 클러스터의 mint·자기 자신(키 중복), 372바이트 각 비트 반전.
- 재인코딩 동일성: 승인한 core와 다른 core → `EncodingMismatch`.
- **이중 서명 방지**(M7 완료 조건): 가짜 RPC로 ① 상태 null·높이 ≤ lvbh가 계속되면(10분이 지나도) `Pending` 유지·재서명 없음, 같은 바이트만 재전송 ② 이력 `context.slot`이 높이 응답의 슬롯보다 뒤면 `Pending` 유지 ③ `confirmed` 높이 > lvbh·이력 null인 라운드 **한 번**이면 서명 1초 뒤라도(벽시계가 서명 시각보다 뒤여도) 바로 `Expired`, 재전송은 새 intent·새 승인 없이는 불가 ③′ 만료 전 "지금 다시 전송"(`LoopState::send_now`)은 주기를 기다리지 않고 같은 바이트·같은 파라미터로 1회 전송(결정적 preflight 오류로 멈춘 뒤에도) ④ 같은 승인 두 번 사용 불가(`Approved` 복제 불가 + 두 번째 `consume` 오류), `consumed_at_ms` + 20 s 초과 시 서명 거부 ⑤ 같은 intent_hash 저널 레코드가 있으면 `AlreadySigned` ⑥ 이력 검색에서 non-null(지연 착지)이면 `Landed`/`FailedOnChain`, 상태 `confirmed`(1 확인)도 `Landed`, `processed`는 처리 중 ⑦ preflight 결정적 오류 후 재전송 중지·`Pending` 유지 ⑧ 전송 응답 서명 불일치 → `RpcAnomaly`, 상태 유지.
- 저널: 컨테이너 entry(`kind = 0x02`) 왕복, body = 89 + tx_len(T_SOL 356 B·T_SPL 526 B), `body_len ≠ 89 + tx_len`·`record_kind ≠ 0x02`·알 수 없는 `state`·변조된 tx 바이트·서명 → 본문 오류(SOL 보내기만 꺼짐, 바이트 보존, 전송 안 함), SOL 레코드 64개 상한 → 종결 정리 후에도 넘으면 `JournalError::Full`·서명 0회, 저널 쓰기 실패 주입 → 전송 0회. `ActivityEntry` 변환: §14.1 표의 각 필드·상태 3종.
- 승인 만료: 표시 후 120 s → `Expired`로 닫히고 보내기 화면 입력 유지, 재검토는 새 intent id·새 승인(만료된 `ApprovalId`의 `consume` 실패).
- 수수료·rent: 경계값(rent0 정확히, `r = rent0 − 1`, 보내기 최대 r=0), `rpc_fee` 큼/작음/같음 × 일반/보내기 최대, CU 가격 클램프, u128 중간값.
- 수신자: §12.1 각 행, lookalike(앞 3자·뒤 3자·둘 다·2자는 미해당). `flags` 비트 ↔ §13.3 경고 등급, 고위험이 있을 때만 `ack_required`.
- 승인 모델: SOL `ApprovalRequest` digest 입력 1비트 변경 → digest 변경([03] §11.4 방식), 표에 없는 `FieldKey` 없음.
- 클러스터: 제네시스 불일치 → 미리보기·서명·재개 모두 중단.
- SPL(v1.1, yw-app 가짜 RPC `tests/sol_spl_flow.rs`): 미리보기 호출 순서(수신자 dataSlice → mint·from_ata·to_ata 전체 데이터 → rent0·rent165 → 우선 수수료(from·from_ata·to_ata)), RPC decimals 거짓(9) → `RpcAnomaly`이지만 메시지 decimals 6 유지, mint 없음·다른 owner·81바이트 → `RpcAnomaly`, `NoTokenAccount`·`InsufficientTokens`·`SolReserve` 경계(정확히 필요액 통과, 1 lamport 부족 차단), 기존 ATA는 rent 0, 동결(`TokenAccountFrozen`·`RecipientTokenAccountUnusable`), from_ata 자리의 다른 소유자 계정 → `RpcAnomaly`, rent165 범위, SPL 보내기 최대 = 토큰 전액(RPC 수수료가 낮아도 허용), 잔액은 허용 목록 ATA만 조회(모르는 토큰은 조회조차 안 함, ATA 자리의 다른 mint → `Invalid`), 브로드캐스트 `InstructionError`[3] → 코드 5, 스캔에서 토큰만 있는 계정은 빈 계정이 아님. 저널: T_SPL 본문 526 B 왕복, `cluster` 바꿈·decimals 바이트 변조 → `NotAllowlisted`, 금액 변조 → 서명 오류, 활동 `asset` = mint. 키 작업자 경로(`tests/sol_journal_worker.rs`) devnet USDC 서명 → 437 B, 526 B 본문, `FailedOnChain` → 활동.

### 17.5 퍼징(cargo-fuzz, [09] §2.4)

`base58_decode_32`, `shortvec::decode`, `parse_transaction`(성공 시 재인코딩 동일성 단언), `journal::sol` 본문 디코더(§14.1).

### 17.6 E2E(devnet, 체크리스트 1회)

1. 별도 계정 인덱스로 devnet 계정 준비(외부 faucet). 2. 새 주소에 rent0 미만 → 차단 확인, rent0 이상 → `Landed`. 3. 보내기 최대 → 보낸 계정 잔액 정확히 0. 4. 저널 기록 직후 앱 강제 종료(디버그 빌드 장애 주입 지점) → 재시작·잠금 해제 → 같은 서명으로 1회만 착지. 5. 서명 직후 네트워크 차단 → 복구(대기 시간 없음) → `Expired`(RPC 높이 > lvbh이고 이력에 없으면 바로) 또는 `Landed`, 그 전 재서명 없음. 만료 전에는 "지금 다시 전송"이 같은 서명 거래만 다시 보낸다. 6. 잘못된 클러스터(devnet 선택 + `solana:devnet` 엔드포인트(`rpc:solana:devnet`)에 mainnet URL) → 중단. 7. 복구 스캔: abandon 니모닉 시험 vault에서 §17.1 주소 표시 확인. 8. (v1.1) devnet USDC: 새 수신자(ATA 생성)·기존 ATA·토큰 보내기 최대·허용 목록 밖 토큰 숨김·곡선 밖 받는 주소 차단(수동 체크리스트 `docs/acceptance/m7-spl-20261028.md` M7-S). 9. CU 한도 측정(§10) 결과를 상수에 반영(T_SOL 2026-10-27, T_SPL 2026-10-28 완료).

## 18. 작업량 (집중 작업일, 테스트 포함)

- v1: SLIP-0010 연결·키 출처 5종·벡터 2–3 / ed25519-dalek 통합·키 소거·의존성 검사 갱신 2–3 / base58·주소 분류·PDA·퍼징 1–2 / 메시지 인코더·템플릿·엄격 파서·sdk 벡터·차등 확인 4–6 / 수수료·rent·보내기 최대 1–2 / Solana RPC·제네시스 고정 3–4 / 저널·브로드캐스트·만료 증명 3–5 / 승인 표시·주소록·중독 방지 3–5 / 복구 스캔 1–2 / devnet E2E·소액 mainnet 3–4. **합계 23–36일.**
- v1.1 SPL(USDC·USDT): ATA·T_SPL·계정 데이터 교차 확인·벡터 **+8–12일.**
- 프로토콜 변경 대응 여유로 20–30%를 더 잡는다.

## 19. dApp 연결: 소유 증명 전용 (2026-10-31, D25·D27)

dApp은 Solana 계정을 **연결**하고 **메시지에 서명**(Sign-In-With-Solana 포함)하게 할 수만 있다. 거래 서명·전송 요청은 받지 않는다(페이지 shim이 4200으로 거부, 와이어 메서드 없음 — [05] §2.13, §3.6). 연결·grant는 [05] §4.9, 승인 창은 [04] §3.

### 19.1 코어 (`yw_core::sol::msgsign`)
- `ApprovalKind::SolMessage = 0x21`(`sol_signMessage`), `SolSignIn = 0x22`(`sol_signIn`). origin은 사이트, `ChainRef::Solana { cluster, genesis = 고정 제네시스 }`(settings 클러스터), `AccountRef::Sol(public)`, `Signer::FromPayload`, `SigningPayload::SolMessage { source, public, message }`(digest 바이트 = transcript `"your-wallet/v3/sol-message"` v1: 출처 태그·인자(태그 8이면 그 뒤 니모닉 record id `push_bytes` 16, §3.5), 공개키, 메시지). 승인 digest·일회 소비·120 s 만료는 [03] §11 그대로.
- 서명(`sign_message(vault, approved)`): 종류·체인·계정·payload 일치 확인 → §19.2 규칙 재확인 → 표준 경로는 `with_ed25519_seed`, 가져온 키는 공개키로 `with_imported_ed25519_seed` → 파생 공개키 = 승인 계정 확인 → Ed25519로 **메시지 바이트 그대로** 서명 → `verify_strict`. 결과는 64바이트 서명.

### 19.2 서명할 수 없는 바이트 (차단, `M01`·`M02`)
- 길이 > 65,536 B.
- 레거시 또는 v0(`0x80`) 메시지로 파싱되는 바이트(헤더: 서명자 ≥ 1, 읽기 전용 서명자 < 서명자, 키 수 ≥ 서명자, 키·블록해시·명령(프로그램·계정 인덱스 < 전체 키 수)·v0 주소 조회 테이블), 또는 `shortvec(서명 수 n ≥ 1) ‖ 64n ‖ 메시지`(헤더 서명자 = n)인 서명된 거래. **앞부분만** 그렇게 파싱되고 뒤에 바이트가 남아도 같다(뒤 바이트로 차단을 피하지 못한다). → `M01` 차단 "Solana 거래로 해석되는 바이트입니다".
- 아직 모르는 메시지 버전: 첫 바이트가 `0x80`–`0xfe`(버전 플래그; `0xff`는 오프체인 도메인의 첫 바이트)이고 버퍼 **전체**가 유효한 UTF-8이 아니면 → `M01` 차단 "버전이 붙은 Solana 거래 메시지처럼 시작합니다"(`looks_like_versioned_message`). `가`처럼 멀티바이트 문자로 시작하는 UTF-8 텍스트는 해당하지 않는다.
- 오프체인 서명 도메인 `\xffsolana offchain`으로 시작하면 버전 0으로 파싱되어야 한다: `solana-sdk` 형식(`0 ‖ format ‖ len u16 LE ‖ message`) 또는 제안서 형식(`0 ‖ application domain 32 ‖ format ‖ 서명자 수 ≥ 1 ‖ 서명자 32×n ‖ len u16 LE ‖ message`), 길이가 정확히 맞고 형식 0(출력 가능 ASCII ≤ 1,212 B)·1(UTF-8 ≤ 1,212 B)·2(UTF-8). 실패 → `M02` 차단. 성공 → `M05` 정보 + `서명 방식` 필드, 본문 표시는 머리글을 뺀 메시지. 제안서 형식인데 서명자 목록에 이 계정이 없으면 `M02` 차단.

### 19.3 표시
제목 `[Solana mainnet] 메시지 서명 (소유 증명)` 또는 `[…] 로그인 요청 (SIWS)`. 필드: 요청 출처(origin 전체), 네트워크(클러스터), 서명 계정(라벨·경로·**전체 base58 주소**), (오프체인이면) 서명 방식, 메시지(텍스트 또는 hex), 바이트 수, (SIWS면) SIWS 필드. 경고: 항상 `M04` 정보 "소유 증명용 메시지 서명입니다 — 거래·송금에는 쓰이지 않습니다". 엄격 UTF-8이고 제어 문자(TAB·LF·CR 제외)가 없고 32바이트가 아니면 텍스트(숨은·방향 제어 문자는 `[U+XXXX]`로 바꾸고 `P02`), 그 밖은 hex + `P01`/`P04`(고위험) — `personal_sign`([03] §9.2)과 같은 규칙.

### 19.4 Sign-In-With-Solana
- 형식은 `@solana/wallet-standard-util` `createSignInMessageText`(2026-10-31 `anza-xyz/wallet-standard` 소스로 확인)와 바이트 단위로 같다: `${domain} wants you to sign in with your Solana account:\n${address}`, 설명이 있으면 `\n\n${statement}`, 필드가 있으면 `\n\n` + `URI: `·`Version: `·`Chain ID: `·`Nonce: `·`Issued At: `·`Expiration Time: `·`Not Before: `·`Request ID: `·`Resources:`(+ `- ${resource}` 줄)을 이 순서로 `\n` 연결. 빈 값은 쓰지 않는다. 지갑은 dApp이 주지 않은 필드를 더하지 않는다(`verifySignIn`은 입력에 없는 필드가 메시지에 있으면 실패한다). 예외: 필수인 `domain`(빠지면 origin의 `host[:port]`)과 `address`(빠지면 서명 계정).
- `sol_signIn` 입력 검증은 [05] §3.6(모르는 키 거부, 줄바꿈 등 제어 문자 거부). 앱이 텍스트를 만들고, `sol_signMessage`의 텍스트가 SIWS 첫 줄 표지를 가지면 같은 파서·검사를 적용한다(표지는 있는데 문법이 틀리면 `W07` 차단).
- 검사(`SiwsContext { origin, account, cluster, now }`): 도메인 ≠ 요청 사이트(호스트 다름, 명시 포트 ≠ 사이트 유효 포트, 사이트가 기본이 아닌 포트(`https://a.example:8443`, `http://localhost:5173`)인데 도메인에 포트가 없음, scheme·userinfo·경로 포함) → `W01` 차단. 포트 없는 도메인은 기본 포트의 사이트만 가리킨다. 주소 ≠ 서명 계정 → `W02` 차단. `Chain ID`가 있고 settings 클러스터가 아님(`mainnet`·`mainnet-beta`·`devnet`, `solana:` 접두 허용) → `W03` 차단. `Expiration Time` ≤ 지금 → `W04` 차단. `Not Before` > 지금 → `W05` 주의. `Issued At`이 지금과 10분 넘게 다름 → `W06` 고위험. `Version` ≠ `1`, 시각 형식 오류(RFC 3339, SIWE 파서 `parse_date_time` 재사용) → `W07` 차단. 경고가 없으면 `W08` 정보.
- 결과: `{ publicKey, signature, signedMessage }` — `signedMessage`는 앱이 만든 바이트 그대로.

### 19.5 시험 (자동)
RFC 8032 벡터 1·2를 메시지 서명기로 재현, 레거시·v0·서명된 거래 탐지(뒤 바이트가 붙은 것 포함)와 오탐 없음, 버전 접두 `0x80`–`0xfe` 전부 차단·UTF-8 텍스트 허용, 오프체인 두 형식·깨진 머리글, SIWS 도메인 포트 규칙, SIWS 텍스트 레이아웃(전 필드·최소·설명 없음)·파서 왕복·W01–W08, 승인 수준(텍스트 Info, 이진 High, 거래 Blocked). fuzz-lite `fuzz_lite_sol_msgsign`(`crates/yw-core/tests/msgsign_fuzz_lite.rs`: 탐지·`signable`·승인 창 차단 일치, 뒤 바이트로 차단이 풀리지 않음, 오프체인 파서, SIWS 파서 왕복)과 `fuzz_lite_base64`, 매개변수·grant 파서는 `fuzz_lite_chain_params`(yw-app). 디스패처·확장 shim 시험은 [05] §10, 수동 체크리스트는 `docs/acceptance/msgsign-20261031.md`.

## 미결 사항

미결 1–3(단일 RPC 만료 증명, D5 문구, 작업량)은 spec.md 개정(§2.2 비목표, D5, §5 M7 작업량)으로 해소되어 삭제했다. 미결 6(다른 문서 등록 항목)은 모두 반영되어 삭제했다: [03] §10.1·§11(`ChainRef::Solana` 태그 2, `AccountRef::Sol`, `ApprovalKind::SolTransfer = 0x20`, `SigningPayload::SolTransfer`, `FieldKey` `0x0501`–`0x0509`, `RuleId` 상위 바이트 `'L'`), [02] §3.5·§10.3(`SolKeySource`, `with_ed25519_seed`, `sol_public_keys`), [04] §3.2–§3.4(필드 라벨, D16 단일 체크박스), [04] §6.3(`rpc:solana:<cluster>`). 다른 문서가 번호로 참조하므로 4·5번 번호를 유지한다.

4. **USDT devnet 시험 불가(구현 시 확인).** D25의 v1.1 허용 목록 중 USDT는 devnet 공식 mint를 확인하지 못했다. devnet USDC는 2026-10-27 확인했다(§8.3). 대안: v1.1 devnet E2E는 USDC로만 하고 USDT는 M9 메인넷 소액 체크리스트에서 확인한다.
5. **CU 한도 상수(해소).** `SOL_TRANSFER_CU_LIMIT = 600`은 2026-10-27 §10 절차로 확정했다(최대 450). `SPL_TRANSFER_CU_LIMIT = 60_000`은 2026-10-28 §10의 bump 모델로 확정했다(새 ATA c255 13,923–13,932 + 1,500 × (255 − bump), 기존 ATA 4,842; bump ≥ 225 전부). 번호는 다른 문서가 참조하므로 남긴다.
