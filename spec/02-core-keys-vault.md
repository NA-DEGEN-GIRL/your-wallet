# 키·니모닉·vault

상위 문서: [spec.md](../spec.md)

- 범위: yw-core의 엔트로피, BIP39, BIP32, SLIP-0010, vault v3·사이드카 바이트 형식, 비밀번호 규칙, 잠금 상태 기계, 메모리 처리, 생성·가져오기·백업 확인, 비밀 표시.
- 마일스톤: M1(이 문서 전체, 단 journal 컨테이너 코덱·`JournalError`는 M4, SLIP-0010·`SolKeySource`는 M7, BTC 경로 사용·CKDpub(`AccountXpub`)은 M8). 판정 기준은 [09](09-testing.md) §5.2.
- 이 문서의 모든 코드는 `yw-core`(unsafe·OS 호출 금지, `getrandom` 예외)에 있다. 파일 입출력과 VirtualLock은 yw-app이 yw-win으로 수행하고, 이 문서는 그 계약(trait)만 정한다.

## 0. 모듈과 공통 규칙

모듈 이름과 배치는 [01](01-repo-build.md) §2.2(D31)를 따른다.

| 모듈 | 내용 |
|---|---|
| `yw_core::entropy` | `RandomSource`(crate 내부 trait), `OsRandom`, `secp_context`; [01] §2.2의 `fill_random`·`random_nonzero_id`·`random_below`는 이 trait 위의 함수(오류는 `KeyError::RandomnessUnavailable`) |
| `yw_core::bip39` (`src/bip39/mod.rs` + `english.txt`) | 단어 목록, `Mnemonic`, `WordCount`, 시드 |
| `yw_core::bip32` | `Bip32Path`, `XPriv`, CKDpriv, `AccountXpub`·`derive_public_child`(CKDpub, §3.1, M8), `preview_evm_address`(§10.3); `bip32::path`(`AccountIndex`, 체인별 경로 생성기), `bip32::xkey`(xprv/xpub 문자열, §3.4) |
| `yw_core::slip10` | `Slip10Path`, Ed25519 파생, `SolKeySource`(§3.5) (M7) |
| `yw_core::password` | `VaultPassword`, `Bip39Passphrase` (D8) |
| `yw_core::codec::base58` | base58·base58check (D6; [07](07-solana.md)·[08](08-bitcoin.md)과 공유, M1에서 먼저 구현하므로 [01] §2.2 `codec`은 M1부터 있다) |
| `yw_core::codec::wif` | Bitcoin WIF 디코드·인코드(§8.4) |
| `yw_core::keyimport` | 가져온 개인키의 형식 파서(`ImportKey::parse`), 주소 미리보기(`ImportPreview`). Bitcoin 키의 주소 형식은 계정과 같은 `btc::ScriptType`이고 출력·주소도 같은 코드(`btc::account::kind_for_key`, BIP86 tweak `btc::taproot`)로 계산한다(§8.4, [08] §3.5) |
| `yw_core::vault` | KDF, v3 헤더·payload 코덱, 사이드카, `VaultStorage`, `LockedSlot`, `Vault` 상태 기계, 백업 확인 |
| `yw_core::journal` (M4) | journal 평문 컨테이너 코덱(§5.4), `JournalError`(§10.2). 체인별 레코드 본문은 EVM `journal::evm`([03](03-evm.md) §5.1), SOL [07] §14.1, BTC [08] §12.4 |

공통 규칙(반드시):

- 비밀 타입(`Mnemonic`, `Bip39Passphrase`, `VaultPassword`, `XPriv`, `XKeyParts`, DEK·KEK·시드 버퍼)은 `Clone`·`Copy`·`Display`를 구현하지 않고, `Debug`는 `"<타입명>([REDACTED])"`만 출력한다.
- 비밀 버퍼는 `zeroize::Zeroizing`에 담고, 크기가 정해진 값은 고정 배열(`[u8; N]`)을 쓴다. 가변 버퍼는 `with_capacity`로 최종 크기를 먼저 잡아 재할당으로 사본이 남지 않게 한다.
- `secp256k1::SecretKey`는 `Copy`이므로 사용 직후 `non_secure_erase()`를 호출한다(아카이브 `EphemeralSecpSecret` 패턴, §12).
- 비밀 바이트 비교는 `subtle::ConstantTimeEq`, 여러 항목은 모두 비교한 뒤 한 번에 판정한다.
- 길이·카운터 연산은 `checked_*`만 쓴다. `panic`·`unwrap`·`expect` 금지(lint, [01](01-repo-build.md) §3.1).
- 오류 값에 비밀을 담지 않는다. 로그에는 오류 변형 이름만 남긴다(D28).

## 1. 엔트로피

### 1.1 난수원

```rust
// yw_core::entropy
pub(crate) trait RandomSource {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), KeyError>;
}
pub(crate) struct OsRandom;
impl RandomSource for OsRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), KeyError> {
        getrandom::fill(out).map_err(|_| KeyError::RandomnessUnavailable)
    }
}
```

- `getrandom = "=0.3.3"`, `default-features = false`. rustc 1.95.0에서 Windows 백엔드는 `bcryptprimitives.dll!ProcessPrng`(raw-dylib)이다. `getrandom_backend` cfg, `windows_legacy`, 다른 난수 크레이트는 금지([01](01-repo-build.md) §3.5·§4.2 검사 스크립트가 차단).
- **fail-closed:** `fill` 오류는 즉시 `KeyError::RandomnessUnavailable`로 해당 작업 전체를 중단한다. 같은 작업 안에서 재시도하지 않고, 시간·카운터·사용자 입력·RDRAND 등 대체 난수원을 절대 쓰지 않는다. 디스크에는 아무것도 쓰지 않은 상태로 끝난다.
- **고착 검사:** 32바이트 비밀(니모닉 엔트로피, DEK)은 32바이트가 모두 같은 값이면 `RandomnessUnavailable`. salt(16바이트)·nonce(24바이트)도 같은 검사를 한다(모든 바이트가 같으면 `RandomnessUnavailable`, 그 작업은 아무것도 쓰지 않고 실패; 세션 중 난수원이 고착되어 같은 DEK로 같은 XChaCha20 nonce를 다시 쓰는 일을 막는다, 2026-11-01 검토 L16). 16바이트 식별자(`vault_id`, `record_id`, 백업 challenge id)는 0이 아니어야 하며, 0이면 최대 4회까지 다시 뽑고 그래도 0이면 `RandomnessUnavailable`(아카이브 `fill_random_nonzero`).
- `RandomSource` 주입은 `pub(crate)` 함수(`*_with_rng`)로만 한다. 공개 API는 항상 `OsRandom`을 쓴다. 테스트 전용 구현(`ScriptedRandom`, `FailingRandom`)은 `#[cfg(test)]`에만 두고, 주입용 cargo feature는 만들지 않는다.

### 1.2 난수 사용처

니모닉 엔트로피 32(생성 경로의 **첫 번째** 추출, 테스트가 확인), DEK 32, `vault_id`·`record_id`·`ChallengeId` 16(0 금지), `kdf_salt` 16, `wrap_nonce`·`payload_nonce`·사이드카 `nonce` 24(쓰기마다 새로), secp256k1 컨텍스트 seed 32(§1.3), 백업 단어 위치 u32×n(거부 표본추출, §8.3).

### 1.3 secp256k1 컨텍스트

```rust
pub(crate) fn secp_context(rng: &mut impl RandomSource)
    -> Result<secp256k1::Secp256k1<secp256k1::All>, KeyError>
{
    let mut ctx = secp256k1::Secp256k1::new();
    let mut seed = Zeroizing::new([0_u8; 32]);
    rng.fill(seed.as_mut())?;
    ctx.seeded_randomize(&seed);
    Ok(ctx)
}
```

- `secp256k1 = "=0.31.1"`, features `["alloc", "recovery"]`만. `rand`·`global-context` 기능이 없으므로 자동 무작위화가 없고, 위 함수가 유일한 생성 경로다.
- 컨텍스트는 키 파생·서명 작업마다 새로 만들고 작업이 끝나면 버린다. 전역·static 컨텍스트 금지.

## 2. BIP39 (자체 구현, D6·D8·D9)

### 2.1 단어 목록

- 파일: `crates/yw-core/src/bip39/english.txt`([01] §1.4가 M0에 만들고 §4.3 privacy-scan이 읽는다). bitcoin/bips `bip-0039/english.txt`를 바이트 그대로 복사한다: 2048줄, 각 줄 LF 종료(마지막 줄 포함), 13,116바이트, 첫 단어 `abandon`, 마지막 `zoo`.
- 내장: `src/bip39/mod.rs`의 `include_str!("english.txt")`. 최초 사용 시 `std::sync::OnceLock`(값은 `&'static str` 2048개 배열, 스택 32 KiB를 피해 `Box`)으로 `'\n'` 분할한다. 분할 결과가 2048개가 아니면 `KeyError::Internal`(패닉 금지).
- 무결성 테스트: 파일 SHA-256 = `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`(조사 단계에서 bip39-2.2.0 내장 목록으로 계산). **확인함(2026-10-27):** bitcoin/bips `bip-0039/english.txt`(커밋 `ce1862a`)의 SHA-256이 이 값과 같아 테스트에 고정했다. 다르면 공식 파일을 따르고 이 문서를 고친다. 이 테스트는 내장 데이터가 공식 목록과 같은지 보는 것이며 §2.3 금지 대상(문서·소스 해시 고정)이 아니다.
- 구조 테스트: 엄격한 오름차순(바이트 비교), 중복 없음, 각 단어 3–8자 `[a-z]`, 앞 4글자가 모두 다름.
- 단어→색인은 이진 탐색이다(타이밍 부채널은 §2.2 비목표).

### 2.2 상수와 타입

```rust
// yw_core::bip39
pub const BIP39_PBKDF2_ROUNDS: u32 = 2_048;
pub const BIP39_SALT_PREFIX: &[u8] = b"mnemonic";
pub const MAX_MNEMONIC_INPUT_BYTES: usize = 256;   // 24단어 최대 215바이트
pub const MAX_PASSPHRASE_BYTES: usize = 256;
pub fn is_word(word: &str) -> bool;   // 목록에 정확히 있는 단어(이진 탐색). [04] §4.2 단어별 검사(E-INP-004)용

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordCount { W12, W15, W18, W21, W24 }      // 엔트로피 16/20/24/28/32바이트

pub struct Mnemonic { entropy: Zeroizing<[u8; 32]>, len: u8 }  // len ∈ {16,20,24,28,32}, 나머지 0
impl Mnemonic {
    pub(crate) fn generate_with_rng(rng: &mut impl RandomSource) -> Result<Self, KeyError>; // 항상 32바이트
    pub fn from_entropy(entropy: &[u8]) -> Result<Self, KeyError>;
    pub fn parse(phrase: &str) -> Result<Self, KeyError>;
    pub fn word_count(&self) -> WordCount;
    pub fn phrase(&self) -> Result<SecretString, KeyError>; // 단어를 0x20 하나로 연결(용량을 미리 계산, `Debug` 가림). 내부 실패는 `Internal` — 빈·부분 문장을 돌려주지 않는다(다른 seed가 되므로)
    pub(crate) fn word_at(&self, position: u8) -> Result<&'static str, KeyError>; // 1-based
    pub(crate) fn entropy(&self) -> &[u8];
    pub fn to_seed(&self, passphrase: &Bip39Passphrase) -> Result<SecretBytes<64>, KeyError>; // `phrase()` 오류를 그대로 전달
}

// yw_core::password
pub struct Bip39Passphrase(Zeroizing<Vec<u8>>);         // 0..=256바이트, 각 0x20..=0x7E
impl Bip39Passphrase {
    pub fn new(input: &str) -> Result<Self, KeyError>;
    pub fn empty() -> Self;
    pub fn is_empty(&self) -> bool;
}
```

### 2.3 엔트로피 ↔ 니모닉

- ENT ∈ {128,160,192,224,256}비트, CS = ENT/32, 체크섬 = `SHA-256(entropy)`의 앞 CS비트. `entropy ‖ CS`를 11비트씩 잘라 단어 색인으로 쓴다(MSB 우선). 단어 수 = (ENT+CS)/11.
- `from_entropy`: 길이가 16/20/24/28/32가 아니면 `InvalidEntropyLength`.
- 생성(D9): 새 지갑은 `generate_with_rng`로 32바이트만 만든다. 12–21단어 생성 API는 없다.

### 2.4 엄격 파싱 (`Mnemonic::parse`)

순서대로 검사하고 처음 실패에서 반환한다. 중간 버퍼(색인, 비트열)는 `Zeroizing`.

| # | 검사 | 실패 |
|---|---|---|
| 1 | `phrase.len() <= 256` | `MnemonicFormat` |
| 2 | 모든 바이트가 `a-z` 또는 `0x20` | `MnemonicFormat` |
| 3 | 첫·마지막 바이트가 공백 아님, 연속 공백 없음 | `MnemonicFormat` |
| 4 | 단어 수 ∈ {12,15,18,21,24} | `MnemonicWordCount` |
| 5 | 각 단어가 목록에 있음 | `MnemonicUnknownWord { position }`(1-based, 첫 번째만) |
| 6 | 체크섬 일치 | `MnemonicChecksum` |

- 탭, 대문자, 선후행 공백, NBSP, 전각 문자, 줄바꿈은 모두 거부한다. 코어는 정규화하지 않는다. UI는 단어별 입력 칸을 소문자 ASCII로만 받아 단일 공백으로 연결해 넘긴다([04](04-app-ui.md) §2.4·§4.2).

### 2.5 시드

```
seed[64] = PBKDF2-HMAC-SHA512(P = phrase() 바이트, S = b"mnemonic" ‖ passphrase 바이트, c = 2048, dkLen = 64)
```

- `pbkdf2::pbkdf2_hmac::<sha2::Sha512>`를 쓴다. P는 항상 `phrase()`의 정규형(단일 공백)이다.
- **NFKD를 하지 않는 이유:** BIP39는 니모닉과 passphrase에 NFKD를 요구한다. 그런데 영어 단어 목록과 passphrase가 모두 출력 가능한 ASCII(0x20–0x7E)로 제한되고(D8), 이 범위의 문자는 정준·호환 분해가 없어 NFKD 결과가 입력과 같다. 따라서 표준과 같은 시드가 나오고 `unicode-normalization`이 필요 없다. 비ASCII passphrase는 `PassphraseInvalidChar`로 거부한다(§2.2 비목표).
- passphrase는 앞뒤 공백을 포함해 입력 그대로 쓴다. UI는 trim하지 않는다.
- `Bip39Passphrase::new`: 257바이트 이상 `PassphraseTooLong`, 0x20–0x7E 밖 바이트 `PassphraseInvalidChar`.

## 3. BIP32·경로·SLIP-0010

### 3.1 BIP32 (secp256k1)

```rust
// yw_core::bip32
pub const HARDENED: u32 = 0x8000_0000;
pub const MAX_PATH_DEPTH: usize = 10;
pub const BIP32_ROOT_KEY: &[u8] = b"Bitcoin seed";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bip32Path { components: Vec<u32> }   // 길이 0..=10, bit31 = hardened
impl core::str::FromStr for Bip32Path { type Err = KeyError; /* §3.2 */ }
impl core::fmt::Display for Bip32Path { /* "m/44'/60'/0'/0/0" */ }

pub(crate) struct XPriv {
    key: Zeroizing<[u8; 32]>, chain_code: Zeroizing<[u8; 32]>,
    depth: u8, child_number: u32,
}
impl XPriv {
    pub(crate) fn from_seed(seed: &[u8]) -> Result<Self, KeyError>;                 // 16..=64바이트
    pub(crate) fn derive_child(&self, ctx: &Secp256k1<All>, i: u32) -> Result<Self, KeyError>;
    pub(crate) fn derive_path(&self, ctx: &Secp256k1<All>, p: &Bip32Path) -> Result<Self, KeyError>;
    pub(crate) fn secret_key(&self) -> Result<SecretKey, KeyError>;                 // 호출자가 erase
    pub(crate) fn public_key(&self, ctx: &Secp256k1<All>) -> Result<PublicKey, KeyError>;
}
```

알고리즘:

- 마스터: `I = HMAC-SHA512(key = "Bitcoin seed", data = seed)`. `IL`이 0이거나 ≥ n이면 `DerivationFailed`. `k = IL`, `c = IR`. seed 길이가 16–64가 아니면 `InvalidEntropyLength`.
- CKDpriv(`k_par`, `c_par`, `i`):
  - `i ≥ 2^31`: `data = 0x00 ‖ ser256(k_par) ‖ ser32(i)`. `ser256`은 선행 0을 포함한 정확히 32바이트다(벡터 3·4가 이 버그를 잡는다).
  - `i < 2^31`: `data = serP(K_par)`(압축 33바이트) `‖ ser32(i)`.
  - `I = HMAC-SHA512(c_par, data)`. `Scalar::from_be_bytes(IL)` 실패(IL ≥ n)면 `DerivationFailed`. `k_i = SecretKey::add_tweak(k_par, IL)`이 실패(결과 0)하면 `DerivationFailed`. `c_i = IR`.
- **무효 자식 건너뛰기를 하지 않는다.** BIP32는 다음 i로 넘어가라고 하지만, 우리는 오류를 반환한다. 확률은 경로당 2^-127 미만이고, 해당 계정 색인은 "이 경로에서 키를 파생할 수 없음" 오류로 쓸 수 없게 된다. vault·meta는 요청 색인만 저장하며 "실제 색인" 필드가 없다(아카이브 `actual_path`, `DerivationExhausted` 삭제).
- `I`, `IL`, `data`, 중간 `SecretKey`·`Scalar`는 사용 직후 소거(`Zeroizing`, `non_secure_erase`).

공개 파생(CKDpub, M8: BTC 주소 발급, [08](08-bitcoin.md) §3.1):

```rust
// yw_core::bip32
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccountXpub { pub pubkey: [u8; 33], pub chain_code: [u8; 32] }   // 공개 정보(비밀 타입 아님), pubkey는 압축형
pub fn derive_public_child(parent: &AccountXpub, index: u32 /* 비강화만 */) -> Result<AccountXpub, KeyError>;
```

- `index ≥ 2^31` → `InvalidPath`(강화 자식은 개인키가 필요하다). `parent.pubkey`가 유효한 압축 점(접두 02/03, 곡선 위)이 아니면 `DerivationFailed`.
- `I = HMAC-SHA512(key = chain_code, data = pubkey ‖ ser32(index))`. `Scalar::from_be_bytes(IL)` 실패(IL ≥ n)면 `DerivationFailed`. `K_i = PublicKey::add_exp_tweak(K_par, IL)`(= point(IL) + K_par)이 실패(무한원점)하면 `DerivationFailed`. `c_i = IR`. CKDpriv와 같이 다음 색인으로 건너뛰지 않는다.
- 컨텍스트는 `secp_context(&mut OsRandom)`(§1.3, 유일한 생성 경로)로 만들고 호출이 끝나면 버린다. 따라서 `RandomnessUnavailable`도 나올 수 있다.
- 계정 노드 m/84'/{coin}'/0'의 `AccountXpub`는 강화 파생이라 `Vault::btc_account_xpub`(§10.3)만 만든다. 그 아래 `/{chain}/{index}`는 이 함수로 공개 파생한다(`chain` ∈ {0, 1}, [08] §3.1).

### 3.2 경로 파서

문법: `"m"` 또는 `"m/" comp ("/" comp)*`, `comp = ("0" | [1-9][0-9]*) "'"?`, 값 < 2^31, 깊이 ≤ 10.

| 허용 | 거부 |
|---|---|
| `m`, `m/0`, `m/44'/60'/0'/0/0`, `m/2147483647'` | `M/0`, `m/`, `m//0`, `m/0/`, `m/00`, `m/01`, `m/0h`, `m/0H`, `m/ 0`, `m/2147483648`, `m/-1`, 깊이 11 |

### 3.3 체인별 경로 (D29)

| 체인 | 경로 | 색인 범위 | 타입 | 사용 시점 |
|---|---|---|---|---|
| EVM (모든 EVM 체인 공통) | `m/44'/60'/0'/0/i` | `i` 0..=999 | `Bip32Path` | M1 |
| Solana | `m/44'/501'/i'/0'` (`SolKeySource::Standard`; 복구 스캔용 비표준 출처는 §3.5) | `i` 0..=999 | `Slip10Path` | M7 |
| Bitcoin mainnet | `m/84'/0'/0'/c/i` | `c` ∈ {0 수신, 1 잔돈}, `i` < 2^31(정책은 [08](08-bitcoin.md) §3) | `Bip32Path` | M8 |
| Bitcoin testnet4 | `m/84'/1'/0'/c/i` | 같음. 지갑마다 네트워크 하나(D26) | `Bip32Path` | M8 |

```rust
// yw_core::bip32::path
pub const MAX_ACCOUNT_INDEX: u32 = 999;
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AccountIndex(u32);
impl AccountIndex { pub const fn new(i: u32) -> Result<Self, KeyError>; pub const fn get(self) -> u32; }
pub enum BtcCoin { Mainnet, Test }            // 0' mainnet / 1' testnet4 (D29)
pub enum BtcChain { Receive, Change }         // 0 / 1
pub fn evm_path(i: AccountIndex) -> Bip32Path;
pub fn btc_path(coin: BtcCoin, chain: BtcChain, index: u32) -> Result<Bip32Path, KeyError>; // index ≥ 2^31 → InvalidPath
pub fn btc_account_path(coin: BtcCoin) -> Bip32Path;                                    // m/84'/{0|1}'/0' (M8)
pub fn sol_path(i: AccountIndex) -> Slip10Path;      // M7(`slip10`과 함께 추가)
```

- `AccountIndex::new`는 999 초과를 `InvalidAccountIndex`로 거부한다. 코어가 상한을 강제하므로 meta에도 그 밖의 색인이 들어올 수 없다.
- EVM 주소 = `keccak256(uncompressed_pubkey[1..65])[12..32]`. 주소 타입·EIP-55 표기는 `yw_core::evm::Address`([03](03-evm.md) §2.1–2.2).

### 3.4 확장 키 문자열 (`bip32::xkey`, M1, KAT·테스트용)

제품 기능이 아니다(xprv/xpub 가져오기·내보내기 없음, [08] §1.2). BIP32 벡터 1–5를 단위 테스트(`src/bip32/tests.rs`, [09] §3.3)에서 전체 문자열로 판정하기 위한 공개 API다.

```rust
pub enum XKeyVersion { Xprv, Xpub, Tprv, Tpub }   // 0488ADE4, 0488B21E, 04358394, 043587CF
pub struct XKeyParts {                             // 비밀 타입(§0): Clone·Display 없음, Debug 가림
    pub version: XKeyVersion, pub depth: u8, pub parent_fingerprint: [u8; 4], pub child_number: u32,
    pub chain_code: [u8; 32], pub key: Zeroizing<[u8; 33]>,   // 개인: 0x00 ‖ k, 공개: 압축 공개키
}
pub fn fingerprint(pubkey: &[u8; 33]) -> [u8; 4];           // RIPEMD160(SHA256(pubkey))[0..4]
pub fn derive_xkey(seed: &[u8], path: &Bip32Path, version: XKeyVersion) -> Result<XKeyParts, KeyError>;
pub fn encode_xkey(p: &XKeyParts) -> Zeroizing<String>;
pub fn decode_xkey(s: &str) -> Result<XKeyParts, KeyError>; // 실패는 모두 InvalidExtendedKey
```

- 직렬화: `version(4) ‖ depth(1) ‖ parent_fingerprint(4) ‖ child_number(4, BE) ‖ chain_code(32) ‖ key(33)` = 78바이트, base58check(체크섬 = SHA-256d 앞 4바이트, `codec::base58`).
- `derive_xkey`: §3.1로 파생한다. depth = 경로 길이, child_number = 마지막 성분(`m`이면 0), parent_fingerprint = `fingerprint(부모 압축 공개키)`(`m`이면 0). 공개 버전이면 key = 압축 공개키. HASH160은 `sha2` + `ripemd =0.1.3`(D5, M0부터 허용 목록).
- `decode_xkey` 거부: 체크섬 오류, 길이 ≠ 78, 버전이 위 4개가 아님, 개인 버전인데 키 첫 바이트 ≠ 0x00 또는 키 ∉ [1, n−1], 공개 버전인데 접두 ∉ {02,03} 또는 곡선 밖 점, depth = 0인데 parent_fingerprint ≠ 0 또는 child_number ≠ 0.

### 3.5 SLIP-0010 Ed25519 (M7, D25)

```rust
pub struct Slip10Path { components: Vec<u32> }   // 모든 성분 hardened, 깊이 1..=10
impl core::str::FromStr for Slip10Path { type Err = KeyError; } // 모든 성분에 ' 필수, 없으면 InvalidPath
pub(crate) fn slip10_ed25519(seed: &[u8; 64], path: &Slip10Path) -> Zeroizing<[u8; 32]>;
```

- 마스터: `I = HMAC-SHA512(key = "ed25519 seed", data = seed)`, `k = IL`, `c = IR`.
- 자식(`i ≥ 2^31`만): `I = HMAC-SHA512(key = c, data = 0x00 ‖ k ‖ ser32(i))`, `k = IL`, `c = IR`. 비강화 색인은 절대 강화로 승격하지 않고 파서 단계에서 거부한다.
- 결과 `k`는 RFC 8032 비밀 seed다. `ed25519_dalek::SigningKey::from_bytes(&k)`에만 넣고 스칼라로 직접 쓰지 않는다([07](07-solana.md) §3.1).
- `Slip10Path`와 `Bip32Path`는 서로 다른 타입이다. secp256k1 파생은 `Bip32Path`만, Ed25519 파생은 `Slip10Path`만 받는다.

Solana 키 출처(Ed25519 seed를 얻는 유일한 입력, [07] §3.2가 태그·지갑 호환·스캔 정책을 정한다):

```rust
// yw_core::slip10 (M7; [07]의 sol 모듈은 이 타입을 그대로 쓰고 다시 정의하지 않는다)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SolKeySource {
    Standard(AccountIndex),                     // m/44'/501'/i'/0'  (D25·D29, 새 계정은 이것만)
    Bip44Account(AccountIndex),                 // m/44'/501'/i'
    Bip44Root,                                  // m/44'/501'
    RawSeed,                                    // 파생 없음: bip39 seed[0..32]
    SolletLegacy { wallet: u32, account: u32 }, // MAY: secp256k1 BIP32 m/501'/w'/0/a, 32바이트 개인키를 Ed25519 seed로 사용
}
```

| 출처 | 32바이트 Ed25519 seed `k` (seed = §2.5의 64바이트 BIP39 시드) |
|---|---|
| `Standard(i)` | `slip10_ed25519(seed, sol_path(i))` |
| `Bip44Account(i)` | `slip10_ed25519(seed, m/44'/501'/i')` |
| `Bip44Root` | `slip10_ed25519(seed, m/44'/501')` |
| `RawSeed` | `seed[0..32]`를 `Zeroizing<[u8; 32]>`에 복사 |
| `SolletLegacy { wallet, account }` | `XPriv::from_seed(seed)` → `derive_path(m/501'/wallet'/0/account)`(§3.1 CKDpriv, 건너뛰기 없음)의 32바이트 개인키. `wallet ≥ 2^31` 또는 `account ≥ 2^31`이면 `InvalidPath`. 중간 `SecretKey`는 `non_secure_erase` |
| `Imported` (태그 6) | BIP39 시드를 쓰지 않는다: vault `SolKey` record(`tag 3`)의 시드. 공개키로 찾으므로 `with_imported_ed25519_seed(public, f)`(§10.3)로만 얻고, `with_ed25519_seed(Imported)`·`sol_public_keys`는 `InvalidPath` |

- 이 계산은 `Vault::with_ed25519_seed`·`Vault::sol_public_keys`(§10.3) 안에서만 한다. 공개 API로 seed를 돌려주는 함수는 없다.
- `SolletLegacy`는 선택(MAY)이다. 구현 여부·확인 벡터 조건은 [07] §3.2를 따르고, 구현하지 않으면 이 변형은 `InvalidPath`를 돌려준다.

## 4. vault v3 파일 형식 (D7)

이전 형식(v1 `YWRVLT01`, 데모 v2 `YWSPV002`)은 읽지 않는다. 다른 magic은 `Malformed`이며, 사용자는 니모닉으로 다시 가져온다.

### 4.1 상수

```rust
pub const VAULT_MAGIC: [u8; 8] = *b"YWVLT003";
pub const VAULT_VERSION: u16 = 3;
pub const VAULT_HEADER_LEN: usize = 176;
pub const KEY_BLOCK_END: usize = 82;         // wrap AAD = header[0..82]
pub const KEY_SECTION_END: usize = 130;      // payload 재작성 시 그대로 두는 범위
pub const KDF_ID_ARGON2ID_V13: u16 = 1;
pub const KDF_V3: KdfParams = KdfParams { m_kib: 262_144, t: 3, p: 4 };  // 256 MiB
pub const HKDF_KEK_SALT: &[u8] = b"your-wallet/v3/kdf";
pub const HKDF_KEK_INFO: &[u8] = b"your-wallet/v3/kek";
pub const DEK_LEN: usize = 32;
pub const WRAPPED_DEK_LEN: usize = 48;       // 32 + tag 16
pub const PAYLOAD_CT_MIN: u32 = 80;          // 최소 평문 64 + tag 16
pub const PAYLOAD_CT_MAX: u32 = 4_096;       // 최대 평문 3,170(§4.6) + tag 16 = 3,186이 들어간다
pub const MAX_RECORDS: usize = 46;           // Bip39 0–1개 + EvmRawKey·SolKey·BtcKey 각 최대 15개
```

### 4.2 헤더 (176바이트, 모든 정수 big-endian)

| 오프셋 | 길이 | 필드 | 값·규칙 |
|---:|---:|---|---|
| 0 | 8 | `magic` | `"YWVLT003"` |
| 8 | 2 | `version` | 3 |
| 10 | 2 | `header_len` | 176 |
| 12 | 16 | `vault_id` | 생성 시 난수, 0 아님, 수명 동안 불변 |
| 28 | 2 | `kdf_id` | 1 = Argon2id v0x13 |
| 30 | 4 | `m_kib` | 262144 |
| 34 | 4 | `t` | 3 |
| 38 | 4 | `p` | 4 |
| 42 | 16 | `kdf_salt` | 난수 |
| 58 | 24 | `wrap_nonce` | 난수 |
| 82 | 48 | `wrapped_dek` | DEK 32 + tag 16 |
| 130 | 8 | `generation` | ≥ 1, 쓰기마다 +1 |
| 138 | 24 | `payload_nonce` | 쓰기마다 난수 |
| 162 | 4 | `payload_ct_len` | 평문 길이 + 16, [80, 4096] |
| 166 | 4 | `flags` | 0 |
| 170 | 6 | `reserved` | 0 |
| 176 | `payload_ct_len` | `payload_ct` | |

파일 길이는 정확히 `176 + payload_ct_len`이어야 한다.

`generation`과 `payload_nonce`를 `wrapped_dek` 뒤에 두는 이유: wrap AAD는 `wrapped_dek` 앞의 바이트 전체다. `generation`이 그 안에 있으면 payload만 바꾸는 쓰기에도 DEK를 다시 감싸야 하고, 그러려면 KEK(=비밀번호 Argon2)가 필요해 D10(메모리 상주 비밀은 DEK·passphrase뿐, KEK 없음)과 "payload 재작성에 Argon2 없음" 규칙을 둘 다 지킬 수 없다.

### 4.3 키 계층

```
pw_kek  = Argon2id(v0x13, password = VaultPassword 바이트, salt = kdf_salt,
                   m = 262144 KiB, t = 3, p = 4, secret 없음, ad 없음, out = 32)
KEK     = HKDF-SHA256(salt = "your-wallet/v3/kdf", ikm = pw_kek, info = "your-wallet/v3/kek", L = 32)
DEK     = 난수 32바이트 (생성 시 1회, 비밀번호 변경에도 유지)
wrapped_dek = XChaCha20-Poly1305(key = KEK, nonce = wrap_nonce, pt = DEK, aad = header[0..82])
payload_ct  = XChaCha20-Poly1305(key = DEK, nonce = payload_nonce, pt = payload 평문, aad = header[0..176])
```

- Argon2: `argon2 = "=0.5.3"`, `default-features = false`, features `["zeroize"]`(`alloc` 금지). `Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(m, t, p, Some(32)))` + `hash_password_into_with_memory(pwd, salt, &mut out, &mut blocks)`.
- `blocks: Vec<argon2::Block>`는 호출자 소유다. `Vec::try_reserve_exact(params.block_count())` 실패 시 `VaultError::OutOfMemory`(할당 실패로 abort하지 않게). 계산 직후 모든 `Block`에 `zeroize()`를 호출하고 해제한다. argon2는 이 메모리를 지우지 않는다.
- `pw_kek`, KEK는 `Zeroizing<[u8; 32]>`이며 wrap/unwrap 직후 소거한다. 메모리에 남기지 않는다.
- AEAD: `chacha20poly1305 = "=0.10.1"`, features `["alloc"]`(`getrandom` 금지), `XChaCha20Poly1305`. 복호화는 `Zeroizing<Vec<u8>>` 사본에 `decrypt_in_place`로 한다.
- 256 MiB Argon2 메모리는 VirtualLock할 수 없어 페이징될 수 있다. 디스크 도난 시 pagefile 노출은 BitLocker 권고(spec §2.4)로 완화한다.

### 4.4 쓰기 종류

| 종류 | 사용처 | 새로 뽑는 값 | Argon2 | 그대로 두는 값 |
|---|---|---|---|---|
| `Create` | 생성·가져오기 | `vault_id`, DEK, `kdf_salt`, `wrap_nonce`, `payload_nonce`; `generation = 1` | 1회 | — |
| `PayloadRewrite` | 백업 확인, raw key 추가·삭제, `.prev` 복구 | `payload_nonce`; `generation + 1` | 0회 | `header[0..130]`(키 구간 전체) |
| `Rewrap` | 비밀번호 변경 | `kdf_salt`, `wrap_nonce`, `wrapped_dek`, `payload_nonce`; `generation + 1` | 새 비밀번호 1회 | `vault_id`, DEK, payload 평문 |

- `Rewrap` 직후 같은 내용으로 `PayloadRewrite`를 한 번 더 커밋한다(`generation + 2`). 그래야 `vault.ywv.prev`에도 새 비밀번호로 감싼 세대만 남는다(§6).
- `Rewrap` 커밋이 반영된 뒤에는 비밀번호 변경이 **성공**이다. 이어지는 `PayloadRewrite`가 실패해도 오류가 아니라 `Ok(PasswordChange::PrevNotRefreshed)`를 돌려준다(이전 비밀번호는 이미 `vault.ywv`를 열지 못하므로 "실패"라고 알리면 틀린 안내가 된다). 이때 `vault.ywv.prev`는 이전 비밀번호로만 열릴 수 있고, 다음 쓰기(`PayloadRewrite`)가 새 비밀번호 세대로 바꾼다. 다 성공하면 `Ok(PasswordChange::Complete)`. `Rewrap` 자체가 실패하면 오류이고 이전 비밀번호가 그대로 유효하다. UI는 두 `Ok` 모두 "새 비밀번호가 적용됨"으로 알린다([04] §2.17).
- 비밀번호 변경은 DEK를 바꾸지 않는다. 이전 비밀번호와 이전 파일을 함께 가진 사람은 DEK를 얻을 수 있다. 이것을 끊으려면 니모닉으로 새 vault를 만든다(새 DEK). 사용자가 따로 만든 파일 사본·섀도 복사본은 지갑이 지울 수 없다. yw-app은 이 사실을 비밀번호 변경 창(W04)·설정 → 보안 → 비밀번호·변경 완료 문구에 적고, `docs/recovery-guide.ko.md`가 대처를 안내한다(2026-11-01 검토 L1).
- **DEK 회전을 하지 않는 이유(L1 검토 결론):** 사이드카 키(`meta_key`·`journal_key`, §5.1)가 DEK에서 나오므로 DEK를 바꾸면 `vault.ywv`·`meta.ywm`·`journal.ywj` 세 파일을 함께 다시 써야 한다. 세 파일은 따로 커밋되므로(§6.2) 그 사이 중단되면 새 DEK의 vault와 옛 DEK의 사이드카가 남아 사이드카가 `SidecarCorrupt`가 된다. 이를 안전하게 하려면 payload에 "이전 DEK" 레코드를 두는 2단계 이행(새 vault 커밋 → 사이드카 이행 → 이전 DEK 레코드 제거)과 그 형식·복구 규칙이 필요하다. 형식 변경 없이 충돌 안전을 보장할 수 없어 이번 판에서는 문서·화면 안내만 한다.
- 모든 쓰기는 커밋 전에 자체 검사를 한다: 새 바이트를 §4.5 순서로 디코드하고, DEK로 payload를 복호화해 원래 평문과 같은지 비교한다. `Create`·`Rewrap`은 손에 있는 KEK로 `wrapped_dek`를 풀어 DEK와 같은지도 비교한다(추가 Argon2 없음).

### 4.5 디코드 순서

1–7은 구조 검사이며 Argon2를 실행하지 않는다.

| # | 검사 | 오류 |
|---|---|---|
| 1 | 길이 ≥ 176, `magic` 일치 | `Malformed` |
| 2 | `version == 3` | `UnsupportedVersion` |
| 3 | `header_len == 176` | `Malformed` |
| 4 | `vault_id ≠ 0`, `generation ≥ 1` | `Malformed` |
| 5 | `kdf_id == 1` 이고 `(m_kib, t, p) == KDF_V3` 정확히 일치 | `UnsupportedParams` |
| 6 | `payload_ct_len` ∈ [80, 4096], 파일 길이 = 176 + `payload_ct_len` | `Malformed` |
| 7 | `flags == 0`, `reserved` 전부 0 | `Malformed` |
| 8 | Argon2 → KEK → `wrapped_dek` 복호화 | `UnlockFailed`(비밀번호 오류와 키 구간 변조를 구분하지 않음) |
| 9 | DEK로 payload 복호화(AEAD 인증) | `PayloadCorrupt` |
| 10 | 인증된 평문 디코드(§4.6) | `UnsupportedPayload` |

- 9와 10을 나누는 이유: 인증에 성공한 평문은 DEK를 가진 앱(이 앱의 어떤 버전)이 쓴 것이다. 그런 평문이 디코드되지 않으면 손상이 아니라 **이 빌드가 모르는 형식**(새 버전이 더한 tag 등)이다. `UnsupportedPayload`는 상태를 `Locked`로 두고 `.prev` 복구를 제안하지 않으며(`Corrupt`가 아님), `recover_from_prev`도 본 파일이 `UnsupportedPayload`면 거부한다 — `.prev`로 되돌리면 새 버전이 추가한 record가 사라지기 때문이다. UI는 E-VLT-014 "새 버전 앱이 저장한 지갑입니다. 앱을 업데이트하세요"를 보인다([04] §7).
- 파라미터는 "이상"이 아니라 **정확히 일치**해야 한다. 더 약한·더 강한 값 모두 거부한다.
- 테스트 빌드에서만 `pub(crate)` 내부 함수가 `&KdfParams`를 받는다. `#[cfg(test)] const KDF_TEST: KdfParams = KdfParams { m_kib: 64, t: 1, p: 1 }`. 공개 API는 항상 `KDF_V3`로 인코드·디코드하므로 `KDF_TEST` 파일은 제품에서 `UnsupportedParams`다(아카이브 데모 `vault_v2.rs`의 축소 파라미터 패턴).

### 4.6 payload 평문 코덱

```
off len
0   8   payload_magic   "YWPAY003"
8   2   record_count    u16, 1..=46
10  6   reserved        0
16  …   records         record_count개, 정확히 끝까지 소비(남는 바이트 금지)
```

```
Bip39 (tag 1, 32 + L 바이트)            EvmRawKey (tag 2, 57바이트)
len field                                len field
1   tag = 1                              1   tag = 2
16  record_id (0 아님)                   16  record_id (0 아님)
8   created_unix u64 (yw-app이 넘긴 값)  8   created_unix u64
1   entropy_len L ∈ {16,20,24,28,32}     32  key (1 ≤ key < n)
L   entropy
1   flags: bit0 = passphrase_used, 나머지 0
1   backup_state: 0 = Pending, 1 = Confirmed
4   passphrase_check: passphrase_used이면 SHA-256(addr0)[0..4], 아니면 00000000
```

```
SolKey (tag 3, 89바이트)                 BtcKey (tag 4, 60바이트)
len field                                len field
1   tag = 3                              1   tag = 4
16  record_id (0 아님)                   16  record_id (0 아님)
8   created_unix u64                     8   created_unix u64
32  seed (RFC 8032 비밀 시드)            32  secret (1 ≤ k < n)
32  public = Ed25519(seed) 공개키        1   flags: bit0 = compressed, 나머지 0
                                         1   network: 1 = mainnet, 2 = testnet4 (`BtcNetwork::id`)
                                         1   script: 1 = P2PKH, 2 = P2SH-P2WPKH, 3 = P2WPKH, 4 = P2TR
```

- 순서 고정: `Bip39`(있으면 정확히 1개, 맨 앞) → `EvmRawKey`들 → `SolKey`들 → `BtcKey`들. 태그는 오름차순으로 묶이고 `tag 1`은 두 번 나올 수 없다. 각 가져온 키 태그(2·3·4)는 0–15개(체인별 상한, §8.4). `record_count ≥ 1`이므로 `Bip39`가 없으면 가져온 키가 최소 1개 있다.
- **키 전용 vault**(복구 단어 없음, §8.5): `Bip39` record가 없는 payload. 잠금 해제하면 곧바로 `Unlocked { alt: false }`(passphrase·백업 확인 없음). 파생(`evm_addresses`의 인덱스, `btc_account_xpub`, `sol_public_keys`의 파생 출처), `reveal_mnemonic`, passphrase는 `NoMnemonic`이다.
- `SolKey`: 디코드 때 `public`을 `seed`에서 다시 계산해 같아야 한다. 같은 `public` 두 개는 거부. `BtcKey`: `secret` 범위, `flags` 예약 비트 0, `network` ∈ {1,2}, `script` ∈ {1..4}, 압축하지 않은 키(bit0 = 0)는 `script = 1`(P2PKH)만. (`secret`, compressed, `network`, `script`)가 모두 같은 두 record는 거부(같은 secret을 다른 형식으로 쓰는 것은 다른 계정이라 허용).
- 호환: `tag 1`·`tag 2`의 바이트 배치와 의미는 바뀌지 않았다(골든 G1–G5 그대로). 이 버전은 이전 버전이 쓴 vault를 그대로 연다. 이전 버전의 앱은 `tag 3`·`tag 4` record, `Bip39` 없는 payload, 2,048바이트를 넘는 `payload_ct_len`을 모르므로 그런 vault를 `PayloadCorrupt`(또는 구조 단계 `Malformed`)로 본다([04] §6.6: 되돌린 뒤 `.prev` 복구를 하지 말고 새 버전을 다시 설치한다). 이 버전부터는 인증된 payload의 디코드 실패가 `UnsupportedPayload`(§4.5 단계 10)라 같은 상황에서 `.prev` 복구를 제안하지 않는다.
- **형식 확장 규칙(앞으로의 버전):** payload에는 별도 형식 버전 바이트가 없고, 호환은 **tag 집합**으로 정한다. 새 record 종류는 새 tag 번호(5 이상)로만 더하고, 기존 tag의 바이트 배치·의미는 바꾸지 않는다. 그러면 이 버전은 새 tag를 만나 `UnsupportedPayload`(업데이트 안내, `.prev` 제안 없음)로 멈추고, 파일은 그대로 남는다. 기존 tag의 의미를 바꿔야 하면 `VAULT_VERSION`을 올린다(`UnsupportedVersion`). 새 tag를 더하는 변경은 이 경로(`UnsupportedPayload` → E-VLT-014)를 시험에 넣는다(§11.6).
- `addr0` = 그 passphrase로 파생한 EVM 계정 0(`m/44'/60'/0'/0/0`)의 20바이트 주소. 다른 passphrase도 유효한 다른 지갑을 열기 때문에 BIP39 자체로는 오타를 알 수 없다. 4바이트 확인값은 잠금 해제 때 오타를 잡는다(놓칠 확률 2^-32). 확인값은 암호화된 payload 안에 있어 vault 비밀번호 없이는 passphrase 추측에 쓸 수 없다(비밀번호를 가진 공격자는 어차피 체인 위 주소로 같은 추측을 할 수 있다).
- 디코드 거부(`UnsupportedPayload`, 인증된 평문이므로 손상이 아니다 — §4.5 단계 10): magic 불일치, `record_count` 범위 밖, reserved ≠ 0, 알 수 없는 tag, 순서 위반, `record_id` 0 또는 (모든 tag를 통틀어) 중복, `entropy_len` 오류, flags 예약 비트, `passphrase_used = 0`인데 확인값 ≠ 0, `backup_state` ∉ {0,1}, `backup_state = 0`이면서 `passphrase_used = 1`(생성 지갑은 passphrase를 쓰지 않음, §8.1), raw key 범위 밖, 같은 raw key 중복, 체인별 16번째 가져온 키, `SolKey` 공개키 불일치·중복, `BtcKey` 값 규칙 위반·중복, 남는 바이트.
- 최대 크기: 16 + `Bip39`(24단어) 64 + 15 × (57 + 89 + 60) = 3,170바이트 평문.
- **tag 5 `HwKey`(2026-11-04, D33):** YubiKey 하나의 슬롯 표(일련번호·펌웨어·마스터 지문·슬롯별 역할·경로 인덱스·정책·공개키, 비밀 없음), 0–8개, tag 4 뒤. 바이트 배치와 검사 규칙은 [10](10-yubikey.md) §8. 이에 따라 `MAX_RECORDS` = 54, `PAYLOAD_CT_MAX` = 16,384(최대 평문 3,170 + 8 × 1,189 = 12,682바이트). tag 5만 있는 payload는 니모닉 없는 **YubiKey 지갑**이다(§8.5와 같이 `has_mnemonic() = false`).
- 인코더는 `Zeroizing<Vec<u8>>`에 정확한 길이를 먼저 계산해 할당한다.

## 5. DEK 하위 키와 사이드카 파일

### 5.1 하위 키

```
meta_key    = HKDF-SHA256(salt = 없음(RFC 5869 기본 0), ikm = DEK, info = "your-wallet/v3/meta",    L = 32)
journal_key = HKDF-SHA256(salt = 없음,                   ikm = DEK, info = "your-wallet/v3/journal", L = 32)
```

하위 키는 사용할 때마다 계산하고 즉시 소거한다.

### 5.2 사이드카 형식 (`meta.ywm`, `journal.ywj`)

| 오프셋 | 길이 | 필드 | 값 |
|---:|---:|---|---|
| 0 | 8 | `magic` | `"YWMETA03"` 또는 `"YWJRNL03"` |
| 8 | 2 | `version` | 3 |
| 10 | 2 | `header_len` | 64 |
| 12 | 16 | `vault_id` | vault 헤더의 `vault_id`와 같아야 함 |
| 28 | 8 | `generation` | ≥ 1, 파일별 독립, 쓰기마다 +1 |
| 36 | 24 | `nonce` | 쓰기마다 난수 |
| 60 | 4 | `ct_len` | 평문 + 16; meta ≤ 8 MiB + 16, journal ≤ 16 MiB + 16 (yw-win `atomic_write` 상한 64 MiB 안, [01] §7.2) |
| 64 | `ct_len` | `ct` | XChaCha20-Poly1305(하위 키, nonce, 평문, aad = header[0..64]) |

- 디코드 오류: 구조 위반은 `SidecarCorrupt(kind)`, `vault_id` 불일치는 `SidecarVaultMismatch(kind)`, AEAD 실패는 `SidecarCorrupt(kind)`.
- 평문: meta는 yw-json 직렬화기 출력(UTF-8, 공백 없음, §5.3 순서의 키), journal은 §5.4 이진 형식이다. `vault`는 바이트만 봉인·개봉한다(`open_sidecar`/`save_sidecar`). meta JSON 변환은 yw-app이 yw-json으로 하고, journal 컨테이너 코덱은 yw-core `journal`이 둔다. yw-core 자체는 EIP-712 입력용으로 yw-json에 의존한다(D5, [03] §0·§8).

### 5.3 meta JSON (`schema = "yw-meta/3"`)

최상위 객체. 중복 키·아래 키(선택 키 `btc_accounts`·`btc_accounts_ext`·`sol_sites`·`btc_sites`·`sol_raw_accounts`·`sol_raw_selected`·`security_settings`·`vault_generation_seen`·`token_view` 제외)의 누락은 거부한다. 아래 표에 없는 **최상위** 키는 같은 `schema`의 새 부 버전이 더한 키로 보고 보존해 다음 쓰기에서 알려진 키 뒤에 그대로 쓴다([04](04-app-ui.md) §6.6). 레코드·객체 안의 알 수 없는 키는 거부한다(`prefs`는 기본값으로 되돌림, [04] §6.4). 정수는 JSON 정수(소수·지수 금지), 64비트 금액은 10진 문자열(각 체인 문서).

| 키 | 타입 | 규칙 |
|---|---|---|
| `schema` | string | `"yw-meta/3"` |
| `evm_accounts` | `Account[]` | 0..=100개, `index` 오름차순·중복 금지, 비어 있지 않으면 첫 항목이 `index` 0. 빈 배열은 키 전용 지갑(§8.5)뿐이다(니모닉 지갑의 빈 배열은 잠금 해제 때 계정 0으로 고친다) |
| `evm_raw_accounts` | `RawAccount[]` | 0..=15개, vault의 `EvmRawKey` record와 1:1 |
| `sol_accounts` | `Account[]` | 0..=100개(M7 전에는 `[]`) |
| `btc` | `BtcMeta` | null | BTC를 켜기 전(M8 전 포함) `null`. BIP84 계정 0(버전 1). 필드는 [08](08-bitcoin.md) §12.3 이름 그대로, 바이트 배열은 소문자 hex 문자열, 없음은 `null` |
| `btc_accounts` (선택) | object | 이 키만 없어도 된다(없음 = 다른 BTC 계정 없음, 기본값이면 쓰지 않음). 다른 BTC 계정(주소 형식·계정 번호·가져온 키, 두 네트워크)과 선택: [08](08-bitcoin.md) §12.3a. 있으면 알려진 키로 엄격 검증. EVM·YubiKey 키 계정과 HD 모드 표시는 2026-11-07부터 선택 최상위 키 `btc_accounts_ext`([08] §12.3b; 객체 안 `single_address`·`btc_accounts` 안 `key.evm`·`key.yubikey`는 읽기만, 이행) |\| null | BTC를 켜기 전(M8 전 포함) `null`. 필드는 [08](08-bitcoin.md) §12.3 이름 그대로, 바이트 배열은 소문자 hex 문자열, 없음은 `null` |
| `address_book` | `AddressBookEntry[]` | 0..=500개, (`chain`, `address`) 중복 금지. `chain`은 체인 **계열**이다: EVM 항목은 모두 `"evm"` 하나로 내장·사용자 추가 EVM 체인 전부에서 같이 쓴다(아래 2026-11-06 이전 규칙) |
| `address_book_favorites` (선택, 2026-11-06) | `BookFavorite[]` | 주소록 ★ 즐겨찾기([04] §2.10). 0..=500개, 별을 붙인 순서, `address_book`에 있는 (`chain`, `address`)만. 비어 있으면 쓰지 않는다(이전 버전은 모르는 최상위 키로 보존하고 다시 쓴다). 형식이 틀리면 문서를 거부하지 않고 즐겨찾기 없음으로 읽는다(표시 전용, `token_view`와 같음). 읽을 때 주소록에 없는 항목·중복은 버린다(이전 버전이 지운 항목의 별) |
| `connected_sites` | `ConnectedSite[]` | 0..=256개, `origin` 중복 금지([05](05-browser.md) §4.1) |
| `sol_sites`·`btc_sites` (선택, 2026-10-31) | object[] | Solana·Bitcoin dApp 연결([05] §4.9). 각 0..=256개의 객체 배열, 비어 있으면 쓰지 않는다(이전 버전은 모르는 키로 보존). 항목: `sol_sites` `{ origin, public_key: base58, granted_at_unix_ms }`, `btc_sites` `{ origin, network: 1|2, addresses: [{ purpose: "payment"|"ordinals"|"any", address, public_key: hex, script_type }], granted_at_unix_ms }`. 쓸 수 없는 항목은 읽을 때 건너뛴다 |
| `tokens` | object: `NetworkId` → `TokenEntry[]` | `eip155:*` 키만(SOL 토큰은 고정 허용 목록, D25), 네트워크당 0..=100개·전체 0..=1,000개(어느 쪽이든 상한이면 S16 저장 거부), `address` 중복 금지, 빈 배열 키는 쓰지 않음 |
| `activity` | object: `NetworkId` → `ActivityEntry[]` | 네트워크당 최신순 0..=500개·전체 0..=3,000개, 넘으면 네트워크 상한은 그 네트워크에서, 전체 상한은 모든 네트워크를 통틀어 `time_unix_ms`가 가장 오래된 항목부터 삭제, `tx_id` 중복 금지(같은 `tx_id`는 덮어씀), 빈 배열 키는 쓰지 않음 |
| `prefs` | object | 개인정보성 UI 상태(선택 계정·탭; 네트워크 선택은 settings.json, D30), [04](04-app-ui.md) §6.4. `evm_account` `{"index": 0}`은 `evm_accounts`가 비어 있으면 "첫 가져온 계정"을 뜻한다 |
| `sol_raw_accounts` | `SolRawAccount[]` | **선택 키**(가져오기 전 파일에는 없음, 없으면 `[]`). 0..=15개, vault `SolKey` record와 1:1, `record_id` 중복 금지 |
| `sol_raw_selected` | Hex16 \| null | **선택 키**. 선택한 Solana 계정이 가져온 키면 그 `record_id`(`sol_raw_accounts`에 있어야 함), 아니면 `null`(`prefs.sol_account`의 파생 계정) |
| `security_settings` (선택, 2026-11-01) | object | 평문 `settings.json`의 보안 관련 값을 앱이 마지막으로 쓴 그대로 둔 스냅샷([04](04-app-ui.md) §6.7). 없으면 잠금 해제 뒤 첫 검사가 만든다. 있으면 아래 형식으로 엄격 검증(위반은 문서 거부) |
| `token_view` (선택, 2026-11-03) | `TokenView` | S10 토큰 카드의 행 숨김([04] §2.6, 표시 전용). 기본값(숨김 없음·`hide_zero` false)이면 쓰지 않는다(이전 버전은 모르는 키로 보존). `hidden`의 키는 `eip155:*`(값 = `EvmAddr`, 레지스트리·사용자 토큰 모두)·`solana:*`(값 = 허용 목록 mint base58)만, 네트워크당 1..=200개(빈 배열 키는 쓰지 않음)·전체 0..=2,000개, 같은 네트워크 안 중복 금지. 사용자 토큰을 `tokens`에서 지우면 그 항목도 지운다. 형식이 틀리면 문서를 거부하지 않고 `prefs`처럼 기본값으로 되돌리고 로그(`meta.prefs_reset`)를 남긴다: 승인·위험 판단·토큰 인식은 이 키를 읽지 않는다 |
| `vault_generation_seen` (선택, 2026-11-01) | u64 | 이 meta와 함께 본 가장 큰 `vault.ywv` `generation`. 0이면 쓰지 않는다. 잠금 해제 때 본 파일의 generation이 이보다 작으면 경고 배너([04] §6.7) |

```
Account          = { "index": u32(0..=999), "label": Label, "address": string, "hidden": bool }
RawAccount       = { "record_id": Hex16, "label": Label, "address": EvmAddr }
SolRawAccount    = { "record_id": Hex16, "label": Label, "address": string(정규 base58) }
AddressBookEntry = { "chain": "evm"|"sol"|"btc", "address": string, "label": Label,
                     "verified": bool, "added_at_unix_ms": u64 }     // 정확히 이 5개 멤버
BookFavorite     = { "chain": "evm"|"sol"|"btc", "address": string }  // address_book 항목을 가리킴
ConnectedSite    = { "origin": string, "accounts": EvmAddr[1..=16], "chain_id": u64(≥ 1, EVM chainId),
                     "granted_at_unix_ms": u64 }
TokenEntry       = { "address": EvmAddr, "label": Label, "decimals": u8(0..=36, [03] §2.5) }
TokenView        = { "hidden": { NetworkId: string[1..=200] }, "hide_zero": bool }
ActivityEntry    = { "account": string, "tx_id": string, "title": string, "asset": string, "amount": string,
                     "counterparty": string, "status": ActivityStatus, "time_unix_ms": u64 }
ActivityStatus   = "succeeded" | "failed" | "dropped" | "replaced" | "expired" | "rejected" | "conflicted" | "abandoned"
Label    = UTF-8 문자열 1..=32 스칼라. C0·C1 제어문자, U+200B–U+200F, U+202A–U+202E, U+2066–U+2069, U+FEFF 금지,
           선후행 공백 금지
EvmAddr  = "0x" + 소문자 hex 40자 (표시용 EIP-55는 UI가 만든다)
Hex16    = 소문자 hex 32자
SecuritySettings = { "version": 1,
                     "llm": { "enabled": bool, "host": string(≤ 300 ASCII, 소문자 host[:port] 또는 ""),
                              "privacy_notice_version": u64 },
                     "genesisPins": { "eip155:<id>": Hash32 },     // HyperEVM 핀 + 사용자 체인 genesisHash
                     "feeCaps": { "eip155:<id>": { "maxFeePerGasGwei": Dec, "maxPriorityFeePerGasGwei": Dec,
                                                    "maxTotalFee": Dec } },
                     "autoLockMinutes": u8(1..=60),
                     "bitcoin": { "indexer": "esplora"|"bb-rpc"|"bb-rest",
                                  "esploraMainnet": EsploraBaseUrl, "esploraTestnet4": EsploraBaseUrl } }
Hash32   = "0x" + 소문자 hex 64자;  Dec = 숫자와 "." 1..=40자
NetworkId = "eip155:" ChainIdDec | "solana:mainnet" | "solana:devnet"
          | "bitcoin:mainnet" | "bitcoin:testnet4"   (SOL·BTC 추가는 해당 체인 문서가 정의)
ChainIdDec = u64 값 1..=2^64−1의 10진 표기, 앞자리 0 없음 (예 "eip155:1", "eip155:11155111", "eip155:999")
```

- EVM 네트워크는 고정 목록이 아니다. 등록된 EVM 체인(D14: 내장 1·11155111·999 + `settings.json`에 정의된 사용자 추가 체인, [04](04-app-ui.md) §6.1)마다 `eip155:<chainId>` 하나다. 등록 가능한 chainId 범위·추가 시 검증은 [03](03-evm.md) §1이 정한다.
- meta 검증은 `eip155:*` 키와 `ConnectedSite.chain_id`의 **형식만** 본다. 레지스트리(평문 settings, 잠긴 동안에도 바뀜)에 없는 chainId도 유효하다. 따라서 사용자 체인을 지워도 meta가 무효가 되지 않는다: `tokens`·`activity`의 그 네트워크 항목은 그대로 보존하고(화면은 등록된 체인만 보이며 같은 chainId를 다시 추가하면 다시 보인다, 전체 상한에는 포함), `connected_sites`의 미등록 `chain_id`는 [05](05-browser.md) §4.3 잠금 해제 규칙이 활성 체인으로 바꾼다.
- 체인 수가 정해져 있지 않으므로 `tokens`·`activity`는 네트워크당 상한과 함께 전체 상한을 둔다. 최악 크기(`ActivityEntry` ≤ 약 1 KiB × 3,000, `TokenEntry` ≤ 약 210바이트 × 1,000)가 meta 평문 8 MiB(§5.2) 안에 든다.

- `address`(계정 목록)는 표시용 캐시다. 받기 주소·QR 표시와 서명은 항상 vault에서 다시 파생한 값을 쓴다. 잠금 해제 직후 yw-app은 `evm_addresses`(§10.3)로 캐시를 다시 계산하고, 다르면 캐시를 고쳐 쓰고 로그에 `MetaAddressMismatch`를 남긴다.
- `address_book`의 `address`는 체인별 정규형(EVM 소문자, SOL base58, BTC 소문자 bech32 또는 base58check)이다. `verified`는 사용자가 다른 경로로 확인했다고 표시한 값이다.
- 주소록 계열(2026-11-06): EVM 항목은 `chain = "evm"` 하나로 **모든 EVM 체인**(내장 7개와 사용자 추가 체인, HyperCore처럼 EVM 주소를 쓰는 화면 포함)이 같이 쓴다 — 주소가 어느 EVM 체인에서나 같기 때문이다. Solana 항목(`"sol"`)은 mainnet·devnet이 같이 쓴다(같은 base58 공개키). Bitcoin 항목(`"btc"`)은 계열 하나지만 mainnet(`bc1…`·`1…`·`3…`)과 testnet4(`tb1…`·`m…`·`n…`·`2…`) 주소가 달라, 보내기 화면은 그 네트워크가 파싱하는 항목만 보인다(값을 나누지 않아 이전 버전과 호환).
- 주소록 이전 규칙(읽을 때, 2026-11-06): `chain`이 `"eip155:<chainId>"`(체인별 EVM 값, 정식 10진 chainId)이고 주소가 `EvmAddr`인 항목은 `"evm"`의 옛 표기로 받아 `"evm"`으로 바꾸고, 같은 (`chain`, `address`)가 여럿이면 **첫 항목**에 합친다: 첫 항목의 라벨·위치를 남기고, 하나라도 `verified`면 `verified = true`, `added_at_unix_ms`는 가장 이른 값. 합친 결과는 다음 meta 저장 때 쓴다. `yw-meta/3` 출시본은 `"evm"|"sol"|"btc"`만 썼으므로 실제 파일에서는 중복 정리만 일어난다. 이 앱은 `"eip155:*"`를 **쓰지 않는다**.
- 이전 버전 호환(확인함, `meta.rs` `valid_book_entry`): 이전 버전은 `AddressBookEntry`의 멤버가 정확히 5개이고 `chain`이 `"evm"|"sol"|"btc"`가 아니면 **meta 문서 전체를 거부**한다(E-VLT-006, `.prev` 복구 화면). 그래서 즐겨찾기를 항목 멤버로 넣지 않고 새 최상위 키 `address_book_favorites`에 두며, 새 `chain` 값(예 체인별 EVM 값, `"btc-testnet4"`)도 쓰지 않는다. 새 계열이 필요하면 `address_book`이 아닌 새 최상위 키로 더한다.
- `ConnectedSite`의 의미와 `origin` 형식(≤ 256바이트 ASCII)은 [05](05-browser.md) §4.1·§4.7이다. 이 절의 상한이 정본이다(D31): `connected_sites` 0..=256개, `accounts` 1..=16개. `accounts`는 dApp에 돌려주는 순서이고 첫 항목이 선택 계정이다. 16개 상한이므로 연결 창([05] §4.2)은 17개 이상 선택하면 `연결`을 비활성화하고, `accountsChanged` payload도 최대 16개다. `granted_at_unix_ms`는 연결을 승인한 시각(Unix ms)이다.
- `tokens`: 레지스트리 토큰([03] §1.2)은 넣지 않는다. 사용자가 S16([04] §2.6)에서 확인한 라벨만 저장한다.
- `activity`: 이 지갑이 보낸 종결 거래만, 체인 문서가 종결 저널 레코드를 정리할 때 만든다. `account`·`counterparty`는 체인별 정규형(위 `address_book`과 같음, 받는 주소가 없으면 `""`; BTC는 계정 0 하나뿐이므로 `account` = `""`, [08] §12.3), `tx_id`는 EVM `0x`+소문자 hex 64, SOL base58 서명, BTC 소문자 hex txid(표시 순서). `title`은 서명 당시 승인 제목(≤ 256바이트, [03] §11.1·[07] §13.3·[08] §10), `asset`은 `"native"` 또는 토큰(EVM `EvmAddr`, SOL mint base58), `amount`는 최소 단위 10진 문자열(≤ 78자, 없으면 `"0"`), `time_unix_ms`는 종결 관측 시각. 상태: EVM `Finalized`(영수증 성공 `succeeded`, 실패 `failed`)·`Dropped`·`Replaced`, SOL `Landed`→`succeeded`·`FailedOnChain`→`failed`·`Expired`→`expired`, BTC `Confirmed`→`succeeded`·`Rejected`·`Replaced`·`Conflicted`·`Abandoned`(나머지는 같은 이름의 소문자). 화면은 표시 전용이다([04] §2.6).
- `ActivityEntry`는 모든 체인이 쓰는 유일한 스키마다. 체인 문서는 필드 대응만 정하고 별도 activity 스키마를 두지 않는다: EVM [03] §5.4; SOL [07] §14.1(`account` = 보낸 주소 from, `tx_id` = base58 서명, `asset` = `"native"`(SOL) 또는 mint base58, `amount` = lamports 또는 토큰 원시 단위, `counterparty` = 받는 주소 to); BTC [08] §12.3.
- meta가 없고 `.prev`도 없으면(첫 실행, 또는 사용자가 지움) 기본 meta(`evm_accounts = [{index 0, label "계정 1"}]`, 나머지 빈 값)로 시작한다. 키 전용 지갑의 기본 meta는 `evm_accounts = []`이고 가져온 키를 해당 목록에 넣는다(라벨 "가져온 계정 n"·"가져온 Solana n"; Bitcoin 키는 `btc_accounts`의 가져온 키 계정으로, 선택된 채).
- 두 선택 키(`sol_raw_accounts`·`sol_raw_selected`)는 [04] §6.6의 "새 최상위 키" 규칙으로 더했다: 이 버전은 없으면 빈 값으로 읽고 항상 `prefs` 뒤에 쓴다. 이전 버전은 모르는 최상위 키로 보존한다. 가져온 Bitcoin 키(`BtcKey` record)는 따로 목록이 없고 선택 최상위 키 `btc_accounts`([08] §12.3a)의 가져온 키 계정(`BtcAccountKey::Single { id = record_id, script_type, pubkey }`, 그 키의 network)과 1:1이다. 잠금 해제 때 yw-app은 `imported_keys`(§10.3)로 가져온 키 목록의 주소 캐시를 다시 계산하고 vault에 없는 항목은 지우며 vault에만 있는 항목은 기본 라벨로 더한다; Bitcoin은 계정이 없는 `BtcKey` record에 계정을 더하고, record가 없거나 키·형식·network가 다른 가져온 키 계정을 지운다(`MetaAddressMismatch` 로그). 그래서 meta 쓰기가 vault 쓰기 뒤에 실패해도, 또는 계정 목록 없이 `BtcKey`만 있는 vault여도 다음 잠금 해제에서 맞춰진다. EVM 키 Bitcoin 계정(`BtcAccountKey::EvmShared { evm_index, script_type, pubkey }`, [08] §3.5)은 vault record가 아니라 이 맞춤의 대상이 아니다(`is_imported()`는 `Single`만): 공개키는 추가할 때 `evm_public_key`로 받아 캐시하고, 서명할 때 vault가 빌려 주는 EVM 키의 공개키와 같지 않으면 `KeyMismatch`로 멈춘다. HD 계정의 주소 방식(기본 고정 주소)의 HD 모드 표시와 EVM·YubiKey 키 Bitcoin 계정은 2026-11-07부터 선택 최상위 키 `btc_accounts_ext`([08] §12.3b)에 쓴다: 이전 앱 버전은 `btc`·`btc_accounts` 안의 모르는 멤버(`single_address`, `key.evm`, `key.yubikey`)를 보면 meta 문서를 거부하기 때문이다. 2026-11-05/06 빌드가 쓴 이전 배치는 읽고 다음 저장에서 옮긴다([04] §6.6).

### 5.4 journal 평문 (이진, `yw_core::journal`, M4)과 롤백

```
off len
0   8   magic        "YWJPL003"
8   2   entry_count  u16 BE, 0..=256
10  6   reserved     0
16  …   entries      entry_count개, 정확히 끝까지 소비(남는 바이트 금지)

entry = kind u8 ‖ body_len u32 BE (1..=1_048_576) ‖ body
kind  = 0x01 EVM ([03](03-evm.md) §5.1, body[0] = record_kind 0x01이어야 함)
      | 0x02 SOL ([07](07-solana.md) §14.1) | 0x03 BTC ([08](08-bitcoin.md) §12.4)
```

- 이 이진 컨테이너가 정본이다. `kind`가 유일한 체인 판별자이고(0x01 EVM, 0x02 SOL, 0x03 BTC), `body`는 체인 문서가 정한 이진 바이트 그대로다(JSON·hex 문자열로 감싸지 않는다). 본문 바이트 배치·상태 기계·종결 정의·정리 순서는 체인 문서가 정한다. entry 순서는 추가 순서이며 의미가 없다. 파일이 없으면 entry 0개다.
- **프레이밍 오류**(magic, `entry_count` 범위, reserved ≠ 0, 알 수 없는 `kind`, `body_len` 범위 밖·남은 길이 초과, 남는 바이트) → `VaultError::SidecarCorrupt(Journal)`, §6.3 선택 대화상자.
- **본문 오류**: 프레이밍은 맞는데 체인 디코더가 본문을 거부하면 그 체인의 보내기만 끄고 "저널 손상"(E-VLT-006, [04] §2.6)을 표시한다([03] §5.1 규칙을 모든 체인에 적용). 자동 삭제하지 않고 다른 entry를 고쳐 쓸 때도 그 본문을 바이트 그대로 보존한다. 다른 체인은 정상 동작한다.
- **개수 상한**: 전체 ≤ 256. SOL ≤ 64([07] §14.2 `SOL_JOURNAL_MAX_RECORDS`), BTC 종결 항목 ≤ 64(진행 중 BTC 항목은 지우지 않음), EVM은 나머지. EVM 몫은 등록된 EVM 체인 수와 무관하게 모든 체인이 함께 쓴다(체인은 본문 `chain_id`, [03](03-evm.md) §5.1). 컨테이너·본문 검증은 체인 레지스트리를 보지 않으므로 미등록 chainId의 레코드도 유효하다.
- **용량 상한**: 평문 ≤ 16 MiB(16,777,216바이트, §5.2). 체인별 최대 본문: EVM 131,761(172 + 255 + 2 + 256 + 4 + 131,072), SOL 1,321(고정 헤더 89 + 트랜잭션 1,232, [07] §14.1), ZEC 32,903(머리 135 + 32,768, [12](12-zcash.md) §12.1), BTC 37,924(238 + 18 + 49 × 100 + 32,768; 레코드 버전 1은 37,906, [08] §12.4).
- **추가 전 검사(서명 전)**: 새 레코드(EVM `Signed` 원본·SpeedUp·Cancel, SOL `Pending`, BTC `Signed`)를 만들 서명 전에 `entry_count + 1 ≤ 256`·체인 상한과 `현재 평문 길이 + 5 + 그 체인 최대 본문 ≤ 16 MiB`를 본다. 넘으면 종결 레코드를 체인 문서의 정리 순서대로(오래된 것부터, activity로 옮긴 뒤) 지우며 다시 보고, 그래도 넘으면 `journal::JournalError::Full`(§10.2)로 차단한다: 서명·전송 없음, 문구 "거래 저널 공간이 부족합니다"([04] §7 오류 표; EVM은 [03] §5.4의 E06 거부와 같은 경로).

**롤백은 막지 않는다(알아챌 수 있게만 한다).** vault·meta·journal을 이전 세대 파일로 바꿔치기하는 것은 거부하지 않는다. 파일 쓰기 권한이 있는 공격자는 §2.2 비목표(PC 장악)이고, 사용자가 직접 예전 사본을 복원하는 경우도 정상 동작으로 본다. `generation`은 동시 쓰기 충돌(CAS)과 `.prev` 구분에 쓰고, 다음 두 가지로 되감기를 보이게 한다(2026-11-01 검토 L17): (1) 잠금 화면과 설정 → 보안에 `vault.ywv`의 `generation`과 마지막 저장 시각을 표시한다. (2) meta의 `vault_generation_seen`(§5.3, AEAD로 보호)이 본 파일의 generation보다 크면 잠금 해제 뒤 배너로 알린다. `vault.ywv`만 되돌린 경우는 이렇게 드러나고, vault·meta를 같은 백업에서 함께 되돌린 경우는 드러나지 않는다(서로 맞는 옛 상태라 구분할 근거가 없다).

## 6. 파일 쓰기와 손상 처리

### 6.1 파일

`%LOCALAPPDATA%\YourWallet\v3\`(spec §4.3)의 `<name>` ∈ {`vault.ywv`, `meta.ywm`, `journal.ywj`}마다 본 파일, 직전 세대 정확히 하나(`<name>.prev`), 쓰기 중 임시 파일(`<name>.tmp`, `<name>.prev.tmp`), 격리된 손상 파일(`<name>.corrupt-<unix초>`, 삭제하지 않음)을 둔다.

### 6.2 저장소 계약

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKind { Vault, Meta, Journal }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StorageError { NotFound, AlreadyExists, GenerationConflict, Corrupt, TooLarge, Io(u32) }

pub trait VaultStorage: Send {
    fn load(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError>;
    fn load_prev(&self, kind: FileKind) -> Result<Option<Vec<u8>>, StorageError>;
    /// expected_generation = None: 본 파일이 없어야 한다. Some(g): 본 파일 generation == g.
    fn commit(&mut self, kind: FileKind, expected_generation: Option<u64>, bytes: &[u8])
        -> Result<(), StorageError>;
    /// 본 파일을 `<name>.corrupt-<now_unix>`로 이름 변경(덮어쓰기 금지).
    fn quarantine(&mut self, kind: FileKind, now_unix: u64) -> Result<(), StorageError>;
}
/// 구조 검사(§4.5 1–7, §5.2)를 통과하면 generation, 아니면 None.
pub fn peek_generation(kind: FileKind, bytes: &[u8]) -> Option<u64>;
/// vault.ywv의 §4.5 1–7(KDF 없음): generation 또는 그 단계의 오류(`Malformed`·`UnsupportedVersion`·`UnsupportedParams`).
pub fn check_vault_header(bytes: &[u8]) -> Result<u64, VaultError>;
```

yw-app이 yw-win 파일 함수로 구현한다(출처: 데모 원자적 쓰기, §12). `commit` 절차(반드시):

1. 본 파일을 읽는다. `None`이면 본 파일이 없어야 한다(있으면 `AlreadyExists`). `Some(g)`이면 `peek_generation == Some(g)`여야 한다. 해석 불가면 `Corrupt`, 다르면 `GenerationConflict`. **이 경우 아무것도 쓰지 않는다.**
2. 본 파일이 있으면 그 바이트를 `<name>.prev.tmp`에 쓰고 → `FlushFileBuffers` → `MoveFileExW(<name>.prev.tmp, <name>.prev, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
3. 새 바이트를 `<name>.tmp`에 `CREATE_NEW`로 쓰고 → `FlushFileBuffers` → 닫기.
4. `MoveFileExW(<name>.tmp, <name>, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)`.
5. 부모 디렉터리 flush(데모 `DurableParentDirectory`). 실패는 오류다(1 전에도 한 번 flush해 보고 실패하면 아무것도 쓰지 않는다; 4 뒤의 실패는 아래 "반영됐지만 실패로 보고된 커밋" 규칙을 따른다).
6. 본 파일을 다시 읽어 바이트가 같지 않으면 `Io`. 호출자는 메모리 상태(generation 등)를 커밋 성공 후에만 갱신한다.

- **반영됐지만 실패로 보고된 커밋:** 4 뒤의 실패(예: 6의 다시 읽기 오류)는 이미 본 파일이 바뀐 상태다. `Vault`는 `commit` 오류마다 본 파일을 다시 읽어 방금 쓴 바이트와 같으면 성공으로 본다(쓰기마다 새 난수 nonce라 같은 바이트는 이 커밋에서만 나온다). 그래서 메모리의 generation·vault 바이트가 디스크보다 뒤처져 다음 CAS가 영구히 실패하는 일이 없다(생성·가져오기·`PayloadRewrite`·`Rewrap`·복구·사이드카 모두).

- 2와 4 사이에 중단되면 `.prev`와 본 파일이 같은 세대다(허용). 4 전에 중단되면 본 파일은 이전 세대 그대로다.
- 시작 시 `*.tmp` 고아 파일은 지운다. 이동 전 임시 파일은 커밋된 적 없는 내용이므로 유일한 사본이 아니다.
- 임시 파일은 같은 디렉터리(같은 볼륨)에 만든다. 파일 ACL은 `%LOCALAPPDATA%` 상속(현재 사용자)을 그대로 쓴다.
- **재분석 지점(심볼릭 링크·정션) 거부(2026-11-01 검토 L8):** 폴더, 본 파일, `<name>.prev`가 재분석 지점이면 `load`·`load_prev`는 링크를 따라가지 않고 오류 `Io(0x1126)`(yw-app이 재분석 지점 거부에 쓰는 고정 코드)를 돌려주고, `commit`은 1에서 아무것도 쓰지 않고 실패한다. 읽기는 `FILE_FLAG_OPEN_REPARSE_POINT`로 연 핸들의 속성을 확인한 뒤 읽는다(확인과 읽기 사이 틈 없음). 데이터 폴더의 ACL 검사([04] §1.4-3)는 재분석 지점의 대상을 보지 않으므로 이 거부가 폴더 DACL 보장을 그 파일들에 잇는다.

### 6.3 시작 시 분류 (`Vault::load`)

| 디스크 상태 | `VaultStatus` | 허용 동작 |
|---|---|---|
| `vault.ywv` 구조 정상 | `Locked` | 잠금 해제 |
| `vault.ywv` 구조 손상(§4.5 1–7 실패: `Malformed`·`UnsupportedVersion`·`UnsupportedParams`) | `Corrupt { prev_available }` | `.prev`로 복구, 또는 앱 종료 |
| `vault.ywv` 없음, `.prev` 있음 | `MainMissing` | `.prev`로 복구 |
| 둘 다 없음(`.tmp`만 있거나 아무것도 없음) | `NoVault` | 생성·가져오기 |

- **손상 파일은 절대 덮어쓰지 않는다.** 생성·가져오기는 `NoVault`에서만 가능하다. 다른 지갑으로 바꾸려면 사용자가 폴더의 파일을 직접 옮긴다(앱은 폴더 경로만 보여준다, [04](04-app-ui.md) §2.2·§2.14).
- `recover_from_prev(password)`: `.prev`를 잠금 해제한다. 성공하면 본 파일이 있을 경우 `quarantine` → `.prev` 내용을 `PayloadRewrite`(generation = prev.generation + 1)로 `commit(Vault, None, …)` → `Unlocked`/`BackupPending`. 본 파일에 있던 더 새로운 변경(예: 추가한 raw key)은 잃는다고 UI가 알린다. 격리한 파일 이름(`vault.ywv.corrupt-<now_unix>`, `quarantined_at()`)을 UI가 그대로 보여 주어 사용자가 직접 되돌릴 수 있게 한다([04] §2.15, `docs/recovery-guide.ko.md`).
- payload 인증 실패(`PayloadCorrupt`)는 잠금 해제 시점에 드러난다. 이때도 본 파일은 그대로 두고 `.prev` 복구를 제안한다. 헤더는 정상이라 다시 `load`하면 `Locked`가 되므로, yw-app은 이 상태를 기억해 S09(복구 화면)를 유지한다([04] §2.5).
- **`Locked`에서의 복구(사용자의 명시적 요청):** 키 구간(`header[0..130]`)이 손상되면 `unlock`은 비밀번호 오류와 구분할 수 없는 `UnlockFailed`만 낸다(§7.4). 그래서 `recover_from_prev`는 `Locked`에서도 받는다. 이때는 먼저 본 파일을 같은 비밀번호로 연다: 열리면 **아무것도 복구하지 않고** `unlock`과 똑같이 세션을 연다. 본 파일이 열리지 않을 때(`UnlockFailed`·`PayloadCorrupt`·구조 오류·없음)만 `.prev`를 같은 비밀번호로 열어 위 절차로 복구한다. 틀린 비밀번호는 두 파일 모두 실패해 `UnlockFailed`이고 어떤 파일도 바뀌지 않는다(Argon2 최대 2회).
- meta·journal: 구조 손상이나 `SidecarCorrupt`(journal 프레이밍 오류 포함, §5.4)면 해당 파일 쓰기를 멈추고 사용자에게 (a) `.prev` 사용, (b) 격리 후 새로 시작 중 하나를 고르게 한다(E-VLT-006, [04] §2.5). journal 새로 시작은 "진행 중 거래 기록이 사라질 수 있음" 경고 후에만 한다. 파일이 없는 것은 손상이 아니다(§5.3 기본값, journal은 entry 0개).

## 7. 잠금 상태 기계

### 7.1 상태

| 상태 | 메모리의 비밀 | 가능한 것 |
|---|---|---|
| `NoVault` | 없음 | 생성, 가져오기, 개인키로 시작(§8.5) |
| `Locked` | 없음 | 잠금 해제 |
| `PassphraseRequired` | DEK | passphrase 입력, 잠금 |
| `PassphraseMismatch` | DEK, 입력한 passphrase | 다시 입력, 확인 후 계속, 잠금 |
| `BackupPending` | DEK | 받기 주소 표시, 니모닉 표시(비밀번호 재입력), 백업 확인, 비밀번호 변경(`change_password`, §4.4). **서명·개인키 표시·raw key 가져오기 불가** |
| `Unlocked { alt_passphrase }` | DEK, (`passphrase_used`이면) passphrase | 모든 기능 |
| `Corrupt`, `MainMissing` | 없음 | `.prev` 복구 |

### 7.2 전이

| 현재 | 호출 | 조건 | 다음 |
|---|---|---|---|
| `NoVault` | `create_wallet` | 비밀번호 규칙 통과, 커밋 성공 | `BackupPending` |
| `NoVault` | `import_mnemonic` | 커밋 성공 | `Unlocked { alt: false }` |
| `NoVault` | `create_with_key` | 커밋 성공 | `Unlocked { alt: false }` (키 전용 vault) |
| `Locked` | `unlock` | 성공 | `Bip39` 없음(키 전용) → `Unlocked { alt: false }`; `passphrase_used = 1` → `PassphraseRequired`; 아니면 `backup = 0` → `BackupPending`, `backup = 1` → `Unlocked { alt: false }` |
| `Locked` | `unlock` | 실패 | `Locked` (`UnlockFailed` 등) |
| `Locked` | `unlock` | `PayloadCorrupt`(§6.3) | `Corrupt { prev_available }` (본 파일은 그대로, `.prev` 복구 제안) |
| `PassphraseRequired` | `enter_passphrase` | 확인값 일치 | `Unlocked { alt: false }` |
| `PassphraseRequired` | `enter_passphrase` | 확인값 불일치 | `PassphraseMismatch` |
| `PassphraseMismatch` | `retry_passphrase` | — | `PassphraseRequired`(입력값 소거) |
| `PassphraseMismatch` | `accept_mismatched_passphrase` | — | `Unlocked { alt: true }` |
| `BackupPending` | `confirm_backup` | 일치, 커밋 성공 | `Unlocked { alt: false }` |
| `PassphraseRequired`, `PassphraseMismatch`, `BackupPending`, `Unlocked` | `lock` | — | `Locked` |
| `Corrupt`, `MainMissing` | `recover_from_prev` | 성공 | `unlock`과 같은 규칙(`BackupPending`·`Unlocked`·`PassphraseRequired`) |
| `Locked` | `recover_from_prev` | 본 파일이 열림 | 복구 없이 `unlock`과 같은 규칙 |
| `Locked` | `recover_from_prev` | 본 파일이 안 열리고 `.prev`가 열림 | 복구 후 `unlock`과 같은 규칙 |

- 커밋 실패 시 상태는 바뀌지 않는다(생성·가져오기 실패는 `NoVault` 유지, 메모리 비밀 소거).
- `lock`: 슬롯 전체를 `zeroize`하고 슬롯을 해제(yw-win이 VirtualUnlock·VirtualFree)하며, 백업 challenge와 보관 중인 vault 바이트를 버린다. 진행 중 승인·비밀 창 취소는 [04](04-app-ui.md) §5.3·[05](05-browser.md) §4.4.
- `Vault`의 `Drop`은 `lock`을 부른다(작업자 종료, `Load`로 교체될 때 등). 슬롯 소거 계약: `Vault`는 슬롯을 놓기 전에 언제나 전체를 0으로 쓴다(`lock`, 슬롯을 받은 작업의 실패, 새 세션이 이전 슬롯을 대체할 때, `Vault` drop). `LockedSlot` 구현은 자체 drop에서 지우지 않아도 된다(yw-app `LockedBox`는 그래도 지운다).
- 잠금 계기(D12, yw-app이 `lock()` 호출): 유휴 10분(설정 1–60분), `WM_WTSSESSION_CHANGE`/`WTS_SESSION_LOCK`, `WM_POWERBROADCAST`/`PBT_APMSUSPEND`(최대 절전 이미지에 DEK가 남지 않게 절전 전에 소거), 수동 잠금, 앱 종료. 코어에는 타이머가 없다.
- `Vault`는 `Send`이며 `Sync`가 아니다. yw-app은 코어 작업 스레드 하나에서만 호출하고, Argon2가 드는 호출(`create_wallet`, `import_mnemonic`, `unlock`, `reveal_*`, `change_password`, `remove_evm_raw_key`, `recover_from_prev`)을 UI 스레드에서 실행하지 않는다. `lock` 요청은 큐 맨 앞에 넣는다.

### 7.3 메모리 규칙 (D10)

```rust
/// 배치: [0..32) DEK, [32] passphrase 존재 0/1, [33..35) passphrase 길이 u16 BE(0..=256),
///       [35..291) passphrase 바이트, [291..320) 0
pub const SLOT_LEN: usize = 320;
/// yw-app이 yw-win의 VirtualLock 페이지로 구현한다(어댑터 newtype; yw-win은 yw-core에 의존하지 않음).
pub trait LockedSlot: Send {
    fn bytes(&self) -> &[u8; SLOT_LEN];
    fn bytes_mut(&mut self) -> &mut [u8; SLOT_LEN];
}
```

- 세션 동안 메모리에 두는 지갑 비밀은 이 슬롯뿐이다. D10에 따라 DEK와 passphrase를 이 슬롯에 둔다. RPC·LLM API 키는 지갑 비밀이 아니며 이 규칙 밖이다(D10, [04] §6.3).
- 슬롯 밖에 두는 것: 현재 vault 파일 바이트(암호문, 비밀 아님), 헤더 필드.
- 비밀이 필요한 모든 작업의 절차(반드시, 캐시 없음):
  1. 상태 확인(서명 계열은 `Unlocked`만, 아니면 `BackupNotConfirmed` 또는 `InvalidState`).
  2. 슬롯의 DEK로 보관 중인 vault 바이트의 payload를 `Zeroizing` 버퍼에 복호화하고 디코드한다.
  3. 필요한 키만 파생한다: `Mnemonic` → `to_seed(passphrase)` → `secp_context` → `XPriv::from_seed` → `derive_path` → `SecretKey`(또는 raw record의 key). Ed25519는 `to_seed` 뒤 §3.5 `SolKeySource` 표대로 32바이트 seed.
  4. 사용한다(서명·주소 계산).
  5. `SecretKey::non_secure_erase`, 시드·평문·중간값 `Zeroizing` drop.
- 디코드한 `Payload.raw_keys`는 처음부터 용량 15(`MAX_RAW_KEYS`)로 잡는다. `push`가 재할당하면 이전 버퍼(키 사본 포함)가 지워지지 않고 해제되기 때문이다. `retain`은 레코드를 앞으로 옮기며 `len` 뒤에 사본을 남기므로 `Payload`의 `Drop`은 살아 있는 레코드가 아니라 **용량 전체**를 지운다.
- 비용 기준: PBKDF2 2048회 + 파생은 release에서 수 ms다. 주소 여러 개는 시드를 한 번만 계산한다(`evm_addresses`).
- 페이징·최대 절전: 슬롯은 VirtualLock으로 pagefile에서 제외되고 절전 전 소거된다. 짧게 존재하는 평문·키 버퍼는 일반 힙이며 BitLocker로 완화한다. VirtualLock·슬롯 할당이 실패하면 잠금 해제하지 않는다(E-VLT-007, [04](04-app-ui.md) §2.5).

### 7.4 잠금 해제 실패

- `UnlockFailed`의 화면 문구는 하나다: **"비밀번호가 올바르지 않거나 vault 파일이 손상되었습니다."** 비밀번호 오류와 키 구간 변조를 구분하지 않는다.
- 실패 후 1초 동안 yw-app이 입력과 확인 버튼을 비활성화한다([04](04-app-ui.md) §2.5; 코어는 시간을 다루지 않는다). `reveal_*`·`change_password`·`remove_evm_raw_key`의 비밀번호 확인 실패에도 같다.
- **실패 횟수 제한·잠금 카운터는 두지 않는다.** 방어 대상인 디스크 도난 공격자는 파일을 복사해 오프라인으로 시도하므로 앱 안의 카운터를 거치지 않고, 그 비용은 Argon2(256 MiB, t=3)가 정한다. 같은 사용자 악성코드는 §2.2 비목표다. 디스크에 둔 카운터는 파일 접근자가 되돌릴 수 있고, 정상 사용자만 잠가 버린다.
- Argon2 1회 시간은 release 빌드에서 대상 PC로 측정해 [09](09-testing.md) 기록에 남긴다(구현 시 확인; argon2 0.5.3는 `parallel` 기능 없이 lane을 순차 계산한다).

### 7.5 passphrase 확인

- `enter_passphrase(pp)`: `pp`가 비면 `KeyError::PassphraseEmpty`(`passphrase_used` vault에서 빈 passphrase는 받지 않음). `addr0 = EVM 계정 0 주소(pp)`, `SHA-256(addr0)[0..4]`를 저장값과 상수 시간 비교한다.
- 불일치 → `PassphraseMismatch`. UI는 **"passphrase가 다를 수 있습니다"** 대화상자에 [다시 입력]과 [이 passphrase로 계속]을 보여준다. 계속은 "다른 passphrase는 다른(빈) 지갑을 엽니다" 확인 체크를 켠 뒤에만 활성화된다([04](04-app-ui.md) §2.5).
- `Unlocked { alt_passphrase: true }` 세션: 코어에서는 서명 포함 모든 기능이 동작한다. 그러나 이 passphrase는 오타일 수 있고, 이 지갑으로 받은 자산은 대소문자·공백까지 같은 passphrase로만 다시 꺼낼 수 있다. 그래서 yw-app은 모든 화면에 닫을 수 없는 경고 띠 T-ALT-PASS를 보이고, **받기(S12, 모든 체인)와 브라우저 연결·서명을 막는다**(`App::passphrase_unverified()`, [04] §2.1·§2.5; dApp 연결·서명은 4100 `PassphraseUnverified`, 읽기는 계속, [05] §5). 앱 자신의 보내기는 허용한다(일부러 다른 passphrase 지갑을 쓰는 경우 자산을 옮길 수 있게). meta는 디스크에서 읽지도 쓰지도 않고 메모리 기본 meta(§5.3)로 동작한다. journal은 정상 저장한다(진행 중 거래 보호). 확인값은 바꾸지 않는다.

## 8. 생성·가져오기·백업 확인

### 8.1 생성 (`create_wallet`)

1. `NoVault`가 아니면 `InvalidState`.
2. `Mnemonic::generate_with_rng`(32바이트, 첫 난수 추출).
3. DEK·`vault_id`·`record_id`·`kdf_salt`·`wrap_nonce`·`payload_nonce` 추출, Argon2 → KEK → `Create` 인코드 → 자체 검사 → `commit(Vault, None, …)`.
4. DEK를 슬롯에 넣고 `BackupPending`. 24단어 `Zeroizing<String>`을 반환한다(첫 표시용, 이후 표시는 §9).

- 생성 지갑은 BIP39 passphrase를 쓰지 않는다(`passphrase_used = 0`, `backup_state = 0`). passphrase는 가져오기에서만 쓴다(D29). 이유: passphrase 오타는 복구 불능 손실의 주원인이고, 생성 직후 백업 확인이 passphrase 없는 계정 0 주소를 기준으로 한다.
- yw-app은 커밋 후 기본 meta(gen 1)를 쓴다. meta 쓰기가 실패해도 vault는 유효하다(다음 잠금 해제 때 기본 meta로 다시 시작).

### 8.2 가져오기

- `import_mnemonic(password, phrase, passphrase: Option<Bip39Passphrase>, slot, now_unix)`: `NoVault`에서만. `Mnemonic::parse`(12/15/18/21/24단어). `passphrase`가 `Some`이면 비어 있지 않아야 하고(비면 `KeyError::PassphraseEmpty`), `passphrase_used = 1`로 두고 `passphrase_check`를 계산해 저장한다. `backup_state = 1`(Confirmed): 사용자가 이미 가진 니모닉이다. 결과 `Unlocked { alt: false }`.
- passphrase 두 번 입력·일치 확인은 UI가 한다([04](04-app-ui.md) §2.4). 커밋 전 첫 주소 확인(S06)은 vault 없이 `preview_evm_address`(§10.3)로 한다.
- `import_evm_private_key(hex, now_unix) -> RecordId`: `Unlocked`에서만, 비밀번호 재입력 없음.
  - 형식: 선택적 `"0x"`(소문자 x만) + 정확히 64자 `[0-9a-fA-F]`. 공백·`0X`·63/65자·비hex 거부. 값은 1 ≤ k < n. 위반은 `InvalidPrivateKey`.
  - 이미 있는 raw key와 같으면 `DuplicateKey`, raw key가 15개면 `RecordLimit`. 결과는 `PayloadRewrite`.
  - 입력 문자열 버퍼는 호출자(UI)가 `Zeroizing`으로 소유한다. 코어는 디코드한 32바이트를 `Zeroizing`에만 둔다.
- `remove_evm_raw_key(password, id)`: `Unlocked`에서만, 비밀번호 재입력(KEK 파생으로 확인) 필요, `PayloadRewrite`. `Bip39` record는 삭제할 수 없다. EVM이 아닌 record id는 `RecordNotFound`, 키 전용 vault의 마지막 키는 `LastKey`(§8.4).

### 8.4 가져온 개인키 (EVM·Solana·Bitcoin, D9)

```rust
// yw_core::keyimport
pub enum ImportChain { Evm, Sol, Btc }
pub enum ImportSpec { Evm, Sol, Btc(btc::ScriptType) }   // ScriptType: P2pkh 1, P2shP2wpkh 2, P2wpkh 3, P2tr 4 ([08] §3.5)
pub struct ImportKey { /* Zeroizing 비밀, Clone 없음, Debug "ImportKey(<체인>, [REDACTED])" */ }
impl ImportKey {
    pub fn parse(spec: ImportSpec, text: &str) -> Result<Self, KeyError>;
    pub fn chain(&self) -> ImportChain;
    pub fn preview(&self) -> Result<ImportPreview, KeyError>;   // 저장 없이 주소만
}
pub enum ImportPreview { Evm(Address), Sol(SolAddress), Btc(BtcKeyInfo) }
pub struct BtcKeyInfo { pub network: BtcNetwork, pub script: ScriptType, pub compressed: bool,
                        pub public_key: BtcPubKey /* 33 또는 65바이트 */, pub kind: ScriptKind, pub address: String }
impl BtcKeyInfo { pub const fn account_key(&self, id: [u8; 16]) -> Result<BtcAccountKey, AccountKeyError>; } // Single
pub const MAX_IMPORTED_PER_CHAIN: usize = 15;
pub const SOL_KEY_TEXT_MAX: usize = 640;
// yw_core::codec::wif
pub fn parse_wif(text: &str) -> Result<WifKey, KeyError>;   // compressed(), network(); secret은 crate 내부
```

모든 파서: 앞뒤 ASCII 공백·탭·CR·LF는 무시하고, ASCII만 받으며, 디코드한 비밀은 `Zeroizing`에만 두고, 오류에 입력을 담지 않는다. 입력 문자열 버퍼는 UI가 `Zeroizing`으로 소유한다.

| 체인 | 형식 | 거부 |
|---|---|---|
| EVM | §8.2와 같음(선택 `0x` + hex 64자, 1 ≤ k < n) | `InvalidPrivateKey` |
| Solana | base58 64바이트 keypair(`seed ‖ public`) 또는 `solana-keygen` JSON 배열(10진 0–255 정확히 64개), 텍스트 ≤ 640바이트 | 32바이트 → `SolKeyIsAddress`, 공개키 불일치 → `SolKeyMismatch`, 그 밖 → `SolKeyFormat` ([07] §3.4) |
| Bitcoin | WIF: base58check 51자(`version ‖ secret`, 압축 안 함) 또는 52자(`version ‖ secret ‖ 01`, 압축). `version` 0x80 = mainnet, 0xef = 테스트넷(이 지갑에서는 testnet4). secret 1 ≤ k < n. 주소 형식은 사용자가 고른다(`btc::ScriptType`) | 길이·문자·체크섬·version·접미사·범위 → `WifFormat`; 압축 안 한 키 + P2PKH 외 형식 → `WifUncompressedScript` |

- Bitcoin 주소(`keyimport::btc`): P2PKH `HASH160(pubkey)`(압축 33 또는 비압축 65바이트), P2SH-P2WPKH `HASH160(00 14 ‖ HASH160(pubkey33))`, P2WPKH `HASH160(pubkey33)`, P2TR BIP86 key-path 출력 키 `x(P + H_TapTweak(x(P))·G)`(스크립트 트리 없음). 주소 문자열은 [08] `encode_address`. 64자 hex 원시 비밀은 네트워크를 알 수 없으므로 받지 않는다(WIF만).
- `import_key(key, now_unix) -> RecordId`: `Unlocked`에서만(`BackupPending`은 `BackupNotConfirmed`), 비밀번호 재입력 없음, `PayloadRewrite`. 체인마다 15개(`RecordLimit`). 중복(`DuplicateKey`): EVM은 같은 키, Solana는 같은 공개키, Bitcoin은 (secret, compressed, network, script)가 모두 같을 때(같은 키를 다른 형식으로 다시 가져오는 것은 다른 주소의 다른 계정이다). 파생 계정과 같은 키를 가져오는 것은 막지 않는다. `import_evm_private_key(hex)`는 §8.2 형식 그대로 `import_key(Evm)`를 부른다.
- `remove_imported_key(password, id) -> ImportChain`: `Unlocked`, 비밀번호 재입력, `PayloadRewrite`. 어느 체인의 가져온 키든 지운다. `Bip39` record는 지울 수 없다. 지운 뒤 record가 0개가 되면(키 전용 vault의 마지막 키) `LastKey`이고 아무것도 쓰지 않는다. **vault가 가져온 키 계정의 진실 원천이다:** Bitcoin 키를 지운 뒤 meta `btc_accounts` 쓰기가 실패해도 yw-app 키 작업자는 그 계정을 세션에서 지우고(쓰기 오류는 알림), `has_btc_key`가 `false`인 단일 키 계정에는 받기 주소(`ReceiveAddress`·`NewReceiveAddress`)를 내주지 않으며 meta에 다시 쓰지 않는다([08] §3.5).
- `reveal_imported_key(password, id) -> (ImportChain, SecretString)`(§9): EVM 소문자 hex 64자(`0x` 없음), Solana base58 64바이트 keypair, Bitcoin WIF(가져온 그대로의 압축 여부·network).
- `imported_keys() -> ImportedKeys`(`BackupPending`·`Unlocked`): `has_mnemonic`, EVM `(RecordId, Address)`, Solana `(RecordId, 공개키)`, Bitcoin `(RecordId, BtcKeyInfo)`를 payload 순서로. meta 캐시 재계산(§5.3)에 쓴다.
- 서명: EVM은 `KeyRef::Evm(EvmKeySource::Raw(id))`, Solana는 `with_imported_ed25519_seed(public, f)`([07] §3.4), Bitcoin은 `btc::sign::sign_plan(&Vault, ..)`이 입력마다 `BtcKeySource::Imported { id, script_type, compressed }`(가져온 키 계정의 입력)를 crate 내부 `BtcImportedKeys::btc_imported_secret(id)`(→ `Vault::imported_btc_secret`, `pub(crate)`, `Unlocked`만)로 받는다: tag 4 record의 비밀키를 record의 압축·network·형식과 함께 `ImportedBtcSecret`(복제 없음, `Debug` 가림, drop 때 지움)으로 감싸 서명 클로저에만 빌려 주고, 계정의 network·형식·압축과 다르면 `KeyMismatch`, record가 없으면 `RecordNotFound`다([08] §3.5, §11.1). `KeyRef`에는 가져온 Bitcoin 키가 없다.
- 가져온 키는 니모닉 밖에 있다(D29): 복구 단어로 복구되지 않고 각 키의 백업은 원래 개인키다. UI는 가져오기 창 W07과 계정 목록에 이 사실을 보인다([04] §2.18).

### 8.5 개인키로 시작 (키 전용 vault)

- `create_with_key(password, key: ImportKey, slot, now_unix) -> RecordId`: `NoVault`에서만. `Create` 쓰기(§4.4)로 `Bip39` 없이 `key` 하나만 담은 vault를 만들고 `Unlocked { alt: false }`. 백업 확인 단계가 없다(백업은 원래 개인키). 실패 시 `NoVault` 유지, 슬롯 소거.
- 커밋 전 주소 확인은 vault 없이 `ImportKey::preview()`로 한다([04] §2.18 S19).
- 키 전용 vault에서 `seed`가 필요한 모든 호출은 `NoMnemonic`: `evm_address(Derived)`, `evm_addresses`(빈 목록은 빈 결과), `btc_account_xpub`, `btc_public_key`, `sol_public_keys`(파생 출처, 빈 목록은 빈 결과), `with_ed25519_seed`, `reveal_mnemonic`, `enter_passphrase`. `backup_challenge`·`confirm_backup`은 상태(`Unlocked`)가 맞지 않아 `InvalidState`.
- 다른 체인의 키는 `import_key`로 더한다. 니모닉을 나중에 더하는 기능은 없다(복구 단어로 시작하려면 새 vault를 만든다).
- `has_mnemonic()`(`BackupPending`·`Unlocked`)이 false면 yw-app은 파생 기능(계정 추가, 다른 경로 스캔, 복구 단어 보기, 파생 Bitcoin 계정)을 숨긴다([04] §2.18).

### 8.3 백업 확인 (아카이브 이식, 변경 포함)

```rust
pub struct ChallengeId([u8; 16]);
pub struct BackupChallenge { pub id: ChallengeId, pub positions: [u8; 4] } // 1-based, 오름차순, 서로 다름
```

- 백업 화면([04](04-app-ui.md) §2.3 W08)은 24단어와 함께 계정 0 EVM 주소(EIP-55)를 보여주고, 사용자는 둘 다 종이에 적는다. 주소는 나중에 복구가 같은 지갑인지 확인하는 데 쓴다(`docs/recovery-guide.ko.md`).
- `backup_challenge()`: `BackupPending`에서만. 단어 수 w(생성 지갑은 24) 중 4개 위치를 부분 Fisher–Yates로 고른다: `for o in 0..4 { j = o + random_below(w − o); swap(o, j) }`, 앞 4개를 1-based로 바꿔 정렬. `random_below(u)`는 `u32` 거부 표본추출(`acceptance = u32::MAX − (u32::MAX % u)`, 그 이상이면 다시 뽑음). 새 challenge는 이전 challenge를 무효로 한다.
- `confirm_backup(id, words: [&str; 4])`:
  1. `BackupPending`이 아니면 `InvalidState`. `id`가 현재 challenge가 아니면 `ChallengeStale`.
  2. 형식: 각 단어 1–8바이트 `[a-z]`. 위반도 `BackupMismatch`로 처리한다.
  3. 4개 단어를 `word_at(position)`과 비교한다. 4개 비교를 모두 상수 시간으로 수행해 합친 뒤 한 번에 판정한다. 주소는 묻지 않는다(W08에 적어 두는 것은 복구 확인용이다).
  4. 불일치 → `BackupMismatch`, challenge 폐기(UI는 새 challenge를 요청). 시도 횟수 제한 없음.
  5. 일치 → `backup_state = 1`로 `PayloadRewrite` → `Unlocked { alt: false }`.
- 아카이브 대비 변경: 계정 0·1 주소 영속 레코드 대신 매번 재파생, 주소 입력 없음(단어 4개만), 단어 최대 길이 16 → 8, 일회성 표시 능력 토큰·deadline 제거, passphrase 지갑은 이 흐름에 들어오지 않음(디코드 규칙으로 보장).

## 9. 비밀 표시 (reveal)

| 함수 | 허용 상태 | 반환 형식 |
|---|---|---|
| `reveal_mnemonic(password)` | `BackupPending`, `Unlocked` | `SecretString`(`Debug` 가림, §10.3), 단어를 공백 하나로 연결 |
| `reveal_evm_private_key(password, src)` | `Unlocked` | `SecretString`, 소문자 hex 64자, `0x` 없음 |
| `reveal_imported_key(password, id)` | `Unlocked` | `(ImportChain, SecretString)`: EVM hex 64자, Solana base58 64바이트 keypair, Bitcoin WIF(§8.4) |
| `reveal_evm_shared_wif(password, index, network)` | `Unlocked` | `SecretString`: EVM 계정 index의 키(m/44'/60'/0'/0/i)를 압축 WIF로(network 버전 바이트) — EVM 키 Bitcoin 계정의 `개인키 보기`([08] §3.5). 같은 비밀은 `reveal_evm_private_key`의 hex이기도 하다 |

- 잠금 해제 상태여도 매번 비밀번호를 다시 받는다: 현재 vault 바이트의 `kdf_salt`로 Argon2 → KEK → `wrapped_dek` 복호화. 실패는 `UnlockFailed`(§7.4 규칙). 성공하면 풀린 DEK와 슬롯의 DEK를 상수 시간 비교하고, 다르면 `UnlockFailed`.
- passphrase는 표시하지 않는다(저장하지 않음). 파생(니모닉) Solana·Bitcoin 개인키 표시는 없다. 가져온 Solana·Bitcoin 키는 `reveal_imported_key`로 가져온 형식 그대로 내보낸다(삭제 전 내보내기, [04] §2.18).
- 반환 버퍼는 UI가 비밀 창에 직접 그린 뒤 drop한다. 일반 `String`으로 복사하거나 로그·클립보드(복사 토글 제외, D11)로 보내지 않는다([04](04-app-ui.md) §4).

## 10. 오류와 공개 API

### 10.1 비밀번호

```rust
// yw_core::password (Bip39Passphrase는 §2.2)
pub const PASSWORD_MIN: usize = 12;
pub const PASSWORD_MAX: usize = 128;
pub struct VaultPassword(Zeroizing<Vec<u8>>);
impl VaultPassword {
    /// 바이트 각각 0x20..=0x7E, 길이 12..=128 (D8). 대소문자·공백 그대로, 정규화 없음.
    pub fn new(input: &[u8]) -> Result<Self, KeyError>;
}
```

강도 검사(사전·zxcvbn)는 하지 않는다. 두 번 입력 일치는 UI가 확인한다.

### 10.2 오류

```rust
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    RandomnessUnavailable,
    PasswordTooShort, PasswordTooLong, PasswordInvalidChar,
    PassphraseTooLong, PassphraseInvalidChar, PassphraseEmpty,
    MnemonicFormat, MnemonicWordCount, MnemonicUnknownWord { position: u8 }, MnemonicChecksum,
    InvalidEntropyLength,
    InvalidPath, InvalidAccountIndex, DerivationFailed,
    InvalidPrivateKey,
    InvalidExtendedKey,          // decode_xkey 거부(§3.4, 테스트용 API에서만)
    SolKeyFormat, SolKeyIsAddress, SolKeyMismatch,   // §8.4 Solana
    WifFormat, WifUncompressedScript,                // §8.4 Bitcoin
    Internal,                    // 라이브러리가 예상 밖 오류 반환, 단어 목록 분할 실패
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultError {
    Key(KeyError),
    Storage(StorageError),
    InvalidState,
    Malformed, UnsupportedVersion, UnsupportedParams,
    UnlockFailed,                // 비밀번호 오류 또는 키 구간 변조
    PayloadCorrupt,              // payload AEAD 인증 실패(손상, `.prev` 복구 제안)
    UnsupportedPayload,          // 인증된 payload를 이 빌드가 디코드하지 못함(새 버전의 tag 등, `.prev` 제안 없음)
    SidecarCorrupt(FileKind), SidecarVaultMismatch(FileKind),
    OutOfMemory,
    BackupNotConfirmed, BackupMismatch, ChallengeStale,
    RecordLimit, DuplicateKey, RecordNotFound,
    NoMnemonic,                  // 키 전용 vault(§8.5)에서 파생·복구 단어·passphrase
    LastKey,                     // 키 전용 vault의 마지막 키 삭제(§8.4)
}

// yw_core::journal (M4, §5.4)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalError {
    Full,                        // 추가 전 검사 실패(정리 후에도 개수·용량 초과). 서명·전송 없음
}
```

- journal 프레이밍 오류는 `VaultError::SidecarCorrupt(Journal)`, 본문 오류는 체인 디코더 오류로 처리하므로(§5.4) `JournalError`에 없다.

`Display`는 `thiserror` 없이 직접 구현하고 고정 한국어 문장만 쓴다. 문장 표는 [04](04-app-ui.md) §7이 가지며, 이 문서가 고정하는 문장은 `UnlockFailed`(§7.4)와 `JournalError::Full` **"거래 저널 공간이 부족합니다"**(§5.4) 둘이다. [04] §7 표에도 같은 문장으로 둔다.

### 10.3 `Vault`

```rust
pub enum VaultStatus {
    NoVault, Locked, PassphraseRequired, PassphraseMismatch, BackupPending,
    Unlocked { alt_passphrase: bool }, Corrupt { prev_available: bool }, MainMissing,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct RecordId([u8; 16]);
pub enum EvmKeySource { Derived(AccountIndex), Raw(RecordId) }
pub enum KeyRef { Evm(EvmKeySource), Btc { coin: BtcCoin, chain: BtcChain, index: u32 } } // coin = 계정 노드([08] §3.1)
pub struct ImportedKeys { pub has_mnemonic: bool, pub evm: Vec<(RecordId, Address)>,
                          pub sol: Vec<(RecordId, [u8; 32])>, pub btc: Vec<(RecordId, BtcKeyInfo)> }

pub struct Vault { /* storage, status, vault_bytes, slot: Option<Box<dyn LockedSlot>>, challenge */ }

impl Vault {
    pub fn load(storage: Box<dyn VaultStorage>) -> Result<Self, VaultError>;     // §6.3; 고아 .tmp는 저장소 구현이 생성 시 정리
    pub fn status(&self) -> VaultStatus;
    pub fn vault_id(&self) -> Option<[u8; 16]>;

    // 아래에서 R<T> = Result<T, VaultError>, Slot = Box<dyn LockedSlot>, Pw = &VaultPassword
    pub fn create_wallet(&mut self, password: Pw, slot: Slot, now_unix: u64) -> R<SecretString>;
    pub fn import_mnemonic(&mut self, password: Pw, phrase: &str, passphrase: Option<Bip39Passphrase>,
                           slot: Slot, now_unix: u64) -> R<()>;
    pub fn unlock(&mut self, password: Pw, slot: Slot) -> R<VaultStatus>;
    pub fn enter_passphrase(&mut self, passphrase: Bip39Passphrase) -> R<VaultStatus>;
    pub fn retry_passphrase(&mut self) -> R<VaultStatus>;
    pub fn accept_mismatched_passphrase(&mut self) -> R<VaultStatus>;
    pub fn lock(&mut self);
    pub fn recover_from_prev(&mut self, password: Pw, slot: Slot, now_unix: u64) -> R<VaultStatus>; // Corrupt·MainMissing·Locked(§6.3)

    pub fn backup_challenge(&mut self) -> R<BackupChallenge>;
    pub fn confirm_backup(&mut self, id: ChallengeId, words: [&str; 4]) -> R<()>;

    pub fn import_evm_private_key(&mut self, hex: &str, now_unix: u64) -> R<RecordId>;
    pub fn remove_evm_raw_key(&mut self, password: Pw, id: RecordId) -> R<()>;
    pub fn create_with_key(&mut self, password: Pw, key: ImportKey, slot: Slot, now_unix: u64) -> R<RecordId>; // §8.5
    pub fn import_key(&mut self, key: ImportKey, now_unix: u64) -> R<RecordId>;                              // §8.4
    pub fn remove_imported_key(&mut self, password: Pw, id: RecordId) -> R<ImportChain>;                       // §8.4
    pub fn reveal_imported_key(&self, password: Pw, id: RecordId) -> R<(ImportChain, SecretString)>;           // §9
    pub fn change_password(&mut self, old: Pw, new: Pw) -> R<PasswordChange>; // §4.4: Complete | PrevNotRefreshed
    pub fn has_btc_key(&self, id: RecordId) -> R<bool>;                       // tag 4 record 존재(가져온 키 계정의 진실 원천)
    pub fn quarantined_at(&self) -> Option<u64>;                              // 마지막 `.prev` 복구가 본 파일을 옮긴 `now_unix`
    pub fn reveal_mnemonic(&self, password: Pw) -> R<SecretString>;
    pub fn reveal_evm_private_key(&self, password: Pw, src: EvmKeySource) -> R<SecretString>;
    pub fn reveal_evm_shared_wif(&self, password: Pw, index: AccountIndex, network: BtcNetwork) -> R<SecretString>; // [08] §3.5, 압축 WIF

    // 공개 정보 (BackupPending·Unlocked)
    pub fn evm_address(&self, src: EvmKeySource) -> R<crate::evm::Address>;
    pub fn evm_addresses(&self, indices: &[AccountIndex]) -> R<Vec<crate::evm::Address>>; // ≤ 100개
    pub fn raw_keys(&self) -> R<Vec<(RecordId, crate::evm::Address)>>;
    pub fn has_mnemonic(&self) -> R<bool>;                                                         // §8.5
    pub fn imported_keys(&self) -> R<ImportedKeys>;                                                // §8.4
    pub fn sol_public_keys(&self, srcs: &[SolKeySource]) -> R<Vec<[u8; 32]>>;                    // M7, ≤ 128개, 입력 순서
    pub fn btc_account_xpub(&self, coin: BtcCoin) -> R<AccountXpub>;                              // M8, m/84'/c'/0'
    pub fn btc_public_key(&self, coin: BtcCoin, chain: BtcChain, index: u32) -> R<[u8; 33]>;      // M8, 개인 파생 잎 공개키
    pub fn evm_public_key(&self, index: AccountIndex) -> R<[u8; 33]>;                            // m/44'/60'/0'/0/i 압축 공개키(EVM 키 BTC 계정, [08] §3.5)

    // 사이드카 (BackupPending·Unlocked)
    pub fn open_sidecar(&self, kind: FileKind) -> R<Option<(u64, SecretVec)>>;
    pub fn save_sidecar(&mut self, kind: FileKind, plaintext: &[u8]) -> R<u64>;       // 새 generation

    // 서명 모듈 전용 (03·07·08), Unlocked만
    pub(crate) fn with_secp_key<T>(&self, key: KeyRef,
        f: impl FnOnce(&Secp256k1<All>, &SecretKey) -> R<T>) -> R<T>;
    pub(crate) fn with_ed25519_seed<T>(&self, src: SolKeySource,
        f: impl FnOnce(&[u8; 32]) -> R<T>) -> R<T>;                                              // M7
    pub(crate) fn with_imported_ed25519_seed<T>(&self, public: &[u8; 32],
        f: impl FnOnce(&[u8; 32]) -> R<T>) -> R<T>;                                              // [07] §3.4
    pub(crate) fn imported_btc_secret(&self, id: &[u8; 16]) -> R<btc::sign::ImportedBtcSecret>; // [08] §11.1
}

// yw_core::bip32 — vault·슬롯 없이 가져오기 첫 주소 미리보기([04] §2.4 5단계 KeyJob::PreviewImport)
pub fn preview_evm_address(phrase: &str, passphrase: Option<&Bip39Passphrase>, index: AccountIndex)
    -> Result<crate::evm::Address, KeyError>;
```

- `preview_evm_address`: `Mnemonic::parse` → (`Some`인데 비어 있으면 `PassphraseEmpty`) → `to_seed` → `secp_context`(`OsRandom`) → `XPriv::from_seed` → `derive_path(evm_path(index))` → 주소. 중간값은 모두 `Zeroizing`·`non_secure_erase`로 지우고 아무것도 저장하지 않는다. 오류는 `import_mnemonic`의 `KeyError`와 같다.
- `open_sidecar`·`save_sidecar`의 generation CAS는 `Vault`가 기억한 마지막 generation으로 한다(`save_sidecar`가 `commit(kind, Some(last), …)`, 파일이 없으면 `None`). `FileKind::Vault`를 넘기면 `InvalidState`.
- 이 세션에서 아직 열지 않은 사이드카를 저장할 때는 먼저 `open_sidecar`로 **인증**한다(구조만 보고 generation을 가져다 덮어쓰지 않는다). 열기가 `SidecarCorrupt`·`SidecarVaultMismatch`로 실패한 파일은 다음 열기가 성공할 때까지(사용자가 `.prev`로 되돌리거나 격리한 뒤) 저장을 같은 오류로 거부한다. 남의 vault의 meta나 손상된 파일을 조용히 덮어써 복구 기회를 없애지 않기 위해서다(§6.3).
- 비밀을 돌려주는 API(`create_wallet`·`reveal_*`·`open_sidecar` 평문, `Mnemonic::phrase`·`to_seed`, `bip32::xkey::encode_xkey`)는 `Debug`가 `[REDACTED]`인 래퍼(`SecretString`·`SecretVec`·`SecretBytes`, [01] §5.3)를 돌려준다. 값은 `expose()`로만 읽는다.
- `with_secp_key`·`with_ed25519_seed`는 `pub(crate)`이며 키를 클로저 밖으로 내보내는 반환 타입을 만들지 않는다. `imported_btc_secret`의 `ImportedBtcSecret`도 crate 내부 타입이고 비밀키를 읽는 접근자가 없다: `btc::sign`만 그 키를 서명 클로저에 빌려 준다(키를 빌려 주는 `BtcKeys`도 `pub(crate)`, crate 밖 서명은 `sign_plan(&Vault, ..)`뿐). 서명 API 자체는 [03](03-evm.md)·[07](07-solana.md)·[08](08-bitcoin.md)이 정의한다.
- `with_ed25519_seed(src, f)`: §3.5 표대로 `src`의 32바이트 seed를 만들어 `f`에 빌려주고, 반환 직후 seed·64바이트 BIP39 시드·중간값을 소거한다(§7.3). 표준·비표준 다섯 출처 모두 이 함수 하나로만 서명 키를 얻는다([07] §3.1–§3.3).
- `sol_public_keys(srcs)`: BIP39 시드를 한 번만 계산하고 각 출처의 seed로 `SigningKey::from_bytes(&k).verifying_key()`를 구해 입력 순서대로 32바이트 공개키를 돌려준다(seed는 출처마다 즉시 소거). 계정 추가·주소 캐시 재계산·복구 스캔([07] §3.3)에 쓴다. 빈 목록은 빈 결과, 129개 이상은 `InvalidState`(호출자 오류)이며 아무것도 파생하지 않는다.
- `btc_account_xpub(coin)`: `XPriv::from_seed` → `derive_path(m/84'/{coin}'/0')`(`BtcCoin::Mainnet` 0', `Test` 1', D29) → 그 노드의 압축 공개키와 chain code를 `AccountXpub`(§3.1)로 돌려준다. 개인키는 반환하지 않고 중간 `XPriv`·`SecretKey`·시드는 소거한다. 주소 발급은 이 값과 `bip32::derive_public_child`로 vault 없이 한다([08] §3.1). `btc_public_key`는 같은 잎을 개인 파생으로 계산한 값으로, CKDpub 결과와의 대조([08] §14.1)에 쓴다.

## 11. 테스트 (판정은 [09](09-testing.md) §5.2 M1)

모든 테스트는 `cargo test`(debug)로 돈다. 프로덕션 파라미터 Argon2를 쓰는 테스트는 [01](01-repo-build.md) §3.1의 `[profile.dev.package."*"] opt-level = 3`(argon2·blake2 포함)으로 실용 속도를 낸다. 저장소는 메모리 mock(`MemStorage`, 커밋 횟수·바이트 기록), 슬롯은 `#[cfg(test)] HeapSlot`(drop 시 소거 여부를 공유 플래그로 기록).

### 11.1 엔트로피

| 테스트 | 확인 |
|---|---|
| `create_draws_entropy_first` | `ScriptedRandom`(0x00..=0x1f 다음 결정적 바이트열 — 상수열이면 DEK가 고착 검사에 걸린다)로 `create_wallet_with_rng` → 반환 니모닉 = `from_entropy(00..1f).phrase()` |
| `rng_failure_aborts_without_commit` | `FailingRandom` → `RandomnessUnavailable`, `MemStorage` 커밋 0회, 상태 `NoVault` |
| `stuck_rng_rejected` | 32바이트가 전부 0x00 / 전부 0x5a → `RandomnessUnavailable` |
| `zero_id_redrawn_then_fails` | 16바이트 0을 4회 → `RandomnessUnavailable`, 3회 후 비0 → 성공 |
| `secp_context_consumes_32_bytes` | `secp_context`가 정확히 32바이트를 소비 |

### 11.2 BIP39

- 단어 목록 SHA-256(§2.1)과 구조 검사.
- trezor/python-mnemonic `vectors.json`의 `english` 24개 전체(passphrase `"TREZOR"`): entropy→phrase, phrase→entropy, phrase→seed. 파일에서 그대로 복사한다(구현 시 확인). 대표값(독립 계산으로 확인):

| entropy | phrase | seed(`"TREZOR"`) 앞 16바이트 |
|---|---|---|
| `00`×16 | `abandon`×11 `about` | `c55257c360c07c72029aebc1b53c05ed` |
| `7f`×16 | `legal winner thank year wave sausage worth useful legal winner thank yellow` | `2e8905819b8723fe2c1d161860e5ee18` |
| `00`×32 | `abandon`×23 `art` | `bda85446c68413707090a52022edd26a` |

- 0 엔트로피 5종: 16 `…about`, 20 `…address`(15단어), 24 `…agent`, 28 `…admit`, 32 `…art`.
- 파싱 거부 표(§2.4): 선행 공백, 후행 공백, 이중 공백, 탭, 대문자 단어, 11·13·25단어, 목록 밖 단어(위치 확인), `abandon`×12(체크섬), 257바이트, 비ASCII.
- passphrase: 256바이트 허용, 257바이트·0x7F·0x1F·`"é"` 거부, `" TREZOR"`와 `"TREZOR"`의 시드가 다름.
- abandon 니모닉 빈 passphrase 시드 = `5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4`.

### 11.3 BIP32·경로

- M1에서 벡터 1–4의 모든 노드(경로 17개)를 xprv·xpub 전체 문자열(부모 fingerprint 포함)로 비교한다: `encode_xkey(derive_xkey(seed, path, Xprv|Xpub))` == 공식 문자열, 그리고 공식 문자열의 `decode_xkey` → `encode_xkey` 왕복이 원문과 같다. 벡터 문자열은 bitcoin/bips `bip-0032.mediawiki`에서 그대로 복사한다([09] §3.1 `bip32.json`).
- 독립 계산 확인값:

| 벡터·경로 | chain code | 개인키 |
|---|---|---|
| 1 `m` | `873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508` | `e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35` |
| 1 `m/0'` | `47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141` | `edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea` |
| 3 `m` (선행 0) | `01d28a3e53cffa419ec122c968b3259e16b65076495494d97cae10bbfec3c36f` | `00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32` |
| 4 `m/0'` (선행 0) | `cdc0f06456a14876c898790e0b3b1a41c531170aec69da44ff7b7265bfe7743b` | `00d948e9261e41362a688b916f297121ba6bfb2274a3575ac0e456551dfd7f7e` |
| 4 `m/0'/1'` | `a48ee6674c5264a237703fd383bccd9fad4d9378ac98ab05e6e7029b06360c0d` | `3a2086edd7d9df86c3487a5905a1712a9aa664bce8cc268141e07549eaa8661d` |

  벡터 1 `m` 공개키 `0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2`, `m/0'` 공개키 `035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56`.
- 벡터 5: 모든 무효 확장 키가 `decode_xkey`에서 `InvalidExtendedKey`로 거부된다.
- `fingerprint`: 벡터 1 `m`의 압축 공개키 → `3442193e`(벡터 1 `m/0'` xprv의 부모 fingerprint와 같음).
- `derive_child_tweak_rejections`: 내부 함수 `ckd_from_il(parent, il)`에 `IL = n` → `DerivationFailed`, `IL = n − k_par` → `DerivationFailed`(합이 0). 건너뛰기 없음.
- 경로 파서 허용·거부 표(§3.2), `AccountIndex::new(1000)` 거부, `btc_path(…, 2^31)` 거부.
- `derive_public_child`(M8): BIP32 벡터 1·2에서 마지막 성분이 비강화인 노드 6개(벡터 1 `m/0'/1`, `m/0'/1/2'/2`, `m/0'/1/2'/2/1000000000`; 벡터 2 `m/0`, `m/0/2147483647'/1`, `m/0/2147483647'/1/2147483646'/2`)에서 부모 xpub의 (공개키, chain code)로 계산한 `AccountXpub` == 자식 xpub의 (공개키, chain code). `index = 2^31` → `InvalidPath`, 접두 04·곡선 밖 부모 공개키 → `DerivationFailed`.

### 11.4 주소 벡터 (`abandon`×11 `about`)

| 경로·조건 | 결과 |
|---|---|
| `m/44'/60'/0'/0/0`, passphrase 없음 | `0x9858EfFD232B4033E47d90003D41EC34EcaEda94`, 개인키 `1ab42cc412b618bdea3a599e3c9bae199ebf030895b039e9db1e30dafb12b727` |
| `m/44'/60'/0'/0/1`, passphrase 없음 | `0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0`, 개인키 `9a983cb3d832fbde5ab49d692b7a8bf5b5d232479c99333d0fc8e1d21f1b55b6` |
| `m/44'/60'/0'/0/0`, passphrase `"TREZOR"` | `0x9c32F71D4DB8Fb9e1A58B0a80dF79935e7256FA6`, `passphrase_check = dc929830` |
| `abandon`×23 `art`, `m/44'/60'/0'/0/0` | `0xF278cF59F82eDcf871d630F28EcC8056f25C1cdb` |
| raw key `00…01` | `0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf` |
| `m/84'/0'/0'/0/0` 압축 공개키 (BIP84) | `0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c` |
| `m/84'/0'/0'/0/1` | `03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77` |
| `m/84'/0'/0'/1/0` | `03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6` |

- (M8) `btc_account_xpub(BtcCoin::Mainnet)`에서 `derive_public_child`로 `/0/0`, `/0/1`, `/1/0`을 공개 파생한 공개키가 위 BIP84 세 행과 같고, `btc_public_key`(개인 파생) 결과와도 같다.

계정 0·1과 raw key 값은 아카이브 데모 KAT(`demo/sepolia-wallet/src/wallet_secret.rs:964-998,1080-1096`)와 일치하고, TREZOR·art·BIP84 값은 이 문서 작성 시 독립 구현으로 계산했다. BTC 주소 문자열(`bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`)은 M8에서 [08](08-bitcoin.md) §14.1이 확인한다.

### 11.5 SLIP-0010 (M7)

- SLIP-0010 Ed25519 벡터 1·2 전체(공식 문서에서 복사). 벡터 1 `m`: chain code `90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb`, key `2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7`, 공개키 `00a4b2856bfec510abab89753fac1ac0e1112364e7d250545963f135f2a33188ed`. `m/0H`: chain code `8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69`, key `68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3`.
- 비강화 성분이 있는 경로 문자열 거부.
- abandon 니모닉 `m/44'/501'/0'/0'`: 비밀 seed `37df573b3ac4ad5b522e064e25b63ea16bcbe79d449e81a0268d1047948bb445`, 공개키 `f036276246a75b9de3349ed42b15e232f6518fc20f5fcd4f1d64e81f9bd258f7`(= `HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk`, [07](07-solana.md) §17.1).
- `SolKeySource`(§3.5): [07] §17.1 표의 `Standard`·`Bip44Account`·`Bip44Root`·`RawSeed` 행 전체(abandon 12·24단어)를 `sol_public_keys` 한 번 호출로 재현하고, 출력 순서가 입력 순서와 같다. `with_ed25519_seed(Standard(0))`가 클로저에 넘기는 seed = 위 `37df…b445`, `with_ed25519_seed(RawSeed)` = §11.2 abandon 시드 앞 32바이트 `5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1`. `sol_public_keys` 128개 허용, 129개 → `InvalidState`. `SolletLegacy`는 구현할 때만 [07] §3.2 확인 벡터로 시험한다.

### 11.6 vault v3

- **골든(프로덕션 파라미터):** 내부 함수 `seal_create_with(material, KDF_V3)`에 아래 고정 값을 넣어 272바이트(176 + 96)를 만든다. 첫 구현 때 파일의 SHA-256을 한 번 계산해 테스트에 고정하고, 이후 형식이 바뀌면 실패한다. 이것은 우리 바이트 형식의 회귀 테스트이며 문서 해시 고정(spec §2.3 금지)이 아니다. 같은 테스트가 디코드·잠금 해제 왕복과 각 필드 오프셋(§4.2)을 확인한다.

```
password "correct horse battery staple"   entropy 00×32 (…art)      created_unix 1790000000
vault_id 000102…0f   DEK 202122…3f   kdf_salt 404142…4f   wrap_nonce 505152…67
payload_nonce 707172…87   record_id 909192…9f   generation 1, backup_state 0, passphrase_used 0
```

- 오답 비밀번호 → `UnlockFailed`.
- 헤더 필드 변조 표(각 필드 1비트 반전, `KDF_TEST`; 테스트 빌드 KDF 호출 카운터로 Argon2 실행 여부 확인):

| 변조 위치 | 기대 오류 | Argon2 실행 |
|---|---|---|
| `magic`, `header_len`, `flags`, `reserved`, `vault_id` → 0, `generation` → 0, `payload_ct_len`, 파일 길이 ±1 | `Malformed` | 아니오 |
| `version` | `UnsupportedVersion` | 아니오 |
| `kdf_id`, `m_kib`, `t`, `p` (예: m 262143·262145, t 2·4, p 3·5) | `UnsupportedParams` | 아니오 |
| `vault_id`(비0), `kdf_salt`, `wrap_nonce`, `wrapped_dek` | `UnlockFailed` | 예 |
| `generation`(≥1), `payload_nonce`, `payload_ct` 임의 바이트 | `PayloadCorrupt` | 예 |

- 모든 길이로 자른 파일, 끝에 1바이트 추가 → KDF 전 `Malformed`.
- `KDF_TEST`로 만든 파일을 공개 API로 열면 `UnsupportedParams`.
- payload 코덱 거부 표(§4.6 목록 전부) + `Bip39` + `EvmRawKey` 15개 왕복, 16번째 `EvmRawKey` 거부(tag 3·4는 §11.9).
- `PayloadRewrite`: KDF 호출 0회, `header[0..130]` 불변, `generation + 1`, `payload_nonce` 변경.
- `change_password`: 이전 비밀번호 `UnlockFailed`, 새 비밀번호 성공(`Complete`), DEK 불변(사이드카가 계속 열림), 커밋 2회(`generation + 2`), `.prev`가 새 비밀번호로 열림. `Rewrap` 뒤 두 번째 커밋 실패 → `Ok(PrevNotRefreshed)`, 이후 이전 비밀번호 `UnlockFailed`·새 비밀번호로 잠금 해제(yw-app `tests/vault_edge_cases.rs`).
- 새 버전 payload: 인증되는 payload에 모르는 tag 5 record → `unlock`은 `UnsupportedPayload`, 상태 `Locked`(`Corrupt` 아님), `recover_from_prev`도 `UnsupportedPayload`이고 격리·복원 없음; payload 바이트 변조(AEAD 실패)는 여전히 `PayloadCorrupt` → `Corrupt { prev_available }` → 복구 시 `quarantined_at`.
- 자체 검사: 인코더가 손상된 바이트를 만들도록 주입하면 커밋 0회.

### 11.7 사이드카·저장소

- 사이드카 왕복, `vault_id` 불일치 → `SidecarVaultMismatch`, 1비트 변조 → `SidecarCorrupt`, magic 교차(meta 파일을 journal로 열기) 거부, generation CAS 충돌 → `Storage(GenerationConflict)`.
- `MemStorage` 기준 `commit` 계약: `None`인데 파일 있음 → `AlreadyExists`, 손상 본 파일 위 커밋 → `Corrupt`이고 바이트 불변, 성공 시 `.prev` = 직전 바이트.
- journal 컨테이너(M4, §5.4): kind 4종 왕복(4 = Zcash, [12](12-zcash.md) §12.1); 알 수 없는 kind, `body_len` 0·초과, 남는 바이트, `entry_count` 257 → `SidecarCorrupt(Journal)`; 본문 오류 entry는 다른 entry 갱신 후에도 바이트 불변; 개수·용량 초과 시 종결 레코드 정리 후에도 넘으면 `Full`이고 커밋 0회.
- yw-win 실제 파일 구현의 중단 지점 테스트(각 단계 후 강제 중단 → 재시작 분류)와 고아 `.tmp` 정리는 [09](09-testing.md) §4.1 V-FS.

### 11.8 상태 기계·백업

- §7.2 전이표의 모든 행. 허용되지 않은 호출은 `InvalidState`.
- `BackupPending`에서 `with_secp_key`·`reveal_evm_private_key`·`import_evm_private_key` → `BackupNotConfirmed`, `evm_address`는 성공.
- `lock` 후 `HeapSlot` 소거 플래그 참, 이후 `evm_address` → `InvalidState`.
- passphrase: 일치 → `Unlocked{alt:false}`, 불일치 → `PassphraseMismatch` → 계속 → `Unlocked{alt:true}`, 다시 입력 → 슬롯의 passphrase 영역이 0.
- 백업: `ScriptedRandom`으로 위치 고정 후 정답 → Confirmed 커밋 1회; 단어 하나 오답, 빈 단어·영문 소문자 밖 문자, 9자 이상 단어, 대문자 단어, 오래된 `ChallengeId` 각각 실패하고 상태 `BackupPending` 유지; 위치는 항상 서로 다르고 오름차순이며 1..=24.
- 디버그 출력 가림: 모든 비밀 타입의 `format!("{:?}")`에 입력 문자열·hex가 없다.

### 11.9 가져온 개인키·키 전용 vault

- WIF(`keyimport::tests`): Bitcoin wiki 예제(비압축 `5HueCGU8…`, 압축 `KwdMAjGm…`)와 secret 1의 네 형식(mainnet·테스트넷 × 압축·비압축) 디코드·인코드 왕복; 체크섬·길이·문자·비ASCII·접미사 02·version 00·0·n 거부.
- Bitcoin 주소: BIP84 WIF → `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`, BIP49 테스트넷 WIF → `2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2`, secret 1의 P2PKH(압축 `1BgGZ9tc…`, 비압축 `1EHNa6Q4…`, 테스트넷 `mrCDrCyb…`)와 BIP173 P2WPKH(`bc1qw508d6…`, `tb1qw508d6…`), BIP86 내부 키 `cc8a4bc6…` → 출력 키 `a60869f0…` → `bc1p5cyxnuxm…`; 비압축 키 + segwit/taproot 형식 거부.
- Solana: RFC 8032 test 1 시드의 base58 keypair·JSON(콤마, 콤마+공백, 줄바꿈 들여쓰기)이 같은 키로 파싱되고 내보내기 base58이 입력과 같다; [07] §17.1 abandon 표준 0 시드 keypair → `HAgk14Jp…`; 주소(32바이트) → `SolKeyIsAddress`, 공개키 바꿈 → `SolKeyMismatch`, 33·65바이트·63개·256·음수·앞자리 0·빈 항목·괄호 누락·hex 시드 → `SolKeyFormat`.
- vault(`vault::tests`): 이전 배치(Bip39 + EvmRawKey) payload의 디코드·재인코드 동일성; 모든 tag 조합·키 전용 payload 왕복; `SolKey` 공개키 불일치·중복, `BtcKey` 값 규칙·중복, tag 순서 위반, tag를 넘는 record_id 중복, 47개 → `UnsupportedPayload`(디코드 거부); 최대 payload(3,170바이트) 봉인·개봉, 16번째 키 → `RecordLimit`; 키 전용 vault 생성·재잠금 해제(곧바로 `Unlocked`)·`NoMnemonic` 표·서명용 시드·내보내기·`LastKey`; 니모닉 vault의 체인별 상한·중복 규칙·가져온 Bitcoin 키를 서명자에게 빌려 줌(BIP84 공개키, 다른 network·형식 → `KeyMismatch`, 없는 id → `RecordNotFound`)·WIF 내보내기·체인별 삭제; `BackupPending`의 `import_key` → `BackupNotConfirmed`.
- Solana 서명(`sol::tests`): 가져온 표준 0 키가 골든 전송을 파생 키와 같은 서명으로 서명, `L07`·`NON_STANDARD_PATH` 없음, 저널 태그 6 왕복; 니모닉 vault의 `Imported` 출처 → `RecordNotFound`, 키 전용 vault의 파생 출처 → `NoMnemonic`.

## 12. 아카이브 이식 출처

| 대상 | 출처 | 변경 |
|---|---|---|
| BIP39 상수, 엔트로피 재구성, `reveal_phrase` | `archive/spec-v2.4:crates/secret-core/src/mnemonic.rs:12-146` | `bip39` 크레이트 제거(자체 목록·엄격 파서), NFKD 제거 |
| `SessionPassphrase` | `archive/spec-v2.4:crates/secret-core/src/mnemonic.rs:210-270` | `Bip39Passphrase`(ASCII 0–256) |
| 경로 상수·파서·Display | `archive/spec-v2.4:crates/secret-core/src/bip32.rs:12-117,392-416` | 변경 없음 |
| `RawPrivateKey`, `EphemeralSecpSecret`, 주소 계산 | `archive/spec-v2.4:crates/secret-core/src/bip32.rs:143-225` | `with_secp_key` 안으로 |
| `from_seed`, `derive_child`, `hmac_sha512` | `archive/spec-v2.4:crates/secret-core/src/bip32.rs:273-298,343-389,418-426` | `Ok(None)` → `Err(DerivationFailed)`, 임의 경로 |
| 삭제: 건너뛰기 | `archive/spec-v2.4:crates/secret-core/src/bip32.rs:227-271,300-341,428-446,500-515` | 삭제 |
| 헤더 코덱·정확 파라미터 거부·헤더 AAD | `archive/spec-v2.4:crates/secret-core/src/vault.rs:582-691,756-801` | v3 배치, DEK wrap |
| KDF | `archive/spec-v2.4:crates/secret-core/src/vault.rs:865-887` | KEK 정보 문자열, `hash_password_into_with_memory` |
| record 코덱, `Cursor`, `fill_random_nonzero` | `archive/spec-v2.4:crates/secret-core/src/vault.rs:996-1159` | v3 record, 계정 영속 레코드 삭제 |
| `BackupState`, 백업 확인 | `archive/spec-v2.4:crates/secret-core/src/vault.rs:41-65,433-484,933-994` | §8.3 변경 |
| 위치 선택·`random_below` | `archive/spec-v2.4:crates/key-agent/src/vault_session.rs:681-746` | 변경 없음 |
| 오류 | `archive/spec-v2.4:crates/secret-core/src/error.rs:1-53` | `thiserror` 제거, `DerivationExhausted` 삭제 |
| 저장소 trait | `archive/spec-v2.4:crates/secret-core/src/storage.rs:1-51` | `FileKind`, `.prev`, `quarantine` |
| KAT·엄격 입력 테스트 | `archive/spec-v2.4:demo/sepolia-wallet/src/wallet_secret.rs:864-1176` | |
| 원자적 쓰기·디렉터리 flush | `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:5228-5410,6148-6403` | yw-win으로 |
| 테스트용 축소 KDF, 테스트 구조 | `archive/spec-v2.4:demo/sepolia-wallet/src/vault_v2.rs:59-74`, `crates/secret-core/src/vault.rs:1161-1432`, `bip32.rs:448-544` | `#[cfg(test)]` 내부 함수만, v3 값 |

## 미결 사항

결정이 필요한 항목은 없다(passphrase 보관은 개정 D10, `ripemd` 시점과 BIP32 전체 문자열 비교는 개정 D5·M1로 해소). 구현 시 확인:

1. **단어 목록 SHA-256**(§2.1): 공식 bitcoin/bips `english.txt`로 다시 계산한다. 다르면 공식 파일을 따르고 이 문서와 [01] §1.4의 값을 고친다.
2. **공식 벡터 원문**(§11.2·§11.3·§11.5): Trezor `vectors.json`, BIP32 벡터 1–5, SLIP-0010 벡터를 원문에서 그대로 복사한다. 이 문서의 대표값과 다르면 원문을 따르고 이 문서를 고친다.
3. **Argon2 1회 시간**(§7.4): release 빌드로 대상 PC에서 재어 [09]에 기록한다. 실사용이 어려울 만큼 길면(> 10 s) `KDF_V3` 변경은 spec D7 개정 사항이며, 바뀌면 기존 vault는 `UnsupportedParams`이므로 니모닉으로 새로 만든다.

[01]: 01-repo-build.md
[03]: 03-evm.md
[04]: 04-app-ui.md
[05]: 05-browser.md
[07]: 07-solana.md
[08]: 08-bitcoin.md
[09]: 09-testing.md
