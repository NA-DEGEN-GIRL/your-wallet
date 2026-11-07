# Bitcoin 전송 전용 (M8)

상위 문서: [spec.md](../spec.md)

D26·D27·D29·D30의 세부 명세다. BTC 보내기·받기는 yw-app 화면에서만 한다. 브라우저·dApp과는 확장 호환 모드에서 **소유 증명(주소 연결 + 메시지 서명)만** 한다(§17, 2026-10-31). 이식할 아카이브 코드는 없다(전부 새 코드). 예외는 BIP32 파생([02](02-core-keys-vault.md) §3.1, 근거 `archive/spec-v2.4:crates/secret-core/src/bip32.rs:12-225,273-298,392-426`)과 공통 승인 모델([03](03-evm.md) §11, D27·D31)이다. 상수는 §15에 모아 둔다.

## 1. 범위

### 1.1 포함 (v1)

| 항목 | 규칙 |
|---|---|
| 받기 | 계정마다 주소 형식 하나(§3.5): 기본 BIP84 P2WPKH 계정 0 m/84'/{coin}'/0'/{0,1}/i(D26·D29; `coin` = mainnet 0, testnet4 1, §2), [계정 추가]로 BIP86 P2TR·BIP49 P2SH-P2WPKH·BIP44 P2PKH·BIP84 다음 계정, 가져온 단일 키(주소 하나), EVM 계정과 같은 키(주소 하나, §3.5). HD 계정은 기본으로 **고정 주소 모드**(§3.5: 받기·잔돈 모두 `…/0/0`, UniSat·Xverse 방식)이고 계정마다 HD 모드(받을 때마다 새 주소)로 바꿀 수 있다. |
| 보내기 대상 | P2PKH, P2SH, P2WPKH(v0/20), P2WSH(v0/32), P2TR(v1/32, 유효한 x-only 키) |
| 보내기 거부 | P2A(`bc1pfeessrawgf`, `tb1pfees9rn5nz`), v1이면서 32바이트가 아닌 프로그램, v2–v16, 사일런트 페이먼트(`sp1`/`tsp1`), 라이트닝(`lnbc`/`lntb`/`lnurl`/`lightning:`), `bitcoin:` URI, 다른 네트워크·다른 코인 주소 |
| 쓰는 입력 | 선택한 계정 하나의 UTXO만(한 거래 = 한 주소 형식). 서명: P2PKH 레거시 sighash, P2SH-P2WPKH·P2WPKH BIP143 — 모두 ECDSA(low-R, low-S) + SIGHASH_ALL; P2TR BIP341 키 경로 Schnorr + SIGHASH_DEFAULT(§6.6–§6.7). |
| 거래 형태 | 수신자 1명 + 잔돈 0–1개, 보내기 최대(send-max), RBF 수수료 올리기 |
| 데이터 원천 | 네트워크마다 둘(D26, §4): (1) `bitcoin:<net>` 엔드포인트 URL 하나(D13, 공급자 무관, 현재 QuickNode)의 Bitcoin Core JSON-RPC — 네트워크 고정, 이전 거래 원본, 수수료, 사전 검사, 전송. (2) 주소 인덱서 `bitcoin.indexer`(§2): **기본 `esplora`**(Esplora REST GET, 무료·키 없음, 기본 mempool.space), 선택 `bb-rpc`(같은 엔드포인트의 QuickNode BTC Blockbook 애드온 `bb_*`, 유료), 선택 `bb-rest`(알케미 UTXO API REST). 인덱서는 믿지 않고(§4.6, §5) 주소 단위로만 묻고 xpub은 보내지 않는다. v1에는 다른 원천이 없다. |

### 1.2 제외 (v1)

PSBT, 멀티시그, dApp의 거래·PSBT 서명과 전송(dApp은 §17의 연결·메시지 서명만), 여러 수신자(batching), coinjoin, 라이트닝, BIP21 URI, 법정화폐 환산, xpub·디스크립터 내보내기, watch-only, Taproot 스크립트 경로·비어 있지 않은 스크립트 트리, 여러 계정 입력을 섞는 거래, 계정 자동 탐색(가져온 니모닉에서 44'/49'/86'·다른 account 번호를 스스로 찾지 않는다 — 사용자가 [계정 추가]로 형식을 고르면 그 계정을 §3.4로 찾는다), signet·testnet3·regtest, 남의 미확정 UTXO 사용, CPFP. **비목표: 오디널스·인스크립션·룬은 범위 밖이다. 코인 선택은 모든 UTXO를 평범한 BTC로 보며(인스크립션이 실린 UTXO도 일반 입력·수수료로 쓰일 수 있다) 지갑은 인스크립션 탐지를 더하지 않는다(Bitcoin은 보관용).** 가져오기 화면에 고정 문구 `BTC_IMPORT_NOTE` "Bitcoin은 네이티브 세그윗(bc1q…, BIP84) 계정 0을 먼저 찾습니다. 탭루트·호환 세그윗·레거시 주소는 Bitcoin 탭의 [계정 추가]로 더하세요"를 표시한다.

## 2. 네트워크 고정

BTC 네트워크는 지갑마다 하나다(D26). 선택은 평문 `settings.json`의 `"bitcoin": {"enabled": bool, "network": "mainnet"|"testnet4", "indexer": "esplora"|"bb-rpc"|"bb-rest", "esploraBaseUrl": {"mainnet": HttpsUrl, "testnet4": HttpsUrl}}`(기본 `{"enabled": false, "network": "mainnet", "indexer": "esplora", "esploraBaseUrl": {"mainnet": "https://mempool.space/api", "testnet4": "https://mempool.space/testnet4/api"}}`, `indexer`·`esploraBaseUrl`은 아래 **인덱서**)에 두고 이 문서가 그 객체의 의미를 소유한다(D30). 키별 형식 검증·되돌림은 [04](04-app-ui.md) §6.1이다. 주소 문자열에서 네트워크를 추론하지 않는다. meta의 `BtcMeta.network`(§12.3)는 일관성 검사용 사본이다.

- **켜기·끄기.** 켤 때 네트워크를 고르면 settings.json(`enabled = true`, `network`)을 쓰고 `BtcMeta`를 만든 뒤 §3.4 발견을 실행한다. 끄기는 진행 중 거래(§12.1)가 없을 때만 하며 `enabled = false`만 쓰고 meta `btc`는 둔다.
- **불일치.** 잠금 해제 뒤 `enabled`인데 settings `network`와 `BtcMeta.network`가 다르면 BTC 호출·송금을 모두 막고(`NetworkMismatch`) [설정을 {BtcMeta 값}으로 되돌리기] / [{settings 값}으로 바꾸기](아래 네트워크 바꾸기)를 보인다. `enabled`인데 meta `btc`가 `null`이면(meta 초기화, alt-passphrase 세션 [02] §7.5) `BtcMeta`를 새로 만들고 §3.4 발견을 실행한다.

| 항목 | `BtcNetwork::Mainnet` (id 1) | `BtcNetwork::Testnet4` (id 2) |
|---|---|---|
| `coin_type()` / 계정 경로 | 0 / m/84'/0'/0' | 1 / m/84'/1'/0' |
| 네트워크 ID (D13) | `bitcoin:mainnet` | `bitcoin:testnet4` |
| QuickNode 템플릿 (D13) | `https://<이름>.btc.quiknode.pro/<토큰>/` (서브도메인 `btc`, 문서 예시와 일치) | `https://<이름>.btc-testnet4.quiknode.pro/<토큰>/` (서브도메인 `btc-testnet4`, 2026-10-27 실측, §4.5) |
| 알케미 템플릿 (D13) | `https://bitcoin-mainnet.g.alchemy.com/v2/<KEY>` | `https://bitcoin-testnet4.g.alchemy.com/v2/<KEY>` |
| `esploraBaseUrl` 기본값 (`BTC_ESPLORA_DEFAULT_*`, §15) | `https://mempool.space/api` | `https://mempool.space/testnet4/api` |
| `bb-rest` 기준 경로 (알케미 UTXO API형, 선택) | `<엔드포인트>/api/v2/` | `<엔드포인트>/api/v2/` (사용 시 확인, §4.5 B1) |
| `getblockhash 0` | `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f` | `00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043` |
| `getblockchaininfo.chain` | `"main"` | `"testnet4"` |
| bech32 HRP | `bc` | `tb` |
| base58 P2PKH / P2SH 버전 | `0x00` / `0x05` | `0x6f` / `0xc4` |
| 배너 | `BITCOIN MAINNET` (빨강 배경) | `BITCOIN TESTNET4 — 가치 없음` (주황 배경) |

`BtcNetwork::coin_type()`은 [02] §3.3의 `yw_core::bip32::path::BtcCoin`(Mainnet → `BtcCoin::Mainnet` 0', Testnet4 → `BtcCoin::Test` 1')을 돌려준다. 이 문서의 경로 `m/84'/{coin}'/0'/…`에서 `{coin}`이 이 값이다(D26·D29).

**엔드포인트(Core).** 네트워크마다 HTTPS URL 하나(`bitcoin:mainnet`·`bitcoin:testnet4`)를 `apikeys.dpapi`(spec.md §4.3, [04] §6.3, 항목 `rpc:bitcoin:<net>`)에 둔다(D13). URL에 토큰이 들어가므로 URL 전체가 비밀이고 settings.json에는 두지 않는다. 공급자를 가정하지 않는다: 위 템플릿(QuickNode 멀티체인·알케미)으로 만들거나 직접 입력하며, 템플릿으로 만든 URL도 네트워크별로 덮어쓸 수 있다. 사용자의 현재 공급자는 QuickNode다(2026-10-27 mainnet·testnet4 Core RPC 동작 확인, §4.5). Core JSON-RPC(§4.2)는 어떤 인덱서를 고르든 이 URL만 쓴다. 그 네트워크의 엔드포인트가 없으면 BTC를 켤 수 없다(인덱서와 무관). 개발 중 실서비스 프로브는 저장소 밖 `%USERPROFILE%\.yw-dev\rpc.json`(또는 `YW_RPC_JSON`이 가리키는 파일)의 `"bitcoin:mainnet"`·`"bitcoin:testnet4"` 키에서 URL을 읽고 URL·토큰을 출력·로그에 남기지 않는다(D13, [09](09-testing.md)).

**인덱서.** 주소별 UTXO·이력 조회 원천은 `bitcoin.indexer`로 고른다(D26, §4.3). 형식은 URL·호스트에서 추론하지 않는다.

| `indexer` | 요청 위치 | 인증·비용 | 비고 |
|---|---|---|---|
| `"esplora"` (기본) | `bitcoin.esploraBaseUrl.<net>` + §4.3 경로, GET(POST는 §11.3 수동 전송뿐) | 없음(무료, 키 없음) | 기본 mempool.space. 사용자가 다른 Esplora 호환 서버(예: 자체 운영, `https://blockstream.info/api`·`https://blockstream.info/testnet4/api` — 2026-10-27 제네시스 일치 확인)로 바꿀 수 있다 |
| `"bb-rpc"` (선택) | Core 엔드포인트 URL에 `bb_*` JSON-RPC POST | 엔드포인트 토큰. QuickNode BTC Blockbook 애드온(유료 요금제 위 추가 요금, 공개 페이지 기준 월 약 75달러부터) | 애드온이 꺼진 엔드포인트에서는 `-32601`(§4.5 사전 실측) → E-BTC-007 |
| `"bb-rest"` (선택) | `<Core 엔드포인트 URL에서 끝 '/' 제거>/api/v2/<경로>` GET | 엔드포인트 키. 알케미 UTXO API(같은 Blockbook JSON) | 사용 전 §4.5 B1–B3 |

- **`esploraBaseUrl`은 비밀이 아니다.** 인증 없는 공개 서버의 기준 URL이므로 평문 settings.json에 두고 설정 화면에 전체를 보인다([04] §2.11). 네트워크마다 하나이며(`mainnet`·`testnet4` 두 키 모두 항상 존재), 현재 `bitcoin.network`의 값만 쓴다. 형식(https만, 끝 `/`·쿼리·fragment 없음, 공급자 토큰 호스트 거부)은 [04] §6.1. 요청 URL = 기준 URL ‖ §4.3 경로(경로는 `/`로 시작하고 끝 `/`가 없다; 예: `https://mempool.space/api` ‖ `/address/<a>/utxo`). 끝에 `/`가 붙으면 404다(2026-10-27 실측: `/block-height/0/` → 404). 다른 URL로 자동 대체하지 않는다([04] §1.9).
- 로그·오류에는 기준 URL도 쓰지 않고 `net=<NetworkId> idx=esplora`와 경로 종류만 쓴다(§4.1). 비밀은 아니지만 Core URL과 같은 규칙으로 단순화한다.
- 어떤 인덱서·URL이든 아래 연결 검사가 그대로 적용된다. 인덱서·`esploraBaseUrl`을 바꾸면 새 `RpcConfig`([04] §1.9)와 연결 검사(3·4단계 포함)를 다시 한다. 진행 중 거래 추적은 새 인덱서로 이어간다.

**연결 검사** `check_chain()`. 네트워크 고정은 공급자·URL·인덱서 형식과 무관하게 제네시스로 한다. BTC 첫 호출 때(잠금 해제 뒤), Core 엔드포인트·`indexer`·`esploraBaseUrl`을 바꾼 뒤, 그 뒤 10분마다, 그리고 매 `testmempoolaccept`·`sendrawtransaction` 직전에 반드시 수행한다(3·4단계는 첫 호출·변경 뒤·10분 주기에만). 1–3단계 중 하나라도 어긋나면 그 세션에서 BTC 호출을 모두 막는다(1·2단계는 "RPC가 다른 네트워크를 가리킵니다", 3단계는 E-BTC-003, [04] §7).

1. `getblockhash [0]` 결과는 소문자 hex 64자이고 위 상수와 같아야 한다.
2. `getblockchaininfo []`: `chain`이 위 값과 같아야 한다. `initialblockdownload == false`, `headers - blocks <= 2`, `mediantime`은 `now - 86400 <= mediantime <= now + 7200`(로컬 UTC 초) 범위여야 한다. `blocks >= 500,000,000`(`BTC_LOCKTIME_THRESHOLD`: 그 값부터 nLockTime은 높이가 아니라 시각)이면 거부한다(`TipImplausible`; `headers`도 같다). `blocks`는 팁 높이(`tip_height`)로 쓴다. `blocks < BtcMeta.max_tip_seen - 6`이면 거부하고(`TipRegressed`), 아니면 `max_tip_seen = max(max_tip_seen, blocks)`로 갱신한다. 단 4단계 인덱서 팁이 있으면 갱신 값은 `min(blocks, 인덱서 팁 + BTC_INDEXER_TIP_LAG_WARN)`까지다(한 엔드포인트가 거짓으로 높은 팁을 주어 `max_tip_seen`을 끌어올리면 이후 정직한 노드가 모두 `TipRegressed`가 된다). `TipRegressed`로 막힌 세션에서는 BTC 탭이 [블록 높이 기록 초기화]를 보이고, 확인 창("노드가 전에 잘못된 높이를 알려 준 경우에만…")을 거쳐 `BtcMeta.max_tip_seen = 0`을 저장한 뒤 세션을 초기화하고 새로고침한다.
3. 인덱서 제네시스 `GenesisHash`(§4.3): `esplora` `GET /block-height/0`(text/plain 본문 = 소문자 hex 64자, 2026-10-27 mempool.space 두 네트워크 모두 위 상수와 일치), `bb-rpc` `bb_getBlockHash ["0"]`·`bb-rest` `GET block-index/0`의 `blockHash`가 위 상수와 같아야 한다. `esplora`는 생략할 수 없다. `bb-*`는 그 인덱서가 이 호출을 지원하지 않음이 §4.5 B3에서 확인되면 3단계를 빼고, 인덱서 응답은 §5 검증(원본은 1·2단계를 통과한 Core에서 txid로 받음)에만 의존한다. 3단계를 통과하기 전에는 그 인덱서에 주소를 보내지 않는다.
4. (`esplora`만, 차단 아님) 인덱서 팁 `TipHeight`(`GET /blocks/tip/height`)와 2단계 `blocks`의 차가 `BTC_INDEXER_TIP_LAG_WARN`(3)을 넘으면 배너 W-BTC-IDX-LAG "인덱서와 노드의 블록 높이가 {n} 차이 납니다. 잔액·확인 수가 늦게 반영될 수 있습니다"를 보이고 계속한다. 이 호출이 실패하면 로그만 남긴다(단 429 재시도 초과는 §4.4대로 그 작업을 중단한다). 거짓 높이는 확인 수 표시와 DoS로만 이어진다(§4.6). 계획(보내기·수수료 올리기, §7·§9) 때는 `TipHeight`를 새로 받아(실패하면 마지막 4단계 값) Core `blocks`가 인덱서 팁 + `BTC_PLAN_TIP_AHEAD_MAX`(6)보다 크면 계획하지 않는다("노드 블록 높이가 인덱서보다 크게 앞서…"; `lock_time = tip`이 다른 노드에서 아직 최종이 아니다). `bb-*`는 `TipHeight`가 없어 이 비교를 하지 않는다.

**다른 네트워크를 쓰지 않는 이유.** QuickNode Bitcoin은 mainnet·testnet4만 제공하고(공식 API 개요, 2026-10 확인) 알케미 UTXO API도 mainnet·testnet4만이다. mempool.space는 testnet3(`/testnet/api`)·signet(`/signet/api`)도 제공하지만 지원하지 않는다. testnet3은 Core 28부터 폐기 예정이다. testnet3(`000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943`)나 signet(`00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6`)의 제네시스가 오면 위 1단계(인덱서면 3단계 — 예: `esploraBaseUrl.testnet4`를 `…/testnet/api`로 잘못 넣은 경우)에서 실패한다. 이 셋은 `tb`·`0x6f`·`0xc4`를 testnet4와 함께 쓰므로 제네시스 검사가 유일한 구분 수단이다.

**네트워크 바꾸기.** 진행 중 거래(§12.1)가 없을 때만 허용한다. 확인 창을 거친 뒤 settings.json `bitcoin.network`를 먼저 쓰고([04] §6.2 원자적 쓰기), 이어서 `BtcMeta`를 새 네트워크 기본값으로 다시 만든다(인덱스·캐시·동결·보낸 주소 기록 초기화, 계정 공개키는 새 `coin`으로 다시 받음). 둘 사이에 끊기면 다음 잠금 해제 때 불일치로 잡힌다. BTC 저널 항목은 `network` 필드로 구분해 보존하고, 현재 네트워크가 아닌 항목은 조회하지 않는다. 그 다음 §3.4 발견을 실행한다.

## 3. 키 파생·주소 발급

### 3.1 경로와 키

- 계정 키: 기본 계정 m/84'/{coin}'/0' (D29, §2 `coin_type()`), 추가 계정 m/{44|49|84|86}'/{coin}'/{account}'(§3.5). 받기 체인 `chain = 0`(`BtcChain::Receive`), 잔돈 체인 `chain = 1`(`BtcChain::Change`), 인덱스 `0 <= i < 2^31`(비강화). 계정 노드 선택자는 `bip32::path::BtcCoin { test, purpose, account }`이고(이름은 BIP84 전용이던 때의 것; `BtcCoin::Mainnet`/`BtcCoin::Test`는 BIP84 계정 0), vault는 이를 그대로 `btc_path`·`btc_account_path`에 넘긴다.
- HD 계정은 압축 공개키(33바이트)만 쓴다. P2WPKH 프로그램은 `HASH160(pubkey) = RIPEMD160(SHA256(pubkey))`이고, 그 밖 형식의 출력은 §3.5 표다. `ripemd =0.1.3`은 M0부터 yw-core 허용 목록에 있다(D5, [01](01-repo-build.md) §3.3); Bitcoin 단계는 의존성을 추가하지 않는다.
- **계정 공개키 캐시.** BTC를 켤 때 `Vault::btc_account_xpub(&self, coin: BtcCoin) -> R<AccountXpub>`([02](02-core-keys-vault.md) §10.3, m/84'/{coin}'/0')로 압축 공개키 33바이트와 체인 코드 32바이트를 받아 `BtcMeta.account_pubkey`·`account_chain_code`에 저장한다. 주소 생성은 이 값에서 공개 파생(CKDpub, `yw_core::bip32::derive_public_child`)으로 한다. 개인키가 아니므로 D10과 충돌하지 않고, meta.ywm은 암호화되어 있다.
- **passphrase.** 파생에 쓰는 BIP39 passphrase(가져온 지갑만, D29)는 잠금 해제 동안 DEK와 같은 VirtualLock 슬롯에 있다(D10, [02] §7.3). BTC에 별도 처리는 없다.
- `AccountXpub`·`derive_public_child`는 `yw_core::bip32`([02] §3.1)가 정의하고 `Vault::btc_account_xpub`는 [02] §10.3이 정의한다(정본은 [02]). 08은 그 이름을 그대로 쓰며 아래는 08이 쓰는 계약의 요약이다(오류는 [02] §10.2 `KeyError`, `Vault` 메서드에서는 `R` = `Result<_, VaultError>`). `p2wpkh_program`만 08 소유(`btc::address`)다.

```rust
// yw_core::bip32 ([02] §3.1)
pub struct AccountXpub { pub pubkey: [u8; 33], pub chain_code: [u8; 32] }   // 공개 정보, 압축 공개키
/// CKDpub, 비강화 index(< 2^31)만: 강화 index는 KeyError::InvalidPath. 부모 공개키가 유효한 압축 점이 아니거나
/// IL >= n 또는 결과가 무한원점이면 KeyError::DerivationFailed (건너뛰지 않는다, [02] §3.1).
pub fn derive_public_child(parent: &AccountXpub, index: u32 /* 비강화만 */) -> Result<AccountXpub, KeyError>;
// I = HMAC-SHA512(chain_code, pubkey || ser32_be(index));
// Scalar::from_be_bytes(IL)?; child = PublicKey::from_slice(pubkey)?.add_exp_tweak(&secp, &il)?; chain = IR
// yw_core::vault ([02] §10.3)
impl Vault { pub fn btc_account_xpub(&self, coin: BtcCoin) -> R<AccountXpub>; }   // m/84'/c'/0', 공개 정보(BackupPending·Unlocked)
// yw_core::btc::address (08)
pub fn p2wpkh_program(acct: &AccountXpub, chain: BtcChain, index: u32) -> Result<[u8; 20], KeyError>;
```

- **서명 시 확인.** 서명할 때 입력마다 `Vault::with_secp_key(KeyRef::Btc { coin, chain, index }, |ctx, sk| ..)`([02] §10.3) 안에서 공개키를 계산하고, 그 HASH160이 캐시 공개키로 만든 프로그램과 같을 때만 서명한다(§11.1). 다르면 `KeyMismatch`로 중단한다. 개인키는 클로저 밖으로 나가지 않는다.
- **EVM 계정과 같은 키(§3.5).** 계정의 키는 EVM 계정 i의 m/44'/60'/0'/0/i(mainnet·testnet4 같은 경로)다. 추가할 때 `Vault::evm_public_key(AccountIndex)`([02] §10.3, 공개 정보)로 압축 공개키를 받아 meta에 캐시하고, 서명할 때 `with_secp_key(KeyRef::Evm(EvmKeySource::Derived(i)))`로 빌린 키의 공개키가 캐시와 같을 때만 서명한다(다르면 `KeyMismatch`). 개인키를 내보내는 길은 `개인키 보기`의 `Vault::reveal_evm_shared_wif`(비밀번호 재입력, 압축 WIF, 네트워크 버전 바이트)뿐이다.

### 3.2 발급 인덱스

- `receive_next`, `change_next`: 다음에 처음 발급할 인덱스(u32, 초기 0). `last_used_receive`, `last_used_change`: 이력이 있는 가장 큰 인덱스(`Option<u32>`). 발급 인덱스는 체인마다 `BTC_MAX_ADDRESS_INDEX`(10,000) 미만이다: 받기 발급은 그 뒤 `IndexExhausted`, 잔돈이 필요한 계획은 `ChangeIndexExhausted`로 거부한다.
- **고정 주소 모드(§3.5, HD 계정의 기본).** 받기 화면은 늘 `(Receive, 0)`을 보인다(`receive_next == 0`이면 0을 발급·저장한 뒤). "새 주소"는 없고(`MetaError::SingleAddress`), 잔돈은 `(Receive, 0)`으로 가며 `change_next`를 쓰지도 올리지도 않는다(아래 잔돈 인덱스 규칙은 HD 모드 거래에만). 발견(§3.4)·감시 집합(§3.3)·이력 판정·`own_recipient`·`owned_scripts`는 HD 모드와 같다 — 그래서 HD 모드였을 때나 다른 HD 지갑이 다른 주소로 받은 돈도 보이고 코인 선택에 쓰인다. 아래 두 항목은 HD 모드의 규칙이다.
- **받기 주소.** 받기 화면은 `[last_used_receive+1(없으면 0), receive_next)` 범위의 가장 작은 인덱스 주소를 보여준다. 범위가 비어 있으면 `receive_next`를 발급한다. 발급은 `receive_next += 1`을 meta에 원자적으로 쓴 **뒤에** 주소를 표시한다. 크래시가 나도 같은 인덱스를 두 번 내주지 않는다.
- "새 주소" 버튼은 `receive_next`를 하나 더 발급한다. 이때 `unused_tail = receive_next - (last_used_receive+1 또는 0)`이 `BTC_GAP_LIMIT`(20) 이상이면 경고 창 "미사용 주소가 20개를 넘으면 다른 지갑으로 복구할 때 이후 입금이 보이지 않을 수 있습니다"를 띄우고 [이전 주소 사용] / [그래도 발급] 중 선택을 받는다. `unused_tail >= BTC_GAP_HARD_LIMIT`(100)이면 발급을 거부한다.
- 받기 화면에는 주소(소문자, 4자 묶음), 경로 `m/84'/{coin}'/0'/0/i`, QR(`bitcoin:` + 소문자 주소, qrcodegen ECC Medium, [04](04-app-ui.md) §2.8의 QR 그리기)을 표시한다.
- **잔돈 인덱스**는 계획(§7) 때 `change_next`를 쓴다. 그 거래가 `Broadcasting` 상태(§12.1)에 들어갈 때 `change_next = index + 1`로 올린다. `testmempoolaccept`에서 거부되어 전송하지 않은 거래의 인덱스는 다시 쓴다. `sendrawtransaction`이 `-25`·`-26`으로 거부한 거래(노드가 중계하지 않음)도 `change_next`가 그 거래 때문에 올라간 경우(`change_next == change_index + 1`)에만 `change_index`로 되돌린다. 시작할 때 `change_next = max(meta 값, 저널의 Broadcasting 이후 상태 항목들의 change_index + 1)`로 맞춘다(meta와 저널은 다른 파일이므로 둘 중 큰 값을 쓴다). 레코드의 `change_index`는 체인을 적지 않으므로(고정 주소 모드 잔돈은 index 0) 잔돈 출력 스크립트가 그 계정의 `(Receive, 0)`이면 잔돈 체인 인덱스로 세지 않는다(`BtcRecord::hd_change_index`: `Broadcasting`·`-25`/`-26` 되돌림·시작 맞춤·`inflight_change` 모두 이것을 쓴다). 그래서 모드를 바꿔도 이전 레코드가 맞게 읽힌다. 추적이 레코드 상태를 바꾸면(예: 공개된 `Rejected`가 `Confirmed`로 — RPC가 결국 퍼뜨려 되돌린 잔돈 인덱스가 체인에서 쓰였다) 그 네트워크의 계정마다 같은 맞춤을 다시 한다(`reconcile_change_next`, meta 쓰기 후 보고).
- **이력 판정**(§4.7): 인덱서 `Address` 응답의 `AddrSummary.tx_count > 0`(§4.3: `esplora` `chain_stats.tx_count + mempool_stats.tx_count`, `bb-*` `txs + unconfirmedTxs`)이면 사용된 주소로 보고 `last_used_*`를 올린다.

### 3.3 감시 집합

새로고침 대상 주소는 선택한 계정(§3.5)의 받기 `[0, receive_next)`와 잔돈 `[0, change_next)`이다(체인마다 `BTC_MAX_ADDRESS_INDEX`를 넘지 않는다). 서버에는 이 주소들을 하나씩만 보낸다. xpub·디스크립터·체인 코드·경로는 어떤 요청에도 넣지 않는다(D26). 인덱서 요청 생성기 `BtcIndexerReq`는 `BtcAddress`(우리 스크립트에서 인코딩한 값)와 `Txid` 타입만 받으므로 다른 문자열이 params·경로에 들어갈 수 없다(§4.3). `esplora` 경로에 들어가는 값은 선택한 계정의 주소(소문자 bech32·bech32m 또는 base58check, `[0-9A-Za-z]`)·소문자 txid hex뿐이라 퍼센트 인코딩이 필요 없다. `bb_getUTXOs`는 첫 인자로 xpub·디스크립터도 받지만 우리 요청에는 주소만 들어간다.

- **프라이버시.** 인덱서 운영자(기본 mempool.space, 선택 QuickNode·알케미)는 질의한 주소 목록과 요청 IP를 보고, 같은 연결·시간대의 질의로 주소들을 한 지갑으로 묶을 수 있다. 주소 단위 질의·xpub 미전송은 묶음을 어렵게 할 뿐 막지 못한다. 이는 spec.md §2.2의 공급자 의존 잔여 위험과 같은 부류로 보고 방어를 주장하지 않는다. 줄이려면 사용자가 `esploraBaseUrl`을 자체 Esplora로 바꾼다. 설정 화면에 고정 안내 T-BTC-ESPLORA-NOTE([04] §2.16)를 보인다.

### 3.4 발견 (가져오기·BTC 켜기·네트워크 변경 때)

```
for chain in [0, 1]:
    gap = 0; i = 0; last = None
    while gap < BTC_GAP_LIMIT:            // 20
        info = indexer.address(addr(chain, i))   // BtcIndexerReq::Address → AddrSummary, §4.3
                                                 // esplora GET /address/{a}; bb-rpc bb_getAddress [a, {"details":"basic"}]; bb-rest GET address/{a}?details=basic
        if info.tx_count > 0 { last = Some(i); gap = 0 } else { gap += 1 }
        i += 1
    next[chain] = last.map(|u| u + 1).unwrap_or(0)
receive_next = next[0]; change_next = next[1]; last_used_* = last; 그 다음 §4.7 새로고침
```

- 한 체인의 검사는 시작 인덱스부터 `BTC_DISCOVERY_MAX_SCAN`(1,000)개에서 멈춘다(모든 주소에 이력이 있다고 답하는 인덱서가 발견·감시 집합을 끝없이 키우지 못한다). "더 찾기"도 같다.
- 발견 중에는 진행률(검사한 주소 수)을 표시하고 취소할 수 있다. 취소하거나 실패하면 `discovery_done = false`로 남겨 송금을 막고 "주소 검색 미완료"와 [다시 시도]를 표시한다.
- "더 찾기" 버튼은 각 체인을 현재 `next`부터 20개 더 검사한다(수동 gap 확장). 이력이 나오면 위 규칙대로 계속한다. 결과는 `next = max(기존 next, last + 1)`로 적용해 발급 인덱스를 줄이지 않는다.
- **요청량.** 새 지갑이면 인덱서 호출 40회와 연결 검사(§2) 3–4회다. 받기 30개·잔돈 15개를 쓴 지갑이면 (30+20)+(15+20) = 85회에, 확정 미사용 출력이 있는 주소마다 인덱서 `Utxo` 1회, 새 UTXO의 이전 거래마다 Core `getrawtransaction` 1회가 더해진다. 요청 간격 200 ms(§4.4)이면 85회에 약 17초 걸린다(429 재시도 제외).
- **호출 비용.** 기본 `esplora`(공용 mempool.space)는 무료이고 키가 없다. 대신 공개 한도가 비공개이며 넘으면 429다(§4.4). Core JSON-RPC(현재 QuickNode)는 요금제 크레딧을 쓴다: 메서드별 크레딧은 문서에서 확인하지 못했다(§4.5 C3). 선택 인덱서: QuickNode BTC Blockbook 애드온(`bb-rpc`)은 유료 요금제 위 추가 월 요금(공개 페이지 기준 약 75달러부터)에 마켓플레이스 설명 기준 `bb_*` 호출당 10 크레딧(구 "Blockbook RPC" 애드온 설명은 20; 85회 발견이면 850 크레딧), 알케미 UTXO API(`bb-rest`) 1회당 CU는 미확인(알케미 Bitcoin JSON-RPC는 호출당 10 CU). 실측값은 §15 `BTC_INDEXER_COST_ASSUMED`에 적는다. 설계는 호출 비용에 의존하지 않는다.

### 3.5 주소 형식과 계정 (`btc::account`)

계정마다 주소 형식(`ScriptType`) 하나가 정해진다. `u8` 값은 meta·저널·vault(가져온 키, 태그 4)에 저장되므로 바꾸지 않는다.

| `ScriptType` | 이름(화면) | 접두 mainnet / testnet4 | HD 경로 | 우리 출력 | 입력 서명 | 입력 weight(추정) |
|---|---|---|---|---|---|---|
| `P2pkh` = 1 | 레거시 | `1…` / `m·n…` | BIP44 m/44'/c'/a' | `76 a9 14 HASH160(K) 88 ac` | 레거시 sighash, scriptSig `<DER‖01> <K>` | 588 (비압축 키 716) |
| `P2shP2wpkh` = 2 | 호환 세그윗 | `3…` / `2…` | BIP49 m/49'/c'/a' | `a9 14 HASH160(00 14 HASH160(K)) 87` | BIP143, scriptSig `16 00 14 <HASH160(K)>`(계획에 고정), 증인 `[DER‖01, K]` | 363 |
| `P2wpkh` = 3 | 네이티브 세그윗 | `bc1q…` / `tb1q…` | BIP84 m/84'/c'/a' | `00 14 HASH160(K)` | BIP143, 증인 `[DER‖01, K]` | 271 |
| `P2tr` = 4 | 탭루트 | `bc1p…` / `tb1p…` | BIP86 m/86'/c'/a' | `51 20 Q`, `Q = P + TaggedHash("TapTweak", P_x)·G`(스크립트 트리 없음) | BIP341 키 경로 `SIGHASH_DEFAULT`, 증인 `[schnorr64]` | 230 |

- **계정 종류.** `BtcAccountKey::Hd { script_type, account, xpub, single_address }`(캐시한 계정 노드에서 공개 파생; `single_address`는 아래 고정 주소 모드, 새 계정·새 지갑·이전 meta 모두 `true`), `BtcAccountKey::Single { id, script_type, pubkey }`(가져온 키 하나: 주소 `(Receive, 0)` 하나, `receive_next = 1`, `change_next = 0`, `discovery_done = true`, "새 주소" 없음(`SingleAddress`), 잔돈은 같은 주소) 또는 `BtcAccountKey::EvmShared { evm_index, script_type, pubkey }`(EVM 계정 `evm_index`(0–999)의 키 m/44'/60'/0'/0/i, 압축 공개키 캐시; 주소·발견·잔돈은 `Single`과 같다 — 한 키·한 주소). 비압축 공개키(65바이트, `04`)는 `P2pkh`로만 쓸 수 있다(`UncompressedNotP2pkh`). 계정 식별자는 `BtcAccountId::Hd { script_type, account }` / `Imported { id }` / `EvmShared { evm_index, script_type }`이고 `BtcAccountId::PRIMARY` = `Hd { P2wpkh, 0 }`(meta `btc`, §12.3). 술어: `is_single()` = 키 하나(`Single`·`EvmShared`: 발견 없음), `is_imported()` = vault 태그 4 레코드(`Single`만: 목록·내보내기·삭제·LoadMeta 맞춤의 대상), `fixed_address()` = 받기·잔돈이 늘 `(Receive, 0)`(키 하나 계정 전부 + `single_address`인 HD 계정).
- **고정 주소 모드(2026-11-05, D29).** UniSat·Xverse처럼 HD 계정이 주소 하나만 쓴다: 받기 주소는 늘 그 형식의 표준 첫 주소 `m/{44|49|84|86}'/{coin}'/a'/0/0`, 보내기의 잔돈도 그 주소(`change_path` = `(Receive, 0)`, 계획의 잔돈 index 0, 받는 주소가 그 주소여도 같음 — 가져온 키와 같은 코드). 같은 니모닉을 Electrum·Sparrow·UniSat에 넣으면 같은 주소가 나오고, 키를 나중에 하드웨어 키로 옮겨도 같은 주소이며, 소유 증명(§17)의 주소도 이것 하나다. 대가(사용자가 받아들임): 주소 재사용으로 그 주소의 잔액·거래가 모두 묶여 보인다. 발견(gap 20)·감시 집합·코인 선택은 HD 그대로라 다른 HD 주소(`/0/1`, `/1/0` …)에 있는 검증된 UTXO도 보이고 쓰인다(입력 키는 그 경로의 파생 키). 수수료 추정은 잔돈 출력이 같은 형식이라 그대로다(§7.2 `spk_len`). 저널·진행 중·공개(disclosed) 규칙은 바뀌지 않는다. 계정마다 `BtcMetaOp::SetAddressMode { network, account, single_address }`로 HD 모드(받을 때마다 새 주소, 잔돈 체인)와 오갈 수 있다: 인덱스·이력·UTXO는 그대로이고, 레코드의 잔돈은 출력 스크립트로 판단하므로(`change_candidates`, §3.2·§12.2-5) 모드를 바꾼 뒤에도 내 잔돈이 맞게 들어온다. BTC 승인이 열려 있으면 바꾸지 않는다("Bitcoin 승인이 진행 중이라 주소 방식을 바꿀 수 없습니다"). 키 하나 계정에는 모드가 없다(`SingleAddress`).
- **입력 키.** 서명할 입력마다 `BtcKeySource::Derived { script_type, account, chain, index }`(vault가 `KeyRef::Btc { coin: BtcCoin(purpose, account), chain, index }`로 파생), `BtcKeySource::Imported { id, script_type, compressed }`(vault 태그 4 레코드) 또는 `BtcKeySource::EvmShared { evm_index, script_type }`(vault가 `KeyRef::Evm(EvmKeySource::Derived(i))`로 빌려 줌, §3.1). 가져온 키는 yw-core 내부(`pub(crate)`) `BtcImportedKeys::btc_imported_secret`이 vault 태그 4 레코드에서 꺼낸다(`Unlocked`만, 없는 레코드 `RecordNotFound`, 잠김 `InvalidState` — 모두 `SignError::Vault`). 비밀키는 `ImportedBtcSecret`(복제 불가, `Debug` 가림, drop 때 지움)에 담겨 `sign_plan`의 서명 클로저에만 빌려 주고, 레코드의 네트워크·형식·압축 여부가 계정과 다르면 `KeyMismatch`다. 키를 빌려 주는 `BtcKeys`도 crate 내부라 yw-core 밖에서는 `sign_plan(&Vault, ..)`로만 서명한다(파생 키의 `with_secp_key`와 같은 원칙, [02] §10.3). 어느 쪽이든 빌린 비밀키로 계산한 공개키(같은 압축 형식)가 계정의 그 입력 공개키와 같아야 서명한다(§3.1 서명 시 확인).
- **[계정 추가].** Bitcoin 탭에서 형식을 고르면(§3.6 문구) key worker가 그 네트워크·형식의 다음 빈 account 번호(0–`BTC_MAX_HD_ACCOUNT`=99, P2WPKH는 1부터 — 0은 meta `btc`)의 노드를 `Vault::btc_account_xpub(BtcCoin)`로 받아 meta `btc_accounts`에 저장하고 선택한 뒤(meta 쓰기 후 보고) §3.4 발견을 실행한다. 계정은 최대 `MAX_BTC_ACCOUNTS`(64)개(두 네트워크 합)다. **키 출처.** 형식 버튼 위 라디오 "키 출처"는 기본 `BTC 표준 경로 (권장, 기본값)`(위 동작)이고, `EVM 계정과 같은 키`는 명시적으로 고르고 EVM 계정(meta `evm_accounts`의 파생 계정)을 고른 뒤 형식을 누르면 확인 창(T-BTC-EVM-SHARED, [04] §2.6)을 한 번 더 거친다. 확인하면 `BtcMetaOp::AddEvmShared { network, script_type, evm_index }`: key worker가 `Vault::evm_public_key`로 공개키를 받아 `BtcAccountKey::evm_shared`를 만들고, 같은 EVM index·형식의 계정이 그 네트워크에 이미 있거나 그 주소가 이미 어떤 계정의 주소(아래 주소 중복 거부와 같은 `btc_address_taken`)면 `DuplicateKey`(E-VLT-011)로 거부하며, 아니면 저장·선택한다(발견 없음). 키 전용 지갑에는 없다(`NoMnemonic`). 같은 EVM 키라도 형식이 다르면 다른 주소라 다른 계정이다. 가져온 키 계정은 `개인키 가져오기`(Bitcoin 탭)가 vault에 레코드를 저장한 뒤 `BtcMetaOp::AddImported { network: WIF의 네트워크, key: BtcAccountKey::single(레코드 id, 형식, 공개키) }`로 더하고 선택한다(발견 없음). "개인키로 시작하기"는 지갑을 만들 때 첫 meta에 같은 계정을 넣고 선택하며, 설정 `bitcoin`을 켜고 네트워크를 그 키의 네트워크로 둔다. meta를 읽을 때(`LoadMeta`) 계정이 없는 태그 4 레코드는 계정을 더하고, 레코드가 없거나 키·형식·네트워크가 다른 가져온 키 계정은 지운다(`MetaAddressMismatch` 로그, [02] §5.3). 가져온 키를 지우면(`삭제`, 비밀번호 확인) key worker가 vault 레코드를 지운 뒤 그 계정을 meta `btc_accounts`에서 지운다(`BtcMetaDone::Removed`, 선택은 기본 계정 또는 첫 계정으로). 그 계정에 BTC 승인이 열려 있거나, 그 주소의 거래(그 계정 식별자의 레코드와 §12.1 "같은 주소의 다른 계정" 레코드)가 아직 확정될 수 있으면(`BtcRecord::may_still_confirm`: 진행 중 1·3·4·5·6, `Replaced`, 살아 있는 `Abandoned`·공개된 `Rejected`, 그리고 30일 안의 모든 `Abandoned`) 지우지 않는다: 화면이 비밀번호 전에 이유를 보이고("Bitcoin 승인이 진행 중이라 이 가져온 키를 지울 수 없습니다…", "이 가져온 키의 주소로 보낸 거래가 아직 확정될 수 있습니다…"), key worker도 다시 확인해 `ImportedKeyBusy`로 거절한다. **주소 중복 거부.** 가져올 WIF의 주소(그 네트워크·고른 형식)가 이미 어떤 계정의 주소이면 — HD 계정의 검색 범위(체인마다 `[0, next + BTC_GAP_LIMIT)`, `BtcMeta::owned_scripts`) 또는 다른 가져온 키 — vault에 넣기 전에 `DuplicateKey`(E-VLT-011)로 거부한다(한 주소가 두 계정 식별자를 갖지 않게). 나중에 더하는 HD 계정은 검사하지 않으므로, 그런 별칭과 이 규칙 이전에 생긴 별칭은 §12.1 "같은 주소의 다른 계정"이 막는다.
- **선택.** 한 번에 한 계정이 선택된다(meta `btc_accounts.selected`, 없으면 기본 계정; 현재 네트워크에 없는 계정이 선택돼 있으면 기본 계정; 기본 계정이 없는 키 전용 지갑은 그 네트워크의 첫 계정 — `BtcAccounts::active_on`). 보내기·받기·새로고침·잔액·UTXO·활동은 선택한 계정의 것이고, D20(진행 중 1건)·입력 재사용 금지·포기 거래 충돌·검증 금액 기록·잔돈 인덱스 규칙은 **계정마다** 적용한다(`journal::btc::of_account`). 추적(§12.2)은 네트워크의 모든 계정 레코드를 따른다. BTC 승인이 열려 있으면 계정을 바꾸거나 더하지 않는다("Bitcoin 승인이 진행 중이라 계정을 바꾸거나 추가할 수 없습니다").
- **한 거래 = 한 계정.** 모든 입력은 선택한 계정의 UTXO이고, 잔돈은 그 계정의 잔돈 체인(같은 형식, HD 모드) 또는 받기 주소 `(Receive, 0)`(고정 주소 모드·가져온 키·EVM 키)이다. 받는 주소는 형식과 무관하게 §6.3의 5종 모두 가능하다.
- **지갑 수준 값.** `max_tip_seen`(§2 2단계)은 **팁 보관 계정**(`BtcAccounts::tip_holder`)에만 쓰고 읽는다: 기본 계정(meta `btc`)이 그 네트워크에 있으면 기본 계정, 없으면(키 전용 지갑) 그 네트워크의 첫 계정. 팁 보관 계정을 지우면 다음 첫 계정이 둘 중 큰 값을 이어받는다. 네트워크 사본 불일치(§2)는 기본 계정으로 판정한다. 키 전용 지갑에는 기본 계정이 없고 가져온 키 계정마다 자기 네트워크가 있으므로 불일치 판정이 없다: 설정 네트워크는 어느 계정을 보일지만 정한다.
- **키 전용 지갑(복구 단어 없음, [02] §8.5).** Bitcoin 계정은 가져온 키뿐이다: 기본 계정 만들기(`Create`)·발견·[계정 추가]가 없고(`VaultError::NoMnemonic` 문구), 켜기·네트워크 바꾸기는 설정만 바꾼다. 그 네트워크에 계정이 없으면 탭은 "이 네트워크에는 가져온 Bitcoin 개인키가 없습니다"(`BtcGate::NoAccount`)와 [개인키 가져오기]만 보인다. 잔액·받기·보내기·추적·수수료 올리기는 다른 계정과 같다.
- **이전 거래 검증(§5)·P2TR.** 모든 형식의 입력은 §5대로 txid 해시 검증한 이전 거래의 금액·스크립트만 쓴다(기대 스크립트 = 위 표의 우리 출력). BIP341은 모든 입력의 금액·scriptPubKey에 서명하므로 P2TR 입력의 sighash에는 검증된 값만 들어간다(한 입력 금액이 틀리면 모든 입력의 서명이 무효). 레거시 sighash는 금액에 서명하지 않으므로 P2PKH 입력 금액은 §5 검증과 §11.2-7 수수료 재계산으로만 보호된다.

### 3.6 [계정 추가] 문구와 화면 (S10 Bitcoin, S12)

- 계정 목록: 행마다 `{이름} · {형식 (접두)} · {사용 가능 잔액}`(예: `탭루트 계정 0 · 탭루트 (bc1p…) · 0.00100000 BTC (100,000 sats)`), 선택한 계정에 표시. 순서: 기본 계정, 그다음 `btc_accounts`에 더한 순서(HD·가져온 키 섞임). 이름: HD `네이티브 세그윗 계정 0`·`탭루트 계정 1`…, 가져온 키는 배지와 줄인 주소 `[가져온 키] {주소 앞 6자}…{끝 6자} · 네이티브 세그윗 (tb1q…) · 0.00100000 BTC (100,000 sats)`. 다른 곳(받기 카드·승인 창 계정 줄)의 가져온 키 계정 이름은 `가져온 키 · {형식}`이다.
- 가져온 키 줄이 선택돼 있으면 목록 아래에 백업 도움말(T-IMPORTED-KEY-BACKUP, 키 전용 지갑은 T-KEY-ONLY-BACKUP)과 [개인키 보기](WIF, W03 비밀번호 → W09)·[삭제](내보내기 먼저 확인 T-REMOVE-IMPORTED(계정 이름·주소) → W03; 키 전용 지갑의 마지막 키는 끔. vault 레코드가 지워지면 meta 쓰기가 실패해도 key worker는 그 계정을 세션에서 지우고 쓰기 오류만 알린다. 레코드가 없는 단일 키 계정에는 받기 주소를 내주지 않고(`BtcKeyError::KeyRemoved`) UI가 저장하는 meta에도 다시 쓰지 않는다 — vault가 진실 원천, [02] §8.4)를 보인다. 그 아래 한 줄 도움말과 [개인키 가져오기]. 누르면([04] §2.18, [계정 추가]처럼 같은 카드에서 열림) T-BTC-IMPORTED, 주소 형식 라디오(`네이티브 세그윗 (bc1q…, P2WPKH)`·`탭루트 (bc1p…, P2TR)`·`호환 세그윗 (3…, P2SH-P2WPKH)`·`레거시 (1…, P2PKH)`), T-KEYSTART-SCRIPT, [다음 (개인키 입력)]·[취소]([다음]이 W07을 연다; 켜지는 조건은 체인당 15개, 계정 목록 64개 미만, BTC 승인이 열려 있지 않을 때 — 가져온 계정이 선택되므로 [계정 추가]와 같은 규칙). 키의 네트워크가 설정 네트워크와 다르면 가져온 뒤 "가져온 키는 {네트워크} 키입니다. 지금 Bitcoin 네트워크가 {설정}라 계정 목록에 보이지 않습니다…"를 보인다.
- EVM 키 계정 줄: 배지 `[EVM 계정 {i} 키]`와 줄인 주소(가져온 키 줄과 같은 모양), 다른 곳의 이름은 `EVM 계정 {i} 키 · {형식}`, 노드·경로 텍스트는 `m/44'/60'/0'/0/{i}`. 선택돼 있으면 목록 아래 T-BTC-EVM-SHARED 도움말과 [개인키 보기](WIF, 가져온 키와 같은 T-REVEAL-WARN → W03 → W09; vault 레코드가 아니므로 [삭제]는 없다).
- **주소 방식(선택한 HD 계정).** 계정 목록 아래 `주소 방식 — {계정 이름}`과 라디오 `고정 주소 하나만 사용 (UniSat·Xverse 방식)`(기본) / `받을 때마다 새 주소 (HD, 프라이버시↑)`, 한 줄 도움말 T-BTC-MODE-HELP("고정 주소는 받기·잔돈이 늘 같은 주소(…/0/0)라 관리와 소유 증명이 쉽지만, 누구나 그 주소의 잔액과 거래를 모두 볼 수 있습니다. 새 주소 방식은 프라이버시가 낫지만 주소가 계속 바뀝니다."). 키 하나 계정에는 없다.
- [계정 추가] → 형식 고르기 도움말, "키 출처" 라디오(`BTC 표준 경로 (권장, 기본값)` 기본 선택과 도움말 "m/{44·49·84·86}'/{코인}'/{계정}'/0/0 — 같은 복구 단어를 다른 Bitcoin 지갑에 넣어도 같은 주소가 나옵니다." / `EVM 계정과 같은 키` — 고르면 주의 띠 T-BTC-EVM-SHARED와 EVM 계정 라디오 `{라벨} · {줄인 주소} · m/44'/60'/0'/0/{i}`(최대 32개, 처음은 첫 EVM 계정)), 선택지(이 순서): mainnet `네이티브 세그윗 (bc1q…, 권장)`, `탭루트 (bc1p…)`, `호환 세그윗 (3…)`, `레거시 (1…)`; testnet4 `네이티브 세그윗 (tb1q…, 권장)`, `탭루트 (tb1p…)`, `호환 세그윗 (2…)`, `레거시 (m·n…)`, 그리고 [취소]. 열 때마다 키 출처는 표준 경로로 돌아간다.
- 받기(S12): 카드 제목 `{계정 이름} · 받기 주소 {i}번`(HD 모드), `{계정 이름} · 고정 주소`(고정 주소 모드), 이름만(가져온 키·EVM 키), `주소 형식: {형식 (접두)}`, 고정 주소 모드면 정보 띠 T-BTC-FIXED-RECEIVE "이 계정은 주소 하나만 씁니다. 같은 니모닉을 Electrum/Sparrow/UniSat에 넣으면 같은 주소가 나옵니다.", QR(`bitcoin:` + 인코딩 그대로의 주소 — base58은 대소문자를 바꾸지 않는다), 경로 `m/{p}'/{c}'/{a}'/0/{i}`(가져온 키는 `가져온 키`, EVM 키는 `m/44'/60'/0'/0/{i}`), [주소 복사], HD 모드만 [새 주소], 아래 도움말(고정: 받은 돈과 잔돈이 모두 이 주소로 오고 주소 방식은 계정 카드에서 바꾼다; EVM 키: "이 계정은 주소 하나만 씁니다. EVM 계정 {i}과 같은 키(…)입니다." + T-BTC-EVM-SHARED; 가져온 키·HD: 기존 문구).

## 4. 데이터 원천: Core JSON-RPC(`bitcoin:<net>` 엔드포인트) + 주소 인덱서(`bitcoin.indexer`)

| 계층 | 위치 | 쓰는 곳 |
|---|---|---|
| Bitcoin Core JSON-RPC (§4.2) | `bitcoin:<net>` 엔드포인트 URL에 POST(현재 QuickNode, 인덱서와 무관) | 네트워크 고정, 이전 거래 원본, 수수료 추정, 사전 검사, 전송, 멤풀 추적 |
| 인덱서 `esplora` (기본, §4.3) | `bitcoin.esploraBaseUrl.<net>` + 경로 GET, 인증 없음(기본 mempool.space) | 주소별 이력·UTXO 후보, 확인 추적, Core 원본 실패 시 원본 hex 대체 |
| 인덱서 `bb-rpc` (선택) | Core 엔드포인트 URL에 `bb_*` JSON-RPC POST (QuickNode BTC Blockbook 애드온, 유료) | 같음 |
| 인덱서 `bb-rest` (선택) | `<Core 엔드포인트 URL>/api/v2/` GET (알케미 UTXO API, 같은 Blockbook JSON) | 같음 |

인덱서는 후보·이력만 준다. 서명에 쓰는 금액·스크립트는 Core `getrawtransaction`으로 txid에 대해 받은 원본(대체: 인덱서 `TxRaw`)을 §5로 해시 검증한 값만 근거로 한다. 수수료 추정·사전 검사·전송은 Core만 쓴다. Esplora의 수수료 API(`/fee-estimates` 등)는 쓰지 않고, Esplora `POST /tx`는 §11.3의 사용자 확인 수동 전송에만 쓴다.

### 4.1 전송 계층

- HTTPS·TLS·타임아웃·리다이렉트 금지·응답 크기 검사는 [04](04-app-ui.md) §1.9의 공용 RPC 전송 계층(yw-win WinHTTP, `Arc<Client>` 공유)을 쓴다. 타임아웃은 `Timeouts { 5000, 5000, 10000, 10000 }`, 호출 기한 10 s다(Esplora 포함). Core·`bb-*` URL은 `apikeys.dpapi`의 `bitcoin:<net>` 엔드포인트(§2, D13)이고 토큰이 들어가므로 로그·오류 메시지에 남기지 않는다. `esplora`는 같은 `Client`로 `http::Client::get(&HttpsUrl, max_response)`([01] §7.4: https만, `Accept: application/json`, 인증·쿠키·리다이렉트 없음)를 부른다. text/plain 경로도 이 헤더로 정상 응답한다(2026-10-27 실측). 수동 전송(§11.3)만 `http::Client::post`를 쓴다.
- 로그에는 `method` 이름(`bb_*` 포함), 인덱서 `idx=esplora|bb-rpc|bb-rest`와 경로 종류(`esplora`: `utxo`·`address`·`tx-status`·`tx-hex`·`block-height`·`tip-height`·`tx-post`, `bb-rest`: `utxo`·`address`·`tx`·`block-index`), HTTP 상태, RPC 오류 코드, txid만 쓴다(D28). Esplora 기준 URL도 쓰지 않는다(§2).
- JSON은 yw-json으로 파싱한다. **금액·수수료율은 JSON 숫자의 원래 10진 문자열을 정수 sats로 바꾼다**(§8.1). f64로 바꾸지 않는다. 숫자 원문은 yw-json `Number::as_str`로 받는다([01](01-repo-build.md) §2.3). Blockbook 금액(`value`·`balance`·`unconfirmedBalance`)은 sats 10진 **JSON 문자열**이다: `^(0|-?[1-9][0-9]{0,18})$`(음수는 `unconfirmedBalance`만)를 정수로 바꾸고, JSON 숫자로 오거나 형식이 다르면 `MalformedResponse`. Esplora 정수 필드는 아래 **Esplora 정수 규칙**을 따른다.
- **Esplora 정수 규칙.** Esplora는 sats·높이·개수를 **JSON 정수 숫자**로 보낸다(문자열 아님). 원문(`Number::as_str`)이 `^(0|[1-9][0-9]*)$`이고 자릿수·값이 필드 상한 이하일 때만 받는다: `value` ≤ `MAX_MONEY`(2,100,000,000,000,000, 16자리 이하), `vout`·`block_height`·`*_txo_count`·`tx_count` ≤ 4,294,967,295(u32, 10자리 이하), `block_time` ≤ 2^63−1. 소수점(`1.0`)·지수(`1e3`·`1E3`)·부호(`-1`·`+1`)·앞자리 0(`01`)·JSON 문자열(`"1000"`)·`null`·상한 초과는 응답 전체를 `MalformedResponse`(E-BTC-004)로 처리한다.
- 알 수 없는 응답 필드는 무시한다(예: Esplora `funded_txo_sum`·`spent_txo_sum`). 필요한 필드가 없거나 타입이 다르면 응답 전체를 `MalformedResponse`로 처리한다. Esplora 응답은 `Content-Type` 미디어 형식(매개변수·대소문자 무시)이 경로별 기대값(`application/json` 또는 `text/plain`, §4.3)과 다르면 `MalformedResponse`다.
- **서버가 보낸 문자열은 화면에 그대로 표시하지 않는다**(§13). RPC `error.message`, `reject-reason`, `warnings`, HTTP 본문(Esplora 오류 본문 예 `Transaction not found`·`Invalid Bitcoin address` 포함)이 모두 해당한다.

### 4.2 Core JSON-RPC (POST, §2 엔드포인트 URL)

요청: `{"jsonrpc":"2.0","id":<u64 증가>,"method":M,"params":[...]}`. 응답의 `id`는 요청과 같아야 하고, `result`와 `error` 중 정확히 하나만 null이 아니어야 한다. `jsonrpc` 필드가 있으면 값은 `"2.0"`이어야 한다(Core 1.0식 `{"result","error","id"}`도 받는다). HTTP 401·403·429가 아닌 2xx 밖의 상태라도 본문이 이 규칙의 `error` 봉투이면 그 `code`로 분류한다(Core는 1.0식 요청의 RPC 오류를 HTTP 500·404로 준다). 이 봉투 규칙은 `bb-rpc` 인덱서 호출(§4.3)에도 그대로 쓴다.

| 메서드 | params | 용도 | 응답 검사 | 응답 상한 |
|---|---|---|---|---|
| `getblockhash` | `[0]` | 제네시스 | hex 64자 | 4 KiB |
| `getblockchaininfo` | `[]` | chain, 팁, IBD | §2 | 16 KiB |
| `getrawtransaction` | `[txid, false]` | 이전 거래 원본 | hex 문자열, 길이 짝수, 디코드 후 `<= BTC_MAX_PREV_TX_BYTES` | 801 KiB |
| `estimatesmartfee` | `[target, "economical"]` | 수수료 추정 | `feerate`(BTC/kvB)가 있으면 사용, 없거나 `errors`만 있거나 §8.1 형식이 아니거나(지수·9자리 이상 소수·부호·문자열) 0이면 추정 없음 | 4 KiB |
| `getmempoolinfo` | `[]` | 하한·증분 | `mempoolminfee`, `minrelaytxfee`(필수), `incrementalrelayfee`(BTC/kvB; 없거나 형식이 다르면 1,000 sat/kvB) | 4 KiB |
| `testmempoolaccept` | `[[hex], maxfeerate]` | 전송 전 검사 | 원소 1개, §11.3 | 16 KiB |
| `sendrawtransaction` | `[hex, maxfeerate, 0]` | 전송 | txid hex 64자 | 4 KiB |
| `getmempoolentry` | `[txid]` | 미확정 추적 | 객체면 멤풀에 있음, `-5`면 없음 | 16 KiB |
| `gettxout` | `[txid, vout, true]` | UTXO 후보 확인(§4.7-3) | 객체(`value` BTC 10진, `scriptPubKey.hex` 소문자, `confirmations`, `coinbase`)면 미사용, `result: null`이면 사용됨(멤풀 포함)·없음. 이 메서드만 `null` 결과를 답으로 받는다 | 16 KiB |

- 메서드·params는 Bitcoin Core 표준이며 공급자와 무관하다. QuickNode 공개 문서(2026-10 확인)에는 `getblockchaininfo`·`getrawtransaction`(`txid`, `verbose`, `blockhash`)·`estimatesmartfee`·`getmempoolinfo`·`testmempoolaccept`(`rawtxs`, `maxfeerate`) 페이지가 있고, `getmempoolentry` 문서 페이지는 찾지 못했다. 문서 유무와 관계없이 표의 9개 메서드 모두 사용자 엔드포인트에서 구현 시 확인한다(§4.5 C1·C2). `getblockhash`·`getblockchaininfo`는 2026-10-27 두 네트워크에서 확인했다(§4.5 사전 실측).
- 호출 비용 단위는 공급자마다 다르다(알케미 호출당 10 CU, QuickNode 메서드별 크레딧은 이 문서에 고정하지 않음, §3.4).
- `scantxoutset`은 쓰지 않는다(공급자 지원이 불확실하고 느리다). 주소 조회는 인덱서(§4.3)로만 한다.

### 4.3 주소 인덱서 (주소 단위, `bitcoin.indexer`, §2)

요청은 `BtcIndexerReq`로만 만들고, 형식별 파서가 응답을 같은 내부 타입 `BtcIndexerResp`로 바꾼다. 소비 코드(§3.4·§4.7·§5·§12.2)는 인덱서 형식을 모른다. `bb-rpc`는 §4.2 봉투, `bb-rest`·`esplora`는 GET(`Accept: application/json`)이다.

```rust
pub enum BtcIndexerReq { Utxo(BtcAddress), Address(BtcAddress), TxStatus(Txid), TxRaw(Txid), GenesisHash, TipHeight }
pub enum BtcIndexerResp {
    Utxo(Vec<UtxoCandidate>),   // 원소 <= BTC_INDEXER_MAX_UTXOS(1000), outpoint 중복 없음
    Address(AddrSummary),
    TxStatus(TxSeen),
    TxRaw(Vec<u8>),             // 디코드한 원본 바이트. §5 검증 전에는 쓰지 않는다
    GenesisHash([u8; 32]),      // 표시 순서 hex를 디코드한 바이트(§2 상수와 같은 순서)
    TipHeight(u32),             // esplora만
}
pub struct UtxoCandidate { pub outpoint: OutPoint, pub value_hint: Sats, pub height: Option<u32> }   // None = 미확정
pub struct AddrSummary { pub tx_count: u64, pub confirmed_unspent: bool, pub unconfirmed_incoming: bool }
pub enum TxSeen { Confirmed { height: u32 }, Unconfirmed, NotFound, UnconfirmedOrUnknown }
pub fn conf(height: u32, tip_height: u32) -> u32;   // tip_height >= height ? tip_height - height + 1 : 0
```

- 확인 수는 모든 형식에서 `conf(height, tip_height)`로 계산한다. `tip_height`는 §2 2단계 Core `blocks`다(서버 기준, §4.6). 인덱서 높이가 Core 팁보다 크면 0(아직 후보 아님)이다. `bb-*`의 `confirmations` 필드는 확정 여부(≥ 1) 판정에만 쓴다.
- txid는 표시 순서 소문자 hex 64자(`^[0-9a-f]{64}$`)로 주고받고 내부 `Txid`는 뒤집은 바이트다(§6.5). 대문자·길이 오류는 `MalformedResponse`.

| 요청 | `esplora` (기본, GET `<esploraBaseUrl>` ‖ 경로) | `bb-rpc` (QuickNode BTC Blockbook 애드온) | `bb-rest` (알케미 UTXO API, `<URL>/api/v2/` 아래) | 응답 상한 |
|---|---|---|---|---|
| `Utxo` UTXO 후보 | `/address/{addr}/utxo` (`application/json`, 확정·미확정 모두) | `bb_getUTXOs [addr, {"confirmed":true}]` | `utxo/{addr}?confirmed=true` | 1 MiB, 원소 ≤ 1000 |
| `Address` 이력 유무·확정 미사용 출력·미확정 입금 | `/address/{addr}` (`application/json`) | `bb_getAddress [addr, {"details":"basic"}]` | `address/{addr}?details=basic` | 16 KiB |
| `TxStatus` 확인 추적(§12.2) | `/tx/{txid}/status` (`application/json`) | `bb_getTx [txid]` | `tx/{txid}` | `esplora` 4 KiB, `bb-*` 2 MiB |
| `TxRaw` 원본 대체(Core `getrawtransaction` 실패 시만, §4.7-4) | `/tx/{txid}/hex` (`text/plain`) | `bb_getTx [txid]`의 `hex` | `tx/{txid}`의 `hex` | `esplora` 801 KiB, `bb-*` 2 MiB |
| `GenesisHash` 인덱서 네트워크 고정(§2 3단계) | `/block-height/0` (`text/plain`) | `bb_getBlockHash ["0"]` | `block-index/0` | 4 KiB |
| `TipHeight` 팁 교차 확인(§2 4단계) | `/blocks/tip/height` (`text/plain`) | 만들지 않음 | 만들지 않음 | 4 KiB |

**`esplora` 응답 → 내부 타입.** 근거: Blockstream `esplora/API.md`, mempool.space REST 문서, 2026-10-27 mempool.space mainnet·testnet4 실측(§4.5). 성공은 HTTP 200뿐이다. 정수는 §4.1 Esplora 정수 규칙, txid·해시는 위 hex 규칙을 따른다.

| 요청 | 응답 형식 | 매핑·검사 |
|---|---|---|
| `Utxo` | JSON 배열. 원소 `{txid, vout: u32, value: sats 정수, status: {confirmed: bool, block_height?: u32, block_hash?: hex64, block_time?: 정수}}` | `UtxoCandidate { outpoint: (txid, vout), value_hint: value, height: confirmed ? Some(block_height) : None }`. `confirmed == true`면 `block_height`·`block_hash`·`block_time`이 모두 있어야 하고, `false`면 셋은 없거나(mempool.space 실측) `null`(API.md)이어야 한다. `status` 없음, outpoint 중복, 원소 1000개 초과 → `MalformedResponse`. 배열 순서는 의미가 없다. 멤풀에서 이미 쓰인 출력은 빠져 있다(Esplora 동작; 완전성은 주장하지 않음, §4.6) |
| `Address` | JSON 객체 `{address, chain_stats: S, mempool_stats: S}`, `S = {funded_txo_count, spent_txo_count, tx_count, …}`(모두 u32 정수) | `address`는 요청 주소(소문자)와 같아야 한다. `S`마다 `tx_count == 0`이면 `funded_txo_count == spent_txo_count == 0`, `chain_stats.spent_txo_count ≤ chain_stats.funded_txo_count`, `c.spent + m.spent ≤ c.funded + m.funded`(멤풀 거래는 확정 출력도 쓰므로 `mempool_stats`만으로는 비교하지 않는다). 어긋나면 `MalformedResponse`. `tx_count = c.tx_count + m.tx_count`, `confirmed_unspent = c.funded > c.spent`, `unconfirmed_incoming = m.funded > 0`. `*_txo_sum`은 읽지 않는다 |
| `TxStatus` | JSON 객체 `{confirmed: bool, block_height?, block_hash?, block_time?}`(`Utxo`의 `status`와 같은 규칙) | `true` → `Confirmed { height: block_height }`, `false` → `UnconfirmedOrUnknown`. **없는 txid에도 HTTP 200 `{"confirmed":false}`를 주므로**(2026-10-27 mempool.space·blockstream.info 실측) 멤풀 존재를 뜻하지 않는다(§12.2). 404 → `NotFound`(방어) |
| `TxRaw` | `text/plain` 본문 = 원본 hex `^([0-9a-f]{2})+$`(앞뒤 공백·줄바꿈 없음), 디코드 후 `<= BTC_MAX_PREV_TX_BYTES` | 바이트 → §5(txid 해시 검증). 404 → `NotFound` |
| `GenesisHash` | `text/plain` 본문 = 정확히 `^[0-9a-f]{64}$` | §2 3단계에서 상수와 비교. 404·형식 이상은 불일치가 아니라 호출 실패(E-BTC-004)이고, 3단계를 통과할 때까지 주소 요청을 하지 않는다 |
| `TipHeight` | `text/plain` 본문 = `^(0\|[1-9][0-9]{0,9})$`, ≤ u32 | §2 4단계 |

- **`esplora` HTTP 상태.** 200 → 위 표. 400(`Utxo`·`Address`) → E-BTC-005: mempool.space는 UTXO 500개 초과 주소와 다른 네트워크 주소에 400을 준다(2026-10-27 실측, 본문은 읽지 않는다). 404 → 위 표(`TxStatus`·`TxRaw`는 `NotFound`, 그 밖은 E-BTC-004). 429 → §4.4. 401·403 → E-BTC-007. 3xx(리다이렉트를 따르지 않는다)·5xx·그 밖 → E-BTC-001. 전송 오류는 [04] §1.9 분류(E-RPC-001·002·008)를 원인 코드로 붙인 E-BTC-001이다.
- **`bb-*` 응답 → 내부 타입.**

  | 요청 | 쓰는 필드 | 매핑 |
  |---|---|---|
  | `Utxo` | 배열 원소 `txid`(hex 64), `vout`(u32), `confirmations`(u32), `height`(u32), `value`(sats 10진 문자열) | `confirmations >= 1`인 원소만 `height: Some(height)`(옵션 `confirmed:true`라 미확정은 오지 않는다; 오면 버린다), `value_hint = value` |
  | `Address` | `txs`(u32), `unconfirmedTxs`(u32), `balance`, `unconfirmedBalance`(sats 10진 문자열, 음수 가능) | `tx_count = txs + unconfirmedTxs`, `confirmed_unspent = balance != "0"`, `unconfirmed_incoming = unconfirmedBalance > 0` |
  | `TxStatus` | `confirmations`(u32), `blockHeight`(i64, 미확정 값은 §4.5 B2에서 확인) | `confirmations >= 1` → `Confirmed { height: blockHeight }`, 0 → `Unconfirmed`, 거래 없음 오류 → `NotFound` |
  | `TxRaw` | `hex` | 바이트 → §5 |
  | `GenesisHash` | `blockHash`(hex 64) | §2 3단계 |

- Blockbook 메서드 이름·params는 QuickNode 문서(`/docs/bitcoin/blockbook/overview`와 메서드 페이지, 2026-10 확인)와 같다: JSON-RPC ↔ REST 대응은 `bb_getUTXOs` = `GET /api/v2/utxo/{addressOrXpub}`, `bb_getAddress` = `/api/v2/address/{address}`, `bb_getTx` = `/api/v2/tx/{txid}`, `bb_getBlockHash` = `/api/v2/block-index/{height}`. `bb_getUTXOs` 옵션은 `confirmed`(bool)·`gap`(xpub 전용, 보내지 않음), `bb_getAddress` 옵션은 `page`·`size`(REST는 `pageSize`)·`fromHeight`·`toHeight`·`details`(`basic`|`txids`|`txs`) 등이다. `bb_getBlockHash` 인자는 문서상 문자열 높이다.
- 선택 인덱서 사용 시 확인(§4.5 B1–B3): QuickNode `bb_getTx` 문서의 응답 예시는 Ethereum 형식이라 Bitcoin 응답의 `hex`·`blockHeight`(미확정)·`confirmations` 값을 실측으로 확정한다. `bb_getBlockHash`가 숫자 인자도 받는지, 알케미가 `block-index/`를 지원하는지 확인한다.
- 만들지 않는 요청: xpub·디스크립터 인자, `bb_getXpub`·`/xpub/`, `bb_sendTransaction`·`sendtx`, `bb_getBalanceHistory`, tickers, `details:"txids"`·`"txs"`, Esplora `/address/{a}/txs*`(받은 거래 목록을 만들지 않는다, §1.2; 이력 판정은 개수로 충분하다), `/scripthash/*`, `/tx/{txid}`(전체 JSON; `status`·`hex`로 충분), `/tx/{txid}/outspend*`, `/mempool*`, `/fee-estimates`·mempool.space `/v1/fees/*`(수수료는 Core만, §8), `POST /tx`(§11.3 수동 전송 함수만 만들고 요청 생성기에는 없다). 전송은 Core `sendrawtransaction`이 기본이다.
- `value_hint`·`balance`를 금액으로 쓰지 않는다. 금액은 §5 검증 값만 쓴다. 두 값이 다르면 해당 UTXO에 "서버 응답 불일치" 표시를 붙이고 검증 값을 쓴다. `bb_getUTXOs`의 `coinbase` 필드(문서상 확인 수 100까지만 판정)는 쓰지 않고 §5가 원본에서 판정한다.
- `bb-*` 오류: HTTP 401/403과 애드온이 꺼진 엔드포인트의 `bb_*` 오류(QuickNode `-32601`, §4.5 사전 실측)는 E-BTC-007, 거래 없음(`bb-rest` 404, `bb-rpc`는 §4.5 B3에서 기록한 오류 코드)은 `NotFound`, 429는 §4.4, 5xx·시간 초과는 E-BTC-001이다. B3에서 거래 없음 코드를 기록하기 전에는 `bb-rpc`의 그 밖 오류 코드와 `bb-rest`의 그 밖 상태(400 포함)도 E-BTC-001, `bb-rest` 404(거래 외 요청)는 E-BTC-004다. 서버 문자열은 표시하지 않는다(§13).

### 4.4 속도 제한

- BTC 요청(Core·인덱서 모두)은 한 줄로 순차 실행하고 요청 시작 간격을 `BTC_REQ_MIN_INTERVAL_MS`(200 ms) 이상 둔다(초당 5회 이하).
- **429.** `BTC_429_BACKOFF_MS`(2,000 → 4,000 → 8,000 ms)만큼 기다린 뒤 같은 요청을 최대 3회 재시도한다. `Retry-After` 헤더는 읽지 않는다([01] §7.4 `Response`에 헤더가 없다). 네 번째도 429면 그 작업(새로고침·발견·추적 1회)을 중단하고 인덱서면 E-BTC-002, Core면 E-RPC-004를 보인다. 발견이면 `discovery_done = false`로 남는다(§3.4 [다시 시도]). 중단 뒤 `BTC_429_COOLDOWN_SECS`(300초) 동안 자동 새로고침(§4.7 60초 주기)은 건너뛰고, 사용자가 누른 새로고침만 실행한다(반복 초과로 인한 차단 방지).
- 5xx·시간 초과는 재시도하지 않는다([04] §1.9, E-BTC-001).
- **공용 mempool.space 한도.** 문서는 수치를 공개하지 않고, 넘으면 429이고 반복해서 넘으면 접근이 막힐 수 있다고만 적는다. 2026-10-27 실측: 같은 IP에서 약 4–5회/초로 25회 순차 요청 → 모두 200, 한도 관련 응답 헤더 없음. 한도가 더 낮아도 위 규칙으로 동작하며(느려질 뿐) 잘못된 잔액으로 서명하지 않는다(§4.6). 계속 막히면 사용자가 다른 Esplora URL이나 선택 인덱서로 바꾼다.
- 잠긴 상태에서는 BTC 네트워크 호출을 하지 않는다(감시 집합이 암호화된 meta에 있다). 예외는 설정의 `Esplora 테스트`([04] §2.11, `/block-height/0`만, 주소 없음)다.

### 4.5 M8 착수 검사 (D26, 1회 체크리스트)

**사전 실측(2026-10-27).**
- Core(QuickNode, `scripts/probe-rpc.mjs`): mainnet·testnet4 엔드포인트 모두 Core JSON-RPC 동작(`getblockhash 0` 제네시스 일치, `getblockchaininfo.chain` = `main`·`testnet4`; testnet4 서브도메인 `btc-testnet4`). `bb_getBlockHash`는 두 네트워크 모두 `-32601`(Method not found) → Blockbook 애드온은 꺼져 있다. 기본 인덱서가 `esplora`이므로 **M8을 막지 않는다**(애드온은 `bb-rpc`를 고를 때만 필요).
- Esplora(mempool.space, `curl`): `/api/block-height/0`·`/testnet4/api/block-height/0` → 200 `text/plain`, 본문 = §2 제네시스. `/blocks/tip/height` → 200 `text/plain` 정수. `/address/{a}` → `application/json`, `address` 반향 + `chain_stats`·`mempool_stats` 각각 `funded_txo_count`·`funded_txo_sum`·`spent_txo_count`·`spent_txo_sum`·`tx_count`(정수; abandon 니모닉 0/0 주소는 mainnet `tx_count` 178, testnet4 119). `/address/{a}/utxo` → 원소 `{"txid","vout","status":{"confirmed":true,"block_height","block_hash","block_time"},"value"}`, 미확정 원소는 `"status":{"confirmed":false}`(다른 키 없음), `value`는 JSON 정수. 없는 txid: `/tx/{txid}/status` → 200 `{"confirmed":false}`, `/tx/{txid}/hex` → 404. UTXO 500개 초과 주소의 `/utxo`·다른 네트워크 주소 → 400, 끝 `/` → 404, `http://` → 301. `Accept: application/json`이어도 text 경로는 200 `text/plain`. 약 4–5회/초 25회 순차 → 429 없음. blockstream.info(`/api`, `/testnet4/api`)도 같은 형식·제네시스.

**검사.** M8 착수 때 아래를 1회 다시 수행하고 [09](09-testing.md) §2.5 형식으로 기록한다. E·C는 필수이고, B는 `bitcoin.indexer`를 `bb-rpc`·`bb-rest`로 쓰기로 한 경우만 한다. Esplora 기준 URL은 비밀이 아니므로 `curl.exe -s -i <기준 URL><경로>` 출력을 그대로 기록해도 된다. Core·`bb-*` 호출은 §2의 `rpc.json` 규칙을 따른다(URL·토큰 출력 금지).

| ID | 대상 | 절차 → 기대 |
|---|---|---|
| E1 | `esploraBaseUrl` 두 네트워크(기본 mempool.space) | `/block-height/0` → 200 `text/plain`, 본문 = §2 제네시스. `/blocks/tip/height` → 정수, Core `getblockchaininfo.blocks`와 차 ≤ 3 |
| E2 | 같음 | `/address/<사용된 주소>`(mainnet `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu`, testnet4 `tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl` — abandon 니모닉 0/0, §14.1) → `tx_count > 0`, 필드 이름·타입이 §4.3과 같음. 새로 만든 미사용 주소 → 모든 개수 0. 확정 UTXO가 있는 공개 주소의 `/utxo` → 원소 필드·`status`가 §4.3과 같음(`value` JSON 정수) |
| E3 | 같음 | 확정 거래 `/tx/<txid>/status` → `confirmed: true` + `block_height`·`block_hash`·`block_time`. `/tx/<txid>/hex` → 200 `text/plain` 소문자 hex(응답을 §14.2 픽스처로 저장해 M8-2에서 §5 검증 통과 확인). 없는 txid → `{"confirmed":false}` / 404 |
| C1 | Core 엔드포인트 | 오래된 남의 거래에 `getrawtransaction [txid,false]` → hex(txindex 여부). 실패하면 이전 거래 원본은 인덱서 `TxRaw`(`esplora` `/tx/{txid}/hex`, `bb-*` `hex`)로 받는다(§5 검증 동일, §4.7-4). 직접 입력한 노드에 txindex가 없을 때도 같다 |
| C2 | Core 엔드포인트 | JSON-RPC 응답 형식(`jsonrpc`, `id` 반향), `estimatesmartfee`가 testnet4에서 추정을 돌려주는지, `getmempoolinfo` 필드, `getmempoolentry` 제공 여부(멤풀 안·밖 txid 각 1개), `testmempoolaccept`·`sendrawtransaction`의 `maxfeerate` 인자 허용 여부 |
| C3 | Core 엔드포인트 | 메서드별 크레딧을 대시보드 사용량으로 확인해 §15 `BTC_INDEXER_COST_ASSUMED`에 적는다(`esplora`는 0) |
| B1 | (선택) `bb-rpc`: QuickNode 대시보드에서 두 엔드포인트에 BTC Blockbook 애드온을 켠다(유료 요금제 위 추가 요금, 공개 페이지 기준 월 약 75달러부터). `bb-rest`: 알케미 엔드포인트(§2 템플릿, 요금제에서 UTXO API 사용 가능 여부 포함) | mainnet·testnet4 `bb_getUTXOs ["<잔액 있는 공개 주소>", {"confirmed":true}]`(`bb-rest` `utxo/`, testnet4 기준 경로 형식 포함) → 배열, 필드 이름·타입이 §4.3과 같음(`value` 문자열 포함) |
| B2 | (선택) 같음 | `bb_getAddress`(`details:"basic"`), `bb_getTx`(확정·미확정 거래의 `confirmations`·`blockHeight`, `hex` 유무) 필드 |
| B3 | (선택) 같음 | `bb_getBlockHash ["0"]`(결과 = §2 제네시스, 숫자 인자 허용 여부; `bb-rest` `block-index/0` 지원 여부). 애드온을 끈 엔드포인트와 없는 txid의 `bb_*` 오류 코드·HTTP 상태를 기록한다(§4.3) |
| B4 | (선택) 같음 | `bb_*`(또는 REST) 1회당 크레딧·CU를 대시보드로 확인해 `BTC_INDEXER_COST_ASSUMED`에 적는다 |

- **판정·대안(D26).** E1–E3과 C1(또는 그 대체 경로)이 통과하면 M8을 시작한다. mempool.space가 E1–E3에서 실패하면 다른 Esplora URL(예: blockstream.info, 자체 운영 Esplora)로 다시 하거나, B1–B4를 통과한 선택 인덱서를 쓴다. 쓸 수 있는 인덱서가 하나도 없거나, Core `getrawtransaction`과 인덱서 `TxRaw`가 모두 실패하면(입력 검증 불가) M8을 보류한다. B 실패는 그 선택 인덱서를 쓰지 않을 이유일 뿐 M8을 막지 않는다. C2 실패는 미결 4의 대안으로 처리한다.

### 4.6 신뢰 경계

| 악성·오류 서버가 할 수 있는 일 | 결과 | 대응 |
|---|---|---|
| 입력 금액 거짓(CVE-2020-14199) | 수수료 폭증 | §5 이전 거래 해시 검증. 금액은 txid가 고정하는 원본에서만 가져온다. |
| 다른 체인(`esploraBaseUrl` 오설정 포함) | 엉뚱한 잔액·전송 | §2 제네시스·chain 검사(Core 1·2단계, 인덱서 3단계). 인덱서 불일치는 E-BTC-003 차단 |
| 인덱서와 Core가 다른 데이터 | 없는 txid·다른 금액 | 금액·스크립트는 txid로 해시 검증한 원본(§5)만 믿는다(원본은 Core가 기본, 인덱서 `TxRaw`는 대체). 원본을 못 받으면 그 UTXO를 쓰지 않는다. |
| 가짜 UTXO(자기모순 없는 가짜 원본) | 가짜 잔액. 서명해도 체인에서 무효 | 서명할 수는 있지만 자산은 잃지 않는다. 확인 수는 서버 기준이라고 표시한다. |
| UTXO·이력 숨김 | 잔액이 적게 보임, 주소 재사용 | 발급 인덱스를 로컬에 보관한다. 완전성은 주장하지 않는다. |
| 확인 수·팁 높이 거짓 | 미확정을 확정으로 오인, nLockTime이 아직 최종이 아님 | 확인 수는 인덱서 높이와 Core 팁으로 계산한다(§4.3 `conf`). 남의 UTXO는 확정분만 쓴다. 거짓 높이는 전송 실패(DoS)로만 이어진다. SPV 검증은 v1에 없다. |
| 수수료 추정 조작 | 과다·과소 지불 | Core만 쓴다. §8 하한·상한·비율 |
| 전송 검열 | 거래가 나가지 않음 | `BroadcastUnknown`, 재전송, 수수료 올리기, 사용자 확인 후 Esplora 수동 전송(§11.3) |
| 요청 한도·차단(429) | 조회 지연, 발견 미완료 | §4.4 백오프·중단. 발견 미완료면 송금 금지(§3.4), 잔액은 검증 UTXO만 |
| 인덱서 운영자(공용 Esplora 포함)가 질의 주소·IP를 봄 | 주소 묶음·IP 노출(프라이버시) | 주소 단위 질의, xpub 미전송(§3.3). 방어는 주장하지 않는다(spec.md §2.2 공급자 의존 잔여 위험과 같은 부류). 자체 Esplora로 바꿀 수 있다 |
| 오류 문자열 피싱 | — | 서버 문자열을 표시하지 않음(§13) |
| 큰·잘못된 응답 | 파서 DoS | 크기 상한, 엄격 파서(§4.1, §6.5) |

### 4.7 새로고침

BTC 화면을 열 때, 사용자가 누를 때, 진행 중 거래가 있으면 60초마다(잠금 해제 상태일 때만, §4.4 429 쿨다운 중이면 건너뜀) 실행한다.

1. `check_chain()`(10분 캐시; 캐시가 유효해도 팁 높이를 새로 받기 위해 2단계 `getblockchaininfo`는 매번 한다)과 `getmempoolinfo`.
2. 감시 집합의 주소마다 인덱서 `Address`(§4.3)를 호출해 `tx_count`로 이력을 판정(§3.2)하고, `unconfirmed_incoming`이면(진행 중 저널 항목의 잔돈 주소는 제외) "미확정 입금 있음(미검증, 교체될 수 있음)"을 표시한다.
3. `confirmed_unspent`인 주소마다 인덱서 `Utxo`(§4.3)를 호출한다. 후보는 `height`가 있고 `conf(height, tip_height) >= 1`인 원소뿐이다(`esplora`가 주는 미확정 원소는 버린다, §7.4). 후보마다 Core `gettxout [txid, vout, true]`로 노드 자신의 보기를 확인한다: `null`(체인이나 멤풀에서 사용됨·없음), 그 주소의 스크립트가 아님, `confirmations == 0`이면 후보에서 뺀다. 객체면 높이를 Core 기준 `tip_height + 1 - confirmations`로 쓴다. 엔드포인트에 `gettxout`이 없거나(`-32601`, 이후 그 새로고침에서 부르지 않음) 호출이 실패하면 인덱서 높이를 그대로 쓰고 UTXO 목록에 "인덱서만 확인(노드 미확인)"을 표시한다(429 중단은 §4.4).
4. 처음 보는 outpoint마다 Core `getrawtransaction`으로 원본을 받아 §5로 검증하고 `BtcMeta.verified`에 넣는다. 3단계 `gettxout`의 `value`·`coinbase`가 검증 값과 다르면 검증 실패로 센다. Core가 원본을 주지 못하면(RPC 오류·전송 실패) 인덱서 `TxRaw`로 1회 받아 같은 §5 검증을 한다(§4.5 C1). 검증에 실패한 outpoint는 "검증 실패 UTXO n개"로만 세고 잔액·선택에서 뺀다.
5. 최신 목록에 없는 `verified` 항목은 지운다. 단, 진행 중 저널 항목(§12.1)이 쓰는 outpoint·그 잔돈과 살아 있는 `Abandoned`·공개된 `Rejected` 항목(§12.1)의 입력은 남긴다(멤풀에서 쓰인 출력은 인덱서 목록에서 빠지지만 RBF와 포기 뒤 보내기가 그 값을 쓴다, §9·§12.1). 자기 거래의 잔돈은 저널 원본에서 직접 만든다(§12.2).
6. 잔액 = 확인 수 1 이상(coinbase는 100 이상)인 검증 UTXO의 합(진행 중 거래가 쓰는 outpoint 제외). 동결분은 따로 표시한다.

## 5. 이전 거래 검증 (필수)

입력으로 쓰는 모든 UTXO는 선택하기 전에 아래를 통과해야 한다. 통과하지 못한 UTXO는 선택·잔액·표시에서 뺀다.

```rust
pub fn verify_prev_output(
    raw: &[u8],                 // Core getrawtransaction hex를 디코드한 바이트 (대체: 인덱서 TxRaw, §4.3·§4.7-4)
    expected_txid: &Txid,       // 인덱서 Utxo가 준 txid
    vout: u32,
    expected_script: &[u8; 22], // 0x00 0x14 || p2wpkh_program(acct, chain, index)
) -> Result<VerifiedPrevOut, PrevTxError>;
pub struct VerifiedPrevOut { pub outpoint: OutPoint, pub value: Sats, pub is_coinbase: bool }
```

1. `raw.len() <= BTC_MAX_PREV_TX_BYTES`(400,000). 넘으면 `TooLarge`("검증 불가 UTXO").
2. §6.5 엄격 파서로 파싱한다. 실패하면 `Malformed`.
3. txid = SHA256d(non-witness 직렬화)를 **원본 바이트 조각**으로 계산한다: `raw[0..4] || raw[s..e] || raw[len-4..]`. `s`는 입력 개수 CompactSize의 시작(세그윗이면 6, 아니면 4), `e`는 마지막 출력의 끝이다. 재직렬화하지 않는다. 계산값(내부 바이트 순서)이 `expected_txid`와 다르면 `TxidMismatch`.
4. `vout < outputs.len()`이어야 한다. 아니면 `VoutOutOfRange`.
5. `outputs[vout].script_pubkey == expected_script`(바이트 단위). 아니면 `ScriptMismatch`.
6. `value`는 `outputs[vout].value`(1 이상, `<= MAX_MONEY`; 0이면 `ZeroValue`)다. `is_coinbase`는 입력이 1개이고 prevout이 `0^32:0xFFFFFFFF`인지로 판정한다. coinbase이면 확인 수 100 이상이어야 선택 후보가 된다.

- **검증 금액 기록.** `BtcMeta.verified`와 저널 입력 기록(§12.4)에 `outpoint → value`를 남긴다. 서명 직전에 계획의 각 입력 금액이 기록된 모든 값과 같아야 한다(기록이 하나도 없어도 불일치). 다르면 `AmountRecordMismatch`로 하드 중단한다(버그·변조 신호). 기록이 하나도 없으면 같은 하드 중단을 `InputNotRecorded`로 하고 문구를 따로 쓴다(승인하는 동안 새로고침이 그 입력을 목록에서 뺀 경우가 대부분이다: "승인하는 동안 입력 UTXO가 검증 목록에서 빠졌습니다…다시 검토하세요"). 검사 함수는 `sign::check_recorded_amounts(plan, recorded)`이고 yw-app이 `sign_plan` 직전에 부른다.
- **같은 outpoint 재서명 거부.** 진행 중 상태(§12.1) 저널 항목이 쓰는 outpoint를 포함한 새 계획은 거부한다. 예외는 그 항목의 RBF 교체(§9)뿐이다(교체 대상과 그 앞 원본들, 곧 대상의 `replaces` 사슬이 쓰는 outpoint. 대상을 교체하는 다른 진행 중 항목은 예외가 아니다).
- 이 검증 덕분에 BIP143(입력 금액을 해당 입력에만 커밋)에서도 금액 위조로 수수료를 부풀릴 수 없다.

## 6. 직접 구현 코드 (yw-core `btc`)

모듈: `crates/yw-core/src/btc/{network, amount, bech32, address, account, script, tx, sighash, taproot, sign, prevtx, select, fee, policy, display, verify, meta}.rs`(`btc::*`, [01](01-repo-build.md) §2.2). BTC 저널 레코드 본문 코덱(§12.4)은 `btc` 아래가 아니라 체인 공통 `journal` 모듈의 `journal::btc`에 둔다(EVM `journal::evm`과 같은 배치, [01] §2.2·[03](03-evm.md) §0). 키 파생은 `yw_core::bip32`(§3.1), hex는 yw-core `hex`를 쓴다. 네트워크 호출과 unsafe는 없다(D4). 해시는 `sha2`·`ripemd`, 서명은 `secp256k1 =0.31.1`(`alloc`,`recovery`, 추가 기능 없음)만 쓴다. bech32는 직접 구현하고(D6), base58check는 M1의 `codec::base58`([02](02-core-keys-vault.md) §0)을 쓴다.

### 6.1 base58check 주소 정책 (`btc::address`)

- 디코드·인코드와 체크섬(`SHA256d` 앞 4바이트) 검사는 `codec::base58`의 base58check를 쓴다. `btc::address`는 길이·버전 바이트·네트워크 정책만 둔다.
- 입력 1–64자. base58check 디코드 결과(체크섬 제외)는 정확히 21바이트(버전 1 + 해시 20)여야 한다. 길이가 다르면 `Base58Length`, 체크섬이 틀리면 `Base58Checksum`(codec 오류를 이 둘로 바꾼다. WIF 길이는 §6.3 4번이 먼저 잡는다).
- 버전 `payload[0]`: 네트워크 P2PKH 버전이면 P2PKH, P2SH 버전이면 P2SH. 다른 네트워크 버전(`0x00`/`0x05`/`0x6f`/`0xc4` 중 나머지)이면 `WrongNetwork`, 그 밖이면 `UnknownVersion`.
- 표시용 인코드도 `codec::base58`로 하고, 디코드 왕복 결과가 원래 문자열과 같아야 한다(테스트).

### 6.2 bech32 / bech32m (BIP173·BIP350, 약 150줄)

- 길이 8–90자, 문자 0x21–0x7E. 전부 소문자이거나 전부 대문자여야 하고 섞이면 `MixedCase`. 이후 소문자로 처리한다. 길이 위반과 데이터부 6자 미만은 주소 단계에서 `InvalidProgramLength`(형식 오류)로 바꾼다.
- 구분자는 마지막 `'1'`이다. HRP는 1자 이상이고, 데이터부는 6자 이상이며 문자는 `qpzry9x8gf2tvdw0s3jn54khce6mua7l`만 쓴다(아니면 `InvalidCharacter`).
- polymod 생성자 `[0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]`. 결과가 `1`이면 bech32, `0x2bc830a3`이면 bech32m, 그 밖이면 `Bech32Checksum`.
- 데이터부(체크섬 6자 제외)의 첫 값이 증인 버전(0–16)이다. 비어 있거나 16을 넘으면 `InvalidWitnessVersion`. 나머지는 5→8비트로 변환한다. 패딩은 4비트 이하이고 0이어야 한다(아니면 `InvalidPadding`). 프로그램은 2–40바이트다.
- v0은 bech32이고 프로그램이 20 또는 32바이트여야 한다. v1 이상은 bech32m이어야 한다. 어긋나면 `WrongChecksumVariant`/`InvalidProgramLength`.

### 6.3 주소 파싱 정책

```rust
pub enum ScriptKind { P2pkh([u8; 20]), P2sh([u8; 20]), P2wpkh([u8; 20]), P2wsh([u8; 32]), P2tr([u8; 32]) }
pub fn parse_address(input: &str, net: BtcNetwork) -> Result<ScriptKind, AddressError>;
pub fn encode_address(kind: &ScriptKind, net: BtcNetwork) -> String;   // bech32는 소문자
pub fn script_pubkey(kind: &ScriptKind) -> Vec<u8>;                    // §6.4
pub fn kind_from_script(spk: &[u8]) -> Option<ScriptKind>;             // 표시용 역변환, 5종만
```

판정 순서(앞에서 처음 맞는 규칙으로 끝낸다):

| # | 조건(앞뒤 ASCII 공백 `\t\r\n ` 제거 후) | 결과 |
|---|---|---|
| 1 | 빈 문자열 / 내부 공백·제어문자 | `Empty` / `InvalidCharacter` |
| 2 | 소문자로 바꿨을 때 `bitcoin:`로 시작 | `UriNotSupported` |
| 3 | `lightning:`, `lnbc`, `lntb`, `lntbs`, `lnbcrt`, `lnurl`로 시작 | `Lightning` |
| 4 | `xprv`/`tprv`/`yprv`/`zprv`/`vprv`/`uprv`로 시작, 또는 base58check 결과(체크섬 제외)가 33/34바이트이고 버전 `0x80`/`0xef`(WIF) | `LooksLikePrivateKey` |
| 5 | HRP(마지막 `'1'` 앞, 소문자)가 `sp`/`tsp` (길이·체크섬 검사 전) | `SilentPayment` |
| 5a | HRP가 `bc`/`tb`/`bcrt`이고 네트워크 HRP가 아님 (체크섬 검사 전) | `WrongNetwork` |
| 5b | HRP가 네트워크 HRP → §6.2 디코드(실패하면 그 오류) 후 아래 | bech32 경로 |
| 5c | v0/20바이트 | `P2wpkh` |
| 5d | v0/32바이트 | `P2wsh` |
| 5e | v1/2바이트 `4e73` | `PayToAnchor` |
| 5f | v1/32바이트: `XOnlyPublicKey::from_byte_array` 성공 / 실패 | `P2tr` / `InvalidTaprootKey`(보내면 소실) |
| 5g | v1 그 밖 길이 / v2–v16 | `InvalidProgramLength` / `UnsupportedWitnessVersion`(BIP350과 의도적으로 다름) |
| 6 | 그 밖에 base58 문자로만 구성 | §6.1 |
| 7 | 그 밖 | `NotBitcoinAddress` |

- HRP를 알 수 없고 base58 알파벳 밖 문자(`0OIl` 등)가 있으면 7번이다(예: `ltc1…`, `tc1…`).
- 2·3번 접두와 5번 HRP는 ASCII 대소문자를 무시하고, 4번 확장 개인키 접두는 대소문자를 구분한다. 1번 공백·제어문자는 유니코드 공백·제어문자 전부다.
- 표시는 항상 `encode_address(kind_from_script(spk))`로 만든 문자열을 쓴다. 붙여넣은 문자열은 표시하지 않는다.

### 6.4 스크립트 템플릿

| 종류 | scriptPubKey | 길이 | 출력 vB | dust(sats) |
|---|---|---|---|---|
| P2PKH | `76 a9 14 <h20> 88 ac` | 25 | 34 | 546 |
| P2SH | `a9 14 <h20> 87` | 23 | 32 | 540 |
| P2WPKH | `00 14 <h20>` | 22 | 31 | 294 |
| P2WSH | `00 20 <h32>` | 34 | 43 | 330 |
| P2TR | `51 20 <x32>` | 34 | 43 | 330 |

dust는 Core `GetDustThreshold`의 dust relay fee 3 sat/vB 기준이다: `(출력 크기 + 소비 입력 크기) × 3`. 소비 입력 크기는 비증인 148, 증인 `32+4+1+107/4+4 = 67`이다. BIP143 scriptCode(P2WPKH·P2SH-P2WPKH 공통)는 `19 76 a9 14 <h20> 88 ac`(길이 접두 0x19 포함)다. P2SH-P2WPKH 리딤 스크립트는 `00 14 <h20>`, scriptSig는 그 한 번의 push `16 00 14 <h20>`(23바이트)이고 계획(서명 전 거래)에 들어간다. P2PKH scriptSig는 두 직접 push `<len> DER‖01 <len> K`(각 1–75바이트)만 받는다(`split_p2pkh_script_sig`).

### 6.5 거래 직렬화·파서

```rust
pub struct OutPoint { pub txid: Txid, pub vout: u32 }       // Txid([u8;32]) 내부 순서, 표시할 때 뒤집은 hex
pub struct TxIn { pub prevout: OutPoint, pub script_sig: Vec<u8>, pub sequence: u32, pub witness: Vec<Vec<u8>> }
pub struct TxOut { pub value: Sats, pub script_pubkey: Vec<u8> }
pub struct Transaction { pub version: u32, pub inputs: Vec<TxIn>, pub outputs: Vec<TxOut>, pub lock_time: u32 }
pub fn parse_transaction(bytes: &[u8]) -> Result<Transaction, TxParseError>;
pub fn serialize(tx: &Transaction, with_witness: bool) -> Vec<u8>;
pub fn txid(tx: &Transaction) -> Txid;     // SHA256d(serialize(tx,false))
pub fn wtxid(tx: &Transaction) -> [u8; 32];// SHA256d(serialize(tx,true))
pub fn weight(tx: &Transaction) -> u64;    // 3*len(base) + len(total)
pub fn vsize(tx: &Transaction) -> u64;     // ceil(weight/4)
```

바이트 형식(정수는 모두 LE):

```
version u32 | [marker 0x00 | flag 0x01] | n_in CS | n_in × (prev_txid[32] | prev_vout u32 | CS len | script_sig | sequence u32)
| n_out CS | n_out × (value u64 | CS len | script_pubkey) | [n_in × (CS n_items | n_items × (CS len | item))] | lock_time u32
```

엄격 규칙(위반하면 `TxParseError`):
- CompactSize는 최소 인코딩만 허용한다(`0xFD`+u16 ≥ 0xFD, `0xFE`+u32 ≥ 0x10000, `0xFF`+u64 ≥ 2^32). 값이 `0x0200_0000`을 넘거나 남은 바이트보다 크면 거부한다.
- 할당 전에 `개수 × 원소 최소 크기 <= 남은 바이트`를 확인한다(입력 41, 출력 9, 증인 항목 1).
- version 다음 바이트가 0x00이면 flag는 0x01이어야 한다(아니면 거부). 세그윗 형식이면 적어도 한 입력의 증인이 비어 있지 않아야 한다. 비세그윗에서 `n_in == 0`은 거부한다. `n_out == 0`도 거부한다.
- 출력 값은 각각 `<= MAX_MONEY`이고 합도 `<= MAX_MONEY`여야 한다. 끝에 남는 바이트가 있으면 거부한다.
- 파서는 이전 거래(임의 version·스크립트)와 우리 서명 거래 검증(§11.2)에 함께 쓴다. 패닉 금지. 무작위·변형 입력 테스트(§14.2)를 통과해야 한다.

### 6.6 BIP143 sighash (P2WPKH, SIGHASH_ALL)

```rust
pub fn bip143_sighash_p2wpkh(tx: &Transaction, index: usize, program: &[u8; 20], amount: Sats) -> Option<[u8; 32]>; // index가 입력 범위 밖이면 None
```

```
preimage = version u32 | hashPrevouts[32] | hashSequence[32] | outpoint[36] | scriptCode(0x19 76a914<h20>88ac)
         | amount u64 | sequence u32 | hashOutputs[32] | lock_time u32 | 0x01000000
hashPrevouts = SHA256d(모든 입력의 txid[32]||vout u32)   hashSequence = SHA256d(모든 sequence u32)
hashOutputs  = SHA256d(모든 출력의 value u64||CS len||spk)   sighash = SHA256d(preimage)
```

P2SH-P2WPKH 입력도 같은 함수다(BIP143 "P2SH-P2WPKH": scriptCode는 키 해시의 P2WPKH 것).

**레거시 sighash (P2PKH, `btc::sighash::legacy_sighash`).** `SIGHASH_ALL` 의미의 hash type만(하위 5비트가 2·3이 아니고 `ANYONECANPAY` 0x80이 없음; 그 밖은 `None`): 증인 없이 직렬화하되 입력 `index`의 scriptSig = scriptCode(우리 P2PKH scriptPubKey, `OP_CODESEPARATOR` 없음), 다른 입력의 scriptSig = 빈 값, 모든 sequence·출력 유지, 끝에 hash type `u32` LE를 붙여 `SHA256d`. 금액에 서명하지 않는다(§3.5).

**BIP341 sighash (P2TR 키 경로, `btc::taproot::sighash_default`).** `SIGHASH_DEFAULT`(0x00), annex 없음, 스크립트 경로 없음:

```
sig_msg = 0x00(epoch) ‖ 0x00(hash_type) ‖ nVersion u32 ‖ nLockTime u32
        ‖ SHA256(모든 outpoint) ‖ SHA256(모든 입력 금액 u64) ‖ SHA256(모든 입력 CS len‖scriptPubKey)
        ‖ SHA256(모든 sequence) ‖ SHA256(모든 출력) ‖ spend_type 0x00 ‖ input_index u32
sighash = TaggedHash("TapSighash", sig_msg),  TaggedHash(t, m) = SHA256(SHA256(t) ‖ SHA256(t) ‖ m)
```

입력 금액·스크립트는 계획의 모든 입력의 검증 금액과 계정이 파생한 우리 scriptPubKey다(`Prevout`). 출력 키 tweak: `t = TaggedHash("TapTweak", P_x)`(BIP86: 머클 루트 없음), `Q = P + t·G`; 서명 키는 `Keypair::add_xonly_tweak`(홀수 Y면 부정 후 더함, BIP341 `taproot_tweak_seckey`).

### 6.7 ECDSA 서명

- 서명은 `with_secp_key`가 넘겨 주는 컨텍스트(`seeded_randomize`, [02] §1.3)와 키로 그 클로저 안에서만 한다([02] §10.3).
- `sig = ctx.sign_ecdsa_low_r(Message::from_digest(sighash), sk)`. libsecp256k1 RFC6979 결정적 nonce이고 r의 첫 비트가 0이 될 때까지 extra entropy로 다시 계산한다. libsecp256k1 결과는 항상 low-S다.
- 증인 = `[sig.serialize_der() || 0x01, pubkey33]`(P2WPKH·P2SH-P2WPKH). DER은 70바이트 이하이므로 서명 항목은 71바이트 이하다. P2PKH는 같은 서명 항목과 계정 공개키(33 또는 65바이트)를 scriptSig에 push한다.
- 서명 직후 `verify_ecdsa(msg, &sig, &pk)`를 반드시 수행한다(§11.2에서 다시 한다).
- **Schnorr (P2TR).** `sign_schnorr_with_aux_rand(sighash, &tweaked_keypair, &aux)`, `aux`는 서명마다 OS CSPRNG 32바이트(`fill_random`, BIP340 보조 난수). 서명 직후 출력 키로 `verify_schnorr`를 하고, tweak한 키의 x좌표가 계정이 파생한 P2TR 프로그램과 같지 않으면 `KeyMismatch`. 증인은 64바이트 서명 하나(hash type 바이트 없음).

## 7. 거래 구성

### 7.1 고정 필드

version 2. 모든 입력의 `sequence = 0xFFFF_FFFD`(교체 가능, nLockTime 유효), `script_sig`는 빈 바이트(P2SH-P2WPKH 계정만 리딤 스크립트 push, §6.4). `lock_time`은 계획 시점의 `tip_height`(anti-fee-sniping, 무작위화 없음). `tip_height >= 500,000,000`이면 계획하지 않는다(`TipImplausible`, §2). 출력은 수신자 1개와 잔돈 0–1개(계정 형식의 출력: HD m/{p}'/{coin}'/{a}'/1/`change_next`, 가져온 키는 같은 주소). 입력은 최대 `BTC_MAX_INPUTS` = 100개이고 모두 한 계정의 것이다. 서명 전 txid(`SendPlan::txid`)는 P2PKH 계정에서만 서명 후에 정해진다(`txid_is_final`).

### 7.2 크기 계산 (서명 전 추정)

```
weight(k, outs) = 42 + 271·k + Σ 4·(9 + len(spk_j))        // k <= 252, 출력 <= 2
vsize = ceil(weight / 4);  fee(rate, vsize) = ceil(rate.sat_per_kvb × vsize / 1000)
```

`42 = (4+4+1+1)·4 + 2`(marker·flag). 입력 271 WU = 41·4 + 증인 107(개수 1 + 길이 1 + 서명 71 + 길이 1 + 공개키 33)이다. 서명 후 실제 크기는 추정 이하여야 한다(§11.2). 예: 1입력 → P2WPKH+잔돈 141 vB, 1입력 1출력 110 vB, 2입력 2출력 208 vB, 3입력 → P2TR 1출력 257 vB.

다른 형식 계정은 `estimate_weight_with(w, k, outs) = 42 + w·k + Σ 4·(9 + len)`의 `w`를 §3.5 표의 입력 weight로 바꾸고, 잔돈 출력 길이는 계정 형식의 scriptPubKey(25 P2PKH, 23 P2SH, 22 P2WPKH, 34 P2TR)다: P2SH-P2WPKH 363 = (41+23)·4 + 107, P2TR 230 = 41·4 + 66(개수 1 + 길이 1 + 서명 64), P2PKH 588 = (41 + 1+71+1+33)·4(비압축 키 716). P2PKH만 쓰는 거래는 marker·flag가 없어 2 WU를 넘게 잡는다(상한이므로 허용). **잔돈 dust**는 P2WPKH 294이고 다른 형식은 §6.4 그 형식의 dust(P2TR 330, P2SH 540, P2PKH 546)다(§7.4 `feasible`의 294 자리).

### 7.3 금액 규칙

- 내부 금액은 `Sats(u64)`이고 모든 연산은 checked이며 `<= MAX_MONEY`(2,100,000,000,000,000)다.
- 사용자 입력은 BTC `^(0|[1-9][0-9]{0,7})(\.[0-9]{1,8})?$` 또는 sats `^[1-9][0-9]{0,15}$`(토글)만 받는다. 천 단위 구분자·지수 표기·음수는 거부한다.
- 수신 금액은 수신 종류의 dust 이상이어야 한다(§6.4). 아니면 `DustAmount`.

### 7.4 코인 선택

후보 `C`: 검증된(§5) UTXO 가운데 확인 수 1 이상(coinbase는 100 이상)이고, 동결되지 않았고(§7.6), 진행 중 거래가 쓰지 않는 것. 남의 미확정 UTXO는 어떤 경우에도 쓰지 않는다. 자기 미확정 잔돈도 후보가 될 수 있지만, D20을 BTC 계정에 적용하므로(§12.1) 새 송금 시점에는 존재하지 않는다. RBF는 원래 입력을 그대로 쓴다.

```
feasible(S, A): k=|S|, V=ΣS
   fee_c = fee(r, vsize(k, [rcpt, p2wpkh])),  fee_n = fee(r, vsize(k, [rcpt]))
   V >= A + fee_c + 294          → WithChange { change = V - A - fee_c }
   else V >= A + fee_n           → NoChange { fee = V - A }   // 잔돈 없이 남는 금액을 수수료로
   else                          → infeasible
1. 단일 입력: C를 (value 오름차순, height 오름차순, txid(표시 순서 hex), vout)으로 정렬해 처음으로 feasible한 u 하나
2. 아니면 C를 (value 내림차순, height 오름차순, txid, vout)으로 정렬하고 k=2..=min(|C|,100)에서 처음 feasible한 앞부분 k개
3. 아니면 InsufficientFunds { available: Σ C(최대 100개), needed: A + fee_n(k) }
```

수수료가 입력 개수에만 의존하므로 2번은 입력 수가 최소인 조합을 찾는다.

**포기한 거래와 충돌(§12.1).** 살아 있는 `Abandoned` 항목이 있으면 새 보내기는 그 항목마다 입력 하나 이상을 반드시 쓴다(`SendRequest.conflicts` = 항목별 입력 집합). 집합마다(이미 고른 입력이 포함된 집합은 건너뜀) `C`에서 그 집합에 속한 후보 중 가장 많은 집합에 걸치는 것, 그다음 값이 큰 것, 그다음 1번 정렬 순으로 하나를 고정 입력으로 고른다. 그 뒤 1–2번 대신 고정 입력에 나머지 후보를 값 내림차순으로 하나씩 더해 처음 feasible한 앞부분을 쓴다(입력 최대 100). 보내기 최대는 고정 입력 + 나머지 최대 100개다. 어느 집합에도 후보가 없으면(동결·미성숙·사라짐) `AbandonedNotConflicted`로 계획하지 않는다. `NoChange`일 때 수수료에 더해지는 금액 `fee - fee_n`을 잔돈 필드(§10 `0x0604`)에 "잔돈 없음: X sats 수수료에 추가"로 표시한다.

### 7.5 배치와 잔돈

- `layout_seed: [u8;32]`는 getrandom으로 만든다(테스트에서는 고정값 주입).
- 입력 순서: Fisher–Yates. `i = n-1..=1`에 대해 `j = u64_be(SHA256(seed || "yw-btc-in" || u32_be(i))[0..8]) mod (i+1)`로 교환한다.
- 잔돈 위치: `SHA256(seed || "yw-btc-chg")[0] & 1`이 0이면 잔돈이 먼저, 1이면 나중이다.
- 잔돈 스크립트는 코어가 캐시 공개키로 `change_next`에서 직접 파생한다. 계산된 잔돈 스크립트가 수신자 스크립트와 같으면 `change_next + 1`을 쓴다(HD 모드). 고정 주소 계정(고정 주소 모드 HD·가져온 키·EVM 키, §3.5)은 잔돈 index 0으로 `(Receive, 0)` 스크립트를 쓴다(수신자가 그 주소여도).

### 7.6 보내기 최대와 동결

- **보내기 최대(send-max):** 입력은 `C`를 2번 정렬로 최대 100개 쓰고, 출력은 수신자 1개다. `amount = V - fee_n(k)`이고 수신 종류 dust 미만이면 `DustAmount`. `C`가 100개를 넘으면 "UTXO n개는 포함되지 않음"(§10 B06)을 표시한다.
- **동결:** UTXO 목록(S10 Bitcoin 탭, 한 번에 300행까지 보이고 나머지는 개수만 적는다)에서 outpoint별로 동결·해제한다(`BtcMeta.frozen`, 사유 1=사용자, 2=자동). 처음 본 남의 UTXO가 `BTC_AUTO_FREEZE_BELOW`(1,000 sats) 미만이면 자동 동결하고 "작은 입금 자동 동결(먼지 공격 방지)"을 표시한다. 사용자가 해제할 수 있고, 해제 기록은 `BtcMeta.unfrozen`에 남겨 다시 동결하지 않는다.

## 8. 수수료

### 8.1 단위 타입

```rust
pub struct FeeRate { sat_per_kvb: u64 }            // 1 sat/vB = 1000
pub fn parse_btc_decimal(text: &str) -> Result<Sats, AmountError>;  // JSON 숫자 원문 → sats
// 허용 형식: ^(0|[1-9][0-9]{0,7})(\.[0-9]{1,8})?$  (부호·지수·9자리 이상 소수 거부)
// BTC/kvB 값 X → sat/kvB = parse_btc_decimal(X) (소수점 이동만)
pub fn fee_rate_from_btc_per_kvb(text: &str) -> Result<FeeRate, AmountError>;
pub fn parse_user_sat_per_vb(text: &str) -> Result<FeeRate, AmountError>; // ^[0-9]{1,6}(\.[0-9]{1,3})?$
```

표시는 `X.XXX sat/vB`(뒤쪽 0 제거)로 한다. BTC/kB·float 단위는 쓰지 않는다.

### 8.2 수수료율 정하기

- 선택지: 빠름 / 보통(기본) / 느림 = `estimatesmartfee [2 / 6 / 24, "economical"]`의 `feerate`, 또는 직접 입력(`parse_user_sat_per_vb`). 추정이 없으면(`feerate` 없음·오류, testnet4에서 흔함) 직접 입력만 허용하고 기본값은 하한이다.
- 하한 `floor = max(1,000 sat/kvB, mempoolminfee, minrelaytxfee)`. 추정이 하한보다 낮으면 하한으로 올리고 "하한 적용"을 표시한다(출처 `Floor`). 직접 입력이 하한 미만이면 거부한다.
- 출처(`FeeSource::Estimate{target}` / `Manual` / `Floor`)를 수수료 필드(§10 `0x0606`)에 표시한다.

### 8.3 상한·비율·입력 확인

최종 계획에서 계산한다. `rate_kvb = ceil(fee × 1000 / vsize)`(sat/kvB). 비교는 모두 sat/kvB 정수로 한다. 등급·경고 ID는 §10 표다.

| 조건 | 처리 |
|---|---|
| `rate_kvb > 500,000`(500 sat/vB, `BTC_FEE_RATE_CAP`) | 상한 초과. 해제 입력이 없으면 B02 차단, 있으면 B03 고위험 |
| `fee > 500,000 sats`(0.005 BTC, `BTC_FEE_ABS_CAP`) | 위와 같다 |
| `fee × 50 > amount`(2% 초과) | B04 고위험 |
| `rate_kvb > 10,000,000`(10,000 sat/vB, `BTC_FEE_RATE_UNOVERRIDABLE`) | B01 차단, 어떤 입력으로도 해제 불가 |

- **해제 입력.** 승인 창에는 입력 칸이 없다([04] §2.7). 상한을 넘으면 BTC 보내기 폼(수수료 올리기 폼 포함)이 오류와 함께 "수수료(sats)를 정확히 입력해 상한 해제" 칸을 보이고, 입력값이 계획 수수료와 정확히 같을 때만 계획을 만들어 승인 요청을 낸다. 이 계획은 `fee_override_typed = true`이고 저널 `flags.fee_override_typed`에 기록한다. 받는 주소·금액·수수료 선택이 바뀌어 해제 요청이 없어지면 칸을 숨기고 입력값도 지운다.
- `maxfeerate`(testmempoolaccept·sendrawtransaction) = `ceil(rate_kvb / 1000) + 1` sat/vB(`rate_kvb`는 서명된 거래의 실제 vsize로 계산, `VerifiedSignedTx::maxfeerate`)를 BTC/kvB 10진 문자열(소수 8자리)로 JSON 숫자 리터럴에 넣는다. 예: 10.2 sat/vB → `0.00012000`. 리터럴은 `Number::from_literal`로 넣고 `to_vec`가 그대로 출력한다([01] §2.3).

## 9. RBF 수수료 올리기

대상: 상태가 `Submitted`·`BroadcastUnknown`·`InMempool`(§12.1)인 자기 거래 `T`. 같은 거래를 여러 번 올릴 수 있고, 항상 최신 교체본을 대상으로 한다.

| 규칙 | 값 |
|---|---|
| 입력 | `T`의 입력 전부 + 필요하면 §7.4 후보에서 추가(값 내림차순, 최소 개수). 전체를 새 `layout_seed`로 섞는다. |
| 수신자 출력 | 스크립트·금액 동일. 예외: `T`가 send-max면 금액을 Δ만큼 줄이고 "수신 금액 감소"(B06)를 표시한다(dust 미만이면 불가). |
| 잔돈 | 같은 잔돈 인덱스. 금액을 다시 계산하고 294 미만이면 없애고 수수료에 더한다. 입력을 추가했는데 원래 잔돈이 없었다면 `change_next`를 새로 쓴다. |
| 수수료 | `new_fee >= old_fee + ceil(incrementalrelayfee_kvb × new_vsize / 1000)`(`getmempoolinfo.incrementalrelayfee`를 sat/kvB로 변환, 없으면 1,000)이고 `new_fee × old_vsize > old_fee × new_vsize`(수수료율이 엄격히 더 높음)이며, Core처럼 sat/kvB로 버림한 비율도 엄격히 높다: `floor(new_fee × 1000 / new_vsize) > floor(old_fee × 1000 / old_vsize)`. 최소 수수료는 `ceil((floor(old_fee × 1000 / old_vsize) + 1) × new_vsize / 1000)`도 넘게 올림으로 잡는다(서명 후 vsize는 계획 이하라 비율만 높아진다) |
| lock_time | 현재 `tip_height` |
| 상한 | §8.3를 그대로 적용(해제 입력은 수수료 올리기 폼에서) |
| 사전 검사 | `testmempoolaccept`. 거부되면 §13 메시지(예: "교체 수수료 부족")를 표시하고 수수료를 더 올리게 한다. Core 31 클러스터 멤풀의 feerate-diagram 판정은 노드에 맡긴다. |
| 승인 | 매번 새 승인(`BtcFeeBump`, §10). 필드 `0x0609`에 "교체 대상 `<txid>`; 수수료 X → Y(+Δ); 수신자 변경 없음 / 수신 금액 감소(B06)"를 표시한다. |

교체본이 `Submitted`가 되면 `T`를 `Replaced{by}`로 바꾸되 둘 다 계속 추적한다. 사슬 앞쪽 원본 중 아직 `Submitted`·`BroadcastUnknown`·`InMempool`인 것(중간 교체본이 노드에 닿지 않은 경우)도 함께 `Replaced{by: 사슬의 다음 거래}`로 바꾼다. `T`가 먼저 확정되면 `T`를 `Confirmed`, 교체본을 `Conflicted`로 바꾼다.

## 10. 승인 표시와 digest

D27·D31에 따라 [03](03-evm.md) §11의 공통 모델(`ApprovalDraft`·`ApprovalRequest`, `ApprovalDisplay`, `ApprovalStore`, `Approved`)과 [04](04-app-ui.md) §3 승인 창을 쓴다. 시뮬레이션은 없고(`simulation = None`) 모든 값은 코어가 계획과 검증 데이터로 만든다. 계획을 만들 수 없는 오류(`DustAmount`, `InsufficientFunds`, §6.3 주소 거부 등)는 보내기 폼에서 막고 요청을 만들지 않는다.

| `ApprovalDraft` 항목 | BTC 값 |
|---|---|
| `origin` / `kind` / `signer` | `App`(`"yw-app"`) / `BtcSend = 0x30`, `BtcFeeBump = 0x31` / `Signer::FromPayload`(입력별 경로) |
| `chain` | `ChainRef::Bitcoin { network: u8 /* 1·2 */, genesis: [u8; 32] /* §2 표 hex를 디코드한 바이트 */ }` |
| `account` / `payload` | `AccountRef::Bitcoin([u8; 33])` = `BtcAccountKey::identity()`(HD: 계정 노드 공개키, 가져온 키·EVM 키: 압축 공개키) / `SigningPayload::Btc(btc_payload)`(아래; 기본 계정이 아니면 끝에 계정 블록 19바이트 `0x01 ‖ source u8 (1 HD, 2 가져온 키, 3 EVM 키) ‖ ScriptType u8 ‖ (HD account u32 ‖ 0^12 | 레코드 id 16 | EVM index u32 ‖ 0^12)`\| 레코드 id 16)` — 같은 키를 여러 형식으로 가져와도 승인이 섞이지 않는다; 서명 전 거래에는 P2SH-P2WPKH scriptSig가 들어 있다) |
| 제목 | `[Bitcoin 메인넷] 보내기: 0.00120000 BTC` / `[Bitcoin testnet4] 수수료 올리기` |

필드(`FieldKey`, 표시 순서). `0x06xx`는 [03] §11.2에 등록하는 BTC 범위다. volatile 필드는 없고, [04] §3.2 자산 변화 영역은 `0x0603`–`0x0607`이다.

| 키 | 이름 | critical | 값 |
|---|---|---|---|
| `0x0001`, `0x0002`, `0x0003` | 요청 출처, 네트워크, 서명 계정 | 예 | `Your Wallet 앱`(EVM·Solana와 같은 `APP_ORIGIN_TEXT`), §2 배너 문구, `Bitcoin {계정 이름} ({노드})`(예: `Bitcoin 네이티브 세그윗 계정 0 (m/84'/0'/0')`, `Bitcoin 탭루트 계정 0 (m/86'/0'/0')`, 가져온 키 `Bitcoin 가져온 키 · 레거시 ({주소})`) |
| `0x0601` | 받는 주소 | 예 | 출력 스크립트를 다시 인코딩한 소문자 주소(공백 없음). 4자 묶음 간격과 앞 6자·뒤 6자 굵게는 [04] §3.3 그리기 |
| `0x0602` | 주소 종류 | 예 | `P2PKH(레거시)` / `P2SH(스크립트)` / `P2WPKH` / `P2WSH(스크립트)` / `P2TR` |
| `0x0603` | 금액 | 예 | `0.00120000 BTC (120,000 sats)` |
| `0x0604` | 잔돈 | 예 | `0.00050000 BTC — 이 지갑으로 돌아옴 m/{p}'/{coin}'/{a}'/1/n`(가져온 키는 그 주소) 또는 `잔돈 없음: X sats 수수료에 추가` |
| `0x0605` | 입력 | 예 | 개수, 합계, 고정 문구 "모든 입력 금액은 이전 거래 해시로 검증됨", 최소 확인 수(서버 기준) |
| `0x0606` | 수수료 | 예 | sats·BTC, sat/vB(계획 vsize 기준, 서명 후 실제 값은 같거나 높음), 보낸 금액 대비 %(소수 2자리), 출처(§8.2) |
| `0x0607` | 총 차감 | 예 | 수신 금액 + 수수료 |
| `0x0608` | 승인 후 잔액 | | 검증 잔액 − 총 차감(= 검증 잔액 − 새로 쓰는 입력 합 + 잔돈. 수수료 올리기는 원래 입력이 이미 잔액에서 빠져 있으므로 추가 입력만 뺀다) |
| `0x0609` | 교체 대상 | 예 | `BtcFeeBump`만(§9) |
| `0x0640` | 고급 | | version 2, nLockTime(=블록 높이 N), RBF 가능, `입력 형식 P2WPKH`(P2PKH·P2SH-P2WPKH·P2TR), vsize·weight, txid(비증인 직렬화로 서명 전에 확정; P2PKH 계정은 `서명 후 결정 (레거시 입력)`) |

경고(`Warning`, [03] §10.1; `RuleId` 상위 바이트 `'B'` = 0x42):

| ID | 조건 | 등급 |
|---|---|---|
| B01 | `rate_kvb > BTC_FEE_RATE_UNOVERRIDABLE`(§8.3) | 차단 |
| B02 | `BTC_FEE_RATE_CAP`·`BTC_FEE_ABS_CAP` 초과이고 해제 입력 없음(§8.3) | 차단 |
| B03 | 위 상한을 보내기 폼 해제 입력으로 넘음(`fee_override_typed`) | 고위험 |
| B04 | `fee × 50 > amount`(2% 초과) | 고위험 |
| B05 | 처음 보내는 주소(`sent_scripts`에 없음) | 주의 |
| B06 | 수신 금액 감소(send-max RBF, §9) / UTXO n개 미포함(send-max, §7.6) | 주의 |
| B07 | 이 지갑의 주소(`m/84'/{coin}'/0'/c/i`) | 정보 |
| B08 | 레거시 형식(P2PKH) / 스크립트 주소(P2SH·P2WSH): 수신자가 스크립트를 관리 | 정보 |

고위험 경고가 있으면(`ack_required = (risk == High)`) D16에 따라 공통 체크박스 1개 "위 경고를 모두 확인했습니다"와 승인 버튼 2초 길게 누르기를 요구한다(경고마다 체크하지 않는다, [03] §10.1, [04] §3.4). 차단이 있으면 승인할 수 없다. 유사 주소 주석(W-ADDR-3)은 yw-app이 따로 붙인다([04] §3.3). BTC 규칙: 고정 접두부(bech32는 HRP·`1`·증인 버전 문자, base58은 버전 문자) 뒤 앞 4자와 끝 4자가 주소록 BTC 항목·이전 수신자(meta `activity["bitcoin:<net>"]`의 `counterparty`)·이 지갑 감시 주소(§3.3) 중 하나와 같고(ASCII 대소문자 무시) 주소는 다르면, 보내기 폼에 W-ADDR-3 "'{이름}'과 앞 4자·끝 4자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다."와 `주소 전체를 직접 확인했습니다` 체크를 보이고 체크 전에는 `검토`를 끈다. 받는 주소가 바뀌면 체크를 지운다.

```
display_digest = [03] §11.3
digest         = [03] §11.4, chain_tag = 3, 체인 줄: T.push_u8(network_id); T.push_bytes(genesis)
                 account_bytes = account_pubkey(33), sim = None, signing_payload_bytes = btc_payload
btc_payload    = network_id u8 ‖ u32 len ‖ unsigned_tx(= serialize(tx,false))
               ‖ n_in u16 ‖ n_in × (value u64 ‖ chain u8 ‖ index u32)     // unsigned_tx의 입력 순서
               ‖ has_change u8 ‖ [change_vout u32 ‖ change_index u32]
               ‖ fee u64 ‖ planned_vsize u32 ‖ has_replaces u8 ‖ [replaces_txid 32]
               ‖ fee_override_typed u8                                   // 정수 BE, [ ]는 앞 바이트가 1일 때만
```

- 발급·소비: 코어가 `ApprovalDraft`를 만들고, A01이 처음 표시할 때 `ApprovalStore::issue` → 승인 → `consume(id, shown_digest)` → `Approved`(1회, [03] §11.5). 만료는 표시 시각 + 120 s다(D23). 재시뮬레이션이 없으므로 `replace`를 쓰지 않는다. `issue`는 BTC 초안의 origin `App`, `Signer::FromPayload`, `ChainRef::Bitcoin`(네트워크 고정 제네시스), `AccountRef::Bitcoin`, `btc_payload` 형식(첫 바이트 = 체인 network, `has_replaces` = `BtcFeeBump`)을 검사한다(위반 `PayloadMismatch`).
- `sign_plan`(§11.1)은 `Approved`를 값으로 받아 `kind`·payload가 `btc_payload(plan)`과 바이트 단위로 같을 때만 서명한다. 계획을 바꿔야 하면(팁·수수료·UTXO 변화) 새 요청으로 다시 승인받는다.

## 11. 서명·서명 후 검증·전송

### 11.1 순서

```
plan → policy(§8.3, §10 경고) → ApprovalDraft → A01 표시·issue(§10) → 승인 → consume → Approved
→ (in-flight 재확인, 금액 기록 확인 §5) → sign_plan(§6.7) → verify_signed(§11.2) → 저널 Signed 커밋
→ check_chain → testmempoolaccept(§11.3) → 저널 Broadcasting 커밋(change_next 갱신)
→ sendrawtransaction → Submitted | BroadcastUnknown | Rejected
```

```rust
pub fn sign_plan(vault: &Vault, approved: Approved, plan: &SendPlan, account: &BtcAccountKey)
    -> Result<SignedTx, SignError>;   // SignedTx { raw, approval_id(= 저널 entry_id), approval_digest }
// (crate 내부 sign_plan_with<K: BtcKeys>가 같은 일을 한다: 단위 테스트의 시드 키 제공자용.)
// plan.account() == account이고 approved의 kind·chain·account(identity)·payload == btc_payload(plan)이
// 아니면 ApprovalMismatch. 입력 i마다 vault.with_btc_key(net, account.key_source(chain, index), i,
// |ctx, sk| 공개키 확인(§3.5) → 형식별 sighash(§6.6, 검증 금액) → ECDSA low-R + verify 또는
// Schnorr + verify(§6.7))로 서명하고 scriptSig·증인을 채운다. Vault는 crate 내부 BtcKeys를 구현한다
// (파생 키: with_secp_key(KeyRef::Btc{BtcCoin(purpose, account), chain, index}), 가져온 키:
// BtcImportedKeys::btc_imported_secret — 태그 4 레코드, 네트워크·형식·압축이 계정과 같아야 함).
pub fn verify_signed(raw: &[u8], plan: &SendPlan, account: &BtcAccountKey)
    -> Result<VerifiedSignedTx, PostSignError>;
```

### 11.2 서명 후 검증 (모두 필수, 하나라도 실패하면 폐기)

1. `parse_transaction(raw)`가 성공하고 `serialize(parsed, true) == raw`이다.
2. 증인을 빼고(P2PKH 계정은 서명 scriptSig도 비우고) 직렬화한 값이 승인된 `unsigned_tx`와 바이트 단위로 같다. 따라서 입력 순서, P2SH-P2WPKH scriptSig, sequence, lock_time, version, 출력이 같다(P2PKH 외에는 txid도 같다). `verify_signed`의 계정은 계획의 계정이어야 한다.
3. 형식별 모양: P2WPKH·P2SH-P2WPKH는 증인 항목이 정확히 2개(항목 0 `DER || 0x01`: DER 70바이트 이하, r < 2^255(low-R), `Signature::from_der`(엄격 DER)·`serialize_der()` 왕복 동일, low-S(`normalize_s` 전후 동일); 항목 1은 0x02/0x03으로 시작하는 33바이트). P2PKH는 증인이 없고 scriptSig가 정확히 두 직접 push(서명 항목 같은 규칙, 키 33 또는 65바이트). P2TR은 64바이트 항목 정확히 1개(65바이트 = 기본이 아닌 hash type은 거부).
4. 키가 계정이 그 입력 `(chain, index)`에 파생한(가져온 키는 그 키) 공개키와 바이트 단위로 같다(P2TR은 5의 출력 키 검증으로 대신한다).
5. 형식별 sighash를 검증 금액으로 다시 계산하고 서명을 검증한다: BIP143 + `verify_ecdsa`, 레거시 + `verify_ecdsa`, BIP341(모든 입력의 검증 금액·우리 scriptPubKey) + 계정이 파생한 출력 키로 `verify_schnorr`.
6. 잔돈 출력 스크립트를 계획의 계정(모드 포함)에서 다시 파생해 비교한다(HD 모드: `(Change, index)`; 고정 주소 모드·가져온 키·EVM 키: `(Receive, 0)` — 그 밖의 계정 주소(`/1/0`, `/0/1` …)를 내는 잔돈은 거부). 잔돈 출력은 최대 1개이고 그 밖의 추가 출력은 없다.
7. `fee = Σ검증 입력 − Σ출력`이 승인 수수료와 같고, §8.3 상한을 넘지 않는다(입력 해제가 있으면 그 값; 승인 표시와 같이 계획 vsize로 계산). 모든 출력이 종류별 dust 이상이고 `<= MAX_MONEY`다.
8. `weight <= 400,000`이고 `vsize(실제) <= planned_vsize`다.

### 11.3 전송

- **공개 표시.** `Signed` 레코드의 바이트를 처음 `testmempoolaccept`로 보내기 전에 저널 flags bit7 `disclosed`(§12.4)를 먼저 커밋한다(key worker `Disclose` 단계, 커밋이 실패하면 보내지 않는다). RPC는 받은 바이트를 그대로 퍼뜨릴 수 있으므로, 그 뒤의 `Rejected`·[취소]도 §12.1 "공개된 거래" 규칙을 따른다. 사전 검사 결과와 `sendrawtransaction` 결과를 적용할 때도 같은 비트를 세운다(이 비트 이전 레코드 보수 처리).
- `testmempoolaccept [[hex], maxfeerate]`: 결과가 원소 1개 배열이고 `allowed == true`, `txid`·`wtxid`가 로컬 값과 같고, `vsize`가 로컬 vsize와 같고, `fees.base`(`parse_btc_decimal`)가 로컬 수수료와 같아야 한다. 하나라도 다르면 `Rejected`로 두고 "노드 검사 결과가 로컬 계산과 다릅니다"를 표시한다. `allowed == false`면 `reject-reason`을 §13 표로 바꿔 표시하고 `Rejected`로 둔다. 예외: `txn-already-in-mempool`·`txn-already-known`이고 `txid`·`wtxid`가 로컬 값과 같으면(노드가 이미 가진 거래) `Rejected`로 두지 않는다. `change_next`를 갱신하고 `Broadcasting`을 거쳐 `BroadcastUnknown`으로 두며(§12.1 표의 두 전이, `sendrawtransaction`은 보내지 않는다. 사전 검사는 전송 결과가 아니고 `vsize`·`fees.base`도 없으므로 `Submitted`로 보지 않는다) "이미 전송된 거래입니다"를 표시한다. 이후 §12.2 추적이 `InMempool`·`Confirmed`로 바꾼다. 통신 오류면 `Signed`로 두고 [다시 시도]를 표시한다.
- `sendrawtransaction [hex, maxfeerate, 0]`: 응답 txid가 로컬 txid와 같으면 `Submitted`, 다르면 `BroadcastUnknown` + "응답 txid 불일치". 오류 `-27`(이미 체인에 있음)이면 `Submitted`로 두고 확인을 추적한다. `-26`·`-25`면 `Rejected`(잔돈 인덱스는 §3.2대로 되돌림), 시간 초과·전송 오류·그 밖 코드면 `BroadcastUnknown`. 바로 앞 §2 1·2단계 검사가 실패하면 아무것도 보내지 않았으므로 `BroadcastUnknown`으로 바꾸지 않는다: 저널은 `Broadcasting`에 두고 "전송 직전 연결 검사에 실패해 보내지 않았습니다"와 [같은 바이트 다시 전송]을 보인다(그 사이 앱을 다시 시작하면 §12.1 시작 정규화로 `BroadcastUnknown`이 된다).
- 마지막 Core `sendrawtransaction`이 통신 실패였는지(아래 수동 전송 조건)는 저널 flags bit6(§12.4)에 저장해 재시작 뒤에도 쓴다. 노드가 답하면(txid·RPC 오류) 지우고, 수동 전송이 `Submitted`로 판정되면 지운다.
- **Esplora 수동 전송(선택, 자동 경로 아님).** 조건: `indexer == "esplora"`, 저널 상태 `BroadcastUnknown`, 마지막 Core `sendrawtransaction`이 통신 실패(시간 초과·전송 오류·HTTP 5xx·429 중단; `-25`·`-26` 등 RPC 거부가 아님), 이번 세션에 §2 3단계를 통과했고 그 뒤 `esploraBaseUrl`이 바뀌지 않음. 이때만 [Esplora로 전송]을 보이고, 누르면 확인 오버레이 T-BTC-ESPLORA-BROADCAST([04] §2.16)를 거친 뒤 `http::Client::post(&EndpointUrl::Https(<esploraBaseUrl> ‖ "/tx"), &[("Content-Type", "text/plain")], <저널 원본 바이트의 소문자 hex>, 4 KiB)`를 1회 보낸다(429는 §4.4). 200 `text/plain` 본문이 `^[0-9a-f]{64}$`이고 로컬 txid와 같으면 `Submitted`, 다른 txid·형식 이상이면 `BroadcastUnknown` 유지 + "응답 txid 불일치", 400이면 `BroadcastUnknown` 유지 + E-BTC-008(본문의 노드 거부 사유는 표시하지 않고 `debug` 로그만, [04] §7), 그 밖은 E-BTC-001. 이후 추적은 §12.2 그대로다. 수수료 추정·사전 검사는 Esplora로 하지 않는다(§4). 이 수동 전송이나 같은 바이트 재전송(§12.2-3)이 `Submitted`로 판정되어도 §12.1 표에 `BroadcastUnknown → Submitted`가 없으므로 저널 상태는 `BroadcastUnknown`에 두고(받는 스크립트는 `sent_scripts`에 넣는다) 추적이 `InMempool`·`Confirmed`로 바꾼다.

- `Submitted`가 되면 수신 스크립트의 SHA-256을 `BtcMeta.sent_scripts`에 넣고, 잔돈 출력을 자기 미확정 잔돈으로 기록한다.
- 화면에는 로컬 txid를 표시한다. 서버가 돌려준 txid는 비교에만 쓴다.

## 12. 상태 추적·저널·메타데이터

### 12.1 저널 상태

| 코드 | 상태 | 진행 중 | 다음 |
|---|---|---|---|
| 1 | `Signed` | 예 | `Broadcasting`, `Rejected`, `Abandoned`(사용자 취소) |
| 2 | `Rejected` | 아니오 | 공개된(bit7) 레코드만: `Confirmed`(30일 안에 확정이 관측되면), `Conflicted`(입력 하나를 쓴 다른 거래가 확정됨) |
| 3 | `Broadcasting` | 예 | `Submitted`, `BroadcastUnknown`, `Rejected` |
| 4 | `Submitted` | 예 | `InMempool`, `Confirmed`, `Replaced`, `BroadcastUnknown`, `Conflicted` |
| 5 | `BroadcastUnknown` | 예 | `InMempool`, `Confirmed`, `Replaced`, `Abandoned`, `Conflicted` |
| 6 | `InMempool` | 예 | `Confirmed`, `Replaced`, `BroadcastUnknown`(사라짐), `Conflicted` |
| 7 | `Confirmed` | 아니오 | — (확인 1 = 최종, D32. 추적을 끝내므로 재구성은 관측하지 않는다. 상태표에 남은 `InMempool`·`BroadcastUnknown` 전이는 추적이 쓰지 않는다) |
| 8 | `Replaced` | 교체본 확정(확인 1) 전까지 추적 | `Confirmed`(원본이 확정됨), `Conflicted`(더 앞선 원본이 확정됨) |
| 9 | `Conflicted` | 아니오 | — |
| 10 | `Abandoned` | 아니오 | `Confirmed`(30일 안에 확정이 관측되면), `Conflicted`(입력 하나를 쓴 다른 거래가 확정됨) |

- **D20 적용:** BTC 계정마다 "진행 중" 항목(1·3·4·5·6)은 교체 사슬 하나만 허용한다. 진행 중이면 새 송금은 `InFlight`("진행 중인 Bitcoin 거래가 확인된 뒤 보낼 수 있습니다. 수수료 올리기는 가능합니다")로 막는다. 확인 수 1 이상이 관측되면 해제한다(D32: 확인 1 = 확정, 추가 확인 대기 없음). 이때 잔돈 출력도 바로 쓸 수 있다(§12.2-5, `BTC_MIN_CONF` = 1).
- 시작할 때 `Broadcasting` 항목은 `BroadcastUnknown`으로 바꾼다. `Signed` 항목은 [전송 계속] / [취소] 중 선택을 받는다.
- `Abandoned`는 멤풀에도 없고 확정도 아닌 `BroadcastUnknown`에서만 허용한다. 곧 §12.2-3의 `not_found_count >= 10`이어야 한다(전송 직후 시간 초과·전송 오류·txid 불일치로 된 `BroadcastUnknown`은 아직 포기할 수 없다). `Signed`의 [취소]는 그대로 허용한다. 바이트가 RPC에 간 적이 없으면(bit7 없음) 아래 충돌 규칙 대상이 아니고 확인 창은 "서명했지만 보내지 않은 거래를 취소합니다. 이 거래는 전송하지 않습니다."이다. 사전 검사를 시도한 뒤(bit7, 예: 통신 오류로 `Signed`에 남음)면 확인 창은 "서명한 거래를 취소합니다. 이 거래는 이미 노드(RPC)에 전달되었을 수 있어, 그 노드가 퍼뜨렸다면 나중에 확정될 수 있습니다. 두 번 지불되지 않도록 다음 보내기는 이 거래의 입력을 하나 이상 다시 써서 이 거래를 무효로 만듭니다(30일 동안)."이고 아래 충돌 규칙을 따른다. [포기]의 확인 창에는 "이 거래는 이미 다른 노드에 퍼졌다면 나중에 확정될 수 있습니다. 포기한 뒤 같은 사람에게 다시 보내면 두 거래가 모두 확정되어 두 번 지불될 수 있습니다. 그래서 다음 보내기는 이 거래의 입력을 하나 이상 다시 써서, 둘 중 하나만 확정되게 합니다(30일 동안)."를 표시한다.
- **포기 뒤 보내기(두 번 지불 방지).** `not_found_count >= 10`이거나 공개된(bit7) `Abandoned` 항목과 공개된 `Rejected` 항목은 `updated_at`부터 30일 동안 "살아 있다"(`BtcRecord::is_live_conflict`): 새 보내기(수수료 올리기 제외)는 그런 항목마다 입력 하나 이상을 써야 한다(§7.4 고정 입력, 서명 직전 `check_abandoned_conflicts`로 다시 확인, 어기면 `AbandonedNotConflicted`). 그 입력은 인덱서가 목록에서 빼도 `verified`에 남긴다(§4.7-5). 두 거래가 입력을 공유하므로 둘 중 하나만 확정된다. 어느 한쪽이 확정되면(확인 1) 입력을 공유하는 다른 쪽(`Abandoned`·공개된 `Rejected`·`Submitted`·`BroadcastUnknown`·`InMempool`)은 `Conflicted`가 된다.
- **공개된 거래(적대적 RPC 대비).** `testmempoolaccept`·`sendrawtransaction`은 서명한 바이트를 RPC에 넘긴다. RPC가 "거부"(`allowed:false`, `-25`·`-26`, 결과 불일치)로 답해도 이미 퍼뜨렸을 수 있으므로, 그 `Rejected` 레코드와 사전 검사 실패 뒤 [취소]한 `Abandoned` 레코드는 위 "살아 있는" 항목으로 다룬다: 다음 새 보내기(금액·수수료가 달라도)는 그 입력 하나 이상을 써야 하고(§7.4, `check_abandoned_conflicts`), 그 입력은 `verified`에 남기며(§4.7-5), 30일 동안 2단계만 추적해(§12.2) 확정되면 `Confirmed`로 기록한다. 한쪽이 확정되거나 30일이 지나면 풀린다. 같은 txid를 다시 서명하면 새 레코드도 처음부터 공개로 둔다. 결과 화면 문구: "노드가 거부했습니다. 다만 노드(RPC)가 이 거래를 이미 받았으므로, 다음 보내기는 이 거래의 입력을 하나 이상 다시 써서 둘 중 하나만 확정되게 합니다(30일 동안). …"
- **같은 주소의 다른 계정.** 가져온 키를 지운 뒤 다시 가져오면 vault 레코드 id(무작위)가 바뀌어 계정 식별자가 달라지고, 별칭(HD 주소와 같은 가져온 키)도 식별자가 둘이다. 그래서 D20·입력 재사용·포기 충돌·`verified`에 남길 입력(§4.7-5)·기록 금액은 계정 식별자가 아니라 **입력이 쓰는 스크립트와 outpoint**로 계정의 레코드를 고른다(`AccountScope::of(meta)` + `related_records`): 같은 식별자, 입력 outpoint가 그 계정의 `verified`에 있음, 입력 scriptPubKey가 `owned_scripts`에 있음(ECDSA 형식은 서명된 바이트의 증인·scriptSig 공개키로 계산, key-path P2TR은 그 레코드 계정 키가 세션에 있으면 그 경로로 파생하고 없으면 이 계정 키로 기록 경로의 서명을 검증) 중 하나면 그 계정의 것이다. 새 식별자는 옛 식별자의 살아 있는 포기·공개된 거부 항목을 이어받아 다음 보내기가 그 입력 하나 이상을 써야 한다(준비 단계 `PrepareJob.conflicts`·`in_flight`, 서명 직전 key worker 재확인 모두). 수수료 올리기 대상·잔돈 인덱스 바닥값·활동은 계정 식별자 기준 그대로다.
- **txid는 네트워크마다 저널에 하나다.** 같은 계획을 다시 승인하면 같은 바이트(같은 txid)가 나올 수 있다(예: 사전 검사 거부 뒤 다시 검토). 새 `Signed` 레코드를 넣기 전에 같은 txid의 끝난 레코드(§12.4)와 `Abandoned`·`Rejected` 레코드는 activity로 옮기고 지운다(옛 레코드가 공개였으면 새 레코드도 bit7). 그 밖의 추적 중 레코드가 있으면 서명한 거래를 버리고 "같은 거래가 이미 저널에 있습니다"로 거부한다. 상태 전이는 단계마다 레코드를 한 번 찾은 뒤 `entry_id`로 한다(이 규칙 이전 저널에 같은 txid가 둘 있으면 저널 순서상 마지막 레코드가 현재 레코드이고, 앞선 것은 activity 행을 만들지 않는다).
- 수수료 올리기 대상(§9 "최신 교체본")은 저널 순서(추가 순서)상 마지막 `Submitted`·`BroadcastUnknown`·`InMempool` 레코드다. 벽시계 시각은 쓰지 않는다.

### 12.2 확인 추적

진행 중 항목과 교체본이 아직 확정되지 않은 `Replaced` 항목마다 60초 간격(§4.7)으로 확인한다. `Confirmed`는 확인 1에서 최종이므로(D32, `BTC_FINAL_CONFIRMATIONS` = 1) 더 추적하지 않는다. `Abandoned` 항목과 공개된 `Rejected` 항목은 30일 동안 새로고침 때마다 2단계만 확인한다.

1. `getmempoolentry [txid]`가 객체를 돌려주면 `InMempool`.
2. `-5`이면 인덱서 `TxStatus`(§4.3: `esplora` `GET /tx/{txid}/status`, `bb-rpc` `bb_getTx [txid]`, `bb-rest` `GET tx/{txid}`)를 호출한다. `Confirmed { height }`이면 `Confirmed{height}`(확인 수 = `conf(height, tip_height)`). `NotFound`이면 `not_found_count += 1`. `Unconfirmed`이면 `InMempool`(서버 기준): Core 멤풀에는 없어도 인덱서 쪽 노드가 아직 가지고 있으므로 퍼지는 중이고, [포기] 쪽으로 세지 않는다. `UnconfirmedOrUnknown`(`esplora`, 없는 txid도 `{"confirmed":false}`)이면 인덱서 `TxRaw`(`GET /tx/{txid}/hex`)를 1회 더 호출해 200이면 `InMempool`(서버 기준; 본문은 쓰지 않는다), 404면 `not_found_count += 1`. 2단계만 하는 항목(`Replaced`·`Abandoned`·공개된 `Rejected`)도 같은 판정을 쓴다.
   - `getmempoolentry`를 쓸 수 없는 엔드포인트(§4.5 C2)면 1단계를 빼고 2단계에서 같은 판정을 한다.
   - 진행 중 교체본(§9, 이 항목을 직접 또는 다른 교체본을 거쳐 교체하는 `Signed`·`Broadcasting`·`Submitted`·`BroadcastUnknown`·`InMempool` 항목)이 있는 항목의 `Confirmed`(확인만 하는 `Replaced`·`Abandoned` 포함)는 그 교체본마다 Core `getmempoolentry`가 `-5`일 때만 반영한다. 반영하면 교체본이 `Conflicted`가 되므로 인덱서만 믿지 않는다. 교체본이 Core 멤풀에 있으면 이번 라운드에는 반영하지 않는다. `getmempoolentry`를 쓸 수 없는 엔드포인트는 Core 답이 없으므로 서버 기준 그대로 반영한다.
3. 멤풀에서 관측되면 `not_found_count = 0`으로 되돌린다. **재구성은 범위 밖이다**(D32): 확인 1로 `Confirmed`가 된 항목은 추적을 끝내므로 재구성으로 빠져도 감지하지 않는다. 진행 중 항목의 잔돈 outpoint는 확정될 때까지 후보·잔액에서 뺀다(`in_flight_outpoints`). **팁 높이 이상값 검사는 유지한다**: 인덱서 높이가 Core 팁보다 커서 `conf = 0`인 `Confirmed{height}`는 아직 확정으로 보지 않고, 팁이 확정 높이보다 낮게 보이면(뒤처지거나 잘못된 팁) 그 `Confirmed` 항목은 아직 끝난 것으로 보지 않는다(§2의 `max_tip_seen` 등 기존 검사도 그대로). `not_found_count >= 10`이면 `BroadcastUnknown`으로 바꾸고 [같은 바이트 다시 전송] / [수수료 올리기] / [포기]를 표시한다. 재전송은 저널의 원본 바이트를 그대로 `sendrawtransaction`으로 보낸다. `indexer = esplora`이고 마지막 Core 전송이 통신 실패였으면 [Esplora로 전송](§11.3 수동 전송)도 표시한다.
4. 표시: `확인 대기` / `확정`(확인 1 이상). 확인 수는 서버 기준이라고 함께 적는다("(서버 기준)"). 확인 1이면 추적을 멈춘다(끝난 항목, §12.4). 그 밖의 상태는 고정 문구로 보인다: `Signed` "서명됨(전송 전)", `Broadcasting` "전송 중", `BroadcastUnknown` "전송 결과 확인 필요", `Rejected` "거부됨", `Replaced` "교체됨", `Conflicted` "충돌(다른 거래가 확정됨)", `Abandoned` "포기함".
5. `Confirmed`가 되면 우리 잔돈 출력을 `verified`에 `(outpoint, value, chain, index, height)`로 넣는다. 원본이 로컬에 있으므로 다시 받지 않는다. 단, 출력 스크립트가 현재 세션의 계정으로 파생한 잔돈 스크립트와 같을 때만 넣는다(다른 패스프레이즈 세션이 같은 저널을 볼 때 등): 후보는 `BtcAccountKey::change_candidates` — 현재 모드의 경로(HD 모드 `(1, index)`, 고정 주소 `(0, 0)`)를 먼저, HD 계정이면 다른 모드의 경로도(모드를 바꾸기 전에 쓴 레코드) — 이고 스크립트가 맞는 경로로 넣는다.

### 12.3 `BtcMeta` (meta.ywm 키 `btc`, [02] §5.3)

meta JSON의 `btc`는 `BtcMeta` 객체 또는 `null`(BTC 데이터 없음)이다. 인코딩: 바이트 배열은 소문자 hex, u64 sats는 10진 문자열([02] §5.3), u8–u32는 JSON 정수, `Option`은 `null`, outpoint는 `"<txid hex(표시 순서)>:<vout 10진>"`. 알 수 없는 키·형식·상한 위반은 [02] §5.3 meta 검증 실패와 같게 처리한다.

| 필드 | JSON 타입 | 상한·규칙 |
|---|---|---|
| `version` | 정수 | 1 |
| `network` | `"mainnet"` \| `"testnet4"` | settings.json `bitcoin.network`의 사본. 다르면 BTC 차단(§2) |
| `account_pubkey` / `account_chain_code` | hex 66자 / hex 64자 | m/84'/{coin}'/0' 압축 공개키·체인 코드(§3.1) |
| `receive_next`, `change_next` | 정수 | `< 2^31` |
| `last_used_receive`, `last_used_change` | 정수 \| `null` | |
| `discovery_done` | bool | false면 송금 금지 |
| `max_tip_seen` | 정수(u32) | §2 |
| `verified` | `{outpoint, value: 10진 문자열, chain: 0\|1, index, height, is_coinbase, own}[]` | ≤ 4096 |
| `frozen` | `{outpoint, reason: 1\|2}[]` | ≤ 1024 |
| `unfrozen` | outpoint[] | ≤ 1024 |
| `sent_scripts` | hex 64자[] (SHA-256(spk)) | ≤ 4096, 넘으면 오래된 것부터 삭제 |

meta `btc`는 언제나 기본 계정(BIP84 계정 0)이고 위 버전 1 형식 그대로다(이전 앱 버전이 읽고 쓰는 바이트가 같다). 다른 계정은 같은 필드에서 `account_pubkey`·`account_chain_code` 대신 `"script_type": "p2pkh"|"p2sh-p2wpkh"|"p2wpkh"|"p2tr"`와 `"key": {"hd": {"account": n, "pubkey": hex66, "chain_code": hex64}}` 또는 `{"imported": {"id": hex32(0 아님), "pubkey": hex66|hex130}}` 또는 `{"evm": {"index": 0–999, "pubkey": hex66}}`(EVM 계정 index의 압축 공개키, §3.5)를 쓰는 `version: 2` 객체다(키 순서: version, network, script_type, key, receive_next, …). 버전 2로 기본 계정을 쓰거나, 가져온 키·EVM 키 객체가 `receive_next ≠ 1`·`change_next ≠ 0`·`(Receive, 0)` 밖의 `verified`를 가지면 검증 실패다.

**주소 방식 `single_address`(선택 키, 2026-11-05).** HD 계정 객체(버전 1·2 모두)의 마지막(`sent_scripts` 뒤)에 올 수 있는 bool이다. **없음 = 고정 주소 모드**(§3.5; 이 키 이전에 쓴 모든 meta와 새 계정이 그렇다)이고, 이 버전은 HD 모드일 때만 `"single_address": false`를 쓴다 — 그래서 기본값의 바이트는 이전과 같다(meta `btc`는 그대로 버전 1 바이트). 읽을 때 `true`도 받아들인다. bool이 아니거나 키 하나 계정 객체에 있으면 검증 실패다. **2026-11-07부터 이 키는 쓰지 않는다**(읽기만, 이행): 이전 앱 버전(2026-11-05 전)은 알려진 객체 안의 모르는 키를 거부해 meta 전체를 읽지 못하므로, HD 모드 표시는 새 최상위 키 `btc_accounts_ext.hd_mode`(§12.3b)로 옮겼다.

### 12.3b meta `btc_accounts_ext` (선택 최상위 키, 2026-11-07)

2026-11-05/06 빌드는 HD 모드 표시(`"single_address": false`)를 계정 객체 안에, EVM 키 계정(`key.evm`)·YubiKey 키 계정(`key.yubikey`)과 그 선택을 `btc_accounts` 안에 썼다. 그 전 빌드는 `btc`·`btc_accounts`를 엄격하게 읽으므로(모르는 멤버 = 문서 전체 E-VLT-006) 그런 meta를 열지 못했다. 그래서 [04] §6.6 규칙대로 새 내용은 새 최상위 키에만 둔다.

```
"btc_accounts_ext": { "version": 1,
                      "selected": null | {"evm": {…}} | {"yubikey": {…}},   // hd·imported 선택은 btc_accounts.selected
                      "accounts": [ BtcMeta 버전 2 객체(key.evm·key.yubikey만), … ],
                      "hd_mode": [ {"network": "mainnet"|"testnet4", "account": 계정 식별자(§12.3a selected 형식)}, … ] }
```

- 쓰기(`btc_meta_values`): `btc`·`btc_accounts`에는 이전 빌드가 아는 것만 — `single_address` 없음, `key.hd`·`key.imported` 계정만, `selected`는 그중 하나일 때만(아니면 `null`). 나머지(EVM·YubiKey 키 계정, 그 선택, HD 모드인 HD 계정 — 기본 계정 포함)는 `btc_accounts_ext`. 넣을 것이 없으면 쓰지 않는다(파일이 이전과 같다).
- 읽기(`btc_meta_from_values`): 이전 배치(객체 안 `single_address`, `btc_accounts` 안 `key.evm`·`key.yubikey`)도 받아들이고(이행), 다음 meta 저장에서 새 배치로 옮긴다. `btc_accounts_ext` 안의 HD·가져온 키 계정, 두 키에 걸친 같은 계정, 합쳐 64개 초과, 모르는/빠진 키, `version` ≠ 1은 검증 실패. `hd_mode`가 가리키는 계정이 없으면(이전 빌드가 그 사이 지움) 무시하고 다음 쓰기에서 빠진다. `btc_accounts_ext.selected`가 있으면 그것이 선택이다.
- 계정 순서: 다시 읽으면 `btc_accounts`의 계정 다음에 `btc_accounts_ext`의 계정이 온다.
- 이전 빌드는 이 키를 모르는 최상위 키로 보존하고 다시 쓴다(그 빌드에서는 EVM·YubiKey 키 계정이 보이지 않고 HD 계정은 그 빌드의 방식으로 동작한다). 2026-11-05/06 빌드가 쓴 meta를 이전 빌드에서 열지 못했다면 [04] §6.6 표의 안내를 따른다.

### 12.3a meta `btc_accounts` (선택 최상위 키)

기본 계정 밖의 계정과 선택은 새 최상위 키 `btc_accounts`에 둔다([04] §6.6: 이전 버전은 모르는 최상위 키로 보존하고 다시 쓴다). 이 키가 없는 파일(이전 버전이 만든 모든 파일) = 다른 계정 없음, 선택은 기본 계정. 내용이 기본값이면 쓰지 않는다(파일이 이전과 같다). 알려진 키이므로 형식 오류는 문서 전체 검증 실패다.

```
"btc_accounts": { "version": 1,
                  "selected": null | {"hd": {"script_type": "p2tr", "account": 0}} | {"imported": hex32}
                            | {"evm": {"script_type": "p2wpkh", "index": 0}},
                  "accounts": [ BtcMeta 버전 2 객체, … ] }      // ≤ 64개, (network, 계정 식별자) 중복 금지
```

- 두 네트워크의 계정을 함께 둔다. 화면·작업은 현재 `bitcoin.network`의 계정만 쓰고, 네트워크를 바꿔도 다른 네트워크 계정은 지우지 않는다(돌아오면 다시 보인다). 네트워크 바꾸기(§2)는 기본 계정만 새로 만든다.
- key worker가 유일한 작성자이고(§12.4 앞 규칙과 같이 meta 쓰기 후 보고), UI가 저장하는 meta 문서에는 worker의 `btc`·`btc_accounts` 사본을 넣는다.

**활동 항목.** 추적이 끝난 BTC 저널 항목은 meta `activity["bitcoin:mainnet" | "bitcoin:testnet4"]`에 [02] §5.3 `ActivityEntry`로 옮긴다: `account` = `BtcAccountId::activity_tag()`(기본 계정 `""` — 이전과 같음, HD `p2tr/0` 꼴, 가져온 키 `imported/<id hex>`, EVM 키 `evm/p2wpkh/0` 꼴; 화면은 선택한 계정의 행만 보인다), `tx_id` = 소문자 txid hex(표시 순서), `title` = 승인 제목(§10), `asset` = `"native"`, `amount` = 수신 금액 sats 10진 문자열, `counterparty` = 받는 주소(§6.3 정규형), `status` = [02] §5.3의 BTC 대응(`Confirmed` → `succeeded`, 나머지는 소문자 상태 이름), `time_unix_ms` = 종결 관측 시각. 같은 `tx_id`는 덮어쓴다.

### 12.4 BTC 저널 레코드 본문 (`yw_core::journal::btc`)

journal.ywj의 컨테이너·암호화·원자적 쓰기는 [02](02-core-keys-vault.md) §5.2·§5.4(`yw_core::journal`)를 따른다. BTC entry는 `kind u8 = 0x03 ‖ body_len u32 BE ‖ body`이고 body가 아래 바이트다(최대 238 + 49 × 100 + 32,768 = 37,906바이트). 본문은 빅엔디언이고(raw 거래 바이트는 그대로) 고정 헤더는 238바이트다.

```
[0] record_version u8 = 1   [1] network u8 (1 mainnet, 2 testnet4)   [2] state u8 (§12.1 코드)
[3] flags u8: bit0 send_max, bit1 fee_override_typed, bit2 has_change, bit3 has_replaces,
              bit4 has_replaced_by, bit5 has_confirmed_height,
              bit6 last_send_comm_failure(마지막 Core 전송이 통신 실패, §11.3),
              bit7 disclosed(바이트를 RPC에 넘김: 첫 testmempoolaccept 전에 커밋, §11.3·§12.1. 이 비트 이전 레코드는 0으로 읽힌다)
[4] entry_id [16] (getrandom, 0 아님)   [20] created_at_unix u64   [28] updated_at_unix u64
[36] txid [32] (내부 순서)   [68] wtxid [32]   [100] approval_digest [32]
[132] fee_sats u64   [140] vsize u32 (실제)   [144] lock_time u32   [148] not_found_count u32
[152] replaces_txid [32] (없으면 0)   [184] replaced_by_txid [32] (없으면 0)   [216] confirmed_height u32 (없으면 0)
[220] change_index u32 (없으면 0xFFFFFFFF)   [224] change_vout u32 (없으면 0xFFFFFFFF)   [228] recipient_vout u32
[232] input_count u16 (1–100)   [234] raw_len u32 (≤ 32,768)
[238] input_count × 49: txid[32] vout u32 value u64 chain u8 index u32
[238 + 49n] raw_len 바이트: 서명된 거래(증인 포함)
```

**레코드 버전 2 (기본 계정 밖의 계정).** 기본 계정 레코드는 위 버전 1 그대로다. 다른 계정은 `record_version = 2`이고 고정 헤더 238바이트 뒤 `[238]`에 계정 블록 18바이트(`source u8` 1 HD / 2 가져온 키 / 3 EVM 키, `script_type u8`, HD account u32 + 0 12바이트, 레코드 id 16바이트, 또는 EVM index u32(0–999) + 0 12바이트)가 오고 입력 목록은 `[256]`부터다(최대 본문 238 + 18 + 49 × 100 + 32,768 = 37,924). 블록이 기본 계정을 가리키거나 패딩이 0이 아니거나 알 수 없는 값이면 거부한다. P2PKH 계정의 raw는 증인이 없어야 하고(다른 형식은 증인 필수), `bump_source`·`own_change_utxo`는 레코드 계정이 그 계정일 때만 값을 준다(P2TR 입력은 저장된 서명을 BIP341로 다시 검증해 경로를 대조한다). 이전 앱 버전은 버전 2 본문을 본문 오류로 보고 BTC 보내기만 멈춘다(바이트는 보존).

디코드 검증: 길이가 정확해야 하고, raw가 §6.5로 파싱되며(증인 포함, 재직렬화가 같음), txid·wtxid가 다시 계산한 값과 같아야 한다. 입력 목록은 raw의 입력 순서와 같고(index < 2^31, value ≥ 1), vout 필드는 출력 개수 미만이며(잔돈 vout ≠ 수신 vout, 수신 출력은 §6.4 5종), `fee_sats` = Σ입력 − Σ출력, `vsize`·`lock_time`이 raw와 같고, flags와 0 필드가 서로 일관되고(`confirmed_height`는 `Confirmed`에서만 있고 0이 아님, `Replaced`는 `replaced_by` 필수), `entry_id`가 0이 아니고, 알 수 없는 state가 없어야 한다(flags 8비트는 모두 정의됨). raw에서 다시 만들 수 없는 값(state, send_max·fee_override_typed·last_send_comm_failure·disclosed 비트, entry_id, 시각, approval_digest, not_found_count, 선택 필드 값, 입력 경로 chain·index)은 디코더가 검증할 수 없다. 입력 경로는 RBF 계획 전에 `bump_source`가 증인 공개키를 계정 공개키로 다시 파생해 대조한다. 하나라도 어긋나면 [02] §5.4 본문 오류로 처리한다(BTC 보내기만 끄고 E-VLT-006, 본문은 그대로 보존).

**상한·정리.** 종결 BTC 항목은 최대 `BTC_JOURNAL_FINAL_KEEP`(64)개다([02] §5.4). 추적이 끝난 항목(`Rejected`(공개된 것은 30일 지난 뒤)·`Conflicted`, 확인 1 이상인 `Confirmed`(D32), 교체 사슬 끝이 확인 1 이상·`Rejected`·`Conflicted`·저널에 없음·30일 지난 `Abandoned`인 `Replaced`, 30일 지난 `Abandoned`; 현재 네트워크가 아닌 항목의 `Confirmed`는 확인 수와 무관하게 끝난 것으로 본다)은 그때 위 활동 항목을 meta에 쓰고, 64개를 넘으면 그런 항목부터 오래된 순으로 저널에서 지운다(meta 쓰기 → 저널 삭제 순서). 추적 중인 항목은 지우지 않는다. 새 `Signed` 레코드 전의 개수·용량(평문 16 MiB) 검사와 `journal::JournalError::Full` 차단(서명·전송 없음, 문구 "거래 저널 공간이 부족합니다")은 [02] §5.4·[04] §7을 따른다.

## 13. 오류 표시 (고정 문구만)

| 내부 값 | 표시 |
|---|---|
| `Empty` / `InvalidCharacter` / `NotBitcoinAddress` | 주소를 입력하세요 / 허용되지 않는 문자가 있습니다 / Bitcoin 주소가 아닙니다 |
| `MixedCase` | 대소문자가 섞인 bech32 주소는 받지 않습니다 |
| `Bech32Checksum` / `Base58Checksum` | 주소 체크섬이 틀립니다(오타 확인) |
| `WrongChecksumVariant` / `InvalidPadding` / `InvalidProgramLength` / `InvalidWitnessVersion` / `Base58Length` | 주소 형식이 올바르지 않습니다 |
| `WrongNetwork` / `UnknownVersion` | 다른 네트워크의 주소입니다(지갑: {MAINNET\|TESTNET4}) / 지원하지 않는 주소 버전입니다 |
| `PayToAnchor` | P2A 앵커 출력은 누구나 가져갈 수 있어 보낼 수 없습니다 |
| `InvalidTaprootKey` | 유효하지 않은 Taproot 키입니다. 보내면 잃습니다 |
| `UnsupportedWitnessVersion` | 지원하지 않는 세그윗 버전(v2–v16) 주소입니다 |
| `SilentPayment` / `Lightning` / `UriNotSupported` | 사일런트 페이먼트 미지원 / 라이트닝 미지원 / 주소만 붙여넣으세요 |
| `LooksLikePrivateKey` | 개인키처럼 보입니다. 다른 곳에 붙여넣지 마세요 |
| `DustAmount` / `InsufficientFunds` | 받는 금액이 최소값({n} sats) 미만입니다 / 잔액이 부족합니다(필요 {a}, 사용 가능 {b}) |
| `NetworkMismatch` / `KeyMismatch` | BTC 네트워크 설정이 지갑 데이터와 다릅니다 / 파생한 키가 계정 공개키와 다릅니다. 서명을 중단했습니다 |
| `AmountRecordMismatch` / `InFlight`(§12.1) | 기록된 입력 금액과 계획 금액이 다릅니다. 서명을 중단했습니다 / 진행 중인 Bitcoin 거래가 확인된 뒤 보낼 수 있습니다. 수수료 올리기는 가능합니다 |
| `journal::JournalError::Full`(§12.4, [02] §5.4) | 거래 저널 공간이 부족합니다 |
| `InputNotRecorded`(§5) | 승인하는 동안 입력 UTXO가 검증 목록에서 빠졌습니다(이미 사용되었거나 인덱서 목록에서 사라짐). 서명하지 않았습니다. 다시 검토하세요 |
| `AbandonedNotConflicted`(§7.4, §12.1) | 포기한 거래의 입력을 이번 보내기에 쓸 수 없어 보내지 않았습니다(두 번 지불 방지). … |
| `TipImplausible` / 계획 팁 앞섬(§2) / `ChangeIndexExhausted`(§3.2) | 노드가 알려준 블록 높이가 올바르지 않아 보내지 않았습니다 / 노드 블록 높이({c})가 인덱서({i})보다 6블록 넘게 앞서 보내기를 멈췄습니다… / 잔돈 주소 인덱스를 모두 써서 잔돈이 있는 거래를 만들 수 없습니다 |
| txid 중복(§12.1) | 같은 거래가 이미 저널에 있습니다. 그 거래의 상태를 확인하세요 |
| 인덱서 오류(§4.3–§4.4, §11.3): `IndexerUnreachable` / `IndexerRateLimited` / `IndexerNetworkMismatch` / `IndexerMalformed` / `IndexerRejected`(HTTP 400) / `IndexerAuth` / `EsploraBroadcastRejected` | [04] §7 E-BTC-001 / 002 / 003 / 004 / 005 / 007 / 008 문구 |
| 인덱서 팁 지연(§2 4단계) | W-BTC-IDX-LAG([04] §2.16) |
| RPC `-25` / `-26` / 그 밖 | 입력이 없거나 이미 사용되었습니다 / 노드가 거래를 거부했습니다 / RPC 오류(코드 {n}) |

`reject-reason`은 아래 토큰과 정확히 같을 때만 대응 문구를 쓰고, 그 밖은 "알 수 없는 거부 사유"로 표시한다. 토큰 원문은 로그에만 남긴다. 토큰 목록은 구현 시 Core 31 소스와 대조한다.

| 토큰 | 표시 |
|---|---|
| `min relay fee not met`, `mempool min fee not met` | 수수료율이 노드 최소값보다 낮습니다 |
| `insufficient fee` | 교체 수수료가 부족합니다 |
| `txn-mempool-conflict` | 다른 미확정 거래와 충돌합니다 |
| `missing-inputs`, `bad-txns-inputs-missingorspent` | 입력이 없거나 이미 사용되었습니다 |
| `non-final` | 잠금 시간이 아직 지나지 않았습니다(노드 높이 확인) |
| `dust` | 먼지 출력이 있습니다 |
| `max-fee-exceeded` | 수수료 상한을 넘었습니다 |
| `txn-already-in-mempool`, `txn-already-known` | 이미 전송된 거래입니다 |

## 14. 테스트

### 14.1 벡터 (자동, `crates/yw-core/tests/btc_*.rs`)

BIP84·BIP143·BIP173/350 값은 공식 값이며 독립 Python 계산으로 다시 확인했다. base58 4건, txid·weight·vsize, testnet4·P2A 주소는 독립 계산으로 확인한 값이다(§14.3 오라클로 재확인).

**BIP84** (`abandon`×11 `about`, passphrase 없음):

| 항목 | 값 |
|---|---|
| master fingerprint | `73c5da0a` |
| m/84'/0'/0' pubkey / chain code | `02707a62fdacc26ea9b63b1c197906f56ee0180d0bcf1966e1a2da34f5f3a09a9b` / `4a53a0ab21b9dc95869c4e92a161194e03c0ef3ff5014ac692f433c4765490fc` |
| 0/0 | pub `0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c`, `bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu` |
| 0/1 | pub `03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77`, `bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g` |
| 1/0 | pub `03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6`, `bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el` |
| testnet4 m/84'/1'/0' pubkey / chain code | `03b88e0fbe3f646337ed93bc0c0f3b843fcf7d2589e5ec884754e6402027a890b4` / `3c8c2037ee4c1621da0d348db51163709a622d0d2838dde6d8419c51f6301c62` |
| testnet4 0/0 = m/84'/1'/0'/0/0 (D29) | pub `02e7ab2537b5d49e970309aae06e9e49f36ce1c9febbd44ec8e0d1cca0b4f9c319`, `tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl` |

CKDpub(`Vault::btc_account_xpub` 캐시 공개키 → `bip32::derive_public_child` 2단계) 결과와 개인키 파생(`Vault::btc_public_key`, [02] §10.3) 결과가 두 coin(0'·1')과 두 체인 모두 인덱스 0–19에서 같아야 한다. `btc_account_xpub` 결과는 위 표의 계정 pubkey·chain code와 같아야 한다. BIP32 벡터 1–5(전체 문자열 비교)는 M1([02] §11.3)에서 이미 통과해야 한다.

**BIP143 Native P2WPKH** (bip-0143.mediawiki): unsigned
`0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000`,
입력 1, 금액 600,000,000, 개인키 `619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9`(pub `025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357`).

| 값 | 기대 |
|---|---|
| hashPrevouts | `96b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37` |
| hashSequence | `52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b` |
| hashOutputs | `863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e5` |
| sighash | `c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670` |
| 증인 서명(`sign_ecdsa_low_r`가 첫 시도에 내는 RFC6979 값과 같아야 함) | `304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01` |
| 서명된 거래(BIP 원문 전체 hex) 파싱·재직렬화 | 바이트 동일, txid `e8151a2af31c368a35053ddd4bdb285a8595c769a3ad83e0fa02314a602d4609`, weight 1042, vsize 261 |

**주소** (BIP173/350, 정책 결과 포함). 결과는 문자열의 HRP·버전과 같은 네트워크 지갑 기준이다. `bc`/`tb` 문자열과 base58 문자열은 다른 네트워크 지갑에서 항상 `WrongNetwork`다(§6.3 5a, §6.1).

| 입력 | 결과 |
|---|---|
| `BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4` | P2WPKH `751e76e8199196d454941c45d1b3a323f1433bd6` |
| `tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7` | P2WSH `1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262` |
| `tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c` | P2TR `000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433`(유효 x) |
| `bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0` | P2TR `79be667e…16f81798`(G.x) |
| `bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y` | `InvalidProgramLength`(v1/40) |
| `BC1SW50QGDZ25J`, `bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs` | `UnsupportedWitnessVersion` |
| `bc1pfeessrawgf`, `tb1pfees9rn5nz` | `PayToAnchor` |
| `bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd`, `tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf`, `BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL`, `bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh`, `tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47` | `WrongChecksumVariant` |
| `bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4` | `InvalidCharacter`(데이터부 `o`) |
| `bc1pw5dgrnzv`, `bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav`, `BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P`(v0/16) | `InvalidProgramLength` |
| `tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq` | `MixedCase` |
| `bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf`, `tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j` | `InvalidPadding` |
| `BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R`(v17), `bc1gmk9yu`(빈 데이터부) | `InvalidWitnessVersion` |
| `tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut` | 두 지갑 모두 `NotBitcoinAddress` |
| `1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i` / `3CMNFxN1oHBc4R1EpboAL5yzHGgE611Xou` | `76a91465a16059864a2fdbc7c99a4723a8395bc6f188eb88ac` / `a91474f209f6ea907e2ea48f74fae05782ae8a66525787` |
| `mo9ncXisMeAoXwqcV5EWuyncbmCcQN4rVs` / `2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br` | `76a91453c0307d6851aa0ce7825ba883c6bd9ad242b48688ac` / `a9146349a418fc4578d10a372b54b45c280cc8c4382f87` |

**Bitcoin Core 데이터**: `src/test/data/{key_io_valid,key_io_invalid,tx_valid,tx_invalid}.json`을 `crates/yw-core/tests/vectors/btc/`에 복사하고 출처 커밋을 파일 머리 주석이 아닌 `README`에 적는다(MIT).
- base58: `base58_encode_decode.json`은 M1 `codec::base58` 시험이 이미 쓴다([02] §0, [09](09-testing.md)). BTC는 §6.1 정책만 시험한다.
- key_io_valid: `isPrivkey == false`이고 `chain`이 `main`/`test`(복사한 Core 커밋 `2b5b6fe`에서는 `testnet4`)인 항목은 `main`은 mainnet, `test`는 testnet4 지갑에서 우리 정책 결과와 맞아야 한다: 5종이면 같은 scriptPubKey(P2TR 프로그램이 유효한 x-only 키가 아니면 `InvalidTaprootKey`), 그 밖이면 §6.3 거부 코드. `signet` 항목은 testnet4 지갑에서 `test`와 같은 규칙, `regtest` 항목은 bech32(`bcrt`)면 `WrongNetwork`, base58이면 버전을 공유하므로 testnet4 결과와 같다.
- key_io_invalid: 모두 거부되어야 한다.
- tx_valid: 주석 항목(문자열 1개짜리 배열)을 뺀 모든 직렬화가 파싱되고 재직렬화 결과가 같아야 한다. tx_invalid: 패닉 없이 처리되어야 한다(파싱 성공 여부는 따지지 않는다).

**크기·dust**: §6.4·§7.2 표의 값이 그대로 나와야 한다.

**다른 주소 형식** (`crates/yw-core/src/btc/types_tests.rs`, 공식 벡터만; 출처·커밋은 `tests/vectors/SOURCES.md`):

| 벡터 | 확인 |
|---|---|
| BIP49 (`abandon`×11 `about`, m/49'/1'/0') | 계정 `uprv`/`upub`의 버전 뒤 74바이트 = 우리 `tprv`/`tpub` 직렬화, 0/0 개인키 `c9bdb4…67e8`·공개키 `03a1af…e77f`, keyhash `38971f…35b3`, 리딤 스크립트 `0014…`, 주소 `2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2`(testnet 0xc4 = testnet4) |
| BIP84 | 0/0·0/1·1/0 주소를 `BtcAccountKey`로 다시 확인 |
| BIP86 (m/86'/0'/0') | root `xprv`, 계정 `xprv`/`xpub`, 0/0·0/1·1/0의 internal key·output key·scriptPubKey·bech32m 주소, tweak한 개인키의 x = output key |
| BIP44 | 공개 벡터가 없어 개인 파생 = 공개 파생, `HASH160` P2PKH, 접두 `1`/`m·n`만 확인(base58 인코딩은 Core key_io로 확인) |
| BIP143 P2SH-P2WPKH | hashPrevouts·hashSequence·hashOutputs, sighash `64f3b0…9fb6`, `sign_ecdsa_low_r` 서명 = 원문 서명, 우리 scriptSig·증인으로 만든 거래 = 원문 서명 거래(바이트 동일), 우리 P2SH 출력 = 원문 scriptPubKey |
| BIP341 `wallet-test-vectors.json` (`tests/vectors/btc/bip341_wallet_test_vectors.json`) | scriptPubKey 7건 모두: tweak(머클 루트 포함)·tweaked key·scriptPubKey·BIP350 주소. keyPathSpending 7입력 모두: internal key·tweak·tweaked 개인키. `hashType = 0` 입력: sigMsg·sigHash·서명(보조 난수 0) 바이트 동일. fullySignedTx: P2TR 입력의 엄격 검증 통과(다른 입력 금액 1 sat 변경 시 실패), P2PKH 입력 서명을 레거시 sighash로, P2WPKH 입력 서명을 BIP143으로 검증 |
| Core `sighash.json` (`tests/vectors/btc/sighash.json`) | `SIGHASH_ALL` 의미(하위 5비트 ≠ 2·3, 0x80 없음)이고 스크립트에 0xab 바이트가 없는 139건 모두 레거시 sighash 일치. NONE·SINGLE·ANYONECANPAY는 `None` |

전송 흐름(같은 파일과 `crates/yw-app/tests/btc_app_flow.rs` `every_address_type_end_to_end`): HD 4형식 × 두 네트워크와 가져온 키(압축 4형식, 비압축 P2PKH) 계정마다 검증된 UTXO → 5종 받는 주소 각각·보내기 최대·자기 주소 → 승인 저장소 issue/consume → `sign_plan` → `verify_signed` → 파싱·재직렬화 → 수수료 = 계획 수수료, 실제 vsize ≤ 계획 vsize ≤ 실제 + 입력당 2 vB + 1, 실제 수수료율 ≥ 선택 수수료율 → 저널 레코드 버전 1/2 왕복. vault 경로(`vault_signs_every_hd_and_imported_type`)는 HD 4형식 계정 3과 태그 4 레코드로 가져온 키(공개 테스트 WIF: 비밀값 1의 testnet 압축형 4형식, 비압축형 P2PKH)에서 같은 흐름이고, 없는 레코드 `Vault(RecordNotFound)`, 다른 형식으로 쓴 레코드 `KeyMismatch`, 잠긴 vault `Vault(InvalidState)`. 앱 수준에서는 [계정 추가](4형식) → 발견 → 받기 → 가짜 체인 입금 → 새로고침 검증 → RPC 작업자(prepare, 가짜 Core·Esplora) → 승인 → 서명 → 사전 검사·전송 → 추적 6확인 → 그 계정의 잔돈 삽입·활동 태그 → 기본 계정으로 전환. 가져온 키(`imported_keys_in_a_mnemonic_wallet_end_to_end`, `imported_keys_in_a_key_only_wallet_end_to_end`: BIP49 테스트 키 압축형으로 P2WPKH·P2TR·P2SH-P2WPKH, 비밀값 1 비압축형으로 P2PKH)는 니모닉 지갑의 `개인키 가져오기`(`AddImported`)와 키 전용 지갑의 "개인키로 시작하기"에서 계정 목록(배지·줄인 주소·잔액·선택) → 가짜 체인 입금 → 새로고침 검증 → 받기(경로 `가져온 키`) → prepare → 승인 → key worker 서명(태그 4 레코드) → 사후 검증 → 사전 검사·전송 → 추적 6확인 → 같은 주소로 돌아온 잔돈이 그 계정에 들어가고 활동 태그 `imported/<id>`; 키 전용 지갑은 기본 계정 없이 그 계정이 팁을 보관한다. `key_only_bitcoin_wallet_locks_and_keeps_its_account`(잠금·해제 뒤 계정·팁 유지, [계정 추가] 거절, 마지막 키 `LastKey`), `imported_key_removal`(승인 중·진행 중 거래면 거절 — 화면 문구와 `ImportedKeyBusy`, 확정 뒤 삭제 → `Removed`, 선택은 기본 계정, 다음 meta 읽기 일치). 금액 위조: P2TR은 다른 입력 금액이 바뀌면 입력 0 서명부터 실패, BIP143은 그 입력만, 레거시는 수수료 검사(`FeeMismatch`)로 잡는다.

### 14.2 정책·픽스처 테스트

| 이름 | 기대 |
|---|---|
| `prev_tx_amount_forgery_rejected` | 인덱서가 txid X를 주고 원본의 출력 금액 1바이트를 바꿔 돌려줌 → `TxidMismatch`, 잔액·후보에서 제외 |
| `prev_tx_script_not_ours_rejected` / `prev_tx_vout_oob` / `prev_tx_trailing_byte` / `prev_tx_noncanonical_compactsize` | 해시는 맞지만 vout 스크립트가 다른 주소 → `ScriptMismatch`. 나머지도 각각 거부 |
| `amount_record_mismatch_aborts` | 기록된 outpoint 금액과 계획 금액이 다름 → 서명 전 중단(기록 없음은 `InputNotRecorded`, 다른 문구) |
| `resigned_identical_transaction` / `bump_target_follows_journal_order` | §12.1 txid 하나 규칙: 끝난 같은 txid 레코드는 activity로 옮기고 교체, 추적 중이면 거부, 옛 저널의 중복은 마지막 레코드로 전이 / 수수료 올리기 대상은 저널 순서 |
| `abandoned_transaction_must_be_conflicted` / `indexer_unconfirmed_is_never_abandonable` | §12.1 포기 뒤 보내기는 포기 거래의 입력을 고정으로 쓰고, 한쪽이 확정되면 다른 쪽 `Conflicted` / Core 멤풀에 없어도 인덱서가 미확정으로 보면 `InMempool`(10회 뒤에도 [포기] 없음) |
| `tip_bounds_and_reset` / `implausible_and_runaway_core_tip` / `plan_refused_when_core_far_ahead_of_indexer` / `reset_tip_after_regression` | §2: `blocks >= 500,000,000` 차단, 인덱서 팁 + 3까지만 `max_tip_seen` 상승, 계획 거부, [블록 높이 기록 초기화] |
| `refresh_checks_candidates_with_gettxout` / `gettxout_answers` | §4.7-3: `null`·미확정·스크립트 다름 → 후보 아님, Core 높이 사용, 값 불일치 → 검증 실패, 실패·`-32601` → 인덱서만 확인 |
| `reorg_of_a_shallow_confirmation` / `replaced_by_an_abandoned_replacement_finishes` / `bump_minimum_under_truncated_rates` / `discovery_and_issuance_caps` | §12.2-3 재구성(코어 전이표만; 추적은 확인 1에서 끝나 쓰지 않음, D32) / §12.4 끝난 항목 / §9 버림 비율 / §3.2·§3.4 상한 |
| `disclosed_rejected_or_cancelled_must_be_conflicted` / `hostile_rpc_rejection_after_receiving_constrains_next_send` / `cancel_after_precheck_failure_constrains_next_send` / `undisclosed_signed_cancel_has_no_constraint` | §12.1 공개된 거래: 사전 검사 전에 bit7 커밋([전송 계속]은 저널 작업만 먼저), RPC가 받은 뒤 거부·사전 검사 통신 실패 뒤 [취소] → 다음 보내기(다른 금액·수수료)가 그 입력을 고정으로 씀, 한쪽 확정 → 다른 쪽 `Conflicted`, 공개 거래가 확정되면 `Confirmed`, 30일 뒤 풀림 / 보낸 적 없는 `Signed`의 [취소]는 이전 문구·제약 없음 |
| `send_stopped_by_chain_check_stays_broadcasting` / `comm_failure_survives_restart` / `rejected_send_gives_change_index_back` / `look_alike_recipient_needs_ack` | §11.3 / §11.3·§12.4 bit6 / §3.2 / §10 W-ADDR-3 |
| `inflight_blocks_new_send` / `rbf_allowed_while_inflight` | §12.1 |
| `selection_single_then_fewest` / `change_fold_below_294` / `send_max_dust` / `recipient_dust_by_type` | §7 결정적 결과(고정 seed) |
| `fee_caps_and_typed_override` / `fee_ratio_confirm` / `fee_floor_raises_estimate` / `rbf_rules` | §8, §9(수수료 증가 조건, 수신자 동일, send-max 감소), §10 B01–B08 등급 |
| `approval_btc_digest` | [03] §11.4 입력과 `btc_payload` 임의 1비트 변경 → digest 변경, 표시 필드는 §10 키만, `Approved` 없이 또는 payload가 다른 계획으로 `sign_plan` → 거부 |
| `network_mismatch_blocks` / `journal_btc_prune` | settings·`BtcMeta.network` 불일치 → BTC 네트워크 호출 0회 / 종결 65개째에 추적 끝난 가장 오래된 항목을 activity로 옮긴 뒤 삭제, 추적 중 항목은 남음 |
| `fee_units_btc_per_kvb` | `"0.00001000"` → 1,000 sat/kvB, `"1e-05"`·`"-0.1"`·9자리 소수 거부(`estimatesmartfee`에서는 "추정 없음", `incrementalrelayfee`는 1,000) |
| `post_sign_tamper_each_field` | §11.2 각 항목을 1바이트 변조 → 모두 거부 |
| `testmempoolaccept_mismatch_rejects` | `fees.base`·vsize 불일치 → `Rejected` |
| `server_strings_never_rendered` | 오류 `message`·`reject-reason`에 표시용 문자열을 넣은 픽스처 → 화면 모델에 그 문자열이 없음 |
| `chain_check_genesis` / `journal_codec_roundtrip_and_truncation` | testnet3·signet 제네시스 응답 → 차단 / §12.4 모든 절단·필드 변조 거부 |
| `indexer_req_types_only` | `BtcIndexerReq`가 만든 요청은 `esplora`면 GET `<base>/address/{a}/utxo`·`/address/{a}`·`/tx/{t}/status`·`/tx/{t}/hex`·`/block-height/0`·`/blocks/tip/height`(끝 `/` 없음, 쿼리 없음, 메서드 GET만), `bb-rpc`면 `bb_getUTXOs`·`bb_getAddress`·`bb_getTx`·`bb_getBlockHash`, `bb-rest`면 `utxo/`·`address/`·`tx/`·`block-index/0`이고 인자는 소문자 주소·소문자 txid·`0`과 §4.3 고정 옵션뿐(xpub·`/xpub/`·`bb_getXpub`·`bb_sendTransaction`·`sendtx`·`/txs`·`/fee-estimates`·`/v1/fees`·`POST /tx` 없음). `TipHeight`는 `bb-*`에서 요청을 만들지 않는다 |
| `indexer_amount_strings` | `bb-*`: `value`·`balance`·`unconfirmedBalance`가 JSON 숫자·지수·소수·앞자리 0이면 `MalformedResponse`, `bb-rpc`·`bb-rest` 같은 픽스처는 같은 파싱 결과 |
| `esplora_integer_strict` | `Utxo`의 `value`: `0`·`1`·`2100000000000000` 통과, `2100000000000001`·`99999999999999999`(17자리)·`1.0`·`1e3`·`1E3`·`-1`·`01`·`"1000"`(문자열)·`null` → `MalformedResponse`. `vout`·`block_height`·`*_txo_count`·`tx_count`: `4294967295` 통과, `4294967296`·음수·소수 → `MalformedResponse`(§4.1) |
| `esplora_utxo_status_fields` | `confirmed:true` + `block_height`·`block_hash`·`block_time` 모두 → `height: Some`. 셋 중 하나 없음·`block_hash` 대문자/63자 → `MalformedResponse`. `confirmed:false` + 다른 키 없음(실측 형태) 또는 셋 모두 `null` → `height: None`, 후보에서 제외. `confirmed:false` + `block_height` 정수 → `MalformedResponse`. `status` 없음·outpoint 중복·원소 1,001개 → `MalformedResponse`. `block_height` > Core `tip_height` → `conf = 0`(후보 아님). §4.5 실측 응답을 그대로 넣은 픽스처가 통과 |
| `esplora_address_stats` | 실측 픽스처(abandon 0/0) → `tx_count` = c + m, `confirmed_unspent`·`unconfirmed_incoming` §4.3대로. `address`가 요청과 다름, `tx_count 0`인데 `funded_txo_count > 0`, `chain_stats.spent > funded`, `mempool_stats` 없음 → `MalformedResponse`. 멤풀이 확정 출력을 쓰는 경우(`m.spent > m.funded`, 합계 조건은 만족) → 통과 |
| `esplora_text_endpoints` | `/block-height/0` 본문에 끝 `\n`·대문자 hex·63자·JSON 문자열(`"…"`), `Content-Type: application/json` → `MalformedResponse`(E-BTC-004, 3단계 불일치 아님). `/tx/{t}/hex` 홀수 길이·대문자·`BTC_MAX_PREV_TX_BYTES` 초과 → 거부, 해시가 다른 원본 → `TxidMismatch`(§5). `/blocks/tip/height` `-1`·`1.5`·`4294967296` → 거부 |
| `esplora_http_status` | 모의 서버: 400(`Utxo`·`Address`) → E-BTC-005, 404 `TxStatus`·`TxRaw` → `NotFound`, 404 그 밖 → E-BTC-004, 401·403 → E-BTC-007, 301·500·503 → E-BTC-001(재시도 없음), 오류 본문 문자열이 화면 모델에 없음 |
| `chain_check_indexer_genesis` | `esplora` `/block-height/0`과 `bb_getBlockHash ["0"]`가 testnet3·signet·mainnet(testnet4 지갑) 제네시스 → E-BTC-003 차단, 이후 그 세션의 BTC 요청 0회(주소를 보낸 적 없음). 4단계 팁 차 4 → W-BTC-IDX-LAG만, 송금 가능 |
| `indexer_429_backoff` | 가짜 시계·모의 서버: 429×3 후 200 → 성공, 대기 2/4/8 s. 429×4 → 그 작업 중단, E-BTC-002, 발견이면 `discovery_done == false`, 300 s 동안 자동 새로고침 요청 0회(수동 새로고침은 실행). 모든 요청 시작 간격 ≥ 200 ms |
| `esplora_tx_status_ambiguous` | `getmempoolentry` `-5` 또는 미지원 모드에서 `{"confirmed":false}` + `/hex` 200 → `InMempool`, + `/hex` 404 → `not_found_count + 1`. `confirmed:true` → `Confirmed{height}` |
| `prev_tx_fallback_txraw` | Core `getrawtransaction` `-5` → 인덱서 `TxRaw` 1회, 원본 해시 일치 → 검증 UTXO, 금액 1바이트 변조 → `TxidMismatch` |
| `esplora_broadcast_manual_only` | 자동 경로(§11.1·§12.2)에서 `POST /tx` 0회. `BroadcastUnknown` + Core 통신 실패 + 사용자 확인일 때만 1회, 본문 = 저널 원본 hex, 응답 txid 일치 → `Submitted`, 불일치 → `BroadcastUnknown`, 400 → E-BTC-008. Core `-26` 거부 뒤에는 버튼 없음 |
| `parser_random_bytes_no_panic` | 고정 seed 무작위 바이트·변형 10만 회, 패닉 없음 |
| 고정 주소 모드(§3.5, 2026-11-05) | 코어 `fixed_address_change_is_the_receive_address`(잔돈 index 0 = `(Receive, 0)` 스크립트, `/1/0` 입력도 씀, 서명·검증 통과, 잔돈이 `/1/0`·`/1/1`·`/0/1`인 계획은 서명해도 `PostSignError::Outputs`, HD 모드는 `/0/0` 잔돈을 거부), `btc_meta::fixed_address_mode`(받기 `/0/0` 고정, "새 주소" `SingleAddress`, 발견이 `/0/1`·`/1/0`을 찾고 그 UTXO가 쓸 수 있음, HD ↔ 고정 전환에 인덱스·UTXO 유지, 기본값은 키 없음(이전 바이트)·HD는 `"single_address":false`, 이전 meta = 고정, 잘못된 값·키 하나 계정의 키 거부), `btc_journal::fixed_address_change_in_records`(`hd_change_index`·`change_next_floor`가 고정 잔돈을 세지 않음, 모드를 바꿔도 `own_change_utxo`가 맞는 경로), 앱 `every_address_type_end_to_end`(4형식 × 두 모드, 모의 RPC 끝까지: 고정이면 잔돈 출력 = 받기 주소, `change_next` 0, 내 잔돈 `/0/0`), `fixed_address_mode_end_to_end`(기본 계정 기본 고정, `/0/1` 이전 입금 발견·사용, 받기 화면 `/0/0`만, 전환 저장·승인 중 거부), `fixed_address_change_never_moves_change_next`(key worker), meta `btc_address_mode_and_evm_shared_accounts`, 화면 `address_mode_radios_and_receive_screen` |
| EVM 계정과 같은 키(§3.5) | `evm_shared_addresses_match_vectors`(독립 구현으로 만든 `abandon`×11 `about` EVM 계정 0·1 키의 4형식 × 2네트워크 주소, 예: 계정 0 P2WPKH `bc1qgsvdpdxec8hsu57lhxg5xem7refr233z2ttx7e`, P2TR `bc1p08q6wdgnqe0gwpp4ygs0y8lwgxlpv2l4uc0zq5qjnagwtg92fussqdhm72`), `evm_shared_send_end_to_end_every_type`(vault가 EVM 키를 빌려 서명, 잔돈 = 같은 주소, 레코드 계정 블록 source 3 왕복, 다른 EVM 키 캐시는 `KeyMismatch`), `evm_shared_account_block`(저널 블록·패딩·범위), `evm_shared_account_json`(`key.evm`·`selected.evm`·중복 거부), `evm_shared_public_key_and_wif`(공개키, WIF = EVM 개인키, 비밀번호), `evm_shared_key_signs_messages`(BIP322), 앱 `evm_shared_account_end_to_end`(기본 키 출처는 표준 경로, 명시 선택 + 확인 전에는 아무것도 없음, 4형식 주소 = 벡터, 보내기 잔돈 = 같은 주소, 같은 EVM index·형식 중복과 같은 키 WIF 가져오기(양쪽 순서) `DuplicateKey`), 화면 `account_card_and_type_chooser`(키 출처 기본 (a)) |

### 14.3 차등 검사 (rust-bitcoin 오라클, 개발 전용)

- 위치: 저장소 안 `tools/btc-oracle/`([01](01-repo-build.md) §2.1, [07](07-solana.md)의 `tools/sol-oracle/`과 같은 방식). 자체 `[workspace]`를 가진 별도 워크스페이스이고 루트 `Cargo.toml`의 `[workspace] exclude`에 넣는다([01] §3.1). 따라서 의존성 허용 목록·`check-core-deps.mjs`·`check.ps1` 대상이 아니고 배포하지 않는다(어떤 바이너리에도 들어가지 않는다).
- 의존성: `yw-core = { path = "../../crates/yw-core" }`, `bitcoin = "=0.32.x"`(구현 시 crates.io의 0.32 최신 패치로 고정). 자체 `Cargo.lock`을 커밋한다. 처음 받을 때만 네트워크가 필요하다.
- 실행: `cargo test --release --manifest-path tools/btc-oracle/Cargo.toml`. M8 판정 때, 그리고 `yw-core/src/btc/` 변경 때 수동으로 실행한다.
- 검사(고정 seed xorshift64*, 각 20,000건): (1) 무작위 거래(입력 1–20, 출력 1–3, 5종 스크립트, 무작위 증인)의 직렬화·txid·wtxid·weight·vsize가 `bitcoin::consensus`·`Transaction::weight()`와 같다. (2) 입력마다 BIP143 sighash가 `SighashCache::p2wpkh_signature_hash(.., EcdsaSighashType::All)`과 같다. (3) 5종 무작위 프로그램의 주소 인코딩이 `Address::from_script`와 같다(testnet4는 `Network::Testnet`, HRP·버전 동일). (4) 우리 서명이 rust-bitcoin secp로 검증된다. (5) 변형 바이트에서 우리 파서가 받아들인 거래는 rust-bitcoin도 같은 값으로 디코드한다.

### 14.4 testnet4 E2E (체크리스트 1회)

1. BTC 켜기(testnet4, 기본 인덱서 `esplora`) → §2 연결 검사 1–4단계 통과(착수 검사 §4.5는 M8-1), 발견 완료, 배너 확인.
2. 파우셋 입금 → "미확정 입금(미검증)" 표시 후 확정되면 검증 잔액에 반영.
3. 5종 대상 송금: P2PKH(`m…`/`n…`), P2SH(`2…`), P2WPKH, P2WSH(Sparrow 멀티시그 지갑, 예: 1-of-2 P2WSH), P2TR(Sparrow taproot). 각각 수신 지갑에서 금액을 확인한다.
4. 보내기 최대, 잔돈 없음(수수료 흡수) 경우.
5. 하한 수수료로 보낸 뒤 RBF → 교체본 확정, 원본 `Replaced`.
6. `Broadcasting` 직후 앱 강제 종료 → 재시작하면 `BroadcastUnknown`이 되고 이후 `InMempool`/`Confirmed`로 바뀜.
7. 거부 확인: mainnet 주소, P2A, v2 주소, dust 금액, 진행 중 두 번째 송금, 600 sat/vB(보내기 폼 입력 해제 경로 포함), 동결 UTXO 제외, settings.json `bitcoin.network`를 손으로 바꾼 뒤 재시작(불일치 차단).
8. 주소 형식(§3.5): [계정 추가]로 탭루트·호환 세그윗·레거시·네이티브 세그윗 계정 1을 하나씩 만들고 각각 입금 → 검증 잔액 → 송금(형식마다 1회 이상, 받는 주소 종류를 섞음) → 확정·잔돈이 그 계정으로 돌아옴. 체크리스트는 `docs/acceptance/btc-types-20261029.md`.
9. 인덱서: 설정에서 `esploraBaseUrl.testnet4`를 `https://mempool.space/api`(mainnet)로 바꿈 → `Esplora 테스트`와 BTC 새로고침 모두 E-BTC-003, 주소 요청 없음 → `기본값으로` → 정상. `https://mempool.space/testnet/api`(testnet3)도 E-BTC-003. (선택 인덱서를 쓰지 않으면) `indexer`를 `bb-rpc`로 바꿈 → 애드온 없는 엔드포인트에서 E-BTC-007 → `esplora`로 되돌림.

### 14.5 복구 확인 (체크리스트 1회 + 자동)

1. 테스트 니모닉 `abandon…about`에 passphrase 없음과 `YourWallet-Test-1` 두 경우를 Sparrow(Native Segwit, m/84'/0'/0')와 Electrum(BIP39 seed, p2wpkh, m/84'/0'/0')에 넣고, 받기·잔돈 각 20개 주소를 `crates/yw-core/tests/vectors/btc/restore_{sparrow,electrum}_{nopass,pass}.txt`에 기록한다. 이후 자동 테스트가 yw-core 파생과 비교한다.
2. 14.4에 쓴 testnet4 전용 테스트 니모닉을 Sparrow testnet4 모드(기본 경로 m/84'/1'/0', 직접 지정 없음)로 복구해 잔액·UTXO가 같은지 본다. 구현 시 확인: Sparrow·Electrum의 testnet4 지원 버전. 둘 다 없으면 주소 비교(1)와 공개 블록 탐색기 잔액 확인으로 대신한다.
3. 실제 자금 니모닉은 다른 앱에 넣지 않는다. 비상 복구 절차는 `docs/recovery-guide.ko.md`에 Sparrow·Electrum 경로와 passphrase 주의를 추가한다.

### 14.6 M8 완료 조건 매핑

spec.md M8의 "BIP143·BIP173/350·BIP84 벡터"는 §14.1(자동), "testnet4 E2E"는 §14.4, "입력 금액 위조 픽스처 거부"는 §14.2 `prev_tx_amount_forgery_rejected`, "Sparrow/Electrum 복구 확인"은 §14.5로 판정한다. 차등 오라클(§14.3) 통과도 M8 판정에 포함한다.

## 15. 상수

| 이름 | 값 |
|---|---|
| `MAX_MONEY` | 2,100,000,000,000,000 sats |
| `BTC_GAP_LIMIT` / `BTC_GAP_HARD_LIMIT` | 20 / 100 |
| `BTC_TX_VERSION` / `BTC_SEQUENCE` / `SIGHASH_ALL` | 2 / `0xFFFF_FFFD` / `0x01` |
| `BTC_MAX_INPUTS` / `BTC_MIN_CONF` / `BTC_COINBASE_MATURITY` | 100 / 1 / 100 |
| `BTC_CHANGE_DUST` / `BTC_AUTO_FREEZE_BELOW` | 294 sats (P2WPKH) / 1,000 sats |
| `BTC_FEE_FLOOR_DEFAULT` | 1,000 sat/kvB (1 sat/vB) |
| `BTC_FEE_RATE_CAP` / `BTC_FEE_RATE_UNOVERRIDABLE` | 500,000 / 10,000,000 sat/kvB (500 / 10,000 sat/vB) |
| `BTC_FEE_ABS_CAP` / `BTC_FEE_RATIO_CONFIRM` | 500,000 sats (0.005 BTC) / 2% (`fee × 50 > amount`) |
| `BTC_CONF_TARGETS` | 2 / 6 / 24 |
| `BTC_MAX_PREV_TX_BYTES` | 400,000 |
| `BTC_MAX_JOURNAL_RAW` / `BTC_JOURNAL_FINAL_KEEP` | 32,768 / 64 ([02] §5.4) |
| `BTC_REQ_MIN_INTERVAL_MS` / `BTC_POLL_SECS` / `BTC_CHAIN_RECHECK_SECS` | 200 / 60 / 600 |
| `BTC_429_BACKOFF_MS` / `BTC_429_COOLDOWN_SECS` | 2,000 → 4,000 → 8,000 (재시도 최대 3회) / 300 |
| `BTC_ESPLORA_DEFAULT_MAINNET` / `BTC_ESPLORA_DEFAULT_TESTNET4` | `https://mempool.space/api` / `https://mempool.space/testnet4/api` |
| `BTC_INDEXER_MAX_UTXOS` / `BTC_INDEXER_TIP_LAG_WARN` | 1,000 / 3 블록 |
| `BTC_DISCOVERY_MAX_SCAN` / `BTC_MAX_ADDRESS_INDEX` | 체인마다 1,000개(한 번의 발견·"더 찾기") / 10,000(발급 인덱스 상한) |
| `BTC_LOCKTIME_THRESHOLD` / `BTC_PLAN_TIP_AHEAD_MAX` | 500,000,000 / 6 블록 |
| `ScriptType` 코드 | `P2pkh` 1 / `P2shP2wpkh` 2 / `P2wpkh` 3 / `P2tr` 4 (meta·저널·vault 태그 4에 저장, 바꾸지 않음) |
| `BTC_MAX_HD_ACCOUNT` / `MAX_BTC_ACCOUNTS` | 99(추가 HD 계정 번호 상한) / 64(`btc_accounts` 계정 수, 두 네트워크 합) |
| 입력 weight 추정 (§3.5) | P2PKH 588(비압축 716) / P2SH-P2WPKH 363 / P2WPKH 271 / P2TR 230 |
| `BTC_RECORD_VERSION` / `BTC_RECORD_VERSION_V2` / `BTC_JOURNAL_ACCOUNT_LEN` | 1 (기본 계정) / 2 (그 밖 계정) / 18 |
| `BTC_NOT_FOUND_LIMIT` / `BTC_INDEXER_COST_ASSUMED` | 10 / `esplora` 0(무료). Core 메서드 크레딧과 선택 인덱서 비용은 미정(§4.5 C3·B4에서 측정; QuickNode 크레딧 또는 알케미 CU, 설명 기준 `bb_*` 10 크레딧) |

## 16. 작업량 (집중 작업일)

주소·base58check 정책·bech32·스크립트·거래 모델·엄격 파서 + 벡터 8–12일, BIP143·서명·서명 후 검증·CKDpub·발급·발견 7–11일, Core RPC·인덱서 3형식(`esplora`·`bb-rpc`·`bb-rest`, 공통 `BtcIndexerResp`)·10진/정수 파싱·새로고침·이전 거래 검증 9–12일, 코인 선택·수수료·dust·send-max·동결·RBF 7–9일, 승인 표시·digest·저널·확인 추적·화면 6–9일, 차등 오라클·testnet4 E2E·복구 확인 3–7일. 합계 40–60일로 spec.md §5와 같다.

## 17. dApp 연결: 소유 증명 전용 (2026-10-31, D26·D27)

dApp은 Bitcoin 주소를 **연결**하고 **메시지에 서명**하게 할 수만 있다. 연결 주소와 서명 키는 계정의 받기 주소 0번 `(Receive, 0)`이다 — 고정 주소 모드(§3.5, 기본)의 받기·잔돈 주소와 같고, EVM 키 계정은 그 한 주소(`BtcKeySource::EvmShared`, vault의 EVM 키로 서명)다. HD 모드 계정도 연결 주소는 바뀌지 않는다. PSBT·거래 서명, dApp발 전송, 인스크립션은 없다(UniSat·Xverse shim이 4200으로 거부, 와이어 메서드 없음 — [05] §2.13, §3.6). Bitcoin dApp 노출은 확장 호환 모드(`unisat`·`xverse`)에서만 한다(`off`면 content가 `btc_*`를 와이어로 보내지 않고 4200). settings에서 Bitcoin을 끄면(§2 BTC 끄기) yw-app은 `btc_getNetwork`·`btc_disconnect` 밖의 `btc_*`를 4100 `NoBtcAccount`로 거부하고 Bitcoin grant는 남지만 쓰지 않는다. 연결·grant는 [05] §4.9(목적마다 계정 하나의 받기 주소 0번, 가져온 키는 그 주소; 가져온 키를 지우면 그 주소를 가진 grant는 통째로 삭제, 연결 창이 열린 사이 네트워크를 바꾸면 승인 때 다시 대조해 4100), 승인 창은 [04] §3.

### 17.1 코어 (`yw_core::btc::msgsign`)
- `ApprovalKind::BtcMessage = 0x32`, origin은 사이트, `ChainRef::Bitcoin { network, genesis = 고정 제네시스 }`, `AccountRef::Bitcoin(주소 공개키의 압축 형식)`, `Signer::FromPayload`, `SigningPayload::BtcMessage { network, source, pubkey, script_type, address, protocol, message }`(digest 바이트 = transcript `"your-wallet/v3/btc-message"` v1의 모든 필드).
- 서명(`sign_message(vault, approved)`): 종류·체인·계정 확인 → 메시지 ≤ 65,536 B이고 §17.2 차단 아님 → `address_of(network, script_type, pubkey)` = 승인 주소 → 키 출처의 형식 = 주소 형식 → `BtcKeys::with_btc_key`로 빌린 키의 공개키 = 승인 공개키 → 아래 방식으로 서명 → 즉시 검증.

### 17.2 방식과 인코딩
| 주소 형식 | `ecdsa`(BIP137) | `bip322` |
|---|---|---|
| P2PKH | 헤더 27+recid(비압축)·31+recid(압축) | **지원 안 함**(legacy BIP322는 구현하지 않음) → -32602 |
| P2SH-P2WPKH | 35+recid | full: 서명된 `to_sign` 거래 전체(scriptSig = 리딤 스크립트 push, 증인 `[sig, pubkey]`) |
| P2WPKH | 39+recid | simple: 증인 스택 `[sig, pubkey]` |
| P2TR(키 경로, BIP86) | **지원 안 함**(BIP137 헤더 없음) → -32602 | simple: 증인 `[schnorr sig 64B]`(SIGHASH_DEFAULT, BIP340 보조 난수) |

- BIP137: `SHA256d("\x18Bitcoin Signed Message:\n" ‖ CompactSize(len) ‖ message)`에 RFC 6979 복구 가능 서명, `header ‖ r ‖ s` 65바이트 base64. 서명 후 복구한 키·압축·헤더가 같은지 확인한다.
- BIP322: `message_hash = TaggedHash("BIP0322-signed-message", message)`, `to_spend`(version 0, 입력 `0^32:0xFFFFFFFF` scriptSig `OP_0 PUSH32[message_hash]` sequence 0, 출력 0 sat·주소 scriptPubKey), `to_sign`(version 0, `to_spend` 출력 0 소비, sequence 0, 출력 0 sat `OP_RETURN`, lock time 0). ECDSA는 기존 `sign_sighash`(low-R RFC 6979, BIP143), Schnorr는 `sign_key_path`. 결과는 base64이며 최종 BIP의 `smp`/`ful` 접두사를 **붙이지 않는다**(BIP가 허용하는 이전 인코딩, UniSat·Xverse·`bip322-js`와 같음).
- 기본 방식(dApp이 정하지 않을 때): P2TR → `bip322`, 그 밖 → `ecdsa`(sats-connect 기본과 같음). UniSat `signMessage(msg)`의 기본은 `ecdsa`.
- 응답 `messageHash`: BIP137은 magic hash, BIP322는 message hash(hex).

### 17.3 차단 (`M03`)
메시지 바이트가 Bitcoin 거래로 엄격 파싱되거나 PSBT magic `psbt\xff`로 시작하면, 또는 텍스트가 그런 바이트의 hex(`0x` 허용)·base64 표현이면 `M03` 차단. 64 KiB 초과도 `M03`.

### 17.4 표시
제목 `[Bitcoin 메인넷] 메시지 서명 (소유 증명)`. 필드: 요청 출처, 네트워크, 서명 계정(라벨·경로·**전체 주소**), 서명 방식(`BIP137 ECDSA (Bitcoin Signed Message)` / `BIP322 (simple)` / `BIP322 (full)`), 메시지(텍스트 또는 hex, [07] §19.3과 같은 규칙), 바이트 수. 항상 `M04` 정보. BTC 네트워크 배너(§2)를 그대로 쓴다.

### 17.5 시험 벡터 (자동, `btc::msgsign::tests`)
BIP322 `basic-test-vectors.json`(2026-10-31 `bitcoin/bips` 저장소): `""`·`"Hello World"`·UTF-8 메시지의 message hash와 `to_spend`/`to_sign` txid, P2WPKH simple 서명(`L3VFeEuj…` 키) 바이트 단위 재현(low-R 벡터)과 두 벡터·`smp` 접두 검증, 오류 벡터(틀린 메시지·빈 스택·잘못된 base64), P2TR "No prefix fallback" 서명 검증과 같은 키로 만든 서명 검증. BIP137: bitcoinjs-message 픽스처(개인키 1, "vires is numeris")의 비압축·압축 P2PKH·P2SH-P2WPKH·P2WPKH 서명 재현, magic hash 2개, verify 픽스처 4개. P2SH-P2WPKH full은 `to_sign` 재파싱과 BIP143 증인 검증. 거래·PSBT·hex·base64 탐지, P2PKH+BIP322·P2TR+ECDSA 거부, 다른 키 거부. fuzz-lite `fuzz_lite_btc_msgsign`(`crates/yw-core/tests/msgsign_fuzz_lite.rs`: 원시 거래·PSBT는 항상 탐지, 12바이트 이상이면 그 hex(`0x`·공백 포함)와 base64도 탐지)과 `fuzz_lite_base64`(엄격 디코딩 = 정규 인코딩).

## 미결 사항

1. **구현 시 확인 — Esplora 기본 인덱서(§4.5 E1–E3).** 공용 mempool.space의 응답 형태가 2026-10-27 실측(§4.5)과 같은지, 실제 사용량에서 429가 나는지(한도 비공개, §4.4). 대안: 다른 Esplora URL(blockstream.info·자체 운영) 또는 선택 인덱서(§4.5 B). 쓸 수 있는 인덱서가 없을 때만 M8 보류(D26). **M8에서 확인함(2026-10-27, `docs/acceptance/m8-live-20261027.md`):** 응답 형태는 §4.5와 같다. 같은 날 반복 조회에 429가 났고(§4.4 백오프·중단 동작), 이 PC의 네트워크에서 mempool.space IPv4 6개 중 2개가 응답하지 않아 WinHTTP 호출이 간헐적으로 E-BTC-001이 되었다(blockstream.info는 정상).
2. **선택 — Blockbook 인덱서(§4.5 B1–B4).** `bitcoin.indexer`를 `bb-rpc`(QuickNode BTC Blockbook 애드온, 유료 요금제 위 월 약 75달러부터)·`bb-rest`(알케미 UTXO API)로 쓰기로 할 때만: 활성화·요금제, `bb_*` 응답 필드 이름·타입(`bb_getTx`의 Bitcoin `hex`·미확정 `blockHeight`), `bb_getBlockHash` 인자 형식, 애드온 미활성·거래 없음 오류 코드, 호출당 크레딧·CU. 애드온이 꺼져 있음(2026-10-27 `-32601`)은 **M8을 막지 않는다**.
3. **구현 시 확인 — 임의 거래 `getrawtransaction`(§4.5 C1, txindex).** QuickNode(현재 공급자)·알케미·직접 입력 엔드포인트 모두. 대안: 인덱서 `TxRaw`(`esplora` `/tx/{txid}/hex`, `bb-*` `hex`; §5 검증 동일). **QuickNode 확인함(2026-10-27):** mainnet 블록 170 거래·testnet4 거래 모두 원본을 준다(txindex), 없는 txid는 `-5`.
4. **구현 시 확인 — §4.5 C2 Core JSON-RPC 세부**(봉투 형식, testnet4 `estimatesmartfee`, `getmempoolentry` 제공 여부(QuickNode 문서 페이지 없음), `maxfeerate` 인자). testnet4 `chain` 값은 2026-10-27 확인. 대안: 추정이 없으면 직접 입력만(§8.2), `getmempoolentry`가 없으면 §12.2의 인덱서 판정(`esplora`는 `TxRaw` 존재 확인 포함), `maxfeerate`를 거부하면 인자를 빼고 §8.3 로컬 상한에만 의존한다. **QuickNode 확인함(2026-10-27):** 봉투 `{"jsonrpc":"2.0","result"|"error","id"}`(반대쪽 키 없음), testnet4 `estimatesmartfee`는 `errors`만(추정 없음), `getmempoolinfo` 세 값 0.00000100, `getmempoolentry` 제공(확정 거래 `-5`), `testmempoolaccept`가 숫자 `maxfeerate`를 받음. `sendrawtransaction`의 `maxfeerate`와 멤풀 안 거래의 `getmempoolentry`는 M8-4에서 확인.
5. **구현 시 확인 — §13 `reject-reason` 토큰을 Core 31 소스와 대조.** 대안: 모르는 토큰은 "알 수 없는 거부 사유"로 표시(기능 영향 없음).
6. **구현 시 확인 — Sparrow·Electrum testnet4 지원 버전(§14.5-2), rust-bitcoin 0.32.x 패치 고정(§14.3).** 대안: 주소 비교(§14.5-1)와 공개 블록 탐색기 잔액 확인.
7. ~~다른 문서 반영 — `bitcoin.indexer`·`esploraBaseUrl`~~ 완료([04] §1.9·§2.11·§2.16·§6.1·§7, [09] §2.5·§4.4·§5.10·§6). `probe-rpc.mjs`(01 §4.7)의 `bb_getBlockHash 0` 줄은 애드온이 없으면 `err`가 정상이다.
