# Zcash 일반(transparent) 전송 전용

상위 문서: [spec.md](../spec.md)

D35의 세부 명세다. 방식은 Bitcoin([08](08-bitcoin.md))과 같다: 받기·보내기는 yw-app 화면(Zcash 탭)에서만 하고 dApp 연결은 없다. 비공개(shielded: Sapling·Orchard) 거래는 범위 밖이다. 코드는 `yw_core::zec`(코어)와 `crates/yw-app/src/{app_zec.rs, zec/, ui/screens_zec.rs, workers/journal_zec.rs}`(앱)이다. 확인한 사실과 출처는 §16에 모은다(2026-11-06 확인).

## 1. 범위

### 1.1 포함

| 항목 | 규칙 |
|---|---|
| 받기 | 계정 하나 = 고정 P2PKH 주소 하나(Bitcoin 고정 주소 방식, D29). 기본 키는 니모닉의 `m/44'/133'/0'/0/0`(testnet `m/44'/1'/0'/0/0`, §2.2). 받기 화면에 T-ZEC-RECEIVE "일반(transparent) 주소입니다 — Zashi 등 비공개 주소로 받으려면 그 지갑에서 받으세요." |
| 보내기 대상 | `t1…`/`t3…`(testnet `tm…`/`t2…`) Base58Check, ZIP 320 TEX(`tex1…`/`textest1…`, P2PKH), ZIP 316 revision 0 통합 주소(`u1…`/`utest1…`)의 일반 수신자(P2PKH 또는 P2SH) |
| 보내기 거부 | Sapling `zs…`/`ztestsapling…`, Sprout `zc…`/`zt…`, 일반 수신자가 없는 UA, ZIP 316 revision 2 초안 형식(`tu…`, `zu…`), MUST-understand 메타데이터(0xE0–0xFC)가 있는 UA, 다른 네트워크·다른 코인 주소, `zcash:` URI |
| 키 출처 | (1) 표준 경로(기본) (2) `EVM 계정과 같은 키`(명시적 선택 + 확인, 연결성 경고 T-ZEC-EVM-SHARED) (3) YubiKey OpenPGP secp256k1 슬롯([10](10-yubikey.md) `KeyRole::Zec`) |
| 거래 형태 | v5(ZIP 225) 일반 입력·출력만, 수신자 1명 + 잔돈 0–1개(잔돈은 같은 주소), 보내기 최대, `SIGHASH_ALL`만 |
| 데이터 원천 | 네트워크마다 `zcash:<net>` 엔드포인트 하나(D13, 현재 QuickNode). UTXO는 `zcash.indexer`로 고른다: `node`(기본, 같은 엔드포인트의 `getaddressutxos`) 또는 `bb-rest`(같은 엔드포인트의 Blockbook REST `/api/v2/utxo/<주소>`) |

### 1.2 제외 (phase 1)

비공개 거래 전부(Sapling·Orchard 출력·입력, 비공개 주소로 받기), dApp 연결·메시지 서명, 여러 수신자, 메모, ZIP 321 결제 URI 해석, RBF(Zcash에 없음), v6 거래(ZIP 229) 작성, **가져온 개인키(WIF)**. WIF 형식은 확인했지만(§16 #2: Zcash도 `0x80`/`0xEF`, 압축 표시 `0x01`) 저장하려면 vault payload에 새 tag가 필요하고, 새 tag는 이전 버전이 vault를 E-VLT-014로 열지 못하게 만든다([04](04-app-ui.md) §6.6 형식 확장 규칙). phase 1에서는 넣지 않고 §미결 사항에 남긴다.

## 2. 네트워크와 키

### 2.1 네트워크 고정

설정 `settings.json`의 `"zcash": {"enabled": bool, "network": "mainnet"|"testnet", "indexer": "node"|"bb-rest"}`(기본 `{"enabled": false, "network": "mainnet", "indexer": "node"}`). 이전 버전은 모르는 최상위 키로 보존한다([04] §6.6).

| 항목 | `ZecNetwork::Mainnet` (id 1) | `ZecNetwork::Testnet` (id 2) |
|---|---|---|
| 네트워크 ID (D13) | `zcash:mainnet` | `zcash:testnet` |
| QuickNode 템플릿 | `https://<이름>.zec-mainnet.quiknode.pro/<토큰>/` (QuickNode 문서 예시 호스트 `docs-demo.zec-mainnet.quiknode.pro`) | `…zec-testnet…` (추정, 첫 사용 때 확인; 다르면 직접 입력) |
| 알케미 템플릿 | 없음 | 없음 |
| SLIP-44 coin type | 133 | 1 |
| `getblockhash 0` | `00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08` | `05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38` |
| `getblockchaininfo.chain` | `"main"` | `"test"` |
| Base58Check P2PKH / P2SH | `1C B8` (`t1`) / `1C BD` (`t3`) | `1D 25` (`tm`) / `1C BA` (`t2`) |
| TEX HRP (ZIP 320) | `tex` | `textest` |
| UA HRP (ZIP 316 R0) | `u` | `utest` |
| WIF 버전 | `0x80` | `0xEF` |
| 배너 | `ZCASH MAINNET` (빨강) | `ZCASH TESTNET — 가치 없음` (테스트넷 색) |

**연결 검사**(`zec::rpc::chain_check`, 매 새로고침과 매 보내기 검토 직전): (1) `getblockhash [0]`이 위 상수와 같아야 하고, (2) `getblockchaininfo`의 `chain`이 같아야 하며, `headers`가 있으면 `headers ≤ blocks + 2`, `blocks ≤ 400,000,000`이어야 한다. 하나라도 어긋나면 그 응답을 버리고 오류를 보인다("RPC가 다른 네트워크를 가리킵니다…"). (3) `consensus.nextblock`(8자리 hex)과 `upgrades`(키 = branch id hex, `activationheight`)를 §4의 업그레이드 표와 대조한다.

### 2.2 키와 주소 (`zec::account`)

- 표준 경로: `m/44'/{133|1}'/{account}'/0/{index}`, 기본 `account = index = 0`(`bip32::path::zec_path`, `vault::KeyRef::Zec`). ZIP 316의 transparent 파생과 같은 경로라 Zashi·YWallet 등의 일반 주소(계정 0, 첫 주소)와 같다(ZIP 320 벡터로 경로 확인, §14).
- 공개키는 압축 33바이트만 쓰고 meta `zcash`(선택 최상위 키, §12.3)에 출처와 함께 캐시한다. 개인키는 서명 때만 `Vault::with_secp_key`로 빌려 쓰고, 빌린 키의 공개키가 캐시와 다르면 서명하지 않는다(`KeyMismatch`).
- EVM 계정과 같은 키: `m/44'/60'/0'/0/i`. 고르면 경고 T-ZEC-EVM-SHARED("EVM 주소와 이 Zcash 주소가 같은 공개키라 누구나 두 주소를 한 사람의 것으로 묶을 수 있습니다. 같은 복구 단어를 다른 Zcash 지갑에 넣어도 이 주소는 나오지 않습니다…")를 보이고 [정말 EVM 키 사용]을 한 번 더 눌러야 바뀐다. 기본은 표준 경로다.
- YubiKey: vault tag 5의 `KeyRole::Zec { network, index }` 슬롯(OpenPGP secp256k1, [10](10-yubikey.md))의 공개키를 계정으로 쓴다. 카드에 서명을 맡기는 규칙은 §8.2.
- 진행 중 거래(§12.1)가 있으면 키 출처·네트워크를 바꾸거나 Zcash를 끄지 않는다.

## 3. 받는 주소 파싱 (`zec::address::parse_recipient`)

순서: 앞뒤 공백 제거 → 빈 값 / 1,000자 초과·ASCII 아님 거부 → `zcash:` 접두는 거부 → `'1'` 앞의 HRP로 bech32 계열 판정, 아니면 Base58Check.

1. **Base58Check**: `zc`/`zt`로 시작하면 Sprout → `Shielded`. 체크섬, 22바이트(접두 2 + HASH160 20), 접두가 §2.1의 네 값 중 하나여야 한다. 다른 네트워크의 값이면 `WrongNetwork`.
2. **TEX (ZIP 320)**: bech32m, 체크섬 길이 제한 없이 디코드(`btc::bech32::decode_limited`), 5→8비트 변환 뒤 정확히 20바이트 → P2PKH. bech32(구 상수)면 체크섬 오류로 본다. TEX로 보낼 때는 일반 입력만 써야 하는데(ZIP 320) 이 지갑의 거래는 늘 일반 입력만 쓴다.
3. **UA (ZIP 316 R0)**: bech32m(길이 제한 없음) → 바이트 → **F4Jumble⁻¹**(§3.1) → 끝 16바이트가 HRP를 0으로 채운 값이어야 함 → `CompactSize typecode ‖ CompactSize length ‖ 값` 항목들. 규칙: typecode가 엄격히 증가(중복 없음), P2PKH(0x00, 20)·P2SH(0x01, 20)·Sapling(0x02, 43)·Orchard(0x03, 43) 길이 일치, P2PKH와 P2SH 동시 금지, 비공개 수신자(Sapling·Orchard·알 수 없는 0x04–0xBF·0xFD 이상 typecode) 최소 1개, 메타데이터 0xC0–0xDF는 건너뜀, MUST-understand 0xE0–0xFC는 `UnifiedUnsupported`. 일반 수신자가 없으면 `UnifiedNoTransparent` "이 통합 주소(UA)에는 일반(transparent) 수신자가 없습니다. 받는 사람에게 t 주소나 TEX 주소를 요청하세요."
4. Sapling HRP(`zs`, `ztestsapling`)와 R2 초안 `zu`/`zutest` → `Shielded`; R2 초안 `tu`/`tutest` → `UnifiedUnsupported`.

### 3.1 F4Jumble (`zec::f4jumble`)

ZIP 316 그대로: `ℓ_L = min(64, ⌊ℓ_M/2⌋)`, `ℓ_R = ℓ_M − ℓ_L`, `38 ≤ ℓ_M ≤ 4,194,368`. `H_i(u) = BLAKE2b-(8·ℓ_L)("UA_F4Jumble_H" ‖ [i,0,0], u)`, `G_i(u)` = `BLAKE2b-512("UA_F4Jumble_G" ‖ [i] ‖ LE16(j), u)`(j = 0, 1, …)를 이어 붙인 앞 `ℓ_R`바이트. 순방향: `x = b⊕G₀(a)`, `y = a⊕H₀(x)`, `d = x⊕G₁(y)`, `c = y⊕H₁(d)` → `c‖d`; 역방향은 그 반대 순서.

## 4. 데이터 원천과 네트워크 업그레이드

### 4.1 호출 (모두 `zcash:<net>` 엔드포인트)

| 용도 | 호출 | 해석 |
|---|---|---|
| 연결 검사 | `getblockhash [0]`, `getblockchaininfo []` | §2.1 |
| UTXO (`node`) | `getaddressutxos [{"addresses":[<우리 주소>]}]` (Zebra, zcashd는 `-insightexplorer`/`-lightwalletd`; QuickNode 문서에 있음) | 행 `{address, txid, outputIndex, script, satoshis, height}`; `address`가 우리 주소가 아니면 응답 전체 거부, `script`가 우리 P2PKH가 아니면 그 행만 건너뜀, `height > 0`만 확인됨. `-32601`이면 "주소 조회 미지원 — Blockbook으로 바꾸세요" |
| UTXO (`bb-rest`) | `GET <엔드포인트>/api/v2/utxo/<주소>` (QuickNode Blockbook REST 애드온 형식) | `{txid, vout, value(문자열), height?, coinbase?}`; `height` 0·없음은 미확인 |
| 상태 추적 | `getrawtransaction [<txid>, 1]` | `height > 0` → 채굴됨, `height` 없음·`-1` → 알려짐(mempool·곁가지), `-5` → 없음 |
| 전송 | `sendrawtransaction [<hex>]` | 결과가 우리 txid면 수락, `-27`(이미 체인에 있음)도 수락, `-25`/`-26` 거부, 그 밖은 결과 모름 |

응답은 모두 관측일 뿐이다: 금액·스크립트는 ZIP 244 `SIGHASH_ALL`이 서명에 묶으므로(§6) 인덱서가 금액이나 스크립트를 속이면 거래가 무효가 될 뿐 자금을 잃지 않는다. **그래서 Bitcoin §5와 달리 이전 거래 원본을 받아 검증하지 않는다.** 인덱서는 UTXO를 숨기거나(잔액이 적게 보임) 없는 UTXO를 지어낼 수 있다(무효 거래로 끝남). 주소 단위로만 묻고 다른 정보는 보내지 않는다. URL·토큰은 로그에 남기지 않는다(`net=zcash:<net>`만).

### 4.2 업그레이드 표 (`zec::upgrade::KNOWN_UPGRADES`)

| 이름 | branch id | mainnet 높이 | testnet 높이 | v5 | 기본 만료 간격 | 블록 간격 |
|---|---|---|---|---|---|---|
| NU5 | `0xC2D6D0B4` | 1,687,104 | 1,842,420 | 유효 | 40 | 75초 |
| NU6 | `0xC8E71055` | 2,726,400 | 2,976,000 | 유효 | 40 | 75초 |
| NU6.1 | `0x4DEC4DF0` | 3,146,400 | 3,536,500 | 유효 | 40 | 75초 |
| NU6.2 | `0x5437F330` | 3,364,600 | 4,052,000 | 유효 | 40 | 75초 |
| NU6.3 | `0x37A5165B` | 3,428,143 | 4,134,000 | 유효(v6 도입, ZIP 229) | 40 | 75초 |
| NU7 | `0x77190AD9` | 3,543,405 | 4,465,026 | 유효(ZIP 259: v5·v6 유효, v4 무효) | 120 | 25초 |

NU7 값은 Zebra `constants.rs`와 ZIP 259(상태 "Proposed")에서 왔고, mainnet 활성화는 블록 3,543,405의 v6 coinbase 헤더(`06000080 98b684d8 d90a1977`)로 확인했다(제3자 탐색기 자료, §16 #8). 그래서 표만 믿지 않고 **노드와 대조한다**(`upgrade::tx_consensus`):

1. 노드의 `consensus.nextblock`이 표에 있어야 한다(없으면 `UnknownBranch` "노드가 이 지갑이 모르는 네트워크 업그레이드(branch id …)를 알려 주었습니다. 지갑을 업데이트하기 전에는 보낼 수 없습니다.").
2. 그 업그레이드에서 v5가 유효해야 한다(`NotV5`).
3. 표가 이 네트워크의 활성화 높이를 알면, 다음 블록(`tip + 1`)에 대해 표가 기대하는 branch id가 노드 값과 같아야 한다(다르면 `BranchMismatch`, 서명 안 함).
4. 만료 높이 = `next + 그 업그레이드의 기본 만료 간격`(NU7부터 120 = 약 50분, 그 전 40). 다음 예정 업그레이드(노드 `upgrades`와 표에서 `next`보다 높은 활성화 높이 중 가장 작은 값)가 있으면 `활성화 − 1`로 낮춘다(zcashd와 같은 규칙). 그 결과가 `next + 4` 미만이면 거부(`UpgradeTooClose` "네트워크 업그레이드가 곧(블록 …) 활성화됩니다. 활성화된 뒤에 다시 보내세요."; zcashd `TX_EXPIRING_SOON_THRESHOLD = 3`보다 1 크게).
5. 서명하는 branch id는 이렇게 확인한 노드 값이다.

## 5. 거래 형식 (`zec::tx`)

v5(ZIP 225), 일반 부분만. 모든 정수는 little-endian:

| 필드 | 값 |
|---|---|
| `header` | `0x80000005` (`05 00 00 80`) |
| `nVersionGroupId` | `0x26A7270A` (`0a 27 a7 26`) |
| `nConsensusBranchId` | §4.2에서 확인한 값 |
| `lock_time` | 0 |
| `nExpiryHeight` | §4.2 |
| `tx_in_count`, `tx_in` | outpoint 36, `scriptSig`(서명 전 빈 값), `nSequence = 0xFFFFFFFF` |
| `tx_out_count`, `tx_out` | 값 8, `scriptPubKey` |
| `nSpendsSapling`, `nOutputsSapling`, `nActionsOrchard` | 각각 `00` (그 뒤 필드 없음) |

파서(`parse_tx`)는 이 모양만 받는다: 비공개 부분이 있거나 남는 바이트·최소가 아닌 CompactSize·`MAX_MONEY` 초과 값은 거부한다. txid는 ZIP 244 `txid_digest`(BLAKE2b-256, personalisation `"ZcashTxHash_" ‖ LE32(branch)`, 머리·일반·빈 Sapling·빈 Orchard 요약)이고, 화면·RPC는 바이트를 뒤집은 hex다.

## 6. 서명 해시 (`zec::sighash`, ZIP 244 §S.2)

`S = BLAKE2b-256("ZcashTxHash_" ‖ LE32(branch), header_digest ‖ transparent_sig_digest ‖ sapling_digest ‖ orchard_digest)`, `transparent_sig_digest = BLAKE2b-256("ZTxIdTranspaHash", 0x01 ‖ prevouts_digest ‖ amounts_sig_digest("ZTxTrAmountsHash") ‖ scriptpubkeys_sig_digest("ZTxTrScriptsHash") ‖ sequence_digest ‖ outputs_digest ‖ txin_sig_digest("Zcash___TxInHash": prevout ‖ value ‖ CompactSize+scriptPubKey ‖ nSequence))`. 빈 Sapling·Orchard 요약은 `BLAKE2b-256("ZTxIdSaplingHash", [])`, `BLAKE2b-256("ZTxIdOrchardHash", [])`.

### 6.1 BLAKE2b personalisation (`zec::blake2b`)

`blake2::Blake2bVarCore::new_with_params(salt = [], persona, key_size = 0, out_len)`와 crate의 lazy 블록 버퍼(`digest::core_api::Buffer`)로 구현한다(마지막 블록을 끝 표시와 함께 압축해야 하므로). 키가 빈 `Blake2bMac`은 쓰지 않는다. `blake2 =0.10.6`은 argon2 폐포로 이미 허용 목록에 있어 새 크레이트가 아니다([01](01-repo-build.md) §3.4; workspace에 직접 의존성 한 줄만 더함).

## 7. 거래 구성 (`zec::plan`)

### 7.1 입력 선택

후보 = 확인된(`height` 있음) 우리 주소 UTXO 중 coinbase 아님, 값 > 0, 중복 아님, **확정될 수 있는 저널 기록의 입력이 아님**(§12.2). 큰 값부터(같으면 outpoint 순) 고르며 최대 50개. 정확한 금액: 잔돈 출력을 넣은 수수료로 잔돈 ≥ `ZEC_DUST`이면 잔돈을 같은 주소로, 아니면 잔돈 없이 나머지를 수수료에 더한다. 보내기 최대: 모든 후보(50개 초과면 거부), 금액 = 합계 − 수수료.

### 7.2 수수료 (ZIP 317)

`logical_actions = max(⌈tx_in_total_size/150⌉, ⌈tx_out_total_size/34⌉)`, `fee = 5,000 × max(2, logical_actions)` zatoshi. 서명 전에는 입력마다 149바이트(카드 DER 72 + 1 포함 최대)로 계산하므로 실제 크기보다 작게 나오지 않는다. 서명 후 검증(§10.2)은 실제 크기의 ZIP 317 수수료 이상인지 다시 본다. 수수료 상한 `ZEC_FEE_ABS_CAP` 0.01 ZEC. ZIP 2009(상태 "Proposed")가 높이 3,590,000(mainnet)·4,465,026(testnet)부터 `marginal_fee`를 1,000으로 낮추려 하지만, 5,000을 내는 쪽은 그 뒤에도 유효(더 냄)이므로 phase 1은 5,000을 유지한다.

### 7.3 금액 규칙

받는 금액·잔돈 최소 `ZEC_DUST` = 1,000 zatoshi(zcashd·Zebra의 P2PKH 먼지 기준은 54 zatoshi; 보수적으로 크게 둠). 금액 입력은 소수 8자리 ZEC(`parse_user_zec`, BTC 금액 규칙 재사용).

## 8. 서명

### 8.1 소프트웨어 키 (`zec::sign::sign_plan`)

승인 토큰이 이 계획의 것(kind `ZecSend`, 체인 `Zcash{network, genesis}`, 계정 공개키, `zec_payload` 바이트 동일)인지, 계획이 자기 거래와 맞는지 확인한 뒤 입력마다 ZIP 244 digest를 계산하고, 빌린 키의 공개키가 계정 키와 같을 때만 RFC 6979 low-R·low-S ECDSA로 서명한다(Bitcoin `sign_sighash` 재사용, 즉시 검증). scriptSig = `<DER ‖ 0x01> <압축 공개키>`. zcashd 표준 정책은 `SCRIPT_VERIFY_LOW_S`·`STRICTENC`·엄격 DER을 요구한다(§16 #12).

### 8.2 YubiKey (`zec::sign::sign_plan_card`)

같은 승인·계획 검사 뒤 입력마다 카드가 32바이트 digest에 서명한다(`yubikey::sign::sign_btc_checked` 경로 재사용: low-S로 정규화하고 기록된 공개키로 검증한 DER). 카드 서명은 high-R을 허용하고 DER ≤ 72바이트, low-S, `SIGHASH_ALL` 바이트를 확인한다([10] §6.3과 같은 완화 규칙). PIN은 작업마다 한 번(모든 입력), 입력마다 터치.

## 9. 승인 표시 (`zec::display::build_zec_request`)

`ApprovalKind::ZecSend`(0x40), `ChainRef::Zcash{network, genesis}`(digest `chain_tag` 4), `AccountRef::Zcash(압축 공개키)`, `Signer::FromPayload`, `SigningPayload::Zec(zec_payload)`(transcript `"your-wallet/v3/zec-send"` v1: 네트워크, 키 출처, 공개키, 받는 사람 형식·스크립트·입력 문자열, 금액, 수수료, 잔돈, 보내기 최대, branch id, 만료 높이, 입력 값들, 서명 전 거래 바이트). 필드(모두 계획에서 만듦, 서버 문자열 없음):

| 키 | 내용 | 표시 |
|---|---|---|
| `0x0001` 요청 출처 | "Your Wallet 앱" | 펼침 |
| `0x0002` 네트워크 | `ZCASH MAINNET` / `ZCASH TESTNET — 가치 없음` | 펼침 |
| `0x0003` 계정 | 키 출처 · 경로 · 보내는 주소 | 펼침 |
| `0x0701` 받는 주소 | 일반 주소로 다시 인코딩한 값, TEX·UA면 "입력한 주소: …"도 | 펼침 |
| `0x0702` 주소 형식 | 일반(transparent) 주소 / TEX / UA의 일반 수신자 | 펼침 |
| `0x0703` 금액 | `x.xxxxxxxx ZEC (n zats)` | 펼침 |
| `0x0704` 잔돈 | 같은 주소로 돌아오는 금액, 또는 수수료에 더한 나머지 | 펼침 |
| `0x0705` 수수료 | 금액 + ZIP 317 기본 수수료(입력·출력 수) | 펼침 |
| `0x0706` 합계 | 금액 + 수수료 | 펼침 |
| `0x0707` 만료 | 만료 높이, 남은 블록·대략 분, 업그레이드 이름·branch id, 다음 업그레이드 높이 | 펼침 |
| `0x0708` 입력 | 개수·합계, "입력 금액과 스크립트는 서명(ZIP 244)에 포함" | 접힘 |
| `0x0740` 고급 | v5·nLockTime 0·sequence·SIGHASH_ALL·보내기 최대 여부 | 접힘 |

경고: Z05(정보) 일반 전송은 공개됨(항상), Z01(정보) 받는 주소가 내 주소, Z02(정보) TEX, Z03(주의) UA의 일반 수신자로 보냄, Z04(정보) 다음 업그레이드 때문에 만료를 앞당김. 승인 창 상단 요약은 "…에서 x ZEC를 아래 주소로 보냅니다."

## 10. 서명·검증·전송 순서

### 10.1 순서

1. [검토] → 새로고침(§2.1 연결 검사, UTXO, 추적)을 다시 한 결과로 계획한다.
2. 받는 주소 파싱 → 금액 → `tx_consensus` → `plan_send` → 승인 대기열.
3. 승인 → `consume` → key worker: 저널 검사(§12.2: 손상 ZEC 기록 없음, 이 계정의 확정될 수 있는 기록 없음, 공간) → 서명(§8) → **서명 후 검증**(§10.2) → `Signed` 기록 커밋. 쓰기에 실패하면 서명을 버린다(디스크에 실제로 써졌는지 다시 읽어 확인).
4. UI: `Disclose`(공개 표시) 커밋 → 그 뒤에만 `sendrawtransaction`.
5. 결과: 수락 → `Broadcast`; `-25`/`-26` → `Rejected`(공개됨: 만료까지 입력 예약); 결과 모름 → 상태 그대로, 다음 새로고침이 노드에 없으면 같은 바이트를 다시 보낸다.

### 10.2 서명 후 검증 (`zec::sign::verify_signed`, 모두 필수)

엄격 파싱 → scriptSig만 비운 거래가 계획의 거래와 동일 → 각 scriptSig가 `<sig> <우리 공개키>`이고 ZIP 244 digest에 대해 유효(소프트웨어: low-R·low-S·DER ≤ 70, 카드: low-S·DER ≤ 72) → 수수료가 계획과 같고, 서명된 크기의 ZIP 317 수수료 이상이며, 상한 이하. 통과해야 txid를 돌려준다.

## 11. 화면 (S10 Zcash 탭, [04](04-app-ui.md) §2.6)

탭 행 `EVM · Solana · Bitcoin · Zcash`(Ctrl+4). 꺼져 있으면 소개 카드와 [Zcash mainnet 켜기]·[Zcash testnet 켜기 (테스트)]. 켜져 있으면 한 화면에 차례로:

- 네트워크 배너(§2.1), ZEC 저널 손상 배너(E-VLT-006), 오류·정보 배너.
- 네트워크 카드: mainnet/testnet 선택, `RPC (zcash:<net>): 연결됨 (genesis 확인) · 블록 n · 업그레이드 NU7` 또는 "엔드포인트 없음 (E-KEY-005)…", UTXO 원천(`노드 getaddressutxos` / `Blockbook (/api/v2)`), [새로고침], [Zcash 끄기].
- 계정 카드: 키 출처·경로, 확인된 잔액(진행 중 거래의 입력 제외, 미확인 금액 별도), 키 출처 바꾸기(표준 / `EVM 계정 i과 같은 키` + T-ZEC-EVM-SHARED + 두 번 확인 / `YubiKey Zcash 주소 i 사용` 버튼은 등록된 슬롯이 있을 때).
- 받기 카드: 주소(4자 묶음), T-ZEC-RECEIVE, [주소 복사], [QR 보기](`zcash:` + 주소). 확인되지 않은 passphrase 세션(T-ALT-PASS)에서는 막는다.
- 보내기 카드: 받는 주소(t/TEX/UA), 금액(ZEC) 또는 [최대], [검토].
- 활동 카드: 이 지갑이 보낸 ZEC 기록(상태·금액·수수료·받는 주소·만료 높이·txid)과 받은 UTXO 목록(서버 기준).
- 체인 배지/로고: chain-logo 작업이 아직 main에 없어 `TODO(chain-logos)` 자리만 둔다.

## 12. 저널·meta

### 12.1 저널 상태 (`journal::zec`, entry `kind 4`)

| 상태 | 뜻 | 종결 |
|---|---|---|
| `Signed` (1) | 서명·기록됨, 아직 노드에 안 넘김(`disclosed` 표시가 있으면 넘겼을 수 있음) | 아니오 |
| `Broadcast` (2) | 노드가 수락(또는 응답 유실 후 mempool에서 봄) | 아니오 |
| `Confirmed` (3) | 블록 `mined_height`에 포함(확인 1 = 확정, D32) | 예 |
| `Expired` (4) | 팁 > `nExpiryHeight + 10`(재구성 여유)이고 채굴 안 됨: 더는 포함될 수 없음(ZIP 203) | 예 |
| `Rejected` (5) | 노드가 거부(`-25`/`-26`), 공개됨 → 만료까지 대기 | 아니오 |
| `Discarded` (6) | 한 번도 노드에 넘기지 않고 버림 | 예 |

본문(135바이트 머리 + 서명된 거래): kind 0x04, version 1, 상태, 네트워크, 키 출처(코드·a·b), 공개키 33, 승인 id 16, 승인 digest 32, 서명 시각, `disclosed`, `mined_height`, `not_found`, 금액, 수수료, 입력 합계, 거래 길이, 거래. 읽을 때 모든 scriptSig 끝 공개키가 기록의 키인지, 첫 출력 = 금액, 출력 합 + 수수료 = 입력 합계인지 확인한다(다르면 "저널 손상": ZEC 보내기만 멈추고 바이트는 보존). 종결 기록은 64개까지 두고 오래된 것부터 지운다.

**형식 호환.** 이전 버전의 저널 디코더는 모르는 `kind`를 손상(`SidecarCorrupt(Journal)`)으로 본다. ZEC를 한 번이라도 보낸 뒤 이전 버전으로 되돌리면 저널을 열지 못하므로 새 버전을 다시 설치해야 한다(vault tag 확장과 같은 안내, [04] §6.6 표에 행 추가).

### 12.2 진행 중 규칙과 공개 거래 규칙

- **한 번에 하나(D20과 같음).** 같은 네트워크·같은 공개키의 기록 중 종결이 아닌 것(`Signed`·`Broadcast`·`Rejected`)이 있으면 새 서명을 거부한다(`InFlight` "이 계정의 이전 Zcash 거래가 아직 확인되지 않았습니다. 확인되거나 만료된 뒤에 다시 보내세요."). 화면도 같은 이유로 [검토]를 막는다.
- **공개 거래 충돌.** 종결이 아닌 기록의 입력은 모든 계획에서 제외한다(`reserved_inputs`). Bitcoin처럼 "포기" 동작이 없는 대신, 만료 높이가 지나면(§12.1 `Expired`) 그 거래는 다시는 채굴될 수 없으므로 그때 입력이 풀린다.
- **추적**(새로고침마다, 탭이 열려 있거나 진행 중 기록이 있으면 30초마다): 채굴됨 → `Mined`; 알려짐 → `Signed`면 `Broadcast`; 없음 → `Broadcast`면 `not_found + 1`, 만료 전이면 같은 바이트를 다시 보냄(공개 표시 먼저); 팁 > 만료 + 10이고 채굴 안 됨 → `Expired`.

### 12.3 meta `zcash` (선택 최상위 키)

`{"mainnet": {"source": 1|2|3, "a": u32, "b": u32, "pubkey": "02…"}, "testnet": {…}}` — 네트워크마다 계정 하나(키 출처 코드 1 표준(a = account, b = index) / 2 EVM 키(a = EVM index) / 3 YubiKey(a = index), 압축 공개키). 비어 있으면 쓰지 않는다. 항목이 잘못되면 그 네트워크 계정만 버리고 잠금 해제 때 표준 경로로 다시 만든다. 이전 버전은 모르는 키로 보존한다. `prefs.tab = "zec"`은 이전 버전에서 `prefs` 전체를 기본값으로 되돌린다(무해). ZEC 활동은 meta `activity`에 넣지 않는다(이전 버전이 `zcash:` 네트워크 키를 거부해 meta 전체를 버리기 때문).

## 13. 오류 문구 (고정, 원격 문자열 없음)

주소: §3의 `ZecAddressError::text`. 계획: "보낼 금액이 올바르지 않습니다 (최소 0.00001000 ZEC).", "확인된 잔액이 부족합니다: 필요 … (수수료 포함), 사용 가능 ….", "입력이 50개를 넘어야 해서 한 번에 보낼 수 없습니다…", "수수료가 상한을 넘습니다.", "보낼 수 있는 확인된 잔액이 없습니다." 업그레이드: §4.2. 서명: "승인 내용과 서명할 거래가 다릅니다.", "서명 키가 이 Zcash 계정의 키와 다릅니다…", "Zcash 거래 서명 검증에 실패해 폐기했습니다.", "거래 저널을 쓰지 못해 서명을 버렸습니다. 아무것도 보내지 않았습니다." RPC: "RPC가 다른 네트워크를 가리킵니다 (Zcash genesis 또는 chain 불일치).", "Zcash 노드가 동기화 중이거나…", "이 Zcash 엔드포인트는 주소 조회(getaddressutxos)를 지원하지 않습니다…", 전송 거부 "Zcash 노드가 거래를 거부했습니다 (코드 n). 만료 높이가 지나면 입력이 풀립니다."

## 14. 테스트

### 14.1 자동 (공식 벡터 + 목 E2E, `cargo test`)

| 테스트 | 내용 |
|---|---|
| `zec::blake2b::tests` | RFC 7693 BLAKE2b-512("abc"), 블록 경계 증분 = 한 번에 |
| `zec::tests::f4jumble_official_vectors` | zcash-test-vectors `f4jumble.json` 8개(ℓ_M 48–16,449) 순·역방향 |
| `zec::tests::unified_address_official_vectors` | `unified_address.json` 60개: 일반 수신자 추출 또는 `UnifiedNoTransparent`, 모든 항목 존재, 다른 네트워크 거부 |
| `zec::tests::tex_official_vectors_and_bip44_path` | `zip_0320.json` 15개: t 주소 ↔ HASH160 ↔ TEX 왕복 |
| `zec::tests::zip244_official_vectors` | `zip_0244.json` 10개: txid 10개 전부, `sighash_all` 있는 행 전부(테스트 전용 v5 파서가 Sapling·Orchard 요약을 계산) |
| `zec::tests::mocked_end_to_end_send` | abandon 니모닉 vault → `m/44'/1'/0'/0/0`(개인 파생과 교차 확인) → TEX 받는 사람 → 계획 → 승인 발행·소비(두 번째 소비 거부) → vault 서명 → 서명 후 검증(1바이트 변조 거부) → 저널 `Signed`·진행 중 차단·입력 예약·`Broadcast`·공개 기록 폐기 거부·`Confirmed` |
| `zec::tests::{recipient_policy, planning_rules, consensus_table_and_expiry, transparent_v5_round_trip_and_strict_parse}`, `zec::fee::tests` | 주소 정책, 선택·먼지·예약 입력·coinbase·미확인, 업그레이드 대조·만료 상한·거부, v5 왕복·비공개 부분 거부, ZIP 317 예 |
| `crates/yw-app/tests/zec_app.rs` | `getblockchaininfo`·`getaddressutxos`·Blockbook·`getrawtransaction` 해석, settings `zcash` 왕복, meta `zcash` 왕복 |

벡터 파일은 `crates/yw-core/tests/vectors/zec/`에 원본 그대로 두고 출처는 `tests/vectors/SOURCES.md`.

### 14.2 수용 체크리스트 (testnet, 수동 1회)

1. `scripts/dev-rpc-setup.ps1`에 `zcash:testnet` 추가 → `node scripts/probe-rpc.mjs`가 `getblockhash 0`(testnet 제네시스), `getblockchaininfo`(`nextblock` = `77190ad9`), `getaddressutxos` 지원을 보고한다(-32601이면 UTXO 원천을 Blockbook으로).
2. 앱: 설정 > RPC에 `zcash:testnet` URL → [테스트] "genesis 일치".
3. Zcash 탭 → [Zcash testnet 켜기] → 주소가 `tm…`이고, 같은 복구 단어를 Zashi(testnet)·YWallet에 넣었을 때의 일반 주소(계정 0, 첫 주소)와 같다.
4. testnet faucet에서 받기 → 새로고침에 미확인, 1확인 뒤 확인된 잔액.
5. 다른 `tm…` 주소로 소액 보내기: 승인 창에 네트워크·보내는 주소·받는 주소·형식·금액·수수료(10,000 zats)·만료 높이(다음 블록 + 120)·업그레이드 NU7이 보이고, 승인 후 txid가 탐색기·노드에서 보이며 1확인에 `확인됨`.
6. TEX(`textest1…`)와 일반 수신자가 있는 `utest1…`로 각각 보내기(Z02·Z03 표시), 일반 수신자 없는 UA·`ztestsapling…`는 거부 문구.
7. 보내기 직후 두 번째 보내기는 "이전 Zcash 거래가 아직 확인되지 않았습니다"로 막힌다.
8. 보낸 직후 앱 강제 종료 → 다시 열어 잠금 해제 → 같은 txid로 추적이 이어진다(노드에 없으면 같은 바이트 재전송).
9. [최대]: 잔액 − 수수료 전부, 잔돈 출력 없음.
10. (선택) `EVM 계정과 같은 키`: 경고와 두 번 확인 뒤 주소가 EVM 키의 HASH160 주소로 바뀌고, 진행 중 거래가 있으면 바뀌지 않는다.
11. (선택, YubiKey) [10](10-yubikey.md)의 Zcash 슬롯 등록 → `YubiKey Zcash 주소 0 사용` → 보내기 때 PIN 1회 + 입력마다 터치, 서명 후 검증 통과.

## 15. 상수 (`yw_core::zec`)

`ZEC_DUST` 1,000 · `ZEC_MAX_INPUTS` 50 · `ZEC_FEE_ABS_CAP` 1,000,000 · `ZEC_SEQUENCE` `0xFFFFFFFF` · `ZEC_MIN_CONF` 1 · `ZEC_POLL_SECS` 30 · `ZEC_MAX_UTXOS` 1,000 · `ZEC_EXPIRED_AFTER` 10 · `ZEC_JOURNAL_FINAL_KEEP` 64 · `ZEC_MAX_JOURNAL_RAW` 32,768 · `upgrade::ZEC_EXPIRY_DELTA_PRE_NU7` 40 · `ZEC_EXPIRY_DELTA_NU7` 120 · `ZEC_MIN_EXPIRY_BLOCKS` 4 · `fee::MARGINAL_FEE` 5,000 · `GRACE_ACTIONS` 2 · `P2PKH_STANDARD_INPUT_SIZE` 150 · `P2PKH_STANDARD_OUTPUT_SIZE` 34 · `f4jumble::MIN_LEN` 38 · `MAX_LEN` 4,194,368.

## 16. 확인한 사실과 출처 (2026-11-06)

정본은 `https://zips.z.cash/zip-XXXX`(원문 `github.com/zcash/zips`), 노드는 zcashd `src/chainparams.cpp`·`main.cpp`·`policy/policy.h`, Zebra `zebra-chain`·`zebra-rpc`.

| # | 사실 | 값 | 출처 |
|---|---|---|---|
| 1 | 일반 주소 Base58Check 접두 | t1 `1CB8`, t3 `1CBD`, tm `1D25`, t2 `1CBA` | zcashd `chainparams.cpp` (base58Prefixes), ZIP 320 |
| 2 | WIF 접두 | mainnet `0x80`, testnet `0xEF`, 압축 `0x01` 꼬리 | zcashd `chainparams.cpp` `SECRET_KEY`, `key_io.cpp` |
| 3 | TEX | bech32m, HRP `tex`/`textest`, 20바이트 P2PKH, 일반 입력만 | https://zips.z.cash/zip-0320 (Active) |
| 4 | UA | R0 HRP `u`/`utest`, F4Jumble, 16바이트 HRP 채움, typecode 오름차순, 비공개 수신자 1개 이상, 메타데이터 0xC0–0xFC(0xE0–0xFC MUST-understand), `38 ≤ ℓ_M ≤ 4,194,368`; R1 철회, R2 초안 `zu`/`tu` | https://zips.z.cash/zip-0316 |
| 5 | v5 형식 | `0x80000005`, `0x26A7270A`, 빈 Sapling·Orchard 카운트 `00 00 00` | https://zips.z.cash/zip-0225 |
| 6 | 서명 해시·txid | §5·§6의 personalisation과 순서, 빈 요약 | https://zips.z.cash/zip-0244 |
| 7 | 수수료 | 5,000 × max(2, actions), 150/34바이트; ZIP 2009 인하 제안(Proposed) | https://zips.z.cash/zip-0317, https://zips.z.cash/zip-2009 |
| 8 | 업그레이드 | §4.2 표 | ZIP 252(NU5), 253(NU6), 255(NU6.1), 257(NU6.2), 258(NU6.3), 259(NU7, Proposed), 229(v6), 2003(v4 무효), Zebra `zebra-chain/src/parameters/network_upgrade.rs`·`constants.rs`; NU7 mainnet 활성화 블록 헤더는 제3자 탐색기(Blockchair) 자료 |
| 9 | 만료 | 기본 간격 20(Blossom 전) / 40(Blossom 후) / 120(NU7부터), 업그레이드 전 활성화 − 1로 제한, `TX_EXPIRING_SOON_THRESHOLD` 3 | https://zips.z.cash/zip-0203, zcashd `main.cpp`, https://zips.z.cash/zip-0218 |
| 10 | 블록 간격 | 75초 → NU7부터 25초 | ZIP 218, Zebra `POST_NU7_POW_TARGET_SPACING` |
| 11 | 먼지 | P2PKH 54 zatoshi (`ONE_THIRD_DUST_THRESHOLD_RATE` 100) | zcashd `primitives/transaction.cpp`, Zebra mempool |
| 12 | 서명 정책 | `SCRIPT_VERIFY_LOW_S`, `STRICTENC`, 엄격 DER | zcashd `policy/policy.h` |
| 13 | 제네시스 | §2.1 | zcashd `chainparams.cpp` |
| 14 | `chain` | `main` / `test` | zcashd, Zebra |
| 15 | RPC | Zebra `getaddressutxos`(`address, txid, outputIndex, script, satoshis, height`), `getrawtransaction` verbose(mempool은 `height` 없음, 곁가지 −1, 없음 −5); QuickNode Zcash 문서의 `getaddressutxos`·`getaddressbalance`, 예시 호스트 `docs-demo.zec-mainnet.quiknode.pro`, Blockbook REST 애드온 | Zebra `zebra-rpc/src/methods.rs`, https://www.quicknode.com/docs/zcash/getaddressutxos, https://www.quicknode.com/docs/zcash/api-overview |
| 16 | Blockbook | `/api/v2/utxo/<주소>`(`txid, vout, value, height, confirmations, coinbase?`) | trezor/blockbook `openapi.yaml` |
| 17 | coin type | 133, testnet 1; 일반 파생 `m/44'/133'/account'/0/index` | SLIP-44, ZIP 32, ZIP 316 |

확인하지 못한 것: QuickNode testnet 서브도메인(`zec-testnet`은 추정), Blockbook Zcash 파서의 v6 지원(이 지갑은 v5만 만들므로 영향 없음).

## 미결 사항

- 가져온 개인키(WIF): vault tag 추가와 형식 호환 정책을 정한 뒤 phase 2.
- 비공개 거래(Orchard 보내기, UA 비공개 수신자 우선): 범위 밖(D35). 하려면 증명 생성 라이브러리가 필요해 의존성 정책([01] §3.4)부터 다시 정해야 한다.
- ZIP 2009 수수료 인하가 확정되면 `MARGINAL_FEE`를 업그레이드 표처럼 높이별로 바꾼다.
- 새 네트워크 업그레이드(branch id)가 나오면 §4.2 표를 갱신하는 릴리스가 필요하다(그 전에는 `UnknownBranch`로 보내기를 막는다).
