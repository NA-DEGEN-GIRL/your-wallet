# Zcash 일반(transparent) 전송 전용

상위 문서: [spec.md](../spec.md)

D36의 세부 명세다. 방식은 Bitcoin([08](08-bitcoin.md))과 같다: 받기·보내기는 yw-app 화면(Zcash 탭)에서만 하고 dApp 연결은 없다. 비공개(shielded: Sapling·Orchard) 거래는 범위 밖이다. 코드는 `yw_core::zec`(코어)와 `crates/yw-app/src/{app_zec.rs, zec/, ui/screens_zec.rs, workers/journal_zec.rs}`(앱)이다. 확인한 사실과 출처는 §16에 모은다(2026-11-06 확인).

## 1. 범위

### 1.1 포함

| 항목 | 규칙 |
|---|---|
| 받기 | 계정 하나 = 고정 P2PKH 주소 하나(Bitcoin 고정 주소 방식, D29). 기본 키는 니모닉의 `m/44'/133'/0'/0/0`(testnet `m/44'/1'/0'/0/0`, §2.2). 받기 화면에 T-ZEC-RECEIVE "일반(transparent) 주소입니다 — Zashi 등 비공개 주소로 받으려면 그 지갑에서 받으세요." |
| 보내기 대상 | `t1…`/`t3…`(testnet `tm…`/`t2…`) Base58Check, ZIP 320 TEX(`tex1…`/`textest1…`, P2PKH), ZIP 316 revision 0 통합 주소(`u1…`/`utest1…`)의 일반 수신자(P2PKH 또는 P2SH) |
| 보내기 거부 | Sapling `zs…`/`ztestsapling…`, Sprout `zc…`/`zt…`, 일반 수신자가 없는 UA, ZIP 316 revision 2 초안 형식(`tu…`, `zu…`), MUST-understand 메타데이터(0xE0–0xFC)가 있는 UA, 다른 네트워크·다른 코인 주소, `zcash:` URI |
| 키 출처 | (1) 표준 경로(기본) (2) `EVM 계정과 같은 키`(명시적 선택 + 확인, 연결성 경고 T-ZEC-EVM-SHARED) (3) YubiKey OpenPGP secp256k1 슬롯([10](10-yubikey.md) `KeyRole::Zec`, 복구 단어 없이 연결한 카드의 "경로 모름" 슬롯 포함 §7.6) (4) 가져온 개인키(WIF, 2026-11-07, §2.3) (5) 추가한 복구 단어의 표준 경로(2026-11-08, §2.4) |
| 거래 형태 | v5(ZIP 225) 일반 입력·출력만, 수신자 1명 + 잔돈 0–1개(잔돈은 같은 주소), 보내기 최대, `SIGHASH_ALL`만 |
| 데이터 원천 | 네트워크마다 `zcash:<net>` 엔드포인트 하나(D13, 현재 QuickNode). UTXO는 `zcash.indexer`로 고른다: `node`(기본, 같은 엔드포인트의 `getaddressutxos`) 또는 `bb-rest`(같은 엔드포인트의 Blockbook REST `/api/v2/utxo/<주소>`) |

### 1.2 제외 (phase 1)

비공개 거래 전부(Sapling·Orchard 출력·입력, 비공개 주소로 받기), dApp 연결·메시지 서명, 여러 수신자, 메모, ZIP 321 결제 URI 해석, RBF(Zcash에 없음), v6 거래(ZIP 229) 작성. (가져온 개인키(WIF)는 phase 2로 2026-11-07 넣었다: §2.3.)

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
- YubiKey 계정 대조(2026-11-07): 카드 기록(vault tag 5)을 읽을 때마다(잠금 해제 후 meta 적재, 등록·슬롯 바꾸기·비우기 뒤) meta `zcash`의 YubiKey 계정을 대조한다 — 같은 네트워크·index의 `KeyRole::Zec` 슬롯이 같은 공개키로 있어야 한다. 없으면 meta는 그대로 두고 받기 카드를 숨기며 보내기를 막고 위험 띠("…YubiKey 키를 찾을 수 없습니다… 키 출처를 '표준'으로 바꾸세요(다른 주소가 됩니다)")를 보인다. 표준 경로로 바꾸는 것은 사용자가 고를 때만. 카드 기록을 아직 못 읽었으면 받기·보내기는 기다린다. YubiKey 비우기·슬롯 바꾸기 확인 화면은 `App::zec_accounts_using_card(serial, slots)`(그 카드의 그 슬롯만 가진 Zcash 계정)로 쓰기 전에 위험 띠를 보인다(2026-11-07, [10] §15).
- 진행 중 거래(§12.1)가 있으면 키 출처(YubiKey 슬롯 선택 포함)·네트워크를 바꾸거나 Zcash를 끄지 않는다.

### 2.3 가져온 개인키 (WIF, phase 2, 2026-11-07)

- 입력(W07, Zcash 탭 `개인키 가져오기`, `ImportSpec::Zec(탭의 네트워크)`): **압축 WIF**(`0x80` 메인넷 `K…`/`L…`, `0xEF` 테스트넷 `c…`, 52자, 끝 `0x01`) 또는 **16진수 64자리**(`0x` 선택, 대소문자, 탭의 네트워크로 씀). 압축하지 않은 WIF(`5…`/`9…`)는 받지 않는다(계정은 압축 공개키 하나). WIF 버전이 탭의 네트워크와 다르면 `ZecKeyNetwork`(E-INP-026), 그 밖 형식 오류는 `ZecKeyFormat`(E-INP-025). 주소는 P2PKH 하나(`t1…`/`tm…`).
- 저장: vault tag 6 `ZecKey`([02] §4.6: secret ‖ network). 체인당 15개(`RecordLimit`), 같은 (secret, network) 거부(`DuplicateKey`), 이 지갑이 이미 Zcash 주소로 쓰는 키도 거부(`DuplicateKey`): YubiKey 슬롯의 공개키, 니모닉의 표준 키 `m/44'/{133|1}'/0'/0/0`(vault), meta `zcash`의 현재 계정 공개키(키 작업자). 같은 secret의 다른 네트워크 키는 다른 계정이라 허용한다. 이전 버전은 tag 6을 모르는 tag로 보고 `UnsupportedPayload`(E-VLT-014)로 멈춘다(손상 아님, `.prev` 제안 없음).
- 계정: 키 출처 `ZecKeySource::Imported`(저장 코드 4, a = b = 0, 경로 문구 "가져온 개인키 (복구 단어 밖)", 이름 "가져온 키"). 서명은 vault가 tag 6에서 그 네트워크·공개키의 record를 찾아 빌려 준다(`KeyRef::ZecImported`), 나머지(§8.1·§10)는 같다.
- 화면(계정 카드, §11): 그 네트워크의 가져온 키마다 `[가져온 키] {주소}` 줄과 `이 키 사용`(쓰는 중이면 `사용 중`), 계정이 가져온 키면 백업 도움말과 `개인키 보기`(T-REVEAL-WARN → W03 → W09 압축 WIF, 캡처 제외)·`삭제`(내보내기 먼저 T-REMOVE-IMPORTED → W03), 끝에 `개인키 가져오기`. 가져오면 탭의 네트워크이고 진행 중 거래가 없을 때 그 네트워크의 계정이 된다.
- 삭제: 그 키의 계정에 종결되지 않은 기록(§12.1)이 있으면 거부한다("진행 중인 Zcash 거래가 이 키를 쓰고 있어…"). 지우면 그 키를 쓰던 네트워크의 meta `zcash` 계정을 비우고 표준 경로로 다시 만든다; 잠금 해제 때 tag 6에 없는 가져온 키 계정도 같은 처리(meta 대조).
- 시험: `vault::tests::zcash_wif_import_reveal_sign_and_refusals`(secret 1의 압축 WIF·주소를 독립 계산한 벡터 `KwDiBf89…`→`t1UYsZVJkLPeMjxEtACvSxfWuNmddpWfxzs`, `cMahea7z…`→`tmLPctKo9j49rtCSKpwEBpLBeykiTGomGQs`, hex 입력, 다른 네트워크·압축 안 함·체크섬·0·주소 거부, 중복·표준 키 충돌·15개 상한, 재잠금 뒤 목록·서명 키·WIF 보기·삭제, tag 6 바이트), `unknown_path_card_vault_accounts_and_zcash_collision`(카드 키 충돌 거부).

### 2.4 추가한 복구 단어의 표준 경로 (2026-11-08, D37, [02] §8.6)

- 출처 `ZecKeySource::Mnemonic { mnemonic, account, index }`(저장 코드 5, `(a, b) = (account, index)`; 앱은 `0, 0`만 만든다): 추가한 니모닉 `mnemonic`의 `m/44'/{133|1}'/{a}'/0/{b}`. 공개키는 `Vault::zec_public_key_of(Some(id), …)`, 서명 키는 `KeyRef::Zec { mnemonic: Some(id), … }`(그 니모닉의 백업 확인 전이면 `BackupNotConfirmed`).
- 화면(§11 계정 카드): `추가한 복구 단어` 줄의 `{니모닉 라벨} 표준 경로 사용`. 키 출처 줄 `[니모닉 2] Zcash 표준 경로 · m/44'/133'/0'/0/0`, 승인 창 계정 필드는 `Zcash 표준 경로 (추가한 복구 단어)`. 진행 중 거래가 있으면 바꾸지 않는다(§2.2).
- 승인 transcript(§9)와 저널(§12.1 버전 2)이 record id를 묶는다. meta는 §12.3(`zcash`가 아닌 `mnemonic_accounts.zec`). 그 니모닉을 지우면(진행 중 기록이 있으면 거부) 그 네트워크 계정은 잠금 해제 맞춤에서 표준 경로로 다시 만든다.
- 가져온 키 중복 거부(§2.3)는 모든 니모닉의 표준 키 `m/44'/{coin}'/0'/0/0`과 비교한다.

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
| UTXO (`node`) | `getaddressutxos [{"addresses":[<우리 주소>]}]` (Zebra, zcashd는 `-insightexplorer`/`-lightwalletd`; QuickNode 문서에 있음) | 행 `{address, txid, outputIndex, script, satoshis, height}`; `address`가 우리 주소가 아니면 응답 전체 거부, `script`가 우리 P2PKH가 아니면 그 행만 건너뜀, `height > 0`만 확인됨, `coinbase: true`가 있으면 coinbase로 표시(선택 제외). `-32601`이면 "주소 조회 미지원 — Blockbook으로 바꾸세요" |
| UTXO (`bb-rest`) | `GET <엔드포인트>/api/v2/utxo/<주소>` (QuickNode Blockbook REST 애드온 형식) | `{txid, vout, value(문자열), height?, coinbase?}`; `height` 0·없음은 미확인 |
| 상태 추적 | `getrawtransaction [<txid>, 1]` | `height > 0` → 채굴됨, `height` 없음·`-1` → 알려짐(mempool·곁가지), `-5` → 없음 |
| 받은 내역 확정분(opt-in, `node`) | `getaddressdeltas [{"addresses":[<우리 주소>],"start":h,"end":tip}]` | §11 받은 내역. 4 MiB 상한 |
| 받은 내역 멤풀 목록(opt-in, `node`, 2026-11-13) | `getrawmempool []` | 문자열 배열, 원소마다 hex 64(소문자로; 나머지는 버림, 중복 무시). 512 KiB 상한, 5,000개 초과·상한 초과면 이번 읽기는 찾지 않음. **주소를 보내지 않는다** |
| 받은 내역 멤풀 거래(opt-in, `node`·`bb-rest`, 2026-11-13) | `getrawtransaction [<txid>, 1]`(새 txid만, 읽기마다 최대 30) | 1 MiB 상한. `txid` 반향이 있으면 같아야 함, `vout[].valueZat`(≤ `MAX_MONEY`)·`scriptPubKey.hex`(짝수 hex ≤ 20,000자)와 `vin[].txid`·`vin[].vout`(`coinbase`는 건너뜀)을 먼저, 없는 쪽은 `hex`를 `zec::tx::transparent_parts`(v4·v5만)로 읽음. 우리 P2PKH로 가는 출력의 합 = 입금. 입력이 우리 아는 출력을 쓰거나 입력의 `scriptSig`가 우리 공개키(HASH160이 우리 P2PKH 해시인 33·65바이트 푸시)를 넣으면 우리 송금(입금 아님 — 이 지갑이든 같은 키를 가진 다른 지갑이든; verbose `vin[].scriptSig.hex`(≤ 20,000자)가 없으면 `hex`로 읽는다. 2026-11-13 리뷰 전에는 스냅숏 UTXO와만 비교해 먼지·미확정·한도 밖 출력이나 UTXO 조회 실패 때의 우리 송금 잔돈이 입금으로 보일 수 있었다), 입력이나 출력을 못 읽으면 `unreadable`(행 없음). 429·`-32005`·2xx 밖 HTTP·전송 실패면 그 읽기의 나머지 호출을 하지 않는다(그 전에는 30개까지 계속 보냈다) |
| 전송 | `sendrawtransaction [<hex>]` | 결과가 우리 txid면 수락, `-27`(이미 체인에 있음)도 수락, `-25`/`-26` 거부, 그 밖은 결과 모름 |

응답은 모두 관측일 뿐이다: 금액·스크립트는 ZIP 244 `SIGHASH_ALL`이 서명에 묶으므로(§6) 인덱서가 금액이나 스크립트를 속이면 거래가 무효가 될 뿐 자금을 잃지 않는다. **그래서 Bitcoin §5와 달리 이전 거래 원본을 받아 검증하지 않는다.** 인덱서는 UTXO를 숨기거나(잔액이 적게 보임) 없는 UTXO를 지어낼 수 있다(무효 거래로 끝남). 주소 단위로만 묻고 다른 정보는 보내지 않는다. URL·토큰은 로그에 남기지 않는다(`net=zcash:<net>`만).

**먼지 공격 대비(2026-11-07, §4.3).** 누구나 우리 주소로 아주 작은 출력을 많이 보낼 수 있으므로 행 수로 응답을 거부하지 않는다(응답 크기·JSON 한도만). `ZEC_MIN_UTXO`(= max(`ZEC_DUST`, 입력 하나의 marginal fee 5,000) zats) 이하 출력은 버리고, 나머지를 큰 값부터(같으면 outpoint 순) `ZEC_MAX_UTXOS`개만 남긴다; 버린 수는 활동 카드에 적는다. UTXO 조회와 상태 추적은 서로 독립이다: UTXO 조회가 실패해도(오류 문구 표시, 보내기 불가) 같은 새로고침의 `getrawtransaction` 결과로 저널 전이는 계속된다(연결 검사 실패만 새로고침 전체 실패).

**한도 초과(2026-11-08).** 먼지가 많아 `getaddressutxos`·Blockbook `utxo/` 답이 4 MiB나 JSON 노드·항목 한도를 넘으면(`ZecRpcError::TooMany`; Blockbook `utxo/`에는 페이지 나누기가 없어 대체 조회는 없다) "UTXO가 너무 많아 일부만 표시합니다 …"를 보이고, 이미 알던 출력(지난 답의 출력과 채굴된 우리 거래의 잔돈 — 한도 초과 중에 받은 잔돈은 목록에 다시 나오지 않는다 — 에서 우리 기록이 쓴 입력(`Confirmed`·`InputsSpent`·종결 아님)을 빼고 큰 것부터 최대 `ZEC_MAX_INPUTS`개, `journal::zec::over_limit_known`)과 감시 입력(§12.2)을 `gettxout <txid> <n> true`로 하나씩 묻는다(객체 = 미사용, `null` = 사용됨·없음). 아직 미사용인 아는 출력만 표시하고 그것으로 보낼 수 있다(계획은 `TooMany`를 막지 않는다). 노드에 `gettxout`이 없으면(`-32601`) 아는 출력을 그대로 두고(우리 거래가 쓴 출력은 위에서 이미 뺐다; 다른 곳에서 쓰인 출력이면 노드가 서명한 거래를 거부할 뿐) 감시 입력은 "알 수 없음"(`watch_unknowable`)으로 표시한다. 그 밖의 `gettxout` 실패는 이번 새로고침에 출력 없음·감시 미확인으로 다음 새로고침을 기다린다.

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

후보 = 확인된(`height` 있음) 우리 주소 UTXO 중 coinbase 아님, 값 > `ZEC_MIN_UTXO`(먼지 제외), 중복 아님, **확정될 수 있는 저널 기록의 입력이 아님**(§12.2). 큰 값부터(같으면 outpoint 순) 고르며 최대 50개. 정확한 금액: 잔돈 출력을 넣은 수수료로 잔돈 ≥ `ZEC_DUST`이면 잔돈을 같은 주소로, 아니면 잔돈 없이 나머지를 수수료에 더한다. 보내기 최대: 후보 중 가장 큰 50개(넘는 후보는 남기고 승인 창 입력 필드에 "가장 큰 입력 50개만 — 나머지 n개는 남습니다"), 금액 = 그 합계 − 수수료.

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

`ApprovalKind::ZecSend`(0x50; 0x40은 HyperCore), `ChainRef::Zcash{network, genesis}`(digest `chain_tag` 5; 4는 HyperCore), `AccountRef::Zcash(압축 공개키)`, `Signer::FromPayload`, `SigningPayload::Zec(zec_payload)`(transcript `"your-wallet/v3/zec-send"` v1: 네트워크, 키 출처(코드·a·b, 코드 5면 그 뒤 니모닉 record id `push_bytes` 16 — 다른 코드의 바이트는 그대로), 공개키, 받는 사람 형식·스크립트·입력 문자열, 금액, 수수료, 잔돈, 보내기 최대, branch id, 만료 높이, 입력 값들, 서명 전 거래 바이트). 필드(모두 계획에서 만듦, 서버 문자열 없음):

| 키 | 내용 | 표시 |
|---|---|---|
| `0x0001` 요청 출처 | "Your Wallet 앱" | 펼침 |
| `0x0002` 네트워크 | `ZCASH MAINNET` / `ZCASH TESTNET — 가치 없음` | 펼침 |
| `0x0003` 계정 | 키 출처 · 경로 · 보내는 주소 | 펼침 |
| `0x0801` 받는 주소 | 일반 주소로 다시 인코딩한 값, TEX·UA면 "입력한 주소: …"도 | 펼침 |
| `0x0802` 주소 형식 | 일반(transparent) 주소 / TEX / UA의 일반 수신자 | 펼침 |
| `0x0803` 금액 | `x.xxxxxxxx ZEC (n zats)` | 펼침 |
| `0x0804` 잔돈 | 같은 주소로 돌아오는 금액, 또는 수수료에 더한 나머지 | 펼침 |
| `0x0805` 수수료 | 금액 + ZIP 317 기본 수수료(입력·출력 수) | 펼침 |
| `0x0806` 합계 | 금액 + 수수료 | 펼침 |
| `0x0807` 만료 | 만료 높이, 남은 블록·대략 분, 업그레이드 이름·branch id, 다음 업그레이드 높이 | 펼침 |
| `0x0808` 입력 | 개수·합계, "입력 금액과 스크립트는 서명(ZIP 244)에 포함" | 접힘 |
| `0x0840` 고급 | v5·nLockTime 0·sequence·SIGHASH_ALL·보내기 최대 여부 | 접힘 |

경고: Z05(정보) 일반 전송은 공개됨(항상), Z01(정보) 받는 주소가 내 주소, Z02(정보) TEX, Z03(주의) UA의 일반 수신자로 보냄, Z04(정보) 다음 업그레이드 때문에 만료를 앞당김, Z06(주의, 2026-11-10) 처음 보내는 주소 — 이 네트워크 ZEC 저널에 그 주소로 확정된(`Confirmed`) 보내기가 없음(내 주소면 Z01만; `display::build_zec_request_with`의 `first_time`, yw-app이 저널로 정한다), 문구 "처음 보내는 주소입니다. 주소 전체를 확인하고, 큰 금액은 소액 시험 송금 뒤 보내세요."(BTC B05·SOL과 같음). 승인 창 상단 요약은 "…에서 x ZEC를 아래 주소로 보냅니다."

## 10. 서명·검증·전송 순서

### 10.1 순서

1. [검토] → 새로고침(§2.1 연결 검사, UTXO, 추적)을 다시 한 결과로 계획한다.
2. 받는 주소 파싱 → 금액 → `tx_consensus` → `plan_send` → 승인 대기열.
3. 승인 → `consume` → key worker: 저널 검사(§12.2: 손상 ZEC 기록 없음, 이 계정의 확정될 수 있는 기록 없음, 공간) → 서명(§8) → **서명 후 검증**(§10.2) → `Signed` 기록 커밋. 쓰기에 실패하면 서명을 버린다(디스크에 실제로 써졌는지 다시 읽어 확인).
4. UI: `Disclose`(공개 표시) 커밋 → 그 뒤에만 `sendrawtransaction`. 커밋에 실패하면(`ZecKeyOutcome::JournalFailed`) 보내지 않고 "거래 기록을 저장하지 못해 아직 보내지 않았습니다 …"를 보이며, 다음 새로고침이 공개 표시를 다시 커밋한 뒤 보낸다.
5. 결과: 수락 → `Broadcast`; `-25`/`-26` → `Rejected`(공개됨: 만료까지 입력 예약); 결과 모름 → 상태 그대로, 다음 새로고침이 노드에 없으면 같은 바이트를 다시 보낸다.

### 10.2 서명 후 검증 (`zec::sign::verify_signed`, 모두 필수)

엄격 파싱 → scriptSig만 비운 거래가 계획의 거래와 동일 → 각 scriptSig가 `<sig> <우리 공개키>`이고 ZIP 244 digest에 대해 유효(소프트웨어: low-R·low-S·DER ≤ 70, 카드: low-S·DER ≤ 72) → 수수료가 계획과 같고, 서명된 크기의 ZIP 317 수수료 이상이며, 상한 이하. 통과해야 txid를 돌려준다.

## 11. 화면 (S10 Zcash 탭, [04](04-app-ui.md) §2.6)

탭 행 `EVM · Solana · Bitcoin · Zcash`(Ctrl+4). 꺼져 있으면 소개 카드와 [Zcash mainnet 켜기]·[Zcash testnet 켜기 (테스트)]. 켜져 있으면 한 화면에 차례로:

- 네트워크 배너(§2.1), ZEC 저널 손상 배너(E-VLT-006), 탭의 오류·정보 배너(키 출처·네트워크 바꾸기 거부, 새로고침 오류 등 — 보내기 결과는 아래 보내기 카드).
- 네트워크 카드: mainnet/testnet 선택, `RPC (zcash:<net>): 연결됨 (genesis 확인) · 블록 n · 업그레이드 NU7` 또는 "RPC 주소 없음 (E-KEY-005) — 설정 → 네트워크(RPC)에서 Zcash RPC 주소를 넣으세요"(2026-11-10 용어; 링크 `RPC 설정하기`는 그 네트워크의 행을 입력 칸이 열린 채 연다, [04] §2.11.1), UTXO 원천(`노드 getaddressutxos` / `Blockbook (/api/v2)`), [새로고침], [Zcash 끄기]. 새로고침 결과는 작업 번호와 물어본 주소로 맞춘다: 작업 번호는 잠금(·초기화)을 넘어 계속 올라가고(2026-11-10 — 이전에는 잠금마다 0부터 다시 세어, 잠금 전이나 초기화 전 지갑의 늦은 답이 다음 세션의 첫 새로고침으로 받아들여질 수 있었다), 결과의 주소가 지금 계정의 주소가 아니면 그 답은 보이지도, 계획·"이미 아는 출력"에 쓰지도 않고 다음 틱에 다시 묻는다.
- 계정 카드: 키 출처·경로, 확인된 잔액 "확인된 잔액 {ZEC} (서버 기준, 진행 중 거래의 입력 제외)"(2026-11-13: 뒤에 붙던 "· 미확인 …"을 나눴다 — 받은 내역이 켜져 있고 읽은 목록(지원 안 함이 아닌)의 미확정 행 합은 흐린 줄 "미확정 입금 {ZEC} (0 확인 — 바뀌거나 취소될 수 있습니다, 아직 쓸 수 없음)"; 스냅숏의 `height` 없는 출력 중 txid가 ZEC 저널에 없고 그 목록이 모르는(행도, 사라짐·뺌으로 센 것도 아닌) 것은 txid별 합이 0.0001 ZEC 이상인 것만 모아 흐린 줄 "미확정 출력 {ZEC} (0 확인 — 입금인지 확인하지 않았습니다, 아직 쓸 수 없음)" — 받은 내역이 꺼져 있으면 모두 여기에(입력을 보지 않았으므로 입금이라 부르지 않는다); 우리 거래의 잔돈은 "확인 대기 {ZEC} (내 거래의 잔돈, 아직 쓸 수 없음)". 2026-11-13 리뷰 전에는 목록에 미확정 행이 없으면 스냅숏 합 전체(먼지·다른 지갑의 우리 송금 잔돈 포함)를 "미확정 입금"으로 보였다. 모두 잔액·보내기에 넣지 않는다 — `plan`이 `height: None`을 거부, D32), 키 출처 바꾸기(표준 / `EVM 계정 i과 같은 키` + T-ZEC-EVM-SHARED + 두 번 확인 / `YubiKey Zcash 주소 i 사용` 버튼은 등록된 슬롯이 있을 때).
- 받기 카드: 주소(묶음 없이 전체 — `t1`·`t3`·`tm`·`t2` 뒤 4자·끝 4자 강조, [04] §3.3, 2026-11-12; 이전 4자 묶음), T-ZEC-RECEIVE, [주소 복사], [QR 보기](`zcash:` + 주소). 확인되지 않은 passphrase 세션(T-ALT-PASS)에서는 막는다.
- 보내기 카드: 받는 주소(t/TEX/UA), 도움말 "확인된 잔액 {ZEC} ZEC ({zats} zats)"(읽기 전이면 "확인된 잔액: 아직 읽지 못했습니다", 2026-11-12), `금액 (ZEC)` 칸과 바로 오른쪽 토글 버튼 `최대`(켜면 눌린 모양이고 칸이 꺼지며 확인된 출력 최대 50개의 합 − 수수료를 보낸다; 2026-11-12 전에는 체크 `보내기 최대`, [04] §2.7), [검토]. `검토`·승인·서명·전송이 끝난 결과는 탭 위 띠가 아니라 [검토] 바로 위 줄에 보인다(2026-11-10 — 기본 창에서는 보내기 카드가 첫 화면 아래라 위 띠는 버튼에서 수백 DIP 떨어져 있었다): "Zcash 노드를 확인하는 중…"·"서명했습니다. Zcash 노드로 보내는 중…"(정보), 계획·노드 확인 오류·만료(T-APPR-EXPIRED)·서명 실패·노드 거부·결과 모름(오류), 노드가 받으면 성공 띠 "보냈습니다. txid … — 아래 활동에서 확인 상태를 봅니다."와 [검토] 옆 `해시 복사`. 탭 위 오류 띠는 같은 글이 이 줄에 있으면 다시 보이지 않는다. 계정의 복구 단어가 백업 확인 전이면 카드 맨 위에 [04] §2.24의 주의 띠와 `지금 백업 확인`을 보이고 [검토]를 끈다(U7). 유사 주소(W-ADDR-3, 2026-11-10): 받는 주소의 일반(transparent) 주소(TEX·UA는 그 일반 수신자를 `t1…`/`tm…`로 인코딩한 것)가 이 지갑 주소(계정·이 네트워크의 가져온 키)나 이전 수신자(이 네트워크 ZEC 저널 기록, 모든 계정) 중 하나와 같지 않으면서 두 글자 접두부(`t1`·`t3`·`tm`·`t2`) 뒤 같은 앞 P자 + 같은 끝 S자 ≥ 5(어떤 나눔이든, [08] §10 BTC 규칙, `yw_core::zec::address::look_alike_ends`)이면 입력 때마다 고위험 띠 "'{이름}'과 앞 P자·끝 S자가 같지만 다른 주소입니다. 주소 오염 공격일 수 있습니다."와 `주소 전체를 직접 확인했습니다` 체크를 보이고, 체크 전에는 [검토]를 끈다(체크는 그 주소에만 걸리고 주소가 바뀌면 지운다; 계획 때 다시 검사). 이 지갑 주소와 정확히 같을 때만 비교하지 않는다. 승인 창은 같은 문장을 요약 아래 `WARN_BG` 주석으로 보인다([04] §3.3, digest 밖).
- 활동 카드: 이 지갑이 보낸 ZEC 기록(상태·금액·수수료·받는 주소·만료 높이·txid — 2026-11-11부터 txid 줄을 누르면 `해시 복사`, 명령 ID 8,100–8,179; 받는 주소도 전체를 누르면 복사, 18,580–18,659)과 받은 UTXO 목록(서버 기준; 미확정 출력은 "미확정 (0 확인)", 2026-11-13 전 "미확인"). 2026-11-11부터 txid 줄 끝에 아이콘 ↗ `탐색기에서 열기`·🔗 `탐색기 링크 복사`, 보내기 카드의 결과 줄에 같은 이름의 버튼, 계정 카드 주소 줄 끝에 ↗ `탐색기에서 주소 보기`([04] §2.6·§2.11 "블록 탐색기"). 기본은 Zcash 커뮤니티 탐색기 `https://mainnet.zcashexplorer.app/transactions/{hash}`·`/address/{address}`; testnet은 `https://testnet.zcashexplorer.app/transactions/{hash}`만(그 사이트의 testnet 주소 페이지가 실제 주소에도 404라 주소 기본값 없음 — 사용자가 넣을 수 있다). Blockchair는 자동 확인을 막아(401) 기본으로 고르지 않았다.받은 내역(2026-11-11, [04] §2.6 opt-in, 일반 주소만): UTXO 원천이 `node`이면 마지막 새로고침(연결 검사를 통과한)의 tip까지 insight식 `getaddressdeltas {"addresses":[주소],"start":h,"end":tip}` 1회(처음 최근 20,000블록, 뒤로는 본 높이 다음부터; zcashd `-insightexplorer`). 입금 = 그 txid의 이 주소 델타가 모두 양수(우리 지출 없음), 0.0001 ZEC 미만은 개수만, 시각 대신 "블록 N", 보낸 주소는 응답에 없어 고정 문구. 응답이 4 MiB를 넘으면(먼지 폭탄) 그 범위를 건너뛰고 그 사실을 보인다. **미확정 입금**(2026-11-13, [04] §2.6 "미확정 입금"): `node`이면 위 다음에 노드의 멤풀을 주소 없이 훑는다 — `getrawmempool`, 이미 본 txid(`seen`, 최대 5,000, 지금 멤풀에 있는 것만 남김)·목록의 미확정 행·ZEC 저널 txid를 뺀 새 txid마다 `getrawtransaction <txid> 1`(읽기마다 `ZEC_MEMPOOL_SCAN_MAX` 30개, 넘으면 나머지는 다음 읽기에 먼저; "멤풀 거래가 많아 일부만 확인했습니다 …"), 판정은 §4.1 표. 0.0001 ZEC 미만은 개수만. `-5`·응답 상한 초과·못 읽음·남의 거래·우리 송금은 `seen`에 넣고, 그 밖의 호출 실패는 넣지 않아 다음 읽기에 다시 묻는다. `getrawmempool`이 실패하면 `seen`을 그대로 두고 "이번에는 멤풀을 읽지 못해 …", `-32601`이면 "…멤풀 조회(getrawmempool)를 지원하지 않아 …", 너무 크면 "멤풀 거래가 너무 많아 …". `bb-rest`이면 새로고침 스냅숏의 `height` 없는 출력의 txid(ZEC 저널 txid 제외)를 멤풀 목록 대신 쓰고, 그중 새 txid마다 같은 `getrawtransaction <txid> 1`로 같은 판정을 한다(같은 30개·5초 한도, `seen`은 스냅숏의 미확정 txid에 있는 것만 남김; 2026-11-13 리뷰 — 그 전에는 요청 없이 모두 입금 행으로 써서 같은 키를 쓰는 다른 지갑의 송금 잔돈이 입금처럼 보였다). 확정 행이 이미 있는 txid(재구성으로 멤풀에 돌아온 입금)는 어느 원천에서도 다시 묻지 않는다. 멤풀(또는 스냅숏)에 없게 된 미확정 행은 행마다 `getrawtransaction <txid> 1`(읽기마다 `ZEC_PENDING_CHECK_MAX` 5개): 채굴됨이면 확정 행("블록 h" — deltas가 없는 Zebra·`bb-rest`에서도 여기서 본 입금은 확정까지 보인다), 알려짐·오류면 그대로, `-5`면 채굴된 거래를 찾을 수 있는 엔드포인트(`getaddressdeltas`가 되는 zcashd, insightexplorer는 txindex 필요)에서만 "사라짐", 아니면 확정 여부를 모르므로 중립 문구로 뺀다(`dropped`). 읽기 하나 전체의 시간 한도 `ZEC_READ_BUDGET_MS` 5초(작업자 시계, 첫 호출 뒤 모든 호출 전에 확인; RPC 작업자는 승인·전송과 같은 줄이다) — 넘으면 멈추고 아무 행도 지우지 않는다. `getaddressdeltas`가 `-32601`(Zebra 등)이거나 `bb-rest`이면 확정분은 읽지 않고 흐린 줄 "이 Zcash 엔드포인트는 주소 내역 조회(getaddressdeltas)를 지원하지 않아 확인된 받은 내역은 표시하지 않습니다 — 미확정 입금과, 여기서 미확정으로 본 뒤 채굴된 입금만 보입니다."를 보이고(자동 읽기는 계속, 커서가 `-32601`을 기억해 자동 읽기는 다시 묻지 않고 `새로고침`만 다시 묻는다), 2026-11-13 전에는 "…받은 내역을 표시하지 않습니다 — 탐색기에서 확인하세요."를 보이고 읽기를 멈췄다. 비공개(shielded) 입금은 범위 밖(보기 키가 없다).
- 체인 배지([04] §1.6.1): 금색 원에 어두운 "Z"(원래 로고 파일이 아닌 단순 도형), testnet은 흐리게 + "T" 모서리. 탭(`Zcash`)에 붙는다. 주소록에는 Zcash 항목을 두지 않는다(이전 버전이 모르는 `chain`의 항목을 거부하므로).

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
| `InputsSpent` (7) | 팁 > 만료 + 10, 노드가 모름(또는 곁가지), 그런데 입력이 하나도 미사용 목록에 없음: "입력이 사용됨 — 포함되었을 수 있음". 다시 보내지 않고, 입력은 계속 예약(§12.2) | 예 |

본문(135바이트 머리 + 서명된 거래): kind 0x04, version 1, 상태, 네트워크, 키 출처(코드·a·b), 공개키 33, 승인 id 16, 승인 digest 32, 서명 시각, `disclosed`, `mined_height`, `not_found`, 금액, 수수료, 입력 합계, 거래 길이, 거래. 읽을 때 모든 scriptSig 끝 공개키가 기록의 키인지, 첫 출력 = 금액, 출력 합 + 수수료 = 입력 합계인지 확인한다(다르면 "저널 손상": ZEC 보내기만 멈추고 바이트는 보존). 종결 기록은 64개까지 두고 오래된 것부터 지운다.

**레코드 버전 2 (추가한 니모닉, 2026-11-08).** 키 출처 코드 5의 기록은 `record_version = 2`이고 135바이트 머리 뒤에 니모닉 record id 16바이트(0 아님)가 온 뒤 거래가 온다(최대 본문 135 + 16 + 32,768). 버전 1에 코드 5, 버전 2에 다른 코드는 거부한다. 다른 출처의 기록은 버전 1 바이트 그대로다. 이전 빌드는 버전 2를 본문 오류로 본다(ZEC 보내기만 멈춤, 바이트 보존, [04] §6.6).

**형식 호환.** 이전 버전의 저널 디코더는 모르는 `kind`를 손상(`SidecarCorrupt(Journal)`)으로 본다. ZEC를 한 번이라도 보낸 뒤 이전 버전으로 되돌리면 저널을 열지 못하므로 새 버전을 다시 설치해야 한다(vault tag 확장과 같은 안내, [04] §6.6 표에 행 추가).

### 12.2 진행 중 규칙과 공개 거래 규칙

- **한 번에 하나(D20과 같음).** 같은 네트워크·같은 공개키의 기록 중 종결이 아닌 것(`Signed`·`Broadcast`·`Rejected`)이 있으면 새 서명을 거부한다(`InFlight` "이 계정의 이전 Zcash 거래가 아직 확인되지 않았습니다. 확인되거나 만료된 뒤에 다시 보내세요."). 화면도 같은 이유로 [검토]를 막는다.
- **공개 거래 충돌.** 종결이 아닌 기록과 `InputsSpent` 기록의 입력은 모든 계획에서 제외한다(`reserved_inputs`, `ZecRecord::reserves_inputs`). Bitcoin처럼 "포기" 동작이 없는 대신, 만료 높이가 지나면(§12.1 `Expired`) 그 거래는 다시는 채굴될 수 없으므로 그때 입력이 풀린다.
- **추적**(새로고침마다, 탭이 열려 있거나 진행 중 기록이 있으면 30초마다): 채굴됨 → `Confirmed`(전이 `ZecTransition::Mined(height)`, `mined_height` 기록); 알려짐 → `Signed`면 `Broadcast`; 없음 → `Broadcast`면 `not_found + 1`, 만료 전이면 같은 바이트를 다시 보냄(공개 표시 먼저; 노드가 거부한 `Rejected` 기록은 10블록마다 한 번만, `REJECTED_RESEND_BLOCKS` — 같은 바이트의 같은 거부를 30초마다 되풀이하지 않는다. 바뀌는 것이 없는 전이는 저널을 다시 쓰지 않는다); 팁 > 만료 + 10이고 채굴 안 됨 → 그 기록의 입력이 같은 새로고침의 주소 UTXO 목록(먼지 제외 전 전체)에 하나라도 있으면 `Expired`(입력 풀림), 하나도 없으면 `InputsSpent`(입력 예약 유지), UTXO 조회가 실패했으면 다음 새로고침까지 기다림("없음"만으로 만료 처리하지 않는다, 2026-11-07). 단, 한도 초과이고 이 엔드포인트가 입력 상태를 알려 줄 수 없으면(`watch_unknowable`, §4.1) 영원히 기다리지 않고 `InputsSpent`(입력 예약 유지, "포함되었을 수 있음")로 닫아 새 보내기를 막지 않는다(2026-11-08).

### 12.3 meta `zcash` (선택 최상위 키)

`{"mainnet": {"source": 1|2|3|4, "a": u32, "b": u32, "pubkey": "02…"}, "testnet": {…}}` — 네트워크마다 계정 하나(키 출처 코드 1 표준(a = account, b = index) / 2 EVM 키(a = EVM index) / 3 YubiKey(a = index; 900–999는 복구 단어 없이 연결한 카드의 경로 모름 슬롯, [10] §7.6) / 4 가져온 키(a = b = 0, 2026-11-07 §2.3), 압축 공개키). 비어 있으면 쓰지 않는다. 추가한 니모닉의 계정(코드 5, §2.4)은 `zcash`에 쓰지 않고(이전 빌드가 그 항목을 버리고 계정을 다시 만든다) 선택 최상위 키 `mnemonic_accounts.zec` = `{"mainnet"?: {"mnemonic": hex32, "a", "b", "pubkey"}, "testnet"?: …}`(엄격, [02] §5.3)에 쓴다. 읽을 때 그 항목이 같은 네트워크의 `zcash` 항목보다 우선한다. 항목이 잘못되면 그 네트워크 계정만 버리고 잠금 해제 때 표준 경로로 다시 만든다. 이전 버전은 모르는 키로 보존한다. `prefs.tab = "zec"`은 이전 버전에서 `prefs` 전체를 기본값으로 되돌린다(무해). ZEC 활동은 meta `activity`에 넣지 않는다(이전 버전이 `zcash:` 네트워크 키를 거부해 meta 전체를 버리기 때문).

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
| `zec::tests::{transparent_parts_v5_vectors, transparent_parts_v4_fixture, transparent_parts_rejects}`, `fuzz_lite_zec_transparent_parts`(무시됨, 게이트 fuzz 단계) | 2026-11-13: `transparent_parts`가 `zip_0244.json`에서 출력 값이 범위 안인 벡터마다 테스트 전용 v5 파서와 같은 일반 입력(2026-11-13 리뷰부터 입력별 `scriptSig` 포함)·출력을 읽음(Sapling·Orchard 부분 무시; 무작위 벡터의 `MAX_MONEY` 초과 값은 전체 거부), v4 왕복, v6·모르는 머리말·잘림·남은 길이 초과 개수·비최소 CompactSize·`MAX_MONEY` 초과·스크립트 10,001바이트 거부, 무작위 바이트에 패닉 없음 |
| `received::zec::tests::mempool::*`(yw-app, 가짜 JSON-RPC·수동 시계) | 2026-11-13 ZEC-N1([09] §4.4): verbose `vout` 입금·먼지·남의 거래(주소는 `getaddressdeltas`에만), `hex` 대체·v6 `unreadable`·우리 출력을 쓰는 송금, 30개 상한과 읽기 전체 5초 한도(10초 호출이면 호출 1회), 상한 초과·잘못된 원소·txid 불일치·음수 `valueZat`·실패 재시도, 저널 txid 미요청, 사라진 행(채굴·`-5` 사라짐·Zebra 중립·5개 상한·`새로고침` deltas 재시도), `bb-rest` 스냅숏, 로그 필드 |

벡터 파일은 `crates/yw-core/tests/vectors/zec/`에 원본 그대로 두고 출처는 `tests/vectors/SOURCES.md`.

### 14.2 수용 체크리스트 (testnet, 수동 1회)

기록: [docs/acceptance/wc-zec-phrases-yk-20261110.md](../docs/acceptance/wc-zec-phrases-yk-20261110.md) ZC-01–ZC-10(아래를 2026-11-10 화면 이름으로 — `보내기 최대` 체크, [검토] 옆 결과 줄과 `해시 복사`).

1. `scripts/dev-rpc-setup.ps1`에 `zcash:testnet` 추가 → `node scripts/probe-rpc.mjs`가 `getblockhash 0`(testnet 제네시스), `getblockchaininfo`(`nextblock` = `77190ad9`), `getaddressutxos` 지원을 보고한다(-32601이면 UTXO 원천을 Blockbook으로). 2026-11-13부터 받은 내역의 미확정 입금용으로 `getrawmempool` 개수와 멤풀 거래 하나의 verbose `getrawtransaction`에 `vout`·`valueZat`·`scriptPubKey.hex`·`vin`·`hex`가 있는지도(개수·참거짓만, txid·주소 출력 없음).
2. 앱: 설정 > RPC에 `zcash:testnet` URL → [테스트] "genesis 일치".
3. Zcash 탭 → [Zcash testnet 켜기] → 주소가 `tm…`이고, 같은 복구 단어를 Zashi(testnet)·YWallet에 넣었을 때의 일반 주소(계정 0, 첫 주소)와 같다.
4. testnet faucet에서 받기 → 새로고침에 "미확정 입금 …"(2026-11-13 이름; 받은 내역을 켜면 그 txid의 미확정 행), 1확인 뒤 확인된 잔액.
5. 다른 `tm…` 주소로 소액 보내기: 승인 창에 네트워크·보내는 주소·받는 주소·형식·금액·수수료(10,000 zats)·만료 높이(다음 블록 + 120)·업그레이드 NU7이 보이고, 승인 후 [검토] 위 성공 띠의 txid(`해시 복사`)가 탐색기·노드에서 보이며 1확인에 `확인됨`.
6. TEX(`textest1…`)와 일반 수신자가 있는 `utest1…`로 각각 보내기(Z02·Z03 표시), 일반 수신자 없는 UA·`ztestsapling…`는 거부 문구.
7. 보내기 직후 두 번째 보내기는 "이전 Zcash 거래가 아직 확인되지 않았습니다"로 막힌다.
8. 보낸 직후 앱 강제 종료 → 다시 열어 잠금 해제 → 같은 txid로 추적이 이어진다(노드에 없으면 같은 바이트 재전송).
9. `최대`(금액 칸 옆 토글, 2026-11-12 전에는 `보내기 최대` 체크): 잔액 − 수수료 전부, 잔돈 출력 없음.
10. (선택) `EVM 계정과 같은 키`: 경고와 두 번 확인 뒤 주소가 EVM 키의 HASH160 주소로 바뀌고, 진행 중 거래가 있으면 바뀌지 않는다.
11. (선택, YubiKey) [10](10-yubikey.md)의 Zcash 슬롯 등록 → `YubiKey Zcash 주소 0 사용` → 보내기 때 PIN 1회 + 입력마다 터치, 서명 후 검증 통과.
12. (선택, 가져온 키 §2.3) 먼저 읽기만: testnet WIF(`c…`)를 `개인키 가져오기`에 넣으면 S19 없이 바로 `[가져온 키] tm…` 줄이 생기고 그 주소가 다른 지갑(zcashd `getaddressesbyaccount`/탐색기)의 그 키 주소와 같다. 메인넷 WIF(`K…`)는 E-INP-026으로 거부, 같은 WIF 두 번은 거부. 그 뒤 소액 받기·보내기, `개인키 보기`가 넣은 WIF와 같음, `삭제`(진행 중 거래가 있으면 거부) 뒤 표준 경로 계정으로 돌아옴.

## 15. 상수 (`yw_core::zec`)

`ZEC_DUST` 1,000 · `ZEC_MAX_INPUTS` 50 · `ZEC_FEE_ABS_CAP` 1,000,000 · `ZEC_SEQUENCE` `0xFFFFFFFF` · `ZEC_MIN_CONF` 1 · `ZEC_POLL_SECS` 30 · `ZEC_MAX_UTXOS` 1,000(초과분은 작은 것부터 버림) · `ZEC_MIN_UTXO` 5,000 · `ZEC_EXPIRED_AFTER` 10 · `ZEC_JOURNAL_FINAL_KEEP` 64 · `ZEC_MAX_JOURNAL_RAW` 32,768 · `upgrade::ZEC_EXPIRY_DELTA_PRE_NU7` 40 · `ZEC_EXPIRY_DELTA_NU7` 120 · `ZEC_MIN_EXPIRY_BLOCKS` 4 · `fee::MARGINAL_FEE` 5,000 · `GRACE_ACTIONS` 2 · `P2PKH_STANDARD_INPUT_SIZE` 150 · `P2PKH_STANDARD_OUTPUT_SIZE` 34 · `f4jumble::MIN_LEN` 38 · `MAX_LEN` 4,194,368 · `tx::PARTS_MAX_BYTES` 2 MiB · `PARTS_MAX_ITEMS` 10,000 · `PARTS_MAX_SCRIPT` 10,000. 받은 내역(yw-app `received::zec`, 2026-11-13): `ZEC_MEMPOOL_SCAN_MAX` 30 · `ZEC_READ_BUDGET_MS` 5,000 · `ZEC_PENDING_CHECK_MAX` 5 · `ZEC_SEEN_MAX` 5,000 · `ZEC_MEMPOOL_MAX_TXIDS` 5,000 · `MAX_MEMPOOL_RESPONSE` 512 KiB · `MAX_TX_RESPONSE` 1 MiB.

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

| 18 | 멤풀(2026-11-13) | `getrawmempool`(비 verbose: txid 문자열 배열; zcashd `[false]`와 같음), verbose `getrawtransaction`의 `vin[].txid`·`vout`·`coinbase`, `vout[].valueZat`·`scriptPubKey.hex`(zcashd; 새 Zebra도), v4 일반 부분은 머리말 8바이트 바로 뒤, v5는 branch·lock_time·expiry 뒤 | zcashd `rpc/rawtransaction.cpp`·`rpc/blockchain.cpp`, Zebra `zebra-rpc/src/methods.rs`, ZIP 202·225 |

확인하지 못한 것: QuickNode testnet 서브도메인(`zec-testnet`은 추정), Blockbook Zcash 파서의 v6 지원(이 지갑은 v5만 만들므로 영향 없음), 공급자 Zebra의 `getrawmempool` 허용 여부와 verbose `getrawtransaction`이 `vout[].valueZat`·`scriptPubKey.hex`를 주는지(없으면 v6 입금은 `unreadable`이고 확정 뒤 deltas로만 보인다), v6(ZIP 230) 형식 — `transparent_parts`는 읽지 않는다. 30개/분 상한이 NU7(25초 블록) 이후 메인넷 멤풀을 따라가는지는 `received.mempool_cap` 로그로 본다.

## 미결 사항

- ~~가져온 개인키(WIF): vault tag 추가와 형식 호환 정책을 정한 뒤 phase 2.~~ 2026-11-07 tag 6으로 넣었다(§2.3).
- 비공개 거래(Orchard 보내기, UA 비공개 수신자 우선): 범위 밖(D36). 하려면 증명 생성 라이브러리가 필요해 의존성 정책([01] §3.4)부터 다시 정해야 한다.
- ZIP 2009 수수료 인하가 확정되면 `MARGINAL_FEE`를 업그레이드 표처럼 높이별로 바꾼다.
- 새 네트워크 업그레이드(branch id)가 나오면 §4.2 표를 갱신하는 릴리스가 필요하다(그 전에는 `UnknownBranch`로 보내기를 막는다).
