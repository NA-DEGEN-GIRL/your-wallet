# 11. Hyperliquid HyperCore — 잔액과 전송 (D34, 2026-11-06)

- 상태: 구현(yw-core `hypercore`, yw-app `app_hypercore`·`hypercore`·`ui::screens_hypercore`). 실제 자산 수동 확인만 남음(`docs/acceptance/hypercore-20261106.md`).
- 범위: 같은 secp256k1 EVM 계정 주소의 HyperCore(Hyperliquid L1) **잔액 보기**와 **사용자 서명 전송**(USDC·현물 토큰 보내기, 현물↔선물 이동, Arbitrum 출금, HyperEVM↔HyperCore 이동). **거래(주문·취소·레버리지·API 지갑 승인)는 범위 밖**이다. dApp(app.hyperliquid.xyz 등)이 요청하는 `eth_signTypedData_v4`는 구조화해 보이되(§7) 지갑이 직접 만들지 않는다.
- 의존성 추가 없음. 서명은 기존 EVM 키 경로(파생·가져온 키·YubiKey, [03] §4, [10] §6)의 typed-data 서명 그대로다.

## 1. 출처 (2026-11-06 확인)

| 항목 | 출처 |
|---|---|
| `/exchange` 요청·응답 예 (usdSend, spotSend, withdraw3, usdClassTransfer, sendAsset; `signatureChainId`·`hyperliquidChain` 의미; `{"status":"ok","response":{"type":"default"}}`) | https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/exchange-endpoint |
| `spotMeta`·`spotClearinghouseState` 요청·응답 | https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint/spot |
| `clearinghouseState`(marginSummary.accountValue, withdrawable, assetPositions) | https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/info-endpoint/perpetuals |
| 서명 주의(두 서명 방식, 주소 소문자, 숫자 끝 0, 로컬 복구만으로 검증하지 말 것) | https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/signing |
| nonce 규칙(서명자별 가장 큰 100개, `(T − 2일, T + 1일)`) | https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/api/nonces-and-api-wallets |
| HyperCore↔HyperEVM 이동(시스템 주소 `0x20…`+index, HYPE `0x2222…2222`, `evm_extra_wei_decimals`, 끝수 소각, 연결 안 된 컨트랙트로 보내면 손실, Core→EVM 200k gas) | https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm/hypercore-less-than-greater-than-hyperevm-transfers |
| HyperEVM chainId 999(메인넷)·998(테스트넷) | https://hyperliquid.gitbook.io/hyperliquid-docs/for-developers/hyperevm |
| USDC Core→EVM은 `sendAsset`(`destination 0x2000…0000`, `destinationDex "spot"`), 받는 주소는 보낸 주소와 같음 | https://developers.circle.com/cctp/howtos/withdraw-usdc-from-hypercore-to-hyperevm.md |
| 출금 고정 수수료 1 USDC(약 5분) | exchange-endpoint 페이지 "~$1 fee", https://docs.chainstack.com/reference/hyperliquid-exchange-withdraw |
| 서명 타입·필드 순서·도메인, 요청 본문 | 공식 Python SDK `hyperliquid/utils/signing.py`(`user_signed_payload`, `*_SIGN_TYPES`, `sign_user_signed_action`, `l1_payload`), `hyperliquid/exchange.py`(`usd_transfer`, `spot_transfer`, `withdraw_from_bridge`, `usd_class_transfer`, `send_asset`, `_post_action`) — https://github.com/hyperliquid-dex/hyperliquid-python-sdk |
| 서명 벡터 | 같은 SDK `tests/signing_test.py` `test_sign_usd_transfer_action`·`test_sign_withdraw_from_bridge_action`(키 `0x0123…0123`, Testnet) |

## 2. 네트워크

| | 메인넷 | 테스트넷 |
|---|---|---|
| API 기준 URL | `https://api.hyperliquid.xyz` (고정, 바꿀 수 없음) | `https://api.hyperliquid-testnet.xyz` (설정에서 HTTPS로 바꿀 수 있음) |
| `hyperliquidChain` | `"Mainnet"` | `"Testnet"` |
| 이 지갑의 `signatureChainId` | `0xa4b1`(42161, 문서 예) | `0x66eee`(421614, SDK 값) |
| HyperEVM chainId | 999 | 998(기본 체인이 아님 — 쓰려면 사용자 체인으로 추가, [04] §2.17) |

`signatureChainId`는 "서명할 때 쓴 체인 id"일 뿐 아무 값이나 된다(SDK 주석). 재사용 방지는 `hyperliquidChain`이 한다.

## 3. 읽기 (`POST {API}/info`)

- `{"type":"spotMeta"}` → `tokens[]`: `name`, `index`, `tokenId`(`0x`+32 hex), `szDecimals`, `weiDecimals`, `evmContract`(`null` 또는 `{"address","evm_extra_wei_decimals"}`), `fullName`. 테스트넷은 1,677개(≈0.45 MB)라 응답 상한 8 MiB·노드 200만으로 파싱한다. 항목 하나라도 형식이 틀리면 전체를 버린다(소수 자릿수를 추측하지 않는다).
- `{"type":"spotClearinghouseState","user":"0x…"}` → `balances[]`: `coin`, `token`(index), `total`, `hold`(10진 문자열).
- `{"type":"clearinghouseState","user":"0x…"}` → `marginSummary.accountValue`, `withdrawable`, `assetPositions`.
- 주소는 소문자로 보낸다. 잔액은 S10이 보이는 동안 60초마다, `새로고침`, 계정 전환, 제출 결과 뒤에 다시 읽는다. `spotMeta`는 네트워크당 한 번(앱 실행 중 캐시).
- 받은 내역(2026-11-11, [04] §2.6 opt-in, 카드를 펼쳤을 때만): `{"type":"userNonFundingLedgerUpdates","user":"0x…","startTime":ms}` 1회(처음 최근 30일, 뒤로는 본 가장 늦은 `time` 다음부터; 응답 `[{time, hash, delta}]`, 오래된 것부터). 행: `deposit`(Arbitrum 브리지 USDC, 보낸 주소 대신 "보낸 곳: Arbitrum 브리지 입금 (보낸 주소 없음)" / "From: Arbitrum bridge deposit (no sender address)"), `destination`이 이 계정이고 `user`가 아닌 `internalTransfer`(USDC)·`spotTransfer`·`send`의 USDC·HYPE만(시스템 주소에서 온 것은 "보낸 곳: HyperEVM에서 이동 (시스템 주소)" / "From: moved from HyperEVM (system address)"). USDC < 0.01·HYPE < 0.001과 0은 개수만, 다른 토큰·펀딩·볼트·현물↔선물 이동은 무시.

## 4. 사용자 서명 작업 (EIP-712)

도메인 = `{name: "HyperliquidSignTransaction", version: "1", chainId: signatureChainId, verifyingContract: 0x0000…0000}`(표준 4필드 `EIP712Domain`). primaryType과 필드(순서 그대로 서명):

| 작업 (wire `type`) | primaryType | 필드 | nonce 필드 |
|---|---|---|---|
| `usdSend` | `HyperliquidTransaction:UsdSend` | `string hyperliquidChain, string destination, string amount, uint64 time` | `time` |
| `spotSend` | `HyperliquidTransaction:SpotSend` | `string hyperliquidChain, string destination, string token, string amount, uint64 time` | `time` |
| `withdraw3` | `HyperliquidTransaction:Withdraw` | `string hyperliquidChain, string destination, string amount, uint64 time` | `time` |
| `usdClassTransfer` | `HyperliquidTransaction:UsdClassTransfer` | `string hyperliquidChain, string amount, bool toPerp, uint64 nonce` | `nonce` |
| `sendAsset` | `HyperliquidTransaction:SendAsset` | `string hyperliquidChain, string destination, string sourceDex, string destinationDex, string token, string amount, string fromSubAccount, uint64 nonce` | `nonce` |

- `destination`은 **string**(소문자 `0x…`), `token`은 `"이름:0x<tokenId>"`, `amount`는 10진 문자열(부호·지수·앞 0·끝 0·끝 점 없음). USDC 금액(`usdSend`·`withdraw3`·`usdClassTransfer`)은 소수 6자리까지(Arbitrum USDC 6, SDK `float_to_usd_int`), 현물은 그 토큰의 `weiDecimals`까지.
- nonce = 검토 시각의 벽시계 ms(요청 `nonce`와 같은 값). 서브계정·볼트(`vaultAddress`, `fromSubAccount`)는 쓰지 않는다(빈 값).
- 요청 본문: `{"action": {"type", "signatureChainId", "hyperliquidChain", …필드}, "nonce": N, "signature": {"r": "0x"+64hex, "s": "0x"+64hex, "v": 27|28}}`. 응답은 HTTP 200에 `{"status":"ok",…}` 또는 `{"status":"err","response":"메시지"}`. 거래 해시는 없다 — 활동은 nonce·시각과 상태로 기록한다.
- 서명 digest = `keccak256(0x19 0x01 ‖ domainSeparator ‖ hashStruct)`. yw-core는 이를 직접 계산하고(`HcAction::preimage`), 시험에서 같은 문서를 범용 EIP-712 구현([03] §8)으로 다시 해시해 같음을 확인한다.

## 5. 이 지갑의 작업 (S-HC, [04] §2.23)

화면 문구는 앱 언어를 따른다(2026-11-14, [14]; 카탈로그 `yw_app::ui::screens_hypercore::text`·`yw_app::app_hypercore::text`). 아래 따옴표 문구는 한국어 / 영어다.

1. `보내기(Core)` / `Send (Core)`: 자산 라디오 — `USDC — 선물(perp) 잔액` / `USDC — perp balance` → `usdSend`, 현물 토큰 → `spotSend`. 받는 주소는 EVM 보내기와 같은 검사([04] §2.15: 형식·체크섬·0 주소 거부, 주소록·내 계정 표시, 주소 오염(앞뒤 같은 주소) → `주소 전체를 직접 확인했습니다` / `I checked the whole address myself` 체크 필요). 받는 주소가 HyperEVM 시스템 주소(`0x20…` + index, `0x2222…2222`)이면 보내기·출금 모두 거부하고 `HyperEVM으로 이동` / `Move to HyperEVM`을 안내한다(2026-11-07). 금액 ≤ 출금 가능(perp `withdrawable`) / 현물 `total − hold`(잔액과 같은 단위 — `weiDecimals` — 로 비교; HyperEVM 이동의 금액은 더 적은 자릿수로 입력받아 환산).
2. `현물↔선물 이동` / `Spot↔perp`: 방향 라디오, 금액 ≤ 현물 USDC(→ 선물) / `withdrawable`(→ 현물). 받는 주소 없음.
3. `Arbitrum으로 출금` / `Withdraw to Arbitrum`(`withdraw3`): 받는 주소 기본값 = 서명 계정(Arbitrum One), 금액 > 1 USDC, 금액 ≤ `withdrawable`. 고정 수수료 1 USDC는 금액에서 빠진다(받는 금액 = 금액 − 1, 사용자 결정 2026-11-06).
4. `HyperEVM으로 이동` / `Move to HyperEVM`(Core → EVM): `sendAsset { destination: 토큰의 시스템 주소, sourceDex: "spot", destinationDex: "spot", token }`. 시스템 주소 = `0x20` + 0 + index(big-endian), HYPE(`evmContract.address == 0x0`, 이름 HYPE)는 `0x2222…2222`. `evmContract`가 있는 현물 잔액만 고를 수 있고, 금액 소수 자릿수 ≤ min(`weiDecimals`, EVM 자릿수 = `weiDecimals + evm_extra_wei_decimals`)(끝수 소각 방지, USDC는 6). 토큰은 HyperEVM의 **같은 주소**로 들어간다(문서: recipient = sender). 공식 문서·Circle 문서는 현재 `sendAsset`을 쓰므로(예전 문서는 시스템 주소로 `spotSend`) 이 지갑은 `sendAsset`을 쓴다. 두 작업의 서명 형식은 테스트넷 서명 복구 시험을 통과했지만(§9), 자금이 실제로 HyperEVM에 들어오는지는 실제 자산 체크리스트에서 확인한다.
5. `HyperEVM에서 Core로 이동` / `Move from HyperEVM to Core`(EVM → Core): 일반 EVM 보내기([04] §2.7)를 HyperEVM(메인넷 999 / 테스트넷 998 — 등록돼 있어야 함)에서 연다. 활성 체인을 그 체인으로 바꾸고 받는 주소 `0x2222…2222`, 자산 HYPE(네이티브)를 채운다. 다른 연결 토큰은 사용자가 자산과 그 토큰의 시스템 주소를 직접 고른다. **시스템 주소 가드**(EVM 보내기, HyperEVM 999·998에서만): 받는 주소가 시스템 주소이면 — HYPE는 `0x2222…2222`에만, 토큰은 `spotMeta`에서 그 index의 `evmContract.address`가 그 토큰일 때만 허용; 아니면 차단 띠("…보내면 잃을 수 있습니다" / "…may lose it")와 `검토` 꺼짐; 토큰 정보를 못 읽었으면 역시 차단(HyperCore 카드 새로고침 안내). USDC의 EVM→Core는 CoreDepositWallet 경로라 이 지갑은 다루지 않는다(가드가 `spotMeta` 연결과 맞으면 막지 않지만, 문서로 확인하지 않은 경로이므로 수동 체크리스트에서 금지).

폼 공통(2026-11-10): `금액` / `Amount` 옆 `최대` / `Max`와 그 아래 `사용 가능: {양} {기호}` / `Available: {amount} {symbol}`(출금은 `출금 가능: …(수수료는 이 금액에서 빠집니다)` / `Withdrawable: … (the fee comes out of this amount)`, HyperEVM 이동은 `옮길 수 있는 양` / `Movable`) — 1–4의 상한 그대로이고 HyperEVM 이동은 폼의 자릿수(min(`weiDecimals`, EVM 자릿수))로 잘라(끝수는 HyperCore에 남김) 채운다. 잔액을 불러오지 못하면 그 오류 띠와 `새로고침`을 보이고(검증 문구는 "불러오지 못했습니다 — 새로고침" / "Could not load … — press 'Refresh'", 불러오는 중이면 정보 띠), S-HC가 열려 있는 동안에도 60초마다 다시 불러온다. 주소 오염 확인 체크는 체크한 그 받는 주소에만 유효하다(받는 주소가 바뀌면 — 다른 비슷한 주소라도 — 체크가 풀린다, S11·Bitcoin 폼과 같음). 출금의 받는 주소가 서명 계정이면 경고가 아닌 정보 문구 "서명 계정과 같은 주소 — Arbitrum One의 내 주소로 출금합니다." / "Same address as the signing account — withdraws to your own address on Arbitrum One."(승인 창 받는 주소 줄도 같은 문구).

## 6. 승인 `HyperCore 전송` (kind `0x40`)

- `ApprovalKind::HyperCoreAction = 0x40`, `ChainRef::HyperCore { network: 1|2, signature_chain_id }`(digest `chain_tag` 4: `u8 network ‖ u64 chainId`), `SigningPayload::HyperCore(HcAction)`; payload digest 바이트 = transcript `"your-wallet/v3/hypercore-action"` v1 (`u8 network ‖ u64 chainId ‖ bytes(action JSON) ‖ bytes(preimage 66)`). origin은 항상 앱, signer는 EVM 키, 시뮬레이션 `NotApplicable`. `issue`는 kind·payload·chain·계정·origin·signer와 `action.validate()`를 확인한다. 일회 소비·120초 만료·digest 규칙은 [03] §11 그대로.
- 서명: `consume` 뒤 vault는 `KeyJob::SignMessage { typed: true }`, YubiKey 계정은 카드 단계(PIN·터치, [10] §9.2)로 같은 typed-data 서명 함수(`sign_typed_data`/`_card`)를 쓰며, 함수는 승인된 작업에서 preimage를 다시 계산하고 chain과 network·chainId가 같은지 본다. 서명 후 복구 주소 = 계정 검사는 기존과 같다.
- 표시(필드 키): `0x0001` 요청 출처(앱), `0x0002` 네트워크 `Hyperliquid HyperCore 메인넷 (chainId 42161로 서명 · hyperliquidChain Mainnet)`, `0x0003` 서명 계정, `0x0701` 작업(한국어 이름, 현물↔선물은 방향, `(type usdSend)`), `0x0702` 받는 주소(전체 체크섬 주소 + 주소 검사 문구; 출금은 "Arbitrum One의 이 주소로", HyperEVM 이동은 "HyperEVM 시스템 주소 — … 같은 주소로"), `0x0703` 토큰·금액(`1.5 USDC` / `0.1 PURR` + `토큰 index·tokenId·소수 자릿수`; 출금은 `Arbitrum 도착 = 금액 − 1 USDC = … USDC`), `0x0704` 수수료(출금 `1 USDC (고정 출금 수수료…)`, HyperEVM 이동은 HYPE 가스, 나머지 없음), `0x0705` nonce(time), `0x0706` 원본 typed data(JSON, 세부 정보 아래). `0x0701`–`0x0704`는 critical. 헤더 배지는 EVM과 같다(메인넷 T-MAINNET, 테스트넷 `TESTNET_BG` "HyperCore 테스트넷 — 실제 자산이 아닙니다").
- 경고: H01 정보(되돌릴 수 없는 HyperCore 작업), H02 주의(주소록에 없는 받는 주소), H03 고위험(주소 오염 — 승인 창 체크박스 + 길게 누르기), H04 정보(HyperEVM 이동 — 받는 주소가 `spotMeta`에서 HyperEVM에 연결된 그 토큰의 시스템 주소이고 `sendAsset`이 현물→현물일 때만, 아니면 H13·H14 고위험), H05 정보(출금 수수료·시간).

## 7. dApp 타입 데이터 인식 ([03] §8.2 추가)

- primaryType·struct 이름에 `:`를 허용한다(첫·끝 글자 제외; 필드 이름은 그대로 식별자 규칙).
- `HyperliquidUser(…)`: 도메인 해시 = 표준 4필드, `name "HyperliquidSignTransaction"`, `version "1"`, verifyingContract 0, primaryType의 typeHash가 §4 표(5종) 또는 `ApproveAgent(string hyperliquidChain,address agentAddress,string agentName,uint64 nonce)`·`ApproveBuilderFee(string hyperliquidChain,string maxFeeRate,address builder,uint64 nonce)`와 정확히 같을 때. chainId는 평소처럼 현재 체인과 같아야 한다(T01). 표시: 제목 `HyperCore 전송 서명`/`Hyperliquid 거래 권한 위임 서명`/`Hyperliquid 빌더 수수료 승인 서명`, 필드 `작업`, `hyperliquidChain`(메인넷/테스트넷), 그 밖 message 필드를 순서대로(`destination`은 주소 분류 + 시스템 주소면 "HyperEVM 시스템 주소", USDC 작업의 `amount`는 `… USDC`, `toPerp`는 방향). 경고: 전송 H01, ApproveAgent **H06 고위험**("거래 권한 위임(API 지갑 승인) — 승인한 주소가 내 계정으로 주문·취소"), ApproveBuilderFee **H08 고위험**, `Testnet`이면 H09 주의. verifyingContract 0의 T10은 붙이지 않는다.
- **해석하지 않는 Hyperliquid 작업**(2026-11-10): 같은 도메인에서 위에 없는 `HyperliquidTransaction:*` primaryType(이름이 표의 것이지만 SDK와 형식이 다른 것 포함)도 Hyperliquid 계정 작업으로 인식한다 — `HyperliquidTransaction:ConvertToMultiSigUser`는 이름으로 `HlUserAction::ConvertToMultiSig`(**H16 고위험**: 멀티시그 전환 — 이후 이 계정의 작업에 `signers`의 서명이 필요해, 모르는 주소가 있으면 계정과 자금을 빼앗길 수 있음), 그 밖은 `HlUserAction::Unknown`(**H15 고위험**: 해석하지 못한 계정 작업 — 권한 이전·자금 이동일 수 있음). T04·T10 대신이며 Testnet이면 H09. 표시: 제목 `Hyperliquid 멀티시그 계정 전환 서명`/`Hyperliquid 계정 작업 서명 (해석하지 못함)`, 형식 줄 끝 "(해석하지 않은 형식 — 원문 필드 표시)", `작업` 줄(멀티시그는 `signers` JSON의 `threshold`와 `authorizedUsers`를 읽은 `서명자 (signers)` 줄 — 읽지 못하면 원문과 "해석할 수 없습니다"), 그 뒤 [03] §8.3의 전체 필드 트리(중첩 필드 포함). 설명 입력([06] §4.3)에서는 미인식 스키마처럼 primaryType·경로가 Untrusted이고 `schema_id`는 `hyperliquid-convert-to-multisig`/`hyperliquid-unknown-action`이다. 접두사가 다른 primaryType은 전과 같이 미인식(T04).
- **dApp 전송 검사**(2026-11-07, `usdSend`·`spotSend`·`sendAsset`·`withdraw3`): 앱은 `destination`에 S-HC와 같은 받는 주소 검사(내 계정·주소록·주소 오염)를 하고 그 `hyperliquidChain`의 캐시된 `spotMeta`를 붙인다(`ChainFacts.hyperliquid`; 없으면 고위험으로 닫힘). 받는 주소가 서명 계정·내 계정·주소록이 아니면 **H10 고위험**, 주소 오염이면 H03, `withdraw3`가 서명 계정이 아닌 주소로 가면 **H11 고위험**, `token`(`NAME:0xID`)이 `spotMeta`의 같은 tokenId·같은 이름과 맞지 않거나 `spotMeta`가 없으면 **H12 고위험**, 시스템 주소인데 `spotSend`/`sendAsset`의 토큰이 그 주소의 HyperEVM 연결 토큰이 아니면 **H13 고위험**(맞으면 H04와 "HyperEVM 이동" 문구). (2026-11-08) 토큰이 맞아도 `sendAsset`은 `sourceDex`·`destinationDex`가 모두 `"spot"`(문서: `"spot"` = 현물 잔액, `""` = 기본 USDC 선물 dex)이고 `fromSubAccount`가 `""`(하위 계정이 아닌 서명 계정 자신)일 때만 H04이고, 아니면(필드가 없을 때 포함) **H14 고위험**이다. 앱이 만드는 `sendAsset`(§6)도 같은 조건으로 H04/H14를 고른다. `destination`에는 EVM 체인의 계정 종류(`[일반 계정(EOA)]` 등)를 붙이지 않고 앱의 주소 검사 문구만 붙인다. 시스템 주소의 문구는 그 경고의 이유와 같다(2026-11-10): H04 이동, H14는 "이 토큰의 HyperEVM 시스템 주소이지만 서명 계정 자신의 현물→현물 이동이 아닙니다", H13은 다른 토큰의 주소 / `spotMeta`로 토큰을 확인하지 못함, 토큰이 없는 작업(`usdSend`·`withdraw3`)은 "HyperEVM 시스템 주소입니다 — 이 작업으로 보내면 자산을 잃을 수 있습니다". `withdraw3` 금액에는 `Arbitrum 도착 = 금액 − 1 USDC`를 붙인다.
- `HyperliquidL1Agent`: 도메인 `{name "Exchange", version "1", chainId 1337, verifyingContract 0}` + primaryType `Agent(string source,bytes32 connectionId)` 정확 일치. 이때만 chainId 1337을 현재 체인 대신 받아들인다(그 밖 `Agent`·`Exchange` 문서는 T01 차단 유지). 또한 요청 출처가 그 네트워크의 공식 앱일 때만 받아들인다(2026-11-07): `source a` ↔ `https://app.hyperliquid.xyz`, `source b` ↔ `https://app.hyperliquid-testnet.xyz`, 확장 프로그램의 사이트 출처(브라우저가 보증하는 출처)일 때만. 그 밖의 출처는 T01로 막는다. **WalletConnect 요청은 Verify 결과(`Valid` 포함)와 상관없이 T01**(2026-11-08, 이전에는 `Valid`인 주장 출처도 허용): Verify가 증명하는 출처는 dApp 쪽 환경이 Verify 서버에 알린 값이라, 브라우저 밖에서 도는 dApp(피싱 페이지에 보인 페어링 URI를 만든 서버)이 `app.hyperliquid.xyz`로 증명받지 못한다고 장담할 수 없다. 디스패처의 사전 검사도 WalletConnect 출처는 바로 막는다(`HlL1Requester::Nobody`). 표시: 네트워크(`source` a = 메인넷, b = 테스트넷), `작업 해시 (connectionId)` + "주문·취소 등 거래 작업의 msgpack 해시 — 내용은 해석할 수 없습니다". 경고 **H07 고위험**("주문·거래 서명(L1 action) — 지갑은 해시만 보며 이 지갑은 거래 기능을 지원하지 않습니다"), source b면 H09. 막지는 않는다(D16: 형식이 맞으면 고위험 확인 후 서명 가능).

## 8. 설정·화면

- `settings.json` `hypercore`: `{"enabled": true, "network": "mainnet"|"testnet", "testnetApi": "https://api.hyperliquid-testnet.xyz"}`(기본: 켜짐, 메인넷, 공식 주소). `testnetApi`는 HTTPS·256바이트 이하·`?`/`#` 없음, 끝 `/` 제거. 틀리면 그 키 전체를 기본값으로(E-APP-001 배너). 메인넷 API는 설정이 없다(고정). 보안 스냅샷([04] §6.7)에는 넣지 않았다(테스트넷만 바꿀 수 있어 실제 자산에 영향이 없음).
- S15 `EVM 체인` 탭 아래 카드 "Hyperliquid HyperCore": 체크 `EVM 탭에 HyperCore 카드 보이기` / `Show the HyperCore card on the EVM tab`, 네트워크 라디오 `메인넷`/`테스트넷` / `Mainnet`/`Testnet`, 메인넷 API(고정 표시), 테스트넷 API 편집 + `저장`·`공식 주소로` / `Save`·`Use official`.
- S10 EVM 탭(토큰 카드 다음, 활동 카드 앞) 카드 "Hyperliquid HyperCore 메인넷|테스트넷"(제목 앞 Hyperliquid 배지): 네트워크 라디오와 그 줄 끝의 작은 태그(테스트넷 "테스트넷 — 실제 자산이 아닙니다"("Testnet — not real assets") / 메인넷 "HyperCore 메인넷: 실제 자산"("HyperCore mainnet: real assets"), 띠와 같은 문구·색; 2026-11-11부터, 그 전에는 라디오 위 띠 — [04] §2.6, S-HC는 그대로 띠), 도움말(같은 EVM 주소, 전송만), `선물(perp) USDC: 계정 가치 … · 출금 가능 … (· 열린 포지션 n개)`(`Perp USDC: Account value … · withdrawable … ( · n open positions)`), `현물 {coin}: {total} (주문 보류 …)`(`Spot {coin}: {total} (on hold for orders …)`), 오류 띠, 버튼 `보내기(Core)`·`현물↔선물 이동`·`Arbitrum으로 출금` / `HyperEVM으로 이동`·`HyperEVM에서 Core로 이동`·`새로고침`(영어 `Send (Core)`·`Spot↔perp`·`Withdraw to Arbitrum` / `Move to HyperEVM`·`Move from HyperEVM to Core`·`Refresh`), "HyperCore 활동 (이번 실행)" / "HyperCore activity (this run)" 행(로컬 시각 · 작업 · 금액 → 받는 주소, `상태: … · nonce N` / `Status: … · nonce N`; 작업 이름은 `yw_core::hypercore::text::kind_name(lang, kind)`, 2026-11-14 `HcKind::korean` 삭제; 2026-11-10부터 잔액처럼 선택한 계정의 행만). 상태: 서명 중 → 전송 중 → `성공 (Hyperliquid status ok)` / `거부됨 (status err): 서버 메시지`(이스케이프) / `결과 불명 — 잔액을 확인하세요` / `서명하지 않음 — …`(잠금·카드 실패); 영어 `Signing` → `Sending` → `Succeeded (Hyperliquid status ok)` / `Rejected (status err): …` / `Outcome unknown — check the balances (…)` / `Not signed — …`. 오류 문장(`Hyperliquid API에 연결할 수 없습니다` / `Cannot connect to the Hyperliquid API` 등)은 작업을 보낼 때의 앱 언어로 RPC 작업자가 만든다(`HcEndpoint.lang`).
- 활동은 이 실행의 메모리에만 있다(meta `activity`는 거래 해시 스키마라 넣지 않음, §10).
- **탐색기**(2026-11-11, [04] §2.6·§2.11 "블록 탐색기"): 카드의 동작 버튼 아래 작은 `탐색기에서 주소 보기` — 선택 계정을 Hyperliquid 탐색기(`https://app.hyperliquid.xyz/explorer/address/{address}`, 테스트넷 `https://app.hyperliquid-testnet.xyz/explorer/…`; 앱 번들의 라우트 `/explorer/tx/:txhash`·`/explorer/address/:address`로 확인)에서 연다. `/exchange` 응답에 거래 해시가 없어(§4) 활동 줄에는 링크가 없고 소제목 아래 도움말이 그 이유와 주소 페이지를 안내한다. 거래 페이지 템플릿(`hypercore:<net>` `tx`)도 기본값을 두어 나중에 해시를 아는 줄(받은 내역 등)이 `App::explorer_tx_url`로 쓸 수 있다.
- **접기**(2026-11-10, [04] §2.6): 선택한 EVM 체인이 999·998·42161·421614가 아니고, 선택 계정의 HyperCore 활동이 서명 중·전송 중이 아니고, 이번 실행에서 `펼치기 ▸`를 누른 적이 없으면 카드는 배지 + "Hyperliquid HyperCore 메인넷 · 계정 가치 … USDC · 현물 n종"("Hyperliquid HyperCore mainnet · Account value … USDC · n spot tokens", 또는 불러오기 상태) 한 줄과 `펼치기 ▸` / `Expand ▸`뿐이고 동작 버튼도 띠도 없다; 펼치면 지금 카드 그대로(제목 아래 `접기 ▴` / `Collapse ▴`, 라디오와 네트워크 태그, 버튼 6개) — 동작 버튼을 그리는 곳에는 언제나 네트워크 표시도 그린다(카드는 작은 태그, S-HC는 늘 띠). 60초마다 잔액을 읽는 동작은 그대로이고 펼친 상태는 실행 중 메모리에만 있다.
- 명령 id 13,450–13,499([04] §1.8 표; 접기 링크 13,494–13,495).

## 9. 시험

1. SDK 서명 벡터(`hypercore::tests::sdk_usd_send_vector`, `sdk_withdraw_vector`): r·s·v 바이트 일치.
2. 다섯 작업 × 두 네트워크: 직접 계산한 preimage = 범용 EIP-712 검증기의 preimage, 스키마 인식 `HyperliquidUser(Transfer(kind))`, encodeType 문자열 = SDK.
3. 승인 → 서명 경로(`evm::sign::tests::hypercore_actions_through_the_approval_store`): 다섯 작업 모두 draft → `issue` → `consume` → vault `sign_typed_data` → 복구 = 계정; network가 다른 chain은 `issue` 거부.
4. dApp 표시(`dapp_typed_data_gets_the_hyperliquid_display`, `l1_agent_is_recognized_only_with_the_exact_schema`, `uninterpreted_hyperliquid_actions_get_their_own_warning`): 전송 H01(T04·T10 없음), ApproveAgent H06, 멀티시그 전환 H16(`signers` 줄), 그 밖의 `HyperliquidTransaction:*` H15(전체 필드), L1 Agent는 정확한 스키마에서만 1337 허용. S-HC(`app_hypercore::tests`): 주소 오염 확인은 그 주소에만, 카드 활동은 선택 계정의 것만, `최대`·사용 가능 양·불러오기 실패 표시.
5. RPC 작업자(`hypercore::tests::load_and_submit_through_the_worker`, 가짜 전송): `/info` 3회 파싱, `/exchange` `status err` 전달.
6. 실서비스(테스트넷만, `cargo test -p yw-app --test hypercore_live -- --ignored --nocapture`, 수동 1회): 무작위 일회용 키를 메모리 vault에 넣고 다섯 작업을 실제 승인·서명 경로로 만들어 테스트넷 `/exchange`에 보낸다. 잔액 없는 계정이라 Hyperliquid가 `status err`로 **서명에서 복구한 주소**를 알려 주며, 그것이 우리 주소와 같아야 한다(바이트 단위 인코딩 증명, 자산 이동 없음). 2026-11-06 실행: 다섯 작업 모두 `Must deposit before performing actions. User: 0x5b30…8175`(= 일회용 키 주소) — 통과. 같은 실행에서 `spotMeta`(1,677개, PURR `weiDecimals` 5, HYPE index 1105 → `0x2222…2222`)와 빈 계정의 두 잔액 응답도 파서를 통과했다. 메인넷에는 아무것도 보내지 않았다.

## 10. 미결 사항

- 출금 수수료 1 USDC는 금액에서 빠지는 것으로 본다(사용자 결정 2026-11-06). 폼은 `금액 > 1`과 `금액 ≤ 출금 가능`만 요구하므로 전액 출금이 된다. 실제 자산 체크리스트에서 도착 금액(금액 − 1)을 확인한다.
- HyperCore 활동을 meta에 저장할지(새 `NetworkId` 또는 별도 목록 필요). 지금은 실행 중에만 보인다.
- 테스트넷 HyperEVM 998은 기본 체인이 아니다(EVM→Core 테스트넷 확인에는 사용자 체인 추가가 필요).
- USDC의 HyperEVM→Core(CoreDepositWallet)는 범위 밖.
- 통합 계정(unified account)·포트폴리오 마진에서는 `spotClearinghouseState`가 거래 잔액의 기준이라는 문서 주석이 있다. 카드는 두 응답을 그대로 보인다.
