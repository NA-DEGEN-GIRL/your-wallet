# HyperCore 판정 기록 — 2026-11-06 (자동·실서비스 확인 완료, 실제 자산 항목만 사용자 수행)

- 범위: spec.md D34, [spec/11](../../spec/11-hypercore.md) 전체, [spec/03](../../spec/03-evm.md) §8.2(HL·HL1 스키마)·§10(H01–H09)·§11(kind 0x40, chain_tag 4), [spec/04](../../spec/04-app-ui.md) §2.6 카드·§2.23 S-HC·§3 승인·§6.1 `hypercore`.
- 의존성: **추가 없음**(`Cargo.lock` 변경 없음).
- 안전 규칙: 메인넷 `/exchange`에는 아무것도 보내지 않았다. 실서비스 확인은 테스트넷 API에 읽기 3회 + 서명 복구 확인 5회(무작위 일회용 키, 잔액 없음)뿐이다.

## 자동 항목 (게이트 `scripts/check.ps1 -Offline`)

| 항목 | 판정 | 근거 |
|---|---|---|
| SDK 서명 벡터 usdSend(Testnet, r·s·v 27) | 통과 | `hypercore::tests::sdk_usd_send_vector` |
| SDK 서명 벡터 withdraw3(Testnet, r·s·v 28) | 통과 | `hypercore::tests::sdk_withdraw_vector` |
| 다섯 작업 × 메인넷·테스트넷: 직접 계산 preimage = 범용 EIP-712 검증기, 스키마 인식, wire `type`·`hyperliquidChain` | 통과 | `hypercore::tests::typed_data_document_hashes_to_the_same_preimage` |
| encodeType 문자열 = SDK `*_SIGN_TYPES` | 통과 | `hypercore::tests::encode_types_match_the_sdk` |
| `/exchange` 본문 형식(`signatureChainId 0x66eee`, 주소 소문자, nonce = time, r·s 32바이트) | 통과 | `hypercore::tests::exchange_body_shape` |
| 금액 wire 규칙(끝 0·앞 0·지수·부호 거부, 자릿수 상한), 시스템 주소(`0x20…c8`, HYPE `0x2222…`) | 통과 | `hypercore::tests::amounts_and_system_addresses` |
| `spotMeta`·`spotClearinghouseState`·`clearinghouseState`·`/exchange` ok/err 문서 예 파싱 | 통과 | `hypercore::tests::info_and_exchange_shapes` |
| dApp typed data: 전송 H01(T04·T10 없음, `1.5 USDC` 표시), ApproveAgent H06 | 통과 | `hypercore::tests::dapp_typed_data_gets_the_hyperliquid_display` |
| L1 Agent(chainId 1337)는 정확한 스키마일 때만 허용, 다른 `Agent`는 T01 | 통과 | `hypercore::tests::l1_agent_is_recognized_only_with_the_exact_schema` |
| 다섯 작업: draft → `issue` → `consume` → vault 서명 → 복구 = 계정, network가 다른 chain은 `issue` 거부 | 통과 | `evm::sign::tests::hypercore_actions_through_the_approval_store` |
| RPC 작업자: `/info` 3회·`/exchange` 1회, 파싱·`status err` 전달 | 통과 | `yw-app hypercore::tests::load_and_submit_through_the_worker` |
| `settings.json` 직렬화(`logLevel` 마지막 유지), 명령 id 겹침 없음, S-HC 포함 모든 화면 id 유일 | 통과 | `tests/settings.rs`, `ui::command_ids::tests::*`, `app::tests::every_screen_has_unique_control_ids` |

## 실서비스 확인 (테스트넷, 2026-11-06, 1회)

`cargo test -p yw-app --test hypercore_live -- --ignored --test-threads=1 --nocapture`

| 항목 | 결과 |
|---|---|
| `spotMeta` 파싱 | 통과 — 토큰 1,677개, PURR `weiDecimals` 5, HYPE index 1105 → 시스템 주소 `0x2222…2222` |
| 빈 계정 `spotClearinghouseState`·`clearinghouseState` 파싱 | 통과 — 잔액 0개, accountValue 0.0, withdrawable 0.0 |
| usdSend 서명 복구 | 통과 — `Must deposit before performing actions. User: 0x5b30bd47…6538175`(= 일회용 키 주소) |
| spotSend(PURR) 서명 복구 | 통과 — 같은 주소 |
| withdraw3 서명 복구 | 통과 — 같은 주소 |
| usdClassTransfer 서명 복구 | 통과 — 같은 주소 |
| sendAsset(HYPE → 시스템 주소) 서명 복구 | 통과 — 같은 주소 |

Hyperliquid는 서명에서 복구한 주소를 오류 메시지에 넣어 돌려주므로, 무작위 키의 주소와 같다는 것은 EIP-712 인코딩(도메인·타입·필드 순서·값 문자열·chainId)과 서명이 바이트 단위로 맞다는 뜻이다. 자금은 움직이지 않았다.

## 수동 항목 (사용자, 실제 자산 — 테스트넷 먼저)

테스트넷 자금은 Hyperliquid 테스트넷 faucet(메인넷 입금 이력이 있는 주소 필요)으로 받는다. 각 항목 뒤에 카드의 활동 상태와 잔액 변화를 적는다.

| # | 항목 | 판정 |
|---|---|---|
| HC-1 | 설정 → EVM 체인 → HyperCore: 카드 보이기 켜짐, 네트워크 `테스트넷`. EVM 탭 카드에 테스트넷 띠·선물/현물 잔액이 웹(app.hyperliquid-testnet.xyz)과 같다 | 대기 |
| HC-2 | `보내기(Core)` USDC 1 → 내 다른 계정: 승인 창에 HyperCore 테스트넷 배지, 작업·받는 주소 전체·`1 USDC`·수수료 없음, 세부 정보에 원본 typed data. 승인 후 `성공 (Hyperliquid status ok)`, 두 계정 잔액 변화. 활동 행은 보낸 계정을 골랐을 때만 카드에 보인다(2026-11-10) | 대기 |
| HC-3 | `보내기(Core)` 현물 토큰(PURR 등) 소량 → 다른 계정: 토큰 index·tokenId·소수 자릿수가 보이고 성공 | 대기 |
| HC-4 | `현물↔선물 이동` 양방향 각 1 USDC: 성공, 잔액이 옮겨짐 | 대기 |
| HC-5 | `Arbitrum으로 출금` 2 USDC → 내 주소(받는 주소 줄은 정보 문구 "서명 계정과 같은 주소…", `최대` = 출금 가능액 전체 — 2026-11-10): 승인 창 수수료 `1 USDC`, 성공, Arbitrum Sepolia에 도착한 금액(1 USDC가 금액에서 빠졌는지 잔액에서 따로 빠졌는지 기록 — spec/11 §10) | 대기 |
| HC-6 | `HyperEVM으로 이동` HYPE 소량(`옮길 수 있는 양`·`최대`는 HyperEVM 자릿수로 자른 양): 승인 창 받는 주소 `0x2222…2222`·HyperEVM 안내, 성공, HyperEVM 테스트넷(998, 사용자 체인으로 추가)의 같은 주소에 HYPE 도착 | 대기 |
| HC-7 | `HyperEVM에서 Core로 이동`: HyperEVM 테스트넷 S11이 `0x2222…2222`·HYPE로 열림, 보내기 후 Core 현물 HYPE 증가. 자산을 토큰으로 바꾸면 차단 띠가 보이고 `검토`가 꺼짐 | 대기 |
| HC-8 | 주소 오염: 주소록 주소와 앞뒤가 같은 주소를 넣으면 고위험 띠·체크 필요(체크 뒤 다른 비슷한 주소로 바꾸면 체크가 풀림), 승인 창 H03 고위험 확인 | 대기 |
| HC-9 | YubiKey 계정으로 HC-2 반복: PIN·터치 뒤 성공 | 대기 |
| HC-10 | 승인 창에서 거부·만료: 활동 행 없음 또는 `서명하지 않음`, 잔액 그대로. 서명 중 잠금 → `서명하지 않음 — 잠겨서 취소됨` | 대기 |
| HC-11 | dApp(app.hyperliquid-testnet.xyz) "Enable trading": 승인 창이 `Hyperliquid 거래 권한 위임 서명` + H06 고위험으로 보이고, 출금 요청은 `HyperCore 전송 서명` + 구조화 필드로 보임 | 대기 |
| HC-12 | 메인넷 소액(실제 자산, 테스트넷 통과 후): HC-2·HC-4·HC-5를 최소 금액으로 1회 | 대기 |
