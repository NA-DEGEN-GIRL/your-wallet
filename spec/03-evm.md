# EVM

상위 문서: [spec.md](../spec.md)

D13–D20, D27–D29의 EVM 세부 명세다. 이 문서는 [spec.md](../spec.md)를 따르며 충돌하면 spec.md가 우선한다. 승인 창 렌더링·조작은 [04](04-app-ui.md), dApp 메서드 라우팅·권한·봉투는 [05](05-browser.md), 키 파생·vault·저널 컨테이너 암호화는 [02](02-core-keys-vault.md), 테스트 값 전문은 [09](09-testing.md)가 정한다. D31: dApp 오류 코드·문구는 [05](05-browser.md) §5, meta·주소록·계정·저널 스키마는 [02](02-core-keys-vault.md) §5, 크레이트·모듈 구성은 [01](01-repo-build.md)이 정본이고, 승인 digest·표시 인코딩(모든 체인)은 이 문서 §11이 정본이다.

## 0. 모듈 배치

yw-core는 네트워크를 호출하지 않는다. yw-app이 RPC를 호출하고 응답을 yw-json으로 파싱해 아래 yw-core 타입으로 넘긴다. EIP-712 원문은 JSON이므로 `yw-core::evm::eip712`는 `yw_json::Value`를 입력으로 받는다(D5·[01](01-repo-build.md) §2.4가 허용하는 유일한 로컬 의존 yw-core → yw-json). yw-core 모듈 이름과 도입 단계는 [01](01-repo-build.md) §2.2가 정본이다(D31): `hex`·`evm::address`는 M1, `journal`(EVM 레코드 `journal::evm`)은 M4, `policy`는 M2에 `BrowserOrigin`으로 시작하고 나머지는 M5, 아래 표의 그 밖 yw-core 모듈은 M2. yw-app의 EVM 모듈 이름(`rpc::evm`, `flow::evm`, `browser::params`)은 아래 표가 정본이고, yw-app 전체 모듈 배치는 [04](04-app-ui.md) §1.8이 정한다(`browser::envelope` 등 브라우저 모듈 내용은 [05](05-browser.md)). yw-core는 시각을 인자(`now_ms: u64` = yw-win `time::monotonic_ms`, `now_unix_ms: u64`)로만 받는다([01](01-repo-build.md) §5.1: `Instant`·`SystemTime` 금지).

| 모듈 | 크레이트 | 내용 | 이식 근거 |
|---|---|---|---|
| `hex`, `codec::transcript` | yw-core | 엄격 hex, `Transcript`(§6.5, §11) | `archive/spec-v2.4:crates/wallet-model/src/codec.rs:1-206` |
| `evm::address`, `evm::amount` | yw-core | EIP-55, `U256`(256비트 산술, §2.3), 금액 형식 | `archive/spec-v2.4:crates/wallet-model/src/bounded.rs:33-262`, `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:4204-4363`, `archive/spec-v2.4:demo/sepolia-wallet/src/erc20.rs:222-290`, `archive/spec-v2.4:crates/wallet-protocol/src/authorization.rs:818-837` |
| `evm::chain` | yw-core | 내장 체인 표·레지스트리, 사용자 체인 검증(§1) | `archive/spec-v2.4:crates/chain-registry/src/registry.rs:20-28` |
| `evm::rlp`, `evm::tx`, `evm::sign` | yw-core | 단일 RLP, type 2, 서명·서명 후 검증 | `archive/spec-v2.4:crates/secret-core/src/signing.rs:14-120,167-279`, `archive/spec-v2.4:crates/key-agent/src/lib.rs:280-358,391-905` |
| `evm::fee` | yw-core | 수수료·가스·대체 수수료(§3.4–3.5, §4.6) | `archive/spec-v2.4:demo/sepolia-wallet/src/rpc.rs:645-679`, `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:6554-6773` |
| `evm::abi`, `evm::decode` | yw-core | calldata 해석(§7) | `archive/spec-v2.4:demo/sepolia-wallet/src/erc20.rs:1-583` |
| `evm::simulate`, `evm::risk` | yw-core | 시뮬레이션 요청 구성·응답 해석·diff(§6), 위험 규칙(§10) | 신규 |
| `evm::eip712`, `evm::eip191`, `evm::siwe` | yw-core | 타입 데이터(§8), EIP-191(§9.1–9.2), SIWE(§9.3–9.4) | `archive/spec-v2.4:crates/eip712/src/{lib.rs,error.rs,json.rs,schema.rs}`, `tests/vectors.rs:1-371`, `archive/spec-v2.4:crates/wallet-model/src/operation.rs:398-415` |
| `evm::display` | yw-core | 승인 제목·표시 필드 빌더(§7.3, §11.1–11.2) | `archive/spec-v2.4:crates/wallet-protocol/src/authorization.rs:36-325,470-837`, `archive/spec-v2.4:crates/approval-wire/src/lib.rs:231-777,1212-1300` |
| `journal` (EVM 레코드는 `journal::evm`) | yw-core | M4. 체인 공통 저널 프레이밍([02] §5.4), EVM 레코드·상태 기계(§5) | `archive/spec-v2.4:crates/key-agent/src/durable.rs:725-806,1100-1129`, `archive/spec-v2.4:crates/wallet-protocol/src/nonce.rs:20-65` |
| `approval`, `policy::BrowserOrigin` | yw-core | 승인 요청·digest·일회 소비(§11). `policy` 모듈은 승인 모델이 쓰는 `BrowserOrigin`으로 M2에 시작하고, 나머지(메서드 허용 목록·연결 권한·공급자 오류 코드, [05])는 M5에 더한다([01] §2.2) | `archive/spec-v2.4:crates/wallet-protocol/src/approval.rs:16-22,163-189,466-541`, `archive/spec-v2.4:crates/wallet-model/src/context.rs:42-131`, `archive/spec-v2.4:crates/approval-wire/src/lib.rs:1266-1300` |
| `rpc::evm`, `browser::params`, `flow::evm` | yw-app | `rpc::evm`: eth_simulateV1 응답 파서는 M2([09](09-testing.md) §3.8, EVM-V08·V14), RPC 호출·JSON↔코어 타입은 M4. `browser::params`(M5): dApp 파라미터 검증([05](05-browser.md) §3.3–3.4, 이 문서 §3.2). `flow::evm`(M4): 처리 순서(§3.7)·저널 I/O·영수증 추적 | `archive/spec-v2.4:demo/sepolia-wallet/src/rpc.rs:491-524,866-932,1125-1464`, `archive/spec-v2.4:crates/broker/src/params.rs:105-540`, `archive/spec-v2.4:demo/sepolia-wallet/src/backend.rs:3239-3296,3549-3770` |

## 1. 체인 (D14)

### 1.1 체인 정보·내장 체인

yw-app이 내장 상수(아래 표), 사용자 체인 정의(§1.6), 고정 제네시스(§1.4)로 `ChainInfo`를 만들어 yw-core에 넘긴다. "등록된 체인" = 내장 3개 + 사용자 체인.

```rust
pub struct ChainInfo {
    pub chain_id: u64, pub source: ChainSource, pub genesis: GenesisRule,   // §1.4
    pub templates: Option<EndpointTemplates>,             // 내장 체인만 Some, 사용자 체인 None. 설정 화면의 URL 생성 전용(아래), 런타임 엔드포인트(§1.4)에 쓰지 않음
    pub name: String, pub native_symbol: String, pub native_decimals: u8,
    pub explorer: Option<String>,                         // 사용자 체인만, https URL. 표시·링크 전용([04]), RPC에 쓰지 않음
    pub simulation: SimulationSupport,                    // D14·D15, §6
    pub amsterdam_time: Option<u64>,                      // Glamsterdam 활성 unix 초, None = 미정·해당 없음
    pub default_caps: FeeCaps, pub tip_floor_wei: u64,    // §3.4
    pub small_block_gas_limit: Option<u64>,               // HyperEVM 작은 블록(§3.5 대체 가스, E38), 그 밖 None
    pub tokens: &'static TokenRegistry, pub contracts: &'static [KnownContract],   // §1.2, 사용자 체인은 빈 목록
}
pub enum ChainSource { BuiltIn, User }
pub struct EndpointTemplates {                            // D13 입력 템플릿 메타데이터(모두 구현 시 공급자 대시보드와 대조)
    pub quicknode_subdomain: Option<&'static str>,        // None = 서브도메인 없음(Ethereum mainnet)
    pub quicknode_path: Option<&'static str>,             // 토큰 뒤 경로, None = 없음(URL 끝 '/')
    pub alchemy_label: Option<&'static str>,              // None = 알케미 템플릿 없음
}
pub enum GenesisRule { Fixed([u8; 32]), PinOnFirstUse(Option<[u8; 32]>) }   // None = 아직 고정 전(§1.4)
#[repr(u8)] pub enum SimulationSupport { Auto = 1, Unsupported = 2 }        // 설정 문자열 "auto" / "unsupported"
pub struct KnownToken { pub address: Address, pub symbol: &'static str, pub decimals: u8, pub role: TokenRole }
pub type TokenRegistry = [KnownToken];         // 내장 목록만 "등록 토큰"(신뢰 심볼)이다
pub enum TokenRole { Plain, Weth, Dai }
pub struct KnownContract { pub address: Address, pub label: &'static str, pub role: ContractRole }
pub enum ContractRole { Permit2, Seaport16, Seaport15, LabelOnly }
```

| 필드 | Ethereum mainnet | Sepolia | HyperEVM mainnet |
|---|---|---|---|
| `chain_id` | 1 (`0x1`) | 11155111 (`0xaa36a7`) | 999 (`0x3e7`) |
| `genesis` | `Fixed(0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3)` | `Fixed(0x25a5cc106eea7138acab33231d7160d69cb777ee0c2c553fcddf5138993e6dd9)` | `PinOnFirstUse` (하드코딩 없음, §1.4) |
| `templates.quicknode_subdomain` (구현 시 대시보드와 대조) | `None` (서브도메인 없음) | `ethereum-sepolia` | `hype-mainnet` (2026-10 QuickNode 문서 예시) |
| `templates.quicknode_path` (구현 시 대시보드와 대조) | `None` | `None` | `nanoreth` (아래) |
| `templates.alchemy_label` | `eth-mainnet` | `eth-sepolia` | `hyperliquid-mainnet` |
| `name` / `native_symbol` / `native_decimals` | `Ethereum 메인넷` / `ETH` / 18 | `Sepolia 테스트넷` / `SepoliaETH` / 18 | `HyperEVM 메인넷` / `HYPE` / 18 |
| `simulation` | `Auto` (§1.5 A2·A5로 확인) | `Auto` (§1.5 A1·A5로 확인) | `Auto` (§1.5 A9 실측 2026-10-27: QuickNode `/nanoreth` 경로에서 성공, `/evm` 경로는 -32601) |
| `amsterdam_time` | `None` (미정) | `Some(1_791_294_816)` = 2026-10-06 13:53:36 UTC | `None` (해당 없음) |
| `default_caps` (maxFee / tip / 총 최대 수수료) | 200 gwei / 5 gwei / 0.05 ETH | 1,000 gwei / 100 gwei / 1 SepoliaETH | 100 gwei / 10 gwei / 0.05 HYPE (평소 base fee 약 0.1 gwei, 사용자 변경 가능) |
| `tip_floor_wei` | 10,000,000 (0.01 gwei) | 10,000,000 | 10,000,000 |
| 거래 가스 상한 | 16,777,216 (EIP-7825, Fusaka 활성 2025-12-03) | 16,777,216 (Fusaka 활성 2025-10-14) | 16,777,216 (D20). `small_block_gas_limit` = 3,000,000 (Hyperliquid 문서 최신판 값, 구현 시 확인 A9). 큰 블록(30,000,000)은 HyperCore 계정 설정이 필요하고 지갑은 하지 않는다(E38, §14-4) |
| 계정 경로 | m/44'/60'/0'/0/i (D29) | 같음 | 같음 → 세 체인 주소가 같으므로 모든 승인 창 제목에 네트워크 이름을 넣는다 |

템플릿(D13)은 설정 화면([04](04-app-ui.md) §1.9·§2.11)이 저장할 때 네트워크별 URL을 만드는 데만 쓴다: QuickNode 멀티체인 = `https://<이름>.<quicknode_subdomain>.quiknode.pro/<토큰>/`(서브도메인 `None`이면 `https://<이름>.quiknode.pro/<토큰>/`, `quicknode_path`가 있으면 끝 `/` 대신 `/<path>`), 알케미 = `https://<alchemy_label>.g.alchemy.com/v2/<KEY>`. 만든 URL은 `apikeys.dpapi` `rpc:eip155:<chainId>`([04] §6.3)에 저장하고 런타임에는 그 URL만 쓴다(§1.4). 템플릿 값이 틀려도 §1.4 체인 확인(chainId·제네시스)이 다른 네트워크 연결을 막는다. HyperEVM QuickNode 경로: 2026-10 QuickNode 문서는 `/evm`(최근 블록만 보관, 약 12시간마다 정리, `debug_*`·`trace_*` 없음)과 `/nanoreth`(전체 이력)를 둔다. §1.4는 블록 0 해시가 필요하므로 `nanoreth`를 기본으로 두고 A9 (a)(b)를 두 경로로 확인해 정한다(`/evm`이 블록 0과 `eth_simulateV1`을 모두 주면 `/evm`도 가능). HyperEVM testnet(998, HYPE 18)은 내장하지 않고 사용자 체인(§1.6)으로 추가할 수 있다.

그 밖 체인(Hoodi, L2 등)은 내장하지 않는다. 필요하면 사용자 체인(§1.6)으로 추가한다(D14). mainnet `amsterdam_time`이 정해지면 상수를 고친다(설정값 아님). EIP-7708·EIP-2780은 2026-11-01까지 Last Call이므로 mainnet 활성 전 세부가 바뀔 수 있다.

### 1.2 레지스트리

레지스트리 주소만 특수 해석(R3)·라벨·신뢰 심볼을 가진다. 레지스트리는 체인별이고 선택이다(없는 체인도 있다). 표시 라벨은 `[라벨]` 형식으로 주소 뒤에 붙는다. "구현 시 확인" 항목은 M4 `live_probe`(전송·호출 구현 후, M4-13 전; 999는 §1.5 A9 (e))에서 탐색기(Etherscan·HyperEVMScan) 검증 코드·`eth_getCode` 비어 있지 않음(999 Permit2는 immutable 두 값(`chainId`, `DOMAIN_SEPARATOR`)을 가리면 mainnet Permit2와 런타임 코드가 같고 `DOMAIN_SEPARATOR()`가 그 체인의 EIP-712 도메인 값과 같음 — immutable이 코드에 들어가므로 해시 자체는 체인마다 다르다, WHYPE는 Deposit·Withdrawal topic이 WETH9와 같음)을 확인하고 실패하면 표에서 뺀다. 사용자 체인(§1.6)은 레지스트리가 비어 있고 사용자가 주소를 더할 수 없다: WETH·Permit2·Seaport 주소는 알 수 없는 컨트랙트로 취급하고(R3 → `Uninterpreted`, typed data는 T04), ERC-20·721·1155 셀렉터·이벤트 해석은 그대로 한다.

| 체인 | 주소 | 종류 | 값 | 확인 |
|---|---|---|---|---|
| 1 | `0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2` | Token(Weth) | `WETH`, 18 | 확인됨 |
| 1 | `0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48` | Token | `USDC`, 6 | 확인됨(M4) |
| 1 | `0xdAC17F958D2ee523a2206206994597C13D831ec7` | Token | `USDT`, 6 | 확인됨(M4) |
| 1 | `0x6B175474E89094C44Da98b954EedeAC495271d0F` | Token(Dai) | `DAI`, 18 | 확인됨(M4) |
| 11155111 | `0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14` | Token(Weth) | `WETH`, 18 | 확인됨(M4) |
| 11155111 | `0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238` | Token | `USDC`, 6 | 확인됨(M4) |
| 1, 11155111 | `0x000000000022D473030F116dDEE9F6B43aC78BA3` | Permit2 | `Uniswap Permit2` | 확인됨 |
| 1, 11155111 | `0x0000000000000068F116a894984e2DB1123eB395` | Seaport16 | `OpenSea Seaport 1.6` | 확인됨(11155111은 M4, `information()` 버전 `1.6`) |
| 1, 11155111 | `0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC` | Seaport15 | `OpenSea Seaport 1.5` | 확인됨(11155111은 M4, `information()` 버전 `1.5`) |
| 1 | `0x00000000006c3852cbEf3e08E8dF289169EdE581` | LabelOnly | `OpenSea Seaport 1.1(구버전)` | 확인됨 |
| 1 | `0x00000000F9490004C11Cef243f5400493c00Ad63` | LabelOnly | `Seaport ConduitController` | 확인됨 |
| 1 | `0x1E0049783F008A0085193E00003D00cd54003c71` | LabelOnly | `OpenSea Conduit` | 확인됨(M4, ConduitController `getConduit(OPENSEA_CONDUIT_KEY)`) |
| 1 | `0x66a9893cC07D91D95644AEDD05D03f95e1dBA8Af`, `0x4C82D1fBFe28C977cBB58D8C7FF8FCF9F70a2cCA`, `0x23617e59A5925b2A4Bf75d73ff6711cD0b29De85` | LabelOnly | `Uniswap Universal Router` | 확인됨(M4, 코드 있음) |
| 11155111 | `0x3A9D48AB9751398BbFa63ad67599Bb04e4BdF98b`, `0x7DfD4F31be6814D2906BDE155c3e1B146EAc1468`, `0x7E4f6c5e954Da5c61B3423D81E2277431Ac043f3` | LabelOnly | `Uniswap Universal Router` | 확인됨(M4, 코드 있음) |
| 999 | `0x5555555555555555555555555555555555555555` | Token(Weth) | `WHYPE`, 18 | 확인됨(M4, WETH9 topic) |
| 999 | `0x000000000022D473030F116dDEE9F6B43aC78BA3` | Permit2 | `Uniswap Permit2` | 확인됨(M4, immutable 제외 코드 일치) |

999에는 Seaport·토큰(USDC 등)을 넣지 않는다.

상수 `OPENSEA_CONDUIT_KEY = 0x0000007b02230091a7ed01230072f7006a004d60a8d4e71d599b8104250f0000`(Seaport 표시용 라벨, 확인됨: mainnet ConduitController가 이 키로 `OpenSea Conduit` 주소·`exists = true`를 돌려줌, M4 `live_probe`).

### 1.3 네이티브 이동 로그 (Glamsterdam, 모든 체인)

규칙은 모든 등록 체인(내장·사용자)에 같다. Ethereum이 아닌 체인은 `amsterdam_time = None`이라 3항 기대값이 `ERC7528_NATIVE`이지만, 어느 발신자가 나와도 2항대로 센다. value > 0인데 두 발신자 로그가 모두 없으면 E04(결과 불완전, 고위험, §6.3).

```
TRANSFER_TOPIC  = 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
ERC7528_NATIVE  = 0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee   // traceTransfers 합성 로그(Glamsterdam 전)
EIP7708_SYSTEM  = 0xfffffffffffffffffffffffffffffffffffffffe   // 프로토콜 로그(Glamsterdam 후)
```

1. **네이티브 로그 모양**: `address ∈ {ERC7528_NATIVE, EIP7708_SYSTEM}`, `topics.len()==3`, `topics[0]==TRANSFER_TOPIC`, `topics[1..3]` 상위 12바이트 0, `data.len()==32`. 두 주소에서 나온 로그가 이 모양이 아니면 응답 이상(E01).
2. **발신자 선택**: 호출 결과에 `EIP7708_SYSTEM` 네이티브 로그가 1개라도 있으면 그것만 센다. 없으면 `ERC7528_NATIVE` 로그를 센다. **둘을 함께 세지 않는다.** 선택되지 않은 쪽 로그는 diff·기타 이벤트 어디에도 넣지 않는다.
3. **포크 기대값**: `expected = if amsterdam_time.is_some_and(|t| sim_block.timestamp >= t) { EIP7708_SYSTEM } else { ERC7528_NATIVE }`. 선택된 발신자 ≠ expected이면 사용자 경고 없이 로컬 로그에 `native-emitter-mismatch`만 남긴다(주소 미기록, D28).
4. 비교는 바이트로 한다(geth는 소문자로 출력). 21,000 가스를 하드코딩하지 않는다. Glamsterdam 후 Sepolia에서 새 계정으로의 ETH 전송은 204,600(`0x31f38`) 가스다(EIP-2780/8037). 항상 `eth_estimateGas`(§3.5)를 쓴다.

### 1.4 RPC 사용 규칙

- **엔드포인트(D13)**: `endpoint(chain)` = [04](04-app-ui.md) §6.3 `apikeys.dpapi`의 `rpc:eip155:<chainId>` URL([04] §1.9 `RpcConfig`). 없으면 엔드포인트 없음: read는 [05](05-browser.md) §5 `ChainUnavailable`(4901), 보내기·서명은 E35 차단(원인 "RPC 엔드포인트 없음"). 템플릿(§1.1 `templates`)·공급자 자격 정보로 URL을 만들어 대신 쓰지 않는다(대체 경로 없음). 아래 규칙은 어느 공급자·체인이든 같다.
- **체인 확인**: 연결마다(앱 실행 후, 그리고 그 체인 URL 변경 후 그 체인의 첫 EVM RPC 전에) `eth_chainId` 결과 문자열 == `chain_id`의 정규 hex(소문자 변환 후 비교)이고, `h = eth_getBlockByNumber(["0x0", false]).hash`(결과가 객체가 아니거나 `hash`가 32바이트가 아니면 전송 오류와 같다)가 `genesis` 규칙을 만족해야 한다: `Fixed(g)`·`PinOnFirstUse(Some(g))` → `h == g`. `PinOnFirstUse(None)`(HyperEVM 첫 사용) → chainId가 맞으면 `h`를 고정값으로 저장([04] §6)하고 저장 성공 후 `Verified`(최초 신뢰: 첫 연결의 RPC가 거짓이면 이후 올바른 RPC에서 불일치로 막히고, 사용자가 [04]에서 고정을 지운 뒤 다시 연결한다). 사용자 체인은 추가 때 고정한다(§1.6). 불일치 → 그 체인 상태 `RpcMismatch`: 읽기는 `ChainUnavailable`, 보내기·서명은 E34 "RPC 체인 불일치"(차단)(앱 재시작 또는 그 체인 `rpc:eip155:<chainId>` URL 변경 전까지 — 템플릿 자격 정보를 바꿔 URL이 다시 만들어진 경우 포함; URL이 바뀌면 상태를 초기화하되 고정 제네시스는 지우지 않는다). 전송 오류 → 150 ms 간격 3회 재시도 후 `Unverified`(다음 사용 때 재시도, 보내기·서명은 E35). `eth_sendRawTransaction` 직전마다 `eth_chainId`를 다시 확인한다.
- **내부 사용 메서드**: `eth_chainId`, `eth_blockNumber`, `eth_getBlockByNumber`, `eth_getTransactionCount`, `eth_getBalance`, `eth_getCode`, `eth_call`, `eth_estimateGas`, `eth_feeHistory`, `eth_simulateV1`, `eth_sendRawTransaction`, `eth_getTransactionByHash`, `eth_getTransactionReceipt`. `simulation = Unsupported` 체인에는 `eth_simulateV1`을 보내지 않는다(E36). 금지: 공급자 전용 메서드(`alchemy_*`·`qn_*` 등; `alchemy_simulate*`는 2026-09-30 종료), `debug_*`, `trace_*`.
- **시간 제한**: 호출당 10 s. 요청 준비 전체(§3.7 단계 3–9) 30 s: 단계 3–7에서 넘으면 E35(차단), 단계 8에서 넘으면 시뮬레이션 결과 없음(`Timeout`, E01 고위험), 단계 9에서 넘으면 남은 사실 조회를 실패로 보고 E27.
- **응답 크기**: `eth_simulateV1` 4 MiB, 그 밖 1 MiB. 초과 → 해당 호출 실패(시뮬레이션은 `TooLarge`, E01).
- **문자열**: RPC `error.message`는 화면에 표시하지 않는다(spec §2.1). 표시는 §6.3 코드 매핑만 쓴다. 엔드포인트 URL은 전체가 비밀이다(D13): URL·호스트·경로·토큰을 로그·오류 문구·승인 창에 쓰지 않는다(QuickNode 호스트에는 엔드포인트 이름이 들어 있다). 로그는 `NetworkId`(`eip155:<chainId>`)만 쓴다(D28, [01] §4.6과 같은 규칙). 설정 화면 표시는 [04] §2.11이 정한다. JSON 파싱: 알려지지 않은 필드는 무시한다(`maxUsedGas`, `blockAccessListHash`, `slotNumber` 등). 필수 필드 누락·형식 위반은 실패.

### 1.5 구현 시 확인 (설정한 공급자(현재 QuickNode)의 엔드포인트로 A1–A8은 M2 전, A9·A10은 M4 전에 수행, 공급자·엔드포인트 URL을 바꾸면 그 네트워크에서 다시 수행)

- 도구: A1–A5와 A9 (a)(b)는 `scripts/probe-rpc.mjs`([01](01-repo-build.md) §4.7)로 한다. 엔드포인트는 저장소 밖 개발 설정 `%USERPROFILE%\.yw-dev\rpc.json` 또는 `YW_RPC_JSON`이 가리키는 파일([01] §4.6, 키 `eip155:1`·`eip155:11155111`·`eip155:999`)에서 읽는다. 출력에는 `NetworkId`만 있으므로 그대로 `docs/acceptance/probe-<YYYYMMDD>.md`에 기록한다. A6–A8, A9 (c)–(e), A10은 같은 설정으로 손으로 확인한다.
- **실측 결과(2026-10-27, QuickNode, `scripts/probe-rpc.mjs`)**: Ethereum mainnet — `eth_simulateV1` 지원, 네이티브 로그 발신자 `0xeeee…`, 새 주소 1 wei 전송 21,000 gas, revert `status 0x0`·`error.code 3`·`error.data 0xdeadbeef`, `chainId`·`type` 필드 수락, 잔액 부족은 최상위 -38014, `maxUsedGas` 있음. Sepolia — 지원, 발신자 `0xff…fe`(Glamsterdam 후), 새 주소 전송 **204,600 gas**, **자기 자신 전송은 로그 없음·12,000 gas**, revert 15,018 gas, base fee ≈ 0. HyperEVM(999) — `/evm` 경로는 `eth_simulateV1` -32601·블록 0 조회 실패(-32603), `/nanoreth` 경로는 블록 0 해시 `0xd8fcc13b6a195b88b7b2da3722ff6cad767b13a8c1e9ffb1c73aa9d216d895f0`(최초 신뢰 고정 대상), `eth_simulateV1` 지원(발신자 `0xeeee…`, 자기 자신 전송도 로그 있음), 잔액 부족은 **최상위 -32003**, `maxUsedGas` 없음, 최근 블록 `gasLimit` 3,000,000, base fee 0.2–1.0 gwei. A1–A5·A9 (a)(b)(d)는 이 결과로 판정 완료, 공급자·URL을 바꾸면 다시 수행한다.
- **M4 `live_probe` 결과(2026-10-27, 같은 설정, `docs/acceptance/m4-live-20261027.md`)**: A6 — 세 체인 모두 `pending` 태그 수락, 최근 송신자 12명 중 `pending > latest`가 Sepolia 1–2명·999 0–1명(멤풀 반영), mainnet 0명(자기 전송 직후 확인은 M4-2). A7 — 1·11155111·999 모두 baseFee 11개·reward 10×1. A8 — 조용한 컨트랙트 10,000블록 `eth_getLogs` 수락(1: 0개, 11155111: 1개), mainnet WETH Transfer 10,000블록은 응답이 클라이언트 4 MiB 한도를 넘음(공급자 오류가 아니라 응답 크기, 2.5–7 s), `eth_simulateV1`(`stateOverrides`) 35–280 ms. A9 (c) — 999 `eth_feeHistory` 정상, 최근 70블록(큰 블록 30,000,000 1개 포함) base fee는 작은 블록 0.1–0.117 gwei, 큰 블록 0.1 gwei로 같은 범위라 `eth_feeHistory`에 큰 블록이 섞여도 §3.4 제안값이 튀지 않음, type 2 `eth_estimateGas` 21,000 수락 (d) 작은 블록 3,000,000 (e) §1.2 999 행 확인. 앱 경로(`check_chain`·`prepare`, 서명·전송 없음)로 세 체인 체인 확인 통과(999 블록 0 해시 = §1.5 1차 실측 값)와 시뮬레이션 `Ok` 승인 초안 생성도 확인했다.
- 시뮬레이션 지원: 2026-10 QuickNode 문서에는 일부 체인(예: Arbitrum)의 `eth_simulateV1` 페이지만 있었지만 위 실측에서 1·11155111·999(`/nanoreth`) 모두 동작했다. 그래서 내장 체인마다 `simulation` 상수(§1.1)를 `Auto`로 둘지는 그 체인의 A1(Sepolia)·A2(mainnet)·A5 결과로 정한다(999는 A9 (b)). 성공하면 `Auto` 유지, -32601·플랜 거부로 쓸 수 없으면 그 네트워크의 URL만 `eth_simulateV1`을 지원하는 공급자 URL로 바꾸거나(D13: 네트워크마다 공급자를 따로 고를 수 있다) 상수를 `Unsupported`로 바꾼다(§14-2).

| # | 확인 내용 | 기대 | 다를 때 |
|---|---|---|---|
| A1·A2 | Sepolia·mainnet `eth_simulateV1`(§6.1)로 새 주소에 1 wei 전송 | Sepolia: 발신자 `0xff…fe`, gasUsed `0x31f38` / mainnet: `0xeeee…`, `0x5208` | 발신자가 다르면 §1.3 규칙 그대로 동작(조치 없음). 네이티브 로그가 전혀 없으면 그 공급자에서 모든 value>0 거래에 E04(고위험)가 붙음 → §14-2 |
| A3 | 호출 객체의 `chainId`, `type` 필드 수락 | 성공 | -32602면 두 필드를 빼고 보낸다(체인은 §1.4로 이미 고정) |
| A4 | revert 호출의 오류 형태 | `status 0x0`, `error.code 3`, `error.data` | 다른 코드면 §6.3 "그 밖" 행으로 처리 |
| A5 | 설정한 공급자(현재 QuickNode)의 현재 플랜·엔드포인트에서 체인별(1·11155111) `eth_simulateV1` 사용 가능(-32601·HTTP 401/403·플랜 거부 없음) | 가능 | 불가면 그 체인 모든 거래에 E01(고위험)이 붙음. 서명은 가능(D15) → 그 네트워크 URL을 지원 공급자로 변경 또는 그 체인 `simulation` 상수 `Unsupported`(§14-2) |
| A6 | `eth_getTransactionCount(…, "pending")`이 멤풀을 반영 | 반영 | 반영 안 하면 §3.6 외부 대기 거래 검사가 약해짐(기능 유지, 메모만) |
| A7 | `eth_feeHistory(["0xa","latest",[50]])` | 11개 baseFee, 10×1 reward | reward 없으면 E35(그 체인 보내기 불가) |
| A8 | `eth_getLogs` 범위·결과 한도, `eth_simulateV1` 응답 시간 | 10,000블록 수락, < 10 s | 상위 오류는 [05](05-browser.md) §3.5 정화 후 dApp에 전달; 시간 제한은 바꾸지 않는다 |
| A9 | HyperEVM(999, `eip155:999` 엔드포인트; QuickNode면 `/nanoreth`·`/evm` 두 URL 각각, §1.1): (a) `eth_chainId`, 블록 0 해시 (b) §6.1 형식 1 wei 전송 `eth_simulateV1` (c) `eth_feeHistory` 모양(A7), type 2 전송 수락, 작은·큰 블록 base fee가 섞이는지 (d) 최근 작은 블록 `gasLimit` (e) §1.2의 999 행 | (a) `0x3e7`, 해시 받음 (b) 성공 + 네이티브 로그(발신자 기록) (c) A7과 같고 EIP-1559 정상 (d) 3,000,000 (e) 확인됨 | (a) 블록 0을 못 받는 경로는 템플릿 `quicknode_path`로 쓰지 않는다. 어느 URL로도 못 받으면 999 체인 확인 불가 → §14-4 (b) 되면 999 `simulation` 상수를 `Auto`로, 안 되면 `Unsupported` 유지(E36) (c) §14-4 (d) `small_block_gas_limit` 상수를 관측값으로 (e) 실패 행은 표에서 뺀다 |
| A10 | 사용자 체인(§1.6): HyperEVM testnet 998을 설정한 공급자 URL(템플릿 또는 직접 입력)로 추가 → 재연결; chainId를 997로 입력; 998의 RPC를 다른 공급자 https URL로 변경 | 일치·블록 0 고정·재연결 통과 / 거부·저장 없음 / 같은 제네시스로 저장 | §1.6 절차를 고친다 |

### 1.6 사용자 EVM 체인 (D14, M4)

사용자는 yw-app 설정([04])에서만 체인을 추가·수정·삭제한다. dApp의 `wallet_addEthereumChain`은 거부한다([05]). 정의와 고정 제네시스의 저장 위치·형식은 [04] §6이 정하고, https RPC URL은 [04] §6.3 `rpc:eip155:<chainId>`에 둔다(D13). 공급자 템플릿으로 입력하면 [04] §2.17이 저장할 때 URL로 만든다. 이 문서의 절차는 그 URL만 다룬다(사용자 체인 `templates = None`).

```rust
pub struct UserChainInput { pub chain_id: u64, pub name: String, pub native_symbol: String, pub native_decimals: u8,
    pub explorer: Option<String>, pub simulation: SimulationSupport }
// RPC URL은 여기 없다: yw-app이 HttpsUrl::parse로 검사하고 apikeys.dpapi rpc:eip155:<chainId>에 둔다(아래 RPC 행)
pub fn validate_user_chain(i: &UserChainInput, registered: &[u64]) -> Result<(), ChainConfigError>;   // yw-core
pub fn user_chain_info(i: &UserChainInput, genesis: [u8; 32]) -> ChainInfo;                           // 아래 고정값
```

| 필드 | 규칙 (위반 → 저장 거부, `ChainConfigError`) |
|---|---|
| chainId | 1 ≤ id ≤ 9,223,372,036,854,775,771(EIP-2294), 등록된 체인(내장 포함)과 겹치지 않음. 추가 뒤 바꿀 수 없다(삭제 후 다시 추가) |
| 이름 | UTF-8 1–32자(≤ 96바이트), §9.2 이스케이프 대상 문자 없음, 앞뒤 공백 없음, 내장 체인 이름과 같지 않음(대소문자 무시). 승인 제목 `[{이름}]`에 쓴다 |
| 네이티브 심볼 / 소수 자릿수 | 0x21–0x7E 1–16자 / 0–36 |
| RPC (yw-app) | https URL 하나(직접 입력 또는 [04] §2.17 템플릿이 만든 URL), yw-win `HttpsUrl::parse`([01] §7.4). 필수(없으면 추가 불가). 로그에는 `NetworkId`만(§1.4), 화면 표시는 [04] |
| 탐색기 URL | 선택, `HttpsUrl::parse` |
| `simulation` | `auto`(기본) / `unsupported` |

고정값: `source = User`, `templates = None`, `tokens`·`contracts` 빈 목록(§1.2), `amsterdam_time = None`, `small_block_gas_limit = None`, `default_caps` = maxFee 1,000 gwei / tip 100 gwei / 총 0.05(네이티브 단위), `tip_floor_wei = 10,000,000`. 상한은 [04] 설정에서 §3.4-7 범위로 바꾼다.

추가 절차(yw-app `rpc::evm`, 각 호출 §1.4 제한):
1. `validate_user_chain`.
2. 입력한 RPC URL로 `eth_chainId` → 입력 chainId의 정규 hex와 같아야 한다. 다르면 거부 "RPC의 chainId({10진})가 입력한 값과 다릅니다"(저장 없음).
3. `eth_getBlockByNumber(["0x0", false]).hash`(32바이트) → 고정값. 못 받으면 거부 "블록 0을 받을 수 없습니다".
4. `eth_feeHistory(["0x1","latest",[50]])`에 `baseFeePerGas`가 있어야 한다(EIP-1559, D19). 없으면 거부 "EIP-1559를 지원하지 않는 체인입니다".
5. 정의·고정 제네시스·URL 저장(모두 성공해야 등록) → 그 체인 `Verified`. 이후 연결마다 §1.4 체인 확인(불일치 → `RpcMismatch`, E34).

수정: RPC를 바꾸면 저장 전에 2·3단계를 다시 해서 chainId와 고정 제네시스가 같아야 한다(다르면 저장 거부). 이름·심볼·소수 자릿수·탐색기·`simulation`은 다음 요청 준비부터 반영한다. 삭제: 그 체인에 미종결 저널 레코드(§5)가 있으면 거부한다. 삭제된 체인을 가리키던 활성 체인·사이트 권한 처리는 [04]·[05]가 정한다.

## 2. 주소·금액

### 2.1 주소 파싱 (EIP-55)

`pub fn parse_address(s: &str) -> Result<Address, AddressError>` (`Address = [u8; 20]` newtype)

1. 정확히 42바이트, 접두 `0x`(소문자 x; `0X` 거부), 40개 hex 숫자.
2. 문자(a–f/A–F)가 모두 소문자 → 수락. 모두 대문자 → 수락. 섞여 있음 → `to_checksum(addr)`와 바이트 단위로 같아야 수락, 아니면 `BadChecksum`.
3. 적용 대상: dApp 파라미터, typed data 주소 값, SIWE address, 사용자 입력(받는 주소), 주소록. 아카이브의 소문자 전용 규칙(`archive/spec-v2.4:crates/wallet-model/src/bounded.rs:354-360`)과 그것을 고정한 테스트(`archive/spec-v2.4:crates/broker/src/params.rs:707-726`)는 뒤집는다.
4. 0 주소도 파싱은 성공한다(위험 규칙 E18이 처리).

`to_checksum`: 소문자 hex 40자의 Keccak-256에서 i번째 니블 ≥ 8이면 i번째 문자를 대문자로(`archive/spec-v2.4:crates/wallet-protocol/src/authorization.rs:818-837`).

### 2.2 내부 표현·표시

- 내부: `Address([u8;20])`. RPC·JSON 출력은 소문자 `0x…`.
- 표시: EIP-55 체크섬 전체 주소를 4자 묶음으로: `"0x" + g1 + " " + g2 + … + " " + g10`. 예: `0x5aAe b605 3F3E 94C9 b9A0 9f33 6694 35E7 Ef1B eAed`. 승인 창에서 자르지 않는다.
- 라벨: 레지스트리 `[Uniswap Permit2]`, 주소록 `[주소록: {이름}]`(이름은 §9.2 이스케이프). 라벨은 주소를 대체하지 않는다.

### 2.3 U256

wallet-model `U256`(`[u8;32]` BE, `checked_mul`만 있음)에 산술을 더해 `yw-core::evm::amount::U256`으로 둔다(`#![deny(clippy::arithmetic_side_effects)]`, [01](01-repo-build.md) §5.2).

```rust
impl U256 {                                     // Ord 구현, Debug는 값 노출 허용(비밀 아님)
    pub const ZERO: Self; pub const MAX: Self;
    pub fn from_u64(v: u64) -> Self;  pub fn from_be_slice(b: &[u8]) -> Option<Self>;   // ≤ 32바이트
    pub fn to_be_bytes(self) -> [u8; 32];  pub fn minimal_be(&self) -> &[u8];           // 0이면 빈 슬라이스(RLP)
    pub fn to_u64(self) -> Option<u64>;
    pub fn checked_add(self, o: Self) -> Option<Self>;  pub fn checked_sub(self, o: Self) -> Option<Self>;
    pub fn checked_mul(self, o: Self) -> Option<Self>;  pub fn checked_mul_u64(self, m: u64) -> Option<Self>;
    pub fn div_rem_u64(self, d: NonZeroU64) -> (Self, u64);
    pub fn ceil_mul_div_u64(self, num: u64, den: NonZeroU64) -> Option<Self>;          // ⌈self·num/den⌉
    pub fn parse_quantity_lenient(s: &str) -> Result<Self, ParseValueError>;           // ^0x[0-9a-fA-F]{1,64}$
    pub fn to_quantity(self) -> String;         // EIP-1474 정규형(소문자, 앞 0 없음, 0 → "0x0")
    pub fn to_decimal_string(self) -> String;
}
pub enum Delta { Zero, In(U256), Out(U256) }    // Σin − Σout 결과
// 수수료·금액 계산은 전부 checked 연산, 포화·래핑 금지. 오버플로: 수수료·가스 계산은 E05(차단), diff 합산은 E09(고위험)
```

### 2.4 금액 형식

- `format_units(v: &U256, decimals: u8) -> String`: 정확한 10진. 정수부는 3자리마다 `,`, 소수부는 끝 0 제거, 소수부가 없으면 `.` 없음, 반올림 없음. 0 → `0`.
- `format_amount(v, decimals, symbol)` = `format_units + " " + symbol`. 무제한(§10, 타입 최댓값)은 숫자 대신 `무제한`.
- gwei: `format_units(v, 9) + " gwei"`. 승인 창의 모든 금액은 이 함수로만 만든다(wei hex 표시 금지).
- `parse_units(s: &str, decimals: u8) -> Result<U256, AmountError>`(사용자 입력): 문법 `^(0|[1-9][0-9]*)(\.[0-9]+)?$`, 소수 자릿수 ≤ decimals, 길이 ≤ 128, 오버플로 오류. `+`, `-`, 지수, 공백, `,`, `.5`, `5.` 거부.
- 벡터: `format_units(1234567890000000000, 18)` = `1.23456789`; `format_units(10^24, 18)` = `1,000,000`; `format_units(1, 18)` = `0.000000000000000001`; `format_units(21000000000, 9)` = `21`; `parse_units("0.1", 18)` = `100000000000000000`; `parse_units("1.0000001", 6)` = 오류.

### 2.5 토큰 메타데이터

- 레지스트리 토큰: 표의 symbol·decimals만 쓰고 RPC를 부르지 않는다.
- 그 밖: `eth_call` at `latest`로 `decimals()`(`0x313ce567`), `symbol()`(`0x95d89b41`).
  - decimals: 결과가 정확히 32바이트, 상위 31바이트 0, 값 ≤ 36. 실패·초과 → 원시 단위(정수) + `(원시 단위)` 표시 + E25.
  - symbol: `archive/spec-v2.4:demo/sepolia-wallet/src/erc20.rs:156-201` 디코더(빈 값, bytes32, 정규 동적 string). 허용 문자 0x21–0x7E, 1–16자. 실패 → `?` + E26.
  - 미등록 토큰 심볼 뒤에 항상 `(미확인)`을 붙이고 컨트랙트 주소를 함께 보인다(E33).
- 캐시: (chain_id, address)별 앱 실행 중 메모리 캐시(디스크에 쓰지 않음). 한 승인 요청에서 조회하는 토큰 ≤ 16, 주소 분류(§8.5) ≤ 16. 넘으면 나머지는 원시 표시 + E27.

## 3. 트랜잭션 모델

### 3.1 타입

```rust
pub struct Eip1559Tx {                      // 필드 순서 = RLP 순서
    pub chain_id: u64, pub nonce: u64,
    pub max_priority_fee_per_gas: U256, pub max_fee_per_gas: U256, pub gas_limit: u64,
    pub to: Address,                        // 배포 없음(D19)
    pub value: U256, pub data: Vec<u8>,     // data ≤ 131,072
    pub access_list: Vec<AccessListItem>,   // ≤ 256 항목, 항목당 키 ≤ 256, 주소 중복 금지
}
pub struct AccessListItem { pub address: Address, pub storage_keys: Vec<[u8; 32]> }
```

불변식: `max_priority_fee_per_gas ≤ max_fee_per_gas`, `gas_limit ≤ 16_777_216`, `chain_id`는 등록된 체인(§1.1 내장, §1.6 사용자)의 값. type 0/1/3/4 거래와 blob은 만들지 않는다(D19). legacy 인코더는 `#[cfg(test)]`에만 둔다(EIP-155 벡터용).

### 3.2 `eth_sendTransaction` 파라미터 검증

`params`는 길이 1 배열, 원소는 객체. 키는 아래 허용 목록과 정확히 일치해야 한다(이식: `archive/spec-v2.4:crates/broker/src/params.rs:415-519`). 위반은 창 없이 즉시 오류(§11.6).

- quantity: `^0x[0-9a-fA-F]{1,64}$`(대소문자·앞 0 허용, 내부 정규화). `gas`·`nonce`·`type`·`chainId`는 u64 범위.
- hex data: `^0x([0-9a-fA-F]{2})*$`, ≤ 131,072바이트.

| 키 | 규칙 | 위반 코드 |
|---|---|---|
| `from` | 필수, §2.1, 이 origin에 연결된 계정과 같음 | 형식 -32602 / 불일치 4100 |
| `to` | 필수, null 금지, §2.1 | -32602 |
| `value` | 선택, quantity, 기본 0 | -32602 |
| `data`, `input` | 선택, hex data. 둘 다 있으면 디코드한 바이트가 같을 때만 수락 | -32602 |
| `gas` | 선택, ≤ 16,777,216 | -32602 |
| `nonce` | 선택. 있으면 §3.6에서 정한 nonce와 같아야 함(§3.7 단계 4에서 판정: 다르면 준비 중이던 창을 닫고 -32602, 실패 표시 없음) | -32602 |
| `type` | 선택, 값 0 또는 2 (1·3·4·그 밖 거부, D19) | -32602 |
| `chainId` | 선택, 활성 체인과 같음 | -32602 |
| `gasPrice`, `maxFeePerGas`, `maxPriorityFeePerGas` | 선택, quantity 형식만 검사, 값은 버림(D20). 하나라도 있으면 E31 | -32602 |
| `accessList` | 선택, 배열 ≤ 256, 원소는 정확히 `{address, storageKeys}`, `storageKeys` ≤ 256개 32바이트 hex, 주소 중복 금지 | -32602 |
| 그 밖(`authorizationList`, `blobVersionedHashes`, `blobs`, `maxFeePerBlobGas`, `commitments`, `proofs` 포함) | 거부 | -32602 |

### 3.3 지갑 자체 보내기 (yw-app, origin `yw-app`)

네이티브(ETH·HYPE 등)는 `to`=받는 주소, `value`=금액(`native_decimals`), `data` 빈 값. ERC-20은 `to`=토큰, `value`=0, `data`=`0xa9059cbb ‖ pad32(recipient) ‖ amount_be32`(68바이트, `archive/spec-v2.4:demo/sepolia-wallet/src/erc20.rs:138-144`). 이후 단계는 dApp 요청과 같다(§3.7).

### 3.4 수수료 (D20)

dApp 수수료 값은 쓰지 않는다. 지갑이 `eth_feeHistory(["0xa", "latest", [50]])`로 계산한다.

```rust
pub struct FeeHistory { pub base_fee_per_gas: Vec<U256>, pub nonempty: Vec<bool>, pub reward_p50: Vec<U256> }
// nonempty[i] = gasUsedRatio[i]의 JSON 숫자 토큰이 0이 아님(부동소수 연산을 쓰지 않는다)
pub struct Fees { pub max_priority_fee_per_gas: U256, pub max_fee_per_gas: U256, pub base_fee_next: U256 }
pub struct FeeCaps { pub max_fee_per_gas: U256, pub max_priority_fee_per_gas: U256, pub max_total_fee: U256 }
pub fn suggest_fees(h: &FeeHistory, chain: &ChainInfo) -> Result<Fees, FeeError>;
pub fn check_caps(f: &Fees, gas_limit: u64, caps: &FeeCaps) -> Result<(), CapViolation>;
```

1. 검증: `n = reward_p50.len()`, 1 ≤ n ≤ 10, `nonempty.len()==n`, `base_fee_per_gas.len()==n+1`. 위반·조회 실패 → E35(차단).
2. `base_fee_next = base_fee_per_gas[n]`.
3. 표본 = `nonempty[i]`인 블록의 `reward_p50[i]`. 정렬 후 하위 중앙값 `s[(len-1)/2]`. 표본 없음 → `tip_floor_wei`.
4. `tip = max(중앙값, tip_floor_wei)`.
5. `max_fee = 2 × base_fee_next + tip` (checked).
6. 상한(§1.1 내장·§1.6 사용자 체인 기본값, 사용자가 [04] 설정에서 변경): `tip ≤ caps.max_priority_fee_per_gas`, `max_fee ≤ caps.max_fee_per_gas`, `gas_limit × max_fee ≤ caps.max_total_fee`. 하나라도 넘으면 E05(차단, 계산값과 상한을 함께 표시). 자동으로 낮추지 않는다.
7. 설정 범위: maxFee 상한 1–10,000 gwei, tip 상한 0.01–10,000 gwei이고 maxFee 상한 이하, 총 상한 0.0001–10(네이티브 단위).

벡터: n=10, 블록 1개 `nonempty`=false, 나머지 reward(gwei) `[0.5,1,2,1.5,3,1,2,0.8,1.2]`, `base_fee_next`=10 gwei → tip 1.2 gwei, maxFee 21.2 gwei.

### 3.5 가스 한도 (D20)

1. `eth_estimateGas([{from, to, value, input, accessList?}, "latest"])`(수수료·gas 필드 없음). 성공 → `estimate`. 오류(revert·실행 오류·최상위 RPC 오류·전송 오류·시간 초과) → 차단하지 않는다: E37 고위험 "가스 추정 실패 — 거래가 실패할 수 있습니다"(revert면 둘째 줄에 `error.data`의 §7.4 해석), 4로.
2. `margin = ⌈estimate × 12 / 10⌉`.
3. `estimate > 16_777_216` → E10(차단, D20). 그 밖 `gas_limit = min(max(dapp_gas.unwrap_or(0), margin), 16_777_216)`.
4. 추정 실패 시 대체 가스: dApp `gas`가 있으면 그 값. 없으면 `min(16_777_216, small_block_gas_limit.unwrap_or(16_777_216), ⌊caps.max_total_fee / max_fee⌋)`(§3.4 수수료를 먼저 구하므로 총 상한 E05에 걸리지 않는 가장 큰 값. < 21,000이면 그대로 두고 시뮬레이션 -38013 → E01).
5. 시뮬레이션은 이 `gas_limit`으로 한다(§6.1). 21,000 고정값은 어디에도 없다.
6. `small_block_gas_limit = Some(s)`(HyperEVM)이고 `gas_limit > s` → E38 주의.

벡터: estimate 21,000, dApp 없음 → 25,200; estimate 204,600, dApp 0x30000(196,608) → 245,520; estimate 50,000, dApp 100,000 → 100,000; estimate 15,000,000 → 16,777,216; 추정 실패, dApp 없음, mainnet maxFee 25 gwei·총 상한 0.05 ETH → 2,000,000(E37); 추정 실패, dApp 0x30d40 → 200,000; HyperEVM 추정 실패, maxFee 0.2 gwei·총 상한 0.05 HYPE → 3,000,000(E38 없음); HyperEVM estimate 2,500,000 → 3,000,000(E38 없음, 같으면 주의 아님); HyperEVM estimate 2,600,000 → 3,120,000(E38).

### 3.6 nonce·진행 중 거래 1건 (D20)

```
reconcile(chain, account)                      // §5.4: 저널의 미종결 레코드 상태 갱신
if journal.has_non_terminal(chain, account) → E06 "진행 중인 거래가 있습니다 (nonce N)"
latest  = eth_getTransactionCount(account, "latest")
pending = eth_getTransactionCount(account, "pending")
if pending != latest → E06 "이 계정에서 다른 곳으로 보낸 대기 중 거래가 있습니다"
nonce = latest
```

- E06은 차단 창으로 보여 주고(창을 닫으면 4001), 앱 화면에서 속도 올리기·취소(§4.6)로 안내한다. dApp이 approve 직후 영수증을 기다리지 않고 swap을 보내면 두 번째 요청은 E06이 된다(D20의 의도된 결과).
- 송신 슬롯: (chain, account)마다 승인 요청 생성부터 저널 `Signed` 기록 또는 거절·만료까지 슬롯 1개를 잡는다. 슬롯이 잡힌 동안 같은 (chain, account)의 새 `eth_sendTransaction`은 창 없이 -32002 `Transaction already pending.`([05](05-browser.md) §5 `TransactionPending`).

### 3.7 처리 순서 (`eth_sendTransaction`, 지갑 보내기 공통)

| 단계 | 동작 | 실패 |
|---|---|---|
| 1 | §3.2 검증 → `TxIntent` (지갑 보내기는 생략) | 즉시 오류 |
| 2 | 송신 슬롯 획득 | -32002 (§3.6) |
| 3 | 체인 확인(§1.4) | 차단 E34(불일치)·E35(미확인·엔드포인트 없음) |
| 4 | `eth_getCode(account)` → E17 판정; §3.6 nonce; 저널 자리(§5.4-4) | E06, 조회 실패 E35 |
| 5 | §3.4 수수료 | E05, 조회 실패 E35 |
| 6 | §3.5 가스 | E10; 추정 실패는 E37(고위험)·대체 가스로 계속 |
| 7 | `Eip1559Tx` 구성, `preimage.len() + 70 ≤ 131,072`(서명 3필드·리스트 머리 증가분 상한 70) | E11 |
| 8 | §6 시뮬레이션(항상 시도, `simulation = unsupported`면 호출 없이 E36) | E01–E04, E07, E36 (고위험, 계속) |
| 9 | §7 해석, §6.4 diff, 사실 조회(§2.5, §8.5, 승인 토큰 `balanceOf`) | E08·E09(고위험), 개별 경고 |
| 10 | §10 위험 → §11 `ApprovalDraft` → 승인 창([04](04-app-ui.md))이 Ready를 표시할 때 `issue`(§11.5) | — |
| 11 | 클릭 → §6.6 신선도 → §11.5 소비 → §4.2 서명(키 작업 스레드, [02] `with_secp_key`) → §4.3 검증 → §5 저널 `Signed` → §4.4 전송 → 응답 | §4.3 실패 시 아무것도 저장·전송하지 않음 |

차단 조건(§10.4 목록)이 생기면 남은 RPC 단계를 건너뛰고 그때까지 구한 필드와 차단 경고로 승인 요청을 만든다(거부 버튼만 활성, 바인딩 `SimulationBinding::None { reason: Skipped }`). 단, 단계 3–4의 차단(E34·E35·E06)은 서명할 거래(nonce·수수료)가 정해지기 전이므로 요청을 만들지 않고 승인 창 `Failed`([04] §3.5, 그 경고 문구, 거부만)로 끝낸다. 단계 5–7의 차단(E05·E10·E11)은 위처럼 차단 요청을 만든다. 시뮬레이션·가스 추정이 성공하지 못한 것은 차단 조건이 아니다(D15): 경고를 더하고 다음 단계로 계속한다.

## 4. 인코딩·서명·전송

### 4.1 RLP (단일 구현, D6)

인코더(이식 `archive/spec-v2.4:crates/secret-core/src/signing.rs:167-248`, 포화 연산을 정확한 연산으로 교체):
- 바이트열 b: `len==1 && b[0]<0x80` → b; `len≤55` → `0x80+len ‖ b`; 그 밖 → `0xb7+len(L) ‖ L ‖ b`(L = len의 최소 BE).
- 리스트 payload p: `len≤55` → `0xc0+len ‖ p`; 그 밖 → `0xf7+len(L) ‖ L ‖ p`.
- 정수(u64/U256): 최소 BE, 0은 빈 바이트열(`0x80`). 주소: 20바이트 문자열.

엄격 디코더 `decode_exact(&[u8]) -> Result<Item<'_>, RlpError>`(이식 `archive/spec-v2.4:crates/key-agent/src/lib.rs:799-905`), 거부 조건:
- 남는 바이트; `0x81` + `<0x80` 한 바이트; 55바이트 이하인데 긴 형식; 길이의 길이에 앞 0; 길이가 입력을 넘음; 깊이 > 4; 입력 > 131,072바이트.
- 정수 필드 `decode_uint(item, max_len)`: 문자열이어야 하고 앞 0 금지, 0은 빈 값, u64 ≤ 8바이트, U256 ≤ 32바이트.

거부 벡터: `[0x81,0x01]`, `[0x01,0x02]`, `[0xb8,0x01,0x80]`(`archive/spec-v2.4:crates/key-agent/src/lib.rs:959-964`).

### 4.2 서명 해시·서명

```
preimage  = 0x02 ‖ rlp([chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas,
                        gas_limit, to, value, data, access_list])
access_list = rlp([[address, [key_0, …]], …])
hash      = keccak256(preimage)
(recid, r‖s) = secp256k1 sign_ecdsa_recoverable(Message::from_digest(hash), sk)   // RFC 6979, low-s
signed    = 0x02 ‖ rlp([...9개 필드, y_parity=recid, r, s])                       // r, s는 최소 BE 정수
tx_hash   = keccak256(signed)
```

- secp256k1 0.31.1 컨텍스트는 [02](02-core-keys-vault.md) §1.3 `secp_context`로 서명 작업마다 만든다(전역·static 금지). `with_secp_key`가 만들어 클로저에 넘긴다.
- `recid ∉ {0,1}` → `SignError::RecoveryId`.
- 개인키는 `Vault::with_secp_key(KeyRef::Evm(signer), |ctx, sk| …)`([02](02-core-keys-vault.md) §10.3, crate 내부) 안에서만 쓰고, 클로저가 끝나면 파생 키는 지워진다(D10). §4.3 검증의 `recover`도 같은 `ctx`로 클로저 안에서 한다. `VaultError`는 `SignError::Vault`로 감싼다.
- 메시지(`personal_sign`·`eth_signTypedData_v4`) 결과는 65바이트 `r ‖ s ‖ v`, `v = 27 + recid`, `"0x"` + 소문자 hex 130자. 서명 후 `recover(digest, sig) == account`를 확인한다.

```rust
// yw-app 키 작업 스레드가 Vault를 소유하고 호출한다([04] §1.2). signer = Approved 안의 Signer::Evm(EvmKeySource)(§11.1)
pub fn sign_transaction(vault: &Vault, approved: Approved) -> Result<SignedTx, SignError>;   // kind 0x10–0x12, payload EvmTx
pub fn sign_personal(vault: &Vault, approved: Approved) -> Result<[u8; 65], SignError>;      // kind 0x13
pub fn sign_typed_data(vault: &Vault, approved: Approved) -> Result<[u8; 65], SignError>;    // kind 0x14
pub struct SignedTx { pub raw: Vec<u8>, pub tx_hash: [u8; 32], pub tx: Eip1559Tx }
// kind·payload·signer 불일치 → SignError::KindMismatch (서명하지 않음)
```

### 4.3 서명 후 검증 (반드시, 저널 기록 전)

1. `keccak256(tx.signing_preimage()) == 서명에 쓴 hash`.
2. `raw.len() ≤ 131,072`(geth txpool 최대 거래 크기). 넘으면 E11.
3. `decode_signed(raw)` 엄격 디코드: 첫 바이트 `0x02`, 정확히 12필드 리스트, 필드 형식(§4.1), `to` 20바이트, `y_parity` ∈ {`0x80`(0), `0x01`(1)}, r·s는 1–32바이트 정규 정수, `0 < r < n`, `0 < s ≤ n/2` (`n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0`).
4. 디코드한 9필드 == 승인된 `Eip1559Tx` 각 필드.
5. `recover(hash, sig)`의 주소 == 승인 계정.
6. `tx_hash = keccak256(raw)`.

하나라도 실패 → `SignError::PostSignVerification`, 저장·전송 없음, 창에 "서명 검증 실패(내부 오류)"(이식 `archive/spec-v2.4:crates/key-agent/src/lib.rs:325-353,607-797`).

### 4.4 전송

전제: 저널 `Signed` 레코드가 디스크에 커밋됨(§5.3), `eth_chainId` 재확인.

`eth_sendRawTransaction(["0x" + hex(raw)])`의 결과:

| 결과 | 저널 | dApp 응답 | 앱 표시 |
|---|---|---|---|
| 반환 해시 == `tx_hash` | `Broadcast` | `tx_hash` | 전송됨 |
| 반환 해시 ≠ `tx_hash` | `Signed` 유지, `flags.rpc_hash_mismatch` | -32603 `BroadcastFailed` | 고위험 알림 "RPC가 다른 거래 해시를 반환했습니다". 자동 재전송 안 함 |
| JSON-RPC 오류 | `eth_getTransactionByHash(tx_hash)` 존재 → `Broadcast`; 없음 → `Signed` 유지 | 존재 시 `tx_hash`, 없으면 -32603 `BroadcastFailed` | 재전송·폐기 버튼 |
| 시간 초과·전송 오류 | 2 s, 5 s 뒤 같은 바이트 재전송 후 `eth_getTransactionByHash`; 존재 → `Broadcast`; 없음 → `Signed` 유지 | `tx_hash` | "전송 확인 중", §5.4 자동 재전송 |

어떤 경우에도 자동으로 다시 서명하지 않는다.

### 4.5 영수증·확정

- 폴링: 같은 nonce의 모든 후보 해시에 `eth_getTransactionReceipt`. 전송 후 120 s까지 4 s 간격, 이후 15 s 간격. 저널 쓰기에 DEK가 필요하므로(D10) 잠금 중에는 폴링을 멈추고 잠금 해제 때 §5.4 조정으로 이어 간다.
- 영수증 검증: `transactionHash == hash`, `from == account`, `status ∈ {0x0,0x1}`, `blockNumber`, `blockHash` 32바이트. 위반 영수증은 무시하고 로컬 로그만 남긴다.
- 포함: 영수증 존재(1 확인) → `Included`, 표시 `포함됨 (블록 N)`; `status 0x0`이면 `포함됨 (실행 실패)`. 실제 수수료 = `gasUsed × effectiveGasPrice`.
- 확정: 포함 후 60 s 간격으로 `eth_getBlockByNumber(["finalized", false]).number ≥ N`이고 `eth_getBlockByNumber([N, false]).hash == 영수증 blockHash` → `Finalized`, 표시 `확정`. 해시가 다르면 재구성 → `Broadcast`로 되돌리고 포함 정보 삭제 후 폴링 재개. 노드가 `finalized` 태그를 JSON-RPC 오류로 거부하면 `eth_blockNumber − 64`를 확정 높이로 쓴다(같은 비교).

### 4.6 속도 올리기·취소 (앱 화면 전용, origin `yw-app`)

미종결(`Signed`/`Broadcast`) 레코드에만 제공한다. 같은 nonce의 후보는 원본 포함 최대 9개(대체 8회). 시작 전 `reconcile`(§5.4)하고 `latest nonce == nonce`일 때만 진행한다. §3.6의 진행 중 거래 검사는 적용하지 않는다(같은 nonce 대체이므로). 저널 자리 검사(§5.4-4)와 송신 슬롯(§3.6)은 같다.

- **속도 올리기**: 최신 후보와 같은 `to`, `value`, `data`, `access_list`, `gas_limit`. 수수료 `f = suggest_fees()`(§3.4)에 대해
  - `tip' = max(⌈old_tip × 11/10⌉, f.tip)`, `max_fee' = max(⌈old_max_fee × 11/10⌉, 2 × f.base_fee_next + tip')`.
- **취소**: `to = account`, `value = 0`, `data` 빈 값, `access_list` 빈 값, `gas_limit = ⌈estimate × 1.2⌉`, 수수료는 위와 같은 +10% 규칙.
- 둘 다: 상한 검사(E05), 시뮬레이션(D15, nonce = 같은 nonce), 새 승인 요청(kind `EvmSpeedUp`/`EvmCancel`)과 재승인. 표시에 대체 대상 해시, 기존·새 최대 수수료를 넣는다. 저널에 같은 nonce의 새 레코드(role `SpeedUp`/`Cancel`)를 추가한다.
- 벡터: old tip 1.2 gwei, old maxFee 21.2 gwei, 새 base_next 12 gwei, 새 tip 1 gwei → tip' 1.32 gwei, maxFee' 25.32 gwei.

## 5. 저널 (journal.ywj, EVM 레코드)

`yw_core::journal`(EVM 레코드 `journal::evm`)은 M4에 만든다([01](01-repo-build.md) §2.2, [02](02-core-keys-vault.md) §5.4). 컨테이너(암호화, 원자적 쓰기)와 평문 프레이밍(`kind u8 ‖ body_len u32 BE ‖ body`, 개수·용량 상한)은 [02](02-core-keys-vault.md) §5.2·§5.4가 정한다. EVM 항목은 `kind = 0x01`(체인 판별자)이고 body는 §5.1 레코드다(body[0] `record_kind`는 0x01 고정이며 읽을 때 검사만 한다). 여기서는 EVM 레코드와 상태 기계, 정리 순서를 정한다.

### 5.1 레코드 형식 (big-endian)

```
off  size  field
0    1     record_kind            0x01 (고정)
1    1     record_version         0x01
2    8     chain_id               u64
10   20    account
30   8     nonce                  u64
38   1     state                  1 Signed, 2 Broadcast, 3 Included, 4 Finalized, 5 Dropped, 6 Replaced
39   1     role                   0 Original, 1 SpeedUp, 2 Cancel
40   1     receipt_status         0 없음, 1 성공, 2 실패
41   1     flags                  bit0 rpc_hash_mismatch, bit1 user_discarded, 나머지 0
42   8     created_unix_ms        u64
50   8     updated_unix_ms        u64
58   8     last_broadcast_unix_ms u64, 0 = 없음
66   32    tx_hash
98   32    approval_digest        §11.4
130  8     included_block_number  0 = 없음
138  32    included_block_hash    0 = 없음
170  2     origin_len             ≤ 255
172  L1    origin                 UTF-8, "yw-app" 또는 직렬화 origin
+0   2     label_len              ≤ 256
+2   L2    label                  §11.1 title
+0   4     raw_len                2..=131,072
+4   L3    raw                    서명된 거래 0x02 ‖ rlp
```

읽기 검증: body 길이 == 필드 합(최대 131,761), `record_kind == 0x01`, 알려진 버전·enum 값, `flags` 미사용 비트 0, `keccak256(raw)==tx_hash`, `decode_signed(raw)` 성공, 디코드한 `chain_id`·`nonce` 일치, 복구 주소 == `account`. 실패 → [02] §5.4 본문 오류: EVM 보내기 비활성 + "저널 손상" 표시(자동 삭제 금지, 바이트 보존, [04]).

### 5.2 상태 기계

| 현재 | 사건 | 다음 |
|---|---|---|
| (없음) | §4.3 통과 | `Signed` |
| `Signed` | RPC가 같은 해시 반환 또는 `eth_getTransactionByHash` 존재 | `Broadcast` |
| `Signed`/`Broadcast` | 이 후보의 영수증 | `Included`; 같은 nonce의 다른 미종결 후보 → `Replaced` |
| `Signed`/`Broadcast` | 어떤 후보에도 영수증 없음 + `latest nonce > nonce`를 30 s 이상 간격으로 2회 관측 | 모든 후보 `Dropped` ("다른 거래가 이 nonce를 사용") |
| `Signed`/`Broadcast` | 사용자 폐기 | `Dropped` + `user_discarded` (경고: 이미 전파됐으면 나중에 처리될 수 있음) |
| `Included` | finalized 조건(§4.5) | `Finalized` |
| `Included` | 블록 해시 불일치(재구성) | `Broadcast`, 포함 정보 0 |
| `Finalized`/`Dropped`/`Replaced` | — | 종결 |

### 5.3 쓰기 순서

1. 서명·§4.3 검증 → 2. `Signed` 레코드 추가 후 저널 커밋(임시 파일 → FlushFileBuffers → MoveFileExW, spec §4.3) → 3. 커밋 성공 후에만 전송 → 4. 상태 바뀔 때마다 커밋.
2단계 실패 → 전송하지 않고 서명 결과를 지운다. dApp -32603 `Internal error.`([05](05-browser.md) §5 `Internal`), 창 "저널 저장 실패".

### 5.4 복구·조정

잠금 해제 직후, 그리고 §3.6 단계마다 `reconcile(chain, account)`:
1. 미종결 레코드의 nonce 그룹마다 모든 후보 영수증 조회 → §5.2.
2. 영수증 없음, `latest nonce == nonce` → 그룹의 최신 후보 `raw`를 그대로 재전송(`eth_getTransactionByHash`가 null일 때만, 60 s에 최대 1회). **다시 서명하지 않는다.**
3. `rpc_hash_mismatch` 레코드는 자동 재전송하지 않는다(사용자 재전송 버튼만).
4. 정리·상한: 종결 레코드(`Finalized`/`Dropped`/`Replaced`)는 종결 후 7일 지나면 다음 저널 쓰기 때 [02](02-core-keys-vault.md) §5.3 `activity`로 옮긴 뒤 삭제한다. 개수·용량 상한은 EVM·SOL·BTC가 함께 쓰는 [02] §5.4 값(전체 ≤ 256, 평문 ≤ 16 MiB, EVM 최대 본문 131,761)이다. 새 레코드(`Signed` 원본·SpeedUp·Cancel)를 만들 서명 전(§3.7 단계 4, §4.6)에 [02] §5.4 추가 전 검사를 하고, 자리가 없으면 EVM 종결 레코드를 오래된 것부터(activity로 옮긴 뒤) 지운다. 다른 체인 항목은 그 문서 규칙으로만 지운다. 그래도 없으면 `journal::JournalError::Full` → E06 "거래 저널 공간이 부족합니다"(서명·전송 없음).

**activity 대응(EVM, [02] §5.3).** 종결 레코드를 activity로 옮길 때: `account` = 레코드 계정(소문자 `0x` hex), `tx_id` = `0x`+최종 후보의 tx_hash, `title` = 서명 당시 승인 제목(§11.1). calldata가 ERC-20 `transfer`로 해석되면 `asset` = 토큰 주소, `amount` = 토큰 최소 단위 10진, `counterparty` = 받는 주소; 아니면 `asset` = `"native"`, `amount` = value(wei 10진, 0이면 `"0"`), `counterparty` = tx `to`. `status`: `Finalized` + 영수증 status 1 → `succeeded`, 0 → `failed`; `Dropped`(사용자 폐기 포함) → `dropped`; `Replaced` → `replaced`. `time_unix_ms` = 종결 관측 시각. SpeedUp은 원본과 한 행(확정된 후보의 해시), Cancel이 확정되면 원본 행은 `replaced`이고 취소 거래는 `title` "거래 취소"인 별도 행이다.

## 6. 시뮬레이션 (D15: 항상 시도, 승인을 막지 않음)

모든 EVM 거래 승인(kind 0x10–0x12)은 시뮬레이션을 시도한다. 결과가 없거나(미지원 체인 포함) 실패·불완전하면 원인별 고위험 경고를 승인 창 맨 위에 두고(§10.1 순서), 승인은 D16 체크박스 1개 + 2초 누르기로 가능하다. 시뮬레이션 때문에 차단하는 경우는 없다.

### 6.1 요청

체인 `simulation = Unsupported`면 요청을 보내지 않는다(`SimOutcome::Unsupported` → E36). 그 밖에는 서명할 바로 그 거래를 보낸다. `stateOverrides`, `blockOverrides`, `returnFullTransactions`는 넣지 않는다. 키 순서 고정, 값은 정규 quantity·소문자 hex.

```json
{"jsonrpc":"2.0","id":<n>,"method":"eth_simulateV1","params":[
 {"blockStateCalls":[{"calls":[{
   "from":"0x<account>","to":"0x<to>","value":"0x<value>","input":"0x<data>",
   "nonce":"0x<nonce>","gas":"0x<gas_limit>",
   "maxFeePerGas":"0x<max_fee>","maxPriorityFeePerGas":"0x<tip>",
   "chainId":"0x<chain_id>","type":"0x2",
   "accessList":[{"address":"0x…","storageKeys":["0x…"]}]
 }]}],
  "traceTransfers":true,"validation":true},
 "latest"]}
```

`accessList`가 비면 키를 생략한다. `chainId`·`type`은 §1.5 A3 결과에 따른다.

### 6.2 응답 해석

```rust
// yw-app이 응답을 파싱해 넘기는 타입
pub struct SimBlock { pub number: u64, pub parent_hash: [u8;32], pub timestamp: u64, pub base_fee_per_gas: U256, pub call: SimCall }
pub struct SimCall  { pub status: SimStatus, pub gas_used: u64, pub max_used_gas: Option<u64>,
                      pub return_data: Vec<u8>, pub logs: Vec<SimLog>, pub error: Option<SimCallError> }
pub enum SimStatus  { Success, Failure }
pub struct SimLog   { pub address: Address, pub topics: Vec<[u8;32]>, pub data: Vec<u8> }
pub struct SimCallError { pub code: i64, pub data: Option<Vec<u8>> }   // message는 버림
pub enum SimOutcome { Block(SimBlock), RpcError { code: i64 }, Transport(TransportKind), Malformed, TooLarge, Unsupported }
pub enum TransportKind { Timeout, RateLimited, Other }                 // HTTP 429·JSON-RPC 코드 429 = RateLimited
pub enum SimResult {                                                   // 차단 경고를 만들지 않는다
    Simulated { verdict: SimVerdict, diff: SimulationDiff, warnings: Vec<Warning> },  // 블록 있음, Reverted면 diff 비움
    Unavailable { reason: SimNoneReason, warning: Option<Warning> } }               // E01 또는 E36, Skipped면 None
pub fn interpret(chain: &ChainInfo, tx: &Eip1559Tx, from: &Address, o: &SimOutcome, now_unix_ms: u64) -> SimResult;
impl SimResult { pub fn binding(&self) -> SimulationBinding; }        // §11.1
```

- `result`는 길이 정확히 1인 배열, 블록의 `calls`도 길이 정확히 1(규칙 3). 아니면 `Malformed`.
- 필수: 블록 `number`, `parentHash`, `timestamp`, `baseFeePerGas`; 호출 `status`(`0x1`/`0x0`), `gasUsed`, 성공 시 `logs`. `returnData`는 선택(≤ 131,072바이트). `status 0x0`이면 로그를 쓰지 않는다.
- 로그 ≤ 1,024개, 로그당 topics ≤ 4, data ≤ 65,536바이트. 넘으면 `TooLarge`(E01).
- 블록 `hash`, 로그의 `blockNumber`·`logIndex` 등 나머지 필드는 무시한다.

### 6.3 결과 판정·경고 표 (모두 고위험, 차단 없음)

경고 문구 = 규칙의 기본 문구 + LF + 아래 "원인" 줄. 기본 문구: E01 "시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다", E36 "시뮬레이션 미지원 체인 — 실제 효과를 확인할 수 없습니다"(원인 줄 없음), E02 "시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다", E03·E04·E07·E08·E09 "시뮬레이션 결과가 불완전합니다". 판정 결과는 `SimResult`(§6.2)와 바인딩(§11.1)이 된다. `SimVerdict`는 `Reverted` > `Incomplete` > `Ok` 순으로 정하고, `Incomplete` 규칙은 여럿이 함께 나올 수 있다.

| 조건 | 결과 | 규칙 | 원인 줄 |
|---|---|---|---|
| 체인 `simulation = Unsupported` (호출 없음) | `None` `Unsupported` | E36 | — |
| 전송 오류 | `None` `Transport` | E01 | 시뮬레이션 RPC에 연결할 수 없습니다 |
| 10 s 초과, 준비 예산 소진(§1.4) | `None` `Timeout` | E01 | 시뮬레이션 응답이 없습니다(10초) |
| HTTP 429 / 코드 429 | `None` `RateLimited` | E01 | RPC 요청 한도를 넘었습니다 |
| 응답 > 4 MiB, §6.2 로그 한도 초과 | `None` `TooLarge` | E01 | 시뮬레이션 응답이 너무 큽니다 |
| `Malformed`, §1.3 모양 위반 | `None` `Malformed` | E01 | 시뮬레이션 응답 형식이 올바르지 않습니다 |
| -32601 | `None` `RpcError` | E01 | RPC가 eth_simulateV1을 지원하지 않습니다(체인 설정에서 시뮬레이션을 "미지원"으로 바꿀 수 있습니다) |
| -38010 | `None` `RpcError` | E01 | nonce가 이미 사용되었습니다. 다른 곳에서 이 계정으로 거래가 전송되었을 수 있습니다 |
| -38011 | `None` `RpcError` | E01 | 앞선 거래가 아직 처리되지 않았습니다 |
| -38012, -32005 | `None` `RpcError` | E01 | 최대 수수료가 현재 기본 수수료보다 낮습니다(재시뮬레이션이면 §6.6 4항) |
| -38013 | `None` `RpcError` | E01 | 가스 한도가 최소 필요량보다 작습니다 |
| -38014, -32003(HyperEVM 실측) | `None` `RpcError` | E01 | 잔액이 보낼 금액과 최대 수수료의 합보다 적습니다 |
| -38015 | `None` `RpcError` | E01 | 가스 한도가 블록 가스 한도를 넘습니다 |
| -32602, -32016, -38020…-38026, 그 밖 최상위 오류 | `None` `RpcError` | E01 | 시뮬레이션 노드 오류(코드 n) |
| `status 0x0`, `error.code 3` | `Simulated` `Reverted` | E02 | 이유: §7.4 해석 |
| `status 0x0`, 그 밖 | `Simulated` `Reverted` | E02 | 이유: 실행 오류(가스 부족 등, 코드 n) |
| `gas_used > gas_limit` 또는 `max_used_gas > gas_limit` | `Simulated` `Incomplete` | E03 | 사용 가스가 가스 한도를 넘습니다 |
| `value > 0`이고 `tx.to != account`인데 선택된 네이티브 로그(§1.3, 모든 체인) 중 `from==account, to==tx.to, amount==value`가 없음(자기 자신에게 보내는 거래는 EIP-7708 체인에서 로그가 없으므로 검사하지 않는다 — Sepolia 실측) | `Simulated` `Incomplete` | E04 | {native_symbol} 이동이 확인되지 않습니다 |
| `|sim.timestamp − now| > 300 s` | `Simulated` `Incomplete` | E07 | 기준 블록 시각이 현재와 {n}초 다릅니다 |
| 표시 행 > 64(§6.4) | `Simulated` `Incomplete` | E08 | 표시 한도를 넘어 {n}행을 생략했습니다 |
| diff 합산 오버플로(§6.4) | `Simulated` `Incomplete` | E09 | 금액 합산이 범위를 넘었습니다 |

### 6.4 자산 변화(diff) 구성

로그를 순서대로 분류한다(`emitter` = 로그 주소, `user` = 서명 계정).

| 분류 | 조건 | 처리 |
|---|---|---|
| 네이티브 | §1.3 선택 집합 | (native, from, to, amount) 이동 |
| ERC-20 Transfer | topic0 Transfer, topics 3, data 32, emitter ∉ 네이티브 주소 | (emitter, from, to, amount) |
| ERC-721 Transfer | topic0 Transfer, topics 4, data 0 | (emitter, tokenId=topics[3], from, to) |
| ERC-1155 TransferSingle | `0xc3d58168…0f62`, topics 4, data 64 | (emitter, id, from=topics[2], to=topics[3], value) |
| ERC-1155 TransferBatch | `0x4a39dc06…f7fb`, topics 4, data = 정규 ABI `(uint256[],uint256[])`, 길이 같음, ≤ 64 | 원소마다 Single처럼 |
| WETH Deposit | emitter == 레지스트리 WETH, `0xe1fffcc4…109c`, topics 2, data 32 | dst==user면 WETH +wad |
| WETH Withdrawal | emitter == 레지스트리 WETH, `0x7fcf532c…1b65`, topics 2, data 32 | src==user면 WETH −wad |
| ERC-20 Approval | `0x8c5be1e5…b925`, topics 3, data 32, owner==user | 승인 (emitter, spender, amount) |
| ERC-721 Approval | 같은 topic0, topics 4, data 0, owner==user | 개별 승인 (emitter, approved, tokenId); approved==0 → 해제 |
| ApprovalForAll | `0x17307eab…6c31`, topics 3, data 32(0 또는 1), owner==user | 전체 권한 (emitter, operator, bool) |
| Permit2 Approval | emitter == Permit2, `0xda9fa7c1…036b`, topics 4, data 64(uint160, uint48 정규), owner==user | (token, spender, amount, expiration) |
| Permit2 Lockdown | emitter == Permit2, `0x89b1add1…98a4`, topics 2, data 64, owner==user | 해제 (token, spender) |
| 기타 | 위에 없음, 모양 불일치, user와 무관한 이동·승인 | "기타 이벤트 N개" (E32) |

- 이동 중 `from==user`는 보냄, `to==user`는 받음. 자산 키 = native / (ERC-20 token) / (ERC-721 token, id) / (ERC-1155 token, id). 자산별 Σin − Σout → `Delta`(오버플로면 그 자산 행을 `합산 불가`로 표시하고 E09). 0이 된 자산은 표시하지 않는다.
- 승인은 같은 (token, spender[, id]) 키의 **마지막** 로그 값을 결과로 한다.
- 수수료는 diff에 넣지 않고 따로 표시: `예상 수수료 = gas_used × min(max_fee, sim.base_fee_per_gas + tip)`.
- 표시 행 ≤ 64(보냄+받음+승인). 넘으면 앞 64행만 표시하고 E08.
- `Reverted`(§6.3)면 changes·approvals·transfers는 비고 `other_events = 0`이다. 시뮬레이션 결과가 없으면 diff 필드(§11.2 `0x0110`–`0x0113`)를 만들지 않는다.

```rust
pub struct SimulationDiff {
    pub block: SimBinding,                  // §11.1: number, parent_hash, timestamp, base_fee, sim_digest
    pub changes: Vec<AssetChange>,          // { asset: AssetId, token_id: Option<U256>, delta: Option<Delta> } (None = 합산 불가, E09); 보냄(합산 불가 포함) 먼저, 받음 다음
    pub approvals: Vec<ApprovalChange>,     // { asset: Address, spender: Address, kind: ApprovalKindEvm }
    pub transfers: Vec<TransferRow>,        // user가 from/to인 이동 원본 목록
    pub other_events: u32, pub gas_used: u64,
    pub events: Vec<LogEvent>,              // 분류된 로그 전체(user 무관, 선택 안 된 네이티브 발신자 제외): R4·R6 입력. Reverted면 비어 있음
    pub omitted_rows: u32,                  // E08로 생략한 행 수
    pub native_emitter_mismatch: bool,      // §1.3-3: yw-core는 로그를 쓰지 않으므로 yw-app이 이 값으로 `native-emitter-mismatch`를 기록
}
pub enum AssetId { Native, Token(Address) }
pub enum ApprovalKindEvm { Erc20 { amount: U256 }, Erc721 { token_id: U256, revoked: bool },
                           ForAll { approved: bool }, Permit2 { amount: U256, expiration: u64 },
                           Permit2Lockdown }
```

### 6.5 시뮬레이션 digest·바인딩

```
T = Transcript::start_domain("your-wallet/v3/evm-simulation", 1)
T.push_u64(number); T.push_bytes(parent_hash); T.push_u64(timestamp); T.push_bytes(base_fee_be32)
T.push_u8(status: 1 성공 / 0 실패); T.push_u64(gas_used); T.push_optional(max_used_gas: u64)
T.push_bytes(return_data)
T.push_u32(logs.len()); for log { T.push_bytes(address); T.push_u8(topics.len()); for t { T.push_bytes(t) }; T.push_bytes(data) }
sim_digest = SHA-256(T)
```

`Transcript`는 `archive/spec-v2.4:crates/wallet-model/src/codec.rs:28-109`(정수 BE, 가변 길이는 u32 BE 길이 접두, `push_optional` = `0` 또는 `1 ‖ 값`)를 그대로 쓴다. 시뮬레이션 블록이 있으면(`Ok`·`Reverted`·`Incomplete`) 승인 digest에 verdict와 (number, parent_hash, timestamp, base_fee, sim_digest)를, 결과가 없으면 `SimNoneReason` 코드를 넣는다(§11.1 `SimulationBinding`, §11.4).

### 6.6 신선도·재시뮬레이션

1. 바인딩이 `SimulationBinding::None`(결과 없음·미지원)이면 재시뮬레이션하지 않고 그대로 소비한다(만료 120 s만 적용).
2. `Simulated`이고 응답 수신 후 경과(yw-app `monotonic_ms`) ≤ 60 s → 그대로 소비(D23).
3. `Simulated`이고 > 60 s → 같은 거래로 재시뮬레이션 → §6.3 판정·표시 재구성. **안정 부분**(volatile이 아닌 필드, 경고, risk, ack_required)이 같으면 요청을 새 digest로 교체(§11.5 `replace`)하고 그 클릭으로 소비한다. 다르면 요청을 교체하고 "시뮬레이션 결과가 바뀌었습니다. 다시 확인하세요"를 띄운 뒤 새 클릭(고위험이면 체크·누르기 다시)을 요구한다. 재시뮬레이션 결과가 없으면(E01) 바인딩을 `None { reason }`으로 바꾼 요청으로 교체하고 "시뮬레이션을 다시 실행하지 못했습니다. 경고를 확인하고 다시 승인하세요"를 띄운 뒤 새 클릭(체크·2초 누르기)을 요구한다(그 클릭은 1항으로 소비). 만료 시각은 바꾸지 않는다.
4. 재시뮬레이션이 -38012/-32005면 §3.4로 수수료를 다시 계산해 거래를 다시 만들고(상한 초과면 E05 차단 요청으로 교체) 한 번 더 시뮬레이션한 뒤 3의 "다르면"(또는 결과 없음) 경로를 탄다. 재시뮬레이션 결과 자체로는 차단하지 않는다(수수료 재계산의 E05만 차단).

## 7. calldata 해석

### 7.1 셀렉터 표

`kind`·제목·인수 이름은 고정 문자열이다([06](06-llm-explain.md) 입력에 그대로 쓴다). 제목의 `{native}`는 체인 `native_symbol`, `{wrapped}`는 그 체인 레지스트리 `Weth` 토큰 심볼(예 `WETH`, `WHYPE`)로 바꾼다. "길이"는 R1 정확 길이(dyn = 동적).

| selector | 함수 | 길이 | 조건 | `kind` | 제목 | 인수 |
|---|---|---|---|---|---|---|
| — | (data 빈 값) | 0 | — | `native_transfer` | {native} 보내기 | — |
| `0xa9059cbb` | `transfer(address,uint256)` | 68 | — | `erc20_transfer` | 토큰 전송 | `to`, `amount` |
| `0x095ea7b3` | `approve(address,uint256)` | 68 | R4 | `erc20_approve` / `erc721_approve` | 토큰 사용 승인 / NFT 개별 승인 | `spender`, `amount` / `approved`, `token_id` |
| `0x23b872dd` | `transferFrom(address,address,uint256)` | 100 | R4 | `erc20_transfer_from` / `erc721_transfer_from` | 토큰 이체 / NFT 이체 | `from`, `to`, `amount` / `token_id` |
| `0x39509351` | `increaseAllowance(address,uint256)` | 68 | — | `erc20_increase_allowance` | 토큰 승인 증가 | `spender`, `added` |
| `0xa457c2d7` | `decreaseAllowance(address,uint256)` | 68 | — | `erc20_decrease_allowance` | 토큰 승인 감소 | `spender`, `subtracted` |
| `0xa22cb465` | `setApprovalForAll(address,bool)` | 68 | — | `set_approval_for_all` | 컬렉션 전체 권한 | `operator`, `approved` |
| `0x42842e0e` | `safeTransferFrom(address,address,uint256)` | 100 | — | `erc721_safe_transfer` | NFT 이체 | `from`, `to`, `token_id` |
| `0xb88d4fde` | `safeTransferFrom(address,address,uint256,bytes)` | dyn, offset `0x80` | — | `erc721_safe_transfer` | NFT 이체 | + `data` |
| `0xf242432a` | `safeTransferFrom(address,address,uint256,uint256,bytes)` | dyn, offset `0xa0` | — | `erc1155_safe_transfer` | 멀티 토큰 이체 | `from`, `to`, `id`, `amount`, `data` |
| `0x2eb2c2d6` | `safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)` | dyn | 길이 같음 | `erc1155_safe_batch_transfer` | 멀티 토큰 일괄 이체 | `from`, `to`, `ids`, `amounts`, `data` |
| `0xd0e30db0` | `deposit()` | 4 | `to`==WETH | `weth_deposit` | {native} → {wrapped} 변환 | — |
| `0x2e1a7d4d` | `withdraw(uint256)` | 36 | `to`==WETH | `weth_withdraw` | {wrapped} → {native} 변환 | `amount` |
| `0x87517c45` | `approve(address,address,uint160,uint48)` | 132 | `to`==Permit2 | `permit2_approve` | Permit2 승인 | `token`, `spender`, `amount`, `expiration` |
| `0xcc53287f` | `lockdown((address,address)[])` | dyn | `to`==Permit2 | `permit2_lockdown` | Permit2 승인 해제 | `pairs` |
| `0x65d9723c` | `invalidateNonces(address,address,uint48)` | 100 | `to`==Permit2 | `permit2_invalidate_nonces` | Permit2 nonce 무효화 | `token`, `spender`, `new_nonce` |
| `0x3ff9dcb1` | `invalidateUnorderedNonces(uint256,uint256)` | 68 | `to`==Permit2 | `permit2_invalidate_unordered_nonces` | Permit2 서명 무효화 | `word_pos`, `mask` |
| `0xd505accf` | `permit(address,address,uint256,uint256,uint8,bytes32,bytes32)` | 228 | — | `erc2612_permit_submit` | permit 제출 | `owner`, `spender`, `value`, `deadline` |
| `0x8fcbaf0c` | `permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)` | 260 | — | `dai_permit_submit` | DAI permit 제출 | `holder`, `spender`, `nonce`, `expiry`, `allowed` |
| `0xac9650d8` | `multicall(bytes[])` | dyn | R5 | `multicall` | 묶음 호출 | `calls` |
| `0x5ae401dc` | `multicall(uint256,bytes[])` | dyn | R5 | `multicall` | 묶음 호출 | `deadline`, `calls` |
| `0x1f0464d1` | `multicall(bytes32,bytes[])` | dyn | R5 | `multicall` | 묶음 호출 | `previous_block_hash`, `calls` |

라벨만(구조 해석 없음 → 해석되지 않은 호출, D16, E12; 제목에 라벨 표시): `to`==Permit2의 `0x2b67b570`, `0x2a2d80d1`(permit), `0x36c78516`, `0x0d58b1db`(transferFrom), `0x30f28b7a`, `0xedd9444b`(permitTransferFrom), `0x137c29fe`(permitWitnessTransferFrom); `to`∈Universal Router의 `0x3593564c`, `0x24856bc3`(execute); `to`∈Seaport 1.5/1.6의 `0xfb0f3ee1`, `0x00000000`(fulfillBasicOrder), `0xfd9f1e10`(cancel), `0x5b34b966`(incrementCounter).

공개 셀렉터 DB 이름은 쓰지 않는다(`0xa22cb465` 등에 충돌 이름 존재). 셀렉터 + R1/R2 디코드 성공만이 해석 근거다.

### 7.2 엄격 디코드 규칙

- **R1** 정적 함수는 표의 정확한 길이, 뒤 바이트 없음.
- **R2** 정규 인코딩: address 워드 상위 12바이트 0; bool 0/1; uint160 상위 12바이트 0; uint48 상위 26바이트 0; uint8 상위 31바이트 0; 동적 오프셋은 정규 위치(첫 tail = head 크기, 다음 tail = 앞 tail 끝); 길이 워드 ≤ 남은 바이트; 패딩 0; 뒤 바이트 없음; 배열 ≤ 64; ERC-1155 배치 `ids.len()==amounts.len()`; bytes 인수 ≤ 131,072. 위반 → `Uninterpreted`(안전 아님).
- **R3** WETH·Permit2·Seaport 셀렉터는 그 체인 레지스트리 주소에서만 해석한다. 다른 주소면 `Uninterpreted`. 사용자 체인은 레지스트리가 비어 있으므로 항상 `Uninterpreted`(§1.2). 그 밖 셀렉터(ERC-20·721·1155 등)는 체인과 무관하게 해석한다.
- **R4** `0x095ea7b3`, `0x23b872dd`: 시뮬레이션에서 `to`가 낸 Approval/Transfer 로그가 topics 3이면 ERC-20, 4면 ERC-721. 로그가 없으면 인수를 `amount_or_token_id`로 표시하고, 시뮬레이션 로그를 쓸 수 있었으면(verdict `Ok`·`Incomplete`) E13.
- **R5** multicall: 한 단계만, 내부 호출 ≤ 16, 각 내부 호출은 같은 `to`에 대해 이 표로 해석, 내부 multicall은 `Uninterpreted`. 내부 하나라도 `Uninterpreted`면 전체에 E12("해석되지 않은 호출 포함"). `deadline`은 UTC 시각으로 표시.
- **R6** 해석된 승인·이동·WETH 변환마다 emitter == `to`(Permit2 함수는 Permit2)이고 같은 종류(§6.4 분류)·같은 주소 인수(owner/spender/operator/from/to/dst/src)를 가진 로그가 있어야 한다. 금액은 `transfer`·`transferFrom`·`approve`·`deposit`(= value)·`withdraw`에서만 비교한다. 없거나 다르면 E13. 시뮬레이션 로그를 쓸 수 없으면(`None`·`Reverted`) R6 검사와 E13을 생략한다(E01·E02·E36이 이미 고위험). 승인 위험 등급은 시뮬레이션 로그(§6.4)로 판정하고, 로그를 쓸 수 없으면 R8.
- **R7** (D16) `Uninterpreted`는 허용하고 E12(고위험 → §10.1 공통 체크박스 1개 + 2초 누르기). 시뮬레이션 결과까지 없으면 E12와 E01(또는 E36)을 함께 표시하고 체크박스는 여전히 1개다.
- **R8** 시뮬레이션 로그를 쓸 수 없을 때(`None`·`Reverted`) 승인 위험(E14–E16, E20–E22, E30)은 해석된 calldata 인수로 판정한다: `approve`(R4로 정할 수 없으면 ERC-20으로 본다), `increaseAllowance`, `setApprovalForAll`, Permit2 `approve`·`lockdown`, multicall 내부 같은 함수.

```rust
pub enum DecodedCall { NativeTransfer,
    Known { kind: &'static str, title: &'static str, args: Vec<(&'static str, AbiValue)> },
    Multicall { kind: &'static str, head: Vec<(&'static str, AbiValue)>, inner: Vec<DecodedCall> },
    Uninterpreted { selector: Option<[u8; 4]>, label: Option<&'static str> } }
pub enum AbiValue { Address(Address), Uint(U256), Bool(bool), Bytes(Vec<u8>), Bytes32([u8;32]), Array(Vec<AbiValue>), Tuple(Vec<AbiValue>) }
pub struct DecodedTx { pub tx: Eip1559Tx, pub call: DecodedCall }
pub fn decode_call(chain: &ChainInfo, to: &Address, data: &[u8]) -> DecodedCall;
```

### 7.3 표시

- 주소 인수: §2.2 + 라벨 + 분류(§8.5). 금액 인수: `to` 토큰의 decimals·symbol(§2.5). `token_id`·`id`: 10진 전체. bool: `예`/`아니오`. bytes: `0x` hex 전체 + 바이트 수. calldata 전체 hex를 길이·selector와 함께 항상 상세 영역에 둔다(크기 제한 없이 스크롤, 아카이브의 512바이트 거부 폐지).

### 7.4 revert 이유

`error.data`(또는 estimateGas 오류 data):
- `0x08c379a0` `Error(string)`: 정규 ABI string 디코드, 0x20–0x7E만, ≤ 160자면 `"…"`로 감싸 "(검증되지 않은 컨트랙트 메시지)" 접두와 함께 표시. 조건 불충족 → "메시지 형식 불명".
- `0x4e487b71` `Panic(uint256)`: `0x00` 일반, `0x01` assert 실패, `0x11` 산술 오버플로, `0x12` 0으로 나눔, `0x21` 잘못된 enum 변환, `0x22` 저장소 바이트 배열 인코딩 오류, `0x31` 빈 배열 pop, `0x32` 배열 범위 초과, `0x41` 메모리 과다 할당, `0x51` 초기화되지 않은 함수 호출, 그 밖 `Panic 0x…`.
- 그 밖 4바이트 이상: "사용자 정의 오류 0x{selector} ({n}바이트)". 빈 값: "이유 없이 되돌려짐".

## 8. 타입 데이터 (D17)

### 8.1 이식·변경

`archive/spec-v2.4:crates/eip712`를 `yw-core::evm::eip712`로 옮긴다. 해시 코어(`schema.rs:426-543`, encodeType·typeHash·hashStruct·배열·string/bytes)는 바꾸지 않는다.

| # | 아카이브 | v3 |
|---|---|---|
| 1 | serde_json(`json.rs:1-236`) | `yw_json::Value`(중복 키 거부, 깊이·개수 제한, 원본 숫자 토큰) |
| 2 | chainId/verifyingContract 없으면 `SchemaExceptionRequired`(`schema.rs:186-208`) | 제거. chainId 없음 → T03, verifyingContract 없음·0 → T10 |
| 3 | chainId 불일치 `ChainIdMismatch`(`schema.rs:566-569`) | 유지 → T01 거부 |
| 4 | 도달 불가 타입 거부(`schema.rs:373-378`) | 허용(해시·표시에 쓰지 않음) |
| 5 | hex 정수의 앞 0·대문자 거부(`schema.rs:892-902`) | 허용(값이 타입 범위 안이면) |
| 6 | 대소문자 섞인 주소 무검사(`schema.rs:812-840`) | §2.1 |
| 7 | primaryType `EIP712Domain` 거부(`schema.rs:265`) | 유지 |
| 8 | 원문 ≤ 1 MiB | 원문 ≤ 131,072바이트; 그 밖 `Limits::default`(`schema.rs:38-52`) 유지 |

파라미터: `[address, typedData]`, typedData는 JSON 문자열 또는 객체. 문자열이면 그 UTF-8 바이트를 파싱하고, 객체면 yw-json 정규 직렬화 바이트를 원문으로 쓴다. `address`는 연결 계정(아니면 4100).

```rust
pub fn validate_typed_data_v4(src: &[u8], v: &yw_json::Value, chain_id: u64) -> Result<DecodedTypedData, TypedDataError>;
pub struct DecodedTypedData {
    pub domain: TdDomain,                 // name, version, chain_id: Option<U256>, verifying_contract: Option<Address>, salt
    pub primary_type: String,
    pub schema: Option<KnownSchema>,
    pub preimage: [u8; 66],               // 0x19 0x01 ‖ domainSeparator ‖ hashStruct(message)
    pub root: TdNode,                     // 표시용 값 트리
}
pub fn eip712_digest(t: &DecodedTypedData) -> [u8; 32];   // keccak256(preimage)
```

값 형식: uint/int는 JSON 정수(≤ 2^53−1), 10진 문자열(int는 `-` 허용, `-0` 거부), `0x` hex 문자열. address §2.1. bytesN/bytes `0x` hex. bool은 JSON bool, string은 JSON 문자열. 모든 값은 선언 타입 범위 검사.

### 8.2 스키마 인식표

primaryType 이름 일치 + primaryType의 typeHash(도달 가능 타입 그래프 전체) 일치로 인식한다. 이름·타입·순서가 하나라도 다르면 미인식.

| `KnownSchema` (`schema_id`) | primaryType | typeHash | 추가 조건 |
|---|---|---|---|
| `Eip2612Permit` (`eip2612-permit`) | `Permit` | `0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9` | verifyingContract = 토큰 |
| `DaiPermit` (`dai-permit`) | `Permit` | `0xea2aa0a1be11a07ed86d755c93467f4f82362b452371d1ba94d1715123511acb` | — |
| `Permit2Single` (`permit2-permit-single`) | `PermitSingle` | `0xf3841cd1ff0085026a6327b620b67997ce40f282c88a8e905a7a5626e310f3d0` | P2 |
| `Permit2Batch` (`permit2-permit-batch`) | `PermitBatch` | `0xaf1b0d30d2cab0380e68f0689007e3254993c596f2fdd0aaa7f4d04f79440863` | P2 |
| `Permit2Transfer` (`permit2-transfer`) | `PermitTransferFrom` | `0x939c21a48a8dbe3a9a2404a1d46691e4d39f6583d6ec6b35714604c986d80106` | P2 |
| `Permit2BatchTransfer` (`permit2-batch-transfer`) | `PermitBatchTransferFrom` | `0xfcf35f5ac6a2c28868dc44c302166470266239195f02b0ee408334829333b766` | P2 |
| `Permit2WitnessTransfer` (`permit2-witness-transfer`) | `PermitWitnessTransferFrom` | 동적 | P2, W |
| `Permit2BatchWitnessTransfer` (`permit2-batch-witness-transfer`) | `PermitBatchWitnessTransferFrom` | 동적 | P2, W |
| `SeaportOrder` (`seaport-order`) | `OrderComponents` | `0xfa445660b7e21515a59617fcd68910b487aa5808b8abda3d78bc85df364b2c2f` | S |

보조 typeHash: `PermitDetails 0x65626cad6cb96493bf6f5ebea28756c966f023ab9e8a83a7101849d5573b3678`, `TokenPermissions 0x618358ac3db8dc274f0cd8829da7e234bd48cd73c4a740aede1adec9846d06a1`, 4필드 도메인 `0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f`, Permit2 3필드 도메인 `0x8cad95687ba82c2ce50e74f7b754645e5117c3a5bec8151c0726d5857980a866`.

- **P2**: domain == `{name:"Permit2", chainId, verifyingContract: Permit2}`(version 없음). 스키마가 Permit2 형인데 verifyingContract ≠ Permit2 → 미인식(T04). verifyingContract == Permit2인데 표의 어느 Permit2 스키마도 아님 → 거부(T02).
- **W**: 처음 네 필드가 `permitted TokenPermissions`(배치는 `TokenPermissions[]`), `spender address`, `nonce uint256`, `deadline uint256`과 정확히 같고, 다섯째 필드가 정확히 하나의 struct 타입(이름 자유). witness 하위 트리는 해석하지 않는다(T06).
- **S**: domain `name:"Seaport"`, (version `"1.6"` ∧ verifyingContract Seaport 1.6) 또는 (version `"1.5"` ∧ Seaport 1.5). verifyingContract가 Seaport 1.5/1.6인데 스키마 불일치 또는 primaryType `BulkOrder` → 거부(T02). Seaport 1.1 등 레지스트리 밖 → 미인식(T04).

### 8.3 스키마별 표시

| 스키마 | 제목 | 필드(순서) |
|---|---|---|
| EIP-2612 | 토큰 사용 허가 서명 (permit) | 토큰(verifyingContract, §2.5), 소유자 `owner`, 사용자 `spender`(+분류), 금액 `value`(2^256−1 → 무제한), nonce, 기한 `deadline` |
| DAI | DAI 사용 허가 서명 | `holder`, `spender`, nonce, 기한 `expiry`(0 → 만료 없음), `allowed`(true → 무제한 허용 / false → 허용 해제) |
| Permit2 Single/Batch | Permit2 승인 서명 | 항목별 토큰·금액(2^160−1 → 무제한)·허용 만료 `expiration`(0 → "사용 블록에서만 유효", 2^48−1 → "만료 없음")·nonce, `spender`, 서명 기한 `sigDeadline` |
| Permit2 Transfer/Batch | Permit2 즉시 이체 서명 | 항목별 토큰·금액, `spender`, nonce, 기한 `deadline`. 문구 "이 서명으로 spender가 토큰을 바로 가져갈 수 있습니다" |
| Permit2 Witness | Permit2 즉시 이체 서명(조건 포함) | 위 + `witness 타입: {이름}` + witness 트리(§8.4) |
| Seaport | NFT 마켓 주문 서명 | offerer, zone(+라벨), orderType(`FULL_OPEN`…`CONTRACT`), 시작·종료 시각, **내가 주는 것**(offer 전부), **내가 받는 것**(recipient == 서명 계정인 consideration), **다른 사람이 받는 것**(나머지, recipient 포함), conduitKey(OpenSea 키면 라벨), counter, salt, zoneHash |

- 시각(uint256 초): `YYYY-MM-DD HH:MM:SS UTC (약 N일 후/전)`. 2^40 이상은 원시 값 + "사실상 만료 없음".
- Seaport 항목: itemType 0 → 네이티브, 1 → 토큰 금액(§2.5), 2 → `NFT #{id}`, 3 → `{id} × {amount}`, 4·5 → identifier 0이면 "컬렉션의 아무 토큰"(T14), 아니면 "기준 루트 0x…". startAmount ≠ endAmount면 "시작 a → 종료 b (시간에 따라 변함)".

### 8.4 미인식 스키마 트리

- 도메인 전체 + primaryType + message 리프를 `경로 = 값`으로 나열(경로 예: `order.items[2].amount`). 이름·타입 문자열은 §9.2 이스케이프.
- 한도: 깊이 ≤ 8, 리프 ≤ 512, string 값 ≤ 1,024바이트, bytes 값 ≤ 1,024바이트. 넘으면 T16(차단).
- 값 형식: address §2.2, 정수 10진, bool, bytes hex, string 이스케이프.

### 8.5 주소 분류

spender·operator·verifyingContract·사용자 계정에 `eth_getCode(addr, "latest")`:
- `0x` → `Eoa`; 정확히 23바이트이고 `0xef0100`으로 시작 → `Delegated7702 { target }`; 그 밖 → `Contract`.
- 표시: 레지스트리 라벨 > `[컨트랙트]` / `[일반 계정(EOA)]` / `[위임된 계정(EIP-7702) → 0x…]`.

## 9. personal_sign·SIWE (D18)

### 9.1 파라미터·다이제스트

- `params` = 정확히 `[message, address]`. `address`는 연결 계정(아니면 4100).
- `message`: `^0x([0-9a-fA-F]{2})*$`이면 hex 디코드, 아니면 문자열의 UTF-8 바이트. 바이트 ≤ 65,536.
- 다이제스트 = `keccak256(0x19 ‖ "Ethereum Signed Message:\n" ‖ 10진(len) ‖ message)`(`archive/spec-v2.4:crates/wallet-model/src/operation.rs:398-415`). `eth_sign`은 지원하지 않는다.

### 9.2 표시

- 엄격 UTF-8이면 텍스트 표시. 아니면 hex(32바이트마다 줄바꿈) + P01.
- 이스케이프(텍스트·typed data 문자열·SIWE 필드 공통): LF는 줄바꿈 유지. TAB, CR, 그 밖 제어 문자, 표시 금지 문자(`archive/spec-v2.4:crates/approval-wire/src/lib.rs:1277-1300` 목록)는 `[U+XXXX]`(대문자 hex 4–6자리) 텍스트로 바꾼다. TAB·CR 외 문자가 바뀌면 P02/T17.
- 바이트 수를 함께 표시한다. 자르지 않는다(스크롤).

```rust
pub struct DecodedPersonalMessage { pub bytes: Vec<u8>, pub text: Option<String>, pub escaped: bool,
                                    pub siwe: Option<SiweMessage>, pub siwe_marker_only: bool }
```

### 9.3 SIWE 파서 (ERC-4361)

UTF-8 텍스트에 대해 실행한다. 줄 구분은 LF만(CR 있으면 형식 불일치). 끝 LF 1개는 허용.

```
[scheme "://"] domain " wants you to sign in with your Ethereum account:" LF
address LF
LF
[statement LF]
LF
"URI: " uri LF
"Version: 1" LF
"Chain ID: " 1*DIGIT LF
"Nonce: " 8*(ALPHA / DIGIT) LF
"Issued At: " date-time
[LF "Expiration Time: " date-time]
[LF "Not Before: " date-time]
[LF "Request ID: " *pchar]
[LF "Resources:" *(LF "- " uri)]
```

- scheme: `https` 또는 `http`, 없으면 `https`. domain: RFC 3986 authority; userinfo(`@`) 있으면 S02. host는 소문자 비교.
- statement: RFC 3986 reserved/unreserved 문자와 공백만, LF 없음.
- address: 문법은 `0x` + hex 40자(대소문자 무관). 체크섬(§2.1)은 §9.4 S03에서 검사한다.
- date-time: RFC 3339 `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`(`T`/`t`, `Z`/`z`) → unix 초.
- uri·resources: 0x21–0x7E, `scheme:` 형태, 각 ≤ 2,048바이트, resources ≤ 64.
- 첫 줄에 `wants you to sign in with your Ethereum account`가 있는데 위 문법을 통과하지 못하면 `siwe_marker_only = true`(S08).

```rust
pub struct SiweMessage { pub scheme: String, pub domain_host: String, pub domain_port: Option<u16>,
    pub address: Address, pub statement: Option<String>, pub uri: String, pub chain_id: u64,
    pub nonce: String, pub issued_at: i64, pub expiration_time: Option<i64>, pub not_before: Option<i64>,
    pub request_id: Option<String>, pub resources: Vec<String>,
    // 재조립(fuzz 불변식 "필드 재조립 == 원문")용 원문 토큰: scheme_explicit, domain(원문 authority), has_userinfo(S02),
    // address_text, chain_id_text, issued_at_text, expiration_time_text, not_before_text, resources_present, trailing_lf
}
```

### 9.4 SIWE 검사 (origin = 요청 사이트의 직렬화 origin)

| 검사 | 결과 |
|---|---|
| host(domain) ≠ host(origin) | S01 차단 |
| scheme ≠ origin scheme, 또는 `http`인데 origin이 D22 로컬호스트 허용이 아님, 또는 userinfo | S02 차단 |
| address ≠ 서명 계정, 체크섬 오류 | S03 차단 |
| Expiration Time ≤ now | S04 차단 |
| domain port 있고 ≠ origin 실효 포트(`BrowserOrigin::effective_port`: https 443, http 80) | S05 주의 |
| Chain ID ≠ 활성 체인 | S06 주의 |
| Not Before > now | S07 주의 |
| `siwe_marker_only` | S08 고위험 |
| 모두 통과 | S09 정보 "로그인 요청 (SIWE)" |

SIWE 표시 필드: 도메인, 주소, 설명(statement), URI, 체인 ID, nonce, 발급·만료·유효 시작 시각(원문 + UTC 상대 시간), 요청 ID, 리소스, 그리고 원문 전체.

## 10. 위험 모델

### 10.1 등급과 승인 조작

```rust
#[repr(u8)] pub enum RiskLevel { Info = 0, Caution = 1, High = 2, Blocked = 3 }   // 정보 / 주의 / 고위험 / 차단
pub struct Warning { pub rule: RuleId, pub level: RiskLevel, pub text: String }   // 경고별 체크 없음(D16)
pub struct RuleId(pub u16);   // 상위 바이트 = 'E'(0x45)·'T'(0x54)·'P'(0x50)·'S'(0x53) EVM, 'L'(0x4C) SOL([07] §13.3), 'B'(0x42) BTC([08] §10); 하위 = 번호
```

| 등급 | 승인 조작([04](04-app-ui.md) §3.4) |
|---|---|
| 정보 | 승인 버튼 클릭 또는 Enter |
| 주의 | 정보와 같음, 경고를 노란색으로 위에 표시 |
| 고위험 | Enter 무시. "위 경고를 모두 확인했습니다" 체크박스 **1개**를 켠 뒤에만 2초 연속 누르기(마우스 또는 Space)를 시작할 수 있다(D16, 모든 체인 공통) |
| 차단 | 승인 버튼 비활성, 거부만 가능 |

차단은 서명 요청 자체가 형식·정책상 허용되지 않거나 서명할 거래를 만들 수 없을 때만 쓴다(D16, 전체 목록 §10.4). 시뮬레이션이 없거나 실패·불완전한 것과 가스 추정 실패는 차단 사유가 아니라 고위험이다(D15).

요청 등급 = 경고 등급의 최댓값(경고 없으면 정보). `ack_required = (risk == High)`. 경고 순서: 등급 내림차순, 같은 등급 안에서는 시뮬레이션 상태 규칙(E01–E04, E07–E09, E36, E37)을 먼저 두어 승인 창 맨 위에 보이고(D15), 나머지는 RuleId 오름차순(시뮬레이션 상태 규칙끼리도 RuleId 오름차순). 아래 표의 고위험 규칙은 모두 이 체크박스 하나로 확인한다. 경고 규칙 표(이 문서 §10.2–10.4, [07](07-solana.md) §13.3, [08](08-bitcoin.md) §10)에는 경고별 확인(ack) 열을 두지 않는다. 확인 필요 여부는 등급에서만 파생한다(`level == High`인 경고가 있으면 `ack_required`).

### 10.2 거래 규칙 (E)

| ID | 조건 | 등급 |
|---|---|---|
| E01 | 시뮬레이션 결과 없음: 전송 오류·시간 초과·429·최상위 RPC 오류·응답 이상·크기 초과(§6.3). 문구 "시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다" + 원인 | 고위험 |
| E02 | 시뮬레이션 실행 실패(revert·VM 오류). 문구 "시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다" + §7.4 이유 | 고위험 |
| E03 | gasUsed/maxUsedGas > gas_limit. 문구 "시뮬레이션 결과가 불완전합니다" + 원인(E04·E07·E08·E09 같음) | 고위험 |
| E04 | value>0이고 받는 주소가 자기 자신이 아닌데 네이티브 이동 로그(§1.3, 모든 체인)로 확인 안 됨 | 고위험 |
| E05 | 수수료 상한 초과(§3.4), 수수료·가스 계산 오버플로 | 차단 |
| E06 | 진행 중 거래(저널 미종결 또는 pending ≠ latest), 저널 공간 부족(§5.4-4) | 차단 |
| E07 | 시뮬레이션 블록 시각 차이 > 300 s | 고위험 |
| E08 | 시뮬레이션 표시 행 > 64(앞 64행만 표시) | 고위험 |
| E09 | diff 금액 합산 오버플로 | 고위험 |
| E10 | 가스 추정값 > 16,777,216(거래 가스 상한, D20) | 차단 |
| E11 | 서명 거래 > 131,072바이트 | 차단 |
| E12 | 해석되지 않은 calldata, 라벨만, multicall 내 미해석 (D16). 문구 "해석되지 않은 컨트랙트 호출" | 고위험 |
| E13 | 해석된 의도가 시뮬레이션 로그로 확인되지 않음 (R4·R6, 로그를 쓸 수 있을 때만) | 고위험 |
| E14 | 무제한 승인 로그(로그를 쓸 수 없으면 R8 인수): ERC-20 amount == 2^256−1, Permit2 amount == 2^160−1 | 고위험 |
| E15 | ApprovalForAll(true) | 고위험 |
| E16 | 승인 spender/operator가 `Eoa` 또는 `Delegated7702` | 고위험 |
| E17 | 서명 계정에 코드 있음(7702 위임 포함) | 고위험 |
| E18 | 0 주소로 네이티브/토큰 이동(해석 인수 또는 diff), 토큰을 그 토큰 컨트랙트 주소로 전송 | 고위험 |
| E19 | 미등록 토큰의 symbol이 같은 체인 레지스트리 symbol 또는 그 체인 `native_symbol`(예 `ETH`, `SepoliaETH`, `HYPE`)과 같음(대소문자 무시) | 고위험 |
| E20 | 유한 ERC-20·Permit2 승인(0 아님), ERC-721 개별 승인 — ERC-20 amount > 현재 `balanceOf`면 문구 "잔액보다 큰 승인" | 주의 |
| E21 | 승인 대상이 레지스트리 밖 `Contract` | 주의 |
| E22 | Permit2 approve 만료 > 30일 또는 2^48−1 | 주의 |
| E23 | dApp 요청에서 보냄은 있고 받음이 없음 | 주의 |
| E24 | `to == from`이고 data 있음 | 주의 |
| E25 | decimals 조회 실패·> 36(원시 단위 표시) | 주의 |
| E26 | symbol 읽기 실패·형식 위반 | 주의 |
| E27 | 사실 조회 한도 초과 | 주의 |
| E28 | 지갑 보내기 받는 주소가 주소록에 없음 | 정보 |
| E29 | 네이티브 단순 전송인데 받는 주소가 `Contract` | 정보 |
| E30 | 승인 해제(0 승인, ApprovalForAll false, ERC-721 approved 0, Permit2 Lockdown) | 정보 |
| E31 | dApp 수수료 필드 무시(D20) | 정보 |
| E32 | 기타 이벤트 N개 | 정보 |
| E33 | 미등록 토큰 `(미확인)` | 정보 |
| E34 | RPC 체인 불일치: chainId·제네시스(고정값 포함) 불일치(§1.4 `RpcMismatch`). 문구 "RPC 체인 불일치" | 차단 |
| E35 | 거래를 준비할 수 없음: RPC 엔드포인트 없음(`rpc:eip155:<chainId>` URL 없음, §1.4; 원인 줄 "RPC 엔드포인트 없음 — 설정에서 이 네트워크의 RPC URL을 저장하세요"), 체인 미확인(`Unverified`), 필수 조회(서명 계정 `eth_getCode`, nonce, `eth_feeHistory`) 실패·응답 이상, 단계 3–7 준비 30 s 초과(§1.4, §3.7) | 차단 |
| E36 | 체인 `simulation = unsupported`(호출하지 않음). 문구 "시뮬레이션 미지원 체인 — 실제 효과를 확인할 수 없습니다" | 고위험 |
| E37 | 가스 추정 실패(§3.5, 대체 가스 사용). 문구 "가스 추정 실패 — 거래가 실패할 수 있습니다" | 고위험 |
| E38 | `gas_limit` > `small_block_gas_limit`(HyperEVM 3,000,000, 구현 시 확인 §1.5 A9; §3.5). 문구 "HyperEVM 작은 블록 한도({n})를 넘는 거래입니다 — 계정에 큰 블록 사용이 켜져 있지 않으면 포함되지 않을 수 있습니다" | 주의 |

### 10.3 타입 데이터 규칙 (T)

| ID | 조건 | 등급 |
|---|---|---|
| T01 | domain.chainId ≠ 활성 체인 | 요청 거부(§10.4) |
| T02 | 파싱·스키마 검증 실패, primaryType `EIP712Domain`, Permit2/Seaport 주소인데 스키마 불일치, Seaport `BulkOrder` | 요청 거부 |
| T03 | domain.chainId 없음 | 고위험 |
| T04 | 미인식 스키마(필드 트리) | 고위험 |
| T05 | permit 계열: EIP-2612, DAI `allowed=true`, Permit2 Single/Batch/Transfer/BatchTransfer | 고위험 |
| T06 | Permit2 witness | 고위험 |
| T07 | owner/holder/offerer ≠ 서명 계정 | 고위험 |
| T08 | Seaport "내가 받는 것" 없음 | 고위험 |
| T09 | spender가 `Eoa`/`Delegated7702` | 고위험 |
| T10 | verifyingContract 없음 또는 0 | 주의 |
| T11 | verifyingContract가 `Eoa` | 주의 |
| T12 | 기한이 이미 지남 / 30일 초과 / 만료 없음(최댓값, DAI expiry 0, Permit2 expiration 2^48−1) | 주의 |
| T13 | Permit2 sigDeadline > 1일, Seaport endTime > 180일 | 주의 |
| T14 | Seaport criteria identifier 0, orderType `CONTRACT` | 주의 |
| T15 | DAI `allowed=false`(해제) | 정보 |
| T16 | 트리 표시 한도 초과 | 차단 |
| T17 | 문자열에 숨은·방향 제어 문자 | 주의 |

무제한 정의: 정확히 타입 최댓값(ERC-20·EIP-2612 2^256−1, Permit2 2^160−1) 또는 DAI `allowed=true`.

### 10.4 메시지 규칙 (P, S)·요청 거부

P01 UTF-8 아님(hex 표시) → 고위험(D18). P02 숨은·방향 제어 문자 → 주의. P03 일반 UTF-8 메시지 → 정보. S01–S09는 §9.4 표.

**요청 거부(창 없음)**: §3.2 파라미터 위반(금지 필드·type 1/3/4·blob·배포, D19), T01(domain.chainId 불일치), T02, 서명 계정 불일치, 미지원 메서드(`eth_sign` 등, [05](05-browser.md) §3.2)는 승인 창을 띄우지 않고 오류로 응답한다(§11.6).

**차단 규칙 전체(창을 띄우고 거부만 가능)**: E05 수수료 상한 초과, E06 진행 중 거래·저널 공간 부족, E10 거래 가스 상한 초과, E11 서명 거래 크기 초과, E34 체인 식별 불일치, E35 거래를 준비할 수 없음, T16 typed data 표시 한도 초과, S01–S04 SIWE 도메인·scheme·주소 불일치·만료. 이 밖의 규칙은 차단하지 않는다. 특히 시뮬레이션·가스 추정 관련 규칙(E01–E04, E07–E09, E36, E37)은 고위험이다(D15).

## 11. 승인 요청 모델 (yw-core `approval`)

D27·D31에 따라 이 절이 모든 체인(EVM·SOL·BTC)의 승인 요청 타입·태그·필드 키·digest의 정본이다. SOL·BTC 변형은 M7·M8에서 코드에 더하며, 값의 내용(intent·계획 바이트, 필드 문구)은 [07](07-solana.md) §13·[08](08-bitcoin.md) §10이 정한다.

### 11.1 타입

```rust
pub struct ApprovalId(pub [u8; 16]);                  // getrandom
pub enum ApprovalOrigin { App, Site(BrowserOrigin) } // 직렬화 "yw-app" / BrowserOrigin::as_str (아래)
pub enum ChainRef {                                   // chain_tag(§11.4)
    Evm { chain_id: u64, genesis: [u8; 32] },         // 1, genesis = §1.4로 확인된 값(고정·최초 신뢰 고정 포함)
    Solana { cluster: SolCluster, genesis: [u8; 32] },// 2, cluster u8: 1 mainnet, 2 devnet ([07] §2)
    Bitcoin { network: u8, genesis: [u8; 32] } }      // 3, network: 1 mainnet, 2 testnet4 ([08] §2)
pub enum AccountRef { Evm(Address), Sol([u8; 32]) /* from 공개키 */,
    Bitcoin([u8; 33]) /* 계정 공개키 m/84'/c'/0' = [08] §12.3 account_pubkey */ }
#[repr(u8)] pub enum ApprovalKind { EvmTransaction = 0x10, EvmSpeedUp = 0x11, EvmCancel = 0x12,
    EvmPersonalSign = 0x13, EvmTypedData = 0x14, SolTransfer = 0x20, BtcSend = 0x30, BtcFeeBump = 0x31 }
pub enum SigningPayload { EvmTx(Eip1559Tx), EvmPersonal(Vec<u8>), EvmTypedData([u8; 66]),
    SolTransfer(SolTransferIntent), Btc(Vec<u8>) }    // 서명 대상 바이트는 §11.4 표
pub enum Signer { Evm(EvmKeySource) /* [02] §10.3 */, FromPayload /* SOL intent source, BTC 입력별 경로 */ }
pub struct ApprovalDisplay { pub title: String, pub fields: Vec<DisplayField>, pub warnings: Vec<Warning>,
    pub risk: RiskLevel, pub ack_required: bool }
pub struct DisplayField { pub key: FieldKey, pub sub_label: String, pub value: String, pub critical: bool, pub volatile: bool }
pub struct SimBinding { pub number: u64, pub parent_hash: [u8; 32], pub timestamp: u64, pub base_fee: U256, pub sim_digest: [u8; 32] }
#[repr(u8)] pub enum SimVerdict { Ok = 0, Reverted = 1 /* E02 */, Incomplete = 2 /* E03·E04·E07·E08·E09 */ }
#[repr(u8)] pub enum SimNoneReason { Unsupported = 1 /* E36 */, Transport = 2, Timeout = 3, RateLimited = 4,
    RpcError = 5, Malformed = 6, TooLarge = 7, Skipped = 8 /* 차단으로 단계 8 전에 멈춤 */ }   // §6.3
pub enum SimulationBinding {                          // sim_tag(§11.4)
    NotApplicable,                                    // 0: 메시지·SOL·BTC
    Simulated { verdict: SimVerdict, block: SimBinding },   // 1: 시뮬레이션 블록 있음
    None { reason: SimNoneReason } }                  // 2: EVM 거래인데 결과 없음
pub struct ApprovalDraft {                            // build_* 결과: 시각·digest 없음
    pub id: ApprovalId, pub origin: ApprovalOrigin, pub chain: ChainRef, pub account: AccountRef, pub signer: Signer,
    pub kind: ApprovalKind, pub payload: SigningPayload, pub display: ApprovalDisplay,
    pub simulation: SimulationBinding,   // EVM 거래 3종은 Simulated 또는 None, 그 밖은 NotApplicable(issue가 검사, 위반 ApprovalError::SimulationBindingMismatch)
}
#[derive(Clone)] pub struct ApprovalRequest {         // ApprovalStore::issue만 만든다(§11.5)
    /* ApprovalDraft의 필드 9개 그대로 */
    pub created_unix_ms: u64,             // 발급 = A01이 Ready를 처음 표시한 시각(로그용)
    pub expires_unix_ms: u64,             // created_unix_ms + 120,000 (D23: 표시 후 120 s)
    pub digest: [u8; 32],
}
pub enum CodeKind { Eoa, Delegated7702 { target: Address }, Contract }       // §8.5
pub struct TokenMeta { pub symbol: Option<String>, pub decimals: Option<u8>, pub registered: bool }
pub struct ChainFacts { pub account_code: CodeKind, pub code: Vec<(Address, CodeKind)>,
    pub tokens: Vec<(Address, TokenMeta)>, pub balances: Vec<(Address, U256)>, pub address_book: Vec<(Address, String)> }
pub fn build_evm_tx_request(id: ApprovalId, origin: ApprovalOrigin, signer: EvmKeySource, account: Address, kind: ApprovalKind,
    chain: &ChainInfo, d: &DecodedTx, sim: &SimResult, facts: &ChainFacts, warnings: Vec<Warning>, now_unix_ms: u64)
    -> Result<ApprovalDraft, DisplayError>;
pub fn build_personal_request(/* 같은 앞 인수 */ m: &DecodedPersonalMessage, now_unix_ms: u64) -> Result<ApprovalDraft, DisplayError>;
pub fn build_typed_request(/* 같은 앞 인수 */ t: &DecodedTypedData, facts: &ChainFacts, now_unix_ms: u64) -> Result<ApprovalDraft, DisplayError>;
// Err(DisplayError)는 방어 중복(모든 입력 문자열은 §9.2로 이스케이프된다): yw-app은 요청을 내부 오류로 끝낸다
```

- `warnings`는 §3.7 단계 1–7에서 생긴 경고다(차단 E05·E06·E10·E11·E34·E35, 고위험 E37, 주의 E38, 정보 E31). 차단이 있으면 `sim`은 `Unavailable { reason: Skipped }`이다. `simulation` 필드는 `sim.binding()`이다. 빌더의 `now_unix_ms`는 상대 시각 표시와 T12·S04·S07 판정용이며 만료와 무관하다.
- `signer`는 yw-app이 서명 계정에서 정한다(meta `evm_accounts` → `Derived(index)`, `evm_raw_accounts` → `Raw(record_id)`, [02] §5.3). digest에 넣지 않는다: 다른 키로 서명하면 §4.3-5 복구 주소 검사가 막는다.
- **`BrowserOrigin`**(`yw_core::policy::BrowserOrigin`, [01](01-repo-build.md) §2.2; `policy` 모듈은 승인 모델이 쓰는 이 타입으로 M2에 시작하고 나머지는 M5): [05](05-browser.md) §4.7 Origin 형식을 그대로 구현한 유일한 origin 타입이다. API는 [05] §6.5(`parse`, `is_http`, `as_str`)에 `effective_port(&self) -> u16`(https 443, http 80; §9.4 S05)을 더한다. `as_str()`이 직렬화(`origin_serialized`, §11.4)다: `https://host[:port]` 또는 허용된 `http://localhost|127.0.0.1[:port]`, port 규칙 포함. yw-app은 별도 origin 파서를 두지 않고 이 타입을 쓴다. localhost 허용 토글은 [05](05-browser.md) §4.6이 따로 판정한다. 이식: `archive/spec-v2.4:crates/wallet-model/src/context.rs:42-131`.
- 제목 형식: `[{네트워크 이름}] {작업 제목}`(예: `[Sepolia 테스트넷] 토큰 전송: 10 USDC`). LLM 설명([06](06-llm-explain.md))은 이 타입에 들어가지 않는다(D21).

### 11.2 표시 필드 키 (`FieldKey`, u16, 표시 순서)

critical = 승인 판단에 필요한 필드(창에서 접지 않음). volatile = 재시뮬레이션으로 바뀌어도 재승인을 요구하지 않는 필드(EVM 거래만; SOL·BTC는 `replace`를 쓰지 않으므로 없음). 범위: `0x00xx` 공통 헤더, `0x01xx` EVM 거래, `0x03xx` 타입 데이터, `0x04xx` 메시지, `0x05xx` SOL, `0x06xx` BTC. 표에 없는 키는 [04](04-app-ui.md) §3.2가 거부한다.

| 키 | 이름 | critical | volatile |
|---|---|---|---|
| `0x0001`, `0x0002`, `0x0003` | 요청 출처, 네트워크, 서명 계정(모든 체인 공통) | 예 | |
| `0x0101`, `0x0102` | 받는 주소/컨트랙트(+라벨·분류), 보내는 네이티브 금액(`native_symbol`) | 예 | |
| `0x0103`, `0x0104` | 호출 내용(제목), 호출 인수(`sub_label`=인수 이름, multicall은 `calls[i].이름`) | 예 | |
| `0x0110`, `0x0111`, `0x0112` | 보냄, 받음, 승인 변경(행마다 1필드) | 예 | |
| `0x0113` | 기타 이벤트 N개 | | |
| `0x0120` | 최대 수수료(gas_limit × maxFee, 네이티브 단위) | 예 | |
| `0x0121` | 예상 수수료(시뮬레이션 블록이 있으면 `Reverted` 포함 §6.4 식, 결과 없음이면 `알 수 없음`) | | 예 |
| `0x0122`, `0x0123`, `0x0124` | maxFee/tip(gwei), 가스 한도, nonce | | |
| `0x0125` | 대체 대상 거래(해시, 기존 최대 수수료) | 예 | |
| `0x0130` | 시뮬레이션 기준(블록 번호·UTC 시각), 결과 없음이면 `시뮬레이션 없음: {원인}`(E36이면 `미지원 체인`) | | 예 |
| `0x0140`, `0x0141` | 액세스 리스트(주소 n·슬롯 m), calldata(hex 전체·바이트 수) | | |
| `0x0301`, `0x0302` | 도메인(name, version, chainId, verifyingContract), 형식(스키마 이름 또는 `알 수 없는 형식: {primaryType}`) | 예 | |
| `0x0303`, `0x0304` | 구조화 필드(`sub_label`=항목), 필드 트리(`sub_label`=경로) | 예 | |
| `0x0401`, `0x0402`, `0x0403` | 메시지 텍스트, 메시지 hex, 바이트 수 | 예, 예, 아니오 | |
| `0x0404` | SIWE 필드(`sub_label`=필드 이름) | 예 | |
| `0x0501`–`0x0505` | SOL([07] §13.3): 받는 주소, 자산·금액(SPL은 `sub_label`=항목), ATA 생성, 수수료, 최대 총 차감 | 예 | |
| `0x0506`–`0x0509` | SOL: 잔액(RPC 참고), 시뮬레이션(참고), 유효 시간, 감사(intent_hash) | | |
| `0x0601`–`0x0607`, `0x0609` | BTC([08] §10): 받는 주소, 주소 종류, 금액, 잔돈, 입력, 수수료, 총 차감, 교체 대상(`BtcFeeBump`만) | 예 | |
| `0x0608`, `0x0640` | BTC: 승인 후 잔액, 고급(version·nLockTime·RBF·vsize·weight·txid) | | |

표시 문자열 규칙: LF 외 제어 문자·표시 금지 문자 없음(빌더가 §9.2로 이스케이프, `DisplayField::new`가 다시 검사), 앞뒤 공백 없음, 값 ≤ 270,000바이트, 필드 ≤ 1,024개, 경고 ≤ 64개.

### 11.3 표시 정규 바이트·digest

```
display_bytes = "YWDSP003" ‖ u16 1 ‖ risk u8 ‖ ack_required u8 ‖ u32 len ‖ title
              ‖ u16 field_count ‖ { key u16 ‖ flags u8 (bit0 critical, bit1 volatile)
                                    ‖ u32 len ‖ sub_label ‖ u32 len ‖ value }*
              ‖ u16 warning_count ‖ { rule u16 ‖ level u8 ‖ u32 len ‖ text }*
display_digest = SHA-256(Transcript::start_domain("your-wallet/v3/display", 1).push_bytes(display_bytes))
```

정수는 BE. 모든 체인이 같은 인코딩을 쓴다(D31). 안정 부분 비교(§6.6)는 volatile 필드를 뺀 같은 인코딩의 바이트 비교다.

### 11.4 승인 digest

이식: `archive/spec-v2.4:crates/wallet-protocol/src/approval.rs:163-189`의 transcript 구조에서 registry/ruleset/rpc_observations/protocol_validity를 빼고 시뮬레이션 상태(결과 또는 결과 없음 이유)를 항상 넣도록 바꿨다.

```
T = Transcript::start_domain("your-wallet/v3/approval", 1)
T.push_bytes(id)                                  // 16
T.push_u8(kind)
T.push_str(origin_serialized)                     // "yw-app" 또는 BrowserOrigin::as_str
T.push_u8(chain_tag)                              // EVM 1, SOL 2, BTC 3
EVM: T.push_u64(chain_id); T.push_bytes(genesis)  / SOL: T.push_u8(cluster); T.push_bytes(genesis)
                                                  / BTC: T.push_u8(network); T.push_bytes(genesis)
T.push_bytes(account_bytes)                       // EVM 20, SOL 32, BTC 33바이트
T.push_bytes(signing_payload_bytes)               // 아래
T.push_bytes(display_digest)                      // 32
T.push_u8(sim_tag)                                // SimulationBinding: 0 NotApplicable, 1 Simulated, 2 None
  1: T.push_u8(verdict)                           // SimVerdict
     T.push_u64(number); T.push_bytes(parent_hash); T.push_u64(timestamp);
     T.push_bytes(base_fee_be32); T.push_bytes(sim_digest)
  2: T.push_u8(reason)                            // SimNoneReason
T.push_u64(expires_unix_ms)
digest = SHA-256(T)
```

| payload | 바이트 |
|---|---|
| `EvmTx` | `0x02 ‖ rlp(9필드)` (§4.2 preimage) |
| `EvmPersonal` | EIP-191 preimage 전체 |
| `EvmTypedData` | 66바이트 `0x19 0x01 ‖ domainSeparator ‖ hashStruct` |
| `SolTransfer` | [07] §13.2 intent transcript 바이트 전체(그 SHA-256 = `intent_hash`) |
| `Btc` | [08] §10 `btc_payload`(network·`unsigned_tx`·입력 금액·경로·잔돈·수수료·교체 대상; `display_digest`는 위 공통 필드로 따로 들어간다) |

시험: digest 입력 중 임의 1비트를 바꾸면 digest가 바뀐다(`archive/spec-v2.4:crates/wallet-protocol/src/approval.rs:708-765` 방식).

### 11.5 일회 소비·만료

```rust
pub const APPROVAL_TTL_MS: u64 = 120_000;            // D23: 표시 후 120 s
pub struct ApprovalStore { /* id → (ApprovalRequest, ApprovalState, deadline_ms: u64) */ }
pub enum ApprovalState { Pending, Consumed, Rejected, Expired, Invalidated }
pub struct Approved { /* private: id, digest, chain, account, signer, kind, payload — Clone/Copy 없음, 읽기 접근자만 */ }
impl ApprovalStore {   // now_ms = yw-win time::monotonic_ms, now_unix_ms = 벽시계 ms (yw-app이 넘김)
    pub fn issue(&mut self, d: ApprovalDraft, now_ms: u64, now_unix_ms: u64) -> Result<ApprovalRequest, ApprovalError>;
    pub fn replace(&mut self, id: ApprovalId, shown: [u8; 32], new: ApprovalDraft) -> Result<ApprovalRequest, ApprovalError>;
    pub fn consume(&mut self, id: ApprovalId, shown: [u8; 32], now_ms: u64) -> Result<Approved, ApprovalError>;
    pub fn reject(&mut self, id: ApprovalId);  pub fn expire_due(&mut self, now_ms: u64) -> Vec<ApprovalId>;
    pub fn invalidate_all(&mut self);                                                // 잠금 시
}
```

- `issue`: A01이 그 요청의 Ready 내용을 처음 표시할 때([04](04-app-ui.md) §3.5) yw-app이 호출한다. `created_unix_ms = now_unix_ms`, `expires_unix_ms = now_unix_ms + 120,000`, §11.4 `digest`를 계산하고 `deadline_ms = now_ms + APPROVAL_TTL_MS`(checked)로 저장한다. 같은 id가 있으면 오류. kind와 `simulation` 바인딩이 맞지 않으면(§11.1) `SimulationBindingMismatch`(`issue`·`replace` 공통). 반환값은 표시용 사본(비밀 없음). 다른 창이 열려 있는 동안 준비된 요청도 표시 전에는 시간이 흐르지 않는다.
- `consume`: `Pending`이고 `now_ms < deadline_ms`이고 `shown == digest`(상수 시간 비교, `subtle`)일 때만 `Consumed`로 바꾸고 `Approved`를 1회 반환한다. digest 불일치 → `Invalidated`. 그 밖 → 오류.
- `consume`은 `risk == Blocked`인 요청에 `ApprovalError::Blocked`를 돌려준다(상태 유지, 방어 중복: 차단 요청은 승인 버튼이 없다).
- `replace`(§6.6): `Pending`, `shown == 현재 digest`, `new.id == id`이고 kind·origin·chain·account·signer가 같을 때만 교체한다(payload·표시·바인딩은 바뀔 수 있다). `created_unix_ms`·`expires_unix_ms`·`deadline_ms`는 그대로 두고 digest만 다시 계산한다.
- 만료 판정은 `deadline_ms`(단조 시계)로만 한다. `expires_unix_ms`는 digest·표시·로그용이다. 지갑 잠금 → `invalidate_all`. 동시 대기 개수·창 대기열은 [05](05-browser.md) §8.4·[04](04-app-ui.md) §3.7이 정한다.
- 서명 함수(§4.2, [07] §13.1, [08] §11)는 `Approved`를 값으로 받아 소비한다. `Approved`는 `consume`으로만 만든다.

### 11.6 dApp 응답

dApp 오류 코드·문구·상위 오류 정화의 정본은 [05](05-browser.md) §5·§3.5다(D31). 이 문서의 상황은 다음 [05] §5 `ProviderError`로 응답한다.

| 상황 | `ProviderError` (code) |
|---|---|
| 승인 거부, 차단 창(E06 등) 닫음, 잠금으로 창 닫힘 | `UserRejected` (4001) |
| 승인 창 만료(표시 후 120 s, §11.5) | `Expired` (4001) |
| `from`·`address`가 grant 계정이 아님 | `Unauthorized` (4100). 잠김은 오류가 아니라 잠금 해제 창([05] §4.4) |
| §3.2·§8.1·§9.1 파라미터 위반, T01, T02 | `InvalidParams` (-32602 `Invalid params.`) |
| 송신 슬롯 사용 중(§3.6) | `TransactionPending` (-32002 `Transaction already pending.`) |
| §4.4 RPC 확정 거부·해시 불일치 | `BroadcastFailed` (-32603) |
| 저널 저장 실패(§5.3), 그 밖 내부 오류 | `Internal` (-32603) |

성공 응답: `eth_sendTransaction` → `tx_hash`(`0x` 소문자 64자), 서명 메서드 → 65바이트 서명 hex(§4.2).

## 12. dApp 읽기 메서드 중계

[05](05-browser.md) §3.1의 read 메서드를 그 origin 체인([05] §4.3)의 엔드포인트(§1.4 `endpoint(chain)` = [04] §6.3 `rpc:eip155:<chainId>` URL)로 보낸다. 파라미터 검증·정규화는 [05] §3.3–3.4, 응답 크기·오류 변환·상위 오류 정화는 [05] §3.5·§5가 정본이다. 이 문서가 더하는 규칙:

- 요청은 검증된 값만으로 다시 만들어(정규 quantity·소문자 hex, `data`·`input`은 `input` 하나) 보내고, 결과는 yw-json 파싱 후 다시 직렬화해 돌려준다. 이 결과는 승인 창에 쓰지 않는다. `eth_chainId`·`net_version`은 지갑이 직접 답한다([05] §3.1).
- 호출 시간 제한 10 s(§1.4). 결과 > 1,044,480바이트 → `ResponseTooLarge`(-32603). HTTP 429 → `RateLimited`(-32005).
- 체인 상태 `RpcMismatch`/`Unverified`(§1.4), 엔드포인트 없음, 전송 오류·시간 초과 → `ChainUnavailable`(4901 `Chain RPC is unavailable.`). 상위 JSON-RPC 오류는 [05] §3.5 규칙으로 정화해 전달한다.
- 속도 제한·동시 실행은 [05] §2.8·§8.4가 정한다(설정한 공급자 플랜의 초당 요청 한도 고려).

## 13. 테스트 벡터 (값 전문은 [09](09-testing.md))

| ID | 내용 | 단계 |
|---|---|---|
| EVM-V01 | EIP-155 예제(키 0x46×32, nonce 9): 서명 해시 `0xdaf5a779…8e53`, v 37, r·s 재현(실제 RFC 6979 서명), legacy 인코더는 테스트 전용 | M2 |
| EVM-V02 | Besu EIP-1559(chainId 4, nonce 819): 해시 `0xe0b52197…f6b2`, yParity 0, 서명 바이트 `0x02f86e…2f83`, 송신자 `0xfe3b557e…bd73` | M2 |
| EVM-V03 | EIP-191 web3.js `Some data` / eth-sig-util `Hello, world!` 서명; EIP-712 Ether Mail digest `0xbe609aee…7bd2` + 서명 v 28 | M2 |
| EVM-V04 | §8.2 typeHash 전부, 도메인 separator(Permit2 mainnet/Sepolia, Seaport 1.6, DAI), §7.1 셀렉터·§6.4 topic0 전부(Keccak 재계산 일치) | M2 |
| EVM-V05 | EIP-55: 수락(EIP-55 예제 `0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed` 등 4개, 전부 소문자, 전부 대문자), 거부(체크섬 1글자 변경, `0X`, 41/39자리) | M2 |
| EVM-V06 | RLP 거부 3종(§4.1), 서명 거래 모든 잘림·뒤 바이트 거부, U256 경계(MAX+1, 0−1), §2.4 형식 표 | M2 |
| EVM-V07 | §3.4 수수료, §3.5 가스, §4.6 대체 수수료 벡터 | M2 |
| EVM-V08 | 시뮬레이션 픽스처: mainnet 형식(`0xeeee…`, 21,000), Sepolia Glamsterdam 후(`0xff…fe`, 204,600), 두 발신자 동시 포함(SYSTEM만 계산), value>0 로그 없음(E04, `Incomplete`), revert code 3(E02, `Reverted`), 최상위 -38014(E01, `None RpcError`). 실패 픽스처는 모두 고위험·`ack_required`이고 차단 경고 없음(§6.3) | M2 |
| EVM-V09 | diff: ERC-20·721·1155(Single/Batch)·WETH Deposit/Withdrawal·Approval·ApprovalForAll·Permit2 Approval/Lockdown, 기타 이벤트 계수 | M2 |
| EVM-V10 | 해석: 각 셀렉터 정상·R1/R2 위반·R3 비레지스트리·R4 모호·R5 중첩 | M2 |
| EVM-V11 | typed data: 각 스키마 인식, chainId 불일치 거부, chainId 없음 T03, verifyingContract 없음 T10, witness, BulkOrder 거부, 트리 한도 T16 | M2 |
| EVM-V12 | SIWE: 정상, S01–S08 각 위반, CR 포함, 끝 LF 1개 | M2 |
| EVM-V13 | 저널 레코드 골든 바이트([02] §5.4 `kind 0x01` 프레이밍 포함), 상태 전이 표 전부, 손상 레코드 거부, 자리 없음 → E06 (`journal` 모듈과 함께 M4, [01] §2.2) | M4 |
| EVM-V14 | 표시 바이트·승인 digest 골든(`SimulationBinding` 태그 0·1·2 각각), 1비트 변경(verdict·reason·태그 포함), `consume` 재사용·만료(`issue`의 `now_ms` 기준)·digest 불일치, `replace` 후 만료 불변, EVM 거래 kind에 `NotApplicable`·메시지에 `Simulated` → `SimulationBindingMismatch` | M2 |
| EVM-V15 | E2E(Sepolia): ETH·ERC-20 송금, 시뮬레이션 실패(잔액보다 큰 토큰) → 고위험 경고가 맨 위 + 체크 1개·2초 누르기 후 승인·전송됨, 강제 종료 후 저널 복구 (M4); HyperEVM 소액 송금(E36 확인 후) (M4); dApp 연결·읽기·송금·personal_sign·SIWE·Permit2 typed data (M5) | M4, M5 |
| EVM-V16 | 체인 설정(가짜 전송): 내장 3체인 상수(§1.1, `templates` 포함, 사용자 체인 `templates = None`); `validate_user_chain` 각 필드 경계(chainId 0·EIP-2294 최댓값+1·중복, 이름 33자·내장 이름, 심볼 17자, 소수 37); RPC URL `http://x`·URL 없음 → 추가 거부; `rpc:eip155:<chainId>` URL이 없는 체인(템플릿 자격 정보는 있음) → 보내기 E35(원인 "RPC 엔드포인트 없음")·읽기 4901, 가짜 전송 호출 0회(템플릿 대체 없음); 추가 시 `eth_chainId` 불일치 → 거부·저장 없음; 블록 0 없음·`baseFeePerGas` 없음 → 거부; 고정 후 다른 제네시스를 주는 RPC → `RpcMismatch`: 보내기 E34 차단·읽기 4901; HyperEVM 첫 연결에서 고정·두 번째 연결 비교; RPC URL 변경 시 재확인 실패 → 저장 거부; 미종결 저널이 있는 체인 삭제 거부 | M4 |
| EVM-V17 | 시뮬레이션 정책: §6.3 표 각 행 → 해당 규칙·`SimulationBinding`·`risk == High`·차단 없음·승인 가능(가짜 승인 입력: 체크+2.0 s → `Approved`); `simulation = unsupported` → 가짜 전송의 `eth_simulateV1` 호출 0회, E36, 바인딩 `None Unsupported`; 해석되지 않은 calldata + 결과 없음 → E12·E01 함께, 체크박스 1개; 경고 순서(시뮬레이션 상태 규칙이 고위험 맨 위); 결과 없음 바인딩은 60 s 뒤 클릭에도 재시뮬레이션 없음; 재시뮬레이션 실패 → `None`으로 `replace` + 새 클릭 요구; R8(결과 없음 + `approve(spender, 2^256−1)` → E14); 가스 추정 실패 → E37 + §3.5 대체 가스 벡터; HyperEVM gas 3,120,000 → E38, 3,000,000 → E38 없음 | M2(코어), M4(`flow::evm`) |

## 14. 미결 사항

1. **D20 가스 상한과 Glamsterdam(EIP-8037)**: D20은 총 가스 한도를 16,777,216(EIP-7825)으로 묶는다. EIP-8037 이후 상태 생성 가스가 따로 계산되면 EIP-7825 상한이 실행 가스에만 적용될 수 있고, 그 경우 상태를 많이 만드는 정상 거래가 E10으로 막힌다. 확인하지 못했다. 권고: v1은 D20 그대로 두고, Sepolia에서 총 가스 > 2^24인 거래가 포함되는지 확인한 뒤 맞으면 D20을 "Amsterdam 이후 체인은 상한을 노드 `eth_estimateGas`·시뮬레이션 성공 여부로만 판단"으로 고친다.
2. **시뮬레이션 공급자 (구현 시 확인)**: 확인할 것은 §1.5 A1·A2·A5·A9(설정된 공급자의 `eth_simulateV1` 사용 가능 여부와 `traceTransfers` 네이티브 로그). 2026-10 QuickNode 문서에는 일부 체인(예: Arbitrum)의 `eth_simulateV1` 페이지만 있고 Ethereum mainnet용은 찾지 못했다(§1.5). 대안: 실패하면 그 체인의 `rpc:eip155:<chainId>` URL을 이를 지원하는 공급자 URL로 바꾸고(D13: 네트워크마다 공급자를 따로 고를 수 있다) 그 네트워크에서 A1–A9를 다시 수행하거나(사용자 조치, §1.4 체인 확인 동일), 그 체인을 `simulation = unsupported`로 둔다(내장 체인은 상수 변경). 어느 경우도 서명은 가능하고 승인 창에 E01·E04·E36 고위험 경고가 붙는다(D15). 단일 공급자에서 오는 잔여 위험은 spec §2.2 비목표다.
3. **EIP-7708 Last Call (구현 시 확인)**: mainnet 활성 전 로그 발신자·형식이 바뀌면 §1.3 상수와 EVM-V08 픽스처를 고쳐야 한다. 확인: mainnet `amsterdam_time`을 넣는 변경에서 §1.5 A1을 mainnet에 다시 수행한다. 대안: 결과가 다르면 §1.3 상수·픽스처를 고친 뒤에 상수를 넣는다(그 전까지 mainnet은 `ERC7528_NATIVE` 기대값 유지).
4. **HyperEVM (구현 시 확인, M4 전 §1.5 A9)**: (1) 설정한 공급자(현재 QuickNode)의 999 `eth_simulateV1` — 2026-10-27 실측: `/nanoreth` 경로에서 동작하므로 기본 `Auto`(§1.5). 공급자를 바꿔 -32601이면 그 체인을 `unsupported`로 둔다(E36). (2) 작은 블록 가스 한도 — 이 명세는 Hyperliquid 문서 최신판 값(작은 블록 3,000,000 약 1초, 큰 블록 30,000,000 약 1분)을 쓴다. A9(d) 관측값이 다르면 `small_block_gas_limit` 상수와 §3.5·EVM-V17 벡터를 고친다. 큰 블록은 HyperCore 동작(`evmUserModify`, `usingBigBlocks: true`)으로 계정마다 켜며 지갑은 이를 하지 않는다(E38 주의만). (3) EIP-1559 — base fee와 priority fee가 모두 소각되고 큰 블록 base fee는 따로(`bigBlockGasPrice`)라고 문서에 있다. `eth_feeHistory`가 작은 블록 기준 값을 주는지, type 2 거래가 정상 처리되는지 확인하고, 아니면 HyperEVM 수수료 규칙을 따로 정한다. (4) 블록 0 — 설정한 엔드포인트가 블록 0을 주지 않으면 999는 체인 확인을 통과할 수 없다(E35). QuickNode `/evm` 경로는 최근 블록만 보관하므로 템플릿 기본은 `/nanoreth`다(§1.1, A9 (a)). 고정 대상 블록을 바꾸려면 D14부터 고친다.
