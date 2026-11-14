# 화면 언어 (한국어·영어)

2026-11-14 신설(D39). 이 문서가 UI 언어 설정, 문구 카탈로그 구조, 승인 표시의 언어 바인딩, 그리고 **승인 창·위험 규칙·승인 표시·비밀 창의 영어 문구 전문**의 정본이다. 한국어 문구의 정본은 지금까지처럼 각 문서(위험 규칙 [03](03-evm.md) §10, 필드 이름 [03] §11.2, 승인 창 [04](04-app-ui.md) §3, 비밀 창 [04] §4, 체인별 [07]·[08]·[11]·[12]·[13])이고, 아래 §5 표의 한국어 열은 코드와 같은 값을 옮겨 적은 것이다. 표와 코드가 다르면 시험(§4)이 실패한다.

## 1. 설정과 전환

- `settings.json` 최상위 키 `language`: `"ko"`(기본) 또는 `"en"`([04] §6.1). 한국어이면 파일에 쓰지 않는다(기존 파일이 바이트 그대로 남는다). 그 밖 값은 한국어 + 배너 E-APP-001(`language`). 새 최상위 키라 이전 빌드는 모르는 키로 보존해 다시 쓴다([04] §6.6). yw-host는 읽지 않는다.
- 보안 스냅숏([04] §6.7)에 넣지 않는다: 두 언어 모두 이 문서로 고정된 문구이고, 언어는 금액·엔드포인트·규칙을 바꾸지 않는다.
- 잠금 해제 전에 읽으므로 첫 화면·잠금 화면·비밀 창부터 설정 언어로 보인다.
- 설정 → 보안 탭 맨 위 카드 `언어 · Language`: 라디오 `한국어` / `English`. 카드 제목과 두 선택지는 언어와 관계없이 같은 글자라, 지금 언어를 못 읽는 사용자도 찾을 수 있다. 바꾸면 곧바로 저장·적용한다(메인 창 다시 그림).
- 승인 창은 열릴 때의 언어로 끝까지 간다: 요청 표시를 그 언어로 만들고(§3), 창의 고정 문구도 표시의 언어를 따른다. 열린 창이 있는 동안 언어를 바꿔도 그 창은 바뀌지 않고 다음 창부터 새 언어다.
- 저널이 활동 기록으로 옮기는 행의 제목(취소 행, Bitcoin 제목)은 옮기는 순간의 앱 언어다(key 작업자에 `KeyJob::SetLanguage`로 알린다). 이미 저장된 활동 제목·저널 `label`은 서명한 때의 언어 그대로다.
- Chrome 확장 팝업은 자기 토글(`chrome.storage.local`)을 쓴다([05] §2.12, 3단계). 페이지에 던지는 고정 오류 문구는 모두 영어다([05] §2.13·§5).

## 2. 구조 (새 crate 없음)

- `yw_core::lang`: `Lang { Ko = 1, En = 2 }`, `Tpl<N> { ko, en }`(자리표시 `{0}`…`{N-1}`, `fill(lang, [&str; N])`은 인자 수를 타입으로 강제), `Text = Tpl<0>`, 그리고 카탈로그 매크로 `texts!`. 한 항목에 두 언어가 나란히 있어 번역이 빠지면 컴파일되지 않고, 매크로가 만드는 `ALL`로 시험이 모든 항목을 돈다.
- 카탈로그는 그 문구를 쓰는 모듈 옆 `text` 모듈에 둔다(§5 표 이름이 모듈 경로다). 위험 규칙은 `evm/risk/rules.rs`의 `rules!` 표에 영어 열을 더했다(`base_text(rule, lang)`).
- yw-core는 전역 언어를 읽지 않는다: 빌더·규칙 평가가 `Lang` 인자(또는 입력 구조체의 `lang`)를 받는다. yw-app은 `settings.language`를 쓰고, 승인 창 하나에 속한 모든 것(표시, 경고, 준비 실패 문구, 재시뮬레이션)은 그 창의 `lang`(`App::approval_lang`)으로 만든다.
- 번역하지 않는 것: dApp 메시지·typed data 이름·ABI 인수 이름·주소록 이름·토큰 심볼·사이트 이름 같은 신뢰하지 않는 텍스트, 숫자·금액·hex·base58·UTC 시각 형식(두 언어 같은 형식).
- 한국어 조사 처리(을/를 등)는 한국어 쪽에만 쓴다: 영어 문구는 조사만 담는 자리표시를 쓰지 않아도 된다(§4 규칙).
- 글꼴은 두 언어 모두 Malgun Gothic이다(사용자가 붙인 이름에 한글이 있을 수 있다).

## 3. 승인 표시의 언어 ("보는 것이 서명하는 것", 언어별)

- `ApprovalDisplay`에 `lang`이 있다. 제목·필드 값·sub_label·경고 문구는 모두 그 언어로 만들어진다. 승인 창은 필드 이름(`field_label(key, display.lang)`, §5 `yw_app::ui::approval::labels`), 등급 이름, 확인 체크박스, 버튼, 상태 줄을 그 언어로만 그린다. 창의 모든 글자가 (key, `display.lang`)과 표시 바이트에서 정해진다.
- 2026-11-14 첫 단계: `lang`은 표시 모델에만 있고 display 바이트는 `YWDSP003` 그대로다(한국어 표시 바이트·digest가 이 변경 전과 같다는 것을 기존 골든이 증명한다). 같은 날 다음 단계에서 `lang`을 display 바이트에 묶는다([03] §11.3).
- 재시뮬레이션(`replace`)은 요청의 원래 언어로 다시 만든다.

## 4. 시험

- `crates/yw-app/tests/lang_spec.rs`
  - `spec14_lists_every_catalogue_exactly`: 이 파일 §5의 표를 읽어, 표에 이름이 있는 카탈로그마다 모든 항목이 있고 한국어·영어가 코드와 바이트 단위로 같으며 표에만 있는 항목이 없는지 본다. 위험 규칙 표는 `ALL_RULES`의 ID·등급·두 언어 문구와 같아야 한다.
  - `every_catalogue_keeps_its_invariants`: 자리표시는 `0..N` 안에 있고 각 번호를 적어도 한 언어가 쓴다, 영어에 한글이 없다, 두 언어 모두 표시 문자 규칙([03] §11.2)을 통과한다.
  - `every_field_key_has_a_label_in_both_languages`: 코어가 받는 모든 `FieldKey`에 두 언어 이름이 있다.
  - `print_spec14_tables`(`--ignored --exact --nocapture`): §5 표를 코드에서 출력한다. 문구를 바꾸면 이것으로 표를 다시 만들고, 바뀐 행을 검토해 커밋한다.
- 빌더마다 영어 표시에 한글이 없는지 보는 단위 시험이 각 모듈에 있다(`english_*`).

## 5. 카탈로그 표 (영어 문구 전문)

셀 표기: 줄바꿈은 `\n`, 세로선은 `\|`, 역슬래시는 `\\`. `{0}`…는 자리표시다. 각 표 앞의 주석이 카탈로그 이름(코드 경로)이다.

<!-- 아래 표는 print_spec14_tables 출력이다. -->

<!-- catalogue: yw_core::evm::risk (rules) -->

| ID | 등급 | 한국어 | English |
|---|---|---|---|
| E01 | 고위험 | 시뮬레이션 결과 없음 — 실제 효과를 확인할 수 없습니다 | No simulation result — the real effect cannot be checked |
| E02 | 고위험 | 시뮬레이션에서 거래가 실패했습니다 — 수수료만 잃을 수 있습니다 | The transaction failed in simulation — you may lose the fee and get nothing |
| E03 | 고위험 | 시뮬레이션 결과가 불완전합니다 | The simulation result is incomplete |
| E04 | 고위험 | 시뮬레이션 결과가 불완전합니다 | The simulation result is incomplete |
| E05 | 차단 | 수수료가 상한을 넘습니다 | The fee exceeds the cap |
| E06 | 차단 | 진행 중인 거래가 있습니다 | A transaction is already in progress |
| E07 | 고위험 | 시뮬레이션 결과가 불완전합니다 | The simulation result is incomplete |
| E08 | 고위험 | 시뮬레이션 결과가 불완전합니다 | The simulation result is incomplete |
| E09 | 고위험 | 시뮬레이션 결과가 불완전합니다 | The simulation result is incomplete |
| E10 | 차단 | 가스 추정값이 거래 가스 상한(16,777,216)을 넘습니다 | The gas estimate exceeds the transaction gas cap (16,777,216) |
| E11 | 차단 | 서명할 거래가 너무 큽니다(131,072바이트 초과) | The transaction to sign is too large (over 131,072 bytes) |
| E12 | 고위험 | 해석되지 않은 컨트랙트 호출 | Uninterpreted contract call |
| E13 | 고위험 | 해석한 호출 내용이 시뮬레이션 결과로 확인되지 않습니다 | The interpreted call is not confirmed by the simulation result |
| E14 | 고위험 | 무제한 승인 | Unlimited approval |
| E15 | 고위험 | 컬렉션 전체 권한 부여 | Permission over the whole collection |
| E16 | 고위험 | 승인 대상이 일반 계정(EOA) 또는 위임된 계정입니다 | The approved party is a regular account (EOA) or a delegated account |
| E17 | 고위험 | 서명 계정에 코드가 있습니다(EIP-7702 위임 포함) | The signing account has code (including an EIP-7702 delegation) |
| E18 | 고위험 | 0 주소 또는 토큰 컨트랙트 자신에게 보내는 이동입니다 | A transfer to the zero address or to the token contract itself |
| E19 | 고위험 | 등록되지 않은 토큰이 알려진 심볼을 사용합니다 | An unregistered token uses a well-known symbol |
| E20 | 주의 | 토큰 사용 승인 | Token spending approval |
| E21 | 주의 | 승인 대상이 등록되지 않은 컨트랙트입니다 | The approved party is an unregistered contract |
| E22 | 주의 | Permit2 승인 만료가 30일을 넘거나 만료가 없습니다 | The Permit2 approval expires in more than 30 days or never |
| E23 | 주의 | 보내는 자산만 있고 받는 자산이 없습니다 | Assets only go out; nothing comes in |
| E24 | 주의 | 자기 자신에게 보내는 호출에 데이터가 있습니다 | A call to your own address carries data |
| E25 | 주의 | 토큰 소수 자릿수를 확인할 수 없어 원시 단위로 표시합니다 | The token's decimals cannot be read, so amounts are shown in raw units |
| E26 | 주의 | 토큰 심볼을 읽을 수 없습니다 | The token symbol cannot be read |
| E27 | 주의 | 조회 한도를 넘어 일부 정보를 원시 값으로 표시합니다 | Lookup limits were exceeded, so some details are shown as raw values |
| E28 | 정보 | 주소록에 없는 받는 주소입니다 | The recipient is not in your address book |
| E29 | 정보 | 받는 주소가 컨트랙트입니다 | The recipient is a contract |
| E30 | 정보 | 승인 해제 | Approval revoked |
| E31 | 정보 | dApp이 보낸 수수료 값은 무시하고 지갑이 계산한 수수료를 씁니다 | Fee values sent by the dApp are ignored; the wallet computes the fee |
| E32 | 정보 | 기타 이벤트 | Other events |
| E33 | 정보 | 등록되지 않은 토큰 (미확인) | Unregistered token (unverified) |
| E34 | 차단 | RPC 체인 불일치 | RPC chain mismatch |
| E35 | 차단 | 거래를 준비할 수 없음 | The transaction cannot be prepared |
| E36 | 고위험 | 시뮬레이션 미지원 체인 — 실제 효과를 확인할 수 없습니다 | Simulation is not supported on this chain — the real effect cannot be checked |
| E37 | 고위험 | 가스 추정 실패 — 거래가 실패할 수 있습니다 | Gas estimation failed — the transaction may fail |
| E38 | 주의 | HyperEVM 작은 블록 한도를 넘는 거래입니다 — 계정에 큰 블록 사용이 켜져 있지 않으면 포함되지 않을 수 있습니다 | The transaction exceeds the HyperEVM small-block limit — it may not be included unless big blocks are enabled for the account |
| E39 | 고위험 | 승인 대상의 계정 종류를 확인할 수 없습니다(조회 실패) | The account type of the approved party cannot be checked (lookup failed) |
| E40 | 고위험 | 내 자산을 보내고 받는 것은 등록되지 않은 토큰·NFT입니다 — 가짜 자산일 수 있습니다 | You send your assets and what you receive is unregistered tokens or NFTs — they may be fake assets |
| E41 | 주의 | L1 데이터 수수료를 확인하지 못했습니다 — 최대 수수료에 L1 수수료가 빠져 있습니다 | The L1 data fee could not be checked — the maximum fee does not include the L1 fee |
| E42 | 고위험 | 보내려는 금액보다 많은 자산이 빠져나갑니다 — 자산을 빼가는 거래일 수 있습니다 | More assets leave than the amount you are sending — this may be a draining transaction |
| E43 | 고위험 | 알고 있는 주소와 앞뒤가 같지만 다른 주소입니다 — 주소 오염 공격일 수 있습니다 | Same start and end as a known address, but a different address — this may be an address-poisoning attack |
| T01 | 차단 | typed data의 chainId가 현재 체인과 다릅니다 | The typed data chainId differs from the current chain |
| T02 | 차단 | typed data 형식이 올바르지 않습니다 | The typed data is malformed |
| T03 | 고위험 | 도메인에 chainId가 없습니다 — 다른 체인에서도 쓰일 수 있습니다 | The domain has no chainId — the signature may also be usable on other chains |
| T04 | 고위험 | 알 수 없는 형식의 서명 요청입니다 | Signature request in an unknown format |
| T05 | 고위험 | 토큰 사용 허가(permit) 서명입니다 — 서명만으로 토큰을 가져갈 수 있습니다 | Token spending permit signature — the signature alone lets your tokens be taken |
| T06 | 고위험 | Permit2 즉시 이체 서명(조건 포함)입니다 — 조건 내용은 해석하지 않았습니다 | Permit2 immediate transfer signature (with conditions) — the conditions were not interpreted |
| T07 | 고위험 | 소유자가 서명 계정과 다릅니다 | The owner differs from the signing account |
| T08 | 고위험 | 이 주문에서 내가 받는 것이 없습니다 | You receive nothing in this order |
| T09 | 고위험 | spender가 일반 계정(EOA) 또는 위임된 계정입니다 | The spender is a regular account (EOA) or a delegated account |
| T10 | 주의 | verifyingContract가 없거나 0 주소입니다 | verifyingContract is missing or the zero address |
| T11 | 주의 | verifyingContract가 일반 계정(EOA)입니다 | verifyingContract is a regular account (EOA) |
| T12 | 주의 | 기한이 이미 지났거나 30일을 넘거나 만료가 없습니다 | The deadline has passed, is more than 30 days away, or there is no expiry |
| T13 | 주의 | 서명 유효 기간이 깁니다 | The signature stays valid for a long time |
| T14 | 주의 | 컬렉션의 아무 토큰이나 대상이 되는 주문이거나 CONTRACT 주문입니다 | The order accepts any token of the collection, or is a CONTRACT order |
| T15 | 정보 | DAI 사용 허가 해제 | DAI permit revoked |
| T16 | 차단 | 표시 한도를 넘는 typed data입니다 | The typed data exceeds the display limit |
| T17 | 주의 | 숨은 문자 또는 방향 제어 문자가 있습니다 | Contains hidden or direction-control characters |
| T18 | 고위험 | spender의 계정 종류를 확인할 수 없습니다(조회 실패) | The spender's account type cannot be checked (lookup failed) |
| T19 | 고위험 | 내 자산을 내놓는 마켓 주문입니다 — 서명만으로 주문이 체결될 수 있습니다 | A market order that gives away your assets — the signature alone can fill the order |
| T20 | 고위험 | 등록되지 않은 토큰이 알려진 심볼을 사용합니다 | An unregistered token uses a well-known symbol |
| P01 | 고위험 | UTF-8 텍스트가 아닌 메시지입니다 — hex로 표시합니다 | The message is not UTF-8 text — shown as hex |
| P02 | 주의 | 숨은 문자 또는 방향 제어 문자가 있습니다 | Contains hidden or direction-control characters |
| P03 | 정보 | 메시지 서명 요청 | Message signature request |
| P04 | 고위험 | 텍스트로 보기 어려운 메시지입니다 — hex로 표시합니다 | The message is hard to read as text — shown as hex |
| S01 | 차단 | SIWE 도메인이 요청 사이트와 다릅니다 | The SIWE domain differs from the requesting site |
| S02 | 차단 | SIWE scheme이 요청 사이트와 다르거나 사용자 정보가 있습니다 | The SIWE scheme differs from the requesting site or contains user info |
| S03 | 차단 | SIWE 주소가 서명 계정과 다르거나 체크섬이 틀립니다 | The SIWE address differs from the signing account or has a wrong checksum |
| S04 | 차단 | SIWE 메시지가 만료되었습니다 | The SIWE message has expired |
| S05 | 주의 | SIWE 도메인의 포트가 요청 사이트와 다릅니다 | The SIWE domain port differs from the requesting site |
| S06 | 주의 | SIWE Chain ID가 현재 체인과 다릅니다 | The SIWE Chain ID differs from the current chain |
| S07 | 주의 | SIWE 메시지가 아직 유효하지 않습니다(Not Before) | The SIWE message is not valid yet (Not Before) |
| S08 | 고위험 | SIWE 형식처럼 보이지만 형식이 올바르지 않습니다 | Looks like SIWE, but the format is wrong |
| S09 | 정보 | 로그인 요청 (SIWE) | Sign-in request (SIWE) |
| M01 | 차단 | Solana 거래로 해석되는 바이트입니다 — 메시지 서명으로 거래에 서명할 수 없습니다 | These bytes parse as a Solana transaction — a message signature cannot be used to sign a transaction |
| M02 | 차단 | Solana 오프체인 메시지 머리글이 있지만 형식이 올바르지 않습니다 | There is a Solana off-chain message header, but its format is wrong |
| M03 | 차단 | Bitcoin 거래 또는 PSBT로 해석되는 바이트입니다 — 메시지 서명으로 거래에 서명할 수 없습니다 | These bytes parse as a Bitcoin transaction or PSBT — a message signature cannot be used to sign a transaction |
| M04 | 정보 | 소유 증명용 메시지 서명입니다 — 거래·송금에는 쓰이지 않습니다 | Message signature for proof of ownership — not used for transactions or transfers |
| M05 | 정보 | Solana 오프체인 메시지(v0)입니다 | Solana off-chain message (v0) |
| M06 | 차단 | Bitcoin 로그인(Sign-In-With-Bitcoin) 메시지의 도메인이 요청 사이트와 다릅니다 | The domain of the Sign-In-With-Bitcoin message differs from the requesting site |
| W01 | 차단 | SIWS 도메인이 요청 사이트와 다릅니다 | The SIWS domain differs from the requesting site |
| W02 | 차단 | SIWS 주소가 서명 계정과 다릅니다 | The SIWS address differs from the signing account |
| W03 | 차단 | SIWS Chain ID가 현재 Solana 클러스터와 다릅니다 | The SIWS Chain ID differs from the current Solana cluster |
| W04 | 차단 | SIWS 메시지가 만료되었습니다 | The SIWS message has expired |
| W05 | 주의 | SIWS 메시지가 아직 유효하지 않습니다(Not Before) | The SIWS message is not valid yet (Not Before) |
| W06 | 고위험 | SIWS 발급 시각이 현재 시각과 10분 넘게 다릅니다 | The SIWS issued-at time differs from the current time by more than 10 minutes |
| W07 | 차단 | SIWS 형식이 올바르지 않습니다 | The SIWS format is wrong |
| W08 | 정보 | 로그인 요청 (SIWS) | Sign-in request (SIWS) |
| X01 | 차단 | Solana 거래에 서명할 수 없습니다 | This Solana transaction cannot be signed |
| X02 | 고위험 | 해석하지 않은 명령을 호출합니다 — 무엇을 하는지 지갑이 확인할 수 없습니다 | Calls an uninterpreted instruction — the wallet cannot check what it does |
| X03 | 고위험 | 내 지갑(서명자)이나 내 토큰 계정이 해석하지 않은 명령에 전달됩니다 — 이 명령이 자산을 옮길 수 있습니다 | Your wallet (signer) or your token account is passed to an uninterpreted instruction — it may move your assets |
| X04 | 고위험 | 토큰 사용 권한 위임(Approve) — 위임받은 주소가 내 토큰을 옮길 수 있습니다 | Token spending delegation (Approve) — the delegate can move your tokens |
| X05 | 고위험 | 계정 권한 변경(SetAuthority) | Account authority change (SetAuthority) |
| X06 | 고위험 | 내 지갑 계정의 소유 프로그램을 바꿉니다(Assign·Allocate) | Changes the owner program of your wallet account (Assign/Allocate) |
| X07 | 고위험 | 내 토큰 계정을 닫고 남은 SOL을 다른 주소로 보냅니다 | Closes your token account and sends the remaining SOL to another address |
| X08 | 고위험 | durable nonce 거래 — 만료되지 않아 나중에 언제든 처리될 수 있습니다 | Durable nonce transaction — it does not expire and can be processed at any time later |
| X09 | 고위험 | 시뮬레이션이 실패했거나 결과가 없습니다 — 실제 효과를 확인할 수 없습니다 | The simulation failed or has no result — the real effect cannot be checked |
| X10 | 주의 | 조회 테이블 주소는 RPC가 알려준 값입니다 | The lookup table addresses are values reported by the RPC |
| X11 | 주의 | 서명만 해서 사이트에 돌려줍니다 — 지갑은 전송·추적하지 않고 활동에 남지 않습니다 | Signed only and returned to the site — the wallet does not send or track it, and it does not appear in activity |
| X12 | 주의 | Token-2022 전송 수수료가 있습니다(민트 TLV 1 TransferFeeConfig — 받는 쪽 금액이 줄 수 있습니다) | Token-2022 transfer fee applies (mint TLV 1 TransferFeeConfig — the recipient may get less) |
| X13 | 정보 | 다른 계정이 수수료를 내거나 사이트가 넣은 서명이 있습니다 | Another account pays the fee, or the site added signatures |
| X14 | 고위험 | 수수료가 설정한 상한을 넘습니다 | The fee exceeds your configured cap |
| X15 | 고위험 | 시뮬레이션에서 위임·소유자·닫기 권한이 바뀌거나 지갑 소유 프로그램이 바뀝니다 | In simulation a delegate, owner or close authority changes, or the owner program of your wallet changes |
| X16 | 고위험 | 알고 있는 주소와 앞뒤가 같지만 다른 주소입니다 — 주소 오염 공격일 수 있습니다 | Same start and end as a known address, but a different address — this may be an address-poisoning attack |
| X17 | 고위험 | 토큰에 영구 위임자 또는 전송 훅이 있습니다(Token-2022) | The token has a permanent delegate or a transfer hook (Token-2022) |
| X18 | 주의 | 런타임 한도나 규칙에 걸려 실패할 수 있습니다 (계정 128개 초과·중복되거나 잘못된 ComputeBudget) | May fail on runtime limits or rules (more than 128 accounts, duplicate or invalid ComputeBudget) |
| X19 | 주의 | 블록해시를 바꿔 시뮬레이션했습니다 — 결과는 참고용입니다 | Simulated with a replaced blockhash — the result is for reference only |
| X20 | 고위험 | RPC가 알려준 수수료가 거래에서 계산한 수수료와 다릅니다 — RPC 값을 믿을 수 없거나 수수료 규칙이 바뀌었을 수 있습니다 | The fee reported by the RPC differs from the fee computed from the transaction — the RPC value may be untrustworthy or the fee rules may have changed |
| H01 | 정보 | HyperCore 사용자 서명 작업입니다 — 서명하면 Hyperliquid가 바로 처리하며 되돌릴 수 없습니다 | HyperCore user-signed action — once signed, Hyperliquid processes it immediately and it cannot be undone |
| H02 | 주의 | 받는 주소가 주소록에 없습니다 — 주소 전체를 확인하세요 | The recipient is not in your address book — check the whole address |
| H03 | 고위험 | 알고 있는 주소와 앞뒤가 같지만 다른 주소입니다 — 주소 오염 공격일 수 있습니다 | Same start and end as a known address, but a different address — this may be an address-poisoning attack |
| H04 | 정보 | HyperEVM으로 이동합니다 — HyperEVM의 같은 주소로 들어갑니다 | Moves to HyperEVM — it arrives at the same address on HyperEVM |
| H05 | 정보 | Arbitrum 출금에는 고정 수수료 1 USDC가 듭니다(약 5분 걸림) | Arbitrum withdrawals cost a fixed fee of 1 USDC (takes about 5 minutes) |
| H06 | 고위험 | Hyperliquid 거래 권한 위임(API 지갑 승인)입니다 — 승인한 주소가 내 계정으로 주문·취소를 할 수 있습니다 | Hyperliquid trading delegation (API wallet approval) — the approved address can place and cancel orders for your account |
| H07 | 고위험 | Hyperliquid 주문·거래 서명(L1 action)입니다 — 지갑은 서명 내용(해시)을 해석할 수 없고, 이 지갑은 거래 기능을 지원하지 않습니다 | Hyperliquid order/trade signature (L1 action) — the wallet cannot interpret what is signed (a hash), and this wallet does not support trading |
| H08 | 고위험 | Hyperliquid 빌더 수수료 승인입니다 — 승인한 주소가 내 주문에 수수료를 붙일 수 있습니다 | Hyperliquid builder fee approval — the approved address can add fees to your orders |
| H09 | 주의 | hyperliquidChain이 Testnet입니다 — 테스트넷 작업입니다 | hyperliquidChain is Testnet — this is a testnet action |
| H10 | 고위험 | 사이트가 요청한 HyperCore 전송의 받는 주소가 내 계정도, 주소록에 있는 주소도 아닙니다 — 되돌릴 수 없으니 주소 전체를 확인하세요 | The recipient of the HyperCore transfer requested by the site is neither your account nor in your address book — this cannot be undone, so check the whole address |
| H11 | 고위험 | 사이트가 요청한 Arbitrum 출금(withdraw3)의 받는 주소가 서명 계정이 아닙니다 — 다른 사람에게 출금될 수 있습니다 | The recipient of the Arbitrum withdrawal (withdraw3) requested by the site is not the signing account — funds may be withdrawn to someone else |
| H12 | 고위험 | 토큰 이름과 tokenId가 spotMeta와 맞지 않거나 spotMeta를 확인할 수 없습니다 — 다른 토큰일 수 있습니다 | The token name and tokenId do not match spotMeta, or spotMeta cannot be checked — it may be a different token |
| H13 | 고위험 | HyperEVM 시스템 주소로 보내지만 이 토큰의 시스템 주소가 아니거나 HyperEVM에 연결되지 않은 토큰입니다 — 자산을 잃을 수 있습니다 | Sends to a HyperEVM system address that is not this token's, or the token is not linked to HyperEVM — you may lose the assets |
| H14 | 고위험 | HyperEVM 시스템 주소로 보내는 sendAsset이 현물(spot)→현물 이동이 아니거나 하위 계정에서 보냅니다 — HyperEVM 이동으로 확인할 수 없어 자산을 잃을 수 있습니다 | sendAsset to a HyperEVM system address is not a spot-to-spot move or is sent from a sub-account — it cannot be confirmed as a HyperEVM move and you may lose the assets |
| H15 | 고위험 | 해석하지 못한 Hyperliquid 계정 작업입니다 — 계정 권한을 넘기거나 자금을 옮기는 작업일 수 있습니다. 무엇인지 확인할 수 없으면 서명하지 마세요 | Uninterpreted Hyperliquid account action — it may hand over account control or move funds. Do not sign if you cannot tell what it is |
| H16 | 고위험 | Hyperliquid 계정을 멀티시그 계정으로 바꾸는 서명입니다 — 이후 이 계정의 작업에는 서명자 목록(signers)의 서명이 필요해, 모르는 주소가 있으면 계정과 자금을 빼앗길 수 있습니다 | Signature that turns the Hyperliquid account into a multisig account — afterwards its actions need signatures from the signers list, so an unknown address there can take the account and its funds |
| C01 | 주의 | WalletConnect 요청입니다 — 사이트 주소는 사이트가 스스로 주장한 값이며 확인되지 않았습니다 | WalletConnect request — the site address is what the site claims and is not verified |
| C02 | 고위험 | WalletConnect Verify 결과 사이트가 주장한 주소와 실제 주소가 다릅니다 — 피싱일 수 있습니다 | WalletConnect Verify reports that the site's real address differs from the claimed one — this may be phishing |
| C03 | 고위험 | WalletConnect Verify가 이 사이트를 알려진 사기 사이트로 표시했습니다 | WalletConnect Verify flagged this site as a known scam site |
| C04 | 정보 | WalletConnect 요청 — Verify 서버는 사이트가 주장한 주소와 일치한다고 알렸지만, 브라우저 밖에서 도는 dApp은 이 결과를 꾸밀 수 있습니다 | WalletConnect request — the Verify server reported a match with the claimed address, but a dApp running outside a browser can fake this result |

<!-- catalogue: yw_app::ui::approval::labels -->

| 이름 | 한국어 | English |
|---|---|---|
| ORIGIN | 요청 출처 | Requested by |
| NETWORK | 네트워크 | Network |
| ACCOUNT | 서명 계정 | Signing account |
| TO | 받는 주소/컨트랙트 | To (address/contract) |
| VALUE | 보내는 금액 | Amount sent |
| CALL | 호출 내용 | Call |
| CALL_ARG | 호출 인수 | Call argument |
| SENT | 보냄 | You send |
| RECEIVED | 받음 | You receive |
| APPROVAL | 승인 변경 | Approval change |
| OTHER_EVENTS | 기타 이벤트 | Other events |
| MAX_FEE | 최대 수수료 | Max fee |
| EXPECTED_FEE | 예상 수수료 | Expected fee |
| FEE_PARAMS | maxFee/tip | maxFee/tip |
| GAS_LIMIT | 가스 한도 | Gas limit |
| NONCE | nonce | nonce |
| REPLACES_TX | 대체 대상 거래 | Replaces transaction |
| SIMULATION | 시뮬레이션 기준 | Simulated at |
| ACCESS_LIST | 액세스 리스트 | Access list |
| CALLDATA | calldata | calldata |
| DOMAIN | 도메인 | Domain |
| SCHEMA | 형식 | Format |
| TD_FIELD | 구조화 필드 | Field |
| TD_TREE | 필드 트리 | Field tree |
| MESSAGE_TEXT | 메시지 텍스트 | Message text |
| MESSAGE_HEX | 메시지 hex | Message hex |
| MESSAGE_BYTES | 바이트 수 | Bytes |
| SIWE_FIELD | SIWE 필드 | SIWE field |
| SIWS_FIELD | SIWS 필드 | SIWS field |
| MESSAGE_FORMAT | 서명 방식 | Signature format |
| RECIPIENT | 받는 주소 | Recipient |
| ASSET_AMOUNT | 자산·금액 | Asset · amount |
| ATA | ATA 생성 | Create token account (ATA) |
| FEE | 수수료 | Fee |
| MAX_TOTAL | 최대 총 차감 | Max total deducted |
| BALANCE_RPC | 잔액 (RPC 참고) | Balance (RPC, reference) |
| SIMULATION_REFERENCE | 시뮬레이션 (참고) | Simulation (reference) |
| VALIDITY | 유효 시간 | Valid until |
| AUDIT | 감사 | Audit |
| REQUEST | 요청 | Request |
| SIGNERS | 서명자·수수료 지불 | Signers · fee payer |
| INSTRUCTIONS | 명령 | Instructions |
| WRITABLE | 쓰기 가능한 계정 | Writable accounts |
| LOOKUPS | 조회 테이블 (RPC) | Lookup tables (RPC) |
| CHANGES | 자산·권한 변화 (시뮬레이션 참고) | Asset and authority changes (simulation, reference) |
| SEND_OPTIONS | 전송 방식 | Send options |
| AUDIT_MESSAGE | 감사 (메시지 SHA-256) | Audit (message SHA-256) |
| RAW_MESSAGE | 원본 메시지 | Raw message |
| ADDRESS_TYPE | 주소 종류 | Address type |
| AMOUNT | 금액 | Amount |
| CHANGE | 잔돈 | Change |
| INPUTS | 입력 | Inputs |
| TOTAL | 총 차감 | Total deducted |
| EXPIRY_HEIGHT | 만료 높이 | Expiry height |
| BALANCE_AFTER | 승인 후 잔액 | Balance after approval |
| REPLACES | 교체 대상 | Replaces |
| ADVANCED | 고급 | Advanced |
| ACTION | 작업 | Action |
| TOKEN_AMOUNT | 토큰·금액 | Token · amount |
| HC_NONCE | nonce (time) | nonce (time) |
| HC_TYPED | 원본 typed data (EIP-712) | Raw typed data (EIP-712) |

<!-- catalogue: yw_app::ui::approval_text -->

| 이름 | 한국어 | English |
|---|---|---|
| TITLE_APPROVAL | Your Wallet — 승인 요청 | Your Wallet — Approval request |
| TITLE_CONNECT | Your Wallet — 사이트 연결 | Your Wallet — Connect site |
| APPROVE | 승인 | Approve |
| APPROVE_HOLD | 승인 (2초 길게 누르기) | Approve (hold 2 s) |
| CONNECT | 연결 | Connect |
| CANNOT_APPROVE | 승인할 수 없음 | Cannot approve |
| SIMULATING_BUTTON | 시뮬레이션 중… | Simulating… |
| REJECT | 거부 | Reject |
| ACK | 위 경고를 모두 확인했습니다 | I have read all the warnings above |
| DETAILS_OPEN | 자세히 ▾  (나머지 항목·원본 데이터) | Details ▾  (other fields · raw data) |
| DETAILS_CLOSED | 자세히 ▸  (나머지 항목·원본 데이터) | Details ▸  (other fields · raw data) |
| SUMMARY | 요약 | Summary |
| RETRY_SIMULATION | 시뮬레이션 다시 시도 | Retry simulation |
| LEVEL_HIGH | 고위험 | High risk |
| LEVEL_BLOCKED | 차단 | Blocked |
| LEVEL_CAUTION | 주의 | Caution |
| LEVEL_INFO | 정보 | Info |
| REMAINING | 남은 시간 {0} | Time left {0} |
| WAITING | 대기 {0}건 | {0} waiting |
| HELD | {0}.{1}초 | {0}.{1} s |
| CHECKING | 확인 중… | Checking… |
| SIMULATING_START | 시뮬레이션 중… (0/10초) | Simulating… (0/10 s) |
| AI_SKIP_BLOCKED | 승인할 수 없는 요청이라 AI 설명을 요청하지 않았습니다. | The request cannot be approved, so no AI explanation was requested. |
| AI_SKIP_FAILED | 요청을 준비하지 못해 AI 설명을 요청하지 않았습니다. | The request could not be prepared, so no AI explanation was requested. |
| SIM_CHANGED | 시뮬레이션 결과가 바뀌었습니다 | The simulation result changed |
| SIM_CHANGED_STEP | . 다시 확인하세요 | . Check again |
| SIM_RESIM_FAILED | 다시 실행한 시뮬레이션이 성공하지 못했습니다 | The re-run simulation did not succeed |
| SIM_RESIM_FAILED_STEP | . 경고를 확인하고 다시 승인하세요. | . Check the warnings and approve again. |
| ARM_WAIT | 잠시 뒤 버튼이 켜집니다 (실수 클릭을 막는 1초 대기) | The button turns on in a moment (a 1 s wait against accidental clicks) |
| ARM_WAIT_BACKGROUND | 이 창을 클릭해 앞으로 가져오면 1초 뒤 버튼이 켜집니다 | Click this window to bring it to the front; the button turns on 1 s later |
| ACK_FIRST | 경고를 읽고 아래 '위 경고를 모두 확인했습니다'에 체크하세요 | Read the warnings and tick 'I have read all the warnings above' below |
| HOLD_NOW | '승인'을 2초 동안 누르고 있으세요 | Hold down 'Approve' for 2 seconds |
| HOLD_EARLY | 2초가 되기 전에 놓았습니다 — 다시 2초 동안 누르세요 | Released before 2 seconds — hold it again for 2 seconds |
| CONNECT_PICK | 연결할 계정을 하나 이상 고르세요 | Choose at least one account to connect |
| BADGE_DEVNET | Solana devnet (테스트) — 실제 자산이 아닙니다 | Solana devnet (test) — not real assets |
| BADGE_TESTNET | 테스트넷 — 실제 자산이 아닙니다 | Testnet — not real assets |
| BADGE_MAINNET | 메인넷 — 실제 자산 | Mainnet — real assets |
| BADGE_HC_TESTNET | HyperCore 테스트넷 — 실제 자산이 아닙니다 | HyperCore testnet — not real assets |
| BADGE_WALLETCONNECT | WalletConnect 세션 | WalletConnect session |
| BADGE_HTTP | 로컬 개발 사이트(http) | Local development site (http) |
| BADGE_PUNYCODE | 국제화 도메인(punycode) | Internationalized domain (punycode) |
| BADGE_PUNYCODE_CHECK | 국제화 도메인(punycode) — 주소를 다시 확인하세요 | Internationalized domain (punycode) — check the address again |
| BADGE_COMPAT | 호환 모드: {0} | Compatibility mode: {0} |
| BADGE_CUSTOM_CHAIN | 사용자 추가 체인 (chainId {0}) | User-added chain (chainId {0}) |
| BADGE_YUBIKEY | YubiKey로 서명 | Signed with YubiKey |
| BADGE_TOUCHES |  · 터치 {0}회 |  · {0} touch(es) |
| SECTION_CHANGES | 자산 변화 (시뮬레이션 결과) | Asset changes (simulation result) |
| CHANGES_PARTIAL | 시뮬레이션에서 확인된 부분만 표시합니다. | Only what the simulation confirmed is shown. |
| CHANGES_NONE | 시뮬레이션 결과가 없어 자산 변화를 표시할 수 없습니다. | There is no simulation result, so asset changes cannot be shown. |
| SECTION_SOL_TX_MONEY | 자산 변화·수수료 (시뮬레이션 참고) | Asset changes · fee (simulation, reference) |
| SECTION_MONEY | 금액·수수료 | Amount · fee |
| FEE | 수수료 | Fee |
| FEE_EXPECTED | 예상 {0} (최대 {1}) | Expected {0} (max {1}) |
| FEE_MAX | 최대 {0} | Max {0} |
| SECTION_WARNINGS | 확인할 경고 | Warnings to check |
| ACK_HINT | 맨 위의 고위험 경고를 읽고, 이해했으면 아래에 체크하세요. | Read the high-risk warning at the top and, if you understand it, tick the box below. |
| SECTION_KEY | 핵심 정보 | Key details |
| SUB_LOGIN | 로그인 내용 | Log-in details |
| SUB_MESSAGE | 메시지 원문 | Original message |
| SECTION_NOTES | 참고 | Notes |
| REMARK | 참고: {0} | Note: {0} |
| ADDRESS_NOTE | 받는 주소: {0} | Recipient: {0} |
| PREPARING | 요청을 준비하는 중입니다… | Preparing the request… |
| SIMULATING | 시뮬레이션 중… ({0}/10초) | Simulating… ({0}/10 s) |
| TOKEN | 토큰 | token |
| PLACE | {0}에서  | On {0}:  |
| REVOKE | {0}아래 주소의 권한을 거둡니다(승인 해제). | {0}Revokes the permission of the address below (approval revoked). |
| GRANT_TOKEN | {0}아래 주소에 {1} 사용 권한을 줍니다: {2}. | {0}Gives the address below permission to spend {1}: {2}. |
| GRANT_INCREASE_ZERO | {0}아래 주소의 {1} 사용 권한을 늘리는 거래이지만 늘리는 양이 0이라 이미 준 권한은 그대로입니다(승인 해제가 아닙니다). | {0}A transaction that increases the {1} allowance of the address below, but by 0, so the permission already given stays as it is (this is not a revoke). |
| GRANT_INCREASE | {0}아래 주소의 {1} 사용 권한을 늘립니다: +{2} (이미 준 권한에 더해집니다). | {0}Increases the {1} allowance of the address below: +{2} (added to the permission already given). |
| GRANT_FOR_ALL | {0}아래 주소에 이 컬렉션 NFT 전체를 옮길 권한을 줍니다. | {0}Gives the address below permission to move every NFT of this collection. |
| GRANT_PERMIT2_TX | {0}아래 주소가 {1} {2} 쓸 수 있게 하는 거래입니다. | {0}A transaction that lets the address below spend {1} {2}. |
| PERMIT_SIG | {0}아래 주소가 {1} 가져갈 수 있게 하는 서명입니다. 거래 없이 서명만으로 쓰일 수 있습니다. | {0}A signature that lets the address below take {1}. It can be used with the signature alone, without a transaction. |
| PERMIT2_BATCH | {0}아래 주소가 토큰 {1}종을 쓸 수 있게 하는 서명입니다. | {0}A signature that lets the address below spend {1} kinds of tokens. |
| PERMIT2_SIG | {0}아래 주소가 {1} {2} 쓸 수 있게 하는 서명입니다. | {0}A signature that lets the address below spend {1} {2}. |
| PERMIT2_TRANSFER | {0}아래 주소가 {1} 바로 가져갈 수 있게 하는 서명입니다. | {0}A signature that lets the address below take {1} at once. |
| TOKEN_KINDS | 토큰 {0}종을 | {0} kinds of tokens |
| HL_AGENT | {0}아래 주소(API 지갑)에 내 계정으로 주문·취소할 권한을 줍니다. | {0}Gives the address below (an API wallet) permission to place and cancel orders for your account. |
| UNLIMITED_OBJECT | {0}{1} 무제한으로 | an unlimited amount of {0} |
| UNTIL | {0}까지 | until {0} |
| NO_TIME_LIMIT | 기한 없이 | with no time limit |
| PERSONAL | {0}메시지에 서명합니다. 거래를 보내지는 않지만, 서명은 로그인이나 권한 확인에 쓰일 수 있습니다. | {0}Signs a message. It sends no transaction, but the signature can be used for a log-in or a permission check. |
| SIWE | {0}{1} 사이트 로그인(Sign-In with Ethereum) 메시지에 서명합니다. 거래를 보내지는 않습니다. | {0}Signs a site log-in message (Sign-In with Ethereum) for {1}. It sends no transaction. |
| TYPED_GENERIC | {0}구조화된 데이터(EIP-712)에 서명합니다. 토큰 사용 권한(permit) 같은 권한을 줄 수 있으니 아래 내용을 확인하세요. | {0}Signs structured data (EIP-712). It can grant permissions such as a token permit, so check the content below. |
| TYPED_ACTION | {0}'{1}'에 서명합니다(EIP-712). 서명만으로 권한이나 자산이 넘어갈 수 있으니 아래 경고와 내용을 확인하세요. | {0}Signs '{1}' (EIP-712). The signature alone can hand over permissions or assets, so check the warnings and content below. |
| SEND | {0}{1}{2} 아래 주소로 보냅니다. | {0}Sends {1} to the address below. |
| SEND_ASSET | {0}{1} 보냅니다. | {0}Sends {1}. |
| ASSET_SOL | SOL을 | SOL |
| ASSET_BTC | BTC를 | BTC |
| ASSET_ZEC | ZEC를 | ZEC |
| SIWB | {0}{1} 사이트 로그인(Sign-In with Bitcoin) 메시지에 서명합니다. 거래 서명이나 전송은 하지 않습니다. | {0}Signs a site log-in message (Sign-In with Bitcoin) for {1}. It does not sign or send a transaction. |
| CONTRACT_CALL | {0}컨트랙트를 호출합니다: {1}. 아래 자산 변화와 경고를 확인하세요. | {0}Calls a contract: {1}. Check the asset changes and warnings below. |
| SPEED_UP | {0}아직 확정되지 않은 거래를 더 높은 수수료로 다시 보냅니다(가속). | {0}Sends an unconfirmed transaction again with a higher fee (speed up). |
| CANCEL | {0}아직 확정되지 않은 거래를 취소합니다(같은 nonce로 0을 보내는 거래). | {0}Cancels an unconfirmed transaction (a transaction that sends 0 with the same nonce). |
| FEE_BUMP | {0}아직 확정되지 않은 거래의 수수료를 올려 다시 보냅니다. | {0}Sends an unconfirmed transaction again with a higher fee. |
| OWNERSHIP | {0}메시지에 서명해 이 주소의 소유를 증명합니다. 거래 서명이나 전송은 하지 않습니다. | {0}Signs a message to prove that you own this address. It does not sign or send a transaction. |
| HYPERCORE | {0}Hyperliquid HyperCore 작업에 서명합니다: {1}. 서명하면 Hyperliquid가 바로 처리하며 되돌릴 수 없습니다. | {0}Signs a Hyperliquid HyperCore action: {1}. Once signed, Hyperliquid processes it immediately and it cannot be undone. |
| SIWS | {0}사이트 로그인(Sign-In-With-Solana) 메시지에 서명합니다. 거래 서명이나 전송은 하지 않습니다. | {0}Signs a site log-in message (Sign-In-With-Solana). It does not sign or send a transaction. |
| SOL_TX_SEND | {0}사이트가 만든 Solana 거래에 서명하고 지갑이 바로 전송합니다. 되돌릴 수 없습니다. | {0}Signs a Solana transaction made by the site, and the wallet sends it at once. This cannot be undone. |
| SOL_TX_SIGN | {0}사이트가 만든 Solana 거래 {1}건에 서명해 사이트에 돌려줍니다. 지갑은 전송하지 않습니다. | {0}Signs {1} Solana transaction(s) made by the site and returns them to the site. The wallet does not send them. |
| CONNECT_EVM | 이 사이트는 선택한 계정의 주소, 잔액, 거래 기록을 볼 수 있습니다. 서명과 전송은 매번 따로 승인합니다. | This site can see the address, balance and transaction history of the accounts you choose. Every signature and send is approved separately. |
| CONNECT_SOL | 이 사이트는 선택한 계정의 공개키를 볼 수 있습니다. 메시지 서명과 거래 서명·전송은 매번 따로 승인합니다. | This site can see the public key of the account you choose. Every message signature and transaction signature or send is approved separately. |
| CONNECT_BTC | 이 사이트는 선택한 주소와 공개키를 볼 수 있습니다. 이 지갑은 Bitcoin에서 메시지 서명(소유 증명)만 지원하며, 거래 서명과 전송은 할 수 없습니다. 메시지 서명은 매번 따로 승인합니다. | This site can see the addresses and public keys you choose. On Bitcoin this wallet only supports message signatures (proof of ownership); it cannot sign or send transactions. Every message signature is approved separately. |
| CONNECT_SECTION_EVM | 연결할 계정 (1–16개) | Accounts to connect (1–16) |
| CONNECT_SECTION_SOL | 연결할 Solana 계정 (1개) | Solana account to connect (1) |
| CONNECT_SECTION_BTC | 연결할 Bitcoin 주소 (용도마다 1개, 받기 주소 0번) | Bitcoin addresses to connect (1 per purpose, receive address 0) |
| CONNECT_LIMIT | 한 사이트에 연결할 수 있는 계정은 16개까지입니다. | At most 16 accounts can be connected to one site. |
| CONNECT_DEFAULT | 사이트가 기본으로 쓰는 계정: {0} (체크한 계정 중 목록의 첫 계정) | Account the site uses by default: {0} (the first checked account in the list) |
| CONNECT_NETWORK | 현재 네트워크 | Current network |
| CONNECT_ORIGIN | 요청 출처 | Requested by |

<!-- catalogue: yw_app::walletconnect::text -->

| 이름 | 한국어 | English |
|---|---|---|
| CLAIMED | {0} (사이트가 주장한 주소) | {0} (address claimed by the site) |
| NO_NAME | (이름 없음) | (no name) |
| NO_URL | (주소 없음) | (no address) |
| BAD_URL | (주소 형식이 올바르지 않음) | (malformed address) |
| VERIFY_VALID | 일치(서버 알림) | match (server report) |
| VERIFY_INVALID | 불일치(위험) | mismatch (danger) |
| VERIFY_SCAM | 알려진 사기 사이트(위험) | known scam site (danger) |
| VERIFY_UNKNOWN | 확인 불가 | unverified |
| CONNECT_VALID | WalletConnect 연결입니다. Verify 서버는 이 연결이 사이트가 주장한 주소에서 시작되었다고 알렸습니다. 다만 브라우저 밖에서 도는 dApp은 이 결과를 꾸밀 수 있으니, 지금 직접 연 사이트에서 연결했는지 확인하세요. | This is a WalletConnect connection. The Verify server reported that it started at the address the site claims. A dApp running outside a browser can fake this result, so check that you connected from a site you opened yourself just now. |
| CONNECT_UNKNOWN | WalletConnect 연결입니다. 사이트 이름과 주소는 사이트가 스스로 주장한 값이며 확인되지 않았습니다. 지금 연결하려던 사이트가 맞는지 확인하세요. | This is a WalletConnect connection. The site name and address are what the site claims and are not verified. Check that this is the site you meant to connect to. |
| CONNECT_INVALID | 위험: WalletConnect Verify 결과, 사이트가 주장한 주소와 실제 주소가 다릅니다. 피싱일 수 있습니다. 연결하지 마세요. | Danger: WalletConnect Verify reports that the site's real address differs from the claimed one. This may be phishing. Do not connect. |
| CONNECT_SCAM | 위험: WalletConnect Verify가 이 사이트를 알려진 사기 사이트로 표시했습니다. 연결하지 마세요. | Danger: WalletConnect Verify flagged this site as a known scam site. Do not connect. |
| SITE_NAME | 사이트 이름 (사이트가 주장) | Site name (claimed by the site) |
| NETWORKS | 연결할 네트워크 (WalletConnect) | Networks to connect (WalletConnect) |
| UNSUPPORTED | 이 지갑이 지원하지 않는 요청은 거부됩니다: {0} | Requests this wallet does not support are rejected: {0} |
| DROPPED | 사이트가 요구한 알 수 없는 요청·이벤트 이름 {0}개는 세션에서 뺐습니다. | {0} unknown request or event name(s) the site asked for were left out of the session. |

<!-- catalogue: yw_app::flow::evm::prepare -->

| 이름 | 한국어 | English |
|---|---|---|
| NO_ENDPOINT | RPC 주소 없음 — 설정 → 네트워크(RPC)에서 이 네트워크의 RPC 주소를 넣으세요 | No RPC address — enter this network's RPC address in Settings → Network (RPC) |
| FEE_OVERFLOW | 수수료 계산이 범위를 넘었습니다 | The fee calculation is out of range |
| DAPP_NONCE | dApp이 지정한 nonce가 지갑의 nonce와 다릅니다 | The nonce set by the dApp differs from the wallet's nonce |
| REPLACED_DONE | 대체할 거래가 이미 처리되었습니다 (nonce {0}) | The transaction to replace was already processed (nonce {0}) |
| REPLACE_LIMIT | 같은 nonce의 대체 거래는 최대 {0} 번입니다 (nonce {1}) | At most {0} replacements per nonce (nonce {1}) |

<!-- catalogue: yw_app::ui::secret_text -->

| 이름 | 한국어 | English |
|---|---|---|
| TITLE_SET_PASSWORD | 비밀번호 정하기 | Set a password |
| UNLOCK | 잠금 해제 | Unlock |
| TITLE_CONFIRM_PASSWORD | 비밀번호 확인 | Confirm password |
| TITLE_CHANGE_PASSWORD | 비밀번호 변경 | Change password |
| TITLE_MNEMONIC | 복구 단어 입력 | Enter recovery words |
| TITLE_PASSPHRASE | passphrase 입력 | Enter passphrase |
| TITLE_PRIVATE_KEY | 개인키 가져오기 | Import private key |
| TITLE_SHOW_MNEMONIC | 복구 단어 (니모닉) | Recovery words (mnemonic) |
| TITLE_SHOW_KEY | 개인키 보기 | View private key |
| TITLE_BACKUP | 백업 확인 | Backup check |
| TITLE_ADMIN_PIN | YubiKey 관리자 PIN | YubiKey admin PIN |
| TITLE_MANAGEMENT_KEY | YubiKey PIV 관리 키 | YubiKey PIV management key |
| TITLE_SET_PINS | YubiKey PIN 하나로 통일 | Use one PIN for the YubiKey |
| TITLE_USER_PIN | YubiKey PIN 확인 (선택) | Check YubiKey PIN (optional) |
| TITLE_CHANGE_OPENPGP_PIN | OpenPGP PIN 바꾸기 | Change OpenPGP PIN |
| TITLE_CHANGE_ADMIN_PIN | OpenPGP 관리자 PIN 바꾸기 | Change OpenPGP admin PIN |
| TITLE_CHANGE_PIV_PIN | PIV PIN 바꾸기 | Change PIV PIN |
| TITLE_CHANGE_PIV_PUK | PIV PUK 바꾸기 | Change PIV PUK |
| NAME_OPENPGP_ADMIN | OpenPGP 관리자 PIN | OpenPGP admin PIN |
| PIN_RULE | 영문·숫자·기호(ASCII) {0}–{1}자입니다(공장 기본값 {2}). | Letters, digits and symbols (ASCII), {0}–{1} characters (factory default {2}). |
| LABEL_PASSWORD | 비밀번호 | Password |
| LABEL_PASSWORD_AGAIN | 비밀번호 확인 | Confirm password |
| LABEL_CURRENT_PASSWORD | 현재 비밀번호 | Current password |
| LABEL_NEW_PASSWORD | 새 비밀번호 | New password |
| LABEL_NEW_PASSWORD_AGAIN | 새 비밀번호 확인 | Confirm new password |
| LABEL_WORDS | 복구 단어 | Recovery words |
| LABEL_PASSPHRASE_AGAIN | passphrase 확인 | Confirm passphrase |
| LABEL_EVM_KEY | 개인키 (16진수 64자리) | Private key (64 hex digits) |
| LABEL_SOL_KEY | Solana 개인키 (base58 keypair 또는 JSON 배열) | Solana private key (base58 keypair or JSON array) |
| LABEL_BTC_KEY | Bitcoin 개인키 (WIF) | Bitcoin private key (WIF) |
| LABEL_ZEC_KEY | Zcash 개인키 (압축 WIF 또는 16진수 64자리) | Zcash private key (compressed WIF or 64 hex digits) |
| LABEL_MANAGEMENT_KEY | PIV 관리 키 (16진수 48자리) | PIV management key (48 hex digits) |
| LABEL_CURRENT | 현재 {0} | Current {0} |
| LABEL_NEW | 새 {0} | New {0} |
| LABEL_NEW_AGAIN | 새 {0} 확인 | Confirm new {0} |
| LABEL_SET_PINS_CURRENT | 현재 PIN (공장 기본값이면 비워 두기) | Current PIN (leave empty if factory default) |
| LABEL_SET_PINS_NEW | 새 PIN (8자) | New PIN (8 characters) |
| LABEL_SET_PINS_AGAIN | 새 PIN 확인 | Confirm new PIN |
| LABEL_WORD | {0}번째 단어 | Word {0} |
| PASSWORD_RULE | 비밀번호는 영문·숫자·기호(ASCII) 12–128자입니다. 단어 4개 이상을 이은 긴 문장을 권장합니다. 잊으면 복구 단어(니모닉)로만 복구할 수 있습니다. | The password is 12–128 letters, digits and symbols (ASCII). A long phrase of four or more words is recommended. If you forget it, you can recover only with the recovery words (mnemonic). |
| CHANGE_PASSWORD_NOTE | 비밀번호를 바꾸면 암호화 키도 새로 만들어, 바꾼 뒤의 내용은 예전 사본으로 열 수 없습니다. 바꾸기 전에 만든 지갑 파일 사본(백업한 vault.ywv 등)은 예전 비밀번호로 계속 열리고 그때의 내용이 드러납니다(예전 비밀번호가 약했다면 나중에 오프라인으로 풀릴 수 있습니다). | Changing the password also makes a new encryption key, so what is stored after the change cannot be opened with older copies. Copies of the wallet file made before the change (such as a backed-up vault.ywv) still open with the old password and reveal what they held then (if the old password was weak, it may be cracked offline later). |
| UNLOCK_INTRO | 지갑을 열려면 비밀번호를 입력하세요. | Enter your password to open the wallet. |
| CONFIRM_INTRO | 계속하려면 비밀번호를 다시 입력하세요. | Enter your password again to continue. |
| MNEMONIC_INTRO | 다른 지갑에서 쓰던 영어 복구 단어(BIP39 니모닉) 12·15·18·21·24개를 순서대로 입력하세요. 공백 또는 Tab으로 다음 칸으로 넘어갑니다. 목록에 없는 단어는 빨간색으로 표시합니다. | Enter the 12, 15, 18, 21 or 24 English recovery words (BIP39 mnemonic) you used in another wallet, in order. Space or Tab moves to the next box. Words that are not in the list are shown in red. |
| PASSPHRASE_CONFIRM_INTRO | 이전 지갑에서 쓰던 BIP39 passphrase를 두 번 입력하세요. ASCII만 지원합니다. | Enter the BIP39 passphrase you used in your previous wallet twice. Only ASCII is supported. |
| PASSPHRASE_INTRO | 이 지갑의 BIP39 passphrase를 입력하세요. | Enter this wallet's BIP39 passphrase. |
| EVM_KEY_INPUT | 가져올 EVM 개인키(16진수 64자리, 0x 선택)를 입력하세요. | Enter the EVM private key to import (64 hex digits, 0x optional). |
| SOL_KEY_INPUT | Phantom·Solflare의 '개인키 내보내기'로 받은 base58 문자열(64바이트 keypair) 또는 solana-keygen JSON 파일의 내용([숫자 64개])을 붙여넣으세요. 주소(32바이트)는 개인키가 아닙니다. | Paste the base58 string (64-byte keypair) from 'Export private key' in Phantom or Solflare, or the content of a solana-keygen JSON file ([64 numbers]). An address (32 bytes) is not a private key. |
| ZEC_KEY_INPUT | Zcash 개인키를 붙여넣으세요: 압축 WIF(K·L로 시작하면 mainnet, c로 시작하면 testnet — Zcash 탭의 네트워크와 같아야 함) 또는 16진수 64자리(지금 Zcash 탭의 네트워크로 씀). 일반(transparent) 주소 하나로 씁니다. | Paste a Zcash private key: compressed WIF (starting with K or L is mainnet, with c is testnet — it must match the network of the Zcash tab) or 64 hex digits (used on the current network of the Zcash tab). It is used as one transparent address. |
| BTC_KEY_INPUT | WIF 형식 개인키(5·K·L로 시작하면 mainnet, 9·c로 시작하면 testnet4)를 붙여넣으세요. 주소 형식은 앞 화면에서 고른 것으로 만듭니다. | Paste a private key in WIF format (starting with 5, K or L is mainnet, with 9 or c is testnet4). The address type is the one you chose on the previous screen. |
| IMPORTED_KEY_BACKUP | 주의: 가져온 개인키는 이 지갑의 복구 단어(24단어)로 복구되지 않습니다. 이 PC나 지갑 파일을 잃으면 이 계정은 원래 개인키로만 되살릴 수 있으니, 원래 개인키를 따로 안전하게 보관하세요. | Caution: imported private keys are not recovered by this wallet's recovery words (24 words). If you lose this PC or the wallet file, this account can be restored only with the original private key, so keep the original private key safe separately. |
| KEY_ONLY_BACKUP | 주의: 이 지갑에는 복구 단어가 없습니다. 이 계정의 백업은 지금 입력하는 원래 개인키뿐입니다. 이 PC나 지갑 파일을 잃으면 원래 개인키로만 되살릴 수 있으니, 원래 개인키를 종이 등 안전한 곳에 따로 보관하세요. | Caution: this wallet has no recovery words. The only backup of this account is the original private key you are entering now. If you lose this PC or the wallet file, it can be restored only with the original private key, so keep the original private key separately in a safe place, such as on paper. |
| SHOW_WORDS | 아래 {0}단어{1}를 순서대로 종이에 적으세요. 이 단어들이 지갑의 유일한 백업이며, 아는 사람은 누구든 자산을 옮길 수 있습니다. 이 창은 화면 캡처에서 제외됩니다. | Write the {0} words below{1} on paper, in order. These words are the wallet's only backup, and anyone who knows them can move your assets. This window is excluded from screen capture. |
| WITH_ADDRESS | 와 첫 주소 |  and the first address |
| SHOW_KEY_INTRO | 개인키입니다. 다른 사람에게 보여주거나 사진·클라우드에 남기지 마세요. 이 창은 화면 캡처에서 제외됩니다. | This is a private key. Do not show it to anyone or leave it in photos or the cloud. This window is excluded from screen capture. |
| BACKUP_INTRO | 적은 종이를 보고 {0}, {1}, {2}, {3}번째 단어를 입력하세요. | Looking at your paper, enter words {0}, {1}, {2} and {3}. |
| CHANGE_PIN_INTRO | YubiKey를 하나만 연결하고 현재 {0}과(와) 새 {0}을(를) 입력하세요. {1} 이 지갑은 PIN을 저장하지 않으니 새 {0}을(를) 따로 기억해 두세요. | Connect only one YubiKey and enter the current {0} and the new {0}. {1} This wallet does not store PINs, so remember the new {0} yourself. |
| CARD_PIN | PIN은 이 서명 한 번에만 쓰고 바로 지웁니다. | The PIN is used for this one signature only and wiped right away. |
| CARD_PIN_STEPS | 1. {0} 연결 → 2. PIN 입력 후 확인 → 3. 깜박이면 15초 안에 터치 (승인 뒤 120초 안에) | 1. Connect {0} → 2. Enter the PIN and confirm → 3. When it blinks, touch it within 15 s (within 120 s of approval) |
| CARD_TOUCHES_PER_TX | YubiKey 터치 {0}회가 필요합니다 (거래마다 한 번, 15초 유지 정책이면 첫 터치 뒤 15초 안의 거래는 터치 없이 서명됩니다). | {0} YubiKey touches are needed (one per transaction; with the 15 s cached-touch policy, transactions within 15 s of the first touch are signed without a touch). |
| CARD_TOUCHES_PER_INPUT | YubiKey 터치 {0}회가 필요합니다 (입력마다 한 번, 15초 유지 정책이면 첫 터치 뒤 15초 안의 입력은 터치 없이 서명됩니다). | {0} YubiKey touches are needed (one per input; with the 15 s cached-touch policy, inputs within 15 s of the first touch are signed without a touch). |
| CARD_ADMIN_PIN | YubiKey를 하나만 연결하고 OpenPGP 관리자 PIN(PW3, 8–127자, 공장 기본값 12345678)을 입력하세요. 키를 가져오는 동안 한 번만 쓰고 바로 지웁니다. | Connect only one YubiKey and enter the OpenPGP admin PIN (PW3, 8–127 characters, factory default 12345678). It is used once while the keys are imported and wiped right away. |
| CARD_MANAGEMENT_KEY | YubiKey의 PIV 관리 키를 16진수 48자리로 입력하세요(ykman이 보여주는 형식). 이 지갑은 관리 키를 저장하지 않으며, 이번 작업에만 쓰고 바로 지웁니다. | Enter the YubiKey's PIV management key as 48 hex digits (the format ykman shows). This wallet does not store the management key; it is used for this task only and wiped right away. |
| CARD_USER_PIN | 선택 사항입니다: 이 YubiKey의 PIN을 한 번 확인해 카드가 내 것인지 봅니다(VERIFY 한 번 — 서명·터치·쓰기 없음). 틀리면 남은 시도가 하나 줄어듭니다. 공장 기본 PIN(123456)은 보내지 않습니다. 확인하지 않아도 연결할 수 있고, 서명할 때는 언제나 PIN과 터치가 필요합니다. | Optional: checks this YubiKey's PIN once to see that the card is yours (one VERIFY — no signature, touch or write). A wrong PIN takes one try off the remaining tries. The factory default PIN (123456) is not sent. You can connect without checking, and signing always needs the PIN and a touch. |
| CARD_PIV_PIN | YubiKey를 하나만 연결하고 PIV PIN(6–8자, 공장 기본값 123456)을 입력하세요. PIN으로 보호된 PIV 관리 키를 꺼내는 데 한 번만 쓰고 바로 지웁니다. | Connect only one YubiKey and enter the PIV PIN (6–8 characters, factory default 123456). It is used once to unlock the PIN-protected PIV management key and wiped right away. |
| CARD_SET_PINS | YubiKey를 하나만 연결하세요. 새 8자 PIN 하나를 OpenPGP PIN·OpenPGP 관리자 PIN·PIV PIN·PIV PUK에 똑같이 넣고, PIV 관리 키는 자동으로 새로 만들어 PIN으로 보호합니다. 현재 값이 공장 기본값이면 '현재 PIN'을 비워 두고, 전에 하나로 통일했다면 그 8자를 넣으세요. 공장 기본값(12345678)은 새 PIN으로 쓸 수 없습니다. 중간에 실패하면 거기서 멈추고 바뀐 것만 알려 드립니다. | Connect only one YubiKey. One new 8-character PIN is set as the OpenPGP PIN, OpenPGP admin PIN, PIV PIN and PIV PUK alike, and a new PIV management key is made automatically and protected by the PIN. If the current values are the factory defaults, leave 'Current PIN' empty; if you unified them before, enter those 8 characters. The factory default (12345678) cannot be the new PIN. If a step fails, it stops there and tells you only what changed. |
| CARD_SET_PINS_SAME | 지금 네 값이 모두 같을 때만(공장값이거나 전에 통일한 값) 쓰세요. 다르면 “하나씩 따로”를 쓰세요. 틀린 현재 값은 그 PIN의 남은 시도를 1회 줄입니다. | Use this only when all four values are the same now (factory values or values you unified before). If they differ, use “One at a time”. A wrong current value takes one try off that PIN's remaining tries. |
| CARD_NEW_FACTORY | 공장 기본값(123456·12345678)은 새 PIN으로 쓸 수 없습니다 — YubiKey를 가진 사람이 그 값으로 바로 서명할 수 있습니다. 다른 값을 고르세요. | A factory default (123456 or 12345678) cannot be a new PIN — anyone holding the YubiKey could sign with it right away. Choose another value. |
| PW_RULE_OK | ✓ 12–128자 | ✓ 12–128 characters |
| PW_RULE_SHORT | ✗ 12자 이상 필요 | ✗ At least 12 characters needed |
| PW_RULE_EMPTY | · 12–128자 | · 12–128 characters |
| PW_SAME | ✓ 두 칸이 같음 | ✓ Both fields match |
| PW_DIFFERENT | ✗ 두 칸이 다름 | ✗ The two fields differ |
| PW_AGAIN | · 확인 칸에 한 번 더 입력 | · Enter it once more in the confirm field |
| ERR_CARD_PIN | PIN은 영문·숫자·기호(ASCII) {0}–{1}자입니다. | The PIN is {0}–{1} letters, digits and symbols (ASCII). |
| ERR_ADMIN_PIN | 관리자 PIN은 영문·숫자·기호(ASCII) 8–127자입니다. | The admin PIN is 8–127 letters, digits and symbols (ASCII). |
| ERR_MANAGEMENT_KEY | 관리 키는 16진수(0–9, a–f) 48자리입니다. | The management key is 48 hex digits (0–9, a–f). |
| ERR_PIV_PIN | PIV PIN은 영문·숫자·기호(ASCII) 6–8자입니다. | The PIV PIN is 6–8 letters, digits and symbols (ASCII). |
| ERR_OPENPGP_PIN | OpenPGP PIN은 영문·숫자·기호(ASCII) 6–127자입니다. | The OpenPGP PIN is 6–127 letters, digits and symbols (ASCII). |
| ERR_SET_PINS_CURRENT | 현재 PIN은 비워 두거나(공장 기본값) 전에 통일한 8자를 넣으세요. | Leave the current PIN empty (factory defaults) or enter the 8 characters you unified before. |
| ERR_SET_PINS_NEW | 새 PIN은 영문·숫자·기호(ASCII) 정확히 8자입니다. | The new PIN is exactly 8 letters, digits and symbols (ASCII). |
| ERR_SET_PINS_DIFFER | 새 PIN 두 칸이 서로 다릅니다. | The two new PIN fields differ. |
| ERR_SET_PINS_SAME | 새 PIN이 현재 값과 같습니다. | The new PIN is the same as the current value. |
| ERR_NEW_DIFFER | 새 {0} 두 칸이 서로 다릅니다. | The two new {0} fields differ. |
| ERR_NEW_SAME | 새 {0}이(가) 현재 값과 같습니다. | The new {0} is the same as the current value. |
| PASSPHRASE_CHECKBOX | BIP39 passphrase 사용 | Use a BIP39 passphrase |
| PASSPHRASE_NOTE | 이전 지갑에서 BIP39 passphrase(25번째 단어)를 썼을 때만 켜세요. ASCII만 지원합니다. | Turn this on only if you used a BIP39 passphrase (25th word) in your previous wallet. Only ASCII is supported. |
| UNLISTED_WORD | {0}번째 칸의 단어가 BIP39 단어 목록에 없습니다. 오타인지, 종이의 철자를 다시 보세요. | Word {0} is not in the BIP39 word list. Check for a typo, and check the spelling on your paper again. |
| COUNTDOWN | {0}:{1} 남음 — 지나면 창이 닫힙니다 | {0}:{1} left — then the window closes |
| CHECKING | 확인 중… | Checking… |
| CAPTURE_WARN | 화면 캡처 제외가 적용되지 않았습니다. 화면 공유·녹화 중이면 입력하지 마세요. | This window is not excluded from screen capture. Do not type while sharing or recording the screen. |
| MASKED | 창이 비활성화되어 내용을 가렸습니다. 창을 클릭하면 다시 표시합니다. | The window is inactive, so its content is hidden. Click the window to show it again. |
| FIRST_ADDRESS | 첫 주소 (계정 1) — 함께 적어 두면 복구할 때 맞는지 확인할 수 있습니다 | First address (account 1) — write it down too, so you can check it when you recover |
| PASSPHRASE_REVEAL_NOTE | 이 지갑은 passphrase를 사용합니다. passphrase는 저장되지 않으므로 따로 보관해야 합니다. | This wallet uses a passphrase. The passphrase is not stored, so you must keep it separately. |
| WORDS_TYPED | {0}단어 입력 · {1}/{2} | {0} words entered · {1}/{2} |
| WORD_LISTED | 목록에 있음 | In the list |
| WORD_UNLISTED | 목록에 없는 단어 | Not in the list |
| REVEAL | 보기 | Show |
| STEPS | {0} · {1}/{2}단계 | {0} · step {1}/{2} |
| HOLD_PROGRESS | 다 적었습니다 ({0}초) | I have written them down ({0} s) |
| HOLD | 다 적었습니다 (2초 길게 누르기) | I have written them down (hold 2 s) |
| CLOSE | 닫기 | Close |
| CHANGE | 변경 | Change |
| NEXT | 다음 | Next |
| IMPORT | 가져오기 | Import |
| OK | 확인 | OK |
| LATER | 나중에 | Later |
| CANCEL | 취소 | Cancel |
| CLEAR_ALL | 모두 지우기 | Clear all |
| COPY | 복사 | Copy |

<!-- catalogue: display-fixed -->

| 이름 | 한국어 | English |
|---|---|---|
| APP_ORIGIN | Your Wallet 앱 | Your Wallet app |
| BTC_MAINNET | BITCOIN MAINNET | BITCOIN MAINNET |
| BTC_TESTNET4 | BITCOIN TESTNET4 — 가치 없음 | BITCOIN TESTNET4 — no value |

<!-- catalogue: yw_core::evm::risk::text -->

| 이름 | 한국어 | English |
|---|---|---|
| UNLIMITED_HUGE | 2^128 이상의 승인 — 사실상 무제한 | Approval of 2^128 or more — effectively unlimited |
| UNLIMITED_ABOVE_BALANCE | 잔액보다 큰 승인 — 사실상 무제한 | Approval larger than the balance — effectively unlimited |
| EXCESS_LARGER | 보내는 자산이 거래 금액보다 많이 나갑니다 | More of the sent asset leaves than the transaction amount |
| EXCESS_UNSHOWN | 거래에 없는 다른 자산 {0}개도 나갑니다 | {0} other asset(s) not in the transaction also leave |
| EXCESS_BOTH | 보내는 자산이 거래 금액보다 많이 나가고, 거래에 없는 다른 자산 {0}개도 나갑니다 | More of the sent asset leaves than the transaction amount, and {0} other asset(s) not in the transaction also leave |
| ENDS_SUFFIX | 끝 {0}자 | last {0} characters |
| ENDS_PREFIX | 앞 {0}자 | first {0} characters |
| ENDS_BOTH | 앞 {0}자·끝 {1}자 | first {0} and last {1} characters |
| LOOK_ALIKE_HISTORY | 보낸 내역에 있는 주소와 {0}가 같습니다: {1} | Same {0} as an address in your send history: {1} |
| LOOK_ALIKE_MINE | 내 계정 '{0}'과 {1}가 같습니다: {2} | Same {1} as your account '{0}': {2} |
| LOOK_ALIKE_BOOK | 주소록 '{0}'과 {1}가 같습니다: {2} | Same {1} as address book entry '{0}': {2} |
| MULTICALL_EMPTY | 내부 호출이 없는 묶음 호출 | Batch call without inner calls |
| MULTICALL_UNINTERPRETED | 해석되지 않은 호출 포함 | Contains uninterpreted calls |
| R4_UNRESOLVED | 시뮬레이션 로그로 토큰 종류(ERC-20/ERC-721)를 정할 수 없습니다 | The simulation logs cannot tell the token kind (ERC-20/ERC-721) |
| R6_UNCONFIRMED | 해석한 승인·이동이 시뮬레이션 로그에 없거나 다릅니다 | The interpreted approval or transfer is missing from the simulation logs or differs |
| ACCOUNT_CODE_UNKNOWN | 서명 계정의 코드를 확인할 수 없습니다 | The signing account's code cannot be checked |
| ONLY_UNVERIFIED_RECEIPTS | 받는 자산은 등록되지 않은 토큰·NFT뿐입니다 | The only assets received are unregistered tokens or NFTs |
| SITE_RECIPIENT | 사이트가 정한 주소입니다 — 받는 주소가 맞는지 확인하세요 | The site chose this address — check that the recipient is right |
| OTHER_EVENTS | 기타 이벤트 {0}개 | Other events: {0} |
| ORDER_ONLY_UNVERIFIED | 받는 것이 등록되지 않은 토큰·NFT뿐입니다 | All you receive are unregistered tokens or NFTs |

<!-- catalogue: yw_core::evm::text -->

| 이름 | 한국어 | English |
|---|---|---|
| TITLE_TOKEN_TRANSFER | 토큰 전송 | Token transfer |
| TITLE_TOKEN_APPROVE | 토큰 사용 승인 | Token spending approval |
| TITLE_TOKEN_TRANSFER_FROM | 토큰 이체 | Token transfer from |
| TITLE_ALLOWANCE_INCREASE | 토큰 승인 증가 | Token approval increase |
| TITLE_ALLOWANCE_DECREASE | 토큰 승인 감소 | Token approval decrease |
| TITLE_APPROVAL_FOR_ALL | 컬렉션 전체 권한 | Permission over the whole collection |
| TITLE_NFT_TRANSFER | NFT 이체 | NFT transfer |
| TITLE_NFT_APPROVE | NFT 개별 승인 | Single NFT approval |
| TITLE_MULTI_TOKEN_TRANSFER | 멀티 토큰 이체 | Multi-token transfer |
| TITLE_MULTI_TOKEN_BATCH | 멀티 토큰 일괄 이체 | Multi-token batch transfer |
| TITLE_WRAP | {native} → {wrapped} 변환 | Convert {native} → {wrapped} |
| TITLE_UNWRAP | {wrapped} → {native} 변환 | Convert {wrapped} → {native} |
| TITLE_PERMIT2_APPROVE | Permit2 승인 | Permit2 approval |
| TITLE_PERMIT2_LOCKDOWN | Permit2 승인 해제 | Permit2 approval revoke |
| TITLE_PERMIT2_INVALIDATE_NONCES | Permit2 nonce 무효화 | Permit2 nonce invalidation |
| TITLE_PERMIT2_INVALIDATE_SIGNATURES | Permit2 서명 무효화 | Permit2 signature invalidation |
| TITLE_PERMIT_SUBMIT | permit 제출 | Submit permit |
| TITLE_DAI_PERMIT_SUBMIT | DAI permit 제출 | Submit DAI permit |
| REVERT_NO_REASON | 이유 없이 되돌려짐 | Reverted without a reason |
| REVERT_UNREADABLE | 메시지 형식 불명 | Unreadable message |
| REVERT_UNVERIFIED_MESSAGE | (검증되지 않은 컨트랙트 메시지) "{0}" | (unverified contract message) "{0}" |
| REVERT_CUSTOM_ERROR | 사용자 정의 오류 0x{0} ({1}바이트) | Custom error 0x{0} ({1} bytes) |
| PANIC_GENERIC | 일반 | generic |
| PANIC_ASSERT | assert 실패 | assert failed |
| PANIC_OVERFLOW | 산술 오버플로 | arithmetic overflow |
| PANIC_DIVISION | 0으로 나눔 | division by zero |
| PANIC_ENUM | 잘못된 enum 변환 | invalid enum conversion |
| PANIC_STORAGE | 저장소 바이트 배열 인코딩 오류 | storage byte array encoding error |
| PANIC_POP | 빈 배열 pop | pop on an empty array |
| PANIC_INDEX | 배열 범위 초과 | array index out of bounds |
| PANIC_MEMORY | 메모리 과다 할당 | too much memory allocated |
| PANIC_UNINITIALIZED | 초기화되지 않은 함수 호출 | call to an uninitialized function |
| SIM_RPC_UNSUPPORTED | RPC가 eth_simulateV1을 지원하지 않습니다(체인 설정에서 시뮬레이션을 "미지원"으로 바꿀 수 있습니다) | The RPC does not support eth_simulateV1 (you can set simulation to "unsupported" in the chain settings) |
| SIM_NONCE_USED | nonce가 이미 사용되었습니다. 다른 곳에서 이 계정으로 거래가 전송되었을 수 있습니다 | The nonce is already used. A transaction may have been sent from this account elsewhere |
| SIM_PREVIOUS_PENDING | 앞선 거래가 아직 처리되지 않았습니다 | An earlier transaction has not been processed yet |
| SIM_FEE_TOO_LOW | 최대 수수료가 현재 기본 수수료보다 낮습니다 | The max fee is lower than the current base fee |
| SIM_GAS_TOO_LOW | 가스 한도가 최소 필요량보다 작습니다 | The gas limit is below the minimum required |
| SIM_INSUFFICIENT_FUNDS | 잔액이 보낼 금액과 최대 수수료의 합보다 적습니다 | The balance is less than the amount plus the max fee |
| SIM_GAS_ABOVE_BLOCK | 가스 한도가 블록 가스 한도를 넘습니다 | The gas limit exceeds the block gas limit |
| SIM_NODE_ERROR | 시뮬레이션 노드 오류(코드 {0}) | Simulation node error (code {0}) |
| SIM_TIMEOUT | 시뮬레이션 응답이 없습니다(10초) | No simulation response (10 s) |
| SIM_RATE_LIMITED | RPC 요청 한도를 넘었습니다 | The RPC request limit was exceeded |
| SIM_TRANSPORT | 시뮬레이션 RPC에 연결할 수 없습니다 | Cannot connect to the simulation RPC |
| SIM_TOO_LARGE | 시뮬레이션 응답이 너무 큽니다 | The simulation response is too large |
| SIM_MALFORMED | 시뮬레이션 응답 형식이 올바르지 않습니다 | The simulation response is malformed |
| SIM_REASON | 이유: {0} | Reason: {0} |
| SIM_EXECUTION_ERROR | 이유: 실행 오류(가스 부족 등, 코드 {0}) | Reason: execution error (out of gas or similar, code {0}) |
| SIM_GAS_USED_ABOVE_LIMIT | 사용 가스가 가스 한도를 넘습니다 | The gas used exceeds the gas limit |
| SIM_NATIVE_UNCONFIRMED | {0} 이동이 확인되지 않습니다 | The {0} transfer is not confirmed |
| SIM_CLOCK_SKEW | 기준 블록 시각이 현재와 {0}초 다릅니다 | The block time differs from now by {0} s |
| SIM_SUM_OVERFLOW | 금액 합산이 범위를 넘었습니다 | An amount sum is out of range |
| SIM_ROWS_OMITTED | 표시 한도를 넘어 {0}행을 생략했습니다 | {0} row(s) omitted over the display limit |
| CAP_PRIORITY | 우선 수수료 {0} > 상한 {1} | Priority fee {0} > cap {1} |
| CAP_MAX_FEE | 최대 가스 가격 {0} > 상한 {1} | Max gas price {0} > cap {1} |
| CAP_TOTAL | 최대 수수료 {0} > 상한 {1} | Max fee {0} > cap {1} |
| CAP_OVERFLOW | 수수료 계산이 범위를 넘었습니다 | The fee calculation is out of range |
| SMALL_BLOCK | HyperEVM 작은 블록 한도({0})를 넘는 거래입니다 — 계정에 큰 블록 사용이 켜져 있지 않으면 포함되지 않을 수 있습니다 | The transaction exceeds the HyperEVM small-block limit ({0}) — it may not be included unless big blocks are enabled for the account |
| CHAIN_ETHEREUM | Ethereum 메인넷 | Ethereum Mainnet |
| CHAIN_SEPOLIA | Sepolia 테스트넷 | Sepolia Testnet |
| CHAIN_HYPEREVM | HyperEVM 메인넷 | HyperEVM Mainnet |
| SEAPORT_11_LABEL | OpenSea Seaport 1.1(구버전) | OpenSea Seaport 1.1 (legacy) |

<!-- catalogue: yw_core::evm::display::text -->

| 이름 | 한국어 | English |
|---|---|---|
| EMPTY_STRING | (빈 문자열) | (empty string) |
| EMPTY_MESSAGE | (빈 메시지) | (empty message) |
| EMPTY_VALUE | (빈 값) | (empty value) |
| NONE_PAREN | (없음) | (none) |
| NONE | 없음 | none |
| YES | 예 | yes |
| NO | 아니오 | no |
| UNKNOWN | 알 수 없음 | unknown |
| UNKNOWN_WITH | 알 수 없음 ({0}) | unknown ({0}) |
| NOT_COMPUTABLE | 계산 불가 | cannot be computed |
| NOTE_CONTRACT | 컨트랙트 | contract |
| NOTE_EOA | 일반 계정(EOA) | regular account (EOA) |
| NOTE_DELEGATED | 위임된 계정(EIP-7702) →  | delegated account (EIP-7702) →  |
| NOTE_KIND_UNKNOWN | 계정 종류 확인 불가 | account type unknown |
| NOTE_MINE | 내 계정:  | My account:  |
| NOTE_BOOK | 주소록:  | Address book:  |
| NOTE_VERIFIED |  ✓ 확인됨 |  ✓ verified |
| RAW_UNVERIFIED_DECIMALS | {0} (원시 단위) {1} (미확인 · decimals {2} 적용 시 {3}) | {0} (raw units) {1} (unverified · with decimals {2}: {3}) |
| RAW_UNVERIFIED | {0} (원시 단위) {1} (미확인) | {0} (raw units) {1} (unverified) |
| NO_EXPIRY_RAW | {0} (사실상 만료 없음) | {0} (effectively no expiry) |
| BYTES_HEX | 0x{0} ({1}바이트) | 0x{0} ({1} bytes) |
| BYTES | {0}바이트 | {0} bytes |
| UNLIMITED | 무제한 | unlimited |
| EFFECTIVELY_UNLIMITED | {0} (사실상 무제한) | {0} (effectively unlimited) |
| NO_EXPIRY | 만료 없음 | no expiry |
| AMOUNT_OR_TOKEN_ID | {0} (금액 또는 토큰 ID) | {0} (amount or token ID) |
| BLOCK_ONLY | 사용 블록에서만 유효 | valid only in the block where it is used |
| SEND_NATIVE | {0} 보내기 | Send {0} |
| MULTICALL | 묶음 호출 ({0}개) | Batch call ({0} calls) |
| UNINTERPRETED_LABEL | 해석되지 않은 컨트랙트 호출 ({0}) | Uninterpreted contract call ({0}) |
| UNINTERPRETED | 해석되지 않은 컨트랙트 호출 | Uninterpreted contract call |
| CANCEL_TITLE | 거래 취소 (nonce {0}) | Cancel transaction (nonce {0}) |
| SIWE_TITLE | 로그인 요청 (SIWE) | Sign-in request (SIWE) |
| MESSAGE_TITLE | 메시지 서명 | Message signature |
| TYPED_TITLE | 타입 데이터 서명 | Typed data signature |
| TREE_TRUNCATED | (표시 한도 초과: 항목 {0}개 생략) | (over the display limit: {0} item(s) omitted) |
| OVER_LIMIT_BYTES | (표시 한도 초과: {0}바이트) | (over the display limit: {0} bytes) |
| SUM_UNAVAILABLE | 합산 불가 · {0} | cannot be summed · {0} |
| NFT_UNVERIFIED | NFT #{0} · {1} (미확인) | NFT #{0} · {1} (unverified) |
| MULTI_UNVERIFIED | {0} × {1} · {2} (미확인) | {0} × {1} · {2} (unverified) |
| APPROVAL_ERC20 | {0}\n사용자: {1}\n금액: {2} | {0}\nSpender: {1}\nAmount: {2} |
| APPROVAL_721_REVOKED | {0} #{1}\n개별 승인 해제 | {0} #{1}\nSingle approval revoked |
| APPROVAL_721 | {0} #{1}\n승인 대상: {2} | {0} #{1}\nApproved: {2} |
| APPROVAL_FOR_ALL | {0} 전체\n운영자: {1}\n{2} | {0} (all)\nOperator: {1}\n{2} |
| PERMISSION_GRANTED | 권한 부여 | Permission granted |
| PERMISSION_REVOKED | 권한 해제 | Permission revoked |
| APPROVAL_PERMIT2 | {0} (Permit2)\n사용자: {1}\n금액: {2}\n만료: {3} | {0} (Permit2)\nSpender: {1}\nAmount: {2}\nExpires: {3} |
| APPROVAL_PERMIT2_LOCKDOWN | {0} (Permit2) 승인 해제\n사용자: {1} | {0} (Permit2) approval revoked\nSpender: {1} |
| SIM_BASIS | 블록 {0} · {1} | Block {0} · {1} |
| SIM_NONE_UNSUPPORTED | 시뮬레이션 없음: 미지원 체인 | No simulation: unsupported chain |
| SIM_NONE_SKIPPED | 시뮬레이션 없음: 차단 조건으로 실행하지 않음 | No simulation: not run because the request is blocked |
| SIM_NONE_UNKNOWN_CAUSE | 알 수 없는 원인 | unknown cause |
| SIM_NONE | 시뮬레이션 없음: {0} | No simulation: {0} |
| OTHER_EVENTS | 기타 이벤트 {0}개 | {0} other event(s) |
| FEE_WITH_L1_MAX | {0} (L1 데이터 수수료 최대 {1} 포함) | {0} (including up to {1} L1 data fee) |
| FEE_WITH_L1_ESTIMATE | {0} (L1 데이터 수수료 약 {1} 포함) | {0} (including about {1} L1 data fee) |
| ACCESS_LIST | 주소 {0}개 · 슬롯 {1}개 | {0} address(es) · {1} slot(s) |
| ACCESS_ITEM | \n{0} · 슬롯 {1}개 | \n{0} · {1} slot(s) |
| CALLDATA_NONE | 없음 (0바이트) | none (0 bytes) |
| CALLDATA | {0}바이트 · selector 0x{1}\n0x{2} | {0} bytes · selector 0x{1}\n0x{2} |
| REPLACES | 0x{0}\n기존 최대 수수료 {1} | 0x{0}\nPrevious max fee {1} |
| HASH32 | 정확히 32바이트입니다 — 해시에 서명하는 것일 수 있습니다 | Exactly 32 bytes — you may be signing a hash |
| CONTROL_CHARS | TAB·줄바꿈 외의 제어 문자가 있습니다 | Contains control characters other than TAB and line breaks |
| SIWE_DOMAIN | 도메인 | Domain |
| SIWE_ADDRESS | 주소 | Address |
| SIWE_STATEMENT | 설명 | Statement |
| SIWE_CHAIN_ID | 체인 ID | Chain ID |
| SIWE_ISSUED_AT | 발급 시각 | Issued at |
| SIWE_EXPIRATION | 만료 시각 | Expiration time |
| SIWE_NOT_BEFORE | 유효 시작 | Not before |
| SIWE_REQUEST_ID | 요청 ID | Request ID |
| SIWE_RESOURCES | 리소스 | Resources |
| STRUCT | (구조) | (struct) |
| EMPTY_DOMAIN | (빈 도메인) | (empty domain) |
| UNKNOWN_SCHEMA | 알 수 없는 형식: {0} | Unknown format: {0} |
| HL_UNINTERPRETED_SUFFIX |  (해석하지 않은 형식 — 원문 필드 표시) |  (uninterpreted format — raw fields shown) |
| ACTION_PERMIT | 토큰 사용 허가 서명 (permit) | Token spending permit signature (permit) |
| ACTION_DAI_PERMIT | DAI 사용 허가 서명 | DAI permit signature |
| ACTION_PERMIT2 | Permit2 승인 서명 | Permit2 approval signature |
| ACTION_PERMIT2_TRANSFER | Permit2 즉시 이체 서명 | Permit2 immediate transfer signature |
| ACTION_PERMIT2_WITNESS | Permit2 즉시 이체 서명(조건 포함) | Permit2 immediate transfer signature (with conditions) |
| ACTION_SEAPORT | NFT 마켓 주문 서명 | NFT marketplace order signature |
| ACTION_HL_TRANSFER | HyperCore 전송 서명 | HyperCore transfer signature |
| ACTION_HL_AGENT | Hyperliquid 거래 권한 위임 서명 | Hyperliquid trading delegation signature |
| ACTION_HL_BUILDER | Hyperliquid 빌더 수수료 승인 서명 | Hyperliquid builder fee approval signature |
| ACTION_HL_MULTISIG | Hyperliquid 멀티시그 계정 전환 서명 | Hyperliquid multisig conversion signature |
| ACTION_HL_UNKNOWN | Hyperliquid 계정 작업 서명 (해석하지 못함) | Hyperliquid account action signature (not interpreted) |
| ACTION_HL_L1 | Hyperliquid 주문·거래 서명 | Hyperliquid order/trade signature |
| HL_AGENT | API 지갑(에이전트) 승인 — 거래 권한 위임 | API wallet (agent) approval — trading delegation |
| HL_BUILDER | 빌더 수수료 승인 | Builder fee approval |
| HL_MULTISIG | 멀티시그 계정으로 전환 — 이후 이 계정의 작업에는 서명자 목록(signers)의 서명이 필요합니다 | Convert to a multisig account — afterwards this account's actions need signatures from the signers list |
| HL_UNKNOWN | 해석하지 못한 Hyperliquid 계정 작업 — 아래 원문 필드를 모두 확인하세요 | Uninterpreted Hyperliquid account action — check every raw field below |
| HL_MAINNET | HyperCore 메인넷 (Mainnet) | HyperCore mainnet (Mainnet) |
| HL_TESTNET | HyperCore 테스트넷 (Testnet) | HyperCore testnet (Testnet) |
| HL_WITHDRAW_DESTINATION | \nArbitrum One의 이 주소로 USDC가 들어갑니다 | \nUSDC arrives at this address on Arbitrum One |
| HL_WITHDRAW_AMOUNT | {0} USDC\nArbitrum 도착 = 금액 − {1} USDC = {2} USDC | {0} USDC\nArrives on Arbitrum = amount − {1} USDC = {2} USDC |
| HL_SPOT_TO_PERP | 현물(spot) → 선물(perp) | spot → perp |
| HL_PERP_TO_SPOT | 선물(perp) → 현물(spot) | perp → spot |
| HL_SIGNERS | {0}명 중 {1}명의 서명이 필요합니다 | {1} of {0} signers must sign |
| HL_SIGNERS_UNREADABLE | {0}\n서명자 목록을 해석할 수 없습니다 | {0}\nThe signers list cannot be interpreted |
| HL_NOT_ADDRESS | {0}\n주소 형식이 아닙니다 | {0}\nNot an address |
| HL_EVM_MOVE | \nHyperEVM 시스템 주소 — 이 토큰을 HyperEVM의 같은 주소(서명 계정)로 옮기는 작업입니다 | \nHyperEVM system address — this moves the token to the same address (the signing account) on HyperEVM |
| HL_SYSTEM_NOT_SPOT | \n이 토큰의 HyperEVM 시스템 주소이지만 서명 계정 자신의 현물(spot)→현물 이동이 아닙니다 — HyperEVM 이동으로 확인할 수 없습니다 | \nThis token's HyperEVM system address, but not a spot-to-spot move from the signing account itself — it cannot be confirmed as a HyperEVM move |
| HL_SYSTEM_OTHER_TOKEN | \nHyperEVM 시스템 주소이지만 이 토큰에 연결된 주소가 아닙니다 | \nA HyperEVM system address, but not the one linked to this token |
| HL_SYSTEM_UNCONFIRMED | \nHyperEVM 시스템 주소이지만 토큰을 spotMeta로 확인하지 못해 이 토큰의 주소인지 알 수 없습니다 | \nA HyperEVM system address, but the token could not be checked with spotMeta, so it is unknown whether it is this token's address |
| HL_SYSTEM | \nHyperEVM 시스템 주소입니다 — 이 작업으로 보내면 자산을 잃을 수 있습니다 | \nA HyperEVM system address — sending with this action may lose the assets |
| HL_SELF | \n서명 계정과 같은 주소입니다 | \nSame address as the signing account |
| HL_NO_BOOK | \n내 계정·주소록 확인 불가 | \nYour accounts and address book could not be checked |
| HL_L1_MAINNET | HyperCore 메인넷 (source a) | HyperCore mainnet (source a) |
| HL_L1_TESTNET | HyperCore 테스트넷 (source b) | HyperCore testnet (source b) |
| HL_L1_UNKNOWN_SOURCE | 알 수 없음 (source {0}) | unknown (source {0}) |
| HL_L1_HASH | 0x{0}\n주문·취소 등 거래 작업의 msgpack 해시입니다 — 내용은 해석할 수 없습니다 | 0x{0}\nThe msgpack hash of a trading action such as an order or cancel — its content cannot be interpreted |
| SEAPORT_RANGE | 시작 {0} → 종료 {1} (시간에 따라 변함) | start {0} → end {1} (changes over time) |
| SEAPORT_ANY_TOKEN | 컬렉션의 아무 토큰 × {0} · {1} | any token of the collection × {0} · {1} |
| SEAPORT_CRITERIA | 기준 루트 0x{0} × {1} · {2} | criteria root 0x{0} × {1} · {2} |
| SEAPORT_UNKNOWN_ITEM | 알 수 없는 itemType {0} | unknown itemType {0} |
| SEAPORT_RECIPIENT | \n받는 주소:  | \nRecipient:  |
| DAI_ALLOWED | 무제한 허용 | unlimited allowance |
| DAI_REVOKED | 허용 해제 | allowance revoked |
| PERMIT2_TRANSFER_NOTE | 이 서명으로 spender가 토큰을 바로 가져갈 수 있습니다 | With this signature the spender can take the tokens at once |
| TD_ACTION | 작업 | Action |
| TD_SIGNERS | 서명자 (signers) | Signers (signers) |
| TD_TOKEN | 토큰 | Token |
| TD_OWNER | 소유자 | Owner |
| TD_SPENDER | 사용자 | Spender |
| TD_AMOUNT | 금액 | Amount |
| TD_DEADLINE | 기한 | Deadline |
| TD_ALLOWED | 허용 | Allowed |
| TD_ITEM | 항목 {0}  | Item {0}  |
| TD_ALLOWANCE_EXPIRY | 허용 만료 | Allowance expiry |
| TD_SIG_DEADLINE | 서명 기한 | Signature deadline |
| TD_NOTE | 안내 | Note |
| TD_WITNESS | witness 타입 | witness type |
| TD_NETWORK | 네트워크 | Network |
| TD_ACTION_HASH | 작업 해시 (connectionId) | Action hash (connectionId) |
| TD_START | 시작 시각 | Start time |
| TD_END | 종료 시각 | End time |
| TD_YOU_GIVE | 내가 주는 것 | You give |
| TD_YOU_RECEIVE | 내가 받는 것 | You receive |
| TD_OTHERS_RECEIVE | 다른 사람이 받는 것 | Others receive |

<!-- catalogue: yw_core::evm::display::time -->

| 이름 | 한국어 | English |
|---|---|---|
| IN_DAYS | 약 {0}일 후 | in about {0} days |
| IN_HOURS | 약 {0}시간 후 | in about {0} hours |
| IN_MINUTES | 약 {0}분 후 | in about {0} minutes |
| DAYS_AGO | 약 {0}일 전 | about {0} days ago |
| HOURS_AGO | 약 {0}시간 전 | about {0} hours ago |
| MINUTES_AGO | 약 {0}분 전 | about {0} minutes ago |

<!-- catalogue: yw_core::journal::evm::text -->

| 이름 | 한국어 | English |
|---|---|---|
| IN_FLIGHT | 진행 중인 거래가 있습니다 (nonce {0}) | A transaction is in progress (nonce {0}) |
| EXTERNAL_PENDING | 이 계정에서 다른 곳으로 보낸 대기 중 거래가 있습니다 | A pending transaction was sent from this account elsewhere |
| JOURNAL_FULL | 거래 저널 공간이 부족합니다 | The transaction journal is full |
| CANCEL_ROW | 거래 취소 | Transaction cancelled |

<!-- catalogue: yw_core::approval::message_text -->

| 이름 | 한국어 | English |
|---|---|---|
| EMPTY_MESSAGE | (빈 메시지) | (empty message) |
| EMPTY_VALUE | (빈 값) | (empty value) |
| HASH32 | 정확히 32바이트입니다 — 해시에 서명하는 것일 수 있습니다 | Exactly 32 bytes — this may be signing a hash |
| CONTROL | TAB·줄바꿈 외의 제어 문자가 있습니다 | Contains control characters other than TAB·line break |
| BYTES | {0}바이트 | {0} bytes |

<!-- catalogue: yw_core::sol::text -->

| 이름 | 한국어 | English |
|---|---|---|
| CLUSTER_DEVNET | Solana devnet (테스트) | Solana devnet (test) |
| NETWORK_GENESIS | {0}\ngenesis 확인됨: {1} | {0}\ngenesis verified: {1} |
| RPC_ANOMALY | RPC 응답 값이 비정상입니다 | The RPC returned an implausible value |
| SIM_FAILED | 실패: {0} | Failed: {0} |
| ERR_FEE_BALANCE | 수수료를 낼 잔액이 부족합니다 | Not enough balance to pay the fee |
| ERR_RENT | rent 기준을 채우지 못했습니다 | The rent minimum was not met |
| ERR_ACCOUNT_NOT_FOUND | 계정을 찾을 수 없습니다 | Account not found |
| ERR_SYSTEM | System 명령이 실패했습니다 | A System instruction failed |
| ERR_TOKEN | 토큰 명령이 실패했습니다 | A token instruction failed |
| ERR_CU | 계산 한도(CU)를 넘었습니다 | The compute limit (CU) was exceeded |
| ERR_BLOCKHASH | 블록해시를 찾을 수 없습니다(일시적) | Blockhash not found (temporary) |
| ERR_ALREADY | 이미 처리된 거래입니다 | The transaction was already processed |
| ERR_PROGRAM | 프로그램 명령이 실패했습니다 | A program instruction failed |
| ERR_UNKNOWN | 알 수 없는 거래 오류 | Unknown transaction error |
| FEE_OVERFLOW | 수수료 계산이 범위를 넘습니다 | The fee calculation is out of range |
| FEE_QUERY_FAILED | RPC에서 수수료를 확인하지 못했습니다 | Could not check the fee with the RPC |
| FEE_FORMULA_CHANGED | RPC 수수료가 지갑 계산과 다릅니다 — 수수료 공식이 바뀌었을 수 있습니다 | The RPC fee differs from the wallet's calculation — the fee formula may have changed |
| FEE_ABOVE_CAP | 수수료가 설정한 상한을 넘습니다 | The fee is above the cap you set |
| RENT_NEW_ACCOUNT | 새 계정에는 최소 {0} SOL을 보내야 합니다 | A new account needs at least {0} SOL |
| RENT_RECIPIENT_BELOW | 받는 계정의 잔액이 rent 기준({0} SOL)보다 적어 최소 {1} SOL을 보내야 합니다 | The receiving account's balance is below the rent minimum ({0} SOL), so at least {1} SOL must be sent |
| RENT_SENDER_DUST | 보낸 뒤 남는 잔액은 0이거나 {0} SOL 이상이어야 합니다 | The balance left after sending must be 0 or at least {0} SOL |
| RENT_INSUFFICIENT | 잔액이 부족합니다(수수료 포함) | Insufficient balance (fee included) |
| RENT_ZERO | 0은 보낼 수 없습니다 | Cannot send 0 |
| RENT_NO_TOKEN_ACCOUNT | 보내는 계정에 이 토큰의 토큰 계정(ATA)이 없습니다(잔액 0) | The sending account has no token account (ATA) for this token (balance 0) |
| RENT_INSUFFICIENT_TOKENS | 토큰 잔액이 부족합니다 | Insufficient token balance |
| RENT_SOL_RESERVE | SOL이 부족합니다: 수수료와 받는 토큰 계정 생성비(필요할 때)를 내고도 {0} SOL이 남아야 합니다(필요 {1} SOL) | Not enough SOL: {0} SOL must remain after the fee and the receiving token account's creation cost (when needed) (needed {1} SOL) |
| BLOCK_CLUSTER_MISMATCH | RPC가 다른 Solana 클러스터를 가리킵니다(제네시스 불일치) | The RPC points to a different Solana cluster (genesis mismatch) |
| BLOCK_TOKEN_ACCOUNT | 지갑 주소가 아니라 토큰 계정/mint 주소입니다 | This is a token account/mint address, not a wallet address |
| BLOCK_PROGRAM | 받는 주소가 프로그램입니다 | The recipient is a program |
| BLOCK_PENDING | 이 계정의 이전 전송을 확인 중입니다 | A previous transfer from this account is still being confirmed |
| BLOCK_JOURNAL_FULL | 거래 저널 공간이 부족합니다 | The transaction journal is full |
| BLOCK_FROZEN | 보내는 토큰 계정이 동결되어 있습니다(토큰 발행자가 막음) | The sending token account is frozen (blocked by the token issuer) |
| BLOCK_RECIPIENT_ATA | 받는 사람의 토큰 계정(ATA)이 동결되었거나 이 토큰의 계정이 아닙니다 | The recipient's token account (ATA) is frozen or is not an account of this token |
| NO_NAME | (이름 없음) | (no name) |
| TITLE_SOL_TRANSFER | SOL 전송 | SOL transfer |
| TITLE_TOKEN_TRANSFER | 토큰 전송 | Token transfer |
| LOOKALIKE_HEAD | 앞 3자 또는 뒤 3자가 같은 다른 주소입니다 — 주소 오염 공격일 수 있습니다 | A different address with the same first 3 or last 3 characters — this may be an address poisoning attack |
| LOOKALIKE_BOOK | 주소록 '{0}'과 비슷함: {1} | Similar to address book '{0}': {1} |
| LOOKALIKE_OWN | 내 계정 '{0}'과 비슷함: {1} | Similar to my account '{0}': {1} |
| LOOKALIKE_SENT | 보낸 내역의 주소와 비슷함: {0} | Similar to an address in your send history: {0} |
| SIM_CU_OVER | CU 초과: 사용 {0} > 한도 {1} | CU over the limit: used {0} > limit {1} |
| SIM_OK | 성공(CU {0}) | Success (CU {0}) |
| SIM_NO_RESULT | 결과 없음(참고 정보이며 승인을 막지 않습니다) | No result (reference only; it does not block approval) |
| L01_CAUSE | 보낼 수 없습니다: {0} | Cannot send: {0} |
| L02_TEXT | 일반 지갑이 아님: 프로그램 소유 주소(PDA)나 토큰 계정일 수 있음 | Not a regular wallet: may be a program-owned address (PDA) or a token account |
| L04_TEXT | 받는 주소가 프로그램 소유 계정입니다 — 일반 지갑이 아닐 수 있습니다 | The recipient is a program-owned account — it may not be a regular wallet |
| L05_TEXT | 시뮬레이션에서 실패했거나 계산 한도를 넘었습니다 — 수수료만 잃을 수 있습니다\n{0} | It failed in simulation or exceeded the compute limit — you may lose the fee and get nothing\n{0} |
| L06_TEXT | 처음 보내는 주소입니다. 주소 전체를 확인하고, 큰 금액은 소액 시험 송금 뒤 보내세요. | First send to this address. Check the whole address, and send a small test amount before a large one. |
| L07_TEXT | 비표준 경로 계정입니다 ({0}) | Non-standard path account ({0}) |
| L08_SOL | 보내기 최대: 보낸 뒤 이 계정의 SOL 잔액은 0이 됩니다 | Send max: this account's SOL balance will be 0 after sending |
| L08_SPL | 보내기 최대: 보낸 뒤 이 계정의 {0} 잔액은 0이 됩니다(SOL은 남습니다) | Send max: this account's {0} balance will be 0 after sending (SOL remains) |
| FEE_RPC_LOWER | {0} lamports (지갑 최대보다 낮은 RPC 추정) | {0} lamports (RPC estimate below the wallet maximum) |
| NOT_CHECKED | 확인하지 못함 | could not check |
| FEE_TEXT | 기본 수수료 {0} lamports × 서명 1\n우선 수수료 {1} lamports (CU 한도 {2} × 가격 {3} micro-lamports/CU, 올림)\n최대 합계 {4} SOL ({5} lamports)\n사용자 상한 {6} lamports\nRPC getFeeForMessage: {7} | Base fee {0} lamports × 1 signature\nPriority fee {1} lamports (CU limit {2} × price {3} micro-lamports/CU, rounded up)\nMax total {4} SOL ({5} lamports)\nYour cap {6} lamports\nRPC getFeeForMessage: {7} |
| RECIPIENT_BOOK_VERIFIED | 주소록: {0} ✓ 확인됨 | Address book: {0} ✓ verified |
| RECIPIENT_BOOK | 주소록: {0} | Address book: {0} |
| RECIPIENT_OWN | 내 계정 #{0}: {1} | My account #{0}: {1} |
| RECIPIENT_OWN_IMPORTED | 내 계정(가져온 개인키): {0} | My account (imported private key): {0} |
| RECIPIENT_OWN_HARDWARE | 내 계정(YubiKey): {0} | My account (YubiKey): {0} |
| RECIPIENT_OWN_MNEMONIC | 내 계정(추가한 복구 단어): {0} | My account (added recovery phrase): {0} |
| RECIPIENT_SENT | 보낸 적 있는 주소 | Address you have sent to before |
| RECIPIENT_NEW | 새 계정(아직 없음) | New account (does not exist yet) |
| RECIPIENT_NO_SOL_ACCOUNT | SOL 계정 없음(새 지갑일 수 있음 — 토큰을 받는 데는 문제없음) | No SOL account (may be a new wallet — receiving tokens is not a problem) |
| RECIPIENT_SPL_OWNER | 받는 지갑(소유자) 주소입니다. 토큰은 아래 '자산·금액'의 받는 토큰 계정(ATA)으로 갑니다. | This is the receiving wallet (owner) address. The tokens go to the receiving token account (ATA) under 'Asset · amount' below. |
| SPL_AMOUNT | {0}\n{1} (원시 단위, decimals {2})\nmint (허용 목록 고정):\n{3}\n토큰 프로그램: SPL Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)\n보내는 토큰 계정(내 ATA):\n{4}\n받는 토큰 계정(받는 지갑의 ATA, 지갑이 계산):\n{5} | {0}\n{1} (raw units, decimals {2})\nmint (pinned in the allowlist):\n{3}\nToken program: SPL Token (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)\nSending token account (my ATA):\n{4}\nReceiving token account (the recipient wallet's ATA, computed by the wallet):\n{5} |
| ATA_EXISTS | 받는 토큰 계정이 이미 있습니다(RPC 참고) — 생성 비용 없음.\n거래에는 '없으면 만들기'(CreateIdempotent) 명령이 항상 들어갑니다. 실행 때 없으면 최대 {0} SOL({1} lamports, rent)을 보내는 계정이 냅니다. | The receiving token account already exists (RPC, reference) — no creation cost.\nThe transaction always includes a 'create if missing' (CreateIdempotent) instruction. If the account is missing at execution, the sending account pays up to {0} SOL ({1} lamports, rent). |
| ATA_MISSING | 받는 토큰 계정이 없습니다(RPC 참고) — 이 거래가 만듭니다.\n생성 비용(rent) 최대 {0} SOL({1} lamports)을 보내는 계정이 냅니다(받는 사람 소유 계정에 들어감). | The receiving token account does not exist (RPC, reference) — this transaction creates it.\nThe sending account pays its creation cost (rent) of up to {0} SOL ({1} lamports), which goes into an account the recipient owns. |
| INSUFFICIENT | 부족 | insufficient |
| BALANCE_AFTER | {0} SOL → {1} (RPC 기준) | {0} SOL → {1} (per RPC) |
| TOKEN_BALANCE_AFTER | {0} → {1} (RPC 기준) | {0} → {1} (per RPC) |
| NO_TOKEN_ACCOUNT_BALANCE | {0} 토큰 계정 없음 (RPC 기준) | No {0} token account (per RPC) |
| SPL_TOTAL | {0}\nSOL 최대 {1} SOL ({2} lamports = 수수료 최대 {3} + 토큰 계정 생성 rent {4}) | {0}\nSOL up to {1} SOL ({2} lamports = max fee {3} + token account creation rent {4}) |
| VALIDITY | 승인 창은 표시 후 120초에 만료(남은 시간은 상태 줄). 승인 즉시 서명하며 거래는 약 30초 뒤 만료 | The approval window expires 120 s after it is shown (time left in the status bar). It signs as soon as you approve, and the transaction expires after about 30 s |
| W07_VERSION | Version은 1이어야 합니다 | Version must be 1 |
| W07_ISSUED_AT | Issued At 시각 형식이 틀립니다 | Issued At has an invalid time format |
| W07_EXPIRATION | Expiration Time 시각 형식이 틀립니다 | Expiration Time has an invalid time format |
| W07_NOT_BEFORE | Not Before 시각 형식이 틀립니다 | Not Before has an invalid time format |
| SIWS_DOMAIN | 도메인 | Domain |
| SIWS_ADDRESS | 주소 | Address |
| SIWS_STATEMENT | 설명 | Statement |
| SIWS_VERSION | 버전 | Version |
| SIWS_ISSUED_AT | 발급 시각 | Issued at |
| SIWS_EXPIRATION | 만료 시각 | Expires at |
| SIWS_NOT_BEFORE | 유효 시작 | Not before |
| SIWS_REQUEST_ID | 요청 ID | Request ID |
| SIWS_RESOURCES | 리소스 | Resources |
| NONE | (없음) | (none) |
| MESSAGE_TITLE_SHORT | 메시지 서명 | Sign message |
| M01_VERSIONED | 버전이 붙은 Solana 거래 메시지처럼 시작합니다 | It starts like a versioned Solana transaction message |
| M01_TOO_LONG | 64KiB를 넘는 메시지입니다 | The message is larger than 64 KiB |
| M02_NOT_SIGNER | 서명자 목록에 이 계정이 없습니다 | This account is not in the signer list |
| OFFCHAIN_FORMAT | Solana 오프체인 메시지 v0 (형식 {0}) — 아래는 머리글을 뺀 본문 | Solana off-chain message v0 (format {0}) — the body below is without the header |
| ACTION_SIWS | 로그인 요청 (SIWS) | Sign-in request (SIWS) |
| ACTION_MESSAGE | 메시지 서명 (소유 증명) | Sign message (proof of ownership) |
| MESSAGE_ERR_INTERNAL | 내부 검증에 실패해 서명하지 않았습니다. | Internal verification failed, so nothing was signed. |
| MESSAGE_ERR_SIGNING | 서명하지 못했습니다(내부 오류) | Could not sign (internal error) |

<!-- catalogue: yw_core::sol::dapp::text -->

| 이름 | 한국어 | English |
|---|---|---|
| MALFORMED | 형식이 맞지 않음 | malformed |
| ATA_MISMATCH | ATA 주소가 유도값과 다릅니다 | The ATA address differs from its derivation |
| UNRESOLVED | 조회 테이블을 해석하지 못함 | lookup table not resolved |
| ALT_MISSING | 조회 테이블이 없습니다: {0} | The lookup table does not exist: {0} |
| ALT_NOT_TABLE | 조회 테이블이 아닙니다: {0} | Not a lookup table: {0} |
| ALT_INDEX | 조회 테이블 인덱스가 범위 밖입니다 | A lookup table index is out of range |
| ALT_DUPLICATE | 조회한 주소가 다른 계정 키와 겹칩니다 | A loaded address duplicates another account key |
| AT_TX_IX | 거래 {0} 명령 {1} | Transaction {0} instruction {1} |
| AT_TX | 거래 {0} | Transaction {0} |
| AT_IX | 명령 {0} | Instruction {0} |
| TAG_SIGNER | [서명] | [signer] |
| TAG_WRITABLE | [쓰기] | [writable] |
| TAG_TABLE | [테이블 {0}] | [table {0}] |
| TAG_PROGRAM | [{0} 프로그램] | [{0} program] |
| TAG_MY_WALLET | [내 지갑] | [my wallet] |
| TAG_MY_TOKEN_SYMBOL | [내 토큰 계정 · {0}] | [my token account · {0}] |
| TAG_MY_TOKEN | [내 토큰 계정] | [my token account] |
| TAG_BOOK_VERIFIED | [주소록: {0} ✓] | [address book: {0} ✓] |
| TAG_BOOK | [주소록: {0}] | [address book: {0}] |
| TAG_MY_ACCOUNT | [내 계정: {0}] | [my account: {0}] |
| TAG_SENT | [보낸 적 있는 주소] | [sent to before] |
| TAG_LOOKALIKE | [비슷한 주소 주의] | [similar address: caution] |
| AMOUNT_LISTED | {0} {1} ({2} 원시 단위) | {0} {1} ({2} raw units) |
| AMOUNT_DECIMALS | {0} 토큰 ({1} 원시 단위, decimals {2}) | {0} tokens ({1} raw units, decimals {2}) |
| AMOUNT_RPC_DECIMALS | {0} 토큰 ({1} 원시 단위, decimals {2} RPC 참고) | {0} tokens ({1} raw units, decimals {2} from RPC, reference) |
| AMOUNT_RAW | {0} (원시 단위) | {0} (raw units) |
| RAW_UNITS | {0} 원시 단위 | {0} raw units |
| OPTION_NONE | {0} 없음 | {0}: none |
| SIZE_BYTES | 크기 {0}바이트 | Size {0} bytes |
| L_FUNDING | 자금 계정 | Funding account |
| L_NEW_ACCOUNT | 새 계정 | New account |
| L_OWNER_PROGRAM | 소유 프로그램 | Owner program |
| L_ACCOUNT | 계정 | Account |
| L_NEW_OWNER_PROGRAM | 새 소유 프로그램 | New owner program |
| L_FROM | 보내는 계정 | Sending account |
| L_TO | 받는 계정 | Receiving account |
| L_BASE | 기준 계정 | Base account |
| L_NONCE | nonce 계정 | Nonce account |
| L_NONCE_AUTHORITY | nonce 권한 | Nonce authority |
| L_CURRENT_AUTHORITY | 현재 권한 | Current authority |
| L_NEW_AUTHORITY | 새 권한 | New authority |
| L_MINT_AUTHORITY | 발행 권한 | Mint authority |
| L_FREEZE_AUTHORITY | 동결 권한 | Freeze authority |
| L_TOKEN_ACCOUNT | 토큰 계정 | Token account |
| L_OWNER | 소유자 | Owner |
| L_MULTISIG | 멀티시그 계정 | Multisig account |
| L_FROM_TOKEN | 보내는 토큰 계정 | Sending token account |
| L_TO_TOKEN | 받는 토큰 계정 | Receiving token account |
| L_OWNER_DELEGATE | 소유자·위임자 | Owner · delegate |
| L_DELEGATE | 위임받는 주소 | Delegate |
| L_MINT_OR_TOKEN | mint·토큰 계정 | Mint · token account |
| L_CLOSING | 닫는 토큰 계정 | Token account being closed |
| L_REST_TO | 남은 SOL을 받는 주소 | Receives the remaining SOL |
| L_OWNER_CLOSE | 소유자·닫기 권한 | Owner · close authority |
| L_WSOL | wrapped SOL 토큰 계정 | Wrapped SOL token account |
| L_RENT_PAYER | rent를 내는 계정 | Account paying the rent |
| L_ATA_DERIVED | 토큰 계정(ATA, 유도값 확인됨) | Token account (ATA, derivation verified) |
| L_OWNER_WALLET | 소유 지갑 | Owner wallet |
| L_TOKEN_PROGRAM | 토큰 프로그램 | Token program |
| L_NESTED | 중첩된 토큰 계정 | Nested token account |
| L_NESTED_MINT | 중첩 mint | Nested mint |
| L_OWNER_TOKEN | 소유 토큰 계정 | Owner token account |
| L_OWNER_MINT | 소유 mint | Owner mint |
| L_WALLET | 지갑 | Wallet |
| L_PROGRAM | 프로그램 | Program |
| L_ACCOUNT_N | 계정 {0} | Account {0} |
| L_BEFORE | 이전 | Before |
| L_AFTER | 이후 | After |
| L_CLOSED | 닫힘 | Closed |
| L_CREATED | 새로 만들어짐 | Newly created |
| L_TOKEN_MINT | 토큰 계정 · mint | Token account · mint |
| T_CREATE_ACCOUNT | 계정 만들기 (CreateAccount) | Create account (CreateAccount) |
| T_ASSIGN | 소유 프로그램 바꾸기 (Assign) | Change owner program (Assign) |
| T_SOL_TRANSFER | SOL 보내기 (Transfer) | Send SOL (Transfer) |
| T_CREATE_WITH_SEED | seed로 계정 만들기 (CreateAccountWithSeed) | Create account with seed (CreateAccountWithSeed) |
| TRAILING_BYTES | 뒤에 붙은 바이트(런타임이 무시): {0} | Trailing bytes (ignored by the runtime): {0} |
| T_ADVANCE_NONCE | durable nonce 진행 (AdvanceNonceAccount) | Advance durable nonce (AdvanceNonceAccount) |
| T_WITHDRAW_NONCE | nonce 계정에서 꺼내기 (WithdrawNonceAccount) | Withdraw from nonce account (WithdrawNonceAccount) |
| T_INIT_NONCE | nonce 계정 초기화 (InitializeNonceAccount) | Initialize nonce account (InitializeNonceAccount) |
| T_AUTHORIZE_NONCE | nonce 권한 바꾸기 (AuthorizeNonceAccount) | Change nonce authority (AuthorizeNonceAccount) |
| T_ALLOCATE | 공간 할당 (Allocate) | Allocate space (Allocate) |
| T_ALLOCATE_WITH_SEED | seed 계정 공간 할당 (AllocateWithSeed) | Allocate space for seed account (AllocateWithSeed) |
| T_ASSIGN_WITH_SEED | seed 계정 소유 프로그램 바꾸기 (AssignWithSeed) | Change seed account owner program (AssignWithSeed) |
| T_TRANSFER_WITH_SEED | seed 계정에서 SOL 보내기 (TransferWithSeed) | Send SOL from seed account (TransferWithSeed) |
| T_UPGRADE_NONCE | nonce 계정 갱신 (UpgradeNonceAccount) | Upgrade nonce account (UpgradeNonceAccount) |
| AUTH_MINT_TOKENS | 발행 권한(MintTokens) | Mint authority (MintTokens) |
| AUTH_FREEZE | 동결 권한(FreezeAccount) | Freeze authority (FreezeAccount) |
| AUTH_ACCOUNT_OWNER | 토큰 계정 소유자(AccountOwner) | Token account owner (AccountOwner) |
| AUTH_CLOSE | 닫기 권한(CloseAccount) | Close authority (CloseAccount) |
| T_INIT_MINT | mint 초기화 (InitializeMint) | Initialize mint (InitializeMint) |
| T_INIT_ACCOUNT | 토큰 계정 초기화 (InitializeAccount) | Initialize token account (InitializeAccount) |
| REQUIRED_SIGNATURES | 필요 서명 {0}개 | Required signatures: {0} |
| T_INIT_MULTISIG | 멀티시그 초기화 (InitializeMultisig) | Initialize multisig (InitializeMultisig) |
| T_TOKEN_TRANSFER | 토큰 보내기 (Transfer) | Send tokens (Transfer) |
| DELEGATE_LIMIT | 위임 한도 {0} | Delegation limit {0} |
| T_APPROVE | 토큰 사용 권한 위임 (Approve) | Delegate token spending (Approve) |
| T_REVOKE | 위임 해제 (Revoke) | Revoke delegation (Revoke) |
| CHANGED_AUTHORITY | 바뀌는 권한: {0} | Authority changed: {0} |
| T_SET_AUTHORITY | 권한 변경 (SetAuthority) | Change authority (SetAuthority) |
| T_MINT_TO | 토큰 발행 (MintTo) | Mint tokens (MintTo) |
| T_BURN | 토큰 소각 (Burn) | Burn tokens (Burn) |
| T_CLOSE | 토큰 계정 닫기 (CloseAccount) | Close token account (CloseAccount) |
| T_FREEZE | 토큰 계정 동결 (FreezeAccount) | Freeze token account (FreezeAccount) |
| T_THAW | 토큰 계정 동결 해제 (ThawAccount) | Thaw token account (ThawAccount) |
| T_TRANSFER_CHECKED | 토큰 보내기 (TransferChecked) | Send tokens (TransferChecked) |
| T_APPROVE_CHECKED | 토큰 사용 권한 위임 (ApproveChecked) | Delegate token spending (ApproveChecked) |
| T_MINT_TO_CHECKED | 토큰 발행 (MintToChecked) | Mint tokens (MintToChecked) |
| T_BURN_CHECKED | 토큰 소각 (BurnChecked) | Burn tokens (BurnChecked) |
| T_SYNC_NATIVE | wrapped SOL 잔액 맞추기 (SyncNative) | Sync wrapped SOL balance (SyncNative) |
| EXTENSION_TYPES | 확장 유형: {0} | Extension types: {0} |
| T_GET_SIZE | 계정 크기 조회 (GetAccountDataSize) | Query account size (GetAccountDataSize) |
| T_IMMUTABLE_OWNER | 소유자 고정 (InitializeImmutableOwner) | Lock the owner (InitializeImmutableOwner) |
| T_AMOUNT_TO_UI | 금액 표기 변환 (AmountToUiAmount) | Convert amount notation (AmountToUiAmount) |
| UI_AMOUNT | 금액 표기: {0} | Amount notation: {0} |
| T_UI_TO_AMOUNT | 금액 표기 변환 (UiAmountToAmount) | Convert amount notation (UiAmountToAmount) |
| T_EXTENSION | Token-2022 확장 명령 {0} (해석하지 않음) | Token-2022 extension instruction {0} (uninterpreted) |
| T_ATA_IDEMPOTENT | 토큰 계정 만들기, 있으면 그대로 (CreateIdempotent) | Create token account, keep it if it exists (CreateIdempotent) |
| T_ATA_CREATE | 토큰 계정 만들기 (Create) | Create token account (Create) |
| T_RECOVER_NESTED | 중첩 토큰 계정 회수 (RecoverNested) | Recover nested token account (RecoverNested) |
| CB_HEAP | 힙 크기 요청 (RequestHeapFrame), 바이트 | Request heap size (RequestHeapFrame), bytes |
| CB_CU_LIMIT | CU 한도 (SetComputeUnitLimit) | CU limit (SetComputeUnitLimit) |
| CB_CU_PRICE | CU 가격 (SetComputeUnitPrice), micro-lamports/CU | CU price (SetComputeUnitPrice), micro-lamports/CU |
| CB_DATA_LIMIT | 읽는 계정 데이터 한도 (SetLoadedAccountsDataSizeLimit), 바이트 | Loaded account data limit (SetLoadedAccountsDataSizeLimit), bytes |
| UNKNOWN_PROGRAM | 알 수 없는 프로그램 | Unknown program |
| MEMO_TEXT | 메모: {0} | Memo: {0} |
| MEMO_HEX | 메모(hex):\n{0} | Memo (hex):\n{0} |
| T_MEMO | 메모 | Memo |
| T_PRECOMPILE | 서명 검증 {0}건 (계정 사용 없음) | Signature verification: {0} (no accounts used) |
| T_UNKNOWN_REASON | 해석하지 않음 — {0} | Uninterpreted — {0} |
| T_UNKNOWN | 해석하지 않음 | Uninterpreted |
| ACCOUNT_UNRESOLVED | {0}: 조회 테이블 인덱스 {1} (해석 못 함) | {0}: lookup table index {1} (unresolved) |
| DATA_BYTES | 데이터 {0}바이트 | Data {0} bytes |
| NO_INSTRUCTIONS | 명령 없음 | No instructions |
| SIGNER_FEE_PAYER | 서명자 {0} · 수수료 지불 | Signer {0} · fee payer |
| SIGNER_N | 서명자 {0} | Signer {0} |
| SLOT_WALLET | 지갑이 서명합니다 | The wallet signs |
| SLOT_MISSING_SEND | 서명 없음 — 지갑이 전송할 수 없습니다 | No signature — the wallet cannot send |
| SLOT_MISSING | 서명 없음 (사이트가 나중에 채움) | No signature (the site fills it in later) |
| SLOT_SITE_OK | 사이트가 넣은 서명 (확인됨) | Signature added by the site (verified) |
| SITE_SIGNATURE_BAD | 사이트가 넣은 서명이 맞지 않습니다 | A signature added by the site does not verify |
| DEMOTED | (런타임에서 읽기 전용) | (read-only at runtime) |
| WRITABLE_UNKNOWN | 조회 테이블을 해석하지 못해 테이블에서 오는 쓰기 가능한 주소를 알 수 없습니다 | The lookup tables could not be resolved, so the writable addresses they give are unknown |
| NONE | 없음 | None |
| NO_TABLES_LEGACY | 조회 테이블 없음 (legacy 거래) | No lookup tables (legacy transaction) |
| NO_TABLES | 조회 테이블 없음 | No lookup tables |
| TABLE_N | 테이블 {0} | Table {0} |
| TABLE_DEACTIVATED | 비활성화된 테이블 | Deactivated table |
| KIND_WRITE | 쓰기 | writable |
| KIND_READ | 읽기 | read-only |
| LOOKUP_ENTRY | {0} · 인덱스 {1} | {0} · index {1} |
| UNRESOLVED_ERROR | 해석하지 못함: {0} | Could not resolve: {0} |
| CHANGES_NO_SIM | 시뮬레이션 결과가 없어 변화를 확인할 수 없습니다 | No simulation result, so the changes cannot be checked |
| CHANGES_NONE | 지켜본 계정(내 지갑·내 토큰 계정·새 계정)에 변화 없음 | No change in the watched accounts (my wallet · my token accounts · new accounts) |
| CHANGE_SOL | 내 지갑 SOL {0} SOL ({1} → {2} lamports{3}) | My wallet SOL {0} SOL ({1} → {2} lamports{3}) |
| FEE_INCLUDED | , 수수료 포함 | , fee included |
| TOKEN_FALLBACK | 토큰 | tokens |
| CHANGE_TOKEN_RPC | {0} 토큰 (decimals {1} RPC 참고) | {0} tokens (decimals {1} from RPC, reference) |
| CHANGE_TOKEN | 내 토큰{0} {1} | My token{0} {1} |
| AUTH_CHANGE_OWNER | 권한 변화: 토큰 계정 소유자 | Authority change: token account owner |
| AUTH_CHANGE_DELEGATE | 권한 변화: 토큰 계정 위임자 | Authority change: token account delegate |
| AUTH_CHANGE_CLOSE | 권한 변화: 토큰 계정 닫기 권한 | Authority change: token account close authority |
| AUTH_CHANGE_WALLET | 권한 변화: 내 지갑의 소유 프로그램 | Authority change: my wallet's owner program |
| SIM_OK | 성공 (CU {0}) | Success (CU {0}) |
| SIM_NO_RESULT | 결과 없음 | No result |
| SIM_REPLACED | 블록해시를 바꿔 시뮬레이션함(replaceRecentBlockhash) — 참고용 | Simulated with a replaced blockhash (replaceRecentBlockhash) — reference only |
| FEE_RPC_NONE | RPC가 답하지 않음 (getFeeForMessage) | No answer from the RPC (getFeeForMessage) |
| FEE_REJECTED | 계산값 {0} (ComputeBudget 명령을 런타임이 거부 — 처리되지 않으며 우선 수수료 없이 계산) | Computed {0} (the runtime rejects the ComputeBudget instructions — not processed; computed without a priority fee) |
| FEE_EXACT | 계산값 {0} (거래 바이트로 계산) | Computed {0} (from the transaction bytes) |
| FEE_RANGE | 계산값 {0} (CU 한도가 없어 범위로 계산) | Computed {0} (a range: no CU limit) |
| FEE_PAYER_ME | 수수료 지불: 내 지갑 | Fee payer: my wallet |
| FEE_CAP | 사용자 상한 {0} lamports | Your cap {0} lamports |
| FEE_PAYER_OTHER | 수수료 지불: 다른 계정 | Fee payer: another account |
| X_EXTENSION | Token-2022 확장 명령 {0} | Token-2022 extension instruction {0} |
| X_PROGRAM_NAMED | {0} 프로그램 {1} | {0} program {1} |
| X_PROGRAM | 프로그램 {0} | Program {0} |
| X04_CAUSE | 토큰 사용 권한 위임 | Delegate token spending |
| X07_CAUSE | 남은 SOL을 받는 주소 {0} | Receives the remaining SOL: {0} |
| X10_DEACTIVATED | 비활성화된 테이블 {0} | Deactivated table {0} |
| X01_NEED_ALL | 전송하려면 다른 서명이 모두 있어야 합니다 | Sending needs every other signature |
| X01_NONCE_SEND | durable nonce 거래는 지갑이 전송하지 않습니다 | The wallet does not send durable nonce transactions |
| X01_SCAN | 복구 스캔 계정으로는 사이트 거래에 서명하지 않습니다 | A recovery-scan account does not sign site transactions |
| X13_OTHER_PAYER | 수수료는 다른 계정이 냅니다 | Another account pays the fee |
| X13_SITE_SIGNED | 사이트가 넣은 서명이 있습니다 | The site added signatures |
| X12_UNREAD | mint {0} · 확장을 읽지 못했습니다 | mint {0} · its extensions could not be read |
| X14_CAUSE | {0} lamports > 상한 {1} lamports | {0} lamports > cap {1} lamports |
| X14_CAUSE_MAX | 최대 {0} lamports > 상한 {1} lamports | up to {0} lamports > cap {1} lamports |
| X20_CAUSE | RPC {0} lamports · 계산값 {1} | RPC {0} lamports · computed {1} |
| SUB_TX | 거래 {0}/{1} | Transaction {0}/{1} |
| VALIDITY_NONCE | durable nonce — 만료 없음\n서명한 거래는 언제든 제출될 수 있습니다 | durable nonce — no expiry\nThe signed transaction can be submitted at any time |
| BLOCKHASH_OK | 블록해시 유효 확인됨 (RPC, processed) | Blockhash verified as valid (RPC, processed) |
| BLOCKHASH_UNCHECKED | 블록해시 확인 안 됨 — 만료되었거나 RPC보다 새것 | Blockhash not verified — expired or newer than the RPC |
| VALIDITY | {0}\n블록해시는 약 150블록 뒤 만료됩니다 — 늦게 승인하면 거래가 실패할 수 있습니다 | {0}\nThe blockhash expires after about 150 blocks — approving late can make the transaction fail |
| TITLE_SIGN_SEND | 사이트 거래 서명 후 전송 | Sign and send site transaction |
| TITLE_SIGN | 사이트 거래 서명 | Sign site transaction |
| TITLE_SIGN_N | 사이트 거래 {0}건 서명 | Sign {0} site transactions |
| PREFLIGHT_SKIP | preflight 검사: 생략 (skipPreflight) | Preflight check: skipped (skipPreflight) |
| PREFLIGHT | preflight 검사: 함 (commitment {0}) | Preflight check: on (commitment {0}) |
| MIN_SLOT_NONE | minContextSlot: 없음 | minContextSlot: none |
| MIN_SLOT | minContextSlot: {0} (첫 전송만) | minContextSlot: {0} (first send only) |
| RESEND | 재전송: 만료될 때까지 지갑이 직접 (maxRetries 0) | Resending: by the wallet itself until expiry (maxRetries 0) |
| SUMMARY_SIGN_ONLY | 서명만 — 서명한 거래를 사이트에 돌려줍니다 (지갑은 전송하지 않음)\n거래 {0}건 | Sign only — the signed transactions go back to the site (the wallet does not send them)\nTransactions: {0} |
| SUMMARY_SEND | 서명 후 전송 — 지갑이 서명하고 바로 전송합니다\n거래 1건 | Sign and send — the wallet signs and sends right away\nTransactions: 1 |

<!-- catalogue: yw_core::btc::text -->

| 이름 | 한국어 | English |
|---|---|---|
| NETWORK_MAINNET | Bitcoin 메인넷 | Bitcoin mainnet |
| BANNER_TESTNET4 | BITCOIN TESTNET4 — 가치 없음 | BITCOIN TESTNET4 — NO VALUE |
| SCRIPT_P2PKH | 레거시 | Legacy |
| SCRIPT_P2SH_P2WPKH | 호환 세그윗 | Nested SegWit |
| SCRIPT_P2WPKH | 네이티브 세그윗 | Native SegWit |
| SCRIPT_P2TR | 탭루트 | Taproot |
| ACCOUNT_HD | {0} 계정 {1} | {0} account {1} |
| ACCOUNT_HD_ADDED | {0} 계정 {1} (추가한 복구 단어) | {0} account {1} (added recovery words) |
| ACCOUNT_IMPORTED | 가져온 키 · {0} | Imported key · {0} |
| ACCOUNT_EVM_KEY | EVM 계정 {0} 키 · {1} | EVM account {0} key · {1} |
| ACCOUNT_YUBIKEY_ADDRESS | YubiKey · {0} 주소 {1} | YubiKey · {0} address {1} |
| ACCOUNT_YUBIKEY_EVM | YubiKey EVM 계정 {0} 키 · {1} | YubiKey EVM account {0} key · {1} |
| PATH_IMPORTED | 가져온 키 | Imported key |
| PATH_UNKNOWN_YUBIKEY | 경로를 알 수 없음 (YubiKey) | Path unknown (YubiKey) |
| TYPE_P2PKH | P2PKH(레거시) | P2PKH (legacy) |
| TYPE_P2SH | P2SH(스크립트) | P2SH (script) |
| TYPE_P2WSH | P2WSH(스크립트) | P2WSH (script) |
| FEE_SOURCE_ESTIMATE_SPEED | 노드 추정({0}, {1}블록 목표) | Node estimate ({0}, {1}-block target) |
| FEE_SOURCE_ESTIMATE | 노드 추정({0}블록 목표) | Node estimate ({0}-block target) |
| FEE_SPEED_FAST | 빠름 | fast |
| FEE_SPEED_NORMAL | 보통 | normal |
| FEE_SPEED_SLOW | 느림 | slow |
| FEE_SOURCE_MANUAL | 직접 입력 | Entered manually |
| FEE_SOURCE_FLOOR | 하한 적용 | Floor applied |
| TITLE_FEE_BUMP | [{0}] 수수료 올리기 | [{0}] Bump fee |
| TITLE_SEND | [{0}] 보내기: {1} BTC | [{0}] Send: {1} BTC |
| TITLE_MESSAGE | [{0}] 메시지 서명 (소유 증명) | [{0}] Sign message (proof of ownership) |
| CHANGE_SAME_ADDRESS | 같은 주소 | same address |
| CHANGE_BACK | {0} BTC — 이 지갑으로 돌아옴 {1} | {0} BTC — returns to this wallet {1} |
| CHANGE_NONE | 잔돈 없음: {0} sats 수수료에 추가 | No change: {0} sats added to the fee |
| CONFIRMATIONS_UNKNOWN | 최소 확인 수 알 수 없음 (서버 기준) | Minimum confirmations unknown (server data) |
| CONFIRMATIONS | 최소 확인 수 {0} (서버 기준) | Minimum confirmations {0} (server data) |
| INPUTS | {0}개, 합계 {1}\n모든 입력 금액은 이전 거래 해시로 검증됨\n{2} | {0}, total {1}\nEvery input amount verified by its previous transaction hash\n{2} |
| FEE | {0}\n{1} (계획 vsize {2} vB 기준, 서명 후 실제 값은 같거나 높음)\n보내는 금액의 {3}%\n출처: {4} | {0}\n{1} (at the planned vsize {2} vB; the actual value after signing is the same or higher)\n{3}% of the amount sent\nSource: {4} |
| FEE_OVERRIDE | 상한 해제: 보내기 화면에서 수수료를 정확히 입력함 | Cap lifted: the exact fee was entered on the send screen |
| BALANCE_BASE | 검증 잔액 {0} BTC 기준 | based on the verified balance {0} BTC |
| BALANCE_UNKNOWN | 알 수 없음 ({0}) | unknown ({0}) |
| REPLACES_DECREASED | 수신 금액 감소(B06): {0} → {1} sats | Recipient amount reduced (B06): {0} → {1} sats |
| REPLACES_SAME_RECIPIENT | 수신자 변경 없음 | Recipient unchanged |
| REPLACES | 교체 대상 {0}\n수수료 {1} → {2} sats (+{3})\n{4} | Replaces {0}\nFee {1} → {2} sats (+{3})\n{4} |
| REPLACES_BIP125_MIN | 교체 최소 수수료(BIP125)를 적용함 | Minimum replacement fee (BIP125) applied |
| TXID_AFTER_SIGNING | 서명 후 결정 (레거시 입력) | decided after signing (legacy inputs) |
| ADVANCED | version {0}\nnLockTime {1} (= 블록 높이 {2})\nRBF 가능 (sequence 0x{3})\n입력 형식 {4}\nvsize {5} vB · weight {6} WU (서명 전 추정)\ntxid {7} | version {0}\nnLockTime {1} (= block height {2})\nRBF enabled (sequence 0x{3})\nInput type {4}\nvsize {5} vB · weight {6} WU (estimated before signing)\ntxid {7} |
| B01_FEE_UNOVERRIDABLE | 수수료율이 10,000 sat/vB를 넘습니다 — 어떤 입력으로도 보낼 수 없습니다 | Fee rate above 10,000 sat/vB — it cannot be sent with any input |
| B02_FEE_CAP_BLOCKED | 수수료가 상한(500 sat/vB 또는 0.005 BTC)을 넘습니다 — 보내기 화면에서 수수료(sats)를 정확히 입력해야 상한이 해제됩니다 | Fee above the cap (500 sat/vB or 0.005 BTC) — enter the exact fee (sats) on the send screen to lift the cap |
| B03_FEE_CAP_OVERRIDDEN | 수수료 상한(500 sat/vB 또는 0.005 BTC)을 직접 입력으로 해제했습니다 | Fee cap (500 sat/vB or 0.005 BTC) lifted by entering the fee manually |
| B04_FEE_RATIO | 수수료가 보내는 금액의 2%를 넘습니다 | Fee above 2% of the amount sent |
| B05_FIRST_TIME | 처음 보내는 주소입니다. 주소 전체를 확인하고, 큰 금액은 소액 시험 송금 뒤 보내세요. | First send to this address. Check the whole address, and send a small test amount before a large one. |
| B06_RECIPIENT_DECREASED | 수신 금액 감소: 늘어난 수수료만큼 받는 금액이 줄어듭니다 | Recipient amount reduced: the recipient gets less by the added fee |
| B06_UTXOS_EXCLUDED | UTXO {0}개는 포함되지 않음(입력 최대 100개) | {0} UTXOs left out (at most 100 inputs) |
| B07_OWN_ADDRESS | 이 지갑의 주소입니다 ({0}) | This is an address of this wallet ({0}) |
| B08_LEGACY_RECIPIENT | 레거시 형식(P2PKH) 주소입니다 | Legacy (P2PKH) address |
| B08_SCRIPT_RECIPIENT | 스크립트 주소(P2SH·P2WSH)입니다: 수신자가 스크립트를 관리합니다 | Script address (P2SH·P2WSH): the recipient controls a script |
| MESSAGE_TOO_LARGE | 64KiB를 넘는 메시지입니다 | The message is larger than 64 KiB |

<!-- catalogue: yw_core::zec::text -->

| 이름 | 한국어 | English |
|---|---|---|
| BANNER_TESTNET | ZCASH TESTNET — 가치 없음 | ZCASH TESTNET — NO VALUE |
| FORM_TRANSPARENT | 일반(transparent) 주소 | Transparent address |
| FORM_TEX | TEX 주소 (ZIP 320, 일반 주소로만 보냄) | TEX address (ZIP 320, sent to a transparent address only) |
| FORM_UNIFIED | 통합 주소(UA)의 일반(transparent) 수신자 | Transparent receiver of a unified address (UA) |
| SOURCE_STANDARD | Zcash 표준 경로 | Zcash standard path |
| SOURCE_PATH | Zcash 경로 (계정 {0}, 주소 {1}) | Zcash path (account {0}, address {1}) |
| SOURCE_STANDARD_ADDED | Zcash 표준 경로 (추가한 복구 단어) | Zcash standard path (added recovery words) |
| SOURCE_PATH_ADDED | Zcash 경로 (계정 {0}, 주소 {1}, 추가한 복구 단어) | Zcash path (account {0}, address {1}, added recovery words) |
| SOURCE_EVM | EVM 계정 {0} 키 | EVM account {0} key |
| SOURCE_YUBIKEY_CARD | YubiKey (카드 키 {0}) | YubiKey (card key {0}) |
| SOURCE_YUBIKEY | YubiKey (주소 {0}) | YubiKey (address {0}) |
| SOURCE_IMPORTED | 가져온 키 | Imported key |
| PATH_IMPORTED | 가져온 개인키 (복구 단어 밖) | Imported private key (outside the recovery words) |
| PATH_UNKNOWN | 경로를 알 수 없음 | Path unknown |
| Z05_PUBLIC | 일반(transparent) 전송은 보내는 주소·받는 주소·금액이 블록체인에 공개됩니다. | A transparent send makes the sending address·recipient address·amount public on the blockchain. |
| Z01_OWN_ADDRESS | 받는 주소가 이 계정의 주소입니다 (수수료만 나갑니다). | The recipient is this account's own address (only the fee is spent). |
| Z02_TEX | TEX 주소: 받는 사람이 일반(transparent) 자금만 받겠다고 요청한 주소입니다. 이 거래는 일반 입력만 씁니다. | TEX address: the recipient asked to receive transparent funds only. This transaction uses transparent inputs only. |
| Z03_UA_TRANSPARENT | 통합 주소(UA)의 일반(transparent) 수신자로 보냅니다. 받는 지갑에는 비공개가 아닌 일반 잔액으로 들어갑니다. | Sending to the transparent receiver of a unified address (UA). The receiving wallet gets a public transparent balance, not a shielded one. |
| Z04_EXPIRY_CAPPED | 다음 네트워크 업그레이드 전에 만료되도록 만료 높이를 앞당겼습니다. | The expiry height was moved earlier so the transaction expires before the next network upgrade. |
| Z06_FIRST_TIME | 처음 보내는 주소입니다. 주소 전체를 확인하고, 큰 금액은 소액 시험 송금 뒤 보내세요. | First send to this address. Check the whole address, and send a small test amount before a large one. |
| TITLE | [{0}] 보내기: {1} ZEC | [{0}] Send: {1} ZEC |
| TO_ENTERED | {0}\n입력한 주소: {1} | {0}\nEntered address: {1} |
| CHANGE_BACK | {0} ZEC — 같은 주소로 돌아옴 {1} | {0} ZEC — returns to the same address {1} |
| CHANGE_FOLDED | 잔돈 없음: {0} zats 수수료에 추가 | No change: {0} zats added to the fee |
| CHANGE_NONE | 잔돈 없음 | No change |
| FEE | {0}\nZIP 317 기본 수수료 {1} zats (입력 {2}개, 출력 {3}개) | {0}\nZIP 317 conventional fee {1} zats ({2} inputs, {3} outputs) |
| EXPIRY | 블록 {0} (다음 블록 {1}부터 {2}블록, 약 {3}분 안에 포함되지 않으면 무효)\n네트워크 업그레이드 {4} (branch id {5}) | Block {0} (invalid unless included within {2} blocks from the next block {1}, about {3} min)\nNetwork upgrade {4} (branch id {5}) |
| EXPIRY_NEXT_UPGRADE | 다음 업그레이드 활성화 높이 {0} | Next upgrade activation height {0} |
| INPUTS | {0}개, 합계 {1}\n입력 금액과 스크립트는 서명(ZIP 244)에 포함되어, 틀리면 거래가 무효가 됩니다 | {0}, total {1}\nInput amounts and scripts are part of the signature (ZIP 244); if they are wrong, the transaction is invalid |
| INPUTS_EXCLUDED | 가장 큰 입력 {0}개만 씁니다 — 나머지 {1}개는 이 주소에 남습니다 | Only the {0} largest inputs are used — the other {1} stay on this address |
| ADVANCED | v5 거래 (ZIP 225), 일반(transparent) 입력·출력만\nnLockTime 0 · sequence 0xFFFFFFFF\nSIGHASH_ALL (ZIP 244)\n{0} | v5 transaction (ZIP 225), transparent inputs·outputs only\nnLockTime 0 · sequence 0xFFFFFFFF\nSIGHASH_ALL (ZIP 244)\n{0} |
| ADVANCED_SEND_MAX | 보내기 최대: 모든 확인된 잔액 − 수수료 | Send max: all confirmed balance − fee |
| ADVANCED_FIXED | 지정 금액 | Specified amount |

<!-- catalogue: yw_core::hypercore::text -->

| 이름 | 한국어 | English |
|---|---|---|
| NETWORK_MAINNET | HyperCore 메인넷 | HyperCore mainnet |
| NETWORK_TESTNET | HyperCore 테스트넷 | HyperCore testnet |
| KIND_USD_SEND | USDC 보내기 (HyperCore) | Send USDC (HyperCore) |
| KIND_SPOT_SEND | 현물 토큰 보내기 (HyperCore) | Send spot token (HyperCore) |
| KIND_WITHDRAW | Arbitrum으로 USDC 출금 | Withdraw USDC to Arbitrum |
| KIND_USD_CLASS_TRANSFER | 현물↔선물 USDC 이동 | Move USDC spot↔perp |
| KIND_SEND_ASSET | HyperEVM으로 이동 | Move to HyperEVM |
| TITLE | [{0}] HyperCore 전송: {1} | [{0}] HyperCore transfer: {1} |
| NETWORK | Hyperliquid {0} (chainId {1}로 서명 · hyperliquidChain {2}) | Hyperliquid {0} (signed with chainId {1} · hyperliquidChain {2}) |
| DIRECTION | {0}\n방향: {1} | {0}\nDirection: {1} |
| SPOT_TO_PERP | 현물(spot) → 선물(perp) | Spot → perp |
| PERP_TO_SPOT | 선물(perp) → 현물(spot) | Perp → spot |
| NOTE_EVM_SYSTEM | HyperEVM 시스템 주소 — 토큰은 HyperEVM의 같은 주소(서명 계정)로 들어갑니다 | HyperEVM system address — the tokens arrive at the same address (the signing account) on HyperEVM |
| NOTE_WITHDRAW | Arbitrum One의 이 주소로 USDC가 들어갑니다 | USDC arrives at this address on Arbitrum One |
| NOTE_SAME_ACCOUNT | 보내는 계정과 같은 주소입니다 | Same address as the sending account |
| TOKEN | {0} (토큰 index {1}, tokenId {2}, 소수 {3}자리) | {0} (token index {1}, tokenId {2}, {3} decimals) |
| WITHDRAW_AMOUNT | {0} USDC\nArbitrum 도착 = 금액 − {1} USDC = {2} USDC | {0} USDC\nArrives on Arbitrum = amount − {1} USDC = {2} USDC |
| FEE_WITHDRAW | {0} USDC (고정 출금 수수료, HyperCore에서 차감) | {0} USDC (fixed withdrawal fee, deducted on HyperCore) |
| FEE_SEND_ASSET | HyperCore에서 HYPE로 HyperEVM 가스(200k gas)를 냅니다 | HyperEVM gas (200k gas) is paid in HYPE on HyperCore |
| FEE_NONE | 없음 (HyperCore 사용자 서명 작업) | None (HyperCore user-signed action) |
| NONCE | {0} (unix ms, 서명 시각) | {0} (unix ms, signing time) |

<!-- catalogue: yw_core::slip10::text -->

| 이름 | 한국어 | English |
|---|---|---|
| PATH_RAW_SEED | BIP39 seed[0..32] (파생 없음) | BIP39 seed[0..32] (not derived) |
| PATH_IMPORTED | 가져온 개인키 (복구 단어 밖) | Imported private key (outside the recovery words) |
| PATH_UNKNOWN | 경로를 알 수 없음 | Unknown path |
