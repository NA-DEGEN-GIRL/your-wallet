# 13. WalletConnect v2 (Reown) — 지갑으로 dApp 연결 (D35, 2026-11-06)

- 상태: 구현(yw-core `walletconnect`, yw-win `ws`·`image`·`cng::p256_verify`·`clipboard::read_dib`, yw-app `walletconnect::{engine, worker, verify, store, qr_decode}`·`app_walletconnect`·`ui::screens_walletconnect`). 실제 dApp 연결은 사용자의 Reown Project ID로 수동 확인만 남음(§10).
- 범위: 이 앱이 **지갑(응답자·controller)** 으로서 WalletConnect Sign v2 세션을 맺는다. 브라우저 확장([05](05-browser.md))과 나란히 쓰는 두 번째 연결 방법이며, 모든 요청은 같은 디스패처·승인 창·arm 지연·위험 규칙·시뮬레이션을 지난다.
- **1단계는 EVM(`eip155`)만**이다. Solana·Bitcoin·기타 네임스페이스는 범위 밖: 필수(required)에 있으면 제안을 5100으로 거부하고, 선택(optional)에 있으면 세션에서 뺀다(§9).
- 의존성 추가 없음: `chacha20poly1305`·`hkdf`·`sha2`·`ed25519-dalek`·`curve25519-dalek`(Montgomery X25519)·`getrandom`은 이미 yw-core에 있고, `windows-sys`에 `Win32_Graphics_GdiPlus` 기능만 더했다(같은 크레이트·같은 lock).

## 1. 출처 (2026-11-06 확인)

| 항목 | 출처 |
|---|---|
| 페어링 URI `wc:{topic}@2?symKey&methods&relay-protocol=irn[&relay-data][&expiryTimestamp]`, 예시 URI | https://specs.walletconnect.com/2.0/specs/clients/core/pairing/pairing-uri (원문 `WalletConnect/walletconnect-specs` `docs/specs/clients/core/pairing/pairing-uri.md`) |
| 타입 0/1 봉투(`tp ‖ iv12 ‖ sealbox`, `tp ‖ pk32 ‖ iv12 ‖ sealbox`, ChaCha20-Poly1305) | https://specs.walletconnect.com/2.0/specs/clients/core/crypto/crypto-envelopes |
| 키 종류(X25519 합의 → HKDF, 토픽 = SHA-256(키)) | https://specs.walletconnect.com/2.0/specs/clients/core/crypto/crypto-keys |
| HKDF 인자(salt 없음·info 없음·32바이트), base64(패딩) 직렬화, `hashKey`·`hashMessage` | 참조 구현 `walletconnect-monorepo` `packages/utils/src/crypto.ts` (`deriveSymKey`: `hkdf(sha256, sharedKey, undefined, undefined, 32)`, `serialize`/`deserialize`) |
| 릴레이 인증 did-JWT(EdDSA, `iss`=did:key, `sub`=연결마다 난수, `aud`=릴레이 URL, `iat`·`exp`), did:key 인코딩, **시험 벡터** | https://specs.walletconnect.com/2.0/specs/clients/core/crypto/crypto-authentication , https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-client-auth |
| 릴레이 URL `wss://relay.walletconnect.org`, `?auth=&projectId=&ua=` | 참조 구현 `packages/core/src/constants/relayer.ts`(`RELAYER_DEFAULT_RELAY_URL`), `packages/utils/src/misc.ts`(`formatRelayRpcUrl`), https://specs.walletconnect.com/2.0/specs/clients/core/relay/relay-user-agent |
| Project ID는 dashboard.reown.com에서 받는다, 출처 허용 목록 규칙 | https://docs.reown.com/cloud/relay |
| `irn_subscribe`·`irn_publish{topic,message,ttl,tag}`·`irn_subscription{id,data{topic,message,attestation,publishedAt,tag}}`·`irn_unsubscribe` | https://specs.walletconnect.com/2.0/specs/servers/relay/relay-server-rpc |
| `wc_sessionPropose`/`Settle`/`Update`/`Extend`/`Request`/`Event`/`Delete`/`Ping` 형식·태그·TTL | https://specs.walletconnect.com/2.0/specs/clients/sign/rpc-methods , 참조 구현 `packages/sign-client/src/constants/engine.ts`(`ENGINE_RPC_OPTS`) |
| 제안·세션 네임스페이스 규칙(필수 전부 만족, 선택 일부, 빈 제안 = 모든 체인, 체인은 CAIP-2) | https://specs.walletconnect.com/2.0/specs/clients/sign/namespaces |
| 제안 순서(지갑이 키 Y 생성 → 세션 토픽 구독 → settle 발행 → 페어링 토픽에 응답) | https://specs.walletconnect.com/2.0/specs/clients/sign/session-proposal , `data-structures` |
| 오류 코드(1006, 3003, 4001, 5000, 5100, 5101, 6000, 7001, 8000) | https://specs.walletconnect.com/2.0/specs/clients/sign/error-codes |
| `chainChanged` data = 숫자 chainId, `accountsChanged` data = CAIP-10 계정 | 참조 구현 `providers/universal-provider/src/UniversalProvider.ts`(`onSessionEventRequest`), `providers/eip155.ts`(`handleSwitchChain`) |
| Verify: v3 ES256 JWT(`attestation`), `GET /v3/public-key`, v2 폴백 `GET /attestation/{sha256(JSON)}?v2Supported=true`, `id = sha256(암호문)` | https://specs.walletconnect.com/2.0/specs/clients/core/verify/verify-client-api , `servers/verify/verify-server-api`, 참조 구현 `packages/core/src/controllers/verify.ts`, `packages/sign-client/src/controllers/engine.ts`(`getVerifyContext`) |
| Verify 결과 VALID/INVALID/UNKNOWN·`isScam` 의미와 경고 권고 | https://docs.walletconnect.com/wallets/web/verify.md (docs.reown.com/walletkit/web/verify 리다이렉트) |
| ES256 서명 시험 벡터 | RFC 7515 부록 A.3 |
| X25519 시험 벡터 | RFC 7748 §6.1 |

실측(2026-11-06): 릴레이는 JWT가 없거나 형식이 틀리면 HTTP 401(`{"error":"JWT is missing"}`, `"JWT validation error: …"`), 이 앱의 JWT에 지어낸 Project ID면 **403**(JWT 통과, ID 거부)을 준다. Verify `/v3/public-key`는 200 JSON(`{"publicKey":{"crv":"P-256",…},"expiresAt":…}`), 모르는 v2 id는 404.

참고: 최신 참조 SDK(2.2x)는 dApp 쪽이 `wc_proposeSession`, 지갑 쪽이 `wc_approveSession` 릴레이 메서드로 제안·승인을 묶어 보내기도 한다. dApp은 여전히 페어링 토픽을 구독하므로 이 앱은 사양의 기본 방식(응답은 페어링 토픽 `irn_publish` tag 1101, settle은 세션 토픽 tag 1102)을 쓴다.

## 2. 페어링 URI

- `wc:`(대소문자 무시)로 시작, 토픽 64자리 16진수, `@2` 필수(`@1` = v1은 "v1은 종료되어 지원하지 않습니다"), `symKey` 64자리 16진수, `relay-protocol=irn`만, `expiryTimestamp`(초) 지나면 "만료". 앞뒤 공백, 통째로 퍼센트 인코딩된 URI(`wc%3A…`), 값의 퍼센트 인코딩을 받는다. 같은 키가 두 번이면 거부. 2,048바이트 이하.
- 붙여넣기(dApp WalletConnect 창의 `링크 복사`)가 기본 입력이다. QR은 §6.
- 페어링 수명(2026-11-08): 최대 5분(`PAIRING_TTL_S`; `expiryTimestamp`는 줄이기만 하고 최소 1분), 지나면 대기 제안이 없을 때 구독을 끊는다. 한 페어링은 제안을 3개까지 받고(그 뒤는 창 없이 5000), 제안 하나가 세션이 되면 더 받지 않고(5000) 남은 대기 제안이 끝나는 즉시 구독을 끊고 버린다(새 연결은 새 URI, §9). 같은 URI를 다시 붙여 넣으면 처음부터 다시 센다.

## 3. 암호

- X25519: `curve25519-dalek` `MontgomeryPoint::mul_base_clamped`/`mul_clamped`. 공유 비밀이 전부 0이면(저차 점) 거부.
- 세션 키 = `HKDF-SHA256(ikm = X25519(우리 비밀, dApp 공개키), salt 없음(= 0×32), info 빈 값, 32바이트)`. 세션 토픽 = `SHA-256(세션 키)`(소문자 16진수).
- 봉투: 타입 0만 보낸다(nonce 12바이트 OS 난수). 받을 때 타입 0만 연다(타입 1은 지갑 흐름에 없음, 타입 2 = 평문 링크 모드는 거부). base64는 표준·패딩.
- 릴레이 클라이언트 키: Ed25519 시드 32바이트(처음 Project ID를 저장하고 잠금 해제할 때 생성, meta에 봉인 저장 §8). JWT 페이로드는 `{"iss","sub","aud","iat","exp"}` 순서(사양 시험 벡터와 바이트 단위 일치), `aud = "wss://relay.walletconnect.org"`, `exp = iat + 86,400`, `sub`는 연결마다 32바이트 난수.

## 4. 릴레이 연결

- `wss://relay.walletconnect.org/?auth={JWT}&projectId={ID}&ua=wc-2%2Frust-yourwallet-{버전}%2Fwindows`. yw-win `ws`(WinHTTP WebSocket: `WINHTTP_OPTION_UPGRADE_TO_WEB_SOCKET` → 101 → `WinHttpWebSocketCompleteUpgrade`), TLS 1.2/1.3, 리다이렉트·쿠키·자동 인증 없음, keep-alive 15초, 닫기 시간 2초. 연결 15초 제한. 오류에는 URL(토큰·ID 포함)을 넣지 않는다.
- 구독할 토픽(페어링 + 세션)이 있고 Project ID와 클라이언트 키가 있을 때만 연결한다. 토픽이 없으면 10초 뒤 닫는다. 끊기면 1초부터 두 배씩 최대 60초 간격으로 다시 붙고, 붙으면 모든 토픽을 다시 구독(우편함의 밀린 메시지가 온다)하고 그동안 쌓인 발행(최대 256개)을 보낸다. 401/403이면 5분 뒤에만 다시 시도하고 패널에 "릴레이가 Project ID를 거부했습니다 (HTTP n)".
- `irn_subscription`은 받은 `id`로 `{"result":true}` 응답한 뒤 처리한다. 같은 (토픽, JSON-RPC id)는 한 번만 처리한다(최근 512개; 릴레이는 최소 한 번 전달).

## 5. Sign 프로토콜

| 메시지 | 이 앱의 처리 | 태그 / TTL |
|---|---|---|
| `wc_sessionPropose`(페어링 토픽) | 검사 후 Verify(§7) → 연결 창 | 응답 1101 / 300, 거부 1120 / 300 |
| `wc_sessionSettle`(세션 토픽, 우리가 보냄) | `relay{irn}`, `namespaces.eip155{chains, accounts = 체인×계정 CAIP-10, methods, events}`, `controller{publicKey, metadata}`, `expiry = 지금 + 7일` | 1102 / 300 |
| `wc_sessionRequest` | §5.2 | 응답 1109 / 300 |
| `wc_sessionEvent`(우리가 보냄) | `chainChanged`(data = 숫자), `accountsChanged`(data = CAIP-10) | 1110 / 300 |
| `wc_sessionUpdate`(우리가 보냄) | 체인 추가(전환) 또는 계정 변경 | 1104 / 86,400 |
| `wc_sessionExtend`(우리가 보냄) | 요청이 오는데 남은 기간 < 2일이면 지금 + 7일 | 1106 / 86,400 |
| `wc_sessionDelete` | 받으면 `true` 응답 후 세션 삭제, 보낼 때 `{code 6000, "User disconnected."}` | 1113·1112 / 86,400 |
| `wc_sessionPing`·`wc_pairingPing` | `true` | 1115·1003 / 30 |
| `wc_pairingDelete` | `true`, 페어링 삭제 — 페어링 토픽에서만(2026-11-10: 세션 토픽으로 온 것은 답하지 않고 무시해 세션 구독을 끊지 않는다) | 1001 / 86,400 |
| `wc_sessionAuthenticate`(원클릭 인증) | 응답하지 않는다(미지원) — dApp은 함께 보낸 제안으로 넘어간다 | — |
| dApp이 보낸 `wc_sessionUpdate`/`Extend`/`Event` | 3003 Unauthorized(controller만 가능) | 1105 |

### 5.1 제안 검사 (namespaces 사양)

- `requiredNamespaces`·`optionalNamespaces`의 `eip155`(키 `eip155` + `chains`, 또는 키 `eip155:N`)에서 CAIP-2 체인을 읽는다. 필수 체인이 CAIP-2가 아니면 5100, 필수에 다른 네임스페이스(solana 등)가 있으면 5100, 필수 체인 중 이 지갑에 등록되지 않은(또는 RPC 불일치로 막힌) 체인이 있으면 5100.
- 승인할 체인 = 필수 ∪ (선택 ∩ 등록 체인), 요청 순서. 필수·선택 네임스페이스가 모두 없거나 비어 있을 때만 등록된 모든 EVM 체인(참조 `buildApprovedNamespaces`와 같음; 2026-11-10 — EVM이 아닌 네임스페이스만 적은 제안, 예: Solana 전용 dApp은 모든 EVM 체인을 받지 않고 5100). 결과가 비면 5100.
- 창 없는 거절에는 이유를 알린다(2026-11-10): 위 5100·1006, 쿨다운·페어링 소진·대기 가득의 5000마다 WalletConnect 패널 알림에 지갑이 쓴 문장 — 없는(또는 막힌) 필수 체인은 등록 이름 또는 `eip155:N`, EVM이 아닌 네트워크는 그 사실만(dApp이 보낸 이름은 보이지 않음), 이미 쓴 연결 주소는 "dApp에서 새 QR/링크를 받아 다시 연결하세요". 제안 없이 만료된 페어링도 알린다(이전에는 "기다리는 중"이 그대로 남았다).
- 세션 메서드 = 이 지갑이 처리하는 6개(`eth_accounts`, `eth_chainId`, `personal_sign`, `eth_signTypedData_v4`, `eth_sendTransaction`, `wallet_switchEthereumChain`) ∪ 필수 메서드(사양상 필수는 모두 넣어야 한다 — 그중 처리하지 않는 것은 요청 때 4200, 연결 창에 "지원하지 않는 요청은 거부됩니다: …"). 이벤트 = `chainChanged`·`accountsChanged` ∪ 필수 이벤트.
- 이름 허용 목록(2026-11-08): 필수 메서드·이벤트 이름은 1–64자 ASCII `[A-Za-z0-9_:]`이고 알려진 `eip155` 이름(`engine::KNOWN_METHODS` 26개 — `eth_sign`·`eth_signTransaction`·`wallet_addEthereumChain`·`wallet_sendCalls` 등 AppKit이 요구하는 이름, `KNOWN_EVENTS` = `chainChanged`·`accountsChanged`·`connect`·`disconnect`·`message`)일 때만 세션에 들어간다. 나머지는 버리고 개수만 센다(연결 창 "사이트가 요구한 알 수 없는 요청·이벤트 이름 n개는 세션에서 뺐습니다." — 이름 자체는 보이지도 저장하지도 않는다). 그래서 세션의 메서드·이벤트 수는 허용 목록 크기를 넘지 않는다. 네임스페이스 키는 객체마다 16개까지 읽는다(필수가 더 많으면 5100). meta에서 읽은 세션도 같은 목록으로 거른다.
- 제안 만료 = `expiryTimestamp`(없으면 5분, 최대 1시간). 대기 제안 8개(가득 차면 새 제안을 창 없이 5000으로 거절 — 대기 중인 제안을 밀어내지 않는다), 세션 64개.
- 대기 제안의 키는 **지갑이 고른 세션 토픽**이다(JSON-RPC id는 dApp이 고르므로 두 페어링이 같은 id를 쓸 수 있다): Verify 기록·승인·거절·UI 목록·`ProposalDone` 모두 세션 토픽으로 찾는다. 다른(또는 같은) 페어링의 대기 제안과 id가 같은 `wc_sessionPropose`는 응답 없이 버린다(중복 창 512개를 넘긴 재전달이 대기 제안을 거절하지 않게).
- 제안이 거절(5000)되거나 만료되면 그 페어링은 15초 동안 새 제안을 연결 창 없이 5000으로 거절한다(창을 계속 띄워 유휴 잠금을 멈추지 못하게, [04](04-app-ui.md) §5.1).

### 5.2 세션 요청 → 디스패처

- 세션이 만료 7001, `chainId`가 세션 체인이 아니거나 **지금 등록되어 있고 막히지 않은 체인이 아니면** 5100(2026-11-08: 지운 체인의 요청이 출처의 이전 체인이나 기본 체인에서 실행되지 않게), 메서드가 세션 메서드가 아니면 5101, `request.expiryTimestamp`(참조 sign-client가 보내는 이름, 기본 보낸 때 + 5분; 사양 페이지의 옛 이름 `request.expiry`도 읽음 — 2026-11-10 전에는 `expiry`만 읽어 실제 dApp의 기한을 놓쳤다)가 지났으면 8000.
- 등록 체인 목록이 바뀌면(작업 스레드가 입력·tick마다 다시 읽음, 잠금 해제 중일 때) 더는 등록되지 않은 체인을 세션에서 빼고 `wc_sessionUpdate`를 보낸다. 체인이 하나도 남지 않은 세션은 끊는다(`wc_sessionDelete`). 막힌(RPC 불일치) 체인은 빼지 않고 요청마다 거절한다.
- 디스패처에는 요청의 체인을 함께 넘긴다(`BrowserCore::submit(conn, envelope, chain)`): 디스패처가 같은 잠금 안에서 그 체인을 확인(등록·막히지 않음, 아니면 4901)하고 출처 체인으로 맞춘 뒤 요청을 처리한다 — 확인과 실행 사이에 체인이 지워져도 다른 체인에서 돌지 않는다.
- `eth_accounts` = 그 세션 출처의 **권한(grant) 계정**(지갑이 잠겨 있거나 권한이 없으면 빈 목록; 2026-11-08부터 세션에 남은 이전 목록으로 답하지 않는다), `eth_chainId` = 요청의 `chainId`(16진수): 세션에서 바로 답한다.
- `wallet_switchEthereumChain`: 등록되지 않은 체인 4902, 막힌 체인 4901, 세션에 없는 등록 체인이면 `wc_sessionUpdate`로 추가, `null` 응답 후 `chainChanged`.
- `personal_sign`·`eth_signTypedData_v4`·`eth_sendTransaction`: 세션의 합성 출처(§7)를 요청 체인으로 맞춘 뒤 디스패처의 **가상 연결**(`BrowserCore::open_virtual_connection`/`submit`, 브라우저 상태 줄 개수에는 세지 않음)로 넣는다. 활성화 nonce = 세션 토픽(세션별 토큰 버킷), 기한 = `expiryTimestamp`와 10분 중 이른 쪽(dApp이 포기한 뒤에 창이 뜨지 않게). 이후는 확장과 같다: 권한(계정이 그 세션 승인에 있어야 함), 승인 큐, arm 지연, 위험 규칙, 시뮬레이션, 서명·전송. 응답·오류(코드·메시지)는 그대로 1109로 돌려준다. 확장과 다른 점: 지갑이 잠겨 있으면(시작 중 포함) 디스패처가 바로 4100으로 거절하고 **잠금 해제 창을 열지 않는다**(원격 dApp이 비밀번호 창을 마음대로 띄우지 못하게; 사용자가 잠금을 풀고 dApp에서 다시 요청). 잠그는 순간 큐에서 기다리던 WalletConnect 요청도 4100으로 끝낸다(2026-11-10: 이전에는 남아서 잠금 뒤 다시 읽기가 잠금 해제 창을 열고 잠금 해제 뒤 옛 요청을 보였다). 잠긴 동안 창 없이 4100으로 거절한 연결·서명 요청 수는 다음 잠금 해제 때 주 창 알림 한 줄("지갑이 잠겨 있는 동안 WalletConnect 요청 n개를 거절했습니다…")로 한 번 알린다. 서명 요청이 답 없이 끝나면(거절 4001, 만료, 시간 초과 — dApp의 짧은 기한 포함) 그 세션의 대기 중인 다른 요청도 4001로 끝내고(미리 줄 세운 요청이 잇달아 창을 띄우지 못하게, 2026-11-10), 다음 서명 요청은 15초 동안 창 없이 4001로 거절한다.
- 그 밖의 메서드는 전부 4200 `Unsupported method.`(`eth_sign` 등 확장과 같음).

### 5.3 연결 승인

- 제안은 세션 합성 출처의 `eth_requestAccounts`로 디스패처에 들어가 확장과 같은 연결 창을 연다. 연결 창은 출처(제목·`요청 출처`) 대신 "WalletConnect: {origin} (사이트가 주장한 주소)", 따로 표시한 `사이트 이름 (사이트가 주장)` 칸, 승인할 네트워크 목록("연결할 네트워크 (WalletConnect)"), Verify 경고·배지(§7)를 보인다. 계정을 고르고 `연결`하면 승인(§5 표) — 답한 창의 합성 출처가 그 제안의 세션 토픽과 같을 때만 —, 거절·만료·시간 초과면 5000 `User rejected.`. 권한(grant)은 합성 출처로 저장되어 확장의 같은 사이트 권한과 섞이지 않는다. 연결 요청이 끝나면 패널 알림이 결과를 말한다(2026-11-10: 승인, 거절, 창 시간 초과, 잠김, EVM 계정 없음, 256개 한도 등 — 이전에는 창 없이 거절돼도 "연결 요청이 도착했습니다"가 남았다).
- settle 확인(2026-11-10): dApp이 settle에 결과로 답하거나 그 세션으로 요청·ping을 보내면 확인된 세션(`acknowledged`)이다. settle에 오류로 답하면 참조 `onSessionSettleResponse`처럼 세션을 지우고 알린다. settle이 실제로 릴레이에 나간 뒤(복원한 미확인 세션은 토픽 구독이 확인된 뒤) `SETTLE_ACK_S` = 11분(settle 5분 + 응답 5분 + 여유 1분) 안에 확인이 없으면 `wc_sessionDelete`로 끊고 권한을 지우고 알린다(dApp 창이 닫혔거나 settle을 버린 세션이 7일 동안 "연결됨"으로 남지 않게). 확인 전 세션 카드에는 `상태: 연결 확인 중`.
- 계정을 숨기거나 지우면 권한에서 빠지고 세션은 `wc_sessionUpdate` + `accountsChanged`(남은 계정), 모두 빠지면 세션 삭제. 세션은 언제나 자기 권한을 따른다(2026-11-08, 앱을 다시 켠 뒤 복원된 세션 포함): ① 세션을 복원하거나 승인하면 그 합성 출처를 다리(가상 연결)의 문서로 등록한다(`BrowserCore::attach_virtual_document`) — 요청을 한 번도 하지 않은 세션도 출처의 `accountsChanged`를 받는다. ② UI가 권한을 쓸 때마다(`write_grants`: 계정 숨김·삭제, `연결 해제`, `모든 사이트 연결 해제`, 연결 승인) `WcCommand::SyncGrants`를 보내고, 잠금 해제 때의 `Load`도 같은 맞춤을 한다. 맞춤은 디스패처 상태가 잠금 해제일 때만(`grants_if_unlocked`, 상태와 권한을 한 잠금에서 읽음): 권한이 없으면 세션을 끊고(`wc_sessionDelete`), 계정이 다르면 `wc_sessionUpdate` + `accountsChanged`. 잠겨 있으면 아무것도 하지 않는다(잠금은 권한을 비우지만 세션은 유지).

## 6. QR 입력

- `클립보드에서 연결`(2026-11-08, 패널의 주 버튼): 누를 때만 `CF_UNICODETEXT`(최대 2,048자)를 읽어 앞 공백을 뺀 값이 `wc:`(또는 통째로 퍼센트 인코딩된 `wc%3A`, 2026-11-10 — 전에는 이미지 경로로 넘어가 "클립보드에 이미지가 없습니다"라고 했다)로 시작하면 그대로 `wc_pair`, 아니면 아래 이미지 경로. 앞머리 검사는 UTF-16 단위에서 바로 하고 링크가 아닌 텍스트는 버퍼 밖으로 복사하지 않는다. 클립보드에 쓰지 않고 읽은 텍스트는 로그에 남기지 않는다(`clipboard.link source=text`만).
- `클립보드 이미지에서 QR 읽기`(이제 `클립보드에서 연결`의 두 번째 단계): `CF_DIB`(Win+Shift+S가 넣음; BITMAPINFOHEADER/V4/V5, 8·24·32비트, 상하 방향 모두)를 읽는다(최대 80 MB).
- `이미지 파일에서 QR 읽기`: 경로 입력(탐색기 `경로로 복사`의 따옴표 허용) → 파일 머리(PNG `89 50 4E 47 0D 0A 1A 0A`, JPEG `FF D8 FF`, BMP `BM`, GIF `GIF87a`/`GIF89a`)와 크기(64 MB 이하)를 먼저 확인한 뒤에만 GDI+ 평면 API로 32비트로 읽는다(최대 64 M 픽셀; EMF·WMF·TIFF·ICO 등 다른 GDI+ 코덱에는 넘기지 않는다).
- 복호기(yw-app `walletconnect::qr_decode`, ISO/IEC 18004): 회색조 → 전역 Otsu, 실패하면 8×8 블록 국소 임계값, 각각 반전도 시도(다크 모드) → 행의 1:1:3:1:1 런으로 파인더 후보 → 세로·가로 교차 확인으로 중심 보정·병합 → 직각 이등변에 가까운 세 후보(TL = 가장 긴 변의 맞은편, 외적 부호로 TR/BL) → 버전 추정(±4, ±8) → 세 중심의 아핀 변환과, 우하 정렬 패턴을 찾으면 그 점을 쓴 사영 변환 → 모듈 표본 → 형식 정보 BCH(32개 중 해밍 ≤ 3) → 버전 정보(v7+, ≤ 3) → 마스크 해제 → 지그재그 → 블록 역인터리브 → GF(256)(0x11D, 근 α⁰…) Reed–Solomon(Berlekamp–Massey·Chien·Forney) → 숫자·영숫자·바이트 세그먼트(ECI 건너뜀). 결과가 `wc:`로 시작할 때만 페어링한다.
- 시험: 앱의 인코더(`qrcodegen`)로 만든 코드(여러 버전·L/M/Q/H), 17°·−8°·33°·90°·180° 회전과 2.6–5.1 픽셀 비정수 배율의 "스크린샷"(회색 배경·UI 상자·3×3 초표본), 다크 모드, 버전 15+, 데이터 영역 손상 복구.

## 7. 출처 표시와 Verify (보안)

- dApp 메타데이터(`name`·`url`·`icons`)는 **사이트가 스스로 주장한 값**이다. 이름 100자, 설명 300자, URL 512바이트로 자르고, 이름은 표시할 때 한 줄로 만든 뒤(공백·제어·방향 제어·숨은 문자의 연속을 공백 하나로) [03](03-evm.md) §11의 이스케이프를 쓴다. 이름은 출처·상태 줄에 넣지 않고 따로 이름표를 단 칸·목록에만 나온다. 아이콘은 저장만 하고 받아오지 않는다.
- 디스패처 출처는 합성: `https://{토픽 앞 32자리}.{뒤 32자리}.walletconnect.invalid`(`.invalid`는 해석되지 않음, RFC 6761). 권한 = (세션 토픽, 그 세션이 주장한 출처)이며 확장 권한·다른 세션과 공유하지 않는다.
- 승인 창·연결 창의 `요청 출처` = `WalletConnect: {origin} (사이트가 주장한 주소)`. `{origin}`은 `new URL(url).origin`에 해당하는 정규형(https 또는 http localhost, 기본 포트 제거)뿐이고, 형식이 틀리면 원문을 보이지 않고 "(주소 형식이 올바르지 않음)"(비었으면 "(주소 없음)"). Verify 상태는 이 줄에 넣지 않고 지갑이 만든 배지("WalletConnect 세션"·"Verify …")와 경고(C01–C04)로만 보인다.
- 승인 창의 표시(digest에 묶이는 `요청 출처` 값과 C0x 경고)는 처음 표시할 때와 재시뮬레이션으로 바뀔 때마다 붙인다. 재시뮬레이션의 안정 부분 비교([03] §6.6-3)는 이 표시를 붙인 뒤에 한다(붙이기 전 초안과 비교하면 늘 "바뀜"이 되어 60초가 지난 승인마다 거짓 경고가 뜬다). 경고가 이미 64개면 가장 덜 심각한 것을 빼고 C0x 자리를 만든다. 그래도 붙이지 못하면(세션이 사라짐 등) 주장한 출처만 있는 창을 보이지 않고 E-UI-001로 요청을 거절한다.
- 승인 digest의 출처(`origin_serialized`)와 SIWE 도메인 검사는 **주장한 출처**를 쓴다(합성 출처로 검사하면 모든 SIWE가 S01로 막힌다). 대신 모든 WalletConnect 요청에 규칙을 붙인다: **C01 주의**(확인되지 않음), **C02 고위험**(Verify 불일치), **C03 고위험**(사기 표시), C04 정보(Verify 서버가 일치라고 알림 — 증명이 아님, 아래). 고위험은 승인 창의 확인 체크·길게 누르기를 요구한다.
- Verify(제안마다, 결과는 세션에 저장): ① 릴레이 메시지에 `attestation`(v3 JWT)이 있으면 `GET https://verify.walletconnect.org/v3/public-key`(만료까지 캐시)의 P-256 키로 ES256을 CNG(`BCRYPT_ECDSA_P256_ALG_HANDLE`)로 검증하고, `exp` > 지금, `id` = SHA-256(받은 암호문 문자열)일 때만 쓴다(`isVerified` 거짓 = 확인 불가). ② 아니면 `GET https://verify.walletconnect.org/attestation/{SHA-256(복호한 JSON)}?v2Supported=true` 200 `{origin, isScam}`. `isScam` → 사기, 증명된 출처 = 주장한 출처 → 일치(서버 알림), 다르면 불일치(2026-11-10: 이 지갑이 해석하지 못하는 출처 — http 비localhost·IPv6·확장 페이지·`null` — 도 주장한 URL의 바로 그 `scheme://authority`가 아니면 불일치; 참조 SDK도 `new URL(metadata.url).origin`과 다르면 INVALID), 답 없음·빈 출처 → 확인 불가. `metadata.verifyUrl`은 무시하고 공식 서버만 쓴다. HTTP 5초 제한.
- Verify `Valid`는 표시(C04·배지)에만 쓰고 권한을 넓히지 않는다: Hyperliquid L1 Agent 예외는 WalletConnect 요청에 열리지 않는다([11] §7, 2026-11-08 — 증명된 출처는 dApp 쪽 환경이 Verify 서버에 알린 값이라 브라우저 밖 dApp이 고를 수 있다). 같은 이유로 표시도 확인이 아니라 서버의 알림으로 쓴다(2026-11-10): 상태 이름 "일치(서버 알림)"(배지 "Verify 일치(서버 알림)", 이전 "확인됨"), 연결 창은 주의 톤으로 "Verify 서버는 이 연결이 사이트가 주장한 주소에서 시작되었다고 알렸습니다. 다만 브라우저 밖에서 도는 dApp은 이 결과를 꾸밀 수 있으니, 지금 직접 연 사이트에서 연결했는지 확인하세요.", C04는 "WalletConnect 요청 — Verify 서버는 사이트가 주장한 주소와 일치한다고 알렸지만, 브라우저 밖에서 도는 dApp은 이 결과를 꾸밀 수 있습니다"(정보 수준 그대로).
- 연결된 사이트(S13)에는 "WalletConnect 세션" 카드가 따로 나온다(이름, 주장한 주소, dApp이 확인하기 전이면 `상태: 연결 확인 중`(§5.3), Verify, 네트워크, 계정, 연결·만료 시각, `연결 해제`), 확장 사이트 목록에서는 빠진다. `모든 WalletConnect 세션 끊기`(2026-11-08부터 확인 오버레이 뒤, [04] §2.9), 기존 `모든 사이트 연결 해제`도 모든 WalletConnect 세션을 끊는다(2026-11-08: 세션마다 바로 `wc_sessionDelete`를 보내고, 확인 문구가 "WalletConnect 세션 n개도 끊습니다"라고 말한다).

## 8. 설정·저장

- `settings.json` `walletconnect: {"projectId": "<32자리 소문자 16진수>"}` — 비밀이 아니다(dApp은 웹 페이지에 넣는다). 기본값 없음(없으면 키를 쓰지 않고 WalletConnect는 꺼짐). **이 지갑에는 기본 Project ID가 없다**: 사용자가 dashboard.reown.com에서 무료 프로젝트를 만들고 ID를 붙여 넣는다. 그 프로젝트의 허용 출처(allowlist)는 비워 둔다(데스크톱 앱은 Origin을 보내지 않는다). 입력 자리는 S13 WalletConnect 카드다([04] §2.9: 없으면 "1단계: Reown Project ID 저장" 준비 카드, 있으면 값 한 줄과 `Project ID 바꾸기 ▸`; 비우고 저장하면 끈다).
- meta 선택 키 `walletconnect: {"clientSeed": hex, "sessions": [{topic, symKey, peerPublic, peer{name,description,url,icons}, accounts, chains, methods, events, expiry, acknowledged, verify, created}]}`. meta는 vault에서 나온 키로 봉인되므로 세션 키·릴레이 클라이언트 키는 평문으로 디스크에 닿지 않는다. 읽을 때 `topic ≠ SHA-256(symKey)`이거나 형식이 틀린 세션은 버리고, 만료된 세션은 복원하지 않는다. 이전 버전은 이 키를 모르는 키로 보존한다.
- 수명: 작업 스레드는 Project ID가 있는 상태로 처음 잠금 해제할 때 시작하고 세션을 받는다. 잠그면 세션·연결은 유지하되(키는 메모리에만), 들어오는 서명·연결 요청은 4100으로 거절한다(§5.2, 잠금 해제 창 없음). 앱을 켠 뒤 첫 잠금 해제 전에는 연결하지 않으며, 그동안 온 요청은 릴레이 우편함(TTL 안)에서 기다린다. 잠긴 동안 끝난 세션의 권한은 다음 세션 목록 동기화 때 지운다.
- 지갑 초기화(S22)는 잠근 뒤 작업 스레드를 멈추고 UI 상태를 비운다(옛 지갑의 세션·릴레이 키·연결이 새 지갑에 남지 않는다; 새 지갑의 첫 잠금 해제 때 새로 시작). 작업 스레드가 이미 받은 meta와 릴레이 클라이언트 키가 다른 `Load`를 받으면 살아 있는 상태(세션·제안·페어링·대기 응답·연결)를 버리고 새로 받는다. UI는 세션 목록 스냅숏의 클라이언트 키가 지금 meta의 키와 다르면 표시도 저장도 하지 않는다.

## 9. 범위 밖

- Solana(`solana:`), Bitcoin(`bip122:`) 등 EVM이 아닌 네임스페이스, `wc_sessionAuthenticate`(원클릭 인증/CACAO), 링크 모드, 푸시, 여러 세션의 한 페어링 재사용(새 연결은 새 URI), `eth_sign`·`eth_signTransaction`·`wallet_addEthereumChain`·`wallet_sendCalls` 등 확장도 지원하지 않는 메서드.
- 세션 요청마다의 Verify(연결 때 결과를 세션 전체에 쓴다).

## 10. 시험

- yw-core: 사양 URI 예시, v1·잘못된 relay·키 길이·중복 키 거부, **JWT 시험 벡터**(바이트 일치), RFC 7748 X25519 + HMAC으로 직접 계산한 HKDF, 봉투 왕복·변조 거부·타입 2 거부.
- yw-app: QR 6개 시험(§6), CF_DIB 24/32비트, RFC 7515 ES256(CNG), Verify 판정 규칙(해석 못 하는 증명 출처 = 불일치 포함)·공개키 형식, 창 없는 거절의 알림과 미확인 세션(`proposal_refusals_say_why_and_unconfirmed_sessions_end`: Solana 전용 제안 5100·`NonEvmOnly`, 없는 필수 체인 이름, 제안 없이 만료된 페어링, settle 오류 → 삭제, 확인 없음 → `SETTLE_ACK_S` 뒤 끊김(릴레이로 나가기 전에는 시계가 돌지 않음), 확인된 세션은 유지, 세션 토픽의 `wc_pairingDelete` 무시, 지난 `expiryTimestamp` 8000), 큐의 WalletConnect 요청(`app_browser::walletconnect_requests_end_with_their_window_and_at_lock`: 답 없이 끝난 요청이 같은 세션의 대기 요청을 데려감, 잠금이 대기 WalletConnect 요청을 끝내고 잠금 해제 창은 확장 요청에만), 출처·라벨·CAIP-2(여러 줄 이름·형식이 틀린 URL 주입, 경고 64개일 때 C0x 자리), 제안 키(두 페어링의 같은 id, 세션 토픽으로 승인·거절, 거절 뒤 15초 대기), 페어링 수명·제안 수·세션 뒤 은퇴·가득 찬 대기 목록(`pairings_are_short_lived_and_bounded`), 이름 허용 목록(`proposal_names_are_allowlisted`), 지운·막힌 체인 거절과 세션 체인 정리(`session_chains_follow_the_registry`), 복원된 세션의 권한 따르기(`restored_sessions_follow_grants_and_chains`: 권한 없는 세션은 `Load`에서 삭제, 계정 숨김 → 업데이트 + `accountsChanged`, `eth_accounts`는 권한에서, 권한 제거 → 삭제, 지운 체인 → 업데이트·5100), 그리고 **모의 종단 시험**(모의 릴레이 + 독립적으로 키를 유도하는 모의 dApp): 페어링 → 제안(체인 137은 미등록이라 빠짐, `eth_sign`은 미지원 표시) → 연결 창 요청 → settle의 CAIP-10 계정 → `personal_sign`(`expiryTimestamp` = 지금 + 5분, 참조 SDK처럼)이 디스패처 큐에 요청 체인과 그 기한으로 도착(더미 값으로 응답, 실제 서명 없음) → `eth_chainId` 0x1 → `eth_sign` 4200 → 세션에 없는 체인 5100 → ping → meta 저장 왕복 → 연결 해제 6000.
- 실제 릴레이 확인(`tests/walletconnect_live.rs`, `#[ignore]`): `YW_WC_PROJECT_ID`가 있으면 두 클라이언트로 구독·발행·수신 왕복, 없으면 지어낸 ID로 연결해 403(JWT 통과)인지 본다. 2026-11-06 실행: 403.
- 수동(사용자): Project ID를 저장하고, 실제 dApp(예: app.uniswap.org → 지갑 연결 → WalletConnect → 링크 복사)에서 연결, 테스트넷에서 메시지 서명·거래 승인 창의 출처 표시·Verify 상태, 잠금 중 요청이 창 없이 거절되는지, 앱 재시작 후 세션 유지, `연결 해제`가 dApp 쪽에서 끊기는지 확인. 기록: [docs/acceptance/wc-zec-phrases-yk-20261110.md](../docs/acceptance/wc-zec-phrases-yk-20261110.md) WC-01–WC-08(`클립보드에서 연결`, 거절 알림, `연결 확인 중`과 확인 없는 세션 끊기, Verify 줄, 잠금 중 거절 알림, 백업 확인 전 계정 태그·거절 알림).
