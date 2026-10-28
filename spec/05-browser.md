# 브라우저 연동

상위 문서: [spec.md](../spec.md)

관련 문서: [01](01-repo-build.md)(크레이트·yw-json·yw-win·검사), [02](02-core-keys-vault.md)(meta 형식), [03](03-evm.md)(EVM 검증·서명·시뮬레이션·SIWE), [04](04-app-ui.md)(창·설정·파일 위치), [09](09-testing.md)(판정 기준).

이 문서는 D3, D14(dApp 쪽 체인 규칙), D15–D16(dApp 응답 부분), D22–D24, D30(잠김 동작)을 구현 수준으로 정한다. 확장 코드는 `extension/`을 제자리에서 고친다(main과 `archive/spec-v2.4`의 `extension/`은 동일). 이식 출처는 `archive/spec-v2.4:<path>:<lines>`로 적는다.

---

## 1. 개요와 신뢰 경계
```
page ──window.ethereum / EIP-6963──▶ provider-main.js (MAIN world)
     ──window.postMessage(channel)──▶ content.js (ISOLATED)
     ──runtime port "your-wallet-content-v1"──▶ background.js (MV3 service worker)
     ──connectNative("com.your_wallet.native")──▶ yw-host.exe   (stdio, 4B LE 길이 + JSON)
     ──\\.\pipe\YourWallet.v3.<SID>──▶ yw-app.exe                (같은 프레이밍)
```

| 구성 | 신뢰 | 하는 일 | 하지 않는 일 |
|---|---|---|---|
| 페이지·dApp | 적대적 | 요청 | — |
| `provider-main.js` | 페이지와 같은 world. 신뢰하지 않음 | EIP-1193/6963 API, 요청 id·타이머 | 정책·메서드 판단 |
| `content.js` | 확장(ISOLATED) | 메서드 허용 목록·크기 검사, 재연결 | 권한 판단 |
| `background.js` | 확장 | `port.sender`에서 origin 도출, 한도·기한·취소, native 연결 | 계정·권한 저장 |
| `yw-host.exe` | 비밀 없는 중계 | 길이 검사, pipe 중계, yw-app 실행(`browserAutoLaunch`, §7.4) | 메시지 해석(예외: §7.6) |
| `yw-app.exe` | 정본 | 봉투·파라미터·권한 검증, 승인 창, RPC, 서명 | — |

규칙:

- 확장과 yw-host는 **신뢰하지 않는 중계**다. yw-app은 확장이 계산한 `route`, origin 형식, 파라미터를 반드시 다시 검증한다. 확장 쪽 검사는 조기 거부와 자원 보호용이다.
- origin은 background가 Chrome의 `port.sender`에서 도출한 값만 쓴다. 페이지가 보낸 값은 쓰지 않는다. 같은 사용자 권한의 프로세스가 stdin·pipe를 위조하는 경우는 spec.md §2.2 비목표다.
- 연결·서명 승인은 yw-app 네이티브 창에서만 한다. 승인 창 내용은 yw-app이 payload에서 직접 만든다([03](03-evm.md), [04](04-app-ui.md)).
- 페이지 브리지(window.postMessage, 채널 nonce)는 같은 페이지의 다른 스크립트가 읽고 위조할 수 있다. 보안 경계로 보지 않는다.
- 로그(D28): 메서드 이름, route, 오류 코드, 소요 시간, 연결 번호만 기록한다. origin, 파라미터, 결과, 주소는 기록하지 않는다.

---

## 2. 확장 변경
### 2.1 파일별 변경 요약
| 파일 | 변경 |
|---|---|
| `manifest.json` | §2.2 내용으로 교체(이름, 버전 0.3.0, `key`, localhost 매치, 호환 모드 팝업 `action`) |
| `popup/popup.html`, `popup/popup.css`, `src/popup.js`, `src/popup-core.js` | 신규. 호환 모드 액션 팝업(§2.12) |
| `extension-id.txt` | 신규. 32자 a–p ID + LF. `scripts/extension-key.mjs generate`가 만든다(§2.3) |
| `package.json` | `version` → `0.3.0`. 스크립트는 `"test": "node --test tests/*.test.mjs"` 유지 |
| `src/shared.js` | 메서드 표 단일 정본(§3.1), `REQUEST_LIMITS`/`RESPONSE_LIMITS`·`checkJson`(§2.9), `isSupportedPageUrl`, 새 메시지 파서(§2.6), 호환 모드 값(`COMPAT_MODES`, `normalizeCompatMode`, §2.12). 수명 상한 제거 |
| `src/provider-main.js` | 메서드 목록 삭제, EventEmitter API, `window.ethereum` 정책, rdns, 브리지 재사용, 시간 초과 시 cancel, 레거시 API `send`·`sendAsync`(§2.5), 호환 모드(§2.12) |
| `src/content-core.js`, `src/content.js` | IDLE/CONNECTING/ACTIVE/DEAD 상태 기계로 재작성, 지연 연결·재연결, cancel 전달(§2.7), 시작 시 호환 모드 읽기(§2.12) |
| `src/background-core.js` | 수명 상한 제거, 토큰 버킷, 기한 타이머, cancel, native 재연결 backoff, native 끊김 시 문서 유지(§2.8), `context.compatMode`·팝업 상태(§2.12) |
| `src/background.js` | `fatal` 메시지 삭제. 외부 연결 리스너 등록 금지(§2.8). 팝업 포트 응답(§2.12) |
| `native-host/*.golden.json` | §10.3 목록으로 갱신·추가 |
| `native-host/validate-manifest.mjs` | 이름 변경 `validateNativeManifest`, CLI 추가, cmd 메타문자 거부(§9.3) |
| `native-host/README.md` | §9 절차 요약으로 교체 |
| `native-host/com.your_wallet.native.json.template` | `description`만 `"Your Wallet native messaging host"`로 변경. 테스트 픽스처로만 유지 |
| `tests/*` | §10.1 |

### 2.2 manifest.json (최종)
`key` 값만 생성 결과로 채운다. 그 밖의 내용은 아래와 같아야 한다(값 비교, 키 순서 무관, 테스트 M1). `action`은 호환 모드 팝업(§2.12)이며 아이콘은 두지 않는다(Chrome이 이름 첫 글자를 표시).

```json
{
  "manifest_version": 3,
  "name": "Your Wallet",
  "version": "0.3.0",
  "description": "Connects web pages to the local Your Wallet app.",
  "minimum_chrome_version": "120",
  "incognito": "not_allowed",
  "key": "<base64 DER SubjectPublicKeyInfo, RSA-2048, 392 chars>",
  "permissions": ["nativeMessaging", "storage"],
  "background": { "service_worker": "src/background.js", "type": "module" },
  "action": { "default_title": "Your Wallet", "default_popup": "popup/popup.html" },
  "content_scripts": [
    {
      "matches": ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
      "js": ["src/provider-main.js"],
      "run_at": "document_start",
      "all_frames": false,
      "world": "MAIN"
    },
    {
      "matches": ["https://*/*", "http://localhost/*", "http://127.0.0.1/*"],
      "js": ["src/shared.js", "src/content-core.js", "src/content.js"],
      "run_at": "document_start",
      "all_frames": false,
      "world": "ISOLATED"
    }
  ]
}
```

- `host_permissions`, `optional_host_permissions`, `optional_permissions`, `externally_connectable`, `web_accessible_resources`, `content_security_policy`는 두지 않는다. 호환 모드(§2.12)도 `scripting`·호스트 권한 없이 동작한다.
- localhost 매치는 항상 주입한다. 허용 여부는 yw-app 설정 토글이 정한다(§4.6). 포트 없는 패턴이 모든 포트에 매치되는지는 §11-1에서 확인한다.
- `storage`(`chrome.storage.local`)는 두 키에만 쓴다: `profileInstallIdV1`(64 hex, background, `archive/spec-v2.4:extension/src/background.js:72-84` 유지)과 `compatMode`(`"off"`·`"metamask"`·`"rabby"`, 팝업이 쓰고 content script가 읽는다, §2.12).

### 2.3 manifest 키와 확장 ID
절차(M5 첫 작업, 1회):

1. `manifest.json`을 §2.2 내용(`"key"` 줄 제외)으로 바꾼 뒤 `node scripts/extension-key.mjs generate` 실행. RSA-2048 키쌍을 만들고 공개키 DER(SPKI)의 base64를 `manifest.json`의 `"incognito"` 다음 위치에 `"key"`로 넣고, ID를 `extension/extension-id.txt`에 쓴다. 개인키는 저장하지 않는다(CRX를 만들지 않으므로 쓸 곳이 없다).
2. 두 파일을 커밋한다. 이후 `generate`는 `key`가 이미 있으면 실패한다(`--force`로만 교체).
3. `chrome://extensions`에 표시된 ID가 `extension-id.txt`와 같은지 확인한다.

ID 규칙(Chrome): `id = map(hex(SHA-256(DER))[0..32])`, `map`은 16진 숫자 `0–9a–f`를 `a–p`로 바꾼다.

```js
// scripts/extension-key.mjs — Node 22+, 의존성 0
import { createHash, generateKeyPairSync } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

const MANIFEST = new URL("../extension/manifest.json", import.meta.url);
const ID_FILE = new URL("../extension/extension-id.txt", import.meta.url);

export function extensionIdFromKey(base64Key) {
  const der = Buffer.from(base64Key, "base64");
  if (der.length < 64 || der.toString("base64") !== base64Key) throw new Error("invalid key");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return Array.from(hex, (c) => String.fromCharCode(0x61 + Number.parseInt(c, 16))).join("");
}

function main(command, flag) {
  const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
  if (command === "generate") {
    if (Object.hasOwn(manifest, "key") && flag !== "--force") throw new Error("manifest already has key");
    const { publicKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048, publicKeyEncoding: { type: "spki", format: "der" } });
    const key = publicKey.toString("base64");
    const out = {};
    for (const [k, v] of Object.entries(manifest)) {
      if (k === "key") continue;
      out[k] = v;
      if (k === "incognito") out.key = key;
    }
    writeFileSync(MANIFEST, `${JSON.stringify(out, null, 2)}\n`);
    writeFileSync(ID_FILE, `${extensionIdFromKey(key)}\n`);
  } else if (command === "id") {
    process.stdout.write(`${extensionIdFromKey(manifest.key)}\n`);
  } else if (command === "check") {
    const expected = readFileSync(ID_FILE, "utf8").trim();
    if (!/^[a-p]{32}$/u.test(expected) || extensionIdFromKey(manifest.key) !== expected) throw new Error("id mismatch");
  } else throw new Error("usage: extension-key.mjs generate [--force] | id | check");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main(process.argv[2], process.argv[3]); } catch (e) { console.error(String(e.message)); process.exit(1); }
}
```

Rust 쪽 고정값: yw-host와 yw-app은 같은 파일을 컴파일 시점에 포함한다.

```rust
// crates/yw-host/src/lib.rs (테스트가 쓰므로 lib에 둔다; yw-app은 crates/yw-app/src/browser/mod.rs에서 상대 경로만 다름)
const EXTENSION_ID_FILE: &str = include_str!("../../../extension/extension-id.txt");
fn pinned_extension_id() -> Option<&'static str> {
    let id = EXTENSION_ID_FILE.trim_end();
    (id.len() == 32 && id.bytes().all(|b| (b'a'..=b'p').contains(&b))).then_some(id)
}
// pinned origin = format!("chrome-extension://{id}/")
```

### 2.4 지원 페이지 규칙
같은 규칙을 네 곳에서 적용한다: `provider-main.js`(자체 사본), `shared.js isSupportedPageUrl`, background `deriveSenderContext`, yw-core `policy::BrowserOrigin::parse`(§4.7).

| 조건 | 결과 |
|---|---|
| 최상위 프레임이 아님(`window.top !== window`, `sender.frameId !== 0`) | 주입·연결 안 함 |
| `https:` | 지원 |
| `http:`이고 `hostname`이 정확히 `localhost` 또는 `127.0.0.1`(포트 무관) | 확장은 지원. yw-app은 토글이 꺼져 있으면 4100(§4.6) |
| 그 밖(`http:` 다른 호스트, `file:`, `data:`, IPv6 리터럴 등) | 주입·연결 안 함 |
| URL에 userinfo, `origin === "null"`, `sender.origin`과 URL origin 불일치, incognito, `documentLifecycle !== "active"` | background가 연결 거부(`archive/spec-v2.4:extension/src/background-core.js:526-568` 규칙 유지, 프로토콜 조건만 위 표로 교체) |

### 2.5 provider-main.js
상수: `REQUEST_TIMEOUT_MS = 605_000`(background 최장 기한 600 s + 5 s. provider에는 메서드 표가 없으므로 최댓값 하나만 쓴다, §6.4), `MAX_PENDING = 64`, `BRIDGE_WAIT_MS = 10_000`, `MAX_MESSAGE_BYTES = 1_048_576`. 삭제: `allowedMethods`, `MAX_REQUESTS`, `MAX_LISTENERS_PER_EVENT`, `window.yourWallet`, `yourWallet#initialized`.

**전역 등록**

- EIP-6963: 모드가 정해지는 순간(§2.12: 첫 유효 `bridge-init`, 또는 로드 후 `MODE_WAIT_MS = 10_000` 동안 없으면 `off`) 한 번, 그 뒤 `eip6963:requestProvider` 이벤트마다 항상 `eip6963:announceProvider`를 보낸다. 모드가 정해지기 전에 받은 `requestProvider`는 그 첫 알림으로 답한다(보통 document_start 뒤 수 ms). `info = Object.freeze({ uuid: <페이지마다 UUIDv4>, name: "Your Wallet", icon: <기존 PNG data URI>, rdns: "io.github.na-degen-girl.yourwallet" })`(기본 모드, 호환 모드의 이름·rdns는 §2.12). 재귀 방지(`archive/spec-v2.4:extension/src/provider-main.js:111-126`) 유지.
- `window.ethereum`(로드 시, 모드와 무관): `!("ethereum" in window)`일 때만 `Object.defineProperty(window, "ethereum", { value: provider, configurable: true, enumerable: true, writable: true })` 후 `window.dispatchEvent(new Event("ethereum#initialized"))`. 이미 있으면 건드리지 않는다. 예외는 삼킨다. 기본 모드는 이것으로 끝이고, 호환 모드는 모드가 정해질 때 §2.12 규칙으로 차지한다.

**provider 객체**: 확장 가능한(extensible) 일반 객체. 아래 멤버는 `writable:false, configurable:false`로 정의한다. 객체를 freeze하지 않는다(레거시 dApp의 속성 대입이 strict mode에서 실패하지 않도록).

| 멤버 | 동작 |
|---|---|
| `isYourWallet` | `true` |
| `isMetaMask` (getter) | 현재 모드가 `metamask`·`rabby`면 `true`, 아니면(`off`, 모드 확정 전) `false` |
| `isRabby` (getter) | 현재 모드가 `rabby`면 `true`, 아니면 `false` |
| `_metamask` (getter) | 호환 모드에서 `Object.freeze({ isUnlocked })`, 기본 모드에서 `undefined`(§2.12). `requestBatch` 없음 |
| `chainId` (getter) | 마지막으로 알게 된 chainId 문자열 또는 `null` |
| `selectedAddress` (getter) | 마지막 계정 목록의 첫 항목 또는 `null` |
| `isConnected()` | 채널 확보 && DEAD 아님 |
| `request(args)` | 아래 |
| `enable()` | `request({ method: "eth_requestAccounts" })`(레거시 API, 아래) |
| `send(…)` / `sendAsync(payload, cb)` | 레거시 API(아래) |
| `on(e, fn)` / `addListener(e, fn)` | 등록, `provider` 반환. `fn`이 함수가 아니면 `TypeError`. 알 수 없는 이벤트 이름은 아무것도 하지 않고 `provider` 반환 |
| `once(e, fn)` | 1회 호출 후 제거. `off(e, fn)`으로 원래 `fn`을 넘겨도 제거된다 |
| `off(e, fn)` / `removeListener(e, fn)` | 제거, `provider` 반환 |
| `removeAllListeners(e?)` | `e` 생략 시 전체 제거 |
| `listenerCount(e)` | 수 반환 |

이벤트(이 다섯 이름만 지원, 리스너 수 상한 없음, 리스너 예외는 삼킴):

| 이벤트 | 발생 조건 | 인자 |
|---|---|---|
| `connect` | 연결 구간에서 chainId를 처음 알게 될 때(eth_chainId 결과 또는 `chainChanged`) 1회 | `{ chainId }` |
| `disconnect` | DEAD(확장 재로드)일 때만. 일시적 연결 끊김에는 보내지 않는다 | `ProviderRpcError(4900, "Wallet extension was reloaded.")` |
| `accountsChanged` | native 이벤트 | `string[]`(소문자 주소) |
| `chainChanged` | native 이벤트 | `"0x…"` |
| `message` | 보내지 않음(`eth_subscribe` 미지원). 등록은 허용 | — |

**request(args)**

1. `args`가 일반 객체가 아니거나 `typeof args.method !== "string"`이거나 `method`가 `^[A-Za-z0-9_]{1,96}$`가 아니면 4200 "Unsupported method.". `args`의 다른 키(`id`, `jsonrpc` 등)는 무시한다.
2. `params` 생략 → `[]`. 배열·일반 객체가 아니면 -32602 "Invalid params.".
3. 메서드 허용 여부는 판단하지 않는다(content가 shared.js 표로 판단).
4. 채널이 없으면 최대 `BRIDGE_WAIT_MS` 기다린다. 그래도 없으면 4900 "Wallet connection closed.". DEAD면 4900 "Wallet extension was reloaded.".
5. pending ≥ 64 → -32005 "Too many pending requests.". `JSON.stringify` 실패 또는 UTF-8 크기 > 1 MiB → -32600 "Request too large.".
6. `id = 16바이트 무작위 hex`로 page request(§2.6) 전송, `REQUEST_TIMEOUT_MS` 타이머 시작. 시간 초과 시 -32603 "Request timed out."으로 거부하고 page `cancel`을 보낸다.
7. 결과 수신 시 `eth_accounts`/`eth_requestAccounts` 결과로 `selectedAddress`, `eth_chainId` 결과로 `chainId`를 갱신한다.

**레거시 API**(`enable`·`send`·`sendAsync`, `request` 이전 MetaMask API만 쓰는 오래된 dApp용): 모든 모드(모드 확정 전 포함)에 같은 멤버로 둔다. 표시 방식(§2.12)과 무관한 EIP-1193 레거시 표면이고, 멤버는 non-configurable이라 모드에 따라 넣고 뺄 수 없다. 각 shim은 위 `request`만 부르므로 메서드 표·권한·크기·pending·rate 한도·오류 코드(§5)가 `request`와 정확히 같다. 새 권한이나 다른 전달 경로는 없다.

| 호출 | 동작 |
|---|---|
| `enable()` | `request({ method: "eth_requestAccounts" })` |
| `send(method: string, params?)` | `request({ method, params })`를 그대로 반환(결과값으로 resolve, `request` 오류로 reject). `params`가 배열·일반 객체가 아니면 -32602 |
| `send(payload, callback)`(`callback`이 함수) | `sendAsync(payload, callback)`, 반환 `undefined` |
| `send(payload)`(그 밖) | 동기 응답 `{ id: payload.id, jsonrpc: "2.0", result }`. I/O 없이 provider가 이미 아는 값만 쓴다: `eth_accounts` → `selectedAddress`가 있으면 `[selectedAddress]`(새 배열), 없으면 `[]`. `eth_coinbase` → `selectedAddress`(없으면 `null`). `net_version` → 캐시된 `chainId`의 10진 문자열(없으면 `null`). 그 밖 메서드(`eth_uninstallFilter` 포함, 필터 미지원)는 `Error`(코드 없음. 호출 방식 오류라 §5 응답이 아니다)를 던지고 아무것도 보내지 않는다 |
| `sendAsync(payload, callback)` | `request({ method: payload.method, params: payload.params })`. 성공 `callback(null, { id, jsonrpc: "2.0", result })`, 실패 `callback(error, { id, jsonrpc: "2.0", error: { code, message, data? } })`. `error`는 `request`가 거부한 `ProviderRpcError`, `data`는 있을 때만, 그 밖 예외는 `{ code: -32603, message: "Internal error." }`. `id`는 그대로(없으면 `undefined`), `payload`의 다른 키(`jsonrpc` 등)는 무시 |
| `sendAsync([payload, …], callback)`(배치) | 원소를 모두 먼저 검사한 뒤 각각 `request`로 보내고, 모두 끝나면 `callback(null, [응답, …])` 1회(payload 순서, 원소 오류는 그 응답의 `error`). 빈 배열 → `callback(null, [])`. 배치 전용 한도는 없다(pending 64 등 `request` 한도가 원소마다 적용) |

- 검사: `callback`이 함수가 아니거나, `payload`(배치 원소 포함)가 배열이 아닌 객체가 아니거나 `typeof payload.method !== "string"`이면 아무것도 보내기 전에 `TypeError`를 동기로 던진다. method 형식·params 형식 오류는 `request` 규칙(4200·-32602)대로 콜백의 오류 응답이 된다.
- 콜백: 항상 호출이 반환된 뒤(비동기) 정확히 1회 부른다. 콜백이 던진 예외는 provider가 잡아 로드 시 잡아 둔 `window.reportError`로 알리고(콘솔에 미처리 오류로 보임) 그 밖에는 무시한다. provider 상태·다른 요청·리스너에 영향이 없다.

**브리지**: 시작 시 page `bridge-request`를 보낸다. `bridge-init`은 정확한 키 집합(§2.6, `compatMode` 포함)이고 `compatMode`가 세 값 중 하나일 때만 유효하다. 채널이 없을 때 받아들여 채널과 모드(아직 정해지지 않았다면)를 정하고, 같은 채널 값이면 다시 받아도 무시하고(모드도 바뀌지 않는다), 다른 채널 값이면 무시한다. 수신 메시지는 `event.source === window && event.origin === location.origin`인 것만 본다.

### 2.6 확장 내부 메시지 (정확한 키 집합, 모든 메시지에 `namespace:"your-wallet"`, `version:1`)
| 방향 | kind | 나머지 키 |
|---|---|---|
| page→content | `bridge-request` | (없음) |
| page→content | `request` | `channel`, `id`(32 hex), `method`, `params` |
| page→content | `cancel` | `channel`, `id` |
| content→page | `bridge-init` | `channel`(64 hex), `compatMode`(`"off"`\|`"metamask"`\|`"rabby"`, §2.12) |
| content→page | `response` | `channel`, `id`, `result` \| `error` |
| content→page | `event` | `channel`, `event`, `payload` |
| content→page | `disconnect` | `channel`, `error` (DEAD 진입 시 1회) |
| content→bg | `request` | `activationNonce`, `id`, `method`, `params`, 선택 `compatMode`(`"metamask"`\|`"rabby"`만, 기본 모드에서는 키 없음. `"off"`·그 밖 값은 형식 오류) |
| content→bg | `cancel` | `activationNonce`, `id`, `reason`(`^[A-Za-z0-9_-]{1,128}$`) |
| content→bg | `disconnect` | `activationNonce`, `reason` |
| bg→content | `activated` | `activationNonce`(64 hex) |
| bg→content | `response` | `activationNonce`, `id`, `result` \| `error` |
| bg→content | `event` | `activationNonce`, `event`, `payload` |

삭제: bg→content `disconnect`, `fatal`. background가 문서를 끊을 때는 port를 닫는다.

팝업 포트 `your-wallet-popup-v1`(§2.12): popup이 연결하면 bg가 `{ namespace, version: 1, kind: "status", native: "connected"|"checking"|"unavailable"|"unknown" }`(정확한 키) 하나를 보낸다. popup은 아무것도 보내지 않는다.

`error` 형식(모든 구간 공통): `{ code: 안전 정수, message: 1–512 UTF-16 단위, data?: JSON }`, 정확한 키 집합.

### 2.7 content 상태 기계
상수: `MAX_PENDING = 64`, `CONNECT_TIMEOUT_MS = 5_000`, `MIN_RECONNECT_INTERVAL_MS = 250`, `MODE_READ_TIMEOUT_MS = 3_000`. 채널 nonce는 문서 수명 동안 하나(`randomHex(32)`)다. content는 document_start에 `chrome.storage.local.get("compatMode")`로 모드를 한 번 읽고(§2.12, 실패·형식 오류·3 s 초과는 `off`) 그 즉시 bridge를 만들어 `bridge-init`을 보내며, 이후 `bridge-request` 수신마다 다시 보낸다. 모드는 문서 수명 동안 고정이다. port는 **첫 요청 때** 연다(모든 https 페이지에서 service worker와 yw-app을 깨우지 않기 위해).

| 상태 | 사건 | 동작 → 다음 상태 |
|---|---|---|
| 모든 상태 | page `request`가 형식 오류 | 무시 |
| 모든 상태 | `shared.methodRoute(method) === null` | 4200 응답(연결하지 않음) |
| 모든 상태 | 메시지가 `REQUEST_LIMITS` 초과 | -32600 "Request too large." |
| 모든 상태 | pending ≥ 64 | -32005 "Too many pending requests." |
| 모든 상태 | 같은 id가 pending 중 | 무시(응답 없음) |
| IDLE | 유효 요청 | 큐에 넣고 port 열기(직전 열기 후 250 ms 미만이면 지연), 5 s 타이머 → CONNECTING. `chrome.runtime.connect`가 예외 → DEAD |
| CONNECTING | 유효 요청 | 큐에 넣음 |
| CONNECTING | `activated` | nonce 저장, 큐를 순서대로 전송, 타이머 해제 → ACTIVE |
| CONNECTING | 5 s 경과 | port 닫기, 큐 전부 4900 "Wallet connection closed." → IDLE |
| ACTIVE | 유효 요청 | 전송 |
| ACTIVE | bg `response`/`event` | 형식·`RESPONSE_LIMITS` 검사 후 페이지로 전달. 이벤트 이름은 `accountsChanged`·`chainChanged`만 |
| CONNECTING/ACTIVE | port `onDisconnect` | pending·큐 전부 4900 "Wallet connection closed." → IDLE. 단 `chrome.runtime?.id === undefined`면 DEAD |
| CONNECTING/ACTIVE | page `cancel` | 큐에 있으면 제거. 전송했으면 bg `cancel`(reason `page-cancel`) 후 pending에서 제거. 페이지에 응답하지 않음 |
| CONNECTING/ACTIVE | 브라우저의 `pagehide` 또는 `freeze`(`event.isTrusted === true`만; 페이지가 `dispatchEvent`로 만든 이벤트는 무시) | bg `disconnect`(reason `document-pagehide`/`document-freeze`), port 닫기, pending 4900 "Wallet connection closed." → IDLE |
| DEAD | 진입 | pending 전부 4900 "Wallet extension was reloaded.", page `disconnect` 1회 |
| DEAD | 요청 | 4900 "Wallet extension was reloaded." |

- 리스너는 `{ once: true }` 없이 등록한다. `beforeunload`에는 반응하지 않는다(사용자가 취소할 수 있다). bfcache 복원 후 다음 요청이 다시 연결한다.
- `content-core.js`의 `ContentBridge`는 Chrome API 없이 테스트할 수 있게 어댑터를 받는다: `new ContentBridge({ channelNonce, compatMode = "off", connectPort, postToPage, isContextValid, setTimer, clearTimer, now })`. `connectPort()`는 `{ postMessage, disconnect, onMessage(fn), onDisconnect(fn) }`를 돌려준다. 모드 읽기는 `loadCompatMode({ readStorage, setTimer, clearTimer })`(거부하지 않는 Promise)다.

### 2.8 background router
상수(`background-core.js`): `CONTENT_PORT_NAME = "your-wallet-content-v1"`, `NATIVE_HOST_NAME = "com.your_wallet.native"`, `READ_DEADLINE_MS = 60_000`(route `read`), `INTERACTIVE_DEADLINE_MS = 600_000`(route `permission`·`signing`, 잠금 해제·검토 포함, D23), `MAX_ACTIVE_DOCUMENTS = 128`, `MAX_GLOBAL_PENDING = 512`, `MAX_PENDING_PER_DOCUMENT = 64`, `RATE_PER_SECOND = 40`(문서별 토큰 버킷 충전), `RATE_BURST = 80`(용량·초기값), `NATIVE_BACKOFF_BASE_MS = 1_000`, `NATIVE_BACKOFF_MAX_MS = 30_000`. 삭제: `MAX_NATIVE_CONNECTION_ATTEMPTS`, `seenIds`, `respondedIds`, `shared.MAX_REQUESTS_PER_ACTIVATION`.

**activation**: content port 하나 = activation 하나(`activationNonce`, `channelNonce`는 `randomHex(32)`, 기존 `issuePortNonce` 유지). `MAX_ACTIVE_DOCUMENTS`에 도달하면 pending이 0인 activation 중 마지막 사용이 가장 오래된 것의 port를 닫는다. 그런 것이 없으면 새 port를 즉시 닫는다.

**content 요청 처리 순서**

1. 형식 오류 → 무시(activation 유지). `id`가 이미 pending → 무시.
2. `shared.methodRoute` → `null`이면 4200.
3. 토큰 버킷 부족 → -32005 "Rate limit exceeded.". pending 한도 → -32005 "Too many pending requests.".
4. backoff 중(`now < nativeRetryAt`) → 4900 "Wallet is unavailable.".
5. native 연결이 없으면 연다(`connectNative` 예외 → 4900 "Wallet is unavailable." + backoff 갱신).
6. §6.1 request 봉투 생성. content 요청에 `compatMode`가 있으면 그 요청의 `context`에만 `compatMode`를 더한다(activation의 context는 바꾸지 않는다, §2.12). `checkJson(envelope, REQUEST_LIMITS)` 실패 → -32600 "Request too large.".
7. 전송 후 pending 등록, route 기한(`READ_DEADLINE_MS` 또는 `INTERACTIVE_DEADLINE_MS`)으로 `setTimeout` 시작. 만료 시 content에 -32603 "Request timed out." 응답, native `cancel`(reason `deadline`).

**cancel/disconnect**: content `cancel` → pending이면 타이머 해제, 제거, native `cancel`(reason `page-cancel`). content `disconnect` 또는 port 끊김 → 그 activation의 pending 모두 native `cancel`(reason은 받은 값, 없으면 `content-port-disconnect`) 후 activation 삭제.

**native 수신**: `checkJson(msg, RESPONSE_LIMITS)`, 정확한 키 집합(§6.1), `sessionId` 일치, `sequence === last + 1`. 위반 또는 알 수 없는 `kind`, 이벤트 이름이 `accountsChanged`·`chainChanged`가 아님, payload 형식(`accountsChanged`: `^0x[0-9a-f]{40}$` 문자열 0–16개 배열(grant 계정 한도, §4.1), `chainChanged`: `^0x[1-9a-f][0-9a-f]*$`)이 틀림 → native 연결만 끊는다(`dropNativeConnection`). response는 `(activationNonce, requestId)`로 pending을 찾고 `requestSequence`가 같을 때만 전달한다. 없으면 버린다.

**native 연결 끊김**(port `onDisconnect`, drop 포함): 모든 pending에 4900 "Wallet connection closed." 응답, 타이머 해제. **activation은 유지한다**(기존 `cancelAllPending`이 문서를 죽이던 버그 수정). 다음 요청이 새로 연결한다. 연결마다 새 `sessionId = randomHex(32)`, 송신 `sequence`는 0부터 다시 센다.

**backoff**: 연결마다 `healthy = false`로 시작하고, 4900이 아닌 response 또는 event를 하나라도 받으면 `true`. 끊길 때 `healthy`면 `failures = 0`, 아니면 `failures += 1`과 `nativeRetryAt = now + min(NATIVE_BACKOFF_BASE_MS × 2^(failures−1), NATIVE_BACKOFF_MAX_MS)`.

**background.js**: router 초기화(`profileInstallId` 로드) 실패 시 그 port를 닫는다(content는 일시 끊김으로 처리). `chrome.runtime.onConnectExternal`, `onMessageExternal`, `onMessage`는 등록하지 않는다(팝업도 `onConnect`의 이름 있는 port를 쓴다, §2.12). `onSuspend`에서 native 연결만 닫는다.

### 2.9 JSON 한도 (JS와 Rust가 정확히 같아야 함)
| 프로필 | 적용 구간 | maxBytes | maxDepth | maxNodes | maxItems |
|---|---|---|---|---|---|
| `REQUEST` | page→content, content→bg, bg→native, yw-app 수신 프레임 | 1,048,576 | 32 | 8,192 | 4,096 |
| `RESPONSE` | yw-app 송신 결과, native→bg, bg→content | 1,048,576 | 32 | 262,144 | 262,144 |

`RESPONSE`가 큰 이유: `eth_getLogs`·`eth_getBlockByNumber(…, true)` 결과는 1 MiB 안에서 노드가 수만 개다. 크기 상한(1 MiB)이 실제 비용 상한이다.

정의(`archive/spec-v2.4:crates/native-host/src/lib.rs:84-91,253-405`의 집계 방식과 같다):

- **depth**: 스칼라 0, 컨테이너는 1 + 자식 최댓값. 루트 객체만 있으면 1. `depth > maxDepth`면 거부.
- **nodes**: 모든 값(루트 포함)의 수 + 모든 객체 키의 수(문서 전체 합계).
- **items**: 모든 배열 원소 수 + 모든 객체 멤버 수(문서 전체 합계).
- **bytes**: JS는 `JSON.stringify` 결과의 UTF-8 길이, Rust는 프레임 길이.
- 문자열·키는 올바른 UTF-16(JS `isWellFormed()`)/UTF-8이어야 한다. 숫자는 유한해야 한다. 일반 객체(`Object.prototype` 또는 `null` 프로토타입)만 허용. Rust는 중복 키를 거부한다.

```js
// shared.js
function checkJson(value, limits) {
  let nodes = 0, items = 0;
  const walk = (v, depth) => {
    if (++nodes > limits.maxNodes) return false;
    if (v === null || typeof v === "boolean") return true;
    if (typeof v === "number") return Number.isFinite(v);
    if (typeof v === "string") return v.isWellFormed();
    if (depth + 1 > limits.maxDepth) return false;
    if (Array.isArray(v)) {
      for (const e of v) if (++items > limits.maxItems || !walk(e, depth + 1)) return false;
      return true;
    }
    if (!isPlainObject(v)) return false;
    for (const k of Object.keys(v)) {
      if (++items > limits.maxItems || ++nodes > limits.maxNodes || !k.isWellFormed()
        || !walk(v[k], depth + 1)) return false;
    }
    return true;
  };
  if (!walk(value, 0)) return false;
  let text;
  try { text = JSON.stringify(value); } catch { return false; }
  return typeof text === "string" && new TextEncoder().encode(text).byteLength <= limits.maxBytes;
}
```

yw-json은 같은 정의의 `yw_json::Limits { max_bytes, max_depth, max_nodes, max_items }`를 파서 인자로 받아야 한다([01](01-repo-build.md)). 경계 사례는 공유 골든 `v1-limits.golden.json`(§10.3)으로 양쪽에서 검사한다.

### 2.10 버그 대응표
| 버그(`s_extension` 감사) | 위치 | 수정 | 회귀 테스트 |
|---|---|---|---|
| service worker 재시작·native 종료 후 provider 영구 사망 | `archive/spec-v2.4:extension/src/content.js:11,70-74`, `provider-main.js:232-244,312-325`, `background-core.js:420-445` | 지연 연결·재연결(§2.7), 같은 채널 재사용(§2.5), native 끊김 시 activation 유지(§2.8) | §10.1 C1–C4, B6 |
| 수명 4,096 상한 | `shared.js:11`, `provider-main.js:11,143-149`, `content-core.js:58-62`, `background-core.js:19,131-136,224-226`, `crates/native-host/src/wire.rs:32,536-538` | 삭제. pending 상한 + 토큰 버킷 + backoff | B1, B2, R-D1 |
| 요청 하나의 오류가 문서·스트림 전체를 끊음 | `background-core.js:89-142,269-289`, `content-core.js:54-61`, `background.js:46-58`, `wire.rs:355-359,532-554,686,826` | 요청 단위 오류(§5). native 쪽 오류는 native 연결만 끊음 | B3, B4, R-D2 |
| 취소 미전파·기한 타이머 없음 | `provider-main.js:166-183`, `background-core.js:315-322`, `wire.rs:562-564` | page `cancel`, bg 기한 타이머 + native `cancel`, yw-app 비동기 디스패처(§8.4) | P5, B5, R-D3 |
| JS(깊이 64, 10,000)와 Rust(32, 8,192, 4,096) 한도 불일치 | `shared.js:77-96`, `provider-main.js:386-402`, `native-host/src/lib.rs:84-91` | §2.9 단일 정의 + 공유 골든 | S2, R-J1 |
| `window.ethereum` 비구성 가능·덮어쓰기 경쟁 | `provider-main.js:80-105,335-352` | §2.5 등록 규칙 | P1, P2 |
| EventEmitter API 부족, 미지원 이벤트에서 throw, `connect` 미발생 | `provider-main.js:186-197` | §2.5 멤버 표 | P3, P4 |
| rdns `com.yourwallet`(소유하지 않은 도메인) | `provider-main.js:99` | `io.github.na-degen-girl.yourwallet` | P1 |
| 메서드 목록 3중 사본 | `shared.js:15-44`, `provider-main.js:19-48`, `crates/broker/src/lib.rs:50-225` | provider 사본 삭제. JS 정본 `shared.js`, Rust 정본 `yw_core::policy::Method`, 둘 다 `v1-methods.golden.json`과 비교 | S1, R-M1 |
| manifest `key` 없음(ID가 폴더 경로에 따라 바뀜) | `manifest.json:1-42` | §2.2–2.3 | M1, M2 |
| native 이벤트 인코더 없음 | `wire.rs` 전체 | yw-app `encode_event`(§6.5) | R-E2 |

### 2.11 audit-extension.mjs
spec.md §6에 따라 유지한다. 이동·정리는 [01](01-repo-build.md) §4.4가 M0에 한다: `release-manifest.mjs` 의존은 `scripts/lib/strict-json.mjs`(`parseStrictJson`·`decodeUtf8`)로 옮기고 `canonicalEncode`·evidence(해시 출력) 모드는 삭제, CLI는 `check`만. M5에서 같은 커밋으로 바꿀 점: manifest 최상위 키 허용 집합에 `key` 추가, `name` 정확히 `"Your Wallet"`, 두 content script의 `matches`를 §2.2의 세 패턴으로 고정, 통과 시 확장 ID 출력([01] §4.4). 금지 패턴 검사(eval, `Function`, 동적 `import()`, `fetch`, `innerHTML`, URL 리터럴 등)는 그대로 둔다.

호환 모드(§2.12)에서 더한 점: 최상위 키는 정확히 §2.2의 11개(`action` 포함). `action`은 정확히 `{ default_title: "Your Wallet", default_popup: "popup/popup.html" }`. `popup/` 폴더는 정확히 `popup.html`·`popup.css` 두 일반 파일. `popup.html`: `<script type="module" src="../src/<이름>.js"></script>` 형태만(내용 없는 것), 인라인 이벤트 처리기·`style` 속성·`<style>`·`iframe`/`object`/`embed`/`base`/`form`/`img` 등 삽입·이동 요소·`meta http-equiv`·scheme 있는 URL·`javascript:`/`data:` 등 scheme·protocol-relative URL 금지, `<link rel="stylesheet" href="popup.css">` 하나만. `popup.css`: `url(`·`@import`·`expression(`·scheme 있는 URL 금지. 팝업 script와 그 정적 import는 `src/`의 다른 파일과 같은 금지 패턴·"참조되지 않은 소스 금지" 검사를 받는다. 패키지 목록은 `manifest.json`, `popup/*`, `src/*` 순서.

### 2.12 호환 모드 (D22: MetaMask·Rabby처럼 보이기)
목적: MetaMask(또는 Rabby)만 지원하는 dApp에서도 연결·SIWE 로그인·서명이 Your Wallet으로 오게 한다. 모드는 표시 방식만 바꾼다. 메서드 표·권한·승인 창·origin 도출·비밀 경계(§1)와 레거시 API(`enable`·`send`·`sendAsync`, §2.5)는 모드와 무관하게 같다.

| 모드(`compatMode`) | 팝업 표시 | `isMetaMask` | `isRabby` | `_metamask` | EIP-6963 `info.name` / `rdns` | `window.ethereum` | 다른 확장 알림 가로채기 |
|---|---|---|---|---|---|---|---|
| `off`(기본) | 기본 (Your Wallet) | `false` | `false` | `undefined` | `Your Wallet` / `io.github.na-degen-girl.yourwallet` | 없을 때만 등록(§2.5) | 안 함 |
| `metamask` | MetaMask처럼 보이기 | `true` | `false` | `{ isUnlocked }` | `MetaMask` / `io.metamask` | 차지(아래) | `io.metamask`·`io.metamask.flask`·`io.rabby` |
| `rabby` | Rabby처럼 보이기 | `true` | `true` | `{ isUnlocked }` | `Rabby Wallet` / `io.rabby` | 차지(아래) | 같음 |

**저장과 전달**

- 팝업이 `chrome.storage.local`의 `compatMode`에 `"off"`·`"metamask"`·`"rabby"` 중 하나를 쓴다. 그 밖의 값·없음은 `off`.
- ISOLATED content script가 document_start에 그 키를 한 번 읽고(`MODE_READ_TIMEOUT_MS = 3_000`, 실패·초과는 `off`) `bridge-init`의 `compatMode`로 MAIN world에 넘긴다. 새 권한은 없다(`storage`는 이미 있음). MAIN world 동기 전달에는 `scripting` + 호스트 권한(동적 content script 등록)이 필요하므로 쓰지 않는다. 그 대가로 document_start 뒤 저장소 응답까지(보통 수 ms) **임시 구간**이 생긴다(아래 한계).
- 모드는 문서마다 한 번 정해진다: 첫 유효 `bridge-init`, 또는 로드 후 `MODE_WAIT_MS = 10_000` 동안 없으면 `off`. 이후 바뀌지 않는다. 팝업에서 바꾼 모드는 **다음 페이지 로드부터** 적용된다.
- 페이지는 `bridge-init`을 위조해 자기 페이지의 provider 표시만 바꿀 수 있다(§1: 브리지는 보안 경계가 아니다). yw-app에 가는 표시는 content가 저장소에서 읽은 값만 쓴다(content→bg `request`의 `compatMode`, page→content 메시지에는 모드가 없다).
- content→bg `request`에 `compatMode`(호환 모드일 때만) → background가 그 요청의 native `context.compatMode`(§6.1)로 옮긴다. yw-app은 엄격히 검사하고(값은 `"metamask"`·`"rabby"`만, 그 밖은 그 요청만 -32600) 연결 창·승인 창에 배지 `호환 모드: MetaMask`·`호환 모드: Rabby`를 더한다(§4.2). origin은 언제나 `port.sender`에서 도출한 실제 사이트 origin이다.

**`window.ethereum` 우선권(호환 모드)**: 모드가 정해질 때 접근자 속성으로 차지한다.

```js
Object.defineProperty(window, "ethereum", { get: () => provider, set: (_ignored) => {}, configurable: true, enumerable: true });
```

- getter는 항상 우리 provider를 돌려준다. setter는 받아서 무시한다: 다른 확장의 `window.ethereum = x`(MetaMask 방식)는 strict mode에서도 예외 없이 효과가 없다.
- `configurable: true`를 유지한다. `configurable: false`로 잠그면 뒤에 `Object.defineProperty(window, "ethereum", …)`를 부르는 다른 지갑 스크립트가 TypeError로 죽는다(다른 확장 기능 파손). 대신 다른 스크립트의 configurable 재정의는 성공하므로, 검문점(모드 확정, `eip6963:requestProvider`, `DOMContentLoaded`, `load`)마다 우리 접근자가 아니면 다시 차지한다(유한 횟수, 반복 타이머 없음). 소유자가 바뀌면 `ethereum#initialized`를 다시 보낸다.
- 우리보다 먼저 다른 지갑이 넣은 값: configurable(일반 대입으로 만든 속성 포함)이면 그대로 재정의한다. non-configurable이면 대입(`window.ethereum = provider`)만 시도한다. 대입을 캐시하는 setter(Rabby 방식)면 우리 provider가 보이고, 쓰기 불가면 그 지갑이 남는다(예외 없음, EIP-6963 알림은 그대로).
- 기본 모드: §2.5 규칙 그대로(없을 때만, 일반 데이터 속성). 차지·재차지·가로채기를 하지 않는다.

**EIP-6963**: 한 페이지에는 한 신원만 알린다. 호환 모드에서는 "Your Wallet" 알림을 **보내지 않고** 표의 호환 신원만 알린다(중복 목록·dApp이 엉뚱한 쪽을 고르는 일 방지). `uuid`는 페이지마다 하나(모드와 무관), 아이콘은 우리 PNG(다른 회사 로고를 복사하지 않는다).

**가로채기**: provider-main.js가 document_start에 `window.addEventListener("eip6963:announceProvider", intercept, true)`(capture)를 등록한다. window 대상 이벤트에서 capture 리스너는 페이지의 일반 리스너보다 먼저 실행되고, 페이지 스크립트는 우리보다 늦게 등록한다. 호환 모드로 확정된 뒤 `event.detail`이 우리 detail이 아니고 `detail.info.rdns`(소문자 비교)가 `io.metamask`·`io.metamask.flask`·`io.rabby`이면 `stopImmediatePropagation()`. 다른 rdns(`io.coinbase.wallet` 등)는 통과한다. `detail` getter가 예외를 던지면 통과시킨다. 기본 모드와 모드 확정 전에는 아무것도 막지 않는다.

**`_metamask.isUnlocked()`**: `eth_accounts`를 보내 결과가 비어 있지 않으면 `true`(이 origin이 연결되어 있고 yw-app이 잠금 해제 상태), 비었거나 오류면 `false`. 거부하지 않는다. `requestBatch` 등 다른 `_metamask` 멤버는 없다.

**한계(최선 노력, 팝업 경고 문구로 알림)**

- 임시 구간(모드 확정 전 수 ms)에 실행된 페이지 코드는 기본 플래그(`isMetaMask: false`)를 보고, 그 사이 실제 MetaMask가 보낸 알림은 막히지 않는다. 대부분의 dApp은 번들 로드 뒤(또는 버튼 클릭 때) 지갑을 찾고, EIP-6963 목록은 계속 듣기 때문에 영향이 적다.
- 실제 MetaMask·Rabby가 `window.ethereum`을 non-configurable·쓰기 불가로 만들면 되찾을 수 없다. 다른 확장이 EIP-6963 이외의 경로(예: MetaMask SDK의 확장 통신, `window.ethereum.providers` 배열)로 자신을 알리면 막지 않는다.
- 그래서 팝업 경고(실제 확장을 끄라는 권고): "호환 모드를 쓸 때는 실제 MetaMask·Rabby 확장을 꺼 두세요. 켜져 있으면 dApp이 그 지갑에 연결될 수 있습니다."

**팝업**(`popup/popup.html` + `src/popup.js` 모듈 + `src/popup-core.js`, 한국어, 원격 자원·인라인 script 없음, 텍스트는 `textContent`만)

- yw-app 연결 상태(제목 "Your Wallet 앱 연결 상태", 사용자 문구에는 `yw-app` 대신 "Your Wallet 앱"을 쓴다): popup이 `chrome.runtime.connect({ name: "your-wallet-popup-v1" })`로 묻고 background가 상태 하나를 답한다(§2.6). 봉투 v1에는 ping이 없으므로 background가 **마지막으로 관찰한** 상태다: `connected`(native 열림 + yw-app 응답 받음) "연결됨", `checking`(열림, 응답 전) "확인 중", `unavailable`(마지막 연결 실패·backoff) "연결 안 됨", `unknown`(관찰 없음: worker 재시작 직후, 요청이 없었음, 2 s 무응답) "확인 불가". 상태 조회는 router를 만들지 않고 native를 열지 않는다(열면 yw-app이 자동 실행된다). background는 `port.sender.id === chrome.runtime.id`, `sender.tab` 없음, `sender.url === chrome.runtime.getURL("popup/popup.html")`일 때만 답하고 그 밖은 port를 닫는다.
- 모드 선택: 고를 수 있는 라디오 카드 3개("기본 (Your Wallet)", "MetaMask처럼 보이기", "Rabby처럼 보이기", 카드마다 그 모드가 하는 일을 쉬운 말로 한 줄 설명), 저장 결과, "모드 변경은 다음 페이지 로드부터 적용됩니다. 열려 있는 dApp 탭은 새로고침하세요.", 위 경고.
- 모양: 데스크톱 앱([04](04-app-ui.md))과 같은 라이트 테마 하나(다크 변형 없음). 배경 `#F3F4F6`, 카드 `#FFFFFF`·테두리 1px `#E1E4E8`·모서리 8px, 글자 `#1F1F1F`, 보조 글자 `#5F6368`, 강조(선택 카드 테두리·라디오) `#0F6CBD`, 글꼴 `"Malgun Gothic", "Segoe UI", system-ui`(본문 13px, 설명 12px, 제목 굵게 16px), 간격 4/8/12/16px. 상단에 앱 이름 머리글, 연결 상태는 색 알약(`connected` 성공 `#DFF6DD`/`#0E700E`, `unavailable` 고위험 `#FDE7E9`/`#A4262C`, 그 밖 정보 `#E8F1FB`/`#0F4C81`), 경고는 주의 색(`#FFF4CE`/`#7A5C00`). 원격 글꼴·이미지 없음(§2.11 검사).

---

## 3. 메서드 허용 목록
### 3.1 허용 메서드 (27개, 정본: JS `shared.js METHOD_ROUTE`, Rust `yw_core::policy::Method`)
`route`는 봉투 v1의 `"permission" | "read" | "signing"`이다. `permission`은 RPC 없이 yw-app이 답하는 메서드를 뜻한다.

| 메서드 | route | 연결 필요 | 동작 | 결과 |
|---|---|---|---|---|
| `eth_requestAccounts` | permission | — | §4.2 연결 흐름. 이미 연결·잠금 해제 상태면 창 없이 반환 | 계정 배열 |
| `eth_accounts` | permission | — | 연결·잠금 해제 상태면 grant 계정, 아니면 `[]` | 계정 배열 |
| `eth_chainId` | permission | — | origin 체인(§4.3) | 정규 hex(`0x` + 앞자리 0 없는 소문자, 예 `"0x1"`·`"0xaa36a7"`·`"0x3e7"`) |
| `net_version` | permission | — | origin 체인 10진 | 10진 문자열(예 `"1"`·`"11155111"`·`"999"`) |
| `wallet_switchEthereumChain` | permission | — | 등록된 EVM 체인(§4.3: 내장 3개 + 사용자 추가)이면 origin 체인 변경(창 없음). 미등록 4902, `RpcMismatch`로 차단된 체인 4901 | `null` |
| `wallet_requestPermissions` | permission | — | 연결 여부와 무관하게 연결 창을 띄움(계정 재선택) | EIP-2255 권한 배열 |
| `wallet_getPermissions` | permission | — | 연결·잠금 해제면 권한 1개, 아니면 `[]` | 권한 배열 |
| `wallet_revokePermissions` | permission | — | grant 삭제(§4.5) | `null` |
| `web3_clientVersion` | permission | — | 정적 | `"YourWallet/" + CARGO_PKG_VERSION`(yw-app) |
| `eth_blockNumber` `eth_call` `eth_estimateGas` `eth_feeHistory` `eth_gasPrice` `eth_maxPriorityFeePerGas` `eth_getBalance` `eth_getBlockByHash` `eth_getBlockByNumber` `eth_getCode` `eth_getLogs` `eth_getStorageAt` `eth_getTransactionByHash` `eth_getTransactionCount` `eth_getTransactionReceipt` | read | 아니오 | §3.5 RPC 전달 | RPC 결과 |
| `eth_sendTransaction` | signing | 예(`from`이 grant 계정) | [03](03-evm.md) 검증·시뮬레이션·승인·서명·브로드캐스트. 시뮬레이션 실패·미지원은 승인 창 경고만 바꾸고 응답 코드는 바꾸지 않는다(D15–D16, §5) | tx hash(소문자 0x+64) |
| `personal_sign` | signing | 예 | [03](03-evm.md) D18 표시·승인 | 서명 0x+130 hex(`r‖s‖v`, `v ∈ {0x1b,0x1c}`) |
| `eth_signTypedData_v4` | signing | 예 | [03](03-evm.md) D17 표시·승인 | 서명(같은 형식) |

EIP-2255 권한 객체: `{ "invoker": "<origin>", "parentCapability": "eth_accounts", "caveats": [{ "type": "restrictReturnedAccounts", "value": [<계정>…] }], "date": <granted_at_unix_ms> }`.

### 3.2 명시적 거부 (4200 "Unsupported method.")
허용 표에 없는 모든 메서드는 4200이다. 아래는 골든 파일의 `rejected` 목록으로 양쪽 테스트가 "허용 표에 없음"을 확인한다:

`eth_sign`, `eth_signTransaction`, `eth_sendRawTransaction`, `eth_signTypedData`, `eth_signTypedData_v1`, `eth_signTypedData_v3`, `wallet_addEthereumChain`, `wallet_watchAsset`, `wallet_getCapabilities`, `wallet_sendCalls`, `wallet_getCallsStatus`, `wallet_showCallsStatus`, `wallet_registerOnboarding`, `wallet_scanQRCode`, `eth_subscribe`, `eth_unsubscribe`, `eth_newFilter`, `eth_newBlockFilter`, `eth_newPendingTransactionFilter`, `eth_getFilterChanges`, `eth_getFilterLogs`, `eth_uninstallFilter`, `eth_coinbase`, `eth_getEncryptionPublicKey`, `eth_decrypt`, `personal_ecRecover`, `personal_unlockAccount`, `personal_sendTransaction`, `eth_getProof`, `debug_traceCall`, `eth_simulateV1`.

`eth_coinbase`는 계정 노출 경로를 줄이기 위해 지원하지 않는다. `wallet_addEthereumChain`은 D14에 따라 params와 무관하게(이미 등록된 체인이어도) 4200이다. 체인 추가는 yw-app 설정([04](04-app-ui.md) §6.1 `evmChains`)에서만 한다. dApp이 4902를 받은 뒤 이어 부르는 `wallet_addEthereumChain`도 4200이며 레지스트리는 바뀌지 않는다.

### 3.3 공통 값 규칙 (yw-app `browser/params.rs`, `archive/spec-v2.4:crates/broker/src/params.rs:186-240`을 고쳐 이식)
| 값 | 허용 | 정규화(RPC 전달·내부 표현) | 거부 |
|---|---|---|---|
| address | `0x` + 40 hex. 전부 소문자, 전부 대문자, 또는 EIP-55 체크섬이 맞는 대소문자 혼합 | 20바이트, 출력은 소문자 | `0X` 접두사, 길이 오류, 혼합 대소문자 체크섬 불일치 |
| quantity | `0x` + 1–64 hex, 대소문자 무관, 앞자리 0 허용 | 앞자리 0 제거 소문자(`"0x0"` 포함) | `"0x"`, 65자리 이상, JSON 숫자, 음수 |
| u64 quantity | quantity이면서 값 ≤ 2^64−1 | 동일 | 초과 |
| data | `0x` + 짝수 길이 hex, 대소문자 무관, `"0x"` 허용 | 소문자 바이트 | 홀수 길이 |
| hash32 | `0x` + 64 hex, 대소문자 무관 | 소문자 | 그 밖 |
| block tag | `latest` `earliest` `pending` `safe` `finalized` 또는 u64 quantity | 동일 | 그 밖 |
| block ref(EIP-1898) | block tag, `{ "blockNumber": q }`, `{ "blockHash": h }`, `{ "blockHash": h, "requireCanonical": bool }` (정확한 키) | 동일 구조 | 그 밖 |

EIP-55 판정과 주소 파싱은 yw-core 함수를 쓴다(이름은 [03](03-evm.md)이 정한다). 모든 파라미터 오류는 -32602 "Invalid params."다.

**call 객체**(read용): 키는 `from to gas gasPrice maxFeePerGas maxPriorityFeePerGas value data input nonce type chainId accessList`의 부분집합. 모두 선택이고 `to`는 `null`·생략 가능(배포 추정). `data`와 `input`이 둘 다 있으면 바이트가 같아야 하며 하나(`input`)로 합친다. `data` ≤ 131,072 B. `accessList`는 ≤ 256 항목, 각 `{ address, storageKeys: hash32[] ≤ 256 }`(정확한 키). 그 밖 키(`authorizationList`, `blobVersionedHashes`, `blobs` 등)는 거부.

**tx 객체**(`eth_sendTransaction`): 키·값 의미의 정본은 [03](03-evm.md) §3.2다. 요약: call 객체 규칙에 더해 `from` 필수이고 grant 계정이어야 한다(아니면 4100). `to` 필수·non-null(D19). `type`은 생략·`0x0`·`0x2`만. `gas` ≤ 16,777,216(D20). `chainId`가 있으면 origin 체인과 같아야 한다. `gasPrice`·`maxFeePerGas`·`maxPriorityFeePerGas`는 quantity 형식만 검사하고 값은 버린다(조합 규칙 없음, [03] §3.2, D20). `nonce` 의미 검사와 가스 한도 계산은 [03]이 한다.

### 3.4 메서드별 파라미터
| 메서드 | params(배열, 정확한 길이) | 추가 규칙 |
|---|---|---|
| `eth_requestAccounts` `eth_accounts` `eth_chainId` `net_version` `wallet_getPermissions` `web3_clientVersion` `eth_blockNumber` `eth_gasPrice` `eth_maxPriorityFeePerGas` | `[]` | — |
| `wallet_switchEthereumChain` | `[{ "chainId": u64q }]` | 정확한 키(형식 위반 -32602). 형식이 맞으면 §4.3 판정: 미등록(0 포함) → 4902, `RpcMismatch` → 4901 |
| `wallet_requestPermissions` `wallet_revokePermissions` | `[{ "eth_accounts": {} }]` | 정확한 키, 값은 빈 객체 |
| `eth_getBalance` `eth_getCode` `eth_getTransactionCount` | `[address]` 또는 `[address, blockRef]` | 생략 시 `"latest"` |
| `eth_getStorageAt` | `[address, slot]` 또는 `[address, slot, blockRef]` | slot은 quantity(1–64 hex, 앞자리 0 허용) |
| `eth_call` `eth_estimateGas` | `[call]` 또는 `[call, blockRef]` | 3번째 인자(state override) 거부 |
| `eth_feeHistory` | `[count, newest]` 또는 `[count, newest, percentiles]` | count는 u64q 또는 JSON 정수, 1–1024. newest는 block tag. percentiles ≤ 100개, 0–100 실수, 엄격 증가 |
| `eth_getBlockByHash` | `[hash32, bool]` | — |
| `eth_getBlockByNumber` | `[blockTag, bool]` | 1898 객체 불가 |
| `eth_getTransactionByHash` `eth_getTransactionReceipt` | `[hash32]` | — |
| `eth_getLogs` | `[filter]` | 아래 |
| `eth_sendTransaction` | `[tx]` | §3.3 |
| `personal_sign` | `[message, address]` | message가 `^0x([0-9a-fA-F]{2})*$`면 hex 바이트, 아니면 문자열의 UTF-8 바이트. ≤ 65,536 B. address는 grant 계정(아니면 4100). 순서가 뒤바뀐 `[address, message]`는 거부 |
| `eth_signTypedData_v4` | `[address, typedData]` | typedData는 JSON 문자열(≤ 131,072 B, `REQUEST_LIMITS`로 엄격 파싱, 객체여야 함) 또는 객체. 최상위 키는 정확히 `types primaryType domain message`. 정규 직렬화 ≤ 131,072 B. address는 grant 계정. domain·스키마 규칙(D17)은 [03](03-evm.md) |

`eth_getLogs` filter: 키는 `fromBlock toBlock blockHash address topics`의 부분집합. `blockHash`가 있으면 `fromBlock`·`toBlock` 금지. `fromBlock`·`toBlock`은 u64 quantity 또는 `latest` `safe` `finalized`(생략은 `latest`). `pending`은 거부하고, `earliest`도 거부한다(`blockHash` 없이 `fromBlock: "earliest"`로 0번 블록부터 훑는 경로 차단). 모두 -32602. `address`는 주소 하나 또는 1–32개 배열. `topics`는 ≤ 4개, 각 항목은 `null`, hash32, 또는 hash32 1–32개 배열. 결과 크기는 §3.5가 제한한다.

범위 규칙(`MAX_LOGS_BLOCK_RANGE = 10,000`, `blockHash`가 없을 때, 위반은 -32602):

| 경계 | 검사 | 시점 |
|---|---|---|
| 둘 다 숫자 | `from ≤ to`이고 `to − from ≤ 10,000` | §6.2 9단계(파라미터 검증) |
| 둘 다 태그(생략 포함) | 범위 0으로 보고 통과. `eth_blockNumber` 조회 없음 | 〃 |
| 한쪽만 태그 | 태그를 B로 바꾼 뒤 `to.saturating_sub(from) ≤ 10,000`. 캐시가 최대 12 s 늦을 수 있으므로 `from ≤ to`는 검사하지 않는다(B보다 큰 숫자 `fromBlock`은 RPC가 처리) | read 워커가 전달 직전(reader 스레드는 RPC를 기다리지 않는다, §8.4) |

- B = origin 체인의 캐시된 `eth_blockNumber` 값. 캐시는 체인별 `(값, 수신 시각 time::monotonic_ms)`이고 그 체인으로 성공한 `eth_blockNumber` 응답(지갑 자체 조회와 dApp read 전달 모두)으로 갱신한다. 캐시가 없거나 `LOGS_BLOCK_CACHE_MS = 12,000`보다 오래되면 같은 엔드포인트로 `eth_blockNumber`를 먼저 호출한다(실패·형식 오류는 §3.5와 같이 4901).
- `latest`·`safe`·`finalized`는 모두 B로 본다. `safe`·`finalized`의 실제 값은 B 이하이므로 `fromBlock`에 쓰이면 범위를 작게 잡는다(정상 상태 차이는 수십 블록, 결과 크기는 §3.5 상한이 막는다).
- 범위 검사에 통과하면 원 params를 태그 그대로 전달한다(태그를 숫자로 바꿔 보내면 `safe`·`finalized`의 의미가 바뀐다).

이식 메모: `archive/spec-v2.4:crates/broker/src/params.rs:105-671`의 스키마를 기준으로 하고 `:186-240,415-663`의 버그 8개를 고친다(EIP-55, 대문자·앞자리 0 quantity, `to` 없는 read, personal_sign UTF-8, typedData 객체, EIP-1898, `data`=`input` 허용, 한쪽만 있는 getLogs 범위). `wallet_addEthereumChain`·`wallet_watchAsset`·`wallet_getCapabilities` 스키마는 버린다.

### 3.5 read 전달
- origin 체인(§4.3, 내장·사용자 체인 공통)의 RPC 엔드포인트([03] §1.4 `endpoint(chain)` = 그 체인의 `apikeys.dpapi` `rpc:eip155:<chainId>` URL. 공급자 템플릿은 설정 저장 때 이 URL을 만들 뿐이고 다른 URL로 대체하지 않는다. D13–D14, spec.md §4.3, [04] §6.3)로 정규화한 params를 그대로 보낸다. 다른 체인의 엔드포인트로 대신 보내지 않는다. RPC 클라이언트(WinHTTP, 시간 제한, 응답 바이트 상한)는 [03](03-evm.md)/[04](04-app-ui.md)의 것을 쓴다. 동시 실행 4개(§8.4).
- 성공: `result`를 yw-json으로 파싱한 값 그대로 반환. `checkJson` 기준 `RESPONSE_LIMITS`를 넘거나 직렬화 크기 > 1,044,480 B(1 MiB − 4 KiB)면 -32603 "Response too large.".
- RPC 엔드포인트 없음(`endpoint(chain)` 없음: 그 체인의 `rpc:eip155:<chainId>` URL이 저장되지 않음), 체인 상태 `RpcMismatch`·`Unverified`([03] §1.4), 연결·TLS·시간 초과·HTTP 비-2xx(429 제외)·JSON 오류 → 4901 "Chain RPC is unavailable.". HTTP 429 → -32005 "Rate limit exceeded.".
- 상위 JSON-RPC `error` 전달(revert 데이터를 dApp이 해석하도록): code가 `3`, −32099…−32000, −32600…−32603이면 유지하고 그 밖은 −32603. message는 0x20–0x7E 문자 1–256자면 유지, 아니면 `"RPC error."`. data는 `^0x([0-9a-fA-F]{2})*$`이고 ≤ 131,074자인 문자열이면 소문자로 유지, 아니면 생략. 이 문자열은 dApp에만 가고 yw-app 화면에는 표시하지 않는다.

---

## 4. 권한 모델
### 4.1 grant 레코드 (meta.ywm `connected_sites`, 스키마 정본은 [02](02-core-keys-vault.md) §5.3, D31)
```rust
pub struct ConnectedSite {
    pub origin: BrowserOrigin,       // §4.7, ≤ 256 B ASCII
    pub accounts: Vec<[u8; 20]>,     // 1..=16, 순서 = 반환 순서, 첫 항목 = 선택 계정
    pub chain_id: u64,               // 등록된 EVM 체인 ID(§4.3, D14)
    pub granted_at_unix_ms: u64,     // unix ms
}
// 한도: connected_sites 0..=256개([02] §5.3), origin당 1개. 키는 origin뿐(Chrome 프로필·profileInstallId와 무관)
```

- 한도 정본은 [02] §5.3이다: grant 0..=256개, grant당 계정 1..=16개. 연결 창은 17개 이상을 고를 수 없고(§4.2), `accountsChanged` payload도 최대 16개다(§2.8). grant가 256개인 상태에서 새 origin이 연결을 요청하면 창을 띄우지 않고 4100(연결된 사이트 화면에서 해제한 뒤 다시 요청).
- 계정 주소는 연결된 origin에만 노출한다. 연결되지 않은 origin이 계정을 요구하는 메서드를 부르면 4100이다. 연결 안 된 계정을 지정한 경우도 같은 4100이다(계정 존재 여부를 구분해 알려주지 않는다).
- 지갑(vault)이 없으면 계정 관련 메서드는 4100, `eth_accounts`는 `[]`다.
- 계정을 지갑에서 숨기거나 지우면([04](04-app-ui.md)) 모든 grant에서 빼고, 빈 grant는 삭제한다.

### 4.2 연결 흐름 (`eth_requestAccounts`, `wallet_requestPermissions`)
1. 같은 origin의 연결 창이 이미 대기·표시 중 → -32002 "Request already pending.".
2. 잠겨 있으면 잠금 해제 창([04](04-app-ui.md)). 닫거나 실패 → 4001. vault가 `BackupPending`([02] §7.1)이면 → 4100(signing도 같음, §8.4).
3. `eth_requestAccounts`이고 이미 연결 → grant 계정 반환(창 없음). 연결되지 않은 origin이고 grant가 이미 256개 → 4100(창 없음, §4.1).
4. "사이트 연결" 창(승인 큐 순서대로, §8.4):
   - 제목 `사이트 연결`, origin 전체(scheme://host[:port]) 크게 표시. `http` origin이면 `로컬 개발 사이트(http)` 표시. 호스트에 `xn--` 라벨이 있으면 `국제화 도메인(punycode)` 경고. 요청 `context.compatMode`가 있으면 배지 `호환 모드: MetaMask` 또는 `호환 모드: Rabby`(§2.12, 서명 승인 창도 같은 배지). origin은 바뀌지 않는다.
   - 안내: `이 사이트는 선택한 계정의 주소, 잔액, 거래 기록을 볼 수 있습니다. 서명과 전송은 매번 따로 승인합니다.`
   - EVM 계정 목록: 체크박스 + 라벨 + 전체 주소(EIP-55 표기). 기본 선택: 기존 grant가 있으면 그 계정, 없으면 계정 0.
   - 현재 origin 체인 이름 표시.
   - 버튼 `거부`, `연결`(선택 0개 또는 16개 초과면 비활성, [02] §5.3). 창 닫기 = 거부.
5. `연결` → grant 저장(meta 원자적 쓰기), origin 체인 = 현재 origin 체인. 결과 반환 후 그 origin의 모든 문서에 `accountsChanged`. `거부` → 4001. 창 표시 후 120 s(D23) → 창 닫고 4001 "Request expired.". 요청 기한(§6.4) 만료 → 창 닫고 -32603 "Request timed out.". 확장 cancel·연결 끊김 → 창 닫고 응답 없음.

### 4.3 체인 상태
- **등록된 EVM 체인**(D14): 내장 Ethereum mainnet(1)·Sepolia(11155111)·HyperEVM(999)과 `settings.json` `evmChains`의 사용자 추가 체인([04](04-app-ui.md) §6.1, 정의·추가 시 검증은 [03](03-evm.md) §1). yw-app은 settings를 읽거나 바꿀 때 메모리 레지스트리를 갱신하고, dApp 요청은 이 레지스트리로 판정한다(평문 설정이므로 잠김과 무관, D30). 이후 규칙은 내장·사용자 체인을 구분하지 않는다.
- **차단 체인**: [03] §1.4 체인 상태가 `RpcMismatch`(`eth_chainId` 또는 블록 0 해시가 고정값과 다름)인 체인. `Unverified`, 아직 확인 전, 엔드포인트 없음은 차단이 아니다(전환은 성공하고 그 체인의 read가 §3.5대로 4901). 상태가 초기화되면([03] §1.4: 앱 재시작, 그 체인 RPC URL 변경) 차단도 풀린다.
- origin마다 활성 체인 하나. 메모리 캐시 `chain_cache: HashMap<BrowserOrigin, u64>`(최대 512, LRU)가 앱 실행 중 정본이다. 가득 차서 밀어낼 때 문서 표(§4.8)에 문서가 남아 있는 origin(그 체인을 안내받은 살아 있는 페이지)은 밀어내지 않는다(밀려나면 다음 요청에서 체인이 알림 없이 바뀐다).
- 캐시에 없는 origin의 체인은 `settings.json`의 EVM 활성 체인 `evmChainId`(D30, 기본값은 [04](04-app-ui.md) §6.1)이며, 처음 쓰는 순간 그 값을 캐시에 넣는다(이후 앱에서 활성 체인을 바꿔도 그 origin의 체인은 그대로이므로 알리지 않은 체인 변경이 없다). 연결 안 된 origin의 체인은 디스크에 저장하지 않는다(앱 재시작 시 초기화).
- `wallet_switchEthereumChain`: 대상이 등록된 체인이고 차단 체인이 아니면 캐시를 바꾸고, 연결되어 있고 잠금 해제 상태면 grant `chain_id`도 저장한다(응답·이벤트는 즉시, meta 쓰기는 2 s에 한 번으로 모아 마지막 값만 쓴다. 전환을 반복하는 페이지가 vault 쓰기를 연달아 일으키지 못한다. 그 사이 잠기면 캐시 값이 해제 병합에서 저장된다). 값이 바뀌었으면 그 origin 문서에 `chainChanged`(같은 체인이면 `null`만, 이벤트 없음). 미등록 → 4902, 차단 → 4901이고 둘 다 캐시·grant·이벤트 변화 없음. 판정은 메모리 레지스트리·체인 상태만 쓰고 RPC를 호출하지 않는다(§8.4 즉시). 승인 창은 띄우지 않는다(서명 창마다 체인을 크게 표시하므로).
- 사용자 체인 삭제([04](04-app-ui.md)): 레지스트리에서 빼는 순간 그 체인을 가진 캐시 항목을 삭제 후의 `evmChainId`로 바꾸고 해당 origin에 `chainChanged`. 잠금 해제 상태면 같은 grant `chain_id`도 저장한다. 그 체인으로 승인 전(큐·창)인 signing 요청은 창을 닫고 4901, 진행 중인 read는 그대로 끝난다.
- 잠금 해제 시: 각 grant에 대해 캐시에 항목이 있으면 grant `chain_id`를 캐시 값으로 저장하고, 없으면 캐시를 grant 값으로 채운다. grant `chain_id`가 레지스트리에 없으면(잠긴 동안 삭제) `evmChainId`로 바꿔 저장한다. 달라진 origin에는 `chainChanged`.
- `chainChanged`는 origin 체인이 실제로 바뀔 때마다(전환, 사용자 체인 삭제, 잠금 해제 병합) 보내며 대상이 사용자 체인이어도 같다. payload는 §3.1 `eth_chainId`와 같은 정규 hex다.
- read·서명은 요청 시점의 origin 체인을 쓴다. 승인 창이 열린 뒤 체인이 바뀌어도 그 요청은 시작 시점 체인으로 처리한다.

### 4.4 잠금 상태 동작
meta가 암호화되어 있으므로(D7) 잠긴 동안 grant를 알 수 없다.

| 메서드 | 잠김 |
|---|---|
| `eth_accounts`, `wallet_getPermissions` | `[]` |
| `eth_chainId`, `net_version`, read | 캐시 체인(없으면 `evmChainId`, §4.3) |
| `wallet_switchEthereumChain` | 캐시만 변경(4902·4901 판정은 §4.3과 같음). grant는 해제 시 병합 |
| `eth_requestAccounts`, `wallet_requestPermissions`, signing | 잠금 해제 창 → 해제 후 정상 처리(요청 기한 600 s에 해제 시간 포함, D23). 여러 요청이 기다리면 해제 창은 하나만 띄우고 결과를 공유한다. 거부 → 모두 4001 |
| `wallet_revokePermissions` | 잠금 해제 창 → 해제 후 처리 |

잠금 시 연결된 origin의 문서에 `accountsChanged([])`, 해제 시 `accountsChanged(grant.accounts)`를 보낸다. 잠금 순간 진행 중이던 승인 창은 닫고 4001로 응답한다. 디스패처는 잠금 절차가 시작되는 순간 잠긴 상태가 된다(절전 잠금의 `LockDone` 대기 1.5 s 동안에도 `eth_accounts`가 계정을 돌려주지 않는다).

dApp 요청으로 띄운 잠금 해제 창을 `나중에`로 닫으면 `UNLOCK_PROMPT_COOLDOWN_MS`(30 s) 동안, 잠글 때 연결되어 있지 않던 origin(메모리에만 두고 해제 시 지움; 잠긴 채 시작했으면 모든 origin)의 잠금 해제를 기다릴 요청은 창을 다시 띄우지 않고 즉시 4001이다. 연결되어 있던 origin의 요청은 그대로 창을 띄운다.

### 4.5 연결 해제
- `wallet_revokePermissions` 또는 yw-app 화면의 연결된 사이트 목록에서 해제([04](04-app-ui.md)) → grant 삭제·저장, 그 origin 문서에 `accountsChanged([])`. 대기 중인 그 origin의 signing 요청은 4100.
- yw-app 화면은 grant의 계정 목록 변경을 제공할 수 있다(선택). 변경 시 `accountsChanged`.

### 4.6 localhost 토글
`settings.json`의 `allowLocalhostDapps`(bool, 기본 `false`, 정의는 [04](04-app-ui.md)). `false`이면 `http://localhost[:port]`·`http://127.0.0.1[:port]` origin의 모든 요청에 4100이고 그 origin 문서에 이벤트(§4.8)도 보내지 않는다. 값 변경은 다음 요청·이벤트부터 적용한다. 기존 grant는 지우지 않는다.

### 4.7 Origin 형식 (yw-core `policy::BrowserOrigin::parse`, [01](01-repo-build.md) §2.2)
- 길이 ≤ 256 B, ASCII.
- `https://` + host [+ `:` port]. host는 `[a-z0-9_-]` 라벨을 `.`으로 이은 것(각 1–63자, 전체 ≤ 253, 끝 점 금지, 대문자 금지). port는 1–65535, 앞자리 0 금지, `443` 금지(브라우저 origin은 기본 포트를 생략한다).
- `http://localhost` 또는 `http://127.0.0.1` [+ `:` port], port ≠ 80.
- `[`(IPv6), userinfo, 경로가 있으면 거부.
- SIWE 도메인 비교([03](03-evm.md) D18)와 승인 창 표시는 이 값을 쓴다.

### 4.8 이벤트 전달
- yw-app은 연결마다 문서 표 `activationNonce → (origin, connection_id)`를 둔다(전체 최대 512, LRU). 요청을 받을 때마다 갱신하고, 연결이 닫히면 그 연결의 항목을 지운다. 가득 차면 pending 요청이 있는 문서는 밀어내지 않고, 이미 `MAX_DOCUMENTS_PER_ORIGIN`(64)개를 가진 origin의 새 문서는 그 origin의 가장 오래된 문서를 밀어낸다(activation을 계속 새로 만드는 페이지가 다른 사이트 문서의 이벤트를 끊지 못한다).
- 이벤트는 origin이 같은 모든 항목으로 보낸다(§6.1 event 봉투). 요청을 한 번도 보내지 않은 문서는 이벤트를 받지 않는다.

| 원인 | 이벤트 |
|---|---|
| 연결 창 `연결`, grant 계정 변경 | `accountsChanged(accounts)` |
| 해제, 잠금 | `accountsChanged([])` |
| 잠금 해제 | `accountsChanged(accounts)` + 필요 시 `chainChanged` |
| origin 체인 변경(`wallet_switchEthereumChain`, 사용자 체인 삭제, §4.3) | `chainChanged("0x…")`(사용자 체인 포함) |

---

## 5. 오류 코드
메시지는 아래 문자열과 정확히 같아야 한다(D31: 다른 문서와 다르면 이 표가 정본). yw-app이 만든 오류에는 `data`를 넣지 않는다(§3.5 상위 RPC 전달만 예외). Rust 타입은 `yw_core::policy::ProviderError`다([01](01-repo-build.md) §2.2).

| code | Rust `ProviderError` | message | 발생 |
|---|---|---|---|
| 4001 | `UserRejected` | `User rejected the request.` | 승인·연결·잠금 해제 창 거부·닫기(D16 차단 창 포함), 잠금으로 창 닫힘, 잠금 해제 창 쿨다운(§4.4) |
| 4001 | `Expired` | `Request expired.` | 승인·연결 창 표시 후 120 s 만료(D23, [03] §11.5) |
| 4100 | `Unauthorized` | `Unauthorized.` | 미연결 origin의 계정 요구 메서드, grant에 없는 계정, localhost 토글 꺼짐, vault 없음, vault가 `BackupPending`(백업 미확인)인 동안의 signing·연결 요청, 대기 중 연결 해제(§4.5), grant 256개 상태에서 새 origin 연결(§4.1) |
| 4200 | `UnsupportedMethod` | `Unsupported method.` | 허용 표 밖(`wallet_addEthereumChain` 포함, D14·§3.2), method 형식 오류 |
| 4900 | `Unavailable` | `Wallet is unavailable.` | yw-host가 yw-app에 연결 실패(§7.6, `browserAutoLaunch` 꺼짐 포함), 확장 backoff 중, `connectNative` 실패 |
| 4900 | `ConnectionClosed` | `Wallet connection closed.` | content port·native 연결이 끊길 때 진행 중인 요청, yw-app 종료 |
| 4900 | `ExtensionReloaded` | `Wallet extension was reloaded.` | 확장 컨텍스트 무효(DEAD) |
| 4901 | `ChainUnavailable` | `Chain RPC is unavailable.` | RPC 엔드포인트 없음(§3.5 `endpoint(chain)` 없음), RPC 전송 실패(§3.4 `eth_getLogs` 태그 해석용 `eth_blockNumber` 포함), 체인 RPC 불일치·미확인(`RpcMismatch`·`Unverified`, [03] §1.4), `wallet_switchEthereumChain` 대상이 차단 체인(`RpcMismatch`, §4.3), 승인 전 signing 요청의 사용자 체인이 삭제됨(§4.3) |
| 4902 | `UnrecognizedChain` | `Unrecognized chain.` | `wallet_switchEthereumChain` 대상이 등록된 EVM 체인(D14: 내장 3개 + 사용자 추가, §4.3)이 아님 |
| -32002 | `RequestPending` | `Request already pending.` | 같은 origin 연결 창 대기 중 |
| -32002 | `TransactionPending` | `Transaction already pending.` | D20 송신 슬롯 사용 중(같은 (체인, 계정), [03] §3.6) |
| -32005 | `RateLimited` | `Rate limit exceeded.` | 토큰 버킷 부족, RPC HTTP 429 |
| -32005 | `TooManyPending` | `Too many pending requests.` | pending 한도 |
| -32600 | `InvalidRequest` | `Invalid request.` | 봉투 형식·순번·route 불일치 |
| -32600 | `RequestTooLarge` | `Request too large.` | 크기·JSON 한도 초과 |
| -32602 | `InvalidParams` | `Invalid params.` | §3.3–3.4, [03](03-evm.md)의 사전 정책 거부(D17 chainId 불일치, D19, nonce 불일치 등) |
| -32603 | `Internal` | `Internal error.` | 그 밖의 내부 오류 |
| -32603 | `TimedOut` | `Request timed out.` | 기한 만료(확장·yw-app) |
| -32603 | `ResponseTooLarge` | `Response too large.` | §3.5 |
| -32603 | `BroadcastFailed` | `Transaction broadcast failed.` | 서명 후 RPC가 확정적으로 거부, 다른 해시 반환, 전송 직전 체인 재확인 불일치(판정은 [03](03-evm.md) §4.4). 자동 재전송이 이어지지 않는 경우만이다: 결과가 불확실(시간 초과)하거나 체인 재확인이 전송 오류로 끝나 자동 재전송이 이어지면 tx hash를 반환한다 |
| 그대로 | `Upstream { code, message, data }` | §3.5 정화 규칙 | read의 상위 JSON-RPC 오류 |

`eth_sendTransaction`의 dApp 응답(D15–D16, 상황별 매핑은 [03](03-evm.md) §11.6): 시뮬레이션 결과(성공·revert·RPC 오류·시간 초과·응답 이상·`simulation = unsupported`)는 승인 창의 경고와 고위험 확인에만 영향을 주고 **어떤 오류 코드로도 바꾸지 않는다**. 결과는 승인 → tx hash(브로드캐스트 결과가 불확실해도 hash), 확정적 브로드캐스트 거부 → -32603 `BroadcastFailed`, 거부·창 닫기·잠금(D16 차단 창 포함) → 4001, 창 표시 후 120 s → 4001 `Request expired.`, 요청 기한 → -32603 `Request timed out.`, 창 없는 사전 거부(§3.3–3.4, [03] §11.6) → -32602·4100·-32002 중 하나, 승인 전 사용자 체인 삭제 → 4901(§4.3)이다.

---

## 6. Native messaging 봉투 v1 (D23)
### 6.1 형식 (정확한 키 집합, 모르는 키는 오류)
공통 타입: `id64` = `^[0-9a-f]{64}$`(32바이트)이고 전부 0이 아님, `id32` = `^[0-9a-f]{32}$`(16바이트)이고 전부 0이 아님, `safe` = 정수 1..=2^53−1. yw-app은 정수 필드에서 JSON 숫자 어휘가 부호·지수 없는 정수이거나 소수부가 정확히 `.0`인 것만 받는다(`yw_json::Number::as_u64_allow_dot_zero`, [01] §2.3, §11-4). 봉투 밖(`params` 등)의 정수는 `as_u64` 규칙이다.

**request** (extension → app) — `extension/native-host/v1-request.golden.json`(변경 없음)

| 키 | 규칙 |
|---|---|
| `namespace` `version` `role` `kind` | `"your-wallet"`, `1`, `"extension"`, `"request"` |
| `sessionId` | id64. native 연결마다 새 값 |
| `sequence` | safe. 같은 세션 안에서 request·cancel에 걸쳐 1부터 +1 |
| `deadlineUnixMs` | safe. 발행 시각 + route 기한(`read` 60,000, `permission`·`signing` 600,000; D23, §6.4) |
| `profileInstallId` | id64. 형식만 검사 |
| `activationNonce` | id64 |
| `requestId` | id32 |
| `method` | 문자열 1–96 |
| `params` | 배열 또는 객체 |
| `route` | `"permission"` \| `"read"` \| `"signing"` |
| `context` | 객체, 아래 9개 키 + 선택 키 1개 |

`context`: `browserFamily` = `"chrome"`, `extensionId` = 고정 ID, `tabId` = 0..=2^53−1 정수, `frameId` = `0`, `documentId` = `^[A-Za-z0-9._:-]{1,256}$`, `topOrigin` = §4.7 `BrowserOrigin`, `frameOrigin` = `topOrigin`과 같음, `documentLifecycle` = `"active"`, `channelNonce` = id64. 선택 `compatMode` = 문자열 `"metamask"` 또는 `"rabby"`(§2.12, 표시 전용). 기본 모드는 키가 없다. `"off"`·대소문자 다른 값·문자열이 아닌 값은 그 요청만 -32600이다. 이 선택 키는 v1 호환 확장이므로 `version`은 1 그대로이고 골든 `v1-request.golden.json`(키 없음)도 그대로다.

**cancel** (extension → app) — 신규 골든 `v1-cancel.golden.json`

```json
{"namespace":"your-wallet","version":1,"role":"extension","kind":"cancel",
 "sessionId":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","sequence":2,
 "activationNonce":"000000000000000000000000000000000000000000000000000000000000000c",
 "requestId":"01010101010101010101010101010101","requestSequence":1,"reason":"deadline"}
```

규칙: `1 ≤ requestSequence < sequence`, `reason` = `^[A-Za-z0-9_-]{1,128}$`. cancel에는 응답하지 않는다.

**response** (app → extension) — `v1-response-result.golden.json`(신규), `v1-unavailable-response.golden.json`(메시지 변경)

```json
{"namespace":"your-wallet","version":1,"role":"native-host","kind":"response",
 "sessionId":"bbbb…(64)","sequence":1,"requestSequence":1,
 "activationNonce":"0000…000c","requestId":"0101…01","result":"0xaa36a7"}
```

오류 응답은 `result` 대신 `"error":{"code":4900,"message":"Wallet is unavailable."}`. `role`은 v1 호환을 위해 yw-app이 보내도 `"native-host"`다. 신규 골든의 `sessionId`·`activationNonce`·`requestId`는 `v1-request.golden.json`과 같은 값이다.

**event** (app → extension) — `v1-event.golden.json`(신규)

```json
{"namespace":"your-wallet","version":1,"role":"native-host","kind":"event",
 "sessionId":"bbbb…(64)","sequence":2,"activationNonce":"0000…000c",
 "event":"chainChanged","payload":"0x1"}
```

`event` ∈ {`accountsChanged`, `chainChanged`}. `sessionId`는 그 연결에서 마지막으로 받은 request의 값이다.

### 6.2 yw-app 수신 처리 순서
1. 프레임을 UTF-8 + `REQUEST_LIMITS`로 파싱. 실패 → 로그 후 버림(상관 정보가 없으므로 응답 불가. 확장 기한이 처리). 연결은 유지한다.
2. 봉투 파싱. 실패했지만 `sessionId`·`sequence`·`activationNonce`·`requestId`가 형식대로 있으면 -32600 "Invalid request.", 아니면 버림. `kind`가 `"cancel"`인 프레임의 형식 오류는 상관 필드가 있어도 버린다(cancel에는 응답하지 않는다, §6.1).
3. 순번: `sequence`가 이 연결에서 받은 최대값보다 커야 한다. 아니면 -32600(request) 또는 버림(cancel).
4. `context` 검사. `extensionId` 불일치·origin 형식 오류 → -32600. http origin이고 토글 꺼짐 → 4100.
5. 문서 표 갱신(§4.8).
6. `Method::parse(method)` 없음 → 4200. `method.route() != route` → -32600.
7. 기한: `deadline = min(deadlineUnixMs, received + route 기한)`(§8.4 `READ_DEADLINE_MS`·`INTERACTIVE_DEADLINE_MS`). 이미 지남 → -32603 "Request timed out.".
8. 토큰 버킷·pending 한도(§8.4) → -32005.
9. 파라미터 검증(§3.3–3.4) → -32602 또는 4100.
10. route별 실행(§8.4). 결과·오류는 정확히 한 번 응답한다. cancel·연결 종료로 취소된 요청에는 응답하지 않는다.

### 6.3 순번·세션 규칙
| 방향 | 송신자 규칙 | 수신자 검사 | 위반 시 |
|---|---|---|---|
| extension → app | 세션마다 1부터 +1(request·cancel 공통) | 엄격 증가(빈틈 허용) | 그 요청만 -32600 |
| app → extension | 연결마다 1부터 +1(response·event 공통, writer 스레드가 쓰는 순간 부여) | 정확히 +1 | 확장이 native 연결만 끊음 |

- `requestSequence`는 원 요청의 `sequence`다. 확장은 `(activationNonce, requestId, requestSequence)`가 모두 맞을 때만 응답을 전달한다.
- yw-app은 세션 값을 응답에 되돌려 쓸 뿐 세션 단위 상태를 두지 않는다. 상태 단위는 pipe 연결이다.

### 6.4 기한
D23: 요청 기한은 읽기 60 s, 연결·서명 600 s(잠금 해제·승인 대기·검토 포함). route 단위로 적용한다: `read` → 60 s, `permission`·`signing` → 600 s(창 없는 `permission` 메서드는 즉시 응답하므로 값이 의미 없다).

| 위치 | 값 | 만료 동작 |
|---|---|---|
| provider | 605 s(전 메서드) | -32603 "Request timed out." + page `cancel` |
| background | route 기한(`deadlineUnixMs`와 같은 값) | content에 -32603, native `cancel`(reason `deadline`) |
| yw-app | `min(deadlineUnixMs, 수신 + route 기한)` | 대기 큐에서 제거·창 닫기, -32603 응답(확장은 이미 응답했으면 버림) |
| 승인·연결 창 | 표시 후 120 s(D23, [03] §11.5, [04] §3.5) | 창 닫기, 4001 "Request expired." |

### 6.5 Rust 타입 (yw-app `browser/envelope.rs`, `archive/spec-v2.4:crates/native-host/src/wire.rs:832-1038`의 serde 타입을 yw-json으로 바꿔 이식)
메서드 표·route·origin·오류 코드는 yw-core `policy`에, 봉투·디스패처·params는 yw-app `browser/`에 둔다([01](01-repo-build.md) §2.2, D31).

```rust
// yw-core src/policy (플랫폼 독립, 시간·I/O 없음)
pub enum Route { Permission, Read, Signing }
pub enum Method { /* §3.1의 27개 */ }
impl Method { pub const ALL: [Method; 27]; pub fn parse(s: &str) -> Option<Method>;
              pub fn as_str(self) -> &'static str; pub fn route(self) -> Route; }
pub struct BrowserOrigin(/* §4.7 정규 문자열 */);
impl BrowserOrigin { pub fn parse(s: &str) -> Option<Self>; pub fn is_http(&self) -> bool /* §4.6 토글 */; pub fn as_str(&self) -> &str; }
pub enum ProviderError { /* §5의 변형 */ }
impl ProviderError { pub fn code(&self) -> i64; pub fn message(&self) -> &str; }

// yw-app src/browser/envelope.rs
use yw_core::policy::{BrowserOrigin, ProviderError, Route};
pub const NAMESPACE: &str = "your-wallet";
pub const PROTOCOL_VERSION: u64 = 1;
pub struct Id32(pub [u8; 32]);   // 와이어: id64(64 hex)
pub struct Id16(pub [u8; 16]);   // 와이어: id32(32 hex)
pub enum CompatMode { MetaMask, Rabby }   // parse("metamask"|"rabby"), as_str, label() = "MetaMask"|"Rabby" (§2.12)
pub struct BrowserContext { pub tab_id: u64, pub document_id: String, pub origin: BrowserOrigin, pub channel_nonce: Id32,
    pub compat_mode: Option<CompatMode> }      // SiteRequest.compat_mode로 승인 큐에 전달, 배지 ui::approval_view::compat_mode_badge
pub struct Correlation { pub session_id: Id32, pub sequence: u64, pub activation_nonce: Id32, pub request_id: Id16 }
pub struct RequestEnvelope {
    pub correlation: Correlation, pub deadline_unix_ms: u64, pub profile_install_id: Id32,
    pub method: String, pub params: yw_json::Value, pub route: Route, pub context: BrowserContext,
}
pub struct CancelEnvelope { pub session_id: Id32, pub sequence: u64, pub activation_nonce: Id32,
    pub request_id: Id16, pub request_sequence: u64, pub reason: String }
pub enum Inbound { Request(Box<RequestEnvelope>), Cancel(CancelEnvelope) }
pub enum EnvelopeError { Uncorrelated, Invalid(Correlation), LocalhostDisabled(Correlation) }
pub enum BrowserEvent { AccountsChanged(Vec<[u8; 20]>) /* 0..=16, §4.1 */, ChainChanged(u64) }

pub fn parse_inbound(frame: &[u8], pinned_extension_id: &str, allow_localhost: bool)
    -> Result<Inbound, EnvelopeError>;
pub fn encode_response(c: &Correlation, out_sequence: u64,
    body: Result<&yw_json::Value, &ProviderError>) -> Vec<u8>;   // ≤ 1 MiB 보장, 넘으면 ResponseTooLarge로 대체
pub fn encode_event(session_id: &Id32, out_sequence: u64, activation_nonce: &Id32,
    event: &BrowserEvent) -> Vec<u8>;
```

인코더는 골든 파일과 같은 키 순서로 쓴다. 테스트는 파싱한 값의 동등성으로 비교한다.

---

## 7. yw-host.exe
의존성: `yw-json`, `yw-win`만(D4). `#![forbid(unsafe_code)]`. 콘솔 서브시스템(기본). 크기 목표 300줄 안팎.

### 7.1 실행 인자
- Chrome은 `yw-host.exe chrome-extension://<id>/ --parent-window=0`처럼 실행한다(cmd.exe 경유 또는 직접, Chrome이 고른다). `std::env::args_os()`로 읽는다.
- `args[1]`이 `pinned_extension_id()`로 만든 `chrome-extension://<id>/`와 바이트 단위로 같아야 한다. 다르거나 없거나 ID 파일이 형식 오류면 아무것도 쓰지 않고 종료 코드 2.
- `args[2..]`는 무시한다(8개 초과면 종료 코드 2). 부모 프로세스는 검사하지 않는다.

### 7.2 stdio
- `GetStdHandle(STD_INPUT_HANDLE / STD_OUTPUT_HANDLE)` + `ReadFile`/`WriteFile`를 감싼 yw-win `StdIn: Read`, `StdOut: Write`를 쓴다(CRT 텍스트 모드·Rust std 콘솔 처리·`LineWriter` 버퍼링을 피한다). `_setmode`는 쓰지 않는다.
- `ReadFile`이 0바이트 성공 또는 `ERROR_BROKEN_PIPE` → EOF.
- stdout에는 프레임 외 아무것도 쓰지 않는다. 진단은 stderr 한 줄(형식: `yw-host: <code-word>`), 메시지 내용 없음.

### 7.3 프레이밍 (`yw_json::frame`, 양방향·pipe 공통)
`archive/spec-v2.4:crates/native-host/src/lib.rs:149-203`을 바이트 단위 API로 이식한다(JSON 파싱 분리, 길이는 LE로 고정).

```rust
pub const MAX_FRAME_BYTES: usize = 1_048_576;
pub enum FrameError { Truncated, Oversized, Allocation, Io }
/// 깨끗한 EOF(길이 첫 바이트 전) → Ok(None). 길이 0 또는 > max → Oversized(할당 전).
pub fn read_frame(r: &mut impl std::io::Read, max: usize) -> Result<Option<Vec<u8>>, FrameError>;
/// u32 LE 길이 + payload, 그다음 flush. payload가 비었거나 > max → Oversized.
pub fn write_frame(w: &mut impl std::io::Write, payload: &[u8], max: usize) -> Result<(), FrameError>;
```

- Chrome→host는 Chrome 기준 64 MiB까지 가능하지만 상한은 1 MiB다(확장이 1 MiB로 제한). 초과는 프레이밍 손상으로 보고 종료 코드 4.
- host→Chrome은 Chrome 상한(1 MB)과 같은 1,048,576 B다. 초과 → 종료 코드 5.

### 7.4 pipe 연결과 yw-app 실행
```
name = "\\\\.\\pipe\\YourWallet.v3." + yw_win::current_user_sid_string()?   // 예: S-1-5-21-…-1001
deadline = start + 10 s; spawned = false
loop:
  match yw_win::pipe::connect_client(&name):            // CreateFileW GENERIC_READ|GENERIC_WRITE, OPEN_EXISTING,
                                                         // FILE_FLAG_OVERLAPPED|SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION
    Ok(p)              → break
    Err(NotFound)      → if !spawned {
                           if !auto_launch_enabled() → UNAVAILABLE(§7.6) 즉시(spawn·10 s 대기 없음)
                           spawn_app(); spawned = true }
                         sleep 100 ms
    Err(Busy)          → WaitNamedPipeW(name, min(500 ms, 남은 시간))
    Err(Other)         → sleep 100 ms
  if now ≥ deadline → UNAVAILABLE(§7.6)
hello 교환(§8.2, 2 s) 실패 → UNAVAILABLE
```

`auto_launch_enabled()`(D24, 첫 `NotFound`에서 1회):

- debug 빌드에서 `YW_TEST_NO_SPAWN=1`이면 `false`(§10.1).
- 경로: `LOCALAPPDATA`(절대 경로가 아니면 `true` 반환) + `\YourWallet\v3\settings.json`. debug 빌드에서만 `YW_TEST_DATA_DIR`이 있으면 `<그 값>\settings.json`.
- `yw_win::file::read_limited(path, 65_536)` → `yw_json::parse(&bytes, &Limits::REQUEST)`. 루트가 객체이고 `version == 1`이고 최상위 `browserAutoLaunch`가 bool이면 그 값. 그 밖(파일 없음·읽기 오류·크기 초과·파싱 오류·키 없음·bool 아님)은 `true`([04](04-app-ui.md) §6.1·§6.2의 기본값 규칙과 같음). 다른 키는 보지 않는다.

`spawn_app()`: `std::env::current_exe()`의 폴더 + `yw-app.exe`를 `yw_win::spawn_detached(&exe, &["--background"])`로 실행한다(`bInheritHandles = FALSE`, `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_BREAKAWAY_FROM_JOB`, `ERROR_ACCESS_DENIED`면 breakaway 없이 1회 재시도, [01] §7.6, §11-3). 핸들을 상속하지 않아야 Chrome이 stdin EOF를 정상적으로 본다. 실패해도 연결 재시도는 계속한다(10 s 뒤 UNAVAILABLE).

### 7.5 중계와 종료
- 스레드 R(stdin 리더): 시작 직후부터 `read_frame(stdin)`을 반복해 용량 64 프레임의 `sync_channel`에 넣는다(가득 차면 블록 = Chrome 쪽 backpressure). EOF → 종료 코드 0.
- 연결 성공 후 메인 스레드: 채널의 프레임을 꺼낼 때마다 `AllowSetForegroundWindow(app_pid)`(실패 무시, `app_pid = GetNamedPipeServerProcessId`)를 호출하고 바이트 그대로 pipe에 `write_frame`. 승인 창이 앞으로 나오게 하기 위함이다(§11-2).
- 스레드 W(pipe 리더): `read_frame(pipe)` → `write_frame(stdout)` 바이트 그대로. pipe EOF → 종료 코드 0.
- 내용은 해석하지 않는다(spec.md §4.1). 예외는 §7.6 UNAVAILABLE 모드의 `version`·`kind`·상관 필드 4개와 §7.4 `settings.json`의 `version`·`browserAutoLaunch`뿐이다.
- 종료: yw-host `main.rs`에 단 하나의 `fn terminate(code: u8) -> ! { std::process::exit(i32::from(code)) }`를 두고 `#[expect(clippy::exit, reason = "stdin/pipe 리더 스레드가 메인이 블록된 I/O 중에 프로세스를 끝내야 함")]`를 붙인다([01] §3.1 `exit = "deny"`). 다른 곳에서는 exit를 쓰지 않는다(`lib.rs` 함수는 종료 코드를 돌려주고 `main.rs`의 스레드 본문이 `terminate`를 부른다).

### 7.6 UNAVAILABLE 모드
yw-app에 연결하지 못했을 때만 쓴다. 채널의 프레임을 `recv_timeout(1 s)`로 꺼내며, 1 s 동안 새 프레임이 없으면 종료 코드 3.

- 프레임을 yw-json `REQUEST_LIMITS`로 파싱한다. 루트 객체에서 `version`, `kind`와 상관 필드 4개만 읽는다(spec.md §4.1): `version == 1`이고 `kind == "request"`이고 `sessionId`(id64), `sequence`(safe), `activationNonce`(id64), `requestId`(id32)가 형식대로이면 아래를 쓴다(정수는 §6.1과 같이 `as_u64_allow_dot_zero`). 다른 키는 보지 않는다. 그 밖(cancel, `version` 불일치, 형식 오류)은 버린다.
- `sequence`는 이 프로세스의 송신 카운터(1부터)다. 이 모드에서는 yw-host가 유일한 송신자다.

```json
{"namespace":"your-wallet","version":1,"role":"native-host","kind":"response",
 "sessionId":"<req>","sequence":<n>,"requestSequence":<req.sequence>,
 "activationNonce":"<req>","requestId":"<req>",
 "error":{"code":4900,"message":"Wallet is unavailable."}}
```

### 7.7 종료 코드
| 코드 | 의미 |
|---|---|
| 0 | stdin EOF 또는 pipe EOF |
| 2 | 인자·확장 ID 오류 |
| 3 | yw-app 연결 실패 후 4900 응답 완료 |
| 4 | Chrome 쪽 프레이밍 오류(크기 초과·절단) |
| 5 | yw-app 쪽 프레이밍 오류 |
| 6 | 그 밖 I/O 오류 |

### 7.8 yw-win이 제공할 API (unsafe는 yw-win 안에만, [01](01-repo-build.md))
```rust
pub fn current_user_sid_string() -> Result<String, WinError>;           // OpenProcessToken + TokenUser + ConvertSidToStringSidW
pub struct StdIn; pub struct StdOut;                                    // Read / Write, GetStdHandle + ReadFile/WriteFile
pub mod pipe {
    pub enum ConnectError { NotFound, Busy, Other(u32) }
    pub fn connect_client(name: &str) -> Result<Duplex, ConnectError>;
    pub fn wait(name: &str, timeout_ms: u32) -> bool;                  // WaitNamedPipeW
    pub struct Duplex;                                                  // overlapped 핸들
    impl Duplex { pub fn split(self) -> (PipeReader, PipeWriter); pub fn server_pid(&self) -> Option<u32>; pub fn client_pid(&self) -> Option<u32>; }
    // PipeReader: Read + Send, PipeWriter: Write + Send. 각 연산은 자기 OVERLAPPED·이벤트로 완료까지 대기한다.
    pub struct Server; // §8.1
}
pub fn spawn_detached(exe: &std::path::Path, args: &[&str]) -> Result<(), WinError>;
pub fn allow_set_foreground_window(pid: u32) -> bool;
```

같은 pipe 핸들에서 동기 `ReadFile`이 대기 중이면 다른 스레드의 동기 `WriteFile`도 막히므로(동기 파일 객체 직렬화) pipe는 양쪽 모두 `FILE_FLAG_OVERLAPPED`로 열고 읽기·쓰기를 각자의 OVERLAPPED로 수행한다. Chrome의 stdin·stdout은 서로 다른 핸들이므로 동기 I/O로 충분하다.

---

## 8. Pipe 프로토콜 (yw-host ↔ yw-app)
### 8.1 이름·보안·인스턴스 (D24)
| 항목 | 값 |
|---|---|
| 이름 | `\\.\pipe\YourWallet.v3.<현재 사용자 SID 문자열>` |
| 보안 | SDDL `O:<SID>D:P(A;;GA;;;<SID>)` → `ConvertStringSecurityDescriptorToSecurityDescriptorW` → `SECURITY_ATTRIBUTES` |
| open mode | `PIPE_ACCESS_DUPLEX \| FILE_FLAG_OVERLAPPED`, **첫 인스턴스만** `\| FILE_FLAG_FIRST_PIPE_INSTANCE` |
| pipe mode | `PIPE_TYPE_BYTE \| PIPE_READMODE_BYTE \| PIPE_WAIT \| PIPE_REJECT_REMOTE_CLIENTS` |
| nMaxInstances | 4(Chrome 프로필마다 연결 1개) |
| 버퍼 | 입출력 각 65,536 B |
| nDefaultTimeOut | 1,000 ms |
| 프레이밍 | §7.3과 같음(4 B LE 길이 + UTF-8 JSON, ≤ 1 MiB) |

- yw-app은 시작하자마자(vault 잠금 해제 전, 프로세스 시작 2 s 안) 첫 인스턴스를 만든다. 첫 인스턴스 생성이 `ERROR_ACCESS_DENIED`면 다른 yw-app이 실행 중이다. 이후 처리(기존 창 활성화, `--background`면 조용히 종료 코드 0)는 [04](04-app-ui.md)의 단일 인스턴스 규칙을 따른다.
- 수락 루프: 대기 인스턴스 하나에 `ConnectNamedPipe`(overlapped, `ERROR_PIPE_CONNECTED`도 성공). 연결되면 활성 연결 수 < 4일 때 다음 대기 인스턴스를 만든다. 4개가 모두 연결 중이면 하나가 닫힐 때까지 만들지 않는다(그동안 클라이언트는 `ERROR_PIPE_BUSY`).
- 클라이언트 PID(`GetNamedPipeClientProcessId`)는 로그에만 쓴다. 같은 사용자 프로세스의 접속은 막지 않는다(§2.2).
- 이식 참고: `archive/spec-v2.4:crates/platform-windows/src/broker_channel.rs:505-558`(SDDL), `:889-918`(`create_server`). 이름 생성 방식(무작위)은 쓰지 않는다.

### 8.2 hello
연결 직후 yw-host가 먼저 보낸다. 둘 다 정확한 키 집합.

```json
{"kind":"hello","protocol":1,"hostVersion":"0.3.0","extensionOrigin":"chrome-extension://<id>/","pid":1234}
{"kind":"hello-ack","protocol":1,"appVersion":"0.3.0"}
{"kind":"hello-reject","reason":"protocol"}
```

- `hostVersion`·`appVersion`: 각 크레이트의 `CARGO_PKG_VERSION`(1–32자, 로그용, 일치를 요구하지 않음). `pid`: u32 > 0, 로그용.
- yw-app 검사: `protocol == 1`, `extensionOrigin` == 고정 origin. 실패 → `hello-reject`(`reason` ∈ `"protocol"`, `"origin"`) 후 연결 종료.
- 시간 제한: yw-app은 연결 후 2 s 안에 hello가 없으면 닫는다. yw-host는 hello 후 2 s 안에 `hello-ack`가 없거나 reject면 UNAVAILABLE.
- 이후 모든 프레임은 §6 봉투이며 양방향 모두 바이트 그대로 지나간다. 제어 메시지는 더 없다.

### 8.3 연결 구조 (yw-app)
연결마다 스레드 2개:

- **reader**: `read_frame` → §6.2 처리 → 디스패처로 넘김. 프레이밍 오류(길이 0·초과·절단)나 EOF면 연결을 닫는다(그 연결만).
- **writer**: `mpsc::Receiver<Outbound>`에서 꺼내 송신 `sequence`를 붙여 인코딩하고 `write_frame`. 연결이 닫히면 그 연결의 pending(큐·창 포함)을 모두 응답 없이 취소한다.

### 8.4 디스패처 동시성과 한도 (yw-app)
```rust
pub const READ_DEADLINE_MS: u64 = 60_000;        pub const INTERACTIVE_DEADLINE_MS: u64 = 600_000; // §6.4, D23
pub const HELLO_TIMEOUT_MS: u64 = 2_000;
pub const RATE_PER_DOCUMENT: u32 = 20;           pub const RATE_BURST: u32 = 40;          // 토큰/초, 용량·초기값
pub const MAX_READS_PER_DOCUMENT: usize = 64;    pub const MAX_READS_GLOBAL: usize = 256; // 대기+실행
pub const MAX_READS_PER_UNCONNECTED_ORIGIN: usize = 64;                                  // 미연결 origin의 모든 문서 합
pub const READ_WORKERS: usize = 4;               pub const PIPE_INSTANCES: u32 = 4;
pub const MAX_APPROVALS_PER_ORIGIN: usize = 16;  pub const MAX_APPROVALS_GLOBAL: usize = 64;
pub const MAX_DOCUMENTS: usize = 512;            pub const MAX_RESULT_BYTES: usize = 1_044_480;
pub const MAX_DOCUMENTS_PER_ORIGIN: usize = 64;                                          // §4.8 밀어내기
pub const MAX_LOGS_BLOCK_RANGE: u64 = 10_000;    pub const LOGS_BLOCK_CACHE_MS: u64 = 12_000; // §3.4 eth_getLogs
pub const UNLOCK_PROMPT_COOLDOWN_MS: u64 = 30_000;                                       // §4.4 해제 창 쿨다운
```

| 분류 | 대상 | 처리 |
|---|---|---|
| 즉시 | `eth_accounts`, `eth_chainId`, `net_version`, `wallet_getPermissions`, `web3_clientVersion`, `wallet_switchEthereumChain`, 창이 필요 없는 `eth_requestAccounts`·`wallet_revokePermissions` | reader 스레드에서 메모리 상태(체인 캐시·레지스트리·체인 상태 포함, RPC 없음)로 응답(meta 쓰기는 저장 스레드에 위임) |
| read | route `read` | 작업 큐 → 워커 4개. 문서당 64, 연결되지 않은 origin(잠금 해제 상태의 grant 없음)은 모든 문서 합쳐 64(한 사이트가 전체 슬롯을 차지하지 못한다), 전체 256. 한쪽만 태그인 `eth_getLogs` 범위 검사(§3.4)는 워커가 전달 직전에 한다 |
| 승인 | signing, 창이 필요한 연결 요청, 잠금 해제를 기다리는 요청 | 전역 FIFO 승인 큐 → GUI 스레드([04](04-app-ui.md)). 창은 한 번에 하나. origin당 16, 전체 64 |

- 토큰 버킷은 문서(`activationNonce`)마다 모든 요청에 적용한다(cancel 제외).
- reader 스레드는 승인·RPC를 기다리지 않는다. 승인 창이 열려 있어도 read와 cancel은 계속 처리된다.
- signing 요청은 도착 시 grant를 검사한다(잠김이면 해제 후 검사). 미연결 또는 vault `BackupPending` → 4100([04] §3.1 `NotReady`). 연결 창이 대기 중인 origin의 signing 요청은 4100 없이 큐에서 기다리고, 창이 표시될 때 grant를 다시 검사한다(연결되지 않았거나 그 계정이 아니면 4100).
- 승인 요청의 입장 검사는 디스패처 잠금 안에서 값싼 검사만 한다(vault·grant·대기 중인 연결 창·§4.4 쿨다운·한도·`eth_sendTransaction`의 `chainId`). `eth_signTypedData_v4`의 origin 체인 검증([03] §8.1 T01·T02 → -32602)은 잠금 해제 상태에서만, 잠금을 놓은 뒤 하고, 잠긴 동안에는 하지 않고 큐에 넣는다(해제 후 승인 흐름이 같은 검증을 한다).
- 응답은 pending 표의 `(activationNonce, requestId)`와 `sequence`가 모두 맞을 때만 보내고, 그때 그 요청의 승인 기록도 지운다(같은 id를 다시 쓰는 새 요청의 기록은 늦은 응답이 지우지 않는다).
- cancel: 큐에 있으면 제거, 창이 열려 있으면 창을 닫는다(거부와 같은 내부 처리, 응답 없음). read 실행 중이면 결과를 버린다.
- 서명·브로드캐스트가 끝난 뒤 연결이 사라졌으면 결과만 버린다(트랜잭션 처리는 [03](03-evm.md) 저널을 따른다).

---

## 9. 등록 (D1: 설치 프로그램 없음, Web Store 없음)
### 9.1 `scripts/register-native-host.ps1`
Windows PowerShell 5.1과 PowerShell 7 모두에서 동작해야 한다. 관리자 권한 불필요(HKCU만).

```
param(
  [string]$BinDir = "$env:LOCALAPPDATA\YourWallet\bin",
  [ValidateSet('release','debug')] [string]$BuildProfile = 'release'
)
```

1. `node scripts/extension-key.mjs check` 실패 → 중단. `extension/extension-id.txt`에서 ID를 읽는다.
2. `$BinDir`을 절대 경로로 정규화. `"`, `%`, `&`, `^`, `|`, `<`, `>`, `!`, 제어 문자가 있으면 중단(cmd.exe 경유 실행 대비, §11-5).
3. `target\<BuildProfile>\yw-host.exe`, `yw-app.exe`가 없으면 `cargo build -p yw-host -p yw-app`(release면 `--release` 추가) 안내 후 중단. 있으면 `$BinDir`을 만들고 두 파일을 복사한다. 복사가 잠금으로 실패하면 "yw-app·Chrome을 종료한 뒤 다시 실행"을 출력하고 중단.
4. `$BinDir\com.your_wallet.native.json`을 쓴다. `[ordered]` 해시테이블(`allowed_origins = @("chrome-extension://<id>/")`) → `ConvertTo-Json -InputObject $m -Depth 3` → `[IO.File]::WriteAllText($path, $json, [Text.UTF8Encoding]::new($false))`(BOM 없음).

```json
{
  "name": "com.your_wallet.native",
  "description": "Your Wallet native messaging host",
  "path": "C:\\Users\\<user>\\AppData\\Local\\YourWallet\\bin\\yw-host.exe",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://<id>/"]
}
```

5. `node extension/native-host/validate-manifest.mjs <manifest> --expect-id <id>` 실패 → 중단.
6. `New-Item -Path 'HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.your_wallet.native' -Value <manifest 절대 경로> -Force | Out-Null`(기본값 설정). 다시 읽어 같은지 확인.
7. 출력: 확장 ID, manifest 경로, 다음 단계(§9.4).

yw-app은 `$BinDir\yw-app.exe`로 실행하는 것을 기본으로 한다(yw-host가 같은 폴더의 yw-app을 실행하므로). 다른 위치에서 실행 중이어도 단일 인스턴스 규칙으로 하나만 남는다.

### 9.2 `scripts/unregister-native-host.ps1`
`param([string]$BinDir = "$env:LOCALAPPDATA\YourWallet\bin", [switch]$RemoveBinaries)`. 레지스트리 키 `HKCU:\Software\Google\Chrome\NativeMessagingHosts\com.your_wallet.native`와 `$BinDir\com.your_wallet.native.json`을 지운다. `-RemoveBinaries`일 때만 두 exe를 지운다. vault·설정(`%LOCALAPPDATA%\YourWallet\v3\`)은 건드리지 않는다.

### 9.3 `extension/native-host/validate-manifest.mjs`
- export 이름 `validateReleaseNativeManifest` → `validateNativeManifest`. 기존 검사(`archive/spec-v2.4:extension/native-host/validate-manifest.mjs:23-62`) 유지 + 추가: `path`의 마지막 구성 요소가 정확히 `yw-host.exe`(대소문자 무시), `path`에 `%`·`&`·`^`·`!`가 없음.
- CLI: `node validate-manifest.mjs <file> [--expect-id <id>]`. UTF-8(BOM 있으면 오류)로 읽고 `JSON.parse` → 검증 → 성공 시 `OK <id>` 출력·종료 코드 0, 실패 시 `INVALID` 출력·종료 코드 1. `--expect-id`가 있으면 ID 일치도 요구.

### 9.4 확장 로드
1. `chrome://extensions` → 개발자 모드 켜기 → "압축해제된 확장 프로그램을 로드합니다" → 저장소의 `extension\` 폴더 선택.
2. 표시된 ID가 `extension/extension-id.txt`와 같은지 확인.
3. `register-native-host.ps1` 실행(순서는 1과 바꿔도 됨). 확장 소스를 고친 뒤에는 확장 카드의 새로고침 버튼을 누르고 열린 탭을 새로고침한다(MV3는 기존 탭에 다시 주입하지 않으며, 옛 content script는 DEAD 상태가 된다).
4. Chrome 시작 시 "개발자 모드 확장 프로그램" 경고가 뜰 수 있다. Web Store·CRX 패키징은 하지 않는다.

---

## 10. 테스트
### 10.1 JS (`node --test`, 확장 폴더에서 `npm test`)
| ID | 파일 | 내용 |
|---|---|---|
| S1 | `tests/shared.test.mjs`(신규) | `METHOD_ROUTE`가 `v1-methods.golden.json`의 permission/read/signing과 정확히 같고 `rejected`는 하나도 없음 |
| S2 | 〃 | `v1-limits.golden.json` 모든 사례에서 `checkJson` 결과 일치, 고립 surrogate 문자열·키 거부 |
| S3 | 〃 | `isSupportedPageUrl`: https 허용, `http://localhost:5173`·`http://127.0.0.1` 허용, `http://example.com`·`http://[::1]`·`file:` 거부 |
| P1 | `tests/provider-main.test.mjs`(갱신) | `ethereum` 없으면 `configurable:true` 등록 + `ethereum#initialized`, 있으면 그대로(기존 159-181 유지), announce는 항상(모드 확정 후. 그 전 `requestProvider`는 확정 시 1회로 답함, `bridge-init` 없으면 10 s 뒤 기본 신원), rdns 값, `window.yourWallet` 없음 |
| P2 | 〃 | provider 객체가 확장 가능하고 내장 멤버(`isRabby`·`_metamask`·`send`·`sendAsync` 포함)는 덮어쓸 수 없음, 열거 멤버 집합이 §2.5 표와 정확히 같음 |
| P3 | 〃 | `on/addListener/once/off/removeListener/removeAllListeners/listenerCount`, 알 수 없는 이벤트 등록이 throw하지 않음, 리스너 예외 격리 |
| P4 | 〃 | `connect`는 chainId를 처음 알 때 1회. 일시적 끊김(content 4900 응답)에 `disconnect` 없음. page `disconnect` 수신 시 `disconnect` 1회 |
| P5 | 〃 | 605 s 시간 초과(`mock.timers`)에 -32603 + page `cancel` 전송, 604 s에는 아직 대기 |
| P6 | 〃 | 같은 채널 `bridge-init` 재수신 허용, 다른 채널 무시, 채널 없을 때 10 s 대기 후 4900 |
| P7 | 〃 (§2.12) | 모드 전달: `compatMode` 없음·`"MetaMask"`·`"on"`·`""`·숫자·null·추가 키인 `bridge-init` 무시(채널·모드 없음), 첫 유효 값이 문서 모드, 이후 다른 모드 무시, 10 s 기본값 확정 뒤 늦은 `bridge-init`은 채널만 |
| P8 | 〃 | 모드별 플래그(`isMetaMask`·`isRabby`·`_metamask`, 확정 전에는 기본값)와 EIP-6963 `name`·`rdns`, 우리 PNG 아이콘, 페이지 uuid 하나, 호환 모드에서 "Your Wallet" 알림 없음(신원 1개) |
| P9 | 〃 | `window.ethereum` 우선권: 임시 구간에 MetaMask가 대입 → 확정 시 되찾음 + `ethereum#initialized`; 확정 뒤 대입(strict 포함)은 예외 없이 무시; configurable 재정의는 예외 없이 성공하고 `requestProvider`·`DOMContentLoaded`·`load`에서 되찾음; 우리보다 먼저 있던 MetaMask(일반 대입) → 우리 것(두 호환 모드); non-configurable 캐시 setter(Rabby 방식) → setter로 들어감; non-configurable 쓰기 불가 → 그대로·예외 없음·알림은 감; 기본 모드는 종전 규칙 |
| P10 | 〃 | EIP-6963 가로채기: 호환 모드에서 남의 `io.metamask`·`io.metamask.flask`·`io.rabby`(대소문자 무관) 알림은 페이지 일반·capture 리스너 모두 못 받고 `io.coinbase.wallet`·`app.phantom`·우리 rdns·`io.metamask.evil` 등은 받음, 이상한·적대적 `detail`은 예외 없이 통과; 기본 모드와 모드 확정 전에는 아무것도 막지 않음 |
| P11 | 〃 | `_metamask.isUnlocked()`: `eth_accounts` `[]`→false, `[주소]`→true, 오류·배열 아님→false, DEAD→false(거부 없음); 기본 모드에는 `_metamask` 없음 |
| P12 | 〃 (§2.5 레거시 API) | `enable` → `eth_requestAccounts`; `send(method, params)`가 결과로 resolve·`request` 오류로 reject(4200·-32602 그대로); `sendAsync`·`send(payload, cb)`의 성공·오류 응답 형식(`id` 그대로·없으면 `undefined`, `data`는 있을 때만), 즉시 실패도 반환 뒤 콜백 1회; 배치: payload 순서, 원소별 오류, 빈 배열, 형식 오류 원소가 하나라도 있으면 아무것도 보내지 않고 TypeError, 65개 배치의 마지막 원소 -32005; 동기 `send(payload)`: `eth_accounts`·`eth_coinbase`·`net_version`만 캐시에서(전송 0), 그 밖(`eth_uninstallFilter` 포함)은 코드 없는 `Error`; 잘못된 payload·callback → TypeError(전송 0); 던지는 콜백은 `reportError`로 1회 보고(없으면 무시)되고 이후 요청 정상; 세 모드와 모드 확정 전 모두 같은 non-writable 멤버 |
| C1 | `tests/content.test.mjs`(신규, `ContentBridge` 어댑터 사용) | 첫 요청 전에는 port를 열지 않음. IDLE→CONNECTING→ACTIVE, 큐 순서 유지 |
| C2 | 〃 | port 끊김 → pending 4900, IDLE. 다음 요청이 재연결해 성공 |
| C3 | 〃 | `isContextValid() === false` → DEAD, page `disconnect` 1회, 이후 4900 "Wallet extension was reloaded." |
| C4 | 〃 | `pagehide` 후 IDLE(DEAD 아님), 5 s 연결 시간 초과, 250 ms 재연결 간격, 미허용 메서드(`wallet_addEthereumChain` 포함)는 연결 없이 4200 |
| C5 | 〃 (§2.12) | `bridge-init`에 문서 모드, content→bg `request`에 호환 모드일 때만 `compatMode`(background 파서가 그대로 수락), 페이지 요청의 `compatMode` 키는 거부, 잘못된 모드로 `ContentBridge` 생성 시 TypeError; `loadCompatMode`: 유효 값 그대로, 없음·대소문자 다름·숫자·null·객체 아님 → `off`, 거부·예외 → `off`, 응답 없음 → 3 s에 `off`·늦은 응답 무시 |
| E1 | `tests/compat-delivery.test.mjs`(신규) | 실제 `provider-main.js`(MAIN)와 `shared.js`·`content-core.js`·`content.js`(ISOLATED)를 두 VM world + 공유 postMessage로 실행: `chrome.storage.local.get("compatMode")` = metamask → 저장소 응답 전에는 기본 플래그·알림 없음 → 응답 후 MetaMask 알림 1개·`isMetaMask` true → `window.ethereum.request(eth_requestAccounts)` → content port 요청 `compatMode` → `BackgroundRouter` native 봉투 `context.compatMode = "metamask"`, `topOrigin` = sender origin, 10개 키 → 응답이 페이지까지 돌아옴 |
| E2 | 〃 | 저장소 거부·`"MetaMask"` 값·예외 → 기본 신원, port 요청·봉투 context에 `compatMode` 없음(9개 키) |
| B1 | `tests/extension.test.mjs`(갱신) | 한 activation에서 요청 5,000개 순차 성공(가짜 `now()`를 요청마다 25 ms 진행, 수명 상한 회귀). `MAX_NATIVE_CONNECTION_ATTEMPTS` 테스트(433)는 "재연결 횟수 무제한 + backoff 간격"으로 반전 |
| B2 | 〃 | 토큰 버킷: 81번째 즉시 요청 -32005, 1 s 뒤 회복 |
| B3 | 〃 | 중복 pending id는 무시되고 activation 유지(261, 515 반전). 형식 오류 메시지가 activation을 끊지 않음 |
| B4 | 〃 | native 프레임 오류·순번 건너뜀·`accountsChanged` 주소 17개 → native만 끊기고 pending 4900, activation 유지, 다음 요청이 새 세션으로 재연결. 주소 16개는 전달 |
| B5 | 〃 | 기한 타이머: `eth_blockNumber` 60 s·`personal_sign` 600 s(봉투 `deadlineUnixMs`도 같은 값) → content에 -32603, native `cancel`이 `v1-cancel.golden.json` 형태 |
| B6 | 〃 | native 끊김 후 backoff: `healthy` 아닌 연결 반복 시 1 s, 2 s, 4 s… 30 s 상한, 그동안 로컬 4900 "Wallet is unavailable." |
| B7 | 〃 | `deriveSenderContext`: §2.4 표 전부 |
| B8 | 〃 (§2.12) | content `compatMode` → 그 요청 봉투 `context.compatMode`만(activation context 불변, 기본 모드 9개 키), `"off"`·모르는 값·null·숫자는 무시(형식 오류); `nativeStatus()`: 처음 `unknown` → 요청 중 `checking` → 응답 `connected` → 정상 연결 종료 `unknown` → 4900만 받고 끊김 `unavailable`, 상태 조회가 native를 열지 않음; `popupStatusMessage` 형식; `isPopupSender`: 팝업 페이지만 허용, 탭·다른 확장·다른 페이지·웹 페이지 거부 |
| S4 | `tests/shared.test.mjs` | `COMPAT_MODES`·`normalizeCompatMode`·`POPUP_PORT_NAME`, content→bg `compatMode` 선택 키 규칙, page `request`의 `compatMode` 거부 |
| PO1 | `tests/popup.test.mjs`(신규) | 모드 라벨 3개·카드 설명 3개·경고 문구·"다음 페이지 로드부터 적용" 문구·상태 제목 정확히, 사용자 문구에 `yw-app` 없음, 상태 표시(`연결됨`·`확인 중`·`연결 안 됨`·`확인 불가`, 모르는 값 → `확인 불가`)와 tone(`ok`·`neutral`·`bad`·`neutral`), 상태 메시지 정확한 키, 저장 값 |
| PO2 | 〃 | `popup.html`: `lang="ko"`, module script 하나(`../src/popup.js`), 인라인 코드·스타일·원격 URL 없음, `popup.js`가 쓰는 id가 모두 있음. `popup.css`: 라이트 전용(`prefers-color-scheme`·`@font-face` 없음), §2.12 모양의 토큰 값, ok → 성공·bad → 고위험·경고 → 주의 색 |
| PO3 | 〃 | 가짜 DOM·`chrome`으로 `popup.js` 실행: 모드마다 카드(`label.mode` > 라디오 + 이름·한 줄 설명), 저장된 모드 선택 표시, MetaMask 선택 시 `chrome.storage.local.set({ compatMode: "metamask" })`·저장 문구, 팝업 port `your-wallet-popup-v1`의 `connected` → "연결됨" 후 port 닫음 |
| N1 | `tests/native-contract.test.mjs`(갱신) | request·cancel 골든과 바이트-필드 일치, response·event·unavailable 골든을 받아 올바르게 전달, `validateNativeManifest` + 템플릿은 항상 무효 |
| M1 | `tests/manifest.test.mjs`(신규) | `JSON.parse`한 manifest에서 `key`를 뺀 값이 §2.2 객체(`action` 포함)와 deep-equal(키 순서 무관), `extensionIdFromKey(manifest.key)` == `extension-id.txt`, 호스트 권한·선택 권한·CSP 키 없음 |
| M2 | 〃 | 가짜 `chrome`으로 `background.js`를 로드했을 때 `onConnectExternal`·`onMessageExternal`·`onMessage` 등록 0회. 팝업 port: router 전 `unknown`(native 0회), 응답 받은 뒤 `connected`, 탭 sender·다른 페이지는 port 닫힘·메시지 없음 |
| H1 | `tests/yw-host-process.test.mjs`(신규, `native-host-process.test.mjs` 대체) | `target/debug/yw-host.exe`가 없으면 `process.env.YW_CHECK === "1"`이면 실패, 아니면 skip([01] §4.1). Node `net.createServer().listen(<테스트 pipe>)`로 가짜 yw-app을 만들고 yw-host를 실행: hello 형식, 바이트 그대로 양방향 중계, 잘못된 origin 인자 → 종료 2·출력 없음, 서버 없음(`YW_TEST_NO_SPAWN=1`) → 4900 응답 후 종료 3, 서버 없음 + `YW_TEST_DATA_DIR`의 settings.json `{"version":1,"browserAutoLaunch":false}`(`YW_TEST_NO_SPAWN` 없음) → 2 s 안에 4900·종료 3 |

H1을 위해 yw-host는 **debug 빌드에서만**(`cfg!(debug_assertions)`) 환경 변수 `YW_TEST_PIPE_NAME`(pipe 전체 이름 대체), `YW_TEST_NO_SPAWN=1`(yw-app 실행 생략, `browserAutoLaunch` false와 같음), `YW_TEST_DATA_DIR`(settings.json 폴더 대체, §7.4)을 읽는다. release 빌드는 무시한다. yw-app도 **debug 빌드에서만** `YW_TEST_PIPE_NAME`(`\.pipe`로 시작할 때)을 pipe 이름으로 쓴다(M5 headless E2E: 버리는 `LOCALAPPDATA` + 테스트 pipe로 실제 yw-host ↔ yw-app 중계 확인).

### 10.2 Rust
| ID | 크레이트 | 내용 |
|---|---|---|
| R-F1 | yw-json `frame` | `archive/spec-v2.4:crates/native-host/src/lib.rs:444-572`에서 이식: 왕복, 깨끗한 EOF → None, 길이 0·1,048,577 → Oversized(할당 전, 페이로드 읽지 않음), 절단 길이·페이로드, LE 고정(`02 00 00 00 7b 7d` → `{}`) |
| R-J1 | yw-json | `v1-limits.golden.json` 전 사례, 중복 키·후행 데이터·비객체 루트 거부, 정수 접근자([01] §2.3, §6.1 `.0` 허용 규칙): `1.0`은 `as_u64_allow_dot_zero` 통과·`as_u64` 거부, `1e0`·`1.00`·`-1`은 둘 다 거부, `18446744073709551616`은 둘 다 `None` |
| R-H1 | yw-host | 인자: 정확한 origin만 통과, 끝 `/` 누락·대문자·다른 ID 거부 |
| R-H2 | yw-host | UNAVAILABLE 응답기: 골든 request → `v1-unavailable-response.golden.json`(sequence 1), cancel·`version` 2·형식 오류 → 출력 없음 |
| R-H3 | yw-host | 메모리 스트림으로 중계 바이트 동일성, 1 MiB 초과 시 종료 코드 4/5 |
| R-H4 | yw-host | `auto_launch_enabled`(§7.4)와 연결 루프(가짜 connect·spawn·시계 주입): settings.json `{"version":1,"browserAutoLaunch":false}` → spawn 0회, 대기 없이 UNAVAILABLE(골든 request → 4900, 종료 3). 파일 없음·깨진 JSON·`version` 2·키 없음·`"false"` 문자열·65,537 B 파일 → spawn 1회 후 10 s에 UNAVAILABLE |
| R-P1 | yw-host·yw-app | hello/hello-ack/hello-reject 인코딩·파싱(골든 `pipe-hello.golden.json`, `pipe-hello-ack.golden.json`) |
| R-P2 | yw-app(Windows) | 테스트 이름으로 pipe 서버 생성 → `GetSecurityInfo`로 DACL이 사용자 SID ACE 1개뿐인지, 두 번째 프로세스의 첫 인스턴스 생성이 `ERROR_ACCESS_DENIED`인지, 5번째 클라이언트가 `ERROR_PIPE_BUSY`인지 |
| R-E1 | yw-app `envelope` | request·cancel 골든 → 기대 구조체. `archive/spec-v2.4:crates/native-host/src/wire.rs:1118-1143,1195-1255`(모르는 키·폭·리터럴·route, cancel 순번) 이식 |
| R-E2 | yw-app `envelope` | `encode_response`·`encode_event`가 골든과 값 동일, 1 MiB 초과 결과 → -32603 "Response too large." |
| R-E3 | yw-app `envelope`·디스패처 (§2.12) | 골든 context에 `compatMode` `"metamask"`·`"rabby"` → `Some`, 골든(키 없음) → `None`; `"off"`·`"MetaMask"`·`"RABBY"`·`""`·끝 공백·null·숫자·bool·배열·객체 → 그 요청만 -32600; `compatMode` + 추가 키, `compatMode` + 필수 키 누락 → -32600; 연결 요청이 승인 큐에 실제 origin과 `compat_mode`로 들어감, 잘못된 모드 뒤에도 연결 유지; 배지 문구 `호환 모드: MetaMask`·`호환 모드: Rabby` |
| R-M1 | yw-core `policy` | `Method::ALL`·route가 `v1-methods.golden.json`과 같고 `rejected`는 `Method::parse`가 `None` |
| R-V1 | yw-app `params` | `archive/spec-v2.4:crates/broker/src/params.rs:673-829` 이식 + 반전·추가: EIP-55 체크섬 주소 허용·틀린 체크섬 거부, 대문자·앞자리 0 quantity 정규화, `to` 없는 `eth_call`, personal_sign UTF-8·hex, typedData 객체·문자열, EIP-1898 객체, `data`=`input` 허용·불일치 거부, getLogs 범위 규칙(§3.4, B = 20,000을 인자로 주입): 숫자 쌍 `to − from` 10,000 통과·10,001 거부·`from > to` 거부, `fromBlock` B−10,000 + `toBlock` `latest` 통과·B−10,001 거부, `fromBlock` 0x0 + `safe` 거부, `fromBlock` B+1 + `latest` 통과, 둘 다 태그·둘 다 생략 통과, `fromBlock`·`toBlock`의 `earliest`·`pending` → -32602 |
| R-ERR | yw-core `policy`·yw-app | `ProviderError` 전 변형의 code·message가 §5 표와 일치(yw-core), `BrowserOrigin::parse`가 §4.7 규칙(yw-core), 상위 RPC 오류 정화 규칙(yw-app) |
| R-D1 | yw-app 디스패처 | 같은 문서 요청 10,000개 처리(가짜 시계 50 ms 간격, 수명 상한 없음), 같은 시각 41번째 요청 -32005 |
| R-D2 | 〃 | JSON 파싱 불가 프레임·봉투 오류·순번 역행 뒤에도 연결 유지, 다음 요청 정상 응답(D23) |
| R-D3 | 〃 | 끝나지 않는 가짜 승인이 열린 동안 read 응답 완료, cancel이 창을 닫고 응답 없음, 요청 기한 만료 -32603(read 60 s, signing 600 s), 창 표시 후 120 s → 4001 "Request expired.". 가짜 시뮬레이션 실패(RPC 오류·revert·`simulation = unsupported`)에서도 `eth_sendTransaction`은 가짜 승인 → tx hash, 가짜 거부 → 4001(시뮬레이션 기인 오류 코드 없음, §5) |
| R-D4 | 〃 | origin당 승인 17번째·전체 65번째 → -32005, 연결 창 중복 → -32002 |
| R-D5 | 〃 | `eth_getLogs` 태그 해석(§3.4, 가짜 RPC·시계): 캐시 12 s 이내면 `eth_blockNumber` 호출 0회, 12,001 ms 경과 또는 캐시 없음이면 1회 후 범위 검사, 둘 다 태그면 0회, `eth_blockNumber` 실패 → 4901, 전달된 params의 태그가 그대로임, 검사는 read 워커에서 실행(reader 스레드는 블록되지 않음) |
| R-G1 | yw-app 권한 | grant 생성·해제·잠금·해제 시 이벤트 순서와 대상 문서, 잠김 동작 표(§4.4), 체인 캐시 병합 규칙(§4.3). 캐시에 없는 origin: `evmChainId` = 1이면 잠김·해제 모두 `eth_chainId` `"0x1"`, 그 뒤 `evmChainId`를 11155111로 바꿔도 같은 origin은 `"0x1"`·`chainChanged` 없음, 새 origin은 `"0xaa36a7"`. `BackupPending`에서 `eth_requestAccounts`·`personal_sign` → 4100. 한도(§4.1): 계정 16개 선택 → `연결` 활성·grant 저장·`accountsChanged` 16개, 17개 선택 → `연결` 비활성(grant 검증 함수도 17개 거부). grant 256개 → 기존 origin 재연결은 정상, 새 origin은 창 없이 4100 |
| R-G2 | yw-app 체인(§4.3, 가짜 레지스트리·체인 상태·RPC) | 사용자 체인(예 8453) 등록 후 `wallet_switchEthereumChain` `0x2105` → `null`, 그 origin 문서에만 `chainChanged("0x2105")`, `eth_chainId` `"0x2105"`·`net_version` `"8453"`, 연결·해제 상태면 grant `chain_id` 8453 저장, 같은 체인 재전환은 이벤트 없음. 내장 999 → `"0x3e7"`. 전환 후 read는 그 체인 엔드포인트(`rpc:eip155:<chainId>` URL)로만 전달. 차단 체인(`RpcMismatch`) 전환 → 4901, 캐시·grant·이벤트 불변, 상태 초기화 후 같은 전환 성공. `Unverified`·엔드포인트 없음 체인(`rpc:eip155:<chainId>` URL 없음, 템플릿 자격 정보만 있어도 같음)은 전환 성공 후 read 4901이고 RPC 호출 0회. 미등록 `0x89`·`0x0` → 4902. `wallet_addEthereumChain`(미등록·등록 chainId params 모두) → 4200(§6.2 6단계), 레지스트리 불변, 이어서 미등록 chainId 전환은 여전히 4902. 잠김: 전환은 캐시만 바꾸고 해제 시 grant 병합·`chainChanged`. 사용자 체인 삭제 → 그 체인 origin에 `chainChanged(evmChainId)`, 승인 전 signing 4901, 잠긴 동안 삭제된 grant 체인은 해제 시 `evmChainId`로 교체. 전환 판정 중 RPC 호출 0회 |

### 10.3 공유 골든 (`extension/native-host/`)
| 파일 | 상태 | 사용 |
|---|---|---|
| `v1-request.golden.json` | 유지 | N1, R-E1 |
| `v1-cancel.golden.json` | 신규(§6.1) | N1, B5, R-E1 |
| `v1-response-result.golden.json` | 신규(§6.1) | N1, R-E2 |
| `v1-unavailable-response.golden.json` | 메시지를 `"Wallet is unavailable."`로 변경 | N1, R-H2 |
| `v1-event.golden.json` | 신규(§6.1) | N1, R-E2 |
| `v1-methods.golden.json` | 신규: `{ "permission": [9개], "read": [15개], "signing": [3개], "rejected": [§3.2] }`, 각 배열은 §3.1·3.2 순서 | S1, R-M1 |
| `v1-limits.golden.json` | 신규(아래) | S2, R-J1 |
| `pipe-hello.golden.json`, `pipe-hello-ack.golden.json` | 신규(§8.2, ID 자리에 `abcdefghijklmnopabcdefghijklmnop`) | R-P1 |

`v1-limits.golden.json`: `{ "limits": { "request": {...}, "response": {...} }, "cases": [ { "profile", "shape", "n", "ok" } ] }`. 각 구현이 `shape`·`n`으로 값을 만든다.

| shape | 만드는 값 | 사례(profile request) |
|---|---|---|
| `depth` | `{"v": X}`, n=1이면 X=`null`, n≥2이면 X는 배열 n−1개를 중첩한 값(`[]`, `[[]]`, …) → depth n | n=32 ok, n=33 거부 |
| `array` | `{"v":[0,…]}` 원소 n개 → items n+1, nodes n+3 | n=4095 ok, n=4096 거부 |
| `object` | 루트가 키 `k0…k(n−1)`, 값 `0`인 평면 객체 → items n, nodes 2n+1 | n=4095 ok, n=4096 거부(nodes 8193) |
| `bytes` | `{"v":"a"×(n−8)}` → 직렬화 n바이트 | n=1,048,576 ok, n=1,048,577 거부 |

response 프로필 사례: `array` n=262,141 ok, n=262,142 거부(nodes 262,145. 직렬화 약 512 KiB라 bytes 한도에 먼저 걸리지 않음), `depth` n=32 ok·33 거부, `bytes`는 request와 같다.

### 10.4 수동 E2E (M5, 판정 정본은 [09](09-testing.md))
1. Sepolia dApp에서 EIP-6963 목록에 "Your Wallet" 표시, 연결 창(origin·계정 선택), `eth_accounts`. yw-app이 꺼진 상태의 첫 요청이 10 s 안에 응답(자동 실행). `browserAutoLaunch` 끔 → yw-app 실행 없이 4900 "Wallet is unavailable."(D24).
2. 읽기, `wallet_switchEthereumChain`(Sepolia↔mainnet↔HyperEVM, yw-app 설정에서 추가한 사용자 체인으로 전환 후 읽기가 그 체인 RPC로 감, 미등록 4902 → 이어서 dApp의 `wallet_addEthereumChain` 4200, `RpcMismatch` 상태 체인 4901), 다른 탭 `chainChanged`(사용자 체인 포함).
3. ETH·ERC-20 송금(시뮬레이션 실패·미지원이면 고위험 경고 + 확인 후 승인 가능, dApp은 tx hash를 받고 시뮬레이션 기인 오류 코드는 없음), `personal_sign`, SIWE(도메인 불일치 거부), `eth_signTypedData_v4`(Permit2 포함).
4. 키를 지운 사본 폴더(다른 ID)로 로드한 확장의 `connectNative` 거부.
5. 오류 요청(잘못된 params, 4200, 2 MiB 요청) 뒤 같은 탭의 다음 요청 성공. 승인 창이 열린 동안 다른 탭 읽기 응답, 탭을 닫으면 창 닫힘. 승인 창 120 s 방치 → 4001 "Request expired."(D23). 대기열에서 600 s 초과 → -32603 "Request timed out.".
6. `chrome://serviceworker-internals`에서 worker 중지 후 새로고침 없이 다음 요청 성공. 잠금·해제·연결 해제 시 `accountsChanged`. localhost 토글 꺼짐 → 4100.
7. `chrome://flags#launch-windows-native-hosts-directly` 켬·끔 각각에서 1–2 반복.
8. 호환 모드(§2.12): 팝업 상태·모드 저장, 모드마다 test-dapp C01–C05와 실제 MetaMask 전용 Sepolia dApp(연결·SIWE), 실제 MetaMask·Rabby를 끈 상태와 켠 상태 각각. 판정 절차는 [09](09-testing.md) §5.6 M5-15–M5-20.

---

## 11. 구현 시 확인
| # | 확인할 것 | 방법 | 실패 시 대안 |
|---|---|---|---|
| 1 | `http://localhost/*` 패턴이 모든 포트에 매치되는가 | `http://localhost:5173` 페이지에서 `window.ethereum` 존재 확인 | 두 content script에 `http://localhost:*/*`, `http://127.0.0.1:*/*` 추가(그래도 안 되면 자주 쓰는 포트를 명시) |
| 2 | yw-host의 `AllowSetForegroundWindow`로 승인 창이 앞으로 오는가(직접 실행·cmd 경유 각각) | E2E 3 | [04](04-app-ui.md)의 `FlashWindowEx` 작업 표시줄 알림만 사용 |
| 3 | yw-host가 실행한 yw-app이 yw-host 종료 후에도 살아 있는가(Chrome job 객체) | Chrome 종료 후 작업 관리자 확인(M5) | `CREATE_BREAKAWAY_FROM_JOB` 실패 시 플래그 없이 실행(§7.4). 그래도 같이 죽으면 D24에 따라 자동 실행을 끈다: `browserAutoLaunch` 기본값을 `false`로 바꾸고([04] §6.1과 §7.4 `auto_launch_enabled`의 기본값 함께) 사용자가 yw-app을 먼저 수동 실행 |
| 4 | Chrome이 2^31 이상 정수(`deadlineUnixMs`)를 정수 어휘로 넘기는가 | 첫 request 프레임 로그(디버그 빌드에서 바이트 덤프) | 이미 `.0` 허용 규칙으로 대비됨. 다른 형태(지수 표기 등)가 보이면 §6.1 규칙에 추가 |
| 5 | cmd.exe 경유 실행 시 사용자 이름에 공백·비ASCII가 있는 경로가 동작하는가 | 해당 경로로 `-BinDir` 지정 후 E2E 1 | `-BinDir C:\YourWallet\bin` 같은 단순 경로 사용 |
| 6 | MV3 worker가 native 포트 연결 중 유지되고, idle 종료 후 content 재연결이 worker를 깨우는가 | E2E 6 | 없음(§2.7 설계가 두 경우를 모두 처리) |

---

## 미결 사항
없음. 이전 항목(yw-host의 상관 필드 읽기, 자동 실행 끄기, 요청 기한)은 spec.md §4.1, D24, D23으로 결정되어 본문(§7.4, §7.6, §6.4)에 반영했다. 구현 중 확인할 항목과 실패 시 대안은 §11.

[01]: 01-repo-build.md
[02]: 02-core-keys-vault.md
[03]: 03-evm.md
[04]: 04-app-ui.md
[09]: 09-testing.md
