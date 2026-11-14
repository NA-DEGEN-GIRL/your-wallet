# dApp integration reference

This page is for dApp developers, and for LLMs helping a user connect Your Wallet to a site.
It summarises the normative specs:
- spec/05 (browser): canonical for methods and error codes
- spec/07 §19–§20 (Solana)
- spec/08 §17 (Bitcoin)
- spec/13 (WalletConnect)

The specs are written in Korean. If this page and a spec disagree, the spec wins.

---

## 1. How it works

```
page → provider-main.js (MAIN world) → content.js → background.js (MV3 service worker)
     → yw-host.exe (Chrome native messaging) → \\.\pipe\YourWallet.v3.<SID> → yw-app.exe
```

- **The extension holds no keys.**
  - Every connect and signing request opens a native Windows window in `yw-app.exe`, outside the browser.
  - The user approves or rejects there.
  - The extension only relays requests.
- **The site origin comes from Chrome** (`port.sender`), never from the page.
- **Supported pages** (spec/05 §2.4):
  - `https://` top-level documents.
  - `http://localhost` and `http://127.0.0.1` (any port) work only when the user turns on the app setting for localhost dApps (`allowLocalhostDapps`). Otherwise every request gets 4100.
  - Iframes, `file:`, other `http:` hosts and incognito windows get nothing injected.
- **Timing:** the app may be locked. A connect or signing request can then wait for the unlock window. Allow up to **600 s** for connect and signing requests (§9).

---

## 2. How a page finds the wallet

### 2.1 EVM (always on)

| Mechanism | Default mode |
|---|---|
| EIP-6963 | One announcement: `name: "Your Wallet (EVM)"`, `rdns: "io.github.na-degen-girl.yourwallet"`, the wallet's own 96×96 PNG icon, one UUID per page |
| `window.ethereum` | Set **only if no other wallet set it first** (data property, then `ethereum#initialized` is dispatched) |
| Provider flags | `isYourWallet: true`, `isMetaMask: false`, `isRabby: false` |

**Prefer EIP-6963.** It works next to other wallets.

### 2.2 Solana (always on)

The Wallet Standard wallet is registered through `wallet-standard:register-wallet` and answers `wallet-standard:app-ready`:
- `name: "Your Wallet (Solana)"`, `version: "1.0.0"`, chains `solana:mainnet` and `solana:devnet`.
- Features:
  - `standard:connect` (`{ silent? }`)
  - `standard:disconnect`
  - `standard:events` (`"change"`)
  - `solana:signMessage`
  - `solana:signIn`
  - `solana:signTransaction` v1.0.0
  - `solana:signAndSendTransaction` v1.0.0
- Both transaction features have `supportedTransactionVersions: ["legacy", 0]`.

`window.phantom` and `window.solana` are **not** defined in the default mode.

### 2.3 Bitcoin (off by default)

The default mode injects **nothing** for Bitcoin. Bitcoin dApps work only after the user turns on a
compatibility mode (§2.4). The scope is proof of ownership only: connect and message signing.

### 2.4 Compatibility modes

**How the user turns them on:** in the Your Wallet extension popup, pick a mode per family. The choice is stored in
`chrome.storage.local` under the keys `compatMode`, `solCompatMode` and `btcCompatMode`. It applies on
the **next page load**: reload open dApp tabs. The popup tells the user to disable the real extension
while a look-alike mode is on (spec/05 §2.12–2.13, D22). The popup has its own `한국어 | English` toggle
(`yourWalletLanguage` in `chrome.storage.local`); it changes only the popup's text. Every message a page sees is
English in both languages.

| Family | Mode | What the page sees |
|---|---|---|
| EVM | `off` (default) | §2.1 |
| EVM | `metamask` | EIP-6963 `MetaMask` / `io.metamask`; `isMetaMask: true`; `_metamask.isUnlocked()`; `window.ethereum` claimed by accessor and re-claimed at checkpoints; other announcements with rdns `io.metamask`, `io.metamask.flask`, `io.rabby` are intercepted |
| EVM | `rabby` | EIP-6963 `Rabby Wallet` / `io.rabby`; `isMetaMask: true`, `isRabby: true`; same claiming and interception |
| Solana | `off` (default) | §2.2 |
| Solana | `phantom` | Wallet Standard name `Phantom` + `window.phantom.solana` (+ `window.solana` if absent). The real Phantom cannot be hidden from the Wallet Standard list |
| Bitcoin | `off` (default) | nothing |
| Bitcoin | `unisat` | `window.unisat` |
| Bitcoin | `xverse` | `window.XverseProviders.BitcoinProvider` (+ `window.BitcoinProvider` if absent) and a WBIP004 `window.btc_providers` entry `{ id: "XverseProviders.BitcoinProvider", name: "Xverse Wallet" }` |

Notes:
- The modes change only how the wallet presents itself. The method table, permissions, approval window and origin handling are the same in every mode.
- The approval window shows a badge such as `호환 모드: MetaMask`.
- In `metamask`/`rabby` mode, `metamask_getProviderState` is answered in the page from `eth_accounts`, `eth_chainId` and `net_version`.
- **MetaMask Connect** (`@metamask/connect-evm`, wagmi `metaMask()`) talks to the MetaMask extension directly and cannot be answered. In MetaMask mode it gets an immediate 4200. Use the default or Rabby mode with such dApps (spec/05 §2.12).
- The look-alike modes are best effort. If a real MetaMask, Rabby or Phantom is enabled, the dApp may connect to it instead.

---

## 3. EVM API

### 3.1 Provider object (spec/05 §2.5)

`request({ method, params })` is the main entry point. The legacy calls `enable()`, `send(…)` and
`sendAsync(payload | payload[], cb)` all go through `request`, so they have the same limits and errors.
The exception is synchronous `send(payload)` without a callback: it answers only `eth_accounts`, `eth_coinbase`
and `net_version` from cached state, with no I/O, and throws an `Error` for anything else.
Other members:
- `chainId` and `selectedAddress` (getters)
- `isConnected()`
- `on` / `addListener` / `once` / `off` / `removeListener` / `removeAllListeners` / `listenerCount`

| Event | When | Argument |
|---|---|---|
| `connect` | First time the chain id is known on a connection | `{ chainId }` |
| `accountsChanged` | Connect, disconnect, lock (`[]`), unlock | lowercase addresses |
| `chainChanged` | The origin's chain actually changed | `"0x…"` |
| `disconnect` | Only when the extension was reloaded | error 4900 `Wallet extension was reloaded.` |
| `message` | Never emitted (no subscriptions) | — |

Each origin has its own active chain. A new origin starts on the app's active EVM chain, and
`wallet_switchEthereumChain` changes only that origin (spec/05 §4.3).

### 3.2 Methods (spec/05 §3.1, §3.4)

| Method | Params | Result / notes |
|---|---|---|
| `eth_requestAccounts` | `[]` | Accounts array. Opens the connect window unless already connected and unlocked |
| `eth_accounts` | `[]` | Granted accounts, or `[]` (locked or not connected) |
| `eth_chainId` | `[]` | Canonical hex, e.g. `"0x1"` |
| `net_version` | `[]` | Decimal string, e.g. `"1"` |
| `wallet_switchEthereumChain` | `[{ chainId }]` | `null`, no window. Unregistered chain → 4902. Chain blocked by RPC mismatch → 4901 |
| `wallet_requestPermissions` | `[{ eth_accounts: {} }]` | EIP-2255 permissions; always opens the connect window |
| `wallet_getPermissions` | `[]` | EIP-2255 array or `[]` |
| `wallet_revokePermissions` | `[{ eth_accounts: {} }]` | `null` |
| `web3_clientVersion` | `[]` | `"YourWallet/<version>"` |
| `eth_sendTransaction` | `[tx]` | Tx hash. See §3.3 |
| `personal_sign` | `[message, address]` or `[message, address, password]` | `0x` + 130 hex (`v` = `0x1b`/`0x1c`). See §3.4 |
| `eth_signTypedData_v4` | `[address, typedData]` | Signature (same format). See §3.5 |

**Read methods**
- `eth_blockNumber`, `eth_call`, `eth_estimateGas`, `eth_feeHistory`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`
- `eth_getBalance`, `eth_getBlockByHash`, `eth_getBlockByNumber`, `eth_getCode`, `eth_getLogs`, `eth_getStorageAt`
- `eth_getTransactionByHash`, `eth_getTransactionCount`, `eth_getTransactionReceipt`

They are forwarded to the origin chain's RPC. They need no connection.

Read method rules:
- `eth_call` and `eth_estimateGas` accept no state override.
- `eth_feeHistory` count is 1–1024.
- `eth_getLogs`:
  - a range of ≤ 10,000 blocks without `blockHash`
  - `earliest` and `pending` are rejected
  - `address` ≤ 32 entries
  - `topics` ≤ 4 entries
- Upstream JSON-RPC errors are passed through, sanitized (spec/05 §3.5).

**Value rules** (spec/05 §3.3):
- Addresses are lowercase, uppercase or valid EIP-55.
- Quantities are `0x` hex.
- `data` and `input` are the same field.
- `gasLimit` is an alias of `gas`.

**Built-in chains:** Ethereum `1`, Sepolia `11155111`, HyperEVM `999`, Arbitrum One `42161`, Base `8453`,
BNB Smart Chain `56`, Robinhood Chain `4663`. Users may add more chains in the app's settings. **Sites cannot add chains:**
`wallet_addEthereumChain` always returns 4200. If you get 4902, ask the user to add the chain in the app.

### 3.3 `eth_sendTransaction` (spec/05 §3.3, spec/03)

- `from` is required and must be a connected account (4100 otherwise).
- `to` is required and non-null: **no contract deployment**.
- `type` may be omitted, `0x0` or `0x2`. The wallet always signs EIP-1559 type 2.
  - EIP-2930 (type 1), blobs (type 3) and EIP-7702 (type 4, `authorizationList`) are rejected.
- `gas` (or `gasLimit`) must be ≤ 16,777,216.
- `chainId`, if given, must equal the origin's chain.
- **Fee fields are format-checked and then ignored.** The wallet computes its own fees.
  - Gas limit = max(dApp value, estimate × 1.2).
- `nonce` must match the wallet's nonce if given.
- **One pending transaction per (chain, account):** a second one gets -32002 `Transaction already pending.`
- Rule violations are rejected without a window as -32602 with a fixed message, e.g. `Invalid params: gas exceeds 16777216.`
- **Simulation:** every request is simulated with `eth_simulateV1`. The result only changes the warnings in the approval window. **It never changes the response code.** Approval returns the tx hash, even if the broadcast result is uncertain.

### 3.4 `personal_sign` (D18)

- **Message format:** a message that matches `^0x([0-9a-fA-F]{2})*$` is hex bytes. Anything else is UTF-8 text. ≤ 65,536 bytes.
- **Order:** `[address, message]` (reversed) is rejected with -32602. So is a message that looks like an address.
- **SIWE (ERC-4361)** is parsed. A SIWE domain or URI scheme that does not match the requesting origin is **blocked**, not just warned.
- `eth_sign` is not supported.

### 3.5 `eth_signTypedData_v4` (D17)

- **Format:** `typedData` is a JSON string or an object with exactly the keys `types`, `primaryType`, `domain` and `message`. ≤ 131,072 bytes.
- **Chain id:** a `domain.chainId` different from the origin chain is **blocked**.
- **Known schemas** are shown as structured views: EIP-2612 permit, DAI permit, Permit2, Seaport, Hyperliquid. Other typed data is shown in full and marked high risk.
- **Rejected versions:** v1 and v3, and plain `eth_signTypedData`, get 4200.

### 3.6 HyperCore (Hyperliquid)

There are no HyperCore-specific dApp methods. Hyperliquid sites use `eth_signTypedData_v4`, and the wallet
recognises Hyperliquid typed data (spec/11 §7):
- **Transfers** (`usdSend`, `spotSend`, `sendAsset`, `withdraw3`) get a structured view and recipient checks.
- **API-wallet approval** (`ApproveAgent`) and other Hyperliquid actions are high risk.
- **The L1 `Agent` signature** with chainId 1337 is accepted only with the exact schema and only from the official app origin. It is not accepted over WalletConnect.

---

## 4. Solana API

### 4.1 Page API (spec/05 §2.13)

**Wallet Standard**

| Feature | Behaviour |
|---|---|
| `standard:connect` `{ silent? }` | `sol_connect` (`silent` → `onlyIfTrusted`; a silent failure returns `{ accounts: [] }`) |
| `solana:signMessage` | `{ signedMessage, signature (64 B), signatureType: "ed25519" }` |
| `solana:signIn` | Connects first if needed. Returns `{ account, signedMessage, signature, signatureType }`. The wallet fills in a missing `domain`/`address` and builds the text |
| `solana:signTransaction` | 1 input → `sol_signTransaction`. N inputs (≤ 32) → **one** `sol_signAllTransactions`: one window, one approval. Result `[{ signedTransaction: Uint8Array }]` in input order. `options` are ignored |
| `solana:signAndSendTransaction` | Inputs are validated first, then sent **one by one** with `sol_signAndSendTransaction`. Result `[{ signature: Uint8Array(64) }]`. If a later input fails, the error carries `data: { signatures: [base58…] }` for the ones already sent |

Input rules for both transaction features:
- `account` must be the connected account (4100 otherwise).
- `chain` is omitted, `solana:mainnet` or `solana:devnet`, and the same for all inputs.
- `transaction` is a `Uint8Array` of ≤ 1,232 bytes with a valid signature section.
- More than 32 inputs → -32602.
- Send options read: `skipPreflight` (boolean), `preflightCommitment` and `minContextSlot` (non-negative safe integer). Others are ignored, including `maxRetries`, `commitment` and `mode`.
- `preflightCommitment` aliases: `recent` → `processed`, `single`/`singleGossip` → `confirmed`, `root`/`max` → `finalized`. Unknown values are dropped.

**Phantom shim** (`phantom` mode only): `window.phantom.solana` with
- `isPhantom`, `publicKey`, `isConnected`
- `connect({ onlyIfTrusted }?)`, `disconnect()`
- `signMessage`, `signIn`
- `signTransaction`, `signAllTransactions`, `signAndSendTransaction`, `signAndSendAllTransactions`
- `request({ method, params })`, which also accepts the deprecated base58 `message` / `messages` form
- events `connect`, `disconnect`, `accountChanged`

Notes:
- `signTransaction` returns an instance of the page's own transaction class.
- `signAndSendAllTransactions` sends sequentially and reports partial failure in `data.signatures`.

**Response check:** the provider verifies that the app changed exactly one 64-byte signature slot and nothing else. Otherwise the call fails with -32603.

### 4.2 Wire methods (spec/05 §3.6, spec/07 §20.1)

| Method | Params | Result |
|---|---|---|
| `sol_connect` | `[]` or `[{ onlyIfTrusted? }]` | `{ publicKey: base58 }` (`onlyIfTrusted` and not connected → 4001, no window) |
| `sol_disconnect` | `[]` | `null` |
| `sol_accounts` | `[]` | `[base58]` or `[]` |
| `sol_signMessage` | `[{ publicKey, message: hex }]` (≤ 65,536 B) | `{ publicKey, signature: hex(64 B) }` |
| `sol_signIn` | `[{ publicKey, input: SolanaSignInInput }]` | `{ publicKey, signature, signedMessage: hex }` |
| `sol_signTransaction` | `[{ publicKey, transaction: hex, chain? }]` | `{ publicKey, signedTransaction: hex }` |
| `sol_signAllTransactions` | `[{ publicKey, transactions: [hex] (1..=32), chain? }]` | `{ publicKey, signedTransactions: [hex] }` |
| `sol_signAndSendTransaction` | `[{ publicKey, transaction: hex, chain?, options?: { skipPreflight?, preflightCommitment?, minContextSlot? } }]` | `{ publicKey, signature: hex(64 B) }` (signature 0 = transaction id) |

### 4.3 What the wallet accepts and does (D38, spec/07 §20)

- **Accepted transactions:**
  - legacy and v0, including Address Lookup Tables (≤ 100 tables per request, ≤ 256 addresses per table)
  - any program
  - signatures the site already added, and a fee payer other than the wallet
  - software keys and YubiKey keys
- **Rejected with -32602:**
  - versions `0x81` and above
  - more than 64 top-level instructions, or more than 256 account keys
  - a `publicKey` that is not a signer of the transaction
  - a `chain` that is not the app's selected cluster. **The wallet never switches cluster for a site.**
- **What the wallet changes:** nothing except its own signature slot. It never replaces the blockhash.
- **Simulation:** the window shows SOL and token changes, authority changes, and closed or created accounts, from `simulateTransaction`. Simulation is reference only: there is no re-simulation at approval.
- **Sign-only** (`sol_signTransaction`, `sol_signAllTransactions`): the signed bytes go back to the site. The wallet does not send or track them, and they do not appear in its activity list.
- **Sign-and-send** (`sol_signAndSendTransaction`):
  - The wallet writes its journal first, sends, and answers after the first send round.
  - Durable-nonce transactions and transactions missing other required signatures are refused with -32602.
  - At most 16 pending sends per (cluster, signer) and 32 in total. Beyond that, -32002.
- **Durable nonce:** allowed for sign-only (high risk X08), refused for send.
- **Fee:** the wallet computes the fee from the transaction bytes (exact when the transaction sets a compute-unit limit, otherwise a range from the runtime's default limits) and shows it next to the RPC's `getFeeForMessage` value. It reads `ComputeBudget` instruction data the way the runtime does (bytes after the value are ignored), so the fee counts a price or limit that the instruction list shows as uninterpreted.
- **Fee cap:** a fee above the user's cap (default 100,000 lamports) is high risk X14, only when the wallet pays. It is not blocked. The fee checked is the RPC value or the computed maximum, whichever is higher, so an RPC that under-reports cannot hide X14. When the fee is a range, the warning says "최대" (maximum).
- **Fee mismatch:** an RPC fee outside the computed range is high risk X20, only when the wallet pays. It is not blocked.
- **Grant re-check:** just before the reply the wallet checks the site's grant again. If the site was disconnected, the reply is 4100 and the bytes are discarded.

### 4.4 Solana-specific responses (spec/05 §5)

| Code | When |
|---|---|
| -32602 | Malformed bytes, unsupported version, not a signer, wrong `chain`, durable nonce on send, missing co-signatures on send, > 64 instructions, > 32 transactions, bad `options` |
| 4100 | Not connected or a different account, disconnected while waiting, grant changed before the reply, unconfirmed backup (`BackupUnconfirmed`) |
| 4901 | No Solana RPC configured |
| -32002 | Too many pending dApp sends |
| -32603 | `Transaction broadcast failed.` (expired blockhash, lookup tables changed, deterministic preflight error, …), or `Internal error.` |
| 4001 | Rejected, expired (120 s), locked, preview failed and the user closed the window |

---

## 5. Bitcoin API (compatibility modes only; spec/05 §2.13, §3.6; spec/08 §17)

The scope is **proof of ownership**: connect and message signing. PSBT signing and sending are **never**
supported. The page shims answer them with 4200 and the message `This wallet supports only message signing (proof of ownership) on Bitcoin.`
(English since 2026-11-14; it was Korean before).

**UniSat mode** (`window.unisat`)

| Method | Behaviour |
|---|---|
| `requestAccounts()` | Address array (opens the connect window) |
| `getAccounts()` | Address array |
| `getPublicKey()` | Public key |
| `getNetwork()` | `"livenet"` or `"testnet"` |
| `getChain()` | `{ enum: "BITCOIN_MAINNET" \| "BITCOIN_TESTNET4", name, network }` |
| `switchNetwork` / `switchChain` | Succeed only for the current network; any other network is 4200 `The Bitcoin network can only be changed in the Your Wallet app settings.` |
| `signMessage(msg, "ecdsa" \| "bip322-simple")` | Base64 signature |
| `on` / `removeListener` | `accountsChanged`, `networkChanged` |
| `signPsbt`, `signPsbts`, `pushPsbt`, `pushTx`, `sendBitcoin`, `sendInscription`, `inscribeTransfer`, `sendRunes`, `getBalance`, `getInscriptions` | 4200 |

**Xverse mode** (sats-connect `request(method, params)`)
- Supported: `getInfo`, `getAccounts`, `signMessage` (`ECDSA` | `BIP322`), `wallet_connect`, `wallet_disconnect`, `wallet_getAccount`, `wallet_getNetwork`, `wallet_renouncePermissions`.
- Anything else → -32001.
- Error mapping: 4001 → -32000, 4100 → -32002, 4200 → -32001.

**Wire methods**

| Method | Params | Result |
|---|---|---|
| `btc_requestAccounts` | `[{ purposes: ["payment" \| "ordinals", …] }]` or `[{ purposes: ["any"] }]` | `[{ address, publicKey: hex, purpose, addressType: "p2pkh" \| "p2sh" \| "p2wpkh" \| "p2tr" }]` |
| `btc_getAccounts` | `[]` | same shape |
| `btc_disconnect` | `[]` | `null` |
| `btc_getNetwork` | `[]` | `"mainnet"` or `"testnet4"` |
| `btc_signMessage` | `[{ address, message (≤ 65,536 B), protocol?: "ecdsa" \| "bip322" }]` | `{ address, signature: base64, messageHash: hex, protocol }` |

- `payment` means P2WPKH or P2SH-P2WPKH. `ordinals` means P2TR.
- If Bitcoin is turned off in the app, every `btc_*` request except `btc_getNetwork` and `btc_disconnect` gets
  4100 `BtcDisabled`.

---

## 6. Rejected methods

Every method outside the allowlist (40 methods: 27 EVM + 13 Solana/Bitcoin) returns
**4200 `Unsupported method.`**. These are explicitly listed as rejected (spec/05 §3.2):

- **Signing and sending:** `eth_sign`, `eth_signTransaction`, `eth_sendRawTransaction`, `eth_signTypedData`, `eth_signTypedData_v1`, `eth_signTypedData_v3`, `personal_sendTransaction`, `personal_unlockAccount`, `personal_ecRecover`
- **Wallet management:** `wallet_addEthereumChain`, `wallet_watchAsset`, `wallet_registerOnboarding`, `wallet_scanQRCode`
- **EIP-5792:** `wallet_getCapabilities`, `wallet_sendCalls`, `wallet_getCallsStatus`, `wallet_showCallsStatus`
- **Subscriptions and filters:** `eth_subscribe`, `eth_unsubscribe`, `eth_newFilter`, `eth_newBlockFilter`, `eth_newPendingTransactionFilter`, `eth_getFilterChanges`, `eth_getFilterLogs`, `eth_uninstallFilter`
- **Other:** `eth_coinbase`, `eth_getEncryptionPublicKey`, `eth_decrypt`, `eth_getProof`, `debug_traceCall`, `eth_simulateV1`
- **Bitcoin:** `btc_signPsbt`, `btc_sendBitcoin`, `btc_pushTx`, `btc_sendTransfer`

---

## 7. Error codes (canonical: spec/05 §5)

Messages are exact strings. Wallet-generated errors carry no `data`, except Solana partial sends (§4.1) and sanitized upstream read errors.

**Grant re-check before every reply (spec/05 §4.5):** a signature (`personal_sign`, `eth_signTypedData_v4`, `sol_signMessage`, `sol_signIn`, Solana transaction signing, `btc_signMessage`) or an `eth_sendTransaction` hash is sent only while the site is still connected with that account. If the site was disconnected (by the user, by its own `wallet_revokePermissions` / `sol_disconnect` / `btc_disconnect`, or because the account was hidden) after the approval, the reply is 4100 and the signature is discarded. A transaction that was already signed and journaled is still broadcast. A YubiKey request still waiting for its PIN ends at once on a disconnect (4100) or when the page goes away (4001); nothing is signed.

| Code | Message | Typical cause |
|---|---|---|
| 4001 | `User rejected the request.` | User rejected or closed the window, wallet locked, unlock window dismissed |
| 4001 | `Request expired.` | Window open 120 s without a decision |
| 4100 | `Unauthorized.` | Not connected, account not granted, localhost toggle off, no wallet, backup pending, disconnected after the approval but before the reply (see below) |
| 4100 | `Unauthorized: …` | Reason variants: `PassphraseUnverified`, `NoEvmAccount`, `NoSolAccount`, `NoBtcAccount`, `BtcDisabled`, `BackupUnconfirmed`, `TooManySites` |
| 4200 | `Unsupported method.` | Not in the allowlist, or a malformed method name |
| 4200 | `This wallet supports only message signing (proof of ownership) on Bitcoin.` | Bitcoin transaction, PSBT or balance methods of the UniSat and Xverse shims (Xverse: -32001); answered in the page |
| 4200 | `The Bitcoin network can only be changed in the Your Wallet app settings.` | UniSat `switchNetwork` / `switchChain` to another network; answered in the page |
| 4900 | `Wallet is unavailable.` | App not running and auto-start off, or the native host failed |
| 4900 | `Wallet connection closed.` | Native connection dropped mid-request |
| 4900 | `Wallet extension was reloaded.` | Extension context invalidated |
| 4901 | `Chain RPC is unavailable.` | No RPC for the chain, RPC failure, RPC/genesis mismatch |
| 4902 | `Unrecognized chain.` | `wallet_switchEthereumChain` to an unregistered chain |
| -32002 | `Request already pending.` | A connect window for this origin is already open |
| -32002 | `Transaction already pending.` | Pending-send limit reached for this (chain, account) |
| -32005 | `Rate limit exceeded.` | Token bucket empty or RPC returned HTTP 429 |
| -32005 | `Too many pending requests.` | Pending-request limit |
| -32600 | `Invalid request.` / `Request too large.` | Envelope or size problems |
| -32602 | `Invalid params.` | Parameter validation; for `eth_sendTransaction`, `Invalid params: <rule>` |
| -32603 | `Internal error.` / `Request timed out.` / `Response too large.` / `Transaction broadcast failed.` | Internal error, deadline, oversized read result, definite broadcast rejection |

---

## 8. Limits

| Limit | Value |
|---|---|
| Request JSON | ≤ 1 MiB, depth ≤ 32, nodes ≤ 8,192, array/object items ≤ 4,096 |
| Response JSON | ≤ 1 MiB, depth ≤ 32, nodes/items ≤ 262,144 |
| Provider pending requests | 64 per page |
| Rate limit (per document) | 20 requests/s refill, burst 40, enforced by yw-app (spec/05 §8.4); over it → -32005 `Rate limit exceeded.` The extension's 40/s, burst 80 is only an outer limit |
| Reads waiting or running (yw-app) | 64 per document, 64 per unconnected origin (all its documents together), 256 global |
| Background | 64 pending per document, 512 global, 128 active documents |
| Approval queue | 16 per origin, 64 total |
| `personal_sign` / `sol_signMessage` / `btc_signMessage` message | ≤ 65,536 bytes |
| `eth_signTypedData_v4` | ≤ 131,072 bytes |
| EVM gas | ≤ 16,777,216 |
| `eth_getLogs` block range | ≤ 10,000 |
| Solana transaction | ≤ 1,232 bytes; ≤ 32 per call; ≤ 64 top-level instructions; ≤ 256 account keys; ≤ 100 lookup tables |
| Solana pending dApp sends | 16 per (cluster, signer), 32 total |
| Connected sites | 256 per family (EVM, Solana, Bitcoin); 1–16 EVM accounts per site |

**Deadlines** (spec/05 §6.4, D23):

| Request | Deadline |
|---|---|
| Read | 60 s |
| Connect and signing (including unlock and review) | 600 s |
| Approval or connect window | Expires 120 s after it is shown → 4001 `Request expired.` |
| The provider's own timeout | 605 s → -32603 `Request timed out.` |

Do not cancel signing requests with a shorter client-side timeout.

---

## 9. WalletConnect v2 (spec/13)

The app can also act as a WalletConnect v2 (Reown) wallet. The user connects by:
- pasting a `wc:` URI (`클립보드에서 연결`), or
- reading the QR code from a screenshot in the clipboard or from an image file.

**Requirements and scope**
- **Project ID:** the user must enter **their own Reown Project ID** in the app. There is no default.
- **Namespaces:** **EVM only** (`eip155`).
  - A non-EVM namespace in `requiredNamespaces` → proposal rejected with 5100.
  - In `optionalNamespaces` it is dropped.
- **Sessions** last 7 days and are extended when less than 2 days are left. They survive app restarts.

**Methods served:** `eth_accounts`, `eth_chainId`, `personal_sign`, `eth_signTypedData_v4`, `eth_sendTransaction`, `wallet_switchEthereumChain`.
- Other required methods the wallet knows are granted but answered 4200.
- Unknown method names are dropped from the session.

**Events emitted:** `chainChanged`, `accountsChanged`.

**Request errors**

| Code | When |
|---|---|
| 7001 | Session expired |
| 5100 | Chain not in the session, or not registered |
| 5101 | Method not in the session |
| 8000 | Request expired |
| 5000 | Proposal rejected by the user |
| 3003 | Session update, extend or event sent by the dApp |

**Behaviour**
- Signing requests go through the same dispatcher, approval window, risk rules and simulation as the extension.
- While the wallet is locked, requests are refused with 4100 and no unlock window opens.
- `wc_sessionAuthenticate` (one-click auth) gets no answer, so the dApp falls back to a normal proposal.
- **Claimed origin:** every window shows the dApp URL as `WalletConnect: {origin} (사이트가 주장한 주소)`.
  - The Verify API result is shown as C01 caution (unverified), C02 high (mismatch), C03 high (scam) or C04 info (`일치(서버 알림)`).
  - A Verify match is a server hint, not proof.

---

## 10. What the user sees

- **Connect window.** The user picks accounts. The origin comes from Chrome and is shown large.
- **Approval window** (spec/04 §3), a separate always-on-top Windows window. It shows:
  - the decoded request, built from the exact bytes to be signed
  - simulation results (EVM `eth_simulateV1`, Solana `simulateTransaction`)
  - warnings with a risk level
- **Risk levels:**

  | Level | Approve |
  |---|---|
  | `정보` (info) | Click or Enter |
  | `주의` (caution) | Click or Enter |
  | `고위험` (high) | A confirmation checkbox **and** a 2-second hold of the button. Enter is ignored |
  | `차단` (blocked) | Cannot be approved |

  - Examples of **high risk:** unlimited approvals (E14), ApprovalForAll (E15), uninterpreted calldata (E12), failed or missing simulation (E01/E02, X09), unknown Solana programs (X02), Solana Approve/SetAuthority/CloseAccount (X04/X05/X07), look-alike addresses (E43/X16).
  - Examples of **blocked:** SIWE domain mismatch, typed-data chainId mismatch, EVM fee cap exceeded, malformed Solana transactions (X01).
- **Timing:**
  - The approve button arms 1 second after the window is ready and in front. Any stray click restarts that wait.
  - Initial focus is on `거부` (Reject).
  - The window expires after 120 s.
- **Your site's best practices:**
  - Send exact, minimal requests.
  - Avoid unlimited approvals.
  - Use standard schemas (EIP-2612, Permit2, SIWE / Sign-In-With-Solana) so the user sees a structured view instead of a high-risk raw dump.
  - Keep requests within the limits in §8.
- **The optional AI explanation** applies only to EVM `eth_sendTransaction`, `personal_sign` and `eth_signTypedData_v4`. It never changes risk or approval (spec/06).

---

## 11. Testing your integration locally

1. Turn on the app's localhost toggle (`allowLocalhostDapps`).
2. Serve your page on `http://localhost:<port>` or `http://127.0.0.1:<port>`.
3. The repository's own manual test page is `node extension/test-dapp/serve.mjs` → `http://127.0.0.1:5173`. It covers EVM and Solana calls (no Bitcoin section).
4. Use Sepolia or Solana devnet and small amounts.
