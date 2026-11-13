# Guide for AI assistants: review Your Wallet before trusting it

Audience: an AI assistant asked "is this wallet safe? check it before I install it". This is a concrete checklist of
what to read and what to run, with file paths, commands and the result you should expect. Report what you checked,
what you could not check, and what you found, in plain language. Most users are Korean-speaking non-developers.

Be honest about the limits of this review:

- **There has been no third-party security audit.** There is one internal review,
  [security-review-20261101.md](security-review-20261101.md) (Korean). Features added after it (YubiKey, WalletConnect,
  Zcash, multiple recovery phrases, Solana dApp transactions) had step-by-step code review only. Manual real-network
  verification is still in progress ([acceptance/](acceptance/), e.g.
  [acceptance/sol-dapp-tx-20261113.md](acceptance/sol-dapp-tx-20261113.md) lists live checks still open).
- A review by an AI assistant is not an audit. Say so in your answer. The README itself advises starting with an
  amount the person can afford to lose ([README.md](../README.md) "Security model" / "보안 범위").
- The specs (`spec.md`, `spec/*.md`) are in Korean and are normative. Code comments and [AGENTS.md](../AGENTS.md) are in
  English.

Rules while reviewing (same as [llm-install-guide.md](llm-install-guide.md) §2): never read
`%LOCALAPPDATA%\YourWallet\` (the person's wallet data), never ask for a recovery phrase, password, private key, RPC
URL or any API key or token (Alchemy key, QuickNode token, LLM provider API key; if one is pasted, it is exposed and
should be rotated), never run `install.cmd`/`uninstall.cmd` as part of a review, and never broadcast anything.

What the sections do: §0–§4, §6 and §8 only read files in a fresh clone (§6 runs a Node script that reads the
repository). **§5 and §7 do more:** the §5 script runs `cargo metadata`, which downloads crates from crates.io, and
the §7 gate compiles and runs code from the repository and from crates.io under the person's Windows account (build
scripts, more than 1,400 tests, Node test suites, a `yw-host.exe` process test) and writes the build folder (the gate
may use `%LOCALAPPDATA%\YourWallet-dev\target`). Do the static checks first, and run §5 and §7 only with the person's
go-ahead, optionally in Windows Sandbox or a virtual machine.

Commands are PowerShell, run from the repository root. `git grep` needs Git; without Git, use
`Get-ChildItem -Recurse -Include *.rs crates | Select-String -Pattern '<regex>'` instead.

---

## 0. Orientation (5 minutes)

Read these first, in this order:

1. [README.md](../README.md), English half ("English" section): features, "Security model", known limits.
2. [AGENTS.md](../AGENTS.md) §1 (repository map), §3 (hard rules) and §6 (security invariants).
3. [spec.md](../spec.md) §2 (threat model: §2.1 defended, §2.2 not defended), §3 (decisions D1–D38), §4 (architecture).

Architecture in one paragraph: `yw-app.exe` (Rust, Win32 GUI) holds the encrypted vault, shows every approval in its own
window and signs. `yw-host.exe` is started by Chrome as a native-messaging host and only relays framed JSON between
Chrome's stdio and a per-user named pipe to yw-app. The Chrome MV3 extension injects the page providers (EIP-1193 /
EIP-6963, Wallet Standard) and forwards requests; it holds no secrets.

| Crate | Role | `unsafe` |
|---|---|---|
| `crates/yw-core` | Wallet core: keys, vault, chain logic, risk rules, approvals. No network, files, threads or GUI | forbidden |
| `crates/yw-json` | Own strict JSON parser/writer and framing. Zero dependencies | forbidden |
| `crates/yw-win` | The only crate allowed `unsafe`: Windows API wrappers (WinHTTP, DPAPI, pipe, UI, …) | allowed, each block has a `// SAFETY:` comment |
| `crates/yw-app` | The wallet binary | forbidden |
| `crates/yw-host` | Native-messaging relay | forbidden |

Check the `unsafe` claim:

```powershell
git grep -n "forbid(unsafe_code)" -- crates
Select-String -Path Cargo.toml, crates\yw-win\Cargo.toml -Pattern 'unsafe_code'
```

Expected: `#![forbid(unsafe_code)]` in `yw-app` (lib and main), `yw-core`, `yw-host` (lib and main), `yw-json`; workspace
lint `unsafe_code = "forbid"` and `yw-win` overriding to `"deny"` with per-module allows.

---

## 1. Network: which hosts the app contacts

Claim (README "Privacy", spec.md D13/D21/D26): no telemetry, no crash upload, no wallet server. HTTPS only through
Windows WinHTTP with TLS 1.2/1.3, except an optional local LLM endpoint on loopback (`http://127.0.0.1`, `localhost`
or `[::1]`) over plain HTTP (D21, `crates/yw-app/src/explain/config.rs`).

### 1.1 Only WinHTTP opens connections

```powershell
git grep -n "WinHttpOpen(" -- crates
git grep -n "SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3" -- crates
git grep -nE "std::net|TcpStream|UdpSocket" -- crates
```

Expected:

- `WinHttpOpen(` only in `crates/yw-win/src/http.rs` (HTTP) and `crates/yw-win/src/ws.rs` (WebSocket, for WalletConnect).
- The TLS 1.2 | 1.3 protocol flags in both files.
- `std::net` only in tests, in `crates/yw-app/src/ui/tour.rs` (the developer screenshot tour's loopback server, bound
  to `127.0.0.1:0`; compiled only under `#[cfg(test)] #[cfg(debug_assertions)]`, `crates/yw-app/src/ui/mod.rs`), and in
  `crates/yw-core/clippy.toml`, which lists these types as **banned** in yw-core.

### 1.2 Fixed hosts compiled into the program

```powershell
git grep -nE 'const [A-Z_0-9]+: &str = "(https|wss)://' -- crates ':!crates/*/tests/*' ':!*tests*'
```

Expected hosts and why:

| Host | Where configured | When contacted |
|---|---|---|
| The user's RPC (QuickNode, Alchemy or any `https://` URL) | Entered by the user; URL templates in `crates/yw-app/src/apikeys.rs` and `crates/yw-app/src/app_rpc_import.rs`; stored DPAPI-encrypted | Balances, fees, simulation, sending |
| `mempool.space` (Esplora) | `crates/yw-core/src/btc/mod.rs`, `crates/yw-app/src/settings.rs`; changeable in 설정 → Bitcoin | Bitcoin address lookups and broadcast (keyless) |
| `api.hyperliquid.xyz`, `api.hyperliquid-testnet.xyz` | `crates/yw-core/src/hypercore/mod.rs` | HyperCore balances and user-signed transfers |
| `relay.walletconnect.org` (wss), `verify.walletconnect.org` | `crates/yw-core/src/walletconnect/mod.rs`, `crates/yw-app/src/walletconnect/verify.rs` | Only when WalletConnect is used with the user's own Reown Project ID (no default ID) |
| The user's LLM endpoint (e.g. OpenAI, Anthropic, OpenRouter, a local Ollama/LM Studio) | `crates/yw-app/src/explain/config.rs`, spec/06 §2 | Only when the optional AI explanation is turned on (off by default, D21). Zero calls when off |
| Block explorers (Etherscan, Solscan, mempool.space, …) | `crates/yw-app/src/explorer.rs` | Never fetched by the app. Opened in the default browser only when the user clicks `탐색기에서 열기` (open in explorer) |

The grep also prints `T_EXPLORER_RULES` in `crates/yw-app/src/ui/screens_explorer.rs`: a Korean help-text constant
with an example explorer link, not a contacted host.

Build time only (not the wallet): `static.rust-lang.org` (rustup toolchain), `crates.io` (crates pinned by checksum),
and winget sources if the user accepts installing tools.

### 1.3 No telemetry, no crash upload

```powershell
git grep -niwE "telemetry|analytics|sentry" -- crates extension/src
git grep -niE "crash.?report" -- crates extension/src
git grep -n "WerAddExcludedApplication" -- crates
```

Expected:

- First command: no output (whole words only; without `-w`, `ClassEntry` in `crates/yw-win/src/ui/window.rs` matches
  "sentry").
- Second command: two comments about the app **excluding itself** from Windows Error Reporting at start-up: a doc
  comment in `crates/yw-app/src/app.rs` and the banner shown if that fails, in `crates/yw-app/src/ui/screens.rs`.
- Third command: the actual call in `crates/yw-win/src/process.rs`, plus comments in `crates/yw-app/src/app.rs`.

### 1.4 The extension makes no network requests

```powershell
git grep -nE "fetch\(|XMLHttpRequest|WebSocket|sendBeacon|https?://" -- extension/src
```

Expected: no output. `scripts/audit-extension.mjs` enforces this (see §4).

---

## 2. Where secrets live

| Secret | Where | How protected | Read |
|---|---|---|---|
| Recovery phrases, imported private keys | `%LOCALAPPDATA%\YourWallet\v3\vault.ywv` (+ `.prev`) | Argon2id (m = 256 MiB, t = 3, p = 4) → HKDF → KEK wraps a random DEK with XChaCha20-Poly1305 | spec/02 §4, `crates/yw-core/src/vault/format.rs` |
| Accounts, address book, sites, activity | `meta.ywm`, `journal.ywj` | Encrypted with the vault DEK | spec/02 §5 |
| RPC URLs, provider tokens, LLM API key | `apikeys.dpapi` | Windows DPAPI: only this Windows user on this PC can decrypt | `crates/yw-app/src/apikeys.rs`, `crates/yw-win/src/dpapi.rs` |
| Settings | `settings.json` | Plain text, contains no secrets | spec/04 §6 |
| YubiKey wallet keys | On the YubiKey; the PC stores public keys only | Card PIN (never cached) and touch | spec/10, README "YubiKey" limits |

Further protections to confirm:

- While unlocked, only the DEK and passphrase stay in memory, in a VirtualLock-ed slot (`crates/yw-win/src/mem.rs`,
  AGENTS.md §6).
- The data folder gets a private DACL (user, SYSTEM, Administrators) and a Medium integrity label with no-write-up and
  no-read-up (`S:(ML;OICI;NRNW;;;ME)`), so low-integrity processes such as a browser sandbox can neither read nor write
  it (`crates/yw-win/src/security.rs`, spec/04 §1.4, [install.ko.md](install.ko.md) §7 "데이터 폴더 권한").
- Recovery-phrase and private-key windows use `WDA_EXCLUDEFROMCAPTURE`, read the setting back, and show nothing if
  exclusion fails (`SetWindowDisplayAffinity` in `crates/yw-win/src/ui/window.rs`, spec/04 §4.5, error E-SEC-001).
  `crates/yw-win/src/ui/capture.rs` is a different thing: a debug-build-only screenshot-tour helper
  (`#[cfg(debug_assertions)]`) whose `dev_tour_lift_capture_exclusion` removes the exclusion for the tour's fake
  data; it is not in release builds.
- Logs never contain secrets, RPC URLs, hosts or site origins (AGENTS.md hard rule 7, `crates/yw-app/src/logging.rs`).

```powershell
git grep -n "Argon2::new\|Params::new" -- crates/yw-core/src/vault
git grep -ln "CryptProtectData\|CryptUnprotectData" -- crates
```

Expected: Argon2id construction in `crates/yw-core/src/vault/format.rs` (plus a test helper in
`crates/yw-core/src/vault/tests.rs`); DPAPI calls only in `crates/yw-win/src/dpapi.rs`.

Honest limits (README "Security model"): no password retry lockout (the Argon2 cost is the only defence against
offline guessing of a copied vault); changing the password does not re-protect old copies of the vault; BitLocker is
recommended; malware running as the same Windows user, an admin/kernel compromise or physical access are out of scope.

---

## 3. The extension holds no secrets

```powershell
Get-Content extension\manifest.json
Get-Content extension\package.json
Get-ChildItem extension\src
```

Expected in `extension/manifest.json`:

- `"permissions": ["nativeMessaging", "storage"]` and nothing else; no `host_permissions`, `externally_connectable` or
  `web_accessible_resources`.
- `"incognito": "not_allowed"`, `"minimum_chrome_version": "120"`.
- Two content-script entries on `https://*/*`, `http://localhost/*`, `http://127.0.0.1/*`, top frame only
  (`all_frames: false`): `src/provider-main.js` in the `MAIN` world (page API), and `shared.js`, `content-core.js`,
  `content.js` in the `ISOLATED` world (bridge).
- Background: module service worker `src/background.js` (router, rate limits, deadlines).
- A `key` field that pins the extension ID `nnpjlobjgbanccjddghlpaafpohfkeph` (also in `extension/extension-id.txt`,
  `scripts/install.ps1` `$ExtensionId`, and an `include_str!` in yw-host and yw-app).

`extension/package.json` has no `dependencies` or `devDependencies` (zero npm packages), and there is no
`package-lock.json` or `node_modules`.

What `chrome.storage` holds: the compatibility-mode choice and a random per-profile install ID, nothing secret:

```powershell
git grep -n "chrome.storage" -- extension/src
```

localhost pages are served only when the app's localhost toggle is on (default off, D22).

### 3.1 Native host (yw-host) checks

File: `crates/yw-host/src/lib.rs`, spec/05 §7–§8.

| Check | Function |
|---|---|
| Chrome's caller argument must byte-equal `chrome-extension://nnpjlobjgbanccjddghlpaafpohfkeph/` | `check_args` |
| Pipe name `\\.\pipe\YourWallet.v3.<SID>` (per Windows user) | `pipe_name` |
| Pipe server owner SID equals the current user | `server_owner_trusted` |
| Server process is `yw-app.exe` next to yw-host, at Medium integrity or higher, before any data (the hello) is sent | `expected_app_image`, `server_process_trusted`, `handshake` |
| Connect deadline 10 s | `CONNECT_DEADLINE_MS`, `connect_app` |
| Hello/ack timeout 2 s | `HELLO_TIMEOUT_MS`, `run_with_deadline`, `handshake_with` |
| Auto-starts `yw-app.exe --background` only when `browserAutoLaunch` is on | `auto_launch_enabled_with`, `connect_app` |

yw-host links only `yw-json` and `yw-win` (`crates/yw-host/Cargo.toml`) and writes no log file.

---

## 4. Approval window and signing path

Nothing is signed without a decision in the app's own window. Files to read:

| What | Where |
|---|---|
| Approval digest and single-use `consume` (bound to bytes, chain, account, simulation, expiry) | `crates/yw-core/src/approval/`, spec/03 §11 (canonical for all chains) |
| Click-jacking defences: 1 s arm delay, focus starts on `거부` (Reject), High risk needs the checkbox "위 경고를 모두 확인했습니다" (I checked all warnings above) + 2 s hold of `승인` (Approve), injected Enter never approves, always-on-top, 120 s expiry | `crates/yw-app/src/ui/interaction.rs`, spec/04 §3 |
| EVM risk rules (E01–E43) and Blocked rules | `crates/yw-core/src/evm/risk/rules.rs`, spec/03 §10 |
| Solana dApp transactions (parser, ALT, decode, diff, display, sign; rules X01–X19) | `crates/yw-core/src/sol/dapp/`, spec/07 §20 |
| App glue for the approval window: issuing, re-simulation, `consume`, the `KeyJob::SignEvm` job | `crates/yw-app/src/app_approval.rs` (signing runs on the key worker, `crates/yw-app/src/workers/key.rs`) |
| EVM post-sign check: re-encode, strict decode, signer recovery must equal the account | `crates/yw-core/src/evm/sign/mod.rs` |
| dApp method allowlist and error codes | `crates/yw-core/src/policy`, spec/05 §3 and §5, [dapp-integration.md](dapp-integration.md) |

Key claims to confirm while reading: the display is built from the exact bytes to be signed (not the site's text);
simulation failure makes the request High risk (D15); `eth_sign` is not supported; EIP-7702 and contract deployment are
blocked; Solana unknown programs are flagged High risk, **not blocked** (D38).

---

## 5. Dependency pinning (supply chain)

```powershell
(Select-String -Path Cargo.lock -Pattern '^source = "registry').Count
(Select-String -Path Cargo.lock -Pattern '^checksum = ').Count
Get-Content Cargo.toml | Select-String '= \{ version = "='
Get-Content .cargo\config.toml
```

Expected:

- `54` registry crates, each with a `checksum` (README says 54 third-party crates).
- Every `[workspace.dependencies]` entry uses an exact `=` version with `default-features = false`.
- `.cargo/config.toml` adds only `--cfg curve25519_dalek_backend="serial"` and `/Brepro` (deterministic PE timestamps).
- The installer and the gate build with `--locked`, so `Cargo.lock` cannot change silently.

Per-crate allowlist: `scripts/check-core-deps.mjs`, object `POLICY`:

| Crate | Allowed |
|---|---|
| `yw-core` | RustCrypto hashes/MACs/KDFs, secp256k1, argon2, chacha20poly1305, ed25519/curve25519, getrandom, zeroize, subtle and their closure; local `yw-json` |
| `yw-json` | nothing |
| `yw-win` | `windows-sys` 0.61.2 / `windows-link` |
| `yw-app` | the above plus `qrcodegen` 1.8.0 |
| `yw-host` | `yw-json` and `yw-win` only |

Build scripts are allowed only for `generic-array`, `getrandom`, `secp256k1-sys`, `curve25519-dalek` and yw-app's own
link-args `build.rs`. To run the check (needs Node 22+ and cargo; reads `cargo metadata`):

```powershell
node scripts/check-core-deps.mjs
```

Expected: exit code 0 and no `not in allowlist` lines. On a fresh clone without cached crates, do not add `--offline`.

---

## 6. Privacy scan of the repository

```powershell
node scripts/privacy-scan.mjs
```

It scans tracked and untracked-not-ignored files for emails, drive-letter profile paths, provider key URLs
(QuickNode, Alchemy, Infura), `sk-` keys, `api_key=` values, authorization headers, labelled private keys and runs of
12+ BIP39 words. Expected: exit code 0. It does **not** catch wallet addresses or personal names; mention that limit.

---

## 7. The full gate (what CI-style checking covers)

Prerequisites: Rust via rustup (the repo's `rust-toolchain.toml` selects 1.95.0), Visual Studio C++ Build Tools, Node.js
22+, and none of `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`,
`CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS` set.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1
```

- On a fresh clone run it **without** `-Offline` (or run `cargo fetch --locked` first); `-Offline` is for when crates are
  already cached.
- One step only: `-Step fmt|deps|clippy|test|fuzz|build|ext-test|script-test|privacy|audit-ext|icons`.
- It takes a long time (1,400+ tests, and a debug-profile fuzz-lite smoke at 20,000 iterations per target). Success
  prints `check: OK`, exit 0.
- It compiles and runs repository and crate code (see the note at the top); run it only with the person's go-ahead.
- If the build folder has a Low integrity label or is a reparse point, the gate builds in
  `%LOCALAPPDATA%\YourWallet-dev\target` instead (a separate developer folder, not wallet data).

| Step | Exit on failure | Covers |
|---|---|---|
| fmt | 20 | `cargo fmt --check` |
| deps | 21 | `scripts/check-core-deps.mjs` allowlist (§5) |
| clippy | 22 | Lints with `-D warnings`, including yw-core's disallowed types (no time, file, network, threads, env) |
| test | 23 | Workspace tests (known-answer vectors, vault, approvals, risk rules, parsers, …) |
| fuzz | 29 | 22 fuzz-lite targets, `YW_FUZZ_RUNS=20000` |
| build | 24 | Debug build incl. `yw-host.exe` for the extension process test |
| ext-test | 25 | `node --test extension/tests/*.test.mjs` |
| script-test | 26 | `node --test scripts/*.test.mjs` (installer validation functions included) |
| privacy | 27 | §6 |
| audit-ext | 28 | `scripts/audit-extension.mjs`: exact permissions and manifest keys; bans `eval`, `Function`, dynamic import, `fetch`, `innerHTML` and URL literals; no unreferenced source files |
| icons | 30 | Committed icons equal the generator output |
| preconditions | 10, 11, 12 | Wrong cargo/Node version; RUSTFLAGS set; unusable build folder |

The gate does not cover: real RPC behaviour, real YubiKeys, real Chrome end-to-end, or the installer writing to the
real install folder. Those are manual checks in [acceptance/](acceptance/).

---

## 8. The installer itself

Read `scripts/install.ps1` (the header comment, lines 1–119 up to `#Requires`, lists everything it does and its exit codes) and
`scripts/uninstall.ps1`. Confirm that it writes only:

- `%LOCALAPPDATA%\Programs\YourWallet\` (exes, `extension\`, `uninstall.ps1`, `com.your_wallet.native.json`,
  `yw-install.json`);
- `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.your_wallet.native`;
- the Start menu shortcut `Your Wallet.lnk`;
- the clipboard (extension path), and the build folder (`target\` or `CARGO_TARGET_DIR`).

It never writes `%LOCALAPPDATA%\YourWallet\`, needs no administrator rights, runs winget only after the user types `Y`,
refuses sources, build folders and tools that other users can modify, and clears compiler-wrapper and `RUSTFLAGS`-style
variables for its build. `-DryRun` shows the plan without changing anything (safe to run during a review).

---

## 9. Known limits to tell the person

From [README.md](../README.md) "Security model" (Korean: "보안 범위") and spec.md §2.2:

- No third-party audit; personal-use scope; keep only what you can afford to lose.
- The configured RPC is trusted for balances, confirmations and simulation; one confirmation counts as final. If the
  RPC lacks `eth_simulateV1`, every EVM transaction is High risk. A lying RPC can mislead the display but cannot change
  the bytes that are signed.
- Solana dApp transactions: unknown programs are flagged, not blocked; a sign-only transaction can be broadcast by the
  site any time before it expires; a durable-nonce transaction never expires. Newest feature, live verification ongoing.
- YubiKey: no screen on the card, so the PC window is the only display. If the same recovery phrase is also in the PC
  vault, the YubiKey adds no protection.
- Compatibility modes (MetaMask, Rabby, Phantom, UniSat, Xverse look-alikes) are best-effort.
- No password retry lockout; BitLocker recommended.
- Malware as the same user, admin/kernel compromise and physical attacks are out of scope.

---

## 10. How to report your review to the person

Use this structure, in the person's language:

1. **What I checked** (list the sections above you actually ran or read, with commands and results).
2. **What I could not check** (for example: did not run the full gate; did not read every risk rule; cannot verify the
   binary you will build matches the source without building it yourself — which the installer does).
3. **Findings** (anything that differs from the "Expected" lines above, with file and line).
4. **Limits** (no third-party audit; AI review is not an audit; §9).
5. **Recommendation**: if they proceed, follow [llm-install-guide.md](llm-install-guide.md), testnet first, then small
   amounts ([first-use-checklist.ko.md](first-use-checklist.ko.md)).

Report suspected vulnerabilities through the project's GitHub repository (issues). Never include anyone's recovery
phrase, keys, passwords, RPC URLs or real wallet addresses in a report.
