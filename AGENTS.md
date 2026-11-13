# AGENTS.md — guide for AI coding agents

Your Wallet is a personal multichain software wallet for **Windows 11 x64 + Chrome**. The Rust app
(`yw-app.exe`) holds the keys, shows every approval in its own native window, and signs. A Chrome MV3
extension holds no secrets and only relays dApp requests to the app.
Chains: EVM (7 built-in + user-added), Solana, Bitcoin, Zcash (transparent), HyperCore. YubiKey 5 and
WalletConnect v2 are optional. It is distributed as source only.

The specs (`spec.md`, `spec/*.md`) are written in Korean and are **normative**. When this file and a
spec disagree, the spec wins, and `spec.md` wins over `spec/*.md`.
Status (spec.md line 3): implemented, manual verification pending.

---

## 1. Repository map

| Path | What it is |
|---|---|
| `Cargo.toml` | Workspace: version 0.3.0, edition 2024, `rust-version = "1.95"`, `license = "Apache-2.0 OR MIT"`, `publish = false`, exact-pinned `[workspace.dependencies]`, `[workspace.lints]`, release profile (LTO fat, `overflow-checks = true`, `panic = "abort"`) |
| `rust-toolchain.toml` | Pins toolchain `1.95.0` (+ clippy, rustfmt) |
| `rustfmt.toml`, `clippy.toml`, `crates/yw-core/clippy.toml` | Formatting (edition 2024, Unix newlines). MSRV and test unwrap allowances. yw-core's disallowed types and methods (no time, file, network, threads or env) |
| `.cargo/config.toml` | `--cfg curve25519_dalek_backend="serial"`, `/Brepro` (deterministic PE) |
| `crates/yw-core` | Platform-independent wallet core. No network, GUI, OS calls (except `getrandom`) or `unsafe`. Modules: `approval`, `bip32`, `bip39`, `btc`, `codec`, `entropy`, `evm` (abi, chain, decode, display, eip712, fee, risk, rlp, sign, simulate, siwe, tx), `hypercore`, `journal`, `keyimport`, `password`, `policy` (dApp `Method` table, `ProviderError`, grants), `secret`, `slip10`, `sol` (incl. `sol::dapp` legacy/v0 parser, ALT, decode, diff, display, sign; `msgsign`), `vault`, `walletconnect`, `yubikey` (incl. `mock` APDU emulator), `zec` |
| `crates/yw-json` | Own strict RFC 8259 JSON parser/writer + `frame` (4-byte LE length + payload, ≤ 1 MiB). Zero dependencies |
| `crates/yw-win` | The **only** crate allowed `unsafe` (windows-sys wrappers): clipboard, cng, dpapi, file, http (WinHTTP), image (GDI+), input, mem (`LockedBox`, wipe), pcsc, pipe, process, security, session, time, ui, ws (WebSocket) |
| `crates/yw-app` | The wallet binary (`windows_subsystem = "windows"`). `browser/` (dApp dispatcher, envelope v1, params, grants, pipe server), `walletconnect/`, `rpc/`, `flow/evm`, `sol/`, `btc/`, `zec/`, `explain/` (optional LLM explanation), `workers/`, `ui/` (main window, `approval.rs`, `approval_view.rs`, `interaction.rs`, `screens_*.rs`, `secret/`, `tour.rs`), `app_*.rs` feature glue, `settings.rs`, `apikeys.rs` (DPAPI), `logging.rs` |
| `crates/yw-host` | Chrome native-messaging host: a secret-less relay between stdio and the named pipe. Auto-starts yw-app when `browserAutoLaunch` is on |
| `crates/*/tests/` | Integration tests. Test placement rules: spec/09 §2.1. `#[ignore]` tests include fuzz-lite, live probes, the screenshot tour and the render harness |
| `extension/` | MV3 extension, **zero npm deps**. `manifest.json`. `src/provider-main.js` (MAIN world: EIP-1193, EIP-6963, Wallet Standard, Phantom/UniSat/Xverse shims). `src/shared.js` (the JS method table `METHOD_ROUTE`, JSON limits, origin rules). `src/content*.js`, `src/background*.js` (router, rate limits, deadlines). `src/popup*.js` + `popup/` (Korean compatibility-mode popup) |
| `extension/native-host/` | Golden JSON contracts shared by JS and Rust tests (`v1-methods`, `v1-request`, `v1-response-result`, `v1-event`, `v1-cancel`, `v1-limits`, `v1-origins`, `pipe-hello(-ack)` …), the host manifest template and `validate-manifest.mjs` |
| `extension/test-dapp/` | Manual E2E page (`serve.mjs` binds 127.0.0.1:5173 and [::1]:5173 only) |
| `extension/tests/` | `node --test` suites |
| `scripts/check.ps1` | **The repository gate** (§2) |
| `scripts/check-core-deps.mjs` | Per-crate dependency-closure allowlist |
| `scripts/privacy-scan.mjs` | Blocks personal data and secrets in tracked and untracked-not-ignored files |
| `scripts/audit-extension.mjs` | Static audit of the extension |
| `scripts/make-icons.mjs` | Generates `extension/icons/*.png`, `crates/yw-app/icons/yw-app.{ico,res}`, `docs/icon-preview.png` and the `PROVIDER_ICON` line in `extension/src/provider-main.js`. The gate's `icons` step (exit 30) compares all of them byte for byte, so never hand-edit any of them |
| `scripts/install.ps1`, `uninstall.ps1` (via `install.cmd` / `uninstall.cmd`) | Source installer. **Agents do not run these** (they write to the real install dir) |
| `scripts/screenshot-tour.ps1` | Regenerates `docs/screenshots/` with throwaway data |
| `scripts/probe-rpc.mjs`, `scripts/dev-rpc-setup.ps1` | Manual live-RPC tools for the owner. Not in the gate |
| `spec.md` | Goals, threat model §2, decisions **D1–D38** §3, architecture §4, milestones §5 |
| `spec/01-repo-build.md` | Workspace, dependency allowlist, lints, gate (§4.1), coding rules §5, yw-win API §7, source install §9 |
| `spec/02-core-keys-vault.md` | Entropy, BIP39/BIP32/SLIP-0010, vault v3 format, meta/journal schemas §5, lock state machine |
| `spec/03-evm.md` | Chains §1, tx model, simulation, decoding, EIP-712, SIWE, risk rules §10, **approval model and digest §11 (canonical for all chains)** |
| `spec/04-app-ui.md` | Screens, approval window §3, secret windows §4, auto-lock §5, settings, errors, logs, file locations §9, screenshot tour §11 |
| `spec/05-browser.md` | Extension, provider API, compatibility modes, method allowlist §3, permissions §4, **error codes §5 (canonical)**, envelope v1 §6, yw-host §7, pipe §8 |
| `spec/06` … `spec/13` | 06 LLM explanation · 07 Solana (§19 dApp connect/messages, §20 dApp transactions) · 08 Bitcoin · 09 testing · 10 YubiKey · 11 HyperCore · 12 Zcash · 13 WalletConnect |
| `docs/` | Install/recovery/first-use guides (Korean), `dapp-integration.md`, `security-review-20261101.md`, `ux-review-*.md`, `acceptance/` (per-milestone records), `screenshots/` |

---

## 2. Build, test, gate

Environment: Windows 11, PowerShell, Rust **1.95.0** (from `rust-toolchain.toml`), Node.js **22+**, VS C++
build tools. Cargo is always run `--locked`. Add `--offline` when the crates are already in the local cache.
`CARGO_TARGET_DIR` may be set to any folder.

```powershell
# Full gate (what must pass before a commit). -Offline adds --offline to cargo and the deps check.
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Offline

# One step: all | fmt | deps | clippy | test | fuzz | build | ext-test | script-test | privacy | audit-ext | icons
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Step clippy -Offline

# Plain commands
cargo build --release --locked
cargo test --workspace --locked --offline
cargo test -p yw-core --locked --offline --test policy        # one test file
node --test extension/tests/*.test.mjs                         # or `npm test` inside extension/
node --test scripts/*.test.mjs
```

Gate order and failure exit codes (`scripts/check.ps1`):
fmt 20 → deps 21 → clippy 22 (`-D warnings`) → test 23 → fuzz 29 → build 24 → ext-test 25 →
script-test 26 → privacy 27 → audit-ext 28 → icons 30. On success it prints `check: OK`.

- **fuzz** runs the `#[ignore]` `fuzz_lite_*` tests with `YW_FUZZ_RUNS=20000`. A direct
  `cargo test --release -- --ignored fuzz_lite` runs 1,000,000 iterations per target. There is no cargo-fuzz and no `fuzz/` dir.
- **build** produces `<target>\debug\yw-host.exe`, which the extension process test needs. The gate sets
  `YW_CHECK=1` so that test fails instead of being skipped.
- Precondition failures:
  - exit 10: cargo is not 1.95.0, or Node < 22
  - exit 11: any of `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`, `CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_RUSTFLAGS` is set (unset them)
  - exit 12: the build folder has a Low integrity label or is a reparse point, and the private fallback `%LOCALAPPDATA%\YourWallet-dev\target` is unusable
- The gate clears `RUSTC_WRAPPER` and similar variables for its run and forces `link.exe`.

Not run by the gate and only run on request (spec/09 §2.2, §2.5):

| What | Command |
|---|---|
| Screenshot tour (throwaway data, public test mnemonic, never the real data dir) | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/screenshot-tour.ps1 [-OutDir <folder>] [-SkipApp] [-SkipPopup]` |
| Scroll artefact check | `cargo test -p yw-app --lib ui::tour::scroll -- --ignored --nocapture` |
| Approval window render harness (no network, no keys) | `cargo test -p yw-app --lib app_approval::smoke -- --ignored` (`YW_SMOKE_FIXTURE`, `YW_SMOKE_HOLD_MS`) |
| Live RPC probes (**owner only**: they read `YW_RPC_JSON` or `%USERPROFILE%\.yw-dev\rpc.json`) | `node scripts/probe-rpc.mjs`, `cargo test -p yw-app --test live_probe -- --ignored --test-threads=1 --nocapture` |
| Test dApp (needs the app's localhost toggle on) | `node extension/test-dapp/serve.mjs` → `http://127.0.0.1:5173` |

Debug-only environment variables: `YW_FAULT_POINT` (abort at a named point, debug builds only), and
`YW_TEST_PIPE_NAME`, `YW_TEST_NO_SPAWN`, `YW_TEST_DATA_DIR` (yw-host tests).

---

## 3. Hard rules

These are not style preferences. Breaking one is a failed change.

1. **Dependencies are frozen.**
   - Do not add crates, features or `[dev-dependencies]`, and do not add a `build.rs` (only yw-app's link-args one exists).
   - Never run `cargo update`. `Cargo.lock` changes only when the owner asks.
   - Extension and scripts use Node built-ins only: no npm dependencies and no `package-lock.json`.
   - `scripts/check-core-deps.mjs` fails on any crate outside its allowlist.
2. **Never touch the real wallet or a real install.**
   - Do not read or write `%LOCALAPPDATA%\YourWallet` (vault, meta, journal, settings, `apikeys.dpapi`, logs) or `%LOCALAPPDATA%\Programs\YourWallet`.
   - Do not run `install.cmd` or `uninstall.cmd`.
   - Tests use temp folders.
3. **Never talk to a real YubiKey.** Use `yw_core::yubikey::mock`, the APDU-level emulator.
4. **Never broadcast a transaction or spend funds.** Live probes and manual checklists are run by the
   owner, not by agents. Never print or commit RPC URLs, tokens or API keys from any `rpc.json`, `apikeys.dpapi` or environment variable.
5. **No personal information in the repo.** `scripts/privacy-scan.mjs` scans every tracked and untracked file that is not ignored. It blocks:
   - email addresses (except the commit trailer's noreply address and `example.com` / `example.org`)
   - drive-letter `Users\<name>` profile paths. Write `%LOCALAPPDATA%`, `%USERPROFILE%` or `<user>` instead.
   - provider key URLs (QuickNode, Alchemy, Infura), `sk-` keys, `api_key=` values and authorization headers
   - labelled private keys, seed-phrase assignments and 12+ word BIP39 runs

   It scans only files with its listed extensions (`.md .rs .js .mjs .json .toml .txt .ps1 .cmd .yml .html .css .template` …).
   **Check by hand; the scan does not catch these:** real wallet addresses, balances and personal names. A wallet
   address that belongs to anyone is never allowed. Use public test vectors only.
6. **No binaries.** Source-only distribution (D1). The only committed binaries are generated assets:
   the icon files from `scripts/make-icons.mjs` (`extension/icons/*.png`, `crates/yw-app/icons/yw-app.{ico,res}`,
   `docs/icon-preview.png`) and screenshots from `scripts/screenshot-tour.ps1`.
7. **Secrets are never logged.**
   - The log API takes static event names and typed fields only. Never log secrets, API keys, RPC URLs or hosts, origins, raw dApp or RPC text, file paths or labels (spec/01 §5.4, D28).
   - Error `Display` text must not contain secrets, URLs or paths.
   - Addresses and tx hashes may appear in logs.
8. **Preserve line endings** (`.gitattributes`): `*.md *.rs *.toml *.js *.mjs *.json *.txt *.yml *.lock` are
   LF, and `*.ps1 *.cmd` are CRLF. Every `scripts/*.ps1` except `screenshot-tour.ps1` (`check`, `install`, `uninstall`, `dev-rpc-setup`) starts with a UTF-8 BOM. Keep whatever BOM a file already has.
9. **Do not add files under `extension/src/`** unless they are referenced. The extension audit fails on
   unreferenced executable source. Do not hand-edit `extension/icons/*.png`, `crates/yw-app/icons/yw-app.{ico,res}`,
   `docs/icon-preview.png` or the `PROVIDER_ICON` line in `extension/src/provider-main.js`; rerun `node scripts/make-icons.mjs`.
10. **Do not commit or push unless asked.** Do not rewrite history.

---

## 4. Conventions

- **Spec and code change together.** A behaviour change updates the owning spec section in the same commit.
  - D31 names the canonical owner: error codes in spec/05 §5, approval digest in spec/03 §11, data schemas in spec/02 §5.
  - Spec text is Korean. Cite specs as `spec/05 §3.6`, `[05] §2.13` or `D38`.
- **Dated rationale comments.** When a rule changes, say when and why, in code and spec, for example
  `(2026-11-12: …)` or `2026-11-12 전에는 …`. Keep the old behaviour visible in the note, not in dead code.
- **Language.**
  - UI strings (app windows, popup, page shim messages) are Korean.
  - dApp-facing JSON-RPC error messages are fixed English strings, copied exactly from spec/05 §5.
  - Code comments are mostly English. Scripts and specs are Korean.
- **Lints** (`[workspace.lints]`):
  - `unsafe_code = "forbid"`, except yw-win: `deny` plus a per-file `#![allow(unsafe_code)]` and a `// SAFETY:` comment on every block.
  - clippy `all` + `pedantic` are deny. Also denied: `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `print_stdout`, `print_stderr`, `dbg_macro`, `mem_forget`, `exit`.
  - Suppress per item only: `#[expect(clippy::<lint>, reason = "…")]`.
  - Parsers use `#![deny(clippy::indexing_slicing)]`. Length and amount math uses `arithmetic_side_effects`.
  - The gate runs clippy with `-D warnings`.
- **Errors** are hand-written enums with `Display` (no `thiserror`).
- **Golden contracts.** JS `METHOD_ROUTE` order equals `extension/native-host/v1-methods.golden.json`, which
  equals Rust `yw_core::policy::Method::ALL`. Change all three together.
- **Commit messages** follow Conventional Commits with a scope and a descriptive subject:
  - Examples: `feat(sol-dapp): step 6 — wire contract, dispatcher, …`, `fix(sol-dapp): step 8 review findings`, `docs(spec/05): …`, `test(ext): …`, `perf(ui): …`.
  - The body is a bulleted list naming the spec sections touched.
  - Review rounds are `fix(<scope>): step N review findings`.
  - End with the trailer `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>` when an agent wrote the commit.

---

## 5. Where to start for common tasks

### Add an EVM network
- **Most users need no code.** Settings → `EVM 체인 추가` adds a user chain with chainId, name, symbol, decimals,
  HTTPS RPC (or template) and explorer. The app checks `eth_chainId` and pins the block-0 hash (D14, spec/03 §1).
- **A new built-in chain** follows the pattern of commit `dd287c0` (Arbitrum/Base/BSC/Robinhood):
  - `crates/yw-core/src/evm/chain.rs`: chain id const, fixed genesis hash, `builtin_chains()` (array length), tip floor, default caps, token registry, known contracts.
  - `crates/yw-core/src/evm/fee.rs` if the chain has extra fees (Base's OP-stack L1 fee, spec/03 §3.4a).
  - `crates/yw-app/src/network.rs`, `settings.rs` (QuickNode subdomain, Alchemy label, explorer), `ui/screens_evm.rs`, `ui/screens.rs`, `ui/command_ids.rs`.
  - Tests: `crates/yw-core/tests/evm_consts.rs`, `crates/yw-app/tests/{apikeys,settings,browser_dispatch,evm_flow}.rs`.
  - `scripts/dev-rpc-setup.ps1` and `scripts/probe-rpc.mjs` network tables.
  - Specs: spec/03 §1.1 (+ §1.1a sources, §1.2 registry), `spec.md` D14, spec/04.
  - The count of built-in chains appears in prose. spec/05 §3.1, §4.3 and §5 still say "내장 3개"; fix them if you touch them.

### Add or change a dApp method
Change all of these in one commit:
1. `extension/src/shared.js` `METHOD_ROUTE`: the route is `permission`, `read` or `signing`, and the order matters.
2. `extension/native-host/v1-methods.golden.json`. Remove the method from its `rejected` list if it is there.
3. `crates/yw-core/src/policy/method.rs`: `Method` and `ALL: [Self; N]`.
4. Param validation:
   - EVM: `crates/yw-app/src/browser/params.rs`
   - Solana and Bitcoin: `crates/yw-app/src/browser/chain_params.rs` (+ `tests/fuzz_lite_chain_params.rs`)
5. Dispatch: `crates/yw-app/src/browser/dispatch.rs`, then the feature glue (`app_browser.rs`, `app_chain_sites.rs`, `app_sol_dapp.rs`, …).
6. Page API, if the page-facing surface changes: `extension/src/provider-main.js` + `extension/tests/provider-main.test.mjs`.
7. Tests: `extension/tests/shared.test.mjs`, `crates/yw-core/tests/policy.rs`, `crates/yw-app/tests/{browser_dispatch,browser_params,browser_chain_dispatch}.rs`.
8. Specs: spec/05 §3.1, §3.4 and §3.6 (keep the method count correct), plus §2.5 and §2.13 if the page API changed. Use existing `ProviderError` variants (spec/05 §5). A new variant changes the canonical error table.
9. WalletConnect, for an EVM method it should serve: `crates/yw-app/src/walletconnect/engine.rs` `WALLET_METHODS` + spec/13 §5.

The Solana dApp transaction series (`git log --grep=sol-dapp`, steps 1–8) is a complete worked example.

### Change how an approval is rendered
- **Display fields are built in yw-core** from the exact payload:
  - shared model, `FieldKey` and digests: `crates/yw-core/src/approval/`
  - per chain: `crates/yw-core/src/evm/display/`, `sol/display.rs`, `sol/dapp/display.rs`, `hypercore/display.rs`, btc/zec modules
- **Drawing is in yw-app**: `ui/approval.rs`, `ui/approval_view.rs`, `ui/text_layout.rs`, with glue in `app_approval.rs`.
- **Interaction rules are in `ui/interaction.rs`.** Do not weaken them (§6).
- Changing the field set changes the display digest. Update goldens on purpose:
  - `crates/yw-app/tests/approval_golden.rs`, `approval_interaction.rs`, `approval_sim_states.rs`
  - spec/09 §3.13
- Specs: spec/03 §11 (fields, digest) and spec/04 §3 (layout, interaction).
- Check visually with the render harness or the screenshot tour.

### Add a risk rule
- **One central table:** the `rules!` macro in `crates/yw-core/src/evm/risk/rules.rs`. Each entry has an id, family byte, level (`Info`, `Caution`, `High`, `Blocked`) and Korean base text.
- **Families and where each is evaluated:**

  | Family | Covers | Evaluated in |
  |---|---|---|
  | E | EVM tx | `evm/risk/mod.rs` |
  | T | typed data | `evm/eip712/`, `evm/risk/mod.rs` |
  | P, S | personal_sign, SIWE | `evm/eip191.rs`, `evm/siwe.rs`, `evm/risk/mod.rs` |
  | X | Solana dApp tx | `sol/dapp/decode.rs`, `sol/dapp/display.rs` |
  | W | SIWS | `sol/msgsign.rs` |
  | M | message-signing blocks | `sol/msgsign.rs`, `btc/msgsign.rs` |
  | C | WalletConnect | `crates/yw-app/src/walletconnect/mod.rs` |
  | H | HyperCore | `hypercore/display.rs` (the app's own transfers), `evm/risk/mod.rs` (dApp Hyperliquid typed data) |

- `ack_required` is derived only from the level: High means checkbox + 2 s hold. Use `Blocked` only for requests that must never be signed.
- **Document the rule in its spec table:**
  - spec/03 §10.2 (E), §10.3 (T), §10.4 (P, S)
  - spec/07 §20.6 (X), §19 (W, M)
  - spec/08 §17.3 (M03, M06: Bitcoin)
  - spec/11 §7 (H)
  - spec/13 §7 (C)

### Update screenshots
- Run `scripts/screenshot-tour.ps1`. The scenes are defined in `crates/yw-app/src/ui/tour.rs` (`screenshot_tour`).
- Add a dated note and the index line to `docs/screenshots/README.md`.
- All values are fake or public test vectors. Never put a real address, balance, RPC URL or key in a scene.

---

## 6. Security invariants you must not break

If a task seems to require breaking one of these, stop and ask the owner.

**Process and trust boundaries**
- **The extension holds no secrets.**
  - MV3 permissions are only `nativeMessaging` and `storage`. No `host_permissions`, `externally_connectable` or `web_accessible_resources`. `incognito: "not_allowed"`, top frame only.
  - The audit bans `eval`, `Function`, dynamic import, `fetch`, `innerHTML` and URL literals.
- **The origin comes only from Chrome's `port.sender`.** The page bridge is not a security boundary. yw-host is a relay that never reads message contents. yw-app re-validates route, origin and params (spec/05 §1).
- **Named pipe** `\\.\pipe\YourWallet.v3.<SID>`: current-user DACL, `FILE_FLAG_FIRST_PIPE_INSTANCE`, `PIPE_REJECT_REMOTE_CLIENTS`. yw-host verifies the server's owner SID, integrity level and image path before hello (D24, spec/05 §8.1).
- **`unsafe` only in yw-win.** yw-core stays free of network, GUI, file and time access.

**Approval window** (spec/04 §3.4–3.7, `crates/yw-app/src/ui/interaction.rs`)
- **Arm delay** `APPROVE_ARM_DELAY_MS = 1_000` after the window is ready and in the foreground. Any stray press while unarmed restarts the wait (any button, non-client clicks, key auto-repeat), and so does re-activation.
- **High risk** needs the checkbox + a 2 s continuous hold (`HIGH_RISK_HOLD_MS = 2_000`) by mouse or Space, on every chain.
- **Reject-first:** initial focus is `거부`. Auto-repeated Enter on Reject is ignored.
- **Enter:** ignored for High risk. Injected or posted Enter never approves (`physical` requires a real key-down that is not injected).
- **Window flags:** `WS_EX_TOPMOST` and `MA_ACTIVATEANDEAT`.
- **Expiry and lock:** the window expires 120 s after it is shown, and locking closes it as Rejected.
- **Display change:** clears the hold and checkbox and resets `ready_at`.
- **Queue limits:** 16 per origin, 64 total.
- **`can_approve` takes no AI or LLM state.** The LLM explanation never affects risk, digest or approval (D21), and when it is off it makes zero network calls.

**What you see is what you sign**
- **The display is built by yw-core from the exact signing payload.**
  - The sanitizer escapes bidi, zero-width and control characters as `[U+XXXX]`. yw-app re-checks and fails with E-UI-001.
  - Values are never truncated. Addresses are drawn whole.
- **Approval digest** (spec/03 §11.4): SHA-256 transcript over
  - id, kind, origin
  - chain tag, chain id / cluster / network, genesis
  - account, the exact payload bytes, display digest
  - simulation binding, expiry
- **Single use:** `consume` is one-shot and constant-time, and only it creates `Approved`, which the signing functions require. A Blocked request is never consumed.
- **Hard blocks stay hard.** Every rule whose level is `Blocked` in `evm/risk/rules.rs` must stay `Blocked`. Examples:
  - EVM: typed-data `domain.chainId` mismatch, SIWE domain ≠ origin, fee cap exceeded (E05), contract deploy, tx types 1/3/4 (EIP-7702), blobs
  - Solana: X01, SIWS W01–W04 and W07 (malformed SIWS)
  - message signing: M01, M03 (transaction bytes signed as a message), M02 (malformed Solana offchain header),
    M06 (Sign-In-With-Bitcoin domain mismatch)
- **Refused methods:** `eth_sign` is unsupported, and `wallet_addEthereumChain` is always 4200 (D14).
- **The wallet computes fees** and ignores dApp fee values. EVM gas ≤ 16,777,216. EIP-1559 type 2 only.
- **Simulation never changes the dApp response code.** A failed or missing simulation is High risk and is never hidden.
- **Post-sign check:** EVM recovers the signer and requires it to equal the account. The journal is written before broadcast (spec/03 §4.3, §5.3; spec/07 §20.8).
- **Solana dApp tx** (spec/07 §20.5, §20.10):
  - Never change the blockhash. Fill only the wallet's own signer slot. Re-parse the **approved** bytes before signing.
  - Re-check the site's grant just before replying (4100 otherwise). The provider checks that exactly one 64-byte slot changed.
  - Durable-nonce transactions are never sent.

**Secrets** (D11, spec/04 §4)
- **Mnemonic and private-key windows** require `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` and fail closed. Secrets are custom-drawn, never in OS EDIT controls, titles or tooltips.
- **Copying secrets is off by default.** When enabled, the copy is excluded from history and cloud sync and auto-clears after 30 s.
- **The approval window is not capture-excluded,** because it holds no secret.
- **Vault v3** (D7, spec/02 §4): Argon2id m = 256 MiB, t = 3, p = 4 → HKDF → KEK wraps a random DEK with XChaCha20-Poly1305 (header AAD). The pinned crypto crates and parameters do not change.
- **Memory:** only the DEK (and BIP39 passphrase) stays in a `VirtualLock` slot while unlocked. Everything else is derived per operation and zeroized.
- **RNG** is OS CSPRNG, fail-closed. Secret comparisons are constant-time.
- **Data folder:** protected DACL plus a Medium integrity label. Reparse points are rejected. Writes are atomic: temp → flush → `MoveFileExW` write-through.

---

## 7. Known stale spec text (fix only when you are already editing that section)

- spec/05 §3.1, §4.3 and §5 say the built-in EVM chains are "내장 3개". There are 7 (spec/03 §1.1, D14).
- `spec.md` D36 says Zcash WIF import is "phase 2". D9 says Zcash WIF/hex import is implemented.
- spec/04 §2.10 (address book rows) mentions "4자 묶음". Addresses are now drawn whole (spec/04 §3.3).

## 8. More documentation

- `README.md`: product overview (Korean + English).
- `docs/dapp-integration.md`: dApp-facing API reference (providers, methods, errors, limits).
- `llms.txt`: index of all docs for LLMs.
- `docs/security-review-20261101.md`: internal security review. Features added after 2026-11-01 were reviewed only per step.
- `docs/acceptance/`: per-milestone acceptance records.
