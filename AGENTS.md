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
| `LICENSE-APACHE`, `LICENSE-MIT` | License texts. The project is dual-licensed `Apache-2.0 OR MIT` (user's choice), with no warranty. `extension/package.json` carries the same `license` |
| `rust-toolchain.toml` | Pins toolchain `1.95.0` (+ clippy, rustfmt) |
| `rustfmt.toml`, `clippy.toml`, `crates/yw-core/clippy.toml`, `crates/yw-platform/clippy.toml`, `crates/yw-engine/clippy.toml` | Formatting (edition 2024, Unix newlines). MSRV and test unwrap allowances. yw-core's and yw-platform's disallowed types and methods (no time, file, network, threads or env). yw-engine's: no file, network, process, wall clock (`SystemTime`) or env; std threads and `Instant` are allowed (spec/01 §5.1) |
| `.cargo/config.toml` | `--cfg curve25519_dalek_backend="serial"`, `/Brepro` (deterministic PE) |
| `crates/yw-core` | Platform-independent wallet core. No network, GUI, OS calls (except `getrandom`) or `unsafe`. Modules: `approval`, `bip32`, `bip39`, `btc`, `codec`, `entropy`, `evm` (abi, chain, decode, display, eip712, fee, risk, rlp, sign, simulate, siwe, tx), `hypercore`, `journal`, `keyimport`, `password`, `policy` (dApp `Method` table, `ProviderError`, grants), `secret`, `slip10`, `sol` (incl. `sol::dapp` legacy/v0 parser, ALT, decode, diff, display, sign; `msgsign`), `vault`, `walletconnect`, `yubikey` (incl. `mock` APDU emulator), `zec` |
| `crates/yw-json` | Own strict RFC 8259 JSON parser/writer + `frame` (4-byte LE length + payload, ≤ 1 MiB). Zero dependencies |
| `crates/yw-platform` | Platform-neutral types and traits, zero dependencies, no OS calls or `unsafe` (2026-11-17): `http` (`HttpsUrl`, `LoopbackUrl`, `EndpointUrl`, `Timeouts`, `Response`, `HttpError`, request limits, `valid_header`, the `Transport` trait and its `HttpReply`), `ws` (`WsLink`, the relay socket trait) and `clock` (`Clock`, re-exported as `flow::evm::Clock`) |
| `crates/yw-engine` | Shared app logic for every platform shell (2026-11-17, spec/15 §11.4 S2; spec/01 §2.3b). Depends on yw-core, yw-json and yw-platform only, no `unsafe`, never yw-win (`cargo test -p yw-engine` builds neither yw-win nor windows-sys). S2 is done (2026-11-17); its modules: `errors` (`ErrorCode` + its texts), `text`, `network` (`NetworkId`), `logging` (log facade: format, sanitize, level, `LogSink`), `yubikey` (card operations, `CardSource`, `MockSource`), `wallet_files` (wallet file names, reset report), `secure_field` (secret input buffers), `approval` (queue, display re-checks and `labels`; `interaction` (arm delay, hold, Enter rules), `text` (approval window texts), `layout` (line breaking); since S4 B3 (2026-11-19) `flow` (the pure approval-flow decisions `status_action`, `session_deadline`, `connect_gate_count`, `bar_facts`, and the window ↔ flow types `ShownId`, `ApprovalInput`, `ApprovalSignal`, `ApprovalEffect`, `OpenOutcome`, not used yet at B3; 2026-11-19 S4 B5/B6: wired, `Effect::Approval`, `Cmd::Approval`/`ApprovalOpened`)), `badge` (chain badge), `catalogues` (its text catalogue registry). Since E2 also `settings`, `apikeys` (the plaintext format; DPAPI sealing stays in yw-app, in `app_store.rs` since 2026-11-20 S4 P1), `explorer`, `token_view`, `meta`, `hypercore`, `explain/` (optional LLM explanation), `rpc/`, `flow/evm`, `sol/`, `btc/`, `zec/`, `received/` and `walletconnect/` (`engine`, `store`, `verify`, `qr_decode`). Since E3 also `browser/` (dApp dispatcher, envelope v1, params, grants, read workers; not the pipe server), `walletconnect/worker.rs` (relay worker) and its unit tests, `events.rs`, `workers/` (`key`, `rpc`, `journal`; `workers/key/platform.rs`: the `KeyPlatform`/`WalletStore`/`KeyDeps` the key worker is given) and `approval/view.rs` (the A01 content model, was `ui/approval_view.rs`), plus `testkit` (`#[doc(hidden)]`, always compiled: test helpers the yw-app tests use across the crate boundary, e.g. `yubikey_wallet`; production code never names it, `card_pcsc::tests::testkit_is_named_only_by_tests`). yw-app re-exports the S2-moved modules under their old paths (`crate::errors`, `crate::settings`, `crate::ui::interaction`, `crate::workers`, …) until S4 (2026-11-18: was "until S3–S4"; S3 kept the facade unchanged). Since S3 (2026-11-18, spec/15 §11.4; done 2026-11-18) also `cmd/` (`Cmd`, `Press`, `Row`, `CopyMark`: shell input, no control id; one file per handler family with its `Press` sub-enum, e.g. `cmd/evm.rs` `EvmPress`; the transitional `Press::Legacy` went in S3 D3, 2026-11-18), `effect.rs` (`Effect`, `TimerId`) and `form.rs` (`EditField`, `FormState`, `FormSnapshot`, `CredField`, `PressInput`, and since S3 D1 (2026-11-18) `ClipInput`, the clipboard read the shell puts in `PressInput.clip`); their `Debug` prints names and lengths only. yw-app imports these three directly as `yw_engine::{cmd, effect, form}`. Since S4 P2 (2026-11-20) also `services.rs` (`Services`: the LLM transport factory, the `WalletConnect` platform parts `WcPlatform` and the relay user agent word, which the optional network workers start from; nothing is opened until a worker starts or the LLM connection test runs, D21) |
| `crates/yw-win` | The **only** crate allowed `unsafe` (windows-sys wrappers): clipboard, cng, dpapi, file, http (the WinHTTP `Client` only, which implements yw-platform `http::Transport`; its types are in yw-platform), image (GDI+), input, mem (`LockedBox`, wipe), pcsc, pipe, process, security, session, time, ui, ws (`WebSocket`, which implements yw-platform `ws::WsLink`) |
| `crates/yw-app` | The wallet binary (`windows_subsystem = "windows"`). `browser/` (a facade over yw-engine's `browser` plus the named-pipe server `server.rs`), `explain_transport.rs` (the `WinHTTP` transport of the LLM explanation; since 2026-11-20 S4 P2 its `llm_factory` is the Windows `Services::llm`, bundled with `app_walletconnect::WinWcPlatform` and `"windows"` by `app::windows_services`), `system_clock.rs` (the Windows `Clock`; since 2026-11-19 S4 B1a also `ArcClock`, which hands the App's `Arc<dyn Clock>` to the RPC and key workers), `store.rs` (`FileStorage`, `LockedSlotBox`, `WinKeyPlatform`), `ui/` (main window, `cmd_table.rs` (control id ↔ `Press` table, edit id ↔ `EditField`/`CredField`, the press input `capture`, 2026-11-18 S3), `tour_forms.rs` (the windowed form test, dev-only `#[ignore]`, 2026-11-18 S3), `approval_input.rs` (Win32 stray presses; since 2026-11-19 S4 B2 also the approval window's trusted input `TrustedSignals`, sampled only by its `sample*` functions, and the pure message map `map_msg`/`map_key` with its table tests `approval_input_tests.rs`), `screens_*.rs`, `secret/`, `tour.rs`; `ui::{approval, interaction, approval_text, text_layout, secure_field, badge, approval_view}` are re-exports of yw-engine), `app_*.rs` feature glue (`app_store.rs` is `WinAppStore`, the Windows `yw_engine::app_store::AppStore`: `settings.json` writes, the DPAPI seal of `apikeys.dpapi` with `APIKEYS_ENTROPY`, the `vault.ywv` facts, `.prev` checks and reset candidates (2026-11-20 S4 P1; before, `app.rs` sealed `apikeys.dpapi`); `app_effects.rs` is the `Effect` executor, 2026-11-18 S3; `approval_flow.rs` is the shown approval's flow state `ApprovalFlow` (item, preparation, the issued request, the gate and its session, the view; private fields, its methods are the only gate writers; 2026-11-19 S4 B4a, was part of `app_approval::ApprovalUi`; since B4b, the same day, also the AI explanation state `AiFlow` and the window's read model `ApprovalPaint`; the window's shell state is `app_approval::ApprovalWin` in `App.approval_win`, the flow is `EvmUi.approval`); `app_approval.rs` is the approval window A01 (its window procedures, `run_steps`, painting, and `apply_approval_effect`, the executor arm of `Effect::Approval`) and, until S4c W14, the flow's `impl App` half (`on_approval_input`/`approval_event` for `Cmd::Approval`, `show_next_approval` … `consume_and_sign`; 2026-11-20 S4a end); `app/tests/s3_census.rs` + `app/tests/s3_census/*.txt` are the S3 command census and its goldens; 2026-11-18 S4 A3–A7, all `cfg(test)`: `app_approval_flow_support.rs` (test clock, hidden approval windows, input log, shared fixture), `app_approval_flow_tests.rs`, `app_approval_lifecycle_tests.rs` and `app_approval_input_tests.rs` (the approval characterization run by gate step `winui`, named `s4fl` before 2026-11-20; since S4 B7 (2026-11-20) also `app_approval_headless_tests.rs`, the same flow and lifecycle scenarios with no window, golden `app/tests/s4_flow/headless.txt`, in the gate's test step, and `app_approval_headless_host.rs`, its `cfg(test)` host that records `Effect::Approval` instead of applying it) with their goldens `app/tests/s4_flow/*.txt`, and `ui/tour_secrets.rs` (the secret-session characterization, dev-only `#[ignore]`) with `app/secret_seam.rs` and the goldens `app/tests/s4_secret/*.txt`; 2026-11-19 S4 F-A: `app/tests/s4_frozen.rs`, a gate test that every test frozen at F-A keeps its leaf name and normalized body hash, listed in `app/tests/s4_flow/frozen-tests.txt`; since the F-A review (2026-11-19) also the non-test helpers of those files in `frozen-helpers.txt`, and gate step `s4fz` that they are compiled), `log_file.rs` (the rotating log file sink), `card_pcsc.rs` (the PC/SC transport and CNG cipher of `yubikey`). `errors`, `text`, `network`, `logging`, `yubikey`, `wallet_files` and (E2) `settings`, `apikeys`, `explorer`, `token_view`, `meta`, `hypercore`, `explain`, `rpc`, `flow`, `sol`, `btc`, `zec`, `received` and (E3) `events`, `walletconnect`, `workers` are re-exports of yw-engine (2026-11-17) |
| `crates/yw-host` | Chrome native-messaging host: a secret-less relay between stdio and the named pipe. Auto-starts yw-app when `browserAutoLaunch` is on |
| `crates/*/tests/` | Integration tests. Test placement rules: spec/09 §2.1. `#[ignore]` tests include fuzz-lite, live probes, the screenshot tour and the render harness (the S4 approval harness of gate step `winui` and the secret characterization are lib tests in yw-app `src`, row above). S4 phase A (2026-11-18) extended `crates/yw-engine/tests/approval_interaction.rs` (AP-7 edges, `fuzz_lite_approval_never_without_its_conditions`), `approval_golden.rs` (a golden for every `ApprovalKind`), `crates/yw-core/tests/evm_approval.rs` and `crates/yw-app/tests/approval_input.rs`; these, `approval_sim_states.rs` and `crates/yw-app/tests/btc_app_flow.rs` are frozen since F-A (2026-11-19, `app/tests/s4_flow/frozen-tests.txt`). Engine-only tests live in `crates/yw-engine/tests/` with the shared helpers (`common/`, `btc_support/`) and `fixtures/`; yw-app tests that need `App`, `store`, yw-win or live endpoints include those helpers with `#[path = "../../yw-engine/tests/common/mod.rs"]` |
| `extension/` | MV3 extension, **zero npm deps**. `manifest.json`. `src/provider-main.js` (MAIN world: EIP-1193, EIP-6963, Wallet Standard, Phantom/UniSat/Xverse shims). `src/shared.js` (the JS method table `METHOD_ROUTE`, JSON limits, origin rules). `src/content*.js`, `src/background*.js` (router, rate limits, deadlines). `src/popup*.js` + `popup/` (compatibility-mode popup with its own 한국어/English toggle) |
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
| `spec/06` … `spec/15` | 06 LLM explanation · 07 Solana (§19 dApp connect/messages, §20 dApp transactions) · 08 Bitcoin · 09 testing · 10 YubiKey · 11 HyperCore · 12 Zcash · 13 WalletConnect · 14 UI language (ko/en setting, text catalogues, canonical English texts §5) · 15 Android (D40, in progress: shared-crate split §11, phases §17) |
| `docs/` | Install/recovery/first-use guides (Korean), `dapp-integration.md`, `security-review-20261101.md`, `ux-review-*.md`, `acceptance/` (per-milestone records), `screenshots/` |

---

## 2. Build, test, gate

Environment: Windows 11, PowerShell, Rust **1.95.0** (from `rust-toolchain.toml`), Node.js **22+**, VS C++
build tools. Cargo is always run `--locked`. Add `--offline` when the crates are already in the local cache.
`CARGO_TARGET_DIR` may be set to any folder.

```powershell
# Full gate (what must pass before a commit). -Offline adds --offline to cargo and the deps check.
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Offline

# One step: all | fmt | deps | clippy | test | fuzz | winui | s4fz | build | ext-test | script-test | privacy | audit-ext | icons
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/check.ps1 -Step clippy -Offline

# Plain commands
cargo build --release --locked
cargo test --workspace --locked --offline
cargo test -p yw-core --locked --offline --test policy        # one test file
node --test extension/tests/*.test.mjs                         # or `npm test` inside extension/
node --test scripts/*.test.mjs
```

Gate order and failure exit codes (`scripts/check.ps1`):
fmt 20 → deps 21 → clippy 22 (`-D warnings`) → test 23 → fuzz 29 → winui 31 → s4fz 32 → build 24 →
ext-test 25 → script-test 26 → privacy 27 → audit-ext 28 → icons 30. On success it prints `check: OK`.

- **fuzz** runs the `#[ignore]` `fuzz_lite_*` tests with `YW_FUZZ_RUNS=20000`. A direct
  `cargo test --release -- --ignored fuzz_lite` runs 1,000,000 iterations per target. There is no cargo-fuzz and no `fuzz/` dir.
- **winui** (2026-11-18 S4 A3 as the temporary `s4fl`; 2026-11-20 S4 B7 renamed it and made it permanent, because the
  real Win32 re-entrancy of `reentry.txt` and the window traces of `input.txt`, `flow.txt` (`l1_*`, focus, Tab, panel
  clicks) and `lifecycle.txt` (`windows=N`) are the critique A-7/A-8 pins and no headless run can produce them; the
  headless half of the same scenarios, `headless.txt` cross-checked against `flow.txt`/`lifecycle.txt`, runs in the test
  step) runs the `#[ignore]` approval flow harness serially:
  `cargo test -p yw-app --lib --locked -- --ignored --test-threads=1 app_approval::flow_support app_approval::flow_tests app_approval::input_tests`.
  It creates hidden approval windows that are never shown and never take the foreground (its self-test checks that); the
  test clock (injected with `App::with_clock` since S4 B1a/B1b, 2026-11-19), the scripted trusted-signal oracle and the input log are `cfg(test)` seams in `app_approval_flow_support.rs`
  (spec/09 §2.2). Never put `fuzz_lite` in the path of such a test. A filter that matches nothing passes in libtest, so the
  step first lists the `#[ignore]` tests per filter and fails 31 below the minimum in `$WinuiMinimum` (2026-11-18 A3 review; `$S4flMinimum` before 2026-11-20);
  the commit that adds, removes or renames such tests (S4 A4, A5, A6) updates it. Since 2026-11-20 (S4 B7 review) the
  minimums are the real counts: flow_support 3, flow_tests 80 (79 windowed tests plus the windowless `print_headless`),
  input_tests 9; before, flow_tests stayed at phase A's 66, so 14 windowed tests could go without exit 31.
- **s4fz** (2026-11-19 S4 F-A review; kept for all of S4) checks that the frozen tests are compiled and run: it
  lists `cargo test --workspace -- --list` and `-- --list --ignored` with the test step's arguments, passes the
  compiled and ignored count of every frozen leaf name (`crates/yw-app/src/app/tests/s4_flow/frozen-tests.txt` and the
  `test` lines of `frozen-helpers.txt`) in `YW_S4_COMPILED`, and runs the `#[ignore]`
  `app::tests::s4_frozen::frozen_tests_are_compiled`, which fails 32 when a name has fewer compiled tests than
  `#[test]` fns in the sources (a `cfg`, a missing `mod`/`#[path]` line, `test = false`, a copy in a dead file) or
  fewer running than not `#[ignore]`d there. The frozen helpers (`frozen-helpers.txt`: the drivers are `fixed`, the
  rest only re-recorded by a planned S4 commit that names the line) are checked in the test step (spec/09 §2.1).
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
| Screenshot tour (throwaway data, public test mnemonic, never the real data dir) | `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/screenshot-tour.ps1 [-Lang ko\|en] [-OutDir <folder>] [-SkipApp] [-SkipPopup]` (`-Lang en` → `docs/screenshots/en/`) |
| Scroll artefact check | `cargo test -p yw-app --lib ui::tour::scroll -- --ignored --nocapture` |
| Approval window render harness (no network, no keys) | `cargo test -p yw-app --lib app_approval::smoke -- --ignored --test-threads=1` (`YW_SMOKE_FIXTURE`, `YW_SMOKE_HOLD_MS`; run it serially: two windows at once can end the hold test's hold, 2026-11-18) |
| Windowed form test (real main window, census temp data, no network or clipboard; spec/09 §2.1) | `cargo test -p yw-app --lib ui::tour_forms -- --ignored --test-threads=1 --nocapture` (must print `form_mismatch = 0, credential misses = 0`) |
| Windowed secret characterization (2026-11-18 S4 A7; real secret windows W02–W12 on the desktop, census temp data, public test vector, mock YubiKey, synthetic passwords/PINs, no clipboard or network; local console session only; spec/09 §2.2) | `cargo test -p yw-app --lib ui::tour_secrets --locked --offline -- --ignored --test-threads=1 --nocapture` (compares with `crates/yw-app/src/app/tests/s4_secret/{secret,lock}.txt`; a commit that touches secret windows before S4 P8 pastes its result line). Regenerate for review: `$env:YW_S4_SECRET_OUT='<folder>'` before the same command |
| Regenerate the S4 approval flow goldens (2026-11-18 S4 A3–A6; hidden approval windows, temp data only; gate step `winui` compares them; the headless golden `headless.txt` is compared in the test step and regenerated with `app_approval::flow_tests::lifecycle::headless::print_headless`, 2026-11-20 S4 B7) | `$env:YW_S4_FLOW_OUT='<folder>'; cargo test -p yw-app --lib --locked --offline -- --ignored --test-threads=1 app_approval::flow_tests::print app_approval::flow_tests::lifecycle::print app_approval::input_tests::print`, then compare with `crates/yw-app/src/app/tests/s4_flow/{flow,lifecycle,input,reentry}.txt` and review every changed line. Record twice with different `TMP`. After the owner's F-A checkpoint, only S4 F1/F2 may change their named lines. The frozen helpers: `$env:YW_S4_FLOW_OUT='<folder>'; cargo test -p yw-app --lib --locked --offline -- --ignored --exact app::tests::s4_frozen::print_frozen_helpers` (only in a commit a line's rule allows; never `frozen-tests.txt`, 2026-11-19) |
| Regenerate the S3 command census goldens (temp data only) | `$env:YW_S3_CENSUS_OUT='<folder>'; cargo test -p yw-app --lib s3_census::print --locked --offline -- --ignored`, then copy the files into `crates/yw-app/src/app/tests/s3_census/` and review every changed line |
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
  - UI strings come in Korean and English (spec/14, D39): every user-visible fixed text of the app is in a
    `texts!` catalogue (`NAME = "한국어" / "English";`) next to the module that uses it, registered in
    `yw_core::lang::catalogues()`, `yw_engine::catalogues::catalogues()` or `yw_app::catalogues::catalogues()`, and shown with the app language
    (`settings.language`; an approval window uses its own `lang`). `scripts/i18n-scan.mjs` fails on a Hangul
    string literal outside a catalogue in non-test code and on an unregistered catalogue. After changing a
    text, regenerate the spec/14 §5 tables with `print_spec14_tables` (`tests/lang_spec.rs`); error-code
    texts are listed in spec/04 §7 instead. The popup has its own toggle. Page shim messages are fixed English.
  - dApp-facing JSON-RPC error messages are fixed English strings, copied exactly from spec/05 §5.
  - Code comments are mostly English. Scripts and specs are Korean.
- **Lints** (`[workspace.lints]`):
  - `unsafe_code = "forbid"`, except yw-win: `deny` plus a per-file `#![allow(unsafe_code)]` and a `// SAFETY:` comment on every block.
  - clippy `all` + `pedantic` are deny. Also denied: `unwrap_used`, `expect_used`, `panic`, `todo`, `unimplemented`, `print_stdout`, `print_stderr`, `dbg_macro`, `mem_forget`, `exit`.
  - Suppress per item only: `#[expect(clippy::<lint>, reason = "…")]`. Exceptions are the shared test helpers in `crates/yw-engine/tests/{common,btc_support}/`, which several test binaries (yw-app's too) include: `#![allow(dead_code)]`, and `#[allow(clippy::disallowed_methods)]` on `common::evm::fixture`, because an `expect` of a yw-engine-only clippy.toml ban would be unfulfilled in yw-app.
  - Parsers use `#![deny(clippy::indexing_slicing)]`. Length and amount math uses `arithmetic_side_effects`.
  - The gate runs clippy with `-D warnings`.
- **Errors** are hand-written enums with `Display` (no `thiserror`).
- **The yw-engine split** (spec/15 §11, spec/01 §2.3b; S2 done 2026-11-17, S3 (`Cmd`, `Effect`, form state) done 2026-11-18; S4 is split into S4a–S4d, and S4a (approval safety net and the approval seam: `ApprovalFlow`/`ApprovalWin`, `Effect::Approval`, `Cmd::Approval`, the injected `Clock`) is done 2026-11-20, spec/15 §11.4 S4):
  - New platform-neutral app logic goes in `crates/yw-engine`, not yw-app. Never make yw-engine depend on yw-win; a trait that names yw-core types goes in yw-engine, one that needs only std and platform types goes in yw-platform, and yw-win implements it for its own types.
  - yw-app re-exports the moved modules under their old paths (`crate::settings`, `crate::ui::interaction`, `crate::browser::*`, …). This facade is transitional and goes in S4 (2026-11-18: was "S3–S4"; S3 left it unchanged): new code may use it, but do not add new re-exports. New code uses `yw_engine::…` paths directly, as S3's `yw_engine::{cmd, effect, form}` do.
  - `yw_engine::testkit` (`#[doc(hidden)]`, always compiled) holds test helpers that yw-app tests use across the crate boundary. Production code never names it or builds `yubikey::MockSource` (yw-app `card_pcsc` source scans). Do not put a raw vault or sidecar writer in it (owner decision); keep such helpers `#[cfg(test)]` where their tests live.
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
  - `crates/yw-engine/src/network.rs`, `crates/yw-engine/src/settings.rs` (QuickNode subdomain, Alchemy label, explorer), and in yw-app `ui/screens_evm.rs`, `ui/screens.rs`, `ui/command_ids.rs`.
  - Tests: `crates/yw-core/tests/evm_consts.rs`, `crates/yw-engine/tests/{apikeys,settings,browser_dispatch}.rs`, `crates/yw-app/tests/evm_flow.rs`.
  - `scripts/dev-rpc-setup.ps1` and `scripts/probe-rpc.mjs` network tables.
  - Specs: spec/03 §1.1 (+ §1.1a sources, §1.2 registry), `spec.md` D14, spec/04.
  - The count of built-in chains appears in prose. spec/05 §3.1, §4.3 and §5 still say "내장 3개"; fix them if you touch them.

### Add or change a dApp method
Change all of these in one commit:
1. `extension/src/shared.js` `METHOD_ROUTE`: the route is `permission`, `read` or `signing`, and the order matters.
2. `extension/native-host/v1-methods.golden.json`. Remove the method from its `rejected` list if it is there.
3. `crates/yw-core/src/policy/method.rs`: `Method` and `ALL: [Self; N]`.
4. Param validation:
   - EVM: `crates/yw-engine/src/browser/params.rs`
   - Solana and Bitcoin: `crates/yw-engine/src/browser/chain_params.rs` (+ `crates/yw-engine/tests/fuzz_lite_chain_params.rs`)
5. Dispatch: `crates/yw-engine/src/browser/dispatch.rs`, then the yw-app feature glue (`app_browser.rs`, `app_chain_sites.rs`, `app_sol_dapp.rs`, …).
6. Page API, if the page-facing surface changes: `extension/src/provider-main.js` + `extension/tests/provider-main.test.mjs`.
7. Tests: `extension/tests/shared.test.mjs`, `crates/yw-core/tests/policy.rs`, `crates/yw-engine/tests/{browser_dispatch,browser_params,browser_chain_dispatch}.rs`.
8. Specs: spec/05 §3.1, §3.4 and §3.6 (keep the method count correct), plus §2.5 and §2.13 if the page API changed. Use existing `ProviderError` variants (spec/05 §5). A new variant changes the canonical error table.
9. WalletConnect, for an EVM method it should serve: `crates/yw-engine/src/walletconnect/engine.rs` `WALLET_METHODS` + spec/13 §5.

The Solana dApp transaction series (`git log --grep=sol-dapp`, steps 1–8) is a complete worked example.

### Change how an approval is rendered
- **Flow or window first** (2026-11-20, S4a end; spec/04 §3.4 Z-a paragraph). A change to *what* is approved or *when* (gate, issue, consume, re-simulation, expiry, which signal does what) is a **flow** change: `approval_flow.rs` (`ApprovalFlow` methods), `App::on_approval_input`/`approval_event` and the flow functions of `app_approval.rs`, the pure decisions in `crates/yw-engine/src/approval/flow.rs`, the rules in `approval/interaction.rs`. A change to *how* it is drawn or *which Win32 message means what* is a **window** change: `app_approval.rs` painting, layout and `ApprovalWin`, the `Effect::Approval` executor arm, and `ui/approval_input.rs` (`TrustedSignals`, `map_msg`/`map_key`, `window_input`). The two meet only through `Cmd::Approval`/`Cmd::ApprovalOpened` and `Effect::Approval`; window code never holds the session, the gate, the issued request or `Approved` (source checks S3, S6, S8). A row of the spec/04 §3.4 table changes together with its table test `ui/approval_input_tests.rs`.
- **The approval goldens are frozen through S4** (spec/15 §11.4 S4, spec/09 §2.1): the windowed `crates/yw-app/src/app/tests/s4_flow/{flow,lifecycle,input,reentry}.txt` (gate step `winui`) and the headless `headless.txt` with its cross-check against `flow.txt`/`lifecycle.txt` (test step) gain lines only for the scenarios a planned S4 step names, and no line of them is changed or removed (the one exception was the owner-approved F1/F2 lines of `flow.txt`); a new or rewritten line is recorded twice with different `TMP`, byte-equal. The two hash files have their own rules (2026-11-20 Z-a review; `s4_frozen.rs`): `frozen-tests.txt` never changes. In `frozen-helpers.txt` a `fixed` line never changes; a `mutable` line is re-recorded or removed only by a planned S4 commit that names the line, its reason and the goldens it kept byte-equal; a commit-list line (`B2,B4a,B4b,B5`, `B2,B4a,B4b,B5,W14a,W14b,E1`) changes only in the listed steps (their commits and review fixes). Any other change to a frozen line stops for the owner; regenerate only for review (§2 table).
- **Display fields are built in yw-core** from the exact payload:
  - shared model, `FieldKey` and digests: `crates/yw-core/src/approval/`
  - per chain: `crates/yw-core/src/evm/display/`, `sol/display.rs`, `sol/dapp/display.rs`, `hypercore/display.rs`, btc/zec modules
- **The shown approval's flow state is yw-app `approval_flow.rs`** (`ApprovalFlow`, 2026-11-19 S4 B4a): its methods are the only writers of the gate, in the order of spec/04 §3.5; `issued` is the one request `consume` and `reject` use.
- **The approval window's operations are effects** (2026-11-19 S4 B5): the flow side emits `Effect::Approval` (`Open`/`Close`/`Rebuilt`/`RepaintBar`, and since B6 `Redraw`, the acknowledgement checkbox's repaint; `crates/yw-engine/src/approval/flow.rs` `ApprovalEffect`) and the executor applies it at once (`app_approval.rs` `apply_approval_effect`); the open is answered with `Cmd::ApprovalOpened` (`on_approval_opened`). The flow functions name no window (source check S6).
- **The window's inputs reach the flow as `Cmd::Approval`** (2026-11-19 S4 B6): one `ApprovalInput` (`ShownId` of the window that got the message, captured when that window was made in its `Forward`'s `Target`; the foreground sample for an event or the close box only; one `ApprovalSignal`), built only by `ui::approval_input::window_input` and sent by `app_approval.rs` `window_event`/`window_signal`; `on_approval_input` drops an input of a window that is not the shown one (critique A-12), and a connect toggle carries the `view_rev` its layout was drawn from (A-13). Source checks S6 and S8.
- **Drawing is in yw-app**: `app_approval.rs` paints from the flow's read model `ApprovalPaint` (2026-11-19 S4 B4b) with the shell state `ApprovalWin`, and the content model `crates/yw-engine/src/approval/view.rs` (re-exported as `ui::approval_view`). The queue and display re-checks (`crates/yw-engine/src/approval/mod.rs`), line breaking (`approval/layout.rs`) and, since S4 B3 (2026-11-19), the bottom bar's facts (`approval/flow.rs` `bar_facts`: countdown, hold progress, next step, button label) are in yw-engine.
- **Interaction rules are in `crates/yw-engine/src/approval/interaction.rs`** (the Win32 message → `InteractionEvent` mapping in yw-app `ui/approval_input.rs`: `TrustedSignals` sampled at the message, the pure `map_msg`/`map_key`, approving events built only by `Trusted::deliver` from its own sample (the sample's fields and `Trusted::event` are private, source checks S2 and S8); 2026-11-19 S4 B2, was `OtherPress` only). Do not weaken them (§6).
- Changing the field set changes the display digest. Update goldens on purpose:
  - `crates/yw-engine/tests/approval_golden.rs`, `approval_interaction.rs`, `approval_sim_states.rs`
  - spec/09 §3.13
- Specs: spec/03 §11 (fields, digest) and spec/04 §3 (layout, interaction).
- Check visually with the render harness or the screenshot tour.

### Add a risk rule
- **One central table:** the `rules!` macro in `crates/yw-core/src/evm/risk/rules.rs`. Each entry has an id, family byte, level (`Info`, `Caution`, `High`, `Blocked`) and Korean / English base text (spec/14 §5 lists the English).
- **Families and where each is evaluated:**

  | Family | Covers | Evaluated in |
  |---|---|---|
  | E | EVM tx | `evm/risk/mod.rs` |
  | T | typed data | `evm/eip712/`, `evm/risk/mod.rs` |
  | P, S | personal_sign, SIWE | `evm/eip191.rs`, `evm/siwe.rs`, `evm/risk/mod.rs` |
  | X | Solana dApp tx | `sol/dapp/decode.rs`, `sol/dapp/display.rs` |
  | W | SIWS | `sol/msgsign.rs` |
  | M | message-signing blocks | `sol/msgsign.rs`, `btc/msgsign.rs` |
  | C | WalletConnect | `crates/yw-engine/src/walletconnect/mod.rs` |
  | H | HyperCore | `hypercore/display.rs` (the app's own transfers), `evm/risk/mod.rs` (dApp Hyperliquid typed data) |

- `ack_required` is derived only from the level: High means checkbox + 2 s hold. Use `Blocked` only for requests that must never be signed.
- **Document the rule in its spec table:**
  - spec/03 §10.2 (E), §10.3 (T), §10.4 (P, S)
  - spec/07 §20.6 (X), §19 (W, M)
  - spec/08 §17.3 (M03, M06: Bitcoin)
  - spec/11 §7 (H)
  - spec/13 §7 (C)

### Add or change a main-window control
- **The control id** goes in the screen module's `ids` (`crates/yw-app/src/ui/screens_*.rs`, or the `ids` of `app_hidden`/`app_sidecar`) and its `FIXED` list (a new module's list is registered in `ui::command_ids::fixed()`; `app_rpc_import::ids` defines no ids of its own, its card's ids are core ids in `screens::ids::FIXED`), or in a row range of `ui::command_ids::ranges()` (`ranges_and_fixed_ids_are_disjoint` must stay green).
- **The press** is a variant of that family's enum in `crates/yw-engine/src/cmd/<family>.rs` (e.g. `EvmPress`), plain data only: a row is `Row`, a check box carries `Option<bool>`, a radio carries its value. No control id, window handle or secret text (spec/15 §11.4 S3).
- **Both directions of the table**: the module's `ids` `press_of`/`id_of` (per-family names where a module holds several families, e.g. `reset_press_of`/`ext_press_of` in `screens_reset`, `manage_press_of`/`connect_press_of` in `screens_yubikey`, each with its `*_id_of`) (`ui::cmd_table` already routes each family; a new family also needs a `Press` variant there and in `cmd_table::press_of`/`id_of`). The `ui::cmd_table` table tests round-trip every id.
- **The handler arm** goes in that family's handler (`App::on_<family>`, routed by `App::on_family`). Read plain edits with `App::form_text(EditField::…)`, never `controls.text`; write them with `Effect::SetField`/`ClearField`; repaint with `self.refresh()`.
- **A new edit** is an `EditField` in `crates/yw-engine/src/form.rs` (an entry in `EditField::ALL` and its read cap in `cap()`), a row in `cmd_table`'s field table (`FIELDS`) and, if its `EN_CHANGE` matters, an arm in `App::on_field_edit` (a `match field`). A masked credential edit is a `CredField` instead, listed in `cmd_table::creds_for` for every press whose handler reads it, and read with `App::read_cred`/`take_cred`. Never put a credential into `FormState`.
- **Census:** regenerate with `s3_census::print` (§2 table) and explain each changed golden line in the commit. Then run the windowed form test, and the screenshot tour if pixels may change.
- Specs: the screen's spec/04 section (and spec/14 texts); spec/04 §2.1 for the id map.

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

**Approval window** (spec/04 §3.4–3.7, `crates/yw-engine/src/approval/interaction.rs`, `crates/yw-app/src/ui/approval_input.rs` (`map_msg`/`map_key`, the spec/04 §3.4 table), `crates/yw-app/src/approval_flow.rs` (the only gate writer); 2026-11-20 S4a end)
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
- **Grant re-check before every dApp answer** (spec/05 §4.5): a signature (any chain) or an EVM tx hash goes to the
  site only while its grant still names the signer (4100 otherwise; a journaled tx is still broadcast). A `YubiKey`
  step still waiting for its PIN ends on a revoke (4100) or page cancel (4001) via `App::card_site_check`; a card
  job past its PIN is never aborted.
- **Solana dApp tx** (spec/07 §20.5, §20.10):
  - Never change the blockhash. Fill only the wallet's own signer slot. Re-parse the **approved** bytes before signing.
  - Re-check the site's grant just before replying (4100 otherwise). The provider checks that exactly one 64-byte slot changed.
  - Durable-nonce transactions are never sent.

**Secrets** (D11, spec/04 §4)
- **Mnemonic and private-key windows** require `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` and fail closed. Secrets are custom-drawn, never in OS EDIT controls, titles or tooltips.
- **Copying secrets is off by default.** When enabled, the copy is excluded from history and cloud sync and auto-clears after 30 s.
- **The approval window is not capture-excluded,** because it holds no secret.
- **Vault v3** (D7, spec/02 §4): Argon2id m = 256 MiB, t = 3, p = 4 → HKDF → KEK wraps a random DEK with XChaCha20-Poly1305 (header AAD). The pinned crypto crates and parameters do not change.
- **Every password change rotates the DEK** (spec/02 §4.4): no file the old password opens may ever hold the new DEK. The old DEK lives only in the transient `PrevDek` block (payload tag 7) of new-password files until meta, journal, every `.prev` and the E-VLT-006 set-aside copies are re-sealed; an interrupted rotation resumes on the next unlock or sidecar save. A sidecar this build cannot read refuses the change, and an unconfirmable `Rewrap` locks the session.
- **Memory:** only the DEK (and BIP39 passphrase) stays in a `VirtualLock` slot while unlocked. Everything else is derived per operation and zeroized.
- **RNG** is OS CSPRNG, fail-closed. Secret comparisons are constant-time.
- **Data folder:** protected DACL plus a Medium integrity label. Reparse points are rejected. Writes are atomic: temp → flush → `MoveFileExW` write-through.

---

## 7. Spec text and the code

The specs were reconciled with the code on 2026-11-13. If you find stale spec text later, fix it in the same commit as the behaviour it describes.

## 8. More documentation

- `README.md`: product overview (Korean + English).
- `docs/dapp-integration.md`: dApp-facing API reference (providers, methods, errors, limits).
- `llms.txt`: index of all docs for LLMs.
- `docs/llm-install-guide.md`, `docs/llm-verify-guide.md`, `docs/llm-user-faq.md`: guides for AI assistants helping an
  owner install, review and use the wallet on their own PC (not for coding agents; coding agents never run `install.cmd`).
- `docs/security-review-20261101.md`: internal security review. Features added after 2026-11-01 were reviewed only per step.
- `docs/acceptance/`: per-milestone acceptance records.
