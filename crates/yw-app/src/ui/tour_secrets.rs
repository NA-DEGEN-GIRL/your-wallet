//! Windowed secret-session characterization — **DEV ONLY** (`#[ignore]`, debug test builds,
//! like `ui::tour_forms`; 2026-11-18, S4 A7; spec/15 §11.4 S4, spec/04 §4, §5.3, spec/10 §9.2,
//! spec/09 §2.2): what the secret-window purposes do today, recorded before S4 moves the secret
//! windows behind a typed seam (P7a/P7b) and makes them headless (P8). The goldens are
//! `app/tests/s4_secret/secret.txt` (the purposes) and `app/tests/s4_secret/lock.txt` (one lock per
//! `LockReason` with a secret window, an approval window and the transient secret buffers held;
//! critique A-2, A-14), recorded from today's code (owner decision O-2, reviewed at F-A).
//!
//! Headless tests cannot see these paths: without a main window `create_secret` refuses every
//! window (E-SEC-001), so `secret_purpose()` is always `None` there. Here the App has its real
//! main window (created, never shown), and the secret windows W02–W12 are real windows on the
//! desktop: created, shown, capture-excluded by yw-win, closed and wiped by the App (W01 is not
//! opened: the first-run scenario enters its passwords through `App::test_submit`, the headless
//! harness's path; 2026-11-18, A7 review). Each
//! scenario runs on a thread of its own (the end-session lock runs the real shutdown, which posts
//! `WM_QUIT` to its thread).
//!
//! What each line holds (format: `<scenario> <step> | t=<ms since the fixture's start> | secret
//! W<nn> <purpose> topmost=<b> shown=<b> | form <flags and counts> | ops <secret-window
//! operations> | key <key jobs> | rpc <RPC jobs> | mode | screen | banners <codes> | info |
//! dapp <answers> | card <step> | yk-words | held <buffers> | approval <open|closed>`): window
//! kinds, purpose names, flags, unit counts, job names, error codes and hashes of fixed texts —
//! never a value. Every line is checked for that before it is kept ([`scan`]).
//!
//! Safety (the `ui::tour_forms` list, critique A-11): no worker is attached (no RPC,
//! `WalletConnect`, LLM or key worker runs; RPC jobs land in the fixture's channel, key jobs stay
//! queued and are only named), no browser bridge (the dApp requests of the card scenarios go
//! through the recorded outlet of `app_approval::flow_support`), explorer links go to
//! `Launcher::Record`, the census guard points `rpc.json` and the extension folder into a census
//! temp folder, and no message loop runs (no timer fires; the secret window's timer tick is
//! delivered by the test). The App's data folder is the flow fixture's own temp folder (S4 A3),
//! never `%LOCALAPPDATA%\YourWallet`. `allowSecretCopy` is never set and no copy or paste is
//! made, so the real clipboard is never touched (the clip clears are pinned through the
//! `cfg(test)` operation log only). The only secret shown is the public `abandon … about` test
//! vector (and, in W09, the private key 1); passwords and PINs are synthetic. The `YubiKey` is the
//! APDU emulator (`yw_engine`'s test kit, mock card wallet; no PC/SC reader, no card job runs).
//! The backup challenges come from a key worker run once on its own temp folder with a synthetic
//! password (its random words are never shown and are wiped with it). Approval windows are the
//! flow fixture's hidden windows (never visible, never the foreground).
//!
//! Preconditions (2026-11-18, A7 review): some columns come from the real desktop, so the goldens
//! hold only on a local console session (not RDP) of a Windows build where
//! `WDA_EXCLUDEFROMCAPTURE` works: `shown=` is the real `is_hidden_or_minimized`, `excluded=` the
//! real `SetWindowDisplayAffinity` result of yw-win, and a display window whose exclusion fails is
//! refused (E-SEC-001), which changes whole scenarios. The secret handler's Ctrl, Shift and Alt
//! reads are scripted "up" (`app::secret_seam::set_keys_up`), so a key held during the run does
//! not change the Esc and Enter lines; the typed text goes in as `WM_CHAR` messages, never through
//! the real keyboard.
//!
//! 2026-11-20 (S4 P8): the same scenarios also run headless in the gate's test step
//! (`app::tests::s4_secret::secret_sessions_run_headless`, byte-equal to the same goldens): this
//! module's `Env` switches on the recording secret host of `app::tests::s4_secret` (no main
//! window, the secret windows' forms held by the host, the approval windows answered by the
//! headless approval host, the main-window entries through `App::test_on_main_windowless`). In
//! this windowed run the host is the real shell's pass-through, and the refused steps set its
//! refusal (`host::refuse`; before P8 the seam's `TEST_SECRET_REFUSE`, `set_refuse`).
//!
//! Run: `cargo test -p yw-app --lib ui::tour_secrets --locked --offline -- --ignored
//! --test-threads=1 --nocapture`. Regenerate for review (PowerShell):
//! `$env:YW_S4_SECRET_OUT='<folder>'; cargo test -p yw-app --lib ui::tour_secrets --locked
//! --offline -- --ignored --test-threads=1`, then compare and review every changed line.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use yw_core::evm::address::parse_address;
use yw_core::policy::{BrowserOrigin, ConnectedSite};
use yw_core::secret::{SecretString, Zeroizing};
use yw_core::vault::{BackupChallenge, EvmKeySource, RecordId};
use yw_win::ui::{Handler, Msg, Reply, Window, WindowKind, WindowSpec, create_window};

use crate::app::App;
use crate::app::secret_seam::{self, Op, Refuse};
use crate::app::tests::s3_census::Census;
use crate::app::tests::s4_secret::host;
use crate::app_approval::flow_support::{Fixture, HostMode, Outlet, START_MS};
use crate::app_approval::headless_host::{self, OpenAnswer};
use crate::explorer_launcher::Launcher;
use crate::ui::secret::SECRET_TIMER_ID;
use yw_engine::events::{KeyJob, KeyOutcome, KeyResult, RevealWhat};
use yw_engine::secret::{CardSecretKind, DisplaySecret, SecretKind};
use yw_engine::wallet::app_mnemonics::MnPurpose;
use yw_engine::wallet::app_yubikey::YkPurpose;
use yw_engine::wallet::lock::LockReason;
use yw_engine::wallet::{AppMode, PasswordAction, Purpose};
use yw_engine::workers::key::mnemonics::MnOutcome;
use yw_engine::workers::key::yubikey::YkOutcome;
use yw_engine::workers::rpc::RpcJob;

pub(crate) const SECRET_GOLDEN: &str = include_str!("../app/tests/s4_secret/secret.txt");
pub(crate) const LOCK_GOLDEN: &str = include_str!("../app/tests/s4_secret/lock.txt");

/// Account 0 of the public `abandon … about` vector.
const ACCOUNT_A: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";
/// Account 1 of the same vector (the mock card wallet's `YubiKey` account).
const ACCOUNT_B: &str = "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0";
/// A synthetic vault password (never a real one).
pub(crate) const PASSWORD: &str = "synthetic-pass-0417";
/// A synthetic card PIN (not a factory value).
pub(crate) const PIN: &str = "135790";
/// The dApp site of the card scenarios.
const SITE: &str = "https://app.example";
/// The other texts a scenario types into a window ([`Env::type_text`] accepts only these,
/// [`PASSWORD`] and [`PIN`]); [`scan`] rejects each as a word of a golden line.
pub(crate) const TYPED: [&str; 4] = ["zoo", "word", "abc", "ab"];

// ----- values ---------------------------------------------------------------------------------

/// The public `abandon … about` test vector.
fn about_text() -> String {
    format!("{} about", ["abandon"; 11].join(" "))
}

fn about_secret() -> SecretString {
    let text = about_text();
    let mut secret = SecretString::with_capacity(text.len());
    secret.push_str(&text).unwrap();
    secret
}

/// The private key 1 (public test data) as W09 shows it.
fn key_one_secret() -> SecretString {
    let text = format!("{}1", "0".repeat(63));
    let mut secret = SecretString::with_capacity(text.len());
    secret.push_str(&text).unwrap();
    secret
}

fn bytes(text: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(text.as_bytes().to_vec())
}

fn address_a() -> yw_core::evm::address::Address {
    parse_address(ACCOUNT_A).unwrap()
}

/// A backup challenge of a real vault session: a key worker on its own temp folder creates a
/// wallet with [`PASSWORD`] (its random words are never shown and are wiped with the result) and
/// asks for the quiz; run once per process. The App does not check the id, so the same value
/// serves the wallet's quiz and an added phrase's.
fn backup_challenge() -> BackupChallenge {
    static CHALLENGE: OnceLock<BackupChallenge> = OnceLock::new();
    *CHALLENGE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!(
            "yw-s4-secret-challenge-{}-{}",
            std::process::id(),
            yw_win::time::monotonic_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let deps =
            crate::store::WinKeyPlatform::deps_with_cards(Box::new(yw_engine::yubikey::NoReaders));
        let mut worker = yw_engine::workers::key::KeyWorker::new(&dir, deps);
        let _ = worker.handle(KeyJob::Load);
        let created = worker.handle(KeyJob::CreateWallet {
            password: bytes(PASSWORD),
        });
        assert!(matches!(created.first(), Some(KeyOutcome::Created(Ok(_)))));
        drop(created);
        let challenge = worker
            .handle(KeyJob::BackupChallenge)
            .into_iter()
            .find_map(|outcome| match outcome {
                KeyOutcome::Challenge(Ok(challenge)) => Some(challenge),
                _ => None,
            })
            .expect("a backup challenge");
        drop(worker);
        let _ = std::fs::remove_dir_all(&dir);
        challenge
    })
}

/// The mock card wallet (an explicit `cfg(test)` module: `card_pcsc`'s source scan
/// `testkit_is_named_only_by_tests` lets only test modules name yw-engine's test kit).
#[cfg(test)]
mod card_wallet {
    /// Builds `yw_engine::testkit::yubikey_wallet` (the `abandon … about` vault with an enrolled
    /// emulator card) in `dir` with no card readers, and returns the wallet folder and its loaded
    /// meta; no card job runs (as `app_approval::flow_tests::lifecycle`).
    pub(super) fn meta(
        dir: std::path::PathBuf,
    ) -> (std::path::PathBuf, yw_engine::events::MetaLoaded) {
        let deps =
            crate::store::WinKeyPlatform::deps_with_cards(Box::new(yw_engine::yubikey::NoReaders));
        let (worker, _cards, wallet_dir, loaded) = yw_engine::testkit::yubikey_wallet(dir, deps);
        drop(worker);
        (wallet_dir, loaded)
    }
}

// ----- the environment ------------------------------------------------------------------------

/// A hidden window for the `window` argument of the main handler, and the stand-in for the real
/// secret window while a message is delivered to it.
struct Inert;

impl Handler for Inert {
    fn on(&mut self, _window: &Window, _msg: &Msg) -> Reply {
        Reply::Default
    }
}

fn spare() -> Window {
    create_window(
        &WindowSpec::new(crate::app_approval::PANEL_CLASS, WindowKind::Floating).size(64, 64),
        Box::new(Inert),
    )
    .unwrap()
}

/// One scenario: the flow fixture's App (hidden approval windows, the shared test clock, its own
/// temp data folder) with its real main window, the census guard, the operation log, and the
/// recorded lines.
struct Env {
    name: &'static str,
    fx: Fixture,
    _census: Census,
    outlet: Option<Outlet>,
    lines: Vec<String>,
    /// 2026-11-20 (S4 P8): the run is headless (no window at all: the secret host of
    /// `app::tests::s4_secret` holds the secret windows' forms and the approval windows are the
    /// headless approval host's).
    headless: bool,
}

impl Env {
    /// 2026-11-20 (S4 P8): headless when the headless runner (`app::tests::s4_secret`) installed
    /// the secret host on this thread as headless: no window class, no main window, the
    /// approval windows answered by the headless approval host. Else the windowed run as before,
    /// with the secret host installed as the real shell's pass-through (its refusals replace
    /// `TEST_SECRET_REFUSE`).
    fn new(name: &'static str, mode: AppMode) -> Self {
        let headless = host::headless();
        if !headless {
            super::tour::register_classes();
            host::install(false);
        }
        let census = Census::new("secrets");
        census.guard();
        let fx = Fixture::new(name, HostMode::Hidden);
        if headless {
            headless_host::install(OpenAnswer::Shown);
        } else {
            App::create_main_window(&fx.app).unwrap();
        }
        {
            let mut app = fx.app();
            app.mode = mode;
            assert!(matches!(app.launcher, Launcher::Record(_)));
            assert!(!app.settings.allow_secret_copy);
            if headless {
                assert!(app.main.is_none());
            } else {
                assert!(
                    app.main
                        .as_ref()
                        .is_some_and(Window::is_hidden_or_minimized)
                );
            }
        }
        secret_seam::start_log();
        secret_seam::set_keys_up(true);
        let _ = fx.key_jobs();
        let _ = fx.rpc_jobs();
        Self {
            name,
            fx,
            _census: census,
            outlet: None,
            lines: Vec::new(),
            headless,
        }
    }

    /// The serial of the open secret window (`0`: none).
    fn serial(&self) -> u64 {
        self.fx
            .app
            .borrow()
            .test_secret()
            .map_or(0, |facts| facts.serial)
    }

    /// `msg` for window `serial`, through the real secret handler (headless: through the secret
    /// host's copy of its window-free arms, 2026-11-20, S4 P8).
    fn msg(&self, serial: u64, msg: &Msg) -> &'static str {
        let reply = if self.headless {
            host::deliver(&mut self.fx.app(), serial, msg)
        } else {
            self.fx.app().test_secret_msg(serial, msg, spare())
        };
        match reply {
            Reply::Default => "default",
            Reply::Handled(_) => "handled",
        }
    }

    /// `text` typed into the open window (one `WM_CHAR` per unit).
    fn type_text(&self, text: &str) {
        assert!(
            text == PASSWORD || text == PIN || TYPED.contains(&text),
            "a typed text the scan does not know: add it to TYPED"
        );
        let serial = self.serial();
        for unit in text.encode_utf16() {
            let _ = self.msg(serial, &Msg::Char(unit));
        }
    }

    /// Enter (`WM_CHAR` 0x0D) in the open window.
    fn enter(&self) {
        let _ = self.msg(self.serial(), &Msg::Char(0x0D));
    }

    /// A key worker outcome of the current lock epoch, as the event drain delivers it.
    fn deliver(&self, outcome: KeyOutcome) {
        let mut app = self.fx.app();
        let epoch = app.lock_epoch;
        app.on_key_result(KeyResult { epoch, outcome });
    }

    /// The clock at `ms` after the fixture's start.
    fn at(&self, ms: u64) {
        self.fx.clock.set(START_MS + ms);
    }

    /// One main-window message through its handler (`on_main`; headless: its window-free arms,
    /// `test_on_main_windowless`, 2026-11-20, S4 P8).
    fn main_msg(&self, msg: &Msg) {
        if self.headless {
            let _ = self.fx.app().test_on_main_windowless(msg);
            return;
        }
        let window = spare();
        let _ = self.fx.app().test_on_main(&window, msg);
    }

    /// The main timer (`App::tick`).
    fn main_tick(&self) {
        if self.headless {
            let _ = self.fx.app().test_main_timer_windowless();
            return;
        }
        let window = spare();
        let _ = self.fx.app().test_main_timer(&window);
    }

    /// The shown Standard request approved as a user does (`Fixture::approve_standard`;
    /// headless: the same inputs without a window, 2026-11-20, S4 P8).
    fn approve_standard(&self) {
        if self.headless {
            self.fx.approve_standard_headless();
        } else {
            self.fx.approve_standard();
        }
    }

    fn fact(&mut self, what: &str, text: &str) {
        let line = format!("{} {what} | {text}", self.name);
        scan(&line);
        self.lines.push(line);
    }

    /// Records one line (format in the module doc).
    fn snap(&mut self, step: &str) {
        let ops = names(secret_seam::take_log().into_iter().map(Op::name));
        let keys = names(self.fx.key_jobs().iter().map(|job| job.name().to_owned()));
        let rpc = names(self.fx.rpc_jobs().iter().map(|job| job.name().to_owned()));
        let dapp = self
            .outlet
            .as_ref()
            .map_or_else(|| "-".to_owned(), dapp_answers);
        let t = self.fx.clock.peek().saturating_sub(START_MS);
        let app = self.fx.app.borrow();
        assert!(
            !app.settings.allow_secret_copy,
            "allowSecretCopy is never set"
        );
        let secret = app.test_secret().map_or_else(
            || "- | form -".to_owned(),
            |facts| {
                format!(
                    "{} {} topmost={} shown={} | form {}",
                    facts.kind,
                    purpose_name(facts.purpose),
                    facts
                        .topmost
                        .map_or_else(|| "?".to_owned(), |t| t.to_string()),
                    facts.shown,
                    facts.form
                )
            },
        );
        let held = app.test_held();
        let line = format!(
            "{} {step} | t=+{t} | secret {secret} | ops {ops} | key {keys} | rpc {rpc} | mode {} | screen {} | banners {} | info {} | dapp {dapp} | card {} | yk-words {:?} | held {} | approval {}",
            self.name,
            format!("{:?}", app.mode).replace(' ', ""),
            screen_name(&app.screen),
            banner_codes(&app),
            info_name(&app),
            card_fact(&app),
            app.yk_words,
            if held.is_empty() {
                "-".to_owned()
            } else {
                held.join(",")
            },
            if app.evm.approval.is_some() {
                "open"
            } else {
                "closed"
            },
        );
        if self.headless {
            // 2026-11-20 (S4 P8): the session's and the held form's `Debug`, for the scan.
            host::note_state(&app);
        }
        drop(app);
        scan(&line);
        self.lines.push(line);
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        secret_seam::stop();
        // 2026-11-20 (S4 P8): the hosts go with the scenario (a held form is wiped); a headless
        // run closes its approval window while the headless approval host still answers.
        if self.headless {
            if let Ok(mut app) = self.fx.app.try_borrow_mut() {
                app.close_approval_window();
            }
            headless_host::remove();
        }
        host::remove();
    }
}

/// Answers the lock's wait for the key worker (`LockSignal`, 1.5 s on `Suspend`, 5 s at the
/// shutdown) the way the worker would, so no scenario sleeps (as the A6 lifecycle tests).
struct LockAck {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LockAck {
    fn start(env: &Env) -> Self {
        let signal = Arc::clone(&env.fx.app.borrow().lock_signal);
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                signal.signal();
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for LockAck {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

// ----- formatting -----------------------------------------------------------------------------

fn names<S: AsRef<str>>(items: impl Iterator<Item = S>) -> String {
    let joined = items
        .map(|item| item.as_ref().to_owned())
        .collect::<Vec<_>>()
        .join(",");
    if joined.is_empty() {
        "-".to_owned()
    } else {
        joined
    }
}

/// The first 8 hex digits of the SHA-256 of `text`.
fn hash8(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for byte in yw_core::codec::sha256(text.as_bytes()).iter().take(4) {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The purpose's name (no record id, card step id or key data).
fn purpose_name(purpose: Purpose) -> String {
    match purpose {
        Purpose::ConfirmPassword(action) => format!(
            "ConfirmPassword/{}",
            match action {
                PasswordAction::RevealMnemonic { then_backup } => {
                    format!("RevealMnemonic(then_backup={then_backup})")
                }
                PasswordAction::RevealKey(_) => "RevealKey".to_owned(),
                PasswordAction::RemoveKey(_) => "RemoveKey".to_owned(),
                PasswordAction::RevealImported(_) => "RevealImported".to_owned(),
                PasswordAction::RevealBtcEvmShared { .. } => "RevealBtcEvmShared".to_owned(),
                PasswordAction::RemoveImported(_) => "RemoveImported".to_owned(),
                PasswordAction::RemoveHardwareKey(_) => "RemoveHardwareKey".to_owned(),
                PasswordAction::Recover => "Recover".to_owned(),
            }
        ),
        Purpose::ImportChainKey(_) => "ImportChainKey".to_owned(),
        Purpose::CardSign(_) => "CardSign".to_owned(),
        Purpose::YubiKey(yk) => format!("YubiKey/{yk:?}"),
        Purpose::Mnemonics(mn) => format!(
            "Mnemonics/{}",
            match mn {
                MnPurpose::ImportWords => "ImportWords".to_owned(),
                MnPurpose::ImportPassphrase => "ImportPassphrase".to_owned(),
                MnPurpose::ImportPassword => "ImportPassword".to_owned(),
                MnPurpose::CreatePassword => "CreatePassword".to_owned(),
                MnPurpose::ShowWords(_, quiz) => format!("ShowWords(quiz={quiz})"),
                MnPurpose::Backup(_) => "Backup".to_owned(),
                MnPurpose::RevealPassword(_, quiz) => format!("RevealPassword(quiz={quiz})"),
                MnPurpose::RemovePassword(_) => "RemovePassword".to_owned(),
            }
        ),
        other => format!("{other:?}"),
    }
}

/// The screen's variant; one that carries text is named with a hash of its `Debug`.
fn screen_name(screen: &yw_engine::wallet::Screen) -> String {
    let debug = format!("{screen:?}");
    if debug.contains(['"', ':', '{', '(']) {
        let name: String = debug
            .chars()
            .take_while(char::is_ascii_alphanumeric)
            .collect();
        format!("{name}#{}", hash8(&debug))
    } else {
        debug
    }
}

/// The banners' codes in order (a banner without a code: `notice#<hash of its text>`).
fn banner_codes(app: &App) -> String {
    names(app.banners.iter().map(|banner| {
        banner.code.map_or_else(
            || format!("notice#{}", hash8(&banner.text)),
            |code| code.code().to_owned(),
        )
    }))
}

/// The information line: `T-TIMED-OUT`, another text by its hash, or `-`.
fn info_name(app: &App) -> String {
    match app.info.as_deref() {
        None => "-".to_owned(),
        Some(info) if info == yw_engine::wallet::text::TIMED_OUT.get(app.settings.language) => {
            "T-TIMED-OUT".to_owned()
        }
        Some(info) => format!("#{}", hash8(info)),
    }
}

/// The `YubiKey` card step: none, waiting for its PIN, or past it.
fn card_fact(app: &App) -> &'static str {
    match app.card.step.as_ref() {
        None => "-",
        Some(step) if step.holds_approval() => "waiting-for-pin",
        Some(_) => "past-pin",
    }
}

fn dapp_answers(outlet: &Outlet) -> String {
    names(outlet.answers().into_iter().map(|answer| match answer {
        Ok(_) => "result".to_owned(),
        Err(error) => format!("{} {}", error.code(), error.message()),
    }))
}

/// A golden line holds no value: ASCII only, no address, URL, e-mail, path, the test vector's
/// words, the synthetic password or PIN, no text a scenario types (as a word: `Password` and
/// `yk-words` are names), and no run of 32 or more hex digits (a key without `0x`, such as W09's
/// key 1; 2026-11-18, A7 review).
pub(crate) fn scan(line: &str) {
    assert!(line.is_ascii(), "non-ASCII text in {line}");
    for banned in [
        "0x", "://", "@", "\\", "Users", ".example", "rpc.json", "abandon", PASSWORD, PIN,
    ] {
        assert!(!line.contains(banned), "{banned:?} in {line}");
    }
    for word in line.split(|c: char| !c.is_ascii_alphanumeric()) {
        assert!(
            !["abandon", "about"].contains(&word) && !TYPED.contains(&word),
            "{word:?} in {line}"
        );
    }
    let mut run = 0_usize;
    for c in line.chars() {
        run = if c.is_ascii_hexdigit() { run + 1 } else { 0 };
        assert!(run < 32, "a run of 32 hex digits in {line}");
    }
}

// ----- the purposes (secret.txt) --------------------------------------------------------------

const UNLOCKED: AppMode = AppMode::Unlocked {
    alt_passphrase: false,
};

/// W03 of `RevealMnemonic { then_backup: true }` → the password → `Revealed` opens W08
/// `ShowForBackup` (create); its close box cancels it to S04 (scout E §5.1).
fn reveal_words_then_backup() -> Vec<String> {
    let mut env = Env::new("reveal_words_then_backup", UNLOCKED);
    env.fx.app().open_input(
        SecretKind::ConfirmPassword,
        Purpose::ConfirmPassword(PasswordAction::RevealMnemonic { then_backup: true }),
        false,
    );
    env.snap("w03-open");
    env.type_text(PASSWORD);
    env.snap("typed");
    env.enter();
    env.snap("submitted");
    env.deliver(KeyOutcome::Revealed(Ok((
        RevealWhat::Mnemonic,
        about_secret(),
        Some(address_a()),
    ))));
    env.snap("revealed");
    let _ = env.msg(env.serial(), &Msg::Close);
    env.snap("close-box");
    std::mem::take(&mut env.lines)
}

/// The same without the quiz: W08 `ShowRevealed`, closed by its close box (`닫기`).
fn reveal_words_plain() -> Vec<String> {
    let mut env = Env::new("reveal_words_plain", UNLOCKED);
    env.fx.app().open_input(
        SecretKind::ConfirmPassword,
        Purpose::ConfirmPassword(PasswordAction::RevealMnemonic { then_backup: false }),
        false,
    );
    env.type_text(PASSWORD);
    env.enter();
    env.snap("submitted");
    env.deliver(KeyOutcome::Revealed(Ok((
        RevealWhat::Mnemonic,
        about_secret(),
        Some(address_a()),
    ))));
    env.snap("revealed");
    let _ = env.msg(env.serial(), &Msg::Close);
    env.snap("close-box");
    std::mem::take(&mut env.lines)
}

/// A private key: W03 `RevealKey` → W09 `ShowRevealed`; Esc closes it.
fn reveal_key() -> Vec<String> {
    let mut env = Env::new("reveal_key", UNLOCKED);
    let source = EvmKeySource::Derived(yw_core::bip32::path::AccountIndex::ZERO);
    env.fx.app().open_input(
        SecretKind::ConfirmPassword,
        Purpose::ConfirmPassword(PasswordAction::RevealKey(source)),
        false,
    );
    env.type_text(PASSWORD);
    env.enter();
    env.snap("submitted");
    env.deliver(KeyOutcome::Revealed(Ok((
        RevealWhat::PrivateKey(source),
        key_one_secret(),
        Some(address_a()),
    ))));
    env.snap("revealed");
    let _ = env.msg(
        env.serial(),
        &Msg::KeyDown {
            vk: 0x1B,
            repeat: false,
        },
    );
    env.snap("esc");
    std::mem::take(&mut env.lines)
}

/// A new wallet's words (`Created`): a display window refused by capture exclusion drops the
/// words, says E-SEC-001 and stays on S04 (`BackupPending`); a failed window (`UiError::Os`) also
/// drops them with E-SEC-001 (the refuse branch: `open_display`'s E-APP-009 arm is unreachable for
/// W08/W09); a shown one is W08 `ShowForBackup` (create).
fn created_words_display() -> Vec<String> {
    let mut env = Env::new("created_words_display", AppMode::Starting);
    host::refuse(Some(Refuse::Exclusion));
    env.deliver(KeyOutcome::Created(Ok((about_secret(), address_a()))));
    env.snap("refused-exclusion");
    host::refuse(Some(Refuse::Os));
    env.deliver(KeyOutcome::Created(Ok((about_secret(), address_a()))));
    env.snap("refused-os");
    host::refuse(None);
    env.deliver(KeyOutcome::Created(Ok((about_secret(), address_a()))));
    env.snap("shown");
    std::mem::take(&mut env.lines)
}

/// An input window refused: as with no main window (E-SEC-001) and as a failed window
/// (E-APP-009); nothing is shown or held.
fn input_refused() -> Vec<String> {
    let mut env = Env::new("input_refused", AppMode::Locked);
    host::refuse(Some(Refuse::Exclusion));
    env.fx
        .app()
        .open_input(SecretKind::Unlock, Purpose::Unlock, false);
    env.snap("unlock-exclusion");
    host::refuse(Some(Refuse::Os));
    env.fx
        .app()
        .open_input(SecretKind::Unlock, Purpose::Unlock, false);
    env.snap("unlock-os");
    host::refuse(None);
    env.fx
        .app()
        .open_input(SecretKind::Unlock, Purpose::Unlock, false);
    env.snap("unlock-shown");
    std::mem::take(&mut env.lines)
}

/// The wallet's quiz: a challenge opens W10; a new challenge while W10 is open resets it in
/// place (`reset_backup`, no new window); Esc ends it on S04.
fn challenge_opens_or_resets_w10() -> Vec<String> {
    let mut env = Env::new("challenge_opens_or_resets_w10", AppMode::BackupPending);
    let challenge = backup_challenge();
    env.deliver(KeyOutcome::Challenge(Ok(challenge)));
    env.snap("challenge");
    env.type_text("zoo");
    env.deliver(KeyOutcome::Challenge(Ok(challenge)));
    env.snap("challenge-again");
    let _ = env.msg(
        env.serial(),
        &Msg::KeyDown {
            vk: 0x1B,
            repeat: false,
        },
    );
    env.snap("esc");
    std::mem::take(&mut env.lines)
}

/// An added phrase's quiz (`app_mnemonics`): the same with `MnOutcome::Challenge`.
fn mn_challenge_opens_or_resets_w10() -> Vec<String> {
    let mut env = Env::new("mn_challenge_opens_or_resets_w10", UNLOCKED);
    let challenge = backup_challenge();
    let id = RecordId::from_bytes([7; 16]);
    env.deliver(KeyOutcome::Mnemonics(MnOutcome::Challenge(Ok((
        id, challenge,
    )))));
    env.snap("challenge");
    env.type_text("zoo");
    env.deliver(KeyOutcome::Mnemonics(MnOutcome::Challenge(Ok((
        id, challenge,
    )))));
    env.snap("challenge-again");
    let _ = env.msg(
        env.serial(),
        &Msg::KeyDown {
            vk: 0x1B,
            repeat: false,
        },
    );
    env.snap("esc");
    std::mem::take(&mut env.lines)
}

/// The new `YubiKey` wallet's quiz (`app_yubikey`): the same with `YkOutcome::Challenge`.
fn yk_challenge_opens_or_resets_w10() -> Vec<String> {
    let mut env = Env::new("yk_challenge_opens_or_resets_w10", AppMode::NoVault);
    let positions = backup_challenge().positions;
    env.deliver(KeyOutcome::YubiKey(YkOutcome::Challenge(Ok(positions))));
    env.snap("challenge");
    env.type_text("zoo");
    env.deliver(KeyOutcome::YubiKey(YkOutcome::Challenge(Ok(positions))));
    env.snap("challenge-again");
    let _ = env.msg(
        env.serial(),
        &Msg::KeyDown {
            vk: 0x1B,
            repeat: false,
        },
    );
    env.snap("esc");
    std::mem::take(&mut env.lines)
}

/// W12 reads the card's PIN counters only when it was shown (`yk_open_card_secret`): shown →
/// `YkCounters`; refused (E-SEC-001 / E-APP-009) → no card read.
fn yk_card_secret_counters_only_when_shown() -> Vec<String> {
    let mut env = Env::new("yk_card_secret_counters_only_when_shown", UNLOCKED);
    env.fx
        .app()
        .yk_open_card_secret(CardSecretKind::AdminPin, YkPurpose::AdminPin, 7_700_011);
    env.snap("shown");
    let _ = env.msg(
        env.serial(),
        &Msg::KeyDown {
            vk: 0x1B,
            repeat: false,
        },
    );
    env.snap("esc");
    for (refuse, step) in [
        (Refuse::Exclusion, "refused-exclusion"),
        (Refuse::Os, "refused-os"),
    ] {
        host::refuse(Some(refuse));
        env.fx
            .app()
            .yk_open_card_secret(CardSecretKind::AdminPin, YkPurpose::AdminPin, 7_700_011);
        env.snap(step);
    }
    std::mem::take(&mut env.lines)
}

/// A new `YubiKey` wallet's words: `yk_words = Shown` only when W08 was shown; the window's own
/// timeout then leaves no T-TIMED-OUT (the words band says it).
fn yk_words_shown_only_when_w08_shown() -> Vec<String> {
    let mut env = Env::new("yk_words_shown_only_when_w08_shown", AppMode::NoVault);
    host::refuse(Some(Refuse::Exclusion));
    env.deliver(KeyOutcome::YubiKey(YkOutcome::Words(Ok((
        about_secret(),
        address_a(),
    )))));
    env.snap("refused");
    host::refuse(None);
    env.deliver(KeyOutcome::YubiKey(YkOutcome::Words(Ok((
        about_secret(),
        address_a(),
    )))));
    env.snap("shown");
    env.at(300_000);
    let _ = env.msg(env.serial(), &Msg::Timer(SECRET_TIMER_ID));
    env.snap("timed-out");
    std::mem::take(&mut env.lines)
}

/// An input window's 300 s timeout: T-TIMED-OUT after the cancel (not at 299 999 ms).
fn timed_out_notice() -> Vec<String> {
    let mut env = Env::new("timed_out_notice", UNLOCKED);
    env.fx.app().open_input(
        SecretKind::ConfirmPassword,
        Purpose::ConfirmPassword(PasswordAction::RevealMnemonic { then_backup: false }),
        false,
    );
    env.snap("open");
    env.at(299_999);
    let _ = env.msg(env.serial(), &Msg::Timer(SECRET_TIMER_ID));
    env.snap("tick-299999");
    env.at(300_000);
    let _ = env.msg(env.serial(), &Msg::Timer(SECRET_TIMER_ID));
    env.snap("tick-300000");
    std::mem::take(&mut env.lines)
}

/// A message for a window that is no longer open never reaches the open one: W03 (typed into)
/// is replaced by W04; a character, Enter and the close box sent to W03's serial change nothing.
fn stale_serial_ignored() -> Vec<String> {
    let mut env = Env::new("stale_serial_ignored", UNLOCKED);
    env.fx.app().open_input(
        SecretKind::ConfirmPassword,
        Purpose::ConfirmPassword(PasswordAction::RevealMnemonic { then_backup: false }),
        false,
    );
    env.type_text("abc");
    let old = env.serial();
    env.snap("w03-typed");
    env.fx
        .app()
        .open_input(SecretKind::ChangePassword, Purpose::ChangePassword, false);
    env.snap("w04-open");
    let replies = [
        env.msg(old, &Msg::Char(u16::from(b'x'))),
        env.msg(old, &Msg::Char(0x0D)),
        env.msg(old, &Msg::Close),
    ];
    env.fact("stale replies", &replies.join(","));
    env.snap("stale-messages");
    let reply = env.msg(env.serial(), &Msg::Char(u16::from(b'y')));
    env.fact("current reply", reply);
    env.snap("current-message");
    std::mem::take(&mut env.lines)
}

/// A lock on S01 (no wallet; `SessionLock`, which locks in every mode): the import's password
/// and "개인키로 시작하기"'s password are held (each submitted through `test_submit` as W01 would,
/// which opens W05 and then W07; W01 itself is not opened), W07 is open with units typed; the
/// lock closes it wiped and drops both.
fn lock_in_first_run_wipes_import_and_key_start() -> Vec<String> {
    let mut env = Env::new(
        "lock_in_first_run_wipes_import_and_key_start",
        AppMode::NoVault,
    );
    env.fx
        .app()
        .test_submit(Purpose::ImportPassword, vec![bytes(PASSWORD)], false);
    env.snap("import-password");
    env.fx
        .app()
        .test_submit(Purpose::KeyStartPassword, vec![bytes(PASSWORD)], false);
    env.type_text("ab");
    env.snap("key-start-password");
    env.main_msg(&Msg::SessionLock);
    env.snap("session-lock");
    std::mem::take(&mut env.lines)
}

/// Critique A-3: a display window opened and a lock in the same entry (one App borrow): today
/// the window is created, shown, then closed and wiped by the lock.
fn display_then_lock_same_entry() -> Vec<String> {
    let mut env = Env::new("display_then_lock_same_entry", UNLOCKED);
    {
        let mut app = env.fx.app();
        app.open_display(
            SecretKind::ShowMnemonic { create: false },
            Purpose::ShowRevealed,
            DisplaySecret {
                text: about_secret(),
                address: Some(address_a().to_checksum()),
                passphrase_note: false,
                copy_allowed: false,
            },
        );
        app.lock(LockReason::Manual);
    }
    env.snap("open-and-lock");
    std::mem::take(&mut env.lines)
}

/// Critique A-21: a password typed into W03, then a lock (Ctrl+L): the window is wiped and
/// closed; a late Enter for its serial reaches nothing and queues no key job.
fn late_submission_after_lock() -> Vec<String> {
    let mut env = Env::new("late_submission_after_lock", UNLOCKED);
    env.fx.app().open_input(
        SecretKind::ConfirmPassword,
        Purpose::ConfirmPassword(PasswordAction::RevealMnemonic { then_backup: false }),
        false,
    );
    env.type_text(PASSWORD);
    let old = env.serial();
    env.snap("typed");
    env.main_msg(&Msg::App {
        msg: crate::shell_msg::WM_YW_LOCK_SHORTCUT,
        wparam: 0,
    });
    env.snap("ctrl-l");
    let replies = [
        env.msg(old, &Msg::Char(u16::from(b'z'))),
        env.msg(old, &Msg::Char(0x0D)),
    ];
    env.fact("late replies", &replies.join(","));
    env.snap("late-enter");
    std::mem::take(&mut env.lines)
}

// ----- the card step's PIN window (W11) -------------------------------------------------------

/// The mock card wallet's App (account 1 on the emulator card), its dApp connection, the site
/// granted account 1; a `personal_sign` of account 1 approved through the hidden approval window
/// opens the card step and W11 (topmost).
fn card_env(name: &'static str) -> Env {
    let mut env = Env::new(name, UNLOCKED);
    let outlet = env.fx.connect_outlet();
    let dir = env.fx.dir().join("card");
    std::fs::create_dir_all(&dir).unwrap();
    let (wallet_dir, loaded) = card_wallet::meta(dir.clone());
    {
        let mut app = env.fx.app();
        app.meta = Some(*loaded.meta);
        app.card_after_meta();
        app.sync_browser();
        if let Some(browser) = app.browser.as_ref() {
            browser.core.upsert_grant(
                ConnectedSite::new(
                    BrowserOrigin::parse(SITE).unwrap(),
                    vec![parse_address(ACCOUNT_B).unwrap()],
                    yw_core::evm::chain::SEPOLIA,
                    1,
                )
                .unwrap(),
            );
        }
    }
    let _ = std::fs::remove_dir_all(&wallet_dir);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = outlet.events.drain();
    let _ = outlet.answers();
    env.outlet = Some(outlet);
    let _ = secret_seam::take_log();
    let _ = env.fx.key_jobs();
    let _ = env.fx.rpc_jobs();
    env
}

/// The dApp's `personal_sign` of account 1, approved (Standard: armed, then one click).
fn card_request(env: &mut Env) {
    if let Some(outlet) = env.outlet.as_ref() {
        let due = env.fx.clock.unix_at(env.fx.clock.peek() + 600_000);
        outlet.send(
            &env.fx,
            1,
            "personal_sign",
            &format!(r#"["0x6869","{ACCOUNT_B}"]"#),
            "signing",
            due,
        );
    }
    env.snap("request");
    env.approve_standard();
    env.snap("approved");
}

/// `card_site_check` on a disconnect: W11 (a PIN typed) closes wiped, 4100, the approval is
/// dropped; a late Enter for W11's serial signs nothing (critique A-21).
fn card_pin_window_site_revoked() -> Vec<String> {
    let mut env = card_env("card_pin_window_site_revoked");
    card_request(&mut env);
    env.type_text(PIN);
    let old = env.serial();
    env.snap("pin-typed");
    env.fx
        .app()
        .disconnect_site(&BrowserOrigin::parse(SITE).unwrap());
    env.snap("disconnected");
    let replies = [
        env.msg(old, &Msg::Char(u16::from(b'1'))),
        env.msg(old, &Msg::Char(0x0D)),
    ];
    env.fact("late replies", &replies.join(","));
    env.snap("late-enter");
    std::mem::take(&mut env.lines)
}

/// `card_site_check` on a page cancel (the extension's `cancel` envelope): W11 closes, 4001.
fn card_pin_window_page_cancelled() -> Vec<String> {
    let mut env = card_env("card_pin_window_page_cancelled");
    card_request(&mut env);
    let frame = format!(
        concat!(
            r#"{{"namespace":"your-wallet","version":1,"role":"extension","kind":"cancel","#,
            r#""sessionId":"{session}","sequence":2,"activationNonce":"{activation}","#,
            r#""requestId":"{request}","requestSequence":1,"reason":"navigation"}}"#
        ),
        session = "bb".repeat(32),
        activation = format!("{}0c", "00".repeat(31)),
        request = "01".repeat(16),
    );
    if let Some(outlet) = env.outlet.as_ref() {
        let core = env
            .fx
            .app
            .borrow()
            .browser
            .as_ref()
            .map(|browser| Arc::clone(&browser.core));
        if let Some(core) = core {
            core.handle_frame(outlet.conn, frame.as_bytes());
        }
        for event in outlet.events.drain() {
            if let yw_engine::events::UiEvent::Dapp(event) = event {
                env.fx.app().on_dapp_event(event);
            }
        }
    }
    env.snap("page-cancelled");
    std::mem::take(&mut env.lines)
}

/// `card_tick`: a W11 that could not open (a failed window) leaves the step waiting; the next
/// tick finds the window gone and cancels the step (nothing signed).
fn card_tick_window_gone() -> Vec<String> {
    let mut env = card_env("card_tick_window_gone");
    host::refuse(Some(Refuse::Os));
    card_request(&mut env);
    host::refuse(None);
    let now = env.fx.clock.peek();
    env.fx.app().card_tick(now);
    env.snap("card-tick");
    std::mem::take(&mut env.lines)
}

/// `card_tick`: the step's 120 s bound closes W11 and fails the step.
fn card_tick_expired() -> Vec<String> {
    let mut env = card_env("card_tick_expired");
    card_request(&mut env);
    env.type_text(PIN);
    let now = env.fx.clock.peek();
    env.fx
        .app()
        .card_tick(now + yw_engine::wallet::app_card::CARD_STEP_MS - 1);
    env.snap("tick-before-bound");
    env.fx
        .app()
        .card_tick(now + yw_engine::wallet::app_card::CARD_STEP_MS);
    env.snap("tick-at-bound");
    std::mem::take(&mut env.lines)
}

// ----- one lock per reason (lock.txt) ---------------------------------------------------------

/// The lock scenarios' state: the wallet's quiz challenge held, the `YubiKey` wizard holding the
/// words of its W05, an added phrase's words held, W06 open with units typed, and the app's own
/// send shown in the (hidden) approval window.
fn lock_env(name: &'static str) -> Env {
    let mut env = Env::new(name, UNLOCKED);
    env.deliver(KeyOutcome::Challenge(Ok(backup_challenge())));
    env.fx.app().yk_open_wizard();
    env.fx.app().test_submit(
        Purpose::YubiKey(YkPurpose::Mnemonic),
        vec![bytes(&about_text())],
        true,
    );
    env.fx.app().test_submit(
        Purpose::Mnemonics(MnPurpose::ImportWords),
        vec![bytes(&about_text())],
        true,
    );
    env.type_text("word");
    env.fx.enqueue_sepolia_send();
    let jobs = env.fx.rpc_jobs();
    let sent = names(jobs.iter().map(|job| job.name().to_owned()));
    for job in jobs {
        if let RpcJob::Prepare(job) = job {
            env.fx.answer_prepare(&job, "S2");
        }
    }
    env.fact(
        "approval",
        &format!("the app send shown; rpc {sent} answered from the S2 fixture"),
    );
    env.snap("setup");
    env
}

/// Critique A-2/A-14: a lock by `msg` through the main window's handler, in one entry.
fn lock_by_message(msg: &Msg, name: &'static str) -> Vec<String> {
    let mut env = lock_env(name);
    {
        let _ack = LockAck::start(&env);
        env.main_msg(msg);
    }
    env.snap("lock");
    std::mem::take(&mut env.lines)
}

/// `Manual`: Ctrl+L (the loop observer's `WM_YW_LOCK_SHORTCUT`).
fn lock_manual() -> Vec<String> {
    lock_by_message(
        &Msg::App {
            msg: crate::shell_msg::WM_YW_LOCK_SHORTCUT,
            wparam: 0,
        },
        "lock_manual",
    )
}

/// `Idle`: the main timer past the auto-lock limit (as A6: a shown request pauses the idle
/// clock; its expiry ends it; a later tick locks).
fn lock_idle() -> Vec<String> {
    let mut env = lock_env("lock_idle");
    let minutes = u64::from(env.fx.app.borrow().settings.auto_lock_minutes);
    let limit = minutes * 60_000;
    env.fact("limit", &format!("auto-lock minutes={minutes}"));
    for (at, step) in [
        (limit + 1_000, "tick-past-limit"),
        (limit + 2_000, "tick-after"),
        (2 * limit + 3_000, "tick-past-limit-again"),
    ] {
        env.at(at);
        env.main_tick();
        env.snap(step);
    }
    std::mem::take(&mut env.lines)
}

// ----- the tables -----------------------------------------------------------------------------

pub(crate) type Scenario = fn() -> Vec<String>;

/// `secret.txt`, in golden order.
pub(crate) const SECRET_SCENARIOS: [(&str, Scenario); 19] = [
    ("reveal_words_then_backup", reveal_words_then_backup),
    ("reveal_words_plain", reveal_words_plain),
    ("reveal_key", reveal_key),
    ("created_words_display", created_words_display),
    ("input_refused", input_refused),
    (
        "challenge_opens_or_resets_w10",
        challenge_opens_or_resets_w10,
    ),
    (
        "mn_challenge_opens_or_resets_w10",
        mn_challenge_opens_or_resets_w10,
    ),
    (
        "yk_challenge_opens_or_resets_w10",
        yk_challenge_opens_or_resets_w10,
    ),
    (
        "yk_card_secret_counters_only_when_shown",
        yk_card_secret_counters_only_when_shown,
    ),
    (
        "yk_words_shown_only_when_w08_shown",
        yk_words_shown_only_when_w08_shown,
    ),
    ("timed_out_notice", timed_out_notice),
    ("stale_serial_ignored", stale_serial_ignored),
    ("display_then_lock_same_entry", display_then_lock_same_entry),
    ("late_submission_after_lock", late_submission_after_lock),
    (
        "lock_in_first_run_wipes_import_and_key_start",
        lock_in_first_run_wipes_import_and_key_start,
    ),
    ("card_pin_window_site_revoked", card_pin_window_site_revoked),
    (
        "card_pin_window_page_cancelled",
        card_pin_window_page_cancelled,
    ),
    ("card_tick_window_gone", card_tick_window_gone),
    ("card_tick_expired", card_tick_expired),
];

/// `lock.txt`, in golden order (one per `LockReason`).
pub(crate) const LOCK_SCENARIOS: [(&str, Scenario); 6] = [
    ("lock_manual", lock_manual),
    ("lock_idle", lock_idle),
    ("lock_session_lock", || {
        lock_by_message(&Msg::SessionLock, "lock_session_lock")
    }),
    ("lock_session_disconnect", || {
        lock_by_message(&Msg::SessionDisconnect, "lock_session_disconnect")
    }),
    ("lock_suspend", || {
        lock_by_message(&Msg::Suspend, "lock_suspend")
    }),
    ("lock_end_session", || {
        lock_by_message(&Msg::EndSession, "lock_end_session")
    }),
];

/// Every scenario of `table`, each on a thread of its own, as one golden text.
fn record(table: &[(&str, Scenario)]) -> String {
    let mut out = String::new();
    for (_, scenario) in table {
        let lines = std::thread::spawn(*scenario)
            .join()
            .expect("the scenario's thread");
        for line in lines {
            out.push_str(&line);
            out.push('\n');
        }
    }
    out
}

pub(crate) fn first_difference(name: &str, generated: &str, committed: &str) -> Option<String> {
    let generated: Vec<&str> = generated.lines().collect();
    let committed: Vec<&str> = committed.lines().collect();
    if generated == committed {
        return None;
    }
    let at = generated
        .iter()
        .zip(&committed)
        .position(|(left, right)| left != right)
        .unwrap_or_else(|| generated.len().min(committed.len()));
    Some(format!(
        "{name}: line {} differs (generated {}, committed {}):\n  generated: {:?}\n  committed: {:?}",
        at + 1,
        generated.len(),
        committed.len(),
        generated.get(at),
        committed.get(at),
    ))
}

/// Records both goldens (real secret windows on the desktop): writes them into
/// `YW_S4_SECRET_OUT` when it is set (for review), else compares them with the committed files.
#[test]
#[ignore = "DEV ONLY: opens real secret windows on the desktop (S4 secret characterization)"]
fn secret_sessions_match_the_goldens() {
    let secret = record(&SECRET_SCENARIOS);
    let lock = record(&LOCK_SCENARIOS);
    if let Some(dir) = std::env::var_os("YW_S4_SECRET_OUT") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("secret.txt"), &secret).unwrap();
        std::fs::write(dir.join("lock.txt"), &lock).unwrap();
        return;
    }
    let differences: Vec<String> = [
        first_difference("secret.txt", &secret, SECRET_GOLDEN),
        first_difference("lock.txt", &lock, LOCK_GOLDEN),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

/// Each golden names only scenarios of its table, each with lines, grouped in table order, and
/// holds no value (gate test step; no window).
/// The scan rejects a bare hex key, the vector's words and the typed texts as words, and keeps
/// the names that contain them (gate test step; 2026-11-18, A7 review).
#[test]
fn the_scan_rejects_values_and_keeps_names() {
    let key = format!("x | key {}1 |", "0".repeat(63));
    for line in [
        key.as_str(),
        "x | about |",
        "x zoo",
        "x | ab |",
        "x word",
        "x abc",
    ] {
        assert!(
            std::panic::catch_unwind(|| scan(line)).is_err(),
            "kept: {line}"
        );
    }
    scan(
        "reveal_words_plain close-box | ConfirmPassword/RevealMnemonic | yk-words None | #0a1b2c3d",
    );
}

#[test]
fn the_secret_goldens_name_only_known_scenarios() {
    for (golden, table) in [
        (SECRET_GOLDEN, &SECRET_SCENARIOS[..]),
        (LOCK_GOLDEN, &LOCK_SCENARIOS[..]),
    ] {
        let mut order = Vec::new();
        for line in golden.lines() {
            let name = line.split(' ').next().unwrap_or_default();
            assert!(
                table.iter().any(|(known, _)| *known == name),
                "unknown scenario: {line}"
            );
            if order.last() != Some(&name) {
                assert!(!order.contains(&name), "{name} is not one block");
                order.push(name);
            }
            scan(line);
        }
        let names: Vec<&str> = table.iter().map(|(name, _)| *name).collect();
        assert_eq!(order, names, "every scenario, in table order");
    }
}
