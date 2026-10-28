//! The UI-thread application (spec/04 §1–§2, §4–§6): window handlers, flows, lock procedure,
//! settings and endpoint management. All windows share one `App` through `Rc<RefCell<…>>`; a
//! handler that cannot borrow it (re-entrant synchronous message) falls back to the default
//! processing, and the yw-win trampoline has already applied the secret-message block list.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::Duration;

use yw_core::error::VaultError;
use yw_core::evm::address::Address;
use yw_core::secret::Zeroizing;
use yw_core::vault::{BackupChallenge, ChallengeId, EvmKeySource, FileKind, RecordId, VaultStatus};
use yw_win::clipboard::{self, ClipError};
use yw_win::file::{FileError, atomic_write, read_limited};
use yw_win::http::HttpsUrl;
use yw_win::input::is_down;
use yw_win::session;
use yw_win::time::monotonic_ms;
use yw_win::ui::{Handler, Msg, Reply, UiError, Window, WindowKind, WindowSpec, create_window};

use crate::apikeys::{
    APIKEYS_ENTROPY, ApiKeys, KeyName, is_registered, template_entry, valid_provider_token,
    valid_quicknode_name,
};
use crate::errors::{ErrorCode, key_code, vault_code};
use crate::events::{
    KeyJob, KeyOutcome, KeyQueue, KeyResult, LockSignal, MetaLoaded, RevealWhat, RpcEvent, UiEvent,
    WM_YW_ACTIVATE, WM_YW_EVENTS, WM_YW_LOCK_SHORTCUT, accept_result,
};
use crate::lock::{IdleTracker, LockReason, SystemAction, system_action};
use crate::logging::{self, Field};
use crate::meta::{EvmAccountPref, Meta, RawAccount};
use crate::network::NetworkId;
use crate::settings::{LogLevel, RpcTemplate, Settings};
use crate::text::is_valid_label;
use crate::ui::main_window::{ControlSet, Placed, layout, paint};
use crate::ui::secret::{
    CaptureDecision, DisplaySecret, FormAction, PASTE_MAX_UTF16_UNITS, SECRET_TIMER_ID,
    SECRET_TIMER_MS, SecretForm, SecretKind, Submission, capture_decision,
};
use crate::ui::theme::{FontCache, FontRole, wide};
use crate::workers::key::new_account;
use crate::workers::rpc::RpcJob;

/// Main window class.
pub const MAIN_CLASS: &str = "YourWalletV3Main";
/// Secret input class (W01–W07, W10): `CaptureExclusion::Preferred`.
pub const SECRET_INPUT_CLASS: &str = "YourWalletV3SecretInput";
/// Secret display class (W08, W09): `CaptureExclusion::Required`.
pub const SECRET_VIEW_CLASS: &str = "YourWalletV3SecretView";
/// Single-instance mutex.
pub const MUTEX_NAME: &str = "Local\\YourWallet.v3.app";
/// Secret clipboard lifetime (D11).
pub const SECRET_CLIPBOARD_TTL_MS: u64 = 30_000;
const MAIN_TIMER_ID: usize = 1;
const LOG_FLUSH_MS: u64 = 2_000;
const SESSION_RETRY_MS: u64 = 1_000;
const SESSION_RETRY_MAX: u32 = 30;
const VK_CONTROL: u16 = 0x11;
const VK_SHIFT: u16 = 0x10;
const VK_MENU: u16 = 0x12;
const MA_ACTIVATEANDEAT: isize = 2;
const EN_CHANGE: u16 = 0x0300;
/// Settings field limits (UTF-16 units).
const TOKEN_MAX_UNITS: usize = 256;
const URL_MAX_UNITS: usize = 2_048;

/// App mode (spec/04 §2.1): `VaultStatus` plus progress states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppMode {
    /// Before the first `Vault::load` result.
    Starting,
    /// No wallet.
    NoVault,
    /// Locked.
    Locked,
    /// `Unlock` in progress.
    Unlocking,
    /// Passphrase needed.
    PassphraseRequired,
    /// Passphrase check failed.
    PassphraseMismatch,
    /// Backup not confirmed.
    BackupPending,
    /// Unlocked.
    Unlocked {
        /// Mismatched passphrase accepted.
        alt_passphrase: bool,
    },
    /// Damaged main vault.
    Corrupt {
        /// `.prev` exists.
        prev_available: bool,
    },
    /// Main vault missing, `.prev` present.
    MainMissing,
    /// Shutting down.
    ShuttingDown,
}

impl AppMode {
    fn from_status(status: VaultStatus) -> Self {
        match status {
            VaultStatus::NoVault => Self::NoVault,
            VaultStatus::Locked => Self::Locked,
            VaultStatus::PassphraseRequired => Self::PassphraseRequired,
            VaultStatus::PassphraseMismatch => Self::PassphraseMismatch,
            VaultStatus::BackupPending => Self::BackupPending,
            VaultStatus::Unlocked { alt_passphrase } => Self::Unlocked { alt_passphrase },
            VaultStatus::Corrupt { prev_available } => Self::Corrupt { prev_available },
            VaultStatus::MainMissing => Self::MainMissing,
        }
    }

    const fn word(self) -> &'static str {
        match self {
            Self::Starting => "Starting",
            Self::NoVault => "NoVault",
            Self::Locked => "Locked",
            Self::Unlocking => "Unlocking",
            Self::PassphraseRequired => "PassphraseRequired",
            Self::PassphraseMismatch => "PassphraseMismatch",
            Self::BackupPending => "BackupPending",
            Self::Unlocked { .. } => "Unlocked",
            Self::Corrupt { .. } => "Corrupt",
            Self::MainMissing => "MainMissing",
            Self::ShuttingDown => "ShuttingDown",
        }
    }

    /// Whether wallet secrets may be in worker memory (lockable).
    const fn holds_secrets(self) -> bool {
        matches!(
            self,
            Self::Unlocking
                | Self::PassphraseRequired
                | Self::PassphraseMismatch
                | Self::BackupPending
                | Self::Unlocked { .. }
        )
    }
}

/// Settings sections (S15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsSection {
    /// 보안.
    Security,
    /// 네트워크 (RPC 공급자, 네트워크 URL).
    Network,
    /// 브라우저·진단·정보.
    Other,
    /// EVM 체인, 수수료 상한 (M4).
    Chains,
    /// Solana: 클러스터, 수수료 상한, 다른 경로 스캔 (M7).
    Solana,
    /// Bitcoin: 켜기·네트워크, 인덱서, Esplora URL (M8).
    Bitcoin,
}

/// Confirmation overlays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirm {
    /// T-COPY-ON.
    CopyOn,
    /// T-LOCALHOST-ON.
    LocalhostOn,
    /// T-REVEAL-WARN for the mnemonic.
    RevealMnemonic,
    /// T-REVEAL-WARN for a private key.
    RevealKey,
    /// T-RPC-GENERATE.
    Generate,
    /// E-VLT-006 for meta.
    SidecarCorrupt,
    /// Remove an imported key.
    RemoveKey,
    /// E-VLT-006 for the journal (T-JOURNAL-RESET).
    JournalCorrupt,
    /// T-CHAIN-PIN.
    ChainPin,
    /// T-CHAIN-REPIN.
    ChainRepin,
    /// T-CHAIN-DELETE.
    ChainDelete,
    /// Discard of an open transaction.
    Discard,
    /// Delete an address-book entry.
    BookDelete,
    /// S13 `모두 해제`.
    DisconnectAll,
    /// A Bitcoin overlay (`BtcUi::confirm` holds which one and its texts).
    Btc,
}

/// Screens S01–S15 (M3 subset).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Screen {
    /// Waiting for `Vault::load`.
    Starting,
    /// S01.
    FirstRun,
    /// S02.
    CreateIntro,
    /// S03.
    Processing(&'static str),
    /// S04.
    BackupPending,
    /// S05.
    ImportIntro,
    /// S06 (EIP-55 address).
    ImportAddress(String),
    /// S07.
    Locked,
    /// S07 overlay T-PASS-MISMATCH.
    PassMismatch,
    /// S08.
    Done,
    /// S09.
    Recovery,
    /// S10.
    Main,
    /// S15.
    Settings(SettingsSection),
    /// Confirmation overlay over the previous screen.
    Confirm(Confirm),
    /// S11.
    Send,
    /// S11 result.
    SendResult,
    /// S12.
    Receive,
    /// S14.
    AddressBook,
    /// S16.
    TokenAdd,
    /// S17.
    ChainEdit,
    /// S13.
    Sites,
    /// S11 for Solana.
    SolSend,
    /// S11 result for Solana.
    SolSendResult,
    /// S12 for Solana.
    SolReceive,
    /// The recovery scan (spec/07 §3.3).
    SolScan,
    /// S11 for Bitcoin.
    BtcSend,
    /// S11 result for Bitcoin.
    BtcSendResult,
    /// The Bitcoin fee-bump form (S10 `수수료 올리기`).
    BtcBump,
    /// S12 for Bitcoin.
    BtcReceive,
}

/// What a password-confirm window (W03) is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PasswordAction {
    /// Reveal the mnemonic; `then_backup` = continue with W08 → W10 (S04).
    RevealMnemonic {
        /// Backup confirmation path.
        then_backup: bool,
    },
    /// Reveal a private key.
    RevealKey(EvmKeySource),
    /// Remove an imported key.
    RemoveKey(RecordId),
    /// Recover from `.prev`.
    Recover,
}

/// What the open secret window is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// W01 in the create flow.
    CreatePassword,
    /// W01 in the import flow.
    ImportPassword,
    /// W05.
    ImportMnemonic,
    /// W06 (two fields).
    ImportPassphrase,
    /// W02.
    Unlock,
    /// W06 (one field) after unlock.
    EnterPassphrase,
    /// W08 after creation or on the backup path.
    ShowForBackup,
    /// W10.
    Backup,
    /// W03.
    ConfirmPassword(PasswordAction),
    /// W08/W09 reveal.
    ShowRevealed,
    /// W04.
    ChangePassword,
    /// W07.
    ImportKey,
}

struct SecretWin {
    serial: u64,
    window: Window,
    form: SecretForm,
    purpose: Purpose,
}

/// A main-window banner (shown until dismissed; one per code).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Banner {
    /// Code (dedup key).
    pub code: Option<ErrorCode>,
    /// Text.
    pub text: String,
}

/// Paths of the data folder.
#[derive(Clone, Debug)]
pub struct Paths {
    /// `%LOCALAPPDATA%\YourWallet\v3`.
    pub data: PathBuf,
    /// `…\logs`.
    pub logs: PathBuf,
}

impl Paths {
    fn settings(&self) -> PathBuf {
        self.data.join("settings.json")
    }

    fn apikeys(&self) -> PathBuf {
        self.data.join("apikeys.dpapi")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Target {
    Main,
    Secret(u64),
}

struct Forward {
    app: Weak<RefCell<App>>,
    target: Target,
}

impl Handler for Forward {
    fn on(&mut self, window: &Window, msg: &Msg) -> Reply {
        let Some(app) = self.app.upgrade() else {
            return Reply::Default;
        };
        let Ok(mut app) = app.try_borrow_mut() else {
            return Reply::Default;
        };
        match self.target {
            Target::Main => app.on_main(window, msg),
            Target::Secret(serial) => app.on_secret(serial, window, msg),
        }
    }
}

/// Import flow buffers held on the UI thread until `PreviewImport` moves them.
#[derive(Default)]
struct ImportFlow {
    password: Option<Zeroizing<Vec<u8>>>,
    phrase: Option<Zeroizing<Vec<u8>>>,
    password_sent: bool,
}

/// The application state (UI thread).
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent UI flags of one window"
)]
pub struct App {
    pub(crate) paths: Paths,
    pub(crate) background: bool,
    pub(crate) main: Option<Window>,
    pub(crate) fonts: FontCache,
    pub(crate) events: Option<Arc<crate::events::EventQueue>>,
    pub(crate) key_queue: Arc<KeyQueue>,
    pub(crate) lock_signal: Arc<LockSignal>,
    pub(crate) rpc_tx: Option<Sender<RpcJob>>,
    pub(crate) workers: Vec<JoinHandle<()>>,
    pub(crate) self_ref: Weak<RefCell<App>>,
    pub(crate) mode: AppMode,
    pub(crate) lock_epoch: u64,
    pub(crate) settings: Settings,
    pub(crate) apikeys: ApiKeys,
    pub(crate) banners: Vec<Banner>,
    pub(crate) meta: Option<Meta>,
    pub(crate) screen: Screen,
    pub(crate) previous_screen: Screen,
    pub(crate) leftover: bool,
    pub(crate) info: Option<String>,
    pub(crate) mismatch_checked: bool,
    pub(crate) overwrite_checked: bool,
    pub(crate) rename: Option<EvmAccountPref>,
    pub(crate) pending_remove: Option<RecordId>,
    pub(crate) replace_target: Option<NetworkId>,
    pub(crate) rpc_messages: Vec<(NetworkId, String, bool)>,
    pub(crate) passphrase_session: bool,
    pub(crate) scroll: i32,
    pub(crate) controls: ControlSet,
    pub(crate) placed: Placed,
    pub(crate) evm: crate::app_evm::EvmUi,
    pub(crate) sol: crate::app_sol::SolUi,
    pub(crate) btc: crate::app_btc::BtcUi,
    pub(crate) browser: Option<crate::app_browser::BrowserUi>,
    secret: Option<SecretWin>,
    secret_serial: u64,
    import: ImportFlow,
    challenge: Option<BackupChallenge>,
    idle: IdleTracker,
    secret_clip: Option<(u32, u64)>,
    startup_load: bool,
    session_retries: u32,
    session_next_ms: u64,
    last_flush_ms: u64,
}

impl core::fmt::Debug for App {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("App")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

fn now_ms() -> u64 {
    monotonic_ms()
}

fn eip55(address: &Address) -> String {
    address.to_checksum()
}

/// Loads `settings.json` (spec/04 §6.2).
#[must_use]
pub fn load_settings(paths: &Paths) -> crate::settings::SettingsLoad {
    match read_limited(
        &paths.settings(),
        u64::try_from(crate::settings::SETTINGS_MAX_BYTES).unwrap_or(65_536),
    ) {
        Ok(bytes) => crate::settings::load(Some(&bytes)),
        Err(FileError::NotFound) => crate::settings::load(None),
        Err(_) => crate::settings::SettingsLoad {
            settings: Settings::default(),
            banners: vec!["settings.json".to_owned()],
        },
    }
}

/// Loads `apikeys.dpapi` (spec/04 §6.3): `(keys, unreadable)`.
#[must_use]
pub fn load_apikeys(paths: &Paths, settings: &Settings) -> (ApiKeys, bool) {
    let blob = match read_limited(&paths.apikeys(), 1_048_576) {
        Ok(blob) => blob,
        Err(FileError::NotFound) => return (ApiKeys::default(), false),
        Err(_) => return (ApiKeys::default(), true),
    };
    let Ok(plain) = yw_win::dpapi::unprotect(&blob, APIKEYS_ENTROPY) else {
        return (ApiKeys::default(), true);
    };
    match ApiKeys::decode(plain.as_slice(), &|network| {
        is_registered(settings, network)
    }) {
        Ok(decoded) => {
            for orphan in decoded.orphans {
                if let KeyName::Rpc(network) = orphan {
                    logging::info("app", "apikeys.orphan", &[("net", Field::Net(network))]);
                }
            }
            (decoded.keys, false)
        }
        Err(_) => (ApiKeys::default(), true),
    }
}

impl App {
    /// A new app (no windows yet).
    #[must_use]
    pub fn new(paths: Paths, background: bool, settings: Settings, apikeys: ApiKeys) -> Self {
        let now = now_ms();
        Self {
            paths,
            background,
            main: None,
            fonts: FontCache::default(),
            events: None,
            key_queue: Arc::new(KeyQueue::default()),
            lock_signal: Arc::new(LockSignal::default()),
            rpc_tx: None,
            workers: Vec::new(),
            self_ref: Weak::new(),
            mode: AppMode::Starting,
            lock_epoch: 0,
            settings,
            apikeys,
            banners: Vec::new(),
            meta: None,
            screen: Screen::Starting,
            previous_screen: Screen::Starting,
            leftover: false,
            info: None,
            mismatch_checked: false,
            overwrite_checked: false,
            rename: None,
            pending_remove: None,
            replace_target: None,
            rpc_messages: Vec::new(),
            passphrase_session: false,
            scroll: 0,
            controls: ControlSet::default(),
            placed: Placed::default(),
            evm: crate::app_evm::EvmUi::default(),
            sol: crate::app_sol::SolUi::default(),
            btc: crate::app_btc::BtcUi::default(),
            browser: None,
            secret: None,
            secret_serial: 0,
            import: ImportFlow::default(),
            challenge: None,
            idle: IdleTracker::new(now),
            secret_clip: None,
            startup_load: true,
            session_retries: 0,
            session_next_ms: 0,
            last_flush_ms: now,
        }
    }

    /// Adds a banner once per code.
    pub fn banner(&mut self, code: Option<ErrorCode>, text: String) {
        if code.is_some() && self.banners.iter().any(|banner| banner.code == code) {
            return;
        }
        self.banners.push(Banner { code, text });
    }

    pub(crate) fn error_banner(&mut self, code: ErrorCode) {
        logging::warn("app", "error", &[("code", Field::Code(code))]);
        self.banner(Some(code), code.text());
    }

    /// Creates the main window and stores it.
    ///
    /// # Errors
    ///
    /// [`UiError`] from window creation.
    pub fn create_main_window(app: &Rc<RefCell<Self>>) -> Result<(), UiError> {
        let handler = Box::new(Forward {
            app: Rc::downgrade(app),
            target: Target::Main,
        });
        let spec = WindowSpec::new(MAIN_CLASS, WindowKind::Main)
            .title("Your Wallet")
            .size(960, 680)
            .min_size(720, 520);
        let window = create_window(&spec, handler)?;
        let mut state = app.borrow_mut();
        state.self_ref = Rc::downgrade(app);
        window.set_timer(MAIN_TIMER_ID, crate::events::MAIN_TIMER_MS)?;
        state.main = Some(window);
        Ok(())
    }

    /// The main window poster.
    #[must_use]
    pub fn main_poster(&self) -> Option<yw_win::ui::Poster> {
        self.main.as_ref().map(Window::poster)
    }

    /// Attaches the started browser bridge (spec/05 §8.1).
    pub fn attach_browser(&mut self, browser: crate::app_browser::BrowserUi) {
        if browser.server.is_none() {
            self.error_banner(ErrorCode::Pipe001);
        }
        self.browser = Some(browser);
    }

    /// The key queue and lock signal shared with the key worker.
    #[must_use]
    pub fn worker_channels(&self) -> (Arc<KeyQueue>, Arc<LockSignal>) {
        (Arc::clone(&self.key_queue), Arc::clone(&self.lock_signal))
    }

    /// Attaches the started workers.
    pub fn attach_workers(
        &mut self,
        events: Arc<crate::events::EventQueue>,
        workers: Vec<JoinHandle<()>>,
        rpc_tx: Sender<RpcJob>,
    ) {
        self.events = Some(events);
        self.workers = workers;
        self.rpc_tx = Some(rpc_tx);
    }

    /// Registers session notifications (retried by the timer, spec/04 §1.4-6).
    pub fn register_session(&mut self) {
        let Some(main) = self.main.as_ref() else {
            return;
        };
        match session::register_session_notifications(main) {
            Ok(()) => self.session_retries = 0,
            Err(error) => {
                logging::warn(
                    "app",
                    "session.register_failed",
                    &[("code", Field::Num(u64::from(error.code)))],
                );
                self.session_retries = self.session_retries.saturating_add(1);
                self.session_next_ms = now_ms().saturating_add(SESSION_RETRY_MS);
                if self.session_retries >= SESSION_RETRY_MAX {
                    self.session_retries = 0;
                    self.error_banner(ErrorCode::App004);
                }
            }
        }
    }

    /// Shows the main window (not in `--background`).
    pub fn show_main(&mut self) {
        if let Some(main) = self.main.as_ref() {
            main.show();
            if !main.set_foreground() {
                main.flash();
            }
        }
        self.refresh();
    }

    /// Queues a key job in the current epoch.
    pub fn key(&self, job: KeyJob) {
        self.key_queue.push(self.lock_epoch, job);
    }

    fn set_mode(&mut self, mode: AppMode) {
        if self.mode != mode {
            logging::info("app", "mode", &[("to", Field::Word(mode.word()))]);
            self.mode = mode;
        }
    }

    pub(crate) fn set_screen(&mut self, screen: Screen) {
        if matches!(screen, Screen::Confirm(_)) && !matches!(self.screen, Screen::Confirm(_)) {
            self.previous_screen = self.screen.clone();
        }
        self.screen = screen;
        self.scroll = 0;
        self.refresh();
    }

    // ----- rendering ---------------------------------------------------------------------

    /// Recomputes the layout, syncs the child controls and repaints.
    pub fn refresh(&mut self) {
        self.sync_browser();
        let Some(main) = self.main.as_ref() else {
            return;
        };
        let dpi = main.dpi();
        let client = main.client_rect();
        let items = self.items();
        let Some(fonts) = self.fonts.for_dpi(dpi) else {
            return;
        };
        let measure = |text: &str, role: FontRole, width: i32| {
            main.measure_text(
                fonts.get(role),
                &wide(text),
                width,
                yw_win::ui::DrawFlags::WRAP,
            )
            .1
        };
        let label = |text: &str| {
            main.measure_text(
                &fonts.body,
                &wide(text),
                10_000,
                yw_win::ui::DrawFlags::LINE,
            )
            .0
        };
        let mut placed = layout(&items, client.w, dpi, self.scroll, &measure, &label);
        let max_scroll = placed.content_height.saturating_sub(client.h).max(0);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
            placed = layout(&items, client.w, dpi, self.scroll, &measure, &label);
        }
        self.controls.sync(main, &placed, fonts, client);
        self.placed = placed;
        main.invalidate();
    }

    fn paint_main(&mut self, window: &Window) {
        let dpi = window.dpi();
        let client = window.client_rect();
        let Some(fonts) = self.fonts.for_dpi(dpi) else {
            return;
        };
        if let Ok(mut dc) = window.begin_paint() {
            paint(&mut dc, client, &self.placed, fonts);
        }
    }

    // ----- main window -------------------------------------------------------------------

    fn on_main(&mut self, window: &Window, msg: &Msg) -> Reply {
        if let Some(action) = system_action(msg) {
            return self.on_system(action);
        }
        match msg {
            Msg::Paint => {
                self.paint_main(window);
                Reply::Handled(0)
            }
            Msg::Size { .. } => {
                self.refresh();
                Reply::Default
            }
            Msg::DpiChanged { .. } => {
                if let Some(main) = self.main.as_ref() {
                    main.invalidate();
                }
                Reply::Default
            }
            Msg::Timer(MAIN_TIMER_ID) => {
                self.tick();
                Reply::Handled(0)
            }
            Msg::Command { id, code } => {
                if *code == 0 {
                    self.on_command(*id);
                } else if *code == EN_CHANGE
                    && !self.on_sol_edit_change(*id)
                    && !self.on_btc_edit_change(*id)
                {
                    self.on_edit_change(*id);
                }
                Reply::Handled(0)
            }
            Msg::Wheel(delta) => {
                let step = window.px(60);
                let lines = i32::from(*delta) / 120;
                self.scroll = self
                    .scroll
                    .saturating_sub(lines.saturating_mul(step))
                    .max(0);
                self.refresh();
                Reply::Handled(0)
            }
            Msg::App { msg, .. } => {
                match *msg {
                    WM_YW_EVENTS => self.drain_events(),
                    WM_YW_ACTIVATE => self.activate(),
                    WM_YW_LOCK_SHORTCUT => self.lock_shortcut(),
                    _ => {}
                }
                Reply::Handled(0)
            }
            Msg::Resume => {
                logging::info("app", "power.resume", &[]);
                Reply::Default
            }
            _ => Reply::Default,
        }
    }

    fn on_system(&mut self, action: SystemAction) -> Reply {
        match action {
            SystemAction::Lock(reason) => {
                self.lock(reason);
                Reply::Default
            }
            SystemAction::AllowEndSession => Reply::Handled(1),
            SystemAction::Shutdown => {
                self.shutdown();
                Reply::Handled(0)
            }
        }
    }

    /// Ctrl+L (posted by the loop observer).
    fn lock_shortcut(&mut self) {
        if self.mode.holds_secrets() {
            self.lock(LockReason::Manual);
        }
    }

    /// Records app input for the idle timer.
    pub fn note_input(&mut self) {
        self.idle.input(now_ms());
    }

    fn activate(&mut self) {
        if let Some(main) = self.main.as_ref() {
            main.show();
            let _ = main.set_foreground();
        }
        self.background = false;
        self.refresh();
        if self.mode == AppMode::Locked && self.secret.is_none() {
            self.open_input(SecretKind::Unlock, Purpose::Unlock, false);
        }
    }

    fn tick(&mut self) {
        let now = now_ms();
        self.drain_events();
        if self.session_retries > 0 && now >= self.session_next_ms {
            self.register_session();
        }
        let paused = self
            .secret
            .as_ref()
            .is_some_and(|secret| secret.form.kind().is_display());
        self.idle.set_paused(now, paused);
        if self.mode.holds_secrets()
            && self.mode != AppMode::Unlocking
            && self.idle.should_lock(now, self.settings.auto_lock_minutes)
        {
            self.lock(LockReason::Idle);
        }
        if let Some((seq, at)) = self.secret_clip
            && now.saturating_sub(at) >= SECRET_CLIPBOARD_TTL_MS
        {
            self.clear_secret_clip(seq);
        }
        self.evm_tick(now);
        self.sol_tick(now);
        self.btc_tick(now);
        if now.saturating_sub(self.last_flush_ms) >= LOG_FLUSH_MS {
            self.last_flush_ms = now;
            logging::flush();
        }
    }

    fn clear_secret_clip(&mut self, seq: u32) {
        self.secret_clip = None;
        if let Some(main) = self.main.as_ref() {
            let result = clipboard::clear_if_unchanged(main, seq);
            logging::info(
                "app",
                "clipboard.secret_clear",
                &[(
                    "cleared",
                    Field::Word(if matches!(result, Ok(true)) {
                        "yes"
                    } else {
                        "no"
                    }),
                )],
            );
        }
    }

    // ----- lock and shutdown -------------------------------------------------------------

    /// The lock procedure (spec/04 §5.3).
    pub fn lock(&mut self, reason: LockReason) {
        let vault_present = !matches!(
            self.mode,
            AppMode::NoVault | AppMode::Starting | AppMode::Corrupt { .. } | AppMode::MainMissing
        );
        self.lock_epoch = self.lock_epoch.saturating_add(1);
        let before = self.lock_signal.count();
        self.key(KeyJob::Lock);
        self.close_secret();
        self.import = ImportFlow::default();
        self.challenge = None;
        if let Some((seq, _)) = self.secret_clip {
            self.clear_secret_clip(seq);
        }
        self.evm_lock();
        self.sol_lock();
        self.btc_lock();
        self.meta = None;
        self.rename = None;
        self.pending_remove = None;
        self.passphrase_session = false;
        logging::info("app", "lock", &[("reason", Field::Word(reason.as_str()))]);
        if reason == LockReason::Suspend {
            let _ = self
                .lock_signal
                .wait_beyond(before, Duration::from_millis(1_500));
        }
        if self.mode == AppMode::ShuttingDown {
            return;
        }
        self.startup_load = false;
        if vault_present {
            self.set_mode(AppMode::Locked);
            self.set_screen(Screen::Locked);
        } else if self.mode == AppMode::NoVault {
            self.set_screen(Screen::FirstRun);
        }
        self.key(KeyJob::Load);
    }

    /// The shutdown sequence (spec/04 §1.5).
    pub fn shutdown(&mut self) {
        if self.mode == AppMode::ShuttingDown {
            return;
        }
        self.set_mode(AppMode::ShuttingDown);
        for (item, outcome) in self.evm.queue.shutdown() {
            self.approval_finished(&item.payload, outcome);
        }
        if let Some(browser) = self.browser.as_mut() {
            browser.stop();
        }
        let before = self.lock_signal.count();
        self.lock(LockReason::Shutdown);
        let _ = self.lock_signal.wait_beyond(before, Duration::from_secs(5));
        self.key_queue.push(self.lock_epoch, KeyJob::Shutdown);
        if let Some(tx) = self.rpc_tx.take() {
            let _ = tx.send(RpcJob::Shutdown);
        }
        let deadline = now_ms().saturating_add(2_000);
        for handle in std::mem::take(&mut self.workers) {
            while !handle.is_finished() && now_ms() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            if handle.is_finished() {
                let _ = handle.join();
            }
        }
        self.controls.clear();
        if let Some(main) = self.main.take() {
            main.kill_timer(MAIN_TIMER_ID);
            session::unregister_session_notifications(&main);
            drop(main);
        }
        logging::info("app", "app.stop", &[]);
        logging::flush();
        yw_win::ui::quit(0);
    }

    // ----- events ------------------------------------------------------------------------

    fn drain_events(&mut self) {
        let Some(events) = self.events.clone() else {
            return;
        };
        for event in events.drain() {
            match event {
                UiEvent::Key(result) => self.on_key_result(result),
                UiEvent::Rpc(RpcEvent::Test {
                    network,
                    message,
                    ok,
                }) => self.on_rpc_event(network, message, ok),
                UiEvent::Rpc(event) => self.evm_rpc_event(event),
                UiEvent::Dapp(event) => self.on_dapp_event(event),
            }
        }
    }

    fn on_rpc_event(&mut self, network: NetworkId, message: String, ok: bool) {
        self.rpc_messages.retain(|(id, _, _)| *id != network);
        self.rpc_messages.push((network, message, ok));
        self.refresh();
    }

    fn secret_purpose(&self) -> Option<Purpose> {
        self.secret.as_ref().map(|secret| secret.purpose)
    }

    fn with_form(&mut self, f: impl FnOnce(&mut SecretForm)) {
        if let Some(secret) = self.secret.as_mut() {
            f(&mut secret.form);
            secret.window.invalidate();
        }
    }

    #[expect(clippy::too_many_lines, reason = "one arm per key outcome")]
    fn on_key_result(&mut self, result: KeyResult) {
        if !accept_result(&result, self.lock_epoch) {
            return;
        }
        let now = now_ms();
        match result.outcome {
            KeyOutcome::Loaded { status, leftover } => {
                self.leftover = leftover;
                self.set_mode(AppMode::from_status(status));
                let screen = match status {
                    VaultStatus::NoVault => Screen::FirstRun,
                    VaultStatus::Corrupt { .. } | VaultStatus::MainMissing => {
                        if matches!(status, VaultStatus::Corrupt { .. }) {
                            self.error_banner(ErrorCode::Vlt002);
                        }
                        Screen::Recovery
                    }
                    _ => Screen::Locked,
                };
                self.set_screen(screen);
                if status == VaultStatus::Locked && self.startup_load && !self.background {
                    self.open_input(SecretKind::Unlock, Purpose::Unlock, false);
                }
                self.startup_load = false;
                self.browser_vault_loaded();
            }
            KeyOutcome::Created(Ok((phrase, address))) => {
                self.set_mode(AppMode::BackupPending);
                self.set_screen(Screen::BackupPending);
                self.open_display(
                    SecretKind::ShowMnemonic { create: true },
                    Purpose::ShowForBackup,
                    DisplaySecret {
                        text: phrase,
                        address: Some(eip55(&address)),
                        passphrase_note: false,
                        copy_allowed: self.settings.allow_secret_copy,
                    },
                );
            }
            KeyOutcome::Created(Err(error)) => {
                self.error_banner(vault_code(error));
                self.set_screen(Screen::FirstRun);
            }
            KeyOutcome::Preview(Ok(address)) => {
                self.set_screen(Screen::ImportAddress(eip55(&address)));
            }
            KeyOutcome::Preview(Err(error)) => {
                let code = key_code(error);
                let message = match error {
                    yw_core::error::KeyError::MnemonicUnknownWord { position } => {
                        code.render(&position.to_string())
                    }
                    _ => code.text(),
                };
                self.import.phrase = None;
                self.set_screen(Screen::ImportIntro);
                self.open_input(SecretKind::Mnemonic, Purpose::ImportMnemonic, false);
                self.with_form(|form| form.set_error(Some(message)));
            }
            KeyOutcome::Imported(Ok(())) => {
                self.import = ImportFlow::default();
                self.set_mode(AppMode::Unlocked {
                    alt_passphrase: false,
                });
                self.idle.input(now);
                self.key(KeyJob::LoadMeta);
                self.set_screen(Screen::Done);
            }
            KeyOutcome::Imported(Err(error)) if error != VaultError::InvalidState => {
                self.import = ImportFlow::default();
                self.error_banner(vault_code(error));
                self.set_screen(Screen::FirstRun);
            }
            KeyOutcome::Status(result) => self.on_status(result, now),
            KeyOutcome::Cancelled("SignEvm" | "SignMessage", _) => self.evm_sign_cancelled(),
            KeyOutcome::Cancelled("SignSol", _) => self.sol_sign_cancelled(),
            KeyOutcome::Cancelled("SignBtc", _) => {
                self.btc.sign_cancelled();
                self.refresh();
            }
            outcome @ (KeyOutcome::BtcMeta(_)
            | KeyOutcome::SignedBtc(_)
            | KeyOutcome::BtcJournal(_)) => self.btc_key_outcome(outcome),
            KeyOutcome::SolKeys(purpose, result) => self.on_sol_keys(purpose, result),
            KeyOutcome::SignedSol(result) => self.on_sol_signed(result),
            KeyOutcome::SignedMessage(result) => self.browser_message_signed(result),
            KeyOutcome::Imported(Err(_))
            | KeyOutcome::LockDone
            | KeyOutcome::Cancelled(..)
            | KeyOutcome::MetaSaved(Ok(())) => {}
            outcome @ (KeyOutcome::Journal(_)
            | KeyOutcome::SignedEvm(_)
            | KeyOutcome::ActivityMoved(_)) => self.evm_key_outcome(outcome),
            KeyOutcome::Challenge(Ok(challenge)) => {
                self.challenge = Some(challenge);
                if self.secret_purpose() == Some(Purpose::Backup) {
                    self.with_form(|form| {
                        form.reset_backup(
                            challenge.positions,
                            Some(
                                "입력한 단어 또는 주소가 맞지 않습니다. 새 위치로 다시 확인합니다."
                                    .to_owned(),
                            ),
                        );
                    });
                } else {
                    self.open_input(
                        SecretKind::Backup {
                            positions: challenge.positions,
                        },
                        Purpose::Backup,
                        false,
                    );
                }
            }
            KeyOutcome::Challenge(Err(error))
            | KeyOutcome::MetaSaved(Err(error))
            | KeyOutcome::Addresses(Err(error)) => self.error_banner(vault_code(error)),
            KeyOutcome::BackupConfirmed(Ok(())) => {
                self.close_secret();
                self.challenge = None;
                logging::info("app", "backup.confirmed", &[]);
                self.set_mode(AppMode::Unlocked {
                    alt_passphrase: false,
                });
                self.idle.input(now);
                self.key(KeyJob::LoadMeta);
                self.info = Some("백업을 확인했습니다. 이제 지갑을 쓸 수 있습니다.".to_owned());
                self.set_screen(Screen::Done);
            }
            KeyOutcome::BackupConfirmed(Err(
                VaultError::BackupMismatch | VaultError::ChallengeStale,
            )) => {
                logging::info("app", "backup.mismatch", &[]);
                self.key(KeyJob::BackupChallenge);
            }
            KeyOutcome::BackupConfirmed(Err(error)) => {
                self.with_form(|form| {
                    form.set_busy(false);
                    form.set_error(Some(vault_code(error).text()));
                });
            }
            KeyOutcome::Revealed(Ok((what, secret, address))) => {
                let then_backup = matches!(
                    self.secret_purpose(),
                    Some(Purpose::ConfirmPassword(PasswordAction::RevealMnemonic {
                        then_backup: true
                    }))
                );
                self.close_secret();
                let display = DisplaySecret {
                    text: secret,
                    address: address.as_ref().map(eip55),
                    passphrase_note: self.passphrase_session,
                    copy_allowed: self.settings.allow_secret_copy,
                };
                match what {
                    RevealWhat::Mnemonic if then_backup => self.open_display(
                        SecretKind::ShowMnemonic { create: true },
                        Purpose::ShowForBackup,
                        display,
                    ),
                    RevealWhat::Mnemonic => self.open_display(
                        SecretKind::ShowMnemonic { create: false },
                        Purpose::ShowRevealed,
                        display,
                    ),
                    RevealWhat::PrivateKey(_) => {
                        self.open_display(SecretKind::ShowKey, Purpose::ShowRevealed, display);
                    }
                }
            }
            KeyOutcome::Revealed(Err(error))
            | KeyOutcome::PasswordChanged(Err(error))
            | KeyOutcome::RawKeyRemoved(Err(error)) => self.password_failure(error, now),
            KeyOutcome::PasswordChanged(Ok(())) => {
                self.close_secret();
                logging::info("app", "password.changed", &[]);
                self.info = Some("비밀번호를 바꿨습니다.".to_owned());
                self.refresh();
            }
            KeyOutcome::RawKeyImported(Ok((id, address))) => {
                self.close_secret();
                if let Some(meta) = self.meta.as_mut() {
                    let number = meta.evm_raw_accounts.len().saturating_add(1);
                    meta.evm_raw_accounts.push(RawAccount {
                        record_id: *id.as_bytes(),
                        label: format!("가져온 계정 {number}"),
                        address: address.to_lower_hex(),
                    });
                }
                logging::info(
                    "app",
                    "rawkey.imported",
                    &[("address", Field::Address(address.as_bytes()))],
                );
                self.save_meta();
                self.refresh();
            }
            KeyOutcome::RawKeyImported(Err(error)) => {
                self.with_form(|form| {
                    form.set_busy(false);
                    form.set_error(Some(vault_code(error).text()));
                });
            }
            KeyOutcome::RawKeyRemoved(Ok(id)) => {
                self.close_secret();
                let removed = self.meta.as_ref().and_then(|meta| {
                    meta.evm_raw_accounts
                        .iter()
                        .find(|raw| raw.record_id == *id.as_bytes())
                        .and_then(|raw| yw_core::evm::address::parse_address(&raw.address).ok())
                });
                if let Some(address) = removed {
                    self.account_removed_from_sites(&address);
                }
                if let Some(meta) = self.meta.as_mut() {
                    meta.evm_raw_accounts
                        .retain(|raw| raw.record_id != *id.as_bytes());
                    if meta.prefs.evm_account == EvmAccountPref::Record(*id.as_bytes()) {
                        meta.prefs.evm_account = EvmAccountPref::Index(0);
                    }
                }
                logging::info("app", "rawkey.removed", &[]);
                self.save_meta();
                self.refresh();
            }
            KeyOutcome::Meta(Ok(MetaLoaded {
                meta, prefs_reset, ..
            })) => {
                if prefs_reset {
                    logging::warn("app", "meta.prefs_reset", &[]);
                }
                self.meta = Some(meta);
                if matches!(self.mode, AppMode::Unlocked { .. })
                    && matches!(
                        self.screen,
                        Screen::Processing(_) | Screen::Locked | Screen::Starting
                    )
                {
                    self.set_screen(Screen::Main);
                } else {
                    self.refresh();
                }
                if self.evm.journal.is_none() {
                    self.evm_after_unlock();
                }
                if self.sol_tab_active() {
                    self.sol_ensure_account();
                }
                self.btc_after_meta();
            }
            KeyOutcome::Meta(Err(
                VaultError::SidecarCorrupt(_) | VaultError::SidecarVaultMismatch(_),
            )) => {
                self.error_banner(ErrorCode::Vlt006);
                self.set_screen(Screen::Confirm(Confirm::SidecarCorrupt));
            }
            KeyOutcome::Meta(Err(error)) => {
                self.error_banner(vault_code(error));
                self.meta = Some(Meta::default());
                self.set_screen(Screen::Main);
            }
            KeyOutcome::SidecarResolved(result) => {
                if let Err(code) = result {
                    self.error_banner(code);
                }
                self.evm.journal = None;
                self.key(KeyJob::LoadMeta);
                self.set_screen(Screen::Processing("불러오는 중…"));
            }
            KeyOutcome::Addresses(Ok(list)) => {
                if let Some(meta) = self.meta.as_mut() {
                    for (index, address) in list {
                        if !meta
                            .evm_accounts
                            .iter()
                            .any(|account| account.index == index)
                        {
                            meta.evm_accounts.push(new_account(index, &address));
                        }
                    }
                    meta.evm_accounts.sort_by_key(|account| account.index);
                }
                self.save_meta();
                self.refresh();
            }
        }
    }

    fn on_status(&mut self, result: Result<VaultStatus, VaultError>, now: u64) {
        match result {
            Ok(status) => {
                self.set_mode(AppMode::from_status(status));
                match status {
                    VaultStatus::PassphraseRequired => {
                        self.passphrase_session = true;
                        self.set_screen(Screen::Locked);
                        self.open_input(
                            SecretKind::Passphrase { confirm: false },
                            Purpose::EnterPassphrase,
                            false,
                        );
                    }
                    VaultStatus::PassphraseMismatch => {
                        self.close_secret();
                        self.mismatch_checked = false;
                        self.set_screen(Screen::PassMismatch);
                    }
                    VaultStatus::BackupPending => {
                        self.close_secret();
                        self.idle.input(now);
                        self.set_screen(Screen::BackupPending);
                        self.browser_vault_loaded();
                    }
                    VaultStatus::Unlocked { alt_passphrase } => {
                        self.close_secret();
                        self.idle.input(now);
                        logging::info("app", "unlock.ok", &[]);
                        if alt_passphrase {
                            self.banner(
                                None,
                                "가져올 때와 다른 passphrase로 연 지갑입니다. 계정 이름·주소록·연결 기록이 저장되지 않습니다.".to_owned(),
                            );
                        }
                        self.key(KeyJob::LoadMeta);
                        self.set_screen(Screen::Processing("불러오는 중…"));
                    }
                    VaultStatus::Corrupt { .. } | VaultStatus::MainMissing => {
                        self.close_secret();
                        self.set_screen(Screen::Recovery);
                    }
                    VaultStatus::Locked | VaultStatus::NoVault => {
                        self.close_secret();
                        self.set_screen(Screen::Locked);
                    }
                }
            }
            Err(VaultError::PayloadCorrupt) => {
                self.close_secret();
                self.error_banner(ErrorCode::Vlt008);
                self.set_mode(AppMode::Corrupt {
                    prev_available: true,
                });
                self.set_screen(Screen::Recovery);
                self.key(KeyJob::Load);
            }
            Err(error) => {
                if self.mode == AppMode::Unlocking {
                    self.set_mode(AppMode::Locked);
                }
                self.password_failure(error, now);
            }
        }
    }

    fn password_failure(&mut self, error: VaultError, now: u64) {
        if error == VaultError::UnlockFailed {
            logging::info("app", "unlock.failed", &[]);
            self.with_form(|form| form.fail_password(now));
        } else {
            let code = vault_code(error);
            logging::warn("app", "key.error", &[("code", Field::Code(code))]);
            self.with_form(|form| {
                form.set_busy(false);
                form.set_error(Some(code.text()));
            });
            if self.secret.is_none() {
                self.error_banner(code);
            }
        }
    }

    // ----- secret windows ----------------------------------------------------------------

    fn create_secret(&mut self, kind: SecretKind, topmost: bool) -> (u64, Result<Window, UiError>) {
        self.secret_serial = self.secret_serial.saturating_add(1);
        let serial = self.secret_serial;
        let Some(owner) = self.main.as_ref().map(Window::hwnd) else {
            return (serial, Err(UiError::CaptureExclusionFailed));
        };
        let (w, h) = kind.size();
        let class = if kind.is_display() {
            SECRET_VIEW_CLASS
        } else {
            SECRET_INPUT_CLASS
        };
        let spec = WindowSpec::new(class, WindowKind::Owned { owner })
            .title(&format!("Your Wallet — {}", kind.title()))
            .size(w, h)
            .topmost(topmost);
        let handler = Box::new(Forward {
            app: self.self_ref.clone(),
            target: Target::Secret(serial),
        });
        (serial, create_window(&spec, handler))
    }

    fn show_secret(&mut self, serial: u64, window: Window, form: SecretForm, purpose: Purpose) {
        let _ = window.set_timer(SECRET_TIMER_ID, SECRET_TIMER_MS);
        if let Some(main) = self.main.as_ref() {
            main.enable(false);
        }
        window.show();
        if !window.set_foreground() {
            window.flash();
        }
        window.set_focus();
        window.invalidate();
        self.secret = Some(SecretWin {
            serial,
            window,
            form,
            purpose,
        });
    }

    fn log_capture(kind: SecretKind, excluded: bool) {
        if !excluded {
            logging::warn(
                "secret",
                "secret.capture_exclusion=failed",
                &[
                    ("window", Field::Word(kind.id())),
                    (
                        "capture",
                        Field::Word(if kind.is_display() {
                            "Required"
                        } else {
                            "Preferred"
                        }),
                    ),
                ],
            );
        }
    }

    /// Opens an input window (W01–W07, W10).
    pub(crate) fn open_input(&mut self, kind: SecretKind, purpose: Purpose, topmost: bool) {
        self.close_secret();
        let (serial, created) = self.create_secret(kind, topmost);
        match created {
            Ok(window) => {
                let excluded = window.capture_excluded();
                Self::log_capture(kind, excluded);
                match capture_decision(kind, Ok(excluded)) {
                    CaptureDecision::Show { warning } => {
                        let form = SecretForm::new(kind, now_ms(), !warning);
                        self.show_secret(serial, window, form, purpose);
                    }
                    CaptureDecision::Refuse(code) => {
                        drop(window);
                        self.error_banner(code);
                    }
                }
            }
            Err(UiError::CaptureExclusionFailed) => {
                Self::log_capture(kind, false);
                self.error_banner(ErrorCode::Sec001);
            }
            Err(UiError::Os(_)) => self.error_banner(ErrorCode::App009),
        }
    }

    /// Opens a display window (W08/W09); on exclusion failure the secret is wiped (E-SEC-001).
    fn open_display(&mut self, kind: SecretKind, purpose: Purpose, display: DisplaySecret) {
        self.close_secret();
        let (serial, created) = self.create_secret(kind, false);
        let excluded = created
            .as_ref()
            .map(Window::capture_excluded)
            .map_err(|_| ());
        Self::log_capture(kind, excluded.unwrap_or(false));
        let decision = capture_decision(kind, excluded);
        match (decision, created) {
            (CaptureDecision::Show { .. }, Ok(window)) => {
                let form = SecretForm::display(kind, now_ms(), display);
                self.show_secret(serial, window, form, purpose);
            }
            (CaptureDecision::Refuse(code), _) => {
                drop(display);
                self.error_banner(code);
                if purpose == Purpose::ShowForBackup {
                    self.set_screen(Screen::BackupPending);
                }
            }
            (CaptureDecision::Show { .. }, Err(_)) => {
                drop(display);
                self.error_banner(ErrorCode::App009);
            }
        }
    }

    /// Whether a secret window (W01–W10) is open.
    #[must_use]
    pub fn secret_open(&self) -> bool {
        self.secret.is_some()
    }

    /// Closes the open secret window (buffers wiped).
    pub fn close_secret(&mut self) {
        if let Some(mut secret) = self.secret.take() {
            secret.form.wipe();
            secret.window.kill_timer(SECRET_TIMER_ID);
            if let Some(main) = self.main.as_ref() {
                main.enable(true);
            }
            drop(secret.window);
            if let Some(main) = self.main.as_ref() {
                let _ = main.set_foreground();
            }
        }
    }

    fn on_secret(&mut self, serial: u64, window: &Window, msg: &Msg) -> Reply {
        let now = now_ms();
        let dpi = window.dpi();
        let Self { secret, fonts, .. } = self;
        let Some(secret) = secret.as_mut().filter(|secret| secret.serial == serial) else {
            return Reply::Default;
        };
        let form = &mut secret.form;
        let action = match msg {
            Msg::Paint => {
                if let Some(fonts) = fonts.for_dpi(dpi)
                    && let Ok(mut dc) = window.begin_paint()
                {
                    form.paint(&mut dc, window.client_rect(), fonts, dpi, now);
                }
                return Reply::Handled(0);
            }
            Msg::Char(unit) => form.on_char(*unit, now),
            Msg::KeyDown { vk, .. } => {
                let action = form.on_key(
                    *vk,
                    is_down(VK_CONTROL),
                    is_down(VK_SHIFT),
                    is_down(VK_MENU),
                    now,
                );
                if matches!(action, FormAction::None) {
                    return Reply::Default;
                }
                action
            }
            Msg::MouseDown { x, y } => {
                let (action, capture) = form.on_mouse_down(*x, *y, now);
                if capture {
                    window.set_capture();
                }
                action
            }
            Msg::MouseUp { x, y } => {
                window.release_capture();
                form.on_mouse_up(*x, *y, now)
            }
            Msg::MouseMove { x, y } => form.on_mouse_move(*x, *y),
            Msg::Timer(SECRET_TIMER_ID) => form.on_tick(now),
            Msg::ActivateApp(false) | Msg::KillFocus { to_foreign: true } => form.on_deactivate(),
            Msg::ActivateApp(true) => {
                form.on_activate();
                FormAction::Redraw
            }
            Msg::CaptureChanged | Msg::CancelMode => form.on_capture_lost(),
            Msg::MouseActivate => {
                return if window.is_foreground() {
                    Reply::Default
                } else {
                    Reply::Handled(MA_ACTIVATEANDEAT)
                };
            }
            Msg::ImeAttempt => form.on_key(0xE5, false, false, false, now),
            Msg::Size { .. } | Msg::DpiChanged { .. } => {
                window.invalidate();
                return Reply::Default;
            }
            Msg::Close => {
                let action = if form.kind().is_display()
                    && form.kind() != (SecretKind::ShowMnemonic { create: true })
                {
                    form.wipe();
                    FormAction::Close
                } else {
                    form.wipe();
                    FormAction::Cancel
                };
                self.apply_form_action(action);
                return Reply::Handled(0);
            }
            _ => return Reply::Default,
        };
        self.apply_form_action(action);
        Reply::Handled(0)
    }

    fn apply_form_action(&mut self, action: FormAction) {
        let Some(purpose) = self.secret_purpose() else {
            return;
        };
        match action {
            FormAction::None => {}
            FormAction::Redraw => {
                if let Some(secret) = self.secret.as_ref() {
                    secret.window.invalidate();
                }
            }
            FormAction::Submit(submission) => self.on_submit(purpose, submission),
            FormAction::Cancel | FormAction::TimedOut => {
                let timed_out = matches!(action, FormAction::TimedOut);
                self.on_cancel(purpose);
                if timed_out {
                    self.info = Some("시간이 지나 창을 닫았습니다.".to_owned());
                    self.refresh();
                }
            }
            FormAction::Close => {
                self.close_secret();
                self.refresh();
            }
            FormAction::Paste => self.paste(),
            FormAction::Copy => self.copy_secret(),
            FormAction::HoldComplete => {
                self.close_secret();
                logging::info("app", "backup.written_ack", &[]);
                self.key(KeyJob::BackupChallenge);
            }
        }
    }

    fn paste(&mut self) {
        let Some(secret) = self.secret.as_mut() else {
            return;
        };
        let read = clipboard::read_text(&secret.window, PASTE_MAX_UTF16_UNITS);
        let message = match read {
            Ok((units, seq)) => match secret.form.apply_paste(units.as_slice()) {
                Ok(()) => {
                    drop(units);
                    match clipboard::clear_if_unchanged(&secret.window, seq) {
                        Ok(true) => Some("붙여넣은 뒤 클립보드를 비웠습니다. Windows 클립보드 기록(Win+V)을 쓴다면 그 항목도 지우세요.".to_owned()),
                        Ok(false) => None,
                        Err(_) => Some(ErrorCode::Sec002.text()),
                    }
                }
                Err(code) => {
                    secret.form.set_error(Some(code.text()));
                    None
                }
            },
            Err(ClipError::TooLong) => {
                secret.form.set_error(Some(ErrorCode::Inp018.text()));
                None
            }
            Err(ClipError::Busy | ClipError::Os(_)) => Some(ErrorCode::Sec002.text()),
        };
        logging::info(
            "secret",
            "clipboard.paste",
            &[("window", Field::Word(secret.form.kind().id()))],
        );
        if message.is_some() {
            secret.form.set_info(message);
        }
        secret.window.invalidate();
    }

    fn copy_secret(&mut self) {
        let allowed = self.settings.allow_secret_copy;
        let Some(secret) = self.secret.as_mut() else {
            return;
        };
        if !allowed {
            secret.form.set_info(Some(
                "복사가 꺼져 있습니다. 설정에서 바꿀 수 있습니다.".to_owned(),
            ));
            secret.window.invalidate();
            return;
        }
        let Some(units) = secret.form.copy_units() else {
            return;
        };
        match clipboard::set_secret_text(&secret.window, &units) {
            Ok(seq) => {
                self.secret_clip = Some((seq, now_ms()));
                secret.form.set_info(Some(
                    "클립보드에 복사했습니다. 30초 뒤 지웁니다.".to_owned(),
                ));
                logging::info(
                    "secret",
                    "clipboard.secret_copy",
                    &[("window", Field::Word(secret.form.kind().id()))],
                );
            }
            Err(_) => secret.form.set_error(Some(ErrorCode::Sec002.text())),
        }
        secret.window.invalidate();
    }

    fn on_submit(&mut self, purpose: Purpose, submission: Submission) {
        let mut values = submission.values.into_iter();
        let mut next = || values.next().unwrap_or_default();
        match purpose {
            Purpose::CreatePassword => {
                let password = next();
                self.close_secret();
                self.set_screen(Screen::Processing(
                    "지갑을 만드는 중입니다. 몇 초 걸립니다.",
                ));
                self.key(KeyJob::CreateWallet { password });
            }
            Purpose::ImportPassword => {
                self.import.password = Some(next());
                self.import.password_sent = false;
                self.open_input(SecretKind::Mnemonic, Purpose::ImportMnemonic, false);
            }
            Purpose::ImportMnemonic => {
                let phrase = next();
                if submission.checkbox {
                    self.import.phrase = Some(phrase);
                    self.open_input(
                        SecretKind::Passphrase { confirm: true },
                        Purpose::ImportPassphrase,
                        false,
                    );
                } else {
                    self.preview_import(phrase, None);
                }
            }
            Purpose::ImportPassphrase => {
                let passphrase = next();
                if let Some(phrase) = self.import.phrase.take() {
                    self.preview_import(phrase, Some(passphrase));
                } else {
                    self.close_secret();
                }
            }
            Purpose::Unlock => {
                self.set_mode(AppMode::Unlocking);
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::Unlock { password: next() });
            }
            Purpose::EnterPassphrase => {
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::EnterPassphrase { passphrase: next() });
            }
            Purpose::Backup => {
                let Some(challenge) = self.challenge else {
                    self.close_secret();
                    return;
                };
                let words = [next(), next(), next(), next()];
                let suffix = next();
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::ConfirmBackup {
                    id: challenge.id,
                    words,
                    suffix,
                });
            }
            Purpose::ConfirmPassword(action) => {
                let password = next();
                self.with_form(|form| form.set_busy(true));
                match action {
                    PasswordAction::RevealMnemonic { .. } => self.key(KeyJob::Reveal {
                        password,
                        what: RevealWhat::Mnemonic,
                    }),
                    PasswordAction::RevealKey(source) => self.key(KeyJob::Reveal {
                        password,
                        what: RevealWhat::PrivateKey(source),
                    }),
                    PasswordAction::RemoveKey(id) => {
                        self.key(KeyJob::RemoveRawKey { password, id });
                    }
                    PasswordAction::Recover => {
                        self.set_mode(AppMode::Unlocking);
                        self.key(KeyJob::RecoverFromPrev { password });
                    }
                }
            }
            Purpose::ChangePassword => {
                let old = next();
                let new = next();
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::ChangePassword { old, new });
            }
            Purpose::ImportKey => {
                self.with_form(|form| form.set_busy(true));
                self.key(KeyJob::ImportPrivateKey { hex: next() });
            }
            Purpose::ShowForBackup | Purpose::ShowRevealed => {}
        }
    }

    fn preview_import(
        &mut self,
        phrase: Zeroizing<Vec<u8>>,
        passphrase: Option<Zeroizing<Vec<u8>>>,
    ) {
        self.close_secret();
        let password = if self.import.password_sent {
            None
        } else {
            self.import.password_sent = true;
            self.import.password.take()
        };
        self.set_screen(Screen::Processing("확인 중…"));
        self.key(KeyJob::PreviewImport {
            password,
            phrase,
            passphrase,
        });
    }

    fn on_cancel(&mut self, purpose: Purpose) {
        self.close_secret();
        match purpose {
            Purpose::CreatePassword => self.set_screen(Screen::FirstRun),
            Purpose::ImportPassword | Purpose::ImportMnemonic | Purpose::ImportPassphrase => {
                self.import = ImportFlow::default();
                self.key(KeyJob::DiscardImport {
                    keep_password: false,
                });
                self.set_screen(Screen::FirstRun);
            }
            Purpose::EnterPassphrase => self.lock(LockReason::Manual),
            Purpose::Unlock => {
                if self.mode == AppMode::Unlocking {
                    self.set_mode(AppMode::Locked);
                }
                self.dapp_unlock_dismissed();
                self.refresh();
            }
            Purpose::ShowForBackup | Purpose::Backup => {
                self.challenge = None;
                self.set_screen(Screen::BackupPending);
            }
            Purpose::ConfirmPassword(PasswordAction::Recover) => {
                self.set_mode(AppMode::from_status(VaultStatus::MainMissing));
                self.key(KeyJob::Load);
            }
            Purpose::ConfirmPassword(_)
            | Purpose::ShowRevealed
            | Purpose::ChangePassword
            | Purpose::ImportKey => self.refresh(),
        }
    }

    // ----- meta, settings, apikeys -------------------------------------------------------

    pub(crate) fn save_meta(&mut self) {
        if let Some(meta) = self.meta.clone() {
            self.key(KeyJob::SaveMeta {
                meta: Box::new(meta),
            });
        }
    }

    /// Writes `settings` atomically; on failure keeps the previous values (E-APP-002).
    pub fn save_settings(&mut self, settings: Settings, key: &'static str) {
        match atomic_write(&self.paths.settings(), &settings.to_json()) {
            Ok(()) => {
                if settings.log_level != self.settings.log_level {
                    logging::set_level(settings.log_level);
                }
                self.settings = settings;
                logging::info("app", "settings.changed", &[("key", Field::Word(key))]);
            }
            Err(_) => self.error_banner(ErrorCode::App002),
        }
        self.refresh();
    }

    /// Encrypts and writes `apikeys.dpapi`; on failure reloads the previous file (E-APP-002).
    pub fn save_apikeys(&mut self) -> bool {
        let plain = self.apikeys.encode();
        let written = yw_win::dpapi::protect(&plain, APIKEYS_ENTROPY)
            .ok()
            .is_some_and(|blob| atomic_write(&self.paths.apikeys(), &blob).is_ok());
        if !written {
            let (keys, _) = load_apikeys(&self.paths, &self.settings);
            self.apikeys = keys;
            self.error_banner(ErrorCode::App002);
        }
        written
    }

    fn open_folder(path: &Path) {
        let root = std::env::var_os("SystemRoot")
            .map_or_else(|| PathBuf::from("C:\\Windows"), PathBuf::from);
        let spawned = std::process::Command::new(root.join("explorer.exe"))
            .arg(path)
            .spawn();
        logging::info(
            "app",
            "folder.open",
            &[(
                "ok",
                Field::Word(if spawned.is_ok() { "yes" } else { "no" }),
            )],
        );
    }

    // ----- commands ----------------------------------------------------------------------

    #[expect(clippy::too_many_lines, reason = "one arm per command id")]
    fn on_command(&mut self, id: u16) {
        use crate::ui::screens::ids;
        self.note_input();
        match id {
            ids::FIRST_CREATE => self.set_screen(Screen::CreateIntro),
            ids::FIRST_IMPORT => self.set_screen(Screen::ImportIntro),
            ids::OPEN_DATA_FOLDER => Self::open_folder(&self.paths.data.clone()),
            ids::OPEN_LOG_FOLDER => Self::open_folder(&self.paths.logs.clone()),
            ids::CREATE_NEXT => {
                self.open_input(SecretKind::SetPassword, Purpose::CreatePassword, false);
            }
            ids::INTRO_CANCEL => self.set_screen(Screen::FirstRun),
            ids::IMPORT_NEXT => {
                self.open_input(SecretKind::SetPassword, Purpose::ImportPassword, false);
            }
            ids::IMPORT_CORRECT => {
                self.set_screen(Screen::Processing(
                    "지갑을 가져오는 중입니다. 몇 초 걸립니다.",
                ));
                self.key(KeyJob::CommitImport);
            }
            ids::IMPORT_WRONG => {
                self.key(KeyJob::DiscardImport {
                    keep_password: true,
                });
                self.set_screen(Screen::ImportIntro);
                self.open_input(SecretKind::Mnemonic, Purpose::ImportMnemonic, false);
            }
            ids::UNLOCK => self.open_input(SecretKind::Unlock, Purpose::Unlock, false),
            ids::BACKUP_CHECK => self.open_input(
                SecretKind::ConfirmPassword,
                Purpose::ConfirmPassword(PasswordAction::RevealMnemonic { then_backup: true }),
                false,
            ),
            ids::LOCK => self.lock(LockReason::Manual),
            ids::DONE_CONTINUE | ids::BACK_MAIN => {
                self.info = None;
                if self.meta.is_some() {
                    self.set_screen(Screen::Main);
                } else {
                    self.key(KeyJob::LoadMeta);
                    self.set_screen(Screen::Processing("불러오는 중…"));
                }
            }
            ids::RECOVER => self.open_input(
                SecretKind::ConfirmPassword,
                Purpose::ConfirmPassword(PasswordAction::Recover),
                false,
            ),
            ids::EXIT => self.shutdown(),
            ids::MISMATCH_RETRY => {
                self.key(KeyJob::RetryPassphrase);
            }
            ids::MISMATCH_CHECK => {
                self.mismatch_checked = self.controls.checked(ids::MISMATCH_CHECK).unwrap_or(false);
                self.refresh();
            }
            ids::MISMATCH_CONTINUE => {
                if self.mismatch_checked {
                    self.key(KeyJob::AcceptMismatch);
                }
            }
            ids::SIDECAR_PREV | ids::SIDECAR_FRESH => {
                self.key(KeyJob::ResolveSidecar {
                    kind: FileKind::Meta,
                    use_prev: id == ids::SIDECAR_PREV,
                });
            }
            ids::OPEN_SETTINGS | ids::SECTION_SECURITY => {
                self.set_screen(Screen::Settings(SettingsSection::Security));
            }
            ids::DONE_RPC | ids::SECTION_NETWORK => {
                self.set_screen(Screen::Settings(SettingsSection::Network));
            }
            ids::SECTION_OTHER => self.set_screen(Screen::Settings(SettingsSection::Other)),
            ids::DISMISS_BANNERS => {
                self.banners.clear();
                self.info = None;
                self.refresh();
            }
            ids::ADD_ACCOUNT => {
                if let Some(index) = self.meta.as_ref().and_then(Meta::next_index) {
                    self.key(KeyJob::DeriveAddresses {
                        indices: vec![index],
                    });
                }
            }
            ids::IMPORT_KEY => {
                if matches!(self.mode, AppMode::Unlocked { .. }) {
                    self.open_input(SecretKind::PrivateKey, Purpose::ImportKey, false);
                }
            }
            ids::RENAME => {
                self.rename = self.meta.as_ref().map(|meta| meta.prefs.evm_account);
                self.refresh();
            }
            ids::RENAME_CANCEL => {
                self.rename = None;
                self.refresh();
            }
            ids::RENAME_SAVE => self.save_rename(),
            ids::HIDE => self.hide_selected(),
            ids::REMOVE_KEY => {
                if let Some(EvmAccountPref::Record(id)) =
                    self.meta.as_ref().map(|meta| meta.prefs.evm_account)
                {
                    self.pending_remove = Some(RecordId::from_bytes(id));
                    self.set_screen(Screen::Confirm(Confirm::RemoveKey));
                }
            }
            ids::REVEAL_MNEMONIC => self.set_screen(Screen::Confirm(Confirm::RevealMnemonic)),
            ids::REVEAL_KEY => self.set_screen(Screen::Confirm(Confirm::RevealKey)),
            ids::CHANGE_PASSWORD => {
                self.open_input(SecretKind::ChangePassword, Purpose::ChangePassword, false);
            }
            ids::AUTOLOCK_SAVE => self.save_autolock(),
            ids::COPY_TOGGLE => {
                let checked = self.controls.checked(ids::COPY_TOGGLE).unwrap_or(false);
                if checked && !self.settings.allow_secret_copy {
                    self.set_screen(Screen::Confirm(Confirm::CopyOn));
                } else if !checked {
                    let mut settings = self.settings.clone();
                    settings.allow_secret_copy = false;
                    self.save_settings(settings, "allowSecretCopy");
                }
            }
            ids::LOCALHOST_TOGGLE => {
                let checked = self
                    .controls
                    .checked(ids::LOCALHOST_TOGGLE)
                    .unwrap_or(false);
                if checked && !self.settings.allow_localhost_dapps {
                    self.set_screen(Screen::Confirm(Confirm::LocalhostOn));
                } else if !checked {
                    let mut settings = self.settings.clone();
                    settings.allow_localhost_dapps = false;
                    self.save_settings(settings, "allowLocalhostDapps");
                }
            }
            ids::AUTOLAUNCH_TOGGLE => {
                let mut settings = self.settings.clone();
                settings.browser_auto_launch = self
                    .controls
                    .checked(ids::AUTOLAUNCH_TOGGLE)
                    .unwrap_or(true);
                self.save_settings(settings, "browserAutoLaunch");
            }
            ids::LOG_ERROR | ids::LOG_WARN | ids::LOG_INFO | ids::LOG_DEBUG => {
                let level = match id {
                    ids::LOG_ERROR => LogLevel::Error,
                    ids::LOG_WARN => LogLevel::Warn,
                    ids::LOG_DEBUG => LogLevel::Debug,
                    _ => LogLevel::Info,
                };
                let mut settings = self.settings.clone();
                settings.log_level = level;
                self.save_settings(settings, "logLevel");
            }
            ids::TPL_QUICKNODE | ids::TPL_ALCHEMY | ids::TPL_MANUAL => {
                let template = match id {
                    ids::TPL_QUICKNODE => RpcTemplate::QuickNode,
                    ids::TPL_ALCHEMY => RpcTemplate::Alchemy,
                    _ => RpcTemplate::Manual,
                };
                let mut settings = self.settings.clone();
                settings.rpc_template = template;
                self.save_settings(settings, "rpc.template");
            }
            ids::TPL_SAVE => {
                let _ = self.save_template_credentials();
                self.refresh();
            }
            ids::TPL_DELETE => self.delete_template_credentials(),
            ids::GENERATE => self.begin_generate(),
            ids::OVERWRITE_CHECK => {
                self.overwrite_checked =
                    self.controls.checked(ids::OVERWRITE_CHECK).unwrap_or(false);
                self.refresh();
            }
            ids::REPLACE_SAVE => self.save_replacement(),
            ids::REPLACE_CANCEL => {
                self.replace_target = None;
                self.refresh();
            }
            ids::CONFIRM_YES => self.confirm_yes(),
            ids::CONFIRM_NO if matches!(self.screen, Screen::Confirm(Confirm::Btc)) => {
                self.btc_confirm_no();
            }
            ids::CONFIRM_NO => {
                self.pending_remove = None;
                self.evm.discard = None;
                self.evm.delete_chain = None;
                self.evm.repin = None;
                if let Some(form) = self.evm.chain_form.as_mut() {
                    form.pending = None;
                    form.message = None;
                }
                if matches!(self.screen, Screen::Confirm(Confirm::BookDelete)) {
                    self.evm.book = crate::app_evm::BookForm::default();
                }
                let previous = self.previous_screen.clone();
                self.set_screen(previous);
            }
            other => {
                if !self.on_sol_command(other)
                    && !self.on_btc_command(other)
                    && !self.on_evm_command(other)
                    && !self.on_sites_command(other)
                {
                    self.on_indexed_command(other);
                }
            }
        }
    }

    fn on_indexed_command(&mut self, id: u16) {
        use crate::ui::screens::ids;
        if let Some(index) = id
            .checked_sub(ids::NETWORK_BASE)
            .filter(|offset| *offset < ids::NETWORK_SPAN)
        {
            let chains = self.settings.registered_evm();
            if let Some(chain_id) = chains.get(usize::from(index)).copied() {
                let mut settings = self.settings.clone();
                settings.evm_chain_id = chain_id;
                self.save_settings(settings, "evmChainId");
            }
            return;
        }
        if let Some(offset) = id
            .checked_sub(ids::ACCOUNT_BASE)
            .filter(|offset| *offset < ids::ACCOUNT_SPAN)
        {
            self.select_account(usize::from(offset));
            return;
        }
        if let Some(offset) = id
            .checked_sub(ids::ROW_BASE)
            .filter(|offset| *offset < ids::ROW_SPAN)
        {
            let row = usize::from(offset / 4);
            let networks = self.url_networks();
            let Some(network) = networks.get(row).copied() else {
                return;
            };
            match offset % 4 {
                0 => {
                    self.replace_target = Some(network);
                    self.refresh();
                }
                1 => self.test_network(network),
                2 => {
                    if self.apikeys.remove(KeyName::Rpc(network)) && self.save_apikeys() {
                        logging::info("app", "rpc.url_deleted", &[("net", Field::Net(network))]);
                        self.network_url_changed(network);
                    }
                    self.rpc_messages.retain(|(id, _, _)| *id != network);
                    self.refresh();
                }
                _ => {}
            }
        }
    }

    /// Networks in the URL list (spec/04 §2.11.1 order).
    #[must_use]
    pub fn url_networks(&self) -> Vec<NetworkId> {
        let mut networks: Vec<NetworkId> = self
            .settings
            .registered_evm()
            .into_iter()
            .map(NetworkId::Eip155)
            .collect();
        networks.push(NetworkId::Solana(crate::network::SolCluster::Mainnet));
        networks.push(NetworkId::Solana(crate::network::SolCluster::Devnet));
        networks.push(NetworkId::Bitcoin(crate::network::BtcNet::Mainnet));
        networks.push(NetworkId::Bitcoin(crate::network::BtcNet::Testnet4));
        networks
    }

    /// Display name of a network.
    #[must_use]
    pub fn network_name(&self, network: NetworkId) -> String {
        match network {
            NetworkId::Eip155(id) => self
                .settings
                .evm_chain_name(id)
                .unwrap_or_else(|| format!("chainId {id}")),
            NetworkId::Solana(cluster) => crate::app_sol::core_cluster(cluster)
                .display_name()
                .to_owned(),
            NetworkId::Bitcoin(net) => crate::btc::core_network(net).display_name().to_owned(),
        }
    }

    /// Visible EVM accounts in display order: derived (not hidden) then raw keys.
    #[must_use]
    pub fn account_rows(&self) -> Vec<(EvmAccountPref, String, String, String)> {
        let Some(meta) = self.meta.as_ref() else {
            return Vec::new();
        };
        let checksum = |text: &str| {
            yw_core::evm::address::parse_address(text)
                .map_or_else(|_| text.to_owned(), |address| eip55(&address))
        };
        let mut rows: Vec<_> = meta
            .evm_accounts
            .iter()
            .filter(|account| !account.hidden)
            .map(|account| {
                (
                    EvmAccountPref::Index(account.index),
                    account.label.clone(),
                    checksum(&account.address),
                    format!("m/44'/60'/0'/0/{}", account.index),
                )
            })
            .collect();
        rows.extend(meta.evm_raw_accounts.iter().map(|raw| {
            (
                EvmAccountPref::Record(raw.record_id),
                raw.label.clone(),
                checksum(&raw.address),
                "가져온 개인키".to_owned(),
            )
        }));
        rows
    }

    fn select_account(&mut self, row: usize) {
        let rows = self.account_rows();
        if let (Some((pref, ..)), Some(meta)) = (rows.get(row), self.meta.as_mut()) {
            meta.prefs.evm_account = *pref;
            self.rename = None;
            self.save_meta();
        }
        self.refresh();
    }

    fn save_rename(&mut self) {
        use crate::ui::screens::ids;
        let label = self.controls.text(ids::RENAME_EDIT, 64).unwrap_or_default();
        if !is_valid_label(&label) {
            self.info = Some(ErrorCode::Inp017.text());
            self.refresh();
            return;
        }
        if let (Some(target), Some(meta)) = (self.rename, self.meta.as_mut()) {
            match target {
                EvmAccountPref::Index(index) => {
                    if let Some(account) = meta
                        .evm_accounts
                        .iter_mut()
                        .find(|account| account.index == index)
                    {
                        account.label = label;
                    }
                }
                EvmAccountPref::Record(id) => {
                    if let Some(raw) = meta
                        .evm_raw_accounts
                        .iter_mut()
                        .find(|raw| raw.record_id == id)
                    {
                        raw.label = label;
                    }
                }
            }
        }
        self.rename = None;
        self.info = None;
        self.save_meta();
        self.refresh();
    }

    fn hide_selected(&mut self) {
        if let Some(meta) = self.meta.as_mut()
            && let EvmAccountPref::Index(index) = meta.prefs.evm_account
            && index != 0
            && let Some(account) = meta
                .evm_accounts
                .iter_mut()
                .find(|account| account.index == index)
        {
            account.hidden = true;
            let hidden = yw_core::evm::address::parse_address(&account.address).ok();
            meta.prefs.evm_account = EvmAccountPref::Index(0);
            self.save_meta();
            if let Some(address) = hidden {
                self.account_removed_from_sites(&address);
            }
        }
        self.refresh();
    }

    fn save_autolock(&mut self) {
        use crate::ui::screens::ids;
        let text = self
            .controls
            .text(ids::AUTOLOCK_EDIT, 8)
            .unwrap_or_default();
        match text.trim().parse::<u8>() {
            Ok(minutes) if (1..=60).contains(&minutes) => {
                let mut settings = self.settings.clone();
                settings.auto_lock_minutes = minutes;
                self.info = Some(format!("자동 잠금을 {minutes}분으로 저장했습니다."));
                self.save_settings(settings, "autoLockMinutes");
            }
            _ => {
                self.info = Some("자동 잠금은 1–60분입니다.".to_owned());
                self.refresh();
            }
        }
    }

    fn read_wiping(&self, id: u16, max: usize) -> Zeroizing<String> {
        let units = self.controls.text_wiping(id, max);
        let mut out = Zeroizing::new(String::new());
        if let Some(units) = units {
            for unit in units.as_slice() {
                if let Some(character) = char::from_u32(u32::from(*unit)) {
                    out.push(character);
                }
            }
        }
        out
    }

    /// `저장` of the template credentials (spec/04 §2.11): E-KEY-002 with the item name.
    fn save_template_credentials(&mut self) -> Result<(), ErrorCode> {
        use crate::ui::screens::ids;
        match self.settings.rpc_template {
            RpcTemplate::QuickNode => {
                let name = self.read_wiping(ids::QN_NAME_EDIT, 128);
                let token = self.read_wiping(ids::QN_TOKEN_EDIT, TOKEN_MAX_UNITS);
                if name.is_empty() && token.is_empty() {
                    return Ok(());
                }
                let lower = name.trim().to_ascii_lowercase();
                if !valid_quicknode_name(&lower) {
                    self.info = Some(
                        ErrorCode::Key002
                            .text()
                            .replace(" (E-KEY-002)", " (엔드포인트 이름) (E-KEY-002)"),
                    );
                    return Err(ErrorCode::Key002);
                }
                let token = token.trim();
                if !valid_provider_token(token) {
                    self.info = Some(
                        ErrorCode::Key002
                            .text()
                            .replace(" (E-KEY-002)", " (토큰) (E-KEY-002)"),
                    );
                    return Err(ErrorCode::Key002);
                }
                self.apikeys.set_quicknode(&lower, token);
            }
            RpcTemplate::Alchemy => {
                let key = self.read_wiping(ids::ALCHEMY_KEY_EDIT, TOKEN_MAX_UNITS);
                if key.is_empty() {
                    return Ok(());
                }
                if !valid_provider_token(key.trim()) {
                    self.info = Some(
                        ErrorCode::Key002
                            .text()
                            .replace(" (E-KEY-002)", " (알케미 키) (E-KEY-002)"),
                    );
                    return Err(ErrorCode::Key002);
                }
                self.apikeys.set_alchemy(key.trim());
            }
            RpcTemplate::Manual => return Ok(()),
        }
        self.controls.clear_text(ids::QN_NAME_EDIT);
        self.controls.clear_text(ids::QN_TOKEN_EDIT);
        self.controls.clear_text(ids::ALCHEMY_KEY_EDIT);
        if self.save_apikeys() {
            logging::info(
                "app",
                "tpl.saved",
                &[("template", Field::Word(self.settings.rpc_template.as_str()))],
            );
            self.info = Some("템플릿 자격 정보를 저장했습니다.".to_owned());
        }
        Ok(())
    }

    fn delete_template_credentials(&mut self) {
        let name = match self.settings.rpc_template {
            RpcTemplate::QuickNode => KeyName::TplQuickNode,
            RpcTemplate::Alchemy => KeyName::TplAlchemy,
            RpcTemplate::Manual => return,
        };
        if self.apikeys.remove(name) && self.save_apikeys() {
            logging::info(
                "app",
                "tpl.deleted",
                &[("template", Field::Word(self.settings.rpc_template.as_str()))],
            );
        }
        self.refresh();
    }

    /// Generation targets and skipped networks for the current template.
    #[must_use]
    pub fn generation_plan(&self) -> (Vec<NetworkId>, Vec<NetworkId>) {
        let template = self.settings.rpc_template;
        self.url_networks()
            .into_iter()
            .partition(|network| template_entry(template, *network, &self.settings).is_some())
    }

    fn begin_generate(&mut self) {
        if self.settings.rpc_template == RpcTemplate::Manual {
            return;
        }
        if self.save_template_credentials().is_err() {
            self.refresh();
            return;
        }
        if self
            .apikeys
            .credential(self.settings.rpc_template)
            .is_none()
        {
            self.info = Some(ErrorCode::Key004.text());
            self.refresh();
            return;
        }
        self.overwrite_checked = false;
        self.set_screen(Screen::Confirm(Confirm::Generate));
    }

    fn generate(&mut self) {
        let template = self.settings.rpc_template;
        let Some(credential) = self.apikeys.credential(template) else {
            self.info = Some(ErrorCode::Key004.text());
            return;
        };
        let (targets, skipped) = self.generation_plan();
        let written = self.apikeys.generate_urls(
            template,
            &credential,
            &self.settings,
            &targets,
            self.overwrite_checked,
        );
        drop(credential);
        if self.save_apikeys() {
            for network in &written {
                logging::info("app", "rpc.generated", &[("net", Field::Net(*network))]);
                self.rpc_messages.retain(|(id, _, _)| id != network);
                self.network_url_changed(*network);
            }
            let skipped_names: Vec<String> = skipped
                .iter()
                .map(|network| self.network_name(*network))
                .collect();
            self.info = Some(format!(
                "RPC URL {}개를 만들었습니다. 템플릿 항목이 없는 네트워크 {}개는 직접 입력하세요: {}",
                written.len(),
                skipped.len(),
                if skipped_names.is_empty() {
                    "없음".to_owned()
                } else {
                    skipped_names.join(", ")
                }
            ));
        }
    }

    fn save_replacement(&mut self) {
        use crate::ui::screens::ids;
        let Some(network) = self.replace_target else {
            return;
        };
        let text = self.read_wiping(ids::REPLACE_EDIT, URL_MAX_UNITS);
        match HttpsUrl::parse(text.trim()) {
            Ok(url) => {
                self.apikeys.set_rpc(network, &url);
                if self.save_apikeys() {
                    logging::info("app", "rpc.url_set", &[("net", Field::Net(network))]);
                    self.rpc_messages.retain(|(id, _, _)| *id != network);
                    self.network_url_changed(network);
                }
                self.controls.clear_text(ids::REPLACE_EDIT);
                self.replace_target = None;
            }
            Err(_) => self.set_rpc_message(network, ErrorCode::Key003.text(), false),
        }
        self.refresh();
    }

    fn set_rpc_message(&mut self, network: NetworkId, message: String, ok: bool) {
        self.rpc_messages.retain(|(id, _, _)| *id != network);
        self.rpc_messages.push((network, message, ok));
    }

    fn test_network(&mut self, network: NetworkId) {
        use crate::ui::screens::ids;
        let typed = if self.replace_target == Some(network) {
            self.read_wiping(ids::REPLACE_EDIT, URL_MAX_UNITS)
        } else {
            Zeroizing::new(String::new())
        };
        let parsed = crate::rpc::endpoint_for_test(&typed, self.apikeys.rpc_url(network));
        let url = match parsed {
            Ok(url) => url,
            Err(code) => {
                logging::info(
                    "rpc",
                    "rpc.test",
                    &[("net", Field::Net(network)), ("result", Field::Code(code))],
                );
                self.set_rpc_message(network, code.text(), false);
                self.refresh();
                return;
            }
        };
        let name = self.network_name(network);
        if let Some(tx) = self.rpc_tx.as_ref()
            && tx.send(RpcJob::Test { network, name, url }).is_ok()
        {
            self.set_rpc_message(network, "테스트 중…".to_owned(), false);
        }
        self.refresh();
    }

    #[expect(clippy::too_many_lines, reason = "one arm per confirmation overlay")]
    fn confirm_yes(&mut self) {
        let Screen::Confirm(kind) = self.screen.clone() else {
            return;
        };
        let previous = self.previous_screen.clone();
        match kind {
            Confirm::CopyOn => {
                let mut settings = self.settings.clone();
                settings.allow_secret_copy = true;
                self.screen = previous;
                self.save_settings(settings, "allowSecretCopy");
            }
            Confirm::LocalhostOn => {
                let mut settings = self.settings.clone();
                settings.allow_localhost_dapps = true;
                self.screen = previous;
                self.save_settings(settings, "allowLocalhostDapps");
            }
            Confirm::DisconnectAll => {
                self.disconnect_all_sites();
                self.set_screen(Screen::Sites);
            }
            Confirm::RevealMnemonic => {
                self.set_screen(previous);
                self.open_input(
                    SecretKind::ConfirmPassword,
                    Purpose::ConfirmPassword(PasswordAction::RevealMnemonic { then_backup: false }),
                    false,
                );
            }
            Confirm::RevealKey => {
                self.set_screen(previous);
                let source = match self.meta.as_ref().map(|meta| meta.prefs.evm_account) {
                    Some(EvmAccountPref::Record(id)) => EvmKeySource::Raw(RecordId::from_bytes(id)),
                    Some(EvmAccountPref::Index(index)) => {
                        yw_core::bip32::path::AccountIndex::new(index).map_or(
                            EvmKeySource::Derived(yw_core::bip32::path::AccountIndex::ZERO),
                            EvmKeySource::Derived,
                        )
                    }
                    None => EvmKeySource::Derived(yw_core::bip32::path::AccountIndex::ZERO),
                };
                self.open_input(
                    SecretKind::ConfirmPassword,
                    Purpose::ConfirmPassword(PasswordAction::RevealKey(source)),
                    false,
                );
            }
            Confirm::Generate => {
                self.generate();
                self.set_screen(previous);
            }
            Confirm::SidecarCorrupt => {}
            Confirm::JournalCorrupt => {
                self.set_screen(Screen::Main);
                self.key(KeyJob::ResolveSidecar {
                    kind: FileKind::Journal,
                    use_prev: false,
                });
            }
            Confirm::ChainPin => {
                let pending = self
                    .evm
                    .chain_form
                    .as_mut()
                    .and_then(|form| form.pending.take());
                if let Some((valid, genesis)) = pending {
                    self.commit_chain(&valid, genesis);
                } else {
                    self.set_screen(previous);
                }
            }
            Confirm::ChainRepin => {
                self.commit_repin();
                self.set_screen(Screen::Settings(SettingsSection::Chains));
            }
            Confirm::ChainDelete => {
                if let Some(chain_id) = self.evm.delete_chain.take() {
                    self.delete_chain(chain_id);
                }
                self.set_screen(Screen::Settings(SettingsSection::Chains));
            }
            Confirm::Discard => {
                if let Some(key) = self.evm.discard.take() {
                    self.discard_group(key);
                }
                self.set_screen(Screen::Main);
            }
            Confirm::BookDelete => {
                self.delete_book_entry();
                self.set_screen(Screen::AddressBook);
            }
            Confirm::Btc => self.btc_confirm_yes(),
            Confirm::RemoveKey => {
                self.set_screen(previous);
                if let Some(id) = self.pending_remove.take() {
                    self.open_input(
                        SecretKind::ConfirmPassword,
                        Purpose::ConfirmPassword(PasswordAction::RemoveKey(id)),
                        false,
                    );
                }
            }
        }
    }

    /// The challenge id currently expected (tests and diagnostics).
    #[must_use]
    pub fn challenge_id(&self) -> Option<ChallengeId> {
        self.challenge.map(|challenge| challenge.id)
    }
}
