//! The UI-thread application (spec/04 §1–§2, §4–§6): window handlers, flows, lock procedure,
//! settings and endpoint management. All windows share one `App` through `Rc<RefCell<…>>`; a
//! handler that cannot borrow it (re-entrant synchronous message) falls back to the default
//! processing, and the yw-win trampoline has already applied the secret-message block list.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::{Rc, Weak};
use std::sync::Arc;
use std::sync::mpsc::Sender;
use std::thread::JoinHandle;
use std::time::Duration;

use yw_core::secret::Zeroizing;
use yw_platform::Clock;
use yw_win::clipboard::{self, ClipError, SecretClip};
use yw_win::file::{FileError, read_limited_no_reparse};
use yw_win::input::is_down;
use yw_win::session;
use yw_win::ui::{Handler, Msg, Reply, UiError, Window, WindowKind, WindowSpec, create_window};

use crate::app_store::WinAppStore;
use crate::shell_msg::{
    SystemAction, WM_YW_ACTIVATE, WM_YW_EVENTS, WM_YW_LOCK_SHORTCUT, WM_YW_NAV_KEY, WM_YW_SHORTCUT,
    WM_YW_TAB_SHORTCUT, system_action,
};
use crate::system_clock::SystemClock;
use crate::ui::main_window::{ControlSet, Placed, layout, paint};
use crate::ui::secret::{
    CaptureDecision, PASTE_MAX_UTF16_UNITS, SECRET_TIMER_ID, SECRET_TIMER_MS, capture_decision,
    paint_form, window_size,
};
use crate::ui::secret_input::{HitLayout, ime_key, map_secret_char, map_secret_key};
use yw_engine::apikeys::ApiKeys;
use yw_engine::errors::ErrorCode;
use yw_engine::events::{KeyQueue, LockSignal};
use yw_engine::logging::{self, Field};
use yw_engine::settings::Settings;
use yw_engine::wallet::lock::LockReason;
use yw_engine::wallet::secret_session::SecretAction;
// `IDOK`/`IDCANCEL`: the ids `IsDialogMessageW` sends for Enter and Esc (2026-11-18, S3 B2: they
// were constants of this file).
use crate::ui::cmd_table::{self, IDCANCEL, IDOK};
use crate::ui::theme::{FontCache, FontRole, wide};
use yw_core::lang::Lang;
use yw_engine::approval::flow::OpenOutcome;
use yw_engine::cmd::{
    ClipNote, Cmd, CorePress, ExtPress, MainStep, PlatformNote, Press, RpcImportPress, TickPart,
};
use yw_engine::effect::TimerId;
use yw_engine::workers::rpc::RpcJob;
// `CredField`: debug builds only until S3 C3 (the shadow reads of plan §3.2a; 2026-11-18 B4–B5
// review); since C3 `Wallet::take_cred` uses it in every build.
use yw_engine::form::{CredField, EditField};
// Settings sections (S15) and the remembered scroll places: 2026-11-20 (S4 P10a) moved unchanged
// to `yw_engine::screen` (the scroll effects carry them). P10a re-exported them as
// `crate::app::SettingsSection` and `crate::app_scroll::ScrollPlace`; 2026-11-21 (S4b final
// review, AGENTS.md §4 "no new re-exports"): the callers name `yw_engine::screen` directly.
use yw_engine::screen::SettingsSection;
use yw_engine::screen::facts::PlatformFlags;
// 2026-11-24 (spec/15 §11.4 S5-8): the secret windows' form is the engine's; the shell owns the
// instance (`App::secret`) and paints it (`ui::secret::paint_form`).
use yw_engine::secret::form::{FormAction, SecretForm};
use yw_engine::secret::{
    DisplayHost, DisplayMade, SecretEffect, SecretFormOp, SecretKind, SecretStep,
};
use yw_engine::services::Services;

/// Main window class.
pub const MAIN_CLASS: &str = "YourWalletV3Main";
/// Secret input class (W01–W07, W10): `CaptureExclusion::Preferred`.
pub const SECRET_INPUT_CLASS: &str = "YourWalletV3SecretInput";
/// Secret display class (W08, W09): `CaptureExclusion::Required`.
pub const SECRET_VIEW_CLASS: &str = "YourWalletV3SecretView";
/// Single-instance mutex: boundary descriptor name of the private namespace (bound to the user's
/// SID and Medium integrity, spec/04 §1.1).
pub const INSTANCE_BOUNDARY: &str = "YourWallet.v3";
/// Alias prefix of the private namespace.
pub const INSTANCE_ALIAS: &str = "YourWalletV3";
/// Mutex name inside the private namespace (`<alias>\app.<session id>`).
pub const INSTANCE_MUTEX: &str = "app";
/// Secret clipboard lifetime (D11).
pub const SECRET_CLIPBOARD_TTL_MS: u64 = 30_000;
/// How long a clear that found the clipboard busy is retried (spec/04 §4.8): every main tick,
/// one `OpenClipboard` each, no sleep on the UI thread.
pub const SECRET_CLIPBOARD_RETRY_MS: u64 = 300_000;
/// Busy this long, the main window says the copy is still on the clipboard (retries go on).
pub const SECRET_CLIPBOARD_NOTICE_MS: u64 = 5_000;
/// At shutdown (no later tick): retries of a busy clear for about this long.
const SECRET_CLIPBOARD_EXIT_MS: u64 = 1_000;
pub mod text;
// 2026-11-18 (S4 A7): the secret-window test seams (`cfg(test)` only, `app::secret_seam`).
#[cfg(test)]
pub(crate) mod secret_seam;
// 2026-11-23 (spec/15 §11.4 S4d E1): the wallet half of this file (`Wallet`, its types and every
// `impl Wallet` block, which S4d E0b had split into the child module `app::wallet`) is
// `yw_engine::wallet`; this file is the Windows shell. (E0b had left a doubled
// `#[cfg(debug_assertions)]` on the `cred_fingerprint` import, from the removed `CredTaken`
// re-export; gone with it.) 2026-11-23 (spec/15 §11.4 S5-0, §18 28): the test-path shims
// `crate::app::{AppMode, Purpose, Wallet}` (`#[cfg(test)] pub(crate)`) and
// `yw_app::app::TestState` (`#[doc(hidden)] pub`), kept from S4d E1 for the bodies of the tests
// frozen at F-A, are gone with the S4 freeze; those bodies name `yw_engine::wallet::…`.
#[cfg(test)]
use yw_engine::wallet::Purpose;
use yw_engine::wallet::Screen;
#[cfg(debug_assertions)]
use yw_engine::wallet::cred_fingerprint;
use yw_engine::wallet::{AppMode, Wallet};

use text::PASTE_CLEARED;
pub use text::PASTE_EDGE_SPACE;
const MAIN_TIMER_ID: usize = 1;
const LOG_FLUSH_MS: u64 = 2_000;
const SESSION_RETRY_MS: u64 = 1_000;
const SESSION_RETRY_MAX: u32 = 30;
const VK_CONTROL: u16 = 0x11;
const VK_SHIFT: u16 = 0x10;
const VK_MENU: u16 = 0x12;
const MA_ACTIVATEANDEAT: isize = 2;
const EN_CHANGE: u16 = 0x0300;
// Settings field limits (UTF-16 units): 2026-11-18 (S3 C12) `CredField::cap` — 256 for the
// `QuickNode`, Alchemy and S08 fields (`TOKEN_MAX_UNITS` here before), 2 048 for `교체`
// (`URL_MAX_UNITS`); the shell reads them with the press (`ui::cmd_table::capture`).

/// The shell's record of the open secret window: its session's serial, the window and the form
/// that holds its buffers. 2026-11-20 (S4 P7a1): the purpose moved to the wallet's
/// [`SecretSession`] (`App::secret_session`); before, it was a field here.
struct SecretWin {
    serial: u64,
    window: Window,
    form: SecretForm,
    /// What the form's last paint drew where, for hit-testing the pointer (2026-11-24, spec/15
    /// §11.4 S5-7: before, the form kept it; empty until the first paint).
    layout: HitLayout,
}

/// A secret copy still to be cleared from the clipboard (spec/04 §4.8).
#[derive(Clone, Copy, Debug)]
struct PendingClip {
    clip: SecretClip,
    /// When it was copied: the clear is due [`SECRET_CLIPBOARD_TTL_MS`] later (or at lock).
    copied_ms: u64,
    retry: ClipRetry,
}

impl PendingClip {
    const fn new(clip: SecretClip, copied_ms: u64) -> Self {
        Self {
            clip,
            copied_ms,
            retry: ClipRetry {
                busy_since_ms: None,
                noticed: false,
            },
        }
    }

    /// A copy an earlier run may have left behind ([`App::clear_earlier_secret_clip`]). `noticed`
    /// starts set: until a clear finds one nothing says it is there, so a busy clipboard is
    /// retried without `T_CLIP_NOT_CLEARED`, and a clear that empties it says so.
    const fn earlier_run(now: u64) -> Self {
        Self {
            clip: SecretClip::ANY,
            copied_ms: now,
            retry: ClipRetry {
                busy_since_ms: None,
                noticed: true,
            },
        }
    }

    const fn due(&self, now: u64) -> bool {
        self.retry.busy_since_ms.is_some()
            || now.saturating_sub(self.copied_ms) >= SECRET_CLIPBOARD_TTL_MS
    }
}

/// The retry state of a pending clear.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ClipRetry {
    /// When a clear first found the clipboard busy: retried every tick from then on.
    busy_since_ms: Option<u64>,
    /// `T_CLIP_NOT_CLEARED` is showing (or, for an earlier run's copy, is never to show): a
    /// clear that empties the clipboard then shows `T_CLIP_CLEARED_LATE` (the wallet's notices,
    /// `Cmd::SecretClip`, 2026-11-24 S5-9).
    noticed: bool,
}

/// What one clear attempt of a pending secret copy means (spec/04 §4.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClipStep {
    /// Cleared, or replaced by another copy meanwhile (`true` = it was emptied).
    Done(bool),
    /// Busy: try again on the next tick (`true` = show `T_CLIP_NOT_CLEARED` now).
    Retry(bool),
    /// Busy for [`SECRET_CLIPBOARD_RETRY_MS`]: stop retrying.
    GiveUp,
}

/// The step after a clear attempt at `now` that returned `result`. A failure starts (or continues)
/// the busy period that bounds the retries and decides when the notice appears (once).
fn clip_step(retry: &mut ClipRetry, now: u64, result: Result<bool, ClipError>) -> ClipStep {
    let Err(_) = result else {
        return ClipStep::Done(matches!(result, Ok(true)));
    };
    let busy_for = now.saturating_sub(*retry.busy_since_ms.get_or_insert(now));
    if busy_for >= SECRET_CLIPBOARD_RETRY_MS {
        return ClipStep::GiveUp;
    }
    let notice = !retry.noticed && busy_for >= SECRET_CLIPBOARD_NOTICE_MS;
    retry.noticed |= notice;
    ClipStep::Retry(notice)
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
    // 2026-11-20 (S4 P1): `pub(crate)` for `app_store::WinAppStore` (was private).
    pub(crate) fn settings(&self) -> PathBuf {
        self.data.join("settings.json")
    }

    pub(crate) fn apikeys(&self) -> PathBuf {
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

thread_local! {
    /// The main window's edits whose `EN_CHANGE` arrived while the `App` was borrowed (2026-11-24,
    /// spec/15 §11.4 S5-6 review, spec/01 §7.7): their control ids only, never a text. The drain
    /// that ends the borrow reads each one again ([`App::edit_changed_in_borrow`]).
    static EDITS_CHANGED_IN_BORROW: RefCell<Vec<u16>> = const { RefCell::new(Vec::new()) };
}

/// A main window message the `App`'s borrow drops (re-entrancy, spec/01 §7.7): an edit's
/// `EN_CHANGE` is remembered by its control id (2026-11-24, S5-6 review: a change made while the
/// app is borrowed — an IME composition that a focus change inside a drain ends, say — would
/// otherwise never reach the wallet; before S5-6 the next press's or render's read-back `Cmd::Form`
/// healed the form state). Nothing else is kept, and nothing is posted.
fn note_dropped(target: Target, msg: &Msg) {
    if target == Target::Main
        && let Msg::Command { id, code } = msg
        && *code == EN_CHANGE
    {
        EDITS_CHANGED_IN_BORROW.with(|ids| {
            let mut ids = ids.borrow_mut();
            if !ids.contains(id) {
                ids.push(*id);
            }
        });
    }
}

impl Handler for Forward {
    fn on(&mut self, window: &Window, msg: &Msg) -> Reply {
        let Some(app) = self.app.upgrade() else {
            return Reply::Default;
        };
        let Ok(mut app) = app.try_borrow_mut() else {
            // A paint requested from inside another handler: owed, not dropped unpainted.
            if matches!(msg, Msg::Paint) {
                window.defer_paint();
                return Reply::Handled(0);
            }
            note_dropped(self.target, msg);
            return Reply::Default;
        };
        // 2026-11-20 (S4 P10b, critique A-14): every entry drained before it returned, and this
        // one drains before it returns: each arm calls an entry that drains itself (`on_main`,
        // `secret_entry`; source check S9 checks every arm), and the drain after them finds the
        // queue empty. (2026-11-20, P10b review: the secret arm called `on_secret`, which does not
        // drain, so only this drain applied a secret window's effects and no test pinned it.)
        app.assert_outbox_empty();
        let reply = match self.target {
            Target::Main => app.on_main(window, msg),
            Target::Secret(serial) => app.secret_entry(serial, window, msg),
        };
        app.drain();
        reply
    }
}

/// The application state (UI thread): the wallet ([`Wallet`]) and the Windows shell's own state
/// (2026-11-21, S4 W2, spec/15 §11.4 S4, plan §3.3; before, one struct). The shell's fields stay
/// flat here, not in a nested `Shell` (preflight §0 item 4: the render builders, the effect
/// executor and the frozen test helpers name them as `App` fields); `App` derefs to the wallet,
/// so `impl App` code reads and writes wallet fields as before. The effect executor
/// (`App::apply`, `app_effects.rs`) writes shell fields only, but for the exceptions its source
/// check lists (the clip notices, the two drawn-row maps the render builders refill; 2026-11-21,
/// S4 W2 review); the one value that moves from the
/// wallet into the shell, a display window's secret, is handed over by the composition in
/// `App::drain` (plan §3.4, D-4; source check `the_executor_writes_no_wallet_state`).
///
/// Drop order (2026-11-21, S4 W2 review): all of the wallet's fields now drop before the shell's
/// (before W2, one field order: `main` dropped before `events`, `rpc_tx`, `workers`, `browser` and
/// `llm`, and `secret` before `secret_session`). Harmless: `App` drops at the end of `main`,
/// after the message loop and the shutdown lock; the windows' forwards hold a `Weak`, which no
/// longer upgrades then, so a window that its drop destroys reaches no `App` field; and no `Drop`
/// of a field reads another field. A later `Drop` that depends on the order pins it.
pub struct App {
    /// The wallet (2026-11-21, S4 W2).
    pub(crate) wallet: Wallet,
    pub(crate) paths: Paths,
    pub(crate) main: Option<Window>,
    pub(crate) fonts: FontCache,
    pub(crate) self_ref: Weak<RefCell<App>>,
    pub(crate) scroll: i32,
    /// Wheel accumulation and glide of the main window (`app_scroll`).
    pub(crate) scroll_state: crate::app_scroll::MainScroll,
    /// Where each S10 tab, settings section, S08, S13 and S14 was left (DIP, this run only) and
    /// the screen under an overlay: the ways back open there (`app_scroll`, 2026-11-10).
    pub(crate) scroll_memory: crate::app_scroll::ScrollMemory,
    /// The main window's position and size (`window.json`, `window_state`).
    pub(crate) window_state: crate::window_state::WindowSaver,
    pub(crate) controls: ControlSet,
    /// Debug builds (S3 B5, plan §3.2a): reads where the form state and the window's edit
    /// differed, and credential units that differed from the handler's own read. Tests assert 0.
    #[cfg(debug_assertions)]
    pub(crate) form_mismatch: core::cell::Cell<u32>,
    /// Debug builds (2026-11-24, spec/15 §11.4 S5-4): drawn presses whose control id maps back
    /// to another control's press and credential edits that came with text, counted by the
    /// lowering of the screen model (`App::items`, `ui::lower::Lowered`). The census asserts 0.
    #[cfg(debug_assertions)]
    pub(crate) press_mismatch: core::cell::Cell<u32>,
    /// Tests (debug builds): every credential read as (the id of the press being handled,
    /// field) (2026-11-20, S4 P6: `cmd_table::id_of(last_press)`; before, `self.command`).
    #[cfg(all(test, debug_assertions))]
    pub(crate) cred_reads: Vec<(u16, CredField)>,
    /// Debug builds (2026-11-21, S4 W3, critique B-11): the shell's own read of the masked edits
    /// the press being handled captured (wiped when dropped), compared with the fields the
    /// handler took when the next drain starts (`App::cred_check`), then dropped.
    #[cfg(debug_assertions)]
    cred_shadow: Vec<(CredField, Option<yw_win::mem::WipeBuf<u16>>)>,
    pub(crate) placed: Placed,
    /// The approval window's shell state (2026-11-19, S4 B4b, spec/15 §11.4 S4): shown exactly
    /// while `evm.approval` is (was part of `EvmUi.window`).
    pub(crate) approval_win: Option<crate::app_approval::ApprovalWin>,
    // 2026-11-24 (spec/15 §11.4 S5-9): `ext` (`app_extension::ExtensionUi`, S23's way back) is
    // gone: S23's presses are the wallet's, and its way back the wallet's `ext_back`.
    /// The shell (2026-11-21, S4 W1, plan §3.3: the state cut out of the wallet's parts): how a
    /// link or a folder is opened (`explorer.exe`; unit-test builds record it). Only the effect
    /// executor uses it (`Effect::OpenUrl`, `Effect::OpenFolder`). Before W1,
    /// `ExplorerUi.launcher`.
    pub(crate) launcher: crate::explorer_launcher::Launcher,
    /// The shell (2026-11-21, S4 W1): the named-pipe server, why there is none and the read
    /// worker threads (`PipeHost`, spec/05 §8.1), attached with the dispatcher (`browser`) by
    /// [`App::attach_browser`]. Before W1, the fields `server`, `pipe_error` and `threads` of
    /// `BrowserUi`.
    pub(crate) pipe: Option<crate::browser::server::PipeHost>,
    /// The shell (2026-11-22, S4c W15, preflight §3.0 "workers"): the key and RPC worker threads
    /// `main.rs` started ([`App::attach_workers`]), joined by the shutdown's composition
    /// ([`App::shutdown`]); nothing of the wallet reads them. Before W15, a field of `Wallet`.
    pub(crate) workers: Vec<JoinHandle<()>>,
    /// The shell (2026-11-21, S4 W1): the control id of the S22 hold area the pointer pressed
    /// (`Placed::holds`), for the pointer's move test. The wallet holds only the hold's gate
    /// (`ResetUi::gate`) and hears of the hold through `Cmd::HoldBegin`/`Cmd::HoldEnd`; it ends a
    /// hold itself with `Effect::ReleaseHold`, which clears this (since F19, 2026-11-21, also a
    /// hold it ends by a phrase change or by replacing S22's state). Before W1,
    /// `ResetUi.holding`.
    pub(crate) reset_hold: Option<u16>,
    /// The shell's open secret window (window and form; S4 P7a1).
    secret: Option<SecretWin>,
    secret_clip: Option<PendingClip>,
    session_retries: u32,
    session_next_ms: u64,
    last_flush_ms: u64,
}

/// 2026-11-21 (S4 W2, plan §3.3, D-21): `impl App` code reaches the wallet's fields through
/// `App`; the render builders keep doing so until S5.
///
/// 2026-11-24 (spec/15 §11.4 S5-10, S5 plan owner item O-8): test builds only, like
/// [`core::ops::DerefMut`] since S4c W15. The render builders left `impl App` in S5-5, and the
/// shell's code names the wallet (`self.wallet.…`) for every read: a field, a method, the clock.
/// The tests and their fixtures (the frozen ones too) keep calling wallet fns on an `App`.
/// Before, every build had it.
#[cfg(test)]
impl core::ops::Deref for App {
    type Target = Wallet;

    fn deref(&self) -> &Wallet {
        &self.wallet
    }
}

/// 2026-11-21 (S4 W2, plan §3.3, D-21): until the handlers are `impl Wallet` and enter as
/// `Cmd`s (S4c W15; preflight §0 item 3: it stays for tests).
///
/// 2026-11-22 (S4c W15, owner's second batch item 1, preflight §0 item 3): test builds only. The
/// frozen tests (`frozen-tests.txt`, which never changes) and the test fixtures call wallet fns on
/// an `App`; production code reaches the wallet's state only through its entries — `Cmd`s
/// (`App::dispatch`, the drain's answers), the typed in-process entries (a worker's result, a
/// secret window's action, the `rpc.json` plan), the shell's compositions (lock, shutdown,
/// the display window's secret) and the other named wallet steps of shell code that S5 turns
/// into `Cmd`s or answers (2026-11-23, S4 end: S4d kept them; was "S4d/S5"; 2026-11-22 ZC
/// review: before, this last way was left out), each
/// `self.wallet.<fn>(` listed with its reason in the source check
/// `the_shell_writes_wallet_state_only_through_entries`. Before W15 every build had it.
#[cfg(test)]
impl core::ops::DerefMut for App {
    fn deref_mut(&mut self) -> &mut Wallet {
        &mut self.wallet
    }
}

impl core::fmt::Debug for App {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("App")
            .field("mode", &self.wallet.mode)
            .finish_non_exhaustive()
    }
}

// 2026-11-24 (spec/15 §11.4 S5-5): the settings note on what a password change does and does not
// do (review L1), `T_PASSWORD_OLD_COPIES`, and its rationale moved to the screens' catalogue
// `yw_engine::screen::build::core::text` with the security section's builder.

/// The information line after an accepted paste: the edge-space notice first, then the
/// clipboard note.
fn paste_notice(lang: Lang, edge_space: bool, cleared: Option<String>) -> Option<String> {
    match (edge_space, cleared) {
        (false, cleared) => cleared,
        (true, None) => Some(PASTE_EDGE_SPACE.get(lang).to_owned()),
        (true, Some(cleared)) => Some(format!("{} {cleared}", PASTE_EDGE_SPACE.get(lang))),
    }
}

/// A modifier read of the secret window's `WM_KEYDOWN` arm (`is_down`; 2026-11-18, S4 A7 review:
/// a `cfg(test)` seam lets the windowed secret characterization read them as up).
fn secret_modifier(vk: u16) -> bool {
    #[cfg(test)]
    if let Some(down) = secret_seam::scripted_modifier() {
        return down;
    }
    is_down(vk)
}

/// The action Enter presses while the focus is in edit `edit` of the main window (2026-11-12):
/// the send forms' `검토` (it only opens the approval window) and the one save, look-up or
/// connect button of a plain form. Not listed, so Enter stays ignored there: forms with two
/// candidate buttons (the RPC template credentials), typed confirmations, the fee caps, the
/// chain form, the `YubiKey` wizard and `HyperCore`.
fn enter_primary(edit: u16) -> Option<u16> {
    use crate::ui::{
        screens, screens_book as book, screens_btc as btc, screens_evm as evm,
        screens_explorer as explorer, screens_llm as llm, screens_mnemonics as mnemonics,
        screens_sol as sol, screens_walletconnect as wc, screens_zec as zec,
    };
    Some(match edit {
        evm::ids::SEND_TO_EDIT | evm::ids::SEND_AMOUNT_EDIT => evm::ids::SEND_REVIEW,
        sol::ids::SEND_TO_EDIT | sol::ids::SEND_AMOUNT_EDIT => sol::ids::SEND_REVIEW,
        btc::ids::SEND_TO_EDIT | btc::ids::SEND_AMOUNT_EDIT | btc::ids::FEE_MANUAL_EDIT => {
            btc::ids::SEND_REVIEW
        }
        zec::ids::SEND_TO_EDIT | zec::ids::SEND_AMOUNT_EDIT => zec::ids::SEND_REVIEW,
        screens::ids::RENAME_EDIT => screens::ids::RENAME_SAVE,
        sol::ids::RENAME_EDIT => sol::ids::RENAME_SAVE,
        btc::ids::RENAME_EDIT => btc::ids::RENAME_SAVE,
        mnemonics::ids::RENAME_EDIT => mnemonics::ids::RENAME_SAVE,
        // A YubiKey's name in Settings (2026-11-15; not the wizard).
        crate::ui::screens_yubikey::ids::CARD_NAME_EDIT => {
            crate::ui::screens_yubikey::ids::CARD_NAME_SAVE
        }
        screens::ids::REPLACE_EDIT => screens::ids::REPLACE_SAVE,
        screens::ids::AUTOLOCK_EDIT => screens::ids::AUTOLOCK_SAVE,
        screens::ids::DONE_QN_EDIT => screens::ids::DONE_CONNECT,
        evm::ids::TOKEN_ADDR_EDIT => evm::ids::TOKEN_LOOKUP,
        evm::ids::TOKEN_LABEL_EDIT => evm::ids::TOKEN_SAVE,
        book::ids::ADDR_EDIT | book::ids::LABEL_EDIT => book::ids::SAVE,
        book::ids::PROMPT_LABEL_EDIT => book::ids::PROMPT_SAVE,
        wc::ids::URI_EDIT => wc::ids::PAIR,
        wc::ids::FILE_EDIT => wc::ids::FILE_QR,
        wc::ids::PROJECT_EDIT => wc::ids::PROJECT_SAVE,
        explorer::ids::EDIT_TX | explorer::ids::EDIT_ADDRESS => explorer::ids::SAVE,
        llm::ids::ENDPOINT_EDIT | llm::ids::MODEL_EDIT | llm::ids::MAX_TOKENS_EDIT => {
            llm::ids::SAVE
        }
        llm::ids::KEY_EDIT => llm::ids::KEY_SAVE,
        _ => return None,
    })
}

/// The buttons the logic presses itself through `on_command`, besides Enter's
/// [`enter_primary`] (2026-11-18, S3 B4–B5 review: named lists, so table test (5) checks the
/// lists the code uses — a check box added to one fails it; plan D-k: a check box's state
/// travels with its click, and no internal press targets one).
pub(crate) mod logic_presses {
    use crate::ui::{
        screens, screens_book as book, screens_btc as btc, screens_evm as evm,
        screens_explorer as explorer, screens_mnemonics as mnemonics, screens_reset as reset,
        screens_sol as sol, screens_yubikey as yk, screens_zec as zec,
    };

    /// Ctrl+1/2/3/4 ([`super::App::tab_shortcut`]): the chain tab of shortcut `n` at `n - 1`.
    pub(crate) const TABS: [u16; 4] = [
        sol::ids::TAB_EVM,
        sol::ids::TAB_SOL,
        btc::ids::TAB_BTC,
        zec::ids::TAB_ZEC,
    ];
    /// F5 on S10 ([`super::App::shortcut`]): the visible chain tab's `새로고침`.
    pub(crate) const REFRESH: [u16; 4] = [
        evm::ids::REFRESH,
        sol::ids::REFRESH,
        btc::ids::REFRESH,
        zec::ids::REFRESH,
    ];
    /// Ctrl+, ([`super::App::shortcut`]): `설정`.
    pub(crate) const SETTINGS: [u16; 1] = [screens::ids::OPEN_SETTINGS];
    /// Esc on an overlay ([`super::App::escape_key`]): its `취소`.
    pub(crate) const ESC_CONFIRM: [u16; 1] = [screens::ids::CONFIRM_NO];
    /// Esc: an open inline edit's or a screen's own cancel, the first one shown.
    pub(crate) const ESC_CANCEL: [u16; 13] = [
        screens::ids::RENAME_CANCEL,
        sol::ids::RENAME_CANCEL,
        btc::ids::RENAME_CANCEL,
        mnemonics::ids::RENAME_CANCEL,
        yk::ids::CARD_NAME_CANCEL,
        screens::ids::REPLACE_CANCEL,
        book::ids::PROMPT_CANCEL,
        // S14's entry being edited.
        book::ids::CANCEL,
        // The block explorer row being changed (2026-11-11).
        explorer::ids::CANCEL,
        // A screen's or chooser's own `취소` (2026-11-12).
        screens::ids::INTRO_CANCEL,
        reset::ids::RESET_CANCEL,
        btc::ids::ACCOUNT_ADD_CANCEL,
        zec::ids::SOURCE_CANCEL,
    ];
    /// Esc: S20's `취소` while its new words were never shown.
    pub(crate) const ESC_NEW_WALLET_CANCEL: [u16; 1] = [yk::ids::NEW_WALLET_CANCEL];
    /// Esc: the back link of a screen that has one.
    pub(crate) const ESC_BACK: [u16; 3] = [
        screens::ids::BACK_DONE,
        screens::ids::BACK_MAIN,
        reset::ids::EXT_BACK,
    ];

    /// Every list above (table test (5)).
    #[cfg(test)]
    pub(crate) const ALL: [&[u16]; 7] = [
        &TABS,
        &REFRESH,
        &SETTINGS,
        &ESC_CONFIRM,
        &ESC_CANCEL,
        &ESC_NEW_WALLET_CANCEL,
        &ESC_BACK,
    ];
}

/// What Esc stands for on the main window (2026-11-20, S4 P4: `App::escape_target`, resolved by
/// the shell).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EscTarget {
    /// Nothing happens.
    Nothing,
    /// The open network or account drop-down closes (nothing else happens on that press).
    ClosePickers,
    /// This control is pressed exactly as a click.
    Press(u16),
}

/// Loads `settings.json` (spec/04 §6.2).
#[must_use]
pub fn load_settings(paths: &Paths) -> yw_engine::settings::SettingsLoad {
    match read_limited_no_reparse(
        &paths.settings(),
        u64::try_from(yw_engine::settings::SETTINGS_MAX_BYTES).unwrap_or(65_536),
    ) {
        Ok(bytes) => yw_engine::settings::load(Some(&bytes)),
        Err(FileError::NotFound) => yw_engine::settings::load(None),
        Err(_) => yw_engine::settings::SettingsLoad {
            settings: Settings::default(),
            banners: vec!["settings.json".to_owned()],
        },
    }
}

/// Loads `apikeys.dpapi` (spec/04 §6.3): `(keys, unreadable)`.
///
/// An LLM key stored by an older version has no `llm:host`. It is no longer bound here to the
/// endpoint in `settings.json` (a plain file anyone can edit, review M1): it stays unbound —
/// never attached to a request — until the first check after an unlock binds it to the host
/// in the vault-encrypted settings snapshot (`Wallet::reconcile_settings`).
///
/// 2026-11-20 (S4 P1): reads through `app_store::WinAppStore` and decodes with
/// `yw_engine::app_store::load_sealed_keys`; the file, the DPAPI call and the results are
/// unchanged.
#[must_use]
pub fn load_apikeys(paths: &Paths, settings: &Settings) -> (ApiKeys, bool) {
    yw_engine::app_store::load_sealed_keys(&WinAppStore::new(paths), settings)
}

/// The Windows platform services (2026-11-20, S4 P2, spec/15 §11.2): the `WinHTTP` LLM transport
/// (`explain_transport::llm_factory`), the `WalletConnect` parts
/// (`wc_platform::WinWcPlatform`; `app_walletconnect::WinWcPlatform` before 2026-11-22 S4d
/// E0c) and the relay user agent word `"windows"` (spec/13 §4;
/// the same bytes as before). Building it opens nothing: every part is made only when a worker
/// starts or the LLM connection test runs.
#[must_use]
pub fn windows_services() -> Services {
    Services {
        llm: crate::explain_transport::llm_factory(),
        walletconnect: Some(Box::new(crate::wc_platform::WinWcPlatform)),
        ua_platform: "windows",
    }
}

impl App {
    /// A new app (no windows yet) on the system clock.
    #[must_use]
    pub fn new(paths: Paths, background: bool, settings: Settings, apikeys: ApiKeys) -> Self {
        Self::with_clock(paths, background, settings, apikeys, Arc::new(SystemClock))
    }

    /// A new app (no windows yet) on `clock` (2026-11-19, S4 B1a: tests inject a manual or
    /// stepping clock; [`App::new`] passes `SystemClock`).
    /// 2026-11-23 (S4d E0b): the wallet's initializers are [`Wallet::new`]'s (its `too_many_lines`
    /// expectation went: this fn is short now).
    #[must_use]
    pub fn with_clock(
        paths: Paths,
        background: bool,
        settings: Settings,
        apikeys: ApiKeys,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let now = clock.now_ms();
        // 2026-11-23 (S4d E0b): the tests' secret seam logs the wallet code's probe notes.
        #[cfg(test)]
        secret_seam::install_probe();
        Self {
            wallet: Wallet::new(
                Box::new(WinAppStore::new(&paths)),
                windows_services(),
                background,
                settings,
                apikeys,
                clock,
                now,
            ),
            paths,
            main: None,
            fonts: FontCache::default(),
            self_ref: Weak::new(),
            scroll: 0,
            scroll_state: crate::app_scroll::MainScroll::default(),
            scroll_memory: crate::app_scroll::ScrollMemory::default(),
            window_state: crate::window_state::WindowSaver::default(),
            controls: ControlSet::default(),
            #[cfg(debug_assertions)]
            form_mismatch: core::cell::Cell::new(0),
            #[cfg(debug_assertions)]
            press_mismatch: core::cell::Cell::new(0),
            #[cfg(all(test, debug_assertions))]
            cred_reads: Vec::new(),
            #[cfg(debug_assertions)]
            cred_shadow: Vec::new(),
            placed: Placed::default(),
            approval_win: None,
            launcher: crate::explorer_launcher::Launcher::default(),
            pipe: None,
            workers: Vec::new(),
            reset_hold: None,
            secret: None,
            secret_clip: None,
            session_retries: 0,
            session_next_ms: 0,
            last_flush_ms: now,
        }
    }
}

impl App {
    /// One of `main.rs`'s start findings (spec/04 §1.4 steps 4–5): the refused `settings.json`
    /// values, whether `apikeys.dpapi` was readable (the template then fills the networks added
    /// since the addresses were made), a failed crash-report exclusion (review L9), the
    /// installed commit (`build_info::read_install_commit`). Handed to the wallet as
    /// `Cmd::Platform`, not drained: `main.rs` drains once after its start steps, as before.
    /// 2026-11-24 (spec/15 §11.4 S5-9): before, four shell fns called the wallet's
    /// `banner`, `fill_template_gaps`, `wer_unprotected_noted` and `install_commit_read` by name
    /// (`start_banner`, `start_fill_template_gaps`, `note_wer_unprotected`, `set_install_commit`;
    /// since 2026-11-22, S4c W15; before W15, `main.rs` called them on the `App`).
    pub fn platform_note(&mut self, note: PlatformNote) {
        self.wallet.on_cmd(Cmd::Platform(note));
    }
}

impl App {
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
        window.set_timer(MAIN_TIMER_ID, yw_engine::screen::MAIN_TIMER_MS)?;
        state.main = Some(window);
        // Made hidden: the wallet's mirror follows (2026-11-21, S4 W3, critique B-10).
        state.sync_main_hidden();
        Ok(())
    }

    /// The main window poster.
    #[must_use]
    pub fn main_poster(&self) -> Option<yw_win::ui::Poster> {
        self.main.as_ref().map(Window::poster)
    }

    /// Attaches the started browser bridge (spec/05 §8.1): the dispatcher (wallet state) and the
    /// shell's pipe end (2026-11-21, S4 W1: two parts; before, one `BrowserUi` held both).
    pub fn attach_browser(
        &mut self,
        browser: yw_engine::wallet::app_browser::BrowserUi,
        pipe: crate::browser::server::PipeHost,
    ) {
        // 2026-11-22 (S4c W15): the wallet's part (the failure's banner, the dispatcher) is
        // [`Wallet::browser_attached`], then the shell's pipe end; before, written here in that
        // order.
        self.wallet.browser_attached(browser, pipe.error);
        self.pipe = Some(pipe);
    }

    /// The key queue and lock signal shared with the key worker.
    #[must_use]
    pub fn worker_channels(&self) -> (Arc<KeyQueue>, Arc<LockSignal>) {
        (
            Arc::clone(&self.wallet.key_queue),
            Arc::clone(&self.wallet.lock_signal),
        )
    }

    /// The wallet's clock, shared with the workers and the browser dispatcher `main.rs` starts
    /// (`Wallet::clock`). 2026-11-24 (spec/15 §11.4 S5-10): `main.rs` read it through `App`'s
    /// `Deref`, which non-test builds no longer have.
    #[must_use]
    pub fn worker_clock(&self) -> Arc<dyn Clock> {
        self.wallet.clock()
    }

    /// The start's first key jobs (`main.rs` step 8): the language, then the vault's load, queued
    /// in the current epoch (`Wallet::key`). 2026-11-24 (spec/15 §11.4 S5-10): `main.rs` queued
    /// the two itself through `App`'s `Deref`; same jobs, same order.
    pub fn start_key_jobs(&self, lang: Lang) {
        self.wallet
            .key(yw_engine::events::KeyJob::SetLanguage(lang));
        self.wallet.key(yw_engine::events::KeyJob::Load);
    }

    /// Attaches the started workers. 2026-11-22 (S4c W15): the threads are the shell's
    /// ([`Self::workers`], joined at shutdown), the event queue and the RPC sender the wallet's
    /// ([`Wallet::workers_attached`]); before, all three were written here (the threads first).
    pub fn attach_workers(
        &mut self,
        events: Arc<yw_engine::events::EventQueue>,
        workers: Vec<JoinHandle<()>>,
        rpc_tx: Sender<RpcJob>,
    ) {
        self.workers = workers;
        self.wallet.workers_attached(events, rpc_tx);
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
                self.session_next_ms = self.wallet.clock.now_ms().saturating_add(SESSION_RETRY_MS);
                if self.session_retries >= SESSION_RETRY_MAX {
                    self.session_retries = 0;
                    // E-APP-004 (2026-11-24, spec/15 §11.4 S5-9: as `Cmd::Platform`; before,
                    // the wallet's `error_banner` called here).
                    self.wallet
                        .on_cmd(Cmd::Platform(PlatformNote::SessionUnregistered));
                }
            }
        }
    }

    /// Shows the main window (not in `--background`).
    pub fn show_main(&mut self) {
        self.show_main_window();
        // Its `WM_SIZE` came inside this borrow and was dropped: the wallet's mirror follows
        // here (2026-11-21, S4 W3, critique B-10).
        self.sync_main_hidden();
        if let Some(main) = self.main.as_ref()
            && !main.set_foreground()
        {
            main.flash();
        }
        // The first layout (2026-11-24, spec/15 §11.4 S5-9: as `Cmd::Main`; before, the
        // wallet's `refresh` called here).
        self.wallet.on_cmd(Cmd::Main(MainStep::Relayout));
    }

    /// `Effect::RaiseMain` (2026-11-20, S4 P4; was the start of [`Self::activate`]): the main
    /// window is shown and asked for the foreground (no flash when refused, as before).
    /// 2026-11-21 (S4 W3, critique B-10): `App::drain` then brings the wallet's main-window
    /// mirror up to date ([`Self::main_hidden_answer`]).
    pub(crate) fn raise_main(&mut self) {
        self.show_main_window();
        if let Some(main) = self.main.as_ref() {
            let _ = main.set_foreground();
        }
    }

    /// Shows the main window; the first show of a place saved maximized maximizes it
    /// (`window_state`).
    fn show_main_window(&mut self) {
        let Some(main) = self.main.as_ref() else {
            return;
        };
        if core::mem::take(&mut self.window_state.start_maximized) {
            main.show_maximized();
        } else {
            main.show();
        }
    }
}

impl App {
    /// `Effect::Render` on Windows: recomputes the layout, syncs the child controls and
    /// repaints the main window (nothing without a window). 2026-11-20 (S4 P4, critique B-12(b)):
    /// cutting the offset to the content height, and the second layout that cut needs, stay here
    /// in the shell's `Render` arm; the offset a screen entry restores comes from
    /// `Effect::ScreenEntered` just before. 2026-11-24 (spec/15 §11.4 S5-6): returns whether the
    /// controls were synced with the model built here (`false`: no window, or no fonts), so the
    /// `Render` arm answers `Cmd::Rendered` only for a model that was drawn.
    pub(crate) fn render_main(&mut self) -> bool {
        let Some(main) = self.main.as_ref() else {
            return false;
        };
        let dpi = main.dpi();
        let client = main.client_rect();
        let items = self.items();
        let Some(fonts) = self.fonts.for_dpi(dpi, self.wallet.settings.language) else {
            return false;
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
        self.scroll_memory.layout_dpi = dpi;
        let mut placed = layout(
            &items,
            self.wallet.settings.language,
            client.w,
            dpi,
            self.scroll,
            &measure,
            &label,
        );
        let max_scroll = placed.content_height.saturating_sub(client.h).max(0);
        if self.scroll > max_scroll {
            self.scroll = max_scroll;
            placed = layout(
                &items,
                self.wallet.settings.language,
                client.w,
                dpi,
                self.scroll,
                &measure,
                &label,
            );
        }
        self.controls.sync(main, &placed, fonts, client);
        main.set_vscroll_content(self.scroll, client.h, placed.content_height);
        self.placed = placed;
        main.invalidate();
        true
    }

    fn paint_main(&mut self, window: &Window) {
        let dpi = window.dpi();
        let client = window.client_rect();
        let Some(fonts) = self.fonts.for_dpi(dpi, self.wallet.settings.language) else {
            return;
        };
        if let Ok(mut dc) = window.begin_paint() {
            paint(&mut dc, client, &self.placed, fonts);
        }
    }

    // ----- main window -------------------------------------------------------------------

    /// A message of the main window, then the effects it emitted (2026-11-20, S4 P10b: every
    /// shell entry drains before it returns; the arms in [`Self::on_main_msg`] drain after each
    /// call into the logic that shell code follows, so that code runs after those effects and
    /// their answers, as when `emit` applied each effect at once).
    fn on_main(&mut self, window: &Window, msg: &Msg) -> Reply {
        let reply = self.on_main_msg(window, msg);
        self.drain();
        reply
    }

    fn on_main_msg(&mut self, window: &Window, msg: &Msg) -> Reply {
        // 2026-11-21 (S4 W3, critique B-10): a minimize or restore by the user (`WM_SIZE`, or
        // any change a dropped re-entrant message carried) reaches the wallet's mirror before
        // the message is handled.
        self.sync_main_hidden();
        if let Some(action) = system_action(msg) {
            return self.on_system(action);
        }
        match msg {
            Msg::Paint => {
                self.paint_main(window);
                Reply::Handled(0)
            }
            Msg::Size { .. } => {
                // 2026-11-24 (spec/15 §11.4 S5-9): the layout as `Cmd::Main`, then the same
                // drain (before, the wallet's `refresh` called here, then `drain`).
                self.dispatch(Cmd::Main(MainStep::Relayout));
                self.window_state.changed(self.wallet.clock.now_ms());
                Reply::Default
            }
            Msg::ExitSizeMove => {
                self.window_state.changed(self.wallet.clock.now_ms());
                Reply::Default
            }
            Msg::DpiChanged { dpi } => {
                // The offset follows the new scale (2026-11-10); the suggested rectangle applied
                // by the default processing resizes and lays the screen out again.
                self.scroll_dpi_changed(*dpi);
                self.window_state.changed(self.wallet.clock.now_ms());
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
                    // (2026-11-20, S4 P10b: `on_command` drains before it returns.)
                    self.on_command(*id);
                    // What the click made due starts now, not at the next tick (2026-11-12).
                    // (2026-11-22, S4c W15: as Cmd::Tick with TickPart::ReadsDue.)
                    let now = self.wallet.clock.now_ms();
                    self.wallet.on_cmd(Cmd::Tick {
                        now_ms: now,
                        part: TickPart::ReadsDue,
                    });
                } else if *code == EN_CHANGE {
                    self.on_edit_notify(*id);
                }
                Reply::Handled(0)
            }
            // The S22 hold area (painted, no child control). A click on the window itself, not
            // on a control, also closes an open drop-down (2026-11-12).
            Msg::MouseDown { x, y } => {
                self.hold_down(*x, *y, self.wallet.clock.now_ms());
                // 2026-11-24 (spec/15 §11.4 S5-9): as `Cmd::Main` (before, the wallet's
                // `close_pickers`, then `refresh` when it closed one, called here).
                self.wallet.on_cmd(Cmd::Main(MainStep::Clicked));
                Reply::Default
            }
            Msg::MouseMove { x, y } => {
                self.hold_move(*x, *y);
                Reply::Default
            }
            Msg::MouseUp { .. } => {
                self.wallet.on_cmd(Cmd::HoldEnd);
                Reply::Default
            }
            Msg::Timer(crate::app_scroll::SCROLL_TIMER_ID) => {
                self.scroll_tick(window);
                Reply::Handled(0)
            }
            // The validation a send-form edit waits for (one shot, `Effect::StartTimer`).
            Msg::Timer(yw_engine::wallet::app_evm::SEND_TIMER_ID) => {
                self.dispatch(Cmd::Timer(TimerId::SendCheck));
                Reply::Handled(0)
            }
            Msg::Wheel(delta) => {
                self.main_wheel(window, *delta);
                Reply::Handled(0)
            }
            Msg::VScroll { code } => {
                self.main_vscroll(window, *code);
                Reply::Handled(0)
            }
            Msg::App { msg, wparam } => {
                match *msg {
                    WM_YW_EVENTS => self.drain_events(),
                    WM_YW_ACTIVATE => self.wallet.on_cmd(Cmd::Activate),
                    WM_YW_LOCK_SHORTCUT => self.lock_shortcut(),
                    WM_YW_TAB_SHORTCUT if window.is_foreground() => self.tab_shortcut(*wparam),
                    WM_YW_SHORTCUT if window.is_foreground() => self.shortcut(*wparam),
                    WM_YW_NAV_KEY if window.is_foreground() => self.main_nav_key(window, *wparam),
                    _ => {}
                }
                // 2026-11-20 (S4 P10b): what that emitted is applied (and answered) before the
                // reads start, as when `emit` applied each effect at once.
                self.drain();
                // A worker's answer, a shortcut or the window shown again may have made a
                // read due. (2026-11-22, S4c W15: as `Cmd::Tick` with `TickPart::ReadsDue`.)
                let now = self.wallet.clock.now_ms();
                self.wallet.on_cmd(Cmd::Tick {
                    now_ms: now,
                    part: TickPart::ReadsDue,
                });
                Reply::Handled(0)
            }
            Msg::Resume => {
                logging::info("app", "power.resume", &[]);
                Reply::Default
            }
            _ => Reply::Default,
        }
    }

    /// Tests (2026-11-18, S4 A6): the main window's own message handler, so the approval
    /// lifecycle scenarios enter a lock, the shutdown, the main timer and the event drain exactly
    /// as the window does (`app_approval::flow_tests::lifecycle`).
    #[cfg(test)]
    pub(crate) fn test_on_main(&mut self, window: &Window, msg: &Msg) -> Reply {
        self.on_main(window, msg)
    }

    /// Tests (2026-11-18, S4 A6): the main timer's message, through [`Self::test_on_main`].
    #[cfg(test)]
    pub(crate) fn test_main_timer(&mut self, window: &Window) -> Reply {
        self.on_main(window, &Msg::Timer(MAIN_TIMER_ID))
    }

    /// Tests (2026-11-20, S4 B7): the arms of [`Self::on_main`] that read no window, for the
    /// headless approval scenarios (`app_approval::flow_tests::lifecycle::headless`), which make
    /// no window at all: the session, power and end-session messages (`system_action`), the main
    /// timer, the event drain (`WM_YW_EVENTS`) and the Ctrl+L shortcut (`WM_YW_LOCK_SHORTCUT`),
    /// each the same calls in the same order as in `on_main` (the source check
    /// `the_windowless_main_entry_mirrors_on_main` pins them). Any other message does nothing.
    /// 2026-11-20 (S4 P10b): it drains before it returns and after the event drain or the lock
    /// shortcut, as `on_main` does (`windowless_msg` mirrors `on_main_msg`).
    #[cfg(test)]
    pub(crate) fn test_on_main_windowless(&mut self, msg: &Msg) -> Reply {
        let reply = self.windowless_msg(msg);
        self.drain();
        reply
    }

    /// The arms of [`Self::on_main_msg`] that [`Self::test_on_main_windowless`] runs. 2026-11-21
    /// (S4 W3): the mirror's sync first, as in `on_main_msg` (with no window it never differs,
    /// so it sends nothing).
    #[cfg(test)]
    fn windowless_msg(&mut self, msg: &Msg) -> Reply {
        self.sync_main_hidden();
        if let Some(action) = system_action(msg) {
            return self.on_system(action);
        }
        match msg {
            Msg::Timer(MAIN_TIMER_ID) => {
                self.tick();
                Reply::Handled(0)
            }
            Msg::App { msg, .. } if matches!(*msg, WM_YW_EVENTS | WM_YW_LOCK_SHORTCUT) => {
                match *msg {
                    WM_YW_EVENTS => self.drain_events(),
                    WM_YW_LOCK_SHORTCUT => self.lock_shortcut(),
                    _ => {}
                }
                self.drain();
                // 2026-11-24 (S5-10): as `on_main_msg` spells it (no `Deref` in non-test builds).
                let now = self.wallet.clock.now_ms();
                self.wallet.on_cmd(Cmd::Tick {
                    now_ms: now,
                    part: TickPart::ReadsDue,
                });
                Reply::Handled(0)
            }
            _ => Reply::Default,
        }
    }

    /// Tests (2026-11-20, S4 B7): the main timer's message, through
    /// [`Self::test_on_main_windowless`].
    #[cfg(test)]
    pub(crate) fn test_main_timer_windowless(&mut self) -> Reply {
        self.test_on_main_windowless(&Msg::Timer(MAIN_TIMER_ID))
    }

    /// S22's hold area: the area under the pointer was pressed (spec/04 §2.20). 2026-11-21 (S4
    /// W1): the shell half of the old `App::hold_down` (`app_reset`): the hit test against the
    /// laid-out areas, the held area's id ([`Self::reset_hold`]) and the pointer capture; the
    /// gate starts in the logic (`Cmd::HoldBegin` with `now`, read by the caller when the message
    /// arrived, as before). The capture is taken before the logic's state changes (before W1,
    /// after); nothing reads either in between, and the repaint is applied when the entry
    /// drains, after both, as before.
    fn hold_down(&mut self, x: i32, y: i32, now: u64) {
        let hit = self
            .placed
            .holds
            .iter()
            .find(|(_, rect, enabled)| *enabled && rect.contains(x, y))
            .map(|(id, ..)| *id);
        if let Some(id) = hit {
            self.reset_hold = Some(id);
            if let Some(main) = self.main.as_ref() {
                main.set_capture();
            }
            self.wallet.on_cmd(Cmd::HoldBegin { now_ms: now });
        }
    }

    /// S22's hold area: the pointer moved; leaving the held area ends the hold (`Cmd::HoldEnd`).
    /// 2026-11-21 (S4 W1): the shell half of the old `App::hold_move` (`app_reset`). The held
    /// area counts only while the logic's gate runs: the logic also ends a hold by replacing
    /// S22's state (phrase change, reset, open, cancel), as the area's id `ResetUi.holding` was
    /// cleared then before W1. 2026-11-21 (S4 F19, spec/15 §18 item 19): the logic tells the
    /// shell then too (`Effect::ReleaseHold`, which clears the id when it is applied); until
    /// then the gate decides, as before (before F19 the shell was never told and kept the
    /// pointer capture).
    fn hold_move(&mut self, x: i32, y: i32) {
        let Some(id) = self.reset_hold.filter(|_| self.wallet.reset.gate.active()) else {
            return;
        };
        let inside = self
            .placed
            .holds
            .iter()
            .any(|(held, rect, _)| *held == id && rect.contains(x, y));
        if !inside {
            self.wallet.on_cmd(Cmd::HoldEnd);
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

    // ----- the main window's keys (the shell, 2026-11-20 S4 P4) ----------------------------
    //
    // Enter, Esc and the posted shortcuts are resolved here, by the shell, from what the main
    // window shows (its laid-out items, the focused control) and a read of the wallet state, into
    // the control they stand for; that control is then pressed exactly as a click (`on_command`),
    // so the logic gets that concrete `Press`. Each `*_target` fn only reads; the resolution and
    // its order are the ones the logic ran before P4 (`on_press` called `escape_key`/`enter_key`,
    // which read the focus and pressed through `press_shown`).

    /// Ctrl+L (posted by the loop observer). 2026-11-20 (S4 P4): unchanged — the lock is the
    /// wallet's `lock(Manual)`, called from this shell entry until S4c makes it a `Cmd`.
    fn lock_shortcut(&mut self) {
        if self.wallet.mode.holds_secrets() {
            self.lock(LockReason::Manual);
        }
    }

    /// Ctrl+1/2/3/4 (posted by the loop observer; the main window is in the foreground): the
    /// chain tab, exactly as clicking it, when S10 shows that tab enabled and no secret window
    /// is open ([`Self::tab_shortcut_target`]).
    pub(crate) fn tab_shortcut(&mut self, tab: usize) {
        if let Some(id) = self.tab_shortcut_target(tab) {
            self.on_command(id);
        }
    }

    /// The chain tab Ctrl+`tab` presses (S4 P4: the read half of [`Self::tab_shortcut`]).
    fn tab_shortcut_target(&self, tab: usize) -> Option<u16> {
        let &id = tab
            .checked_sub(1)
            .and_then(|index| logic_presses::TABS.get(index))?;
        if self.wallet.screen != Screen::Main || self.wallet.secret_open() {
            return None;
        }
        let shown = self.items().iter().any(|item| {
            matches!(item, crate::ui::main_window::Item::Row(ctls)
                if ctls.iter().any(|ctl| ctl.id == id && ctl.enabled))
        });
        shown.then_some(id)
    }

    /// The first of `ids` the current screen shows enabled (the keyboard shortcuts' targets).
    /// 2026-11-20 (S4 P4): only reads; before, `press_shown` also pressed it.
    fn shown_of(&self, ids: &[u16]) -> Option<u16> {
        let items = self.items();
        ids.iter().copied().find(|id| {
            items.iter().any(|item| {
                matches!(item, crate::ui::main_window::Item::Row(ctls)
                    | crate::ui::main_window::Item::LabeledRow(_, ctls)
                    | crate::ui::main_window::Item::Toolbar(_, ctls)
                    if ctls.iter().any(|ctl| ctl.id == *id && ctl.enabled))
            })
        })
    }

    /// F5 and Ctrl+, (posted by the loop observer; the main window is in the foreground; never
    /// while a secret window is open), 2026-11-10: F5 is the visible chain tab's `새로고침` on
    /// S10, Ctrl+, the `설정` button (the section last opened in this run), each only when that
    /// control is shown enabled ([`Self::shortcut_target`]), pressed exactly as a click.
    pub(crate) fn shortcut(&mut self, code: usize) {
        if let Some(id) = self.shortcut_target(code) {
            self.on_command(id);
        }
    }

    /// The control F5 or Ctrl+, presses (S4 P4: the read half of [`Self::shortcut`]).
    fn shortcut_target(&self, code: usize) -> Option<u16> {
        if self.wallet.secret_open() {
            return None;
        }
        match crate::shell_msg::Shortcut::from_code(code) {
            Some(crate::shell_msg::Shortcut::Refresh) if self.wallet.screen == Screen::Main => {
                self.shown_of(&logic_presses::REFRESH)
            }
            Some(crate::shell_msg::Shortcut::Settings) => self.shown_of(&logic_presses::SETTINGS),
            _ => None,
        }
    }

    /// Esc on the main window (`IDCANCEL` from the dialog manager), after its `Press::Back`
    /// (2026-11-20, S4 P4: called by `on_command`; before, by the logic's `on_press`): what
    /// [`Self::escape_target`] finds — a control pressed exactly as a click, or an open
    /// drop-down closed (and the screen laid out again). Enter is [`Self::enter_key`].
    pub(crate) fn escape_key(&mut self) {
        match self.escape_target() {
            EscTarget::Press(id) => self.on_command(id),
            // 2026-11-24 (spec/15 §11.4 S5-9): as two `Cmd::Main` steps (before, the wallet's
            // `close_pickers` and `refresh` called here).
            EscTarget::ClosePickers => {
                self.wallet.on_cmd(Cmd::Main(MainStep::ClosePickers));
                self.wallet.on_cmd(Cmd::Main(MainStep::Relayout));
            }
            EscTarget::Nothing => {}
        }
    }

    /// Whether a drop-down is open: what `Wallet::close_pickers` would return (2026-11-20, S4
    /// P4: the shell's Esc resolution reads it before closing). 2026-11-24 (spec/15 §11.4 S5-5):
    /// moved here from `ui/screens_links.rs`, whose builders moved to yw-engine (a shell read).
    #[must_use]
    pub(crate) const fn pickers_open(&self) -> bool {
        self.wallet.account_menu.is_some() || self.wallet.evm.network_picker
    }

    /// What Esc stands for now (2026-11-10): an overlay's `취소`; else an open inline edit's
    /// cancel (rename, an RPC row's `교체`, the address-book save prompt or entry being edited);
    /// else the back link of a screen that has one (S11–S16, S23, S-HC, the Solana and Bitcoin
    /// send and receive screens) — its inputs stay. Nothing on S17, the `YubiKey` flows, a
    /// waiting screen or S01, nor while a secret window is open. 2026-11-12: after the overlay
    /// an open network or account drop-down closes first (nothing else happens on that press),
    /// and a screen's own `취소` counts like an inline edit's: the intro screens (S02, S05, S18,
    /// S20), S22, the Bitcoin `계정 추가` chooser and the Zcash key-source confirmation.
    /// 2026-11-20 (S4 P4): only reads, in the order `escape_key` checked and pressed before (an
    /// overlay whose `취소` is not shown is still nothing; the drop-downs are what
    /// `close_pickers` closes, [`Self::pickers_open`]).
    fn escape_target(&self) -> EscTarget {
        if self.wallet.secret_open() {
            return EscTarget::Nothing;
        }
        if matches!(self.wallet.screen, Screen::Confirm(_)) {
            return self
                .shown_of(&logic_presses::ESC_CONFIRM)
                .map_or(EscTarget::Nothing, EscTarget::Press);
        }
        if self.pickers_open() {
            return EscTarget::ClosePickers;
        }
        let in_yubikey_flow = matches!(
            self.wallet.screen,
            Screen::Settings(SettingsSection::YubiKey)
        ) && self.wallet.card.manage.is_some();
        if in_yubikey_flow {
            return EscTarget::Nothing;
        }
        if let Some(id) = self.shown_of(&logic_presses::ESC_CANCEL) {
            return EscTarget::Press(id);
        }
        // S20's `취소` too, but never once its new words were shown: it discards them, like the
        // YubiKey wizard's (both stay a click then).
        if self.wallet.yk_words == yw_engine::wallet::app_yubikey::YkWords::None
            && let Some(id) = self.shown_of(&logic_presses::ESC_NEW_WALLET_CANCEL)
        {
            return EscTarget::Press(id);
        }
        if matches!(
            self.wallet.screen,
            Screen::Send
                | Screen::Receive
                | Screen::Sites
                | Screen::AddressBook
                | Screen::Settings(_)
                | Screen::TokenAdd
                | Screen::Extension
                | Screen::HyperCore
                | Screen::SolSend
                | Screen::SolReceive
                | Screen::BtcSend
                | Screen::BtcReceive
        ) && let Some(id) = self.shown_of(&logic_presses::ESC_BACK)
        {
            return EscTarget::Press(id);
        }
        EscTarget::Nothing
    }

    /// Enter on the main window (`IDOK` from the dialog manager; the buttons are owner-drawn, so
    /// there is no default button), 2026-11-12: [`Self::enter_on`] the control that has the
    /// focus. 2026-11-20 (S4 P4): called by `on_command` after its `Press::Enter` (before, by the
    /// logic's `on_press`).
    fn enter_key(&mut self) {
        let focus = self
            .controls
            .focused()
            .and_then(|index| self.placed.controls.get(index))
            .map(|(ctl, _)| ctl.clone());
        self.enter_on(focus.as_ref());
    }

    /// Enter with the focus on `focus` ([`Self::enter_target`]), pressed exactly as a click. The
    /// tests' and the census's way in (a control as the window placed it). 2026-11-20 (S4 P4
    /// review): it skips the shell's `IDOK` → `enter_key` → focus read; the windowed form test
    /// (`ui::tour_forms`) runs that path, and the source check
    /// `app::tests::converted_handlers_reach_the_main_window_only_through_effects` pins
    /// `on_command`'s calls of `enter_key`/`escape_key`.
    pub(crate) fn enter_on(&mut self, focus: Option<&crate::ui::main_window::Ctl>) {
        if let Some(id) = self.enter_target(focus) {
            self.on_command(id);
        }
    }

    /// What Enter with the focus on `focus` presses: an enabled button itself; in an edit of a
    /// form with one obvious action ([`enter_primary`]) that action, when it is shown enabled. A
    /// check box, a radio, any other edit or no focus: nothing, and nothing while a secret window
    /// is open (the secret and approval windows have their own key rules). 2026-11-20 (S4 P4):
    /// only reads. 2026-11-20 (S4 P4 review): `pub(crate)` so the windowed form test
    /// (`ui::tour_forms`) can say which press a real Enter (`IDOK` with the focus on an edit)
    /// must reach; no caller outside `App` in production.
    pub(crate) fn enter_target(&self, focus: Option<&crate::ui::main_window::Ctl>) -> Option<u16> {
        let ctl = focus?;
        if self.wallet.secret_open() || !ctl.enabled {
            return None;
        }
        if ctl.is_button() {
            Some(ctl.id)
        } else {
            self.shown_of(&[enter_primary(ctl.id)?])
        }
    }

    /// Records app input for the idle timer. 2026-11-22 (S4c W15): `Cmd::Input` to the wallet
    /// (no drain here: it emits nothing, and every caller is an entry that drains, the loop
    /// observer and `on_command`); before, this fn wrote the idle clock itself.
    pub fn note_input(&mut self) {
        self.wallet.on_cmd(Cmd::Input);
    }
}

impl App {
    /// The shell's half of the wallet's main-window mirror (2026-11-21, S4 W3, critique B-10,
    /// spec/04 §2.6): whether the main window exists and is hidden or minimized now, sent to the
    /// wallet as `Cmd::MainHidden` (through [`Self::dispatch`], an entry of its own) when it
    /// differs from what the wallet holds. Called where the live value can change: when the
    /// window is made (hidden, [`Self::create_main_window`]), shown ([`Self::show_main`]; an
    /// effect that changes it — `RaiseMain`, a secret or approval window's close that asks for
    /// the main window's foreground — is followed in `App::drain` by [`Self::main_hidden_answer`]
    /// instead, as the executor writes no wallet state) and dropped
    /// ([`Self::shutdown`]), and at every main window message before its handling
    /// ([`Self::on_main_msg`]: a minimize or restore by the user arrives as `WM_SIZE`, outside any
    /// borrow; one the shell's own show causes inside the borrow is dropped by the `Forward` and
    /// covered by the call after the show). Before W3 the wallet's readers (`evm_balance_tick`,
    /// `sol_balance_tick`, `hc_tick`, `received_tick`) read the window at each call
    /// (`App::main_hidden`); the mirror equals that read at every one of them (debug builds
    /// check it at the end of every drain, [`Self::assert_main_hidden_in_step`]).
    pub(crate) fn sync_main_hidden(&mut self) {
        if let Some(cmd) = self.main_hidden_answer() {
            self.dispatch(cmd);
        }
    }

    /// `Cmd::MainHidden` with the window's hidden state when it differs from the wallet's mirror
    /// (2026-11-21, S4 W3, critique B-10): [`Self::sync_main_hidden`]'s, and `App::drain`'s after
    /// each effect it applied (the executor writes no wallet state, D-4).
    pub(crate) fn main_hidden_answer(&self) -> Option<Cmd> {
        let hidden = self.main_hidden_now();
        (hidden != self.wallet.main_hidden()).then_some(Cmd::MainHidden(hidden))
    }

    /// The live value the mirror follows: the main window exists and is hidden or minimized
    /// (a destroyed window counts as hidden). No window (tests) is not hidden (2026-11-11).
    fn main_hidden_now(&self) -> bool {
        self.main
            .as_ref()
            .is_some_and(Window::is_hidden_or_minimized)
    }

    /// Debug builds: the wallet's main-window mirror equals the window (2026-11-21, S4 W3,
    /// critique B-10), checked at the end of every drain. It compares with [`Self::main_hidden_now`]
    /// itself, so it finds a missed sync, not a wrong live read (2026-11-21, W3 review: that read's
    /// body is pinned by `the_main_hidden_mirror_changes_where_the_window_does`, and checked on a
    /// real window by the windowed `ui::tour_forms`).
    ///
    /// # Panics
    ///
    /// Debug builds: when the mirror differs from the window.
    #[cfg(debug_assertions)]
    pub(crate) fn assert_main_hidden_in_step(&self) {
        debug_assert_eq!(
            self.wallet.main_hidden(),
            self.main_hidden_now(),
            "the main-window mirror follows the window"
        );
    }

    /// The main timer. 2026-11-20 (S4 P10b): each of its calls into the logic is an entry of its
    /// own — the effects it emitted are applied (and answered) before the next part runs, as
    /// when `emit` applied each effect at once; the event drain drains after each event.
    /// 2026-11-22 (S4c W15): each of the wallet's parts is a `Cmd::Tick` sent with
    /// [`Self::dispatch`] (its `on_cmd`, then the drain the part had after it); before, this fn
    /// called the part's wallet fn, then drained.
    fn tick(&mut self) {
        let now = self.wallet.clock.now_ms();
        self.drain_events();
        if self.session_retries > 0 && now >= self.session_next_ms {
            self.register_session();
        }
        self.tick_part(now, TickPart::Idle);
        self.tick_part(now, TickPart::Wait);
        self.tick_part(now, TickPart::ResetHold);
        if self.secret_clip.is_some_and(|pending| pending.due(now)) {
            // 2026-11-24 (spec/15 §11.4 S5-9): the clear's notice goes to the wallet as
            // `Cmd::SecretClip`, then the same drain (before, the clear wrote it itself).
            if let Some(note) = self.clear_secret_clip(now) {
                self.wallet.on_cmd(note);
            }
            self.drain();
        }
        self.window_state_tick(now);
        self.tick_part(now, TickPart::Copied);
        self.tick_part(now, TickPart::Evm);
        self.tick_part(now, TickPart::HyperCore);
        self.tick_part(now, TickPart::Sol);
        self.tick_part(now, TickPart::Btc);
        self.tick_part(now, TickPart::Zec);
        self.tick_part(now, TickPart::Received);
        if now.saturating_sub(self.last_flush_ms) >= LOG_FLUSH_MS {
            self.last_flush_ms = now;
            logging::flush();
        }
    }

    /// One wallet part of the main timer at `now` (2026-11-22, S4c W15): `Cmd::Tick` through
    /// [`Self::dispatch`], so it is drained before the timer's next part.
    fn tick_part(&mut self, now: u64, part: TickPart) {
        self.dispatch(Cmd::Tick { now_ms: now, part });
    }
}

impl App {
    /// The automatic clear of the pending secret copy (spec/04 §4.8), when due (copy + 30 s, or
    /// at lock). The first attempt retries `OpenClipboard` 5 times 20 ms apart; while another
    /// program holds the clipboard, every main tick tries once more (no sleep) for
    /// [`SECRET_CLIPBOARD_RETRY_MS`], and after [`SECRET_CLIPBOARD_NOTICE_MS`] of that the main
    /// window says so (`T_CLIP_NOT_CLEARED`) instead of leaving the user believing it is gone.
    ///
    /// 2026-11-24 (spec/15 §11.4 S5-9): returns the notice the clear's result calls for, as
    /// `Cmd::SecretClip` (`None`: nothing to say), which the main tick sends and the lock's
    /// `SecretEffect::ClearClip` answers with; the wallet writes the notices. Before, this fn
    /// wrote them itself where the clipboard answered (the wallet's `drop_clip_notice`, `notice`
    /// and `refresh`, the executor's one wallet write), in the same order.
    fn clear_secret_clip(&mut self, now: u64) -> Option<Cmd> {
        #[cfg(test)]
        secret_seam::log(secret_seam::Op::ClearClip {
            at_exit: false,
            pending: self.secret_clip.is_some(),
        });
        let mut pending = self.secret_clip.take()?;
        let main = self.main.as_ref()?;
        let retrying = pending.retry.busy_since_ms.is_some();
        let result = if retrying {
            clipboard::try_clear_secret(main, &pending.clip)
        } else {
            clipboard::clear_secret(main, &pending.clip)
        };
        let step = clip_step(&mut pending.retry, now, result);
        let outcome = match step {
            ClipStep::Done(true) => "yes",
            ClipStep::Done(false) => "no",
            ClipStep::Retry(_) => "busy",
            ClipStep::GiveUp => "gave_up",
        };
        // Every outcome once: the retries in between are not logged.
        if !(retrying && matches!(step, ClipStep::Retry(_))) {
            logging::info(
                "app",
                "clipboard.secret_clear",
                &[("cleared", Field::Word(outcome))],
            );
        }
        let note = match step {
            ClipStep::Done(cleared) => pending
                .retry
                .noticed
                .then_some(ClipNote::NoticeEnds { cleared }),
            ClipStep::Retry(notice) => {
                self.secret_clip = Some(pending);
                notice.then_some(ClipNote::NotCleared)
            }
            // The banner stays: the copy may still be there. (Not shown yet only when the PC
            // slept through the whole retry period.)
            ClipStep::GiveUp => (!pending.retry.noticed).then_some(ClipNote::NotCleared),
        };
        note.map(Cmd::SecretClip)
    }

    /// At start-up, right after the main window (spec/04 §1.4-6, §4.8): clears a secret copy an
    /// earlier run left on the clipboard, a run that ended before its own clear (a panic under
    /// `panic = "abort"`, a forced kill, Chrome closing the job it started us in, a clipboard
    /// still busy at exit). Only the marker format says it is ours ([`SecretClip::ANY`]): the
    /// single-instance mutex is held, so no running copy of the app placed it, and a later copy by
    /// another program would have emptied it. A busy clipboard is retried by the tick like any
    /// pending clear ([`PendingClip::earlier_run`]).
    pub fn clear_earlier_secret_clip(&mut self) {
        let Some(main) = self.main.as_ref() else {
            return;
        };
        let now = self.wallet.clock.now_ms();
        let mut pending = PendingClip::earlier_run(now);
        let result = clipboard::clear_secret(main, &pending.clip);
        let outcome = match clip_step(&mut pending.retry, now, result) {
            // The usual start: nothing left behind (not logged).
            ClipStep::Done(false) => return,
            // 2026-11-24 (spec/15 §11.4 S5-9): the wallet's notice, as `Cmd::SecretClip`
            // (before, the wallet's `notice` called here).
            ClipStep::Done(true) => {
                self.wallet
                    .on_cmd(Cmd::SecretClip(ClipNote::EarlierRunCleared));
                "yes"
            }
            ClipStep::Retry(_) | ClipStep::GiveUp => {
                self.secret_clip = Some(pending);
                "busy"
            }
        };
        logging::info(
            "app",
            "clipboard.earlier_clear",
            &[("cleared", Field::Word(outcome))],
        );
    }

    /// At shutdown there is no later tick: a busy clipboard is retried for about
    /// [`SECRET_CLIPBOARD_EXIT_MS`].
    fn clear_secret_clip_at_exit(&mut self) {
        #[cfg(test)]
        secret_seam::log(secret_seam::Op::ClearClip {
            at_exit: true,
            pending: self.secret_clip.is_some(),
        });
        let Some(pending) = self.secret_clip.take() else {
            return;
        };
        let Some(main) = self.main.as_ref() else {
            return;
        };
        let deadline = self
            .wallet
            .clock
            .now_ms()
            .saturating_add(SECRET_CLIPBOARD_EXIT_MS);
        let result = loop {
            let result = clipboard::clear_secret(main, &pending.clip);
            if result.is_ok() || self.wallet.clock.now_ms() >= deadline {
                break result;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        logging::info(
            "app",
            "clipboard.secret_clear",
            &[(
                "cleared",
                Field::Word(match result {
                    Ok(true) => "yes",
                    Ok(false) => "no",
                    Err(_) => "gave_up",
                }),
            )],
        );
    }
}

impl App {
    // ----- lock and shutdown -------------------------------------------------------------

    /// The lock procedure (spec/04 §5.3), the shell's composition of the wallet's two halves
    /// (2026-11-21, S4 W3a, critique B-1, preflight §3 W3a): [`Self::lock_steps`]; for `Suspend`
    /// the drain of what they emitted (the secret close, the clip clear, the approval close and,
    /// last, `Effect::AwaitKeyLock`: the 1.5 s wait for the key worker's lock, so it ends before
    /// the mode and screen change and before `KeyJob::Load`); then [`Self::lock_after_wait`].
    /// Called by the shell's entries (`on_system`, `lock_shortcut`; 2026-11-22, S4c W3b: no
    /// longer `shutdown`, whose wallet half locks with `lock_wallet(WalletLock::Shutdown)`);
    /// wallet code locks with [`Self::lock_wallet`], which cannot take `Suspend`. Before W3a this
    /// one fn held both halves and drained itself between them for `Suspend`, at the same point.
    pub fn lock(&mut self, reason: LockReason) {
        let vault_present = self.wallet.lock_steps(reason);
        if reason == LockReason::Suspend {
            self.drain();
        }
        self.wallet.lock_after_wait(vault_present);
    }
}

impl App {
    /// The shutdown sequence (spec/04 §1.5), the shell's composition of the wallet's three halves
    /// (2026-11-22, S4c W3b, preflight critic C11, owner's second batch item 1: split like the
    /// lock): [`Self::shutdown_begin`] (the mode and the queue's items), the shell's pipe server,
    /// [`Self::shutdown_steps`] (the dispatcher, `WalletConnect` and the wallet's own lock for
    /// `Shutdown`), the drain of what the lock emitted and the 5 s wait for the key worker,
    /// [`Self::shutdown_after_wait`] (the workers told to stop), then the shell's window place,
    /// the worker joins, the controls and the main window. Called by the shell's entries only:
    /// `on_system` (`WM_CLOSE`, `WM_ENDSESSION`, logoff) and `on_command` after the `종료` press
    /// (`CorePress::Exit`, whose wallet arm does nothing more). Same statements in the same
    /// order: before W3b this one fn held them all, called `lock(LockReason::Shutdown)` (for that
    /// reason the same two halves with no drain) and was also called by the wallet's `on_core`.
    pub fn shutdown(&mut self) {
        if !self.wallet.shutdown_begin() {
            return;
        }
        // The shell's pipe server first, then the dispatcher and its read workers (2026-11-21,
        // S4 W1: before, `BrowserUi::stop` did both, in this order). 2026-11-22 (S4c W3b): the
        // dispatcher's stop is the first step of `shutdown_steps`, right after this.
        if self.wallet.browser.is_some()
            && let Some(pipe) = self.pipe.as_mut()
        {
            pipe.stop();
        }
        let before = self.wallet.shutdown_steps();
        // 2026-11-20 (S4 P10b): the lock's secret close, clip clear (at exit) and approval close
        // are applied now, before the wait and while the main window still exists, as when
        // `emit` applied each effect at once.
        self.drain();
        #[cfg(test)]
        secret_seam::log(secret_seam::Op::Wait {
            what: "shutdown",
            ms: 5_000,
        });
        let _ = self
            .wallet
            .lock_signal
            .wait_beyond(before, Duration::from_secs(5));
        self.wallet.shutdown_after_wait();
        // The window's place for the next start (`window.json`, 2026-11-10).
        self.save_window_state();
        let deadline = self.wallet.clock.now_ms().saturating_add(2_000);
        for handle in std::mem::take(&mut self.workers) {
            while !handle.is_finished() && self.wallet.clock.now_ms() < deadline {
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
        // No main window is not hidden (2026-11-21, S4 W3, critique B-10: the wallet's mirror,
        // the last step; before, the wallet's readers saw `None` as not hidden too).
        self.sync_main_hidden();
    }
}

impl App {
    // ----- events ------------------------------------------------------------------------

    /// Drains the event queue (screenshot tour: the worker results of a scene). Gated like
    /// `ui::tour` (debug test builds only).
    #[cfg(test)]
    #[cfg(debug_assertions)]
    pub(crate) fn tour_drain_events(&mut self) {
        self.drain_events();
    }

    /// The worker events (`WM_YW_EVENTS`, and first thing in the main timer). 2026-11-20 (S4
    /// P10): each event is an entry of its own: the effects its handler emitted are applied (and
    /// answered) before the next event is handled, as when `emit` applied each effect at once.
    /// 2026-11-22 (S4c W15): each event goes to the wallet's typed in-process entry
    /// [`Wallet::worker_event`] (never a `Cmd`: a key worker's outcome can hold a secret, plan §7.1);
    /// before, this fn matched the event and called the wallet's handler itself (a key result
    /// through `App::on_key_result`, which drained once more before this fn's drain).
    fn drain_events(&mut self) {
        self.assert_outbox_empty();
        let Some(events) = self.wallet.events.clone() else {
            return;
        };
        for event in events.drain() {
            self.wallet.worker_event(event);
            self.drain();
        }
    }
}

impl App {
    /// A key worker's result, then the effects its handler emitted (2026-11-20, S4 P10b: an
    /// entry; the handler is `Wallet::key_result`). 2026-11-22 (S4c W15): tests only, the way
    /// in of a key result as the event drain hands it on (`App::drain_events`: the typed entry
    /// [`Wallet::worker_event`], then the drain); before, also the event drain's own call.
    #[cfg(test)]
    pub(crate) fn on_key_result(&mut self, result: yw_engine::events::KeyResult) {
        self.wallet
            .worker_event(yw_engine::events::UiEvent::Key(Box::new(result)));
        self.drain();
    }
}

/// The shell makes the window of secret session `serial` (hidden; yw-win applies and checks the
/// capture exclusion before the handler exists). Without a main window (headless tests, the
/// census) it refuses as yw-win refuses a `Required` window whose exclusion failed. 2026-11-24
/// (spec/15 §11.4 S5-1): the body of `App::create_secret` before, over the two shell fields it
/// reads (`main`, `self_ref`), so the display host ([`WinDisplayHost`]) makes its window while
/// the wallet is borrowed by `Wallet::open_display_window`; `App::create_secret` calls it.
fn create_secret_window(
    main: Option<&Window>,
    self_ref: &Weak<RefCell<App>>,
    serial: u64,
    kind: SecretKind,
    topmost: bool,
    lang: Lang,
) -> Result<Window, UiError> {
    // 2026-11-18 (S4 A7): the cfg(test) seam logs the request and can refuse it as yw-win
    // would; release builds have no such line. 2026-11-20 (S4 P8): the refusal is the
    // recording secret host's answer (`app::tests::s4_secret::host::refuse`; was the
    // thread-local `TEST_SECRET_REFUSE`).
    // 2026-11-20 (S4 P7a1 review): it runs before the main-window check (it ran after), so a
    // headless test sees every window the shell was asked for (the A-3 stale-open pin). With
    // a main window (the windowed runs) the order changes nothing.
    #[cfg(test)]
    if let Some(refused) = secret_seam::create(serial, kind, topmost) {
        return Err(refused);
    }
    let Some(owner) = main.map(Window::hwnd) else {
        return Err(UiError::CaptureExclusionFailed);
    };
    let (w, h) = window_size(kind);
    let class = if kind.is_display() {
        SECRET_VIEW_CLASS
    } else {
        SECRET_INPUT_CLASS
    };
    let spec = WindowSpec::new(class, WindowKind::Owned { owner })
        .title(&format!("Your Wallet — {}", kind.title(lang)))
        .size(w, h)
        .topmost(topmost);
    let handler = Box::new(Forward {
        app: self_ref.clone(),
        target: Target::Secret(serial),
    });
    create_window(&spec, handler)
}

/// The shell shows a made secret window with its form and keeps the window record in `slot`
/// (`App::secret`). 2026-11-24 (spec/15 §11.4 S5-1): the body of `App::show_secret` before, over
/// the two shell fields it uses (`main`, `secret`), for the display host ([`WinDisplayHost`]);
/// `App::show_secret` calls it.
fn show_secret_window(
    main: Option<&Window>,
    slot: &mut Option<SecretWin>,
    serial: u64,
    window: Window,
    form: SecretForm,
) {
    // 2026-11-20 (S4 P7a1 review): every open closes the previous window first, so a second
    // window record never silently replaces the first (its timer and the main window's
    // enable would be left unpaired).
    debug_assert!(slot.is_none(), "a secret window is already open");
    let _ = window.set_timer(SECRET_TIMER_ID, SECRET_TIMER_MS);
    if let Some(main) = main {
        main.enable(false);
    }
    window.show();
    if !window.set_foreground() {
        window.flash();
    }
    window.set_focus();
    window.invalidate();
    #[cfg(test)]
    secret_seam::log(secret_seam::Op::Show {
        kind: form.kind().id(),
    });
    *slot = Some(SecretWin {
        serial,
        window,
        form,
        layout: HitLayout::default(),
    });
}

impl App {
    /// The shell makes the window of secret session `serial` ([`create_secret_window`], the body
    /// of this fn before 2026-11-24, S5-1).
    fn create_secret(
        &self,
        serial: u64,
        kind: SecretKind,
        topmost: bool,
        lang: Lang,
    ) -> Result<Window, UiError> {
        create_secret_window(
            self.main.as_ref(),
            &self.self_ref,
            serial,
            kind,
            topmost,
            lang,
        )
    }

    /// The shell shows a made secret window ([`show_secret_window`], the body of this fn before
    /// 2026-11-24, S5-1).
    fn show_secret(&mut self, serial: u64, window: Window, form: SecretForm) {
        show_secret_window(self.main.as_ref(), &mut self.secret, serial, window, form);
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
}

impl App {
    /// The shell's half of an input window's open (today's `open_input` body before S4 P7a1):
    /// create, check the capture exclusion (spec/04 §4.5: `Preferred` — not excluded opens with
    /// T-CAPTURE-WARN and `보기` off), make the form and show it.
    fn open_input_window(
        &mut self,
        serial: u64,
        kind: SecretKind,
        step: Option<SecretStep>,
        topmost: bool,
        lang: Lang,
    ) -> OpenOutcome {
        // 2026-11-20 (S4 P8): the headless secret host of the tests makes the window without
        // Win32 (the same decision on a window it says was made); release builds have no such
        // line, and with no host (or the windowed run) this returns `None`.
        #[cfg(test)]
        if let Some(outcome) =
            tests::s4_secret::host::open_input(self, serial, kind, step, topmost, lang)
        {
            return outcome;
        }
        match self.create_secret(serial, kind, topmost, lang) {
            Ok(window) => {
                let excluded = window.capture_excluded();
                Self::log_capture(kind, excluded);
                match capture_decision(kind, Ok(excluded)) {
                    CaptureDecision::Show { warning } => {
                        let mut form = SecretForm::new(
                            kind,
                            lang,
                            self.wallet.clock.now_ms(),
                            !warning,
                            PlatformFlags::WINDOWS,
                        );
                        form.set_step(step);
                        self.show_secret(serial, window, form);
                        OpenOutcome::Shown {
                            capture_excluded: !warning,
                        }
                    }
                    CaptureDecision::Refuse(code) => {
                        drop(window);
                        OpenOutcome::Refused(code)
                    }
                }
            }
            Err(UiError::CaptureExclusionFailed) => {
                Self::log_capture(kind, false);
                OpenOutcome::Refused(ErrorCode::Sec001)
            }
            Err(UiError::Os(_)) => OpenOutcome::Failed(ErrorCode::App009),
        }
    }

    /// Applies one `Effect::Secret` (the shell; S4 P7a1). An open is answered with
    /// `Cmd::SecretOpened`. An open whose session is no longer the open one (it ended before the
    /// effect was applied: critique A-3), or whose session is already shown (a second open of the
    /// same session), makes nothing and is answered `Refused`, which `on_secret_opened` drops
    /// (that session has ended or is shown). 2026-11-20 (P7a1 review): the guard compared the
    /// serial only, so a second open of a shown session would have made a second window.
    pub(crate) fn apply_secret_effect(&mut self, effect: SecretEffect) -> Option<Cmd> {
        // 2026-11-20 (S4 P8): the recording secret host notes every effect's `Debug` (its scan
        // for secrets); release builds have no such line.
        #[cfg(test)]
        tests::s4_secret::host::saw(&effect);
        match effect {
            SecretEffect::OpenInput {
                serial,
                kind,
                step,
                topmost,
                lang,
            } => {
                let unshown = self.wallet.secret_unshown(serial);
                let outcome = if unshown {
                    self.open_input_window(serial, kind, step, topmost, lang)
                } else {
                    OpenOutcome::Refused(ErrorCode::Sec001)
                };
                Some(Cmd::SecretOpened { serial, outcome })
            }
            SecretEffect::Close { serial } => {
                self.close_secret_window(serial);
                None
            }
            // S4 P7b: a display window. 2026-11-21 (S4 W2, plan §3.4, D-4): never applied here
            // — `App::drain` hands it to the composition (`open_display_composed`), which moves
            // the secret into the shell. Were one applied here, the shell makes nothing and
            // refuses it, as a stale open (fail closed: the answer ends the session, which drops
            // its secret).
            SecretEffect::OpenDisplay { serial, .. } => Some(Cmd::SecretOpened {
                serial,
                outcome: OpenOutcome::Refused(ErrorCode::Sec001),
            }),
            SecretEffect::Form { serial, op } => {
                self.apply_form_op(serial, op);
                None
            }
            // S4 P7b: the lock's clear of a pending secret copy (spec/04 §5.3 step 4), with the
            // clock read where the lock read it before.
            // 2026-11-24 (spec/15 §11.4 S5-9): answered with the clear's notice
            // (`Cmd::SecretClip`) when it has one; before, the clear wrote the notice itself here,
            // the executor's one wallet write.
            SecretEffect::ClearClip { at_exit } => {
                if at_exit {
                    self.clear_secret_clip_at_exit();
                    None
                } else {
                    self.clear_secret_clip(self.wallet.clock.now_ms())
                }
            }
        }
    }

    /// The shell's half of `SecretEffect::Form` (2026-11-20, S4 P7b; the body of `with_form`
    /// before): the form of the window of session `serial`, when it is the open one, changes and
    /// the window repaints.
    fn apply_form_op(&mut self, serial: u64, op: SecretFormOp) {
        // 2026-11-20 (S4 P8): the headless secret host's window takes its form operations;
        // release builds have no such line.
        #[cfg(test)]
        let Some(op) = tests::s4_secret::host::form_op(serial, op) else {
            return;
        };
        let Some(secret) = self
            .secret
            .as_mut()
            .filter(|secret| secret.serial == serial)
        else {
            return;
        };
        let form = &mut secret.form;
        match op {
            SecretFormOp::Busy(busy) => form.set_busy(busy),
            SecretFormOp::Error(message) => form.set_error(message),
            SecretFormOp::Details(lines) => form.set_details(lines),
            SecretFormOp::Card(card) => form.set_card(card),
            SecretFormOp::Info(message) => form.set_info(message),
            SecretFormOp::FailPassword { now_ms } => form.fail_password(now_ms),
            SecretFormOp::ResetBackup { positions, message } => {
                form.reset_backup(positions, message);
            }
        }
        secret.window.invalidate();
    }
}

impl App {
    /// A display window's open, the composition's (2026-11-21, S4 W2, plan §3.4, D-4: called
    /// only by `App::drain`; before, the executor's `apply_secret_effect` arm, which moved the
    /// secret in `open_display_window`). Answered with `Cmd::SecretOpened`, as before.
    ///
    /// 2026-11-24 (spec/15 §11.4 S5-1, §18 30 (나), 주인 결정(2026-11-23); spec/04 §4.5 item 4):
    /// the open goes to the wallet's `Wallet::open_display_window` with the shell's display host
    /// ([`WinDisplayHost`], over the shell fields `main`, `self_ref` and `secret` only, borrowed
    /// beside the wallet). The wallet checks the open, unshown session (critique A-3: a stale or
    /// second open makes nothing and is refused), has the host make the window and read its
    /// capture exclusion back, and moves the secret into a verified window only, by value; no call
    /// hands it back to the shell. Before S5-1 the guard was here (`self.secret_unshown`) and the
    /// composition `display_window_handoff` made the window (`make_display_window`), asked the
    /// engine for the secret (`hand_display_secret(serial, DisplayCheck::Verified)`, which
    /// returned it) and showed it (`show_display`) — the same steps in the same order.
    pub(crate) fn open_display_composed(
        &mut self,
        serial: u64,
        kind: SecretKind,
        step: Option<SecretStep>,
        timeout_note: Option<&'static str>,
        lang: Lang,
    ) -> Cmd {
        // 2026-11-20 (S4 P8): the recording secret host notes every effect's `Debug` (its scan
        // for secrets); release builds have no such line.
        #[cfg(test)]
        tests::s4_secret::host::saw(&SecretEffect::OpenDisplay {
            serial,
            kind,
            step,
            timeout_note,
            lang,
        });
        // 2026-11-20 (S4 P8): the headless secret host of the tests makes the window without
        // Win32 (2026-11-24, S5-1: a `DisplayHost` of its own over the window record, was a hook
        // of `display_window_handoff` taking the whole `App`); release builds have no such line,
        // and with no host (or the windowed run) this is `None`.
        #[cfg(test)]
        if let Some(mut host) = tests::s4_secret::host::display_host(self.secret.as_ref()) {
            let outcome =
                self.wallet
                    .open_display_window(&mut host, serial, kind, step, timeout_note, lang);
            return Self::display_answer(serial, outcome);
        }
        let mut host = WinDisplayHost {
            main: self.main.as_ref(),
            self_ref: &self.self_ref,
            secret: &mut self.secret,
        };
        let outcome =
            self.wallet
                .open_display_window(&mut host, serial, kind, step, timeout_note, lang);
        Self::display_answer(serial, outcome)
    }

    /// The display open's answer (2026-11-24, S5-1: the tail of `open_display_composed`, which
    /// has two hosts since S5-1).
    fn display_answer(serial: u64, outcome: OpenOutcome) -> Cmd {
        let answer = Cmd::SecretOpened { serial, outcome };
        // 2026-11-20 (S4 P8 review): the recording secret host notes the answer's `Debug` too
        // (its scan for secrets); release builds have no such line.
        #[cfg(test)]
        tests::s4_secret::host::saw_cmd(&answer);
        answer
    }
}

/// The Windows shell's display host (2026-11-24, spec/15 §11.4 S5-1, §18 30 (나), 주인
/// 결정(2026-11-23); spec/04 §4.5 items 1–4): the shell fields a display window's open uses —
/// the main window (the owner, disabled while the window is open), the `App`'s weak self (the
/// window's `Forward`) and the secret window record — borrowed beside the wallet, never a
/// wallet field. [`DisplayHost::make`] is `App::make_display_window` of before (the window made
/// hidden, its exclusion read back, the decision), [`DisplayHost::fill_and_show`] is
/// `App::show_display` of before (the form filled with the secret the wallet moved in, then
/// shown). The only non-test `DisplayHost` (source check
/// `the_display_secret_moves_only_in_the_composition`).
struct WinDisplayHost<'a> {
    main: Option<&'a Window>,
    self_ref: &'a Weak<RefCell<App>>,
    secret: &'a mut Option<SecretWin>,
}

impl DisplayHost for WinDisplayHost<'_> {
    type Window = Window;

    /// The shell makes a display window for session `serial` and reads its capture exclusion
    /// back (2026-11-21, S4 W2: the window part of `open_display_window` before, which also moved
    /// the secret; 2026-11-24, S5-1: `App::make_display_window` before). Holds no secret.
    fn make(&mut self, serial: u64, kind: SecretKind, lang: Lang) -> DisplayMade<Window> {
        let created = create_secret_window(self.main, self.self_ref, serial, kind, false, lang);
        let excluded = created
            .as_ref()
            .map(Window::capture_excluded)
            .map_err(|_| ());
        App::log_capture(kind, excluded.unwrap_or(false));
        let decision = capture_decision(kind, excluded);
        match (decision, created) {
            // Verified: `Show` without the warning is a window whose exclusion was read back as
            // 0x11 (`capture_decision`, `Required`).
            (CaptureDecision::Show { warning: false }, Ok(window)) => DisplayMade::Verified(window),
            // A display kind never shows with the warning (`capture_decision`); were it to, the
            // window is dropped like a refused one (fail closed), before the secret is.
            (CaptureDecision::Show { warning: true }, Ok(window)) => {
                drop(window);
                DisplayMade::Unverified {
                    outcome: OpenOutcome::Refused(ErrorCode::Sec001),
                    window: None,
                }
            }
            (CaptureDecision::Refuse(code), window) => DisplayMade::Unverified {
                outcome: OpenOutcome::Refused(code),
                window: window.ok(),
            },
            (CaptureDecision::Show { .. }, Err(_)) => DisplayMade::Unverified {
                outcome: OpenOutcome::Failed(ErrorCode::App009),
                window: None,
            },
        }
    }

    /// Windows offers every platform feature but `seen_all` (2026-11-24, S5-8).
    fn flags(&self) -> PlatformFlags {
        PlatformFlags::WINDOWS
    }

    /// The shell shows a verified display window with the form the wallet built around the
    /// secret (2026-11-21, S4 W2: the verified arm of `open_display_window` before; 2026-11-24,
    /// S5-1: `App::show_display` before, which read the wallet's clock itself; 2026-11-24, S5-8,
    /// S5 plan critic C1: before, this got the secret, the step, the note, the language and the
    /// clock and built the form itself — now the shell never names the secret).
    fn fill_and_show(&mut self, serial: u64, window: Window, form: SecretForm) {
        show_secret_window(self.main, self.secret, serial, window, form);
    }
}

impl App {
    /// The shell's half of `SecretEffect::Close` (the body of `close_secret` before S4 P7a1):
    /// the window of session `serial`, when it is the open one, is wiped, its timer stopped, the
    /// main window enabled again, the window destroyed and the main window brought forward.
    fn close_secret_window(&mut self, serial: u64) {
        // 2026-11-20 (S4 P8): the headless secret host's window closes (wiped) there; release
        // builds have no such line.
        #[cfg(test)]
        if tests::s4_secret::host::close(serial) {
            return;
        }
        if let Some(mut secret) = self.secret.take_if(|secret| secret.serial == serial) {
            secret.form.wipe();
            #[cfg(test)]
            secret_seam::log(secret_seam::Op::Close {
                kind: secret.form.kind().id(),
                left: secret_seam::held_units(&secret.form),
            });
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

    /// A message of the secret window `serial`, then the effects it emitted (2026-11-20, S4 P10b
    /// review): the secret window's entry, as [`Self::on_main`] is the main window's, so a close
    /// box's or `취소`'s `Secret(Close)` (the form wiped, the window destroyed), a form operation
    /// and a repaint are applied before the message returns. Before, `Forward`'s drain after the
    /// call applied them and nothing pinned it. The tests' headless entry
    /// [`Self::test_secret_entry_headless`] is this fn with the secret host's arms.
    fn secret_entry(&mut self, serial: u64, window: &Window, msg: &Msg) -> Reply {
        let reply = self.on_secret(serial, window, msg);
        self.drain();
        reply
    }

    /// Tests (2026-11-20, S4 P10b review): [`Self::secret_entry`] without a window — the recording
    /// secret host's copy of `on_secret`'s window-free arms (`tests::s4_secret::host::deliver`),
    /// then the drain (source check `the_secret_entry_drains_and_its_headless_twin_mirrors_it`).
    #[cfg(all(test, debug_assertions))]
    pub(crate) fn test_secret_entry_headless(&mut self, serial: u64, msg: &Msg) -> Reply {
        let reply = tests::s4_secret::host::deliver(self, serial, msg);
        self.drain();
        reply
    }

    fn on_secret(&mut self, serial: u64, window: &Window, msg: &Msg) -> Reply {
        let now = self.wallet.clock.now_ms();
        let dpi = window.dpi();
        let Self { secret, fonts, .. } = self;
        let Some(secret) = secret.as_mut().filter(|secret| secret.serial == serial) else {
            return Reply::Default;
        };
        let SecretWin {
            form, layout: hits, ..
        } = secret;
        // 2026-11-24 (spec/15 §11.4 S5-7): keys and pointer messages reach the form as neutral
        // events, built by `ui::secret_input` (the key map, and the hit layout the last paint
        // returned); before, the form took the virtual-key code, the modifiers and the pixels.
        let action = match msg {
            Msg::Paint => {
                if let Some(fonts) = fonts.for_dpi(dpi, form.lang())
                    && let Ok(mut dc) = window.begin_paint()
                {
                    *hits = paint_form(
                        &form.paint_view(),
                        &mut dc,
                        window.client_rect(),
                        fonts,
                        dpi,
                        now,
                    );
                }
                return Reply::Handled(0);
            }
            Msg::Char(unit) => form.on_key(map_secret_char(*unit), now),
            Msg::KeyDown { vk, .. } => {
                let action = form.on_key(
                    map_secret_key(
                        *vk,
                        secret_modifier(VK_CONTROL),
                        secret_modifier(VK_SHIFT),
                        secret_modifier(VK_MENU),
                    ),
                    now,
                );
                if matches!(action, FormAction::None) {
                    return Reply::Default;
                }
                action
            }
            Msg::MouseDown { x, y } => {
                let (action, capture) = form.on_pointer(hits.down(*x, *y), now);
                if capture {
                    window.set_capture();
                }
                action
            }
            Msg::MouseUp { x, y } => {
                window.release_capture();
                form.on_pointer(hits.up(*x, *y), now).0
            }
            Msg::MouseMove { x, y } => form.on_pointer(hits.moved(*x, *y), now).0,
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
            Msg::ImeAttempt => form.on_key(ime_key(), now),
            Msg::Size { .. } | Msg::DpiChanged { .. } => {
                window.invalidate();
                return Reply::Default;
            }
            Msg::Close => {
                if form.busy() {
                    // The submitted job runs on and cannot be called back (like Esc): the
                    // window closes with its result instead of pretending to cancel.
                    return Reply::Handled(0);
                }
                let action = if form.kind().is_display() && !form.kind().needs_hold() {
                    form.wipe();
                    FormAction::Close
                } else {
                    form.wipe();
                    FormAction::Cancel
                };
                self.apply_form_action(serial, action);
                return Reply::Handled(0);
            }
            _ => return Reply::Default,
        };
        self.apply_form_action(serial, action);
        Reply::Handled(0)
    }

    /// What the form of the window of secret session `serial` asked for. 2026-11-20 (S4 P7a1):
    /// the purpose is the wallet session's, and an action of a window that is not the open
    /// session's is dropped (`on_secret` already finds the window by `serial`; the two agree).
    /// 2026-11-22 (S4c W12, preflight critic C12): the shell's half. It keeps the window's own
    /// arms (a repaint, the clipboard's paste and copy) and hands what is the wallet's (submit,
    /// cancel, time-out, close, the acknowledgement hold) to [`Self::on_secret_action`] as a
    /// [`SecretAction`], in-process (never a `Cmd`: a submission holds secrets). Before, this fn
    /// held both, so it reached wallet state through `DerefMut`. Same arms, same order, same
    /// drop of another serial's action (a dropped submission is wiped). 2026-11-22 (S4c W12
    /// review): one wallet write is still reached from here, the copy's clip-notice drop and its
    /// repaint (`copy_secret` → `drop_clip_notice`, `refresh`), a named exception until W15; the
    /// serial check that opens this fn is pinned by the source check
    /// `the_secret_form_action_splits_at_on_secret_action`. 2026-11-22 (ZC review): resolved at W15:
    /// `drop_clip_notice` and `refresh` are wallet code, called on `self.wallet` and listed in
    /// `SHELL_WALLET_CALLS`; non-test builds have no `DerefMut`.
    fn apply_form_action(&mut self, serial: u64, action: FormAction) {
        if !self.wallet.secret_session_is(serial) {
            return;
        }
        match action {
            FormAction::None => {}
            FormAction::Redraw => {
                if let Some(secret) = self.secret.as_ref() {
                    secret.window.invalidate();
                }
            }
            FormAction::Paste => self.paste(),
            FormAction::Copy => self.copy_secret(),
            FormAction::Submit(submission) => {
                self.wallet
                    .on_secret_action(serial, SecretAction::Submit(submission));
            }
            FormAction::Cancel => self.wallet.on_secret_action(serial, SecretAction::Cancel),
            FormAction::TimedOut => self.wallet.on_secret_action(serial, SecretAction::TimedOut),
            FormAction::Close => self.wallet.on_secret_action(serial, SecretAction::Close),
            FormAction::HoldComplete => {
                self.wallet
                    .on_secret_action(serial, SecretAction::HoldComplete);
            }
        }
    }
}

impl App {
    fn paste(&mut self) {
        let lang = self.wallet.settings.language;
        let Some(secret) = self.secret.as_mut() else {
            return;
        };
        let read = clipboard::read_text(&secret.window, PASTE_MAX_UTF16_UNITS);
        let message = match read {
            Ok((units, seq)) => {
                // Accepted or rejected (E-INP-018), the text was secret-shaped and was read: the
                // clipboard is cleared either way (spec/04 §4.7-4).
                let applied = secret.form.apply_paste(units.as_slice());
                drop(units);
                let cleared = match clipboard::clear_if_unchanged(&secret.window, seq) {
                    Ok(true) => Some(PASTE_CLEARED.get(lang).to_owned()),
                    Ok(false) => None,
                    Err(_) => Some(ErrorCode::Sec002.text_in(lang)),
                };
                match applied {
                    Ok(edge_space) => paste_notice(lang, edge_space, cleared),
                    Err(code) => {
                        secret.form.set_error(Some(code.text_in(lang)));
                        cleared
                    }
                }
            }
            Err(ClipError::TooLong) => {
                secret.form.set_error(Some(ErrorCode::Inp018.text_in(lang)));
                None
            }
            Err(ClipError::Busy | ClipError::Os(_)) => Some(ErrorCode::Sec002.text_in(lang)),
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
        let lang = self.wallet.settings.language;
        let allowed = self.wallet.settings.allow_secret_copy;
        let Some(secret) = self.secret.as_mut() else {
            return;
        };
        if !allowed {
            secret
                .form
                .set_info(Some(text::COPY_OFF.get(lang).to_owned()));
            secret.window.invalidate();
            return;
        }
        let Some(units) = secret.form.copy_units() else {
            return;
        };
        let mut replaced = None;
        match clipboard::set_secret_text(&secret.window, &units) {
            Ok(clip) => {
                replaced = self
                    .secret_clip
                    .replace(PendingClip::new(clip, self.wallet.clock.now_ms()));
                secret
                    .form
                    .set_info(Some(text::COPIED_SECRET.get(lang).to_owned()));
                logging::info(
                    "secret",
                    "clipboard.secret_copy",
                    &[("window", Field::Word(secret.form.kind().id()))],
                );
            }
            Err(_) => secret.form.set_error(Some(ErrorCode::Sec002.text_in(lang))),
        }
        secret.window.invalidate();
        // This copy replaced the earlier one whose clear was still being retried: its notice
        // ends (2026-11-24, spec/15 §11.4 S5-9: as `Cmd::SecretClip`; before, the wallet's
        // `drop_clip_notice` and `refresh` called here).
        if replaced.is_some_and(|old| old.retry.noticed) {
            self.wallet
                .on_cmd(Cmd::SecretClip(ClipNote::NoticeEnds { cleared: false }));
        }
    }
}

impl App {
    // ----- commands ----------------------------------------------------------------------

    /// A command of the main window. Any command but Enter, Esc and a drop-down's own selector
    /// closes an open network or account drop-down (2026-11-12); the layout follows after the
    /// command ran, because its handler may read the live controls (check boxes, edits).
    /// 2026-11-18 (S3 B2): the id goes through `ui::cmd_table` as a `Cmd::Press`; before, this
    /// called `dispatch_command(id)` directly. S3 B5: first the plain edits' text
    /// (`Cmd::Form`), then the press with the credential edits it reads, captured now
    /// (`cmd_table::capture`). S3 D1: and, for the `WalletConnect` clipboard presses, what the
    /// clipboard holds. S3 D3: an id that is no press (`cmd_table::press_of` → `None`: no
    /// control of the main window sends it) only becomes the last command id and clears the copy
    /// mark — what every id did first before S3 — and nothing else runs (before D3 it went
    /// through `Press::Legacy` to `dispatch_legacy`, whose received-history check found no
    /// `새로고침` in it). The last press (`App::last_press`) stays the one before.
    /// 2026-11-20 (S4 P6): such an id only clears the copy mark; the last command id `command`
    /// it also set is gone (the last command is `last_press`).
    /// 2026-11-20 (S4 P4): Enter and Esc are resolved here, by the shell, after their own press
    /// (which still sets the last command and clears the copy mark, as every press does first):
    /// `enter_key`/`escape_key` find the control they stand for and press it through this fn,
    /// so the logic gets that control's concrete `Press`. Before P4 the logic's `on_press` called
    /// them inside the `Enter`/`Back` press (the inner press nested in it); the steps and their
    /// order are the same.
    ///
    /// 2026-11-24 (spec/15 §11.4 S5-6): the plain edits are no longer read first (`Cmd::Form`
    /// is gone); the press carries only the credential edits it reads, as before.
    ///
    /// 2026-11-20 (S4 P10b): the shell's entry for a press — `Cmd::Form` and `Cmd::Press` go in
    /// through `dispatch` (each drains), and it drains before it returns, so the Enter/Esc
    /// resolution and the caller's reads run after the press's effects and their answers, as
    /// when `emit` applied each effect at once.
    ///
    /// 2026-11-22 (S4c W15, critique B-5): the two families whose press handlers are the shell's
    /// — S23 `Chrome 확장 설치` (`Press::Ext`, its way back is shell state and its `경로 복사`
    /// reads the installed folder) and the `rpc.json` import (`Press::RpcImport`, the file) — run
    /// here right after their press reached the wallet (which only took it as the last press and
    /// cleared the copy mark, as for every press), like `종료`'s composition; before, the
    /// wallet's family router called them inside that press. Neither reads the press's
    /// credential input, and the press emits nothing before them.
    /// 2026-11-22 (S4c W15 review): only the press's own drain runs between the two (it applies
    /// nothing, the press emitted nothing; its debug `cred_check` finds no credential taken, as
    /// none of these ids captures one); and the handler's effects and their answers
    /// (`OpenFolder` → `Cmd::FolderMissing`, `CopyText` → `Cmd::CopyDone`, the scroll memory,
    /// `Reveal`) are drained right after it, before the closed drop-down's repaint, in the order
    /// they had inside the press. In the W15 commit they waited for the final drain, behind that
    /// repaint (cosmetic only).
    fn on_command(&mut self, id: u16) {
        self.note_input();
        // 2026-11-24 (spec/15 §11.4 S5-9): an open drop-down closes as `Cmd::Main` (before, the
        // wallet's `close_pickers` called here; it answered whether one was open, which the
        // shell's `pickers_open` reads, as Esc's resolution does).
        let closed = !matches!(id, IDOK | IDCANCEL)
            && !crate::ui::cmd_table::is_picker_button(id)
            && self.pickers_open();
        if closed {
            self.wallet.on_cmd(Cmd::Main(MainStep::ClosePickers));
        }
        // 2026-11-24 (spec/15 §11.4 S5-6): no `Cmd::Form` first — the engine keeps what the plain
        // edits show (`EN_CHANGE` → `Cmd::Edit`, its own field writes, `Cmd::Rendered`).
        let input = cmd_table::capture(
            id,
            &self.controls,
            self.main.as_ref(),
            &self.wallet.wc.file_text,
        );
        if let Some(press) = cmd_table::press_of(id, &self.controls) {
            // Debug builds (2026-11-21, S4 W3, critique B-11): the shell's own read of the masked
            // edits the press captures, compared with the edits the handler took when the drain
            // starts, before any effect of the press is applied (`cred_check`).
            #[cfg(debug_assertions)]
            {
                self.cred_shadow = self.cred_shadow_of(id);
            }
            self.dispatch(Cmd::Press { press, input });
            match press {
                Press::Enter => self.enter_key(),
                Press::Back => self.escape_key(),
                // `종료` (2026-11-22, S4c W3b, preflight critic C11): the shell's composition
                // after the press reached the wallet; before, the wallet's `on_core` called
                // `shutdown` inside this `dispatch` as the press's last step (only the press
                // input's wipe and the dispatch's drain followed it, and both now precede it).
                Press::Core(CorePress::Exit) => self.shutdown(),
                // The shell's press handlers (2026-11-22, S4c W15, critique B-5; see above), each
                // drained at once (W15 review). 2026-11-24 (spec/15 §11.4 S5-9): only the presses
                // that need the shell's files — S23's `경로 복사` (the extension folder) and the
                // `rpc.json` read and delete; the rest of both families are the wallet's, handled
                // in the press.
                Press::Ext(ExtPress::CopyPath) => {
                    self.on_ext_copy_path();
                    self.drain();
                }
                Press::RpcImport(
                    press @ (RpcImportPress::Import | RpcImportPress::DeleteConfirm),
                ) => {
                    self.on_rpc_import(press);
                    self.drain();
                }
                _ => {}
            }
        } else {
            // 2026-11-22 (S4c W15): the wallet's own fn; before, `self.copied = None` here.
            // 2026-11-24 (spec/15 §11.4 S5-9): as `Cmd::Main` (before, `forget_copy_mark`).
            self.wallet.on_cmd(Cmd::Main(MainStep::NotAPress));
        }
        if closed {
            // 2026-11-24 (S5-9): as `Cmd::Main` (before, the wallet's `refresh`).
            self.wallet.on_cmd(Cmd::Main(MainStep::Relayout));
        }
        self.drain();
    }
}

impl App {
    /// Test adapter of a converted family (S3 C, plan §3.2): a module test or the tour presses
    /// control `id` directly, as before S3 — no copy mark or last command, no receive gate and
    /// no received-history read — with the form state and the press input taken as
    /// `on_command` takes them. `pick` keeps the family's presses; `false` when `id` is not one
    /// of them, else what `run` returns.
    #[cfg(test)]
    pub(crate) fn press_family<P>(
        &mut self,
        id: u16,
        pick: impl FnOnce(Press) -> Option<P>,
        run: impl FnOnce(&mut Self, P) -> bool,
    ) -> bool {
        let Some(press) = cmd_table::press_of(id, &self.controls).and_then(pick) else {
            return false;
        };
        // (2026-11-24, S5-6: no `Cmd::Form` first, as `on_command`.)
        let input = cmd_table::capture(id, &self.controls, self.main.as_ref(), &self.wc.file_text);
        // 2026-11-21 (S4 W3, critique B-11): the shell's own read of the captured edits, as
        // `on_command` keeps it, for the comparison when the drain below starts.
        #[cfg(debug_assertions)]
        {
            self.cred_shadow = self.cred_shadow_of(id);
        }
        let outer = test_steps::swap_press_input(&mut self.wallet, input);
        let claimed = run(self, press);
        let used = test_steps::swap_press_input(&mut self.wallet, outer);
        #[cfg(debug_assertions)]
        {
            self.cred_misses = self.cred_misses.saturating_add(used.misses());
        }
        drop(used);
        // 2026-11-20 (S4 P10b): an entry, as `on_command` (whose `Cmd::Press` drains here).
        self.drain();
        claimed
    }

    /// An edit of the main window changed (`EN_CHANGE`, 2026-11-18 S3: moved out of `on_main`
    /// so a test drives an edit as the window does). S3 B5: a plain edit becomes `Cmd::Edit`
    /// with its text; a masked credential edit is never read (no handler claims it).
    pub(crate) fn on_edit_notify(&mut self, id: u16) {
        // 2026-11-18 (S3 B4–B5 review): `let … else`, not two nested `if let`s, so the shape is
        // the same with and without the debug-only statement (release clippy: `collapsible_if`).
        // 2026-11-18 (S3 C11): a masked credential edit (no field) reaches no handler, as before
        // (the last legacy edit handlers, `YubiKey`'s, never claimed one).
        let Some(field) = cmd_table::field_of(id) else {
            return;
        };
        if let Some(text) = self.controls.text(id, field.cap()) {
            // (2026-11-20, S4 P10b: through `dispatch`, which drains.)
            self.dispatch(Cmd::Edit {
                field,
                text: Zeroizing::new(text),
            });
        } else {
            // No such edit (only a headless test can notify one): no `Cmd::Edit`, counted.
            // 2026-11-18 (S3 C1–C3 review): a converted family (C2: WalletConnect `WcUri`,
            // `WcFile`, `WcProject`; C3: explorer `ExplorerTx`, `ExplorerAddress`, AI
            // `LlmEndpoint`, `LlmModel`, `LlmMaxTokens`) now keeps its draft here; before C2/C3
            // `edit_chain` reached its `on_*_edit_change`, which cleared the draft to ""
            // (`unwrap_or_default`). Production cannot get here (`EN_CHANGE` comes from a live
            // edit), and the census asserts `form_mismatch == 0` at every observation, so a test
            // that notifies without typing fails there. (S3 C4: the address book's
            // `BookAddress`, `BookLabel`, `BookPromptLabel` likewise; S3 C5: S22's
            // `ResetPhrase`; S3 C6: the removal warning's `MnRemoveTyped`; S3 C7: `HcTo`,
            // `HcAmount`, `HcApi`, `ZecSendTo`, `ZecSendAmount`; S3 C8: `SolSendTo`,
            // `SolSendAmount`; S3 C9: the Bitcoin send, bump and Esplora fields; S3 C10: the
            // EVM send, token, S17 and fee-cap fields; S3 C11: the `YubiKey` wizard and card
            // action fields.)
            #[cfg(debug_assertions)]
            self.note_form_mismatch(field);
        }
    }

    /// The next edit whose `EN_CHANGE` the `App`'s borrow dropped ([`note_dropped`]; 2026-11-24,
    /// spec/15 §11.4 S5-6 review, spec/04 §1.3) and that is still drawn and shows another text
    /// than the wallet's form state: the user's change as `on_edit_notify` reads it, `Cmd::Edit`,
    /// which [`App::drain`] hands to the wallet once its queue is empty (then drains again and asks
    /// for the next). An edit the engine wrote itself (`SetField`/`ClearField`, whose `EN_CHANGE`
    /// always arrives inside the borrow) shows what the form state holds and gives nothing, so a
    /// drain that lost no user change runs as before; an edit that is gone, or a masked credential
    /// edit (never read), gives nothing either. Each noted edit is asked once.
    pub(crate) fn edit_changed_in_borrow(&self) -> Option<Cmd> {
        let next = || {
            EDITS_CHANGED_IN_BORROW.with(|ids| {
                let mut ids = ids.borrow_mut();
                (!ids.is_empty()).then(|| ids.remove(0))
            })
        };
        while let Some(id) = next() {
            let Some(field) = cmd_table::field_of(id) else {
                continue;
            };
            let Some(text) = self.controls.text(id, field.cap()).map(Zeroizing::new) else {
                continue;
            };
            if self.wallet.form.text(field) != Some(text.as_str()) {
                return Some(Cmd::Edit { field, text });
            }
        }
        None
    }
}

impl App {
    /// Debug builds: one form-state difference (tests: its field name in the shell-call log,
    /// never a text).
    #[cfg(debug_assertions)]
    pub(crate) fn note_form_mismatch(&self, field: EditField) {
        self.form_mismatch
            .set(self.form_mismatch.get().saturating_add(1));
        #[cfg(test)]
        self.controls.record(format!("form.mismatch {field:?}"));
        #[cfg(not(test))]
        let _ = field;
    }

    /// Debug builds, the shell (2026-11-21, S4 W3, critique B-11): the wallet's form state equals
    /// what the plain edits show (`controls.text(id, field.cap())`, the read `Cmd::Form` made
    /// until S5-6) for every field; each difference is counted ([`Self::note_form_mismatch`]).
    /// 2026-11-24 (spec/15 §11.4 S5-6): the shadow of the engine's own form state (no read-back
    /// feeds it any more), so it is what checks the engine's keep rule. Run at the end of
    /// every drain, when no field write is queued. Before W3 this comparison ran in the wallet's
    /// `form_text`/`form_text_wiping`, for the field read, at each read. Not once the shutdown
    /// has begun (2026-11-21, S4 W3 review): `shutdown` clears the controls and drops the main
    /// window while the form state keeps its last values, so every field shown at exit would
    /// count (its own last drain and the `Exit` press's); before W3 nothing read a field then.
    #[cfg(debug_assertions)]
    pub(crate) fn check_form_in_step(&self) {
        if self.wallet.mode == AppMode::ShuttingDown {
            return;
        }
        for field in EditField::ALL {
            let shown = self
                .controls
                .text(cmd_table::edit_id_of(field), field.cap())
                .map(Zeroizing::new);
            if shown.as_deref().map(String::as_str) != self.wallet.form.text(field) {
                self.note_form_mismatch(field);
            }
        }
    }

    /// Debug builds, the shell (2026-11-21, S4 W3, critique B-11): the masked edits `id`'s press
    /// captures, read again as `cmd_table::capture` reads them (wiped when dropped), kept in
    /// `cred_shadow` for [`Self::cred_check`] until the next drain starts.
    #[cfg(debug_assertions)]
    fn cred_shadow_of(&self, id: u16) -> Vec<(CredField, Option<yw_win::mem::WipeBuf<u16>>)> {
        cmd_table::creds_for(id)
            .iter()
            .map(|&field| {
                (
                    field,
                    self.controls
                        .text_wiping(cmd_table::cred_id_of(field), field.cap()),
                )
            })
            .collect()
    }

    /// Debug builds, the shell (2026-11-21, S4 W3, critique B-11): when a drain starts, each
    /// credential field the logic took since the last one ([`Wallet::take_cred_log`]: a press's
    /// handler) is compared with the edit as read now, against `cred_shadow`, the read made with
    /// the press (none outside a press: empty units, as the press input gives then); the shadow
    /// is dropped (wiped) either way. A difference is counted in `form_mismatch` and logged by
    /// field name (tests), never by text, and tests record the read as (the press's id, field) in
    /// `cred_reads`. No effect has been applied since the take, so the edit reads as it did when
    /// the handler took the units. Before W3, `take_cred` read the edit itself at the take and
    /// compared it with the units the press captured (`cred_compare`); a field the press did not
    /// capture is still a miss (`PressInput::take`).
    ///
    /// 2026-11-21 (S4 W3 review): the units the handler took are compared too, by the length and
    /// SHA-256 its take noted ([`cred_fingerprint`]) against the shadow's, so a take that hands
    /// over another field's units counts as before W3; from W3 until this review only the shadow
    /// and the edit now, two shell reads, were compared. Not compared once the shutdown has begun
    /// (its controls are gone; [`Self::check_form_in_step`]).
    #[cfg(debug_assertions)]
    pub(crate) fn cred_check(&mut self) {
        let shadow = core::mem::take(&mut self.cred_shadow);
        for (field, took_len, took_digest) in self.wallet.take_cred_log() {
            #[cfg(test)]
            self.cred_reads.push((
                cmd_table::id_of(test_steps::last_press(&self.wallet)),
                field,
            ));
            if self.wallet.mode == AppMode::ShuttingDown {
                continue;
            }
            let read = self
                .controls
                .text_wiping(cmd_table::cred_id_of(field), field.cap());
            let captured = shadow
                .iter()
                .find(|(known, _)| *known == field)
                .and_then(|(_, units)| units.as_ref())
                .map(yw_win::mem::WipeBuf::as_slice)
                .unwrap_or_default();
            let (captured_len, captured_digest) = cred_fingerprint(captured);
            if captured
                != read
                    .as_ref()
                    .map(yw_win::mem::WipeBuf::as_slice)
                    .unwrap_or_default()
                || took_len != captured_len
                || *took_digest != *captured_digest
            {
                self.form_mismatch
                    .set(self.form_mismatch.get().saturating_add(1));
                #[cfg(test)]
                self.controls.record(format!("cred.mismatch {field:?}"));
            }
        }
    }
}

impl App {
    /// Debug builds: credential reads of a field no press captured (tests assert 0).
    #[cfg(all(test, debug_assertions))]
    #[must_use]
    pub(crate) fn cred_misses(&self) -> u32 {
        self.cred_misses
            .saturating_add(test_steps::press_input_misses(self))
    }
}

/// Hooks for the screenshot tour (`ui::tour`, an `#[ignore]` test). Gated like the tour module
/// (`#[cfg(test)]` + `#[cfg(debug_assertions)]`), so `cargo test --release` has no dead code.
#[cfg(test)]
#[cfg(debug_assertions)]
impl App {
    /// The open secret window.
    pub(crate) fn tour_secret_window(&self) -> Option<&Window> {
        self.secret.as_ref().map(|secret| &secret.window)
    }

    /// Opens a display window (W08/W09) with a non-secret tour value.
    pub(crate) fn tour_open_display(
        &mut self,
        kind: SecretKind,
        purpose: Purpose,
        display: yw_engine::secret::DisplaySecret,
    ) {
        test_steps::open_display(&mut self.wallet, kind, purpose, display);
    }

    /// Types `text` into the open secret window's active field (tour values only). 2026-11-24
    /// (S5-7): as `WM_CHAR` units through the key map (`on_char(unit)` before).
    pub(crate) fn tour_type(&mut self, text: &str) {
        let now = self.clock.now_ms();
        if let Some(secret) = self.secret.as_mut() {
            for unit in text.encode_utf16() {
                let _ = secret.form.on_key(map_secret_char(unit), now);
            }
            secret.window.invalidate();
        }
    }

    /// Moves to the next field of the open secret window (Tab). 2026-11-24 (S5-7): Tab with no
    /// modifier through the key map (`on_key(0x09, false, false, false)` before).
    pub(crate) fn tour_next_field(&mut self) {
        let now = self.clock.now_ms();
        if let Some(secret) = self.secret.as_mut() {
            let _ = secret
                .form
                .on_key(map_secret_key(0x09, false, false, false), now);
            secret.window.invalidate();
        }
    }
}

/// Test builds: the wallet steps that `impl App` test adapters and tour hooks of production
/// files call (the press input swap of [`App::press_family`], the miss count of
/// [`App::cred_misses`], `tour_open_display`, `tour_reject_approval`, `on_links_command`,
/// `on_sites_command`). 2026-11-23 (S4d final review, A-15/D-22): these wallet fields and steps
/// are crate-private in yw-engine again and the tests reach them through `testkit`; before, the
/// adapters called them through `DerefMut`. A production file names `testkit` only inside a
/// `#[cfg(test)]` module (source check `testkit_is_named_only_by_tests`), hence this one.
#[cfg(test)]
pub(crate) mod test_steps {
    use yw_engine::cmd::{LinksPress, SitesPress};
    use yw_engine::form::PressInput;
    use yw_engine::testkit::WalletTestExt;
    use yw_engine::wallet::Wallet;

    pub(crate) fn swap_press_input(wallet: &mut Wallet, input: PressInput) -> PressInput {
        wallet.swap_press_input(input)
    }

    #[cfg(debug_assertions)]
    pub(crate) fn press_input_misses(app: &super::App) -> u32 {
        app.wallet.press_input_misses()
    }

    #[cfg(debug_assertions)]
    pub(crate) fn open_display(
        wallet: &mut Wallet,
        kind: yw_engine::secret::SecretKind,
        purpose: yw_engine::wallet::Purpose,
        display: yw_engine::secret::DisplaySecret,
    ) {
        wallet.open_display(kind, purpose, display);
    }

    #[cfg(debug_assertions)]
    pub(crate) fn finish_approval(wallet: &mut Wallet, outcome: yw_engine::approval::QueueOutcome) {
        wallet.finish_approval(outcome);
    }

    pub(crate) fn on_links(wallet: &mut Wallet, press: LinksPress) {
        wallet.on_links(press);
    }

    pub(crate) fn on_sites(wallet: &mut Wallet, press: SitesPress) {
        wallet.on_sites(press);
    }

    /// The last press, for the credential-read record of [`super::App::cred_check`]
    /// (2026-11-23, spec/15 §11.4 S5-0, §18 31 (가): `Wallet::last_press` is `pub(crate)` since;
    /// before, the record read the `#[doc(hidden)] pub` field).
    #[cfg(debug_assertions)]
    pub(crate) fn last_press(wallet: &Wallet) -> yw_engine::cmd::Press {
        wallet.last_press()
    }
}

#[cfg(test)]
pub(crate) mod tests;
