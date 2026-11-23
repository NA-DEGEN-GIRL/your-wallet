//! Secret-window test seams (2026-11-18, S4 A7; spec/15 §11.4 S4, spec/04 §4, §5.3,
//! spec/09 §2.2).
//!
//! `cfg(test)` only: release builds compile none of this, and the production functions that call
//! it (`create_secret`, `show_secret`, `open_display`, `close_secret_window` — 2026-11-20, S4
//! P7a1: the shell's half of `close_secret`, which logged before —, the two secret-clip
//! clears, the lock's and the shutdown's waits for the key worker, `close_approval_window`)
//! behave exactly as before while no log runs, no refusal is set and the modifiers are not
//! scripted. 2026-11-20 (S4 P7b): the display windows' drop is logged by `drop_display_secret`
//! (the shell's half, was `open_display`), the clip clears are called by the shell's
//! `SecretEffect::ClearClip` arm and the lock's `Suspend` wait by the executor's
//! `Effect::AwaitKeyLock` arm (were called by `App::lock`), at the same points. The seams are
//! thread-locals of the test thread:
//!
//! - `TEST_SECRET_LOG`: the secret-window operations in call order ([`Op`]): window kinds, unit
//!   counts and flags only, never a value. A closed window's units are counted after its wipe
//!   (`left`), so the log shows the wipe; the clip clears are logged when called, before they
//!   look at a pending copy (the windowed characterization never makes one, so it never touches
//!   the real clipboard); the lock's `Suspend` wait and the shutdown's wait are logged just
//!   before they wait (critique A-2: the order secret close < clip clear < approval close < wait
//!   is pinned by `s4_secret/lock.txt`).
//! - The window refusal ([`Refuse`]): `create_secret` refuses the window the way yw-win does
//!   when a `Required` window cannot be excluded from capture (`CaptureExclusionFailed`) or
//!   `CreateWindowExW` fails (`Os`), before a window exists, while the secret host of the tests
//!   (`app::tests::s4_secret::host`) says so. 2026-11-20 (S4 P8): the thread-local
//!   `TEST_SECRET_REFUSE` and its setter `set_refuse` are gone (they were S4 A7's); the refusal
//!   is the recording host's answer now, the same one the headless run and the windowed
//!   `ui::tour_secrets` set (`host::refuse`), read here at the same point.
//! - `TEST_SECRET_KEYS_UP` (2026-11-18, A7 review): while set, the modifier reads of the secret
//!   handler's `WM_KEYDOWN` arm (`on_secret`: Ctrl, Shift, Alt) answer "up" instead of reading the
//!   real keyboard (`yw_win::input::is_down`), so a key the person at the desk holds during the
//!   windowed run cannot change the Esc and Enter lines. Not logged (the goldens are unchanged).
//!
//! The `impl App` accessors (debug test builds, like `ui::tour_secrets`, their only user) read
//! the open secret window and the transient secret buffers as facts (kinds, flags, counts), and
//! deliver one message to the open window's real handler (`on_secret`).

use std::cell::{Cell, RefCell};

use yw_win::ui::UiError;

use yw_engine::secret::SecretKind;

/// How `create_secret` refuses a window while a refusal is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Refuse {
    /// As yw-win for a `Required` (display) class whose exclusion failed: the window was
    /// destroyed (`UiError::CaptureExclusionFailed`).
    Exclusion,
    /// As a failed `CreateWindowExW` (`UiError::Os`).
    Os,
}

/// One secret-window operation (S4 A7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Op {
    /// `create_secret` was asked for a window (`topmost`: W11, the dApp W02).
    Create { kind: &'static str, topmost: bool },
    /// The refusal seam answered instead of yw-win.
    Refused(Refuse),
    /// `show_secret`: the window is shown and holds its form.
    Show { kind: &'static str },
    /// `open_display` dropped (wiped) the secret of a refused window.
    DisplayDropped,
    /// `close_secret` closed a window; `left` = the units its form still held after the wipe.
    Close { kind: &'static str, left: usize },
    /// A secret-clip clear was called (`pending`: a secret copy was waiting to be cleared).
    ClearClip { at_exit: bool, pending: bool },
    /// `close_approval_window` was called (`shown`: an approval window was open).
    ApprovalClose { shown: bool },
    /// A wait for the key worker's lock (`what` = `lock` on `Suspend`, `shutdown`).
    Wait { what: &'static str, ms: u64 },
}

impl Op {
    /// The golden name of the operation.
    pub(crate) fn name(self) -> String {
        match self {
            Self::Create { kind, topmost } => {
                format!("create:{kind}{}", if topmost { ":topmost" } else { "" })
            }
            Self::Refused(Refuse::Exclusion) => "refused:exclusion".to_owned(),
            Self::Refused(Refuse::Os) => "refused:os".to_owned(),
            Self::Show { kind } => format!("show:{kind}"),
            Self::DisplayDropped => "display-dropped".to_owned(),
            Self::Close { kind, left } => format!("close:{kind}:left={left}"),
            Self::ClearClip { at_exit, pending } => format!(
                "clear-clip{}{}",
                if at_exit { ":exit" } else { "" },
                if pending { ":pending" } else { "" }
            ),
            Self::ApprovalClose { shown } => {
                format!("approval-close:{}", if shown { "shown" } else { "none" })
            }
            Self::Wait { what, ms } => format!("wait:{what}:{ms}"),
        }
    }
}

thread_local! {
    static TEST_SECRET_LOG: RefCell<Option<Vec<Op>>> = const { RefCell::new(None) };
    /// The serial and `topmost` of the last window `create_secret` was asked for.
    static TEST_LAST_CREATE: Cell<Option<(u64, bool)>> = const { Cell::new(None) };
    /// Whether the secret handler's modifier reads answer "up" (A7 review).
    static TEST_SECRET_KEYS_UP: Cell<bool> = const { Cell::new(false) };
}

/// Starts (or restarts) the operation log of this thread.
pub(crate) fn start_log() {
    let _ = TEST_SECRET_LOG.try_with(|slot| *slot.borrow_mut() = Some(Vec::new()));
    let _ = TEST_AFTER_QUEUED.try_with(|slot| slot.borrow_mut().clear());
}

/// The operations logged since the last call (the log keeps running).
pub(crate) fn take_log() -> Vec<Op> {
    TEST_SECRET_LOG
        .try_with(|slot| slot.borrow_mut().as_mut().map(std::mem::take))
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// Stops the log and clears the last creation and the scripted modifiers of this thread
/// (2026-11-20, S4 P8: the refusal is the secret host's, removed with it).
pub(crate) fn stop() {
    let _ = TEST_SECRET_LOG.try_with(|slot| *slot.borrow_mut() = None);
    let _ = TEST_LAST_CREATE.try_with(|slot| slot.set(None));
    let _ = TEST_SECRET_KEYS_UP.try_with(|slot| slot.set(false));
    let _ = TEST_AFTER_QUEUED.try_with(|slot| slot.borrow_mut().clear());
}

/// Makes the secret handler's modifier reads answer "up" (`true`) or read the real keyboard
/// again (`false`) on this thread.
pub(crate) fn set_keys_up(up: bool) {
    let _ = TEST_SECRET_KEYS_UP.try_with(|slot| slot.set(up));
}

/// `on_secret`'s modifier read: `Some(false)` ("up") while scripted, else `None` (the real read
/// follows).
pub(crate) fn scripted_modifier() -> Option<bool> {
    TEST_SECRET_KEYS_UP
        .try_with(Cell::get)
        .ok()
        .filter(|up| *up)
        .map(|_| false)
}

thread_local! {
    /// The logic's own steps logged while effects it emitted before them were still queued, each
    /// with the number of those effects not yet applied (2026-11-20, S4 P10b).
    static TEST_AFTER_QUEUED: RefCell<Vec<(usize, Op)>> = const { RefCell::new(Vec::new()) };
}

/// Logs `op`, a step of the logic itself (`close_approval_window`), where it stands among the
/// effects the logic emitted: after the `queued` ones emitted before it, once the shell applied
/// them (2026-11-20, S4 P10b, plan §3.4). With effects applied at once (before P10) `queued` was
/// always 0 and the step was logged when called; with the outbox the shell applies them when
/// the entry drains, so a step logged at its call would come before the secret close and clip
/// clear the lock emitted before it, although the shell still closes the windows in that order
/// (critique A-2, `s4_secret/lock.txt`).
pub(crate) fn log_after(queued: usize, op: Op) {
    if queued == 0 {
        log(op);
        return;
    }
    let _ = TEST_AFTER_QUEUED.try_with(|slot| slot.borrow_mut().push((queued, op)));
}

/// The shell applied one queued effect (`App::drain`): the steps waiting for it are logged, in
/// their order (2026-11-20, S4 P10b).
pub(crate) fn applied() {
    let due: Vec<Op> = TEST_AFTER_QUEUED
        .try_with(|slot| {
            let mut waiting = slot.borrow_mut();
            for entry in waiting.iter_mut() {
                entry.0 = entry.0.saturating_sub(1);
            }
            let ready = waiting.iter().take_while(|(left, _)| *left == 0).count();
            waiting.drain(..ready).map(|(_, op)| op).collect()
        })
        .unwrap_or_default();
    for op in due {
        log(op);
    }
}

/// Installs this thread's sink of the wallet code's probe notes ([`probe_sink`]); every test
/// `App` does when it is built (`App::with_clock`). 2026-11-23 (spec/15 §11.4 S4d E0b, preflight
/// O-4): the wallet code notes `yw_engine::probe::Probe`s where it called this seam under
/// `cfg(test)` before (`drop_display_secret`, `close_approval_window`); the only installer of a
/// probe sink (source check `the_probe_is_installed_only_by_tests`).
pub(crate) fn install_probe() {
    let _ = yw_engine::probe::install(Some(probe_sink));
}

/// The probe sink: each note is logged as the seam call it replaced, at the same point
/// (2026-11-23, S4d E0b): `DisplayDropped` with [`log`], `ApprovalClose` with [`log_after`] and
/// the count of effects queued before it.
fn probe_sink(probe: yw_engine::probe::Probe) {
    match probe {
        yw_engine::probe::Probe::DisplayDropped => log(Op::DisplayDropped),
        yw_engine::probe::Probe::ApprovalClose { shown, queued } => {
            log_after(queued, Op::ApprovalClose { shown });
        }
    }
}

/// Appends to the log while it runs.
pub(crate) fn log(op: Op) {
    let _ = TEST_SECRET_LOG.try_with(|slot| {
        if let Ok(mut log) = slot.try_borrow_mut()
            && let Some(log) = log.as_mut()
        {
            log.push(op);
        }
    });
}

/// `create_secret`'s seam: logs the request and, while the secret host of this thread refuses
/// windows (`app::tests::s4_secret::host::refuse`), answers with that refusal (2026-11-20, S4 P8:
/// was `TEST_SECRET_REFUSE`). The headless host's own window-free opens log through here too.
pub(crate) fn create(serial: u64, kind: SecretKind, topmost: bool) -> Option<UiError> {
    let _ = TEST_LAST_CREATE.try_with(|slot| slot.set(Some((serial, topmost))));
    log(Op::Create {
        kind: kind.id(),
        topmost,
    });
    let refuse = super::tests::s4_secret::host::refusal()?;
    log(Op::Refused(refuse));
    Some(match refuse {
        Refuse::Exclusion => UiError::CaptureExclusionFailed,
        Refuse::Os => UiError::Os(yw_win::WinError {
            api: "CreateWindowExW",
            code: 8,
        }),
    })
}

/// The `topmost` of window `serial`, when it was the last one asked for.
pub(crate) fn topmost_of(serial: u64) -> Option<bool> {
    TEST_LAST_CREATE
        .try_with(Cell::get)
        .ok()
        .flatten()
        .filter(|(last, _)| *last == serial)
        .map(|(_, topmost)| topmost)
}

/// The open secret window as facts (no value).
#[cfg(debug_assertions)]
#[derive(Clone, Debug)]
pub(crate) struct SecretFacts {
    pub(crate) serial: u64,
    pub(crate) kind: &'static str,
    pub(crate) purpose: super::Purpose,
    pub(crate) topmost: Option<bool>,
    /// Real Win32 state in the windowed run: the window is visible (not hidden or minimized).
    /// Always `true` for a window the headless secret host made (2026-11-20, S4 P8 review: it
    /// has no window to read; `app::tests::s4_secret::host::facts`).
    pub(crate) shown: bool,
    /// `SecretForm` facts (flags and counts).
    pub(crate) form: String,
}

/// Accessors of `ui::tour_secrets` (debug test builds, like it).
#[cfg(debug_assertions)]
impl super::App {
    /// The open secret window, if any (2026-11-20, S4 P7a1: its purpose is the wallet's secret
    /// session's; the window record no longer holds one).
    pub(crate) fn test_secret(&self) -> Option<SecretFacts> {
        let purpose = self.secret_purpose()?;
        // 2026-11-20 (S4 P8): the headless secret host's window, when it holds one.
        if let Some(facts) = super::tests::s4_secret::host::facts(purpose) {
            return Some(facts);
        }
        self.secret.as_ref().map(|secret| SecretFacts {
            serial: secret.serial,
            kind: secret.form.kind().id(),
            purpose,
            topmost: topmost_of(secret.serial),
            shown: !secret.window.is_hidden_or_minimized(),
            form: secret.form.test_facts(),
        })
    }

    /// The transient secret buffers that hold something now (names only).
    pub(crate) fn test_held(&self) -> Vec<&'static str> {
        let mut held = Vec::new();
        if self.import.password.is_some() {
            held.push("import-password");
        }
        if self.import.phrase.is_some() {
            held.push("import-phrase");
        }
        if self.challenge.is_some() {
            held.push("challenge");
        }
        if self.keys.start.holds_secret() {
            held.push("key-start");
        }
        let (phrase, quiz) = self.mn.test_holds();
        if phrase {
            held.push("mn-phrase");
        }
        if quiz {
            held.push("mn-challenge");
        }
        if self
            .card
            .wizard
            .as_ref()
            .is_some_and(crate::app_yubikey::YkWizard::test_holds_secret)
        {
            held.push("yk-wizard");
        }
        if self
            .card
            .step
            .as_ref()
            .is_some_and(|step| step.approved.is_some())
        {
            held.push("card-approval");
        }
        if self.secret_clip.is_some() {
            held.push("secret-clip");
        }
        held
    }

    /// A submission of `purpose` straight to `on_submit`, as the headless `app::tests::Harness`
    /// does (setup of a purpose's buffers; the windowed path is [`Self::test_secret_msg`]).
    pub(crate) fn test_submit(
        &mut self,
        purpose: super::Purpose,
        values: Vec<yw_core::secret::Zeroizing<Vec<u8>>>,
        checkbox: bool,
    ) {
        self.on_submit(purpose, crate::ui::secret::Submission { values, checkbox });
    }

    /// Delivers `msg` for window `serial` to the real secret handler (`on_secret`, as the
    /// window's `Forward` does once it borrowed the App), with the open window's real `Window`:
    /// `spare` stands in the App meanwhile and the real one is put back while that window is
    /// still open; a window its handler closed is destroyed when this returns.
    pub(crate) fn test_secret_msg(
        &mut self,
        serial: u64,
        msg: &yw_win::ui::Msg,
        spare: yw_win::ui::Window,
    ) -> yw_win::ui::Reply {
        let mut held = spare;
        let owner = self.secret.as_ref().map(|secret| secret.serial);
        if let Some(secret) = self.secret.as_mut() {
            core::mem::swap(&mut secret.window, &mut held);
        }
        let reply = self.on_secret(serial, &held, msg);
        if let Some(secret) = self
            .secret
            .as_mut()
            .filter(|secret| Some(secret.serial) == owner)
        {
            core::mem::swap(&mut secret.window, &mut held);
        }
        drop(held);
        reply
    }
}

/// The seams are inert without a log or a refusal (gate test step; no window). 2026-11-20 (S4
/// P8): the refusal comes from the secret host (`host::refuse`), not `set_refuse`.
#[test]
fn secret_seams_are_inert_without_a_log() {
    use super::tests::s4_secret::host;
    stop();
    log(Op::DisplayDropped);
    assert!(take_log().is_empty());
    assert!(create(1, SecretKind::Unlock, false).is_none());
    assert_eq!(topmost_of(1), Some(false));
    assert_eq!(topmost_of(2), None);
    start_log();
    host::install(true);
    host::refuse(Some(Refuse::Exclusion));
    assert!(matches!(
        create(2, SecretKind::ShowKey, true),
        Some(UiError::CaptureExclusionFailed)
    ));
    host::refuse(Some(Refuse::Os));
    assert!(matches!(
        create(3, SecretKind::Unlock, false),
        Some(UiError::Os(_))
    ));
    host::refuse(None);
    assert!(create(4, SecretKind::Unlock, false).is_none());
    host::refuse(Some(Refuse::Os));
    host::remove();
    assert!(create(5, SecretKind::Unlock, false).is_none());
    let names: Vec<String> = take_log().into_iter().map(Op::name).collect();
    assert_eq!(
        names,
        [
            "create:W09:topmost",
            "refused:exclusion",
            "create:W02",
            "refused:os",
            "create:W02",
            "create:W02"
        ]
    );
    stop();
    assert!(create(6, SecretKind::Unlock, false).is_none());
    assert!(take_log().is_empty());
    assert_eq!(scripted_modifier(), None);
    set_keys_up(true);
    assert_eq!(scripted_modifier(), Some(false));
    stop();
    assert_eq!(scripted_modifier(), None);
}
