//! S4 P8 (2026-11-20; spec/15 §11.4 S4, spec/09 §2.1–§2.2, spec/04 §4.5): the secret sessions
//! headless in the gate.
//!
//! [`host`] is the recording secret host, `cfg(test)` only (release builds compile none of it):
//! a shell for the secret windows that can succeed, refuse or fail, and records what passes
//! through it. While it is installed on the test thread:
//!
//! - every `Effect::Secret` the executor applies (`App::apply_secret_effect`) is noted as its
//!   `Debug` text, and so are the form actions the host delivers and the session's and form's
//!   `Debug` at every recorded line, so the scan below sees whether a secret reaches any of them;
//! - **succeed** (the headless run's default): an open of the open, unshown session (the
//!   production guard runs first) is the shell's own decision on a window that was made and
//!   excluded from capture (`capture_decision(kind, Ok(true))`), without Win32: the host holds the
//!   window's `SecretForm` (built exactly as `open_input_window` / `open_display_window` build it;
//!   a display secret moves out of the session only in that arm, `take_display_secret`; since
//!   2026-11-21 (S4 W2) the shell's display open is `make_display_window` + `show_display` with
//!   the composition `display_window_handoff` between, and the host's one fn mirrors all three), logs
//!   `create:` and `show:` as `create_secret` / `show_secret` do, and answers `Shown`. Its
//!   messages go through [`host::deliver`], the window-free arms of `on_secret` (character, key,
//!   timer, close box) with the same form calls and the same `apply_form_action`; its form
//!   operations and its close (wipe, `close:…:left=`) through `apply_form_op` /
//!   `close_secret_window`'s hooks. **Made, not excluded** ([`host::not_excluded`]): the same on
//!   `Ok(false)` (an input window shows with the warning; a display window is refused and its
//!   secret dropped).
//! - **refuse** / **fail** ([`host::refuse`] with `Refuse::Exclusion` / `Refuse::Os`): the
//!   production path runs and `create_secret`'s seam (`secret_seam::create`) answers
//!   `CaptureExclusionFailed` / `UiError::Os` before a window exists, as yw-win would. This
//!   replaces S4 A7's thread-local `TEST_SECRET_REFUSE` (removed here); the windowed
//!   `ui::tour_secrets` installs the host as a pass-through of the real shell (`install(false)`)
//!   and sets its refusals the same way.
//!
//! The headless run ([`secret_sessions_run_headless`], gate test step, no `#[ignore]`, no window)
//! runs every scenario of `ui::tour_secrets` (the same code, its `Env` switches on
//! [`host::headless`]) with the secret host headless and the approval windows answered by
//! `app_approval::headless_host`, the main-window entries through `App::test_on_main_windowless`,
//! and compares the lines with the frozen goldens `s4_secret/secret.txt` and `lock.txt` byte for
//! byte (no second copy, no line dropped). The windowed `ui::tour_secrets` stays on request (real
//! windows: `shown=` and capture exclusion are real Win32 reads there).
//!
//! The copies of the shell's code here (`open_input_window`'s `Ok(window)` arm, `open_display_window`,
//! `show_secret`'s log, `close_secret_window`'s wipe, `apply_form_op`'s match and `on_secret`'s
//! arms) are pinned by [`the_headless_secret_host_mirrors_the_shell`], which reads `app.rs` and
//! this file: each shell statement the host copies is still in the shell fn and, with the
//! documented renames, in the host fn (2026-11-20, S4 P8 review: before, only the shell side was
//! read, and a change made only in the host passed).
//!
//! Not delivered headless (2026-11-20, S4 P8 review): the window record `App::secret` stays empty
//! (the host holds the form), so the form actions that act on it do nothing here. `Redraw` (the
//! window's invalidate) has no window to repaint; `Copy` and `Paste` need the clipboard and that
//! record (`copy_secret`'s copy-off notice included), so [`host::deliver`] fails the test on
//! them, as on any message it does not deliver. No scenario sends them (`allowSecretCopy` stays
//! off and no scenario copies or pastes, spec/09 §2.2).

/// The recording secret host (see the module doc).
pub(crate) mod host {
    use std::cell::RefCell;

    use yw_core::lang::Lang;
    use yw_engine::approval::flow::OpenOutcome;
    use yw_engine::cmd::Cmd;
    use yw_engine::secret::{SecretEffect, SecretFormOp, SecretKind, SecretStep};
    #[cfg(debug_assertions)]
    use yw_win::ui::{Msg, Reply};

    use crate::app::App;
    use crate::app::secret_seam::{self, Op, Refuse};
    #[cfg(debug_assertions)]
    use crate::app::{VK_CONTROL, VK_MENU, VK_SHIFT, secret_modifier};
    use crate::errors::ErrorCode;
    use crate::ui::secret::{CaptureDecision, SecretForm, capture_decision};
    #[cfg(debug_assertions)]
    use crate::ui::secret::{FormAction, SECRET_TIMER_ID};

    /// The window the headless host holds instead of a Win32 window: its session's serial and
    /// its form.
    struct Held {
        serial: u64,
        form: SecretForm,
    }

    struct Host {
        /// The headless run (else the pass-through of the windowed run: only refusals).
        headless: bool,
        refuse: Option<Refuse>,
        not_excluded: bool,
        window: Option<Held>,
        answers: Vec<OpenOutcome>,
    }

    thread_local! {
        static HOST: RefCell<Option<Host>> = const { RefCell::new(None) };
        /// The `Debug` texts noted for the scan; kept when the host is removed (the scenario's
        /// `Env` removes it before the runner reads them).
        static SEEN: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
    }

    /// Installs the host on this thread (`headless`: the headless run; else the windowed run's
    /// pass-through of the real shell). No refusal; a held window is dropped (wiped).
    pub(crate) fn install(headless: bool) {
        remove();
        let _ = HOST.try_with(|slot| {
            *slot.borrow_mut() = Some(Host {
                headless,
                refuse: None,
                not_excluded: false,
                window: None,
                answers: Vec::new(),
            });
        });
    }

    /// Removes the host (a held window's form is wiped first).
    pub(crate) fn remove() {
        let host = HOST
            .try_with(|slot| slot.borrow_mut().take())
            .ok()
            .flatten();
        if let Some(mut held) = host.and_then(|host| host.window) {
            held.form.wipe();
        }
    }

    /// Whether the host is installed for the headless run on this thread.
    #[cfg(debug_assertions)]
    pub(crate) fn headless() -> bool {
        HOST.try_with(|slot| slot.borrow().as_ref().is_some_and(|host| host.headless))
            .unwrap_or(false)
    }

    /// Sets (or with `None` clears) the refusal: `create_secret` refuses every window as yw-win
    /// would (`Exclusion`: refuse; `Os`: fail).
    pub(crate) fn refuse(refuse: Option<Refuse>) {
        let _ = HOST.try_with(|slot| {
            if let Some(host) = slot.borrow_mut().as_mut() {
                host.refuse = refuse;
            }
        });
    }

    /// The refusal `create_secret`'s seam answers with now (`None`: none, or no host).
    pub(crate) fn refusal() -> Option<Refuse> {
        HOST.try_with(|slot| slot.borrow().as_ref().and_then(|host| host.refuse))
            .ok()
            .flatten()
    }

    /// Headless: the windows it makes are made but not excluded from capture (`true`).
    #[cfg(debug_assertions)]
    pub(crate) fn not_excluded(on: bool) {
        let _ = HOST.try_with(|slot| {
            if let Some(host) = slot.borrow_mut().as_mut() {
                host.not_excluded = on;
            }
        });
    }

    /// The outcomes the headless host answered its opens with since the last call.
    #[cfg(debug_assertions)]
    pub(crate) fn take_answers() -> Vec<OpenOutcome> {
        HOST.try_with(|slot| {
            slot.borrow_mut()
                .as_mut()
                .map(|host| std::mem::take(&mut host.answers))
        })
        .ok()
        .flatten()
        .unwrap_or_default()
    }

    fn note(text: String) {
        let installed = HOST
            .try_with(|slot| slot.borrow().is_some())
            .unwrap_or(false);
        if installed {
            let _ = SEEN.try_with(|seen| seen.borrow_mut().push(text));
        }
    }

    /// The `Debug` texts noted since the last call.
    #[cfg(debug_assertions)]
    pub(crate) fn take_seen() -> Vec<String> {
        SEEN.try_with(|seen| std::mem::take(&mut *seen.borrow_mut()))
            .unwrap_or_default()
    }

    /// `App::apply_secret_effect`'s note of one effect.
    pub(crate) fn saw(effect: &SecretEffect) {
        note(format!("{effect:?}"));
    }

    /// The executor's note of the answer to a secret effect (`Cmd::SecretOpened`, 2026-11-20,
    /// S4 P8 review), before it goes to `Wallet::on_cmd` (`App::on_cmd` before 2026-11-22 S4c W15).
    pub(crate) fn saw_cmd(cmd: &Cmd) {
        note(format!("{cmd:?}"));
    }

    /// The session's and the held form's `Debug` (each recorded line of the headless run).
    #[cfg(debug_assertions)]
    pub(crate) fn note_state(app: &App) {
        note(format!("{:?}", app.secret_session));
        let form = HOST
            .try_with(|slot| {
                slot.borrow()
                    .as_ref()
                    .and_then(|host| host.window.as_ref())
                    .map(|held| format!("{:?}", held.form))
            })
            .ok()
            .flatten();
        if let Some(form) = form {
            note(form);
        }
    }

    /// Whether the headless host makes the window itself, and whether it is excluded from
    /// capture: `Some(excluded)` in the headless run without a refusal, else `None` (the
    /// production path runs, refusals included).
    fn made() -> Option<bool> {
        HOST.try_with(|slot| {
            slot.borrow()
                .as_ref()
                .filter(|host| host.headless && host.refuse.is_none())
                .map(|host| !host.not_excluded)
        })
        .ok()
        .flatten()
    }

    fn answered(outcome: OpenOutcome) -> OpenOutcome {
        let _ = HOST.try_with(|slot| {
            if let Some(host) = slot.borrow_mut().as_mut() {
                host.answers.push(outcome);
            }
        });
        outcome
    }

    /// `show_secret` without a window: the log line and the window record (the host's).
    fn show(app: &App, serial: u64, form: SecretForm) {
        debug_assert!(app.secret.is_none(), "a secret window is already open");
        secret_seam::log(Op::Show {
            kind: form.kind().id(),
        });
        let _ = HOST.try_with(|slot| {
            if let Some(host) = slot.borrow_mut().as_mut() {
                assert!(host.window.is_none(), "a secret window is already open");
                host.window = Some(Held { serial, form });
            }
        });
    }

    /// `open_input_window`'s hook: in the headless run without a refusal, its `Ok(window)` arm on
    /// the window the host says was made (`None`: the production path runs).
    pub(crate) fn open_input(
        app: &mut App,
        serial: u64,
        kind: SecretKind,
        step: Option<SecretStep>,
        topmost: bool,
        lang: Lang,
    ) -> Option<OpenOutcome> {
        let excluded = made()?;
        // `create_secret`'s seam line (no refusal while `made()` answers).
        let refused = secret_seam::create(serial, kind, topmost);
        assert!(refused.is_none(), "no refusal while the host makes windows");
        App::log_capture(kind, excluded);
        let outcome = match capture_decision(kind, Ok(excluded)) {
            CaptureDecision::Show { warning } => {
                let mut form = SecretForm::new(kind, lang, app.clock.now_ms(), !warning);
                form.set_step(step);
                show(app, serial, form);
                OpenOutcome::Shown {
                    capture_excluded: !warning,
                }
            }
            CaptureDecision::Refuse(code) => OpenOutcome::Refused(code),
        };
        Some(answered(outcome))
    }

    /// `display_window_handoff`'s hook (2026-11-21, S4 W2: was `open_display_window`'s): as
    /// [`open_input`], its decision on the window the host says
    /// was made; the secret leaves the session only in the verified arm, every other arm drops it.
    pub(crate) fn open_display(
        app: &mut App,
        serial: u64,
        kind: SecretKind,
        step: Option<SecretStep>,
        timeout_note: Option<&'static str>,
        lang: Lang,
    ) -> Option<OpenOutcome> {
        let made = made()?;
        let refused = secret_seam::create(serial, kind, false);
        assert!(refused.is_none(), "no refusal while the host makes windows");
        let excluded: Result<bool, ()> = Ok(made);
        App::log_capture(kind, made);
        let outcome = match capture_decision(kind, excluded) {
            CaptureDecision::Show { warning: false } => {
                let Some(display) = app.wallet.take_display_secret(serial) else {
                    return Some(answered(OpenOutcome::Refused(ErrorCode::Sec001)));
                };
                note(format!("{display:?}"));
                let mut form = SecretForm::display(kind, lang, app.clock.now_ms(), display);
                form.set_step(step);
                form.set_timeout_note(timeout_note);
                show(app, serial, form);
                OpenOutcome::Shown {
                    capture_excluded: true,
                }
            }
            CaptureDecision::Show { warning: true } => {
                app.wallet.drop_display_secret(serial);
                OpenOutcome::Refused(ErrorCode::Sec001)
            }
            CaptureDecision::Refuse(code) => {
                app.wallet.drop_display_secret(serial);
                OpenOutcome::Refused(code)
            }
        };
        Some(answered(outcome))
    }

    /// `close_secret_window`'s hook: the held window of session `serial` is wiped and closed
    /// (`true`); `false`: the host holds no such window (the production path runs).
    pub(crate) fn close(serial: u64) -> bool {
        let held = HOST
            .try_with(|slot| {
                slot.borrow_mut()
                    .as_mut()
                    .and_then(|host| host.window.take_if(|held| held.serial == serial))
            })
            .ok()
            .flatten();
        let Some(mut held) = held else {
            return false;
        };
        held.form.wipe();
        secret_seam::log(Op::Close {
            kind: held.form.kind().id(),
            left: held.form.test_held_units(),
        });
        true
    }

    fn holds(serial: u64) -> bool {
        HOST.try_with(|slot| {
            slot.borrow()
                .as_ref()
                .and_then(|host| host.window.as_ref())
                .is_some_and(|held| held.serial == serial)
        })
        .unwrap_or(false)
    }

    /// `apply_form_op`'s hook: the held window of session `serial` takes `op` (`None`); `Some`:
    /// the host holds no such window (the production path runs with it).
    pub(crate) fn form_op(serial: u64, op: SecretFormOp) -> Option<SecretFormOp> {
        if !holds(serial) {
            return Some(op);
        }
        let _ = HOST.try_with(|slot| {
            if let Some(held) = slot
                .borrow_mut()
                .as_mut()
                .and_then(|host| host.window.as_mut())
            {
                let form = &mut held.form;
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
            }
        });
        None
    }

    #[cfg(debug_assertions)]
    enum Step {
        Reply(Reply),
        Act(FormAction),
        Unsupported,
    }

    /// One message for the held window `serial`: `on_secret`'s window-free arms (a character, a
    /// key, the window's timer, the close box) with the same form calls, then the same
    /// `apply_form_action`. Another serial (a window that is not open): `Reply::Default`, nothing
    /// changes, as `on_secret`. Any other message is not delivered headless (the test fails), and
    /// neither is a `Copy` or `Paste` the form asks for (the module doc).
    #[cfg(debug_assertions)]
    pub(crate) fn deliver(app: &mut App, serial: u64, msg: &Msg) -> Reply {
        let now = app.clock.now_ms();
        let step = HOST
            .try_with(|slot| {
                let mut slot = slot.borrow_mut();
                let held = slot
                    .as_mut()
                    .and_then(|host| host.window.as_mut())
                    .filter(|held| held.serial == serial)?;
                let form = &mut held.form;
                Some(match msg {
                    Msg::Char(unit) => Step::Act(form.on_char(*unit, now)),
                    Msg::KeyDown { vk, .. } => {
                        let action = form.on_key(
                            *vk,
                            secret_modifier(VK_CONTROL),
                            secret_modifier(VK_SHIFT),
                            secret_modifier(VK_MENU),
                            now,
                        );
                        if matches!(action, FormAction::None) {
                            Step::Reply(Reply::Default)
                        } else {
                            Step::Act(action)
                        }
                    }
                    Msg::Timer(SECRET_TIMER_ID) => Step::Act(form.on_tick(now)),
                    Msg::Close => {
                        if form.busy() {
                            Step::Reply(Reply::Handled(0))
                        } else if form.kind().is_display() && !form.kind().needs_hold() {
                            form.wipe();
                            Step::Act(FormAction::Close)
                        } else {
                            form.wipe();
                            Step::Act(FormAction::Cancel)
                        }
                    }
                    _ => Step::Unsupported,
                })
            })
            .ok()
            .flatten();
        assert!(
            !matches!(step, Some(Step::Unsupported)),
            "the headless secret host delivers no {msg:?}"
        );
        match step {
            None | Some(Step::Unsupported) => Reply::Default,
            Some(Step::Reply(reply)) => reply,
            Some(Step::Act(action)) => {
                assert!(
                    !matches!(action, FormAction::Copy | FormAction::Paste),
                    "the headless secret host delivers no clipboard action"
                );
                note(format!("{action:?}"));
                app.apply_form_action(serial, action);
                Reply::Handled(0)
            }
        }
    }

    /// The held window as facts (no value), for `App::test_secret`.
    #[cfg(debug_assertions)]
    pub(crate) fn facts(purpose: crate::app::Purpose) -> Option<secret_seam::SecretFacts> {
        HOST.try_with(|slot| {
            slot.borrow()
                .as_ref()
                .and_then(|host| host.window.as_ref())
                .map(|held| secret_seam::SecretFacts {
                    serial: held.serial,
                    kind: held.form.kind().id(),
                    purpose,
                    topmost: secret_seam::topmost_of(held.serial),
                    // A window the host made counts as shown (the windowed run reads it).
                    shown: true,
                    form: held.form.test_facts(),
                })
        })
        .ok()
        .flatten()
    }

    /// Whether the host holds a window now.
    #[cfg(debug_assertions)]
    pub(crate) fn holds_window() -> bool {
        HOST.try_with(|slot| {
            slot.borrow()
                .as_ref()
                .is_some_and(|host| host.window.is_some())
        })
        .unwrap_or(false)
    }
}

#[cfg(debug_assertions)]
use crate::ui::tour_secrets::{self, Scenario};

/// Every scenario of `table` headless, each on a thread of its own (as `ui::tour_secrets`'s
/// `record`), as one golden text, and the `Debug` texts the host noted on the way.
#[cfg(debug_assertions)]
fn record_headless(table: &[(&str, Scenario)]) -> (String, Vec<String>) {
    let mut out = String::new();
    let mut seen = Vec::new();
    for (_, scenario) in table {
        let scenario = *scenario;
        let (lines, noted) = std::thread::spawn(move || {
            host::install(true);
            let lines = scenario();
            host::remove();
            (lines, host::take_seen())
        })
        .join()
        .expect("the scenario's thread");
        for line in lines {
            out.push_str(&line);
            out.push('\n');
        }
        seen.extend(noted);
    }
    (out, seen)
}

/// No secret value in a noted `Debug` text: not the synthetic password or PIN, no word of the
/// test vector (`abandon`, `about`), not W09's key 1 (63 zeros and a 1), no text a scenario types
/// (as a word). A failure names the text's leading type name and its length only, never the text.
#[cfg(debug_assertions)]
fn scan_debug(text: &str) {
    let key_one = format!("{}1", "0".repeat(63));
    let name: String = text
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    let len = text.len();
    for banned in [
        tour_secrets::PASSWORD,
        tour_secrets::PIN,
        "abandon",
        &key_one,
    ] {
        assert!(
            !text.contains(banned),
            "a secret in a Debug text ({name}..., {len} bytes)"
        );
    }
    for word in text.split(|c: char| !c.is_ascii_alphanumeric()) {
        assert!(
            word != "about" && !tour_secrets::TYPED.contains(&word),
            "a typed or shown secret in a Debug text ({name}..., {len} bytes)"
        );
    }
}

/// The secret sessions headless (gate test step; no window, no `#[ignore]`): every scenario of
/// `ui::tour_secrets` gives the frozen `s4_secret/secret.txt` and `lock.txt` byte for byte, and
/// no secret reaches a recorded line (`tour_secrets::scan`, at every line) or a noted `Debug`
/// text (effects, their `Cmd::SecretOpened` answers, form actions, the session, the form).
#[cfg(debug_assertions)]
#[test]
fn secret_sessions_run_headless() {
    let (secret, mut seen) = record_headless(&tour_secrets::SECRET_SCENARIOS);
    let (lock, lock_seen) = record_headless(&tour_secrets::LOCK_SCENARIOS);
    seen.extend(lock_seen);
    let differences: Vec<String> = [
        tour_secrets::first_difference("secret.txt", &secret, tour_secrets::SECRET_GOLDEN),
        tour_secrets::first_difference("lock.txt", &lock, tour_secrets::LOCK_GOLDEN),
    ]
    .into_iter()
    .flatten()
    .collect();
    assert!(differences.is_empty(), "{}", differences.join("\n"));
    assert_eq!(
        secret,
        tour_secrets::SECRET_GOLDEN,
        "secret.txt byte for byte"
    );
    assert_eq!(lock, tour_secrets::LOCK_GOLDEN, "lock.txt byte for byte");
    // The scan cannot pass on nothing (critique A-20): the opens, a display, a submission, the
    // form operations, the sessions and the forms were all seen.
    for needle in [
        "OpenInput",
        "OpenDisplay",
        "Close",
        "Form",
        "ClearClip",
        "Submit",
        "SecretSession",
        "SecretForm",
        "DisplaySecret",
        "SecretOpened",
    ] {
        assert!(
            seen.iter().any(|text| text.contains(needle)),
            "no noted Debug text holds {needle}"
        );
    }
    for text in &seen {
        scan_debug(text);
    }
}

/// The scan of `Debug` texts rejects every value it bans and keeps names (gate test step).
#[cfg(debug_assertions)]
#[test]
fn the_debug_scan_rejects_values_and_keeps_names() {
    let key = format!("x {}1", "0".repeat(63));
    for text in [
        tour_secrets::PASSWORD,
        tour_secrets::PIN,
        "abandon",
        "x about",
        key.as_str(),
        "Char zoo",
        "ab",
    ] {
        assert!(
            std::panic::catch_unwind(|| scan_debug(text)).is_err(),
            "kept: {text}"
        );
    }
    scan_debug("SecretSession { kind: \"W03\", purpose: ConfirmPassword(RevealMnemonic) }");
    scan_debug("Submission(1 values, [REDACTED]) DisplaySecret([REDACTED]) Password");
}

/// The P7b review's open item (spec/15 §11.4 S4 P7b note, spec/04 §4.5 item 4): a display window
/// that was made but whose capture exclusion was not read back is refused — `create:W08,
/// display-dropped`, no window, the secret not taken (dropped, wiped), `Refused(E-SEC-001)`, the
/// banner and S04 for a new wallet's words; an input window in the same case opens with the
/// warning (`Preferred`: not excluded, `보기` off). Headless, no window.
#[cfg(debug_assertions)]
#[test]
fn a_made_but_unexcluded_display_window_drops_its_secret() {
    use yw_engine::approval::flow::OpenOutcome;
    use yw_engine::secret::SecretKind;

    use crate::app::{AppMode, Purpose, Screen, secret_seam};
    use crate::errors::ErrorCode;
    use yw_engine::secret::DisplaySecret;

    let dir = super::temp_dir("p8-not-excluded");
    let mut app = super::app_at(&dir);
    host::install(true);
    host::not_excluded(true);
    secret_seam::stop();
    secret_seam::start_log();
    app.mode = AppMode::Starting;
    let mut text = yw_core::secret::SecretString::with_capacity(16);
    text.push_str("not a real word").unwrap();
    app.open_display(
        SecretKind::ShowMnemonic { create: true },
        Purpose::ShowForBackup,
        DisplaySecret {
            text,
            address: None,
            passphrase_note: false,
            copy_allowed: false,
        },
    );
    app.drain();
    let ops: Vec<String> = secret_seam::take_log()
        .into_iter()
        .map(secret_seam::Op::name)
        .collect();
    assert_eq!(ops, ["create:W08", "display-dropped"]);
    assert_eq!(
        host::take_answers(),
        [OpenOutcome::Refused(ErrorCode::Sec001)]
    );
    assert!(!host::holds_window(), "no window");
    assert!(app.secret_session.is_none(), "the session ended");
    assert!(
        app.banners
            .iter()
            .any(|banner| banner.code == Some(ErrorCode::Sec001)),
        "E-SEC-001"
    );
    assert_eq!(app.screen, Screen::BackupPending, "a new wallet's S04");

    app.open_input(SecretKind::Unlock, Purpose::Unlock, false);
    app.drain();
    let ops: Vec<String> = secret_seam::take_log()
        .into_iter()
        .map(secret_seam::Op::name)
        .collect();
    assert_eq!(ops, ["create:W02", "show:W02"]);
    assert_eq!(
        host::take_answers(),
        [OpenOutcome::Shown {
            capture_excluded: false
        }]
    );
    let facts = app.test_secret().expect("the warned window");
    assert!(facts.form.contains("excluded=false"), "{}", facts.form);
    app.close_secret();
    app.drain();
    let ops: Vec<String> = secret_seam::take_log()
        .into_iter()
        .map(secret_seam::Op::name)
        .collect();
    assert_eq!(ops, ["close:W02:left=0"]);
    assert!(!host::holds_window());
    secret_seam::stop();
    host::remove();
    drop(app);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The host's copies of the shell's code are the shell's code (gate test step): each named fn of
/// `app.rs` still holds, in order and whitespace aside (comments dropped), the statements the host
/// copies, and its hook comes first. A change to one of them fails here until the host's copy
/// follows it. 2026-11-20 (S4 P8 review): the host's side too — each host fn of this file
/// (`open_input`, `open_display`, `show`, `close`, `form_op`, `deliver`) holds the same shell
/// statements in the same order, spelled with the documented renames (`self.show_secret(serial,
/// window, form)` → `show(app, serial, form)`, `secret_seam::Op::` → `Op::`, `self.` → `app.`,
/// `Self::` → `App::`); before, a change made only in the host (say, its `Refuse` arm no longer
/// dropping the display secret) passed here.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "two tables of the shell statements the host copies"
)]
fn the_headless_secret_host_mirrors_the_shell() {
    /// The body of `fn name` in `source` (from `fn name(` to its closing brace), without `//`
    /// comments and whitespace.
    fn body(source: &str, name: &str) -> String {
        let start = source
            .find(&format!("fn {name}("))
            .unwrap_or_else(|| unreachable_fn(name));
        let open = start + source[start..].find('{').unwrap_or(0);
        let mut depth = 0_i32;
        let mut end = open;
        for (at, c) in source[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = open + at + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        source[start..end]
            .lines()
            .map(|line| line.split("//").next().unwrap_or_default())
            .collect::<String>()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
    }
    /// A fn the check names is gone (fails the test).
    fn unreachable_fn(name: &str) -> usize {
        assert!(name.is_empty(), "fn {name} not found");
        0
    }
    fn squeeze(text: &str) -> String {
        text.chars().filter(|c| !c.is_whitespace()).collect()
    }
    fn holds_in_order(name: &str, body: &str, parts: &[&str]) {
        let mut from = 0;
        for part in parts {
            let part = squeeze(part);
            let at = body[from..].find(&part);
            assert!(at.is_some(), "fn {name} no longer holds (in order): {part}");
            from += at.unwrap_or(0) + part.len();
        }
    }
    /// A shell statement as the host spells it (the renames in the test's doc).
    fn host_spelling(part: &str) -> String {
        squeeze(part)
            .replace(
                "self.show_secret(serial,window,form)",
                "show(app,serial,form)",
            )
            .replace("secret_seam::Op::", "Op::")
            .replace("self.", "app.")
            .replace("Self::", "App::")
    }
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let source = std::fs::read_to_string(src.join("app.rs")).unwrap();
    let host_source = std::fs::read_to_string(src.join("app/tests/s4_secret.rs")).unwrap();
    let checks: [(&str, &[&str]); 10] = [
        (
            "open_input_window",
            &[
                "#[cfg(test)] if let Some(outcome) = tests::s4_secret::host::open_input(self, \
                 serial, kind, step, topmost, lang) { return outcome; }",
                "match self.create_secret(serial, kind, topmost, lang) { Ok(window) => { let \
                 excluded = window.capture_excluded(); Self::log_capture(kind, excluded); match \
                 capture_decision(kind, Ok(excluded)) { CaptureDecision::Show { warning } => { \
                 let mut form = SecretForm::new(kind, lang, self.clock.now_ms(), !warning); \
                 form.set_step(step); self.show_secret(serial, window, form); OpenOutcome::Shown \
                 { capture_excluded: !warning, } } CaptureDecision::Refuse(code) => { \
                 drop(window); OpenOutcome::Refused(code) } } }",
            ],
        ),
        // 2026-11-21 (S4 W2, plan §3.4, D-4): a display window's open is the composition's
        // (`display_window_handoff`, called by `open_display_composed` from `App::drain`), with
        // the shell's two halves `make_display_window` and `show_display`; before, one shell fn
        // `open_display_window` held all of it, in this order. 2026-11-22 (S4c W15): the take and
        // the drop are named on the wallet (`self.wallet.`; non-test builds have no `DerefMut`),
        // and the host spells them the same way.
        (
            "display_window_handoff",
            &[
                "#[cfg(test)] if let Some(outcome) = tests::s4_secret::host::open_display(self, \
                 serial, kind, step, timeout_note, lang) { return outcome; }",
                "match self.make_display_window(serial, kind, lang) { \
                 DisplayWindow::Verified(window) => { let Some(display) = \
                 self.wallet.take_display_secret(serial) else { drop(window); return \
                 OpenOutcome::Refused(ErrorCode::Sec001); }; self.show_display(serial, window, \
                 kind, display, step, timeout_note, lang); OpenOutcome::Shown { \
                 capture_excluded: true, } }",
                "DisplayWindow::Unverified { outcome, window } => { \
                 self.wallet.drop_display_secret(serial); drop(window); outcome }",
            ],
        ),
        (
            "make_display_window",
            &[
                "let created = self.create_secret(serial, kind, false, lang); let excluded = \
                 created.as_ref().map(Window::capture_excluded).map_err(|_| ()); \
                 Self::log_capture(kind, excluded.unwrap_or(false)); let decision = \
                 capture_decision(kind, excluded);",
                "(CaptureDecision::Show { warning: false }, Ok(window)) => { \
                 DisplayWindow::Verified(window) }",
                "(CaptureDecision::Show { warning: true }, Ok(window)) => { drop(window); \
                 DisplayWindow::Unverified { outcome: OpenOutcome::Refused(ErrorCode::Sec001), \
                 window: None, } }",
                "(CaptureDecision::Refuse(code), window) => DisplayWindow::Unverified { outcome: \
                 OpenOutcome::Refused(code), window: window.ok(), },",
            ],
        ),
        (
            "show_display",
            &[
                "let mut form = SecretForm::display(kind, lang, self.clock.now_ms(), display); \
               form.set_step(step); form.set_timeout_note(timeout_note); \
               self.show_secret(serial, window, form);",
            ],
        ),
        (
            "show_secret",
            &[
                "debug_assert!(self.secret.is_none(), \"a secret window is already open\");",
                "#[cfg(test)] secret_seam::log(secret_seam::Op::Show { kind: form.kind().id(), \
                 }); self.secret = Some(SecretWin { serial, window, form, });",
            ],
        ),
        (
            "close_secret_window",
            &[
                "#[cfg(test)] if tests::s4_secret::host::close(serial) { return; }",
                "if let Some(mut secret) = self.secret.take_if(|secret| secret.serial == serial) \
                 { secret.form.wipe(); #[cfg(test)] secret_seam::log(secret_seam::Op::Close { \
                 kind: secret.form.kind().id(), left: secret.form.test_held_units(), });",
            ],
        ),
        (
            "apply_form_op",
            &[
                "#[cfg(test)] let Some(op) = tests::s4_secret::host::form_op(serial, op) else { \
                 return; };",
                "match op { SecretFormOp::Busy(busy) => form.set_busy(busy), \
                 SecretFormOp::Error(message) => form.set_error(message), \
                 SecretFormOp::Details(lines) => form.set_details(lines), \
                 SecretFormOp::Card(card) => form.set_card(card), SecretFormOp::Info(message) \
                 => form.set_info(message), SecretFormOp::FailPassword { now_ms } => \
                 form.fail_password(now_ms), SecretFormOp::ResetBackup { positions, message } \
                 => { form.reset_backup(positions, message); } }",
            ],
        ),
        (
            "on_secret",
            &[
                "let now = self.clock.now_ms();",
                "let Some(secret) = secret.as_mut().filter(|secret| secret.serial == serial) \
                 else { return Reply::Default; };",
                "Msg::Char(unit) => form.on_char(*unit, now),",
                "Msg::KeyDown { vk, .. } => { let action = form.on_key( *vk, \
                 secret_modifier(VK_CONTROL), secret_modifier(VK_SHIFT), \
                 secret_modifier(VK_MENU), now, ); if matches!(action, FormAction::None) { \
                 return Reply::Default; } action }",
                "Msg::Timer(SECRET_TIMER_ID) => form.on_tick(now),",
                "Msg::Close => { if form.busy() {",
                "return Reply::Handled(0); } let action = if form.kind().is_display() && \
                 !form.kind().needs_hold() { form.wipe(); FormAction::Close } else { \
                 form.wipe(); FormAction::Cancel }; self.apply_form_action(serial, action); \
                 return Reply::Handled(0); }",
                "self.apply_form_action(serial, action); Reply::Handled(0)",
            ],
        ),
        (
            "apply_secret_effect",
            &[
                "#[cfg(test)] tests::s4_secret::host::saw(&effect);",
                "let unshown = self.secret_session.as_ref().is_some_and(|session| \
                 session.serial() == serial && !session.shown()); let outcome = if unshown { \
                 self.open_input_window(serial, kind, step, topmost, lang) } else { \
                 OpenOutcome::Refused(ErrorCode::Sec001) };",
            ],
        ),
        // 2026-11-21 (S4 W2): the display open's guard, in the composition (was the
        // `apply_secret_effect` arm's, calling `open_display_window`).
        (
            "open_display_composed",
            &[
                "#[cfg(test)] tests::s4_secret::host::saw(&SecretEffect::OpenDisplay { serial, \
                 kind, step, timeout_note, lang, });",
                "let unshown = self.secret_session.as_ref().is_some_and(|session| \
                 session.serial() == serial && !session.shown()); let outcome = if unshown { \
                 self.display_window_handoff(serial, kind, step, timeout_note, lang) } else { \
                 OpenOutcome::Refused(ErrorCode::Sec001) };",
                "#[cfg(test)] tests::s4_secret::host::saw_cmd(&answer);",
            ],
        ),
    ];
    for (name, parts) in checks {
        let text = body(&source, name);
        assert!(text.len() > 40, "fn {name} found");
        holds_in_order(name, &text, parts);
    }
    // 2026-11-20 (S4 P8 review): the statements both sides hold, in the shell's spelling: each
    // is in the shell fn (`app.rs`) and, renamed, in the host fn (this file), in this order.
    let shared: [(&str, &str, &[&str]); 8] = [
        (
            "open_input_window",
            "open_input",
            &[
                "Self::log_capture(kind, excluded);",
                "match capture_decision(kind, Ok(excluded)) { CaptureDecision::Show { warning } \
                 => { let mut form = SecretForm::new(kind, lang, self.clock.now_ms(), \
                 !warning); form.set_step(step); self.show_secret(serial, window, form); \
                 OpenOutcome::Shown { capture_excluded: !warning, } } \
                 CaptureDecision::Refuse(code) =>",
                "OpenOutcome::Refused(code)",
            ],
        ),
        // 2026-11-21 (S4 W2): the host's one `open_display` against the shell's
        // `make_display_window` (the decision), the composition's `display_window_handoff` (the
        // secret's move and drop) and the shell's `show_display` (the form); before, against the
        // one `open_display_window`.
        (
            "make_display_window",
            "open_display",
            &[
                "capture_decision(kind, excluded)",
                "CaptureDecision::Show { warning: false }",
                "CaptureDecision::Show { warning: true }",
                "OpenOutcome::Refused(ErrorCode::Sec001)",
                "CaptureDecision::Refuse(code)",
                "OpenOutcome::Refused(code)",
            ],
        ),
        (
            "display_window_handoff",
            "open_display",
            &[
                "let Some(display) = self.wallet.take_display_secret(serial) else {",
                "OpenOutcome::Refused(ErrorCode::Sec001)",
                "OpenOutcome::Shown { capture_excluded: true, }",
                "self.wallet.drop_display_secret(serial);",
            ],
        ),
        (
            "show_display",
            "open_display",
            &[
                "let mut form = SecretForm::display(kind, lang, self.clock.now_ms(), display); \
               form.set_step(step); form.set_timeout_note(timeout_note); \
               self.show_secret(serial, window, form);",
            ],
        ),
        (
            "show_secret",
            "show",
            &[
                "debug_assert!(self.secret.is_none(), \"a secret window is already open\");",
                "secret_seam::log(secret_seam::Op::Show { kind: form.kind().id(), });",
            ],
        ),
        (
            "close_secret_window",
            "close",
            &[
                "take_if(|",
                ".serial == serial)",
                ".form.wipe();",
                "secret_seam::log(secret_seam::Op::Close { kind:",
                ".form.kind().id(), left:",
                ".form.test_held_units(), });",
            ],
        ),
        (
            "apply_form_op",
            "form_op",
            &[
                "match op { SecretFormOp::Busy(busy) => form.set_busy(busy), \
               SecretFormOp::Error(message) => form.set_error(message), \
               SecretFormOp::Details(lines) => form.set_details(lines), \
               SecretFormOp::Card(card) => form.set_card(card), SecretFormOp::Info(message) \
               => form.set_info(message), SecretFormOp::FailPassword { now_ms } => \
               form.fail_password(now_ms), SecretFormOp::ResetBackup { positions, message } \
               => { form.reset_backup(positions, message); } }",
            ],
        ),
        (
            "on_secret",
            "deliver",
            &[
                "let now = self.clock.now_ms();",
                ".serial == serial)",
                "Msg::Char(unit) =>",
                "form.on_char(*unit, now)",
                "Msg::KeyDown { vk, .. } => { let action = form.on_key( *vk, \
                 secret_modifier(VK_CONTROL), secret_modifier(VK_SHIFT), \
                 secret_modifier(VK_MENU), now, ); if matches!(action, FormAction::None) {",
                "Reply::Default",
                "Msg::Timer(SECRET_TIMER_ID) =>",
                "form.on_tick(now)",
                "Msg::Close => { if form.busy() {",
                "Reply::Handled(0)",
                "form.kind().is_display() && !form.kind().needs_hold() { form.wipe();",
                "FormAction::Close",
                "else { form.wipe();",
                "FormAction::Cancel",
                "self.apply_form_action(serial, action);",
            ],
        ),
    ];
    for (shell, host, parts) in shared {
        let text = body(&source, shell);
        assert!(text.len() > 40, "fn {shell} found");
        holds_in_order(shell, &text, parts);
        let text = body(&host_source, host);
        assert!(text.len() > 40, "host fn {host} found");
        let renamed: Vec<String> = parts.iter().map(|part| host_spelling(part)).collect();
        let renamed: Vec<&str> = renamed.iter().map(String::as_str).collect();
        holds_in_order(&format!("host::{host}"), &text, &renamed);
    }
    // The hooks are the fns' first statements (nothing of the shell runs before the host).
    for (name, hook) in [
        (
            "open_input_window",
            "{#[cfg(test)]iflet Some(outcome)=tests::s4_secret::host::open_input(",
        ),
        (
            "display_window_handoff",
            "{#[cfg(test)]iflet Some(outcome)=tests::s4_secret::host::open_display(",
        ),
        (
            "close_secret_window",
            "{#[cfg(test)]iftests::s4_secret::host::close(serial)",
        ),
        (
            "apply_form_op",
            "{#[cfg(test)]letSome(op)=tests::s4_secret::host::form_op(",
        ),
    ] {
        let text = body(&source, name);
        let hook = squeeze(hook);
        let open = text.find('{').unwrap_or(0);
        assert!(
            text[open..].starts_with(&hook),
            "fn {name}: the host's hook is not the first statement"
        );
    }
}

/// The secret window's entry drains (2026-11-20, S4 P10b review; critique A-14, spec/04 §1.3,
/// §4.5): `Forward` hands a secret window's message to `App::secret_entry`, which is `on_secret`
/// and then the drain, and the tests' headless entry `App::test_secret_entry_headless` is the
/// same with the secret host's copy of `on_secret`'s window-free arms (both bodies pinned here,
/// whitespace aside). Through that headless entry, with no drain of the test's own, the close box
/// of an input window (W02, `Cancel`) and Esc in the next one leave the outbox empty, the window
/// closed and wiped (`close:W02:left=0`) and the session ended when the entry returns. Before
/// the review the secret arm called `on_secret` (no drain of its own) and only `Forward`'s drain
/// after it applied `Secret(Close)`; no test pinned that drain. Headless, no window.
#[cfg(debug_assertions)]
#[test]
fn the_secret_entry_drains_and_its_headless_twin_mirrors_it() {
    use yw_engine::secret::SecretKind;
    use yw_win::ui::{Msg, Reply};

    use crate::app::{AppMode, Purpose, secret_seam};

    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/app.rs"),
    )
    .unwrap();
    // The fn's text from its head to its closing brace, without `//` comments, each run of
    // whitespace one space.
    let body = |head: &str| -> String {
        assert_eq!(source.matches(head).count(), 1, "{head}");
        let start = source.find(head).unwrap_or(0);
        let rest = &source[start..];
        let end = rest.find("\n    }\n").unwrap_or(rest.len());
        rest[..end]
            .lines()
            .map(|line| line.split_once("//").map_or(line, |(code, _)| code))
            .flat_map(str::split_whitespace)
            .collect::<Vec<_>>()
            .join(" ")
    };
    assert_eq!(
        body("    fn secret_entry(&mut self, serial: u64, window: &Window, msg: &Msg) -> Reply {"),
        "fn secret_entry(&mut self, serial: u64, window: &Window, msg: &Msg) -> Reply { let \
         reply = self.on_secret(serial, window, msg); self.drain(); reply"
    );
    assert_eq!(
        body(
            "    pub(crate) fn test_secret_entry_headless(&mut self, serial: u64, msg: &Msg) -> \
             Reply {"
        ),
        "pub(crate) fn test_secret_entry_headless(&mut self, serial: u64, msg: &Msg) -> Reply { \
         let reply = tests::s4_secret::host::deliver(self, serial, msg); self.drain(); reply"
    );
    assert_eq!(
        source
            .matches("Target::Secret(serial) => app.secret_entry(serial, window, msg),")
            .count(),
        1,
        "the main window's Forward hands a secret window's message to secret_entry"
    );

    let dir = super::temp_dir("p10b-secret-entry");
    let mut app = super::app_at(&dir);
    host::install(true);
    secret_seam::stop();
    secret_seam::start_log();
    app.mode = AppMode::Starting;
    let ops = |log: Vec<secret_seam::Op>| -> Vec<String> {
        log.into_iter().map(secret_seam::Op::name).collect()
    };
    let esc = Msg::KeyDown {
        vk: 0x1B,
        repeat: false,
    };
    for msg in [Msg::Close, esc] {
        app.open_input(SecretKind::Unlock, Purpose::Unlock, false);
        app.drain();
        assert_eq!(ops(secret_seam::take_log()), ["create:W02", "show:W02"]);
        let serial = app
            .secret_session
            .as_ref()
            .map(crate::secret_session::SecretSession::serial);
        let serial = serial.unwrap_or_default();
        assert!(host::holds_window(), "W02 open");
        let reply = app.test_secret_entry_headless(serial, &msg);
        assert!(matches!(reply, Reply::Handled(0)), "{msg:?}");
        assert!(app.outbox.is_empty(), "{msg:?}: the entry drained");
        assert_eq!(
            ops(secret_seam::take_log()),
            ["close:W02:left=0"],
            "{msg:?}"
        );
        assert!(!host::holds_window(), "{msg:?}: the window closed");
        assert!(app.secret_session.is_none(), "{msg:?}: the session ended");
    }
    secret_seam::stop();
    host::remove();
    drop(app);
    let _ = std::fs::remove_dir_all(&dir);
}
