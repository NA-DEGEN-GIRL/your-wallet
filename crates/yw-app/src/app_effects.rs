//! The Windows shell's effect executor (spec/15 §11.2, §11.4 S3): applies one
//! [`yw_engine::effect::Effect`] the wallet logic emitted.
//!
//! 2026-11-20 (S4 P10b, plan §3.4, D-3): effects go through an outbox. `Wallet::emit` queues the
//! effect (a field write puts its text into the form state first, owner decision O-10) and
//! `App::drain` applies the queue in emission order, never coalesced, inside the `App` borrow of
//! the entry that emitted them, before that entry returns: every shell entry into the logic
//! (`App::dispatch` for a `Cmd`, the main and secret windows' messages, the approval windows'
//! inputs, each worker event, each part of the main timer, `main.rs`'s start) drains when that
//! call returns. An answer (`Cmd::CopyDone`, `ApprovalOpened`, `Opened`, `FolderMissing`,
//! `SecretOpened`) goes back to the logic in the same drain, and what it emits joins the end of
//! the queue. The `EN_CHANGE` a field write causes and any activation still arrive inside the
//! borrow and stay unseen (re-entrancy, spec/01 §7.7), and a screen is laid out as often as
//! before. Nothing here posts a message or defers work past the borrow (source check
//! `effects_are_never_posted`). Before P10b `emit` applied each effect at once, so a handler's
//! code after an `emit` ran after the effect and its answer; P9 and P10a moved every such step
//! that depends on the answer behind it (spec/15 §11.4 S4, P9/P10a notes; source check S5).
//!
//! Until P10b (S3 B3 … S4 P10a) the text above read: an effect is applied at once, inside the `App`
//! borrow of the handler that emitted it, in emission order, and never coalesced; an outbox, if S4
//! adds one, must drain inside the same borrow; a result goes back to the logic as a `Cmd` before
//! `emit` returns. 2026-11-20 (S4 P10b review): so in the dated paragraphs below, "at once" and
//! "inside `emit`" describe the executor at their dates (until P10b); today each arm runs in
//! `App::apply`, called by `App::drain`, and an answer goes back from the drain.
//!
//! 2026-11-18 (S3 B3): created with `Effect::Render` (the body of `Wallet::refresh` after the dApp
//! state sync). S3 B4: the send forms' one-shot timer (`StartTimer`/`StopTimer`, was
//! `App::arm_send_timer`'s and `App::on_send_timer`'s own `set_timer`/`kill_timer`) and the plain
//! copy (`CopyText`, was `App::copy`'s `clipboard::set_text`). S3 B5: `Render` reads the plain
//! edits back into the form state. The field writes get their arms when their callers convert
//! (C); nothing emits them before. S3 C3: `SetField` (the AI section's `빠른 입력`) and
//! `ClearCred` (the AI key after `키 저장`). S3 C4: `ClearField` (the address book's form).
//!
//! 2026-11-19 (S4 B5): `Approval`, the approval window's open, close, rebuilt view and bottom-bar
//! repaint (`app_approval.rs` `apply_approval_effect`: the code `open_approval`,
//! `close_approval_window`, `rebuild_view_with` and `interaction()` ran inline before). The open
//! is answered at once with `Cmd::ApprovalOpened`. Tests record no shell-call line for it (the
//! census recorder is unchanged: before B5 these steps recorded none either).
//!
//! 2026-11-20 (S4 P3): `OpenUrl` (the explorer link's launch, was in `App::open_explorer`;
//! answered at once with `Cmd::Opened`) and `OpenFolder` (`App::open_folder` resolves and opens
//! the folder, was called by the handlers with the path; an extension folder it does not find is
//! answered with `Cmd::FolderMissing`). Both go through the `Launcher`, which unit-test builds
//! replace with a record, also for folders (before, a folder press started `explorer.exe` in
//! every build). They apply with or without a main window, as before, and record no shell-call
//! line (none was recorded before; the census counts the launcher's record, `launch N`).
//!
//! 2026-11-20 (S4 P4): the main window's own work the handlers did themselves before:
//! `Reveal` (`App::reveal_id`, the id from `cmd_table`), `RaiseMain` (was in `App::activate`),
//! the scroll memory of a screen entry (`ScreenLeaving`/`ScreenEntered`, `OverlayClosedInPlace`,
//! `TabTop`, `ScrollMemoryClear`: `app_scroll`; were in `App::enter_screen`,
//! `close_overlay_in_place`, the tab selectors and `lock`) and `ReleaseHold` (was in
//! `App::hold_cancel`). Each arm is the code that ran at the emitting point, so the order is the
//! same; none answers or records a shell-call line (none was recorded before). The scroll arms
//! read the wallet's screen and tab while applied, exactly as that code did. 2026-11-20 (S4
//! P10a): they no longer do — the effects carry the places the logic worked out when it emitted
//! them (`left`, `at`), and the arms read only the shell's scroll offset and memory, so applying
//! one later (an outbox) gives the same result. 2026-11-21 (S4 W4): `ScrollTop` sets the offset
//! to 0 and nothing else (was `self.scroll = 0` in `App::on_book_row`, the one main-window write
//! P4 left in a handler); it records no shell-call line either.
//!
//! 2026-11-20 (S4 P7a1): `Secret`, a secret window's open (an input window:
//! `App::open_input_window`, the body of `App::open_input` before) and close
//! (`App::close_secret_window`, the body of `App::close_secret` before), in
//! `App::apply_secret_effect`. The open is answered at once with `Cmd::SecretOpened`. Neither
//! records a shell-call line (none was recorded before).
//!
//! 2026-11-20 (S4 P7b): `Secret` also opens a display window (`App::open_display_window`, the
//! window part of `App::open_display` before: the secret moves from the session into the form
//! only after the window's capture exclusion was verified, here inside `emit` where the window
//! was made before), changes an open window's form (`App::apply_form_op`, the body of
//! `App::with_form` before) and clears a pending secret copy (`App::clear_secret_clip`/
//! `clear_secret_clip_at_exit`, called by `App::lock` before). `AwaitKeyLock` is the lock's
//! `Suspend` wait for the key worker (was in `App::lock`; critique A-2). None records a
//! shell-call line (none was recorded before).
//!
//! 2026-11-21 (S4 W2, plan §3.3–§3.4 D-4): `App` is the wallet (`app::Wallet`) and the shell's
//! fields, and this executor writes no wallet state (source check
//! `the_executor_writes_no_wallet_state`): the form state's read-backs are answers, `Cmd::Form`
//! after `Render` and `Cmd::FieldShown` after `SetField`/`ClearField` (the drain hands them to
//! the logic at once; before, the arms wrote the form state themselves at the same point), and
//! the one exception left is the clip-clear notices of `clear_secret_clip` (spec/04 §4.8). A
//! display window's open is not applied here: `App::drain` hands it to the composition
//! (`App::open_display_composed`), the one place a value moves from the wallet into the shell
//! (the secret, after the shell verified the window's capture exclusion; before, the
//! `apply_secret_effect` arm's `open_display_window` moved it). The plan's
//! `Shell::apply(effect, &Wallet)` waits for the render builders to leave `impl App` (S5).
//!
//! 2026-11-21 (S4 W3, plan §3.4): the outbox is the wallet's. `Wallet::emit` queues (the same
//! body, the form state written first for a field write) and `Wallet::next_effect` hands the
//! drain one effect at a time; `App::drain` (the composition) stays here and applies each one as
//! before. Before W3 the queue and `emit` were `App`'s (`App::emit`, `self.outbox.pop_front()`
//! in the drain).
//!
//! 2026-11-22 (S4c W15): non-test builds have no `App` → `Wallet` `DerefMut`, so the drain and
//! `App::dispatch` hand a `Cmd` to `Wallet::on_cmd` on the wallet (`self.wallet.on_cmd`; before,
//! `App::on_cmd`), and every other wallet fn the shell calls is listed with its reason in the
//! source check `the_shell_writes_wallet_state_only_through_entries`.

use yw_core::secret::Zeroizing;
use yw_engine::cmd::Cmd;
use yw_engine::effect::{Effect, Folder, RevealTarget, TimerId};
use yw_engine::secret::SecretEffect;
use yw_win::clipboard;

use crate::app::App;
use crate::logging::{self, Field};
use crate::ui::cmd_table::{self, cred_id_of, edit_id_of};

#[cfg(test)]
thread_local! {
    /// Tests (2026-11-20, S4 P6): the answer `Effect::CopyText` gets without a main window
    /// (`None`, the default: none, as headless always had). Set, the copy is answered with
    /// `Cmd::CopyDone { ok, mark }` at the point the clipboard result is answered; no clipboard is
    /// touched.
    pub(crate) static TEST_COPY_ANSWER: core::cell::Cell<Option<bool>> =
        const { core::cell::Cell::new(None) };
}

#[cfg(test)]
thread_local! {
    /// Tests (2026-11-20, S4 P10a): while `Some`, `emit` keeps each effect here instead of
    /// applying it, so a test can apply them after the handler that emitted them returned, as an
    /// outbox would ([`hold_effects`]). 2026-11-23 (S4d E0b, preflight O-4): the shell keeps
    /// them, [`App::drain`] taking them out of the wallet's outbox instead of applying them, so
    /// the wallet's `emit` holds no test hook (before, `emit` kept them, ahead of the outbox and
    /// of its `SetField` form write).
    static TEST_HELD_EFFECTS: core::cell::RefCell<Option<Vec<Effect>>> =
        const { core::cell::RefCell::new(None) };
}

/// Tests (2026-11-20, S4 P10a): runs `steps` with every effect they emit kept, not applied, and
/// returns them in emission order.
#[cfg(test)]
pub(crate) fn hold_effects(app: &mut App, steps: impl FnOnce(&mut App)) -> Vec<Effect> {
    TEST_HELD_EFFECTS.with(|held| *held.borrow_mut() = Some(Vec::new()));
    steps(app);
    // 2026-11-23 (S4d E0b): what is still queued when `steps` return is held too (the test-side
    // take from the outbox; before, `emit` never queued while a hold ran).
    app.drain();
    TEST_HELD_EFFECTS
        .with(|held| held.borrow_mut().take())
        .unwrap_or_default()
}

/// Tests (2026-11-20, S4 P10b): a borrow of the `App` that is one shell entry — the effects its
/// calls emitted are applied (and answered) when it drops, as a shell entry drains before it
/// returns. The approval and secret fixtures hand it out (`Fixture::app`), so a scenario's direct
/// calls into the logic (`tick_approval`, `on_resimulated`, a revoke, …) end as entries do; with
/// effects applied at once (before P10) the plain `RefMut` did the same. Not while panicking.
#[cfg(test)]
pub(crate) struct Entry<'a>(core::cell::RefMut<'a, App>);

#[cfg(test)]
impl<'a> Entry<'a> {
    pub(crate) const fn new(app: core::cell::RefMut<'a, App>) -> Self {
        Self(app)
    }
}

#[cfg(test)]
impl core::ops::Deref for Entry<'_> {
    type Target = App;

    fn deref(&self) -> &App {
        &self.0
    }
}

#[cfg(test)]
impl core::ops::DerefMut for Entry<'_> {
    fn deref_mut(&mut self) -> &mut App {
        &mut self.0
    }
}

#[cfg(test)]
impl Drop for Entry<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            self.0.drain();
        }
    }
}

/// The main window's timer id for `timer`, and its name in the tests' shell-call log.
const fn timer_of(timer: TimerId) -> (usize, &'static str) {
    match timer {
        TimerId::SendCheck => (yw_engine::wallet::app_evm::SEND_TIMER_ID, "send"),
    }
}

impl App {
    /// The shell's half of `Effect::OpenFolder` (2026-11-20, S4 P3; was `App::open_folder(path)`
    /// in `app.rs`, called by the handlers with the path they resolved): the folder's path (the
    /// data and log folders of `paths`, the extension folder of `app_extension::extension_dir`),
    /// started in File Explorer through the launcher (unit-test builds record it) and the
    /// `folder.open` log line, as before. An extension folder that is not found starts and logs
    /// nothing here and is answered with `Cmd::FolderMissing` (the handler's band, as before).
    fn open_folder(&mut self, folder: Folder) -> Option<Cmd> {
        let path = match folder {
            Folder::Data => self.paths.data.clone(),
            Folder::Logs => self.paths.logs.clone(),
            Folder::Extension => match crate::app_extension::extension_dir() {
                Some(dir) => dir,
                None => return Some(Cmd::FolderMissing),
            },
        };
        let started = self.launcher.open_folder(&path);
        logging::info(
            "app",
            "folder.open",
            &[("ok", Field::Word(if started { "yes" } else { "no" }))],
        );
        None
    }

    /// Applies every queued effect in order, each answer going back to the logic at once
    /// (`on_cmd`; what it emits joins the end of the queue), until the queue is empty
    /// (2026-11-20, S4 P10b). Called by every shell entry before it returns (module doc), also by
    /// `main.rs` after each of its start steps. 2026-11-21 (S4 W3, plan §3.4): the queue is the
    /// wallet's; each effect is taken from it on its own ([`Wallet::next_effect`]), so the
    /// wallet is free again before the effect is applied and its answer handled (an answer's
    /// effects join the same queue; before W3, `self.outbox.pop_front()` on `App`'s queue).
    /// Debug builds then check that the wallet's form state and main-window mirror equal the
    /// window (2026-11-21, S4 W3, critique B-10/B-11).
    ///
    /// # Panics
    ///
    /// Debug builds only: never for the queue (the loop ends with it empty); when the wallet's
    /// main-window mirror differs from the window ([`App::assert_main_hidden_in_step`]).
    pub fn drain(&mut self) {
        // Debug builds (2026-11-21, S4 W3, critique B-11): the credential edits the logic took
        // since the last drain, before any effect is applied.
        #[cfg(debug_assertions)]
        self.cred_check();
        // Tests (2026-11-23, S4d E0b): held for `hold_effects`, in emission order, not applied.
        #[cfg(test)]
        if TEST_HELD_EFFECTS.with(|held| held.borrow().is_some()) {
            while let Some(effect) = self.wallet.next_effect() {
                TEST_HELD_EFFECTS.with(|held| {
                    if let Some(kept) = held.borrow_mut().as_mut() {
                        kept.push(effect);
                    }
                });
            }
            return;
        }
        while let Some(effect) = self.wallet.next_effect() {
            // 2026-11-21 (S4 W2, plan §3.4, D-4): the composition. A display window's open is the
            // one effect that moves a value from the wallet into the shell (the secret), so it
            // is not the executor's: `open_display_composed` has the shell make and verify the
            // window, moves the secret in only then, and answers. Every other effect is the
            // executor's (`apply`), which writes no wallet state (source check
            // `the_executor_writes_no_wallet_state`). Before W2 the executor's display arm
            // moved the secret itself (`open_display_window`), at the same point.
            let answer = match effect {
                Effect::Secret(SecretEffect::OpenDisplay {
                    serial,
                    kind,
                    step,
                    timeout_note,
                    lang,
                }) => Some(self.open_display_composed(serial, kind, step, timeout_note, lang)),
                effect => self.apply(effect),
            };
            // Tests: the logic's steps logged behind this effect are logged now.
            #[cfg(test)]
            crate::app::secret_seam::applied();
            // 2026-11-21 (S4 W3, critique B-10): an effect that changed the main window's
            // hidden state (`RaiseMain` shows it; a secret or approval window's close asks for
            // its foreground, which can show a hidden one) — the wallet's mirror follows at once,
            // before the effect's answer; the window's own `WM_SIZE` came inside this borrow and
            // was dropped. Before W3 the wallet read the window when it needed to.
            if let Some(hidden) = self.main_hidden_answer() {
                self.wallet.on_cmd(hidden);
            }
            if let Some(answer) = answer {
                self.wallet.on_cmd(answer);
            }
        }
        debug_assert!(self.queued_effects() == 0, "the outbox drained");
        // Tests (2026-11-20, S4 P10b review): the approval flow and its window are in step again
        // once the queue is empty, so an open's and a close's pairing is checked here (the checks
        // where the flow changes skip while its `Approval(Open)`/`Approval(Close)` is queued).
        #[cfg(test)]
        self.assert_flow_and_window_in_step();
        // Debug builds (2026-11-21, S4 W3, critique B-10/B-11): with the queue empty the wallet
        // is in step with the window again — its form state equals the plain edits (the shadow
        // read of `App::form_text` before W3, now the shell's) and its main-window mirror equals
        // the window.
        #[cfg(debug_assertions)]
        {
            self.check_form_in_step();
            self.assert_main_hidden_in_step();
        }
    }

    /// One input from the shell, then the effects it emitted (2026-11-20, S4 P10b, plan §3.4:
    /// `App::dispatch`): the shell's way to send a `Cmd`. An answer is not sent this way: the
    /// drain that applied its effect hands it to `on_cmd`. 2026-11-22 (S4c W15): the wallet's
    /// `Wallet::on_cmd`, named on the wallet (non-test builds have no `DerefMut`).
    pub(crate) fn dispatch(&mut self, cmd: Cmd) {
        self.wallet.on_cmd(cmd);
        self.drain();
    }

    /// Debug builds: a shell entry starts with an empty outbox (2026-11-20, S4 P10b, critique
    /// A-14): an entry that returned without draining is found at the next one (the windows'
    /// `Forward`s, the event drain and `main.rs`'s loop observer check it).
    ///
    /// # Panics
    ///
    /// Debug builds: when an effect is queued.
    pub fn assert_outbox_empty(&self) {
        debug_assert!(
            self.queued_effects() == 0,
            "an entry returned with {} effect(s) queued",
            self.queued_effects()
        );
    }

    /// Applies `effect` now and returns its answer, if it has one (see the module doc; 2026-11-20,
    /// S4 P10b: the body of `emit` before, which handed the answer to `on_cmd` itself). Tests
    /// record each effect in the shell-call log before the window check, so headless tests see
    /// it too.
    #[expect(clippy::too_many_lines, reason = "one arm per effect")]
    fn apply(&mut self, effect: Effect) -> Option<Cmd> {
        match effect {
            Effect::Render => {
                #[cfg(test)]
                self.controls.record("refresh".to_owned());
                self.render_main();
                // S3 B5 (Windows-transitional): the layout may have created edits again (from
                // their model text) or kept the one being typed in, so the form state is read
                // back from the window. Headless (no window) nothing was laid out.
                // 2026-11-21 (S4 W2, plan §3.4, D-4): answered as `Cmd::Form`, which the drain
                // hands to the logic at once (it replaces the form state, nothing else); before,
                // this arm replaced the form state itself, at the same point.
                self.main
                    .is_some()
                    .then(|| Cmd::Form(self.controls.form_snapshot()))
            }
            Effect::StartTimer { timer, ms } => {
                #[cfg(test)]
                self.controls
                    .record(format!("timer.start {} {ms}", timer_of(timer).1));
                if let Some(main) = self.main.as_ref() {
                    let _ =
                        main.set_timer(timer_of(timer).0, u32::try_from(ms).unwrap_or(u32::MAX));
                }
                None
            }
            Effect::StopTimer { timer } => {
                #[cfg(test)]
                self.controls
                    .record(format!("timer.stop {}", timer_of(timer).1));
                if let Some(main) = self.main.as_ref() {
                    main.kill_timer(timer_of(timer).0);
                }
                None
            }
            Effect::CopyText { text, mark } => {
                // Tests: the length only, in `char`s (`text.chars().count()`, not UTF-16 units as
                // the `set_text` line counts); a text that `Path::new(text).is_absolute()` holds
                // (`경로 복사`, machine-dependent) is `len=<path>` (the A1 recorder's two rules).
                #[cfg(test)]
                self.controls
                    .record(if std::path::Path::new(&text).is_absolute() {
                        format!("copy len=<path> address={}", mark.address)
                    } else {
                        format!("copy len={} address={}", text.chars().count(), mark.address)
                    });
                // Headless (no main window): no clipboard and no result, as before.
                #[cfg(test)]
                if let Some(ok) = TEST_COPY_ANSWER.with(core::cell::Cell::get) {
                    return Some(Cmd::CopyDone { ok, mark });
                }
                let main = self.main.as_ref()?;
                let ok = clipboard::set_text(main, &text).is_ok();
                Some(Cmd::CopyDone { ok, mark })
            }
            Effect::SetField { field, text } => {
                // The edit's `EN_CHANGE` arrives inside this borrow and is not seen (as before,
                // spec/01 §7.7); the form state reads the edit back (headless: the edit keeps
                // what a test typed, as `ControlSet::set_text` writes no window there).
                // 2026-11-20 (S4 P10b, O-10): `emit` already put the text into the form state;
                // the read-back keeps it equal to what the edit holds, as before.
                // 2026-11-21 (S4 W2, D-4): the read-back is answered as `Cmd::FieldShown`, which
                // the drain hands to the logic at once (it sets that one field of the form state,
                // nothing else); before, this arm set it itself, at the same point.
                let id = edit_id_of(field);
                self.controls.set_text(id, &text);
                Some(Cmd::FieldShown {
                    field,
                    text: self.controls.text(id, field.cap()).map(Zeroizing::new),
                })
            }
            // A credential edit is emptied after its one read; it is never form state.
            Effect::ClearCred { field } => {
                self.controls.clear_text(cred_id_of(field));
                None
            }
            // S3 C4 (the address book's clears): emptied now, before the handler's next
            // `refresh()` (`keeps_edit` reads the edit), and read back into the form state
            // (headless: `ControlSet::clear_text` drops what a test typed, so the field is gone
            // there as from the edit). (2026-11-18, S3 C1–C3 review: before C4 debug builds
            // counted a `ClearField` as a form mismatch, as nothing could emit one yet.)
            // 2026-11-21 (S4 W2, D-4): answered as `Cmd::FieldShown`, as `SetField` is.
            Effect::ClearField { field } => {
                let id = edit_id_of(field);
                self.controls.clear_text(id);
                Some(Cmd::FieldShown {
                    field,
                    text: self.controls.text(id, field.cap()).map(Zeroizing::new),
                })
            }
            // S4 B5: the approval window; an open is answered (2026-11-20, S4 P10b: by the drain).
            Effect::Approval(effect) => self.apply_approval_effect(effect),
            // S4 P3: the browser is started now and its result answered.
            Effect::OpenUrl { url, which } => {
                let ok = self.launcher.launch(&url);
                Some(Cmd::Opened { ok, which })
            }
            // S4 P3: the folder is opened now; a missing extension folder is answered.
            Effect::OpenFolder(folder) => self.open_folder(folder),
            // S4 P4: the main window's own work (module doc).
            Effect::Reveal(target) => {
                self.reveal_id(match target {
                    RevealTarget::Press(press) => cmd_table::id_of(press),
                    RevealTarget::Cred(field) => cred_id_of(field),
                });
                None
            }
            Effect::RaiseMain => {
                self.raise_main();
                None
            }
            Effect::ScreenLeaving {
                overlay_opens,
                left,
            } => {
                self.screen_leaving(overlay_opens, left);
                None
            }
            Effect::ScreenEntered { at } => {
                self.screen_entered(at);
                None
            }
            Effect::OverlayClosedInPlace => {
                self.overlay_closed_in_place();
                None
            }
            Effect::TabTop { left } => {
                self.tab_top(left);
                None
            }
            Effect::ScrollMemoryClear => {
                self.scroll_memory.clear();
                None
            }
            // 2026-11-21 (S4 W4): the offset only, as `App::on_book_row` set it before (no
            // glide stop, no memory change); the `Render` the handler queued after it lays out.
            Effect::ScrollTop => {
                self.scroll = 0;
                None
            }
            Effect::ReleaseHold => {
                if let Some(main) = self.main.as_ref() {
                    main.release_capture();
                }
                // 2026-11-21 (S4 W1): the held area is the shell's now; the hold ended.
                self.reset_hold = None;
                None
            }
            // S4 P7a1: a secret window; an open is answered.
            Effect::Secret(effect) => {
                let answer = self.apply_secret_effect(effect);
                // 2026-11-20 (S4 P8 review): the recording secret host notes the answer's
                // `Debug` too (its scan for secrets); release builds have no such line.
                #[cfg(test)]
                if let Some(answer) = answer.as_ref() {
                    crate::app::tests::s4_secret::host::saw_cmd(answer);
                }
                answer
            }
            // S4 P7b (critique A-2): the lock's wait for the key worker, in its place in the
            // queue (after the lock's secret close, clip clear and approval close).
            Effect::AwaitKeyLock { before, ms } => {
                #[cfg(test)]
                crate::app::secret_seam::log(crate::app::secret_seam::Op::Wait {
                    what: "lock",
                    ms,
                });
                let _ = self
                    .lock_signal
                    .wait_beyond(before, core::time::Duration::from_millis(ms));
                None
            }
        }
    }
}
