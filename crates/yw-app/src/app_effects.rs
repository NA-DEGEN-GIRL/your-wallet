//! The Windows shell's effect executor (spec/15 §11.2, §11.4 S3): applies one
//! [`yw_engine::effect::Effect`] the wallet logic emitted.
//!
//! An effect is applied at once, inside the `App` borrow of the handler that emitted it, in
//! emission order, and never coalesced: the `EN_CHANGE` a field write causes and any activation
//! stay unseen exactly as before (re-entrancy, spec/01 §7.7), and a screen is laid out as often as
//! before. Nothing here posts a message or defers work past the borrow; an outbox, if S4 adds one,
//! must drain inside the same borrow. A result goes back to the logic as a `Cmd` before `emit`
//! returns (`Cmd::CopyDone`).
//!
//! 2026-11-18 (S3 B3): created with `Effect::Render` (the body of `App::refresh` after the dApp
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
//! read the wallet's screen and tab while applied, exactly as that code did.
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

use yw_core::secret::Zeroizing;
use yw_engine::cmd::Cmd;
use yw_engine::effect::{Effect, Folder, RevealTarget, TimerId};
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

/// The main window's timer id for `timer`, and its name in the tests' shell-call log.
const fn timer_of(timer: TimerId) -> (usize, &'static str) {
    match timer {
        TimerId::SendCheck => (crate::app_evm::SEND_TIMER_ID, "send"),
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
        let started = self.explorer_ui.launcher.open_folder(&path);
        logging::info(
            "app",
            "folder.open",
            &[("ok", Field::Word(if started { "yes" } else { "no" }))],
        );
        None
    }

    /// Applies `effect` now (see the module doc). Tests record each effect in the shell-call log
    /// before the window check, so headless tests see it too.
    #[expect(clippy::too_many_lines, reason = "one arm per effect")]
    pub(crate) fn emit(&mut self, effect: Effect) {
        match effect {
            Effect::Render => {
                #[cfg(test)]
                self.controls.record("refresh".to_owned());
                self.render_main();
                // S3 B5 (Windows-transitional): the layout may have created edits again (from
                // their model text) or kept the one being typed in, so the form state is read
                // back from the window. Headless (no window) nothing was laid out.
                if self.main.is_some() {
                    self.form.replace(self.controls.form_snapshot());
                }
            }
            Effect::StartTimer { timer, ms } => {
                #[cfg(test)]
                self.controls
                    .record(format!("timer.start {} {ms}", timer_of(timer).1));
                if let Some(main) = self.main.as_ref() {
                    let _ =
                        main.set_timer(timer_of(timer).0, u32::try_from(ms).unwrap_or(u32::MAX));
                }
            }
            Effect::StopTimer { timer } => {
                #[cfg(test)]
                self.controls
                    .record(format!("timer.stop {}", timer_of(timer).1));
                if let Some(main) = self.main.as_ref() {
                    main.kill_timer(timer_of(timer).0);
                }
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
                    self.on_cmd(Cmd::CopyDone { ok, mark });
                    return;
                }
                if let Some(main) = self.main.as_ref() {
                    let ok = clipboard::set_text(main, &text).is_ok();
                    self.on_cmd(Cmd::CopyDone { ok, mark });
                }
            }
            Effect::SetField { field, text } => {
                // The edit's `EN_CHANGE` arrives inside this borrow and is not seen (as before,
                // spec/01 §7.7); the form state reads the edit back (headless: the edit keeps
                // what a test typed, as `ControlSet::set_text` writes no window there).
                let id = edit_id_of(field);
                self.controls.set_text(id, &text);
                self.form.set(
                    field,
                    self.controls.text(id, field.cap()).map(Zeroizing::new),
                );
            }
            // A credential edit is emptied after its one read; it is never form state.
            Effect::ClearCred { field } => self.controls.clear_text(cred_id_of(field)),
            // S3 C4 (the address book's clears): emptied now, before the handler's next
            // `refresh()` (`keeps_edit` reads the edit), and read back into the form state
            // (headless: `ControlSet::clear_text` drops what a test typed, so the field is gone
            // there as from the edit). (2026-11-18, S3 C1–C3 review: before C4 debug builds
            // counted a `ClearField` as a form mismatch, as nothing could emit one yet.)
            Effect::ClearField { field } => {
                let id = edit_id_of(field);
                self.controls.clear_text(id);
                self.form.set(
                    field,
                    self.controls.text(id, field.cap()).map(Zeroizing::new),
                );
            }
            // S4 B5: the approval window; an open is answered before `emit` returns.
            Effect::Approval(effect) => {
                if let Some(answer) = self.apply_approval_effect(effect) {
                    self.on_cmd(answer);
                }
            }
            // S4 P3: the browser is started now and its result answered before `emit` returns.
            Effect::OpenUrl { url, which } => {
                let ok = self.explorer_ui.launcher.launch(&url);
                self.on_cmd(Cmd::Opened { ok, which });
            }
            // S4 P3: the folder is opened now; a missing extension folder is answered at once.
            Effect::OpenFolder(folder) => {
                if let Some(answer) = self.open_folder(folder) {
                    self.on_cmd(answer);
                }
            }
            // S4 P4: the main window's own work, at the emitting point (module doc).
            Effect::Reveal(target) => self.reveal_id(match target {
                RevealTarget::Press(press) => cmd_table::id_of(press),
                RevealTarget::Cred(field) => cred_id_of(field),
            }),
            Effect::RaiseMain => self.raise_main(),
            Effect::ScreenLeaving {
                overlay_opens,
                changes,
            } => self.screen_leaving(overlay_opens, changes),
            Effect::ScreenEntered { back, overlay } => self.screen_entered(back, overlay),
            Effect::OverlayClosedInPlace => self.overlay_closed_in_place(),
            Effect::TabTop => self.tab_top(),
            Effect::ScrollMemoryClear => self.scroll_memory.clear(),
            Effect::ReleaseHold => {
                if let Some(main) = self.main.as_ref() {
                    main.release_capture();
                }
            }
            // S4 P7a1: a secret window; an open is answered before `emit` returns.
            Effect::Secret(effect) => {
                if let Some(answer) = self.apply_secret_effect(effect) {
                    self.on_cmd(answer);
                }
            }
            // S4 P7b (critique A-2): the lock's wait for the key worker, at the emitting point.
            Effect::AwaitKeyLock { before, ms } => {
                #[cfg(test)]
                crate::app::secret_seam::log(crate::app::secret_seam::Op::Wait {
                    what: "lock",
                    ms,
                });
                let _ = self
                    .lock_signal
                    .wait_beyond(before, core::time::Duration::from_millis(ms));
            }
        }
    }
}
