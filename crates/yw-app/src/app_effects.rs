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

use yw_core::secret::Zeroizing;
use yw_engine::cmd::Cmd;
use yw_engine::effect::{Effect, TimerId};
use yw_win::clipboard;

use crate::app::App;
use crate::ui::cmd_table::{cred_id_of, edit_id_of};

/// The main window's timer id for `timer`, and its name in the tests' shell-call log.
const fn timer_of(timer: TimerId) -> (usize, &'static str) {
    match timer {
        TimerId::SendCheck => (crate::app_evm::SEND_TIMER_ID, "send"),
    }
}

impl App {
    /// Applies `effect` now (see the module doc). Tests record each effect in the shell-call log
    /// before the window check, so headless tests see it too.
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
        }
    }
}
