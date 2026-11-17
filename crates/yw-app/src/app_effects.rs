//! The Windows shell's effect executor (spec/15 §11.2, §11.4 S3): applies one
//! [`yw_engine::effect::Effect`] the wallet logic emitted.
//!
//! An effect is applied at once, inside the `App` borrow of the handler that emitted it, in
//! emission order, and never coalesced: the `EN_CHANGE` a field write causes and any activation
//! stay unseen exactly as before (re-entrancy, spec/01 §7.7), and a screen is laid out as often as
//! before. Nothing here posts a message or defers work past the borrow; an outbox, if S4 adds one,
//! must drain inside the same borrow.
//!
//! 2026-11-18 (S3 B3): created with `Effect::Render` (the body of `App::refresh` after the dApp
//! state sync). The other effects get their arms when their callers convert (B4: timer and copy;
//! B5 and C: field writes); nothing emits them before.

use yw_engine::effect::Effect;

use crate::app::App;

impl App {
    /// Applies `effect` now (see the module doc).
    #[expect(
        clippy::needless_pass_by_value,
        reason = "until S3 B4 no arm consumes a payload (the copy text)"
    )]
    pub(crate) fn emit(&mut self, effect: Effect) {
        match effect {
            Effect::Render => {
                // Recorded before the window check, as `refresh` did: headless tests see it too.
                #[cfg(test)]
                self.controls.record("refresh".to_owned());
                self.render_main();
            }
            // Not emitted before S3 B4 (timer, copy) and B5/C (field writes).
            Effect::SetField { .. }
            | Effect::ClearField { .. }
            | Effect::ClearCred { .. }
            | Effect::StartTimer { .. }
            | Effect::StopTimer { .. }
            | Effect::CopyText { .. } => {}
        }
    }
}
