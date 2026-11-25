//! The wallet's half of the Android wire (spec/15 §3.2, §18 8; 2026-11-25 A2-6): the model a
//! shell draws ([`Wallet::draw`]) and the inputs resolved against it ([`Wallet::on_input`]). The
//! rules are `crate::wire`'s module doc. Windows draws through [`Wallet::screen`] and its control
//! ids, never through these.

use yw_core::secret::Zeroizing;

use crate::cmd::{Cmd, Press};
use crate::effect::Effect;
use crate::form::PressInput;
use crate::screen::facts::ScreenFacts;
use crate::screen::model::{Act, CtlKind};
use crate::wallet::Wallet;
use crate::wire::{self, Drawn, EditSync, Input, InputOutcome};

impl Wallet {
    /// Builds the current screen ([`Wallet::screen`], which also keeps the plan of the plain
    /// edits that `Cmd::Rendered` takes), records it as the next revision and returns it on the
    /// wire (`crate::wire::model`). The shell sends it to be drawn and answers with
    /// `Input::Rendered` of that revision; inputs of any other revision are dropped from now on.
    pub fn draw(&mut self, facts: &dyn ScreenFacts) -> Vec<u8> {
        let items = self.screen(facts);
        self.wire.rev = self.wire.rev.saturating_add(1);
        let drawn = Drawn::new(self.wire.rev, items);
        let bytes = drawn.encode(self.settings.language);
        self.wire.previous = self.wire.drawn.replace(drawn);
        self.wire.seen.clear();
        self.wire.sync = None;
        bytes
    }

    /// What the drawn model's plain edits must show, once after the shell answered its render
    /// (`crate::wire` module doc, 2026-11-25 A2-6 review): every drawn plain edit whose text in the
    /// form state differs from its model text, and the slot the field that had the focus is drawn
    /// at now. `None` when no render was answered since, or a newer model is drawn or queued.
    pub fn take_edit_sync(&mut self) -> Option<EditSync> {
        let (rev, focus) = self.wire.sync.take()?;
        let drawn = self.current_slot(rev)?;
        let mut fields = Vec::new();
        let mut focus_slot = None;
        let mut slot = 0_u32;
        wire::for_each_ctl(drawn.items(), &mut |_, ctl| {
            let at = slot;
            slot = slot.saturating_add(1);
            let (Act::Field(field), CtlKind::Edit { .. }) = (ctl.act, ctl.kind) else {
                return;
            };
            if !wire::field_on_wire(field) {
                return;
            }
            let shown = self.form.text(field).unwrap_or("");
            if shown != ctl.text {
                fields.push((at, Zeroizing::new(shown.to_owned())));
            }
            if focus == Some(field)
                && focus_slot.is_none()
                && drawn.slot(at).is_some_and(wire::takes_edit)
            {
                focus_slot = Some(at);
            }
        });
        Some(EditSync {
            rev,
            fields,
            focus: focus_slot,
        })
    }

    /// How many edits of `slot` of the drawn model the engine took since the shell answered its
    /// render (`crate::wire` module doc): a field write carries it, and the shell applies the
    /// write only when it sent no more edits of that slot since.
    #[must_use]
    pub fn edits_seen(&self, slot: u32) -> u64 {
        self.wire.seen.get(&slot).copied().unwrap_or(0)
    }

    /// The model [`Self::draw`] handed out last (`None`: none yet). The shell finds the slots of
    /// a field write or a reveal in it.
    #[must_use]
    pub const fn drawn(&self) -> Option<&Drawn> {
        self.wire.drawn.as_ref()
    }

    /// One input from the shell, resolved against the model drawn last (`crate::wire` module
    /// doc): a press or an edit reaches the logic as the `Cmd` of the control drawn at its slot,
    /// a render's answer as `Cmd::Rendered` with the focused field (and the edit texts to hand
    /// back, [`Self::take_edit_sync`]), a timer as `Cmd::Timer`, the lifetime events as
    /// `Cmd::MainHidden`. `facts` are the shell's, for the rebuild that checks a pressed control's
    /// item.
    pub fn on_input(&mut self, input: Input, facts: &dyn ScreenFacts) -> InputOutcome {
        match input {
            Input::Press { rev, slot } => self.wire_press(rev, slot, facts),
            Input::Edit { rev, slot, text } => {
                let Some(field) = self.current_slot(rev).map(|drawn| {
                    drawn
                        .slot(slot)
                        .filter(|info| wire::takes_edit(info))
                        .and_then(|info| match info.act {
                            Act::Field(field) => Some(field),
                            Act::Press(_) | Act::Cred(_) => None,
                        })
                }) else {
                    return InputOutcome::Stale;
                };
                let Some(field) = field else {
                    return InputOutcome::Refused;
                };
                let seen = self.wire.seen.entry(slot).or_insert(0);
                *seen = seen.saturating_add(1);
                self.on_cmd(Cmd::Edit { field, text });
                InputOutcome::Done
            }
            Input::Rendered { rev, focus } => {
                // The answer of the model just drawn: a newer one queued makes it no answer.
                if self
                    .wire
                    .drawn
                    .as_ref()
                    .is_none_or(|drawn| drawn.rev() != rev)
                {
                    return InputOutcome::Stale;
                }
                // The focused edit, in the model the shell showed before it drew this one.
                let focus = focus
                    .and_then(|(of, slot)| {
                        [self.wire.drawn.as_ref(), self.wire.previous.as_ref()]
                            .into_iter()
                            .flatten()
                            .find(|drawn| drawn.rev() == of)?
                            .slot(slot)
                    })
                    .and_then(|info| match info.act {
                        Act::Field(field) => Some(field),
                        Act::Press(_) | Act::Cred(_) => None,
                    });
                // The shell drew this model with its model texts and counts its edits from here
                // (`crate::wire` module doc): so does the engine, and it hands the texts back.
                self.wire.seen.clear();
                self.wire.sync = Some((rev, focus));
                self.on_cmd(Cmd::Rendered { focus });
                InputOutcome::Done
            }
            Input::Life(life) => {
                self.on_cmd(Cmd::MainHidden(life != wire::Life::Front));
                InputOutcome::Life(life)
            }
            Input::Timer(timer) => {
                self.on_cmd(Cmd::Timer(timer));
                InputOutcome::Done
            }
            // The shell's: a copy answer (it keeps the mark), and the main timer, whose parts it sends
            // one by one, each an entry with its drain, as the Windows timer does
            // (`crate::wire::TICK_PARTS`).
            Input::Copied { .. } | Input::Tick => InputOutcome::NotMine,
        }
    }

    /// The model drawn last when it is revision `rev` and no newer one is queued (an
    /// `Effect::Render` the shell has not taken yet); `None` otherwise.
    fn current_slot(&self, rev: u64) -> Option<&Drawn> {
        let queued = self
            .outbox
            .iter()
            .any(|effect| matches!(effect, Effect::Render));
        self.wire
            .drawn
            .as_ref()
            .filter(|drawn| drawn.rev() == rev && !queued)
    }

    /// `Input::Press`: the drawn control's press, if it takes one and its item is built the same
    /// now; a check box's press carries the state the click leaves it in (the drawn state turned
    /// over).
    fn wire_press(&mut self, rev: u64, slot: u32, facts: &dyn ScreenFacts) -> InputOutcome {
        let Some(drawn) = self.current_slot(rev) else {
            return InputOutcome::Stale;
        };
        let Some(info) = drawn
            .slot(slot)
            .filter(|info| wire::takes_press(info))
            .cloned()
        else {
            return InputOutcome::Refused;
        };
        let Act::Press(press) = info.act else {
            return InputOutcome::Refused;
        };
        // Built from the state now, never recorded (`Wallet::screen` would replace the plan the
        // shell's next `Rendered` answers).
        let mut now = crate::screen::build::Screen::new(self, facts).screen_model();
        if !wire::item_unchanged(drawn, &info, &mut now) {
            self.refresh();
            return InputOutcome::Changed;
        }
        let press: Press = match info.kind {
            CtlKind::Check => press.with_check(Some(!info.checked.unwrap_or(false))),
            CtlKind::Button(_) | CtlKind::Radio { .. } | CtlKind::Edit { .. } => press,
        };
        self.on_cmd(Cmd::Press {
            press,
            input: PressInput::default(),
        });
        InputOutcome::Done
    }
}
