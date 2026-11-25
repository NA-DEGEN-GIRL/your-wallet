//! The Android shell's half of the screen (spec/15 §3.2, §11.3, §18 8; 2026-11-25 A2-6): it holds
//! the [`Wallet`], hands each input `call` brings to [`Wallet::on_input`], and turns the effects
//! the wallet queued into the frames Java draws or applies (`next`, frame kind
//! [`crate::io_request::FRAME_UI`]): the screen model, a field write, a reveal, the scroll to
//! the top, a one-shot timer, a copy. The effects Java has no part in are answered here, after
//! the batch, each answer an entry of its own (the deferred schedule of spec/15 §3.2, yw-engine
//! `testkit::Schedule::Deferred`): an approval window cannot open yet (A3), a link is not opened
//! (no browser and no network in A2). 2026-11-25 A2-7: a secret window is no longer refused here:
//! its effects go to the secret host (`crate::secret_host`, the two-phase open of spec/15 §9.1),
//! whose answer (`Cmd::SecretOpened`) comes when Java's secure window is ready, and the window's
//! inputs (`crate::secret_wire`, tried before the engine's), keys (`secretKey`) and fills
//! (`secretFill`) reach it here. Before A2-7 every secret open was answered `Refused(E-SEC-001)`.
//!
//! Frames (yw-json, UTF-8): the model (yw-engine `wire::model`), and
//!
//! - `{"t":"field","rev":R,"slot":S,"text":"…","seen":N}`: a plain edit of model `R` now shows
//!   `text` (one frame per slot the field is drawn at; none when it is not drawn), unless Java has
//!   sent more than `N` edits of that slot since it drew `R` (yw-engine `Wallet::edits_seen`: the
//!   engine takes those after the write, so the edit already shows the engine's text). 2026-11-25
//!   A2-6 review: after Java answers a render, the engine's text of every drawn plain edit that
//!   differs from its model text comes as such a frame, and the field that had the focus as a
//!   `reveal` (`Wallet::take_edit_sync`): Java draws the model's texts and keeps none of its own,
//!   so what an edit shows is always the engine's form state, which a press reads; before, Java
//!   kept the focused edit's typed text by a rule of its own, which could differ;
//! - `{"t":"reveal","rev":R,"slot":S}`: scroll that control into view and focus it;
//! - `{"t":"top"}`: the screen opens at its top (a screen entry; A2 keeps no scroll memory);
//! - `{"t":"timer","id":"send_check","ms":N}`, `{"t":"stop_timer","id":"send_check"}`;
//! - `{"t":"copy","id":N,"text":"…"}`: non-secret text (an address, a hash) for the clipboard,
//!   answered with the input `{"t":"copied","id":N,"ok":B}`. The shell keeps the copy's mark by
//!   id; an id it does not know is dropped.
//!
//! No frame carries a secret (spec/15 §3.1): the model has none (a credential edit's text is never
//! in it, and the `WalletConnect` pairing link, a plain field that carries the pairing `symKey`,
//! is drawn like one, yw-engine `wire::field_on_wire`), a field write is a plain field's and never
//! that link's, a copy is `Effect::CopyText`'s non-secret text. 2026-11-25 A2-6 review: before,
//! the pairing link's text would have gone in the model and its field writes (no A2 screen draws
//! it: no network, `walletconnect: None`).
//!
//! A full UI queue (`crate::io_request::IoBroker::post_ui`) that cannot make room drops every
//! waiting frame; the poster then sends [`UiHost::resync`]: a fresh model (whose render answer
//! hands back the edit texts), the one-shot timers still running, and a failed answer for every
//! copy Java has not answered (its frame may be lost; a late answer is dropped); 2026-11-25 A2-7
//! review: first the secret windows' `s_keep` (`crate::secret_host::SecretHost::resync`), so a
//! secret window whose `s_close` was dropped closes. Platform-neutral:
//! the gate's Windows build tests it.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use yw_core::lang::Lang;
use yw_core::secret::Zeroizing;
use yw_engine::approval::flow::{ApprovalEffect, OpenOutcome};
use yw_engine::cmd::{Cmd, CopyMark};
use yw_engine::effect::{Effect, Folder, RevealTarget, TimerId};
use yw_engine::errors::ErrorCode;
use yw_engine::protection::Surface;
use yw_engine::screen::facts::{PipeStatus, PlatformFlags, ScreenFacts};
use yw_engine::screen::model::Act;
use yw_engine::secret::SecretEffect;
use yw_engine::wallet::Wallet;
use yw_engine::wallet::secret_session::SecretAction;
use yw_engine::wire::{self, Input, InputOutcome, Life, WireError};
use yw_json::{Number, Object, Value};

use crate::io_request::UiKind;
use crate::secret_host::{Reply, SecretHost, Shape};
use crate::{device, secret_keys, secret_wire};

/// What the Android build offers (spec/15 §11.3, §9.3–§9.4, §8.5): no secret copy, no word paste,
/// no `rpc.json`, no Chrome extension, no folders; the narrow-screen `seen_all` rule on.
pub const ANDROID_FLAGS: PlatformFlags = PlatformFlags {
    secret_copy: false,
    secret_word_paste: false,
    rpc_json_import: false,
    browser_extension: false,
    open_folders: false,
    seen_all: true,
};

/// The most copies waiting for their answer (older ones are forgotten: their answer is dropped).
const COPIES_MAX: usize = 16;

/// The shell facts the screens ask while they are built: answered from values held here, never
/// by calling Java (spec/15 §3.2, §11.3).
#[derive(Clone, Debug, Default)]
pub struct AndroidFacts;

impl ScreenFacts for AndroidFacts {
    /// A2 has no time-zone fact yet: the screens show UTC with its suffix.
    fn local_wall_ms(&self, _unix_ms: u64) -> Option<u64> {
        None
    }

    /// The data folder is the app's own (`no_backup/v3`); no screen of A2 shows it.
    fn data_dir(&self) -> String {
        String::new()
    }

    fn rpc_json_present(&self) -> bool {
        false
    }

    fn extension_dir(&self) -> Option<String> {
        None
    }

    fn expected_extension_dir(&self) -> Option<String> {
        None
    }

    fn pipe(&self) -> PipeStatus {
        PipeStatus {
            server: false,
            error: None,
        }
    }

    /// The version only (no words to translate: the install record is a Windows fact).
    fn version_text(&self, _lang: Lang) -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }

    fn flags(&self) -> PlatformFlags {
        ANDROID_FLAGS
    }
}

/// What the shell gives the wallet after a batch (the deferred schedule): an answer `Cmd`, or a
/// secret window's end or request (`Wallet::on_secret_action`, in-process: a submission holds
/// secrets, so it is never a `Cmd`; 2026-11-25 A2-7).
enum Answer {
    Cmd(Cmd),
    Secret(u64, SecretAction),
}

/// The wallet and what the shell keeps for it (module doc).
pub struct UiHost {
    wallet: Wallet,
    /// The secret windows (2026-11-25 A2-7).
    secret: SecretHost,
    facts: AndroidFacts,
    /// The marks of the copies Java has not answered yet, by frame id.
    copies: BTreeMap<u64, CopyMark>,
    /// The last copy frame id (ids count up from 1 and are never reused).
    last_copy: u64,
    /// The frames made since they were last taken ([`Self::take_frames`]).
    frames: Vec<Vec<u8>>,
    /// An answer was given since the screen was last drawn (see [`Self::drain`]).
    answered: bool,
    /// The one-shot timers Java runs (started, not yet stopped or fired), with their period:
    /// [`Self::resync`] sends them again.
    timers: Vec<(TimerId, u64)>,
}

impl core::fmt::Debug for UiHost {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("UiHost")
            .field("copies", &self.copies.len())
            .field("frames", &self.frames.len())
            .finish_non_exhaustive()
    }
}

impl UiHost {
    /// A host for `wallet`.
    #[must_use]
    pub const fn new(wallet: Wallet) -> Self {
        Self {
            wallet,
            secret: SecretHost::new(),
            facts: AndroidFacts,
            copies: BTreeMap::new(),
            last_copy: 0,
            frames: Vec::new(),
            answered: false,
            timers: Vec::new(),
        }
    }

    /// The wallet.
    #[must_use]
    pub const fn wallet(&self) -> &Wallet {
        &self.wallet
    }

    /// The wallet, to change.
    pub const fn wallet_mut(&mut self) -> &mut Wallet {
        &mut self.wallet
    }

    /// The first frames: the current screen, then whatever the wallet queued before.
    pub fn start(&mut self) -> Vec<Vec<u8>> {
        let first = self.wallet.draw(&self.facts);
        self.frames.push(first);
        self.drain();
        self.take_frames()
    }

    /// The frames made since they were last taken, in order.
    pub fn take_frames(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.frames)
    }

    /// One input from `call` (yw-engine `wire::decode_input`): handed to the wallet, then the
    /// effects it queued turned into frames, each call of the wallet an entry followed by its
    /// drain. A copy answer is resolved here; a tick sends the main timer's parts one by one
    /// (`wire::TICK_PARTS`, one clock reading), as the Windows timer does.
    ///
    /// # Errors
    ///
    /// [`WireError`] when the bytes are no input; nothing changes then.
    pub fn on_wire_input(
        &mut self,
        bytes: &[u8],
    ) -> Result<(InputOutcome, Vec<Vec<u8>>), WireError> {
        // 2026-11-25 A2-7: a secret window's input (`s_…`, which no engine input begins with).
        if secret_wire::is_secret_input(bytes) {
            let input = secret_wire::decode(bytes).ok_or(WireError::Shape)?;
            let now_ms = self.wallet.clock.now_ms();
            let wall_ms = self.wallet.clock.now_unix_ms();
            let mut frames = Vec::new();
            let mut reply = Reply::default();
            self.secret.take_input(
                &mut self.wallet,
                input,
                now_ms,
                |facts| device::bands_with(facts, Surface::Secret, wall_ms),
                &mut frames,
                &mut reply,
            );
            self.frames.extend(frames);
            self.answer(reply);
            return Ok((InputOutcome::Done, self.take_frames()));
        }
        let input = wire::decode_input(bytes)?;
        match input {
            Input::Copied { id, ok } => {
                // A copy's answer, like the answers of `drain`: the mark shows at once.
                if let Some(mark) = self.copies.remove(&id) {
                    self.answered = true;
                    self.wallet.on_cmd(Cmd::CopyDone { ok, mark });
                    self.drain();
                }
                Ok((InputOutcome::Done, self.take_frames()))
            }
            Input::Tick => {
                let now_ms = self.wallet.clock.now_ms();
                for part in wire::TICK_PARTS {
                    self.wallet.on_cmd(Cmd::Tick { now_ms, part });
                    self.drain();
                }
                // 2026-11-25 A2-7: the secret window's timer (its hold, time-outs, countdown) and
                // the wait of an asked one, on the same tick.
                let mut frames = Vec::new();
                let mut reply = Reply::default();
                self.secret
                    .tick(&mut self.wallet, now_ms, &mut frames, &mut reply);
                self.frames.extend(frames);
                self.answer(reply);
                Ok((InputOutcome::Done, self.take_frames()))
            }
            other => {
                if let Input::Timer(fired) = &other {
                    self.timers.retain(|(timer, _)| timer != fired);
                }
                let outcome = self.wallet.on_input(other, &self.facts);
                self.drain();
                self.edit_sync();
                Ok((outcome, self.take_frames()))
            }
        }
    }

    /// One `secretKey(field, codeUnit)` (2026-11-25 A2-7, `crate::secret_keys`): fed to the open
    /// secret window it names; a key of no open window does nothing. The frames it made.
    pub fn on_secret_key(&mut self, field: i32, code_unit: i32) -> Vec<Vec<u8>> {
        let Some(event) = secret_keys::decode_key(field, code_unit) else {
            return Vec::new();
        };
        let now_ms = self.wallet.clock.now_ms();
        let mut frames = Vec::new();
        let mut reply = Reply::default();
        self.secret.take_key(event, now_ms, &mut frames, &mut reply);
        self.frames.extend(frames);
        self.answer(reply);
        self.take_frames()
    }

    /// The units of a `secretFill` handle (2026-11-25 A2-7, `crate::secret_host::SecretHost::fill`),
    /// wiped when dropped; `None` fills nothing.
    #[must_use]
    pub fn secret_fill(&self, handle: i64) -> Option<Zeroizing<Vec<u16>>> {
        self.secret.fill(handle)
    }

    /// The secret host (tests).
    #[must_use]
    pub const fn secret(&self) -> &SecretHost {
        &self.secret
    }

    /// Gives the wallet the secret host's answers and window actions, each an entry followed by
    /// its drain (2026-11-25 A2-7).
    fn answer(&mut self, reply: Reply) {
        if reply.opened.is_empty() && reply.actions.is_empty() {
            return;
        }
        for (serial, outcome) in reply.opened {
            self.answered = true;
            self.wallet.on_cmd(Cmd::SecretOpened { serial, outcome });
            self.drain();
        }
        for (serial, action) in reply.actions {
            self.answered = true;
            self.wallet.on_secret_action(serial, action);
            self.drain();
        }
    }

    /// The screen's state again, after the UI queue dropped every waiting frame (module doc):
    /// a failed answer for every copy Java has not answered, the secret windows that may exist
    /// (2026-11-25 A2-7 review), a fresh model, and the one-shot timers still running.
    pub fn resync(&mut self) -> Vec<Vec<u8>> {
        self.frames.clear();
        for (_, mark) in core::mem::take(&mut self.copies) {
            self.wallet.on_cmd(Cmd::CopyDone { ok: false, mark });
            self.drain();
        }
        self.frames.clear();
        // 2026-11-25 A2-7: the asked or open secret window again. 2026-11-25 A2-7 review: first,
        // with `s_keep`, which Java closes every other secret window by (a dropped `s_close`, or
        // one the copies' answers above made and the clear dropped); before, after the timers,
        // and no frame closed a window whose `s_close` was lost.
        let now_ms = self.wallet.clock.now_ms();
        let secret = self.secret.resync(now_ms);
        self.frames.extend(secret);
        let model = self.wallet.draw(&self.facts);
        self.frames.push(model);
        self.drain();
        for (timer, ms) in self.timers.clone() {
            self.frames.push(timer_frame(timer, ms));
        }
        self.take_frames()
    }

    /// After Java answered a render: the field writes and the focus the engine hands back
    /// (`Wallet::take_edit_sync`, module doc).
    fn edit_sync(&mut self) {
        let Some(sync) = self.wallet.take_edit_sync() else {
            return;
        };
        for (slot, shown) in &sync.fields {
            let seen = self.wallet.edits_seen(*slot);
            self.frames.push(field_frame(sync.rev, *slot, shown, seen));
        }
        if let Some(slot) = sync.focus {
            self.frames.push(frame(vec![
                ("t", text("reveal")),
                ("rev", number(sync.rev)),
                ("slot", number(u64::from(slot))),
            ]));
        }
    }

    /// Takes every queued effect in order: a frame for each one Java applies, an answer for each
    /// one the shell answers; the answers go to the wallet after the batch, each followed by the
    /// batch it queued, until nothing is left. The frames wait for [`Self::take_frames`].
    ///
    /// An answer can change what the screen shows without queuing a redraw (a refused secret
    /// window's error band: on Windows the main window is repainted when the entry's drain ends);
    /// so when answers were given and no model was drawn after the last of them, the screen is
    /// drawn once more at the end.
    pub fn drain(&mut self) {
        let mut frames = core::mem::take(&mut self.frames);
        loop {
            let mut answers = Vec::new();
            while let Some(effect) = self.wallet.next_effect() {
                if matches!(effect, Effect::Render) {
                    self.answered = false;
                }
                self.apply(effect, &mut frames, &mut answers);
            }
            if answers.is_empty() {
                break;
            }
            self.answered = true;
            for answer in answers {
                match answer {
                    Answer::Cmd(cmd) => self.wallet.on_cmd(cmd),
                    Answer::Secret(serial, action) => self.wallet.on_secret_action(serial, action),
                }
            }
        }
        if core::mem::take(&mut self.answered) {
            frames.push(self.wallet.draw(&self.facts));
        }
        self.frames = frames;
    }

    fn apply(&mut self, effect: Effect, frames: &mut Vec<Vec<u8>>, answers: &mut Vec<Answer>) {
        match effect {
            Effect::Render => frames.push(self.wallet.draw(&self.facts)),
            Effect::SetField { field, text } => self.field_frames(Act::Field(field), &text, frames),
            Effect::ClearField { field } => self.field_frames(Act::Field(field), "", frames),
            Effect::Reveal(target) => {
                let act = match target {
                    RevealTarget::Press(press) => Act::Press(press),
                    RevealTarget::Cred(field) => Act::Cred(field),
                };
                if let Some(drawn) = self.wallet.drawn()
                    && let Some(slot) = drawn.slots_of(act).next()
                {
                    frames.push(frame(vec![
                        ("t", text("reveal")),
                        ("rev", number(drawn.rev())),
                        ("slot", number(u64::from(slot))),
                    ]));
                }
            }
            Effect::ScreenEntered { .. } | Effect::ScrollTop => {
                frames.push(frame(vec![("t", text("top"))]));
            }
            Effect::StartTimer { timer, ms } => {
                self.timers.retain(|(running, _)| *running != timer);
                self.timers.push((timer, ms));
                frames.push(timer_frame(timer, ms));
            }
            Effect::StopTimer { timer } => {
                self.timers.retain(|(running, _)| *running != timer);
                frames.push(frame(vec![
                    ("t", text("stop_timer")),
                    ("id", text(wire::timer_word(timer))),
                ]));
            }
            Effect::CopyText { text: copied, mark } => {
                self.last_copy = self.last_copy.saturating_add(1);
                let id = self.last_copy;
                while self.copies.len() >= COPIES_MAX {
                    let _ = self.copies.pop_first();
                }
                self.copies.insert(id, mark);
                frames.push(frame(vec![
                    ("t", text("copy")),
                    ("id", number(id)),
                    ("text", text(&copied)),
                ]));
            }
            // No browser in A2 (no network permission, spec/15 §18 42 N16).
            Effect::OpenUrl { which, .. } => {
                answers.push(Answer::Cmd(Cmd::Opened { ok: false, which }));
            }
            Effect::OpenFolder(Folder::Extension) => answers.push(Answer::Cmd(Cmd::FolderMissing)),
            // The approval window is A3: an open fails like a window that could not be made.
            Effect::Approval(ApprovalEffect::Open { shown, .. }) => {
                answers.push(Answer::Cmd(Cmd::ApprovalOpened {
                    shown,
                    outcome: OpenOutcome::Failed(ErrorCode::App009),
                    wide: false,
                }));
            }
            // 2026-11-25 A2-7: the secret windows (`crate::secret_host`); before, every open was
            // answered `Refused(E-SEC-001)` here.
            Effect::Secret(effect) => self.apply_secret(effect, frames, answers),
            // Nothing on Android in A2: no folder button is drawn (`open_folders` off), no
            // approval window exists to close or repaint, no secret copy is pending,
            // no key worker runs yet (A2-8), the main window is the app's task, credential
            // edits and the scroll memory come later (A3, A7).
            Effect::OpenFolder(Folder::Data | Folder::Logs)
            | Effect::Approval(_)
            | Effect::AwaitKeyLock { .. }
            | Effect::ClearCred { .. }
            | Effect::RaiseMain
            | Effect::ScreenLeaving { .. }
            | Effect::OverlayClosedInPlace
            | Effect::TabTop { .. }
            | Effect::ScrollMemoryClear
            | Effect::ReleaseHold => {}
        }
    }

    /// A secret window's effect (2026-11-25 A2-7): an open is asked of Java (answered when its
    /// window is ready, `SecretHost::on_input`), a close and a form change go to the window; the
    /// clip clear has nothing to clear (no secret copy on Android, spec/15 §9.3).
    fn apply_secret(
        &mut self,
        effect: SecretEffect,
        frames: &mut Vec<Vec<u8>>,
        answers: &mut Vec<Answer>,
    ) {
        let now_ms = self.wallet.clock.now_ms();
        let mut reply = Reply::default();
        match effect {
            SecretEffect::OpenInput {
                serial,
                kind,
                step,
                lang,
                ..
            } => self.secret.ask(
                &self.wallet,
                serial,
                kind,
                step,
                Shape::Input,
                lang,
                now_ms,
                frames,
                &mut reply,
            ),
            SecretEffect::OpenDisplay {
                serial,
                kind,
                step,
                timeout_note,
                lang,
            } => self.secret.ask(
                &self.wallet,
                serial,
                kind,
                step,
                Shape::Display(timeout_note),
                lang,
                now_ms,
                frames,
                &mut reply,
            ),
            SecretEffect::Close { serial } => self.secret.close(serial, frames),
            SecretEffect::Form { serial, op } => self.secret.form_op(serial, op, now_ms, frames),
            SecretEffect::ClearClip { .. } => {}
        }
        answers.extend(
            reply
                .opened
                .into_iter()
                .map(|(serial, outcome)| Answer::Cmd(Cmd::SecretOpened { serial, outcome })),
        );
        answers.extend(
            reply
                .actions
                .into_iter()
                .map(|(serial, action)| Answer::Secret(serial, action)),
        );
    }

    /// The field writes of `act` (a plain field) in the drawn model; none for a field that never
    /// goes on the wire (`wire::field_on_wire`).
    fn field_frames(&self, act: Act, shown: &str, frames: &mut Vec<Vec<u8>>) {
        let Some(drawn) = self.wallet.drawn() else {
            return;
        };
        if matches!(act, Act::Field(field) if !wire::field_on_wire(field)) {
            return;
        }
        for slot in drawn.slots_of(act) {
            frames.push(field_frame(
                drawn.rev(),
                slot,
                shown,
                self.wallet.edits_seen(slot),
            ));
        }
    }
}

/// What a UI frame is to the queue (`crate::io_request::UiKind`): every frame this host makes
/// starts with its `t` member, so the kind is read from that.
#[must_use]
pub fn ui_kind(frame: &[u8]) -> UiKind {
    if frame.starts_with(br#"{"t":"model","#) {
        UiKind::Model
    } else if frame.starts_with(br#"{"t":"field","#) || frame.starts_with(br#"{"t":"reveal","#) {
        UiKind::OfModel
    } else {
        UiKind::Other
    }
}

fn field_frame(rev: u64, slot: u32, shown: &str, seen: u64) -> Vec<u8> {
    frame(vec![
        ("t", text("field")),
        ("rev", number(rev)),
        ("slot", number(u64::from(slot))),
        ("text", text(shown)),
        ("seen", number(seen)),
    ])
}

fn timer_frame(timer: TimerId, ms: u64) -> Vec<u8> {
    frame(vec![
        ("t", text("timer")),
        ("id", text(wire::timer_word(timer))),
        ("ms", number(ms)),
    ])
}

/// Whether the outcome is a lifetime event the shell acts on itself (A2-8: the screen-off and
/// background locks).
#[must_use]
pub const fn life_of(outcome: InputOutcome) -> Option<Life> {
    match outcome {
        InputOutcome::Life(life) => Some(life),
        _ => None,
    }
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn number(value: u64) -> Value {
    Value::Number(Number::from_u64(value))
}

fn frame(members: Vec<(&str, Value)>) -> Vec<u8> {
    let object = Object::from_pairs(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
    .map_or(Value::Null, Value::Object);
    yw_json::to_vec(&object)
}

#[cfg(test)]
mod tests;

// The Android shell keeps the host behind a process-wide lock (`shell::HOST`): it must be `Send`.
const _: () = {
    const fn sendable<T: Send>() {}
    sendable::<UiHost>();
};
