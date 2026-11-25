//! The Android shell's secret windows (spec/15 §9.1–§9.2, §3.2, §18 42 N22·N23; 2026-11-25 A2-7):
//! the shell's half of W01–W12 on Android, as yw-app `App::secret` with its window record is on
//! Windows. The engine's form (`SecretForm`) decides; this host owns its instance, feeds it what
//! the map `crate::secret_keys` built, and hands Java a model of what to draw (`s_model`): texts,
//! flags, counts and *handles*, never a secret. Java draws a field's content, the displayed secret
//! and W05's completions only through `secretFill(handle, char[])` ([`SecretHost::fill`]).
//!
//! **Two-phase open** (N23). An input window's open (`SecretEffect::OpenInput`) or a display
//! window's (`OpenDisplay`) is a frame `s_open` and a record of what was asked; nothing is
//! answered yet. Java starts the secure Activity, sets `FLAG_SECURE` before any content, and once
//! the window is attached reads the flag back and answers `s_ready` (`crate::secret_wire`). Only a
//! ready answer for the asked serial makes a window: an input window gets its form (capture
//! exclusion "verified", `FLAG_SECURE` being Android's), a display window goes to
//! `Wallet::open_display_window` with [`AndroidDisplayHost`], whose `make` reports the window
//! verified only when the ready said `secure` — so the secret moves only into a window whose flag
//! was read back. A ready that is not secure is refused (E-SEC-001; a display window's secret is
//! wiped); a ready for a serial not asked (late, after a lock or a close ended it) only closes
//! that window; no ready within [`OPEN_WAIT_MS`] fails the open (E-APP-009). The window is bound
//! to the Activity instance (`win`, counted up by Java and never reused: a ready whose `win` is
//! not above every `win` seen is refused) and every input, key and fill must name it.
//! 2026-11-25 A2-7 review: a ready the host does not take is answered `s_close_win` (that
//! instance only), never `s_close` of its session: a second Activity of the open session (a
//! resync's `s_open` sent again while the first one was starting) must not close the window the
//! host keeps open; before, it did, and Java lost its handle on the window that stayed. A resync
//! begins with `s_keep` naming the asked and the open window ([`SecretHost::resync`]), so Java
//! closes every other one even when the full UI queue dropped their `s_close`.
//!
//! **Fill.** A handle is `win << 16 | item` ([`handle`]): field `i`, the shown secret, or
//! completion `k`. It is valid only while that window is open: a closed, gone or other window's
//! handle fills nothing (0). While the content is masked (focus lost) nothing fills. Java reads
//! its `FLAG_SECURE` back right before every fill and closes the window instead when it is off.
//!
//! **What the model holds.** Window texts in the window's language (title, step, intro, labels,
//! buttons, messages, the bands of the secret surface from the facts of this open, spec/15 §8.2),
//! and the facts the Windows window draws as text: a field's `count/limit`, W01/W04's two rule
//! lines, W10's list verdicts, W05's word count, W08's address and countdown. Never a field's
//! content, the shown secret or a completion (secret-derived, N22): for those only a handle and
//! a fixed capacity, and always [`yw_engine::secret::form::WORD_CANDIDATES_MAX`] completion
//! handles whatever their number.
//!
//! Platform-neutral (no `unsafe`): the gate's Windows build tests it (`tests`).
#![forbid(unsafe_code)]

use core::fmt;

use yw_core::lang::Lang;
use yw_core::secret::Zeroizing;
use yw_engine::approval::flow::OpenOutcome;
use yw_engine::errors::ErrorCode;
use yw_engine::logging::{self, Field};
use yw_engine::protection::Band;
use yw_engine::screen::facts::PlatformFlags;
use yw_engine::secret::form::{FormAction, SecretForm, WORD_CANDIDATES_MAX, WordMark};
use yw_engine::secret::input::SecretButton;
use yw_engine::secret::{
    DisplayHost, DisplayMade, SecretFormOp, SecretKind, SecretStep, TimeoutNote, text,
};
use yw_engine::wallet::Wallet;
use yw_engine::wallet::secret_session::SecretAction;
use yw_json::{Number, Object, Value};

use crate::secret_keys::{self, KeyEvent, Step};
use crate::secret_wire::{self, SecretInput};
use crate::ui_host::ANDROID_FLAGS;

/// How long an open waits for Java's ready answer before it fails (E-APP-009).
pub const OPEN_WAIT_MS: u64 = 10_000;

/// The handle item of field `i` is `FIELD_ITEM + i`.
const FIELD_ITEM: u64 = 0x000;
/// The handle item of the shown secret (W08/W09).
const SHOWN_ITEM: u64 = 0x100;
/// The handle item of W05's completion `k` is `CANDIDATE_ITEM + k`.
const CANDIDATE_ITEM: u64 = 0x200;
/// The capacity Java allocates for the shown secret (24 words are at most 215 units; a key less).
pub const SHOWN_CAP: usize = 256;
/// The capacity of a completion (the longest list word).
pub const CANDIDATE_CAP: usize = 8;

/// What one handle names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillItem {
    /// Field `i`'s content (dots for a masked field unless its `보기` is held).
    Field(usize),
    /// The shown secret.
    Shown,
    /// W05's completion `k`.
    Candidate(usize),
}

/// The handle of `item` in window `win` (module doc).
#[must_use]
pub fn handle(win: u32, item: FillItem) -> u64 {
    let wide = |index: usize| u64::try_from(index).unwrap_or(u64::MAX);
    let item = match item {
        FillItem::Field(index) => FIELD_ITEM.saturating_add(wide(index)),
        FillItem::Shown => SHOWN_ITEM,
        FillItem::Candidate(index) => CANDIDATE_ITEM.saturating_add(wide(index)),
    };
    u64::from(win) << 16 | item
}

/// The window and item of a handle; `None` for one no model could have given.
#[must_use]
pub fn parse_handle(handle: i64) -> Option<(u32, FillItem)> {
    let handle = u64::try_from(handle).ok()?;
    let win = u32::try_from(handle >> 16).ok()?;
    if win == 0 || win > secret_keys::WIN_MAX {
        return None;
    }
    let item = handle & 0xFFFF;
    let index = usize::try_from(item & 0xFF).ok()?;
    match item & 0xFF00 {
        FIELD_ITEM if index <= usize::from(secret_keys::FIELD_MAX) => {
            Some((win, FillItem::Field(index)))
        }
        SHOWN_ITEM if index == 0 => Some((win, FillItem::Shown)),
        CANDIDATE_ITEM if index < WORD_CANDIDATES_MAX => Some((win, FillItem::Candidate(index))),
        _ => None,
    }
}

/// What kind of window an open asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// An input window (W01–W07, W10–W12): the shell makes its form.
    Input,
    /// A display window (W08/W09) with its note: the wallet makes its form around the secret.
    Display(Option<TimeoutNote>),
}

/// A window the shell asked Java for, waiting for its ready answer.
#[derive(Clone, Copy, Debug)]
struct Asked {
    serial: u64,
    kind: SecretKind,
    step: Option<SecretStep>,
    shape: Shape,
    lang: Lang,
    at_ms: u64,
}

/// The open window: its session, its Activity instance, its form and its bands.
struct OpenWin {
    serial: u64,
    win: u32,
    form: SecretForm,
    bands: Vec<Band>,
}

/// What the screen host does after the secret host took an input or an effect: the answers to
/// give the wallet (each an entry of its own, after the batch) and the window actions that are
/// the wallet's (`Wallet::on_secret_action`, in-process: a submission holds secrets).
#[derive(Default)]
pub struct Reply {
    /// `Cmd::SecretOpened` answers.
    pub opened: Vec<(u64, OpenOutcome)>,
    /// What a window ended or asked for.
    pub actions: Vec<(u64, SecretAction)>,
}

impl fmt::Debug for Reply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Reply")
            .field("opened", &self.opened.len())
            .field("actions", &self.actions.len())
            .finish()
    }
}

/// The shell's secret windows (module doc).
pub struct SecretHost {
    asked: Option<Asked>,
    open: Option<OpenWin>,
    /// The highest window id seen in a ready answer (a ready must name a higher one).
    last_win: u32,
}

impl fmt::Debug for SecretHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretHost")
            .field("asked", &self.asked.map(|asked| asked.serial))
            .field(
                "open",
                &self.open.as_ref().map(|open| (open.serial, open.win)),
            )
            .field("last_win", &self.last_win)
            .finish()
    }
}

/// Whether the decided window is verified for a display open (the ready said `secure`), refused
/// or failed (module doc).
#[derive(Clone, Copy, Debug)]
enum Verdict {
    Verified(u32),
    Refused,
    Failed,
}

/// The Android shell's display host (spec/15 §9.1 N23, §18 30): the second phase of a display
/// window's open. `make` reports the window verified only when Java's ready answer read
/// `FLAG_SECURE` back for it; `fill_and_show` keeps the form the wallet built around the secret as
/// the open window. The window is the Activity instance's id (Java's window, which Rust never
/// holds).
struct AndroidDisplayHost<'a> {
    verdict: Verdict,
    slot: &'a mut Option<OpenWin>,
    bands: Vec<Band>,
}

impl DisplayHost for AndroidDisplayHost<'_> {
    type Window = u32;

    fn make(&mut self, _serial: u64, _kind: SecretKind, _lang: Lang) -> DisplayMade<u32> {
        match self.verdict {
            Verdict::Verified(win) => DisplayMade::Verified(win),
            Verdict::Refused => DisplayMade::Unverified {
                outcome: OpenOutcome::Refused(ErrorCode::Sec001),
                window: None,
            },
            Verdict::Failed => DisplayMade::Unverified {
                outcome: OpenOutcome::Failed(ErrorCode::App009),
                window: None,
            },
        }
    }

    fn flags(&self) -> PlatformFlags {
        ANDROID_FLAGS
    }

    fn fill_and_show(&mut self, serial: u64, window: u32, form: SecretForm) {
        *self.slot = Some(OpenWin {
            serial,
            win: window,
            form,
            bands: core::mem::take(&mut self.bands),
        });
    }
}

/// The only place this crate feeds the form (yw-app source check
/// `secret_keys_are_mapped_only_by_the_mapper`): each step the map built, in order.
fn feed(form: &mut SecretForm, step: Step, now_ms: u64) -> FormAction {
    match step {
        Step::Key(key) => form.on_key(key, now_ms),
        Step::Pointer(pointer) => form.on_pointer(pointer, now_ms).0,
        Step::CaptureLost => form.on_capture_lost(),
        Step::Deactivate => form.on_deactivate(),
        Step::Activate => {
            form.on_activate();
            FormAction::Redraw
        }
    }
}

impl Default for SecretHost {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretHost {
    /// No window asked or open.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            asked: None,
            open: None,
            last_win: 0,
        }
    }

    /// Asks Java for the input window of session `serial` (the first phase): the `s_open` frame.
    /// A serial that is not the wallet's open, unshown session is refused at once, as on
    /// Windows (critique A-3).
    #[expect(
        clippy::too_many_arguments,
        reason = "the open effect's members, then the host's state"
    )]
    pub fn ask(
        &mut self,
        wallet: &Wallet,
        serial: u64,
        kind: SecretKind,
        step: Option<SecretStep>,
        shape: Shape,
        lang: Lang,
        now_ms: u64,
        frames: &mut Vec<Vec<u8>>,
        reply: &mut Reply,
    ) {
        if !wallet.secret_unshown(serial) {
            reply
                .opened
                .push((serial, OpenOutcome::Refused(ErrorCode::Sec001)));
            return;
        }
        self.asked = Some(Asked {
            serial,
            kind,
            step,
            shape,
            lang,
            at_ms: now_ms,
        });
        frames.push(secret_wire::open_frame(serial));
    }

    /// `SecretEffect::Close`: the window of `serial`, asked or open, goes (its form wiped first).
    pub fn close(&mut self, serial: u64, frames: &mut Vec<Vec<u8>>) {
        if self.asked.is_some_and(|asked| asked.serial == serial) {
            self.asked = None;
            frames.push(secret_wire::close_frame(serial));
        }
        if let Some(mut open) = self.open.take_if(|open| open.serial == serial) {
            open.form.wipe();
            frames.push(secret_wire::close_frame(serial));
        }
    }

    /// `SecretEffect::Form`: the open window of `serial` changes and is drawn again (nothing for
    /// another serial or a window not open yet, as on Windows).
    pub fn form_op(
        &mut self,
        serial: u64,
        op: SecretFormOp,
        now_ms: u64,
        frames: &mut Vec<Vec<u8>>,
    ) {
        let Some(open) = self.open.as_mut().filter(|open| open.serial == serial) else {
            return;
        };
        let form = &mut open.form;
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
        frames.push(model(open, now_ms));
    }

    /// One input of a secret window (`crate::secret_wire`).
    pub fn take_input(
        &mut self,
        wallet: &mut Wallet,
        input: SecretInput,
        now_ms: u64,
        bands: impl FnOnce(Option<yw_engine::protection::DeviceFacts>) -> Vec<Band>,
        frames: &mut Vec<Vec<u8>>,
        reply: &mut Reply,
    ) {
        match input {
            SecretInput::Ready {
                serial,
                win,
                secure,
                facts,
            } => self.on_ready(
                wallet,
                serial,
                win,
                secure,
                bands(facts),
                now_ms,
                frames,
                reply,
            ),
            SecretInput::Button { win, control, edge } => {
                self.steps(
                    win,
                    secret_keys::button_steps(control, edge),
                    now_ms,
                    frames,
                    reply,
                );
            }
            SecretInput::Focus { win, on } => {
                self.steps(win, secret_keys::focus_steps(on), now_ms, frames, reply);
            }
            SecretInput::Back { win } => {
                self.steps(win, secret_keys::back_steps(), now_ms, frames, reply);
            }
            SecretInput::Gone { serial, win } => self.on_gone(wallet, serial, win, frames, reply),
        }
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "the ready answer's members, then the host's state"
    )]
    fn on_ready(
        &mut self,
        wallet: &mut Wallet,
        serial: u64,
        win: u32,
        secure: bool,
        bands: Vec<Band>,
        now_ms: u64,
        frames: &mut Vec<Vec<u8>>,
        reply: &mut Reply,
    ) {
        // A window id never comes twice (Java counts them up): a repeated or older one is
        // refused, its window closed.
        let fresh = win > self.last_win;
        self.last_win = self.last_win.max(win);
        let Some(asked) = self
            .asked
            .filter(|asked| asked.serial == serial)
            .filter(|_| fresh)
        else {
            // Late (the open ended: a lock, a close, the wait ran out), not asked, or a repeated
            // or older instance (a second Activity of the open session): that window only
            // closes (N23: the late answer is dropped by its number). 2026-11-25 A2-7 review: by
            // its instance; before, `s_close` of the serial also closed the open window's.
            frames.push(secret_wire::close_win_frame(serial, win));
            return;
        };
        self.asked = None;
        if !secure {
            logging::warn(
                "secret",
                "secret.flag_secure=failed",
                &[("window", Field::Word(asked.kind.id()))],
            );
        }
        let verdict = if secure {
            Verdict::Verified(win)
        } else {
            Verdict::Refused
        };
        let outcome = self.decide(wallet, asked, verdict, bands, now_ms);
        match outcome {
            OpenOutcome::Shown { .. } => {
                if let Some(open) = self.open.as_ref() {
                    frames.push(model(open, now_ms));
                }
            }
            OpenOutcome::Refused(_) | OpenOutcome::Failed(_) => {
                frames.push(secret_wire::close_frame(serial));
            }
        }
        reply.opened.push((serial, outcome));
    }

    /// The second phase of an open: an input window gets its form when verified; a display
    /// window goes to the wallet's `open_display_window` with this shell's display host.
    fn decide(
        &mut self,
        wallet: &mut Wallet,
        asked: Asked,
        verdict: Verdict,
        bands: Vec<Band>,
        now_ms: u64,
    ) -> OpenOutcome {
        if let Shape::Display(note) = asked.shape {
            let mut host = AndroidDisplayHost {
                verdict,
                slot: &mut self.open,
                bands,
            };
            return wallet.open_display_window(
                &mut host,
                asked.serial,
                asked.kind,
                asked.step,
                note,
                asked.lang,
            );
        }
        match verdict {
            Verdict::Verified(win) if wallet.secret_unshown(asked.serial) => {
                let mut form = SecretForm::new(asked.kind, asked.lang, now_ms, true, ANDROID_FLAGS);
                form.set_step(asked.step);
                self.open = Some(OpenWin {
                    serial: asked.serial,
                    win,
                    form,
                    bands,
                });
                OpenOutcome::Shown {
                    capture_excluded: true,
                }
            }
            Verdict::Verified(_) | Verdict::Refused => OpenOutcome::Refused(ErrorCode::Sec001),
            Verdict::Failed => OpenOutcome::Failed(ErrorCode::App009),
        }
    }

    /// The window `win` of `serial` is destroyed: an asked one fails like a refused open; the
    /// open one's form is wiped and the wallet told it ended (a display window with no hold
    /// closes, any other cancels) — also while a submitted job runs, since no window is left to
    /// show its result.
    fn on_gone(
        &mut self,
        wallet: &mut Wallet,
        serial: u64,
        win: u32,
        frames: &mut Vec<Vec<u8>>,
        reply: &mut Reply,
    ) {
        if let Some(asked) = self.asked.filter(|asked| asked.serial == serial) {
            self.asked = None;
            let outcome = self.decide(wallet, asked, Verdict::Refused, Vec::new(), 0);
            reply.opened.push((serial, outcome));
            frames.push(secret_wire::close_frame(serial));
            return;
        }
        if let Some(mut open) = self
            .open
            .take_if(|open| open.serial == serial && open.win == win)
        {
            open.form.wipe();
            let kind = open.form.kind();
            let action = if kind.is_display() && !kind.needs_hold() {
                SecretAction::Close
            } else {
                SecretAction::Cancel
            };
            reply.actions.push((serial, action));
        }
    }

    /// One `secretKey` (module doc): fed to the open window it names.
    pub fn take_key(
        &mut self,
        event: KeyEvent,
        now_ms: u64,
        frames: &mut Vec<Vec<u8>>,
        reply: &mut Reply,
    ) {
        let Some(active) = self
            .open
            .as_ref()
            .filter(|open| open.win == event.win)
            .map(|open| open.form.paint_view().active())
        else {
            return;
        };
        self.steps(
            event.win,
            secret_keys::key_steps(event, active),
            now_ms,
            frames,
            reply,
        );
    }

    fn steps(
        &mut self,
        win: u32,
        steps: Vec<Step>,
        now_ms: u64,
        frames: &mut Vec<Vec<u8>>,
        reply: &mut Reply,
    ) {
        for step in steps {
            let Some(open) = self.open.as_mut().filter(|open| open.win == win) else {
                return;
            };
            let action = feed(&mut open.form, step, now_ms);
            self.act(action, now_ms, frames, reply);
        }
    }

    /// The main timer's tick: an asked window that never got ready fails; the open window's
    /// form ticks (hold, time-outs, countdown).
    pub fn tick(
        &mut self,
        wallet: &mut Wallet,
        now_ms: u64,
        frames: &mut Vec<Vec<u8>>,
        reply: &mut Reply,
    ) {
        if let Some(asked) = self
            .asked
            .filter(|asked| now_ms.saturating_sub(asked.at_ms) >= OPEN_WAIT_MS)
        {
            self.asked = None;
            logging::warn(
                "secret",
                "secret.open_timeout",
                &[("window", Field::Word(asked.kind.id()))],
            );
            let outcome = self.decide(wallet, asked, Verdict::Failed, Vec::new(), now_ms);
            reply.opened.push((asked.serial, outcome));
            frames.push(secret_wire::close_frame(asked.serial));
        }
        let Some(open) = self.open.as_mut() else {
            return;
        };
        let action = open.form.on_tick(now_ms);
        self.act(action, now_ms, frames, reply);
    }

    /// What the form asked for: a redraw, or an end that is the wallet's. Android offers no
    /// paste (A5) and no secret copy (spec/15 §9.3): those ask nothing.
    fn act(&self, action: FormAction, now_ms: u64, frames: &mut Vec<Vec<u8>>, reply: &mut Reply) {
        let Some(open) = self.open.as_ref() else {
            return;
        };
        let serial = open.serial;
        let ended = match action {
            FormAction::None | FormAction::Paste | FormAction::Copy => return,
            FormAction::Redraw => None,
            FormAction::Submit(submission) => Some(SecretAction::Submit(submission)),
            FormAction::Cancel => Some(SecretAction::Cancel),
            FormAction::TimedOut => Some(SecretAction::TimedOut),
            FormAction::Close => Some(SecretAction::Close),
            FormAction::HoldComplete => Some(SecretAction::HoldComplete),
        };
        frames.push(model(open, now_ms));
        if let Some(action) = ended {
            reply.actions.push((serial, action));
        }
    }

    /// The units of `handle` for Java's `secretFill`, a copy wiped when dropped (module doc);
    /// `None` for a handle of no open window, an item it does not have, or masked content.
    #[must_use]
    pub fn fill(&self, handle: i64) -> Option<Zeroizing<Vec<u16>>> {
        let (win, item) = parse_handle(handle)?;
        let open = self.open.as_ref().filter(|open| open.win == win)?;
        let view = open.form.paint_view();
        if view.masked() {
            return None;
        }
        match item {
            FillItem::Field(index) => {
                let field = view.fields().nth(index)?;
                let plain = !field.masked() || view.revealing() == Some(index);
                Some(field.render_utf16(!plain))
            }
            FillItem::Shown => {
                let shown = view.shown_text()?;
                let mut units = Zeroizing::new(Vec::with_capacity(shown.len()));
                units.extend(shown.encode_utf16());
                Some(units)
            }
            FillItem::Candidate(index) => {
                let word = view.word_candidates().get(index).copied()?;
                let mut units = Zeroizing::new(Vec::with_capacity(word.len()));
                units.extend(word.encode_utf16());
                Some(units)
            }
        }
    }

    /// The secret windows' state again after the UI queue dropped its frames
    /// (`crate::ui_host::UiHost::resync`): first `s_keep` naming the windows that may exist (the
    /// asked session's, any instance, and the open one; 2026-11-25 A2-7 review: Java closes every
    /// other, so a dropped `s_close` still closes its window), then the asked window's open and
    /// the open window's model.
    #[must_use]
    pub fn resync(&self, now_ms: u64) -> Vec<Vec<u8>> {
        let mut kept = Vec::new();
        if let Some(asked) = self.asked {
            kept.push((asked.serial, 0));
        }
        if let Some(open) = self.open.as_ref() {
            kept.push((open.serial, open.win));
        }
        let mut frames = vec![secret_wire::keep_frame(&kept)];
        if let Some(asked) = self.asked {
            frames.push(secret_wire::open_frame(asked.serial));
        }
        if let Some(open) = self.open.as_ref() {
            frames.push(model(open, now_ms));
        }
        frames
    }

    /// The open window's session and window id, if one is open (tests and logs).
    #[must_use]
    pub fn open_window(&self) -> Option<(u64, u32)> {
        self.open.as_ref().map(|open| (open.serial, open.win))
    }

    /// The asked window's session, if one waits for its ready answer.
    #[must_use]
    pub fn asked_serial(&self) -> Option<u64> {
        self.asked.map(|asked| asked.serial)
    }
}

fn text(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn number(value: u64) -> Value {
    Value::Number(Number::from_u64(value))
}

fn object(members: Vec<(&str, Value)>) -> Value {
    Object::from_pairs(
        members
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    )
    .map_or(Value::Null, Value::Object)
}

fn maybe(value: Option<&str>) -> Value {
    value.map_or(Value::Null, text)
}

fn line(value: &str, tone: &str) -> Value {
    object(vec![("text", text(value)), ("tone", text(tone))])
}

fn count(value: usize) -> Value {
    number(u64::try_from(value).unwrap_or(u64::MAX))
}

/// The keyboard a window takes (`none` for a display window).
const fn keys(kind: SecretKind) -> &'static str {
    match kind {
        SecretKind::ShowMnemonic { .. } | SecretKind::ShowKey => "none",
        SecretKind::Mnemonic => "words",
        SecretKind::Backup { .. } => "letters",
        _ => "text",
    }
}

/// The open window's model frame `s_model` (module doc): what Java draws, with handles for every
/// secret text. Built from the form's read-only paint view only.
#[expect(
    clippy::too_many_lines,
    reason = "one pass over everything the window draws, as the Windows paint"
)]
fn model(open: &OpenWin, now_ms: u64) -> Vec<u8> {
    let view = open.form.paint_view();
    let lang = view.lang();
    let kind = view.kind();
    let win = open.win;
    let enabled = view.input_enabled(now_ms);
    let step = view.step().map_or(Value::Null, |step| {
        let labels = step.labels(lang);
        object(vec![
            (
                "head",
                text(&text::STEPS.fill(
                    lang,
                    [
                        step.title(lang),
                        &step.current.to_string(),
                        &labels.len().to_string(),
                    ],
                )),
            ),
            (
                "labels",
                Value::Array(labels.iter().map(|label| text(label)).collect()),
            ),
            ("current", count(step.current)),
        ])
    });
    let intro: Vec<Value> = view
        .intro()
        .iter()
        .chain(view.details())
        .map(|paragraph| text(paragraph))
        .collect();
    let mut fields = Vec::new();
    for (index, field) in view.fields().enumerate() {
        let (right, bad) = if matches!(kind, SecretKind::Backup { .. }) {
            match view.word_mark(index) {
                WordMark::None => (String::new(), false),
                WordMark::Listed => (text::WORD_LISTED.get(lang).to_owned(), false),
                WordMark::Unlisted => (text::WORD_UNLISTED.get(lang).to_owned(), true),
            }
        } else if kind == SecretKind::Mnemonic {
            (String::new(), false)
        } else {
            (format!("{}/{}", field.len(), field.limit()), false)
        };
        let reveal = if field.masked() {
            object(vec![
                ("label", text(text::REVEAL.get(lang))),
                (
                    "on",
                    Value::Bool(view.button_enabled(SecretButton::Reveal(index), now_ms)),
                ),
            ])
        } else {
            Value::Null
        };
        fields.push(object(vec![
            ("label", text(field.label())),
            ("h", number(handle(win, FillItem::Field(index)))),
            ("cap", count(field.limit())),
            ("right", text(&right)),
            ("bad", Value::Bool(bad)),
            ("masked", Value::Bool(field.masked())),
            ("active", Value::Bool(index == view.active())),
            ("reveal", reveal),
        ]));
    }
    let words = if kind == SecretKind::Mnemonic {
        view.first_field().map_or(Value::Null, |field| {
            text(&text::WORDS_TYPED.fill(
                lang,
                [
                    &view.word_count().to_string(),
                    &field.len().to_string(),
                    &field.limit().to_string(),
                ],
            ))
        })
    } else {
        Value::Null
    };
    // Always every completion handle (never how many there are, N22); Java draws those that fill.
    let candidates: Vec<Value> = if kind == SecretKind::Mnemonic {
        (0..WORD_CANDIDATES_MAX)
            .map(|index| {
                object(vec![
                    ("h", number(handle(win, FillItem::Candidate(index)))),
                    ("cap", count(CANDIDATE_CAP)),
                ])
            })
            .collect()
    } else {
        Vec::new()
    };
    let checks: Vec<Value> = view
        .password_checks()
        .map(|(rule, same)| {
            let rule = match rule {
                Some(true) => line(text::PW_RULE_OK.get(lang), "ok"),
                Some(false) => line(text::PW_RULE_SHORT.get(lang), "bad"),
                None => line(text::PW_RULE_EMPTY.get(lang), "muted"),
            };
            let same = match same {
                Some(true) => line(text::PW_SAME.get(lang), "ok"),
                Some(false) => line(text::PW_DIFFERENT.get(lang), "bad"),
                None => line(text::PW_AGAIN.get(lang), "muted"),
            };
            vec![rule, same]
        })
        .unwrap_or_default();
    let checkbox = view.checkbox().map_or(Value::Null, |(label, checked)| {
        object(vec![
            ("label", text(label)),
            ("on", Value::Bool(checked)),
            (
                "enabled",
                Value::Bool(view.button_enabled(SecretButton::Checkbox, now_ms)),
            ),
        ])
    });
    let note = view
        .checkbox()
        .filter(|(_, checked)| *checked)
        .and_then(|_| view.note());
    let mut status = Vec::new();
    if let Some(position) = view.unlisted_position() {
        status.push(line(
            &text::UNLISTED_WORD.fill(lang, [&position.to_string()]),
            "bad",
        ));
    }
    if let Some(countdown) = view.countdown_line(now_ms) {
        status.push(line(&countdown, "muted"));
    }
    let mut messages = Vec::new();
    for (message, tone) in [
        (view.error(), "bad"),
        (view.transient(), "bad"),
        (view.info(), "muted"),
        (view.busy().then_some(text::CHECKING.get(lang)), "muted"),
    ] {
        if let Some(message) = message {
            messages.push(line(message, tone));
        }
    }
    let shown = if view.shown_text().is_some() {
        object(vec![
            ("h", number(handle(win, FillItem::Shown))),
            ("cap", count(SHOWN_CAP)),
            (
                "grid",
                Value::Bool(matches!(kind, SecretKind::ShowMnemonic { .. })),
            ),
        ])
    } else {
        Value::Null
    };
    let address = view.shown_address().map_or(Value::Null, |address| {
        object(vec![
            ("label", text(text::FIRST_ADDRESS.get(lang))),
            ("text", text(address)),
        ])
    });
    let (right, left) = view.button_labels(now_ms);
    let mut buttons = Vec::new();
    for (button, label) in left.iter().chain(&right) {
        let Some(word) = secret_keys::button_word(*button) else {
            continue;
        };
        let hold = *button == SecretButton::Primary && kind.needs_hold();
        let done = if hold && view.hold_active() {
            yw_engine::secret::BACKUP_ACK_HOLD_MS.saturating_sub(view.hold_remaining_ms(now_ms))
        } else {
            0
        };
        buttons.push(object(vec![
            ("b", text(word)),
            ("label", text(label)),
            ("on", Value::Bool(view.button_enabled(*button, now_ms))),
            ("hold", Value::Bool(hold)),
            ("done", number(done)),
        ]));
    }
    let frame = object(vec![
        ("t", text("s_model")),
        ("serial", number(open.serial)),
        ("win", number(u64::from(win))),
        ("kind", text(kind.id())),
        (
            "bands",
            Value::Array(
                open.bands
                    .iter()
                    .map(|band| text(band.text(lang)))
                    .collect(),
            ),
        ),
        ("step", step),
        ("title", text(kind.title(lang))),
        ("intro", Value::Array(intro)),
        ("fields", Value::Array(fields)),
        ("words", words),
        ("cands", Value::Array(candidates)),
        ("checks", Value::Array(checks)),
        ("checkbox", checkbox),
        ("note", maybe(note)),
        ("status", Value::Array(status)),
        ("msgs", Value::Array(messages)),
        (
            "masked",
            maybe(view.masked().then_some(text::MASKED.get(lang))),
        ),
        ("shown", shown),
        ("address", address),
        (
            "pp_note",
            maybe(
                view.shown_passphrase_note()
                    .then_some(text::PASSPHRASE_REVEAL_NOTE.get(lang)),
            ),
        ),
        ("buttons", Value::Array(buttons)),
        ("keys", text(keys(kind))),
        ("input", Value::Bool(enabled)),
    ]);
    yw_json::to_vec(&frame)
}

#[cfg(test)]
mod tests;
