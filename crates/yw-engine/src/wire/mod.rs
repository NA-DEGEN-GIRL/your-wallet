//! The Android wire format (spec/15 §3.2, §11.3, §18 8; 2026-11-25 A2-6): the yw-json encoding of
//! the screen model a shell draws ([`model`]) and the inputs it sends back ([`Input`]).
//!
//! The inputs are resolved against the model the engine handed out last, never taken as values
//! (spec/15 §18 8 (나), 주인 위임 결정(2026-11-24)): a press names the model's revision and a
//! control's slot (its place in the model's document order), and the engine finds the
//! [`Press`](crate::cmd::Press) or [`EditField`](crate::form::EditField) that control drew. The
//! shell never builds a `Press`, so it can press only what was drawn, and only while it is drawn:
//!
//! - an input of another revision is dropped ([`InputOutcome::Stale`]), and so is one that comes
//!   while the engine has a newer model queued (an `Effect::Render` not yet taken);
//! - a press is taken only when the item that holds the control is still built the same from the
//!   wallet's state now ([`InputOutcome::Changed`] otherwise, with a redraw): the row a press names
//!   by its position (`Row`) is the row the person saw — the stable key of spec/15 §18 40 (3) is
//!   the drawn row's content, not a new key per list;
//! - a disabled control, a press on an edit, an edit of a button, a read-only edit and a
//!   credential edit are refused ([`InputOutcome::Refused`]): a credential never comes this way
//!   (the app keyboard's `secretKey`, spec/15 §9.2).
//!
//! What a plain edit shows is the engine's to decide, never the shell's (2026-11-25 A2-6 review):
//! the shell draws every edit of a model with the model's text and keeps nothing it typed; when
//! it answers the render, the engine applies the Windows keep rule (`form::FormSync`, field
//! identity at the common ends of the control keys) and hands back, with
//! [`Wallet::take_edit_sync`](crate::wallet::Wallet::take_edit_sync), the text of every drawn
//! plain edit that differs from its model text and the slot the focused field is drawn at now.
//! The shell's field writes carry how many edits of that slot the engine had taken since the
//! render ([`Wallet::edits_seen`](crate::wallet::Wallet::edits_seen)); one the shell has sent more
//! edits for since is stale (the engine takes those edits after the write) and is not applied.
//! Before the review the Android shell kept the focused edit's typed text by its own rule (same
//! slot, limit and model text), which could differ from the engine's.
//!
//! A plain field whose text carries a secret ([`field_on_wire`]: the `WalletConnect` pairing link
//! with its `symKey`, spec/15 §12.2) never goes on the wire: it is drawn like a credential (no
//! text, takes no input), its text is wiped from the drawn record, and no field write names it,
//! until the §12.2 pairing path exists (2026-11-25 A2-6 review).
//!
//! There is no decoder of `Cmd::Approval` here or anywhere on the wire (spec/15 §18 8, §11.4 S4
//! end): an approval window's input is made only by the Android shell's own mapper from touch
//! facts (A3), as Windows makes it only in `ui::approval_input`. Source check
//! `the_wire_has_no_approval_decoder`.
//!
//! Platform-neutral: the gate's Windows build tests it; the Android shell (yw-android) is its one
//! user, and Java's `Ui` reads the same bytes (its JVM tests pin them).

use core::fmt;

use yw_core::secret::Zeroizing;
use yw_json::{Limits, Value};

use crate::cmd::TickPart;
use crate::effect::TimerId;
use crate::form::EditField;
use crate::screen::model::{Act, CtlKind, Item};

pub mod model;

pub use model::{Drawn, SlotInfo, encode_model, for_each_ctl};

/// The longest input a shell may send (a plain edit's text at its largest cap, 2 048 UTF-16 units,
/// escaped, fits with room).
pub const INPUT_MAX: usize = 16_384;

/// The highest slot number an input may name (a model has far fewer controls).
pub const SLOT_MAX: u64 = 65_535;

/// The parser limits of one input: one flat object of at most six members.
const INPUT_LIMITS: Limits = Limits {
    max_bytes: INPUT_MAX,
    max_depth: 1,
    max_nodes: 16,
    max_items: 8,
};

/// What the app's lifetime did (spec/15 §5.4): the shell's activity came to the front, went to
/// the background, or the screen went off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Life {
    /// An app activity is in front again.
    Front,
    /// No app activity is in front.
    Back,
    /// The screen went off (`ACTION_SCREEN_OFF`).
    ScreenOff,
}

impl Life {
    /// Every event (the wire's word table).
    pub const ALL: [Self; 3] = [Self::Front, Self::Back, Self::ScreenOff];

    /// The word on the wire.
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            Self::Front => "front",
            Self::Back => "back",
            Self::ScreenOff => "screen_off",
        }
    }
}

/// The word of a one-shot timer on the wire.
#[must_use]
pub const fn timer_word(timer: TimerId) -> &'static str {
    match timer {
        TimerId::SendCheck => "send_check",
    }
}

/// Every timer (the wire's word table).
pub const TIMERS: [TimerId; 1] = [TimerId::SendCheck];

/// The main timer's parts in the Windows timer's order (`Cmd::Tick`, spec/04 §1.4): the shell
/// answers an [`Input::Tick`] by sending them one at a time, each with the same clock reading and
/// each followed by its drain (one entry each, as the Windows timer). `TickPart::ReadsDue` is a
/// Windows main-window step, not the timer's.
pub const TICK_PARTS: [TickPart; 10] = [
    TickPart::Idle,
    TickPart::Wait,
    TickPart::ResetHold,
    TickPart::Copied,
    TickPart::Evm,
    TickPart::HyperCore,
    TickPart::Sol,
    TickPart::Btc,
    TickPart::Zec,
    TickPart::Received,
];

/// One input from the shell, decoded ([`decode_input`]). Not `Clone`: an edit's text is wiped
/// on drop.
pub enum Input {
    /// `{"t":"press","rev":R,"slot":S}`: the control at `slot` of model `rev` was pressed.
    Press {
        /// The model's revision.
        rev: u64,
        /// The control's slot.
        slot: u32,
    },
    /// `{"t":"edit","rev":R,"slot":S,"text":"…"}`: the plain edit at `slot` now shows `text`.
    Edit {
        /// The model's revision.
        rev: u64,
        /// The edit's slot.
        slot: u32,
        /// Its text now (cut to the field's cap by the logic).
        text: Zeroizing<String>,
    },
    /// `{"t":"rendered","rev":R,"focus":S,"of":P}` or `{"t":"rendered","rev":R,"focus":null,
    /// "of":null}`: the shell drew model `rev`; `focus` is the plain edit that had the keyboard
    /// focus before it did (`Cmd::Rendered`), named by its slot `S` in model `P` (the one the
    /// shell showed then).
    Rendered {
        /// The model's revision.
        rev: u64,
        /// The focused edit: the revision it was drawn in and its slot there.
        focus: Option<(u64, u32)>,
    },
    /// `{"t":"life","e":"front"|"back"|"screen_off"}`.
    Life(Life),
    /// `{"t":"tick"}`: one period of the main timer (`screen::MAIN_TIMER_MS`).
    Tick,
    /// `{"t":"timer","id":"send_check"}`: a one-shot timer asked for by `Effect::StartTimer`.
    Timer(TimerId),
    /// `{"t":"copied","id":N,"ok":B}`: the answer to the shell's copy frame `id` (the shell keeps
    /// the copy's mark; the engine never sees this one).
    Copied {
        /// The copy frame's id.
        id: u64,
        /// Whether the text reached the clipboard.
        ok: bool,
    },
}

/// Kinds, numbers and lengths only (D28): never an edit's text.
impl fmt::Debug for Input {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Press { rev, slot } => formatter
                .debug_struct("Press")
                .field("rev", rev)
                .field("slot", slot)
                .finish(),
            Self::Edit { rev, slot, text } => formatter
                .debug_struct("Edit")
                .field("rev", rev)
                .field("slot", slot)
                .field("len", &text.len())
                .finish(),
            Self::Rendered { rev, focus } => formatter
                .debug_struct("Rendered")
                .field("rev", rev)
                .field("focus", focus)
                .finish(),
            Self::Life(life) => formatter.debug_tuple("Life").field(life).finish(),
            Self::Tick => formatter.write_str("Tick"),
            Self::Timer(timer) => formatter.debug_tuple("Timer").field(timer).finish(),
            Self::Copied { id, ok } => formatter
                .debug_struct("Copied")
                .field("id", id)
                .field("ok", ok)
                .finish(),
        }
    }
}

/// Why an input could not be read. Codes only, never input content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    /// Longer than [`INPUT_MAX`].
    TooLarge,
    /// Not strict JSON within the limits.
    Json,
    /// JSON, but not one of the inputs above (a member missing or extra, a wrong type, a number
    /// out of range, an unknown word).
    Shape,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "input too large",
            Self::Json => "input is not valid JSON",
            Self::Shape => "input has an unknown shape",
        })
    }
}

impl std::error::Error for WireError {}

/// Decodes one input (strict: exactly the members of its kind, nothing else).
///
/// # Errors
///
/// [`WireError`] for anything else.
pub fn decode_input(bytes: &[u8]) -> Result<Input, WireError> {
    if bytes.len() > INPUT_MAX {
        return Err(WireError::TooLarge);
    }
    let value = yw_json::parse(bytes, &INPUT_LIMITS).map_err(|_| WireError::Json)?;
    let object = value.as_object().ok_or(WireError::Shape)?;
    let kind = object
        .get("t")
        .and_then(Value::as_str)
        .ok_or(WireError::Shape)?;
    let members = |names: &[&str]| -> Result<(), WireError> {
        let exact = object.len() == names.len().saturating_add(1)
            && names.iter().all(|name| object.get(name).is_some());
        if exact { Ok(()) } else { Err(WireError::Shape) }
    };
    let number = |name: &str, max: u64| -> Result<u64, WireError> {
        object
            .get(name)
            .and_then(Value::as_number)
            .and_then(yw_json::Number::as_u64)
            .filter(|value| *value <= max)
            .ok_or(WireError::Shape)
    };
    let slot = |name: &str| -> Result<u32, WireError> {
        u32::try_from(number(name, SLOT_MAX)?).map_err(|_| WireError::Shape)
    };
    match kind {
        "press" => {
            members(&["rev", "slot"])?;
            Ok(Input::Press {
                rev: number("rev", u64::MAX)?,
                slot: slot("slot")?,
            })
        }
        "edit" => {
            members(&["rev", "slot", "text"])?;
            let text = object
                .get("text")
                .and_then(Value::as_str)
                .ok_or(WireError::Shape)?;
            Ok(Input::Edit {
                rev: number("rev", u64::MAX)?,
                slot: slot("slot")?,
                text: Zeroizing::new(text.to_owned()),
            })
        }
        "rendered" => {
            members(&["rev", "focus", "of"])?;
            let focus = match (object.get("focus"), object.get("of")) {
                (Some(Value::Null), Some(Value::Null)) => None,
                _ => Some((number("of", u64::MAX)?, slot("focus")?)),
            };
            Ok(Input::Rendered {
                rev: number("rev", u64::MAX)?,
                focus,
            })
        }
        "life" => {
            members(&["e"])?;
            let word = object
                .get("e")
                .and_then(Value::as_str)
                .ok_or(WireError::Shape)?;
            Life::ALL
                .into_iter()
                .find(|life| life.word() == word)
                .map(Input::Life)
                .ok_or(WireError::Shape)
        }
        "tick" => {
            members(&[])?;
            Ok(Input::Tick)
        }
        "timer" => {
            members(&["id"])?;
            let word = object
                .get("id")
                .and_then(Value::as_str)
                .ok_or(WireError::Shape)?;
            TIMERS
                .into_iter()
                .find(|timer| timer_word(*timer) == word)
                .map(Input::Timer)
                .ok_or(WireError::Shape)
        }
        "copied" => {
            members(&["id", "ok"])?;
            let ok = object
                .get("ok")
                .and_then(Value::as_bool)
                .ok_or(WireError::Shape)?;
            Ok(Input::Copied {
                id: number("id", u64::MAX)?,
                ok,
            })
        }
        _ => Err(WireError::Shape),
    }
}

/// What became of one input ([`crate::wallet::Wallet::on_input`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputOutcome {
    /// Resolved and handed to the logic.
    Done,
    /// Of another model than the one drawn last, or a newer model is queued: dropped.
    Stale,
    /// The item that holds the pressed control is not built the same any more: dropped, and a
    /// redraw is queued.
    Changed,
    /// No such slot, or a control that cannot take this input: dropped.
    Refused,
    /// A lifetime event the shell acts on itself as well (spec/15 §5.4: the background and
    /// screen-off locks are the shell's compositions).
    Life(Life),
    /// Not the engine's input: a copy answer (the shell keeps the copy's mark) or the main timer
    /// (the shell sends its parts, [`TICK_PARTS`]).
    NotMine,
}

/// The engine's wire state: the revision counter and the model drawn last.
#[derive(Debug, Default)]
pub struct WireState {
    /// The revision of the last model handed out (0: none yet).
    pub(crate) rev: u64,
    /// That model.
    pub(crate) drawn: Option<Drawn>,
    /// The model before it (a render's answer names the focused edit in the model the shell
    /// showed before it drew the new one).
    pub(crate) previous: Option<Drawn>,
    /// The edits taken per slot of the drawn model since the shell last answered its render
    /// (2026-11-25 A2-6 review; module doc).
    pub(crate) seen: std::collections::BTreeMap<u32, u64>,
    /// The drawn model's render was answered and its edit texts are not handed back yet
    /// ([`crate::wallet::Wallet::take_edit_sync`]), with the field that had the focus.
    pub(crate) sync: Option<(u64, Option<EditField>)>,
}

/// What the plain edits of the drawn model must show after the shell answered its render
/// (2026-11-25 A2-6 review; module doc). Not `Clone`; the texts are wiped on drop, and `Debug`
/// prints slots and lengths only.
pub struct EditSync {
    /// The model's revision.
    pub rev: u64,
    /// Each drawn plain edit whose text differs from its model text, by slot, with the text it
    /// shows (the engine's form state).
    pub fields: Vec<(u32, Zeroizing<String>)>,
    /// The slot the field that had the focus is drawn at now (`None`: none had it, or it is not
    /// drawn as an edit that takes input).
    pub focus: Option<u32>,
}

impl fmt::Debug for EditSync {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EditSync")
            .field("rev", &self.rev)
            .field(
                "fields",
                &self
                    .fields
                    .iter()
                    .map(|(slot, text)| (*slot, text.len()))
                    .collect::<Vec<_>>(),
            )
            .field("focus", &self.focus)
            .finish()
    }
}

/// Whether plain field `field`'s text may go on the wire (module doc): every field but the
/// `WalletConnect` pairing link, which carries the pairing `symKey` (spec/15 §12.2).
#[must_use]
pub const fn field_on_wire(field: EditField) -> bool {
    !matches!(field, EditField::WcUri)
}

/// What a slot's control may take: a press (a button, link, check box or radio, enabled), or a
/// plain edit's text (enabled, not read-only). Every other combination is refused.
pub(crate) fn takes_press(slot: &SlotInfo) -> bool {
    slot.enabled && matches!(slot.act, Act::Press(_)) && !matches!(slot.kind, CtlKind::Edit { .. })
}

/// See [`takes_press`]; a field that never goes on the wire ([`field_on_wire`]) takes no text.
pub(crate) fn takes_edit(slot: &SlotInfo) -> bool {
    slot.enabled
        && matches!(slot.act, Act::Field(field) if field_on_wire(field))
        && matches!(
            slot.kind,
            CtlKind::Edit {
                readonly: false,
                ..
            }
        )
}

/// The item a slot's control is in, rebuilt now, is the one drawn (see the module doc); `now`
/// is wiped of what never goes on the wire first, as the drawn record was ([`model::scrub`]).
pub(crate) fn item_unchanged(drawn: &Drawn, slot: &SlotInfo, now: &mut [Item]) -> bool {
    model::scrub(now);
    drawn.items().get(slot.item) == now.get(slot.item)
}

#[cfg(test)]
mod tests;
