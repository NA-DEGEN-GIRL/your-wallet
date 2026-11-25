//! The Android secret windows' input map (spec/15 §9.2, §3.2 `secretKey`; 2026-11-25 A2-7): what
//! the app keyboard's keys and the secret window's buttons become for the engine's form
//! (`yw_engine::secret::form::SecretForm`), as the Windows map `ui::secret_input` does for its
//! messages (spec/04 §4.3). This file and the engine's `secret::input` are the only ones of this
//! crate that name a key or pointer event; the screen host feeds what it returns to the form in
//! one place (`secret_host::feed`; yw-app source check `secret_keys_are_mapped_only_by_the_mapper`).
//!
//! - A key: `secretKey(field, codeUnit)` ([`decode_key`]). `field` is a token Java built from the
//!   model: the window id (the Activity instance, spec/15 §9.1 N23) in bits 8–30 and the target in
//!   bits 0–7 — a field index (0–[`FIELD_MAX`]) or [`TARGET_PICK`], W05's completion
//!   `codeUnit` (spec/15 §9.2 N22: picked by its index, never by the word). A key goes in as typed
//!   only on the form's active field (0x08 Backspace, 0x0D Enter, 0x20–0x7E the character; the
//!   form refuses anything else, ≥ 0x80 with E-INP-008); a key naming another field is dropped
//!   ([`key_steps`]): Java names the field active in the last model it drew, so after Enter moved
//!   the active field and before Java drew that, the key is stale (spec/15 §18 8: stale input is
//!   dropped). Only a tap on a field box (`s_btn` `field` `down`) makes another field active.
//!   2026-11-25 A2-7 review: before, such a key first pressed its field back to active and was
//!   typed there (12 units, Enter, then a key on field 0 went into field 0).
//! - A button input ([`button_steps`]): a press, a release inside (`up`) or the finger leaving it
//!   (`out`, the hold and the reveal end). Focus (`focus`) masks the plaintext windows when lost
//!   and shows them again when back; the Back key is Esc ([`back_steps`]).
//!
//! No event here is a `Cmd` or an `Effect`; [`KeyEvent`]'s `Debug` shows no unit. Platform-neutral
//! (no `unsafe`): the gate's Windows build tests the tables.
#![forbid(unsafe_code)]

use core::fmt;

use yw_engine::secret::form::WORD_CANDIDATES_MAX;
use yw_engine::secret::input::{SecretButton, SecretKey, SecretPointer, SecretTarget};

/// Bits of a field token below the window id.
pub const TARGET_BITS: u32 = 8;
/// The largest window id a field token or a fill handle carries (the token stays a positive
/// Java `int`).
pub const WIN_MAX: u32 = (1 << 23) - 1;
/// The largest field index a token names (no window has more than four fields).
pub const FIELD_MAX: u8 = 0x3F;
/// The token target that picks W05's completion `codeUnit` (0-based).
pub const TARGET_PICK: u8 = 0x40;

/// What a key goes to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyTarget {
    /// The field at this index.
    Field(usize),
    /// W05's completion of the word being typed (the unit is its index).
    Pick,
}

/// One `secretKey` call, decoded. Its `Debug` shows the window and the target, never the unit.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// The window (Activity instance) the key was typed in.
    pub win: u32,
    /// The field or the completion row.
    pub target: KeyTarget,
    /// The typed unit, or the completion's index.
    pub unit: u16,
}

impl fmt::Debug for KeyEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyEvent")
            .field("win", &self.win)
            .field("target", &self.target)
            .finish_non_exhaustive()
    }
}

/// The field token of `target` in window `win` (what Java builds, `SecretWire.field`).
#[must_use]
pub const fn field_token(win: u32, target: u8) -> i32 {
    ((win & WIN_MAX) << TARGET_BITS | target as u32).cast_signed()
}

/// Decodes `secretKey(field, codeUnit)`; `None` for a token with no window, an unknown target, a
/// unit outside UTF-16 or a completion index past [`WORD_CANDIDATES_MAX`].
#[must_use]
pub fn decode_key(field: i32, code_unit: i32) -> Option<KeyEvent> {
    let token = u32::try_from(field).ok()?;
    let win = token >> TARGET_BITS;
    if win == 0 || win > WIN_MAX {
        return None;
    }
    let target = u8::try_from(token & 0xFF).ok()?;
    let unit = u16::try_from(code_unit).ok()?;
    let target = match target {
        index @ 0..=FIELD_MAX => KeyTarget::Field(usize::from(index)),
        TARGET_PICK if usize::from(unit) < WORD_CANDIDATES_MAX => KeyTarget::Pick,
        _ => return None,
    };
    Some(KeyEvent { win, target, unit })
}

/// One step for the window's form, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// `SecretForm::on_key`.
    Key(SecretKey),
    /// `SecretForm::on_pointer`.
    Pointer(SecretPointer),
    /// `SecretForm::on_capture_lost` (the finger left a held button).
    CaptureLost,
    /// `SecretForm::on_deactivate` (the window lost the focus).
    Deactivate,
    /// `SecretForm::on_activate` (the focus is back).
    Activate,
}

/// The steps of `event` on a window whose active field is `active`: none for a key naming
/// another field (stale, module doc).
#[must_use]
pub fn key_steps(event: KeyEvent, active: usize) -> Vec<Step> {
    match event.target {
        KeyTarget::Field(index) if index == active => vec![Step::Key(SecretKey::Char(event.unit))],
        KeyTarget::Field(_) => Vec::new(),
        KeyTarget::Pick => u8::try_from(event.unit)
            .map(|index| vec![Step::Key(SecretKey::Pick(index))])
            .unwrap_or_default(),
    }
}

/// What a button input did to the button.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edge {
    /// Pressed.
    Down,
    /// Released on it.
    Up,
    /// The finger left it or the touch was cancelled.
    Out,
}

impl Edge {
    /// The wire word (`down`, `up`, `out`).
    #[must_use]
    pub fn from_word(word: &str) -> Option<Self> {
        match word {
            "down" => Some(Self::Down),
            "up" => Some(Self::Up),
            "out" => Some(Self::Out),
            _ => None,
        }
    }
}

/// What a button input names: a button of the row, a field's `보기`, the checkbox, or a field
/// box (a tap that makes it active).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Control {
    /// A button.
    Button(SecretButton),
    /// The field box at this index.
    Field(usize),
}

/// The control of the wire word `word` (and index `index` for `reveal` and `field`); `None` for
/// any other word. `copy` is no word: the Android build copies no secret (spec/15 §9.3).
#[must_use]
pub fn control(word: &str, index: usize) -> Option<Control> {
    let in_range = index <= usize::from(FIELD_MAX);
    match word {
        "primary" => Some(Control::Button(SecretButton::Primary)),
        "cancel" => Some(Control::Button(SecretButton::Cancel)),
        "clear" => Some(Control::Button(SecretButton::ClearAll)),
        "checkbox" => Some(Control::Button(SecretButton::Checkbox)),
        "reveal" if in_range => Some(Control::Button(SecretButton::Reveal(index))),
        "field" if in_range => Some(Control::Field(index)),
        _ => None,
    }
}

/// The wire word of a button the model draws (`None`: the Android model draws no such button).
#[must_use]
pub const fn button_word(button: SecretButton) -> Option<&'static str> {
    match button {
        SecretButton::Primary => Some("primary"),
        SecretButton::Cancel => Some("cancel"),
        SecretButton::ClearAll => Some("clear"),
        SecretButton::Checkbox => Some("checkbox"),
        SecretButton::Reveal(_) => Some("reveal"),
        SecretButton::Copy => None,
    }
}

/// The steps of a button input: a press is a pointer down on the control, a release on it a
/// pointer up on it, a finger that left it ends a hold or a reveal. A field box only takes a
/// press (it becomes active).
#[must_use]
pub fn button_steps(control: Control, edge: Edge) -> Vec<Step> {
    match (control, edge) {
        (Control::Field(index), Edge::Down) => vec![Step::Pointer(SecretPointer::Down(Some(
            SecretTarget::Field(index),
        )))],
        (Control::Field(_), Edge::Up | Edge::Out) => Vec::new(),
        (Control::Button(button), Edge::Down) => vec![Step::Pointer(SecretPointer::Down(Some(
            SecretTarget::Button(button),
        )))],
        (Control::Button(button), Edge::Up) => {
            vec![Step::Pointer(SecretPointer::Up(Some(button)))]
        }
        (Control::Button(_), Edge::Out) => vec![Step::CaptureLost],
    }
}

/// The steps of the window's focus change.
#[must_use]
pub fn focus_steps(on: bool) -> Vec<Step> {
    vec![if on { Step::Activate } else { Step::Deactivate }]
}

/// The steps of the Back key: Esc (wipe and close; nothing while a submitted job runs).
#[must_use]
pub fn back_steps() -> Vec<Step> {
    vec![Step::Key(SecretKey::Escape)]
}

#[cfg(test)]
mod tests {
    use yw_engine::secret::input::{SecretButton, SecretKey, SecretPointer, SecretTarget};

    use super::{
        Control, Edge, FIELD_MAX, KeyEvent, KeyTarget, Step, TARGET_PICK, WIN_MAX, back_steps,
        button_steps, button_word, control, decode_key, field_token, focus_steps, key_steps,
    };

    /// The tokens Java builds (`SecretWire.field`, pinned by `JvmTests.secretInputs`).
    #[test]
    fn field_tokens_are_window_and_target() {
        assert_eq!(field_token(1, 0), 0x100);
        assert_eq!(field_token(7, 2), 0x702);
        assert_eq!(field_token(5, TARGET_PICK), 0x540);
        assert_eq!(field_token(WIN_MAX, FIELD_MAX), i32::MAX - 0xFF + 0x3F);
        assert!(field_token(WIN_MAX, 0xFF) > 0);
    }

    /// The key table: every accepted token and unit, and every refused one.
    #[test]
    fn the_key_table() {
        for (field, unit, expected) in [
            (0x100, 0x61, Some((1, KeyTarget::Field(0), 0x61))),
            (0x101, 0x08, Some((1, KeyTarget::Field(1), 0x08))),
            (0x23F, 0x0D, Some((2, KeyTarget::Field(0x3F), 0x0D))),
            (0x340, 0, Some((3, KeyTarget::Pick, 0))),
            (0x340, 3, Some((3, KeyTarget::Pick, 3))),
            (0x100, 0xAC00, Some((1, KeyTarget::Field(0), 0xAC00))),
            (0x100, 0xFFFF, Some((1, KeyTarget::Field(0), 0xFFFF))),
        ] {
            let decoded =
                decode_key(field, unit).map(|event| (event.win, event.target, event.unit));
            assert_eq!(decoded, expected, "{field:#x} {unit:#x}");
        }
        for (field, unit) in [
            (0x000, 0x61),
            (0x040, 0),
            (0x0FF, 0x61),
            (-1, 0x61),
            (i32::MIN, 0x61),
            (0x140, 4),
            (0x141, 0),
            (0x17F, 0x61),
            (0x1FF, 0x61),
            (0x100, -1),
            (0x100, 0x1_0000),
        ] {
            assert_eq!(decode_key(field, unit), None, "{field:#x} {unit:#x}");
        }
    }

    /// A key on the active field is the typed unit; a key on another field is stale and dropped
    /// (2026-11-25 A2-7 review: before, it first made that field active); a completion is picked
    /// by its index.
    #[test]
    fn key_steps_type_only_into_the_active_field() {
        let key = |target, unit| KeyEvent {
            win: 1,
            target,
            unit,
        };
        assert_eq!(
            key_steps(key(KeyTarget::Field(0), 0x61), 0),
            [Step::Key(SecretKey::Char(0x61))]
        );
        assert!(key_steps(key(KeyTarget::Field(1), 0x08), 0).is_empty());
        assert!(key_steps(key(KeyTarget::Field(0), 0x61), 1).is_empty());
        assert_eq!(
            key_steps(key(KeyTarget::Field(1), 0x08), 1),
            [Step::Key(SecretKey::Char(0x08))]
        );
        assert_eq!(
            key_steps(key(KeyTarget::Pick, 2), 0),
            [Step::Key(SecretKey::Pick(2))]
        );
        let shown = format!("{:?}", key(KeyTarget::Field(0), 0x61));
        assert!(!shown.contains("97") && !shown.contains("61"), "{shown}");
    }

    /// The button table: the words the model draws and Java sends back, and the steps.
    #[test]
    fn the_button_table() {
        for (word, index, expected) in [
            ("primary", 0, Some(Control::Button(SecretButton::Primary))),
            ("cancel", 9, Some(Control::Button(SecretButton::Cancel))),
            ("clear", 0, Some(Control::Button(SecretButton::ClearAll))),
            ("checkbox", 0, Some(Control::Button(SecretButton::Checkbox))),
            ("reveal", 1, Some(Control::Button(SecretButton::Reveal(1)))),
            ("field", 2, Some(Control::Field(2))),
            ("reveal", 0x40, None),
            ("field", 0x40, None),
            ("copy", 0, None),
            ("Primary", 0, None),
            ("", 0, None),
        ] {
            assert_eq!(control(word, index), expected, "{word} {index}");
        }
        for button in [
            SecretButton::Primary,
            SecretButton::Cancel,
            SecretButton::ClearAll,
            SecretButton::Checkbox,
            SecretButton::Reveal(3),
        ] {
            let word = button_word(button).unwrap();
            let index = if let SecretButton::Reveal(index) = button {
                index
            } else {
                0
            };
            assert_eq!(control(word, index), Some(Control::Button(button)));
        }
        assert_eq!(button_word(SecretButton::Copy), None);
        let primary = Control::Button(SecretButton::Primary);
        assert_eq!(
            button_steps(primary, Edge::Down),
            [Step::Pointer(SecretPointer::Down(Some(
                SecretTarget::Button(SecretButton::Primary)
            )))]
        );
        assert_eq!(
            button_steps(primary, Edge::Up),
            [Step::Pointer(SecretPointer::Up(Some(
                SecretButton::Primary
            )))]
        );
        assert_eq!(button_steps(primary, Edge::Out), [Step::CaptureLost]);
        assert_eq!(
            button_steps(Control::Field(1), Edge::Down),
            [Step::Pointer(SecretPointer::Down(Some(
                SecretTarget::Field(1)
            )))]
        );
        assert!(button_steps(Control::Field(1), Edge::Up).is_empty());
        assert_eq!(
            (
                Edge::from_word("down"),
                Edge::from_word("up"),
                Edge::from_word("out")
            ),
            (Some(Edge::Down), Some(Edge::Up), Some(Edge::Out))
        );
        assert_eq!(Edge::from_word("move"), None);
        assert_eq!(focus_steps(false), [Step::Deactivate]);
        assert_eq!(focus_steps(true), [Step::Activate]);
        assert_eq!(back_steps(), [Step::Key(SecretKey::Escape)]);
    }
}
