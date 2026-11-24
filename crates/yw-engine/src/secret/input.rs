//! A secret window's input as neutral events (spec/04 §4.3, spec/15 §3.2 `secretKey`, §11.4 S5).
//!
//! 2026-11-24 (spec/15 §11.4 S5-7): the secret windows' form (`SecretForm`, yw-app `ui::secret`
//! until S5-8) takes these events instead of Windows virtual-key codes and pixel positions. The
//! Windows shell maps a `WM_KEYDOWN` with its modifier state and a `WM_CHAR` unit into a
//! [`SecretKey`] (yw-app `ui::secret_input::map_secret_key`, the precedence the form applied to the
//! virtual-key code itself before), and hit-tests a pointer message against the layout its last
//! paint returned into a [`SecretPointer`]. The Android shell's Rust side will build the same
//! events from `secretKey(field, codeUnit)` and its view's touches.
//!
//! None of these is ever a `Cmd` or an `Effect`: a key is applied in-process to the window's form,
//! and a [`SecretKey::Char`] holds one typed unit of a secret, so its `Debug` prints no unit.

use core::fmt;

/// One key of a secret window, after the shell's mapping (spec/04 §4.3).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SecretKey {
    /// One UTF-16 unit (Windows `WM_CHAR`; Android `secretKey`'s `codeUnit`): 0x20–0x7E typed,
    /// 0x08 Backspace, 0x0D Enter, ≥ 0x80 refused with E-INP-008, any other ignored.
    Char(u16),
    /// Esc, whatever modifier is down: wipe and close (ignored while a submitted job runs).
    Escape,
    /// Tab without Ctrl; `back` is Shift (W05: the next word field).
    Tab {
        /// Shift+Tab.
        back: bool,
    },
    /// Ctrl+V or Shift+Insert with Alt up: paste (spec/04 §4.7), where the window allows it.
    Paste,
    /// Ctrl+C with Alt up: copy (W08·W09 only, spec/04 §4.8).
    Copy,
    /// A key the IME is processing (Windows `VK_PROCESSKEY`, `WM_IME_STARTCOMPOSITION`): E-INP-008
    /// (spec/04 §4.6).
    Composition,
    /// Any other key-down: only the inactivity clock is touched, and the shell lets its
    /// platform handle the key (Windows: `DefWindowProc`, so Alt+F4 still closes).
    Other,
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // A typed unit of a secret: never printed.
            Self::Char(_) => formatter.write_str("Char"),
            Self::Escape => formatter.write_str("Escape"),
            Self::Tab { back } => write!(formatter, "Tab {{ back: {back} }}"),
            Self::Paste => formatter.write_str("Paste"),
            Self::Copy => formatter.write_str("Copy"),
            Self::Composition => formatter.write_str("Composition"),
            Self::Other => formatter.write_str("Other"),
        }
    }
}

/// A button of a secret window (spec/04 §4: the button row, `보기` beside a masked field and the
/// acknowledgement checkbox). Was yw-app `ui::secret`'s private `Button` before 2026-11-24 (S5-7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretButton {
    /// The primary button (`확인`, `다음`, W08's `다 적었습니다`, `닫기`).
    Primary,
    /// `취소` (`나중에`).
    Cancel,
    /// `모두 지우기`.
    ClearAll,
    /// `복사` (W08·W09 with secret copy on).
    Copy,
    /// `보기` of field `n` (held).
    Reveal(usize),
    /// The acknowledgement checkbox.
    Checkbox,
}

/// What a pointer press landed on: a field (by its index) or a button.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretTarget {
    /// Field `n` (fields are hit before buttons).
    Field(usize),
    /// A button.
    Button(SecretButton),
}

/// One pointer event of a secret window, hit-tested by the shell against the layout it drew
/// (spec/04 §4.3 `WM_LBUTTONDOWN`, §4.9 the hold).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SecretPointer {
    /// Pressed: the first field under the pointer, else the first button, else nothing.
    Down(Option<SecretTarget>),
    /// Moved while pressed: every button under the pointer (a hold or a reveal ends when the
    /// pressed button is not among them).
    Move(Vec<SecretButton>),
    /// Released: the first button under the pointer (fields are not hit), else nothing.
    Up(Option<SecretButton>),
}

#[cfg(test)]
mod tests {
    use super::SecretKey;

    #[test]
    fn a_typed_unit_is_never_printed() {
        for unit in [0x20_u16, u16::from(b'a'), 0x7E, 0xAC00, 0xD83D] {
            assert_eq!(format!("{:?}", SecretKey::Char(unit)), "Char");
        }
        assert_eq!(
            format!("{:?}", SecretKey::Tab { back: true }),
            "Tab { back: true }"
        );
        for key in [
            SecretKey::Escape,
            SecretKey::Paste,
            SecretKey::Copy,
            SecretKey::Composition,
            SecretKey::Other,
        ] {
            let text = format!("{key:?}");
            assert!(text.chars().all(char::is_alphabetic), "{text}");
        }
    }
}
