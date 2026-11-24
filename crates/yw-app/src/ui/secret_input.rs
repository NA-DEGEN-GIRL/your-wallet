//! The secret windows' Windows input map (spec/04 §4.3; spec/15 §11.4 S5-7).
//!
//! 2026-11-24 (S5-7): the secret window's form (`ui::secret::SecretForm`) takes neutral events,
//! `yw_engine::secret::input::{SecretKey, SecretPointer}`. This module is the only place that
//! turns a Windows key message into a [`SecretKey`] ([`map_secret_key`], [`map_secret_char`],
//! [`ime_key`]) and a pointer message into a [`SecretPointer`] ([`HitLayout`], which the form's
//! paint returns and the shell keeps in its window record). Before, the form compared
//! virtual-key codes itself (`SecretForm::on_key(vk, ctrl, shift, alt)`) and hit-tested the pixel
//! rects it kept from its own paint (`on_mouse_down`/`on_mouse_move`/`on_mouse_up`); the
//! precedence below is that of its `on_key`, so Windows behaves as before (the differential test
//! `ui::secret::tests::differential`). Source check `secret_keys_are_mapped_only_by_the_mapper`.

use yw_engine::secret::input::{SecretButton, SecretKey, SecretPointer, SecretTarget};
use yw_win::ui::Rect;

const VK_TAB: u16 = 0x09;
const VK_ESCAPE: u16 = 0x1B;
const VK_INSERT: u16 = 0x2D;
const VK_PROCESSKEY: u16 = 0xE5;
const VK_C: u16 = 0x43;
const VK_V: u16 = 0x56;

/// A secret window's `WM_KEYDOWN` with the modifier state read at the message (Ctrl, Shift,
/// Alt), in the precedence the form applied before 2026-11-24 (S5-7): an IME key first, then Esc
/// whatever modifier is down, then nothing with Alt, then paste (Ctrl+V, Shift+Insert), copy
/// (Ctrl+C), Tab without Ctrl (Shift = back); any other key is [`SecretKey::Other`].
#[must_use]
pub const fn map_secret_key(vk: u16, ctrl: bool, shift: bool, alt: bool) -> SecretKey {
    if vk == VK_PROCESSKEY {
        return SecretKey::Composition;
    }
    if vk == VK_ESCAPE {
        return SecretKey::Escape;
    }
    if alt {
        return SecretKey::Other;
    }
    if (ctrl && vk == VK_V) || (shift && vk == VK_INSERT) {
        return SecretKey::Paste;
    }
    if ctrl && vk == VK_C {
        return SecretKey::Copy;
    }
    if vk == VK_TAB && !ctrl {
        return SecretKey::Tab { back: shift };
    }
    SecretKey::Other
}

/// A secret window's `WM_CHAR` unit.
#[must_use]
pub const fn map_secret_char(unit: u16) -> SecretKey {
    SecretKey::Char(unit)
}

/// A secret window's `Msg::ImeAttempt` (`WM_IME_STARTCOMPOSITION`, spec/04 §4.6): the IME key
/// (before 2026-11-24, `on_key(VK_PROCESSKEY, false, false, false)`).
#[must_use]
pub const fn ime_key() -> SecretKey {
    map_secret_key(VK_PROCESSKEY, false, false, false)
}

/// What a secret window's last paint drew where, in client pixels: the field boxes (W05: the
/// word grid as one) and the buttons, in paint order. The form's paint returns it and the shell
/// keeps it in its window record (`App::secret`); before 2026-11-24 (S5-7) the form kept it
/// (`Layout`). Empty until the first paint; a masked paint draws no field.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HitLayout {
    /// The field boxes, by field index.
    pub fields: Vec<Rect>,
    /// The buttons with their rects.
    pub buttons: Vec<(SecretButton, Rect)>,
}

impl HitLayout {
    /// The first button whose rect holds `(x, y)`.
    fn button_at(&self, x: i32, y: i32) -> Option<SecretButton> {
        self.buttons
            .iter()
            .find(|(_, rect)| rect.contains(x, y))
            .map(|(button, _)| *button)
    }

    /// `WM_LBUTTONDOWN` at `(x, y)`: the first field there, else the first button.
    #[must_use]
    pub fn down(&self, x: i32, y: i32) -> SecretPointer {
        SecretPointer::Down(
            self.fields
                .iter()
                .position(|rect| rect.contains(x, y))
                .map(SecretTarget::Field)
                .or_else(|| self.button_at(x, y).map(SecretTarget::Button)),
        )
    }

    /// `WM_MOUSEMOVE` at `(x, y)`: every button there.
    #[must_use]
    pub fn moved(&self, x: i32, y: i32) -> SecretPointer {
        SecretPointer::Move(
            self.buttons
                .iter()
                .filter(|(_, rect)| rect.contains(x, y))
                .map(|(button, _)| *button)
                .collect(),
        )
    }

    /// `WM_LBUTTONUP` at `(x, y)`: the first button there (fields are not hit).
    #[must_use]
    pub fn up(&self, x: i32, y: i32) -> SecretPointer {
        SecretPointer::Up(self.button_at(x, y))
    }
}

#[cfg(test)]
mod tests {
    use super::{HitLayout, ime_key, map_secret_char, map_secret_key};
    use yw_engine::secret::input::{SecretButton, SecretKey, SecretPointer, SecretTarget};
    use yw_win::ui::Rect;

    /// The map's table (spec/04 §4.3, the neutral column): every key and modifier set the form
    /// treats apart, the precedence edges (Alt+Esc, Ctrl+Shift+Tab, Shift+Insert with Ctrl,
    /// Alt+Ctrl+V, an IME key with any modifier) and keys that are `Other`.
    #[test]
    fn the_key_map_keeps_the_forms_precedence() {
        let other = SecretKey::Other;
        let rows: [(u16, bool, bool, bool, SecretKey); 30] = [
            (0xE5, false, false, false, SecretKey::Composition),
            (0xE5, true, true, true, SecretKey::Composition),
            (0x1B, false, false, false, SecretKey::Escape),
            (0x1B, false, false, true, SecretKey::Escape),
            (0x1B, true, true, false, SecretKey::Escape),
            (0x1B, true, true, true, SecretKey::Escape),
            (0x56, true, false, false, SecretKey::Paste),
            (0x56, true, true, false, SecretKey::Paste),
            (0x56, true, false, true, other),
            (0x56, false, false, false, other),
            (0x56, false, true, false, other),
            (0x2D, false, true, false, SecretKey::Paste),
            (0x2D, true, true, false, SecretKey::Paste),
            (0x2D, true, false, false, other),
            (0x2D, false, true, true, other),
            (0x43, true, false, false, SecretKey::Copy),
            (0x43, true, true, false, SecretKey::Copy),
            (0x43, true, false, true, other),
            (0x43, false, false, false, other),
            (0x09, false, false, false, SecretKey::Tab { back: false }),
            (0x09, false, true, false, SecretKey::Tab { back: true }),
            (0x09, true, false, false, other),
            (0x09, true, true, false, other),
            (0x09, false, false, true, other),
            (0x0D, false, false, false, other),
            (0x08, false, false, false, other),
            (0x41, false, false, false, other),
            (0x73, false, false, true, other),
            (0x00, false, false, false, other),
            (0xFF, true, true, true, other),
        ];
        for (vk, ctrl, shift, alt, key) in rows {
            assert_eq!(
                map_secret_key(vk, ctrl, shift, alt),
                key,
                "vk {vk:#04x} ctrl {ctrl} shift {shift} alt {alt}"
            );
        }
        assert_eq!(ime_key(), SecretKey::Composition);
        for unit in [
            0_u16, 0x08, 0x0D, 0x20, 0x7E, 0x7F, 0x80, 0xAC00, 0xD83D, 0xFFFF,
        ] {
            assert_eq!(map_secret_char(unit), SecretKey::Char(unit));
        }
    }

    /// Every virtual-key code but the six the map names is `Other` with any modifiers.
    #[test]
    fn unnamed_keys_are_other() {
        for vk in 0..=u16::MAX {
            if matches!(vk, 0x09 | 0x1B | 0x2D | 0x43 | 0x56 | 0xE5) {
                continue;
            }
            for bits in 0..8_u8 {
                assert_eq!(
                    map_secret_key(vk, bits & 1 != 0, bits & 2 != 0, bits & 4 != 0),
                    SecretKey::Other,
                    "vk {vk:#06x} bits {bits}"
                );
            }
        }
    }

    /// The hit layout: fields before buttons on a press, every button on a move, the first
    /// button (never a field) on a release, nothing outside.
    #[test]
    fn the_hit_layout_finds_what_was_drawn() {
        let layout = HitLayout {
            fields: vec![Rect::new(0, 0, 100, 20), Rect::new(0, 30, 100, 20)],
            buttons: vec![
                (SecretButton::Reveal(0), Rect::new(90, 0, 30, 20)),
                (SecretButton::Checkbox, Rect::new(0, 60, 50, 20)),
                (SecretButton::Primary, Rect::new(40, 70, 60, 20)),
            ],
        };
        assert_eq!(
            layout.down(95, 5),
            SecretPointer::Down(Some(SecretTarget::Field(0)))
        );
        assert_eq!(
            layout.down(110, 5),
            SecretPointer::Down(Some(SecretTarget::Button(SecretButton::Reveal(0))))
        );
        assert_eq!(
            layout.down(45, 75),
            SecretPointer::Down(Some(SecretTarget::Button(SecretButton::Checkbox)))
        );
        assert_eq!(layout.down(500, 500), SecretPointer::Down(None));
        assert_eq!(
            layout.moved(45, 75),
            SecretPointer::Move(vec![SecretButton::Checkbox, SecretButton::Primary])
        );
        assert_eq!(layout.moved(500, 500), SecretPointer::Move(Vec::new()));
        assert_eq!(
            layout.up(95, 5),
            SecretPointer::Up(Some(SecretButton::Reveal(0)))
        );
        assert_eq!(layout.up(5, 5), SecretPointer::Up(None));
        assert_eq!(HitLayout::default().down(0, 0), SecretPointer::Down(None));
    }
}
