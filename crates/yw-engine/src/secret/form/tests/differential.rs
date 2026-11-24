//! The differential test of S5-7 (2026-11-24, spec/15 §11.4 S5-7; spec/04 §4.3): the neutral
//! entries `SecretForm::on_key(SecretKey)` and `SecretForm::on_pointer(SecretPointer)`, fed by the
//! Windows map `ui::secret_input`, against a copy of the entries they replaced, kept here only as
//! the reference (`old_on_char`, `old_on_key`, `old_mouse_down`, `old_mouse_move`,
//! `old_mouse_up`: the bodies at `3949186` with `self` as `form` and the form's hit rects as a
//! parameter). Two forms are built the same way; one gets the old entry, the other the map and
//! the new entry; then the action, the shell's reply and every field of the two forms must be
//! the same. Every virtual-key code 0–255 with each of the eight Ctrl/Shift/Alt sets, `WM_CHAR`
//! units 0–0x2FF and edge units, on the windows and states the form treats apart (every kind;
//! fresh, typed, last field, busy, paused after a wrong password, not excluded, masked; display
//! with copy on and off), lock-step key sequences, and pointer press-move-move-release sequences
//! over a layout whose rects overlap (a field and its `보기`, the checkbox and the primary
//! button), so first-hit and any-hit differ. Test values only.
//!
//! 2026-11-24 (spec/15 §11.4 S5-8): moved here from yw-app `ui::secret::tests::differential` with
//! the form (the reference and the comparisons unchanged; the forms are built with
//! `PlatformFlags::WINDOWS`). The Windows map and hit layout the new entries are fed by are
//! yw-app's (`ui::secret_input`, which this crate cannot name), so this file keeps a copy of them
//! as they are at S5-7 (`a9006d1`/`90f8e0f`, unchanged by S5-8): [`map_secret_key`],
//! [`map_secret_char`], [`HitLayout`] with its `down`/`moved`/`up` and a [`Rect`] with
//! `yw_win::ui::Rect::contains`'s rule. yw-app's own table tests
//! (`ui::secret_input::tests`) pin the real map.

use yw_core::keyimport::ImportChain;
use yw_core::lang::Lang;
use yw_core::secret::{SecretString, Zeroizing};

use super::super::{CardSecretKind, DisplaySecret, FormAction, SecretForm, SecretKind};
use crate::screen::facts::PlatformFlags;
use crate::secret::input::{SecretButton, SecretKey, SecretPointer, SecretTarget};
use crate::secure_field::{PushResult, RejectReason};
use crate::yubikey::PinTarget;

// ---- a copy of yw-app `ui::secret_input` at S5-7 (the Windows map and hit layout) ----

/// `yw_win::ui::Rect` (its `contains`: left and top inclusive, right and bottom exclusive).
#[derive(Clone, Copy)]
struct Rect {
    x: i32,
    y: i32,
    w: i32,
    h: i32,
}

impl Rect {
    const fn new(x: i32, y: i32, w: i32, h: i32) -> Self {
        Self { x, y, w, h }
    }

    const fn contains(&self, px: i32, py: i32) -> bool {
        px >= self.x
            && py >= self.y
            && px < self.x.saturating_add(self.w)
            && py < self.y.saturating_add(self.h)
    }
}

const VK_C: u16 = 0x43;
const VK_V: u16 = 0x56;

/// yw-app `ui::secret_input::map_secret_key`.
const fn map_secret_key(vk: u16, ctrl: bool, shift: bool, alt: bool) -> SecretKey {
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

/// yw-app `ui::secret_input::map_secret_char`.
const fn map_secret_char(unit: u16) -> SecretKey {
    SecretKey::Char(unit)
}

/// yw-app `ui::secret_input::HitLayout`.
#[derive(Default)]
struct HitLayout {
    fields: Vec<Rect>,
    buttons: Vec<(SecretButton, Rect)>,
}

impl HitLayout {
    fn button_at(&self, x: i32, y: i32) -> Option<SecretButton> {
        self.buttons
            .iter()
            .find(|(_, rect)| rect.contains(x, y))
            .map(|(button, _)| *button)
    }

    fn down(&self, x: i32, y: i32) -> SecretPointer {
        SecretPointer::Down(
            self.fields
                .iter()
                .position(|rect| rect.contains(x, y))
                .map(SecretTarget::Field)
                .or_else(|| self.button_at(x, y).map(SecretTarget::Button)),
        )
    }

    fn moved(&self, x: i32, y: i32) -> SecretPointer {
        SecretPointer::Move(
            self.buttons
                .iter()
                .filter(|(_, rect)| rect.contains(x, y))
                .map(|(button, _)| *button)
                .collect(),
        )
    }

    fn up(&self, x: i32, y: i32) -> SecretPointer {
        SecretPointer::Up(self.button_at(x, y))
    }
}

const VK_TAB: u16 = 0x09;
const VK_ESCAPE: u16 = 0x1B;
const VK_INSERT: u16 = 0x2D;
const VK_PROCESSKEY: u16 = 0xE5;

// ---- the reference: the entries before S5-7, verbatim but `self` → `form` ----

/// `SecretForm::on_char` at `3949186`.
fn old_on_char(form: &mut SecretForm, unit: u16, now_ms: u64) -> FormAction {
    form.touch(now_ms);
    if unit >= 0x80 {
        return form.non_ascii(now_ms);
    }
    if !form.input_enabled(now_ms) {
        return FormAction::None;
    }
    match unit {
        0x08 => {
            if let Some(slot) = form.slots.get_mut(form.active)
                && slot.field.backspace()
            {
                form.error = None;
                form.backup_left = false;
                return FormAction::Redraw;
            }
            FormAction::None
        }
        0x0D => {
            if form.active.saturating_add(1) < form.slots.len() {
                form.active = form.active.saturating_add(1);
                FormAction::Redraw
            } else {
                form.submit(now_ms)
            }
        }
        0x20..=0x7E => {
            let Some(slot) = form.slots.get_mut(form.active) else {
                return FormAction::None;
            };
            match slot.field.push_unit(unit) {
                PushResult::Accepted => {
                    form.error = None;
                    form.backup_left = false;
                    FormAction::Redraw
                }
                PushResult::Rejected(RejectReason::NonAscii) => form.non_ascii(now_ms),
                PushResult::Full | PushResult::Rejected(_) => FormAction::None,
            }
        }
        _ => FormAction::None,
    }
}

/// `SecretForm::on_key` at `3949186`.
fn old_on_key(
    form: &mut SecretForm,
    vk: u16,
    ctrl: bool,
    shift: bool,
    alt: bool,
    now_ms: u64,
) -> FormAction {
    form.touch(now_ms);
    if vk == VK_PROCESSKEY {
        return form.non_ascii(now_ms);
    }
    if vk == VK_ESCAPE {
        return if form.busy {
            FormAction::None
        } else {
            form.cancel()
        };
    }
    if alt {
        return FormAction::None;
    }
    if (ctrl && vk == u16::from(b'V')) || (shift && vk == VK_INSERT) {
        return if form.kind.paste_allowed() && form.input_enabled(now_ms) {
            FormAction::Paste
        } else {
            FormAction::None
        };
    }
    if ctrl && vk == u16::from(b'C') {
        return if form.kind.is_display() {
            FormAction::Copy
        } else {
            FormAction::None
        };
    }
    if vk == VK_TAB && !ctrl {
        if form.kind == SecretKind::Mnemonic {
            return old_on_char(form, 0x20, now_ms);
        }
        let count = form.slots.len();
        if count > 0 {
            form.active = if shift {
                form.active
                    .checked_sub(1)
                    .unwrap_or(count.saturating_sub(1))
            } else {
                form.active.saturating_add(1) % count
            };
            return FormAction::Redraw;
        }
    }
    FormAction::None
}

/// `SecretForm::hit` at `3949186`.
fn old_hit(layout: &HitLayout, x: i32, y: i32) -> Option<SecretButton> {
    layout
        .buttons
        .iter()
        .find(|(_, rect)| rect.contains(x, y))
        .map(|(button, _)| *button)
}

/// `SecretForm::on_mouse_down` at `3949186`.
fn old_mouse_down(
    form: &mut SecretForm,
    layout: &HitLayout,
    x: i32,
    y: i32,
    now_ms: u64,
) -> (FormAction, bool) {
    form.touch(now_ms);
    form.masked = false;
    if let Some(index) = layout.fields.iter().position(|rect| rect.contains(x, y)) {
        form.active = index;
        return (FormAction::Redraw, false);
    }
    let Some(button) = old_hit(layout, x, y) else {
        return (FormAction::Redraw, false);
    };
    if !form.button_enabled(button, now_ms) {
        return (FormAction::None, false);
    }
    form.pressed = Some(button);
    match button {
        SecretButton::Primary if form.kind.needs_hold() => {
            form.hold.begin(now_ms);
            (FormAction::Redraw, true)
        }
        SecretButton::Reveal(index) => {
            form.revealing = Some(index);
            (FormAction::Redraw, true)
        }
        _ => (FormAction::Redraw, true),
    }
}

/// `SecretForm::on_mouse_move` at `3949186`.
fn old_mouse_move(form: &mut SecretForm, layout: &HitLayout, x: i32, y: i32) -> FormAction {
    let Some(pressed) = form.pressed else {
        return FormAction::None;
    };
    let inside = layout
        .buttons
        .iter()
        .any(|(button, rect)| *button == pressed && rect.contains(x, y));
    if !inside && (form.hold.active() || form.revealing.is_some()) {
        form.hold.cancel();
        form.revealing = None;
        return FormAction::Redraw;
    }
    FormAction::None
}

/// `SecretForm::on_mouse_up` at `3949186`.
fn old_mouse_up(
    form: &mut SecretForm,
    layout: &HitLayout,
    x: i32,
    y: i32,
    now_ms: u64,
) -> FormAction {
    form.touch(now_ms);
    let pressed = form.pressed.take();
    form.revealing = None;
    if form.hold.active() {
        form.hold.cancel();
        return FormAction::Redraw;
    }
    let Some(pressed) = pressed else {
        return FormAction::None;
    };
    if old_hit(layout, x, y) != Some(pressed) || !form.button_enabled(pressed, now_ms) {
        return FormAction::Redraw;
    }
    match pressed {
        SecretButton::Primary => form.submit(now_ms),
        SecretButton::Cancel => {
            if form.display.is_some() && !form.kind.needs_hold() {
                form.wipe();
                FormAction::Close
            } else {
                form.cancel()
            }
        }
        SecretButton::ClearAll => {
            for slot in &mut form.slots {
                slot.field.clear();
            }
            form.active = 0;
            form.error = None;
            FormAction::Redraw
        }
        SecretButton::Copy => FormAction::Copy,
        SecretButton::Checkbox => {
            if let Some((_, checked)) = form.checkbox.as_mut() {
                *checked = !*checked;
            }
            FormAction::Redraw
        }
        SecretButton::Reveal(_) => FormAction::Redraw,
    }
}

// ---- the states ----

/// Every window kind (the list of `every_secret_window_is_english_with_lang_en`).
fn kinds() -> Vec<SecretKind> {
    let mut kinds = vec![
        SecretKind::SetPassword,
        SecretKind::Unlock,
        SecretKind::ConfirmPassword,
        SecretKind::ChangePassword,
        SecretKind::Mnemonic,
        SecretKind::Passphrase { confirm: true },
        SecretKind::Passphrase { confirm: false },
        SecretKind::ShowMnemonic { create: true },
        SecretKind::ShowMnemonic { create: false },
        SecretKind::ShowKey,
        SecretKind::Backup {
            positions: [3, 7, 12, 24],
        },
        SecretKind::CardSecret(CardSecretKind::AdminPin),
        SecretKind::CardSecret(CardSecretKind::ManagementKey),
        SecretKind::CardSecret(CardSecretKind::PivPin),
        SecretKind::CardSecret(CardSecretKind::SetPins),
        SecretKind::CardSecret(CardSecretKind::UserPin { piv: false }),
        SecretKind::CardSecret(CardSecretKind::UserPin { piv: true }),
        SecretKind::CardSecret(CardSecretKind::ChangePin(PinTarget::PivPuk)),
        SecretKind::CardPin {
            min: 6,
            max: 8,
            touches: 2,
            per_tx: true,
            serial: 7,
        },
    ];
    for chain in [
        ImportChain::Evm,
        ImportChain::Sol,
        ImportChain::Btc,
        ImportChain::Zec,
    ] {
        kinds.push(SecretKind::PrivateKey {
            chain,
            no_words: false,
        });
    }
    kinds
}

/// How a state is reached from a fresh window.
#[derive(Clone, Copy, Debug)]
enum Variant {
    Fresh,
    /// Text typed into the first field (`a1 ` for W05, so a word ends).
    Typed,
    /// Text typed, then the last field active.
    LastField,
    /// A submitted job runs (`확인 중…`).
    Busy,
    /// Input paused after a wrong password (until 2 000 ms).
    Paused,
    /// Made without capture exclusion (an input window; a display window is always excluded).
    NotExcluded,
    /// Masked after focus loss.
    Masked,
    /// A display window with secret copy on.
    CopyOn,
}

const VARIANTS: [Variant; 8] = [
    Variant::Fresh,
    Variant::Typed,
    Variant::LastField,
    Variant::Busy,
    Variant::Paused,
    Variant::NotExcluded,
    Variant::Masked,
    Variant::CopyOn,
];

/// The time every event of the test is delivered at (inside `Paused`'s pause).
const NOW: u64 = 1_500;

fn build(kind: SecretKind, variant: Variant) -> SecretForm {
    let mut form = if kind.is_display() {
        SecretForm::display(
            kind,
            Lang::Ko,
            0,
            DisplaySecret {
                text: SecretString::from_zeroizing(Zeroizing::new("ab".repeat(32))),
                address: None,
                passphrase_note: false,
                copy_allowed: matches!(variant, Variant::CopyOn),
            },
            PlatformFlags::WINDOWS,
        )
    } else {
        SecretForm::new(
            kind,
            Lang::Ko,
            0,
            !matches!(variant, Variant::NotExcluded),
            PlatformFlags::WINDOWS,
        )
    };
    let typed = if kind == SecretKind::Mnemonic {
        "a1 "
    } else {
        "a1"
    };
    match variant {
        Variant::Typed | Variant::Busy | Variant::Paused | Variant::Masked => {
            for unit in typed.encode_utf16() {
                let _ = form.on_char(unit, 100);
            }
        }
        Variant::LastField => {
            for unit in typed.encode_utf16() {
                let _ = form.on_char(unit, 100);
            }
            form.active = form.slots.len().saturating_sub(1);
        }
        Variant::Fresh | Variant::NotExcluded | Variant::CopyOn => {}
    }
    match variant {
        Variant::Busy => form.set_busy(true),
        Variant::Paused => form.fail_password(1_000),
        Variant::Masked => {
            let _ = form.on_deactivate();
        }
        _ => {}
    }
    form
}

/// Every field of a form (test values only; never in a golden or a log).
fn snapshot(form: &SecretForm) -> String {
    let slots: Vec<String> = form
        .slots
        .iter()
        .map(|slot| {
            format!(
                "{}:{:?}:{}:{}",
                slot.label,
                slot.field.as_bytes(),
                slot.min,
                slot.masked
            )
        })
        .collect();
    format!(
        "kind={:?} lang={:?} active={} checkbox={:?} display={:?} error={:?} transient={:?} \
         info={:?} disabled_until={} busy={} revealing={:?} masked={} excluded={} started={} \
         last={} hold={:?} pressed={:?} note={:?} step={:?} details={:?} card={:?} \
         timeout_note={:?} countdown={} backup_left={} slots={slots:?}",
        form.kind,
        form.lang,
        form.active,
        form.checkbox,
        form.display
            .as_ref()
            .map(|display| (display.text.expose().to_owned(), display.copy_allowed)),
        form.error,
        form.transient,
        form.info,
        form.disabled_until,
        form.busy,
        form.revealing,
        form.masked,
        form.capture_excluded,
        form.started_ms,
        form.last_activity_ms,
        form.hold,
        form.pressed,
        form.note,
        form.step,
        form.details,
        form.card,
        form.timeout_note,
        form.countdown_secs,
        form.backup_left,
    )
}

/// An action with a submission's values (the `Debug` of `Submission` prints counts only).
fn action_text(action: &FormAction) -> String {
    match action {
        FormAction::Submit(submission) => format!(
            "Submit({:?}, {})",
            submission
                .values
                .iter()
                .map(|value| value.as_slice().to_vec())
                .collect::<Vec<_>>(),
            submission.checkbox
        ),
        other => format!("{other:?}"),
    }
}

/// The shell's reply to a `WM_KEYDOWN` (`on_secret`): the platform's on `None`.
fn key_reply(action: &FormAction) -> &'static str {
    if matches!(action, FormAction::None) {
        "Default"
    } else {
        "Handled"
    }
}

/// Differences found, with the first few described.
#[derive(Default)]
struct Diffs {
    count: usize,
    compared: usize,
    first: Vec<String>,
}

impl Diffs {
    #[expect(
        clippy::needless_pass_by_value,
        reason = "every call site builds the two tuples in place"
    )]
    fn check(&mut self, what: &str, old: (&str, String, String), new: (&str, String, String)) {
        self.compared += 1;
        if old != new {
            self.count += 1;
            if self.first.len() < 5 {
                self.first.push(format!("{what}: old {old:?} new {new:?}"));
            }
        }
    }
}

/// One key on a pair of freshly built forms.
fn key_pair(diffs: &mut Diffs, kind: SecretKind, variant: Variant, vk: u16, bits: u8) {
    let (ctrl, shift, alt) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
    let mut old = build(kind, variant);
    let mut new = build(kind, variant);
    let old_action = old_on_key(&mut old, vk, ctrl, shift, alt, NOW);
    let new_action = new.on_key(map_secret_key(vk, ctrl, shift, alt), NOW);
    diffs.check(
        &format!("{kind:?} {variant:?} vk {vk:#04x} bits {bits}"),
        (
            key_reply(&old_action),
            action_text(&old_action),
            snapshot(&old),
        ),
        (
            key_reply(&new_action),
            action_text(&new_action),
            snapshot(&new),
        ),
    );
}

/// One `WM_CHAR` unit on a pair of freshly built forms.
fn char_pair(diffs: &mut Diffs, kind: SecretKind, variant: Variant, unit: u16) {
    let mut old = build(kind, variant);
    let mut new = build(kind, variant);
    let old_action = old_on_char(&mut old, unit, NOW);
    let new_action = new.on_key(map_secret_char(unit), NOW);
    diffs.check(
        &format!("{kind:?} {variant:?} unit {unit:#06x}"),
        ("Handled", action_text(&old_action), snapshot(&old)),
        ("Handled", action_text(&new_action), snapshot(&new)),
    );
}

/// The windows whose every key and unit is compared (one of each family).
fn core_kinds() -> Vec<SecretKind> {
    vec![
        SecretKind::SetPassword,
        SecretKind::Unlock,
        SecretKind::Mnemonic,
        SecretKind::Passphrase { confirm: true },
        SecretKind::PrivateKey {
            chain: ImportChain::Evm,
            no_words: false,
        },
        SecretKind::ShowMnemonic { create: true },
        SecretKind::ShowKey,
        SecretKind::Backup {
            positions: [3, 7, 12, 24],
        },
        SecretKind::CardSecret(CardSecretKind::ManagementKey),
    ]
}

/// The units compared on every state besides 0–0x2FF on the core windows: controls, edges of the
/// printable range, non-ASCII, surrogates, the last unit.
const EDGE_UNITS: [u16; 16] = [
    0x00, 0x08, 0x09, 0x0D, 0x1B, 0x1F, 0x20, 0x41, 0x61, 0x7E, 0x7F, 0x80, 0xAC00, 0xD83D, 0xDC00,
    0xFFFF,
];

/// The virtual keys compared on every state besides 0–255 on the core windows: the six the map
/// names and some it does not.
const EDGE_KEYS: [u16; 10] = [0x09, 0x1B, 0x2D, 0x43, 0x56, 0xE5, 0x0D, 0x08, 0x41, 0x73];

#[test]
fn the_neutral_keys_decide_as_the_virtual_keys_did() {
    let mut diffs = Diffs::default();
    for kind in core_kinds() {
        for variant in VARIANTS {
            for vk in 0..=255_u16 {
                for bits in 0..8 {
                    key_pair(&mut diffs, kind, variant, vk, bits);
                }
            }
            for unit in (0..=0x2FF_u16).chain(EDGE_UNITS) {
                char_pair(&mut diffs, kind, variant, unit);
            }
        }
    }
    for kind in kinds() {
        for variant in VARIANTS {
            for vk in EDGE_KEYS {
                for bits in 0..8 {
                    key_pair(&mut diffs, kind, variant, vk, bits);
                }
            }
            for unit in EDGE_UNITS {
                char_pair(&mut diffs, kind, variant, unit);
            }
        }
    }
    assert!(diffs.compared > 150_000, "compared {}", diffs.compared);
    assert_eq!(diffs.count, 0, "{:#?}", diffs.first);
}

/// Lock-step sequences: the same 400 pseudo-random keys and units (a fixed LCG, biased to the
/// keys the form treats apart) on two forms of every state, compared after each.
#[test]
fn key_sequences_stay_in_step() {
    const KEYS: [u16; 9] = [0x09, 0x1B, 0x2D, 0x43, 0x56, 0xE5, 0x0D, 0x41, 0x08];
    const UNITS: [u16; 12] = [
        0x61, 0x62, 0x20, 0x30, 0x39, 0x08, 0x0D, 0x41, 0x78, 0x7F, 0xAC00, 0x2D,
    ];
    let mut diffs = Diffs::default();
    for kind in kinds() {
        for variant in VARIANTS {
            let mut old = build(kind, variant);
            let mut new = build(kind, variant);
            let mut seed = 0x2545_F491_u32;
            for step in 0..400_u64 {
                seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                let pick = usize::try_from(seed >> 16).unwrap_or(0);
                let now = NOW + step * 7;
                let what = format!("{kind:?} {variant:?} step {step}");
                if pick % 3 == 0 {
                    let vk = KEYS[(pick / 3) % KEYS.len()];
                    let bits = u8::try_from((pick / 31) % 8).unwrap_or(0);
                    let (ctrl, shift, alt) = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0);
                    let old_action = old_on_key(&mut old, vk, ctrl, shift, alt, now);
                    let new_action = new.on_key(map_secret_key(vk, ctrl, shift, alt), now);
                    diffs.check(
                        &what,
                        (
                            key_reply(&old_action),
                            action_text(&old_action),
                            snapshot(&old),
                        ),
                        (
                            key_reply(&new_action),
                            action_text(&new_action),
                            snapshot(&new),
                        ),
                    );
                } else {
                    let unit = UNITS[(pick / 3) % UNITS.len()];
                    let old_action = old_on_char(&mut old, unit, now);
                    let new_action = new.on_key(map_secret_char(unit), now);
                    diffs.check(
                        &what,
                        ("Handled", action_text(&old_action), snapshot(&old)),
                        ("Handled", action_text(&new_action), snapshot(&new)),
                    );
                }
            }
        }
    }
    assert!(diffs.compared > 50_000, "compared {}", diffs.compared);
    assert_eq!(diffs.count, 0, "{:#?}", diffs.first);
}

/// A fixed layout with overlapping rects: field 0 and its `보기`, the checkbox and the primary
/// button.
fn layout() -> HitLayout {
    HitLayout {
        fields: vec![Rect::new(10, 10, 200, 30), Rect::new(10, 50, 200, 30)],
        buttons: vec![
            (SecretButton::Reveal(0), Rect::new(180, 10, 60, 30)),
            (SecretButton::Reveal(1), Rect::new(220, 50, 60, 30)),
            (SecretButton::Checkbox, Rect::new(10, 90, 120, 20)),
            (SecretButton::Primary, Rect::new(100, 95, 100, 40)),
            (SecretButton::Cancel, Rect::new(210, 100, 80, 40)),
            (SecretButton::ClearAll, Rect::new(10, 140, 80, 30)),
            (SecretButton::Copy, Rect::new(100, 140, 80, 30)),
        ],
    }
}

/// Points on every region, the overlaps and nothing.
const POINTS: [(i32, i32); 16] = [
    (15, 15),
    (190, 15),
    (230, 15),
    (15, 55),
    (230, 55),
    (15, 92),
    (110, 92),
    (110, 100),
    (150, 120),
    (220, 110),
    (20, 150),
    (110, 150),
    (300, 300),
    (0, 0),
    (209, 39),
    (99, 109),
];

#[test]
fn the_neutral_pointer_decides_as_the_pixels_did() {
    let layout = layout();
    let mut diffs = Diffs::default();
    for kind in kinds() {
        for variant in VARIANTS {
            for (index, &(x1, y1)) in POINTS.iter().enumerate() {
                for (other, &(x2, y2)) in POINTS.iter().enumerate() {
                    let mut old = build(kind, variant);
                    let mut new = build(kind, variant);
                    let what = format!("{kind:?} {variant:?} {index}->{other}");
                    let (old_action, old_capture) = old_mouse_down(&mut old, &layout, x1, y1, NOW);
                    let (new_action, new_capture) = new.on_pointer(layout.down(x1, y1), NOW);
                    diffs.check(
                        &format!("{what} down"),
                        (
                            if old_capture { "capture" } else { "-" },
                            action_text(&old_action),
                            snapshot(&old),
                        ),
                        (
                            if new_capture { "capture" } else { "-" },
                            action_text(&new_action),
                            snapshot(&new),
                        ),
                    );
                    for (step, &(x, y)) in [(x2, y2), (x1, y1)].iter().enumerate() {
                        let old_action = old_mouse_move(&mut old, &layout, x, y);
                        let (new_action, new_capture) = new.on_pointer(layout.moved(x, y), NOW);
                        diffs.check(
                            &format!("{what} move {step}"),
                            ("-", action_text(&old_action), snapshot(&old)),
                            (
                                if new_capture { "capture" } else { "-" },
                                action_text(&new_action),
                                snapshot(&new),
                            ),
                        );
                    }
                    // Released at once or after the 2 s hold.
                    let up = NOW + if other % 2 == 0 { 10 } else { 2_100 };
                    let old_action = old_mouse_up(&mut old, &layout, x2, y2, up);
                    let (new_action, new_capture) = new.on_pointer(layout.up(x2, y2), up);
                    diffs.check(
                        &format!("{what} up"),
                        ("-", action_text(&old_action), snapshot(&old)),
                        (
                            if new_capture { "capture" } else { "-" },
                            action_text(&new_action),
                            snapshot(&new),
                        ),
                    );
                }
            }
        }
    }
    assert!(diffs.compared > 100_000, "compared {}", diffs.compared);
    assert_eq!(diffs.count, 0, "{:#?}", diffs.first);
}

/// The reference sees what the new entries see: a mutation of the copy (Shift+Tab forward) is
/// found, so the comparison can fail.
#[test]
fn the_comparison_can_fail() {
    let mut old = build(SecretKind::ChangePassword, Variant::LastField);
    let mut new = build(SecretKind::ChangePassword, Variant::LastField);
    let _ = old_on_key(&mut old, VK_TAB, false, false, false, NOW);
    let _ = new.on_key(map_secret_key(VK_TAB, false, true, false), NOW);
    assert_ne!(snapshot(&old), snapshot(&new));
    let mut empty = build(SecretKind::ShowKey, Variant::Fresh);
    assert_eq!(empty.slots.len(), 0, "a display window has no field");
    assert!(matches!(
        empty.on_key(map_secret_key(VK_TAB, false, false, false), NOW),
        FormAction::None
    ));
}
