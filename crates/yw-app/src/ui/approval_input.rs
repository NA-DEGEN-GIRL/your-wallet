//! Win32 input of the approval window (spec/04 §3.4): the window messages that count as presses
//! for [`ApprovalInteraction`](crate::ui::interaction::ApprovalInteraction). 2026-11-17 (spec/15
//! §11.4 S2): [`stray_press`] moved here from `ui::interaction`, which no longer names a `yw_win`
//! type; the interaction rules themselves are unchanged.

use yw_win::ui::Msg;

use crate::ui::interaction::InteractionEvent;

/// The approval-window (and panel) messages that are presses with no approval meaning of their
/// own: a right, middle or X button press in the client area, and any button press on the
/// non-client area (title bar, caption buttons, frame, scroll bar). They count as
/// [`InteractionEvent::OtherPress`] (press-gap rule, arm-delay restart while not armed); the window
/// still lets the system handle the message (`Reply::Default`).
#[must_use]
pub const fn stray_press(msg: &Msg) -> Option<InteractionEvent> {
    match msg {
        Msg::OtherButtonDown | Msg::NonClientButtonDown => Some(InteractionEvent::OtherPress),
        _ => None,
    }
}
