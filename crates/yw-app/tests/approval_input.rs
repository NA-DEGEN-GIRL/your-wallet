//! AP-2, the Win32 half (spec/04 §3.4, §3.9): which approval-window messages are stray presses.
//! The interaction half (a stray press restarts the arm delay and counts for the press gap) is
//! `ap2_right_middle_x_and_non_client_clicks_restart_the_arm_delay` in
//! `tests/approval_interaction.rs`. 2026-11-17 (spec/15 §11.4 S2): split from that test when
//! `stray_press` moved to `ui::approval_input`; this file stays with the Windows shell.

use yw_app::ui::approval_input::stray_press;
use yw_app::ui::interaction::InteractionEvent;
use yw_win::ui::Msg;

#[test]
fn ap2_right_middle_x_and_non_client_clicks_are_stray_presses() {
    // Every mouse button in the client area other than the left one and any press on the title
    // bar, caption buttons, frame or scroll bar is a press (spec/04 §3.4).
    for msg in [Msg::OtherButtonDown, Msg::NonClientButtonDown] {
        assert_eq!(
            stray_press(&msg),
            Some(InteractionEvent::OtherPress),
            "{msg:?}"
        );
    }
    // Releases, moves, the left button and everything else map to nothing here (the left button
    // has its own `MouseDown` arm).
    for msg in [
        Msg::MouseDown { x: 1, y: 1 },
        Msg::MouseUp { x: 1, y: 1 },
        Msg::MouseMove { x: 1, y: 1 },
        Msg::MouseActivate,
        Msg::Wheel(120),
        Msg::Paint,
        Msg::Timer(1),
    ] {
        assert_eq!(stray_press(&msg), None, "{msg:?}");
    }
}
