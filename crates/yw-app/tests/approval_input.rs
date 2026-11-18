//! AP-2, the Win32 half (spec/04 §3.4, §3.9): which approval-window messages are stray presses.
//! The interaction half (a stray press restarts the arm delay and counts for the press gap) is
//! `ap2_right_middle_x_and_non_client_clicks_restart_the_arm_delay` in yw-engine
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

/// Every `Msg` value the tests below try: one of each variant. The `match` fails to compile when
/// yw-win adds a variant, so a new message kind cannot slip past the stray-press map unseen.
fn every_msg() -> Vec<Msg> {
    let all = vec![
        Msg::Create,
        Msg::Paint,
        Msg::Size { w: 800, h: 700 },
        Msg::DpiChanged { dpi: 96 },
        Msg::ExitSizeMove,
        Msg::Char(0x41),
        Msg::KeyDown {
            vk: 0x0D,
            repeat: false,
        },
        Msg::KeyUp { vk: 0x20 },
        Msg::MouseDown { x: 1, y: 1 },
        Msg::MouseUp { x: 1, y: 1 },
        Msg::MouseMove { x: 1, y: 1 },
        Msg::OtherButtonDown,
        Msg::NonClientButtonDown,
        Msg::VScroll { code: 1 },
        Msg::Wheel(120),
        Msg::MouseActivate,
        Msg::Timer(7),
        Msg::Command { id: 1, code: 0 },
        Msg::ActivateApp(true),
        Msg::KillFocus { to_foreign: true },
        Msg::CaptureChanged,
        Msg::CancelMode,
        Msg::Close,
        Msg::Destroy,
        Msg::SessionLock,
        Msg::SessionUnlock,
        Msg::SessionDisconnect,
        Msg::SessionLogoff,
        Msg::Suspend,
        Msg::Resume,
        Msg::QueryEndSession,
        Msg::EndSession,
        Msg::ImeAttempt,
        Msg::App {
            msg: 0x8001,
            wparam: 0,
        },
    ];
    for msg in &all {
        match msg {
            Msg::Create
            | Msg::Paint
            | Msg::Size { .. }
            | Msg::DpiChanged { .. }
            | Msg::ExitSizeMove
            | Msg::Char(_)
            | Msg::KeyDown { .. }
            | Msg::KeyUp { .. }
            | Msg::MouseDown { .. }
            | Msg::MouseUp { .. }
            | Msg::MouseMove { .. }
            | Msg::OtherButtonDown
            | Msg::NonClientButtonDown
            | Msg::VScroll { .. }
            | Msg::Wheel(_)
            | Msg::MouseActivate
            | Msg::Timer(_)
            | Msg::Command { .. }
            | Msg::ActivateApp(_)
            | Msg::KillFocus { .. }
            | Msg::CaptureChanged
            | Msg::CancelMode
            | Msg::Close
            | Msg::Destroy
            | Msg::SessionLock
            | Msg::SessionUnlock
            | Msg::SessionDisconnect
            | Msg::SessionLogoff
            | Msg::Suspend
            | Msg::Resume
            | Msg::QueryEndSession
            | Msg::EndSession
            | Msg::ImeAttempt
            | Msg::App { .. } => {}
        }
    }
    all
}

/// 2026-11-18 (S4 A5, spec/15 §11.4 S4): over every message kind, only the other buttons and
/// the non-client presses are stray presses, and the map never yields an approving event; the
/// arms of the window that turn the rest into events (A01, panel, AI body) are pinned by the
/// App-level golden `app/tests/s4_flow/input.txt`.
#[test]
fn ap2_only_other_and_non_client_buttons_are_stray_presses_of_every_message_kind() {
    let mut stray = 0;
    for msg in every_msg() {
        let expected = matches!(msg, Msg::OtherButtonDown | Msg::NonClientButtonDown)
            .then_some(InteractionEvent::OtherPress);
        assert_eq!(stray_press(&msg), expected, "{msg:?}");
        stray += usize::from(expected.is_some());
    }
    assert_eq!(stray, 2);
}
