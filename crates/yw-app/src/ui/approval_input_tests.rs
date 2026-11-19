//! Table tests of the approval window's input map (2026-11-19, S4 B2; spec/04 §3.4, spec/15
//! §11.4 S4). One test per row of the spec/04 §3.4 table, plus the arms the table does not list
//! (stray presses, the activating click, keys that are not approval input, Tab, scrolling, the
//! panel and the AI body, no window). Pure: no window, no Win32 read; the shell's run of these
//! steps on real windows is pinned by `app/tests/s4_flow/input.txt` and `reentry.txt`.

use yw_win::ui::{Msg, Rect, Reply};

use super::{
    APPROVAL_TIMER_ID, BarHits, Facts, Focus, KeyScroll, MA_ACTIVATEANDEAT, Mapped, PanelHit,
    Pressed, SB_ENDSCROLL, ScrollGoal, Step, Surface, Trusted, TrustedSignals, VK_DOWN, VK_END,
    VK_ESCAPE, VK_HOME, VK_NEXT, VK_PRIOR, VK_RETURN, VK_SPACE, VK_TAB, VK_UP, is_release, map_key,
    map_msg, panel_click, panel_hit, stray_press, tab_order, tab_target, wheel_delta,
};
use crate::ui::interaction::InteractionEvent;

const OTHER: Step = Step::Event(InteractionEvent::OtherPress);
const VK_A: u16 = 0x41;
const NONE: TrustedSignals = TrustedSignals {
    foreground: false,
    foreground_raw: false,
    lbutton_down: false,
    space_down: false,
    shift_down: false,
    enter_in_message: false,
    injected: false,
};
const ALL: TrustedSignals = TrustedSignals {
    foreground: true,
    foreground_raw: true,
    lbutton_down: true,
    space_down: true,
    shift_down: true,
    enter_in_message: true,
    injected: false,
};
const NO_HIT: BarHits = BarHits {
    approve: false,
    reject: false,
    retry: false,
    ai_retry: false,
};

#[expect(
    clippy::unnecessary_wraps,
    reason = "the map takes `Option<Facts>`; these rows have a window"
)]
const fn facts(focus: Focus, pressed: Option<Pressed>, hits: BarHits) -> Option<Facts> {
    Some(Facts {
        focus,
        pressed,
        hits,
    })
}

#[expect(
    clippy::fn_params_excessive_bools,
    reason = "one rectangle test each, as `BarHits`"
)]
const fn on(approve: bool, reject: bool, retry: bool, ai_retry: bool) -> BarHits {
    BarHits {
        approve,
        reject,
        retry,
        ai_retry,
    }
}

fn a01(msg: Msg, facts: Option<Facts>) -> Mapped {
    map_msg(Surface::Approval, &msg, facts, NONE)
}

fn steps(steps: &[Step], reply: Reply) -> Mapped {
    Mapped {
        steps: steps.to_vec(),
        reply,
    }
}

/// One value of every `Msg` variant (the `match` breaks the build when yw-win adds one), and
/// (2026-11-19, S4 B2 review) the other values the map tells apart: each key it maps (and a
/// letter) with and without auto-repeat, the key-up of Enter, both `ActivateApp` and `KillFocus`
/// values, `SB_ENDSCROLL` and a timer that is not A01's.
fn every_msg() -> Vec<Msg> {
    let mut all = vec![
        Msg::Create,
        Msg::Paint,
        Msg::Size { w: 800, h: 700 },
        Msg::DpiChanged { dpi: 96 },
        Msg::ExitSizeMove,
        Msg::Char(0x41),
        Msg::KeyDown {
            vk: VK_RETURN,
            repeat: false,
        },
        Msg::KeyUp { vk: VK_SPACE },
        Msg::MouseDown { x: 1, y: 1 },
        Msg::MouseUp { x: 1, y: 1 },
        Msg::MouseMove { x: 1, y: 1 },
        Msg::OtherButtonDown,
        Msg::NonClientButtonDown,
        Msg::VScroll { code: 1 },
        Msg::Wheel(120),
        Msg::MouseActivate,
        Msg::Timer(APPROVAL_TIMER_ID),
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
    for vk in [
        VK_RETURN, VK_SPACE, VK_ESCAPE, VK_TAB, VK_A, VK_PRIOR, VK_NEXT, VK_HOME, VK_END, VK_UP,
        VK_DOWN,
    ] {
        for repeat in [false, true] {
            all.push(Msg::KeyDown { vk, repeat });
        }
    }
    all.extend([
        Msg::KeyUp { vk: VK_RETURN },
        Msg::ActivateApp(false),
        Msg::KillFocus { to_foreign: false },
        Msg::VScroll { code: SB_ENDSCROLL },
        Msg::Timer(99),
    ]);
    all
}

/// Whether `event` is approving or holding (built only from a sample, never by the map itself).
const fn trusted_only(event: InteractionEvent) -> bool {
    matches!(
        event,
        InteractionEvent::ApproveActivated { .. }
            | InteractionEvent::PointerPressed { .. }
            | InteractionEvent::PointerReleased { .. }
            | InteractionEvent::SpacePressed { .. }
            | InteractionEvent::SpaceReleased { .. }
    )
}

// ----- spec/04 §3.4 table, row by row ---------------------------------------------------------

/// Row 1: `WM_LBUTTONDOWN` on `승인` (+`SetCapture`) → `PointerPressed { inside, click_through:
/// !foreground, physical_down }`. Focus and capture come before the sample (critique A-7); no
/// `OtherPress` first.
#[test]
fn row_approve_press_is_a_sampled_pointer_press_after_focus_and_capture() {
    let hits = on(true, false, false, false);
    for focus in [Focus::Reject, Focus::Approve, Focus::Scroll] {
        assert_eq!(
            a01(Msg::MouseDown { x: 1, y: 1 }, facts(focus, None, hits)),
            steps(
                &[
                    Step::FocusReceiver,
                    Step::Press(Pressed::Approve),
                    Step::MoveFocus(Focus::Approve),
                    Step::Capture,
                    Step::Sampled(Trusted::PointerPressed),
                    Step::Invalidate,
                ],
                Reply::Handled(0),
            )
        );
    }
    for (raw, down) in [(false, false), (false, true), (true, false), (true, true)] {
        let signals = TrustedSignals {
            foreground_raw: raw,
            lbutton_down: down,
            ..NONE
        };
        assert_eq!(
            Trusted::PointerPressed.event(signals),
            InteractionEvent::PointerPressed {
                inside: true,
                click_through: !raw,
                physical_down: down,
            }
        );
    }
}

/// Row 2: `WM_MOUSEMOVE` while `승인` is pressed → `PointerMoved { inside }`; `WM_LBUTTONUP`
/// (+`ReleaseCapture`) → `PointerReleased { physical_down }`, the release before the sample
/// (critique A-8).
#[test]
fn row_captured_move_and_release() {
    for inside in [false, true] {
        let hits = on(inside, false, false, false);
        assert_eq!(
            a01(
                Msg::MouseMove { x: 1, y: 1 },
                facts(Focus::Approve, Some(Pressed::Approve), hits)
            ),
            steps(
                &[Step::Event(InteractionEvent::PointerMoved { inside })],
                Reply::Handled(0),
            )
        );
        assert_eq!(
            a01(
                Msg::MouseUp { x: 1, y: 1 },
                facts(Focus::Approve, Some(Pressed::Approve), hits)
            ),
            steps(
                &[
                    Step::Release,
                    Step::Unpress,
                    Step::Sampled(Trusted::PointerReleased),
                    Step::Invalidate,
                ],
                Reply::Handled(0),
            )
        );
    }
    // A move with another button pressed, or none, is nothing.
    for pressed in [None, Some(Pressed::Reject)] {
        assert_eq!(
            a01(
                Msg::MouseMove { x: 1, y: 1 },
                facts(Focus::Reject, pressed, on(true, true, true, true))
            ),
            steps(&[], Reply::Handled(0))
        );
    }
    for down in [false, true] {
        let signals = TrustedSignals {
            lbutton_down: down,
            ..NONE
        };
        assert_eq!(
            Trusted::PointerReleased.event(signals),
            InteractionEvent::PointerReleased {
                physical_down: down
            }
        );
    }
}

/// Row 3: Space with the focus on `승인`: `WM_KEYDOWN` → `SpacePressed { repeat, physical_down }`
/// (no `OtherPress` first), `WM_KEYUP` → `SpaceReleased { physical_down }`.
#[test]
fn row_space_on_approve() {
    for repeat in [false, true] {
        assert_eq!(
            map_key(VK_SPACE, repeat, facts(Focus::Approve, None, NO_HIT)),
            [Step::Sampled(Trusted::SpacePressed { repeat })]
        );
        for down in [false, true] {
            let signals = TrustedSignals {
                space_down: down,
                ..NONE
            };
            assert_eq!(
                Trusted::SpacePressed { repeat }.event(signals),
                InteractionEvent::SpacePressed {
                    repeat,
                    physical_down: down,
                }
            );
        }
    }
    assert_eq!(
        a01(
            Msg::KeyUp { vk: VK_SPACE },
            facts(Focus::Approve, None, NO_HIT)
        ),
        steps(&[Step::Sampled(Trusted::SpaceReleased)], Reply::Handled(0))
    );
    assert_eq!(
        Trusted::SpaceReleased.event(TrustedSignals {
            space_down: true,
            ..NONE
        }),
        InteractionEvent::SpaceReleased {
            physical_down: true
        }
    );
    // Space released elsewhere, or another key released, is nothing.
    for (vk, focus) in [(VK_SPACE, Focus::Reject), (VK_RETURN, Focus::Approve)] {
        assert_eq!(
            a01(Msg::KeyUp { vk }, facts(focus, None, NO_HIT)),
            steps(&[], Reply::Handled(0))
        );
    }
}

/// Row 4: Enter with the focus on `승인` → `ApproveActivated { physical }`, `physical` = Enter in
/// the message's key state **and** not injected (security review L5); auto-repeat included.
#[test]
fn row_enter_on_approve_is_physical_only_in_the_message_and_not_injected() {
    for repeat in [false, true] {
        assert_eq!(
            map_key(VK_RETURN, repeat, facts(Focus::Approve, None, NO_HIT)),
            [Step::Sampled(Trusted::ApproveEnter)]
        );
    }
    for (in_message, injected, physical) in [
        (false, false, false),
        (false, true, false),
        (true, true, false),
        (true, false, true),
    ] {
        let signals = TrustedSignals {
            enter_in_message: in_message,
            injected,
            ..ALL
        };
        assert_eq!(
            Trusted::ApproveEnter.event(signals),
            InteractionEvent::ApproveActivated { physical }
        );
    }
}

/// Row 5: `거부` click, Enter or Space on `거부` (not auto-repeated), Esc, the close box and
/// Alt+F4 (`WM_CLOSE`) → `RejectActivated`. Every key counts as `OtherPress` first; an
/// auto-repeated Enter or Space on `거부` is that press only.
#[test]
fn row_reject_inputs() {
    let reject = facts(Focus::Reject, None, NO_HIT);
    let rejected = Step::Event(InteractionEvent::RejectActivated);
    let guard = Step::SameWindow(Reply::Handled(0));
    for vk in [VK_RETURN, VK_SPACE] {
        assert_eq!(map_key(vk, false, reject), [OTHER, guard, rejected]);
        assert_eq!(map_key(vk, true, reject), [OTHER, guard]);
    }
    for focus in [
        Focus::Reject,
        Focus::Ack,
        Focus::Approve,
        Focus::Raw,
        Focus::Scroll,
    ] {
        for repeat in [false, true] {
            assert_eq!(
                map_key(VK_ESCAPE, repeat, facts(focus, None, NO_HIT)),
                [OTHER, guard, rejected]
            );
        }
    }
    let on_reject = on(false, true, false, false);
    assert_eq!(
        a01(
            Msg::MouseDown { x: 1, y: 1 },
            facts(Focus::Approve, None, on_reject)
        ),
        steps(
            &[
                OTHER,
                Step::SameWindow(Reply::Default),
                Step::FocusReceiver,
                Step::Press(Pressed::Reject),
                Step::MoveFocus(Focus::Reject),
                Step::Capture,
                Step::Invalidate,
            ],
            Reply::Handled(0),
        )
    );
    assert_eq!(
        a01(
            Msg::MouseUp { x: 1, y: 1 },
            facts(Focus::Reject, Some(Pressed::Reject), on_reject)
        ),
        steps(
            &[Step::Release, Step::Unpress, rejected, Step::Invalidate],
            Reply::Handled(0),
        )
    );
    // Released off `거부`: nothing but the release.
    assert_eq!(
        a01(
            Msg::MouseUp { x: 1, y: 1 },
            facts(Focus::Reject, Some(Pressed::Reject), NO_HIT)
        ),
        steps(
            &[Step::Release, Step::Unpress, Step::Invalidate],
            Reply::Handled(0)
        )
    );
    for open in [reject, None] {
        assert_eq!(
            a01(Msg::Close, open),
            steps(&[Step::Close], Reply::Handled(0))
        );
    }
}

/// Row 6: `WM_KILLFOCUS` to another window / `WM_ACTIVATEAPP(0)` / an unexpected
/// `WM_CAPTURECHANGED` while a button is pressed / `WM_CANCELMODE` → `FocusLost` /
/// `ForegroundLost` / `CaptureLost` / `CancelMode`.
#[test]
fn row_focus_foreground_capture_and_cancel_losses() {
    let open = facts(Focus::Approve, None, NO_HIT);
    assert_eq!(
        a01(Msg::KillFocus { to_foreign: true }, open),
        steps(&[Step::Event(InteractionEvent::FocusLost)], Reply::Default)
    );
    assert_eq!(
        a01(Msg::KillFocus { to_foreign: false }, open),
        steps(&[], Reply::Default)
    );
    assert_eq!(
        a01(Msg::ActivateApp(false), open),
        steps(
            &[Step::Event(InteractionEvent::ForegroundLost)],
            Reply::Default
        )
    );
    for pressed in [
        Pressed::Approve,
        Pressed::Reject,
        Pressed::Retry,
        Pressed::AiRetry,
    ] {
        assert_eq!(
            a01(
                Msg::CaptureChanged,
                facts(Focus::Approve, Some(pressed), NO_HIT)
            ),
            steps(
                &[Step::Unpress, Step::Event(InteractionEvent::CaptureLost)],
                Reply::Default,
            )
        );
    }
    for idle in [open, None] {
        assert_eq!(a01(Msg::CaptureChanged, idle), steps(&[], Reply::Default));
    }
    assert_eq!(
        a01(Msg::CancelMode, open),
        steps(&[Step::Event(InteractionEvent::CancelMode)], Reply::Default)
    );
}

/// Row 7: the 50 ms `WM_TIMER` → `Tick`, then the AI tick and the simulating rebuild; any other
/// timer is nothing.
#[test]
fn row_timer_tick() {
    for open in [facts(Focus::Reject, None, NO_HIT), None] {
        assert_eq!(
            a01(Msg::Timer(APPROVAL_TIMER_ID), open),
            steps(
                &[Step::Event(InteractionEvent::Tick), Step::TimerTail],
                Reply::Handled(0),
            )
        );
        assert_eq!(a01(Msg::Timer(99), open), steps(&[], Reply::Default));
    }
}

// ----- the arms outside the table --------------------------------------------------------------

/// Stray presses (other buttons, non-client presses) are `OtherPress` with the system's own
/// handling on every surface; the activating click, while A01 is not the foreground window (raw
/// read on arrival), is `OtherPress` eaten with `MA_ACTIVATEANDEAT`; the panel and the AI body
/// have no activation arm (spec/04 §3.4, §3.6).
#[test]
fn stray_presses_and_the_activating_click() {
    for surface in [Surface::Approval, Surface::Panel, Surface::AiBody] {
        for msg in [Msg::OtherButtonDown, Msg::NonClientButtonDown] {
            assert_eq!(
                map_msg(surface, &msg, facts(Focus::Reject, None, NO_HIT), ALL),
                steps(&[OTHER], Reply::Default),
                "{surface:?} {msg:?}"
            );
        }
    }
    let open = facts(Focus::Reject, None, NO_HIT);
    assert_eq!(
        map_msg(Surface::Approval, &Msg::MouseActivate, open, NONE),
        steps(&[OTHER], Reply::Handled(MA_ACTIVATEANDEAT))
    );
    assert_eq!(MA_ACTIVATEANDEAT, 2);
    assert_eq!(
        map_msg(
            Surface::Approval,
            &Msg::MouseActivate,
            open,
            TrustedSignals {
                foreground_raw: true,
                ..NONE
            }
        ),
        steps(&[], Reply::Default)
    );
    for surface in [Surface::Panel, Surface::AiBody] {
        assert_eq!(
            map_msg(surface, &Msg::MouseActivate, open, NONE),
            steps(&[], Reply::Default)
        );
    }
}

/// `WM_ACTIVATEAPP(TRUE)` restarts the arm delay unconditionally (not an interaction event).
#[test]
fn activation_restarts_the_arm_delay() {
    for open in [facts(Focus::Reject, None, NO_HIT), None] {
        assert_eq!(
            a01(Msg::ActivateApp(true), open),
            steps(&[Step::Activated], Reply::Default)
        );
    }
}

/// Every key but Enter and Space on `승인` counts as `OtherPress` first, then goes on only while
/// the same window is shown (S4 F1); with no window it is that press only.
#[test]
fn other_keys_count_first_then_act_on_the_same_window_only() {
    for focus in [
        Focus::Reject,
        Focus::Ack,
        Focus::Approve,
        Focus::Raw,
        Focus::Scroll,
    ] {
        assert_eq!(
            map_key(VK_A, false, facts(focus, None, NO_HIT)),
            [OTHER, Step::SameWindow(Reply::Handled(0))]
        );
        assert_eq!(
            map_key(VK_TAB, false, facts(focus, None, NO_HIT)),
            [OTHER, Step::SameWindow(Reply::Handled(0)), Step::Tab]
        );
    }
    for vk in [VK_A, VK_RETURN, VK_SPACE, VK_TAB, VK_ESCAPE, VK_PRIOR] {
        assert_eq!(map_key(vk, false, None), [OTHER]);
    }
    assert_eq!(
        a01(
            Msg::KeyDown {
                vk: VK_A,
                repeat: true
            },
            facts(Focus::Reject, None, NO_HIT)
        ),
        steps(
            &[OTHER, Step::SameWindow(Reply::Handled(0))],
            Reply::Handled(0)
        )
    );
}

/// Enter and Space toggle the checkbox and `원본 데이터` only when not auto-repeated; on the
/// scroll area they are the press only.
#[test]
fn enter_and_space_on_the_checkbox_raw_and_scroll() {
    let guard = Step::SameWindow(Reply::Handled(0));
    for vk in [VK_RETURN, VK_SPACE] {
        let ack = facts(Focus::Ack, None, NO_HIT);
        let raw = facts(Focus::Raw, None, NO_HIT);
        let scroll = facts(Focus::Scroll, None, NO_HIT);
        assert_eq!(map_key(vk, false, ack), [OTHER, guard, Step::ToggleAck]);
        assert_eq!(map_key(vk, true, ack), [OTHER, guard]);
        assert_eq!(map_key(vk, false, raw), [OTHER, guard, Step::ToggleRaw]);
        assert_eq!(map_key(vk, true, raw), [OTHER, guard]);
        for repeat in [false, true] {
            assert_eq!(map_key(vk, repeat, scroll), [OTHER, guard]);
        }
    }
}

/// Page keys and Home/End scroll the panel wherever the focus is; the arrows only on the scroll
/// area (spec/04 §3.4; 2026-11-12).
#[test]
fn scroll_keys() {
    let guard = Step::SameWindow(Reply::Handled(0));
    for focus in [
        Focus::Reject,
        Focus::Ack,
        Focus::Approve,
        Focus::Raw,
        Focus::Scroll,
    ] {
        let open = facts(focus, None, NO_HIT);
        for (vk, scroll) in [
            (VK_PRIOR, KeyScroll::PageUp),
            (VK_NEXT, KeyScroll::PageDown),
            (VK_HOME, KeyScroll::Top),
            (VK_END, KeyScroll::Bottom),
        ] {
            assert_eq!(
                map_key(vk, false, open),
                [OTHER, guard, Step::KeyScroll(scroll)]
            );
        }
        for (vk, scroll) in [(VK_UP, KeyScroll::LineUp), (VK_DOWN, KeyScroll::LineDown)] {
            let expected = if focus == Focus::Scroll {
                vec![OTHER, guard, Step::KeyScroll(scroll)]
            } else {
                vec![OTHER, guard]
            };
            assert_eq!(map_key(vk, false, open), expected, "{focus:?} {vk}");
        }
    }
    assert_eq!(KeyScroll::PageUp.delta(600, 20), -600);
    assert_eq!(KeyScroll::PageDown.delta(600, 20), 600);
    assert_eq!(KeyScroll::LineUp.delta(600, 20), -20);
    assert_eq!(KeyScroll::LineDown.delta(600, 20), 20);
    assert_eq!(KeyScroll::Top.delta(600, 20), i32::MIN / 2);
    assert_eq!(KeyScroll::Bottom.delta(600, 20), i32::MAX / 2);
    assert_eq!(wheel_delta(120, 60), -60);
    assert_eq!(wheel_delta(-240, 60), 120);
    assert_eq!(wheel_delta(60, 60), 0);
}

/// Tab and Shift+Tab: `거부` → checkbox → `승인` → `원본 데이터` → scroll area, the shown stops
/// only (spec/04 §3.4).
#[test]
fn tab_order_and_direction() {
    let full = tab_order(true, true);
    assert_eq!(
        full,
        [
            Focus::Reject,
            Focus::Ack,
            Focus::Approve,
            Focus::Raw,
            Focus::Scroll
        ]
    );
    assert_eq!(
        tab_order(false, false),
        [Focus::Reject, Focus::Approve, Focus::Scroll]
    );
    assert_eq!(tab_target(&full, Focus::Reject, false), Focus::Ack);
    assert_eq!(tab_target(&full, Focus::Scroll, false), Focus::Reject);
    assert_eq!(tab_target(&full, Focus::Reject, true), Focus::Scroll);
    assert_eq!(tab_target(&full, Focus::Approve, true), Focus::Ack);
    let short = tab_order(false, false);
    // A focus that is not a stop counts as the first.
    assert_eq!(tab_target(&short, Focus::Ack, false), Focus::Approve);
    assert_eq!(tab_target(&short, Focus::Raw, true), Focus::Scroll);
    assert_eq!(tab_target(&[], Focus::Raw, false), Focus::Reject);
}

/// The other A01 bottom-bar buttons: press counts first, then capture; the release acts only on
/// the button it started on. With no window a press is that press only.
#[test]
fn retry_buttons_and_no_window() {
    let guard = Step::SameWindow(Reply::Default);
    assert_eq!(
        a01(
            Msg::MouseDown { x: 1, y: 1 },
            facts(Focus::Reject, None, on(false, false, true, false))
        ),
        steps(
            &[
                OTHER,
                guard,
                Step::FocusReceiver,
                Step::Press(Pressed::Retry),
                Step::Capture,
                Step::Invalidate,
            ],
            Reply::Handled(0),
        )
    );
    assert_eq!(
        a01(
            Msg::MouseDown { x: 1, y: 1 },
            facts(Focus::Reject, None, on(false, false, false, true))
        ),
        steps(
            &[
                OTHER,
                guard,
                Step::FocusReceiver,
                Step::Press(Pressed::AiRetry),
                Step::Capture,
                Step::Invalidate,
            ],
            Reply::Handled(0),
        )
    );
    assert_eq!(
        a01(
            Msg::MouseDown { x: 1, y: 1 },
            facts(Focus::Raw, None, NO_HIT)
        ),
        steps(
            &[OTHER, guard, Step::FocusReceiver, Step::Invalidate],
            Reply::Handled(0)
        )
    );
    for (pressed, hit, step) in [
        (Pressed::Retry, on(false, false, true, false), Step::Retry),
        (
            Pressed::AiRetry,
            on(false, false, false, true),
            Step::AiRetry,
        ),
    ] {
        assert_eq!(
            a01(
                Msg::MouseUp { x: 1, y: 1 },
                facts(Focus::Reject, Some(pressed), hit)
            ),
            steps(
                &[Step::Release, Step::Unpress, step, Step::Invalidate],
                Reply::Handled(0)
            )
        );
        assert_eq!(
            a01(
                Msg::MouseUp { x: 1, y: 1 },
                facts(Focus::Reject, Some(pressed), on(true, true, false, false))
            ),
            steps(
                &[Step::Release, Step::Unpress, Step::Invalidate],
                Reply::Handled(0)
            )
        );
    }
    assert_eq!(
        a01(Msg::MouseDown { x: 1, y: 1 }, None),
        steps(&[OTHER], Reply::Default)
    );
    assert_eq!(
        a01(Msg::MouseUp { x: 1, y: 1 }, None),
        steps(&[Step::Release], Reply::Default)
    );
}

/// The panel: a click counts first, then (with a window) A01 takes the focus and the click is
/// hit-tested; a scroll-bar press counts unless it is `SB_ENDSCROLL`; the wheel only scrolls.
#[test]
fn panel_rows() {
    assert_eq!(
        map_msg(Surface::Panel, &Msg::MouseDown { x: 3, y: 4 }, None, NONE),
        steps(
            &[
                OTHER,
                Step::AnyWindow(Reply::Default),
                Step::FocusApproval,
                Step::PanelClick { x: 3, y: 4 },
            ],
            Reply::Handled(0),
        )
    );
    for code in 0..=8 {
        let mut expected = Vec::new();
        if code != SB_ENDSCROLL {
            expected.push(OTHER);
        }
        expected.push(Step::AnyWindow(Reply::Default));
        expected.push(Step::PanelScroll(ScrollGoal::of(code)));
        assert_eq!(
            map_msg(Surface::Panel, &Msg::VScroll { code }, None, NONE),
            Mapped {
                steps: expected,
                reply: Reply::Handled(0)
            }
        );
    }
    assert_eq!(
        map_msg(Surface::Panel, &Msg::Wheel(-120), None, NONE),
        steps(&[Step::Wheel(-120)], Reply::Handled(0))
    );
    assert_eq!(
        map_msg(Surface::Panel, &Msg::Paint, None, NONE),
        steps(&[Step::Paint], Reply::Handled(0))
    );
    let rect = |y: i32| Rect::new(0, y, 100, 10);
    let accounts = [(0, rect(0)), (1, rect(20))];
    for (y, hit) in [
        (5, PanelHit::Account(0)),
        (25, PanelHit::Account(1)),
        (45, PanelHit::Ack),
        (65, PanelHit::Raw),
        (85, PanelHit::Nothing),
    ] {
        assert_eq!(
            panel_hit(&accounts, Some(rect(40)), Some(rect(60)), 50, y),
            hit
        );
    }
    assert_eq!(panel_hit(&[], None, None, 50, 5), PanelHit::Nothing);
    assert_eq!(panel_click(PanelHit::Account(1)), [Step::ToggleAccount(1)]);
    assert_eq!(
        panel_click(PanelHit::Ack),
        [Step::MoveFocus(Focus::Ack), Step::ToggleAck]
    );
    assert_eq!(
        panel_click(PanelHit::Raw),
        [Step::MoveFocus(Focus::Raw), Step::ToggleRaw]
    );
    assert_eq!(
        panel_click(PanelHit::Nothing),
        [Step::MoveFocus(Focus::Scroll), Step::InvalidateApproval]
    );
}

/// The AI body: a click counts first, then (with a window) opens or folds an inconsistent
/// explanation and gives A01 the focus; the AI body never takes the keyboard focus (spec/04
/// §3.8).
#[test]
fn ai_body_rows() {
    assert_eq!(
        map_msg(Surface::AiBody, &Msg::MouseDown { x: 3, y: 4 }, None, NONE),
        steps(
            &[
                OTHER,
                Step::AnyWindow(Reply::Handled(0)),
                Step::AiExpand,
                Step::FocusApproval,
            ],
            Reply::Handled(0),
        )
    );
    for code in 0..=8 {
        let mut expected = Vec::new();
        if code != SB_ENDSCROLL {
            expected.push(OTHER);
        }
        expected.push(Step::AiScroll(ScrollGoal::of(code)));
        assert_eq!(
            map_msg(Surface::AiBody, &Msg::VScroll { code }, None, NONE),
            Mapped {
                steps: expected,
                reply: Reply::Handled(0)
            }
        );
    }
    assert_eq!(
        map_msg(Surface::AiBody, &Msg::Wheel(240), None, NONE),
        steps(&[Step::AiWheel(240)], Reply::Handled(0))
    );
    for msg in [
        Msg::KeyDown {
            vk: VK_RETURN,
            repeat: false,
        },
        Msg::Close,
        Msg::ActivateApp(true),
    ] {
        assert_eq!(
            map_msg(Surface::AiBody, &msg, None, NONE),
            steps(&[], Reply::Default)
        );
    }
}

/// `WM_VSCROLL` codes: line, page, thumb, top and bottom; `SB_ENDSCROLL` and unknown codes stay.
#[test]
fn scroll_goals() {
    let target = |code: u16| ScrollGoal::of(code).target(700, 600, 20, 1_100);
    assert_eq!(target(0), 680);
    assert_eq!(target(1), 720);
    assert_eq!(target(2), 100);
    assert_eq!(target(3), 1_300);
    assert_eq!(target(4), 1_100);
    assert_eq!(target(5), 1_100);
    assert_eq!(target(6), 0);
    assert_eq!(target(7), i32::MAX / 2);
    assert_eq!(target(SB_ENDSCROLL), 700);
    assert_eq!(target(99), 700);
}

/// A01 size and DPI changes lay out again; paint paints; the rest of the messages are nothing.
#[test]
fn layout_paint_and_the_rest() {
    let open = facts(Focus::Reject, None, NO_HIT);
    for msg in [Msg::Size { w: 1, h: 1 }, Msg::DpiChanged { dpi: 144 }] {
        assert_eq!(a01(msg, open), steps(&[Step::Relayout], Reply::Default));
    }
    assert_eq!(
        a01(Msg::Paint, open),
        steps(&[Step::Paint], Reply::Handled(0))
    );
    assert_eq!(
        a01(Msg::Wheel(120), open),
        steps(&[Step::Wheel(120)], Reply::Handled(0))
    );
    for msg in [Msg::Create, Msg::Destroy, Msg::Char(0x41), Msg::SessionLock] {
        assert_eq!(a01(msg, open), steps(&[], Reply::Default), "{msg:?}");
    }
}

/// Over every message of [`every_msg`], surface, window state (no window, or every focus ×
/// pressed button × hit) and arrival sample: the map never builds an approving or holding event
/// itself (only `Step::Sampled` delivers one, from a sample taken at delivery, source check S8),
/// and a sampled step never comes before the press's own focus and capture steps. (2026-11-19,
/// S4 B2 review: the no-window state, the keys, auto-repeats and the other values of
/// `every_msg` were added; before, one `KeyDown` and no `None` facts.)
#[test]
fn approving_events_come_only_from_samples() {
    let mut states = vec![None];
    for focus in [
        Focus::Reject,
        Focus::Ack,
        Focus::Approve,
        Focus::Raw,
        Focus::Scroll,
    ] {
        for pressed in [
            None,
            Some(Pressed::Approve),
            Some(Pressed::Reject),
            Some(Pressed::Retry),
            Some(Pressed::AiRetry),
        ] {
            for hits in [
                NO_HIT,
                on(true, false, false, false),
                on(false, true, true, true),
                on(true, true, true, true),
            ] {
                states.push(facts(focus, pressed, hits));
            }
        }
    }
    let mut cases = Vec::new();
    for msg in every_msg() {
        for surface in [Surface::Approval, Surface::Panel, Surface::AiBody] {
            for state in &states {
                for signals in [NONE, ALL] {
                    cases.push((msg, surface, *state, signals));
                }
            }
        }
    }
    let mut sampled = Vec::new();
    for (msg, surface, state, signals) in cases {
        let Mapped { steps, .. } = map_msg(surface, &msg, state, signals);
        for (at, step) in steps.iter().enumerate() {
            let case = format!("{msg:?} {surface:?} {state:?} {signals:?}: {step:?}");
            if let Step::Event(event) = step {
                assert!(!trusted_only(*event), "{case}");
            }
            let Step::Sampled(trusted) = step else {
                continue;
            };
            assert!(state.is_some(), "no window, no sampled event: {case}");
            match trusted {
                Trusted::PointerPressed => assert_eq!(
                    steps.get(..at),
                    Some(
                        &[
                            Step::FocusReceiver,
                            Step::Press(Pressed::Approve),
                            Step::MoveFocus(Focus::Approve),
                            Step::Capture,
                        ][..]
                    ),
                    "{case}"
                ),
                Trusted::PointerReleased => assert_eq!(
                    steps.get(..at),
                    Some(&[Step::Release, Step::Unpress][..]),
                    "{case}"
                ),
                Trusted::SpacePressed { .. } | Trusted::SpaceReleased | Trusted::ApproveEnter => {}
            }
            if !sampled.contains(trusted) {
                sampled.push(*trusted);
            }
        }
    }
    // The sweep reached every sampled event.
    for trusted in [
        Trusted::PointerPressed,
        Trusted::PointerReleased,
        Trusted::SpacePressed { repeat: false },
        Trusted::SpacePressed { repeat: true },
        Trusted::SpaceReleased,
        Trusted::ApproveEnter,
    ] {
        assert!(sampled.contains(&trusted), "{trusted:?} not reached");
    }
}

/// The stray-press map is unchanged (`tests/approval_input.rs` pins it too), and the release
/// events are the ones that end a hold.
#[test]
fn stray_press_and_release_events() {
    for msg in every_msg() {
        let expected = matches!(msg, Msg::OtherButtonDown | Msg::NonClientButtonDown)
            .then_some(InteractionEvent::OtherPress);
        assert_eq!(stray_press(&msg), expected, "{msg:?}");
    }
    assert!(is_release(InteractionEvent::PointerReleased {
        physical_down: false
    }));
    assert!(is_release(InteractionEvent::SpaceReleased {
        physical_down: true
    }));
    for event in [
        InteractionEvent::Tick,
        InteractionEvent::OtherPress,
        InteractionEvent::CaptureLost,
        InteractionEvent::PointerMoved { inside: false },
        InteractionEvent::SpacePressed {
            repeat: false,
            physical_down: true,
        },
    ] {
        assert!(!is_release(event), "{event:?}");
    }
}
