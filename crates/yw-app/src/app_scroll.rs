//! Main window scrolling (spec/04 §1.7): the window's own vertical scroll bar (always shown,
//! disabled when the screen fits), the mouse wheel and touchpads, and the bar's arrows, track
//! and thumb.
//!
//! A scroll never lays the screen out again: the placed rectangles move by the offset change
//! ([`Placed::shift`](crate::ui::main_window::Placed::shift)), the system copies the pixels that
//! stay visible and moves the child controls with them (`ScrollWindowEx`), and only the
//! uncovered strip is painted — synchronously, as soon as the handler that scrolled returns
//! (`Window::update_now`; a `WM_PAINT` sent while the app is borrowed would be dropped and leave
//! a stale copy of the content in the strip). Controls that cross the view's edge are shown or
//! hidden.
//!
//! Wheel: the delta accumulates in 1/120 notches (high-resolution touchpads send small deltas),
//! one notch = `SPI_GETWHEELSCROLLLINES` lines of [`LINE_DIP`] (or a page). A whole-notch wheel
//! step glides over [`GLIDE_TICKS`] timer ticks; small touchpad deltas scroll at once.

use yw_win::ui::{Window, wheel_scroll_lines};

use crate::app::App;

/// Main window timer of the wheel glide (the main tick is 1).
pub(crate) const SCROLL_TIMER_ID: usize = 2;
/// One scroll line (bar arrows, wheel lines).
const LINE_DIP: i32 = 20;
/// Ticks of a wheel glide (about 60 ms at the timer's resolution).
const GLIDE_TICKS: u8 = 4;
const GLIDE_TICK_MS: u32 = 15;
const WHEEL_DELTA: i32 = 120;

/// Scroll input state of the main window.
#[derive(Debug, Default)]
pub struct MainScroll {
    /// Wheel travel not yet scrolled, in pixels × 120 (below one pixel; same sign as the last
    /// delta).
    wheel_rest: i32,
    /// A wheel glide in progress: target offset and ticks left.
    glide: Option<(i32, u8)>,
}

impl App {
    /// Scrolls the main window to `target` (clamped to the content), without a new layout.
    pub(crate) fn scroll_to(&mut self, target: i32) {
        let Some(main) = self.main.as_ref() else {
            return;
        };
        let client = main.client_rect();
        let target = target.clamp(0, self.max_scroll());
        let dy = self.scroll.saturating_sub(target);
        if dy == 0 {
            return;
        }
        self.scroll = target;
        self.placed.shift(dy);
        main.scroll_content(dy);
        self.controls.scrolled(&self.placed, client);
        main.set_vscroll_content(self.scroll, client.h, self.placed.content_height);
        main.update_now();
    }

    /// Ends any wheel glide and forgets partial wheel travel (a new screen, a bar drag).
    pub(crate) fn stop_scroll(&mut self) {
        self.scroll_state = MainScroll::default();
    }

    /// `WM_MOUSEWHEEL` on the main window.
    pub(crate) fn main_wheel(&mut self, window: &Window, delta: i16) {
        let delta = i32::from(delta);
        let notch = match wheel_scroll_lines() {
            None => window.client_rect().h,
            Some(lines) => window
                .px(LINE_DIP)
                .saturating_mul(i32::try_from(lines).unwrap_or(i32::MAX)),
        };
        let state = &mut self.scroll_state;
        if (state.wheel_rest > 0 && delta < 0) || (state.wheel_rest < 0 && delta > 0) {
            state.wheel_rest = 0;
        }
        let travel = state.wheel_rest.saturating_add(delta.saturating_mul(notch));
        let pixels = travel / WHEEL_DELTA;
        state.wheel_rest = travel % WHEEL_DELTA;
        if pixels == 0 {
            return;
        }
        // Wheel forward (positive) shows what is above.
        let gliding = state.glide.map(|(target, _)| target);
        let target = gliding
            .unwrap_or(self.scroll)
            .saturating_sub(pixels)
            .clamp(0, self.max_scroll());
        if delta.abs() >= WHEEL_DELTA && window.set_timer(SCROLL_TIMER_ID, GLIDE_TICK_MS).is_ok() {
            self.scroll_state.glide = Some((target, GLIDE_TICKS));
        } else if let Some((glide_target, _)) = self.scroll_state.glide.as_mut() {
            *glide_target = target;
        } else {
            self.scroll_to(target);
        }
    }

    /// The largest scroll offset of the current layout.
    fn max_scroll(&self) -> i32 {
        let page = self.main.as_ref().map_or(0, |main| main.client_rect().h);
        self.placed.content_height.saturating_sub(page).max(0)
    }

    /// One glide tick: half the remaining distance, the rest on the last tick.
    pub(crate) fn scroll_tick(&mut self, window: &Window) {
        let Some((target, left)) = self.scroll_state.glide else {
            window.kill_timer(SCROLL_TIMER_ID);
            return;
        };
        let next = if left <= 1 {
            self.scroll_state.glide = None;
            window.kill_timer(SCROLL_TIMER_ID);
            target
        } else {
            self.scroll_state.glide = Some((target, left.saturating_sub(1)));
            let remaining = target.saturating_sub(self.scroll);
            let half = remaining / 2;
            self.scroll
                .saturating_add(if half == 0 { remaining } else { half })
        };
        self.scroll_to(next);
    }

    /// `WM_VSCROLL` from the main window's bar; the thumb tracks live (`SB_THUMBTRACK`).
    pub(crate) fn main_vscroll(&mut self, window: &Window, code: u16) {
        let page = window.client_rect().h;
        let line = window.px(LINE_DIP);
        let current = self.scroll;
        let target = match code {
            0 => current.saturating_sub(line),
            1 => current.saturating_add(line),
            2 => current.saturating_sub(page),
            3 => current.saturating_add(page),
            4 | 5 => window.vscroll_track_pos(),
            6 => 0,
            7 => i32::MAX / 2,
            _ => return,
        };
        self.stop_scroll();
        window.kill_timer(SCROLL_TIMER_ID);
        self.scroll_to(target);
    }
}
