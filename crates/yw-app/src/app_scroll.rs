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
//! step glides: its first step ([`glide_step`]) is taken in the wheel handler itself
//! (2026-11-12; before, nothing moved until the first timer tick, and a fast wheel that kept
//! restarting the timer moved nothing until it slowed), the rest over [`GLIDE_TICKS`] timer
//! ticks; small touchpad deltas scroll at once. A page (Page keys, a click in the bar's track, a
//! wheel set to pages) keeps [`PAGE_KEEP_DIP`] of the old view in sight ([`page_step`]).
//!
//! Keyboard (2026-11-10): the message loop's observer posts [`WM_YW_NAV_KEY`] for Page Up/Down,
//! Home/End (with or without Ctrl, 2026-11-12), Tab and the arrows ([`NavKey`]); it is handled
//! after the dialog manager has moved the focus. Page keys scroll a page, Home/End to the top or
//! bottom (not while an edit has the focus: there they move the caret; plain Home/End did nothing
//! anywhere else before). Controls out of view are hidden, so the dialog
//! manager's Tab skips them and wraps around inside the view: Tab instead goes to the next tab stop
//! in placed order ([`tab_target`]; a radio group's checked button, [`radio_entry`]), scrolling it
//! into view, and every focus moved by the keyboard ends fully in view ([`reveal_offset`]).
//!
//! [`WM_YW_NAV_KEY`]: crate::events::WM_YW_NAV_KEY

use yw_win::ui::{Window, wheel_scroll_lines};

use crate::app::App;
use crate::events::NavKey;
use crate::ui::main_window::{is_tab_stop, radio_state};

/// Main window timer of the wheel glide (the main tick is 1).
pub(crate) const SCROLL_TIMER_ID: usize = 2;
/// One scroll line (bar arrows, wheel lines). 36 since 2026-11-12: a notch of the default three
/// lines moves 108 DIP, about what browsers and Explorer move (20 made it 60, half of that).
const LINE_DIP: i32 = 36;
/// What a page step keeps of the old view, so the reader does not lose their place.
const PAGE_KEEP_DIP: i32 = 48;
/// Timer ticks of a wheel glide after its first step, which the wheel handler takes itself
/// (about 60 ms at the timer's resolution).
const GLIDE_TICKS: u8 = 4;
const GLIDE_TICK_MS: u32 = 15;
const WHEEL_DELTA: i32 = 120;
/// Room kept between a control the keyboard brought into view and the view's edge.
const REVEAL_MARGIN_DIP: i32 = 12;
/// `WM_VSCROLL` codes [`App::main_vscroll`] takes.
const SB_PAGEUP: u16 = 2;
const SB_PAGEDOWN: u16 = 3;
const SB_TOP: u16 = 6;
const SB_BOTTOM: u16 = 7;

/// A screen whose scroll offset is remembered for the ways back (2026-11-10): each S10 chain tab,
/// each settings section, S08, S13 and S14.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScrollPlace {
    /// S10 on a chain tab.
    Main(crate::meta::Tab),
    /// A settings section.
    Settings(crate::app::SettingsSection),
    /// S08 '처음 설정' (`← 처음 설정으로` returns there).
    Done,
    /// S13.
    Sites,
    /// S14.
    AddressBook,
}

/// Where the remembered screens were left (DIP, so a DPI change keeps them; this run only,
/// emptied by a lock) and the screen under an open overlay.
#[derive(Debug, Default)]
pub struct ScrollMemory {
    places: Vec<(ScrollPlace, i32)>,
    /// The offset (DIP) of the screen an overlay opened over.
    pub under_overlay: Option<i32>,
    /// The DPI of the last layout (a `WM_DPICHANGED` scales the offset by new / old).
    pub layout_dpi: u32,
}

impl ScrollMemory {
    /// The offset `place` was left at.
    #[must_use]
    pub fn get(&self, place: ScrollPlace) -> Option<i32> {
        self.places
            .iter()
            .find(|(known, _)| *known == place)
            .map(|(_, dip)| *dip)
    }

    /// Notes where `place` was left.
    pub fn set(&mut self, place: ScrollPlace, dip: i32) {
        match self.places.iter_mut().find(|(known, _)| *known == place) {
            Some(slot) => slot.1 = dip,
            None => self.places.push((place, dip)),
        }
    }

    /// Forgets every place (lock: the next session opens at the top).
    pub fn clear(&mut self) {
        self.places.clear();
        self.under_overlay = None;
    }
}

/// `value` × `to` / `from` (DPI conversions), saturating.
#[must_use]
pub fn rescale(value: i32, from: u32, to: u32) -> i32 {
    if from == 0 {
        return value;
    }
    let scaled = i64::from(value).saturating_mul(i64::from(to)) / i64::from(from);
    i32::try_from(scaled).unwrap_or(if scaled < 0 { i32::MIN } else { i32::MAX })
}

/// Scroll input state of the main window.
#[derive(Debug, Default)]
pub struct MainScroll {
    /// Wheel travel not yet scrolled, in pixels × 120 (below one pixel; same sign as the last
    /// delta).
    wheel_rest: i32,
    /// A wheel glide in progress: target offset and ticks left.
    glide: Option<(i32, u8)>,
    /// The command id of the control that had the focus when Tab was pressed (noted by the loop
    /// observer before the dialog manager moved the focus).
    tab_from: Option<u16>,
}

/// The control Tab (Shift+Tab: `back`) reaches from the control at `from`, given whether each
/// control in placed order is a tab stop: the next stop after it (before it), wrapping around;
/// `None` when there is no other stop or `from` is out of range.
#[must_use]
pub fn tab_target(stops: &[bool], from: usize, back: bool) -> Option<usize> {
    let len = stops.len();
    if from >= len {
        return None;
    }
    (1..len)
        .map(|step| {
            if back {
                (from + len - step) % len
            } else {
                (from + step) % len
            }
        })
        .find(|&index| stops.get(index).copied().unwrap_or(false))
}

/// Where Tab enters the radio group whose first button (the group's only tab stop) is `target`,
/// as the dialog manager does: on its checked button. Focusing an unchecked auto radio button
/// clicks it (`BN_CLICKED`), so the first button is never focused while another one is checked.
/// `radios[i]` is control `i`'s [`radio_state`](crate::ui::main_window::radio_state) in placed
/// order; the group runs to the next first-of-group radio (the only `WS_GROUP` controls). `now`,
/// where the dialog manager already put the focus, is kept when it is a radio of the group.
/// `target` itself when it starts no group or no enabled button of the group is checked.
#[must_use]
pub fn radio_entry(radios: &[Option<(bool, bool)>], target: usize, now: usize) -> usize {
    if !matches!(radios.get(target), Some(Some((true, _)))) {
        return target;
    }
    let end = radios
        .iter()
        .enumerate()
        .skip(target.saturating_add(1))
        .find(|(_, radio)| matches!(radio, Some((true, _))))
        .map_or(radios.len(), |(index, _)| index);
    if (target..end).contains(&now) && matches!(radios.get(now), Some(Some(_))) {
        return now;
    }
    (target..end)
        .find(|&index| matches!(radios.get(index), Some(Some((_, true)))))
        .unwrap_or(target)
}

/// The scroll offset that shows a control at client `y` with height `h` fully in a `view` px
/// high view, `margin` px from its edges: `scroll` when it already is; a control taller than the
/// view shows its top.
#[must_use]
pub const fn reveal_offset(scroll: i32, y: i32, h: i32, view: i32, margin: i32) -> i32 {
    if y < margin {
        return scroll.saturating_add(y).saturating_sub(margin);
    }
    let overflow = y
        .saturating_add(h)
        .saturating_sub(view.saturating_sub(margin));
    if overflow > 0 {
        let to_top = y.saturating_sub(margin);
        return scroll.saturating_add(if overflow < to_top { overflow } else { to_top });
    }
    scroll
}

/// The offset one glide step takes `scroll` to on its way to `target`: half the remaining
/// distance, all of it once the half rounds to nothing. The wheel handler's first step and the
/// timer ticks share it.
#[must_use]
pub const fn glide_step(scroll: i32, target: i32) -> i32 {
    let remaining = target.saturating_sub(scroll);
    let half = remaining / 2;
    scroll.saturating_add(if half == 0 { remaining } else { half })
}

/// A page step in a `view` px high view: the view less `keep` px of context, at least one
/// `line`.
#[must_use]
pub const fn page_step(view: i32, keep: i32, line: i32) -> i32 {
    let step = view.saturating_sub(keep);
    if step < line { line } else { step }
}

/// The main window's page step at its size and DPI ([`page_step`]).
fn page_px(window: &Window) -> i32 {
    page_step(
        window.client_rect().h,
        window.px(PAGE_KEEP_DIP),
        window.px(LINE_DIP),
    )
}

impl App {
    fn window_dpi(&self) -> u32 {
        self.main.as_ref().map_or(96, Window::dpi)
    }

    /// The current offset in DIP.
    pub(crate) fn scroll_dip(&self) -> i32 {
        rescale(self.scroll, self.window_dpi(), 96)
    }

    /// A remembered offset (DIP) in pixels at the window's DPI.
    pub(crate) fn scroll_px(&self, dip: i32) -> i32 {
        rescale(dip, 96, self.window_dpi()).max(0)
    }

    /// The remembered place of `screen`, if it is one.
    pub(crate) fn scroll_place(&self, screen: &crate::app::Screen) -> Option<ScrollPlace> {
        use crate::app::Screen;
        Some(match screen {
            Screen::Main => ScrollPlace::Main(
                self.meta
                    .as_ref()
                    .map_or(crate::meta::Tab::Evm, |meta| meta.prefs.tab),
            ),
            Screen::Settings(section) => ScrollPlace::Settings(*section),
            Screen::Done => ScrollPlace::Done,
            Screen::Sites => ScrollPlace::Sites,
            Screen::AddressBook => ScrollPlace::AddressBook,
            _ => return None,
        })
    }

    /// Notes where the current screen was left (before it is left, or its tab switched).
    pub(crate) fn remember_scroll(&mut self) {
        if let Some(place) = self.scroll_place(&self.screen) {
            let dip = self.scroll_dip();
            self.scroll_memory.set(place, dip);
        }
    }

    /// A chain tab click or Ctrl+1–4 (2026-11-10): the old tab's offset is noted and the new tab
    /// opens at its top, its network band first (the previous tab's offset stayed before).
    pub(crate) fn tab_top(&mut self) {
        self.remember_scroll();
        self.scroll = 0;
        self.stop_scroll();
        if let Some(main) = self.main.as_ref() {
            main.kill_timer(SCROLL_TIMER_ID);
        }
    }

    /// `WM_DPICHANGED` on the main window: the offset keeps its place in the content (× new DPI /
    /// old DPI); the layout that follows the new size cuts it to the content height.
    pub(crate) fn scroll_dpi_changed(&mut self, dpi: u32) {
        let old = self.scroll_memory.layout_dpi;
        if old != 0 && old != dpi {
            self.scroll = rescale(self.scroll, old, dpi).max(0);
        }
        self.stop_scroll();
    }

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
            None => page_px(window),
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
        if delta.abs() >= WHEEL_DELTA {
            // The first step now, in this handler (2026-11-12): a `WM_TIMER` comes 16–31 ms
            // later, and not at all while notches keep arriving, each one restarting the timer.
            self.scroll_to(glide_step(self.scroll, target));
            if self.scroll == target {
                // Already there (one pixel to go, or at the top or bottom): no ticks to wait for.
                self.scroll_state.glide = None;
                window.kill_timer(SCROLL_TIMER_ID);
            } else if window.set_timer(SCROLL_TIMER_ID, GLIDE_TICK_MS).is_ok() {
                self.scroll_state.glide = Some((target, GLIDE_TICKS));
            } else {
                self.scroll_state.glide = None;
                self.scroll_to(target);
            }
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
            glide_step(self.scroll, target)
        };
        self.scroll_to(next);
    }

    /// The loop observer saw a navigation key, before the dialog manager handles it: Tab notes
    /// which control had the focus.
    pub fn note_nav_key(&mut self, key: NavKey) {
        if let NavKey::Tab { .. } = key {
            self.scroll_state.tab_from = self
                .controls
                .focused()
                .and_then(|index| self.placed.controls.get(index))
                .map(|(ctl, _)| ctl.id);
        }
    }

    /// `WM_YW_NAV_KEY` while the main window is in the foreground (module docs).
    pub(crate) fn main_nav_key(&mut self, window: &Window, code: usize) {
        let Some(key) = NavKey::from_code(code) else {
            return;
        };
        match key {
            NavKey::Page { up } => {
                self.main_vscroll(window, if up { SB_PAGEUP } else { SB_PAGEDOWN });
            }
            NavKey::Edge { top } => {
                if !self
                    .controls
                    .focused()
                    .is_some_and(|index| self.controls.is_edit(index))
                {
                    self.main_vscroll(window, if top { SB_TOP } else { SB_BOTTOM });
                }
            }
            NavKey::Tab { back } => {
                let from = self.scroll_state.tab_from.take();
                // Focus outside the main window's controls (another window): nothing to do.
                let Some(now) = self.controls.focused() else {
                    return;
                };
                let stops: Vec<bool> = self
                    .placed
                    .controls
                    .iter()
                    .map(|(ctl, _)| is_tab_stop(ctl))
                    .collect();
                let target = from
                    .and_then(|id| {
                        self.placed
                            .controls
                            .iter()
                            .position(|(ctl, _)| ctl.id == id)
                    })
                    .and_then(|from| tab_target(&stops, from, back))
                    .unwrap_or(now);
                // A radio group is entered on its checked button, never by focusing (and so
                // clicking) its unchecked first one.
                let radios: Vec<Option<(bool, bool)>> = self
                    .placed
                    .controls
                    .iter()
                    .map(|(ctl, _)| radio_state(ctl))
                    .collect();
                let target = radio_entry(&radios, target, now);
                self.reveal_control(target);
                if target != now {
                    self.controls.focus_at(target);
                }
            }
            NavKey::Arrow => {
                if let Some(now) = self.controls.focused() {
                    self.reveal_control(now);
                }
            }
        }
    }

    /// Scrolls the control at `index` (placed order) fully into view ([`reveal_offset`]); a
    /// control that comes into view is shown by the scroll (also `App::open_rpc_row`).
    pub(crate) fn reveal_control(&mut self, index: usize) {
        let Some(main) = self.main.as_ref() else {
            return;
        };
        let Some(rect) = self.placed.controls.get(index).map(|(_, rect)| *rect) else {
            return;
        };
        let target = reveal_offset(
            self.scroll,
            rect.y,
            rect.h,
            main.client_rect().h,
            main.px(REVEAL_MARGIN_DIP),
        );
        if target == self.scroll {
            return;
        }
        main.kill_timer(SCROLL_TIMER_ID);
        self.stop_scroll();
        self.scroll_to(target);
    }

    /// `WM_VSCROLL` from the main window's bar; the thumb tracks live (`SB_THUMBTRACK`).
    pub(crate) fn main_vscroll(&mut self, window: &Window, code: u16) {
        let page = page_px(window);
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

#[cfg(test)]
mod tests {
    use super::{glide_step, page_step, radio_entry, reveal_offset, tab_target};
    use crate::events::NavKey;

    /// Review 2026-11-10: Tab into S11's asset radios (ETH first, USDC checked) focused the
    /// unchecked ETH, which Windows answers with a click; the group is entered on USDC.
    #[test]
    fn tab_enters_a_radio_group_on_its_checked_button() {
        // 0 button, 1 ETH (first), 2 WETH, 3 USDC (checked), 4 link, 5 fee radio (first, checked).
        let radios = [
            None,
            Some((true, false)),
            Some((false, false)),
            Some((false, true)),
            None,
            Some((true, true)),
        ];
        // The dialog manager already put the focus on USDC: it stays there.
        assert_eq!(radio_entry(&radios, 1, 3), 3);
        // The group was out of view (the focus wrapped elsewhere): USDC, not ETH.
        assert_eq!(radio_entry(&radios, 1, 0), 3);
        // The next group starts at 5; a target that is no first radio is kept.
        assert_eq!(radio_entry(&radios, 5, 0), 5);
        assert_eq!(radio_entry(&radios, 4, 0), 4);
        // Nothing checked (or only a disabled button): the first button, as before.
        let unchecked = [None, Some((true, false)), Some((false, false))];
        assert_eq!(radio_entry(&unchecked, 1, 0), 1);
    }

    /// Review 2026-11-10: controls out of view are hidden, so the dialog manager's Tab wrapped
    /// inside the view; the placed-order target reaches the ones below (and above) the fold.
    #[test]
    fn tab_goes_through_every_stop_in_placed_order_and_wraps() {
        // 0 label, 1 button, 2 disabled, 3 edit, 4 label, 5 button (below the fold).
        let stops = [false, true, false, true, false, true];
        assert_eq!(tab_target(&stops, 3, false), Some(5));
        assert_eq!(tab_target(&stops, 5, false), Some(1));
        assert_eq!(tab_target(&stops, 1, true), Some(5));
        assert_eq!(tab_target(&stops, 5, true), Some(3));
        // From a control that is not a stop (a clicked label-like control): the next stop.
        assert_eq!(tab_target(&stops, 4, false), Some(5));
        assert_eq!(tab_target(&[true], 0, false), None);
        assert_eq!(tab_target(&stops, 6, false), None);
    }

    #[test]
    fn a_control_cut_by_the_edge_is_scrolled_fully_into_view() {
        // View 500 px, margin 12, scrolled to 100.
        assert_eq!(reveal_offset(100, 200, 30, 500, 12), 100);
        // Cut by the bottom edge (480..510): up by 22 to end 12 px above the edge.
        assert_eq!(reveal_offset(100, 480, 30, 500, 12), 122);
        // Far below (900..930): its bottom 12 px above the edge.
        assert_eq!(reveal_offset(100, 900, 30, 500, 12), 542);
        // Above the view: its top 12 px below the edge.
        assert_eq!(reveal_offset(100, -40, 30, 500, 12), 48);
        // Taller than the view: its top.
        assert_eq!(reveal_offset(100, 300, 900, 500, 12), 388);
    }

    /// 2026-11-12: the wheel handler takes the first of these steps itself and the timer the
    /// rest, so both use one rule. A 108 px notch: 54, 27, 13, 7, then the last tick lands.
    #[test]
    fn a_glide_halves_the_remaining_distance_and_lands_on_the_target() {
        let mut scroll = 200;
        let steps: Vec<i32> = (0..4)
            .map(|_| {
                let next = glide_step(scroll, 308);
                let step = next - scroll;
                scroll = next;
                step
            })
            .collect();
        assert_eq!(steps, [54, 27, 13, 7]);
        // Upwards it mirrors.
        assert_eq!(glide_step(308, 200), 254);
        // One pixel left (its half is 0): the target itself, either way; there: stays.
        assert_eq!(glide_step(307, 308), 308);
        assert_eq!(glide_step(201, 200), 200);
        assert_eq!(glide_step(200, 200), 200);
    }

    /// 2026-11-12: a page keeps 48 px of the old view (it moved the whole view before), and is
    /// never shorter than a line.
    #[test]
    fn a_page_step_keeps_some_of_the_old_view() {
        assert_eq!(page_step(680, 48, 36), 632);
        assert_eq!(page_step(70, 48, 36), 36);
        assert_eq!(page_step(0, 48, 36), 36);
    }

    #[test]
    fn navigation_keys_and_their_codes() {
        assert_eq!(
            NavKey::of(0x09, false, false, true),
            Some(NavKey::Tab { back: true })
        );
        assert_eq!(
            NavKey::of(0x22, false, false, false),
            Some(NavKey::Page { up: false })
        );
        assert_eq!(
            NavKey::of(0x24, true, false, false),
            Some(NavKey::Edge { top: true })
        );
        // Home/End without Ctrl too (2026-11-12; `main_nav_key` leaves them to a focused edit).
        assert_eq!(
            NavKey::of(0x24, false, false, false),
            Some(NavKey::Edge { top: true })
        );
        assert_eq!(
            NavKey::of(0x23, false, false, true),
            Some(NavKey::Edge { top: false })
        );
        // Alt never; Ctrl+Tab is not Tab.
        assert_eq!(NavKey::of(0x23, false, true, false), None);
        assert_eq!(NavKey::of(0x22, false, true, false), None);
        assert_eq!(NavKey::of(0x09, true, false, false), None);
        for code in 1..=7 {
            let key = NavKey::from_code(code).unwrap();
            assert_eq!(key.code(), code);
        }
        assert_eq!(NavKey::from_code(0), None);
        assert_eq!(NavKey::from_code(8), None);
    }
}
