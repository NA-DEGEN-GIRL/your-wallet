//! The main window's place across runs (spec/04 §1.7, 2026-11-10): `window.json` in the data
//! folder, `{"v":1,"x":…,"y":…,"w":…,"h":…,"max":false,"dpi":96}` — the restored rectangle in
//! screen pixels (`GetWindowPlacement` `rcNormalPosition`, kept while maximized), whether it was
//! maximized and the DPI it was saved at. It is not in `settings.json`: `save_settings` clears
//! the settings-file warning (`guard.pending`) and a newer version's settings file is never
//! written. It is neither part of the security snapshot nor moved by a wallet reset.
//!
//! Written 1 s after a move or resize ends (`WM_EXITSIZEMOVE`) or the window is maximized or
//! restored (`WM_SIZE`) — the main timer debounces — and at exit, only when it changed. Read once
//! at start (≤ 256 bytes, no links, strict JSON, ranges checked) and used only when the rectangle
//! overlaps the work area of the monitor it mostly lies on by 160×120 DIP; otherwise the default
//! place: 960 DIP wide, the work area's height less 96 DIP (680–900) tall, centered. The tour
//! and the screen tests keep their fixed 960×680 (they never call [`App::place_main_window`]).

use yw_json::{Limits, Value};
use yw_win::file::{FileError, atomic_write, read_limited_no_reparse};
use yw_win::ui::{MonitorArea, Rect, scale};

use crate::app::App;
use crate::app_scroll::rescale;
use crate::logging;

/// The file name in the data folder.
pub const WINDOW_FILE: &str = "window.json";
/// Read limit of [`WINDOW_FILE`].
pub const WINDOW_FILE_MAX_BYTES: u64 = 256;
/// The debounce after the last move, resize, maximize or restore.
const SAVE_DELAY_MS: u64 = 1_000;
/// The part of a saved rectangle that must lie on a monitor's work area for it to be used (DIP).
pub const MIN_VISIBLE_DIP: (i32, i32) = (160, 120);
/// The default client width (DIP).
pub const DEFAULT_WIDTH_DIP: i32 = 960;
/// The default client height bounds (DIP): the work area's height less
/// [`DEFAULT_HEIGHT_MARGIN_DIP`], within these.
pub const DEFAULT_HEIGHT_DIP: (i32, i32) = (680, 900);
/// See [`DEFAULT_HEIGHT_DIP`].
pub const DEFAULT_HEIGHT_MARGIN_DIP: i32 = 96;
/// The main window's minimum client size (DIP; `WindowSpec::min_size`).
pub const MIN_CLIENT_DIP: (i32, i32) = (720, 520);
/// Largest coordinate or size accepted from the file.
const COORD_LIMIT: i64 = 100_000;
const LIMITS: Limits = Limits {
    max_bytes: 256,
    max_depth: 1,
    max_nodes: 16,
    max_items: 16,
};

/// What `window.json` holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SavedWindow {
    /// The restored rectangle (outer, screen pixels at [`SavedWindow::dpi`]).
    pub rect: Rect,
    /// Maximized (or minimized from maximized).
    pub maximized: bool,
    /// The window's DPI when it was saved.
    pub dpi: u32,
}

impl SavedWindow {
    /// Parses `window.json` strictly: one object with exactly `v` (1), `x`, `y`, `w`, `h`,
    /// `max` and `dpi`, integers in range; `None` for anything else.
    #[must_use]
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let Ok(Value::Object(object)) = yw_json::parse(bytes, &LIMITS) else {
            return None;
        };
        if object.len() != 7
            || object
                .keys()
                .any(|key| !matches!(key, "v" | "x" | "y" | "w" | "h" | "max" | "dpi"))
        {
            return None;
        }
        let int = |key: &str| match object.get(key) {
            Some(Value::Number(number)) => number.as_i64(),
            _ => None,
        };
        let coordinate = |key: &str| {
            int(key)
                .filter(|value| value.abs() <= COORD_LIMIT)
                .and_then(|value| i32::try_from(value).ok())
        };
        let size = |key: &str| {
            int(key)
                .filter(|value| (1..=COORD_LIMIT).contains(value))
                .and_then(|value| i32::try_from(value).ok())
        };
        if int("v")? != 1 {
            return None;
        }
        let maximized = match object.get("max") {
            Some(Value::Bool(value)) => *value,
            _ => return None,
        };
        let dpi = int("dpi")
            .filter(|dpi| (48..=1_536).contains(dpi))
            .and_then(|dpi| u32::try_from(dpi).ok())?;
        Some(Self {
            rect: Rect::new(coordinate("x")?, coordinate("y")?, size("w")?, size("h")?),
            maximized,
            dpi,
        })
    }

    /// The file text.
    #[must_use]
    pub fn to_json(self) -> String {
        format!(
            "{{\"v\":1,\"x\":{},\"y\":{},\"w\":{},\"h\":{},\"max\":{},\"dpi\":{}}}\n",
            self.rect.x, self.rect.y, self.rect.w, self.rect.h, self.maximized, self.dpi
        )
    }
}

/// Where a saved window goes on `monitor` — the monitor its rectangle mostly lies on
/// (`MonitorFromRect`, `None` when it lies on none) —: `None` (the default place) unless it
/// overlaps the work area by [`MIN_VISIBLE_DIP`] at that monitor's DPI; else its size converted to
/// that DPI, at least `min_outer` (pixels) and at most the work area, moved inside the work area.
#[must_use]
pub fn restored_rect(
    saved: &SavedWindow,
    monitor: Option<MonitorArea>,
    min_outer: (i32, i32),
) -> Option<Rect> {
    let MonitorArea { work, dpi } = monitor?;
    let right = |rect: Rect| rect.x.saturating_add(rect.w);
    let bottom = |rect: Rect| rect.y.saturating_add(rect.h);
    let visible_w = right(saved.rect)
        .min(right(work))
        .saturating_sub(saved.rect.x.max(work.x));
    let visible_h = bottom(saved.rect)
        .min(bottom(work))
        .saturating_sub(saved.rect.y.max(work.y));
    if visible_w < scale(MIN_VISIBLE_DIP.0, dpi) || visible_h < scale(MIN_VISIBLE_DIP.1, dpi) {
        return None;
    }
    let w = rescale(saved.rect.w, saved.dpi, dpi)
        .max(min_outer.0)
        .min(work.w)
        .max(1);
    let h = rescale(saved.rect.h, saved.dpi, dpi)
        .max(min_outer.1)
        .min(work.h)
        .max(1);
    let x = saved
        .rect
        .x
        .clamp(work.x, right(work).saturating_sub(w).max(work.x));
    let y = saved
        .rect
        .y
        .clamp(work.y, bottom(work).saturating_sub(h).max(work.y));
    Some(Rect::new(x, y, w, h))
}

/// The default client height (DIP) for a work area `work_h` pixels tall at `dpi`.
#[must_use]
pub fn default_client_height(work_h: i32, dpi: u32) -> i32 {
    rescale(work_h, dpi, 96)
        .saturating_sub(DEFAULT_HEIGHT_MARGIN_DIP)
        .clamp(DEFAULT_HEIGHT_DIP.0, DEFAULT_HEIGHT_DIP.1)
}

/// The saver's state.
#[derive(Debug, Default)]
pub struct WindowSaver {
    /// The place last read or written (nothing is written while it is unchanged).
    last: Option<SavedWindow>,
    /// When the debounced write is due (main-timer ms).
    due_ms: Option<u64>,
    /// [`App::place_main_window`] ran (changes before it are the window's creation).
    ready: bool,
    /// The first show maximizes (the saved place was maximized).
    pub start_maximized: bool,
}

impl WindowSaver {
    /// A move, resize, maximize, restore or DPI change: the place is written 1 s after the last.
    pub fn changed(&mut self, now: u64) {
        if self.ready {
            self.due_ms = Some(now.saturating_add(SAVE_DELAY_MS));
        }
    }
}

impl App {
    /// Puts the hidden main window where it was last (`window.json`), or in the default place
    /// (spec/04 §1.7). Called once at start, before the first show (also `--background`).
    pub fn place_main_window(&mut self) {
        let saved = match read_limited_no_reparse(
            &self.paths.data.join(WINDOW_FILE),
            WINDOW_FILE_MAX_BYTES,
        ) {
            Ok(bytes) => {
                let parsed = SavedWindow::parse(&bytes);
                if parsed.is_none() {
                    logging::warn("app", "window.unreadable", &[]);
                }
                parsed
            }
            Err(FileError::NotFound) => None,
            Err(_) => {
                logging::warn("app", "window.unreadable", &[]);
                None
            }
        };
        let Some(main) = self.main.as_ref() else {
            return;
        };
        let restored = saved.and_then(|saved| {
            let monitor = yw_win::ui::monitor_for_rect(saved.rect)?;
            let min_outer = main.outer_size(MIN_CLIENT_DIP.0, MIN_CLIENT_DIP.1, monitor.dpi);
            restored_rect(&saved, Some(monitor), min_outer).map(|rect| (rect, saved.maximized))
        });
        match restored {
            Some((rect, maximized)) => {
                // Onto that monitor first (another DPI resizes the window by the suggested
                // rectangle), then the same rectangle again at its DPI.
                main.set_outer_rect(rect);
                main.set_outer_rect(rect);
                self.window_state.start_maximized = maximized;
            }
            None => {
                if let Some(area) = main.monitor_area() {
                    let height = default_client_height(area.work.h, area.dpi);
                    let (w, h) = main.outer_size(DEFAULT_WIDTH_DIP, height, area.dpi);
                    let (w, h) = (w.min(area.work.w), h.min(area.work.h));
                    main.set_outer_rect(Rect::new(
                        area.work.x.saturating_add((area.work.w - w) / 2),
                        area.work.y.saturating_add((area.work.h - h) / 2),
                        w,
                        h,
                    ));
                }
            }
        }
        // What is on disk now (the default place is not written until it changes).
        self.window_state.last = saved
            .filter(|_| restored.is_some())
            .or_else(|| self.window_now());
        self.window_state.ready = true;
    }

    fn window_now(&self) -> Option<SavedWindow> {
        let placement = self.main.as_ref()?.placement()?;
        Some(SavedWindow {
            rect: placement.rect,
            maximized: placement.maximized,
            dpi: placement.dpi,
        })
    }

    /// The main-timer part: the debounced write.
    pub(crate) fn window_state_tick(&mut self, now: u64) {
        if self.window_state.due_ms.is_some_and(|due| now >= due) {
            self.save_window_state();
        }
    }

    /// Writes `window.json` when the place changed (the debounced write and the exit).
    pub(crate) fn save_window_state(&mut self) {
        self.window_state.due_ms = None;
        if !self.window_state.ready {
            return;
        }
        let Some(now) = self.window_now() else {
            return;
        };
        if self.window_state.last == Some(now) {
            return;
        }
        match atomic_write(&self.paths.data.join(WINDOW_FILE), now.to_json().as_bytes()) {
            Ok(()) => self.window_state.last = Some(now),
            Err(_) => logging::warn("app", "window.save_failed", &[]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MonitorArea, Rect, SavedWindow, default_client_height, restored_rect};

    fn saved(x: i32, y: i32, w: i32, h: i32, dpi: u32) -> SavedWindow {
        SavedWindow {
            rect: Rect::new(x, y, w, h),
            maximized: false,
            dpi,
        }
    }

    /// 2-12: a place the monitors no longer show (enough of) goes to the default place; one that
    /// is shown keeps its position, converted to the monitor's DPI and kept inside its work area.
    #[test]
    fn a_saved_place_off_every_monitor_goes_to_the_default_place() {
        let monitor = MonitorArea {
            work: Rect::new(0, 0, 1_920, 1_040),
            dpi: 96,
        };
        let min = (736, 559);
        // On no monitor (a disconnected one): the default place.
        assert_eq!(
            restored_rect(&saved(-3_000, 0, 976, 719, 96), None, min),
            None
        );
        // On a monitor, but only 100×719 px of it visible (< 160×120 DIP): the default place.
        assert_eq!(
            restored_rect(&saved(1_820, 100, 976, 719, 96), Some(monitor), min),
            None
        );
        // Enough of it visible: moved inside the work area.
        assert_eq!(
            restored_rect(&saved(1_500, 100, 976, 719, 96), Some(monitor), min),
            Some(Rect::new(944, 100, 976, 719))
        );
        // Saved at 192 DPI, now 96: the size follows the scale, never below the minimum.
        assert_eq!(
            restored_rect(&saved(10, 10, 1_952, 1_000, 192), Some(monitor), min),
            Some(Rect::new(10, 10, 976, 559))
        );
        // The file's strict form round-trips; anything else is refused.
        let place = saved(-1_280, 40, 976, 719, 120);
        assert_eq!(SavedWindow::parse(place.to_json().as_bytes()), Some(place));
        for bad in [
            &b"{\"v\":2,\"x\":0,\"y\":0,\"w\":1,\"h\":1,\"max\":false,\"dpi\":96}"[..],
            b"{\"v\":1,\"x\":0,\"y\":0,\"w\":0,\"h\":1,\"max\":false,\"dpi\":96}",
            b"{\"v\":1,\"x\":0,\"y\":0,\"w\":1,\"h\":1,\"max\":0,\"dpi\":96}",
            b"{\"v\":1,\"x\":0,\"y\":0,\"w\":1,\"h\":1,\"max\":false,\"dpi\":96,\"z\":1}",
        ] {
            assert_eq!(SavedWindow::parse(bad), None);
        }
        // Default height: the work area less 96 DIP, within 680–900.
        assert_eq!(default_client_height(1_040, 96), 900);
        assert_eq!(default_client_height(1_400, 144), 837);
        assert_eq!(default_client_height(700, 96), 680);
    }
}
