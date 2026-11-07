//! Scroll repaint check — **DEV ONLY** (`#[ignore]`, debug test builds, like the tour): drives the
//! main window's real scroll paths (posted wheel notches that glide, touchpad-sized deltas, the
//! scroll bar's line/page/end codes, a re-layout while a glide runs) on settings → 네트워크(RPC)
//! with a made-up `*.example.test` RPC URL on every network (the screen after `rpc.json에서
//! 가져오기`), and compares what the window shows with a full repaint and with a fresh layout at the
//! same offset. Any differing pixel is a stale image the scroll left behind.
//!
//! The scenes run twice: as the tour runs (DPI-unaware, so 96 DPI scaled by the system, classic
//! controls) and as the installed app runs (`plain` / `app`: themed comctl32 v6 controls from the
//! app's manifest at the monitor's DPI, Per-Monitor-V2). The window is moved off the mouse pointer
//! first, because a themed control under a still pointer keeps a hover shade.
//!
//! `cargo test -p yw-app --lib ui::tour::scroll -- --ignored --nocapture`

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use yw_win::http::HttpsUrl;
use yw_win::ui::Hwnd;
use yw_win::ui::capture::{
    Capture, capture_client, dev_tour_app_env, dev_tour_clear_of_pointer, dev_tour_flush,
    dev_tour_post_vscroll, dev_tour_post_wheel, dev_tour_redraw,
};

use super::{UNLOCKED, main_hwnd, pump, register_classes, tour_apikeys, tour_meta, tour_settings};
use crate::app::{App, Paths, Screen, SettingsSection};
use crate::events::{EventQueue, RpcEvent, UiEvent, WM_YW_EVENTS};

const SB_LINEDOWN: u16 = 1;
const SB_PAGEUP: u16 = 2;
const SB_PAGEDOWN: u16 = 3;
const SB_TOP: u16 = 6;
const SB_BOTTOM: u16 = 7;

/// Pixels that differ between two captures of the same size, and their bounding rows.
fn differing(a: &Capture, b: &Capture) -> (usize, Option<(u32, u32)>) {
    assert_eq!((a.width, a.height), (b.width, b.height));
    let stride = usize::try_from(a.width.saturating_mul(3).saturating_add(3) / 4 * 4).unwrap();
    let width = usize::try_from(a.width).unwrap();
    let height = usize::try_from(a.height).unwrap();
    let (pa, pb) = (&a.bmp[54..], &b.bmp[54..]);
    let mut count = 0;
    let mut rows: Option<(u32, u32)> = None;
    for line in 0..height {
        let start = line * stride;
        let row_a = &pa[start..start + width * 3];
        let row_b = &pb[start..start + width * 3];
        let changed = row_a
            .chunks_exact(3)
            .zip(row_b.chunks_exact(3))
            .filter(|(x, y)| x != y)
            .count();
        if changed > 0 {
            count += changed;
            // Bottom-up rows: line 0 is the client's last row.
            let y = u32::try_from(height - 1 - line).unwrap();
            rows = Some(rows.map_or((y, y), |(top, bottom)| (top.min(y), bottom.max(y))));
        }
    }
    (count, rows)
}

struct Probe {
    app: Rc<RefCell<App>>,
    hwnd: Hwnd,
    /// `plain` or `app` (module docs).
    env: &'static str,
    failures: Vec<String>,
}

impl Probe {
    /// Compares the current frame with a full repaint and with a fresh layout at the same offset.
    #[expect(clippy::print_stdout, reason = "the check reports each scene")]
    fn check(&mut self, scene: &str) {
        dev_tour_flush();
        let seen = capture_client(self.hwnd).unwrap();
        dev_tour_redraw(self.hwnd);
        dev_tour_flush();
        let repainted = capture_client(self.hwnd).unwrap();
        self.app.borrow_mut().refresh();
        dev_tour_redraw(self.hwnd);
        dev_tour_flush();
        let fresh = capture_client(self.hwnd).unwrap();
        let (stale, stale_rows) = differing(&seen, &repainted);
        let (misplaced, misplaced_rows) = differing(&repainted, &fresh);
        let scroll = self.app.borrow().scroll;
        let env = self.env;
        println!(
            "scroll-check: {env:<5} {scene:<28} scroll {scroll:>5}  stale px {stale:>7} rows {stale_rows:?}  misplaced px {misplaced:>7} rows {misplaced_rows:?}"
        );
        if stale != 0 || misplaced != 0 {
            self.failures.push(format!("{env}: {scene}"));
        }
        if std::env::var_os("YW_SCROLL_DUMP").is_some() && stale != 0 {
            let dir = super::out_dir();
            let _ = std::fs::create_dir_all(&dir);
            let name = scene.replace(' ', "-");
            let _ = std::fs::write(dir.join(format!("scroll-{env}-{name}-seen.bmp")), &seen.bmp);
            let _ = std::fs::write(
                dir.join(format!("scroll-{env}-{name}-fresh.bmp")),
                &fresh.bmp,
            );
        }
    }

    fn wheel(&self, delta: i16, times: usize) {
        for _ in 0..times {
            dev_tour_post_wheel(self.hwnd, delta);
        }
    }

    fn bar(&self, code: u16, times: usize) {
        for _ in 0..times {
            dev_tour_post_vscroll(self.hwnd, code);
        }
    }
}

/// Runs every scene in a new main window on this thread; returns the failed scenes.
#[expect(clippy::print_stdout, reason = "the check reports the window's DPI")]
fn scenes(env: &'static str) -> Vec<String> {
    let dir = std::env::temp_dir().join(format!("yw-scroll-{env}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let app = Rc::new(RefCell::new(App::new(
        Paths {
            data: dir.clone(),
            logs: dir.join("logs"),
        },
        false,
        tour_settings(),
        tour_apikeys(),
    )));
    App::create_main_window(&app).unwrap();
    {
        let mut state = app.borrow_mut();
        state.mode = UNLOCKED;
        state.meta = Some(tour_meta());
        // Every network has a (made-up, never contacted) URL: 교체 · 테스트 · 삭제 on each row.
        for (index, network) in state.url_networks().into_iter().enumerate() {
            let url =
                HttpsUrl::parse(&format!("https://rpc-{index}.example.test/v1/token")).unwrap();
            state.apikeys.set_rpc(network, &url);
        }
        let poster = state.main_poster().unwrap();
        state.events = Some(std::sync::Arc::new(EventQueue::new(Box::new(move || {
            let _ = poster.post(WM_YW_EVENTS, 0);
        }))));
        state.show_main();
    }
    super::set_screen(&app, UNLOCKED, Screen::Settings(SettingsSection::Network));
    pump(300);
    let hwnd = main_hwnd(&app).unwrap();
    let moved = dev_tour_clear_of_pointer(hwnd);
    if moved {
        pump(300);
    }
    println!(
        "scroll-check: {env:<5} dpi {} content {} px, moved off the pointer: {moved}",
        app.borrow().main.as_ref().unwrap().dpi(),
        app.borrow().placed.content_height
    );
    let mut probe = Probe {
        app: Rc::clone(&app),
        hwnd,
        env,
        failures: Vec::new(),
    };
    probe.check("start");

    probe.wheel(-120, 1);
    pump(150);
    probe.check("wheel notch (glide)");
    probe.wheel(-120, 3);
    pump(200);
    probe.check("3 wheel notches (glide)");
    // Frames inside a glide (the timer still running between checks).
    probe.wheel(-120, 3);
    for tick in 0..4 {
        pump(16);
        probe.check(&format!("mid-glide frame {tick}"));
    }
    pump(150);
    probe.wheel(-24, 12);
    pump(80);
    probe.check("touchpad deltas");
    probe.wheel(120, 2);
    pump(200);
    probe.check("wheel up (glide)");
    probe.bar(SB_LINEDOWN, 6);
    pump(80);
    probe.check("bar line down x6");
    probe.bar(SB_PAGEDOWN, 1);
    pump(80);
    probe.check("bar page down");
    probe.bar(SB_PAGEUP, 1);
    pump(80);
    probe.check("bar page up");
    probe.bar(SB_BOTTOM, 1);
    pump(80);
    probe.check("bar bottom");
    probe.bar(SB_TOP, 1);
    pump(80);
    probe.check("bar top");

    // A test result arrives while a glide runs: the banner re-lays the screen out mid-scroll.
    let networks = app.borrow().url_networks();
    for (round, network) in networks.iter().take(3).enumerate() {
        probe.wheel(-120, 2);
        pump(20);
        let events = app.borrow().events.clone().unwrap();
        events
            .push(UiEvent::Rpc(RpcEvent::Test {
                network: *network,
                message: format!("연결 확인 {round}"),
                ok: round % 2 == 0,
            }))
            .unwrap();
        pump(200);
        probe.check(&format!("re-layout mid-glide {round}"));
    }

    let Probe { failures, .. } = probe;
    // Destroyed here, while the environment it was made in is still active.
    let main = app.borrow_mut().main.take();
    drop(main);
    drop(app);
    let _ = std::fs::remove_dir_all(&dir);
    failures
}

#[test]
#[ignore = "DEV ONLY: opens a window on the desktop (scroll repaint check)"]
fn scrolling_leaves_no_stale_pixels() {
    register_classes();
    let mut failures = scenes("plain");
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("yw-app.manifest");
    let env = dev_tour_app_env(&manifest).unwrap();
    failures.extend(scenes("app"));
    drop(env);
    assert!(failures.is_empty(), "stale pixels after: {failures:?}");
}
