//! yw-app entry point (spec/04 §1.1, §1.4). The binary only wires the process together; the
//! logic lives in the library.
#![windows_subsystem = "windows"]
#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::ExitCode;
use std::rc::Rc;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use yw_app::app::{
    App, MAIN_CLASS, MUTEX_NAME, Paths, SECRET_INPUT_CLASS, SECRET_VIEW_CLASS, load_apikeys,
    load_settings,
};
use yw_app::errors::ErrorCode;
use yw_app::events::{
    EventQueue, KeyJob, UiEvent, WM_YW_ACTIVATE, WM_YW_EVENTS, WM_YW_LOCK_SHORTCUT,
};
use yw_app::logging::{self, Field};
use yw_app::rpc::{RPC_TIMEOUTS, Transport};
use yw_app::settings::LogLevel;
use yw_app::workers::key::{KeyWorker, run as run_key_worker};
use yw_app::workers::rpc::run as run_rpc_worker;
use yw_win::input::is_down;
use yw_win::process::{InstanceError, SingleInstance};
use yw_win::ui::{self, CaptureExclusion, ClassSpec, InputKind, MbKind};

const EXIT_ARGUMENTS: u8 = 2;
const EXIT_INIT: u8 = 10;
const VK_CONTROL: u16 = 0x11;
const VK_MENU: u16 = 0x12;
const VK_L: u16 = 0x4C;

/// Second instance started by the user: bring the first one forward (spec/04 §1.1).
fn hand_off() {
    for _ in 0..10 {
        if let Some((poster, pid)) = ui::find_window(MAIN_CLASS) {
            let _ = yw_win::allow_set_foreground_window(pid);
            let _ = poster.post(WM_YW_ACTIVATE, 0);
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// `%LOCALAPPDATA%\YourWallet\v3\` and `logs\` (spec/04 §1.4-3).
fn data_paths() -> Option<Paths> {
    let local = PathBuf::from(std::env::var_os("LOCALAPPDATA")?);
    if !local.is_absolute() {
        return None;
    }
    let data = local.join("YourWallet").join("v3");
    let logs = data.join("logs");
    yw_win::file::ensure_dir(&data).ok()?;
    yw_win::file::ensure_dir(&logs).ok()?;
    for name in ["settings.json.tmp", "apikeys.dpapi.tmp"] {
        let _ = std::fs::remove_file(data.join(name));
    }
    Some(Paths { data, logs })
}

fn fail(text: &str) -> ExitCode {
    let _ = ui::message_box(None, text, "Your Wallet", MbKind::Error);
    ExitCode::from(EXIT_INIT)
}

#[expect(
    clippy::too_many_lines,
    reason = "the startup sequence of spec/04 §1.4 in order"
)]
fn main() -> ExitCode {
    // 1. Process setup (failures are logged in step 4 and ignored).
    let init_results = [
        ("init_process", yw_win::process::init_process()),
        ("ui_init", ui::init()),
        (
            "wer_exclude",
            yw_win::process::exclude_from_error_reporting(),
        ),
    ];

    // 2. Arguments and single instance.
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let background = match args.as_slice() {
        [] => false,
        [arg] if arg == "--background" => true,
        _ => return ExitCode::from(EXIT_ARGUMENTS),
    };
    let _instance = match SingleInstance::acquire(MUTEX_NAME) {
        Ok(instance) => instance,
        Err(InstanceError::AlreadyRunning) => {
            if !background {
                hand_off();
            }
            return ExitCode::SUCCESS;
        }
        Err(InstanceError::Os(_)) => {
            return fail("Your Wallet을 시작하지 못했습니다. (단일 인스턴스)");
        }
    };

    // 3. Data folder.
    let Some(paths) = data_paths() else {
        return fail("데이터 폴더를 만들지 못했습니다. LOCALAPPDATA 경로와 권한을 확인하세요.");
    };

    // 4. Logging.
    logging::init(&paths.logs, LogLevel::Info);
    logging::info(
        "app",
        "app.start",
        &[
            ("version", Field::Word(env!("CARGO_PKG_VERSION"))),
            (
                "background",
                Field::Word(if background { "yes" } else { "no" }),
            ),
        ],
    );
    for (step, result) in init_results {
        if let Err(error) = result {
            logging::warn(
                "app",
                "init.failed",
                &[
                    ("step", Field::Word(step)),
                    ("code", Field::Num(u64::from(error.code))),
                ],
            );
        }
    }

    // 5. settings.json and apikeys.dpapi.
    let loaded = load_settings(&paths);
    logging::set_level(loaded.settings.log_level);
    let (apikeys, apikeys_unreadable) = load_apikeys(&paths, &loaded.settings);
    let app = Rc::new(RefCell::new(App::new(
        paths.clone(),
        background,
        loaded.settings,
        apikeys,
    )));
    {
        let mut state = app.borrow_mut();
        if !loaded.banners.is_empty() {
            logging::warn(
                "app",
                "settings.invalid",
                &[("code", Field::Code(ErrorCode::App001))],
            );
            state.banner(
                Some(ErrorCode::App001),
                ErrorCode::App001.render(&loaded.banners.join(", ")),
            );
        }
        if apikeys_unreadable {
            logging::warn(
                "app",
                "apikeys.unreadable",
                &[("code", Field::Code(ErrorCode::Key001))],
            );
            state.banner(Some(ErrorCode::Key001), ErrorCode::Key001.text());
        }
    }

    // 6. Window classes, main window (hidden), session notifications.
    for spec in [
        ClassSpec {
            name: MAIN_CLASS,
            secret: false,
            capture: CaptureExclusion::Preferred,
        },
        ClassSpec {
            name: SECRET_INPUT_CLASS,
            secret: true,
            capture: CaptureExclusion::Preferred,
        },
        ClassSpec {
            name: SECRET_VIEW_CLASS,
            secret: true,
            capture: CaptureExclusion::Required,
        },
    ] {
        if ui::register_class(&spec).is_err() {
            return fail("창 클래스를 등록하지 못했습니다.");
        }
    }
    if App::create_main_window(&app).is_err() {
        return fail("주 창을 만들지 못했습니다.");
    }
    let Some(poster) = app.borrow().main_poster() else {
        return fail("주 창을 만들지 못했습니다.");
    };
    app.borrow_mut().register_session();

    // 7. Workers.
    let events = Arc::new(EventQueue::new(Box::new(move || {
        let _ = poster.post(WM_YW_EVENTS, 0);
    })));
    {
        let mut state = app.borrow_mut();
        let (queue, signal) = state.worker_channels();
        let key_events = Arc::clone(&events);
        let dir = paths.data.clone();
        let key_thread = std::thread::Builder::new()
            .name("yw-key".to_owned())
            .spawn(move || {
                run_key_worker(
                    KeyWorker::new(&dir),
                    &queue,
                    &|result| {
                        if key_events.push(UiEvent::Key(result)).is_err() {
                            logging::warn("key", "E-APP-005", &[]);
                        }
                    },
                    &signal,
                );
            });
        let (rpc_tx, rpc_rx) = mpsc::channel();
        let rpc_events = Arc::clone(&events);
        let rpc_thread = std::thread::Builder::new()
            .name("yw-rpc".to_owned())
            .spawn(move || {
                let client = yw_win::http::Client::new(RPC_TIMEOUTS).ok();
                if client.is_none() {
                    logging::warn("rpc", "client.init_failed", &[]);
                }
                run_rpc_worker(
                    client.as_ref().map(|client| client as &dyn Transport),
                    &rpc_rx,
                    &rpc_events,
                );
            });
        match (key_thread, rpc_thread) {
            (Ok(key_thread), Ok(rpc_thread)) => {
                state.attach_workers(Arc::clone(&events), vec![key_thread, rpc_thread], rpc_tx);
            }
            _ => return fail("작업 스레드를 시작하지 못했습니다."),
        }
        // 8. Classify the vault.
        state.key(KeyJob::Load);
        // 9. Show unless started for the browser.
        if !background {
            state.show_main();
        }
    }

    // 10. The message loop.
    let observer = Rc::clone(&app);
    let code = ui::run_loop(&mut |kind, _| {
        if let Ok(mut state) = observer.try_borrow_mut() {
            state.note_input();
        }
        if kind == (InputKind::Key { vk: Some(VK_L) }) && is_down(VK_CONTROL) && !is_down(VK_MENU) {
            let _ = poster.post(WM_YW_LOCK_SHORTCUT, 0);
        }
    });
    logging::flush();
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
