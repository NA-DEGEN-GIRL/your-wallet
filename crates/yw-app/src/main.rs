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
    App, INSTANCE_ALIAS, INSTANCE_BOUNDARY, INSTANCE_MUTEX, MAIN_CLASS, Paths, SECRET_INPUT_CLASS,
    SECRET_VIEW_CLASS, load_apikeys, load_settings,
};
use yw_app::app_approval::{APPROVAL_CLASS, PANEL_CLASS};
use yw_app::app_browser::BrowserUi;
use yw_app::errors::ErrorCode;
use yw_app::events::{
    EventQueue, KeyJob, NavKey, Shortcut, UiEvent, WM_YW_ACTIVATE, WM_YW_EVENTS,
    WM_YW_LOCK_SHORTCUT, WM_YW_NAV_KEY, WM_YW_SHORTCUT, WM_YW_TAB_SHORTCUT, chain_tab_key,
};
use yw_app::logging::{self, Field};
use yw_app::rpc::{RPC_TIMEOUTS, Transport};
use yw_app::settings::LogLevel;
use yw_app::workers::key::{KeyWorker, run as run_key_worker};
use yw_app::workers::rpc::{RpcWorker, run as run_rpc_worker};
use yw_win::clipboard::SecretClip;
use yw_win::input::{is_down, is_down_in_message};
use yw_win::process::{InstanceError, SingleInstance};
use yw_win::ui::{self, CaptureExclusion, ClassSpec, InputKind, MbKind};

const EXIT_ARGUMENTS: u8 = 2;
const EXIT_INIT: u8 = 10;
const VK_SHIFT: u16 = 0x10;
const VK_CONTROL: u16 = 0x11;
const VK_MENU: u16 = 0x12;
const VK_L: u16 = 0x4C;

/// Second instance started by the user: bring the first one forward (spec/04 §1.1). Only a
/// window whose process runs this executable at Medium integrity or higher gets the foreground
/// right and the activate message; a window of our class owned by any other process is
/// ignored. `false` when only such impostor windows were found.
fn hand_off() -> bool {
    let own_exe = std::env::current_exe().ok();
    let mut impostor = false;
    for _ in 0..10 {
        for (poster, pid) in ui::find_windows(MAIN_CLASS) {
            let verified = own_exe
                .as_deref()
                .is_some_and(|exe| yw_win::security::verify_process(pid, exe).is_ok());
            if verified {
                let _ = yw_win::allow_set_foreground_window(pid);
                let _ = poster.post(WM_YW_ACTIVATE, 0);
                return true;
            }
            impostor = true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    !impostor
}

/// A data folder check that did something (logged once logging runs).
type DirReport = (&'static str, yw_win::security::PrivateDir);

/// Why the data folder could not be prepared.
enum DataDirError {
    /// `LOCALAPPDATA` missing or relative, or a folder could not be created.
    Unavailable,
    /// Owned by someone else or open to others in a way this user cannot repair.
    Untrusted,
    /// This folder (as shown to the user) is a link (junction, symbolic link) or a file.
    NotPlain(&'static str),
}

/// `%LOCALAPPDATA%\YourWallet`, `v3\` and `logs\` (spec/04 §1.4-3), each created or checked by
/// `ensure_private_dir`: protected DACL (user, SYSTEM, Administrators), Medium no-read-up /
/// no-write-up label, extra grants on a folder the user owns repaired.
fn data_paths() -> Result<(Paths, Vec<DirReport>), DataDirError> {
    let local = PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or(DataDirError::Unavailable)?);
    if !local.is_absolute() {
        return Err(DataDirError::Unavailable);
    }
    let user = yw_win::current_user_sid_string().map_err(|_| DataDirError::Unavailable)?;
    let base = local.join("YourWallet");
    let data = base.join("v3");
    let logs = data.join("logs");
    let mut reports = Vec::new();
    for (tag, shown, dir) in [
        ("base", "%LOCALAPPDATA%\\YourWallet", &base),
        ("data", "%LOCALAPPDATA%\\YourWallet\\v3", &data),
        ("logs", "%LOCALAPPDATA%\\YourWallet\\v3\\logs", &logs),
    ] {
        match yw_win::security::ensure_private_dir(dir, &user) {
            Ok(outcome) => {
                if outcome.repaired || outcome.entries_repaired > 0 {
                    reports.push((tag, outcome));
                }
            }
            Err(yw_win::security::PrivateDirError::Untrusted) => {
                return Err(DataDirError::Untrusted);
            }
            Err(yw_win::security::PrivateDirError::NotPlainDir) => {
                return Err(DataDirError::NotPlain(shown));
            }
            Err(_) => return Err(DataDirError::Unavailable),
        }
    }
    for name in ["settings.json.tmp", "apikeys.dpapi.tmp", "window.json.tmp"] {
        let _ = std::fs::remove_file(data.join(name));
    }
    Ok((Paths { data, logs }, reports))
}

fn fail(text: &str) -> ExitCode {
    let _ = ui::message_box(None, text, "Your Wallet", MbKind::Error);
    ExitCode::from(EXIT_INIT)
}

/// The panic hook (spec/04 §1.5-6). A panic on any thread aborts the process (`panic = "abort"`,
/// D28) without the orderly exit, so this is the last code of ours to run: one `app.panic` line
/// with where it happened (never the message) flushed with the lines buffered before it, one
/// attempt to empty the clipboard of a secret copy (no window, no sleep; the next start clears
/// what is left, spec/04 §4.8), then the default hook (stderr, when there is one) and the abort.
fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        logging::panic_line(info.location());
        let _ = yw_win::clipboard::try_clear_secret_windowless(&SecretClip::ANY);
        default(info);
    }));
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
    let session = yw_win::security::current_session_id().unwrap_or(0);
    let instance_name = format!("{INSTANCE_MUTEX}.{session}");
    let _instance = match SingleInstance::acquire_private(
        INSTANCE_BOUNDARY,
        INSTANCE_ALIAS,
        &instance_name,
    ) {
        Ok(instance) => instance,
        Err(InstanceError::AlreadyRunning) => {
            if !background && !hand_off() {
                return fail(
                    "실행 중인 Your Wallet 창을 확인하지 못했습니다. 같은 이름의 창이 이 실행 파일이 아닌 다른 프로그램(또는 다른 위치의 Your Wallet)에 속해 있어 전환하지 않았습니다. 작업 표시줄에서 Your Wallet을 직접 여세요.",
                );
            }
            return ExitCode::SUCCESS;
        }
        Err(InstanceError::Os(_)) => {
            return fail("Your Wallet을 시작하지 못했습니다. (단일 인스턴스)");
        }
    };

    // 3. Data folder.
    let (paths, dir_reports) = match data_paths() {
        Ok(found) => found,
        Err(DataDirError::Untrusted) => {
            return fail(
                "데이터 폴더(%LOCALAPPDATA%\\YourWallet)를 열지 않았습니다. 이 폴더나 안의 파일이 다른 계정의 소유이거나, 이 사용자가 고칠 수 없는 방식으로 다른 계정에 열려 있습니다. 지갑 파일을 보호하기 위해 시작을 멈춥니다.",
            );
        }
        Err(DataDirError::Unavailable) => {
            return fail("데이터 폴더를 만들지 못했습니다. LOCALAPPDATA 경로와 권한을 확인하세요.");
        }
        Err(DataDirError::NotPlain(shown)) => {
            return fail(&format!(
                "다음 데이터 폴더가 링크(정션·심볼릭 링크)이거나 폴더가 아닌 파일입니다: {shown}\n\n지갑 파일을 보호하기 위해 링크된 데이터 폴더는 쓰지 않습니다. 다른 드라이브로 옮기고 링크를 만들었다면 링크만 지우고(대상 폴더의 지갑 파일은 지우지 마세요) 옮긴 폴더를 원래 자리로 되돌린 뒤 다시 시작하세요."
            ));
        }
    };

    // 4. Logging, and the panic hook that writes to it. The installed commit (checked, 2026-11-10)
    // says which build wrote the lines that follow.
    logging::init(&paths.logs, LogLevel::Info);
    install_panic_hook();
    let install_commit = yw_app::build_info::read_install_commit();
    let mut start_fields = vec![
        ("version", Field::Word(env!("CARGO_PKG_VERSION"))),
        (
            "background",
            Field::Word(if background { "yes" } else { "no" }),
        ),
    ];
    if let Some(commit) = install_commit.as_deref() {
        start_fields.push(("commit", Field::Commit(commit)));
    }
    logging::info("app", "app.start", &start_fields);
    for (dir, outcome) in dir_reports {
        logging::info(
            "app",
            "datadir.acl_repaired",
            &[
                ("dir", Field::Word(dir)),
                (
                    "folder",
                    Field::Word(if outcome.repaired { "yes" } else { "no" }),
                ),
                ("entries", Field::Num(u64::from(outcome.entries_repaired))),
            ],
        );
    }
    let mut wer_unprotected = false;
    for (step, result) in init_results {
        if let Err(error) = result {
            wer_unprotected |= step == "wer_exclude";
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
        } else {
            // Networks added since the addresses were made get the template's address.
            state.fill_template_gaps();
        }
        if wer_unprotected {
            // Review L9: crash dumps are possible; say so instead of only logging it.
            state.note_wer_unprotected();
        }
        state.set_install_commit(install_commit);
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
        ClassSpec {
            name: APPROVAL_CLASS,
            secret: false,
            capture: CaptureExclusion::Preferred,
        },
        ClassSpec {
            name: PANEL_CLASS,
            secret: false,
            capture: CaptureExclusion::Preferred,
        },
    ] {
        if ui::register_class(&spec).is_err() {
            return fail("창 클래스를 등록하지 못했습니다.");
        }
    }
    if App::create_main_window(&app).is_err() {
        return fail("주 창을 만들지 못했습니다.");
    }
    // Where it was last (window.json), also for --background (spec/04 §1.7).
    app.borrow_mut().place_main_window();
    let Some(poster) = app.borrow().main_poster() else {
        return fail("주 창을 만들지 못했습니다.");
    };
    {
        let mut state = app.borrow_mut();
        // A secret copy an earlier run left on the clipboard (spec/04 §4.8).
        state.clear_earlier_secret_clip();
        state.register_session();
    }

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
                        if key_events.push(UiEvent::Key(Box::new(result))).is_err() {
                            logging::warn("key", "E-APP-005", &[]);
                        }
                    },
                    &signal,
                );
            });
        let (rpc_tx, rpc_rx) = mpsc::channel();
        let rpc_events = Arc::clone(&events);
        // One HTTPS client shared by yw-rpc and yw-read-0..3 (spec/04 §1.2, §1.9).
        let client = yw_win::http::Client::new(RPC_TIMEOUTS).ok();
        if client.is_none() {
            logging::warn("rpc", "client.init_failed", &[]);
        }
        let transport = client.map(|client| Arc::new(client) as Arc<dyn Transport>);
        let rpc_transport = transport.clone();
        let rpc_thread = std::thread::Builder::new()
            .name("yw-rpc".to_owned())
            .spawn(move || {
                run_rpc_worker(RpcWorker::production(rpc_transport), &rpc_rx, &rpc_events);
            });
        match (key_thread, rpc_thread) {
            (Ok(key_thread), Ok(rpc_thread)) => {
                state.attach_workers(Arc::clone(&events), vec![key_thread, rpc_thread], rpc_tx);
            }
            _ => return fail("작업 스레드를 시작하지 못했습니다."),
        }
        // Browser bridge: dispatcher, read workers, pipe server (spec/05 §8.1, within 2 s).
        state.attach_browser(BrowserUi::start(&events, transport));
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
        // Page Up/Down, Ctrl+Home/End, Tab, arrows: the main window scrolls after the dialog
        // manager has handled the key (spec/04 §1.7; it decides whether it applies). The
        // modifiers as of this message, as the dialog manager reads Shift for Shift+Tab.
        let nav = match kind {
            InputKind::Key { vk: Some(vk) } => NavKey::of(
                vk,
                is_down_in_message(VK_CONTROL),
                is_down_in_message(VK_MENU),
                is_down_in_message(VK_SHIFT),
            ),
            _ => None,
        };
        if let Ok(mut state) = observer.try_borrow_mut() {
            state.note_input();
            if let Some(key) = nav {
                state.note_nav_key(key);
            }
        }
        if let Some(key) = nav {
            let _ = poster.post(WM_YW_NAV_KEY, key.code());
        }
        if kind == (InputKind::Key { vk: Some(VK_L) }) && is_down(VK_CONTROL) && !is_down(VK_MENU) {
            let _ = poster.post(WM_YW_LOCK_SHORTCUT, 0);
        }
        // F5 (the visible tab's refresh) and Ctrl+, (settings), 2026-11-10: the main window
        // decides whether they apply.
        if let InputKind::Key { vk: Some(vk) } = kind
            && let Some(shortcut) = Shortcut::of(vk, is_down(VK_CONTROL), is_down(VK_MENU))
        {
            let _ = poster.post(WM_YW_SHORTCUT, shortcut.code());
        }
        // Ctrl+1/2/3/4: chain tabs EVM·Solana·Bitcoin·Zcash (the main window decides whether
        // it applies).
        if let InputKind::Key { vk: Some(vk) } = kind
            && let Some(tab) = chain_tab_key(vk)
            && is_down(VK_CONTROL)
            && !is_down(VK_MENU)
        {
            let _ = poster.post(WM_YW_TAB_SHORTCUT, tab);
        }
    });
    logging::flush();
    ExitCode::from(u8::try_from(code).unwrap_or(1))
}
