//! yw-host entry point (console subsystem, spec/05 §7). Owns the threads and the only exit:
//! thread R (stdin → queue), thread W (pipe → stdout, after the hello) and the main thread (connect
//! loop, then queue → pipe or UNAVAILABLE mode). The logic lives in the library.
#![forbid(unsafe_code)]

use std::io::Write as _;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use yw_host::{EXIT_IO, SystemEnv};
use yw_win::{StdIn, StdOut, allow_set_foreground_window};

static REPORTED: AtomicBool = AtomicBool::new(false);

#[expect(
    clippy::exit,
    reason = "stdin/pipe 리더 스레드가 메인이 블록된 I/O 중에 프로세스를 끝내야 함"
)]
fn terminate(code: u8) -> ! {
    std::process::exit(i32::from(code))
}

/// At most one stderr line `yw-host: <code-word>` (never message content), then exit.
fn finish(code: u8) -> ! {
    if let Some(word) = yw_host::code_word(code)
        && !REPORTED.swap(true, Ordering::SeqCst)
    {
        let _ = std::io::stderr().write_all(format!("yw-host: {word}\n").as_bytes());
    }
    terminate(code)
}

fn spawn_or_exit(body: impl FnOnce() + Send + 'static) {
    if thread::Builder::new().spawn(body).is_err() {
        finish(EXIT_IO);
    }
}

fn main() -> ExitCode {
    // DLLs load from System32 only (spec/01 §7.6); a failure is not fatal, like in yw-app.
    let _ = yw_win::process::init_process();
    let args: Vec<_> = std::env::args_os().collect();
    let origin = match yw_host::check_args(&args) {
        Ok(origin) => origin,
        Err(code) => finish(code),
    };
    let (queue, frames) = mpsc::sync_channel(yw_host::QUEUED_FRAMES);
    spawn_or_exit(move || finish(yw_host::pump_stdin(&mut StdIn, &queue)));

    let debug = cfg!(debug_assertions);
    let connected = yw_host::pipe_name(&|key| std::env::var_os(key), debug)
        .and_then(|name| yw_host::connect_app(&mut SystemEnv::default(), &name))
        .and_then(|duplex| yw_host::handshake(duplex, &origin));
    let code = match connected {
        Some((mut reader, mut writer, app_pid)) => {
            spawn_or_exit(move || finish(yw_host::pump_app(&mut reader, &mut StdOut)));
            // `app_pid` passed the server-process check of `handshake` (spec/05 §8.1 H1).
            yw_host::relay_to_app(&frames, &mut writer, || {
                let _ = allow_set_foreground_window(app_pid);
            })
        }
        None => yw_host::run_unavailable(
            &frames,
            &mut StdOut,
            Duration::from_millis(yw_host::UNAVAILABLE_IDLE_MS),
        ),
    };
    finish(code)
}
