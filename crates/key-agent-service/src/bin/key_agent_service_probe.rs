//! Standalone desktop client for one debug-only, non-signing Approval exchange.
//!
//! No arguments, server selection, request bytes, wallet material, or credentials
//! are accepted. Default/release execution is silent and cannot reach RPC.

const UNAVAILABLE_EXIT: i32 = 78;

#[cfg(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "desktop-rpc-probe-feasibility-test-hook"
))]
fn main() {
    let started = std::time::Instant::now();
    // This standalone debug process owns its panic policy. Nothing installs a
    // hook in a library caller, and no panic payload may reach blocked stderr.
    std::panic::set_hook(Box::new(|_| {}));
    let Some(deadline) = started.checked_add(std::time::Duration::from_secs(25)) else {
        std::process::exit(UNAVAILABLE_EXIT);
    };
    let exit = watchdog::run_bounded(
        || watchdog::ProcessWatchdog::arm(deadline),
        || {
            let outcome = command_outcome(std::env::args_os().count(), || {
                platform_windows::run_non_signing_service_approval_probe().is_ok()
            });
            write_outcome(std::io::stdout().lock(), outcome)
        },
        watchdog::ProcessWatchdog::complete,
    );
    std::process::exit(exit);
}

#[cfg(not(all(
    windows,
    target_arch = "x86_64",
    target_env = "msvc",
    debug_assertions,
    feature = "desktop-rpc-probe-feasibility-test-hook"
)))]
fn main() {
    std::process::exit(UNAVAILABLE_EXIT);
}

#[cfg(any(
    test,
    all(
        windows,
        target_arch = "x86_64",
        target_env = "msvc",
        debug_assertions,
        feature = "desktop-rpc-probe-feasibility-test-hook"
    )
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeOutcome {
    Completed,
    Unavailable,
}

#[cfg(any(
    test,
    all(
        windows,
        target_arch = "x86_64",
        target_env = "msvc",
        debug_assertions,
        feature = "desktop-rpc-probe-feasibility-test-hook"
    )
))]
fn command_outcome(argument_count: usize, probe: impl FnOnce() -> bool) -> ProbeOutcome {
    if argument_count != 1 {
        return ProbeOutcome::Unavailable;
    }
    if probe() {
        ProbeOutcome::Completed
    } else {
        ProbeOutcome::Unavailable
    }
}

#[cfg(any(
    test,
    all(
        windows,
        target_arch = "x86_64",
        target_env = "msvc",
        debug_assertions,
        feature = "desktop-rpc-probe-feasibility-test-hook"
    )
))]
fn write_outcome(mut output: impl std::io::Write, outcome: ProbeOutcome) -> i32 {
    let (bytes, exit): (&[u8], i32) = match outcome {
        ProbeOutcome::Completed => (
            b"SERVICE_APPROVAL_TRANSPORT_COMPLETED_NOT_RELEASE_EVIDENCE\n",
            0,
        ),
        ProbeOutcome::Unavailable => (
            b"SERVICE_APPROVAL_TRANSPORT_UNAVAILABLE\n",
            UNAVAILABLE_EXIT,
        ),
    };
    if output
        .write_all(bytes)
        .and_then(|()| output.flush())
        .is_err()
    {
        return UNAVAILABLE_EXIT;
    }
    exit
}

#[cfg(any(
    test,
    all(
        windows,
        target_arch = "x86_64",
        target_env = "msvc",
        debug_assertions,
        feature = "desktop-rpc-probe-feasibility-test-hook"
    )
))]
mod watchdog {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::mpsc::{RecvTimeoutError, SyncSender, sync_channel};
    use std::thread::{Builder, JoinHandle};
    use std::time::{Duration, Instant};

    use super::UNAVAILABLE_EXIT;

    pub(super) struct ProcessWatchdog {
        completed: SyncSender<()>,
        worker: JoinHandle<()>,
        deadline: Instant,
    }

    impl ProcessWatchdog {
        pub(super) fn arm(deadline: Instant) -> Result<Self, ()> {
            remaining(deadline, Instant::now())?;
            let (completed, receiver) = sync_channel(1);
            let worker = Builder::new()
                .name("service-probe-deadline".to_owned())
                .spawn(move || {
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        #[cfg(test)]
                        inject_worker_panic_for_test();
                        wait_for_completion(deadline, Instant::now, |duration| {
                            receiver.recv_timeout(duration)
                        })
                    }));
                    if !matches!(result, Ok(Ok(()))) {
                        // ncalrpc does not promise an interruptible synchronous
                        // call. Terminate only this standalone debug process;
                        // do not claim RPC cancellation, joined IO, or RAII
                        // rundown of a still-executing server operation.
                        std::process::exit(UNAVAILABLE_EXIT);
                    }
                })
                .map_err(|_| ())?;
            Ok(Self {
                completed,
                worker,
                deadline,
            })
        }

        pub(super) fn complete(self) -> Result<(), ()> {
            let Self {
                completed,
                worker,
                deadline,
            } = self;
            complete_with(
                deadline,
                Instant::now,
                || completed.try_send(()).map_err(|_| ()),
                || worker.join().map_err(|_| ()),
            )
        }
    }

    fn remaining(deadline: Instant, now: Instant) -> Result<Duration, ()> {
        deadline
            .checked_duration_since(now)
            .filter(|duration| !duration.is_zero())
            .ok_or(())
    }

    #[cfg(test)]
    fn inject_worker_panic_for_test() {
        if std::env::var("YOUR_WALLET_PROBE_WATCHDOG_TEST_CHILD").as_deref() == Ok("worker-panic") {
            std::panic::resume_unwind(Box::new(()));
        }
    }

    pub(super) fn wait_for_completion(
        deadline: Instant,
        mut now: impl FnMut() -> Instant,
        receive: impl FnOnce(Duration) -> Result<(), RecvTimeoutError>,
    ) -> Result<(), ()> {
        let timeout = remaining(deadline, now())?;
        receive(timeout).map_err(|_| ())?;
        remaining(deadline, now())?;
        Ok(())
    }

    pub(super) fn complete_with(
        deadline: Instant,
        mut now: impl FnMut() -> Instant,
        send: impl FnOnce() -> Result<(), ()>,
        join: impl FnOnce() -> Result<(), ()>,
    ) -> Result<(), ()> {
        remaining(deadline, now())?;
        send()?;
        join()?;
        remaining(deadline, now())?;
        Ok(())
    }

    pub(super) fn run_bounded<Guard>(
        arm: impl FnOnce() -> Result<Guard, ()>,
        operation: impl FnOnce() -> i32,
        complete: impl FnOnce(Guard) -> Result<(), ()>,
    ) -> i32 {
        let Ok(Ok(guard)) = catch_unwind(AssertUnwindSafe(arm)) else {
            // Without a watchdog, even a fixed stdout failure message could
            // block. The caller exits silently before any RPC or output.
            return UNAVAILABLE_EXIT;
        };
        let Ok(exit) = catch_unwind(AssertUnwindSafe(operation)) else {
            return UNAVAILABLE_EXIT;
        };
        if matches!(
            catch_unwind(AssertUnwindSafe(|| complete(guard))),
            Ok(Ok(()))
        ) {
            exit
        } else {
            UNAVAILABLE_EXIT
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn arguments_are_never_forwarded_and_reject_before_any_probe() {
        for count in [0, 2, 100] {
            let calls = Cell::new(0);
            let result = command_outcome(count, || {
                calls.set(calls.get() + 1);
                true
            });
            assert_eq!(result, ProbeOutcome::Unavailable);
            assert_eq!(calls.get(), 0);
        }
    }

    #[test]
    fn one_exact_command_runs_once_without_retry() {
        for completed in [false, true] {
            let calls = Cell::new(0);
            let result = command_outcome(1, || {
                calls.set(calls.get() + 1);
                completed
            });
            assert_eq!(calls.get(), 1);
            assert_eq!(result == ProbeOutcome::Completed, completed);
        }
    }

    #[test]
    fn output_is_fixed_non_authorizing_and_data_free() {
        let mut output = Vec::new();
        assert_eq!(write_outcome(&mut output, ProbeOutcome::Completed), 0);
        assert_eq!(
            output,
            b"SERVICE_APPROVAL_TRANSPORT_COMPLETED_NOT_RELEASE_EVIDENCE\n"
        );
        output.clear();
        assert_eq!(
            write_outcome(&mut output, ProbeOutcome::Unavailable),
            UNAVAILABLE_EXIT
        );
        assert_eq!(output, b"SERVICE_APPROVAL_TRANSPORT_UNAVAILABLE\n");
    }

    #[test]
    fn failed_output_never_reports_success() {
        struct FailedOutput;
        impl std::io::Write for FailedOutput {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("output unavailable"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert_eq!(
            write_outcome(FailedOutput, ProbeOutcome::Completed),
            UNAVAILABLE_EXIT
        );
    }

    #[test]
    fn failed_flush_never_returns_a_successful_exit() {
        struct FailedFlush;
        impl std::io::Write for FailedFlush {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("output unavailable"))
            }
        }
        assert_eq!(
            write_outcome(FailedFlush, ProbeOutcome::Completed),
            UNAVAILABLE_EXIT
        );
    }

    #[test]
    fn watchdog_rejects_an_already_expired_or_equal_deadline_before_waiting() {
        let deadline = std::time::Instant::now();
        for now in [deadline, deadline + std::time::Duration::from_millis(1)] {
            let calls = Cell::new(0);
            assert_eq!(
                watchdog::wait_for_completion(
                    deadline,
                    || now,
                    |_| {
                        calls.set(calls.get() + 1);
                        Ok(())
                    }
                ),
                Err(())
            );
            assert_eq!(calls.get(), 0);
        }
    }

    #[test]
    fn watchdog_completion_uses_the_original_deadline_and_rejects_late_or_equal() {
        let started = std::time::Instant::now();
        let budget = std::time::Duration::from_millis(20);
        let deadline = started + budget;
        for observed in [started, deadline, deadline + budget] {
            let reads = Cell::new(0);
            let result = watchdog::wait_for_completion(
                deadline,
                || {
                    let index = reads.get();
                    reads.set(index + 1);
                    if index == 0 { started } else { observed }
                },
                |timeout| {
                    assert_eq!(timeout, budget);
                    Ok(())
                },
            );
            assert_eq!(result.is_ok(), observed < deadline);
            assert_eq!(reads.get(), 2);
        }
    }

    #[test]
    fn watchdog_disconnect_and_timeout_are_terminal_without_another_wait() {
        use std::sync::mpsc::RecvTimeoutError;
        let now = std::time::Instant::now();
        for failure in [RecvTimeoutError::Disconnected, RecvTimeoutError::Timeout] {
            let calls = Cell::new(0);
            assert_eq!(
                watchdog::wait_for_completion(
                    now + std::time::Duration::from_secs(1),
                    || now,
                    |_| {
                        calls.set(calls.get() + 1);
                        Err(failure)
                    }
                ),
                Err(())
            );
            assert_eq!(calls.get(), 1);
        }
    }

    #[test]
    fn watchdog_spawn_error_or_panic_precedes_all_rpc_and_output() {
        for panic in [false, true] {
            let operations = Cell::new(0);
            let completions = Cell::new(0);
            let exit = watchdog::run_bounded(
                || -> Result<(), ()> {
                    if panic {
                        std::panic::resume_unwind(Box::new(()));
                    }
                    Err(())
                },
                || {
                    operations.set(operations.get() + 1);
                    0
                },
                |()| {
                    completions.set(completions.get() + 1);
                    Ok(())
                },
            );
            assert_eq!(exit, UNAVAILABLE_EXIT);
            assert_eq!(operations.get(), 0);
            assert_eq!(completions.get(), 0);
        }
    }

    #[test]
    fn watchdog_is_joined_only_after_outcome_write_and_flush() {
        use std::cell::RefCell;
        struct RecordedOutput<'a>(&'a RefCell<Vec<&'static str>>);
        impl std::io::Write for RecordedOutput<'_> {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.borrow_mut().push("write");
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.0.borrow_mut().push("flush");
                Ok(())
            }
        }
        let events = RefCell::new(Vec::new());
        let exit = watchdog::run_bounded(
            || {
                events.borrow_mut().push("arm");
                Ok(())
            },
            || {
                events.borrow_mut().push("rpc");
                write_outcome(RecordedOutput(&events), ProbeOutcome::Completed)
            },
            |()| {
                events.borrow_mut().push("complete");
                Ok(())
            },
        );
        assert_eq!(exit, 0);
        assert_eq!(
            *events.borrow(),
            ["arm", "rpc", "write", "flush", "complete"]
        );
    }

    #[test]
    fn watchdog_operation_panic_drops_its_owner_and_never_signals_success() {
        struct Guard<'a>(&'a Cell<u32>);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let drops = Cell::new(0);
        let completions = Cell::new(0);
        let exit = watchdog::run_bounded(
            || Ok(Guard(&drops)),
            || std::panic::resume_unwind(Box::new(())),
            |_| {
                completions.set(completions.get() + 1);
                Ok(())
            },
        );
        assert_eq!(exit, UNAVAILABLE_EXIT);
        assert_eq!(drops.get(), 1);
        assert_eq!(completions.get(), 0);
    }

    #[test]
    fn watchdog_send_failure_join_failure_and_join_panic_never_return_success() {
        for failure in 0..3 {
            let now = std::time::Instant::now();
            let sends = Cell::new(0);
            let joins = Cell::new(0);
            let exit = watchdog::run_bounded(
                || Ok(()),
                || 0,
                |()| {
                    watchdog::complete_with(
                        now + std::time::Duration::from_secs(1),
                        || now,
                        || {
                            sends.set(sends.get() + 1);
                            if failure == 0 { Err(()) } else { Ok(()) }
                        },
                        || {
                            joins.set(joins.get() + 1);
                            if failure == 2 {
                                std::panic::resume_unwind(Box::new(()));
                            }
                            Err(())
                        },
                    )
                },
            );
            assert_eq!(exit, UNAVAILABLE_EXIT);
            assert_eq!(sends.get(), 1);
            assert_eq!(joins.get(), usize::from(failure != 0));
        }
    }

    #[test]
    fn watchdog_post_join_check_rejects_late_or_equal_completion() {
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_millis(20);
        for observed in [
            started,
            deadline,
            deadline + std::time::Duration::from_millis(1),
        ] {
            let reads = Cell::new(0);
            let joins = Cell::new(0);
            let result = watchdog::complete_with(
                deadline,
                || {
                    let index = reads.get();
                    reads.set(index + 1);
                    if index == 0 { started } else { observed }
                },
                || Ok(()),
                || {
                    joins.set(joins.get() + 1);
                    Ok(())
                },
            );
            assert_eq!(joins.get(), 1);
            assert_eq!(result.is_ok(), observed < deadline);
            assert_eq!(reads.get(), 2);
        }
    }

    #[test]
    fn watchdog_subprocess_entry() {
        let Ok(mode) = std::env::var("YOUR_WALLET_PROBE_WATCHDOG_TEST_CHILD") else {
            return;
        };
        std::panic::set_hook(Box::new(|_| {}));
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(100);
        let exit = watchdog::run_bounded(
            || watchdog::ProcessWatchdog::arm(deadline),
            || match mode.as_str() {
                "rpc" | "worker-panic" => loop {
                    std::thread::park();
                },
                "stdout" => {
                    struct BlockedStdout<'a>(std::io::StdoutLock<'a>);
                    impl std::io::Write for BlockedStdout<'_> {
                        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                            loop {
                                self.0.write_all(&[b'.'; 8_192])?;
                            }
                        }
                        fn flush(&mut self) -> std::io::Result<()> {
                            self.0.flush()
                        }
                    }
                    write_outcome(
                        BlockedStdout(std::io::stdout().lock()),
                        ProbeOutcome::Completed,
                    )
                }
                "flush" => {
                    struct BlockedFlush;
                    impl std::io::Write for BlockedFlush {
                        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                            Ok(bytes.len())
                        }
                        fn flush(&mut self) -> std::io::Result<()> {
                            loop {
                                std::thread::park();
                            }
                        }
                    }
                    write_outcome(BlockedFlush, ProbeOutcome::Completed)
                }
                "panic" => std::panic::resume_unwind(Box::new(())),
                _ => UNAVAILABLE_EXIT,
            },
            watchdog::ProcessWatchdog::complete,
        );
        std::process::exit(exit);
    }

    #[test]
    fn watchdog_process_bound_covers_blocked_rpc_stdout_flush_and_panic() -> Result<(), &'static str>
    {
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};
        struct OwnedChild(std::process::Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if !matches!(self.0.try_wait(), Ok(Some(_))) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
        }
        let executable = std::env::current_exe().map_err(|_| "test executable unavailable")?;
        for mode in ["rpc", "stdout", "flush", "panic", "worker-panic"] {
            let mut command = Command::new(&executable);
            command
                .args(["--exact", "tests::watchdog_subprocess_entry", "--nocapture"])
                .env("YOUR_WALLET_PROBE_WATCHDOG_TEST_CHILD", mode)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt as _;
                command.creation_flags(0x0800_0000);
            }
            let mut child = OwnedChild(
                command
                    .spawn()
                    .map_err(|_| "watchdog test child unavailable")?,
            );
            let deadline = Instant::now() + Duration::from_secs(3);
            let status = loop {
                if let Some(status) = child
                    .0
                    .try_wait()
                    .map_err(|_| "watchdog test child observation failed")?
                {
                    break status;
                }
                if Instant::now() >= deadline {
                    return Err("watchdog test child exceeded its bound");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(status.code(), Some(UNAVAILABLE_EXIT));
        }
        Ok(())
    }
}
