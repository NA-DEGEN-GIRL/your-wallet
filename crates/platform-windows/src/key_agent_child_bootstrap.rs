//! Earliest child-side standard-handle sealing for the Key Agent process.
//!
//! The parent must temporarily mark the three explicit standard handles as
//! inheritable so Windows can place them in the new process. The child clears
//! those bits before any descendant creation can occur. This module borrows
//! the process standard handles; it never adopts or closes them.

#![allow(unsafe_code)]

use core::fmt;
use core::marker::PhantomData;
use std::rc::Rc;

use thiserror::Error;
use windows::Win32::Foundation::{
    CompareObjectHandles, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS,
    INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows::Win32::Storage::FileSystem::{FILE_TYPE, FILE_TYPE_CHAR, FILE_TYPE_PIPE, GetFileType};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

/// Stable failure category for the Key Agent's earliest child-side boundary.
///
/// The error intentionally retains no raw handle or operating-system details.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("Key Agent child standard-handle boundary rejected")]
pub struct KeyAgentChildBootstrapError;

/// Proof that the exact inherited Key Agent stdio handles are non-inheritable.
///
/// The value exposes no handle access and is neither cloneable nor transferable
/// to another thread. Future Key Agent runtime entry must consume this proof
/// instead of independently trusting ambient standard handles.
#[must_use = "the Key Agent must retain its sealed stdio proof through startup"]
pub struct SealedKeyAgentStdio {
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl fmt::Debug for SealedKeyAgentStdio {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealedKeyAgentStdio([BORROWED NON-INHERITABLE STDIO])")
    }
}

/// Validates and removes inheritance from the Key Agent's three stdio handles.
///
/// This must be the Key Agent binary's first Windows operation. All three
/// handles are validated before any mutation: stdin and stdout must be distinct
/// pipes, stderr must be a third distinct character device, and every handle
/// must initially have exactly `HANDLE_FLAG_INHERIT`. The function then clears
/// that flag from all three and verifies that every resulting flag word is zero.
///
/// If one clear operation fails, the function still attempts to clear the
/// remaining handles and never restores inheritance. The caller must terminate
/// the process immediately on any error, before starting threads or descendants.
///
/// # Errors
///
/// Returns [`KeyAgentChildBootstrapError`] when a standard handle is absent,
/// aliased, of the wrong kernel type, has unexpected flags, cannot be changed,
/// or does not read back as exactly non-inheritable.
pub fn seal_inherited_key_agent_stdio() -> Result<SealedKeyAgentStdio, KeyAgentChildBootstrapError>
{
    // SAFETY: GetStdHandle returns one borrowed process-table value. This code
    // neither adopts nor closes it, and no Key Agent application code has run.
    let stdin =
        unsafe { GetStdHandle(STD_INPUT_HANDLE) }.map_err(|_| KeyAgentChildBootstrapError)?;
    // SAFETY: same borrowed-handle contract as stdin.
    let stdout =
        unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }.map_err(|_| KeyAgentChildBootstrapError)?;
    // SAFETY: same borrowed-handle contract as stdin.
    let stderr =
        unsafe { GetStdHandle(STD_ERROR_HANDLE) }.map_err(|_| KeyAgentChildBootstrapError)?;

    seal_exact_standard_handle_set([stdin, stdout, stderr])?;
    Ok(SealedKeyAgentStdio {
        _not_send_or_sync: PhantomData,
    })
}

fn seal_exact_standard_handle_set(handles: [HANDLE; 3]) -> Result<(), KeyAgentChildBootstrapError> {
    let [stdin, stdout, stderr] = handles;
    if handles.iter().copied().any(invalid)
        || same_object(stdin, stdout)
        || same_object(stdin, stderr)
        || same_object(stdout, stderr)
        || file_type(stdin) != FILE_TYPE_PIPE
        || file_type(stdout) != FILE_TYPE_PIPE
        || file_type(stderr) != FILE_TYPE_CHAR
        || handles
            .iter()
            .any(|handle| handle_flags(*handle) != Ok(HANDLE_FLAG_INHERIT.0))
    {
        return Err(KeyAgentChildBootstrapError);
    }

    let mut clear_failed = false;
    for handle in handles {
        // SAFETY: every value was just proven to be one live borrowed standard
        // handle. Only its process-local inherit flag is cleared; ownership and
        // access rights are unchanged.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }.is_err()
        {
            clear_failed = true;
        }
    }

    let exact_zero_flags = handles.iter().all(|handle| handle_flags(*handle) == Ok(0));
    if clear_failed || !exact_zero_flags {
        return Err(KeyAgentChildBootstrapError);
    }
    Ok(())
}

fn invalid(handle: HANDLE) -> bool {
    handle.is_invalid() || handle == INVALID_HANDLE_VALUE
}

fn same_object(first: HANDLE, second: HANDLE) -> bool {
    // SAFETY: callers reject invalid values before relying on this result, and
    // all candidates are borrowed from the current process handle table.
    unsafe { CompareObjectHandles(first, second) }.as_bool()
}

fn file_type(handle: HANDLE) -> FILE_TYPE {
    // SAFETY: the caller retains the live process standard handle.
    unsafe { GetFileType(handle) }
}

fn handle_flags(handle: HANDLE) -> Result<u32, KeyAgentChildBootstrapError> {
    let mut flags = u32::MAX;
    // SAFETY: the output points to one initialized flag word and the caller
    // retains the borrowed handle for this scalar query.
    unsafe { GetHandleInformation(handle, &raw mut flags) }
        .map_err(|_| KeyAgentChildBootstrapError)?;
    Ok(flags)
}

#[cfg(test)]
mod tests {
    use core::ffi::c_void;
    use core::mem::size_of;
    use std::ffi::{OsStr, OsString};
    use std::io::{Read, Write};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CreateEventW, CreateProcessW, GetCurrentProcess, PROCESS_INFORMATION,
        STARTUPINFOW, TerminateProcess, WaitForSingleObject,
    };
    use windows::core::{PCWSTR, PWSTR};

    use super::{
        KeyAgentChildBootstrapError, handle_flags, invalid, same_object,
        seal_exact_standard_handle_set, seal_inherited_key_agent_stdio,
    };
    use crate::inheritable_handle_launch::acquire_inheritable_handle_launch;
    use crate::pipe::{PipeError, PrivateKeyAgentPipes};

    const CHILD_FIXTURE: &str = "key_agent_child_bootstrap::tests::inherited_stdio_child_fixture";
    const GRANDCHILD_FIXTURE: &str =
        "key_agent_child_bootstrap::tests::deinheritance_grandchild_fixture";
    const CHILD_FIXTURE_ENV: &str = "YOUR_WALLET_KEY_AGENT_STDIO_CHILD_FIXTURE";
    const CHALLENGE: &[u8] = b"key-agent-stdio-challenge";
    const ACKNOWLEDGEMENT: &[u8] = b"key-agent-stdio-sealed";

    struct ReapedChild(Child);

    impl ReapedChild {
        fn wait_before(&mut self, deadline: Instant) -> std::io::Result<ExitStatus> {
            loop {
                match self.0.try_wait()? {
                    Some(status) => return Ok(status),
                    None if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    None => {
                        self.terminate_before(Instant::now() + Duration::from_secs(5))?;
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Key Agent stdio subprocess exceeded its deadline",
                        ));
                    }
                }
            }
        }

        fn terminate_before(&mut self, deadline: Instant) -> std::io::Result<()> {
            if self.0.try_wait()?.is_some() {
                return Ok(());
            }
            let _ = self.0.kill();
            loop {
                match self.0.try_wait()? {
                    Some(_) => return Ok(()),
                    None if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    None => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Key Agent stdio subprocess cleanup exceeded its deadline",
                        ));
                    }
                }
            }
        }
    }

    impl Drop for ReapedChild {
        fn drop(&mut self) {
            let _ = self.terminate_before(Instant::now() + Duration::from_secs(5));
        }
    }

    struct BroadInheritanceGrandchild {
        process: OwnedHandle,
    }

    impl BroadInheritanceGrandchild {
        fn spawn(executable: &std::path::Path) -> Result<Self, KeyAgentChildBootstrapError> {
            let mut application = executable.as_os_str().encode_wide().collect::<Vec<_>>();
            application.push(0);
            let mut command = OsString::from("\"");
            command.push(executable.as_os_str());
            command.push("\" ");
            command.push(GRANDCHILD_FIXTURE);
            command.push(" --exact --ignored --test-threads=1");
            let mut command = command.encode_wide().collect::<Vec<_>>();
            command.push(0);
            let startup = STARTUPINFOW {
                cb: u32::try_from(size_of::<STARTUPINFOW>())
                    .map_err(|_| KeyAgentChildBootstrapError)?,
                ..Default::default()
            };
            let mut information = PROCESS_INFORMATION::default();
            // SAFETY: this test-only positive control supplies live terminated
            // UTF-16 buffers and initialized output structures. TRUE inheritance
            // intentionally has no HANDLE_LIST so the sentinel must cross.
            unsafe {
                CreateProcessW(
                    PCWSTR(application.as_ptr()),
                    Some(PWSTR(command.as_mut_ptr())),
                    None,
                    None,
                    true,
                    CREATE_NO_WINDOW,
                    None,
                    PCWSTR::null(),
                    &raw const startup,
                    &raw mut information,
                )
            }
            .map_err(|_| KeyAgentChildBootstrapError)?;
            if invalid(information.hProcess) || invalid(information.hThread) {
                if !invalid(information.hProcess) {
                    // SAFETY: the process handle is live even though the result
                    // was incomplete, and cleanup remains bounded below.
                    unsafe {
                        let _ = TerminateProcess(information.hProcess, 1);
                        let _ = WaitForSingleObject(information.hProcess, 5_000);
                    }
                    // SAFETY: CreateProcessW transferred this valid fresh process
                    // handle even though the companion handle was malformed.
                    drop(unsafe {
                        OwnedHandle::from_raw_handle(information.hProcess.0.cast::<c_void>())
                    });
                }
                if !invalid(information.hThread) {
                    // SAFETY: CreateProcessW transferred this valid fresh thread
                    // handle even though the companion handle was malformed.
                    drop(unsafe {
                        OwnedHandle::from_raw_handle(information.hThread.0.cast::<c_void>())
                    });
                }
                return Err(KeyAgentChildBootstrapError);
            }
            // SAFETY: CreateProcessW returned two fresh owned handles.
            let process =
                unsafe { OwnedHandle::from_raw_handle(information.hProcess.0.cast::<c_void>()) };
            // SAFETY: same fresh ownership transfer for the primary thread.
            let thread =
                unsafe { OwnedHandle::from_raw_handle(information.hThread.0.cast::<c_void>()) };
            drop(thread);
            Ok(Self { process })
        }

        fn is_alive(&self) -> bool {
            // SAFETY: this zero-timeout query borrows the retained process.
            (unsafe { WaitForSingleObject(HANDLE(self.process.as_raw_handle()), 0) })
                == WAIT_TIMEOUT
        }

        fn names_same_object(
            &self,
            candidate: HANDLE,
            expected: HANDLE,
        ) -> Result<bool, KeyAgentChildBootstrapError> {
            let mut duplicate = HANDLE::default();
            // SAFETY: the retained process handle has duplication rights.
            // Windows inherited handles keep the parent's numeric value, so an
            // exact-object comparison distinguishes inheritance from reuse.
            let result = unsafe {
                DuplicateHandle(
                    HANDLE(self.process.as_raw_handle()),
                    candidate,
                    GetCurrentProcess(),
                    &raw mut duplicate,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
            };
            if result.is_err() {
                return Ok(false);
            }
            if duplicate.is_invalid() {
                return Err(KeyAgentChildBootstrapError);
            }
            // SAFETY: successful DuplicateHandle returned one fresh owned handle.
            let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate.0.cast::<c_void>()) };
            Ok(same_object(HANDLE(duplicate.as_raw_handle()), expected))
        }

        fn terminate_and_reap(&self) -> Result<(), KeyAgentChildBootstrapError> {
            let process = HANDLE(self.process.as_raw_handle());
            // SAFETY: the retained process object is live for both bounded calls.
            let state = unsafe { WaitForSingleObject(process, 0) };
            if state == WAIT_OBJECT_0 {
                return Ok(());
            }
            if state != WAIT_TIMEOUT {
                return Err(KeyAgentChildBootstrapError);
            }
            // SAFETY: this exact test child has no externally visible work and
            // is synchronously reaped under a fixed five-second bound.
            unsafe {
                TerminateProcess(process, 1).map_err(|_| KeyAgentChildBootstrapError)?;
                if WaitForSingleObject(process, 5_000) != WAIT_OBJECT_0 {
                    return Err(KeyAgentChildBootstrapError);
                }
            }
            Ok(())
        }
    }

    impl Drop for BroadInheritanceGrandchild {
        fn drop(&mut self) {
            let _ = self.terminate_and_reap();
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn raw(handle: std::os::windows::io::BorrowedHandle<'_>) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    #[test]
    fn exact_set_seals_all_three_without_closing_them() -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateKeyAgentPipes::create()?;
        let flight = acquire_inheritable_handle_launch(deadline())
            .map_err(|_| PipeError::OperatingSystem)?;
        let prepared = pipes.prepare_child_inheritance(&flight)?;
        let handles = [
            raw(prepared.stdin()),
            raw(prepared.stdout()),
            raw(prepared.stderr()),
        ];
        for handle in handles {
            assert_eq!(handle_flags(handle)?, HANDLE_FLAG_INHERIT.0);
        }

        seal_exact_standard_handle_set(handles)?;
        for handle in handles {
            assert_eq!(handle_flags(handle)?, 0);
        }
        assert_eq!(
            seal_exact_standard_handle_set(handles),
            Err(KeyAgentChildBootstrapError)
        );

        drop(prepared);
        drop(flight);
        Ok(())
    }

    #[test]
    fn invalid_or_aliased_set_is_rejected_before_any_mutation()
    -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateKeyAgentPipes::create()?;
        let flight = acquire_inheritable_handle_launch(deadline())
            .map_err(|_| PipeError::OperatingSystem)?;
        let prepared = pipes.prepare_child_inheritance(&flight)?;
        let handles = [
            raw(prepared.stdin()),
            raw(prepared.stdout()),
            raw(prepared.stderr()),
        ];

        assert_eq!(
            seal_exact_standard_handle_set([handles[0], handles[0], handles[2]]),
            Err(KeyAgentChildBootstrapError)
        );
        assert_eq!(
            seal_exact_standard_handle_set([HANDLE::default(), handles[1], handles[2]]),
            Err(KeyAgentChildBootstrapError)
        );
        for handle in handles {
            assert_eq!(handle_flags(handle)?, HANDLE_FLAG_INHERIT.0);
        }

        drop(prepared);
        drop(flight);
        Ok(())
    }

    #[test]
    fn inherited_stdio_is_sealed_in_an_isolated_child_before_descendant_creation()
    -> Result<(), Box<dyn std::error::Error>> {
        let executable = std::env::current_exe()?;
        let flight = acquire_inheritable_handle_launch(deadline())
            .map_err(|_| KeyAgentChildBootstrapError)?;
        let mut command = Command::new(executable);
        command
            .arg(CHILD_FIXTURE)
            .arg("--exact")
            .arg("--ignored")
            .arg("--test-threads=1")
            .env(CHILD_FIXTURE_ENV, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let child = command.spawn()?;
        drop(command);
        drop(flight);
        let mut child = ReapedChild(child);

        let mut child_input = child.0.stdin.take().ok_or_else(|| {
            std::io::Error::other("isolated Key Agent child stdin was not retained")
        })?;
        child_input.write_all(CHALLENGE)?;
        drop(child_input);
        let mut child_output = child.0.stdout.take().ok_or_else(|| {
            std::io::Error::other("isolated Key Agent child stdout was not retained")
        })?;
        let status = child.wait_before(Instant::now() + Duration::from_secs(25))?;
        let mut output = Vec::new();
        child_output.read_to_end(&mut output)?;
        if !status.success() {
            return Err(
                std::io::Error::other("isolated Key Agent stdio sealing fixture failed").into(),
            );
        }
        assert!(
            output
                .windows(ACKNOWLEDGEMENT.len())
                .any(|window| window == ACKNOWLEDGEMENT)
        );
        Ok(())
    }

    #[test]
    #[ignore = "launched only by the isolated Key Agent stdio driver"]
    fn inherited_stdio_child_fixture() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(CHILD_FIXTURE_ENV).as_deref() != Some(OsStr::new("1")) {
            return Ok(());
        }
        let original_handles = current_standard_handles()?;
        let sealed = seal_inherited_key_agent_stdio()?;
        for handle in original_handles {
            assert_eq!(handle_flags(handle)?, 0);
        }

        let mut challenge = vec![0_u8; CHALLENGE.len()];
        std::io::stdin().read_exact(&mut challenge)?;
        assert_eq!(challenge, CHALLENGE);

        let executable = std::env::current_exe()?;
        let flight = acquire_inheritable_handle_launch(deadline())
            .map_err(|_| KeyAgentChildBootstrapError)?;
        // SAFETY: this unnamed event is initially non-inheritable and becomes
        // the positive control only while the process-wide flight is held.
        let sentinel = unsafe { CreateEventW(None, true, false, None) }
            .map_err(|_| KeyAgentChildBootstrapError)?;
        if sentinel.is_invalid() {
            return Err(KeyAgentChildBootstrapError.into());
        }
        // SAFETY: CreateEventW returned one fresh owned event handle.
        let sentinel = unsafe { OwnedHandle::from_raw_handle(sentinel.0) };
        let sentinel_handle = HANDLE(sentinel.as_raw_handle());
        // SAFETY: the retained event is live and only its inherit bit changes.
        unsafe {
            super::SetHandleInformation(sentinel_handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
        }
        .map_err(|_| KeyAgentChildBootstrapError)?;
        assert_eq!(handle_flags(sentinel_handle)?, HANDLE_FLAG_INHERIT.0);

        let grandchild = BroadInheritanceGrandchild::spawn(&executable)?;
        // SAFETY: immediately remove the temporary positive-control bit before
        // releasing the same process-wide inheritable-launch flight.
        unsafe {
            super::SetHandleInformation(sentinel_handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))
        }
        .map_err(|_| KeyAgentChildBootstrapError)?;
        assert_eq!(handle_flags(sentinel_handle)?, 0);
        drop(flight);

        assert!(grandchild.is_alive());
        assert!(grandchild.names_same_object(sentinel_handle, sentinel_handle)?);
        for original in original_handles {
            assert!(!grandchild.names_same_object(original, original)?);
        }
        grandchild.terminate_and_reap()?;

        std::io::stdout().write_all(ACKNOWLEDGEMENT)?;
        std::io::stdout().flush()?;
        drop(sealed);
        Ok(())
    }

    #[test]
    #[ignore = "launched only as the Key Agent stdio grandchild probe"]
    fn deinheritance_grandchild_fixture() {
        std::thread::sleep(Duration::from_secs(15));
    }

    fn current_standard_handles() -> Result<[HANDLE; 3], KeyAgentChildBootstrapError> {
        // SAFETY: all returned values are borrowed for scalar queries only.
        let stdin = unsafe { super::GetStdHandle(super::STD_INPUT_HANDLE) }
            .map_err(|_| KeyAgentChildBootstrapError)?;
        // SAFETY: same borrowed-handle contract as stdin.
        let stdout = unsafe { super::GetStdHandle(super::STD_OUTPUT_HANDLE) }
            .map_err(|_| KeyAgentChildBootstrapError)?;
        // SAFETY: same borrowed-handle contract as stdin.
        let stderr = unsafe { super::GetStdHandle(super::STD_ERROR_HANDLE) }
            .map_err(|_| KeyAgentChildBootstrapError)?;
        Ok([stdin, stdout, stderr])
    }
}
