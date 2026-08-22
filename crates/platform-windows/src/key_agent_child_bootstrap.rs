//! Earliest child-side storage startup for the Key Agent process.
//!
//! The parent must temporarily mark the three explicit standard handles as
//! inheritable so Windows can place them in the new process. The child clears
//! those bits before any descendant creation can occur. It then accepts only
//! the fixed storage-startup request, opens and retains the bound root, writes
//! one response, and waits for the parent disconnect. This module borrows the
//! process standard handles; it never adopts or closes them.

#![allow(unsafe_code)]

use core::fmt;
use core::marker::PhantomData;
use std::os::windows::io::{BorrowedHandle, RawHandle};
use std::rc::Rc;

use thiserror::Error;
use windows::Win32::Foundation::{
    CompareObjectHandles, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, FILETIME, GetHandleInformation,
    HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows::Win32::Storage::FileSystem::{
    FILE_TYPE, FILE_TYPE_CHAR, FILE_TYPE_PIPE, GetFileType, ReadFile, WriteFile,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetProcessTimes};
use zeroize::Zeroizing;

use crate::key_agent_startup::{
    KEY_AGENT_STARTUP_REQUEST_BYTES, KEY_AGENT_STARTUP_RESPONSE_BYTES, KeyAgentStartupRequest,
    KeyAgentStartupResponse,
};
#[cfg(test)]
use crate::key_agent_storage::open_test_key_agent_storage_root_for_child;
use crate::key_agent_storage::{
    FixedKeyAgentGenerationStoreBindings, open_fixed_key_agent_storage_root_for_child,
};
use crate::pipe::reject_buffered_key_agent_startup_bytes;

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
struct SealedKeyAgentStdio {
    stdin: HANDLE,
    stdout: HANDLE,
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
fn seal_inherited_key_agent_stdio() -> Result<SealedKeyAgentStdio, KeyAgentChildBootstrapError> {
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
        stdin,
        stdout,
        _not_send_or_sync: PhantomData,
    })
}

/// Serves the exact inherited Key Agent storage-startup handshake.
///
/// Standard handles are sealed before any other operation. The function then
/// reads one fixed request, binds it to this process and the freshly opened
/// storage root, writes one fixed response, and retains both child proofs until
/// the parent disconnects its request pipe. Any post-startup input byte fails
/// closed without another response.
///
/// # Errors
///
/// Returns [`KeyAgentChildBootstrapError`] when stdio sealing, exact pipe I/O,
/// request decoding, process identity, storage opening or revalidation, request
/// binding, response construction, or the final disconnect contract fails.
pub fn serve_inherited_key_agent_storage_startup() -> Result<(), KeyAgentChildBootstrapError> {
    let sealed_stdio = seal_inherited_key_agent_stdio()?;

    let mut request_frame = Zeroizing::new([0_u8; KEY_AGENT_STARTUP_REQUEST_BYTES]);
    read_exact_synchronous(sealed_stdio.stdin, &mut request_frame)?;
    // SAFETY: the sealed proof retains this borrowed process-table handle for
    // the complete call and never adopts or closes it.
    let stdin = unsafe { BorrowedHandle::borrow_raw(sealed_stdio.stdin.0 as RawHandle) };
    reject_buffered_key_agent_startup_bytes(stdin).map_err(|_| KeyAgentChildBootstrapError)?;
    let request = KeyAgentStartupRequest::decode(request_frame.as_slice())
        .map_err(|_| KeyAgentChildBootstrapError)?;

    let actual_process_id = current_process_id()?;
    let actual_creation_time = current_process_creation_time()?;
    #[cfg(test)]
    let child_root = if request.is_test_mode() {
        open_test_key_agent_storage_root_for_child(request.storage_leaf())
    } else {
        open_fixed_key_agent_storage_root_for_child()
    }
    .map_err(|_| KeyAgentChildBootstrapError)?;
    #[cfg(not(test))]
    let child_root =
        open_fixed_key_agent_storage_root_for_child().map_err(|_| KeyAgentChildBootstrapError)?;
    let actual_storage_identity = child_root.identity();

    if request.expected_process_id() != actual_process_id
        || request.expected_creation_time() != actual_creation_time
        || request.storage_root_identity() != actual_storage_identity
    {
        return Err(KeyAgentChildBootstrapError);
    }
    child_root
        .revalidate()
        .map_err(|_| KeyAgentChildBootstrapError)?;
    let generation_store_bindings = child_root
        .into_fixed_generation_store_bindings()
        .map_err(|_| KeyAgentChildBootstrapError)?;
    #[cfg(test)]
    if request.is_test_mode() {
        generation_store_bindings
            .verify_forbidden_root_rights_for_test()
            .map_err(|_| KeyAgentChildBootstrapError)?;
        crate::storage::exercise_fixed_key_agent_generation_stores_for_test(
            &generation_store_bindings,
        )
        .map_err(|_| KeyAgentChildBootstrapError)?;
        generation_store_bindings
            .revalidate()
            .map_err(|_| KeyAgentChildBootstrapError)?;
        if generation_store_bindings.identity() != actual_storage_identity {
            return Err(KeyAgentChildBootstrapError);
        }
    }

    let response = KeyAgentStartupResponse::from_validated_request(
        &request,
        actual_process_id,
        actual_creation_time,
        actual_storage_identity,
    )
    .map_err(|_| KeyAgentChildBootstrapError)?;
    let response_frame = response.encode().map_err(|_| KeyAgentChildBootstrapError)?;
    write_exact_synchronous(sealed_stdio.stdout, response_frame.as_bytes())?;

    wait_for_parent_disconnect(&sealed_stdio, &generation_store_bindings)
}

fn current_process_id() -> Result<u32, KeyAgentChildBootstrapError> {
    // SAFETY: this scalar query has no preconditions.
    let process_id = unsafe { GetCurrentProcessId() };
    (process_id != 0)
        .then_some(process_id)
        .ok_or(KeyAgentChildBootstrapError)
}

fn current_process_creation_time() -> Result<u64, KeyAgentChildBootstrapError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: GetCurrentProcess returns this process's always-valid pseudo
    // handle, and all four output pointers name initialized FILETIME storage.
    unsafe {
        GetProcessTimes(
            GetCurrentProcess(),
            &raw mut creation,
            &raw mut exit,
            &raw mut kernel,
            &raw mut user,
        )
    }
    .map_err(|_| KeyAgentChildBootstrapError)?;
    let value = (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime);
    (value != 0)
        .then_some(value)
        .ok_or(KeyAgentChildBootstrapError)
}

fn read_exact_synchronous(
    handle: HANDLE,
    bytes: &mut [u8; KEY_AGENT_STARTUP_REQUEST_BYTES],
) -> Result<(), KeyAgentChildBootstrapError> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let remaining = bytes.get_mut(offset..).ok_or(KeyAgentChildBootstrapError)?;
        let mut transferred = 0_u32;
        // SAFETY: `handle` is the retained borrowed synchronous stdin pipe. The
        // selected output slice and count remain live for the complete call,
        // and no OVERLAPPED is supplied.
        unsafe { ReadFile(handle, Some(remaining), Some(&raw mut transferred), None) }
            .map_err(|_| KeyAgentChildBootstrapError)?;
        let transferred = usize::try_from(transferred).map_err(|_| KeyAgentChildBootstrapError)?;
        let available = bytes
            .len()
            .checked_sub(offset)
            .ok_or(KeyAgentChildBootstrapError)?;
        if transferred == 0 || transferred > available {
            return Err(KeyAgentChildBootstrapError);
        }
        offset = offset
            .checked_add(transferred)
            .ok_or(KeyAgentChildBootstrapError)?;
    }
    Ok(())
}

fn write_exact_synchronous(
    handle: HANDLE,
    bytes: &[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES],
) -> Result<(), KeyAgentChildBootstrapError> {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let remaining = bytes.get(offset..).ok_or(KeyAgentChildBootstrapError)?;
        let mut transferred = 0_u32;
        // SAFETY: `handle` is the retained borrowed synchronous stdout pipe.
        // The selected input slice and count remain live for the complete call,
        // and no OVERLAPPED is supplied.
        unsafe { WriteFile(handle, Some(remaining), Some(&raw mut transferred), None) }
            .map_err(|_| KeyAgentChildBootstrapError)?;
        let transferred = usize::try_from(transferred).map_err(|_| KeyAgentChildBootstrapError)?;
        let available = bytes
            .len()
            .checked_sub(offset)
            .ok_or(KeyAgentChildBootstrapError)?;
        if transferred == 0 || transferred > available {
            return Err(KeyAgentChildBootstrapError);
        }
        offset = offset
            .checked_add(transferred)
            .ok_or(KeyAgentChildBootstrapError)?;
    }
    Ok(())
}

fn wait_for_parent_disconnect(
    sealed_stdio: &SealedKeyAgentStdio,
    _generation_store_bindings: &FixedKeyAgentGenerationStoreBindings,
) -> Result<(), KeyAgentChildBootstrapError> {
    let mut byte = [0_u8; 1];
    let mut transferred = 0_u32;
    // SAFETY: the sealed proof retains the borrowed synchronous stdin pipe;
    // the one-byte destination and count remain live for the complete call,
    // and no OVERLAPPED is supplied.
    let result = unsafe {
        ReadFile(
            sealed_stdio.stdin,
            Some(&mut byte),
            Some(&raw mut transferred),
            None,
        )
    };
    reject_nonzero_post_startup_bytes(transferred)?;
    match result {
        Ok(()) => Ok(()),
        Err(error)
            if error.code() == ERROR_BROKEN_PIPE.to_hresult()
                || error.code() == ERROR_HANDLE_EOF.to_hresult() =>
        {
            Ok(())
        }
        Err(_) => Err(KeyAgentChildBootstrapError),
    }
}

fn reject_nonzero_post_startup_bytes(transferred: u32) -> Result<(), KeyAgentChildBootstrapError> {
    (transferred == 0)
        .then_some(())
        .ok_or(KeyAgentChildBootstrapError)
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
        KeyAgentChildBootstrapError, current_process_creation_time, handle_flags, invalid,
        reject_nonzero_post_startup_bytes, same_object, seal_exact_standard_handle_set,
        seal_inherited_key_agent_stdio, serve_inherited_key_agent_storage_startup,
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
    fn current_process_creation_filetime_is_nonzero() -> Result<(), KeyAgentChildBootstrapError> {
        assert_ne!(current_process_creation_time()?, 0);
        Ok(())
    }

    #[test]
    fn post_startup_input_contract_accepts_only_zero_bytes() {
        assert_eq!(reject_nonzero_post_startup_bytes(0), Ok(()));
        for transferred in [1, u32::MAX] {
            assert_eq!(
                reject_nonzero_post_startup_bytes(transferred),
                Err(KeyAgentChildBootstrapError)
            );
        }
    }

    #[test]
    #[ignore = "launched only by the isolated Key Agent storage-startup driver"]
    fn storage_startup_child_fixture() -> Result<(), KeyAgentChildBootstrapError> {
        serve_inherited_key_agent_storage_startup()
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
