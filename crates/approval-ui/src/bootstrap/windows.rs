//! Documented Win32 checks for the Approval runtime bootstrap.

#![allow(unsafe_code)]

use core::fmt;
use core::marker::PhantomData;
use std::rc::Rc;

use windows::Win32::Foundation::{
    CompareObjectHandles, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS,
    INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};

#[must_use = "binary mode and request processing require the sealed Approval stdio proof"]
pub(crate) struct SealedApprovalStdio {
    input: HANDLE,
    output: HANDLE,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl fmt::Debug for SealedApprovalStdio {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SealedApprovalStdio([REDACTED])")
    }
}

/// Seals the exact two unique inherited pipe objects before any other Windows,
/// CRT, protocol, or UI application operation. Stderr must be the same numeric
/// handle-table entry as stdout, matching the private launcher contract.
pub(crate) fn seal_inherited_approval_stdio()
-> Result<SealedApprovalStdio, approval_ui::ApprovalError> {
    // SAFETY: these APIs return borrowed process standard handles. The process
    // retains ownership and the values are used only for this bootstrap proof.
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) }.map_err(native_failure)?;
    // SAFETY: same borrowed standard-handle contract as input.
    let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }.map_err(native_failure)?;
    // SAFETY: same borrowed standard-handle contract as input.
    let error = unsafe { GetStdHandle(STD_ERROR_HANDLE) }.map_err(native_failure)?;

    seal_exact_approval_stdio([input, output, error])?;
    Ok(SealedApprovalStdio {
        input,
        output,
        _not_send_or_sync: PhantomData,
    })
}

fn seal_exact_approval_stdio(handles: [HANDLE; 3]) -> Result<(), approval_ui::ApprovalError> {
    let [input, output, error] = handles;
    let unique = [input, output];
    if handles.iter().copied().any(invalid_handle)
        || input == output
        || output != error
        || same_object(input, output)
        || !same_object(output, error)
        // SAFETY: all candidates were proven live above and remain borrowed.
        || unsafe { GetFileType(input) } != FILE_TYPE_PIPE
        // SAFETY: same live borrowed-handle contract as input.
        || unsafe { GetFileType(output) } != FILE_TYPE_PIPE
        || unique.iter().any(|handle| {
            !matches!(handle_flags(*handle), Ok(flags) if flags == HANDLE_FLAG_INHERIT.0)
        })
    {
        return Err(native_failure(()));
    }

    // Clearing is intentionally non-atomic and has no rollback: attempt both
    // unique objects even when one call fails, then require exact zero flags on
    // both before issuing a proof.
    let mut clear_failed = false;
    for handle in unique {
        // SAFETY: both values are live borrowed standard handles. This changes
        // only the process-local inherit flag and never transfers ownership.
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }.is_err()
        {
            clear_failed = true;
        }
    }
    let exact_zero_flags = unique
        .iter()
        .all(|handle| matches!(handle_flags(*handle), Ok(0)));
    if clear_failed || !exact_zero_flags {
        return Err(native_failure(()));
    }
    Ok(())
}

pub(crate) fn set_binary_stdio(
    sealed: &SealedApprovalStdio,
) -> Result<(), approval_ui::ApprovalError> {
    const O_BINARY: i32 = 0x8000;

    unsafe extern "C" {
        fn _setmode(file_descriptor: i32, mode: i32) -> i32;
    }

    let input_still_sealed = matches!(handle_flags(sealed.input), Ok(0));
    let output_still_sealed = matches!(handle_flags(sealed.output), Ok(0));
    if !input_still_sealed || !output_still_sealed {
        return Err(native_failure(()));
    }
    // SAFETY: the stdio kernel objects were sealed above. File descriptors 0
    // and 1 remain live; `_setmode` changes only this process's CRT translation.
    let (input_mode, output_mode) = unsafe { (_setmode(0, O_BINARY), _setmode(1, O_BINARY)) };
    if input_mode == -1 || output_mode == -1 {
        return Err(std::io::Error::other("binary standard I/O unavailable").into());
    }
    Ok(())
}

fn invalid_handle(handle: HANDLE) -> bool {
    handle.is_invalid() || handle == INVALID_HANDLE_VALUE
}

fn same_object(first: HANDLE, second: HANDLE) -> bool {
    // SAFETY: callers reject invalid values before relying on this result and
    // all candidates remain live in the current process handle table.
    unsafe { CompareObjectHandles(first, second) }.as_bool()
}

fn handle_flags(handle: HANDLE) -> Result<u32, approval_ui::ApprovalError> {
    let mut flags = u32::MAX;
    // SAFETY: output points to one initialized flag word and the caller retains
    // the live borrowed or owned handle for this scalar query.
    unsafe { GetHandleInformation(handle, &raw mut flags) }.map_err(native_failure)?;
    Ok(flags)
}

fn native_failure<T>(_error: T) -> approval_ui::ApprovalError {
    std::io::Error::other("Approval stdio bootstrap failed").into()
}

#[cfg(test)]
mod tests {
    use core::mem::size_of;
    use std::ffi::OsString;
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::sync::Mutex;

    use super::{
        SealedApprovalStdio, handle_flags, seal_exact_approval_stdio,
        seal_inherited_approval_stdio, set_binary_stdio,
    };
    use approval_ui::ApprovalError;
    use windows::Win32::Foundation::{
        DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS,
        SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateEventW, CreateProcessW, GetCurrentProcess,
        GetExitCodeProcess, PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW,
        TerminateProcess, WaitForSingleObject,
    };
    use windows::core::{PCWSTR, PWSTR};

    const CHILD_FIXTURE: &str = "bootstrap::windows::tests::inherited_approval_stdio_child_fixture";
    const GRANDCHILD_FIXTURE: &str =
        "bootstrap::windows::tests::approval_deinheritance_grandchild_fixture";
    const CHALLENGE: &[u8] = b"approval-two-handle-challenge";
    const ACKNOWLEDGEMENT: &[u8] = b"approval-two-handles-sealed";
    const PROCESS_WAIT_MILLISECONDS: u32 = 25_000;
    static INHERITANCE_TEST_LOCK: Mutex<()> = Mutex::new(());

    trait AmbiguousIfSend<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

    trait AmbiguousIfSync<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

    trait AmbiguousIfClone<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<A> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    struct ReapedTestProcess {
        process: OwnedHandle,
    }

    impl ReapedTestProcess {
        fn is_alive(&self) -> bool {
            // SAFETY: the zero-timeout wait borrows the retained process handle.
            (unsafe { WaitForSingleObject(raw(&self.process), 0) }) == WAIT_TIMEOUT
        }

        fn wait_for_success(&self) -> Result<(), ApprovalError> {
            // SAFETY: the retained process handle remains live for this bounded
            // wait and the subsequent scalar exit-code query.
            let state =
                unsafe { WaitForSingleObject(raw(&self.process), PROCESS_WAIT_MILLISECONDS) };
            if state != WAIT_OBJECT_0 {
                return Err(test_failure());
            }
            let mut exit_code = u32::MAX;
            // SAFETY: output points to one initialized DWORD.
            unsafe { GetExitCodeProcess(raw(&self.process), &raw mut exit_code) }
                .map_err(super::native_failure)?;
            (exit_code == 0).then_some(()).ok_or_else(test_failure)
        }

        fn terminate_and_reap(&self) -> Result<(), ApprovalError> {
            let process = raw(&self.process);
            // SAFETY: this retained handle targets only an isolated test process.
            let state = unsafe { WaitForSingleObject(process, 0) };
            if state == WAIT_OBJECT_0 {
                return Ok(());
            }
            // SAFETY: every non-signaled result takes the conservative cleanup
            // path. Terminate and bounded wait target the exact retained test
            // process, which has no external work or persistent state. A race
            // where it already exited is accepted only after the wait observes it.
            unsafe {
                let _ = TerminateProcess(process, 1);
                if WaitForSingleObject(process, 5_000) != WAIT_OBJECT_0 {
                    return Err(test_failure());
                }
            }
            Ok(())
        }
    }

    impl Drop for ReapedTestProcess {
        fn drop(&mut self) {
            let _ = self.terminate_and_reap();
        }
    }

    struct BroadInheritanceGrandchild {
        child: ReapedTestProcess,
    }

    impl BroadInheritanceGrandchild {
        fn spawn(executable: &std::path::Path) -> Result<Self, ApprovalError> {
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
                cb: u32::try_from(size_of::<STARTUPINFOW>()).map_err(super::native_failure)?,
                ..Default::default()
            };
            let mut information = PROCESS_INFORMATION::default();
            // SAFETY: terminated UTF-16 buffers and initialized structures stay
            // live. TRUE inheritance intentionally has no HANDLE_LIST so the
            // positive-control sentinel must cross this boundary.
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
            .map_err(super::native_failure)?;
            let (process, thread) = owned_process_information(information)?;
            drop(thread);
            Ok(Self {
                child: ReapedTestProcess { process },
            })
        }

        fn names_same_object(
            &self,
            candidate: HANDLE,
            expected: HANDLE,
        ) -> Result<bool, ApprovalError> {
            let mut duplicate = HANDLE::default();
            // SAFETY: the retained grandchild process grants duplication rights.
            // Inherited handles preserve numeric values; exact-object comparison
            // below rejects coincidental reuse of the same numeric slot.
            let result = unsafe {
                DuplicateHandle(
                    raw(&self.child.process),
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
            if super::invalid_handle(duplicate) {
                return Err(test_failure());
            }
            // SAFETY: successful DuplicateHandle returned one fresh owned handle.
            let duplicate = unsafe { OwnedHandle::from_raw_handle(duplicate.0) };
            Ok(super::same_object(raw(&duplicate), expected))
        }
    }

    struct TemporaryInheritFlags {
        handles: Vec<HANDLE>,
    }

    impl TemporaryInheritFlags {
        fn set(handles: impl IntoIterator<Item = HANDLE>) -> Result<Self, ApprovalError> {
            let mut changed = Vec::new();
            for handle in handles {
                if let Err(error) = set_inherit(handle, true) {
                    for previous in changed.iter().copied() {
                        let _ = set_inherit(previous, false);
                    }
                    return Err(error);
                }
                changed.push(handle);
            }
            Ok(Self { handles: changed })
        }
    }

    impl Drop for TemporaryInheritFlags {
        fn drop(&mut self) {
            for handle in self.handles.iter().copied() {
                let _ = set_inherit(handle, false);
            }
        }
    }

    fn owned_process_information(
        information: PROCESS_INFORMATION,
    ) -> Result<(OwnedHandle, OwnedHandle), ApprovalError> {
        if super::invalid_handle(information.hProcess) || super::invalid_handle(information.hThread)
        {
            if !super::invalid_handle(information.hProcess) {
                // SAFETY: CreateProcessW returned this fresh process handle. A
                // malformed companion result is terminated and reaped here.
                unsafe {
                    let _ = TerminateProcess(information.hProcess, 1);
                    let _ = WaitForSingleObject(information.hProcess, 5_000);
                    drop(OwnedHandle::from_raw_handle(information.hProcess.0));
                }
            }
            if !super::invalid_handle(information.hThread) {
                // SAFETY: CreateProcessW returned this fresh primary-thread handle.
                drop(unsafe { OwnedHandle::from_raw_handle(information.hThread.0) });
            }
            return Err(test_failure());
        }
        // SAFETY: successful CreateProcessW returned two fresh owned handles.
        let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) };
        // SAFETY: same unique ownership transfer for the primary thread.
        let thread = unsafe { OwnedHandle::from_raw_handle(information.hThread.0) };
        Ok((process, thread))
    }

    fn anonymous_pipe() -> Result<(OwnedHandle, OwnedHandle), ApprovalError> {
        let mut read = HANDLE::default();
        let mut write = HANDLE::default();
        // SAFETY: both output pointers are valid. Each successful raw handle is
        // transferred exactly once into an independent owner below.
        unsafe { CreatePipe(&raw mut read, &raw mut write, None, 0) }
            .map_err(super::native_failure)?;
        if super::invalid_handle(read) || super::invalid_handle(write) {
            return Err(test_failure());
        }
        // SAFETY: successful CreatePipe returned two fresh owned handles.
        let read = unsafe { OwnedHandle::from_raw_handle(read.0) };
        // SAFETY: same unique ownership transfer for the write end.
        let write = unsafe { OwnedHandle::from_raw_handle(write.0) };
        Ok((read, write))
    }

    fn duplicate_local(source: HANDLE, inheritable: bool) -> Result<OwnedHandle, ApprovalError> {
        let mut duplicate = HANDLE::default();
        // SAFETY: the source is retained by the caller and the success result is
        // one fresh current-process handle adopted exactly once below.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                &raw mut duplicate,
                0,
                inheritable,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(super::native_failure)?;
        if super::invalid_handle(duplicate) {
            return Err(test_failure());
        }
        // SAFETY: successful DuplicateHandle returned one fresh owned handle.
        Ok(unsafe { OwnedHandle::from_raw_handle(duplicate.0) })
    }

    fn raw(handle: &OwnedHandle) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    fn set_inherit(handle: HANDLE, inherit: bool) -> Result<(), ApprovalError> {
        let flags = if inherit {
            HANDLE_FLAG_INHERIT
        } else {
            HANDLE_FLAGS(0)
        };
        // SAFETY: tests retain the exact owned handle and alter only its local
        // inherit attribute.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, flags) }
            .map_err(super::native_failure)
    }

    fn test_failure() -> ApprovalError {
        super::native_failure(())
    }

    #[test]
    fn exact_approval_stdio_set_seals_two_unique_objects_without_closing_them()
    -> Result<(), ApprovalError> {
        let (input, _input_peer) = anonymous_pipe()?;
        let (_output_peer, output) = anonymous_pipe()?;
        let input = raw(&input);
        let output = raw(&output);
        set_inherit(input, true)?;
        set_inherit(output, true)?;

        seal_exact_approval_stdio([input, output, output])?;
        assert!(matches!(handle_flags(input), Ok(0)));
        assert!(matches!(handle_flags(output), Ok(0)));
        assert!(seal_exact_approval_stdio([input, output, output]).is_err());
        Ok(())
    }

    #[test]
    fn sealed_approval_stdio_is_thread_bound_non_clone_and_non_copy() {
        let _ = <SealedApprovalStdio as AmbiguousIfSend<_>>::marker;
        let _ = <SealedApprovalStdio as AmbiguousIfSync<_>>::marker;
        let _ = <SealedApprovalStdio as AmbiguousIfClone<_>>::marker;
        let _ = <SealedApprovalStdio as AmbiguousIfCopy<_>>::marker;
    }

    #[test]
    fn invalid_alias_type_or_flags_are_rejected_before_mutation() -> Result<(), ApprovalError> {
        let (input, _input_peer) = anonymous_pipe()?;
        let (_output_peer, output) = anonymous_pipe()?;
        let (_error_peer, distinct_error) = anonymous_pipe()?;
        let input = raw(&input);
        let output = raw(&output);
        let distinct_error = raw(&distinct_error);
        for handle in [input, output, distinct_error] {
            set_inherit(handle, true)?;
        }

        assert!(seal_exact_approval_stdio([input, input, output]).is_err());
        assert!(seal_exact_approval_stdio([input, output, distinct_error]).is_err());
        assert!(seal_exact_approval_stdio([HANDLE::default(), output, output]).is_err());

        let output_alias = duplicate_local(output, true)?;
        assert!(seal_exact_approval_stdio([input, output, raw(&output_alias)]).is_err());
        let input_alias = duplicate_local(output, true)?;
        assert!(seal_exact_approval_stdio([raw(&input_alias), output, output]).is_err());

        // SAFETY: the event is a fresh non-pipe kernel object owned below.
        let event =
            unsafe { CreateEventW(None, true, false, None) }.map_err(super::native_failure)?;
        if super::invalid_handle(event) {
            return Err(test_failure());
        }
        // SAFETY: successful CreateEventW returned one fresh owned handle.
        let event = unsafe { OwnedHandle::from_raw_handle(event.0) };
        set_inherit(raw(&event), true)?;
        assert!(seal_exact_approval_stdio([raw(&event), output, output]).is_err());

        for handle in [
            input,
            output,
            distinct_error,
            raw(&output_alias),
            raw(&input_alias),
            raw(&event),
        ] {
            assert!(matches!(handle_flags(handle), Ok(flags) if flags == HANDLE_FLAG_INHERIT.0));
        }
        set_inherit(output, false)?;
        assert!(seal_exact_approval_stdio([input, output, output]).is_err());
        assert!(matches!(handle_flags(input), Ok(flags) if flags == HANDLE_FLAG_INHERIT.0));
        assert!(matches!(handle_flags(output), Ok(0)));

        for handle in [
            input,
            distinct_error,
            raw(&output_alias),
            raw(&input_alias),
            raw(&event),
        ] {
            assert!(matches!(handle_flags(handle), Ok(flags) if flags == HANDLE_FLAG_INHERIT.0));
            set_inherit(handle, false)?;
        }
        Ok(())
    }

    #[test]
    fn inherited_approval_stdio_is_sealed_before_descendant_creation() -> Result<(), ApprovalError>
    {
        let _inheritance_guard = INHERITANCE_TEST_LOCK
            .lock()
            .map_err(super::native_failure)?;
        let executable = std::env::current_exe().map_err(super::native_failure)?;
        let (child_input, parent_writer) = anonymous_pipe()?;
        let (parent_reader, child_output) = anonymous_pipe()?;
        let child_input_raw = raw(&child_input);
        let child_output_raw = raw(&child_output);
        let temporary_inherit = TemporaryInheritFlags::set([child_input_raw, child_output_raw])?;

        let mut application = executable.as_os_str().encode_wide().collect::<Vec<_>>();
        application.push(0);
        let mut command = OsString::from("\"");
        command.push(executable.as_os_str());
        command.push("\" ");
        command.push(CHILD_FIXTURE);
        command.push(" --exact --ignored --test-threads=1");
        let mut command = command.encode_wide().collect::<Vec<_>>();
        command.push(0);
        let startup = STARTUPINFOW {
            cb: u32::try_from(size_of::<STARTUPINFOW>()).map_err(super::native_failure)?,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: child_input_raw,
            hStdOutput: child_output_raw,
            hStdError: child_output_raw,
            ..Default::default()
        };
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: buffers and structures remain live. TRUE inheritance passes
        // the two temporarily inheritable exact stdio objects to the suspended
        // isolated fixture process.
        unsafe {
            CreateProcessW(
                PCWSTR(application.as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_SUSPENDED | CREATE_NO_WINDOW,
                None,
                PCWSTR::null(),
                &raw const startup,
                &raw mut information,
            )
        }
        .map_err(super::native_failure)?;
        drop(temporary_inherit);
        let (process, thread) = owned_process_information(information)?;
        let child = ReapedTestProcess { process };
        assert!(matches!(handle_flags(child_input_raw), Ok(0)));
        assert!(matches!(handle_flags(child_output_raw), Ok(0)));
        drop(child_input);
        drop(child_output);

        let mut parent_writer = File::from(parent_writer);
        parent_writer.write_all(CHALLENGE)?;
        drop(parent_writer);

        // SAFETY: this is the exact still-suspended primary thread returned for
        // the guarded fixture child. A count other than one fails closed.
        let previous_suspend_count = unsafe { ResumeThread(raw(&thread)) };
        if previous_suspend_count != 1 {
            return Err(test_failure());
        }
        drop(thread);
        child.wait_for_success()?;

        let mut output = Vec::new();
        File::from(parent_reader).read_to_end(&mut output)?;
        assert!(
            output
                .windows(ACKNOWLEDGEMENT.len())
                .any(|window| window == ACKNOWLEDGEMENT)
        );
        Ok(())
    }

    #[test]
    #[ignore = "launched only by the isolated Approval handle driver"]
    fn inherited_approval_stdio_child_fixture() -> Result<(), ApprovalError> {
        let sealed = seal_inherited_approval_stdio()?;
        set_binary_stdio(&sealed)?;
        assert!(matches!(handle_flags(sealed.input), Ok(0)));
        assert!(matches!(handle_flags(sealed.output), Ok(0)));

        let mut request = Vec::new();
        std::io::stdin()
            .take(u64::try_from(CHALLENGE.len()).map_err(super::native_failure)? + 1)
            .read_to_end(&mut request)?;
        if request.as_slice() != CHALLENGE {
            return Err(test_failure());
        }

        // SAFETY: this unnamed event is initially non-inheritable and becomes a
        // positive control only for the immediately following broad launch.
        let sentinel =
            unsafe { CreateEventW(None, true, false, None) }.map_err(super::native_failure)?;
        if super::invalid_handle(sentinel) {
            return Err(test_failure());
        }
        // SAFETY: successful CreateEventW returned one fresh owned event handle.
        let sentinel = unsafe { OwnedHandle::from_raw_handle(sentinel.0) };
        let sentinel_raw = raw(&sentinel);
        let sentinel_inherit = TemporaryInheritFlags::set([sentinel_raw])?;

        let executable = std::env::current_exe().map_err(super::native_failure)?;
        let grandchild = BroadInheritanceGrandchild::spawn(&executable)?;
        drop(sentinel_inherit);
        assert!(matches!(handle_flags(sentinel_raw), Ok(0)));
        assert!(grandchild.child.is_alive());
        assert!(grandchild.names_same_object(sentinel_raw, sentinel_raw)?);
        assert!(!grandchild.names_same_object(sealed.input, sealed.input)?);
        assert!(!grandchild.names_same_object(sealed.output, sealed.output)?);
        grandchild.child.terminate_and_reap()?;

        std::io::stdout().write_all(ACKNOWLEDGEMENT)?;
        std::io::stdout().flush()?;
        drop(sealed);
        Ok(())
    }

    #[test]
    #[ignore = "launched only as the Approval deinheritance grandchild probe"]
    fn approval_deinheritance_grandchild_fixture() {
        std::thread::sleep(std::time::Duration::from_secs(15));
    }
}
