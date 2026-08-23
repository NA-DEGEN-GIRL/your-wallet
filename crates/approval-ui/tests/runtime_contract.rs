#![cfg(all(feature = "runtime-contract-test-hook", debug_assertions))]
#![cfg_attr(windows, allow(unsafe_code))]

#[cfg(not(windows))]
use std::io::Write as _;
#[cfg(not(windows))]
use std::process::{Command, Stdio};

use approval_ui::{
    ApprovalDisplay, ApprovalRequest, Decision, DisplayField, FieldSemantic, OperationKind,
    RiskLevel, SimulationStatus,
};

fn field(semantic: FieldSemantic, value: &str) -> Result<DisplayField, String> {
    DisplayField::new(semantic, value, semantic != FieldSemantic::SimulationEngine)
        .map_err(|_| "invalid display field".to_owned())
}

fn valid_request() -> Result<ApprovalRequest, String> {
    let display = ApprovalDisplay::new(
        RiskLevel::High,
        vec![
            field(
                FieldSemantic::NoSimulationWarning,
                "No simulation was performed.",
            )?,
            field(FieldSemantic::Origin, "https://example.test")?,
            field(
                FieldSemantic::PersonalMessageWarning,
                "Personal signatures can be reused by protocols.",
            )?,
            field(
                FieldSemantic::Account,
                "0x1111111111111111111111111111111111111111",
            )?,
            field(FieldSemantic::NetworkName, "Ethereum")?,
            field(FieldSemantic::ChainId, "1")?,
            field(
                FieldSemantic::GenesisHash,
                "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )?,
            field(
                FieldSemantic::RulesetRevision,
                "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )?,
            field(
                FieldSemantic::RpcObservationsDigest,
                "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            )?,
            field(
                FieldSemantic::OperationKind,
                OperationKind::PersonalMessage.value(),
            )?,
            field(FieldSemantic::PersonalMessageBytes, "0x0102")?,
            field(
                FieldSemantic::SimulationStatus,
                SimulationStatus::NotPerformed.value(),
            )?,
            field(
                FieldSemantic::OriginProvenance,
                "Browser-reported; not independently verified",
            )?,
            field(
                FieldSemantic::OriginWarning,
                "Browser origin is not independently attested.",
            )?,
        ],
    )
    .map_err(|_| "invalid display fixture".to_owned())?;
    ApprovalRequest::new([7; 32], [9; 32], 120_000, "blue comet", display)
        .map_err(|_| "invalid request fixture".to_owned())
}

struct ChildOutput {
    succeeded: bool,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[cfg(not(windows))]
fn run_child(input: &[u8]) -> Result<ChildOutput, String> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_approval-ui"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| "could not start approval-ui")?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| "approval-ui stdin was not piped".to_owned())?;
    stdin
        .write_all(input)
        .map_err(|_| "could not write approval request".to_owned())?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .map_err(|_| "could not collect approval-ui output".to_owned())?;
    Ok(ChildOutput {
        succeeded: output.status.success(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

#[cfg(windows)]
fn run_child(input: &[u8]) -> Result<ChildOutput, String> {
    windows_child::run(input)
}

#[test]
fn inherited_stream_contract_is_exact_and_silent() -> Result<(), String> {
    let request = valid_request()?;
    let request_bytes = approval_wire::encode_request(&request);
    let output = run_child(&request_bytes)?;

    assert!(output.succeeded);
    assert!(output.stderr.is_empty());
    let response = approval_wire::decode_response(&output.stdout)
        .map_err(|_| "approval response was malformed".to_owned())?;
    assert_eq!(response.decision(), Decision::Reject);
    assert_eq!(response.digest(), request.digest());
    assert_eq!(response.approval_nonce(), request.approval_nonce());
    Ok(())
}

#[test]
fn trailing_request_byte_fails_without_output() -> Result<(), String> {
    let request = valid_request()?;
    let mut request_bytes = approval_wire::encode_request(&request);
    request_bytes.push(0);
    let output = run_child(&request_bytes)?;

    assert!(!output.succeeded);
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}

#[test]
fn oversized_request_fails_without_output_or_pipe_deadlock() -> Result<(), String> {
    let oversized_len = usize::try_from(approval_ui::MAX_REQUEST_BYTES)
        .map_err(|_| "approval request bound did not fit usize".to_owned())?
        .checked_add(1)
        .ok_or_else(|| "approval request bound overflowed".to_owned())?;
    let output = run_child(&vec![0_u8; oversized_len])?;

    assert!(!output.succeeded);
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    Ok(())
}

#[cfg(windows)]
mod windows_child {
    use core::mem::size_of;
    use std::ffi::{OsStr, OsString};
    use std::fs::File;
    use std::io::{Read as _, Write as _};
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
    use std::sync::Mutex;

    use windows::Win32::Foundation::{
        GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation,
        WAIT_OBJECT_0,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CreateProcessW, GetExitCodeProcess,
        PROCESS_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess,
        WaitForSingleObject,
    };
    use windows::core::{PCWSTR, PWSTR};

    use super::ChildOutput;

    const PROCESS_WAIT_MILLISECONDS: u32 = 10_000;
    static INHERITANCE_TEST_LOCK: Mutex<()> = Mutex::new(());

    struct ReapedProcess {
        process: OwnedHandle,
    }

    impl ReapedProcess {
        fn wait_for_exit(&self) -> Result<u32, String> {
            // SAFETY: the retained process handle remains live for the bounded
            // wait and following scalar exit-code query.
            let state =
                unsafe { WaitForSingleObject(raw(&self.process), PROCESS_WAIT_MILLISECONDS) };
            if state != WAIT_OBJECT_0 {
                return Err("approval-ui did not exit within the test bound".to_owned());
            }
            let mut exit_code = u32::MAX;
            // SAFETY: output points to one initialized DWORD.
            unsafe { GetExitCodeProcess(raw(&self.process), &raw mut exit_code) }
                .map_err(|_| "could not read approval-ui exit status".to_owned())?;
            Ok(exit_code)
        }

        fn terminate_and_reap(&self) {
            let process = raw(&self.process);
            // SAFETY: the process handle targets only this isolated test child.
            let state = unsafe { WaitForSingleObject(process, 0) };
            if state == WAIT_OBJECT_0 {
                return;
            }
            // SAFETY: every non-signaled result takes the conservative cleanup
            // path. Cleanup targets the exact retained test child and is bounded
            // so a failing test cannot leave it running.
            unsafe {
                let _ = TerminateProcess(process, 1);
                let _ = WaitForSingleObject(process, 5_000);
            }
        }
    }

    impl Drop for ReapedProcess {
        fn drop(&mut self) {
            self.terminate_and_reap();
        }
    }

    struct TemporaryInheritFlags {
        handles: [HANDLE; 2],
    }

    impl TemporaryInheritFlags {
        fn set(handles: [HANDLE; 2]) -> Result<Self, String> {
            set_inherit(handles[0], true)?;
            if let Err(error) = set_inherit(handles[1], true) {
                let _ = set_inherit(handles[0], false);
                return Err(error);
            }
            Ok(Self { handles })
        }
    }

    impl Drop for TemporaryInheritFlags {
        fn drop(&mut self) {
            for handle in self.handles {
                let _ = set_inherit(handle, false);
            }
        }
    }

    pub(super) fn run(input: &[u8]) -> Result<ChildOutput, String> {
        let _inheritance_guard = INHERITANCE_TEST_LOCK
            .lock()
            .map_err(|_| "approval runtime inheritance lock was poisoned".to_owned())?;
        let (child_input, parent_writer) = anonymous_pipe()?;
        let (parent_reader, child_output) = anonymous_pipe()?;
        let child_input_raw = raw(&child_input);
        let child_output_raw = raw(&child_output);
        let temporary_inherit = TemporaryInheritFlags::set([child_input_raw, child_output_raw])?;

        let executable = OsStr::new(env!("CARGO_BIN_EXE_approval-ui"));
        let mut application = executable.encode_wide().collect::<Vec<_>>();
        application.push(0);
        let mut command = OsString::from("\"");
        command.push(executable);
        command.push("\"");
        let mut command = command.encode_wide().collect::<Vec<_>>();
        command.push(0);
        let startup = STARTUPINFOW {
            cb: u32::try_from(size_of::<STARTUPINFOW>())
                .map_err(|_| "approval startup structure size was invalid".to_owned())?,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: child_input_raw,
            hStdOutput: child_output_raw,
            hStdError: child_output_raw,
            ..Default::default()
        };
        let mut information = PROCESS_INFORMATION::default();
        // SAFETY: terminated buffers and initialized structures stay live. The
        // exact same output handle-table value is deliberately used for stdout
        // and stderr, matching the private production launcher topology.
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
        .map_err(|_| "could not start approval-ui".to_owned())?;
        drop(temporary_inherit);
        let (process, thread) = owned_process_information(information)?;
        let child = ReapedProcess { process };
        require_zero_flags(child_input_raw)?;
        require_zero_flags(child_output_raw)?;
        drop(child_input);
        drop(child_output);

        // SAFETY: this is the exact still-suspended primary thread returned for
        // the guarded child. A count other than one fails closed.
        if unsafe { ResumeThread(raw(&thread)) } != 1 {
            return Err("could not resume approval-ui exactly once".to_owned());
        }
        drop(thread);

        let mut parent_writer = File::from(parent_writer);
        parent_writer
            .write_all(input)
            .map_err(|_| "could not write approval request".to_owned())?;
        drop(parent_writer);
        let exit_code = child.wait_for_exit()?;

        let mut stdout = Vec::new();
        File::from(parent_reader)
            .read_to_end(&mut stdout)
            .map_err(|_| "could not collect approval-ui output".to_owned())?;
        Ok(ChildOutput {
            succeeded: exit_code == 0,
            stdout,
            // Windows intentionally has one shared response/diagnostic stream.
            // Exact response decoding and the failure-empty assertion below
            // therefore prove that no diagnostic bytes were emitted.
            stderr: Vec::new(),
        })
    }

    fn anonymous_pipe() -> Result<(OwnedHandle, OwnedHandle), String> {
        let mut read = HANDLE::default();
        let mut write = HANDLE::default();
        // SAFETY: both outputs are valid and each success value transfers to one
        // independent owner exactly once below.
        unsafe { CreatePipe(&raw mut read, &raw mut write, None, 0) }
            .map_err(|_| "could not create approval runtime pipe".to_owned())?;
        if read.is_invalid() || write.is_invalid() {
            return Err("approval runtime pipe was invalid".to_owned());
        }
        // SAFETY: successful CreatePipe returned two fresh owned handles.
        let read = unsafe { OwnedHandle::from_raw_handle(read.0) };
        // SAFETY: same unique ownership transfer for the write end.
        let write = unsafe { OwnedHandle::from_raw_handle(write.0) };
        Ok((read, write))
    }

    fn owned_process_information(
        information: PROCESS_INFORMATION,
    ) -> Result<(OwnedHandle, OwnedHandle), String> {
        if information.hProcess.is_invalid() || information.hThread.is_invalid() {
            if !information.hProcess.is_invalid() {
                // SAFETY: this malformed partial result is terminated, reaped,
                // and closed synchronously before returning an error.
                unsafe {
                    let _ = TerminateProcess(information.hProcess, 1);
                    let _ = WaitForSingleObject(information.hProcess, 5_000);
                    drop(OwnedHandle::from_raw_handle(information.hProcess.0));
                }
            }
            if !information.hThread.is_invalid() {
                // SAFETY: CreateProcessW returned this fresh primary-thread handle.
                drop(unsafe { OwnedHandle::from_raw_handle(information.hThread.0) });
            }
            return Err("approval-ui returned incomplete process handles".to_owned());
        }
        // SAFETY: successful CreateProcessW returned two fresh owned handles.
        let process = unsafe { OwnedHandle::from_raw_handle(information.hProcess.0) };
        // SAFETY: same unique ownership transfer for the primary thread.
        let thread = unsafe { OwnedHandle::from_raw_handle(information.hThread.0) };
        Ok((process, thread))
    }

    fn raw(handle: &OwnedHandle) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    fn set_inherit(handle: HANDLE, inherit: bool) -> Result<(), String> {
        let flags = if inherit {
            HANDLE_FLAG_INHERIT
        } else {
            HANDLE_FLAGS(0)
        };
        // SAFETY: the caller retains the exact owned handle and changes only its
        // process-local inherit attribute.
        unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, flags) }
            .map_err(|_| "could not change approval runtime inherit flags".to_owned())
    }

    fn require_zero_flags(handle: HANDLE) -> Result<(), String> {
        let mut flags = u32::MAX;
        // SAFETY: output points to one initialized flag word and the caller
        // retains the live owned handle.
        unsafe { GetHandleInformation(handle, &raw mut flags) }
            .map_err(|_| "could not query approval runtime inherit flags".to_owned())?;
        (flags == 0)
            .then_some(())
            .ok_or_else(|| "approval runtime inherit flags were not cleared".to_owned())
    }
}
