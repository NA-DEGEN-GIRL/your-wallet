//! Bounded parent-side helper-channel duplication.
//!
//! The service retains its overlapped client endpoints and duplicates exactly
//! two already-connected child-server handles into one suspended helper. The
//! private wrappers' sole dormant caller authenticates that exact process and
//! capture gate first; this module's parameter type does not encode that proof.
//! Returned target-process handle values are opaque numeric words, not local
//! `HANDLE` owners. Any error is process-terminal for the sole dormant
//! orchestration layer; this module never attempts to close a target-process
//! handle value from the service process.

#![allow(unsafe_code)]

use core::ffi::c_void;
use core::fmt;
use std::os::windows::io::{AsRawHandle as _, BorrowedHandle};

use thiserror::Error;
use windows::Win32::Foundation::{DUPLICATE_HANDLE_OPTIONS, DuplicateHandle, HANDLE};
use windows::Win32::System::Threading::GetCurrentProcess;

use crate::pipe::{
    ApprovalRequestWriter, ApprovalResponseReader, PrivateApprovalPipes, PrivateSecretInputPipes,
    SecretRequestWriter, SecretResponseReader,
};

const CHILD_REQUEST_ACCESS: u32 = 0x0010_0001;
const CHILD_RESPONSE_ACCESS: u32 = 0x0010_0002;
const NO_DUPLICATE_OPTIONS: u32 = 0;

/// Data-free failure from the bounded parent-side channel injection boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum ServiceChannelInjectionError {
    /// The retained local pipe sources no longer have their exact properties.
    #[error("service helper channel sources are unavailable")]
    SourceValidation,
    /// Windows rejected one of the two exact target-process duplications.
    #[error("service helper channel duplication failed")]
    Duplication,
    /// Windows returned a zero, pseudo, out-of-range, or repeated target value.
    #[error("service helper remote channel values are invalid")]
    RemoteHandle,
    /// At least one local child-server source did not close successfully.
    #[error("service helper local channel-source close failed")]
    SourceClose,
}

/// One validated handle value in the child process's handle table.
///
/// This is deliberately neither a Win32 `HANDLE` nor an owning/borrowed Rust
/// handle. Dropping it performs no operation in the service process.
pub(super) struct RemoteChildHandleWord(u64);

impl RemoteChildHandleWord {
    fn from_duplicate_result(value: usize) -> Result<Self, ServiceChannelInjectionError> {
        if invalid_handle_word(value) {
            return Err(ServiceChannelInjectionError::RemoteHandle);
        }
        let value = u64::try_from(value).map_err(|_| ServiceChannelInjectionError::RemoteHandle)?;
        if value > i64::MAX as u64 {
            return Err(ServiceChannelInjectionError::RemoteHandle);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for RemoteChildHandleWord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteChildHandleWord([REMOTE HANDLE])")
    }
}

/// Exact request/response handle values installed in one child handle table.
#[must_use = "remote channel values must enter the authenticated register gate"]
pub(super) struct InjectedChildChannelHandles {
    request: RemoteChildHandleWord,
    response: RemoteChildHandleWord,
}

impl InjectedChildChannelHandles {
    /// Consumes both opaque target-process values for the one exact R10/R11
    /// context mutation. The returned integers are register payloads only;
    /// they never become local Win32 or Rust handle values.
    pub(super) fn into_register_words(self) -> (u64, u64) {
        (self.request.0, self.response.0)
    }
}

impl fmt::Debug for InjectedChildChannelHandles {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InjectedChildChannelHandles")
            .field("request", &"[REMOTE HANDLE]")
            .field("response", &"[REMOTE HANDLE]")
            .finish()
    }
}

/// Role-typed overlapped service endpoints for an Approval helper.
#[must_use = "the service endpoints must remain live through bootstrap"]
pub(super) struct ApprovalParentChannels {
    request: ApprovalRequestWriter,
    response: ApprovalResponseReader,
}

impl ApprovalParentChannels {
    pub(super) fn into_parts(self) -> (ApprovalRequestWriter, ApprovalResponseReader) {
        (self.request, self.response)
    }
}

impl fmt::Debug for ApprovalParentChannels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovalParentChannels([HANDLES])")
    }
}

/// Role-typed overlapped service endpoints for a Secret Input helper.
#[must_use = "the service endpoints must remain live through bootstrap"]
pub(super) struct SecretInputParentChannels {
    request: SecretRequestWriter,
    response: SecretResponseReader,
}

impl SecretInputParentChannels {
    pub(super) fn into_parts(self) -> (SecretRequestWriter, SecretResponseReader) {
        (self.request, self.response)
    }
}

impl fmt::Debug for SecretInputParentChannels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretInputParentChannels([HANDLES])")
    }
}

/// Successful Approval-channel installation plus retained service endpoints.
#[must_use = "injected channels must complete the authenticated bootstrap"]
pub(super) struct InjectedApprovalChannels {
    child: InjectedChildChannelHandles,
    parent: ApprovalParentChannels,
}

impl InjectedApprovalChannels {
    pub(super) fn into_parts(self) -> (InjectedChildChannelHandles, ApprovalParentChannels) {
        (self.child, self.parent)
    }
}

impl fmt::Debug for InjectedApprovalChannels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InjectedApprovalChannels([REDACTED])")
    }
}

/// Successful Secret Input channel installation plus retained service ends.
#[must_use = "injected channels must complete the authenticated bootstrap"]
pub(super) struct InjectedSecretInputChannels {
    child: InjectedChildChannelHandles,
    parent: SecretInputParentChannels,
}

impl InjectedSecretInputChannels {
    pub(super) fn into_parts(self) -> (InjectedChildChannelHandles, SecretInputParentChannels) {
        (self.child, self.parent)
    }
}

impl fmt::Debug for InjectedSecretInputChannels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InjectedSecretInputChannels([REDACTED])")
    }
}

/// Duplicates the exact Approval request/response server sources into one
/// suspended child process. Its sole dormant caller first authenticates the
/// exact child at the capture gate; this parameter type does not prove that
/// obligation. No source handle or pipe name is inherited or serialized.
pub(super) fn duplicate_approval_channels_for_child(
    pipes: PrivateApprovalPipes,
    child_process: BorrowedHandle<'_>,
) -> Result<InjectedApprovalChannels, ServiceChannelInjectionError> {
    let (child, parent) = duplicate_channels(
        pipes,
        TargetProcessHandleWord::from_borrowed(child_process),
        &mut WindowsDuplicateHandle,
    )?;
    Ok(InjectedApprovalChannels { child, parent })
}

/// Duplicates the exact Secret Input request/response server sources into one
/// suspended child process. Its sole dormant caller first authenticates the
/// exact child at the capture gate; this parameter type does not prove that
/// obligation. No source handle or pipe name is inherited or serialized.
pub(super) fn duplicate_secret_input_channels_for_child(
    pipes: PrivateSecretInputPipes,
    child_process: BorrowedHandle<'_>,
) -> Result<InjectedSecretInputChannels, ServiceChannelInjectionError> {
    let (child, parent) = duplicate_channels(
        pipes,
        TargetProcessHandleWord::from_borrowed(child_process),
        &mut WindowsDuplicateHandle,
    )?;
    Ok(InjectedSecretInputChannels { child, parent })
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct LocalSourceHandleWord(usize);

impl LocalSourceHandleWord {
    fn from_borrowed(handle: BorrowedHandle<'_>) -> Result<Self, ServiceChannelInjectionError> {
        let value = handle.as_raw_handle() as usize;
        if invalid_handle_word(value) {
            return Err(ServiceChannelInjectionError::SourceValidation);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for LocalSourceHandleWord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LocalSourceHandleWord([LOCAL HANDLE])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct TargetProcessHandleWord(usize);

impl TargetProcessHandleWord {
    fn from_borrowed(handle: BorrowedHandle<'_>) -> Result<Self, ServiceChannelInjectionError> {
        let value = handle.as_raw_handle() as usize;
        if invalid_handle_word(value) {
            return Err(ServiceChannelInjectionError::SourceValidation);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for TargetProcessHandleWord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TargetProcessHandleWord([LOCAL HANDLE])")
    }
}

const fn invalid_handle_word(value: usize) -> bool {
    // Every documented current-process/thread/token pseudo-handle is a
    // sign-extended negative `isize`. Reject the complete negative range
    // instead of maintaining a brittle list of individual pseudo constants.
    value == 0 || value > isize::MAX.cast_unsigned()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DuplicateSourceProcess {
    Current,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct DuplicateCall {
    source_process: DuplicateSourceProcess,
    source_handle: LocalSourceHandleWord,
    target_process: TargetProcessHandleWord,
    desired_access: u32,
    inherit_handle: bool,
    options: u32,
}

impl fmt::Debug for DuplicateCall {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DuplicateCall")
            .field("source_process", &self.source_process)
            .field("source_handle", &"[LOCAL HANDLE]")
            .field("target_process", &"[LOCAL HANDLE]")
            .field("desired_access", &self.desired_access)
            .field("inherit_handle", &self.inherit_handle)
            .field("options", &self.options)
            .finish()
    }
}

trait DuplicateHandleApi {
    fn duplicate_handle(&mut self, call: DuplicateCall) -> Result<usize, ()>;
}

#[derive(Debug)]
struct WindowsDuplicateHandle;

impl DuplicateHandleApi for WindowsDuplicateHandle {
    fn duplicate_handle(&mut self, call: DuplicateCall) -> Result<usize, ()> {
        let mut remote = HANDLE::default();
        // SAFETY: both local words originate from simultaneously live borrowed
        // handles. The source process is exactly the current process, the target
        // is the authenticated suspended child, and the output receives only a
        // numeric value meaningful in the target process. This module never
        // claims local ownership of that returned value.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                HANDLE(call.source_handle.0 as *mut c_void),
                HANDLE(call.target_process.0 as *mut c_void),
                &raw mut remote,
                call.desired_access,
                call.inherit_handle,
                DUPLICATE_HANDLE_OPTIONS(call.options),
            )
            .map_err(|_| ())?;
        }
        Ok(remote.0 as usize)
    }
}

trait PendingChannelBundle {
    type Parent;

    fn revalidate_sources(&self) -> Result<(), ()>;
    fn source_words(&self) -> Result<(LocalSourceHandleWord, LocalSourceHandleWord), ()>;
    fn close_sources_checked(self) -> Result<Self::Parent, ()>;
}

impl PendingChannelBundle for PrivateApprovalPipes {
    type Parent = ApprovalParentChannels;

    fn revalidate_sources(&self) -> Result<(), ()> {
        self.revalidate_service_launch_sources().map_err(|_| ())
    }

    fn source_words(&self) -> Result<(LocalSourceHandleWord, LocalSourceHandleWord), ()> {
        Ok((
            LocalSourceHandleWord::from_borrowed(self.child_input()).map_err(|_| ())?,
            LocalSourceHandleWord::from_borrowed(self.child_output()).map_err(|_| ())?,
        ))
    }

    fn close_sources_checked(self) -> Result<Self::Parent, ()> {
        let (request, response) = self.into_parent_checked().map_err(|_| ())?;
        Ok(ApprovalParentChannels { request, response })
    }
}

impl PendingChannelBundle for PrivateSecretInputPipes {
    type Parent = SecretInputParentChannels;

    fn revalidate_sources(&self) -> Result<(), ()> {
        self.revalidate_service_launch_sources().map_err(|_| ())
    }

    fn source_words(&self) -> Result<(LocalSourceHandleWord, LocalSourceHandleWord), ()> {
        Ok((
            LocalSourceHandleWord::from_borrowed(self.child_input()).map_err(|_| ())?,
            LocalSourceHandleWord::from_borrowed(self.child_output()).map_err(|_| ())?,
        ))
    }

    fn close_sources_checked(self) -> Result<Self::Parent, ()> {
        let (request, response) = self.into_parent_checked().map_err(|_| ())?;
        Ok(SecretInputParentChannels { request, response })
    }
}

fn duplicate_channels<Bundle, Api>(
    bundle: Bundle,
    target_process: Result<TargetProcessHandleWord, ServiceChannelInjectionError>,
    api: &mut Api,
) -> Result<(InjectedChildChannelHandles, Bundle::Parent), ServiceChannelInjectionError>
where
    Bundle: PendingChannelBundle,
    Api: DuplicateHandleApi,
{
    let injection = (|| {
        let target_process = target_process?;
        bundle
            .revalidate_sources()
            .map_err(|()| ServiceChannelInjectionError::SourceValidation)?;
        let (request_source, response_source) = bundle
            .source_words()
            .map_err(|()| ServiceChannelInjectionError::SourceValidation)?;
        if request_source == response_source {
            return Err(ServiceChannelInjectionError::SourceValidation);
        }

        let request = api
            .duplicate_handle(DuplicateCall {
                source_process: DuplicateSourceProcess::Current,
                source_handle: request_source,
                target_process,
                desired_access: CHILD_REQUEST_ACCESS,
                inherit_handle: false,
                options: NO_DUPLICATE_OPTIONS,
            })
            .map_err(|()| ServiceChannelInjectionError::Duplication)
            .and_then(RemoteChildHandleWord::from_duplicate_result)?;
        let response = api
            .duplicate_handle(DuplicateCall {
                source_process: DuplicateSourceProcess::Current,
                source_handle: response_source,
                target_process,
                desired_access: CHILD_RESPONSE_ACCESS,
                inherit_handle: false,
                options: NO_DUPLICATE_OPTIONS,
            })
            .map_err(|()| ServiceChannelInjectionError::Duplication)
            .and_then(RemoteChildHandleWord::from_duplicate_result)?;
        if request.0 == response.0 {
            return Err(ServiceChannelInjectionError::RemoteHandle);
        }
        Ok(InjectedChildChannelHandles { request, response })
    })();

    let parent = bundle
        .close_sources_checked()
        .map_err(|()| ServiceChannelInjectionError::SourceClose);
    match (injection, parent) {
        (Ok(child), Ok(parent)) => Ok((child, parent)),
        (Err(failure), Ok(parent)) => {
            drop(parent);
            Err(failure)
        }
        (Ok(child), Err(failure)) => {
            drop(child);
            Err(failure)
        }
        // Local source closure is an independent authority-cleanup obligation.
        // It dominates an earlier injection failure so orchestration cannot
        // mistake an unproven local close for an ordinary child-only failure.
        (Err(_injection_failure), Err(close_failure)) => Err(close_failure),
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;
    use core::ffi::c_void;
    use core::mem::size_of;
    use std::io::Read as _;
    use std::os::windows::io::{
        AsHandle as _, AsRawHandle, BorrowedHandle, FromRawHandle as _, OwnedHandle,
    };
    use std::process::{Child, Command, Stdio};
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    use windows::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
    use windows::Win32::Foundation::{
        CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE, STATUS_SUCCESS,
        WAIT_OBJECT_0,
    };
    use windows::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, ReadFile, WriteFile};
    use windows::Win32::System::Threading::{GetCurrentProcess, WaitForSingleObject};
    use windows::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;

    use super::*;

    const IDLE_CHILD_FIXTURE: &str =
        "key_agent_service_launch::channel::tests::service_channel_idle_child_fixture";
    const IDLE_CHILD_ENV: &str = "YOUR_WALLET_SERVICE_CHANNEL_IDLE_CHILD";
    const CHILD_CLEANUP_TIMEOUT_MILLISECONDS: u32 = 5_000;

    struct IdleChildGuard(Option<Child>);

    impl IdleChildGuard {
        fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
            let executable = std::env::current_exe()?;
            let child = Command::new(executable)
                .arg(IDLE_CHILD_FIXTURE)
                .arg("--exact")
                .arg("--ignored")
                .arg("--test-threads=1")
                .arg("--quiet")
                .env(IDLE_CHILD_ENV, "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            Ok(Self(Some(child)))
        }

        fn process_handle(&mut self) -> Result<BorrowedHandle<'_>, Box<dyn std::error::Error>> {
            {
                let child = self.0.as_mut().ok_or("idle child was already reaped")?;
                if child.try_wait()?.is_some() {
                    return Err("idle child exited before channel injection".into());
                }
            }
            Ok(self
                .0
                .as_ref()
                .ok_or("idle child was already reaped")?
                .as_handle())
        }

        fn terminate_and_reap(mut self) -> Result<(), Box<dyn std::error::Error>> {
            self.terminate_and_reap_in_place()
        }

        fn terminate_and_reap_in_place(&mut self) -> Result<(), Box<dyn std::error::Error>> {
            let child = self.0.as_mut().ok_or("idle child was already reaped")?;
            if child.try_wait()?.is_some() {
                self.0.take();
                return Err("idle child exited before bounded cleanup".into());
            }
            child.kill()?;
            let process = HANDLE(child.as_raw_handle());
            // SAFETY: the Child owner retains its live process handle throughout
            // the bounded wait. A signaled process makes the following Rust wait
            // nonblocking while allowing Child to cache and close its status.
            if unsafe { WaitForSingleObject(process, CHILD_CLEANUP_TIMEOUT_MILLISECONDS) }
                != WAIT_OBJECT_0
            {
                return Err("idle child did not terminate within the cleanup bound".into());
            }
            let _status = child.wait()?;
            self.0.take();
            Ok(())
        }
    }

    impl Drop for IdleChildGuard {
        fn drop(&mut self) {
            let Some(child) = self.0.as_mut() else {
                return;
            };
            let _ = child.kill();
            let process = HANDLE(child.as_raw_handle());
            // SAFETY: the guard retains the Child process handle for this one
            // bounded best-effort failure-path wait. It calls Child::wait only
            // after the kernel reports the process signaled.
            if unsafe { WaitForSingleObject(process, CHILD_CLEANUP_TIMEOUT_MILLISECONDS) }
                == WAIT_OBJECT_0
            {
                let _ = child.wait();
            }
        }
    }

    fn native_handle(handle: &OwnedHandle) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    fn duplicate_same_access_observer(
        source_process: HANDLE,
        source_handle: HANDLE,
    ) -> Result<OwnedHandle, Box<dyn std::error::Error>> {
        let mut observer = HANDLE::default();
        // SAFETY: source_process identifies a retained live process, source_handle
        // is valid in that process, the current-process pseudo-handle is the exact
        // observer target, and successful output ownership is adopted immediately.
        unsafe {
            DuplicateHandle(
                source_process,
                source_handle,
                GetCurrentProcess(),
                &raw mut observer,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )?;
        }
        // `false` constrains only the fresh local observer's inherit flag. It
        // does not reveal the remote source slot's per-handle flags; the
        // production injection call separately pins remote noninheritance.
        if observer.is_invalid() {
            return Err("DuplicateHandle returned an invalid observer".into());
        }
        // SAFETY: successful DuplicateHandle returned one fresh current-process
        // handle and no owner has yet been constructed from the numeric value.
        Ok(unsafe { OwnedHandle::from_raw_handle(observer.0.cast::<c_void>()) })
    }

    fn duplicate_local_source_observer(
        source: BorrowedHandle<'_>,
    ) -> Result<OwnedHandle, Box<dyn std::error::Error>> {
        // SAFETY: this scalar pseudo-handle query has no caller-provided storage.
        let process = unsafe { GetCurrentProcess() };
        duplicate_same_access_observer(process, HANDLE(source.as_raw_handle()))
    }

    fn duplicate_remote_candidate_observer(
        target_process: BorrowedHandle<'_>,
        remote_word: u64,
    ) -> Result<OwnedHandle, Box<dyn std::error::Error>> {
        let remote = usize::try_from(remote_word)?;
        duplicate_same_access_observer(
            HANDLE(target_process.as_raw_handle()),
            HANDLE(remote as *mut c_void),
        )
    }

    fn native_granted_access(handle: &OwnedHandle) -> Result<u32, Box<dyn std::error::Error>> {
        let mut information = PUBLIC_OBJECT_BASIC_INFORMATION::default();
        let information_size = u32::try_from(size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>())?;
        let mut returned_length = 0_u32;
        // SAFETY: the observer owns one live handle and both output objects are
        // correctly sized writable storage. This native query is test-only.
        let status = unsafe {
            NtQueryObject(
                Some(native_handle(handle)),
                ObjectBasicInformation,
                Some((&raw mut information).cast()),
                information_size,
                Some(&raw mut returned_length),
            )
        };
        if status != STATUS_SUCCESS || returned_length != information_size {
            return Err("NtQueryObject did not return exact basic information".into());
        }
        Ok(information.GrantedAccess)
    }

    fn same_object(left: &OwnedHandle, right: &OwnedHandle) -> bool {
        // SAFETY: both observer owners retain live handles for the comparison.
        unsafe { CompareObjectHandles(native_handle(left), native_handle(right)) }.as_bool()
    }

    fn read_exact_from_observer(
        handle: &OwnedHandle,
        bytes: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut offset = 0;
        while offset < bytes.len() {
            let mut read = 0_u32;
            // SAFETY: the observer owns a synchronous pipe handle, the remaining
            // output slice and scalar count remain live, and no OVERLAPPED is used.
            unsafe {
                ReadFile(
                    native_handle(handle),
                    Some(&mut bytes[offset..]),
                    Some(&raw mut read),
                    None,
                )?;
            }
            let read = usize::try_from(read)?;
            if read == 0 || read > bytes.len() - offset {
                return Err("observer read made invalid progress".into());
            }
            offset += read;
        }
        Ok(())
    }

    fn write_all_to_observer(
        handle: &OwnedHandle,
        bytes: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut offset = 0;
        while offset < bytes.len() {
            let mut written = 0_u32;
            // SAFETY: the observer owns a synchronous pipe handle, the remaining
            // input slice and scalar count remain live, and no OVERLAPPED is used.
            unsafe {
                WriteFile(
                    native_handle(handle),
                    Some(&bytes[offset..]),
                    Some(&raw mut written),
                    None,
                )?;
            }
            let written = usize::try_from(written)?;
            if written == 0 || written > bytes.len() - offset {
                return Err("observer write made invalid progress".into());
            }
            offset += written;
        }
        Ok(())
    }

    fn assert_candidate_observers(
        source_request: &OwnedHandle,
        source_response: &OwnedHandle,
        candidate_request: &OwnedHandle,
        candidate_response: &OwnedHandle,
    ) -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(native_granted_access(source_request)?, CHILD_REQUEST_ACCESS);
        assert_eq!(
            native_granted_access(source_response)?,
            CHILD_RESPONSE_ACCESS
        );
        assert_eq!(
            native_granted_access(candidate_request)?,
            CHILD_REQUEST_ACCESS
        );
        assert_eq!(
            native_granted_access(candidate_response)?,
            CHILD_RESPONSE_ACCESS
        );
        // SAFETY: the observer owns a live handle for this scalar type query.
        let request_type = unsafe { GetFileType(native_handle(candidate_request)) };
        // SAFETY: the observer owns a live handle for this scalar type query.
        let response_type = unsafe { GetFileType(native_handle(candidate_response)) };
        assert_eq!(request_type, FILE_TYPE_PIPE);
        assert_eq!(response_type, FILE_TYPE_PIPE);
        assert!(same_object(source_request, candidate_request));
        assert!(same_object(source_response, candidate_response));
        assert!(!same_object(candidate_request, candidate_response));
        Ok(())
    }

    fn observer_deadline() -> Result<Instant, Box<dyn std::error::Error>> {
        Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| "observer deadline overflow".into())
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Event {
        Validate,
        Duplicate(u32),
        CloseRequest,
        CloseResponse,
        DropParent,
    }

    struct FakeParent {
        events: Rc<RefCell<Vec<Event>>>,
    }

    impl Drop for FakeParent {
        fn drop(&mut self) {
            self.events.borrow_mut().push(Event::DropParent);
        }
    }

    struct FakeBundle {
        request: LocalSourceHandleWord,
        response: LocalSourceHandleWord,
        validation_fails: bool,
        request_close_fails: bool,
        response_close_fails: bool,
        events: Rc<RefCell<Vec<Event>>>,
        parent: FakeParent,
    }

    impl FakeBundle {
        fn new(events: Rc<RefCell<Vec<Event>>>) -> Self {
            Self {
                request: LocalSourceHandleWord(0x101),
                response: LocalSourceHandleWord(0x202),
                validation_fails: false,
                request_close_fails: false,
                response_close_fails: false,
                parent: FakeParent {
                    events: Rc::clone(&events),
                },
                events,
            }
        }
    }

    impl PendingChannelBundle for FakeBundle {
        type Parent = FakeParent;

        fn revalidate_sources(&self) -> Result<(), ()> {
            self.events.borrow_mut().push(Event::Validate);
            if self.validation_fails {
                Err(())
            } else {
                Ok(())
            }
        }

        fn source_words(&self) -> Result<(LocalSourceHandleWord, LocalSourceHandleWord), ()> {
            Ok((self.request, self.response))
        }

        fn close_sources_checked(self) -> Result<Self::Parent, ()> {
            self.events.borrow_mut().push(Event::CloseRequest);
            let request_failed = self.request_close_fails;
            self.events.borrow_mut().push(Event::CloseResponse);
            let response_failed = self.response_close_fails;
            if request_failed || response_failed {
                drop(self.parent);
                Err(())
            } else {
                Ok(self.parent)
            }
        }
    }

    struct FakeDuplicateHandle {
        outputs: Vec<Result<usize, ()>>,
        calls: Vec<DuplicateCall>,
        events: Rc<RefCell<Vec<Event>>>,
    }

    impl FakeDuplicateHandle {
        fn new(
            outputs: impl IntoIterator<Item = Result<usize, ()>>,
            events: Rc<RefCell<Vec<Event>>>,
        ) -> Self {
            let mut outputs: Vec<_> = outputs.into_iter().collect();
            outputs.reverse();
            Self {
                outputs,
                calls: Vec::new(),
                events,
            }
        }
    }

    impl DuplicateHandleApi for FakeDuplicateHandle {
        fn duplicate_handle(&mut self, call: DuplicateCall) -> Result<usize, ()> {
            self.events
                .borrow_mut()
                .push(Event::Duplicate(call.desired_access));
            self.calls.push(call);
            self.outputs.pop().unwrap_or(Err(()))
        }
    }

    fn target() -> TargetProcessHandleWord {
        TargetProcessHandleWord(0x303)
    }

    fn expected_call(source: usize, desired_access: u32) -> DuplicateCall {
        DuplicateCall {
            source_process: DuplicateSourceProcess::Current,
            source_handle: LocalSourceHandleWord(source),
            target_process: target(),
            desired_access,
            inherit_handle: false,
            options: 0,
        }
    }

    #[test]
    fn success_uses_exactly_two_restricted_non_inheritable_calls()
    -> Result<(), ServiceChannelInjectionError> {
        let events = Rc::new(RefCell::new(Vec::new()));
        let bundle = FakeBundle::new(Rc::clone(&events));
        let mut api = FakeDuplicateHandle::new([Ok(0x404), Ok(0x505)], Rc::clone(&events));

        let (child, parent) = duplicate_channels(bundle, Ok(target()), &mut api)?;
        assert_eq!(api.calls.len(), 2);
        assert_eq!(
            api.calls,
            [
                expected_call(0x101, CHILD_REQUEST_ACCESS),
                expected_call(0x202, CHILD_RESPONSE_ACCESS),
            ]
        );
        let (request_register, response_register) = child.into_register_words();
        assert_eq!(request_register, 0x404);
        assert_eq!(response_register, 0x505);
        assert_eq!(
            *events.borrow(),
            [
                Event::Validate,
                Event::Duplicate(CHILD_REQUEST_ACCESS),
                Event::Duplicate(CHILD_RESPONSE_ACCESS),
                Event::CloseRequest,
                Event::CloseResponse,
            ]
        );
        drop(parent);
        assert_eq!(events.borrow().last(), Some(&Event::DropParent));
        Ok(())
    }

    #[test]
    fn each_duplicate_failure_prefix_closes_both_sources_and_parent() {
        for (outputs, expected_calls) in [
            (vec![Err(())], 1_usize),
            (vec![Ok(0x404), Err(())], 2_usize),
        ] {
            let events = Rc::new(RefCell::new(Vec::new()));
            let bundle = FakeBundle::new(Rc::clone(&events));
            let mut api = FakeDuplicateHandle::new(outputs, Rc::clone(&events));
            assert!(matches!(
                duplicate_channels(bundle, Ok(target()), &mut api),
                Err(ServiceChannelInjectionError::Duplication)
            ));
            assert_eq!(api.calls.len(), expected_calls);
            assert_eq!(
                events
                    .borrow()
                    .iter()
                    .filter(|event| **event == Event::CloseRequest)
                    .count(),
                1
            );
            assert_eq!(
                events
                    .borrow()
                    .iter()
                    .filter(|event| **event == Event::CloseResponse)
                    .count(),
                1
            );
            assert_eq!(events.borrow().last(), Some(&Event::DropParent));
        }
    }

    #[test]
    fn invalid_or_repeated_remote_words_fail_closed_without_local_ownership() {
        for outputs in [
            vec![Ok(0), Ok(0x505)],
            vec![Ok(usize::MAX), Ok(0x505)],
            vec![Ok(0x404), Ok(0x404)],
        ] {
            let events = Rc::new(RefCell::new(Vec::new()));
            let bundle = FakeBundle::new(Rc::clone(&events));
            let mut api = FakeDuplicateHandle::new(outputs, Rc::clone(&events));
            assert!(matches!(
                duplicate_channels(bundle, Ok(target()), &mut api),
                Err(ServiceChannelInjectionError::RemoteHandle)
            ));
            assert_eq!(events.borrow().last(), Some(&Event::DropParent));
        }

        #[cfg(target_pointer_width = "64")]
        {
            let events = Rc::new(RefCell::new(Vec::new()));
            let bundle = FakeBundle::new(Rc::clone(&events));
            let out_of_range = usize::try_from((i64::MAX as u64) + 1).unwrap_or(usize::MAX);
            let mut api = FakeDuplicateHandle::new([Ok(out_of_range)], Rc::clone(&events));
            assert!(matches!(
                duplicate_channels(bundle, Ok(target()), &mut api),
                Err(ServiceChannelInjectionError::RemoteHandle)
            ));
        }
    }

    #[test]
    fn validation_and_both_close_failure_shapes_are_terminal() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let bundle = FakeBundle::new(Rc::clone(&events));
        let mut api = FakeDuplicateHandle::new([], Rc::clone(&events));
        assert!(matches!(
            duplicate_channels(
                bundle,
                Err(ServiceChannelInjectionError::SourceValidation),
                &mut api,
            ),
            Err(ServiceChannelInjectionError::SourceValidation)
        ));
        assert!(api.calls.is_empty());
        assert_eq!(
            *events.borrow(),
            [Event::CloseRequest, Event::CloseResponse, Event::DropParent,]
        );

        let events = Rc::new(RefCell::new(Vec::new()));
        let mut invalid = FakeBundle::new(Rc::clone(&events));
        invalid.validation_fails = true;
        let mut api = FakeDuplicateHandle::new([], Rc::clone(&events));
        assert!(matches!(
            duplicate_channels(invalid, Ok(target()), &mut api),
            Err(ServiceChannelInjectionError::SourceValidation)
        ));
        assert!(api.calls.is_empty());
        assert_eq!(
            *events.borrow(),
            [
                Event::Validate,
                Event::CloseRequest,
                Event::CloseResponse,
                Event::DropParent,
            ]
        );

        for (request_fails, response_fails) in [(true, false), (false, true), (true, true)] {
            let events = Rc::new(RefCell::new(Vec::new()));
            let mut bundle = FakeBundle::new(Rc::clone(&events));
            bundle.request_close_fails = request_fails;
            bundle.response_close_fails = response_fails;
            let mut api = FakeDuplicateHandle::new([Ok(0x404), Ok(0x505)], Rc::clone(&events));
            assert!(matches!(
                duplicate_channels(bundle, Ok(target()), &mut api),
                Err(ServiceChannelInjectionError::SourceClose)
            ));
            assert_eq!(
                events
                    .borrow()
                    .iter()
                    .filter(|event| **event == Event::CloseRequest)
                    .count(),
                1
            );
            assert_eq!(
                events
                    .borrow()
                    .iter()
                    .filter(|event| **event == Event::CloseResponse)
                    .count(),
                1
            );
            assert_eq!(events.borrow().last(), Some(&Event::DropParent));
        }

        let events = Rc::new(RefCell::new(Vec::new()));
        let mut bundle = FakeBundle::new(Rc::clone(&events));
        bundle.validation_fails = true;
        bundle.request_close_fails = true;
        let mut api = FakeDuplicateHandle::new([], Rc::clone(&events));
        assert!(matches!(
            duplicate_channels(bundle, Ok(target()), &mut api),
            Err(ServiceChannelInjectionError::SourceClose)
        ));
        assert!(api.calls.is_empty());
        assert_eq!(events.borrow().last(), Some(&Event::DropParent));

        let events = Rc::new(RefCell::new(Vec::new()));
        let mut bundle = FakeBundle::new(Rc::clone(&events));
        bundle.response_close_fails = true;
        let mut api = FakeDuplicateHandle::new([Err(())], Rc::clone(&events));
        assert!(matches!(
            duplicate_channels(bundle, Ok(target()), &mut api),
            Err(ServiceChannelInjectionError::SourceClose)
        ));
        assert_eq!(api.calls.len(), 1);
        assert_eq!(events.borrow().last(), Some(&Event::DropParent));
    }

    trait AmbiguousIfClone<Marker> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<Marker> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    trait AmbiguousIfAsRawHandle<Marker> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfAsRawHandle<()> for T {}
    impl<T: ?Sized + AsRawHandle> AmbiguousIfAsRawHandle<u8> for T {}

    #[test]
    fn remote_words_are_move_only_non_handle_values_with_redacted_debug()
    -> Result<(), ServiceChannelInjectionError> {
        let _ = <RemoteChildHandleWord as AmbiguousIfClone<_>>::marker;
        let _ = <RemoteChildHandleWord as AmbiguousIfCopy<_>>::marker;
        let _ = <RemoteChildHandleWord as AmbiguousIfAsRawHandle<_>>::marker;
        let word = RemoteChildHandleWord::from_duplicate_result(0x404)?;
        assert_eq!(
            format!("{word:?}"),
            "RemoteChildHandleWord([REMOTE HANDLE])"
        );
        assert_eq!(
            format!("{:?}", expected_call(0x101, CHILD_REQUEST_ACCESS)),
            "DuplicateCall { source_process: Current, source_handle: \"[LOCAL HANDLE]\", target_process: \"[LOCAL HANDLE]\", desired_access: 1048577, inherit_handle: false, options: 0 }"
        );
        Ok(())
    }

    fn prove_approval_target_candidates() -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateApprovalPipes::create()?;
        let source_request = duplicate_local_source_observer(pipes.child_input())?;
        let source_response = duplicate_local_source_observer(pipes.child_output())?;
        let mut target = IdleChildGuard::spawn()?;
        let injected = duplicate_approval_channels_for_child(pipes, target.process_handle()?)?;
        let (remote, parent) = injected.into_parts();
        let (remote_request, remote_response) = remote.into_register_words();
        let candidate_request =
            duplicate_remote_candidate_observer(target.process_handle()?, remote_request)?;
        let candidate_response =
            duplicate_remote_candidate_observer(target.process_handle()?, remote_response)?;
        assert_candidate_observers(
            &source_request,
            &source_response,
            &candidate_request,
            &candidate_response,
        )?;

        assert!(write_all_to_observer(&candidate_request, b"wrong request direction").is_err());
        let mut wrong_response_direction = [0_u8; 1];
        assert!(
            read_exact_from_observer(&candidate_response, &mut wrong_response_direction).is_err()
        );

        let (request_writer, response_reader) = parent.into_parts();
        let request = [0x71_u8; 32];
        request_writer.write_all(&request, observer_deadline()?)?;
        let mut observed_request = [0_u8; 32];
        read_exact_from_observer(&candidate_request, &mut observed_request)?;
        assert_eq!(observed_request, request);

        let response = [0x72_u8; 32];
        write_all_to_observer(&candidate_response, &response)?;
        assert_eq!(
            response_reader
                .read_exact(response.len(), observer_deadline()?)?
                .as_slice(),
            response
        );
        target.terminate_and_reap()
    }

    fn prove_secret_input_target_candidates() -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateSecretInputPipes::create()?;
        let source_request = duplicate_local_source_observer(pipes.child_input())?;
        let source_response = duplicate_local_source_observer(pipes.child_output())?;
        let mut target = IdleChildGuard::spawn()?;
        let injected = duplicate_secret_input_channels_for_child(pipes, target.process_handle()?)?;
        let (remote, parent) = injected.into_parts();
        let (remote_request, remote_response) = remote.into_register_words();
        let candidate_request =
            duplicate_remote_candidate_observer(target.process_handle()?, remote_request)?;
        let candidate_response =
            duplicate_remote_candidate_observer(target.process_handle()?, remote_response)?;
        assert_candidate_observers(
            &source_request,
            &source_response,
            &candidate_request,
            &candidate_response,
        )?;

        assert!(write_all_to_observer(&candidate_request, b"wrong request direction").is_err());
        let mut wrong_response_direction = [0_u8; 1];
        assert!(
            read_exact_from_observer(&candidate_response, &mut wrong_response_direction).is_err()
        );

        let (request_writer, response_reader) = parent.into_parts();
        let request = [0x73_u8; 32];
        request_writer.write_all(&request, observer_deadline()?)?;
        let mut observed_request = [0_u8; 32];
        read_exact_from_observer(&candidate_request, &mut observed_request)?;
        assert_eq!(observed_request, request);

        let response = [0x74_u8; 32];
        write_all_to_observer(&candidate_response, &response)?;
        assert_eq!(
            response_reader
                .read_exact(response.len(), observer_deadline()?)?
                .as_slice(),
            response
        );
        target.terminate_and_reap()
    }

    #[test]
    #[ignore = "cross-process NtQueryObject service-channel kernel-matrix evidence only"]
    fn kernel_matrix_cross_process_service_channel_candidates_have_exact_authority_and_direction()
    -> Result<(), Box<dyn std::error::Error>> {
        prove_approval_target_candidates()?;
        prove_secret_input_target_candidates()
    }

    #[test]
    #[ignore = "launched only as the service-channel idle target process"]
    fn service_channel_idle_child_fixture() -> Result<(), Box<dyn std::error::Error>> {
        if std::env::var_os(IDLE_CHILD_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
            return Ok(());
        }
        let mut release = [0_u8; 1];
        std::io::stdin().read_exact(&mut release)?;
        Ok(())
    }

    #[test]
    fn role_typed_results_are_distinct() {
        assert_ne!(
            core::any::type_name::<InjectedApprovalChannels>(),
            core::any::type_name::<InjectedSecretInputChannels>()
        );
    }
}
