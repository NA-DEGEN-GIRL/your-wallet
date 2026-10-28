#![allow(unsafe_code)]
//! Named pipes between yw-host and yw-app (spec/01 §7.5, spec/05 §7.8, §8.1, D24).
//!
//! Both ends open the pipe with `FILE_FLAG_OVERLAPPED` and every read, write and connect uses its
//! own `OVERLAPPED` with a manual-reset event, waited with `GetOverlappedResult(wait = TRUE)`: on
//! a synchronous handle a pending `ReadFile` blocks another thread's `WriteFile` (synchronous file
//! objects serialize I/O), which would make a full-duplex relay impossible. The two halves of a
//! connection share one handle through an `Arc`; the last one dropped closes it with plain
//! `CloseHandle` (no `DisconnectNamedPipe`, which would discard data the peer has not read yet,
//! e.g. a final hello-reject). `DisconnectNamedPipe` is used only to reuse an instance whose client
//! left before the connect completed.
//!
//! Security and creation flags follow
//! `archive/spec-v2.4:crates/platform-windows/src/broker_channel.rs:505-558` (SDDL →
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW`, `LocalFree`) and `:889-918`
//! (`create_server`), except for the name: it is fixed per user (`YourWallet.v3.<SID>`), never
//! random, and the instance limit is 4. Because the name is predictable, both ends check who owns
//! the pipe object: the client reads the owner of its handle ([`Duplex::owner_sid`]) and refuses a
//! server that another user created, and the server compares the security of every later instance
//! with the first one (created with `FILE_FLAG_FIRST_PIPE_INSTANCE`) and closes an instance that
//! joined a pipe someone else created after all of ours had closed.

use core::ffi::c_void;
use core::fmt;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Weak};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND,
    ERROR_INVALID_HANDLE, ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_OPERATION_ABORTED,
    ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, GENERIC_READ, GENERIC_WRITE,
    HANDLE, INVALID_HANDLE_VALUE, LocalFree, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
    DACL_SECURITY_INFORMATION, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
    PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_WAIT, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, INFINITE, ResetEvent, SetEvent, WaitForMultipleObjects,
};

use crate::error::WinError;
use crate::process::sid_to_string;
use crate::wide::to_wide;

/// `nMaxInstances` (one connection per Chrome profile, spec/05 §8.1).
const MAX_INSTANCES: u32 = 4;
/// Input and output buffer size of each instance.
const BUFFER_BYTES: u32 = 65_536;
/// `nDefaultTimeOut` (used by `WaitNamedPipeW` with `NMPWAIT_USE_DEFAULT_WAIT`).
const DEFAULT_TIMEOUT_MS: u32 = 1_000;
/// Retry delay after `CreateNamedPipeW` reported `ERROR_PIPE_BUSY` below the instance limit.
const BUSY_RETRY_MS: u32 = 100;

/// `\\.\pipe\YourWallet.v3.<SID>` (D24).
#[must_use]
pub fn wallet_pipe_name(user_sid: &str) -> String {
    format!(r"\\.\pipe\YourWallet.v3.{user_sid}")
}

/// `O:<SID>D:P(A;;GA;;;<SID>)`: owner = the user, protected DACL with one allow-all ACE for the
/// user (spec/05 §8.1).
#[must_use]
pub fn user_only_sddl(user_sid: &str) -> String {
    format!("O:{user_sid}D:P(A;;GA;;;{user_sid})")
}

fn last_code(api: &'static str) -> u32 {
    WinError::last(api).code
}

fn os_error(code: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::from_ne_bytes(code.to_ne_bytes()))
}

fn clamp_len(length: usize) -> u32 {
    u32::try_from(length).unwrap_or(u32::MAX)
}

/// A kernel handle closed on drop.
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    const fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: The handle was returned to us by the OS and is closed exactly once here.
        unsafe { CloseHandle(self.0) };
    }
}

// SAFETY: A kernel handle value may be used and closed from any thread.
unsafe impl Send for OwnedHandle {}
// SAFETY: Every operation on the handle goes through thread-safe kernel calls.
unsafe impl Sync for OwnedHandle {}

/// An unnamed event with default security.
struct Event(OwnedHandle);

impl Event {
    fn new(manual_reset: bool) -> Result<Self, WinError> {
        // SAFETY: Default security, no name; both flags are plain values.
        let handle = unsafe {
            CreateEventW(
                core::ptr::null(),
                i32::from(manual_reset),
                0,
                core::ptr::null(),
            )
        };
        if handle.is_null() {
            return Err(WinError::last("CreateEventW"));
        }
        Ok(Self(OwnedHandle(handle)))
    }

    const fn raw(&self) -> HANDLE {
        self.0.raw()
    }

    fn set(&self) {
        // SAFETY: `self` owns a live event handle.
        unsafe { SetEvent(self.raw()) };
    }

    fn reset(&self) {
        // SAFETY: `self` owns a live event handle.
        unsafe { ResetEvent(self.raw()) };
    }
}

/// `WaitForMultipleObjects(any)`: `Ok(Some(index))` of the signaled handle, `Ok(None)` on timeout.
fn wait_any(handles: &[HANDLE], timeout_ms: u32) -> Result<Option<usize>, WinError> {
    let count = u32::try_from(handles.len())
        .map_err(|_| WinError::invalid_argument("WaitForMultipleObjects"))?;
    // SAFETY: `handles` holds `count` live event handles for the duration of the call.
    let result = unsafe { WaitForMultipleObjects(count, handles.as_ptr(), 0, timeout_ms) };
    if result == WAIT_FAILED {
        return Err(WinError::last("WaitForMultipleObjects"));
    }
    if result == WAIT_TIMEOUT {
        return Ok(None);
    }
    usize::try_from(result.wrapping_sub(WAIT_OBJECT_0))
        .ok()
        .filter(|&index| index < handles.len())
        .map(Some)
        .ok_or(WinError::new("WaitForMultipleObjects", result))
}

/// Runs one overlapped operation started by `start` and waits for it on `event`.
///
/// Returns the transferred byte count or the Win32 error code. The `OVERLAPPED` lives in this
/// frame and the function returns only after the operation is complete, so the kernel never
/// writes to it after it goes out of scope. When `cancelled` is already set after the operation
/// was queued, the operation is cancelled here (closes the race with [`PipeCanceller::cancel`]).
fn overlapped_io(
    handle: HANDLE,
    event: &Event,
    cancelled: &AtomicBool,
    start: impl FnOnce(*mut OVERLAPPED) -> i32,
) -> Result<u32, u32> {
    event.reset();
    let mut overlapped = OVERLAPPED {
        hEvent: event.raw(),
        ..OVERLAPPED::default()
    };
    if start(&raw mut overlapped) == 0 {
        let code = last_code("overlapped I/O");
        if code != ERROR_IO_PENDING {
            return Err(code);
        }
        if cancelled.load(Ordering::SeqCst) {
            // SAFETY: Cancels only this pending operation on a live handle; completion is still
            // awaited below.
            unsafe { CancelIoEx(handle, &raw const overlapped) };
        }
    }
    let mut transferred = 0_u32;
    // SAFETY: `overlapped` describes an operation started on `handle` (pending or completed);
    // waiting with bWait = TRUE keeps it alive and in place until the operation is complete.
    let ok = unsafe { GetOverlappedResult(handle, &raw const overlapped, &raw mut transferred, 1) };
    if ok == 0 {
        return Err(last_code("GetOverlappedResult"));
    }
    Ok(transferred)
}

/// Server bookkeeping: connected instances and an auto-reset event signaled when one closes.
struct Slots {
    active: AtomicU32,
    freed: Event,
}

impl Slots {
    fn active(&self) -> u32 {
        self.active.load(Ordering::SeqCst)
    }
}

/// One counted server connection; dropping it releases the slot.
struct Slot(Arc<Slots>);

impl Slot {
    fn acquire(slots: &Arc<Slots>) -> Self {
        slots.active.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(slots))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::SeqCst);
        self.0.freed.set();
    }
}

/// The handle shared by both halves of a connection. Dropping it closes the handle without
/// `DisconnectNamedPipe`, so the peer still reads every byte written before the close (then EOF).
struct PipeShared {
    // Field order matters: the handle closes before the slot is released, so the server never
    // exceeds the instance limit when it creates the next instance.
    handle: OwnedHandle,
    slot: Option<Slot>,
    cancelled: AtomicBool,
}

/// A connected pipe (either end). Split it into a reader and a writer for full-duplex use.
pub struct Duplex {
    shared: Arc<PipeShared>,
    read_event: Event,
    write_event: Event,
}

impl fmt::Debug for Duplex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Duplex")
            .field("server_side", &self.shared.slot.is_some())
            .finish_non_exhaustive()
    }
}

impl Duplex {
    fn new(handle: OwnedHandle, slot: Option<Slot>) -> Result<Self, WinError> {
        let read_event = Event::new(true)?;
        let write_event = Event::new(true)?;
        Ok(Self {
            shared: Arc::new(PipeShared {
                handle,
                slot,
                cancelled: AtomicBool::new(false),
            }),
            read_event,
            write_event,
        })
    }

    /// Splits into independent halves; a read blocked in one thread never blocks a write in
    /// another. The handle closes when both halves (and any upgraded canceller) are dropped.
    #[must_use]
    pub fn split(self) -> (PipeReader, PipeWriter) {
        (
            PipeReader {
                shared: Arc::clone(&self.shared),
                event: self.read_event,
            },
            PipeWriter {
                shared: self.shared,
                event: self.write_event,
            },
        )
    }

    /// `GetNamedPipeServerProcessId`.
    #[must_use]
    pub fn server_pid(&self) -> Option<u32> {
        let mut pid = 0_u32;
        // SAFETY: Live pipe handle and a writable `pid`.
        let ok = unsafe { GetNamedPipeServerProcessId(self.shared.handle.raw(), &raw mut pid) };
        (ok != 0 && pid != 0).then_some(pid)
    }

    /// `GetNamedPipeClientProcessId` (for logs only, spec/05 §8.1).
    #[must_use]
    pub fn client_pid(&self) -> Option<u32> {
        let mut pid = 0_u32;
        // SAFETY: Live pipe handle and a writable `pid`.
        let ok = unsafe { GetNamedPipeClientProcessId(self.shared.handle.raw(), &raw mut pid) };
        (ok != 0 && pid != 0).then_some(pid)
    }

    /// The owner SID string of the pipe object behind this end
    /// (`GetSecurityInfo(SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION)` on the handle). On the
    /// client side this is the owner the *server* gave the pipe: a process of another user cannot
    /// make it this user's SID (that needs `SeRestorePrivilege`), so it identifies a squatter on
    /// the predictable per-user name (spec/05 §8.1).
    ///
    /// # Errors
    ///
    /// The failing call's [`WinError`] (e.g. the handle lacks `READ_CONTROL`).
    pub fn owner_sid(&self) -> Result<String, WinError> {
        query_security(self.shared.handle.raw(), false).map(|summary| summary.owner)
    }

    /// Whether the pipe object is owned by the user running this process: [`Self::owner_sid`]
    /// equals [`crate::current_user_sid_string`] ([`owner_is`]; any failure is `false`).
    #[must_use]
    pub fn owned_by_current_user(&self) -> bool {
        owner_is(self.owner_sid(), crate::current_user_sid_string())
    }
}

/// `true` only when both SIDs were read, the owner is not empty and both strings are equal (the
/// owner check of [`Duplex::owned_by_current_user`], separated so callers can inject the
/// expected SID).
#[must_use]
pub fn owner_is(owner: Result<String, WinError>, expected: Result<String, WinError>) -> bool {
    matches!((owner, expected), (Ok(owner), Ok(expected)) if !owner.is_empty() && owner == expected)
}

/// The reading half. `ERROR_BROKEN_PIPE`, `ERROR_PIPE_NOT_CONNECTED` and a 0-byte read are EOF
/// (`Ok(0)`); a cancelled read fails with `ERROR_OPERATION_ABORTED`.
pub struct PipeReader {
    shared: Arc<PipeShared>,
    event: Event,
}

impl fmt::Debug for PipeReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PipeReader").finish_non_exhaustive()
    }
}

impl PipeReader {
    /// A handle that aborts this connection's I/O from another thread.
    #[must_use]
    pub fn cancel_handle(&self) -> PipeCanceller {
        PipeCanceller(Arc::downgrade(&self.shared))
    }
}

impl io::Read for PipeReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.shared.cancelled.load(Ordering::SeqCst) {
            return Err(os_error(ERROR_OPERATION_ABORTED));
        }
        let handle = self.shared.handle.raw();
        let length = clamp_len(buffer.len());
        let pointer = buffer.as_mut_ptr();
        let result = overlapped_io(handle, &self.event, &self.shared.cancelled, |overlapped| {
            // SAFETY: `pointer` is writable for `length` bytes and `buffer` stays mutably borrowed
            // until `overlapped_io` returns after completion; `overlapped` is live and in place.
            unsafe { ReadFile(handle, pointer, length, core::ptr::null_mut(), overlapped) }
        });
        match result {
            Ok(count) => usize::try_from(count).map_err(|_| io::ErrorKind::InvalidData.into()),
            Err(ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => Ok(0),
            Err(code) => Err(os_error(code)),
        }
    }
}

/// The writing half. `flush` does nothing: a completed write is in the pipe.
pub struct PipeWriter {
    shared: Arc<PipeShared>,
    event: Event,
}

impl fmt::Debug for PipeWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PipeWriter").finish_non_exhaustive()
    }
}

impl io::Write for PipeWriter {
    /// A cancelled connection ([`PipeCanceller::cancel`]) fails with `ERROR_OPERATION_ABORTED`,
    /// whether the cancel came before the write started or while it was pending.
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.shared.cancelled.load(Ordering::SeqCst) {
            return Err(os_error(ERROR_OPERATION_ABORTED));
        }
        let handle = self.shared.handle.raw();
        let length = clamp_len(buffer.len());
        let pointer = buffer.as_ptr();
        let result = overlapped_io(handle, &self.event, &self.shared.cancelled, |overlapped| {
            // SAFETY: `pointer` is readable for `length` bytes and `buffer` stays borrowed until
            // `overlapped_io` returns after completion; `overlapped` is live and in place.
            unsafe { WriteFile(handle, pointer, length, core::ptr::null_mut(), overlapped) }
        });
        match result {
            Ok(count) => usize::try_from(count).map_err(|_| io::ErrorKind::InvalidData.into()),
            Err(code) => Err(os_error(code)),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Aborts a connection's I/O: `cancel()` = `CancelIoEx(handle, NULL)`, which completes every
/// pending read and write on the shared handle with `ERROR_OPERATION_ABORTED`; later reads and
/// writes fail at once. Holds no strong reference, so it never keeps the connection open.
#[derive(Clone)]
pub struct PipeCanceller(Weak<PipeShared>);

impl fmt::Debug for PipeCanceller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PipeCanceller")
            .finish_non_exhaustive()
    }
}

impl PipeCanceller {
    /// Cancels pending and future reads and writes of the connection, if it is open.
    pub fn cancel(&self) {
        if let Some(shared) = self.0.upgrade() {
            shared.cancelled.store(true, Ordering::SeqCst);
            // SAFETY: Live handle (held by `shared`); a null OVERLAPPED cancels all of this
            // process's I/O on it.
            unsafe { CancelIoEx(shared.handle.raw(), core::ptr::null()) };
        }
    }
}

/// `connect_client` failure (spec/05 §7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectError {
    /// `ERROR_FILE_NOT_FOUND`: no server instance exists.
    NotFound,
    /// `ERROR_PIPE_BUSY`: every instance is connected; `wait` then retry.
    Busy,
    /// Any other Win32 error code.
    Other(u32),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => formatter.write_str("pipe not found"),
            Self::Busy => formatter.write_str("pipe busy"),
            Self::Other(code) => write!(formatter, "pipe connect failed: 0x{code:08X}"),
        }
    }
}

impl std::error::Error for ConnectError {}

/// Opens the client end: `CreateFileW(GENERIC_READ | GENERIC_WRITE, no sharing, OPEN_EXISTING,
/// FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION)`.
///
/// # Errors
///
/// [`ConnectError`].
pub fn connect_client(name: &str) -> Result<Duplex, ConnectError> {
    let wide = to_wide(name, "CreateFileW").map_err(|error| ConnectError::Other(error.code))?;
    // SAFETY: `wide` is NUL-terminated and live; no security attributes or template handle.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            core::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            core::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(match last_code("CreateFileW") {
            ERROR_FILE_NOT_FOUND => ConnectError::NotFound,
            ERROR_PIPE_BUSY => ConnectError::Busy,
            code => ConnectError::Other(code),
        });
    }
    Duplex::new(OwnedHandle(handle), None).map_err(|error| ConnectError::Other(error.code))
}

/// `WaitNamedPipeW(name, timeout_ms)`: whether an instance became available. `0` is treated as
/// 1 ms (Win32 would use the server's default timeout instead).
#[must_use]
pub fn wait(name: &str, timeout_ms: u32) -> bool {
    let Ok(wide) = to_wide(name, "WaitNamedPipeW") else {
        return false;
    };
    // SAFETY: `wide` is NUL-terminated and live; the timeout is a plain value.
    let ok = unsafe { WaitNamedPipeW(wide.as_ptr(), timeout_ms.max(1)) };
    ok != 0
}

/// `Server` failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerError {
    /// The first instance could not be created (`ERROR_ACCESS_DENIED`): another server (another
    /// yw-app) owns the name. Also returned by `accept` when a later instance turned out to belong
    /// to a pipe with another owner or DACL (someone created the name after all of this server's
    /// instances had closed); that instance is closed at once.
    AlreadyExists,
    /// [`ServerStop::stop`] was called.
    Stopped,
    /// A Win32 call failed.
    Os(WinError),
}

impl fmt::Display for ServerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => formatter.write_str("pipe server already exists"),
            Self::Stopped => formatter.write_str("pipe server stopped"),
            Self::Os(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ServerError {}

/// A security descriptor from `ConvertStringSecurityDescriptorToSecurityDescriptorW`, freed with
/// `LocalFree`.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self, WinError> {
        const API: &str = "ConvertStringSecurityDescriptorToSecurityDescriptorW";
        let wide = to_wide(sddl, API)?;
        let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
        // SAFETY: `wide` is NUL-terminated and live; `descriptor` is a writable out pointer; the
        // size output is not requested.
        let ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &raw mut descriptor,
                core::ptr::null_mut(),
            )
        };
        if ok == 0 || descriptor.is_null() {
            return Err(WinError::last(API));
        }
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        // SAFETY: Allocated by the SDDL conversion (LocalAlloc); freed exactly once here.
        unsafe { LocalFree(self.0) };
    }
}

// SAFETY: The descriptor is an immutable LocalAlloc buffer owned exclusively by this value; it is
// only read by `CreateNamedPipeW` and may be freed from any thread.
unsafe impl Send for SecurityDescriptor {}

/// A buffer returned by `GetSecurityInfo`, freed with `LocalFree`.
struct LocalBuffer(*mut c_void);

impl Drop for LocalBuffer {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Allocated by `GetSecurityInfo` (LocalAlloc); freed exactly once here.
            unsafe { LocalFree(self.0) };
        }
    }
}

fn create_instance(
    name: &[u16],
    security: &SecurityDescriptor,
    first: bool,
) -> Result<OwnedHandle, WinError> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(core::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| WinError::invalid_argument("CreateNamedPipeW"))?,
        lpSecurityDescriptor: security.0,
        bInheritHandle: 0,
    };
    let open_mode = PIPE_ACCESS_DUPLEX
        | FILE_FLAG_OVERLAPPED
        | if first {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    // SAFETY: `name` is NUL-terminated and live; `attributes` points at a live descriptor; the
    // API does not retain either pointer.
    let handle = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            MAX_INSTANCES,
            BUFFER_BYTES,
            BUFFER_BYTES,
            DEFAULT_TIMEOUT_MS,
            &raw const attributes,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(WinError::last("CreateNamedPipeW"));
    }
    Ok(OwnedHandle(handle))
}

struct StopState {
    stopped: AtomicBool,
    event: Event,
}

/// Stops a [`Server`]: a blocked or later [`Server::accept`] returns [`ServerError::Stopped`].
#[derive(Clone)]
pub struct ServerStop(Arc<StopState>);

impl fmt::Debug for ServerStop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerStop")
            .field("stopped", &self.0.stopped.load(Ordering::SeqCst))
            .finish()
    }
}

impl ServerStop {
    /// Signals the stop event (idempotent). The waiting instance is closed by `accept`.
    pub fn stop(&self) {
        self.0.stopped.store(true, Ordering::SeqCst);
        self.0.event.set();
    }
}

/// One ACE of a [`SecuritySummary`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AceSummary {
    /// `ACE_HEADER.AceType` (0 = `ACCESS_ALLOWED_ACE_TYPE`).
    pub ace_type: u8,
    /// The access mask as stored on the object (generic rights are mapped).
    pub mask: u32,
    /// The trustee SID string; empty for ACE types without a plain SID.
    pub sid: String,
}

/// Owner and DACL of the waiting pipe instance, from `GetSecurityInfo` (R-P2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecuritySummary {
    /// The owner SID string.
    pub owner: String,
    /// `SE_DACL_PROTECTED` is set (no inherited ACEs).
    pub dacl_protected: bool,
    /// The DACL entries in order.
    pub aces: Vec<AceSummary>,
}

enum Connect {
    Connected,
    Retry,
    Stopped,
    Failed(WinError),
}

/// The pipe server (spec/05 §8.1): one waiting instance, at most 4 connected.
pub struct Server {
    name: Vec<u16>,
    security: SecurityDescriptor,
    /// Owner and DACL read back from the first instance; every later instance must match.
    expected: SecuritySummary,
    listening: Option<OwnedHandle>,
    connect_event: Event,
    slots: Arc<Slots>,
    stop: Arc<StopState>,
}

impl fmt::Debug for Server {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Server")
            .field("listening", &self.listening.is_some())
            .field("active", &self.slots.active())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Converts `sddl` and creates the first instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`:
    /// `PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED`, `PIPE_TYPE_BYTE | PIPE_READMODE_BYTE |
    /// PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS`, 4 instances, 65,536-byte buffers, 1,000 ms
    /// default timeout, non-inheritable.
    ///
    /// # Errors
    ///
    /// [`ServerError::AlreadyExists`] on `ERROR_ACCESS_DENIED`, otherwise [`ServerError::Os`].
    pub fn create(name: &str, sddl: &str) -> Result<Self, ServerError> {
        let name = to_wide(name, "CreateNamedPipeW").map_err(ServerError::Os)?;
        let security = SecurityDescriptor::from_sddl(sddl).map_err(ServerError::Os)?;
        let first = create_instance(&name, &security, true).map_err(|error| {
            if error.code == ERROR_ACCESS_DENIED {
                ServerError::AlreadyExists
            } else {
                ServerError::Os(error)
            }
        })?;
        // The first instance created the pipe, so its security is ours (read back once).
        let expected = query_security(first.raw(), true).map_err(ServerError::Os)?;
        Ok(Self {
            name,
            security,
            expected,
            listening: Some(first),
            connect_event: Event::new(true).map_err(ServerError::Os)?,
            slots: Arc::new(Slots {
                active: AtomicU32::new(0),
                freed: Event::new(false).map_err(ServerError::Os)?,
            }),
            stop: Arc::new(StopState {
                stopped: AtomicBool::new(false),
                event: Event::new(true).map_err(ServerError::Os)?,
            }),
        })
    }

    /// A handle that makes a blocked or later `accept` return [`ServerError::Stopped`].
    #[must_use]
    pub fn stop_handle(&self) -> ServerStop {
        ServerStop(Arc::clone(&self.stop))
    }

    /// Blocks until a client connects (overlapped `ConnectNamedPipe`; `ERROR_PIPE_CONNECTED` is
    /// success). Afterwards the next waiting instance is created while fewer than 4 connections
    /// are active; with 4 active, the next `accept` waits until a connection closes (both halves
    /// of its `Duplex` dropped) before creating one, and clients meanwhile get `ERROR_PIPE_BUSY`.
    /// Every later instance is checked against the first one's owner and DACL (see
    /// [`ServerError::AlreadyExists`]).
    ///
    /// # Errors
    ///
    /// [`ServerError::Stopped`] after [`ServerStop::stop`], [`ServerError::AlreadyExists`] for an
    /// instance of a foreign pipe, or [`ServerError::Os`].
    pub fn accept(&mut self) -> Result<Duplex, ServerError> {
        loop {
            if self.stop.stopped.load(Ordering::SeqCst) {
                self.listening = None;
                return Err(ServerError::Stopped);
            }
            let Some(instance) = self.listening.take() else {
                self.listening = Some(self.next_instance()?);
                continue;
            };
            match self.connect(&instance) {
                Connect::Connected => {
                    let slot = Slot::acquire(&self.slots);
                    let duplex = Duplex::new(instance, Some(slot)).map_err(ServerError::Os)?;
                    if self.slots.active() < MAX_INSTANCES {
                        // A failure here is retried (and reported) by the next `accept`.
                        self.listening = self.create_later().ok();
                    }
                    return Ok(duplex);
                }
                Connect::Retry => {
                    // The client left before the connect completed: reuse the instance.
                    // SAFETY: Live server instance handle owned by `instance`.
                    unsafe { DisconnectNamedPipe(instance.raw()) };
                    self.listening = Some(instance);
                }
                Connect::Stopped => return Err(ServerError::Stopped),
                Connect::Failed(error) => return Err(ServerError::Os(error)),
            }
        }
    }

    /// Creates a non-first instance and checks that it belongs to this server's pipe: its owner
    /// and DACL (shared by all instances of a pipe) must equal the first instance's. Without the
    /// check, an instance created after all of ours had closed could join a pipe another user
    /// created under the same name in between. A mismatching instance is closed here.
    fn create_later(&self) -> Result<OwnedHandle, ServerError> {
        let instance = create_instance(&self.name, &self.security, false).map_err(|error| {
            if error.code == ERROR_ACCESS_DENIED {
                ServerError::AlreadyExists
            } else {
                ServerError::Os(error)
            }
        })?;
        match query_security(instance.raw(), true) {
            Ok(summary) if summary == self.expected => Ok(instance),
            Ok(_) => Err(ServerError::AlreadyExists),
            Err(error) => Err(ServerError::Os(error)),
        }
    }

    /// Creates a non-first instance once fewer than 4 connections are active.
    fn next_instance(&self) -> Result<OwnedHandle, ServerError> {
        loop {
            let mut timeout = INFINITE;
            if self.slots.active() < MAX_INSTANCES {
                match self.create_later() {
                    Ok(instance) => return Ok(instance),
                    Err(ServerError::Os(error)) if error.code == ERROR_PIPE_BUSY => {
                        timeout = BUSY_RETRY_MS;
                    }
                    Err(error) => return Err(error),
                }
            }
            match wait_any(&[self.stop.event.raw(), self.slots.freed.raw()], timeout) {
                Ok(Some(0)) => return Err(ServerError::Stopped),
                Ok(_) => {}
                Err(error) => return Err(ServerError::Os(error)),
            }
        }
    }

    fn connect(&self, instance: &OwnedHandle) -> Connect {
        self.connect_event.reset();
        let mut overlapped = OVERLAPPED {
            hEvent: self.connect_event.raw(),
            ..OVERLAPPED::default()
        };
        // SAFETY: Live server instance; `overlapped` stays in place until the operation is
        // complete (awaited below on every pending path).
        let ok = unsafe { ConnectNamedPipe(instance.raw(), &raw mut overlapped) };
        if ok != 0 {
            return Connect::Connected;
        }
        match last_code("ConnectNamedPipe") {
            ERROR_PIPE_CONNECTED => return Connect::Connected,
            ERROR_NO_DATA => return Connect::Retry,
            ERROR_IO_PENDING => {}
            code => return Connect::Failed(WinError::new("ConnectNamedPipe", code)),
        }
        let waited = wait_any(&[self.connect_event.raw(), self.stop.event.raw()], INFINITE);
        if !matches!(waited, Ok(Some(0))) {
            // SAFETY: Cancels this pending connect on a live handle; completion is awaited below.
            unsafe { CancelIoEx(instance.raw(), &raw const overlapped) };
        }
        let mut transferred = 0_u32;
        // SAFETY: Waits until the connect (completed, failed or cancelled) is done, so the kernel
        // no longer references `overlapped` when this frame returns.
        let done = unsafe {
            GetOverlappedResult(
                instance.raw(),
                &raw const overlapped,
                &raw mut transferred,
                1,
            )
        };
        let code = (done == 0).then(|| last_code("ConnectNamedPipe"));
        match waited {
            Ok(Some(0)) => match code {
                None | Some(ERROR_PIPE_CONNECTED) => Connect::Connected,
                Some(ERROR_NO_DATA | ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED) => {
                    Connect::Retry
                }
                Some(code) => Connect::Failed(WinError::new("ConnectNamedPipe", code)),
            },
            Ok(_) => Connect::Stopped,
            Err(error) => Connect::Failed(error),
        }
    }

    /// Owner, DACL protection and ACEs of the waiting instance (`GetSecurityInfo(SE_KERNEL_OBJECT,
    /// OWNER | DACL)` + `GetSecurityDescriptorControl`), for the R-P2 DACL check.
    ///
    /// # Errors
    ///
    /// `ERROR_INVALID_HANDLE` when no instance is waiting (4 connected or stopped), or the
    /// failing call's [`WinError`].
    pub fn security_summary(&self) -> Result<SecuritySummary, WinError> {
        let instance = self
            .listening
            .as_ref()
            .ok_or(WinError::new("GetSecurityInfo", ERROR_INVALID_HANDLE))?;
        query_security(instance.raw(), true)
    }
}

/// `GetSecurityInfo(handle, SE_KERNEL_OBJECT, OWNER [| DACL])` + `GetSecurityDescriptorControl`.
/// Without `with_dacl` only the owner is read (`dacl_protected` is then `false`, `aces` empty).
fn query_security(handle: HANDLE, with_dacl: bool) -> Result<SecuritySummary, WinError> {
    let mut owner: PSID = core::ptr::null_mut();
    let mut dacl: *mut ACL = core::ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut();
    let info = if with_dacl {
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
    } else {
        OWNER_SECURITY_INFORMATION
    };
    let dacl_out: *mut *mut ACL = if with_dacl {
        &raw mut dacl
    } else {
        core::ptr::null_mut()
    };
    // SAFETY: `handle` is a live pipe handle owned by the caller; every requested out pointer is
    // writable (the DACL one is null when the DACL is not requested); group and SACL are not
    // requested.
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            info,
            &raw mut owner,
            core::ptr::null_mut(),
            dacl_out,
            core::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(WinError::new("GetSecurityInfo", status));
    }
    let descriptor = LocalBuffer(descriptor);
    let mut control = 0_u16;
    let mut revision = 0_u32;
    // SAFETY: `descriptor` is the live descriptor returned above; outputs are writable.
    let ok =
        unsafe { GetSecurityDescriptorControl(descriptor.0, &raw mut control, &raw mut revision) };
    if ok == 0 {
        return Err(WinError::last("GetSecurityDescriptorControl"));
    }
    let owner = if owner.is_null() {
        String::new()
    } else {
        // SAFETY: `owner` points into `descriptor`, which is alive.
        unsafe { sid_to_string(owner) }?
    };
    let aces = if dacl.is_null() {
        Vec::new()
    } else {
        // SAFETY: `dacl` points into `descriptor`, which is alive.
        unsafe { read_aces(dacl) }?
    };
    Ok(SecuritySummary {
        owner,
        dacl_protected: with_dacl && control & SE_DACL_PROTECTED != 0,
        aces,
    })
}

/// The ACEs of `dacl`.
///
/// # Safety
///
/// `dacl` must point to a valid ACL that stays alive for the call.
unsafe fn read_aces(dacl: *const ACL) -> Result<Vec<AceSummary>, WinError> {
    let mut info = ACL_SIZE_INFORMATION::default();
    let size = u32::try_from(core::mem::size_of::<ACL_SIZE_INFORMATION>())
        .map_err(|_| WinError::invalid_argument("GetAclInformation"))?;
    // SAFETY: The caller guarantees `dacl`; `info` is writable for `size` bytes.
    let ok = unsafe { GetAclInformation(dacl, (&raw mut info).cast(), size, AclSizeInformation) };
    if ok == 0 {
        return Err(WinError::last("GetAclInformation"));
    }
    let header_len = core::mem::size_of::<ACE_HEADER>();
    let sid_offset = core::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let mut aces = Vec::new();
    for index in 0..info.AceCount {
        let mut ace: *mut c_void = core::ptr::null_mut();
        // SAFETY: `index < AceCount` of the valid ACL; `ace` is a writable out pointer.
        let ok = unsafe { GetAce(dacl, index, &raw mut ace) };
        if ok == 0 || ace.is_null() {
            return Err(WinError::last("GetAce"));
        }
        // SAFETY: `ace` points at an ACE inside the ACL; every ACE starts with an ACE_HEADER.
        let header = unsafe { ace.cast::<ACE_HEADER>().read_unaligned() };
        let ace_len = usize::from(header.AceSize);
        let mask = if ace_len >= header_len.saturating_add(4) {
            // SAFETY: The ACE is at least header + 4 bytes; the mask follows the header.
            unsafe {
                ace.cast::<u8>()
                    .wrapping_add(header_len)
                    .cast::<u32>()
                    .read_unaligned()
            }
        } else {
            0
        };
        // Types 0–3 (allowed, denied, audit, alarm) share the {header, mask, SID} layout.
        let sid = if header.AceType <= 3 && ace_len > sid_offset {
            // SAFETY: For these ACE types a SID starts at `SidStart`, inside the ACE.
            unsafe { sid_to_string(ace.cast::<u8>().wrapping_add(sid_offset).cast()) }?
        } else {
            String::new()
        };
        aces.push(AceSummary {
            ace_type: header.AceType,
            mask,
            sid,
        });
    }
    Ok(aces)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::{Server, ServerError, owner_is, user_only_sddl, wallet_pipe_name};
    use crate::error::WinError;

    static NEXT: AtomicU32 = AtomicU32::new(0);

    fn unique_name() -> String {
        format!(
            r"\\.\pipe\YourWallet.test.unit.{}.{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        )
    }

    #[test]
    fn owner_check_needs_two_equal_readable_sids() {
        let sid = || Ok::<_, WinError>("S-1-5-21-1-2-3-1001".to_owned());
        assert!(owner_is(sid(), sid()));
        assert!(!owner_is(sid(), Ok("S-1-5-21-1-2-3-1002".to_owned())));
        assert!(!owner_is(Ok(String::new()), Ok(String::new())));
        assert!(!owner_is(Err(WinError::new("GetSecurityInfo", 5)), sid()));
        assert!(!owner_is(sid(), Err(WinError::new("OpenProcessToken", 5))));
    }

    /// All of the server's instances closed and another server took the name: the next instance
    /// joins that pipe (same name), so its security differs from the first instance's and it is
    /// closed instead of being offered to clients. The "squatter" here is the same user with a
    /// wider DACL; a real one also has another owner.
    #[test]
    fn a_later_instance_of_a_foreign_pipe_is_refused() -> Result<(), Box<dyn std::error::Error>> {
        let sid = crate::current_user_sid_string()?;
        let name = unique_name();
        let mut server = Server::create(&name, &user_only_sddl(&sid))?;
        server.listening = None;
        let squatter = Server::create(&name, &format!("O:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;WD)"))?;
        assert_ne!(squatter.security_summary()?, server.expected);
        assert!(matches!(server.accept(), Err(ServerError::AlreadyExists)));
        assert!(server.listening.is_none());
        drop(squatter);
        // The name is free again: the server recreates a verified instance.
        assert!(server.create_later().is_ok());
        Ok(())
    }

    #[test]
    fn pipe_name_and_sddl_follow_d24() {
        let sid = "S-1-5-21-1-2-3-1001";
        assert_eq!(
            wallet_pipe_name(sid),
            "\\\\.\\pipe\\YourWallet.v3.S-1-5-21-1-2-3-1001"
        );
        assert_eq!(
            user_only_sddl(sid),
            "O:S-1-5-21-1-2-3-1001D:P(A;;GA;;;S-1-5-21-1-2-3-1001)"
        );
    }
}
