//! Narrow Rust surface over checked-in classic-MIDL x64 RPC stubs.
//!
//! This crate owns only the fixed NDR frame and the generated interface
//! specifications. Binding creation, authentication, explicit security
//! descriptors, per-call authorization, listening, and orderly RPC shutdown
//! remain the responsibility of the Windows platform layer.
//!
//! On non-Windows targets the API compiles but returns unavailable and exposes
//! no interface specification.

#![deny(unsafe_op_in_unsafe_fn)]

use core::{ffi::c_void, fmt, marker::PhantomData, ptr::NonNull};

#[cfg(any(windows, test))]
use std::panic;
#[cfg(windows)]
use std::sync::OnceLock;

/// Maximum number of bytes transported inside one RPC frame.
pub const RPC_FRAME_CAPACITY: usize = 72;
/// Exact in-memory size of the fixed NDR frame on Windows x64.
pub const RPC_FRAME_SIZE: usize = 76;
/// Interface UUID in canonical RFC 4122 byte order.
pub const INTERFACE_UUID: [u8; 16] = [
    0x4c, 0xb7, 0xf9, 0x5a, 0x26, 0x97, 0x4f, 0x96, 0xbd, 0x29, 0x56, 0xe4, 0xb9, 0x78, 0x74, 0x8a,
];
/// Major MIDL interface version.
pub const INTERFACE_VERSION_MAJOR: u16 = 1;
/// Minor MIDL interface version.
pub const INTERFACE_VERSION_MINOR: u16 = 0;
/// Fixed, non-secret local-RPC endpoint name for version 1.
pub const LOCAL_RPC_ENDPOINT: &str = "YourWallet.KeyAgentService.v1";
/// NUL-terminated UTF-16 form of [`LOCAL_RPC_ENDPOINT`].
pub const LOCAL_RPC_ENDPOINT_WIDE: &[u16] = &[
    0x0059, 0x006f, 0x0075, 0x0072, 0x0057, 0x0061, 0x006c, 0x006c, 0x0065, 0x0074, 0x002e, 0x004b,
    0x0065, 0x0079, 0x0041, 0x0067, 0x0065, 0x006e, 0x0074, 0x0053, 0x0065, 0x0072, 0x0076, 0x0069,
    0x0063, 0x0065, 0x002e, 0x0076, 0x0031, 0x0000,
];

#[cfg(windows)]
const RPC_S_OK: u32 = 0;
#[cfg(any(windows, test))]
const RPC_S_INVALID_ARG: u32 = 87;
#[cfg(windows)]
const RPC_S_ALREADY_REGISTERED: u32 = 1_711;
const RPC_S_SERVER_UNAVAILABLE: u32 = 1_722;
#[cfg(windows)]
const RPC_X_BAD_STUB_DATA: u32 = 1_783;

/// A bounded frame transported by the sole RPC operation.
///
/// Payload bytes are intentionally omitted from `Debug` output.
#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RpcFrame {
    length: u32,
    payload: [u8; RPC_FRAME_CAPACITY],
}

impl RpcFrame {
    /// Creates an empty, fully zeroed frame.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            length: 0,
            payload: [0; RPC_FRAME_CAPACITY],
        }
    }

    /// Copies a bounded payload into a zero-padded fixed frame.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::PayloadTooLarge`] when `payload` exceeds 72 bytes.
    pub fn from_payload(payload: &[u8]) -> Result<Self, FrameError> {
        if payload.len() > RPC_FRAME_CAPACITY {
            return Err(FrameError::PayloadTooLarge);
        }

        let mut frame = Self::empty();
        frame.payload[..payload.len()].copy_from_slice(payload);
        frame.length = u32::try_from(payload.len()).map_err(|_| FrameError::PayloadTooLarge)?;
        Ok(frame)
    }

    /// Returns the initialized payload length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.length as usize
    }

    /// Returns whether this frame carries no payload bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    /// Borrows exactly the initialized payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.len()]
    }

    /// Returns whether length and zero padding form a canonical fixed frame.
    #[must_use]
    pub fn is_canonical(&self) -> bool {
        let length = self.length as usize;
        length <= RPC_FRAME_CAPACITY && self.payload[length..].iter().all(|byte| *byte == 0)
    }
}

impl Default for RpcFrame {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Debug for RpcFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RpcFrame")
            .field("length", &self.length)
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

/// Validation failure while constructing a fixed frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    /// The input exceeded [`RPC_FRAME_CAPACITY`].
    PayloadTooLarge,
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RPC frame payload exceeds 72 bytes")
    }
}

impl std::error::Error for FrameError {}

/// A raw Win32 RPC status returned without allowing RPC SEH into Rust.
#[repr(transparent)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RpcStatus(u32);

impl RpcStatus {
    /// Generic local-RPC unavailability status.
    pub const UNAVAILABLE: Self = Self(RPC_S_SERVER_UNAVAILABLE);

    /// Returns the Win32 RPC status code.
    #[must_use]
    pub const fn code(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for RpcStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("RpcStatus").field(&self.0).finish()
    }
}

impl fmt::Display for RpcStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Windows RPC status {}", self.0)
    }
}

impl std::error::Error for RpcStatus {}

/// Borrowed, process-static MIDL interface specification.
#[repr(transparent)]
#[derive(Clone, Copy)]
pub struct InterfaceSpec(NonNull<c_void>);

impl InterfaceSpec {
    /// Returns the `RPC_IF_HANDLE` value accepted by Rpcrt4 registration APIs.
    #[must_use]
    pub const fn as_raw(self) -> *mut c_void {
        self.0.as_ptr()
    }
}

impl fmt::Debug for InterfaceSpec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InterfaceSpec(..)")
    }
}

/// Borrowed RPC binding handle used by the generated client stub.
#[repr(transparent)]
pub struct BindingHandle(NonNull<c_void>);

impl BindingHandle {
    /// Wraps a live `RPC_BINDING_HANDLE` without taking ownership.
    ///
    /// # Safety
    ///
    /// `raw` must be a valid, non-null RPC binding for the duration of every
    /// call using the returned value. The owner must not concurrently free it.
    #[must_use]
    pub unsafe fn from_raw(raw: *mut c_void) -> Option<Self> {
        NonNull::new(raw).map(Self)
    }

    /// Returns the borrowed raw binding handle.
    #[must_use]
    pub const fn as_raw(&self) -> *mut c_void {
        self.0.as_ptr()
    }
}

impl fmt::Debug for BindingHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BindingHandle(..)")
    }
}

/// Non-owning server-side binding valid only for the active manager call.
///
/// This type is intentionally distinct from [`BindingHandle`], is neither
/// `Copy` nor `Clone`, and cannot be constructed publicly. Authentication and
/// call-attribute queries must complete before the handler returns.
pub struct CallBinding<'call> {
    raw: NonNull<c_void>,
    call_lifetime: PhantomData<&'call mut c_void>,
}

impl CallBinding<'_> {
    /// Borrows the opaque server call binding for a Win32 RPC query.
    ///
    /// # Safety
    ///
    /// The returned pointer must not be freed, copied into longer-lived state,
    /// or used after the handler returns. It is valid only for synchronous
    /// per-call authentication, impersonation, and call-attribute APIs.
    #[must_use]
    pub unsafe fn as_raw(&self) -> *mut c_void {
        self.raw.as_ptr()
    }
}

impl fmt::Debug for CallBinding<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CallBinding(..)")
    }
}

/// Closed set of fail-closed server manager outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagerError {
    /// Authentication, authorization, replay, epoch, or binding checks failed
    /// (`RPC_S_ACCESS_DENIED`).
    AccessDenied,
    /// Outer-frame or wire-format input was malformed (`RPC_S_INVALID_ARG`).
    InvalidArgument,
    /// The bounded service call set is full (`RPC_S_SERVER_TOO_BUSY`).
    ServerTooBusy,
    /// Service startup or stopping state rejects new work (`RPC_S_SERVER_UNAVAILABLE`).
    ServerUnavailable,
    /// An internal call failed without a more specific safe result (`RPC_S_CALL_FAILED`).
    CallFailed,
}

impl ManagerError {
    #[cfg(any(windows, test))]
    const fn rpc_status(self) -> RpcStatus {
        let code = match self {
            Self::AccessDenied => 5,
            Self::InvalidArgument => RPC_S_INVALID_ARG,
            Self::ServerTooBusy => 1_723,
            Self::ServerUnavailable => RPC_S_SERVER_UNAVAILABLE,
            Self::CallFailed => 1_726,
        };
        RpcStatus(code)
    }
}

/// Process-lifetime server callback for the single Exchange operation.
///
/// Application-level unavailable responses should normally be encoded in the
/// returned frame. The higher-ranked call lifetime prevents safe retention of
/// [`CallBinding`] beyond the synchronous callback.
pub type ExchangeHandler =
    for<'call> fn(CallBinding<'call>, &'call RpcFrame) -> Result<RpcFrame, ManagerError>;

/// Failure to install the one-shot server callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallError {
    /// This target does not provide the Windows x64 RPC implementation.
    PlatformUnavailable,
    /// A callback was already installed or an earlier install attempt consumed
    /// the process-lifetime one-shot.
    AlreadyInstalled,
    /// The native registration shim rejected the callback.
    Native(RpcStatus),
}

impl fmt::Display for InstallError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlatformUnavailable => formatter.write_str("Windows x64 RPC is unavailable"),
            Self::AlreadyInstalled => {
                formatter.write_str("RPC manager callback is already installed")
            }
            Self::Native(status) => write!(formatter, "RPC manager install failed: {status}"),
        }
    }
}

impl std::error::Error for InstallError {}

/// Returns the generated client interface specification on Windows x64.
#[must_use]
pub fn client_interface_spec() -> Option<InterfaceSpec> {
    platform::client_interface_spec()
}

/// Returns the generated server interface specification on Windows x64.
#[must_use]
pub fn server_interface_spec() -> Option<InterfaceSpec> {
    platform::server_interface_spec()
}

/// Calls the sole generated client operation through the SEH boundary shim.
///
/// # Errors
///
/// Returns the exact Win32 RPC communication/fault status. The response is
/// discarded on every nonzero or malformed result.
pub fn exchange(binding: &BindingHandle, request: &RpcFrame) -> Result<RpcFrame, RpcStatus> {
    platform::exchange(binding, request)
}

/// Installs the process-lifetime server callback exactly once.
///
/// There is deliberately no uninstall API. The service must stop listening,
/// unregister the interface with call draining, and wait for RPC rundown before
/// process exit; keeping this function pointer permanent prevents callback UAF.
///
/// # Errors
///
/// Returns [`InstallError::AlreadyInstalled`] for all later attempts, including
/// after a native failure, so registration fails closed rather than retrying
/// through uncertain native state.
pub fn install_server_handler(handler: ExchangeHandler) -> Result<(), InstallError> {
    platform::install_server_handler(handler)
}

#[cfg(any(windows, test))]
fn invoke_handler<'call>(
    handler: ExchangeHandler,
    binding: CallBinding<'call>,
    request: &'call RpcFrame,
) -> Result<RpcFrame, RpcStatus> {
    match panic::catch_unwind(panic::AssertUnwindSafe(|| handler(binding, request))) {
        Ok(Ok(response)) if response.is_canonical() => Ok(response),
        Ok(Ok(_)) => Err(ManagerError::InvalidArgument.rpc_status()),
        Ok(Err(error)) => Err(error.rpc_status()),
        Err(_) => Err(ManagerError::CallFailed.rpc_status()),
    }
}

#[cfg(windows)]
mod platform {
    use super::{
        BindingHandle, CallBinding, ExchangeHandler, InstallError, InterfaceSpec, NonNull,
        OnceLock, PhantomData, RPC_S_ALREADY_REGISTERED, RPC_S_INVALID_ARG, RPC_S_OK,
        RPC_S_SERVER_UNAVAILABLE, RPC_X_BAD_STUB_DATA, RpcFrame, RpcStatus, c_void, invoke_handler,
    };

    #[cfg(not(all(target_arch = "x86_64", target_env = "msvc")))]
    compile_error!("key-agent-service-rpc-sys supports only Windows x64 MSVC in Phase 1");

    static HANDLER: OnceLock<ExchangeHandler> = OnceLock::new();

    unsafe extern "system" fn dispatch_trampoline(
        call_binding: *mut c_void,
        request: *const RpcFrame,
        response: *mut RpcFrame,
    ) -> u32 {
        let Some(raw_call_binding) = NonNull::new(call_binding) else {
            return RPC_S_INVALID_ARG;
        };
        if request.is_null() || response.is_null() {
            return RPC_S_INVALID_ARG;
        }

        // SAFETY: the C manager validates both fixed-frame pointers before it
        // invokes this process-lifetime callback. Copying isolates the handler
        // from the RPC runtime's input storage.
        let request = unsafe { request.read() };
        // SAFETY: response is non-null and points to the C manager's local,
        // writable fixed frame for the duration of this callback.
        unsafe { response.write(RpcFrame::empty()) };

        if !request.is_canonical() {
            return RPC_S_INVALID_ARG;
        }

        let Some(handler) = HANDLER.get().copied() else {
            return RPC_S_SERVER_UNAVAILABLE;
        };

        let call_binding = CallBinding {
            raw: raw_call_binding,
            call_lifetime: PhantomData,
        };
        match invoke_handler(handler, call_binding, &request) {
            Ok(candidate) => {
                // SAFETY: response remains the validated C-owned output frame.
                unsafe { response.write(candidate) };
                RPC_S_OK
            }
            Err(status) => status.code(),
        }
    }

    pub(super) fn client_interface_spec() -> Option<InterfaceSpec> {
        // SAFETY: the checked-in client stub owns a process-static ifspec.
        NonNull::new(unsafe { ffi::ywkas_rpc_client_ifspec() }).map(InterfaceSpec)
    }

    pub(super) fn server_interface_spec() -> Option<InterfaceSpec> {
        // SAFETY: the checked-in server stub owns a process-static ifspec.
        NonNull::new(unsafe { ffi::ywkas_rpc_server_ifspec() }).map(InterfaceSpec)
    }

    pub(super) fn exchange(
        binding: &BindingHandle,
        request: &RpcFrame,
    ) -> Result<RpcFrame, RpcStatus> {
        let mut response = RpcFrame::empty();
        // SAFETY: BindingHandle's constructor contract keeps the binding live;
        // the C shim validates both fixed frames and contains RPC SEH.
        let status = unsafe {
            ffi::ywkas_rpc_client_exchange(
                binding.as_raw(),
                core::ptr::from_ref(request),
                core::ptr::from_mut(&mut response),
            )
        };

        if status != RPC_S_OK {
            return Err(RpcStatus(status));
        }
        if !response.is_canonical() {
            return Err(RpcStatus(RPC_X_BAD_STUB_DATA));
        }
        Ok(response)
    }

    pub(super) fn install_server_handler(handler: ExchangeHandler) -> Result<(), InstallError> {
        if HANDLER.set(handler).is_err() {
            return Err(InstallError::AlreadyInstalled);
        }

        // SAFETY: dispatch_trampoline is a process-static system-ABI function;
        // the native shim stores it once and deliberately never unregisters it.
        let status = unsafe { ffi::ywkas_rpc_install_server_handler(dispatch_trampoline) };
        match status {
            RPC_S_OK => Ok(()),
            RPC_S_ALREADY_REGISTERED => Err(InstallError::AlreadyInstalled),
            code => Err(InstallError::Native(RpcStatus(code))),
        }
    }

    mod ffi {
        use super::{RpcFrame, c_void};

        unsafe extern "C" {
            pub(super) fn ywkas_rpc_client_ifspec() -> *mut c_void;
            pub(super) fn ywkas_rpc_server_ifspec() -> *mut c_void;
            pub(super) fn ywkas_rpc_client_exchange(
                binding: *mut c_void,
                request: *const RpcFrame,
                response: *mut RpcFrame,
            ) -> u32;
            pub(super) fn ywkas_rpc_install_server_handler(
                handler: unsafe extern "system" fn(
                    *mut c_void,
                    *const RpcFrame,
                    *mut RpcFrame,
                ) -> u32,
            ) -> u32;
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::{BindingHandle, ExchangeHandler, InstallError, InterfaceSpec, RpcFrame, RpcStatus};

    pub(super) const fn client_interface_spec() -> Option<InterfaceSpec> {
        None
    }

    pub(super) const fn server_interface_spec() -> Option<InterfaceSpec> {
        None
    }

    pub(super) fn exchange(
        _binding: &BindingHandle,
        _request: &RpcFrame,
    ) -> Result<RpcFrame, RpcStatus> {
        Err(RpcStatus::UNAVAILABLE)
    }

    pub(super) fn install_server_handler(_handler: ExchangeHandler) -> Result<(), InstallError> {
        Err(InstallError::PlatformUnavailable)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(windows))]
    use super::{
        BindingHandle, InstallError, client_interface_spec, exchange, install_server_handler,
        server_interface_spec,
    };
    use super::{
        CallBinding, FrameError, ManagerError, NonNull, PhantomData, RPC_FRAME_CAPACITY,
        RPC_FRAME_SIZE, RpcFrame, RpcStatus, c_void, invoke_handler,
    };
    #[cfg(windows)]
    use super::{InstallError, install_server_handler};

    fn echo(_binding: CallBinding<'_>, request: &RpcFrame) -> Result<RpcFrame, ManagerError> {
        if request.is_canonical() {
            Ok(*request)
        } else {
            Err(ManagerError::InvalidArgument)
        }
    }

    fn unavailable(
        _binding: CallBinding<'_>,
        _request: &RpcFrame,
    ) -> Result<RpcFrame, ManagerError> {
        Err(ManagerError::ServerUnavailable)
    }

    fn panics(_binding: CallBinding<'_>, _request: &RpcFrame) -> Result<RpcFrame, ManagerError> {
        std::panic::resume_unwind(Box::new("test panic must be contained"))
    }

    fn test_call_binding<'call>() -> CallBinding<'call> {
        CallBinding {
            raw: NonNull::<u8>::dangling().cast::<c_void>(),
            call_lifetime: PhantomData,
        }
    }

    #[test]
    fn frame_layout_is_exact() {
        assert_eq!(core::mem::size_of::<RpcFrame>(), RPC_FRAME_SIZE);
        assert_eq!(core::mem::align_of::<RpcFrame>(), 4);
    }

    #[test]
    fn bounded_constructor_zero_pads() {
        let result = RpcFrame::from_payload(&[1, 2, 3]);
        assert!(result.is_ok());
        if let Ok(frame) = result {
            assert_eq!(frame.payload(), &[1, 2, 3]);
            assert!(frame.payload[3..].iter().all(|byte| *byte == 0));
        }
        assert_eq!(
            RpcFrame::from_payload(&[0; RPC_FRAME_CAPACITY + 1]),
            Err(FrameError::PayloadTooLarge)
        );
    }

    #[test]
    fn handler_cannot_mutate_the_request() {
        let request_result = RpcFrame::from_payload(&[7; RPC_FRAME_CAPACITY]);
        assert!(request_result.is_ok());
        if let Ok(request) = request_result {
            let before = request;
            let response = invoke_handler(echo, test_call_binding(), &request);
            assert_eq!(request, before);
            assert_eq!(response, Ok(before));
        }
    }

    #[test]
    fn handler_failure_and_panic_are_fail_closed() {
        let request = RpcFrame::empty();
        assert_eq!(
            invoke_handler(unavailable, test_call_binding(), &request),
            Err(RpcStatus::UNAVAILABLE)
        );
        assert_eq!(
            invoke_handler(panics, test_call_binding(), &request),
            Err(ManagerError::CallFailed.rpc_status())
        );
    }

    #[test]
    fn manager_errors_map_to_only_the_five_approved_statuses() {
        let mappings = [
            (ManagerError::AccessDenied, 5),
            (ManagerError::InvalidArgument, 87),
            (ManagerError::ServerTooBusy, 1_723),
            (ManagerError::ServerUnavailable, 1_722),
            (ManagerError::CallFailed, 1_726),
        ];

        for (error, expected) in mappings {
            assert_eq!(error.rpc_status().code(), expected);
        }
    }

    #[test]
    fn nonzero_unused_tail_is_noncanonical() {
        let mut payload = [0; RPC_FRAME_CAPACITY];
        payload[RPC_FRAME_CAPACITY - 1] = 1;
        let malformed = RpcFrame { length: 1, payload };
        assert!(!malformed.is_canonical());
    }

    #[cfg(windows)]
    #[test]
    fn server_handler_install_is_process_lifetime_one_shot() {
        assert_eq!(install_server_handler(echo), Ok(()));
        assert_eq!(
            install_server_handler(echo),
            Err(InstallError::AlreadyInstalled)
        );
    }

    #[test]
    fn debug_never_displays_payload_bytes() {
        let result = RpcFrame::from_payload(b"private-frame-content");
        assert!(result.is_ok());
        if let Ok(frame) = result {
            let debug = format!("{frame:?}");
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("private-frame-content"));
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_surface_is_inert() {
        let raw = NonNull::<u8>::dangling().as_ptr().cast::<c_void>();
        // SAFETY: non-Windows exchange never dereferences or passes the inert
        // sentinel to a platform API.
        let binding = unsafe { BindingHandle::from_raw(raw) };
        let request = RpcFrame::from_payload(b"unchanged");
        assert!(binding.is_some());
        assert!(request.is_ok());
        if let (Some(binding), Ok(request)) = (binding, request) {
            let before = request;
            assert_eq!(exchange(&binding, &request), Err(RpcStatus::UNAVAILABLE));
            assert_eq!(request, before);
        }
        assert!(client_interface_spec().is_none());
        assert!(server_interface_spec().is_none());
        assert_eq!(
            install_server_handler(echo),
            Err(InstallError::PlatformUnavailable)
        );
    }
}
