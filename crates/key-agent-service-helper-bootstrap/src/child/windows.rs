//! Sole unsafe Windows leaf for injected-channel capture and ownership.

use core::ffi::c_void;
use core::fmt;
#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
use std::os::windows::io::IntoRawHandle;
use std::os::windows::io::{FromRawHandle, OwnedHandle};

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
use key_agent_service_rpc_sys::{BindingHandle, RpcFrame};
#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
use key_agent_service_wire::debug_v2::{
    self as wire_v2, HelperReadyRequest, ServiceRequest, ServiceResponse,
};
use windows::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, DUPLICATE_HANDLE_OPTIONS, DuplicateHandle, FILETIME,
    GetHandleInformation, HANDLE,
};
use windows::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType, ReadFile, WriteFile};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
use windows::Win32::System::Rpc::{
    RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, RPC_C_OPT_CALL_TIMEOUT, RPC_STATUS, RpcBindingFree,
    RpcBindingFromStringBindingW, RpcBindingSetAuthInfoW, RpcBindingSetOption,
    RpcStringBindingComposeW, RpcStringFreeW,
};
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetProcessTimes};
#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
use windows::core::{PCWSTR, PWSTR};
use zeroize::Zeroizing;

use crate::gate_spec::{
    ADOPTION_COMPLETE_R10_MARKER, ADOPTION_COMPLETE_R11_MARKER, REQUEST_INPUT_MARKER,
    RESPONSE_OUTPUT_MARKER,
};
use crate::wire::{
    HELPER_ADOPTION_ACK_BYTES, HELPER_BOOTSTRAP_HELLO_BYTES, HELPER_RPC_CONFIRMATION_BYTES,
    HelperAdoptionAck, HelperBootstrapHello, HelperBootstrapRole, HelperRpcConfirmation,
};

const REQUEST_INPUT_DUPLICATE_ACCESS: u32 = 0x0010_0001;
const RESPONSE_OUTPUT_DUPLICATE_ACCESS: u32 = 0x0010_0002;
const DUPLICATE_OPTIONS_NONE: u32 = 0;
const EXPECTED_HANDLE_FLAGS: u32 = 0;
const EXPECTED_FILE_TYPE: u32 = FILE_TYPE_PIPE.0;
const MAX_BOOTSTRAP_WINDOW_MILLISECONDS: u64 = 5_000;
#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
const LOCAL_RPC_PROTOCOL_SEQUENCE_WIDE: [u16; 8] = [110, 99, 97, 108, 114, 112, 99, 0];
#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
const RPC_AUTHN_LEVEL_PACKET_PRIVACY: u32 = 6;

/// Fixed capture gate authenticated and edited by the service debugger.
///
/// On entry the ordinary Windows x64 ABI places the two valid output pointers
/// in `rcx` and `rdx`. The parent authenticates the exact marker instructions
/// and breakpoint, substitutes the two candidate handle words in `r10` and
/// `r11`, and continues at the following stores. Both transport registers are
/// cleared before returning to ordinary Rust code.
#[unsafe(naked)]
unsafe extern "C" fn injected_channel_capture_gate(
    _request_input: *mut u64,
    _response_output: *mut u64,
) {
    core::arch::naked_asm!(
        "movabs r10, {request_input_marker}",
        "movabs r11, {response_output_marker}",
        "int3",
        "mov [rcx], r10",
        "mov [rdx], r11",
        "xor r10d, r10d",
        "xor r11d, r11d",
        "ret",
        request_input_marker = const REQUEST_INPUT_MARKER,
        response_output_marker = const RESPONSE_OUTPUT_MARKER,
    );
}

/// Independent gate proving that identity checks and the acknowledgement have
/// completed while the parent debugger still controls child resumption.
#[unsafe(naked)]
unsafe extern "C" fn injected_channel_adoption_complete_gate() {
    core::arch::naked_asm!(
        "movabs r10, {r10_marker}",
        "movabs r11, {r11_marker}",
        "int3",
        "xor r10d, r10d",
        "xor r11d, r11d",
        "ret",
        r10_marker = const ADOPTION_COMPLETE_R10_MARKER,
        r11_marker = const ADOPTION_COMPLETE_R11_MARKER,
    );
}

#[inline(never)]
fn capture_candidate_words() -> [u64; 2] {
    let mut request_input = 0_u64;
    let mut response_output = 0_u64;
    // SAFETY: both pointers name independent, initialized stack locals that
    // remain valid for the complete call. The gate writes exactly one `u64`
    // through each pointer and otherwise touches no Rust-owned memory.
    unsafe {
        injected_channel_capture_gate(&raw mut request_input, &raw mut response_output);
    }
    [request_input, response_output]
}

#[inline(never)]
fn enter_adoption_complete_gate() {
    // SAFETY: this leaf has no Rust-level inputs or outputs. Its only purpose
    // is the authenticated debugger breakpoint; after the debugger continues,
    // it clears both marker registers before returning normally.
    unsafe {
        injected_channel_adoption_complete_gate();
    }
}

/// Windows-owned half of the opaque public adoption proof.
pub(super) struct AdoptedInjectedChannels {
    request_input: FreshHandle,
    response_output: FreshHandle,
    source_access_and_direction: UnverifiedSourceAccessAndDirection,
}

impl fmt::Debug for AdoptedInjectedChannels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AdoptedInjectedChannels([OWNED PIPE HANDLES])")
    }
}

pub(super) fn capture_and_adopt_injected_channels() -> Result<AdoptedInjectedChannels, ()> {
    let [request_input, response_output] = capture_candidate_words();
    let mut operations = WindowsHandleOperations;
    let (request_input, response_output) =
        adopt_candidate_words(&mut operations, request_input, response_output)?;
    Ok(AdoptedInjectedChannels {
        request_input,
        response_output,
        source_access_and_direction: UnverifiedSourceAccessAndDirection,
    })
}

/// Windows-owned half of opaque ownership after bootstrap completion.
pub(super) struct BootstrappedInjectedChannels {
    _request_input: FreshHandle,
    _response_output: FreshHandle,
    _source_access_and_direction: UnverifiedSourceAccessAndDirection,
    _helper_rpc_correlation: RetainedHelperRpcCorrelation,
}

impl fmt::Debug for BootstrappedInjectedChannels {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BootstrappedInjectedChannels([OWNED PIPE HANDLES])")
    }
}

pub(super) fn complete_injected_channel_bootstrap(
    channels: AdoptedInjectedChannels,
    expected_role: HelperBootstrapRole,
) -> Result<BootstrappedInjectedChannels, ()> {
    let request_input = channels.request_input.word();
    let response_output = channels.response_output.word();
    let mut operations = WindowsBootstrapOperations;
    let helper_rpc_correlation = complete_bootstrap_with_operations(
        &mut operations,
        request_input,
        response_output,
        expected_role,
    )?;

    Ok(BootstrappedInjectedChannels {
        _request_input: channels.request_input,
        _response_output: channels.response_output,
        _source_access_and_direction: channels.source_access_and_direction,
        _helper_rpc_correlation: helper_rpc_correlation,
    })
}

/// Opaque, zeroizing continuation state for the later helper RPC round trip.
///
/// The encoded correlation key is retained instead of reconstructing it from
/// ambient process state. The absolute deadline is likewise kept private: it
/// is neither cloneable nor available through a raw accessor. The debug-only
/// RPC transition borrows it only to create and verify the exact `HelperReady`
/// exchange, then releases it before entering the terminal request-pipe wait.
/// Expected-peer registry classification remains the sole server-side role
/// authority.
struct RetainedHelperRpcCorrelation {
    confirmation_frame: Zeroizing<[u8; HELPER_RPC_CONFIRMATION_BYTES]>,
    deadline_tick_count_ms: Zeroizing<u64>,
}

impl RetainedHelperRpcCorrelation {
    fn from_hello(hello: &HelperBootstrapHello) -> Result<Self, ()> {
        let retained = Self {
            confirmation_frame: Zeroizing::new(
                HelperRpcConfirmation::new(hello.epoch_nonce(), hello.request_id(), hello.role())
                    .encode(),
            ),
            deadline_tick_count_ms: Zeroizing::new(hello.deadline_tick_count_ms().get()),
        };
        if retained.exactly_matches_hello(hello) {
            Ok(retained)
        } else {
            Err(())
        }
    }

    fn confirmation(&self) -> Result<HelperRpcConfirmation, ()> {
        HelperRpcConfirmation::decode(self.confirmation_frame.as_slice()).map_err(|_| ())
    }

    fn exactly_matches_hello(&self, hello: &HelperBootstrapHello) -> bool {
        self.confirmation().is_ok_and(|confirmation| {
            confirmation
                .ensure_correlates_with(hello.epoch_nonce(), hello.request_id(), hello.role())
                .is_ok()
                && *self.deadline_tick_count_ms == hello.deadline_tick_count_ms().get()
        })
    }

    #[cfg(test)]
    fn is_live_at_for_test(&self, tick_count_ms: u64) -> bool {
        tick_count_ms < *self.deadline_tick_count_ms
    }
}

impl fmt::Debug for RetainedHelperRpcCorrelation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RetainedHelperRpcCorrelation([REDACTED])")
    }
}

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
pub(super) fn complete_helper_ready_rpc_probe(
    channels: BootstrappedInjectedChannels,
    expected_role: HelperBootstrapRole,
) -> ! {
    let BootstrappedInjectedChannels {
        _request_input: request_input,
        _response_output: response_output,
        _source_access_and_direction: source_access_and_direction,
        _helper_rpc_correlation: helper_rpc_correlation,
    } = channels;
    let mut operations = WindowsHelperReadyOperations {
        request_input,
        response_output: Some(response_output),
        _source_access_and_direction: source_access_and_direction,
    };

    if complete_helper_ready_with_operations(
        &mut operations,
        &helper_rpc_correlation,
        expected_role,
    )
    .is_err()
    {
        std::process::abort();
    }
    drop(helper_rpc_correlation);
    operations.block_on_request_input()
}

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
trait HelperReadyOperations {
    type Binding;

    fn tick_count_milliseconds(&mut self) -> Result<u64, ()>;
    fn connect_fixed_binding(&mut self) -> Result<Self::Binding, ()>;
    fn exchange(
        &mut self,
        binding: &Self::Binding,
        request: &[u8],
        timeout_milliseconds: u32,
    ) -> Result<Zeroizing<Vec<u8>>, ()>;
    fn write_confirmation(&mut self, bytes: &[u8; HELPER_RPC_CONFIRMATION_BYTES])
    -> Result<(), ()>;
    fn close_response(&mut self) -> Result<(), ()>;
}

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
fn complete_helper_ready_with_operations<Operations: HelperReadyOperations>(
    operations: &mut Operations,
    retained: &RetainedHelperRpcCorrelation,
    expected_role: HelperBootstrapRole,
) -> Result<(), ()> {
    let confirmation = retained.confirmation()?;
    if confirmation.role() != expected_role {
        return Err(());
    }

    let request = HelperReadyRequest::new(confirmation.epoch_nonce(), confirmation.request_id());
    let request = ServiceRequest::HelperReady(request);
    let request_bytes = Zeroizing::new(wire_v2::encode_request(&request));
    if request_bytes.len() != wire_v2::HELPER_READY_REQUEST_BYTES {
        return Err(());
    }

    let deadline = *retained.deadline_tick_count_ms;
    let initial_now = operations.tick_count_milliseconds()?;
    remaining_call_timeout_milliseconds(deadline, initial_now)?;
    let binding = operations.connect_fixed_binding()?;
    let call_now = operations.tick_count_milliseconds()?;
    let timeout_milliseconds = remaining_call_timeout_milliseconds(deadline, call_now)?;
    let response_bytes =
        operations.exchange(&binding, request_bytes.as_slice(), timeout_milliseconds)?;
    drop(request_bytes);
    // Free the authenticated RPC binding before emitting confirmation. A
    // native binding-free failure is process-terminal in the Windows owner and
    // therefore cannot occur after the parent has observed confirmation EOF.
    drop(binding);
    let response_now = operations.tick_count_milliseconds()?;
    remaining_call_timeout_milliseconds(deadline, response_now)?;

    let response = wire_v2::decode_response(response_bytes.as_slice()).map_err(|_| ())?;
    let ServiceResponse::HelperReady(acknowledgement) = response else {
        return Err(());
    };
    let ServiceRequest::HelperReady(request) = request else {
        return Err(());
    };
    acknowledgement
        .ensure_correlates_with(&request)
        .map_err(|_| ())?;
    drop(response_bytes);

    operations.write_confirmation(&retained.confirmation_frame)?;
    let confirmation_now = operations.tick_count_milliseconds()?;
    remaining_call_timeout_milliseconds(deadline, confirmation_now)?;
    operations.close_response()?;
    Ok(())
}

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
fn remaining_call_timeout_milliseconds(deadline: u64, now: u64) -> Result<u32, ()> {
    let remaining = deadline
        .checked_sub(now)
        .filter(|remaining| *remaining != 0)
        .ok_or(())?;
    if remaining > MAX_BOOTSTRAP_WINDOW_MILLISECONDS {
        return Err(());
    }
    u32::try_from(remaining).map_err(|_| ())
}

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
struct WindowsHelperReadyOperations {
    request_input: FreshHandle,
    response_output: Option<FreshHandle>,
    _source_access_and_direction: UnverifiedSourceAccessAndDirection,
}

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
impl WindowsHelperReadyOperations {
    fn block_on_request_input(self) -> ! {
        if self.response_output.is_some() {
            std::process::abort();
        }
        let Ok(request_input) = native_handle(self.request_input.word()) else {
            std::process::abort();
        };
        let mut byte = [0_u8; 1];
        let mut read = 0_u32;
        // SAFETY: the retained request handle remains owned by `self`, the
        // one-byte destination and count remain live for the complete
        // synchronous wait, and no OVERLAPPED state is supplied. Any read,
        // EOF, or error is an unexpected parent-channel transition and is
        // process-terminal below.
        let _read_result =
            unsafe { ReadFile(request_input, Some(&mut byte), Some(&raw mut read), None) };
        std::process::abort()
    }
}

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
impl HelperReadyOperations for WindowsHelperReadyOperations {
    type Binding = OwnedRpcBinding;

    fn tick_count_milliseconds(&mut self) -> Result<u64, ()> {
        // SAFETY: this scalar system-information query has no arguments.
        Ok(unsafe { GetTickCount64() })
    }

    fn connect_fixed_binding(&mut self) -> Result<Self::Binding, ()> {
        OwnedRpcBinding::connect()
    }

    fn exchange(
        &mut self,
        binding: &Self::Binding,
        request: &[u8],
        timeout_milliseconds: u32,
    ) -> Result<Zeroizing<Vec<u8>>, ()> {
        let timeout = usize::try_from(timeout_milliseconds).map_err(|_| ())?;
        // SAFETY: the binding owner remains live through the option update;
        // the exact nonzero timeout is derived from the retained absolute
        // bootstrap deadline immediately before this synchronous call.
        rpc_success(unsafe {
            RpcBindingSetOption(binding.0.cast_const(), RPC_C_OPT_CALL_TIMEOUT, timeout)
        })?;
        // SAFETY: `binding` owns the non-null RPC binding for the complete
        // synchronous generated call and does not concurrently free it.
        let borrowed = unsafe { BindingHandle::from_raw(binding.0) }.ok_or(())?;
        // The checked-in classic-MIDL ABI requires one fixed `RpcFrame` value
        // in each direction. `RpcFrame` deliberately exposes no mutable raw
        // payload or `Zeroize` implementation, so these unavoidable bounded
        // stack copies are kept inside this synchronous leaf. The owning V2
        // byte vectors on both sides are zeroized.
        let request_frame = RpcFrame::from_payload(request).map_err(|_| ())?;
        let response_frame =
            key_agent_service_rpc_sys::exchange(&borrowed, &request_frame).map_err(|_| ())?;
        Ok(Zeroizing::new(response_frame.payload().to_vec()))
    }

    fn write_confirmation(
        &mut self,
        bytes: &[u8; HELPER_RPC_CONFIRMATION_BYTES],
    ) -> Result<(), ()> {
        let response = self.response_output.as_ref().ok_or(())?.word();
        let mut offset = 0;
        while offset < bytes.len() {
            let mut written = 0_u32;
            // SAFETY: the response pipe owner remains live; the selected
            // suffix and count remain valid for the complete synchronous
            // write, and no OVERLAPPED state is supplied.
            unsafe {
                WriteFile(
                    native_handle(response)?,
                    Some(&bytes[offset..]),
                    Some(&raw mut written),
                    None,
                )
            }
            .map_err(|_| ())?;
            let written = usize::try_from(written).map_err(|_| ())?;
            let remaining = bytes.len() - offset;
            if written == 0 || written > remaining {
                return Err(());
            }
            offset += written;
        }
        Ok(())
    }

    fn close_response(&mut self) -> Result<(), ()> {
        self.response_output.take().ok_or(())?.close()
    }
}

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
struct OwnedRpcBinding(*mut c_void);

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
impl OwnedRpcBinding {
    fn connect() -> Result<Self, ()> {
        let mut string_binding = PWSTR::null();
        // SAFETY: every input is a fixed NUL-terminated string and the RPC
        // runtime returns one independently owned string through the output.
        let compose_status = unsafe {
            RpcStringBindingComposeW(
                PCWSTR::null(),
                PCWSTR(LOCAL_RPC_PROTOCOL_SEQUENCE_WIDE.as_ptr()),
                PCWSTR::null(),
                PCWSTR(key_agent_service_rpc_sys::LOCAL_RPC_ENDPOINT_WIDE.as_ptr()),
                PCWSTR::null(),
                Some(&raw mut string_binding),
            )
        };
        let string_binding = OwnedRpcString(string_binding);
        rpc_success(compose_status)?;
        if string_binding.0.is_null() {
            return Err(());
        }

        let mut binding = core::ptr::null_mut::<c_void>();
        // SAFETY: the composed string remains live through conversion and the
        // runtime returns one independent binding owner through the output.
        let binding_status = unsafe {
            RpcBindingFromStringBindingW(PCWSTR(string_binding.0.0.cast_const()), &raw mut binding)
        };
        let binding = Self(binding);
        rpc_success(binding_status)?;
        if binding.0.is_null() {
            return Err(());
        }

        // SAFETY: the fixed local binding is live. Implicit credentials are
        // restricted to exact WINNT packet-privacy authentication and no
        // caller-selectable principal, auth service, or authz mode exists.
        rpc_success(unsafe {
            RpcBindingSetAuthInfoW(
                binding.0.cast_const(),
                PCWSTR::null(),
                RPC_AUTHN_LEVEL_PACKET_PRIVACY,
                RPC_C_AUTHN_WINNT,
                None,
                RPC_C_AUTHZ_NONE,
            )
        })?;
        Ok(binding)
    }
}

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
impl Drop for OwnedRpcBinding {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        // SAFETY: this is the exact binding owner returned by Rpcrt4 and the
        // generated synchronous call has already completed.
        let status = unsafe { RpcBindingFree(&raw mut self.0) };
        if status.0 != 0 || !self.0.is_null() {
            std::process::abort();
        }
    }
}

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
struct OwnedRpcString(PWSTR);

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
impl Drop for OwnedRpcString {
    fn drop(&mut self) {
        if self.0.is_null() {
            return;
        }
        // SAFETY: this is the exact string owner returned by Rpcrt4.
        let status = unsafe { RpcStringFreeW(&raw mut self.0) };
        if status.0 != 0 || !self.0.is_null() {
            std::process::abort();
        }
    }
}

#[cfg(all(
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
fn rpc_success(status: RPC_STATUS) -> Result<(), ()> {
    if status.0 == 0 { Ok(()) } else { Err(()) }
}

/// Deliberate kernel-evidence blocker retained in the adopted type.
///
/// The supported Win32 queries in this seam prove handle validity, flags,
/// kernel type, and object identity. They do not expose the source handles'
/// exact granted access or effective pipe direction, and `DuplicateHandle`
/// with an explicit desired mask is not itself a proof of either source fact.
/// Nor does the minimum-rights request handle authorize a supported queued-byte
/// query: exact framing therefore relies on the trusted service-owned sole
/// writer boundary, without claiming independent trailing-byte attribution.
#[derive(Debug)]
struct UnverifiedSourceAccessAndDirection;

#[derive(Clone, Copy, Eq, PartialEq)]
struct HandleWord(u64);

impl HandleWord {
    fn new(word: u64) -> Result<Self, ()> {
        if word == 0 || word > i64::MAX as u64 {
            return Err(());
        }
        Ok(Self(word))
    }

    fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
#[cfg_attr(test, derive(Debug))]
enum StandardStream {
    Input,
    Output,
    Error,
}

impl StandardStream {
    const ALL: [Self; 3] = [Self::Input, Self::Output, Self::Error];

    fn native(self) -> STD_HANDLE {
        match self {
            Self::Input => STD_INPUT_HANDLE,
            Self::Output => STD_OUTPUT_HANDLE,
            Self::Error => STD_ERROR_HANDLE,
        }
    }
}

trait FreshHandleOwner {
    fn word(&self) -> HandleWord;
}

trait HandleOperations {
    type Fresh: FreshHandleOwner;

    fn standard_handle(&mut self, stream: StandardStream) -> Result<Option<HandleWord>, ()>;
    fn handle_flags(&mut self, handle: HandleWord) -> Result<u32, ()>;
    fn file_type(&mut self, handle: HandleWord) -> Result<u32, ()>;
    fn same_object(&mut self, left: HandleWord, right: HandleWord) -> Result<bool, ()>;
    fn duplicate(
        &mut self,
        source: HandleWord,
        desired_access: u32,
        inherit: bool,
        options: u32,
    ) -> Result<Self::Fresh, ()>;
    fn close_candidate(&mut self, handle: HandleWord) -> Result<(), ()>;
}

fn adopt_candidate_words<Operations: HandleOperations>(
    operations: &mut Operations,
    request_input: u64,
    response_output: u64,
) -> Result<(Operations::Fresh, Operations::Fresh), ()> {
    let request_input = HandleWord::new(request_input)?;
    let response_output = HandleWord::new(response_output)?;
    if request_input == response_output {
        return Err(());
    }

    validate_pair(operations, request_input, response_output)?;

    let fresh_request_input = operations.duplicate(
        request_input,
        REQUEST_INPUT_DUPLICATE_ACCESS,
        false,
        DUPLICATE_OPTIONS_NONE,
    )?;
    let fresh_response_output = operations.duplicate(
        response_output,
        RESPONSE_OUTPUT_DUPLICATE_ACCESS,
        false,
        DUPLICATE_OPTIONS_NONE,
    )?;
    let fresh_request_word = fresh_request_input.word();
    let fresh_response_word = fresh_response_output.word();

    validate_pair(operations, fresh_request_word, fresh_response_word)?;
    if !operations.same_object(fresh_request_word, request_input)?
        || !operations.same_object(fresh_response_word, response_output)?
    {
        return Err(());
    }

    // Once two verified duplicates exist, both injected candidates are closed
    // without short-circuiting. Any close failure drops both fresh owners.
    let request_closed = operations.close_candidate(request_input).is_ok();
    let response_closed = operations.close_candidate(response_output).is_ok();
    if !request_closed || !response_closed {
        return Err(());
    }

    validate_pair(operations, fresh_request_word, fresh_response_word)?;
    Ok((fresh_request_input, fresh_response_output))
}

fn validate_pair<Operations: HandleOperations>(
    operations: &mut Operations,
    request_input: HandleWord,
    response_output: HandleWord,
) -> Result<(), ()> {
    if request_input == response_output {
        return Err(());
    }
    validate_no_standard_stream_alias(operations, request_input, response_output)?;
    if operations.handle_flags(request_input)? != EXPECTED_HANDLE_FLAGS
        || operations.handle_flags(response_output)? != EXPECTED_HANDLE_FLAGS
        || operations.file_type(request_input)? != EXPECTED_FILE_TYPE
        || operations.file_type(response_output)? != EXPECTED_FILE_TYPE
        || operations.same_object(request_input, response_output)?
    {
        return Err(());
    }
    Ok(())
}

fn validate_no_standard_stream_alias<Operations: HandleOperations>(
    operations: &mut Operations,
    request_input: HandleWord,
    response_output: HandleWord,
) -> Result<(), ()> {
    for stream in StandardStream::ALL {
        let Some(standard) = operations.standard_handle(stream)? else {
            continue;
        };
        if request_input == standard
            || response_output == standard
            || operations.same_object(request_input, standard)?
            || operations.same_object(response_output, standard)?
        {
            return Err(());
        }
    }
    Ok(())
}

trait BootstrapOperations {
    fn read_request(&mut self, handle: HandleWord, buffer: &mut [u8]) -> Result<usize, ()>;
    fn current_process_id(&mut self) -> Result<u32, ()>;
    fn current_process_creation_filetime(&mut self) -> Result<u64, ()>;
    fn tick_count_milliseconds(&mut self) -> Result<u64, ()>;
    fn named_pipe_client_process_id(&mut self, handle: HandleWord) -> Result<u32, ()>;
    fn write_response(&mut self, handle: HandleWord, bytes: &[u8]) -> Result<usize, ()>;
    fn enter_adoption_complete_gate(&mut self);
}

fn complete_bootstrap_with_operations<Operations: BootstrapOperations>(
    operations: &mut Operations,
    request_input: HandleWord,
    response_output: HandleWord,
    expected_role: HelperBootstrapRole,
) -> Result<RetainedHelperRpcCorrelation, ()> {
    let hello_bytes =
        read_exact_request::<HELPER_BOOTSTRAP_HELLO_BYTES, _>(operations, request_input)?;
    let hello = HelperBootstrapHello::decode(hello_bytes.as_slice()).map_err(|_| ())?;
    if hello.role() != expected_role {
        return Err(());
    }

    let child_process_id = hello.child_process_id().get();
    if operations.current_process_id()? != child_process_id
        || hello.service_process_id().get() == child_process_id
    {
        return Err(());
    }
    if operations.current_process_creation_filetime()? != hello.child_creation_filetime().get() {
        return Err(());
    }

    let now = operations.tick_count_milliseconds()?;
    let deadline = hello.deadline_tick_count_ms().get();
    if now >= deadline || deadline - now > MAX_BOOTSTRAP_WINDOW_MILLISECONDS {
        return Err(());
    }

    let service_process_id = hello.service_process_id().get();
    if operations.named_pipe_client_process_id(request_input)? != service_process_id
        || operations.named_pipe_client_process_id(response_output)? != service_process_id
    {
        return Err(());
    }

    let helper_rpc_correlation = RetainedHelperRpcCorrelation::from_hello(&hello)?;
    let acknowledgement = Zeroizing::new(
        HelperAdoptionAck::new(hello.epoch_nonce(), hello.request_id(), hello.role()).encode(),
    );
    write_exact_response(operations, response_output, &acknowledgement)?;
    // The exact synchronous write completes before this transition. Do not use
    // `FlushFileBuffers`: its documented `GENERIC_WRITE` requirement is wider
    // than the deliberately injected `SYNCHRONIZE | FILE_WRITE_DATA` handle.
    // Gate two independently stops the child while the parent reads and binds
    // the complete ACK, before installing the explicit suspend count.
    operations.enter_adoption_complete_gate();
    Ok(helper_rpc_correlation)
}

fn read_exact_request<const N: usize, Operations: BootstrapOperations>(
    operations: &mut Operations,
    handle: HandleWord,
) -> Result<Zeroizing<[u8; N]>, ()> {
    let mut bytes = Zeroizing::new([0_u8; N]);
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        let read = operations.read_request(handle, &mut bytes[offset..])?;
        if read == 0 || read > remaining {
            return Err(());
        }
        offset += read;
    }
    Ok(bytes)
}

fn write_exact_response<Operations: BootstrapOperations>(
    operations: &mut Operations,
    handle: HandleWord,
    bytes: &[u8; HELPER_ADOPTION_ACK_BYTES],
) -> Result<(), ()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        let written = operations.write_response(handle, &bytes[offset..])?;
        if written == 0 || written > remaining {
            return Err(());
        }
        offset += written;
    }
    Ok(())
}

struct FreshHandle {
    _owner: OwnedHandle,
    word: HandleWord,
}

impl FreshHandle {
    #[cfg(all(
        target_env = "msvc",
        feature = "helper-ready-rpc-feasibility-test-hook"
    ))]
    fn close(self) -> Result<(), ()> {
        let Self {
            _owner: owner,
            word: _,
        } = self;
        let raw = owner.into_raw_handle();
        // SAFETY: `into_raw_handle` transfers the sole owned kernel handle to
        // this exact close. On failure the caller aborts the process instead of
        // retrying an indeterminate handle state.
        unsafe { CloseHandle(HANDLE(raw)) }.map_err(|_| ())
    }
}

impl fmt::Debug for FreshHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshHandle([OWNED])")
    }
}

impl FreshHandleOwner for FreshHandle {
    fn word(&self) -> HandleWord {
        self.word
    }
}

#[derive(Debug)]
struct WindowsHandleOperations;

impl HandleOperations for WindowsHandleOperations {
    type Fresh = FreshHandle;

    fn standard_handle(&mut self, stream: StandardStream) -> Result<Option<HandleWord>, ()> {
        // SAFETY: GetStdHandle returns a borrowed scalar process-table value.
        let handle = unsafe { GetStdHandle(stream.native()) }.map_err(|_| ())?;
        Ok(handle_word(handle))
    }

    fn handle_flags(&mut self, handle: HandleWord) -> Result<u32, ()> {
        let mut flags = u32::MAX;
        // SAFETY: the candidate is borrowed for this scalar query and the
        // output pointer names initialized live storage.
        unsafe { GetHandleInformation(native_handle(handle)?, &raw mut flags) }.map_err(|_| ())?;
        Ok(flags)
    }

    fn file_type(&mut self, handle: HandleWord) -> Result<u32, ()> {
        // SAFETY: the candidate is borrowed for this scalar query.
        Ok(unsafe { GetFileType(native_handle(handle)?) }.0)
    }

    fn same_object(&mut self, left: HandleWord, right: HandleWord) -> Result<bool, ()> {
        // SAFETY: both candidates are borrowed for this identity comparison.
        Ok(unsafe { CompareObjectHandles(native_handle(left)?, native_handle(right)?) }.as_bool())
    }

    fn duplicate(
        &mut self,
        source: HandleWord,
        desired_access: u32,
        inherit: bool,
        options: u32,
    ) -> Result<Self::Fresh, ()> {
        let mut duplicate = HANDLE::default();
        // SAFETY: source is a validated live candidate in the current process;
        // both process pseudo-handles designate that same process, the output
        // pointer is live, and ownership of a successful result is transferred
        // immediately below. Desired access, inheritance, and options are the
        // exact explicit values supplied by the state machine.
        unsafe {
            let process = GetCurrentProcess();
            DuplicateHandle(
                process,
                native_handle(source)?,
                process,
                &raw mut duplicate,
                desired_access,
                inherit,
                DUPLICATE_HANDLE_OPTIONS(options),
            )
        }
        .map_err(|_| ())?;
        let word = handle_word(duplicate).ok_or(())?;
        // SAFETY: successful DuplicateHandle returned a fresh positive handle
        // and no other owner has been constructed from this value.
        let owner = unsafe { OwnedHandle::from_raw_handle(duplicate.0.cast::<c_void>()) };
        Ok(FreshHandle {
            _owner: owner,
            word,
        })
    }

    fn close_candidate(&mut self, handle: HandleWord) -> Result<(), ()> {
        // SAFETY: the state machine calls this exactly once for each distinct
        // injected candidate, only after verified fresh duplicates exist.
        unsafe { CloseHandle(native_handle(handle)?) }.map_err(|_| ())
    }
}

#[derive(Debug)]
struct WindowsBootstrapOperations;

impl BootstrapOperations for WindowsBootstrapOperations {
    fn read_request(&mut self, handle: HandleWord, buffer: &mut [u8]) -> Result<usize, ()> {
        let mut read = 0_u32;
        // SAFETY: the adopted handle remains owned for the call, `buffer` is a
        // live writable slice, the count pointer is live, and this synchronous
        // bootstrap path deliberately supplies no OVERLAPPED state.
        unsafe {
            ReadFile(
                native_handle(handle)?,
                Some(buffer),
                Some(&raw mut read),
                None,
            )
        }
        .map_err(|_| ())?;
        usize::try_from(read).map_err(|_| ())
    }

    fn current_process_id(&mut self) -> Result<u32, ()> {
        // SAFETY: this scalar query takes no caller-provided pointers.
        Ok(unsafe { GetCurrentProcessId() })
    }

    fn current_process_creation_filetime(&mut self) -> Result<u64, ()> {
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        // SAFETY: the pseudo-handle designates this process and all four output
        // pointers name initialized, live FILETIME storage.
        unsafe {
            GetProcessTimes(
                GetCurrentProcess(),
                &raw mut creation,
                &raw mut exit,
                &raw mut kernel,
                &raw mut user,
            )
        }
        .map_err(|_| ())?;
        Ok(filetime_word(creation))
    }

    fn tick_count_milliseconds(&mut self) -> Result<u64, ()> {
        // SAFETY: this scalar system-information query has no arguments.
        Ok(unsafe { GetTickCount64() })
    }

    fn named_pipe_client_process_id(&mut self, handle: HandleWord) -> Result<u32, ()> {
        let mut process_id = 0_u32;
        // SAFETY: the adopted handle remains owned and is already proven to be
        // a pipe; the process-id output pointer is initialized and live.
        unsafe { GetNamedPipeClientProcessId(native_handle(handle)?, &raw mut process_id) }
            .map_err(|_| ())?;
        Ok(process_id)
    }

    fn write_response(&mut self, handle: HandleWord, bytes: &[u8]) -> Result<usize, ()> {
        let mut written = 0_u32;
        // SAFETY: the adopted handle remains owned for the call, `bytes` is a
        // live readable slice, the count pointer is live, and this synchronous
        // bootstrap path deliberately supplies no OVERLAPPED state.
        unsafe {
            WriteFile(
                native_handle(handle)?,
                Some(bytes),
                Some(&raw mut written),
                None,
            )
        }
        .map_err(|_| ())?;
        usize::try_from(written).map_err(|_| ())
    }

    fn enter_adoption_complete_gate(&mut self) {
        enter_adoption_complete_gate();
    }
}

fn filetime_word(filetime: FILETIME) -> u64 {
    (u64::from(filetime.dwHighDateTime) << u32::BITS) | u64::from(filetime.dwLowDateTime)
}

fn handle_word(handle: HANDLE) -> Option<HandleWord> {
    let word = u64::try_from(handle.0 as usize).ok()?;
    HandleWord::new(word).ok()
}

fn native_handle(handle: HandleWord) -> Result<HANDLE, ()> {
    let word = usize::try_from(handle.get()).map_err(|_| ())?;
    Ok(HANDLE(word as *mut c_void))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::num::{NonZeroU32, NonZeroU64};
    use std::rc::Rc;

    use key_agent_service_wire::{EpochNonce, ServiceRequestId, WireError};
    use windows::Win32::Foundation::FILETIME;

    use super::{
        BootstrapOperations, DUPLICATE_OPTIONS_NONE, EXPECTED_FILE_TYPE, EXPECTED_HANDLE_FLAGS,
        FreshHandleOwner, HandleOperations, HandleWord, MAX_BOOTSTRAP_WINDOW_MILLISECONDS,
        REQUEST_INPUT_DUPLICATE_ACCESS, RESPONSE_OUTPUT_DUPLICATE_ACCESS,
        RetainedHelperRpcCorrelation, StandardStream, adopt_candidate_words,
        complete_bootstrap_with_operations, filetime_word,
    };
    use crate::wire::{
        HELPER_ADOPTION_ACK_BYTES, HELPER_BOOTSTRAP_HELLO_BYTES, HelperAdoptionAck,
        HelperBootstrapHello, HelperBootstrapRole,
    };

    const REQUEST: u64 = 10;
    const RESPONSE: u64 = 20;
    const FRESH_REQUEST: u64 = 30;
    const FRESH_RESPONSE: u64 = 40;
    const STDIN: u64 = 50;
    const STDOUT: u64 = 60;
    const STDERR: u64 = 70;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Standard(StandardStream),
        Flags(u64),
        FileType(u64),
        SameObject(u64, u64),
        Duplicate {
            source: u64,
            desired_access: u32,
            inherit: bool,
            options: u32,
        },
        Close(u64),
        DropOwner(u64),
    }

    struct FakeFreshHandle {
        word: HandleWord,
        events: Rc<RefCell<Vec<Event>>>,
    }

    impl FreshHandleOwner for FakeFreshHandle {
        fn word(&self) -> HandleWord {
            self.word
        }
    }

    impl Drop for FakeFreshHandle {
        fn drop(&mut self) {
            self.events
                .borrow_mut()
                .push(Event::DropOwner(self.word.get()));
        }
    }

    struct FakeOperations {
        events: Rc<RefCell<Vec<Event>>>,
        calls: usize,
        fail_at: Option<usize>,
        standards: [Option<HandleWord>; 3],
        objects: Vec<(u64, u64)>,
        flag_sequences: Vec<(u64, VecDeque<u32>)>,
        type_sequences: Vec<(u64, VecDeque<u32>)>,
        duplicate_outputs: [HandleWord; 2],
        duplicate_index: usize,
        close_failures: Vec<u64>,
    }

    impl FakeOperations {
        fn scenario() -> Self {
            Self {
                events: Rc::new(RefCell::new(Vec::new())),
                calls: 0,
                fail_at: None,
                standards: [
                    Some(HandleWord(STDIN)),
                    Some(HandleWord(STDOUT)),
                    Some(HandleWord(STDERR)),
                ],
                objects: vec![
                    (REQUEST, 100),
                    (RESPONSE, 200),
                    (FRESH_REQUEST, 100),
                    (FRESH_RESPONSE, 200),
                    (STDIN, 500),
                    (STDOUT, 600),
                    (STDERR, 700),
                ],
                flag_sequences: Vec::new(),
                type_sequences: Vec::new(),
                duplicate_outputs: [HandleWord(FRESH_REQUEST), HandleWord(FRESH_RESPONSE)],
                duplicate_index: 0,
                close_failures: Vec::new(),
            }
        }

        fn event_log(&self) -> Vec<Event> {
            self.events.borrow().clone()
        }

        fn record(&mut self, event: Event) -> Result<(), ()> {
            self.events.borrow_mut().push(event);
            let call = self.calls;
            self.calls = self.calls.checked_add(1).ok_or(())?;
            if self.fail_at == Some(call) {
                return Err(());
            }
            Ok(())
        }

        fn standard_index(stream: StandardStream) -> usize {
            match stream {
                StandardStream::Input => 0,
                StandardStream::Output => 1,
                StandardStream::Error => 2,
            }
        }

        fn object(&self, word: u64) -> u64 {
            self.objects
                .iter()
                .find_map(|(handle, object)| (*handle == word).then_some(*object))
                .unwrap_or(word)
        }

        fn next_sequence(sequences: &mut [(u64, VecDeque<u32>)], word: u64, fallback: u32) -> u32 {
            sequences
                .iter_mut()
                .find_map(|(handle, values)| {
                    (*handle == word).then(|| values.pop_front()).flatten()
                })
                .unwrap_or(fallback)
        }
    }

    impl HandleOperations for FakeOperations {
        type Fresh = FakeFreshHandle;

        fn standard_handle(&mut self, stream: StandardStream) -> Result<Option<HandleWord>, ()> {
            self.record(Event::Standard(stream))?;
            Ok(self.standards[Self::standard_index(stream)])
        }

        fn handle_flags(&mut self, handle: HandleWord) -> Result<u32, ()> {
            self.record(Event::Flags(handle.get()))?;
            Ok(Self::next_sequence(
                &mut self.flag_sequences,
                handle.get(),
                EXPECTED_HANDLE_FLAGS,
            ))
        }

        fn file_type(&mut self, handle: HandleWord) -> Result<u32, ()> {
            self.record(Event::FileType(handle.get()))?;
            Ok(Self::next_sequence(
                &mut self.type_sequences,
                handle.get(),
                EXPECTED_FILE_TYPE,
            ))
        }

        fn same_object(&mut self, left: HandleWord, right: HandleWord) -> Result<bool, ()> {
            self.record(Event::SameObject(left.get(), right.get()))?;
            Ok(self.object(left.get()) == self.object(right.get()))
        }

        fn duplicate(
            &mut self,
            source: HandleWord,
            desired_access: u32,
            inherit: bool,
            options: u32,
        ) -> Result<Self::Fresh, ()> {
            self.record(Event::Duplicate {
                source: source.get(),
                desired_access,
                inherit,
                options,
            })?;
            let word = *self.duplicate_outputs.get(self.duplicate_index).ok_or(())?;
            self.duplicate_index = self.duplicate_index.checked_add(1).ok_or(())?;
            Ok(FakeFreshHandle {
                word,
                events: Rc::clone(&self.events),
            })
        }

        fn close_candidate(&mut self, handle: HandleWord) -> Result<(), ()> {
            self.record(Event::Close(handle.get()))?;
            if self.close_failures.contains(&handle.get()) {
                return Err(());
            }
            Ok(())
        }
    }

    fn validation_events(request: u64, response: u64) -> Vec<Event> {
        let mut events = Vec::new();
        for (stream, standard) in [
            (StandardStream::Input, STDIN),
            (StandardStream::Output, STDOUT),
            (StandardStream::Error, STDERR),
        ] {
            events.push(Event::Standard(stream));
            events.push(Event::SameObject(request, standard));
            events.push(Event::SameObject(response, standard));
        }
        events.extend([
            Event::Flags(request),
            Event::Flags(response),
            Event::FileType(request),
            Event::FileType(response),
            Event::SameObject(request, response),
        ]);
        events
    }

    #[test]
    fn successful_adoption_has_one_exact_operation_order_and_drop_boundary() {
        let mut operations = FakeOperations::scenario();
        let adopted = adopt_candidate_words(&mut operations, REQUEST, RESPONSE);
        assert!(adopted.is_ok());

        let mut expected = validation_events(REQUEST, RESPONSE);
        expected.extend([
            Event::Duplicate {
                source: REQUEST,
                desired_access: REQUEST_INPUT_DUPLICATE_ACCESS,
                inherit: false,
                options: DUPLICATE_OPTIONS_NONE,
            },
            Event::Duplicate {
                source: RESPONSE,
                desired_access: RESPONSE_OUTPUT_DUPLICATE_ACCESS,
                inherit: false,
                options: DUPLICATE_OPTIONS_NONE,
            },
        ]);
        expected.extend(validation_events(FRESH_REQUEST, FRESH_RESPONSE));
        expected.extend([
            Event::SameObject(FRESH_REQUEST, REQUEST),
            Event::SameObject(FRESH_RESPONSE, RESPONSE),
            Event::Close(REQUEST),
            Event::Close(RESPONSE),
        ]);
        expected.extend(validation_events(FRESH_REQUEST, FRESH_RESPONSE));
        assert_eq!(operations.event_log(), expected);

        drop(adopted);
        let events = operations.event_log();
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::DropOwner(_)))
                .count(),
            2
        );
    }

    #[test]
    fn zero_signed_negative_pseudo_and_equal_words_fail_before_operations() {
        for (request, response) in [
            (0, RESPONSE),
            (REQUEST, 0),
            (u64::MAX, RESPONSE),
            (REQUEST, u64::MAX - 1),
            (i64::MIN.cast_unsigned(), RESPONSE),
            (REQUEST, REQUEST),
        ] {
            let mut operations = FakeOperations::scenario();
            assert!(adopt_candidate_words(&mut operations, request, response).is_err());
            assert!(operations.event_log().is_empty());
        }
    }

    #[test]
    fn numeric_and_object_standard_stream_aliases_fail_without_closing_candidates() {
        let mut numeric = FakeOperations::scenario();
        numeric.standards[0] = Some(HandleWord(REQUEST));
        assert!(adopt_candidate_words(&mut numeric, REQUEST, RESPONSE).is_err());
        assert!(
            !numeric
                .event_log()
                .iter()
                .any(|event| matches!(event, Event::Close(_)))
        );

        let mut object = FakeOperations::scenario();
        object.objects.retain(|(handle, _)| *handle != REQUEST);
        object.objects.push((REQUEST, 500));
        assert!(adopt_candidate_words(&mut object, REQUEST, RESPONSE).is_err());
        assert!(
            !object
                .event_log()
                .iter()
                .any(|event| matches!(event, Event::Close(_)))
        );
    }

    #[test]
    fn original_flags_type_and_object_alias_fail_before_duplication_or_close() {
        let mut flags = FakeOperations::scenario();
        flags.flag_sequences.push((REQUEST, VecDeque::from([1])));
        assert!(adopt_candidate_words(&mut flags, REQUEST, RESPONSE).is_err());

        let mut file_type = FakeOperations::scenario();
        file_type
            .type_sequences
            .push((RESPONSE, VecDeque::from([2])));
        assert!(adopt_candidate_words(&mut file_type, REQUEST, RESPONSE).is_err());

        let mut aliased = FakeOperations::scenario();
        aliased.objects.retain(|(handle, _)| *handle != RESPONSE);
        aliased.objects.push((RESPONSE, 100));
        assert!(adopt_candidate_words(&mut aliased, REQUEST, RESPONSE).is_err());

        for operations in [&flags, &file_type, &aliased] {
            assert!(
                !operations
                    .event_log()
                    .iter()
                    .any(|event| matches!(event, Event::Duplicate { .. } | Event::Close(_)))
            );
        }
    }

    #[test]
    fn fresh_flags_type_source_continuity_and_pair_identity_are_required() {
        let mut flags = FakeOperations::scenario();
        flags
            .flag_sequences
            .push((FRESH_REQUEST, VecDeque::from([1])));
        assert!(adopt_candidate_words(&mut flags, REQUEST, RESPONSE).is_err());

        let mut file_type = FakeOperations::scenario();
        file_type
            .type_sequences
            .push((FRESH_RESPONSE, VecDeque::from([1])));
        assert!(adopt_candidate_words(&mut file_type, REQUEST, RESPONSE).is_err());

        let mut discontinuous = FakeOperations::scenario();
        discontinuous
            .objects
            .retain(|(handle, _)| *handle != FRESH_REQUEST);
        discontinuous.objects.push((FRESH_REQUEST, 900));
        assert!(adopt_candidate_words(&mut discontinuous, REQUEST, RESPONSE).is_err());

        let mut aliased = FakeOperations::scenario();
        aliased
            .objects
            .retain(|(handle, _)| *handle != FRESH_RESPONSE);
        aliased.objects.push((FRESH_RESPONSE, 100));
        assert!(adopt_candidate_words(&mut aliased, REQUEST, RESPONSE).is_err());

        for operations in [&flags, &file_type, &discontinuous, &aliased] {
            let events = operations.event_log();
            assert!(!events.iter().any(|event| matches!(event, Event::Close(_))));
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, Event::DropOwner(_)))
                    .count(),
                2
            );
        }
    }

    #[test]
    fn first_candidate_close_failure_still_attempts_second_and_drops_both_owners() {
        let mut operations = FakeOperations::scenario();
        operations.close_failures.push(REQUEST);
        assert!(adopt_candidate_words(&mut operations, REQUEST, RESPONSE).is_err());
        let events = operations.event_log();
        assert!(
            events
                .windows(2)
                .any(|events| { events == [Event::Close(REQUEST), Event::Close(RESPONSE)] })
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| matches!(event, Event::DropOwner(_)))
                .count(),
            2
        );
    }

    #[test]
    fn final_recheck_rejects_post_close_flag_or_type_drift_and_drops_owners() {
        let mut flags = FakeOperations::scenario();
        flags
            .flag_sequences
            .push((FRESH_REQUEST, VecDeque::from([0, 1])));
        assert!(adopt_candidate_words(&mut flags, REQUEST, RESPONSE).is_err());

        let mut file_type = FakeOperations::scenario();
        file_type
            .type_sequences
            .push((FRESH_RESPONSE, VecDeque::from([EXPECTED_FILE_TYPE, 1])));
        assert!(adopt_candidate_words(&mut file_type, REQUEST, RESPONSE).is_err());

        for operations in [&flags, &file_type] {
            let events = operations.event_log();
            assert!(events.contains(&Event::Close(REQUEST)));
            assert!(events.contains(&Event::Close(RESPONSE)));
            assert_eq!(
                events
                    .iter()
                    .filter(|event| matches!(event, Event::DropOwner(_)))
                    .count(),
                2
            );
        }
    }

    #[test]
    fn every_fallible_operation_prefix_rejects_without_returning_owners() {
        let mut baseline = FakeOperations::scenario();
        let adopted = adopt_candidate_words(&mut baseline, REQUEST, RESPONSE);
        assert!(adopted.is_ok());
        let call_count = baseline.calls;
        drop(adopted);

        for failure in 0..call_count {
            let mut operations = FakeOperations::scenario();
            operations.fail_at = Some(failure);
            assert!(adopt_candidate_words(&mut operations, REQUEST, RESPONSE).is_err());
        }
    }

    #[test]
    fn partial_duplicate_failure_drops_the_first_owner_without_closing_candidates() {
        let mut baseline = FakeOperations::scenario();
        let result = adopt_candidate_words(&mut baseline, REQUEST, RESPONSE);
        assert!(result.is_ok());
        let expected_second_duplicate_call = validation_events(REQUEST, RESPONSE).len() + 1;
        let second_duplicate_call = baseline
            .event_log()
            .iter()
            .enumerate()
            .filter_map(|(index, event)| matches!(event, Event::Duplicate { .. }).then_some(index))
            .nth(1);
        assert_eq!(second_duplicate_call, Some(expected_second_duplicate_call));
        drop(result);

        let mut operations = FakeOperations::scenario();
        operations.fail_at = Some(expected_second_duplicate_call);
        assert!(adopt_candidate_words(&mut operations, REQUEST, RESPONSE).is_err());
        let events = operations.event_log();
        assert_eq!(
            events
                .iter()
                .filter(|event| **event == Event::DropOwner(FRESH_REQUEST))
                .count(),
            1
        );
        assert!(!events.iter().any(|event| matches!(event, Event::Close(_))));
    }

    const BOOTSTRAP_SERVICE_PROCESS_ID: u32 = 101;
    const BOOTSTRAP_CHILD_PROCESS_ID: u32 = 202;
    const BOOTSTRAP_CHILD_CREATION_FILETIME: u64 = 303;
    const BOOTSTRAP_DEADLINE_MILLISECONDS: u64 = 20_000;
    const BOOTSTRAP_NOW_MILLISECONDS: u64 = 16_000;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum BootstrapEvent {
        Read { handle: u64, requested: usize },
        CurrentProcessId,
        CurrentProcessCreationFiletime,
        TickCount,
        NamedPipeClientProcessId(u64),
        Write { handle: u64, offered: usize },
        AdoptionCompleteGate,
    }

    struct FakeBootstrapOperations {
        events: Vec<BootstrapEvent>,
        calls: usize,
        fail_at: Option<usize>,
        hello_bytes: [u8; HELPER_BOOTSTRAP_HELLO_BYTES],
        read_offset: usize,
        read_sizes: VecDeque<usize>,
        current_process_id: u32,
        current_process_creation_filetime: u64,
        tick_count_milliseconds: u64,
        request_client_process_id: u32,
        response_client_process_id: u32,
        write_sizes: VecDeque<usize>,
        written_response: Vec<u8>,
    }

    impl FakeBootstrapOperations {
        fn scenario() -> Result<Self, WireError> {
            Self::scenario_for_role(HelperBootstrapRole::Approval)
        }

        fn scenario_for_role(role: HelperBootstrapRole) -> Result<Self, WireError> {
            Ok(Self {
                events: Vec::new(),
                calls: 0,
                fail_at: None,
                hello_bytes: sample_bootstrap_hello_for_role(role)?.encode(),
                read_offset: 0,
                read_sizes: VecDeque::new(),
                current_process_id: BOOTSTRAP_CHILD_PROCESS_ID,
                current_process_creation_filetime: BOOTSTRAP_CHILD_CREATION_FILETIME,
                tick_count_milliseconds: BOOTSTRAP_NOW_MILLISECONDS,
                request_client_process_id: BOOTSTRAP_SERVICE_PROCESS_ID,
                response_client_process_id: BOOTSTRAP_SERVICE_PROCESS_ID,
                write_sizes: VecDeque::new(),
                written_response: Vec::new(),
            })
        }

        fn record(&mut self, event: BootstrapEvent) -> Result<(), ()> {
            self.events.push(event);
            let call = self.calls;
            self.calls = self.calls.checked_add(1).ok_or(())?;
            if self.fail_at == Some(call) {
                return Err(());
            }
            Ok(())
        }

        fn has_entered_gate(&self) -> bool {
            self.events.contains(&BootstrapEvent::AdoptionCompleteGate)
        }
    }

    impl BootstrapOperations for FakeBootstrapOperations {
        fn read_request(&mut self, handle: HandleWord, buffer: &mut [u8]) -> Result<usize, ()> {
            self.record(BootstrapEvent::Read {
                handle: handle.get(),
                requested: buffer.len(),
            })?;
            let read = self.read_sizes.pop_front().unwrap_or(buffer.len());
            if read <= buffer.len() {
                let source_remaining = self.hello_bytes.len().saturating_sub(self.read_offset);
                let copied = read.min(source_remaining);
                buffer[..copied].copy_from_slice(
                    &self.hello_bytes[self.read_offset..self.read_offset + copied],
                );
                self.read_offset += copied;
            }
            Ok(read)
        }

        fn current_process_id(&mut self) -> Result<u32, ()> {
            self.record(BootstrapEvent::CurrentProcessId)?;
            Ok(self.current_process_id)
        }

        fn current_process_creation_filetime(&mut self) -> Result<u64, ()> {
            self.record(BootstrapEvent::CurrentProcessCreationFiletime)?;
            Ok(self.current_process_creation_filetime)
        }

        fn tick_count_milliseconds(&mut self) -> Result<u64, ()> {
            self.record(BootstrapEvent::TickCount)?;
            Ok(self.tick_count_milliseconds)
        }

        fn named_pipe_client_process_id(&mut self, handle: HandleWord) -> Result<u32, ()> {
            self.record(BootstrapEvent::NamedPipeClientProcessId(handle.get()))?;
            if handle == HandleWord(FRESH_REQUEST) {
                Ok(self.request_client_process_id)
            } else if handle == HandleWord(FRESH_RESPONSE) {
                Ok(self.response_client_process_id)
            } else {
                Err(())
            }
        }

        fn write_response(&mut self, handle: HandleWord, bytes: &[u8]) -> Result<usize, ()> {
            self.record(BootstrapEvent::Write {
                handle: handle.get(),
                offered: bytes.len(),
            })?;
            let written = self.write_sizes.pop_front().unwrap_or(bytes.len());
            if written <= bytes.len() {
                self.written_response.extend_from_slice(&bytes[..written]);
            }
            Ok(written)
        }

        fn enter_adoption_complete_gate(&mut self) {
            self.events.push(BootstrapEvent::AdoptionCompleteGate);
        }
    }

    fn sample_bootstrap_hello() -> Result<HelperBootstrapHello, WireError> {
        sample_bootstrap_hello_for_role(HelperBootstrapRole::Approval)
    }

    fn sample_bootstrap_hello_for_role(
        role: HelperBootstrapRole,
    ) -> Result<HelperBootstrapHello, WireError> {
        sample_bootstrap_hello_for_role_and_service(role, BOOTSTRAP_SERVICE_PROCESS_ID)
    }

    fn sample_bootstrap_hello_for_role_and_service(
        role: HelperBootstrapRole,
        service_process_id: u32,
    ) -> Result<HelperBootstrapHello, WireError> {
        Ok(HelperBootstrapHello::new(
            EpochNonce::new([0xA5; 32])?,
            ServiceRequestId::new([0x5A; 16])?,
            role,
            NonZeroU32::new(service_process_id).ok_or(WireError::InvalidValue)?,
            NonZeroU32::new(BOOTSTRAP_CHILD_PROCESS_ID).ok_or(WireError::InvalidValue)?,
            NonZeroU64::new(BOOTSTRAP_CHILD_CREATION_FILETIME).ok_or(WireError::InvalidValue)?,
            NonZeroU64::new(BOOTSTRAP_DEADLINE_MILLISECONDS).ok_or(WireError::InvalidValue)?,
        ))
    }

    fn complete_with_fake(operations: &mut FakeBootstrapOperations) -> Result<(), ()> {
        complete_with_expected_role(operations, HelperBootstrapRole::Approval)
    }

    fn complete_with_expected_role(
        operations: &mut FakeBootstrapOperations,
        expected_role: HelperBootstrapRole,
    ) -> Result<(), ()> {
        complete_bootstrap_with_operations(
            operations,
            HandleWord(FRESH_REQUEST),
            HandleWord(FRESH_RESPONSE),
            expected_role,
        )
        .map(|_| ())
    }

    fn complete_with_retained_correlation(
        operations: &mut FakeBootstrapOperations,
        expected_role: HelperBootstrapRole,
    ) -> Result<RetainedHelperRpcCorrelation, ()> {
        complete_bootstrap_with_operations(
            operations,
            HandleWord(FRESH_REQUEST),
            HandleWord(FRESH_RESPONSE),
            expected_role,
        )
    }

    #[test]
    fn successful_bootstrap_has_exact_order_ack_and_fake_gate() -> Result<(), WireError> {
        let hello = sample_bootstrap_hello()?;
        let mut operations = FakeBootstrapOperations::scenario()?;
        let retained =
            complete_with_retained_correlation(&mut operations, HelperBootstrapRole::Approval)
                .map_err(|()| WireError::InvalidValue)?;
        assert_eq!(
            operations.events,
            [
                BootstrapEvent::Read {
                    handle: FRESH_REQUEST,
                    requested: HELPER_BOOTSTRAP_HELLO_BYTES,
                },
                BootstrapEvent::CurrentProcessId,
                BootstrapEvent::CurrentProcessCreationFiletime,
                BootstrapEvent::TickCount,
                BootstrapEvent::NamedPipeClientProcessId(FRESH_REQUEST),
                BootstrapEvent::NamedPipeClientProcessId(FRESH_RESPONSE),
                BootstrapEvent::Write {
                    handle: FRESH_RESPONSE,
                    offered: HELPER_ADOPTION_ACK_BYTES,
                },
                BootstrapEvent::AdoptionCompleteGate,
            ]
        );

        let acknowledgement = HelperAdoptionAck::decode(&operations.written_response)?;
        acknowledgement.ensure_correlates_with(
            hello.epoch_nonce(),
            hello.request_id(),
            hello.role(),
        )?;

        let confirmation = retained
            .confirmation()
            .map_err(|()| WireError::InvalidValue)?;
        confirmation.ensure_correlates_with(
            hello.epoch_nonce(),
            hello.request_id(),
            hello.role(),
        )?;
        assert!(retained.is_live_at_for_test(BOOTSTRAP_NOW_MILLISECONDS));
        assert!(retained.is_live_at_for_test(BOOTSTRAP_DEADLINE_MILLISECONDS - 1));
        assert!(!retained.is_live_at_for_test(BOOTSTRAP_DEADLINE_MILLISECONDS));
        assert!(!retained.is_live_at_for_test(BOOTSTRAP_DEADLINE_MILLISECONDS + 1));
        assert_eq!(
            format!("{retained:?}"),
            "RetainedHelperRpcCorrelation([REDACTED])"
        );
        Ok(())
    }

    #[test]
    fn partial_reads_and_writes_are_completed_before_gate() -> Result<(), WireError> {
        let mut operations = FakeBootstrapOperations::scenario()?;
        operations.read_sizes = VecDeque::from([1, 2, HELPER_BOOTSTRAP_HELLO_BYTES - 3]);
        operations.write_sizes = VecDeque::from([1, 2, HELPER_ADOPTION_ACK_BYTES - 3]);
        assert_eq!(complete_with_fake(&mut operations), Ok(()));
        assert_eq!(operations.written_response.len(), HELPER_ADOPTION_ACK_BYTES);
        assert!(operations.has_entered_gate());
        assert_eq!(
            operations
                .events
                .iter()
                .filter(|event| matches!(event, BootstrapEvent::Read { .. }))
                .count(),
            3
        );
        assert_eq!(
            operations
                .events
                .iter()
                .filter(|event| matches!(event, BootstrapEvent::Write { .. }))
                .count(),
            3
        );
        Ok(())
    }

    #[test]
    fn zero_or_oversized_read_and_write_progress_is_rejected() -> Result<(), WireError> {
        for read_sizes in [
            VecDeque::from([0]),
            VecDeque::from([HELPER_BOOTSTRAP_HELLO_BYTES + 1]),
        ] {
            let mut operations = FakeBootstrapOperations::scenario()?;
            operations.read_sizes = read_sizes;
            assert!(complete_with_fake(&mut operations).is_err());
            assert!(!operations.has_entered_gate());
        }

        for write_sizes in [
            VecDeque::from([0]),
            VecDeque::from([HELPER_ADOPTION_ACK_BYTES + 1]),
        ] {
            let mut operations = FakeBootstrapOperations::scenario()?;
            operations.write_sizes = write_sizes;
            assert!(complete_with_fake(&mut operations).is_err());
            assert!(!operations.has_entered_gate());
            assert!(
                !operations
                    .events
                    .iter()
                    .any(|event| matches!(event, BootstrapEvent::AdoptionCompleteGate))
            );
        }
        Ok(())
    }

    #[test]
    fn malformed_hello_stops_before_identity_queries() -> Result<(), WireError> {
        let mut malformed = FakeBootstrapOperations::scenario()?;
        malformed.hello_bytes[0] ^= 1;
        assert!(complete_with_fake(&mut malformed).is_err());
        assert_eq!(
            malformed.events,
            [BootstrapEvent::Read {
                handle: FRESH_REQUEST,
                requested: HELPER_BOOTSTRAP_HELLO_BYTES,
            }]
        );
        Ok(())
    }

    #[test]
    fn expected_role_is_bound_before_identity_queries_or_ack() -> Result<(), WireError> {
        let mut operations = FakeBootstrapOperations::scenario()?;
        assert!(
            complete_with_expected_role(&mut operations, HelperBootstrapRole::SecretInput).is_err()
        );
        assert_eq!(
            operations.events,
            [BootstrapEvent::Read {
                handle: FRESH_REQUEST,
                requested: HELPER_BOOTSTRAP_HELLO_BYTES,
            }]
        );
        assert!(operations.written_response.is_empty());
        assert!(!operations.has_entered_gate());

        let mut matched =
            FakeBootstrapOperations::scenario_for_role(HelperBootstrapRole::SecretInput)?;
        let retained =
            complete_with_retained_correlation(&mut matched, HelperBootstrapRole::SecretInput)
                .map_err(|()| WireError::InvalidValue)?;
        assert_eq!(
            HelperAdoptionAck::decode(&matched.written_response)?.role(),
            HelperBootstrapRole::SecretInput
        );
        assert_eq!(
            retained
                .confirmation()
                .map_err(|()| WireError::InvalidValue)?
                .role(),
            HelperBootstrapRole::SecretInput
        );
        assert!(matched.has_entered_gate());
        Ok(())
    }

    #[test]
    fn process_and_both_pipe_client_identities_are_required() -> Result<(), WireError> {
        let mut child_process = FakeBootstrapOperations::scenario()?;
        child_process.current_process_id = BOOTSTRAP_CHILD_PROCESS_ID + 1;
        assert!(complete_with_fake(&mut child_process).is_err());

        let mut self_service = FakeBootstrapOperations::scenario()?;
        self_service.hello_bytes = sample_bootstrap_hello_for_role_and_service(
            HelperBootstrapRole::Approval,
            BOOTSTRAP_CHILD_PROCESS_ID,
        )?
        .encode();
        assert!(complete_with_fake(&mut self_service).is_err());
        assert_eq!(
            self_service.events,
            [
                BootstrapEvent::Read {
                    handle: FRESH_REQUEST,
                    requested: HELPER_BOOTSTRAP_HELLO_BYTES,
                },
                BootstrapEvent::CurrentProcessId,
            ]
        );

        let mut creation = FakeBootstrapOperations::scenario()?;
        creation.current_process_creation_filetime = BOOTSTRAP_CHILD_CREATION_FILETIME + 1;
        assert!(complete_with_fake(&mut creation).is_err());

        let mut request_client = FakeBootstrapOperations::scenario()?;
        request_client.request_client_process_id = BOOTSTRAP_SERVICE_PROCESS_ID + 1;
        assert!(complete_with_fake(&mut request_client).is_err());
        assert!(
            !request_client
                .events
                .contains(&BootstrapEvent::NamedPipeClientProcessId(FRESH_RESPONSE))
        );

        let mut response_client = FakeBootstrapOperations::scenario()?;
        response_client.response_client_process_id = BOOTSTRAP_SERVICE_PROCESS_ID + 1;
        assert!(complete_with_fake(&mut response_client).is_err());
        assert!(
            response_client
                .events
                .contains(&BootstrapEvent::NamedPipeClientProcessId(FRESH_REQUEST))
        );
        assert!(
            response_client
                .events
                .contains(&BootstrapEvent::NamedPipeClientProcessId(FRESH_RESPONSE))
        );

        for operations in [
            &child_process,
            &self_service,
            &creation,
            &request_client,
            &response_client,
        ] {
            assert!(!operations.events.iter().any(|event| matches!(
                event,
                BootstrapEvent::Write { .. } | BootstrapEvent::AdoptionCompleteGate
            )));
        }
        Ok(())
    }

    #[test]
    fn deadline_is_strict_future_and_at_most_five_seconds() -> Result<(), WireError> {
        for now in [
            BOOTSTRAP_DEADLINE_MILLISECONDS,
            BOOTSTRAP_DEADLINE_MILLISECONDS + 1,
            BOOTSTRAP_DEADLINE_MILLISECONDS - MAX_BOOTSTRAP_WINDOW_MILLISECONDS - 1,
        ] {
            let mut operations = FakeBootstrapOperations::scenario()?;
            operations.tick_count_milliseconds = now;
            assert!(complete_with_fake(&mut operations).is_err());
            assert!(!operations.has_entered_gate());
        }

        let mut exact_window = FakeBootstrapOperations::scenario()?;
        exact_window.tick_count_milliseconds =
            BOOTSTRAP_DEADLINE_MILLISECONDS - MAX_BOOTSTRAP_WINDOW_MILLISECONDS;
        assert_eq!(complete_with_fake(&mut exact_window), Ok(()));
        assert!(exact_window.has_entered_gate());
        Ok(())
    }

    #[test]
    fn every_fallible_bootstrap_operation_prefix_rejects_before_gate() -> Result<(), WireError> {
        let mut baseline = FakeBootstrapOperations::scenario()?;
        assert_eq!(complete_with_fake(&mut baseline), Ok(()));
        let call_count = baseline.calls;

        for failure in 0..call_count {
            let mut operations = FakeBootstrapOperations::scenario()?;
            operations.fail_at = Some(failure);
            assert!(complete_with_fake(&mut operations).is_err());
            assert!(!operations.has_entered_gate());
        }
        Ok(())
    }

    #[test]
    fn process_creation_filetime_combines_high_and_low_halves() {
        assert_eq!(
            filetime_word(FILETIME {
                dwLowDateTime: 0x89AB_CDEF,
                dwHighDateTime: 0x0123_4567,
            }),
            0x0123_4567_89AB_CDEF
        );
    }
}

#[cfg(all(
    test,
    target_env = "msvc",
    feature = "helper-ready-rpc-feasibility-test-hook"
))]
mod helper_ready_tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    use key_agent_service_wire::debug_v2::{
        self as wire_v2, HelperReadyAck, OpenEpochAck, ServiceRequest, ServiceResponse,
    };
    use key_agent_service_wire::{EpochNonce, ServiceRequestId, WireError};
    use zeroize::Zeroizing;

    use super::{
        HELPER_RPC_CONFIRMATION_BYTES, HelperReadyOperations, MAX_BOOTSTRAP_WINDOW_MILLISECONDS,
        RPC_AUTHN_LEVEL_PACKET_PRIVACY, RetainedHelperRpcCorrelation,
        complete_helper_ready_with_operations, remaining_call_timeout_milliseconds,
    };
    use crate::wire::{HelperBootstrapRole, HelperRpcConfirmation};

    const DEADLINE: u64 = 20_000;
    const INITIAL_NOW: u64 = 15_000;
    const CALL_NOW: u64 = 15_100;
    const RESPONSE_NOW: u64 = 15_200;
    const CONFIRMATION_NOW: u64 = 15_300;

    #[derive(Clone, Debug, Eq, PartialEq)]
    enum Event {
        Tick(u64),
        Connect,
        Exchange {
            request_bytes: usize,
            timeout_milliseconds: u32,
        },
        Write(usize),
        CloseResponse,
    }

    struct FakeHelperReadyOperations {
        events: Vec<Event>,
        calls: usize,
        fail_at: Option<usize>,
        ticks: VecDeque<u64>,
        response: Zeroizing<Vec<u8>>,
        observed_request: Option<Zeroizing<Vec<u8>>>,
        written_confirmation: Option<Zeroizing<Vec<u8>>>,
        binding_dropped: Rc<Cell<bool>>,
    }

    struct FakeBinding {
        dropped: Rc<Cell<bool>>,
    }

    impl Drop for FakeBinding {
        fn drop(&mut self) {
            self.dropped.set(true);
        }
    }

    impl FakeHelperReadyOperations {
        fn scenario() -> Result<Self, WireError> {
            Ok(Self {
                events: Vec::new(),
                calls: 0,
                fail_at: None,
                ticks: VecDeque::from([INITIAL_NOW, CALL_NOW, RESPONSE_NOW, CONFIRMATION_NOW]),
                response: Zeroizing::new(canonical_ack_bytes()?),
                observed_request: None,
                written_confirmation: None,
                binding_dropped: Rc::new(Cell::new(false)),
            })
        }

        fn record(&mut self, event: Event) -> Result<(), ()> {
            self.events.push(event);
            let call = self.calls;
            self.calls = self.calls.checked_add(1).ok_or(())?;
            if self.fail_at == Some(call) {
                return Err(());
            }
            Ok(())
        }
    }

    impl HelperReadyOperations for FakeHelperReadyOperations {
        type Binding = FakeBinding;

        fn tick_count_milliseconds(&mut self) -> Result<u64, ()> {
            let tick = self.ticks.pop_front().ok_or(())?;
            self.record(Event::Tick(tick))?;
            Ok(tick)
        }

        fn connect_fixed_binding(&mut self) -> Result<Self::Binding, ()> {
            self.record(Event::Connect)?;
            Ok(FakeBinding {
                dropped: Rc::clone(&self.binding_dropped),
            })
        }

        fn exchange(
            &mut self,
            _binding: &Self::Binding,
            request: &[u8],
            timeout_milliseconds: u32,
        ) -> Result<Zeroizing<Vec<u8>>, ()> {
            self.record(Event::Exchange {
                request_bytes: request.len(),
                timeout_milliseconds,
            })?;
            self.observed_request = Some(Zeroizing::new(request.to_vec()));
            Ok(self.response.clone())
        }

        fn write_confirmation(
            &mut self,
            bytes: &[u8; HELPER_RPC_CONFIRMATION_BYTES],
        ) -> Result<(), ()> {
            if !self.binding_dropped.get() {
                return Err(());
            }
            self.record(Event::Write(bytes.len()))?;
            self.written_confirmation = Some(Zeroizing::new(bytes.to_vec()));
            Ok(())
        }

        fn close_response(&mut self) -> Result<(), ()> {
            self.record(Event::CloseResponse)
        }
    }

    fn epoch_nonce() -> Result<EpochNonce, WireError> {
        EpochNonce::new([0xA5; 32])
    }

    fn request_id() -> Result<ServiceRequestId, WireError> {
        ServiceRequestId::new([0x5A; 16])
    }

    fn retained(role: HelperBootstrapRole) -> Result<RetainedHelperRpcCorrelation, WireError> {
        Ok(RetainedHelperRpcCorrelation {
            confirmation_frame: Zeroizing::new(
                HelperRpcConfirmation::new(epoch_nonce()?, request_id()?, role).encode(),
            ),
            deadline_tick_count_ms: Zeroizing::new(DEADLINE),
        })
    }

    fn canonical_ack_bytes() -> Result<Vec<u8>, WireError> {
        Ok(wire_v2::encode_response(&ServiceResponse::HelperReady(
            HelperReadyAck::new(epoch_nonce()?, request_id()?),
        )))
    }

    #[test]
    fn exact_helper_ready_round_trip_uses_original_deadline_and_confirmation_order()
    -> Result<(), WireError> {
        let retained = retained(HelperBootstrapRole::Approval)?;
        let expected_confirmation = retained.confirmation_frame.clone();
        let mut operations = FakeHelperReadyOperations::scenario()?;

        assert_eq!(
            complete_helper_ready_with_operations(
                &mut operations,
                &retained,
                HelperBootstrapRole::Approval,
            ),
            Ok(())
        );
        assert_eq!(operations.events.len(), 8);
        assert_eq!(operations.events[0], Event::Tick(INITIAL_NOW));
        assert_eq!(operations.events[1], Event::Connect);
        assert_eq!(operations.events[2], Event::Tick(CALL_NOW));
        let Event::Exchange {
            request_bytes,
            timeout_milliseconds,
        } = &operations.events[3]
        else {
            return Err(WireError::InvalidValue);
        };
        assert_eq!(*request_bytes, wire_v2::HELPER_READY_REQUEST_BYTES);
        assert_eq!(
            *timeout_milliseconds,
            u32::try_from(DEADLINE - CALL_NOW).map_err(|_| WireError::InvalidValue)?
        );
        let observed_request = operations
            .observed_request
            .as_ref()
            .ok_or(WireError::InvalidValue)?;
        let ServiceRequest::HelperReady(request) =
            wire_v2::decode_request(observed_request.as_slice())?
        else {
            return Err(WireError::InvalidValue);
        };
        assert_eq!(request.epoch_nonce(), epoch_nonce()?);
        assert_eq!(request.request_id(), request_id()?);
        assert_eq!(operations.events[4], Event::Tick(RESPONSE_NOW));
        assert_eq!(
            operations.events[5],
            Event::Write(HELPER_RPC_CONFIRMATION_BYTES)
        );
        assert_eq!(
            operations
                .written_confirmation
                .as_ref()
                .ok_or(WireError::InvalidValue)?
                .as_slice(),
            expected_confirmation.as_slice()
        );
        assert_eq!(operations.events[6], Event::Tick(CONFIRMATION_NOW));
        assert_eq!(operations.events[7], Event::CloseResponse);
        assert!(operations.binding_dropped.get());
        Ok(())
    }

    #[test]
    fn entrypoint_role_mismatch_rejects_before_time_rpc_or_pipe_operations() -> Result<(), WireError>
    {
        let retained = retained(HelperBootstrapRole::Approval)?;
        let mut operations = FakeHelperReadyOperations::scenario()?;
        assert!(
            complete_helper_ready_with_operations(
                &mut operations,
                &retained,
                HelperBootstrapRole::SecretInput,
            )
            .is_err()
        );
        assert!(operations.events.is_empty());
        Ok(())
    }

    #[test]
    fn deadline_is_strict_at_start_before_call_after_call_and_after_confirmation()
    -> Result<(), WireError> {
        for expired_tick_index in 0..4 {
            let retained = retained(HelperBootstrapRole::Approval)?;
            let mut operations = FakeHelperReadyOperations::scenario()?;
            operations.ticks[expired_tick_index] = DEADLINE;
            assert!(
                complete_helper_ready_with_operations(
                    &mut operations,
                    &retained,
                    HelperBootstrapRole::Approval,
                )
                .is_err()
            );
            assert!(!operations.events.contains(&Event::CloseResponse));
            if expired_tick_index < 2 {
                assert!(
                    !operations
                        .events
                        .iter()
                        .any(|event| matches!(event, Event::Exchange { .. }))
                );
            }
            if expired_tick_index < 3 {
                assert!(
                    !operations
                        .events
                        .iter()
                        .any(|event| matches!(event, Event::Write(_)))
                );
            }
        }
        Ok(())
    }

    #[test]
    fn malformed_wrong_variant_and_wrong_correlation_never_emit_confirmation()
    -> Result<(), WireError> {
        let mut malformed = FakeHelperReadyOperations::scenario()?;
        malformed.response = Zeroizing::new(vec![0_u8; wire_v2::HELPER_READY_ACK_BYTES]);

        let mut wrong_variant = FakeHelperReadyOperations::scenario()?;
        wrong_variant.response = Zeroizing::new(wire_v2::encode_response(
            &ServiceResponse::OpenEpoch(OpenEpochAck::new(epoch_nonce()?)),
        ));

        let mut wrong_correlation = FakeHelperReadyOperations::scenario()?;
        wrong_correlation.response =
            Zeroizing::new(wire_v2::encode_response(&ServiceResponse::HelperReady(
                HelperReadyAck::new(epoch_nonce()?, ServiceRequestId::new([0x6B; 16])?),
            )));

        for operations in [&mut malformed, &mut wrong_variant, &mut wrong_correlation] {
            let retained = retained(HelperBootstrapRole::Approval)?;
            assert!(
                complete_helper_ready_with_operations(
                    operations,
                    &retained,
                    HelperBootstrapRole::Approval,
                )
                .is_err()
            );
            assert!(
                !operations
                    .events
                    .iter()
                    .any(|event| matches!(event, Event::Write(_) | Event::CloseResponse))
            );
        }
        Ok(())
    }

    #[test]
    fn every_fallible_operation_prefix_is_terminal_and_close_follows_exact_write()
    -> Result<(), WireError> {
        let baseline_retained = retained(HelperBootstrapRole::Approval)?;
        let mut baseline = FakeHelperReadyOperations::scenario()?;
        assert_eq!(
            complete_helper_ready_with_operations(
                &mut baseline,
                &baseline_retained,
                HelperBootstrapRole::Approval,
            ),
            Ok(())
        );
        let call_count = baseline.calls;

        for failure in 0..call_count {
            let retained = retained(HelperBootstrapRole::Approval)?;
            let mut operations = FakeHelperReadyOperations::scenario()?;
            operations.fail_at = Some(failure);
            assert!(
                complete_helper_ready_with_operations(
                    &mut operations,
                    &retained,
                    HelperBootstrapRole::Approval,
                )
                .is_err()
            );
            assert!(operations.events.len() <= failure + 1);
            if operations.events.contains(&Event::CloseResponse) {
                assert!(matches!(
                    operations.events.as_slice(),
                    [.., Event::Write(_), Event::Tick(_), Event::CloseResponse]
                ));
            }
        }
        Ok(())
    }

    #[test]
    fn remaining_timeout_is_nonzero_bounded_and_fixed_rpc_profile_is_exact() {
        assert_eq!(
            remaining_call_timeout_milliseconds(DEADLINE, DEADLINE - 1),
            Ok(1)
        );
        assert_eq!(
            remaining_call_timeout_milliseconds(
                DEADLINE,
                DEADLINE - MAX_BOOTSTRAP_WINDOW_MILLISECONDS,
            ),
            Ok(u32::try_from(MAX_BOOTSTRAP_WINDOW_MILLISECONDS).unwrap_or(u32::MAX))
        );
        for now in [
            DEADLINE,
            DEADLINE + 1,
            DEADLINE - MAX_BOOTSTRAP_WINDOW_MILLISECONDS - 1,
        ] {
            assert!(remaining_call_timeout_milliseconds(DEADLINE, now).is_err());
        }
        assert_eq!(RPC_AUTHN_LEVEL_PACKET_PRIVACY, 6);
        assert_eq!(super::RPC_C_AUTHN_WINNT, 10);
        assert_eq!(super::RPC_C_AUTHZ_NONE, 0);
        assert_eq!(super::RPC_C_OPT_CALL_TIMEOUT, 12);
        assert_eq!(
            super::LOCAL_RPC_PROTOCOL_SEQUENCE_WIDE,
            [110, 99, 97, 108, 114, 112, 99, 0]
        );
        assert_eq!(
            key_agent_service_rpc_sys::LOCAL_RPC_ENDPOINT,
            "YourWallet.KeyAgentService.v1"
        );
    }
}
