//! Sole unsafe Windows leaf for injected-channel capture and ownership.

use core::ffi::c_void;
use core::fmt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, DUPLICATE_HANDLE_OPTIONS, DuplicateHandle, FILETIME,
    GetHandleInformation, HANDLE,
};
use windows::Win32::Storage::FileSystem::{
    FILE_TYPE_PIPE, FlushFileBuffers, GetFileType, ReadFile, WriteFile,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetProcessTimes};

use crate::gate_spec::{
    ADOPTION_COMPLETE_R10_MARKER, ADOPTION_COMPLETE_R11_MARKER, REQUEST_INPUT_MARKER,
    RESPONSE_OUTPUT_MARKER,
};
use crate::wire::{
    HELPER_ADOPTION_ACK_BYTES, HELPER_BOOTSTRAP_HELLO_BYTES, HelperAdoptionAck,
    HelperBootstrapHello, HelperBootstrapRole,
};

const REQUEST_INPUT_DUPLICATE_ACCESS: u32 = 0x0010_0001;
const RESPONSE_OUTPUT_DUPLICATE_ACCESS: u32 = 0x0010_0002;
const DUPLICATE_OPTIONS_NONE: u32 = 0;
const EXPECTED_HANDLE_FLAGS: u32 = 0;
const EXPECTED_FILE_TYPE: u32 = FILE_TYPE_PIPE.0;
const MAX_BOOTSTRAP_WINDOW_MILLISECONDS: u64 = 5_000;

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
    complete_bootstrap_with_operations(
        &mut operations,
        request_input,
        response_output,
        expected_role,
    )?;

    Ok(BootstrappedInjectedChannels {
        _request_input: channels.request_input,
        _response_output: channels.response_output,
        _source_access_and_direction: channels.source_access_and_direction,
    })
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
    fn flush_response(&mut self, handle: HandleWord) -> Result<(), ()>;
    fn enter_adoption_complete_gate(&mut self);
}

fn complete_bootstrap_with_operations<Operations: BootstrapOperations>(
    operations: &mut Operations,
    request_input: HandleWord,
    response_output: HandleWord,
    expected_role: HelperBootstrapRole,
) -> Result<(), ()> {
    let hello_bytes =
        read_exact_request::<HELPER_BOOTSTRAP_HELLO_BYTES, _>(operations, request_input)?;
    let hello = HelperBootstrapHello::decode(&hello_bytes).map_err(|_| ())?;
    if hello.role() != expected_role {
        return Err(());
    }

    if operations.current_process_id()? != hello.child_process_id().get()
        || operations.current_process_creation_filetime()? != hello.child_creation_filetime().get()
    {
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

    let acknowledgement =
        HelperAdoptionAck::new(hello.epoch_nonce(), hello.request_id(), hello.role()).encode();
    write_exact_response(operations, response_output, &acknowledgement)?;
    operations.flush_response(response_output)?;
    operations.enter_adoption_complete_gate();
    Ok(())
}

fn read_exact_request<const N: usize, Operations: BootstrapOperations>(
    operations: &mut Operations,
    handle: HandleWord,
) -> Result<[u8; N], ()> {
    let mut bytes = [0_u8; N];
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

    fn flush_response(&mut self, handle: HandleWord) -> Result<(), ()> {
        // SAFETY: the adopted response server handle remains owned for the
        // synchronous flush operation.
        unsafe { FlushFileBuffers(native_handle(handle)?) }.map_err(|_| ())
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
        REQUEST_INPUT_DUPLICATE_ACCESS, RESPONSE_OUTPUT_DUPLICATE_ACCESS, StandardStream,
        adopt_candidate_words, complete_bootstrap_with_operations, filetime_word,
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
        Flush(u64),
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

        fn flush_response(&mut self, handle: HandleWord) -> Result<(), ()> {
            self.record(BootstrapEvent::Flush(handle.get()))
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
        Ok(HelperBootstrapHello::new(
            EpochNonce::new([0xA5; 32])?,
            ServiceRequestId::new([0x5A; 16])?,
            role,
            NonZeroU32::new(BOOTSTRAP_SERVICE_PROCESS_ID).ok_or(WireError::InvalidValue)?,
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
    }

    #[test]
    fn successful_bootstrap_has_exact_order_ack_and_fake_gate() -> Result<(), WireError> {
        let hello = sample_bootstrap_hello()?;
        let mut operations = FakeBootstrapOperations::scenario()?;
        assert_eq!(complete_with_fake(&mut operations), Ok(()));
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
                BootstrapEvent::Flush(FRESH_RESPONSE),
                BootstrapEvent::AdoptionCompleteGate,
            ]
        );

        let acknowledgement = HelperAdoptionAck::decode(&operations.written_response)?;
        acknowledgement.ensure_correlates_with(
            hello.epoch_nonce(),
            hello.request_id(),
            hello.role(),
        )?;
        Ok(())
    }

    #[test]
    fn partial_reads_and_writes_are_completed_before_flush_and_gate() -> Result<(), WireError> {
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
            assert!(!operations.events.iter().any(|event| matches!(
                event,
                BootstrapEvent::Flush(_) | BootstrapEvent::AdoptionCompleteGate
            )));
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
        assert_eq!(
            complete_with_expected_role(&mut matched, HelperBootstrapRole::SecretInput),
            Ok(())
        );
        assert_eq!(
            HelperAdoptionAck::decode(&matched.written_response)?.role(),
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

        for operations in [&child_process, &creation, &request_client, &response_client] {
            assert!(!operations.events.iter().any(|event| matches!(
                event,
                BootstrapEvent::Write { .. }
                    | BootstrapEvent::Flush(_)
                    | BootstrapEvent::AdoptionCompleteGate
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
    fn flush_failure_keeps_complete_ack_but_never_enters_gate() -> Result<(), WireError> {
        let mut baseline = FakeBootstrapOperations::scenario()?;
        assert_eq!(complete_with_fake(&mut baseline), Ok(()));
        let flush_call = baseline.calls.saturating_sub(1);

        let mut operations = FakeBootstrapOperations::scenario()?;
        operations.fail_at = Some(flush_call);
        assert!(complete_with_fake(&mut operations).is_err());
        assert_eq!(operations.written_response.len(), HELPER_ADOPTION_ACK_BYTES);
        assert!(!operations.has_entered_gate());
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
