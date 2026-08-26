//! Sole unsafe Windows leaf for injected-channel capture and ownership.

use core::ffi::c_void;
use core::fmt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};

use windows::Win32::Foundation::{
    CloseHandle, CompareObjectHandles, DUPLICATE_HANDLE_OPTIONS, DuplicateHandle,
    GetHandleInformation, HANDLE,
};
use windows::Win32::Storage::FileSystem::{FILE_TYPE_PIPE, GetFileType};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::GetCurrentProcess;

use super::{REQUEST_INPUT_MARKER, RESPONSE_OUTPUT_MARKER};

const REQUEST_INPUT_DUPLICATE_ACCESS: u32 = 0x0010_0001;
const RESPONSE_OUTPUT_DUPLICATE_ACCESS: u32 = 0x0010_0002;
const DUPLICATE_OPTIONS_NONE: u32 = 0;
const EXPECTED_HANDLE_FLAGS: u32 = 0;
const EXPECTED_FILE_TYPE: u32 = FILE_TYPE_PIPE.0;

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

/// Windows-owned half of the opaque public adoption proof.
pub(super) struct AdoptedInjectedChannels {
    _request_input: FreshHandle,
    _response_output: FreshHandle,
    _source_access_and_direction: UnverifiedSourceAccessAndDirection,
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
        _request_input: request_input,
        _response_output: response_output,
        _source_access_and_direction: UnverifiedSourceAccessAndDirection,
    })
}

/// Deliberate kernel-evidence blocker retained in the adopted type.
///
/// The supported Win32 queries in this seam prove handle validity, flags,
/// kernel type, and object identity. They do not expose the source handles'
/// exact granted access or anonymous-pipe direction, and `DuplicateHandle`
/// with an explicit desired mask is not itself a proof of either source fact.
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
    use std::rc::Rc;

    use super::{
        DUPLICATE_OPTIONS_NONE, EXPECTED_FILE_TYPE, EXPECTED_HANDLE_FLAGS, FreshHandleOwner,
        HandleOperations, HandleWord, REQUEST_INPUT_DUPLICATE_ACCESS,
        RESPONSE_OUTPUT_DUPLICATE_ACCESS, StandardStream, adopt_candidate_words,
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
}
