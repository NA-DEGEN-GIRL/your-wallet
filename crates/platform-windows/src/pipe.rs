//! Private named-pipe endpoint construction and connected-peer validation.
//!
//! The pipe DACL and peer checks reduce accidental cross-user/cross-session
//! exposure. They do **not** make the endpoint safe from malware already running
//! as the same user in the same logon session.

use core::fmt;
#[cfg(windows)]
use core::marker::PhantomData;

#[cfg(windows)]
use std::os::windows::io::{AsHandle as _, BorrowedHandle};
#[cfg(windows)]
use std::time::Instant;

use thiserror::Error;
#[cfg(windows)]
use zeroize::Zeroizing;

#[cfg(windows)]
use crate::key_agent_startup::{KEY_AGENT_STARTUP_REQUEST_BYTES, KEY_AGENT_STARTUP_RESPONSE_BYTES};

/// Maximum bytes buffered by the operating system in either direction.
pub const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

/// Errors produced while constructing or accepting a private pipe.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum PipeError {
    /// The endpoint label is outside the deliberately small grammar.
    #[error("invalid pipe endpoint label")]
    InvalidLabel,
    /// The expected process identifier is not valid.
    #[error("invalid expected process identifier")]
    InvalidProcessId,
    /// The operating system rejected a security or pipe operation.
    #[error("Windows pipe boundary operation failed")]
    OperatingSystem,
    /// The connected process did not match the process selected by the broker.
    #[error("named-pipe client process did not match the expected process")]
    UnexpectedProcess,
    /// The client escaped or did not belong to the expected Windows session.
    #[error("named-pipe client session did not match the expected session")]
    UnexpectedSession,
    /// A trusted monotonic deadline elapsed and the pending operation was
    /// cancelled before its buffers went out of scope.
    #[error("private pipe operation deadline elapsed")]
    DeadlineElapsed,
    /// The peer closed before the complete expected frame was transferred.
    #[error("private pipe frame ended early")]
    UnexpectedEnd,
    /// The peer sent bytes after the one exact expected frame.
    #[error("private pipe response contains trailing data")]
    TrailingData,
    /// The peer exceeded the caller's fixed maximum complete-frame size.
    #[error("private pipe response exceeds its maximum frame size")]
    FrameTooLarge,
    /// This boundary is available only on Windows.
    #[error("Windows named-pipe boundary is unavailable on this platform")]
    UnsupportedPlatform,
}

/// Exact private pipe ends for one approval helper launch.
///
/// Parent client ends use overlapped I/O so a trusted monotonic deadline can
/// cancel a pending operation. Child server ends are never named or exposed
/// outside this crate; the restricted launcher duplicates only these exact
/// handles into its handle allowlist. The server/client orientation lets the
/// child query the kernel for the process owning each parent endpoint.
#[cfg(windows)]
pub(crate) struct PrivateApprovalPipes {
    parent_request: sys::OwnedWinHandle,
    child_request: sys::OwnedWinHandle,
    parent_response: sys::OwnedWinHandle,
    child_response: sys::OwnedWinHandle,
}

#[cfg(windows)]
impl PrivateApprovalPipes {
    pub(crate) fn create() -> Result<Self, PipeError> {
        let request_name = SensitivePipeName::generate("approval-request")?;
        let response_name = SensitivePipeName::generate("approval-response")?;
        let security = sys::PipeSecurity::for_current_logon()?;
        let (parent_request, child_request) = sys::create_child_server_pipe(
            &request_name,
            &security,
            sys::PipeDirection::ParentWrites,
        )?;
        let (parent_response, child_response) = sys::create_child_server_pipe(
            &response_name,
            &security,
            sys::PipeDirection::ParentReads,
        )?;
        Ok(Self {
            parent_request,
            child_request,
            parent_response,
            child_response,
        })
    }

    pub(crate) fn child_input(&self) -> BorrowedHandle<'_> {
        self.child_request.as_handle()
    }

    pub(crate) fn child_output(&self) -> BorrowedHandle<'_> {
        self.child_response.as_handle()
    }

    pub(crate) fn into_parent(self) -> (ApprovalRequestWriter, ApprovalResponseReader) {
        let Self {
            parent_request,
            child_request,
            parent_response,
            child_response,
        } = self;
        drop(child_request);
        drop(child_response);
        (
            ApprovalRequestWriter(parent_request),
            ApprovalResponseReader(parent_response),
        )
    }

    #[cfg(test)]
    fn into_test_parts(
        self,
    ) -> (
        ApprovalRequestWriter,
        sys::OwnedWinHandle,
        ApprovalResponseReader,
        sys::OwnedWinHandle,
    ) {
        (
            ApprovalRequestWriter(self.parent_request),
            self.child_request,
            ApprovalResponseReader(self.parent_response),
            self.child_response,
        )
    }
}

#[cfg(windows)]
impl fmt::Debug for PrivateApprovalPipes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateApprovalPipes")
            .field("parent_request", &"[HANDLE]")
            .field("child_request", &"[HANDLE]")
            .field("parent_response", &"[HANDLE]")
            .field("child_response", &"[HANDLE]")
            .finish()
    }
}

/// Parent's one-shot request writer.
#[cfg(windows)]
pub(crate) struct ApprovalRequestWriter(sys::OwnedWinHandle);

#[cfg(windows)]
impl ApprovalRequestWriter {
    pub(crate) fn write_bytes(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), PipeError> {
        sys::write_all_before(self.0.raw(), bytes, deadline)
    }

    pub(crate) fn write_all(self, bytes: &[u8], deadline: Instant) -> Result<(), PipeError> {
        sys::write_all_before(self.0.raw(), bytes, deadline)
    }
}

#[cfg(windows)]
impl fmt::Debug for ApprovalRequestWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovalRequestWriter([HANDLE])")
    }
}

/// Parent's one-shot response reader.
#[cfg(windows)]
pub(crate) struct ApprovalResponseReader(sys::OwnedWinHandle);

#[cfg(windows)]
impl ApprovalResponseReader {
    pub(crate) fn read_exact(
        &self,
        exact_bytes: usize,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, PipeError> {
        sys::read_exact_before(self.0.raw(), exact_bytes, deadline)
    }

    pub(crate) fn read_exact_frame(
        self,
        exact_bytes: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, PipeError> {
        sys::read_exact_frame_before(self.0.raw(), exact_bytes, deadline)
    }
}

#[cfg(windows)]
impl fmt::Debug for ApprovalResponseReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovalResponseReader([HANDLE])")
    }
}

/// Exact private pipe ends for one Secret Input helper launch.
///
/// This deliberately remains distinct from [`PrivateApprovalPipes`] so a
/// caller cannot accidentally cross-wire an approval endpoint into the
/// secret-bearing protocol. Only the child request and response ends are
/// borrowed by the restricted launcher's explicit inherited-handle list.
#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent arming seam.
pub(crate) struct PrivateSecretInputPipes {
    parent_request: sys::OwnedWinHandle,
    child_request: sys::OwnedWinHandle,
    parent_response: sys::OwnedWinHandle,
    child_response: sys::OwnedWinHandle,
}

#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent arming seam.
impl PrivateSecretInputPipes {
    pub(crate) fn create() -> Result<Self, PipeError> {
        let request_name = SensitivePipeName::generate("secret-request")?;
        let response_name = SensitivePipeName::generate("secret-response")?;
        let security = sys::PipeSecurity::for_current_logon()?;
        let (parent_request, child_request) = sys::create_child_server_pipe(
            &request_name,
            &security,
            sys::PipeDirection::ParentWrites,
        )?;
        let (parent_response, child_response) = sys::create_child_server_pipe(
            &response_name,
            &security,
            sys::PipeDirection::ParentReads,
        )?;
        Ok(Self {
            parent_request,
            child_request,
            parent_response,
            child_response,
        })
    }

    pub(crate) fn child_input(&self) -> BorrowedHandle<'_> {
        self.child_request.as_handle()
    }

    pub(crate) fn child_output(&self) -> BorrowedHandle<'_> {
        self.child_response.as_handle()
    }

    pub(crate) fn into_parent(self) -> (SecretRequestWriter, SecretResponseReader) {
        let Self {
            parent_request,
            child_request,
            parent_response,
            child_response,
        } = self;
        drop(child_request);
        drop(child_response);
        (
            SecretRequestWriter(parent_request),
            SecretResponseReader(parent_response),
        )
    }

    #[cfg(test)]
    fn into_test_parts(
        self,
    ) -> (
        SecretRequestWriter,
        sys::OwnedWinHandle,
        SecretResponseReader,
        sys::OwnedWinHandle,
    ) {
        (
            SecretRequestWriter(self.parent_request),
            self.child_request,
            SecretResponseReader(self.parent_response),
            self.child_response,
        )
    }
}

#[cfg(windows)]
impl fmt::Debug for PrivateSecretInputPipes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateSecretInputPipes")
            .field("parent_request", &"[HANDLE]")
            .field("child_request", &"[HANDLE]")
            .field("parent_response", &"[HANDLE]")
            .field("child_response", &"[HANDLE]")
            .finish()
    }
}

/// Parent's one-shot Secret Input request writer.
#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent arming seam.
pub(crate) struct SecretRequestWriter(sys::OwnedWinHandle);

#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent arming seam.
impl SecretRequestWriter {
    pub(crate) fn write_bytes(&mut self, bytes: &[u8], deadline: Instant) -> Result<(), PipeError> {
        sys::write_all_before(self.0.raw(), bytes, deadline)
    }

    pub(crate) fn write_all(self, bytes: &[u8], deadline: Instant) -> Result<(), PipeError> {
        sys::write_all_before(self.0.raw(), bytes, deadline)
    }
}

#[cfg(windows)]
impl fmt::Debug for SecretRequestWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretRequestWriter([HANDLE])")
    }
}

/// Parent's concrete, one-shot Secret Input response reader.
#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent arming seam.
pub(crate) struct SecretResponseReader(sys::OwnedWinHandle);

#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent arming seam.
impl SecretResponseReader {
    pub(crate) fn read_exact(
        &self,
        exact_bytes: usize,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, PipeError> {
        sys::read_exact_before(self.0.raw(), exact_bytes, deadline)
    }

    pub(crate) fn read_bounded_to_end(
        self,
        maximum_bytes: usize,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, PipeError> {
        sys::read_bounded_to_end_before(self.0.raw(), maximum_bytes, deadline)
    }
}

#[cfg(windows)]
impl fmt::Debug for SecretResponseReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretResponseReader([HANDLE])")
    }
}

/// Persistent private pipe sources reserved for the dormant Key Agent supervisor.
///
/// Every handle stored here is non-inheritable. Immediately around one exact
/// `STARTUPINFOEX` launch, [`Self::prepare_child_inheritance`] creates three
/// short-lived inheritable handles for stdin, stdout, and an independent null
/// stderr sink. The borrowed lifetime prevents those duplicates from outliving
/// this owner, and consuming the owner closes both persistent child sources.
#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
pub(crate) struct PrivateKeyAgentPipes {
    parent_request: sys::OwnedWinHandle,
    child_request_source: sys::OwnedWinHandle,
    parent_response: sys::OwnedWinHandle,
    child_response_source: sys::OwnedWinHandle,
}

#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
impl PrivateKeyAgentPipes {
    pub(crate) fn create() -> Result<Self, PipeError> {
        let request_name = SensitivePipeName::generate("key-agent-request")?;
        let response_name = SensitivePipeName::generate("key-agent-response")?;
        let security = sys::PipeSecurity::for_current_logon()?;
        let (parent_request, child_request_source) = sys::create_child_server_pipe(
            &request_name,
            &security,
            sys::PipeDirection::ParentWrites,
        )?;
        let (parent_response, child_response_source) = sys::create_child_server_pipe(
            &response_name,
            &security,
            sys::PipeDirection::ParentReads,
        )?;
        sys::validate_key_agent_persistent_pipe_handles(
            &parent_request,
            &child_request_source,
            &parent_response,
            &child_response_source,
        )?;
        Ok(Self {
            parent_request,
            child_request_source,
            parent_response,
            child_response_source,
        })
    }

    pub(crate) fn prepare_child_inheritance<'pipes, 'flight>(
        &'pipes self,
        flight: &'flight crate::inheritable_handle_launch::InheritableHandleLaunchFlight<'static>,
    ) -> Result<PreparedKeyAgentInheritance<'pipes, 'flight>, PipeError> {
        let stdin = sys::duplicate_inheritable(&self.child_request_source, flight)?;
        let stdout = sys::duplicate_inheritable(&self.child_response_source, flight)?;
        let stderr = sys::create_inheritable_null_sink(flight)?;
        sys::validate_prepared_key_agent_inheritance(
            &self.child_request_source,
            &self.child_response_source,
            &stdin,
            &stdout,
            &stderr,
        )?;
        Ok(PreparedKeyAgentInheritance {
            stdin,
            stdout,
            stderr,
            owner: PhantomData,
            flight,
        })
    }

    pub(crate) fn into_parent(
        self,
    ) -> (KeyAgentStartupRequestWriter, KeyAgentStartupResponseReader) {
        let Self {
            parent_request,
            child_request_source,
            parent_response,
            child_response_source,
        } = self;
        drop(child_request_source);
        drop(child_response_source);
        (
            KeyAgentStartupRequestWriter(parent_request),
            KeyAgentStartupResponseReader(parent_response),
        )
    }

    #[cfg(test)]
    fn into_test_parts(
        self,
    ) -> (
        KeyAgentStartupRequestWriter,
        sys::OwnedWinHandle,
        KeyAgentStartupResponseReader,
        sys::OwnedWinHandle,
    ) {
        (
            KeyAgentStartupRequestWriter(self.parent_request),
            self.child_request_source,
            KeyAgentStartupResponseReader(self.parent_response),
            self.child_response_source,
        )
    }
}

#[cfg(windows)]
impl fmt::Debug for PrivateKeyAgentPipes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateKeyAgentPipes")
            .field("parent_request", &"[HANDLE]")
            .field("child_request_source", &"[HANDLE]")
            .field("parent_response", &"[HANDLE]")
            .field("child_response_source", &"[HANDLE]")
            .finish()
    }
}

/// Short-lived inherited stdio handles for one exact Key Agent activation.
///
/// The three handles are distinct kernel objects and are the complete explicit
/// `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`. Stderr is a write-only null-device sink,
/// so diagnostics can neither persist nor corrupt the trusted stdout response.
/// Dropping this type closes all three inheritable duplicates.
#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
#[must_use = "inheritable handles must be retained only through the exact process creation call"]
pub(crate) struct PreparedKeyAgentInheritance<'pipes, 'flight> {
    stdin: sys::OwnedWinHandle,
    stdout: sys::OwnedWinHandle,
    stderr: sys::OwnedWinHandle,
    owner: PhantomData<&'pipes PrivateKeyAgentPipes>,
    flight: &'flight crate::inheritable_handle_launch::InheritableHandleLaunchFlight<'static>,
}

#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
impl PreparedKeyAgentInheritance<'_, '_> {
    pub(crate) fn stdin(&self) -> BorrowedHandle<'_> {
        self.stdin.as_handle()
    }

    pub(crate) fn stdout(&self) -> BorrowedHandle<'_> {
        self.stdout.as_handle()
    }

    pub(crate) fn stderr(&self) -> BorrowedHandle<'_> {
        self.stderr.as_handle()
    }
}

#[cfg(windows)]
impl fmt::Debug for PreparedKeyAgentInheritance<'_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedKeyAgentInheritance")
            .field("stdin", &"[BORROWED HANDLE]")
            .field("stdout", &"[BORROWED HANDLE]")
            .field("stderr", &"[BORROWED HANDLE]")
            .finish()
    }
}

/// Parent request endpoint before the exact storage-startup frame is sent.
#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
pub(crate) struct KeyAgentStartupRequestWriter(sys::OwnedWinHandle);

// SAFETY: this wrapper uniquely owns one named-pipe client HANDLE, contains no
// borrowed or thread-affine state, and its sole method consumes the wrapper so
// the request endpoint closes before the call returns.
#[allow(unsafe_code)]
unsafe impl Send for KeyAgentStartupRequestWriter {}

#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
impl KeyAgentStartupRequestWriter {
    pub(crate) fn send(
        self,
        frame: &[u8; KEY_AGENT_STARTUP_REQUEST_BYTES],
        deadline: Instant,
    ) -> Result<(), PipeError> {
        sys::write_all_before(self.0.raw(), frame, deadline)
    }
}

#[cfg(windows)]
impl fmt::Debug for KeyAgentStartupRequestWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentStartupRequestWriter([HANDLE])")
    }
}

/// Parent response endpoint before the exact storage-startup frame is received.
#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
pub(crate) struct KeyAgentStartupResponseReader(sys::OwnedWinHandle);

// SAFETY: this wrapper uniquely owns one named-pipe client HANDLE, contains no
// borrowed or thread-affine state, and every method consumes the wrapper so the
// response endpoint closes before the call returns.
#[allow(unsafe_code)]
unsafe impl Send for KeyAgentStartupResponseReader {}

#[cfg(windows)]
#[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
impl KeyAgentStartupResponseReader {
    pub(crate) fn receive(
        self,
        deadline: Instant,
    ) -> Result<Zeroizing<[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES]>, PipeError> {
        let frame = sys::read_exact_zeroizing_frame_before(
            self.0.raw(),
            KEY_AGENT_STARTUP_RESPONSE_BYTES,
            deadline,
        )?;
        Ok(exact_key_agent_startup_response(&frame))
    }

    /// Test-only adapter for the pinned libtest fixture. Production callers
    /// always require the response magic at byte zero and cannot reach this
    /// exact preamble consumer.
    #[cfg(test)]
    pub(crate) fn receive_after_exact_libtest_terse_preamble_for_test(
        self,
        deadline: Instant,
    ) -> Result<Zeroizing<[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES]>, PipeError> {
        const EXACT_PINNED_LIBTEST_PREFIX: &[u8; 16] = b"\nrunning 1 test\n";
        let prefix =
            sys::read_exact_before(self.0.raw(), EXACT_PINNED_LIBTEST_PREFIX.len(), deadline)?;
        if prefix.as_slice() != EXACT_PINNED_LIBTEST_PREFIX {
            return Err(PipeError::TrailingData);
        }
        self.receive(deadline)
    }

    #[cfg(test)]
    fn receive_with_after_frame_hook_for_test<F>(
        self,
        deadline: Instant,
        after_frame: F,
    ) -> Result<Zeroizing<[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES]>, PipeError>
    where
        F: FnOnce(),
    {
        let frame = sys::read_exact_zeroizing_frame_before_with_hook_for_test(
            self.0.raw(),
            KEY_AGENT_STARTUP_RESPONSE_BYTES,
            deadline,
            after_frame,
        )?;
        Ok(exact_key_agent_startup_response(&frame))
    }
}

#[cfg(windows)]
fn exact_key_agent_startup_response(
    frame: &Zeroizing<Vec<u8>>,
) -> Zeroizing<[u8; KEY_AGENT_STARTUP_RESPONSE_BYTES]> {
    let mut exact = Zeroizing::new([0_u8; KEY_AGENT_STARTUP_RESPONSE_BYTES]);
    exact.copy_from_slice(frame.as_slice());
    exact
}

#[cfg(windows)]
impl fmt::Debug for KeyAgentStartupResponseReader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("KeyAgentStartupResponseReader([HANDLE])")
    }
}

#[cfg(all(test, windows))]
pub(crate) fn key_agent_startup_parent_endpoints_are_noninheritable_for_test(
    writer: &KeyAgentStartupRequestWriter,
    reader: &KeyAgentStartupResponseReader,
) -> Result<bool, PipeError> {
    Ok(!sys::handle_inheritable_for_test(&writer.0)?
        && !sys::handle_inheritable_for_test(&reader.0)?)
}

/// The exact process and session permitted to connect to a one-shot pipe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExpectedPeer {
    process_id: u32,
    session_id: u32,
}

impl ExpectedPeer {
    /// Binds a peer to a non-zero PID and a Windows session identifier.
    ///
    /// # Errors
    ///
    /// Returns [`PipeError::InvalidProcessId`] for PID zero.
    pub fn new(process_id: u32, session_id: u32) -> Result<Self, PipeError> {
        if process_id == 0 {
            return Err(PipeError::InvalidProcessId);
        }
        Ok(Self {
            process_id,
            session_id,
        })
    }

    /// Returns the process identifier.
    #[must_use]
    pub const fn process_id(self) -> u32 {
        self.process_id
    }

    /// Returns the Windows session identifier.
    #[must_use]
    pub const fn session_id(self) -> u32 {
        self.session_id
    }
}

/// A random, unguessable endpoint name.
///
/// The name is a capability and is intentionally redacted from `Debug`.
pub struct SensitivePipeName {
    utf16_with_nul: Vec<u16>,
}

impl SensitivePipeName {
    /// Generates a fresh endpoint in the current Windows session.
    ///
    /// # Errors
    ///
    /// Returns [`PipeError::InvalidLabel`] for a label outside the canonical
    /// grammar, or an OS/platform error when secure generation is unavailable.
    pub fn generate(label: &str) -> Result<Self, PipeError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        if label.is_empty()
            || label.len() > 32
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(PipeError::InvalidLabel);
        }

        #[cfg(windows)]
        {
            let session_id = sys::current_session_id()?;
            let mut random = [0_u8; 24];
            getrandom::fill(&mut random).map_err(|_| PipeError::OperatingSystem)?;
            let mut token = String::with_capacity(random.len() * 2);
            for byte in random {
                token.push(char::from(HEX[usize::from(byte >> 4)]));
                token.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
            let endpoint = format!(r"\\.\pipe\LOCAL\your-wallet-{label}-{session_id}-{token}");
            let mut utf16_with_nul: Vec<u16> = endpoint.encode_utf16().collect();
            utf16_with_nul.push(0);
            Ok(Self { utf16_with_nul })
        }

        #[cfg(not(windows))]
        {
            let _ = label;
            Err(PipeError::UnsupportedPlatform)
        }
    }

    #[cfg(windows)]
    fn as_pcwstr(&self) -> windows::core::PCWSTR {
        windows::core::PCWSTR(self.utf16_with_nul.as_ptr())
    }

    #[cfg(test)]
    fn utf16_for_test(&self) -> &[u16] {
        &self.utf16_with_nul
    }
}

impl fmt::Debug for SensitivePipeName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SensitivePipeName")
            .field("value", &"[REDACTED]")
            .finish()
    }
}

/// A one-instance, local-only named-pipe server.
#[cfg(windows)]
pub struct PrivatePipeServer {
    handle: sys::OwnedWinHandle,
    name: SensitivePipeName,
}

#[cfg(windows)]
impl PrivatePipeServer {
    /// Creates a pipe whose DACL grants only the current logon SID full access.
    ///
    /// # Errors
    ///
    /// Returns [`PipeError`] if randomness, SID/DACL construction, or local pipe
    /// creation cannot be proven successful.
    pub fn create(label: &str) -> Result<Self, PipeError> {
        let name = SensitivePipeName::generate(label)?;
        let security = sys::PipeSecurity::for_current_logon()?;
        let handle = sys::create_named_pipe(&name, &security)?;
        Ok(Self { handle, name })
    }

    /// Accepts one client and validates both its PID and Windows session.
    ///
    /// # Errors
    ///
    /// Returns [`PipeError::UnexpectedProcess`] or
    /// [`PipeError::UnexpectedSession`] on a peer mismatch, and fails closed on
    /// any OS validation error.
    pub fn accept(&self, expected: ExpectedPeer) -> Result<(), PipeError> {
        sys::connect_and_validate(self.handle.raw(), expected)
    }

    /// Returns the sensitive endpoint capability for a trusted launcher.
    ///
    /// Callers must pass this value directly and must never log or display it.
    #[must_use]
    pub const fn endpoint(&self) -> &SensitivePipeName {
        &self.name
    }
}

#[cfg(windows)]
impl fmt::Debug for PrivatePipeServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivatePipeServer")
            .field("handle", &"[OWNED]")
            .field("name", &self.name)
            .finish()
    }
}

#[cfg(windows)]
mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;
    use std::os::windows::io::{AsHandle, BorrowedHandle, RawHandle};
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{
        CloseHandle, CompareObjectHandles, DUPLICATE_SAME_ACCESS, DuplicateHandle,
        ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, GENERIC_READ,
        GENERIC_WRITE, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL, LocalFree,
        WAIT_TIMEOUT,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SDDL_REVISION_1,
    };
    use windows::Win32::Security::{
        GetTokenInformation, IsValidSecurityDescriptor, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TokenGroups,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        FILE_SHARE_MODE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE, FILE_TYPE_CHAR,
        FILE_TYPE_PIPE, GetFileType, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, PIPE_ACCESS_INBOUND,
        PIPE_ACCESS_OUTBOUND, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    };
    use windows::Win32::System::IO::{
        CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
    };
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        GetNamedPipeClientSessionId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::SystemServices::SE_GROUP_LOGON_ID;
    use windows::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::core::{BOOL, HRESULT, PCWSTR, PWSTR};
    use zeroize::Zeroizing;

    use super::{ExpectedPeer, PIPE_BUFFER_BYTES, PipeError, SensitivePipeName};
    use crate::inheritable_handle_launch::InheritableHandleLaunchFlight;

    pub(super) struct OwnedWinHandle(HANDLE);

    impl OwnedWinHandle {
        pub(super) const fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl AsHandle for OwnedWinHandle {
        fn as_handle(&self) -> BorrowedHandle<'_> {
            // SAFETY: the returned borrow is tied to this exclusive owner and the
            // wrapper holds a valid handle until after the borrow ends.
            unsafe { BorrowedHandle::borrow_raw(self.0.0 as RawHandle) }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum PipeDirection {
        ParentWrites,
        ParentReads,
    }

    impl Drop for OwnedWinHandle {
        fn drop(&mut self) {
            // SAFETY: `OwnedWinHandle` is constructed only from a successful Win32
            // handle-returning call and owns that handle exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    pub(super) struct PipeSecurity {
        descriptor: PSECURITY_DESCRIPTOR,
    }

    impl PipeSecurity {
        pub(super) fn for_current_logon() -> Result<Self, PipeError> {
            let sid = current_logon_sid_string()?;
            let sddl = dacl_sddl_for_sid(&sid);
            let wide = wide_nul(&sddl);
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            // SAFETY: `wide` is NUL terminated and outlives the call; the output is
            // initialized by the API and later released with LocalFree.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(wide.as_ptr()),
                    SDDL_REVISION_1,
                    &raw mut descriptor,
                    None,
                )
                .map_err(|_| PipeError::OperatingSystem)?;
                if !IsValidSecurityDescriptor(descriptor).as_bool() {
                    let _ = LocalFree(Some(HLOCAL(descriptor.0)));
                    return Err(PipeError::OperatingSystem);
                }
            }
            Ok(Self { descriptor })
        }

        fn attributes(&self) -> SECURITY_ATTRIBUTES {
            SECURITY_ATTRIBUTES {
                nLength: u32::try_from(size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
                lpSecurityDescriptor: self.descriptor.0,
                bInheritHandle: BOOL(0),
            }
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            // SAFETY: this pointer was allocated by
            // ConvertStringSecurityDescriptorToSecurityDescriptorW and is owned here.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
            }
        }
    }

    pub(super) fn create_named_pipe(
        name: &SensitivePipeName,
        security: &PipeSecurity,
    ) -> Result<OwnedWinHandle, PipeError> {
        let attributes = security.attributes();
        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE;
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: the pipe name and security descriptor are valid for the call;
        // neither pointer is retained by CreateNamedPipeW.
        let handle = unsafe {
            CreateNamedPipeW(
                name.as_pcwstr(),
                open_mode,
                pipe_mode,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                Some(ptr::from_ref(&attributes)),
            )
        };
        if handle.is_invalid() {
            return Err(PipeError::OperatingSystem);
        }
        Ok(OwnedWinHandle(handle))
    }

    /// Creates a one-way pair with the synchronous named-pipe server inherited
    /// by the child and the overlapped client retained by the parent. This
    /// reversed topology lets the child ask the kernel which process owns both
    /// parent endpoints before it parses or displays any prompt bytes.
    pub(super) fn create_child_server_pipe(
        name: &SensitivePipeName,
        security: &PipeSecurity,
        direction: PipeDirection,
    ) -> Result<(OwnedWinHandle, OwnedWinHandle), PipeError> {
        let attributes = security.attributes();
        let server_direction = match direction {
            PipeDirection::ParentWrites => PIPE_ACCESS_INBOUND,
            PipeDirection::ParentReads => PIPE_ACCESS_OUTBOUND,
        };
        let open_mode = server_direction | FILE_FLAG_FIRST_PIPE_INSTANCE;
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: the capability name and protected security descriptor remain
        // live throughout creation and are not retained by the API.
        let child_server = unsafe {
            CreateNamedPipeW(
                name.as_pcwstr(),
                open_mode,
                pipe_mode,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                Some(ptr::from_ref(&attributes)),
            )
        };
        if child_server.is_invalid() {
            return Err(PipeError::OperatingSystem);
        }
        let child_server = OwnedWinHandle(child_server);
        let desired_access = match direction {
            PipeDirection::ParentWrites => GENERIC_WRITE.0,
            PipeDirection::ParentReads => GENERIC_READ.0,
        };
        // The parent endpoint is overlapped so every broker-side operation can
        // be cancelled and drained at the trusted monotonic deadline. The
        // identification-only SQOS setting prevents accidental impersonation.
        // CreateFile succeeding also completes the connection to this already
        // available one-instance server; no blocking ConnectNamedPipe call is
        // needed before the server handle is inherited.
        // SAFETY: the private NUL-terminated name remains live, the server is
        // already held open, and all optional pointer arguments are absent.
        let parent_client = unsafe {
            CreateFileW(
                name.as_pcwstr(),
                desired_access,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL
                    | FILE_FLAG_OVERLAPPED
                    | SECURITY_SQOS_PRESENT
                    | SECURITY_IDENTIFICATION,
                None,
            )
        }
        .map_err(|_| PipeError::OperatingSystem)?;
        Ok((OwnedWinHandle(parent_client), child_server))
    }

    /// Creates one inheritable duplicate with exactly the source access mask.
    /// The persistent source remains non-inheritable.
    #[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
    pub(super) fn duplicate_inheritable(
        source: &OwnedWinHandle,
        _flight: &InheritableHandleLaunchFlight<'_>,
    ) -> Result<OwnedWinHandle, PipeError> {
        let mut duplicate = HANDLE::default();
        // SAFETY: the source is owned and live. Both process pseudo-handles name
        // this process, and the requested inheritance bit applies only to the
        // returned duplicate.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source.raw(),
                GetCurrentProcess(),
                &raw mut duplicate,
                0,
                true,
                DUPLICATE_SAME_ACCESS,
            )
            .map_err(|_| PipeError::OperatingSystem)?;
        }
        if duplicate.is_invalid() {
            return Err(PipeError::OperatingSystem);
        }
        let duplicate = OwnedWinHandle(duplicate);
        if handle_flags(duplicate.raw())? != HANDLE_FLAG_INHERIT.0 {
            return Err(PipeError::OperatingSystem);
        }
        Ok(duplicate)
    }

    /// Opens the Windows null device write-only and returns only an inheritable
    /// duplicate. The non-inheritable source closes before this function returns.
    #[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
    pub(super) fn create_inheritable_null_sink(
        flight: &InheritableHandleLaunchFlight<'_>,
    ) -> Result<OwnedWinHandle, PipeError> {
        const NULL_DEVICE: [u16; 8] = [
            b'\\' as u16,
            b'\\' as u16,
            b'.' as u16,
            b'\\' as u16,
            b'N' as u16,
            b'U' as u16,
            b'L' as u16,
            0,
        ];
        // SAFETY: the constant device name is NUL terminated. The exact access is
        // write-only, and no security attributes means this source cannot inherit.
        let source = unsafe {
            CreateFileW(
                PCWSTR(NULL_DEVICE.as_ptr()),
                GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map(OwnedWinHandle)
        .map_err(|_| PipeError::OperatingSystem)?;
        duplicate_inheritable(&source, flight)
    }

    #[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
    pub(super) fn validate_key_agent_persistent_pipe_handles(
        parent_request: &OwnedWinHandle,
        child_request_source: &OwnedWinHandle,
        parent_response: &OwnedWinHandle,
        child_response_source: &OwnedWinHandle,
    ) -> Result<(), PipeError> {
        if handle_flags(parent_request.raw())? != 0
            || handle_flags(child_request_source.raw())? != 0
            || handle_flags(parent_response.raw())? != 0
            || handle_flags(child_response_source.raw())? != 0
        {
            return Err(PipeError::OperatingSystem);
        }
        if same_kernel_object(child_request_source, child_response_source)
            || !handle_has_file_type(child_request_source, FILE_TYPE_PIPE)
            || !handle_has_file_type(child_response_source, FILE_TYPE_PIPE)
        {
            return Err(PipeError::OperatingSystem);
        }
        Ok(())
    }

    #[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
    pub(super) fn validate_prepared_key_agent_inheritance(
        child_request_source: &OwnedWinHandle,
        child_response_source: &OwnedWinHandle,
        stdin: &OwnedWinHandle,
        stdout: &OwnedWinHandle,
        stderr: &OwnedWinHandle,
    ) -> Result<(), PipeError> {
        if handle_flags(stdin.raw())? != HANDLE_FLAG_INHERIT.0
            || handle_flags(stdout.raw())? != HANDLE_FLAG_INHERIT.0
            || handle_flags(stderr.raw())? != HANDLE_FLAG_INHERIT.0
            || !same_kernel_object(child_request_source, stdin)
            || !same_kernel_object(child_response_source, stdout)
            || same_kernel_object(stdin, stdout)
            || same_kernel_object(stdin, stderr)
            || same_kernel_object(stdout, stderr)
            || !handle_has_file_type(stdin, FILE_TYPE_PIPE)
            || !handle_has_file_type(stdout, FILE_TYPE_PIPE)
            || !handle_has_file_type(stderr, FILE_TYPE_CHAR)
        {
            return Err(PipeError::OperatingSystem);
        }
        Ok(())
    }

    fn same_kernel_object(first: &OwnedWinHandle, second: &OwnedWinHandle) -> bool {
        // SAFETY: callers first retain live owned handles. TRUE means the exact
        // same underlying kernel object, even when numeric handle values differ.
        unsafe { CompareObjectHandles(first.raw(), second.raw()) }.as_bool()
    }

    fn handle_has_file_type(handle: &OwnedWinHandle, expected: FILE_TYPE) -> bool {
        // SAFETY: the wrapper owns a live handle for this scalar kernel query.
        (unsafe { GetFileType(handle.raw()) }) == expected
    }

    fn handle_flags(handle: HANDLE) -> Result<u32, PipeError> {
        let mut flags = 0_u32;
        // SAFETY: the caller retains ownership of a live handle for this query.
        unsafe { GetHandleInformation(handle, &raw mut flags) }
            .map_err(|_| PipeError::OperatingSystem)?;
        Ok(flags)
    }

    pub(super) fn write_all_before(
        handle: HANDLE,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), PipeError> {
        let mut written = 0_usize;
        while written < bytes.len() {
            let count = write_once_before(handle, &bytes[written..], deadline)?;
            if count == 0 {
                return Err(PipeError::UnexpectedEnd);
            }
            written = written
                .checked_add(count)
                .ok_or(PipeError::OperatingSystem)?;
        }
        Ok(())
    }

    pub(super) fn read_exact_frame_before(
        handle: HANDLE,
        exact_bytes: usize,
        deadline: Instant,
    ) -> Result<Vec<u8>, PipeError> {
        let mut frame = vec![0_u8; exact_bytes];
        let mut read = 0_usize;
        while read < exact_bytes {
            match read_once_before(handle, &mut frame[read..], deadline)? {
                IoRead::Bytes(0) | IoRead::End => return Err(PipeError::UnexpectedEnd),
                IoRead::Bytes(count) => {
                    read = read.checked_add(count).ok_or(PipeError::OperatingSystem)?;
                }
            }
        }

        require_end_before(handle, deadline)?;
        Ok(frame)
    }

    #[allow(dead_code)] // Reserved for the private Key Agent arming seam.
    pub(super) fn read_exact_before(
        handle: HANDLE,
        exact_bytes: usize,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, PipeError> {
        let mut frame = Zeroizing::new(vec![0_u8; exact_bytes]);
        let mut read = 0_usize;
        while read < exact_bytes {
            match read_once_before(handle, &mut frame[read..], deadline)? {
                IoRead::Bytes(0) | IoRead::End => return Err(PipeError::UnexpectedEnd),
                IoRead::Bytes(count) => {
                    read = read.checked_add(count).ok_or(PipeError::OperatingSystem)?;
                }
            }
        }
        Ok(frame)
    }

    #[allow(dead_code)] // Reserved for the private Key Agent supervisor seam.
    pub(super) fn read_exact_zeroizing_frame_before(
        handle: HANDLE,
        exact_bytes: usize,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, PipeError> {
        read_exact_zeroizing_frame_before_with_hook(handle, exact_bytes, deadline, || {})
    }

    fn read_exact_zeroizing_frame_before_with_hook<F>(
        handle: HANDLE,
        exact_bytes: usize,
        deadline: Instant,
        after_frame: F,
    ) -> Result<Zeroizing<Vec<u8>>, PipeError>
    where
        F: FnOnce(),
    {
        let frame = read_exact_before(handle, exact_bytes, deadline)?;
        after_frame();
        require_end_before(handle, deadline)?;
        Ok(frame)
    }

    #[cfg(test)]
    pub(super) fn read_exact_zeroizing_frame_before_with_hook_for_test<F>(
        handle: HANDLE,
        exact_bytes: usize,
        deadline: Instant,
        after_frame: F,
    ) -> Result<Zeroizing<Vec<u8>>, PipeError>
    where
        F: FnOnce(),
    {
        read_exact_zeroizing_frame_before_with_hook(handle, exact_bytes, deadline, after_frame)
    }

    fn require_end_before(handle: HANDLE, deadline: Instant) -> Result<(), PipeError> {
        // A valid one-shot peer writes one frame and then closes its endpoint.
        // Waiting for EOF within the original deadline makes a delayed trailing
        // byte just as invalid as an immediately buffered byte.
        let mut trailing = [0_u8; 1];
        match read_once_before(handle, &mut trailing, deadline)? {
            IoRead::End | IoRead::Bytes(0) => Ok(()),
            IoRead::Bytes(_) => Err(PipeError::TrailingData),
        }
    }

    #[allow(dead_code)] // Reserved for the private Key Agent arming seam.
    pub(super) fn read_bounded_to_end_before(
        handle: HANDLE,
        maximum_bytes: usize,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, PipeError> {
        let overflow_limit = maximum_bytes
            .checked_add(1)
            .ok_or(PipeError::OperatingSystem)?;
        let mut frame = Zeroizing::new(Vec::with_capacity(overflow_limit));
        loop {
            if frame.len() == overflow_limit {
                return Err(PipeError::FrameTooLarge);
            }
            let offset = frame.len();
            let remaining = overflow_limit
                .checked_sub(offset)
                .ok_or(PipeError::OperatingSystem)?;
            let read_size = remaining.min(256);
            frame.resize(
                offset
                    .checked_add(read_size)
                    .ok_or(PipeError::OperatingSystem)?,
                0,
            );
            match read_once_before(handle, &mut frame[offset..], deadline)? {
                IoRead::End | IoRead::Bytes(0) => {
                    frame.truncate(offset);
                    return Ok(frame);
                }
                IoRead::Bytes(count) => {
                    if count > read_size {
                        return Err(PipeError::OperatingSystem);
                    }
                    frame.truncate(
                        offset
                            .checked_add(count)
                            .ok_or(PipeError::OperatingSystem)?,
                    );
                    if frame.len() > maximum_bytes {
                        return Err(PipeError::FrameTooLarge);
                    }
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum IoRead {
        Bytes(usize),
        End,
    }

    fn write_once_before(
        handle: HANDLE,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<usize, PipeError> {
        let event = create_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..OVERLAPPED::default()
        };
        let mut transferred = 0_u32;
        // SAFETY: the immutable source buffer, OVERLAPPED, event, and handle stay
        // live until `complete_before` reports or drains cancellation.
        let started = unsafe {
            WriteFile(
                handle,
                Some(bytes),
                Some(&raw mut transferred),
                Some(&raw mut overlapped),
            )
        };
        complete_before(handle, &overlapped, started, transferred, deadline)
            .map(|outcome| usize::try_from(outcome).unwrap_or(usize::MAX))
    }

    fn read_once_before(
        handle: HANDLE,
        bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<IoRead, PipeError> {
        let event = create_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..OVERLAPPED::default()
        };
        let mut transferred = 0_u32;
        // SAFETY: the mutable destination buffer, OVERLAPPED, event, and handle
        // stay live until the operation completes or cancellation is drained.
        let started = unsafe {
            ReadFile(
                handle,
                Some(bytes),
                Some(&raw mut transferred),
                Some(&raw mut overlapped),
            )
        };
        if let Err(error) = &started
            && is_pipe_end(error.code())
        {
            deadline_result(deadline, 0)?;
            return Ok(IoRead::End);
        }
        match complete_before(handle, &overlapped, started, transferred, deadline) {
            Ok(count) => Ok(IoRead::Bytes(usize::try_from(count).unwrap_or(usize::MAX))),
            Err(PipeError::UnexpectedEnd) => {
                deadline_result(deadline, 0)?;
                Ok(IoRead::End)
            }
            Err(error) => Err(error),
        }
    }

    fn complete_before(
        handle: HANDLE,
        overlapped: &OVERLAPPED,
        started: windows::core::Result<()>,
        immediate_transferred: u32,
        deadline: Instant,
    ) -> Result<u32, PipeError> {
        if started.is_ok() {
            return deadline_result(deadline, immediate_transferred);
        }
        let error = started.err().ok_or(PipeError::OperatingSystem)?;
        if is_pipe_end(error.code()) {
            return Err(PipeError::UnexpectedEnd);
        }
        if error.code() != ERROR_IO_PENDING.to_hresult() {
            return Err(PipeError::OperatingSystem);
        }
        let timeout_ms = match remaining_milliseconds(deadline) {
            Ok(timeout_ms) => timeout_ms,
            Err(error) => {
                cancel_and_drain(handle, overlapped);
                return Err(error);
            }
        };
        let mut transferred = 0_u32;
        // SAFETY: this function is called only while the initiating buffer,
        // OVERLAPPED, event, and handle remain live. Timeout is followed by
        // cancellation and a mandatory drain.
        let completion = unsafe {
            GetOverlappedResultEx(
                handle,
                ptr::from_ref(overlapped),
                &raw mut transferred,
                timeout_ms,
                false,
            )
        };
        if let Err(error) = completion {
            // Once an operation returned IO_PENDING, every failure exit must
            // synchronously drain it before the OVERLAPPED and caller buffer
            // leave scope. This is safe even if completion won the race.
            cancel_and_drain(handle, overlapped);
            if error.code() == HRESULT::from_win32(WAIT_TIMEOUT.0) {
                Err(PipeError::DeadlineElapsed)
            } else if is_pipe_end(error.code()) {
                Err(PipeError::UnexpectedEnd)
            } else {
                Err(PipeError::OperatingSystem)
            }
        } else {
            deadline_result(deadline, transferred)
        }
    }

    fn cancel_and_drain(handle: HANDLE, overlapped: &OVERLAPPED) {
        // SAFETY: this targets precisely the operation represented by the live
        // OVERLAPPED pointer. Completion may win the race, so cancellation's
        // return value is not itself a safe lifetime signal.
        let _ = unsafe { CancelIoEx(handle, Some(ptr::from_ref(overlapped))) };
        let mut ignored = 0_u32;
        // SAFETY: always drain, even if cancellation reported an unexpected
        // failure. Returning while kernel I/O still references the stack
        // OVERLAPPED or caller buffer would violate their lifetime contract.
        let _ = unsafe {
            GetOverlappedResult(handle, ptr::from_ref(overlapped), &raw mut ignored, true)
        };
    }

    fn create_event() -> Result<OwnedWinHandle, PipeError> {
        // SAFETY: no security attributes or name are supplied. The returned
        // manual-reset event is exclusively owned by the pending operation.
        let event = unsafe { CreateEventW(None, true, false, None) }
            .map_err(|_| PipeError::OperatingSystem)?;
        Ok(OwnedWinHandle(event))
    }

    fn remaining_milliseconds(deadline: Instant) -> Result<u32, PipeError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(PipeError::DeadlineElapsed)?;
        let rounded = remaining
            .checked_add(Duration::from_nanos(999_999))
            .ok_or(PipeError::DeadlineElapsed)?
            .as_millis();
        u32::try_from(rounded.max(1)).map_err(|_| PipeError::OperatingSystem)
    }

    fn deadline_result(deadline: Instant, transferred: u32) -> Result<u32, PipeError> {
        if Instant::now().checked_duration_since(deadline).is_some() {
            Err(PipeError::DeadlineElapsed)
        } else {
            Ok(transferred)
        }
    }

    fn is_pipe_end(code: HRESULT) -> bool {
        code == ERROR_BROKEN_PIPE.to_hresult() || code == ERROR_HANDLE_EOF.to_hresult()
    }

    pub(super) fn connect_and_validate(
        pipe: HANDLE,
        expected: ExpectedPeer,
    ) -> Result<(), PipeError> {
        // SAFETY: `pipe` is the live server handle owned by PrivatePipeServer.
        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        if let Err(error) = connected
            && error.code() != ERROR_PIPE_CONNECTED.to_hresult()
        {
            return Err(PipeError::OperatingSystem);
        }

        let mut client_pid = 0_u32;
        let mut pipe_session = 0_u32;
        // SAFETY: output pointers refer to initialized stack values and `pipe` is
        // connected for the duration of both calls.
        unsafe {
            GetNamedPipeClientProcessId(pipe, &raw mut client_pid)
                .map_err(|_| PipeError::OperatingSystem)?;
            GetNamedPipeClientSessionId(pipe, &raw mut pipe_session)
                .map_err(|_| PipeError::OperatingSystem)?;
        }
        if client_pid != expected.process_id() {
            return Err(PipeError::UnexpectedProcess);
        }

        let mut process_session = 0_u32;
        // OpenProcess ensures the PID is still present before asking for its
        // session. The handle is held until validation completes.
        // SAFETY: requesting query-only access for a numeric PID is safe.
        let process = unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, client_pid)
                .map_err(|_| PipeError::OperatingSystem)?
        };
        let process = OwnedWinHandle(process);
        // SAFETY: output points to a stack value; the queried process is held open.
        unsafe {
            ProcessIdToSessionId(client_pid, &raw mut process_session)
                .map_err(|_| PipeError::OperatingSystem)?;
        }
        let _held_until_here = process;

        if pipe_session != expected.session_id() || process_session != expected.session_id() {
            return Err(PipeError::UnexpectedSession);
        }
        Ok(())
    }

    pub(super) fn current_session_id() -> Result<u32, PipeError> {
        let mut session_id = 0_u32;
        // SAFETY: output points to a valid stack value and the current PID exists.
        unsafe {
            ProcessIdToSessionId(GetCurrentProcessId(), &raw mut session_id)
                .map_err(|_| PipeError::OperatingSystem)?;
        }
        Ok(session_id)
    }

    fn current_logon_sid_string() -> Result<String, PipeError> {
        let mut token = HANDLE::default();
        // SAFETY: output points to a stack HANDLE and TOKEN_QUERY is read-only.
        unsafe {
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token)
                .map_err(|_| PipeError::OperatingSystem)?;
        }
        let token = OwnedWinHandle(token);

        let mut needed = 0_u32;
        // SAFETY: the first call intentionally supplies no buffer to obtain size.
        let _ = unsafe { GetTokenInformation(token.raw(), TokenGroups, None, 0, &raw mut needed) };
        if needed < u32::try_from(size_of::<TOKEN_GROUPS>()).unwrap_or(u32::MAX) {
            return Err(PipeError::OperatingSystem);
        }
        let word_size = size_of::<usize>();
        let word_count = usize::try_from(needed)
            .map_err(|_| PipeError::OperatingSystem)?
            .checked_add(word_size - 1)
            .and_then(|rounded| rounded.checked_div(word_size))
            .ok_or(PipeError::OperatingSystem)?;
        let mut buffer = vec![0_usize; word_count];
        // SAFETY: the usize buffer is suitably aligned and writable for at least
        // `needed` bytes. Windows initializes a TOKEN_GROUPS flexible array.
        unsafe {
            GetTokenInformation(
                token.raw(),
                TokenGroups,
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                needed,
                &raw mut needed,
            )
            .map_err(|_| PipeError::OperatingSystem)?;
        }
        let token_groups = buffer.as_ptr().cast::<TOKEN_GROUPS>();
        // SAFETY: GetTokenInformation initialized a TOKEN_GROUPS at this aligned
        // address, including GroupCount.
        let group_count = unsafe { (*token_groups).GroupCount };
        let group_count = usize::try_from(group_count).map_err(|_| PipeError::OperatingSystem)?;
        let header_bytes = core::mem::offset_of!(TOKEN_GROUPS, Groups);
        let groups_bytes = group_count
            .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
            .and_then(|bytes| bytes.checked_add(header_bytes))
            .ok_or(PipeError::OperatingSystem)?;
        if groups_bytes > usize::try_from(needed).map_err(|_| PipeError::OperatingSystem)? {
            return Err(PipeError::OperatingSystem);
        }
        // SAFETY: GroupCount has been bounds-checked against the initialized
        // buffer. `Groups` is the documented flexible-array first element.
        let groups = unsafe {
            core::slice::from_raw_parts(
                ptr::addr_of!((*token_groups).Groups).cast::<SID_AND_ATTRIBUTES>(),
                group_count,
            )
        };
        let logon_flag = u32::from_ne_bytes(SE_GROUP_LOGON_ID.to_ne_bytes());
        let logon_sid = groups
            .iter()
            .find(|group| group.Attributes & logon_flag == logon_flag)
            .ok_or(PipeError::OperatingSystem)?
            .Sid;
        let mut sid_text = PWSTR::null();
        // SAFETY: the SID is owned by `buffer` and remains live for the call; output
        // is allocated with LocalAlloc and released below.
        unsafe {
            ConvertSidToStringSidW(logon_sid, &raw mut sid_text)
                .map_err(|_| PipeError::OperatingSystem)?;
        }
        // SAFETY: a successful conversion returns a NUL-terminated string.
        let result = unsafe { sid_text.to_string() }.map_err(|_| PipeError::OperatingSystem);
        // SAFETY: ConvertSidToStringSidW allocated the string with LocalAlloc.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sid_text.0.cast::<c_void>())));
        }
        result
    }

    fn dacl_sddl_for_sid(sid: &str) -> String {
        // Protected DACL, exactly one allow ACE, no inherited broad principals.
        format!("D:P(A;;GA;;;{sid})")
    }

    fn wide_nul(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(core::iter::once(0)).collect()
    }

    #[cfg(test)]
    pub(super) fn current_session_for_test() -> Result<u32, PipeError> {
        current_session_id()
    }

    #[cfg(test)]
    pub(super) fn current_dacl_for_test() -> Result<String, PipeError> {
        current_logon_sid_string().map(|sid| dacl_sddl_for_sid(&sid))
    }

    #[cfg(test)]
    pub(super) fn handle_inheritable_for_test(handle: &OwnedWinHandle) -> Result<bool, PipeError> {
        Ok(handle_flags(handle.raw())? & HANDLE_FLAG_INHERIT.0 != 0)
    }

    #[cfg(test)]
    pub(super) fn same_kernel_object_for_test(
        first: &OwnedWinHandle,
        second: &OwnedWinHandle,
    ) -> bool {
        // SAFETY: both test handles are owned and remain live for this query.
        unsafe { CompareObjectHandles(first.raw(), second.raw()) }.as_bool()
    }

    #[cfg(test)]
    pub(super) const fn raw_handle_for_test(handle: &OwnedWinHandle) -> HANDLE {
        handle.raw()
    }

    #[cfg(test)]
    pub(super) fn duplicate_noninheritable_for_test(
        handle: &OwnedWinHandle,
    ) -> Result<OwnedWinHandle, PipeError> {
        let mut duplicate = HANDLE::default();
        // SAFETY: this test observer duplicates one live owned handle into the
        // current process and explicitly clears inheritance on the result.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                handle.raw(),
                GetCurrentProcess(),
                &raw mut duplicate,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
            .map_err(|_| PipeError::OperatingSystem)?;
        }
        Ok(OwnedWinHandle(duplicate))
    }

    #[cfg(test)]
    pub(super) fn raw_handle_names_same_object_for_test(
        expected: &OwnedWinHandle,
        candidate: HANDLE,
    ) -> bool {
        let mut flags = 0_u32;
        // SAFETY: this deliberately probes a captured numeric handle value. A
        // closed value fails here; a concurrently reused value is compared with
        // the retained exact-object observer below instead of treated as live.
        if unsafe { GetHandleInformation(candidate, &raw mut flags) }.is_err() {
            return false;
        }
        // SAFETY: `expected` remains owned and the candidate was just proven live.
        unsafe { CompareObjectHandles(expected.raw(), candidate) }.as_bool()
    }

    #[cfg(test)]
    pub(super) const fn open_mode_for_test() -> u32 {
        PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_FIRST_PIPE_INSTANCE.0
    }

    #[cfg(test)]
    pub(super) const fn pipe_mode_for_test() -> u32 {
        PIPE_TYPE_BYTE.0 | PIPE_READMODE_BYTE.0 | PIPE_WAIT.0 | PIPE_REJECT_REMOTE_CLIENTS.0
    }

    #[cfg(test)]
    pub(super) fn child_server_client_for_test(
        handle: &OwnedWinHandle,
    ) -> Result<(u32, u32), PipeError> {
        let mut process_id = 0_u32;
        let mut session_id = u32::MAX;
        // SAFETY: the child-server handle is live and both outputs point to
        // initialized DWORD storage for the duration of these kernel queries.
        unsafe {
            GetNamedPipeClientProcessId(handle.raw(), &raw mut process_id)
                .map_err(|_| PipeError::OperatingSystem)?;
            GetNamedPipeClientSessionId(handle.raw(), &raw mut session_id)
                .map_err(|_| PipeError::OperatingSystem)?;
        }
        if process_id == 0 || session_id == u32::MAX {
            return Err(PipeError::OperatingSystem);
        }
        Ok((process_id, session_id))
    }

    #[cfg(test)]
    pub(super) fn read_child_exact_for_test(
        handle: &OwnedWinHandle,
        exact_bytes: usize,
    ) -> Result<Vec<u8>, PipeError> {
        let mut output = vec![0_u8; exact_bytes];
        let mut offset = 0_usize;
        while offset < exact_bytes {
            let mut read = 0_u32;
            // SAFETY: this is a synchronous client handle and the selected
            // output slice plus count remain live for the complete call.
            unsafe {
                ReadFile(
                    handle.raw(),
                    Some(&mut output[offset..]),
                    Some(&raw mut read),
                    None,
                )
            }
            .map_err(|_| PipeError::OperatingSystem)?;
            if read == 0 {
                return Err(PipeError::UnexpectedEnd);
            }
            offset = offset
                .checked_add(usize::try_from(read).unwrap_or(usize::MAX))
                .ok_or(PipeError::OperatingSystem)?;
        }
        Ok(output)
    }

    #[cfg(test)]
    pub(super) fn read_child_to_end_for_test(
        handle: &OwnedWinHandle,
    ) -> Result<Vec<u8>, PipeError> {
        let mut output = Vec::new();
        loop {
            let mut chunk = [0_u8; 4_096];
            let mut read = 0_u32;
            // SAFETY: this is a synchronous client handle; the buffer and count
            // remain live for the entire call and no OVERLAPPED is supplied.
            let result =
                unsafe { ReadFile(handle.raw(), Some(&mut chunk), Some(&raw mut read), None) };
            match result {
                Ok(()) if read == 0 => return Ok(output),
                Ok(()) => output.extend_from_slice(
                    chunk
                        .get(..usize::try_from(read).unwrap_or(usize::MAX))
                        .ok_or(PipeError::OperatingSystem)?,
                ),
                Err(error) if is_pipe_end(error.code()) => return Ok(output),
                Err(_) => return Err(PipeError::OperatingSystem),
            }
        }
    }

    #[cfg(test)]
    pub(super) fn write_child_for_test(
        handle: &OwnedWinHandle,
        bytes: &[u8],
    ) -> Result<(), PipeError> {
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let mut written = 0_u32;
            // SAFETY: this is a synchronous client handle; the source slice and
            // output count remain live for the complete call.
            unsafe {
                WriteFile(
                    handle.raw(),
                    Some(&bytes[offset..]),
                    Some(&raw mut written),
                    None,
                )
            }
            .map_err(|_| PipeError::OperatingSystem)?;
            if written == 0 {
                return Err(PipeError::UnexpectedEnd);
            }
            offset = offset
                .checked_add(usize::try_from(written).unwrap_or(usize::MAX))
                .ok_or(PipeError::OperatingSystem)?;
        }
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod tests {
    use std::collections::HashSet;
    use std::os::windows::io::AsRawHandle as _;
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};

    use windows::Win32::Storage::FileSystem::FILE_FLAG_FIRST_PIPE_INSTANCE;
    use windows::Win32::System::Pipes::PIPE_REJECT_REMOTE_CLIENTS;

    use super::{
        PipeError, PrivateApprovalPipes, PrivateKeyAgentPipes, PrivatePipeServer,
        PrivateSecretInputPipes, SensitivePipeName, sys,
    };
    use crate::inheritable_handle_launch::acquire_inheritable_handle_launch;
    use crate::key_agent_startup::{
        KEY_AGENT_STARTUP_REQUEST_BYTES, KEY_AGENT_STARTUP_RESPONSE_BYTES,
    };

    fn launch_deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    #[test]
    fn current_logon_dacl_can_create_a_private_server() -> Result<(), Box<dyn std::error::Error>> {
        let server = PrivatePipeServer::create("boundary-test")?;
        assert_eq!(
            format!("{server:?}"),
            "PrivatePipeServer { handle: \"[OWNED]\", name: SensitivePipeName { value: \"[REDACTED]\" } }"
        );
        Ok(())
    }

    #[test]
    fn generated_pipe_names_are_random_and_redacted() -> Result<(), Box<dyn std::error::Error>> {
        let mut observed = HashSet::new();
        for _ in 0..32 {
            let name = SensitivePipeName::generate("approval")?;
            assert!(observed.insert(name.utf16_for_test().to_vec()));
            assert_eq!(
                format!("{name:?}"),
                "SensitivePipeName { value: \"[REDACTED]\" }"
            );
        }
        Ok(())
    }

    #[test]
    fn current_session_is_resolvable() -> Result<(), Box<dyn std::error::Error>> {
        let _session = sys::current_session_for_test()?;
        Ok(())
    }

    #[test]
    fn dacl_has_one_current_user_allow_ace_and_is_protected()
    -> Result<(), Box<dyn std::error::Error>> {
        let sddl = sys::current_dacl_for_test()?;
        assert!(sddl.starts_with("D:P(A;;GA;;;S-1-"));
        assert_eq!(sddl.matches("(A;;").count(), 1);
        assert!(!sddl.contains(";;;WD"));
        assert!(!sddl.contains(";;;AU"));
        assert!(!sddl.contains(";;;BU"));
        Ok(())
    }

    #[test]
    fn pipe_flags_reject_remote_clients_and_second_server() {
        assert_ne!(sys::pipe_mode_for_test() & PIPE_REJECT_REMOTE_CLIENTS.0, 0);
        assert_ne!(
            sys::open_mode_for_test() & FILE_FLAG_FIRST_PIPE_INSTANCE.0,
            0
        );
    }

    #[test]
    fn key_agent_persistent_lifetime_has_zero_inheritable_handles()
    -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateKeyAgentPipes::create()?;
        assert_eq!(
            format!("{pipes:?}"),
            "PrivateKeyAgentPipes { parent_request: \"[HANDLE]\", child_request_source: \"[HANDLE]\", parent_response: \"[HANDLE]\", child_response_source: \"[HANDLE]\" }"
        );
        let inheritable = [
            sys::handle_inheritable_for_test(&pipes.parent_request)?,
            sys::handle_inheritable_for_test(&pipes.child_request_source)?,
            sys::handle_inheritable_for_test(&pipes.parent_response)?,
            sys::handle_inheritable_for_test(&pipes.child_response_source)?,
        ];
        assert_eq!(inheritable.into_iter().filter(|flag| *flag).count(), 0);
        assert!(!sys::same_kernel_object_for_test(
            &pipes.child_request_source,
            &pipes.child_response_source
        ));
        let request_peer = sys::child_server_client_for_test(&pipes.child_request_source)?;
        let response_peer = sys::child_server_client_for_test(&pipes.child_response_source)?;
        assert_eq!(request_peer, response_peer);
        assert_eq!(request_peer.0, std::process::id());
        assert_eq!(request_peer.1, sys::current_session_for_test()?);
        Ok(())
    }

    #[test]
    fn key_agent_prepared_stdio_is_exactly_three_distinct_inheritable_objects()
    -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateKeyAgentPipes::create()?;
        let flight = acquire_inheritable_handle_launch(launch_deadline())
            .map_err(|_| PipeError::OperatingSystem)?;
        let prepared = pipes.prepare_child_inheritance(&flight)?;
        assert_eq!(
            format!("{prepared:?}"),
            "PreparedKeyAgentInheritance { stdin: \"[BORROWED HANDLE]\", stdout: \"[BORROWED HANDLE]\", stderr: \"[BORROWED HANDLE]\" }"
        );
        assert!(sys::handle_inheritable_for_test(&prepared.stdin)?);
        assert!(sys::handle_inheritable_for_test(&prepared.stdout)?);
        assert!(sys::handle_inheritable_for_test(&prepared.stderr)?);
        assert!(sys::same_kernel_object_for_test(
            &pipes.child_request_source,
            &prepared.stdin
        ));
        assert!(sys::same_kernel_object_for_test(
            &pipes.child_response_source,
            &prepared.stdout
        ));
        assert!(!sys::same_kernel_object_for_test(
            &prepared.stdin,
            &prepared.stdout
        ));
        assert!(!sys::same_kernel_object_for_test(
            &prepared.stdin,
            &prepared.stderr
        ));
        assert!(!sys::same_kernel_object_for_test(
            &prepared.stdout,
            &prepared.stderr
        ));

        let stdin = prepared.stdin().as_raw_handle() as usize;
        let stdout = prepared.stdout().as_raw_handle() as usize;
        let stderr = prepared.stderr().as_raw_handle() as usize;
        assert_ne!(stdin, stdout);
        assert_ne!(stdin, stderr);
        assert_ne!(stdout, stderr);
        let explicit_handle_list = [stdin, stdout, stderr];
        assert_eq!(explicit_handle_list.len(), 3);
        assert_eq!(
            explicit_handle_list
                .into_iter()
                .collect::<HashSet<_>>()
                .len(),
            3
        );
        Ok(())
    }

    #[test]
    fn key_agent_prepared_and_persistent_handle_drops_close_exact_scopes()
    -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateKeyAgentPipes::create()?;
        let flight = acquire_inheritable_handle_launch(launch_deadline())
            .map_err(|_| PipeError::OperatingSystem)?;
        let prepared = pipes.prepare_child_inheritance(&flight)?;
        let stdin = sys::raw_handle_for_test(&prepared.stdin);
        let stdout = sys::raw_handle_for_test(&prepared.stdout);
        let stderr = sys::raw_handle_for_test(&prepared.stderr);
        let stderr_observer = sys::duplicate_noninheritable_for_test(&prepared.stderr)?;
        assert!(sys::raw_handle_names_same_object_for_test(
            &pipes.child_request_source,
            stdin
        ));
        assert!(sys::raw_handle_names_same_object_for_test(
            &pipes.child_response_source,
            stdout
        ));
        assert!(sys::raw_handle_names_same_object_for_test(
            &stderr_observer,
            stderr
        ));
        drop(prepared);
        assert!(!sys::raw_handle_names_same_object_for_test(
            &pipes.child_request_source,
            stdin
        ));
        assert!(!sys::raw_handle_names_same_object_for_test(
            &pipes.child_response_source,
            stdout
        ));
        assert!(!sys::raw_handle_names_same_object_for_test(
            &stderr_observer,
            stderr
        ));
        assert!(!sys::handle_inheritable_for_test(&stderr_observer)?);
        drop(stderr_observer);

        let (writer, reader) = pipes.into_parent();
        let request = [0_u8; KEY_AGENT_STARTUP_REQUEST_BYTES];
        assert!(matches!(
            writer.send(&request, future_deadline()?),
            Err(PipeError::UnexpectedEnd | PipeError::OperatingSystem)
        ));
        assert!(matches!(
            reader.receive(future_deadline()?),
            Err(PipeError::UnexpectedEnd)
        ));
        Ok(())
    }

    #[test]
    fn key_agent_prepared_stdio_has_exact_directions_and_isolated_stderr()
    -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateKeyAgentPipes::create()?;
        let flight = acquire_inheritable_handle_launch(launch_deadline())
            .map_err(|_| PipeError::OperatingSystem)?;
        let prepared = pipes.prepare_child_inheritance(&flight)?;

        let request = [0x42_u8; 64];
        sys::write_all_before(pipes.parent_request.raw(), &request, future_deadline()?)?;
        assert_eq!(
            sys::read_child_exact_for_test(&prepared.stdin, request.len())?,
            request
        );
        assert_eq!(
            sys::write_child_for_test(&prepared.stdin, b"wrong direction"),
            Err(PipeError::OperatingSystem)
        );
        assert_eq!(
            sys::read_child_exact_for_test(&prepared.stdout, 1),
            Err(PipeError::OperatingSystem)
        );
        assert_eq!(
            sys::read_child_exact_for_test(&prepared.stderr, 1),
            Err(PipeError::OperatingSystem)
        );

        let diagnostic = b"must be discarded outside the response stream";
        sys::write_child_for_test(&prepared.stderr, diagnostic)?;
        let response = [0x57_u8; KEY_AGENT_STARTUP_RESPONSE_BYTES];
        sys::write_child_for_test(&prepared.stdout, &response)?;
        drop(prepared);

        let (writer, child_request_source, reader, child_response_source) = pipes.into_test_parts();
        drop(writer);
        drop(child_request_source);
        drop(child_response_source);
        let received = reader.receive(future_deadline()?)?;
        assert_eq!(received.as_slice(), response);
        Ok(())
    }

    #[test]
    fn key_agent_request_writer_writes_exact_frame_then_closes()
    -> Result<(), Box<dyn std::error::Error>> {
        let (writer, child_request, reader, child_response) =
            PrivateKeyAgentPipes::create()?.into_test_parts();
        drop(reader);
        drop(child_response);
        let request = [0x42_u8; KEY_AGENT_STARTUP_REQUEST_BYTES];
        writer.send(&request, future_deadline()?)?;
        assert_eq!(sys::read_child_to_end_for_test(&child_request)?, request);
        Ok(())
    }

    #[test]
    fn key_agent_response_reader_requires_exact_frame_plus_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let (writer, child_request, reader, child_response) =
            PrivateKeyAgentPipes::create()?.into_test_parts();
        drop(writer);
        drop(child_request);
        let response = [0x57_u8; KEY_AGENT_STARTUP_RESPONSE_BYTES];
        sys::write_child_for_test(&child_response, &response)?;
        drop(child_response);
        let received = reader.receive(future_deadline()?)?;
        assert_eq!(received.as_slice(), response);
        Ok(())
    }

    #[test]
    fn key_agent_test_reader_accepts_only_the_exact_pinned_libtest_prefix()
    -> Result<(), Box<dyn std::error::Error>> {
        let (writer, child_request, reader, child_response) =
            PrivateKeyAgentPipes::create()?.into_test_parts();
        drop(writer);
        drop(child_request);
        let response = [0x58_u8; KEY_AGENT_STARTUP_RESPONSE_BYTES];
        sys::write_child_for_test(&child_response, b"\nrunning 1 test\n")?;
        sys::write_child_for_test(&child_response, &response)?;
        drop(child_response);
        let received =
            reader.receive_after_exact_libtest_terse_preamble_for_test(future_deadline()?)?;
        assert_eq!(received.as_slice(), response);

        let (_writer, _child_request, wrong_reader, wrong_child_response) =
            PrivateKeyAgentPipes::create()?.into_test_parts();
        sys::write_child_for_test(&wrong_child_response, b"\nrunning 2 test\n")?;
        drop(wrong_child_response);
        assert!(matches!(
            wrong_reader.receive_after_exact_libtest_terse_preamble_for_test(future_deadline()?),
            Err(PipeError::TrailingData)
        ));
        Ok(())
    }

    #[test]
    fn key_agent_parent_endpoints_transfer_once_to_a_fresh_thread()
    -> Result<(), Box<dyn std::error::Error>> {
        fn assert_send<T: Send>() {}
        assert_send::<super::KeyAgentStartupRequestWriter>();
        assert_send::<super::KeyAgentStartupResponseReader>();

        let (writer, reader) = PrivateKeyAgentPipes::create()?.into_parent();
        let worker = std::thread::spawn(move || -> Result<(), PipeError> {
            let write_deadline = Instant::now()
                .checked_add(Duration::from_secs(5))
                .ok_or(PipeError::DeadlineElapsed)?;
            let request = [0_u8; KEY_AGENT_STARTUP_REQUEST_BYTES];
            assert!(matches!(
                writer.send(&request, write_deadline),
                Err(PipeError::UnexpectedEnd | PipeError::OperatingSystem)
            ));
            let read_deadline = Instant::now()
                .checked_add(Duration::from_secs(5))
                .ok_or(PipeError::DeadlineElapsed)?;
            assert!(matches!(
                reader.receive(read_deadline),
                Err(PipeError::UnexpectedEnd)
            ));
            Ok(())
        });
        worker
            .join()
            .map_err(|_| "Key Agent endpoint transfer worker panicked")??;
        Ok(())
    }

    #[test]
    fn key_agent_startup_transport_rejects_early_response() -> Result<(), Box<dyn std::error::Error>>
    {
        let (writer, child_request, reader, child_response) =
            PrivateKeyAgentPipes::create()?.into_test_parts();
        drop(writer);
        drop(child_request);

        sys::write_child_for_test(
            &child_response,
            &[0x33; KEY_AGENT_STARTUP_RESPONSE_BYTES - 1],
        )?;
        drop(child_response);
        assert!(matches!(
            reader.receive(future_deadline()?),
            Err(PipeError::UnexpectedEnd)
        ));
        Ok(())
    }

    #[test]
    fn key_agent_startup_transport_rejects_delayed_response_suffix_after_exact_frame()
    -> Result<(), Box<dyn std::error::Error>> {
        let (writer, child_request, reader, child_response) =
            PrivateKeyAgentPipes::create()?.into_test_parts();
        drop(writer);
        drop(child_request);

        let response = [0x44_u8; KEY_AGENT_STARTUP_RESPONSE_BYTES];
        sys::write_child_for_test(&child_response, &response)?;
        let after_frame = Arc::new(Barrier::new(2));
        let reader_after_frame = Arc::clone(&after_frame);
        let deadline = future_deadline()?;
        let worker = std::thread::spawn(move || {
            reader.receive_with_after_frame_hook_for_test(deadline, || {
                reader_after_frame.wait();
            })
        });

        // The test-only hook runs only after the exact fixed frame has been
        // consumed. Releasing this barrier before writing proves that a suffix
        // arriving later is rejected rather than merely caught while buffered.
        after_frame.wait();
        sys::write_child_for_test(&child_response, &[0x45])?;
        drop(child_response);
        assert!(matches!(
            worker.join().map_err(|_| "response reader panicked")?,
            Err(PipeError::TrailingData)
        ));
        Ok(())
    }

    #[test]
    fn key_agent_response_eof_observed_after_deadline_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let (writer, child_request, reader, child_response) =
            PrivateKeyAgentPipes::create()?.into_test_parts();
        drop(writer);
        drop(child_request);

        sys::write_child_for_test(&child_response, &[0x46; KEY_AGENT_STARTUP_RESPONSE_BYTES])?;
        let after_frame = Arc::new(Barrier::new(2));
        let release_eof_read = Arc::new(Barrier::new(2));
        let reader_after_frame = Arc::clone(&after_frame);
        let reader_release = Arc::clone(&release_eof_read);
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(20))
            .ok_or("monotonic deadline overflow")?;
        let worker = std::thread::spawn(move || {
            reader.receive_with_after_frame_hook_for_test(deadline, || {
                reader_after_frame.wait();
                reader_release.wait();
            })
        });

        after_frame.wait();
        while Instant::now() < deadline {
            std::thread::yield_now();
        }
        drop(child_response);
        release_eof_read.wait();
        assert!(matches!(
            worker.join().map_err(|_| "response reader panicked")?,
            Err(PipeError::DeadlineElapsed)
        ));
        Ok(())
    }

    #[test]
    fn key_agent_full_response_without_eof_cancels_and_drains_at_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, child_request, reader, child_response) =
            PrivateKeyAgentPipes::create()?.into_test_parts();
        drop(child_request);
        sys::write_child_for_test(&child_response, &[0x56; KEY_AGENT_STARTUP_RESPONSE_BYTES])?;
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(20))
            .ok_or("monotonic deadline overflow")?;
        assert!(matches!(
            reader.receive(deadline),
            Err(PipeError::DeadlineElapsed)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(child_response);
        Ok(())
    }

    fn future_deadline() -> Result<Instant, Box<dyn std::error::Error>> {
        Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or_else(|| "monotonic deadline overflow".into())
    }

    #[test]
    fn approval_pipe_transfers_exact_request_and_response_without_names()
    -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateApprovalPipes::create()?;
        assert_eq!(
            format!("{pipes:?}"),
            "PrivateApprovalPipes { parent_request: \"[HANDLE]\", child_request: \"[HANDLE]\", parent_response: \"[HANDLE]\", child_response: \"[HANDLE]\" }"
        );
        let (writer, child_request, reader, child_response) = pipes.into_test_parts();
        let request = b"exact bounded request";
        writer.write_all(request, future_deadline()?)?;
        assert_eq!(sys::read_child_to_end_for_test(&child_request)?, request);
        drop(child_request);

        let response = [0x5a_u8; 75];
        sys::write_child_for_test(&child_response, &response)?;
        drop(child_response);
        assert_eq!(reader.read_exact_frame(75, future_deadline()?)?, response);
        Ok(())
    }

    #[test]
    fn approval_pipe_supports_staged_parent_authentication_then_exact_response_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateApprovalPipes::create()?;
        let (mut writer, child_request, reader, child_response) = pipes.into_test_parts();

        let parent_hello = [0x31_u8; 62];
        writer.write_bytes(&parent_hello, future_deadline()?)?;
        assert_eq!(
            sys::read_child_exact_for_test(&child_request, parent_hello.len())?,
            parent_hello
        );

        let child_hello = [0x42_u8; 106];
        sys::write_child_for_test(&child_response, &child_hello)?;
        assert_eq!(
            reader
                .read_exact(child_hello.len(), future_deadline()?)?
                .as_slice(),
            child_hello
        );

        let parent_finish = [0x53_u8; 128];
        writer.write_all(&parent_finish, future_deadline()?)?;
        assert_eq!(
            sys::read_child_to_end_for_test(&child_request)?,
            parent_finish
        );
        drop(child_request);

        let response = [0x64_u8; 75];
        sys::write_child_for_test(&child_response, &response)?;
        drop(child_response);
        assert_eq!(
            reader.read_exact_frame(response.len(), future_deadline()?)?,
            response
        );
        Ok(())
    }

    #[test]
    fn approval_pipe_rejects_truncation_and_delayed_trailing_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, child_request, reader, child_response) =
            PrivateApprovalPipes::create()?.into_test_parts();
        drop(child_request);
        sys::write_child_for_test(&child_response, &[7; 74])?;
        drop(child_response);
        assert_eq!(
            reader.read_exact_frame(75, future_deadline()?),
            Err(PipeError::UnexpectedEnd)
        );

        let (_, child_request, reader, child_response) =
            PrivateApprovalPipes::create()?.into_test_parts();
        drop(child_request);
        sys::write_child_for_test(&child_response, &[8; 76])?;
        drop(child_response);
        assert_eq!(
            reader.read_exact_frame(75, future_deadline()?),
            Err(PipeError::TrailingData)
        );
        Ok(())
    }

    #[test]
    fn secret_pipe_transfers_variable_response_through_exact_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateSecretInputPipes::create()?;
        assert_eq!(
            format!("{pipes:?}"),
            "PrivateSecretInputPipes { parent_request: \"[HANDLE]\", child_request: \"[HANDLE]\", parent_response: \"[HANDLE]\", child_response: \"[HANDLE]\" }"
        );
        let (writer, child_request, reader, child_response) = pipes.into_test_parts();
        let request = b"canonical secret prompt";
        writer.write_all(request, future_deadline()?)?;
        assert_eq!(sys::read_child_to_end_for_test(&child_request)?, request);
        drop(child_request);

        let response = [0x5a_u8; 41];
        sys::write_child_for_test(&child_response, &response)?;
        drop(child_response);
        assert_eq!(
            reader
                .read_bounded_to_end(41, future_deadline()?)?
                .as_slice(),
            response
        );
        Ok(())
    }

    #[test]
    fn recovery_pipe_supports_one_exact_two_nonce_handshake_then_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let pipes = PrivateSecretInputPipes::create()?;
        let (mut writer, child_request, reader, child_response) = pipes.into_test_parts();

        let display_hello = [0x41_u8; 62];
        writer.write_bytes(&display_hello, future_deadline()?)?;
        assert_eq!(
            sys::read_child_exact_for_test(&child_request, display_hello.len())?,
            display_hello
        );

        let child_hello = [0x52_u8; 106];
        sys::write_child_for_test(&child_response, &child_hello)?;
        assert_eq!(
            reader
                .read_exact(child_hello.len(), future_deadline()?)?
                .as_slice(),
            child_hello
        );

        let display_finish = [0x63_u8; 128];
        writer.write_all(&display_finish, future_deadline()?)?;
        assert_eq!(
            sys::read_child_to_end_for_test(&child_request)?,
            display_finish
        );
        drop(child_request);

        let acknowledgement = [0x74_u8; 124];
        sys::write_child_for_test(&child_response, &acknowledgement)?;
        drop(child_response);
        assert_eq!(
            reader
                .read_bounded_to_end(acknowledgement.len(), future_deadline()?)?
                .as_slice(),
            acknowledgement
        );
        Ok(())
    }

    #[test]
    fn frontend_child_servers_report_one_exact_parent_peer()
    -> Result<(), Box<dyn std::error::Error>> {
        let expected = (std::process::id(), sys::current_session_for_test()?);
        let (_, approval_request, _, approval_response) =
            PrivateApprovalPipes::create()?.into_test_parts();
        assert_eq!(
            sys::child_server_client_for_test(&approval_request)?,
            expected
        );
        assert_eq!(
            sys::child_server_client_for_test(&approval_response)?,
            expected
        );

        let (_, secret_request, _, secret_response) =
            PrivateSecretInputPipes::create()?.into_test_parts();
        assert_eq!(
            sys::child_server_client_for_test(&secret_request)?,
            expected
        );
        assert_eq!(
            sys::child_server_client_for_test(&secret_response)?,
            expected
        );
        Ok(())
    }

    #[test]
    fn secret_pipe_caps_at_maximum_plus_one_and_requires_eof()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, child_request, reader, child_response) =
            PrivateSecretInputPipes::create()?.into_test_parts();
        drop(child_request);
        sys::write_child_for_test(&child_response, &[0x33; 42])?;
        drop(child_response);
        assert!(matches!(
            reader.read_bounded_to_end(41, future_deadline()?),
            Err(PipeError::FrameTooLarge)
        ));
        Ok(())
    }

    #[test]
    fn approval_pipe_timeout_cancels_pending_read_before_buffer_scope_ends()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, child_request, reader, child_response) =
            PrivateApprovalPipes::create()?.into_test_parts();
        drop(child_request);
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(20))
            .ok_or("monotonic deadline overflow")?;
        assert_eq!(
            reader.read_exact_frame(75, deadline),
            Err(PipeError::DeadlineElapsed)
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(child_response);
        Ok(())
    }

    #[test]
    fn already_expired_pending_read_is_cancelled_and_drained_before_return()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, child_request, reader, child_response) =
            PrivateApprovalPipes::create()?.into_test_parts();
        drop(child_request);
        let started = Instant::now();
        let deadline = started
            .checked_sub(Duration::from_millis(1))
            .ok_or("monotonic deadline underflow")?;
        assert_eq!(
            reader.read_exact_frame(1, deadline),
            Err(PipeError::DeadlineElapsed)
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(child_response);
        Ok(())
    }

    #[test]
    fn secret_pipe_timeout_cancels_and_drains_before_zeroizing_buffer_drops()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_, child_request, reader, child_response) =
            PrivateSecretInputPipes::create()?.into_test_parts();
        drop(child_request);
        let started = Instant::now();
        let deadline = started
            .checked_add(Duration::from_millis(20))
            .ok_or("monotonic deadline overflow")?;
        assert!(matches!(
            reader.read_bounded_to_end(41, deadline),
            Err(PipeError::DeadlineElapsed)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(child_response);
        Ok(())
    }
}
