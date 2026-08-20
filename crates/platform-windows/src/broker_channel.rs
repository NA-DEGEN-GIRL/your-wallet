//! Dormant Windows-only native-host/Broker channel proof.
//!
//! This module proves only a one-shot, secretless, process-bound transport. It
//! is intentionally crate-private and no production entrypoint constructs it.
//! The following remain STOP-SHIP before activation:
//!
//! - exact mapped-image identity for the Chrome-launched native host;
//! - an exact, retained Broker child image and lifecycle proof;
//! - signed, immutable installation plus native-messaging registration;
//! - direct composition with `broker::ipc`'s nonce, sequence, 4,096-command,
//!   and typed schema contract (this crate deliberately has no `broker`
//!   dependency);
//! - any signing or Key Agent route.
//!
//! The transport implemented here matches only the Broker codec's four-byte
//! little-endian length prefix and 8 KiB payload ceiling. It never accepts a
//! raw handle or an externally supplied pipe name in production builds.

use core::fmt;
use std::time::Instant;

const MAX_BROKER_FRAME_BYTES: usize = 8_192;

/// Fail-closed categories for the dormant Broker channel.
pub(crate) enum BrokerChannelError {
    InvalidLabel,
    InvalidExpectedPeer,
    RandomnessUnavailable,
    OperatingSystemBoundary,
    InsecurePipe,
    PeerMismatch,
    PeerExited,
    DeadlineElapsed,
    UnexpectedEnd,
    InvalidFrame,
    FrameTooLarge,
}

impl fmt::Debug for BrokerChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLabel => "BrokerChannelError::InvalidLabel",
            Self::InvalidExpectedPeer => "BrokerChannelError::InvalidExpectedPeer",
            Self::RandomnessUnavailable => "BrokerChannelError::RandomnessUnavailable",
            Self::OperatingSystemBoundary => "BrokerChannelError::OperatingSystemBoundary",
            Self::InsecurePipe => "BrokerChannelError::InsecurePipe",
            Self::PeerMismatch => "BrokerChannelError::PeerMismatch",
            Self::PeerExited => "BrokerChannelError::PeerExited",
            Self::DeadlineElapsed => "BrokerChannelError::DeadlineElapsed",
            Self::UnexpectedEnd => "BrokerChannelError::UnexpectedEnd",
            Self::InvalidFrame => "BrokerChannelError::InvalidFrame",
            Self::FrameTooLarge => "BrokerChannelError::FrameTooLarge",
        })
    }
}

impl fmt::Display for BrokerChannelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidLabel => "invalid dormant Broker pipe label",
            Self::InvalidExpectedPeer => "invalid expected Broker peer",
            Self::RandomnessUnavailable => "secure pipe capability generation failed",
            Self::OperatingSystemBoundary => "Windows Broker channel boundary failed",
            Self::InsecurePipe => "private Broker pipe security proof failed",
            Self::PeerMismatch => "Broker pipe peer identity did not match",
            Self::PeerExited => "Broker pipe peer is no longer running",
            Self::DeadlineElapsed => "Broker pipe operation deadline elapsed",
            Self::UnexpectedEnd => "Broker pipe ended before a complete frame",
            Self::InvalidFrame => "Broker pipe frame was empty or malformed",
            Self::FrameTooLarge => "Broker pipe frame exceeded 8 KiB",
        })
    }
}

impl std::error::Error for BrokerChannelError {}

/// Exact retained process object expected at the other end of the pipe.
///
/// No production constructor accepts a PID or session number. A future exact
/// launcher must move its already-held, restricted process handle into this
/// token. That constructor intentionally does not exist while exact image and
/// launcher composition remain STOP-SHIP.
pub(crate) struct ExpectedBrokerPeer {
    process: sys::OwnedHandle,
    identity: sys::ProcessIdentity,
}

impl ExpectedBrokerPeer {
    #[cfg(test)]
    fn from_child_for_test(child: &std::process::Child) -> Result<Self, BrokerChannelError> {
        sys::expected_peer_from_child_for_test(child)
    }

    #[cfg(test)]
    fn from_inherited_parent_for_test() -> Result<Self, BrokerChannelError> {
        sys::expected_peer_from_inherited_parent_for_test()
    }
}

impl fmt::Debug for ExpectedBrokerPeer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExpectedBrokerPeer([REDACTED])")
    }
}

/// Move-only, unloggable capability naming the one available pipe instance.
pub(crate) struct BrokerEndpointCapability {
    name: sys::SecretPipeName,
}

impl BrokerEndpointCapability {
    /// Connects the client end and proves the exact retained server process.
    pub(crate) fn connect(
        self,
        expected_server: ExpectedBrokerPeer,
        deadline: Instant,
    ) -> Result<VerifiedBrokerChannel, BrokerChannelError> {
        sys::check_deadline(deadline)?;
        let pipe = sys::open_client(&self.name, deadline)?;
        let peer = sys::bind_server_peer(&pipe, expected_server, deadline)?;
        Ok(VerifiedBrokerChannel { pipe, peer })
    }

    #[cfg(test)]
    fn into_environment_value_for_test(self) -> std::ffi::OsString {
        self.name.into_environment_value_for_test()
    }

    #[cfg(test)]
    fn from_environment_value_for_test(
        value: &std::ffi::OsStr,
    ) -> Result<Self, BrokerChannelError> {
        Ok(Self {
            name: sys::SecretPipeName::from_environment_value_for_test(value)?,
        })
    }

    #[cfg(test)]
    fn second_instance_is_rejected_for_test(&self) -> Result<bool, BrokerChannelError> {
        sys::second_instance_is_rejected_for_test(&self.name)
    }
}

impl fmt::Debug for BrokerEndpointCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BrokerEndpointCapability([REDACTED])")
    }
}

/// Unconnected one-shot server end of the dormant Broker channel.
pub(crate) struct DormantBrokerPipe {
    pipe: sys::OwnedHandle,
}

impl DormantBrokerPipe {
    /// Creates a protected session-local endpoint and kernel-rechecks its owner
    /// and sole DACL entry before returning it.
    pub(crate) fn create(
        label: &str,
    ) -> Result<(Self, BrokerEndpointCapability), BrokerChannelError> {
        let local = sys::current_identity()?;
        let name = sys::SecretPipeName::generate(label, local.session_id)?;
        let security = sys::PipeSecurity::for_identity(&local)?;
        let pipe = sys::create_server(&name, &security)?;
        sys::verify_kernel_security(&pipe, &local)?;
        Ok((Self { pipe }, BrokerEndpointCapability { name }))
    }

    /// Accepts once before an absolute monotonic deadline and proves the exact
    /// retained client process, session, `TokenUser`, and logon SID.
    pub(crate) fn accept(
        self,
        expected_client: ExpectedBrokerPeer,
        deadline: Instant,
    ) -> Result<VerifiedBrokerChannel, BrokerChannelError> {
        sys::connect_server(&self.pipe, deadline)?;
        let peer = sys::bind_client_peer(&self.pipe, expected_client, deadline)?;
        Ok(VerifiedBrokerChannel {
            pipe: self.pipe,
            peer,
        })
    }

    #[cfg(test)]
    fn kernel_security_is_exact_for_test(&self) -> Result<bool, BrokerChannelError> {
        let local = sys::current_identity()?;
        Ok(sys::verify_kernel_security(&self.pipe, &local).is_ok())
    }

    #[cfg(test)]
    fn maximum_instances_for_test(&self) -> Result<u32, BrokerChannelError> {
        sys::maximum_instances_for_test(&self.pipe)
    }
}

impl fmt::Debug for DormantBrokerPipe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DormantBrokerPipe([OWNED])")
    }
}

/// Connected pipe whose peer process object remains held and is revalidated
/// before every underlying read or write operation.
pub(crate) struct VerifiedBrokerChannel {
    pipe: sys::OwnedHandle,
    peer: sys::PeerBinding,
}

impl VerifiedBrokerChannel {
    /// Writes one non-empty, length-prefixed secretless Broker transport frame.
    ///
    /// Ownership is returned only after complete success. Any error, including
    /// a timeout whose remote outcome is unknowable, drops the pipe and retained
    /// peer handle before returning.
    pub(crate) fn write_frame(
        self,
        payload: &[u8],
        deadline: Instant,
    ) -> Result<Self, BrokerChannelError> {
        self.write_frame_after_prefix(payload, deadline, || {})
    }

    fn write_frame_after_prefix<AfterPrefix>(
        self,
        payload: &[u8],
        deadline: Instant,
        after_prefix: AfterPrefix,
    ) -> Result<Self, BrokerChannelError>
    where
        AfterPrefix: FnOnce(),
    {
        sys::check_deadline(deadline)?;
        if payload.is_empty() {
            return Err(BrokerChannelError::InvalidFrame);
        }
        if payload.len() > MAX_BROKER_FRAME_BYTES {
            return Err(BrokerChannelError::FrameTooLarge);
        }
        let length = u32::try_from(payload.len()).map_err(|_| BrokerChannelError::FrameTooLarge)?;
        sys::write_all(&self.pipe, &self.peer, &length.to_le_bytes(), deadline)?;
        after_prefix();
        sys::write_all(&self.pipe, &self.peer, payload, deadline)?;
        Ok(self)
    }

    /// Reads one non-empty, length-prefixed secretless Broker transport frame.
    ///
    /// The channel is returned alongside the complete frame only on success.
    /// Any malformed, partial, peer, or deadline error consumes and closes it.
    pub(crate) fn read_frame(
        self,
        deadline: Instant,
    ) -> Result<(Self, Vec<u8>), BrokerChannelError> {
        sys::check_deadline(deadline)?;
        let mut prefix = [0_u8; 4];
        sys::read_exact(&self.pipe, &self.peer, &mut prefix, deadline)?;
        let length = usize::try_from(u32::from_le_bytes(prefix))
            .map_err(|_| BrokerChannelError::FrameTooLarge)?;
        if length == 0 {
            return Err(BrokerChannelError::InvalidFrame);
        }
        if length > MAX_BROKER_FRAME_BYTES {
            return Err(BrokerChannelError::FrameTooLarge);
        }
        let mut payload = vec![0_u8; length];
        sys::read_exact(&self.pipe, &self.peer, &mut payload, deadline)?;
        Ok((self, payload))
    }
}

impl fmt::Debug for VerifiedBrokerChannel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedBrokerChannel([BOUND])")
    }
}

mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;
    #[cfg(test)]
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    #[cfg(test)]
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle as StdOwnedHandle};
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{
        CloseHandle, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED,
        ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL, LocalFree, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    };
    #[cfg(test)]
    use windows::Win32::Foundation::{
        DUPLICATE_HANDLE_OPTIONS, DuplicateHandle, GetHandleInformation, HANDLE_FLAG_INHERIT,
    };
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
    };
    use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
        AclSizeInformation, DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetAclInformation,
        GetLengthSid, GetSecurityDescriptorControl, GetTokenInformation, IsValidAcl,
        IsValidSecurityDescriptor, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
        PSID, SE_DACL_AUTO_INHERIT_REQ, SE_DACL_AUTO_INHERITED, SE_DACL_DEFAULTED, SE_DACL_PRESENT,
        SE_DACL_PROTECTED, SE_OWNER_DEFAULTED, SE_SELF_RELATIVE, SECURITY_ATTRIBUTES,
        SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenSessionId,
        TokenUser,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ALL_ACCESS, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
        FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
        SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    };
    #[cfg(test)]
    use windows::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};
    use windows::Win32::System::IO::{
        CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
    };
    #[cfg(test)]
    use windows::Win32::System::Pipes::GetNamedPipeInfo;
    use windows::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
        GetNamedPipeClientSessionId, GetNamedPipeServerProcessId, GetNamedPipeServerSessionId,
        PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows::Win32::System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, SE_GROUP_LOGON_ID};
    use windows::Win32::System::Threading::{
        CreateEventW, GetCurrentProcess, GetProcessId, OpenProcessToken, WaitForSingleObject,
    };
    #[cfg(test)]
    use windows::Win32::System::Threading::{
        GetCurrentProcessId, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };
    use windows::core::{BOOL, HRESULT, PCWSTR, PWSTR};
    use zeroize::{Zeroize, Zeroizing};

    #[cfg(test)]
    use super::MAX_BROKER_FRAME_BYTES;
    use super::{BrokerChannelError, ExpectedBrokerPeer};

    const MIN_BINARY_SID_BYTES: usize = 8;
    const PIPE_BUFFER_BYTES: u32 = 8_192;

    pub(super) struct OwnedHandle(HANDLE);

    impl OwnedHandle {
        const fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: every instance owns one successful handle result exactly once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    pub(super) struct SecretPipeName {
        utf16_with_nul: Vec<u16>,
    }

    impl SecretPipeName {
        pub(super) fn generate(label: &str, session_id: u32) -> Result<Self, BrokerChannelError> {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            if label.is_empty()
                || label.len() > 24
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            {
                return Err(BrokerChannelError::InvalidLabel);
            }
            let mut random = [0_u8; 24];
            getrandom::fill(&mut random).map_err(|_| BrokerChannelError::RandomnessUnavailable)?;
            let mut token = Zeroizing::new(String::with_capacity(random.len() * 2));
            for byte in &random {
                token.push(char::from(HEX[usize::from(*byte >> 4)]));
                token.push(char::from(HEX[usize::from(*byte & 0x0f)]));
            }
            random.zeroize();
            let endpoint = Zeroizing::new(format!(
                r"\\.\pipe\LOCAL\your-wallet-broker-{label}-{session_id}-{}",
                token.as_str()
            ));
            let utf16_with_nul = endpoint.encode_utf16().chain(core::iter::once(0)).collect();
            Ok(Self { utf16_with_nul })
        }

        fn as_pcwstr(&self) -> PCWSTR {
            PCWSTR(self.utf16_with_nul.as_ptr())
        }

        #[cfg(test)]
        pub(super) fn into_environment_value_for_test(self) -> std::ffi::OsString {
            let without_nul = self
                .utf16_with_nul
                .get(..self.utf16_with_nul.len().saturating_sub(1))
                .unwrap_or_default();
            std::ffi::OsString::from_wide(without_nul)
        }

        #[cfg(test)]
        pub(super) fn from_environment_value_for_test(
            value: &std::ffi::OsStr,
        ) -> Result<Self, BrokerChannelError> {
            let mut utf16_with_nul: Vec<u16> = value.encode_wide().collect();
            if utf16_with_nul.is_empty()
                || utf16_with_nul.contains(&0)
                || !utf16_with_nul.starts_with(
                    &r"\\.\pipe\LOCAL\your-wallet-broker-"
                        .encode_utf16()
                        .collect::<Vec<_>>(),
                )
            {
                return Err(BrokerChannelError::InvalidLabel);
            }
            utf16_with_nul.push(0);
            Ok(Self { utf16_with_nul })
        }
    }

    impl Drop for SecretPipeName {
        fn drop(&mut self) {
            self.utf16_with_nul.zeroize();
        }
    }

    struct OwnedSid(Vec<u8>);

    impl OwnedSid {
        fn as_psid(&self) -> PSID {
            PSID(self.0.as_ptr().cast_mut().cast::<c_void>())
        }
    }

    impl Drop for OwnedSid {
        fn drop(&mut self) {
            self.0.fill(0);
        }
    }

    pub(super) struct ProcessIdentity {
        process_id: u32,
        pub(super) session_id: u32,
        token_user: OwnedSid,
        logon_sid: OwnedSid,
    }

    pub(super) struct PeerBinding {
        process: OwnedHandle,
        identity: ProcessIdentity,
    }

    impl PeerBinding {
        fn revalidate(&self) -> Result<(), BrokerChannelError> {
            ensure_process_running(&self.process)?;
            let current = identity_for_process(&self.process)?;
            if !same_identity(&current, &self.identity) {
                return Err(BrokerChannelError::PeerMismatch);
            }
            Ok(())
        }
    }

    pub(super) struct PipeSecurity {
        descriptor: PSECURITY_DESCRIPTOR,
    }

    impl PipeSecurity {
        pub(super) fn for_identity(identity: &ProcessIdentity) -> Result<Self, BrokerChannelError> {
            let owner = sid_to_string(&identity.token_user)?;
            let logon = sid_to_string(&identity.logon_sid)?;
            let sddl = format!("O:{owner}D:P(A;;FA;;;{logon})");
            let wide: Vec<u16> = sddl.encode_utf16().chain(core::iter::once(0)).collect();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            // SAFETY: input is NUL terminated; the returned LocalAlloc buffer is
            // retained by this owner and released only after pipe creation.
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    PCWSTR(wide.as_ptr()),
                    SDDL_REVISION_1,
                    &raw mut descriptor,
                    None,
                )
                .map_err(|_| BrokerChannelError::InsecurePipe)?;
            }
            if descriptor.0.is_null()
                // SAFETY: the conversion returned a purported complete descriptor.
                || !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool()
            {
                if !descriptor.0.is_null() {
                    // SAFETY: successful conversion uses LocalAlloc.
                    unsafe {
                        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
                    }
                }
                return Err(BrokerChannelError::InsecurePipe);
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
            // SAFETY: descriptor was allocated by the SDDL conversion API.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.descriptor.0)));
            }
        }
    }

    #[cfg(test)]
    pub(super) fn current_process_id() -> u32 {
        // SAFETY: this scalar query has no preconditions.
        unsafe { GetCurrentProcessId() }
    }

    pub(super) fn current_identity() -> Result<ProcessIdentity, BrokerChannelError> {
        // SAFETY: the current-process pseudo-handle remains valid for this process.
        identity_for_handle(unsafe { GetCurrentProcess() })
    }

    #[cfg(test)]
    pub(super) fn expected_peer_from_child_for_test(
        child: &std::process::Child,
    ) -> Result<ExpectedBrokerPeer, BrokerChannelError> {
        let source = HANDLE(child.as_raw_handle());
        let process = duplicate_restricted_process_handle(source, false)?;
        expected_peer_from_owned_handle(process)
    }

    #[cfg(test)]
    pub(super) fn expected_peer_from_inherited_parent_for_test()
    -> Result<ExpectedBrokerPeer, BrokerChannelError> {
        // SAFETY: the test launcher installs one restricted exact parent process
        // handle as the child's standard-input bootstrap slot.
        let source = unsafe { GetStdHandle(STD_INPUT_HANDLE) }
            .map_err(|_| BrokerChannelError::InvalidExpectedPeer)?;
        let process = duplicate_restricted_process_handle(source, false)?;
        expected_peer_from_owned_handle(process)
    }

    #[cfg(test)]
    pub(super) fn current_process_stdio_for_test() -> Result<std::process::Stdio, BrokerChannelError>
    {
        // SAFETY: the pseudo-handle names the exact current process object.
        process_handle_as_inherited_stdio(unsafe { GetCurrentProcess() })
    }

    #[cfg(test)]
    pub(super) fn child_process_stdio_for_test(
        child: &std::process::Child,
    ) -> Result<std::process::Stdio, BrokerChannelError> {
        process_handle_as_inherited_stdio(HANDLE(child.as_raw_handle()))
    }

    #[cfg(test)]
    fn process_handle_as_inherited_stdio(
        source: HANDLE,
    ) -> Result<std::process::Stdio, BrokerChannelError> {
        let process = duplicate_restricted_process_handle(source, true)?;
        let raw = process.raw().0;
        core::mem::forget(process);
        // SAFETY: ownership of the successful duplicate moves exactly once into
        // the standard library handle, then into Stdio for CreateProcess.
        let owned = unsafe { StdOwnedHandle::from_raw_handle(raw) };
        Ok(std::process::Stdio::from(owned))
    }

    #[cfg(test)]
    fn duplicate_restricted_process_handle(
        source: HANDLE,
        inheritable: bool,
    ) -> Result<OwnedHandle, BrokerChannelError> {
        let mut duplicate = HANDLE::default();
        let desired = (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE).0;
        // SAFETY: source is a retained process handle in this process. The exact
        // restricted duplicate is created into this process with no broader
        // rights and one explicit inheritance choice.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                &raw mut duplicate,
                desired,
                inheritable,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
            .map_err(|_| BrokerChannelError::InvalidExpectedPeer)?;
        }
        if duplicate.is_invalid() {
            return Err(BrokerChannelError::InvalidExpectedPeer);
        }
        let duplicate = OwnedHandle(duplicate);
        let mut flags = 0_u32;
        // SAFETY: the duplicate is live and output is initialized scalar storage.
        unsafe {
            GetHandleInformation(duplicate.raw(), &raw mut flags)
                .map_err(|_| BrokerChannelError::InvalidExpectedPeer)?;
        }
        let is_inheritable = flags & HANDLE_FLAG_INHERIT.0 != 0;
        if is_inheritable != inheritable {
            return Err(BrokerChannelError::InvalidExpectedPeer);
        }
        Ok(duplicate)
    }

    #[cfg(test)]
    fn expected_peer_from_owned_handle(
        process: OwnedHandle,
    ) -> Result<ExpectedBrokerPeer, BrokerChannelError> {
        ensure_process_running(&process)?;
        let identity = identity_for_process(&process)?;
        if identity.process_id == 0 || identity.process_id == current_process_id() {
            return Err(BrokerChannelError::InvalidExpectedPeer);
        }
        Ok(ExpectedBrokerPeer { process, identity })
    }

    fn identity_for_process(process: &OwnedHandle) -> Result<ProcessIdentity, BrokerChannelError> {
        // SAFETY: the retained process object remains live during this scalar query.
        let process_id = unsafe { GetProcessId(process.raw()) };
        if process_id == 0 {
            return Err(BrokerChannelError::PeerExited);
        }
        identity_for_handle(process.raw())
    }

    fn identity_for_handle(process: HANDLE) -> Result<ProcessIdentity, BrokerChannelError> {
        // SAFETY: the retained process object remains live during this query.
        let process_id = unsafe { GetProcessId(process) };
        if process_id == 0 {
            return Err(BrokerChannelError::PeerExited);
        }
        let mut token = HANDLE::default();
        // SAFETY: query-only access is requested from a live process handle.
        unsafe {
            OpenProcessToken(process, TOKEN_QUERY, &raw mut token)
                .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        }
        let token = OwnedHandle(token);
        let session_id = query_token_session(&token)?;
        let token_user = query_token_user(&token)?;
        let logon_sid = query_logon_sid(&token)?;
        Ok(ProcessIdentity {
            process_id,
            session_id,
            token_user,
            logon_sid,
        })
    }

    fn query_token_session(token: &OwnedHandle) -> Result<u32, BrokerChannelError> {
        let mut session_id = u32::MAX;
        let mut returned = 0_u32;
        // SAFETY: output has the exact TokenSessionId scalar size and the token
        // handle remains retained for the complete query.
        unsafe {
            GetTokenInformation(
                token.raw(),
                TokenSessionId,
                Some((&raw mut session_id).cast::<c_void>()),
                u32::try_from(size_of::<u32>()).unwrap_or(u32::MAX),
                &raw mut returned,
            )
            .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        }
        if returned != u32::try_from(size_of::<u32>()).unwrap_or(u32::MAX) || session_id == u32::MAX
        {
            return Err(BrokerChannelError::OperatingSystemBoundary);
        }
        Ok(session_id)
    }

    fn query_token_user(token: &OwnedHandle) -> Result<OwnedSid, BrokerChannelError> {
        let mut needed = 0_u32;
        // SAFETY: first call deliberately requests the required byte count.
        let _ = unsafe { GetTokenInformation(token.raw(), TokenUser, None, 0, &raw mut needed) };
        if needed < u32::try_from(size_of::<TOKEN_USER>()).unwrap_or(u32::MAX) {
            return Err(BrokerChannelError::OperatingSystemBoundary);
        }
        let mut buffer = aligned_buffer(needed)?;
        // SAFETY: aligned buffer is writable for at least `needed` bytes.
        unsafe {
            GetTokenInformation(
                token.raw(),
                TokenUser,
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                needed,
                &raw mut needed,
            )
            .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        }
        let token_user = buffer.as_ptr().cast::<TOKEN_USER>();
        // SAFETY: Windows initialized a complete TOKEN_USER record.
        copy_sid(unsafe { (*token_user).User.Sid })
    }

    fn query_logon_sid(token: &OwnedHandle) -> Result<OwnedSid, BrokerChannelError> {
        let mut needed = 0_u32;
        // SAFETY: first call deliberately requests the required byte count.
        let _ = unsafe { GetTokenInformation(token.raw(), TokenGroups, None, 0, &raw mut needed) };
        if needed < u32::try_from(size_of::<TOKEN_GROUPS>()).unwrap_or(u32::MAX) {
            return Err(BrokerChannelError::OperatingSystemBoundary);
        }
        let mut buffer = aligned_buffer(needed)?;
        // SAFETY: aligned buffer is writable for at least `needed` bytes.
        unsafe {
            GetTokenInformation(
                token.raw(),
                TokenGroups,
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                needed,
                &raw mut needed,
            )
            .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        }
        let groups = buffer.as_ptr().cast::<TOKEN_GROUPS>();
        // SAFETY: Windows initialized the TOKEN_GROUPS header.
        let count = usize::try_from(unsafe { (*groups).GroupCount })
            .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        let required = count
            .checked_mul(size_of::<SID_AND_ATTRIBUTES>())
            .and_then(|bytes| bytes.checked_add(core::mem::offset_of!(TOKEN_GROUPS, Groups)))
            .ok_or(BrokerChannelError::OperatingSystemBoundary)?;
        if required
            > usize::try_from(needed).map_err(|_| BrokerChannelError::OperatingSystemBoundary)?
        {
            return Err(BrokerChannelError::OperatingSystemBoundary);
        }
        // SAFETY: count was bounded by the initialized token buffer.
        let group_slice = unsafe {
            core::slice::from_raw_parts(
                ptr::addr_of!((*groups).Groups).cast::<SID_AND_ATTRIBUTES>(),
                count,
            )
        };
        let logon_flag = u32::from_ne_bytes(SE_GROUP_LOGON_ID.to_ne_bytes());
        let sid = group_slice
            .iter()
            .find(|group| group.Attributes & logon_flag == logon_flag)
            .ok_or(BrokerChannelError::OperatingSystemBoundary)?
            .Sid;
        copy_sid(sid)
    }

    fn aligned_buffer(bytes: u32) -> Result<Vec<usize>, BrokerChannelError> {
        let word_size = size_of::<usize>();
        let words = usize::try_from(bytes)
            .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?
            .checked_add(word_size.saturating_sub(1))
            .and_then(|rounded| rounded.checked_div(word_size))
            .ok_or(BrokerChannelError::OperatingSystemBoundary)?;
        Ok(vec![0_usize; words])
    }

    fn copy_sid(sid: PSID) -> Result<OwnedSid, BrokerChannelError> {
        // SAFETY: callers pass a SID pointer from a live token-info buffer.
        if sid.0.is_null() || !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(BrokerChannelError::OperatingSystemBoundary);
        }
        // SAFETY: IsValidSid accepted the complete SID.
        let length = usize::try_from(unsafe { GetLengthSid(sid) })
            .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        if !(MIN_BINARY_SID_BYTES..=256).contains(&length) {
            return Err(BrokerChannelError::OperatingSystemBoundary);
        }
        let mut copy = vec![0_u8; length];
        // SAFETY: source SID contains `length` bytes and destination has exactly
        // that writable capacity.
        unsafe {
            ptr::copy_nonoverlapping(sid.0.cast::<u8>(), copy.as_mut_ptr(), length);
        }
        Ok(OwnedSid(copy))
    }

    fn sid_to_string(sid: &OwnedSid) -> Result<String, BrokerChannelError> {
        let mut text = PWSTR::null();
        // SAFETY: owned SID is valid and live; output is LocalAlloc memory.
        unsafe {
            ConvertSidToStringSidW(sid.as_psid(), &raw mut text)
                .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        }
        // SAFETY: successful conversion returns a NUL-terminated allocation.
        let result =
            unsafe { text.to_string() }.map_err(|_| BrokerChannelError::OperatingSystemBoundary);
        // SAFETY: conversion allocated with LocalAlloc.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(text.0.cast::<c_void>())));
        }
        result
    }

    fn same_sid(first: &OwnedSid, second: &OwnedSid) -> bool {
        // SAFETY: both owned SID copies remain valid for this comparison.
        unsafe { EqualSid(first.as_psid(), second.as_psid()) }.is_ok()
    }

    fn same_identity(first: &ProcessIdentity, second: &ProcessIdentity) -> bool {
        first.process_id == second.process_id
            && first.session_id == second.session_id
            && same_sid(&first.token_user, &second.token_user)
            && same_sid(&first.logon_sid, &second.logon_sid)
    }

    pub(super) fn create_server(
        name: &SecretPipeName,
        security: &PipeSecurity,
    ) -> Result<OwnedHandle, BrokerChannelError> {
        let attributes = security.attributes();
        let open_mode = FILE_FLAGS_AND_ATTRIBUTES(
            PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_FIRST_PIPE_INSTANCE.0 | FILE_FLAG_OVERLAPPED.0,
        );
        let pipe_mode =
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS;
        // SAFETY: name and descriptor remain live for the complete call and are
        // not retained by the API.
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
            return Err(BrokerChannelError::OperatingSystemBoundary);
        }
        Ok(OwnedHandle(handle))
    }

    pub(super) fn open_client(
        name: &SecretPipeName,
        deadline: Instant,
    ) -> Result<OwnedHandle, BrokerChannelError> {
        check_deadline(deadline)?;
        let flags = FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION;
        // SAFETY: secret name is NUL terminated and retained through the call;
        // the already-created one-instance server makes this non-waiting.
        let handle = unsafe {
            CreateFileW(
                name.as_pcwstr(),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                flags,
                None,
            )
        }
        .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        let handle = OwnedHandle(handle);
        check_deadline(deadline)?;
        Ok(handle)
    }

    pub(super) fn connect_server(
        pipe: &OwnedHandle,
        deadline: Instant,
    ) -> Result<(), BrokerChannelError> {
        check_deadline(deadline)?;
        let event = create_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..OVERLAPPED::default()
        };
        // SAFETY: pipe, event, and OVERLAPPED remain live until immediate
        // completion or the pending operation is cancelled and drained.
        let started = unsafe { ConnectNamedPipe(pipe.raw(), Some(&raw mut overlapped)) };
        match started {
            Ok(()) => check_deadline(deadline),
            Err(error) if error.code() == ERROR_PIPE_CONNECTED.to_hresult() => {
                check_deadline(deadline)
            }
            Err(error) if error.code() == ERROR_IO_PENDING.to_hresult() => {
                complete_pending(pipe.raw(), &overlapped, deadline).map(|_| ())
            }
            Err(_) => Err(BrokerChannelError::OperatingSystemBoundary),
        }
    }

    pub(super) fn bind_client_peer(
        pipe: &OwnedHandle,
        expected: ExpectedBrokerPeer,
        deadline: Instant,
    ) -> Result<PeerBinding, BrokerChannelError> {
        let mut process_id = 0_u32;
        let mut session_id = u32::MAX;
        // SAFETY: connected server handle and output pointers remain valid.
        unsafe {
            GetNamedPipeClientProcessId(pipe.raw(), &raw mut process_id)
                .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
            GetNamedPipeClientSessionId(pipe.raw(), &raw mut session_id)
                .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        }
        bind_peer(process_id, session_id, expected, deadline)
    }

    pub(super) fn bind_server_peer(
        pipe: &OwnedHandle,
        expected: ExpectedBrokerPeer,
        deadline: Instant,
    ) -> Result<PeerBinding, BrokerChannelError> {
        let mut process_id = 0_u32;
        let mut session_id = u32::MAX;
        // SAFETY: connected client handle and output pointers remain valid.
        unsafe {
            GetNamedPipeServerProcessId(pipe.raw(), &raw mut process_id)
                .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
            GetNamedPipeServerSessionId(pipe.raw(), &raw mut session_id)
                .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        }
        bind_peer(process_id, session_id, expected, deadline)
    }

    fn bind_peer(
        process_id: u32,
        session_id: u32,
        expected: ExpectedBrokerPeer,
        deadline: Instant,
    ) -> Result<PeerBinding, BrokerChannelError> {
        check_deadline(deadline)?;
        ensure_process_running(&expected.process)?;
        let current = identity_for_process(&expected.process)?;
        if !same_identity(&current, &expected.identity)
            || process_id != current.process_id
            || session_id != current.session_id
        {
            return Err(BrokerChannelError::PeerMismatch);
        }
        let local = current_identity()?;
        if expected.identity.session_id != local.session_id
            || !same_sid(&expected.identity.token_user, &local.token_user)
            || !same_sid(&expected.identity.logon_sid, &local.logon_sid)
        {
            return Err(BrokerChannelError::PeerMismatch);
        }
        check_deadline(deadline)?;
        Ok(PeerBinding {
            process: expected.process,
            identity: expected.identity,
        })
    }

    fn ensure_process_running(process: &OwnedHandle) -> Result<(), BrokerChannelError> {
        // SAFETY: retained handle has SYNCHRONIZE access and remains live.
        match unsafe { WaitForSingleObject(process.raw(), 0) } {
            WAIT_TIMEOUT => Ok(()),
            WAIT_OBJECT_0 => Err(BrokerChannelError::PeerExited),
            _ => Err(BrokerChannelError::OperatingSystemBoundary),
        }
    }

    pub(super) fn write_all(
        pipe: &OwnedHandle,
        peer: &PeerBinding,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<(), BrokerChannelError> {
        let mut offset = 0_usize;
        while offset < bytes.len() {
            peer.revalidate()?;
            check_deadline(deadline)?;
            let written = write_once(pipe.raw(), &bytes[offset..], deadline)?;
            if written == 0 {
                return Err(BrokerChannelError::UnexpectedEnd);
            }
            offset = offset
                .checked_add(written)
                .ok_or(BrokerChannelError::OperatingSystemBoundary)?;
        }
        Ok(())
    }

    pub(super) fn read_exact(
        pipe: &OwnedHandle,
        peer: &PeerBinding,
        bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<(), BrokerChannelError> {
        let mut offset = 0_usize;
        while offset < bytes.len() {
            peer.revalidate()?;
            check_deadline(deadline)?;
            let read = read_once(pipe.raw(), &mut bytes[offset..], deadline)?;
            if read == 0 {
                return Err(BrokerChannelError::UnexpectedEnd);
            }
            offset = offset
                .checked_add(read)
                .ok_or(BrokerChannelError::OperatingSystemBoundary)?;
        }
        Ok(())
    }

    fn write_once(
        pipe: HANDLE,
        bytes: &[u8],
        deadline: Instant,
    ) -> Result<usize, BrokerChannelError> {
        let event = create_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..OVERLAPPED::default()
        };
        let mut immediate = 0_u32;
        // SAFETY: source, OVERLAPPED, event, and pipe remain live until pending
        // completion is cancelled and drained or reported complete.
        let started = unsafe {
            WriteFile(
                pipe,
                Some(bytes),
                Some(&raw mut immediate),
                Some(&raw mut overlapped),
            )
        };
        complete_io(pipe, &overlapped, started, immediate, deadline).and_then(|count| {
            usize::try_from(count).map_err(|_| BrokerChannelError::OperatingSystemBoundary)
        })
    }

    fn read_once(
        pipe: HANDLE,
        bytes: &mut [u8],
        deadline: Instant,
    ) -> Result<usize, BrokerChannelError> {
        let event = create_event()?;
        let mut overlapped = OVERLAPPED {
            hEvent: event.raw(),
            ..OVERLAPPED::default()
        };
        let mut immediate = 0_u32;
        // SAFETY: destination, OVERLAPPED, event, and pipe remain live until
        // pending completion is cancelled and drained or reported complete.
        let started = unsafe {
            ReadFile(
                pipe,
                Some(bytes),
                Some(&raw mut immediate),
                Some(&raw mut overlapped),
            )
        };
        complete_io(pipe, &overlapped, started, immediate, deadline).and_then(|count| {
            usize::try_from(count).map_err(|_| BrokerChannelError::OperatingSystemBoundary)
        })
    }

    fn complete_io(
        pipe: HANDLE,
        overlapped: &OVERLAPPED,
        started: windows::core::Result<()>,
        immediate: u32,
        deadline: Instant,
    ) -> Result<u32, BrokerChannelError> {
        match started {
            Ok(()) => deadline_result(immediate, deadline),
            Err(error) if error.code() == ERROR_IO_PENDING.to_hresult() => {
                complete_pending(pipe, overlapped, deadline)
            }
            Err(error) if is_pipe_end(error.code()) => Err(BrokerChannelError::UnexpectedEnd),
            Err(_) => Err(BrokerChannelError::OperatingSystemBoundary),
        }
    }

    fn complete_pending(
        pipe: HANDLE,
        overlapped: &OVERLAPPED,
        deadline: Instant,
    ) -> Result<u32, BrokerChannelError> {
        let timeout = remaining_milliseconds(deadline)?;
        let mut transferred = 0_u32;
        // SAFETY: initiating buffers, event, OVERLAPPED, and handle remain live.
        let completed = unsafe {
            GetOverlappedResultEx(
                pipe,
                ptr::from_ref(overlapped),
                &raw mut transferred,
                timeout,
                false,
            )
        };
        match completed {
            Ok(()) => deadline_result(transferred, deadline),
            Err(error) => {
                let code = error.code();
                cancel_and_drain(pipe, overlapped);
                if code == HRESULT::from_win32(WAIT_TIMEOUT.0) {
                    Err(BrokerChannelError::DeadlineElapsed)
                } else if is_pipe_end(code) {
                    Err(BrokerChannelError::UnexpectedEnd)
                } else {
                    Err(BrokerChannelError::OperatingSystemBoundary)
                }
            }
        }
    }

    fn cancel_and_drain(pipe: HANDLE, overlapped: &OVERLAPPED) {
        // SAFETY: exact pending operation is identified by this live OVERLAPPED.
        let _ = unsafe { CancelIoEx(pipe, Some(ptr::from_ref(overlapped))) };
        let mut ignored = 0_u32;
        // SAFETY: mandatory blocking drain prevents return while the kernel may
        // still reference the stack OVERLAPPED or its caller-owned buffer. Its
        // result is intentionally never converted into success for the timed-out
        // original operation.
        let _ =
            unsafe { GetOverlappedResult(pipe, ptr::from_ref(overlapped), &raw mut ignored, true) };
    }

    fn create_event() -> Result<OwnedHandle, BrokerChannelError> {
        // SAFETY: unnamed, non-inheritable manual-reset event is exclusively owned.
        let event = unsafe { CreateEventW(None, true, false, None) }
            .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        Ok(OwnedHandle(event))
    }

    pub(super) fn check_deadline(deadline: Instant) -> Result<(), BrokerChannelError> {
        if Instant::now() >= deadline {
            Err(BrokerChannelError::DeadlineElapsed)
        } else {
            Ok(())
        }
    }

    fn remaining_milliseconds(deadline: Instant) -> Result<u32, BrokerChannelError> {
        let now = Instant::now();
        if now >= deadline {
            return Err(BrokerChannelError::DeadlineElapsed);
        }
        let remaining = deadline.duration_since(now);
        let rounded = remaining
            .checked_add(Duration::from_nanos(999_999))
            .ok_or(BrokerChannelError::DeadlineElapsed)?
            .as_millis();
        u32::try_from(rounded.max(1)).map_err(|_| BrokerChannelError::OperatingSystemBoundary)
    }

    fn deadline_result(transferred: u32, deadline: Instant) -> Result<u32, BrokerChannelError> {
        check_deadline(deadline).map(|()| transferred)
    }

    fn is_pipe_end(code: HRESULT) -> bool {
        code == ERROR_BROKEN_PIPE.to_hresult() || code == ERROR_HANDLE_EOF.to_hresult()
    }

    pub(super) fn verify_kernel_security(
        pipe: &OwnedHandle,
        expected: &ProcessIdentity,
    ) -> Result<(), BrokerChannelError> {
        let mut owner = PSID::default();
        let mut dacl = ptr::null_mut::<ACL>();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: outputs remain valid; the returned descriptor is released below.
        let status = unsafe {
            GetSecurityInfo(
                pipe.raw(),
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&raw mut owner),
                None,
                Some(&raw mut dacl),
                None,
                Some(&raw mut descriptor),
            )
        };
        if status != ERROR_SUCCESS || descriptor.0.is_null() || owner.0.is_null() || dacl.is_null()
        {
            return Err(BrokerChannelError::InsecurePipe);
        }
        let result = inspect_exact_security(
            descriptor,
            owner,
            dacl,
            &expected.token_user,
            &expected.logon_sid,
        );
        // SAFETY: GetSecurityInfo allocated this descriptor with LocalAlloc.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        result
    }

    fn inspect_exact_security(
        descriptor: PSECURITY_DESCRIPTOR,
        owner: PSID,
        dacl: *mut ACL,
        expected_owner: &OwnedSid,
        expected_logon: &OwnedSid,
    ) -> Result<(), BrokerChannelError> {
        // SAFETY: descriptor is the live result of GetSecurityInfo.
        if !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool() {
            return Err(BrokerChannelError::InsecurePipe);
        }
        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: outputs and live descriptor have exact API types.
        unsafe {
            GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
                .map_err(|_| BrokerChannelError::InsecurePipe)?;
        }
        let protected = u16::from_ne_bytes(SE_DACL_PROTECTED.0.to_ne_bytes());
        let present = u16::from_ne_bytes(SE_DACL_PRESENT.0.to_ne_bytes());
        let relative = u16::from_ne_bytes(SE_SELF_RELATIVE.0.to_ne_bytes());
        let forbidden = u16::from_ne_bytes(SE_DACL_DEFAULTED.0.to_ne_bytes())
            | u16::from_ne_bytes(SE_OWNER_DEFAULTED.0.to_ne_bytes())
            | u16::from_ne_bytes(SE_DACL_AUTO_INHERITED.0.to_ne_bytes())
            | u16::from_ne_bytes(SE_DACL_AUTO_INHERIT_REQ.0.to_ne_bytes());
        if control & protected == 0
            || control & (present | relative) != (present | relative)
            || control & forbidden != 0
            || revision == 0
        {
            return Err(BrokerChannelError::InsecurePipe);
        }
        // SAFETY: owner belongs to the live descriptor and expected owner is an
        // owned valid SID copied from TokenUser.
        unsafe { EqualSid(owner, expected_owner.as_psid()) }
            .map_err(|_| BrokerChannelError::InsecurePipe)?;
        inspect_exact_dacl(dacl, expected_logon)
    }

    fn inspect_exact_dacl(
        dacl: *mut ACL,
        expected_logon: &OwnedSid,
    ) -> Result<(), BrokerChannelError> {
        // SAFETY: DACL is non-null and belongs to the live descriptor.
        if !unsafe { IsValidAcl(dacl) }.as_bool() {
            return Err(BrokerChannelError::InsecurePipe);
        }
        // SAFETY: IsValidAcl accepted the complete ACL header.
        let acl = unsafe { &*dacl };
        if u32::from(acl.AclRevision) != ACL_REVISION.0 || acl.Sbz1 != 0 || acl.Sbz2 != 0 {
            return Err(BrokerChannelError::InsecurePipe);
        }
        let mut information = ACL_SIZE_INFORMATION::default();
        // SAFETY: output has the documented exact size.
        unsafe {
            GetAclInformation(
                dacl,
                (&raw mut information).cast::<c_void>(),
                u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
                AclSizeInformation,
            )
            .map_err(|_| BrokerChannelError::InsecurePipe)?;
        }
        if information.AceCount != 1 {
            return Err(BrokerChannelError::InsecurePipe);
        }
        let mut ace = ptr::null_mut::<c_void>();
        // SAFETY: validated ACL reports an ACE at index zero.
        unsafe {
            GetAce(dacl, 0, &raw mut ace).map_err(|_| BrokerChannelError::InsecurePipe)?;
        }
        if ace.is_null() {
            return Err(BrokerChannelError::InsecurePipe);
        }
        inspect_exact_allow_ace(acl, &information, ace, expected_logon)
    }

    fn inspect_exact_allow_ace(
        acl: &ACL,
        information: &ACL_SIZE_INFORMATION,
        ace: *mut c_void,
        expected_logon: &OwnedSid,
    ) -> Result<(), BrokerChannelError> {
        // SAFETY: IsValidAcl and GetAce proved the common ACE header exists.
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        let ace_size = usize::from(header.AceSize);
        let exact_acl_bytes = size_of::<ACL>()
            .checked_add(ace_size)
            .ok_or(BrokerChannelError::InsecurePipe)?;
        if usize::try_from(information.AclBytesInUse)
            .map_err(|_| BrokerChannelError::InsecurePipe)?
            != exact_acl_bytes
            || information.AclBytesFree != 0
            || usize::from(acl.AclSize) != exact_acl_bytes
        {
            return Err(BrokerChannelError::InsecurePipe);
        }
        let sid_offset = core::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        if header.AceType != u8::try_from(ACCESS_ALLOWED_ACE_TYPE).unwrap_or(u8::MAX)
            || header.AceFlags != 0
            || ace_size < sid_offset.saturating_add(MIN_BINARY_SID_BYTES)
        {
            return Err(BrokerChannelError::InsecurePipe);
        }
        // SAFETY: type and size prove the fixed ACCESS_ALLOWED_ACE fields exist.
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        if allowed.Mask != FILE_ALL_ACCESS.0 {
            return Err(BrokerChannelError::InsecurePipe);
        }
        let sid_bytes = ptr::addr_of!(allowed.SidStart).cast::<u8>();
        let available = ace_size.saturating_sub(sid_offset);
        // SAFETY: minimum SID header includes the SubAuthorityCount byte.
        let count = usize::from(unsafe { *sid_bytes.add(1) });
        let declared = count
            .checked_mul(size_of::<u32>())
            .and_then(|bytes| bytes.checked_add(MIN_BINARY_SID_BYTES))
            .ok_or(BrokerChannelError::InsecurePipe)?;
        if available != declared {
            return Err(BrokerChannelError::InsecurePipe);
        }
        let actual = PSID(sid_bytes.cast_mut().cast::<c_void>());
        // SAFETY: declared SID was proven to fit exactly in the valid ACE.
        if !unsafe { IsValidSid(actual) }.as_bool()
            // SAFETY: the valid SID remains inside the live ACE.
            || usize::try_from(unsafe { GetLengthSid(actual) })
                .map_err(|_| BrokerChannelError::InsecurePipe)?
                != declared
        {
            return Err(BrokerChannelError::InsecurePipe);
        }
        // SAFETY: actual and expected logon SID are valid and live.
        unsafe { EqualSid(actual, expected_logon.as_psid()) }
            .map_err(|_| BrokerChannelError::InsecurePipe)
    }

    #[cfg(test)]
    pub(super) fn second_instance_is_rejected_for_test(
        name: &SecretPipeName,
    ) -> Result<bool, BrokerChannelError> {
        let identity = current_identity()?;
        let security = PipeSecurity::for_identity(&identity)?;
        Ok(create_server(name, &security).is_err())
    }

    #[cfg(test)]
    pub(super) fn maximum_instances_for_test(
        pipe: &OwnedHandle,
    ) -> Result<u32, BrokerChannelError> {
        let mut maximum = 0_u32;
        // SAFETY: server handle remains live and output is initialized storage.
        unsafe {
            GetNamedPipeInfo(pipe.raw(), None, None, None, Some(&raw mut maximum))
                .map_err(|_| BrokerChannelError::OperatingSystemBoundary)?;
        }
        Ok(maximum)
    }

    #[cfg(test)]
    pub(super) const fn creation_pipe_mode_for_test() -> u32 {
        PIPE_TYPE_BYTE.0 | PIPE_READMODE_BYTE.0 | PIPE_WAIT.0 | PIPE_REJECT_REMOTE_CLIENTS.0
    }

    #[cfg(test)]
    pub(super) const fn creation_open_mode_for_test() -> u32 {
        PIPE_ACCESS_DUPLEX.0 | FILE_FLAG_FIRST_PIPE_INSTANCE.0 | FILE_FLAG_OVERLAPPED.0
    }

    #[cfg(test)]
    pub(super) const fn frame_limit_for_test() -> usize {
        MAX_BROKER_FRAME_BYTES
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::time::{Duration, Instant};

    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    };
    use windows::Win32::System::Pipes::PIPE_REJECT_REMOTE_CLIENTS;
    use windows::Win32::System::Threading::CREATE_NO_WINDOW;

    use super::{
        BrokerChannelError, BrokerEndpointCapability, DormantBrokerPipe, ExpectedBrokerPeer,
        MAX_BROKER_FRAME_BYTES, VerifiedBrokerChannel, sys,
    };

    const CHILD_MODE: &str = "YOUR_WALLET_BROKER_CHANNEL_TEST_MODE";
    const CHILD_ENDPOINT: &str = "YOUR_WALLET_BROKER_CHANNEL_TEST_ENDPOINT";
    const CHILD_HELPER_NAME: &str = "broker_channel::tests::broker_channel_child_helper";

    #[derive(Clone, Copy)]
    enum ExpectedServerBootstrap<'child> {
        CurrentProcess,
        Child(&'child Child),
    }

    struct ChildGuard(Option<Child>);

    impl ChildGuard {
        fn child(&self) -> Result<&Child, Box<dyn std::error::Error>> {
            self.0
                .as_ref()
                .ok_or_else(|| "child process was already reaped".into())
        }

        fn wait(mut self) -> Result<ExitStatus, Box<dyn std::error::Error>> {
            self.wait_in_place()
        }

        fn wait_in_place(&mut self) -> Result<ExitStatus, Box<dyn std::error::Error>> {
            let mut child = self.0.take().ok_or("child process was already reaped")?;
            Ok(child.wait()?)
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if let Some(child) = &mut self.0 {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }

    #[test]
    fn private_kernel_policy_and_consuming_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let (server, endpoint) = DormantBrokerPipe::create("round-trip")?;
        assert!(server.kernel_security_is_exact_for_test()?);
        assert_eq!(server.maximum_instances_for_test()?, 1);
        assert!(endpoint.second_instance_is_rejected_for_test()?);
        assert_eq!(
            sys::creation_open_mode_for_test() & FILE_FLAG_FIRST_PIPE_INSTANCE.0,
            FILE_FLAG_FIRST_PIPE_INSTANCE.0
        );
        assert_eq!(
            sys::creation_open_mode_for_test() & FILE_FLAG_OVERLAPPED.0,
            FILE_FLAG_OVERLAPPED.0
        );
        assert_eq!(
            sys::creation_pipe_mode_for_test() & PIPE_REJECT_REMOTE_CLIENTS.0,
            PIPE_REJECT_REMOTE_CLIENTS.0
        );
        assert_eq!(sys::frame_limit_for_test(), MAX_BROKER_FRAME_BYTES);
        assert_eq!(format!("{server:?}"), "DormantBrokerPipe([OWNED])");
        assert_eq!(
            format!("{endpoint:?}"),
            "BrokerEndpointCapability([REDACTED])"
        );

        let endpoint_value = endpoint.into_environment_value_for_test();
        assert!(
            endpoint_value
                .to_string_lossy()
                .starts_with(r"\\.\pipe\LOCAL\your-wallet-broker-")
        );
        let child = spawn_child(
            "round-trip",
            Some(&endpoint_value),
            ExpectedServerBootstrap::CurrentProcess,
        )?;
        let expected = expected_child(&child)?;
        assert_eq!(format!("{expected:?}"), "ExpectedBrokerPeer([REDACTED])");
        let channel = server.accept(expected, deadline_after(5_000)?)?;
        assert_eq!(format!("{channel:?}"), "VerifiedBrokerChannel([BOUND])");

        let maximum = vec![0xa5_u8; MAX_BROKER_FRAME_BYTES];
        let channel = channel.write_frame(&maximum, deadline_after(5_000)?)?;
        let (channel, response) = channel.read_frame(deadline_after(5_000)?)?;
        assert_eq!(response, b"max-ok");
        let channel = channel.write_frame(b"ping", deadline_after(5_000)?)?;
        let (_channel, response) = channel.read_frame(deadline_after(5_000)?)?;
        assert_eq!(response, b"pong");

        assert!(child.wait()?.success());
        Ok(())
    }

    #[test]
    fn inclusive_connect_deadline_discards_the_unbound_pipe()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            sys::check_deadline(Instant::now()),
            Err(BrokerChannelError::DeadlineElapsed)
        ));
        let (server, endpoint) = DormantBrokerPipe::create("connect-timeout")?;
        drop(endpoint);
        let child = spawn_child("idle", None, ExpectedServerBootstrap::CurrentProcess)?;
        let expected = expected_child(&child)?;
        let started = Instant::now();
        let result = server.accept(expected, deadline_after(40)?);
        assert!(matches!(result, Err(BrokerChannelError::DeadlineElapsed)));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(child);
        Ok(())
    }

    #[test]
    fn timed_out_read_discards_channel_and_late_completion_cannot_succeed()
    -> Result<(), Box<dyn std::error::Error>> {
        let (child, channel) = connected_child("delayed-frame")?;
        assert!(matches!(
            channel.read_frame(deadline_after(40)?),
            Err(BrokerChannelError::DeadlineElapsed)
        ));
        assert!(child.wait()?.success());
        Ok(())
    }

    #[test]
    fn retained_exited_process_object_fails_closed_before_io()
    -> Result<(), Box<dyn std::error::Error>> {
        let (child, channel) = connected_child("exit-after-connect")?;
        assert!(child.wait()?.success());
        assert!(matches!(
            channel.write_frame(b"must-not-send", deadline_after(1_000)?),
            Err(BrokerChannelError::PeerExited)
        ));
        Ok(())
    }

    #[test]
    fn server_rejects_a_different_retained_client_process_object()
    -> Result<(), Box<dyn std::error::Error>> {
        let decoy = spawn_child("idle", None, ExpectedServerBootstrap::CurrentProcess)?;
        let (server, endpoint) = DormantBrokerPipe::create("wrong-client")?;
        let endpoint_value = endpoint.into_environment_value_for_test();
        let connector = spawn_child(
            "connect-and-wait",
            Some(&endpoint_value),
            ExpectedServerBootstrap::CurrentProcess,
        )?;
        let expected_decoy = ExpectedBrokerPeer::from_child_for_test(decoy.child()?)?;
        assert!(matches!(
            server.accept(expected_decoy, deadline_after(5_000)?),
            Err(BrokerChannelError::PeerMismatch)
        ));
        drop(connector);
        drop(decoy);
        Ok(())
    }

    #[test]
    fn client_rejects_a_different_retained_server_process_object()
    -> Result<(), Box<dyn std::error::Error>> {
        let decoy = spawn_child("idle", None, ExpectedServerBootstrap::CurrentProcess)?;
        let (server, endpoint) = DormantBrokerPipe::create("wrong-server")?;
        let endpoint_value = endpoint.into_environment_value_for_test();
        let connector = spawn_child(
            "wrong-server",
            Some(&endpoint_value),
            ExpectedServerBootstrap::Child(decoy.child()?),
        )?;
        assert!(connector.wait()?.success());
        drop(server);
        drop(decoy);
        Ok(())
    }

    #[test]
    fn exited_original_child_handle_cannot_be_replaced_by_a_pid_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut exited = spawn_child("exit-soon", None, ExpectedServerBootstrap::CurrentProcess)?;
        let expected_exited = ExpectedBrokerPeer::from_child_for_test(exited.child()?)?;
        assert!(exited.wait_in_place()?.success());

        let (server, endpoint) = DormantBrokerPipe::create("exited-object")?;
        let endpoint_value = endpoint.into_environment_value_for_test();
        let connector = spawn_child(
            "connect-and-wait",
            Some(&endpoint_value),
            ExpectedServerBootstrap::CurrentProcess,
        )?;
        assert!(matches!(
            server.accept(expected_exited, deadline_after(5_000)?),
            Err(BrokerChannelError::PeerExited)
        ));
        drop(connector);
        Ok(())
    }

    #[test]
    fn empty_or_oversized_local_write_consumes_and_closes_channel()
    -> Result<(), Box<dyn std::error::Error>> {
        let (child, channel) = connected_child("observe-close")?;
        assert!(matches!(
            channel.write_frame(&[], deadline_after(1_000)?),
            Err(BrokerChannelError::InvalidFrame)
        ));
        assert!(child.wait()?.success());

        let (child, channel) = connected_child("observe-close")?;
        let oversized = vec![0_u8; MAX_BROKER_FRAME_BYTES + 1];
        assert!(matches!(
            channel.write_frame(&oversized, deadline_after(1_000)?),
            Err(BrokerChannelError::FrameTooLarge)
        ));
        assert!(child.wait()?.success());
        Ok(())
    }

    #[test]
    fn malformed_prefix_then_valid_frame_attempt_is_closed_not_reused()
    -> Result<(), Box<dyn std::error::Error>> {
        let (child, channel) = connected_child("zero-then-valid")?;
        assert!(matches!(
            channel.read_frame(deadline_after(5_000)?),
            Err(BrokerChannelError::InvalidFrame)
        ));
        assert!(child.wait()?.success());

        let (child, channel) = connected_child("oversized-then-valid")?;
        assert!(matches!(
            channel.read_frame(deadline_after(5_000)?),
            Err(BrokerChannelError::FrameTooLarge)
        ));
        assert!(child.wait()?.success());
        Ok(())
    }

    #[test]
    fn partial_prefix_or_payload_timeout_discards_and_closes_channel()
    -> Result<(), Box<dyn std::error::Error>> {
        let (child, channel) = connected_child("partial-prefix")?;
        assert!(matches!(
            channel.read_frame(deadline_after(40)?),
            Err(BrokerChannelError::DeadlineElapsed)
        ));
        assert!(child.wait()?.success());

        let (child, channel) = connected_child("partial-payload")?;
        assert!(matches!(
            channel.read_frame(deadline_after(40)?),
            Err(BrokerChannelError::DeadlineElapsed)
        ));
        assert!(child.wait()?.success());
        Ok(())
    }

    #[test]
    fn partial_write_error_consumes_channel_after_prefix() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut child, channel) = connected_child("close-after-prefix")?;
        let mut child_exited = false;
        let result = channel.write_frame_after_prefix(
            b"payload-after-prefix",
            deadline_after(5_000)?,
            || {
                child_exited = child.wait_in_place().is_ok_and(|status| status.success());
            },
        );
        assert!(child_exited);
        assert!(matches!(result, Err(BrokerChannelError::PeerExited)));
        Ok(())
    }

    #[test]
    fn production_source_has_no_pid_constructor_or_reopen_race() {
        let source = include_str!("broker_channel.rs");
        let production_api = source.split("mod sys {").next().unwrap_or_default();
        let open_by_pid = ["Open", "Process("].concat();
        let pid_session_lookup = ["ProcessId", "ToSessionId"].concat();

        assert!(!production_api.contains("process_id: u32"));
        assert!(!production_api.contains("session_id: u32"));
        assert!(!production_api.contains("ExpectedBrokerPeer::new"));
        assert!(!source.contains(&open_by_pid));
        assert!(!source.contains(&pid_session_lookup));
        assert!(production_api.contains("process: sys::OwnedHandle"));
        assert!(production_api.contains("identity: sys::ProcessIdentity"));
        assert!(production_api.contains("write_frame(\n        self,"));
        assert!(production_api.contains("read_frame(\n        self,"));
        assert!(!production_api.contains("read_frame(\n        &mut self,"));
    }

    #[test]
    #[ignore = "invoked only as a subprocess by Broker channel kernel tests"]
    fn broker_channel_child_helper() -> Result<(), Box<dyn std::error::Error>> {
        let Some(mode) = std::env::var_os(CHILD_MODE) else {
            return Ok(());
        };
        if mode == OsStr::new("idle") {
            std::thread::sleep(Duration::from_secs(5));
            return Ok(());
        }
        if mode == OsStr::new("exit-soon") {
            std::thread::sleep(Duration::from_millis(120));
            return Ok(());
        }
        if mode == OsStr::new("wrong-server") {
            let endpoint = endpoint_from_environment()?;
            let expected = ExpectedBrokerPeer::from_inherited_parent_for_test()?;
            assert!(matches!(
                endpoint.connect(expected, deadline_after(5_000)?),
                Err(BrokerChannelError::PeerMismatch)
            ));
            return Ok(());
        }

        let channel = connect_to_parent()?;
        match mode.to_string_lossy().as_ref() {
            "round-trip" => {
                let (channel, maximum) = channel.read_frame(deadline_after(5_000)?)?;
                assert_eq!(maximum.len(), MAX_BROKER_FRAME_BYTES);
                assert!(maximum.iter().all(|byte| *byte == 0xa5));
                let channel = channel.write_frame(b"max-ok", deadline_after(5_000)?)?;
                let (channel, request) = channel.read_frame(deadline_after(5_000)?)?;
                assert_eq!(request, b"ping");
                let _channel = channel.write_frame(b"pong", deadline_after(5_000)?)?;
            }
            "delayed-frame" => {
                std::thread::sleep(Duration::from_millis(180));
                assert!(
                    channel
                        .write_frame(b"late", deadline_after(5_000)?)
                        .is_err()
                );
            }
            "exit-after-connect" => {
                std::thread::sleep(Duration::from_millis(120));
            }
            "connect-and-wait" => {
                std::thread::sleep(Duration::from_secs(5));
            }
            "observe-close" => {
                expect_peer_closed(&channel)?;
            }
            "zero-then-valid" => {
                raw_write(&channel, &0_u32.to_le_bytes())?;
                assert_later_valid_frame_is_rejected(&channel);
            }
            "oversized-then-valid" => {
                let oversized = u32::try_from(MAX_BROKER_FRAME_BYTES + 1)?;
                raw_write(&channel, &oversized.to_le_bytes())?;
                assert_later_valid_frame_is_rejected(&channel);
            }
            "partial-prefix" => {
                raw_write(&channel, &[4_u8, 0_u8])?;
                std::thread::sleep(Duration::from_millis(180));
                assert!(raw_write(&channel, &[0_u8, 0_u8]).is_err());
            }
            "partial-payload" => {
                raw_write(&channel, &4_u32.to_le_bytes())?;
                raw_write(&channel, b"pa")?;
                std::thread::sleep(Duration::from_millis(180));
                assert!(raw_write(&channel, b"rt").is_err());
            }
            "close-after-prefix" => {
                let mut prefix = [0_u8; 4];
                sys::read_exact(
                    &channel.pipe,
                    &channel.peer,
                    &mut prefix,
                    deadline_after(5_000)?,
                )?;
                assert_eq!(u32::from_le_bytes(prefix), 20);
            }
            _ => return Err("unknown Broker channel subprocess mode".into()),
        }
        Ok(())
    }

    fn connected_child(
        mode: &str,
    ) -> Result<(ChildGuard, VerifiedBrokerChannel), Box<dyn std::error::Error>> {
        let (server, endpoint) = DormantBrokerPipe::create("fixture")?;
        let endpoint_value = endpoint.into_environment_value_for_test();
        let child = spawn_child(
            mode,
            Some(&endpoint_value),
            ExpectedServerBootstrap::CurrentProcess,
        )?;
        let expected = expected_child(&child)?;
        let channel = server.accept(expected, deadline_after(5_000)?)?;
        Ok((child, channel))
    }

    fn connect_to_parent() -> Result<VerifiedBrokerChannel, Box<dyn std::error::Error>> {
        let endpoint = endpoint_from_environment()?;
        let expected = ExpectedBrokerPeer::from_inherited_parent_for_test()?;
        Ok(endpoint.connect(expected, deadline_after(5_000)?)?)
    }

    fn endpoint_from_environment() -> Result<BrokerEndpointCapability, Box<dyn std::error::Error>> {
        let endpoint = required_environment(CHILD_ENDPOINT)?;
        Ok(BrokerEndpointCapability::from_environment_value_for_test(
            &endpoint,
        )?)
    }

    fn raw_write(channel: &VerifiedBrokerChannel, bytes: &[u8]) -> Result<(), BrokerChannelError> {
        sys::write_all(
            &channel.pipe,
            &channel.peer,
            bytes,
            Instant::now()
                .checked_add(Duration::from_secs(5))
                .ok_or(BrokerChannelError::DeadlineElapsed)?,
        )
    }

    fn expect_peer_closed(
        channel: &VerifiedBrokerChannel,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut byte = [0_u8; 1];
        assert!(matches!(
            sys::read_exact(
                &channel.pipe,
                &channel.peer,
                &mut byte,
                deadline_after(5_000)?
            ),
            Err(BrokerChannelError::UnexpectedEnd)
        ));
        Ok(())
    }

    fn assert_later_valid_frame_is_rejected(channel: &VerifiedBrokerChannel) {
        std::thread::sleep(Duration::from_millis(120));
        let valid_prefix = 4_u32.to_le_bytes();
        assert!(raw_write(channel, &valid_prefix).is_err());
    }

    fn spawn_child(
        mode: &str,
        endpoint: Option<&OsStr>,
        expected_server: ExpectedServerBootstrap<'_>,
    ) -> Result<ChildGuard, Box<dyn std::error::Error>> {
        let executable = std::env::current_exe()?;
        let stdin = match expected_server {
            ExpectedServerBootstrap::CurrentProcess => sys::current_process_stdio_for_test()?,
            ExpectedServerBootstrap::Child(child) => sys::child_process_stdio_for_test(child)?,
        };
        let mut command = Command::new(executable);
        command
            .arg("--ignored")
            .arg("--exact")
            .arg(CHILD_HELPER_NAME)
            .env(CHILD_MODE, mode)
            .stdin(stdin)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(CREATE_NO_WINDOW.0);
        if let Some(endpoint) = endpoint {
            command.env(CHILD_ENDPOINT, endpoint);
        } else {
            command.env_remove(CHILD_ENDPOINT);
        }
        Ok(ChildGuard(Some(command.spawn()?)))
    }

    fn expected_child(
        child: &ChildGuard,
    ) -> Result<ExpectedBrokerPeer, Box<dyn std::error::Error>> {
        Ok(ExpectedBrokerPeer::from_child_for_test(child.child()?)?)
    }

    fn deadline_after(milliseconds: u64) -> Result<Instant, Box<dyn std::error::Error>> {
        Instant::now()
            .checked_add(Duration::from_millis(milliseconds))
            .ok_or_else(|| "monotonic deadline overflow".into())
    }

    fn required_environment(name: &str) -> Result<OsString, Box<dyn std::error::Error>> {
        std::env::var_os(name).ok_or_else(|| "subprocess environment was incomplete".into())
    }
}
