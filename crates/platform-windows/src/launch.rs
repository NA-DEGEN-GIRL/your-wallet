//! Restricted one-shot helper launcher.
//!
//! The low-level Win32 launcher uses separate persistent, revision-bound LPAC
//! profiles for the manifest-derived Approval and Secret Input roles. Both have
//! zero capability SIDs, opt out of `ALL APPLICATION PACKAGES`, receive an
//! explicit inherited-handle list and minimal environment, start suspended,
//! verify the resulting `AppContainer` token, and enter a kill-on-close
//! single-process job before resume. There is deliberately no unsandboxed
//! fallback. Public launch also remains disabled until release evidence for the
//! exact signed artifact is compiled into [`ReleaseAttestation`].

use core::fmt;
#[cfg(windows)]
use std::time::Instant;

use thiserror::Error;

use crate::attestation::ReleaseAttestation;
use crate::helper::{FileIdentity, VerifiedHelper};

/// A helper sandbox profile with no network capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NoNetworkLpacProfile {
    profile_revision: u32,
}

impl NoNetworkLpacProfile {
    /// The only profile accepted by the one-shot helper launcher.
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            profile_revision: 1,
        }
    }

    /// Returns the revision bound into the deterministic profile name and held
    /// process identity.
    #[must_use]
    pub const fn revision(self) -> u32 {
        self.profile_revision
    }
}

/// LPAC role proof derived exclusively from [`VerifiedHelper`]'s authenticated
/// release-manifest role. It is deliberately private: callers select a launch
/// entry point, never an `AppContainer` identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifiedLpacRole {
    ApprovalFrontend,
    SecretInputFrontend,
}

impl VerifiedLpacRole {
    fn from_helper(helper: &VerifiedHelper) -> Result<Self, LaunchError> {
        if helper.is_approval_frontend() {
            return Ok(Self::ApprovalFrontend);
        }
        if helper.is_secret_input_frontend() {
            return Ok(Self::SecretInputFrontend);
        }
        if helper.is_key_agent() {
            return Err(LaunchError::KeyAgentRequiresSupervisorActivation);
        }
        Err(LaunchError::HelperRoleNotAllowed)
    }

    const fn inherits_parent_proof(self) -> bool {
        matches!(self, Self::SecretInputFrontend)
    }
}

/// Errors from explicit handle selection or restricted process creation.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum LaunchError {
    /// One of the supplied handles was invalid.
    #[error("invalid inherited handle")]
    InvalidHandle,
    /// The release artifact has not passed every mandatory boundary test.
    #[error("Windows release boundary attestation is incomplete")]
    ReleaseNotAttested,
    /// The Key Agent may be created only by the private supervisor activation
    /// seam that authenticates the mapped image before user-mode execution.
    #[error("Key Agent requires private supervisor activation")]
    KeyAgentRequiresSupervisorActivation,
    /// The verified manifest role is not accepted by the selected launch entry
    /// point.
    #[error("verified helper role is not allowed by this launch entry point")]
    HelperRoleNotAllowed,
    /// The helper manifest is not one of the three exact release-bound helpers.
    #[error("helper manifest is absent from the compiled release allowlist")]
    HelperManifestNotAllowed,
    /// The LPAC profile revision is not one compiled into this launcher.
    #[error("unknown no-network LPAC profile revision")]
    InvalidProfile,
    /// The selected current directory is not an immutable system directory.
    #[error("restricted helper working directory is unsafe")]
    UnsafeWorkingDirectory,
    /// The suspended child did not have the exact expected `AppContainer` token.
    #[error("restricted helper token verification failed")]
    SandboxVerification,
    /// A Win32 process, job, or attribute-list operation failed.
    #[error("restricted Windows helper launch failed")]
    OperatingSystem,
    /// A held helper did not exit within its caller-supplied monotonic deadline.
    #[error("restricted helper termination deadline elapsed")]
    TerminationDeadlineElapsed,
    /// This launcher is available only on Windows.
    #[error("Windows restricted launcher is unavailable on this platform")]
    UnsupportedPlatform,
}

/// The three standard handles made visible to a helper.
///
/// The underlying values are never formatted or logged. Repeated handles are
/// de-duplicated in the Win32 allowlist while preserving their stdio mapping.
#[cfg(windows)]
pub struct InheritedStdio<'handle> {
    input: std::os::windows::io::BorrowedHandle<'handle>,
    output: std::os::windows::io::BorrowedHandle<'handle>,
    error: std::os::windows::io::BorrowedHandle<'handle>,
}

#[cfg(windows)]
impl<'handle> InheritedStdio<'handle> {
    /// Selects the only handles that may cross the process boundary.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchError::InvalidHandle`] if any borrowed handle is invalid,
    /// already inheritable, or is not an anonymous or named-pipe handle. Disk
    /// files and sockets are rejected before duplication; release evidence must
    /// separately exercise remote named-pipe and inherited-endpoint denial.
    pub fn new(
        input: std::os::windows::io::BorrowedHandle<'handle>,
        output: std::os::windows::io::BorrowedHandle<'handle>,
        error: std::os::windows::io::BorrowedHandle<'handle>,
    ) -> Result<Self, LaunchError> {
        sys::validate_handle(input)?;
        sys::validate_handle(output)?;
        sys::validate_handle(error)?;
        Ok(Self {
            input,
            output,
            error,
        })
    }

    /// Selects the synchronous named-pipe server ends created and retained by
    /// the crate-private Secret Input pipe owner. Some Windows versions deny
    /// `GetNamedPipeInfo` for direction-limited server handles, so this path
    /// validates handle liveness and non-inheritability while relying on the
    /// unforgeable Rust owner type for the pipe-kind invariant.
    #[allow(dead_code)] // Reserved for the private Key Agent arming seam.
    pub(crate) fn for_secret_input_servers(
        input: std::os::windows::io::BorrowedHandle<'handle>,
        output: std::os::windows::io::BorrowedHandle<'handle>,
        error: std::os::windows::io::BorrowedHandle<'handle>,
    ) -> Result<Self, LaunchError> {
        sys::validate_live_handle(input)?;
        sys::validate_live_handle(output)?;
        sys::validate_live_handle(error)?;
        Ok(Self {
            input,
            output,
            error,
        })
    }

    /// Number of unique inherited handles. This is intended for tests and
    /// release evidence, not diagnostics containing raw handle values.
    #[must_use]
    pub fn unique_handle_count(&self) -> usize {
        sys::unique_raw_handles(self).len()
    }
}

#[cfg(windows)]
impl fmt::Debug for InheritedStdio<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InheritedStdio")
            .field("input", &"[HANDLE]")
            .field("output", &"[HANDLE]")
            .field("error", &"[HANDLE]")
            .finish()
    }
}

/// Public fail-closed entry point for one-shot release helper launch.
#[derive(Clone, Copy, Debug)]
pub struct RestrictedLauncher {
    attestation: ReleaseAttestation,
    profile: NoNetworkLpacProfile,
}

impl RestrictedLauncher {
    /// Constructs a launcher bound to release evidence and an LPAC profile.
    #[must_use]
    pub const fn new(attestation: ReleaseAttestation, profile: NoNetworkLpacProfile) -> Self {
        Self {
            attestation,
            profile,
        }
    }

    fn require_allowed_helper(self, manifest_digest: [u8; 32]) -> Result<(), LaunchError> {
        if !self.attestation.signing_enabled() {
            return Err(LaunchError::ReleaseNotAttested);
        }
        if !self.attestation.allows_helper_manifest(manifest_digest) {
            return Err(LaunchError::HelperManifestNotAllowed);
        }
        Ok(())
    }

    fn require_approval_frontend(
        self,
        helper: &VerifiedHelper,
    ) -> Result<VerifiedLpacRole, LaunchError> {
        let role = VerifiedLpacRole::from_helper(helper)?;
        if role != VerifiedLpacRole::ApprovalFrontend {
            return Err(LaunchError::HelperRoleNotAllowed);
        }
        self.require_allowed_helper(helper.manifest_digest())?;
        Ok(role)
    }

    fn require_secret_input_frontend(
        self,
        helper: &VerifiedHelper,
    ) -> Result<VerifiedLpacRole, LaunchError> {
        let role = VerifiedLpacRole::from_helper(helper)?;
        if role != VerifiedLpacRole::SecretInputFrontend {
            return Err(LaunchError::HelperRoleNotAllowed);
        }
        self.require_allowed_helper(helper.manifest_digest())?;
        Ok(role)
    }

    /// Launches a verified helper with only the selected handles inherited.
    ///
    /// The low-level Windows path has no non-LPAC fallback. Development builds
    /// still return [`LaunchError::ReleaseNotAttested`] before creating a profile
    /// or process because no immutable release policy is compiled into them.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchError::HelperRoleNotAllowed`] unless the manifest-derived
    /// role is exactly Approval Frontend. The Key Agent receives the narrower
    /// [`LaunchError::KeyAgentRequiresSupervisorActivation`]. Both errors occur
    /// before release evaluation or process creation. Returns
    /// [`LaunchError::ReleaseNotAttested`] until all release evidence is bound.
    /// Profile, current-directory, operating-system, or post-creation token
    /// verification failures all fail closed before the child is resumed.
    #[cfg(windows)]
    pub fn spawn(
        self,
        helper: &VerifiedHelper,
        handles: &InheritedStdio<'_>,
    ) -> Result<LaunchedHelper, LaunchError> {
        let role = self.require_approval_frontend(helper)?;
        sys::launch(helper, handles, self.profile, role)
    }

    /// Launches Secret Input with two additional, least-privilege proof handles
    /// for the exact calling process and its held executable image.
    #[cfg(windows)]
    #[allow(dead_code)] // Reserved for the private Key Agent arming seam.
    pub(crate) fn spawn_secret_input(
        self,
        helper: &VerifiedHelper,
        handles: &InheritedStdio<'_>,
    ) -> Result<LaunchedHelper, LaunchError> {
        let role = self.require_secret_input_frontend(helper)?;
        sys::launch(helper, handles, self.profile, role)
    }

    /// Refuses launch on non-Windows platforms.
    #[cfg(not(windows))]
    pub fn spawn(self, helper: &VerifiedHelper) -> Result<LaunchedHelper, LaunchError> {
        let role = VerifiedLpacRole::from_helper(helper)?;
        if role != VerifiedLpacRole::ApprovalFrontend {
            return Err(LaunchError::HelperRoleNotAllowed);
        }
        Err(LaunchError::UnsupportedPlatform)
    }
}

/// Identity record for one held helper process.
///
/// While owned by [`LaunchedHelper`], its private process handle keeps the exact
/// process object selected. The file and manifest identities bind that selection
/// to the already verified helper artifact and its manifest-derived role; the
/// role plus profile revision deterministically bind the sandbox identity used
/// at creation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct HeldProcessIdentity {
    process_id: u32,
    helper_file: FileIdentity,
    helper_manifest_digest: [u8; 32],
    profile_revision: u32,
}

impl fmt::Debug for HeldProcessIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeldProcessIdentity")
            .field("process_id", &"[REDACTED]")
            .field("helper_file", &"[REDACTED]")
            .field("helper_manifest_digest", &"[REDACTED]")
            .field("profile_revision", &self.profile_revision)
            .finish()
    }
}

impl HeldProcessIdentity {
    /// Returns the child process identifier.
    #[must_use]
    pub const fn process_id(self) -> u32 {
        self.process_id
    }

    /// Returns the verified executable file identity.
    #[must_use]
    pub const fn helper_file(self) -> FileIdentity {
        self.helper_file
    }

    /// Returns the verified helper-manifest digest.
    #[must_use]
    pub const fn helper_manifest_digest(self) -> [u8; 32] {
        self.helper_manifest_digest
    }

    /// Returns the no-network LPAC profile revision used for creation.
    #[must_use]
    pub const fn profile_revision(self) -> u32 {
        self.profile_revision
    }
}

#[cfg(test)]
mod debug_tests {
    use super::{HeldProcessIdentity, NoNetworkLpacProfile};
    use crate::helper::FileIdentity;

    #[test]
    fn held_process_debug_retains_only_sandbox_state() {
        let identity = HeldProcessIdentity {
            process_id: 4_000_000_001,
            helper_file: FileIdentity {
                volume_serial_number: 4_000_000_002,
                file_index: 8_000_000_003,
                file_size: 9_000_000_004,
            },
            helper_manifest_digest: [0xc3; 32],
            profile_revision: NoNetworkLpacProfile::v1().revision(),
        };

        let rendered = format!("{identity:?}");
        assert!(rendered.contains("HeldProcessIdentity"));
        assert!(rendered.contains("profile_revision: 1"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("4000000001"));
        assert!(!rendered.contains("4000000002"));
        assert!(!rendered.contains("8000000003"));
        assert!(!rendered.contains("9000000004"));
        assert!(!rendered.contains("195, 195"));
    }
}

/// A process held in a single-process kill-on-close job.
#[cfg(windows)]
pub struct LaunchedHelper {
    process: sys::OwnedWinHandle,
    job: sys::OwnedWinHandle,
    identity: HeldProcessIdentity,
    parent_proof: Option<InheritedParentProof>,
}

/// Numeric values of the two proof handles inherited by one Secret Input
/// child. Values are opaque and never formatted; the child validates the
/// underlying kernel objects before accepting protocol bytes.
#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct InheritedParentProof {
    process_handle: u64,
    image_handle: u64,
    process_id: u32,
}

#[cfg(windows)]
impl InheritedParentProof {
    #[allow(dead_code)] // Read only by the dormant private arming seam.
    pub(crate) const fn process_handle(self) -> u64 {
        self.process_handle
    }

    #[allow(dead_code)] // Read only by the dormant private arming seam.
    pub(crate) const fn image_handle(self) -> u64 {
        self.image_handle
    }

    #[allow(dead_code)] // Read only by the dormant private arming seam.
    pub(crate) const fn process_id(self) -> u32 {
        self.process_id
    }
}

#[cfg(windows)]
impl fmt::Debug for InheritedParentProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InheritedParentProof([REDACTED HANDLES AND PID])")
    }
}

#[cfg(windows)]
impl LaunchedHelper {
    /// Returns the child PID for subsequent named-pipe peer binding.
    #[must_use]
    pub const fn process_id(&self) -> u32 {
        self.identity.process_id()
    }

    /// Returns the held process, helper-artifact, and sandbox-profile identity.
    #[must_use]
    pub const fn identity(&self) -> HeldProcessIdentity {
        self.identity
    }

    /// Returns true while the process and kill-on-close job handles are owned.
    #[must_use]
    pub fn is_held_in_job(&self) -> bool {
        !self.process.raw().is_invalid() && !self.job.raw().is_invalid()
    }

    #[allow(dead_code)] // Read only by the dormant private arming seam.
    pub(crate) const fn parent_proof(&self) -> Option<InheritedParentProof> {
        self.parent_proof
    }

    /// Explicitly terminates the single-process job and waits for the exact
    /// held process object before the supplied monotonic deadline.
    ///
    /// Consuming `self` guarantees that every error path also closes the process
    /// and kill-on-close job handles. Recovery uses this before constructing a
    /// capability for its next child stage.
    pub(crate) fn terminate_and_wait(self, deadline: Instant) -> Result<(), LaunchError> {
        let Self {
            process,
            job,
            identity: _,
            parent_proof: _,
        } = self;
        let result = sys::terminate_and_wait(process.raw(), job.raw(), deadline);
        drop(job);
        drop(process);
        result
    }
}

#[cfg(windows)]
impl fmt::Debug for LaunchedHelper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchedHelper")
            .field("process", &"[HANDLE]")
            .field("job", &"[HANDLE]")
            .field("identity", &self.identity)
            .field("parent_proof", &self.parent_proof)
            .finish()
    }
}

#[cfg(not(windows))]
#[derive(Debug)]
pub struct LaunchedHelper;

#[cfg(windows)]
mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;
    use std::collections::HashSet;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, BorrowedHandle};
    use std::path::Path;
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{
        CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_ALREADY_EXISTS, GENERIC_READ,
        GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
    };
    use windows::Win32::Security::{
        EqualSid, FreeSid, GetTokenInformation, IsValidSid, PSID, SECURITY_CAPABILITIES,
        TOKEN_APPCONTAINER_INFORMATION, TOKEN_QUERY, TokenAppContainerSid, TokenCapabilities,
        TokenIsAppContainer,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows::Win32::System::JobObjects::{
        CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
    };
    use windows::Win32::System::Pipes::GetNamedPipeInfo;
    use windows::Win32::System::Threading::{
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentProcessId, GetProcessId,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcess,
        OpenProcessToken, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
        PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_ACCESS_RIGHTS, PROCESS_INFORMATION,
        PROCESS_QUERY_LIMITED_INFORMATION, ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW,
        TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
    };
    use windows::Win32::System::WindowsProgramming::{
        PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
        PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
    };
    use windows::core::{BOOL, PCWSTR};

    use super::{
        HeldProcessIdentity, InheritedParentProof, InheritedStdio, LaunchError, LaunchedHelper,
        NoNetworkLpacProfile, VerifiedHelper, VerifiedLpacRole,
    };
    use crate::inheritable_handle_launch::{
        InheritableHandleLaunchFlight, acquire_inheritable_handle_launch,
    };
    use crate::restricted_process_context::{
        RestrictedProcessContext, RestrictedProcessContextError,
    };

    const APPROVAL_PROFILE_V1_NAME: &str = "YourWallet.ApprovalFrontend.LPAC.v1";
    const APPROVAL_PROFILE_DISPLAY_NAME: &str = "Your Wallet approval frontend";
    const APPROVAL_PROFILE_DESCRIPTION: &str =
        "Persistent no-network LPAC identity for Your Wallet approval prompts";
    const SECRET_INPUT_PROFILE_V1_NAME: &str = "YourWallet.SecretInputFrontend.LPAC.v1";
    const SECRET_INPUT_PROFILE_DISPLAY_NAME: &str = "Your Wallet secret input frontend";
    const SECRET_INPUT_PROFILE_DESCRIPTION: &str =
        "Persistent no-network LPAC identity for Your Wallet secret input";
    const ATTRIBUTE_COUNT: u32 = 6;
    const CAPABILITY_COUNT: u32 = 0;
    const MAX_TOKEN_INFORMATION_BYTES: usize = 64 * 1024;
    const MAX_INHERITABLE_LAUNCH_WAIT: Duration = Duration::from_secs(5);
    const PROCESS_SYNCHRONIZE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0010_0000);

    const MITIGATION_DEP_ENABLE: u64 = 1;
    const MITIGATION_SEHOP_ENABLE: u64 = 1 << 2;
    const MITIGATION_FORCE_RELOCATE_IMAGES_ALWAYS_ON: u64 = 1 << 8;
    const MITIGATION_HEAP_TERMINATE_ALWAYS_ON: u64 = 1 << 12;
    const MITIGATION_BOTTOM_UP_ASLR_ALWAYS_ON: u64 = 1 << 16;
    const MITIGATION_HIGH_ENTROPY_ASLR_ALWAYS_ON: u64 = 1 << 20;
    const MITIGATION_STRICT_HANDLE_CHECKS_ALWAYS_ON: u64 = 1 << 24;
    const MITIGATION_EXTENSION_POINT_DISABLE_ALWAYS_ON: u64 = 1 << 32;
    const MITIGATION_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON: u64 = 1 << 36;
    const MITIGATION_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON: u64 = 1 << 44;
    const MITIGATION_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON: u64 = 1 << 52;
    const MITIGATION_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON: u64 = 1 << 56;
    const MITIGATION_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON: u64 = 1 << 60;

    const HELPER_MITIGATION_POLICY: u64 = MITIGATION_DEP_ENABLE
        | MITIGATION_SEHOP_ENABLE
        | MITIGATION_FORCE_RELOCATE_IMAGES_ALWAYS_ON
        | MITIGATION_HEAP_TERMINATE_ALWAYS_ON
        | MITIGATION_BOTTOM_UP_ASLR_ALWAYS_ON
        | MITIGATION_HIGH_ENTROPY_ASLR_ALWAYS_ON
        | MITIGATION_STRICT_HANDLE_CHECKS_ALWAYS_ON
        | MITIGATION_EXTENSION_POINT_DISABLE_ALWAYS_ON
        | MITIGATION_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON
        | MITIGATION_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
        | MITIGATION_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON
        | MITIGATION_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON
        | MITIGATION_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;

    pub(super) struct OwnedWinHandle(HANDLE);

    impl OwnedWinHandle {
        pub(super) const fn raw(&self) -> HANDLE {
            self.0
        }
    }

    impl Drop for OwnedWinHandle {
        fn drop(&mut self) {
            // SAFETY: this wrapper exclusively owns a successful Win32 handle.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    /// Every handle in this owner was created under one exact process-wide
    /// launch flight. The retained borrow makes releasing the flight before all
    /// duplicates close a compile-time error.
    struct InheritableDuplicates<'flight, 'coordinator> {
        handles: Vec<OwnedWinHandle>,
        flight: &'flight InheritableHandleLaunchFlight<'coordinator>,
    }

    impl<'flight, 'coordinator> InheritableDuplicates<'flight, 'coordinator> {
        fn new(flight: &'flight InheritableHandleLaunchFlight<'coordinator>) -> Self {
            Self {
                handles: Vec::new(),
                flight,
            }
        }

        fn duplicate(&mut self, source: HANDLE) -> Result<HANDLE, LaunchError> {
            let duplicate = duplicate_inheritable(self.flight, source)?;
            let raw = duplicate.raw();
            self.handles.push(duplicate);
            Ok(raw)
        }

        fn raw_handles(&self) -> Box<[HANDLE]> {
            self.handles
                .iter()
                .map(OwnedWinHandle::raw)
                .collect::<Vec<_>>()
                .into_boxed_slice()
        }
    }

    struct OwnedAppContainerSid(PSID);

    impl OwnedAppContainerSid {
        fn open_or_create(
            profile: NoNetworkLpacProfile,
            role: VerifiedLpacRole,
        ) -> Result<Self, LaunchError> {
            let metadata = profile_metadata(profile, role)?;
            let name_wide = wide_nul_str(metadata.name);
            let display_wide = wide_nul_str(metadata.display_name);
            let description_wide = wide_nul_str(metadata.description);

            // SAFETY: all strings are NUL terminated and there are deliberately no
            // capability SIDs. The returned SID is owned and freed with FreeSid.
            let created = unsafe {
                CreateAppContainerProfile(
                    PCWSTR(name_wide.as_ptr()),
                    PCWSTR(display_wide.as_ptr()),
                    PCWSTR(description_wide.as_ptr()),
                    None,
                )
            };
            match created {
                Ok(created_sid) => {
                    let created = Self::from_raw(created_sid)?;
                    // Derivation is checked even on first creation so a changed OS
                    // profile contract cannot silently select a different SID.
                    let derived = Self::derive(&name_wide)?;
                    // SAFETY: both wrappers contain valid live SIDs.
                    unsafe {
                        EqualSid(created.raw(), derived.raw())
                            .map_err(|_| LaunchError::SandboxVerification)?;
                    }
                    Ok(derived)
                }
                Err(error) if error.code() == ERROR_ALREADY_EXISTS.to_hresult() => {
                    Self::derive(&name_wide)
                }
                Err(_) => Err(LaunchError::OperatingSystem),
            }
        }

        fn derive(name_wide: &[u16]) -> Result<Self, LaunchError> {
            // SAFETY: `name_wide` is a live NUL-terminated profile name.
            let sid = unsafe {
                DeriveAppContainerSidFromAppContainerName(PCWSTR(name_wide.as_ptr()))
                    .map_err(|_| LaunchError::OperatingSystem)?
            };
            Self::from_raw(sid)
        }

        fn from_raw(sid: PSID) -> Result<Self, LaunchError> {
            // SAFETY: the SID came from a successful profile API call.
            if sid.is_invalid() || !unsafe { IsValidSid(sid) }.as_bool() {
                if !sid.is_invalid() {
                    // SAFETY: even a malformed non-null SID returned by the profile
                    // API must be released with FreeSid.
                    unsafe {
                        let _ = FreeSid(sid);
                    }
                }
                return Err(LaunchError::SandboxVerification);
            }
            Ok(Self(sid))
        }

        const fn raw(&self) -> PSID {
            self.0
        }
    }

    impl Drop for OwnedAppContainerSid {
        fn drop(&mut self) {
            // SAFETY: this wrapper exclusively owns a SID returned by an
            // AppContainer profile API.
            unsafe {
                let _ = FreeSid(self.0);
            }
        }
    }

    impl core::fmt::Debug for OwnedAppContainerSid {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("OwnedAppContainerSid([SID])")
        }
    }

    struct AttributeValues {
        handles: Box<[HANDLE]>,
        job: [HANDLE; 1],
        mitigation: u64,
        security_capabilities: SECURITY_CAPABILITIES,
        all_application_packages_policy: u32,
        child_process_policy: u32,
    }

    impl AttributeValues {
        fn new(handles: Box<[HANDLE]>, job: HANDLE, profile_sid: PSID) -> Self {
            Self {
                handles,
                job: [job],
                mitigation: HELPER_MITIGATION_POLICY,
                security_capabilities: SECURITY_CAPABILITIES {
                    AppContainerSid: profile_sid,
                    Capabilities: ptr::null_mut(),
                    CapabilityCount: CAPABILITY_COUNT,
                    Reserved: 0,
                },
                all_application_packages_policy: PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
                child_process_policy: PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
            }
        }
    }

    struct AttributeList<'handles, 'flight, 'coordinator, 'job> {
        words: Vec<usize>,
        pointer: LPPROC_THREAD_ATTRIBUTE_LIST,
        values: Box<AttributeValues>,
        profile_sid: Option<OwnedAppContainerSid>,
        duplicate_owner: &'handles InheritableDuplicates<'flight, 'coordinator>,
        job_owner: &'job OwnedWinHandle,
    }

    impl<'handles, 'flight, 'coordinator, 'job> AttributeList<'handles, 'flight, 'coordinator, 'job> {
        fn for_lpac(
            duplicate_owner: &'handles InheritableDuplicates<'flight, 'coordinator>,
            job_owner: &'job OwnedWinHandle,
            profile_sid: OwnedAppContainerSid,
        ) -> Result<Self, LaunchError> {
            let handles = duplicate_owner.raw_handles();
            if handles.is_empty() {
                return Err(LaunchError::InvalidHandle);
            }
            let values = Box::new(AttributeValues::new(
                handles,
                job_owner.raw(),
                profile_sid.raw(),
            ));
            let mut bytes = 0_usize;
            // SAFETY: the documented sizing call uses a null list and initializes
            // `bytes`. Its expected insufficient-buffer error is ignored.
            let _ = unsafe {
                InitializeProcThreadAttributeList(None, ATTRIBUTE_COUNT, None, &raw mut bytes)
            };
            if bytes == 0 {
                return Err(LaunchError::OperatingSystem);
            }
            let word_size = size_of::<usize>();
            let word_count = bytes
                .checked_add(word_size - 1)
                .and_then(|rounded| rounded.checked_div(word_size))
                .ok_or(LaunchError::OperatingSystem)?;
            let mut words = vec![0_usize; word_count];
            let pointer = LPPROC_THREAD_ATTRIBUTE_LIST(words.as_mut_ptr().cast::<c_void>());
            // SAFETY: `words` is aligned writable storage of at least `bytes` and
            // is not reallocated while the attribute list exists.
            unsafe {
                InitializeProcThreadAttributeList(
                    Some(pointer),
                    ATTRIBUTE_COUNT,
                    None,
                    &raw mut bytes,
                )
                .map_err(|_| LaunchError::OperatingSystem)?;
            }
            let list = Self {
                words,
                pointer,
                values,
                profile_sid: Some(profile_sid),
                duplicate_owner,
                job_owner,
            };
            list.install_attributes()?;
            Ok(list)
        }

        fn install_attributes(&self) -> Result<(), LaunchError> {
            self.update(
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                self.values.handles.as_ptr().cast::<c_void>(),
                size_of_val(self.values.handles.as_ref()),
            )?;
            self.update(
                PROC_THREAD_ATTRIBUTE_JOB_LIST,
                self.values.job.as_ptr().cast::<c_void>(),
                size_of_val(&self.values.job),
            )?;
            self.update(
                PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                ptr::from_ref(&self.values.mitigation).cast::<c_void>(),
                size_of::<u64>(),
            )?;
            self.update(
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                ptr::from_ref(&self.values.security_capabilities).cast::<c_void>(),
                size_of::<SECURITY_CAPABILITIES>(),
            )?;
            self.update(
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                ptr::from_ref(&self.values.all_application_packages_policy).cast::<c_void>(),
                size_of::<u32>(),
            )?;
            self.update(
                PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                ptr::from_ref(&self.values.child_process_policy).cast::<c_void>(),
                size_of::<u32>(),
            )
        }

        fn update(
            &self,
            attribute: u32,
            value: *const c_void,
            value_bytes: usize,
        ) -> Result<(), LaunchError> {
            // SAFETY: the attribute list is initialized, every pointer refers to
            // stable heap-backed storage owned by `self`, and all values remain
            // live until the list is deleted in Drop.
            unsafe {
                UpdateProcThreadAttribute(
                    self.pointer,
                    0,
                    usize::try_from(attribute).map_err(|_| LaunchError::OperatingSystem)?,
                    Some(value),
                    value_bytes,
                    None,
                    None,
                )
                .map_err(|_| LaunchError::OperatingSystem)
            }
        }

        fn pointer(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            debug_assert!(!self.words.is_empty());
            debug_assert_eq!(
                self.duplicate_owner.handles.len(),
                self.values.handles.len()
            );
            debug_assert_eq!(self.job_owner.raw(), self.values.job[0]);
            self.pointer
        }

        fn into_profile_sid(mut self) -> Result<OwnedAppContainerSid, LaunchError> {
            let profile_sid = self
                .profile_sid
                .take()
                .ok_or(LaunchError::OperatingSystem)?;
            drop(self);
            Ok(profile_sid)
        }
    }

    impl Drop for AttributeList<'_, '_, '_, '_> {
        fn drop(&mut self) {
            // SAFETY: initialization succeeded and this pointer is deleted once
            // before its backing Vec and attribute-value storage are dropped.
            unsafe {
                DeleteProcThreadAttributeList(self.pointer);
            }
        }
    }

    pub(super) fn validate_handle(handle: BorrowedHandle<'_>) -> Result<(), LaunchError> {
        validate_live_handle(handle)?;
        // Sockets and ordinary files must never be smuggled through the public
        // stdio list. Both anonymous and named-pipe handles satisfy this API.
        // SAFETY: BorrowedHandle proves the handle remains live for this call.
        unsafe {
            GetNamedPipeInfo(HANDLE(handle.as_raw_handle()), None, None, None, None)
                .map_err(|_| LaunchError::InvalidHandle)?;
        }
        Ok(())
    }

    pub(super) fn validate_live_handle(handle: BorrowedHandle<'_>) -> Result<(), LaunchError> {
        let mut flags = 0_u32;
        // SAFETY: BorrowedHandle proves the handle remains live for this call.
        unsafe {
            GetHandleInformation(HANDLE(handle.as_raw_handle()), &raw mut flags)
                .map_err(|_| LaunchError::InvalidHandle)?;
        }
        if flags & HANDLE_FLAG_INHERIT.0 != 0 {
            return Err(LaunchError::InvalidHandle);
        }
        Ok(())
    }

    pub(super) fn unique_raw_handles(handles: &InheritedStdio<'_>) -> Vec<HANDLE> {
        let candidates = [
            HANDLE(handles.input.as_raw_handle()),
            HANDLE(handles.output.as_raw_handle()),
            HANDLE(handles.error.as_raw_handle()),
        ];
        let mut seen = HashSet::with_capacity(candidates.len());
        candidates
            .into_iter()
            .filter(|handle| seen.insert(handle.0 as usize))
            .collect()
    }

    #[derive(Clone, Copy)]
    struct ProfileMetadata {
        name: &'static str,
        display_name: &'static str,
        description: &'static str,
    }

    fn profile_metadata(
        profile: NoNetworkLpacProfile,
        role: VerifiedLpacRole,
    ) -> Result<ProfileMetadata, LaunchError> {
        match (profile.revision(), role) {
            (1, VerifiedLpacRole::ApprovalFrontend) => Ok(ProfileMetadata {
                name: APPROVAL_PROFILE_V1_NAME,
                display_name: APPROVAL_PROFILE_DISPLAY_NAME,
                description: APPROVAL_PROFILE_DESCRIPTION,
            }),
            (1, VerifiedLpacRole::SecretInputFrontend) => Ok(ProfileMetadata {
                name: SECRET_INPUT_PROFILE_V1_NAME,
                display_name: SECRET_INPUT_PROFILE_DISPLAY_NAME,
                description: SECRET_INPUT_PROFILE_DESCRIPTION,
            }),
            _ => Err(LaunchError::InvalidProfile),
        }
    }

    #[cfg(test)]
    fn profile_name(
        profile: NoNetworkLpacProfile,
        role: VerifiedLpacRole,
    ) -> Result<&'static str, LaunchError> {
        Ok(profile_metadata(profile, role)?.name)
    }

    fn wide_nul_str(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(core::iter::once(0)).collect()
    }

    fn wide_nul_path(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect()
    }

    const fn map_process_context_error(error: RestrictedProcessContextError) -> LaunchError {
        match error {
            RestrictedProcessContextError::OperatingSystem
            | RestrictedProcessContextError::ThreadImpersonation => LaunchError::OperatingSystem,
            RestrictedProcessContextError::UnsafeWorkingDirectory => {
                LaunchError::UnsafeWorkingDirectory
            }
        }
    }

    fn token_information(
        token: HANDLE,
        class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    ) -> Result<Vec<usize>, LaunchError> {
        let mut required = 0_u32;
        // SAFETY: this is the documented sizing call; failure is expected and the
        // required byte count is validated before allocating.
        let _ = unsafe { GetTokenInformation(token, class, None, 0, &raw mut required) };
        let required = usize::try_from(required).map_err(|_| LaunchError::SandboxVerification)?;
        if required == 0 || required > MAX_TOKEN_INFORMATION_BYTES {
            return Err(LaunchError::SandboxVerification);
        }
        let word_size = size_of::<usize>();
        let words = required
            .checked_add(word_size - 1)
            .and_then(|rounded| rounded.checked_div(word_size))
            .ok_or(LaunchError::SandboxVerification)?;
        let mut buffer = vec![0_usize; words];
        let mut returned = 0_u32;
        // SAFETY: the buffer is aligned and has at least `required` writable bytes.
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(buffer.as_mut_ptr().cast::<c_void>()),
                u32::try_from(required).map_err(|_| LaunchError::SandboxVerification)?,
                &raw mut returned,
            )
            .map_err(|_| LaunchError::SandboxVerification)?;
        }
        let returned = usize::try_from(returned).map_err(|_| LaunchError::SandboxVerification)?;
        if returned == 0 || returned > required {
            return Err(LaunchError::SandboxVerification);
        }
        Ok(buffer)
    }

    fn verify_child_token(process: HANDLE, expected_sid: PSID) -> Result<(), LaunchError> {
        let mut token = HANDLE::default();
        // SAFETY: `process` is the suspended child process handle and the output
        // token handle is exclusively owned below.
        unsafe {
            OpenProcessToken(process, TOKEN_QUERY, &raw mut token)
                .map_err(|_| LaunchError::SandboxVerification)?;
        }
        let token = OwnedWinHandle(token);

        let mut is_appcontainer = 0_u32;
        let mut returned = 0_u32;
        // SAFETY: the fixed-size output matches TokenIsAppContainer's DWORD ABI.
        unsafe {
            GetTokenInformation(
                token.raw(),
                TokenIsAppContainer,
                Some(ptr::from_mut(&mut is_appcontainer).cast::<c_void>()),
                u32::try_from(size_of::<u32>()).map_err(|_| LaunchError::SandboxVerification)?,
                &raw mut returned,
            )
            .map_err(|_| LaunchError::SandboxVerification)?;
        }
        if is_appcontainer != 1
            || usize::try_from(returned).map_err(|_| LaunchError::SandboxVerification)?
                != size_of::<u32>()
        {
            return Err(LaunchError::SandboxVerification);
        }

        let sid_buffer = token_information(token.raw(), TokenAppContainerSid)?;
        if sid_buffer.len().saturating_mul(size_of::<usize>())
            < size_of::<TOKEN_APPCONTAINER_INFORMATION>()
        {
            return Err(LaunchError::SandboxVerification);
        }
        // SAFETY: size and alignment were established above; the buffer remains
        // live while its interior SID pointer is checked and compared.
        let container = unsafe {
            ptr::read_unaligned(sid_buffer.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>())
        };
        if container.TokenAppContainer.is_invalid() {
            return Err(LaunchError::SandboxVerification);
        }
        // SAFETY: the pointer was returned inside a successful token-information
        // buffer and remains live until the comparison completes.
        let sid_is_valid = unsafe { IsValidSid(container.TokenAppContainer) }.as_bool();
        // SAFETY: both SIDs remain live for the duration of this comparison.
        let sid_matches = unsafe { EqualSid(container.TokenAppContainer, expected_sid) }.is_ok();
        if !sid_is_valid || !sid_matches {
            return Err(LaunchError::SandboxVerification);
        }

        let capabilities = token_information(token.raw(), TokenCapabilities)?;
        if capabilities.len().saturating_mul(size_of::<usize>()) < size_of::<u32>() {
            return Err(LaunchError::SandboxVerification);
        }
        // SAFETY: the aligned buffer contains at least the leading GroupCount.
        let capability_count = unsafe { ptr::read_unaligned(capabilities.as_ptr().cast::<u32>()) };
        if capability_count != CAPABILITY_COUNT {
            return Err(LaunchError::SandboxVerification);
        }
        Ok(())
    }

    fn duplicate_inheritable(
        _flight: &InheritableHandleLaunchFlight<'_>,
        source: HANDLE,
    ) -> Result<OwnedWinHandle, LaunchError> {
        let mut duplicate = HANDLE::default();
        // SAFETY: source was validated and is live; duplication targets the current
        // process and explicitly marks only the duplicate inheritable.
        unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                source,
                GetCurrentProcess(),
                &raw mut duplicate,
                0,
                true,
                DUPLICATE_SAME_ACCESS,
            )
            .map_err(|_| LaunchError::OperatingSystem)?;
        }
        if duplicate.is_invalid() {
            return Err(LaunchError::OperatingSystem);
        }
        let duplicate = OwnedWinHandle(duplicate);
        let mut flags = 0_u32;
        // SAFETY: the successful duplicate remains owned for this exact flag
        // query and must carry no ambient handle property besides inheritance.
        unsafe { GetHandleInformation(duplicate.raw(), &raw mut flags) }
            .map_err(|_| LaunchError::OperatingSystem)?;
        if flags != HANDLE_FLAG_INHERIT.0 {
            return Err(LaunchError::OperatingSystem);
        }
        Ok(duplicate)
    }

    struct ParentProofSources {
        process: OwnedWinHandle,
        image: OwnedWinHandle,
        process_id: u32,
    }

    fn current_parent_proof_sources() -> Result<ParentProofSources, LaunchError> {
        // SAFETY: both calls take scalar values only. OpenProcess returns a real
        // least-privilege handle rather than the non-inheritable pseudo handle.
        let process_id = unsafe { GetCurrentProcessId() };
        if process_id == 0 {
            return Err(LaunchError::OperatingSystem);
        }
        // SAFETY: the nonzero PID is the current process and only documented,
        // least-privilege query/wait rights are requested.
        let process = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                false,
                process_id,
            )
        }
        .map(OwnedWinHandle)
        .map_err(|_| LaunchError::OperatingSystem)?;

        let executable = std::env::current_exe().map_err(|_| LaunchError::OperatingSystem)?;
        if !executable.is_absolute() {
            return Err(LaunchError::OperatingSystem);
        }
        let executable_wide = wide_nul_path(&executable);
        // SAFETY: the absolute path is NUL terminated and retained for the
        // complete call. Read-only sharing intentionally excludes replacement.
        let image = unsafe {
            CreateFileW(
                PCWSTR(executable_wide.as_ptr()),
                GENERIC_READ.0,
                FILE_SHARE_READ,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        }
        .map(OwnedWinHandle)
        .map_err(|_| LaunchError::OperatingSystem)?;
        Ok(ParentProofSources {
            process,
            image,
            process_id,
        })
    }

    fn inherited_handle_value(handle: HANDLE) -> Result<u64, LaunchError> {
        u64::try_from(handle.0 as usize).map_err(|_| LaunchError::OperatingSystem)
    }

    fn restricted_job() -> Result<OwnedWinHandle, LaunchError> {
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        information.BasicLimitInformation.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        information.BasicLimitInformation.ActiveProcessLimit = 1;
        // SAFETY: unnamed job creation has no retained input pointers.
        let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map(OwnedWinHandle)
            .map_err(|_| LaunchError::OperatingSystem)?;
        // SAFETY: the information pointer has the exact structure and size selected
        // by JobObjectExtendedLimitInformation.
        unsafe {
            SetInformationJobObject(
                job.raw(),
                JobObjectExtendedLimitInformation,
                ptr::from_ref(&information).cast::<c_void>(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .map_err(|_| LaunchError::OperatingSystem)?,
            )
            .map_err(|_| LaunchError::OperatingSystem)?;
        }
        Ok(job)
    }

    const CREATED_CHILD_CLEANUP_TIMEOUT_MILLISECONDS: u32 = 5_000;

    fn terminate_and_reap_created_child(process: HANDLE, job: HANDLE) {
        // SAFETY: the guard invokes this only for the exact process returned by
        // CreateProcessW and its atomically assigned kill-on-close Job. The
        // process is suspended until the guard is disarmed.
        unsafe {
            let _ = TerminateJobObject(job, 1);
            let _ = TerminateProcess(process, 1);
            let _ = WaitForSingleObject(process, CREATED_CHILD_CLEANUP_TIMEOUT_MILLISECONDS);
        }
    }

    struct CreatedChildGuard<'process, 'job> {
        process: &'process OwnedWinHandle,
        job: &'job OwnedWinHandle,
        armed: bool,
    }

    impl<'process, 'job> CreatedChildGuard<'process, 'job> {
        fn new(process: &'process OwnedWinHandle, job: &'job OwnedWinHandle) -> Self {
            Self {
                process,
                job,
                armed: true,
            }
        }

        fn disarm(mut self) {
            self.armed = false;
        }
    }

    impl Drop for CreatedChildGuard<'_, '_> {
        fn drop(&mut self) {
            if self.armed {
                terminate_and_reap_created_child(self.process.raw(), self.job.raw());
            }
        }
    }

    pub(super) fn terminate_and_wait(
        process: HANDLE,
        job: HANDLE,
        deadline: Instant,
    ) -> Result<(), LaunchError> {
        let timeout = remaining_milliseconds(deadline)?;
        // SAFETY: both handles remain owned by the consuming LaunchedHelper for
        // this call. The job contains at most the one held helper process.
        unsafe { TerminateJobObject(job, 1) }.map_err(|_| LaunchError::OperatingSystem)?;
        // SAFETY: `process` is the live held process object and the finite wait
        // is bounded by the trusted monotonic deadline calculated above.
        let wait = unsafe { WaitForSingleObject(process, timeout) };
        if wait == WAIT_TIMEOUT || deadline_elapsed(deadline) {
            Err(LaunchError::TerminationDeadlineElapsed)
        } else if wait == WAIT_OBJECT_0 {
            Ok(())
        } else {
            Err(LaunchError::OperatingSystem)
        }
    }

    fn remaining_milliseconds(deadline: Instant) -> Result<u32, LaunchError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(LaunchError::TerminationDeadlineElapsed)?;
        let whole_millis = remaining.as_millis();
        let rounded_millis =
            whole_millis.saturating_add(u128::from(remaining.subsec_nanos() % 1_000_000 != 0));
        u32::try_from(rounded_millis).map_err(|_| LaunchError::TerminationDeadlineElapsed)
    }

    fn deadline_elapsed(deadline: Instant) -> bool {
        Instant::now().checked_duration_since(deadline).is_some()
    }

    #[allow(clippy::too_many_lines)] // Process creation is kept linear for cleanup auditing.
    pub(super) fn launch(
        helper: &VerifiedHelper,
        handles: &InheritedStdio<'_>,
        profile: NoNetworkLpacProfile,
        role: VerifiedLpacRole,
    ) -> Result<LaunchedHelper, LaunchError> {
        // Keep the identity-pinned executable file live through CreateProcessW.
        let _verified_file_handle = helper.raw_handle();
        validate_live_handle(handles.input)?;
        validate_live_handle(handles.output)?;
        validate_live_handle(handles.error)?;
        let process_context =
            RestrictedProcessContext::prepare().map_err(map_process_context_error)?;
        let helper_file = helper.identity();
        let helper_manifest_digest = helper.manifest_digest();
        let originals = unique_raw_handles(handles);
        let parent_sources = role
            .inherits_parent_proof()
            .then(current_parent_proof_sources)
            .transpose()?;
        let profile_sid = OwnedAppContainerSid::open_or_create(profile, role)?;
        let job = restricted_job()?;
        let application: Vec<u16> = helper
            .path()
            .as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect();
        let coordination_deadline = Instant::now()
            .checked_add(MAX_INHERITABLE_LAUNCH_WAIT)
            .ok_or(LaunchError::OperatingSystem)?;
        let flight = acquire_inheritable_handle_launch(coordination_deadline)
            .map_err(|_| LaunchError::OperatingSystem)?;
        if Instant::now() >= coordination_deadline {
            return Err(LaunchError::OperatingSystem);
        }
        validate_live_handle(handles.input)?;
        validate_live_handle(handles.output)?;
        validate_live_handle(handles.error)?;
        let mut duplicates = InheritableDuplicates::new(&flight);
        let stdio_duplicate_raw: Vec<HANDLE> = originals
            .iter()
            .copied()
            .map(|source| duplicates.duplicate(source))
            .collect::<Result<_, _>>()?;

        let map_duplicate = |borrowed: BorrowedHandle<'_>| -> Result<HANDLE, LaunchError> {
            let raw = borrowed.as_raw_handle() as usize;
            let index = originals
                .iter()
                .position(|candidate| candidate.0 as usize == raw)
                .ok_or(LaunchError::InvalidHandle)?;
            stdio_duplicate_raw
                .get(index)
                .copied()
                .ok_or(LaunchError::InvalidHandle)
        };

        let standard_input = map_duplicate(handles.input)?;
        let standard_output = map_duplicate(handles.output)?;
        let standard_error = map_duplicate(handles.error)?;
        let parent_proof = if let Some(sources) = parent_sources.as_ref() {
            let process = duplicates.duplicate(sources.process.raw())?;
            let image = duplicates.duplicate(sources.image.raw())?;
            let proof = InheritedParentProof {
                process_handle: inherited_handle_value(process)?,
                image_handle: inherited_handle_value(image)?,
                process_id: sources.process_id,
            };
            Some(proof)
        } else {
            None
        };
        drop(parent_sources);
        let attributes = AttributeList::for_lpac(&duplicates, &job, profile_sid)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb =
            u32::try_from(size_of::<STARTUPINFOEXW>()).map_err(|_| LaunchError::OperatingSystem)?;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = standard_input;
        startup.StartupInfo.hStdOutput = standard_output;
        startup.StartupInfo.hStdError = standard_error;
        startup.lpAttributeList = attributes.pointer();
        if Instant::now() >= coordination_deadline {
            return Err(LaunchError::OperatingSystem);
        }
        process_context
            .recheck_thread()
            .map_err(map_process_context_error)?;

        let mut process_information = PROCESS_INFORMATION::default();
        // SAFETY: helper path is verified and NUL-terminated; startup and attribute
        // storage remain live. TRUE inheritance is constrained by HANDLE_LIST.
        // The Unicode environment is an explicit two-name allowlist, and the
        // current directory was checked non-writable and free of reparses.
        unsafe {
            flight
                .create_process_with_explicit_handle_list(
                    PCWSTR(application.as_ptr()),
                    None,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                    Some(process_context.environment().as_ptr().cast::<c_void>()),
                    PCWSTR(process_context.current_directory().as_ptr()),
                    ptr::from_ref(&startup.StartupInfo),
                    &raw mut process_information,
                )
                .map_err(|_| LaunchError::OperatingSystem)?;
        }
        let process = OwnedWinHandle(process_information.hProcess);
        let thread = OwnedWinHandle(process_information.hThread);
        let child_guard = CreatedChildGuard::new(&process, &job);
        let profile_sid = match attributes.into_profile_sid() {
            Ok(profile_sid) => profile_sid,
            Err(error) => {
                drop(duplicates);
                drop(flight);
                return Err(error);
            }
        };
        drop(duplicates);
        drop(flight);
        // SAFETY: the process handle is live and refers to the suspended child.
        let held_process_id = unsafe { GetProcessId(process.raw()) };
        if held_process_id == 0 || held_process_id != process_information.dwProcessId {
            return Err(LaunchError::SandboxVerification);
        }
        let mut in_job = BOOL(0);
        // SAFETY: CreateProcessW atomically assigned the suspended child through
        // PROC_THREAD_ATTRIBUTE_JOB_LIST; both exact handles remain live.
        unsafe { IsProcessInJob(process.raw(), Some(job.raw()), &raw mut in_job) }
            .map_err(|_| LaunchError::SandboxVerification)?;
        if !in_job.as_bool() {
            return Err(LaunchError::SandboxVerification);
        }
        if verify_child_token(process.raw(), profile_sid.raw()).is_err() {
            return Err(LaunchError::SandboxVerification);
        }
        // SAFETY: thread is the suspended primary thread returned by CreateProcess.
        let previous_suspend_count = unsafe { ResumeThread(thread.raw()) };
        if previous_suspend_count != 1 {
            return Err(LaunchError::OperatingSystem);
        }
        child_guard.disarm();
        drop(thread);
        drop(profile_sid);

        Ok(LaunchedHelper {
            process,
            job,
            identity: HeldProcessIdentity {
                process_id: held_process_id,
                helper_file,
                helper_manifest_digest,
                profile_revision: profile.revision(),
            },
            parent_proof,
        })
    }

    #[cfg(test)]
    pub(super) const fn mitigation_policy_for_test() -> u64 {
        HELPER_MITIGATION_POLICY
    }

    #[cfg(test)]
    pub(super) const fn job_flags_for_test() -> u32 {
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0 | JOB_OBJECT_LIMIT_ACTIVE_PROCESS.0
    }

    #[cfg(test)]
    pub(super) const fn capability_count_for_test() -> u32 {
        CAPABILITY_COUNT
    }

    #[cfg(test)]
    pub(super) const fn attribute_count_for_test() -> u32 {
        ATTRIBUTE_COUNT
    }

    #[cfg(test)]
    pub(super) const fn lpac_opt_out_policy_for_test() -> u32 {
        PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
    }

    #[cfg(test)]
    pub(super) const fn child_process_policy_for_test() -> u32 {
        PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
    }

    #[cfg(test)]
    pub(super) fn approval_profile_name_for_test(
        profile: NoNetworkLpacProfile,
    ) -> Result<&'static str, LaunchError> {
        profile_name(profile, VerifiedLpacRole::ApprovalFrontend)
    }

    #[cfg(test)]
    pub(super) fn secret_input_profile_name_for_test(
        profile: NoNetworkLpacProfile,
    ) -> Result<&'static str, LaunchError> {
        profile_name(profile, VerifiedLpacRole::SecretInputFrontend)
    }

    #[cfg(test)]
    pub(super) fn profiles_have_distinct_sids_for_test(
        profile: NoNetworkLpacProfile,
    ) -> Result<bool, LaunchError> {
        let approval_name =
            wide_nul_str(profile_name(profile, VerifiedLpacRole::ApprovalFrontend)?);
        let secret_input_name = wide_nul_str(profile_name(
            profile,
            VerifiedLpacRole::SecretInputFrontend,
        )?);
        let approval = OwnedAppContainerSid::derive(&approval_name)?;
        let secret_input = OwnedAppContainerSid::derive(&secret_input_name)?;
        // SAFETY: both wrappers contain valid live SIDs. EqualSid returns
        // success only when they identify the same principal; distinct
        // role-bound profile names must not do so.
        Ok(unsafe { EqualSid(approval.raw(), secret_input.raw()) }.is_err())
    }

    #[cfg(test)]
    pub(super) fn environment_for_test(root: &Path) -> Result<Vec<u16>, LaunchError> {
        crate::restricted_process_context::environment_for_test(root)
            .map_err(map_process_context_error)
    }

    #[cfg(test)]
    pub(super) fn validate_working_directory_for_test(path: &Path) -> Result<(), LaunchError> {
        crate::restricted_process_context::validate_working_directory_for_test(path)
            .map_err(map_process_context_error)
    }
}

#[cfg(all(test, windows))]
mod tests {
    #![allow(unsafe_code)]

    use std::fs::OpenOptions;
    use std::net::{Ipv4Addr, TcpListener};
    use std::os::windows::io::{
        AsHandle, AsRawHandle, AsRawSocket, BorrowedHandle, FromRawHandle, OwnedHandle, RawHandle,
    };
    use std::path::Path;
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{
        HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, SetHandleInformation,
    };
    use windows::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::WindowsProgramming::{
        PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
        PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
    };

    use super::RestrictedLauncher;
    use super::{HeldProcessIdentity, InheritedStdio, LaunchError, NoNetworkLpacProfile, sys};
    use crate::attestation::ReleaseAttestation;
    use crate::helper::{FileIdentity, VerifiedHelper};

    fn anonymous_pipe() -> Result<(OwnedHandle, OwnedHandle), Box<dyn std::error::Error>> {
        let mut read = HANDLE::default();
        let mut write = HANDLE::default();
        // SAFETY: both output pointers are valid and each successful raw handle is
        // transferred exactly once into an OwnedHandle.
        unsafe {
            CreatePipe(&raw mut read, &raw mut write, None, 0)?;
            Ok((
                OwnedHandle::from_raw_handle(read.0),
                OwnedHandle::from_raw_handle(write.0),
            ))
        }
    }

    fn parse_environment(block: &[u16]) -> Result<Vec<String>, std::string::FromUtf16Error> {
        block
            .split(|unit| *unit == 0)
            .take_while(|entry| !entry.is_empty())
            .map(String::from_utf16)
            .collect()
    }

    #[test]
    fn stdio_allowlist_contains_only_unique_selected_handles()
    -> Result<(), Box<dyn std::error::Error>> {
        let (read, write) = anonymous_pipe()?;
        let list = InheritedStdio::new(read.as_handle(), write.as_handle(), write.as_handle())?;
        assert_eq!(list.unique_handle_count(), 2);
        assert_eq!(
            format!("{list:?}"),
            "InheritedStdio { input: \"[HANDLE]\", output: \"[HANDLE]\", error: \"[HANDLE]\" }"
        );
        Ok(())
    }

    #[test]
    fn already_inheritable_stdio_sources_are_rejected_before_launch()
    -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or(LaunchError::OperatingSystem)?;
        let flight = crate::inheritable_handle_launch::acquire_inheritable_handle_launch(deadline)
            .map_err(|_| LaunchError::OperatingSystem)?;
        let (read, write) = anonymous_pipe()?;
        // SAFETY: the exact owned pipe source is live. The global flight keeps
        // every cooperating inheriting launch out until the flag is restored.
        unsafe {
            SetHandleInformation(
                HANDLE(read.as_raw_handle()),
                HANDLE_FLAG_INHERIT.0,
                HANDLE_FLAG_INHERIT,
            )?;
        }
        let public_result =
            InheritedStdio::new(read.as_handle(), write.as_handle(), write.as_handle());
        let private_result = InheritedStdio::for_secret_input_servers(
            read.as_handle(),
            write.as_handle(),
            write.as_handle(),
        );
        // SAFETY: restore the same live source before releasing the flight.
        unsafe {
            SetHandleInformation(
                HANDLE(read.as_raw_handle()),
                HANDLE_FLAG_INHERIT.0,
                HANDLE_FLAGS(0),
            )?;
        }
        drop(flight);
        assert!(matches!(public_result, Err(LaunchError::InvalidHandle)));
        assert!(matches!(private_result, Err(LaunchError::InvalidHandle)));
        Ok(())
    }

    #[test]
    fn disk_handles_cannot_cross_the_stdio_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let disk = OpenOptions::new().read(true).write(true).open("NUL")?;
        assert!(matches!(
            InheritedStdio::new(disk.as_handle(), disk.as_handle(), disk.as_handle()),
            Err(LaunchError::InvalidHandle)
        ));
        Ok(())
    }

    #[test]
    fn inherited_sockets_cannot_cross_the_stdio_boundary() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let raw_socket = usize::try_from(listener.as_raw_socket())?;
        // SAFETY: the listener stays alive for the complete borrow and Winsock
        // SOCKET values occupy the same pointer-sized handle representation.
        let borrowed = unsafe { BorrowedHandle::borrow_raw(raw_socket as RawHandle) };
        assert!(matches!(
            InheritedStdio::new(borrowed, borrowed, borrowed),
            Err(LaunchError::InvalidHandle)
        ));
        Ok(())
    }

    #[test]
    fn mitigation_job_and_lpac_contract_is_fail_closed() {
        let mitigation = sys::mitigation_policy_for_test();
        assert_ne!(mitigation & (1 << 24), 0, "strict handle checks");
        assert_ne!(mitigation & (1 << 36), 0, "dynamic code prohibited");
        assert_ne!(mitigation & (1 << 52), 0, "remote images prohibited");
        assert_ne!(mitigation & (1 << 56), 0, "low-label images prohibited");
        let job_flags = sys::job_flags_for_test();
        assert_ne!(job_flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.0, 0);
        assert_ne!(job_flags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS.0, 0);
        assert_eq!(sys::attribute_count_for_test(), 6);
        assert_eq!(sys::capability_count_for_test(), 0);
        assert_eq!(
            sys::lpac_opt_out_policy_for_test(),
            PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT
        );
        assert_eq!(
            sys::child_process_policy_for_test(),
            PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
        );
        assert_eq!(NoNetworkLpacProfile::v1().revision(), 1);
    }

    #[test]
    fn profile_names_are_role_separated_deterministic_and_revision_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            sys::approval_profile_name_for_test(NoNetworkLpacProfile::v1())?,
            "YourWallet.ApprovalFrontend.LPAC.v1"
        );
        assert_eq!(
            sys::secret_input_profile_name_for_test(NoNetworkLpacProfile::v1())?,
            "YourWallet.SecretInputFrontend.LPAC.v1"
        );
        assert_ne!(
            sys::approval_profile_name_for_test(NoNetworkLpacProfile::v1())?,
            sys::secret_input_profile_name_for_test(NoNetworkLpacProfile::v1())?
        );
        let unknown = NoNetworkLpacProfile {
            profile_revision: 2,
        };
        assert!(matches!(
            sys::approval_profile_name_for_test(unknown),
            Err(LaunchError::InvalidProfile)
        ));
        assert!(matches!(
            sys::secret_input_profile_name_for_test(unknown),
            Err(LaunchError::InvalidProfile)
        ));
        Ok(())
    }

    #[test]
    fn role_separated_profile_names_derive_distinct_kernel_sids()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(sys::profiles_have_distinct_sids_for_test(
            NoNetworkLpacProfile::v1()
        )?);
        Ok(())
    }

    #[test]
    fn environment_is_an_exact_allowlist_without_user_secrets()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = sys::environment_for_test(Path::new(r"C:\Windows"))?;
        assert!(block.ends_with(&[0, 0]));
        assert_eq!(
            parse_environment(&block)?,
            [r"SystemRoot=C:\Windows", r"WINDIR=C:\Windows"]
        );
        let decoded = String::from_utf16(&block)?;
        for ambient_name in [
            "PATH",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "AUTHORIZATION",
            "PASSWORD",
            "SECRET",
            "TOKEN",
        ] {
            assert!(!decoded.contains(ambient_name));
        }
        Ok(())
    }

    #[test]
    fn relative_and_user_writable_working_directories_are_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(matches!(
            sys::validate_working_directory_for_test(Path::new("relative")),
            Err(LaunchError::UnsafeWorkingDirectory)
        ));
        let current = std::env::current_dir()?;
        assert!(matches!(
            sys::validate_working_directory_for_test(&current),
            Err(LaunchError::UnsafeWorkingDirectory)
        ));
        Ok(())
    }

    #[test]
    fn held_identity_binds_process_artifact_and_profile() {
        let identity = HeldProcessIdentity {
            process_id: 42,
            helper_file: FileIdentity {
                volume_serial_number: 7,
                file_index: 9,
                file_size: 11,
            },
            helper_manifest_digest: [13; 32],
            profile_revision: NoNetworkLpacProfile::v1().revision(),
        };
        assert_eq!(identity.process_id(), 42);
        assert_eq!(identity.helper_file().file_index, 9);
        assert_eq!(identity.helper_manifest_digest(), [13; 32]);
        assert_eq!(identity.profile_revision(), 1);
    }

    #[test]
    fn launcher_requires_exact_release_bound_helper_manifest() {
        let profile = NoNetworkLpacProfile::v1();
        let development = RestrictedLauncher::new(ReleaseAttestation::default(), profile);
        assert_eq!(
            development.require_allowed_helper([5; 32]),
            Err(LaunchError::ReleaseNotAttested)
        );

        let release =
            ReleaseAttestation::with_helper_manifests_for_test([[5; 32], [6; 32], [7; 32]]);
        let launcher = RestrictedLauncher::new(release, profile);
        assert_eq!(launcher.require_allowed_helper([5; 32]), Ok(()));
        assert_eq!(launcher.require_allowed_helper([6; 32]), Ok(()));
        assert_eq!(launcher.require_allowed_helper([7; 32]), Ok(()));
        assert_eq!(
            launcher.require_allowed_helper([8; 32]),
            Err(LaunchError::HelperManifestNotAllowed)
        );
    }

    #[test]
    fn generic_launcher_rejects_allowlisted_key_agent_before_process_creation()
    -> Result<(), Box<dyn std::error::Error>> {
        let key_agent = VerifiedHelper::for_key_agent_activation_test()?;
        let release = ReleaseAttestation::with_helper_manifests_for_test([
            key_agent.manifest_digest(),
            [6; 32],
            [7; 32],
        ]);
        let launcher = RestrictedLauncher::new(release, NoNetworkLpacProfile::v1());
        let (read, write) = anonymous_pipe()?;
        let stdio = InheritedStdio::new(read.as_handle(), write.as_handle(), write.as_handle())?;

        let development =
            RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());
        assert!(matches!(
            development.spawn(&key_agent, &stdio),
            Err(LaunchError::KeyAgentRequiresSupervisorActivation)
        ));
        assert!(matches!(
            development.spawn_secret_input(&key_agent, &stdio),
            Err(LaunchError::KeyAgentRequiresSupervisorActivation)
        ));
        assert!(matches!(
            launcher.spawn(&key_agent, &stdio),
            Err(LaunchError::KeyAgentRequiresSupervisorActivation)
        ));
        assert!(matches!(
            launcher.spawn_secret_input(&key_agent, &stdio),
            Err(LaunchError::KeyAgentRequiresSupervisorActivation)
        ));
        Ok(())
    }

    #[test]
    fn launch_entry_points_reject_cross_role_and_other_before_release_or_win32()
    -> Result<(), Box<dyn std::error::Error>> {
        let approval = VerifiedHelper::for_approval_channel_test(true)?;
        let secret_input = VerifiedHelper::for_secret_input_channel_test()?;
        let other = VerifiedHelper::for_approval_channel_test(false)?;
        let launcher =
            RestrictedLauncher::new(ReleaseAttestation::default(), NoNetworkLpacProfile::v1());
        let (read, write) = anonymous_pipe()?;
        let stdio = InheritedStdio::new(read.as_handle(), write.as_handle(), write.as_handle())?;

        assert!(matches!(
            launcher.spawn(&secret_input, &stdio),
            Err(LaunchError::HelperRoleNotAllowed)
        ));
        assert!(matches!(
            launcher.spawn(&other, &stdio),
            Err(LaunchError::HelperRoleNotAllowed)
        ));
        assert!(matches!(
            launcher.spawn_secret_input(&approval, &stdio),
            Err(LaunchError::HelperRoleNotAllowed)
        ));
        assert!(matches!(
            launcher.spawn_secret_input(&other, &stdio),
            Err(LaunchError::HelperRoleNotAllowed)
        ));

        // The exact roles advance to the still-disabled release gate, proving
        // the role checks do not accidentally reject their intended frontend.
        assert!(matches!(
            launcher.spawn(&approval, &stdio),
            Err(LaunchError::ReleaseNotAttested)
        ));
        assert!(matches!(
            launcher.spawn_secret_input(&secret_input, &stdio),
            Err(LaunchError::ReleaseNotAttested)
        ));
        Ok(())
    }
}
