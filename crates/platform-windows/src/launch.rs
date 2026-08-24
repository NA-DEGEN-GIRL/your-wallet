//! Restricted one-shot helper launcher.
//!
//! The low-level Win32 launcher uses separate persistent, revision-bound LPAC
//! profiles for the manifest-derived Approval and Secret Input roles. Both have
//! zero capability SIDs, opt out of `ALL APPLICATION PACKAGES`, receive an
//! explicit inherited-handle list and minimal environment, start suspended,
//! verify the resulting `AppContainer` token, and enter a kill-on-close
//! single-process job before resume. There is deliberately no unsandboxed
//! fallback. Crate-private launch also remains disabled until release evidence
//! for the exact signed artifact is compiled into [`ReleaseAttestation`].

use core::fmt;
#[cfg(all(test, windows))]
use std::ffi::OsString;
#[cfg(all(test, windows))]
use std::os::windows::ffi::OsStrExt as _;
#[cfg(windows)]
use std::time::{Duration, Instant};

use thiserror::Error;

#[cfg(windows)]
use crate::approval_activation::ApprovalActivationSeal;
#[cfg(all(test, windows))]
use crate::attestation::ArtifactDigest;
use crate::attestation::ReleaseAttestation;
use crate::helper::{FileIdentity, VerifiedHelper};
#[cfg(windows)]
use crate::key_agent_supervisor::ApprovalParentSourcePreparedKeyAgent;
#[cfg(all(test, windows))]
use crate::pipe::PrivateApprovalPipes;
#[cfg(windows)]
use approval_wire::ApprovalParentHello;

#[cfg(windows)]
const APPROVAL_RESUME_REJECTION_GRACE: Duration = Duration::from_secs(5);
#[cfg(windows)]
const APPROVAL_EXCHANGE_REJECTION_GRACE: Duration = Duration::from_secs(5);

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

    const fn requires_parent_proof(self) -> bool {
        matches!(self, Self::ApprovalFrontend | Self::SecretInputFrontend)
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
    /// Approval may resume only from the complete parent-bound bootstrap.
    #[error("Approval requires private parent-bound activation")]
    ApprovalRequiresParentBoundActivation,
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
    /// A rejected child could not be synchronously terminated and reaped.
    #[error("restricted helper rejection cleanup failed")]
    Cleanup,
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

    /// Selects synchronous named-pipe server ends created and retained by a
    /// crate-private frontend pipe owner. Some Windows versions deny
    /// `GetNamedPipeInfo` for direction-limited server handles, so this path
    /// validates liveness, non-inheritability, pipe kind, and an exact current-
    /// process client PID/session before the handle can enter the launch set.
    pub(crate) fn for_child_pipe_servers(
        input: std::os::windows::io::BorrowedHandle<'handle>,
        output: std::os::windows::io::BorrowedHandle<'handle>,
        error: std::os::windows::io::BorrowedHandle<'handle>,
    ) -> Result<Self, LaunchError> {
        sys::validate_child_pipe_server(input)?;
        sys::validate_child_pipe_server(output)?;
        sys::validate_child_pipe_server(error)?;
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

/// Unforgeable permission to copy one already-proven logical Key Agent parent
/// capability into a child that this module still holds suspended.
///
/// Only this module can construct the seal. Sibling modules may accept a
/// borrow at their exact duplication leaf, but cannot independently authorize
/// a child-local handle injection.
#[cfg(windows)]
pub(crate) struct ApprovalLogicalParentInjectionSeal {
    _private: (),
}

#[cfg(windows)]
impl ApprovalLogicalParentInjectionSeal {
    const fn new() -> Self {
        Self { _private: () }
    }
}

/// Opaque child-local coordinates for the exact logical Key Agent parent.
///
/// The values name objects only in the suspended Approval child's handle table
/// and are never formatted. Construction requires the launch-local injection
/// seal, so arbitrary scalar pairs cannot enter the dormant activation state.
#[cfg(windows)]
#[must_use = "the injected logical parent must remain bound to its suspended Approval"]
#[allow(dead_code)] // Child-local coordinates are consumed only by the sealed child bootstrap/test.
pub(crate) struct InjectedApprovalLogicalParent {
    process_handle: u64,
    process_id: u32,
}

#[cfg(windows)]
impl InjectedApprovalLogicalParent {
    pub(crate) const fn from_child_local(
        process_handle: u64,
        process_id: u32,
        _seal: &ApprovalLogicalParentInjectionSeal,
    ) -> Self {
        Self {
            process_handle,
            process_id,
        }
    }

    #[must_use]
    #[allow(dead_code)] // Reserved for the sealed Approval child bootstrap.
    pub(crate) const fn process_handle(&self) -> u64 {
        self.process_handle
    }

    #[must_use]
    #[allow(dead_code)] // Reserved for the sealed Approval child bootstrap.
    pub(crate) const fn process_id(&self) -> u32 {
        self.process_id
    }
}

#[cfg(windows)]
impl fmt::Debug for InjectedApprovalLogicalParent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InjectedApprovalLogicalParent([REDACTED HANDLE AND PID])")
    }
}

/// Public fail-closed policy carrier whose launch operations are crate-private.
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

    #[cfg(all(test, windows))]
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

    /// Rejects the parentless legacy Approval launcher before process creation.
    ///
    /// The complete parent-bound activation path is the sole production path
    /// permitted to create and resume Approval. This method samples no release
    /// policy, nonce, pipe, process, or request state.
    ///
    /// # Errors
    ///
    /// Returns [`LaunchError::HelperRoleNotAllowed`] unless the manifest-derived
    /// role is exactly Approval Frontend. The Key Agent receives the narrower
    /// [`LaunchError::KeyAgentRequiresSupervisorActivation`]. Both errors occur
    /// before release evaluation or process creation. Returns
    /// [`LaunchError::ApprovalRequiresParentBoundActivation`] for the exact
    /// Approval role without consulting release policy or creating resources.
    #[cfg(windows)]
    #[allow(dead_code)] // The v2 bootstrap cannot use this parentless legacy path.
    pub(crate) fn spawn(
        self,
        helper: &VerifiedHelper,
        handles: &InheritedStdio<'_>,
    ) -> Result<LaunchedHelper, LaunchError> {
        let role = VerifiedLpacRole::from_helper(helper)?;
        if role != VerifiedLpacRole::ApprovalFrontend {
            return Err(LaunchError::HelperRoleNotAllowed);
        }
        let _ = (self, handles);
        Err(LaunchError::ApprovalRequiresParentBoundActivation)
    }

    /// Test-only launch of one exact ignored libtest fixture inside the real
    /// Approval LPAC, with a separate logical Key Agent parent capability.
    /// The ordinary channel-supervisor process/image proof remains unchanged.
    #[cfg(all(test, windows))]
    pub(crate) fn spawn_approval_parent_probe_for_kernel_test(
        self,
        helper: &VerifiedHelper,
        handles: &InheritedStdio<'_>,
        logical_parent: &ApprovalParentSourcePreparedKeyAgent,
        command_line: &mut [u16],
    ) -> Result<LaunchedHelper, LaunchError> {
        let role = self.require_approval_frontend(helper)?;
        sys::launch_approval_parent_probe(
            helper,
            handles,
            self.profile,
            role,
            logical_parent,
            command_line,
        )
    }

    /// Launches Secret Input with two additional, least-privilege proof handles
    /// for the exact calling process and its held executable image. The handles
    /// are injected non-inheritable while the child remains suspended; only the
    /// selected stdio objects enter the inheritable handle list.
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
    pub(crate) fn spawn(self, helper: &VerifiedHelper) -> Result<LaunchedHelper, LaunchError> {
        let role = VerifiedLpacRole::from_helper(helper)?;
        if role != VerifiedLpacRole::ApprovalFrontend {
            return Err(LaunchError::HelperRoleNotAllowed);
        }
        Err(LaunchError::UnsupportedPlatform)
    }
}

/// Prepares one exact Approval Frontend in the fixed no-network LPAC and keeps
/// its primary thread suspended after both supervisor and logical Key Agent
/// parent capabilities have been injected.
///
/// This sealed path deliberately accepts no attestation, generic launcher, or
/// selectable profile. The caller already owns the pinned release Approval
/// artifact and the intact storage-proven Key Agent aggregate.
#[cfg(windows)]
pub(crate) fn prepare_parent_bound_approval(
    helper: &VerifiedHelper,
    handles: &InheritedStdio<'_>,
    parent_source: &ApprovalParentSourcePreparedKeyAgent,
    _seal: &ApprovalActivationSeal,
) -> Result<HeldSuspendedApproval, LaunchError> {
    let role = VerifiedLpacRole::from_helper(helper)?;
    if role != VerifiedLpacRole::ApprovalFrontend {
        return Err(LaunchError::HelperRoleNotAllowed);
    }
    sys::prepare_parent_bound_approval(helper, handles, role, parent_source)
}

#[cfg(all(test, windows))]
const APPROVAL_PARENT_PROBE_CHILD_FIXTURE: &str =
    "launch::tests::approval_lpac_parent_probe_child_fixture";
#[cfg(all(test, windows))]
const APPROVAL_PARENT_PROBE_MAGIC: [u8; 8] = *b"YWAPLP01";
#[cfg(all(test, windows))]
const APPROVAL_PARENT_PROBE_FRAME_BYTES: usize = 28;
#[cfg(all(test, windows))]
const APPROVAL_PARENT_PROBE_SUCCESS_EXIT_CODE: u32 = 0x51A0_0001;

/// Stable stage categories for the test-only Approval LPAC kernel probe.
#[cfg(all(test, windows))]
#[derive(Debug, Error)]
pub(crate) enum ApprovalParentProbeError {
    #[error("Approval parent probe source revalidation failed")]
    ParentState,
    #[error("Approval parent probe private pipes failed")]
    PipeSetup,
    #[error("Approval parent probe inherited-handle policy failed")]
    Inheritance,
    #[error("Approval parent probe launch failed: {0}")]
    Launch(LaunchError),
    #[error("Approval parent probe did not receive a child-local capability")]
    MissingCapability,
    #[error("Approval parent probe request write failed")]
    RequestWrite,
    #[error("Approval parent probe cleanup failed")]
    Cleanup,
    #[error("Approval parent probe child validation failed: {0}")]
    Child(LaunchError),
}

/// Runs the exact logical-parent capability probe inside a real zero-capability
/// Approval LPAC. This is repo-local kernel feasibility evidence only: it does
/// not activate the production channel, prove a signed/mapped release image, or
/// change the compiled fail-closed release policy.
#[cfg(all(test, windows))]
pub(crate) fn prove_approval_parent_in_lpac_for_kernel_test(
    helper: &VerifiedHelper,
    logical_parent: &ApprovalParentSourcePreparedKeyAgent,
) -> Result<(), ApprovalParentProbeError> {
    logical_parent
        .revalidate_for_lpac_probe()
        .map_err(|_| ApprovalParentProbeError::ParentState)?;
    let pipes = PrivateApprovalPipes::create().map_err(|_| ApprovalParentProbeError::PipeSetup)?;
    let inherited = InheritedStdio::for_child_pipe_servers(
        pipes.child_input(),
        pipes.child_output(),
        pipes.child_output(),
    )
    .map_err(|_| ApprovalParentProbeError::Inheritance)?;
    let attestation = ReleaseAttestation::with_helper_manifests_for_test(
        ArtifactDigest::for_test([0x91; 32]),
        [helper.manifest_digest(), [0x92; 32], [0x93; 32]],
    );
    let restricted_launcher = RestrictedLauncher::new(attestation, NoNetworkLpacProfile::v1());

    let mut command_line = OsString::from("\"");
    command_line.push(helper.path().as_os_str());
    command_line.push("\" --exact ");
    command_line.push(APPROVAL_PARENT_PROBE_CHILD_FIXTURE);
    command_line.push(" --ignored --test-threads=1 --quiet");
    let mut command_line = command_line.encode_wide().collect::<Vec<_>>();
    command_line.push(0);
    let debug_luid =
        sys::debug_privilege_luid_for_kernel_test().map_err(ApprovalParentProbeError::Launch)?;
    let deadline = Instant::now().checked_add(Duration::from_secs(25)).ok_or(
        ApprovalParentProbeError::Launch(LaunchError::OperatingSystem),
    )?;

    let launched = restricted_launcher
        .spawn_approval_parent_probe_for_kernel_test(
            helper,
            &inherited,
            logical_parent,
            &mut command_line,
        )
        .map_err(ApprovalParentProbeError::Launch)?;
    let Some(proof) = launched.approval_parent_probe() else {
        return match cleanup_approval_parent_probe(launched) {
            Ok(()) => Err(ApprovalParentProbeError::MissingCapability),
            Err(error) => Err(error),
        };
    };
    let mut frame = [0_u8; APPROVAL_PARENT_PROBE_FRAME_BYTES];
    frame[..8].copy_from_slice(&APPROVAL_PARENT_PROBE_MAGIC);
    frame[8..16].copy_from_slice(&proof.process_handle().to_be_bytes());
    frame[16..20].copy_from_slice(&proof.process_id().to_be_bytes());
    frame[20..28].copy_from_slice(&debug_luid);

    let (writer, _response_reader) = pipes.into_parent();
    if writer.write_all(&frame, deadline).is_err() {
        return match cleanup_approval_parent_probe(launched) {
            Ok(()) => Err(ApprovalParentProbeError::RequestWrite),
            Err(error) => Err(error),
        };
    }
    launched
        .wait_for_success_for_kernel_test(deadline)
        .map_err(ApprovalParentProbeError::Child)?;
    logical_parent
        .revalidate_for_lpac_probe()
        .map_err(|_| ApprovalParentProbeError::ParentState)
}

#[cfg(all(test, windows))]
fn cleanup_approval_parent_probe(launched: LaunchedHelper) -> Result<(), ApprovalParentProbeError> {
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(5))
        .ok_or(ApprovalParentProbeError::Cleanup)?;
    launched
        .terminate_and_wait(deadline)
        .map_err(|_| ApprovalParentProbeError::Cleanup)
}

/// Identity record for one held helper process.
///
/// While owned by [`LaunchedHelper`], its private process handle keeps the exact
/// process object selected. The file and manifest identities bind that selection
/// to the already verified helper artifact and its manifest-derived role; the
/// role plus profile revision deterministically bind the sandbox identity used
/// at creation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct HeldProcessIdentity {
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
    pub(crate) const fn process_id(self) -> u32 {
        self.process_id
    }

    /// Returns the verified executable file identity.
    #[must_use]
    pub(crate) const fn helper_file(self) -> FileIdentity {
        self.helper_file
    }

    /// Returns the verified helper-manifest digest.
    #[must_use]
    pub(crate) const fn helper_manifest_digest(self) -> [u8; 32] {
        self.helper_manifest_digest
    }

    /// Returns the no-network LPAC profile revision used for creation.
    #[must_use]
    pub(crate) const fn profile_revision(self) -> u32 {
        self.profile_revision
    }
}

/// Test-owned Approval executable copy placed beneath the exact profile's
/// OS-managed `AppContainer` folder.
#[cfg(all(test, windows))]
pub(crate) struct ApprovalLpacKernelTestFixture(sys::ApprovalLpacKernelTestFixture);

#[cfg(all(test, windows))]
impl ApprovalLpacKernelTestFixture {
    pub(crate) fn create() -> Result<Self, LaunchError> {
        sys::ApprovalLpacKernelTestFixture::create().map(Self)
    }

    pub(crate) fn path(&self) -> &std::path::Path {
        self.0.path()
    }

    pub(crate) fn cleanup(self) -> Result<(), LaunchError> {
        self.0.cleanup()
    }
}

#[cfg(all(test, windows))]
impl fmt::Debug for ApprovalLpacKernelTestFixture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ApprovalLpacKernelTestFixture([REDACTED PATH])")
    }
}

#[cfg(test)]
mod debug_tests {
    #[cfg(windows)]
    use super::{ApprovalLogicalParentInjectionSeal, InjectedApprovalLogicalParent};
    use super::{HeldProcessIdentity, NoNetworkLpacProfile, VerifiedLpacRole};
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

    #[test]
    fn every_lpac_frontend_requires_injected_parent_proof() {
        assert!(VerifiedLpacRole::ApprovalFrontend.requires_parent_proof());
        assert!(VerifiedLpacRole::SecretInputFrontend.requires_parent_proof());
    }

    #[cfg(windows)]
    #[test]
    fn logical_parent_coordinates_are_child_local_and_debug_redacted() {
        let seal = ApprovalLogicalParentInjectionSeal::new();
        let injected = InjectedApprovalLogicalParent::from_child_local(
            0x7fff_abcd_1234_5678,
            0xfedc_ba98,
            &seal,
        );

        assert_eq!(injected.process_handle(), 0x7fff_abcd_1234_5678);
        assert_eq!(injected.process_id(), 0xfedc_ba98);
        assert_eq!(
            format!("{injected:?}"),
            "InjectedApprovalLogicalParent([REDACTED HANDLE AND PID])"
        );
    }
}

/// One parent-bound Approval held before its first user-mode instruction.
///
/// The owner retains the exact process, its single-process kill-on-close Job,
/// the suspended primary thread, the pinned artifact/profile identity, and two
/// distinct parent proofs. Production exposes only the activation-sealed,
/// hello-only resume used by the consuming parent-bound bootstrap transition.
#[cfg(windows)]
#[must_use = "dropping a suspended Approval attempts bounded termination and reap"]
pub(crate) struct HeldSuspendedApproval {
    guard: HeldApprovalProcessGuard,
    thread: sys::OwnedWinHandle,
    parent_proof: InjectedParentProof,
    logical_parent: InjectedApprovalLogicalParent,
}

#[cfg(windows)]
impl HeldSuspendedApproval {
    /// Builds the only parent hello that may describe this suspended child.
    ///
    /// Both proof capabilities contain child-local handle-table coordinates.
    /// Keeping construction behind the activation seal prevents either tuple
    /// from escaping as a generic scalar/resource API.
    pub(crate) fn parent_hello_for_bootstrap(
        &self,
        parent_nonce: [u8; 32],
        _seal: &ApprovalActivationSeal,
    ) -> Result<ApprovalParentHello, LaunchError> {
        ApprovalParentHello::new(
            self.parent_proof.process_id(),
            self.parent_proof.process_handle(),
            self.parent_proof.image_handle(),
            self.logical_parent.process_id(),
            self.logical_parent.process_handle(),
            parent_nonce,
        )
        .map_err(|_| LaunchError::SandboxVerification)
    }

    /// Resumes the exact primary thread once for the sealed Approval bootstrap.
    ///
    /// No public or generic resume primitive is exposed. Consuming the suspended
    /// typestate makes a second safe-Rust resume impossible. Any resume rejection
    /// receives its own fixed synchronous cleanup attempt, with cleanup failure
    /// taking precedence.
    pub(crate) fn resume_for_bootstrap(
        self,
        _seal: &ApprovalActivationSeal,
    ) -> Result<HeldRunningApproval, LaunchError> {
        let Self {
            guard,
            thread,
            parent_proof,
            logical_parent,
        } = self;
        if let Err(error) = sys::resume_parent_bound_approval(
            guard.process_raw(),
            guard.job_raw(),
            thread.raw(),
            guard.identity().process_id(),
        ) {
            let Some(cleanup_deadline) =
                Instant::now().checked_add(APPROVAL_RESUME_REJECTION_GRACE)
            else {
                drop(guard);
                return Err(LaunchError::Cleanup);
            };
            return match guard.terminate_and_wait(cleanup_deadline) {
                Ok(()) => Err(error),
                Err(_) => Err(LaunchError::Cleanup),
            };
        }
        Ok(HeldRunningApproval {
            guard,
            thread,
            parent_proof,
            logical_parent,
        })
    }

    /// Test-only observation that the exact child is still live in its retained
    /// one-process Job with both mandatory Job limits intact.
    #[cfg(test)]
    pub(crate) fn is_live_in_job_for_test(&self) -> Result<bool, LaunchError> {
        sys::is_live_held_process_in_job_for_test(
            self.guard.process_raw(),
            self.guard.job_raw(),
            self.guard.identity().process_id(),
        )
    }

    /// Explicitly terminates the one-process Job and waits for the exact held
    /// Approval process before the supplied monotonic deadline.
    pub(crate) fn terminate_and_wait(self, deadline: Instant) -> Result<(), LaunchError> {
        self.guard.terminate_and_wait(deadline)
    }
}

#[cfg(windows)]
impl fmt::Debug for HeldSuspendedApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.guard,
            &self.thread,
            &self.parent_proof,
            &self.logical_parent,
        );
        formatter.write_str(
            "HeldSuspendedApproval([SUSPENDED APPROVAL; HELD JOB; REDACTED PARENT PROOFS])",
        )
    }
}

/// The unique post-resume Approval process retained by sealed bootstrap and
/// consumed only by the sealed full exchange or bounded rejection cleanup.
#[cfg(windows)]
#[must_use = "dropping a running Approval attempts bounded termination and reap"]
pub(crate) struct HeldRunningApproval {
    guard: HeldApprovalProcessGuard,
    thread: sys::OwnedWinHandle,
    parent_proof: InjectedParentProof,
    logical_parent: InjectedApprovalLogicalParent,
}

#[cfg(windows)]
impl HeldRunningApproval {
    /// Revalidates that the exact resumed process is live in its retained Job.
    pub(crate) fn revalidate_for_bootstrap(
        &self,
        _seal: &ApprovalActivationSeal,
    ) -> Result<(), LaunchError> {
        sys::revalidate_running_held_process(
            self.guard.process_raw(),
            self.guard.job_raw(),
            self.guard.identity().process_id(),
        )
    }

    /// Revalidates the exact live process/Job and returns its immutable
    /// launcher-branded identity only to the sealed parent exchange.
    pub(crate) fn revalidated_identity_for_exchange(
        &self,
        seal: &ApprovalActivationSeal,
    ) -> Result<HeldProcessIdentity, LaunchError> {
        self.revalidate_for_bootstrap(seal)?;
        Ok(self.guard.identity())
    }

    /// Consumes the running Approval into one deadline-bound natural-exit
    /// observation and requires the ordinary success exit code.
    ///
    /// Response-pipe EOF is not process success: the child may close stdout and
    /// remain live or exit with a failure. On any wait, exit-code, or operating-
    /// system rejection this consuming transition makes its own fresh bounded
    /// terminate/reap attempt. Cleanup failure takes precedence, while closing
    /// the retained kill-on-close Job remains the final fallback.
    pub(crate) fn wait_for_success_for_exchange(
        self,
        deadline: Instant,
        _seal: &ApprovalActivationSeal,
    ) -> Result<HeldExitedApproval, LaunchError> {
        let Self {
            guard,
            thread,
            parent_proof,
            logical_parent,
        } = self;
        let guard = guard.wait_for_success_or_cleanup(deadline)?;
        Ok(HeldExitedApproval {
            guard,
            thread,
            parent_proof,
            logical_parent,
        })
    }

    #[cfg(test)]
    pub(crate) fn is_live_in_job_for_test(&self) -> Result<bool, LaunchError> {
        sys::is_live_held_process_in_job_for_test(
            self.guard.process_raw(),
            self.guard.job_raw(),
            self.guard.identity().process_id(),
        )
    }

    pub(crate) fn terminate_and_wait(self, deadline: Instant) -> Result<(), LaunchError> {
        self.guard.terminate_and_wait(deadline)
    }
}

/// Exact Approval process object retained after deadline-bound exit-code-zero
/// success.
///
/// This terminal typestate is deliberately opaque and has no methods. It keeps
/// the signalled process, one-process Job, immutable identity, primary thread,
/// and both injected parent proofs alive inside the sealed exchange result.
/// Its rejection-cleanup guard is disarmed only after exit code zero.
#[cfg(windows)]
#[must_use = "retain exited Approval evidence with the sealed exchange"]
pub(crate) struct HeldExitedApproval {
    guard: HeldApprovalProcessGuard,
    thread: sys::OwnedWinHandle,
    parent_proof: InjectedParentProof,
    logical_parent: InjectedApprovalLogicalParent,
}

#[cfg(windows)]
impl fmt::Debug for HeldExitedApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.guard,
            &self.thread,
            &self.parent_proof,
            &self.logical_parent,
        );
        formatter
            .write_str("HeldExitedApproval([EXITED APPROVAL; HELD JOB; REDACTED PARENT PROOFS])")
    }
}

#[cfg(windows)]
impl fmt::Debug for HeldRunningApproval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (
            &self.guard,
            &self.thread,
            &self.parent_proof,
            &self.logical_parent,
        );
        formatter
            .write_str("HeldRunningApproval([RUNNING APPROVAL; HELD JOB; REDACTED PARENT PROOFS])")
    }
}

/// Shared fail-closed process ownership beneath the suspended/running typestates.
#[cfg(windows)]
struct HeldApprovalProcessGuard {
    process: sys::OwnedWinHandle,
    job: sys::OwnedWinHandle,
    identity: HeldProcessIdentity,
    cleanup_armed: bool,
}

#[cfg(windows)]
fn resolve_exchange_natural_exit_with_cleanup<W, C>(
    cleanup_armed: &mut bool,
    wait_for_natural_exit: W,
    cleanup_rejected_child: C,
) -> Result<(), LaunchError>
where
    W: FnOnce() -> Result<(), LaunchError>,
    C: FnOnce() -> Option<Result<(), LaunchError>>,
{
    let wait_error = match wait_for_natural_exit() {
        Ok(()) => {
            *cleanup_armed = false;
            return Ok(());
        }
        Err(error) => error,
    };

    let Some(cleanup_result) = cleanup_rejected_child() else {
        // No explicit cleanup attempt occurred, so retain the Drop fallback.
        return Err(LaunchError::Cleanup);
    };
    // Do not start another bounded wait from Drop after an explicit attempt.
    // Kill-on-close remains effective when the attempt failed.
    *cleanup_armed = false;
    cleanup_result.map_err(|_| LaunchError::Cleanup)?;
    Err(wait_error)
}

#[cfg(windows)]
impl HeldApprovalProcessGuard {
    fn process_raw(&self) -> windows::Win32::Foundation::HANDLE {
        self.process.raw()
    }

    fn job_raw(&self) -> windows::Win32::Foundation::HANDLE {
        self.job.raw()
    }

    const fn identity(&self) -> HeldProcessIdentity {
        self.identity
    }

    fn terminate_and_wait(mut self, deadline: Instant) -> Result<(), LaunchError> {
        let result = sys::terminate_and_wait(self.process.raw(), self.job.raw(), deadline);
        // Do not start a second bounded wait from Drop after the explicit
        // attempt. Closing the retained kill-on-close Job remains the final
        // fail-closed fallback if the OS reported a cleanup failure.
        self.cleanup_armed = false;
        result
    }

    fn wait_for_success_or_cleanup(mut self, deadline: Instant) -> Result<Self, LaunchError> {
        let process = self.process.raw();
        let job = self.job.raw();
        resolve_exchange_natural_exit_with_cleanup(
            &mut self.cleanup_armed,
            || sys::wait_for_expected_exit_code(process, deadline, 0, LaunchError::OperatingSystem),
            || {
                Instant::now()
                    .checked_add(APPROVAL_EXCHANGE_REJECTION_GRACE)
                    .map(|cleanup_deadline| sys::terminate_and_wait(process, job, cleanup_deadline))
            },
        )?;
        Ok(self)
    }
}

#[cfg(windows)]
impl Drop for HeldApprovalProcessGuard {
    fn drop(&mut self) {
        if self.cleanup_armed {
            self.cleanup_armed = false;
            let _ = sys::terminate_and_reap_created_child(self.process.raw(), self.job.raw());
        }
    }
}

#[cfg(windows)]
impl fmt::Debug for HeldApprovalProcessGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeldApprovalProcessGuard([HELD PROCESS AND JOB])")
    }
}

/// A process held in a single-process kill-on-close job.
#[cfg(windows)]
pub(crate) struct LaunchedHelper {
    process: sys::OwnedWinHandle,
    job: sys::OwnedWinHandle,
    identity: HeldProcessIdentity,
    parent_proof: Option<InjectedParentProof>,
    #[cfg(test)]
    approval_parent_probe: Option<InjectedApprovalLogicalParent>,
}

/// Numeric values of the two non-inheritable proof handles injected into one
/// suspended Approval or Secret Input child. Values are opaque and never
/// formatted; the child validates the underlying kernel objects before
/// accepting protocol bytes.
#[cfg(windows)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct InjectedParentProof {
    process_handle: u64,
    image_handle: u64,
    process_id: u32,
}

#[cfg(windows)]
impl InjectedParentProof {
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
impl fmt::Debug for InjectedParentProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InjectedParentProof([REDACTED HANDLES AND PID])")
    }
}

#[cfg(windows)]
impl LaunchedHelper {
    /// Returns the held process, helper-artifact, and sandbox-profile identity.
    #[must_use]
    pub(crate) const fn identity(&self) -> HeldProcessIdentity {
        self.identity
    }

    /// Revalidates the exact held PID, process-to-Job membership, and Job limits.
    #[must_use]
    pub(crate) fn is_held_in_job(&self) -> bool {
        self.revalidate_held_process().is_ok()
    }

    /// Requeries the live OS objects retained by this launch capability.
    pub(crate) fn revalidate_held_process(&self) -> Result<(), LaunchError> {
        sys::revalidate_held_process(
            self.process.raw(),
            self.job.raw(),
            self.identity.process_id(),
        )
    }

    #[allow(dead_code)] // Read only by the dormant private arming seam.
    pub(crate) const fn parent_proof(&self) -> Option<InjectedParentProof> {
        self.parent_proof
    }

    #[cfg(test)]
    pub(crate) fn approval_parent_probe(&self) -> Option<&InjectedApprovalLogicalParent> {
        self.approval_parent_probe.as_ref()
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
            #[cfg(test)]
                approval_parent_probe: _,
        } = self;
        let result = sys::terminate_and_wait(process.raw(), job.raw(), deadline);
        drop(job);
        drop(process);
        result
    }

    /// Waits for the exact test child to emit the dedicated proof-complete exit
    /// code. Any other result attempts termination and reaping of the one-process
    /// Job until the bounded cleanup deadline and surfaces cleanup failure.
    #[cfg(test)]
    pub(crate) fn wait_for_success_for_kernel_test(
        self,
        deadline: Instant,
    ) -> Result<(), LaunchError> {
        let Self {
            process,
            job,
            identity: _,
            parent_proof: _,
            approval_parent_probe: _,
        } = self;
        let result = sys::wait_for_success_for_kernel_test(process.raw(), deadline);
        let cleanup = result
            .as_ref()
            .err()
            .map(|_| sys::cleanup_failed_kernel_probe(process.raw(), job.raw()))
            .transpose();
        drop(job);
        drop(process);
        cleanup?;
        result
    }
}

#[cfg(windows)]
impl fmt::Debug for LaunchedHelper {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("LaunchedHelper");
        debug
            .field("process", &"[HANDLE]")
            .field("job", &"[HANDLE]")
            .field("identity", &self.identity)
            .field("parent_proof", &self.parent_proof);
        #[cfg(test)]
        debug.field("approval_parent_probe", &self.approval_parent_probe);
        debug.finish()
    }
}

#[cfg(not(windows))]
#[derive(Debug)]
pub(crate) struct LaunchedHelper;

#[cfg(windows)]
mod sys {
    #![allow(unsafe_code)]

    use core::ffi::c_void;
    use core::mem::size_of;
    use core::ptr;
    use std::collections::HashSet;
    #[cfg(test)]
    use std::fs::{File, OpenOptions};
    #[cfg(test)]
    use std::io;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, BorrowedHandle};
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    #[cfg(test)]
    use windows::Win32::Foundation::LUID;
    use windows::Win32::Foundation::{
        CloseHandle, CompareObjectHandles, DUPLICATE_HANDLE_OPTIONS, DUPLICATE_SAME_ACCESS,
        DuplicateHandle, ERROR_ALREADY_EXISTS, ERROR_INVALID_PARAMETER, GENERIC_READ,
        GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    #[cfg(test)]
    use windows::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows::Win32::Security::Isolation::GetAppContainerFolderPath;
    use windows::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
    };
    use windows::Win32::Security::{
        CheckTokenMembershipEx, DuplicateToken, EqualSid, FreeSid, GetTokenInformation, IsValidSid,
        PSID, SECURITY_CAPABILITIES, SecurityIdentification, TOKEN_APPCONTAINER_INFORMATION,
        TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER, TokenAppContainerSid, TokenCapabilities,
        TokenIsAppContainer, TokenIsLessPrivilegedAppContainer, TokenUser,
    };
    #[cfg(test)]
    use windows::Win32::Security::{
        DACL_SECURITY_INFORMATION, IsValidSecurityDescriptor, LookupPrivilegeValueW,
        PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SetFileSecurityW,
    };
    use windows::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
    };
    use windows::Win32::System::Com::CoTaskMemFree;
    use windows::Win32::System::JobObjects::{
        CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject,
    };
    use windows::Win32::System::Pipes::{
        GetNamedPipeClientProcessId, GetNamedPipeClientSessionId, GetNamedPipeInfo,
    };
    use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
    use windows::Win32::System::SystemServices::{CTMF_INCLUDE_APPCONTAINER, CTMF_INCLUDE_LPAC};
    use windows::Win32::System::Threading::{
        CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess,
        GetProcessId, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
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
    use windows::core::{BOOL, PCWSTR, PWSTR};

    use super::{
        ApprovalLogicalParentInjectionSeal, ApprovalParentSourcePreparedKeyAgent,
        HeldApprovalProcessGuard, HeldProcessIdentity, HeldSuspendedApproval, InheritedStdio,
        InjectedParentProof, LaunchError, LaunchedHelper, NoNetworkLpacProfile, VerifiedHelper,
        VerifiedLpacRole,
    };
    use crate::appcontainer_profile_api::{
        AppContainerProfileApiGuard, acquire_appcontainer_profile_api,
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
    #[cfg(test)]
    const APPROVAL_KERNEL_FIXTURE_MITIGATION_POLICY: u64 =
        HELPER_MITIGATION_POLICY & !MITIGATION_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON;

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

    /// Owns one as-yet-untrusted SID returned by a profile API.
    ///
    /// The native allocation is retained before the post-call impersonation
    /// check and is released even when that check or SID validation fails.
    struct UnvalidatedProfileApiSid {
        raw: Option<PSID>,
    }

    impl UnvalidatedProfileApiSid {
        const fn new(raw: PSID) -> Self {
            Self { raw: Some(raw) }
        }

        fn into_validated(mut self) -> Result<OwnedAppContainerSid, LaunchError> {
            let sid = self.raw.ok_or(LaunchError::SandboxVerification)?;
            // SAFETY: the pointer is inspected only for validity before this
            // owner transfers it to the validated wrapper.
            if sid.is_invalid() || !unsafe { IsValidSid(sid) }.as_bool() {
                return Err(LaunchError::SandboxVerification);
            }
            self.raw = None;
            Ok(OwnedAppContainerSid(sid))
        }
    }

    impl Drop for UnvalidatedProfileApiSid {
        fn drop(&mut self) {
            let Some(sid) = self.raw.take() else {
                return;
            };
            if sid.is_invalid() {
                return;
            }
            // SAFETY: every non-null success value remains owned by this guard
            // until validation transfers it exactly once.
            unsafe {
                let _ = FreeSid(sid);
            }
        }
    }

    /// Owns one as-yet-untrusted `CoTaskMem` path returned by a profile API.
    struct UnvalidatedProfileApiFolderPath {
        raw: Option<PWSTR>,
    }

    impl UnvalidatedProfileApiFolderPath {
        const fn new(raw: PWSTR) -> Self {
            Self { raw: Some(raw) }
        }

        fn to_path(&self) -> Result<PathBuf, LaunchError> {
            let folder = self.raw.ok_or(LaunchError::OperatingSystem)?;
            if folder.is_null() {
                return Err(LaunchError::OperatingSystem);
            }
            // SAFETY: a successful non-null result is NUL terminated and stays
            // owned by this wrapper for the complete conversion.
            unsafe { folder.to_string() }
                .map(PathBuf::from)
                .map_err(|_| LaunchError::OperatingSystem)
        }
    }

    impl Drop for UnvalidatedProfileApiFolderPath {
        fn drop(&mut self) {
            let Some(folder) = self.raw.take() else {
                return;
            };
            if folder.is_null() {
                return;
            }
            // SAFETY: GetAppContainerFolderPath allocates this result with
            // CoTaskMemAlloc and ownership has not escaped this wrapper.
            unsafe { CoTaskMemFree(Some(folder.0.cast::<c_void>())) };
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
            let profile_api =
                acquire_appcontainer_profile_api().map_err(|_| LaunchError::OperatingSystem)?;

            profile_api
                .recheck_thread()
                .map_err(|_| LaunchError::OperatingSystem)?;
            // SAFETY: all strings are NUL terminated and there are deliberately no
            // capability SIDs. The returned SID is owned and freed with FreeSid.
            let created = unsafe {
                CreateAppContainerProfile(
                    PCWSTR(name_wide.as_ptr()),
                    PCWSTR(display_wide.as_ptr()),
                    PCWSTR(description_wide.as_ptr()),
                    None,
                )
            }
            .map(UnvalidatedProfileApiSid::new);
            profile_api
                .recheck_thread()
                .map_err(|_| LaunchError::OperatingSystem)?;
            match created {
                Ok(created_sid) => {
                    let created = created_sid.into_validated()?;
                    // Derivation is checked even on first creation so a changed OS
                    // profile contract cannot silently select a different SID.
                    let derived = Self::derive_under_guard(&profile_api, &name_wide)?;
                    // SAFETY: both wrappers contain valid live SIDs.
                    unsafe {
                        EqualSid(created.raw(), derived.raw())
                            .map_err(|_| LaunchError::SandboxVerification)?;
                    }
                    Ok(derived)
                }
                Err(error) if error.code() == ERROR_ALREADY_EXISTS.to_hresult() => {
                    Self::derive_under_guard(&profile_api, &name_wide)
                }
                Err(_) => Err(LaunchError::OperatingSystem),
            }
        }

        #[cfg(test)]
        fn derive(name_wide: &[u16]) -> Result<Self, LaunchError> {
            let profile_api =
                acquire_appcontainer_profile_api().map_err(|_| LaunchError::OperatingSystem)?;
            Self::derive_under_guard(&profile_api, name_wide)
        }

        fn derive_under_guard(
            profile_api: &AppContainerProfileApiGuard,
            name_wide: &[u16],
        ) -> Result<Self, LaunchError> {
            profile_api
                .recheck_thread()
                .map_err(|_| LaunchError::OperatingSystem)?;
            // SAFETY: `name_wide` is a live NUL-terminated profile name.
            let sid =
                unsafe { DeriveAppContainerSidFromAppContainerName(PCWSTR(name_wide.as_ptr())) }
                    .map(UnvalidatedProfileApiSid::new);
            profile_api
                .recheck_thread()
                .map_err(|_| LaunchError::OperatingSystem)?;
            sid.map_err(|_| LaunchError::OperatingSystem)?
                .into_validated()
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

    /// Exact executable copy used only to run the Approval LPAC kernel probe.
    #[cfg(test)]
    pub(super) struct ApprovalLpacKernelTestFixture {
        directory: PathBuf,
        executable: PathBuf,
        cleaned: bool,
    }

    #[cfg(test)]
    impl ApprovalLpacKernelTestFixture {
        pub(super) fn create() -> Result<Self, LaunchError> {
            let profile_sid = OwnedAppContainerSid::open_or_create(
                NoNetworkLpacProfile::v1(),
                VerifiedLpacRole::ApprovalFrontend,
            )?;
            let profile_folder = appcontainer_folder(profile_sid.raw())?;
            if !profile_folder.is_absolute() || !profile_folder.is_dir() {
                return Err(LaunchError::OperatingSystem);
            }

            let directory = create_unique_approval_fixture_directory(&profile_folder)?;
            let executable = directory.join("approval-parent-probe.exe");
            let fixture = Self {
                directory,
                executable,
                cleaned: false,
            };
            apply_exact_approval_fixture_dacl(&fixture.directory, profile_sid.raw())?;
            copy_current_test_image(&fixture.executable)?;
            apply_exact_approval_fixture_dacl(&fixture.executable, profile_sid.raw())?;
            Ok(fixture)
        }

        pub(super) fn path(&self) -> &Path {
            &self.executable
        }

        pub(super) fn cleanup(mut self) -> Result<(), LaunchError> {
            // Both removals are attempted so a partial cleanup still leaves the
            // Drop fallback able to retry only these exact non-recursive paths.
            let executable = std::fs::remove_file(&self.executable);
            let directory = std::fs::remove_dir(&self.directory);
            if executable.is_err() || directory.is_err() {
                return Err(LaunchError::OperatingSystem);
            }
            self.cleaned = true;
            Ok(())
        }
    }

    #[cfg(test)]
    impl Drop for ApprovalLpacKernelTestFixture {
        fn drop(&mut self) {
            // These are the exact CSPRNG-named children created above. Cleanup
            // is deliberately non-recursive and never targets the profile root.
            if !self.cleaned {
                let _ = std::fs::remove_file(&self.executable);
                let _ = std::fs::remove_dir(&self.directory);
            }
        }
    }

    #[cfg(test)]
    impl core::fmt::Debug for ApprovalLpacKernelTestFixture {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("ApprovalLpacKernelTestFixture([REDACTED PATH])")
        }
    }

    fn appcontainer_folder(profile_sid: PSID) -> Result<PathBuf, LaunchError> {
        let sid_text = wide_nul_str(&sid_string(profile_sid)?);
        let profile_api =
            acquire_appcontainer_profile_api().map_err(|_| LaunchError::OperatingSystem)?;
        profile_api
            .recheck_thread()
            .map_err(|_| LaunchError::OperatingSystem)?;
        // SAFETY: the canonical SID string is live and NUL terminated.
        let folder = unsafe { GetAppContainerFolderPath(PCWSTR(sid_text.as_ptr())) }
            .map(UnvalidatedProfileApiFolderPath::new);
        profile_api
            .recheck_thread()
            .map_err(|_| LaunchError::OperatingSystem)?;
        folder.map_err(|_| LaunchError::OperatingSystem)?.to_path()
    }

    fn sid_string(sid: PSID) -> Result<String, LaunchError> {
        // SAFETY: callers supply a SID retained by a live token or profile owner.
        if sid.is_invalid() || !unsafe { IsValidSid(sid) }.as_bool() {
            return Err(LaunchError::OperatingSystem);
        }
        let mut text = PWSTR::null();
        // SAFETY: the validated SID remains live and the output receives one
        // LocalAlloc-owned NUL-terminated string.
        unsafe { ConvertSidToStringSidW(sid, &raw mut text) }
            .map_err(|_| LaunchError::OperatingSystem)?;
        if text.is_null() {
            return Err(LaunchError::OperatingSystem);
        }
        // SAFETY: successful conversion returned a live NUL-terminated string.
        let converted = unsafe { text.to_string() }.map_err(|_| LaunchError::OperatingSystem);
        // SAFETY: ConvertSidToStringSidW allocates with LocalAlloc.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(text.0.cast::<c_void>())));
        }
        converted
    }

    fn environment_with_local_app_data(
        profile_sid: PSID,
        expected_profile_name: &str,
        base_environment: &[u16],
    ) -> Result<Box<[u16]>, LaunchError> {
        let appcontainer_local_data = appcontainer_folder(profile_sid)?;
        let local_folder_name = appcontainer_local_data
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(LaunchError::OperatingSystem)?;
        let profile_folder = appcontainer_local_data
            .parent()
            .ok_or(LaunchError::OperatingSystem)?;
        let profile_name = profile_folder
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(LaunchError::OperatingSystem)?;
        let packages = profile_folder
            .parent()
            .ok_or(LaunchError::OperatingSystem)?;
        let packages_name = packages
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(LaunchError::OperatingSystem)?;
        let user_local_data = packages.parent().ok_or(LaunchError::OperatingSystem)?;
        if !local_folder_name.eq_ignore_ascii_case("AC")
            || !profile_name.eq_ignore_ascii_case(expected_profile_name)
            || !packages_name.eq_ignore_ascii_case("Packages")
            || !user_local_data.is_absolute()
            || !base_environment_is_exact(base_environment)
        {
            return Err(LaunchError::OperatingSystem);
        }

        let local_value: Vec<u16> = user_local_data.as_os_str().encode_wide().collect();
        if local_value.is_empty() || local_value.contains(&0) {
            return Err(LaunchError::OperatingSystem);
        }
        let mut environment = Vec::with_capacity(
            "LOCALAPPDATA="
                .encode_utf16()
                .count()
                .checked_add(local_value.len())
                .and_then(|length| length.checked_add(base_environment.len() + 1))
                .ok_or(LaunchError::OperatingSystem)?,
        );
        environment.extend("LOCALAPPDATA=".encode_utf16());
        environment.extend_from_slice(&local_value);
        environment.push(0);
        environment.extend_from_slice(base_environment);
        if environment.len() > 32_767 || !environment.ends_with(&[0, 0]) {
            return Err(LaunchError::OperatingSystem);
        }
        Ok(environment.into_boxed_slice())
    }

    fn base_environment_is_exact(environment: &[u16]) -> bool {
        if !environment.ends_with(&[0, 0]) {
            return false;
        }
        let mut entries = environment[..environment.len() - 1].split(|unit| *unit == 0);
        let Some(system_root) = entries.next() else {
            return false;
        };
        let Some(windir) = entries.next() else {
            return false;
        };
        let Some(final_empty) = entries.next() else {
            return false;
        };
        entries.next().is_none()
            && final_empty.is_empty()
            && system_root.starts_with(&"SystemRoot=".encode_utf16().collect::<Vec<_>>())
            && windir.starts_with(&"WINDIR=".encode_utf16().collect::<Vec<_>>())
            && system_root.len() > "SystemRoot=".encode_utf16().count()
            && windir.len() > "WINDIR=".encode_utf16().count()
    }

    #[cfg(test)]
    fn current_user_sid_string_for_test() -> Result<String, LaunchError> {
        let mut raw_token = HANDLE::default();
        // SAFETY: the current-process pseudo handle is valid and output receives
        // one exclusively owned query-only token handle.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) }
            .map_err(|_| LaunchError::OperatingSystem)?;
        if raw_token.is_invalid() {
            return Err(LaunchError::OperatingSystem);
        }
        let token = OwnedWinHandle(raw_token);
        let information = token_information(token.raw(), TokenUser)?;
        if information.len().saturating_mul(size_of::<usize>()) < size_of::<TOKEN_USER>() {
            return Err(LaunchError::OperatingSystem);
        }
        // SAFETY: aligned storage contains the complete returned TOKEN_USER.
        let user = unsafe { ptr::read_unaligned(information.as_ptr().cast::<TOKEN_USER>()) };
        sid_string(user.User.Sid)
    }

    #[cfg(test)]
    fn apply_exact_approval_fixture_dacl(
        path: &Path,
        profile_sid: PSID,
    ) -> Result<(), LaunchError> {
        let user_sid = current_user_sid_string_for_test()?;
        let profile_sid = sid_string(profile_sid)?;
        let descriptor_text =
            wide_nul_str(&format!("D:P(A;;FA;;;{user_sid})(A;;GRGX;;;{profile_sid})"));
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: SDDL is live and NUL terminated; output receives one
        // LocalAlloc-owned self-relative descriptor.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(descriptor_text.as_ptr()),
                SDDL_REVISION_1,
                &raw mut descriptor,
                None,
            )
        }
        .map_err(|_| LaunchError::OperatingSystem)?;
        // SAFETY: the conversion above returned a live descriptor allocation.
        let valid = unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool();
        let wide_path = wide_nul_path(path);
        let applied = if valid {
            // SAFETY: path and descriptor stay live for the exact protected-DACL
            // update and no owner or SACL component is selected.
            unsafe {
                SetFileSecurityW(
                    PCWSTR(wide_path.as_ptr()),
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    descriptor,
                )
            }
            .ok()
            .map_err(|_| LaunchError::OperatingSystem)
        } else {
            Err(LaunchError::OperatingSystem)
        };
        // SAFETY: the SDDL conversion allocated this descriptor with LocalAlloc.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
        applied
    }

    #[cfg(test)]
    fn create_unique_approval_fixture_directory(root: &Path) -> Result<PathBuf, LaunchError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for _ in 0..16 {
            let mut random = [0_u8; 16];
            getrandom::fill(&mut random).map_err(|_| LaunchError::OperatingSystem)?;
            let mut suffix = String::with_capacity(random.len() * 2);
            for byte in random {
                suffix.push(char::from(HEX[usize::from(byte >> 4)]));
                suffix.push(char::from(HEX[usize::from(byte & 0x0f)]));
            }
            let candidate = root.join(format!("your-wallet-approval-parent-{suffix}"));
            match std::fs::create_dir(&candidate) {
                Ok(()) => return Ok(candidate),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(LaunchError::OperatingSystem),
            }
        }
        Err(LaunchError::OperatingSystem)
    }

    #[cfg(test)]
    fn copy_current_test_image(destination: &Path) -> Result<(), LaunchError> {
        let source = std::env::current_exe().map_err(|_| LaunchError::OperatingSystem)?;
        let mut source = File::open(source).map_err(|_| LaunchError::OperatingSystem)?;
        let mut destination_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .map_err(|_| LaunchError::OperatingSystem)?;
        let copied =
            io::copy(&mut source, &mut destination_file).and_then(|_| destination_file.sync_all());
        if copied.is_err() {
            drop(destination_file);
            let _ = std::fs::remove_file(destination);
            return Err(LaunchError::OperatingSystem);
        }
        Ok(())
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
        fn new(handles: Box<[HANDLE]>, job: HANDLE, profile_sid: PSID, mitigation: u64) -> Self {
            Self {
                handles,
                job: [job],
                mitigation,
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
            mitigation: u64,
        ) -> Result<Self, LaunchError> {
            let handles = duplicate_owner.raw_handles();
            if handles.is_empty() {
                return Err(LaunchError::InvalidHandle);
            }
            let values = Box::new(AttributeValues::new(
                handles,
                job_owner.raw(),
                profile_sid.raw(),
                mitigation,
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

    pub(super) fn validate_child_pipe_server(
        handle: BorrowedHandle<'_>,
    ) -> Result<(), LaunchError> {
        validate_live_handle(handle)?;
        let raw = HANDLE(handle.as_raw_handle());
        let mut client_process_id = 0_u32;
        let mut client_session_id = u32::MAX;
        // SAFETY: the borrowed server handle remains live and both outputs are
        // initialized exact-width values. These calls reject non-server handles.
        unsafe {
            GetNamedPipeClientProcessId(raw, &raw mut client_process_id)
                .map_err(|_| LaunchError::InvalidHandle)?;
            GetNamedPipeClientSessionId(raw, &raw mut client_session_id)
                .map_err(|_| LaunchError::InvalidHandle)?;
        }
        // The parent creates and retains the connected client end before this
        // server end can enter the restricted launch handle list.
        // SAFETY: this scalar query takes no pointers or caller-owned resources.
        let current_process_id = unsafe { GetCurrentProcessId() };
        let mut current_session_id = u32::MAX;
        if current_process_id == 0 || client_process_id != current_process_id {
            return Err(LaunchError::InvalidHandle);
        }
        // SAFETY: the nonzero PID is the live current process and output points
        // to one initialized DWORD.
        unsafe { ProcessIdToSessionId(current_process_id, &raw mut current_session_id) }
            .map_err(|_| LaunchError::InvalidHandle)?;
        if client_session_id == u32::MAX || client_session_id != current_session_id {
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
            OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &raw mut token)
                .map_err(|_| LaunchError::SandboxVerification)?;
        }
        if token.is_invalid() {
            return Err(LaunchError::SandboxVerification);
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

        let mut is_lpac = 0_u32;
        let mut lpac_returned = 0_u32;
        // SAFETY: the fixed-size output matches the LPAC token-information
        // class's DWORD ABI and the suspended child token remains live.
        let queried_lpac = match unsafe {
            GetTokenInformation(
                token.raw(),
                TokenIsLessPrivilegedAppContainer,
                Some(ptr::from_mut(&mut is_lpac).cast::<c_void>()),
                u32::try_from(size_of::<u32>()).map_err(|_| LaunchError::SandboxVerification)?,
                &raw mut lpac_returned,
            )
        } {
            Ok(()) => Some((is_lpac, lpac_returned)),
            Err(error) if error.code() == ERROR_INVALID_PARAMETER.to_hresult() => None,
            Err(_) => return Err(LaunchError::SandboxVerification),
        };
        if queried_lpac.is_some_and(|(value, bytes)| {
            value != 1 || usize::try_from(bytes).ok() != Some(size_of::<u32>())
        }) {
            return Err(LaunchError::SandboxVerification);
        }
        require_lpac_membership(token.raw())?;

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

    fn require_lpac_membership(token: HANDLE) -> Result<(), LaunchError> {
        let user_information = token_information(token, TokenUser)?;
        if user_information.len().saturating_mul(size_of::<usize>()) < size_of::<TOKEN_USER>() {
            return Err(LaunchError::SandboxVerification);
        }
        // SAFETY: aligned storage contains the complete returned TOKEN_USER
        // prefix and remains live through both membership checks.
        let user = unsafe { ptr::read_unaligned(user_information.as_ptr().cast::<TOKEN_USER>()) };
        // SAFETY: the SID pointer belongs to the still-live token-information
        // allocation populated by Windows.
        if user.User.Sid.is_invalid() || !unsafe { IsValidSid(user.User.Sid) }.as_bool() {
            return Err(LaunchError::SandboxVerification);
        }

        let mut impersonation = HANDLE::default();
        // SAFETY: the source token is live and query/duplicate-authorized; the
        // output receives one exclusively owned impersonation token.
        unsafe { DuplicateToken(token, SecurityIdentification, &raw mut impersonation) }
            .map_err(|_| LaunchError::SandboxVerification)?;
        if impersonation.is_invalid() {
            return Err(LaunchError::SandboxVerification);
        }
        let impersonation = OwnedWinHandle(impersonation);
        let check = |flags| -> Result<bool, LaunchError> {
            let mut member = BOOL(0);
            // SAFETY: the impersonation token and user SID remain live and the
            // output BOOL is writable for this AppContainer-aware check.
            unsafe {
                CheckTokenMembershipEx(
                    Some(impersonation.raw()),
                    user.User.Sid,
                    flags,
                    &raw mut member,
                )
            }
            .map_err(|_| LaunchError::SandboxVerification)?;
            Ok(member.as_bool())
        };
        let regular_appcontainer = check(CTMF_INCLUDE_APPCONTAINER)?;
        let lpac = check(CTMF_INCLUDE_APPCONTAINER | CTMF_INCLUDE_LPAC)?;
        (!regular_appcontainer && lpac)
            .then_some(())
            .ok_or(LaunchError::SandboxVerification)
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
        // SAFETY: the pseudo handle denotes this exact process object and is valid
        // as both the source/target process and the handle being duplicated.
        let current_process = unsafe { GetCurrentProcess() };
        let mut process = HANDLE::default();
        // SAFETY: duplication converts the pseudo current-process handle directly
        // into one real, non-inheritable, least-privilege process-object handle.
        unsafe {
            DuplicateHandle(
                current_process,
                current_process,
                current_process,
                &raw mut process,
                (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE).0,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        }
        .map_err(|_| LaunchError::OperatingSystem)?;
        if process.is_invalid() {
            return Err(LaunchError::OperatingSystem);
        }
        let process = OwnedWinHandle(process);
        let mut flags = u32::MAX;
        // SAFETY: the real duplicate remains owned throughout all scalar checks.
        unsafe { GetHandleInformation(process.raw(), &raw mut flags) }
            .map_err(|_| LaunchError::OperatingSystem)?;
        // SAFETY: all calls borrow either the retained real handle or the current
        // pseudo handle, and return only scalar/object-equality observations.
        let process_id = unsafe { GetProcessId(process.raw()) };
        // SAFETY: this call returns only the current process's scalar identifier.
        let current_process_id = unsafe { GetCurrentProcessId() };
        // SAFETY: both handles remain live and denote process objects for this
        // non-owning exact kernel-object comparison.
        let exact_current_process =
            unsafe { CompareObjectHandles(process.raw(), current_process) }.as_bool();
        if flags != 0
            || process_id == 0
            || process_id != current_process_id
            || !exact_current_process
        {
            return Err(LaunchError::OperatingSystem);
        }

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

    fn child_handle_value(handle: HANDLE) -> Result<u64, LaunchError> {
        u64::try_from(handle.0 as usize).map_err(|_| LaunchError::OperatingSystem)
    }

    fn require_exact_non_inheritable(handle: HANDLE) -> Result<(), LaunchError> {
        let mut flags = u32::MAX;
        // SAFETY: the caller retains the live source handle for this scalar
        // query. Parent-proof sources must carry no inheritable or protected
        // handle-table attribute before they are copied into another process.
        unsafe { GetHandleInformation(handle, &raw mut flags) }
            .map_err(|_| LaunchError::OperatingSystem)?;
        (flags == 0)
            .then_some(())
            .ok_or(LaunchError::OperatingSystem)
    }

    fn inject_parent_proof(
        sources: &ParentProofSources,
        child_process: HANDLE,
    ) -> Result<InjectedParentProof, LaunchError> {
        require_exact_non_inheritable(sources.process.raw())?;
        require_exact_non_inheritable(sources.image.raw())?;

        let duplicate_into_child = |source: HANDLE| -> Result<HANDLE, LaunchError> {
            let mut target = HANDLE::default();
            // SAFETY: both source handles are retained above and child_process is
            // the still-suspended process protected by CreatedChildGuard. The
            // returned numeric value names a new child-local handle whose inherit
            // attribute is explicitly false. If the second duplication fails,
            // the armed guard terminates and reaps the child, closing the first.
            unsafe {
                DuplicateHandle(
                    GetCurrentProcess(),
                    source,
                    child_process,
                    &raw mut target,
                    0,
                    false,
                    DUPLICATE_SAME_ACCESS,
                )
                .map_err(|_| LaunchError::OperatingSystem)?;
            }
            if target.is_invalid() {
                return Err(LaunchError::OperatingSystem);
            }
            Ok(target)
        };

        let process = duplicate_into_child(sources.process.raw())?;
        let image = duplicate_into_child(sources.image.raw())?;
        if process == image {
            return Err(LaunchError::OperatingSystem);
        }
        Ok(InjectedParentProof {
            process_handle: child_handle_value(process)?,
            image_handle: child_handle_value(image)?,
            process_id: sources.process_id,
        })
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

    pub(super) fn terminate_and_reap_created_child(
        process: HANDLE,
        job: HANDLE,
    ) -> Result<(), LaunchError> {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(u64::from(
                CREATED_CHILD_CLEANUP_TIMEOUT_MILLISECONDS,
            )))
            .ok_or(LaunchError::Cleanup)?;
        // Drop cannot surface cleanup failure. It nevertheless attempts both
        // termination paths and a bounded wait on the retained exact process.
        terminate_and_wait(process, job, deadline).map_err(|_| LaunchError::Cleanup)
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

        /// Gives failed synchronous cleanup precedence over the rejection that
        /// triggered it, while keeping the kill-on-close Job as a final fallback.
        fn reject(mut self, rejection: LaunchError) -> LaunchError {
            self.armed = false;
            match terminate_and_reap_created_child(self.process.raw(), self.job.raw()) {
                Ok(()) => rejection,
                Err(_) => LaunchError::Cleanup,
            }
        }
    }

    impl Drop for CreatedChildGuard<'_, '_> {
        fn drop(&mut self) {
            if self.armed {
                let _ = terminate_and_reap_created_child(self.process.raw(), self.job.raw());
            }
        }
    }

    pub(super) fn terminate_and_wait(
        process: HANDLE,
        job: HANDLE,
        deadline: Instant,
    ) -> Result<(), LaunchError> {
        // SAFETY: both handles remain owned by the consuming LaunchedHelper for
        // this call. The job contains at most the one held helper process, and
        // the zero-time observation never transfers handle ownership.
        if unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
            return Ok(());
        }
        // TerminateJobObject and TerminateProcess are asynchronous. Always try
        // both exact retained objects; one successful request is sufficient to
        // proceed to the mandatory process wait.
        // SAFETY: `job` is the retained one-process Job owned by the caller.
        let job_termination = unsafe { TerminateJobObject(job, 1) };
        // SAFETY: `process` is the retained exact child process owned by the caller.
        let process_termination = unsafe { TerminateProcess(process, 1) };
        if job_termination.is_err() && process_termination.is_err() {
            return Err(LaunchError::OperatingSystem);
        }
        let timeout = remaining_milliseconds(deadline)?;
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

    pub(super) fn wait_for_expected_exit_code(
        process: HANDLE,
        deadline: Instant,
        expected_exit_code: u32,
        unexpected_exit_error: LaunchError,
    ) -> Result<(), LaunchError> {
        // SAFETY: the sealed running owner retains the exact process handle for
        // the complete bounded wait and subsequent exit-code observation.
        let wait = unsafe { WaitForSingleObject(process, remaining_milliseconds(deadline)?) };
        if wait == WAIT_TIMEOUT || deadline_elapsed(deadline) {
            return Err(LaunchError::TerminationDeadlineElapsed);
        }
        if wait != WAIT_OBJECT_0 {
            return Err(LaunchError::OperatingSystem);
        }
        let mut exit_code = u32::MAX;
        // SAFETY: the exact process handle remains owned and is signalled.
        unsafe { GetExitCodeProcess(process, &raw mut exit_code) }
            .map_err(|_| LaunchError::OperatingSystem)?;
        (exit_code == expected_exit_code)
            .then_some(())
            .ok_or(unexpected_exit_error)
    }

    pub(super) fn revalidate_held_process(
        process: HANDLE,
        job: HANDLE,
        expected_process_id: u32,
    ) -> Result<(), LaunchError> {
        if process.is_invalid() || job.is_invalid() || expected_process_id == 0 {
            return Err(LaunchError::SandboxVerification);
        }
        // SAFETY: process is retained by LaunchedHelper for this scalar query.
        let process_id = unsafe { GetProcessId(process) };
        if process_id == 0 || process_id != expected_process_id {
            return Err(LaunchError::SandboxVerification);
        }
        let mut in_job = BOOL(0);
        // SAFETY: both retained handles are live and output is one writable BOOL.
        unsafe { IsProcessInJob(process, Some(job), &raw mut in_job) }
            .map_err(|_| LaunchError::SandboxVerification)?;
        if !in_job.as_bool() {
            return Err(LaunchError::SandboxVerification);
        }
        let mut information = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        // SAFETY: output is exact writable storage and the retained Job stays live.
        unsafe {
            QueryInformationJobObject(
                Some(job),
                JobObjectExtendedLimitInformation,
                ptr::from_mut(&mut information).cast::<c_void>(),
                u32::try_from(size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
                    .map_err(|_| LaunchError::SandboxVerification)?,
                None,
            )
        }
        .map_err(|_| LaunchError::SandboxVerification)?;
        let basic = &information.BasicLimitInformation;
        if basic.LimitFlags & JOB_OBJECT_LIMIT_ACTIVE_PROCESS == JOB_OBJECT_LIMIT(0)
            || basic.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == JOB_OBJECT_LIMIT(0)
            || basic.ActiveProcessLimit != 1
        {
            return Err(LaunchError::SandboxVerification);
        }
        Ok(())
    }

    pub(super) fn revalidate_running_held_process(
        process: HANDLE,
        job: HANDLE,
        expected_process_id: u32,
    ) -> Result<(), LaunchError> {
        revalidate_held_process(process, job, expected_process_id)?;
        // SAFETY: the exact retained process handle stays owned by the held
        // Approval capability for this zero-time liveness observation.
        if unsafe { WaitForSingleObject(process, 0) } != WAIT_TIMEOUT {
            return Err(LaunchError::SandboxVerification);
        }
        Ok(())
    }

    pub(super) fn resume_parent_bound_approval(
        process: HANDLE,
        job: HANDLE,
        thread: HANDLE,
        expected_process_id: u32,
    ) -> Result<(), LaunchError> {
        revalidate_held_process(process, job, expected_process_id)?;
        // SAFETY: `thread` is the retained suspended primary thread created for
        // this exact process and no other production API can resume it.
        let previous_suspend_count = unsafe { ResumeThread(thread) };
        if previous_suspend_count != 1 {
            return Err(LaunchError::OperatingSystem);
        }
        revalidate_running_held_process(process, job, expected_process_id)
    }

    #[cfg(test)]
    pub(super) fn is_live_held_process_in_job_for_test(
        process: HANDLE,
        job: HANDLE,
        expected_process_id: u32,
    ) -> Result<bool, LaunchError> {
        // SAFETY: the test borrows the exact process retained by the suspended
        // capability. A zero-time wait observes liveness without changing it.
        match unsafe { WaitForSingleObject(process, 0) } {
            WAIT_OBJECT_0 => Ok(false),
            WAIT_TIMEOUT => {
                revalidate_held_process(process, job, expected_process_id)?;
                Ok(true)
            }
            _ => Err(LaunchError::SandboxVerification),
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

    struct SuspendedLaunch<LogicalParent> {
        process: OwnedWinHandle,
        job: OwnedWinHandle,
        thread: OwnedWinHandle,
        identity: HeldProcessIdentity,
        parent_proof: InjectedParentProof,
        logical_parent: LogicalParent,
    }

    pub(super) fn launch(
        helper: &VerifiedHelper,
        handles: &InheritedStdio<'_>,
        profile: NoNetworkLpacProfile,
        role: VerifiedLpacRole,
    ) -> Result<LaunchedHelper, LaunchError> {
        if role != VerifiedLpacRole::SecretInputFrontend {
            return Err(LaunchError::ApprovalRequiresParentBoundActivation);
        }
        let suspended = prepare_suspended_inner(
            helper,
            handles,
            profile,
            role,
            |_child| Ok(()),
            #[cfg(test)]
            None,
            #[cfg(test)]
            false,
        )?;
        let suspended = resume_suspended_for_legacy(suspended)?;
        let SuspendedLaunch {
            process,
            job,
            thread,
            identity,
            parent_proof,
            logical_parent: (),
        } = suspended;
        drop(thread);
        Ok(LaunchedHelper {
            process,
            job,
            identity,
            parent_proof: Some(parent_proof),
            #[cfg(test)]
            approval_parent_probe: None,
        })
    }

    pub(super) fn prepare_parent_bound_approval(
        helper: &VerifiedHelper,
        handles: &InheritedStdio<'_>,
        role: VerifiedLpacRole,
        parent_source: &ApprovalParentSourcePreparedKeyAgent,
    ) -> Result<HeldSuspendedApproval, LaunchError> {
        if role != VerifiedLpacRole::ApprovalFrontend {
            return Err(LaunchError::HelperRoleNotAllowed);
        }
        let injection_seal = ApprovalLogicalParentInjectionSeal::new();
        let suspended = prepare_suspended_inner(
            helper,
            handles,
            NoNetworkLpacProfile::v1(),
            role,
            |child| {
                parent_source
                    .inject_into_suspended_approval(child, &injection_seal)
                    .map_err(|_| LaunchError::SandboxVerification)
            },
            #[cfg(test)]
            None,
            #[cfg(test)]
            true,
        )?;
        let SuspendedLaunch {
            process,
            job,
            thread,
            identity,
            parent_proof,
            logical_parent,
        } = suspended;
        Ok(HeldSuspendedApproval {
            guard: HeldApprovalProcessGuard {
                process,
                job,
                identity,
                cleanup_armed: true,
            },
            thread,
            parent_proof,
            logical_parent,
        })
    }

    #[cfg(test)]
    pub(super) fn launch_approval_parent_probe(
        helper: &VerifiedHelper,
        handles: &InheritedStdio<'_>,
        profile: NoNetworkLpacProfile,
        role: VerifiedLpacRole,
        logical_parent: &ApprovalParentSourcePreparedKeyAgent,
        command_line: &mut [u16],
    ) -> Result<LaunchedHelper, LaunchError> {
        let injection_seal = ApprovalLogicalParentInjectionSeal::new();
        let suspended = prepare_suspended_inner(
            helper,
            handles,
            profile,
            role,
            |child| {
                logical_parent
                    .inject_into_suspended_approval(child, &injection_seal)
                    .map_err(|_| LaunchError::SandboxVerification)
            },
            Some(command_line),
            true,
        )?;
        let suspended = resume_suspended_for_legacy(suspended)?;
        let SuspendedLaunch {
            process,
            job,
            thread,
            identity,
            parent_proof,
            logical_parent,
        } = suspended;
        drop(thread);
        Ok(LaunchedHelper {
            process,
            job,
            identity,
            parent_proof: Some(parent_proof),
            approval_parent_probe: Some(logical_parent),
        })
    }

    /// Explicit legacy resume is confined to Secret Input and the test-only
    /// Approval kernel probe. Production Approval cannot reach this function.
    fn resume_suspended_for_legacy<LogicalParent>(
        suspended: SuspendedLaunch<LogicalParent>,
    ) -> Result<SuspendedLaunch<LogicalParent>, LaunchError> {
        {
            let child_guard = CreatedChildGuard::new(&suspended.process, &suspended.job);
            // SAFETY: thread is the suspended primary thread returned by
            // CreateProcessW and is still owned by `suspended`.
            let previous_suspend_count = unsafe { ResumeThread(suspended.thread.raw()) };
            if previous_suspend_count != 1 {
                return Err(child_guard.reject(LaunchError::OperatingSystem));
            }
            child_guard.disarm();
        }
        Ok(suspended)
    }

    #[allow(clippy::too_many_lines)] // Process creation is kept linear for cleanup auditing.
    fn prepare_suspended_inner<LogicalParent>(
        helper: &VerifiedHelper,
        handles: &InheritedStdio<'_>,
        profile: NoNetworkLpacProfile,
        role: VerifiedLpacRole,
        inject_logical_parent: impl FnOnce(BorrowedHandle<'_>) -> Result<LogicalParent, LaunchError>,
        #[cfg(test)] command_line: Option<&mut [u16]>,
        #[cfg(test)] kernel_test_context: bool,
    ) -> Result<SuspendedLaunch<LogicalParent>, LaunchError> {
        // Keep the identity-pinned executable file live through CreateProcessW.
        let _verified_file_handle = helper.raw_handle();
        validate_live_handle(handles.input)?;
        validate_live_handle(handles.output)?;
        validate_live_handle(handles.error)?;
        #[cfg(test)]
        let process_context = if kernel_test_context {
            RestrictedProcessContext::prepare_for_kernel_test()
        } else {
            RestrictedProcessContext::prepare()
        }
        .map_err(map_process_context_error)?;
        #[cfg(not(test))]
        let process_context =
            RestrictedProcessContext::prepare().map_err(map_process_context_error)?;
        let helper_file = helper.identity();
        let helper_manifest_digest = helper.manifest_digest();
        let originals = unique_raw_handles(handles);
        let parent_sources = role
            .requires_parent_proof()
            .then(current_parent_proof_sources)
            .transpose()?;
        let metadata = profile_metadata(profile, role)?;
        let profile_sid = OwnedAppContainerSid::open_or_create(profile, role)?;
        let environment = environment_with_local_app_data(
            profile_sid.raw(),
            metadata.name,
            process_context.environment(),
        )?;
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
        #[cfg(test)]
        let mitigation = if kernel_test_context {
            APPROVAL_KERNEL_FIXTURE_MITIGATION_POLICY
        } else {
            HELPER_MITIGATION_POLICY
        };
        #[cfg(not(test))]
        let mitigation = HELPER_MITIGATION_POLICY;
        let attributes = AttributeList::for_lpac(&duplicates, &job, profile_sid, mitigation)?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb =
            u32::try_from(size_of::<STARTUPINFOEXW>()).map_err(|_| LaunchError::OperatingSystem)?;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = standard_input;
        startup.StartupInfo.hStdOutput = standard_output;
        startup.StartupInfo.hStdError = standard_error;
        startup.lpAttributeList = attributes.pointer();

        #[cfg(test)]
        let command_line = command_line.map(|buffer| PWSTR(buffer.as_mut_ptr()));
        #[cfg(not(test))]
        let command_line = None;

        if Instant::now() >= coordination_deadline {
            return Err(LaunchError::OperatingSystem);
        }
        process_context
            .recheck_thread()
            .map_err(map_process_context_error)?;

        let mut process_information = PROCESS_INFORMATION::default();
        // SAFETY: helper path is verified and NUL-terminated; startup and attribute
        // storage remain live. TRUE inheritance is constrained by HANDLE_LIST.
        // The Unicode environment is an exact three-name allowlist, and the
        // current directory was checked non-writable and free of reparses.
        unsafe {
            flight
                .create_process_with_explicit_handle_list(
                    PCWSTR(application.as_ptr()),
                    command_line,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                    Some(environment.as_ptr().cast::<c_void>()),
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
                return Err(child_guard.reject(error));
            }
        };
        drop(duplicates);
        drop(flight);
        let post_creation = (|| {
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
            let parent_proof = parent_sources
                .as_ref()
                .map(|sources| inject_parent_proof(sources, process.raw()))
                .transpose()?
                .ok_or(LaunchError::SandboxVerification)?;
            // SAFETY: the owned child process handle stays live and the armed guard
            // keeps the exact process suspended throughout the sealed injection.
            let child = unsafe { BorrowedHandle::borrow_raw(process.raw().0) };
            let logical_parent = inject_logical_parent(child)?;
            drop(parent_sources);
            Ok((held_process_id, parent_proof, logical_parent))
        })();
        let (held_process_id, parent_proof, logical_parent) = match post_creation {
            Ok(prepared) => prepared,
            Err(error) => return Err(child_guard.reject(error)),
        };
        child_guard.disarm();
        drop(profile_sid);

        Ok(SuspendedLaunch {
            process,
            job,
            thread,
            identity: HeldProcessIdentity {
                process_id: held_process_id,
                helper_file,
                helper_manifest_digest,
                profile_revision: profile.revision(),
            },
            parent_proof,
            logical_parent,
        })
    }

    #[cfg(test)]
    pub(super) fn wait_for_success_for_kernel_test(
        process: HANDLE,
        deadline: Instant,
    ) -> Result<(), LaunchError> {
        wait_for_expected_exit_code(
            process,
            deadline,
            super::APPROVAL_PARENT_PROBE_SUCCESS_EXIT_CODE,
            LaunchError::SandboxVerification,
        )
    }

    #[cfg(test)]
    pub(super) fn cleanup_failed_kernel_probe(
        process: HANDLE,
        job: HANDLE,
    ) -> Result<(), LaunchError> {
        // SAFETY: the consuming launch owner retains the exact process handle;
        // a zero-time wait first distinguishes an already reaped child.
        if unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
            return Ok(());
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or(LaunchError::OperatingSystem)?;
        terminate_and_wait(process, job, deadline)
    }

    #[cfg(test)]
    pub(super) fn debug_privilege_luid_for_kernel_test() -> Result<[u8; 8], LaunchError> {
        let name = wide_nul_str("SeDebugPrivilege");
        let mut luid = LUID::default();
        // SAFETY: the local-system lookup uses one NUL-terminated constant and
        // writes the system-wide LUID into initialized storage.
        unsafe { LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(name.as_ptr()), &raw mut luid) }
            .map_err(|_| LaunchError::OperatingSystem)?;
        let mut encoded = [0_u8; 8];
        encoded[..4].copy_from_slice(&luid.LowPart.to_be_bytes());
        encoded[4..].copy_from_slice(&luid.HighPart.to_be_bytes());
        Ok(encoded)
    }

    #[cfg(test)]
    pub(super) const fn mitigation_policy_for_test() -> u64 {
        HELPER_MITIGATION_POLICY
    }

    #[cfg(test)]
    pub(super) const fn approval_kernel_fixture_mitigation_policy_for_test() -> u64 {
        APPROVAL_KERNEL_FIXTURE_MITIGATION_POLICY
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
    pub(super) fn approval_environment_for_test(root: &Path) -> Result<Box<[u16]>, LaunchError> {
        let base = environment_for_test(root)?;
        let profile_sid = OwnedAppContainerSid::open_or_create(
            NoNetworkLpacProfile::v1(),
            VerifiedLpacRole::ApprovalFrontend,
        )?;
        environment_with_local_app_data(profile_sid.raw(), APPROVAL_PROFILE_V1_NAME, &base)
    }

    #[cfg(test)]
    pub(super) fn validate_working_directory_for_test(path: &Path) -> Result<(), LaunchError> {
        crate::restricted_process_context::validate_working_directory_for_test(path)
            .map_err(map_process_context_error)
    }

    #[cfg(test)]
    pub(super) fn verify_current_parent_proof_for_test() -> Result<(), LaunchError> {
        let proof = current_parent_proof_sources()?;
        let mut flags = u32::MAX;
        // SAFETY: both proof handles remain owned for the complete validation.
        unsafe { GetHandleInformation(proof.process.raw(), &raw mut flags) }
            .map_err(|_| LaunchError::OperatingSystem)?;
        // SAFETY: the pseudo handle denotes this exact test process.
        let current_process = unsafe { GetCurrentProcess() };
        // SAFETY: both handles remain live and denote process objects for this
        // non-owning exact kernel-object comparison.
        let exact_current_process =
            unsafe { CompareObjectHandles(proof.process.raw(), current_process) }.as_bool();
        // SAFETY: this call returns only the current test process's scalar ID.
        let current_process_id = unsafe { GetCurrentProcessId() };
        // SAFETY: a zero-timeout wait only observes the retained exact process.
        let process_wait = unsafe { WaitForSingleObject(proof.process.raw(), 0) };
        (flags == 0
            && proof.process_id == current_process_id
            && exact_current_process
            && process_wait == WAIT_TIMEOUT
            && proof.image.raw() != proof.process.raw())
        .then_some(())
        .ok_or(LaunchError::OperatingSystem)
    }
}

#[cfg(all(test, windows))]
mod tests {
    #![allow(unsafe_code)]

    use core::mem::{offset_of, size_of};
    use core::ptr;
    use std::cell::Cell;
    use std::fs::OpenOptions;
    use std::io::Read as _;
    use std::net::{Ipv4Addr, TcpListener};
    use std::os::windows::io::{
        AsHandle, AsRawHandle, AsRawSocket, BorrowedHandle, FromRawHandle, OwnedHandle, RawHandle,
    };
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use windows::Win32::Foundation::{
        CloseHandle, DUPLICATE_HANDLE_OPTIONS, DuplicateHandle, ERROR_ACCESS_DENIED,
        GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAGS, LUID,
        SetHandleInformation, WAIT_TIMEOUT,
    };
    use windows::Win32::Security::{
        GetTokenInformation, LUID_AND_ATTRIBUTES, TOKEN_ACCESS_MASK, TOKEN_ADJUST_DEFAULT,
        TOKEN_ADJUST_GROUPS, TOKEN_ADJUST_PRIVILEGES, TOKEN_ADJUST_SESSIONID, TOKEN_ASSIGN_PRIMARY,
        TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_QUERY_SOURCE,
        TokenPrivileges, TokenSessionId,
    };
    use windows::Win32::Storage::FileSystem::{DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER};
    use windows::Win32::System::JobObjects::{
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        GetCurrentProcess, GetProcessId, OpenProcess, OpenProcessToken, PROCESS_ACCESS_RIGHTS,
        PROCESS_CREATE_PROCESS, PROCESS_CREATE_THREAD, PROCESS_DUP_HANDLE, PROCESS_NAME_WIN32,
        PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION,
        PROCESS_SET_QUOTA, PROCESS_SUSPEND_RESUME, PROCESS_TERMINATE, PROCESS_VM_OPERATION,
        PROCESS_VM_READ, PROCESS_VM_WRITE, QueryFullProcessImageNameW, WaitForSingleObject,
    };
    use windows::Win32::System::WindowsProgramming::{
        PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,
        PROCESS_CREATION_CHILD_PROCESS_RESTRICTED,
    };

    use windows::core::PWSTR;

    use super::RestrictedLauncher;
    use super::{
        APPROVAL_PARENT_PROBE_FRAME_BYTES, APPROVAL_PARENT_PROBE_MAGIC,
        APPROVAL_PARENT_PROBE_SUCCESS_EXIT_CODE, HeldProcessIdentity, InheritedStdio, LaunchError,
        NoNetworkLpacProfile, resolve_exchange_natural_exit_with_cleanup, sys,
    };
    use crate::attestation::{ArtifactDigest, ReleaseAttestation};
    use crate::helper::{FileIdentity, VerifiedHelper};

    struct ExchangeCleanupDropObserver<'a> {
        cleanup_armed: bool,
        cleanup_calls: &'a Cell<u32>,
    }

    const FULL_EXCHANGE_EXIT_FIXTURE_MODE: &str = "YOUR_WALLET_FULL_EXCHANGE_EXIT_FIXTURE_MODE";

    struct FullExchangeExitFixture {
        child: Child,
    }

    impl Drop for FullExchangeExitFixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl Drop for ExchangeCleanupDropObserver<'_> {
        fn drop(&mut self) {
            if self.cleanup_armed {
                self.cleanup_armed = false;
                self.cleanup_calls
                    .set(self.cleanup_calls.get().saturating_add(1));
            }
        }
    }

    fn spawn_full_exchange_exit_fixture(
        mode: &str,
    ) -> Result<FullExchangeExitFixture, Box<dyn std::error::Error>> {
        let executable = std::env::current_exe()?;
        let child = Command::new(executable)
            .arg("launch::tests::full_exchange_process_exit_fixture")
            .arg("--exact")
            .arg("--ignored")
            .env(FULL_EXCHANGE_EXIT_FIXTURE_MODE, mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        Ok(FullExchangeExitFixture { child })
    }

    #[test]
    #[ignore = "spawned only by exact full-exchange natural-exit process tests"]
    fn full_exchange_process_exit_fixture() {
        match std::env::var(FULL_EXCHANGE_EXIT_FIXTURE_MODE).as_deref() {
            Ok("exit-zero") | Err(_) => {}
            Ok("exit-nonzero") => std::process::exit(23),
            Ok("hang") => std::thread::sleep(Duration::from_secs(30)),
            Ok(_) => std::process::exit(24),
        }
    }

    #[test]
    fn full_exchange_real_held_process_exit_zero_is_observed()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = spawn_full_exchange_exit_fixture("exit-zero")?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or(LaunchError::TerminationDeadlineElapsed)?;

        let result = sys::wait_for_expected_exit_code(
            HANDLE(fixture.child.as_raw_handle()),
            deadline,
            0,
            LaunchError::OperatingSystem,
        );
        let status = fixture.child.wait()?;

        assert_eq!(result, Ok(()));
        assert!(status.success());
        Ok(())
    }

    #[test]
    fn full_exchange_real_held_process_nonzero_exit_is_rejected()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = spawn_full_exchange_exit_fixture("exit-nonzero")?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(5))
            .ok_or(LaunchError::TerminationDeadlineElapsed)?;

        let result = sys::wait_for_expected_exit_code(
            HANDLE(fixture.child.as_raw_handle()),
            deadline,
            0,
            LaunchError::OperatingSystem,
        );
        let status = fixture.child.wait()?;

        assert_eq!(result, Err(LaunchError::OperatingSystem));
        assert_eq!(status.code(), Some(23));
        Ok(())
    }

    #[test]
    fn full_exchange_real_held_process_hang_obeys_wait_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut fixture = spawn_full_exchange_exit_fixture("hang")?;
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(100))
            .ok_or(LaunchError::TerminationDeadlineElapsed)?;

        let result = sys::wait_for_expected_exit_code(
            HANDLE(fixture.child.as_raw_handle()),
            deadline,
            0,
            LaunchError::OperatingSystem,
        );
        let _ = fixture.child.kill();
        let _ = fixture.child.wait();

        assert_eq!(result, Err(LaunchError::TerminationDeadlineElapsed));
        Ok(())
    }

    #[test]
    fn full_exchange_natural_exit_zero_disarms_without_invoking_cleanup() {
        let cleanup_calls = Cell::new(0_u32);
        let mut cleanup_armed = true;

        let result = resolve_exchange_natural_exit_with_cleanup(
            &mut cleanup_armed,
            || Ok(()),
            || {
                cleanup_calls.set(cleanup_calls.get().saturating_add(1));
                Some(Ok(()))
            },
        );

        assert_eq!(result, Ok(()));
        assert!(!cleanup_armed);
        assert_eq!(cleanup_calls.get(), 0);
    }

    #[test]
    fn full_exchange_nonzero_exit_runs_cleanup_and_preserves_wait_error() {
        let cleanup_calls = Cell::new(0_u32);
        let mut cleanup_armed = true;

        let result = resolve_exchange_natural_exit_with_cleanup(
            &mut cleanup_armed,
            || Err(LaunchError::OperatingSystem),
            || {
                cleanup_calls.set(cleanup_calls.get().saturating_add(1));
                Some(Ok(()))
            },
        );

        assert_eq!(result, Err(LaunchError::OperatingSystem));
        assert!(!cleanup_armed);
        assert_eq!(cleanup_calls.get(), 1);
    }

    #[test]
    fn full_exchange_wait_error_runs_cleanup_and_preserves_wait_error() {
        let cleanup_calls = Cell::new(0_u32);
        let mut cleanup_armed = true;

        let result = resolve_exchange_natural_exit_with_cleanup(
            &mut cleanup_armed,
            || Err(LaunchError::TerminationDeadlineElapsed),
            || {
                cleanup_calls.set(cleanup_calls.get().saturating_add(1));
                Some(Ok(()))
            },
        );

        assert_eq!(result, Err(LaunchError::TerminationDeadlineElapsed));
        assert!(!cleanup_armed);
        assert_eq!(cleanup_calls.get(), 1);
    }

    #[test]
    fn full_exchange_cleanup_failure_precedes_natural_exit_wait_error() {
        let cleanup_calls = Cell::new(0_u32);
        let mut cleanup_armed = true;

        let result = resolve_exchange_natural_exit_with_cleanup(
            &mut cleanup_armed,
            || Err(LaunchError::TerminationDeadlineElapsed),
            || {
                cleanup_calls.set(cleanup_calls.get().saturating_add(1));
                Some(Err(LaunchError::OperatingSystem))
            },
        );

        assert_eq!(result, Err(LaunchError::Cleanup));
        assert!(!cleanup_armed);
        assert_eq!(cleanup_calls.get(), 1);
    }

    #[test]
    fn full_exchange_explicit_cleanup_disarms_drop_without_double_cleanup() {
        let cleanup_calls = Cell::new(0_u32);
        {
            let mut observer = ExchangeCleanupDropObserver {
                cleanup_armed: true,
                cleanup_calls: &cleanup_calls,
            };
            let result = resolve_exchange_natural_exit_with_cleanup(
                &mut observer.cleanup_armed,
                || Err(LaunchError::OperatingSystem),
                || {
                    cleanup_calls.set(cleanup_calls.get().saturating_add(1));
                    Some(Ok(()))
                },
            );

            assert_eq!(result, Err(LaunchError::OperatingSystem));
            assert!(!observer.cleanup_armed);
        }
        assert_eq!(cleanup_calls.get(), 1);
    }

    #[test]
    fn full_exchange_missing_cleanup_deadline_keeps_drop_fallback_armed() {
        let cleanup_calls = Cell::new(0_u32);
        {
            let mut observer = ExchangeCleanupDropObserver {
                cleanup_armed: true,
                cleanup_calls: &cleanup_calls,
            };
            let result = resolve_exchange_natural_exit_with_cleanup(
                &mut observer.cleanup_armed,
                || Err(LaunchError::TerminationDeadlineElapsed),
                || None,
            );

            assert_eq!(result, Err(LaunchError::Cleanup));
            assert!(observer.cleanup_armed);
        }
        assert_eq!(cleanup_calls.get(), 1);
    }

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

    fn probe_token_information(
        token: HANDLE,
        class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
    ) -> Result<Vec<usize>, LaunchError> {
        let mut required = 0_u32;
        // SAFETY: documented sizing call with a live token and writable size.
        let _ = unsafe { GetTokenInformation(token, class, None, 0, &raw mut required) };
        let required = usize::try_from(required).map_err(|_| LaunchError::SandboxVerification)?;
        if required == 0 || required > 64 * 1024 {
            return Err(LaunchError::SandboxVerification);
        }
        let words = required
            .checked_add(size_of::<usize>() - 1)
            .and_then(|bytes| bytes.checked_div(size_of::<usize>()))
            .ok_or(LaunchError::SandboxVerification)?;
        let mut buffer = vec![0_usize; words];
        let mut returned = 0_u32;
        // SAFETY: aligned storage has at least `required` writable bytes.
        unsafe {
            GetTokenInformation(
                token,
                class,
                Some(buffer.as_mut_ptr().cast::<core::ffi::c_void>()),
                u32::try_from(required).map_err(|_| LaunchError::SandboxVerification)?,
                &raw mut returned,
            )
        }
        .map_err(|_| LaunchError::SandboxVerification)?;
        let returned = usize::try_from(returned).map_err(|_| LaunchError::SandboxVerification)?;
        if returned == 0 || returned > required {
            return Err(LaunchError::SandboxVerification);
        }
        Ok(buffer)
    }

    fn require_token_right_denied(
        process: HANDLE,
        access: TOKEN_ACCESS_MASK,
    ) -> Result<(), LaunchError> {
        let mut token = HANDLE::default();
        // SAFETY: the retained logical-parent process handle remains live. The
        // output receives ownership only on success.
        let result = unsafe { OpenProcessToken(process, access, &raw mut token) };
        match result {
            Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => Ok(()),
            Err(_) => Err(LaunchError::SandboxVerification),
            Ok(()) => {
                if !token.is_invalid() {
                    // SAFETY: unexpected success returned one fresh owned handle.
                    unsafe {
                        let _ = CloseHandle(token);
                    }
                }
                Err(LaunchError::SandboxVerification)
            }
        }
    }

    fn require_process_right_denied(
        process_id: u32,
        access: PROCESS_ACCESS_RIGHTS,
    ) -> Result<(), LaunchError> {
        // SAFETY: this only requests one explicit right against the observed
        // live PID and adopts a handle only on unexpected success.
        match unsafe { OpenProcess(access, false, process_id) } {
            Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => Ok(()),
            Err(_) => Err(LaunchError::SandboxVerification),
            Ok(handle) => {
                if !handle.is_invalid() {
                    // SAFETY: unexpected success returned one fresh owned handle.
                    unsafe {
                        let _ = CloseHandle(handle);
                    }
                }
                Err(LaunchError::SandboxVerification)
            }
        }
    }

    fn require_local_duplicate_right_denied(
        process: HANDLE,
        access: u32,
    ) -> Result<(), LaunchError> {
        let mut amplified = HANDLE::default();
        // SAFETY: this attempts to derive a stronger local handle from the exact
        // injected source. Success would violate the least-authority contract;
        // an unexpected owned result is closed below.
        let result = unsafe {
            DuplicateHandle(
                GetCurrentProcess(),
                process,
                GetCurrentProcess(),
                &raw mut amplified,
                access,
                false,
                DUPLICATE_HANDLE_OPTIONS(0),
            )
        };
        match result {
            Err(error) if error.code() == ERROR_ACCESS_DENIED.to_hresult() => Ok(()),
            Err(_) => Err(LaunchError::SandboxVerification),
            Ok(()) => {
                if !amplified.is_invalid() {
                    // SAFETY: unexpected success returned one fresh owned handle.
                    unsafe {
                        let _ = CloseHandle(amplified);
                    }
                }
                Err(LaunchError::SandboxVerification)
            }
        }
    }

    fn require_debug_privilege_absent(debug_luid: LUID) -> Result<(), LaunchError> {
        let mut raw_token = HANDLE::default();
        // SAFETY: the current Approval LPAC pseudo handle is valid and output
        // receives one fresh query-only token handle.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut raw_token) }
            .map_err(|_| LaunchError::SandboxVerification)?;
        if raw_token.is_invalid() {
            return Err(LaunchError::SandboxVerification);
        }
        // SAFETY: the successful API call transferred unique ownership.
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token.0) };
        let privileges = probe_token_information(HANDLE(token.as_raw_handle()), TokenPrivileges)?;
        let returned_bytes = privileges.len().saturating_mul(size_of::<usize>());
        let entries_offset = offset_of!(TOKEN_PRIVILEGES, Privileges);
        if returned_bytes < entries_offset {
            return Err(LaunchError::SandboxVerification);
        }
        // SAFETY: the returned aligned storage contains the leading count.
        let count = unsafe { ptr::read_unaligned(privileges.as_ptr().cast::<u32>()) };
        let count = usize::try_from(count).map_err(|_| LaunchError::SandboxVerification)?;
        let required = count
            .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
            .and_then(|bytes| entries_offset.checked_add(bytes))
            .ok_or(LaunchError::SandboxVerification)?;
        if required > returned_bytes {
            return Err(LaunchError::SandboxVerification);
        }

        let entries = privileges.as_ptr().cast::<u8>();
        for index in 0..count {
            let offset = index
                .checked_mul(size_of::<LUID_AND_ATTRIBUTES>())
                .and_then(|bytes| entries_offset.checked_add(bytes))
                .ok_or(LaunchError::SandboxVerification)?;
            // SAFETY: the complete entry range was bounds-checked above.
            let entry =
                unsafe { ptr::read_unaligned(entries.add(offset).cast::<LUID_AND_ATTRIBUTES>()) };
            if entry.Luid == debug_luid {
                return Err(LaunchError::SandboxVerification);
            }
        }
        Ok(())
    }

    fn validate_logical_parent_observation(
        process: HANDLE,
        expected_process_id: u32,
    ) -> Result<(), LaunchError> {
        let mut flags = u32::MAX;
        // SAFETY: the child owns the injected process handle for this query.
        unsafe { GetHandleInformation(process, &raw mut flags) }
            .map_err(|_| LaunchError::SandboxVerification)?;
        // SAFETY: the child owns and retains the injected process handle.
        let process_id = unsafe { GetProcessId(process) };
        // SAFETY: the child still owns that handle; a zero-time wait only
        // observes liveness of the exact process object.
        let wait = unsafe { WaitForSingleObject(process, 0) };
        if flags != 0
            || process_id == 0
            || process_id != expected_process_id
            || wait != WAIT_TIMEOUT
        {
            return Err(LaunchError::SandboxVerification);
        }

        let mut path = vec![0_u16; 32_768];
        let mut path_units =
            u32::try_from(path.len()).map_err(|_| LaunchError::SandboxVerification)?;
        // SAFETY: the retained handle has QUERY_LIMITED_INFORMATION and the
        // mutable output buffer is valid for its declared capacity.
        unsafe {
            QueryFullProcessImageNameW(
                process,
                PROCESS_NAME_WIN32,
                PWSTR(path.as_mut_ptr()),
                &raw mut path_units,
            )
        }
        .map_err(|_| LaunchError::SandboxVerification)?;
        let path_units =
            usize::try_from(path_units).map_err(|_| LaunchError::SandboxVerification)?;
        if path_units == 0 || path_units >= path.len() {
            return Err(LaunchError::SandboxVerification);
        }

        let mut raw_token = HANDLE::default();
        // SAFETY: QUERY_LIMITED_INFORMATION is sufficient to request the token;
        // TOKEN_QUERY is independently checked against the token-object DACL.
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut raw_token) }
            .map_err(|_| LaunchError::SandboxVerification)?;
        if raw_token.is_invalid() {
            return Err(LaunchError::SandboxVerification);
        }
        // SAFETY: successful OpenProcessToken returned one fresh owned handle.
        let token = unsafe { OwnedHandle::from_raw_handle(raw_token.0) };
        let session = probe_token_information(HANDLE(token.as_raw_handle()), TokenSessionId)?;
        if session.len().saturating_mul(size_of::<usize>()) < size_of::<u32>() {
            return Err(LaunchError::SandboxVerification);
        }
        // SAFETY: the exact DWORD token information was bounds-checked above.
        let session_id = unsafe { ptr::read_unaligned(session.as_ptr().cast::<u32>()) };
        if session_id == u32::MAX {
            return Err(LaunchError::SandboxVerification);
        }
        Ok(())
    }

    #[test]
    #[ignore = "launched only by the integrated Approval LPAC logical-parent kernel probe"]
    fn approval_lpac_parent_probe_child_fixture() -> Result<(), LaunchError> {
        let mut frame = Vec::new();
        std::io::stdin()
            .take(
                u64::try_from(APPROVAL_PARENT_PROBE_FRAME_BYTES)
                    .map_err(|_| LaunchError::SandboxVerification)?
                    + 1,
            )
            .read_to_end(&mut frame)
            .map_err(|_| LaunchError::SandboxVerification)?;
        if frame.len() != APPROVAL_PARENT_PROBE_FRAME_BYTES
            || frame[..8] != APPROVAL_PARENT_PROBE_MAGIC
        {
            return Err(LaunchError::SandboxVerification);
        }
        let process_value = u64::from_be_bytes(
            frame[8..16]
                .try_into()
                .map_err(|_| LaunchError::SandboxVerification)?,
        );
        let process_id = u32::from_be_bytes(
            frame[16..20]
                .try_into()
                .map_err(|_| LaunchError::SandboxVerification)?,
        );
        let debug_luid = LUID {
            LowPart: u32::from_be_bytes(
                frame[20..24]
                    .try_into()
                    .map_err(|_| LaunchError::SandboxVerification)?,
            ),
            HighPart: i32::from_be_bytes(
                frame[24..28]
                    .try_into()
                    .map_err(|_| LaunchError::SandboxVerification)?,
            ),
        };
        let process_value =
            usize::try_from(process_value).map_err(|_| LaunchError::SandboxVerification)?;
        let process = HANDLE(process_value as RawHandle);
        if process.is_invalid() || process_id == 0 {
            return Err(LaunchError::SandboxVerification);
        }

        validate_logical_parent_observation(process, process_id)?;
        for access in [
            TOKEN_DUPLICATE,
            TOKEN_ASSIGN_PRIMARY,
            TOKEN_IMPERSONATE,
            TOKEN_ADJUST_PRIVILEGES,
            TOKEN_ADJUST_GROUPS,
            TOKEN_ADJUST_DEFAULT,
            TOKEN_ADJUST_SESSIONID,
            TOKEN_QUERY_SOURCE,
            TOKEN_ACCESS_MASK(WRITE_DAC.0),
            TOKEN_ACCESS_MASK(WRITE_OWNER.0),
            TOKEN_ACCESS_MASK(READ_CONTROL.0),
            TOKEN_ACCESS_MASK(DELETE.0),
        ] {
            require_token_right_denied(process, access)?;
        }

        for access in [
            PROCESS_DUP_HANDLE.0,
            PROCESS_TERMINATE.0,
            PROCESS_CREATE_THREAD.0,
            PROCESS_VM_OPERATION.0,
            PROCESS_VM_READ.0,
            PROCESS_VM_WRITE.0,
            PROCESS_CREATE_PROCESS.0,
            PROCESS_QUERY_INFORMATION.0,
            PROCESS_SET_QUOTA.0,
            PROCESS_SET_INFORMATION.0,
            PROCESS_ACCESS_RIGHTS(0x0000_2000).0,
            PROCESS_SUSPEND_RESUME.0,
            WRITE_DAC.0,
            WRITE_OWNER.0,
            READ_CONTROL.0,
            DELETE.0,
        ] {
            require_local_duplicate_right_denied(process, access)?;
        }

        require_process_right_denied(process_id, PROCESS_DUP_HANDLE)?;
        require_process_right_denied(process_id, PROCESS_QUERY_INFORMATION)?;
        require_process_right_denied(process_id, PROCESS_QUERY_LIMITED_INFORMATION)?;
        require_process_right_denied(process_id, PROCESS_ACCESS_RIGHTS(0x0000_2000))?;
        require_process_right_denied(process_id, PROCESS_ACCESS_RIGHTS(0x0010_0000))?;
        require_process_right_denied(
            process_id,
            PROCESS_ACCESS_RIGHTS(PROCESS_QUERY_LIMITED_INFORMATION.0 | 0x0010_0000),
        )?;
        require_process_right_denied(process_id, PROCESS_ACCESS_RIGHTS(WRITE_DAC.0))?;
        require_debug_privilege_absent(debug_luid)?;
        validate_logical_parent_observation(process, process_id)?;
        std::process::exit(
            i32::try_from(APPROVAL_PARENT_PROBE_SUCCESS_EXIT_CODE)
                .map_err(|_| LaunchError::SandboxVerification)?,
        )
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
        // The full libtest suite runs many cooperating process-launch fixtures
        // concurrently. This test proves source rejection, not the production
        // launch-admission deadline, so allow the shared test flight to drain.
        let deadline = Instant::now()
            .checked_add(Duration::from_mins(1))
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
        let private_result = InheritedStdio::for_child_pipe_servers(
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
        assert!(matches!(
            InheritedStdio::for_child_pipe_servers(
                disk.as_handle(),
                disk.as_handle(),
                disk.as_handle()
            ),
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
        assert!(matches!(
            InheritedStdio::for_child_pipe_servers(borrowed, borrowed, borrowed),
            Err(LaunchError::InvalidHandle)
        ));
        Ok(())
    }

    #[test]
    fn mitigation_job_and_lpac_contract_is_fail_closed() {
        let mitigation = sys::mitigation_policy_for_test();
        let kernel_fixture_mitigation = sys::approval_kernel_fixture_mitigation_policy_for_test();
        assert_ne!(mitigation & (1 << 24), 0, "strict handle checks");
        assert_ne!(mitigation & (1 << 36), 0, "dynamic code prohibited");
        assert_ne!(mitigation & (1 << 52), 0, "remote images prohibited");
        assert_ne!(mitigation & (1 << 56), 0, "low-label images prohibited");
        assert_eq!(kernel_fixture_mitigation & (1 << 56), 0);
        assert_eq!(mitigation ^ kernel_fixture_mitigation, 1 << 56);
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
    fn parent_process_proof_is_a_real_non_inheritable_exact_current_object()
    -> Result<(), Box<dyn std::error::Error>> {
        sys::verify_current_parent_proof_for_test()?;
        Ok(())
    }

    #[test]
    fn approval_lpac_kernel_fixture_is_profile_scoped_and_exactly_cleaned()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = super::ApprovalLpacKernelTestFixture::create()?;
        let executable = fixture.path().to_path_buf();
        let directory = executable
            .parent()
            .ok_or_else(|| std::io::Error::other("fixture executable has no parent"))?
            .to_path_buf();
        assert!(executable.is_file());
        assert!(directory.is_dir());
        assert_eq!(
            format!("{fixture:?}"),
            "ApprovalLpacKernelTestFixture([REDACTED PATH])"
        );
        fixture.cleanup()?;
        assert!(!executable.exists());
        assert!(!directory.exists());
        Ok(())
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
    fn approval_launch_environment_adds_only_os_derived_local_app_data()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = sys::approval_environment_for_test(Path::new(r"C:\Windows"))?;
        assert!(block.ends_with(&[0, 0]));
        let entries = parse_environment(&block)?;
        assert_eq!(entries.len(), 3);
        let local_app_data = entries[0]
            .strip_prefix("LOCALAPPDATA=")
            .ok_or_else(|| std::io::Error::other("LOCALAPPDATA entry is absent"))?;
        assert!(Path::new(local_app_data).is_absolute());
        assert_eq!(entries[1], r"SystemRoot=C:\Windows");
        assert_eq!(entries[2], r"WINDIR=C:\Windows");

        let decoded = String::from_utf16(&block)?;
        for ambient_name in [
            "PATH=",
            "TEMP=",
            "TMP=",
            "USERPROFILE=",
            "HTTP_PROXY=",
            "HTTPS_PROXY=",
            "AUTHORIZATION=",
            "PASSWORD=",
            "SECRET=",
            "TOKEN=",
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

        let release = ReleaseAttestation::with_helper_manifests_for_test(
            ArtifactDigest::for_test([4; 32]),
            [[5; 32], [6; 32], [7; 32]],
        );
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
        let release = ReleaseAttestation::with_helper_manifests_for_test(
            ArtifactDigest::for_test([4; 32]),
            [key_agent.manifest_digest(), [6; 32], [7; 32]],
        );
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

        // Approval is structurally confined to the parent-bound activation,
        // while Secret Input advances to its still-disabled release gate.
        assert!(matches!(
            launcher.spawn(&approval, &stdio),
            Err(LaunchError::ApprovalRequiresParentBoundActivation)
        ));
        assert!(matches!(
            launcher.spawn_secret_input(&secret_input, &stdio),
            Err(LaunchError::ReleaseNotAttested)
        ));
        Ok(())
    }
}
