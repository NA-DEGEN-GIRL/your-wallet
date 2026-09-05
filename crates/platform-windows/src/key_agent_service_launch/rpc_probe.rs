//! Synchronous coordinator leaf for one debug-only service-created helper probe.
//!
//! The caller serializes requests and owns the restricted-service-token proof.
//! This module performs one complete process-terminal attempt: pin one fixed
//! sibling helper, prepare the exact service/user creation inputs on a fresh
//! debugger thread, complete both cooperative gates, register before resume,
//! wait for the helper's RPC confirmation, and retire the admitted process.

#![forbid(unsafe_code)]

use core::fmt;
use core::num::NonZeroU32;
use std::path::{Path, PathBuf};

use key_agent_service_helper_bootstrap::HelperBootstrapRole;
use key_agent_service_wire::debug_v2::{DesktopCommand, DesktopCommandRequest, DesktopResult};
use thiserror::Error;

use super::debug_gate::{
    ServiceHelperAdmission, ServiceProbeChannelSources, ServiceProbeDebugCorrelation,
    ServiceProbeDebugGateError, authenticate_and_arm_service_probe,
};
use super::gate::preflight_service_helper_gates;
use super::process::{
    FreshDebuggerThread, FreshDebuggerThreadError, PendingServiceProbeCleanup,
    ServiceProbeCreateError, ServiceProbeCreateInputs, run_on_fresh_debugger_thread,
};
use crate::helper::VerifiedHelper;
use crate::key_agent_service_rpc::{AuthenticatedRpcClient, ExpectedHelperRole};
use crate::key_agent_service_token::ServiceTokenFixtureProof;
use crate::pipe::{PrivateApprovalPipes, PrivateSecretInputPipes};
use crate::restricted_process_context::RestrictedProcessContext;

const SERVICE_EXECUTABLE_NAME: &str = "key-agent-service.exe";
const APPROVAL_EXECUTABLE_NAME: &str = "approval-ui.exe";
const SECRET_INPUT_EXECUTABLE_NAME: &str = "secret-input-ui.exe";
const COORDINATION_MILLISECONDS: u32 = super::debug_gate::MAX_COORDINATION_MILLISECONDS;

/// Closed helper roles derived only from the exact authenticated desktop request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceRpcProbeRole {
    Approval,
    SecretInput,
}

impl ServiceRpcProbeRole {
    const fn from_request(request: &DesktopCommandRequest) -> Result<Self, ServiceRpcProbeError> {
        match request.command() {
            DesktopCommand::LaunchApprovalRpcProbe => Ok(Self::Approval),
            DesktopCommand::LaunchSecretInputRpcProbe => Ok(Self::SecretInput),
            DesktopCommand::Status => Err(ServiceRpcProbeError::Role),
        }
    }

    const fn bootstrap(self) -> HelperBootstrapRole {
        match self {
            Self::Approval => HelperBootstrapRole::Approval,
            Self::SecretInput => HelperBootstrapRole::SecretInput,
        }
    }

    const fn admitted(self) -> ExpectedHelperRole {
        match self {
            Self::Approval => ExpectedHelperRole::Approval,
            Self::SecretInput => ExpectedHelperRole::SecretInput,
        }
    }

    const fn executable_name(self) -> &'static str {
        match self {
            Self::Approval => APPROVAL_EXECUTABLE_NAME,
            Self::SecretInput => SECRET_INPUT_EXECUTABLE_NAME,
        }
    }

    const fn completed_result(self) -> DesktopResult {
        match self {
            Self::Approval => DesktopResult::ApprovalRpcProbeCompleted,
            Self::SecretInput => DesktopResult::SecretInputRpcProbeCompleted,
        }
    }
}

/// Data-free failure from one complete helper RPC probe attempt.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(crate) enum ServiceRpcProbeError {
    #[error("service helper artifact is unavailable")]
    Artifact,
    #[error("service helper process context is unavailable")]
    ProcessContext,
    #[error("service helper private channels are unavailable")]
    Channel,
    #[error("service helper launch preparation is unavailable")]
    Preparation,
    #[error("service token creation authority violated an invariant")]
    ServiceTokenInvariant,
    #[error("service-created helper process violated an invariant")]
    CreatedProcessInvariant,
    #[error("service helper debugger thread is unavailable")]
    DebuggerThread,
    #[error("service helper debugger thread violated an invariant")]
    DebuggerInvariant,
    #[error("service helper debugger gate is unavailable")]
    DebuggerGate,
    #[error("service helper expected-peer admission is unavailable")]
    Admission,
    #[error("service helper expected-peer registry violated an invariant")]
    RegistryInternal,
    #[error("service helper confirmation is unavailable")]
    Confirmation,
    #[error("service helper role correlation failed")]
    Role,
    #[error("service helper terminal cleanup failed")]
    Cleanup,
}

impl ServiceRpcProbeError {
    /// Whether continuing to admit RPC work could hide a cleanup or authority
    /// invariant failure. The wire result remains data-free `Unavailable`.
    pub(crate) const fn is_fatal(self) -> bool {
        matches!(
            self,
            Self::ServiceTokenInvariant
                | Self::CreatedProcessInvariant
                | Self::DebuggerInvariant
                | Self::RegistryInternal
                | Self::Role
                | Self::Cleanup
        )
    }
}

enum DebuggerAttempt {
    Armed(Box<super::debug_gate::PendingDebuggerExitServiceProbe>),
    Cleanup(Box<PendingServiceProbeCleanup>, ServiceRpcProbeError),
    Rejected(ServiceRpcProbeError),
}

/// Runs one exact service-created helper RPC round trip.
///
/// Success is reported only after the helper's exact role-specific exchange was
/// observed, the registry independently reached `Admitted`, the registry-owned
/// role matched the fixed desktop command, and process/Job cancellation and
/// reap completed while the request writer was still retained.
pub(crate) fn run_service_helper_rpc_probe(
    service_token: &mut ServiceTokenFixtureProof,
    client: AuthenticatedRpcClient,
    request: DesktopCommandRequest,
    admission: &ServiceHelperAdmission,
) -> Result<DesktopResult, ServiceRpcProbeError> {
    let role = ServiceRpcProbeRole::from_request(&request)?;
    let service_executable = std::env::current_exe().map_err(|_| ServiceRpcProbeError::Artifact)?;
    let helper_path = fixed_sibling_helper_path(&service_executable, role)?;

    let joined = run_on_fresh_debugger_thread(move |debugger_thread| {
        prepare_debugger_attempt(
            debugger_thread,
            service_token,
            &client,
            request,
            role,
            &helper_path,
        )
    })
    .map_err(|error| match error {
        FreshDebuggerThreadError::Spawn => ServiceRpcProbeError::DebuggerThread,
        FreshDebuggerThreadError::Panic => ServiceRpcProbeError::DebuggerInvariant,
    })?;

    let (attempt, proof) = joined.into_parts();
    let detached = match attempt {
        DebuggerAttempt::Armed(armed) => (*armed)
            .finish_after_debugger_exit(proof)
            .map_err(|_| ServiceRpcProbeError::Cleanup)?,
        DebuggerAttempt::Cleanup(mut cleanup, original) => {
            let cleanup_result = cleanup.finish_after_debugger_exit(&proof);
            drop(proof);
            return match cleanup_result {
                Ok(_) => Err(original),
                Err(_) => Err(ServiceRpcProbeError::Cleanup),
            };
        }
        DebuggerAttempt::Rejected(error) => {
            drop(proof);
            return Err(error);
        }
    };

    let (mut lease, mut confirmation) = detached
        .register_revalidate_and_resume_once(admission)
        .map_err(map_registry_error)?;
    if confirmation.role() != role.bootstrap() {
        let cleanup = lease.cancel();
        drop(confirmation);
        return if cleanup.is_ok() {
            Err(ServiceRpcProbeError::Role)
        } else {
            Err(ServiceRpcProbeError::Cleanup)
        };
    }
    let exchange = match role {
        ServiceRpcProbeRole::Approval => non_signing_approval_probe_request()
            .map_err(|_| ServiceProbeDebugGateError::Correlation)
            .and_then(|request| confirmation.exchange_approval_probe(&request)),
        ServiceRpcProbeRole::SecretInput => confirmation.wait_for_confirmation().map(|_| ()),
    };
    if exchange.is_err() {
        let cleanup = lease.cancel();
        drop(confirmation);
        return if cleanup.is_ok() {
            Err(ServiceRpcProbeError::Confirmation)
        } else {
            Err(ServiceRpcProbeError::Cleanup)
        };
    }

    // Retain the request writer in `confirmation` until registry-owned role
    // extraction and the exact process/Job terminal proof have both completed.
    let admitted = lease.finish_admitted_and_cancel();
    // Cleanup is unconditional, even when the original deadline has elapsed.
    let timely = confirmation.ensure_live_deadline();
    drop(confirmation);
    match admitted {
        Ok(admitted_role) if admitted_role == role.admitted() => {
            timely.map_err(|_| ServiceRpcProbeError::Confirmation)?;
            Ok(role.completed_result())
        }
        Ok(_) => Err(ServiceRpcProbeError::Role),
        Err(_) => Err(ServiceRpcProbeError::Cleanup),
    }
}

/// A service-authored display fixture, never a wallet or signing request. The
/// digest/nonce are fresh public correlation bytes, not signing authority. No
/// account, secret, network, vault or broker-supplied display is consulted.
fn non_signing_approval_probe_request()
-> Result<approval_wire::ApprovalRequest, ServiceRpcProbeError> {
    use approval_wire::{
        ApprovalDisplay, ApprovalRequest, DisplayField, FieldSemantic as F, OperationKind,
        RiskLevel, SimulationStatus,
    };
    let mut digest = [0_u8; 32];
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut digest).map_err(|_| ServiceRpcProbeError::Preparation)?;
    getrandom::fill(&mut nonce).map_err(|_| ServiceRpcProbeError::Preparation)?;
    let fields = [
        (F::Origin, "https://service-probe.invalid"),
        (
            F::OriginProvenance,
            "Service transport test; no browser request",
        ),
        (F::Account, "No wallet account - transport test only"),
        (F::NetworkName, "No network - transport test only"),
        (F::ChainId, "Not applicable - no signing"),
        (F::GenesisHash, "Not applicable - no signing"),
        (F::RulesetRevision, "Not applicable - no signing"),
        (
            F::RpcObservationsDigest,
            "Not applicable - no network access",
        ),
        (F::OperationKind, OperationKind::PersonalMessage.value()),
        (
            F::PersonalMessageBytes,
            "Transport test only; these bytes will never be signed",
        ),
        (F::SimulationStatus, SimulationStatus::NotPerformed.value()),
        (
            F::OriginWarning,
            "Local service fixture, not a site authorization request.",
        ),
        (
            F::PersonalMessageWarning,
            "Approve and Reject only test transport; neither can sign.",
        ),
        (
            F::NoSimulationWarning,
            "No simulation, network access or transaction occurs.",
        ),
    ]
    .into_iter()
    .map(|(semantic, value)| DisplayField::new(semantic, value, true))
    .collect::<Result<Vec<_>, _>>()
    .map_err(|_| ServiceRpcProbeError::Preparation)?;
    let display = ApprovalDisplay::new(RiskLevel::High, fields)
        .map_err(|_| ServiceRpcProbeError::Preparation)?;
    ApprovalRequest::new(
        digest,
        nonce,
        COORDINATION_MILLISECONDS,
        "TRANSPORT TEST - NO SIGNING",
        display,
    )
    .map_err(|_| ServiceRpcProbeError::Preparation)
}

fn prepare_debugger_attempt(
    debugger_thread: FreshDebuggerThread,
    service_token: &mut ServiceTokenFixtureProof,
    client: &AuthenticatedRpcClient,
    request: DesktopCommandRequest,
    role: ServiceRpcProbeRole,
    helper_path: &Path,
) -> DebuggerAttempt {
    let Ok(helper) = hold_helper(helper_path, role) else {
        return DebuggerAttempt::Rejected(ServiceRpcProbeError::Artifact);
    };
    let Ok(layout) = preflight_service_helper_gates(&helper) else {
        return DebuggerAttempt::Rejected(ServiceRpcProbeError::Artifact);
    };
    let Ok(context) = RestrictedProcessContext::prepare() else {
        return DebuggerAttempt::Rejected(ServiceRpcProbeError::ProcessContext);
    };
    let Ok(creation_token) = service_token.creation_token() else {
        return DebuggerAttempt::Rejected(ServiceRpcProbeError::ServiceTokenInvariant);
    };
    let inputs = match role {
        ServiceRpcProbeRole::Approval => {
            ServiceProbeCreateInputs::prepare_approval(client, creation_token, helper, &context)
        }
        ServiceRpcProbeRole::SecretInput => {
            ServiceProbeCreateInputs::prepare_secret_input(client, creation_token, helper, &context)
        }
    };
    let inputs = match inputs {
        Ok(inputs) => inputs,
        Err(error) => return DebuggerAttempt::Rejected(map_create_error(error)),
    };
    let Ok(sources) = create_channel_sources(role) else {
        return DebuggerAttempt::Rejected(ServiceRpcProbeError::Channel);
    };
    let Some(timeout) = NonZeroU32::new(COORDINATION_MILLISECONDS) else {
        return DebuggerAttempt::Rejected(ServiceRpcProbeError::Preparation);
    };
    let Ok(correlation) =
        ServiceProbeDebugCorrelation::new(request.epoch_nonce(), request.request_id(), timeout)
    else {
        return DebuggerAttempt::Rejected(ServiceRpcProbeError::Preparation);
    };
    let suspended = match inputs.create_suspended(debugger_thread) {
        Ok(suspended) => suspended,
        Err(cleanup) => {
            let original = map_create_error(cleanup.failure());
            return DebuggerAttempt::Cleanup(Box::new(cleanup), original);
        }
    };
    match authenticate_and_arm_service_probe(suspended, layout, correlation, sources) {
        Ok(armed) => DebuggerAttempt::Armed(Box::new(armed)),
        Err(failed) => {
            let original = map_debug_gate_error(failed.error());
            DebuggerAttempt::Cleanup(Box::new(failed.into_cleanup()), original)
        }
    }
}

const fn map_debug_gate_error(error: ServiceProbeDebugGateError) -> ServiceRpcProbeError {
    match error {
        ServiceProbeDebugGateError::Cleanup => ServiceRpcProbeError::Cleanup,
        ServiceProbeDebugGateError::JoinProof => ServiceRpcProbeError::DebuggerInvariant,
        ServiceProbeDebugGateError::Deadline
        | ServiceProbeDebugGateError::UnexpectedEvent
        | ServiceProbeDebugGateError::EventIdentity
        | ServiceProbeDebugGateError::ImageIdentity
        | ServiceProbeDebugGateError::GateAuthentication
        | ServiceProbeDebugGateError::Channel
        | ServiceProbeDebugGateError::Correlation
        | ServiceProbeDebugGateError::Suspension
        | ServiceProbeDebugGateError::Detach => ServiceRpcProbeError::DebuggerGate,
    }
}

const fn map_create_error(error: ServiceProbeCreateError) -> ServiceRpcProbeError {
    match error {
        ServiceProbeCreateError::ServiceSecurity => ServiceRpcProbeError::ServiceTokenInvariant,
        ServiceProbeCreateError::Verification => ServiceRpcProbeError::CreatedProcessInvariant,
        ServiceProbeCreateError::Cleanup => ServiceRpcProbeError::Cleanup,
        ServiceProbeCreateError::Helper
        | ServiceProbeCreateError::ProcessContext
        | ServiceProbeCreateError::TargetLpac
        | ServiceProbeCreateError::Job
        | ServiceProbeCreateError::Startup
        | ServiceProbeCreateError::Authentication
        | ServiceProbeCreateError::Creation
        | ServiceProbeCreateError::Aborted => ServiceRpcProbeError::Preparation,
    }
}

const fn map_registry_error(
    error: crate::key_agent_service_rpc::ExpectedPeerRegistryError,
) -> ServiceRpcProbeError {
    match error {
        crate::key_agent_service_rpc::ExpectedPeerRegistryError::Internal => {
            ServiceRpcProbeError::RegistryInternal
        }
        crate::key_agent_service_rpc::ExpectedPeerRegistryError::Denied
        | crate::key_agent_service_rpc::ExpectedPeerRegistryError::Full
        | crate::key_agent_service_rpc::ExpectedPeerRegistryError::Stopping => {
            ServiceRpcProbeError::Admission
        }
    }
}

fn hold_helper(
    helper_path: &Path,
    role: ServiceRpcProbeRole,
) -> Result<VerifiedHelper, ServiceRpcProbeError> {
    match role {
        ServiceRpcProbeRole::Approval => VerifiedHelper::hold_dormant_service_approval(helper_path),
        ServiceRpcProbeRole::SecretInput => {
            VerifiedHelper::hold_dormant_service_secret_input(helper_path)
        }
    }
    .map_err(|_| ServiceRpcProbeError::Artifact)
}

fn create_channel_sources(
    role: ServiceRpcProbeRole,
) -> Result<ServiceProbeChannelSources, ServiceRpcProbeError> {
    match role {
        ServiceRpcProbeRole::Approval => PrivateApprovalPipes::create()
            .map(ServiceProbeChannelSources::Approval)
            .map_err(|_| ServiceRpcProbeError::Channel),
        ServiceRpcProbeRole::SecretInput => PrivateSecretInputPipes::create()
            .map(ServiceProbeChannelSources::SecretInput)
            .map_err(|_| ServiceRpcProbeError::Channel),
    }
}

fn fixed_sibling_helper_path(
    service_executable: &Path,
    role: ServiceRpcProbeRole,
) -> Result<PathBuf, ServiceRpcProbeError> {
    if !service_executable.is_absolute()
        || service_executable
            .file_name()
            .and_then(|name| name.to_str())
            != Some(SERVICE_EXECUTABLE_NAME)
    {
        return Err(ServiceRpcProbeError::Artifact);
    }
    let mut helper = service_executable.to_path_buf();
    helper.set_file_name(role.executable_name());
    if !helper.is_absolute() || helper == service_executable {
        return Err(ServiceRpcProbeError::Artifact);
    }
    Ok(helper)
}

impl fmt::Debug for DebuggerAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Armed(_) => formatter.write_str("DebuggerAttempt::Armed([REDACTED])"),
            Self::Cleanup(_, _) => formatter.write_str("DebuggerAttempt::Cleanup([REDACTED])"),
            Self::Rejected(_) => formatter.write_str("DebuggerAttempt::Rejected([REDACTED])"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_probe_fixture_is_fresh_canonical_and_explicitly_non_signing()
    -> Result<(), Box<dyn std::error::Error>> {
        use approval_wire::FieldSemantic;
        let first = non_signing_approval_probe_request()?;
        let second = non_signing_approval_probe_request()?;
        assert_ne!(first.digest(), second.digest());
        assert_ne!(first.approval_nonce(), second.approval_nonce());
        assert_eq!(
            first.expires_after_milliseconds(),
            COORDINATION_MILLISECONDS
        );
        assert_eq!(first.anti_phishing_phrase(), "TRANSPORT TEST - NO SIGNING");
        assert_eq!(
            first
                .display()
                .field(FieldSemantic::Account)
                .ok_or("missing account")?
                .value(),
            "No wallet account - transport test only"
        );
        assert_eq!(
            first
                .display()
                .field(FieldSemantic::PersonalMessageWarning)
                .ok_or("missing warning")?
                .value(),
            "Approve and Reject only test transport; neither can sign."
        );
        let encoded = approval_wire::encode_request(&first);
        assert_eq!(approval_wire::decode_request(&encoded)?, first);
        let prefix = key_agent_service_helper_bootstrap::encode_service_approval_request_prefix(
            encoded.len(),
        )?;
        assert_eq!(
            key_agent_service_helper_bootstrap::decode_service_approval_request_prefix(&prefix)?,
            encoded.len()
        );
        Ok(())
    }

    #[test]
    fn fixed_roles_bind_to_distinct_helper_names_and_authorities() {
        assert_eq!(
            ServiceRpcProbeRole::Approval.executable_name(),
            APPROVAL_EXECUTABLE_NAME
        );
        assert_eq!(
            ServiceRpcProbeRole::SecretInput.executable_name(),
            SECRET_INPUT_EXECUTABLE_NAME
        );
        assert_eq!(
            ServiceRpcProbeRole::Approval.bootstrap(),
            HelperBootstrapRole::Approval
        );
        assert_eq!(
            ServiceRpcProbeRole::SecretInput.bootstrap(),
            HelperBootstrapRole::SecretInput
        );
        assert_eq!(
            ServiceRpcProbeRole::Approval.admitted(),
            ExpectedHelperRole::Approval
        );
        assert_eq!(
            ServiceRpcProbeRole::SecretInput.admitted(),
            ExpectedHelperRole::SecretInput
        );
        assert_eq!(
            ServiceRpcProbeRole::Approval.completed_result(),
            DesktopResult::ApprovalRpcProbeCompleted
        );
        assert_eq!(
            ServiceRpcProbeRole::SecretInput.completed_result(),
            DesktopResult::SecretInputRpcProbeCompleted
        );
    }

    #[test]
    fn exact_desktop_request_is_the_only_role_and_correlation_authority()
    -> Result<(), Box<dyn std::error::Error>> {
        let epoch_nonce = key_agent_service_wire::EpochNonce::new([0xA5; 32])?;
        let request_id = key_agent_service_wire::ServiceRequestId::new([0x5A; 16])?;
        let approval = DesktopCommandRequest::new(
            epoch_nonce,
            request_id,
            DesktopCommand::LaunchApprovalRpcProbe,
        );
        let secret_input = DesktopCommandRequest::new(
            epoch_nonce,
            request_id,
            DesktopCommand::LaunchSecretInputRpcProbe,
        );
        let status = DesktopCommandRequest::new(epoch_nonce, request_id, DesktopCommand::Status);

        assert_eq!(
            ServiceRpcProbeRole::from_request(&approval),
            Ok(ServiceRpcProbeRole::Approval)
        );
        assert_eq!(
            ServiceRpcProbeRole::from_request(&secret_input),
            Ok(ServiceRpcProbeRole::SecretInput)
        );
        assert_eq!(
            ServiceRpcProbeRole::from_request(&status),
            Err(ServiceRpcProbeError::Role)
        );
        assert_eq!(approval.epoch_nonce(), epoch_nonce);
        assert_eq!(approval.request_id(), request_id);
        Ok(())
    }

    #[test]
    fn only_cleanup_and_authority_invariants_are_fatal() {
        for error in [
            ServiceRpcProbeError::ServiceTokenInvariant,
            ServiceRpcProbeError::CreatedProcessInvariant,
            ServiceRpcProbeError::DebuggerInvariant,
            ServiceRpcProbeError::RegistryInternal,
            ServiceRpcProbeError::Role,
            ServiceRpcProbeError::Cleanup,
        ] {
            assert!(error.is_fatal());
        }
        for error in [
            ServiceRpcProbeError::Artifact,
            ServiceRpcProbeError::ProcessContext,
            ServiceRpcProbeError::Channel,
            ServiceRpcProbeError::Preparation,
            ServiceRpcProbeError::DebuggerThread,
            ServiceRpcProbeError::DebuggerGate,
            ServiceRpcProbeError::Admission,
            ServiceRpcProbeError::Confirmation,
        ] {
            assert!(!error.is_fatal());
        }
    }

    #[test]
    fn process_creation_errors_preserve_fatal_health_classes() {
        assert_eq!(
            map_create_error(ServiceProbeCreateError::ServiceSecurity),
            ServiceRpcProbeError::ServiceTokenInvariant
        );
        assert_eq!(
            map_create_error(ServiceProbeCreateError::Verification),
            ServiceRpcProbeError::CreatedProcessInvariant
        );
        assert_eq!(
            map_create_error(ServiceProbeCreateError::Cleanup),
            ServiceRpcProbeError::Cleanup
        );
        assert_eq!(
            map_create_error(ServiceProbeCreateError::Authentication),
            ServiceRpcProbeError::Preparation
        );
        assert_eq!(
            map_create_error(ServiceProbeCreateError::Creation),
            ServiceRpcProbeError::Preparation
        );
    }

    #[test]
    fn debugger_gate_preserves_only_global_cleanup_and_join_invariants() {
        assert_eq!(
            map_debug_gate_error(ServiceProbeDebugGateError::Cleanup),
            ServiceRpcProbeError::Cleanup
        );
        assert_eq!(
            map_debug_gate_error(ServiceProbeDebugGateError::JoinProof),
            ServiceRpcProbeError::DebuggerInvariant
        );
        for error in [
            ServiceProbeDebugGateError::Deadline,
            ServiceProbeDebugGateError::UnexpectedEvent,
            ServiceProbeDebugGateError::EventIdentity,
            ServiceProbeDebugGateError::ImageIdentity,
            ServiceProbeDebugGateError::GateAuthentication,
            ServiceProbeDebugGateError::Channel,
            ServiceProbeDebugGateError::Correlation,
            ServiceProbeDebugGateError::Suspension,
            ServiceProbeDebugGateError::Detach,
        ] {
            assert_eq!(
                map_debug_gate_error(error),
                ServiceRpcProbeError::DebuggerGate
            );
        }
    }

    #[test]
    fn sibling_resolution_requires_the_exact_service_image_name() {
        let service = Path::new(r"C:\Program Files\YourWallet\key-agent-service.exe");
        assert_eq!(
            fixed_sibling_helper_path(service, ServiceRpcProbeRole::Approval),
            Ok(PathBuf::from(
                r"C:\Program Files\YourWallet\approval-ui.exe"
            ))
        );
        assert_eq!(
            fixed_sibling_helper_path(service, ServiceRpcProbeRole::SecretInput),
            Ok(PathBuf::from(
                r"C:\Program Files\YourWallet\secret-input-ui.exe"
            ))
        );
        assert_eq!(
            fixed_sibling_helper_path(
                Path::new(r"C:\Program Files\YourWallet\other.exe"),
                ServiceRpcProbeRole::Approval,
            ),
            Err(ServiceRpcProbeError::Artifact)
        );
        assert_eq!(
            fixed_sibling_helper_path(
                Path::new(r"relative\key-agent-service.exe"),
                ServiceRpcProbeRole::Approval,
            ),
            Err(ServiceRpcProbeError::Artifact)
        );
    }
}
