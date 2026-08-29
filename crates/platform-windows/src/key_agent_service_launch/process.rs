//! One-shot process, debugger-join, and detached cleanup states for the dormant
//! service-owned LPAC helper probe.
//!
//! Creation and both authenticated gates run on one fresh dedicated debugger OS
//! thread. Sendable pending owners cross only its exact join; success then proves
//! debugger absence, closes matrix-qualified event aliases, and retains one
//! explicit suspend count. Every failure prefix requests exact process and
//! whole-Job termination or fails fast before authority can be lost.

#![allow(unsafe_code)]

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::num::NonZeroU32;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::BorrowedHandle;
use std::path::Path;
use std::rc::Rc;
use std::sync::Arc;
use std::thread::{self, ThreadId};

use thiserror::Error;
use windows::Win32::Foundation::WAIT_TIMEOUT;
use windows::Win32::System::Diagnostics::Debug::CheckRemoteDebuggerPresent;
use windows::Win32::System::Threading::{ResumeThread, SuspendThread, WaitForSingleObject};
use windows::core::BOOL;

use super::debug_gate::ServiceProbeDebugEventCleanup;
use super::job::ServiceProbeJob;
use super::startup::ServiceProbeStartup;
use super::target_profile::{
    ExpectedServiceCreatedLpac, PreparedTargetUserLpac, VerifiedCreatedTargetLpac,
};
use crate::helper::VerifiedHelper;
use crate::key_agent_lpac::PreparedServiceKeyAgentCreationSecurity;
use crate::key_agent_service_rpc::{
    AuthenticatedRpcClient, CreatedDesktopProcess, DetachedDesktopProcess,
    PendingDebuggerExitProcessCleanup, PendingDebuggerExitProcessSuccess,
    PreparedDebuggerExitProcessSuccess,
};
use crate::key_agent_service_token::VerifiedServiceCreationToken;
use crate::restricted_process_context::RestrictedProcessContext;

const MAX_WIDE_PATH_UNITS: usize = 32_767;
const DEBUGGER_THREAD_NAME: &str = "yw-key-agent-service-probe";

/// Data-free failure to create or join the one fresh debugger OS thread.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum FreshDebuggerThreadError {
    /// Windows could not create the dedicated thread.
    #[error("service probe debugger thread is unavailable")]
    Spawn,
    /// The dedicated thread panicked and published no trusted result.
    #[error("service probe debugger thread failed")]
    Panic,
}

/// Move-only proof that the current code runs on one newly spawned thread.
pub(super) struct FreshDebuggerThread {
    thread_id: ThreadId,
    debug_event_cleanup: Arc<ServiceProbeDebugEventCleanup>,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl FreshDebuggerThread {
    fn require_current(&self) -> Result<ThreadId, ServiceProbeCreateError> {
        if thread::current().id() != self.thread_id {
            return Err(ServiceProbeCreateError::Verification);
        }
        Ok(self.thread_id)
    }

    #[cfg(test)]
    fn cleanup_identity_for_test(&self) -> usize {
        Arc::as_ptr(&self.debug_event_cleanup) as usize
    }
}

impl fmt::Debug for FreshDebuggerThread {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FreshDebuggerThread([REDACTED])")
    }
}

/// Result of joining the exact fresh debugger thread that produced `output`.
#[must_use = "the joined-thread proof must accompany any pending cleanup owner"]
pub(super) struct JoinedFreshDebuggerThread<Output> {
    output: Output,
    proof: DebuggerThreadExitProof,
}

impl<Output> JoinedFreshDebuggerThread<Output> {
    pub(super) fn into_parts(self) -> (Output, DebuggerThreadExitProof) {
        (self.output, self.proof)
    }
}

impl<Output> fmt::Debug for JoinedFreshDebuggerThread<Output> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JoinedFreshDebuggerThread([REDACTED])")
    }
}

/// Move-only evidence that one exact debugger thread has exited and joined.
pub(super) struct DebuggerThreadExitProof {
    thread_id: ThreadId,
    debug_event_cleanup: Arc<ServiceProbeDebugEventCleanup>,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl DebuggerThreadExitProof {
    #[cfg(test)]
    fn cleanup_identity_for_test(&self) -> usize {
        Arc::as_ptr(&self.debug_event_cleanup) as usize
    }
}

impl fmt::Debug for DebuggerThreadExitProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DebuggerThreadExitProof([REDACTED])")
    }
}

fn debugger_exit_matches(
    creator_thread_id: ThreadId,
    debug_event_cleanup: &Arc<ServiceProbeDebugEventCleanup>,
    proof: &DebuggerThreadExitProof,
) -> bool {
    proof.thread_id == creator_thread_id
        && Arc::ptr_eq(debug_event_cleanup, &proof.debug_event_cleanup)
}

/// Runs one complete attempt on a newly spawned scoped OS thread.
///
/// `Output: Send` structurally prevents a still-debug-attached
/// `SuspendedServiceProbe` from crossing the join boundary. The operation must
/// finish its debug gate or convert the process into a pending cleanup owner.
pub(super) fn run_on_fresh_debugger_thread<Output, Operation>(
    operation: Operation,
) -> Result<JoinedFreshDebuggerThread<Output>, FreshDebuggerThreadError>
where
    Output: Send,
    Operation: FnOnce(FreshDebuggerThread) -> Output + Send,
{
    let debug_event_cleanup = ServiceProbeDebugEventCleanup::new_shared();
    let worker_cleanup = Arc::clone(&debug_event_cleanup);
    thread::scope(|scope| {
        let handle = thread::Builder::new()
            .name(DEBUGGER_THREAD_NAME.to_owned())
            .spawn_scoped(scope, move || {
                let thread_id = thread::current().id();
                let output = operation(FreshDebuggerThread {
                    thread_id,
                    debug_event_cleanup: Arc::clone(&worker_cleanup),
                    _thread_bound: PhantomData,
                });
                (output, thread_id)
            })
            .map_err(|_| FreshDebuggerThreadError::Spawn)?;
        let joined = handle.join();
        debug_event_cleanup.mark_joined();
        let Ok((output, thread_id)) = joined else {
            if debug_event_cleanup.require_empty_after_join().is_err() {
                // A panic after event-alias registration cannot return a
                // data-free error while losing authority. The registry's own
                // last-owner Drop repeats this fail-safe invariant.
                std::process::abort();
            }
            return Err(FreshDebuggerThreadError::Panic);
        };
        Ok(JoinedFreshDebuggerThread {
            output,
            proof: DebuggerThreadExitProof {
                thread_id,
                debug_event_cleanup,
                _thread_bound: PhantomData,
            },
        })
    })
}

/// Data-free failures from the pre-event service probe boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub(super) enum ServiceProbeCreateError {
    /// The held helper did not name the fixed role or an exact absolute path.
    #[error("service probe helper verification failed")]
    Helper,
    /// The restricted machine-only process context changed.
    #[error("service probe process context is unavailable")]
    ProcessContext,
    /// The retained restricted-service token or creation descriptors changed.
    #[error("service probe creation security is unavailable")]
    ServiceSecurity,
    /// The authenticated user's fixed LPAC profile could not be proven.
    #[error("service probe target LPAC is unavailable")]
    TargetLpac,
    /// The exact unnamed one-process Job policy could not be proven.
    #[error("service probe Job is unavailable")]
    Job,
    /// The exact five-slot extended startup owner could not be prepared.
    #[error("service probe startup state is unavailable")]
    Startup,
    /// The authenticated desktop-client proof changed or was already consumed.
    #[error("service probe desktop authentication is unavailable")]
    Authentication,
    /// Windows rejected the single fixed process-creation call.
    #[error("service probe process creation is unavailable")]
    Creation,
    /// A created process, thread, token, descriptor, or Job fact was not exact.
    #[error("service probe created-process verification failed")]
    Verification,
    /// Exact post-debugger-exit process or Job cleanup could not be proven.
    #[error("service probe cleanup failed")]
    Cleanup,
    /// A later debug phase explicitly abandoned the still-suspended probe.
    #[error("service probe was aborted")]
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ServiceProbeRole {
    Approval,
    SecretInput,
}

/// Complete one-shot creation inputs for one fixed helper role.
#[must_use = "prepared service probe inputs contain one-shot launch authority"]
pub(super) struct ServiceProbeCreateInputs<'client, 'proof, 'context> {
    client: &'client AuthenticatedRpcClient,
    context: &'context RestrictedProcessContext,
    helper: VerifiedHelper,
    application_name: Box<[u16]>,
    service_security: PreparedServiceKeyAgentCreationSecurity<'proof>,
    target: PreparedTargetUserLpac<'client>,
    job: ServiceProbeJob,
    role: ServiceProbeRole,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl<'client, 'proof, 'context> ServiceProbeCreateInputs<'client, 'proof, 'context> {
    /// Prepares the exact Approval helper composition without creating a child.
    pub(super) fn prepare_approval(
        client: &'client AuthenticatedRpcClient,
        service_token: VerifiedServiceCreationToken<'proof>,
        helper: VerifiedHelper,
        context: &'context RestrictedProcessContext,
    ) -> Result<Self, ServiceProbeCreateError> {
        if !helper.is_approval_frontend() {
            return Err(ServiceProbeCreateError::Helper);
        }
        let application_name = wide_nul_absolute_path(helper.path())?;
        context
            .recheck_thread()
            .map_err(|_| ServiceProbeCreateError::ProcessContext)?;
        let service_security = PreparedServiceKeyAgentCreationSecurity::prepare(service_token)
            .map_err(|_| ServiceProbeCreateError::ServiceSecurity)?;
        let target = PreparedTargetUserLpac::prepare_approval(client, context)
            .map_err(|_| ServiceProbeCreateError::TargetLpac)?;
        let job = ServiceProbeJob::create_non_nested().map_err(|_| ServiceProbeCreateError::Job)?;
        let prepared = Self {
            client,
            context,
            helper,
            application_name,
            service_security,
            target,
            job,
            role: ServiceProbeRole::Approval,
            _thread_bound: PhantomData,
        };
        prepared.verify_helper_binding()?;
        Ok(prepared)
    }

    /// Prepares the exact Secret Input helper composition without creating a child.
    pub(super) fn prepare_secret_input(
        client: &'client AuthenticatedRpcClient,
        service_token: VerifiedServiceCreationToken<'proof>,
        helper: VerifiedHelper,
        context: &'context RestrictedProcessContext,
    ) -> Result<Self, ServiceProbeCreateError> {
        if !helper.is_secret_input_frontend() {
            return Err(ServiceProbeCreateError::Helper);
        }
        let application_name = wide_nul_absolute_path(helper.path())?;
        context
            .recheck_thread()
            .map_err(|_| ServiceProbeCreateError::ProcessContext)?;
        let service_security = PreparedServiceKeyAgentCreationSecurity::prepare(service_token)
            .map_err(|_| ServiceProbeCreateError::ServiceSecurity)?;
        let target = PreparedTargetUserLpac::prepare_secret_input(client, context)
            .map_err(|_| ServiceProbeCreateError::TargetLpac)?;
        let job = ServiceProbeJob::create_non_nested().map_err(|_| ServiceProbeCreateError::Job)?;
        let prepared = Self {
            client,
            context,
            helper,
            application_name,
            service_security,
            target,
            job,
            role: ServiceProbeRole::SecretInput,
            _thread_bound: PhantomData,
        };
        prepared.verify_helper_binding()?;
        Ok(prepared)
    }

    /// Consumes the one-shot authority and creates a still-suspended,
    /// debug-attached helper on the current dedicated debugger thread.
    pub(super) fn create_suspended(
        mut self,
        debugger_thread: FreshDebuggerThread,
    ) -> Result<SuspendedServiceProbe<'client, 'proof, 'context>, PendingServiceProbeCleanup> {
        let debug_event_cleanup = Arc::clone(&debugger_thread.debug_event_cleanup);
        let creator_thread_id = match debugger_thread.require_current() {
            Ok(thread_id) => thread_id,
            Err(failure) => {
                return Err(self.into_pending_cleanup(
                    None,
                    failure,
                    debugger_thread.thread_id,
                    debug_event_cleanup,
                ));
            }
        };
        if let Err(failure) = self.verify_pre_create() {
            return Err(self.into_pending_cleanup(
                None,
                failure,
                creator_thread_id,
                debug_event_cleanup,
            ));
        }

        let created = match self.create_native_suspended() {
            Ok(created) => created,
            Err(failure) => {
                return Err(self.into_pending_cleanup(
                    None,
                    failure,
                    creator_thread_id,
                    debug_event_cleanup,
                ));
            }
        };

        let verification = {
            let mut operations = WindowsPostCreateVerification {
                client: self.client,
                context: self.context,
                helper: &self.helper,
                role: self.role,
                application_name: &self.application_name,
                service_security: &mut self.service_security,
                target: &self.target,
                job: &self.job,
                created: &created,
            };
            verify_initial_post_create(&mut operations)
        };
        let target_proof = match verification {
            Ok(proof) => proof,
            Err(failure) => {
                let process = created.request_termination_into_pending_debugger_exit_cleanup();
                return Err(self.into_pending_cleanup(
                    Some(process),
                    failure,
                    creator_thread_id,
                    debug_event_cleanup,
                ));
            }
        };

        let Self {
            client,
            context,
            helper,
            application_name,
            service_security,
            target,
            job,
            role,
            _thread_bound: _,
        } = self;
        Ok(SuspendedServiceProbe {
            debugger_thread,
            created,
            target_proof,
            job,
            helper,
            application_name,
            service_security,
            target,
            client,
            context,
            role,
            _thread_bound: PhantomData,
        })
    }

    fn create_native_suspended(
        &mut self,
    ) -> Result<CreatedDesktopProcess, ServiceProbeCreateError> {
        let startup = ServiceProbeStartup::prepare(&self.job, &self.target)
            .map_err(|_| ServiceProbeCreateError::Startup)?;
        startup
            .revalidate(self.context)
            .map_err(|_| ServiceProbeCreateError::Startup)?;
        let attempt = self
            .client
            .claim_desktop_process_creation()
            .map_err(|_| ServiceProbeCreateError::Authentication)?;
        let creation_security = self
            .service_security
            .creation_security_for_attempt()
            .map_err(|_| ServiceProbeCreateError::ServiceSecurity)?;
        let view = startup.process_creation_view();
        // SAFETY: `view` is the lifetime-bound prefix of this live `startup`
        // allocation. The paired descriptors, exact environment, application,
        // and current-directory slices all remain borrowed through the single
        // synchronous native call, and neither raw pointer is retained.
        let created = unsafe {
            attempt.create_suspended_process(
                &self.application_name,
                creation_security,
                self.target.environment(),
                self.context.current_directory(),
                view.as_raw(),
            )
        };
        drop(view);
        drop(startup);
        created.map_err(|_| ServiceProbeCreateError::Creation)
    }

    fn verify_pre_create(&mut self) -> Result<(), ServiceProbeCreateError> {
        self.verify_helper_binding()?;
        self.context
            .recheck_thread()
            .map_err(|_| ServiceProbeCreateError::ProcessContext)?;
        self.service_security
            .revalidate()
            .map_err(|_| ServiceProbeCreateError::ServiceSecurity)?;
        self.target
            .revalidate(self.context)
            .map_err(|_| ServiceProbeCreateError::TargetLpac)?;
        self.job
            .recheck_non_nested()
            .map_err(|_| ServiceProbeCreateError::Job)?;
        self.client
            .revalidate()
            .map_err(|_| ServiceProbeCreateError::Authentication)
    }

    fn verify_helper_binding(&self) -> Result<(), ServiceProbeCreateError> {
        let role_matches = match self.role {
            ServiceProbeRole::Approval => self.helper.is_approval_frontend(),
            ServiceProbeRole::SecretInput => self.helper.is_secret_input_frontend(),
        };
        if !role_matches
            || wide_nul_absolute_path(self.helper.path())?.as_ref()
                != self.application_name.as_ref()
        {
            return Err(ServiceProbeCreateError::Helper);
        }
        Ok(())
    }

    fn into_pending_cleanup(
        self,
        process: Option<PendingDebuggerExitProcessCleanup>,
        failure: ServiceProbeCreateError,
        creator_thread_id: ThreadId,
        debug_event_cleanup: Arc<ServiceProbeDebugEventCleanup>,
    ) -> PendingServiceProbeCleanup {
        let Self { mut job, .. } = self;
        let job_request_failed = job.request_termination().is_err();
        PendingServiceProbeCleanup {
            process,
            job,
            failure,
            job_request_failed,
            process_cleanup_failed: false,
            worker_cleanup_failed: false,
            creator_thread_id,
            debug_event_cleanup,
        }
    }
}

impl fmt::Debug for ServiceProbeCreateInputs<'_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceProbeCreateInputs([REDACTED])")
    }
}

/// Verified pre-event process state that remains on its creator/debugger thread.
#[must_use = "the suspended debuggee must enter the event gate or explicit cleanup"]
pub(super) struct SuspendedServiceProbe<'client, 'proof, 'context> {
    debugger_thread: FreshDebuggerThread,
    created: CreatedDesktopProcess,
    target_proof: VerifiedCreatedTargetLpac<'client>,
    job: ServiceProbeJob,
    helper: VerifiedHelper,
    application_name: Box<[u16]>,
    service_security: PreparedServiceKeyAgentCreationSecurity<'proof>,
    target: PreparedTargetUserLpac<'client>,
    client: &'client AuthenticatedRpcClient,
    context: &'context RestrictedProcessContext,
    role: ServiceProbeRole,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl SuspendedServiceProbe<'_, '_, '_> {
    pub(super) fn process_handle(&self) -> BorrowedHandle<'_> {
        self.created.process_handle()
    }

    pub(super) fn primary_thread_handle(&self) -> BorrowedHandle<'_> {
        self.created.primary_thread_handle()
    }

    pub(super) const fn process_id(&self) -> NonZeroU32 {
        self.created.process_id()
    }

    pub(super) const fn primary_thread_id(&self) -> NonZeroU32 {
        self.created.primary_thread_id()
    }

    pub(super) const fn role(&self) -> ServiceProbeRole {
        self.role
    }

    pub(super) fn helper(&self) -> &VerifiedHelper {
        &self.helper
    }

    pub(super) fn debug_event_cleanup(&self) -> &Arc<ServiceProbeDebugEventCleanup> {
        &self.debugger_thread.debug_event_cleanup
    }

    pub(super) fn system_directory(&self) -> &[u16] {
        self.context.current_directory()
    }

    /// Repeats every object-bound proof without changing ownership while a
    /// debug event or explicit suspend count holds the primary thread.
    pub(super) fn revalidate_held(&mut self) -> Result<(), ServiceProbeCreateError> {
        self.debugger_thread.require_current()?;
        let verification = {
            let mut operations = WindowsPostCreateVerification {
                client: self.client,
                context: self.context,
                helper: &self.helper,
                role: self.role,
                application_name: &self.application_name,
                service_security: &mut self.service_security,
                target: &self.target,
                job: &self.job,
                created: &self.created,
            };
            revalidate_held_post_create(&mut operations)
        }?;
        let retained = self.target.revalidate_created_process(
            &self.target_proof,
            self.created.process_handle(),
            self.context,
        );
        drop(verification);
        retained.map_err(|_| ServiceProbeCreateError::Verification)?;
        Ok(())
    }

    /// Repeats every object-bound proof before a future debug event or handle
    /// injection transition.
    pub(super) fn revalidate(mut self) -> Result<Self, PendingServiceProbeCleanup> {
        if let Err(failure) = self.revalidate_held() {
            return Err(self.into_pending_cleanup(failure));
        }
        Ok(self)
    }

    /// Prepares every ownership move needed after successful no-kill arming.
    /// This must be called only after the second event was continued and all
    /// live object proofs were revalidated on this exact debugger thread.
    pub(super) fn prepare_pending_debugger_exit_success(
        mut self,
    ) -> Result<PreparedServiceProbeDetach, PendingServiceProbeCleanup> {
        if let Err(failure) = self.revalidate_held() {
            return Err(self.into_pending_cleanup(failure));
        }
        let Self {
            debugger_thread,
            created,
            target_proof,
            mut job,
            helper,
            application_name,
            service_security,
            target,
            client: _,
            context: _,
            role,
            _thread_bound: _,
        } = self;
        let creator_thread_id = debugger_thread.thread_id;
        let debug_event_cleanup = Arc::clone(&debugger_thread.debug_event_cleanup);
        let Ok(expected_target) = target_proof.into_expected_service_created() else {
            let process = created.request_termination_into_pending_debugger_exit_cleanup();
            let job_request_failed = job.request_termination().is_err();
            drop(helper);
            drop(application_name);
            drop(service_security);
            drop(target);
            return Err(PendingServiceProbeCleanup {
                process: Some(process),
                job,
                failure: ServiceProbeCreateError::Verification,
                job_request_failed,
                process_cleanup_failed: false,
                worker_cleanup_failed: false,
                creator_thread_id,
                debug_event_cleanup,
            });
        };
        let process = created.prepare_pending_debugger_exit_success();
        drop(application_name);
        drop(service_security);
        drop(target);
        Ok(PreparedServiceProbeDetach {
            process,
            job,
            expected_target,
            helper,
            role,
            creator_thread_id,
            debug_event_cleanup,
            _thread_bound: PhantomData,
        })
    }

    /// Requests exact process and whole-Job termination without waiting. The
    /// returned owner may cross the debugger-thread join boundary.
    pub(super) fn abort_for_debugger_exit(self) -> PendingServiceProbeCleanup {
        self.into_pending_cleanup(ServiceProbeCreateError::Aborted)
    }

    fn into_pending_cleanup(self, failure: ServiceProbeCreateError) -> PendingServiceProbeCleanup {
        let Self {
            debugger_thread,
            created,
            target_proof,
            mut job,
            helper,
            application_name,
            service_security,
            target,
            client: _,
            context: _,
            role: _,
            _thread_bound: _,
        } = self;
        let creator_thread_id = debugger_thread.thread_id;
        let debug_event_cleanup = Arc::clone(&debugger_thread.debug_event_cleanup);
        let process = created.request_termination_into_pending_debugger_exit_cleanup();
        let job_request_failed = job.request_termination().is_err();
        drop(target_proof);
        drop(helper);
        drop(application_name);
        drop(service_security);
        drop(target);
        PendingServiceProbeCleanup {
            process: Some(process),
            job,
            failure,
            job_request_failed,
            process_cleanup_failed: false,
            worker_cleanup_failed: false,
            creator_thread_id,
            debug_event_cleanup,
        }
    }
}

/// Thread-bound process/Job handoff prepared before no-kill arming.
#[must_use = "the prepared service probe must commit or enter cleanup"]
pub(super) struct PreparedServiceProbeDetach {
    process: PreparedDebuggerExitProcessSuccess,
    job: ServiceProbeJob,
    expected_target: ExpectedServiceCreatedLpac,
    helper: VerifiedHelper,
    role: ServiceProbeRole,
    creator_thread_id: ThreadId,
    debug_event_cleanup: Arc<ServiceProbeDebugEventCleanup>,
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl PreparedServiceProbeDetach {
    /// Commits only infallible phase and ownership moves after the successful
    /// `DebugSetProcessKillOnExit(FALSE)` call.
    pub(super) fn commit_after_no_kill(self) -> PendingServiceProbeDetach {
        let Self {
            process,
            job,
            expected_target,
            helper,
            role,
            creator_thread_id,
            debug_event_cleanup,
            _thread_bound: _,
        } = self;
        PendingServiceProbeDetach {
            process: process.commit_after_no_kill(),
            job,
            expected_target,
            helper,
            role,
            creator_thread_id,
            debug_event_cleanup,
            _not_sync: PhantomData,
        }
    }

    /// Requests process and whole-Job termination when no-kill arming fails.
    pub(super) fn abort_after_no_kill_failure(self) -> PendingServiceProbeCleanup {
        let Self {
            process,
            mut job,
            expected_target,
            helper,
            role: _,
            creator_thread_id,
            debug_event_cleanup,
            _thread_bound: _,
        } = self;
        let process = process.abort_into_pending_cleanup();
        let job_request_failed = job.request_termination().is_err();
        drop(expected_target);
        drop(helper);
        PendingServiceProbeCleanup {
            process: Some(process),
            job,
            failure: ServiceProbeCreateError::Aborted,
            job_request_failed,
            process_cleanup_failed: false,
            worker_cleanup_failed: false,
            creator_thread_id,
            debug_event_cleanup,
        }
    }
}

impl fmt::Debug for PreparedServiceProbeDetach {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedServiceProbeDetach([REDACTED])")
    }
}

/// Sendable, non-shareable service probe awaiting exact debugger-thread join.
///
/// Neither process nor thread handle is exposed in this state.
#[must_use = "consume the exact debugger-thread join proof"]
pub(super) struct PendingServiceProbeDetach {
    process: PendingDebuggerExitProcessSuccess,
    job: ServiceProbeJob,
    expected_target: ExpectedServiceCreatedLpac,
    helper: VerifiedHelper,
    role: ServiceProbeRole,
    creator_thread_id: ThreadId,
    debug_event_cleanup: Arc<ServiceProbeDebugEventCleanup>,
    _not_sync: PhantomData<Cell<()>>,
}

impl PendingServiceProbeDetach {
    /// Consumes the exact join proof, proves debugger absence before adopting
    /// event aliases, and verifies the still-suspended detached kernel state.
    pub(super) fn finish_after_debugger_exit(
        self,
        proof: DebuggerThreadExitProof,
    ) -> Result<DetachedSuspendedServiceProbe, ServiceProbeCreateError> {
        let Self {
            process,
            mut job,
            expected_target,
            helper,
            role,
            creator_thread_id,
            debug_event_cleanup,
            _not_sync: _,
        } = self;
        let process = process.finish_after_debugger_exit();
        if !debug_event_cleanup.debugger_thread_has_joined()
            || !debugger_exit_matches(creator_thread_id, &debug_event_cleanup, &proof)
        {
            drop(proof);
            return Err(fail_detached_service_probe(
                &process,
                &mut job,
                &debug_event_cleanup,
                ServiceProbeCreateError::Cleanup,
            ));
        }
        drop(proof);

        if let Err(error) = verify_debugger_absent(&process) {
            return Err(fail_detached_service_probe(
                &process,
                &mut job,
                &debug_event_cleanup,
                error,
            ));
        }
        if debug_event_cleanup
            .authorize_after_debugger_absence(
                process.process_id().get(),
                process.primary_thread_id().get(),
            )
            .and_then(|()| {
                close_debug_event_aliases(
                    debug_event_cleanup.as_ref(),
                    process.process_handle(),
                    process.primary_thread_handle(),
                )
            })
            .is_err()
        {
            return Err(fail_detached_service_probe(
                &process,
                &mut job,
                &debug_event_cleanup,
                ServiceProbeCreateError::Cleanup,
            ));
        }
        if let Err(error) = verify_detached_suspended_process(&process, &job) {
            return Err(fail_detached_service_probe(
                &process,
                &mut job,
                &debug_event_cleanup,
                error,
            ));
        }
        Ok(DetachedSuspendedServiceProbe {
            process,
            job,
            expected_target,
            helper,
            role,
            resumed: false,
            _not_sync: PhantomData,
        })
    }
}

impl fmt::Debug for PendingServiceProbeDetach {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingServiceProbeDetach([REDACTED])")
    }
}

/// Post-join detached process/Job owner with exactly one explicit suspend count.
///
#[must_use = "the detached suspended service probe remains process-terminal"]
pub(super) struct DetachedSuspendedServiceProbe {
    process: DetachedDesktopProcess,
    job: ServiceProbeJob,
    expected_target: ExpectedServiceCreatedLpac,
    helper: VerifiedHelper,
    role: ServiceProbeRole,
    resumed: bool,
    _not_sync: PhantomData<Cell<()>>,
}

impl DetachedSuspendedServiceProbe {
    pub(super) const fn role(&self) -> ServiceProbeRole {
        self.role
    }

    pub(super) fn revalidate_suspended(&self) -> Result<(), ServiceProbeCreateError> {
        if self.resumed {
            return Err(ServiceProbeCreateError::Verification);
        }
        verify_detached_suspended_process(&self.process, &self.job)?;
        self.revalidate_identity_and_role()
    }

    pub(super) fn resume_once(&mut self) -> Result<(), ServiceProbeCreateError> {
        if self.resumed {
            return Err(ServiceProbeCreateError::Verification);
        }
        // SAFETY: the joined-debugger proof retained exactly one explicit
        // suspend count on this exact primary thread. The returned previous
        // count must therefore be exactly one for the sole resume transition.
        let previous =
            unsafe { ResumeThread(windows_handle(self.process.primary_thread_handle())) };
        if previous != 1 {
            return Err(ServiceProbeCreateError::Verification);
        }
        self.resumed = true;
        Ok(())
    }

    pub(super) fn revalidate_running(&self) -> Result<(), ServiceProbeCreateError> {
        if !self.resumed {
            return Err(ServiceProbeCreateError::Verification);
        }
        verify_detached_running_process(&self.process, &self.job)?;
        self.revalidate_identity_and_role()
    }

    pub(super) fn process_handle(&self) -> BorrowedHandle<'_> {
        self.process.process_handle()
    }

    pub(super) fn terminate_and_reap(&mut self) -> Result<(), ServiceProbeCreateError> {
        let mut operations = WindowsDetachedTermination {
            process: &self.process,
            job: &mut self.job,
        };
        terminate_and_reap_detached(&mut operations)
    }

    fn revalidate_identity_and_role(&self) -> Result<(), ServiceProbeCreateError> {
        self.expected_target
            .revalidate_for_process(self.process.process_handle())
            .map_err(|_| ServiceProbeCreateError::Verification)?;
        let exact_role = match self.role {
            ServiceProbeRole::Approval => {
                self.helper.is_approval_frontend() && self.expected_target.is_approval()
            }
            ServiceProbeRole::SecretInput => {
                self.helper.is_secret_input_frontend() && self.expected_target.is_secret_input()
            }
        };
        exact_role
            .then_some(())
            .ok_or(ServiceProbeCreateError::Verification)
    }
}

impl fmt::Debug for DetachedSuspendedServiceProbe {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DetachedSuspendedServiceProbe([REDACTED])")
    }
}

fn verify_detached_suspended_process(
    process: &DetachedDesktopProcess,
    job: &ServiceProbeJob,
) -> Result<(), ServiceProbeCreateError> {
    let _ = (process.process_id(), process.primary_thread_id());
    // SAFETY: the exact creator process handle remains live after the debugger
    // thread joined; a zero wait observes only liveness.
    if unsafe { WaitForSingleObject(windows_handle(process.process_handle()), 0) } != WAIT_TIMEOUT {
        return Err(ServiceProbeCreateError::Cleanup);
    }
    if !job
        .contains_process(process.process_handle())
        .map_err(|_| ServiceProbeCreateError::Cleanup)?
        || job
            .active_process_count()
            .map_err(|_| ServiceProbeCreateError::Cleanup)?
            != 1
    {
        return Err(ServiceProbeCreateError::Cleanup);
    }
    // SAFETY: gate 2 installed exactly one suspend count before continuing its
    // event. The joined debugger no longer contributes a debug-event stop.
    let previous = unsafe { SuspendThread(windows_handle(process.primary_thread_handle())) };
    if previous != 1 {
        return Err(ServiceProbeCreateError::Cleanup);
    }
    // SAFETY: the immediately preceding successful SuspendThread established
    // count two on this exact primary thread. This restores the retained one.
    let resumed = unsafe { ResumeThread(windows_handle(process.primary_thread_handle())) };
    if resumed != 2 {
        return Err(ServiceProbeCreateError::Cleanup);
    }
    Ok(())
}

fn verify_detached_running_process(
    process: &DetachedDesktopProcess,
    job: &ServiceProbeJob,
) -> Result<(), ServiceProbeCreateError> {
    // SAFETY: the exact process handle owns synchronize access; a zero wait is
    // only a liveness observation.
    if unsafe { WaitForSingleObject(windows_handle(process.process_handle()), 0) } != WAIT_TIMEOUT {
        return Err(ServiceProbeCreateError::Cleanup);
    }
    if !job
        .contains_process(process.process_handle())
        .map_err(|_| ServiceProbeCreateError::Cleanup)?
        || job
            .active_process_count()
            .map_err(|_| ServiceProbeCreateError::Cleanup)?
            != 1
    {
        return Err(ServiceProbeCreateError::Cleanup);
    }
    Ok(())
}

fn verify_debugger_absent(process: &DetachedDesktopProcess) -> Result<(), ServiceProbeCreateError> {
    // SAFETY: the exact creator process handle remains live after the debugger
    // thread joined; a zero wait observes only liveness.
    if unsafe { WaitForSingleObject(windows_handle(process.process_handle()), 0) } != WAIT_TIMEOUT {
        return Err(ServiceProbeCreateError::Cleanup);
    }
    let mut debugger_present = BOOL::default();
    // SAFETY: the process handle and writable BOOL remain live for this query.
    unsafe {
        CheckRemoteDebuggerPresent(
            windows_handle(process.process_handle()),
            &raw mut debugger_present,
        )
    }
    .map_err(|_| ServiceProbeCreateError::Cleanup)?;
    if debugger_present.as_bool() {
        Err(ServiceProbeCreateError::Cleanup)
    } else {
        Ok(())
    }
}

trait DetachedTerminationOps {
    fn request_job_termination(&mut self) -> bool;
    fn request_process_termination(&mut self) -> bool;
    fn wait_for_process_exit(&mut self) -> bool;
    fn wait_for_empty_job(&mut self) -> bool;
    fn fail_fast_with_owners(&mut self) -> !;
}

/// Attempts both termination requests before either bounded terminal proof.
/// Success means both requests succeeded, the exact process exited, and the
/// one-process Job reached exact zero. A missing terminal proof cannot return:
/// the concrete owner remains live through the process-wide fail-fast boundary.
fn terminate_and_reap_detached<O: DetachedTerminationOps>(
    operations: &mut O,
) -> Result<(), ServiceProbeCreateError> {
    let job_request = operations.request_job_termination();
    let process_request = operations.request_process_termination();
    let process_terminal = operations.wait_for_process_exit();
    let job_terminal = operations.wait_for_empty_job();
    if !process_terminal || !job_terminal {
        operations.fail_fast_with_owners();
    }
    if job_request && process_request {
        Ok(())
    } else {
        Err(ServiceProbeCreateError::Cleanup)
    }
}

struct WindowsDetachedTermination<'process, 'job> {
    process: &'process DetachedDesktopProcess,
    job: &'job mut ServiceProbeJob,
}

impl DetachedTerminationOps for WindowsDetachedTermination<'_, '_> {
    fn request_job_termination(&mut self) -> bool {
        self.job.request_termination().is_ok()
    }

    fn request_process_termination(&mut self) -> bool {
        self.process.request_termination_for_cleanup().is_ok()
    }

    fn wait_for_process_exit(&mut self) -> bool {
        self.process.wait_for_exit_for_cleanup().is_ok()
    }

    fn wait_for_empty_job(&mut self) -> bool {
        self.job.finish_termination_and_wait().is_ok()
    }

    fn fail_fast_with_owners(&mut self) -> ! {
        std::process::abort()
    }
}

fn fail_detached_service_probe(
    process: &DetachedDesktopProcess,
    job: &mut ServiceProbeJob,
    debug_event_cleanup: &ServiceProbeDebugEventCleanup,
    original: ServiceProbeCreateError,
) -> ServiceProbeCreateError {
    // Both kill requests are attempted before either bounded terminal proof.
    // A failed request remains an error even when later observations prove the
    // process and one-process Job empty.
    let job_request = job.request_termination();
    let process_request = process.request_termination_for_cleanup();
    let process_wait = process.wait_for_exit_for_cleanup();
    let job_wait = job.finish_termination_and_wait();
    let terminal = process_wait.is_ok() && job_wait.is_ok();
    if !terminal {
        // No recoverable return may close the creator anchors while registered
        // event authority remains. Process-wide exit reclaims the handle table.
        std::process::abort();
    }
    let alias_cleanup = debug_event_cleanup
        .authorize_after_process_terminal()
        .and_then(|()| {
            close_debug_event_aliases(
                debug_event_cleanup,
                process.process_handle(),
                process.primary_thread_handle(),
            )
        });
    if alias_cleanup.is_err() {
        // Preserve the exact creator objects through the fail-fast boundary;
        // closing them would make a residual primary alias unrecoverable.
        std::process::abort();
    }
    if job_request.is_err()
        || process_request.is_err()
        || process_wait.is_err()
        || job_wait.is_err()
    {
        ServiceProbeCreateError::Cleanup
    } else {
        original
    }
}

fn close_debug_event_aliases(
    cleanup: &ServiceProbeDebugEventCleanup,
    process: BorrowedHandle<'_>,
    primary_thread: BorrowedHandle<'_>,
) -> Result<(), super::debug_gate::ServiceProbeDebugGateError> {
    let first = cleanup.close_after_join(process, primary_thread);
    if first.is_ok() {
        first
    } else {
        // The registry clears each word only after a successful checked close.
        // One bounded retry therefore reauthenticates every remaining alias
        // against the still-live creator handles without risking double-close.
        cleanup.close_after_join(process, primary_thread)
    }
}

fn windows_handle(handle: BorrowedHandle<'_>) -> windows::Win32::Foundation::HANDLE {
    use std::os::windows::io::AsRawHandle as _;
    windows::Win32::Foundation::HANDLE(handle.as_raw_handle())
}

impl fmt::Debug for SuspendedServiceProbe<'_, '_, '_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SuspendedServiceProbe([REDACTED])")
    }
}

/// Sendable cleanup authority that is valid only after the debugger thread exits.
#[must_use = "join the debugger thread, then finish process and Job cleanup"]
pub(super) struct PendingServiceProbeCleanup {
    process: Option<PendingDebuggerExitProcessCleanup>,
    job: ServiceProbeJob,
    failure: ServiceProbeCreateError,
    job_request_failed: bool,
    process_cleanup_failed: bool,
    worker_cleanup_failed: bool,
    creator_thread_id: ThreadId,
    debug_event_cleanup: Arc<ServiceProbeDebugEventCleanup>,
}

impl PendingServiceProbeCleanup {
    pub(super) const fn failure(&self) -> ServiceProbeCreateError {
        self.failure
    }

    /// Latches an independent checked cleanup failure on the debugger worker.
    pub(super) fn note_worker_cleanup_failure(&mut self) {
        self.worker_cleanup_failed = true;
    }

    /// Completes exact process reap and Job-empty proof after the debugger
    /// thread has exited and its join has succeeded.
    pub(super) fn finish_after_debugger_exit(
        &mut self,
        proof: &DebuggerThreadExitProof,
    ) -> Result<ServiceProbeCreateError, ServiceProbeCreateError> {
        let proof_matches = self.debug_event_cleanup.debugger_thread_has_joined()
            && debugger_exit_matches(self.creator_thread_id, &self.debug_event_cleanup, proof);
        if !proof_matches {
            // The exact join proof is unforgeable in normal control flow. Do
            // not touch or outlive residual event authority on substitution.
            std::process::abort();
        }
        // Whole-Job emptiness is a prerequisite for partial-prefix cleanup when
        // no-kill was never armed. It is not sufficient by itself: exact
        // creator/canonical identity checks still precede every alias close.
        let job_result = self.job.finish_termination_and_wait();
        if job_result.is_err() {
            std::process::abort();
        }
        let event_alias_result = match self.process.as_ref() {
            Some(process) => self
                .debug_event_cleanup
                .authorize_after_process_terminal()
                .and_then(|()| {
                    close_debug_event_aliases(
                        &self.debug_event_cleanup,
                        process.process_handle(),
                        process.primary_thread_handle(),
                    )
                }),
            None => self.debug_event_cleanup.require_empty_after_join(),
        };
        if event_alias_result.is_err() {
            // Keep creator handles live when checked alias cleanup cannot clear
            // the registry. The last-owner guard is a second line of defense.
            std::process::abort();
        }
        let process_result = match self.process.take() {
            Some(process) => process.wait_and_close(),
            None => Ok(()),
        };
        self.process_cleanup_failed |= process_result.is_err();
        if self.job_request_failed || self.process_cleanup_failed || self.worker_cleanup_failed {
            return Err(ServiceProbeCreateError::Cleanup);
        }
        Ok(self.failure)
    }
}

impl fmt::Debug for PendingServiceProbeCleanup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingServiceProbeCleanup([REDACTED])")
    }
}

trait PostCreateVerificationOps {
    type TargetProof;

    fn revalidate_client(&mut self) -> Result<(), ServiceProbeCreateError>;
    fn verify_helper(&mut self) -> Result<(), ServiceProbeCreateError>;
    fn verify_service_objects(&mut self) -> Result<(), ServiceProbeCreateError>;
    fn verify_desktop_dup_handle_denial(&mut self) -> Result<(), ServiceProbeCreateError>;
    fn revalidate_service(&mut self) -> Result<(), ServiceProbeCreateError>;
    fn verify_target(&mut self) -> Result<Self::TargetProof, ServiceProbeCreateError>;
    fn verify_job(&mut self) -> Result<(), ServiceProbeCreateError>;
    fn revalidate_context(&mut self) -> Result<(), ServiceProbeCreateError>;
    fn revalidate_target(
        &mut self,
        proof: &Self::TargetProof,
    ) -> Result<(), ServiceProbeCreateError>;
}

/// Performs the creation-only verification sequence. The desktop access denial
/// is a one-shot authenticated-client claim and must not be repeated later.
fn verify_initial_post_create<O: PostCreateVerificationOps>(
    operations: &mut O,
) -> Result<O::TargetProof, ServiceProbeCreateError> {
    operations.revalidate_client()?;
    operations.verify_helper()?;
    operations.verify_service_objects()?;
    operations.verify_desktop_dup_handle_denial()?;
    verify_post_create_tail(operations)
}

/// Repeats only object-bound proofs while the process remains held. The
/// creation-only desktop access denial has already been consumed and proven.
fn revalidate_held_post_create<O: PostCreateVerificationOps>(
    operations: &mut O,
) -> Result<O::TargetProof, ServiceProbeCreateError> {
    operations.revalidate_client()?;
    operations.verify_helper()?;
    operations.verify_service_objects()?;
    verify_post_create_tail(operations)
}

fn verify_post_create_tail<O: PostCreateVerificationOps>(
    operations: &mut O,
) -> Result<O::TargetProof, ServiceProbeCreateError> {
    operations.revalidate_service()?;
    let proof = operations.verify_target()?;
    operations.verify_job()?;
    operations.revalidate_context()?;
    operations.revalidate_target(&proof)?;
    operations.revalidate_service()?;
    operations.revalidate_client()?;
    Ok(proof)
}

struct WindowsPostCreateVerification<'state, 'client, 'proof, 'context> {
    client: &'client AuthenticatedRpcClient,
    context: &'context RestrictedProcessContext,
    helper: &'state VerifiedHelper,
    role: ServiceProbeRole,
    application_name: &'state [u16],
    service_security: &'state mut PreparedServiceKeyAgentCreationSecurity<'proof>,
    target: &'state PreparedTargetUserLpac<'client>,
    job: &'state ServiceProbeJob,
    created: &'state CreatedDesktopProcess,
}

impl<'client> PostCreateVerificationOps for WindowsPostCreateVerification<'_, 'client, '_, '_> {
    type TargetProof = VerifiedCreatedTargetLpac<'client>;

    fn revalidate_client(&mut self) -> Result<(), ServiceProbeCreateError> {
        self.client
            .revalidate()
            .map_err(|_| ServiceProbeCreateError::Authentication)
    }

    fn verify_helper(&mut self) -> Result<(), ServiceProbeCreateError> {
        let role_matches = match self.role {
            ServiceProbeRole::Approval => self.helper.is_approval_frontend(),
            ServiceProbeRole::SecretInput => self.helper.is_secret_input_frontend(),
        };
        if !role_matches
            || wide_nul_absolute_path(self.helper.path())?.as_ref() != self.application_name
        {
            return Err(ServiceProbeCreateError::Helper);
        }
        Ok(())
    }

    fn verify_service_objects(&mut self) -> Result<(), ServiceProbeCreateError> {
        self.service_security
            .verify_created_objects(
                self.created.process_handle(),
                self.created.primary_thread_handle(),
            )
            .map_err(|_| ServiceProbeCreateError::Verification)
    }

    fn verify_desktop_dup_handle_denial(&mut self) -> Result<(), ServiceProbeCreateError> {
        self.client
            .require_desktop_process_dup_handle_denied(self.created.process_id())
            .map_err(|_| ServiceProbeCreateError::Verification)
    }

    fn revalidate_service(&mut self) -> Result<(), ServiceProbeCreateError> {
        self.service_security
            .revalidate()
            .map_err(|_| ServiceProbeCreateError::ServiceSecurity)
    }

    fn verify_target(&mut self) -> Result<Self::TargetProof, ServiceProbeCreateError> {
        self.target
            .verify_created_process(self.created.process_handle(), self.context)
            .map_err(|_| ServiceProbeCreateError::TargetLpac)
    }

    fn verify_job(&mut self) -> Result<(), ServiceProbeCreateError> {
        let contains = self
            .job
            .contains_process(self.created.process_handle())
            .map_err(|_| ServiceProbeCreateError::Job)?;
        let count = self
            .job
            .active_process_count()
            .map_err(|_| ServiceProbeCreateError::Job)?;
        if !contains || count != 1 {
            return Err(ServiceProbeCreateError::Verification);
        }
        Ok(())
    }

    fn revalidate_context(&mut self) -> Result<(), ServiceProbeCreateError> {
        self.context
            .recheck_thread()
            .map_err(|_| ServiceProbeCreateError::ProcessContext)
    }

    fn revalidate_target(
        &mut self,
        proof: &Self::TargetProof,
    ) -> Result<(), ServiceProbeCreateError> {
        self.target
            .revalidate_created_process(proof, self.created.process_handle(), self.context)
            .map_err(|_| ServiceProbeCreateError::TargetLpac)
    }
}

fn wide_nul_absolute_path(path: &Path) -> Result<Box<[u16]>, ServiceProbeCreateError> {
    if !path.is_absolute() {
        return Err(ServiceProbeCreateError::Helper);
    }
    let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
    if value.is_empty() || value.len() >= MAX_WIDE_PATH_UNITS || value.contains(&0) {
        return Err(ServiceProbeCreateError::Helper);
    }
    value.push(0);
    Ok(value.into_boxed_slice())
}

#[cfg(test)]
mod tests {
    use super::{
        DebuggerThreadExitProof, DetachedTerminationOps, FreshDebuggerThread,
        JoinedFreshDebuggerThread, PendingServiceProbeCleanup, PostCreateVerificationOps,
        ServiceProbeCreateError, SuspendedServiceProbe, debugger_exit_matches,
        revalidate_held_post_create, run_on_fresh_debugger_thread, terminate_and_reap_detached,
        verify_initial_post_create, wide_nul_absolute_path,
    };

    trait AmbiguousIfClone<A = Self> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<A = Self> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    trait AmbiguousIfSend<A = Self> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSend<()> for T {}
    impl<T: ?Sized + Send> AmbiguousIfSend<u8> for T {}

    trait AmbiguousIfSync<A = Self> {
        fn marker() {}
    }
    impl<T: ?Sized> AmbiguousIfSync<()> for T {}
    impl<T: ?Sized + Sync> AmbiguousIfSync<u8> for T {}

    fn require_send<T: Send>() {}

    struct FakePostCreate {
        events: Vec<&'static str>,
        failure_at: Option<usize>,
    }

    impl FakePostCreate {
        fn record(&mut self, event: &'static str) -> Result<(), ServiceProbeCreateError> {
            self.events.push(event);
            if self.failure_at == Some(self.events.len() - 1) {
                return Err(ServiceProbeCreateError::Verification);
            }
            Ok(())
        }
    }

    impl PostCreateVerificationOps for FakePostCreate {
        type TargetProof = ();

        fn revalidate_client(&mut self) -> Result<(), ServiceProbeCreateError> {
            self.record("client")
        }

        fn verify_helper(&mut self) -> Result<(), ServiceProbeCreateError> {
            self.record("helper")
        }

        fn verify_service_objects(&mut self) -> Result<(), ServiceProbeCreateError> {
            self.record("objects")
        }

        fn verify_desktop_dup_handle_denial(&mut self) -> Result<(), ServiceProbeCreateError> {
            self.record("desktop-dup-denied")
        }

        fn revalidate_service(&mut self) -> Result<(), ServiceProbeCreateError> {
            self.record("service")
        }

        fn verify_target(&mut self) -> Result<Self::TargetProof, ServiceProbeCreateError> {
            self.record("target")
        }

        fn verify_job(&mut self) -> Result<(), ServiceProbeCreateError> {
            self.record("job")
        }

        fn revalidate_context(&mut self) -> Result<(), ServiceProbeCreateError> {
            self.record("context")
        }

        fn revalidate_target(
            &mut self,
            (): &Self::TargetProof,
        ) -> Result<(), ServiceProbeCreateError> {
            self.record("target-fresh")
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum TerminationEvent {
        RequestJob,
        RequestProcess,
        WaitProcess,
        WaitJob,
        FailFast,
    }

    struct FakeDetachedTermination {
        events: Vec<TerminationEvent>,
        failure: Option<TerminationEvent>,
    }

    impl FakeDetachedTermination {
        fn outcome(&mut self, event: TerminationEvent) -> bool {
            self.events.push(event);
            self.failure != Some(event)
        }
    }

    impl DetachedTerminationOps for FakeDetachedTermination {
        fn request_job_termination(&mut self) -> bool {
            self.outcome(TerminationEvent::RequestJob)
        }

        fn request_process_termination(&mut self) -> bool {
            self.outcome(TerminationEvent::RequestProcess)
        }

        fn wait_for_process_exit(&mut self) -> bool {
            self.outcome(TerminationEvent::WaitProcess)
        }

        fn wait_for_empty_job(&mut self) -> bool {
            self.outcome(TerminationEvent::WaitJob)
        }

        #[allow(clippy::panic)]
        fn fail_fast_with_owners(&mut self) -> ! {
            self.events.push(TerminationEvent::FailFast);
            panic!("detached cleanup terminal proof missing")
        }
    }

    #[test]
    fn detached_termination_orders_both_requests_before_both_terminal_proofs() {
        const COMPLETE: [TerminationEvent; 4] = [
            TerminationEvent::RequestJob,
            TerminationEvent::RequestProcess,
            TerminationEvent::WaitProcess,
            TerminationEvent::WaitJob,
        ];

        let mut success = FakeDetachedTermination {
            events: Vec::new(),
            failure: None,
        };
        assert_eq!(terminate_and_reap_detached(&mut success), Ok(()));
        assert_eq!(success.events, COMPLETE);

        for failure in [
            TerminationEvent::RequestJob,
            TerminationEvent::RequestProcess,
        ] {
            let mut operations = FakeDetachedTermination {
                events: Vec::new(),
                failure: Some(failure),
            };
            assert_eq!(
                terminate_and_reap_detached(&mut operations),
                Err(ServiceProbeCreateError::Cleanup)
            );
            assert_eq!(operations.events, COMPLETE);
        }
    }

    #[test]
    fn detached_termination_fail_fast_keeps_owner_through_every_missing_terminal_proof() {
        for failure in [TerminationEvent::WaitProcess, TerminationEvent::WaitJob] {
            let mut operations = FakeDetachedTermination {
                events: Vec::new(),
                failure: Some(failure),
            };
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = terminate_and_reap_detached(&mut operations);
            }));
            assert!(outcome.is_err());
            assert_eq!(
                operations.events,
                [
                    TerminationEvent::RequestJob,
                    TerminationEvent::RequestProcess,
                    TerminationEvent::WaitProcess,
                    TerminationEvent::WaitJob,
                    TerminationEvent::FailFast,
                ]
            );
        }
    }

    #[test]
    fn initial_post_create_verification_is_exact_and_every_prefix_fails_closed() {
        const INITIAL_EVENTS: [&str; 11] = [
            "client",
            "helper",
            "objects",
            "desktop-dup-denied",
            "service",
            "target",
            "job",
            "context",
            "target-fresh",
            "service",
            "client",
        ];

        let mut success = FakePostCreate {
            events: Vec::new(),
            failure_at: None,
        };
        assert_eq!(verify_initial_post_create(&mut success), Ok(()));
        assert_eq!(success.events, INITIAL_EVENTS);

        for failure_at in 0..INITIAL_EVENTS.len() {
            let mut failure = FakePostCreate {
                events: Vec::new(),
                failure_at: Some(failure_at),
            };
            assert_eq!(
                verify_initial_post_create(&mut failure),
                Err(ServiceProbeCreateError::Verification)
            );
            assert_eq!(failure.events, INITIAL_EVENTS[..=failure_at]);
        }
    }

    #[test]
    fn held_post_create_revalidation_is_repeatable_without_reusing_denial_claim() {
        const HELD_EVENTS: [&str; 10] = [
            "client",
            "helper",
            "objects",
            "service",
            "target",
            "job",
            "context",
            "target-fresh",
            "service",
            "client",
        ];

        let mut repeated = FakePostCreate {
            events: Vec::new(),
            failure_at: None,
        };
        assert_eq!(revalidate_held_post_create(&mut repeated), Ok(()));
        assert_eq!(repeated.events, HELD_EVENTS);
        assert_eq!(revalidate_held_post_create(&mut repeated), Ok(()));
        assert_eq!(&repeated.events[HELD_EVENTS.len()..], HELD_EVENTS);

        for failure_at in 0..HELD_EVENTS.len() {
            let mut failure = FakePostCreate {
                events: Vec::new(),
                failure_at: Some(failure_at),
            };
            assert_eq!(
                revalidate_held_post_create(&mut failure),
                Err(ServiceProbeCreateError::Verification)
            );
            assert_eq!(failure.events, HELD_EVENTS[..=failure_at]);
        }
    }

    #[test]
    fn application_path_is_absolute_bounded_and_exactly_nul_terminated()
    -> Result<(), ServiceProbeCreateError> {
        let path = std::path::Path::new(r"C:\Program Files\Your Wallet\approval-ui.exe");
        let encoded = wide_nul_absolute_path(path)?;
        assert_eq!(encoded.last(), Some(&0));
        assert!(!encoded[..encoded.len() - 1].contains(&0));
        assert_eq!(
            wide_nul_absolute_path(std::path::Path::new("approval-ui.exe")),
            Err(ServiceProbeCreateError::Helper)
        );
        Ok(())
    }

    #[test]
    fn process_state_is_move_only_thread_bound_and_debug_is_data_free() {
        let _ = <FreshDebuggerThread as AmbiguousIfClone<_>>::marker;
        let _ = <FreshDebuggerThread as AmbiguousIfCopy<_>>::marker;
        let _ = <FreshDebuggerThread as AmbiguousIfSend<_>>::marker;
        let _ = <FreshDebuggerThread as AmbiguousIfSync<_>>::marker;
        let _ = <DebuggerThreadExitProof as AmbiguousIfClone<_>>::marker;
        let _ = <DebuggerThreadExitProof as AmbiguousIfCopy<_>>::marker;
        let _ = <DebuggerThreadExitProof as AmbiguousIfSend<_>>::marker;
        let _ = <DebuggerThreadExitProof as AmbiguousIfSync<_>>::marker;
        let _ = <JoinedFreshDebuggerThread<()> as AmbiguousIfClone<_>>::marker;
        let _ = <JoinedFreshDebuggerThread<()> as AmbiguousIfCopy<_>>::marker;
        let _ = <JoinedFreshDebuggerThread<()> as AmbiguousIfSend<_>>::marker;
        let _ = <JoinedFreshDebuggerThread<()> as AmbiguousIfSync<_>>::marker;
        let _ = <SuspendedServiceProbe<'static, 'static, 'static> as AmbiguousIfClone<_>>::marker;
        let _ = <SuspendedServiceProbe<'static, 'static, 'static> as AmbiguousIfCopy<_>>::marker;
        let _ = <SuspendedServiceProbe<'static, 'static, 'static> as AmbiguousIfSend<_>>::marker;
        let _ = <SuspendedServiceProbe<'static, 'static, 'static> as AmbiguousIfSync<_>>::marker;
        let _ = <PendingServiceProbeCleanup as AmbiguousIfClone<_>>::marker;
        let _ = <PendingServiceProbeCleanup as AmbiguousIfCopy<_>>::marker;
        let _ = <PendingServiceProbeCleanup as AmbiguousIfSync<_>>::marker;
        require_send::<PendingServiceProbeCleanup>();
        assert_eq!(
            format!("{}", ServiceProbeCreateError::Cleanup),
            "service probe cleanup failed"
        );
    }

    #[test]
    fn fresh_debugger_runner_mints_one_exact_post_join_proof()
    -> Result<(), super::FreshDebuggerThreadError> {
        let parent = std::thread::current().id();
        let first = run_on_fresh_debugger_thread(move |witness| {
            let current = std::thread::current().id();
            assert_ne!(current, parent);
            assert_eq!(witness.require_current(), Ok(current));
            (current, witness.cleanup_identity_for_test())
        })?;
        let ((first_thread, first_cleanup), first_proof) = first.into_parts();
        assert!(debugger_exit_matches(
            first_thread,
            &first_proof.debug_event_cleanup,
            &first_proof,
        ));
        assert_eq!(first_cleanup, first_proof.cleanup_identity_for_test());

        let second = run_on_fresh_debugger_thread(|witness| {
            let current = std::thread::current().id();
            assert_eq!(witness.require_current(), Ok(current));
            (current, witness.cleanup_identity_for_test())
        })?;
        let ((second_thread, second_cleanup), second_proof) = second.into_parts();
        assert!(debugger_exit_matches(
            second_thread,
            &second_proof.debug_event_cleanup,
            &second_proof,
        ));
        assert_eq!(second_cleanup, second_proof.cleanup_identity_for_test());
        assert!(!debugger_exit_matches(
            first_thread,
            &first_proof.debug_event_cleanup,
            &second_proof,
        ));
        assert!(!debugger_exit_matches(
            second_thread,
            &second_proof.debug_event_cleanup,
            &first_proof,
        ));
        assert!(!debugger_exit_matches(
            first_thread,
            &second_proof.debug_event_cleanup,
            &first_proof,
        ));
        Ok(())
    }

    #[test]
    #[allow(clippy::panic)]
    fn fresh_debugger_runner_returns_data_free_panic_only_for_empty_registry() {
        let result = run_on_fresh_debugger_thread::<(), _>(|_| panic!("inert worker panic"));
        assert_eq!(result.err(), Some(super::FreshDebuggerThreadError::Panic));
    }
}
