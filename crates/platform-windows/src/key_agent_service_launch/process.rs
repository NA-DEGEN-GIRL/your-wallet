//! One-shot, pre-event creation state for the service-owned LPAC helper probe.
//!
//! The caller must execute this boundary on one fresh dedicated debugger OS
//! thread. Success retains the still-suspended, debug-attached process without
//! receiving or continuing a debug event. Failure requests exact process and
//! whole-Job termination, then returns a sendable cleanup owner that may only
//! be completed after that debugger thread has exited and been joined.

#![allow(unsafe_code)]

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::num::NonZeroU32;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::io::BorrowedHandle;
use std::path::Path;
use std::rc::Rc;
use std::thread::{self, ThreadId};

use thiserror::Error;

use super::job::ServiceProbeJob;
use super::startup::ServiceProbeStartup;
use super::target_profile::{PreparedTargetUserLpac, VerifiedCreatedTargetLpac};
use crate::helper::VerifiedHelper;
use crate::key_agent_lpac::PreparedServiceKeyAgentCreationSecurity;
use crate::key_agent_service_rpc::{
    AuthenticatedRpcClient, CreatedDesktopProcess, PendingDebuggerExitProcessCleanup,
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
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl FreshDebuggerThread {
    fn require_current(&self) -> Result<ThreadId, ServiceProbeCreateError> {
        if thread::current().id() != self.thread_id {
            return Err(ServiceProbeCreateError::Verification);
        }
        Ok(self.thread_id)
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
    _thread_bound: PhantomData<Rc<Cell<()>>>,
}

impl fmt::Debug for DebuggerThreadExitProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DebuggerThreadExitProof([REDACTED])")
    }
}

fn debugger_exit_matches(creator_thread_id: ThreadId, proof: &DebuggerThreadExitProof) -> bool {
    proof.thread_id == creator_thread_id
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
    thread::scope(|scope| {
        let handle = thread::Builder::new()
            .name(DEBUGGER_THREAD_NAME.to_owned())
            .spawn_scoped(scope, move || {
                let thread_id = thread::current().id();
                let output = operation(FreshDebuggerThread {
                    thread_id,
                    _thread_bound: PhantomData,
                });
                (output, thread_id)
            })
            .map_err(|_| FreshDebuggerThreadError::Spawn)?;
        let (output, thread_id) = handle.join().map_err(|_| FreshDebuggerThreadError::Panic)?;
        Ok(JoinedFreshDebuggerThread {
            output,
            proof: DebuggerThreadExitProof {
                thread_id,
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
enum ServiceProbeRole {
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
        let creator_thread_id = match debugger_thread.require_current() {
            Ok(thread_id) => thread_id,
            Err(failure) => {
                return Err(self.into_pending_cleanup(None, failure, debugger_thread.thread_id));
            }
        };
        if let Err(failure) = self.verify_pre_create() {
            return Err(self.into_pending_cleanup(None, failure, creator_thread_id));
        }

        let created = match self.create_native_suspended() {
            Ok(created) => created,
            Err(failure) => {
                return Err(self.into_pending_cleanup(None, failure, creator_thread_id));
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
            verify_post_create(&mut operations)
        };
        let target_proof = match verification {
            Ok(proof) => proof,
            Err(failure) => {
                let process = created.request_termination_into_pending_debugger_exit_cleanup();
                return Err(self.into_pending_cleanup(Some(process), failure, creator_thread_id));
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
    ) -> PendingServiceProbeCleanup {
        let Self { mut job, .. } = self;
        let job_request_failed = job.request_termination().is_err();
        PendingServiceProbeCleanup {
            process,
            job,
            failure,
            job_request_failed,
            process_cleanup_failed: false,
            creator_thread_id,
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

    /// Repeats every object-bound proof before a future debug event or handle
    /// injection transition.
    pub(super) fn revalidate(mut self) -> Result<Self, PendingServiceProbeCleanup> {
        if let Err(failure) = self.debugger_thread.require_current() {
            return Err(self.into_pending_cleanup(failure));
        }
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
            verify_post_create(&mut operations)
        };
        let fresh = match verification {
            Ok(fresh) => fresh,
            Err(failure) => return Err(self.into_pending_cleanup(failure)),
        };
        let retained = self.target.revalidate_created_process(
            &self.target_proof,
            self.created.process_handle(),
            self.context,
        );
        drop(fresh);
        if retained.is_err() {
            return Err(self.into_pending_cleanup(ServiceProbeCreateError::Verification));
        }
        Ok(self)
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
            creator_thread_id,
        }
    }
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
    creator_thread_id: ThreadId,
}

impl PendingServiceProbeCleanup {
    pub(super) const fn failure(&self) -> ServiceProbeCreateError {
        self.failure
    }

    /// Completes exact process reap and Job-empty proof after the debugger
    /// thread has exited and its join has succeeded.
    pub(super) fn finish_after_debugger_exit(
        &mut self,
        proof: &DebuggerThreadExitProof,
    ) -> Result<ServiceProbeCreateError, ServiceProbeCreateError> {
        if !debugger_exit_matches(self.creator_thread_id, proof) {
            return Err(ServiceProbeCreateError::Cleanup);
        }
        let process_result = match self.process.take() {
            Some(process) => process.wait_and_close(),
            None => Ok(()),
        };
        self.process_cleanup_failed |= process_result.is_err();
        let job_result = self.job.finish_termination_and_wait();
        if self.job_request_failed || self.process_cleanup_failed || job_result.is_err() {
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
    fn revalidate_service(&mut self) -> Result<(), ServiceProbeCreateError>;
    fn verify_target(&mut self) -> Result<Self::TargetProof, ServiceProbeCreateError>;
    fn verify_job(&mut self) -> Result<(), ServiceProbeCreateError>;
    fn revalidate_context(&mut self) -> Result<(), ServiceProbeCreateError>;
    fn revalidate_target(
        &mut self,
        proof: &Self::TargetProof,
    ) -> Result<(), ServiceProbeCreateError>;
}

fn verify_post_create<O: PostCreateVerificationOps>(
    operations: &mut O,
) -> Result<O::TargetProof, ServiceProbeCreateError> {
    operations.revalidate_client()?;
    operations.verify_helper()?;
    operations.verify_service_objects()?;
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
        DebuggerThreadExitProof, FreshDebuggerThread, JoinedFreshDebuggerThread,
        PendingServiceProbeCleanup, PostCreateVerificationOps, ServiceProbeCreateError,
        SuspendedServiceProbe, debugger_exit_matches, run_on_fresh_debugger_thread,
        verify_post_create, wide_nul_absolute_path,
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

    #[test]
    fn post_create_verification_is_exact_and_every_prefix_fails_closed() {
        const EVENTS: [&str; 10] = [
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

        let mut success = FakePostCreate {
            events: Vec::new(),
            failure_at: None,
        };
        assert_eq!(verify_post_create(&mut success), Ok(()));
        assert_eq!(success.events, EVENTS);

        for failure_at in 0..EVENTS.len() {
            let mut failure = FakePostCreate {
                events: Vec::new(),
                failure_at: Some(failure_at),
            };
            assert_eq!(
                verify_post_create(&mut failure),
                Err(ServiceProbeCreateError::Verification)
            );
            assert_eq!(failure.events, EVENTS[..=failure_at]);
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
            current
        })?;
        let (first_thread, first_proof) = first.into_parts();
        assert!(debugger_exit_matches(first_thread, &first_proof));

        let second = run_on_fresh_debugger_thread(|witness| {
            let current = std::thread::current().id();
            assert_eq!(witness.require_current(), Ok(current));
            current
        })?;
        let (second_thread, second_proof) = second.into_parts();
        assert!(debugger_exit_matches(second_thread, &second_proof));
        assert!(!debugger_exit_matches(first_thread, &second_proof));
        assert!(!debugger_exit_matches(second_thread, &first_proof));
        Ok(())
    }
}
