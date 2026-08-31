//! Dormant Windows no-secret lifecycle composition.
//!
//! This private, production-compiled module binds the authority-independent
//! startup/runtime policy to the checked Windows durable writer. It has no
//! executable caller, key source, SCM adapter, secret operation, or call to
//! `process::exit`. Move-only typestates preserve the required ordering until
//! exact stopped evidence, checked exit-78 evidence, or an irreversible
//! terminal state is reached.

use core::fmt;
use std::num::NonZeroU64;

use super::durable_run_state::{
    FixtureRunStateAuthenticationKey, InstallationIdentity, RecoveryRequired,
    WindowsActiveCommitOutcome, WindowsActiveReloadOutcome, WindowsActiveReloadRequired,
    WindowsActiveRunLease, WindowsBootEvidence, WindowsCheckedRetired,
    WindowsCheckedRetirementFailure, WindowsCleanCommitOutcome, WindowsCleanReloadOutcome,
    WindowsCleanReloadRequired, WindowsCleanWithWriter, WindowsPostReleaseTerminal,
    WindowsPreparedActiveTransition, WindowsReleasedNoReceipt, WindowsRetirementPending,
    WindowsRuntimeBindingFailure, WindowsRuntimeStartFailure, WindowsStopOutcome,
    WindowsStoppedRunEvidence, WindowsTerminalCause, WindowsTerminalFailure, WindowsUnboundRetired,
    start_windows_runtime,
};
use super::lifecycle_core::{
    AdmissionPendingPolicy, CleanBoundaryPolicy, CleanupStep, CompletedStartupChecklist,
    FatalReason, LifecycleError, ListenerPendingPolicy, NoSecretFixtureWorkKind,
    NoSecretStartupRequirement, ReleaseBoundaryPolicy, RuntimePolicy, RuntimePolicyFailure,
    RuntimeState, ScmRunningPendingPolicy, SessionEvent, SessionId, SessionInvalidationReport,
    StartupChecklist, StartupFailure, StartupObservation, StopReason, StoppedRuntimePolicy, WorkId,
};
use super::run_state_root::{HeldServiceRunStateWriter, ServiceRunStateError};

const WINDOWS_SERVICE_EXIT_CODE: i32 = 78;

/// Exact cause retained by the lifecycle independently of checked Windows
/// retirement authority.
#[must_use = "a lifecycle cause must remain attached to its terminal authority"]
pub(super) enum WindowsLifecycleCause {
    Binding(RecoveryRequired),
    Startup(StartupFailure),
    RuntimePolicy(RuntimePolicyFailure),
    Lifecycle(LifecycleError),
    Fatal(FatalReason),
    Durable(WindowsTerminalCause),
}

impl fmt::Debug for WindowsLifecycleCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Binding(cause) => formatter.debug_tuple("Binding").field(cause).finish(),
            Self::Startup(cause) => formatter.debug_tuple("Startup").field(cause).finish(),
            Self::RuntimePolicy(cause) => {
                formatter.debug_tuple("RuntimePolicy").field(cause).finish()
            }
            Self::Lifecycle(cause) => formatter.debug_tuple("Lifecycle").field(cause).finish(),
            Self::Fatal(cause) => formatter.debug_tuple("Fatal").field(cause).finish(),
            Self::Durable(cause) => formatter.debug_tuple("Durable").field(cause).finish(),
        }
    }
}

#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
enum WindowsLifecycleExitAuthority<'key> {
    Unbound(WindowsRuntimeBindingFailure),
    Bound(WindowsRetirementPending<'key>),
}

/// Terminal lifecycle authority that can produce exit code 78 only after its
/// exact Windows writer retirement has been checked.
#[must_use = "terminal lifecycle authority must be retired exactly once"]
pub(super) struct WindowsLifecycleExitRequired<'key> {
    cause: WindowsLifecycleCause,
    authority: WindowsLifecycleExitAuthority<'key>,
}

impl<'key> WindowsLifecycleExitRequired<'key> {
    fn unbound(cause: WindowsLifecycleCause, authority: WindowsRuntimeBindingFailure) -> Self {
        Self {
            cause,
            authority: WindowsLifecycleExitAuthority::Unbound(authority),
        }
    }

    fn bound(cause: WindowsLifecycleCause, authority: WindowsRetirementPending<'key>) -> Self {
        Self {
            cause,
            authority: WindowsLifecycleExitAuthority::Bound(authority),
        }
    }

    fn from_terminal(failure: WindowsTerminalFailure<'key>) -> Self {
        let (cause, authority) = failure.into_retirement_parts();
        Self::bound(WindowsLifecycleCause::Durable(cause), authority)
    }

    pub(super) const fn cause(&self) -> &WindowsLifecycleCause {
        &self.cause
    }

    /// Checks the exact unbound or bound writer retirement before minting an
    /// exit-78 receipt. Any cleanup ambiguity is irreversible and preserves
    /// both the original lifecycle cause and platform cleanup cause.
    #[allow(clippy::result_large_err)] // Failure retains the terminal obligation inline.
    pub(super) fn retire_checked(
        self,
    ) -> Result<WindowsLifecycleCheckedExit78<'key>, WindowsLifecycleIrreversibleExit78<'key>> {
        let Self { cause, authority } = self;
        match authority {
            WindowsLifecycleExitAuthority::Unbound(authority) => match authority.retire() {
                Ok(retired) => Ok(WindowsLifecycleCheckedExit78 {
                    cause,
                    authority: WindowsLifecycleCheckedExitAuthority::Unbound(retired),
                }),
                Err(platform) => Err(WindowsLifecycleIrreversibleExit78::retirement_failure(
                    cause, platform, None,
                )),
            },
            WindowsLifecycleExitAuthority::Bound(authority) => match authority.retire_checked() {
                Ok(retired) => Ok(WindowsLifecycleCheckedExit78 {
                    cause,
                    authority: WindowsLifecycleCheckedExitAuthority::Bound(retired),
                }),
                Err(failure) => {
                    let platform = failure.cause();
                    Err(WindowsLifecycleIrreversibleExit78::retirement_failure(
                        cause,
                        platform,
                        Some(failure),
                    ))
                }
            },
        }
    }
}

impl fmt::Debug for WindowsLifecycleExitRequired<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsLifecycleExitRequired")
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

enum WindowsLifecycleCheckedExitAuthority<'key> {
    Unbound(WindowsUnboundRetired),
    Bound(WindowsCheckedRetired<'key>),
}

/// Checked terminal receipt. This is the sole lifecycle state that authorizes
/// exit code 78 after a checked writer-retirement path.
#[must_use = "checked exit evidence is terminal"]
pub(super) struct WindowsLifecycleCheckedExit78<'key> {
    cause: WindowsLifecycleCause,
    authority: WindowsLifecycleCheckedExitAuthority<'key>,
}

impl WindowsLifecycleCheckedExit78<'_> {
    pub(super) const fn cause(&self) -> &WindowsLifecycleCause {
        &self.cause
    }

    #[allow(clippy::unused_self)] // The receipt instance is the exit authority.
    pub(super) const fn code(&self) -> i32 {
        WINDOWS_SERVICE_EXIT_CODE
    }
}

impl fmt::Debug for WindowsLifecycleCheckedExit78<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.authority;
        formatter
            .debug_struct("WindowsLifecycleCheckedExit78")
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Cause attached to an irreversible exit-78 state. These states expose no
/// retry, retirement, recovery-exit, or normal stopped conversion.
#[must_use = "an irreversible exit cause must remain terminal"]
pub(super) enum WindowsLifecycleIrreversibleCause {
    Retirement {
        original: WindowsLifecycleCause,
        platform: ServiceRunStateError,
    },
    ReleasedNoReceipt {
        recovery: RecoveryRequired,
        platform: ServiceRunStateError,
    },
    PostRelease {
        recovery: RecoveryRequired,
    },
}

impl fmt::Debug for WindowsLifecycleIrreversibleCause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retirement { original, platform } => formatter
                .debug_struct("Retirement")
                .field("original", original)
                .field("platform", platform)
                .finish(),
            Self::ReleasedNoReceipt { recovery, platform } => formatter
                .debug_struct("ReleasedNoReceipt")
                .field("recovery", recovery)
                .field("platform", platform)
                .finish(),
            Self::PostRelease { recovery } => formatter
                .debug_struct("PostRelease")
                .field("recovery", recovery)
                .finish(),
        }
    }
}

#[allow(clippy::large_enum_variant)] // Inline terminal state avoids fallible allocation.
enum WindowsLifecycleIrreversibleAuthority<'key> {
    UnboundRetirementFailure,
    BoundRetirementFailure(WindowsCheckedRetirementFailure<'key>),
    ReleasedNoReceipt(WindowsReleasedNoReceipt<'key>),
    PostRelease(WindowsPostReleaseTerminal<'key>),
}

/// Irreversible terminal state that authorizes silent exit 78 but deliberately
/// exposes no retry or retirement method.
#[must_use = "irreversible exit evidence is terminal"]
pub(super) struct WindowsLifecycleIrreversibleExit78<'key> {
    cause: WindowsLifecycleIrreversibleCause,
    authority: WindowsLifecycleIrreversibleAuthority<'key>,
}

impl<'key> WindowsLifecycleIrreversibleExit78<'key> {
    fn retirement_failure(
        original: WindowsLifecycleCause,
        platform: ServiceRunStateError,
        failure: Option<WindowsCheckedRetirementFailure<'key>>,
    ) -> Self {
        let authority = failure.map_or(
            WindowsLifecycleIrreversibleAuthority::UnboundRetirementFailure,
            WindowsLifecycleIrreversibleAuthority::BoundRetirementFailure,
        );
        Self {
            cause: WindowsLifecycleIrreversibleCause::Retirement { original, platform },
            authority,
        }
    }

    fn released_no_receipt(failure: WindowsReleasedNoReceipt<'key>) -> Self {
        let recovery = failure.reason();
        let platform = failure.cause();
        Self {
            cause: WindowsLifecycleIrreversibleCause::ReleasedNoReceipt { recovery, platform },
            authority: WindowsLifecycleIrreversibleAuthority::ReleasedNoReceipt(failure),
        }
    }

    fn post_release(failure: WindowsPostReleaseTerminal<'key>) -> Self {
        let recovery = failure.reason();
        Self {
            cause: WindowsLifecycleIrreversibleCause::PostRelease { recovery },
            authority: WindowsLifecycleIrreversibleAuthority::PostRelease(failure),
        }
    }

    pub(super) const fn cause(&self) -> &WindowsLifecycleIrreversibleCause {
        &self.cause
    }

    #[allow(clippy::unused_self)] // The terminal instance is the exit authority.
    pub(super) const fn code(&self) -> i32 {
        WINDOWS_SERVICE_EXIT_CODE
    }
}

impl fmt::Debug for WindowsLifecycleIrreversibleExit78<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.authority;
        formatter
            .debug_struct("WindowsLifecycleIrreversibleExit78")
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

/// Begins the dormant Windows lifecycle from an already-held, installer-bound
/// writer. No listener or SCM authority exists at this stage.
#[allow(clippy::large_types_passed_by_value)] // Transfers the opaque writer exactly once.
#[allow(clippy::result_large_err)] // Failure retains move-only terminal authority inline.
pub(super) fn begin_windows_lifecycle(
    writer: HeldServiceRunStateWriter,
    installation: InstallationIdentity,
    key: &FixtureRunStateAuthenticationKey,
) -> Result<WindowsStartupAttempt<'_>, WindowsLifecycleExitRequired<'_>> {
    match start_windows_runtime(writer, installation, key) {
        Ok(windows) => Ok(WindowsStartupAttempt {
            checklist: StartupChecklist::new(),
            windows,
        }),
        Err(WindowsRuntimeStartFailure::Binding(failure)) => {
            let reason = failure.reason();
            Err(WindowsLifecycleExitRequired::unbound(
                WindowsLifecycleCause::Binding(reason),
                failure,
            ))
        }
        Err(WindowsRuntimeStartFailure::Terminal(failure)) => {
            Err(WindowsLifecycleExitRequired::from_terminal(failure))
        }
    }
}

/// Authenticated Clean boot plus a fresh authority-independent checklist.
#[must_use = "startup observations must be completed or retired"]
pub(super) struct WindowsStartupAttempt<'key> {
    checklist: StartupChecklist,
    windows: WindowsBootEvidence<'key>,
}

impl<'key> WindowsStartupAttempt<'key> {
    pub(super) fn observe(
        &mut self,
        requirement: NoSecretStartupRequirement,
        observation: StartupObservation,
    ) -> Result<(), StartupFailure> {
        self.checklist.observe(requirement, observation)
    }

    #[allow(clippy::result_large_err)] // Failure retains checked retirement authority inline.
    pub(super) fn finish(
        self,
    ) -> Result<WindowsActiveCommitPending<'key>, WindowsLifecycleExitRequired<'key>> {
        let Self { checklist, windows } = self;
        let checklist = match checklist.finish() {
            Ok(checklist) => checklist,
            Err(cause) => {
                return Err(WindowsLifecycleExitRequired::bound(
                    WindowsLifecycleCause::Startup(cause),
                    windows.into_retirement(),
                ));
            }
        };
        match windows.prepare_active() {
            Ok(windows) => Ok(WindowsActiveCommitPending { checklist, windows }),
            Err(failure) => Err(WindowsLifecycleExitRequired::from_terminal(failure)),
        }
    }

    pub(super) fn abort(self, cause: StartupFailure) -> WindowsLifecycleExitRequired<'key> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Startup(cause),
            self.windows.into_retirement(),
        )
    }
}

impl fmt::Debug for WindowsStartupAttempt<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsStartupAttempt([REDACTED])")
    }
}

/// Completed startup policy and prepared exact Active transition.
#[must_use = "the prepared Active transition must commit, reload, or retire"]
pub(super) struct WindowsActiveCommitPending<'key> {
    checklist: CompletedStartupChecklist,
    windows: WindowsPreparedActiveTransition<'key>,
}

impl<'key> WindowsActiveCommitPending<'key> {
    pub(super) fn commit_and_reread(self) -> WindowsLifecycleActiveCommitOutcome<'key> {
        let Self { checklist, windows } = self;
        match windows.commit_and_reread() {
            WindowsActiveCommitOutcome::Active(windows) => {
                WindowsLifecycleActiveCommitOutcome::ListenerPending(WindowsListenerPending {
                    policy: checklist.begin_listener_startup(),
                    windows,
                })
            }
            WindowsActiveCommitOutcome::ReloadRequired(windows) => {
                WindowsLifecycleActiveCommitOutcome::ReloadRequired(WindowsActiveReloadPending {
                    checklist,
                    windows,
                })
            }
            WindowsActiveCommitOutcome::Terminal(failure) => {
                WindowsLifecycleActiveCommitOutcome::ExitRequired(
                    WindowsLifecycleExitRequired::from_terminal(failure),
                )
            }
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'key> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
        )
    }
}

impl fmt::Debug for WindowsActiveCommitPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsActiveCommitPending([REDACTED])")
    }
}

#[must_use = "the Active commit outcome retains exact lifecycle authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsLifecycleActiveCommitOutcome<'key> {
    ListenerPending(WindowsListenerPending<'key>),
    ReloadRequired(WindowsActiveReloadPending<'key>),
    ExitRequired(WindowsLifecycleExitRequired<'key>),
}

/// Active commit ambiguity plus the checklist completed for that exact attempt.
#[must_use = "Active ambiguity must reload or retire"]
pub(super) struct WindowsActiveReloadPending<'key> {
    checklist: CompletedStartupChecklist,
    windows: WindowsActiveReloadRequired<'key>,
}

impl<'key> WindowsActiveReloadPending<'key> {
    pub(super) fn reload(self) -> WindowsLifecycleActiveReloadOutcome<'key> {
        let Self { checklist, windows } = self;
        match windows.reload() {
            WindowsActiveReloadOutcome::Boot(windows) => {
                WindowsLifecycleActiveReloadOutcome::Revalidate(WindowsStartupAttempt {
                    checklist: StartupChecklist::new(),
                    windows,
                })
            }
            WindowsActiveReloadOutcome::Active(windows) => {
                WindowsLifecycleActiveReloadOutcome::ListenerPending(WindowsListenerPending {
                    policy: checklist.begin_listener_startup(),
                    windows,
                })
            }
            WindowsActiveReloadOutcome::Terminal(failure) => {
                WindowsLifecycleActiveReloadOutcome::ExitRequired(
                    WindowsLifecycleExitRequired::from_terminal(failure),
                )
            }
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'key> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
        )
    }
}

impl fmt::Debug for WindowsActiveReloadPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsActiveReloadPending([REDACTED])")
    }
}

#[must_use = "the Active reload outcome retains exact lifecycle authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsLifecycleActiveReloadOutcome<'key> {
    Revalidate(WindowsStartupAttempt<'key>),
    ListenerPending(WindowsListenerPending<'key>),
    ExitRequired(WindowsLifecycleExitRequired<'key>),
}

/// Exact Active authority before listener preparation is recorded.
#[must_use = "listeners must be prepared before SCM_RUNNING publication"]
pub(super) struct WindowsListenerPending<'key> {
    policy: ListenerPendingPolicy,
    windows: WindowsActiveRunLease<'key>,
}

impl<'key> WindowsListenerPending<'key> {
    pub(super) fn record_listeners_prepared(self) -> WindowsScmRunningPending<'key> {
        WindowsScmRunningPending {
            policy: self.policy.record_listeners_prepared(),
            windows: self.windows,
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'key> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
        )
    }
}

impl fmt::Debug for WindowsListenerPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsListenerPending([REDACTED])")
    }
}

/// Exact Active authority after listener preparation but before `SCM_RUNNING`.
#[must_use = "SCM_RUNNING publication must precede admission"]
pub(super) struct WindowsScmRunningPending<'key> {
    policy: ScmRunningPendingPolicy,
    windows: WindowsActiveRunLease<'key>,
}

impl<'key> WindowsScmRunningPending<'key> {
    pub(super) fn record_scm_running_published(self) -> WindowsAdmissionPending<'key> {
        WindowsAdmissionPending {
            policy: self.policy.record_scm_running_published(),
            windows: self.windows,
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'key> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
        )
    }
}

impl fmt::Debug for WindowsScmRunningPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsScmRunningPending([REDACTED])")
    }
}

/// Exact Active authority after `SCM_RUNNING` but before admission opens.
#[must_use = "admission must be opened explicitly"]
pub(super) struct WindowsAdmissionPending<'key> {
    policy: AdmissionPendingPolicy,
    windows: WindowsActiveRunLease<'key>,
}

impl<'key> WindowsAdmissionPending<'key> {
    pub(super) fn open_admission(self) -> WindowsNoSecretService<'key> {
        WindowsNoSecretService {
            policy: self.policy.open_admission(),
            windows: self.windows,
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'key> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
        )
    }
}

impl fmt::Debug for WindowsAdmissionPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsAdmissionPending([REDACTED])")
    }
}

/// Running no-secret service. Every work/session/cleanup decision delegates to
/// the single authority-independent [`RuntimePolicy`] implementation.
#[must_use = "the running service must reach Clean or checked retirement"]
pub(super) struct WindowsNoSecretService<'key> {
    policy: RuntimePolicy,
    windows: WindowsActiveRunLease<'key>,
}

impl<'key> WindowsNoSecretService<'key> {
    pub(super) const fn state(&self) -> RuntimeState {
        self.policy.state()
    }

    pub(super) fn work_count(&self) -> usize {
        self.policy.work_count()
    }

    pub(super) fn retained_user_token_count(&self) -> usize {
        self.policy.retained_user_token_count()
    }

    pub(super) fn quarantined_session_count(&self) -> usize {
        self.policy.quarantined_session_count()
    }

    pub(super) fn admit_fixture_work(
        &mut self,
        id: WorkId,
        session: SessionId,
        kind: NoSecretFixtureWorkKind,
    ) -> Result<(), LifecycleError> {
        self.policy.admit_fixture_work(id, session, kind)
    }

    pub(super) fn retain_user_token(&mut self, session: SessionId) -> Result<(), LifecycleError> {
        self.policy.retain_user_token(session)
    }

    pub(super) fn handle_session_event(
        &mut self,
        event: SessionEvent,
    ) -> Result<SessionInvalidationReport, LifecycleError> {
        self.policy.handle_session_event(event)
    }

    pub(super) fn reap_cancelled_fixture_work(&mut self, id: WorkId) -> Result<(), LifecycleError> {
        self.policy.reap_cancelled_fixture_work(id)
    }

    pub(super) fn begin_stop(&mut self, reason: StopReason) -> Result<(), LifecycleError> {
        self.policy.begin_stop(reason)
    }

    pub(super) fn expected_cleanup_step(&self) -> Option<CleanupStep> {
        self.policy.expected_cleanup_step()
    }

    pub(super) fn complete_cleanup_step(
        &mut self,
        step: CleanupStep,
    ) -> Result<(), LifecycleError> {
        self.policy.complete_cleanup_step(step)
    }

    pub(super) fn fail_cleanup(&mut self, step: CleanupStep) -> Result<(), LifecycleError> {
        self.policy.fail_cleanup(step)
    }

    pub(super) fn cleanup_deadline_expired(&mut self) -> Result<(), LifecycleError> {
        self.policy.cleanup_deadline_expired()
    }

    pub(super) fn crash(&mut self) {
        self.policy.crash();
    }

    pub(super) fn prepare_clean(self) -> WindowsLifecycleCleanCommitOutcome<'key> {
        let Self { policy, windows } = self;
        if let RuntimeState::Fatal(cause) = policy.state() {
            return WindowsLifecycleCleanCommitOutcome::ExitRequired(
                WindowsLifecycleExitRequired::bound(
                    WindowsLifecycleCause::Fatal(cause),
                    windows.into_retirement(),
                ),
            );
        }
        let policy = match policy.prepare_clean() {
            Ok(policy) => policy,
            Err(cause) => {
                return WindowsLifecycleCleanCommitOutcome::ExitRequired(
                    WindowsLifecycleExitRequired::bound(
                        WindowsLifecycleCause::RuntimePolicy(cause),
                        windows.into_retirement(),
                    ),
                );
            }
        };
        match windows.commit_clean() {
            WindowsCleanCommitOutcome::Clean(windows) => {
                WindowsLifecycleCleanCommitOutcome::ReleasePending(WindowsCleanReleasePending {
                    policy: policy.record_clean_committed(),
                    windows,
                })
            }
            WindowsCleanCommitOutcome::ReloadRequired(windows) => {
                WindowsLifecycleCleanCommitOutcome::ReloadRequired(WindowsCleanReloadPending {
                    policy,
                    windows,
                })
            }
            WindowsCleanCommitOutcome::Terminal(failure) => {
                WindowsLifecycleCleanCommitOutcome::ExitRequired(
                    WindowsLifecycleExitRequired::from_terminal(failure),
                )
            }
        }
    }

    pub(super) fn into_exit(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'key> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
        )
    }

    pub(super) fn into_fatal_exit(self) -> WindowsLifecycleExitRequired<'key> {
        let cause = match self.policy.state() {
            RuntimeState::Fatal(cause) => WindowsLifecycleCause::Fatal(cause),
            RuntimeState::Ready | RuntimeState::Draining(_) => {
                WindowsLifecycleCause::Lifecycle(LifecycleError::NotReady)
            }
        };
        WindowsLifecycleExitRequired::bound(cause, self.windows.into_retirement())
    }
}

impl fmt::Debug for WindowsNoSecretService<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsNoSecretService")
            .field("policy", &self.policy)
            .field("windows", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[must_use = "the Clean commit outcome retains exact lifecycle authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsLifecycleCleanCommitOutcome<'key> {
    ReleasePending(WindowsCleanReleasePending<'key>),
    ReloadRequired(WindowsCleanReloadPending<'key>),
    ExitRequired(WindowsLifecycleExitRequired<'key>),
}

/// Ambiguous Clean commit paired with a pure Clean boundary that has not yet
/// advanced to release policy.
#[must_use = "Clean ambiguity must reload or retire"]
pub(super) struct WindowsCleanReloadPending<'key> {
    policy: CleanBoundaryPolicy,
    windows: WindowsCleanReloadRequired<'key>,
}

impl<'key> WindowsCleanReloadPending<'key> {
    pub(super) fn reload(self) -> WindowsLifecycleCleanReloadOutcome<'key> {
        let Self { policy, windows } = self;
        match windows.reload() {
            WindowsCleanReloadOutcome::Clean(windows) => {
                WindowsLifecycleCleanReloadOutcome::ReleasePending(WindowsCleanReleasePending {
                    policy: policy.record_clean_committed(),
                    windows,
                })
            }
            WindowsCleanReloadOutcome::Terminal(failure) => {
                WindowsLifecycleCleanReloadOutcome::ExitRequired(
                    WindowsLifecycleExitRequired::from_terminal(failure),
                )
            }
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'key> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
        )
    }
}

impl fmt::Debug for WindowsCleanReloadPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsCleanReloadPending([REDACTED])")
    }
}

#[must_use = "the Clean reload outcome retains exact lifecycle authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsLifecycleCleanReloadOutcome<'key> {
    ReleasePending(WindowsCleanReleasePending<'key>),
    ExitRequired(WindowsLifecycleExitRequired<'key>),
}

/// Exact durable/OS Clean authority paired with the pure release boundary.
#[must_use = "the exact writer release must be checked"]
pub(super) struct WindowsCleanReleasePending<'key> {
    policy: ReleaseBoundaryPolicy,
    windows: WindowsCleanWithWriter<'key>,
}

impl<'key> WindowsCleanReleasePending<'key> {
    pub(super) fn release_writer(self) -> WindowsLifecycleStopOutcome<'key> {
        let Self { policy, windows } = self;
        complete_lifecycle_stop(policy, windows.stop())
    }

    #[cfg(test)]
    fn release_writer_with_post_release_fault_for_test(self) -> WindowsLifecycleStopOutcome<'key> {
        let Self { policy, windows } = self;
        complete_lifecycle_stop(policy, windows.stop_with_post_release_fault_for_test())
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'key> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
        )
    }
}

fn complete_lifecycle_stop(
    policy: ReleaseBoundaryPolicy,
    outcome: WindowsStopOutcome<'_>,
) -> WindowsLifecycleStopOutcome<'_> {
    match outcome {
        WindowsStopOutcome::Stopped(windows) => {
            WindowsLifecycleStopOutcome::Stopped(WindowsLifecycleStopped {
                policy: policy.record_writer_released(),
                windows,
            })
        }
        WindowsStopOutcome::Terminal(failure) => WindowsLifecycleStopOutcome::ExitRequired(
            WindowsLifecycleExitRequired::from_terminal(failure),
        ),
        WindowsStopOutcome::ReleasedNoReceipt(failure) => {
            WindowsLifecycleStopOutcome::IrreversibleExit78(
                WindowsLifecycleIrreversibleExit78::released_no_receipt(failure),
            )
        }
        WindowsStopOutcome::PostReleaseTerminal(failure) => {
            WindowsLifecycleStopOutcome::IrreversibleExit78(
                WindowsLifecycleIrreversibleExit78::post_release(failure),
            )
        }
    }
}

impl fmt::Debug for WindowsCleanReleasePending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsCleanReleasePending([REDACTED])")
    }
}

#[must_use = "the final writer-release outcome must be handled explicitly"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsLifecycleStopOutcome<'key> {
    Stopped(WindowsLifecycleStopped),
    ExitRequired(WindowsLifecycleExitRequired<'key>),
    IrreversibleExit78(WindowsLifecycleIrreversibleExit78<'key>),
}

/// Sole normal terminal lifecycle evidence. It intentionally exposes no exit-78
/// method because normal stopped completion is not a fail-closed process exit.
#[must_use = "normal stopped evidence is terminal"]
pub(super) struct WindowsLifecycleStopped {
    policy: StoppedRuntimePolicy,
    windows: WindowsStoppedRunEvidence,
}

impl WindowsLifecycleStopped {
    pub(super) const fn generation(&self) -> NonZeroU64 {
        self.windows.generation()
    }
}

impl fmt::Debug for WindowsLifecycleStopped {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = &self.policy;
        formatter.write_str("WindowsLifecycleStopped([REDACTED])")
    }
}

#[cfg(test)]
#[path = "windows_lifecycle_tests.rs"]
mod tests;
