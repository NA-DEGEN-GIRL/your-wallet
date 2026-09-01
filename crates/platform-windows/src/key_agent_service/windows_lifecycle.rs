//! Dormant Windows no-secret lifecycle composition.
//!
//! This private, production-compiled module binds the authority-independent
//! startup/runtime policy to the checked Windows durable writer. It has no
//! executable caller, provider source, SCM adapter, secret operation, or call to
//! `process::exit`. Move-only typestates preserve the required ordering until
//! exact stopped evidence, checked exit-78 evidence, or an irreversible
//! terminal state is reached.

#[path = "windows_lifecycle_effects.rs"]
pub(super) mod effects;

use core::fmt;
use std::num::NonZeroU64;

use super::durable_run_state::{
    RecoveryRequired, RuntimeRunStateAuthority, WindowsActiveCommitOutcome,
    WindowsActiveReloadOutcome, WindowsActiveReloadRequired, WindowsActiveRunLease,
    WindowsBootEvidence, WindowsCheckedRetired, WindowsCheckedRetirementFailure,
    WindowsCleanCommitOutcome, WindowsCleanReloadOutcome, WindowsCleanReloadRequired,
    WindowsCleanWithWriter, WindowsPostReleaseTerminal, WindowsPreparedActiveTransition,
    WindowsReleasedNoReceipt, WindowsRetirementPending, WindowsRuntimeBindingFailure,
    WindowsRuntimeStartFailure, WindowsStopOutcome, WindowsStoppedRunEvidence,
    WindowsTerminalCause, WindowsTerminalFailure, WindowsUnboundRetired,
    WindowsUnboundRetirementFailure, start_windows_runtime,
};
use super::lifecycle_core::{
    AdmissionPendingPolicy, CleanBoundaryPolicy, CleanupStep, CompletedStartupChecklist,
    FatalReason, LifecycleError, ListenerPendingPolicy, NoSecretFixtureWorkKind,
    NoSecretStartupRequirement, ReleaseBoundaryPolicy, RuntimePolicy, RuntimePolicyFailure,
    RuntimeState, ScmRunningPendingPolicy, SessionEvent, SessionId, SessionInvalidationReport,
    StartupChecklist, StartupFailure, StartupObservation, StopReason, StoppedRuntimePolicy, WorkId,
};
use super::run_state_root::{HeldServiceRunStateWriter, ServiceRunStateError};
use effects::{
    WindowsAdmissionClosedEffects, WindowsAdmissionOpenEffects, WindowsLifecycleEffectAuthority,
    WindowsLifecycleEffectCause, WindowsLifecycleEffectFailure, WindowsLifecycleTerminalEffects,
    WindowsListenersDrainedEffects, WindowsListenersPreparedEffects, WindowsScmRunningEffects,
    WindowsScmStoppedEffectEvidence,
};

const WINDOWS_SERVICE_EXIT_CODE: i32 = 78;

/// Exact cause retained by the lifecycle independently of checked Windows
/// retirement authority.
#[must_use = "a lifecycle cause must remain attached to its terminal authority"]
pub(super) enum WindowsLifecycleCause {
    Binding(RecoveryRequired),
    Startup(StartupFailure),
    Effect(WindowsLifecycleEffectCause),
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
            Self::Effect(cause) => formatter.debug_tuple("Effect").field(cause).finish(),
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
enum WindowsLifecycleExitAuthority<'provider> {
    Unbound(WindowsRuntimeBindingFailure<'provider>),
    Bound(WindowsRetirementPending<'provider>),
}

/// Terminal lifecycle authority that can produce exit code 78 only after its
/// exact Windows writer retirement has been checked.
#[must_use = "terminal lifecycle authority must be retired exactly once"]
pub(super) struct WindowsLifecycleExitRequired<'provider> {
    cause: WindowsLifecycleCause,
    authority: WindowsLifecycleExitAuthority<'provider>,
    effects: WindowsLifecycleTerminalEffects,
}

impl<'provider> WindowsLifecycleExitRequired<'provider> {
    fn unbound(
        cause: WindowsLifecycleCause,
        authority: WindowsRuntimeBindingFailure<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    ) -> Self {
        Self {
            cause,
            authority: WindowsLifecycleExitAuthority::Unbound(authority),
            effects,
        }
    }

    fn bound(
        cause: WindowsLifecycleCause,
        authority: WindowsRetirementPending<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    ) -> Self {
        Self {
            cause,
            authority: WindowsLifecycleExitAuthority::Bound(authority),
            effects,
        }
    }

    fn from_terminal(
        failure: WindowsTerminalFailure<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    ) -> Self {
        let (cause, authority) = failure.into_retirement_parts();
        Self::bound(WindowsLifecycleCause::Durable(cause), authority, effects)
    }

    pub(super) const fn cause(&self) -> &WindowsLifecycleCause {
        &self.cause
    }

    #[cfg(test)]
    const fn effects_attached_for_test(&self) -> bool {
        self.effects.is_attached_for_test()
    }

    #[cfg(test)]
    const fn effect_failure_for_test(&self) -> Option<WindowsLifecycleEffectCause> {
        self.effects.failure_cause_for_test()
    }

    /// Checks the exact unbound or bound writer retirement before minting an
    /// exit-78 receipt. Any cleanup ambiguity is irreversible and preserves
    /// both the original lifecycle cause and platform cleanup cause.
    #[allow(clippy::result_large_err)] // Failure retains the terminal obligation inline.
    pub(super) fn retire_checked(
        self,
    ) -> Result<
        WindowsLifecycleCheckedExit78<'provider>,
        WindowsLifecycleIrreversibleExit78<'provider>,
    > {
        let Self {
            cause,
            authority,
            effects,
        } = self;
        match authority {
            WindowsLifecycleExitAuthority::Unbound(authority) => match authority.retire() {
                Ok(retired) => Ok(WindowsLifecycleCheckedExit78 {
                    cause,
                    authority: WindowsLifecycleCheckedExitAuthority::Unbound { retired, effects },
                }),
                Err(failure) => Err(
                    WindowsLifecycleIrreversibleExit78::unbound_retirement_failure(
                        cause, failure, effects,
                    ),
                ),
            },
            WindowsLifecycleExitAuthority::Bound(authority) => match authority.retire_checked() {
                Ok(retired) => Ok(WindowsLifecycleCheckedExit78 {
                    cause,
                    authority: WindowsLifecycleCheckedExitAuthority::Bound { retired, effects },
                }),
                Err(failure) => {
                    let platform = failure.cause();
                    Err(
                        WindowsLifecycleIrreversibleExit78::bound_retirement_failure(
                            cause, platform, failure, effects,
                        ),
                    )
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
            .field("effects", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

enum WindowsLifecycleCheckedExitAuthority<'provider> {
    Unbound {
        retired: WindowsUnboundRetired<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    },
    Bound {
        retired: WindowsCheckedRetired<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    },
}

/// Checked terminal receipt. This is the sole lifecycle state that authorizes
/// exit code 78 after a checked writer-retirement path.
#[must_use = "checked exit evidence is terminal"]
pub(super) struct WindowsLifecycleCheckedExit78<'provider> {
    cause: WindowsLifecycleCause,
    authority: WindowsLifecycleCheckedExitAuthority<'provider>,
}

impl WindowsLifecycleCheckedExit78<'_> {
    pub(super) const fn cause(&self) -> &WindowsLifecycleCause {
        &self.cause
    }

    #[allow(clippy::unused_self)] // The receipt instance is the exit authority.
    pub(super) const fn code(&self) -> i32 {
        WINDOWS_SERVICE_EXIT_CODE
    }

    #[cfg(test)]
    const fn effects_attached_for_test(&self) -> bool {
        match &self.authority {
            WindowsLifecycleCheckedExitAuthority::Unbound { effects, .. }
            | WindowsLifecycleCheckedExitAuthority::Bound { effects, .. } => {
                effects.is_attached_for_test()
            }
        }
    }

    #[cfg(test)]
    const fn effect_failure_for_test(&self) -> Option<WindowsLifecycleEffectCause> {
        match &self.authority {
            WindowsLifecycleCheckedExitAuthority::Unbound { effects, .. }
            | WindowsLifecycleCheckedExitAuthority::Bound { effects, .. } => {
                effects.failure_cause_for_test()
            }
        }
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
    ScmStoppedPublication {
        effect: WindowsLifecycleEffectCause,
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
            Self::ScmStoppedPublication { effect } => formatter
                .debug_struct("ScmStoppedPublication")
                .field("effect", effect)
                .finish(),
        }
    }
}

#[allow(clippy::large_enum_variant)] // Inline terminal state avoids fallible allocation.
enum WindowsLifecycleIrreversibleAuthority<'provider> {
    UnboundRetirementFailure {
        failure: WindowsUnboundRetirementFailure<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    },
    BoundRetirementFailure {
        failure: WindowsCheckedRetirementFailure<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    },
    ReleasedNoReceipt {
        failure: WindowsReleasedNoReceipt<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    },
    PostRelease {
        failure: WindowsPostReleaseTerminal<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    },
    PostWriterReleaseScmStop(WindowsPostWriterReleaseScmStopFailure<'provider>),
}

/// Irreversible terminal state that authorizes silent exit 78 but deliberately
/// exposes no retry or retirement method.
#[must_use = "irreversible exit evidence is terminal"]
pub(super) struct WindowsLifecycleIrreversibleExit78<'provider> {
    cause: WindowsLifecycleIrreversibleCause,
    authority: WindowsLifecycleIrreversibleAuthority<'provider>,
}

impl<'provider> WindowsLifecycleIrreversibleExit78<'provider> {
    fn unbound_retirement_failure(
        original: WindowsLifecycleCause,
        failure: WindowsUnboundRetirementFailure<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    ) -> Self {
        let platform = failure.cause();
        Self {
            cause: WindowsLifecycleIrreversibleCause::Retirement { original, platform },
            authority: WindowsLifecycleIrreversibleAuthority::UnboundRetirementFailure {
                failure,
                effects,
            },
        }
    }

    fn bound_retirement_failure(
        original: WindowsLifecycleCause,
        platform: ServiceRunStateError,
        failure: WindowsCheckedRetirementFailure<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    ) -> Self {
        Self {
            cause: WindowsLifecycleIrreversibleCause::Retirement { original, platform },
            authority: WindowsLifecycleIrreversibleAuthority::BoundRetirementFailure {
                failure,
                effects,
            },
        }
    }

    fn released_no_receipt(
        failure: WindowsReleasedNoReceipt<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    ) -> Self {
        let recovery = failure.reason();
        let platform = failure.cause();
        Self {
            cause: WindowsLifecycleIrreversibleCause::ReleasedNoReceipt { recovery, platform },
            authority: WindowsLifecycleIrreversibleAuthority::ReleasedNoReceipt {
                failure,
                effects,
            },
        }
    }

    fn post_release(
        failure: WindowsPostReleaseTerminal<'provider>,
        effects: WindowsLifecycleTerminalEffects,
    ) -> Self {
        let recovery = failure.reason();
        Self {
            cause: WindowsLifecycleIrreversibleCause::PostRelease { recovery },
            authority: WindowsLifecycleIrreversibleAuthority::PostRelease { failure, effects },
        }
    }

    fn post_writer_release_scm_stop(
        failure: WindowsPostWriterReleaseScmStopFailure<'provider>,
    ) -> Self {
        let effect = failure.cause();
        Self {
            cause: WindowsLifecycleIrreversibleCause::ScmStoppedPublication { effect },
            authority: WindowsLifecycleIrreversibleAuthority::PostWriterReleaseScmStop(failure),
        }
    }

    pub(super) const fn cause(&self) -> &WindowsLifecycleIrreversibleCause {
        &self.cause
    }

    #[allow(clippy::unused_self)] // The terminal instance is the exit authority.
    pub(super) const fn code(&self) -> i32 {
        WINDOWS_SERVICE_EXIT_CODE
    }

    #[cfg(test)]
    const fn effects_attached_for_test(&self) -> bool {
        match &self.authority {
            WindowsLifecycleIrreversibleAuthority::UnboundRetirementFailure { effects, .. }
            | WindowsLifecycleIrreversibleAuthority::BoundRetirementFailure { effects, .. }
            | WindowsLifecycleIrreversibleAuthority::ReleasedNoReceipt { effects, .. }
            | WindowsLifecycleIrreversibleAuthority::PostRelease { effects, .. } => {
                effects.is_attached_for_test()
            }
            WindowsLifecycleIrreversibleAuthority::PostWriterReleaseScmStop(failure) => {
                failure.effects.retains_authority_for_test()
            }
        }
    }

    #[cfg(test)]
    const fn post_writer_release_generation_for_test(&self) -> Option<NonZeroU64> {
        match &self.authority {
            WindowsLifecycleIrreversibleAuthority::PostWriterReleaseScmStop(failure) => {
                Some(failure.windows.generation())
            }
            WindowsLifecycleIrreversibleAuthority::UnboundRetirementFailure { .. }
            | WindowsLifecycleIrreversibleAuthority::BoundRetirementFailure { .. }
            | WindowsLifecycleIrreversibleAuthority::ReleasedNoReceipt { .. }
            | WindowsLifecycleIrreversibleAuthority::PostRelease { .. } => None,
        }
    }

    #[cfg(test)]
    fn post_writer_release_effect_binding_matches_for_test(
        &self,
        witness: effects::WindowsLifecycleEffectBindingWitness,
    ) -> bool {
        match &self.authority {
            WindowsLifecycleIrreversibleAuthority::PostWriterReleaseScmStop(failure) => {
                failure.effects.matches_binding_witness_for_test(witness)
            }
            WindowsLifecycleIrreversibleAuthority::UnboundRetirementFailure { .. }
            | WindowsLifecycleIrreversibleAuthority::BoundRetirementFailure { .. }
            | WindowsLifecycleIrreversibleAuthority::ReleasedNoReceipt { .. }
            | WindowsLifecycleIrreversibleAuthority::PostRelease { .. } => false,
        }
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

fn effect_exit(
    failure: WindowsLifecycleEffectFailure,
    authority: WindowsRetirementPending<'_>,
) -> WindowsLifecycleExitRequired<'_> {
    let cause = failure.cause();
    WindowsLifecycleExitRequired::bound(
        WindowsLifecycleCause::Effect(cause),
        authority,
        failure.into_terminal(),
    )
}

/// Begins the dormant Windows lifecycle from an already-held, installer-bound
/// writer. No listener or SCM authority exists at this stage.
#[allow(clippy::large_types_passed_by_value)] // Transfers the opaque writer exactly once.
#[allow(clippy::result_large_err)] // Failure retains move-only terminal authority inline.
pub(super) fn begin_windows_lifecycle(
    writer: HeldServiceRunStateWriter,
    authority: RuntimeRunStateAuthority<'_>,
) -> Result<WindowsStartupAttempt<'_>, WindowsLifecycleExitRequired<'_>> {
    match start_windows_runtime(writer, authority) {
        Ok(windows) => Ok(WindowsStartupAttempt {
            checklist: StartupChecklist::new(),
            windows,
        }),
        Err(WindowsRuntimeStartFailure::Binding(failure)) => {
            let reason = failure.reason();
            Err(WindowsLifecycleExitRequired::unbound(
                WindowsLifecycleCause::Binding(reason),
                failure,
                WindowsLifecycleTerminalEffects::unattached(),
            ))
        }
        Err(WindowsRuntimeStartFailure::Terminal(failure)) => {
            Err(WindowsLifecycleExitRequired::from_terminal(
                failure,
                WindowsLifecycleTerminalEffects::unattached(),
            ))
        }
    }
}

/// Authenticated Clean boot plus a fresh authority-independent checklist.
#[must_use = "startup observations must be completed or retired"]
pub(super) struct WindowsStartupAttempt<'provider> {
    checklist: StartupChecklist,
    windows: WindowsBootEvidence<'provider>,
}

impl<'provider> WindowsStartupAttempt<'provider> {
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
    ) -> Result<WindowsActiveCommitPending<'provider>, WindowsLifecycleExitRequired<'provider>>
    {
        let Self { checklist, windows } = self;
        let checklist = match checklist.finish() {
            Ok(checklist) => checklist,
            Err(cause) => {
                return Err(WindowsLifecycleExitRequired::bound(
                    WindowsLifecycleCause::Startup(cause),
                    windows.into_retirement(),
                    WindowsLifecycleTerminalEffects::unattached(),
                ));
            }
        };
        match windows.prepare_active() {
            Ok(windows) => Ok(WindowsActiveCommitPending { checklist, windows }),
            Err(failure) => Err(WindowsLifecycleExitRequired::from_terminal(
                failure,
                WindowsLifecycleTerminalEffects::unattached(),
            )),
        }
    }

    pub(super) fn abort(self, cause: StartupFailure) -> WindowsLifecycleExitRequired<'provider> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Startup(cause),
            self.windows.into_retirement(),
            WindowsLifecycleTerminalEffects::unattached(),
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
pub(super) struct WindowsActiveCommitPending<'provider> {
    checklist: CompletedStartupChecklist,
    windows: WindowsPreparedActiveTransition<'provider>,
}

impl<'provider> WindowsActiveCommitPending<'provider> {
    pub(super) fn commit_and_reread(self) -> WindowsLifecycleActiveCommitOutcome<'provider> {
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
                    WindowsLifecycleExitRequired::from_terminal(
                        failure,
                        WindowsLifecycleTerminalEffects::unattached(),
                    ),
                )
            }
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'provider> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
            WindowsLifecycleTerminalEffects::unattached(),
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
pub(super) enum WindowsLifecycleActiveCommitOutcome<'provider> {
    ListenerPending(WindowsListenerPending<'provider>),
    ReloadRequired(WindowsActiveReloadPending<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
}

/// Active commit ambiguity plus the checklist completed for that exact attempt.
#[must_use = "Active ambiguity must reload or retire"]
pub(super) struct WindowsActiveReloadPending<'provider> {
    checklist: CompletedStartupChecklist,
    windows: WindowsActiveReloadRequired<'provider>,
}

impl<'provider> WindowsActiveReloadPending<'provider> {
    pub(super) fn reload(self) -> WindowsLifecycleActiveReloadOutcome<'provider> {
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
                    WindowsLifecycleExitRequired::from_terminal(
                        failure,
                        WindowsLifecycleTerminalEffects::unattached(),
                    ),
                )
            }
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'provider> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
            WindowsLifecycleTerminalEffects::unattached(),
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
pub(super) enum WindowsLifecycleActiveReloadOutcome<'provider> {
    Revalidate(WindowsStartupAttempt<'provider>),
    ListenerPending(WindowsListenerPending<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
}

/// Exact Active authority before listener preparation is recorded.
#[must_use = "listeners must be prepared before SCM_RUNNING publication"]
pub(super) struct WindowsListenerPending<'provider> {
    policy: ListenerPendingPolicy,
    windows: WindowsActiveRunLease<'provider>,
}

impl<'provider> WindowsListenerPending<'provider> {
    pub(super) fn prepare_listeners(
        self,
        effects: WindowsLifecycleEffectAuthority,
    ) -> WindowsListenerPreparationOutcome<'provider> {
        match effects.prepare_listeners() {
            Ok(effects) => {
                WindowsListenerPreparationOutcome::ScmRunningPending(WindowsScmRunningPending {
                    policy: self.policy.record_listeners_prepared(),
                    windows: self.windows,
                    effects,
                })
            }
            Err(failure) => WindowsListenerPreparationOutcome::ExitRequired(effect_exit(
                failure,
                self.windows.into_retirement(),
            )),
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'provider> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
            WindowsLifecycleTerminalEffects::unattached(),
        )
    }
}

#[must_use = "listener preparation must retain both durable and effect authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsListenerPreparationOutcome<'provider> {
    ScmRunningPending(WindowsScmRunningPending<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
}

impl fmt::Debug for WindowsListenerPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsListenerPending([REDACTED])")
    }
}

/// Exact Active authority after listener preparation but before `SCM_RUNNING`.
#[must_use = "SCM_RUNNING publication must precede admission"]
pub(super) struct WindowsScmRunningPending<'provider> {
    policy: ScmRunningPendingPolicy,
    windows: WindowsActiveRunLease<'provider>,
    effects: WindowsListenersPreparedEffects,
}

impl<'provider> WindowsScmRunningPending<'provider> {
    pub(super) fn publish_scm_running(self) -> WindowsScmRunningPublicationOutcome<'provider> {
        let Self {
            policy,
            windows,
            effects,
        } = self;
        match effects.publish_scm_running() {
            Ok(effects) => {
                WindowsScmRunningPublicationOutcome::AdmissionPending(WindowsAdmissionPending {
                    policy: policy.record_scm_running_published(),
                    windows,
                    effects,
                })
            }
            Err(failure) => WindowsScmRunningPublicationOutcome::ExitRequired(effect_exit(
                failure,
                windows.into_retirement(),
            )),
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'provider> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
            self.effects.into_terminal(),
        )
    }
}

#[must_use = "SCM_RUNNING publication must retain both durable and effect authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsScmRunningPublicationOutcome<'provider> {
    AdmissionPending(WindowsAdmissionPending<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
}

impl fmt::Debug for WindowsScmRunningPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsScmRunningPending([REDACTED])")
    }
}

/// Exact Active authority after `SCM_RUNNING` but before admission opens.
#[must_use = "admission must be opened explicitly"]
pub(super) struct WindowsAdmissionPending<'provider> {
    policy: AdmissionPendingPolicy,
    windows: WindowsActiveRunLease<'provider>,
    effects: WindowsScmRunningEffects,
}

impl<'provider> WindowsAdmissionPending<'provider> {
    pub(super) fn establish_admission(self) -> WindowsAdmissionOpenOutcome<'provider> {
        let Self {
            policy,
            windows,
            effects,
        } = self;
        match effects.open_admission() {
            Ok(effects) => WindowsAdmissionOpenOutcome::Running(WindowsNoSecretService {
                policy: policy.open_admission(),
                windows,
                effects,
            }),
            Err(failure) => WindowsAdmissionOpenOutcome::ExitRequired(effect_exit(
                failure,
                windows.into_retirement(),
            )),
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'provider> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
            self.effects.into_terminal(),
        )
    }
}

#[must_use = "admission publication must retain both durable and effect authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsAdmissionOpenOutcome<'provider> {
    Running(WindowsNoSecretService<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
}

impl fmt::Debug for WindowsAdmissionPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsAdmissionPending([REDACTED])")
    }
}

/// Running no-secret service. Every work/session/cleanup decision delegates to
/// the single authority-independent [`RuntimePolicy`] implementation.
#[must_use = "the running service must reach Clean or checked retirement"]
pub(super) struct WindowsNoSecretService<'provider> {
    policy: RuntimePolicy,
    windows: WindowsActiveRunLease<'provider>,
    effects: WindowsAdmissionOpenEffects,
}

impl<'provider> WindowsNoSecretService<'provider> {
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

    pub(super) fn expected_cleanup_step(&self) -> Option<CleanupStep> {
        self.policy.expected_cleanup_step()
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

    pub(super) fn close_admission(self) -> WindowsAdmissionCloseOutcome<'provider> {
        let Self {
            policy,
            windows,
            effects,
        } = self;
        match effects.close_admission() {
            Ok(effects) => {
                WindowsAdmissionCloseOutcome::StopPending(WindowsAdmissionClosedService {
                    policy,
                    windows,
                    effects,
                })
            }
            Err(failure) => WindowsAdmissionCloseOutcome::ExitRequired(effect_exit(
                failure,
                windows.into_retirement(),
            )),
        }
    }

    pub(super) fn into_exit(
        self,
        cause: LifecycleError,
    ) -> WindowsLifecycleExitRequired<'provider> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
            self.effects.into_terminal(),
        )
    }

    pub(super) fn into_fatal_exit(self) -> WindowsLifecycleExitRequired<'provider> {
        let cause = match self.policy.state() {
            RuntimeState::Fatal(cause) => WindowsLifecycleCause::Fatal(cause),
            RuntimeState::Ready | RuntimeState::Draining(_) => {
                WindowsLifecycleCause::Lifecycle(LifecycleError::NotReady)
            }
        };
        WindowsLifecycleExitRequired::bound(
            cause,
            self.windows.into_retirement(),
            self.effects.into_terminal(),
        )
    }
}

impl fmt::Debug for WindowsNoSecretService<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsNoSecretService")
            .field("policy", &self.policy)
            .field("windows", &"[REDACTED]")
            .field("effects", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[must_use = "admission close must precede runtime stop policy"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsAdmissionCloseOutcome<'provider> {
    StopPending(WindowsAdmissionClosedService<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
}

#[must_use = "closed admission must advance to exact stop policy or terminal retirement"]
pub(super) struct WindowsAdmissionClosedService<'provider> {
    policy: RuntimePolicy,
    windows: WindowsActiveRunLease<'provider>,
    effects: WindowsAdmissionClosedEffects,
}

impl<'provider> WindowsAdmissionClosedService<'provider> {
    pub(super) fn begin_stop_and_reject(
        mut self,
        reason: StopReason,
    ) -> WindowsStopPolicyOutcome<'provider> {
        if let Err(cause) = self.policy.begin_stop(reason) {
            return WindowsStopPolicyOutcome::ExitRequired(self.into_exit(cause));
        }
        if let Err(cause) = self
            .policy
            .complete_cleanup_step(CleanupStep::RejectNewWork)
        {
            return WindowsStopPolicyOutcome::ExitRequired(self.into_exit(cause));
        }
        WindowsStopPolicyOutcome::InvalidationPending(WindowsInvalidationPending {
            policy: self.policy,
            windows: self.windows,
            effects: self.effects,
        })
    }

    fn into_exit(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'provider> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
            self.effects.into_terminal(),
        )
    }
}

#[must_use = "stop policy outcome must retain exact lifecycle authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsStopPolicyOutcome<'provider> {
    InvalidationPending(WindowsInvalidationPending<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
}

impl fmt::Debug for WindowsAdmissionClosedService<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsAdmissionClosedService([REDACTED])")
    }
}

#[must_use = "non-durable authority must be invalidated before listeners drain"]
pub(super) struct WindowsInvalidationPending<'provider> {
    policy: RuntimePolicy,
    windows: WindowsActiveRunLease<'provider>,
    effects: WindowsAdmissionClosedEffects,
}

impl<'provider> WindowsInvalidationPending<'provider> {
    pub(super) fn invalidate_non_durable_authority(
        mut self,
    ) -> WindowsInvalidationOutcome<'provider> {
        if let Err(cause) = self
            .policy
            .complete_cleanup_step(CleanupStep::InvalidateNonDurableAuthority)
        {
            return WindowsInvalidationOutcome::ExitRequired(WindowsLifecycleExitRequired::bound(
                WindowsLifecycleCause::Lifecycle(cause),
                self.windows.into_retirement(),
                self.effects.into_terminal(),
            ));
        }
        WindowsInvalidationOutcome::ListenerDrainPending(WindowsListenerDrainPending {
            policy: self.policy,
            windows: self.windows,
            effects: self.effects,
        })
    }
}

#[must_use = "invalidation outcome must retain exact lifecycle authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsInvalidationOutcome<'provider> {
    ListenerDrainPending(WindowsListenerDrainPending<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
}

impl fmt::Debug for WindowsInvalidationPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsInvalidationPending([REDACTED])")
    }
}

#[must_use = "listener drain must complete before remaining cleanup"]
pub(super) struct WindowsListenerDrainPending<'provider> {
    policy: RuntimePolicy,
    windows: WindowsActiveRunLease<'provider>,
    effects: WindowsAdmissionClosedEffects,
}

impl<'provider> WindowsListenerDrainPending<'provider> {
    pub(super) fn drain_listeners(self) -> WindowsListenerDrainOutcome<'provider> {
        let Self {
            mut policy,
            windows,
            effects,
        } = self;
        let effects = match effects.drain_listeners() {
            Ok(effects) => effects,
            Err(failure) => {
                return WindowsListenerDrainOutcome::ExitRequired(effect_exit(
                    failure,
                    windows.into_retirement(),
                ));
            }
        };
        if let Err(cause) = policy.complete_cleanup_step(CleanupStep::CloseAndDrainListeners) {
            return WindowsListenerDrainOutcome::ExitRequired(WindowsLifecycleExitRequired::bound(
                WindowsLifecycleCause::Lifecycle(cause),
                windows.into_retirement(),
                effects.into_terminal(),
            ));
        }
        WindowsListenerDrainOutcome::RemainingCleanup(WindowsRemainingCleanup {
            policy,
            windows,
            effects,
        })
    }
}

impl fmt::Debug for WindowsListenerDrainPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsListenerDrainPending([REDACTED])")
    }
}

#[must_use = "listener drain outcome must retain exact lifecycle authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsListenerDrainOutcome<'provider> {
    RemainingCleanup(WindowsRemainingCleanup<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
}

#[must_use = "remaining cleanup must reach Clean or terminal retirement"]
pub(super) struct WindowsRemainingCleanup<'provider> {
    policy: RuntimePolicy,
    windows: WindowsActiveRunLease<'provider>,
    effects: WindowsListenersDrainedEffects,
}

impl<'provider> WindowsRemainingCleanup<'provider> {
    pub(super) fn expected_cleanup_step(&self) -> Option<CleanupStep> {
        self.policy.expected_cleanup_step()
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

    pub(super) fn cancel_requests(&mut self) -> Result<(), LifecycleError> {
        self.policy
            .complete_cleanup_step(CleanupStep::CancelRequests)
    }

    pub(super) fn terminate_helpers(&mut self) -> Result<(), LifecycleError> {
        self.policy
            .complete_cleanup_step(CleanupStep::TerminateHelpers)
    }

    pub(super) fn reap_helpers(&mut self) -> Result<(), LifecycleError> {
        self.policy.complete_cleanup_step(CleanupStep::ReapHelpers)
    }

    pub(super) fn discard_user_tokens(&mut self) -> Result<(), LifecycleError> {
        self.policy
            .complete_cleanup_step(CleanupStep::DiscardUserTokens)
    }

    pub(super) fn flush_defined_durable_records(&mut self) -> Result<(), LifecycleError> {
        self.policy
            .complete_cleanup_step(CleanupStep::FlushDefinedDurableRecords)
    }

    pub(super) fn release_request_hardware_and_storage_handles(
        &mut self,
    ) -> Result<(), LifecycleError> {
        self.policy
            .complete_cleanup_step(CleanupStep::ReleaseRequestHardwareAndStorageHandles)
    }

    pub(super) fn prepare_clean(self) -> WindowsLifecycleCleanCommitOutcome<'provider> {
        let Self {
            policy,
            windows,
            effects,
        } = self;
        if let RuntimeState::Fatal(cause) = policy.state() {
            return WindowsLifecycleCleanCommitOutcome::ExitRequired(
                WindowsLifecycleExitRequired::bound(
                    WindowsLifecycleCause::Fatal(cause),
                    windows.into_retirement(),
                    effects.into_terminal(),
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
                        effects.into_terminal(),
                    ),
                );
            }
        };
        match windows.commit_clean() {
            WindowsCleanCommitOutcome::Clean(windows) => {
                WindowsLifecycleCleanCommitOutcome::ReleasePending(WindowsCleanReleasePending {
                    policy: policy.record_clean_committed(),
                    windows,
                    effects,
                })
            }
            WindowsCleanCommitOutcome::ReloadRequired(windows) => {
                WindowsLifecycleCleanCommitOutcome::ReloadRequired(WindowsCleanReloadPending {
                    policy,
                    windows,
                    effects,
                })
            }
            WindowsCleanCommitOutcome::Terminal(failure) => {
                WindowsLifecycleCleanCommitOutcome::ExitRequired(
                    WindowsLifecycleExitRequired::from_terminal(failure, effects.into_terminal()),
                )
            }
        }
    }

    pub(super) fn into_exit(
        self,
        cause: LifecycleError,
    ) -> WindowsLifecycleExitRequired<'provider> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
            self.effects.into_terminal(),
        )
    }
}

impl fmt::Debug for WindowsRemainingCleanup<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsRemainingCleanup([REDACTED])")
    }
}

#[must_use = "the Clean commit outcome retains exact lifecycle authority"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsLifecycleCleanCommitOutcome<'provider> {
    ReleasePending(WindowsCleanReleasePending<'provider>),
    ReloadRequired(WindowsCleanReloadPending<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
}

/// Ambiguous Clean commit paired with a pure Clean boundary that has not yet
/// advanced to release policy.
#[must_use = "Clean ambiguity must reload or retire"]
pub(super) struct WindowsCleanReloadPending<'provider> {
    policy: CleanBoundaryPolicy,
    windows: WindowsCleanReloadRequired<'provider>,
    effects: WindowsListenersDrainedEffects,
}

impl<'provider> WindowsCleanReloadPending<'provider> {
    pub(super) fn reload(self) -> WindowsLifecycleCleanReloadOutcome<'provider> {
        let Self {
            policy,
            windows,
            effects,
        } = self;
        match windows.reload() {
            WindowsCleanReloadOutcome::Clean(windows) => {
                WindowsLifecycleCleanReloadOutcome::ReleasePending(WindowsCleanReleasePending {
                    policy: policy.record_clean_committed(),
                    windows,
                    effects,
                })
            }
            WindowsCleanReloadOutcome::Terminal(failure) => {
                WindowsLifecycleCleanReloadOutcome::ExitRequired(
                    WindowsLifecycleExitRequired::from_terminal(failure, effects.into_terminal()),
                )
            }
        }
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'provider> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
            self.effects.into_terminal(),
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
pub(super) enum WindowsLifecycleCleanReloadOutcome<'provider> {
    ReleasePending(WindowsCleanReleasePending<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
}

/// Exact durable/OS Clean authority paired with the pure release boundary.
#[must_use = "the exact writer release must be checked"]
pub(super) struct WindowsCleanReleasePending<'provider> {
    policy: ReleaseBoundaryPolicy,
    windows: WindowsCleanWithWriter<'provider>,
    effects: WindowsListenersDrainedEffects,
}

impl<'provider> WindowsCleanReleasePending<'provider> {
    pub(super) fn release_writer(self) -> WindowsLifecycleWriterReleaseOutcome<'provider> {
        let Self {
            policy,
            windows,
            effects,
        } = self;
        complete_lifecycle_writer_release(policy, windows.stop(), effects)
    }

    #[cfg(test)]
    fn release_writer_with_post_release_fault_for_test(
        self,
    ) -> WindowsLifecycleWriterReleaseOutcome<'provider> {
        let Self {
            policy,
            windows,
            effects,
        } = self;
        complete_lifecycle_writer_release(
            policy,
            windows.stop_with_post_release_fault_for_test(),
            effects,
        )
    }

    pub(super) fn abort(self, cause: LifecycleError) -> WindowsLifecycleExitRequired<'provider> {
        WindowsLifecycleExitRequired::bound(
            WindowsLifecycleCause::Lifecycle(cause),
            self.windows.into_retirement(),
            self.effects.into_terminal(),
        )
    }
}

fn complete_lifecycle_writer_release(
    policy: ReleaseBoundaryPolicy,
    outcome: WindowsStopOutcome<'_>,
    effects: WindowsListenersDrainedEffects,
) -> WindowsLifecycleWriterReleaseOutcome<'_> {
    match outcome {
        WindowsStopOutcome::Stopped(windows) => {
            WindowsLifecycleWriterReleaseOutcome::ScmStopPending(WindowsScmStopPending {
                policy: policy.record_writer_released(),
                windows,
                effects,
            })
        }
        WindowsStopOutcome::Terminal(failure) => {
            WindowsLifecycleWriterReleaseOutcome::ExitRequired(
                WindowsLifecycleExitRequired::from_terminal(failure, effects.into_terminal()),
            )
        }
        WindowsStopOutcome::ReleasedNoReceipt(failure) => {
            WindowsLifecycleWriterReleaseOutcome::IrreversibleExit78(
                WindowsLifecycleIrreversibleExit78::released_no_receipt(
                    failure,
                    effects.into_terminal(),
                ),
            )
        }
        WindowsStopOutcome::PostReleaseTerminal(failure) => {
            WindowsLifecycleWriterReleaseOutcome::IrreversibleExit78(
                WindowsLifecycleIrreversibleExit78::post_release(failure, effects.into_terminal()),
            )
        }
    }
}

impl fmt::Debug for WindowsCleanReleasePending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsCleanReleasePending([REDACTED])")
    }
}

#[must_use = "writer release must advance to exact SCM_STOPPED publication"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsLifecycleWriterReleaseOutcome<'provider> {
    ScmStopPending(WindowsScmStopPending<'provider>),
    ExitRequired(WindowsLifecycleExitRequired<'provider>),
    IrreversibleExit78(WindowsLifecycleIrreversibleExit78<'provider>),
}

/// Durable stopped evidence held until `SCM_STOPPED` is published exactly once.
#[must_use = "SCM_STOPPED must be published or preserved as irreversible evidence"]
pub(super) struct WindowsScmStopPending<'provider> {
    policy: StoppedRuntimePolicy,
    windows: WindowsStoppedRunEvidence<'provider>,
    effects: WindowsListenersDrainedEffects,
}

impl<'provider> WindowsScmStopPending<'provider> {
    pub(super) fn publish_scm_stopped(self) -> WindowsLifecycleScmStopOutcome<'provider> {
        let Self {
            policy,
            windows,
            effects,
        } = self;
        match effects.publish_scm_stopped() {
            Ok(effects) => WindowsLifecycleScmStopOutcome::Stopped(WindowsLifecycleStopped {
                policy,
                windows,
                effects,
            }),
            Err(effects) => WindowsLifecycleScmStopOutcome::IrreversibleExit78(
                WindowsLifecycleIrreversibleExit78::post_writer_release_scm_stop(
                    WindowsPostWriterReleaseScmStopFailure { windows, effects },
                ),
            ),
        }
    }
}

impl fmt::Debug for WindowsScmStopPending<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsScmStopPending([REDACTED])")
    }
}

#[must_use = "SCM_STOPPED outcome must remain terminal"]
#[allow(clippy::large_enum_variant)] // Inline authority avoids fallible allocation.
pub(super) enum WindowsLifecycleScmStopOutcome<'provider> {
    Stopped(WindowsLifecycleStopped<'provider>),
    IrreversibleExit78(WindowsLifecycleIrreversibleExit78<'provider>),
}

/// Irreversible `SCM_STOPPED` failure after the durable writer was released.
#[must_use = "post-writer-release SCM failure is terminal exit-78 evidence"]
struct WindowsPostWriterReleaseScmStopFailure<'provider> {
    windows: WindowsStoppedRunEvidence<'provider>,
    effects: WindowsLifecycleEffectFailure,
}

impl WindowsPostWriterReleaseScmStopFailure<'_> {
    const fn cause(&self) -> WindowsLifecycleEffectCause {
        self.effects.cause()
    }
}

impl fmt::Debug for WindowsPostWriterReleaseScmStopFailure<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.windows, &self.effects);
        formatter.write_str("WindowsPostWriterReleaseScmStopFailure([REDACTED])")
    }
}

/// Sole normal terminal lifecycle evidence. It intentionally exposes no exit-78
/// method because normal stopped completion is not a fail-closed process exit.
#[must_use = "normal stopped evidence is terminal"]
pub(super) struct WindowsLifecycleStopped<'provider> {
    policy: StoppedRuntimePolicy,
    windows: WindowsStoppedRunEvidence<'provider>,
    effects: WindowsScmStoppedEffectEvidence,
}

impl WindowsLifecycleStopped<'_> {
    pub(super) const fn generation(&self) -> NonZeroU64 {
        self.windows.generation()
    }
}

impl fmt::Debug for WindowsLifecycleStopped<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let _ = (&self.policy, &self.effects);
        formatter.write_str("WindowsLifecycleStopped([REDACTED])")
    }
}

#[cfg(test)]
#[path = "windows_lifecycle_tests.rs"]
mod tests;
