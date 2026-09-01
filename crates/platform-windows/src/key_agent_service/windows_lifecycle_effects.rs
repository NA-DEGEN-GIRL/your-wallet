//! Sealed local effects for the dormant Windows lifecycle compositor.
//!
//! The production-compiled service backend remains unreachable from an
//! executable or durable provider. Its move-only source can only bind the exact
//! listener/SCM/admission resources supplied by the sibling service adapter.

#[cfg(not(test))]
use core::convert::Infallible;
use core::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};

#[path = "windows_service_effects.rs"]
mod windows_service_effects;

use self::windows_service_effects::WindowsServiceEffectBackend;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::key_agent_service) enum WindowsLifecycleEffectStage {
    PrepareListeners,
    PublishScmRunning,
    OpenAdmission,
    CloseAdmission,
    DrainListeners,
    PublishScmStopped,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::key_agent_service) enum WindowsLifecycleEffectDisposition {
    KnownNotApplied,
    Ambiguous,
    InvalidReceipt,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::key_agent_service) struct WindowsLifecycleEffectCause {
    stage: WindowsLifecycleEffectStage,
    disposition: WindowsLifecycleEffectDisposition,
}

impl WindowsLifecycleEffectCause {
    pub(super) const fn stage(self) -> WindowsLifecycleEffectStage {
        self.stage
    }

    pub(super) const fn disposition(self) -> WindowsLifecycleEffectDisposition {
        self.disposition
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct WindowsLifecycleEffectBinding(NonZeroU64);

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct WindowsLifecycleEffectBindingWitness(WindowsLifecycleEffectBinding);

impl fmt::Debug for WindowsLifecycleEffectBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsLifecycleEffectBinding([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EffectPurpose {
    PrepareListeners,
    PublishScmRunning,
    OpenAdmission,
    CloseAdmission,
    DrainListeners,
    PublishScmStopped,
}

impl EffectPurpose {
    const fn stage(self) -> WindowsLifecycleEffectStage {
        match self {
            Self::PrepareListeners => WindowsLifecycleEffectStage::PrepareListeners,
            Self::PublishScmRunning => WindowsLifecycleEffectStage::PublishScmRunning,
            Self::OpenAdmission => WindowsLifecycleEffectStage::OpenAdmission,
            Self::CloseAdmission => WindowsLifecycleEffectStage::CloseAdmission,
            Self::DrainListeners => WindowsLifecycleEffectStage::DrainListeners,
            Self::PublishScmStopped => WindowsLifecycleEffectStage::PublishScmStopped,
        }
    }

    #[cfg(test)]
    const fn different(self) -> Self {
        match self {
            Self::PrepareListeners => Self::PublishScmRunning,
            Self::PublishScmRunning => Self::OpenAdmission,
            Self::OpenAdmission => Self::CloseAdmission,
            Self::CloseAdmission => Self::DrainListeners,
            Self::DrainListeners => Self::PublishScmStopped,
            Self::PublishScmStopped => Self::PrepareListeners,
        }
    }
}

#[derive(Clone, Copy)]
struct EffectReceipt {
    binding: WindowsLifecycleEffectBinding,
    attempt: NonZeroU64,
    purpose: EffectPurpose,
}

enum BackendEffectOutcome {
    Receipt(EffectReceipt),
    KnownNotApplied,
    Ambiguous,
    InvalidReceipt,
}

enum SealedWindowsLifecycleEffectBackend {
    Service(WindowsServiceEffectBackend),
    #[cfg(test)]
    Fixture(FixtureWindowsLifecycleEffectBackend),
    #[cfg(not(test))]
    Unavailable(Infallible),
}

impl SealedWindowsLifecycleEffectBackend {
    fn execute(
        self,
        binding: WindowsLifecycleEffectBinding,
        attempt: NonZeroU64,
        purpose: EffectPurpose,
    ) -> (Self, BackendEffectOutcome) {
        match self {
            Self::Service(backend) => {
                let (backend, outcome) = backend.execute(binding, attempt, purpose);
                (Self::Service(backend), outcome)
            }
            #[cfg(test)]
            Self::Fixture(mut backend) => {
                let outcome = backend.execute(binding, attempt, purpose);
                (Self::Fixture(backend), outcome)
            }
            #[cfg(not(test))]
            Self::Unavailable(never) => match never {},
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FixtureWindowsLifecycleEffectFault {
    KnownNotApplied(WindowsLifecycleEffectStage),
    Ambiguous(WindowsLifecycleEffectStage),
    DuplicateReceipt(WindowsLifecycleEffectStage),
    WrongPurpose(WindowsLifecycleEffectStage),
}

#[cfg(test)]
struct FixtureWindowsLifecycleEffectBackend {
    fault: Option<FixtureWindowsLifecycleEffectFault>,
    cross_binding: Option<(WindowsLifecycleEffectStage, WindowsLifecycleEffectBinding)>,
}

#[cfg(test)]
impl FixtureWindowsLifecycleEffectBackend {
    fn execute(
        &mut self,
        binding: WindowsLifecycleEffectBinding,
        attempt: NonZeroU64,
        purpose: EffectPurpose,
    ) -> BackendEffectOutcome {
        let stage = purpose.stage();
        if let Some((fault_stage, foreign)) = self.cross_binding
            && fault_stage == stage
        {
            self.cross_binding = None;
            return BackendEffectOutcome::Receipt(EffectReceipt {
                binding: foreign,
                attempt,
                purpose,
            });
        }
        match self.fault.take() {
            Some(FixtureWindowsLifecycleEffectFault::KnownNotApplied(fault_stage))
                if fault_stage == stage =>
            {
                BackendEffectOutcome::KnownNotApplied
            }
            Some(FixtureWindowsLifecycleEffectFault::Ambiguous(fault_stage))
                if fault_stage == stage =>
            {
                BackendEffectOutcome::Ambiguous
            }
            Some(FixtureWindowsLifecycleEffectFault::DuplicateReceipt(fault_stage))
                if fault_stage == stage =>
            {
                let duplicate =
                    NonZeroU64::new(attempt.get().saturating_sub(1)).unwrap_or(NonZeroU64::MAX);
                BackendEffectOutcome::Receipt(EffectReceipt {
                    binding,
                    attempt: duplicate,
                    purpose,
                })
            }
            Some(FixtureWindowsLifecycleEffectFault::WrongPurpose(fault_stage))
                if fault_stage == stage =>
            {
                BackendEffectOutcome::Receipt(EffectReceipt {
                    binding,
                    attempt,
                    purpose: purpose.different(),
                })
            }
            other => {
                self.fault = other;
                BackendEffectOutcome::Receipt(EffectReceipt {
                    binding,
                    attempt,
                    purpose,
                })
            }
        }
    }
}

struct EffectCore {
    binding: WindowsLifecycleEffectBinding,
    next_attempt: NonZeroU64,
    backend: SealedWindowsLifecycleEffectBackend,
}

impl EffectCore {
    fn execute(self, purpose: EffectPurpose) -> Result<Self, WindowsLifecycleEffectFailure> {
        let Self {
            binding,
            next_attempt,
            backend,
        } = self;
        let (backend, outcome) = backend.execute(binding, next_attempt, purpose);
        let mut core = Self {
            binding,
            next_attempt,
            backend,
        };
        match outcome {
            BackendEffectOutcome::KnownNotApplied => {
                Err(core.fail(purpose, WindowsLifecycleEffectDisposition::KnownNotApplied))
            }
            BackendEffectOutcome::Ambiguous => {
                Err(core.fail(purpose, WindowsLifecycleEffectDisposition::Ambiguous))
            }
            BackendEffectOutcome::InvalidReceipt => {
                Err(core.fail(purpose, WindowsLifecycleEffectDisposition::InvalidReceipt))
            }
            BackendEffectOutcome::Receipt(receipt)
                if receipt.binding != core.binding
                    || receipt.attempt != core.next_attempt
                    || receipt.purpose != purpose =>
            {
                Err(core.fail(purpose, WindowsLifecycleEffectDisposition::InvalidReceipt))
            }
            BackendEffectOutcome::Receipt(_) => {
                let Some(next) = core
                    .next_attempt
                    .get()
                    .checked_add(1)
                    .and_then(NonZeroU64::new)
                else {
                    return Err(
                        core.fail(purpose, WindowsLifecycleEffectDisposition::InvalidReceipt)
                    );
                };
                core.next_attempt = next;
                Ok(core)
            }
        }
    }

    fn fail(
        self,
        purpose: EffectPurpose,
        disposition: WindowsLifecycleEffectDisposition,
    ) -> WindowsLifecycleEffectFailure {
        WindowsLifecycleEffectFailure {
            cause: WindowsLifecycleEffectCause {
                stage: purpose.stage(),
                disposition,
            },
            core: self,
        }
    }

    fn into_terminal(self) -> WindowsLifecycleTerminalEffects {
        WindowsLifecycleTerminalEffects::Attached(WindowsLifecycleAttachedTerminalEffects {
            cause: None,
            core: self,
        })
    }
}

impl fmt::Debug for EffectCore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EffectCore([REDACTED])")
    }
}

/// Move-only source authority for one local listener/SCM/admission lifecycle.
#[must_use = "the effect authority must attach to one exact Active lifecycle"]
pub(in crate::key_agent_service) struct WindowsLifecycleEffectAuthority {
    core: EffectCore,
}

impl WindowsLifecycleEffectAuthority {
    #[cfg(test)]
    pub(super) fn from_fixture(
        fault: Option<FixtureWindowsLifecycleEffectFault>,
    ) -> Result<Self, WindowsLifecycleEffectFixtureError> {
        Ok(Self {
            core: EffectCore {
                binding: allocate_fixture_binding()?,
                next_attempt: NonZeroU64::MIN,
                backend: SealedWindowsLifecycleEffectBackend::Fixture(
                    FixtureWindowsLifecycleEffectBackend {
                        fault,
                        cross_binding: None,
                    },
                ),
            },
        })
    }

    #[cfg(test)]
    pub(super) fn from_cross_bound_fixture(
        stage: WindowsLifecycleEffectStage,
        foreign: &Self,
    ) -> Result<Self, WindowsLifecycleEffectFixtureError> {
        let binding = allocate_fixture_binding()?;
        if binding == foreign.core.binding {
            return Err(WindowsLifecycleEffectFixtureError::BindingExhausted);
        }
        Ok(Self {
            core: EffectCore {
                binding,
                next_attempt: NonZeroU64::MIN,
                backend: SealedWindowsLifecycleEffectBackend::Fixture(
                    FixtureWindowsLifecycleEffectBackend {
                        fault: None,
                        cross_binding: Some((stage, foreign.core.binding)),
                    },
                ),
            },
        })
    }

    #[cfg(test)]
    pub(super) fn from_attempt_exhaustion_fixture()
    -> Result<Self, WindowsLifecycleEffectFixtureError> {
        Ok(Self {
            core: EffectCore {
                binding: allocate_fixture_binding()?,
                next_attempt: NonZeroU64::MAX,
                backend: SealedWindowsLifecycleEffectBackend::Fixture(
                    FixtureWindowsLifecycleEffectBackend {
                        fault: None,
                        cross_binding: None,
                    },
                ),
            },
        })
    }

    #[cfg(test)]
    pub(super) fn has_distinct_binding_for_test(&self, other: &Self) -> bool {
        self.core.binding != other.core.binding
    }

    #[cfg(test)]
    pub(super) const fn binding_witness_for_test(&self) -> WindowsLifecycleEffectBindingWitness {
        WindowsLifecycleEffectBindingWitness(self.core.binding)
    }

    pub(super) fn prepare_listeners(
        self,
    ) -> Result<WindowsListenersPreparedEffects, WindowsLifecycleEffectFailure> {
        self.core
            .execute(EffectPurpose::PrepareListeners)
            .map(|core| WindowsListenersPreparedEffects { core })
    }
}

impl fmt::Debug for WindowsLifecycleEffectAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsLifecycleEffectAuthority([REDACTED])")
    }
}

macro_rules! effect_state {
    ($name:ident, $debug_name:literal) => {
        #[must_use = "effect evidence must advance or remain terminal"]
        pub(super) struct $name {
            core: EffectCore,
        }

        impl $name {
            pub(super) fn into_terminal(self) -> WindowsLifecycleTerminalEffects {
                self.core.into_terminal()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($debug_name, "([REDACTED])"))
            }
        }
    };
}

effect_state!(
    WindowsListenersPreparedEffects,
    "WindowsListenersPreparedEffects"
);
effect_state!(WindowsScmRunningEffects, "WindowsScmRunningEffects");
effect_state!(WindowsAdmissionOpenEffects, "WindowsAdmissionOpenEffects");
effect_state!(
    WindowsAdmissionClosedEffects,
    "WindowsAdmissionClosedEffects"
);
effect_state!(
    WindowsListenersDrainedEffects,
    "WindowsListenersDrainedEffects"
);
effect_state!(
    WindowsScmStoppedEffectEvidence,
    "WindowsScmStoppedEffectEvidence"
);

impl WindowsListenersPreparedEffects {
    pub(super) fn publish_scm_running(
        self,
    ) -> Result<WindowsScmRunningEffects, WindowsLifecycleEffectFailure> {
        self.core
            .execute(EffectPurpose::PublishScmRunning)
            .map(|core| WindowsScmRunningEffects { core })
    }
}

impl WindowsScmRunningEffects {
    pub(super) fn open_admission(
        self,
    ) -> Result<WindowsAdmissionOpenEffects, WindowsLifecycleEffectFailure> {
        self.core
            .execute(EffectPurpose::OpenAdmission)
            .map(|core| WindowsAdmissionOpenEffects { core })
    }
}

impl WindowsAdmissionOpenEffects {
    pub(super) fn close_admission(
        self,
    ) -> Result<WindowsAdmissionClosedEffects, WindowsLifecycleEffectFailure> {
        self.core
            .execute(EffectPurpose::CloseAdmission)
            .map(|core| WindowsAdmissionClosedEffects { core })
    }
}

impl WindowsAdmissionClosedEffects {
    pub(super) fn drain_listeners(
        self,
    ) -> Result<WindowsListenersDrainedEffects, WindowsLifecycleEffectFailure> {
        self.core
            .execute(EffectPurpose::DrainListeners)
            .map(|core| WindowsListenersDrainedEffects { core })
    }
}

impl WindowsListenersDrainedEffects {
    pub(super) fn publish_scm_stopped(
        self,
    ) -> Result<WindowsScmStoppedEffectEvidence, WindowsLifecycleEffectFailure> {
        self.core
            .execute(EffectPurpose::PublishScmStopped)
            .map(|core| WindowsScmStoppedEffectEvidence { core })
    }
}

#[must_use = "effect failure evidence must remain attached to terminal lifecycle evidence"]
pub(super) struct WindowsLifecycleEffectFailure {
    cause: WindowsLifecycleEffectCause,
    core: EffectCore,
}

impl WindowsLifecycleEffectFailure {
    pub(super) const fn cause(&self) -> WindowsLifecycleEffectCause {
        self.cause
    }

    pub(super) fn into_terminal(self) -> WindowsLifecycleTerminalEffects {
        WindowsLifecycleTerminalEffects::Attached(WindowsLifecycleAttachedTerminalEffects {
            cause: Some(self.cause),
            core: self.core,
        })
    }

    #[cfg(test)]
    pub(super) fn matches_binding_witness_for_test(
        &self,
        witness: WindowsLifecycleEffectBindingWitness,
    ) -> bool {
        self.core.binding == witness.0
    }

    #[cfg(test)]
    pub(super) const fn retains_authority_for_test(&self) -> bool {
        self.core.binding.0.get() != 0
    }
}

impl fmt::Debug for WindowsLifecycleEffectFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsLifecycleEffectFailure")
            .field("cause", &self.cause)
            .field("authority", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

#[must_use = "terminal effects must remain attached to lifecycle evidence"]
pub(super) enum WindowsLifecycleTerminalEffects {
    Unattached,
    Attached(WindowsLifecycleAttachedTerminalEffects),
}

impl WindowsLifecycleTerminalEffects {
    pub(super) const fn unattached() -> Self {
        Self::Unattached
    }

    #[cfg(test)]
    pub(super) const fn is_attached_for_test(&self) -> bool {
        matches!(self, Self::Attached(_))
    }

    #[cfg(test)]
    pub(super) const fn failure_cause_for_test(&self) -> Option<WindowsLifecycleEffectCause> {
        match self {
            Self::Unattached => None,
            Self::Attached(effects) => effects.cause,
        }
    }
}

pub(super) struct WindowsLifecycleAttachedTerminalEffects {
    cause: Option<WindowsLifecycleEffectCause>,
    core: EffectCore,
}

impl fmt::Debug for WindowsLifecycleTerminalEffects {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unattached => formatter.write_str("WindowsLifecycleTerminalEffects::Unattached"),
            Self::Attached(effects) => {
                let _ = &effects.core;
                formatter
                    .debug_struct("WindowsLifecycleTerminalEffects::Attached")
                    .field("cause", &effects.cause)
                    .field("authority", &"[REDACTED]")
                    .finish_non_exhaustive()
            }
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WindowsLifecycleEffectFixtureError {
    BindingExhausted,
}

#[cfg(test)]
impl fmt::Display for WindowsLifecycleEffectFixtureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the lifecycle effect fixture binding space is exhausted")
    }
}

#[cfg(test)]
impl std::error::Error for WindowsLifecycleEffectFixtureError {}

static NEXT_EFFECT_BINDING: AtomicU64 = AtomicU64::new(1);

fn allocate_effect_binding() -> Option<WindowsLifecycleEffectBinding> {
    let value = NEXT_EFFECT_BINDING
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
            current.checked_add(1)
        })
        .ok()?;
    NonZeroU64::new(value).map(WindowsLifecycleEffectBinding)
}

#[cfg(test)]
fn allocate_fixture_binding()
-> Result<WindowsLifecycleEffectBinding, WindowsLifecycleEffectFixtureError> {
    allocate_effect_binding().ok_or(WindowsLifecycleEffectFixtureError::BindingExhausted)
}
