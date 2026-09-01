//! Dormant production adapter for the six Windows service lifecycle effects.
//!
//! The adapter owns one sealed SCM status authority and the exact RPC worker
//! typestate. It has no executable caller and cannot supply durable run-state
//! authority. Unit tests replace only the leaf driver; they exercise the same
//! consuming effect state machine without touching process-global RPC or SCM.

use core::fmt;
use std::num::NonZeroU64;

#[cfg(not(test))]
use crate::key_agent_service::WindowsScmStatusAuthority;
#[cfg(not(test))]
use crate::key_agent_service_rpc::{
    AdmissionClosedStatusRpcWorker, StatusRpcWorker, StatusRpcWorkerError,
};

use super::{
    BackendEffectOutcome, EffectCore, EffectPurpose, EffectReceipt,
    SealedWindowsLifecycleEffectBackend, WindowsLifecycleEffectAuthority,
    WindowsLifecycleEffectBinding,
};

/// Terminal failure to bind a production service-effect source to a lifecycle.
///
/// The consumed source remains owned here so an exhausted process-local binding
/// space can never discard the SCM/RPC authority or expose a retry surface.
pub(in crate::key_agent_service) struct WindowsServiceEffectSourceError {
    _source: WindowsServiceEffectSource,
}

impl fmt::Debug for WindowsServiceEffectSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsServiceEffectSourceError([REDACTED])")
    }
}

impl fmt::Display for WindowsServiceEffectSourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the Windows service effect binding space is exhausted")
    }
}

impl std::error::Error for WindowsServiceEffectSourceError {}

/// Single-use source for one exact listener/SCM/admission lifecycle.
#[must_use = "the service effect source must bind to one exact lifecycle"]
pub(in crate::key_agent_service) struct WindowsServiceEffectSource {
    backend: WindowsServiceEffectBackend,
}

impl WindowsServiceEffectSource {
    /// Seals one already-registered SCM status authority into a dormant source.
    #[cfg(not(test))]
    pub(in crate::key_agent_service) fn new(scm: WindowsScmStatusAuthority) -> Self {
        Self {
            backend: WindowsServiceEffectBackend::new(WindowsServiceEffectDriver::new(
                NativeWindowsServiceScmLeaf(scm),
                NativeWindowsServiceRpcLeaf,
            )),
        }
    }

    /// Consumes this source into the sole authority for its exact lifecycle.
    pub(in crate::key_agent_service) fn into_authority(
        self,
    ) -> Result<WindowsLifecycleEffectAuthority, WindowsServiceEffectSourceError> {
        let Some(binding) = super::allocate_effect_binding() else {
            return Err(WindowsServiceEffectSourceError { _source: self });
        };
        Ok(WindowsLifecycleEffectAuthority {
            core: EffectCore {
                binding,
                next_attempt: NonZeroU64::MIN,
                backend: SealedWindowsLifecycleEffectBackend::Service(self.backend),
            },
        })
    }

    #[cfg(test)]
    fn from_fixture(
        fault: Option<FixtureWindowsServiceEffectFault>,
    ) -> (Self, FixtureWindowsServiceEffectProbe) {
        let (driver, probe) = fixture_windows_service_effect_driver(fault);
        (
            Self {
                backend: WindowsServiceEffectBackend::new(driver),
            },
            probe,
        )
    }
}

impl fmt::Debug for WindowsServiceEffectSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsServiceEffectSource([REDACTED])")
    }
}

pub(super) struct WindowsServiceEffectBackend {
    stage: WindowsServiceEffectBackendStage,
    driver: SealedWindowsServiceEffectDriver,
}

impl WindowsServiceEffectBackend {
    fn new(driver: SealedWindowsServiceEffectDriver) -> Self {
        Self {
            stage: WindowsServiceEffectBackendStage::ListenerPreparationPending,
            driver,
        }
    }

    pub(super) fn execute(
        self,
        binding: WindowsLifecycleEffectBinding,
        attempt: NonZeroU64,
        purpose: EffectPurpose,
    ) -> (Self, BackendEffectOutcome) {
        let Self { stage, driver } = self;
        if stage.expected_purpose() != Some(purpose) {
            return (
                Self {
                    stage: WindowsServiceEffectBackendStage::Terminal,
                    driver,
                },
                BackendEffectOutcome::InvalidReceipt,
            );
        }

        let (driver, outcome) = match purpose {
            EffectPurpose::PrepareListeners => driver.prepare_listeners(binding, attempt),
            EffectPurpose::PublishScmRunning => driver.publish_scm_running(binding, attempt),
            EffectPurpose::OpenAdmission => driver.open_admission(binding, attempt),
            EffectPurpose::CloseAdmission => driver.close_admission(binding, attempt),
            EffectPurpose::DrainListeners => driver.drain_listeners(binding, attempt),
            EffectPurpose::PublishScmStopped => driver.publish_scm_stopped(binding, attempt),
        };
        let (next_stage, effect_outcome) = match outcome {
            WindowsServiceDriverOutcome::Receipt(receipt)
                if receipt.binding == binding
                    && receipt.attempt == attempt
                    && receipt.purpose == purpose =>
            {
                (
                    stage.after_success(),
                    BackendEffectOutcome::Receipt(receipt),
                )
            }
            WindowsServiceDriverOutcome::Receipt(_)
            | WindowsServiceDriverOutcome::InvalidReceipt => (
                WindowsServiceEffectBackendStage::Terminal,
                BackendEffectOutcome::InvalidReceipt,
            ),
            WindowsServiceDriverOutcome::KnownNotApplied => (
                WindowsServiceEffectBackendStage::Terminal,
                BackendEffectOutcome::KnownNotApplied,
            ),
            WindowsServiceDriverOutcome::Ambiguous => (
                WindowsServiceEffectBackendStage::Terminal,
                BackendEffectOutcome::Ambiguous,
            ),
        };
        let backend = Self {
            stage: next_stage,
            driver,
        };
        (backend, effect_outcome)
    }
}

impl fmt::Debug for WindowsServiceEffectBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WindowsServiceEffectBackend([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsServiceEffectBackendStage {
    ListenerPreparationPending,
    ListenersPrepared,
    ScmRunning,
    AdmissionOpen,
    AdmissionClosed,
    ListenersDrained,
    Stopped,
    Terminal,
}

impl WindowsServiceEffectBackendStage {
    const fn expected_purpose(self) -> Option<EffectPurpose> {
        match self {
            Self::ListenerPreparationPending => Some(EffectPurpose::PrepareListeners),
            Self::ListenersPrepared => Some(EffectPurpose::PublishScmRunning),
            Self::ScmRunning => Some(EffectPurpose::OpenAdmission),
            Self::AdmissionOpen => Some(EffectPurpose::CloseAdmission),
            Self::AdmissionClosed => Some(EffectPurpose::DrainListeners),
            Self::ListenersDrained => Some(EffectPurpose::PublishScmStopped),
            Self::Stopped | Self::Terminal => None,
        }
    }

    const fn after_success(self) -> Self {
        match self {
            Self::ListenerPreparationPending => Self::ListenersPrepared,
            Self::ListenersPrepared => Self::ScmRunning,
            Self::ScmRunning => Self::AdmissionOpen,
            Self::AdmissionOpen => Self::AdmissionClosed,
            Self::AdmissionClosed => Self::ListenersDrained,
            Self::ListenersDrained => Self::Stopped,
            Self::Stopped | Self::Terminal => Self::Terminal,
        }
    }
}

enum WindowsServiceDriverOutcome {
    Receipt(EffectReceipt),
    KnownNotApplied,
    Ambiguous,
    InvalidReceipt,
}

#[cfg(not(test))]
type SealedWindowsServiceEffectDriver =
    WindowsServiceEffectDriver<NativeWindowsServiceScmLeaf, NativeWindowsServiceRpcLeaf>;

#[cfg(test)]
type SealedWindowsServiceEffectDriver =
    WindowsServiceEffectDriver<FixtureWindowsServiceScmLeaf, FixtureWindowsServiceRpcLeaf>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WindowsServiceRpcError {
    Unavailable,
    RuntimeStateRetained,
}

trait WindowsServiceScmLeaf {
    fn publish_running(&mut self) -> bool;

    fn with_running_admission_gate<T>(&mut self, operation: impl FnOnce() -> T) -> Option<T>;

    fn publish_stopped(&mut self) -> bool;
}

trait WindowsServiceRpcLeaf {
    type Listening;
    type AdmissionClosed;

    fn start(&mut self) -> Result<Self::Listening, WindowsServiceRpcError>;

    fn begin_accepting(
        &mut self,
        worker: &mut Self::Listening,
    ) -> Result<(), WindowsServiceRpcError>;

    fn close_admission(&mut self, worker: Self::Listening) -> Self::AdmissionClosed;

    fn drain(&mut self, worker: Self::AdmissionClosed) -> Result<(), WindowsServiceRpcError>;
}

enum WindowsServiceWorker<R>
where
    R: WindowsServiceRpcLeaf,
{
    NotStarted,
    Listening(R::Listening),
    AdmissionClosed(R::AdmissionClosed),
    Drained,
    Retained,
}

struct WindowsServiceEffectDriver<S, R>
where
    R: WindowsServiceRpcLeaf,
{
    scm: S,
    rpc: R,
    worker: WindowsServiceWorker<R>,
}

impl<S, R> WindowsServiceEffectDriver<S, R>
where
    S: WindowsServiceScmLeaf,
    R: WindowsServiceRpcLeaf,
{
    fn new(scm: S, rpc: R) -> Self {
        Self {
            scm,
            rpc,
            worker: WindowsServiceWorker::NotStarted,
        }
    }

    fn prepare_listeners(
        self,
        binding: WindowsLifecycleEffectBinding,
        attempt: NonZeroU64,
    ) -> (Self, WindowsServiceDriverOutcome) {
        let Self {
            scm,
            mut rpc,
            worker,
        } = self;
        if !matches!(&worker, WindowsServiceWorker::NotStarted) {
            return (
                Self { scm, rpc, worker },
                WindowsServiceDriverOutcome::InvalidReceipt,
            );
        }
        match rpc.start() {
            Ok(worker) => (
                Self {
                    scm,
                    rpc,
                    worker: WindowsServiceWorker::Listening(worker),
                },
                WindowsServiceDriverOutcome::Receipt(EffectReceipt {
                    binding,
                    attempt,
                    purpose: EffectPurpose::PrepareListeners,
                }),
            ),
            Err(WindowsServiceRpcError::Unavailable) => (
                Self {
                    scm,
                    rpc,
                    worker: WindowsServiceWorker::NotStarted,
                },
                WindowsServiceDriverOutcome::KnownNotApplied,
            ),
            Err(WindowsServiceRpcError::RuntimeStateRetained) => (
                Self {
                    scm,
                    rpc,
                    worker: WindowsServiceWorker::Retained,
                },
                WindowsServiceDriverOutcome::Ambiguous,
            ),
        }
    }

    fn publish_scm_running(
        self,
        binding: WindowsLifecycleEffectBinding,
        attempt: NonZeroU64,
    ) -> (Self, WindowsServiceDriverOutcome) {
        let Self {
            mut scm,
            rpc,
            worker,
        } = self;
        if !matches!(&worker, WindowsServiceWorker::Listening(_)) {
            return (
                Self { scm, rpc, worker },
                WindowsServiceDriverOutcome::InvalidReceipt,
            );
        }
        let outcome = if scm.publish_running() {
            WindowsServiceDriverOutcome::Receipt(EffectReceipt {
                binding,
                attempt,
                purpose: EffectPurpose::PublishScmRunning,
            })
        } else {
            WindowsServiceDriverOutcome::Ambiguous
        };
        (Self { scm, rpc, worker }, outcome)
    }

    fn open_admission(
        self,
        binding: WindowsLifecycleEffectBinding,
        attempt: NonZeroU64,
    ) -> (Self, WindowsServiceDriverOutcome) {
        let Self {
            mut scm,
            mut rpc,
            worker,
        } = self;
        let WindowsServiceWorker::Listening(mut worker) = worker else {
            return (
                Self { scm, rpc, worker },
                WindowsServiceDriverOutcome::InvalidReceipt,
            );
        };
        let gated = scm.with_running_admission_gate(|| rpc.begin_accepting(&mut worker));
        if !matches!(gated, Some(Ok(()))) {
            let worker = rpc.close_admission(worker);
            return (
                Self {
                    scm,
                    rpc,
                    worker: WindowsServiceWorker::AdmissionClosed(worker),
                },
                WindowsServiceDriverOutcome::Ambiguous,
            );
        }
        (
            Self {
                scm,
                rpc,
                worker: WindowsServiceWorker::Listening(worker),
            },
            WindowsServiceDriverOutcome::Receipt(EffectReceipt {
                binding,
                attempt,
                purpose: EffectPurpose::OpenAdmission,
            }),
        )
    }

    fn close_admission(
        self,
        binding: WindowsLifecycleEffectBinding,
        attempt: NonZeroU64,
    ) -> (Self, WindowsServiceDriverOutcome) {
        let Self {
            scm,
            mut rpc,
            worker,
        } = self;
        let WindowsServiceWorker::Listening(worker) = worker else {
            return (
                Self { scm, rpc, worker },
                WindowsServiceDriverOutcome::InvalidReceipt,
            );
        };
        let worker = rpc.close_admission(worker);
        (
            Self {
                scm,
                rpc,
                worker: WindowsServiceWorker::AdmissionClosed(worker),
            },
            WindowsServiceDriverOutcome::Receipt(EffectReceipt {
                binding,
                attempt,
                purpose: EffectPurpose::CloseAdmission,
            }),
        )
    }

    fn drain_listeners(
        self,
        binding: WindowsLifecycleEffectBinding,
        attempt: NonZeroU64,
    ) -> (Self, WindowsServiceDriverOutcome) {
        let Self {
            scm,
            mut rpc,
            worker,
        } = self;
        let WindowsServiceWorker::AdmissionClosed(worker) = worker else {
            return (
                Self { scm, rpc, worker },
                WindowsServiceDriverOutcome::InvalidReceipt,
            );
        };
        match rpc.drain(worker) {
            Ok(()) => (
                Self {
                    scm,
                    rpc,
                    worker: WindowsServiceWorker::Drained,
                },
                WindowsServiceDriverOutcome::Receipt(EffectReceipt {
                    binding,
                    attempt,
                    purpose: EffectPurpose::DrainListeners,
                }),
            ),
            Err(
                WindowsServiceRpcError::Unavailable | WindowsServiceRpcError::RuntimeStateRetained,
            ) => (
                Self {
                    scm,
                    rpc,
                    worker: WindowsServiceWorker::Retained,
                },
                WindowsServiceDriverOutcome::Ambiguous,
            ),
        }
    }

    fn publish_scm_stopped(
        self,
        binding: WindowsLifecycleEffectBinding,
        attempt: NonZeroU64,
    ) -> (Self, WindowsServiceDriverOutcome) {
        let Self {
            mut scm,
            rpc,
            worker,
        } = self;
        if !matches!(&worker, WindowsServiceWorker::Drained) {
            return (
                Self { scm, rpc, worker },
                WindowsServiceDriverOutcome::InvalidReceipt,
            );
        }
        let outcome = if scm.publish_stopped() {
            WindowsServiceDriverOutcome::Receipt(EffectReceipt {
                binding,
                attempt,
                purpose: EffectPurpose::PublishScmStopped,
            })
        } else {
            WindowsServiceDriverOutcome::Ambiguous
        };
        (Self { scm, rpc, worker }, outcome)
    }
}

#[cfg(not(test))]
struct NativeWindowsServiceScmLeaf(WindowsScmStatusAuthority);

#[cfg(not(test))]
impl WindowsServiceScmLeaf for NativeWindowsServiceScmLeaf {
    fn publish_running(&mut self) -> bool {
        self.0.publish_running()
    }

    fn with_running_admission_gate<T>(&mut self, operation: impl FnOnce() -> T) -> Option<T> {
        self.0.with_running_admission_gate(operation)
    }

    fn publish_stopped(&mut self) -> bool {
        self.0.publish_stopped()
    }
}

#[cfg(not(test))]
struct NativeWindowsServiceRpcLeaf;

#[cfg(not(test))]
impl WindowsServiceRpcLeaf for NativeWindowsServiceRpcLeaf {
    type Listening = StatusRpcWorker;
    type AdmissionClosed = AdmissionClosedStatusRpcWorker;

    fn start(&mut self) -> Result<Self::Listening, WindowsServiceRpcError> {
        StatusRpcWorker::start().map_err(map_status_rpc_error)
    }

    fn begin_accepting(
        &mut self,
        worker: &mut Self::Listening,
    ) -> Result<(), WindowsServiceRpcError> {
        worker.begin_accepting().map_err(map_status_rpc_error)
    }

    fn close_admission(&mut self, worker: Self::Listening) -> Self::AdmissionClosed {
        worker.close_admission()
    }

    fn drain(&mut self, worker: Self::AdmissionClosed) -> Result<(), WindowsServiceRpcError> {
        worker.drain().map_err(map_status_rpc_error)
    }
}

#[cfg(not(test))]
const fn map_status_rpc_error(error: StatusRpcWorkerError) -> WindowsServiceRpcError {
    match error {
        StatusRpcWorkerError::Unavailable => WindowsServiceRpcError::Unavailable,
        StatusRpcWorkerError::RuntimeStateRetained => WindowsServiceRpcError::RuntimeStateRetained,
    }
}

#[cfg(test)]
use std::{cell::RefCell, rc::Rc};

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureWindowsServiceEffectFault {
    StartUnavailable,
    StartRuntimeStateRetained,
    PublishScmRunningFalse,
    RunningAdmissionGateRejected,
    BeginAdmissionError,
    DrainUnavailable,
    DrainRuntimeStateRetained,
    PublishScmStoppedFalse,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureWindowsServiceResourceState {
    NotStarted,
    ListeningAdmissionClosed,
    ListeningAdmissionOpen,
    AdmissionClosed,
    Drained,
    TerminalRetained,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureWindowsServiceEffectEvent {
    Stage(super::WindowsLifecycleEffectStage),
    AdmissionBecameOpen,
    AdmissionFailClosed,
    EpochsInvalidated,
}

#[cfg(test)]
struct FixtureWindowsServiceEffectObservation {
    fault: Option<FixtureWindowsServiceEffectFault>,
    events: Vec<FixtureWindowsServiceEffectEvent>,
    resource: FixtureWindowsServiceResourceState,
}

#[cfg(test)]
type FixtureWindowsServiceEffectProbe = Rc<RefCell<FixtureWindowsServiceEffectObservation>>;

#[cfg(test)]
struct FixtureWindowsServiceScmLeaf {
    probe: FixtureWindowsServiceEffectProbe,
}

#[cfg(test)]
struct FixtureWindowsServiceRpcLeaf {
    probe: FixtureWindowsServiceEffectProbe,
}

#[cfg(test)]
struct FixtureListeningStatusRpcWorker;

#[cfg(test)]
struct FixtureAdmissionClosedStatusRpcWorker;

#[cfg(test)]
fn fixture_windows_service_effect_driver(
    fault: Option<FixtureWindowsServiceEffectFault>,
) -> (
    SealedWindowsServiceEffectDriver,
    FixtureWindowsServiceEffectProbe,
) {
    let probe = Rc::new(RefCell::new(FixtureWindowsServiceEffectObservation {
        fault,
        events: Vec::new(),
        resource: FixtureWindowsServiceResourceState::NotStarted,
    }));
    (
        WindowsServiceEffectDriver::new(
            FixtureWindowsServiceScmLeaf {
                probe: Rc::clone(&probe),
            },
            FixtureWindowsServiceRpcLeaf {
                probe: Rc::clone(&probe),
            },
        ),
        probe,
    )
}

#[cfg(test)]
fn fixture_take_fault(
    probe: &FixtureWindowsServiceEffectProbe,
    expected: FixtureWindowsServiceEffectFault,
) -> bool {
    let mut observation = probe.borrow_mut();
    if observation.fault == Some(expected) {
        observation.fault = None;
        true
    } else {
        false
    }
}

#[cfg(test)]
fn fixture_record_stage(
    probe: &FixtureWindowsServiceEffectProbe,
    stage: super::WindowsLifecycleEffectStage,
) {
    probe
        .borrow_mut()
        .events
        .push(FixtureWindowsServiceEffectEvent::Stage(stage));
}

#[cfg(test)]
fn fixture_set_resource(
    probe: &FixtureWindowsServiceEffectProbe,
    resource: FixtureWindowsServiceResourceState,
) {
    probe.borrow_mut().resource = resource;
}

#[cfg(test)]
impl WindowsServiceScmLeaf for FixtureWindowsServiceScmLeaf {
    fn publish_running(&mut self) -> bool {
        fixture_record_stage(
            &self.probe,
            super::WindowsLifecycleEffectStage::PublishScmRunning,
        );
        if self.probe.borrow().resource
            != FixtureWindowsServiceResourceState::ListeningAdmissionClosed
        {
            fixture_set_resource(
                &self.probe,
                FixtureWindowsServiceResourceState::TerminalRetained,
            );
            return false;
        }
        !fixture_take_fault(
            &self.probe,
            FixtureWindowsServiceEffectFault::PublishScmRunningFalse,
        )
    }

    fn with_running_admission_gate<T>(&mut self, operation: impl FnOnce() -> T) -> Option<T> {
        fixture_record_stage(
            &self.probe,
            super::WindowsLifecycleEffectStage::OpenAdmission,
        );
        if self.probe.borrow().resource
            != FixtureWindowsServiceResourceState::ListeningAdmissionClosed
            || fixture_take_fault(
                &self.probe,
                FixtureWindowsServiceEffectFault::RunningAdmissionGateRejected,
            )
        {
            return None;
        }
        Some(operation())
    }

    fn publish_stopped(&mut self) -> bool {
        fixture_record_stage(
            &self.probe,
            super::WindowsLifecycleEffectStage::PublishScmStopped,
        );
        if self.probe.borrow().resource != FixtureWindowsServiceResourceState::Drained {
            fixture_set_resource(
                &self.probe,
                FixtureWindowsServiceResourceState::TerminalRetained,
            );
            return false;
        }
        !fixture_take_fault(
            &self.probe,
            FixtureWindowsServiceEffectFault::PublishScmStoppedFalse,
        )
    }
}

#[cfg(test)]
impl WindowsServiceRpcLeaf for FixtureWindowsServiceRpcLeaf {
    type Listening = FixtureListeningStatusRpcWorker;
    type AdmissionClosed = FixtureAdmissionClosedStatusRpcWorker;

    fn start(&mut self) -> Result<Self::Listening, WindowsServiceRpcError> {
        fixture_record_stage(
            &self.probe,
            super::WindowsLifecycleEffectStage::PrepareListeners,
        );
        if self.probe.borrow().resource != FixtureWindowsServiceResourceState::NotStarted {
            fixture_set_resource(
                &self.probe,
                FixtureWindowsServiceResourceState::TerminalRetained,
            );
            return Err(WindowsServiceRpcError::RuntimeStateRetained);
        }
        if fixture_take_fault(
            &self.probe,
            FixtureWindowsServiceEffectFault::StartUnavailable,
        ) {
            return Err(WindowsServiceRpcError::Unavailable);
        }
        if fixture_take_fault(
            &self.probe,
            FixtureWindowsServiceEffectFault::StartRuntimeStateRetained,
        ) {
            fixture_set_resource(
                &self.probe,
                FixtureWindowsServiceResourceState::TerminalRetained,
            );
            return Err(WindowsServiceRpcError::RuntimeStateRetained);
        }
        fixture_set_resource(
            &self.probe,
            FixtureWindowsServiceResourceState::ListeningAdmissionClosed,
        );
        Ok(FixtureListeningStatusRpcWorker)
    }

    fn begin_accepting(
        &mut self,
        _worker: &mut Self::Listening,
    ) -> Result<(), WindowsServiceRpcError> {
        if self.probe.borrow().resource
            != FixtureWindowsServiceResourceState::ListeningAdmissionClosed
        {
            return Err(WindowsServiceRpcError::RuntimeStateRetained);
        }
        if fixture_take_fault(
            &self.probe,
            FixtureWindowsServiceEffectFault::BeginAdmissionError,
        ) {
            return Err(WindowsServiceRpcError::Unavailable);
        }
        self.probe
            .borrow_mut()
            .events
            .push(FixtureWindowsServiceEffectEvent::AdmissionBecameOpen);
        fixture_set_resource(
            &self.probe,
            FixtureWindowsServiceResourceState::ListeningAdmissionOpen,
        );
        Ok(())
    }

    fn close_admission(&mut self, _worker: Self::Listening) -> Self::AdmissionClosed {
        let resource = self.probe.borrow().resource;
        if resource == FixtureWindowsServiceResourceState::ListeningAdmissionOpen {
            fixture_record_stage(
                &self.probe,
                super::WindowsLifecycleEffectStage::CloseAdmission,
            );
        } else {
            self.probe
                .borrow_mut()
                .events
                .push(FixtureWindowsServiceEffectEvent::AdmissionFailClosed);
        }
        fixture_set_resource(
            &self.probe,
            FixtureWindowsServiceResourceState::AdmissionClosed,
        );
        FixtureAdmissionClosedStatusRpcWorker
    }

    fn drain(&mut self, _worker: Self::AdmissionClosed) -> Result<(), WindowsServiceRpcError> {
        if self.probe.borrow().resource != FixtureWindowsServiceResourceState::AdmissionClosed {
            fixture_set_resource(
                &self.probe,
                FixtureWindowsServiceResourceState::TerminalRetained,
            );
            return Err(WindowsServiceRpcError::RuntimeStateRetained);
        }
        self.probe
            .borrow_mut()
            .events
            .push(FixtureWindowsServiceEffectEvent::EpochsInvalidated);
        fixture_record_stage(
            &self.probe,
            super::WindowsLifecycleEffectStage::DrainListeners,
        );
        if fixture_take_fault(
            &self.probe,
            FixtureWindowsServiceEffectFault::DrainUnavailable,
        ) {
            fixture_set_resource(
                &self.probe,
                FixtureWindowsServiceResourceState::TerminalRetained,
            );
            return Err(WindowsServiceRpcError::Unavailable);
        }
        if fixture_take_fault(
            &self.probe,
            FixtureWindowsServiceEffectFault::DrainRuntimeStateRetained,
        ) {
            fixture_set_resource(
                &self.probe,
                FixtureWindowsServiceResourceState::TerminalRetained,
            );
            return Err(WindowsServiceRpcError::RuntimeStateRetained);
        }
        fixture_set_resource(&self.probe, FixtureWindowsServiceResourceState::Drained);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io};

    use crate::key_agent_service::durable_run_state::{
        InstallationIdentity, RecoveryRequired, RunStateAuthenticationProvider,
        install_windows_runtime_clean_fixture,
    };
    use crate::key_agent_service::lifecycle_core::{
        LifecycleError, NoSecretStartupRequirement, StartupObservation, StopReason,
    };
    use crate::key_agent_service::run_state_root::RuntimePairFixture;
    use crate::key_agent_service::windows_lifecycle::{
        WindowsActiveCommitPending, WindowsAdmissionCloseOutcome, WindowsAdmissionOpenOutcome,
        WindowsInvalidationOutcome, WindowsLifecycleActiveCommitOutcome,
        WindowsLifecycleCleanCommitOutcome, WindowsLifecycleExitRequired,
        WindowsLifecycleIrreversibleCause, WindowsLifecycleScmStopOutcome,
        WindowsLifecycleWriterReleaseOutcome, WindowsListenerDrainOutcome, WindowsListenerPending,
        WindowsListenerPreparationOutcome, WindowsNoSecretService, WindowsRemainingCleanup,
        WindowsScmRunningPublicationOutcome, WindowsStartupAttempt, WindowsStopPolicyOutcome,
        begin_windows_lifecycle,
    };

    use super::super::{
        WindowsAdmissionOpenEffects, WindowsLifecycleEffectAuthority,
        WindowsLifecycleEffectDisposition, WindowsLifecycleEffectFailure,
        WindowsLifecycleEffectStage, WindowsListenersDrainedEffects, WindowsScmRunningEffects,
    };
    use super::*;

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    trait AmbiguousIfClone<Marker> {
        fn marker() {}
    }

    impl<T> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    trait AmbiguousIfCopy<Marker> {
        fn marker() {}
    }

    impl<T> AmbiguousIfCopy<()> for T {}
    impl<T: Copy> AmbiguousIfCopy<u8> for T {}

    macro_rules! assert_move_only {
        ($type:ty) => {
            let _ = <$type as AmbiguousIfClone<_>>::marker;
            let _ = <$type as AmbiguousIfCopy<_>>::marker;
        };
    }

    fn fixture_effects(
        fault: Option<FixtureWindowsServiceEffectFault>,
    ) -> TestResult<(
        WindowsLifecycleEffectAuthority,
        FixtureWindowsServiceEffectProbe,
    )> {
        let (source, probe) = WindowsServiceEffectSource::from_fixture(fault);
        Ok((source.into_authority()?, probe))
    }

    fn effect_failure(
        failure: WindowsLifecycleEffectFailure,
        stage: WindowsLifecycleEffectStage,
        disposition: WindowsLifecycleEffectDisposition,
    ) -> WindowsLifecycleEffectFailure {
        assert_eq!(failure.cause().stage(), stage);
        assert_eq!(failure.cause().disposition(), disposition);
        failure
    }

    fn prepare_and_publish_running(
        effects: WindowsLifecycleEffectAuthority,
    ) -> TestResult<WindowsScmRunningEffects> {
        let prepared = effects.prepare_listeners().map_err(|failure| {
            io::Error::other(format!("listener preparation failed: {failure:?}"))
        })?;
        prepared
            .publish_scm_running()
            .map_err(|failure| {
                io::Error::other(format!("SCM_RUNNING publication failed: {failure:?}"))
            })
            .map_err(Into::into)
    }

    fn open_admission(
        effects: WindowsScmRunningEffects,
    ) -> TestResult<WindowsAdmissionOpenEffects> {
        effects.open_admission().map_err(|failure| {
            io::Error::other(format!("admission open failed: {failure:?}")).into()
        })
    }

    fn close_and_drain(
        effects: WindowsAdmissionOpenEffects,
    ) -> TestResult<WindowsListenersDrainedEffects> {
        let closed = effects
            .close_admission()
            .map_err(|failure| io::Error::other(format!("admission close failed: {failure:?}")))?;
        closed.drain_listeners().map_err(|failure| {
            io::Error::other(format!("listener drain failed: {failure:?}")).into()
        })
    }

    fn test_installation(byte: u8) -> Result<InstallationIdentity, RecoveryRequired> {
        InstallationIdentity::from_fixed_bytes([byte; 32])
    }

    fn test_provider(
        installation: InstallationIdentity,
        byte: u8,
    ) -> Result<RunStateAuthenticationProvider, RecoveryRequired> {
        RunStateAuthenticationProvider::from_fixture_bytes(installation, [byte; 32])
    }

    fn clean_fixture(
        byte: u8,
    ) -> TestResult<(
        RuntimePairFixture,
        InstallationIdentity,
        RunStateAuthenticationProvider,
    )> {
        let fixture = RuntimePairFixture::new()?;
        let installation = test_installation(byte)?;
        let provider = test_provider(installation, byte.wrapping_add(1))?;
        install_windows_runtime_clean_fixture(&fixture, installation, &provider)?;
        Ok((fixture, installation, provider))
    }

    fn assert_exit78(exit: WindowsLifecycleExitRequired<'_>) -> TestResult {
        match exit.retire_checked() {
            Ok(receipt) => {
                assert_eq!(receipt.code(), 78);
                Ok(())
            }
            Err(failure) => Err(io::Error::other(format!(
                "checked retirement became irreversible: {failure:?}"
            ))
            .into()),
        }
    }

    fn begin<'provider>(
        fixture: &RuntimePairFixture,
        provider: &'provider mut RunStateAuthenticationProvider,
    ) -> TestResult<WindowsStartupAttempt<'provider>> {
        match begin_windows_lifecycle(fixture.acquire_writer()?, provider.runtime_authority()) {
            Ok(startup) => Ok(startup),
            Err(exit) => {
                assert_exit78(exit)?;
                Err(io::Error::other("clean fixture failed lifecycle startup").into())
            }
        }
    }

    #[allow(clippy::result_large_err)]
    fn complete_checklist(
        mut startup: WindowsStartupAttempt<'_>,
    ) -> Result<WindowsActiveCommitPending<'_>, WindowsLifecycleExitRequired<'_>> {
        for requirement in NoSecretStartupRequirement::ALL {
            if let Err(cause) = startup.observe(requirement, StartupObservation::Verified) {
                return Err(startup.abort(cause));
            }
        }
        startup.finish()
    }

    fn listener_pending<'provider>(
        fixture: &RuntimePairFixture,
        provider: &'provider mut RunStateAuthenticationProvider,
    ) -> TestResult<WindowsListenerPending<'provider>> {
        let startup = begin(fixture, provider)?;
        let prepared = match complete_checklist(startup) {
            Ok(prepared) => prepared,
            Err(exit) => {
                assert_exit78(exit)?;
                return Err(
                    io::Error::other("verified checklist failed Active preparation").into(),
                );
            }
        };
        match prepared.commit_and_reread() {
            WindowsLifecycleActiveCommitOutcome::ListenerPending(listener) => Ok(listener),
            WindowsLifecycleActiveCommitOutcome::ReloadRequired(reload) => {
                assert_exit78(reload.abort(LifecycleError::NotReady))?;
                Err(io::Error::other("fault-free Active commit required reload").into())
            }
            WindowsLifecycleActiveCommitOutcome::ExitRequired(exit) => {
                assert_exit78(exit)?;
                Err(io::Error::other("fault-free Active commit became terminal").into())
            }
        }
    }

    fn ready_service_with_effects<'provider>(
        fixture: &RuntimePairFixture,
        provider: &'provider mut RunStateAuthenticationProvider,
        effects: WindowsLifecycleEffectAuthority,
    ) -> TestResult<WindowsNoSecretService<'provider>> {
        let scm = match listener_pending(fixture, provider)?.prepare_listeners(effects) {
            WindowsListenerPreparationOutcome::ScmRunningPending(scm) => scm,
            WindowsListenerPreparationOutcome::ExitRequired(exit) => {
                assert_exit78(exit)?;
                return Err(io::Error::other("listener service effect failed").into());
            }
        };
        let admission = match scm.publish_scm_running() {
            WindowsScmRunningPublicationOutcome::AdmissionPending(admission) => admission,
            WindowsScmRunningPublicationOutcome::ExitRequired(exit) => {
                assert_exit78(exit)?;
                return Err(io::Error::other("SCM_RUNNING service effect failed").into());
            }
        };
        match admission.establish_admission() {
            WindowsAdmissionOpenOutcome::Running(service) => Ok(service),
            WindowsAdmissionOpenOutcome::ExitRequired(exit) => {
                assert_exit78(exit)?;
                Err(io::Error::other("admission service effect failed").into())
            }
        }
    }

    fn begin_listener_drain(
        service: WindowsNoSecretService<'_>,
    ) -> TestResult<crate::key_agent_service::windows_lifecycle::WindowsListenerDrainPending<'_>>
    {
        let closed = match service.close_admission() {
            WindowsAdmissionCloseOutcome::StopPending(closed) => closed,
            WindowsAdmissionCloseOutcome::ExitRequired(exit) => {
                assert_exit78(exit)?;
                return Err(io::Error::other("admission close service effect failed").into());
            }
        };
        let invalidation = match closed.begin_stop_and_reject(StopReason::ScmStop) {
            WindowsStopPolicyOutcome::InvalidationPending(invalidation) => invalidation,
            WindowsStopPolicyOutcome::ExitRequired(exit) => {
                assert_exit78(exit)?;
                return Err(io::Error::other("stop/reject policy failed").into());
            }
        };
        match invalidation.invalidate_non_durable_authority() {
            WindowsInvalidationOutcome::ListenerDrainPending(drain) => Ok(drain),
            WindowsInvalidationOutcome::ExitRequired(exit) => {
                assert_exit78(exit)?;
                Err(io::Error::other("authority invalidation failed").into())
            }
        }
    }

    fn complete_remaining_cleanup(
        mut cleanup: WindowsRemainingCleanup<'_>,
    ) -> TestResult<WindowsRemainingCleanup<'_>> {
        cleanup.cancel_requests()?;
        cleanup.terminate_helpers()?;
        cleanup.reap_helpers()?;
        cleanup.discard_user_tokens()?;
        cleanup.flush_defined_durable_records()?;
        cleanup.release_request_hardware_and_storage_handles()?;
        Ok(cleanup)
    }

    fn clean_release_pending_with_effects<'provider>(
        fixture: &RuntimePairFixture,
        provider: &'provider mut RunStateAuthenticationProvider,
        effects: WindowsLifecycleEffectAuthority,
    ) -> TestResult<
        crate::key_agent_service::windows_lifecycle::WindowsCleanReleasePending<'provider>,
    > {
        let service = ready_service_with_effects(fixture, provider, effects)?;
        let cleanup = match begin_listener_drain(service)?.drain_listeners() {
            WindowsListenerDrainOutcome::RemainingCleanup(cleanup) => cleanup,
            WindowsListenerDrainOutcome::ExitRequired(exit) => {
                assert_exit78(exit)?;
                return Err(io::Error::other("listener drain service effect failed").into());
            }
        };
        match complete_remaining_cleanup(cleanup)?.prepare_clean() {
            WindowsLifecycleCleanCommitOutcome::ReleasePending(release) => Ok(release),
            WindowsLifecycleCleanCommitOutcome::ReloadRequired(reload) => {
                assert_exit78(reload.abort(LifecycleError::NotReady))?;
                Err(io::Error::other("fault-free Clean commit required reload").into())
            }
            WindowsLifecycleCleanCommitOutcome::ExitRequired(exit) => {
                assert_exit78(exit)?;
                Err(io::Error::other("fault-free Clean commit became terminal").into())
            }
        }
    }

    fn stage_events(probe: &FixtureWindowsServiceEffectProbe) -> Vec<WindowsLifecycleEffectStage> {
        probe
            .borrow()
            .events
            .iter()
            .filter_map(|event| match event {
                FixtureWindowsServiceEffectEvent::Stage(stage) => Some(*stage),
                FixtureWindowsServiceEffectEvent::AdmissionBecameOpen
                | FixtureWindowsServiceEffectEvent::AdmissionFailClosed
                | FixtureWindowsServiceEffectEvent::EpochsInvalidated => None,
            })
            .collect()
    }

    #[test]
    fn production_effect_source_is_single_use_redacted_and_resource_opaque() -> TestResult {
        let source_text = include_str!("windows_service_effects.rs");
        let (production_text, _) = source_text
            .split_once("\n#[cfg(test)]\nmod tests {")
            .ok_or_else(|| io::Error::other("service effect test boundary missing"))?;
        for forbidden in [
            "RawHandle",
            "HANDLE",
            "as_raw",
            "into_raw",
            "dyn Any",
            "downcast",
            "impl Clone for WindowsServiceEffectSource",
            "impl Copy for WindowsServiceEffectSource",
            "impl Default for WindowsServiceEffectSource",
            "impl From<",
        ] {
            assert!(
                !production_text.contains(forbidden),
                "forbidden service effect source surface: {forbidden}"
            );
        }
        assert_eq!(production_text.matches("fn into_authority(").count(), 1);
        assert_eq!(
            production_text
                .matches("scm.with_running_admission_gate(||")
                .count(),
            1
        );

        let (source, _probe) = WindowsServiceEffectSource::from_fixture(None);
        assert_eq!(
            format!("{source:?}"),
            "WindowsServiceEffectSource([REDACTED])"
        );
        assert_move_only!(WindowsServiceEffectSource);
        let authority = source.into_authority()?;
        assert_eq!(
            format!("{authority:?}"),
            "WindowsLifecycleEffectAuthority([REDACTED])"
        );

        let (terminal_source, _probe) = WindowsServiceEffectSource::from_fixture(None);
        let terminal_error = WindowsServiceEffectSourceError {
            _source: terminal_source,
        };
        assert_eq!(
            format!("{terminal_error:?}"),
            "WindowsServiceEffectSourceError([REDACTED])"
        );
        assert_move_only!(WindowsServiceEffectSourceError);
        Ok(())
    }

    #[test]
    fn production_effect_backend_success_has_exact_six_stage_order() -> TestResult {
        let (effects, probe) = fixture_effects(None)?;
        let running = prepare_and_publish_running(effects)?;
        let open = open_admission(running)?;
        let drained = close_and_drain(open)?;
        let _stopped = drained.publish_scm_stopped().map_err(|failure| {
            io::Error::other(format!("SCM_STOPPED publication failed: {failure:?}"))
        })?;
        assert_eq!(
            stage_events(&probe),
            [
                WindowsLifecycleEffectStage::PrepareListeners,
                WindowsLifecycleEffectStage::PublishScmRunning,
                WindowsLifecycleEffectStage::OpenAdmission,
                WindowsLifecycleEffectStage::CloseAdmission,
                WindowsLifecycleEffectStage::DrainListeners,
                WindowsLifecycleEffectStage::PublishScmStopped,
            ]
        );
        assert_eq!(
            probe.borrow().resource,
            FixtureWindowsServiceResourceState::Drained
        );
        Ok(())
    }

    #[test]
    fn listener_prepare_failure_distinguishes_unapplied_from_ambiguous() -> TestResult {
        for (fault, disposition, resource) in [
            (
                FixtureWindowsServiceEffectFault::StartUnavailable,
                WindowsLifecycleEffectDisposition::KnownNotApplied,
                FixtureWindowsServiceResourceState::NotStarted,
            ),
            (
                FixtureWindowsServiceEffectFault::StartRuntimeStateRetained,
                WindowsLifecycleEffectDisposition::Ambiguous,
                FixtureWindowsServiceResourceState::TerminalRetained,
            ),
        ] {
            let (effects, probe) = fixture_effects(Some(fault))?;
            let witness = effects.binding_witness_for_test();
            let Err(failure) = effects.prepare_listeners() else {
                return Err(io::Error::other("listener preparation fault was accepted").into());
            };
            let failure = effect_failure(
                failure,
                WindowsLifecycleEffectStage::PrepareListeners,
                disposition,
            );
            assert!(failure.matches_binding_witness_for_test(witness));
            assert_eq!(probe.borrow().resource, resource);
        }
        Ok(())
    }

    #[test]
    fn scm_running_failure_never_opens_admission() -> TestResult {
        let (effects, probe) = fixture_effects(Some(
            FixtureWindowsServiceEffectFault::PublishScmRunningFalse,
        ))?;
        let witness = effects.binding_witness_for_test();
        let prepared = effects.prepare_listeners().map_err(|failure| {
            io::Error::other(format!("listener preparation failed: {failure:?}"))
        })?;
        let Err(failure) = prepared.publish_scm_running() else {
            return Err(io::Error::other("SCM_RUNNING fault was accepted").into());
        };
        let failure = effect_failure(
            failure,
            WindowsLifecycleEffectStage::PublishScmRunning,
            WindowsLifecycleEffectDisposition::Ambiguous,
        );
        assert!(failure.matches_binding_witness_for_test(witness));
        let observation = probe.borrow();
        assert_eq!(
            observation.resource,
            FixtureWindowsServiceResourceState::ListeningAdmissionClosed
        );
        assert!(
            !observation
                .events
                .contains(&FixtureWindowsServiceEffectEvent::AdmissionBecameOpen)
        );
        assert_eq!(
            stage_events(&probe),
            [
                WindowsLifecycleEffectStage::PrepareListeners,
                WindowsLifecycleEffectStage::PublishScmRunning,
            ]
        );
        Ok(())
    }

    #[test]
    fn admission_open_failure_retains_closed_listener_and_effect_authority() -> TestResult {
        for fault in [
            FixtureWindowsServiceEffectFault::RunningAdmissionGateRejected,
            FixtureWindowsServiceEffectFault::BeginAdmissionError,
        ] {
            let (effects, probe) = fixture_effects(Some(fault))?;
            let witness = effects.binding_witness_for_test();
            let running = prepare_and_publish_running(effects)?;
            let Err(failure) = running.open_admission() else {
                return Err(io::Error::other("admission-open fault was accepted").into());
            };
            let failure = effect_failure(
                failure,
                WindowsLifecycleEffectStage::OpenAdmission,
                WindowsLifecycleEffectDisposition::Ambiguous,
            );
            assert!(failure.matches_binding_witness_for_test(witness));
            let observation = probe.borrow();
            assert_eq!(
                observation.resource,
                FixtureWindowsServiceResourceState::AdmissionClosed
            );
            assert!(
                observation
                    .events
                    .contains(&FixtureWindowsServiceEffectEvent::AdmissionFailClosed)
            );
        }
        Ok(())
    }

    #[test]
    fn admission_close_precedes_epoch_invalidation_and_listener_drain() -> TestResult {
        let (effects, probe) = fixture_effects(None)?;
        let running = prepare_and_publish_running(effects)?;
        let open = open_admission(running)?;
        let _drained = close_and_drain(open)?;
        let observation = probe.borrow();
        let events = &observation.events;
        let close = events
            .iter()
            .position(|event| {
                *event
                    == FixtureWindowsServiceEffectEvent::Stage(
                        WindowsLifecycleEffectStage::CloseAdmission,
                    )
            })
            .ok_or_else(|| io::Error::other("admission-close event missing"))?;
        let invalidation = events
            .iter()
            .position(|event| *event == FixtureWindowsServiceEffectEvent::EpochsInvalidated)
            .ok_or_else(|| io::Error::other("epoch invalidation event missing"))?;
        let drain = events
            .iter()
            .position(|event| {
                *event
                    == FixtureWindowsServiceEffectEvent::Stage(
                        WindowsLifecycleEffectStage::DrainListeners,
                    )
            })
            .ok_or_else(|| io::Error::other("listener-drain event missing"))?;
        assert!(close < invalidation && invalidation < drain);
        Ok(())
    }

    #[test]
    fn listener_drain_failure_never_claims_clean_or_writer_release() -> TestResult {
        for (fixture_byte, fault) in [
            (0x91, FixtureWindowsServiceEffectFault::DrainUnavailable),
            (
                0x92,
                FixtureWindowsServiceEffectFault::DrainRuntimeStateRetained,
            ),
        ] {
            let (fixture, _installation, mut provider) = clean_fixture(fixture_byte)?;
            let (effects, probe) = fixture_effects(Some(fault))?;
            let service = ready_service_with_effects(&fixture, &mut provider, effects)?;
            let drain = begin_listener_drain(service)?;
            let exit = match drain.drain_listeners() {
                WindowsListenerDrainOutcome::ExitRequired(exit) => exit,
                WindowsListenerDrainOutcome::RemainingCleanup(_) => {
                    return Err(io::Error::other("listener-drain fault reached cleanup").into());
                }
            };
            assert!(matches!(
                exit.cause(),
                crate::key_agent_service::windows_lifecycle::WindowsLifecycleCause::Effect(cause)
                    if cause.stage() == WindowsLifecycleEffectStage::DrainListeners
                        && cause.disposition() == WindowsLifecycleEffectDisposition::Ambiguous
            ));
            assert!(
                exit.effect_failure_for_test().is_some_and(
                    |cause| cause.stage() == WindowsLifecycleEffectStage::DrainListeners
                )
            );
            let failure_matches = exit
                .effect_failure_for_test()
                .is_some_and(|_| exit.effects_attached_for_test());
            assert!(failure_matches);
            assert_eq!(
                probe.borrow().resource,
                FixtureWindowsServiceResourceState::TerminalRetained
            );
            assert!(
                !stage_events(&probe).contains(&WindowsLifecycleEffectStage::PublishScmStopped)
            );
            match exit.retire_checked() {
                Ok(checked) => {
                    assert_eq!(checked.code(), 78);
                    assert!(checked.effects_attached_for_test());
                    assert!(checked.effect_failure_for_test().is_some_and(
                        |cause| cause.stage() == WindowsLifecycleEffectStage::DrainListeners
                    ));
                }
                Err(failure) => {
                    return Err(io::Error::other(format!(
                        "drain failure retirement became irreversible: {failure:?}"
                    ))
                    .into());
                }
            }
            fixture.cleanup_checked()?;
        }
        Ok(())
    }

    #[test]
    fn scm_stopped_failure_after_writer_release_retains_both_terminal_evidences() -> TestResult {
        let (fixture, _installation, mut provider) = clean_fixture(0x93)?;
        let (effects, probe) = fixture_effects(Some(
            FixtureWindowsServiceEffectFault::PublishScmStoppedFalse,
        ))?;
        let binding = effects.binding_witness_for_test();
        let release = clean_release_pending_with_effects(&fixture, &mut provider, effects)?;
        let pending = match release.release_writer() {
            WindowsLifecycleWriterReleaseOutcome::ScmStopPending(pending) => pending,
            WindowsLifecycleWriterReleaseOutcome::ExitRequired(exit) => {
                assert_exit78(exit)?;
                return Err(io::Error::other("writer release retained the writer").into());
            }
            WindowsLifecycleWriterReleaseOutcome::IrreversibleExit78(failure) => {
                return Err(io::Error::other(format!(
                    "writer release became irreversible before SCM_STOPPED: {failure:?}"
                ))
                .into());
            }
        };
        let failure = match pending.publish_scm_stopped() {
            WindowsLifecycleScmStopOutcome::IrreversibleExit78(failure) => failure,
            WindowsLifecycleScmStopOutcome::Stopped(_) => {
                return Err(io::Error::other("SCM_STOPPED fault minted Stopped").into());
            }
        };
        assert_eq!(failure.code(), 78);
        assert!(failure.effects_attached_for_test());
        assert!(failure.post_writer_release_effect_binding_matches_for_test(binding));
        assert_eq!(
            failure
                .post_writer_release_generation_for_test()
                .map(NonZeroU64::get),
            Some(3)
        );
        assert!(matches!(
            failure.cause(),
            WindowsLifecycleIrreversibleCause::ScmStoppedPublication { effect }
                if effect.stage() == WindowsLifecycleEffectStage::PublishScmStopped
                    && effect.disposition() == WindowsLifecycleEffectDisposition::Ambiguous
        ));
        assert_eq!(
            probe.borrow().resource,
            FixtureWindowsServiceResourceState::Drained
        );
        fixture.cleanup_checked()
    }

    #[test]
    fn default_and_release_service_remain_silent_exit78_without_durable_provider() {
        let executable = include_str!("../../../key-agent-service/src/main.rs");
        let platform_lib = include_str!("../lib.rs");
        let platform_service = include_str!("../key_agent_service.rs");
        let platform_manifest = include_str!("../../Cargo.toml");
        let authentication = include_str!("durable_run_state/authentication.rs");

        assert!(executable.contains("const SERVICE_UNAVAILABLE: i32 = 78;"));
        assert!(executable.contains("std::process::exit(SERVICE_UNAVAILABLE);"));
        assert!(!executable.contains("WindowsServiceEffectSource"));
        assert!(!executable.contains("begin_windows_lifecycle"));
        assert!(!executable.contains("println!"));
        assert!(!executable.contains("eprintln!"));
        assert!(!platform_lib.contains("WindowsServiceEffectSource"));
        assert!(!platform_service.contains("WindowsServiceEffectSource"));
        assert!(!platform_service.contains("begin_windows_lifecycle("));
        assert!(platform_manifest.contains("default = []"));
        assert!(authentication.contains("Unavailable(Infallible)"));
    }
}
