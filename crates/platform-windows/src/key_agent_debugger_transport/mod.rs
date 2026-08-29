//! Dormant one-shot parent transport for an isolated Key Agent debugger helper.
//!
//! This module proves only current-host, deadline-driven process transport and
//! one sentinel-handle install/pull round trip. Before helper user mode it also
//! consumes release-bound artifact admission, authenticates the first
//! `CREATE_PROCESS_DEBUG_EVENT` image, installs one explicit suspend count, and
//! detaches on the same creator thread. It creates no Key Agent and has no
//! production caller or re-export.
//!
//! Its unnamed, non-inheritable containment Job is assigned before the helper's
//! initial thread can run and uses exact kill-on-close plus a two-process bound
//! with no breakaway. The helper creates one inert suspended target, freezes its
//! source-handle table, and hands parent-side constrained observers plus the
//! only Job handle retained by this implementation to a dormant typestate.
//! A debug-only exact-argv outer supervisor fixture proves current-host forced
//! parent death before READY, at READY, and after the target handoff without
//! activating any default or production policy.
//! It does not prove that an executed same-token helper cannot acquire
//! `PROCESS_DUP_HANDLE` on the parent and retain another Job handle. Signed and
//! versioned package evidence, production release-policy enablement,
//! token/process-DACL separation, parent-pinned target-image admission (the
//! current fixture reopens an untrusted `current_exe` path), supported-kernel
//! access normalization/cancellation and post-detach event-alias accounting,
//! system-wide Job-handle exclusion, and production policy remain STOP-SHIP.

#![allow(dead_code)] // Entire module is an explicitly dormant feasibility surface.

mod sys;

use core::fmt;
#[cfg(test)]
use std::ffi::OsStr;
#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use key_agent_debugger_wire::{
    DebuggerBootstrap, DebuggerDecision, DebuggerDecisionFrame, DebuggerExitCode,
    DebuggerReadyFrozen, DebuggerRunNonce, DebuggerTargetFrozen, RemoteHandleWord,
};
#[cfg(test)]
use key_agent_debugger_wire::{
    DebuggerParentDeathCommand, DebuggerParentDeathReport, PARENT_DEATH_COMMAND_FRAME_BYTES,
    PARENT_DEATH_REPORT_FRAME_BYTES, ParentDeathStage,
};
use thiserror::Error;

#[cfg(test)]
use super::artifact::{
    PreparedReleaseDebuggerArtifact, preflight_debugger_artifact, prepare_release_debugger_artifact,
};
#[cfg(test)]
use crate::attestation::{ArtifactDigest, ReleaseAttestation};
#[cfg(test)]
use crate::helper::VerifiedHelper;
#[cfg(test)]
use crate::inheritable_handle_launch::acquire_inheritable_handle_launch;
#[cfg(test)]
use crate::pipe::PrivateKeyAgentDebuggerPipes;
use crate::pipe::{KeyAgentDebuggerControlWriter, KeyAgentDebuggerStatusReader};
#[cfg(test)]
use crate::restricted_process_context::RestrictedProcessContext;

#[cfg(test)]
const TEST_DEBUGGER_EXECUTABLE_ENV: &str = "YW_TEST_KEY_AGENT_DEBUGGER_EXECUTABLE";
#[cfg(test)]
const EXACT_DEBUGGER_FILENAME: &str = "key-agent-debugger.exe";
#[cfg(test)]
const TEST_DEBUGGER_MANIFEST: [u8; 32] = [0x51; 32];
#[cfg(test)]
const RUN_BOUND: Duration = Duration::from_secs(4);
const CLEANUP_BOUND: Duration = Duration::from_secs(5);

/// Stable, data-free failure categories for the dormant transport.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
enum DebuggerTransportError {
    #[error("debugger executable test environment was invalid")]
    ExecutableEnvironment,
    #[error("debugger executable path was invalid")]
    ExecutablePath,
    #[error("debugger release artifact admission failed")]
    ArtifactAdmission,
    #[error("debugger process context preparation failed")]
    ProcessContext,
    #[error("debugger inheritable-handle launch flight failed")]
    LaunchFlight,
    #[error("debugger private pipe preparation failed")]
    PrivatePipes,
    #[error("debugger process creation failed")]
    ProcessCreation,
    #[error("debugger containment Job preparation failed")]
    JobPreparation,
    #[error("debugger containment Job proof failed")]
    JobProof,
    #[error("debugger process identity validation failed")]
    ProcessIdentity,
    #[error("debugger first process-creation event validation failed")]
    DebugEvent,
    #[error("debugger mapped executable image validation failed")]
    MappedImage,
    #[error("debugger explicit suspension proof failed")]
    Suspension,
    #[error("debugger detach proof failed")]
    DebugDetach,
    #[error("debugger sentinel installation failed")]
    SentinelInstall,
    #[error("debugger bootstrap construction failed")]
    Bootstrap,
    #[error("debugger primary-thread resume proof failed")]
    Resume,
    #[error("debugger READY_FROZEN receive failed")]
    ReadyReceive,
    #[error("debugger READY_FROZEN binding was invalid")]
    ReadyBinding,
    #[error("debugger TARGET_FROZEN receive failed")]
    TargetReceive,
    #[error("debugger TARGET_FROZEN binding was invalid")]
    TargetBinding,
    #[error("debugger target observer pull failed")]
    TargetPull,
    #[error("debugger target topology proof failed")]
    TargetProof,
    #[error("debugger target identity proof failed")]
    TargetIdentity,
    #[error("debugger target access proof failed")]
    TargetAccess,
    #[error("debugger target process access proof failed")]
    TargetProcessAccess,
    #[error("debugger target thread access proof failed")]
    TargetThreadAccess,
    #[error("debugger target state proof failed")]
    TargetState,
    #[error("debugger target creation-time proof failed")]
    TargetCreation,
    #[error("debugger sentinel observer pull failed")]
    SentinelPull,
    #[error("debugger sentinel observer proof failed")]
    SentinelProof,
    #[error("debugger decision send failed")]
    Decision,
    #[error("debugger process cleanup or exit proof failed")]
    ProcessExit,
    #[error("debugger containment Job termination failed")]
    JobTermination,
    #[error("debugger containment Job did not reach zero")]
    JobNotEmpty,
    #[error("debugger target process did not reach terminal state")]
    TargetProcessTerminal,
    #[error("debugger target thread did not reach terminal state")]
    TargetThreadTerminal,
    #[error("debugger operation deadline elapsed")]
    Deadline,
    #[error("debugger parent-death fixture activation was invalid")]
    ParentDeathActivation,
    #[error("debugger parent-death fixture command was invalid")]
    ParentDeathCommand,
    #[error("debugger parent-death fixture report was invalid")]
    ParentDeathReport,
    #[error("debugger parent-death fixture report binding was invalid")]
    ParentDeathBinding,
    #[error("debugger parent-death fixture supervisor failed")]
    ParentDeathSupervisor,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct ParentDeathReportBindingFacts {
    nonce_bound: bool,
    expected_stage: ParentDeathStage,
    reported_stage: ParentDeathStage,
    spawned_supervisor_process_id: u32,
    reported_supervisor_process_id: u32,
    debugger_process_id: u32,
    target_process_id: u32,
    supervisor_creation_time: u64,
    debugger_creation_time: u64,
    target_creation_time: u64,
}

#[cfg(test)]
impl fmt::Debug for ParentDeathReportBindingFacts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ParentDeathReportBindingFacts([REDACTED])")
    }
}

#[cfg(test)]
const fn exact_parent_death_report_binding(facts: ParentDeathReportBindingFacts) -> bool {
    let target_required = !matches!(facts.expected_stage, ParentDeathStage::PreReady);
    facts.nonce_bound
        && facts.reported_stage as u16 == facts.expected_stage as u16
        && facts.spawned_supervisor_process_id != 0
        && facts.reported_supervisor_process_id == facts.spawned_supervisor_process_id
        && facts.debugger_process_id != 0
        && facts.debugger_process_id != facts.spawned_supervisor_process_id
        && facts.supervisor_creation_time != 0
        && facts.debugger_creation_time != 0
        && if target_required {
            facts.target_process_id != 0
                && facts.target_process_id != facts.spawned_supervisor_process_id
                && facts.target_process_id != facts.debugger_process_id
                && facts.target_creation_time != 0
        } else {
            facts.target_process_id == 0 && facts.target_creation_time == 0
        }
}

const READY_NONCE_BOUND: u8 = 1 << 0;
const TARGET_NONCE_BOUND: u8 = 1 << 1;
const ALL_NONCE_BINDINGS: u8 = READY_NONCE_BOUND | TARGET_NONCE_BOUND;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrozenTopologyBindingFacts {
    expected_debugger_process_id: u32,
    ready_debugger_process_id: u32,
    target_source_process_id: u32,
    target_process_id: u32,
    target_thread_id: u32,
    expected_sentinel_source: u64,
    ready_sentinel_source: u64,
    target_process_source: u64,
    target_thread_source: u64,
    target_creation_time: u64,
    nonce_bindings: u8,
}

const fn exact_frozen_topology_binding(facts: FrozenTopologyBindingFacts) -> bool {
    facts.expected_debugger_process_id != 0
        && facts.ready_debugger_process_id == facts.expected_debugger_process_id
        && facts.target_source_process_id == facts.expected_debugger_process_id
        && facts.target_process_id != 0
        && facts.target_process_id != facts.expected_debugger_process_id
        && facts.target_thread_id != 0
        && facts.expected_sentinel_source != 0
        && facts.ready_sentinel_source == facts.expected_sentinel_source
        && facts.target_process_source != 0
        && facts.target_thread_source != 0
        && facts.target_process_source != facts.target_thread_source
        && facts.target_creation_time != 0
        && facts.nonce_bindings == ALL_NONCE_BINDINGS
}

/// Mapped-image-authenticated and detached debugger helper whose primary thread
/// retains the exact explicit suspend count installed at the first event and
/// whose SYNCHRONIZE-only sentinel source is already in its private handle table.
#[must_use = "a suspended debugger helper must be resumed or terminal cleanup attempted"]
struct SuspendedDebuggerTransport {
    child: sys::DebuggerChild,
    control: KeyAgentDebuggerControlWriter,
    status: KeyAgentDebuggerStatusReader,
    sentinel: sys::SentinelOwner,
    remote_sentinel_word: u64,
}

impl SuspendedDebuggerTransport {
    #[cfg(test)]
    fn launch_for_kernel_test(deadline: Instant) -> Result<Self, DebuggerTransportError> {
        let executable = debugger_executable_from_test_environment()?;
        let prepared = prepare_kernel_test_artifact(executable)?;
        Self::launch_prepared_for_kernel_test(prepared, None, deadline)
    }

    #[cfg(test)]
    fn launch_prepared_for_kernel_test(
        prepared: PreparedReleaseDebuggerArtifact,
        application_override: Option<&Path>,
        deadline: Instant,
    ) -> Result<Self, DebuggerTransportError> {
        let context = RestrictedProcessContext::prepare_for_kernel_test()
            .map_err(|_| DebuggerTransportError::ProcessContext)?;
        let pipes = PrivateKeyAgentDebuggerPipes::create()
            .map_err(|_| DebuggerTransportError::PrivatePipes)?;
        let flight = acquire_inheritable_handle_launch(deadline)
            .map_err(|_| DebuggerTransportError::LaunchFlight)?;
        let inheritance = pipes
            .prepare_child_inheritance(&flight)
            .map_err(|_| DebuggerTransportError::PrivatePipes)?;
        let child = if let Some(application_override) = application_override {
            sys::DebuggerChild::create_suspended_with_application_override_for_test(
                prepared,
                application_override,
                &context,
                &inheritance,
                &flight,
                deadline,
            )
        } else {
            sys::DebuggerChild::create_suspended(
                prepared,
                &context,
                &inheritance,
                &flight,
                deadline,
            )
        }?;
        drop(inheritance);
        drop(flight);
        let (control, status) = pipes.into_parent();
        let (sentinel, remote_sentinel_word) = child.install_sentinel()?;
        Ok(Self {
            child,
            control,
            status,
            sentinel,
            remote_sentinel_word,
        })
    }

    fn bootstrap_and_resume(
        mut self,
        deadline: Instant,
    ) -> Result<AwaitingReadyDebugger, DebuggerTransportError> {
        let bootstrap = self.bootstrap(deadline)?;
        self.control
            .write_bootstrap(&bootstrap.encode(), deadline)
            .map_err(|_| DebuggerTransportError::Bootstrap)?;
        self.child.resume_exactly_once()?;
        Ok(AwaitingReadyDebugger {
            child: self.child,
            control: self.control,
            status: self.status,
            sentinel: self.sentinel,
            bootstrap,
        })
    }

    #[cfg(test)]
    fn resume_with_malformed_bootstrap_for_test(
        mut self,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        let mut malformed = self.bootstrap(deadline)?.encode();
        malformed[0] ^= 1;
        self.control
            .write_bootstrap(&malformed, deadline)
            .map_err(|_| DebuggerTransportError::Bootstrap)?;
        self.child.resume_exactly_once()?;
        drop(self.status);
        let _control_kept_open_until_exit = self.control;
        let _sentinel_kept_live_until_exit = self.sentinel;
        self.child
            .wait_for_exact_exit(DebuggerExitCode::ProtocolViolation, cleanup_deadline())
    }

    #[cfg(test)]
    fn terminate_while_suspended_for_test(mut self) -> Result<(), DebuggerTransportError> {
        self.child
            .terminate_and_wait(DebuggerExitCode::OperatingSystem, cleanup_deadline())
    }

    #[cfg(test)]
    fn close_containment_job_while_suspended_for_test(
        mut self,
    ) -> Result<(), DebuggerTransportError> {
        self.child
            .close_job_and_wait_for_terminal_for_test(cleanup_deadline())
    }

    #[cfg(test)]
    fn terminate_containment_job_without_process_wait_for_test(
        mut self,
    ) -> Result<(), DebuggerTransportError> {
        self.child
            .terminate_job_and_wait_empty_without_process_for_test(cleanup_deadline())
    }

    fn bootstrap(&self, deadline: Instant) -> Result<DebuggerBootstrap, DebuggerTransportError> {
        let nonce = fresh_nonce()?;
        let remote = RemoteHandleWord::new(self.remote_sentinel_word)
            .map_err(|_| DebuggerTransportError::Bootstrap)?;
        DebuggerBootstrap::new(
            nonce,
            sys::current_process_id(),
            self.child.process_id(),
            remote,
            sys::absolute_tick_deadline(deadline)?,
        )
        .map_err(|_| DebuggerTransportError::Bootstrap)
    }

    #[cfg(test)]
    fn prove_parent_death_identity(&self) -> Result<(u32, u64), DebuggerTransportError> {
        self.child.prove_pre_ready_parent_death_identity()
    }
}

impl fmt::Debug for SuspendedDebuggerTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "SuspendedDebuggerTransport([SUSPENDED HELPER; SENTINEL INSTALLED; HANDLES REDACTED])",
        )
    }
}

/// Resumed helper awaiting exact `READY_FROZEN` and `TARGET_FROZEN` frames.
#[must_use = "an awaiting debugger helper must reach READY_FROZEN or terminal cleanup attempted"]
struct AwaitingReadyDebugger {
    child: sys::DebuggerChild,
    control: KeyAgentDebuggerControlWriter,
    status: KeyAgentDebuggerStatusReader,
    sentinel: sys::SentinelOwner,
    bootstrap: DebuggerBootstrap,
}

impl AwaitingReadyDebugger {
    fn await_ready(self, deadline: Instant) -> Result<ReadyFrozenDebugger, DebuggerTransportError> {
        let (ready_frame, target_frame) = self
            .status
            .receive_frozen_topology(deadline)
            .map_err(|_| DebuggerTransportError::ReadyReceive)?;
        let ready = DebuggerReadyFrozen::decode_exact(&ready_frame)
            .map_err(|_| DebuggerTransportError::ReadyReceive)?;
        let target = DebuggerTargetFrozen::decode_exact(&target_frame)
            .map_err(|_| DebuggerTransportError::TargetReceive)?;
        let facts = FrozenTopologyBindingFacts {
            expected_debugger_process_id: self.child.process_id(),
            ready_debugger_process_id: ready.debugger_process_id(),
            target_source_process_id: target.debugger_process_id(),
            target_process_id: target.target_process_id(),
            target_thread_id: target.target_thread_id(),
            expected_sentinel_source: self.bootstrap.sentinel_handle().value(),
            ready_sentinel_source: ready.sentinel_source_handle().value(),
            target_process_source: target.target_process_source_handle().value(),
            target_thread_source: target.target_thread_source_handle().value(),
            target_creation_time: target.target_creation_time(),
            nonce_bindings: if ready.run_nonce() == self.bootstrap.run_nonce() {
                READY_NONCE_BOUND
            } else {
                0
            } | if target.run_nonce() == ready.run_nonce() {
                TARGET_NONCE_BOUND
            } else {
                0
            },
        };
        if !exact_frozen_topology_binding(facts) {
            return Err(
                if facts.ready_debugger_process_id != facts.expected_debugger_process_id
                    || facts.ready_sentinel_source != facts.expected_sentinel_source
                    || facts.nonce_bindings & READY_NONCE_BOUND == 0
                {
                    DebuggerTransportError::ReadyBinding
                } else {
                    DebuggerTransportError::TargetBinding
                },
            );
        }
        let (nonce, _debugger_process_id, source_word) = ready.into_parts();
        let (
            _target_nonce,
            _source_process_id,
            target_process_id,
            target_thread_id,
            target_process_source,
            target_thread_source,
            target_creation_time,
        ) = target.into_parts();
        let observer = self.child.pull_sentinel_observer(source_word.value())?;
        let sentinel = sys::SentinelEvidence::prove(self.sentinel, observer)?;
        let target = self.child.pull_target_topology(
            target_process_id,
            target_thread_id,
            target_process_source.value(),
            target_thread_source.value(),
            target_creation_time,
        )?;
        #[cfg(test)]
        {
            if sys::native_granted_access_for_test(sentinel.observer())? != sys::SYNCHRONIZE_ACCESS
            {
                return Err(DebuggerTransportError::SentinelProof);
            }
        }
        Ok(ReadyFrozenDebugger {
            child: self.child,
            control: self.control,
            nonce,
            sentinel,
            target,
        })
    }
}

impl fmt::Debug for AwaitingReadyDebugger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("AwaitingReadyDebugger([RESUMED HELPER; READY PENDING; HANDLES REDACTED])")
    }
}

/// One helper that proved immutable sentinel and target source words and now
/// accepts only a final decision.
///
/// `READY_FROZEN` names a protocol state: the helper's sentinel source-handle
/// set is fixed and its control protocol is decision-only. It does **not** mean
/// the helper process or primary thread is suspended by the operating system.
#[must_use = "a READY_FROZEN debugger helper requires one terminal decision"]
struct ReadyFrozenDebugger {
    child: sys::DebuggerChild,
    control: KeyAgentDebuggerControlWriter,
    nonce: DebuggerRunNonce,
    sentinel: sys::SentinelEvidence,
    target: sys::FrozenTargetEvidence,
}

impl ReadyFrozenDebugger {
    #[cfg(test)]
    fn prove_parent_death_identities(
        &self,
    ) -> Result<
        (
            sys::ParentDeathProcessIdentity,
            sys::ParentDeathProcessIdentity,
        ),
        DebuggerTransportError,
    > {
        self.child.prove_ready_parent_death_identities(&self.target)
    }

    fn commit(self, deadline: Instant) -> Result<DetachedTargetTopology, DebuggerTransportError> {
        let Self {
            child,
            control,
            nonce,
            sentinel,
            target,
        } = self;
        let frame = DebuggerDecisionFrame::new(nonce, DebuggerDecision::Commit).encode();
        control
            .finish(&frame, deadline)
            .map_err(|_| DebuggerTransportError::Decision)?;
        let topology = child.handoff_target_after_exact_exit(
            target,
            DebuggerExitCode::Success,
            cleanup_deadline(),
        )?;
        drop(sentinel);
        Ok(DetachedTargetTopology { topology })
    }

    #[cfg(test)]
    fn reject_post_exit_target_termination_for_test(
        self,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        let Self {
            child,
            control,
            nonce,
            sentinel,
            target,
        } = self;
        let frame = DebuggerDecisionFrame::new(nonce, DebuggerDecision::Commit).encode();
        control
            .finish(&frame, deadline)
            .map_err(|_| DebuggerTransportError::Decision)?;
        let result = child.reject_post_exit_target_termination_for_test(
            &target,
            DebuggerExitCode::Success,
            cleanup_deadline(),
        );
        drop(sentinel);
        result
    }

    fn abort(self, deadline: Instant) -> Result<(), DebuggerTransportError> {
        let Self {
            mut child,
            control,
            nonce,
            sentinel,
            target,
        } = self;
        let frame = DebuggerDecisionFrame::new(nonce, DebuggerDecision::Abort).encode();
        control
            .finish(&frame, deadline)
            .map_err(|_| DebuggerTransportError::Decision)?;
        child.wait_for_exact_exit(DebuggerExitCode::Aborted, cleanup_deadline())?;
        let _sentinel_kept_live_until_exit = sentinel;
        let _target_kept_live_until_job_cleanup = target;
        child.terminate_job_and_wait_empty(DebuggerExitCode::Aborted, cleanup_deadline())
    }

    #[cfg(test)]
    fn parent_eof(self) -> Result<(), DebuggerTransportError> {
        let Self {
            mut child,
            control,
            nonce: _,
            sentinel,
            target,
        } = self;
        control
            .close_after_bootstrap_for_test()
            .map_err(|_| DebuggerTransportError::Decision)?;
        let _sentinel_kept_live_until_exit = sentinel;
        let _target_kept_live_until_cleanup = target;
        child.wait_for_exact_exit(DebuggerExitCode::ParentEof, cleanup_deadline())?;
        child.terminate_job_and_wait_empty(DebuggerExitCode::ParentEof, cleanup_deadline())
    }

    #[cfg(test)]
    fn wait_for_protocol_deadline(self) -> Result<(), DebuggerTransportError> {
        let Self {
            mut child,
            control,
            nonce: _,
            sentinel,
            target,
        } = self;
        let _control_kept_open_until_exit = control;
        let _sentinel_kept_live_until_exit = sentinel;
        let _target_kept_live_until_cleanup = target;
        child.wait_for_exact_exit(DebuggerExitCode::DeadlineElapsed, cleanup_deadline())?;
        child.terminate_job_and_wait_empty(DebuggerExitCode::DeadlineElapsed, cleanup_deadline())
    }

    #[cfg(test)]
    fn natural_exit_then_drop_cleanup_for_test(
        self,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        let Self {
            child,
            control,
            nonce,
            sentinel,
            target,
        } = self;
        let frame = DebuggerDecisionFrame::new(nonce, DebuggerDecision::Commit).encode();
        control
            .finish(&frame, deadline)
            .map_err(|_| DebuggerTransportError::Decision)?;
        child.observe_exact_exit_without_reaping_for_test(
            DebuggerExitCode::Success,
            cleanup_deadline(),
        )?;
        let _sentinel_kept_live_until_exit = sentinel;
        let _target_kept_live_until_drop_cleanup = target;
        // Drop deliberately begins with `reaped == false` after natural exit.
        // Its expected forced-exit code will mismatch, but terminal proof must
        // suppress fail-fast and permit ordinary owner closure.
        drop(child);
        Ok(())
    }
}

impl fmt::Debug for ReadyFrozenDebugger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "ReadyFrozenDebugger([SENTINEL AND TARGET SOURCE SETS FIXED; TARGET SUSPENDED; DECISION-ONLY; HANDLES REDACTED])",
        )
    }
}

/// The only Job handle retained by this implementation plus exact narrow
/// handles for one frozen, untrusted, never-resumable target.
#[must_use = "detached target topology must be explicitly aborted or dropped"]
struct DetachedTargetTopology {
    topology: sys::DetachedTargetTopology,
}

impl DetachedTargetTopology {
    fn abort(self, deadline: Instant) -> Result<(), DebuggerTransportError> {
        self.topology
            .terminate_and_wait_empty(DebuggerExitCode::Aborted, deadline)
    }

    #[cfg(test)]
    fn prove_parent_death_target_identity(&self) -> Result<(u32, u64), DebuggerTransportError> {
        self.topology.prove_parent_death_target_identity()
    }
}

impl fmt::Debug for DetachedTargetTopology {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "DetachedTargetTopology([TARGET PROCESS; PRIMARY THREAD; RETAINED JOB HANDLE REDACTED])",
        )
    }
}

#[cfg(test)]
fn debugger_executable_from_test_environment() -> Result<PathBuf, DebuggerTransportError> {
    let candidate = std::env::var_os(TEST_DEBUGGER_EXECUTABLE_ENV)
        .map(PathBuf::from)
        .ok_or(DebuggerTransportError::ExecutableEnvironment)?;
    if !candidate.is_absolute()
        || candidate.file_name() != Some(OsStr::new(EXACT_DEBUGGER_FILENAME))
        || candidate
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(DebuggerTransportError::ExecutablePath);
    }
    let canonical =
        fs::canonicalize(&candidate).map_err(|_| DebuggerTransportError::ExecutablePath)?;
    if !canonical.is_absolute()
        || canonical.file_name() != Some(OsStr::new(EXACT_DEBUGGER_FILENAME))
        || !canonical.is_file()
    {
        return Err(DebuggerTransportError::ExecutablePath);
    }
    Ok(canonical)
}

#[cfg(test)]
fn prepare_kernel_test_artifact(
    path: PathBuf,
) -> Result<PreparedReleaseDebuggerArtifact, DebuggerTransportError> {
    let artifact =
        VerifiedHelper::for_key_agent_debugger_artifact_test(path, TEST_DEBUGGER_MANIFEST, true)
            .map_err(|_| DebuggerTransportError::ArtifactAdmission)?;
    let attestation = ReleaseAttestation::with_key_agent_debugger_manifest_for_test(
        ArtifactDigest::for_test([0x50; 32]),
        TEST_DEBUGGER_MANIFEST,
    );
    let preflight = preflight_debugger_artifact(attestation, artifact)
        .map_err(|_| DebuggerTransportError::ArtifactAdmission)?;
    prepare_release_debugger_artifact(preflight)
        .map_err(|_| DebuggerTransportError::ArtifactAdmission)
}

fn fresh_nonce() -> Result<DebuggerRunNonce, DebuggerTransportError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| DebuggerTransportError::Bootstrap)?;
    DebuggerRunNonce::new(bytes).map_err(|_| DebuggerTransportError::Bootstrap)
}

fn cleanup_deadline() -> Instant {
    Instant::now() + CLEANUP_BOUND
}

#[cfg(test)]
fn run_deadline() -> Instant {
    Instant::now() + RUN_BOUND
}

#[cfg(test)]
mod tests {
    use super::{
        ALL_NONCE_BINDINGS, DebuggerExitCode, DebuggerParentDeathCommand,
        DebuggerParentDeathReport, DebuggerRunNonce, DebuggerTransportError,
        FrozenTopologyBindingFacts, PARENT_DEATH_COMMAND_FRAME_BYTES,
        PARENT_DEATH_REPORT_FRAME_BYTES, ParentDeathReportBindingFacts, ParentDeathStage,
        ReadyFrozenDebugger, SuspendedDebuggerTransport, cleanup_deadline,
        debugger_executable_from_test_environment, exact_frozen_topology_binding,
        exact_parent_death_report_binding, fresh_nonce, prepare_kernel_test_artifact, run_deadline,
        sys,
    };
    use std::ffi::{OsStr, OsString};
    use std::io::{Read, Write};
    use std::os::windows::process::CommandExt;
    use std::process::{Child, ChildStdin, Command, Stdio};
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    use windows::Win32::System::Threading::CREATE_NO_WINDOW;

    const PARENT_DEATH_SUPERVISOR_ENV: &str = "YW_TEST_KEY_AGENT_DEBUGGER_PARENT_DEATH_SUPERVISOR";
    const PARENT_DEATH_SUPERVISOR_TEST: &str =
        "key_agent_debugger::transport::tests::parent_death_supervisor_fixture";
    const PARENT_DEATH_SUPERVISOR_ARGS: [&str; 5] = [
        PARENT_DEATH_SUPERVISOR_TEST,
        "--exact",
        "--ignored",
        "--test-threads=1",
        "--nocapture",
    ];
    const EXACT_PINNED_LIBTEST_PREFIX: &[u8] = b"\nrunning 1 test\ntest key_agent_debugger::transport::tests::parent_death_supervisor_fixture ... ";
    const PARENT_DEATH_REPORT_BOUND: Duration = Duration::from_secs(8);

    struct ParentDeathSupervisor {
        child: Child,
        input: Option<ChildStdin>,
        reports: Receiver<Result<DebuggerParentDeathReport, DebuggerTransportError>>,
        reader: Option<JoinHandle<Result<(), DebuggerTransportError>>>,
        terminal: bool,
    }

    impl ParentDeathSupervisor {
        fn spawn(expected_reports: usize) -> Result<Self, DebuggerTransportError> {
            let executable = std::env::current_exe()
                .map_err(|_| DebuggerTransportError::ParentDeathSupervisor)?;
            let mut command = Command::new(executable);
            command
                .args(PARENT_DEATH_SUPERVISOR_ARGS)
                .env(PARENT_DEATH_SUPERVISOR_ENV, "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            command.creation_flags(CREATE_NO_WINDOW.0);
            let mut child = command
                .spawn()
                .map_err(|_| DebuggerTransportError::ParentDeathSupervisor)?;
            let input = child
                .stdin
                .take()
                .ok_or(DebuggerTransportError::ParentDeathSupervisor)?;
            let output = child
                .stdout
                .take()
                .ok_or(DebuggerTransportError::ParentDeathSupervisor)?;
            let (sender, reports) = mpsc::channel();
            let reader = std::thread::spawn(move || {
                read_parent_death_reports(output, expected_reports, |report| {
                    sender.send(report).is_ok()
                })
            });
            Ok(Self {
                child,
                input: Some(input),
                reports,
                reader: Some(reader),
                terminal: false,
            })
        }

        fn process_id(&self) -> u32 {
            self.child.id()
        }

        fn send_command(
            &mut self,
            command: &DebuggerParentDeathCommand,
        ) -> Result<(), DebuggerTransportError> {
            let input = self
                .input
                .as_mut()
                .ok_or(DebuggerTransportError::ParentDeathCommand)?;
            input
                .write_all(&command.encode())
                .and_then(|()| input.flush())
                .map_err(|_| DebuggerTransportError::ParentDeathCommand)
        }

        fn send_raw_command(
            &mut self,
            command: &[u8; PARENT_DEATH_COMMAND_FRAME_BYTES],
        ) -> Result<(), DebuggerTransportError> {
            let input = self
                .input
                .as_mut()
                .ok_or(DebuggerTransportError::ParentDeathCommand)?;
            input
                .write_all(command)
                .and_then(|()| input.flush())
                .map_err(|_| DebuggerTransportError::ParentDeathCommand)
        }

        fn receive_report(
            &self,
            deadline: Instant,
        ) -> Result<DebuggerParentDeathReport, DebuggerTransportError> {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .ok_or(DebuggerTransportError::Deadline)?;
            match self.reports.recv_timeout(remaining) {
                Ok(result) => result,
                Err(RecvTimeoutError::Timeout) => Err(DebuggerTransportError::Deadline),
                Err(RecvTimeoutError::Disconnected) => {
                    Err(DebuggerTransportError::ParentDeathReport)
                }
            }
        }

        fn close_input_and_wait_for_failure(
            &mut self,
            deadline: Instant,
        ) -> Result<(), DebuggerTransportError> {
            drop(self.input.take());
            let status = wait_for_child_exit(&mut self.child, deadline)?;
            self.terminal = true;
            self.join_reader(false)?;
            if status.success() {
                return Err(DebuggerTransportError::ParentDeathSupervisor);
            }
            Ok(())
        }

        fn terminate_and_prove(
            &mut self,
            observations: &[&sys::ParentDeathProcessObservation],
            deadline: Instant,
            expect_complete_report_stream: bool,
        ) -> Result<(), DebuggerTransportError> {
            sys::terminate_parent_death_supervisor(&self.child)?;
            for observation in observations {
                observation.wait_for_terminal(deadline)?;
            }
            let status = wait_for_child_exit(&mut self.child, deadline)?;
            self.terminal = true;
            drop(self.input.take());
            self.join_reader(expect_complete_report_stream)?;
            if status.code() != Some(DebuggerExitCode::OperatingSystem.code()) {
                return Err(DebuggerTransportError::ParentDeathSupervisor);
            }
            Ok(())
        }

        fn join_reader(&mut self, expect_success: bool) -> Result<(), DebuggerTransportError> {
            let result = self
                .reader
                .take()
                .ok_or(DebuggerTransportError::ParentDeathSupervisor)?
                .join()
                .map_err(|_| DebuggerTransportError::ParentDeathSupervisor)?;
            if result.is_ok() == expect_success {
                Ok(())
            } else {
                Err(DebuggerTransportError::ParentDeathSupervisor)
            }
        }
    }

    impl Drop for ParentDeathSupervisor {
        fn drop(&mut self) {
            if !self.terminal {
                let _termination = sys::terminate_parent_death_supervisor(&self.child);
                let terminal = wait_for_child_exit(&mut self.child, cleanup_deadline());
                if terminal.is_err() {
                    std::process::abort();
                }
            }
            drop(self.input.take());
            if let Some(reader) = self.reader.take() {
                let _ = reader.join();
            }
        }
    }

    fn read_parent_death_reports<R, F>(
        mut input: R,
        expected_reports: usize,
        mut sink: F,
    ) -> Result<(), DebuggerTransportError>
    where
        R: Read,
        F: FnMut(Result<DebuggerParentDeathReport, DebuggerTransportError>) -> bool,
    {
        let mut prefix = [0_u8; EXACT_PINNED_LIBTEST_PREFIX.len()];
        if input.read_exact(&mut prefix).is_err() || prefix != EXACT_PINNED_LIBTEST_PREFIX {
            let _ = sink(Err(DebuggerTransportError::ParentDeathReport));
            return Err(DebuggerTransportError::ParentDeathReport);
        }
        for _ in 0..expected_reports {
            let mut frame = [0_u8; PARENT_DEATH_REPORT_FRAME_BYTES];
            let report = input
                .read_exact(&mut frame)
                .map_err(|_| DebuggerTransportError::ParentDeathReport)
                .and_then(|()| {
                    DebuggerParentDeathReport::decode_exact(&frame)
                        .map_err(|_| DebuggerTransportError::ParentDeathReport)
                });
            let failed = report.is_err();
            if !sink(report) || failed {
                return Err(DebuggerTransportError::ParentDeathReport);
            }
        }
        let mut trailing = [0_u8; 1];
        match input.read(&mut trailing) {
            Ok(0) => Ok(()),
            Ok(_) | Err(_) => Err(DebuggerTransportError::ParentDeathReport),
        }
    }

    fn wait_for_child_exit(
        child: &mut Child,
        deadline: Instant,
    ) -> Result<std::process::ExitStatus, DebuggerTransportError> {
        loop {
            if let Some(status) = child
                .try_wait()
                .map_err(|_| DebuggerTransportError::ParentDeathSupervisor)?
            {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(DebuggerTransportError::Deadline);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn exact_parent_death_supervisor_activation() -> bool {
        let guard = std::env::var_os(PARENT_DEATH_SUPERVISOR_ENV);
        let arguments: Vec<_> = std::env::args_os().skip(1).collect();
        exact_parent_death_supervisor_activation_values(guard.as_deref(), &arguments)
    }

    fn exact_parent_death_supervisor_activation_values(
        guard: Option<&OsStr>,
        arguments: &[OsString],
    ) -> bool {
        guard == Some(OsStr::new("1"))
            && arguments.len() == PARENT_DEATH_SUPERVISOR_ARGS.len()
            && arguments
                .iter()
                .zip(PARENT_DEATH_SUPERVISOR_ARGS)
                .all(|(actual, expected)| actual == OsStr::new(expected))
    }

    fn read_parent_death_command<R: Read>(
        input: &mut R,
    ) -> Result<DebuggerParentDeathCommand, DebuggerTransportError> {
        let mut frame = [0_u8; PARENT_DEATH_COMMAND_FRAME_BYTES];
        input
            .read_exact(&mut frame)
            .map_err(|_| DebuggerTransportError::ParentDeathCommand)?;
        DebuggerParentDeathCommand::decode_exact(&frame)
            .map_err(|_| DebuggerTransportError::ParentDeathCommand)
    }

    fn copy_parent_death_nonce(
        nonce: &DebuggerRunNonce,
    ) -> Result<DebuggerRunNonce, DebuggerTransportError> {
        DebuggerRunNonce::new(*nonce.as_bytes())
            .map_err(|_| DebuggerTransportError::ParentDeathReport)
    }

    #[allow(clippy::too_many_arguments)]
    fn write_parent_death_report<W: Write>(
        output: &mut W,
        command: &DebuggerParentDeathCommand,
        stage: ParentDeathStage,
        supervisor: (u32, u64),
        debugger: (u32, u64),
        target: Option<(u32, u64)>,
    ) -> Result<(), DebuggerTransportError> {
        let (target_process_id, target_creation_time) = target.unwrap_or((0, 0));
        let report = DebuggerParentDeathReport::new(
            copy_parent_death_nonce(command.run_nonce())?,
            stage,
            supervisor.0,
            debugger.0,
            target_process_id,
            supervisor.1,
            debugger.1,
            target_creation_time,
        )
        .map_err(|_| DebuggerTransportError::ParentDeathReport)?;
        output
            .write_all(&report.encode())
            .and_then(|()| output.flush())
            .map_err(|_| DebuggerTransportError::ParentDeathReport)
    }

    fn bind_parent_death_report(
        command: &DebuggerParentDeathCommand,
        expected_stage: ParentDeathStage,
        spawned_supervisor_process_id: u32,
        report: &DebuggerParentDeathReport,
    ) -> Result<(), DebuggerTransportError> {
        let facts = ParentDeathReportBindingFacts {
            nonce_bound: report.run_nonce() == command.run_nonce(),
            expected_stage,
            reported_stage: report.stage(),
            spawned_supervisor_process_id,
            reported_supervisor_process_id: report.supervisor_process_id(),
            debugger_process_id: report.debugger_process_id(),
            target_process_id: report.target_process_id(),
            supervisor_creation_time: report.supervisor_creation_time(),
            debugger_creation_time: report.debugger_creation_time(),
            target_creation_time: report.target_creation_time(),
        };
        if !exact_parent_death_report_binding(facts) {
            return Err(DebuggerTransportError::ParentDeathBinding);
        }
        Ok(())
    }

    fn exact_parent_death_transition(
        ready: &DebuggerParentDeathReport,
        handed_off: &DebuggerParentDeathReport,
    ) -> bool {
        ready.stage() == ParentDeathStage::Ready
            && handed_off.stage() == ParentDeathStage::PostHandoff
            && ready.run_nonce() == handed_off.run_nonce()
            && ready.supervisor_process_id() == handed_off.supervisor_process_id()
            && ready.debugger_process_id() == handed_off.debugger_process_id()
            && ready.target_process_id() == handed_off.target_process_id()
            && ready.supervisor_creation_time() == handed_off.supervisor_creation_time()
            && ready.debugger_creation_time() == handed_off.debugger_creation_time()
            && ready.target_creation_time() == handed_off.target_creation_time()
    }

    fn park_until_parent_termination<R: Read>(input: &mut R) -> Result<(), DebuggerTransportError> {
        let mut unexpected = [0_u8; 1];
        input
            .read_exact(&mut unexpected)
            .map_err(|_| DebuggerTransportError::ParentDeathSupervisor)?;
        Err(DebuggerTransportError::ParentDeathSupervisor)
    }

    fn launch_ready(deadline: Instant) -> Result<ReadyFrozenDebugger, DebuggerTransportError> {
        SuspendedDebuggerTransport::launch_for_kernel_test(deadline)?
            .bootstrap_and_resume(deadline)?
            .await_ready(deadline)
    }

    fn parent_death_report_for_test(
        stage: ParentDeathStage,
    ) -> Result<DebuggerParentDeathReport, DebuggerTransportError> {
        let target = if stage == ParentDeathStage::PreReady {
            (0, 0)
        } else {
            (13, 103)
        };
        DebuggerParentDeathReport::new(
            DebuggerRunNonce::new([0xA7; 32])
                .map_err(|_| DebuggerTransportError::ParentDeathReport)?,
            stage,
            11,
            12,
            target.0,
            101,
            102,
            target.1,
        )
        .map_err(|_| DebuggerTransportError::ParentDeathReport)
    }

    fn run_forced_parent_death_stage(
        stage: ParentDeathStage,
    ) -> Result<(), DebuggerTransportError> {
        let expected_reports = if stage == ParentDeathStage::PostHandoff {
            2
        } else {
            1
        };
        let mut supervisor = ParentDeathSupervisor::spawn(expected_reports)?;
        let command = DebuggerParentDeathCommand::new(fresh_nonce()?, stage);
        supervisor.send_command(&command)?;

        let first_stage = if stage == ParentDeathStage::PostHandoff {
            ParentDeathStage::Ready
        } else {
            stage
        };
        let first = supervisor.receive_report(Instant::now() + PARENT_DEATH_REPORT_BOUND)?;
        bind_parent_death_report(&command, first_stage, supervisor.process_id(), &first)?;
        let supervisor_observation = sys::ParentDeathProcessObservation::open_exact(
            first.supervisor_process_id(),
            first.supervisor_creation_time(),
        )?;
        let debugger_observation = sys::ParentDeathProcessObservation::open_exact(
            first.debugger_process_id(),
            first.debugger_creation_time(),
        )?;
        let target_observation = if first_stage == ParentDeathStage::PreReady {
            None
        } else {
            Some(sys::ParentDeathProcessObservation::open_exact(
                first.target_process_id(),
                first.target_creation_time(),
            )?)
        };

        if stage == ParentDeathStage::PostHandoff {
            supervisor.send_command(&command)?;
            let handed_off =
                supervisor.receive_report(Instant::now() + PARENT_DEATH_REPORT_BOUND)?;
            bind_parent_death_report(
                &command,
                ParentDeathStage::PostHandoff,
                supervisor.process_id(),
                &handed_off,
            )?;
            if !exact_parent_death_transition(&first, &handed_off) {
                return Err(DebuggerTransportError::ParentDeathBinding);
            }
            debugger_observation.wait_for_terminal(cleanup_deadline())?;
            supervisor_observation.prove_live()?;
            target_observation
                .as_ref()
                .ok_or(DebuggerTransportError::ParentDeathBinding)?
                .prove_live()?;
        } else {
            supervisor_observation.prove_live()?;
            debugger_observation.prove_live()?;
            if let Some(target) = target_observation.as_ref() {
                target.prove_live()?;
            }
        }

        let mut observations = vec![&supervisor_observation, &debugger_observation];
        if let Some(target) = target_observation.as_ref() {
            observations.push(target);
        }
        supervisor.terminate_and_prove(&observations, cleanup_deadline(), true)
    }

    #[test]
    #[ignore = "launched only by the exact parent-death outer fixture"]
    fn parent_death_supervisor_fixture() -> Result<(), DebuggerTransportError> {
        if std::env::var_os(PARENT_DEATH_SUPERVISOR_ENV).is_none() {
            return Ok(());
        }
        if !exact_parent_death_supervisor_activation() {
            return Err(DebuggerTransportError::ParentDeathActivation);
        }
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        let command = read_parent_death_command(&mut input)?;
        let supervisor = (
            sys::current_process_id(),
            sys::current_process_creation_time()?,
        );
        match command.stage() {
            ParentDeathStage::PreReady => {
                let suspended = SuspendedDebuggerTransport::launch_for_kernel_test(run_deadline())?;
                let debugger = suspended.prove_parent_death_identity()?;
                write_parent_death_report(
                    &mut output,
                    &command,
                    ParentDeathStage::PreReady,
                    supervisor,
                    debugger,
                    None,
                )?;
                park_until_parent_termination(&mut input)
            }
            ParentDeathStage::Ready => {
                let ready = launch_ready(run_deadline())?;
                let (debugger, target) = ready.prove_parent_death_identities()?;
                write_parent_death_report(
                    &mut output,
                    &command,
                    ParentDeathStage::Ready,
                    supervisor,
                    debugger,
                    Some(target),
                )?;
                park_until_parent_termination(&mut input)
            }
            ParentDeathStage::PostHandoff => {
                let deadline = run_deadline();
                let ready = launch_ready(deadline)?;
                let (debugger, target) = ready.prove_parent_death_identities()?;
                write_parent_death_report(
                    &mut output,
                    &command,
                    ParentDeathStage::Ready,
                    supervisor,
                    debugger,
                    Some(target),
                )?;
                let acknowledgement = read_parent_death_command(&mut input)?;
                if acknowledgement != command {
                    return Err(DebuggerTransportError::ParentDeathCommand);
                }
                let detached = ready.commit(deadline)?;
                if detached.prove_parent_death_target_identity()? != target {
                    return Err(DebuggerTransportError::ParentDeathBinding);
                }
                write_parent_death_report(
                    &mut output,
                    &command,
                    ParentDeathStage::PostHandoff,
                    supervisor,
                    debugger,
                    Some(target),
                )?;
                park_until_parent_termination(&mut input)
            }
        }
    }

    #[test]
    fn frozen_topology_binding_rejects_every_field_mutation() {
        let exact = FrozenTopologyBindingFacts {
            expected_debugger_process_id: 10,
            ready_debugger_process_id: 10,
            target_source_process_id: 10,
            target_process_id: 11,
            target_thread_id: 12,
            expected_sentinel_source: 13,
            ready_sentinel_source: 13,
            target_process_source: 14,
            target_thread_source: 15,
            target_creation_time: 16,
            nonce_bindings: ALL_NONCE_BINDINGS,
        };
        assert!(exact_frozen_topology_binding(exact));
        for rejected in [
            FrozenTopologyBindingFacts {
                expected_debugger_process_id: 0,
                ..exact
            },
            FrozenTopologyBindingFacts {
                ready_debugger_process_id: 9,
                ..exact
            },
            FrozenTopologyBindingFacts {
                target_source_process_id: 9,
                ..exact
            },
            FrozenTopologyBindingFacts {
                target_process_id: 0,
                ..exact
            },
            FrozenTopologyBindingFacts {
                target_process_id: 10,
                ..exact
            },
            FrozenTopologyBindingFacts {
                target_thread_id: 0,
                ..exact
            },
            FrozenTopologyBindingFacts {
                expected_sentinel_source: 0,
                ..exact
            },
            FrozenTopologyBindingFacts {
                ready_sentinel_source: 12,
                ..exact
            },
            FrozenTopologyBindingFacts {
                target_process_source: 0,
                ..exact
            },
            FrozenTopologyBindingFacts {
                target_thread_source: 0,
                ..exact
            },
            FrozenTopologyBindingFacts {
                target_thread_source: 14,
                ..exact
            },
            FrozenTopologyBindingFacts {
                target_creation_time: 0,
                ..exact
            },
        ] {
            assert!(!exact_frozen_topology_binding(rejected));
        }
        for rejected_nonce_bindings in 0..=u8::MAX {
            if rejected_nonce_bindings != ALL_NONCE_BINDINGS {
                assert!(!exact_frozen_topology_binding(FrozenTopologyBindingFacts {
                    nonce_bindings: rejected_nonce_bindings,
                    ..exact
                }));
            }
        }
    }

    #[test]
    fn parent_death_activation_requires_exact_guard_and_every_argument() {
        let exact: Vec<OsString> = PARENT_DEATH_SUPERVISOR_ARGS
            .iter()
            .map(OsString::from)
            .collect();
        assert!(exact_parent_death_supervisor_activation_values(
            Some(OsStr::new("1")),
            &exact,
        ));
        assert!(!exact_parent_death_supervisor_activation_values(
            None, &exact
        ));
        assert!(!exact_parent_death_supervisor_activation_values(
            Some(OsStr::new("0")),
            &exact,
        ));
        for index in 0..exact.len() {
            let mut mutated = exact.clone();
            mutated[index].push("-mutated");
            assert!(!exact_parent_death_supervisor_activation_values(
                Some(OsStr::new("1")),
                &mutated,
            ));
        }
        let mut trailing = exact.clone();
        trailing.push(OsString::from("--quiet"));
        assert!(!exact_parent_death_supervisor_activation_values(
            Some(OsStr::new("1")),
            &trailing,
        ));
        for index in 0..exact.len() {
            let mut missing = exact.clone();
            missing.remove(index);
            assert!(!exact_parent_death_supervisor_activation_values(
                Some(OsStr::new("1")),
                &missing,
            ));
        }
    }

    #[test]
    fn parent_death_report_stream_accepts_every_frame_and_rejects_malformed_input()
    -> Result<(), DebuggerTransportError> {
        for stage in [
            ParentDeathStage::PreReady,
            ParentDeathStage::Ready,
            ParentDeathStage::PostHandoff,
        ] {
            let canonical = parent_death_report_for_test(stage)?.encode();
            let mut stream = EXACT_PINNED_LIBTEST_PREFIX.to_vec();
            stream.extend_from_slice(&canonical);
            let mut observed = Vec::new();
            let stream_result =
                read_parent_death_reports(std::io::Cursor::new(stream), 1, |report| {
                    observed.push(report);
                    true
                });
            assert_eq!(stream_result, Ok(()));
            assert_eq!(observed.len(), 1);
            assert_eq!(
                observed.pop(),
                Some(Ok(parent_death_report_for_test(stage)?))
            );
        }

        let canonical = parent_death_report_for_test(ParentDeathStage::Ready)?.encode();
        for malformed in [
            Vec::new(),
            b"\nrunning 0 test\n".to_vec(),
            EXACT_PINNED_LIBTEST_PREFIX[..15].to_vec(),
        ] {
            let mut observed = Vec::new();
            let stream_result =
                read_parent_death_reports(std::io::Cursor::new(malformed), 1, |report| {
                    observed.push(report);
                    true
                });
            assert_eq!(
                stream_result,
                Err(DebuggerTransportError::ParentDeathReport)
            );
            assert_eq!(
                observed,
                vec![Err(DebuggerTransportError::ParentDeathReport)]
            );
        }
        for length in 0..canonical.len() {
            let mut stream = EXACT_PINNED_LIBTEST_PREFIX.to_vec();
            stream.extend_from_slice(&canonical[..length]);
            let mut observed = Vec::new();
            let stream_result =
                read_parent_death_reports(std::io::Cursor::new(stream), 1, |report| {
                    observed.push(report);
                    true
                });
            assert_eq!(
                stream_result,
                Err(DebuggerTransportError::ParentDeathReport)
            );
            assert_eq!(
                observed,
                vec![Err(DebuggerTransportError::ParentDeathReport)]
            );
        }
        let mut corrupt = canonical;
        corrupt[0] ^= 1;
        let mut stream = EXACT_PINNED_LIBTEST_PREFIX.to_vec();
        stream.extend_from_slice(&corrupt);
        let mut observed = Vec::new();
        let stream_result = read_parent_death_reports(std::io::Cursor::new(stream), 1, |report| {
            observed.push(report);
            true
        });
        assert_eq!(
            stream_result,
            Err(DebuggerTransportError::ParentDeathReport)
        );
        assert_eq!(
            observed,
            vec![Err(DebuggerTransportError::ParentDeathReport)]
        );

        let mut trailing = EXACT_PINNED_LIBTEST_PREFIX.to_vec();
        trailing.extend_from_slice(&canonical);
        trailing.push(0);
        let mut observed = Vec::new();
        let stream_result =
            read_parent_death_reports(std::io::Cursor::new(trailing), 1, |report| {
                observed.push(report);
                true
            });
        assert_eq!(
            stream_result,
            Err(DebuggerTransportError::ParentDeathReport)
        );
        assert_eq!(
            observed,
            vec![Ok(parent_death_report_for_test(ParentDeathStage::Ready)?)]
        );
        Ok(())
    }

    #[test]
    fn parent_death_report_binding_rejects_every_fact_class() {
        let exact = ParentDeathReportBindingFacts {
            nonce_bound: true,
            expected_stage: ParentDeathStage::Ready,
            reported_stage: ParentDeathStage::Ready,
            spawned_supervisor_process_id: 10,
            reported_supervisor_process_id: 10,
            debugger_process_id: 11,
            target_process_id: 12,
            supervisor_creation_time: 13,
            debugger_creation_time: 14,
            target_creation_time: 15,
        };
        assert!(exact_parent_death_report_binding(exact));
        for rejected in [
            ParentDeathReportBindingFacts {
                nonce_bound: false,
                ..exact
            },
            ParentDeathReportBindingFacts {
                expected_stage: ParentDeathStage::PostHandoff,
                ..exact
            },
            ParentDeathReportBindingFacts {
                reported_stage: ParentDeathStage::PreReady,
                ..exact
            },
            ParentDeathReportBindingFacts {
                spawned_supervisor_process_id: 0,
                ..exact
            },
            ParentDeathReportBindingFacts {
                reported_supervisor_process_id: 9,
                ..exact
            },
            ParentDeathReportBindingFacts {
                debugger_process_id: 0,
                ..exact
            },
            ParentDeathReportBindingFacts {
                debugger_process_id: 10,
                ..exact
            },
            ParentDeathReportBindingFacts {
                target_process_id: 0,
                ..exact
            },
            ParentDeathReportBindingFacts {
                target_process_id: 10,
                ..exact
            },
            ParentDeathReportBindingFacts {
                target_process_id: 11,
                ..exact
            },
            ParentDeathReportBindingFacts {
                supervisor_creation_time: 0,
                ..exact
            },
            ParentDeathReportBindingFacts {
                debugger_creation_time: 0,
                ..exact
            },
            ParentDeathReportBindingFacts {
                target_creation_time: 0,
                ..exact
            },
        ] {
            assert!(!exact_parent_death_report_binding(rejected));
        }
        let pre_ready = ParentDeathReportBindingFacts {
            expected_stage: ParentDeathStage::PreReady,
            reported_stage: ParentDeathStage::PreReady,
            target_process_id: 0,
            target_creation_time: 0,
            ..exact
        };
        assert!(exact_parent_death_report_binding(pre_ready));
        assert!(!exact_parent_death_report_binding(
            ParentDeathReportBindingFacts {
                target_process_id: 12,
                ..pre_ready
            }
        ));
        assert!(!exact_parent_death_report_binding(
            ParentDeathReportBindingFacts {
                target_creation_time: 15,
                ..pre_ready
            }
        ));
    }

    #[test]
    fn parent_death_fixture_debug_output_is_data_free() -> Result<(), DebuggerTransportError> {
        let observation = ParentDeathReportBindingFacts {
            nonce_bound: true,
            expected_stage: ParentDeathStage::PreReady,
            reported_stage: ParentDeathStage::PreReady,
            spawned_supervisor_process_id: 1,
            reported_supervisor_process_id: 1,
            debugger_process_id: 2,
            target_process_id: 0,
            supervisor_creation_time: 3,
            debugger_creation_time: 4,
            target_creation_time: 0,
        };
        assert_eq!(
            format!("{observation:?}"),
            "ParentDeathReportBindingFacts([REDACTED])"
        );
        assert_eq!(
            format!(
                "{:?}",
                parent_death_report_for_test(ParentDeathStage::PreReady)?
            ),
            "DebuggerParentDeathReport([REDACTED])"
        );
        Ok(())
    }

    #[test]
    #[ignore = "requires an explicitly built debug-only key-agent-debugger.exe and supported Windows kernel"]
    fn kernel_matrix_forced_parent_death_is_terminal_at_every_checkpoint()
    -> Result<(), DebuggerTransportError> {
        for stage in [
            ParentDeathStage::PreReady,
            ParentDeathStage::Ready,
            ParentDeathStage::PostHandoff,
        ] {
            run_forced_parent_death_stage(stage)?;
        }
        Ok(())
    }

    #[test]
    #[ignore = "requires an explicitly built debug-only key-agent-debugger.exe and supported Windows kernel"]
    fn kernel_forced_parent_death_pre_ready() -> Result<(), DebuggerTransportError> {
        run_forced_parent_death_stage(ParentDeathStage::PreReady)
    }

    #[test]
    #[ignore = "requires an explicitly built debug-only key-agent-debugger.exe and supported Windows kernel"]
    fn kernel_forced_parent_death_ready() -> Result<(), DebuggerTransportError> {
        run_forced_parent_death_stage(ParentDeathStage::Ready)
    }

    #[test]
    #[ignore = "requires an explicitly built debug-only key-agent-debugger.exe and supported Windows kernel"]
    fn kernel_forced_parent_death_post_handoff() -> Result<(), DebuggerTransportError> {
        run_forced_parent_death_stage(ParentDeathStage::PostHandoff)
    }

    #[test]
    #[ignore = "requires an explicitly built debug-only key-agent-debugger.exe and supported Windows kernel"]
    fn kernel_parent_death_native_checkpoint_proofs() -> Result<(), DebuggerTransportError> {
        let suspended = SuspendedDebuggerTransport::launch_for_kernel_test(run_deadline())?;
        let identity = suspended.prove_parent_death_identity()?;
        assert_ne!(identity.0, 0);
        assert_ne!(identity.1, 0);
        suspended.terminate_while_suspended_for_test()?;

        let deadline = run_deadline();
        let ready = launch_ready(deadline)?;
        let (debugger, target) = ready.prove_parent_death_identities()?;
        assert_ne!(debugger.0, 0);
        assert_ne!(debugger.1, 0);
        assert_ne!(target.0, 0);
        assert_ne!(target.1, 0);
        ready.abort(deadline)
    }

    #[test]
    #[ignore = "runs one exact isolated libtest subprocess"]
    fn parent_death_malformed_command_exits_and_cleans_supervisor()
    -> Result<(), DebuggerTransportError> {
        let mut supervisor = ParentDeathSupervisor::spawn(0)?;
        let mut malformed =
            DebuggerParentDeathCommand::new(fresh_nonce()?, ParentDeathStage::PreReady).encode();
        malformed[0] ^= 1;
        supervisor.send_raw_command(&malformed)?;
        supervisor.close_input_and_wait_for_failure(cleanup_deadline())
    }

    #[test]
    #[ignore = "runs one exact isolated libtest subprocess"]
    fn parent_death_report_timeout_forces_bounded_supervisor_cleanup()
    -> Result<(), DebuggerTransportError> {
        let mut supervisor = ParentDeathSupervisor::spawn(1)?;
        let identity = sys::prove_parent_death_supervisor_identity(&supervisor.child)?;
        let observation = sys::ParentDeathProcessObservation::open_exact(identity.0, identity.1)?;
        assert_eq!(
            supervisor.receive_report(Instant::now() + Duration::from_millis(75)),
            Err(DebuggerTransportError::Deadline)
        );
        supervisor.terminate_and_prove(&[&observation], cleanup_deadline(), false)
    }

    #[test]
    #[ignore = "requires an explicitly built debug-only key-agent-debugger.exe and supported Windows kernel"]
    fn kernel_matrix_third_member_is_denied_and_handoff_reaches_two_then_one_then_zero()
    -> Result<(), DebuggerTransportError> {
        let deadline = run_deadline();
        let detached = launch_ready(deadline)?.commit(deadline)?;
        detached.abort(cleanup_deadline())
    }

    #[test]
    #[ignore = "requires an explicitly built debug-only key-agent-debugger.exe and supported Windows kernel"]
    fn kernel_matrix_post_exit_target_termination_is_rejected() -> Result<(), DebuggerTransportError>
    {
        let deadline = run_deadline();
        launch_ready(deadline)?.reject_post_exit_target_termination_for_test(deadline)
    }

    #[test]
    #[ignore = "requires an explicitly built debug-only key-agent-debugger.exe and supported Windows kernel"]
    fn kernel_matrix_dormant_one_shot_debugger_transport_is_exact_on_current_host()
    -> Result<(), DebuggerTransportError> {
        let commit_deadline = run_deadline();
        let detached = launch_ready(commit_deadline)?.commit(commit_deadline)?;
        detached.abort(cleanup_deadline())?;

        let post_exit_mutation_deadline = run_deadline();
        launch_ready(post_exit_mutation_deadline)?
            .reject_post_exit_target_termination_for_test(post_exit_mutation_deadline)?;

        let abort_deadline = run_deadline();
        launch_ready(abort_deadline)?.abort(abort_deadline)?;

        launch_ready(run_deadline())?.parent_eof()?;

        let timeout_deadline = Instant::now() + Duration::from_millis(750);
        launch_ready(timeout_deadline)?.wait_for_protocol_deadline()?;

        let malformed_deadline = run_deadline();
        SuspendedDebuggerTransport::launch_for_kernel_test(malformed_deadline)?
            .resume_with_malformed_bootstrap_for_test(malformed_deadline)?;

        SuspendedDebuggerTransport::launch_for_kernel_test(run_deadline())?
            .terminate_while_suspended_for_test()?;

        SuspendedDebuggerTransport::launch_for_kernel_test(run_deadline())?
            .close_containment_job_while_suspended_for_test()?;

        SuspendedDebuggerTransport::launch_for_kernel_test(run_deadline())?
            .terminate_containment_job_without_process_wait_for_test()?;

        let natural_exit_deadline = run_deadline();
        launch_ready(natural_exit_deadline)?
            .natural_exit_then_drop_cleanup_for_test(natural_exit_deadline)?;

        let suspended = SuspendedDebuggerTransport::launch_for_kernel_test(run_deadline())?;
        assert_eq!(
            format!("{suspended:?}"),
            "SuspendedDebuggerTransport([SUSPENDED HELPER; SENTINEL INSTALLED; HANDLES REDACTED])"
        );
        suspended.terminate_while_suspended_for_test()?;

        let awaiting_deadline = run_deadline();
        let awaiting = SuspendedDebuggerTransport::launch_for_kernel_test(awaiting_deadline)?
            .bootstrap_and_resume(awaiting_deadline)?;
        assert_eq!(
            format!("{awaiting:?}"),
            "AwaitingReadyDebugger([RESUMED HELPER; READY PENDING; HANDLES REDACTED])"
        );
        let ready = awaiting.await_ready(awaiting_deadline)?;
        assert_eq!(
            format!("{ready:?}"),
            "ReadyFrozenDebugger([SENTINEL AND TARGET SOURCE SETS FIXED; TARGET SUSPENDED; DECISION-ONLY; HANDLES REDACTED])"
        );
        ready.abort(awaiting_deadline)
    }

    #[test]
    #[ignore = "requires an explicitly built debug-only key-agent-debugger.exe and supported Windows kernel"]
    fn kernel_matrix_mapped_image_mismatch_is_reaped_before_return()
    -> Result<(), DebuggerTransportError> {
        let actual_debugger = debugger_executable_from_test_environment()?;
        let mismatched = prepare_kernel_test_artifact(
            std::env::current_exe().map_err(|_| DebuggerTransportError::ArtifactAdmission)?,
        )?;
        assert!(matches!(
            SuspendedDebuggerTransport::launch_prepared_for_kernel_test(
                mismatched,
                Some(&actual_debugger),
                run_deadline(),
            ),
            Err(DebuggerTransportError::MappedImage)
        ));
        Ok(())
    }
}
