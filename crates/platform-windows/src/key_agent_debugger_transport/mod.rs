//! Dormant one-shot parent transport for an isolated Key Agent debugger helper.
//!
//! This module proves only current-host, deadline-driven process transport and
//! one sentinel-handle install/pull round trip. It creates no Key Agent,
//! receives no `DEBUG_EVENT`, and has no production caller or re-export.
//!
//! It deliberately owns no Job. Named-pipe cancellation still depends on the
//! kernel completing the mandatory overlapped-I/O drain, and process fail-fast
//! prevents parent continuation but cannot prove child death. Those liveness
//! and parent-death-containment gaps remain production STOP-SHIP work.

#![allow(dead_code)] // Entire module is an explicitly dormant feasibility surface.

mod sys;

use core::fmt;
#[cfg(test)]
use std::ffi::OsStr;
#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::path::{Component, PathBuf};
use std::time::{Duration, Instant};

use key_agent_debugger_wire::{
    DebuggerBootstrap, DebuggerDecision, DebuggerDecisionFrame, DebuggerExitCode,
    DebuggerReadyFrozen, DebuggerRunNonce, RemoteHandleWord,
};
use thiserror::Error;

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
const RUN_BOUND: Duration = Duration::from_secs(4);
const CLEANUP_BOUND: Duration = Duration::from_secs(5);

/// Stable, data-free failure categories for the dormant transport.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
enum DebuggerTransportError {
    #[error("debugger executable test environment was invalid")]
    ExecutableEnvironment,
    #[error("debugger executable path was invalid")]
    ExecutablePath,
    #[error("debugger process context preparation failed")]
    ProcessContext,
    #[error("debugger inheritable-handle launch flight failed")]
    LaunchFlight,
    #[error("debugger private pipe preparation failed")]
    PrivatePipes,
    #[error("debugger process creation failed")]
    ProcessCreation,
    #[error("debugger process identity validation failed")]
    ProcessIdentity,
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
    #[error("debugger sentinel observer pull failed")]
    SentinelPull,
    #[error("debugger sentinel observer proof failed")]
    SentinelProof,
    #[error("debugger decision send failed")]
    Decision,
    #[error("debugger process cleanup or exit proof failed")]
    ProcessExit,
    #[error("debugger operation deadline elapsed")]
    Deadline,
}

/// Newly created debugger helper whose primary thread still has the exact
/// `CREATE_SUSPENDED` count and whose SYNCHRONIZE-only sentinel source is already
/// installed in its private handle table.
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
        let context = RestrictedProcessContext::prepare_for_kernel_test()
            .map_err(|_| DebuggerTransportError::ProcessContext)?;
        let pipes = PrivateKeyAgentDebuggerPipes::create()
            .map_err(|_| DebuggerTransportError::PrivatePipes)?;
        let flight = acquire_inheritable_handle_launch(deadline)
            .map_err(|_| DebuggerTransportError::LaunchFlight)?;
        let inheritance = pipes
            .prepare_child_inheritance(&flight)
            .map_err(|_| DebuggerTransportError::PrivatePipes)?;
        let child = sys::DebuggerChild::create_suspended(
            &executable,
            &context,
            &inheritance,
            &flight,
            deadline,
        )?;
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
}

impl fmt::Debug for SuspendedDebuggerTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "SuspendedDebuggerTransport([SUSPENDED HELPER; SENTINEL INSTALLED; HANDLES REDACTED])",
        )
    }
}

/// Resumed helper awaiting one exact `READY_FROZEN` frame and stdout EOF.
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
        let frame = self
            .status
            .receive(deadline)
            .map_err(|_| DebuggerTransportError::ReadyReceive)?;
        let ready = DebuggerReadyFrozen::decode_exact(&frame)
            .map_err(|_| DebuggerTransportError::ReadyReceive)?;
        if ready.run_nonce() != self.bootstrap.run_nonce()
            || ready.debugger_process_id() != self.child.process_id()
            || ready.sentinel_source_handle().value() != self.bootstrap.sentinel_handle().value()
        {
            return Err(DebuggerTransportError::ReadyBinding);
        }
        let (nonce, _debugger_process_id, source_word) = ready.into_parts();
        let observer = self.child.pull_sentinel_observer(source_word.value())?;
        let sentinel = sys::SentinelEvidence::prove(self.sentinel, observer)?;
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
        })
    }
}

impl fmt::Debug for AwaitingReadyDebugger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("AwaitingReadyDebugger([RESUMED HELPER; READY PENDING; HANDLES REDACTED])")
    }
}

/// One helper that proved the immutable sentinel source word and now accepts
/// only a final decision.
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
}

impl ReadyFrozenDebugger {
    fn commit(self, deadline: Instant) -> Result<(), DebuggerTransportError> {
        self.finish(
            DebuggerDecision::Commit,
            DebuggerExitCode::Success,
            deadline,
        )
    }

    fn abort(self, deadline: Instant) -> Result<(), DebuggerTransportError> {
        self.finish(DebuggerDecision::Abort, DebuggerExitCode::Aborted, deadline)
    }

    #[cfg(test)]
    fn parent_eof(self) -> Result<(), DebuggerTransportError> {
        let Self {
            mut child,
            control,
            nonce: _,
            sentinel,
        } = self;
        control
            .close_after_bootstrap_for_test()
            .map_err(|_| DebuggerTransportError::Decision)?;
        let _sentinel_kept_live_until_exit = sentinel;
        child.wait_for_exact_exit(DebuggerExitCode::ParentEof, cleanup_deadline())
    }

    #[cfg(test)]
    fn wait_for_protocol_deadline(self) -> Result<(), DebuggerTransportError> {
        let Self {
            mut child,
            control,
            nonce: _,
            sentinel,
        } = self;
        let _control_kept_open_until_exit = control;
        let _sentinel_kept_live_until_exit = sentinel;
        child.wait_for_exact_exit(DebuggerExitCode::DeadlineElapsed, cleanup_deadline())
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
        } = self;
        let frame = DebuggerDecisionFrame::new(nonce, DebuggerDecision::Commit).encode();
        control
            .finish(&frame, deadline)
            .map_err(|_| DebuggerTransportError::Decision)?;
        child.observe_terminal_without_reaping_for_test(cleanup_deadline())?;
        let _sentinel_kept_live_until_exit = sentinel;
        // Drop deliberately begins with `reaped == false` after natural exit.
        // Its expected forced-exit code will mismatch, but terminal proof must
        // suppress fail-fast and permit ordinary owner closure.
        drop(child);
        Ok(())
    }

    fn finish(
        self,
        decision: DebuggerDecision,
        expected_exit: DebuggerExitCode,
        deadline: Instant,
    ) -> Result<(), DebuggerTransportError> {
        let Self {
            mut child,
            control,
            nonce,
            sentinel,
        } = self;
        let frame = DebuggerDecisionFrame::new(nonce, decision).encode();
        control
            .finish(&frame, deadline)
            .map_err(|_| DebuggerTransportError::Decision)?;
        let _sentinel_kept_live_until_exit = sentinel;
        child.wait_for_exact_exit(expected_exit, cleanup_deadline())
    }
}

impl fmt::Debug for ReadyFrozenDebugger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "ReadyFrozenDebugger([SENTINEL SOURCE SET FIXED; DECISION-ONLY; NOT OS-SUSPENDED; HANDLES REDACTED])",
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
        DebuggerTransportError, ReadyFrozenDebugger, SuspendedDebuggerTransport, run_deadline,
    };
    use std::time::{Duration, Instant};

    fn launch_ready(deadline: Instant) -> Result<ReadyFrozenDebugger, DebuggerTransportError> {
        SuspendedDebuggerTransport::launch_for_kernel_test(deadline)?
            .bootstrap_and_resume(deadline)?
            .await_ready(deadline)
    }

    #[test]
    #[ignore = "requires an explicitly built debug-only key-agent-debugger.exe and supported Windows kernel"]
    fn kernel_matrix_dormant_one_shot_debugger_transport_is_exact_on_current_host()
    -> Result<(), DebuggerTransportError> {
        let commit_deadline = run_deadline();
        launch_ready(commit_deadline)?.commit(commit_deadline)?;

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
            "ReadyFrozenDebugger([SENTINEL SOURCE SET FIXED; DECISION-ONLY; NOT OS-SUSPENDED; HANDLES REDACTED])"
        );
        ready.abort(awaiting_deadline)
    }
}
