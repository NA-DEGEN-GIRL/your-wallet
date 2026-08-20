//! Fail-closed dispatcher for the offline inherited-channel protocol.
//!
//! The controller owns the vault service and never accepts secret-bearing
//! values from the Broker.  Creation, opening, and both backup stages can run
//! only through a crate-sealed trusted frontend capability.  The compiled
//! adapter deliberately reports `Unavailable`; wiring authenticated one-shot
//! Secret Input and Recovery helpers remains a release blocker.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use secret_core::AtomicVaultStorage;
use thiserror::Error;

use crate::offline_service::{
    FrontendFailure, NewPasswordInput, OfflineMnemonicSize, OfflineServiceError,
    OfflineWalletService, RecoveryConfirmationInput, RecoveryConfirmationPrompt, RecoveryMaterial,
    UnlockPasswordInput,
};
use crate::offline_wire::{
    OfflineAccount, OfflineCommand, OfflineOutcome, OfflineRequest, OfflineResponse,
    OfflineResponseCode, OfflineStatus, OfflineWireError, decode_request, encode_response,
};
use crate::vault_session::{ManagedAccount, VaultSessionError, VaultSessionStatus};

const FIRST_SEQUENCE: u64 = 1;
const MAX_REQUESTS_PER_CHANNEL: usize = 64;
const MAX_DEADLINE_AHEAD_MS: u64 = 120_000;

/// Seal for trusted clocks and secret/recovery frontend adapters.
mod sealed {
    /// Prevents trust capabilities from being implemented outside Key Agent.
    pub trait Sealed {}
}

/// Stable outcome from a trusted frontend adapter.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum FrontendDispatchError {
    /// No release-approved adapter is installed.
    #[error("trusted offline frontend is unavailable")]
    Unavailable,
    /// The request's admitted absolute/monotonic deadline elapsed.
    #[error("offline request deadline elapsed")]
    Expired,
    /// The requested recovery substage is not live.
    #[error("offline recovery stage is invalid")]
    InvalidState,
    /// The user explicitly cancelled.
    #[error("trusted offline interaction was cancelled")]
    Cancelled,
    /// The authenticated helper exceeded its deadline.
    #[error("trusted offline interaction timed out")]
    TimedOut,
    /// User input or a lifecycle rule rejected the request.
    #[error("trusted offline interaction was rejected")]
    Rejected,
    /// Storage, cryptography, or authenticated helper execution failed.
    #[error("trusted offline interaction failed")]
    Failed,
}

impl From<OfflineServiceError> for FrontendDispatchError {
    fn from(error: OfflineServiceError) -> Self {
        match error {
            OfflineServiceError::Frontend(FrontendFailure::Cancelled) => Self::Cancelled,
            OfflineServiceError::Frontend(FrontendFailure::TimedOut) => Self::TimedOut,
            OfflineServiceError::PasswordMismatch
            | OfflineServiceError::InvalidPassword
            | OfflineServiceError::StaleConfirmation
            | OfflineServiceError::Vault(
                VaultSessionError::InvalidState
                | VaultSessionError::OpenFailed
                | VaultSessionError::RecoveryDisplayConsumed
                | VaultSessionError::RecoveryConfirmationFailed,
            ) => Self::Rejected,
            OfflineServiceError::Frontend(FrontendFailure::Failed)
            | OfflineServiceError::Vault(
                VaultSessionError::CryptographicFailure
                | VaultSessionError::Storage(_)
                | VaultSessionError::TrustedClockFailure,
            ) => Self::Failed,
            OfflineServiceError::Vault(VaultSessionError::DeadlineExpired) => Self::Expired,
        }
    }
}

impl From<FrontendFailure> for FrontendDispatchError {
    fn from(error: FrontendFailure) -> Self {
        Self::from(OfflineServiceError::Frontend(error))
    }
}

/// Opaque deadline passed unchanged to authenticated helper adapters.
///
/// It is intentionally non-`Clone`: one controller admission owns the exact
/// absolute helper expiry and its locally pinned monotonic enforcement point.
pub(crate) struct OfflineFrontendDeadline {
    expires_at_unix_ms: u64,
    expires_at_monotonic: Instant,
}

impl fmt::Debug for OfflineFrontendDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OfflineFrontendDeadline([REDACTED])")
    }
}

impl OfflineFrontendDeadline {
    /// Exact absolute expiry a real helper adapter must put on its request.
    #[must_use]
    pub(crate) const fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

/// One-shot proof that the controller checked its trusted monotonic clock after
/// a frontend returned.
///
/// The fields and minting function are private to this module. Sibling modules
/// can require and consume the proof, but safe Rust cannot construct one or
/// clone it to authorize another transition.
///
/// ```compile_fail
/// use key_agent::offline_controller::CheckedOfflineDeadline;
/// ```
pub(crate) struct CheckedOfflineDeadline<'a> {
    expires_at_monotonic: Instant,
    clock: &'a mut dyn OfflineClock,
}

impl fmt::Debug for CheckedOfflineDeadline<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CheckedOfflineDeadline([REDACTED ONE-SHOT PROOF])")
    }
}

/// Stable internal result of a trusted monotonic recheck.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeadlineRecheckError {
    /// The pinned absolute monotonic expiry has elapsed.
    Expired,
    /// The controller-owned clock could not be sampled.
    Clock,
}

impl CheckedOfflineDeadline<'_> {
    /// Rechecks the same trusted clock and pinned monotonic expiry.
    ///
    /// This remains the only operation exposed to downstream mutation code;
    /// there is deliberately no public or crate-visible constructor.
    pub(crate) fn recheck(&mut self) -> Result<(), DeadlineRecheckError> {
        let now = self
            .clock
            .monotonic_now()
            .map_err(|_| DeadlineRecheckError::Clock)?;
        if now >= self.expires_at_monotonic {
            Err(DeadlineRecheckError::Expired)
        } else {
            Ok(())
        }
    }
}

struct AdmittedRequest {
    now_unix_ms: u64,
    deadline: OfflineFrontendDeadline,
}

/// Crate-sealed access to authenticated password and recovery helpers.
///
/// No method receives recovery answers from an [`OfflineRequest`].  An adapter
/// must acquire them itself through the Secret TCB and pass only opaque trusted
/// frontend objects to [`OfflineWalletService`].
pub(crate) trait OfflineFrontendCapabilities: sealed::Sealed {
    /// Acquires two independent password entries without mutating vault state.
    fn acquire_new_password(
        &mut self,
        _size: OfflineMnemonicSize,
        _deadline: &OfflineFrontendDeadline,
    ) -> Result<NewPasswordInput, FrontendDispatchError> {
        Err(FrontendDispatchError::Unavailable)
    }

    /// Presents borrowed recovery material and returns only a display outcome.
    fn present_backup(
        &mut self,
        _material: RecoveryMaterial<'_>,
        _deadline: &OfflineFrontendDeadline,
    ) -> Result<(), FrontendDispatchError> {
        Err(FrontendDispatchError::Unavailable)
    }

    /// Acquires answers for positions only; expected secrets are unavailable.
    fn acquire_backup_confirmation(
        &mut self,
        _prompt: &RecoveryConfirmationPrompt<'_>,
        _deadline: &OfflineFrontendDeadline,
    ) -> Result<RecoveryConfirmationInput, FrontendDispatchError> {
        Err(FrontendDispatchError::Unavailable)
    }

    /// Acquires one password without mutating vault state.
    fn acquire_unlock_password(
        &mut self,
        _deadline: &OfflineFrontendDeadline,
    ) -> Result<UnlockPasswordInput, FrontendDispatchError> {
        Err(FrontendDispatchError::Unavailable)
    }
}

/// Compiled frontend capability while authenticated production adapters are
/// absent.  Every secret-bearing lifecycle operation fails closed.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct UnavailableOfflineFrontends;

impl sealed::Sealed for UnavailableOfflineFrontends {}
impl OfflineFrontendCapabilities for UnavailableOfflineFrontends {}

/// Trusted time source owned by the controller rather than supplied in wire
/// request data.
pub(crate) trait OfflineClock: sealed::Sealed {
    /// Returns current Unix time in milliseconds.
    fn unix_time_ms(&mut self) -> Result<u64, ClockError>;

    /// Returns a trusted monotonic instant for local deadline enforcement.
    fn monotonic_now(&mut self) -> Result<Instant, ClockError>;
}

/// System wall-clock adapter for the eventual inherited-channel runtime.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SystemOfflineClock;

impl sealed::Sealed for SystemOfflineClock {}

impl OfflineClock for SystemOfflineClock {
    fn unix_time_ms(&mut self) -> Result<u64, ClockError> {
        let milliseconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| ClockError)?
            .as_millis();
        u64::try_from(milliseconds).map_err(|_| ClockError)
    }

    fn monotonic_now(&mut self) -> Result<Instant, ClockError> {
        Ok(Instant::now())
    }
}

/// Non-disclosive trusted-clock failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("trusted offline clock failed")]
pub(crate) struct ClockError;

/// Per-inherited-channel controller with exact replay and sequence state.
pub(crate) struct OfflineController<S, F = UnavailableOfflineFrontends, C = SystemOfflineClock> {
    service: OfflineWalletService<S>,
    frontends: F,
    clock: C,
    expected_sequence: u64,
    seen_request_ids: [u64; MAX_REQUESTS_PER_CHANNEL],
    seen_request_count: usize,
    exhausted: bool,
}

impl<S, F, C> fmt::Debug for OfflineController<S, F, C> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineController")
            .field("service", &"[REDACTED]")
            .field("frontends", &"[REDACTED]")
            .field("clock", &"[REDACTED]")
            .field("expected_sequence", &"[REDACTED]")
            .field("seen_request_ids", &"[REDACTED]")
            .field("seen_request_count", &"[REDACTED]")
            .field("exhausted", &self.exhausted)
            .finish()
    }
}

impl<S> OfflineController<S> {
    /// Creates the production-disabled controller over vault storage.
    #[must_use]
    pub(crate) const fn new_fail_closed(storage: S) -> Self {
        Self {
            service: OfflineWalletService::new(storage),
            frontends: UnavailableOfflineFrontends,
            clock: SystemOfflineClock,
            expected_sequence: FIRST_SEQUENCE,
            seen_request_ids: [0_u64; MAX_REQUESTS_PER_CHANNEL],
            seen_request_count: 0,
            exhausted: false,
        }
    }
}

impl<S, F, C> OfflineController<S, F, C> {
    /// Constructs a controller from crate-internal trusted capabilities.
    #[must_use]
    #[cfg(test)]
    pub(crate) const fn with_parts(
        service: OfflineWalletService<S>,
        frontends: F,
        clock: C,
    ) -> Self {
        Self {
            service,
            frontends,
            clock,
            expected_sequence: FIRST_SEQUENCE,
            seen_request_ids: [0_u64; MAX_REQUESTS_PER_CHANNEL],
            seen_request_count: 0,
            exhausted: false,
        }
    }

    /// Returns only the coarse non-secret state.
    #[must_use]
    pub(crate) const fn status(&self) -> VaultSessionStatus {
        self.service.status()
    }

    /// Locks and consumes this channel controller, returning storage.
    #[must_use]
    pub(crate) fn into_storage(mut self) -> S {
        self.service.lock();
        self.service.into_storage()
    }
}

impl<S, F, C> OfflineController<S, F, C>
where
    S: AtomicVaultStorage,
    F: OfflineFrontendCapabilities,
    C: OfflineClock,
{
    /// Decodes and dispatches one exact request frame.
    ///
    /// A malformed frame produces no response because its request binding is
    /// untrusted; the caller must close the inherited channel.  Every such
    /// failure locks the vault first.
    pub(crate) fn handle_bytes(&mut self, bytes: &[u8]) -> Result<Vec<u8>, OfflineWireError> {
        let request = match decode_request(bytes) {
            Ok(request) => request,
            Err(error) => {
                self.service.lock();
                return Err(error);
            }
        };
        let response = self.handle(&request);
        match encode_response(&response) {
            Ok(encoded) => Ok(encoded),
            Err(error) => {
                self.service.lock();
                Err(error)
            }
        }
    }

    fn handle(&mut self, request: &OfflineRequest) -> OfflineResponse {
        let request_id = request.request_id();
        let sequence = request.sequence();
        let outcome = match self.admit_request(request) {
            Ok(admitted) => self.dispatch(request.command(), &admitted),
            Err(code) => {
                self.service.lock();
                OfflineOutcome::Error(code)
            }
        };
        OfflineResponse::new(request_id, sequence, outcome)
    }

    fn admit_request(
        &mut self,
        request: &OfflineRequest,
    ) -> Result<AdmittedRequest, OfflineResponseCode> {
        if self.seen_request_ids[..self.seen_request_count].contains(&request.request_id()) {
            return Err(OfflineResponseCode::Duplicate);
        }
        if self.exhausted || self.seen_request_count >= MAX_REQUESTS_PER_CHANNEL {
            return Err(OfflineResponseCode::ChannelExhausted);
        }
        if request.sequence() < self.expected_sequence {
            return Err(OfflineResponseCode::Replay);
        }
        if request.sequence() > self.expected_sequence {
            return Err(OfflineResponseCode::OutOfSequence);
        }

        self.seen_request_ids[self.seen_request_count] = request.request_id();
        self.seen_request_count += 1;
        self.expected_sequence = if let Some(next) = self.expected_sequence.checked_add(1) {
            next
        } else {
            self.exhausted = true;
            self.expected_sequence
        };
        if self.seen_request_count == MAX_REQUESTS_PER_CHANNEL {
            self.exhausted = true;
        }

        let now = self
            .clock
            .unix_time_ms()
            .map_err(|_| OfflineResponseCode::Internal)?;
        let remaining = request
            .deadline_unix_ms()
            .checked_sub(now)
            .ok_or(OfflineResponseCode::Expired)?;
        if remaining == 0 || remaining > MAX_DEADLINE_AHEAD_MS {
            return Err(OfflineResponseCode::Expired);
        }
        let expires_at_monotonic = self
            .clock
            .monotonic_now()
            .map_err(|_| OfflineResponseCode::Internal)?
            .checked_add(Duration::from_millis(remaining))
            .ok_or(OfflineResponseCode::Internal)?;
        Ok(AdmittedRequest {
            now_unix_ms: now,
            deadline: OfflineFrontendDeadline {
                expires_at_unix_ms: request.deadline_unix_ms(),
                expires_at_monotonic,
            },
        })
    }

    fn dispatch(&mut self, command: OfflineCommand, admitted: &AdmittedRequest) -> OfflineOutcome {
        let result = match command {
            OfflineCommand::Status => {
                return OfflineOutcome::Status(status_for_wire(self.service.status()));
            }
            OfflineCommand::Lock => {
                self.service.lock();
                return OfflineOutcome::Acknowledged;
            }
            OfflineCommand::GetConfirmedAddress(account) => {
                return if let Ok(address) = self.service.address(managed_account(account)) {
                    OfflineOutcome::ConfirmedAddress {
                        account,
                        address: *address.as_bytes(),
                    }
                } else {
                    self.service.lock();
                    OfflineOutcome::Error(OfflineResponseCode::InvalidState)
                };
            }
            OfflineCommand::Create12 => {
                if self.service.status() == VaultSessionStatus::Locked {
                    self.create(
                        OfflineMnemonicSize::TwelveWords,
                        admitted.now_unix_ms,
                        &admitted.deadline,
                    )
                } else {
                    return self.locked_error(OfflineResponseCode::InvalidState);
                }
            }
            OfflineCommand::Create24 => {
                if self.service.status() == VaultSessionStatus::Locked {
                    self.create(
                        OfflineMnemonicSize::TwentyFourWords,
                        admitted.now_unix_ms,
                        &admitted.deadline,
                    )
                } else {
                    return self.locked_error(OfflineResponseCode::InvalidState);
                }
            }
            OfflineCommand::BeginBackupDisplay => {
                if self.service.status() == VaultSessionStatus::BackupPending {
                    self.begin_backup_display(&admitted.deadline)
                } else {
                    return self.locked_error(OfflineResponseCode::InvalidState);
                }
            }
            OfflineCommand::SubmitBackupConfirmation => {
                if self.service.status() == VaultSessionStatus::BackupPending {
                    self.submit_backup_confirmation(&admitted.deadline)
                } else {
                    return self.locked_error(OfflineResponseCode::InvalidState);
                }
            }
            OfflineCommand::Open => {
                if self.service.status() == VaultSessionStatus::Locked {
                    self.open(&admitted.deadline)
                } else {
                    return self.locked_error(OfflineResponseCode::InvalidState);
                }
            }
        };

        match result {
            Ok(()) if valid_success_state(command, self.service.status()) => {
                OfflineOutcome::Acknowledged
            }
            Ok(()) => self.locked_error(OfflineResponseCode::Internal),
            Err(error) => self.locked_error(map_frontend_error(error)),
        }
    }

    fn create(
        &mut self,
        size: OfflineMnemonicSize,
        now_unix_ms: u64,
        deadline: &OfflineFrontendDeadline,
    ) -> Result<(), FrontendDispatchError> {
        let input = self.frontends.acquire_new_password(size, deadline)?;
        let checked_deadline = checked_deadline(&mut self.clock, deadline)?;
        self.service
            .create_from_input(size, now_unix_ms / 1_000, input, checked_deadline)
            .map_err(FrontendDispatchError::from)
    }

    fn begin_backup_display(
        &mut self,
        deadline: &OfflineFrontendDeadline,
    ) -> Result<(), FrontendDispatchError> {
        let mut frontend_result = None;
        let displayed = self
            .service
            .display_recovery(|material| {
                frontend_result = Some(self.frontends.present_backup(material, deadline));
            })
            .map_err(map_recovery_stage_error)?;
        frontend_result.ok_or(FrontendDispatchError::Failed)??;
        let checked_deadline = checked_deadline(&mut self.clock, deadline)?;
        self.service
            .begin_display(displayed, checked_deadline)
            .map_err(FrontendDispatchError::from)
    }

    fn submit_backup_confirmation(
        &mut self,
        deadline: &OfflineFrontendDeadline,
    ) -> Result<(), FrontendDispatchError> {
        let input = {
            let prompt = self
                .service
                .confirmation_prompt()
                .map_err(map_recovery_stage_error)?;
            self.frontends
                .acquire_backup_confirmation(&prompt, deadline)?
        };
        let checked_deadline = checked_deadline(&mut self.clock, deadline)?;
        self.service
            .submit_confirmation(input, checked_deadline)
            .map_err(FrontendDispatchError::from)
    }

    fn open(&mut self, deadline: &OfflineFrontendDeadline) -> Result<(), FrontendDispatchError> {
        let input = self.frontends.acquire_unlock_password(deadline)?;
        let checked_deadline = checked_deadline(&mut self.clock, deadline)?;
        self.service
            .unlock_from_input(input, checked_deadline)
            .map_err(FrontendDispatchError::from)
    }

    fn locked_error(&mut self, code: OfflineResponseCode) -> OfflineOutcome {
        self.service.lock();
        OfflineOutcome::Error(code)
    }
}

fn checked_deadline<'a, C: OfflineClock>(
    clock: &'a mut C,
    deadline: &OfflineFrontendDeadline,
) -> Result<CheckedOfflineDeadline<'a>, FrontendDispatchError> {
    let mut checked = CheckedOfflineDeadline {
        expires_at_monotonic: deadline.expires_at_monotonic,
        clock,
    };
    checked.recheck().map_err(map_deadline_recheck_error)?;
    Ok(checked)
}

const fn map_deadline_recheck_error(error: DeadlineRecheckError) -> FrontendDispatchError {
    match error {
        DeadlineRecheckError::Expired => FrontendDispatchError::Expired,
        DeadlineRecheckError::Clock => FrontendDispatchError::Failed,
    }
}

#[cfg(test)]
pub(crate) fn with_live_test_deadline<R>(
    operation: impl for<'a> FnOnce(CheckedOfflineDeadline<'a>) -> R,
) -> R {
    let mut clock = SystemOfflineClock;
    let deadline = OfflineFrontendDeadline {
        expires_at_unix_ms: 1,
        expires_at_monotonic: Instant::now()
            .checked_add(Duration::from_hours(1))
            .unwrap_or_else(|| unreachable!("test deadline overflow")),
    };
    let checked = checked_deadline(&mut clock, &deadline)
        .unwrap_or_else(|_| unreachable!("live test deadline"));
    operation(checked)
}

const fn managed_account(account: OfflineAccount) -> ManagedAccount {
    match account {
        OfflineAccount::Index0 => ManagedAccount::Index0,
        OfflineAccount::Index1 => ManagedAccount::Index1,
    }
}

const fn status_for_wire(status: VaultSessionStatus) -> OfflineStatus {
    match status {
        VaultSessionStatus::Locked => OfflineStatus::Locked,
        VaultSessionStatus::BackupPending => OfflineStatus::BackupPending,
        VaultSessionStatus::Unlocked => OfflineStatus::Unlocked,
    }
}

const fn valid_success_state(command: OfflineCommand, status: VaultSessionStatus) -> bool {
    match command {
        OfflineCommand::Create12 | OfflineCommand::Create24 => {
            matches!(status, VaultSessionStatus::BackupPending)
        }
        OfflineCommand::BeginBackupDisplay => matches!(status, VaultSessionStatus::BackupPending),
        OfflineCommand::SubmitBackupConfirmation => matches!(status, VaultSessionStatus::Unlocked),
        OfflineCommand::Open => matches!(
            status,
            VaultSessionStatus::BackupPending | VaultSessionStatus::Unlocked
        ),
        OfflineCommand::Status | OfflineCommand::Lock | OfflineCommand::GetConfirmedAddress(_) => {
            false
        }
    }
}

const fn map_frontend_error(error: FrontendDispatchError) -> OfflineResponseCode {
    match error {
        FrontendDispatchError::Unavailable => OfflineResponseCode::Unavailable,
        FrontendDispatchError::Expired => OfflineResponseCode::Expired,
        FrontendDispatchError::InvalidState => OfflineResponseCode::InvalidState,
        FrontendDispatchError::Cancelled => OfflineResponseCode::Cancelled,
        FrontendDispatchError::TimedOut => OfflineResponseCode::TimedOut,
        FrontendDispatchError::Rejected => OfflineResponseCode::Rejected,
        FrontendDispatchError::Failed => OfflineResponseCode::Internal,
    }
}

fn map_recovery_stage_error(error: OfflineServiceError) -> FrontendDispatchError {
    match error {
        OfflineServiceError::Vault(
            VaultSessionError::InvalidState | VaultSessionError::RecoveryDisplayConsumed,
        ) => FrontendDispatchError::InvalidState,
        other => FrontendDispatchError::from(other),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use secret_core::{AtomicVaultStorage, EthereumAddress, StorageError, VaultBlob};
    use zeroize::Zeroizing;

    use super::{
        ClockError, FrontendDispatchError, OfflineClock, OfflineController,
        OfflineFrontendCapabilities, UnavailableOfflineFrontends, sealed,
    };
    use crate::offline_service::{
        FrontendFailure, NewPasswordInput, OfflineMnemonicSize, OfflineWalletService,
        PasswordFrontend, RecoveryConfirmationFrontend, RecoveryConfirmationInput,
        RecoveryConfirmationPrompt, RecoveryMaterial, RecoveryPresenter, UnlockPasswordInput,
        sealed as service_sealed,
    };
    use crate::offline_wire::{
        OfflineAccount, OfflineCommand, OfflineOutcome, OfflineRequest, OfflineResponseCode,
        OfflineStatus, OfflineWireError, decode_response, encode_request,
    };
    use crate::vault_session::VaultSessionStatus;

    const NOW: u64 = 1_800_000_000_000;

    #[derive(Clone, Default)]
    struct SharedMemoryStorage {
        bytes: Arc<Mutex<Option<Vec<u8>>>>,
        successful_commits: Arc<AtomicUsize>,
    }

    impl SharedMemoryStorage {
        fn successful_commits(&self) -> usize {
            self.successful_commits.load(Ordering::SeqCst)
        }
    }

    impl AtomicVaultStorage for SharedMemoryStorage {
        fn load(&self) -> Result<Vec<u8>, StorageError> {
            self.bytes
                .lock()
                .map_err(|_| StorageError::DurabilityFailure)?
                .clone()
                .ok_or(StorageError::NotFound)
        }

        fn commit(
            &mut self,
            expected_generation: Option<u64>,
            blob: &VaultBlob,
        ) -> Result<(), StorageError> {
            let mut current = self
                .bytes
                .lock()
                .map_err(|_| StorageError::DurabilityFailure)?;
            let actual_generation = current
                .as_deref()
                .map(VaultBlob::parse)
                .transpose()
                .map_err(|_| StorageError::DurabilityFailure)?
                .map(|existing| existing.header().generation());
            if actual_generation != expected_generation {
                return Err(StorageError::GenerationConflict);
            }
            *current = Some(blob.as_bytes().to_vec());
            self.successful_commits.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[derive(Debug)]
    struct FakeClock {
        now: Result<u64, ClockError>,
        monotonic: Instant,
    }

    impl sealed::Sealed for FakeClock {}

    impl OfflineClock for FakeClock {
        fn unix_time_ms(&mut self) -> Result<u64, ClockError> {
            self.now
        }

        fn monotonic_now(&mut self) -> Result<Instant, ClockError> {
            Ok(self.monotonic)
        }
    }

    struct AdvancingClock {
        now: u64,
        base: Instant,
        elapsed: Rc<Cell<Duration>>,
    }

    impl sealed::Sealed for AdvancingClock {}

    impl OfflineClock for AdvancingClock {
        fn unix_time_ms(&mut self) -> Result<u64, ClockError> {
            Ok(self.now)
        }

        fn monotonic_now(&mut self) -> Result<Instant, ClockError> {
            self.base.checked_add(self.elapsed.get()).ok_or(ClockError)
        }
    }

    struct ExpireOnMonotonicCallClock {
        now: u64,
        base: Instant,
        monotonic_calls: usize,
        expire_on_call: usize,
    }

    impl sealed::Sealed for ExpireOnMonotonicCallClock {}

    impl OfflineClock for ExpireOnMonotonicCallClock {
        fn unix_time_ms(&mut self) -> Result<u64, ClockError> {
            Ok(self.now)
        }

        fn monotonic_now(&mut self) -> Result<Instant, ClockError> {
            self.monotonic_calls = self.monotonic_calls.saturating_add(1);
            if self.monotonic_calls >= self.expire_on_call {
                self.base
                    .checked_add(Duration::from_secs(2))
                    .ok_or(ClockError)
            } else {
                Ok(self.base)
            }
        }
    }

    fn controller() -> OfflineController<SharedMemoryStorage, UnavailableOfflineFrontends, FakeClock>
    {
        OfflineController::with_parts(
            OfflineWalletService::new(SharedMemoryStorage::default()),
            UnavailableOfflineFrontends,
            FakeClock {
                now: Ok(NOW),
                monotonic: Instant::now(),
            },
        )
    }

    #[test]
    fn compiled_constructor_is_locked_and_fail_closed() {
        let value = OfflineController::new_fail_closed(SharedMemoryStorage::default());
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        let _storage = value.into_storage();
    }

    fn invoke<S, F, C>(
        controller: &mut OfflineController<S, F, C>,
        command: OfflineCommand,
        request_id: u64,
        sequence: u64,
    ) -> Result<crate::offline_wire::OfflineResponse, OfflineWireError>
    where
        S: AtomicVaultStorage,
        F: OfflineFrontendCapabilities,
        C: OfflineClock,
    {
        let request = OfflineRequest::new(command, request_id, sequence, NOW + 1_000)?;
        let bytes = controller.handle_bytes(&encode_request(&request)?)?;
        decode_response(&bytes)
    }

    #[test]
    fn fail_closed_adapter_allows_status_and_lock_but_not_secret_lifecycle()
    -> Result<(), OfflineWireError> {
        let mut value = controller();
        assert_eq!(
            invoke(&mut value, OfflineCommand::Status, 11, 1)?.outcome(),
            &OfflineOutcome::Status(OfflineStatus::Locked)
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Create12, 12, 2)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Unavailable)
        );
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        assert_eq!(
            invoke(&mut value, OfflineCommand::Lock, 13, 3)?.outcome(),
            &OfflineOutcome::Acknowledged
        );
        Ok(())
    }

    #[test]
    fn duplicate_replay_and_skipped_sequences_are_distinct_and_lock() -> Result<(), OfflineWireError>
    {
        let mut value = controller();
        let _ = invoke(&mut value, OfflineCommand::Status, 20, 1)?;
        assert_eq!(
            invoke(&mut value, OfflineCommand::Status, 20, 2)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Duplicate)
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Status, 21, 1)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Replay)
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Status, 22, 3)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::OutOfSequence)
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Status, 23, 2)?.outcome(),
            &OfflineOutcome::Status(OfflineStatus::Locked)
        );
        Ok(())
    }

    #[test]
    fn expired_request_is_consumed_and_cannot_be_retried() -> Result<(), OfflineWireError> {
        let mut value = controller();
        let expired = OfflineRequest::new(OfflineCommand::Status, 30, 1, NOW)?;
        let first = decode_response(&value.handle_bytes(&encode_request(&expired)?)?)?;
        assert_eq!(
            first.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Expired)
        );
        let retry = OfflineRequest::new(OfflineCommand::Status, 30, 1, NOW + 1_000)?;
        let second = decode_response(&value.handle_bytes(&encode_request(&retry)?)?)?;
        assert_eq!(
            second.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Duplicate)
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Status, 31, 2)?.outcome(),
            &OfflineOutcome::Status(OfflineStatus::Locked)
        );
        Ok(())
    }

    #[test]
    fn deadline_farther_than_the_fixed_window_is_consumed_and_rejected()
    -> Result<(), OfflineWireError> {
        let mut value = controller();
        let too_far = OfflineRequest::new(
            OfflineCommand::Status,
            32,
            1,
            NOW + super::MAX_DEADLINE_AHEAD_MS + 1,
        )?;
        let response = decode_response(&value.handle_bytes(&encode_request(&too_far)?)?)?;
        assert_eq!(
            response.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Expired)
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Status, 32, 1)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Duplicate)
        );
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn fixed_channel_budget_never_forgets_an_identifier() -> Result<(), OfflineWireError> {
        let mut value = controller();
        for sequence in 1_u64..=64 {
            let response = invoke(
                &mut value,
                OfflineCommand::Status,
                sequence + 1_000,
                sequence,
            )?;
            assert_eq!(
                response.outcome(),
                &OfflineOutcome::Status(OfflineStatus::Locked)
            );
        }
        assert_eq!(
            invoke(&mut value, OfflineCommand::Status, 2_000, 65)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::ChannelExhausted)
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Status, 1_001, 65)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Duplicate)
        );
        Ok(())
    }

    #[test]
    fn malformed_frame_locks_without_emitting_a_response() {
        let mut value = controller();
        assert!(value.handle_bytes(b"not-a-frame").is_err());
        assert_eq!(value.status(), VaultSessionStatus::Locked);
    }

    struct PasswordFake;

    impl service_sealed::Sealed for PasswordFake {}

    fn password_text() -> Zeroizing<String> {
        Zeroizing::new("test-only-controller-password".to_owned())
    }

    impl PasswordFrontend for PasswordFake {
        fn acquire_new_password(&mut self) -> Result<NewPasswordInput, FrontendFailure> {
            Ok(NewPasswordInput::new(password_text(), password_text()))
        }

        fn acquire_unlock_password(&mut self) -> Result<UnlockPasswordInput, FrontendFailure> {
            Ok(UnlockPasswordInput::new(password_text()))
        }
    }

    #[derive(Default)]
    struct BackupCopy {
        phrase: Option<Zeroizing<String>>,
        address: Option<EthereumAddress>,
    }

    struct Presenter {
        backup: Rc<RefCell<BackupCopy>>,
    }

    impl service_sealed::Sealed for Presenter {}

    impl RecoveryPresenter for Presenter {
        fn present(&mut self, material: RecoveryMaterial<'_>) -> Result<(), FrontendFailure> {
            let mut backup = self.backup.borrow_mut();
            backup.phrase = Some(Zeroizing::new(material.phrase().to_owned()));
            backup.address = Some(material.first_address());
            Ok(())
        }
    }

    struct Confirmation {
        backup: Rc<RefCell<BackupCopy>>,
    }

    impl service_sealed::Sealed for Confirmation {}

    impl RecoveryConfirmationFrontend for Confirmation {
        fn acquire_confirmation(
            &mut self,
            prompt: &RecoveryConfirmationPrompt<'_>,
        ) -> Result<RecoveryConfirmationInput, FrontendFailure> {
            let backup = self.backup.borrow();
            let phrase = backup.phrase.as_ref().ok_or(FrontendFailure::Failed)?;
            let address = backup.address.ok_or(FrontendFailure::Failed)?;
            let words: Result<Vec<_>, _> = prompt
                .positions()
                .iter()
                .map(|position| {
                    phrase
                        .split(' ')
                        .nth(usize::from(*position).saturating_sub(1))
                        .map(str::to_owned)
                        .ok_or(FrontendFailure::Failed)
                })
                .collect();
            Ok(prompt.bind(Zeroizing::new(words?), address))
        }
    }

    struct CeremonyFrontend {
        backup: Rc<RefCell<BackupCopy>>,
        elapsed: Rc<Cell<Duration>>,
        expire_confirmation: bool,
    }

    impl sealed::Sealed for CeremonyFrontend {}

    impl OfflineFrontendCapabilities for CeremonyFrontend {
        fn present_backup(
            &mut self,
            material: RecoveryMaterial<'_>,
            _deadline: &super::OfflineFrontendDeadline,
        ) -> Result<(), FrontendDispatchError> {
            let mut backup = self.backup.borrow_mut();
            backup.phrase = Some(Zeroizing::new(material.phrase().to_owned()));
            backup.address = Some(material.first_address());
            Ok(())
        }

        fn acquire_backup_confirmation(
            &mut self,
            prompt: &RecoveryConfirmationPrompt<'_>,
            _deadline: &super::OfflineFrontendDeadline,
        ) -> Result<RecoveryConfirmationInput, FrontendDispatchError> {
            let input = Confirmation {
                backup: Rc::clone(&self.backup),
            }
            .acquire_confirmation(prompt)
            .map_err(FrontendDispatchError::from)?;
            if self.expire_confirmation {
                self.elapsed.set(Duration::from_secs(2));
            }
            Ok(input)
        }
    }

    fn pending_service(
        storage: SharedMemoryStorage,
    ) -> Result<OfflineWalletService<SharedMemoryStorage>, FrontendDispatchError> {
        let mut service = OfflineWalletService::new(storage);
        service
            .create(
                OfflineMnemonicSize::TwelveWords,
                NOW / 1_000,
                &mut PasswordFake,
            )
            .map_err(FrontendDispatchError::from)?;
        Ok(service)
    }

    struct CreateFrontend {
        passwords: PasswordFake,
    }

    struct OpenFrontend {
        passwords: PasswordFake,
    }

    impl sealed::Sealed for OpenFrontend {}

    impl OfflineFrontendCapabilities for OpenFrontend {
        fn acquire_unlock_password(
            &mut self,
            _deadline: &super::OfflineFrontendDeadline,
        ) -> Result<UnlockPasswordInput, FrontendDispatchError> {
            self.passwords
                .acquire_unlock_password()
                .map_err(FrontendDispatchError::from)
        }
    }

    impl sealed::Sealed for CreateFrontend {}

    impl OfflineFrontendCapabilities for CreateFrontend {
        fn acquire_new_password(
            &mut self,
            size: OfflineMnemonicSize,
            deadline: &super::OfflineFrontendDeadline,
        ) -> Result<NewPasswordInput, FrontendDispatchError> {
            let _ = (size, deadline.expires_at_unix_ms());
            self.passwords
                .acquire_new_password()
                .map_err(FrontendDispatchError::from)
        }
    }

    struct LyingFrontend;

    impl sealed::Sealed for LyingFrontend {}

    impl OfflineFrontendCapabilities for LyingFrontend {
        fn acquire_new_password(
            &mut self,
            _size: OfflineMnemonicSize,
            _deadline: &super::OfflineFrontendDeadline,
        ) -> Result<NewPasswordInput, FrontendDispatchError> {
            Ok(NewPasswordInput::new(
                Zeroizing::new("valid-test-password-one".to_owned()),
                Zeroizing::new("valid-test-password-two".to_owned()),
            ))
        }
    }

    struct ExpiringCreateFrontend {
        elapsed: Rc<Cell<Duration>>,
        observed_expiry: Rc<Cell<u64>>,
    }

    impl sealed::Sealed for ExpiringCreateFrontend {}

    impl OfflineFrontendCapabilities for ExpiringCreateFrontend {
        fn acquire_new_password(
            &mut self,
            _size: OfflineMnemonicSize,
            deadline: &super::OfflineFrontendDeadline,
        ) -> Result<NewPasswordInput, FrontendDispatchError> {
            self.observed_expiry.set(deadline.expires_at_unix_ms());
            self.elapsed.set(Duration::from_secs(2));
            Ok(NewPasswordInput::new(password_text(), password_text()))
        }
    }

    #[test]
    fn frontend_return_after_monotonic_deadline_cannot_create_or_commit()
    -> Result<(), OfflineWireError> {
        let storage = SharedMemoryStorage::default();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let observed_expiry = Rc::new(Cell::new(0_u64));
        let mut value = OfflineController::with_parts(
            OfflineWalletService::new(storage.clone()),
            ExpiringCreateFrontend {
                elapsed: Rc::clone(&elapsed),
                observed_expiry: Rc::clone(&observed_expiry),
            },
            AdvancingClock {
                now: NOW,
                base: Instant::now(),
                elapsed,
            },
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Create12, 86, 1)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Expired)
        );
        assert_eq!(observed_expiry.get(), NOW + 1_000);
        assert_eq!(storage.successful_commits(), 0);
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn expiry_after_post_frontend_check_but_before_create_commit_leaves_storage_empty()
    -> Result<(), OfflineWireError> {
        let storage = SharedMemoryStorage::default();
        let mut value = OfflineController::with_parts(
            OfflineWalletService::new(storage.clone()),
            CreateFrontend {
                passwords: PasswordFake,
            },
            ExpireOnMonotonicCallClock {
                now: NOW,
                base: Instant::now(),
                monotonic_calls: 0,
                expire_on_call: 3,
            },
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Create12, 87, 1)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Expired)
        );
        assert_eq!(storage.successful_commits(), 0);
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn expiry_after_open_kdf_but_before_state_activation_leaves_session_locked()
    -> Result<(), Box<dyn std::error::Error>> {
        let storage = SharedMemoryStorage::default();
        let mut service = pending_service(storage.clone())?;
        service.lock();
        let mut value = OfflineController::with_parts(
            service,
            OpenFrontend {
                passwords: PasswordFake,
            },
            ExpireOnMonotonicCallClock {
                now: NOW,
                base: Instant::now(),
                monotonic_calls: 0,
                expire_on_call: 3,
            },
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Open, 88, 1)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Expired)
        );
        assert_eq!(storage.successful_commits(), 1);
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    fn confirmed_service()
    -> Result<OfflineWalletService<SharedMemoryStorage>, FrontendDispatchError> {
        let mut service = OfflineWalletService::new(SharedMemoryStorage::default());
        service
            .create(
                OfflineMnemonicSize::TwelveWords,
                NOW / 1_000,
                &mut PasswordFake,
            )
            .map_err(FrontendDispatchError::from)?;
        let backup = Rc::new(RefCell::new(BackupCopy::default()));
        service
            .confirm_backup(
                &mut Presenter {
                    backup: Rc::clone(&backup),
                },
                &mut Confirmation { backup },
            )
            .map_err(FrontendDispatchError::from)?;
        Ok(service)
    }

    #[test]
    fn sealed_test_capability_drives_service_without_wire_secrets()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut value = OfflineController::with_parts(
            OfflineWalletService::new(SharedMemoryStorage::default()),
            CreateFrontend {
                passwords: PasswordFake,
            },
            FakeClock {
                now: Ok(NOW),
                monotonic: Instant::now(),
            },
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Create24, 80, 1)?.outcome(),
            &OfflineOutcome::Acknowledged
        );
        assert_eq!(value.status(), VaultSessionStatus::BackupPending);
        assert_eq!(
            invoke(&mut value, OfflineCommand::BeginBackupDisplay, 81, 2)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Unavailable)
        );
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn confirmation_after_monotonic_deadline_never_commits_confirmed_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let storage = SharedMemoryStorage::default();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let backup = Rc::new(RefCell::new(BackupCopy::default()));
        let mut value = OfflineController::with_parts(
            pending_service(storage.clone())?,
            CeremonyFrontend {
                backup,
                elapsed: Rc::clone(&elapsed),
                expire_confirmation: true,
            },
            AdvancingClock {
                now: NOW,
                base: Instant::now(),
                elapsed,
            },
        );
        assert_eq!(storage.successful_commits(), 1);
        assert_eq!(
            invoke(&mut value, OfflineCommand::BeginBackupDisplay, 82, 1)?.outcome(),
            &OfflineOutcome::Acknowledged
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::SubmitBackupConfirmation, 83, 2,)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Expired)
        );
        assert_eq!(storage.successful_commits(), 1);
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn final_display_recheck_prevents_pending_challenge_activation()
    -> Result<(), Box<dyn std::error::Error>> {
        let storage = SharedMemoryStorage::default();
        let backup = Rc::new(RefCell::new(BackupCopy::default()));
        let mut value = OfflineController::with_parts(
            pending_service(storage.clone())?,
            CeremonyFrontend {
                backup,
                elapsed: Rc::new(Cell::new(Duration::ZERO)),
                expire_confirmation: false,
            },
            ExpireOnMonotonicCallClock {
                now: NOW,
                base: Instant::now(),
                monotonic_calls: 0,
                expire_on_call: 3,
            },
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::BeginBackupDisplay, 89, 1,)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Expired)
        );
        assert_eq!(storage.successful_commits(), 1);
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn expiry_after_confirmation_reseal_but_before_commit_preserves_unconfirmed_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let storage = SharedMemoryStorage::default();
        let backup = Rc::new(RefCell::new(BackupCopy::default()));
        let mut value = OfflineController::with_parts(
            pending_service(storage.clone())?,
            CeremonyFrontend {
                backup,
                elapsed: Rc::new(Cell::new(Duration::ZERO)),
                expire_confirmation: false,
            },
            ExpireOnMonotonicCallClock {
                now: NOW,
                base: Instant::now(),
                monotonic_calls: 0,
                expire_on_call: 6,
            },
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::BeginBackupDisplay, 93, 1,)?.outcome(),
            &OfflineOutcome::Acknowledged
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::SubmitBackupConfirmation, 94, 2,)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Expired)
        );
        assert_eq!(storage.successful_commits(), 1);
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn confirmation_before_display_and_repeated_display_are_rejected_and_lock()
    -> Result<(), Box<dyn std::error::Error>> {
        let storage = SharedMemoryStorage::default();
        let elapsed = Rc::new(Cell::new(Duration::ZERO));
        let backup = Rc::new(RefCell::new(BackupCopy::default()));
        let frontend = CeremonyFrontend {
            backup: Rc::clone(&backup),
            elapsed: Rc::clone(&elapsed),
            expire_confirmation: false,
        };
        let mut before_display = OfflineController::with_parts(
            pending_service(storage.clone())?,
            frontend,
            AdvancingClock {
                now: NOW,
                base: Instant::now(),
                elapsed: Rc::clone(&elapsed),
            },
        );
        assert_eq!(
            invoke(
                &mut before_display,
                OfflineCommand::SubmitBackupConfirmation,
                84,
                1,
            )?
            .outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::InvalidState)
        );
        assert_eq!(before_display.status(), VaultSessionStatus::Locked);

        let repeated_storage = SharedMemoryStorage::default();
        let mut repeated_display = OfflineController::with_parts(
            pending_service(repeated_storage)?,
            CeremonyFrontend {
                backup,
                elapsed: Rc::clone(&elapsed),
                expire_confirmation: false,
            },
            AdvancingClock {
                now: NOW,
                base: Instant::now(),
                elapsed,
            },
        );
        assert_eq!(
            invoke(
                &mut repeated_display,
                OfflineCommand::BeginBackupDisplay,
                85,
                1,
            )?
            .outcome(),
            &OfflineOutcome::Acknowledged
        );
        assert_eq!(
            invoke(
                &mut repeated_display,
                OfflineCommand::BeginBackupDisplay,
                86,
                2,
            )?
            .outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::InvalidState)
        );
        assert_eq!(repeated_display.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn frontend_cannot_claim_success_without_service_validation() -> Result<(), OfflineWireError> {
        let mut value = OfflineController::with_parts(
            OfflineWalletService::new(SharedMemoryStorage::default()),
            LyingFrontend,
            FakeClock {
                now: Ok(NOW),
                monotonic: Instant::now(),
            },
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Create12, 85, 1)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Rejected)
        );
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn confirmed_address_is_available_then_lock_removes_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut value = OfflineController::with_parts(
            confirmed_service()?,
            UnavailableOfflineFrontends,
            FakeClock {
                now: Ok(NOW),
                monotonic: Instant::now(),
            },
        );
        let response = invoke(
            &mut value,
            OfflineCommand::GetConfirmedAddress(OfflineAccount::Index0),
            90,
            1,
        )?;
        assert!(matches!(
            response.outcome(),
            OfflineOutcome::ConfirmedAddress {
                account: OfflineAccount::Index0,
                ..
            }
        ));
        assert_eq!(
            invoke(&mut value, OfflineCommand::Lock, 91, 2)?.outcome(),
            &OfflineOutcome::Acknowledged
        );
        assert_eq!(
            invoke(
                &mut value,
                OfflineCommand::GetConfirmedAddress(OfflineAccount::Index0),
                92,
                3,
            )?
            .outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::InvalidState)
        );
        Ok(())
    }

    #[test]
    fn trusted_clock_failure_is_stable_consumed_and_fail_closed() -> Result<(), OfflineWireError> {
        let mut value = OfflineController::with_parts(
            OfflineWalletService::new(SharedMemoryStorage::default()),
            UnavailableOfflineFrontends,
            FakeClock {
                now: Err(ClockError),
                monotonic: Instant::now(),
            },
        );
        assert_eq!(
            invoke(&mut value, OfflineCommand::Status, 100, 1)?.outcome(),
            &OfflineOutcome::Error(OfflineResponseCode::Internal)
        );
        assert_eq!(value.status(), VaultSessionStatus::Locked);
        assert!(!format!("{value:?}").contains("100"));
        let _storage = value.into_storage();
        Ok(())
    }
}
