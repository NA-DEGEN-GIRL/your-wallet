//! Internal controller for the offline vault lifecycle.
//!
//! This module is deliberately crate-private. Passwords, recovery words, and
//! private keys never become broker protocol values: the controller acquires
//! secrets only through sealed Key Agent frontend traits and borrows signing
//! keys only inside a caller-supplied closure.
//!
//! # STOP-SHIP
//!
//! `RecoveryPresenter`, `RecoveryConfirmationFrontend`, and `PasswordFrontend`
//! are contracts, not a production UI implementation. Mainnet and production
//! runtime entrypoints must remain fail-closed until their only implementations
//! use the authenticated, one-shot Secret Input/Recovery helper channel with
//! peer-process authentication, exact bounded framing, explicit cancel and
//! timeout outcomes, clipboard suppression, and immediate helper teardown.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use secret_core::{
    AtomicVaultStorage, EthereumAddress, MnemonicWordCount, RawPrivateKey, VaultPassword,
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::offline_controller::CheckedOfflineDeadline;
use crate::vault_session::{
    DisplayedRecovery, ManagedAccount, RecoveryChallenge, RecoveryConfirmation,
    RecoveryDisplayView, VaultSession, VaultSessionError, VaultSessionStatus,
};

const MAX_PASSWORD_INPUT_BYTES: usize = 4_096;
const FRONTEND_BINDING_BYTES: usize = 32;
const FRONTEND_BINDING_ATTEMPTS: usize = 16;

/// Crate-only seal implemented by trusted Key Agent frontend adapters.
pub(crate) mod sealed {
    /// Prevents frontend contracts from being implemented outside this crate.
    pub trait Sealed {}
}

/// Stable non-secret reasons why a trusted frontend did not return a value.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum FrontendFailure {
    /// The user explicitly cancelled the interaction.
    #[error("frontend interaction was cancelled")]
    Cancelled,
    /// The one-shot interaction exceeded its deadline.
    #[error("frontend interaction timed out")]
    TimedOut,
    /// The authenticated helper or its private channel failed.
    #[error("frontend interaction failed")]
    Failed,
}

/// Two independently entered candidate passwords for a new vault.
pub(crate) struct NewPasswordInput {
    first: Zeroizing<String>,
    confirmation: Zeroizing<String>,
}

impl fmt::Debug for NewPasswordInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NewPasswordInput([REDACTED])")
    }
}

impl NewPasswordInput {
    /// Takes ownership of already-zeroizing frontend values.
    #[must_use]
    pub(crate) const fn new(first: Zeroizing<String>, confirmation: Zeroizing<String>) -> Self {
        Self {
            first,
            confirmation,
        }
    }
}

/// One password entered for a vault-unlock attempt.
pub(crate) struct UnlockPasswordInput {
    value: Zeroizing<String>,
}

impl fmt::Debug for UnlockPasswordInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("UnlockPasswordInput([REDACTED])")
    }
}

impl UnlockPasswordInput {
    /// Takes ownership of an already-zeroizing frontend value.
    #[must_use]
    pub(crate) const fn new(value: Zeroizing<String>) -> Self {
        Self { value }
    }
}

/// Authenticated source for password interactions inside the Key Agent TCB.
pub(crate) trait PasswordFrontend: sealed::Sealed {
    /// Acquires a new password and an independent repeat entry.
    fn acquire_new_password(&mut self) -> Result<NewPasswordInput, FrontendFailure>;

    /// Acquires one password for opening an existing vault.
    fn acquire_unlock_password(&mut self) -> Result<UnlockPasswordInput, FrontendFailure>;
}

/// Borrowed recovery material valid only during one presenter callback.
pub(crate) struct RecoveryMaterial<'a> {
    phrase: &'a str,
    first_address: EthereumAddress,
}

impl fmt::Debug for RecoveryMaterial<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryMaterial([REDACTED])")
    }
}

impl<'a> RecoveryMaterial<'a> {
    const fn from_view(view: &RecoveryDisplayView<'a>) -> Self {
        Self {
            phrase: view.phrase(),
            first_address: view.first_address(),
        }
    }

    /// Borrows the mnemonic for immediate rendering by the trusted presenter.
    #[must_use]
    pub(crate) const fn phrase(&self) -> &'a str {
        self.phrase
    }

    /// Returns the first address that belongs on the independent backup copy.
    #[must_use]
    pub(crate) const fn first_address(&self) -> EthereumAddress {
        self.first_address
    }
}

/// One-shot recovery-output frontend inside the Secret TCB.
pub(crate) trait RecoveryPresenter: sealed::Sealed {
    /// Presents the borrowed phrase and first address without returning either.
    fn present(&mut self, material: RecoveryMaterial<'_>) -> Result<(), FrontendFailure>;
}

/// Secret-free recovery word positions plus an opaque per-call binding.
pub(crate) struct RecoveryConfirmationPrompt<'a> {
    positions: [u8; 4],
    binding: &'a [u8; FRONTEND_BINDING_BYTES],
}

impl fmt::Debug for RecoveryConfirmationPrompt<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecoveryConfirmationPrompt")
            .field("positions", &self.positions)
            .field("binding", &"[REDACTED]")
            .finish()
    }
}

impl RecoveryConfirmationPrompt<'_> {
    /// Returns the four sorted, one-based word positions to ask the user for.
    #[must_use]
    pub(crate) const fn positions(&self) -> &[u8; 4] {
        &self.positions
    }

    /// Binds newly entered answers to this exact frontend call.
    ///
    /// Only a trusted frontend implementation can obtain a prompt. Moving an
    /// older response into a later call fails the controller's binding check.
    #[must_use]
    pub(crate) fn bind(
        &self,
        words: Zeroizing<Vec<String>>,
        first_address: EthereumAddress,
    ) -> RecoveryConfirmationInput {
        RecoveryConfirmationInput {
            words,
            first_address,
            binding: Zeroizing::new(*self.binding),
        }
    }
}

/// User-entered recovery answers, zeroized and bound to one frontend call.
pub(crate) struct RecoveryConfirmationInput {
    words: Zeroizing<Vec<String>>,
    first_address: EthereumAddress,
    binding: Zeroizing<[u8; FRONTEND_BINDING_BYTES]>,
}

impl fmt::Debug for RecoveryConfirmationInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryConfirmationInput([REDACTED])")
    }
}

/// Authenticated source for independent recovery-confirmation entries.
pub(crate) trait RecoveryConfirmationFrontend: sealed::Sealed {
    /// Acquires four words and the independently retained first address.
    fn acquire_confirmation(
        &mut self,
        prompt: &RecoveryConfirmationPrompt<'_>,
    ) -> Result<RecoveryConfirmationInput, FrontendFailure>;
}

/// User-selected mnemonic size for vault creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OfflineMnemonicSize {
    /// Create a 12-word BIP-39 backup.
    TwelveWords,
    /// Create a 24-word BIP-39 backup.
    TwentyFourWords,
}

impl From<OfflineMnemonicSize> for MnemonicWordCount {
    fn from(value: OfflineMnemonicSize) -> Self {
        match value {
            OfflineMnemonicSize::TwelveWords => Self::Twelve,
            OfflineMnemonicSize::TwentyFourWords => Self::TwentyFour,
        }
    }
}

/// Stable, secret-free failures from the internal offline controller.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum OfflineServiceError {
    /// A trusted frontend cancelled, timed out, or failed.
    #[error(transparent)]
    Frontend(#[from] FrontendFailure),
    /// The two new-password entries were not byte-for-byte identical.
    #[error("new password entries did not match")]
    PasswordMismatch,
    /// A password did not satisfy the fixed vault profile.
    #[error("password did not satisfy the vault profile")]
    InvalidPassword,
    /// A response object belonged to an older confirmation call.
    #[error("recovery confirmation response was stale")]
    StaleConfirmation,
    /// The underlying fail-closed vault transition failed.
    #[error(transparent)]
    Vault(#[from] VaultSessionError),
}

/// Single internal controller for create, backup, unlock, and lock operations.
pub(crate) struct OfflineWalletService<S> {
    session: VaultSession<S>,
    pending_confirmation: Option<PendingRecoveryConfirmation>,
}

struct PendingRecoveryConfirmation {
    challenge: RecoveryChallenge,
    frontend_binding: Zeroizing<[u8; FRONTEND_BINDING_BYTES]>,
}

impl fmt::Debug for PendingRecoveryConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PendingRecoveryConfirmation([REDACTED])")
    }
}

impl<S> fmt::Debug for OfflineWalletService<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfflineWalletService")
            .field("session", &"[REDACTED]")
            .field("status", &self.status())
            .finish()
    }
}

impl<S> OfflineWalletService<S> {
    /// Creates a locked controller over an atomic vault storage implementation.
    #[must_use]
    pub(crate) const fn new(storage: S) -> Self {
        Self {
            session: VaultSession::new(storage),
            pending_confirmation: None,
        }
    }

    /// Returns the only lifecycle state suitable for status surfaces.
    #[must_use]
    pub(crate) const fn status(&self) -> VaultSessionStatus {
        self.session.status()
    }

    /// Immediately drops decrypted vault state.
    pub(crate) fn lock(&mut self) {
        self.pending_confirmation = None;
        self.session.lock();
    }

    /// Consumes the controller after locking and returns its storage.
    #[must_use]
    pub(crate) fn into_storage(self) -> S {
        self.session.into_storage()
    }
}

impl<S: AtomicVaultStorage> OfflineWalletService<S> {
    /// Creates a pending vault from two already-acquired password entries.
    ///
    /// Requires the controller's one-shot checked-deadline capability. The
    /// session rechecks it after expensive work and before durable mutation.
    pub(crate) fn create_from_input(
        &mut self,
        size: OfflineMnemonicSize,
        created_at_unix: u64,
        entries: NewPasswordInput,
        checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<(), OfflineServiceError> {
        let result = self.create_from_input_inner(size, created_at_unix, entries, checked_deadline);
        self.lock_on_error(result)
    }

    fn create_from_input_inner(
        &mut self,
        size: OfflineMnemonicSize,
        created_at_unix: u64,
        entries: NewPasswordInput,
        checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<(), OfflineServiceError> {
        let NewPasswordInput {
            first,
            confirmation,
        } = entries;
        if !passwords_match(&first, &confirmation) {
            return Err(OfflineServiceError::PasswordMismatch);
        }
        let password =
            VaultPassword::new(first.as_str()).map_err(|_| OfflineServiceError::InvalidPassword)?;
        self.session
            .create_checked(password, size.into(), created_at_unix, checked_deadline)?;
        Ok(())
    }

    /// Test-only compatibility helper that acquires password input in-process.
    #[cfg(test)]
    pub(crate) fn create(
        &mut self,
        size: OfflineMnemonicSize,
        created_at_unix: u64,
        passwords: &mut impl PasswordFrontend,
    ) -> Result<(), OfflineServiceError> {
        let entries = passwords.acquire_new_password()?;
        crate::offline_controller::with_live_test_deadline(|checked_deadline| {
            self.create_from_input(size, created_at_unix, entries, checked_deadline)
        })
    }

    /// Opens the latest committed generation from already-acquired input.
    ///
    /// Requires the controller's one-shot checked-deadline capability. The
    /// session rechecks it after open/derivation and before state activation.
    pub(crate) fn unlock_from_input(
        &mut self,
        input: UnlockPasswordInput,
        checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<(), OfflineServiceError> {
        let result = self.unlock_from_input_inner(input, checked_deadline);
        self.lock_on_error(result)
    }

    fn unlock_from_input_inner(
        &mut self,
        input: UnlockPasswordInput,
        checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<(), OfflineServiceError> {
        let UnlockPasswordInput { value } = input;
        let password =
            VaultPassword::new(value.as_str()).map_err(|_| OfflineServiceError::InvalidPassword)?;
        self.session.open_checked(password, checked_deadline)?;
        Ok(())
    }

    /// Test-only compatibility helper that acquires password input in-process.
    #[cfg(test)]
    pub(crate) fn unlock(
        &mut self,
        passwords: &mut impl PasswordFrontend,
    ) -> Result<(), OfflineServiceError> {
        let input = passwords.acquire_unlock_password()?;
        crate::offline_controller::with_live_test_deadline(|checked_deadline| {
            self.unlock_from_input(input, checked_deadline)
        })
    }

    /// Borrows recovery material for one read-only display callback.
    ///
    /// Returning from the callback only creates a non-clone, secret-free
    /// capability. The live session is unchanged until [`Self::begin_display`]
    /// consumes it after the controller's monotonic deadline recheck.
    pub(crate) fn display_recovery(
        &mut self,
        presenter: impl FnOnce(RecoveryMaterial<'_>),
    ) -> Result<DisplayedRecovery, OfflineServiceError> {
        let result = if self.pending_confirmation.is_some() {
            Err(OfflineServiceError::Vault(VaultSessionError::InvalidState))
        } else {
            self.session
                .display_recovery(|view| presenter(RecoveryMaterial::from_view(&view)))
                .map_err(OfflineServiceError::from)
        };
        self.lock_on_error(result)
    }

    /// Commits a completed display to one in-memory confirmation challenge.
    ///
    /// This does not durably confirm the backup. It consumes the controller's
    /// checked-deadline capability and rechecks after binding randomness but
    /// before pending-state mutation.
    #[allow(clippy::needless_pass_by_value)] // Intentionally consumes a one-shot capability.
    pub(crate) fn begin_display(
        &mut self,
        displayed: DisplayedRecovery,
        checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<(), OfflineServiceError> {
        let result = self.begin_display_inner(displayed, checked_deadline);
        self.lock_on_error(result)
    }

    fn begin_display_inner(
        &mut self,
        displayed: DisplayedRecovery,
        checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<(), OfflineServiceError> {
        if self.pending_confirmation.is_some() {
            return Err(OfflineServiceError::Vault(VaultSessionError::InvalidState));
        }
        let frontend_binding = random_frontend_binding()?;
        let challenge = self
            .session
            .commit_displayed_recovery_checked(displayed, checked_deadline)?;
        self.pending_confirmation = Some(PendingRecoveryConfirmation {
            challenge,
            frontend_binding,
        });
        Ok(())
    }

    /// Borrows only the four positions and a fresh opaque frontend binding.
    pub(crate) fn confirmation_prompt(
        &self,
    ) -> Result<RecoveryConfirmationPrompt<'_>, OfflineServiceError> {
        let pending = self
            .pending_confirmation
            .as_ref()
            .ok_or(OfflineServiceError::Vault(VaultSessionError::InvalidState))?;
        Ok(RecoveryConfirmationPrompt {
            positions: (*pending.challenge.positions())
                .map(crate::vault_session::RecoveryWordPosition::get),
            binding: &pending.frontend_binding,
        })
    }

    /// Consumes independent confirmation input and durably confirms the backup.
    ///
    /// Consumes the controller's checked-deadline capability; the session
    /// rechecks after resealing and immediately before the durable commit.
    pub(crate) fn submit_confirmation(
        &mut self,
        mut input: RecoveryConfirmationInput,
        checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<(), OfflineServiceError> {
        let result = self.submit_confirmation_inner(&mut input, checked_deadline);
        self.lock_on_error(result)
    }

    fn submit_confirmation_inner(
        &mut self,
        input: &mut RecoveryConfirmationInput,
        checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<(), OfflineServiceError> {
        let pending = self
            .pending_confirmation
            .take()
            .ok_or(OfflineServiceError::Vault(VaultSessionError::InvalidState))?;
        if !bool::from(
            input
                .binding
                .as_ref()
                .ct_eq(pending.frontend_binding.as_ref()),
        ) {
            return Err(OfflineServiceError::StaleConfirmation);
        }
        let words = core::mem::take(input.words.as_mut());
        self.session.confirm_backup_checked(
            pending.challenge,
            RecoveryConfirmation::new(words, input.first_address),
            checked_deadline,
        )?;
        Ok(())
    }

    /// Test-only compatibility helper for the former combined ceremony API.
    #[cfg(test)]
    pub(crate) fn confirm_backup(
        &mut self,
        presenter: &mut impl RecoveryPresenter,
        confirmation: &mut impl RecoveryConfirmationFrontend,
    ) -> Result<(), OfflineServiceError> {
        let result = self.confirm_backup_for_test(presenter, confirmation);
        self.lock_on_error(result)
    }

    #[cfg(test)]
    fn confirm_backup_for_test(
        &mut self,
        presenter: &mut impl RecoveryPresenter,
        confirmation: &mut impl RecoveryConfirmationFrontend,
    ) -> Result<(), OfflineServiceError> {
        let mut presentation_result = Ok(());
        let displayed = self.display_recovery(|material| {
            presentation_result = presenter.present(material);
        })?;
        presentation_result?;
        crate::offline_controller::with_live_test_deadline(|checked_deadline| {
            self.begin_display(displayed, checked_deadline)
        })?;
        let input = confirmation.acquire_confirmation(&self.confirmation_prompt()?)?;
        crate::offline_controller::with_live_test_deadline(|checked_deadline| {
            self.submit_confirmation(input, checked_deadline)
        })
    }

    /// Returns an address only after durable backup confirmation.
    pub(crate) fn address(
        &self,
        account: ManagedAccount,
    ) -> Result<EthereumAddress, OfflineServiceError> {
        self.session
            .copyable_address(account)
            .map_err(OfflineServiceError::from)
    }

    /// Borrows a confirmed account key only for one internal signing operation.
    pub(crate) fn with_signing_key_checked<R>(
        &self,
        account: ManagedAccount,
        checked_deadline: CheckedOfflineDeadline<'_>,
        operation: impl FnOnce(&RawPrivateKey) -> R,
    ) -> Result<R, OfflineServiceError> {
        self.session
            .with_signing_key_checked(account, checked_deadline, operation)
            .map_err(OfflineServiceError::from)
    }

    /// Test-only compatibility helper using a live controller-minted deadline.
    #[cfg(test)]
    pub(crate) fn with_signing_key<R>(
        &self,
        account: ManagedAccount,
        operation: impl FnOnce(&RawPrivateKey) -> R,
    ) -> Result<R, OfflineServiceError> {
        crate::offline_controller::with_live_test_deadline(|checked_deadline| {
            self.with_signing_key_checked(account, checked_deadline, operation)
        })
    }

    fn lock_on_error<T>(
        &mut self,
        result: Result<T, OfflineServiceError>,
    ) -> Result<T, OfflineServiceError> {
        if result.is_err() {
            self.lock();
        }
        result
    }
}

fn passwords_match(first: &str, confirmation: &str) -> bool {
    if first.len() > MAX_PASSWORD_INPUT_BYTES || confirmation.len() > MAX_PASSWORD_INPUT_BYTES {
        return false;
    }
    let mut first_padded = Zeroizing::new([0_u8; MAX_PASSWORD_INPUT_BYTES]);
    let mut confirmation_padded = Zeroizing::new([0_u8; MAX_PASSWORD_INPUT_BYTES]);
    first_padded[..first.len()].copy_from_slice(first.as_bytes());
    confirmation_padded[..confirmation.len()].copy_from_slice(confirmation.as_bytes());
    let same_length = u64::try_from(first.len()).map_or(0_u8, |first_length| {
        u64::try_from(confirmation.len()).map_or(0_u8, |confirmation_length| {
            first_length.ct_eq(&confirmation_length).unwrap_u8()
        })
    });
    let same_bytes = first_padded
        .as_slice()
        .ct_eq(confirmation_padded.as_slice())
        .unwrap_u8();
    same_length & same_bytes == 1
}

fn random_frontend_binding() -> Result<Zeroizing<[u8; FRONTEND_BINDING_BYTES]>, OfflineServiceError>
{
    for _ in 0..FRONTEND_BINDING_ATTEMPTS {
        let mut binding = Zeroizing::new([0_u8; FRONTEND_BINDING_BYTES]);
        getrandom::fill(binding.as_mut())
            .map_err(|_| OfflineServiceError::Vault(VaultSessionError::CryptographicFailure))?;
        if binding.iter().any(|byte| *byte != 0) {
            return Ok(binding);
        }
    }
    Err(OfflineServiceError::Vault(
        VaultSessionError::CryptographicFailure,
    ))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::{Arc, Mutex};

    use secret_core::{AtomicVaultStorage, StorageError, VaultBlob};
    use zeroize::Zeroizing;

    use super::{
        FrontendFailure, NewPasswordInput, OfflineMnemonicSize, OfflineServiceError,
        OfflineWalletService, PasswordFrontend, RecoveryConfirmationFrontend,
        RecoveryConfirmationInput, RecoveryConfirmationPrompt, RecoveryMaterial, RecoveryPresenter,
        UnlockPasswordInput, sealed,
    };
    use crate::vault_session::{ManagedAccount, VaultSessionStatus};

    const CREATED_AT: u64 = 1_700_100_000;

    #[derive(Clone, Default)]
    struct SharedMemoryStorage {
        bytes: Arc<Mutex<Option<Vec<u8>>>>,
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
            Ok(())
        }
    }

    struct PasswordFake {
        new_password: Option<Result<NewPasswordInput, FrontendFailure>>,
        unlock_password: Option<Result<UnlockPasswordInput, FrontendFailure>>,
    }

    impl sealed::Sealed for PasswordFake {}

    impl PasswordFrontend for PasswordFake {
        fn acquire_new_password(&mut self) -> Result<NewPasswordInput, FrontendFailure> {
            self.new_password
                .take()
                .unwrap_or(Err(FrontendFailure::Failed))
        }

        fn acquire_unlock_password(&mut self) -> Result<UnlockPasswordInput, FrontendFailure> {
            self.unlock_password
                .take()
                .unwrap_or(Err(FrontendFailure::Failed))
        }
    }

    fn password_text() -> Zeroizing<String> {
        Zeroizing::new("test-only-offline-password".to_owned())
    }

    fn creating_passwords() -> PasswordFake {
        PasswordFake {
            new_password: Some(Ok(NewPasswordInput::new(password_text(), password_text()))),
            unlock_password: None,
        }
    }

    fn unlocking_passwords() -> PasswordFake {
        PasswordFake {
            new_password: None,
            unlock_password: Some(Ok(UnlockPasswordInput::new(password_text()))),
        }
    }

    #[derive(Default)]
    struct BackupCopy {
        phrase: Option<Zeroizing<String>>,
        first_address: Option<secret_core::EthereumAddress>,
    }

    struct CapturingPresenter {
        backup: Rc<RefCell<BackupCopy>>,
        failure: Option<FrontendFailure>,
    }

    impl sealed::Sealed for CapturingPresenter {}

    impl RecoveryPresenter for CapturingPresenter {
        fn present(&mut self, material: RecoveryMaterial<'_>) -> Result<(), FrontendFailure> {
            if let Some(failure) = self.failure {
                return Err(failure);
            }
            let mut backup = self.backup.borrow_mut();
            backup.phrase = Some(Zeroizing::new(material.phrase().to_owned()));
            backup.first_address = Some(material.first_address());
            Ok(())
        }
    }

    struct SolvingConfirmation {
        backup: Rc<RefCell<BackupCopy>>,
        failure: Option<FrontendFailure>,
    }

    impl sealed::Sealed for SolvingConfirmation {}

    impl RecoveryConfirmationFrontend for SolvingConfirmation {
        fn acquire_confirmation(
            &mut self,
            prompt: &RecoveryConfirmationPrompt<'_>,
        ) -> Result<RecoveryConfirmationInput, FrontendFailure> {
            if let Some(failure) = self.failure {
                return Err(failure);
            }
            solve_from_backup(&self.backup.borrow(), prompt)
        }
    }

    fn solve_from_backup(
        backup: &BackupCopy,
        prompt: &RecoveryConfirmationPrompt<'_>,
    ) -> Result<RecoveryConfirmationInput, FrontendFailure> {
        let phrase = backup.phrase.as_ref().ok_or(FrontendFailure::Failed)?;
        let first_address = backup.first_address.ok_or(FrontendFailure::Failed)?;
        let answers: Result<Vec<_>, _> = prompt
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
        Ok(prompt.bind(Zeroizing::new(answers?), first_address))
    }

    #[test]
    fn password_mismatch_never_creates_or_unlocks_a_vault() {
        let storage = SharedMemoryStorage::default();
        let mut service = OfflineWalletService::new(storage.clone());
        let mut passwords = PasswordFake {
            new_password: Some(Ok(NewPasswordInput::new(
                password_text(),
                Zeroizing::new("different-test-password".to_owned()),
            ))),
            unlock_password: None,
        };
        assert_eq!(
            service.create(OfflineMnemonicSize::TwelveWords, CREATED_AT, &mut passwords),
            Err(OfflineServiceError::PasswordMismatch)
        );
        assert_eq!(service.status(), VaultSessionStatus::Locked);
        assert_eq!(storage.load(), Err(StorageError::NotFound));
    }

    #[test]
    fn cancellation_and_timeout_lock_pending_decrypted_state()
    -> Result<(), Box<dyn std::error::Error>> {
        for failure in [FrontendFailure::Cancelled, FrontendFailure::TimedOut] {
            let storage = SharedMemoryStorage::default();
            let mut service = OfflineWalletService::new(storage);
            service.create(
                OfflineMnemonicSize::TwelveWords,
                CREATED_AT,
                &mut creating_passwords(),
            )?;
            let backup = Rc::new(RefCell::new(BackupCopy::default()));
            let mut presenter = CapturingPresenter {
                backup: Rc::clone(&backup),
                failure: None,
            };
            let mut confirmation = SolvingConfirmation {
                backup,
                failure: Some(failure),
            };
            assert_eq!(
                service.confirm_backup(&mut presenter, &mut confirmation),
                Err(OfflineServiceError::Frontend(failure))
            );
            assert_eq!(service.status(), VaultSessionStatus::Locked);
        }
        Ok(())
    }

    #[test]
    fn presenter_failure_locks_without_exposing_an_address()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut service = OfflineWalletService::new(SharedMemoryStorage::default());
        service.create(
            OfflineMnemonicSize::TwelveWords,
            CREATED_AT,
            &mut creating_passwords(),
        )?;
        let backup = Rc::new(RefCell::new(BackupCopy::default()));
        let mut presenter = CapturingPresenter {
            backup: Rc::clone(&backup),
            failure: Some(FrontendFailure::Failed),
        };
        let mut confirmation = SolvingConfirmation {
            backup,
            failure: None,
        };
        assert_eq!(
            service.confirm_backup(&mut presenter, &mut confirmation),
            Err(OfflineServiceError::Frontend(FrontendFailure::Failed))
        );
        assert_eq!(service.status(), VaultSessionStatus::Locked);
        assert!(service.address(ManagedAccount::Index0).is_err());
        Ok(())
    }

    struct StashingConfirmation {
        backup: Rc<RefCell<BackupCopy>>,
        stashed: Option<RecoveryConfirmationInput>,
    }

    impl sealed::Sealed for StashingConfirmation {}

    impl RecoveryConfirmationFrontend for StashingConfirmation {
        fn acquire_confirmation(
            &mut self,
            prompt: &RecoveryConfirmationPrompt<'_>,
        ) -> Result<RecoveryConfirmationInput, FrontendFailure> {
            if let Some(stale) = self.stashed.take() {
                return Ok(stale);
            }
            self.stashed = Some(solve_from_backup(&self.backup.borrow(), prompt)?);
            Err(FrontendFailure::Cancelled)
        }
    }

    #[test]
    fn stale_confirmation_object_is_rejected_after_reopen() -> Result<(), Box<dyn std::error::Error>>
    {
        let storage = SharedMemoryStorage::default();
        let mut service = OfflineWalletService::new(storage);
        service.create(
            OfflineMnemonicSize::TwelveWords,
            CREATED_AT,
            &mut creating_passwords(),
        )?;
        let backup = Rc::new(RefCell::new(BackupCopy::default()));
        let mut presenter = CapturingPresenter {
            backup: Rc::clone(&backup),
            failure: None,
        };
        let mut confirmation = StashingConfirmation {
            backup,
            stashed: None,
        };
        assert_eq!(
            service.confirm_backup(&mut presenter, &mut confirmation),
            Err(OfflineServiceError::Frontend(FrontendFailure::Cancelled))
        );
        assert_eq!(service.status(), VaultSessionStatus::Locked);

        service.unlock(&mut unlocking_passwords())?;
        assert_eq!(service.status(), VaultSessionStatus::BackupPending);
        assert_eq!(
            service.confirm_backup(&mut presenter, &mut confirmation),
            Err(OfflineServiceError::StaleConfirmation)
        );
        assert_eq!(service.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn confirmed_twenty_four_word_vault_unlocks_after_restart()
    -> Result<(), Box<dyn std::error::Error>> {
        let storage = SharedMemoryStorage::default();
        let mut service = OfflineWalletService::new(storage.clone());
        service.create(
            OfflineMnemonicSize::TwentyFourWords,
            CREATED_AT,
            &mut creating_passwords(),
        )?;
        assert_eq!(service.status(), VaultSessionStatus::BackupPending);
        assert!(service.address(ManagedAccount::Index0).is_err());
        let signing_called = std::cell::Cell::new(false);
        assert!(
            service
                .with_signing_key(ManagedAccount::Index0, |_| signing_called.set(true))
                .is_err()
        );
        assert!(!signing_called.get());

        let backup = Rc::new(RefCell::new(BackupCopy::default()));
        let mut presenter = CapturingPresenter {
            backup: Rc::clone(&backup),
            failure: None,
        };
        let mut confirmation = SolvingConfirmation {
            backup,
            failure: None,
        };
        service.confirm_backup(&mut presenter, &mut confirmation)?;
        assert_eq!(service.status(), VaultSessionStatus::Unlocked);
        let address = service.address(ManagedAccount::Index0)?;
        let derived = service.with_signing_key(
            ManagedAccount::Index0,
            secret_core::RawPrivateKey::ethereum_address,
        )??;
        assert_eq!(address, derived);

        service.lock();
        drop(service);
        let mut restarted = OfflineWalletService::new(storage);
        restarted.unlock(&mut unlocking_passwords())?;
        let _ = restarted.address(ManagedAccount::Index1)?;
        assert_eq!(restarted.status(), VaultSessionStatus::Unlocked);
        assert_eq!(restarted.address(ManagedAccount::Index0)?, address);
        Ok(())
    }

    #[test]
    fn secret_bearing_debug_is_fixed_and_redacted() {
        let password = NewPasswordInput::new(password_text(), password_text());
        assert_eq!(format!("{password:?}"), "NewPasswordInput([REDACTED])");
        let service = OfflineWalletService::new(SharedMemoryStorage::default());
        assert_eq!(
            format!("{service:?}"),
            "OfflineWalletService { session: \"[REDACTED]\", status: Locked }"
        );
        let _storage = service.into_storage();
    }
}
