//! Offline vault creation, recovery confirmation, and in-memory lock lifecycle.
//!
//! The session owns all decrypted material. Callers can observe only a coarse
//! state until backup confirmation has been durably committed. The production
//! storage implementation remains responsible for rollback protection and the
//! full [`AtomicVaultStorage`] durability contract.

// Recovery entry points stay crate-private until the internal Key Agent
// service binds them to the authenticated secret helper. The production
// library therefore has no caller yet; tests exercise the complete boundary.
#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use secret_core::{
    AccountIndex, AtomicVaultStorage, BackupState, Bip39Record, DerivedAccount,
    DerivedAccountRecord, EthereumAddress, MnemonicWordCount, RawPrivateKey, SecretError,
    SecretRecord, SessionPassphrase, StorageError, VaultBlob, VaultHeader, VaultPassword,
    VaultPayload,
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::offline_controller::{CheckedOfflineDeadline, DeadlineRecheckError};

const MANAGED_ACCOUNT_COUNT: usize = 2;
const RECOVERY_CHALLENGE_WORDS: usize = 4;

/// Coarse, non-secret vault lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VaultSessionStatus {
    /// No decrypted vault material is resident.
    Locked,
    /// A vault is open, but its recovery backup has not been confirmed.
    BackupPending,
    /// Backup confirmation was durably committed and signing is eligible.
    Unlocked,
}

/// The two accounts created for a new mnemonic source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ManagedAccount {
    /// Requested derivation index zero.
    Index0,
    /// Requested derivation index one.
    Index1,
}

impl ManagedAccount {
    const fn offset(self) -> usize {
        match self {
            Self::Index0 => 0,
            Self::Index1 => 1,
        }
    }
}

/// Stable, path-free failures for the vault lifecycle.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum VaultSessionError {
    /// The requested transition is not valid in the current state.
    #[error("vault session state does not permit this operation")]
    InvalidState,
    /// The encrypted vault could not be authenticated or validated.
    #[error("vault could not be opened")]
    OpenFailed,
    /// Secret generation, derivation, or sealing failed.
    #[error("vault cryptographic operation failed")]
    CryptographicFailure,
    /// Durable storage failed or rejected the expected generation.
    #[error("durable vault storage failed")]
    Storage(#[from] StorageError),
    /// A recovery display capability was already consumed in this session.
    #[error("recovery display capability was already consumed")]
    RecoveryDisplayConsumed,
    /// Recovery words or the first address did not match exactly.
    #[error("recovery confirmation failed")]
    RecoveryConfirmationFailed,
    /// The controller-pinned monotonic deadline elapsed before mutation.
    #[error("vault transition deadline elapsed")]
    DeadlineExpired,
    /// The controller-owned trusted monotonic clock could not be sampled.
    #[error("trusted vault transition clock failed")]
    TrustedClockFailure,
}

/// One-based BIP-39 word position requested during recovery confirmation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) struct RecoveryWordPosition(u8);

impl RecoveryWordPosition {
    /// Returns the one-based word position shown to the user.
    #[must_use]
    pub(crate) const fn get(self) -> u8 {
        self.0
    }
}

/// User-entered recovery confirmation, owned and zeroized on drop.
///
/// The expected address is deliberately never exposed by
/// [`RecoveryChallenge`]. It must come from the user's independently retained
/// backup copy.
pub(crate) struct RecoveryConfirmation {
    words: Zeroizing<Vec<String>>,
    first_address: EthereumAddress,
}

impl fmt::Debug for RecoveryConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryConfirmation([REDACTED])")
    }
}

impl RecoveryConfirmation {
    /// Takes ownership of words and the first address entered by the trusted
    /// confirmation UI.
    #[must_use]
    pub(crate) fn new(words: Vec<String>, first_address: EthereumAddress) -> Self {
        Self {
            words: Zeroizing::new(words),
            first_address,
        }
    }
}

/// Borrowed data available only while a one-shot recovery display is consumed.
pub(crate) struct RecoveryDisplayView<'a> {
    phrase: &'a str,
    first_address: EthereumAddress,
}

impl fmt::Debug for RecoveryDisplayView<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryDisplayView([REDACTED PHRASE])")
    }
}

impl<'a> RecoveryDisplayView<'a> {
    /// Exposes the mnemonic only inside the consuming display callback.
    #[must_use]
    pub(crate) const fn phrase(&self) -> &'a str {
        self.phrase
    }

    /// First derived address to include in the independent backup copy.
    ///
    /// This address is available only while recovery material is presented. It
    /// is not echoed by the later challenge.
    #[must_use]
    pub(crate) const fn first_address(&self) -> EthereumAddress {
        self.first_address
    }
}

/// Secret-free one-shot challenge bound to one live pending session.
pub(crate) struct RecoveryChallenge {
    positions: [RecoveryWordPosition; RECOVERY_CHALLENGE_WORDS],
    binding: RecoveryBinding,
}

/// Secret-free proof that one recovery display callback returned.
///
/// This capability is deliberately non-`Clone`. Merely displaying recovery
/// material does not mutate the session; the controller must first recheck its
/// trusted monotonic deadline and then consume this value to commit the
/// one-shot confirmation challenge.
pub(crate) struct DisplayedRecovery {
    positions: [RecoveryWordPosition; RECOVERY_CHALLENGE_WORDS],
    binding: RecoveryBinding,
}

impl fmt::Debug for DisplayedRecovery {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DisplayedRecovery([REDACTED])")
    }
}

impl fmt::Debug for RecoveryChallenge {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecoveryChallenge([REDACTED])")
    }
}

impl RecoveryChallenge {
    /// Returns the positions requested by this challenge.
    #[must_use]
    pub(crate) const fn positions(&self) -> &[RecoveryWordPosition; RECOVERY_CHALLENGE_WORDS] {
        &self.positions
    }
}

struct RecoveryBinding {
    vault_id: [u8; 16],
    generation: u64,
    record_id: [u8; 16],
    session_nonce: Zeroizing<[u8; 32]>,
    challenge_nonce: Zeroizing<[u8; 32]>,
}

impl RecoveryBinding {
    fn matches_pending(&self, pending: &PendingState) -> bool {
        let Some(expected_nonce) = pending.challenge_nonce.as_ref() else {
            return false;
        };
        pending.display_consumed
            && self.vault_id == *pending.header.vault_id()
            && self.generation == pending.header.generation()
            && self.record_id == pending.record_id
            && bool::from(
                self.session_nonce
                    .as_ref()
                    .ct_eq(pending.session_nonce.as_ref()),
            )
            && bool::from(self.challenge_nonce.as_ref().ct_eq(expected_nonce.as_ref()))
    }

    fn matches_uncommitted_display(&self, pending: &PendingState) -> bool {
        !pending.display_consumed
            && pending.challenge_nonce.is_none()
            && self.vault_id == *pending.header.vault_id()
            && self.generation == pending.header.generation()
            && self.record_id == pending.record_id
            && bool::from(
                self.session_nonce
                    .as_ref()
                    .ct_eq(pending.session_nonce.as_ref()),
            )
    }
}

struct PendingState {
    password: VaultPassword,
    payload: VaultPayload,
    header: VaultHeader,
    record_id: [u8; 16],
    accounts: [DerivedAccount; MANAGED_ACCOUNT_COUNT],
    session_nonce: Zeroizing<[u8; 32]>,
    display_consumed: bool,
    challenge_nonce: Option<Zeroizing<[u8; 32]>>,
}

struct UnlockedState {
    accounts: [DerivedAccount; MANAGED_ACCOUNT_COUNT],
}

// Keep secret-bearing states inline so their existing zeroizing drops do not
// depend on an additional allocation/indirection boundary.
#[allow(clippy::large_enum_variant)]
enum SessionState {
    Locked,
    BackupPending(PendingState),
    Unlocked(UnlockedState),
}

/// Generic vault lifecycle over a release-critical atomic storage boundary.
///
/// Recovery presentation and confirmation are deliberately not public crate
/// APIs. They remain inside the Key Agent's Secret TCB until an internal
/// service connects them exclusively to the authenticated secret helper.
///
pub struct VaultSession<S> {
    storage: S,
    state: SessionState,
}

impl<S> fmt::Debug for VaultSession<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultSession")
            .field("storage", &"[REDACTED]")
            .field("status", &self.status())
            .finish()
    }
}

impl<S> VaultSession<S> {
    /// Constructs a locked session around a storage implementation.
    #[must_use]
    pub const fn new(storage: S) -> Self {
        Self {
            storage,
            state: SessionState::Locked,
        }
    }

    /// Returns the current non-secret lifecycle status.
    #[must_use]
    pub const fn status(&self) -> VaultSessionStatus {
        match self.state {
            SessionState::Locked => VaultSessionStatus::Locked,
            SessionState::BackupPending(_) => VaultSessionStatus::BackupPending,
            SessionState::Unlocked(_) => VaultSessionStatus::Unlocked,
        }
    }

    /// Drops all decrypted material and returns to the locked state.
    pub fn lock(&mut self) {
        self.state = SessionState::Locked;
    }

    /// Consumes the session and returns its storage after dropping secrets.
    #[must_use]
    pub fn into_storage(mut self) -> S {
        self.lock();
        self.storage
    }
}

impl<S: AtomicVaultStorage> VaultSession<S> {
    /// Creates and durably stores an unconfirmed 12- or 24-word BIP-39 vault.
    ///
    /// Accounts at requested indices zero and one are derived and authenticated
    /// into generation one. Signing remains unavailable until confirmation.
    pub(crate) fn create_checked(
        &mut self,
        password: VaultPassword,
        word_count: MnemonicWordCount,
        created_at_unix: u64,
        mut checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<(), VaultSessionError> {
        if self.status() != VaultSessionStatus::Locked {
            return Err(VaultSessionError::InvalidState);
        }
        let session_nonce = random_challenge_nonce()?;

        let entropy =
            secret_core::MnemonicEntropy::generate(word_count).map_err(map_secret_failure)?;
        let passphrase = SessionPassphrase::empty();
        let index_zero = AccountIndex::new(0).map_err(map_secret_failure)?;
        let index_one = AccountIndex::new(1).map_err(map_secret_failure)?;
        let account_zero = entropy
            .derive_ethereum_account(&passphrase, index_zero)
            .map_err(map_secret_failure)?;
        let account_one = entropy
            .derive_ethereum_account(&passphrase, index_one)
            .map_err(map_secret_failure)?;
        let accounts = [account_zero, account_one];

        let record_id = random_nonzero_id()?;
        let mut record = Bip39Record::new_unconfirmed(record_id, created_at_unix, false, entropy);
        record
            .add_account(DerivedAccountRecord::from_derived(index_zero, &accounts[0]))
            .map_err(map_secret_failure)?;
        record
            .add_account(DerivedAccountRecord::from_derived(index_one, &accounts[1]))
            .map_err(map_secret_failure)?;
        let mut payload = VaultPayload::new();
        payload
            .push(SecretRecord::Bip39(record))
            .map_err(map_secret_failure)?;
        let blob = VaultBlob::seal_new(&payload, &password).map_err(map_secret_failure)?;
        recheck_deadline(&mut checked_deadline)?;
        self.storage.commit(None, &blob)?;
        let header = *blob.header();
        self.state = SessionState::BackupPending(PendingState {
            password,
            payload,
            header,
            record_id,
            accounts,
            session_nonce,
            display_consumed: false,
            challenge_nonce: None,
        });
        Ok(())
    }

    /// Test-only compatibility helper using a live controller-minted deadline.
    #[cfg(test)]
    pub(crate) fn create(
        &mut self,
        password: VaultPassword,
        word_count: MnemonicWordCount,
        created_at_unix: u64,
    ) -> Result<(), VaultSessionError> {
        crate::offline_controller::with_live_test_deadline(|checked_deadline| {
            self.create_checked(password, word_count, created_at_unix, checked_deadline)
        })
    }

    /// Opens the latest committed generation and validates its exact source and
    /// derivation metadata before retaining any unlocked keys.
    pub(crate) fn open_checked(
        &mut self,
        password: VaultPassword,
        mut checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<(), VaultSessionError> {
        self.lock();
        let bytes = self.storage.load()?;
        let blob = VaultBlob::parse(&bytes).map_err(|_| VaultSessionError::OpenFailed)?;
        let header = *blob.header();
        let payload = blob
            .open(&password)
            .map_err(|_| VaultSessionError::OpenFailed)?;
        let inspected = inspect_payload(&payload).map_err(|_| VaultSessionError::OpenFailed)?;
        let session_nonce = random_challenge_nonce()?;
        let next_state = match inspected.backup_state {
            BackupState::Unconfirmed => SessionState::BackupPending(PendingState {
                password,
                payload,
                header,
                record_id: inspected.record_id,
                accounts: inspected.accounts,
                session_nonce,
                display_consumed: false,
                challenge_nonce: None,
            }),
            BackupState::Confirmed => SessionState::Unlocked(UnlockedState {
                accounts: inspected.accounts,
            }),
        };
        recheck_deadline(&mut checked_deadline)?;
        self.state = next_state;
        Ok(())
    }

    /// Test-only compatibility helper using a live controller-minted deadline.
    #[cfg(test)]
    pub(crate) fn open(&mut self, password: VaultPassword) -> Result<(), VaultSessionError> {
        crate::offline_controller::with_live_test_deadline(|checked_deadline| {
            self.open_checked(password, checked_deadline)
        })
    }

    /// Presents recovery material read-only and returns a secret-free,
    /// non-clone display capability only after the callback has ended.
    ///
    /// Locking and reopening invalidates the returned challenge. Challenge
    /// positions are unavailable inside the callback. The callback itself is
    /// trusted Secret TCB code and must pass the borrow only to the one-shot
    /// authenticated secret helper; safe Rust cannot prevent trusted callback
    /// code from deliberately making a copy.
    pub(crate) fn display_recovery(
        &self,
        presenter: impl FnOnce(RecoveryDisplayView<'_>),
    ) -> Result<DisplayedRecovery, VaultSessionError> {
        let SessionState::BackupPending(pending) = &self.state else {
            return Err(VaultSessionError::InvalidState);
        };
        if pending.display_consumed {
            return Err(VaultSessionError::RecoveryDisplayConsumed);
        }
        let phrase = pending_phrase(&pending.payload)?;
        let word_count = phrase.expose_secret().split(' ').count();
        let first_address = pending.accounts[0].address();
        presenter(RecoveryDisplayView {
            phrase: phrase.expose_secret(),
            first_address,
        });
        let positions = random_challenge_positions(word_count)?;
        let challenge_nonce = random_challenge_nonce()?;
        Ok(DisplayedRecovery {
            positions,
            binding: RecoveryBinding {
                vault_id: *pending.header.vault_id(),
                generation: pending.header.generation(),
                record_id: pending.record_id,
                session_nonce: Zeroizing::new(*pending.session_nonce),
                challenge_nonce,
            },
        })
    }

    /// Commits one displayed capability into the live in-memory confirmation
    /// state. No durable vault transition occurs here.
    #[allow(clippy::needless_pass_by_value)] // Intentionally consumes a one-shot value.
    pub(crate) fn commit_displayed_recovery_checked(
        &mut self,
        displayed: DisplayedRecovery,
        mut checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<RecoveryChallenge, VaultSessionError> {
        let SessionState::BackupPending(pending) = &mut self.state else {
            return Err(VaultSessionError::InvalidState);
        };
        if !displayed.binding.matches_uncommitted_display(pending) {
            return Err(VaultSessionError::RecoveryConfirmationFailed);
        }
        recheck_deadline(&mut checked_deadline)?;
        pending.display_consumed = true;
        pending.challenge_nonce = Some(Zeroizing::new(*displayed.binding.challenge_nonce));
        Ok(RecoveryChallenge {
            positions: displayed.positions,
            binding: displayed.binding,
        })
    }

    /// Test-only compatibility helper using a live controller-minted deadline.
    #[cfg(test)]
    pub(crate) fn commit_displayed_recovery(
        &mut self,
        displayed: DisplayedRecovery,
    ) -> Result<RecoveryChallenge, VaultSessionError> {
        crate::offline_controller::with_live_test_deadline(|checked_deadline| {
            self.commit_displayed_recovery_checked(displayed, checked_deadline)
        })
    }

    /// Test-only compatibility helper for the former combined display commit.
    #[cfg(test)]
    pub(crate) fn present_recovery(
        &mut self,
        presenter: impl FnOnce(RecoveryDisplayView<'_>),
    ) -> Result<RecoveryChallenge, VaultSessionError> {
        let displayed = self.display_recovery(presenter)?;
        self.commit_displayed_recovery(displayed)
    }

    /// Durably commits the one-way `Unconfirmed -> Confirmed` transition.
    ///
    /// Any mismatch or storage ambiguity locks the in-memory session. The
    /// caller must reopen the latest durable generation before trying again.
    #[allow(clippy::needless_pass_by_value)] // Intentionally consumes one-shot values.
    pub(crate) fn confirm_backup_checked(
        &mut self,
        challenge: RecoveryChallenge,
        confirmation: RecoveryConfirmation,
        mut checked_deadline: CheckedOfflineDeadline<'_>,
    ) -> Result<(), VaultSessionError> {
        let RecoveryChallenge { positions, binding } = challenge;
        let state = core::mem::replace(&mut self.state, SessionState::Locked);
        let SessionState::BackupPending(mut pending) = state else {
            return Err(VaultSessionError::InvalidState);
        };
        if !binding.matches_pending(&pending) {
            return Err(VaultSessionError::RecoveryConfirmationFailed);
        }
        let RecoveryConfirmation {
            words,
            first_address,
        } = confirmation;
        pending
            .payload
            .verify_and_confirm_bip39_backup(
                pending.record_id,
                positions.map(RecoveryWordPosition::get),
                words.as_slice(),
                first_address,
            )
            .map_err(|_| VaultSessionError::RecoveryConfirmationFailed)?;
        let blob = VaultBlob::reseal(&pending.payload, &pending.password, &pending.header)
            .map_err(map_secret_failure)?;
        recheck_deadline(&mut checked_deadline)?;
        self.storage
            .commit(Some(pending.header.generation()), &blob)?;
        self.state = SessionState::Unlocked(UnlockedState {
            accounts: pending.accounts,
        });
        Ok(())
    }

    /// Test-only compatibility helper using a live controller-minted deadline.
    #[cfg(test)]
    pub(crate) fn confirm_backup(
        &mut self,
        challenge: RecoveryChallenge,
        confirmation: RecoveryConfirmation,
    ) -> Result<(), VaultSessionError> {
        crate::offline_controller::with_live_test_deadline(|checked_deadline| {
            self.confirm_backup_checked(challenge, confirmation, checked_deadline)
        })
    }

    /// Returns an address only after backup confirmation was durably committed.
    pub fn copyable_address(
        &self,
        account: ManagedAccount,
    ) -> Result<EthereumAddress, VaultSessionError> {
        let SessionState::Unlocked(unlocked) = &self.state else {
            return Err(VaultSessionError::InvalidState);
        };
        Ok(unlocked.accounts[account.offset()].address())
    }

    /// Borrows a signing key only for the duration of an operation after backup
    /// confirmation. No raw key getter is exposed by this session.
    pub(crate) fn with_signing_key_checked<R>(
        &self,
        account: ManagedAccount,
        mut checked_deadline: CheckedOfflineDeadline<'_>,
        operation: impl FnOnce(&RawPrivateKey) -> R,
    ) -> Result<R, VaultSessionError> {
        let SessionState::Unlocked(unlocked) = &self.state else {
            return Err(VaultSessionError::InvalidState);
        };
        recheck_deadline(&mut checked_deadline)?;
        Ok(operation(unlocked.accounts[account.offset()].private_key()))
    }

    /// Test-only compatibility helper using a live controller-minted deadline.
    #[cfg(test)]
    pub(crate) fn with_signing_key<R>(
        &self,
        account: ManagedAccount,
        operation: impl FnOnce(&RawPrivateKey) -> R,
    ) -> Result<R, VaultSessionError> {
        crate::offline_controller::with_live_test_deadline(|checked_deadline| {
            self.with_signing_key_checked(account, checked_deadline, operation)
        })
    }
}

fn recheck_deadline(
    checked_deadline: &mut CheckedOfflineDeadline<'_>,
) -> Result<(), VaultSessionError> {
    checked_deadline.recheck().map_err(|error| match error {
        DeadlineRecheckError::Expired => VaultSessionError::DeadlineExpired,
        DeadlineRecheckError::Clock => VaultSessionError::TrustedClockFailure,
    })
}

struct InspectedPayload {
    backup_state: BackupState,
    record_id: [u8; 16],
    accounts: [DerivedAccount; MANAGED_ACCOUNT_COUNT],
}

fn inspect_payload(payload: &VaultPayload) -> Result<InspectedPayload, SecretError> {
    let [SecretRecord::Bip39(record)] = payload.records() else {
        return Err(SecretError::InvalidPayload);
    };
    let phrase = record.entropy().reveal_phrase()?;
    let word_count = phrase.expose_secret().split(' ').count();
    if record.passphrase_required() || !matches!(word_count, 12 | 24) {
        return Err(SecretError::InvalidPayload);
    }
    let [persisted_zero, persisted_one] = record.accounts() else {
        return Err(SecretError::InvalidPayload);
    };
    let passphrase = SessionPassphrase::empty();
    let account_zero = derive_and_validate_account(record, &passphrase, 0, persisted_zero)?;
    let account_one = derive_and_validate_account(record, &passphrase, 1, persisted_one)?;
    Ok(InspectedPayload {
        backup_state: record.backup_state(),
        record_id: *record.record_id(),
        accounts: [account_zero, account_one],
    })
}

fn derive_and_validate_account(
    record: &Bip39Record,
    passphrase: &SessionPassphrase,
    expected_index: u32,
    persisted: &DerivedAccountRecord,
) -> Result<DerivedAccount, SecretError> {
    let requested = AccountIndex::new(expected_index)?;
    if persisted.requested_index() != requested {
        return Err(SecretError::InvalidPayload);
    }
    let account = record
        .entropy()
        .derive_ethereum_account(passphrase, requested)?;
    if account.path() != persisted.actual_path() || account.address() != persisted.address() {
        return Err(SecretError::InvalidPayload);
    }
    Ok(account)
}

fn pending_phrase(payload: &VaultPayload) -> Result<secret_core::SecretPhrase, VaultSessionError> {
    let [SecretRecord::Bip39(record)] = payload.records() else {
        return Err(VaultSessionError::OpenFailed);
    };
    if record.backup_state() != BackupState::Unconfirmed {
        return Err(VaultSessionError::OpenFailed);
    }
    record.entropy().reveal_phrase().map_err(map_secret_failure)
}

fn random_nonzero_id() -> Result<[u8; 16], VaultSessionError> {
    for _ in 0..4 {
        let mut id = [0_u8; 16];
        getrandom::fill(&mut id).map_err(|_| VaultSessionError::CryptographicFailure)?;
        if id != [0_u8; 16] {
            return Ok(id);
        }
    }
    Err(VaultSessionError::CryptographicFailure)
}

fn random_challenge_positions(
    word_count: usize,
) -> Result<[RecoveryWordPosition; RECOVERY_CHALLENGE_WORDS], VaultSessionError> {
    choose_challenge_positions(word_count, random_below)
}

fn choose_challenge_positions(
    word_count: usize,
    mut choose: impl FnMut(usize) -> Result<usize, VaultSessionError>,
) -> Result<[RecoveryWordPosition; RECOVERY_CHALLENGE_WORDS], VaultSessionError> {
    if !matches!(word_count, 12 | 24) {
        return Err(VaultSessionError::CryptographicFailure);
    }
    let mut candidates = [0_usize; 24];
    for (index, candidate) in candidates[..word_count].iter_mut().enumerate() {
        *candidate = index;
    }
    for offset in 0..RECOVERY_CHALLENGE_WORDS {
        let remaining = word_count.saturating_sub(offset);
        let selected = offset
            .checked_add(choose(remaining)?)
            .ok_or(VaultSessionError::CryptographicFailure)?;
        candidates.swap(offset, selected);
    }
    let mut selected = [RecoveryWordPosition(0); RECOVERY_CHALLENGE_WORDS];
    for (output, index) in selected
        .iter_mut()
        .zip(candidates[..RECOVERY_CHALLENGE_WORDS].iter().copied())
    {
        let one_based = index
            .checked_add(1)
            .and_then(|value| u8::try_from(value).ok())
            .ok_or(VaultSessionError::CryptographicFailure)?;
        *output = RecoveryWordPosition(one_based);
    }
    selected.sort_unstable();
    Ok(selected)
}

fn random_challenge_nonce() -> Result<Zeroizing<[u8; 32]>, VaultSessionError> {
    for _ in 0..4 {
        let mut nonce = Zeroizing::new([0_u8; 32]);
        getrandom::fill(nonce.as_mut()).map_err(|_| VaultSessionError::CryptographicFailure)?;
        if nonce.as_ref() != [0_u8; 32] {
            return Ok(nonce);
        }
    }
    Err(VaultSessionError::CryptographicFailure)
}

fn random_below(upper: usize) -> Result<usize, VaultSessionError> {
    let upper = u32::try_from(upper).map_err(|_| VaultSessionError::CryptographicFailure)?;
    if upper == 0 {
        return Err(VaultSessionError::CryptographicFailure);
    }
    let acceptance = u32::MAX - (u32::MAX % upper);
    loop {
        let mut bytes = [0_u8; 4];
        getrandom::fill(&mut bytes).map_err(|_| VaultSessionError::CryptographicFailure)?;
        let candidate = u32::from_le_bytes(bytes);
        if candidate < acceptance {
            let reduced = candidate % upper;
            return usize::try_from(reduced).map_err(|_| VaultSessionError::CryptographicFailure);
        }
    }
}

const fn map_secret_failure(_: SecretError) -> VaultSessionError {
    VaultSessionError::CryptographicFailure
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::{
        ManagedAccount, RecoveryConfirmation, VaultSession, VaultSessionError, VaultSessionStatus,
        choose_challenge_positions,
    };
    use secret_core::{AtomicVaultStorage, StorageError, VaultBlob, VaultPassword};
    use zeroize::Zeroizing;

    #[derive(Clone, Default)]
    struct SharedMemoryStorage {
        bytes: Arc<Mutex<Option<Vec<u8>>>>,
        next_commit: Arc<Mutex<CommitMode>>,
    }

    #[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
    enum CommitMode {
        #[default]
        Success,
        FailBeforeWrite,
        FailAfterWrite,
    }

    impl SharedMemoryStorage {
        fn fail_next_commit(&self, mode: CommitMode) -> Result<(), StorageError> {
            *self
                .next_commit
                .lock()
                .map_err(|_| StorageError::DurabilityFailure)? = mode;
            Ok(())
        }

        fn corrupt_last_byte(&self) -> Result<(), StorageError> {
            let mut bytes = self
                .bytes
                .lock()
                .map_err(|_| StorageError::DurabilityFailure)?;
            let Some(bytes) = bytes.as_mut() else {
                return Err(StorageError::NotFound);
            };
            let Some(last) = bytes.last_mut() else {
                return Err(StorageError::DurabilityFailure);
            };
            *last ^= 1;
            Ok(())
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
            let mode = core::mem::take(
                &mut *self
                    .next_commit
                    .lock()
                    .map_err(|_| StorageError::DurabilityFailure)?,
            );
            if mode == CommitMode::FailBeforeWrite {
                return Err(StorageError::DurabilityFailure);
            }
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
            if mode == CommitMode::FailAfterWrite {
                Err(StorageError::DurabilityFailure)
            } else {
                Ok(())
            }
        }
    }

    fn password() -> Result<VaultPassword, secret_core::SecretError> {
        VaultPassword::new("test-only-vault-password")
    }

    fn solve_pending_recovery(
        session: &mut VaultSession<SharedMemoryStorage>,
    ) -> Result<(super::RecoveryChallenge, RecoveryConfirmation), VaultSessionError> {
        let mut backup_phrase = None;
        let mut backup_address = None;
        let challenge = session.present_recovery(|view| {
            backup_phrase = Some(Zeroizing::new(view.phrase().to_owned()));
            backup_address = Some(view.first_address());
        })?;
        let phrase = backup_phrase.ok_or(VaultSessionError::RecoveryConfirmationFailed)?;
        let address = backup_address.ok_or(VaultSessionError::RecoveryConfirmationFailed)?;
        let answers: Result<Vec<_>, _> = challenge
            .positions()
            .iter()
            .map(|position| {
                phrase
                    .split(' ')
                    .nth(usize::from(position.get()).saturating_sub(1))
                    .map(str::to_owned)
                    .ok_or(VaultSessionError::RecoveryConfirmationFailed)
            })
            .collect();
        Ok((challenge, RecoveryConfirmation::new(answers?, address)))
    }

    #[test]
    fn deterministic_challenge_selection_is_distinct_sorted_and_bounded()
    -> Result<(), VaultSessionError> {
        let choices = [11_usize, 0, 5, 2];
        let mut next = 0_usize;
        let selected = choose_challenge_positions(12, |upper| {
            let value = choices
                .get(next)
                .copied()
                .ok_or(VaultSessionError::CryptographicFailure)?;
            next = next.saturating_add(1);
            Ok(value % upper)
        })?;
        assert_eq!(
            selected.map(super::RecoveryWordPosition::get),
            [2, 6, 8, 12]
        );
        Ok(())
    }

    #[test]
    fn create_confirm_lock_and_restart_preserve_the_gate() -> Result<(), Box<dyn std::error::Error>>
    {
        let storage = SharedMemoryStorage::default();
        let mut session = VaultSession::new(storage.clone());
        session.create(
            password()?,
            secret_core::MnemonicWordCount::Twelve,
            1_700_000_000,
        )?;
        assert_eq!(session.status(), VaultSessionStatus::BackupPending);
        assert_eq!(
            session.copyable_address(ManagedAccount::Index0),
            Err(VaultSessionError::InvalidState)
        );
        assert_eq!(
            session.with_signing_key(ManagedAccount::Index0, |_| ()),
            Err(VaultSessionError::InvalidState)
        );

        let (challenge, confirmation) = solve_pending_recovery(&mut session)?;
        session.confirm_backup(challenge, confirmation)?;
        assert_eq!(session.status(), VaultSessionStatus::Unlocked);
        let primary = session.copyable_address(ManagedAccount::Index0)?;
        let derived = session.with_signing_key(
            ManagedAccount::Index0,
            secret_core::RawPrivateKey::ethereum_address,
        )??;
        assert_eq!(primary, derived);

        session.lock();
        assert_eq!(session.status(), VaultSessionStatus::Locked);
        drop(session);
        let mut restarted = VaultSession::new(storage);
        restarted.open(password()?)?;
        assert_eq!(restarted.status(), VaultSessionStatus::Unlocked);
        assert_eq!(restarted.copyable_address(ManagedAccount::Index0)?, primary);
        Ok(())
    }

    #[test]
    fn create_commit_failures_leave_the_session_locked() -> Result<(), Box<dyn std::error::Error>> {
        for mode in [CommitMode::FailBeforeWrite, CommitMode::FailAfterWrite] {
            let storage = SharedMemoryStorage::default();
            storage.fail_next_commit(mode)?;
            let mut session = VaultSession::new(storage);
            assert_eq!(
                session.create(
                    password()?,
                    secret_core::MnemonicWordCount::Twelve,
                    1_700_000_002,
                ),
                Err(VaultSessionError::Storage(StorageError::DurabilityFailure))
            );
            assert_eq!(session.status(), VaultSessionStatus::Locked);
            assert_eq!(
                session.with_signing_key(ManagedAccount::Index0, |_| ()),
                Err(VaultSessionError::InvalidState)
            );
        }
        Ok(())
    }

    #[test]
    fn ambiguous_confirmation_commit_locks_until_reopen() -> Result<(), Box<dyn std::error::Error>>
    {
        let storage = SharedMemoryStorage::default();
        let mut session = VaultSession::new(storage.clone());
        session.create(
            password()?,
            secret_core::MnemonicWordCount::Twelve,
            1_700_000_003,
        )?;
        let (challenge, confirmation) = solve_pending_recovery(&mut session)?;
        storage.fail_next_commit(CommitMode::FailAfterWrite)?;
        assert_eq!(
            session.confirm_backup(challenge, confirmation),
            Err(VaultSessionError::Storage(StorageError::DurabilityFailure))
        );
        assert_eq!(session.status(), VaultSessionStatus::Locked);
        assert_eq!(
            session.copyable_address(ManagedAccount::Index0),
            Err(VaultSessionError::InvalidState)
        );

        let mut restarted = VaultSession::new(storage);
        restarted.open(password()?)?;
        assert_eq!(restarted.status(), VaultSessionStatus::Unlocked);
        Ok(())
    }

    #[test]
    fn stale_verified_recovery_cannot_cross_a_confirmed_generation()
    -> Result<(), Box<dyn std::error::Error>> {
        let storage = SharedMemoryStorage::default();
        let mut stale_session = VaultSession::new(storage.clone());
        stale_session.create(
            password()?,
            secret_core::MnemonicWordCount::Twelve,
            1_700_000_004,
        )?;
        let (stale_challenge, stale_confirmation) = solve_pending_recovery(&mut stale_session)?;

        let mut winning_session = VaultSession::new(storage);
        winning_session.open(password()?)?;
        let (winning_challenge, winning_confirmation) =
            solve_pending_recovery(&mut winning_session)?;
        winning_session.confirm_backup(winning_challenge, winning_confirmation)?;
        assert_eq!(winning_session.status(), VaultSessionStatus::Unlocked);

        assert_eq!(
            stale_session.confirm_backup(stale_challenge, stale_confirmation),
            Err(VaultSessionError::Storage(StorageError::GenerationConflict))
        );
        assert_eq!(stale_session.status(), VaultSessionStatus::Locked);
        assert_eq!(
            stale_session.with_signing_key(ManagedAccount::Index0, |_| ()),
            Err(VaultSessionError::InvalidState)
        );
        Ok(())
    }

    #[test]
    fn lock_and_reopen_invalidate_an_old_recovery_token() -> Result<(), Box<dyn std::error::Error>>
    {
        let storage = SharedMemoryStorage::default();
        let mut session = VaultSession::new(storage);
        session.create(
            password()?,
            secret_core::MnemonicWordCount::Twelve,
            1_700_000_006,
        )?;
        let (stale_challenge, stale_confirmation) = solve_pending_recovery(&mut session)?;
        session.lock();
        assert_eq!(
            session.present_recovery(|_| {}).err(),
            Some(VaultSessionError::InvalidState)
        );
        session.open(password()?)?;
        assert_eq!(session.status(), VaultSessionStatus::BackupPending);

        assert_eq!(
            session.confirm_backup(stale_challenge, stale_confirmation),
            Err(VaultSessionError::RecoveryConfirmationFailed)
        );
        assert_eq!(session.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn recovery_tokens_cannot_cross_live_sessions() -> Result<(), Box<dyn std::error::Error>> {
        let storage = SharedMemoryStorage::default();
        let mut first_session = VaultSession::new(storage.clone());
        first_session.create(
            password()?,
            secret_core::MnemonicWordCount::Twelve,
            1_700_000_007,
        )?;
        let mut second_session = VaultSession::new(storage);
        second_session.open(password()?)?;

        let (first_challenge, first_confirmation) = solve_pending_recovery(&mut first_session)?;
        let (second_challenge, second_confirmation) = solve_pending_recovery(&mut second_session)?;
        assert_eq!(
            first_session.confirm_backup(second_challenge, second_confirmation),
            Err(VaultSessionError::RecoveryConfirmationFailed)
        );
        assert_eq!(first_session.status(), VaultSessionStatus::Locked);
        assert_eq!(
            second_session.confirm_backup(first_challenge, first_confirmation),
            Err(VaultSessionError::RecoveryConfirmationFailed)
        );
        assert_eq!(second_session.status(), VaultSessionStatus::Locked);
        Ok(())
    }

    #[test]
    fn displayed_capability_is_live_session_bound_and_commits_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let storage = SharedMemoryStorage::default();
        let mut first_session = VaultSession::new(storage.clone());
        first_session.create(
            password()?,
            secret_core::MnemonicWordCount::Twelve,
            1_700_000_008,
        )?;
        let mut second_session = VaultSession::new(storage);
        second_session.open(password()?)?;

        let cross_session = first_session.display_recovery(|_| {})?;
        assert!(matches!(
            second_session.commit_displayed_recovery(cross_session),
            Err(VaultSessionError::RecoveryConfirmationFailed)
        ));

        let restart_display = first_session.display_recovery(|_| {})?;
        first_session.lock();
        first_session.open(password()?)?;
        assert!(matches!(
            first_session.commit_displayed_recovery(restart_display),
            Err(VaultSessionError::RecoveryConfirmationFailed)
        ));

        let first_display = first_session.display_recovery(|_| {})?;
        let replay_display = first_session.display_recovery(|_| {})?;
        let _challenge = first_session.commit_displayed_recovery(first_display)?;
        assert!(matches!(
            first_session.commit_displayed_recovery(replay_display),
            Err(VaultSessionError::RecoveryConfirmationFailed)
        ));
        assert_eq!(
            first_session.display_recovery(|_| {}).err(),
            Some(VaultSessionError::RecoveryDisplayConsumed)
        );
        Ok(())
    }

    #[test]
    fn confirmation_payload_mutation_failure_locks_the_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let storage = SharedMemoryStorage::default();
        let mut session = VaultSession::new(storage);
        session.create(
            password()?,
            secret_core::MnemonicWordCount::Twelve,
            1_700_000_005,
        )?;
        let (mut challenge, confirmation) = solve_pending_recovery(&mut session)?;
        let unknown_record_id = [0xA5; 16];
        let super::SessionState::BackupPending(pending) = &mut session.state else {
            return Err(VaultSessionError::InvalidState.into());
        };
        pending.record_id = unknown_record_id;
        challenge.binding.record_id = unknown_record_id;

        assert_eq!(
            session.confirm_backup(challenge, confirmation),
            Err(VaultSessionError::RecoveryConfirmationFailed)
        );
        assert_eq!(session.status(), VaultSessionStatus::Locked);
        assert_eq!(
            session.with_signing_key(ManagedAccount::Index0, |_| ()),
            Err(VaultSessionError::InvalidState)
        );
        Ok(())
    }

    #[test]
    fn secret_bearing_debug_output_is_fixed_and_redacted() {
        let confirmation = RecoveryConfirmation::new(
            vec!["must-never-appear".to_owned()],
            secret_core::EthereumAddress::from_bytes([0xA5; 20]),
        );
        assert_eq!(
            format!("{confirmation:?}"),
            "RecoveryConfirmation([REDACTED])"
        );
        let session = VaultSession::new(SharedMemoryStorage::default());
        assert_eq!(
            format!("{session:?}"),
            "VaultSession { storage: \"[REDACTED]\", status: Locked }"
        );
    }

    #[test]
    fn wrong_password_and_corrupt_ciphertext_fail_closed() -> Result<(), Box<dyn std::error::Error>>
    {
        let storage = SharedMemoryStorage::default();
        let mut creator = VaultSession::new(storage.clone());
        creator.create(
            password()?,
            secret_core::MnemonicWordCount::TwentyFour,
            1_700_000_001,
        )?;
        creator.lock();

        let mut wrong = VaultSession::new(storage.clone());
        assert_eq!(
            wrong.open(VaultPassword::new("wrong-test-vault-password")?),
            Err(VaultSessionError::OpenFailed)
        );
        assert_eq!(wrong.status(), VaultSessionStatus::Locked);

        storage.corrupt_last_byte()?;
        let mut corrupt = VaultSession::new(storage);
        assert_eq!(
            corrupt.open(password()?),
            Err(VaultSessionError::OpenFailed)
        );
        assert_eq!(corrupt.status(), VaultSessionStatus::Locked);
        Ok(())
    }
}
