//! Vault-bound authenticated transaction activity for the Sepolia demo.
//!
//! The file is fixed-size, accepts at most 64 immutable transaction identities,
//! and never evicts an entry automatically. Its key is independently derived
//! by the v2 vault. The authenticated generation is a local consistency value,
//! not a monotonic anti-rollback anchor; durable compare-and-swap installation
//! and rollback resistance remain the storage owner's responsibility.

#![cfg_attr(not(test), allow(dead_code))]

use core::fmt;

use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const FILE_MAGIC: &[u8; 8] = b"YWSAH001";
const PAYLOAD_MAGIC: &[u8; 8] = b"YWSAP001";
const VERSION: u16 = 1;
const AEAD_XCHACHA20_POLY1305: u16 = 1;
const PAYLOAD_SCHEMA: u16 = 1;
const SEPOLIA_CHAIN_ID: u64 = 11_155_111;
const HEADER_BYTES: usize = 80;
const PAYLOAD_PREFIX_BYTES: usize = 48;
const RECORD_BYTES: usize = 416;
pub(crate) const ACTIVITY_CAPACITY: usize = 64;
const ACTIVITY_CAPACITY_U16: u16 = 64;
const PAYLOAD_BYTES: usize = PAYLOAD_PREFIX_BYTES + RECORD_BYTES * ACTIVITY_CAPACITY;
const AEAD_TAG_BYTES: usize = 16;
const CIPHERTEXT_BYTES: usize = PAYLOAD_BYTES + AEAD_TAG_BYTES;
pub(crate) const ACTIVITY_FILE_BYTES: usize = HEADER_BYTES + CIPHERTEXT_BYTES;
const MAX_SYMBOL_BYTES: usize = 16;
const MAX_TOTAL_OBSERVATIONS: u32 = 1_000_000;
const MAX_CONSECUTIVE_MISSING: u16 = 4_096;
const DROPPED_MINIMUM_CONSECUTIVE_MISSING: u16 = 3;
const DROPPED_MINIMUM_HEAD_ADVANCE: u64 = 64;

const TRANSFER_NATIVE: u8 = 1;
const TRANSFER_SAVED_ERC20: u8 = 2;
const STATUS_SUBMITTED: u8 = 1;
const STATUS_PENDING: u8 = 2;
const STATUS_INCLUDED: u8 = 3;
const STATUS_REORGED: u8 = 4;
const STATUS_DROPPED_CANDIDATE: u8 = 5;
const STATUS_REPLACEMENT_SUSPECTED: u8 = 6;
const OUTCOME_NONE: u8 = 0;
const OUTCOME_SUCCESS: u8 = 1;
const OUTCOME_REVERT: u8 = 2;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ActivityStoreError {
    InvalidInput,
    Full,
    NotFound,
    IdentityConflict,
    NonceConflict,
    InvalidTransition,
    ObservationLimit,
    RandomnessUnavailable,
    AuthenticationFailed,
    InvalidRecord,
    GenerationOverflow,
}

impl fmt::Debug for ActivityStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "ActivityStoreError::InvalidInput",
            Self::Full => "ActivityStoreError::Full",
            Self::NotFound => "ActivityStoreError::NotFound",
            Self::IdentityConflict => "ActivityStoreError::IdentityConflict",
            Self::NonceConflict => "ActivityStoreError::NonceConflict",
            Self::InvalidTransition => "ActivityStoreError::InvalidTransition",
            Self::ObservationLimit => "ActivityStoreError::ObservationLimit",
            Self::RandomnessUnavailable => "ActivityStoreError::RandomnessUnavailable",
            Self::AuthenticationFailed => "ActivityStoreError::AuthenticationFailed",
            Self::InvalidRecord => "ActivityStoreError::InvalidRecord",
            Self::GenerationOverflow => "ActivityStoreError::GenerationOverflow",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActivityMutation {
    Changed,
    Unchanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ActivityUpsertDisposition {
    Same,
    Available,
}

#[derive(Eq, PartialEq)]
pub(crate) enum Transfer {
    Native {
        recipient: [u8; 20],
        value: [u8; 32],
    },
    SavedErc20 {
        contract: [u8; 20],
        recipient: [u8; 20],
        raw_amount: [u8; 32],
        decimals: u8,
        /// Untrusted display hint. The full contract address remains canonical.
        symbol: Option<String>,
    },
}

impl Transfer {
    pub(crate) const fn recipient(&self) -> &[u8; 20] {
        match self {
            Self::Native { recipient, .. } | Self::SavedErc20 { recipient, .. } => recipient,
        }
    }

    pub(crate) const fn native_value(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Native { value, .. } => Some(value),
            Self::SavedErc20 { .. } => None,
        }
    }

    pub(crate) const fn contract(&self) -> Option<&[u8; 20]> {
        match self {
            Self::Native { .. } => None,
            Self::SavedErc20 { contract, .. } => Some(contract),
        }
    }

    pub(crate) const fn raw_amount(&self) -> Option<&[u8; 32]> {
        match self {
            Self::Native { .. } => None,
            Self::SavedErc20 { raw_amount, .. } => Some(raw_amount),
        }
    }

    pub(crate) const fn decimals(&self) -> Option<u8> {
        match self {
            Self::Native { .. } => None,
            Self::SavedErc20 { decimals, .. } => Some(*decimals),
        }
    }

    pub(crate) fn symbol(&self) -> Option<&str> {
        match self {
            Self::Native { .. } => None,
            Self::SavedErc20 { symbol, .. } => symbol.as_deref(),
        }
    }

    fn duplicate(&self) -> Self {
        match self {
            Self::Native { recipient, value } => Self::Native {
                recipient: *recipient,
                value: *value,
            },
            Self::SavedErc20 {
                contract,
                recipient,
                raw_amount,
                decimals,
                symbol,
            } => Self::SavedErc20 {
                contract: *contract,
                recipient: *recipient,
                raw_amount: *raw_amount,
                decimals: *decimals,
                symbol: symbol.clone(),
            },
        }
    }
}

impl fmt::Debug for Transfer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Transfer([REDACTED])")
    }
}

#[derive(Eq, PartialEq)]
pub(crate) struct TransactionIdentity {
    transaction_hash: [u8; 32],
    sender: [u8; 20],
    account_index: u8,
    nonce: [u8; 32],
    gas_limit: [u8; 32],
    max_priority_fee_per_gas: [u8; 32],
    max_fee_per_gas: [u8; 32],
    transfer: Transfer,
}

impl TransactionIdentity {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn native(
        transaction_hash: [u8; 32],
        sender: [u8; 20],
        account_index: u8,
        nonce: [u8; 32],
        gas_limit: [u8; 32],
        max_priority_fee_per_gas: [u8; 32],
        max_fee_per_gas: [u8; 32],
        recipient: [u8; 20],
        value: [u8; 32],
    ) -> Result<Self, ActivityStoreError> {
        Self::new(
            transaction_hash,
            sender,
            account_index,
            nonce,
            gas_limit,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            Transfer::Native { recipient, value },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn erc20(
        transaction_hash: [u8; 32],
        sender: [u8; 20],
        account_index: u8,
        nonce: [u8; 32],
        gas_limit: [u8; 32],
        max_priority_fee_per_gas: [u8; 32],
        max_fee_per_gas: [u8; 32],
        contract: [u8; 20],
        recipient: [u8; 20],
        raw_amount: [u8; 32],
        decimals: u8,
        symbol: Option<String>,
    ) -> Result<Self, ActivityStoreError> {
        Self::new(
            transaction_hash,
            sender,
            account_index,
            nonce,
            gas_limit,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            Transfer::SavedErc20 {
                contract,
                recipient,
                raw_amount,
                decimals,
                symbol,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn new(
        transaction_hash: [u8; 32],
        sender: [u8; 20],
        account_index: u8,
        nonce: [u8; 32],
        gas_limit: [u8; 32],
        max_priority_fee_per_gas: [u8; 32],
        max_fee_per_gas: [u8; 32],
        transfer: Transfer,
    ) -> Result<Self, ActivityStoreError> {
        let identity = Self {
            transaction_hash,
            sender,
            account_index,
            nonce,
            gas_limit,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            transfer,
        };
        validate_identity(&identity)?;
        Ok(identity)
    }

    pub(crate) const fn transaction_hash(&self) -> &[u8; 32] {
        &self.transaction_hash
    }

    pub(crate) const fn sender(&self) -> &[u8; 20] {
        &self.sender
    }

    pub(crate) const fn account_index(&self) -> u8 {
        self.account_index
    }

    pub(crate) const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    pub(crate) const fn gas_limit(&self) -> &[u8; 32] {
        &self.gas_limit
    }

    pub(crate) const fn max_priority_fee_per_gas(&self) -> &[u8; 32] {
        &self.max_priority_fee_per_gas
    }

    pub(crate) const fn max_fee_per_gas(&self) -> &[u8; 32] {
        &self.max_fee_per_gas
    }

    pub(crate) const fn transfer(&self) -> &Transfer {
        &self.transfer
    }

    fn duplicate(&self) -> Self {
        Self {
            transaction_hash: self.transaction_hash,
            sender: self.sender,
            account_index: self.account_index,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            max_fee_per_gas: self.max_fee_per_gas,
            transfer: self.transfer.duplicate(),
        }
    }
}

impl fmt::Debug for TransactionIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TransactionIdentity([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum InclusionOutcome {
    Success,
    Revert,
}

impl fmt::Debug for InclusionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InclusionOutcome([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Inclusion {
    outcome: InclusionOutcome,
    block_number: u64,
    block_hash: [u8; 32],
    observed_head_number: u64,
    observed_head_hash: [u8; 32],
    depth: u32,
}

impl Inclusion {
    pub(crate) fn new(
        outcome: InclusionOutcome,
        block_number: u64,
        block_hash: [u8; 32],
        observed_head_number: u64,
        observed_head_hash: [u8; 32],
    ) -> Result<Self, ActivityStoreError> {
        if block_number == 0 || block_hash == [0; 32] || observed_head_hash == [0; 32] {
            return Err(ActivityStoreError::InvalidInput);
        }
        let depth = observed_head_number
            .checked_sub(block_number)
            .and_then(|difference| difference.checked_add(1))
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value != 0)
            .ok_or(ActivityStoreError::InvalidInput)?;
        Ok(Self {
            outcome,
            block_number,
            block_hash,
            observed_head_number,
            observed_head_hash,
            depth,
        })
    }

    pub(crate) const fn outcome(&self) -> InclusionOutcome {
        self.outcome
    }

    pub(crate) const fn block_number(&self) -> u64 {
        self.block_number
    }

    pub(crate) const fn block_hash(&self) -> &[u8; 32] {
        &self.block_hash
    }

    pub(crate) const fn observed_head_number(&self) -> u64 {
        self.observed_head_number
    }

    pub(crate) const fn observed_head_hash(&self) -> &[u8; 32] {
        &self.observed_head_hash
    }

    pub(crate) const fn depth(&self) -> u32 {
        self.depth
    }
}

impl fmt::Debug for Inclusion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Inclusion([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ActivityStatus {
    Submitted,
    Pending,
    Included(Inclusion),
    /// The former canonical inclusion retained as reorg evidence.
    Reorged(Inclusion),
    DroppedCandidate,
    ReplacementSuspected,
}

impl fmt::Debug for ActivityStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActivityStatus([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ObservationCounters {
    total_observations: u32,
    total_misses: u32,
    consecutive_missing: u16,
    first_missing_head: Option<u64>,
    last_observed_head: Option<u64>,
}

impl ObservationCounters {
    pub(crate) const fn initial() -> Self {
        Self {
            total_observations: 0,
            total_misses: 0,
            consecutive_missing: 0,
            first_missing_head: None,
            last_observed_head: None,
        }
    }

    pub(crate) fn record_present(self, head_number: u64) -> Result<Self, ActivityStoreError> {
        self.validate_next_head(head_number)?;
        let total_observations = self.next_total()?;
        Ok(Self {
            total_observations,
            total_misses: self.total_misses,
            consecutive_missing: 0,
            first_missing_head: None,
            last_observed_head: Some(head_number),
        })
    }

    pub(crate) fn record_missing(self, head_number: u64) -> Result<Self, ActivityStoreError> {
        self.validate_next_head(head_number)?;
        let total_observations = self.next_total()?;
        let total_misses = self
            .total_misses
            .checked_add(1)
            .filter(|value| *value <= MAX_TOTAL_OBSERVATIONS)
            .ok_or(ActivityStoreError::ObservationLimit)?;
        let consecutive_missing = self
            .consecutive_missing
            .checked_add(1)
            .filter(|value| *value <= MAX_CONSECUTIVE_MISSING)
            .ok_or(ActivityStoreError::ObservationLimit)?;
        Ok(Self {
            total_observations,
            total_misses,
            consecutive_missing,
            first_missing_head: self.first_missing_head.or(Some(head_number)),
            last_observed_head: Some(head_number),
        })
    }

    pub(crate) const fn total_observations(&self) -> u32 {
        self.total_observations
    }

    pub(crate) const fn total_misses(&self) -> u32 {
        self.total_misses
    }

    pub(crate) const fn consecutive_missing(&self) -> u16 {
        self.consecutive_missing
    }

    pub(crate) const fn first_missing_head(&self) -> Option<u64> {
        self.first_missing_head
    }

    pub(crate) const fn last_observed_head(&self) -> Option<u64> {
        self.last_observed_head
    }

    pub(crate) fn dropped_candidate_ready(&self) -> bool {
        self.consecutive_missing >= DROPPED_MINIMUM_CONSECUTIVE_MISSING
            && self
                .first_missing_head
                .zip(self.last_observed_head)
                .and_then(|(first, last)| last.checked_sub(first))
                .is_some_and(|advance| advance >= DROPPED_MINIMUM_HEAD_ADVANCE)
    }

    fn next_total(self) -> Result<u32, ActivityStoreError> {
        self.total_observations
            .checked_add(1)
            .filter(|value| *value <= MAX_TOTAL_OBSERVATIONS)
            .ok_or(ActivityStoreError::ObservationLimit)
    }

    fn validate_next_head(self, head_number: u64) -> Result<(), ActivityStoreError> {
        if head_number == 0
            || self
                .last_observed_head
                .is_some_and(|previous| head_number < previous)
        {
            return Err(ActivityStoreError::InvalidInput);
        }
        Ok(())
    }
}

impl fmt::Debug for ObservationCounters {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ObservationCounters([REDACTED])")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ObservationKind {
    Present,
    Missing,
}

#[derive(Eq, PartialEq)]
pub(crate) struct ActivityEntry {
    submission_sequence: u64,
    identity: TransactionIdentity,
    status: ActivityStatus,
    observations: ObservationCounters,
}

impl ActivityEntry {
    pub(crate) const fn submission_sequence(&self) -> u64 {
        self.submission_sequence
    }

    pub(crate) const fn identity(&self) -> &TransactionIdentity {
        &self.identity
    }

    pub(crate) const fn status(&self) -> ActivityStatus {
        self.status
    }

    pub(crate) const fn observations(&self) -> ObservationCounters {
        self.observations
    }
}

impl fmt::Debug for ActivityEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActivityEntry([REDACTED])")
    }
}

pub(crate) struct ActivityStore {
    vault_id: [u8; 16],
    generation: u64,
    entries: Vec<ActivityEntry>,
}

impl ActivityStore {
    pub(crate) fn empty(vault_id: [u8; 16]) -> Result<Self, ActivityStoreError> {
        if vault_id == [0; 16] {
            return Err(ActivityStoreError::InvalidInput);
        }
        Ok(Self {
            vault_id,
            generation: 0,
            entries: Vec::with_capacity(ACTIVITY_CAPACITY),
        })
    }

    pub(crate) const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    /// Authenticated file-version consistency value, not an anti-rollback anchor.
    pub(crate) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn entries(&self) -> &[ActivityEntry] {
        &self.entries
    }

    pub(crate) fn find(&self, transaction_hash: &[u8; 32]) -> Option<&ActivityEntry> {
        self.entries
            .iter()
            .find(|entry| entry.identity.transaction_hash == *transaction_hash)
    }

    /// Reject an occupied sender nonce before signing creates a transaction hash.
    pub(crate) fn ensure_nonce_available(
        &self,
        account_index: u8,
        sender: &[u8; 20],
        nonce: &[u8; 32],
    ) -> Result<(), ActivityStoreError> {
        if account_index > 1 || *sender == [0; 20] {
            return Err(ActivityStoreError::InvalidInput);
        }
        if self.entries.iter().any(|entry| {
            entry.identity.account_index == account_index
                && entry.identity.sender == *sender
                && entry.identity.nonce == *nonce
        }) {
            return Err(ActivityStoreError::NonceConflict);
        }
        Ok(())
    }

    /// Classify an immutable post-sign identity without mutating the store.
    pub(crate) fn can_upsert(
        &self,
        identity: &TransactionIdentity,
    ) -> Result<ActivityUpsertDisposition, ActivityStoreError> {
        validate_identity(identity)?;
        if let Some(existing) = self.find(identity.transaction_hash()) {
            return if existing.identity == *identity {
                Ok(ActivityUpsertDisposition::Same)
            } else {
                Err(ActivityStoreError::IdentityConflict)
            };
        }
        self.ensure_nonce_available(identity.account_index, &identity.sender, &identity.nonce)?;
        if self.entries.len() >= ACTIVITY_CAPACITY {
            return Err(ActivityStoreError::Full);
        }
        Ok(ActivityUpsertDisposition::Available)
    }

    pub(crate) fn upsert_submitted(
        &mut self,
        identity: &TransactionIdentity,
    ) -> Result<ActivityMutation, ActivityStoreError> {
        match self.can_upsert(identity)? {
            ActivityUpsertDisposition::Same => return Ok(ActivityMutation::Unchanged),
            ActivityUpsertDisposition::Available => {}
        }
        let next_generation = self.next_generation()?;
        self.entries.push(ActivityEntry {
            submission_sequence: next_generation,
            identity: identity.duplicate(),
            status: ActivityStatus::Submitted,
            observations: ObservationCounters::initial(),
        });
        self.generation = next_generation;
        Ok(ActivityMutation::Changed)
    }

    pub(crate) fn transition(
        &mut self,
        transaction_hash: &[u8; 32],
        next_status: ActivityStatus,
        next_observations: ObservationCounters,
    ) -> Result<ActivityMutation, ActivityStoreError> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.identity.transaction_hash == *transaction_hash)
            .ok_or(ActivityStoreError::NotFound)?;
        let entry = &self.entries[index];
        if entry.status == next_status && entry.observations == next_observations {
            return Ok(ActivityMutation::Unchanged);
        }
        let observation_kind = validate_observation_step(entry.observations, next_observations)?;
        validate_status_transition(
            entry.status,
            next_status,
            observation_kind,
            next_observations,
        )?;
        let next_generation = self.next_generation()?;
        self.entries[index].status = next_status;
        self.entries[index].observations = next_observations;
        self.generation = next_generation;
        Ok(ActivityMutation::Changed)
    }

    pub(crate) fn seal(&self, key: &[u8; 32]) -> Result<Vec<u8>, ActivityStoreError> {
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| ActivityStoreError::RandomnessUnavailable)?;
        self.seal_with_nonce(key, nonce)
    }

    fn seal_with_nonce(
        &self,
        key: &[u8; 32],
        nonce: [u8; 24],
    ) -> Result<Vec<u8>, ActivityStoreError> {
        if self.vault_id == [0; 16]
            || self.generation == 0
            || self.entries.is_empty()
            || nonce == [0; 24]
        {
            return Err(ActivityStoreError::InvalidInput);
        }
        validate_entries(&self.entries, self.generation)?;
        let header = encode_header(self.vault_id, self.generation, nonce);
        let plaintext = Zeroizing::new(encode_payload(
            self.vault_id,
            self.generation,
            &self.entries,
        )?);
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &header,
                },
            )
            .map_err(|_| ActivityStoreError::AuthenticationFailed)?;
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(ActivityStoreError::AuthenticationFailed);
        }
        let mut file = Vec::with_capacity(ACTIVITY_FILE_BYTES);
        file.extend_from_slice(&header);
        file.extend_from_slice(&ciphertext);
        if file.len() != ACTIVITY_FILE_BYTES {
            return Err(ActivityStoreError::InvalidRecord);
        }
        Ok(file)
    }

    pub(crate) fn open(
        bytes: &[u8],
        key: &[u8; 32],
        expected_vault_id: &[u8; 16],
    ) -> Result<Self, ActivityStoreError> {
        if bytes.len() != ACTIVITY_FILE_BYTES || expected_vault_id == &[0; 16] {
            return Err(ActivityStoreError::InvalidRecord);
        }
        let header: &[u8; HEADER_BYTES] = bytes[..HEADER_BYTES]
            .try_into()
            .map_err(|_| ActivityStoreError::InvalidRecord)?;
        let decoded = decode_header(header, expected_vault_id)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&decoded.nonce),
                Payload {
                    msg: &bytes[HEADER_BYTES..],
                    aad: header,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| ActivityStoreError::AuthenticationFailed)?;
        if plaintext.len() != PAYLOAD_BYTES {
            return Err(ActivityStoreError::InvalidRecord);
        }
        let entries = decode_payload(plaintext.as_slice(), expected_vault_id, decoded.generation)?;
        Ok(Self {
            vault_id: *expected_vault_id,
            generation: decoded.generation,
            entries,
        })
    }

    fn next_generation(&self) -> Result<u64, ActivityStoreError> {
        self.generation
            .checked_add(1)
            .ok_or(ActivityStoreError::GenerationOverflow)
    }
}

impl fmt::Debug for ActivityStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ActivityStore([REDACTED])")
    }
}

struct DecodedHeader {
    generation: u64,
    nonce: [u8; 24],
}

fn encode_header(vault_id: [u8; 16], generation: u64, nonce: [u8; 24]) -> [u8; HEADER_BYTES] {
    let mut header = [0_u8; HEADER_BYTES];
    header[..8].copy_from_slice(FILE_MAGIC);
    put_u16(&mut header, 8, VERSION);
    put_u16(&mut header, 10, HEADER_BYTES as u16);
    put_u16(&mut header, 12, AEAD_XCHACHA20_POLY1305);
    put_u16(&mut header, 14, PAYLOAD_SCHEMA);
    put_u64(&mut header, 16, SEPOLIA_CHAIN_ID);
    put_u64(&mut header, 24, generation);
    header[32..48].copy_from_slice(&vault_id);
    header[48..72].copy_from_slice(&nonce);
    put_u32(&mut header, 72, CIPHERTEXT_BYTES as u32);
    put_u16(&mut header, 76, ACTIVITY_CAPACITY_U16);
    header
}

fn decode_header(
    header: &[u8; HEADER_BYTES],
    expected_vault_id: &[u8; 16],
) -> Result<DecodedHeader, ActivityStoreError> {
    if &header[..8] != FILE_MAGIC
        || read_u16(header, 8)? != VERSION
        || usize::from(read_u16(header, 10)?) != HEADER_BYTES
        || read_u16(header, 12)? != AEAD_XCHACHA20_POLY1305
        || read_u16(header, 14)? != PAYLOAD_SCHEMA
        || read_u64(header, 16)? != SEPOLIA_CHAIN_ID
        || &header[32..48] != expected_vault_id
        || usize::try_from(read_u32(header, 72)?).ok() != Some(CIPHERTEXT_BYTES)
        || read_u16(header, 76)? != ACTIVITY_CAPACITY_U16
        || header[78..].iter().any(|byte| *byte != 0)
    {
        return Err(ActivityStoreError::InvalidRecord);
    }
    let generation = read_u64(header, 24)?;
    let nonce = array_at::<24>(header, 48)?;
    if generation == 0 || nonce == [0; 24] {
        return Err(ActivityStoreError::InvalidRecord);
    }
    Ok(DecodedHeader { generation, nonce })
}

fn encode_payload(
    vault_id: [u8; 16],
    generation: u64,
    entries: &[ActivityEntry],
) -> Result<Vec<u8>, ActivityStoreError> {
    let count = u16::try_from(entries.len()).map_err(|_| ActivityStoreError::Full)?;
    let mut payload = vec![0_u8; PAYLOAD_BYTES];
    payload[..8].copy_from_slice(PAYLOAD_MAGIC);
    put_u16(&mut payload, 8, PAYLOAD_SCHEMA);
    put_u16(&mut payload, 10, count);
    put_u16(&mut payload, 12, ACTIVITY_CAPACITY_U16);
    put_u64(&mut payload, 16, generation);
    payload[24..40].copy_from_slice(&vault_id);
    put_u64(&mut payload, 40, SEPOLIA_CHAIN_ID);
    for (index, entry) in entries.iter().enumerate() {
        encode_entry(entry, &mut payload[record_range(index)])?;
    }
    Ok(payload)
}

fn decode_payload(
    payload: &[u8],
    expected_vault_id: &[u8; 16],
    expected_generation: u64,
) -> Result<Vec<ActivityEntry>, ActivityStoreError> {
    if payload.len() != PAYLOAD_BYTES
        || &payload[..8] != PAYLOAD_MAGIC
        || read_u16(payload, 8)? != PAYLOAD_SCHEMA
        || read_u16(payload, 12)? != ACTIVITY_CAPACITY_U16
        || payload[14..16].iter().any(|byte| *byte != 0)
        || read_u64(payload, 16)? != expected_generation
        || &payload[24..40] != expected_vault_id
        || read_u64(payload, 40)? != SEPOLIA_CHAIN_ID
    {
        return Err(ActivityStoreError::InvalidRecord);
    }
    let count = usize::from(read_u16(payload, 10)?);
    if count == 0 || count > ACTIVITY_CAPACITY {
        return Err(ActivityStoreError::InvalidRecord);
    }
    let mut entries = Vec::with_capacity(ACTIVITY_CAPACITY);
    for index in 0..count {
        entries.push(decode_entry(&payload[record_range(index)])?);
    }
    for index in count..ACTIVITY_CAPACITY {
        if payload[record_range(index)].iter().any(|byte| *byte != 0) {
            return Err(ActivityStoreError::InvalidRecord);
        }
    }
    validate_entries(&entries, expected_generation)?;
    Ok(entries)
}

fn encode_entry(entry: &ActivityEntry, output: &mut [u8]) -> Result<(), ActivityStoreError> {
    if output.len() != RECORD_BYTES {
        return Err(ActivityStoreError::InvalidRecord);
    }
    output.fill(0);
    output[0..32].copy_from_slice(entry.identity.transaction_hash());
    output[32..52].copy_from_slice(entry.identity.sender());
    output[52] = entry.identity.account_index();
    output[53] = match entry.identity.transfer() {
        Transfer::Native { .. } => TRANSFER_NATIVE,
        Transfer::SavedErc20 { .. } => TRANSFER_SAVED_ERC20,
    };
    let (status_tag, outcome_tag, inclusion) = encode_status(entry.status);
    output[54] = status_tag;
    output[55] = outcome_tag;
    put_u64(output, 56, entry.submission_sequence);
    output[64..96].copy_from_slice(entry.identity.nonce());
    output[96..128].copy_from_slice(entry.identity.gas_limit());
    output[128..160].copy_from_slice(entry.identity.max_priority_fee_per_gas());
    output[160..192].copy_from_slice(entry.identity.max_fee_per_gas());
    output[192..212].copy_from_slice(entry.identity.transfer().recipient());
    match entry.identity.transfer() {
        Transfer::Native { value, .. } => output[232..264].copy_from_slice(value),
        Transfer::SavedErc20 {
            contract,
            raw_amount,
            decimals,
            symbol,
            ..
        } => {
            output[212..232].copy_from_slice(contract);
            output[232..264].copy_from_slice(raw_amount);
            output[264] = *decimals;
            let symbol = symbol.as_deref().unwrap_or("").as_bytes();
            output[265] =
                u8::try_from(symbol.len()).map_err(|_| ActivityStoreError::InvalidInput)?;
            output[266..266 + symbol.len()].copy_from_slice(symbol);
        }
    }
    if let Some(inclusion) = inclusion {
        put_u64(output, 288, inclusion.block_number);
        output[296..328].copy_from_slice(&inclusion.block_hash);
        put_u64(output, 328, inclusion.observed_head_number);
        output[336..368].copy_from_slice(&inclusion.observed_head_hash);
        put_u32(output, 368, inclusion.depth);
    }
    put_u32(output, 372, entry.observations.total_observations);
    put_u32(output, 376, entry.observations.total_misses);
    put_u16(output, 380, entry.observations.consecutive_missing);
    put_u64(
        output,
        384,
        entry.observations.first_missing_head.unwrap_or(0),
    );
    put_u64(
        output,
        392,
        entry.observations.last_observed_head.unwrap_or(0),
    );
    Ok(())
}

fn decode_entry(input: &[u8]) -> Result<ActivityEntry, ActivityStoreError> {
    if input.len() != RECORD_BYTES
        || input[282..288].iter().any(|byte| *byte != 0)
        || input[382..384].iter().any(|byte| *byte != 0)
        || input[400..416].iter().any(|byte| *byte != 0)
    {
        return Err(ActivityStoreError::InvalidRecord);
    }
    let symbol_length = usize::from(input[265]);
    if symbol_length > MAX_SYMBOL_BYTES
        || input[266 + symbol_length..282]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(ActivityStoreError::InvalidRecord);
    }
    let recipient = array_at::<20>(input, 192)?;
    let amount = array_at::<32>(input, 232)?;
    let identity = match input[53] {
        TRANSFER_NATIVE => {
            if input[212..232].iter().any(|byte| *byte != 0)
                || input[264] != 0
                || symbol_length != 0
            {
                return Err(ActivityStoreError::InvalidRecord);
            }
            TransactionIdentity::native(
                array_at::<32>(input, 0)?,
                array_at::<20>(input, 32)?,
                input[52],
                array_at::<32>(input, 64)?,
                array_at::<32>(input, 96)?,
                array_at::<32>(input, 128)?,
                array_at::<32>(input, 160)?,
                recipient,
                amount,
            )
        }
        TRANSFER_SAVED_ERC20 => {
            let symbol = if symbol_length == 0 {
                None
            } else {
                Some(
                    core::str::from_utf8(&input[266..266 + symbol_length])
                        .map_err(|_| ActivityStoreError::InvalidRecord)?
                        .to_owned(),
                )
            };
            TransactionIdentity::erc20(
                array_at::<32>(input, 0)?,
                array_at::<20>(input, 32)?,
                input[52],
                array_at::<32>(input, 64)?,
                array_at::<32>(input, 96)?,
                array_at::<32>(input, 128)?,
                array_at::<32>(input, 160)?,
                array_at::<20>(input, 212)?,
                recipient,
                amount,
                input[264],
                symbol,
            )
        }
        _ => return Err(ActivityStoreError::InvalidRecord),
    }
    .map_err(|_| ActivityStoreError::InvalidRecord)?;
    let inclusion = decode_inclusion(input[55], input)?;
    let status = match input[54] {
        STATUS_SUBMITTED if inclusion.is_none() => ActivityStatus::Submitted,
        STATUS_PENDING if inclusion.is_none() => ActivityStatus::Pending,
        STATUS_INCLUDED => {
            ActivityStatus::Included(inclusion.ok_or(ActivityStoreError::InvalidRecord)?)
        }
        STATUS_REORGED => {
            ActivityStatus::Reorged(inclusion.ok_or(ActivityStoreError::InvalidRecord)?)
        }
        STATUS_DROPPED_CANDIDATE if inclusion.is_none() => ActivityStatus::DroppedCandidate,
        STATUS_REPLACEMENT_SUSPECTED if inclusion.is_none() => ActivityStatus::ReplacementSuspected,
        _ => return Err(ActivityStoreError::InvalidRecord),
    };
    let first_missing_head = nonzero_option(read_u64(input, 384)?);
    let last_observed_head = nonzero_option(read_u64(input, 392)?);
    let observations = ObservationCounters {
        total_observations: read_u32(input, 372)?,
        total_misses: read_u32(input, 376)?,
        consecutive_missing: read_u16(input, 380)?,
        first_missing_head,
        last_observed_head,
    };
    validate_observations(observations)?;
    validate_status_state(status, observations)?;
    Ok(ActivityEntry {
        submission_sequence: read_u64(input, 56)?,
        identity,
        status,
        observations,
    })
}

fn encode_status(status: ActivityStatus) -> (u8, u8, Option<Inclusion>) {
    match status {
        ActivityStatus::Submitted => (STATUS_SUBMITTED, OUTCOME_NONE, None),
        ActivityStatus::Pending => (STATUS_PENDING, OUTCOME_NONE, None),
        ActivityStatus::Included(inclusion) => (
            STATUS_INCLUDED,
            encode_outcome(inclusion.outcome),
            Some(inclusion),
        ),
        ActivityStatus::Reorged(inclusion) => (
            STATUS_REORGED,
            encode_outcome(inclusion.outcome),
            Some(inclusion),
        ),
        ActivityStatus::DroppedCandidate => (STATUS_DROPPED_CANDIDATE, OUTCOME_NONE, None),
        ActivityStatus::ReplacementSuspected => (STATUS_REPLACEMENT_SUSPECTED, OUTCOME_NONE, None),
    }
}

const fn encode_outcome(outcome: InclusionOutcome) -> u8 {
    match outcome {
        InclusionOutcome::Success => OUTCOME_SUCCESS,
        InclusionOutcome::Revert => OUTCOME_REVERT,
    }
}

fn decode_inclusion(
    outcome_tag: u8,
    input: &[u8],
) -> Result<Option<Inclusion>, ActivityStoreError> {
    if outcome_tag == OUTCOME_NONE {
        if input[288..372].iter().any(|byte| *byte != 0) {
            return Err(ActivityStoreError::InvalidRecord);
        }
        return Ok(None);
    }
    let outcome = match outcome_tag {
        OUTCOME_SUCCESS => InclusionOutcome::Success,
        OUTCOME_REVERT => InclusionOutcome::Revert,
        _ => return Err(ActivityStoreError::InvalidRecord),
    };
    let inclusion = Inclusion::new(
        outcome,
        read_u64(input, 288)?,
        array_at::<32>(input, 296)?,
        read_u64(input, 328)?,
        array_at::<32>(input, 336)?,
    )
    .map_err(|_| ActivityStoreError::InvalidRecord)?;
    if inclusion.depth != read_u32(input, 368)? {
        return Err(ActivityStoreError::InvalidRecord);
    }
    Ok(Some(inclusion))
}

fn validate_identity(identity: &TransactionIdentity) -> Result<(), ActivityStoreError> {
    if identity.transaction_hash == [0; 32]
        || identity.sender == [0; 20]
        || identity.account_index > 1
        || identity.gas_limit == [0; 32]
        || identity.max_fee_per_gas == [0; 32]
        || identity.max_fee_per_gas < identity.max_priority_fee_per_gas
        || identity.transfer.recipient() == &[0; 20]
    {
        return Err(ActivityStoreError::InvalidInput);
    }
    match &identity.transfer {
        Transfer::Native { value, .. } => {
            if *value == [0; 32] {
                return Err(ActivityStoreError::InvalidInput);
            }
        }
        Transfer::SavedErc20 {
            contract,
            raw_amount,
            decimals,
            symbol,
            ..
        } => {
            if *contract == [0; 20] || *raw_amount == [0; 32] || *decimals > 36 {
                return Err(ActivityStoreError::InvalidInput);
            }
            if let Some(symbol) = symbol.as_deref() {
                validate_symbol(symbol)?;
            }
        }
    }
    Ok(())
}

fn validate_symbol(symbol: &str) -> Result<(), ActivityStoreError> {
    if symbol.is_empty()
        || symbol.len() > MAX_SYMBOL_BYTES
        || !symbol.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'$' | b'+' | b'-' | b'.' | b'_')
        })
    {
        return Err(ActivityStoreError::InvalidInput);
    }
    Ok(())
}

fn validate_observations(observations: ObservationCounters) -> Result<(), ActivityStoreError> {
    let empty = observations.total_observations == 0
        && observations.total_misses == 0
        && observations.consecutive_missing == 0
        && observations.first_missing_head.is_none()
        && observations.last_observed_head.is_none();
    if empty {
        return Ok(());
    }
    if observations.total_observations == 0
        || observations.total_observations > MAX_TOTAL_OBSERVATIONS
        || observations.total_misses > observations.total_observations
        || observations.consecutive_missing > MAX_CONSECUTIVE_MISSING
        || observations.last_observed_head.is_none()
        || (observations.consecutive_missing == 0) != observations.first_missing_head.is_none()
        || observations
            .first_missing_head
            .zip(observations.last_observed_head)
            .is_some_and(|(first, last)| first > last)
        || u32::from(observations.consecutive_missing) > observations.total_misses
    {
        return Err(ActivityStoreError::InvalidRecord);
    }
    Ok(())
}

fn validate_observation_step(
    current: ObservationCounters,
    next: ObservationCounters,
) -> Result<ObservationKind, ActivityStoreError> {
    validate_observations(next).map_err(|_| ActivityStoreError::InvalidTransition)?;
    let expected_total = current
        .total_observations
        .checked_add(1)
        .ok_or(ActivityStoreError::InvalidTransition)?;
    if next.total_observations != expected_total
        || next
            .last_observed_head
            .zip(current.last_observed_head)
            .is_some_and(|(next_head, current_head)| next_head < current_head)
    {
        return Err(ActivityStoreError::InvalidTransition);
    }
    if next.total_misses == current.total_misses {
        if next.consecutive_missing != 0 || next.first_missing_head.is_some() {
            return Err(ActivityStoreError::InvalidTransition);
        }
        Ok(ObservationKind::Present)
    } else if next.total_misses
        == current
            .total_misses
            .checked_add(1)
            .ok_or(ActivityStoreError::InvalidTransition)?
    {
        let expected_streak = current
            .consecutive_missing
            .checked_add(1)
            .ok_or(ActivityStoreError::InvalidTransition)?;
        let expected_first = current.first_missing_head.or(next.last_observed_head);
        if next.consecutive_missing != expected_streak || next.first_missing_head != expected_first
        {
            return Err(ActivityStoreError::InvalidTransition);
        }
        Ok(ObservationKind::Missing)
    } else {
        Err(ActivityStoreError::InvalidTransition)
    }
}

fn validate_status_transition(
    current: ActivityStatus,
    next: ActivityStatus,
    observation: ObservationKind,
    counters: ObservationCounters,
) -> Result<(), ActivityStoreError> {
    let allowed = match (current, next) {
        (ActivityStatus::Submitted, ActivityStatus::Submitted)
        | (ActivityStatus::Submitted, ActivityStatus::Pending)
        | (ActivityStatus::Pending, ActivityStatus::Pending)
        | (ActivityStatus::Reorged(_), ActivityStatus::Pending)
        | (ActivityStatus::DroppedCandidate, ActivityStatus::Pending)
        | (ActivityStatus::ReplacementSuspected, ActivityStatus::Pending) => true,
        (
            ActivityStatus::Submitted
            | ActivityStatus::Pending
            | ActivityStatus::Reorged(_)
            | ActivityStatus::DroppedCandidate
            | ActivityStatus::ReplacementSuspected,
            ActivityStatus::Included(_),
        ) => true,
        (ActivityStatus::Included(current_inclusion), ActivityStatus::Included(next_inclusion)) => {
            current_inclusion.outcome == next_inclusion.outcome
                && current_inclusion.block_number == next_inclusion.block_number
                && current_inclusion.block_hash == next_inclusion.block_hash
                && match observation {
                    ObservationKind::Present => {
                        next_inclusion.observed_head_number
                            >= current_inclusion.observed_head_number
                            && next_inclusion.depth >= current_inclusion.depth
                    }
                    ObservationKind::Missing => current_inclusion == next_inclusion,
                }
        }
        (ActivityStatus::Included(current_inclusion), ActivityStatus::Reorged(former)) => {
            current_inclusion == former
        }
        (ActivityStatus::Reorged(current_former), ActivityStatus::Reorged(next_former)) => {
            current_former == next_former
        }
        (
            ActivityStatus::Submitted
            | ActivityStatus::Pending
            | ActivityStatus::Reorged(_)
            | ActivityStatus::DroppedCandidate
            | ActivityStatus::ReplacementSuspected,
            ActivityStatus::DroppedCandidate | ActivityStatus::ReplacementSuspected,
        ) => true,
        _ => false,
    };
    if !allowed {
        return Err(ActivityStoreError::InvalidTransition);
    }
    match next {
        ActivityStatus::Included(inclusion) => match observation {
            ObservationKind::Present => {
                if counters.last_observed_head != Some(inclusion.observed_head_number)
                    || counters.consecutive_missing != 0
                    || counters.first_missing_head.is_some()
                {
                    return Err(ActivityStoreError::InvalidTransition);
                }
            }
            ObservationKind::Missing => {
                if current != ActivityStatus::Included(inclusion) {
                    return Err(ActivityStoreError::InvalidTransition);
                }
            }
        },
        ActivityStatus::Reorged(_)
        | ActivityStatus::DroppedCandidate
        | ActivityStatus::ReplacementSuspected => {
            if observation != ObservationKind::Missing {
                return Err(ActivityStoreError::InvalidTransition);
            }
        }
        ActivityStatus::Submitted => {
            if observation != ObservationKind::Missing {
                return Err(ActivityStoreError::InvalidTransition);
            }
        }
        ActivityStatus::Pending => {
            if current != ActivityStatus::Pending && observation != ObservationKind::Present {
                return Err(ActivityStoreError::InvalidTransition);
            }
        }
    }
    if matches!(next, ActivityStatus::DroppedCandidate) && !counters.dropped_candidate_ready() {
        return Err(ActivityStoreError::InvalidTransition);
    }
    Ok(())
}

fn validate_status_state(
    status: ActivityStatus,
    observations: ObservationCounters,
) -> Result<(), ActivityStoreError> {
    match status {
        ActivityStatus::Submitted
            if observations == ObservationCounters::initial()
                || (observations.total_observations > 0
                    && observations.total_observations == observations.total_misses
                    && observations.total_misses
                        == u32::from(observations.consecutive_missing)) =>
        {
            Ok(())
        }
        ActivityStatus::Included(inclusion)
            if observations.total_observations > 0
                && observations.total_observations > observations.total_misses
                && if observations.consecutive_missing == 0 {
                    observations.first_missing_head.is_none()
                        && observations.last_observed_head == Some(inclusion.observed_head_number)
                } else {
                    observations
                        .first_missing_head
                        .is_some_and(|head| head >= inclusion.observed_head_number)
                        && observations
                            .last_observed_head
                            .is_some_and(|head| head >= inclusion.observed_head_number)
                } =>
        {
            Ok(())
        }
        ActivityStatus::Reorged(former)
            if observations.consecutive_missing > 0
                && observations.total_observations > observations.total_misses
                && observations
                    .first_missing_head
                    .is_some_and(|head| head >= former.observed_head_number)
                && observations
                    .last_observed_head
                    .is_some_and(|head| head >= former.observed_head_number) =>
        {
            Ok(())
        }
        ActivityStatus::ReplacementSuspected if observations.consecutive_missing > 0 => Ok(()),
        ActivityStatus::DroppedCandidate if observations.dropped_candidate_ready() => Ok(()),
        ActivityStatus::Pending if observations.total_observations > observations.total_misses => {
            Ok(())
        }
        _ => Err(ActivityStoreError::InvalidRecord),
    }
}

fn validate_entries(entries: &[ActivityEntry], generation: u64) -> Result<(), ActivityStoreError> {
    if entries.is_empty() || entries.len() > ACTIVITY_CAPACITY || generation == 0 {
        return Err(ActivityStoreError::InvalidRecord);
    }
    let mut prior_sequence = 0_u64;
    for (index, entry) in entries.iter().enumerate() {
        validate_identity(&entry.identity).map_err(|_| ActivityStoreError::InvalidRecord)?;
        validate_observations(entry.observations)?;
        validate_status_state(entry.status, entry.observations)?;
        if entry.submission_sequence == 0
            || entry.submission_sequence <= prior_sequence
            || entry.submission_sequence > generation
            || entries[index + 1..].iter().any(|other| {
                other.identity.transaction_hash == entry.identity.transaction_hash
                    || same_nonce_slot(&other.identity, &entry.identity)
                    || other.submission_sequence == entry.submission_sequence
            })
        {
            return Err(ActivityStoreError::InvalidRecord);
        }
        prior_sequence = entry.submission_sequence;
    }
    Ok(())
}

fn same_nonce_slot(left: &TransactionIdentity, right: &TransactionIdentity) -> bool {
    left.account_index == right.account_index
        && left.sender == right.sender
        && left.nonce == right.nonce
}

const fn nonzero_option(value: u64) -> Option<u64> {
    if value == 0 { None } else { Some(value) }
}

fn record_range(index: usize) -> core::ops::Range<usize> {
    let start = PAYLOAD_PREFIX_BYTES + index * RECORD_BYTES;
    start..start + RECORD_BYTES
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, ActivityStoreError> {
    array_at::<2>(bytes, offset).map(u16::from_be_bytes)
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, ActivityStoreError> {
    array_at::<4>(bytes, offset).map(u32::from_be_bytes)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, ActivityStoreError> {
    array_at::<8>(bytes, offset).map(u64::from_be_bytes)
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], ActivityStoreError> {
    bytes
        .get(offset..offset.saturating_add(N))
        .and_then(|slice| slice.try_into().ok())
        .ok_or(ActivityStoreError::InvalidRecord)
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
    use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};

    use super::{
        ACTIVITY_CAPACITY, ACTIVITY_FILE_BYTES, ActivityMutation, ActivityStatus, ActivityStore,
        ActivityStoreError, ActivityUpsertDisposition, HEADER_BYTES, Inclusion, InclusionOutcome,
        MAX_CONSECUTIVE_MISSING, MAX_TOTAL_OBSERVATIONS, ObservationCounters, PAYLOAD_BYTES,
        RECORD_BYTES, TransactionIdentity, Transfer, decode_payload, encode_header, encode_payload,
        put_u16, put_u32, put_u64, record_range,
    };

    fn word(value: u64) -> [u8; 32] {
        let mut output = [0_u8; 32];
        output[24..].copy_from_slice(&value.to_be_bytes());
        output
    }

    fn native(marker: u8) -> TransactionIdentity {
        TransactionIdentity::native(
            [marker; 32],
            [0x11 + marker; 20],
            marker % 2,
            word(u64::from(marker)),
            word(21_000),
            word(1_000_000_000),
            word(2_000_000_000),
            [0x55 + marker; 20],
            word(1_000 + u64::from(marker)),
        )
        .expect("valid native identity")
    }

    fn erc20(marker: u8) -> TransactionIdentity {
        TransactionIdentity::erc20(
            [marker; 32],
            [0x11 + marker; 20],
            marker % 2,
            word(u64::from(marker)),
            word(50_000),
            word(1_000_000_000),
            word(2_000_000_000),
            [0x77 + marker; 20],
            [0x55 + marker; 20],
            word(1_000 + u64::from(marker)),
            18,
            Some(format!("TOK{marker}")),
        )
        .expect("valid ERC-20 identity")
    }

    fn native_in_slot(
        transaction_hash: [u8; 32],
        sender: [u8; 20],
        account_index: u8,
        nonce: [u8; 32],
    ) -> TransactionIdentity {
        TransactionIdentity::native(
            transaction_hash,
            sender,
            account_index,
            nonce,
            word(21_000),
            word(1_000_000_000),
            word(2_000_000_000),
            [0x55; 20],
            word(1_000),
        )
        .expect("valid native identity in requested slot")
    }

    fn populated_store() -> ActivityStore {
        let mut store = ActivityStore::empty([0x11; 16]).expect("empty store");
        assert_eq!(
            store.upsert_submitted(&native(1)),
            Ok(ActivityMutation::Changed)
        );
        assert_eq!(
            store.upsert_submitted(&erc20(2)),
            Ok(ActivityMutation::Changed)
        );
        store
    }

    fn assert_nonce_slot_blocked(store: &ActivityStore, identity: &TransactionIdentity) {
        let conflict = native_in_slot(
            [0xee; 32],
            *identity.sender(),
            identity.account_index(),
            *identity.nonce(),
        );
        assert_eq!(
            store.ensure_nonce_available(
                identity.account_index(),
                identity.sender(),
                identity.nonce()
            ),
            Err(ActivityStoreError::NonceConflict)
        );
        assert_eq!(
            store.can_upsert(&conflict),
            Err(ActivityStoreError::NonceConflict)
        );
    }

    fn authenticate_payload(
        payload: &[u8],
        vault_id: [u8; 16],
        generation: u64,
        key: &[u8; 32],
        nonce: [u8; 24],
    ) -> Vec<u8> {
        let header = encode_header(vault_id, generation, nonce);
        let ciphertext = XChaCha20Poly1305::new(Key::from_slice(key))
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: payload,
                    aad: &header,
                },
            )
            .expect("authenticate test payload");
        let mut file = header.to_vec();
        file.extend_from_slice(&ciphertext);
        file
    }

    #[test]
    fn fixed_file_round_trip_binds_vault_key_and_metadata() {
        let store = populated_store();
        let key = [0x22; 32];
        let bytes = store
            .seal_with_nonce(&key, [0x55; 24])
            .expect("seal activity store");
        assert_eq!(bytes.len(), ACTIVITY_FILE_BYTES);
        assert_eq!(ACTIVITY_FILE_BYTES, 26_768);
        assert_eq!(PAYLOAD_BYTES, 26_672);
        assert_eq!(RECORD_BYTES, 416);

        let opened = ActivityStore::open(&bytes, &key, &[0x11; 16]).expect("open store");
        assert_eq!(opened.generation(), 2);
        assert_eq!(opened.entries().len(), 2);
        assert_eq!(opened.entries()[0].submission_sequence(), 1);
        assert_eq!(opened.entries()[1].submission_sequence(), 2);
        assert_eq!(opened.entries()[0].identity(), &native(1));
        assert_eq!(opened.entries()[1].identity(), &erc20(2));
        assert_eq!(format!("{opened:?}"), "ActivityStore([REDACTED])");
    }

    #[test]
    fn production_random_nonce_seal_round_trips() {
        let store = populated_store();
        let key = [0x22; 32];
        let first = store.seal(&key).expect("randomized seal one");
        let second = store.seal(&key).expect("randomized seal two");
        assert_ne!(first, second);
        assert_eq!(
            ActivityStore::open(&first, &key, &[0x11; 16])
                .expect("open randomized store")
                .entries()
                .len(),
            2
        );
    }

    #[test]
    fn tamper_wrong_key_vault_chain_nonce_and_lengths_fail_closed() {
        let store = populated_store();
        let key = [0x22; 32];
        let bytes = store
            .seal_with_nonce(&key, [0x55; 24])
            .expect("seal activity store");
        assert!(ActivityStore::open(&bytes, &[0x23; 32], &[0x11; 16]).is_err());
        assert!(ActivityStore::open(&bytes, &key, &[0x12; 16]).is_err());
        for offset in [
            0_usize,
            16,
            24,
            32,
            48,
            72,
            76,
            78,
            HEADER_BYTES,
            bytes.len() - 1,
        ] {
            let mut mutated = bytes.clone();
            mutated[offset] ^= 1;
            assert!(ActivityStore::open(&mutated, &key, &[0x11; 16]).is_err());
        }
        let mut zero_nonce = bytes.clone();
        zero_nonce[48..72].fill(0);
        assert!(ActivityStore::open(&zero_nonce, &key, &[0x11; 16]).is_err());
        for length in [0, HEADER_BYTES, ACTIVITY_FILE_BYTES - 1] {
            assert!(ActivityStore::open(&bytes[..length], &key, &[0x11; 16]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(ActivityStore::open(&trailing, &key, &[0x11; 16]).is_err());
    }

    #[test]
    fn payload_rejects_magic_version_tags_reserved_unused_capacity_generation_and_chain() {
        let store = populated_store();
        let payload = encode_payload([0x11; 16], store.generation(), store.entries())
            .expect("encode canonical payload");
        for offset in [0_usize, 8, 12, 14, 16, 24, 40] {
            let mut corrupt = payload.clone();
            corrupt[offset] ^= 1;
            assert!(decode_payload(&corrupt, &[0x11; 16], store.generation()).is_err());
        }
        let mut bad_kind = payload.clone();
        bad_kind[record_range(0).start + 53] = 0xff;
        assert!(decode_payload(&bad_kind, &[0x11; 16], store.generation()).is_err());
        let mut bad_status = payload.clone();
        bad_status[record_range(0).start + 54] = 0xff;
        assert!(decode_payload(&bad_status, &[0x11; 16], store.generation()).is_err());
        let mut bad_outcome = payload.clone();
        bad_outcome[record_range(0).start + 55] = 0xff;
        assert!(decode_payload(&bad_outcome, &[0x11; 16], store.generation()).is_err());
        let mut bad_record_reserved = payload.clone();
        bad_record_reserved[record_range(0).start + 282] = 1;
        assert!(decode_payload(&bad_record_reserved, &[0x11; 16], store.generation()).is_err());
        let mut bad_unused = payload.clone();
        bad_unused[record_range(2).start] = 1;
        assert!(decode_payload(&bad_unused, &[0x11; 16], store.generation()).is_err());
        let mut duplicate_nonce_slot = payload.clone();
        let second = record_range(1).start;
        duplicate_nonce_slot[second + 32..second + 52].fill(0x12);
        duplicate_nonce_slot[second + 52] = 1;
        duplicate_nonce_slot[second + 64..second + 96].copy_from_slice(&word(1));
        assert!(decode_payload(&duplicate_nonce_slot, &[0x11; 16], store.generation()).is_err());
        let mut too_many = payload.clone();
        too_many[10..12].copy_from_slice(&65_u16.to_be_bytes());
        assert!(decode_payload(&too_many, &[0x11; 16], store.generation()).is_err());
        let mut trailing = payload;
        trailing.push(0);
        assert!(decode_payload(&trailing, &[0x11; 16], store.generation()).is_err());
    }

    #[test]
    fn authenticated_codec_rejects_unreachable_status_provenance() {
        let vault_id = [0x11; 16];
        let key = [0x22; 32];
        let mut store = ActivityStore::empty(vault_id).expect("empty store");
        let identity = native(1);
        let hash = *identity.transaction_hash();
        store.upsert_submitted(&identity).expect("submitted");

        let mut submitted_payload = encode_payload(vault_id, store.generation(), store.entries())
            .expect("submitted payload");
        let record = record_range(0).start;
        put_u32(&mut submitted_payload, record + 372, 2);
        put_u32(&mut submitted_payload, record + 376, 1);
        put_u16(&mut submitted_payload, record + 380, 1);
        put_u64(&mut submitted_payload, record + 384, 100);
        put_u64(&mut submitted_payload, record + 392, 100);
        let submitted_file = authenticate_payload(
            &submitted_payload,
            vault_id,
            store.generation(),
            &key,
            [0x50; 24],
        );
        assert!(matches!(
            ActivityStore::open(&submitted_file, &key, &vault_id),
            Err(ActivityStoreError::InvalidRecord)
        ));

        let pending_counts = ObservationCounters::initial()
            .record_present(100)
            .expect("pending present");
        store
            .transition(&hash, ActivityStatus::Pending, pending_counts)
            .expect("pending");
        let mut pending_payload =
            encode_payload(vault_id, store.generation(), store.entries()).expect("pending payload");
        put_u32(&mut pending_payload, record + 376, 1);
        put_u16(&mut pending_payload, record + 380, 1);
        put_u64(&mut pending_payload, record + 384, 100);
        let pending_file = authenticate_payload(
            &pending_payload,
            vault_id,
            store.generation(),
            &key,
            [0x51; 24],
        );
        assert!(matches!(
            ActivityStore::open(&pending_file, &key, &vault_id),
            Err(ActivityStoreError::InvalidRecord)
        ));

        let inclusion = Inclusion::new(InclusionOutcome::Success, 100, [0xaa; 32], 101, [0xbb; 32])
            .expect("included evidence");
        let included_counts = pending_counts
            .record_present(101)
            .expect("included present");
        store
            .transition(&hash, ActivityStatus::Included(inclusion), included_counts)
            .expect("included");
        let mut included_payload = encode_payload(vault_id, store.generation(), store.entries())
            .expect("included payload");
        put_u32(&mut included_payload, record + 376, 2);
        put_u16(&mut included_payload, record + 380, 1);
        put_u64(&mut included_payload, record + 384, 101);
        let included_file = authenticate_payload(
            &included_payload,
            vault_id,
            store.generation(),
            &key,
            [0x52; 24],
        );
        assert!(matches!(
            ActivityStore::open(&included_file, &key, &vault_id),
            Err(ActivityStoreError::InvalidRecord)
        ));

        let reorged_counts = included_counts.record_missing(102).expect("reorg missing");
        store
            .transition(&hash, ActivityStatus::Reorged(inclusion), reorged_counts)
            .expect("reorged");
        let mut reorged_payload =
            encode_payload(vault_id, store.generation(), store.entries()).expect("reorged payload");
        let mut premature_reorg = reorged_payload.clone();
        put_u64(&mut premature_reorg, record + 384, 100);
        put_u64(&mut premature_reorg, record + 392, 100);
        let premature_reorg_file = authenticate_payload(
            &premature_reorg,
            vault_id,
            store.generation(),
            &key,
            [0x53; 24],
        );
        assert!(matches!(
            ActivityStore::open(&premature_reorg_file, &key, &vault_id),
            Err(ActivityStoreError::InvalidRecord)
        ));

        put_u32(&mut reorged_payload, record + 376, 3);
        let reorged_file = authenticate_payload(
            &reorged_payload,
            vault_id,
            store.generation(),
            &key,
            [0x54; 24],
        );
        assert!(matches!(
            ActivityStore::open(&reorged_file, &key, &vault_id),
            Err(ActivityStoreError::InvalidRecord)
        ));
    }

    #[test]
    fn immutable_upsert_is_idempotent_conflict_detecting_and_never_evicts() {
        let mut store = ActivityStore::empty([0x11; 16]).expect("empty store");
        let first = native(1);
        assert_eq!(
            store.can_upsert(&first),
            Ok(ActivityUpsertDisposition::Available)
        );
        assert_eq!(
            store.ensure_nonce_available(first.account_index(), first.sender(), first.nonce()),
            Ok(())
        );
        assert_eq!(
            store.upsert_submitted(&first),
            Ok(ActivityMutation::Changed)
        );
        assert_eq!(
            store.can_upsert(&first),
            Ok(ActivityUpsertDisposition::Same)
        );
        assert_eq!(
            store.ensure_nonce_available(first.account_index(), first.sender(), first.nonce()),
            Err(ActivityStoreError::NonceConflict)
        );
        assert_eq!(
            store.upsert_submitted(&first),
            Ok(ActivityMutation::Unchanged)
        );
        assert_eq!(store.generation(), 1);
        let conflict = TransactionIdentity::native(
            *first.transaction_hash(),
            *first.sender(),
            first.account_index(),
            *first.nonce(),
            *first.gas_limit(),
            *first.max_priority_fee_per_gas(),
            *first.max_fee_per_gas(),
            [0x66; 20],
            word(999),
        )
        .expect("valid conflicting identity");
        assert_eq!(
            store.upsert_submitted(&conflict),
            Err(ActivityStoreError::IdentityConflict)
        );
        let nonce_conflict = native_in_slot(
            [0x99; 32],
            *first.sender(),
            first.account_index(),
            *first.nonce(),
        );
        assert_eq!(
            store.can_upsert(&nonce_conflict),
            Err(ActivityStoreError::NonceConflict)
        );
        assert_eq!(
            store.upsert_submitted(&nonce_conflict),
            Err(ActivityStoreError::NonceConflict)
        );
        for marker in 2..=ACTIVITY_CAPACITY as u8 {
            store
                .upsert_submitted(&native(marker))
                .expect("fill exact capacity");
        }
        assert_eq!(store.entries().len(), ACTIVITY_CAPACITY);
        assert_eq!(store.can_upsert(&native(65)), Err(ActivityStoreError::Full));
        assert_eq!(
            store.upsert_submitted(&native(65)),
            Err(ActivityStoreError::Full)
        );
        assert_eq!(store.entries()[0].identity(), &first);
    }

    #[test]
    fn present_resets_missing_streak_and_dropped_threshold_is_core_enforced() {
        let initial = ObservationCounters::initial();
        let first = initial.record_missing(100).expect("first miss");
        let second = first.record_missing(132).expect("second miss");
        let third_too_early = second.record_missing(163).expect("third miss");
        assert!(!third_too_early.dropped_candidate_ready());
        let fourth = third_too_early.record_missing(164).expect("fourth miss");
        assert!(fourth.dropped_candidate_ready());
        assert_eq!(fourth.first_missing_head(), Some(100));
        let present = fourth.record_present(165).expect("present observation");
        assert_eq!(present.consecutive_missing(), 0);
        assert_eq!(present.first_missing_head(), None);
        assert_eq!(present.total_misses(), 4);
        assert_eq!(present.total_observations(), 5);
    }

    #[test]
    fn missing_observations_retain_submitted_pending_and_included_labels() {
        let mut store = ActivityStore::empty([0x11; 16]).expect("empty store");
        let identity = native(1);
        let hash = *identity.transaction_hash();
        store.upsert_submitted(&identity).expect("submitted");

        let submitted_present = ObservationCounters::initial()
            .record_present(100)
            .expect("submitted present");
        assert_eq!(
            store.transition(&hash, ActivityStatus::Submitted, submitted_present),
            Err(ActivityStoreError::InvalidTransition)
        );
        let submitted_missing = ObservationCounters::initial()
            .record_missing(100)
            .expect("submitted missing");
        assert_eq!(
            store.transition(&hash, ActivityStatus::Pending, submitted_missing),
            Err(ActivityStoreError::InvalidTransition)
        );
        store
            .transition(&hash, ActivityStatus::Submitted, submitted_missing)
            .expect("retain submitted label");

        let pending_present = submitted_missing
            .record_present(101)
            .expect("transaction appeared");
        store
            .transition(&hash, ActivityStatus::Pending, pending_present)
            .expect("pending after presence");
        let pending_missing = pending_present
            .record_missing(102)
            .expect("pending missing");
        store
            .transition(&hash, ActivityStatus::Pending, pending_missing)
            .expect("retain pending label");

        let inclusion = Inclusion::new(InclusionOutcome::Success, 100, [0xaa; 32], 103, [0xbb; 32])
            .expect("included evidence");
        let included_present = pending_missing
            .record_present(103)
            .expect("included present");
        store
            .transition(&hash, ActivityStatus::Included(inclusion), included_present)
            .expect("included");
        let premature_reorg = ObservationCounters {
            total_observations: included_present.total_observations + 1,
            total_misses: included_present.total_misses + 1,
            consecutive_missing: 1,
            first_missing_head: Some(100),
            last_observed_head: Some(100),
        };
        assert_eq!(
            store.transition(&hash, ActivityStatus::Reorged(inclusion), premature_reorg,),
            Err(ActivityStoreError::InvalidTransition)
        );
        let included_missing = included_present
            .record_missing(104)
            .expect("included missing");
        store
            .transition(&hash, ActivityStatus::Included(inclusion), included_missing)
            .expect("retain included label");

        let changed_evidence =
            Inclusion::new(InclusionOutcome::Success, 100, [0xaa; 32], 104, [0xcc; 32])
                .expect("changed observation evidence");
        let another_missing = included_missing
            .record_missing(105)
            .expect("another included miss");
        assert_eq!(
            store.transition(
                &hash,
                ActivityStatus::Included(changed_evidence),
                another_missing,
            ),
            Err(ActivityStoreError::InvalidTransition)
        );

        let bytes = store
            .seal_with_nonce(&[0x22; 32], [0x55; 24])
            .expect("seal labels with missing streaks");
        let opened = ActivityStore::open(&bytes, &[0x22; 32], &[0x11; 16])
            .expect("open labels with missing streaks");
        assert_eq!(
            opened.entries()[0].status(),
            ActivityStatus::Included(inclusion)
        );
        assert_eq!(opened.entries()[0].observations(), included_missing);

        let reappeared = included_missing
            .record_present(105)
            .expect("included reappeared");
        let refreshed = Inclusion::new(InclusionOutcome::Success, 100, [0xaa; 32], 105, [0xdd; 32])
            .expect("refreshed inclusion evidence");
        store
            .transition(&hash, ActivityStatus::Included(refreshed), reappeared)
            .expect("refresh included evidence on presence");
    }

    #[test]
    fn nonce_slot_is_unique_in_every_status_but_scoped_by_account_and_sender() {
        let mut store = ActivityStore::empty([0x11; 16]).expect("empty store");
        let identity = native(1);
        let hash = *identity.transaction_hash();
        store.upsert_submitted(&identity).expect("submitted");
        assert_nonce_slot_blocked(&store, &identity);

        let different_sender = native_in_slot(
            [0xf1; 32],
            [0x44; 20],
            identity.account_index(),
            *identity.nonce(),
        );
        assert_eq!(
            store.can_upsert(&different_sender),
            Ok(ActivityUpsertDisposition::Available)
        );
        store
            .upsert_submitted(&different_sender)
            .expect("same nonce with different sender");
        let different_account = native_in_slot(
            [0xf2; 32],
            *identity.sender(),
            identity.account_index() ^ 1,
            *identity.nonce(),
        );
        assert_eq!(
            store.can_upsert(&different_account),
            Ok(ActivityUpsertDisposition::Available)
        );
        store
            .upsert_submitted(&different_account)
            .expect("same sender nonce with different account");

        let pending = ObservationCounters::initial()
            .record_present(100)
            .expect("pending observation");
        store
            .transition(&hash, ActivityStatus::Pending, pending)
            .expect("pending");
        assert_nonce_slot_blocked(&store, &identity);

        let inclusion = Inclusion::new(InclusionOutcome::Success, 100, [0xaa; 32], 101, [0xbb; 32])
            .expect("included evidence");
        let included = pending.record_present(101).expect("included observation");
        store
            .transition(&hash, ActivityStatus::Included(inclusion), included)
            .expect("included");
        assert_nonce_slot_blocked(&store, &identity);

        let first_missing = included.record_missing(102).expect("reorg observation");
        store
            .transition(&hash, ActivityStatus::Reorged(inclusion), first_missing)
            .expect("reorged");
        assert_nonce_slot_blocked(&store, &identity);

        let second_missing = first_missing
            .record_missing(133)
            .expect("replacement observation");
        store
            .transition(&hash, ActivityStatus::ReplacementSuspected, second_missing)
            .expect("replacement suspected");
        assert_nonce_slot_blocked(&store, &identity);

        let third_missing = second_missing
            .record_missing(166)
            .expect("dropped observation");
        store
            .transition(&hash, ActivityStatus::DroppedCandidate, third_missing)
            .expect("dropped candidate");
        assert_nonce_slot_blocked(&store, &identity);
    }

    #[test]
    fn suspect_states_recover_to_pending_only_on_a_present_observation() {
        for target in [
            ActivityStatus::ReplacementSuspected,
            ActivityStatus::DroppedCandidate,
        ] {
            let mut store = ActivityStore::empty([0x11; 16]).expect("empty store");
            let identity = native(1);
            let hash = *identity.transaction_hash();
            store.upsert_submitted(&identity).expect("submitted");
            let first = ObservationCounters::initial()
                .record_missing(100)
                .expect("first missing");
            store
                .transition(&hash, ActivityStatus::ReplacementSuspected, first)
                .expect("replacement suspected");
            let current = if target == ActivityStatus::DroppedCandidate {
                let second = first.record_missing(132).expect("second missing");
                store
                    .transition(&hash, ActivityStatus::ReplacementSuspected, second)
                    .expect("replacement still suspected");
                let third = second.record_missing(164).expect("third missing");
                store
                    .transition(&hash, ActivityStatus::DroppedCandidate, third)
                    .expect("dropped candidate");
                third
            } else {
                first
            };
            let missing = current.record_missing(165).expect("another missing");
            assert_eq!(
                store.transition(&hash, ActivityStatus::Pending, missing),
                Err(ActivityStoreError::InvalidTransition)
            );
            let present = current.record_present(165).expect("reappeared");
            assert_eq!(
                store.transition(&hash, ActivityStatus::Pending, present),
                Ok(ActivityMutation::Changed)
            );
        }

        let mut store = ActivityStore::empty([0x11; 16]).expect("empty store");
        let identity = native(1);
        let hash = *identity.transaction_hash();
        store.upsert_submitted(&identity).expect("submitted");
        let pending = ObservationCounters::initial()
            .record_present(100)
            .expect("pending");
        store
            .transition(&hash, ActivityStatus::Pending, pending)
            .expect("pending");
        let inclusion = Inclusion::new(InclusionOutcome::Success, 100, [0xaa; 32], 101, [0xbb; 32])
            .expect("included evidence");
        let included = pending.record_present(101).expect("included");
        store
            .transition(&hash, ActivityStatus::Included(inclusion), included)
            .expect("included");
        let reorged = included.record_missing(102).expect("reorged");
        store
            .transition(&hash, ActivityStatus::Reorged(inclusion), reorged)
            .expect("reorged");
        let still_missing = reorged.record_missing(103).expect("still missing");
        assert_eq!(
            store.transition(&hash, ActivityStatus::Pending, still_missing),
            Err(ActivityStoreError::InvalidTransition)
        );
        let present = reorged.record_present(103).expect("reappeared");
        assert_eq!(
            store.transition(&hash, ActivityStatus::Pending, present),
            Ok(ActivityMutation::Changed)
        );
    }

    #[test]
    fn status_transition_round_trip_covers_success_revert_reorg_and_suspects() {
        let mut store = ActivityStore::empty([0x11; 16]).expect("empty store");
        let identity = native(1);
        let hash = *identity.transaction_hash();
        store.upsert_submitted(&identity).expect("upsert");
        let pending_counts = ObservationCounters::initial()
            .record_present(100)
            .expect("pending observation");
        assert_eq!(
            store.transition(&hash, ActivityStatus::Pending, pending_counts),
            Ok(ActivityMutation::Changed)
        );
        assert_eq!(
            store.transition(&hash, ActivityStatus::Pending, pending_counts),
            Ok(ActivityMutation::Unchanged)
        );
        let inclusion = Inclusion::new(InclusionOutcome::Success, 100, [0xaa; 32], 101, [0xbb; 32])
            .expect("valid inclusion");
        assert_eq!(inclusion.depth(), 2);
        let included_counts = pending_counts.record_present(101).expect("receipt");
        store
            .transition(&hash, ActivityStatus::Included(inclusion), included_counts)
            .expect("included");
        let missing = included_counts.record_missing(102).expect("reorg miss");
        store
            .transition(&hash, ActivityStatus::Reorged(inclusion), missing)
            .expect("reorged");
        let pending_again = missing.record_present(103).expect("reappeared");
        store
            .transition(&hash, ActivityStatus::Pending, pending_again)
            .expect("pending again");
        let reverted = Inclusion::new(InclusionOutcome::Revert, 103, [0xcc; 32], 103, [0xdd; 32])
            .expect("valid reverted inclusion");
        let reverted_counts = pending_again.record_present(103).expect("revert receipt");
        store
            .transition(&hash, ActivityStatus::Included(reverted), reverted_counts)
            .expect("reverted inclusion");

        let key = [0x22; 32];
        let bytes = store
            .seal_with_nonce(&key, [0x55; 24])
            .expect("seal transitioned store");
        let opened = ActivityStore::open(&bytes, &key, &[0x11; 16]).expect("reopen");
        assert_eq!(
            opened.entries()[0].status(),
            ActivityStatus::Included(reverted)
        );
        assert_eq!(opened.entries()[0].observations(), reverted_counts);
    }

    #[test]
    fn dropped_and_replacement_suspects_are_nonterminal() {
        let mut store = ActivityStore::empty([0x11; 16]).expect("empty store");
        let identity = native(1);
        let hash = *identity.transaction_hash();
        store.upsert_submitted(&identity).expect("upsert");
        let first = ObservationCounters::initial()
            .record_missing(100)
            .expect("first miss");
        assert_eq!(
            store.transition(&hash, ActivityStatus::DroppedCandidate, first),
            Err(ActivityStoreError::InvalidTransition)
        );
        store
            .transition(&hash, ActivityStatus::ReplacementSuspected, first)
            .expect("replacement candidate");
        let second = first.record_missing(132).expect("second miss");
        store
            .transition(&hash, ActivityStatus::ReplacementSuspected, second)
            .expect("same suspect");
        let third = second.record_missing(164).expect("third miss");
        store
            .transition(&hash, ActivityStatus::DroppedCandidate, third)
            .expect("dropped candidate");
        let present = third.record_present(165).expect("reappeared");
        store
            .transition(&hash, ActivityStatus::Pending, present)
            .expect("candidate is nonterminal");
    }

    #[test]
    fn every_status_tag_survives_authenticated_round_trip() {
        let mut store = ActivityStore::empty([0x11; 16]).expect("empty store");
        for marker in 1..=6 {
            store
                .upsert_submitted(&native(marker))
                .expect("insert identity");
        }

        let pending = ObservationCounters::initial()
            .record_present(100)
            .expect("pending");
        store
            .transition(&[2; 32], ActivityStatus::Pending, pending)
            .expect("pending status");

        let included = Inclusion::new(InclusionOutcome::Success, 100, [0xa3; 32], 101, [0xb3; 32])
            .expect("included evidence");
        let included_counts = ObservationCounters::initial()
            .record_present(101)
            .expect("included observation");
        store
            .transition(
                &[3; 32],
                ActivityStatus::Included(included),
                included_counts,
            )
            .expect("included status");

        let former = Inclusion::new(InclusionOutcome::Revert, 100, [0xa4; 32], 101, [0xb4; 32])
            .expect("former inclusion");
        let former_counts = ObservationCounters::initial()
            .record_present(101)
            .expect("former observation");
        store
            .transition(&[4; 32], ActivityStatus::Included(former), former_counts)
            .expect("included before reorg");
        let reorg_counts = former_counts.record_missing(102).expect("reorg miss");
        store
            .transition(&[4; 32], ActivityStatus::Reorged(former), reorg_counts)
            .expect("reorged status");

        let mut dropped_counts = ObservationCounters::initial();
        for head in [100, 132] {
            dropped_counts = dropped_counts.record_missing(head).expect("candidate miss");
            store
                .transition(&[5; 32], ActivityStatus::Submitted, dropped_counts)
                .expect("submitted while missing");
        }
        dropped_counts = dropped_counts.record_missing(164).expect("third miss");
        store
            .transition(&[5; 32], ActivityStatus::DroppedCandidate, dropped_counts)
            .expect("dropped candidate status");

        let replacement_counts = ObservationCounters::initial()
            .record_missing(100)
            .expect("replacement miss");
        store
            .transition(
                &[6; 32],
                ActivityStatus::ReplacementSuspected,
                replacement_counts,
            )
            .expect("replacement status");

        let key = [0x22; 32];
        let bytes = store
            .seal_with_nonce(&key, [0x55; 24])
            .expect("seal all statuses");
        let opened = ActivityStore::open(&bytes, &key, &[0x11; 16]).expect("reopen statuses");
        assert_eq!(opened.entries()[0].status(), ActivityStatus::Submitted);
        assert_eq!(opened.entries()[1].status(), ActivityStatus::Pending);
        assert_eq!(
            opened.entries()[2].status(),
            ActivityStatus::Included(included)
        );
        assert_eq!(
            opened.entries()[3].status(),
            ActivityStatus::Reorged(former)
        );
        assert_eq!(
            opened.entries()[4].status(),
            ActivityStatus::DroppedCandidate
        );
        assert_eq!(
            opened.entries()[5].status(),
            ActivityStatus::ReplacementSuspected
        );
    }

    #[test]
    fn inclusion_and_observation_bounds_are_strict() {
        assert!(Inclusion::new(InclusionOutcome::Success, 101, [1; 32], 100, [2; 32]).is_err());
        assert!(Inclusion::new(InclusionOutcome::Success, 1, [0; 32], 1, [2; 32]).is_err());
        assert!(Inclusion::new(InclusionOutcome::Success, 1, [1; 32], 1, [0; 32]).is_err());
        let at_total_limit = ObservationCounters {
            total_observations: MAX_TOTAL_OBSERVATIONS,
            total_misses: 0,
            consecutive_missing: 0,
            first_missing_head: None,
            last_observed_head: Some(1),
        };
        assert_eq!(
            at_total_limit.record_present(2),
            Err(ActivityStoreError::ObservationLimit)
        );
        let at_streak_limit = ObservationCounters {
            total_observations: u32::from(MAX_CONSECUTIVE_MISSING),
            total_misses: u32::from(MAX_CONSECUTIVE_MISSING),
            consecutive_missing: MAX_CONSECUTIVE_MISSING,
            first_missing_head: Some(1),
            last_observed_head: Some(1),
        };
        assert_eq!(
            at_streak_limit.record_missing(2),
            Err(ActivityStoreError::ObservationLimit)
        );

        let high_water = ObservationCounters::initial()
            .record_present(100)
            .expect("establish high-water head");
        assert_eq!(
            high_water.record_present(99),
            Err(ActivityStoreError::InvalidInput)
        );
        assert_eq!(
            high_water.record_missing(99),
            Err(ActivityStoreError::InvalidInput)
        );
        let same_head = high_water
            .record_missing(100)
            .expect("same head remains observable");
        assert_eq!(same_head.last_observed_head(), Some(100));
        let resumed = same_head
            .record_present(101)
            .expect("higher head resumes observations");
        assert_eq!(resumed.last_observed_head(), Some(101));
        assert_eq!(resumed.total_observations(), 3);
    }

    #[test]
    fn identity_tags_symbols_and_debug_are_strict_and_redacted() {
        for invalid in [
            Some(String::new()),
            Some("TO K".to_owned()),
            Some("X".repeat(17)),
        ] {
            assert!(
                TransactionIdentity::erc20(
                    [1; 32],
                    [2; 20],
                    0,
                    word(1),
                    word(50_000),
                    word(1),
                    word(2),
                    [3; 20],
                    [4; 20],
                    word(5),
                    18,
                    invalid,
                )
                .is_err()
            );
        }
        assert!(
            TransactionIdentity::native(
                [1; 32],
                [2; 20],
                2,
                word(1),
                word(21_000),
                word(1),
                word(2),
                [3; 20],
                word(4)
            )
            .is_err()
        );
        let identity = erc20(1);
        assert_eq!(format!("{identity:?}"), "TransactionIdentity([REDACTED])");
        assert_eq!(format!("{:?}", identity.transfer()), "Transfer([REDACTED])");
        assert!(matches!(identity.transfer(), Transfer::SavedErc20 { .. }));
    }

    #[test]
    fn generation_overflow_and_empty_or_zero_nonce_seal_fail_before_mutation() {
        let key = [0x22; 32];
        let empty = ActivityStore::empty([0x11; 16]).expect("empty store");
        assert_eq!(
            empty.seal_with_nonce(&key, [0x55; 24]),
            Err(ActivityStoreError::InvalidInput)
        );
        let mut store = populated_store();
        assert_eq!(
            store.seal_with_nonce(&key, [0; 24]),
            Err(ActivityStoreError::InvalidInput)
        );
        store.generation = u64::MAX;
        let before = store.entries().len();
        assert_eq!(
            store.upsert_submitted(&native(3)),
            Err(ActivityStoreError::GenerationOverflow)
        );
        assert_eq!(store.entries().len(), before);
    }
}
