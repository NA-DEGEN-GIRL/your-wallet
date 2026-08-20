use core::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{
    AccountIndex, DerivationPath, DerivedAccount, EthereumAddress, MnemonicEntropy, RawPrivateKey,
    SecretError, SessionPassphrase, VaultOpenError, VaultPassword,
};

const VAULT_MAGIC: [u8; 8] = *b"YWRVLT01";
const PAYLOAD_MAGIC: [u8; 8] = *b"YWPAY001";
const VAULT_VERSION: u16 = 1;
const BIP39_LANGUAGE_ENGLISH: u8 = 1;
const HEADER_LENGTH: usize = 112;
const HEADER_LENGTH_U16: u16 = 112;
const PAYLOAD_SCHEMA: u16 = 1;
const PASSWORD_PROFILE_ID: u16 = 1;
const KDF_ID_ARGON2ID: u16 = 1;
const AEAD_ID_XCHACHA20_POLY1305: u16 = 1;
const ARGON2_MEMORY_KIB: u32 = 262_144;
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;
const ARGON2_OUTPUT_BYTES: usize = 32;
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;
const AEAD_TAG_LENGTH: usize = 16;
const MAX_CIPHERTEXT_LENGTH: usize = 4 * 1_024 * 1_024;
const MAX_RECORDS: usize = 64;
const MAX_DERIVED_ACCOUNTS: usize = 4_096;
const BACKUP_CHALLENGE_WORDS: usize = 4;
const MAX_BACKUP_WORD_BYTES: usize = 16;
const HKDF_SALT: &[u8] = b"your-wallet/hkdf-sha256/v1";
const VAULT_AEAD_INFO: &[u8] = b"your-wallet/vault-v1/xchacha20poly1305";

/// Backup-confirmation status stored inside the encrypted payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupState {
    /// The user has not completed backup confirmation.
    Unconfirmed,
    /// The user completed the wallet's backup verification flow.
    Confirmed,
}

impl BackupState {
    const fn code(self) -> u8 {
        match self {
            Self::Unconfirmed => 0,
            Self::Confirmed => 1,
        }
    }

    fn from_code(code: u8) -> Result<Self, SecretError> {
        match code {
            0 => Ok(Self::Unconfirmed),
            1 => Ok(Self::Confirmed),
            _ => Err(SecretError::InvalidPayload),
        }
    }
}

/// Persisted public account metadata for a derived mnemonic account.
#[derive(Clone, PartialEq, Eq)]
pub struct DerivedAccountRecord {
    requested_index: AccountIndex,
    actual_path: DerivationPath,
    address: EthereumAddress,
}

impl fmt::Debug for DerivedAccountRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DerivedAccountRecord")
            .field("requested_index", &self.requested_index)
            .field("actual_path", &self.actual_path)
            .field("address", &"[REDACTED]")
            .finish()
    }
}

impl DerivedAccountRecord {
    /// Captures the actual derivation result, including any invalid-child skip.
    #[must_use]
    pub fn from_derived(requested_index: AccountIndex, account: &DerivedAccount) -> Self {
        Self {
            requested_index,
            actual_path: account.path().clone(),
            address: account.address(),
        }
    }

    /// Returns the originally requested index.
    #[must_use]
    pub const fn requested_index(&self) -> AccountIndex {
        self.requested_index
    }

    /// Returns the actual derivation path that must be reused.
    #[must_use]
    pub const fn actual_path(&self) -> &DerivationPath {
        &self.actual_path
    }

    /// Returns the derived account address.
    #[must_use]
    pub const fn address(&self) -> EthereumAddress {
        self.address
    }

    fn validate(&self) -> Result<(), SecretError> {
        let components: [u32; 5] = self
            .actual_path
            .components()
            .try_into()
            .map_err(|_| SecretError::InvalidPayload)?;
        let actual_index = AccountIndex::new(components[4])?;
        let hardened = 1_u32 << 31;
        let valid_shape = components[0] >= (0x002C | hardened)
            && components[1] >= (0x003C | hardened)
            && components[2] & hardened != 0
            && components[3] & hardened == 0;
        if !valid_shape || actual_index < self.requested_index {
            return Err(SecretError::InvalidPayload);
        }
        Ok(())
    }
}

/// Encrypted payload record for a BIP-39 source.
pub struct Bip39Record {
    record_id: [u8; 16],
    created_at_unix: u64,
    backup_state: BackupState,
    passphrase_required: bool,
    entropy: MnemonicEntropy,
    accounts: Vec<DerivedAccountRecord>,
}

impl fmt::Debug for Bip39Record {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Bip39Record")
            .field("record_id", &"[REDACTED]")
            .field("created_at_unix", &self.created_at_unix)
            .field("backup_state", &self.backup_state)
            .field("passphrase_required", &self.passphrase_required)
            .field("entropy", &"[REDACTED]")
            .field("accounts", &self.accounts)
            .finish()
    }
}

impl Bip39Record {
    /// Creates a mnemonic source that is always backup-pending.
    ///
    /// A caller cannot construct a confirmed mnemonic record or mutate its
    /// backup state directly. Confirmation is performed only by
    /// [`VaultPayload::verify_and_confirm_bip39_backup`].
    ///
    /// ```compile_fail
    /// use secret_core::{BackupState, Bip39Record, MnemonicEntropy};
    /// let entropy = MnemonicEntropy::from_entropy(&[0_u8; 16]).unwrap();
    /// let _ = Bip39Record::new(
    ///     [1_u8; 16],
    ///     1,
    ///     BackupState::Confirmed,
    ///     false,
    ///     entropy,
    /// );
    /// ```
    ///
    /// ```compile_fail
    /// use secret_core::{BackupState, Bip39Record, MnemonicEntropy};
    /// let entropy = MnemonicEntropy::from_entropy(&[0_u8; 16]).unwrap();
    /// let mut record = Bip39Record::new_unconfirmed([1_u8; 16], 1, false, entropy);
    /// record.set_backup_state(BackupState::Confirmed);
    /// ```
    #[must_use]
    pub const fn new_unconfirmed(
        record_id: [u8; 16],
        created_at_unix: u64,
        passphrase_required: bool,
        entropy: MnemonicEntropy,
    ) -> Self {
        Self::new_with_state(
            record_id,
            created_at_unix,
            BackupState::Unconfirmed,
            passphrase_required,
            entropy,
        )
    }

    const fn new_with_state(
        record_id: [u8; 16],
        created_at_unix: u64,
        backup_state: BackupState,
        passphrase_required: bool,
        entropy: MnemonicEntropy,
    ) -> Self {
        Self {
            record_id,
            created_at_unix,
            backup_state,
            passphrase_required,
            entropy,
            accounts: Vec::new(),
        }
    }

    /// Adds a derived account record while rejecting duplicates and bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid path shape, duplicate actual path, or a
    /// record beyond the frozen account bound.
    pub fn add_account(&mut self, account: DerivedAccountRecord) -> Result<(), SecretError> {
        account.validate()?;
        if self.accounts.len() >= MAX_DERIVED_ACCOUNTS {
            return Err(SecretError::BoundsExceeded);
        }
        if self
            .accounts
            .iter()
            .any(|existing| existing.actual_path == account.actual_path)
        {
            return Err(SecretError::InvalidPayload);
        }
        self.accounts.push(account);
        Ok(())
    }

    /// Returns the opaque record identifier.
    #[must_use]
    pub const fn record_id(&self) -> &[u8; 16] {
        &self.record_id
    }

    /// Returns creation time in Unix seconds.
    #[must_use]
    pub const fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    /// Returns backup status.
    #[must_use]
    pub const fn backup_state(&self) -> BackupState {
        self.backup_state
    }

    const fn set_backup_state(&mut self, state: BackupState) {
        self.backup_state = state;
    }

    /// Whether unlock requires a non-persisted session passphrase.
    #[must_use]
    pub const fn passphrase_required(&self) -> bool {
        self.passphrase_required
    }

    /// Borrows secret entropy for key-agent-internal derivation.
    #[must_use]
    pub const fn entropy(&self) -> &MnemonicEntropy {
        &self.entropy
    }

    /// Returns persisted derived account metadata.
    #[must_use]
    pub fn accounts(&self) -> &[DerivedAccountRecord] {
        &self.accounts
    }
}

/// Encrypted payload record for a strict raw-key import.
pub struct RawKeyRecord {
    record_id: [u8; 16],
    created_at_unix: u64,
    backup_state: BackupState,
    private_key: RawPrivateKey,
    address: EthereumAddress,
}

impl fmt::Debug for RawKeyRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawKeyRecord")
            .field("record_id", &"[REDACTED]")
            .field("created_at_unix", &self.created_at_unix)
            .field("backup_state", &self.backup_state)
            .field("private_key", &"[REDACTED]")
            .field("address", &self.address)
            .finish()
    }
}

impl RawKeyRecord {
    /// Imports a raw key and binds its derived address.
    ///
    /// # Errors
    ///
    /// Returns an error unless `private_key` is exactly one valid `secp256k1`
    /// scalar and its public address can be derived.
    pub fn import(
        record_id: [u8; 16],
        created_at_unix: u64,
        backup_state: BackupState,
        private_key: &[u8],
    ) -> Result<Self, SecretError> {
        let private_key = RawPrivateKey::import(private_key)?;
        let address = private_key.ethereum_address()?;
        Ok(Self {
            record_id,
            created_at_unix,
            backup_state,
            private_key,
            address,
        })
    }

    /// Returns the opaque record identifier.
    #[must_use]
    pub const fn record_id(&self) -> &[u8; 16] {
        &self.record_id
    }

    /// Returns creation time in Unix seconds.
    #[must_use]
    pub const fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    /// Returns backup status.
    #[must_use]
    pub const fn backup_state(&self) -> BackupState {
        self.backup_state
    }

    /// Returns the corresponding Ethereum address.
    #[must_use]
    pub const fn address(&self) -> EthereumAddress {
        self.address
    }

    /// Borrows the key for key-agent-internal signing.
    #[must_use]
    pub const fn private_key(&self) -> &RawPrivateKey {
        &self.private_key
    }
}

/// A supported secret source in the authenticated payload.
pub enum SecretRecord {
    /// BIP-39 entropy with derived account metadata.
    Bip39(Bip39Record),
    /// Individually imported raw secp256k1 private key.
    RawKey(RawKeyRecord),
}

impl fmt::Debug for SecretRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bip39(record) => formatter.debug_tuple("Bip39").field(record).finish(),
            Self::RawKey(record) => formatter.debug_tuple("RawKey").field(record).finish(),
        }
    }
}

/// Version-one authenticated vault payload.
pub struct VaultPayload {
    records: Vec<SecretRecord>,
}

impl fmt::Debug for VaultPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultPayload")
            .field("records", &self.records)
            .finish()
    }
}

impl VaultPayload {
    /// Creates an empty payload.
    #[must_use]
    pub fn new() -> Self {
        Self {
            // A raw-key record owns inline zeroizing material. Reserving the
            // complete frozen bound up front prevents Vec growth from copying
            // an element into a new allocation and leaving the old heap bytes
            // outside the final drop-time zeroization pass.
            records: Vec::with_capacity(MAX_RECORDS),
        }
    }

    /// Adds a bounded secret record.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero/duplicate record ID or a record beyond the
    /// frozen payload bound.
    pub fn push(&mut self, record: SecretRecord) -> Result<(), SecretError> {
        if self.records.len() >= MAX_RECORDS || self.records.capacity() < MAX_RECORDS {
            return Err(SecretError::BoundsExceeded);
        }
        let initial_capacity = self.records.capacity();
        let id = record_id(&record);
        if id == &[0_u8; 16]
            || self
                .records
                .iter()
                .any(|existing| record_id(existing) == id)
        {
            return Err(SecretError::InvalidPayload);
        }
        self.records.push(record);
        if self.records.capacity() != initial_capacity {
            return Err(SecretError::CryptographicFailure);
        }
        Ok(())
    }

    /// Returns authenticated secret records.
    #[must_use]
    pub fn records(&self) -> &[SecretRecord] {
        &self.records
    }

    /// Verifies recovery answers and advances one exact mnemonic record from
    /// backup-pending to confirmed.
    ///
    /// The operation accepts exactly four distinct, increasing, one-based word
    /// positions. It verifies every answer in constant time, checks the first
    /// address entered by the user, and re-derives the two managed accounts
    /// from the authenticated entropy before changing state. The current
    /// lifecycle rejects passphrase-dependent and non-12/24-word records.
    ///
    /// # Errors
    ///
    /// Returns [`SecretError::InvalidPayload`] unless all recovery answers and
    /// authenticated record invariants match exactly. Raw-key records, unknown
    /// IDs, replayed confirmation attempts, malformed challenges, missing or
    /// altered accounts, and passphrase-dependent records fail closed.
    pub fn verify_and_confirm_bip39_backup(
        &mut self,
        target_record_id: [u8; 16],
        positions: [u8; BACKUP_CHALLENGE_WORDS],
        answers: &[String],
        confirmed_first_address: EthereumAddress,
    ) -> Result<(), SecretError> {
        if target_record_id == [0_u8; 16] {
            return Err(SecretError::InvalidPayload);
        }
        let mut matched_index = None;
        for (index, record) in self.records.iter().enumerate() {
            if record_id(record) != &target_record_id {
                continue;
            }
            if matched_index.replace(index).is_some() {
                return Err(SecretError::InvalidPayload);
            }
        }
        let record = self
            .records
            .get_mut(matched_index.ok_or(SecretError::InvalidPayload)?)
            .ok_or(SecretError::InvalidPayload)?;
        match record {
            SecretRecord::Bip39(bip39) if bip39.backup_state() == BackupState::Unconfirmed => {
                verify_bip39_backup_confirmation(
                    bip39,
                    positions,
                    answers,
                    confirmed_first_address,
                )?;
                bip39.set_backup_state(BackupState::Confirmed);
                Ok(())
            }
            SecretRecord::Bip39(_) | SecretRecord::RawKey(_) => Err(SecretError::InvalidPayload),
        }
    }

    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        if self.records.len() > MAX_RECORDS {
            return Err(SecretError::BoundsExceeded);
        }
        let record_count =
            u16::try_from(self.records.len()).map_err(|_| SecretError::BoundsExceeded)?;
        let encoded_length = encoded_payload_length(&self.records)?;
        if encoded_length
            .checked_add(AEAD_TAG_LENGTH)
            .ok_or(SecretError::BoundsExceeded)?
            > MAX_CIPHERTEXT_LENGTH
        {
            return Err(SecretError::BoundsExceeded);
        }
        let mut output = Zeroizing::new(Vec::with_capacity(encoded_length));
        let initial_capacity = output.capacity();
        output.extend_from_slice(&PAYLOAD_MAGIC);
        output.extend_from_slice(&record_count.to_be_bytes());
        output.extend_from_slice(&[0_u8; 6]);
        for record in &self.records {
            encode_record(&mut output, record)?;
        }
        if output.len() != encoded_length || output.capacity() != initial_capacity {
            return Err(SecretError::CryptographicFailure);
        }
        Ok(output)
    }

    fn decode(bytes: &[u8]) -> Result<Self, SecretError> {
        let mut cursor = Cursor::new(bytes);
        if cursor.read_array::<8>()? != PAYLOAD_MAGIC {
            return Err(SecretError::InvalidPayload);
        }
        let record_count = usize::from(cursor.read_u16()?);
        if record_count > MAX_RECORDS || cursor.read_array::<6>()? != [0_u8; 6] {
            return Err(SecretError::InvalidPayload);
        }
        let mut payload = Self::new();
        for _ in 0..record_count {
            payload.push(decode_record(&mut cursor)?)?;
        }
        if !cursor.is_finished() {
            return Err(SecretError::InvalidPayload);
        }
        Ok(payload)
    }
}

impl Default for VaultPayload {
    fn default() -> Self {
        Self::new()
    }
}

/// Parsed fixed-size vault header. All integer fields are big-endian on disk.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VaultHeader {
    vault_id: [u8; 16],
    generation: u64,
    salt: [u8; SALT_LENGTH],
    nonce: [u8; NONCE_LENGTH],
    ciphertext_length: u32,
}

impl fmt::Debug for VaultHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultHeader")
            .field("vault_id", &"[REDACTED]")
            .field("generation", &self.generation)
            .field("salt", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("ciphertext_length", &self.ciphertext_length)
            .finish()
    }
}

impl VaultHeader {
    /// Returns the random vault identifier.
    #[must_use]
    pub const fn vault_id(&self) -> &[u8; 16] {
        &self.vault_id
    }

    /// Returns the monotonic storage generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the authenticated ciphertext length, including the AEAD tag.
    #[must_use]
    pub const fn ciphertext_length(&self) -> u32 {
        self.ciphertext_length
    }

    fn encode(self) -> [u8; HEADER_LENGTH] {
        let mut bytes = [0_u8; HEADER_LENGTH];
        bytes[0..8].copy_from_slice(&VAULT_MAGIC);
        bytes[8..10].copy_from_slice(&VAULT_VERSION.to_be_bytes());
        bytes[10..12].copy_from_slice(&HEADER_LENGTH_U16.to_be_bytes());
        bytes[12..28].copy_from_slice(&self.vault_id);
        bytes[28..36].copy_from_slice(&self.generation.to_be_bytes());
        bytes[36..38].copy_from_slice(&PASSWORD_PROFILE_ID.to_be_bytes());
        bytes[38..40].copy_from_slice(&KDF_ID_ARGON2ID.to_be_bytes());
        bytes[40..42].copy_from_slice(&AEAD_ID_XCHACHA20_POLY1305.to_be_bytes());
        bytes[42..44].copy_from_slice(&PAYLOAD_SCHEMA.to_be_bytes());
        bytes[44..48].copy_from_slice(&ARGON2_MEMORY_KIB.to_be_bytes());
        bytes[48..52].copy_from_slice(&ARGON2_ITERATIONS.to_be_bytes());
        bytes[52..56].copy_from_slice(&ARGON2_PARALLELISM.to_be_bytes());
        bytes[56..72].copy_from_slice(&self.salt);
        bytes[72..96].copy_from_slice(&self.nonce);
        bytes[96..100].copy_from_slice(&self.ciphertext_length.to_be_bytes());
        // 100..104 flags and 104..112 reserved remain zero in v1.
        bytes
    }

    fn decode(bytes: &[u8]) -> Result<Self, VaultOpenError> {
        if bytes.len() < HEADER_LENGTH {
            return Err(VaultOpenError::InvalidEnvelope);
        }
        let mut cursor = Cursor::new(&bytes[..HEADER_LENGTH]);
        if cursor
            .read_array::<8>()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?
            != VAULT_MAGIC
            || cursor
                .read_u16()
                .map_err(|_| VaultOpenError::InvalidEnvelope)?
                != VAULT_VERSION
            || cursor
                .read_u16()
                .map_err(|_| VaultOpenError::InvalidEnvelope)?
                != HEADER_LENGTH_U16
        {
            return Err(VaultOpenError::InvalidEnvelope);
        }
        let vault_id = cursor
            .read_array::<16>()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let generation = cursor
            .read_u64()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let profile = cursor
            .read_u16()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let kdf = cursor
            .read_u16()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let aead = cursor
            .read_u16()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let schema = cursor
            .read_u16()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let memory = cursor
            .read_u32()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let iterations = cursor
            .read_u32()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let parallelism = cursor
            .read_u32()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let salt = cursor
            .read_array::<SALT_LENGTH>()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let nonce = cursor
            .read_array::<NONCE_LENGTH>()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let ciphertext_length = cursor
            .read_u32()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let flags = cursor
            .read_u32()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let reserved = cursor
            .read_array::<8>()
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;

        let ciphertext_length_usize =
            usize::try_from(ciphertext_length).map_err(|_| VaultOpenError::InvalidEnvelope)?;
        if profile != PASSWORD_PROFILE_ID
            || kdf != KDF_ID_ARGON2ID
            || aead != AEAD_ID_XCHACHA20_POLY1305
            || schema != PAYLOAD_SCHEMA
            || memory != ARGON2_MEMORY_KIB
            || iterations != ARGON2_ITERATIONS
            || parallelism != ARGON2_PARALLELISM
            || flags != 0
            || reserved != [0_u8; 8]
            || vault_id == [0_u8; 16]
            || generation == 0
            || !(AEAD_TAG_LENGTH..=MAX_CIPHERTEXT_LENGTH).contains(&ciphertext_length_usize)
        {
            return Err(VaultOpenError::InvalidEnvelope);
        }

        Ok(Self {
            vault_id,
            generation,
            salt,
            nonce,
            ciphertext_length,
        })
    }
}

/// An encrypted vault envelope. Its secret-bearing fields are ciphertext only.
pub struct VaultBlob {
    header: VaultHeader,
    bytes: Vec<u8>,
}

impl fmt::Debug for VaultBlob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultBlob")
            .field("header", &self.header)
            .field("bytes", &"[ENCRYPTED]")
            .finish()
    }
}

impl VaultBlob {
    /// Creates generation one with a random vault ID, salt, and nonce.
    ///
    /// # Errors
    ///
    /// Returns an error for unavailable randomness, invalid payload bounds, or
    /// fixed cryptographic primitive failure.
    pub fn seal_new(payload: &VaultPayload, password: &VaultPassword) -> Result<Self, SecretError> {
        let mut vault_id = [0_u8; 16];
        let mut salt = [0_u8; SALT_LENGTH];
        let mut nonce = [0_u8; NONCE_LENGTH];
        fill_random_nonzero(&mut vault_id)?;
        getrandom::fill(&mut salt).map_err(|_| SecretError::RandomnessUnavailable)?;
        getrandom::fill(&mut nonce).map_err(|_| SecretError::RandomnessUnavailable)?;
        Self::seal_with_material(payload, password, vault_id, 1, salt, nonce)
    }

    /// Reseals an updated payload under the same vault ID and next generation.
    ///
    /// # Errors
    ///
    /// Returns an error for generation overflow, unavailable randomness,
    /// invalid payload bounds, or fixed cryptographic primitive failure.
    pub fn reseal(
        payload: &VaultPayload,
        password: &VaultPassword,
        previous: &VaultHeader,
    ) -> Result<Self, SecretError> {
        let generation = previous
            .generation
            .checked_add(1)
            .ok_or(SecretError::BoundsExceeded)?;
        let mut salt = [0_u8; SALT_LENGTH];
        let mut nonce = [0_u8; NONCE_LENGTH];
        getrandom::fill(&mut salt).map_err(|_| SecretError::RandomnessUnavailable)?;
        getrandom::fill(&mut nonce).map_err(|_| SecretError::RandomnessUnavailable)?;
        Self::seal_with_material(
            payload,
            password,
            previous.vault_id,
            generation,
            salt,
            nonce,
        )
    }

    /// Parses a bounded vault envelope without attempting authentication.
    ///
    /// # Errors
    ///
    /// Returns [`VaultOpenError::InvalidEnvelope`] for any unsupported profile,
    /// malformed length, non-zero reserved field, or out-of-bound ciphertext.
    pub fn parse(bytes: &[u8]) -> Result<Self, VaultOpenError> {
        let header = VaultHeader::decode(bytes)?;
        let ciphertext_length = usize::try_from(header.ciphertext_length)
            .map_err(|_| VaultOpenError::InvalidEnvelope)?;
        let expected_length = HEADER_LENGTH
            .checked_add(ciphertext_length)
            .ok_or(VaultOpenError::InvalidEnvelope)?;
        if bytes.len() != expected_length {
            return Err(VaultOpenError::InvalidEnvelope);
        }
        Ok(Self {
            header,
            bytes: bytes.to_vec(),
        })
    }

    /// Authenticates and decodes this vault.
    ///
    /// # Errors
    ///
    /// Returns [`VaultOpenError::AuthenticationFailed`] for both a wrong
    /// password and an AEAD integrity failure. Authenticated but malformed
    /// plaintext returns [`VaultOpenError::InvalidPayload`].
    pub fn open(&self, password: &VaultPassword) -> Result<VaultPayload, VaultOpenError> {
        let aad = self.header.encode();
        let key = derive_vault_key(password, &self.header.salt)
            .map_err(|_| VaultOpenError::CryptographicFailure)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&self.header.nonce),
                Payload {
                    msg: &self.bytes[HEADER_LENGTH..],
                    aad: &aad,
                },
            )
            .map_err(|_| VaultOpenError::AuthenticationFailed)?;
        let plaintext = Zeroizing::new(plaintext);
        VaultPayload::decode(plaintext.as_slice()).map_err(|_| VaultOpenError::InvalidPayload)
    }

    /// Returns parsed public envelope metadata.
    #[must_use]
    pub const fn header(&self) -> &VaultHeader {
        &self.header
    }

    /// Returns bytes suitable for the release-critical atomic storage boundary.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn seal_with_material(
        payload: &VaultPayload,
        password: &VaultPassword,
        vault_id: [u8; 16],
        generation: u64,
        salt: [u8; SALT_LENGTH],
        nonce: [u8; NONCE_LENGTH],
    ) -> Result<Self, SecretError> {
        if vault_id == [0_u8; 16] || generation == 0 {
            return Err(SecretError::InvalidPayload);
        }
        let plaintext = payload.encode()?;
        let ciphertext_length_usize = plaintext
            .len()
            .checked_add(AEAD_TAG_LENGTH)
            .ok_or(SecretError::BoundsExceeded)?;
        if ciphertext_length_usize > MAX_CIPHERTEXT_LENGTH {
            return Err(SecretError::BoundsExceeded);
        }
        let ciphertext_length =
            u32::try_from(ciphertext_length_usize).map_err(|_| SecretError::BoundsExceeded)?;
        let header = VaultHeader {
            vault_id,
            generation,
            salt,
            nonce,
            ciphertext_length,
        };
        let aad = header.encode();
        let key = derive_vault_key(password, &salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(key.as_ref()));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| SecretError::CryptographicFailure)?;
        if ciphertext.len() != ciphertext_length_usize {
            return Err(SecretError::CryptographicFailure);
        }
        let mut bytes = Vec::with_capacity(HEADER_LENGTH + ciphertext.len());
        bytes.extend_from_slice(&aad);
        bytes.extend_from_slice(&ciphertext);
        Ok(Self { header, bytes })
    }
}

fn derive_vault_key(
    password: &VaultPassword,
    salt: &[u8; SALT_LENGTH],
) -> Result<Zeroizing<[u8; ARGON2_OUTPUT_BYTES]>, SecretError> {
    let parameters = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(ARGON2_OUTPUT_BYTES),
    )
    .map_err(|_| SecretError::CryptographicFailure)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    let mut master = Zeroizing::new([0_u8; ARGON2_OUTPUT_BYTES]);
    argon2
        .hash_password_into(password.as_bytes(), salt, master.as_mut())
        .map_err(|_| SecretError::CryptographicFailure)?;

    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), master.as_ref());
    let mut key = Zeroizing::new([0_u8; ARGON2_OUTPUT_BYTES]);
    hkdf.expand(VAULT_AEAD_INFO, key.as_mut())
        .map_err(|_| SecretError::CryptographicFailure)?;
    Ok(key)
}

fn record_id(record: &SecretRecord) -> &[u8; 16] {
    match record {
        SecretRecord::Bip39(record) => &record.record_id,
        SecretRecord::RawKey(record) => &record.record_id,
    }
}

fn encoded_payload_length(records: &[SecretRecord]) -> Result<usize, SecretError> {
    records.iter().try_fold(16_usize, |payload_length, record| {
        payload_length
            .checked_add(encoded_record_length(record)?)
            .ok_or(SecretError::BoundsExceeded)
    })
}

fn encoded_record_length(record: &SecretRecord) -> Result<usize, SecretError> {
    match record {
        SecretRecord::Bip39(record) => {
            if record.accounts.len() > MAX_DERIVED_ACCOUNTS {
                return Err(SecretError::BoundsExceeded);
            }
            let entropy_length = record.entropy.expose_entropy().len();
            u8::try_from(entropy_length).map_err(|_| SecretError::BoundsExceeded)?;
            let mut length = 32_usize
                .checked_add(entropy_length)
                .ok_or(SecretError::BoundsExceeded)?;
            for account in &record.accounts {
                account.validate()?;
                let path_depth = account.actual_path.components().len();
                u8::try_from(path_depth).map_err(|_| SecretError::BoundsExceeded)?;
                let path_bytes = path_depth
                    .checked_mul(core::mem::size_of::<u32>())
                    .ok_or(SecretError::BoundsExceeded)?;
                length = length
                    .checked_add(25_usize)
                    .and_then(|value| value.checked_add(path_bytes))
                    .ok_or(SecretError::BoundsExceeded)?;
            }
            Ok(length)
        }
        SecretRecord::RawKey(_) => Ok(60),
    }
}

fn verify_bip39_backup_confirmation(
    record: &Bip39Record,
    positions: [u8; BACKUP_CHALLENGE_WORDS],
    answers: &[String],
    confirmed_first_address: EthereumAddress,
) -> Result<(), SecretError> {
    if record.passphrase_required
        || answers.len() != BACKUP_CHALLENGE_WORDS
        || answers.iter().any(|answer| {
            answer.is_empty()
                || answer.len() > MAX_BACKUP_WORD_BYTES
                || !answer.bytes().all(|byte| byte.is_ascii_lowercase())
        })
    {
        return Err(SecretError::InvalidPayload);
    }

    let [persisted_zero, persisted_one] = record.accounts.as_slice() else {
        return Err(SecretError::InvalidPayload);
    };
    let passphrase = SessionPassphrase::empty();
    for (expected_index, persisted) in [(0_u32, persisted_zero), (1_u32, persisted_one)] {
        let requested = AccountIndex::new(expected_index)?;
        if persisted.requested_index != requested {
            return Err(SecretError::InvalidPayload);
        }
        let derived = record
            .entropy
            .derive_ethereum_account(&passphrase, requested)?;
        if derived.path() != &persisted.actual_path || derived.address() != persisted.address {
            return Err(SecretError::InvalidPayload);
        }
    }
    if confirmed_first_address != persisted_zero.address {
        return Err(SecretError::InvalidPayload);
    }

    let phrase = record.entropy.reveal_phrase()?;
    let word_count = phrase.expose_secret().split(' ').count();
    if !matches!(word_count, 12 | 24) {
        return Err(SecretError::InvalidPayload);
    }

    let mut previous = 0_u8;
    let mut all_match = 1_u8;
    for (position, answer) in positions.into_iter().zip(answers) {
        if position <= previous || usize::from(position) > word_count {
            return Err(SecretError::InvalidPayload);
        }
        previous = position;
        let expected = phrase
            .expose_secret()
            .split(' ')
            .nth(usize::from(position) - 1)
            .ok_or(SecretError::InvalidPayload)?;
        all_match &= expected.as_bytes().ct_eq(answer.as_bytes()).unwrap_u8();
    }
    if all_match != 1 {
        return Err(SecretError::InvalidPayload);
    }
    Ok(())
}

fn encode_record(output: &mut Vec<u8>, record: &SecretRecord) -> Result<(), SecretError> {
    match record {
        SecretRecord::Bip39(record) => {
            if record.accounts.len() > MAX_DERIVED_ACCOUNTS {
                return Err(SecretError::BoundsExceeded);
            }
            output.push(1);
            output.push(record.backup_state.code());
            output.extend_from_slice(&u16::from(record.passphrase_required).to_be_bytes());
            output.extend_from_slice(&record.record_id);
            output.extend_from_slice(&record.created_at_unix.to_be_bytes());
            output.push(BIP39_LANGUAGE_ENGLISH);
            let entropy_length = u8::try_from(record.entropy.expose_entropy().len())
                .map_err(|_| SecretError::BoundsExceeded)?;
            output.push(entropy_length);
            output.extend_from_slice(record.entropy.expose_entropy());
            let account_count =
                u16::try_from(record.accounts.len()).map_err(|_| SecretError::BoundsExceeded)?;
            output.extend_from_slice(&account_count.to_be_bytes());
            for account in &record.accounts {
                account.validate()?;
                output.extend_from_slice(&account.requested_index.value().to_be_bytes());
                let path_length = u8::try_from(account.actual_path.components().len())
                    .map_err(|_| SecretError::BoundsExceeded)?;
                output.push(path_length);
                for child in account.actual_path.components() {
                    output.extend_from_slice(&child.to_be_bytes());
                }
                output.extend_from_slice(account.address.as_bytes());
            }
        }
        SecretRecord::RawKey(record) => {
            output.push(2);
            output.push(record.backup_state.code());
            output.extend_from_slice(&0_u16.to_be_bytes());
            output.extend_from_slice(&record.record_id);
            output.extend_from_slice(&record.created_at_unix.to_be_bytes());
            output.extend_from_slice(record.private_key.expose_bytes());
        }
    }
    Ok(())
}

fn decode_record(cursor: &mut Cursor<'_>) -> Result<SecretRecord, SecretError> {
    let tag = cursor.read_u8()?;
    let backup_state = BackupState::from_code(cursor.read_u8()?)?;
    let flags = cursor.read_u16()?;
    let record_id = cursor.read_array::<16>()?;
    let created_at_unix = cursor.read_u64()?;
    match tag {
        1 => {
            if flags & !1 != 0 {
                return Err(SecretError::InvalidPayload);
            }
            if cursor.read_u8()? != BIP39_LANGUAGE_ENGLISH {
                return Err(SecretError::InvalidPayload);
            }
            let entropy_length = usize::from(cursor.read_u8()?);
            let entropy = MnemonicEntropy::from_entropy(cursor.read_slice(entropy_length)?)?;
            let account_count = usize::from(cursor.read_u16()?);
            if account_count > MAX_DERIVED_ACCOUNTS {
                return Err(SecretError::BoundsExceeded);
            }
            let mut record = Bip39Record::new_with_state(
                record_id,
                created_at_unix,
                backup_state,
                flags & 1 == 1,
                entropy,
            );
            for _ in 0..account_count {
                let requested_index = AccountIndex::new(cursor.read_u32()?)?;
                let depth = usize::from(cursor.read_u8()?);
                let mut components = Vec::with_capacity(depth);
                for _ in 0..depth {
                    components.push(cursor.read_u32()?);
                }
                let actual_path = DerivationPath::new(components)?;
                let address = EthereumAddress::from_bytes(cursor.read_array::<20>()?);
                record.add_account(DerivedAccountRecord {
                    requested_index,
                    actual_path,
                    address,
                })?;
            }
            Ok(SecretRecord::Bip39(record))
        }
        2 => {
            if flags != 0 {
                return Err(SecretError::InvalidPayload);
            }
            let private_key = Zeroizing::new(cursor.read_array::<32>()?);
            RawKeyRecord::import(
                record_id,
                created_at_unix,
                backup_state,
                private_key.as_slice(),
            )
            .map(SecretRecord::RawKey)
        }
        _ => Err(SecretError::InvalidPayload),
    }
}

fn fill_random_nonzero(bytes: &mut [u8; 16]) -> Result<(), SecretError> {
    for _ in 0..4 {
        getrandom::fill(bytes).map_err(|_| SecretError::RandomnessUnavailable)?;
        if *bytes != [0_u8; 16] {
            return Ok(());
        }
    }
    Err(SecretError::RandomnessUnavailable)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, SecretError> {
        let bytes = self.read_array::<1>()?;
        Ok(bytes[0])
    }

    fn read_u16(&mut self) -> Result<u16, SecretError> {
        Ok(u16::from_be_bytes(self.read_array()?))
    }

    fn read_u32(&mut self) -> Result<u32, SecretError> {
        Ok(u32::from_be_bytes(self.read_array()?))
    }

    fn read_u64(&mut self) -> Result<u64, SecretError> {
        Ok(u64::from_be_bytes(self.read_array()?))
    }

    fn read_array<const LENGTH: usize>(&mut self) -> Result<[u8; LENGTH], SecretError> {
        self.read_slice(LENGTH)?
            .try_into()
            .map_err(|_| SecretError::InvalidPayload)
    }

    fn read_slice(&mut self, length: usize) -> Result<&'a [u8], SecretError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(SecretError::InvalidPayload)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(SecretError::InvalidPayload)?;
        self.offset = end;
        Ok(value)
    }

    const fn is_finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AEAD_TAG_LENGTH, BackupState, Bip39Record, SALT_LENGTH, SecretRecord, VaultBlob,
        VaultHeader, VaultOpenError, VaultPayload,
    };
    use crate::{
        AccountIndex, EthereumAddress, MnemonicEntropy, SecretError, SessionPassphrase,
        VaultPassword,
    };
    use sha2::{Digest, Sha256};

    fn fixture_payload() -> Result<VaultPayload, SecretError> {
        let entropy = MnemonicEntropy::from_entropy(&[19_u8; 16])?;
        let record = Bip39Record::new_with_state(
            [3_u8; 16],
            1_700_000_000,
            BackupState::Confirmed,
            true,
            entropy,
        );
        let mut payload = VaultPayload::new();
        payload.push(SecretRecord::Bip39(record))?;
        Ok(payload)
    }

    #[test]
    fn deterministic_payload_codec_round_trips() -> Result<(), SecretError> {
        let payload = fixture_payload()?;
        let first = payload.encode()?;
        let second = payload.encode()?;
        assert_eq!(first.as_slice(), second.as_slice());
        let decoded = VaultPayload::decode(first.as_slice())?;
        assert_eq!(decoded.records().len(), 1);
        Ok(())
    }

    #[test]
    fn backup_confirmation_mutates_only_one_exact_pending_mnemonic() -> Result<(), SecretError> {
        let record_id = [7_u8; 16];
        let entropy = MnemonicEntropy::from_entropy(&[29_u8; 16])?;
        let passphrase = crate::SessionPassphrase::empty();
        let account_zero =
            entropy.derive_ethereum_account(&passphrase, crate::AccountIndex::new(0)?)?;
        let account_one =
            entropy.derive_ethereum_account(&passphrase, crate::AccountIndex::new(1)?)?;
        let first_address = account_zero.address();
        let phrase = entropy.reveal_phrase()?;
        let answers = phrase
            .expose_secret()
            .split(' ')
            .take(4)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut record = Bip39Record::new_unconfirmed(record_id, 1_700_000_001, false, entropy);
        record.add_account(super::DerivedAccountRecord::from_derived(
            crate::AccountIndex::new(0)?,
            &account_zero,
        ))?;
        record.add_account(super::DerivedAccountRecord::from_derived(
            crate::AccountIndex::new(1)?,
            &account_one,
        ))?;
        let mut payload = VaultPayload::new();
        payload.push(SecretRecord::Bip39(record))?;

        assert_eq!(
            payload.verify_and_confirm_bip39_backup(
                record_id,
                [1, 2, 2, 4],
                &answers,
                first_address,
            ),
            Err(SecretError::InvalidPayload)
        );
        let mut wrong_answers = answers.clone();
        wrong_answers[0].push('x');
        assert_eq!(
            payload.verify_and_confirm_bip39_backup(
                record_id,
                [1, 2, 3, 4],
                &wrong_answers,
                first_address,
            ),
            Err(SecretError::InvalidPayload)
        );
        payload.verify_and_confirm_bip39_backup(
            record_id,
            [1, 2, 3, 4],
            &answers,
            first_address,
        )?;
        let state = match payload.records().first() {
            Some(SecretRecord::Bip39(record)) => record.backup_state(),
            Some(SecretRecord::RawKey(_)) | None => return Err(SecretError::InvalidPayload),
        };
        assert_eq!(state, BackupState::Confirmed);
        assert_eq!(
            payload.verify_and_confirm_bip39_backup(
                record_id,
                [1, 2, 3, 4],
                &answers,
                first_address,
            ),
            Err(SecretError::InvalidPayload)
        );
        assert_eq!(
            payload.verify_and_confirm_bip39_backup(
                [8_u8; 16],
                [1, 2, 3, 4],
                &answers,
                first_address,
            ),
            Err(SecretError::InvalidPayload)
        );
        Ok(())
    }

    #[test]
    fn backup_confirmation_rejects_missing_accounts_passphrases_and_bad_challenges()
    -> Result<(), SecretError> {
        let record_id = [9_u8; 16];
        let entropy = MnemonicEntropy::from_entropy(&[37_u8; 16])?;
        let phrase = entropy.reveal_phrase()?;
        let answers = phrase
            .expose_secret()
            .split(' ')
            .take(4)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let empty_address = EthereumAddress::from_bytes([0_u8; 20]);
        let mut missing_accounts = VaultPayload::new();
        missing_accounts.push(SecretRecord::Bip39(Bip39Record::new_unconfirmed(
            record_id,
            1_700_000_002,
            false,
            entropy,
        )))?;
        assert_eq!(
            missing_accounts.verify_and_confirm_bip39_backup(
                record_id,
                [1, 2, 3, 4],
                &answers,
                empty_address,
            ),
            Err(SecretError::InvalidPayload)
        );

        let entropy = MnemonicEntropy::from_entropy(&[41_u8; 16])?;
        let passphrase = SessionPassphrase::empty();
        let account_zero = entropy.derive_ethereum_account(&passphrase, AccountIndex::new(0)?)?;
        let account_one = entropy.derive_ethereum_account(&passphrase, AccountIndex::new(1)?)?;
        let first_address = account_zero.address();
        let phrase = entropy.reveal_phrase()?;
        let answers = phrase
            .expose_secret()
            .split(' ')
            .take(4)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut record = Bip39Record::new_unconfirmed(record_id, 1_700_000_003, true, entropy);
        record.add_account(super::DerivedAccountRecord::from_derived(
            AccountIndex::new(0)?,
            &account_zero,
        ))?;
        record.add_account(super::DerivedAccountRecord::from_derived(
            AccountIndex::new(1)?,
            &account_one,
        ))?;
        let mut passphrase_dependent = VaultPayload::new();
        passphrase_dependent.push(SecretRecord::Bip39(record))?;
        assert_eq!(
            passphrase_dependent.verify_and_confirm_bip39_backup(
                record_id,
                [1, 2, 3, 4],
                &answers,
                first_address,
            ),
            Err(SecretError::InvalidPayload)
        );
        assert_eq!(
            passphrase_dependent.verify_and_confirm_bip39_backup(
                record_id,
                [1, 2, 2, 4],
                &answers,
                first_address,
            ),
            Err(SecretError::InvalidPayload)
        );
        Ok(())
    }

    #[test]
    fn header_codec_has_frozen_layout() {
        let header = VaultHeader {
            vault_id: [1_u8; 16],
            generation: 7,
            salt: [2_u8; SALT_LENGTH],
            nonce: [4_u8; 24],
            ciphertext_length: 16,
        };
        let bytes = header.encode();
        assert_eq!(&bytes[..8], b"YWRVLT01");
        assert_eq!(&bytes[8..12], &[0, 1, 0, 112]);
        assert_eq!(&bytes[12..28], &[1_u8; 16]);
        assert_eq!(&bytes[28..36], &7_u64.to_be_bytes());
        assert_eq!(&bytes[44..48], &262_144_u32.to_be_bytes());
        assert_eq!(&bytes[48..52], &3_u32.to_be_bytes());
        assert_eq!(&bytes[52..56], &4_u32.to_be_bytes());
        assert_eq!(&bytes[100..112], &[0_u8; 12]);
    }

    #[test]
    fn seal_parse_open_round_trip_and_auth_error_collapse() -> Result<(), SecretError> {
        let password = VaultPassword::new("correct-test-password")?;
        let wrong_password = VaultPassword::new("incorrect-test-password")?;
        let blob = VaultBlob::seal_with_material(
            &fixture_payload()?,
            &password,
            [8_u8; 16],
            1,
            [9_u8; 16],
            [10_u8; 24],
        )?;
        assert_eq!(
            Sha256::digest(blob.as_bytes()).as_slice(),
            &[
                167, 35, 230, 229, 167, 190, 228, 19, 28, 253, 0, 249, 0, 204, 200, 242, 61, 188,
                48, 130, 93, 127, 239, 225, 108, 34, 169, 218, 21, 195, 110, 26,
            ]
        );
        let parsed = VaultBlob::parse(blob.as_bytes()).map_err(|_| SecretError::InvalidPayload)?;
        let opened = parsed
            .open(&password)
            .map_err(|_| SecretError::InvalidPayload)?;
        assert_eq!(opened.records().len(), 1);
        assert_eq!(
            parsed.open(&wrong_password).err(),
            Some(VaultOpenError::AuthenticationFailed)
        );

        let mut tampered = blob.as_bytes().to_vec();
        let final_index = tampered.len().saturating_sub(1);
        if let Some(byte) = tampered.get_mut(final_index) {
            *byte ^= 1;
        }
        let tampered = VaultBlob::parse(&tampered).map_err(|_| SecretError::InvalidPayload)?;
        assert_eq!(
            tampered.open(&password).err(),
            Some(VaultOpenError::AuthenticationFailed)
        );
        Ok(())
    }

    #[test]
    fn malformed_envelopes_are_rejected_before_kdf() {
        let header = VaultHeader {
            vault_id: [12_u8; 16],
            generation: 1,
            salt: [13_u8; SALT_LENGTH],
            nonce: [14_u8; 24],
            ciphertext_length: 16,
        };
        let mut bytes = Vec::from(header.encode());
        bytes.extend_from_slice(&[0_u8; AEAD_TAG_LENGTH]);
        bytes[44..48].copy_from_slice(&131_072_u32.to_be_bytes());
        assert_eq!(
            VaultBlob::parse(&bytes).err(),
            Some(VaultOpenError::InvalidEnvelope)
        );
    }
}
